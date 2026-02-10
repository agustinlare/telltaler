package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Metric definitions
var (
	deletedResources = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "telltale_deleted_total",
			Help: "Total number of resources deleted",
		},
		[]string{"resource_type", "deleted_by", "transport"},
	)
)

func init() {
	prometheus.MustRegister(deletedResources)
}

// TransportType defines the notification transport method
type TransportType string

const (
	TransportMail    TransportType = "mail"
	TransportWebhook TransportType = "webhook"
	TransportTeams   TransportType = "teams"
)

// Config holds the application configuration
type Config struct {
	// Transport configuration
	TransportType TransportType

	// SMTP configuration (for mail transport)
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPassword string
	EmailFrom    string
	EmailTo      string

	// Webhook configuration (for webhook and teams transport)
	WebhookURL string

	// TLS configuration
	TLSCertFile string
	TLSKeyFile  string
}

func loadConfig() Config {
	transportType := TransportType(strings.ToLower(getEnv("TRANSPORT_TYPE", "mail")))

	// Validate transport type
	if transportType != TransportMail && transportType != TransportWebhook && transportType != TransportTeams {
		log.Printf("WARNING: Invalid TRANSPORT_TYPE '%s', defaulting to 'mail'", transportType)
		transportType = TransportMail
	}

	return Config{
		TransportType: transportType,

		// SMTP config
		SMTPHost:     getEnv("SMTP_HOST", "localhost"),
		SMTPPort:     getEnv("SMTP_PORT", "25"),
		SMTPUser:     getEnv("SMTP_USER", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		EmailFrom:    getEnv("EMAIL_FROM", "telltale@openshift.local"),
		EmailTo:      getEnv("EMAIL_TO", ""),

		// Webhook config
		WebhookURL: getEnv("WEBHOOK_URL", ""),

		// TLS config
		TLSCertFile: getEnv("TLS_CERT_FILE", "/certs/tls.crt"),
		TLSKeyFile:  getEnv("TLS_KEY_FILE", "/certs/tls.key"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// WebhookPayload represents the JSON payload sent to the webhook
// Compatible with Discord webhooks (uses 'content' field)
type WebhookPayload struct {
	Content      string   `json:"content"`
	Event        string   `json:"event,omitempty"`
	ResourceType string   `json:"resource_type,omitempty"`
	ResourceName string   `json:"resource_name,omitempty"`
	DeletedBy    string   `json:"deleted_by,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	Timestamp    string   `json:"timestamp,omitempty"`
}

// TeamsPayload represents the JSON payload sent to Microsoft Teams
type TeamsPayload struct {
	Type       string         `json:"@type"`
	Context    string         `json:"@context"`
	ThemeColor string         `json:"themeColor"`
	Summary    string         `json:"summary"`
	Sections   []TeamsSection `json:"sections"`
}

type TeamsSection struct {
	ActivityTitle    string      `json:"activityTitle"`
	ActivitySubtitle string      `json:"activitySubtitle"`
	Facts            []TeamsFact `json:"facts"`
	Markdown         bool        `json:"markdown"`
}

type TeamsFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// sendNotification sends a notification using the configured transport
func sendNotification(config Config, resourceType, resourceName, username string, groups []string) error {
	// Increment metrics
	deletedResources.WithLabelValues(resourceType, username, string(config.TransportType)).Inc()

	switch config.TransportType {
	case TransportMail:
		return sendEmail(config, resourceType, resourceName, username, groups)
	case TransportWebhook:
		return sendWebhook(config, resourceType, resourceName, username, groups)
	case TransportTeams:
		return sendTeamsWebhook(config, resourceType, resourceName, username, groups)
	default:
		return fmt.Errorf("unknown transport type: %s", config.TransportType)
	}
}

// sendWebhook sends a webhook notification about the deletion
func sendWebhook(config Config, resourceType, resourceName, username string, groups []string) error {
	if config.WebhookURL == "" {
		return fmt.Errorf("WEBHOOK_URL is not configured")
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05 MST")

	// Build the message content (compatible with Discord)
	content := fmt.Sprintf(`🚨 **RESOURCE DELETED**

**Type:** %s
**Name:** %s
**Deleted by:** %s
**Groups:** %s
**Date/Time:** %s`,
		resourceType,
		resourceName,
		username,
		strings.Join(groups, ", "),
		timestamp,
	)

	payload := WebhookPayload{
		Content:      content,
		Event:        "resource_deleted",
		ResourceType: resourceType,
		ResourceName: resourceName,
		DeletedBy:    username,
		Groups:       groups,
		Timestamp:    timestamp,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	resp, err := http.Post(config.WebhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("Webhook sent successfully to %s about deletion of %s '%s' by '%s'",
		config.WebhookURL, resourceType, resourceName, username)
	return nil
}

// sendTeamsWebhook sends a notification to Microsoft Teams
func sendTeamsWebhook(config Config, resourceType, resourceName, username string, groups []string) error {
	if config.WebhookURL == "" {
		return fmt.Errorf("WEBHOOK_URL is not configured")
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05 MST")
	title := fmt.Sprintf("🚨 Resource Deleted: %s", resourceName)

	payload := TeamsPayload{
		Type:       "MessageCard",
		Context:    "http://schema.org/extensions",
		ThemeColor: "FF0000", // Red color for alert
		Summary:    title,
		Sections: []TeamsSection{
			{
				ActivityTitle:    title,
				ActivitySubtitle: "OpenShift Notification",
				Markdown:         true,
				Facts: []TeamsFact{
					{Name: "Resource Type", Value: resourceType},
					{Name: "Name", Value: resourceName},
					{Name: "Deleted by", Value: username},
					{Name: "Groups", Value: strings.Join(groups, ", ")},
					{Name: "Date/Time", Value: timestamp},
				},
			},
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal teams payload: %w", err)
	}

	resp, err := http.Post(config.WebhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send teams webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("teams webhook returned status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("Teams webhook sent successfully to %s about deletion of %s '%s' by '%s'",
		config.WebhookURL, resourceType, resourceName, username)
	return nil
}

// sendEmail sends an email notification about the deletion
func sendEmail(config Config, resourceType, resourceName, username string, groups []string) error {
	subject := fmt.Sprintf("🚨 [OpenShift] %s '%s' has been deleted", resourceType, resourceName)

	body := fmt.Sprintf(`
================================================================================
                    RESOURCE DELETION NOTIFICATION
================================================================================

Resource Type: %s
Name:          %s
Deleted by:    %s
Groups:        %s
Date/Time:     %s

================================================================================
This is an automated message from TellTale Notification System.
================================================================================
`,
		resourceType,
		resourceName,
		username,
		strings.Join(groups, ", "),
		time.Now().Format("2006-01-02 15:04:05 MST"),
	)

	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		config.EmailFrom,
		config.EmailTo,
		subject,
		body,
	)

	addr := fmt.Sprintf("%s:%s", config.SMTPHost, config.SMTPPort)

	var auth smtp.Auth
	if config.SMTPUser != "" && config.SMTPPassword != "" {
		auth = smtp.PlainAuth("", config.SMTPUser, config.SMTPPassword, config.SMTPHost)
	}

	err := smtp.SendMail(addr, auth, config.EmailFrom, []string{config.EmailTo}, []byte(message))
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Printf("Email sent successfully to %s about deletion of %s '%s' by '%s'",
		config.EmailTo, resourceType, resourceName, username)
	return nil
}

// handleValidate handles the admission webhook validation requests
func handleValidate(config Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Log the request (logging middleware handles suppression for health/metrics)
		// but we still log specific validation logic here if needed

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading body: %v", err)
			http.Error(w, "Error reading body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var admissionReview admissionv1.AdmissionReview
		if err := json.Unmarshal(body, &admissionReview); err != nil {
			log.Printf("Error unmarshaling request: %v", err)
			http.Error(w, "Error parsing request", http.StatusBadRequest)
			return
		}

		request := admissionReview.Request
		if request == nil {
			log.Printf("Empty admission request")
			http.Error(w, "Empty admission request", http.StatusBadRequest)
			return
		}

		log.Printf("Processing admission request: UID=%s, Kind=%s/%s, Name=%s, Operation=%s, User=%s",
			request.UID,
			request.Kind.Group,
			request.Kind.Kind,
			request.Name,
			request.Operation,
			request.UserInfo.Username,
		)

		// Only process DELETE operations
		if request.Operation == admissionv1.Delete {
			resourceType := request.Kind.Kind
			resourceName := request.Name

			// If name is empty for namespace, try to get it from the object
			if resourceName == "" && request.OldObject.Raw != nil {
				var obj map[string]interface{}
				if err := json.Unmarshal(request.OldObject.Raw, &obj); err == nil {
					if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
						if name, ok := metadata["name"].(string); ok {
							resourceName = name
						}
					}
				}
			}

			username := request.UserInfo.Username
			groups := request.UserInfo.Groups

			log.Printf("DELETE detected: %s '%s' by user '%s' (groups: %v)",
				resourceType, resourceName, username, groups)

			// Send notification asynchronously to not block the admission
			go func() {
				if err := sendNotification(config, resourceType, resourceName, username, groups); err != nil {
					log.Printf("Error sending notification: %v", err)
				}
			}()
		}

		// Always allow the operation - we're just notifying, not blocking
		response := admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "admission.k8s.io/v1",
				Kind:       "AdmissionReview",
			},
			Response: &admissionv1.AdmissionResponse{
				UID:     request.UID,
				Allowed: true,
				Result: &metav1.Status{
					Message: "Deletion allowed, notification sent",
				},
			},
		}

		responseBytes, err := json.Marshal(response)
		if err != nil {
			log.Printf("Error marshaling response: %v", err)
			http.Error(w, "Error creating response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(responseBytes)
	}
}

// handleHealth handles health check requests
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// loggingMiddleware logs requests but excludes health and metrics endpoints
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip logging for health and metrics endpoints
		if r.URL.Path != "/health" && r.URL.Path != "/metrics" && !strings.HasSuffix(r.URL.Path, "z") {
			log.Printf("Received request: %s %s", r.Method, r.URL.Path)
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	config := loadConfig()

	log.Printf("Starting TellTale Notification Service...")
	log.Printf("Transport Type: %s", config.TransportType)

	switch config.TransportType {
	case TransportMail:
		log.Printf("SMTP Server: %s:%s", config.SMTPHost, config.SMTPPort)
		log.Printf("Email notifications will be sent to: %s", config.EmailTo)
	case TransportWebhook, TransportTeams:
		log.Printf("Webhook URL: %s", config.WebhookURL)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", handleValidate(config))
	mux.HandleFunc("/health", handleHealth)

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// Wrap mux with logging middleware
	handler := loggingMiddleware(mux)

	server := &http.Server{
		Addr:         ":8443",
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Check if TLS certificates exist
	if _, err := os.Stat(config.TLSCertFile); err == nil {
		log.Printf("TLS certificates found, starting HTTPS server on :8443")
		cert, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
		if err != nil {
			log.Fatalf("Failed to load TLS certificates: %v", err)
		}
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	} else {
		log.Printf("TLS certificates not found, starting HTTP server on :8443 (for local testing only)")
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}
}
