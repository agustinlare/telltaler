# TellTale - Kubernetes Delete Notifier

A **ValidatingWebhook** for Kubernetes that sends notifications by email, Webhook or Microsoft Teams when Namespaces or ArgoCD Applications are deleted, indicating who performed the action.

> **TellTale**: For mismanaged clusters.

## Features

- Intercepts DELETE of **Namespaces**
- Intercepts DELETE of **ArgoCD Applications**
- Captures the **user or ServiceAccount** that performed the deletion
- Supports multiple transports: **Email (SMTP)**, **Webhook** (Discord/Slack) or **Microsoft Teams**
- **Does not block** the operation (always allows deletion)
- Excludes OpenShift system namespaces

## Prerequisites

-  Kubernetes 1.19+ or OpenShift 4.12+
- SMTP server, Webhook URL or Teams Webhook URL
- `oc` or `kubectl` with administrator permissions
- Docker/Podman to build the image
- OpenSSL to generate certificates

## Installation

### Step 1: Clone the repository

```bash
git clone <repository-url>
cd telltale
```

### Step 2: Generate and Configure TLS Certificates

Copy and run the following script to generate certificates and create the necessary secrets:

```bash
#!/bin/bash
set -e

SERVICE_NAME="telltale"
NAMESPACE="telltale"
CERTS_DIR="certs"
mkdir -p "${CERTS_DIR}"

echo "Generating TLS certificates for ${SERVICE_NAME}..."

# 1. Generate CA
openssl genrsa -out "${CERTS_DIR}/ca.key" 2048
openssl req -x509 -new -nodes -key "${CERTS_DIR}/ca.key" -subj "/CN=${SERVICE_NAME}-ca" -days 3650 -out "${CERTS_DIR}/ca.crt"

# 2. Generate Server Cert
openssl genrsa -out "${CERTS_DIR}/tls.key" 2048
cat > "${CERTS_DIR}/csr.conf" <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${SERVICE_NAME}
DNS.2 = ${SERVICE_NAME}.${NAMESPACE}
DNS.3 = ${SERVICE_NAME}.${NAMESPACE}.svc
DNS.4 = ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
EOF

openssl req -new -key "${CERTS_DIR}/tls.key" -subj "/CN=${SERVICE_NAME}.${NAMESPACE}.svc" -out "${CERTS_DIR}/tls.csr" -config "${CERTS_DIR}/csr.conf"
openssl x509 -req -in "${CERTS_DIR}/tls.csr" -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" -CAcreateserial -out "${CERTS_DIR}/tls.crt" -days 365 -extensions v3_req -extfile "${CERTS_DIR}/csr.conf"

# 3. Create Secrets directly
echo "Creating TLS Secret..."
# Ensure namespace exists (or create it manually first with: oc create ns telltale)
kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret tls ${SERVICE_NAME}-tls --cert="${CERTS_DIR}/tls.crt" --key="${CERTS_DIR}/tls.key" -n ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -

# 4. Patch Webhook CA Bundle
echo "Patching Webhook CA Bundle..."
CA_BUNDLE=$(cat "${CERTS_DIR}/ca.crt" | base64 | tr -d '\n')
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s|caBundle: \"\"|caBundle: ${CA_BUNDLE}|g" "k8s/validatingwebhook.yaml"
else
    sed -i "s|caBundle: \"\"|caBundle: ${CA_BUNDLE}|g" "k8s/validatingwebhook.yaml"
fi

echo "Certificates generated and configured!"
```

### Step 3: Build the Docker Image

```bash
# Build the image
docker build -t telltale:latest .

# If you use a private registry:
docker tag telltale:latest <your-registry>/telltale:latest
docker push <your-registry>/telltale:latest
```

### Step 4: Configure the Transport

Edit the `k8s/configmap.yaml` file and choose the transport type:

#### Option A: Email (SMTP)

```yaml
data:
  TRANSPORT_TYPE: "mail"
  SMTP_HOST: "smtp.domain.com"
  SMTP_PORT: "25"
  EMAIL_FROM: "[EMAIL_ADDRESS]"
  EMAIL_TO: "[EMAIL_ADDRESS]"
```

#### Option B: Webhook (Discord, Slack, etc.)

```yaml
data:
  TRANSPORT_TYPE: "webhook"
  WEBHOOK_URL: "https://discord.com/api/webhooks/..."
```

#### Option C: Microsoft Teams

```yaml
data:
  TRANSPORT_TYPE: "teams"
  WEBHOOK_URL: "https://outlook.office.com/webhook/..."
```

### Step 5: Update the Image in the Deployment

If you use a private registry, edit `k8s/deployment.yaml`:

```yaml
spec:
  containers:
    - name: webhook
      image: <tu-registry>/telltale:latest
```

### Step 6: Deploy in OpenShift

```bash
# Apply all manifests
kubectl apply -f k8s/
```

> **Note:** If you already ran the script in Step 2, `namespace.yaml` and `secret-tls.yaml` will already be applied or configured. Applying `k8s/` will reaffirm the configuration.

### Step 7: Verify the Deployment

```bash
# Verify that the pods are running
kubectl get pods -n telltale

# View logs
kubectl logs -n telltale -l app.kubernetes.io/name=telltale -f
```

## Test the Functionality

1. Create a test namespace:
```bash
kubectl create namespace test-whistleblower
```

2. Delete the namespace:
```bash
kubectl delete namespace test-whistleblower
```

3. Verify the webhook logs:
```bash
kubectl logs -n telltale -l app.kubernetes.io/name=telltale --tail=50
```

4. Verify that the message was received through the configured medium.

## Project Structure

```
telltale/
├── Dockerfile                    # Container image
├── go.mod                        # Go dependencies
├── main.go                       # Application code
├── README.md                     # This documentation
└── k8s/
    ├── namespace.yaml            # Webhook namespace
    ├── serviceaccount.yaml       # ServiceAccount
    ├── configmap.yaml            # Transport configuration
    ├── secret-smtp.yaml          # SMTP credentials (optional)
    ├── secret-tls.yaml           # TLS certificates (placeholder)
    ├── deployment.yaml           # Application deployment
    ├── service.yaml              # Service
    └── validatingwebhook.yaml    # Webhook configuration
```

## Environment Variables

| Variable | Description | Default Value |
|----------|-------------|-------------------|
| `TRANSPORT_TYPE` | Tipo de transporte: `mail`, `webhook`, `teams` | `mail` |
| `SMTP_HOST` | Servidor SMTP (para mail) | `localhost` |
| `SMTP_PORT` | Puerto SMTP (para mail) | `25` |
| `SMTP_USER` | Usuario SMTP (opcional) | `""` |
| `SMTP_PASSWORD` | Contraseña SMTP (opcional) | `""` |
| `EMAIL_FROM` | Remitente del email | `whistleblower@openshift.local` |
| `EMAIL_TO` | Destinatario del email | `...` |
| `WEBHOOK_URL` | URL del webhook (para webhook/teams) | `""` |
| `TLS_CERT_FILE` | Ruta al certificado TLS | `/certs/tls.crt` |
| `TLS_KEY_FILE` | Ruta a la clave TLS | `/certs/tls.key` |

## Security

- The application runs as a non-root user (UID 1001)
- Read-only filesystem
- No privilege escalation
- Capabilities removed
- Seccomp profile RuntimeDefault
- TLS 1.2 minimum
