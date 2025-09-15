#!/bin/bash
set -e

NAMESPACE="tailscale-webhook"
SERVICE="tailscale-webhook"
CERT_DIR="/tmp"

# Generate CA key and certificate
openssl req -x509 -newkey rsa:4096 -keyout ${CERT_DIR}/ca-key.pem -out ${CERT_DIR}/ca-cert.pem -days 365 -nodes -subj "/CN=Tailscale Webhook CA"

# Generate server key
openssl genrsa -out ${CERT_DIR}/webhook-key.pem 2048

# Generate certificate signing request
cat <<EOF > ${CERT_DIR}/csr.conf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${SERVICE}
DNS.2 = ${SERVICE}.${NAMESPACE}
DNS.3 = ${SERVICE}.${NAMESPACE}.svc
DNS.4 = ${SERVICE}.${NAMESPACE}.svc.cluster.local
EOF

openssl req -new -key ${CERT_DIR}/webhook-key.pem -out ${CERT_DIR}/webhook.csr -config ${CERT_DIR}/csr.conf -subj "/CN=${SERVICE}.${NAMESPACE}.svc"

# Sign the certificate
openssl x509 -req -in ${CERT_DIR}/webhook.csr -CA ${CERT_DIR}/ca-cert.pem -CAkey ${CERT_DIR}/ca-key.pem -CAcreateserial -out ${CERT_DIR}/webhook-cert.pem -days 365 -extensions v3_req -extfile ${CERT_DIR}/csr.conf

# Get the CA bundle for the webhook configuration
CA_BUNDLE=$(cat ${CERT_DIR}/ca-cert.pem | base64 | tr -d '\n')
echo "CA Bundle (save this for webhook configuration):"
echo "${CA_BUNDLE}"