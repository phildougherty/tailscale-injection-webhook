# Tailscale Injection Webhook

A Kubernetes admission webhook that automatically injects Tailscale sidecar containers into pods, enabling seamless mesh networking for your applications.

[![Go Report Card](https://goreportcard.com/badge/github.com/phildougherty/tailscale-injection-webhook)](https://goreportcard.com/report/github.com/phildougherty/tailscale-injection-webhook)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Docker Pulls](https://img.shields.io/docker/pulls/phildougherty/tailscale-injection-webhook)](https://hub.docker.com/r/phildougherty/tailscale-injection-webhook)

## Overview

The Tailscale Injection Webhook integrates with the Kubernetes admission controller system to automatically inject Tailscale sidecar containers into pods based on annotations. This enables your applications to join your Tailscale network without requiring code changes or complex networking configurations.

### Key Features

- **Automatic Sidecar Injection**: Seamlessly inject Tailscale containers based on pod annotations
- **Flexible Configuration**: Support for userspace and kernel networking modes
- **Tag-based ACLs**: Automatic tag assignment for fine-grained access control
- **Subnet Routing**: Enable pods to advertise cluster networks to Tailscale
- **Exit Nodes**: Create Kubernetes-based exit nodes for internet traffic
- **Multiple Auth Methods**: Support for auth keys, OAuth, and ephemeral nodes
- **Production Ready**: High availability, monitoring, and security best practices

## Quick Start

### Prerequisites

- Kubernetes cluster (1.19+)
- kubectl configured to access your cluster
- Tailscale account and auth key
- cert-manager (recommended) or manual certificate management

### Installation

1. **Install the webhook using kubectl:**

```bash
# Clone the repository
git clone https://github.com/phildougherty/tailscale-injection-webhook.git
cd tailscale-injection-webhook

# Create the tailscale-system namespace
kubectl apply -f deploy/manifests/rbac.yaml

# Create your auth key secret
kubectl create secret generic tailscale-auth-key \
  --from-literal=authkey=tskey-auth-your-key-here \
  -n tailscale-system

# Deploy the webhook
kubectl apply -f deploy/manifests/certificates.yaml
kubectl apply -f deploy/manifests/webhook.yaml
```

2. **Verify the installation:**

```bash
kubectl get pods -n tailscale-system
kubectl logs -n tailscale-system deployment/tailscale-injection-webhook
```

3. **Test with a simple pod:**

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  annotations:
    tailscale.com/inject: "true"
spec:
  containers:
  - name: app
    image: nginx:latest
    ports:
    - containerPort: 80
EOF
```

## Usage

### Basic Injection

To inject a Tailscale sidecar into a pod, add the `tailscale.com/inject: "true"` annotation:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  annotations:
    tailscale.com/inject: "true"
spec:
  containers:
  - name: app
    image: myapp:latest
```

### Advanced Configuration

The webhook supports numerous annotations for customization:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: advanced-app
  annotations:
    # Basic injection
    tailscale.com/inject: "true"

    # Custom hostname (optional)
    tailscale.com/hostname: "my-app-prod"

    # Tags for ACL management
    tailscale.com/tags: '["tag:web-frontend", "tag:production"]'

    # Custom auth key secret
    tailscale.com/auth-key: "production-auth-key"

    # Network configuration
    tailscale.com/accept-routes: "true"
    tailscale.com/userspace: "false"

    # Expose application ports
    tailscale.com/expose: "3000,8080"

    # Debug mode
    tailscale.com/debug: "false"
spec:
  containers:
  - name: app
    image: myapp:latest
    ports:
    - containerPort: 3000
```

### Supported Annotations

| Annotation | Description | Default | Example |
|------------|-------------|---------|---------|
| `tailscale.com/inject` | Enable injection | `false` | `"true"` |
| `tailscale.com/hostname` | Custom hostname | Pod name | `"web-frontend"` |
| `tailscale.com/tags` | Tailscale tags | `["tag:k8s"]` | `'["tag:web", "tag:prod"]'` |
| `tailscale.com/auth-key` | Auth key secret name | `tailscale-auth-key` | `"custom-auth-key"` |
| `tailscale.com/userspace` | Userspace networking | `false` | `"true"` |
| `tailscale.com/accept-routes` | Accept subnet routes | `false` | `"true"` |
| `tailscale.com/subnet-router` | Advertise routes | None | `"10.0.0.0/8,192.168.1.0/24"` |
| `tailscale.com/exit-node` | Advertise as exit node | `false` | `"true"` |
| `tailscale.com/expose` | Expose ports | None | `"80,443,8080"` |
| `tailscale.com/debug` | Debug logging | `false` | `"true"` |

## Configuration

### Webhook Configuration

The webhook can be configured via environment variables or a configuration file:

```yaml
# config/webhook-config.yaml
webhook:
  port: 8443
  certFile: /etc/certs/tls.crt
  keyFile: /etc/certs/tls.key

injection:
  defaultImage: tailscale/tailscale:v1.52.1
  defaultUserspace: false
  defaultDebug: false
  resources:
    requests:
      cpu: 10m
      memory: 32Mi
    limits:
      cpu: 100m
      memory: 128Mi

tags:
  autoGenerate: true
  defaultTags:
    - tag:k8s
  rules:
    namespace: true
    environment: true
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TAILSCALE_WEBHOOK_PORT` | Webhook server port | `8443` |
| `TAILSCALE_WEBHOOK_BIND_ADDRESS` | Bind address | `0.0.0.0` |
| `TAILSCALE_WEBHOOK_TLS_CERT_FILE` | TLS certificate path | `/etc/certs/tls.crt` |
| `TAILSCALE_WEBHOOK_TLS_KEY_FILE` | TLS key path | `/etc/certs/tls.key` |
| `TAILSCALE_WEBHOOK_CONFIG_FILE` | Config file path | `/etc/config/config.yaml` |

## Examples

### Subnet Router

Create a subnet router to expose cluster networks:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: subnet-router
spec:
  template:
    metadata:
      annotations:
        tailscale.com/inject: "true"
        tailscale.com/hostname: "k8s-subnet-router"
        tailscale.com/subnet-router: "10.96.0.0/12,10.244.0.0/16"
        tailscale.com/tags: '["tag:subnet-router", "tag:k8s-infra"]'
    spec:
      hostNetwork: true
      containers:
      - name: router
        image: alpine:latest
        command: ["sleep", "infinity"]
```

### Exit Node

Create an exit node for internet traffic routing:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: exit-node
spec:
  template:
    metadata:
      annotations:
        tailscale.com/inject: "true"
        tailscale.com/hostname: "k8s-exit-node"
        tailscale.com/exit-node: "true"
        tailscale.com/tags: '["tag:exit-node", "tag:k8s-infra"]'
    spec:
      hostNetwork: true
      containers:
      - name: exit-node
        image: alpine:latest
        command: ["sleep", "infinity"]
```

### Userspace Mode

For environments where privileged containers aren't allowed:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: userspace-app
  annotations:
    tailscale.com/inject: "true"
    tailscale.com/userspace: "true"
    tailscale.com/tags: '["tag:userspace", "tag:secure"]'
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
  containers:
  - name: app
    image: nginx:alpine
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: [ALL]
```

## Security

### Authentication

The webhook supports multiple authentication methods:

1. **Auth Keys**: Pre-shared keys with specific permissions
2. **OAuth**: Integration with Tailscale OAuth providers
3. **Ephemeral Nodes**: Short-lived nodes for temporary workloads

### Authorization

Access control is managed through Tailscale ACLs and tags:

```json
{
  "tagOwners": {
    "tag:k8s": ["group:k8s-admins"],
    "tag:production": ["group:production-team"]
  },
  "acls": [
    {
      "action": "accept",
      "src": ["tag:k8s"],
      "dst": ["tag:k8s:*"]
    }
  ]
}
```

### Pod Security

The webhook enforces security best practices:

- Non-root execution for userspace mode
- Minimal capabilities for kernel mode
- Read-only root filesystems where possible
- Network policies for traffic isolation

## Monitoring

### Metrics

The webhook exposes Prometheus metrics on port 8080:

- `tailscale_webhook_injections_total`: Total number of injections
- `tailscale_webhook_injection_duration_seconds`: Injection duration
- `tailscale_webhook_validation_errors_total`: Validation errors
- `tailscale_sidecar_status`: Sidecar container status

### Health Checks

- Health endpoint: `GET /health`
- Readiness endpoint: `GET /ready`
- Metrics endpoint: `GET /metrics`

### Logging

Structured logging with configurable levels:

```json
{
  "level": "info",
  "time": "2023-10-01T10:00:00Z",
  "msg": "Injecting Tailscale sidecar",
  "namespace": "production",
  "pod": "web-frontend-abc123",
  "hostname": "web-frontend-prod"
}
```

## Troubleshooting

### Common Issues

1. **Injection not happening**
   - Check webhook configuration and certificates
   - Verify namespace selectors and object selectors
   - Check admission controller logs

2. **Sidecar fails to start**
   - Verify auth key secret exists and is valid
   - Check Tailscale service connectivity
   - Review sidecar container logs

3. **Networking issues**
   - Verify security contexts for kernel vs userspace mode
   - Check network policies and firewall rules
   - Ensure proper capabilities are set

### Debug Mode

Enable debug logging for troubleshooting:

```yaml
metadata:
  annotations:
    tailscale.com/inject: "true"
    tailscale.com/debug: "true"
```

### Logs

Check various log sources:

```bash
# Webhook logs
kubectl logs -n tailscale-system deployment/tailscale-injection-webhook

# Sidecar logs
kubectl logs <pod-name> -c tailscale

# Admission controller events
kubectl get events --field-selector reason=AdmissionWebhook
```

## Development

### Building

```bash
# Build the binary
make build

# Build Docker image
make docker-build

# Run tests
make test

# Run linting
make lint
```

### Local Development

```bash
# Install dependencies
go mod download

# Run locally (requires kubeconfig)
go run cmd/webhook/main.go --kubeconfig ~/.kube/config --tls-cert-file=cert.pem --tls-key-file=key.pem
```

### Testing

```bash
# Run unit tests
make test-unit

# Run integration tests
make test-integration

# Run end-to-end tests
make test-e2e
```

## Helm Chart

Deploy using Helm for production environments:

```bash
# Add the Helm repository
helm repo add phildougherty https://phildougherty.github.io/tailscale-injection-webhook

# Install the chart
helm install tailscale-injector phildougherty/tailscale-injection-webhook \
  --namespace tailscale-system \
  --create-namespace \
  --set authKey.value=tskey-auth-your-key-here
```

### Helm Values

```yaml
# values.yaml
image:
  repository: phildougherty/tailscale-injection-webhook
  tag: v1.0.0
  pullPolicy: IfNotPresent

webhook:
  port: 8443
  failurePolicy: Fail

injection:
  defaultImage: tailscale/tailscale:v1.52.1
  defaultUserspace: false

authKey:
  # Auth key value (required)
  value: ""
  # Or reference existing secret
  secretName: ""
  secretKey: "authkey"

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi

monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
```

## Migration

### From Manual Sidecars

If you're currently using manual Tailscale sidecars:

1. Remove existing sidecar containers from your deployments
2. Add the injection annotation
3. Update any hardcoded networking assumptions

### From Other Service Meshes

The webhook can coexist with other service meshes:

- Istio: Use different injection selectors
- Linkerd: Ensure proxy-init doesn't conflict
- Consul Connect: Coordinate port usage

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include logs, configurations, and steps to reproduce
- Check existing issues before creating new ones

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [https://tailscale.com/kb/](https://tailscale.com/kb/)
- **Community**: [https://github.com/tailscale/tailscale/discussions](https://github.com/tailscale/tailscale/discussions)
- **Issues**: [https://github.com/phildougherty/tailscale-injection-webhook/issues](https://github.com/phildougherty/tailscale-injection-webhook/issues)

## Acknowledgments

- Tailscale team for the excellent mesh networking platform
- Kubernetes community for the admission webhook framework
- Contributors and users who make this project possible