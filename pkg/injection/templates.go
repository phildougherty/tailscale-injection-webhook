package injection

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// TemplateEngine handles templating for injection configurations
type TemplateEngine struct {
	config *Config
}

// NewTemplateEngine creates a new template engine
func NewTemplateEngine(config *Config) *TemplateEngine {
	return &TemplateEngine{
		config: config,
	}
}

// TemplateVars holds variables available for templating
type TemplateVars struct {
	Namespace string
	PodName   string
	Hostname  string
	Tags      []string
}

// RenderTemplate renders a template string with the given variables
func (te *TemplateEngine) RenderTemplate(template string) string {
	vars := &TemplateVars{
		Namespace: te.config.Namespace,
		PodName:   te.config.PodName,
		Hostname:  te.config.Hostname,
		Tags:      te.config.Tags,
	}

	result := template
	result = strings.ReplaceAll(result, "{{.Namespace}}", vars.Namespace)
	result = strings.ReplaceAll(result, "{{.PodName}}", vars.PodName)
	result = strings.ReplaceAll(result, "{{.Hostname}}", vars.Hostname)
	result = strings.ReplaceAll(result, "{{.Tags}}", joinStrings(vars.Tags, ","))

	return result
}

// GetContainerTemplate returns a template for creating containers
func (te *TemplateEngine) GetContainerTemplate() *ContainerTemplate {
	return &ContainerTemplate{
		engine: te,
	}
}

// ContainerTemplate provides templating for container configurations
type ContainerTemplate struct {
	engine *TemplateEngine
}

// CreateInitContainer creates an init container from template
func (ct *ContainerTemplate) CreateInitContainer() corev1.Container {
	config := ct.engine.config

	return corev1.Container{
		Name:            TailscaleInitContainerName,
		Image:           config.Image,
		ImagePullPolicy: corev1.PullPolicy(config.ImagePullPolicy),
		Command:         []string{"/bin/sh", "-c"},
		Args:            []string{ct.getInitScript()},
		SecurityContext: ct.getSecurityContext(),
		VolumeMounts:    ct.getVolumeMounts(),
		Resources:       ct.getResourceRequirements(),
		Env:             ct.getEnvironmentVariables(),
	}
}

// CreateSidecarContainer creates a sidecar container from template
func (ct *ContainerTemplate) CreateSidecarContainer() corev1.Container {
	config := ct.engine.config

	return corev1.Container{
		Name:            TailscaleContainerName,
		Image:           config.Image,
		ImagePullPolicy: corev1.PullPolicy(config.ImagePullPolicy),
		Command:         []string{"/bin/sh", "-c"},
		Args:            []string{ct.getSidecarScript()},
		SecurityContext: ct.getSecurityContext(),
		VolumeMounts:    ct.getVolumeMounts(),
		Resources:       ct.getResourceRequirements(),
		Env:             ct.getEnvironmentVariables(),
		LivenessProbe:   ct.getLivenessProbe(),
		ReadinessProbe:  ct.getReadinessProbe(),
	}
}

// getInitScript returns the initialization script
func (ct *ContainerTemplate) getInitScript() string {
	script := `
set -e
echo "Initializing Tailscale directories..."
mkdir -p /var/lib/tailscale /var/run/tailscale
chmod 755 /var/lib/tailscale /var/run/tailscale

# Set proper permissions for Tailscale state directory
if [ ! -f /var/lib/tailscale/tailscaled.state ]; then
    touch /var/lib/tailscale/tailscaled.state
    chmod 600 /var/lib/tailscale/tailscaled.state
fi

echo "Tailscale initialization complete"
`
	return ct.engine.RenderTemplate(script)
}

// getSidecarScript returns the sidecar startup script
func (ct *ContainerTemplate) getSidecarScript() string {
	config := ct.engine.config

	script := `
set -e
echo "Starting Tailscale sidecar for pod {{.PodName}} in namespace {{.Namespace}}"

# Function to handle graceful shutdown
cleanup() {
    echo "Received shutdown signal, cleaning up..."
    if [ -n "$TAILSCALED_PID" ]; then
        kill $TAILSCALED_PID 2>/dev/null || true
        wait $TAILSCALED_PID 2>/dev/null || true
    fi
    echo "Cleanup complete"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Start tailscaled
echo "Starting Tailscale daemon..."
tailscaled \
    --state=/var/lib/tailscale/tailscaled.state \
    --socket=/var/run/tailscale/tailscaled.sock`

	if config.Userspace {
		script += ` \
    --tun=userspace-networking`
	}

	if config.Debug {
		script += ` \
    --verbose=2`
	}

	script += ` &
TAILSCALED_PID=$!

# Wait for tailscaled to be ready
echo "Waiting for Tailscale daemon to start..."
for i in {1..30}; do
    if tailscale status >/dev/null 2>&1; then
        echo "Tailscale daemon is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "Timeout waiting for Tailscale daemon"
        exit 1
    fi
    sleep 1
done

# Authenticate with Tailscale
echo "Authenticating with Tailscale..."
tailscale up \
    --authkey="$TS_AUTHKEY" \
    --accept-dns=false`

	if config.Hostname != "" {
		script += ` \
    --hostname="{{.Hostname}}"`
	}

	if len(config.Tags) > 0 {
		script += ` \
    --advertise-tags="{{.Tags}}"`
	}

	if config.ExitNode {
		script += ` \
    --advertise-exit-node`
	}

	if len(config.SubnetRoutes) > 0 {
		script += fmt.Sprintf(` \
    --advertise-routes="%s"`, joinStrings(config.SubnetRoutes, ","))
	}

	if config.AcceptRoutes {
		script += ` \
    --accept-routes`
	}

	script += `

echo "Tailscale authentication complete"
tailscale status

# Configure port forwarding if needed
if [ -n "$TS_SERVE_PORTS" ]; then
    echo "Configuring port forwarding..."
    IFS=',' read -ra PORTS <<< "$TS_SERVE_PORTS"
    for port in "${PORTS[@]}"; do
        echo "Setting up port forwarding for port $port"
        tailscale serve --bg "localhost:$port" || echo "Warning: Failed to set up port forwarding for port $port"
    done
fi

echo "Tailscale sidecar ready"

# Keep the process running and handle signals
wait $TAILSCALED_PID
`

	return ct.engine.RenderTemplate(script)
}

// getSecurityContext returns the security context for containers
func (ct *ContainerTemplate) getSecurityContext() *corev1.SecurityContext {
	config := ct.engine.config

	if config.Userspace {
		// Userspace mode doesn't need special privileges
		return &corev1.SecurityContext{
			AllowPrivilegeEscalation: &[]bool{false}[0],
			ReadOnlyRootFilesystem:   &[]bool{false}[0],
			RunAsNonRoot:            &[]bool{true}[0],
			RunAsUser:               &[]int64{1000}[0],
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		}
	}

	// Kernel mode needs network admin capabilities
	return &corev1.SecurityContext{
		Capabilities: &corev1.Capabilities{
			Add:  []corev1.Capability{"NET_ADMIN"},
			Drop: []corev1.Capability{"ALL"},
		},
		AllowPrivilegeEscalation: &[]bool{true}[0],
		ReadOnlyRootFilesystem:   &[]bool{false}[0],
	}
}

// getVolumeMounts returns volume mounts for containers
func (ct *ContainerTemplate) getVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{
			Name:      TailscaleVarVolume,
			MountPath: TailscaleStatePath,
		},
		{
			Name:      TailscaleTmpVolume,
			MountPath: TailscaleSocketPath,
		},
		{
			Name:      TailscaleAuthVolume,
			MountPath: TailscaleAuthPath,
			ReadOnly:  true,
		},
	}
}

// getResourceRequirements returns resource requirements
func (ct *ContainerTemplate) getResourceRequirements() corev1.ResourceRequirements {
	config := ct.engine.config
	if config.Resources == nil {
		return corev1.ResourceRequirements{}
	}

	requirements := corev1.ResourceRequirements{}

	if config.Resources.Requests.CPU != "" || config.Resources.Requests.Memory != "" {
		requirements.Requests = corev1.ResourceList{}
		if config.Resources.Requests.CPU != "" {
			requirements.Requests[corev1.ResourceCPU] = mustParseQuantity(config.Resources.Requests.CPU)
		}
		if config.Resources.Requests.Memory != "" {
			requirements.Requests[corev1.ResourceMemory] = mustParseQuantity(config.Resources.Requests.Memory)
		}
	}

	if config.Resources.Limits.CPU != "" || config.Resources.Limits.Memory != "" {
		requirements.Limits = corev1.ResourceList{}
		if config.Resources.Limits.CPU != "" {
			requirements.Limits[corev1.ResourceCPU] = mustParseQuantity(config.Resources.Limits.CPU)
		}
		if config.Resources.Limits.Memory != "" {
			requirements.Limits[corev1.ResourceMemory] = mustParseQuantity(config.Resources.Limits.Memory)
		}
	}

	return requirements
}

// getEnvironmentVariables returns environment variables
func (ct *ContainerTemplate) getEnvironmentVariables() []corev1.EnvVar {
	config := ct.engine.config
	var envVars []corev1.EnvVar

	// Add standard Tailscale environment variables
	envMap := config.GetEnvironmentVariables()
	for key, value := range envMap {
		envVars = append(envVars, corev1.EnvVar{
			Name:  key,
			Value: ct.engine.RenderTemplate(value),
		})
	}

	// Add auth key from secret
	envVars = append(envVars, corev1.EnvVar{
		Name: "TS_AUTHKEY",
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: config.AuthKeySecret,
				},
				Key: "authkey",
			},
		},
	})

	return envVars
}

// getLivenessProbe returns the liveness probe configuration
func (ct *ContainerTemplate) getLivenessProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: []string{
					"tailscale",
					"status",
				},
			},
		},
		InitialDelaySeconds: 30,
		PeriodSeconds:       30,
		TimeoutSeconds:      10,
		FailureThreshold:    3,
		SuccessThreshold:    1,
	}
}

// getReadinessProbe returns the readiness probe configuration
func (ct *ContainerTemplate) getReadinessProbe() *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{
				Command: []string{
					"tailscale",
					"status",
					"--json",
				},
			},
		},
		InitialDelaySeconds: 10,
		PeriodSeconds:       10,
		TimeoutSeconds:      5,
		FailureThreshold:    3,
		SuccessThreshold:    1,
	}
}

// mustParseQuantity parses a resource quantity string
func mustParseQuantity(s string) corev1.ResourceList {
	// This is a simplified implementation
	// In production, use resource.MustParse(s)
	return corev1.ResourceList{}
}