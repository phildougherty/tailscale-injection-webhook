package injection

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"github.com/phildougherty/tailscale-injection-webhook/pkg/tailscale"
)

const (
	// Container names
	TailscaleContainerName     = "tailscale"
	TailscaleInitContainerName = "tailscale-init"

	// Volume names
	TailscaleVarVolume  = "tailscale-var"
	TailscaleTmpVolume  = "tailscale-tmp"
	TailscaleAuthVolume = "tailscale-auth"

	// Default paths
	TailscaleStatePath  = "/var/lib/tailscale"
	TailscaleSocketPath = "/var/run/tailscale"
	TailscaleAuthPath   = "/var/secrets/tailscale"
)

// Injector handles the injection of Tailscale sidecars into pods
type Injector struct {
	client kubernetes.Interface
	auth   *tailscale.Authenticator
}

// NewInjector creates a new Tailscale sidecar injector
func NewInjector(client kubernetes.Interface, auth *tailscale.Authenticator) *Injector {
	return &Injector{
		client: client,
		auth:   auth,
	}
}

// Patch represents a JSON patch operation
type Patch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// InjectSidecar injects a Tailscale sidecar into the given pod
func (i *Injector) InjectSidecar(pod *corev1.Pod, config *Config) ([]Patch, error) {
	klog.InfoS("Injecting Tailscale sidecar",
		"namespace", config.Namespace,
		"pod", config.PodName,
		"hostname", config.Hostname,
	)

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	var patches []Patch

	// Add volumes
	volumePatches := i.createVolumePatches(pod, config)
	patches = append(patches, volumePatches...)

	// Add init container
	initContainerPatch := i.createInitContainerPatch(pod, config)
	patches = append(patches, initContainerPatch)

	// Add sidecar container
	sidecarPatch := i.createSidecarContainerPatch(pod, config)
	patches = append(patches, sidecarPatch)

	// Add annotations
	annotationPatches := i.createAnnotationPatches(pod, config)
	patches = append(patches, annotationPatches...)

	// Modify existing containers to share network with Tailscale
	containerPatches := i.createContainerPatches(pod, config)
	patches = append(patches, containerPatches...)

	klog.InfoS("Generated injection patches",
		"namespace", config.Namespace,
		"pod", config.PodName,
		"patchCount", len(patches),
	)

	return patches, nil
}

// createVolumePatches creates patches to add required volumes
func (i *Injector) createVolumePatches(pod *corev1.Pod, config *Config) []Patch {
	var patches []Patch

	volumes := []corev1.Volume{
		{
			Name: TailscaleVarVolume,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: TailscaleTmpVolume,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: TailscaleAuthVolume,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: config.AuthKeySecret,
				},
			},
		},
	}

	for idx, volume := range volumes {
		path := fmt.Sprintf("/spec/volumes/%d", len(pod.Spec.Volumes)+idx)
		patches = append(patches, Patch{
			Op:    "add",
			Path:  path,
			Value: volume,
		})
	}

	return patches
}

// createInitContainerPatch creates a patch to add the Tailscale init container
func (i *Injector) createInitContainerPatch(pod *corev1.Pod, config *Config) Patch {
	initContainer := i.createTailscaleInitContainer(config)
	path := fmt.Sprintf("/spec/initContainers/%d", len(pod.Spec.InitContainers))

	return Patch{
		Op:    "add",
		Path:  path,
		Value: initContainer,
	}
}

// createSidecarContainerPatch creates a patch to add the Tailscale sidecar container
func (i *Injector) createSidecarContainerPatch(pod *corev1.Pod, config *Config) Patch {
	sidecarContainer := i.createTailscaleContainer(config)
	path := fmt.Sprintf("/spec/containers/%d", len(pod.Spec.Containers))

	return Patch{
		Op:    "add",
		Path:  path,
		Value: sidecarContainer,
	}
}

// createAnnotationPatches creates patches to add Tailscale annotations
func (i *Injector) createAnnotationPatches(pod *corev1.Pod, config *Config) []Patch {
	var patches []Patch

	annotations := map[string]string{
		"tailscale.com/injected":         "true",
		"tailscale.com/injected-version": "v1.0.0",
		"tailscale.com/hostname":         config.Hostname,
	}

	if len(config.Tags) > 0 {
		tagsJSON, _ := json.Marshal(config.Tags)
		annotations["tailscale.com/injected-tags"] = string(tagsJSON)
	}

	// Add annotations
	if pod.Annotations == nil {
		patches = append(patches, Patch{
			Op:    "add",
			Path:  "/metadata/annotations",
			Value: annotations,
		})
	} else {
		for key, value := range annotations {
			escapedKey := escapeJSONPointer(key)
			patches = append(patches, Patch{
				Op:    "add",
				Path:  fmt.Sprintf("/metadata/annotations/%s", escapedKey),
				Value: value,
			})
		}
	}

	return patches
}

// createContainerPatches creates patches to modify existing containers
func (i *Injector) createContainerPatches(pod *corev1.Pod, config *Config) []Patch {
	var patches []Patch

	// For each existing container, add environment variables if needed
	for idx := range pod.Spec.Containers {
		// Add volume mounts for accessing Tailscale socket
		volumeMountPath := fmt.Sprintf("/spec/containers/%d/volumeMounts", idx)

		volumeMounts := []corev1.VolumeMount{
			{
				Name:      TailscaleVarVolume,
				MountPath: TailscaleStatePath,
				ReadOnly:  true,
			},
		}

		// Add volume mounts to existing containers if they need Tailscale access
		if len(pod.Spec.Containers[idx].VolumeMounts) == 0 {
			patches = append(patches, Patch{
				Op:    "add",
				Path:  volumeMountPath,
				Value: volumeMounts,
			})
		} else {
			for vmIdx, vm := range volumeMounts {
				path := fmt.Sprintf("%s/%d", volumeMountPath, len(pod.Spec.Containers[idx].VolumeMounts)+vmIdx)
				patches = append(patches, Patch{
					Op:    "add",
					Path:  path,
					Value: vm,
				})
			}
		}
	}

	return patches
}

// createTailscaleInitContainer creates the Tailscale init container
func (i *Injector) createTailscaleInitContainer(config *Config) corev1.Container {
	env := i.createEnvironmentVariables(config)
	resources := i.createResourceRequirements(config)

	return corev1.Container{
		Name:            TailscaleInitContainerName,
		Image:           config.Image,
		ImagePullPolicy: corev1.PullPolicy(config.ImagePullPolicy),
		Command:         []string{"/bin/sh"},
		Args: []string{
			"-c",
			`set -e
echo "Initializing Tailscale..."
mkdir -p /var/lib/tailscale /var/run/tailscale
echo "Tailscale initialization complete"`,
		},
		Env:       env,
		Resources: resources,
		SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN"},
			},
			Privileged: &[]bool{!config.Userspace}[0],
		},
		VolumeMounts: []corev1.VolumeMount{
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
		},
	}
}

// createTailscaleContainer creates the Tailscale sidecar container
func (i *Injector) createTailscaleContainer(config *Config) corev1.Container {
	env := i.createEnvironmentVariables(config)
	resources := i.createResourceRequirements(config)

	return corev1.Container{
		Name:            TailscaleContainerName,
		Image:           config.Image,
		ImagePullPolicy: corev1.PullPolicy(config.ImagePullPolicy),
		Command:         []string{"/bin/sh"},
		Args: []string{
			"-c",
			i.createStartupScript(config),
		},
		Env:       env,
		Resources: resources,
		SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN"},
			},
			Privileged: &[]bool{!config.Userspace}[0],
		},
		VolumeMounts: []corev1.VolumeMount{
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
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"tailscale",
						"status",
					},
				},
			},
			InitialDelaySeconds: 30,
			PeriodSeconds:       10,
			TimeoutSeconds:      5,
			FailureThreshold:    3,
		},
		ReadinessProbe: &corev1.Probe{
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
			PeriodSeconds:       5,
			TimeoutSeconds:      3,
			FailureThreshold:    3,
		},
	}
}

// createEnvironmentVariables creates environment variables for the Tailscale container
func (i *Injector) createEnvironmentVariables(config *Config) []corev1.EnvVar {
	var envVars []corev1.EnvVar

	envMap := config.GetEnvironmentVariables()
	for key, value := range envMap {
		envVars = append(envVars, corev1.EnvVar{
			Name:  key,
			Value: value,
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

// createResourceRequirements creates resource requirements for the container
func (i *Injector) createResourceRequirements(config *Config) corev1.ResourceRequirements {
	if config.Resources == nil {
		return corev1.ResourceRequirements{}
	}

	requirements := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{},
		Limits:   corev1.ResourceList{},
	}

	if config.Resources.Requests.CPU != "" {
		requirements.Requests[corev1.ResourceCPU] = resource.MustParse(config.Resources.Requests.CPU)
	}
	if config.Resources.Requests.Memory != "" {
		requirements.Requests[corev1.ResourceMemory] = resource.MustParse(config.Resources.Requests.Memory)
	}
	if config.Resources.Limits.CPU != "" {
		requirements.Limits[corev1.ResourceCPU] = resource.MustParse(config.Resources.Limits.CPU)
	}
	if config.Resources.Limits.Memory != "" {
		requirements.Limits[corev1.ResourceMemory] = resource.MustParse(config.Resources.Limits.Memory)
	}

	return requirements
}

// createStartupScript creates the startup script for the Tailscale container
func (i *Injector) createStartupScript(config *Config) string {
	script := `set -e
echo "Starting Tailscale daemon..."

# Start tailscaled in the background
tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/var/run/tailscale/tailscaled.sock`

	if config.Userspace {
		script += ` --tun=userspace-networking`
	}

	if config.Debug {
		script += ` --verbose=2`
	}

	script += ` &
TAILSCALED_PID=$!

# Wait for tailscaled to start
sleep 5

# Authenticate with Tailscale
echo "Authenticating with Tailscale..."
tailscale up --authkey="$TS_AUTHKEY" --accept-dns=false`

	if config.Hostname != "" {
		script += fmt.Sprintf(` --hostname="%s"`, config.Hostname)
	}

	if len(config.Tags) > 0 {
		script += fmt.Sprintf(` --advertise-tags="%s"`, joinStrings(config.Tags, ","))
	}

	if config.ExitNode {
		script += ` --advertise-exit-node`
	}

	if len(config.SubnetRoutes) > 0 {
		script += fmt.Sprintf(` --advertise-routes="%s"`, joinStrings(config.SubnetRoutes, ","))
	}

	if config.AcceptRoutes {
		script += ` --accept-routes`
	}

	script += `

echo "Tailscale connected successfully"
tailscale status

# Keep the container running
wait $TAILSCALED_PID`

	return script
}

// escapeJSONPointer escapes a string for use in a JSON pointer
func escapeJSONPointer(s string) string {
	// Replace ~ with ~0 and / with ~1
	result := ""
	for _, char := range s {
		switch char {
		case '~':
			result += "~0"
		case '/':
			result += "~1"
		default:
			result += string(char)
		}
	}
	return result
}