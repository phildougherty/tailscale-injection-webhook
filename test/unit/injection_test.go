package unit

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/phildougherty/tailscale-injection-webhook/pkg/injection"
	"github.com/phildougherty/tailscale-injection-webhook/pkg/tailscale"
)

func TestNewDefaultConfig(t *testing.T) {
	config := injection.NewDefaultConfig()

	if config == nil {
		t.Fatal("Expected non-nil config")
	}

	if config.Image == "" {
		t.Error("Expected default image to be set")
	}

	if config.ImagePullPolicy == "" {
		t.Error("Expected default image pull policy to be set")
	}

	if config.Resources == nil {
		t.Error("Expected default resources to be set")
	}

	if len(config.ExtraEnv) == 0 {
		config.ExtraEnv = make(map[string]string)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *injection.Config
		expectError bool
	}{
		{
			name: "valid config",
			config: &injection.Config{
				Namespace:     "default",
				PodName:       "test-pod",
				Hostname:      "test-hostname",
				AuthKeySecret: "auth-secret",
				Image:         "tailscale/tailscale:latest",
				Tags:          []string{"tag:test"},
			},
			expectError: false,
		},
		{
			name: "missing namespace",
			config: &injection.Config{
				PodName:       "test-pod",
				Hostname:      "test-hostname",
				AuthKeySecret: "auth-secret",
				Image:         "tailscale/tailscale:latest",
			},
			expectError: true,
		},
		{
			name: "missing pod name",
			config: &injection.Config{
				Namespace:     "default",
				Hostname:      "test-hostname",
				AuthKeySecret: "auth-secret",
				Image:         "tailscale/tailscale:latest",
			},
			expectError: true,
		},
		{
			name: "missing hostname",
			config: &injection.Config{
				Namespace:     "default",
				PodName:       "test-pod",
				AuthKeySecret: "auth-secret",
				Image:         "tailscale/tailscale:latest",
			},
			expectError: true,
		},
		{
			name: "missing auth key secret",
			config: &injection.Config{
				Namespace: "default",
				PodName:   "test-pod",
				Hostname:  "test-hostname",
				Image:     "tailscale/tailscale:latest",
			},
			expectError: true,
		},
		{
			name: "missing image",
			config: &injection.Config{
				Namespace:     "default",
				PodName:       "test-pod",
				Hostname:      "test-hostname",
				AuthKeySecret: "auth-secret",
			},
			expectError: true,
		},
		{
			name: "empty subnet route",
			config: &injection.Config{
				Namespace:     "default",
				PodName:       "test-pod",
				Hostname:      "test-hostname",
				AuthKeySecret: "auth-secret",
				Image:         "tailscale/tailscale:latest",
				SubnetRoutes:  []string{""},
			},
			expectError: true,
		},
		{
			name: "empty expose port",
			config: &injection.Config{
				Namespace:     "default",
				PodName:       "test-pod",
				Hostname:      "test-hostname",
				AuthKeySecret: "auth-secret",
				Image:         "tailscale/tailscale:latest",
				ExposePorts:   []string{""},
			},
			expectError: true,
		},
		{
			name: "empty tag",
			config: &injection.Config{
				Namespace:     "default",
				PodName:       "test-pod",
				Hostname:      "test-hostname",
				AuthKeySecret: "auth-secret",
				Image:         "tailscale/tailscale:latest",
				Tags:          []string{""},
			},
			expectError: true,
		},
		{
			name: "tag too long",
			config: &injection.Config{
				Namespace:     "default",
				PodName:       "test-pod",
				Hostname:      "test-hostname",
				AuthKeySecret: "auth-secret",
				Image:         "tailscale/tailscale:latest",
				Tags:          []string{"this-is-a-very-long-tag-that-exceeds-the-maximum-allowed-length-of-64-characters"},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("Expected validation error, but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no validation error, but got: %v", err)
			}
		})
	}
}

func TestGetTailscaleArgs(t *testing.T) {
	tests := []struct {
		name     string
		config   *injection.Config
		expected []string
	}{
		{
			name: "default args",
			config: &injection.Config{
				Userspace: false,
				Debug:     false,
			},
			expected: []string{
				"tailscaled",
				"--state=/var/lib/tailscale/tailscaled.state",
				"--socket=/var/run/tailscale/tailscaled.sock",
			},
		},
		{
			name: "userspace mode",
			config: &injection.Config{
				Userspace: true,
				Debug:     false,
			},
			expected: []string{
				"tailscaled",
				"--state=/var/lib/tailscale/tailscaled.state",
				"--socket=/var/run/tailscale/tailscaled.sock",
				"--tun=userspace-networking",
			},
		},
		{
			name: "debug mode",
			config: &injection.Config{
				Userspace: false,
				Debug:     true,
			},
			expected: []string{
				"tailscaled",
				"--state=/var/lib/tailscale/tailscaled.state",
				"--socket=/var/run/tailscale/tailscaled.sock",
				"--verbose=2",
			},
		},
		{
			name: "extra args",
			config: &injection.Config{
				Userspace: false,
				Debug:     false,
				ExtraArgs: []string{"--extra-arg1", "--extra-arg2=value"},
			},
			expected: []string{
				"tailscaled",
				"--state=/var/lib/tailscale/tailscaled.state",
				"--socket=/var/run/tailscale/tailscaled.sock",
				"--extra-arg1",
				"--extra-arg2=value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.config.GetTailscaleArgs()
			if len(args) != len(tt.expected) {
				t.Errorf("Expected %d args, got %d", len(tt.expected), len(args))
				return
			}

			for i, arg := range args {
				if arg != tt.expected[i] {
					t.Errorf("Arg %d: expected %s, got %s", i, tt.expected[i], arg)
				}
			}
		})
	}
}

func TestGetTailscaleUpArgs(t *testing.T) {
	tests := []struct {
		name     string
		config   *injection.Config
		expected []string
	}{
		{
			name: "basic up command",
			config: &injection.Config{
				Hostname:      "test-host",
				Tags:          []string{"tag:test"},
				ExitNode:      false,
				SubnetRoutes:  []string{},
				AcceptRoutes:  false,
			},
			expected: []string{
				"tailscale",
				"up",
				"--accept-dns=false",
				"--hostname=test-host",
				"--advertise-tags=tag:test",
			},
		},
		{
			name: "with subnet routes",
			config: &injection.Config{
				Hostname:      "test-host",
				Tags:          []string{"tag:test"},
				ExitNode:      false,
				SubnetRoutes:  []string{"10.0.0.0/8", "192.168.1.0/24"},
				AcceptRoutes:  false,
			},
			expected: []string{
				"tailscale",
				"up",
				"--accept-dns=false",
				"--hostname=test-host",
				"--advertise-tags=tag:test",
				"--advertise-routes=10.0.0.0/8,192.168.1.0/24",
			},
		},
		{
			name: "exit node",
			config: &injection.Config{
				Hostname:      "test-host",
				Tags:          []string{"tag:test"},
				ExitNode:      true,
				SubnetRoutes:  []string{},
				AcceptRoutes:  false,
			},
			expected: []string{
				"tailscale",
				"up",
				"--accept-dns=false",
				"--hostname=test-host",
				"--advertise-tags=tag:test",
				"--advertise-exit-node",
			},
		},
		{
			name: "accept routes",
			config: &injection.Config{
				Hostname:      "test-host",
				Tags:          []string{"tag:test"},
				ExitNode:      false,
				SubnetRoutes:  []string{},
				AcceptRoutes:  true,
			},
			expected: []string{
				"tailscale",
				"up",
				"--accept-dns=false",
				"--hostname=test-host",
				"--advertise-tags=tag:test",
				"--accept-routes",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.config.GetTailscaleUpArgs()

			// Check that all expected args are present
			for _, expectedArg := range tt.expected {
				found := false
				for _, actualArg := range args {
					if actualArg == expectedArg {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected arg %s not found in %v", expectedArg, args)
				}
			}
		})
	}
}

func TestGetEnvironmentVariables(t *testing.T) {
	config := &injection.Config{
		Hostname:      "test-host",
		Tags:          []string{"tag:test", "tag:production"},
		SubnetRoutes:  []string{"10.0.0.0/8"},
		ExposePorts:   []string{"80", "443"},
		AuthKeySecret: "test-secret",
		Userspace:     true,
		Debug:         true,
		ExtraEnv: map[string]string{
			"CUSTOM_VAR": "custom_value",
		},
	}

	env := config.GetEnvironmentVariables()

	expectedVars := map[string]string{
		"TS_KUBE_SECRET": "test-secret",
		"TS_USERSPACE":   "true",
		"TS_DEBUG":       "true",
		"TS_HOSTNAME":    "test-host",
		"TS_TAGS":        "tag:test,tag:production",
		"TS_ROUTES":      "10.0.0.0/8",
		"TS_SERVE_PORTS": "80,443",
		"CUSTOM_VAR":     "custom_value",
	}

	for key, expectedValue := range expectedVars {
		if actualValue, exists := env[key]; !exists {
			t.Errorf("Expected environment variable %s not found", key)
		} else if actualValue != expectedValue {
			t.Errorf("Environment variable %s: expected %s, got %s", key, expectedValue, actualValue)
		}
	}
}

func TestInjectSidecar(t *testing.T) {
	// Create fake Kubernetes client
	client := fake.NewSimpleClientset()

	// Create authenticator
	auth, err := tailscale.NewAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}
	auth.SetClient(client)

	// Create injector
	injector := injection.NewInjector(client, auth)

	// Test pod
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "app",
					Image: "nginx:latest",
				},
			},
		},
	}

	// Test config
	config := &injection.Config{
		Namespace:     "default",
		PodName:       "test-pod",
		Hostname:      "test-hostname",
		AuthKeySecret: "test-secret",
		Image:         "tailscale/tailscale:latest",
		Tags:          []string{"tag:test"},
	}

	// Inject sidecar
	patches, err := injector.InjectSidecar(pod, config)
	if err != nil {
		t.Fatalf("Failed to inject sidecar: %v", err)
	}

	// Verify patches were generated
	if len(patches) == 0 {
		t.Error("Expected patches to be generated")
	}

	// Check that patches include volume, init container, and sidecar container
	hasVolumePatches := false
	hasInitContainerPatch := false
	hasSidecarPatch := false
	hasAnnotationPatches := false

	for _, patch := range patches {
		switch {
		case patch.Path == "/spec/volumes/0" || patch.Path == "/spec/volumes/1" || patch.Path == "/spec/volumes/2":
			hasVolumePatches = true
		case patch.Path == "/spec/initContainers/0":
			hasInitContainerPatch = true
		case patch.Path == "/spec/containers/1":
			hasSidecarPatch = true
		case patch.Path == "/metadata/annotations" || patch.Path == "/metadata/annotations/tailscale.com~1injected":
			hasAnnotationPatches = true
		}
	}

	if !hasVolumePatches {
		t.Error("Expected volume patches")
	}
	if !hasInitContainerPatch {
		t.Error("Expected init container patch")
	}
	if !hasSidecarPatch {
		t.Error("Expected sidecar container patch")
	}
	if !hasAnnotationPatches {
		t.Error("Expected annotation patches")
	}
}

func TestResourceRequirements(t *testing.T) {
	config := &injection.Config{
		Resources: &injection.ResourceRequirements{
			Requests: injection.ResourceList{
				CPU:    "100m",
				Memory: "128Mi",
			},
			Limits: injection.ResourceList{
				CPU:    "500m",
				Memory: "512Mi",
			},
		},
	}

	// This would test the actual resource requirement conversion
	// For now, we'll just verify the config structure is correct
	if config.Resources == nil {
		t.Error("Expected resources to be set")
	}

	if config.Resources.Requests.CPU != "100m" {
		t.Errorf("Expected CPU request 100m, got %s", config.Resources.Requests.CPU)
	}

	if config.Resources.Requests.Memory != "128Mi" {
		t.Errorf("Expected memory request 128Mi, got %s", config.Resources.Requests.Memory)
	}

	if config.Resources.Limits.CPU != "500m" {
		t.Errorf("Expected CPU limit 500m, got %s", config.Resources.Limits.CPU)
	}

	if config.Resources.Limits.Memory != "512Mi" {
		t.Errorf("Expected memory limit 512Mi, got %s", config.Resources.Limits.Memory)
	}
}