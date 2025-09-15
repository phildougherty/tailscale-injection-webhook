package injection

import (
	"fmt"
)

// Config holds the configuration for Tailscale sidecar injection
type Config struct {
	// Pod metadata
	Namespace string
	PodName   string

	// Tailscale configuration
	Hostname       string
	Tags           []string
	AuthKeySecret  string
	ExitNode       bool
	SubnetRoutes   []string
	ExposePorts    []string
	AcceptRoutes   bool
	Userspace      bool
	Debug          bool

	// Container configuration
	Image           string
	ImagePullPolicy string
	Resources       *ResourceRequirements

	// Advanced configuration
	ExtraArgs []string
	ExtraEnv  map[string]string
}

// ResourceRequirements defines resource requirements for the Tailscale container
type ResourceRequirements struct {
	Requests ResourceList
	Limits   ResourceList
}

// ResourceList defines resource quantities
type ResourceList struct {
	CPU    string
	Memory string
}

// NewDefaultConfig returns a default injection configuration
func NewDefaultConfig() *Config {
	return &Config{
		Image:           "tailscale/tailscale:v1.52.1",
		ImagePullPolicy: "IfNotPresent",
		Userspace:       false,
		Debug:           false,
		AcceptRoutes:    false,
		ExitNode:        false,
		Resources: &ResourceRequirements{
			Requests: ResourceList{
				CPU:    "10m",
				Memory: "32Mi",
			},
			Limits: ResourceList{
				CPU:    "100m",
				Memory: "128Mi",
			},
		},
		ExtraEnv: make(map[string]string),
	}
}

// Validate validates the injection configuration
func (c *Config) Validate() error {
	if c.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}

	if c.PodName == "" {
		return fmt.Errorf("pod name is required")
	}

	if c.AuthKeySecret == "" {
		return fmt.Errorf("auth key secret is required")
	}

	if c.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}

	if c.Image == "" {
		return fmt.Errorf("image is required")
	}

	// Validate subnet routes format
	for _, route := range c.SubnetRoutes {
		if route == "" {
			return fmt.Errorf("subnet route cannot be empty")
		}
	}

	// Validate expose ports format
	for _, port := range c.ExposePorts {
		if port == "" {
			return fmt.Errorf("expose port cannot be empty")
		}
	}

	// Validate tags
	for _, tag := range c.Tags {
		if tag == "" {
			return fmt.Errorf("tag cannot be empty")
		}
		if len(tag) > 64 {
			return fmt.Errorf("tag '%s' is too long (max 64 characters)", tag)
		}
	}

	return nil
}

// GetTailscaleArgs returns the command line arguments for the Tailscale daemon
func (c *Config) GetTailscaleArgs() []string {
	args := []string{
		"tailscaled",
		"--state=/var/lib/tailscale/tailscaled.state",
		"--socket=/var/run/tailscale/tailscaled.sock",
	}

	if c.Userspace {
		args = append(args, "--tun=userspace-networking")
	}

	if c.Debug {
		args = append(args, "--verbose=2")
	}

	// Add extra args
	args = append(args, c.ExtraArgs...)

	return args
}

// GetTailscaleUpArgs returns the arguments for tailscale up command
func (c *Config) GetTailscaleUpArgs() []string {
	args := []string{
		"tailscale",
		"up",
		"--accept-dns=false",
	}

	if c.Hostname != "" {
		args = append(args, fmt.Sprintf("--hostname=%s", c.Hostname))
	}

	if len(c.Tags) > 0 {
		args = append(args, fmt.Sprintf("--advertise-tags=%s", joinStrings(c.Tags, ",")))
	}

	if c.ExitNode {
		args = append(args, "--advertise-exit-node")
	}

	if len(c.SubnetRoutes) > 0 {
		args = append(args, fmt.Sprintf("--advertise-routes=%s", joinStrings(c.SubnetRoutes, ",")))
	}

	if c.AcceptRoutes {
		args = append(args, "--accept-routes")
	}

	return args
}

// GetEnvironmentVariables returns the environment variables for the Tailscale container
func (c *Config) GetEnvironmentVariables() map[string]string {
	env := make(map[string]string)

	// Copy extra environment variables
	for k, v := range c.ExtraEnv {
		env[k] = v
	}

	// Set Tailscale-specific environment variables
	env["TS_KUBE_SECRET"] = c.AuthKeySecret
	env["TS_USERSPACE"] = boolToString(c.Userspace)
	env["TS_DEBUG"] = boolToString(c.Debug)

	if c.Hostname != "" {
		env["TS_HOSTNAME"] = c.Hostname
	}

	if len(c.Tags) > 0 {
		env["TS_TAGS"] = joinStrings(c.Tags, ",")
	}

	if len(c.SubnetRoutes) > 0 {
		env["TS_ROUTES"] = joinStrings(c.SubnetRoutes, ",")
	}

	if len(c.ExposePorts) > 0 {
		env["TS_SERVE_PORTS"] = joinStrings(c.ExposePorts, ",")
	}

	return env
}

// joinStrings joins a slice of strings with a delimiter
func joinStrings(strs []string, delimiter string) string {
	if len(strs) == 0 {
		return ""
	}

	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += delimiter + strs[i]
	}
	return result
}

// boolToString converts a boolean to string
func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}