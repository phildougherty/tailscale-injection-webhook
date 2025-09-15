package injection

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
)

// SecurityValidator validates annotations for security issues
type SecurityValidator struct {
	// Regex patterns for validation
	hostnamePattern *regexp.Regexp
	tagPattern      *regexp.Regexp
	cidrPattern     *regexp.Regexp
}

// NewSecurityValidator creates a new security validator
func NewSecurityValidator() *SecurityValidator {
	return &SecurityValidator{
		hostnamePattern: regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$`),
		tagPattern:      regexp.MustCompile(`^tag:[a-zA-Z0-9][a-zA-Z0-9-_]{0,62}$`),
		cidrPattern:     regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$`),
	}
}

// ValidateAnnotations validates all security-sensitive annotations
func (sv *SecurityValidator) ValidateAnnotations(annotations map[string]string) error {
	// Validate hostname
	if hostname, exists := annotations[AnnotationHostname]; exists {
		if err := sv.validateHostname(hostname); err != nil {
			return fmt.Errorf("invalid hostname: %w", err)
		}
	}

	// Validate tags
	if tags, exists := annotations[AnnotationTags]; exists {
		if err := sv.validateTags(tags); err != nil {
			return fmt.Errorf("invalid tags: %w", err)
		}
	}

	// Validate subnet routes
	if routes, exists := annotations[AnnotationSubnetRouter]; exists {
		if err := sv.validateCIDRs(routes); err != nil {
			return fmt.Errorf("invalid subnet routes: %w", err)
		}
	}

	// Validate exposed ports
	if ports, exists := annotations[AnnotationExpose]; exists {
		if err := sv.validatePorts(ports); err != nil {
			return fmt.Errorf("invalid exposed ports: %w", err)
		}
	}

	// Check for injection attempts
	if err := sv.checkForInjection(annotations); err != nil {
		return fmt.Errorf("potential injection detected: %w", err)
	}

	return nil
}

// validateHostname validates a hostname
func (sv *SecurityValidator) validateHostname(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}

	if len(hostname) > 63 {
		return fmt.Errorf("hostname too long (max 63 characters)")
	}

	if !sv.hostnamePattern.MatchString(hostname) {
		return fmt.Errorf("hostname contains invalid characters")
	}

	// Check for reserved names
	reserved := []string{"localhost", "tailscale", "operator", "webhook"}
	lowerHostname := strings.ToLower(hostname)
	for _, r := range reserved {
		if lowerHostname == r {
			return fmt.Errorf("hostname '%s' is reserved", hostname)
		}
	}

	return nil
}

// validateTags validates Tailscale tags
func (sv *SecurityValidator) validateTags(tagsStr string) error {
	if tagsStr == "" {
		return nil
	}

	// Parse tags JSON array
	tags, err := parseTags(tagsStr)
	if err != nil {
		return fmt.Errorf("failed to parse tags: %w", err)
	}

	if len(tags) > 10 {
		return fmt.Errorf("too many tags (max 10)")
	}

	for _, tag := range tags {
		if !sv.tagPattern.MatchString(tag) {
			return fmt.Errorf("invalid tag format: %s", tag)
		}

		// Check for reserved tags
		if strings.HasPrefix(tag, "tag:k8s-operator") || strings.HasPrefix(tag, "tag:webhook") {
			return fmt.Errorf("tag '%s' is reserved for system use", tag)
		}
	}

	return nil
}

// validateCIDRs validates CIDR blocks
func (sv *SecurityValidator) validateCIDRs(cidrsStr string) error {
	if cidrsStr == "" {
		return nil
	}

	cidrs := strings.Split(cidrsStr, ",")
	if len(cidrs) > 10 {
		return fmt.Errorf("too many CIDR blocks (max 10)")
	}

	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)

		// Parse CIDR
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR: %s", cidr)
		}

		// Check for dangerous networks
		dangerousNetworks := []string{
			"0.0.0.0/0",      // All IPv4
			"::/0",           // All IPv6
			"127.0.0.0/8",    // Loopback
			"169.254.0.0/16", // Link-local
		}

		for _, dangerous := range dangerousNetworks {
			_, dangerousNet, _ := net.ParseCIDR(dangerous)
			if ipNet.String() == dangerousNet.String() {
				klog.WarningS(nil, "Potentially dangerous CIDR block requested",
					"cidr", cidr,
				)
			}
		}

		// Check prefix length
		ones, _ := ipNet.Mask.Size()
		if ones < 8 {
			return fmt.Errorf("CIDR prefix too broad (minimum /8): %s", cidr)
		}
	}

	return nil
}

// validatePorts validates port numbers
func (sv *SecurityValidator) validatePorts(portsStr string) error {
	if portsStr == "" {
		return nil
	}

	ports := strings.Split(portsStr, ",")
	if len(ports) > 20 {
		return fmt.Errorf("too many ports (max 20)")
	}

	for _, portStr := range ports {
		portStr = strings.TrimSpace(portStr)

		// Handle port ranges
		if strings.Contains(portStr, "-") {
			parts := strings.Split(portStr, "-")
			if len(parts) != 2 {
				return fmt.Errorf("invalid port range: %s", portStr)
			}

			startPort, err := strconv.Atoi(parts[0])
			if err != nil {
				return fmt.Errorf("invalid start port in range: %s", parts[0])
			}

			endPort, err := strconv.Atoi(parts[1])
			if err != nil {
				return fmt.Errorf("invalid end port in range: %s", parts[1])
			}

			if startPort >= endPort {
				return fmt.Errorf("invalid port range (start >= end): %s", portStr)
			}

			if err := sv.validatePort(startPort); err != nil {
				return err
			}
			if err := sv.validatePort(endPort); err != nil {
				return err
			}
		} else {
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return fmt.Errorf("invalid port: %s", portStr)
			}
			if err := sv.validatePort(port); err != nil {
				return err
			}
		}
	}

	return nil
}

// validatePort validates a single port number
func (sv *SecurityValidator) validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port out of range (1-65535): %d", port)
	}

	// Warn about privileged ports
	if port < 1024 {
		klog.V(2).InfoS("Privileged port requested", "port", port)
	}

	// Check for commonly exploited ports
	dangerousPorts := []int{
		445,   // SMB
		3389,  // RDP
		5900,  // VNC
		6379,  // Redis
		27017, // MongoDB
	}

	for _, dangerous := range dangerousPorts {
		if port == dangerous {
			klog.WarningS(nil, "Potentially dangerous port requested",
				"port", port,
			)
		}
	}

	return nil
}

// checkForInjection checks for potential injection attempts
func (sv *SecurityValidator) checkForInjection(annotations map[string]string) error {
	suspiciousPatterns := []string{
		"$(",          // Command substitution
		"`",           // Command substitution
		"&&",          // Command chaining
		"||",          // Command chaining
		";",           // Command separator
		"|",           // Pipe
		">",           // Redirect
		"<",           // Redirect
		"../",         // Path traversal
		"..\\",        // Path traversal
		"%00",         // Null byte
		"\x00",        // Null byte
		"${",          // Variable expansion
		"$(IFS)",      // IFS manipulation
		"/etc/passwd", // Sensitive file
		"/etc/shadow", // Sensitive file
	}

	for key, value := range annotations {
		// Skip non-Tailscale annotations
		if !strings.HasPrefix(key, "tailscale.com/") {
			continue
		}

		lowerValue := strings.ToLower(value)
		for _, pattern := range suspiciousPatterns {
			if strings.Contains(lowerValue, strings.ToLower(pattern)) {
				return fmt.Errorf("suspicious pattern detected in annotation %s: contains '%s'", key, pattern)
			}
		}

		// Check for excessive length (potential buffer overflow)
		if len(value) > 4096 {
			return fmt.Errorf("annotation value too long (max 4096): %s", key)
		}

		// Check for non-printable characters
		for _, r := range value {
			if r < 32 && r != '\t' && r != '\n' && r != '\r' {
				return fmt.Errorf("non-printable character detected in annotation %s", key)
			}
		}
	}

	return nil
}

// parseTags parses the tags annotation value
func parseTags(tagsStr string) ([]string, error) {
	// Handle JSON array format
	if strings.HasPrefix(tagsStr, "[") {
		// Parse as JSON array
		var jsonTags []string
		if err := json.Unmarshal([]byte(tagsStr), &jsonTags); err != nil {
			return nil, fmt.Errorf("failed to parse JSON array: %w", err)
		}
		result := make([]string, 0, len(jsonTags))
		for _, tag := range jsonTags {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				result = append(result, tag)
			}
		}
		return result, nil
	}

	// Handle comma-separated format
	tags := strings.Split(tagsStr, ",")
	result := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag != "" {
			result = append(result, tag)
		}
	}

	return result, nil
}