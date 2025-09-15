package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

// validate handles the admission validation logic
func (s *Server) validate(admissionReview *admissionv1.AdmissionReview) *admissionv1.AdmissionReview {
	req := admissionReview.Request
	var pod corev1.Pod

	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		klog.ErrorS(err, "Failed to unmarshal pod object")
		return &admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "admission.k8s.io/v1",
				Kind:       "AdmissionReview",
			},
			Response: &admissionv1.AdmissionResponse{
				UID:     req.UID,
				Allowed: false,
				Result: &metav1.Status{
					Message: err.Error(),
				},
			},
		}
	}

	klog.InfoS("Processing validation request",
		"namespace", req.Namespace,
		"name", pod.Name,
		"kind", req.Kind.Kind,
	)

	// If injection is not requested, allow the pod
	if !shouldInject(&pod) {
		return &admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "admission.k8s.io/v1",
				Kind:       "AdmissionReview",
			},
			Response: &admissionv1.AdmissionResponse{
				UID:     req.UID,
				Allowed: true,
			},
		}
	}

	// Validate injection configuration
	if err := s.validateInjectionConfig(&pod, req.Namespace); err != nil {
		klog.ErrorS(err, "Validation failed",
			"namespace", req.Namespace,
			"name", pod.Name,
		)
		return &admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "admission.k8s.io/v1",
				Kind:       "AdmissionReview",
			},
			Response: &admissionv1.AdmissionResponse{
				UID:     req.UID,
				Allowed: false,
				Result: &metav1.Status{
					Message: fmt.Sprintf("Validation failed: %v", err),
				},
			},
		}
	}

	// Validate that pod doesn't conflict with Tailscale requirements
	if err := s.validatePodSpec(&pod); err != nil {
		klog.ErrorS(err, "Pod specification validation failed",
			"namespace", req.Namespace,
			"name", pod.Name,
		)
		return &admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "admission.k8s.io/v1",
				Kind:       "AdmissionReview",
			},
			Response: &admissionv1.AdmissionResponse{
				UID:     req.UID,
				Allowed: false,
				Result: &metav1.Status{
					Message: fmt.Sprintf("Pod specification validation failed: %v", err),
				},
			},
		}
	}

	klog.InfoS("Validation successful",
		"namespace", req.Namespace,
		"name", pod.Name,
	)

	return &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: true,
		},
	}
}

// validateInjectionConfig validates the Tailscale injection configuration
func (s *Server) validateInjectionConfig(pod *corev1.Pod, namespace string) error {
	if pod.Annotations == nil {
		return fmt.Errorf("no annotations found")
	}

	// Validate tags format
	if tags, exists := pod.Annotations[AnnotationTags]; exists && tags != "" {
		if err := validateTags(tags); err != nil {
			return fmt.Errorf("invalid tags: %w", err)
		}
	}

	// Validate hostname
	if hostname, exists := pod.Annotations[AnnotationHostname]; exists && hostname != "" {
		if err := validateHostname(hostname); err != nil {
			return fmt.Errorf("invalid hostname: %w", err)
		}
	}

	// Validate subnet routes
	if routes, exists := pod.Annotations[AnnotationSubnetRouter]; exists && routes != "" {
		if err := validateSubnetRoutes(routes); err != nil {
			return fmt.Errorf("invalid subnet routes: %w", err)
		}
	}

	// Validate expose ports
	if ports, exists := pod.Annotations[AnnotationExpose]; exists && ports != "" {
		if err := validateExposePorts(ports); err != nil {
			return fmt.Errorf("invalid expose ports: %w", err)
		}
	}

	// Validate auth key secret exists
	authKeySecret := DefaultAuthKeySecret
	if authKey, exists := pod.Annotations[AnnotationAuthKey]; exists {
		authKeySecret = authKey
	}

	if err := s.validateAuthKeySecret(authKeySecret, namespace); err != nil {
		return fmt.Errorf("invalid auth key secret: %w", err)
	}

	return nil
}

// validatePodSpec validates the pod specification for compatibility with Tailscale
func (s *Server) validatePodSpec(pod *corev1.Pod) error {
	// Check for container name conflicts
	for _, container := range pod.Spec.Containers {
		if container.Name == "tailscale" {
			return fmt.Errorf("container name 'tailscale' is reserved")
		}
	}

	for _, container := range pod.Spec.InitContainers {
		if container.Name == "tailscale-init" {
			return fmt.Errorf("init container name 'tailscale-init' is reserved")
		}
	}

	// Check for volume name conflicts
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == "tailscale-var" || volume.Name == "tailscale-tmp" || volume.Name == "tailscale-auth" {
			return fmt.Errorf("volume name '%s' is reserved for Tailscale", volume.Name)
		}
	}

	// Validate security context compatibility
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil && *pod.Spec.SecurityContext.RunAsNonRoot {
		// Check if userspace mode is enabled
		if userspace, exists := pod.Annotations[AnnotationUserspace]; !exists || userspace != "true" {
			return fmt.Errorf("pod has runAsNonRoot=true but userspace mode is not enabled; add annotation %s=true", AnnotationUserspace)
		}
	}

	return nil
}

// validateTags validates the tags annotation format
func validateTags(tags string) error {
	// Try parsing as JSON array first
	var tagList []string
	if err := json.Unmarshal([]byte(tags), &tagList); err == nil {
		return validateTagList(tagList)
	}

	// Try parsing as comma-separated string
	tagList = parseCommaSeparated(tags)
	return validateTagList(tagList)
}

// validateTagList validates individual tags
func validateTagList(tags []string) error {
	for _, tag := range tags {
		if len(tag) == 0 {
			return fmt.Errorf("empty tag not allowed")
		}
		if len(tag) > 64 {
			return fmt.Errorf("tag '%s' is too long (max 64 characters)", tag)
		}
		// Validate tag format (alphanumeric, hyphens, underscores)
		for _, char := range tag {
			if !isAlphaNumeric(char) && char != '-' && char != '_' {
				return fmt.Errorf("tag '%s' contains invalid character '%c'", tag, char)
			}
		}
	}
	return nil
}

// validateHostname validates the hostname format
func validateHostname(hostname string) error {
	if len(hostname) == 0 {
		return fmt.Errorf("hostname cannot be empty")
	}
	if len(hostname) > 63 {
		return fmt.Errorf("hostname too long (max 63 characters)")
	}

	// Validate hostname format (RFC 1123)
	for i, char := range hostname {
		if i == 0 || i == len(hostname)-1 {
			if !isAlphaNumeric(char) {
				return fmt.Errorf("hostname must start and end with alphanumeric character")
			}
		} else {
			if !isAlphaNumeric(char) && char != '-' {
				return fmt.Errorf("hostname contains invalid character '%c'", char)
			}
		}
	}

	return nil
}

// validateSubnetRoutes validates subnet route CIDR notation
func validateSubnetRoutes(routes string) error {
	routeList := parseCommaSeparated(routes)
	for _, route := range routeList {
		if err := validateCIDR(route); err != nil {
			return fmt.Errorf("invalid subnet route '%s': %w", route, err)
		}
	}
	return nil
}

// validateExposePorts validates port specifications
func validateExposePorts(ports string) error {
	portList := parseCommaSeparated(ports)
	for _, port := range portList {
		if err := validatePort(port); err != nil {
			return fmt.Errorf("invalid port '%s': %w", port, err)
		}
	}
	return nil
}

// validateAuthKeySecret validates that the auth key secret exists and contains valid data
func (s *Server) validateAuthKeySecret(secretName, namespace string) error {
	secret, err := s.client.CoreV1().Secrets(namespace).Get(
		context.TODO(),
		secretName,
		metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("auth key secret '%s' not found in namespace '%s': %w", secretName, namespace, err)
	}

	// Validate that the secret contains required fields
	if secret.Data == nil {
		return fmt.Errorf("auth key secret '%s' has no data", secretName)
	}

	authKey, exists := secret.Data["authkey"]
	if !exists {
		return fmt.Errorf("auth key secret '%s' does not contain 'authkey' field", secretName)
	}

	if len(authKey) == 0 {
		return fmt.Errorf("auth key in secret '%s' is empty", secretName)
	}

	// Basic validation of auth key format
	authKeyStr := string(authKey)
	if len(authKeyStr) < 10 {
		return fmt.Errorf("auth key in secret '%s' appears to be invalid (too short)", secretName)
	}

	// Validate auth key prefix
	if !strings.HasPrefix(authKeyStr, "tskey-") {
		return fmt.Errorf("auth key in secret '%s' does not have valid format (should start with 'tskey-')", secretName)
	}

	return nil
}

// validateCIDR validates CIDR notation
func validateCIDR(cidr string) error {
	if cidr == "" {
		return fmt.Errorf("CIDR cannot be empty")
	}

	// Parse and validate CIDR notation
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR format: %w", err)
	}

	// Additional validation for common issues
	if ipNet == nil {
		return fmt.Errorf("parsed CIDR is nil")
	}

	// Validate that it's not a host address (mask bits should be less than max)
	maskBits, maxBits := ipNet.Mask.Size()
	if maskBits == maxBits {
		return fmt.Errorf("CIDR appears to be a host address (/%d), not a network range", maskBits)
	}

	// Check for common private network ranges and warn about very broad ranges
	if maskBits < 8 {
		return fmt.Errorf("CIDR range too broad (/%d), consider using more specific ranges", maskBits)
	}

	return nil
}

// validatePort validates port specification
func validatePort(port string) error {
	if port == "" {
		return fmt.Errorf("port cannot be empty")
	}

	// Handle port ranges (e.g., "8080-8090")
	if strings.Contains(port, "-") {
		return validatePortRange(port)
	}

	// Handle protocol specification (e.g., "tcp:8080", "udp:53")
	if strings.Contains(port, ":") {
		return validatePortWithProtocol(port)
	}

	// Simple port number
	return validateSinglePort(port)
}

// validatePortRange validates a port range specification
func validatePortRange(portRange string) error {
	parts := strings.Split(portRange, "-")
	if len(parts) != 2 {
		return fmt.Errorf("invalid port range format, expected 'start-end'")
	}

	startPort, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return fmt.Errorf("invalid start port: %w", err)
	}

	endPort, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return fmt.Errorf("invalid end port: %w", err)
	}

	if err := validatePortNumber(startPort); err != nil {
		return fmt.Errorf("invalid start port: %w", err)
	}

	if err := validatePortNumber(endPort); err != nil {
		return fmt.Errorf("invalid end port: %w", err)
	}

	if startPort >= endPort {
		return fmt.Errorf("start port (%d) must be less than end port (%d)", startPort, endPort)
	}

	if endPort-startPort > 1000 {
		return fmt.Errorf("port range too large (%d ports), maximum allowed is 1000", endPort-startPort+1)
	}

	return nil
}

// validatePortWithProtocol validates port with protocol specification
func validatePortWithProtocol(portSpec string) error {
	parts := strings.Split(portSpec, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid port specification format, expected 'protocol:port'")
	}

	protocol := strings.ToLower(strings.TrimSpace(parts[0]))
	portStr := strings.TrimSpace(parts[1])

	// Validate protocol
	validProtocols := []string{"tcp", "udp", "icmp"}
	validProtocol := false
	for _, p := range validProtocols {
		if protocol == p {
			validProtocol = true
			break
		}
	}
	if !validProtocol {
		return fmt.Errorf("invalid protocol '%s', must be one of: %v", protocol, validProtocols)
	}

	// ICMP doesn't use ports
	if protocol == "icmp" {
		if portStr != "" && portStr != "*" {
			return fmt.Errorf("ICMP protocol should not specify a port")
		}
		return nil
	}

	// Validate port for TCP/UDP
	return validateSinglePort(portStr)
}

// validateSinglePort validates a single port number
func validateSinglePort(port string) error {
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port number: %w", err)
	}

	return validatePortNumber(portNum)
}

// validatePortNumber validates that a port number is in valid range
func validatePortNumber(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port number %d is out of valid range (1-65535)", port)
	}

	// Check for well-known privileged ports and warn
	if port < 1024 {
		// This is informational - not an error, but could be logged
		// Well-known ports might require special privileges
	}

	return nil
}

// isAlphaNumeric checks if a character is alphanumeric
func isAlphaNumeric(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}