package webhook

import (
	"encoding/json"
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"

	"github.com/phildougherty/tailscale-injection-webhook/pkg/injection"
)

const (
	// Annotation keys
	AnnotationInject       = "tailscale.com/inject"
	AnnotationTags         = "tailscale.com/tags"
	AnnotationAuthKey      = "tailscale.com/auth-key"
	AnnotationExitNode     = "tailscale.com/exit-node"
	AnnotationSubnetRouter = "tailscale.com/subnet-router"
	AnnotationExpose       = "tailscale.com/expose"
	AnnotationHostname     = "tailscale.com/hostname"
	AnnotationAcceptRoutes = "tailscale.com/accept-routes"
	AnnotationUserspace    = "tailscale.com/userspace"
	AnnotationDebug        = "tailscale.com/debug"

	// Default values
	DefaultTailscaleImage = "tailscale/tailscale:v1.52.1"
	DefaultAuthKeySecret  = "tailscale-auth-key"
)

// mutate handles the admission mutation logic
func (s *Server) mutate(admissionReview *admissionv1.AdmissionReview) *admissionv1.AdmissionReview {
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

	klog.InfoS("Processing mutation request",
		"namespace", req.Namespace,
		"name", pod.Name,
		"kind", req.Kind.Kind,
	)

	// Check if injection is requested
	if !shouldInject(&pod) {
		klog.V(4).InfoS("Skipping injection - not requested",
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

	// Check if already injected
	if isAlreadyInjected(&pod) {
		klog.V(4).InfoS("Skipping injection - already injected",
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

	// Parse injection config from annotations
	config, err := s.parseInjectionConfig(&pod, req.Namespace)
	if err != nil {
		klog.ErrorS(err, "Failed to parse injection config",
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
					Message: fmt.Sprintf("Invalid injection configuration: %v", err),
				},
			},
		}
	}

	// Perform injection
	patches, err := s.injector.InjectSidecar(&pod, config)
	if err != nil {
		klog.ErrorS(err, "Failed to inject sidecar",
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
					Message: fmt.Sprintf("Injection failed: %v", err),
				},
			},
		}
	}

	patchBytes, err := json.Marshal(patches)
	if err != nil {
		klog.ErrorS(err, "Failed to marshal patches")
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

	patchType := admissionv1.PatchTypeJSONPatch
	klog.InfoS("Successfully generated injection patches",
		"namespace", req.Namespace,
		"name", pod.Name,
		"patchCount", len(patches),
	)

	return &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: &admissionv1.AdmissionResponse{
			UID:       req.UID,
			Allowed:   true,
			Patch:     patchBytes,
			PatchType: &patchType,
		},
	}
}

// shouldInject determines if the pod should have Tailscale sidecar injected
func shouldInject(pod *corev1.Pod) bool {
	if pod.Annotations == nil {
		return false
	}

	value, exists := pod.Annotations[AnnotationInject]
	if !exists {
		return false
	}

	return value == "true" || value == "yes" || value == "1"
}

// isAlreadyInjected checks if the pod already has a Tailscale sidecar
func isAlreadyInjected(pod *corev1.Pod) bool {
	for _, container := range pod.Spec.Containers {
		if container.Name == "tailscale" {
			return true
		}
	}

	for _, container := range pod.Spec.InitContainers {
		if container.Name == "tailscale-init" {
			return true
		}
	}

	return false
}

// parseInjectionConfig extracts and validates injection configuration from pod annotations
func (s *Server) parseInjectionConfig(pod *corev1.Pod, namespace string) (*injection.Config, error) {
	config := &injection.Config{
		Namespace: namespace,
		PodName:   pod.Name,
		Tags:      []string{},
		Debug:     false,
		Userspace: false,
	}

	if pod.Annotations == nil {
		return config, nil
	}

	// Parse tags
	if tags, exists := pod.Annotations[AnnotationTags]; exists && tags != "" {
		var tagList []string
		if err := json.Unmarshal([]byte(tags), &tagList); err != nil {
			// Try parsing as comma-separated string
			config.Tags = parseCommaSeparated(tags)
		} else {
			config.Tags = tagList
		}
	}

	// Parse auth key reference
	if authKey, exists := pod.Annotations[AnnotationAuthKey]; exists {
		config.AuthKeySecret = authKey
	} else {
		config.AuthKeySecret = DefaultAuthKeySecret
	}

	// Parse hostname
	if hostname, exists := pod.Annotations[AnnotationHostname]; exists {
		config.Hostname = hostname
	} else {
		config.Hostname = fmt.Sprintf("%s-%s", pod.Name, namespace)
	}

	// Parse exit node
	if exitNode, exists := pod.Annotations[AnnotationExitNode]; exists {
		config.ExitNode = exitNode == "true"
	}

	// Parse subnet router
	if subnetRouter, exists := pod.Annotations[AnnotationSubnetRouter]; exists && subnetRouter != "" {
		config.SubnetRoutes = parseCommaSeparated(subnetRouter)
	}

	// Parse expose ports
	if expose, exists := pod.Annotations[AnnotationExpose]; exists && expose != "" {
		config.ExposePorts = parseCommaSeparated(expose)
	}

	// Parse accept routes
	if acceptRoutes, exists := pod.Annotations[AnnotationAcceptRoutes]; exists {
		config.AcceptRoutes = acceptRoutes == "true"
	}

	// Parse userspace mode
	if userspace, exists := pod.Annotations[AnnotationUserspace]; exists {
		config.Userspace = userspace == "true"
	}

	// Parse debug mode
	if debug, exists := pod.Annotations[AnnotationDebug]; exists {
		config.Debug = debug == "true"
	}

	return config, nil
}

// parseCommaSeparated parses a comma-separated string into a slice
func parseCommaSeparated(input string) []string {
	if input == "" {
		return nil
	}

	var result []string
	for _, item := range splitAndTrim(input, ",") {
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

// splitAndTrim splits a string by delimiter and trims whitespace
func splitAndTrim(input, delimiter string) []string {
	parts := make([]string, 0)
	for _, part := range splitString(input, delimiter) {
		trimmed := trimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

// splitString splits a string by delimiter
func splitString(input, delimiter string) []string {
	if input == "" {
		return []string{}
	}

	var result []string
	start := 0
	for i := 0; i < len(input); i++ {
		if input[i:i+len(delimiter)] == delimiter {
			result = append(result, input[start:i])
			start = i + len(delimiter)
			i += len(delimiter) - 1
		}
	}
	result = append(result, input[start:])
	return result
}

// trimSpace removes leading and trailing whitespace
func trimSpace(s string) string {
	start := 0
	end := len(s)

	for start < end && isSpace(s[start]) {
		start++
	}

	for end > start && isSpace(s[end-1]) {
		end--
	}

	return s[start:end]
}

// isSpace checks if a character is whitespace
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}