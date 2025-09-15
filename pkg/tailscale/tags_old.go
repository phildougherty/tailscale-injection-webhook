package tailscale

import (
	"fmt"
	"strings"
)

// TagManager handles Tailscale tag operations
type TagManager struct {
	auth *Authenticator
}

// NewTagManager creates a new tag manager
func NewTagManager(auth *Authenticator) *TagManager {
	return &TagManager{
		auth: auth,
	}
}

// TagConfig represents configuration for tag operations
type TagConfig struct {
	Namespace   string
	PodName     string
	BaseTags    []string
	ExtraTags   []string
	AutoGenTags bool
}

// TagRule defines rules for automatic tag generation
type TagRule struct {
	Name        string
	Pattern     string
	Tags        []string
	Enabled     bool
	Description string
}

// Default tag rules for automatic tag generation
var DefaultTagRules = []TagRule{
	{
		Name:        "namespace",
		Pattern:     "tag:k8s-namespace-{{.Namespace}}",
		Tags:        []string{"tag:k8s"},
		Enabled:     true,
		Description: "Add namespace-based tag",
	},
	{
		Name:        "pod",
		Pattern:     "tag:k8s-pod-{{.PodName}}",
		Tags:        []string{"tag:k8s"},
		Enabled:     false,
		Description: "Add pod-specific tag",
	},
	{
		Name:        "environment",
		Pattern:     "tag:env-{{.Environment}}",
		Tags:        []string{"tag:k8s"},
		Enabled:     true,
		Description: "Add environment-based tag",
	},
}

// GenerateTags generates tags for a pod based on configuration and rules
func (tm *TagManager) GenerateTags(config *TagConfig) ([]string, error) {
	var allTags []string

	// Add base tags
	allTags = append(allTags, config.BaseTags...)

	// Add extra tags
	allTags = append(allTags, config.ExtraTags...)

	// Generate automatic tags if enabled
	if config.AutoGenTags {
		autoTags, err := tm.generateAutoTags(config)
		if err != nil {
			return nil, fmt.Errorf("failed to generate automatic tags: %w", err)
		}
		allTags = append(allTags, autoTags...)
	}

	// Validate and normalize tags
	validatedTags, err := tm.validateAndNormalizeTags(allTags)
	if err != nil {
		return nil, fmt.Errorf("tag validation failed: %w", err)
	}

	// Remove duplicates
	uniqueTags := removeDuplicateTags(validatedTags)

	return uniqueTags, nil
}

// generateAutoTags generates automatic tags based on rules
func (tm *TagManager) generateAutoTags(config *TagConfig) ([]string, error) {
	var autoTags []string

	for _, rule := range DefaultTagRules {
		if !rule.Enabled {
			continue
		}

		tag, err := tm.applyTagRule(rule, config)
		if err != nil {
			return nil, fmt.Errorf("failed to apply tag rule '%s': %w", rule.Name, err)
		}

		if tag != "" {
			autoTags = append(autoTags, tag)
		}

		// Add associated tags
		autoTags = append(autoTags, rule.Tags...)
	}

	return autoTags, nil
}

// applyTagRule applies a single tag rule to generate a tag
func (tm *TagManager) applyTagRule(rule TagRule, config *TagConfig) (string, error) {
	template := rule.Pattern

	// Simple template replacement
	replacements := map[string]string{
		"{{.Namespace}}": config.Namespace,
		"{{.PodName}}":   config.PodName,
		"{{.Environment}}": tm.getEnvironmentFromNamespace(config.Namespace),
	}

	result := template
	for placeholder, value := range replacements {
		result = strings.ReplaceAll(result, placeholder, value)
	}

	return result, nil
}

// getEnvironmentFromNamespace extracts environment information from namespace
func (tm *TagManager) getEnvironmentFromNamespace(namespace string) string {
	// Simple heuristics to determine environment from namespace
	lowerNS := strings.ToLower(namespace)

	if strings.Contains(lowerNS, "prod") || strings.Contains(lowerNS, "production") {
		return "production"
	}
	if strings.Contains(lowerNS, "stage") || strings.Contains(lowerNS, "staging") {
		return "staging"
	}
	if strings.Contains(lowerNS, "dev") || strings.Contains(lowerNS, "development") {
		return "development"
	}
	if strings.Contains(lowerNS, "test") || strings.Contains(lowerNS, "testing") {
		return "testing"
	}

	return "unknown"
}

// validateAndNormalizeTags validates and normalizes a list of tags
func (tm *TagManager) validateAndNormalizeTags(tags []string) ([]string, error) {
	var validTags []string

	for _, tag := range tags {
		normalizedTag, err := tm.normalizeTag(tag)
		if err != nil {
			return nil, fmt.Errorf("invalid tag '%s': %w", tag, err)
		}

		if normalizedTag != "" {
			validTags = append(validTags, normalizedTag)
		}
	}

	return validTags, nil
}

// normalizeTag normalizes a single tag
func (tm *TagManager) normalizeTag(tag string) (string, error) {
	if tag == "" {
		return "", nil
	}

	// Trim whitespace
	normalized := strings.TrimSpace(tag)

	// Ensure tag starts with "tag:" prefix if it doesn't already
	if !strings.HasPrefix(normalized, "tag:") {
		normalized = "tag:" + normalized
	}

	// Validate tag format
	if err := validateTagFormat(normalized); err != nil {
		return "", err
	}

	return normalized, nil
}

// validateTagFormat validates the format of a tag
func validateTagFormat(tag string) error {
	if len(tag) == 0 {
		return fmt.Errorf("tag cannot be empty")
	}

	if len(tag) > 80 {
		return fmt.Errorf("tag is too long (max 80 characters)")
	}

	// Check that tag starts with "tag:"
	if !strings.HasPrefix(tag, "tag:") {
		return fmt.Errorf("tag must start with 'tag:' prefix")
	}

	// Extract the tag value after "tag:"
	tagValue := tag[4:]
	if len(tagValue) == 0 {
		return fmt.Errorf("tag value cannot be empty")
	}

	// Validate characters in tag value
	for i, char := range tagValue {
		if !isValidTagChar(char, i == 0 || i == len(tagValue)-1) {
			return fmt.Errorf("invalid character '%c' in tag", char)
		}
	}

	return nil
}

// isValidTagChar checks if a character is valid in a tag
func isValidTagChar(c rune, isFirstOrLast bool) bool {
	// Alphanumeric characters are always valid
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
		return true
	}

	// First and last characters must be alphanumeric
	if isFirstOrLast {
		return false
	}

	// Allowed special characters in the middle
	switch c {
	case '-', '_', '.':
		return true
	}

	return false
}

// removeDuplicateTags removes duplicate tags from a slice
func removeDuplicateTags(tags []string) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, tag := range tags {
		if !seen[tag] {
			seen[tag] = true
			unique = append(unique, tag)
		}
	}

	return unique
}

// GetRecommendedTags returns recommended tags for common scenarios
func (tm *TagManager) GetRecommendedTags(scenario string) []string {
	recommendations := map[string][]string{
		"web-frontend": {
			"tag:role-frontend",
			"tag:service-web",
			"tag:external-access",
		},
		"api-backend": {
			"tag:role-backend",
			"tag:service-api",
			"tag:internal-only",
		},
		"database": {
			"tag:role-database",
			"tag:service-db",
			"tag:internal-only",
			"tag:sensitive-data",
		},
		"worker": {
			"tag:role-worker",
			"tag:service-processing",
			"tag:internal-only",
		},
		"monitoring": {
			"tag:role-monitoring",
			"tag:service-observability",
			"tag:admin-access",
		},
		"development": {
			"tag:env-development",
			"tag:temporary",
		},
		"production": {
			"tag:env-production",
			"tag:critical",
		},
	}

	if tags, exists := recommendations[scenario]; exists {
		return tags
	}

	return []string{"tag:k8s", "tag:custom"}
}

// ACLRule represents an ACL rule for tag validation
type ACLRule struct {
	AllowedTags    []string          `json:"allowedTags"`
	ForbiddenTags  []string          `json:"forbiddenTags"`
	TagPatterns    []string          `json:"tagPatterns"`
	NamespaceRules map[string][]string `json:"namespaceRules"`
	MaxTags        int               `json:"maxTags"`
	RequiredTags   []string          `json:"requiredTags"`
}

// DefaultACLRules provides default ACL rules for tag validation
var DefaultACLRules = &ACLRule{
	AllowedTags: []string{
		"tag:k8s",
		"tag:kubernetes",
		"tag:app-*",
		"tag:env-*",
		"tag:role-*",
		"tag:service-*",
	},
	ForbiddenTags: []string{
		"tag:admin",
		"tag:root",
		"tag:system",
		"tag:privileged",
		"tag:forbidden",
	},
	TagPatterns: []string{
		"^tag:[a-z0-9][a-z0-9-_]*[a-z0-9]$",
		"^tag:[a-z0-9]$",
	},
	NamespaceRules: map[string][]string{
		"production": {"tag:env-production", "tag:critical"},
		"staging":    {"tag:env-staging"},
		"development": {"tag:env-development", "tag:temporary"},
		"testing":     {"tag:env-testing", "tag:temporary"},
	},
	MaxTags:      10,
	RequiredTags: []string{"tag:k8s"},
}

// ValidateTagACL validates tags against ACL rules
func (tm *TagManager) ValidateTagACL(tags []string, namespace string) error {
	return tm.ValidateTagACLWithRules(tags, namespace, DefaultACLRules)
}\n\n// ValidateTagACLWithRules validates tags against specific ACL rules\nfunc (tm *TagManager) ValidateTagACLWithRules(tags []string, namespace string, rules *ACLRule) error {\n\tif rules == nil {\n\t\treturn fmt.Errorf(\"ACL rules not provided\")\n\t}\n\n\t// Check maximum number of tags\n\tif rules.MaxTags > 0 && len(tags) > rules.MaxTags {\n\t\treturn fmt.Errorf(\"too many tags (%d), maximum allowed is %d\", len(tags), rules.MaxTags)\n\t}\n\n\t// Check required tags\n\tif err := tm.validateRequiredTags(tags, rules.RequiredTags); err != nil {\n\t\treturn fmt.Errorf(\"required tags validation failed: %w\", err)\n\t}\n\n\t// Check forbidden tags\n\tif err := tm.validateForbiddenTags(tags, rules.ForbiddenTags); err != nil {\n\t\treturn fmt.Errorf(\"forbidden tags validation failed: %w\", err)\n\t}\n\n\t// Check allowed tags and patterns\n\tif err := tm.validateAllowedTags(tags, rules.AllowedTags, rules.TagPatterns); err != nil {\n\t\treturn fmt.Errorf(\"allowed tags validation failed: %w\", err)\n\t}\n\n\t// Check namespace-specific rules\n\tif err := tm.validateNamespaceRules(tags, namespace, rules.NamespaceRules); err != nil {\n\t\treturn fmt.Errorf(\"namespace rules validation failed: %w\", err)\n\t}\n\n\treturn nil\n}\n\n// validateRequiredTags checks that all required tags are present\nfunc (tm *TagManager) validateRequiredTags(tags []string, requiredTags []string) error {\n\tfor _, required := range requiredTags {\n\t\tfound := false\n\t\tfor _, tag := range tags {\n\t\t\tif tm.matchesTag(tag, required) {\n\t\t\t\tfound = true\n\t\t\t\tbreak\n\t\t\t}\n\t\t}\n\t\tif !found {\n\t\t\treturn fmt.Errorf(\"required tag '%s' is missing\", required)\n\t\t}\n\t}\n\treturn nil\n}\n\n// validateForbiddenTags checks that no forbidden tags are present\nfunc (tm *TagManager) validateForbiddenTags(tags []string, forbiddenTags []string) error {\n\tfor _, tag := range tags {\n\t\tfor _, forbidden := range forbiddenTags {\n\t\t\tif tm.matchesTag(tag, forbidden) {\n\t\t\t\treturn fmt.Errorf(\"tag '%s' is forbidden by ACL rules\", tag)\n\t\t\t}\n\t\t}\n\t}\n\treturn nil\n}\n\n// validateAllowedTags checks that all tags are in the allowed list or match allowed patterns\nfunc (tm *TagManager) validateAllowedTags(tags []string, allowedTags []string, patterns []string) error {\n\tfor _, tag := range tags {\n\t\tallowed := false\n\n\t\t// Check explicit allowed tags\n\t\tfor _, allowedTag := range allowedTags {\n\t\t\tif tm.matchesTag(tag, allowedTag) {\n\t\t\t\tallowed = true\n\t\t\t\tbreak\n\t\t\t}\n\t\t}\n\n\t\t// Check patterns if not explicitly allowed\n\t\tif !allowed {\n\t\t\tfor _, pattern := range patterns {\n\t\t\t\tif tm.matchesPattern(tag, pattern) {\n\t\t\t\t\tallowed = true\n\t\t\t\t\tbreak\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\n\t\tif !allowed {\n\t\t\treturn fmt.Errorf(\"tag '%s' is not allowed by ACL rules\", tag)\n\t\t}\n\t}\n\treturn nil\n}\n\n// validateNamespaceRules checks namespace-specific tag requirements\nfunc (tm *TagManager) validateNamespaceRules(tags []string, namespace string, namespaceRules map[string][]string) error {\n\tif requiredTags, exists := namespaceRules[namespace]; exists {\n\t\tfor _, required := range requiredTags {\n\t\t\tfound := false\n\t\t\tfor _, tag := range tags {\n\t\t\t\tif tm.matchesTag(tag, required) {\n\t\t\t\t\tfound = true\n\t\t\t\t\tbreak\n\t\t\t\t}\n\t\t\t}\n\t\t\tif !found {\n\t\t\t\treturn fmt.Errorf(\"namespace '%s' requires tag '%s'\", namespace, required)\n\t\t\t}\n\t\t}\n\t}\n\treturn nil\n}\n\n// matchesTag checks if a tag matches an allowed tag (supports wildcards)\nfunc (tm *TagManager) matchesTag(tag, pattern string) bool {\n\tif pattern == tag {\n\t\treturn true\n\t}\n\n\t// Handle wildcard patterns\n\tif strings.HasSuffix(pattern, \"*\") {\n\t\tprefix := strings.TrimSuffix(pattern, \"*\")\n\t\treturn strings.HasPrefix(tag, prefix)\n\t}\n\n\tif strings.HasPrefix(pattern, \"*\") {\n\t\tsuffix := strings.TrimPrefix(pattern, \"*\")\n\t\treturn strings.HasSuffix(tag, suffix)\n\t}\n\n\treturn false\n}\n\n// matchesPattern checks if a tag matches a regex pattern\nfunc (tm *TagManager) matchesPattern(tag, pattern string) bool {\n\t// Simple pattern matching - in production, use regexp package\n\t// For now, implement basic pattern matching\n\tif pattern == \"\" {\n\t\treturn false\n\t}\n\n\t// Check basic tag format pattern\n\tif pattern == \"^tag:[a-z0-9][a-z0-9-_]*[a-z0-9]$\" {\n\t\treturn tm.isValidTagFormat(tag)\n\t}\n\n\tif pattern == \"^tag:[a-z0-9]$\" {\n\t\treturn len(tag) == 5 && strings.HasPrefix(tag, \"tag:\") && tm.isAlphaNumeric(rune(tag[4]))\n\t}\n\n\treturn false\n}\n\n// isValidTagFormat checks if tag follows the standard format\nfunc (tm *TagManager) isValidTagFormat(tag string) bool {\n\tif !strings.HasPrefix(tag, \"tag:\") {\n\t\treturn false\n\t}\n\n\tvalue := tag[4:]\n\tif len(value) == 0 {\n\t\treturn false\n\t}\n\n\t// Check first and last characters are alphanumeric\n\tif !tm.isAlphaNumeric(rune(value[0])) || !tm.isAlphaNumeric(rune(value[len(value)-1])) {\n\t\treturn false\n\t}\n\n\t// Check all characters are valid\n\tfor _, char := range value {\n\t\tif !tm.isAlphaNumeric(char) && char != '-' && char != '_' {\n\t\t\treturn false\n\t\t}\n\t}\n\n\treturn true\n}\n\n// isAlphaNumeric checks if a character is alphanumeric\nfunc (tm *TagManager) isAlphaNumeric(c rune) bool {\n\treturn (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')\n}"}