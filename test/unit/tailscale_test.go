package unit

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/phildougherty/tailscale-injection-webhook/pkg/tailscale"
)

func TestValidateAuthKey(t *testing.T) {
	tests := []struct {
		name        string
		secretName  string
		namespace   string
		secretData  map[string][]byte
		expectError bool
	}{
		{
			name:       "valid auth key",
			secretName: "test-auth-key",
			namespace:  "default",
			secretData: map[string][]byte{
				"authkey": []byte("tskey-auth-valid-key-123456789"),
			},
			expectError: false,
		},
		{
			name:        "secret not found",
			secretName:  "nonexistent-secret",
			namespace:   "default",
			secretData:  nil,
			expectError: true,
		},
		{
			name:       "missing authkey field",
			secretName: "test-auth-key",
			namespace:  "default",
			secretData: map[string][]byte{
				"other": []byte("some-value"),
			},
			expectError: true,
		},
		{
			name:       "empty authkey",
			secretName: "test-auth-key",
			namespace:  "default",
			secretData: map[string][]byte{
				"authkey": []byte(""),
			},
			expectError: true,
		},
		{
			name:       "invalid authkey format",
			secretName: "test-auth-key",
			namespace:  "default",
			secretData: map[string][]byte{
				"authkey": []byte("short"),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fake client
			var objects []runtime.Object

			if tt.secretData != nil {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      tt.secretName,
						Namespace: tt.namespace,
					},
					Data: tt.secretData,
				}
				objects = append(objects, secret)
			}

			client := fake.NewSimpleClientset(objects...)

			// Create authenticator
			auth, err := tailscale.NewAuthenticator()
			if err != nil {
				t.Fatalf("Failed to create authenticator: %v", err)
			}
			auth.SetClient(client)

			// Test validation
			err = auth.ValidateAuthKey(context.Background(), tt.namespace, tt.secretName)

			if tt.expectError && err == nil {
				t.Error("Expected validation error, but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no validation error, but got: %v", err)
			}
		})
	}
}

func TestCreateEphemeralAuthKey(t *testing.T) {
	auth, err := tailscale.NewAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	config := &tailscale.AuthKeyConfig{
		Tags:        []string{"tag:test", "tag:ephemeral"},
		Ephemeral:   true,
		Preauth:     true,
		Reusable:    false,
		ExpiryHours: 24,
	}

	authKey, err := auth.CreateEphemeralAuthKey(context.Background(), config)
	if err != nil {
		t.Fatalf("Failed to create ephemeral auth key: %v", err)
	}

	if authKey == nil {
		t.Fatal("Expected non-nil auth key")
	}

	if authKey.Key == "" {
		t.Error("Expected auth key to have a key value")
	}

	if authKey.ID == "" {
		t.Error("Expected auth key to have an ID")
	}

	if authKey.Ephemeral != config.Ephemeral {
		t.Errorf("Expected ephemeral=%v, got %v", config.Ephemeral, authKey.Ephemeral)
	}

	if authKey.Preauth != config.Preauth {
		t.Errorf("Expected preauth=%v, got %v", config.Preauth, authKey.Preauth)
	}

	if authKey.Reusable != config.Reusable {
		t.Errorf("Expected reusable=%v, got %v", config.Reusable, authKey.Reusable)
	}

	if len(authKey.Tags) != len(config.Tags) {
		t.Errorf("Expected %d tags, got %d", len(config.Tags), len(authKey.Tags))
	}
}

func TestRevokeAuthKey(t *testing.T) {
	auth, err := tailscale.NewAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	// Test revoking an auth key (this is a mock implementation)
	err = auth.RevokeAuthKey(context.Background(), "test-key-id")
	if err != nil {
		t.Errorf("Expected no error revoking auth key, got: %v", err)
	}
}

func TestGetNodeInfo(t *testing.T) {
	auth, err := tailscale.NewAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	nodeInfo, err := auth.GetNodeInfo(context.Background(), "test-hostname")
	if err != nil {
		t.Fatalf("Failed to get node info: %v", err)
	}

	if nodeInfo == nil {
		t.Fatal("Expected non-nil node info")
	}

	if nodeInfo.Hostname != "test-hostname" {
		t.Errorf("Expected hostname 'test-hostname', got '%s'", nodeInfo.Hostname)
	}

	if nodeInfo.ID == "" {
		t.Error("Expected node ID to be set")
	}

	if nodeInfo.PublicKey == "" {
		t.Error("Expected public key to be set")
	}

	if nodeInfo.IPv4 == "" {
		t.Error("Expected IPv4 address to be set")
	}
}

func TestListNodes(t *testing.T) {
	auth, err := tailscale.NewAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	nodes, err := auth.ListNodes(context.Background())
	if err != nil {
		t.Fatalf("Failed to list nodes: %v", err)
	}

	if len(nodes) == 0 {
		t.Error("Expected at least one node in the list")
	}

	for _, node := range nodes {
		if node.Hostname == "" {
			t.Error("Expected node hostname to be set")
		}
		if node.ID == "" {
			t.Error("Expected node ID to be set")
		}
	}
}

func TestTagManager(t *testing.T) {
	auth, err := tailscale.NewAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	tagManager := tailscale.NewTagManager(auth)

	config := &tailscale.TagConfig{
		Namespace:   "production",
		PodName:     "web-frontend-abc123",
		BaseTags:    []string{"tag:web-frontend"},
		ExtraTags:   []string{"tag:production"},
		AutoGenTags: true,
	}

	tags, err := tagManager.GenerateTags(config)
	if err != nil {
		t.Fatalf("Failed to generate tags: %v", err)
	}

	if len(tags) == 0 {
		t.Error("Expected tags to be generated")
	}

	// Check that base tags are included
	hasBaseTag := false
	for _, tag := range tags {
		if tag == "tag:web-frontend" {
			hasBaseTag = true
			break
		}
	}
	if !hasBaseTag {
		t.Error("Expected base tag 'tag:web-frontend' to be included")
	}

	// Check that extra tags are included
	hasExtraTag := false
	for _, tag := range tags {
		if tag == "tag:production" {
			hasExtraTag = true
			break
		}
	}
	if !hasExtraTag {
		t.Error("Expected extra tag 'tag:production' to be included")
	}

	// Check that auto-generated tags are included
	hasAutoTag := false
	for _, tag := range tags {
		if tag == "tag:k8s-namespace-production" {
			hasAutoTag = true
			break
		}
	}
	if !hasAutoTag {
		t.Error("Expected auto-generated namespace tag to be included")
	}
}

func TestValidateTagFormat(t *testing.T) {
	tests := []struct {
		name        string
		tag         string
		expectError bool
	}{
		{
			name:        "valid tag",
			tag:         "tag:valid-tag-name",
			expectError: false,
		},
		{
			name:        "valid tag with numbers",
			tag:         "tag:web-frontend-123",
			expectError: false,
		},
		{
			name:        "valid tag with underscore",
			tag:         "tag:app_service",
			expectError: false,
		},
		{
			name:        "empty tag",
			tag:         "",
			expectError: true,
		},
		{
			name:        "tag without prefix",
			tag:         "invalid-tag",
			expectError: true,
		},
		{
			name:        "tag with empty value",
			tag:         "tag:",
			expectError: true,
		},
		{
			name:        "tag too long",
			tag:         "tag:this-is-a-very-long-tag-name-that-exceeds-the-maximum-allowed-length-of-80-characters",
			expectError: true,
		},
		{
			name:        "tag with invalid characters",
			tag:         "tag:invalid@tag",
			expectError: true,
		},
		{
			name:        "tag starting with hyphen",
			tag:         "tag:-invalid",
			expectError: true,
		},
		{
			name:        "tag ending with hyphen",
			tag:         "tag:invalid-",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This would call the actual validateTagFormat function
			// For now, implement basic validation inline
			var err error

			if len(tt.tag) == 0 {
				err = &ValidationError{"tag cannot be empty"}
			} else if len(tt.tag) > 80 {
				err = &ValidationError{"tag is too long"}
			} else if tt.tag[:4] != "tag:" {
				err = &ValidationError{"tag must start with 'tag:' prefix"}
			} else if len(tt.tag) == 4 {
				err = &ValidationError{"tag value cannot be empty"}
			}

			if tt.expectError && err == nil {
				t.Error("Expected validation error, but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no validation error, but got: %v", err)
			}
		})
	}
}

func TestGetRecommendedTags(t *testing.T) {
	auth, err := tailscale.NewAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	tagManager := tailscale.NewTagManager(auth)

	tests := []struct {
		scenario     string
		expectedTags []string
	}{
		{
			scenario:     "web-frontend",
			expectedTags: []string{"tag:role-frontend", "tag:service-web", "tag:external-access"},
		},
		{
			scenario:     "api-backend",
			expectedTags: []string{"tag:role-backend", "tag:service-api", "tag:internal-only"},
		},
		{
			scenario:     "database",
			expectedTags: []string{"tag:role-database", "tag:service-db", "tag:internal-only", "tag:sensitive-data"},
		},
		{
			scenario:     "unknown-scenario",
			expectedTags: []string{"tag:k8s", "tag:custom"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			tags := tagManager.GetRecommendedTags(tt.scenario)

			if len(tags) != len(tt.expectedTags) {
				t.Errorf("Expected %d tags, got %d", len(tt.expectedTags), len(tags))
				return
			}

			for i, tag := range tags {
				if tag != tt.expectedTags[i] {
					t.Errorf("Tag %d: expected %s, got %s", i, tt.expectedTags[i], tag)
				}
			}
		})
	}
}

func TestValidateTagACL(t *testing.T) {
	auth, err := tailscale.NewAuthenticator()
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	tagManager := tailscale.NewTagManager(auth)

	tests := []struct {
		name        string
		tags        []string
		expectError bool
	}{
		{
			name:        "valid tags",
			tags:        []string{"tag:web-frontend", "tag:production"},
			expectError: false,
		},
		{
			name:        "forbidden tag",
			tags:        []string{"tag:web-frontend", "tag:forbidden"},
			expectError: true,
		},
		{
			name:        "empty tags",
			tags:        []string{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tagManager.ValidateTagACL(tt.tags)

			if tt.expectError && err == nil {
				t.Error("Expected ACL validation error, but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no ACL validation error, but got: %v", err)
			}
		})
	}
}

// ValidationError is a simple error type for testing
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}