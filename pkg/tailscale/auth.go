package tailscale

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// Authenticator handles Tailscale authentication operations
type Authenticator struct {
	client     kubernetes.Interface
	apiBaseURL string
	apiKey     string
	tailnet    string
	httpClient *http.Client
}

// NewAuthenticator creates a new Tailscale authenticator
func NewAuthenticator(apiKey, tailnet string) (*Authenticator, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("tailscale API key is required")
	}
	if tailnet == "" {
		return nil, fmt.Errorf("tailnet is required")
	}

	return &Authenticator{
		apiBaseURL: "https://api.tailscale.com/api/v2",
		apiKey:     apiKey,
		tailnet:    tailnet,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// SetClient sets the Kubernetes client
func (a *Authenticator) SetClient(client kubernetes.Interface) {
	a.client = client
}

// AuthKeyConfig represents configuration for creating auth keys
type AuthKeyConfig struct {
	Tags        []string
	Ephemeral   bool
	Preauth     bool
	Reusable    bool
	ExpiryHours int
}

// AuthKey represents a Tailscale auth key
type AuthKey struct {
	Key       string    `json:"key"`
	ID        string    `json:"id"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
	Tags      []string  `json:"tags"`
	Ephemeral bool      `json:"ephemeral"`
	Preauth   bool      `json:"preauth"`
	Reusable  bool      `json:"reusable"`
}

// ValidateAuthKey validates that an auth key secret exists and is valid
func (a *Authenticator) ValidateAuthKey(ctx context.Context, namespace, secretName string) error {
	if a.client == nil {
		return fmt.Errorf("kubernetes client not set")
	}

	secret, err := a.client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get auth key secret '%s' in namespace '%s': %w", secretName, namespace, err)
	}

	authKey, exists := secret.Data["authkey"]
	if !exists {
		return fmt.Errorf("secret '%s' does not contain 'authkey' field", secretName)
	}

	if len(authKey) == 0 {
		return fmt.Errorf("auth key in secret '%s' is empty", secretName)
	}

	// Validate auth key format (basic validation)
	authKeyStr := string(authKey)
	if len(authKeyStr) < 10 {
		return fmt.Errorf("auth key appears to be invalid (too short)")
	}

	if !isValidAuthKeyFormat(authKeyStr) {
		return fmt.Errorf("auth key format is invalid")
	}

	klog.V(4).InfoS("Auth key validation successful",
		"namespace", namespace,
		"secret", secretName,
	)

	return nil
}

// CreateEphemeralAuthKey creates an ephemeral auth key for pod use
func (a *Authenticator) CreateEphemeralAuthKey(ctx context.Context, config *AuthKeyConfig) (*AuthKey, error) {
	if a.apiKey == "" {
		return nil, fmt.Errorf("tailscale API key not configured")
	}

	klog.InfoS("Creating ephemeral auth key",
		"tags", config.Tags,
		"ephemeral", config.Ephemeral,
		"preauth", config.Preauth,
		"reusable", config.Reusable,
		"expiryHours", config.ExpiryHours,
	)

	// Prepare request payload
	payload := map[string]interface{}{
		"capabilities": map[string]interface{}{
			"devices": map[string]interface{}{
				"create": map[string]interface{}{
					"reusable":      config.Reusable,
					"ephemeral":     config.Ephemeral,
					"preauthorized": config.Preauth,
					"tags":          config.Tags,
				},
			},
		},
	}

	if config.ExpiryHours > 0 {
		expiry := time.Now().Add(time.Duration(config.ExpiryHours) * time.Hour)
		payload["expirySeconds"] = int64(config.ExpiryHours * 3600)
	}

	// Make API request
	url := fmt.Sprintf("%s/tailnet/%s/keys", a.apiBaseURL, url.PathEscape(a.tailnet))
	authKey, err := a.makeAuthKeyRequest(ctx, "POST", url, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth key: %w", err)
	}

	klog.InfoS("Auth key created successfully",
		"keyID", authKey.ID,
		"expires", authKey.Expires,
	)

	return authKey, nil
}

// RevokeAuthKey revokes an auth key
func (a *Authenticator) RevokeAuthKey(ctx context.Context, keyID string) error {
	if a.apiKey == "" {
		return fmt.Errorf("tailscale API key not configured")
	}
	if keyID == "" {
		return fmt.Errorf("key ID is required")
	}

	klog.InfoS("Revoking auth key", "keyID", keyID)

	// Make API request to revoke the key
	url := fmt.Sprintf("%s/tailnet/%s/keys/%s", a.apiBaseURL, url.PathEscape(a.tailnet), url.PathEscape(keyID))
	_, err := a.makeAPIRequest(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to revoke auth key: %w", err)
	}

	klog.InfoS("Auth key revoked successfully", "keyID", keyID)
	return nil
}

// GetNodeInfo retrieves information about a Tailscale node
func (a *Authenticator) GetNodeInfo(ctx context.Context, hostname string) (*NodeInfo, error) {
	if a.apiKey == "" {
		return nil, fmt.Errorf("tailscale API key not configured")
	}
	if hostname == "" {
		return nil, fmt.Errorf("hostname is required")
	}

	// Get all nodes and find the one with matching hostname
	nodes, err := a.ListNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	for _, node := range nodes {
		if node.Hostname == hostname {
			return node, nil
		}
	}

	return nil, fmt.Errorf("node with hostname '%s' not found", hostname)
}

// ListNodes lists all nodes in the Tailscale network
func (a *Authenticator) ListNodes(ctx context.Context) ([]*NodeInfo, error) {
	if a.apiKey == "" {
		return nil, fmt.Errorf("tailscale API key not configured")
	}

	// Make API request to get devices
	url := fmt.Sprintf("%s/tailnet/%s/devices", a.apiBaseURL, url.PathEscape(a.tailnet))
	response, err := a.makeAPIRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	var apiResponse struct {
		Devices []struct {
			ID           string    `json:"id"`
			Name         string    `json:"name"`
			NodeKey      string    `json:"nodeKey"`
			MachineKey   string    `json:"machineKey"`
			Addresses    []string  `json:"addresses"`
			Tags         []string  `json:"tags"`
			Online       bool      `json:"online"`
			LastSeen     time.Time `json:"lastSeen"`
			Capabilities []string  `json:"capabilities"`
		} `json:"devices"`
	}

	if err := json.Unmarshal(response, &apiResponse); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %w", err)
	}

	nodes := make([]*NodeInfo, 0, len(apiResponse.Devices))
	for _, device := range apiResponse.Devices {
		node := &NodeInfo{
			Hostname:     device.Name,
			ID:           device.ID,
			PublicKey:    device.NodeKey,
			MachineKey:   device.MachineKey,
			Tags:         device.Tags,
			Online:       device.Online,
			LastSeen:     device.LastSeen,
			Capabilities: device.Capabilities,
		}

		// Parse IP addresses
		for _, addr := range device.Addresses {
			if strings.Contains(addr, ":") {
				node.IPv6 = addr
			} else {
				node.IPv4 = addr
			}
		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}

// NodeInfo represents information about a Tailscale node
type NodeInfo struct {
	Hostname     string    `json:"hostname"`
	ID           string    `json:"id"`
	PublicKey    string    `json:"publicKey"`
	IPv4         string    `json:"ipv4"`
	IPv6         string    `json:"ipv6"`
	Online       bool      `json:"online"`
	LastSeen     time.Time `json:"lastSeen"`
	MachineKey   string    `json:"machineKey"`
	Tags         []string  `json:"tags"`
	Capabilities []string  `json:"capabilities"`
}

// isValidAuthKeyFormat performs basic validation of auth key format
func isValidAuthKeyFormat(authKey string) bool {
	// Basic validation - auth keys typically start with "tskey-"
	if len(authKey) < 10 {
		return false
	}

	// Check for valid characters (alphanumeric and some special characters)
	for _, char := range authKey {
		if !isValidAuthKeyChar(char) {
			return false
		}
	}

	return true
}

// isValidAuthKeyChar checks if a character is valid in an auth key
func isValidAuthKeyChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.'
}

// makeAuthKeyRequest makes an API request specifically for auth key operations
func (a *Authenticator) makeAuthKeyRequest(ctx context.Context, method, url string, payload interface{}) (*AuthKey, error) {
	response, err := a.makeAPIRequest(ctx, method, url, payload)
	if err != nil {
		return nil, err
	}

	var authKeyResponse struct {
		Key       string    `json:"key"`
		ID        string    `json:"id"`
		Created   time.Time `json:"created"`
		Expires   time.Time `json:"expires"`
		Tags      []string  `json:"tags"`
		Ephemeral bool      `json:"ephemeral"`
		Preauth   bool      `json:"preauthorized"`
		Reusable  bool      `json:"reusable"`
	}

	if err := json.Unmarshal(response, &authKeyResponse); err != nil {
		return nil, fmt.Errorf("failed to parse auth key response: %w", err)
	}

	return &AuthKey{
		Key:       authKeyResponse.Key,
		ID:        authKeyResponse.ID,
		Created:   authKeyResponse.Created,
		Expires:   authKeyResponse.Expires,
		Tags:      authKeyResponse.Tags,
		Ephemeral: authKeyResponse.Ephemeral,
		Preauth:   authKeyResponse.Preauth,
		Reusable:  authKeyResponse.Reusable,
	}, nil
}

// makeAPIRequest makes a generic API request to the Tailscale API
func (a *Authenticator) makeAPIRequest(ctx context.Context, method, url string, payload interface{}) ([]byte, error) {
	var reqBody io.Reader
	if payload != nil {
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload: %w", err)
		}
		reqBody = bytes.NewReader(payloadBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+a.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tailscale-injection-webhook/1.0")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errorResp struct {
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		if err := json.Unmarshal(body, &errorResp); err == nil {
			if errorResp.Message != "" {
				return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, errorResp.Message)
			}
			if errorResp.Error != "" {
				return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, errorResp.Error)
			}
		}
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// generateSecureID generates a cryptographically secure random ID
func generateSecureID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails
		return fmt.Sprintf("fallback-id-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}