package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

// createTLSConfig creates a secure TLS configuration
func (s *Server) createTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: s.config.TLSMinVersion,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}

	// Load client CA if specified for mutual TLS
	if s.config.ClientCAFile != "" {
		caCert, err := os.ReadFile(s.config.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA file: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

		klog.InfoS("Mutual TLS enabled", "clientCAFile", s.config.ClientCAFile)
	}

	return tlsConfig, nil
}

// performReadinessCheck verifies the server is ready to handle requests
func (s *Server) performReadinessCheck(ctx context.Context) error {
	// Check certificate expiry
	if err := s.checkCertificateExpiry(); err != nil {
		return fmt.Errorf("certificate check failed: %w", err)
	}

	// Additional readiness checks
	if err := s.checkKubernetesConnectivity(); err != nil {
		return fmt.Errorf("kubernetes connectivity check failed: %w", err)
	}

	if err := s.checkWebhookConfiguration(); err != nil {
		return fmt.Errorf("webhook configuration check failed: %w", err)
	}

	return nil
}

// checkKubernetesConnectivity verifies connection to Kubernetes API
func (s *Server) checkKubernetesConnectivity() error {
	// Try to get the kube-system namespace as a connectivity test
	_, err := s.client.CoreV1().Namespaces().Get(context.TODO(), "kube-system", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("cannot access Kubernetes API: %w", err)
	}
	return nil
}

// checkWebhookConfiguration verifies webhook is properly configured
func (s *Server) checkWebhookConfiguration() error {
	// Check if admission webhooks are properly configured
	// This is a basic check - in production, you might want to verify
	// the specific webhook configuration exists and is correct
	webhooks, err := s.client.AdmissionregistrationV1().MutatingAdmissionWebhooks().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("cannot list mutating admission webhooks: %w", err)
	}

	// Look for our webhook configuration
	found := false
	for _, webhook := range webhooks.Items {
		if strings.Contains(webhook.Name, "tailscale") {
			found = true
			break
		}
	}

	if !found {
		// This is a warning, not a hard error in some cases
		klog.Warning("No Tailscale webhook configuration found - this may be expected during initial setup")
	}

	return nil
}

// checkCertificateExpiry checks if the TLS certificate is about to expire
func (s *Server) checkCertificateExpiry() error {
	cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Update metrics
	s.metrics.SetCertificateExpiry(float64(x509Cert.NotAfter.Unix()))

	// Check expiry
	daysUntilExpiry := time.Until(x509Cert.NotAfter).Hours() / 24
	if daysUntilExpiry < 7 {
		klog.WarningS(nil, "Certificate expires very soon",
			"daysUntilExpiry", int(daysUntilExpiry),
			"expiryDate", x509Cert.NotAfter,
		)
	}

	return nil
}

// setReady updates the ready status
func (s *Server) setReady(ready bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ready = ready
}

// setHealthy updates the healthy status
func (s *Server) setHealthy(healthy bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.healthy = healthy
}

// isReady returns the ready status
func (s *Server) isReady() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ready
}

// isHealthy returns the healthy status
func (s *Server) isHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.healthy
}