package webhook

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"k8s.io/klog/v2"
)

// withMiddleware wraps the handler with logging, metrics, and panic recovery
func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Add request ID for tracing
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}

		// Create response wrapper to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Panic recovery
		defer func() {
			if rec := recover(); rec != nil {
				klog.ErrorS(fmt.Errorf("panic: %v", rec), "Handler panicked",
					"requestID", requestID,
					"method", r.Method,
					"path", r.URL.Path,
					"stack", string(debug.Stack()),
				)

				// Record metrics
				s.metrics.RecordWebhookRequest(r.URL.Path, "panic")

				// Return error response
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()

		// Log request
		klog.V(4).InfoS("Handling request",
			"requestID", requestID,
			"method", r.Method,
			"path", r.URL.Path,
			"remoteAddr", r.RemoteAddr,
		)

		// Call the actual handler
		next.ServeHTTP(rw, r)

		// Calculate duration
		duration := time.Since(start).Seconds()

		// Record metrics
		status := fmt.Sprintf("%d", rw.statusCode)
		s.metrics.RecordWebhookRequest(r.URL.Path, status)
		s.metrics.RecordWebhookDuration(r.URL.Path, duration)

		// Log response
		klog.V(4).InfoS("Request completed",
			"requestID", requestID,
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.statusCode,
			"duration", duration,
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.ResponseWriter.WriteHeader(code)
		rw.written = true
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}

// NewErrorLogger creates a new error logger for the HTTP server
func NewErrorLogger() *log.Logger {
	return log.New(klogWriter{}, "", 0)
}

// klogWriter implements io.Writer to redirect logs to klog
type klogWriter struct{}

func (klogWriter) Write(p []byte) (n int, err error) {
	klog.ErrorS(nil, string(p))
	return len(p), nil
}

// validateTLSConfig validates the TLS certificate and key files
func validateTLSConfig(certFile, keyFile string) error {
	// Check if files exist
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return fmt.Errorf("TLS certificate file does not exist: %s", certFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return fmt.Errorf("TLS key file does not exist: %s", keyFile)
	}

	// Read certificate file
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Parse certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check certificate expiry
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid (not before: %v)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired (not after: %v)", cert.NotAfter)
	}

	// Warn if certificate expires soon
	daysUntilExpiry := cert.NotAfter.Sub(now).Hours() / 24
	if daysUntilExpiry < 30 {
		klog.WarningS(nil, "Certificate expires soon",
			"daysUntilExpiry", int(daysUntilExpiry),
			"expiryDate", cert.NotAfter,
		)
	}

	klog.InfoS("TLS certificate validated successfully",
		"subject", cert.Subject,
		"issuer", cert.Issuer,
		"notBefore", cert.NotBefore,
		"notAfter", cert.NotAfter,
	)

	return nil
}

// readBody safely reads the request body with size limits
func readBodySafe(r *http.Request) ([]byte, error) {
	defer r.Body.Close()

	// Limit request body size to 1MB
	const maxBodySize = 1 << 20 // 1MB
	limitedReader := io.LimitReader(r.Body, maxBodySize+1)

	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	if len(body) > maxBodySize {
		return nil, fmt.Errorf("request body too large (max %d bytes)", maxBodySize)
	}

	return body, nil
}