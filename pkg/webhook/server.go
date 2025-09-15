package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/phildougherty/tailscale-injection-webhook/pkg/injection"
	"github.com/phildougherty/tailscale-injection-webhook/pkg/tailscale"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

// Config holds the webhook server configuration
type Config struct {
	BindAddress        string
	Port               int
	TLSCertFile        string
	TLSKeyFile         string
	KubeConfig         string
	MetricsEnabled     bool
	MetricsBindAddress string
	MetricsPort        int
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	IdleTimeout        time.Duration
	MaxHeaderBytes     int
	TLSMinVersion      uint16
	ClientCAFile       string
	HealthPort         int
}

// Server represents the admission webhook server
type Server struct {
	config        *Config
	server        *http.Server
	metricsServer *http.Server
	healthServer  *http.Server
	client        kubernetes.Interface
	injector      *injection.Injector
	tsAuth        *tailscale.Authenticator
	metrics       *Metrics
	mu            sync.RWMutex
	ready         bool
	healthy       bool
}

// Metrics holds Prometheus metrics
type Metrics struct {
	webhookRequestsTotal    *prometheus.CounterVec
	webhookDuration         *prometheus.HistogramVec
	injectionAttemptsTotal  *prometheus.CounterVec
	injectionSuccessTotal   *prometheus.CounterVec
	validationAttemptsTotal *prometheus.CounterVec
	validationSuccessTotal  *prometheus.CounterVec
	certificateExpiry       prometheus.Gauge
}

// NewServer creates a new webhook server
func NewServer(config *Config) (*Server, error) {
	// Set defaults
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 30 * time.Second
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 30 * time.Second
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 60 * time.Second
	}
	if config.MaxHeaderBytes == 0 {
		config.MaxHeaderBytes = 1 << 20 // 1MB
	}
	if config.TLSMinVersion == 0 {
		config.TLSMinVersion = tls.VersionTLS13
	}
	if config.HealthPort == 0 {
		config.HealthPort = 8081
	}

	// Validate TLS configuration
	if err := validateTLSConfig(config.TLSCertFile, config.TLSKeyFile); err != nil {
		return nil, fmt.Errorf("TLS configuration validation failed: %w", err)
	}

	// Create Kubernetes client with retry and rate limiting
	var kubeConfig *rest.Config
	var err error

	if config.KubeConfig != "" {
		kubeConfig, err = clientcmd.BuildConfigFromFlags("", config.KubeConfig)
	} else {
		kubeConfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes config: %w", err)
	}

	// Configure client with proper timeouts and rate limiting
	kubeConfig.Timeout = 30 * time.Second
	kubeConfig.QPS = 50
	kubeConfig.Burst = 100

	client, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	// Create Tailscale authenticator
	tsAuth, err := tailscale.NewAuthenticator()
	if err != nil {
		return nil, fmt.Errorf("failed to create tailscale authenticator: %w", err)
	}
	tsAuth.SetClient(client)

	// Create sidecar injector
	injector := injection.NewInjector(client, tsAuth)

	// Initialize metrics
	metrics, err := NewMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	// Setup HTTP mux with middleware
	mux := http.NewServeMux()
	server := &Server{
		config:   config,
		client:   client,
		injector: injector,
		tsAuth:   tsAuth,
		metrics:  metrics,
		healthy:  true,
		ready:    false,
	}

	// Add middleware for logging, metrics, and panic recovery
	mux.Handle("/mutate", server.withMiddleware(http.HandlerFunc(server.handleMutate)))
	mux.Handle("/validate", server.withMiddleware(http.HandlerFunc(server.handleValidate)))

	// Create TLS config with security hardening
	tlsConfig, err := server.createTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	// Create main server with security hardening
	server.server = &http.Server{
		Addr:           fmt.Sprintf("%s:%d", config.BindAddress, config.Port),
		Handler:        mux,
		TLSConfig:      tlsConfig,
		ReadTimeout:    config.ReadTimeout,
		WriteTimeout:   config.WriteTimeout,
		IdleTimeout:    config.IdleTimeout,
		MaxHeaderBytes: config.MaxHeaderBytes,
		ErrorLog:       NewErrorLogger(),
	}

	// Create separate health server (non-TLS)
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", server.handleHealth)
	healthMux.HandleFunc("/ready", server.handleReady)
	server.healthServer = &http.Server{
		Addr:           fmt.Sprintf("%s:%d", config.BindAddress, config.HealthPort),
		Handler:        healthMux,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    30 * time.Second,
		MaxHeaderBytes: 1 << 16, // 64KB
	}

	// Create metrics server if enabled
	if config.MetricsEnabled {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", promhttp.Handler())
		server.metricsServer = &http.Server{
			Addr:           fmt.Sprintf("%s:%d", config.MetricsBindAddress, config.MetricsPort),
			Handler:        metricsMux,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			IdleTimeout:    30 * time.Second,
			MaxHeaderBytes: 1 << 16, // 64KB
		}
	}

	return server, nil
}

// Start starts the webhook server
func (s *Server) Start(ctx context.Context) error {
	// Start health server
	go func() {
		klog.InfoS("Starting health server", "address", s.healthServer.Addr)
		if err := s.healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			klog.ErrorS(err, "Health server failed")
		}
	}()

	// Start metrics server if enabled
	if s.metricsServer != nil {
		go func() {
			klog.InfoS("Starting metrics server", "address", s.metricsServer.Addr)
			if err := s.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				klog.ErrorS(err, "Metrics server failed")
			}
		}()
	}

	// Wait a moment for servers to start
	time.Sleep(100 * time.Millisecond)

	// Perform readiness check
	if err := s.performReadinessCheck(ctx); err != nil {
		klog.ErrorS(err, "Readiness check failed")
		return fmt.Errorf("readiness check failed: %w", err)
	}

	s.setReady(true)

	// Start main webhook server
	klog.InfoS("Starting webhook server", "address", s.server.Addr)
	return s.server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
}

// Shutdown gracefully shuts down the webhook server
func (s *Server) Shutdown(ctx context.Context) error {
	s.setReady(false)
	s.setHealthy(false)

	klog.InfoS("Shutting down webhook server...")

	// Create a wait group to track all shutdowns
	var wg sync.WaitGroup
	errorChan := make(chan error, 3)

	// Shutdown health server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.healthServer.Shutdown(ctx); err != nil {
			klog.ErrorS(err, "Failed to shutdown health server")
			errorChan <- err
		}
	}()

	// Shutdown metrics server
	if s.metricsServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.metricsServer.Shutdown(ctx); err != nil {
				klog.ErrorS(err, "Failed to shutdown metrics server")
				errorChan <- err
			}
		}()
	}

	// Shutdown main server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.server.Shutdown(ctx); err != nil {
			klog.ErrorS(err, "Failed to shutdown main server")
			errorChan <- err
		}
	}()

	// Wait for all shutdowns to complete
	go func() {
		wg.Wait()
		close(errorChan)
	}()

	// Return first error if any
	select {
	case err := <-errorChan:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func (s *Server) handleMutate(w http.ResponseWriter, r *http.Request) {
	klog.V(4).InfoS("Handling mutation request", "method", r.Method, "url", r.URL.Path)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := readBody(r)
	if err != nil {
		klog.ErrorS(err, "Failed to read request body")
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var admissionReview admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &admissionReview); err != nil {
		klog.ErrorS(err, "Failed to unmarshal admission review")
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	response := s.mutate(&admissionReview)
	responseBytes, err := json.Marshal(response)
	if err != nil {
		klog.ErrorS(err, "Failed to marshal admission response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(responseBytes); err != nil {
		klog.ErrorS(err, "Failed to write response")
	}
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	klog.V(4).InfoS("Handling validation request", "method", r.Method, "url", r.URL.Path)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := readBody(r)
	if err != nil {
		klog.ErrorS(err, "Failed to read request body")
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var admissionReview admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &admissionReview); err != nil {
		klog.ErrorS(err, "Failed to unmarshal admission review")
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	response := s.validate(&admissionReview)
	responseBytes, err := json.Marshal(response)
	if err != nil {
		klog.ErrorS(err, "Failed to marshal admission response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(responseBytes); err != nil {
		klog.ErrorS(err, "Failed to write response")
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	// Check if we can connect to Kubernetes API
	_, err := s.client.CoreV1().Namespaces().Get(r.Context(), "kube-system", metav1.GetOptions{})
	if err != nil {
		klog.ErrorS(err, "Readiness check failed - cannot connect to Kubernetes API")
		http.Error(w, "Not ready", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Ready"))
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// Use the standard Prometheus handler
	handler := promhttp.Handler()
	handler.ServeHTTP(w, r)
}

func readBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	body := make([]byte, r.ContentLength)
	if _, err := r.Body.Read(body); err != nil {
		return nil, err
	}
	return body, nil
}