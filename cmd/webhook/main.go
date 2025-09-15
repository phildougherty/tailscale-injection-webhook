package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/klog/v2"

	"github.com/phildougherty/tailscale-injection-webhook/pkg/webhook"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Set up panic recovery
	defer func() {
		if r := recover(); r != nil {
			klog.ErrorS(fmt.Errorf("panic: %v", r), "Application panicked",
				"stack", string(debug.Stack()),
				"goroutines", runtime.NumGoroutine(),
			)
			os.Exit(1)
		}
	}()

	// Configure runtime
	runtime.GOMAXPROCS(runtime.NumCPU())

	klog.InitFlags(nil)

	var rootCmd = &cobra.Command{
		Use:   "tailscale-injection-webhook",
		Short: "Tailscale admission webhook for Kubernetes sidecar injection",
		Long: `A Kubernetes admission webhook that automatically injects Tailscale sidecar containers
into pods based on annotations. This enables seamless mesh networking for your applications.`,
		Run: runWebhook,
	}

	// Define flags with proper defaults and validation
	rootCmd.Flags().String("bind-address", "0.0.0.0", "Address to bind the webhook server to")
	rootCmd.Flags().Int("port", 8443, "Port to serve the webhook on")
	rootCmd.Flags().String("tls-cert-file", "/etc/certs/tls.crt", "Path to TLS certificate file")
	rootCmd.Flags().String("tls-key-file", "/etc/certs/tls.key", "Path to TLS private key file")
	rootCmd.Flags().String("kubeconfig", "", "Path to kubeconfig file (optional, uses in-cluster config if not provided)")
	rootCmd.Flags().String("config-file", "/etc/config/config.yaml", "Path to webhook configuration file")
	rootCmd.Flags().Bool("version", false, "Print version information and exit")
	rootCmd.Flags().Duration("graceful-timeout", 30*time.Second, "Graceful shutdown timeout")
	rootCmd.Flags().Bool("metrics", true, "Enable metrics endpoint")
	rootCmd.Flags().String("metrics-bind-address", "0.0.0.0", "Address to bind the metrics server to")
	rootCmd.Flags().Int("metrics-port", 8080, "Port to serve metrics on")
	rootCmd.Flags().Int("health-port", 8081, "Port to serve health checks on")
	rootCmd.Flags().Duration("read-timeout", 30*time.Second, "HTTP read timeout")
	rootCmd.Flags().Duration("write-timeout", 30*time.Second, "HTTP write timeout")
	rootCmd.Flags().Duration("idle-timeout", 60*time.Second, "HTTP idle timeout")
	rootCmd.Flags().String("client-ca-file", "", "Path to client CA certificate file (optional)")
	rootCmd.Flags().String("tls-min-version", "1.3", "Minimum TLS version (1.2 or 1.3)")

	// Bind flags to viper with environment variable support
	viper.BindPFlags(rootCmd.Flags())
	viper.SetEnvPrefix("TAILSCALE_WEBHOOK")
	viper.AutomaticEnv()

	flag.Parse()

	if err := rootCmd.Execute(); err != nil {
		klog.ErrorS(err, "Failed to execute command")
		os.Exit(1)
	}
}

func runWebhook(cmd *cobra.Command, args []string) {
	if viper.GetBool("version") {
		printVersion()
		return
	}

	logStartupInfo()

	// Validate configuration early
	config, err := createWebhookConfig()
	if err != nil {
		klog.ErrorS(err, "Invalid configuration")
		os.Exit(1)
	}

	// Load additional configuration from file if specified
	if err := loadConfigFile(); err != nil {
		klog.ErrorS(err, "Failed to load configuration file")
		os.Exit(1)
	}

	// Create webhook server with proper error handling
	webhookServer, err := webhook.NewServer(config)
	if err != nil {
		klog.ErrorS(err, "Failed to create webhook server")
		os.Exit(1)
	}

	// Set up signal handling for graceful shutdown
	ctx, cancel := setupSignalHandling()
	defer cancel()

	// Start webhook server in goroutine
	serverErrChan := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				serverErrChan <- fmt.Errorf("webhook server panic: %v", r)
			}
		}()

		if err := webhookServer.Start(ctx); err != nil && err != http.ErrServerClosed {
			serverErrChan <- fmt.Errorf("webhook server failed: %w", err)
		}
	}()

	klog.InfoS("Webhook server started",
		"address", fmt.Sprintf("%s:%d", config.BindAddress, config.Port),
		"metrics", config.MetricsEnabled,
		"health", fmt.Sprintf("%s:%d", config.BindAddress, config.HealthPort),
	)

	// Wait for shutdown signal or server error
	select {
	case <-ctx.Done():
		klog.InfoS("Shutdown signal received")
	case err := <-serverErrChan:
		klog.ErrorS(err, "Server error received")
		cancel()
	}

	// Perform graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), viper.GetDuration("graceful-timeout"))
	defer shutdownCancel()

	klog.InfoS("Shutting down webhook server...")

	if err := webhookServer.Shutdown(shutdownCtx); err != nil {
		klog.ErrorS(err, "Failed to gracefully shutdown webhook server")
		os.Exit(1)
	}

	klog.InfoS("Webhook server shutdown complete")
}

func printVersion() {
	fmt.Printf("Tailscale Injection Webhook\n")
	fmt.Printf("Version: %s\n", version)
	fmt.Printf("Commit: %s\n", commit)
	fmt.Printf("Build Date: %s\n", date)
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

func logStartupInfo() {
	klog.InfoS("Starting Tailscale Injection Webhook",
		"version", version,
		"commit", commit,
		"buildDate", date,
		"goVersion", runtime.Version(),
		"platform", fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		"maxProcs", runtime.GOMAXPROCS(0),
	)
}

func createWebhookConfig() (*webhook.Config, error) {
	// Parse TLS minimum version
	var tlsMinVersion uint16
	switch viper.GetString("tls-min-version") {
	case "1.2":
		tlsMinVersion = tls.VersionTLS12
	case "1.3":
		tlsMinVersion = tls.VersionTLS13
	default:
		return nil, fmt.Errorf("invalid TLS minimum version: %s (must be 1.2 or 1.3)", viper.GetString("tls-min-version"))
	}

	config := &webhook.Config{
		BindAddress:        viper.GetString("bind-address"),
		Port:               viper.GetInt("port"),
		TLSCertFile:        viper.GetString("tls-cert-file"),
		TLSKeyFile:         viper.GetString("tls-key-file"),
		KubeConfig:         viper.GetString("kubeconfig"),
		MetricsEnabled:     viper.GetBool("metrics"),
		MetricsBindAddress: viper.GetString("metrics-bind-address"),
		MetricsPort:        viper.GetInt("metrics-port"),
		HealthPort:         viper.GetInt("health-port"),
		ReadTimeout:        viper.GetDuration("read-timeout"),
		WriteTimeout:       viper.GetDuration("write-timeout"),
		IdleTimeout:        viper.GetDuration("idle-timeout"),
		TLSMinVersion:      tlsMinVersion,
		ClientCAFile:       viper.GetString("client-ca-file"),
	}

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

func validateConfig(config *webhook.Config) error {
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("invalid port: %d", config.Port)
	}
	if config.MetricsPort <= 0 || config.MetricsPort > 65535 {
		return fmt.Errorf("invalid metrics port: %d", config.MetricsPort)
	}
	if config.HealthPort <= 0 || config.HealthPort > 65535 {
		return fmt.Errorf("invalid health port: %d", config.HealthPort)
	}
	if config.ReadTimeout <= 0 {
		return fmt.Errorf("read timeout must be positive")
	}
	if config.WriteTimeout <= 0 {
		return fmt.Errorf("write timeout must be positive")
	}
	if config.IdleTimeout <= 0 {
		return fmt.Errorf("idle timeout must be positive")
	}
	if config.TLSCertFile == "" {
		return fmt.Errorf("TLS certificate file must be specified")
	}
	if config.TLSKeyFile == "" {
		return fmt.Errorf("TLS key file must be specified")
	}

	return nil
}

func loadConfigFile() error {
	configFile := viper.GetString("config-file")
	if configFile == "" {
		return nil
	}

	// Check if config file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		klog.InfoS("Configuration file does not exist, using defaults", "file", configFile)
		return nil
	}

	viper.SetConfigFile(configFile)
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config file %s: %w", configFile, err)
	}

	klog.InfoS("Loaded configuration", "file", configFile)
	return nil
}

func setupSignalHandling() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	// Handle shutdown signals
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		sig := <-signalChan
		klog.InfoS("Received signal", "signal", sig)
		cancel()
	}()

	return ctx, cancel
}