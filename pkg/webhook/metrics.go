package webhook

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// NewMetrics creates and registers Prometheus metrics
func NewMetrics() (*Metrics, error) {
	m := &Metrics{
		webhookRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tailscale_webhook_requests_total",
				Help: "Total number of webhook requests",
			},
			[]string{"operation", "status"},
		),
		webhookDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "tailscale_webhook_duration_seconds",
				Help:    "Duration of webhook processing in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"operation"},
		),
		injectionAttemptsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tailscale_injection_attempts_total",
				Help: "Total number of injection attempts",
			},
			[]string{"namespace"},
		),
		injectionSuccessTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tailscale_injection_success_total",
				Help: "Total number of successful injections",
			},
			[]string{"namespace"},
		),
		validationAttemptsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tailscale_validation_attempts_total",
				Help: "Total number of validation attempts",
			},
			[]string{"namespace"},
		),
		validationSuccessTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tailscale_validation_success_total",
				Help: "Total number of successful validations",
			},
			[]string{"namespace"},
		),
		certificateExpiry: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "tailscale_webhook_cert_expiry_timestamp",
				Help: "Unix timestamp of webhook certificate expiry",
			},
		),
	}
	return m, nil
}

// RecordWebhookRequest records a webhook request
func (m *Metrics) RecordWebhookRequest(operation, status string) {
	m.webhookRequestsTotal.WithLabelValues(operation, status).Inc()
}

// RecordWebhookDuration records the duration of webhook processing
func (m *Metrics) RecordWebhookDuration(operation string, duration float64) {
	m.webhookDuration.WithLabelValues(operation).Observe(duration)
}

// RecordInjectionAttempt records an injection attempt
func (m *Metrics) RecordInjectionAttempt(namespace string) {
	m.injectionAttemptsTotal.WithLabelValues(namespace).Inc()
}

// RecordInjectionSuccess records a successful injection
func (m *Metrics) RecordInjectionSuccess(namespace string) {
	m.injectionSuccessTotal.WithLabelValues(namespace).Inc()
}

// RecordValidationAttempt records a validation attempt
func (m *Metrics) RecordValidationAttempt(namespace string) {
	m.validationAttemptsTotal.WithLabelValues(namespace).Inc()
}

// RecordValidationSuccess records a successful validation
func (m *Metrics) RecordValidationSuccess(namespace string) {
	m.validationSuccessTotal.WithLabelValues(namespace).Inc()
}

// SetCertificateExpiry sets the certificate expiry timestamp
func (m *Metrics) SetCertificateExpiry(timestamp float64) {
	m.certificateExpiry.Set(timestamp)
}