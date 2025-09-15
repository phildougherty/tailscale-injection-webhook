{{/*
Expand the name of the chart.
*/}}
{{- define "tailscale-injector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "tailscale-injector.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "tailscale-injector.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "tailscale-injector.labels" -}}
helm.sh/chart: {{ include "tailscale-injector.chart" . }}
{{ include "tailscale-injector.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "tailscale-injector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tailscale-injector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "tailscale-injector.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "tailscale-injector.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the auth key secret
*/}}
{{- define "tailscale-injector.authKeySecretName" -}}
{{- if .Values.authKey.secretName }}
{{- .Values.authKey.secretName }}
{{- else }}
{{- printf "%s-auth-key" (include "tailscale-injector.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Create the name of the certificates secret
*/}}
{{- define "tailscale-injector.certificateSecretName" -}}
{{- printf "%s-certs" (include "tailscale-injector.fullname" .) }}
{{- end }}

{{/*
Create the name of the CA secret
*/}}
{{- define "tailscale-injector.caSecretName" -}}
{{- printf "%s-ca" (include "tailscale-injector.fullname" .) }}
{{- end }}

{{/*
Create the name of the configuration ConfigMap
*/}}
{{- define "tailscale-injector.configMapName" -}}
{{- printf "%s-config" (include "tailscale-injector.fullname" .) }}
{{- end }}

{{/*
Create the image name
*/}}
{{- define "tailscale-injector.image" -}}
{{- $registry := .Values.global.imageRegistry | default .Values.image.registry -}}
{{- if $registry }}
{{- printf "%s/%s:%s" $registry .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}
{{- end }}

{{/*
Create the namespace
*/}}
{{- define "tailscale-injector.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride }}
{{- end }}

{{/*
Common annotations
*/}}
{{- define "tailscale-injector.annotations" -}}
{{- with .Values.commonAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Pod annotations
*/}}
{{- define "tailscale-injector.podAnnotations" -}}
{{- with .Values.pod.annotations }}
{{ toYaml . }}
{{- end }}
{{- with .Values.commonAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Service annotations
*/}}
{{- define "tailscale-injector.serviceAnnotations" -}}
{{- with .Values.service.annotations }}
{{ toYaml . }}
{{- end }}
{{- with .Values.commonAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Validate auth key configuration
*/}}
{{- define "tailscale-injector.validateAuthKey" -}}
{{- if and (not .Values.authKey.value) (not .Values.authKey.secretName) }}
{{- fail "Either authKey.value or authKey.secretName must be provided" }}
{{- end }}
{{- end }}

{{/*
CA Bundle for webhooks
*/}}
{{- define "tailscale-injector.caBundle" -}}
{{- if eq .Values.certificates.method "cert-manager" }}
# CA bundle will be injected by cert-manager
{{- else if eq .Values.certificates.method "manual" }}
{{- .Values.certificates.manual.caCert }}
{{- else }}
# CA bundle will be injected by certificate management
{{- end }}
{{- end }}

{{/*
Certificate issuer name
*/}}
{{- define "tailscale-injector.issuerName" -}}
{{- if eq .Values.certificates.certManager.issuerType "selfsigned" }}
{{- printf "%s-selfsigned" (include "tailscale-injector.fullname" .) }}
{{- else if eq .Values.certificates.certManager.issuerType "ca" }}
{{- printf "%s-ca-issuer" (include "tailscale-injector.fullname" .) }}
{{- else }}
{{- printf "%s-issuer" (include "tailscale-injector.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Webhook service name
*/}}
{{- define "tailscale-injector.webhookServiceName" -}}
{{- include "tailscale-injector.fullname" . }}
{{- end }}

{{/*
Metrics service name
*/}}
{{- define "tailscale-injector.metricsServiceName" -}}
{{- printf "%s-metrics" (include "tailscale-injector.fullname" .) }}
{{- end }}

{{/*
Environment variables
*/}}
{{- define "tailscale-injector.env" -}}
- name: TAILSCALE_WEBHOOK_BIND_ADDRESS
  value: {{ .Values.webhook.bindAddress | quote }}
- name: TAILSCALE_WEBHOOK_PORT
  value: {{ .Values.webhook.port | quote }}
- name: TAILSCALE_WEBHOOK_TLS_CERT_FILE
  value: {{ .Values.webhook.certFile | quote }}
- name: TAILSCALE_WEBHOOK_TLS_KEY_FILE
  value: {{ .Values.webhook.keyFile | quote }}
- name: TAILSCALE_WEBHOOK_CONFIG_FILE
  value: "/etc/config/config.yaml"
- name: TAILSCALE_WEBHOOK_METRICS
  value: {{ .Values.metrics.enabled | quote }}
- name: TAILSCALE_WEBHOOK_METRICS_BIND_ADDRESS
  value: {{ .Values.metrics.bindAddress | quote }}
- name: TAILSCALE_WEBHOOK_METRICS_PORT
  value: {{ .Values.metrics.port | quote }}
{{- end }}

{{/*
Volume mounts
*/}}
{{- define "tailscale-injector.volumeMounts" -}}
- name: certs
  mountPath: /etc/certs
  readOnly: true
- name: config
  mountPath: /etc/config
  readOnly: true
{{- end }}

{{/*
Volumes
*/}}
{{- define "tailscale-injector.volumes" -}}
- name: certs
  secret:
    secretName: {{ include "tailscale-injector.certificateSecretName" . }}
    defaultMode: 0644
- name: config
  configMap:
    name: {{ include "tailscale-injector.configMapName" . }}
    defaultMode: 0644
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "tailscale-injector.imagePullSecrets" -}}
{{- $secrets := list -}}
{{- if .Values.global.imagePullSecrets -}}
{{- $secrets = concat $secrets .Values.global.imagePullSecrets -}}
{{- end -}}
{{- if .Values.image.pullSecrets -}}
{{- $secrets = concat $secrets .Values.image.pullSecrets -}}
{{- end -}}
{{- if $secrets -}}
imagePullSecrets:
{{- range $secrets }}
- name: {{ . }}
{{- end }}
{{- end }}
{{- end }}