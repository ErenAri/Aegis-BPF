{{/*
Expand the name of the chart.
*/}}
{{- define "aegisbpf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "aegisbpf.fullname" -}}
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
{{- define "aegisbpf.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "aegisbpf.labels" -}}
helm.sh/chart: {{ include "aegisbpf.chart" . }}
{{ include "aegisbpf.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "aegisbpf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aegisbpf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "aegisbpf.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "aegisbpf.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image name with tag
*/}}
{{- define "aegisbpf.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag }}
{{- if .Values.image.digest }}
{{- printf "%s:%s@%s" .Values.image.repository $tag .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}
{{- end }}

{{/*
Operator image name with tag and optional digest.
*/}}
{{- define "aegisbpf.operatorImage" -}}
{{- $tag := default .Chart.AppVersion .Values.operator.image.tag }}
{{- if .Values.operator.image.digest }}
{{- printf "%s:%s@%s" .Values.operator.image.repository $tag .Values.operator.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.operator.image.repository $tag }}
{{- end }}
{{- end }}

{{/*
Posture automation image name with tag and optional digest.
*/}}
{{- define "aegisbpf.postureAutomationImage" -}}
{{- if .Values.postureAutomation.image.digest }}
{{- printf "%s:%s@%s" .Values.postureAutomation.image.repository .Values.postureAutomation.image.tag .Values.postureAutomation.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.postureAutomation.image.repository .Values.postureAutomation.image.tag }}
{{- end }}
{{- end }}

{{/*
Webhook serving certificate secret.
*/}}
{{- define "aegisbpf.webhookSecretName" -}}
{{- if .Values.operator.webhook.certManager }}
{{- printf "%s-webhook-tls" (include "aegisbpf.fullname" .) }}
{{- else }}
{{- required "operator.webhook.tls.secretName is required when operator.webhook.enabled=true and operator.webhook.certManager=false" .Values.operator.webhook.tls.secretName }}
{{- end }}
{{- end }}
