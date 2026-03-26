{{/*
Expand the name of the chart.
*/}}
{{- define "usgs-pub-wh-mcp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "usgs-pub-wh-mcp.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart label.
*/}}
{{- define "usgs-pub-wh-mcp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "usgs-pub-wh-mcp.labels" -}}
helm.sh/chart: {{ include "usgs-pub-wh-mcp.chart" . }}
{{ include "usgs-pub-wh-mcp.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "usgs-pub-wh-mcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "usgs-pub-wh-mcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Service account name.
*/}}
{{- define "usgs-pub-wh-mcp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{ default (include "usgs-pub-wh-mcp.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
{{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
ConfigMap name.
*/}}
{{- define "usgs-pub-wh-mcp.configMapName" -}}
{{- printf "%s-config" (include "usgs-pub-wh-mcp.fullname" .) -}}
{{- end -}}

{{/*
Secret name.
*/}}
{{- define "usgs-pub-wh-mcp.authSecretName" -}}
{{- if .Values.auth.existingSecret -}}
{{- .Values.auth.existingSecret -}}
{{- else if .Values.auth.secretName -}}
{{- .Values.auth.secretName -}}
{{- else -}}
{{- printf "%s-auth" (include "usgs-pub-wh-mcp.fullname" .) -}}
{{- end -}}
{{- end -}}
