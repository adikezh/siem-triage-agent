{{- define "siem-triage-agent.name" -}}{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}{{- end }}
{{- define "siem-triage-agent.fullname" -}}{{- default (include "siem-triage-agent.name" .) .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}{{- end }}
{{- define "siem-triage-agent.labels" -}}
app.kubernetes.io/name: {{ include "siem-triage-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
