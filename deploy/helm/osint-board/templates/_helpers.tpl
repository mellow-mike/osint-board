{{- define "osint.name" -}}{{ .Chart.Name }}{{- end -}}
{{- define "osint.labels" -}}
app.kubernetes.io/name: {{ include "osint.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
{{- end -}}
{{- define "osint.env" -}}
envFrom:
  - configMapRef:
      name: {{ include "osint.name" . }}-config
  - secretRef:
      name: {{ .Values.existingSecret }}
{{- end -}}
