{{- define "web.labels" -}}
app.kubernetes.io/name: {{ .Values.appId }}
app.kubernetes.io/instance: {{ .Release.Name }}
aegis.io/app: {{ .Values.appId }}
aegis.io/environment: {{ .Values.environment }}
{{- end -}}
{{- define "web.selector" -}}
app.kubernetes.io/name: {{ .Values.appId }}
aegis.io/environment: {{ .Values.environment }}
{{- end -}}
{{- define "web.binding" -}}
{{- if ne .Release.Namespace (printf "aegis-%s-%s" .Values.appId .Values.environment) -}}
{{- fail "Namespace must match the app/environment binding" -}}
{{- end -}}
{{- if ne .Release.Name .Values.appId -}}
{{- fail "Helm release name must match the registered application" -}}
{{- end -}}
{{- end -}}
