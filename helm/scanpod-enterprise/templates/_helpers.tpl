{{- define "transport-lookout.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "transport-lookout.credentialsSecretName" -}}
{{- default (printf "%s-credentials" (include "transport-lookout.fullname" .)) .Values.env.existingSecret }}
{{- end }}

{{- define "transport-lookout.serviceAccountName" -}}
{{- if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else if .Values.serviceAccount.create }}
{{- printf "%s-worker" (include "transport-lookout.fullname" .) }}
{{- else }}
default
{{- end }}
{{- end }}

{{- define "transport-lookout.env" -}}
- name: SCANPOD_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "transport-lookout.credentialsSecretName" . }}
      key: {{ .Values.env.databaseUrlKey }}
- name: SCANPOD_AMQP_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "transport-lookout.credentialsSecretName" . }}
      key: {{ .Values.env.amqpUrlKey }}
- name: SCANPOD_BOOTSTRAP_ENABLED
  value: {{ .Values.env.bootstrapEnabled | quote }}
- name: SCANPOD_ARTIFACT_BACKEND
  value: {{ .Values.env.artifactBackend | quote }}
{{- if eq .Values.env.artifactBackend "s3" }}
- name: SCANPOD_ARTIFACT_S3_BUCKET
  value: {{ .Values.env.artifactS3Bucket | quote }}
- name: SCANPOD_ARTIFACT_S3_PREFIX
  value: {{ .Values.env.artifactS3Prefix | quote }}
- name: SCANPOD_ARTIFACT_S3_REGION
  value: {{ .Values.env.artifactS3Region | quote }}
{{- if .Values.env.artifactS3EndpointUrl }}
- name: SCANPOD_ARTIFACT_S3_ENDPOINT_URL
  value: {{ .Values.env.artifactS3EndpointUrl | quote }}
{{- end }}
{{- end }}
{{- end }}
