{{- define "kdt-identity.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kdt-identity.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "kdt-identity.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "kdt-identity.labels" -}}
app.kubernetes.io/name: {{ include "kdt-identity.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "kdt-identity.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kdt-identity.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kdt-identity.serviceAccountName" -}}
{{- default (include "kdt-identity.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{/*
  Environnement commun aux deux déploiements. Les valeurs sensibles arrivent par `envFrom`
  depuis des Secrets, jamais en clair ici : un ConfigMap est lisible par quiconque peut lister
  les ConfigMaps du namespace.
*/}}
{{- define "kdt-identity.env" -}}
- name: KDT_IDENTITY_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
- name: KDT_IDENTITY_CLUSTER_NAME
  value: {{ required "clusterName est obligatoire : il nomme le cluster pour les utilisateurs" .Values.clusterName | quote }}
- name: KDT_IDENTITY_PORTAL_URL
  value: {{ required "portalUrl est obligatoire : il sert à construire les liens d'activation" .Values.portalUrl | quote }}
- name: KDT_IDENTITY_APISERVER_URL
  value: {{ required "apiserverUrl est obligatoire : l'URL interne du service ne sert à rien à un poste de travail" .Values.apiserverUrl | quote }}
- name: RUST_LOG
  value: {{ .Values.logLevel | quote }}
{{- end -}}
