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
{{- /*
  Le mode est commun aux deux déploiements : les commandes d'administration s'exécutent dans le
  pod du contrôleur, et « revoke » doit savoir s'il y a des sessions à fermer.
*/}}
- name: KDT_IDENTITY_CREDENTIAL_MODE
  value: {{ .Values.credentialMode | quote }}
- name: KDT_IDENTITY_REFRESH_TTL
  value: {{ .Values.refreshTtl | quote }}
{{- if eq .Values.credentialMode "certificate" }}
- name: KDT_IDENTITY_CERT_TTL
  value: {{ .Values.certTtl | quote }}
- name: KDT_IDENTITY_DOWNLOAD_CERT_TTL
  value: {{ .Values.portal.downloadCertTtl | quote }}
- name: KDT_IDENTITY_KUBECONFIG_DOWNLOAD
  value: {{ .Values.portal.kubeconfigDownload | quote }}
{{- end }}
{{- if eq .Values.credentialMode "oidc" }}
- name: KDT_IDENTITY_OIDC_AUDIENCE
  value: {{ .Values.oidc.audience | quote }}
- name: KDT_IDENTITY_OIDC_TOKEN_TTL
  value: {{ .Values.oidc.tokenTtl | quote }}
{{- end }}
{{- end -}}

{{/*
  Refuse une combinaison de valeurs qui produirait un déploiement inerte : le portail
  démarrerait, signerait des jetons parfaitement formés, et l'apiserver les refuserait tous
  sans que rien ne dise pourquoi.
*/}}
{{- define "kdt-identity.validate" -}}
{{- if not (has .Values.credentialMode (list "certificate" "oidc")) -}}
{{- fail (printf "credentialMode vaut %q : attendu certificate ou oidc" .Values.credentialMode) -}}
{{- end -}}
{{- if eq .Values.credentialMode "oidc" -}}
{{- if not (hasPrefix "https://" .Values.portalUrl) -}}
{{- fail "credentialMode=oidc exige un portalUrl en https : c'est l'émetteur que l'apiserver vérifie, et il n'en accepte pas d'autre" -}}
{{- end -}}
{{- if not .Values.ingress.enabled -}}
{{- fail "credentialMode=oidc exige que l'apiserver puisse joindre le portail : activez l'ingress, ou exposez-le autrement et retirez ce garde-fou" -}}
{{- end -}}
{{- end -}}
{{- end -}}
