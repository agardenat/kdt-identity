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
  kdt-web est facultative. Sans cette valeur, le flow d'autorisation n'est pas monté et la page
  du compte n'en dit rien : le portail n'annonce pas ce qui n'a pas été déclaré.
*/}}
{{- if .Values.webUrl }}
- name: KDT_IDENTITY_WEB_URL
  value: {{ .Values.webUrl | quote }}
{{- end }}
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
{{- /*
  Le mode d'authentification est orthogonal au mode de délivrance : le premier dit qui reconnaît
  la personne, le second ce qu'on lui remet. Les quatre combinaisons sont valides.
*/}}
- name: KDT_IDENTITY_AUTH_MODE
  value: {{ .Values.authMode | quote }}
{{- if eq .Values.authMode "ldap" }}
- name: KDT_IDENTITY_LDAP_PROFILE
  value: {{ .Values.ldap.profile | quote }}
- name: KDT_IDENTITY_LDAP_URL
  value: {{ required "ldap.url est obligatoire en authMode=ldap" .Values.ldap.url | quote }}
- name: KDT_IDENTITY_LDAP_START_TLS
  value: {{ .Values.ldap.startTls | quote }}
- name: KDT_IDENTITY_LDAP_USER_SEARCH_BASE
  value: {{ required "ldap.userSearchBase est obligatoire en authMode=ldap" .Values.ldap.userSearchBase | quote }}
- name: KDT_IDENTITY_LDAP_TIMEOUT
  value: {{ .Values.ldap.timeout | quote }}
- name: KDT_IDENTITY_LDAP_RESYNC
  value: {{ .Values.ldap.resync | quote }}
{{- /*
  La table de correspondance voyage en JSON : c'est la seule forme qu'une variable
  d'environnement puisse porter sans ambiguïté, et `toJson` échappe pour nous ce que des DN
  pleins de virgules et d'égals mettraient à mal.
*/}}
- name: KDT_IDENTITY_LDAP_GROUP_MAPPINGS
  value: {{ .Values.ldap.groupMappings | toJson | quote }}
{{- /*
  Les attributs ne sont posés que s'ils sont surchargés : une variable vide vaut une variable
  absente côté serveur, qui reprend alors le défaut du profil.
*/}}
{{- range $var, $value := dict "LOGIN_ATTR" .Values.ldap.userLoginAttribute "EMAIL_ATTR" .Values.ldap.userEmailAttribute "DISPLAY_ATTR" .Values.ldap.userDisplayAttribute "MEMBER_ATTR" .Values.ldap.groupMemberAttribute "OBJECT_CLASS" .Values.ldap.userObjectClass }}
{{- if $value }}
- name: KDT_IDENTITY_LDAP_{{ $var }}
  value: {{ $value | quote }}
{{- end }}
{{- end }}
{{- if $.Values.ldap.caCert }}
- name: KDT_IDENTITY_LDAP_CA_FILE
  value: /etc/kdt-identity/ldap/ca.crt
- name: KDT_IDENTITY_RUNTIME_DIR
  value: /run/kdt-identity
{{- end }}
{{- end }}
{{- if eq .Values.authMode "oidc" }}
- name: KDT_IDENTITY_AUTH_OIDC_ISSUER
  value: {{ required "oidcAuth.issuer est obligatoire en authMode=oidc" .Values.oidcAuth.issuer | quote }}
- name: KDT_IDENTITY_AUTH_OIDC_CLIENT_ID
  value: {{ required "oidcAuth.clientId est obligatoire en authMode=oidc" .Values.oidcAuth.clientId | quote }}
- name: KDT_IDENTITY_AUTH_OIDC_SCOPES
  value: {{ .Values.oidcAuth.scopes | quote }}
- name: KDT_IDENTITY_AUTH_OIDC_TIMEOUT
  value: {{ .Values.oidcAuth.timeout | quote }}
{{- /*
  Même forme qu'en LDAP, et pour la même raison : le JSON est ce qu'une variable d'environnement
  porte sans ambiguïté, et `toJson` échappe ce que des chemins de groupes mettraient à mal.
*/}}
- name: KDT_IDENTITY_AUTH_OIDC_GROUP_MAPPINGS
  value: {{ .Values.oidcAuth.groupMappings | toJson | quote }}
{{- if .Values.oidcAuth.providerName }}
- name: KDT_IDENTITY_AUTH_OIDC_PROVIDER_NAME
  value: {{ .Values.oidcAuth.providerName | quote }}
{{- end }}
{{- /*
  Les claims ne sont posés que s'ils sont surchargés : une variable vide vaut une variable
  absente côté serveur, qui reprend alors son défaut.
*/}}
{{- range $var, $value := dict "USERNAME_CLAIM" .Values.oidcAuth.claims.username "EMAIL_CLAIM" .Values.oidcAuth.claims.email "DISPLAY_CLAIM" .Values.oidcAuth.claims.display "GROUPS_CLAIM" .Values.oidcAuth.claims.groups "SUBJECT_CLAIM" .Values.oidcAuth.claims.subject }}
{{- if $value }}
- name: KDT_IDENTITY_AUTH_OIDC_{{ $var }}
  value: {{ $value | quote }}
{{- end }}
{{- end }}
{{- if $.Values.oidcAuth.caCert }}
- name: KDT_IDENTITY_AUTH_OIDC_CA_FILE
  value: /etc/kdt-identity/oidc/ca.crt
{{- end }}
{{- if $.Values.oidcAuth.graph.enabled }}
- name: KDT_IDENTITY_AUTH_OIDC_GRAPH_TENANT_ID
  value: {{ required "oidcAuth.graph.tenantId est obligatoire quand graph.enabled" .Values.oidcAuth.graph.tenantId | quote }}
{{- if .Values.oidcAuth.graph.clientId }}
- name: KDT_IDENTITY_AUTH_OIDC_GRAPH_CLIENT_ID
  value: {{ .Values.oidcAuth.graph.clientId | quote }}
{{- end }}
- name: KDT_IDENTITY_AUTH_OIDC_GRAPH_ENDPOINT
  value: {{ .Values.oidcAuth.graph.endpoint | quote }}
- name: KDT_IDENTITY_AUTH_OIDC_GRAPH_AUTHORITY
  value: {{ .Values.oidcAuth.graph.authority | quote }}
- name: KDT_IDENTITY_AUTH_OIDC_GRAPH_RESYNC
  value: {{ .Values.oidcAuth.graph.resync | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
  Volumes de la CA de l'annuaire. Les deux seuls du chart, et ils n'existent qu'en authMode=ldap.

  Deux volumes et non un : la CA arrive en lecture seule depuis un ConfigMap, mais le magasin
  assemblé — celui de l'image plus celle-ci — doit être écrit au démarrage, et la racine du
  conteneur est en lecture seule.
*/}}
{{- define "kdt-identity.ldapVolumes" -}}
- name: ldap-ca
  configMap:
    name: {{ include "kdt-identity.fullname" . }}-ldap-ca
- name: runtime
  emptyDir:
    medium: Memory
{{- end -}}

{{- define "kdt-identity.ldapVolumeMounts" -}}
- name: ldap-ca
  mountPath: /etc/kdt-identity/ldap
  readOnly: true
- name: runtime
  mountPath: /run/kdt-identity
{{- end -}}

{{/*
  CA du fournisseur d'identité. Un seul volume, là où l'annuaire en demande deux : le client HTTP
  reçoit cette autorité directement, sans magasin à assembler au démarrage.
*/}}
{{- define "kdt-identity.oidcVolumes" -}}
- name: oidc-ca
  configMap:
    name: {{ include "kdt-identity.fullname" . }}-oidc-ca
{{- end -}}

{{- define "kdt-identity.oidcVolumeMounts" -}}
- name: oidc-ca
  mountPath: /etc/kdt-identity/oidc
  readOnly: true
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
{{- if .Values.webUrl -}}
{{- if and (not (hasPrefix "https://" .Values.webUrl)) (not (hasPrefix "http://localhost" .Values.webUrl)) (not (hasPrefix "http://127.0.0.1" .Values.webUrl)) -}}
{{- fail "webUrl doit être en https : un code d'autorisation s'échange contre un droit de session, il n'a pas à voyager en clair" -}}
{{- end -}}
{{- end -}}
{{- if not (has .Values.authMode (list "local" "ldap" "oidc")) -}}
{{- fail (printf "authMode vaut %q : attendu local, ldap ou oidc" .Values.authMode) -}}
{{- end -}}
{{- if eq .Values.authMode "oidc" -}}
{{- /*
  L'émetteur sert à joindre le fournisseur et se compare à ce que portent les jetons. En clair,
  les jetons d'identité de tout le cluster traverseraient le réseau en lecture directe.
*/}}
{{- if not (hasPrefix "https://" .Values.oidcAuth.issuer) -}}
{{- fail (printf "oidcAuth.issuer vaut %q : une racine en https est exigée, c'est par là que passent les jetons d'identité" .Values.oidcAuth.issuer) -}}
{{- end -}}
{{- /*
  Le code d'autorisation revient sur la racine du portail. Les fournisseurs refusent d'ailleurs
  presque tous d'enregistrer une adresse de retour en clair, la boucle locale exceptée.
*/}}
{{- if and (not (hasPrefix "https://" .Values.portalUrl)) (not (hasPrefix "http://localhost" .Values.portalUrl)) (not (hasPrefix "http://127.0.0.1" .Values.portalUrl)) -}}
{{- fail "authMode=oidc exige un portalUrl en https : c'est l'adresse de retour où le code d'autorisation est redirigé" -}}
{{- end -}}
{{- if not .Values.oidcAuth.groupMappings -}}
{{- fail "oidcAuth.groupMappings est vide : les comptes fédérés se connecteraient sans obtenir le moindre groupe, donc le moindre droit" -}}
{{- end -}}
{{- range .Values.oidcAuth.groupMappings -}}
{{- if not .claim -}}
{{- fail "chaque entrée de oidcAuth.groupMappings doit porter un claim" -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$" (.group | default "")) -}}
{{- fail (printf "oidcAuth.groupMappings : le groupe %q n'est pas un nom de ressource valide (minuscules, chiffres, - et ., 60 caractères au plus)" (.group | default "")) -}}
{{- end -}}
{{- if gt (len .group) 60 -}}
{{- fail (printf "oidcAuth.groupMappings : le groupe %q dépasse 60 caractères" .group) -}}
{{- end -}}
{{- end -}}
{{- if .Values.oidcAuth.graph.enabled -}}
{{- /*
  La relecture désigne les comptes par leur identifiant d'objet dans le tenant. Le `sub` d'un
  jeton ne convient pas : il est propre à l'application qui l'a reçu, et Graph ne le connaît pas.
  Sans ce garde-fou, le premier tour de relecture ne retrouverait pas un seul compte.
*/}}
{{- if not (eq (.Values.oidcAuth.claims.subject | default "") "oid") -}}
{{- fail "oidcAuth.graph.enabled exige oidcAuth.claims.subject=oid : la relecture désigne les comptes par leur identifiant d'objet, que seul ce claim porte" -}}
{{- end -}}
{{- if not .Values.oidcAuth.existingSecret -}}
{{- fail "oidcAuth.graph.enabled exige oidcAuth.existingSecret : le secret d'application y est lu sous KDT_IDENTITY_AUTH_OIDC_GRAPH_CLIENT_SECRET" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if eq .Values.authMode "ldap" -}}
{{- if not (has .Values.ldap.profile (list "activedirectory" "freeipa")) -}}
{{- fail (printf "ldap.profile vaut %q : attendu activedirectory ou freeipa" .Values.ldap.profile) -}}
{{- end -}}
{{- /*
  Un bind simple présente le mot de passe en clair dans la requête : c'est le protocole. Sans
  TLS, tout ce qui se trouve entre le portail et l'annuaire lit chaque mot de passe d'entreprise
  qui passe. Refusé au rendu, et pas seulement au démarrage : mieux vaut que `helm upgrade`
  échoue que de devoir lire les journaux d'un pod en CrashLoop.
*/}}
{{- if and (not (hasPrefix "ldaps://" .Values.ldap.url)) (not .Values.ldap.startTls) -}}
{{- fail (printf "ldap.url vaut %q sans startTls : un bind présente le mot de passe en clair, exigez ldaps:// ou activez StartTLS" .Values.ldap.url) -}}
{{- end -}}
{{- if and (hasPrefix "ldaps://" .Values.ldap.url) .Values.ldap.startTls -}}
{{- fail "ldap.startTls sur une racine ldaps:// : StartTLS négocie le chiffrement sur une connexion en clair, il n'a pas de sens sur une connexion déjà chiffrée" -}}
{{- end -}}
{{- if not .Values.ldap.groupMappings -}}
{{- fail "ldap.groupMappings est vide : les comptes fédérés se connecteraient sans obtenir le moindre groupe, donc le moindre droit" -}}
{{- end -}}
{{- /*
  Le nom de groupe doit satisfaire le même langage que la ValidatingAdmissionPolicy, sinon le
  KdtGroup est refusé par l'apiserver — à la première connexion, du côté de la personne qui se
  connecte plutôt que de celle qui a écrit la table.
*/}}
{{- range .Values.ldap.groupMappings -}}
{{- if not .dn -}}
{{- fail "chaque entrée de ldap.groupMappings doit porter un dn" -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$" (.group | default "")) -}}
{{- fail (printf "ldap.groupMappings : le groupe %q n'est pas un nom de ressource valide (minuscules, chiffres, - et ., 60 caractères au plus)" (.group | default "")) -}}
{{- end -}}
{{- if gt (len .group) 60 -}}
{{- fail (printf "ldap.groupMappings : le groupe %q dépasse 60 caractères" .group) -}}
{{- end -}}
{{- end -}}
{{- /*
  FreeIPA émet toujours depuis sa propre CA, Active Directory presque toujours. Sans CA
  déclarée, le magasin de l'image est le seul en vigueur et le handshake échouera — ce qui se
  lit comme une panne réseau plutôt que comme une configuration incomplète.
*/}}
{{- if and (not .Values.ldap.caCert) (not (eq .Values.ldap.skipCaCheck true)) -}}
{{- fail "ldap.caCert est vide : un annuaire d'entreprise émet presque toujours depuis sa propre autorité, et le magasin de l'image ne la contient pas. Renseignez-la, ou posez ldap.skipCaCheck=true si votre annuaire présente un certificat issu d'une autorité publique" -}}
{{- end -}}
{{- end -}}
{{- end -}}
