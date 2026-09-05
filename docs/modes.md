# Les deux modes

kdt-identity délivre les accès de deux façons. Le mode se choisit au déploiement,
`credentialMode` dans les valeurs du chart, et vaut pour tout le cluster.

| | `certificate` (défaut) | `oidc` |
|---|---|---|
| Ce qui est délivré | certificat X.509 signé par la CA du cluster | jeton JWT signé par kdt-identity |
| Durée | 10 min | 5 min |
| Configuration de l'apiserver | aucune | émetteur, audience, CA |
| Révocation | ≤ 10 min | ≤ 5 min |
| Saisie mot de passe + code | tous les 7 jours | tous les 7 jours |
| Identité produite | `kdt:alice`, groupes `kdt:*` | identique |
| Kubeconfig téléchargeable | oui, non révocable | non |
| Audit d'une session | empreinte du certificat | `jti` unique par jeton |

La révocation, le renouvellement silencieux et l'identité produite sont **identiques dans les
deux modes**. Ce qui diffère : ce que le cluster doit accepter, et ce qu'on peut tracer.

## Choisir

Prenez `certificate` sauf si l'une de ces trois conditions s'applique :

1. **Le cluster ne signe pas de certificat client.** C'est le cas d'EKS. Voir la table de
   compatibilité ci-dessous.
2. **Vous avez besoin de tracer les sessions individuellement.** Un certificat ne laisse dans
   l'audit que son empreinte, identique tant qu'il n'est pas renouvelé ; un jeton porte un
   `jti` unique.
3. **Vous voulez un émetteur validable par d'autres composants** que l'apiserver.

## Où le mode certificat fonctionne

Le signeur `kubernetes.io/kube-apiserver-client` est servi par le contrôleur `csrsigning` du
kube-controller-manager. Sur un control plane managé, ce composant n'est pas le vôtre, et rien
n'oblige le fournisseur à l'exposer.

| Plateforme | Fonctionne | Constaté comment |
|---|---|---|
| k3s | oui | en service |
| AKS | oui | vérifié sur 1.34 : demande signée par la CA du cluster, identité reconnue |
| kubeadm, RKE2, auto-gérés | attendu | `csrsigning` en configuration standard |
| EKS | **non** | AWS ne sert pas ce signeur et refuse l'usage `client auth` ([containers-roadmap#1856](https://github.com/aws/containers-roadmap/issues/1856)) |
| GKE, OpenShift | non vérifié | à confirmer avant de s'engager |

Tester en une minute sur un cluster donné :

```sh
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout /tmp/probe.key -out /tmp/probe.csr -subj "/CN=probe-signeur"

kubectl create -f - <<YAML
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata: {name: probe-signeur}
spec:
  request: $(base64 -w0 < /tmp/probe.csr)
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 600
  usages: ["client auth", "digital signature"]
YAML

kubectl certificate approve probe-signeur
kubectl get csr probe-signeur       # CONDITION doit passer à Approved,Issued
kubectl delete csr probe-signeur
```

`Approved,Issued` en quelques secondes répond oui. Une demande qui reste `Approved` sans jamais
être signée répond non. Le sujet n'a aucune importance : tant qu'aucun binding ne le vise, le
certificat obtenu n'accorde rien.

## Où le mode OIDC fonctionne

Il faut pouvoir configurer l'apiserver.

| Plateforme | Fonctionne |
|---|---|
| kubeadm, k3s, RKE2, auto-gérés | oui |
| EKS | oui, par `associate-identity-provider-config` |
| GKE | via Identity Service for GKE |
| OpenShift | par la ressource `Authentication` du cluster |
| AKS | **non** pour un émetteur tiers — Entra ID uniquement |

La marche à suivre est dans [oidc.md](oidc.md).

## Ce que le mode ne change pas

- **L'identité.** `kdt:alice` et les groupes `kdt:*` des deux côtés. Les `RoleBinding` et
  `ClusterRoleBinding` écrits pour un mode fonctionnent avec l'autre, sans modification.
- **Le kubeconfig du poste.** Le même fichier vaut pour les deux : le plugin découvre le mode à
  l'ouverture de session et s'y conforme.
- **La révocation.** `kdt-identity-server revoke` et `spec.disabled` agissent de la même façon.
- **Le préfixe.** Posé à l'émission, jamais par la configuration de l'apiserver.

## Changer de mode

Le mode se change rarement, mais il se change sans casse.

**De `certificate` vers `oidc`** :

1. Configurer l'apiserver d'abord ([oidc.md](oidc.md)). L'authentification Kubernetes est une
   chaîne : un émetteur OIDC déclaré ne perturbe pas la validation des certificats.
2. `helm upgrade --set credentialMode=oidc`.
3. Les certificats en circulation restent valides jusqu'à expiration — dix minutes. Les postes
   qui utilisent le plugin basculent au renouvellement suivant, sans rien faire.

Les utilisateurs qui téléchargeaient un kubeconfig depuis le portail devront installer le
plugin : le téléchargement n'existe pas en mode OIDC.

**De `oidc` vers `certificate`** :

1. `helm upgrade --set credentialMode=certificate`.
2. Retirer la configuration de l'apiserver, une fois que plus aucun jeton n'est en circulation
   (cinq minutes).

Dans cet ordre, personne n'est bloqué : le portail délivre à nouveau des certificats avant que
l'apiserver cesse de reconnaître les jetons.

## Le kubeconfig téléchargeable

En mode certificat, le portail propose un kubeconfig autoportant, pour les postes où l'on ne
veut rien installer. Ce fichier :

- contient une clé privée engendrée par le serveur, qui a donc traversé le réseau ;
- vit `portal.downloadCertTtl` — 8 h par défaut — sans se renouveler ;
- **n'est pas révocable** : ni `revoke` ni `spec.disabled` ne l'atteignent.

Quand la révocation doit être sans exception, fermer ce chemin :

```yaml
portal:
  kubeconfigDownload: false
```

La page « Mon accès » propose alors uniquement le plugin.
