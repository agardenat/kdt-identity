# Les modes

kdt-identity a **deux modes indépendants**, et il faut les distinguer avant de lire la suite :

| Axe | Valeur | Répond à | Valeurs |
|---|---|---|---|
| Mode de délivrance | `credentialMode` | ce que le portail **remet** | `proxy`, `certificate`, `oidc` |
| Mode d'authentification | `authMode` | qui il **reconnaît** | `local`, `ldap`, `oidc` |

Ils se combinent librement : les neuf couples sont valides. Un annuaire d'entreprise peut aussi
bien aboutir à un certificat qu'à un jeton, et changer l'un n'oblige jamais à toucher l'autre.

Ce document traite du mode de délivrance. Pour le mode d'authentification, voir
[ldap.md](ldap.md) et [fournisseur-oidc.md](fournisseur-oidc.md) — en `local`, le défaut, les
comptes vivent dans le cluster et il n'y a rien à configurer.

⚠️ `oidc` désigne deux choses différentes selon l'axe. En délivrance, le portail **émet** des
jetons que l'apiserver vérifie. En authentification, il **consomme** ceux d'un fournisseur. Les
deux sont indépendants, et un déploiement peut n'en avoir aucun comme les avoir tous les deux.

## Les trois modes de délivrance

Le mode se choisit au déploiement, `credentialMode` dans les valeurs du chart, et vaut pour tout
le cluster.

| | `proxy` (défaut) | `certificate` | `oidc` |
|---|---|---|---|
| Ce qui est délivré | jeton opaque, vérifié par kdt-identity | certificat X.509 signé par la CA du cluster | jeton JWT signé par kdt-identity |
| Durée | 7 j | 10 min | 5 min |
| Configuration de l'apiserver | aucune | aucune | émetteur, audience, CA |
| Révocation | ≤ 30 s | ≤ 10 min | ≤ 5 min |
| Saisie mot de passe + code | tous les 7 jours | tous les 7 jours | tous les 7 jours |
| Identité produite | `kdt:alice`, groupes `kdt:*` | identique | identique |
| Kubeconfig téléchargeable | oui, **révocable** | oui, non révocable | non |
| Plugin nécessaire | non | non, mais recommandé | oui |
| Ce qu'une application autorisée obtient | un accès par le proxy, coupé par `revoke` | un certificat de 10 min | un jeton de 5 min |
| kdt-identity sur le chemin | oui | non | non |
| Audit d'une session | identité impersonnée | empreinte du certificat | `jti` unique par jeton |

L'identité produite est **identique dans les trois modes**. Ce qui diffère : ce que le cluster
doit accepter, ce qu'on peut couper, et ce dont dépend l'accès.

## Choisir

**`proxy`** est le défaut, et convient partout. C'est le seul mode où un kubeconfig téléchargé
se révoque, et le seul qui n'exige rien du poste ni du control plane. Sa contrepartie est unique
et il faut l'accepter : kdt-identity est sur le chemin des requêtes, donc son indisponibilité
coupe ces accès. Voir [proxy.md](proxy.md).

**`certificate`** quand les clients doivent parler directement à l'apiserver — parce que le
proxy serait un point de panne de trop, ou parce que le débit compte. Le prix est la révocation :
un certificat émis vaut jusqu'à son expiration.

**`oidc`** quand l'une de ces trois conditions s'applique :

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
- **La provenance des comptes.** `authMode` est un axe séparé : passer de `certificate` à `oidc`
  ne change rien à la façon dont les personnes s'authentifient, et réciproquement.

## Où le mode proxy fonctionne

Partout. Il ne demande rien à l'apiserver — ni drapeau, ni signeur, ni émetteur déclaré — et
n'utilise que l'impersonation, qui fait partie de l'API depuis toujours. C'est la seule réponse
pour AKS, où ni le webhook d'authentification ni un émetteur OIDC tiers ne sont configurables.

## Changer de mode

Le mode se change rarement, mais il se change sans casse. Vers `proxy` et depuis `proxy`, voir
[proxy.md](proxy.md).

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

Le portail propose un kubeconfig à télécharger, pour les postes où l'on ne veut rien installer.
Ce qu'il contient, et ce qu'il vaut, dépend du mode.

**En mode `proxy`** : un jeton, et l'adresse du proxy. Aucun secret durable — le jeton ne vaut
rien sans la session qui le porte dans le cluster. `revoke` et `spec.disabled` l'atteignent comme
le reste. `portal.kubeconfigDownload` est sans effet : il n'y a rien à fermer.

**En mode `certificate`** : un fichier autoportant. Il contient une clé privée engendrée par le
serveur, qui a donc traversé le réseau ; il vit `portal.downloadCertTtl` — 8 h par défaut — sans
se renouveler ; et il **n'est pas révocable**, ni par `revoke` ni par `spec.disabled`.

Quand la révocation doit être sans exception, deux voies : passer en mode `proxy`, ou fermer ce
chemin.

```yaml
portal:
  kubeconfigDownload: false
```

La page « Mon accès » propose alors uniquement le plugin.

**En mode `oidc`** : pas de téléchargement. Un jeton signé vit cinq minutes, ce qui ne tient pas
dans un fichier.
