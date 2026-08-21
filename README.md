# kdt-identity — utilisateurs et groupes locaux pour Kubernetes

Kubernetes n'a volontairement aucun objet `User` ni `Group` : l'authentification est déléguée à
un composant externe, et un groupe n'est qu'une chaîne portée par le credential. Sur un cluster
vanilla, il n'existe donc aucun moyen de dire « crée l'utilisateur X, mets-le dans le groupe Y,
envoie-lui son accès ».

kdt-identity comble ce trou : des utilisateurs et des groupes matérialisés en CRDs, un
contrôleur qui en tient l'appartenance à jour, et l'émission à la demande d'un kubeconfig que
l'apiserver reconnaît — sans toucher à la configuration du control plane.

Compagnon de [kdt](https://github.com/agardenat/kdt).

> **État : complet et déployable.** Créer un compte, l'inviter, l'activer depuis le portail
> avec mot de passe et TOTP, puis obtenir un accès — par téléchargement d'un kubeconfig ou par
> le plugin `exec`. Chart Helm et image fournis.

## Ce que ça fait

```console
$ kubectl apply -f - <<'EOF'
apiVersion: identity.kdt.sh/v1alpha1
kind: KdtUser
metadata: {name: alice}
spec: {email: alice@example.com}
---
apiVersion: identity.kdt.sh/v1alpha1
kind: KdtGroup
metadata: {name: lecteurs}
spec: {members: ["alice"]}
EOF

$ kubectl get kdtuser,kdtgroup
NAME                            EMAIL               PHASE     GROUPES
kdtuser.identity.kdt.sh/alice   alice@example.com   Pending   ["lecteurs"]

NAME                                MEMBRES   SUJET
kdtgroup.identity.kdt.sh/lecteurs   1         kdt:lecteurs

$ kdt-identity-server issue alice --ttl 8h > alice.kubeconfig

$ kubectl --kubeconfig=alice.kubeconfig auth whoami
ATTRIBUTE   VALUE
Username    kdt:alice
Groups      [kdt:lecteurs system:authenticated]
```

Un groupe n'accorde rien par lui-même. Pour qu'il serve à quelque chose, il faut un binding qui
le vise — c'est un geste délibéré, à committer dans votre dépôt GitOps :

```yaml
subjects:
- kind: Group
  name: kdt:lecteurs        # le sujet est publié dans KdtGroup.status.subject
  apiGroup: rbac.authorization.k8s.io
```

## Inviter quelqu'un

L'invitation est une action d'administrateur, pas un envoi automatique : aucun SMTP n'est requis
pour faire tourner kdt-identity.

```console
$ kdt-identity-server invite alice
Invitation pour alice <alice@example.com>
  expire le      24/08/2026 à 12:17 UTC
  lien           https://identity.example.com/activate?u=alice&t=rcMTOCKBV_69KSvnpRVKfyRJx…
  code           FXJK-MNUQ

Transmettez le lien et le code par deux canaux différents :
le code de vive voix, pour qu'intercepter le lien ne suffise pas.
```

Activer un compte demande **les deux**. C'est délibéré : le lien voyage presque toujours par
courriel, c'est-à-dire par le canal le moins maîtrisé de la chaîne, et l'intercepter ne doit pas
suffire. Le code est court, prononçable et dépourvu de caractères confondables (`O`/`0`,
`I`/`1`/`L`) pour être dicté au téléphone sans erreur.

C'est un mot de passe à usage unique au sens strict : il est consommé au moment où le mot de
passe est posé, dans la même écriture, donc aucun chemin ne peut le laisser rejouable.

`--send-mail` envoie le lien par courriel si un SMTP est configuré. Le code reste affiché dans
le terminal : l'envoyer par le même canal que le lien annulerait tout l'intérêt de la
séparation.

Ni le lien ni le code ne sont journalisés, ni écrits dans le statut du `KdtUser` — un statut est
lisible par quiconque peut lister les utilisateurs. Ils n'apparaissent que dans le terminal de
l'administrateur qui les demande, une seule fois.

Relancer `invite` sur un compte existant réémet une invitation et efface le mot de passe
précédent : c'est aussi le chemin de réinitialisation.

### Pourquoi pas un code TOTP par SMS

TOTP ne se bootstrape pas par un code : les codes sont *dérivés* d'un secret partagé. Il
faudrait donc transmettre le secret lui-même — or il est permanent, là où le SMS est en clair,
conservé par l'opérateur et vulnérable au SIM-swap. Une passerelle SMS serait par ailleurs une
dépendance au moins aussi lourde que le SMTP qu'on cherche à éviter.

Le TOTP s'enrôle par QR code dans le navigateur au moment de l'activation, ce qui est la seule
façon correcte. Le code d'activation, lui, joue le rôle de second canal.

## Le portail

```sh
kdt-identity-server serve
```

Trois pages, rendues côté serveur, sans script ni ressource externe — le portail manipule des
credentials, il doit rester lisible sur un réseau isolé et incapable d'exfiltrer ce qu'il
affiche.

| Page | Ce qu'elle demande |
|---|---|
| `/activate` | le code d'activation, un mot de passe, et un code TOTP prouvant que le QR a bien été scanné |
| `/login` | mot de passe et code TOTP |
| `/` | rien — affiche l'identité effective et produit le kubeconfig |

Aucune réponse ne distingue « ce compte n'existe pas » de « le mot de passe est faux », ni « ce
lien est faux » de « ce lien a expiré ». Un portail qui répond précisément est un annuaire : il
laisse énumérer les comptes du cluster depuis l'extérieur. Les journaux, eux, gardent la raison
exacte — c'est là qu'elle sert.

Un code TOTP n'est accepté qu'une fois, comme l'exige la [RFC 6238
§5.2](https://datatracker.ietf.org/doc/html/rfc6238#section-5.2). Les échecs répétés allongent
progressivement l'attente, sans jamais verrouiller définitivement : un verrou permanent
déclenché à distance serait un déni de service offert à qui connaît un nom de compte.

Variables d'environnement du portail :

| Variable | Rôle |
|---|---|
| `KDT_IDENTITY_PORTAL_URL` | racine publique, pour construire les liens d'activation |
| `KDT_IDENTITY_CLUSTER_NAME` | nom affiché aux utilisateurs |
| `KDT_IDENTITY_APISERVER_URL` | adresse publique de l'apiserver ; à défaut, le kubeconfig courant |
| `KDT_IDENTITY_SESSION_KEY` | clé de signature, 32 octets en base64 |
| `KDT_IDENTITY_LISTEN` | adresse d'écoute, `0.0.0.0:8080` par défaut |

Sans `KDT_IDENTITY_SESSION_KEY`, une clé est tirée au démarrage : les sessions ne survivent
alors ni à un redémarrage ni à une seconde instance. Le serveur le signale au lancement.

## Le plugin `exec`

Le téléchargement d'un kubeconfig depuis le portail est pratique, mais il fait voyager une clé
privée sur le réseau et il faut recommencer à chaque expiration. Le plugin fait mieux :

```sh
kdt-identity kubeconfig --portal https://identity.example.com --user alice \
    --cluster production --server https://k8s.example.com:6443 --ca-file ca.crt > ~/.kube/config
```

Le kubeconfig produit ne contient **aucun secret** : il déclare simplement `kubectl` doit
appeler `kdt-identity` quand il a besoin d'un credential.

À la première commande, le plugin demande le mot de passe et un code TOTP, engendre une paire
de clés **sur le poste**, en envoie seulement la demande de signature, et met le certificat en
cache jusqu'à son expiration. Les commandes suivantes ne demandent rien.

La clé privée ne traverse jamais le réseau — c'est ce que le téléchargement navigateur ne peut
pas offrir. Le cache est écrit en 0600 dans `~/.kube/cache/kdt-identity/`.

`kdt-identity logout` efface le cache et force une nouvelle authentification.

### Pourquoi deux appels HTTP

Le sujet d'un certificat X.509 — nom d'utilisateur et groupes — est fixé dans la demande de
signature, elle-même signée par la clé du client. Le portail ne peut donc pas compléter un
sujet incomplet : il ne peut que l'accepter ou le refuser. Le plugin doit connaître ses groupes
**avant** de signer, et un code TOTP ne servant qu'une fois, il ne peut pas s'authentifier deux
fois pour les apprendre. Le premier appel authentifie et rend l'identité effective avec un
jeton valable une minute ; le second fait signer.

### Faire vivre les groupes

Ajouter ou retirer quelqu'un d'un groupe fonctionne normalement : le portail comme le plugin
relisent les groupes depuis le cluster **au moment d'émettre**, jamais depuis un cache.

```console
$ kubectl patch kdtgroup ops --type=merge -p '{"spec":{"members":[]}}'

$ kubectl auth whoami                    # certificat déjà émis : inchangé
Groups   [kdt:ops kdt:lecteurs system:authenticated]

$ kdt-identity logout --portal … --user alice && kubectl auth whoami
Groups   [kdt:lecteurs system:authenticated]
```

Le certificat déjà émis garde ses groupes jusqu'à expiration — c'est la contrepartie du modèle
par certificats, détaillée dans [Révocation](#révocation). Un changement d'appartenance prend
donc effet au renouvellement suivant, soit au plus tard huit heures.

## Comment ça marche

Les identités sont des certificats clients X.509 obtenus via l'API
`CertificateSigningRequest` : `CN=kdt:<utilisateur>`, un `O=kdt:<groupe>` par groupe, signés par
la CA du cluster.

Ce choix a une conséquence heureuse et une conséquence gênante, toutes deux structurantes :

- **Ça marche partout**, y compris sur AKS, EKS, GKE et OpenShift : aucun drapeau de
  l'apiserver à changer, aucune `AuthenticationConfiguration` à écrire, aucun IdP existant à
  déplacer.
- **Il n'y a pas de révocation.** Kubernetes ne consulte aucune CRL : un certificat émis reste
  valide jusqu'à son expiration. Voir [Révocation](#révocation).

### Coexistence avec un IdP déjà en place

L'authentification Kubernetes est une chaîne d'authentificateurs essayés jusqu'à ce que l'un
accepte. kdt-identity **ne modifie rien de l'existant** : ni drapeaux de l'apiserver, ni
configuration d'authentification, ni webhook. Il ajoute des CRDs dans son propre groupe d'API,
un contrôleur, et des CSR éphémères supprimées après émission.

Rancher, Entra ID, Keycloak, authentik continuent de fonctionner à l'identique. Deux précautions
sont prises pour que la cohabitation reste lisible :

| Risque | Ce qui est fait |
|---|---|
| Rancher expose déjà un kind `User` | Les kinds sont `KdtUser` / `KdtGroup`, shortNames `kdtuser` / `kdtgroup`. Jamais `user` ni `group`. |
| Un sujet RBAC n'est qu'une chaîne : `alice` émis ici hériterait d'un binding Rancher visant `alice` | Toute identité émise porte le préfixe `kdt:`, non désactivable. Aucune collision possible avec les `u-*` de Rancher, les UPN Entra ou `system:*`. |

Le kubeconfig produit ne décrit **que** le cluster et l'identité : ni `proxy-url`, ni bastion.
Atteindre l'apiserver est une propriété du poste, pas du cluster ; qui passe par un tunnel le
sait et l'ajoute de son côté.

## Sécurité

**kdt-identity est un composant équivalent cluster-admin.** Approuver une CSR
`kubernetes.io/kube-apiserver-client` revient à choisir une identité auprès de l'apiserver : qui
peut le faire peut forger `O=system:masters`. Déployez-le comme tel — namespace dédié,
NetworkPolicy en deny-by-default, RBAC restreint au seul signeur utilisé.

Trois barrières indépendantes empêchent une identité de sortir du cadre :

1. **À l'admission** — une `ValidatingAdmissionPolicy` en CEL refuse les noms réservés, hors jeu
   de caractères ou trop longs, y compris dans la liste des membres d'un groupe.
2. **À la construction** — `Subject` ne peut être obtenu que par une fonction validante, et
   ajoute lui-même le préfixe.
3. **Avant approbation** — le sujet de la CSR est relu et doit correspondre **exactement** à
   l'identité attendue, groupes compris. Une demande fournie par un client n'est jamais crue sur
   parole : c'est ce qui empêche un utilisateur authentifié de réclamer une autre identité.

La politique d'admission et la vérification à l'émission se recouvrent volontairement. Une CRD
peut être créée avant l'installation de la politique, ou la politique être retirée : aucune des
deux ne doit dépendre de l'autre.

### Révocation

Un certificat émis vaut jusqu'à son expiration, sans exception. Trois moyens d'agir :

1. **Une durée courte** (8 à 24 h). Le plugin `exec` la rendra indolore une fois écrit.
2. **`spec.disabled: true`** bloque immédiatement toute nouvelle émission.
3. **Retirer le binding du groupe** coupe l'accès de tous ses membres sans attendre
   l'expiration. C'est le levier le plus rapide, et la raison pour laquelle les droits doivent
   vivre sur les groupes plutôt que sur les individus.

Une révocation individuelle instantanée demanderait le mode OIDC ou un proxy d'impersonation.

## Installation

```sh
helm install kdt-identity deploy/helm/kdt-identity \
    --namespace kdt-identity --create-namespace \
    --set clusterName=production \
    --set portalUrl=https://identity.example.com \
    --set apiserverUrl=https://k8s.example.com:6443 \
    --set ingress.enabled=true \
    --set ingress.host=identity.example.com
```

`apiserverUrl` n'est pas `https://kubernetes.default.svc` : cette adresse finit dans le
kubeconfig d'un utilisateur, qui n'est pas dans le cluster.

Le chart refuse de s'installer avec un ingress sans TLS. Ce n'est pas du zèle : le cookie de
session porte l'attribut `Secure`, donc un navigateur ne le renverrait pas sur du HTTP — le
portail serait inutilisable, et silencieusement.

Sans ingress, pour essayer :

```sh
kubectl -n kdt-identity port-forward svc/kdt-identity-kdt-identity 8080:80
```

### Ce que le chart installe

| Ressource | Pourquoi |
|---|---|
| `ClusterRole` | lecture des CRDs, écriture de leur statut, cycle de vie des CSR |
| `signers` avec `resourceNames` | l'autorisation d'approuver est restreinte au seul `kubernetes.io/kube-apiserver-client` |
| `Role` namespacé | les Secrets de credentials, **sans le verbe `list`** : le contrôleur y accède toujours par leur nom, et l'absence de ce verbe empêche d'énumérer les comptes |
| `NetworkPolicy` | apiserver, DNS et SMTP uniquement — le reste est refusé |
| `ValidatingAdmissionPolicy` | les règles de nommage, rejouées côté apiserver |

Les CRDs et la politique d'admission du chart sont **générées depuis le code**, et un test
échoue si le YAML committé s'en écarte. Sans ce verrou, le schéma servi par le contrôleur et le
schéma installé dans le cluster finiraient par diverger en silence.

Sans Helm, pour un essai rapide :

```sh
kdt-identity-server crd | kubectl apply -f -
kdt-identity-server controller
```

## Développement

```sh
cargo test --workspace
```

Les tests de bout en bout créent de vraies CSR et s'authentifient avec le certificat obtenu.
Ils sont ignorés par défaut :

```sh
KUBECONFIG=~/.kube/config cargo test -p kdt-identity-server --test e2e_issuance -- --ignored
```

Ils ne créent aucun binding RBAC : l'identité de test doit pouvoir s'authentifier sans obtenir
le moindre droit, et c'est précisément ce qu'ils vérifient.

## Licence

Apache-2.0.
