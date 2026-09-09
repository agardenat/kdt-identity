# kdt-identity — utilisateurs et groupes locaux pour Kubernetes

Des utilisateurs et des groupes en CRDs, un contrôleur qui tient leur appartenance à jour, un
portail d'activation, un plugin d'authentification pour `kubectl`, et l'émission à la demande d'un
kubeconfig que l'apiserver reconnaît — sans modifier la configuration du control plane.

Compagnon de [kdt](https://github.com/agardenat/kdt). 🗒️ [Changelog](CHANGELOG.md)

Deux modes de délivrance, certificat ou OIDC, éprouvés contre un apiserver réel. Les comptes
peuvent venir des CRDs, d'un annuaire Active Directory / FreeIPA (`authMode: ldap`) ou d'un
fournisseur OpenID Connect — Entra ID, Keycloak, Okta (`authMode: oidc`) : dans les deux cas le
`KdtUser` est créé à la première connexion réussie et l'appartenance reportée depuis les groupes
de la source. Chart Helm et image fournis.

| Guide | Pour qui |
| --- | --- |
| [Les modes](docs/modes.md) | choisir, vérifier la compatibilité de son cluster, basculer |
| [Le plugin](docs/plugin.md) | postes de travail : installation, cycle de vie, dépannage |
| [Administration](docs/administration.md) | comptes, groupes, révocation, droits RBAC |
| [Mode OIDC](docs/oidc.md) | configurer l'apiserver |
| [Mode LDAP](docs/ldap.md) | fédérer les comptes sur un annuaire Active Directory ou FreeIPA |
| [Mode fournisseur](docs/fournisseur-oidc.md) | fédérer les comptes sur Entra ID, Keycloak ou Okta |

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

$ kdt-identity-server issue alice > alice.kubeconfig

$ kubectl --kubeconfig=alice.kubeconfig auth whoami
ATTRIBUTE   VALUE
Username    kdt:alice
Groups      [kdt:lecteurs system:authenticated]
```

Un groupe n'accorde aucun droit par lui-même : il faut un binding RBAC qui vise son sujet, publié
dans `KdtGroup.status.subject`.

```yaml
subjects:
- kind: Group
  name: kdt:lecteurs
  apiGroup: rbac.authorization.k8s.io
```

### Faire vivre les groupes

Le portail comme le plugin relisent les groupes depuis le cluster au moment d'émettre, jamais
depuis un cache. Un certificat déjà émis garde les siens jusqu'à expiration — dix minutes au plus
—, `logout` force le passage immédiatement.

```console
$ kubectl patch kdtgroup ops --type=merge -p '{"spec":{"members":[]}}'

$ kubectl auth whoami                    # certificat déjà émis : inchangé
Groups   [kdt:ops kdt:lecteurs system:authenticated]

$ kdt-identity logout --portal … --user alice && kubectl auth whoami
Groups   [kdt:lecteurs system:authenticated]
```

Créer, inviter, désactiver, gérer l'appartenance et passer des groupes aux droits RBAC :
[guide d'administration](docs/administration.md).

## Inviter quelqu'un

L'invitation est une commande d'administrateur ; aucun SMTP n'est requis pour faire tourner
kdt-identity.

```console
$ kdt-identity-server invite alice
Invitation pour alice <alice@example.com>
  expire le      24/08/2026 à 12:17 UTC
  lien           https://identity.example.com/activate?u=alice&t=rcMTOCKBV_69KSvnpRVKfyRJx…
  code           FXJK-MNUQ

Transmettez le lien et le code par deux canaux différents :
le code de vive voix, pour qu'intercepter le lien ne suffise pas.
```

Activer un compte demande les deux. Le code est court, prononçable et sans caractères confondables
(`O`/`0`, `I`/`1`/`L`) ; il est consommé au moment où le mot de passe est posé, dans la même
écriture. Le TOTP s'enrôle par QR code dans le navigateur pendant l'activation.

`--send-mail` envoie le lien par courriel si un SMTP est configuré ; le code reste affiché dans le
terminal. Ni le lien ni le code ne sont journalisés ni écrits dans le statut du `KdtUser`.

Relancer `invite` sur un compte existant réémet une invitation et efface le mot de passe précédent
— c'est aussi le chemin de réinitialisation.

## Le portail

```sh
kdt-identity-server serve
```

Trois pages rendues côté serveur, sans script ni ressource externe :

| Page | Ce qu'elle demande |
|---|---|
| `/activate` | le code d'activation, un mot de passe, et un code TOTP prouvant que le QR a bien été scanné |
| `/login` | mot de passe et code TOTP |
| `/` | rien — affiche l'identité effective et produit le kubeconfig |

Aucune réponse ne distingue « ce compte n'existe pas » de « le mot de passe est faux », ni « ce
lien est faux » de « ce lien a expiré » ; les journaux gardent la raison exacte. Un code TOTP n'est
accepté qu'une fois ([RFC 6238 §5.2](https://datatracker.ietf.org/doc/html/rfc6238#section-5.2)).
Les échecs répétés allongent progressivement l'attente, sans verrouillage définitif.

| Variable | Rôle |
|---|---|
| `KDT_IDENTITY_PORTAL_URL` | racine publique, pour construire les liens d'activation |
| `KDT_IDENTITY_CLUSTER_NAME` | nom affiché aux utilisateurs |
| `KDT_IDENTITY_APISERVER_URL` | adresse publique de l'apiserver ; à défaut, le kubeconfig courant |
| `KDT_IDENTITY_SESSION_KEY` | clé de signature, 32 octets en base64 |
| `KDT_IDENTITY_LISTEN` | adresse d'écoute, `0.0.0.0:8080` par défaut |

Sans `KDT_IDENTITY_SESSION_KEY`, une clé est tirée au démarrage : les sessions ne survivent alors
ni à un redémarrage ni à une seconde instance. Le serveur le signale au lancement.

## Le plugin `kdt-identity`

Sur un poste de travail, `kubectl` appelle le plugin quand il a besoin d'un accès ; il l'obtient,
le met en cache et le renouvelle tout seul.

```sh
kdt-identity kubeconfig --portal https://identity.example.com --user alice \
    --cluster production --server https://k8s.example.com:6443 --ca-file ca.crt > ~/.kube/config
```

Le kubeconfig produit ne contient aucun secret : il dit seulement à `kubectl` d'appeler
`kdt-identity`.

```console
$ kubectl get pods
Authentification kdt-identity — alice sur https://identity.example.com
Mot de passe :
Code à 6 chiffres : 123456
NAME   READY   STATUS
…

$ kubectl get pods        # plus aucune saisie, pendant sept jours
```

Deux durées : le credential vaut dix minutes et se renouvelle en silence, le droit de session vaut
sept jours et borne l'intervalle entre deux saisies. La clé privée est engendrée sur le poste et
n'en sort jamais ; seule la demande de signature part sur le réseau.

Installation, cycle de vie, déconnexion, cache et dépannage : [guide du plugin](docs/plugin.md).

## Autoriser une application

Une application web obtient un accès par OAuth 2.0 réduit à ce qui est nécessaire : elle envoie le
navigateur sur `/authorize`, le portail reconnaît la session ouverte, montre sous quelle identité
l'accès sera utilisé et attend un accord, puis redirige vers l'application avec un code valable une
minute, échangé contre un droit de session avec PKCE (`S256`).

```yaml
# helm-values.yaml
webUrl: https://kdt.example.com
```

L'adresse de retour en découle — `https://kdt.example.com/auth/callback` — et c'est la seule que le
portail accepte. Il n'y a pas de registre d'applications ni d'enregistrement à chaud. Laissée vide,
`webUrl` ne monte pas les points d'accès et la page du compte n'en dit rien.

Ce que l'application obtient est un droit de session ordinaire : il compte dans les sessions du
compte, `revoke` le ferme, `spec.disabled` le coupe.

> **Servez l'application sous le même domaine enregistrable que le portail.** Le cookie de session
> est `SameSite=Strict` : `kdt.example.com` et `identity.example.com` le partagent, un domaine
> étranger ne le recevra pas et chaque autorisation repassera par une connexion complète.

Le premier client de ce chemin est [kdt-web](https://github.com/agardenat/kdt), l'interface web de
kdt. Elle s'installe séparément.

## Ce que l'apiserver reconnaît

Par défaut, les identités sont des certificats clients X.509 obtenus via l'API
`CertificateSigningRequest` : `CN=kdt:<utilisateur>`, un `O=kdt:<groupe>` par groupe, signés par la
CA du cluster. Ils durent dix minutes et le plugin les renouvelle en silence. Rien à changer sur le
control plane — aucun drapeau de l'apiserver, aucune `AuthenticationConfiguration`, aucun IdP à
déplacer — mais le cluster doit honorer ce signeur : k3s et AKS oui, EKS non.

Le mode `oidc` remplace les certificats par des jetons que l'apiserver valide. Il sert aux clusters
qui ne signent pas, et à tracer les sessions individuellement. La révocation et l'identité produite
sont identiques dans les deux cas.

[Guide des modes](docs/modes.md) — tableau de décision, compatibilité par plateforme, comment
tester son cluster en une minute, comment basculer.

### Coexistence avec un IdP déjà en place

kdt-identity ne modifie rien de l'existant : ni drapeaux de l'apiserver, ni configuration
d'authentification, ni webhook. Il ajoute des CRDs dans son propre groupe d'API, un contrôleur, et
des CSR éphémères supprimées après émission. Rancher, Entra ID, Keycloak et authentik continuent de
fonctionner à l'identique. En `authMode: ldap`, l'annuaire est lu, jamais écrit ; en
`authMode: oidc`, le fournisseur ne reçoit du portail que ce qu'un client OAuth lui demande.

| Risque | Ce qui est fait |
|---|---|
| Rancher expose déjà un kind `User` | Les kinds sont `KdtUser` / `KdtGroup`, shortNames `kdtuser` / `kdtgroup`. Jamais `user` ni `group`. |
| Un sujet RBAC n'est qu'une chaîne : `alice` émis ici hériterait d'un binding Rancher visant `alice` | Toute identité émise porte le préfixe `kdt:`, non désactivable. Aucune collision avec les `u-*` de Rancher, les UPN Entra ou `system:*`. |

Le kubeconfig produit ne décrit que le cluster et l'identité : ni `proxy-url`, ni bastion.

## Sécurité

**kdt-identity est un composant équivalent cluster-admin.** Approuver une CSR
`kubernetes.io/kube-apiserver-client` revient à choisir une identité auprès de l'apiserver : qui
peut le faire peut forger `O=system:masters`. Déploiement en conséquence — namespace dédié,
NetworkPolicy en deny-by-default, RBAC restreint au seul signeur utilisé.

Trois vérifications encadrent les identités, et se recouvrent volontairement :

1. **À l'admission** — une `ValidatingAdmissionPolicy` en CEL refuse les noms réservés, hors jeu de
   caractères ou trop longs, y compris dans la liste des membres d'un groupe.
2. **À la construction** — `Subject` ne peut être obtenu que par une fonction validante, qui ajoute
   elle-même le préfixe.
3. **Avant approbation** — le sujet de la CSR est relu et doit correspondre exactement à l'identité
   attendue, groupes compris ; une demande fournie par un client n'est jamais crue sur parole.

### Révocation

Un credential émis vaut jusqu'à son expiration : Kubernetes ne consulte aucune CRL. La révocation
porte donc sur le droit d'en obtenir un autre, conservé dans le cluster. Deux gestes :

```console
$ kubectl -n kdt-identity exec deploy/kdt-identity-controller -- \
    /usr/local/bin/kdt-identity-server revoke alice          # poste perdu ou volé

$ kubectl patch kdtuser alice --type=merge \
    -p '{"spec":{"disabled":true}}'                          # départ, compte compromis
```

`revoke` ferme les sessions ouvertes : la personne reste habilitée et se reconnecte depuis un autre
poste. `disabled` va plus loin : le portail refuse la connexion, le contrôleur ferme les sessions
en cours, plus aucun renouvellement n'aboutit — et c'est un champ de la spec, donc déclaratif.

Dans les deux cas, le credential en circulation vit sa durée : dix minutes au plus en mode
certificat, cinq en mode OIDC, `certTtl` en décide.

Deux autres leviers :

- **retirer le binding d'un groupe** coupe l'accès de tous ses membres instantanément, sans
  attendre le moindre renouvellement ;
- **un kubeconfig téléchargé depuis le portail** est autoportant : personne ne le renouvelle, et il
  reste valable jusqu'à son expiration, huit heures par défaut. `portal.kubeconfigDownload: false`
  ferme ce chemin.

## Obtenir les binaires

| Binaire | Où | Pour qui |
| --- | --- | --- |
| `kdt-identity-server` | dans le cluster, fourni par l'image | contrôleur, portail, commandes d'administration |
| `kdt-identity` | sur le poste de travail | plugin d'authentification de kubectl |

Côté administration, il n'y a rien à installer : les commandes du serveur s'exécutent dans le pod
déjà déployé. Le chemin est absolu, l'image ne contenant ni shell ni `PATH`.

```sh
kubectl -n kdt-identity exec deploy/kdt-identity-controller -- \
    /usr/local/bin/kdt-identity-server invite alice
```

Côté poste de travail, installer le paquet `.deb` ou `.rpm` de la release, extraire le binaire de
l'image, ou compiler depuis les sources — voir le [guide du plugin](docs/plugin.md#installation).

## Installation

Le chart est publié dans un dépôt Helm : rien à cloner.

```sh
helm repo add kdt https://agardenat.github.io/helm-charts
helm repo update
```

```sh
helm install kdt-identity kdt/kdt-identity \
    --namespace kdt-identity --create-namespace \
    --set clusterName=production \
    --set portalUrl=https://identity.example.com \
    --set apiserverUrl=https://k8s.example.com:6443 \
    --set ingress.enabled=true \
    --set ingress.host=identity.example.com
```

`apiserverUrl` n'est pas `https://kubernetes.default.svc` : cette adresse finit dans le kubeconfig
d'un utilisateur, qui n'est pas dans le cluster.

Le chart refuse un ingress sans TLS : le cookie de session porte l'attribut `Secure`, un navigateur
ne le renverrait pas sur du HTTP. Sans ingress, pour essayer :

```sh
kubectl -n kdt-identity port-forward svc/kdt-identity-kdt-identity 8080:80
```

### Depuis un fichier de valeurs

```yaml
# helm-values.yaml
clusterName: production
portalUrl: https://identity.example.com
apiserverUrl: https://k8s.example.com:6443

ingress:
  enabled: true
  className: nginx
  host: identity.example.com
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod

networkPolicy:
  enabled: true
  # Sur un cluster sous Cilium, sans quoi le contrôleur n'atteint pas l'apiserver.
  cilium: false
  # Les pods autorisés à joindre le portail. Vide, seul le namespace de la release y accède,
  # et le contrôleur d'ingress est refusé.
  ingressFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
      podSelector:
        matchLabels:
          app.kubernetes.io/name: ingress-nginx
```

```sh
helm upgrade --install kdt-identity kdt/kdt-identity --version 1.2.0 \
    --namespace kdt-identity --create-namespace \
    --values helm-values.yaml
```

`upgrade --install` installe la première fois et met à jour ensuite. `--version` épingle la version
du chart, sans quoi la version déployée dépend de la date du pipeline.

#### La clé de session, si le rendu se fait hors du cluster

`sessionKey` laissée vide, le chart engendre une clé au premier déploiement et la relit ensuite
avec `lookup`, pour qu'une montée de version ne déconnecte pas tout le monde.

`lookup` ne rend quelque chose que si le rendu a accès au cluster : c'est le cas de `helm upgrade`
et du contrôleur Helm de Flux, pas de `helm template` ni d'un outil qui rend le chart avant de
l'appliquer — Argo CD par défaut. Là, la clé est régénérée à chaque synchronisation et toutes les
sessions ouvertes tombent. Dans ce cas, fixer la clé explicitement :

```sh
helm upgrade --install kdt-identity kdt/kdt-identity --version 1.2.0 \
    --namespace kdt-identity --create-namespace \
    --values helm-values.yaml \
    --set sessionKey="$KDT_SESSION_KEY"
```

`KDT_SESSION_KEY` vaut 32 octets en base64, `openssl rand -base64 32`. Elle n'a pas sa place dans
le fichier de valeurs versionné.

### Ce que le chart installe

| Ressource | Rôle |
|---|---|
| `ClusterRole` | lecture des CRDs, écriture de leur statut, cycle de vie des CSR |
| `signers` avec `resourceNames` | l'autorisation d'approuver est restreinte au seul `kubernetes.io/kube-apiserver-client` |
| `Role` namespacé | les Secrets de credentials, **sans le verbe `list`** : le contrôleur y accède par leur nom, et l'absence de ce verbe empêche d'énumérer les comptes |
| `NetworkPolicy` | apiserver, DNS et SMTP uniquement — le reste est refusé |
| `ValidatingAdmissionPolicy` | les règles de nommage, rejouées côté apiserver |

Les CRDs et la politique d'admission sont générées depuis le code, et un test échoue si le YAML
committé s'en écarte.

Sans Helm, avec le binaire du serveur extrait de l'image
(`/usr/local/bin/kdt-identity-server`) :

```sh
kdt-identity-server crd | kubectl apply -f -
kdt-identity-server controller
```

Les CRDs seules s'appliquent aussi directement depuis le dépôt :

```sh
kubectl apply -f https://raw.githubusercontent.com/agardenat/kdt-identity/main/deploy/helm/kdt-identity/crds/kdt-identity-crds.yaml
```

## Développement

```sh
cargo test --workspace
```

Les tests de bout en bout créent de vraies CSR et s'authentifient avec le certificat obtenu. Ils ne
créent aucun binding RBAC — l'identité de test doit pouvoir s'authentifier sans obtenir le moindre
droit — et sont ignorés par défaut :

```sh
KUBECONFIG=~/.kube/config cargo test -p kdt-identity-server --test e2e_issuance -- --ignored
```

## Licence

Apache-2.0.
