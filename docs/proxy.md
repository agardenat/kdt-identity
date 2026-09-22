# Le mode proxy

`credentialMode: proxy` remet un kubeconfig qui ne contient qu'un jeton et l'adresse de
kdt-identity. `kubectl` et `helm` le lisent sans rien installer, et il cesse de fonctionner dès
que l'accès est coupé.

C'est le seul mode qui réunit les trois propriétés à la fois, et il ne demande **aucune** option
de l'apiserver.

## Pourquoi il existe

Un kubeconfig lisible sans binaire externe n'a que deux formes : un certificat client, ou un
jeton. Kubernetes ne consulte aucune CRL, donc un certificat émis vaut jusqu'à son expiration,
sans recours. Un jeton n'est révocable que s'il est vérifié **en ligne**, et les deux mécanismes
qui le permettent se règlent par des options de l'apiserver :

| Plateforme | Webhook d'authentification | Émetteur OIDC tiers |
|---|---|---|
| k3s, RKE2, kubeadm, auto-gérés | oui | oui |
| EKS | non | oui, `associate-identity-provider-config` |
| GKE | non | via Identity Service for GKE |
| AKS | **non** | **non** — Entra ID uniquement |

Sur un control plane qu'on n'administre pas, il n'y a donc rien à configurer. Le proxy contourne
la question : il se place **devant** le cluster au lieu d'agir dessus.

## Comment ça marche

```
kubectl ──jeton──▶ kdt-identity ──impersonation──▶ apiserver
```

À chaque requête, le proxy :

1. écarte ce qui n'a pas le préfixe `kdt_`, sans rien lire dans le cluster ;
2. vérifie le jeton contre la session enregistrée — empreinte SHA-256, comparaison à temps
   constant, date d'expiration ;
3. relit le `KdtUser` : le compte doit être actif ;
4. relit les groupes depuis les `KdtGroup`, jamais depuis `status.memberOf` ;
5. relaie à l'apiserver avec `Impersonate-User: kdt:<compte>`, un `Impersonate-Group: kdt:<groupe>`
   par groupe, et `Impersonate-Uid`.

L'apiserver voit donc `kdt:alice` dans ses groupes. **Les `RoleBinding` et `ClusterRoleBinding`
existants s'appliquent sans modification**, qu'ils visent `User: kdt:alice` ou `Group: kdt:ops`.

Les en-têtes `Impersonate-*` présentés par un client sont **retirés** avant le relais : un
`kubectl --as` ne traverse pas.

## Déployer

```yaml
credentialMode: proxy
portalUrl: https://identity.example.com
clusterName: production
```

Il n'y a rien de plus à publier : le proxy est servi par le portail, sous `/k8s`. Même hôte, même
certificat, même Ingress. Le kubeconfig remis pointe sur
`https://identity.example.com/k8s/production`.

Partager l'hôte n'ouvre rien : `kubectl` n'envoie pas de cookie, et le proxy n'authentifie que
sur `Authorization: Bearer`.

### Les applications autorisées

Une application qui a reçu un droit de session — kdt-web — ne télécharge pas de fichier : elle
demande un accès sur `POST /api/v1/proxy`, en présentant le jeton de session que lui a rendu
`/api/v1/session`, et reçoit l'adresse du cluster, un jeton et sa date d'expiration.

```json
{
  "token": "kdt_alice.…",
  "server": "https://identity.example.com/k8s/production",
  "expiresAt": "2026-09-22T12:10:00Z"
}
```

L'accès vit `certTtl` — dix minutes par défaut —, l'application le renouvelle comme elle
renouvellerait un certificat, et la route n'est montée qu'en mode proxy : un client qui la trouve
sait qu'il y a un proxy à joindre.

Deux conséquences qui n'existent pas dans les autres modes : les groupes ne sont pas figés dans ce
qui est remis, donc un retrait s'applique à l'application aussi vite qu'à `kubectl` ; et `revoke`
ferme son accès dans la seconde, là où un certificat de dix minutes la laissait travailler jusqu'à
son expiration.

La session ouverte porte l'usage `application`, et le plafond de cinq sessions se compte par
usage : une application qui renouvelle toutes les dix minutes n'évince pas les kubeconfigs
téléchargés du compte. Devant le proxy, les deux usages valent la même chose.

### Le publier séparément

Pour exposer le proxy et le portail à deux adresses — n'ouvrir que l'une, les protéger
différemment :

```yaml
proxy:
  url: https://kube.example.com
  listen: "0.0.0.0:8443"
```

Le chart ajoute alors un port au pod et au Service ; l'Ingress est à votre charge. `listen` sans
`url` est refusé au rendu.

### Les réglages

| Valeur | Défaut | Ce qu'elle décide |
|---|---|---|
| `proxy.cacheTtl` | `30s` | délai maximal entre une révocation et sa prise d'effet |
| `proxy.tokenTtl` | `7d` | durée de vie du jeton, entre `1h` et `30d` |
| `proxy.caSecret` | — | autorité à inscrire dans les kubeconfigs, si le certificat n'est pas public |
| `certTtl` | `10m` | durée de l'accès remis à une application autorisée, qui le renouvelle |

`cacheTtl` est le **seul** curseur du délai de révocation. Il existe pour ne pas relire un
`Secret` et deux objets à chaque `kubectl get`. À `0s`, la révocation est immédiate et chaque
requête coûte trois lectures.

## Ce qui passe

Tout, y compris les connexions promues — `exec`, `attach`, `port-forward`, `cp` — que le proxy
transporte sans les lire. Il ne parle ni SPDY ni WebSocket : les démultiplexer reviendrait à
réimplémenter `exec`, et à casser à la prochaine version du canal.

Vérifié contre un cluster k3s 1.35 : `get`, `apply`, `logs -f`, `watch`, `helm`, `exec` (y compris
interactif), `cp`, `port-forward`.

Une limite : les connexions promues ouvrent leur propre socket et **n'honorent pas** un
`proxy-url` déclaré dans le kubeconfig du serveur. Sans objet dans un pod, qui joint l'apiserver
en direct ; visible en développement contre un cluster atteint par un tunnel, où le proxy le dit
explicitement.

## Révoquer

```sh
kdt-identity-server revoke alice
```

ferme toutes les sessions d'un compte — plugin, kubeconfigs téléchargés **et** applications
autorisées. `spec.disabled` produit le même effet, et interdit en plus toute réouverture.

```
alice : 2 sessions fermées
L'accès s'arrête dans 30 s au plus, kubeconfigs téléchargés et applications compris.
```

Retirer un compte d'un `KdtGroup` prend effet tout aussi vite : les groupes sont relus à chaque
requête, là où un certificat déjà émis garde les siens jusqu'à expiration.

## Ce que ça coûte

- **kdt-identity est sur le chemin des requêtes.** S'il tombe, ces kubeconfigs ne fonctionnent
  plus. Les kubeconfigs administrateur natifs ne passent pas par lui : on ne peut pas s'enfermer
  dehors. Prévoir plusieurs réplicas du portail — l'état vit dans le cluster, le proxy est sans
  état.
- **Le ServiceAccount a le droit d'impersonation.** Sans `resourceNames`, qui n'accepte pas de
  joker. Ce n'est pas un pouvoir nouveau : approuver une CSR `kube-apiserver-client`, ce que font
  les autres modes, permet déjà de se forger n'importe quelle identité. En mode proxy le chart
  **retire** ces règles de signature au lieu de les cumuler. Ce qui garantit qu'aucune identité
  hors `kdt:` ne peut être produite est le type `Subject`, qui valide le nom et impose le préfixe.

## Changer de mode

**Vers `proxy`** : `helm upgrade --set credentialMode=proxy`, puis redistribuer les kubeconfigs
depuis le portail. Les certificats en circulation restent valides jusqu'à expiration, et le RBAC
ne bouge pas.

**Depuis `proxy`** : les jetons cessent de fonctionner dès que le mode change — ils ne valent que
par le proxy. Prévenir avant.

Un déploiement qui ne pose pas `credentialMode` reste en `certificate` : le mode proxy exige le
droit d'impersonation, qu'une montée de version ne doit pas accorder en silence.
