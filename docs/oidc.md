# Mode OIDC

kdt-identity émet par défaut des certificats X.509 de dix minutes, renouvelés silencieusement
par le plugin. Ce mode ne demande rien à l'apiserver, et il est révocable : le droit de
renouveler vit dans le cluster, le retirer coupe l'accès au renouvellement suivant.

**Le mode OIDC n'apporte donc pas la révocation** — elle est commune aux deux. Il sert à autre
chose.

## À quoi il sert vraiment

1. **Aux clusters qui ne signent pas.** Le signeur `kubernetes.io/kube-apiserver-client` est
   servi par le kube-controller-manager, que personne ne maîtrise sur un control plane managé.
   EKS ne le sert pas : aucune demande de signature n'y produit de certificat client. Le mode
   OIDC y est la seule voie.
2. **À l'audit.** Chaque jeton porte un `jti` unique, repris dans les journaux d'audit de
   l'apiserver. Un certificat ne laisse que son sujet, identique d'une émission à l'autre : on
   ne peut pas distinguer deux sessions de la même personne.
3. **À la granularité.** Cinq minutes contre dix, parce qu'un jeton n'a pas le plancher que
   l'API Kubernetes impose à `expirationSeconds`.

## Ce qu'il change

| | Certificat | OIDC |
|---|---|---|
| Configuration de l'apiserver | aucune | émetteur, audience, CA |
| Fonctionne sur EKS | non | oui |
| Fonctionne sur AKS | oui | non, émetteur tiers refusé |
| Révocation d'une personne | ≤ 10 min | ≤ 5 min |
| Audit d'une session | sujet du certificat | `jti` par jeton |
| Kubeconfig téléchargeable | oui | non, le plugin est nécessaire |

Dans les deux modes, le portail est une dépendance de disponibilité de l'accès : personne ne
renouvelle plus rien pendant qu'il est indisponible, et une durée de dix ou cinq minutes ne
laisse pas de marge. Prévoyez au moins deux répliques, et gardez un accès de secours qui ne
dépende pas de kdt-identity.

## Avant de commencer

Il faut pouvoir configurer l'apiserver. C'est la seule vraie condition, et elle exclut des
plateformes entières :

- **Kubeadm, k3s, RKE2, kops, clusters auto-gérés** : possible, c'est le cas nominal.
- **EKS** : possible, par `associate-identity-provider-config`.
- **GKE** : possible via Identity Service for GKE.
- **AKS** : impossible pour un émetteur tiers. L'intégration d'identité y est Entra ID, et rien
  d'autre. Restez en mode certificat.
- **OpenShift** : possible, par la ressource `OAuth`/`Authentication` du cluster.

Il faut aussi que **l'apiserver puisse joindre le portail en HTTPS**, avec un certificat qu'il
approuve. L'apiserver récupère `https://<portail>/.well-known/openid-configuration` puis le
JWKS. Si le portail n'est joignable que depuis les postes de travail, ce mode ne fonctionnera
pas.

## Activer le mode

```yaml
credentialMode: oidc

portalUrl: https://identity.example.com

refreshTtl: 7d

oidc:
  audience: kdt-identity
  tokenTtl: 5m
```

Le chart refuse de rendre si `portalUrl` n'est pas en `https` ou si aucun ingress n'est activé :
dans les deux cas l'apiserver ne pourrait pas valider un seul jeton, et l'échec se manifesterait
côté cluster par un message qui ne dit pas pourquoi.

Au premier démarrage, le portail crée un `Secret` `kdt-identity-oidc-key` portant sa clé de
signature. Elle n'est ni dans le chart ni dans une valeur : elle doit être identique d'une
réplique à l'autre et survivre aux redémarrages, sans quoi tous les jetons émis deviennent
invalides à chaque bascule.

Vérifiez ensuite que l'émetteur se découvre :

```console
$ curl -s https://identity.example.com/.well-known/openid-configuration | jq .issuer
"https://identity.example.com"

$ curl -s https://identity.example.com/.well-known/jwks.json | jq '.keys[0] | {kty, crv, alg}'
{"kty": "EC", "crv": "P-256", "alg": "ES256"}
```

## Configurer l'apiserver

Deux façons, selon la version. La configuration structurée est préférable partout où elle est
disponible : elle est explicite là où les drapeaux ont des valeurs par défaut surprenantes.

### Configuration structurée (recommandée)

Le format est le même d'une version à l'autre ; seule l'`apiVersion` change :

| Kubernetes | `apiVersion` | État |
|---|---|---|
| 1.34 et au-delà | `apiserver.config.k8s.io/v1` | stable |
| 1.30 à 1.33 | `apiserver.config.k8s.io/v1beta1` | bêta |
| 1.29 | `apiserver.config.k8s.io/v1alpha1` | alpha, à éviter |
| avant 1.29 | — | passer par les drapeaux ci-dessous |

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
  - issuer:
      url: https://identity.example.com
      audiences:
        - kdt-identity
      # La CA qui signe le certificat TLS du portail. Inutile si elle est déjà dans le magasin
      # de confiance du système sur les nœuds du control plane.
      certificateAuthority: |
        -----BEGIN CERTIFICATE-----
        …
        -----END CERTIFICATE-----
    claimMappings:
      username:
        claim: sub
        # Vide, et c'est délibéré : le préfixe `kdt:` est déjà dans le jeton. Un préfixe
        # supplémentaire produirait `kdt:kdt:alice`, que plus aucun binding ne vise.
        prefix: ""
      groups:
        claim: groups
        prefix: ""
    # Quatrième barrière, et la seule que kdt-identity ne peut pas contourner s'il est
    # compromis : l'apiserver refuse tout jeton dont le sujet sort du préfixe, quelle que soit
    # la clé qui l'a signé.
    claimValidationRules:
      - expression: 'claims.sub.startsWith("kdt:")'
        message: le sujet doit porter le prefixe kdt
```

> **Posez les règles CEL une par une.** Elles sont compilées au démarrage de l'apiserver, et
> une expression que le compilateur refuse **empêche l'apiserver de démarrer** — pas de
> message à l'admission, pas de dégradation : le service ne remonte pas. Vérifié sur k3s 1.35,
> où une règle portant sur `claims.groups` a fait échouer le démarrage là où la règle sur
> `claims.sub` passe sans problème. Gardez une session SSH ouverte et le rollback sous la main
> à chaque ajout.
>
> Une règle équivalente sur les groupes serait utile, mais la syntaxe CEL acceptée dépend de la
> façon dont l'apiserver type les revendications, et celle qui paraît naturelle ne compile pas.
> Elle sera ajoutée ici une fois vérifiée sur un cluster, pas avant.

Puis `--authentication-config=/etc/kubernetes/authentication.yaml` sur l'apiserver.

Deux détails qui coûtent cher :

- **`--authentication-config` et les drapeaux `--oidc-*` sont mutuellement exclusifs.** Poser
  les deux fait refuser le démarrage de l'apiserver. Choisissez l'un ou l'autre.
- **`prefix` doit être présent dès que `claim` l'est**, et peut valoir la chaîne vide. L'omettre
  n'est pas équivalent à le laisser vide : c'est une erreur de validation.

`kubectl explain` ne renseigne pas sur ce fichier — c'est une configuration lue par
l'apiserver, pas une ressource de l'API. La référence est
[apiserver-config.v1](https://kubernetes.io/docs/reference/config-api/apiserver-config.v1/).

### Drapeaux hérités (toutes versions)

Dépréciés mais toujours acceptés, et le seul chemin avant Kubernetes 1.29 :

```
--oidc-issuer-url=https://identity.example.com
--oidc-client-id=kdt-identity
--oidc-username-claim=sub
--oidc-username-prefix=-
--oidc-groups-claim=groups
--oidc-groups-prefix=-
--oidc-signing-algs=ES256
--oidc-ca-file=/etc/kubernetes/pki/identity-ca.crt
```

Trois de ces lignes sont des pièges, et les omettre produit un cluster qui refuse tout :

- **`--oidc-username-prefix=-`** est obligatoire. Sans lui, et dès lors que le claim n'est pas
  `email`, l'apiserver préfixe **automatiquement** les identités avec `<issuer>#`. `alice`
  deviendrait `https://identity.example.com#kdt:alice`, qu'aucun binding ne vise. Le tiret est
  la façon de dire « aucun préfixe » — une chaîne vide est ignorée, pas respectée.
- **`--oidc-groups-prefix=-`** pour la même raison, appliquée aux groupes.
- **`--oidc-signing-algs=ES256`** parce que la valeur par défaut est `RS256` seul. kdt-identity
  signe en ES256, qui réutilise la courbe déjà employée pour les demandes de signature.

## Vérifier

```console
$ kdt-identity kubeconfig --portal https://identity.example.com --user alice \
    --cluster production --server https://k8s.example.com:6443 --ca-file ca.crt > ~/.kube/config

$ kubectl auth whoami
ATTRIBUTE   VALUE
Username    kdt:alice
Groups      [kdt:lecteurs system:authenticated]
```

L'identité est identique à celle du mode certificat, préfixe compris. Les `RoleBinding` et
`ClusterRoleBinding` déjà écrits continuent donc de fonctionner sans être touchés — c'est la
raison pour laquelle le préfixe est posé à l'émission plutôt que par la configuration de
l'apiserver.

Si `kubectl` répond `Unauthorized`, l'erreur est presque toujours dans cet ordre : préfixe
ajouté deux fois, audience qui ne correspond pas, émetteur écrit différemment des deux côtés
(une barre oblique finale suffit), algorithme non autorisé, CA inconnue de l'apiserver. Les
journaux de l'apiserver nomment la cause ; ceux du portail montrent seulement qu'un jeton a
été émis.

## Révoquer

```console
$ kubectl -n kdt-identity exec deploy/kdt-identity-controller -- \
    /usr/local/bin/kdt-identity-server revoke alice
alice : 2 sessions fermées
L'accès s'arrête au prochain renouvellement, dans 5 min au plus.
Le compte reste actif : il peut rouvrir une session. Pour l'en empêcher,
kubectl patch kdtuser alice --type=merge -p '{"spec":{"disabled":true}}'
```

Rien de tout cela n'est propre au mode OIDC : `revoke` et `disabled` fonctionnent à
l'identique en mode certificat, où le délai est de dix minutes au lieu de cinq. Voir la section
Révocation du README.

Le jeton déjà en circulation reste valide jusqu'à son échéance — cinq minutes par défaut. C'est
le seul délai irréductible, et le réglage `tokenTtl` en décide.

## Ce que le mode OIDC retire

**Le kubeconfig téléchargeable depuis le portail.** Un jeton de cinq minutes dans un fichier
serait périmé avant d'être rangé, et il n'existe pas d'équivalent long : contrairement à un
certificat, un jeton ne peut pas être émis pour huit heures sans annuler ce qui le rend
révocable. En mode OIDC, **le plugin `kdt-identity` doit être installé sur chaque poste** ;
le mode certificat, lui, permet encore de s'en passer — au prix d'un accès non révocable, et
c'est un choix qui se ferme par `portal.kubeconfigDownload: false`.

## Changer de mode

Le mode se choisit une fois. En changer invalide tout ce qui a été distribué : les certificats
en circulation restent valides jusqu'à leur expiration mais ne se renouvellent plus, et les
jetons cessent d'être acceptés dès que l'apiserver ne connaît plus l'émetteur.

Pour passer de `certificate` à `oidc` sans coupure : configurez l'apiserver **d'abord** —
l'authentification Kubernetes est une chaîne, un émetteur OIDC configuré ne perturbe pas la
validation des certificats — puis basculez `credentialMode`, puis attendez que les certificats
en cours expirent. Les utilisateurs referont un `kdt-identity kubeconfig` ou, s'ils utilisent
déjà le plugin, ne verront qu'une saisie de mot de passe de plus.
