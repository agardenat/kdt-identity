# kdt-identity — utilisateurs et groupes locaux pour Kubernetes

Kubernetes n'a volontairement aucun objet `User` ni `Group` : l'authentification est déléguée à
un composant externe, et un groupe n'est qu'une chaîne portée par le credential. Sur un cluster
vanilla, il n'existe donc aucun moyen de dire « crée l'utilisateur X, mets-le dans le groupe Y,
envoie-lui son accès ».

kdt-identity comble ce trou : des utilisateurs et des groupes matérialisés en CRDs, un
contrôleur qui en tient l'appartenance à jour, et l'émission à la demande d'un kubeconfig que
l'apiserver reconnaît — sans toucher à la configuration du control plane.

Compagnon de [kdt](https://github.com/agardenat/kdt).

> **État : Phase 2 en cours.** Le noyau fonctionne de bout en bout (CRDs, contrôleur, émission
> de kubeconfig, invitations, CLI), et les primitives d'authentification sont écrites et
> testées. Le portail web qui les assemble, lui, n'existe pas encore : l'activation d'un compte
> n'est donc pas encore possible. Le plugin `exec` et le chart Helm restent à faire.

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

Les manifestes sont dérivés des types Rust — rien n'est recopié à la main :

```sh
kdt-identity-server crd | kubectl apply -f -
kdt-identity-server controller
```

Pour tout retirer :

```sh
kubectl delete -f <(kdt-identity-server crd)
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
