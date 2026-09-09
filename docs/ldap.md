# Mode LDAP

`authMode: ldap` fait de l'annuaire — Active Directory ou FreeIPA — la source des identités. Les
personnes se connectent avec leurs identifiants d'entreprise, leur `KdtUser` est créé à la
première connexion réussie, et leur appartenance aux groupes kdt est reportée depuis leurs
groupes d'annuaire.

C'est un axe **indépendant** du mode de délivrance : `ldap` se combine aussi bien avec
`certificate` qu'avec `oidc`. Voir [modes.md](modes.md).

Pour fédérer sur un fournisseur OpenID Connect plutôt que sur un annuaire — Entra ID n'expose pas
de LDAP, sauf à passer par Entra Domain Services ou par un AD synchronisé — voir
[fournisseur-oidc.md](fournisseur-oidc.md).

## À quoi il sert vraiment

Sans lui, un cluster dont l'entreprise a déjà un annuaire porte deux populations de comptes et
deux mots de passe. Chaque arrivée demande deux gestes, chaque départ aussi — et c'est le second
qu'on oublie.

Avec lui, il n'y a plus qu'un endroit où quelqu'un existe. Un compte désactivé dans l'annuaire ne
peut plus se connecter, et un retrait de groupe se traduit en retrait de droits sans que personne
n'écrive un `kubectl`.

## Ce qu'il change

| | `local` (défaut) | `ldap` |
|---|---|---|
| Mot de passe | Argon2id, dans un `Secret` du cluster | vérifié par un bind sur l'annuaire |
| Second facteur | TOTP, enrôlé au portail | celui de l'annuaire, le cas échéant |
| Création du compte | `kdt-identity-server invite` | à la première connexion réussie |
| Appartenance | `KdtGroup.spec.members`, à la main | reportée depuis l'annuaire |
| Page `/activate` | servie | non montée |
| `invite` | disponible | refuse de s'exécuter |
| Identité produite | `kdt:alice`, groupes `kdt:*` | identique |

Le second facteur est **délégué**. kdt-identity n'enrôle plus de TOTP et n'en vérifie plus : si
l'annuaire n'impose rien, la connexion se fait à un facteur. C'est le choix qu'engage ce mode, et
il vaut d'être posé explicitement — la posture MFA du cluster devient celle de l'annuaire.

## Avant de commencer

Il faut :

1. **Une URL en `ldaps://`**, ou en `ldap://` accompagnée de `startTls: true`. Un bind simple
   présente le mot de passe en clair dans la requête : c'est le protocole. Le chart refuse de
   rendre une configuration sans TLS, et le serveur refuse de démarrer.
2. **L'autorité qui a émis le certificat de l'annuaire**, en PEM. FreeIPA émet toujours depuis sa
   propre CA ; Active Directory presque toujours. Le magasin de l'image ne contient que les
   autorités publiques.
3. **Une racine de recherche** — `ou=users,dc=example,dc=com` — sous laquelle chercher les
   personnes.
4. **Un compte de service**, sauf si l'annuaire autorise la recherche anonyme. FreeIPA le fait
   souvent, Active Directory pratiquement jamais.
5. **La liste des groupes d'annuaire** qui doivent ouvrir des droits, avec leur DN complet.

## Activer le mode

Le compte de service arrive par un `Secret` que le chart ne crée pas : il porte des identifiants
qui n'ont pas à traverser un fichier de valeurs.

```sh
kubectl -n kdt-identity create secret generic kdt-identity-ldap \
    --from-literal=KDT_IDENTITY_LDAP_BIND_DN='CN=svc-kdt,OU=Services,DC=example,DC=com' \
    --from-literal=KDT_IDENTITY_LDAP_BIND_PASSWORD='…'
```

Puis les valeurs :

```yaml
authMode: ldap

ldap:
  profile: activedirectory
  url: ldaps://dc01.example.com:636
  userSearchBase: "OU=Users,DC=example,DC=com"
  existingSecret: kdt-identity-ldap
  caCert: |
    -----BEGIN CERTIFICATE-----
    …
    -----END CERTIFICATE-----
  groupMappings:
    - dn: "CN=K8s-Admins,OU=Groups,DC=example,DC=com"
      group: admins
    - dn: "CN=K8s-Devs,OU=Groups,DC=example,DC=com"
      group: devs
```

```sh
helm upgrade --install kdt-identity … -f helm-values.yaml
```

### La table de correspondance

Rien n'est déduit d'un DN. Dériver un nom kdt demanderait de le normaliser — minuscules,
caractères interdits remplacés, longueur coupée — et deux groupes distincts de l'annuaire
pourraient alors aboutir au même nom, donc aux mêmes droits.

Ce qui ne figure pas dans `groupMappings` n'existe pas côté cluster : un compte membre de trois
cents groupes d'annuaire n'obtient que ceux qui y sont déclarés.

Le nom du groupe doit être un nom de ressource valide — minuscules, chiffres, `-` et `.`, soixante
caractères au plus — et c'est lui qui donne le sujet RBAC `kdt:<groupe>` à référencer dans les
bindings. Le chart le vérifie au rendu : un nom invalide fait échouer `helm upgrade` plutôt que la
première connexion.

Les correspondances multiples sont permises dans les deux sens : deux groupes d'annuaire vers un
même groupe kdt, ou un groupe d'annuaire vers plusieurs.

### Les attributs du schéma

`profile` préremplit les noms d'attributs :

| | `activedirectory` | `freeipa` |
|---|---|---|
| Identifiant de connexion | `sAMAccountName` | `uid` |
| Adresse | `mail` | `mail` |
| Nom affiché | `displayName` | `cn` |
| Groupes | `memberOf` | `memberOf` |
| Classe d'objet | `user` | `person` |

Chacun se surcharge séparément — `userLoginAttribute`, `userEmailAttribute`,
`userDisplayAttribute`, `groupMemberAttribute`, `userObjectClass` — pour un schéma qui s'écarte
du profil sur un point.

## Ce que le mode fait des comptes

Un compte créé depuis l'annuaire porte deux marques :

```sh
kubectl get kdtusers -l identity.kdt.sh/source=ldap
kubectl get kdtuser alice -o jsonpath='{.metadata.annotations.identity\.kdt\.sh/ldap-dn}'
```

- le **label** `identity.kdt.sh/source: ldap` le distingue d'un compte créé à la main ;
- l'**annotation** `identity.kdt.sh/ldap-dn` garde son DN, et il est revérifié à chaque
  connexion.

Cette vérification n'est pas décorative. L'identifiant de connexion est normalisé pour donner un
nom de ressource — `Jean_Dupont` devient `jean-dupont` — et deux identifiants distincts peuvent
donner le même nom. Sans l'épinglage du DN, le second se connecterait sur le compte du premier et
hériterait de ses droits. Une divergence est refusée, jamais arbitrée.

Pour la même raison, un compte **local** qui porte déjà le nom visé n'est pas absorbé : il faudrait
prendre possession d'un compte que quelqu'un a créé avec son mot de passe et son TOTP.

L'adresse électronique est obligatoire — `KdtUserSpec.email` l'est — et vient de l'attribut
`mail`. Une entrée qui n'en porte pas ne peut pas donner de compte.

## La relecture périodique

Une connexion ne renseigne que la personne qui se connecte. Sans plus, un retrait de groupe côté
annuaire n'aurait d'effet qu'à sa prochaine saisie de mot de passe — et comme le renouvellement
silencieux ne rebinde jamais, cela peut vouloir dire jusqu'à `refreshTtl`, sept jours par défaut.

Le contrôleur relit donc l'annuaire toutes les `ldap.resync` — quinze minutes par défaut — pour
tous les comptes marqués `source=ldap` :

- l'appartenance est réalignée sur ce que dit l'annuaire ;
- un compte dont l'entrée a **disparu** passe en `spec.disabled`, ce qui ferme ses sessions.

Il n'est jamais supprimé : une suppression emporterait ses `Secret` par cascade, et une panne de
lecture prise pour une disparition ferait perdre des comptes. Un compte déjà désactivé à la main
n'est pas réactivé par l'annuaire — `spec.disabled` reste le geste d'un administrateur.

Une panne d'annuaire interrompt le tour sans rien désactiver. C'est la règle qui gouverne tout ce
mécanisme : une absence de réponse ne dit rien, et la prendre pour une disparition désactiverait
tous les comptes du cluster à la première coupure réseau.

## Vérifier

Le portail annonce ce qu'il attend, sans authentification :

```sh
curl -s https://identity.example.com/api/v1/portal
{"credentialMode":"certificate","authMode":"ldap","totpRequired":false}
```

C'est ce que le plugin lit pour savoir s'il doit demander un code. Un portail antérieur à ce point
d'accès répond 404, et le plugin retombe alors sur son comportement historique.

Puis une connexion réelle :

```sh
kubectl kdt-identity credential --portal https://identity.example.com --user alice
# Mot de passe : …          ← aucun code demandé

kubectl auth whoami
ATTRIBUTE   VALUE
Username    kdt:alice
Groups      [kdt:admins system:authenticated]
```

Et le compte tel que le cluster le voit :

```sh
kubectl get kdtuser alice -o yaml
kubectl get kdtgroup admins -o jsonpath='{.spec.members}'
```

## Dépannage

| Symptôme | Cause habituelle |
|---|---|
| Toute connexion refusée, journaux `annuaire injoignable` | CA absente ou fausse — le handshake TLS échoue avant le bind |
| `identifiants refusés` alors que le mot de passe est bon | `userSearchBase` ne couvre pas l'entrée, ou `userLoginAttribute` ne correspond pas au schéma |
| Connexion acceptée, aucun droit | DN absent de `groupMappings`, ou écrit pour un autre sous-arbre |
| `un compte local nommé alice existe déjà` | un `KdtUser` créé à la main porte ce nom : le renommer ou le supprimer |
| `le compte alice est déjà rattaché à une autre entrée` | deux identifiants d'annuaire normalisent vers le même nom |

Les journaux du portail nomment la cause exacte ; le visiteur, lui, reçoit toujours le même
message. Un portail qui répond précisément permet d'énumérer les comptes depuis l'extérieur.

```sh
kubectl -n kdt-identity logs deploy/kdt-identity-portal
kubectl -n kdt-identity logs deploy/kdt-identity-controller
```

## Ce que le mode LDAP retire

- **L'invitation.** `kdt-identity-server invite` refuse de s'exécuter, et `/activate` n'est pas
  montée. Les comptes naissent d'une connexion réussie.
- **Le TOTP côté kdt.** Plus d'enrôlement, plus de QR code, plus de vérification de code.
- **La gestion manuelle des groupes fédérés.** Un `KdtGroup` marqué `source=ldap` est réaligné à
  chaque connexion et à chaque relecture : y ajouter un membre à la main ne tient pas. Les groupes
  **non** marqués, eux, ne sont jamais touchés — les deux façons de faire coexistent sur un même
  cluster.

Ce que le mode ne retire pas : la révocation, le verrouillage progressif après échecs répétés,
`spec.disabled`, le préfixe `kdt:` et le kubeconfig téléchargeable en mode certificat.

## Changer de mode

**De `local` vers `ldap`** : les comptes locaux existants restent, et restent utilisables par le
portail tant qu'ils ne portent pas le label — mais plus personne ne peut s'authentifier contre
eux, puisque le portail ne vérifie plus que l'annuaire. Prévoir que chaque personne existe dans
l'annuaire avant de basculer.

**De `ldap` vers `local`** : les comptes fédérés subsistent avec leur label, mais n'ont ni mot de
passe ni TOTP. Il faut les inviter (`kdt-identity-server invite`) pour qu'ils redeviennent
utilisables. Le label et l'annotation peuvent alors être retirés.

Dans les deux sens, ni les groupes, ni les bindings RBAC, ni les kubeconfig n'ont à changer :
l'identité produite est la même.
