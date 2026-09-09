# Mode fournisseur d'identité

`authMode: oidc` délègue l'authentification à un fournisseur OpenID Connect — Entra ID, Keycloak,
Okta. Les personnes se connectent chez lui, leur `KdtUser` est créé à la première connexion
réussie, et leur appartenance aux groupes kdt est reportée depuis les groupes qu'il déclare.

C'est un axe **indépendant** du mode de délivrance : `oidc` en authentification se combine aussi
bien avec `certificate` qu'avec `oidc` en délivrance. Voir [modes.md](modes.md) — et ne pas
confondre les deux : [oidc.md](oidc.md) parle de ce que le portail **émet** vers l'apiserver, ce
document de qui il **reconnaît**.

## À quoi il sert vraiment

À ne plus détenir de mot de passe. En `local`, le cluster héberge des empreintes et des secrets
TOTP ; en `ldap`, il les relaie. Ici, il n'en voit aucun : le navigateur part chez le fournisseur,
revient avec un code, et le portail échange ce code contre un jeton d'identité.

Ce que le fournisseur applique s'applique donc aussi au cluster, sans une ligne de configuration
supplémentaire : second facteur, accès conditionnel, réinitialisation, départ d'un collaborateur.

La question qui vient ensuite est légitime : pourquoi ne pas configurer l'apiserver directement
sur le fournisseur ? Parce qu'en `credentialMode: certificate`, l'apiserver n'a **rien** à savoir
de lui — c'est le cas des clusters qu'on ne peut pas reconfigurer. Et parce que dans les deux
modes de délivrance, la révocation, les `KdtGroup` et le portail restent ceux de kdt-identity.

## Ce que ce mode change

| | `local` | `ldap` | `oidc` |
|---|---|---|---|
| Mot de passe | Argon2id, dans le cluster | vérifié par un bind | **jamais présenté au portail** |
| Second facteur | TOTP, enrôlé au portail | celui de l'annuaire | celui du fournisseur |
| Création du compte | `invite` | première connexion | première connexion |
| Appartenance | à la main | reportée de l'annuaire | reportée du fournisseur |
| Page `/login` | formulaire | formulaire | bouton vers le fournisseur |
| `POST /login` | monté | monté | **non monté** |
| Page `/activate` | servie | non montée | non montée |
| `invite` | disponible | refuse | refuse |
| Session du plugin | mot de passe au terminal | idem | **navigateur** |
| Identité produite | `kdt:alice`, groupes `kdt:*` | identique | identique |

Le mot de passe n'est pas seulement inutile : il est **refusé**, à trois endroits. Le formulaire
n'est pas monté, l'API le rejette avant toute lecture, et la fonction d'authentification a un cas
qui refuse. Laisser subsister une porte par mot de passe à côté du fournisseur reviendrait à
contourner tout ce qu'il applique.

## Avant de commencer

Il faut :

1. **Une application enregistrée** chez le fournisseur, de type *web* (client confidentiel avec
   secret) ou *public* avec PKCE. Le portail sait faire les deux, mais les deux s'excluent : un
   secret configuré face à un client déclaré public est refusé aussi sûrement que l'inverse.
2. **L'adresse de retour** `https://<portalUrl>/login/callback`, déclarée sur cette application.
   C'est la seule à enregistrer — celle du plugin est un port de la boucle locale, et la
   RFC 8252 §7.3 veut qu'un fournisseur l'accepte sans qu'il soit déclaré.
3. **Un `portalUrl` en https**. Un code d'autorisation s'échange contre un droit de session : il
   n'a pas à voyager en clair, et la plupart des fournisseurs refusent d'enregistrer une adresse
   de retour qui ne l'est pas.
4. **Les groupes émis dans le jeton**. Chez Entra ID, c'est un réglage de l'application (*Token
   configuration* → *groups claim*) ; sans lui, personne n'obtient de droit.
5. **La liste des groupes** qui doivent ouvrir des droits, par leur identifiant — chez Entra ID,
   un GUID.

## Activer le mode

Le secret de l'application arrive par un `Secret` que le chart ne crée pas : il porte des
identifiants qui n'ont pas à traverser un fichier de valeurs.

```sh
kubectl -n kdt-identity create secret generic kdt-identity-oidc \
    --from-literal=KDT_IDENTITY_AUTH_OIDC_CLIENT_SECRET='…'
```

Puis les valeurs :

```yaml
authMode: oidc

oidcAuth:
  issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
  clientId: <identifiant d'application>
  existingSecret: kdt-identity-oidc
  providerName: Entra ID
  claims:
    subject: oid
  groupMappings:
    - claim: "8f4a1c2e-0b77-4e3b-9a21-2c5d8e7f0a11"
      group: admins
    - claim: "c1d9b0a4-73e2-4a55-8f10-6b2c9d4e1f33"
      group: devs
```

### La table de correspondance

Même règle qu'en LDAP : rien n'est déduit. Ce qui ne figure pas dans `groupMappings` n'existe pas
côté cluster, et le nom du groupe doit être un nom de ressource valide — c'est lui qui donne le
sujet RBAC `kdt:<groupe>` à référencer dans les bindings. Le chart le vérifie au rendu.

La clé est la valeur telle qu'elle apparaît dans le claim. Chez Entra ID, ce sont des **GUID** :
le format `sam_account_name` n'est disponible que pour les groupes synchronisés depuis un AD
on-premise. Une table de GUID se relit mal ; les *app roles* sont l'alternative, avec
`claims.groups: roles` et des noms choisis.

### Sur quoi le compte est épinglé

Le nom du `KdtUser` est dérivé du claim `preferred_username`, par une normalisation qui n'est pas
injective : `Jean_Dupont` et `jean-dupont` donnent le même compte. Le claim d'épinglage —
`claims.subject` — est ce qui empêche la seconde personne d'hériter des droits de la première : il
est enregistré à la création, dans l'annotation `identity.kdt.sh/oidc-subject`, et revérifié à
chaque connexion.

`sub` est le défaut, et le seul que la spécification garantisse stable. Chez Entra ID, il est
**propre à l'application** : réenregistrer le portail changerait tous les `sub` déjà épinglés, et
chaque compte serait alors refusé. `oid` — l'identifiant de l'objet dans le tenant — n'a pas ce
défaut, et devient d'ailleurs obligatoire dès que l'accès à l'API est déclaré.

## L'accès à l'API du fournisseur

Facultatif, et il répond à deux manques d'un coup.

**Les groupes déportés.** Au-delà d'environ deux cents groupes, Entra ID cesse de les mettre dans
le jeton et n'y laisse qu'un renvoi vers Microsoft Graph. Sans cet accès, la personne la mieux
dotée en groupes est précisément celle dont la connexion est refusée — avec un message qui le dit,
plutôt qu'une session ouverte sans droits.

**La relecture.** Une session se renouvelle en silence, sans jamais revenir au fournisseur. Un
retrait de groupe fait chez lui n'a donc d'effet qu'à la prochaine connexion interactive. Sans cet
accès, `refreshTtl` est **plafonné à 24 h** pour borner ce retard ; avec lui, l'appartenance est
relue toutes les quinze minutes et le plafond disparaît.

Il exige une permission d'application — `GroupMember.Read.All` et `User.Read.All` — accordée **et
consentie par un administrateur** du tenant. Une permission déléguée y ressemble à s'y méprendre
tant que le consentement n'est pas donné ; le portail traduit le 403 qui en résulte en un message
qui nomme la cause.

```sh
kubectl -n kdt-identity create secret generic kdt-identity-oidc \
    --from-literal=KDT_IDENTITY_AUTH_OIDC_CLIENT_SECRET='…' \
    --from-literal=KDT_IDENTITY_AUTH_OIDC_GRAPH_CLIENT_SECRET='…'
```

```yaml
oidcAuth:
  claims:
    subject: oid          # exigé par le chart dès que graph.enabled
  graph:
    enabled: true
    tenantId: <tenant-id>
    resync: 15m
```

Un compte **supprimé ou fermé** chez le fournisseur passe alors en `spec.disabled` — jamais
supprimé. Le mode LDAP ne connaît que la disparition d'une entrée ; ici, un départ se traduit
d'abord par un `accountEnabled: false`, et l'ignorer laisserait l'accès ouvert jusqu'à une
suppression définitive qui n'arrive parfois jamais.

Une panne, elle, ne désactive rien : un tour de relecture est abandonné dès que le fournisseur se
dérobe. Confondre les deux désactiverait tous les comptes du cluster à la première coupure réseau.

## Se connecter avec kubectl

Le plugin n'a plus de mot de passe à présenter. Il ouvre un port sur la boucle locale, affiche une
adresse, et attend le retour du navigateur :

```
$ kubectl get pods
kdt-identity : ouverture de session dans le navigateur.
Si rien ne s'ouvre, ouvrez cette adresse :

  https://identity.example.com/authorize?client_id=kdt-identity-cli&…
```

L'adresse est affichée même quand le navigateur s'ouvre : sur une session distante, il n'y a rien
à ouvrir, et c'est alors le seul moyen de continuer — depuis un poste qui peut joindre ce port.

Le portail montre ensuite la même page d'accord que pour kdt-web, et ce qui en sort est une
session ordinaire : elle se voit dans la colonne SESS de kdt et se ferme par `revoke`.

Ce chemin existe dans les trois modes : `kubectl kdt-identity credential --browser` l'utilise
aussi en `local` et en `ldap`, pour qui préfère son navigateur au terminal.

## Ce que le portail vérifie sur un jeton

L'émetteur, l'audience, l'expiration — avec soixante secondes de tolérance d'horloge — et le
`nonce`. Ce sont les quatre qui disent que *ce* jeton a été émis pour *cette* connexion.

La signature n'est pas vérifiée, et le JWKS du fournisseur n'est jamais lu. Ce n'est pas un
raccourci : le jeton n'arrive pas par le navigateur mais par un échange direct avec le point
d'accès du fournisseur, sur une connexion TLS dont le certificat est validé, et cet échange
présente le `code_verifier` que seul le portail détient. OpenID Connect Core §3.1.3.7 autorise
explicitement à s'en remettre au TLS dans ce cas précis.

## Diagnostiquer

| Symptôme | Cause habituelle |
|---|---|
| `helm upgrade` refuse : *une racine en https est exigée* | `oidcAuth.issuer` ou `portalUrl` en clair |
| Le pod refuse de démarrer sur `KDT_IDENTITY_REFRESH_TTL` | plus de 24 h sans `graph.enabled` |
| Le pod refuse de démarrer sur `SUBJECT_CLAIM` | `graph.enabled` sans `claims.subject: oid` |
| *le fournisseur se nomme X alors que Y est configuré* | `issuer` ne correspond pas à ce qu'annonce la découverte — chez Entra ID, le tenant doit être son identifiant, pas `common` |
| *Cette tentative de connexion a expiré* | plus de dix minutes chez le fournisseur, ou cookie perdu |
| Connexion refusée, journal : *le jeton ne porte pas de claim …* | le claim n'est pas émis par l'application |
| Connexion refusée, journal : *n'a pas transmis le claim groups* | groupes déportés, et pas d'accès à l'API déclaré |
| Connexion réussie mais aucun droit | la table `groupMappings` ne cite aucun groupe de cette personne |
| *un compte nommé X existe déjà et n'est pas gouverné par cette source* | un compte local — ou LDAP — porte déjà ce nom |
| Relecture inerte, journal : *Graph refuse l'accès* | permission d'application non consentie par un administrateur |

Les comptes gouvernés par le fournisseur se listent par leur label :

```sh
kubectl get kdtusers -l identity.kdt.sh/source=oidc
```
