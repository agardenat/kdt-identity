# Changelog

Toutes les versions publiées de kdt-identity, la plus récente en premier. Chaque entrée reprend le
sujet du commit qui l'a apportée : type, portée, et ce qui change pour qui utilise l'outil.
Le versionnement suit [SemVer](https://semver.org/lang/fr/) et chaque version correspond au
tag `v<version>` qui a déclenché sa publication.

Les notes de version publiées avec un tag sont la section correspondante de ce fichier, extraite
par `packaging/changelog-section.sh` : ce fichier est la source, pas une copie.

## [1.2.0] — 2026-09-08

- **feat(server)** — **fédération d'identité sur un annuaire LDAP(S)**, Active Directory ou
  FreeIPA. `authMode: ldap` fait de l'annuaire la source des identités : le mot de passe y est
  vérifié par un bind, le `KdtUser` est créé à la première connexion réussie, et l'appartenance
  aux groupes kdt est reportée depuis les groupes de l'annuaire.

  C'est un **second axe**, indépendant du mode de délivrance. `credentialMode` dit ce que le
  portail remet, `authMode` qui il reconnaît : les quatre combinaisons sont valides, et changer
  l'un n'oblige jamais à toucher l'autre.

  La correspondance entre groupes d'annuaire et `KdtGroup` est **déclarée**, dans
  `ldap.groupMappings`. Rien n'est déduit d'un DN : le dériver demanderait de le normaliser, et
  deux groupes distincts de l'annuaire pourraient alors aboutir au même nom, donc aux mêmes
  droits. Ce qui n'est pas déclaré n'existe pas côté cluster.

  L'identifiant de connexion, lui, doit bien être normalisé pour donner un nom de ressource — et
  cette normalisation est ambiguë, `Jean_Dupont` et `jean-dupont` aboutissant au même nom. D'où
  le DN épinglé en annotation à la création du compte et revérifié à chaque connexion : une
  divergence est refusée, jamais arbitrée. Un compte local qui porte le nom visé n'est pas
  absorbé non plus.

  Le second facteur est délégué à l'annuaire : plus de TOTP enrôlé côté kdt, plus de page
  `/activate` montée, et `invite` refuse de s'exécuter. Le nouveau point d'accès
  `GET /api/v1/portal` annonce ce que le portail attend, pour que le plugin sache s'il doit
  demander un code avant de le demander — un portail plus ancien répond 404, et le plugin retombe
  sur son comportement d'avant.

  Le contrôleur relit l'annuaire toutes les quinze minutes, sans quoi un retrait de groupe
  n'aurait d'effet qu'à la prochaine saisie de mot de passe — soit jusqu'à sept jours, le
  renouvellement silencieux ne rebindant jamais. Un compte dont l'entrée a disparu passe en
  `spec.disabled`, jamais supprimé. Une panne d'annuaire, elle, n'a aucun effet : une absence de
  réponse ne dit rien, et la prendre pour une disparition désactiverait tous les comptes du
  cluster à la première coupure réseau. Pour la même raison, elle n'incrémente pas le compteur
  d'échecs.

  Deux refus au démarrage, et au rendu du chart. Un annuaire en clair : un bind simple présente
  le mot de passe dans la requête, c'est le protocole, et `ldaps://` ou StartTLS est donc exigé.
  Une table de correspondance vide : les comptes se connecteraient sans obtenir le moindre droit.

  Le chart monte l'autorité de l'annuaire — FreeIPA émet toujours depuis la sienne, AD presque
  toujours — et le serveur assemble au démarrage un magasin qui la réunit à celui de l'image :
  `ldap3` n'offre aucun moyen de recevoir une autorité pour la seule connexion à l'annuaire, et
  la variable qui reste, `SSL_CERT_FILE`, remplace le magasin natif au lieu de s'y ajouter.

  Voir [docs/ldap.md](docs/ldap.md). En `local`, le défaut, rien ne change.

- **feat(packaging)** — le plugin se distribue en `.deb` et en `.rpm`, publiés avec chaque
  release à côté du tarball. Jusqu'ici il fallait le sortir de l'image avec `podman cp` ou le
  compiler : deux gestes que personne ne fait sur un poste qu'il n'administre pas. Le binaire
  reste le même, lié statiquement, donc installable sur une distribution que le paquet ne connaît
  pas.

  Une pré-version s'épelle comme il faut de chaque côté : `1.2.0-beta.1` devient `1.2.0~beta.1`
  pour dpkg — `~` trie sous tout, la chaîne vide comprise — et `Version: 1.2.0` + `Release:
  0.beta.1` pour rpm, qui refuse un tiret. Les deux trient sous la version finale, ce qui est
  tout l'intérêt de couper une bêta.

- **change(ci)** — l'image n'est plus construite qu'en `linux/amd64`. La jambe arm64 était émulée
  par QEMU et prenait à elle seule plus d'une heure sur les quatre-vingts minutes du job, pour une
  architecture qu'aucun cluster visé n'utilise. Qui en a besoin construit l'image depuis le dépôt.

## [1.1.0] — 2026-09-07

- **feat(portal)** — **flow d'autorisation**, pour qu'une application web puisse agir au nom de
  quelqu'un sans jamais voir son mot de passe. `/authorize` reconnaît la session ouverte du
  portail, demande un accord, et redirige avec un code d'une minute ;
  `/api/v1/authorize/token` l'échange contre un droit de session, contre preuve PKCE (`S256`
  seul, `plain` refusé).

  Ce que l'application obtient est une session ordinaire : elle compte dans les sessions du
  compte, `revoke` la ferme et `spec.disabled` la coupe. Il n'y a pas deux façons de révoquer.

  L'adresse de retour est comparée en entier, jamais par préfixe — un préfixe accepterait un
  domaine voisin, et rediriger un code revient à le donner. Tant que le client et l'adresse ne
  sont pas reconnus, aucune redirection n'a lieu, pas même pour signaler l'erreur. Un code ne sert
  qu'une fois, et l'état du compte est relu à l'accord puis à l'échange : un code émis avant une
  désactivation ne vaut plus rien.

- **feat(chart)** — **`webUrl`** dans les valeurs : la racine publique de l'application autorisée,
  dont l'adresse de retour découle. Vide — le défaut — les points d'accès ne sont pas montés et la
  page du compte n'en dit rien. Renseignée, elle doit être en `https` : un code d'autorisation n'a
  pas à voyager en clair.

- **feat(portal)** — un lien vers kdt-web sur la page du compte, affiché seulement si `webUrl` est
  déclarée, sur le modèle du téléchargement de kubeconfig qui n'apparaît que s'il est ouvert.

- **change(portal)** — la page de connexion accepte un retour après authentification, restreint au
  seul flow d'autorisation : ni URL absolue, ni double barre oblique, ni caractère de contrôle.

- **refactor(api)** — l'identifiant du client autorisé et son adresse de retour passent dans le
  contrat partagé : le portail n'accepte qu'une adresse, et l'application doit servir exactement
  celle-là. Déclarées de part et d'autre, les deux constantes finiraient par diverger, et le refus
  qui s'ensuivrait ne dirait d'où il vient ni à l'une ni à l'autre.

- **feat** — `--context` sur toutes les commandes, pour qu'aucune ne parte sur le cluster d'à côté.
  Le contexte courant n'est presque jamais celui qu'on vise, et rien ne le signale : une commande
  qui écrit sur le mauvais cluster n'est pas rattrapable. Sans effet dans un pod, où l'identité
  vient du compte de service.

## [1.0.0] — 2026-09-05

Première version stable. Ce qui manquait à la 0.1 pour être utilisable en production tenait en
un mot : la révocation. Un accès émis y valait jusqu'à son expiration, sans recours, et un
changement de groupe mettait huit heures à se propager. C'est réglé, sans rien demander au
control plane.

Les deux modes de délivrance ont été éprouvés contre un apiserver réel, et la compatibilité
annoncée est celle qui a été constatée — pas celle qui paraissait probable.

Les CRD restent en `v1alpha1` : la version du produit ne préjuge pas de la stabilité du schéma,
qui évoluera encore.

- **feat(server)** — **la révocation.** Le plugin obtient des certificats de dix minutes qu'il
  renouvelle tout seul, contre un droit de session valable sept jours conservé dans le cluster.
  Retirer ce droit coupe l'accès au renouvellement suivant.

  Deux gestes, deux intentions : `kdt-identity-server revoke alice` ferme les sessions d'un
  poste perdu — la personne reste habilitée et se reconnecte ailleurs ; `spec.disabled: true`
  coupe tout — le portail refuse la connexion et le contrôleur ferme les sessions de lui-même.
  Le second est un champ de la spec, donc utilisable depuis un dépôt GitOps, sans ouvrir de
  shell dans un pod.

  Chaque renouvellement relit l'état du compte et ses groupes depuis le cluster : une
  désactivation comme un changement d'appartenance prennent effet en dix minutes, contre huit
  heures auparavant. Les saisies de mot de passe et de code passent de toutes les huit heures à
  tous les sept jours — deux durées distinctes, l'une bornant le délai de révocation, l'autre
  la patience demandée à l'utilisateur.

  Le seul accès que cela ne couvre pas est le kubeconfig téléchargé depuis le portail :
  autoportant, il vit sa durée quoi qu'il arrive. La page le dit explicitement, et
  `portal.kubeconfigDownload: false` ferme ce chemin quand la révocation doit être sans
  exception.

- **feat(server)** — **mode OIDC**, au choix du déploiement : `credentialMode: oidc` remplace les
  certificats X.509 par des jetons signés que l'apiserver valide. Révocation, renouvellement
  silencieux et identité produite sont identiques au mode certificat.

  Il sert à trois choses : aux clusters qui ne signent pas de certificat client — EKS —, à
  l'audit, puisque chaque jeton porte un `jti` unique visible dans les journaux de l'apiserver,
  et à une granularité de cinq minutes au lieu de dix. Son prix est la portabilité : il exige
  de configurer l'apiserver, ce qu'AKS ne permet pas pour un émetteur tiers.

  Vérifié de bout en bout sur k3s 1.35 : découverte et JWKS lus par l'apiserver, identité
  `kdt:…` et groupes reconnus, `jti` dans l'audit, renouvellement par le plugin, retrait d'un
  groupe pris en compte au renouvellement suivant, révocation effective. Voir `docs/oidc.md`.

- **feat(chart)** — **les durées se règlent** dans les valeurs : `certTtl` (10 min) pour les
  certificats remis au plugin, `refreshTtl` (7 j) pour le droit de session,
  `portal.downloadCertTtl` (8 h) pour le kubeconfig téléchargé, `oidc.tokenTtl` (5 min) pour les
  jetons. La durée des certificats était jusqu'ici fixée à la compilation, sans que rien ne le
  dise.

- **feat(server)** — toute émission avertit quand le signeur du cluster a raccourci la durée
  demandée. Le kube-controller-manager plafonne à `--cluster-signing-duration`, 24 h par défaut,
  sans rien signaler : la demande est signée, simplement plus courte.

- **feat(chart)** — installation depuis un fichier de valeurs, pour une chaîne d'intégration :
  `helm-values.yaml` d'exemple, `upgrade --install` idempotent, clone épinglé sur un tag. Avec
  l'avertissement qui va avec — `lookup` ne rend rien quand le chart est rendu hors du cluster
  (`helm template`, Argo CD par défaut), donc la clé de session y est régénérée à chaque
  synchronisation et toutes les sessions tombent : la fixer explicitement dans ce cas.

- **change(server)** — **les certificats durent dix minutes au lieu de huit heures.** C'est ce qui
  rend la révocation utile ; le renouvellement silencieux rend cette brièveté invisible.

- **change(portal)** — la page « Mon accès » propose le plugin en premier, et présente le
  téléchargement pour ce qu'il est : un accès qui ne peut pas être révoqué.

- **docs** — documentation restructurée : `docs/modes.md` pour choisir un mode et vérifier la
  compatibilité de son cluster, `docs/plugin.md` pour les postes de travail. Le README renvoie
  vers l'un et l'autre au lieu de tout porter.

- **fix(docs)** — **le README promettait une compatibilité qui n'était pas vérifiée.** « Ça marche
  partout, y compris sur AKS, EKS, GKE et OpenShift » était une hypothèse : le signeur
  `kubernetes.io/kube-apiserver-client` dépend du `csrsigning` du kube-controller-manager, que
  personne ne maîtrise sur un control plane managé. EKS ne le sert pas et refuse l'usage
  `client auth` ; AKS le sert, vérifié sur 1.34. La documentation distingue désormais ce qui
  est constaté de ce qui ne l'est pas, et donne la commande pour trancher soi-même.

- **fix(docs)** — **la documentation du plugin laissait croire à une authentification unique.**
  Elle disait « les commandes suivantes ne demandent rien » sans préciser que l'invite revenait à
  chaque expiration. On pouvait en déduire qu'il fallait repasser par le portail web, alors que la
  saisie se fait dans le terminal.

- **fix(portal)** — le bloc de commande de la page « Mon accès » était illisible en thème sombre :
  une variable CSS non définie retombait sur un fond clair, sous un texte clair. Un test relit
  désormais le rendu de chaque page et refuse toute variable employée sans être définie.

- **fix(chart)** — les notes d'installation annonçaient la réserve sur le kubeconfig
  téléchargeable même en mode OIDC, où ce chemin n'existe pas.

- **remove(api)** — **`KdtUser.spec.certTtl`**, qui était accepté et ignoré : aucun chemin
  d'émission ne le lisait, alors que sa documentation promettait un réglage par utilisateur. La
  durée se règle désormais globalement, par `certTtl` dans les valeurs du chart.

## [0.1.1] — 2026-09-05

- **fix(chart)** — **le chart ne fonctionnait pas sous Cilium.** La règle d'egress de la
  `NetworkPolicy` vise l'apiserver par son CIDR, or Cilium range le trafic vers un nœud sous les
  entités `host` et `remote-node`, hors de portée d'un `ipBlock` tant que
  `policy-cidr-match-mode=nodes` n'est pas posé — ce qui n'est pas le défaut. Le contrôleur
  démarrait, n'atteignait jamais l'apiserver et ne réconciliait rien, sans rien journaliser.
  Nouveau `networkPolicy.cilium`, qui ajoute une `CiliumNetworkPolicy` autorisant la seule entité
  `kube-apiserver`.

- **fix(chart)** — **l'émission de certificat échouait avec un RBAC conforme au chart.** Le
  `ClusterRole` n'accordait qu'`update` sur `certificatesigningrequests/approval`, alors que
  l'émetteur approuve la demande par un `PATCH`. Tout le parcours réussissait — invitation,
  activation, connexion, résolution des groupes — pour échouer au téléchargement du kubeconfig.
  Le verbe `patch` est désormais accordé.

- **docs** — guide d'[administration](docs/administration.md) : cycle de vie des comptes,
  appartenance aux groupes, passage des groupes aux droits RBAC, et dépannage.

- **docs** — section « Obtenir les binaires » du README : où vit chacun des deux binaires, comment
  extraire le client de l'image ou le compiler, et pourquoi il doit être dans le `PATH`.

- **change(docs)** — l'installation part désormais du dépôt public plutôt que d'une copie locale
  supposée : le chart s'installe après un `git clone`, et les CRDs seules s'appliquent depuis une
  URL.

- **feat(image)** — labels OCI (`source`, `licenses`, `description`), qui rattachent le package à
  son dépôt.

## [0.1.0] — 2026-08-21

Première version.

- **feat(api)** — `KdtUser` et `KdtGroup`, réconciliés par un contrôleur qui n'écrit que les
  statuts.

- **feat(server)** — identités par certificats clients X.509 émis via l'API
  `CertificateSigningRequest` (`CN=kdt:<utilisateur>`, un `O=kdt:<groupe>` par groupe), sans
  drapeau d'apiserver à changer ni IdP à déplacer.

- **feat(server)** — activation par lien plus code hors bande, sans dépendance SMTP.

- **feat(portal)** — portail d'activation, de connexion et de téléchargement du kubeconfig.
