# Journal des modifications

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), et le projet respecte
le [versionnage sémantique](https://semver.org/lang/fr/).

Chaque version publiée est accompagnée de notes de version reprenant la section correspondante.

## [Non publié]

## [1.0.0] - 2026-09-05

Première version stable. Ce qui manquait à la 0.1 pour être utilisable en production tenait en
un mot : la révocation. Un accès émis y valait jusqu'à son expiration, sans recours, et un
changement de groupe mettait huit heures à se propager. C'est réglé, sans rien demander au
control plane.

Les deux modes de délivrance ont été éprouvés contre un apiserver réel, et la compatibilité
annoncée est celle qui a été constatée — pas celle qui paraissait probable.

Les CRD restent en `v1alpha1` : la version du produit ne préjuge pas de la stabilité du schéma,
qui évoluera encore.

### Ajouté

- **La révocation.** Le plugin obtient des certificats de dix minutes qu'il renouvelle tout
  seul, contre un droit de session valable sept jours conservé dans le cluster. Retirer ce
  droit coupe l'accès au renouvellement suivant.

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

- **Mode OIDC**, au choix du déploiement : `credentialMode: oidc` remplace les certificats
  X.509 par des jetons signés que l'apiserver valide. Révocation, renouvellement silencieux et
  identité produite sont identiques au mode certificat.

  Il sert à trois choses : aux clusters qui ne signent pas de certificat client — EKS —, à
  l'audit, puisque chaque jeton porte un `jti` unique visible dans les journaux de l'apiserver,
  et à une granularité de cinq minutes au lieu de dix. Son prix est la portabilité : il exige
  de configurer l'apiserver, ce qu'AKS ne permet pas pour un émetteur tiers.

  Vérifié de bout en bout sur k3s 1.35 : découverte et JWKS lus par l'apiserver, identité
  `kdt:…` et groupes reconnus, `jti` dans l'audit, renouvellement par le plugin, retrait d'un
  groupe pris en compte au renouvellement suivant, révocation effective. Voir `docs/oidc.md`.

- **Les durées se règlent** dans les valeurs du chart : `certTtl` (10 min) pour les certificats
  remis au plugin, `refreshTtl` (7 j) pour le droit de session, `portal.downloadCertTtl` (8 h)
  pour le kubeconfig téléchargé, `oidc.tokenTtl` (5 min) pour les jetons. La durée des
  certificats était jusqu'ici fixée à la compilation, sans que rien ne le dise.

- Toute émission avertit quand le signeur du cluster a raccourci la durée demandée. Le
  kube-controller-manager plafonne à `--cluster-signing-duration`, 24 h par défaut, sans rien
  signaler : la demande est signée, simplement plus courte.

- Installation depuis un fichier de valeurs, pour une chaîne d'intégration : `helm-values.yaml`
  d'exemple, `upgrade --install` idempotent, clone épinglé sur un tag. Avec l'avertissement qui
  va avec — `lookup` ne rend rien quand le chart est rendu hors du cluster (`helm template`,
  Argo CD par défaut), donc la clé de session y est régénérée à chaque synchronisation et
  toutes les sessions tombent : la fixer explicitement dans ce cas.

### Modifié

- **Les certificats durent dix minutes au lieu de huit heures.** C'est ce qui rend la
  révocation utile ; le renouvellement silencieux rend cette brièveté invisible.
- La page « Mon accès » propose le plugin en premier, et présente le téléchargement pour ce
  qu'il est : un accès qui ne peut pas être révoqué.
- **Documentation restructurée** : `docs/modes.md` pour choisir un mode et vérifier la
  compatibilité de son cluster, `docs/plugin.md` pour les postes de travail. Le README renvoie
  vers l'un et l'autre au lieu de tout porter.

### Corrigé

- **Le README promettait une compatibilité qui n'était pas vérifiée.** « Ça marche partout, y
  compris sur AKS, EKS, GKE et OpenShift » était une hypothèse : le signeur
  `kubernetes.io/kube-apiserver-client` dépend du `csrsigning` du kube-controller-manager, que
  personne ne maîtrise sur un control plane managé. EKS ne le sert pas et refuse l'usage
  `client auth` ; AKS le sert, vérifié sur 1.34. La documentation distingue désormais ce qui
  est constaté de ce qui ne l'est pas, et donne la commande pour trancher soi-même.
- **La documentation du plugin laissait croire à une authentification unique.** Elle disait
  « les commandes suivantes ne demandent rien » sans préciser que l'invite revenait à chaque
  expiration. On pouvait en déduire qu'il fallait repasser par le portail web, alors que la
  saisie se fait dans le terminal.
- Le bloc de commande de la page « Mon accès » était illisible en thème sombre : une variable
  CSS non définie retombait sur un fond clair, sous un texte clair. Un test relit désormais le
  rendu de chaque page et refuse toute variable employée sans être définie.
- Les notes d'installation du chart annonçaient la réserve sur le kubeconfig téléchargeable
  même en mode OIDC, où ce chemin n'existe pas.

### Retiré

- **`KdtUser.spec.certTtl`**, qui était accepté et ignoré : aucun chemin d'émission ne le
  lisait, alors que sa documentation promettait un réglage par utilisateur. La durée se règle
  désormais globalement, par `certTtl` dans les valeurs du chart.

## [0.1.1] - 2026-09-05

### Corrigé

- **Le chart ne fonctionnait pas sous Cilium.** La règle d'egress de la `NetworkPolicy` vise
  l'apiserver par son CIDR, or Cilium range le trafic vers un nœud sous les entités `host` et
  `remote-node`, hors de portée d'un `ipBlock` tant que `policy-cidr-match-mode=nodes` n'est pas
  posé — ce qui n'est pas le défaut. Le contrôleur démarrait, n'atteignait jamais l'apiserver et
  ne réconciliait rien, sans rien journaliser. Nouveau `networkPolicy.cilium`, qui ajoute une
  `CiliumNetworkPolicy` autorisant la seule entité `kube-apiserver`.
- **L'émission de certificat échouait avec un RBAC conforme au chart.** Le `ClusterRole`
  n'accordait qu'`update` sur `certificatesigningrequests/approval`, alors que l'émetteur
  approuve la demande par un `PATCH`. Tout le parcours réussissait — invitation, activation,
  connexion, résolution des groupes — pour échouer au téléchargement du kubeconfig. Le verbe
  `patch` est désormais accordé.

### Ajouté

- Guide d'[administration](docs/administration.md) : cycle de vie des comptes, appartenance aux
  groupes, passage des groupes aux droits RBAC, et dépannage.
- Section « Obtenir les binaires » du README : où vit chacun des deux binaires, comment extraire
  le client de l'image ou le compiler, et pourquoi il doit être dans le `PATH`.
- L'installation part désormais du dépôt public plutôt que d'une copie locale supposée : le
  chart s'installe après un `git clone`, et les CRDs seules s'appliquent depuis une URL.
- Labels OCI sur l'image (`source`, `licenses`, `description`), qui rattachent le package à son
  dépôt.

## [0.1.0] - 2026-08-21

Première version.

### Ajouté

- `KdtUser` et `KdtGroup`, réconciliés par un contrôleur qui n'écrit que les statuts.
- Identités par certificats clients X.509 émis via l'API `CertificateSigningRequest`
  (`CN=kdt:<utilisateur>`, un `O=kdt:<groupe>` par groupe), sans drapeau d'apiserver à changer
  ni IdP à déplacer.
- Activation par lien plus code hors bande, sans dépendance SMTP.
- Portail d'activation, de connexion et de téléchargement du kubeconfig.
- Plugin `exec` pour kubectl : la clé privée ne quitte pas le poste.
- Credentials rangés dans un Secret par utilisateur, détruit avec son `KdtUser`.
- Chart Helm et image, avec un RBAC réduit à ce qui est strictement nécessaire et un
  `ValidatingAdmissionPolicy` sur les noms.
