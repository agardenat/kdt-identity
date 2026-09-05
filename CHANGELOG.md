# Journal des modifications

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), et le projet respecte
le [versionnage sémantique](https://semver.org/lang/fr/).

Chaque version publiée est accompagnée de notes de version reprenant la section correspondante.

## [Non publié]

### Ajouté

- Installation depuis un fichier de valeurs, pour une chaîne d'intégration : `helm-values.yaml`
  d'exemple, `upgrade --install` idempotent, clone épinglé sur un tag. Avec l'avertissement qui
  va avec — `lookup` ne rend rien quand le chart est rendu hors du cluster (`helm template`,
  Argo CD par défaut), donc la clé de session y est régénérée à chaque synchronisation et toutes
  les sessions tombent : la fixer explicitement dans ce cas.

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
