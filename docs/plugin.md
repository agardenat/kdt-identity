# Le plugin `kdt-identity`

C'est le binaire installé sur les postes de travail. `kubectl` l'appelle quand il a besoin d'un
accès, il l'obtient auprès du portail, le met en cache, et le renouvelle tout seul.

Deux propriétés en découlent, et ce sont les raisons de préférer ce chemin au téléchargement
d'un kubeconfig depuis le portail :

- **La clé privée ne quitte jamais le poste.** Elle est engendrée localement, seule la demande
  de signature part sur le réseau. Un kubeconfig téléchargé, lui, contient une clé produite par
  le serveur, qui a donc traversé le réseau.
- **L'accès devient révocable.** Le plugin renouvelle contre un droit de session conservé dans
  le cluster ; retirer ce droit coupe l'accès au renouvellement suivant. Un fichier téléchargé
  ne se renouvelle pas, donc rien ne peut le couper avant son échéance.

## Installation

Il n'y a pas encore de paquets `deb`, `rpm` ni de formule Homebrew. Deux façons de l'obtenir.

Depuis l'image, où il est lié statiquement et ne dépend d'aucune libc :

```sh
c=$(podman create ghcr.io/agardenat/kdt-identity:1.0.0)
podman cp $c:/usr/local/bin/kdt-identity ~/.local/bin/kdt-identity
podman rm $c
```

Depuis les sources, avec une chaîne Rust :

```sh
cargo install --git https://github.com/agardenat/kdt-identity kdt-identity-cli
```

Dans les deux cas, le binaire doit se trouver dans le `PATH` : le kubeconfig produit déclare
`command: kdt-identity`, sans chemin, et c'est `kubectl` qui l'exécutera.

## Écrire son kubeconfig

```sh
kdt-identity kubeconfig \
    --portal https://identity.example.com \
    --user alice \
    --cluster production \
    --server https://k8s.example.com:6443 \
    --ca-file ca.crt > ~/.kube/config
```

Le fichier produit **ne contient aucun secret** : il dit seulement à `kubectl` d'appeler
`kdt-identity` quand il a besoin d'un credential. Il peut être versionné, envoyé par courriel,
recopié — il n'ouvre rien à lui seul.

Ni `proxy-url`, ni bastion : atteindre l'apiserver est une propriété du poste, pas du cluster.
Qui passe par un tunnel le sait et l'ajoute de son côté.

Le même kubeconfig fonctionne dans les deux modes du serveur. Le plugin découvre à l'ouverture
de session ce que le cluster délivre — un certificat ou un jeton — et s'y conforme.

## Le cycle de vie d'un accès

```console
$ kubectl get pods
Authentification kdt-identity — alice sur https://identity.example.com
Mot de passe :
Code à 6 chiffres : 123456
NAME   READY   STATUS
…

$ kubectl get pods        # plus aucune saisie, pendant sept jours
```

Deux durées, qui ne mesurent pas la même chose :

| | Durée | Ce qu'elle borne |
|---|---|---|
| Le credential | 10 min (5 en mode OIDC) | le délai entre une révocation et sa prise d'effet |
| Le droit de session | 7 jours | la patience demandée à l'utilisateur |

Toutes les dix minutes, le plugin redemande un credential en présentant son droit de session.
L'échange est silencieux : rien ne s'affiche, aucune saisie. À chaque passage, **le portail
relit l'état du compte et ses groupes depuis le cluster** — c'est là qu'une désactivation prend
effet, et qu'un changement d'appartenance arrive.

Au bout de sept jours, ou si quelqu'un a fermé la session, l'invite revient.

**Le portail web n'intervient jamais dans ce cycle.** Le plugin l'appelle en HTTP, mais la
saisie se fait dans le terminal. Le navigateur ne sert qu'une fois, à l'activation du compte.

## Se déconnecter

```sh
kdt-identity logout --portal https://identity.example.com --user alice
```

Efface le cache local **et** ferme la session côté serveur. Les deux comptent, et pas
également : effacer le fichier empêche ce poste de s'en resservir, fermer la session empêche
quiconque en aurait copié le contenu de continuer.

Si le portail est injoignable, le cache est effacé quand même et un avertissement le signale —
laisser un credential utilisable sur le poste parce que le serveur ne répond pas serait le pire
des deux mondes.

## Là où le plugin ne convient pas

**Sans terminal, le renouvellement échoue.** La saisie passe par `/dev/tty`, jamais par
l'entrée standard, qui appartient à la commande en cours : lire dessus capterait ce qui était
destiné à `kubectl`, ou bloquerait indéfiniment. Un `kubectl` lancé par un script, ou dans un
conteneur sans tty, reçoit donc une erreur explicite plutôt qu'une attente sans fin.

C'est un outil de poste de travail. Une chaîne d'intégration s'authentifie par ServiceAccount,
pas avec le compte de quelqu'un.

## Le cache

Les credentials sont rangés dans `~/.kube/cache/kdt-identity/`, ou sous `$KUBECACHEDIR` si la
variable est définie. Le fichier est écrit en 0600 dans un répertoire en 0700 : il contient une
clé privée et un droit de session.

Le nom du fichier dérive du portail **et** du compte : deux clusters, ou deux identités sur le
même cluster, ne se marchent pas dessus. Un cache illisible n'est pas une erreur — il est
remplacé, au prix d'une authentification.

## Dépannage

| Message | Ce qu'il signifie |
|---|---|
| `renouvellement refusé (compte, mot de passe, code ou session invalide)` | la session a été fermée, ou le compte désactivé. Une authentification complète suit. |
| `renouvellement refusé (ce cluster n'émet plus de jetons)` | le déploiement a changé de mode. Le plugin se ré-authentifie et s'adapte. |
| `authentification nécessaire … mais aucun terminal n'est disponible` | `kubectl` a été lancé sans tty. Rejouer la commande dans un terminal. |
| `le portail a répondu pour X alors que Y était demandé` | à ne pas ignorer : le portail désigne une autre identité que celle demandée. Le plugin refuse de construire une demande dessus. |
| `failed to find any PEM data` (côté kubectl) | version de plugin et de portail désaccordées. Réinstaller le binaire depuis l'image du déploiement. |

## Pourquoi deux appels HTTP

Le sujet d'un certificat X.509 — nom d'utilisateur et groupes — est fixé dans la demande de
signature, elle-même signée par la clé du client. Le portail ne peut donc pas compléter un
sujet incomplet : il ne peut que l'accepter ou le refuser. Le plugin doit connaître ses groupes
**avant** de signer.

Il ne peut pas non plus s'authentifier deux fois pour les apprendre : un code TOTP ne sert
qu'une fois. D'où l'échange en deux temps — le premier appel authentifie et rend l'identité
effective avec un jeton valable une minute, le second fait signer.

Le portail relit les groupes depuis le cluster **au moment d'émettre**, jamais depuis ce que le
premier appel avait annoncé. Un groupe retiré entre les deux fait échouer l'émission plutôt que
de se glisser dans un credential.
