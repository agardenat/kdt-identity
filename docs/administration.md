# Administration

Il n'y a pas d'interface d'administration, et c'est délibéré : le portail n'expose que
l'activation, la connexion et le téléchargement du kubeconfig. Tout ce qui relève de
l'administration — comptes, groupes, droits — est un objet Kubernetes, donc versionnable et
réconciliable comme le reste du cluster.

Ce document décrit les opérations courantes. Pour l'invitation et son modèle de menace, la
révocation et l'installation, voir le [README](../README.md).

## Cycle de vie d'un compte

### Créer

```console
$ kubectl apply -f - <<'YAML'
apiVersion: identity.kdt.sh/v1alpha1
kind: KdtUser
metadata: {name: alice}
spec: {email: alice@example.com}
YAML
```

Le nom est celui qui apparaîtra à l'apiserver, préfixé : `alice` devient l'utilisateur
`kdt:alice`. Il est limité à 60 caractères et aux caractères `[a-z0-9]`, `-` et `.` — un
`ValidatingAdmissionPolicy` posé par le chart refuse le reste, ainsi que les préfixes réservés
`system:`, `kubernetes:` et `kdt:`.

Un compte fraîchement créé est en phase `Pending` : il existe, il n'a pas de mot de passe, et
il ne peut rien obtenir tant qu'il n'a pas été invité puis activé.

### Inviter

```console
$ kubectl -n <namespace> exec deploy/<release>-controller -- \
      /usr/local/bin/kdt-identity-server invite alice
```

Le chemin est absolu parce que l'image ne contient ni shell ni `PATH`. Il n'y a rien à
installer sur le poste de l'administrateur : la commande s'exécute dans le pod déjà déployé.
Pour le binaire client, destiné aux utilisateurs, voir
[Obtenir les binaires](../README.md#obtenir-les-binaires).

Le lien et le code ne s'affichent qu'une fois : ils ne sont ni journalisés, ni écrits dans le
statut.

Relancer `invite` sur un compte déjà actif réémet une invitation et efface le mot de passe
précédent — c'est aussi le chemin de réinitialisation.

### Désactiver

```console
$ kubectl patch kdtuser alice --type=merge -p '{"spec":{"disabled":true}}'
```

Le compte ne peut plus se connecter au portail ni obtenir de nouveau certificat. Un certificat
déjà émis reste valide jusqu'à son expiration — au plus tard huit heures, la durée de tout ce
qu'émet le portail : Kubernetes ne consulte aucune CRL, c'est la contrepartie du modèle par
certificats. Pour une exclusion immédiate, retirer les bindings qui visent ses groupes.

`disabled` se suffit à lui-même : le contrôleur ferme les sessions ouvertes dès qu'il le voit,
donc plus aucun renouvellement n'aboutit. L'accès s'arrête quand le credential en cours expire,
soit dix minutes au plus. C'est un champ de la spec : le geste vit dans un dépôt GitOps, sans
qu'aucun shell ne soit ouvert dans un pod.

### Fermer les sessions sans désactiver le compte

Pour un poste perdu ou volé, la personne reste habilitée et doit continuer à travailler
ailleurs :

```console
$ kubectl -n kdt-identity exec deploy/kdt-identity-controller -- \
    /usr/local/bin/kdt-identity-server revoke alice
alice : 2 sessions fermées
L'accès s'arrête au prochain renouvellement, dans 10 min au plus.
Le compte reste actif : il peut rouvrir une session.
```

Le poste perdu ne renouvelle plus rien ; sa propriétaire se reconnecte depuis un autre, avec
son mot de passe et son code — que le voleur n'a pas.

| Situation | Geste | Effet |
|---|---|---|
| Poste perdu ou volé | `revoke alice` | sessions fermées, la personne se reconnecte |
| Départ, compte compromis | `spec.disabled: true` | portail bloqué, sessions fermées, plus aucun renouvellement |

Une réserve dans les deux cas : un kubeconfig téléchargé depuis le portail échappe à tout cela.
Il est autoportant, personne ne le renouvelle, et il reste valable jusqu'à son expiration —
huit heures par défaut. Quand la révocation doit être sans exception, fermer ce chemin :
`portal.kubeconfigDownload: false`.

### Supprimer

```console
$ kubectl delete kdtuser alice
```

Les credentials sont rangés dans un Secret propre à l'utilisateur, détruit avec lui. Le nom
reste listé dans les `members` des groupes qui le mentionnaient : l'y retirer aussi, sans quoi
le contrôleur avertira à chaque réconciliation.

## Groupes

Un groupe porte la liste de ses membres ; un utilisateur ne déclare jamais ses groupes. Le
champ `groups` affiché par `kubectl get kdtuser` est un statut calculé par le contrôleur, pas
une entrée.

### Ajouter un membre

```console
$ kubectl patch kdtgroup ops --type=json \
      -p '[{"op":"add","path":"/spec/members/-","value":"alice"}]'
```

Utiliser `--type=json`. Un `--type=merge` remplace le tableau entier, ce qui impose de
réécrire la liste complète des membres — et efface les autres si on l'oublie.

### Retirer un membre

```console
$ kubectl patch kdtgroup ops --type=json \
      -p '[{"op":"remove","path":"/spec/members/0"}]'
```

L'index est celui du membre dans `spec.members`. Le changement prend effet à la prochaine
émission de certificat, pas sur les certificats déjà remis.

### Vérifier

```console
$ kubectl get kdtgroup ops -o jsonpath='{.status.resolvedMembers}'
$ kubectl get kdtgroup -o custom-columns=NOM:.metadata.name,SUJET:.status.subject
```

`resolvedMembers` ne retient que les membres qui existent réellement comme `KdtUser`. Un nom
listé sans compte correspondant n'est pas bloquant : il est ignoré, et journalisé en
avertissement à chaque réconciliation.

## Des groupes aux droits

C'est l'étape que rien ne fait à votre place. kdt-identity **authentifie** : il émet un
certificat dont le `CN` devient l'utilisateur et chaque `O` un groupe. Il n'**autorise** rien.

Un groupe n'ouvre aucun droit par lui-même : tant qu'aucun binding ne le nomme, une identité
émise ne dispose que de ce que possède tout compte authentifié — les self-reviews et la
découverte d'API. C'est vérifiable avant même d'émettre le moindre certificat :

```console
$ kubectl auth can-i --list --as=kdt:alice --as-group=kdt:ops
```

Les droits se donnent avec les ClusterRoles intégrés de Kubernetes, présents sur tout cluster :

| Rôle | Ce qu'il donne |
| --- | --- |
| `view` | lecture seule, sans les Secrets |
| `edit` | lecture/écriture sur les ressources courantes, ni Roles ni RoleBindings |
| `admin` | `edit`, plus la gestion des Roles et RoleBindings du namespace |
| `cluster-admin` | tout, partout, RBAC compris |

Le binding se pose sur le **groupe**, jamais sur l'utilisateur : ajouter quelqu'un aux
`members` suffit alors à lui transmettre les droits, sans retoucher à RBAC.

```console
$ kubectl create rolebinding kdt-ops-edit \
      -n <namespace> --clusterrole=edit --group=kdt:ops
```

Un `RoleBinding` qui référence un `ClusterRole` est la forme la plus utile : le rôle intégré
est réutilisé, mais ne s'applique que dans le namespace du binding. `ClusterRoleBinding` ne
sert que lorsque le groupe doit agir sur tout le cluster.

Le sujet à référencer est celui publié dans `status.subject` du groupe, jamais une chaîne
recopiée à la main.

Sur `cluster-admin` : le lier à un groupe signifie qu'un `kubectl patch` sur les `members`
suffit à faire de quelqu'un un administrateur complet, sans passer par RBAC. C'est l'intérêt
du système, et la raison de garder ce groupe-là court — et ses membres sous revue.

## Dépannage

**« L'émission du certificat a échoué » sur le portail.** L'authentification a réussi, c'est
l'approbation de la `CertificateSigningRequest` qui a été refusée. Regarder les logs du
portail, qui portent l'erreur exacte de l'apiserver. Vérifier les droits effectifs du
ServiceAccount :

```console
$ kubectl auth can-i --list --as=system:serviceaccount:<namespace>:<release> \
      | grep certificatesigningrequests
```

`certificatesigningrequests/approval` doit accorder `update` **et** `patch`, et `signers` doit
accorder `approve` sur `kubernetes.io/kube-apiserver-client`.

**Le contrôleur ne réconcilie rien et ne journalise rien.** Il n'a pas de log de démarrage : il
ne parle qu'en cas de changement de statut, donc un contrôleur muet ressemble à un contrôleur
au repos. Créer un `KdtUser` de test est le moyen le plus rapide de trancher — si son statut
reste vide, le contrôleur n'atteint pas l'apiserver. Sous Cilium, la cause habituelle est la
NetworkPolicy : voir `networkPolicy.cilium` dans les valeurs du chart.

**Le portail est injoignable derrière l'ingress.** La NetworkPolicy n'autorise par défaut que
le trafic du même namespace. Renseigner `networkPolicy.ingressFrom` avec le sélecteur des pods
du contrôleur d'ingress.

**Un compte authentifié reçoit des 403 partout.** Aucun binding ne vise ses groupes. Voir
[Des groupes aux droits](#des-groupes-aux-droits).
