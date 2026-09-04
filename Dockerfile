# Les images sont pleinement qualifiées : un nom court dépend du registre configuré sur la
# machine qui construit, ce qui est à la fois non reproductible et une porte ouverte au
# typosquattage.
#
# Image de kdt-identity : le serveur, le contrôleur et le portail dans un binaire unique.
#
# La cible est statique (musl) et l'image finale ne contient rien d'autre que le binaire et un
# jeu de certificats racines. Un composant capable de forger n'importe quelle identité du
# cluster n'a pas besoin d'un shell, d'un gestionnaire de paquets ni d'une libc : ce qui n'est
# pas là ne peut pas servir à quelqu'un qui obtiendrait l'exécution de code dans le conteneur.

FROM docker.io/library/rust:1.95-alpine AS build

RUN apk add --no-cache musl-dev

WORKDIR /src

# Les manifestes seuls d'abord : tant qu'ils ne changent pas, la couche des dépendances est
# réutilisée et la compilation ne repart pas de zéro à chaque modification du code.
COPY Cargo.toml Cargo.lock ./
COPY crates/api/Cargo.toml crates/api/
COPY crates/server/Cargo.toml crates/server/
COPY crates/cli/Cargo.toml crates/cli/
RUN mkdir -p crates/api/src crates/server/src crates/cli/src \
    && echo 'fn main() {}' > crates/server/src/main.rs \
    && echo 'fn main() {}' > crates/cli/src/main.rs \
    && touch crates/api/src/lib.rs crates/server/src/lib.rs \
    && cargo build --release --locked \
    && rm -rf crates/*/src

COPY crates crates
# Sans ce `touch`, cargo garde les artefacts des souches ci-dessus : leurs horodatages sont
# plus récents que ceux des sources qu'on vient de copier.
RUN touch crates/*/src/*.rs && cargo build --release --locked

FROM scratch

# Rattache l'image à son dépôt. GitHub lit ce label au push pour lier le package au dépôt : la
# page du package y gagne le README et le lien vers les sources, et les droits d'accès suivent
# ceux du dépôt. Sans lui, le package reste un objet isolé dont la visibilité se règle à la main.
LABEL org.opencontainers.image.source=https://github.com/agardenat/kdt-identity
LABEL org.opencontainers.image.licenses=Apache-2.0
LABEL org.opencontainers.image.description="Utilisateurs et groupes locaux pour Kubernetes, avec portail d'activation et émission de kubeconfig"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /src/target/release/kdt-identity-server /usr/local/bin/
COPY --from=build /src/target/release/kdt-identity /usr/local/bin/

# Correspond au `runAsUser` du chart. Déclaré ici aussi pour que l'image ne tourne pas en root
# même lancée sans contexte de sécurité.
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/kdt-identity-server"]
CMD ["--help"]
