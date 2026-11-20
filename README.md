# Tocsin

Tocsin est un standard ouvert, en cours de rédaction, pour que les défenseurs réagissent aux failles de sécurité **à vitesse machine**.

Chaque logiciel déclare, dès son installation, le canal où son éditeur publie ses alertes. Un agent local s'y abonne, sait quel service utilise quel composant, et réagit selon une politique fixée par l'administrateur : avertir, proposer une parade ou l'appliquer automatiquement.

> État : brouillon v0.1 de la spécification et premier prototype de l'agent. Rien n'est stable.

## Contenu du dépôt

| Chemin | Contenu |
| --- | --- |
| [`spec/tocsin-v0.1.fr.md`](spec/tocsin-v0.1.fr.md) | Spécification v0.1 (brouillon, en français) |
| [`examples/`](examples/) | Exemples de déclaration, d'avis et de politique, validés par les tests |
| [`crates/tocsin-core`](crates/tocsin-core) | Bibliothèque Rust : formats de la spécification (déclaration, avis OSV avec l'extension Tocsin, purl, priorité effective, politique) |
| [`crates/tocsin-inventory`](crates/tocsin-inventory) | Bibliothèque Rust : inventaire d'une machine Linux (composants, services, ports en écoute) |
| [`crates/tocsin-sources`](crates/tocsin-sources) | Bibliothèque Rust : sources de repli, OSV.dev et catalogue KEV de la CISA |
| [`crates/tocsin-agent`](crates/tocsin-agent) | Binaire `tocsin` : prototype de l'agent |

## Essayer le prototype

Prérequis : Rust 1.88 ou plus récent ([rustup](https://rustup.rs)).

```sh
cargo test --workspace

# Valider les formats
cargo run -q -- validate declaration examples/declaration.json
cargo run -q -- validate advisory examples/advisory.json
cargo run -q -- validate policy examples/policy.toml

# Évaluer un avis pour un composant installé, exposé à Internet, avis signé
cargo run -q -- check --advisory examples/advisory.json \
  --purl pkg:npm/example-widget@2.3.1 --policy examples/policy.toml --internet --signed

# Inventorier la machine (en root pour un résultat complet)
cargo run -q -- inventory --project /srv/mon-app
cargo run -q -- inventory --format cyclonedx > inventaire.cdx.json
```

L'inventaire est en lecture seule et ne demande aucun service extérieur. Il relève :

- les **composants** : paquets dpkg et rpm, dépendances listées par les fichiers de verrouillage (`package-lock.json`, `npm-shrinkwrap.json`, `Cargo.lock`, `poetry.lock`) des projets désignés avec `--project`, et les déclarations Tocsin trouvées (`/usr/share/tocsin/*.json`, champ `tocsin` des `package.json`) ;
- les **services** : processus regroupés par unité systemd ou par conteneur ;
- le **lien composant → service**, avec sa preuve : exécutable, bibliothèque chargée en mémoire, ou répertoire de travail dans un projet désigné ;
- les **ports en écoute** et leur exposition (boucle locale, réseau local, toutes interfaces, adresse publique), dans chaque espace de noms réseau, conteneurs compris ;
- les **redémarrages nécessaires** : un service qui exécute encore une bibliothèque remplacée sur le disque par une mise à jour reste vulnérable tant qu'il n'est pas redémarré.

### Croiser l'inventaire avec les failles connues

```sh
cargo run -q -- scan --project /srv/mon-app                 # constats de priorité high et plus
cargo run -q -- scan --min-priority low --format json       # tout, en JSON
cargo run -q -- scan --policy examples/policy.toml          # décisions selon une politique
```

`tocsin scan` inventorie la machine, interroge [OSV.dev](https://osv.dev) puis le [catalogue KEV de la CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), et produit pour chaque faille : le paquet et sa version, les composants installés concernés, la version corrigée, les services qui l'utilisent avec leur exposition, la priorité effective (section 9.2 de la spécification) et la décision de la politique.

- Les paquets de distribution sont interrogés par **paquet source** et pour la **release exacte** (`Ubuntu:26.04:LTS`, `Debian:12`…), comme les distributions publient leurs avis ; les dépendances applicatives, par purl.
- La gravité vient du classement de la distribution ou de GitHub, sinon du score CVSS 3 calculé à partir du vecteur.
- Une faille listée par le catalogue KEV passe en `critical`, quel que soit son classement d'origine.
- Les bulletins qui regroupent plusieurs CVE (USN…) sont fusionnés avec les fiches par CVE.
- Les avis et le catalogue sont mis en cache dans `~/.cache/tocsin` (catalogue KEV : 24 h).
- **Confidentialité** : la requête à OSV.dev envoie les noms et versions des paquets. Le catalogue KEV, lui, est téléchargé en entier : rien ne sort de la machine pour cette partie. Un mode hors ligne, à partir des exports complets d'OSV, est prévu.
- Les sources de repli ne sont jamais signées par l'éditeur : comme le veut la section 11 de la spécification, elles ne déclenchent jamais d'atténuation automatique.

Limites actuelles : le contenu des conteneurs, Flatpak et Snap n'est pas encore inventorié (ces services sont signalés, sans leur attribuer à tort les paquets de l'hôte) ; sans droits root, les processus des autres utilisateurs ne sont que partiellement inspectés.

Ce que fait déjà le prototype :

- lecture des déclarations dans `package.json`, `tocsin.json`, `Cargo.toml` et `pyproject.toml`, avec les règles de la section 5 (HTTPS obligatoire, champs inconnus refusés) ;
- lecture des avis OSV et de l'extension `tocsin`, comparaison des plages de versions SEMVER ;
- calcul de la priorité effective (section 9.2) ;
- application de la politique (section 9.3), avec un garde-fou : un avis non signé n'est jamais atténué automatiquement.

Pas encore fait : vérification des signatures Sigstore, registre persistant, contenu des conteneurs, connexion aux relais, score EPSS, mode hors ligne pour OSV, adaptateurs d'atténuation. Voir la feuille de route (section 12.2 de la spécification).

## Licences

- Code : [Apache-2.0](LICENSE-APACHE)
- Spécification : [CC-BY-4.0](spec/LICENSE)
