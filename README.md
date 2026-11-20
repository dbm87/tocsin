# Tocsin

Tocsin est un standard ouvert, en cours de rédaction, pour que les défenseurs réagissent aux failles de sécurité **à vitesse machine**.

Chaque logiciel déclare, dès son installation, le canal où son éditeur publie ses alertes. Un agent local s'y abonne, sait quel service utilise quel composant, et réagit selon une politique fixée par l'administrateur : avertir, proposer une parade ou l'appliquer automatiquement.

> État : brouillon v0.1 de la spécification et premier prototype de l'agent. Rien n'est stable.

## Résumé et motivation

Tocsin permet à chaque logiciel de déclarer, dès son installation, où publier ses alertes de sécurité. Un agent local s'y abonne, reçoit l'alerte en quelques secondes et réagit selon une politique fixée par l'administrateur. L'objectif est de défendre à vitesse machine, et plus à vitesse humaine.

**Le problème.** Une faille critique publiée peut désormais être exploitée en masse en quelques minutes, par des attaquants équipés d'agents IA qui lisent l'avis, écrivent l'exploit et balayent Internet. En face, la chaîne de défense reste humaine : lire une liste de diffusion, comprendre si l'on est concerné, trouver la machine, corriger.

**Ce qui manque aujourd'hui.**

- Aucun lien standard entre un logiciel installé et le canal où son éditeur publie ses alertes.
- Aucune machine ne sait, de façon lisible, quels composants elle fait tourner et quel service les utilise.
- Les avis décrivent la faille, rarement une parade applicable automatiquement.
- Les outils actuels (scanners, bases de failles) sont consultés périodiquement : l'information est tirée, pas poussée.

**Ce que Tocsin apporte.** Une couche fine au-dessus des standards existants (purl, OSV, CSAF, VEX, CycloneDX, WebSub, Sigstore) qui définit quatre choses : la déclaration du canal, le registre local, le protocole de l'agent et un format d'atténuation lisible par machine.

Le détail est dans la [spécification](spec/tocsin-v0.1.fr.md) (section 1 et suivantes).

## Contenu du dépôt

| Chemin | Contenu |
| --- | --- |
| [`spec/tocsin-v0.1.fr.md`](spec/tocsin-v0.1.fr.md) | Spécification v0.1 (brouillon, en français) |
| [`examples/`](examples/) | Exemples de déclaration, d'avis et de politique, validés par les tests |
| [`crates/tocsin-core`](crates/tocsin-core) | Bibliothèque Rust : formats de la spécification (déclaration, avis OSV avec l'extension Tocsin, purl, priorité effective, politique) |
| [`crates/tocsin-agent`](crates/tocsin-agent) | Binaire `tocsin` : prototype de l'agent |

## Essayer le prototype

Prérequis : Rust 1.85 ou plus récent ([rustup](https://rustup.rs)).

```sh
cargo test --workspace

# Valider les formats
cargo run -q -- validate declaration examples/declaration.json
cargo run -q -- validate advisory examples/advisory.json
cargo run -q -- validate policy examples/policy.toml

# Évaluer un avis pour un composant installé, exposé à Internet, avis signé
cargo run -q -- check --advisory examples/advisory.json \
  --purl pkg:npm/example-widget@2.3.1 --policy examples/policy.toml --internet --signed
```

Ce que fait déjà le prototype :

- lecture des déclarations dans `package.json`, `tocsin.json`, `Cargo.toml` et `pyproject.toml`, avec les règles de la section 5 (HTTPS obligatoire, champs inconnus refusés) ;
- lecture des avis OSV et de l'extension `tocsin`, comparaison des plages de versions SEMVER ;
- calcul de la priorité effective (section 9.2) ;
- application de la politique (section 9.3), avec un garde-fou : un avis non signé n'est jamais atténué automatiquement.

Pas encore fait : vérification des signatures Sigstore, inventaire de la machine, lien avec les services, connexion aux relais, repli OSV.dev et CISA KEV, adaptateurs d'atténuation. Voir la feuille de route (section 12.2 de la spécification).

## Licences

- Code : [Apache-2.0](LICENSE-APACHE)
- Spécification : [CC-BY-4.0](spec/LICENSE)
