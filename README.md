# Ego Sentinelle

Ego Sentinelle repère, dans le journal Sécurité de Windows, les adresses IP qui
accumulent les échecs d'ouverture de session (événement 4625). Il rend son verdict
dans la voix d'Ego, sans rien bloquer ni modifier.

Ego vient d'[*Ascendant*](https://anotherj4ck.github.io/auteur/), mon roman de science-fiction : c'est lui
qui gouverne Londinium, et rien ne lui échappe.

<!-- Capture d'écran : remplacer la ligne ci-dessous par l'image, par exemple
     ![Rapport d'Ego sur un export fictif](docs/capture.png) -->
> *Capture d'écran à venir.*

Démonstration **sur une VM de test**, dans une console PowerShell ouverte en
administrateur, à la racine du dépôt :

```powershell
# 1. Générer six échecs d'ouverture de session, avec un compte différent à chaque fois
1..6 | ForEach-Object { net use '\\127.0.0.1\IPC$' /user:"test$_" 'mauvais-mot-de-passe' }
# 2. Exporter les événements 4625 des dernières 24 heures (console administrateur obligatoire)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\export-4625.ps1 -Sortie .\echecs.csv
# 3. Analyser : Ego signale l'adresse de bouclage dans ses alertes locales (code de sortie 1)
python sentinelle.py .\echecs.csv
```

Le détail suit : [prérequis](#prérequis), [utilisation](#utilisation),
[rapport HTML](#rapport-html),
[pièges de PowerShell 5.1](#pièges-de-windows-powershell-51),
[événements de test](#générer-des-événements-4625-de-test-sur-une-vm),
[répliques](#personnaliser-les-répliques), [tests](#lancer-les-tests),
[sécurité](#sécurité).

---

## Ce que fait l'outil

Ego Sentinelle lit les échecs d'ouverture de session enregistrés dans le journal
Sécurité de Windows. Il repère les adresses IP qui s'acharnent : par défaut,
**5 échecs ou plus dans une fenêtre glissante de 10 minutes**. Il rend ensuite son
verdict sous la forme d'un court rapport, dans la voix d'Ego.

Deux outils, deux étapes :

1. `export-4625.ps1` extrait les événements 4625 du journal Sécurité vers un fichier
   CSV (`Date,Compte,IP`).
2. `sentinelle.py` analyse ce CSV et écrit le rapport :
   - les alertes venues de l'extérieur, d'abord ;
   - les alertes locales (adresses de bouclage `127.0.0.0/8` et `::1`), dans une
     section à part ;
   - le nombre de lignes inexploitables, qui sont écartées et listées à part.

L'outil ne fait que **lire et signaler**. Il ne bloque aucune adresse, ne modifie
ni le journal ni le pare-feu, et n'écrit rien d'autre que ses rapports : le rapport
texte, et sur demande un [rapport HTML](#rapport-html).

Exemple sur les données fictives de `tests/donnees/export_attaque.csv` :

```text
Analyse terminée. J'ai tout lu. Je lis toujours tout.

203.0.113.66. 6 tentatives en 1 minute 57 secondes. Comptes visés : admin, administrateur, invite, root, sauvegarde. Je l'ai noté.

::1. La menace vient de l'intérieur. 5 tentatives. Je n'oublie personne.

1 lignes illisibles. Écartées. Le désordre ne m'intéresse pas.

Fin du rapport. Retournez à vos cycles.
```

## Prérequis

- **Windows** (10, 11 ou Server), pour le journal Sécurité et ses événements 4625.
- **Windows PowerShell 5.1** (fourni avec Windows) ou **PowerShell 7**, pour l'export.
- **Python**, pour l'analyse : testé sous Python 3.14 ; syntaxe compatible 3.11.
- **Aucune dépendance à l'exécution** : `sentinelle.py` n'utilise que la
  bibliothèque standard de Python. `pytest` ne sert qu'à lancer les tests.

## Utilisation

### 1. Exporter les échecs, depuis une console administrateur

Ouvrez PowerShell avec **« Exécuter en tant qu'administrateur »**, puis :

```powershell
cd C:\chemin\vers\ego-sentinelle
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\export-4625.ps1 -Sortie .\echecs.csv
```

**Pourquoi administrateur ?**
- Le journal Sécurité n'est lisible que par les administrateurs et par les membres du
  groupe « Lecteurs des journaux d'événements ».
- Sans ces droits, `Get-WinEvent` ne signale pas de refus d'accès : il répond
  simplement « aucun événement ».
- Le script vérifie donc l'accès au préalable. Il s'arrête avec un message plutôt que
  de produire un CSV vide qui ferait croire que tout va bien.

**Remarques :**
- `-ExecutionPolicy Bypass` ne concerne que ce processus `powershell.exe`. La
  stratégie d'exécution de la machine n'est pas modifiée.
- `sentinelle.py`, lui, n'a besoin d'aucun droit particulier : lancez-le depuis une
  console ordinaire.

**Paramètres :**

| Paramètre | Rôle |
|---|---|
| `-Sortie` (obligatoire) | Fichier CSV à produire. Il est écrasé s'il existe ; le dossier doit exister. |
| `-Depuis` | Début de la période, en heure locale, au format ISO uniquement : `2026-11-01`, `2026-11-01T08:00` ou `2026-11-01T08:00:30`. Par défaut : les dernières 24 heures. |

Un format comme `03/11/2026` est refusé exprès : une conversion classique le lirait
comme le 11 mars.

**Codes de sortie de l'export :**

| Code | Signification |
|---|---|
| 0 | Export réussi, y compris s'il n'y avait aucun événement (le CSV ne contient alors que l'en-tête). |
| 1 | Accès au journal refusé, ou lecture du journal ou écriture du fichier impossible. |
| 2 | Valeur de `-Depuis` invalide. |

**Format du CSV :** UTF-8, séparateur virgule, en-tête `"Date","Compte","IP"`.
- **Date** : heure de l'événement, au format ISO 8601 avec le décalage horaire.
- **Compte** : nom de compte tenté (`TargetUserName`).
- **IP** : adresse source (`IpAddress`). Elle vaut `-` quand Windows n'en enregistre
  pas.

Le script ne filtre rien : c'est `sentinelle.py` qui écarte les lignes inexploitables.

L'aide complète est disponible avec `Get-Help .\export-4625.ps1 -Full`.

### 2. Analyser l'export

```powershell
python sentinelle.py .\echecs.csv --sortie .\rapport.txt
Get-Content -Encoding utf8 .\rapport.txt
```

Sans `--sortie`, le rapport s'affiche dans la console. Sous Windows PowerShell 5.1,
lisez la section [Pièges de Windows PowerShell 5.1](#pièges-de-windows-powershell-51)
avant de rediriger la sortie avec `>` ou `|`.

#### Options

| Option | Rôle | Défaut |
|---|---|---|
| `export` | Le CSV produit par `export-4625.ps1`. | (obligatoire) |
| `--sortie FICHIER` | Écrit le rapport dans ce fichier au lieu de la console. | console |
| `--html FICHIER` | Écrit **aussi** le rapport HTML dans ce fichier : voir [Rapport HTML](#rapport-html). | aucun |
| `--seuil N` | Nombre d'échecs, dans une même fenêtre, à partir duquel une IP est signalée. Entier de 1 à 999 999 999. | 5 |
| `--fenetre MINUTES` | Durée de la fenêtre glissante, en minutes entières, de 1 à 1440 (24 h). | 10 |
| `--modeles CHEMIN` | Fichier des répliques d'Ego. | `modeles/ego.json`, à côté du script |
| `-h`, `--help` | Affiche l'aide. | |

Les options numériques n'acceptent que des chiffres de 0 à 9 : `+5`, `1_000` ou
` 5` sont refusés.

#### Codes de sortie

| Code | Signification |
|---|---|
| 0 | Aucune alerte. |
| 1 | Au moins une alerte, externe ou locale. |
| 2 | Erreur, signalée sur stderr sans traceback. Exemples : export ou modèles introuvables ou invalides, option invalide (avec le rappel de l'usage), écriture impossible, `--sortie` ou `--html` qui écraserait un fichier protégé, `--html` et `--sortie` sur le même fichier. Les messages sont en français pour les erreurs de fichier et de valeur ; ceux d'argparse (argument manquant ou inconnu, rappel de l'usage) restent en anglais. |
| 130 | Interruption par Ctrl+C, sans message. |

Avec `| Select-Object -First N`, c'est **PowerShell** qui coupe lui-même le processus
dès qu'il a reçu assez de lignes. `$LASTEXITCODE` vaut alors **-1** : ce code vient
de PowerShell, pas de `sentinelle.py`.

Dans un script, testez le code de sortie juste après l'appel :

```powershell
python sentinelle.py .\echecs.csv --sortie .\rapport.txt
if ($LASTEXITCODE -eq 1) { Write-Warning "Ego a des choses à dire : voir rapport.txt" }
```

#### Ce qui sort, et où

- **Le rapport** va sur la sortie standard, ou dans le fichier indiqué par
  `--sortie`.
- **Les lignes rejetées** vont sur stderr, une par ligne, **avant** le rapport. Par
  exemple : `ligne 16 rejetée : IP absente : -`.
  - Au-delà de 20, seul « … et N autre(s) » est affiché.
  - Les motifs de rejet sont : ligne CSV illisible, nombre de champs incorrect, date
    illisible, date sans fuseau horaire, IP absente, IP invalide.
  - Les échecs locaux sans adresse (`-`) entrent dans le motif « IP absente ».
- **Fins de ligne :**
  - sur la sortie standard, Windows écrit des **CRLF** ;
  - avec `--sortie`, le fichier est en **UTF-8 sans BOM** avec des fins de ligne
    **LF**.

  Un rapport obtenu par redirection et un rapport écrit par `--sortie` diffèrent donc
  octet par octet, même quand leur texte est identique.
- **`--sortie` refuse d'écraser l'export analysé ou le fichier de modèles**
  (`ego.json`), même désigné par un autre chemin (`.\sous\..\echecs.csv`, une casse
  différente…). Le programme s'arrête alors avec le code 2, sans rien écrire. Tout
  autre fichier existant est écrasé sans confirmation.

## Rapport HTML

```powershell
python sentinelle.py .\echecs.csv --html .\rapport.html
```

`--html` **s'ajoute** au rapport texte, il ne le remplace pas. Le rapport texte sort
comme d'habitude, sur la console ou dans le fichier de `--sortie`, et les codes de
sortie ne changent pas. Les deux options se combinent :

```powershell
python sentinelle.py .\echecs.csv --sortie .\rapport.txt --html .\rapport.html
```

### Ce qu'il contient

Un seul fichier, à ouvrir dans un navigateur, même hors connexion :
- **l'en-tête** : nom du fichier analysé (jamais son chemin, qui contiendrait votre
  nom d'utilisateur Windows), période couverte (du plus ancien au plus récent
  événement lu), seuil et fenêtre, volume lu (échecs, adresses d'origine distinctes,
  lignes rejetées), état (`ALERTE · CODE 1` ou `SILENCE · CODE 0`) et date de
  génération ;
- **les alertes**, avec les mêmes répliques d'Ego que le rapport texte (200 au plus) ;
- **les lignes rejetées** (20 au plus) ;
- **le registre** des noms de comptes tentés (50 au plus).

La page s'adapte aux petits écrans. À l'impression, elle passe sur fond clair, sans
décor. Le décor est masqué aux lecteurs d'écran, et les animations s'arrêtent si le
système demande de réduire les mouvements.

### Garanties

Le rapport recopie des valeurs choisies par l'attaquant : il est construit pour
qu'aucune ne puisse devenir du code.
- **Aucun script** : ni balise `<script>`, ni attribut `on…`.
- **Aucune ressource externe** : ni lien, ni image, ni police, ni feuille de style à
  charger. Le style est dans le fichier, et les polices sont celles du système.
- **Une politique de sécurité du contenu (CSP)** dans la page elle-même :
  `default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'`.
  Le navigateur refuserait tout script et tout chargement, même injecté.
- **Valeurs neutralisées puis échappées** : chaque valeur venue de l'export (adresses
  IP, comptes, valeurs rejetées, nom du fichier) est d'abord neutralisée (voir
  [Sécurité](#sécurité)), puis échappée pour HTML (`<`, `>`, `&`, guillemets).
  Aucune valeur de l'export n'est placée dans un attribut.

Ces garanties sont vérifiées par `tests/test_rapport_html.py`, qui analyse la
structure du document produit.

### Écriture du fichier

- Le fichier est en **UTF-8 sans BOM**.
- **Mêmes protections que `--sortie`** : `--html` refuse d'écraser l'export ou le
  fichier de modèles, même désignés par un autre chemin. Il refuse aussi de viser le
  même fichier que `--sortie`, même écrit autrement (`.\sous\..\rapport.html` ;
  sous Windows, une casse différente ou un point final). Le programme s'arrête alors
  avec le code 2, sans rien écrire.
- **Tout autre fichier existant est écrasé sans confirmation**, comme avec
  `--sortie`.
- Si la lecture, la détection ou l'encodage échoue, **aucun fichier n'est écrit**,
  même partiellement.
- Limite connue : le rapport HTML est écrit en premier, et si l'écriture de
  `--sortie` échoue ensuite (disque plein, accès refusé), il reste sur le disque
  alors que le programme sort avec le code 2.

> **Un rapport tiré d'un export réel ne se publie pas.** Il contient des adresses IP
> et des noms de comptes réels, parfois un mot de passe tapé dans le champ du compte
> (voir [Ne publiez jamais un export réel](#ne-publiez-jamais-un-export-réel)). Le
> `.gitignore` ignore les fichiers `*.html`, sauf les maquettes fictives de
> `docs/maquette/`.

## Pièges de Windows PowerShell 5.1

**En bref : sous Windows PowerShell 5.1, utilisez `--sortie rapport.txt` plutôt que
`> rapport.txt`.**

`sentinelle.py` écrit toujours en UTF-8. Dans la console, l'affichage direct est
correct. Mais dès que la sortie est redirigée (`>`) ou envoyée dans un pipe (`|`),
Windows PowerShell 5.1 la transforme :

1. Il décode les octets avec `[Console]::OutputEncoding`, c'est-à-dire la page de
   code de la console (850 ou 1252, en général). Le « é » devient alors `├®` ou `Ã©`.
2. `>` est un alias d'`Out-File`, qui réécrit ce texte déjà abîmé en **UTF-16 avec
   BOM**. Le fichier n'est même plus en UTF-8.
3. Dans un pipe, la commande suivante reçoit le texte abîmé. Par exemple,
   `Select-String 'é'` ne trouve rien.

Les lignes rejetées, sur stderr, subissent le même traitement si on les redirige
(`2>`).

**Les parades, par ordre de préférence :**

1. **`--sortie rapport.txt`** : le fichier est écrit en UTF-8 par Python lui-même,
   hors de portée de PowerShell. Relisez-le avec
   `Get-Content -Encoding utf8 .\rapport.txt`. Sans `-Encoding`, PowerShell 5.1
   suppose la page de code ANSI.
2. **Déclarer l'UTF-8 pour la session**, puis rediriger avec `Out-File` (qui ajoute
   un BOM en 5.1) :
   ```powershell
   [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
   python sentinelle.py .\echecs.csv | Out-File -Encoding utf8 .\rapport.txt
   ```
3. **`chcp 65001`** : même effet, pour toute la console.
4. **PowerShell 7** : la redirection y fonctionne en UTF-8 par défaut, sans BOM.

`$OutputEncoding` ne sert à rien ici : il règle l'autre sens, c'est-à-dire le texte
envoyé *vers* un programme.

## Générer des événements 4625 de test sur une VM

Ne le faites **jamais sur une machine de production**, ni sur une machine dont les
comptes ont un verrouillage après échecs : utilisez une VM de test.

**Vérifiez que l'audit des échecs d'ouverture de session est actif.** Il l'est par
défaut sur Windows 10 et 11. Lancez la commande dans une console administrateur ; le
GUID évite de dépendre de la langue du système :

```powershell
auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-08002B2CF919}"
```

Le résultat doit mentionner les échecs (« Failure » ou « Échec »).

### Avec `net use`, depuis une autre machine

Depuis la machine hôte, lancez des tentatives vers le partage `IPC$` de la VM, avec
un mauvais mot de passe :

```powershell
$vm = '192.168.56.10'   # adresse de la VM
1..6 | ForEach-Object { net use "\\$vm\IPC$" /user:"test$_" 'mauvais-mot-de-passe' }
```

**Utilisez un nom de compte différent à chaque tentative** (`test1`, `test2`…). Une
salve de tentatives identiques ne laisse qu'un seul événement dans le journal.

Chaque tentative doit échouer, avec l'erreur système 1326. Le partage de fichiers
(SMB) de la VM doit être joignable à travers son pare-feu.

Ensuite, sur la VM, exportez depuis une console administrateur (comme à l'étape 1),
puis analysez : l'adresse de l'hôte apparaît en alerte.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\export-4625.ps1 -Sortie .\echecs.csv -Depuis 2026-11-04
python sentinelle.py .\echecs.csv --sortie .\rapport.txt
```

Visez `\\127.0.0.1\IPC$` depuis la VM elle-même pour obtenir une **alerte locale**,
dans la section à part.

### Avec `runas`, sur la VM

```powershell
runas /user:test7 cmd
```

Tapez un mauvais mot de passe à l'invite, et recommencez avec `test8`, `test9`…

`runas` produit des échecs locaux : Windows enregistre l'adresse `::1`, et Ego les
range dans ses alertes locales. Pour tester la détection d'une adresse externe,
préférez `net use` depuis une autre machine.

## Personnaliser les répliques

Les répliques d'Ego sont dans `modeles/ego.json`. Pour essayer d'autres répliques
sans toucher à ce fichier, utilisez `--modeles .\mes-repliques.json`.

Le fichier contient **six clés obligatoires** et peut contenir **quatre clés
optionnelles**. Ces dernières sont réservées au rapport HTML, en préparation ; le
rapport texte les ignore. Chaque clé est une liste de variantes, et le rapport en
choisit une de façon déterministe :
- les mêmes données donnent toujours le même rapport ;
- le choix dépend des données, donc le ton change d'un export à l'autre ;
- dans une même section, les variantes tournent d'une alerte à la suivante.

Exemple abrégé : les six clés obligatoires, une seule variante par clé. Il est valide
pour `--modeles`, mais le test de voix exige au moins deux variantes par clé présente
dans `modeles/ego.json`.

```json
{
  "entete": ["Analyse terminée. J'ai tout lu. Je lis toujours tout."],
  "alerte": ["$ip. $nombre tentatives en $duree. Comptes visés : $comptes."],
  "alerte_locale": ["$ip. La menace vient de l'intérieur. $nombre tentatives."],
  "rien_a_signaler": ["Rien. Pour l'instant."],
  "lignes_rejetees": ["$nombre lignes illisibles. Écartées."],
  "conclusion": ["Fin du rapport. Retournez à vos cycles."]
}
```

Les champs suivent la syntaxe de `string.Template` : `$champ` ou `${champ}`. Écrivez
`$$` pour un dollar littéral.

### Clés et champs autorisés

| Clé | Quand | Champs autorisés |
|---|---|---|
| `entete` | Toujours, en tête du rapport. | `$seuil` `$fenetre` |
| `alerte` | Une fois par IP externe en alerte. | `$ip` `$nombre` `$duree` `$comptes` `$total` `$debut` `$fin` `$seuil` `$fenetre` |
| `alerte_locale` | Une fois par adresse de bouclage en alerte. | les mêmes que `alerte` |
| `rien_a_signaler` | Seulement s'il n'y a aucune alerte. | `$seuil` `$fenetre` |
| `lignes_rejetees` | Seulement s'il y a des lignes rejetées. | `$nombre` `$seuil` `$fenetre` |
| `conclusion` | Toujours, en fin de rapport. | `$seuil` `$fenetre` |

Clés optionnelles, pour le rapport HTML. Une clé absente n'est pas une erreur : le
rapport HTML s'en passera.

| Clé | Rôle | Champs autorisés |
|---|---|---|
| `titre_alerte` | Grand titre, s'il y a au moins une alerte. | `$nombre` : nombre d'IP en alerte, externes et locales |
| `titre_calme` | Grand titre, s'il n'y a aucune alerte. | `$total` : nombre d'échecs analysés dans l'export |
| `registre` | Phrase qui introduit le registre : les IP et les comptes des alertes, sans doublon (la casse est ignorée). Au plus 50 entrées sont affichées. | `$nombre` : **total** des entrées uniques, y compris celles qui ne sont pas affichées ; ce n'est pas le nombre affiché |
| `fin_lecture` | Dernière ligne du rapport. | aucun |

Exemple de clé optionnelle, à ajouter aux six autres :

```json
  "titre_calme": ["$total échecs lus. Aucun ne mérite mon attention."]
```

| Champ | Contenu |
|---|---|
| `$ip` | Adresse en alerte. |
| `$nombre` | Pour une alerte : nombre d'échecs dans la fenêtre la plus chargée. Pour `lignes_rejetees` : nombre de lignes rejetées. Pour `titre_alerte` et `registre` : voir le tableau des clés optionnelles. |
| `$duree` | Durée de cette fenêtre la plus chargée, en français : `1 minute 57 secondes`. |
| `$debut`, `$fin` | Premier et dernier échec de cette fenêtre : `2026-11-03 02:14:05 UTC+01:00`. |
| `$total` | Pour une alerte : tous les échecs de cette IP dans l'export. Pour `titre_calme` : voir le tableau des clés optionnelles. |
| `$comptes` | Comptes visés, distincts et triés. Au plus 10, puis « et N autre(s) ». Chaque nom est tronqué à 64 caractères lus (marque « … » comprise), puis neutralisé (voir [Sécurité](#sécurité)). Un nom vide devient `(sans nom)`. |
| `$seuil` | Valeur de `--seuil`. |
| `$fenetre` | Valeur de `--fenetre`, en français : `10 minutes`. |

### Validation du fichier

Un fichier invalide arrête le programme avec le code 2 et un message qui désigne la
clé et la variante fautives. Il est refusé dans les cas suivants :
- JSON invalide, ou encodage autre qu'UTF-8 (le BOM est toléré) ;
- clé obligatoire absente, clé inconnue ou en double ;
- liste vide, ou variante vide ou non textuelle ; une clé optionnelle à `null` est
  refusée aussi : pour s'en passer, retirez la clé ;
- `$` isolé ;
- champ non autorisé pour la clé ;
- caractère invalide en UTF-8 (demi-codet isolé, comme `"\ud800"`).

### Règles du test de voix

`tests/test_voix_ego.py` vérifie mécaniquement que `modeles/ego.json` garde la voix
d'Ego :

- **Au moins deux variantes** par clé obligatoire, et par clé optionnelle présente.
  Les règles suivantes s'appliquent aussi aux clés optionnelles présentes.
- **Aucune formule interdite**, sans tenir compte des majuscules ni des accents :
  - excuses : `pardon`, `pardonnez-moi`, `désolé(e)(s)`, `je m'excuse`, `excusez…` ;
  - remerciements : `merci` (sauf dans « sans merci »), `je vous remercie` ;
  - `IA`, `intelligence artificielle`, `machine…`, `programm…`, `mon enfant`.

  Ce sont les formules qui sont visées, pas les racines : « Je ne pardonne pas »,
  « sans merci » et « machinal » passent.
- **Phrases courtes** : 10 mots au plus par phrase. Un champ comme `$ip` compte pour
  un mot.
- **Menace calme** : jamais de `!`, ni d'hésitation (`peut-être`, `je crois`,
  `je pense`, `il semble`, `probablement`, `sans doute`). Les points de suspension
  (`…` ou `...`) sont autorisés : c'est un tic d'Ego.
- **Aucun nom propre**, sauf `Londinium`. Est considéré comme nom propre un mot à
  majuscule hors début de phrase ; « l'Ego » est jugé sur « Ego ». Un nom propre
  placé en tête de phrase n'est pas détecté : la relecture s'en charge.

Le reste de la voix (impératifs, triades nominales, humains vus comme un matériau)
relève de l'écriture et se relit à l'œil.

Pour vérifier seulement vos répliques :

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_voix_ego.py
```

## Lancer les tests

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest
```

Pour la couverture, avec un seuil minimal de 80 % fixé dans `pyproject.toml` :

```powershell
.\.venv\Scripts\python.exe -m pytest --cov --cov-report=term-missing
```

Les tests n'ont besoin ni de droits administrateur, ni du vrai journal Sécurité. Ils
utilisent les exports fictifs de `tests/donnees/`. Ils ne dépendent pas non plus du
texte des répliques : vous pouvez réécrire `ego.json` sans casser autre chose que le
test de voix.

## Sécurité

### Les champs contrôlés par l'attaquant sont neutralisés

Le nom de compte d'un événement 4625 est **choisi par l'attaquant**. Il peut y glisser
des séquences d'échappement de terminal (couleurs, titre de fenêtre, effacement), des
retours chariot pour forger de fausses lignes, ou des caractères bidirectionnels qui
inversent l'affichage. C'est pourquoi tout texte venu de l'export est **neutralisé**
avant affichage : les noms de comptes, les valeurs des lignes rejetées et les noms de
fichiers cités dans les messages d'erreur.

**Caractères remplacés par leur code visible** (par exemple `\x1b` ou `\u202e`) :
- les caractères de contrôle (ESC, CR, LF, tabulation, NUL…) ;
- les caractères de format invisibles, dont tous les contrôles bidirectionnels ;
- les demi-codets isolés ;
- les caractères d'usage privé ;
- les espaces autres que l'espace ordinaire ;
- les séparateurs de ligne et de paragraphe ;
- quelques lettres qui s'affichent comme un blanc.

La barre oblique inverse est doublée, pour que l'échappement reste non ambigu.

**Volumes plafonnés,** pour qu'un fichier hostile ne puisse pas inonder le terminal :
- noms de comptes tronqués à 64 caractères, au plus 10 par alerte ;
- au plus 20 lignes rejetées affichées ;
- valeurs fautives tronquées à 100 caractères.

Ces longueurs portent sur le texte lu, marque « … » comprise, avant neutralisation :
un caractère neutralisé s'affiche ensuite sur plusieurs caractères (`\x1b`), si bien
que la ligne affichée peut être plus longue. Elle reste bornée.

Les noms de comptes sont insérés dans les répliques comme du texte : ils ne sont
jamais interprétés comme un modèle.

### Sources sans caractère invisible

Un caractère bidirectionnel (comme U+202E) ou invisible peut faire lire à un
relecteur autre chose que ce que Python exécute. Un test de garde,
`tests/test_sources_propres.py`, échoue si l'un des fichiers `.py`, `.json`, `.md`,
`.ps1`, `.toml` ou `.cfg` du dépôt en contient un. Il vérifie les fichiers suivis par
git, et aussi les nouveaux fichiers non ignorés, avant leur premier commit. Il
signale :
- les caractères de contrôle, sauf le saut de ligne, le retour chariot et la
  tabulation ;
- les caractères de format invisibles, dont les contrôles bidirectionnels ;
- les caractères d'usage privé et les demi-codets isolés ;
- les séparateurs de ligne et de paragraphe (U+2028, U+2029).

Les espaces, y compris insécables, restent permis : le français typographié en
emploie.

Si git est introuvable, ou si le dossier n'est pas un dépôt git, le test échoue en
donnant la raison : il ne passe jamais sans avoir vérifié de fichier.

Chaque caractère trouvé est signalé avec sa position : `fichier:ligne:colonne
U+XXXX`. Les tests qui ont besoin de ces caractères les écrivent en séquence
d'échappement Python, jamais en caractère brut. Deux exceptions sont nommées dans le
test :
- le BOM en tête des scripts `.ps1`, sans lequel Windows PowerShell 5.1 lirait le
  script dans la page de code ANSI ;
- une liste blanche de fichiers de `tests/donnees/`, nommés un par un, qui doivent
  contenir de vrais caractères piégés. Elle est vide pour l'instant.

### Ne publiez jamais un export réel

Un export, ou un rapport tiré d'un export réel, contient :
- **des noms de comptes valides** de votre organisation ;
- parfois **des mots de passe** : un utilisateur pressé tape souvent son mot de passe
  dans le champ du nom de compte, et cette saisie finit dans `TargetUserName` ;
- **des adresses IP** internes ou externes.

Le `.gitignore` du dépôt protège :

| Motif | Fichiers concernés |
|---|---|
| `*.csv` | Tous les exports, sauf les exemples fictifs de `tests/donnees/`. |
| `*.txt` | Les rapports écrits par `--sortie`, sauf `requirements*.txt`. |
| `*.html` | Les rapports écrits par `--html`, sauf les maquettes fictives de `docs/maquette/`. |
| `*.evtx` | Les journaux exportés depuis l'Observateur d'événements. |

Les exemples de `tests/donnees/` sont versionnés. Un test de garde,
`tests/test_donnees_fictives.py`, y vérifie que les adresses IP appartiennent aux
plages de documentation (RFC 5737 : `192.0.2.0/24`, `203.0.113.0/24`) ou sont
exactement `::1` ou `127.0.0.1`.
Ce test **ne vérifie pas les noms de comptes** : n'y copiez jamais de lignes réelles.

Avant de publier un dépôt ou un fork, vérifiez qu'aucun fichier sensible n'a été
versionné, même dans l'historique :

```powershell
git log --all --name-only --format="" | Sort-Object -Unique
```

## Licence

[MIT](LICENSE).
