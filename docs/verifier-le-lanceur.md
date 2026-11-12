# Vérifier le lanceur à la main

Le lanceur (`ego-sentinelle.cmd` et `lancer.ps1`) demande une élévation UAC et ouvre un
navigateur : la suite automatique ne peut pas le faire. `tests/test_lanceur.py` couvre
tout le reste (arguments, chemins piégés, codes de sortie, messages). Cette liste
couvre ce qui manque.

À refaire après toute modification de `ego-sentinelle.cmd`, de `lancer.ps1` ou de
`export-4625.ps1`. Les vérifications marquées **indispensable** sont le minimum ; les
autres couvrent des configurations plus rares.

## État des vérifications

Une vérification reste **non vérifiée** tant que personne ne l'a faite. Quand elle
l'est, remplacez l'état par « vérifiée » et notez la date et l'environnement
(version de Windows, type de compte, version de Python). Après une modification du
lanceur, remettez à « non vérifiée » ce qui n'a pas été refait.

| N° | Vérification | État | Date | Environnement |
|---|---|---|---|---|
| 1 | Double-clic nominal (indispensable) | vérifiée | 2026-11-12 | VM-1 |
| 2 | Élévation refusée (indispensable) | vérifiée | 2026-11-12 | VM-1 |
| 3 | Dossier au nom piégé (indispensable) | vérifiée | 2026-11-12 | VM-1 |
| 4 | Python absent (indispensable) | vérifiée | 2026-11-12 | VM-1 |
| 5 | Compte standard | non vérifiée | | |
| 6 | Lecteur réseau mappé | non vérifiée | | |
| 7 | Console déjà administrateur | non vérifiée | | |
| 8 | Aucun événement 4625 | non vérifiée | | |
| 9 | Archive téléchargée depuis GitHub | non vérifiée | | |
| 10 | Rien n'est écrit dans le dépôt (indispensable) | vérifiée | 2026-11-12 | VM-1 |
| 11 | Code de sortie transmis | non vérifiée | | |
| 12 | Interruption | non vérifiée | | |

**Environnements :**
- **VM-1** : VM Windows, Windows PowerShell 5.1, Python 3.14, compte
  administrateur, UAC au réglage par défaut (`EnableLUA=1`,
  `ConsentPromptBehaviorAdmin=5`).

**Constaté le 2026-11-12 sur VM-1 :**
- **N° 1** : fenêtre UAC « Windows PowerShell », export, rapport texte avec accents
  corrects, rapport HTML ouvert dans le navigateur, console maintenue ouverte.
- **N° 2** : message « Élévation refusée ou impossible », aucun navigateur ouvert.
- **N° 3** : dans `C:\Temp\Ego l'essai & (copie)`, même résultat qu'au n° 1.
- **N° 4** : message clair, aucune fenêtre UAC.
- **N° 10** : `git status` propre après le déroulé, aucun `.csv` ni `.html`.

Points de la liste non rapportés lors de cet essai, à confirmer au prochain passage :
le chemin du script dans « Afficher plus de détails » et l'indication du dossier en
fin de déroulé (1) ; l'absence de fichier créé et le code 2 (2) ; le code 2 (4) ; le
contenu de `%LOCALAPPDATA%\EgoSentinelle` (10).

Ce que le README affirme sur les configurations 5 à 9, 11 et 12 repose, pour
l'instant, sur la lecture du code et sur la documentation de Windows, pas sur un
essai.

## Préparation

- Travaillez **sur une VM de test**, avec un compte administrateur.
- Générez quelques événements 4625 : voir
  [Générer des événements 4625 de test sur une VM](../README.md#générer-des-événements-4625-de-test-sur-une-vm).
- Le dossier de travail est `%LOCALAPPDATA%\EgoSentinelle`. Videz-le avant de
  commencer, pour voir ce que chaque essai y écrit.

## Vérifications

### 1. Double-clic nominal — indispensable

Double-cliquez sur `ego-sentinelle.cmd`, puis acceptez l'élévation.

- [ ] La fenêtre UAC annonce « Windows PowerShell », éditeur vérifié : Microsoft Windows.
- [ ] « Afficher plus de détails » montre le chemin de `export-4625.ps1`, dans le dépôt.
- [ ] Le rapport texte s'affiche dans la console, **accents corrects** (« terminée »,
      « visés »).
- [ ] Le navigateur s'ouvre sur le rapport HTML, état `ALERTE · CODE 1`.
- [ ] La console indique le dossier et les deux noms de fichiers horodatés.
- [ ] La fenêtre reste ouverte jusqu'à l'appui sur une touche.

### 2. Élévation refusée — indispensable

Double-cliquez, puis répondez **Non** à la fenêtre UAC.

- [ ] Message « Élévation refusée ou impossible : aucun export n'a été fait. »
- [ ] Aucun fichier `echecs-…` ni `rapport-…` n'est créé.
- [ ] Aucun navigateur ne s'ouvre.
- [ ] Depuis une console : `cmd /c ego-sentinelle.cmd`, refus, puis
      `echo %ERRORLEVEL%` affiche `2`.

### 3. Dossier au nom piégé — indispensable

Copiez le dépôt dans `C:\Temp\Ego l'essai & (copie)`, puis double-cliquez sur le
lanceur de cette copie.

- [ ] Le déroulé est le même qu'en 1 : export, rapport texte, navigateur.

Faites cet essai avec un Python installé depuis python.org (`py.exe` ou
`python.exe`) : voir la deuxième limite ci-dessous.

### 4. Python absent — indispensable

Dans une console, retirez Python du `PATH` pour cette session, puis lancez :

```bat
set "PATH=%SystemRoot%\System32"
ego-sentinelle.cmd
```

- [ ] Message « Python 3.11 ou plus récent est introuvable […] Aucun export n'a été
      fait. »
- [ ] **Aucune fenêtre UAC** n'est apparue.
- [ ] `echo %ERRORLEVEL%` affiche `2`.

### 5. Compte standard

Avec un compte non administrateur, double-cliquez : l'UAC demande l'identifiant et le
mot de passe d'un administrateur.

- [ ] Les fichiers arrivent dans le `%LOCALAPPDATA%` **du compte standard**.
- [ ] Le compte standard peut lire le CSV : l'analyse et le navigateur fonctionnent.

### 6. Lecteur réseau mappé

Placez le dépôt sur un lecteur mappé (`Z:`), puis double-cliquez.

- [ ] L'export échoue avec un message compréhensible, sans rapport ni navigateur.
      (Limite connue et documentée : le processus élevé ne voit pas ce lecteur.)

### 7. Console déjà administrateur

Lancez `ego-sentinelle.cmd` depuis une console ouverte en administrateur.

- [ ] Aucune fenêtre UAC ; le déroulé est normal.

### 8. Aucun événement 4625

Sur une VM sans échec d'ouverture de session sur la période (`-Jours 1`).

- [ ] Le navigateur s'ouvre sur un rapport à l'état `SILENCE · CODE 0`.
- [ ] `echo %ERRORLEVEL%` affiche `0`.

### 9. Archive téléchargée depuis GitHub

Téléchargez le dépôt en ZIP avec un navigateur, extrayez-le avec l'Explorateur, puis
double-cliquez sur le lanceur.

- [ ] Notez l'avertissement affiché par Windows (SmartScreen ou « Impossible de
      vérifier l'éditeur »).
- [ ] Après `Get-ChildItem -Recurse -File | Unblock-File` dans le dossier,
      l'avertissement a disparu et le déroulé est normal.

### 10. Rien n'est écrit dans le dépôt — indispensable

Après les essais précédents, dans le dépôt :

```powershell
git status --short --ignored
```

- [ ] Aucun fichier `.csv` ni `.html` nouveau, même parmi les fichiers ignorés.
- [ ] `%LOCALAPPDATA%\EgoSentinelle` contient un CSV et un rapport par essai réussi.

### 11. Code de sortie transmis

Depuis une console `cmd`, après un déroulé avec alertes :

```bat
ego-sentinelle.cmd
echo %ERRORLEVEL%
```

- [ ] `1` après un rapport avec alertes, malgré la pause finale.

### 12. Interruption

Pendant l'analyse (étape 4), appuyez sur Ctrl+C.

- [ ] Le rapport HTML ne s'ouvre pas.

## Limites connues

Elles ne sont pas corrigées : évitez ces configurations.

- **Dossier du dépôt dont le nom contient `%`.** C'est `cmd` qui développe ce
  caractère avant même de lire `ego-sentinelle.cmd` : le lanceur ne démarre pas, ou
  démarre depuis un autre chemin.
- **Python fourni par un fichier `.bat` ou `.cmd` (pyenv-win, par exemple) et « & »
  dans le chemin du dépôt.** Windows exécute un tel fichier par l'intermédiaire de
  `cmd`, qui relit la ligne de commande. Si le chemin contient un « & » **et aucun
  espace**, PowerShell ne le met pas entre guillemets : `cmd` coupe alors le chemin
  de `sentinelle.py` au « & » et exécute la suite comme une commande, sans élévation.
  L'analyse échoue. Constaté par un essai le 2026-11-12 (Windows 11, Windows
  PowerShell 5.1, faux `python.cmd`) ; avec un espace dans le chemin, les guillemets
  protègent le « & ». Il en va de même du chemin de `%LOCALAPPDATA%`. Avec `py.exe`
  ou `python.exe`, aucun interpréteur de commandes n'intervient et le « & » est sans
  effet (vérification 3). Si votre Python passe par un fichier `.bat`, placez le
  dépôt dans un dossier sans « & ».
- **Dépôt sur un lecteur réseau mappé.** Le processus élevé ne voit pas les lecteurs
  de la session ordinaire (vérification 6).

## Nettoyage

```powershell
Remove-Item -Recurse -LiteralPath "$env:LOCALAPPDATA\EgoSentinelle"
```
