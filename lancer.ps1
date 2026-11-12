<#
.SYNOPSIS
    Lanceur d'Ego Sentinelle : exporte les échecs 4625 (avec élévation), les analyse, puis ouvre le rapport HTML.

.DESCRIPTION
    Lancé par ego-sentinelle.cmd, d'un double-clic. Usage depuis une console :

      ego-sentinelle.cmd [-Jours N]      N de 1 à 365 : période exportée, en jours (défaut : 7)

    Déroulé :
      1. crée le dossier de travail %LOCALAPPDATA%\EgoSentinelle, hors du dépôt ;
      2. vérifie que Python 3.11 ou plus récent est disponible (py -3, sinon python) ;
      3. lance export-4625.ps1 dans un PowerShell élevé (fenêtre UAC), attend sa fin et lit son code ;
      4. lance sentinelle.py, non élevé, sur le CSV obtenu, avec --html ;
      5. ouvre le rapport HTML si l'analyse a abouti (codes 0 et 1), puis indique où sont les fichiers.

    Moindre privilège : seul export-4625.ps1 est élevé, parce que seule la lecture du journal Sécurité
    l'exige. Ni ce script ni Python ne le sont jamais.

    Les fichiers produits contiennent de vraies adresses IP et de vrais noms de compte : ils restent
    dans %LOCALAPPDATA%, jamais dans le dépôt. Ce script ne lit pas leur contenu : il ne manipule que
    des chemins qu'il a construits lui-même.

    Codes de sortie : ceux de sentinelle.py quand l'analyse a eu lieu (0 aucune alerte, 1 alertes,
    2 erreur, 130 interruption). Les échecs propres au lanceur donnent 2 : usage incorrect, Python
    introuvable, élévation refusée, export en échec.

.NOTES
    Compatible Windows PowerShell 5.1. Fichier en UTF-8 avec BOM : sans BOM, PowerShell 5.1 le lirait
    dans la page de code ANSI.

    Les arguments sont lus par Read-Arguments et non par un bloc param() : un argument refusé par
    PowerShell lui-même ferait sortir le script avec le code 1, que l'appelant prendrait pour
    « alertes ».

    Les fonctions de la première partie sont sans effet de bord : tests/test_lanceur.py les appelle
    une à une. Chargé par dot-sourcing, ce script définit ses fonctions sans rien exécuter.
#>
#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$NomDossierTravail = 'EgoSentinelle'
$JoursParDefaut = '7'
$JoursMax = 365
# Une valeur refusée est recopiée dans le message, mais pas au-delà.
$EchoMax = 20
$CodeErreurLanceur = 2
# Format accepté par le paramètre -Depuis de export-4625.ps1 (heure locale).
$FormatDepuis = "yyyy-MM-dd'T'HH:mm:ss"
$FormatHorodatage = 'yyyyMMdd-HHmmss'
# Culture invariante : sous une culture à calendrier non grégorien, l'année serait fausse.
$CultureInvariante = [System.Globalization.CultureInfo]::InvariantCulture
$Usage = "Usage : ego-sentinelle.cmd [-Jours N], avec N de 1 à $JoursMax (défaut : $JoursParDefaut)."
$PythonMinimum = '3.11'

# --- Fonctions sans effet de bord ---------------------------------------------------------------

function Read-Arguments {
    # Lit « -Jours N » ; rend @{ Jours ; Erreur }. La valeur est validée par ConvertTo-Depuis.
    param([string[]]$Arguments)

    $liste = @()
    if ($null -ne $Arguments) { $liste = @($Arguments) }
    if ($liste.Count -eq 0) {
        return @{ Jours = $JoursParDefaut; Erreur = $null }
    }
    if ($liste.Count -eq 2 -and $liste[0] -ieq '-Jours' -and $liste[1] -ne '') {
        return @{ Jours = $liste[1]; Erreur = $null }
    }
    return @{ Jours = $null; Erreur = "Arguments non reconnus. $Usage" }
}

function ConvertTo-Depuis {
    # Convertit -Jours en valeur de -Depuis pour export-4625.ps1 ; rend @{ Depuis ; Erreur }.
    param([string]$Jours, [datetime]$Maintenant)

    # Chiffres ASCII seulement : \d accepterait les chiffres d'autres écritures, et « $ »
    # tolérerait un saut de ligne final (d'où \z).
    if ($Jours -cmatch '^[0-9]{1,3}\z') {
        $nombre = [int]$Jours
        if ($nombre -ge 1 -and $nombre -le $JoursMax) {
            $debut = $Maintenant.AddDays(-$nombre)
            return @{ Depuis = $debut.ToString($FormatDepuis, $CultureInvariante); Erreur = $null }
        }
    }
    $apercu = $Jours
    if ($Jours.Length -gt $EchoMax) { $apercu = $Jours.Substring(0, $EchoMax) + '…' }
    return @{
        Depuis = $null
        Erreur = "-Jours invalide : '$apercu'. Nombre entier de 1 à $JoursMax attendu, " +
            'en chiffres de 0 à 9.'
    }
}

function Get-NomsFichiers {
    # Noms horodatés : deux lancements ne s'écrasent pas, et l'ordre alphabétique est chronologique.
    param([datetime]$Maintenant)

    $horodatage = $Maintenant.ToString($FormatHorodatage, $CultureInvariante)
    return @{ Export = "echecs-$horodatage.csv"; Rapport = "rapport-$horodatage.html" }
}

function Get-DossierTravail {
    param([string]$LocalAppData)

    return [System.IO.Path]::Combine($LocalAppData, $NomDossierTravail)
}

function ConvertTo-ArgumentWindows {
    # Met un argument entre guillemets pour une ligne de commande Windows.
    # Entre guillemets, l'espace, l'apostrophe, « & », les parenthèses, « $ » ou « ; » sont du
    # texte : aucun interpréteur de commandes ne relit la ligne. Seules les barres obliques inverses
    # placées devant un guillemet comptent : celles de la fin sont doublées, sinon la dernière
    # avalerait le guillemet fermant.
    param([string]$Texte)

    if ($Texte.Contains('"')) {
        throw 'Argument refusé : il contient un guillemet double, impossible dans un chemin Windows.'
    }
    $barresFinales = [regex]::Match($Texte, '\\+\z').Value
    return '"' + $Texte + $barresFinales + '"'
}

function Get-ArgumentsExport {
    # Ligne de commande du PowerShell élevé. -File, et jamais une commande à interpréter :
    # ce qui suit le chemin du script est transmis tel quel à ses paramètres.
    param([string]$Script, [string]$Sortie, [string]$Depuis)

    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', (ConvertTo-ArgumentWindows -Texte $Script),
        '-Sortie', (ConvertTo-ArgumentWindows -Texte $Sortie),
        '-Depuis', (ConvertTo-ArgumentWindows -Texte $Depuis)
    )
    return ($arguments -join ' ')
}

function Get-CheminPowerShell {
    # Chemin complet, demandé à Windows : « powershell.exe » seul serait cherché dans le PATH,
    # et c'est ce programme qui est élevé.
    return [System.IO.Path]::Combine(
        [Environment]::GetFolderPath('System'), 'WindowsPowerShell\v1.0\powershell.exe')
}

function Get-DecisionExport {
    # Rend @{ Continuer ; Message } selon le code de sortie de export-4625.ps1.
    # La fenêtre élevée se ferme dès la fin de l'export et son texte est perdu : chaque message
    # dit donc ce qui s'est passé, les causes possibles et comment en savoir plus.
    param([int]$Code)

    if ($Code -eq 0) {
        return @{ Continuer = $true; Message = 'Export réussi.' }
    }
    $suite = " Aucun rapport n'a été produit. Pour lire le message d'origine, lancez " +
        'export-4625.ps1 depuis une console administrateur (voir le README).'
    switch ($Code) {
        1 {
            $constat = "L'export a échoué (code 1) : le journal Sécurité n'a pas pu être lu, ou le " +
                "fichier CSV n'a pas pu être écrit. Causes possibles : le compte choisi dans la " +
                "fenêtre UAC n'est pas administrateur ; une stratégie d'exécution imposée par " +
                "l'organisation interdit les scripts ; le dossier de travail est inaccessible à ce " +
                'compte.'
        }
        2 {
            $constat = "L'export a refusé la date de début (code 2) : la valeur de -Depuis calculée " +
                "par le lanceur n'est pas acceptée. C'est une anomalie du lanceur : signalez-la."
        }
        default {
            $constat = "L'export s'est arrêté avec un code inattendu (code $Code) : la fenêtre " +
                'élevée a peut-être été fermée avant la fin.'
        }
    }
    return @{ Continuer = $false; Message = $constat + $suite }
}

function Get-DecisionAnalyse {
    # Rend @{ Ouvrir ; Message } selon le code de sortie de sentinelle.py.
    param([int]$Code)

    switch ($Code) {
        0 { return @{ Ouvrir = $true; Message = 'Analyse terminée : aucune alerte.' } }
        1 { return @{ Ouvrir = $true; Message = 'Analyse terminée : Ego signale au moins une alerte.' } }
        2 {
            return @{
                Ouvrir  = $false
                Message = "L'analyse a échoué (code 2) : voir l'erreur affichée ci-dessus. " +
                    "Le rapport n'est pas ouvert."
            }
        }
        130 { return @{ Ouvrir = $false; Message = "Analyse interrompue (code 130). Le rapport n'est pas ouvert." } }
        default {
            return @{
                Ouvrir  = $false
                Message = "L'analyse s'est arrêtée avec un code inattendu (code $Code). " +
                    "Le rapport n'est pas ouvert."
            }
        }
    }
}

# --- Fonctions à effets ---------------------------------------------------------------------------

function Find-Python {
    # Rend @{ Commande ; Arguments } pour le premier Python assez récent, sinon $null.
    # Chaque candidat est réellement exécuté : l'alias « python » du Microsoft Store existe
    # sur le disque, mais sort en erreur.
    $verification = "import sys; sys.exit(0 if sys.version_info >= ($($PythonMinimum.Replace('.', ', '))) else 1)"
    $candidats = @(
        @{ Nom = 'py'; Arguments = @('-3') },
        @{ Nom = 'python'; Arguments = @() }
    )
    # Ce que le candidat écrit sur stderr est ignoré : avec « Stop », Windows PowerShell 5.1 en
    # ferait une erreur fatale.
    $ErrorActionPreference = 'Continue'
    foreach ($candidat in $candidats) {
        $commande = Get-Command -Name $candidat.Nom -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -eq $commande) { continue }
        $global:LASTEXITCODE = 1
        try {
            & $commande.Path @($candidat.Arguments) -c $verification 2>$null | Out-Null
        } catch {
            continue
        }
        if ($LASTEXITCODE -eq 0) {
            return @{ Commande = $commande.Path; Arguments = $candidat.Arguments }
        }
    }
    return $null
}

function Invoke-ExportEleve {
    # Seul endroit du lanceur où une élévation est demandée. Rend le code de sortie de l'export.
    # Rien n'est capturé : l'export écrit dans le fichier, et c'est le fichier qui est lu ensuite.
    param([string]$Script, [string]$Sortie, [string]$Depuis)

    # Une chaîne unique : Windows PowerShell 5.1 joint un tableau d'arguments par des espaces,
    # sans guillemets, et un chemin contenant un espace serait coupé en deux.
    $ligne = Get-ArgumentsExport -Script $Script -Sortie $Sortie -Depuis $Depuis
    $processus = Start-Process -FilePath (Get-CheminPowerShell) -ArgumentList $ligne `
        -Verb RunAs -Wait -PassThru
    # Un code absent ne doit pas passer pour 0 ([int]$null vaut 0).
    if ($null -eq $processus -or $null -eq $processus.ExitCode) { return -1 }
    return $processus.ExitCode
}

function Invoke-Analyse {
    # Lance sentinelle.py, non élevé. Ne rend rien : le code de sortie est dans $LASTEXITCODE.
    # Ni affectation ni pipe, ici comme chez l'appelant : Python hérite de la console, et le
    # rapport texte s'y affiche sans passer par l'encodage d'un pipe.
    param($Python, [string]$Sentinelle, [string]$Csv, [string]$Rapport)

    $global:LASTEXITCODE = $CodeErreurLanceur
    & $Python.Commande @($Python.Arguments) $Sentinelle $Csv '--html' $Rapport
}

function Stop-Lanceur {
    param([string]$Message)

    $Host.UI.WriteErrorLine($Message)
    exit $CodeErreurLanceur
}

function Invoke-Lanceur {
    # Le déroulé complet. N'écrit rien dans le pipeline et ne doit pas être capturé : Python
    # hérite ainsi de la console, et le rapport texte s'affiche sans pipe ni redirection.
    param([string[]]$Arguments)

    $maintenant = Get-Date
    $lus = Read-Arguments -Arguments $Arguments
    if ($null -ne $lus.Erreur) { Stop-Lanceur -Message $lus.Erreur }
    $periode = ConvertTo-Depuis -Jours $lus.Jours -Maintenant $maintenant
    if ($null -ne $periode.Erreur) { Stop-Lanceur -Message "$($periode.Erreur) $Usage" }

    # Chemins calculés depuis l'emplacement de ce script : jamais depuis le dossier courant,
    # jamais depuis le PATH.
    $scriptExport = Join-Path $PSScriptRoot 'export-4625.ps1'
    $sentinelle = Join-Path $PSScriptRoot 'sentinelle.py'
    foreach ($requis in @($scriptExport, $sentinelle, (Get-CheminPowerShell))) {
        if (-not (Test-Path -LiteralPath $requis -PathType Leaf)) {
            Stop-Lanceur -Message "Fichier introuvable : $requis. Le dépôt est incomplet."
        }
    }

    # 1. Dossier de travail, hors du dépôt.
    if ([string]::IsNullOrEmpty($env:LOCALAPPDATA)) {
        Stop-Lanceur -Message "La variable LOCALAPPDATA est vide : impossible de ranger les fichiers."
    }
    $dossier = Get-DossierTravail -LocalAppData $env:LOCALAPPDATA
    [System.IO.Directory]::CreateDirectory($dossier) | Out-Null
    $noms = Get-NomsFichiers -Maintenant $maintenant
    $csv = [System.IO.Path]::Combine($dossier, $noms.Export)
    $rapport = [System.IO.Path]::Combine($dossier, $noms.Rapport)

    # 2. Python, vérifié avant la fenêtre UAC : inutile d'élever pour échouer ensuite.
    $python = Find-Python
    if ($null -eq $python) {
        Stop-Lanceur -Message ("Python $PythonMinimum ou plus récent est introuvable (ni « py -3 » " +
            "ni « python »). Installez-le depuis https://www.python.org/downloads/ puis relancez. " +
            "Aucun export n'a été fait.")
    }

    # 3. Export élevé, et lui seul.
    Write-Host "Export des échecs d'ouverture de session depuis le $($periode.Depuis)."
    Write-Host 'Windows demande une élévation (fenêtre UAC) : elle sert uniquement à lire le journal Sécurité.'
    try {
        $codeExport = Invoke-ExportEleve -Script $scriptExport -Sortie $csv -Depuis $periode.Depuis
    } catch {
        Stop-Lanceur -Message ("Élévation refusée ou impossible : aucun export n'a été fait. " +
            "Détail donné par Windows : $($_.Exception.Message)")
    }
    $export = Get-DecisionExport -Code $codeExport
    if (-not $export.Continuer) { Stop-Lanceur -Message $export.Message }
    if (-not (Test-Path -LiteralPath $csv -PathType Leaf)) {
        Stop-Lanceur -Message ("L'export a rendu le code 0, mais le fichier attendu est absent : " +
            "$csv. Aucun rapport n'a été produit.")
    }

    # 4. Analyse, non élevée.
    Write-Host ''
    Invoke-Analyse -Python $python -Sentinelle $sentinelle -Csv $csv -Rapport $rapport
    $codeAnalyse = $LASTEXITCODE
    $analyse = Get-DecisionAnalyse -Code $codeAnalyse
    Write-Host ''
    if ($analyse.Ouvrir) { Write-Host $analyse.Message } else { $Host.UI.WriteErrorLine($analyse.Message) }

    $rapportEcrit = Test-Path -LiteralPath $rapport -PathType Leaf
    if ($analyse.Ouvrir -and $rapportEcrit) {
        try {
            Start-Process -FilePath $rapport
        } catch {
            $Host.UI.WriteErrorLine("Le rapport n'a pas pu être ouvert : $($_.Exception.Message)")
        }
    }

    # 5. Où sont les fichiers.
    Write-Host ''
    Write-Host "Fichiers rangés dans : $dossier"
    Write-Host "  export  : $($noms.Export)"
    if ($rapportEcrit) { Write-Host "  rapport : $($noms.Rapport)" }
    Write-Host 'Ils contiennent de vraies adresses IP et de vrais noms de compte : ne les publiez pas.'
    exit $codeAnalyse
}

# Lancé (double-clic, console) : le déroulé s'exécute. Chargé par dot-sourcing (tests) : rien.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-Lanceur -Arguments $args
    } catch {
        # Une erreur imprévue ferait sortir PowerShell avec le code 1, celui des alertes.
        Stop-Lanceur -Message "Erreur inattendue du lanceur : $($_.Exception.Message)"
    }
}
