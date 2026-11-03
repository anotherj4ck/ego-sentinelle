<#
.SYNOPSIS
    Exporte les échecs d'ouverture de session Windows (événement 4625) au format CSV lu par sentinelle.py.

.DESCRIPTION
    Lit le journal Sécurité, ne retient que l'événement 4625 survenu depuis la date indiquée,
    et écrit un CSV UTF-8, séparateur virgule, avec l'en-tête Date,Compte,IP :

      Date   : propriété TimeCreated, au format ISO 8601 aller-retour ("o"), décalage horaire inclus
               (exemple : 2026-11-03T08:12:45.1234567+01:00).
      Compte : champ TargetUserName de l'événement (compte visé ; peut être vide).
      IP     : champ IpAddress de l'événement, exporté tel quel (peut valoir "-" pour une tentative locale).

    Aucune ligne n'est filtrée ni corrigée : c'est sentinelle.py qui écarte les lignes inexploitables.
    Si aucun événement ne correspond, le fichier ne contient que l'en-tête.

    Droits requis : lecture du journal Sécurité, c'est-à-dire une console administrateur
    ou l'appartenance au groupe « Lecteurs des journaux d'événements ».

    Codes de sortie :
      0  export réussi (y compris sans aucun événement) ;
      1  accès au journal refusé, lecture du journal ou écriture du fichier impossible ;
      2  valeur de -Depuis invalide.

.PARAMETER Sortie
    Chemin du fichier CSV à produire. Le fichier est écrasé s'il existe ; le dossier doit exister.

.PARAMETER Depuis
    Début de la période exportée, en heure locale, au format ISO uniquement :
      AAAA-MM-JJ             (exemple : 2026-11-01)
      AAAA-MM-JJTHH:mm       (exemple : 2026-11-01T08:00)
      AAAA-MM-JJTHH:mm:ss    (exemple : 2026-11-01T08:00:30)
    Tout autre format est refusé (code de sortie 2). En particulier, « 03/11/2026 » est rejeté :
    une conversion [datetime] classique utilise la culture invariante (mois/jour) et le lirait
    comme le 11 mars.
    Par défaut : les dernières 24 heures.

.EXAMPLE
    .\export-4625.ps1 -Sortie .\echecs.csv

    Exporte les échecs d'ouverture de session des dernières 24 heures.

.EXAMPLE
    .\export-4625.ps1 -Sortie .\echecs.csv -Depuis 2026-11-01T08:00

    Exporte les échecs survenus depuis le 1er novembre 2026 à 8 h, heure locale.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\export-4625.ps1 -Sortie C:\Temp\echecs.csv -Depuis 2026-11-01

    À lancer depuis une console ouverte avec « Exécuter en tant qu'administrateur ».
    -ExecutionPolicy Bypass ne concerne que ce processus powershell.exe : la stratégie
    d'exécution de la machine n'est pas modifiée.

.NOTES
    Compatible Windows PowerShell 5.1 et PowerShell 7.
    En 5.1, le CSV est écrit avec un BOM UTF-8 ; en 7, sans BOM. sentinelle.py accepte les deux.
#>
#Requires -Version 5.1
# (#Requires est placé après l'aide : placé avant, il empêche Get-Help de la trouver.)
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Sortie,

    [string]$Depuis
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$IdEchecOuverture = 4625
$EnTeteCsv = '"Date","Compte","IP"'
$FormatsDepuis = [string[]]@('yyyy-MM-dd', "yyyy-MM-dd'T'HH:mm", "yyyy-MM-dd'T'HH:mm:ss")
$CodeErreurExport = 1
$CodeErreurParametre = 2

function ConvertFrom-DateIso {
    # Convertit -Depuis en date locale ; $null si le texte n'est pas dans un format ISO accepté.
    param([string]$Texte)

    $resultat = [datetime]::MinValue
    $valide = [datetime]::TryParseExact(
        $Texte,
        $FormatsDepuis,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeLocal,
        [ref]$resultat)
    if (-not $valide) { return $null }
    return $resultat
}

function Assert-AccesJournalSecurite {
    # Sans droits, Get-WinEvent -FilterHashtable répond « aucun événement » au lieu d'un refus
    # d'accès : sans ce contrôle, on produirait un CSV vide en croyant que tout va bien.
    try {
        Get-WinEvent -LogName 'Security' -MaxEvents 1 -ErrorAction Stop | Out-Null
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return }
        $Host.UI.WriteErrorLine(
            "Lecture du journal Sécurité refusée : $($_.Exception.Message) " +
            "Relancez depuis une console administrateur (voir Get-Help .\export-4625.ps1 -Examples).")
        exit $CodeErreurExport
    }
}

function Get-ChampEvenement {
    # Lit un champ nommé de EventData ; chaîne vide s'il est absent.
    param([xml]$Xml, [string]$Nom)

    $noeud = $Xml.Event.EventData.Data | Where-Object { $_.Name -eq $Nom } | Select-Object -First 1
    if ($null -eq $noeud) { return '' }
    return $noeud.InnerText
}

function ConvertTo-LigneCsv {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Evenement)

    $xml = [xml]$Evenement.ToXml()
    return [PSCustomObject][ordered]@{
        Date   = $Evenement.TimeCreated.ToString('o')
        Compte = Get-ChampEvenement -Xml $xml -Nom 'TargetUserName'
        IP     = Get-ChampEvenement -Xml $xml -Nom 'IpAddress'
    }
}

if ($PSBoundParameters.ContainsKey('Depuis')) {
    $debut = ConvertFrom-DateIso -Texte $Depuis
    if ($null -eq $debut) {
        $Host.UI.WriteErrorLine(
            "-Depuis invalide : '$Depuis'. Formats acceptés : AAAA-MM-JJ, AAAA-MM-JJTHH:mm ou " +
            "AAAA-MM-JJTHH:mm:ss (exemple : 2026-11-01T08:00).")
        exit $CodeErreurParametre
    }
} else {
    $debut = (Get-Date).AddDays(-1)
}

Assert-AccesJournalSecurite

$filtre = @{ LogName = 'Security'; Id = $IdEchecOuverture; StartTime = $debut }
$nombre = 0

try {
    Get-WinEvent -FilterHashtable $filtre -ErrorAction Stop |
        ForEach-Object { $nombre++; ConvertTo-LigneCsv -Evenement $_ } |
        Export-Csv -Path $Sortie -NoTypeInformation -Encoding UTF8
} catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
        $Host.UI.WriteErrorLine("Export impossible : $($_.Exception.Message)")
        exit $CodeErreurExport
    }
}

if ($nombre -eq 0) {
    try {
        Set-Content -Path $Sortie -Value $EnTeteCsv -Encoding UTF8
    } catch {
        $Host.UI.WriteErrorLine("Écriture impossible : $($_.Exception.Message)")
        exit $CodeErreurExport
    }
}

Write-Host ("{0} événement(s) {1} exporté(s) depuis {2} vers {3}" -f
    $nombre, $IdEchecOuverture, $debut.ToString('yyyy-MM-dd HH:mm'), $Sortie)
exit 0
