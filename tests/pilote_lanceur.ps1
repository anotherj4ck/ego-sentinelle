<#
.SYNOPSIS
    Pilote de test : appelle des fonctions de lancer.ps1 et rend leurs résultats en JSON.

.DESCRIPTION
    Utilisé par tests/test_lanceur.py, jamais par le lanceur lui-même.

    Lit sur l'entrée standard une demande JSON :
      { "culture": "ar-SA" ou null,
        "appels": [ { "fonction": "ConvertTo-Depuis", "parametres": { ... } }, ... ] }

    Écrit sur la sortie standard une réponse JSON, une entrée par appel, dans l'ordre :
      { "resultats": [ { "resultat": ... } ou { "erreur": "message" }, ... ] }

    Demande et réponse sont en ASCII pur, accents échappés (antislash, u, quatre chiffres
    hexadécimaux) : Windows PowerShell 5.1 abîme les accents sur ses flux standard.

    lancer.ps1 est chargé par dot-sourcing : ses fonctions sont définies, son déroulé
    (export élevé, analyse, navigateur) ne s'exécute pas.
#>
#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path (Split-Path -Parent $PSScriptRoot) 'lancer.ps1')

function ConvertTo-JsonAscii {
    param($Objet)

    $json = ConvertTo-Json -InputObject $Objet -Depth 6 -Compress
    $echapper = { param($trouve) '\u{0:x4}' -f [int][char]$trouve.Value }
    return [regex]::Replace($json, '[^\x20-\x7E]', $echapper)
}

function Invoke-ExportSansElevation {
    # Le lancement de Invoke-ExportEleve, sans élévation : powershell.exe reçoit et découpe
    # la même ligne de commande, mais aucune fenêtre UAC ne s'ouvre.
    param([string]$Script, [string]$Sortie, [string]$Depuis)

    $ligne = Get-ArgumentsExport -Script $Script -Sortie $Sortie -Depuis $Depuis
    $processus = Start-Process -FilePath (Get-CheminPowerShell) -ArgumentList $ligne `
        -WindowStyle Hidden -Wait -PassThru
    return $processus.ExitCode
}

function Invoke-AnalyseSansConsole {
    # Invoke-Analyse laisse Python écrire sur la console et ne rend rien : ici, sa sortie est
    # écartée et son code de sortie rendu.
    param($Python, [string]$Sentinelle, [string]$Csv, [string]$Rapport)

    Invoke-Analyse -Python $Python -Sentinelle $Sentinelle -Csv $Csv -Rapport $Rapport | Out-Null
    return $LASTEXITCODE
}

$demande = [Console]::In.ReadToEnd() | ConvertFrom-Json
if ($null -ne $demande.culture) {
    [System.Threading.Thread]::CurrentThread.CurrentCulture =
        [System.Globalization.CultureInfo]::GetCultureInfo($demande.culture)
}

$resultats = New-Object System.Collections.ArrayList
foreach ($appel in $demande.appels) {
    $parametres = @{}
    foreach ($propriete in $appel.parametres.PSObject.Properties) {
        $parametres[$propriete.Name] = $propriete.Value
    }
    try {
        $resultat = & $appel.fonction @parametres
        [void]$resultats.Add(@{ resultat = $resultat })
    } catch {
        [void]$resultats.Add(@{ erreur = $_.Exception.Message })
    }
}

[Console]::Out.Write((ConvertTo-JsonAscii -Objet @{ resultats = $resultats.ToArray() }))
exit 0
