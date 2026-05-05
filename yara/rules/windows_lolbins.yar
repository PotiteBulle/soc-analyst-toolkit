/*
    Fichier : windows_lolbins.yar
    Projet  : soc-analyst-toolkit
    Usage   : Détection de chaînes liées à des LOLBins Windows.

    LOLBins = binaires légitimes Windows pouvant être abusés.
    Cette règle est utile pour le triage statique de scripts, logs exportés,
    fichiers texte, commandes collectées ou artefacts suspects.

    Attention :
    Ces chaînes peuvent aussi être présentes dans des scripts d'administration
    légitimes. Toujours corréler avec le contexte.
*/

rule Windows_LOLBins_Common_References
{
    meta:
        description = "Références communes à des LOLBins Windows"
        author = "soc-analyst-toolkit : PotiteBulle"
        category = "windows"
        severity = "medium"
        confidence = "low_to_medium"

    strings:
        $lolbin_01 = "powershell.exe" ascii wide nocase
        $lolbin_02 = "pwsh.exe" ascii wide nocase
        $lolbin_03 = "cmd.exe" ascii wide nocase
        $lolbin_04 = "rundll32.exe" ascii wide nocase
        $lolbin_05 = "regsvr32.exe" ascii wide nocase
        $lolbin_06 = "mshta.exe" ascii wide nocase
        $lolbin_07 = "certutil.exe" ascii wide nocase
        $lolbin_08 = "bitsadmin.exe" ascii wide nocase
        $lolbin_09 = "wmic.exe" ascii wide nocase
        $lolbin_10 = "schtasks.exe" ascii wide nocase
        $lolbin_11 = "wscript.exe" ascii wide nocase
        $lolbin_12 = "cscript.exe" ascii wide nocase
        $lolbin_13 = "msiexec.exe" ascii wide nocase
        $lolbin_14 = "installutil.exe" ascii wide nocase
        $lolbin_15 = "forfiles.exe" ascii wide nocase
        $lolbin_16 = "msbuild.exe" ascii wide nocase

    condition:
        2 of them
}


rule Windows_LOLBins_Suspicious_Arguments
{
    meta:
        description = "Arguments suspects fréquemment associés à des LOLBins"
        author = "soc-analyst-toolkit"
        category = "windows"
        severity = "medium"
        confidence = "medium"

    strings:
        $arg_01 = "-EncodedCommand" ascii wide nocase
        $arg_02 = "-enc" ascii wide nocase
        $arg_03 = "Bypass" ascii wide nocase
        $arg_04 = "DownloadString" ascii wide nocase
        $arg_05 = "scrobj.dll" ascii wide nocase
        $arg_06 = "javascript:" ascii wide nocase
        $arg_07 = "vbscript:" ascii wide nocase
        $arg_08 = "urlcache" ascii wide nocase
        $arg_09 = "split" ascii wide nocase
        $arg_10 = "create" ascii wide nocase
        $arg_11 = "delete shadows" ascii wide nocase
        $arg_12 = "wevtutil cl" ascii wide nocase

    condition:
        2 of them
}


rule Windows_Suspicious_User_Writable_Paths
{
    meta:
        description = "Chemins Windows fréquemment utilisés pour exécution suspecte"
        author = "soc-analyst-toolkit"
        category = "windows"
        severity = "low"
        confidence = "low"

    strings:
        $path_01 = "\\AppData\\Roaming\\" ascii wide nocase
        $path_02 = "\\AppData\\Local\\Temp\\" ascii wide nocase
        $path_03 = "\\Users\\Public\\" ascii wide nocase
        $path_04 = "\\ProgramData\\" ascii wide nocase
        $path_05 = "\\Windows\\Temp\\" ascii wide nocase
        $path_06 = "%TEMP%" ascii wide nocase
        $path_07 = "%APPDATA%" ascii wide nocase
        $path_08 = "%PUBLIC%" ascii wide nocase

    condition:
        any of them
}
