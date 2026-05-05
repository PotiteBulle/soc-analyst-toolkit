/*
    Fichier : suspicious_scripts.yar
    Projet  : soc-analyst-toolkit
    Usage   : Repérage défensif de scripts potentiellement suspects.

    Cette règle vise les scripts contenant des motifs fréquemment rencontrés
    dans des chaînes d'exécution abusives : PowerShell encodé, téléchargement
    distant, exécution dynamique, obfuscation simple.

    Une alerte doit toujours être validée manuellement.
*/

rule Suspicious_PowerShell_Behavior
{
    meta:
        description = "Motifs PowerShell fréquemment suspects"
        author = "soc-analyst-toolkit : PotiteBulle"
        category = "script"
        severity = "medium"
        confidence = "medium"

    strings:
        $ps_01 = "powershell" ascii wide nocase
        $ps_02 = "-EncodedCommand" ascii wide nocase
        $ps_03 = "-enc" ascii wide nocase
        $ps_04 = "IEX" ascii wide nocase
        $ps_05 = "Invoke-Expression" ascii wide nocase
        $ps_06 = "DownloadString" ascii wide nocase
        $ps_07 = "DownloadFile" ascii wide nocase
        $ps_08 = "Net.WebClient" ascii wide nocase
        $ps_09 = "FromBase64String" ascii wide nocase
        $ps_10 = "Start-Process" ascii wide nocase
        $ps_11 = "Bypass" ascii wide nocase
        $ps_12 = "Hidden" ascii wide nocase

    condition:
        $ps_01 and 2 of ($ps_02,$ps_03,$ps_04,$ps_05,$ps_06,$ps_07,$ps_08,$ps_09,$ps_10,$ps_11,$ps_12)
}


rule Suspicious_JavaScript_Behavior
{
    meta:
        description = "Motifs JavaScript/JScript suspects"
        author = "soc-analyst-toolkit"
        category = "script"
        severity = "medium"
        confidence = "medium"

    strings:
        $js_01 = "ActiveXObject" ascii wide nocase
        $js_02 = "WScript.Shell" ascii wide nocase
        $js_03 = "MSXML2.XMLHTTP" ascii wide nocase
        $js_04 = "ADODB.Stream" ascii wide nocase
        $js_05 = "CreateObject" ascii wide nocase
        $js_06 = "cmd.exe" ascii wide nocase
        $js_07 = "powershell" ascii wide nocase
        $js_08 = "eval(" ascii wide nocase
        $js_09 = "unescape(" ascii wide nocase
        $js_10 = "fromCharCode" ascii wide nocase

    condition:
        3 of them
}


rule Suspicious_Script_Obfuscation
{
    meta:
        description = "Signaux simples d'obfuscation dans scripts"
        author = "soc-analyst-toolkit"
        category = "script"
        severity = "low"
        confidence = "low"

    strings:
        $obf_01 = "base64" ascii wide nocase
        $obf_02 = "frombase64string" ascii wide nocase
        $obf_03 = "charcode" ascii wide nocase
        $obf_04 = "replace(" ascii wide nocase
        $obf_05 = "split(" ascii wide nocase
        $obf_06 = "join(" ascii wide nocase
        $obf_07 = "xor" ascii wide nocase
        $obf_08 = "gzipstream" ascii wide nocase

    condition:
        4 of them
}
