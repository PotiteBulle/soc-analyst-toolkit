/*
    Fichier : example_rule.yar
    Projet  : soc-analyst-toolkit
    Usage   : Exemple pédagogique de règle YARA défensive.

    Cette règle sert de modèle. Elle n'est pas destinée à être utilisée
    seule comme détection fiable en production.
*/

rule Example_Suspicious_Strings
{
    meta:
        description = "Exemple simple de règle YARA pour chaînes suspectes"
        author = "soc-analyst-toolkit : PotiteBulle"
        category = "example"
        severity = "low"
        usage = "training"

    strings:
        $s1 = "powershell" ascii wide nocase
        $s2 = "cmd.exe" ascii wide nocase
        $s3 = "http://" ascii wide nocase
        $s4 = "https://" ascii wide nocase

    condition:
        2 of them
}
