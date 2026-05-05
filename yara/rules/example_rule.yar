rule Example_Suspicious_Strings
{
    meta:
        description = "Exemple pédagogique de règle YARA"
        author = "PotiteBulle"
        purpose = "training SOC ANALYST"

    strings:
        $s1 = "powershell" ascii nocase
        $s2 = "cmd.exe" ascii nocase
        $s3 = "Content-Transfer-Encoding: base64" ascii nocase

    condition:
        any of them
}
