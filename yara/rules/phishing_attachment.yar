/*
    Fichier : phishing_attachment.yar
    Projet  : soc-analyst-toolkit
    Usage   : Détection défensive de pièces jointes potentiellement liées au phishing.

    Objectif :
    - Repérer des documents ou archives contenant des chaînes souvent associées
      aux campagnes de phishing.
    - Aider au triage initial.
    - Ne pas considérer une correspondance comme une preuve définitive.

    Recommandation :
    - Utiliser cette règle avec contexte : email source, headers, URLs,
      réputation des domaines, hash, sandbox, etc.
*/

rule Phishing_Attachment_Common_Lures
{
    meta:
        description = "Chaînes communes observées dans des pièces jointes de phishing"
        author = "soc-analyst-toolkit : PotiteBulle"
        category = "phishing"
        severity = "medium"
        confidence = "low_to_medium"

    strings:
        $lure_01 = "verify your account" ascii wide nocase
        $lure_02 = "update your payment" ascii wide nocase
        $lure_03 = "account suspended" ascii wide nocase
        $lure_04 = "invoice attached" ascii wide nocase
        $lure_05 = "payment overdue" ascii wide nocase
        $lure_06 = "security alert" ascii wide nocase
        $lure_07 = "login to continue" ascii wide nocase
        $lure_08 = "password expires" ascii wide nocase
        $lure_09 = "cloud storage full" ascii wide nocase
        $lure_10 = "download document" ascii wide nocase

        $brand_01 = "Office 365" ascii wide nocase
        $brand_02 = "Microsoft" ascii wide nocase
        $brand_03 = "OneDrive" ascii wide nocase
        $brand_04 = "SharePoint" ascii wide nocase
        $brand_05 = "Adobe Document Cloud" ascii wide nocase
        $brand_06 = "DHL" ascii wide nocase
        $brand_07 = "PayPal" ascii wide nocase
        $brand_08 = "Netflix" ascii wide nocase

        $html_01 = "<form" ascii wide nocase
        $html_02 = "password" ascii wide nocase
        $html_03 = "email address" ascii wide nocase
        $html_04 = "submit.php" ascii wide nocase
        $html_05 = "window.location" ascii wide nocase
        $html_06 = "meta http-equiv=\"refresh\"" ascii wide nocase

    condition:
        (
            2 of ($lure_*) and 1 of ($brand_*)
        )
        or
        (
            2 of ($html_*) and filesize < 5MB
        )
}


rule Phishing_Attachment_Suspicious_Extension_Mismatch
{
    meta:
        description = "Détection indicative de noms de fichiers trompeurs dans pièces jointes"
        author = "soc-analyst-toolkit"
        category = "phishing"
        severity = "medium"
        confidence = "low"

    strings:
        $fake_pdf_01 = ".pdf.exe" ascii wide nocase
        $fake_pdf_02 = "PDF__.CAB" ascii wide nocase
        $fake_doc_01 = ".doc.exe" ascii wide nocase
        $fake_xls_01 = ".xls.exe" ascii wide nocase
        $archive_01 = ".cab" ascii wide nocase
        $archive_02 = ".scr" ascii wide nocase

    condition:
        any of them
}
