rule VBA_AutoExec_DownloadCradle
{
    meta:
        description = "Decompiled VBA: auto-exec + download/shell cradle"
    strings:
        $hdr  = "Attribute VB_"
        $auto = /Auto_?Open|Document_Open|Workbook_Open|Auto_?Exec/ nocase
        $x1 = "powershell" nocase
        $x2 = "DownloadString" nocase
        $x3 = "DownloadFile" nocase
        $x4 = "Net.WebClient" nocase
        $x5 = ".Run" nocase
        $x6 = "Shell" nocase
        $x7 = "CreateObject" nocase
        $x8 = "FromBase64String" nocase
        $x9 = "URLDownloadToFile" nocase
    condition:
        $hdr and $auto and 2 of ($x*)
}
