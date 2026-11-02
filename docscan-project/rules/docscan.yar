// Minimal rules file for `yara64.exe --docscan-json <this> <file>`.
// Importing the module makes it run (type detection + structural analysis);
// --docscan-json then prints the findings as JSON. The dummy rule never matches.
import "docscan"

private rule _docscan_probe
{
  condition:
    false
}
