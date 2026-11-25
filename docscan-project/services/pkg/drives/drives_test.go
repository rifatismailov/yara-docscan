package drives

import "testing"

func TestProtected(t *testing.T) {
	for p, want := range map[string]bool{
		`C:\Windows\System32\x.dll`: true, `c:\program files\JetBrains\t.zip`: true, `C:\Program Files (x86)\a`: true,
		`C:\ProgramData\Microsoft\x`: true, `C:\Users\anna\AppData\Local\Programs\Code\a.zip`: true,
		`C:\Users\anna\Documents\a.docx`: false, `C:\ProgramData\evil\a.docm`: false, `D:\Windows\a.docx`: true,
		`C:\Users\anna\Downloads\Program Files\a.docm`: false,
		"/Applications/GoLand.app/Contents/t.zip":      true, "/Users/u/Library/x.docx": true, "/Users/u/Documents/a.docx": false,
	} {
		if Protected(p) != want {
			t.Errorf("Protected(%s) != %v", p, want)
		}
	}
}
