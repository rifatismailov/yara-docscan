package main

// Аудит: кожна дія у вебі — рядок у web.log і запис event "Admin" у docscan-results.json (його читає агент Wazuh).
// Тексти аудиту — англійською (поля для SOC і правил Wazuh). Опис: docscan-project/DOCSCAN.md#web.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

func (s *server) audit(r *http.Request, user, action, detail string) {
	wu := ""
	if r != nil {
		port, _ := strconv.Atoi(s.port)
		wu = winUser(r.RemoteAddr, port) // хто з користувачів Windows (термінальний сервер: веб бачать усі)
	}
	who := user
	if wu != "" {
		who += " (" + wu + ")"
	}
	s.log.Log("AUDIT", "%s %s %s", who, action, detail)
	if err := writeAdminRecord(s.p, s.host, user, action, detail, "web", wu); err != nil {
		s.log.Log("ERROR", "audit record: %v", err)
	}
}

// writeAdminRecord — запис аудиту (event "Admin") у docscan-results.json -> Wazuh. via: web | cli;
// windows_user — обліковий запис Windows, що зробив дію (браузер / командний рядок), якщо відомий.
func writeAdminRecord(p paths, host, user, action, detail, via, wu string) error {
	a := map[string]string{"user": user, "action": action, "detail": detail, "via": via}
	if wu != "" {
		a["windows_user"] = wu
	}
	rec := map[string]any{"timestamp": time.Now().Format("2006-01-02T15:04:05.000-07:00"), "source": "docscan", "host": host,
		"event": "Admin", "admin": a}
	b, _ := json.Marshal(rec)
	return appendLine(p.resultsLog(), append(b, '\n'))
}
