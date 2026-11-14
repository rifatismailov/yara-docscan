/* DocScan sandbox: privilege separation of a docscan run (Windows).

   The watcher runs yara64 as SYSTEM. The process that parses a (possibly hostile) document must not keep
   those rights, so on Windows one yara64.exe runs in two roles:

     BROKER  (the process the watcher starts, SYSTEM)   parses nothing. Starts itself again as the WORKER
             with a locked-down token, passes the worker's output through, and carries out what only it
             may do: write the macro dump (--docscan-extract), append to the critical queue (--critical-out),
             back up / replace / delete the file (--docscan-disarm).
     WORKER  (yara64 --docscan-worker=<pipe> ...)        loads the rules and opens + maps the file while its
             main thread still impersonates a normal token, then drops to the LOCKDOWN token: every group
             and the user deny-only, the NULL SID as the only restricting SID (any access check fails),
             untrusted integrity, no privileges, in a job (1 process, UI limits). Everything that touches
             document bytes - module, rules, second pass, text extraction, disarm plan - runs after that.
             Results go to the broker through the pipe as records.

   The watcher's interface is unchanged: the same command line, the same lines on stdout.
   On other systems everything here is a no-op (docscan_worker_active() == 0). */

#ifndef DOCSCAN_SANDBOX_H
#define DOCSCAN_SANDBOX_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#include <windows.h>

// what the broker needs to know (paths UTF-8, "" = option not given)
typedef struct
{
  const wchar_t* target;       // the file to scan, as given on the command line
  const char* target_utf8;     // the same in UTF-8 (printed in "docscan-disarm: <path> -> ...")
  const char* extract_utf8;    // --docscan-extract
  const char* critical_utf8;   // --critical-out
  const char* backup_utf8;     // --docscan-backup-dir
  long timeout;                // yara --timeout (seconds); the worker is killed a bit later
  int confine_check;           // --docscan-confine-check: test the sandbox instead of scanning
} docscan_broker_cfg;

// Broker: run the docscan scan of one file in a worker. Returns 1 if the worker was started (*exit_code =
// the exit code to return: the worker's own, its crash code, or 1 on a timeout) - then the file must NOT be
// scanned again, whatever happened (a file that kills the worker must never be parsed with full rights);
// 0 if the worker could not be started (nothing was done; the caller may scan in-process).
int docscan_broker_run(const docscan_broker_cfg* cfg, int* exit_code);

// In-process confinement (job object with 1 process + privileges removed) - the broker applies it to
// itself after starting the worker; also used with --docscan-no-sandbox.
void docscan_confine(void);
int docscan_confine_report(void);

// Worker side.
int docscan_worker_init(const char* pipe_arg);   // --docscan-worker=<handle>; 1 = ok
int docscan_worker_active(void);
// open + map the file (target may be NULL), lower the integrity, drop the impersonation; 1 = locked down
int docscan_worker_lockdown(const wchar_t* target);
const uint8_t* docscan_worker_data(size_t* size, int* open_failed);
int docscan_worker_times(FILETIME* created, FILETIME* modified);
int docscan_worker_confine_check(void);          // --docscan-confine-check in the worker: probes

// records worker -> broker: [tag][4-byte length, little endian][payload = a + b]
#define DOCSCAN_REC_EXTRACT  'X'  // payload: decompressed VBA
#define DOCSCAN_REC_CRITICAL 'C'  // payload: message line "\0" queue JSON line
#define DOCSCAN_REC_DISARM   'D'  // payload: kind (1 byte) action "\0" cured bytes
int docscan_worker_send(char tag, const void* a, size_t alen, const void* b, size_t blen);

#else
#define docscan_worker_active() 0
#endif

#endif
