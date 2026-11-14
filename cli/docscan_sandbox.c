/* DocScan sandbox (Windows): broker / worker privilege separation. See docscan_sandbox.h. */

#include "docscan_sandbox.h"

#if defined(_WIN32)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <yara/docscan_disarm.h>

// ================================================================ in-process confinement
// A job object with ActiveProcessLimit = 1 (no child process: cmd / powershell fail to start), UI limits
// (no clipboard, desktops, system settings, logoff), and every privilege REMOVED from the token except
// SeChangeNotify (path traversal). Best effort: a failure is reported by --docscan-confine-check.
static int confined_job = 0;     // 1 - the job object is applied to this process
static int privs_removed = -1;   // number of privileges removed (-1 - not done)

static HANDLE limited_job(void)
{
  HANDLE job = CreateJobObjectW(NULL, NULL);
  if (job == NULL)
    return NULL;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION li;
  memset(&li, 0, sizeof(li));
  li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
                                        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
                                        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  li.BasicLimitInformation.ActiveProcessLimit = 1;
  JOBOBJECT_BASIC_UI_RESTRICTIONS ui;
  ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                           JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_GLOBALATOMS |
                           JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
                           JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_HANDLES;
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &li, sizeof(li)) ||
      !SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui, sizeof(ui)))
  {
    CloseHandle(job);
    return NULL;
  }
  return job;
}

static int count_privileges(HANDLE tok)
{
  DWORD len = 0;
  int n = -1;
  GetTokenInformation(tok, TokenPrivileges, NULL, 0, &len);
  TOKEN_PRIVILEGES* tp = len ? (TOKEN_PRIVILEGES*) malloc(len) : NULL;
  if (tp != NULL && GetTokenInformation(tok, TokenPrivileges, tp, len, &len))
    n = (int) tp->PrivilegeCount;
  free(tp);
  return n;
}

void docscan_confine(void)
{
  HANDLE job = limited_job();
  if (job != NULL)
  {
    if (AssignProcessToJobObject(job, GetCurrentProcess()))
      confined_job = 1;  // the handle stays open for the life of the process
    else
      CloseHandle(job);
  }

  HANDLE tok;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
  {
    DWORD len = 0;
    GetTokenInformation(tok, TokenPrivileges, NULL, 0, &len);
    TOKEN_PRIVILEGES* tp = len ? (TOKEN_PRIVILEGES*) malloc(len) : NULL;
    if (tp != NULL && GetTokenInformation(tok, TokenPrivileges, tp, len, &len))
    {
      LUID keep;
      LookupPrivilegeValueW(NULL, L"SeChangeNotifyPrivilege", &keep);
      DWORD n = 0;
      for (DWORD i = 0; i < tp->PrivilegeCount; i++)
      {
        LUID l = tp->Privileges[i].Luid;
        if (l.LowPart == keep.LowPart && l.HighPart == keep.HighPart)
          continue;
        tp->Privileges[n].Luid = l;
        tp->Privileges[n].Attributes = SE_PRIVILEGE_REMOVED;  // gone for good, cannot be re-enabled
        n++;
      }
      tp->PrivilegeCount = n;
      if (n == 0 || (AdjustTokenPrivileges(tok, FALSE, tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS))
        privs_removed = (int) n;
    }
    free(tp);
    CloseHandle(tok);
  }
}

// 1 if cmd.exe could be started (it must not)
static int try_child_process(void)
{
  wchar_t cmd[] = L"cmd.exe /c exit 0";
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    return 0;
  WaitForSingleObject(pi.hProcess, 5000);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return 1;
}

// lines about this process; 1 = confined
static int confine_lines(const char* who)
{
  int privs_left = -1;
  HANDLE tok;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
  {
    privs_left = count_privileges(tok);
    CloseHandle(tok);
  }
  int started = try_child_process();
  printf("%sjob object: %s\n", who, confined_job ? "applied (1 active process, UI limits)" : "NOT applied");
  printf("%sprivileges removed: %d, left: %d\n", who, privs_removed, privs_left);
  printf("%schild process: %s\n", who, started ? "STARTED (not confined)" : "blocked");
  fflush(stdout);
  return confined_job && !started && privs_left >= 0 && privs_left <= 1;
}

int docscan_confine_report(void)
{
  int ok = confine_lines("");
  printf("sandbox: not used (in-process scan)\n");
  printf("RESULT: %s\n", ok ? "CONFINED" : "NOT CONFINED");
  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

// ================================================================ worker
static HANDLE wk_pipe = NULL;           // result pipe to the broker
static const uint8_t* wk_data = NULL;   // the file, mapped before the lockdown
static size_t wk_size = 0;
static int wk_open_failed = 0;
static FILETIME wk_created, wk_modified;
static int wk_times = 0;
static int wk_privs = -1;               // privileges of the primary token (counted before the lockdown)
static int wk_integrity = -1;           // integrity RID of the primary token after lowering it

int docscan_worker_init(const char* arg)
{
  char* end = NULL;
  unsigned long long v = arg ? strtoull(arg, &end, 10) : 0;
  if (v == 0 || end == NULL || *end != '\0')
    return 0;
  wk_pipe = (HANDLE) (uintptr_t) v;
  return GetFileType(wk_pipe) == FILE_TYPE_PIPE;
}

int docscan_worker_active(void)
{
  return wk_pipe != NULL;
}

static int write_all(HANDLE h, const void* p, size_t n)
{
  const char* c = (const char*) p;
  while (n > 0)
  {
    DWORD chunk = n > 0x100000 ? 0x100000 : (DWORD) n, w = 0;
    if (!WriteFile(h, c, chunk, &w, NULL) || w == 0)
      return 0;
    c += w;
    n -= w;
  }
  return 1;
}

int docscan_worker_send(char tag, const void* a, size_t alen, const void* b, size_t blen)
{
  if (wk_pipe == NULL || alen + blen > 0x7fffffff)
    return 0;
  uint32_t len = (uint32_t) (alen + blen);
  unsigned char hdr[5] = {(unsigned char) tag, (unsigned char) (len & 0xff), (unsigned char) ((len >> 8) & 0xff),
                          (unsigned char) ((len >> 16) & 0xff), (unsigned char) ((len >> 24) & 0xff)};
  return write_all(wk_pipe, hdr, 5) && (alen == 0 || write_all(wk_pipe, a, alen)) &&
         (blen == 0 || write_all(wk_pipe, b, blen));
}

// lower the integrity of the primary token to Untrusted (allowed while still impersonating)
static int lower_integrity(void)
{
  HANDLE tok;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &tok))
    return 0;
  wk_privs = count_privileges(tok);
  SID_IDENTIFIER_AUTHORITY ml = SECURITY_MANDATORY_LABEL_AUTHORITY;
  PSID sid = NULL;
  int ok = 0;
  if (AllocateAndInitializeSid(&ml, 1, SECURITY_MANDATORY_UNTRUSTED_RID, 0, 0, 0, 0, 0, 0, 0, &sid))
  {
    TOKEN_MANDATORY_LABEL tml;
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = sid;
    ok = SetTokenInformation(tok, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(sid));
    FreeSid(sid);
  }
  DWORD len = 0;
  GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &len);
  TOKEN_MANDATORY_LABEL* cur = len ? (TOKEN_MANDATORY_LABEL*) malloc(len) : NULL;
  if (cur != NULL && GetTokenInformation(tok, TokenIntegrityLevel, cur, len, &len))
    wk_integrity = (int) *GetSidSubAuthority(cur->Label.Sid, *GetSidSubAuthorityCount(cur->Label.Sid) - 1);
  free(cur);
  CloseHandle(tok);
  return ok;
}

// 1 if a file can be opened for reading (it must not, after the lockdown)
static int can_read(const wchar_t* path)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                         OPEN_EXISTING, 0, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  CloseHandle(h);
  return 1;
}

int docscan_worker_lockdown(const wchar_t* target)
{
  // 1. the file, while the main thread still impersonates the broker's (restricted) token
  if (target != NULL)
  {
    HANDLE h = CreateFileW(target, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE)
      wk_open_failed = 1;
    else
    {
      LARGE_INTEGER sz;
      if (GetFileTime(h, &wk_created, NULL, &wk_modified))
        wk_times = 1;
      if (!GetFileSizeEx(h, &sz) || (unsigned long long) sz.QuadPart > (size_t) -1)
        wk_open_failed = 1;
      else if (sz.QuadPart > 0)
      {
        HANDLE m = CreateFileMappingW(h, NULL, PAGE_READONLY, 0, 0, NULL);
        if (m != NULL)
        {
          wk_data = (const uint8_t*) MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
          CloseHandle(m);  // the view keeps the mapping
        }
        if (wk_data == NULL)
          wk_open_failed = 1;
        else
          wk_size = (size_t) sz.QuadPart;
      }
      CloseHandle(h);
    }
  }

  // 2. untrusted integrity, 3. drop the impersonation -> only the lockdown token is left
  if (!lower_integrity())
  {
    fprintf(stderr, "error: docscan worker: cannot lower the integrity level (%lu)\n", GetLastError());
    return 0;
  }
  if (!RevertToSelf())
  {
    fprintf(stderr, "error: docscan worker: RevertToSelf failed (%lu)\n", GetLastError());
    return 0;
  }
  HANDLE t = NULL;
  if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &t) || GetLastError() != ERROR_NO_TOKEN)
  {
    if (t != NULL)
      CloseHandle(t);
    fprintf(stderr, "error: docscan worker: still impersonating after RevertToSelf\n");
    return 0;
  }
  return 1;
}

const uint8_t* docscan_worker_data(size_t* size, int* open_failed)
{
  *size = wk_size;
  *open_failed = wk_open_failed;
  return wk_data;
}

int docscan_worker_times(FILETIME* created, FILETIME* modified)
{
  if (!wk_times)
    return 0;
  *created = wk_created;
  *modified = wk_modified;
  return 1;
}

// --docscan-confine-check in the worker: what a hijacked parser could still do. Every probe must fail.
int docscan_worker_confine_check(void)
{
  wchar_t self[MAX_PATH] = L"", winini[MAX_PATH] = L"", tmp[MAX_PATH] = L"", pd[MAX_PATH] = L"";
  GetModuleFileNameW(NULL, self, MAX_PATH);
  GetWindowsDirectoryW(winini, MAX_PATH);
  wcsncat(winini, L"\\win.ini", MAX_PATH - wcslen(winini) - 1);
  DWORD tl = GetTempPathW(MAX_PATH, tmp);
  _snwprintf(tmp + tl, MAX_PATH - tl - 1, L"docscan-probe-%lu.tmp", GetCurrentProcessId());
  _snwprintf(pd, MAX_PATH - 1, L"C:\\ProgramData\\docscan-probe-%lu.tmp", GetCurrentProcessId());

  if (!docscan_worker_lockdown(NULL))
  {
    printf("worker: lockdown FAILED\n");
    return EXIT_FAILURE;
  }
  int r_self = can_read(self), r_ini = can_read(winini);
  int w_tmp = 0, w_pd = 0;
  const wchar_t* wp[2] = {tmp, pd};
  for (int k = 0; k < 2; k++)
  {
    HANDLE h = CreateFileW(wp[k], GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
      CloseHandle(h);
      if (k == 0) w_tmp = 1; else w_pd = 1;
    }
  }
  HKEY key;
  int reg = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_READ, &key) == ERROR_SUCCESS;
  if (reg)
    RegCloseKey(key);
  int child = try_child_process();

  printf("worker: token: lockdown (restricting SID NULL, no privileges), integrity RID %d%s, privileges %d\n",
         wk_integrity, wk_integrity == SECURITY_MANDATORY_UNTRUSTED_RID ? " (untrusted)" : "", wk_privs);
  printf("worker: read own exe: %s\n", r_self ? "ALLOWED" : "blocked");
  printf("worker: read %%WINDIR%%\\win.ini: %s\n", r_ini ? "ALLOWED" : "blocked");
  printf("worker: write %%TEMP%%: %s\n", w_tmp ? "ALLOWED" : "blocked");
  printf("worker: write C:\\ProgramData: %s\n", w_pd ? "ALLOWED" : "blocked");
  printf("worker: registry HKLM\\SOFTWARE: %s\n", reg ? "ALLOWED" : "blocked");
  printf("worker: child process: %s\n", child ? "STARTED" : "blocked");
  fflush(stdout);
  int ok = !r_self && !r_ini && !w_tmp && !w_pd && !reg && !child &&
           wk_integrity == SECURITY_MANDATORY_UNTRUSTED_RID && wk_privs >= 0 && wk_privs <= 1;
  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

// ================================================================ broker
typedef struct
{
  HANDLE from;    // read end of a pipe from the worker
  HANDLE to;      // where to copy it (NULL / invalid - nowhere, unless collect)
  int collect;    // 1 - collect into buf instead
  char* buf;
  size_t len, cap;
} pump_t;

static DWORD WINAPI pump(LPVOID p)
{
  pump_t* s = (pump_t*) p;
  char chunk[65536];
  DWORD n;
  while (ReadFile(s->from, chunk, sizeof(chunk), &n, NULL) && n > 0)
  {
    if (!s->collect)
    {
      DWORD w;
      if (s->to != NULL && s->to != INVALID_HANDLE_VALUE)
        WriteFile(s->to, chunk, n, &w, NULL);
    }
    else
    {
      if (s->len + n > s->cap)
      {
        size_t nc = s->cap ? s->cap * 2 : 1 << 20;
        while (nc < s->len + n) nc *= 2;
        char* nb = (char*) realloc(s->buf, nc);
        if (nb == NULL)
          continue;  // out of memory: the record is lost, reported as truncated below
        s->buf = nb;
        s->cap = nc;
      }
      memcpy(s->buf + s->len, chunk, n);
      s->len += n;
    }
  }
  return 0;
}

static void enable_privilege(const wchar_t* name)
{
  HANDLE tok;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
    return;
  TOKEN_PRIVILEGES tp;
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  if (LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid))
    AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
  CloseHandle(tok);
}

static void* token_info(HANDLE tok, TOKEN_INFORMATION_CLASS cls)
{
  DWORD len = 0;
  GetTokenInformation(tok, cls, NULL, 0, &len);
  void* p = len ? malloc(len) : NULL;
  if (p != NULL && !GetTokenInformation(tok, cls, p, len, &len))
  {
    free(p);
    p = NULL;
  }
  return p;
}

// lockdown: primary token of the worker - DISABLE_MAX_PRIVILEGE (only SeChangeNotify left) and the NULL SID
// as the only restricting SID: every access check is done twice, the second time with the restricting SIDs
// only, and no object grants anything to the NULL SID - so nothing can be opened. (The worker also lowers
// itself to untrusted integrity.) The groups are left as they are: with the NULL SID restricting they give
// no access, and the token keeps the same groups - and so the same "elevation" - as the initial token:
// Windows does not let a non-elevated process impersonate an elevated token of the same user.
// initial: impersonation token of the worker's main thread until it is ready - the broker's access, but
// restricted (Windows lets a restricted process impersonate only a restricted token): restricting SIDs =
// the user + every enabled group + RESTRICTED (S-1-5-12) - many system objects a starting process needs
// (csrss port, \KnownDlls, BaseNamedObjects) grant restricted tokens access only through that SID.
// For the diagnostic matrix: lockdown_deny_only = 1 makes every group deny-only (the first design),
// restricted_sid = 0 leaves S-1-5-12 out; initial_primary = the initial token as a primary token.
static int make_tokens_ex(int lockdown_deny_only, int restricted_sid, HANDLE* lockdown, HANDLE* initial,
                          HANDLE* initial_primary)
{
  *lockdown = *initial = NULL;
  if (initial_primary != NULL)
    *initial_primary = NULL;
  HANDLE self = NULL;
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &self))
    return 0;
  TOKEN_USER* user = (TOKEN_USER*) token_info(self, TokenUser);
  TOKEN_GROUPS* groups = (TOKEN_GROUPS*) token_info(self, TokenGroups);
  int ok = 0;
  SID_AND_ATTRIBUTES* deny = NULL;
  SID_AND_ATTRIBUTES* same = NULL;
  PSID null_sid = NULL;
  BYTE restricted[SECURITY_MAX_SID_SIZE];
  DWORD rlen = sizeof(restricted);
  HANDLE init_primary = NULL;
  SID_IDENTIFIER_AUTHORITY null_auth = SECURITY_NULL_SID_AUTHORITY;
  if (user == NULL || groups == NULL ||
      !AllocateAndInitializeSid(&null_auth, 1, SECURITY_NULL_RID, 0, 0, 0, 0, 0, 0, 0, &null_sid) ||
      !CreateWellKnownSid(WinRestrictedCodeSid, NULL, restricted, &rlen))
    goto done;
  deny = (SID_AND_ATTRIBUTES*) calloc(groups->GroupCount + 1, sizeof(SID_AND_ATTRIBUTES));
  same = (SID_AND_ATTRIBUTES*) calloc(groups->GroupCount + 2, sizeof(SID_AND_ATTRIBUTES));
  if (deny == NULL || same == NULL)
    goto done;
  DWORD nd = 0, ns = 0;
  deny[nd++].Sid = user->User.Sid;
  same[ns++].Sid = user->User.Sid;
  for (DWORD i = 0; i < groups->GroupCount; i++)
  {
    DWORD a = groups->Groups[i].Attributes;
    if (a & SE_GROUP_INTEGRITY)
      continue;  // the integrity label is not a group
    deny[nd++].Sid = groups->Groups[i].Sid;
    if ((a & SE_GROUP_ENABLED) && !(a & SE_GROUP_USE_FOR_DENY_ONLY))
      same[ns++].Sid = groups->Groups[i].Sid;
  }
  if (restricted_sid)
    same[ns++].Sid = (PSID) restricted;
  SID_AND_ATTRIBUTES restrict_null;
  restrict_null.Sid = null_sid;
  restrict_null.Attributes = 0;
  if (!CreateRestrictedToken(self, DISABLE_MAX_PRIVILEGE, lockdown_deny_only ? nd : 0,
                             lockdown_deny_only ? deny : NULL, 0, NULL, 1, &restrict_null, lockdown))
    goto done;
  if (!CreateRestrictedToken(self, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, ns, same, &init_primary) ||
      !DuplicateTokenEx(init_primary, TOKEN_IMPERSONATE | TOKEN_QUERY, NULL, SecurityImpersonation,
                        TokenImpersonation, initial))
    goto done;
  if (initial_primary != NULL)
  {
    *initial_primary = init_primary;
    init_primary = NULL;
  }
  ok = 1;
done:
  if (!ok)
  {
    if (*lockdown != NULL)
      CloseHandle(*lockdown);
    if (*initial != NULL)
      CloseHandle(*initial);
    *lockdown = *initial = NULL;
  }
  if (init_primary != NULL)
    CloseHandle(init_primary);
  if (null_sid != NULL)
    FreeSid(null_sid);
  free(deny);
  free(same);
  free(user);
  free(groups);
  CloseHandle(self);
  return ok;
}

static int make_tokens(HANDLE* lockdown, HANDLE* initial)
{
  return make_tokens_ex(0, 1, lockdown, initial, NULL);
}

static int token_elevated(HANDLE tok)
{
  TOKEN_ELEVATION e;
  DWORD len = 0;
  return GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &len) ? (int) e.TokenIsElevated : -1;
}

// one diagnostic start: "<this exe> --version" with this primary token and (optionally) this impersonation
// token on the main thread -> its exit code (0 = it started and ran); 0xFFFFFFFF = could not create it
static DWORD probe_start(HANDLE primary, HANDLE imp)
{
  wchar_t exe[MAX_PATH], cmd[MAX_PATH + 32];
  if (GetModuleFileNameW(NULL, exe, MAX_PATH) == 0)
    return 0xFFFFFFFF;
  _snwprintf(cmd, MAX_PATH + 32, L"\"%s\" --version", exe);
  cmd[MAX_PATH + 31] = L'\0';
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  HANDLE job = limited_job();
  if (!CreateProcessAsUserW(primary, exe, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL,
                            NULL, &si, &pi))
  {
    if (job != NULL)
      CloseHandle(job);
    return 0xFFFFFFFF;
  }
  if (job != NULL)
    AssignProcessToJobObject(job, pi.hProcess);
  if (imp != NULL)
    SetThreadToken(&pi.hThread, imp);
  ResumeThread(pi.hThread);
  DWORD code = 0xFFFFFFFE;
  if (WaitForSingleObject(pi.hProcess, 15000) == WAIT_TIMEOUT)
    TerminateProcess(pi.hProcess, 0xFFFFFFFE);
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  if (job != NULL)
    CloseHandle(job);
  return code;
}

// --docscan-confine-check: which token combinations can start a process at all
static void probe_matrix(void)
{
  HANDLE L = NULL, I = NULL, IP = NULL;      // production: lockdown (groups kept) + initial with RESTRICTED
  HANDLE Ld = NULL, Id = NULL;               // lockdown with every group deny-only (first design)
  HANDLE L0 = NULL, I0 = NULL, IP0 = NULL;   // initial without RESTRICTED
  HANDLE self = NULL;
  make_tokens_ex(0, 1, &L, &I, &IP);
  make_tokens_ex(1, 1, &Ld, &Id, NULL);
  make_tokens_ex(0, 0, &L0, &I0, &IP0);
  OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &self);
  printf("probe: elevated: broker=%d lockdown=%d lockdown(deny-only)=%d initial=%d\n", self ? token_elevated(self) : -1,
         L ? token_elevated(L) : -1, Ld ? token_elevated(Ld) : -1, I ? token_elevated(I) : -1);
  printf("probe: initial (+RESTRICTED) as primary:          0x%08lx\n", IP ? probe_start(IP, NULL) : 0xFFFFFFFFUL);
  printf("probe: initial (no RESTRICTED) as primary:        0x%08lx\n", IP0 ? probe_start(IP0, NULL) : 0xFFFFFFFFUL);
  printf("probe: lockdown + initial  (used by the sandbox): 0x%08lx\n", L && I ? probe_start(L, I) : 0xFFFFFFFFUL);
  printf("probe: lockdown(deny-only) + initial:             0x%08lx\n", Ld && I ? probe_start(Ld, I) : 0xFFFFFFFFUL);
  printf("probe: lockdown, no impersonation:                0x%08lx\n", L ? probe_start(L, NULL) : 0xFFFFFFFFUL);
  fflush(stdout);
  HANDLE hs[] = {L, I, IP, Ld, Id, L0, I0, IP0, self};
  for (size_t i = 0; i < sizeof(hs) / sizeof(hs[0]); i++)
    if (hs[i] != NULL)
      CloseHandle(hs[i]);
}

static FILE* wfopen_utf8(const char* path, const wchar_t* mode)
{
  wchar_t w[4096];
  if (MultiByteToWideChar(CP_UTF8, 0, path, -1, w, 4096) == 0)
    return NULL;
  return _wfopen(w, mode);
}

static int file_stamp(const wchar_t* path, WIN32_FILE_ATTRIBUTE_DATA* fa)
{
  return GetFileAttributesExW(path, GetFileExInfoStandard, fa) != 0;
}

// carry out the worker's records (all of them complete and in order)
static void apply_records(const docscan_broker_cfg* cfg, const char* buf, size_t len,
                          const WIN32_FILE_ATTRIBUTE_DATA* before)
{
  size_t off = 0;
  while (off + 5 <= len)
  {
    char tag = buf[off];
    uint32_t n = (uint32_t) (unsigned char) buf[off + 1] | ((uint32_t) (unsigned char) buf[off + 2] << 8) |
                 ((uint32_t) (unsigned char) buf[off + 3] << 16) | ((uint32_t) (unsigned char) buf[off + 4] << 24);
    if (off + 5 + n > len)
    {
      fprintf(stderr, "error: docscan worker: truncated result\n");
      return;
    }
    const char* p = buf + off + 5;
    off += 5 + n;

    if (tag == DOCSCAN_REC_EXTRACT && cfg->extract_utf8[0])
    {
      FILE* fh = wfopen_utf8(cfg->extract_utf8, L"wb");
      if (fh != NULL)
      {
        fwrite(p, 1, n, fh);
        fclose(fh);
      }
    }
    else if (tag == DOCSCAN_REC_CRITICAL && cfg->critical_utf8[0])
    {
      size_t ml = strnlen(p, n);
      if (ml >= n)
        continue;
      const char* json = p + ml + 1;
      size_t jl = n - ml - 1;
      // one line, one write, appended; the reader takes the file by renaming it
      FILE* q = wfopen_utf8(cfg->critical_utf8, L"ab");
      int ok = q != NULL && fwrite(json, 1, jl, q) == jl;
      if (q != NULL && fclose(q) != 0)
        ok = 0;
      if (ok)
        fwrite(p, 1, ml, stdout);
      else
        fputs("docscan-critical: could not write the queue file - not queued\n", stderr);
      fflush(stdout);
    }
    else if (tag == DOCSCAN_REC_DISARM && n >= 2)
    {
      int kind = (unsigned char) p[0];
      size_t al = strnlen(p + 1, n - 1);
      if (1 + al >= n)
        continue;
      const char* plan = p + 1;
      const unsigned char* cured = (const unsigned char*) (p + 1 + al + 1);
      size_t cl = n - 1 - al - 1;
      char action[256] = "";
      WIN32_FILE_ATTRIBUTE_DATA now;
      // the worker saw the file as it was when it started: never replace or delete a newer version
      if ((kind == DOCSCAN_DISARM_DELETE || kind == DOCSCAN_DISARM_REPLACE) &&
          (!file_stamp(cfg->target, &now) || now.nFileSizeLow != before->nFileSizeLow ||
           now.nFileSizeHigh != before->nFileSizeHigh ||
           CompareFileTime(&now.ftLastWriteTime, &before->ftLastWriteTime) != 0))
        snprintf(action, sizeof(action), "failed:changed");
      else
        docscan_disarm_apply(cfg->target_utf8, cfg->backup_utf8[0] ? cfg->backup_utf8 : NULL, kind, cured, cl,
                             plan, action, sizeof(action));
      printf("docscan-disarm: %s -> %s\n", cfg->target_utf8, action[0] ? action : "none");
      fflush(stdout);
    }
  }
}

static int make_pipe(HANDLE* r, HANDLE* w)
{
  SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
  if (!CreatePipe(r, w, &sa, 0))
    return 0;
  SetHandleInformation(*r, HANDLE_FLAG_INHERIT, 0);  // only the write end goes to the worker
  return 1;
}

int docscan_broker_run(const docscan_broker_cfg* cfg, int* exit_code)
{
  HANDLE lockdown = NULL, initial = NULL, job = NULL;
  HANDLE out_r = NULL, out_w = NULL, err_r = NULL, err_w = NULL, res_r = NULL, res_w = NULL, nul = NULL;
  PROCESS_INFORMATION pi;
  memset(&pi, 0, sizeof(pi));
  LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
  wchar_t* cmd = NULL;
  int rc = EXIT_FAILURE, started = 0;
  WIN32_FILE_ATTRIBUTE_DATA before;
  memset(&before, 0, sizeof(before));
  if (cfg->target != NULL)
    file_stamp(cfg->target, &before);

  enable_privilege(L"SeIncreaseQuotaPrivilege");
  enable_privilege(L"SeAssignPrimaryTokenPrivilege");
  if (cfg->confine_check)
    probe_matrix();  // which token combinations can start a process (diagnostics in the CI log)
  if (!make_tokens(&lockdown, &initial) || (job = limited_job()) == NULL)
    goto fail;
  SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
  nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
  if (nul == INVALID_HANDLE_VALUE)
    nul = NULL;
  if (nul == NULL || !make_pipe(&out_r, &out_w) || !make_pipe(&err_r, &err_w) || !make_pipe(&res_r, &res_w))
    goto fail;

  // command line: "<this exe>" --docscan-worker=<pipe> <the original arguments>
  wchar_t exe[MAX_PATH];
  if (GetModuleFileNameW(NULL, exe, MAX_PATH) == 0)
    goto fail;
  const wchar_t* rest = GetCommandLineW();
  if (*rest == L'"')
  {
    rest++;
    while (*rest && *rest != L'"') rest++;
    if (*rest) rest++;
  }
  else
    while (*rest && *rest != L' ' && *rest != L'\t') rest++;
  size_t cl = wcslen(exe) + wcslen(rest) + 64;
  cmd = (wchar_t*) malloc(cl * sizeof(wchar_t));
  if (cmd == NULL)
    goto fail;
  _snwprintf(cmd, cl, L"\"%s\" --docscan-worker=%llu%s", exe, (unsigned long long) (uintptr_t) res_w, rest);
  cmd[cl - 1] = L'\0';

  // the worker inherits exactly these handles
  HANDLE inherit[4] = {nul, out_w, err_w, res_w};
  SIZE_T asz = 0;
  InitializeProcThreadAttributeList(NULL, 1, 0, &asz);
  attrs = (LPPROC_THREAD_ATTRIBUTE_LIST) malloc(asz);
  if (attrs == NULL || !InitializeProcThreadAttributeList(attrs, 1, 0, &asz) ||
      !UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit, sizeof(inherit), NULL, NULL))
  {
    free(attrs);
    attrs = NULL;
    goto fail;
  }
  STARTUPINFOEXW si;
  memset(&si, 0, sizeof(si));
  si.StartupInfo.cb = sizeof(si);
  si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  si.StartupInfo.hStdInput = nul;
  si.StartupInfo.hStdOutput = out_w;
  si.StartupInfo.hStdError = err_w;
  si.lpAttributeList = attrs;
  if (!CreateProcessAsUserW(lockdown, exe, cmd, NULL, NULL, TRUE,
                            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                            &si.StartupInfo, &pi))
    goto fail;
  // still suspended: into the job, the initial token on the main thread, then run
  if (!AssignProcessToJobObject(job, pi.hProcess) || !SetThreadToken(&pi.hThread, initial) ||
      ResumeThread(pi.hThread) == (DWORD) -1)
  {
    TerminateProcess(pi.hProcess, 1);
    goto fail;
  }
  started = 1;  // from here on the file is never scanned again in-process
  CloseHandle(out_w); out_w = NULL;
  CloseHandle(err_w); err_w = NULL;
  CloseHandle(res_w); res_w = NULL;
  CloseHandle(initial); initial = NULL;
  CloseHandle(lockdown); lockdown = NULL;

  // the broker needs no privileges and no child processes from now on
  docscan_confine();

  pump_t po = {out_r, GetStdHandle(STD_OUTPUT_HANDLE), 0, NULL, 0, 0};
  pump_t pe = {err_r, GetStdHandle(STD_ERROR_HANDLE), 0, NULL, 0, 0};
  pump_t pr = {res_r, NULL, 1, NULL, 0, 0};
  fflush(stdout);
  fflush(stderr);
  HANDLE th[3] = {CreateThread(NULL, 0, pump, &po, 0, NULL), CreateThread(NULL, 0, pump, &pe, 0, NULL),
                  CreateThread(NULL, 0, pump, &pr, 0, NULL)};
  long secs = cfg->timeout > 0 && cfg->timeout < 600 ? cfg->timeout + 30 : 630;
  int timed_out = WaitForSingleObject(pi.hProcess, (DWORD) secs * 1000) == WAIT_TIMEOUT;
  if (timed_out)
    TerminateJobObject(job, 1);
  WaitForSingleObject(pi.hProcess, 30000);
  for (int i = 0; i < 3; i++)
    if (th[i] != NULL)
    {
      WaitForSingleObject(th[i], 30000);
      CloseHandle(th[i]);
    }
  DWORD code = 1;
  GetExitCodeProcess(pi.hProcess, &code);

  if (timed_out)
  {
    fprintf(stderr, "error: docscan worker timed out after %ld s\n", secs);
    rc = EXIT_FAILURE;
  }
  else if (code >= 0xC0000000UL)
  {
    // the crash code is passed on as it is: tests tell a crash (NTSTATUS) from an error (1)
    fprintf(stderr, "error: docscan worker crashed (0x%08lx)\n", code);
    rc = (int) code;
  }
  else if (cfg->confine_check)
  {
    int ok = confine_lines("broker: ") && code == 0;
    printf("RESULT: %s\n", ok ? "CONFINED" : "NOT CONFINED");
    rc = ok ? EXIT_SUCCESS : EXIT_FAILURE;
  }
  else
  {
    apply_records(cfg, pr.buf, pr.len, &before);
    rc = (int) code;
  }
  free(pr.buf);
  goto done;

fail:
done:
  if (attrs != NULL)
  {
    DeleteProcThreadAttributeList(attrs);
    free(attrs);
  }
  free(cmd);
  HANDLE hs[] = {pi.hThread, pi.hProcess, lockdown, initial, out_r, out_w, err_r, err_w, res_r, res_w, nul, job};
  for (size_t i = 0; i < sizeof(hs) / sizeof(hs[0]); i++)
    if (hs[i] != NULL)
      CloseHandle(hs[i]);
  *exit_code = rc;
  return started;
}

#endif  // _WIN32
