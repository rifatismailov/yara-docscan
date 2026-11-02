/*
Copyright (c) 2007-2021. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#if !defined(_WIN32) && !defined(__CYGWIN__)

// for getline(3)
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>

#else

#include <fcntl.h>
#include <io.h>
#include <windows.h>

#define PRIx64 "I64x"
#define PRId64 "I64d"

#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yara.h>
#include <yara/docscan_disarm.h>

#include "args.h"
#include "common.h"
#include "threading.h"
#include "unicode.h"

#define ERROR_COULD_NOT_CREATE_THREAD 100

#ifndef min
#define min(x, y) ((x < y) ? (x) : (y))
#endif

#define MAX_ARGS_TAG         32
#define MAX_ARGS_IDENTIFIER  32
#define MAX_ARGS_EXT_VAR     32
#define MAX_ARGS_MODULE_DATA 32
#define MAX_QUEUED_FILES     64

#define exit_with_code(code) \
  {                          \
    result = code;           \
    goto _exit;              \
  }

typedef struct _MODULE_DATA
{
  const char* module_name;
  YR_MAPPED_FILE mapped_file;
  struct _MODULE_DATA* next;

} MODULE_DATA;

// Per-file docscan state. The module is unloaded before rule callbacks run,
// so its facts are copied at CALLBACK_MSG_MODULE_IMPORTED; matching policy
// rules (meta.severity) are collected at CALLBACK_MSG_RULE_MATCHING; the JSON
// line is printed at CALLBACK_MSG_SCAN_FINISHED.
typedef struct _DOCSCAN_STATE
{
  int active;                // docscan module ran for this file
  const char* ftype;
  char template_url[512];
  char dde_command[512];
  char vba_evidence[512];
  char lnk_target[512];
  char lnk_args[512];
  char* vba;                 // copy of docscan.vba_code (Layer-2 re-scan)
  size_t vba_len;
  int max_severity;          // 0 INFO, 1 MEDIUM, 2 HIGH
  char findings[2048];       // JSON tokens: "A","B"
  char details[8192];        // JSON objects, one per matching policy rule
  char file_matches[4096];   // JSON tokens: vendor rules matching the raw file
  docscan_disarm_info ds;    // what --docscan-disarm should remove
} DOCSCAN_STATE;

typedef struct _CALLBACK_ARGS
{
  const char_t* file_path;
  int current_count;
  DOCSCAN_STATE dsc;

} CALLBACK_ARGS;

typedef struct _THREAD_ARGS
{
  YR_SCANNER* scanner;
  CALLBACK_ARGS callback_args;
  time_t deadline;
  int current_count;

} THREAD_ARGS;

typedef struct _QUEUED_FILE
{
  char_t* path;

} QUEUED_FILE;

typedef struct COMPILER_RESULTS
{
  int errors;
  int warnings;

} COMPILER_RESULTS;

typedef struct SCAN_OPTIONS
{
  bool follow_symlinks;
  bool recursive_search;
  time_t deadline;

} SCAN_OPTIONS;

#define MAX_ARGS_TAG         32
#define MAX_ARGS_IDENTIFIER  32
#define MAX_ARGS_EXT_VAR     32
#define MAX_ARGS_MODULE_DATA 32

static char* atom_quality_table;
static char* tags[MAX_ARGS_TAG + 1];
static char* identifiers[MAX_ARGS_IDENTIFIER + 1];
static char* ext_vars[MAX_ARGS_EXT_VAR + 1];
static char* modules_data[MAX_ARGS_MODULE_DATA + 1];

static bool follow_symlinks = true;
static bool recursive_search = false;
static bool scan_list_search = false;
static bool show_module_data = false;
static bool show_tags = false;
static bool show_stats = false;
static bool show_strings = false;
static bool show_string_length = false;
static bool show_xor_key = false;
static bool show_meta = false;
static bool show_module_names = false;
static bool show_namespace = false;
static bool show_version = false;
static bool show_help = false;
static bool ignore_warnings = false;
static bool fast_scan = false;
static bool negate = false;
static bool print_count_only = false;
static bool strict_escape = false;
static bool fail_on_warnings = false;
static bool rules_are_compiled = false;
static bool disable_console_logs = false;
static bool docscan_json = false;
static char* docscan_extract = NULL;
static bool docscan_disarm_flag = false;
static YR_RULES* g_rules = NULL;  // loaded rules, for Layer-2 VBA re-scan
static long total_count = 0;
static long limit = 0;
static long timeout = 1000000;
static long stack_size = DEFAULT_STACK_SIZE;
static long threads = YR_MAX_THREADS;
static long max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE;
static long max_process_memory_chunk = DEFAULT_MAX_PROCESS_MEMORY_CHUNK;
static long long skip_larger = 0;

#define USAGE_STRING \
  "Usage: yara [OPTION]... [NAMESPACE:]RULES_FILE... FILE | DIR | PID"

args_option_t options[] = {
    OPT_STRING(
        0,
        _T("atom-quality-table"),
        &atom_quality_table,
        _T("path to a file with the atom quality table"),
        _T("FILE")),

    OPT_BOOLEAN(
        'C',
        _T("compiled-rules"),
        &rules_are_compiled,
        _T("load compiled rules")),

    OPT_BOOLEAN(
        0,
        _T("docscan-json"),
        &docscan_json,
        _T("print docscan module findings as JSON")),

    OPT_STRING(
        0,
        _T("docscan-extract"),
        &docscan_extract,
        _T("write decompressed VBA to FILE (for a 2nd vendor-rules scan)"),
        _T("FILE")),

    OPT_BOOLEAN(
        0,
        _T("docscan-disarm"),
        &docscan_disarm_flag,
        _T("cure (disarm) the document in place if a HIGH vector is found")),

    OPT_BOOLEAN(
        'c',
        _T("count"),
        &print_count_only,
        _T("print only number of matches")),

    OPT_BOOLEAN(
        'E',
        _T("strict-escape"),
        &strict_escape,
        _T("warn on unknown escape sequences")),

    OPT_STRING_MULTI(
        'd',
        _T("define"),
        &ext_vars,
        MAX_ARGS_EXT_VAR,
        _T("define external variable"),
        _T("VAR=VALUE")),

    OPT_BOOLEAN(
        'q',
        _T("disable-console-logs"),
        &disable_console_logs,
        _T("disable printing console log messages")),

    OPT_BOOLEAN(
        0,
        _T("fail-on-warnings"),
        &fail_on_warnings,
        _T("fail on warnings")),

    OPT_BOOLEAN('f', _T("fast-scan"), &fast_scan, _T("fast matching mode")),

    OPT_BOOLEAN('h', _T("help"), &show_help, _T("show this help and exit")),

    OPT_STRING_MULTI(
        'i',
        _T("identifier"),
        &identifiers,
        MAX_ARGS_IDENTIFIER,
        _T("print only rules named IDENTIFIER"),
        _T("IDENTIFIER")),

    OPT_LONG(
        0,
        _T("max-process-memory-chunk"),
        &max_process_memory_chunk,
        _T("set maximum chunk size while reading process memory")
        _T(" (default=1073741824)"),
        _T("NUMBER")),

    OPT_LONG(
        'l',
        _T("max-rules"),
        &limit,
        _T("abort scanning after matching a NUMBER of rules"),
        _T("NUMBER")),

    OPT_LONG(
        0,
        _T("max-strings-per-rule"),
        &max_strings_per_rule,
        _T("set maximum number of strings per rule (default=10000)"),
        _T("NUMBER")),

    OPT_STRING_MULTI(
        'x',
        _T("module-data"),
        &modules_data,
        MAX_ARGS_MODULE_DATA,
        _T("pass FILE's content as extra data to MODULE"),
        _T("MODULE=FILE")),

    OPT_BOOLEAN(
        'n',
        _T("negate"),
        &negate,
        _T("print only not satisfied rules (negate)"),
        NULL),

    OPT_BOOLEAN(
        'N',
        _T("no-follow-symlinks"),
        &follow_symlinks,
        _T("do not follow symlinks when scanning")),

    OPT_BOOLEAN(
        'w',
        _T("no-warnings"),
        &ignore_warnings,
        _T("disable warnings")),

    OPT_BOOLEAN('m', _T("print-meta"), &show_meta, _T("print metadata")),

    OPT_BOOLEAN(
        'D',
        _T("print-module-data"),
        &show_module_data,
        _T("print module data")),

    OPT_BOOLEAN(
        'M',
        _T("module-names"),
        &show_module_names,
        _T("show module names")),

    OPT_BOOLEAN(
        'e',
        _T("print-namespace"),
        &show_namespace,
        _T("print rules' namespace")),

    OPT_BOOLEAN(
        'S',
        _T("print-stats"),
        &show_stats,
        _T("print rules' statistics")),

    OPT_BOOLEAN(
        's',
        _T("print-strings"),
        &show_strings,
        _T("print matching strings")),

    OPT_BOOLEAN(
        'L',
        _T("print-string-length"),
        &show_string_length,
        _T("print length of matched strings")),

    OPT_BOOLEAN(
        'X',
        _T("print-xor-key"),
        &show_xor_key,
        _T("print xor key and plaintext of matched strings")),

    OPT_BOOLEAN('g', _T("print-tags"), &show_tags, _T("print tags")),

    OPT_BOOLEAN(
        'r',
        _T("recursive"),
        &recursive_search,
        _T("recursively search directories")),

    OPT_BOOLEAN(
        0,
        _T("scan-list"),
        &scan_list_search,
        _T("scan files listed in FILE, one per line")),

    OPT_LONG_LONG(
        'z',
        _T("skip-larger"),
        &skip_larger,
        _T("skip files larger than the given size when scanning a directory"),
        _T("NUMBER")),

    OPT_LONG(
        'k',
        _T("stack-size"),
        &stack_size,
        _T("set maximum stack size (default=16384)"),
        _T("SLOTS")),

    OPT_STRING_MULTI(
        't',
        _T("tag"),
        &tags,
        MAX_ARGS_TAG,
        _T("print only rules tagged as TAG"),
        _T("TAG")),

    OPT_LONG(
        'p',
        _T("threads"),
        &threads,
        _T("use the specified NUMBER of threads to scan a directory"),
        _T("NUMBER")),

    OPT_LONG(
        'a',
        _T("timeout"),
        &timeout,
        _T("abort scanning after the given number of SECONDS"),
        _T("SECONDS")),

    OPT_BOOLEAN(
        'v',
        _T("version"),
        &show_version,
        _T("show version information")),

    OPT_END(),
};

// file_queue is size-limited queue stored as a circular array, files are
// removed from queue_head position and new files are added at queue_tail
// position. The array has room for one extra element to avoid queue_head
// being equal to queue_tail in a full queue. The only situation where
// queue_head == queue_tail is when queue is empty.

QUEUED_FILE file_queue[MAX_QUEUED_FILES + 1];

int queue_head;
int queue_tail;

SEMAPHORE used_slots;
SEMAPHORE unused_slots;

MUTEX queue_mutex;
MUTEX output_mutex;

MODULE_DATA* modules_data_list = NULL;

static int file_queue_init()
{
  int result;

  queue_tail = 0;
  queue_head = 0;

  result = cli_mutex_init(&queue_mutex);

  if (result != 0)
    return result;

  result = cli_semaphore_init(&used_slots, 0);

  if (result != 0)
    return result;

  return cli_semaphore_init(&unused_slots, MAX_QUEUED_FILES);
}

static void file_queue_destroy()
{
  cli_mutex_destroy(&queue_mutex);
  cli_semaphore_destroy(&unused_slots);
  cli_semaphore_destroy(&used_slots);
}

static void file_queue_finish()
{
  for (int i = 0; i < YR_MAX_THREADS; i++) cli_semaphore_release(&used_slots);
}

static int file_queue_put(const char_t* file_path, time_t deadline)
{
  if (cli_semaphore_wait(&unused_slots, deadline) == ERROR_SCAN_TIMEOUT)
    return ERROR_SCAN_TIMEOUT;

  cli_mutex_lock(&queue_mutex);

  file_queue[queue_tail].path = _tcsdup(file_path);
  queue_tail = (queue_tail + 1) % (MAX_QUEUED_FILES + 1);

  cli_mutex_unlock(&queue_mutex);
  cli_semaphore_release(&used_slots);

  return ERROR_SUCCESS;
}

static char_t* file_queue_get(time_t deadline)
{
  char_t* result;

  if (cli_semaphore_wait(&used_slots, deadline) == ERROR_SCAN_TIMEOUT)
    return NULL;

  cli_mutex_lock(&queue_mutex);

  if (queue_head == queue_tail)  // queue is empty
  {
    result = NULL;
  }
  else
  {
    result = file_queue[queue_head].path;
    queue_head = (queue_head + 1) % (MAX_QUEUED_FILES + 1);
  }

  cli_mutex_unlock(&queue_mutex);
  cli_semaphore_release(&unused_slots);

  return result;
}

#if defined(_WIN32) || defined(__CYGWIN__)

static bool is_directory(const char_t* path)
{
  DWORD attributes = GetFileAttributes(path);

  if (attributes != INVALID_FILE_ATTRIBUTES &&
      attributes & FILE_ATTRIBUTE_DIRECTORY)
    return true;
  else
    return false;
}

static int scan_dir(const char_t* dir, SCAN_OPTIONS* scan_opts)
{
  int result = ERROR_SUCCESS;
  char_t path[YR_MAX_PATH];

  _sntprintf(path, YR_MAX_PATH, _T("%s\\*"), dir);

  WIN32_FIND_DATA FindFileData;
  HANDLE hFind = FindFirstFile(path, &FindFileData);

  if (hFind != INVALID_HANDLE_VALUE)
  {
    do
    {
      _sntprintf(path, YR_MAX_PATH, _T("%s\\%s"), dir, FindFileData.cFileName);

      // If symbolic links must not be followed, and this entry is a symbolic
      // link, ignore it and continue with the next one.
      if (!scan_opts->follow_symlinks && 
          FindFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) 
      {
        continue;
      }

      if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
      {
        LARGE_INTEGER file_size;

        file_size.HighPart = FindFileData.nFileSizeHigh;
        file_size.LowPart = FindFileData.nFileSizeLow;

        if (skip_larger > file_size.QuadPart || skip_larger <= 0)
        {
          result = file_queue_put(path, scan_opts->deadline);
        }
        else if (!ignore_warnings)
        {
          _ftprintf(
              stderr,
              _T("skipping %s (%" PRIu64
                 " bytes) because it's larger than %lld bytes.\n"),
              path,
              file_size.QuadPart,
              skip_larger);
        }
      }
      else if (
          scan_opts->recursive_search &&
          _tcscmp(FindFileData.cFileName, _T(".")) != 0 &&
          _tcscmp(FindFileData.cFileName, _T("..")) != 0)
      {
        result = scan_dir(path, scan_opts);
      }

    } while (result != ERROR_SCAN_TIMEOUT &&
             FindNextFile(hFind, &FindFileData));

    FindClose(hFind);
  }

  return result;
}

static int scan_file(YR_SCANNER* scanner, const char_t* filename)
{
  YR_FILE_DESCRIPTOR fd = CreateFile(
      filename,
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      FILE_FLAG_SEQUENTIAL_SCAN,
      NULL);

  if (fd == INVALID_HANDLE_VALUE)
    return ERROR_COULD_NOT_OPEN_FILE;

  int result = yr_scanner_scan_fd(scanner, fd);

  CloseHandle(fd);

  return result;
}

static int populate_scan_list(const char_t* filename, SCAN_OPTIONS* scan_opts)
{
  char_t* context;
  DWORD nread;
  int result = ERROR_SUCCESS;

  HANDLE hFile = CreateFile(
      filename,
      GENERIC_READ,
      FILE_SHARE_READ,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL);

  if (hFile == INVALID_HANDLE_VALUE)
  {
    _ftprintf(stderr, _T("error: could not open file \"%s\".\n"), filename);
    return ERROR_COULD_NOT_OPEN_FILE;
  }

  DWORD fileSize = GetFileSize(hFile, NULL);

  if (fileSize == INVALID_FILE_SIZE)
  {
    _ftprintf(
        stderr,
        _T("error: could not determine size of file \"%s\".\n"),
        filename);
    CloseHandle(hFile);
    return ERROR_COULD_NOT_READ_FILE;
  }

  // INVALID_FILE_SIZE is 0xFFFFFFFF, so (+1) will not overflow
  char_t* buf = (char_t*) VirtualAlloc(
      NULL, fileSize + 1, MEM_COMMIT, PAGE_READWRITE);

  if (buf == NULL)
  {
    _ftprintf(
        stderr,
        _T("error: could not allocate memory for file \"%s\".\n"),
        filename);
    CloseHandle(hFile);
    return ERROR_INSUFFICIENT_MEMORY;
  }

  DWORD total = 0;

  while (total < fileSize)
  {
    if (!ReadFile(hFile, buf + total, fileSize - total, &nread, NULL))
    {
      _ftprintf(stderr, _T("error: could not read file \"%s\".\n"), filename);
      CloseHandle(hFile);
      return ERROR_COULD_NOT_READ_FILE;
    }
    total += nread;
  }

  char_t* path = _tcstok_s(buf, _T("\n"), &context);

  while (result != ERROR_SCAN_TIMEOUT && path != NULL)
  {
    // Remove trailing carriage return, if present.
    if (*path != '\0')
    {
      char_t* final = path + _tcslen(path) - 1;

      if (*final == '\r')
        *final = '\0';
    }

    if (is_directory(path))
      result = scan_dir(path, scan_opts);
    else
      result = file_queue_put(path, scan_opts->deadline);

    path = _tcstok_s(NULL, _T("\n"), &context);
  }

  CloseHandle(hFile);

  return result;
}

#else

static bool is_directory(const char* path)
{
  struct stat st;

  if (stat(path, &st) == 0)
    return S_ISDIR(st.st_mode);

  return 0;
}

static int scan_dir(const char* dir, SCAN_OPTIONS* scan_opts)
{
  int result = ERROR_SUCCESS;
  DIR* dp = opendir(dir);

  if (dp)
  {
    struct dirent* de = readdir(dp);

    char* full_path = calloc(YR_MAX_PATH, sizeof(char));
    const size_t full_path_size = YR_MAX_PATH * sizeof(char);

    while (de && result != ERROR_SCAN_TIMEOUT)
    {
      struct stat st;

      snprintf(full_path, full_path_size, "%s/%s", dir, de->d_name);

      int err = lstat(full_path, &st);

      // If lstat returned error, or this directory entry is a symlink and the
      // user doesn't want to follow symlinks, skip the entry and continue with
      // the next one.
      if (err != 0 || (S_ISLNK(st.st_mode) && !scan_opts->follow_symlinks))
      {
        de = readdir(dp);
        continue;
      }
      // If the directory entry is a symlink, check if it points to . or .. and
      // skip it in those cases.
      else if (S_ISLNK(st.st_mode))
      {
        char buf[2];
        int len = readlink(full_path, buf, sizeof(buf));

        if ((len == 1 && buf[0] == '.') ||
            (len == 2 && buf[0] == '.' && buf[1] == '.'))
        {
          de = readdir(dp);
          continue;
        }
      }

      err = stat(full_path, &st);

      if (err == 0)
      {
        if (S_ISREG(st.st_mode))
        {
          if (skip_larger > st.st_size || skip_larger <= 0)
          {
            result = file_queue_put(full_path, scan_opts->deadline);
          }
          else if (!ignore_warnings)
          {
            fprintf(
                stderr,
                "skipping %s (%" PRId64 " bytes) because it's larger than %lld"
                " bytes.\n",
                full_path,
                st.st_size,
                skip_larger);
          }
        }
        else if (
            scan_opts->recursive_search && S_ISDIR(st.st_mode) &&
            strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
        {
          result = scan_dir(full_path, scan_opts);
        }
      }

      de = readdir(dp);
    }

    free(full_path);
    closedir(dp);
  }

  return result;
}

static int scan_file(YR_SCANNER* scanner, const char_t* filename)
{
  YR_FILE_DESCRIPTOR fd = open(filename, O_RDONLY);

  if (fd == -1)
    return ERROR_COULD_NOT_OPEN_FILE;

  int result = yr_scanner_scan_fd(scanner, fd);

  close(fd);

  return result;
}

static int populate_scan_list(const char* filename, SCAN_OPTIONS* scan_opts)
{
  size_t nsize = 0;
  ssize_t nread;
  char* path = NULL;
  int result = ERROR_SUCCESS;

  FILE* fh_scan_list = fopen(filename, "r");

  if (fh_scan_list == NULL)
  {
    fprintf(stderr, "error: could not open file \"%s\".\n", filename);
    return ERROR_COULD_NOT_OPEN_FILE;
  }

  while (result != ERROR_SCAN_TIMEOUT &&
         (nread = getline(&path, &nsize, fh_scan_list)) != -1)
  {
    // remove trailing newline
    if (nread && path[nread - 1] == '\n')
    {
      path[nread - 1] = '\0';
      nread--;
    }

    if (is_directory(path))
      result = scan_dir(path, scan_opts);
    else
      result = file_queue_put(path, scan_opts->deadline);
  }

  free(path);
  fclose(fh_scan_list);

  return result;
}

#endif

static void print_string(const uint8_t* data, int length, uint8_t xor_key)
{
  for (int i = 0; i < length; i++)
  {
    uint8_t c = data[i] ^ xor_key;
    if (c >= 32 && c <= 126)
      _tprintf(_T("%c"), c);
    else
      _tprintf(_T("\\x%02X"), c);
  }
}

static char cescapes[] = {
    0, 0, 0, 0, 0, 0, 0, 'a', 'b', 't', 'n', 'v', 'f', 'r', 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,   0,   0,   0,   0,   0,   0,   0, 0,
};

static void print_escaped_data(const uint8_t* data, size_t length)
{
  for (size_t i = 0; i < length; i++)
  {
    switch (data[i])
    {
    case '\"':
    case '\'':
    case '\\':
      _tprintf(_T("\\%" PF_C), data[i]);
      break;

    default:
      if (data[i] >= 127)
        _tprintf(_T("\\%03o"), data[i]);
      else if (data[i] >= 32)
        _tprintf(_T("%" PF_C), data[i]);
      else if (cescapes[data[i]] != 0)
        _tprintf(_T("\\%" PF_C), cescapes[data[i]]);
      else
        _tprintf(_T("\\%03o"), data[i]);
    }
  }
}

void print_escaped_file_path(const char_t* str) {
    for (size_t i = 0; str[i] != '\0'; ++i) {
        if (str[i] == _T('\n')) {
            _tprintf(_T("\\n"));
        } else if (str[i] == _T('\r')) {
            _tprintf(_T("\\r"));
        }
        else {
            _tprintf(_T("%c"), str[i]);
        }
    }
    _tprintf(_T("\n"));
}

static void print_hex_string(const uint8_t* data, int length)
{
  for (int i = 0; i < min(64, length); i++)
    _tprintf(_T("%s%02X"), (i == 0 ? _T("") : _T(" ")), data[i]);

  if (length > 64)
    _tprintf(_T(" ..."));
}

static void print_error(int error)
{
  switch (error)
  {
  case ERROR_SUCCESS:
    break;
  case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
    fprintf(stderr, "can not attach to process (try running as root)\n");
    break;
  case ERROR_INSUFFICIENT_MEMORY:
    fprintf(stderr, "not enough memory\n");
    break;
  case ERROR_SCAN_TIMEOUT:
    fprintf(stderr, "scanning timed out\n");
    break;
  case ERROR_COULD_NOT_OPEN_FILE:
    fprintf(stderr, "could not open file\n");
    break;
  case ERROR_UNSUPPORTED_FILE_VERSION:
    fprintf(stderr, "rules were compiled with a different version of YARA\n");
    break;
  case ERROR_INVALID_FILE:
    fprintf(stderr, "invalid compiled rules file.\n");
    break;
  case ERROR_CORRUPT_FILE:
    fprintf(stderr, "corrupt compiled rules file.\n");
    break;
  case ERROR_EXEC_STACK_OVERFLOW:
    fprintf(
        stderr,
        "stack overflow while evaluating condition "
        "(see --stack-size argument) \n");
    break;
  case ERROR_INVALID_EXTERNAL_VARIABLE_TYPE:
    fprintf(stderr, "invalid type for external variable\n");
    break;
  case ERROR_TOO_MANY_MATCHES:
    fprintf(stderr, "too many matches\n");
    break;
  default:
    fprintf(stderr, "error: %d\n", error);
    break;
  }
}

static void print_scanner_error(YR_SCANNER* scanner, int error)
{
  YR_RULE* rule = yr_scanner_last_error_rule(scanner);
  YR_STRING* string = yr_scanner_last_error_string(scanner);

  if (rule != NULL && string != NULL)
  {
    fprintf(
        stderr,
        "string \"%s\" in rule \"%s\" caused ",
        string->identifier,
        rule->identifier);
  }
  else if (rule != NULL)
  {
    fprintf(stderr, "rule \"%s\" caused ", rule->identifier);
  }

  print_error(error);
}

static void print_compiler_error(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data)
{
  char* msg_type;

  if (error_level == YARA_ERROR_LEVEL_ERROR)
  {
    msg_type = "error";
  }
  else if (!ignore_warnings)
  {
    COMPILER_RESULTS* compiler_results = (COMPILER_RESULTS*) user_data;
    compiler_results->warnings++;
    msg_type = "warning";
  }
  else
  {
    return;
  }

  if (rule != NULL)
  {
    fprintf(
        stderr,
        "%s: rule \"%s\" in %s(%d): %s\n",
        msg_type,
        rule->identifier,
        file_name,
        line_number,
        message);
  }
  else
  {
    fprintf(
        stderr, "%s(%d): %s: %s\n", file_name, line_number, msg_type, message);
  }
}

static void print_rules_stats(YR_RULES* rules)
{
  YR_RULES_STATS stats;

  int t = sizeof(stats.top_ac_match_list_lengths) /
          sizeof(stats.top_ac_match_list_lengths[0]);

  int result = yr_rules_get_stats(rules, &stats);

  if (result != ERROR_SUCCESS)
  {
    print_error(result);
    return;
  }

  _tprintf(
      _T("size of AC transition table        : %d\n"), stats.ac_tables_size);

  _tprintf(
      _T("average length of AC matches lists : %f\n"),
      stats.ac_average_match_list_length);

  _tprintf(_T("number of rules                    : %d\n"), stats.num_rules);

  _tprintf(_T("number of strings                  : %d\n"), stats.num_strings);

  _tprintf(_T("number of AC matches               : %d\n"), stats.ac_matches);

  _tprintf(
      _T("number of AC matches in root node  : %d\n"),
      stats.ac_root_match_list_length);

  _tprintf(_T("number of AC matches in top %d longest lists\n"), t);

  for (int i = 0; i < t; i++)
    _tprintf(_T(" %3d: %d\n"), i + 1, stats.top_ac_match_list_lengths[i]);

  _tprintf(_T("match list length percentiles\n"));

  for (int i = 100; i >= 0; i--)
    _tprintf(_T(" %3d: %d\n"), i, stats.ac_match_list_length_pctls[i]);
}

static int handle_message(
    YR_SCAN_CONTEXT* context,
    int message,
    YR_RULE* rule,
    void* data)
{
  const char* tag;
  bool show = true;

  if (tags[0] != NULL)
  {
    // The user specified one or more -t <tag> arguments, let's show this rule
    // only if it's tagged with some of the specified tags.

    show = false;

    for (int i = 0; !show && tags[i] != NULL; i++)
    {
      yr_rule_tags_foreach(rule, tag)
      {
        if (strcmp(tag, tags[i]) == 0)
        {
          show = true;
          break;
        }
      }
    }
  }

  if (identifiers[0] != NULL)
  {
    // The user specified one or more -i <identifier> arguments, let's show
    // this rule only if it's identifier is among of the provided ones.

    show = false;

    for (int i = 0; !show && identifiers[i] != NULL; i++)
    {
      if (strcmp(identifiers[i], rule->identifier) == 0)
      {
        show = true;
        break;
      }
    }
  }

  bool is_matching = (message == CALLBACK_MSG_RULE_MATCHING);

  show = show && ((!negate && is_matching) || (negate && !is_matching));

  if (show && !print_count_only)
  {
    cli_mutex_lock(&output_mutex);

    if (show_namespace)
      _tprintf(_T("%" PF_S ":"), rule->ns->name);

    _tprintf(_T("%" PF_S " "), rule->identifier);

    if (show_tags)
    {
      _tprintf(_T("["));

      yr_rule_tags_foreach(rule, tag)
      {
        // print a comma except for the first tag
        if (tag != rule->tags)
          _tprintf(_T(","));

        _tprintf(_T("%" PF_S), tag);
      }

      _tprintf(_T("] "));
    }

    // Show meta-data.

    if (show_meta)
    {
      YR_META* meta;

      _tprintf(_T("["));

      yr_rule_metas_foreach(rule, meta)
      {
        if (meta != rule->metas)
          _tprintf(_T(","));

        if (meta->type == META_TYPE_INTEGER)
        {
          _tprintf(_T("%" PF_S " =%" PRId64), meta->identifier, meta->integer);
        }
        else if (meta->type == META_TYPE_BOOLEAN)
        {
          _tprintf(
              _T("%" PF_S "=%" PF_S),
              meta->identifier,
              meta->integer ? "true" : "false");
        }
        else
        {
          _tprintf(_T("%" PF_S "=\""), meta->identifier);
          print_escaped_data((uint8_t*) (meta->string), strlen(meta->string));
          _tprintf(_T("\""));
        }
      }

      _tprintf(_T("] "));
    }

    print_escaped_file_path(((CALLBACK_ARGS*) data)->file_path);

    // Show matched strings.

    if (show_strings || show_string_length || show_xor_key)
    {
      YR_STRING* string;

      yr_rule_strings_foreach(rule, string)
      {
        YR_MATCH* match;

        yr_string_matches_foreach(context, string, match)
        {
          if (show_string_length)
            _tprintf(
                _T("0x%" PRIx64 ":%d:%" PF_S),
                match->base + match->offset,
                match->data_length,
                string->identifier);
          else
            _tprintf(
                _T("0x%" PRIx64 ":%" PF_S),
                match->base + match->offset,
                string->identifier);

          if (show_xor_key)
          {
            _tprintf(_T(":xor(0x%02x,"), match->xor_key);
            print_string(match->data, match->data_length, match->xor_key);
            _tprintf(_T(")"));
          }

          if (show_strings)
          {
            _tprintf(_T(": "));

            if (STRING_IS_HEX(string))
              print_hex_string(match->data, match->data_length);
            else
              print_string(match->data, match->data_length, 0);
          }

          _tprintf(_T("\n"));
        }
      }
    }

    cli_mutex_unlock(&output_mutex);
  }

  if (is_matching)
  {
    ((CALLBACK_ARGS*) data)->current_count++;
    total_count++;
  }

  if (limit != 0 && total_count >= limit)
    return CALLBACK_ABORT;

  return CALLBACK_CONTINUE;
}

// ---- docscan JSON output (--docscan-json) ----

static void docscan_json_puts(const char* s)
{
  for (const char* p = s; *p; p++)
  {
    unsigned char c = (unsigned char) *p;
    switch (c)
    {
    case '"': fputs("\\\"", stdout); break;
    case '\\': fputs("\\\\", stdout); break;
    case '\n': fputs("\\n", stdout); break;
    case '\r': fputs("\\r", stdout); break;
    case '\t': fputs("\\t", stdout); break;
    default:
      if (c < 0x20)
        printf("\\u%04x", c);
      else
        putchar(c);
    }
  }
}

static void docscan_defang(char* s)
{
  for (char* p = s; *p; p++)
  {
    if (strncmp(p, "http", 4) == 0)
      memcpy(p, "hxxp", 4);
    else if (strncmp(p, "ftp", 3) == 0)
      memcpy(p, "fxp", 3);
  }
}

static void docscan_json_evidence(
    const char* field,
    const char* value,
    int defang,
    int* first)
{
  if (value == NULL || value[0] == '\0')
    return;

  char buf[1024];
  snprintf(buf, sizeof(buf), "%s", value);

  if (defang)
    docscan_defang(buf);

  printf("%s\"%s\":\"", *first ? "" : ",", field);
  docscan_json_puts(buf);
  putchar('"');
  *first = 0;
}

// Appends a JSON-quoted, escaped token to a comma-separated list (bounded).
static void docscan_list_add(char* list, size_t sz, const char* token)
{
  size_t l = strlen(list);
  char esc[512];
  size_t k = 0;
  for (const char* p = token; *p && k + 2 < sizeof(esc); p++)
  {
    if (*p == '"' || *p == '\\')
      esc[k++] = '\\';
    esc[k++] = *p;
  }
  esc[k] = '\0';
  if (l + strlen(esc) + 4 < sz)
    snprintf(list + l, sz - l, "%s\"%s\"", l ? "," : "", esc);
}

static int docscan_list_has(const char* list, const char* token)
{
  char q[512];
  snprintf(q, sizeof(q), "\"%s\"", token);
  return strstr(list, q) != NULL;
}

static void docscan_state_reset(DOCSCAN_STATE* st)
{
  free(st->vba);
  memset(st, 0, sizeof(*st));
}

static void docscan_copy_string(YR_OBJECT* m, const char* field, char* out, size_t sz)
{
  SIZED_STRING* s = yr_object_get_string(m, field);
  size_t n = (s == NULL) ? 0 : (size_t) s->length;
  if (n >= sz)
    n = sz - 1;
  if (n)
    memcpy(out, s->c_string, n);
  out[n] = '\0';
}

// CALLBACK_MSG_MODULE_IMPORTED: copy the facts the JSON line and disarm need.
static void docscan_capture(YR_OBJECT* m, DOCSCAN_STATE* st)
{
  docscan_state_reset(st);
  st->active = 1;
  st->ds.present = 1;

  st->ftype = "unknown";
  if (yr_object_get_integer(m, "is_ooxml") == 1) { st->ftype = "ooxml"; st->ds.type = 1; }
  else if (yr_object_get_integer(m, "is_ole") == 1) { st->ftype = "ole"; st->ds.type = 2; }
  else if (yr_object_get_integer(m, "is_rtf") == 1) { st->ftype = "rtf"; st->ds.type = 3; }
  else if (yr_object_get_integer(m, "is_pdf") == 1) { st->ftype = "pdf"; st->ds.type = 4; }
  else if (yr_object_get_integer(m, "is_lnk") == 1) { st->ftype = "lnk"; st->ds.type = 5; }

  docscan_copy_string(m, "template_url", st->template_url, sizeof(st->template_url));
  docscan_copy_string(m, "dde_command", st->dde_command, sizeof(st->dde_command));
  docscan_copy_string(m, "vba_evidence", st->vba_evidence, sizeof(st->vba_evidence));
  docscan_copy_string(m, "lnk_target", st->lnk_target, sizeof(st->lnk_target));
  docscan_copy_string(m, "lnk_args", st->lnk_args, sizeof(st->lnk_args));

  SIZED_STRING* vba = yr_object_get_string(m, "vba_code");
  if (vba != NULL && vba->length > 0)
  {
    st->vba = (char*) malloc((size_t) vba->length);
    if (st->vba != NULL)
    {
      memcpy(st->vba, vba->c_string, (size_t) vba->length);
      st->vba_len = (size_t) vba->length;
    }
  }
}

static const char* docscan_meta(YR_RULE* rule, const char* name)
{
  YR_META* meta;
  yr_rule_metas_foreach(rule, meta)
  {
    if (meta->type == META_TYPE_STRING && strcmp(meta->identifier, name) == 0)
      return meta->string;
  }
  return NULL;
}

// CALLBACK_MSG_RULE_MATCHING: a rule with meta.severity is a policy rule
// (finding + severity + disarm action); any other rule is a vendor match.
static void docscan_on_match(YR_RULE* rule, DOCSCAN_STATE* st)
{
  const char* sev = docscan_meta(rule, "severity");

  if (sev == NULL)
  {
    docscan_list_add(st->file_matches, sizeof(st->file_matches), rule->identifier);
    return;
  }

  int level = 0;
  if (strcmp(sev, "HIGH") == 0 || strcmp(sev, "high") == 0)
    level = 2;
  else if (strcmp(sev, "MEDIUM") == 0 || strcmp(sev, "medium") == 0)
    level = 1;
  if (level > st->max_severity)
    st->max_severity = level;

  const char* finding = docscan_meta(rule, "finding");
  if (finding == NULL)
    finding = rule->identifier;
  if (!docscan_list_has(st->findings, finding))
    docscan_list_add(st->findings, sizeof(st->findings), finding);

  const char* disarm = docscan_meta(rule, "disarm");
  const char* mitre = docscan_meta(rule, "mitre");

  // {"rule":"..","finding":"..","severity":"..","disarm":"..","mitre":".."}
  char obj[1024], tok[512];
  tok[0] = '\0'; docscan_list_add(tok, sizeof(tok), rule->identifier);
  snprintf(obj, sizeof(obj), "{\"rule\":%s", tok);
  tok[0] = '\0'; docscan_list_add(tok, sizeof(tok), finding);
  snprintf(obj + strlen(obj), sizeof(obj) - strlen(obj), ",\"finding\":%s", tok);
  tok[0] = '\0'; docscan_list_add(tok, sizeof(tok), level == 2 ? "HIGH" : level == 1 ? "MEDIUM" : "INFO");
  snprintf(obj + strlen(obj), sizeof(obj) - strlen(obj), ",\"severity\":%s", tok);
  if (disarm != NULL)
  {
    tok[0] = '\0'; docscan_list_add(tok, sizeof(tok), disarm);
    snprintf(obj + strlen(obj), sizeof(obj) - strlen(obj), ",\"disarm\":%s", tok);
  }
  if (mitre != NULL)
  {
    tok[0] = '\0'; docscan_list_add(tok, sizeof(tok), mitre);
    snprintf(obj + strlen(obj), sizeof(obj) - strlen(obj), ",\"mitre\":%s", tok);
  }
  snprintf(obj + strlen(obj), sizeof(obj) - strlen(obj), "}");
  size_t l = strlen(st->details);
  if (l + strlen(obj) + 2 < sizeof(st->details))
    snprintf(st->details + l, sizeof(st->details) - l, "%s%s", l ? "," : "", obj);

  // Disarm actions are chosen by the policy, not by the module.
  if (disarm != NULL)
  {
    docscan_disarm_info* ds = &st->ds;
    if (strcmp(disarm, "macro") == 0) ds->macro = 1;
    else if (strcmp(disarm, "remote_template") == 0) ds->remote_template = 1;
    else if (strcmp(disarm, "protocol_handler") == 0) ds->protocol_handler = 1;
    else if (strcmp(disarm, "dde") == 0) ds->dde_auto = 1;
    else if (strcmp(disarm, "embedded") == 0) ds->embedded = 1;
    else if (strcmp(disarm, "rtf_objupdate") == 0) ds->rtf_objupdate = 1;
    else if (strcmp(disarm, "lnk_delete") == 0) ds->lnk_bad = 1;
    else return;
    ds->high = 1;  // "something to cure"
  }
}

// Collects matched rule names (as JSON-quoted tokens) during the VBA re-scan.
typedef struct
{
  char* buf;
  size_t sz;
} vmatch_collect;

static int vendor_match_cb(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  if (message == CALLBACK_MSG_RULE_MATCHING)
  {
    YR_RULE* r = (YR_RULE*) message_data;
    // policy rules (meta.severity) describe documents, not VBA text
    if (r->identifier && docscan_meta(r, "severity") == NULL)
    {
      vmatch_collect* v = (vmatch_collect*) user_data;
      docscan_list_add(v->buf, v->sz, r->identifier);
    }
  }
  return CALLBACK_CONTINUE;
}

// CALLBACK_MSG_SCAN_FINISHED: one JSON line per file.
static void print_docscan_json(DOCSCAN_STATE* st)
{
  const char* verdict = st->max_severity == 2   ? "HIGH"
                        : st->max_severity == 1 ? "MEDIUM"
                                                : "INFO";

  printf("{\"ftype\":\"%s\",\"findings\":[%s],\"verdict\":\"%s\",\"evidence\":{",
         st->ftype, st->findings, verdict);

  int fe = 1;
  docscan_json_evidence("template_url", st->template_url, 1, &fe);
  docscan_json_evidence("dde_command", st->dde_command, 1, &fe);
  docscan_json_evidence("vba_evidence", st->vba_evidence, 0, &fe);
  docscan_json_evidence("lnk_target", st->lnk_target, 0, &fe);
  docscan_json_evidence("lnk_args", st->lnk_args, 1, &fe);
  printf("}");  // close "evidence"

  // Layer-2: re-scan the decompressed VBA with the loaded rules.
  char vmatches[4096] = "";
  if (g_rules != NULL && st->vba != NULL && st->vba_len > 0)
  {
    YR_SCANNER* sc2 = NULL;
    if (yr_scanner_create(g_rules, &sc2) == ERROR_SUCCESS)
    {
      vmatch_collect vm = {vmatches, sizeof(vmatches)};
      yr_scanner_set_callback(sc2, vendor_match_cb, &vm);
      yr_scanner_scan_mem(sc2, (const uint8_t*) st->vba, st->vba_len);
      yr_scanner_destroy(sc2);
    }
  }

  printf(",\"yara_matches\":[%s]", vmatches);
  printf(",\"yara_file_matches\":[%s]", st->file_matches);
  printf(",\"details\":[%s]", st->details);
  printf("}\n");  // close root object
  fflush(stdout);
}

// Cure a file in place and print the action (handles wide paths on Windows).
static void do_disarm(const char_t* file_path, docscan_disarm_info* ds)
{
  char action[256];
#if defined(_WIN32) && defined(_UNICODE)
  char utf8[4096];
  WideCharToMultiByte(
      CP_UTF8, 0, file_path, -1, utf8, (int) sizeof(utf8), NULL, NULL);
  docscan_disarm(utf8, ds, action, sizeof(action));
  // Print the whole line in narrow mode (wide/narrow mixing drops output).
  fflush(stdout);
  _setmode(_fileno(stdout), _O_TEXT);
  printf("docscan-disarm: %s -> %s\n", utf8, action[0] ? action : "none");
  fflush(stdout);
  _setmode(_fileno(stdout), _O_U8TEXT);
#else
  docscan_disarm(file_path, ds, action, sizeof(action));
  printf("docscan-disarm: %s -> %s\n", file_path, action[0] ? action : "none");
  fflush(stdout);
#endif
}

static int callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  YR_MODULE_IMPORT* mi;
  YR_STRING* string;
  YR_RULE* rule;
  YR_OBJECT* object;
  MODULE_DATA* module_data;

  switch (message)
  {
  case CALLBACK_MSG_RULE_MATCHING:
  case CALLBACK_MSG_RULE_NOT_MATCHING:
    if ((docscan_json || docscan_disarm_flag) &&
        message == CALLBACK_MSG_RULE_MATCHING &&
        ((CALLBACK_ARGS*) user_data)->dsc.active)
      docscan_on_match((YR_RULE*) message_data, &((CALLBACK_ARGS*) user_data)->dsc);
    if (docscan_json)  // in docscan-json mode we only emit the JSON line
      return CALLBACK_CONTINUE;
    return handle_message(context, message, (YR_RULE*) message_data, user_data);

  case CALLBACK_MSG_SCAN_FINISHED:
    if (docscan_json && ((CALLBACK_ARGS*) user_data)->dsc.active)
    {
      cli_mutex_lock(&output_mutex);
#if defined(_WIN32) && defined(_UNICODE)
      fflush(stdout);
      _setmode(_fileno(stdout), _O_TEXT);
#endif
      print_docscan_json(&((CALLBACK_ARGS*) user_data)->dsc);
#if defined(_WIN32) && defined(_UNICODE)
      fflush(stdout);
      _setmode(_fileno(stdout), _O_U8TEXT);
#endif
      cli_mutex_unlock(&output_mutex);
    }
    return CALLBACK_CONTINUE;

  case CALLBACK_MSG_IMPORT_MODULE:

    mi = (YR_MODULE_IMPORT*) message_data;
    module_data = modules_data_list;

    while (module_data != NULL)
    {
      if (strcmp(module_data->module_name, mi->module_name) == 0)
      {
        mi->module_data = (void*) module_data->mapped_file.data;
        mi->module_data_size = module_data->mapped_file.size;
        break;
      }

      module_data = module_data->next;
    }

    return CALLBACK_CONTINUE;

  case CALLBACK_MSG_MODULE_IMPORTED:

    if (docscan_json || docscan_extract != NULL || docscan_disarm_flag)
    {
      object = (YR_OBJECT*) message_data;

      if (object->identifier != NULL &&
          strcmp(object->identifier, "docscan") == 0)
      {
        // Copy facts now: the module is unloaded before rule callbacks run.
        docscan_capture(object, &((CALLBACK_ARGS*) user_data)->dsc);

        // Extract the decompressed VBA to a file for a 2nd vendor-rules scan.
        if (docscan_extract != NULL)
        {
          SIZED_STRING* vc = yr_object_get_string(object, "vba_code");
          if (vc != NULL && vc->length > 0)
          {
            FILE* fh = fopen(docscan_extract, "wb");
            if (fh != NULL)
            {
              fwrite(vc->c_string, 1, (size_t) vc->length, fh);
              fclose(fh);
            }
          }
        }

        // The JSON line is printed at CALLBACK_MSG_SCAN_FINISHED.
      }
    }

    if (show_module_data)
    {
      object = (YR_OBJECT*) message_data;

      cli_mutex_lock(&output_mutex);

#if defined(_WIN32)
      // In Windows restore stdout to normal text mode as yr_object_print_data
      // calls printf which is not supported in UTF-8 mode.
      // Explicitly flush the buffer before the switch in case we already
      // printed something and it haven't been flushed automatically.
      fflush(stdout);
      _setmode(_fileno(stdout), _O_TEXT);
#endif

      yr_object_print_data(object, 0, 1);
      printf("\n");

#if defined(_WIN32)
      // Go back to UTF-8 mode.
      // Explicitly flush the buffer before the switch in case we already
      // printed something and it haven't been flushed automatically.
      fflush(stdout);
      _setmode(_fileno(stdout), _O_U8TEXT);
#endif

      cli_mutex_unlock(&output_mutex);
    }

    return CALLBACK_CONTINUE;

  case CALLBACK_MSG_TOO_SLOW_SCANNING:
    if (ignore_warnings)
      return CALLBACK_CONTINUE;

    string = (YR_STRING*) message_data;
    rule = &context->rules->rules_table[string->rule_idx];

    if (rule != NULL && string != NULL)
      fprintf(
          stderr,
          "warning: rule \"%s\": scanning with string %s is taking a very long "
          "time, it is either too general or very common.\n",
          rule->identifier,
          string->identifier);
    else
      return CALLBACK_CONTINUE;

    if (fail_on_warnings)
      return CALLBACK_ERROR;

    return CALLBACK_CONTINUE;

  case CALLBACK_MSG_TOO_MANY_MATCHES:
    if (ignore_warnings)
      return CALLBACK_CONTINUE;

    string = (YR_STRING*) message_data;
    rule = &context->rules->rules_table[string->rule_idx];

    fprintf(
        stderr,
        "warning: rule \"%s\": too many matches for %s, results for this rule "
        "may be incorrect\n",
        rule->identifier,
        string->identifier);

    if (fail_on_warnings)
      return CALLBACK_ERROR;

    return CALLBACK_CONTINUE;

  case CALLBACK_MSG_CONSOLE_LOG:
    if (!disable_console_logs)
      _tprintf(_T("%" PF_S "\n"), (char*) message_data);
    return CALLBACK_CONTINUE;
  }

  return CALLBACK_ERROR;
}

#if defined(_WIN32) || defined(__CYGWIN__)
static DWORD WINAPI scanning_thread(LPVOID param)
#else
static void* scanning_thread(void* param)
#endif
{
  int result = ERROR_SUCCESS;
  THREAD_ARGS* args = (THREAD_ARGS*) param;

  char_t* file_path = file_queue_get(args->deadline);

  while (file_path != NULL)
  {
    args->callback_args.current_count = 0;
    args->callback_args.file_path = file_path;
    docscan_state_reset(&args->callback_args.dsc);

    time_t current_time = time(NULL);

    if (current_time < args->deadline)
    {
      yr_scanner_set_timeout(
          args->scanner, (int) (args->deadline - current_time));

      result = scan_file(args->scanner, file_path);

      if (print_count_only)
      {
        cli_mutex_lock(&output_mutex);
        _tprintf(_T("%s: %d\n"), file_path, args->callback_args.current_count);
        cli_mutex_unlock(&output_mutex);
      }

      if (result != ERROR_SUCCESS)
      {
        cli_mutex_lock(&output_mutex);
        _ftprintf(stderr, _T("error scanning %s: "), file_path);
        print_scanner_error(args->scanner, result);
        cli_mutex_unlock(&output_mutex);
      }

      // cure what the policy asked for; a HIGH without actions -> "detect-only"
      if (docscan_disarm_flag && args->callback_args.dsc.ds.present &&
          (args->callback_args.dsc.ds.high ||
           args->callback_args.dsc.max_severity == 2))
      {
        cli_mutex_lock(&output_mutex);
        do_disarm(file_path, &args->callback_args.dsc.ds);
        cli_mutex_unlock(&output_mutex);
      }

      free(file_path);
      file_path = file_queue_get(args->deadline);
    }
    else
    {
      file_path = NULL;
    }
  }

  return 0;
}

static int load_modules_data()
{
  for (int i = 0; modules_data[i] != NULL; i++)
  {
    char* equal_sign = strchr(modules_data[i], '=');

    if (!equal_sign)
    {
      fprintf(stderr, "error: wrong syntax for `-x` option.\n");
      return false;
    }

    *equal_sign = '\0';

    MODULE_DATA* module_data = (MODULE_DATA*) malloc(sizeof(MODULE_DATA));

    if (module_data != NULL)
    {
      module_data->module_name = modules_data[i];

      int result = yr_filemap_map(equal_sign + 1, &module_data->mapped_file);

      if (result != ERROR_SUCCESS)
      {
        free(module_data);

        fprintf(stderr, "error: could not open file \"%s\".\n", equal_sign + 1);

        return false;
      }

      module_data->next = modules_data_list;
      modules_data_list = module_data;
    }
  }

  return true;
}

static void unload_modules_data()
{
  MODULE_DATA* module_data = modules_data_list;

  while (module_data != NULL)
  {
    MODULE_DATA* next_module_data = module_data->next;

    yr_filemap_unmap(&module_data->mapped_file);
    free(module_data);

    module_data = next_module_data;
  }

  modules_data_list = NULL;
}

int _tmain(int argc, const char_t** argv)
{
  COMPILER_RESULTS cr;

  YR_COMPILER* compiler = NULL;
  YR_RULES* rules = NULL;
  YR_SCANNER* scanner = NULL;
  SCAN_OPTIONS scan_opts;

  bool arg_is_dir = false;
  int flags = 0;
  int result;

  argc = args_parse(options, argc, argv);

  scan_opts.follow_symlinks = follow_symlinks;
  scan_opts.recursive_search = recursive_search;

  if (show_version)
  {
    printf("%s\n", YR_VERSION);
    return EXIT_SUCCESS;
  }

  if (show_help)
  {
    printf(
        "YARA %s, the pattern matching swiss army knife.\n"
        "%s\n\n"
        "Mandatory arguments to long options are mandatory for "
        "short options too.\n\n",
        YR_VERSION,
        USAGE_STRING);

    args_print_usage(options, 43);
    printf(
        "\nSend bug reports and suggestions to: vmalvarez@virustotal.com.\n");

    return EXIT_SUCCESS;
  }

  if (threads > YR_MAX_THREADS)
  {
    fprintf(stderr, "maximum number of threads is %d\n", YR_MAX_THREADS);
    return EXIT_FAILURE;
  }

  // This can be done before yr_initialize() because we aren't calling any
  // module functions, just accessing the name pointer for each module.
  if (show_module_names)
  {
    for (YR_MODULE* module = yr_modules_get_table(); module->name != NULL;
         module++)
    {
      printf("%s\n", module->name);
    }
    return EXIT_SUCCESS;
  }

  if (argc < 2)
  {
    // After parsing the command-line options we expect two additional
    // arguments, the rules file and the target file, directory or pid to
    // be scanned.

    fprintf(stderr, "yara: wrong number of arguments\n");
    fprintf(stderr, "%s\n\n", USAGE_STRING);
    fprintf(stderr, "Try `--help` for more options\n");

    return EXIT_FAILURE;
  }

#if defined(_WIN32) && defined(_UNICODE)
  // In Windows set stdout to UTF-8 mode.
  if (_setmode(_fileno(stdout), _O_U8TEXT) == -1)
  {
    return EXIT_FAILURE;
  }
#endif

  if (!load_modules_data())
    exit_with_code(EXIT_FAILURE);

  result = yr_initialize();

  if (result != ERROR_SUCCESS)
  {
    fprintf(stderr, "error: initialization error (%d)\n", result);
    exit_with_code(EXIT_FAILURE);
  }

  yr_set_configuration_uint32(YR_CONFIG_STACK_SIZE, (uint32_t) stack_size);

  yr_set_configuration_uint32(
      YR_CONFIG_MAX_STRINGS_PER_RULE, (uint32_t) max_strings_per_rule);

  yr_set_configuration_uint64(
      YR_CONFIG_MAX_PROCESS_MEMORY_CHUNK, max_process_memory_chunk);

  // Try to load the rules file as a binary file containing
  // compiled rules first

  if (rules_are_compiled)
  {
    // When a binary file containing compiled rules is provided, yara accepts
    // only two arguments, the compiled rules file and the target to be scanned.

    if (argc != 2)
    {
      fprintf(
          stderr,
          "error: can't accept multiple rules files if one of them is in "
          "compiled form.\n");
      exit_with_code(EXIT_FAILURE);
    }

    // Not using yr_rules_load because it does not have support for unicode
    // file names. Instead use open _tfopen for openning the file and
    // yr_rules_load_stream for loading the rules from it.

    FILE* fh = _tfopen(argv[0], _T("rb"));

    if (fh != NULL)
    {
      YR_STREAM stream;

      stream.user_data = fh;
      stream.read = (YR_STREAM_READ_FUNC) fread;

      result = yr_rules_load_stream(&stream, &rules);

      fclose(fh);

      if (result == ERROR_SUCCESS)
        result = define_external_variables(ext_vars, rules, NULL);
    }
    else
    {
      result = ERROR_COULD_NOT_OPEN_FILE;
    }
  }
  else
  {
    // Rules file didn't contain compiled rules, let's handle it
    // as a text file containing rules in source form.

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
      exit_with_code(EXIT_FAILURE);

    result = define_external_variables(ext_vars, NULL, compiler);

    if (result != ERROR_SUCCESS)
    {
      print_error(result);
      exit_with_code(EXIT_FAILURE);
    }

    if (atom_quality_table != NULL)
    {
      result = yr_compiler_load_atom_quality_table(
          compiler, atom_quality_table, 0);

      if (result != ERROR_SUCCESS)
      {
        fprintf(stderr, "error loading atom quality table: ");
        print_error(result);
        exit_with_code(EXIT_FAILURE);
      }
    }

    cr.errors = 0;
    cr.warnings = 0;

    yr_compiler_set_callback(compiler, print_compiler_error, &cr);

    if (strict_escape)
      compiler->strict_escape = true;
    else
      compiler->strict_escape = false;

    if (!compile_files(compiler, argc, argv))
      exit_with_code(EXIT_FAILURE);

    if (cr.errors > 0)
      exit_with_code(EXIT_FAILURE);

    if (fail_on_warnings && cr.warnings > 0)
      exit_with_code(EXIT_FAILURE);

    result = yr_compiler_get_rules(compiler, &rules);

    yr_compiler_destroy(compiler);

    compiler = NULL;
  }

  g_rules = rules;  // for Layer-2 VBA re-scan

  if (result != ERROR_SUCCESS)
  {
    print_error(result);
    exit_with_code(EXIT_FAILURE);
  }

  if (show_stats)
    print_rules_stats(rules);

  cli_mutex_init(&output_mutex);

  if (fast_scan)
    flags |= SCAN_FLAGS_FAST_MODE;

  scan_opts.deadline = time(NULL) + timeout;

  arg_is_dir = is_directory(argv[argc - 1]);

  if (scan_list_search && arg_is_dir)
  {
    fprintf(stderr, "error: cannot use a directory as scan list.\n");
    exit_with_code(EXIT_FAILURE);
  }
  else if (scan_list_search || arg_is_dir)
  {
    if (file_queue_init() != 0)
    {
      print_error(ERROR_INTERNAL_FATAL_ERROR);
      exit_with_code(EXIT_FAILURE);
    }

    THREAD thread[YR_MAX_THREADS];
    THREAD_ARGS thread_args[YR_MAX_THREADS];

    for (int i = 0; i < threads; i++)
    {
      thread_args[i].deadline = scan_opts.deadline;
      thread_args[i].current_count = 0;
      memset(&thread_args[i].callback_args, 0, sizeof(CALLBACK_ARGS));

      result = yr_scanner_create(rules, &thread_args[i].scanner);

      if (result != ERROR_SUCCESS)
      {
        print_error(result);
        exit_with_code(EXIT_FAILURE);
      }

      yr_scanner_set_callback(
          thread_args[i].scanner, callback, &thread_args[i].callback_args);

      yr_scanner_set_flags(thread_args[i].scanner, flags);

      if (cli_create_thread(
              &thread[i], scanning_thread, (void*) &thread_args[i]))
      {
        print_error(ERROR_COULD_NOT_CREATE_THREAD);
        exit_with_code(EXIT_FAILURE);
      }
    }

    if (arg_is_dir)
    {
      scan_dir(argv[argc - 1], &scan_opts);
    }
    else
    {
      result = populate_scan_list(argv[argc - 1], &scan_opts);
    }

    file_queue_finish();

    // Wait for scan threads to finish
    for (int i = 0; i < threads; i++) cli_thread_join(&thread[i]);

    for (int i = 0; i < threads; i++)
      yr_scanner_destroy(thread_args[i].scanner);

    file_queue_destroy();

    if (result != ERROR_SUCCESS)
      exit_with_code(EXIT_FAILURE);
  }
  else
  {
    CALLBACK_ARGS user_data = {argv[argc - 1], 0};

    result = yr_scanner_create(rules, &scanner);

    if (result != ERROR_SUCCESS)
    {
      _ftprintf(stderr, _T("error: %d\n"), result);
      exit_with_code(EXIT_FAILURE);
    }

    yr_scanner_set_callback(scanner, callback, &user_data);
    yr_scanner_set_flags(scanner, flags);
    yr_scanner_set_timeout(scanner, timeout);

    // Assume the last argument is a file first. This assures we try to process
    // files that start with numbers first.
    result = scan_file(scanner, argv[argc - 1]);

    if (result == ERROR_COULD_NOT_OPEN_FILE)
    {
      // Is it a PID? To be a PID it must be made up entirely of digits.
      char_t* endptr = NULL;
      long pid = _tcstol(argv[argc - 1], &endptr, 10);

      if (pid > 0 && argv[argc - 1] != NULL && *endptr == '\x00')
        result = yr_scanner_scan_proc(scanner, (int) pid);
    }

    if (result != ERROR_SUCCESS)
    {
      _ftprintf(stderr, _T("error scanning %s: "), argv[argc - 1]);
      print_scanner_error(scanner, result);
      exit_with_code(EXIT_FAILURE);
    }

    if (docscan_disarm_flag && user_data.dsc.ds.present &&
        (user_data.dsc.ds.high || user_data.dsc.max_severity == 2))
      do_disarm(argv[argc - 1], &user_data.dsc.ds);
    docscan_state_reset(&user_data.dsc);

    if (print_count_only)
      _tprintf(_T("%d\n"), user_data.current_count);

#ifdef YR_PROFILING_ENABLED
    yr_scanner_print_profiling_info(scanner);
#endif
  }

  result = EXIT_SUCCESS;

_exit:

  unload_modules_data();

  if (scanner != NULL)
    yr_scanner_destroy(scanner);

  if (compiler != NULL)
    yr_compiler_destroy(compiler);

  if (rules != NULL)
    yr_rules_destroy(rules);

  yr_finalize();

  args_free(options);

  return result;
}
