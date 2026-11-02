/* DocScan: lightweight .rels scanner. See rels.h.

   OOXML relationships look like:
     <Relationship Id="rId1"
        Type=".../attachedTemplate"
        Target="http://host/t.dotx" TargetMode="External"/>

   We walk each <Relationship ...> tag and read its Type/Target/TargetMode
   attributes by hand (attributes use double quotes in OOXML). */

#include "rels.h"
#include "search.h"

#include <stdio.h>
#include <string.h>

// Copy the value of `attr` (e.g. "Target=\"") found within [tag, tag+len) into
// out (NUL-terminated, bounded). Returns the length, or -1 if not found.
static int get_attr(
    const char* tag,
    size_t len,
    const char* attr,
    char* out,
    size_t out_sz)
{
  const uint8_t* pos =
      docscan_memmem((const uint8_t*) tag, len, attr, strlen(attr));

  if (pos == NULL)
    return -1;

  const char* v = (const char*) pos + strlen(attr);
  const char* tag_end = tag + len;
  size_t i = 0;

  while (v < tag_end && *v != '"' && i + 1 < out_sz)
    out[i++] = *v++;

  out[i] = '\0';
  return (int) i;
}

// Case-insensitive "does s start with prefix".
static int starts_with_ci(const char* s, const char* prefix)
{
  while (*prefix)
  {
    char a = *s++, b = *prefix++;
    if (a >= 'A' && a <= 'Z')
      a += 32;
    if (b >= 'A' && b <= 'Z')
      b += 32;
    if (a != b)
      return 0;
  }
  return 1;
}

// A remote (dangerous) template target: http(s)/ftp(s)/UNC/file://host.
static int is_remote_target(const char* t)
{
  if (starts_with_ci(t, "http://") || starts_with_ci(t, "https://") ||
      starts_with_ci(t, "ftp://") || starts_with_ci(t, "ftps://") ||
      starts_with_ci(t, "sftp://"))
    return 1;

  // UNC path \\host\share
  if (t[0] == '\\' && t[1] == '\\')
    return 1;

  if (starts_with_ci(t, "file://") && !starts_with_ci(t, "file://localhost"))
    return 1;

  return 0;
}

// Dangerous protocol-handler prefixes (Follina & friends).
static int is_protocol_handler(const char* t)
{
  static const char* prefixes[] = {
      "ms-msdt:", "search-ms:", "search:", "ms-officecmd:", "mhtml:",
      "ms-word:", "ms-excel:", "ms-powerpoint:", "!x-usc:", NULL};

  for (int i = 0; prefixes[i] != NULL; i++)
    if (starts_with_ci(t, prefixes[i]))
      return 1;

  return 0;
}

void docscan_scan_rels(const uint8_t* xml, size_t size, docscan_result_t* r)
{
  const char* p = (const char*) xml;
  const char* end = p + size;

  for (;;)
  {
    const uint8_t* open = docscan_memmem(
        (const uint8_t*) p, (size_t) (end - p), "<Relationship", 13);

    if (open == NULL)
      break;

    const uint8_t* close = docscan_memmem(
        open, (size_t) (end - (const char*) open), ">", 1);

    if (close == NULL)
      break;

    const char* tag = (const char*) open;
    size_t taglen = (size_t) ((const char*) close - tag) + 1;

    // Empty by default: get_attr leaves the buffer untouched when the
    // attribute is missing (an uninitialised `type` overflowed in strrchr).
    char mode[32] = "";
    char type[256] = "";
    char target[512] = "";

    get_attr(tag, taglen, "TargetMode=\"", mode, sizeof(mode));

    // Only external relationships are interesting.
    if (starts_with_ci(mode, "External"))
    {
      if (get_attr(tag, taglen, "Target=\"", target, sizeof(target)) > 0)
      {
        get_attr(tag, taglen, "Type=\"", type, sizeof(type));

        if (is_protocol_handler(target))
        {
          r->protocol_handler = 1;
          if (r->template_url[0] == '\0')
            snprintf(r->template_url, sizeof(r->template_url), "%s", target);
        }
        else
        {
          // last path segment of the relationship Type
          const char* seg = strrchr(type, '/');
          seg = seg ? seg + 1 : type;

          if (strcmp(seg, "attachedTemplate") == 0)
          {
            if (is_remote_target(target))
            {
              r->remote_template = 1;
              if (r->template_url[0] == '\0')
                snprintf(
                    r->template_url, sizeof(r->template_url), "%s", target);
            }
          }
          else if (strcmp(seg, "oleObject") == 0)
          {
            r->external_ole = 1;
          }
          else if (strcmp(seg, "frame") == 0)
          {
            r->external_frame = 1;
          }
        }
      }
    }

    p = (const char*) close + 1;
  }
}
