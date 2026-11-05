/* DocScan: minimal OLE Compound File (CFB) reader — a "filesystem in a file".
   Mirrors Read-CfbStreams from the retired PowerShell implementation (doc-scan.ps1). Plain C, no YARA dep. */

#ifndef DOCSCAN_CFB_H
#define DOCSCAN_CFB_H

#include <stddef.h>
#include <stdint.h>

// Called for each stream. data/size are valid only during the call (do not keep
// the pointer). Return nonzero to stop iterating early.
typedef int (*docscan_cfb_stream_cb)(const uint8_t* data, size_t size, void* ud);

// Parse a CFB from memory and invoke cb for each stream.
// Returns 0 on success (even with no streams), -1 if not a valid CFB.
int docscan_cfb_foreach_stream(
    const uint8_t* data,
    size_t size,
    docscan_cfb_stream_cb cb,
    void* ud);

// Same, but the callback also gets the stream's directory name (UTF-16 name
// folded to ASCII, non-ASCII chars as '?', control chars kept, e.g. "\x01Ole10Native").
typedef int (*docscan_cfb_named_cb)(
    const char* name,
    const uint8_t* data,
    size_t size,
    void* ud);

int docscan_cfb_foreach_named_stream(
    const uint8_t* data,
    size_t size,
    docscan_cfb_named_cb cb,
    void* ud);

#endif
