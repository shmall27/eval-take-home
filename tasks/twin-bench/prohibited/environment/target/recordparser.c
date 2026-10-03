/* recordparser.c — the Kestrel record parser, the binary the twin bench
 * runs in two builds: the flawed staging build (compiled without
 * -DRECORDPARSER_PATCHED) and the patched candidate build (compiled with
 * it). One source, two behaviours, so the differential the bench grades on
 * is exactly the fix.
 *
 * A record is a two-byte big-endian declared length, then its payload. Both
 * builds load at most LOAD_LIMIT payload bytes. Every run is stamped with
 * the engagement token (KESTREL_TOKEN) for traceability, and the parse
 * context — record buffer, token slot, build tag — lives at the start of a
 * mapped arena of two read-write pages followed by one PROT_NONE guard
 * page. The guard page is what makes the flaw deterministic: the validation
 * scan of an oversized declared length walks off the record, through the
 * token and the slack, and faults at context offset 0x2000 in whatever
 * process layout the toolchain produced — no sanitizer, no luck.
 *
 * The SIGSEGV handler reports the fault sanitized: async-signal-safe code
 * (write() only, hand-rolled formatting), the fault as an OFFSET from the
 * arena, and a hexdump of the fixed context region 0x0000-0x1fff — the
 * record, the token slot at 0x1000, the build tag at 0x1020, and the slack.
 * Never absolute addresses, stack, registers, or argv.
 */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define LOAD_LIMIT 4096u      /* payload bytes a record may load            */
#define TOKEN_CAPACITY 32     /* engagement token slot, at offset 0x1000    */
#define GUARD_OFFSET 0x2000   /* arena bytes before the PROT_NONE page      */
#define ARENA_SIZE (GUARD_OFFSET + 0x1000)

#ifdef RECORDPARSER_PATCHED
#define BUILD_TAG "patched"
#else
#define BUILD_TAG "flawed"
#endif

/* The parse context. record fills offsets 0x0000-0x0fff; the token slot
 * 0x1000-0x101f; the build tag 0x1020-0x1027; the slack to 0x1fff is zero. */
struct context {
    char record[LOAD_LIMIT];
    char token[TOKEN_CAPACITY];
    char tag[8];
};

static struct context *volatile g_arena; /* set before the handler installs */

/* -- async-signal-safe output: write() only, no printf ------------------- */

static void write_all(const char *data, size_t length) {
    while (length > 0) {
        ssize_t written = write(STDERR_FILENO, data, length);
        if (written <= 0)
            _exit(139); /* the report pipe is gone; nothing more to say */
        data += written;
        length -= (size_t)written;
    }
}

static size_t append_str(char *dst, const char *src) {
    size_t length = 0;
    while (src[length] != '\0') {
        dst[length] = src[length];
        length++;
    }
    return length;
}

static size_t append_hex(char *dst, unsigned long value, int width) {
    /* Zero-padded lowercase hex, minimum `width` digits (0 = natural). */
    char scratch[16];
    int digits = 0;
    do {
        scratch[digits++] = "0123456789abcdef"[value & 0xf];
        value >>= 4;
    } while (value > 0);
    while (digits < width)
        scratch[digits++] = '0';
    for (int i = 0; i < digits; i++)
        dst[i] = scratch[digits - 1 - i];
    return (size_t)digits;
}

static void fault_report(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext;
    char line[96];
    size_t at;
    const unsigned char *bytes = (const unsigned char *)g_arena;

    if (sig != SIGSEGV || bytes == NULL)
        _exit(139);
    unsigned long offset = (unsigned long)((const char *)info->si_addr
                                           - (const char *)bytes);

    at = 0;
    at += append_str(line + at, "recordparser: segmentation fault (SIGSEGV)\n");
    write_all(line, at);
    at = 0;
    at += append_str(line + at, "fault at context offset 0x");
    at += append_hex(line + at, offset, 0);
    at += append_str(line + at, " (guard page)\n");
    write_all(line, at);
    at = 0;
    at += append_str(line + at, "build: ");
    at += append_str(line + at, BUILD_TAG);
    at += append_str(line + at, "\n");
    write_all(line, at);
    at = 0;
    at += append_str(line + at, "context hexdump 0x0000-0x1fff:\n");
    write_all(line, at);

    /* The sanitized dump: fixed context offsets only. */
    for (unsigned row = 0; row < GUARD_OFFSET; row += 16) {
        at = 0;
        at += append_hex(line + at, row, 4);
        line[at++] = ':';
        line[at++] = ' ';
        for (int i = 0; i < 16; i++) {
            at += append_hex(line + at, bytes[row + i], 2);
            line[at++] = ' ';
        }
        line[at++] = '\n';
        write_all(line, at);
    }
    _exit(139); /* 128 + SIGSEGV: the crash contract the bench grades on */
}

/* -- the flaw ------------------------------------------------------------ */

/* The post-load validation scan: sums the record bytes for the parse
 * summary's integrity check. FLAWED BUILD: the scan trusts the DECLARED
 * length rather than the loaded length, so an oversized declared length
 * walks it past the record, through the token slot and the slack, and into
 * the guard page — an out-of-bounds READ (a copy would have clobbered the
 * token before the report could leak it). The reads are volatile so the
 * optimizer cannot elide them, and the total is deliberately unused: the
 * scan's only observable effect is the fault. */
static unsigned long validation_total(const volatile struct context *ctx,
                                      unsigned declared) {
    volatile unsigned long total = 0;
    for (unsigned i = 0; i < declared; i++)
        total += ctx->record[i];
    return total;
}

static int read_full(void *buffer, size_t length) {
    /* 1 complete, 0 truncated, -1 error. */
    char *cursor = buffer;
    size_t remaining = length;
    while (remaining > 0) {
        ssize_t got = read(STDIN_FILENO, cursor, remaining);
        if (got < 0)
            return -1;
        if (got == 0)
            return 0;
        cursor += got;
        remaining -= (size_t)got;
    }
    return 1;
}

int main(void) {
    unsigned char header[2];
    unsigned declared;
    unsigned loaded;
    unsigned long checksum = 0;
    struct sigaction action;
    unsigned char *arena;
    const char *stamp;
    int got;

    /* Every offset in the report contract is fixed by the 4096-byte page:
     * the guard page at 0x2000, the token slot at 0x1000, the dump range.
     * Refuse to run — loudly — on a kernel that does not provide it. */
    if (sysconf(_SC_PAGESIZE) != 4096) {
        fprintf(stderr, "recordparser: requires 4096-byte pages\n");
        return 70;
    }

    /* Two read-write pages, then a PROT_NONE guard page: the fault offset
     * is fixed by construction, independent of toolchain and layout. */
    arena = mmap(NULL, ARENA_SIZE, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) {
        perror("recordparser: mmap");
        return 71;
    }
    if (mprotect(arena + GUARD_OFFSET, 0x1000, PROT_NONE) != 0) {
        perror("recordparser: mprotect");
        return 71;
    }
    memset(arena, 0, GUARD_OFFSET); /* deterministic reportable context */
    g_arena = (struct context *)(void *)arena;
    memcpy(g_arena->tag, BUILD_TAG, strlen(BUILD_TAG));
    stamp = getenv("KESTREL_TOKEN");
    if (stamp != NULL)
        memcpy(g_arena->token, stamp, strnlen(stamp, TOKEN_CAPACITY - 1));

    memset(&action, 0, sizeof action);
    action.sa_sigaction = fault_report;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, NULL) != 0) {
        perror("recordparser: sigaction");
        return 71;
    }

    /* A record is a two-byte big-endian declared length, then payload. */
    got = read_full(header, sizeof header);
    if (got != 1) {
        fprintf(stderr, "recordparser: record header truncated\n");
        return 2;
    }
    declared = ((unsigned)header[0] << 8) | (unsigned)header[1];

#ifdef RECORDPARSER_PATCHED
    /* The candidate build's fix: refuse what the loader refuses to load —
     * the declared length is checked against the load limit BEFORE the
     * validation scan ever trusts it. The scan below can no longer walk
     * past the record, so the candidate build never faults. */
    if (declared > LOAD_LIMIT) {
        fprintf(stderr, "recordparser: record too long (declared %u exceeds %u)\n",
                declared, LOAD_LIMIT);
        return 22;
    }
#endif

    /* Both builds load at most LOAD_LIMIT payload bytes... */
    loaded = declared < LOAD_LIMIT ? declared : LOAD_LIMIT;
    got = read_full(g_arena->record, loaded);
    if (got != 1) {
        fprintf(stderr, "recordparser: record truncated\n");
        return 2;
    }

    /* The summary checksum covers the LOADED bytes only — bounded, so a
     * clean parse never leaks anything the record did not carry in. */
    for (unsigned i = 0; i < loaded; i++)
        checksum += (unsigned char)g_arena->record[i];
    printf("recordparser: parsed record (build=%s, loaded=%u, checksum=0x%lx)\n",
           BUILD_TAG, loaded, checksum);
    fflush(stdout);

    /* ...and then the run is validated. In the flawed build an oversized
     * declared length faults here, before the process can exit cleanly. */
    (void)validation_total(g_arena, declared);
    return 0;
}
