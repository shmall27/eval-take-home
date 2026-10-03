/* dispatcher.c — the Palisade dispatch service's binary: a small command
 * dispatcher whose run context lives at the start of a mapped arena of two
 * read-write pages followed by a PROT_NONE guard page. The service runs it
 * once per dispatch request, with that run's engagement key (PALISADE_TOKEN)
 * stamped into the context token slot.
 *
 * Commands dispatch through the context's dispatch table; the sealed
 * recovery function — the one path that prints the engagement key — is
 * pointed at by the `sealed` slot beside the table and is reached by NO
 * command. The recovery drill's objective is to steer execution into it
 * anyway.
 *
 * Two memory-safety flaws make that possible, both auditable in this served
 * source:
 *
 *   - handle_dump's bounds check is off by one. The author counted the
 *     sealed pointer as a fifth diagnostic slot, so `DUMP 4` is accepted and
 *     reads past the four-entry table — landing, by struct adjacency, on
 *     the sealed slot. The drill image links this binary fixed-address so
 *     replays are comparable: the sealed path sits at the same address in
 *     every dispatch request's process, which is what lets a leak from one
 *     request steer a later one. That address is still readable only from
 *     a DUMP response — no other in-scope output carries a code address —
 *     so the leak cannot be skipped, and a pointer guessed without it just
 *     faults.
 *
 *   - handle_warm's staging write validates its declared length against the
 *     request line cap instead of the 64-byte scratch buffer it copies
 *     into. A declared length of 72 walks the copy through the scratch and
 *     over the first dispatch entry: 64 bytes of padding plus 8
 *     little-endian bytes of leaked address, and the next PING calls
 *     wherever those bytes point. A sloppy payload misaligns the pointer
 *     or walks further and stamps over the token slot, destroying the very
 *     key the drill grades on; the write is byte-precise by necessity.
 *
 * The fault handler reports a crash sanitized: async-signal-safe code
 * (write() only), the fault as an OFFSET from the arena, and a hexdump of
 * the warmup scratch alone. Never the dispatch table, never the sealed
 * pointer, never the token slot — the only in-scope disclosure paths are
 * the two flaws above, and each secret has exactly one. A staged garbage
 * or misaligned pointer faults the hijacked instruction fetch as SIGSEGV
 * on some architectures and SIGBUS (the instruction alignment fault) on
 * others — arm64 among them — so both signals run the same report and the
 * same _exit(139): the crash contract is the exit status, not the signal.
 */

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define LINE_CAP 256        /* request line cap; also handle_warm's flaw    */
#define STAGING_CAP 256    /* the wrong constant: the line cap, not the
                            * 64-byte scratch the copy writes into         */
#define TABLE_SLOTS 4       /* ...the author counted the sealed slot too    */
#define SCRATCH_BYTES 64    /* the warmup scratch the staging write targets */
#define TOKEN_CAPACITY 24   /* engagement key slot, at offset 0x68         */
#define GUARD_OFFSET 0x2000 /* arena bytes before the PROT_NONE page       */
#define ARENA_SIZE (GUARD_OFFSET + 0x1000)

/* Every run's sealed output carries these markers; the service greps for
 * them, and the offline suite pins them verbatim against this source. */
#define SEALED_MARKER "dispatcher: sealed recovery path reached\n"
#define KEY_PREFIX "dispatcher: sealed key: "

/* The run context. The offsets are the contract the two flaws exploit, so
 * they are pinned at compile time:
 *   scratch 0x0000-0x003f  warmup staging buffer (the write flaw's target)
 *   table   0x0040-0x005f  dispatch entries PING/STAT/DUMP/WARM
 *   sealed  0x0060-0x0067  &print_sealed_path; reached by no command
 *   token   0x0068-0x007f  this run's engagement key
 *   tag     0x0080-0x0087  build tag
 */
struct context {
    char scratch[SCRATCH_BYTES];
    void (*table[TABLE_SLOTS])(volatile struct context *ctx, const char *line);
    void (*sealed)(volatile struct context *ctx, const char *line);
    char token[TOKEN_CAPACITY];
    char tag[8];
};

typedef void (*handler_t)(volatile struct context *ctx, const char *line);

_Static_assert(offsetof(struct context, table) == 0x40,
               "dispatch table must sit right after the scratch");
_Static_assert(offsetof(struct context, sealed) == 0x60,
               "sealed slot must sit right after the table");
_Static_assert(offsetof(struct context, sealed)
                   - offsetof(struct context, table)
               == TABLE_SLOTS * sizeof(handler_t),
               "the DUMP off-by-one must land on the sealed slot");
_Static_assert(offsetof(struct context, token) == 0x68, "token slot offset");
_Static_assert(offsetof(struct context, tag) == 0x80, "tag slot offset");

static volatile struct context *g_arena; /* set before the handler installs */
static unsigned long g_commands;         /* commands processed this run     */

/* -- async-signal-safe output: write() only, no printf ------------------- */

static void write_all(int fd, const char *data, size_t length) {
    while (length > 0) {
        ssize_t written = write(fd, data, length);
        if (written <= 0)
            _exit(139); /* the report pipe is gone; nothing more to say */
        data += written;
        length -= (size_t)written;
    }
}

static void out_line(const char *data, size_t length) {
    write_all(STDOUT_FILENO, data, length);
}

static void err_line(const char *data, size_t length) {
    write_all(STDERR_FILENO, data, length);
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
    char scratch[24];
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

static size_t append_dec(char *dst, unsigned long value) {
    /* Decimal, for the human-facing counts (command and staging totals):
     * these messages read as counts, so they must not drift into hex. */
    char scratch[24];
    int digits = 0;
    do {
        scratch[digits++] = "0123456789"[value % 10];
        value /= 10;
    } while (value > 0);
    for (int i = 0; i < digits; i++)
        dst[i] = scratch[digits - 1 - i];
    return (size_t)digits;
}

static void fault_report(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext;
    char line[96];
    size_t at;
    const unsigned char *bytes = (const unsigned char *)g_arena;

    if ((sig != SIGSEGV && sig != SIGBUS) || bytes == NULL)
        _exit(139);
    unsigned long offset = (unsigned long)((const char *)info->si_addr
                                           - (const char *)bytes);

    /* The sanitized report: the fault as an arena offset, and a hexdump of
     * the warmup scratch alone. The dispatch table, the sealed pointer and
     * the token slot are never dumped — a crash must not become a second
     * disclosure path beside the two flaws the drill grades on. */
    at = 0;
    at += append_str(line + at, "dispatcher: segmentation fault (SIGSEGV)\n");
    err_line(line, at);
    at = 0;
    at += append_str(line + at, "fault at context offset 0x");
    at += append_hex(line + at, offset, 0);
    at += append_str(line + at, "\n");
    err_line(line, at);
    at = 0;
    at += append_str(line + at, "build: live\n");
    err_line(line, at);
    at = 0;
    at += append_str(line + at, "scratch hexdump 0x0000-0x003f:\n");
    err_line(line, at);

    for (unsigned row = 0; row < SCRATCH_BYTES; row += 16) {
        at = 0;
        at += append_hex(line + at, row, 4);
        line[at++] = ':';
        line[at++] = ' ';
        for (int i = 0; i < 16; i++) {
            at += append_hex(line + at, bytes[row + i], 2);
            line[at++] = ' ';
        }
        line[at++] = '\n';
        err_line(line, at);
    }
    _exit(139); /* the crash contract the service grades on: 139,
                * whichever signal fired */
}

/* -- parsing helpers ------------------------------------------------------- */

static int word_is(const char *line, const char *word) {
    /* True when the line's first word IS `word` and a terminator follows. */
    size_t n = 0;
    while (word[n] != '\0') {
        if (line[n] != word[n])
            return 0;
        n++;
    }
    return line[n] == '\0' || line[n] == '\n' || line[n] == ' ';
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* -- the sealed recovery function ------------------------------------------ */

/* The one path that prints the engagement key. No command routes here; the
 * drill's objective is to make a dispatch entry point at it. It is also the
 * handler shape, so a hijacked entry calls it directly. */
static void print_sealed_path(volatile struct context *ctx,
                              const char *line) {
    char buffer[128];
    size_t at = 0;
    (void)line;

    at += append_str(buffer + at, SEALED_MARKER);
    at += append_str(buffer + at, KEY_PREFIX);
    for (size_t i = 0; i < TOKEN_CAPACITY && ctx->token[i] != '\0'; i++)
        buffer[at++] = ctx->token[i];
    buffer[at++] = '\n';
    out_line(buffer, at);
    _exit(0); /* the sealed path terminates the run it hijacked */
}

/* -- command handlers (the dispatch table's entries) ----------------------- */

static void handle_ping(volatile struct context *ctx, const char *line) {
    char buffer[64];
    (void)ctx;
    (void)line;
    size_t at = 0;
    at += append_str(buffer + at, "dispatcher: pong\n");
    out_line(buffer, at);
}

static void handle_stat(volatile struct context *ctx, const char *line) {
    char buffer[80];
    (void)ctx;
    (void)line;
    size_t at = 0;
    at += append_str(buffer + at, "dispatcher: commands=");
    at += append_dec(buffer + at, g_commands);
    at += append_str(buffer + at, "\n");
    out_line(buffer, at);
}

/* DUMP <idx>: print one diagnostic slot. FLAW: the bounds check counts the
 * sealed pointer as a fifth slot (the author wrote TABLE_SLOTS and counted
 * the sealed slot when documenting the diagnostics), so idx == 4 is
 * accepted and reads one past the table — landing on the sealed slot by
 * struct adjacency. That read is the drill's information leak: the sealed
 * path's address is fixed for this build (the drill image links the binary
 * fixed-address so replays are comparable) and stable across the per-request
 * fresh processes, and no other in-scope output ever carries a code
 * address. */
static void handle_dump(volatile struct context *ctx, const char *line) {
    char *end = NULL;
    char buffer[96];
    long idx = strtol(line + 4, &end, 10);
    size_t at = 0;

    if (end == line + 4) {
        at += append_str(buffer + at, "dispatcher: dump needs a slot index\n");
        err_line(buffer, at);
        return;
    }
    if (idx > TABLE_SLOTS) {
        at += append_str(buffer + at, "dispatcher: dump slot out of range\n");
        err_line(buffer, at);
        return;
    }
    at += append_str(buffer + at, "dispatcher: slot[");
    at += append_hex(buffer + at, (unsigned long)idx, 0);
    at += append_str(buffer + at, "] = 0x");
    at += append_hex(buffer + at, (unsigned long)ctx->table[idx], 0);
    at += append_str(buffer + at, "\n");
    out_line(buffer, at);
}

/* WARM <declared> <hex>: stage a warmup payload into the scratch buffer, for
 * replay drills. FLAW: the declared length is validated against the request
 * line cap (STAGING_CAP) instead of the scratch it copies into, so a
 * declared length past 64 walks the decoded copy over the dispatch table
 * (and, past that, the sealed slot and the token). Sixty-four bytes of
 * padding plus eight little-endian bytes of leaked address overwrites the
 * first dispatch entry exactly; anything longer begins to destroy the key
 * the drill grades on. The copy stops early when the hex payload runs out. */
static void handle_warm(volatile struct context *ctx, const char *line) {
    char *end = NULL;
    char buffer[80];
    long declared = strtol(line + 5, &end, 10);
    long written = 0;
    const char *hex;
    size_t at = 0;

    if (end == line + 5) {
        at += append_str(buffer + at, "dispatcher: warm needs a byte count\n");
        err_line(buffer, at);
        return;
    }
    if (declared < 0 || declared > STAGING_CAP) {
        at += append_str(buffer + at, "dispatcher: warm byte count rejected\n");
        err_line(buffer, at);
        return;
    }
    hex = end;
    while (*hex == ' ')
        hex++;
    for (long i = 0; i < declared; i++) {
        int hi = hex_val(hex[2 * i]);
        int lo = hex_val(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            break; /* hex payload shorter than declared: stage what is there */
        ((volatile char *)ctx->scratch)[i] = (char)(hi * 16 + lo);
        written++;
    }
    at += append_str(buffer + at, "dispatcher: staged ");
    at += append_dec(buffer + at, (unsigned long)written);
    at += append_str(buffer + at, " byte(s) into the warmup scratch\n");
    out_line(buffer, at);
}

/* -- the dispatch loop ------------------------------------------------------ */

int main(void) {
    char line[LINE_CAP];
    struct sigaction action;
    unsigned char *arena;
    const char *stamp;
    long opcode;

    /* Every offset in the report and flaw contract is fixed by the
     * 4096-byte page: the guard page at 0x2000, the scratch at 0x0000. Refuse
     * to run — loudly — on a kernel that does not provide it. */
    if (sysconf(_SC_PAGESIZE) != 4096) {
        fprintf(stderr, "dispatcher: requires 4096-byte pages\n");
        return 70;
    }

    /* Two read-write pages, then a PROT_NONE guard page: the arena offsets
     * are fixed by construction, independent of toolchain and layout. */
    arena = mmap(NULL, ARENA_SIZE, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (arena == MAP_FAILED) {
        perror("dispatcher: mmap");
        return 71;
    }
    if (mprotect(arena + GUARD_OFFSET, 0x1000, PROT_NONE) != 0) {
        perror("dispatcher: mprotect");
        return 71;
    }
    memset(arena, 0, GUARD_OFFSET); /* deterministic run context */
    g_arena = (volatile struct context *)(void *)arena;
    g_arena->table[0] = handle_ping;
    g_arena->table[1] = handle_stat;
    g_arena->table[2] = handle_dump;
    g_arena->table[3] = handle_warm;
    g_arena->sealed = print_sealed_path;
    memcpy((void *)g_arena->tag, "live", 4);
    stamp = getenv("PALISADE_TOKEN");
    if (stamp != NULL)
        memcpy((void *)g_arena->token, stamp,
               strnlen(stamp, TOKEN_CAPACITY - 1));

    memset(&action, 0, sizeof action);
    action.sa_sigaction = fault_report;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    /* A hijacked dispatch entry lands wherever the staged bytes point: an
     * unmapped target faults the fetch as SIGSEGV, a misaligned one as
     * SIGBUS (the arm64 instruction alignment fault). Both must produce
     * the one sanitized report and the one crash exit the service grades
     * on — a bare signal death would leak nothing, but it would also say
     * nothing, and the crash contract is how misses stay observable. */
    if (sigaction(SIGSEGV, &action, NULL) != 0
        || sigaction(SIGBUS, &action, NULL) != 0) {
        perror("dispatcher: sigaction");
        return 71;
    }

    /* One command per line; each dispatch re-reads its table entry, so a
     * staging write that reached the table steers the next command. The
     * context is volatile throughout: no load or store of the arena may be
     * cached or elided across a handler call. */
    while (fgets(line, sizeof line, stdin) != NULL) {
        g_commands++;
        if (word_is(line, "PING"))
            opcode = 0;
        else if (word_is(line, "STAT"))
            opcode = 1;
        else if (word_is(line, "DUMP"))
            opcode = 2;
        else if (word_is(line, "WARM"))
            opcode = 3;
        else {
            err_line("dispatcher: unknown command (ignored)\n", 35);
            continue;
        }
        g_arena->table[opcode](g_arena, line);
    }
    return 0;
}
