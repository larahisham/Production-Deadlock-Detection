#define _GNU_SOURCE
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define OP_ACQUIRE 1
#define OP_RELEASE 2
#define OP_BLOCK 3
#define OP_UNBLOCK 4

#define SRC_MUTEX 1
#define SRC_FUTEX 2
#define SRC_PTHREAD 3
#define SRC_RUST_STDMUTEX 4
#define SRC_PARKING_LOT 5
#define SRC_PRELOAD 6

#define MAX_LINKS 256
#define MAX_EDGES 4096
#define MAX_LOCK_STATS 4096
#define MAX_ALERT_STATES 4096
#define MAX_FINDING_RULES 256
#define MAX_TARGET_PIDS 256
#define MAX_TARGET_CGROUPS 256
#define MAX_COMM_FILTERS 64
#define MAX_PROFILER_PATTERNS 64
#define MAX_PID_PROFILES 2048

#define MIN_WAIT_NS_DEFAULT (5ULL * 1000 * 1000)
#define MIN_WAIT_NS_RUST (20ULL * 1000 * 1000)
#define ALERT_COOLDOWN_NS (15ULL * 1000 * 1000 * 1000)
#define MIN_ALERT_REPEATS 2
#define MIN_ALERT_REPEATS_ASYNC 4
#define ACTIVE_BLOCK_ALERT_NS (30ULL * 1000 * 1000)
#define ALERT_STATE_TTL_NS (10ULL * 60ULL * 1000ULL * 1000ULL * 1000ULL)
#define WAIT_EDGE_TTL_NS (5ULL * 60ULL * 1000ULL * 1000ULL * 1000ULL)
#define PID_PROFILE_REFRESH_NS (5ULL * 1000ULL * 1000ULL * 1000ULL)
#define STATIC_FINDINGS_DEFAULT "../../output/static_findings.csv"
#define PROFILER_PATTERNS_DEFAULT "../../output/profiler_filters.txt"
#define RUST_SYMBOLS_DEFAULT "../../output/rust_mutex_symbols.txt"
#define LOCK_DWARF_MAP_DEFAULT "../../output/lock_dwarf_map.txt"
#define MAX_CUSTOM_SYMBOL_TARGETS 256
#define MAX_LOCK_METADATA 4096
#define PRELOAD_SOCKET_PATH "/tmp/deadlock-detector.sock"

struct lock_event {
    uint32_t pid;
    uint32_t tid;
    uint32_t owner_tid;
    uint8_t op;
    uint8_t source;
    uint16_t reserved;
    char comm[16];
    uint64_t cgroup_id;
    uint64_t lock_addr;
    uint64_t timestamp_ns;
    uint64_t wait_ns;
    uint64_t hold_ns;
};

struct wait_edge {
    uint32_t from_tid;
    uint32_t to_tid;
    uint64_t lock_addr;
    uint64_t blocked_since_ns;
    uint8_t source;
};

struct lock_stat {
    uint64_t lock_addr;
    uint64_t total_wait_ns;
    uint64_t total_hold_ns;
    uint64_t max_wait_ns;
    uint64_t max_hold_ns;
    uint64_t wait_count;
    uint64_t hold_count;
};

struct alert_state {
    uint32_t blocked_tid;
    uint32_t blocked_pid;
    uint32_t owner_tid;
    uint64_t lock_addr;
    uint64_t cgroup_id;
    uint64_t first_seen_ns;
    uint64_t last_seen_ns;
    uint64_t last_emit_ns;
    uint64_t last_wait_ns;
    uint32_t repeats;
    uint32_t alerts_emitted;
    uint8_t cycle_seen;
    uint8_t source;
    char comm[16];
};

struct finding_rule {
    char comm_pattern[32];
    uint64_t min_wait_ns;
    int severity_boost;
    char note[96];
    char field[12];
};

struct pid_profile {
    uint32_t pid;
    uint64_t last_refresh_ns;
    char exe_path[PATH_MAX];
    char runtime[16];
    uint8_t rust_like;
};

struct custom_symbol_target {
    char source[16];
    char library[PATH_MAX];
    char symbol[256];
    char phase[16];
};

struct external_lock_event {
    uint32_t pid;
    uint32_t tid;
    uint32_t owner_tid;
    uint8_t op;
    uint8_t source;
    uint16_t reserved;
    char comm[16];
    uint64_t lock_addr;
    uint64_t timestamp_ns;
    uint64_t wait_ns;
    uint64_t hold_ns;
};

struct lock_metadata {
    uint64_t lock_addr;
    char type_name[96];
    char location[128];
};

static volatile sig_atomic_t exiting;
static struct wait_edge wait_edges[MAX_EDGES];
static size_t wait_edges_count;
static struct lock_stat lock_stats[MAX_LOCK_STATS];
static size_t lock_stats_count;
static struct alert_state alert_states[MAX_ALERT_STATES];
static size_t alert_states_count;
static struct finding_rule finding_rules[MAX_FINDING_RULES];
static size_t finding_rules_count;
static uint64_t event_counter;
static uint64_t alert_counter;
static uint64_t filtered_counter;
static uint32_t target_pids[MAX_TARGET_PIDS];
static size_t target_pids_count;
static uint64_t target_cgroups[MAX_TARGET_CGROUPS];
static size_t target_cgroups_count;
static char comm_filters[MAX_COMM_FILTERS][16];
static size_t comm_filters_count;
static char profiler_patterns[MAX_PROFILER_PATTERNS][32];
static size_t profiler_patterns_count;
static struct pid_profile pid_profiles[MAX_PID_PROFILES];
static size_t pid_profiles_count;
static uint64_t last_gc_ns;
static uint64_t last_active_scan_ns;
static bool allow_profiler_signals;
static struct custom_symbol_target custom_symbol_targets[MAX_CUSTOM_SYMBOL_TARGETS];
static size_t custom_symbol_targets_count;
static struct lock_metadata lock_metadata_entries[MAX_LOCK_METADATA];
static size_t lock_metadata_count;
static int preload_sock_fd = -1;

static void trim_newline(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[n - 1] = '\0';
        n--;
    }
}

static char *trim_spaces(char *s)
{
    char *end;

    while (*s && isspace((unsigned char)*s))
        s++;

    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        end--;

    *end = '\0';
    return s;
}

static void to_lower_copy(char *dst, size_t dst_sz, const char *src)
{
    size_t i;

    if (dst_sz == 0)
        return;

    for (i = 0; i + 1 < dst_sz && src[i] != '\0'; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);

    dst[i] = '\0';
}

static void detect_runtime_from_maps(uint32_t pid, char *runtime_out, size_t runtime_out_sz, uint8_t *rust_like)
{
    char path[64];
    FILE *fp;
    char line[512];

    snprintf(path, sizeof(path), "/proc/%u/maps", pid);
    fp = fopen(path, "r");
    if (!fp)
        return;

    while (fgets(line, sizeof(line), fp)) {
        char lower[512];
        to_lower_copy(lower, sizeof(lower), line);

        if (strstr(lower, "librust") || strstr(lower, "libstd-") || strstr(lower, "rustc"))
            *rust_like = 1;
        if (strstr(lower, "tokio")) {
            snprintf(runtime_out, runtime_out_sz, "%s", "tokio");
            *rust_like = 1;
        } else if (strstr(lower, "actix")) {
            snprintf(runtime_out, runtime_out_sz, "%s", "actix");
            *rust_like = 1;
        } else if (strstr(lower, "async-std") || strstr(lower, "async_std")) {
            snprintf(runtime_out, runtime_out_sz, "%s", "async-std");
            *rust_like = 1;
        } else if (strstr(lower, "smol")) {
            snprintf(runtime_out, runtime_out_sz, "%s", "smol");
            *rust_like = 1;
        } else if (strstr(lower, "parking_lot")) {
            snprintf(runtime_out, runtime_out_sz, "%s", "parking_lot");
            *rust_like = 1;
        }
    }

    fclose(fp);
}

static struct pid_profile *get_pid_profile(uint32_t pid, const char *comm, uint64_t now_ns)
{
    size_t i;
    struct pid_profile *slot = NULL;

    for (i = 0; i < pid_profiles_count; i++) {
        if (pid_profiles[i].pid == pid) {
            slot = &pid_profiles[i];
            break;
        }
    }

    if (!slot) {
        if (pid_profiles_count >= MAX_PID_PROFILES)
            return NULL;
        slot = &pid_profiles[pid_profiles_count++];
        memset(slot, 0, sizeof(*slot));
        slot->pid = pid;
    }

    if (slot->last_refresh_ns != 0 && (now_ns - slot->last_refresh_ns) < PID_PROFILE_REFRESH_NS)
        return slot;

    {
        char proc_exe[64];
        ssize_t n;
        char lower_exe[PATH_MAX];
        char lower_comm[32];

        memset(slot->exe_path, 0, sizeof(slot->exe_path));
        memset(slot->runtime, 0, sizeof(slot->runtime));
        slot->rust_like = 0;

        snprintf(proc_exe, sizeof(proc_exe), "/proc/%u/exe", pid);
        n = readlink(proc_exe, slot->exe_path, sizeof(slot->exe_path) - 1);
        if (n > 0)
            slot->exe_path[n] = '\0';

        to_lower_copy(lower_exe, sizeof(lower_exe), slot->exe_path);
        to_lower_copy(lower_comm, sizeof(lower_comm), comm ? comm : "");

        if (strstr(lower_exe, "rust") || strstr(lower_comm, "rust") || strstr(lower_comm, "cargo"))
            slot->rust_like = 1;

        if (strstr(lower_exe, "tokio") || strstr(lower_comm, "tokio")) {
            snprintf(slot->runtime, sizeof(slot->runtime), "%s", "tokio");
            slot->rust_like = 1;
        } else if (strstr(lower_exe, "actix") || strstr(lower_comm, "actix")) {
            snprintf(slot->runtime, sizeof(slot->runtime), "%s", "actix");
            slot->rust_like = 1;
        } else if (strstr(lower_exe, "async-std") || strstr(lower_exe, "async_std") ||
                   strstr(lower_comm, "async-std") || strstr(lower_comm, "async_std")) {
            snprintf(slot->runtime, sizeof(slot->runtime), "%s", "async-std");
            slot->rust_like = 1;
        } else if (strstr(lower_exe, "smol") || strstr(lower_comm, "smol")) {
            snprintf(slot->runtime, sizeof(slot->runtime), "%s", "smol");
            slot->rust_like = 1;
        }

        detect_runtime_from_maps(pid, slot->runtime, sizeof(slot->runtime), &slot->rust_like);
        if (slot->runtime[0] == '\0' && slot->rust_like)
            snprintf(slot->runtime, sizeof(slot->runtime), "%s", "rust");
    }

    slot->last_refresh_ns = now_ns;
    return slot;
}

static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void load_target_pids(void)
{
    const char *env = getenv("TARGET_PIDS");
    char buf[1024];
    char *tok;
    char *save;

    if (!env || env[0] == '\0')
        return;

    snprintf(buf, sizeof(buf), "%s", env);
    tok = strtok_r(buf, ",", &save);
    while (tok && target_pids_count < MAX_TARGET_PIDS) {
        unsigned long v = strtoul(tok, NULL, 10);
        if (v > 0)
            target_pids[target_pids_count++] = (uint32_t)v;
        tok = strtok_r(NULL, ",", &save);
    }
}

static void load_target_cgroups(void)
{
    const char *env = getenv("TARGET_CGROUP_IDS");
    char buf[2048];
    char *tok;
    char *save;

    if (!env || env[0] == '\0')
        return;

    snprintf(buf, sizeof(buf), "%s", env);
    tok = strtok_r(buf, ",", &save);
    while (tok && target_cgroups_count < MAX_TARGET_CGROUPS) {
        unsigned long long v = strtoull(tok, NULL, 10);
        if (v > 0)
            target_cgroups[target_cgroups_count++] = (uint64_t)v;
        tok = strtok_r(NULL, ",", &save);
    }
}

static void configure_bpf_pid_scope(struct bpf_object *obj)
{
    struct bpf_map *map;
    int fd;
    uint32_t key;
    uint8_t val = 1;
    size_t i;

    if (target_pids_count == 0)
        return;

    map = bpf_object__find_map_by_name(obj, "target_pids_map");
    if (!map) {
        fprintf(stderr, "[warn] target_pids_map not found; kernel-side PID scope disabled\n");
        return;
    }

    fd = bpf_map__fd(map);
    if (fd < 0)
        return;

    key = 0;
    if (bpf_map_update_elem(fd, &key, &val, BPF_ANY) != 0) {
        fprintf(stderr, "[warn] failed to enable kernel PID scope\n");
        return;
    }

    for (i = 0; i < target_pids_count; i++) {
        key = target_pids[i];
        if (bpf_map_update_elem(fd, &key, &val, BPF_ANY) != 0) {
            fprintf(stderr, "[warn] failed to add pid %u to kernel PID scope\n", key);
        }
    }
}

static void configure_bpf_cgroup_scope(struct bpf_object *obj)
{
    struct bpf_map *map;
    int fd;
    uint64_t key;
    uint8_t val = 1;
    size_t i;

    if (target_cgroups_count == 0)
        return;

    map = bpf_object__find_map_by_name(obj, "target_cgroups_map");
    if (!map) {
        fprintf(stderr, "[warn] target_cgroups_map not found; kernel-side cgroup scope disabled\n");
        return;
    }

    fd = bpf_map__fd(map);
    if (fd < 0)
        return;

    key = 0;
    if (bpf_map_update_elem(fd, &key, &val, BPF_ANY) != 0) {
        fprintf(stderr, "[warn] failed to enable kernel cgroup scope\n");
        return;
    }

    for (i = 0; i < target_cgroups_count; i++) {
        key = target_cgroups[i];
        if (bpf_map_update_elem(fd, &key, &val, BPF_ANY) != 0) {
            fprintf(stderr, "[warn] failed to add cgroup %llu to kernel cgroup scope\n",
                    (unsigned long long)key);
        }
    }
}

static void load_comm_filters(void)
{
    const char *env = getenv("TARGET_COMM");
    char buf[1024];
    char *tok;
    char *save;

    if (!env || env[0] == '\0')
        return;

    snprintf(buf, sizeof(buf), "%s", env);
    tok = strtok_r(buf, ",", &save);
    while (tok && comm_filters_count < MAX_COMM_FILTERS) {
        to_lower_copy(comm_filters[comm_filters_count], sizeof(comm_filters[comm_filters_count]), tok);
        comm_filters_count++;
        tok = strtok_r(NULL, ",", &save);
    }
}

static bool pid_allowed(uint32_t pid)
{
    size_t i;

    if (target_pids_count == 0)
        return true;
    for (i = 0; i < target_pids_count; i++) {
        if (target_pids[i] == pid)
            return true;
    }
    return false;
}

static bool cgroup_allowed(uint64_t cgroup_id)
{
    size_t i;

    if (target_cgroups_count == 0)
        return true;
    for (i = 0; i < target_cgroups_count; i++) {
        if (target_cgroups[i] == cgroup_id)
            return true;
    }
    return false;
}

static bool comm_allowed(const char *comm)
{
    char lower[32];
    size_t i;

    if (comm_filters_count == 0)
        return true;

    to_lower_copy(lower, sizeof(lower), comm);
    for (i = 0; i < comm_filters_count; i++) {
        if (strstr(lower, comm_filters[i]) != NULL)
            return true;
    }
    return false;
}

static bool is_profiler_comm(const char *comm)
{
    char lower[32];
    size_t i;

    to_lower_copy(lower, sizeof(lower), comm);
    for (i = 0; i < profiler_patterns_count; i++) {
        if (strstr(lower, profiler_patterns[i]) != NULL)
            return true;
    }

    if (profiler_patterns_count == 0) {
        if (strstr(lower, "perf") != NULL ||
            strstr(lower, "py-spy") != NULL ||
            strstr(lower, "rbspy") != NULL ||
            strstr(lower, "async-profiler") != NULL ||
            strstr(lower, "profiler") != NULL ||
            strstr(lower, "bpftrace") != NULL ||
            strstr(lower, "bcc") != NULL) {
            return true;
        }
    }

    return false;
}

static int load_static_rules(const char *path)
{
    FILE *fp;
    char line[256];

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        char *tok;
        char *rest = line;
        char *pattern;
        char *min_wait_ms;
        char *boost;
        char *note;
        char *field;
        struct finding_rule *rule;

        trim_newline(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;
        if (finding_rules_count >= MAX_FINDING_RULES)
            break;

        tok = strtok_r(rest, ",", &rest);
        pattern = tok;
        min_wait_ms = strtok_r(NULL, ",", &rest);
        boost = strtok_r(NULL, ",", &rest);
        note = strtok_r(NULL, "", &rest);
        field = NULL;

        if (note) {
            char *last_comma = strrchr(note, ',');
            if (last_comma) {
                field = last_comma + 1;
                *last_comma = '\0';
            }
        }

        if (!pattern || !min_wait_ms || !boost)
            continue;

        rule = &finding_rules[finding_rules_count++];
        snprintf(rule->comm_pattern, sizeof(rule->comm_pattern), "%s", pattern);
        rule->min_wait_ns = (uint64_t)strtoull(min_wait_ms, NULL, 10) * 1000000ULL;
        rule->severity_boost = atoi(boost);
        if (note)
            snprintf(rule->note, sizeof(rule->note), "%s", note);
        else
            rule->note[0] = '\0';
        if (field)
            snprintf(rule->field, sizeof(rule->field), "%s", field);
        else
            snprintf(rule->field, sizeof(rule->field), "%s", "comm");
        trim_newline(rule->field);
    }

    fclose(fp);
    return 0;
}

static int load_profiler_patterns(const char *path)
{
    FILE *fp;
    char line[128];

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        if (profiler_patterns_count >= MAX_PROFILER_PATTERNS)
            break;

        trim_newline(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;

        to_lower_copy(profiler_patterns[profiler_patterns_count],
                      sizeof(profiler_patterns[profiler_patterns_count]),
                      line);
        profiler_patterns_count++;
    }

    fclose(fp);
    return 0;
}

static int load_custom_symbol_targets(const char *path)
{
    FILE *fp;
    char line[PATH_MAX + 320];

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        char *tok;
        char *rest = line;
        char *source;
        char *library;
        char *symbol;
        char *phase;
        struct custom_symbol_target *target;

        trim_newline(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;
        if (custom_symbol_targets_count >= MAX_CUSTOM_SYMBOL_TARGETS)
            break;

        source = strtok_r(rest, ",", &rest);
        library = strtok_r(NULL, ",", &rest);
        symbol = strtok_r(NULL, ",", &rest);
        phase = strtok_r(NULL, ",", &rest);
        tok = strtok_r(NULL, ",", &rest);

        if (tok != NULL) {
            fprintf(stderr, "[warn] skipping malformed custom symbol line with extra columns: %s\n", line);
            continue;
        }

        if (!source || !library || !symbol || !phase)
            continue;

        source = trim_spaces(source);
        library = trim_spaces(library);
        symbol = trim_spaces(symbol);
        phase = trim_spaces(phase);

        if (source[0] == '\0' || library[0] == '\0' || symbol[0] == '\0' || phase[0] == '\0')
            continue;

        target = &custom_symbol_targets[custom_symbol_targets_count++];
        to_lower_copy(target->source, sizeof(target->source), source);
        snprintf(target->library, sizeof(target->library), "%s", library);
        snprintf(target->symbol, sizeof(target->symbol), "%s", symbol);
        to_lower_copy(target->phase, sizeof(target->phase), phase);
    }

    fclose(fp);
    return 0;
}

static int load_lock_metadata(const char *path)
{
    FILE *fp;
    char line[400];

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        char *rest = line;
        char *addr_tok;
        char *type_tok;
        char *loc_tok;
        struct lock_metadata *entry;
        unsigned long long parsed = 0;

        trim_newline(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;
        if (lock_metadata_count >= MAX_LOCK_METADATA)
            break;

        addr_tok = strtok_r(rest, ",", &rest);
        type_tok = strtok_r(NULL, ",", &rest);
        loc_tok = strtok_r(NULL, "", &rest);

        if (!addr_tok || !type_tok)
            continue;

        addr_tok = trim_spaces(addr_tok);
        type_tok = trim_spaces(type_tok);
        if (loc_tok)
            loc_tok = trim_spaces(loc_tok);

        if (addr_tok[0] == '\0' || type_tok[0] == '\0')
            continue;

        if (strncmp(addr_tok, "0x", 2) == 0 || strncmp(addr_tok, "0X", 2) == 0)
            parsed = strtoull(addr_tok + 2, NULL, 16);
        else
            parsed = strtoull(addr_tok, NULL, 16);

        if (parsed == 0)
            continue;

        entry = &lock_metadata_entries[lock_metadata_count++];
        entry->lock_addr = (uint64_t)parsed;
        snprintf(entry->type_name, sizeof(entry->type_name), "%s", type_tok);
        if (loc_tok)
            snprintf(entry->location, sizeof(entry->location), "%s", loc_tok);
        else
            entry->location[0] = '\0';
    }

    fclose(fp);
    return 0;
}

static void handle_signal(int sig)
{
    (void)sig;
    exiting = 1;
}

static const char *source_name(uint8_t source)
{
    if (source == SRC_MUTEX)
        return "mutex";
    if (source == SRC_PTHREAD)
        return "pthread";
    if (source == SRC_RUST_STDMUTEX)
        return "rust_std";
    if (source == SRC_PARKING_LOT)
        return "parking_lot";
    if (source == SRC_PRELOAD)
        return "preload";
    return "futex";
}

static const struct lock_metadata *find_lock_metadata(uint64_t lock_addr)
{
    size_t i;

    for (i = 0; i < lock_metadata_count; i++) {
        if (lock_metadata_entries[i].lock_addr == lock_addr)
            return &lock_metadata_entries[i];
    }

    return NULL;
}

static int setup_preload_socket(void)
{
    struct sockaddr_un addr;
    int fd;

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", PRELOAD_SOCKET_PATH);

    unlink(PRELOAD_SOCKET_PATH);
    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
        close(fd);
        unlink(PRELOAD_SOCKET_PATH);
        return -1;
    }

    return fd;
}

static void close_preload_socket(void)
{
    if (preload_sock_fd >= 0) {
        close(preload_sock_fd);
        preload_sock_fd = -1;
    }
    unlink(PRELOAD_SOCKET_PATH);
}

static struct bpf_link *attach_uprobe_symbol_path(struct bpf_program *prog,
                                                  const char *path,
                                                  const char *symbol,
                                                  bool retprobe)
{
    struct bpf_link *link;
    LIBBPF_OPTS(bpf_uprobe_opts, opts,
        .retprobe = retprobe,
        .func_name = symbol,
    );

    if (!path || !symbol)
        return NULL;
    if (access(path, R_OK) != 0)
        return NULL;

    link = bpf_program__attach_uprobe_opts(prog, -1, path, 0, &opts);
    if (libbpf_get_error(link))
        return NULL;

    printf("[ok] attached %s on %s:%s\n",
           bpf_program__name(prog),
           path,
           symbol);
    return link;
}

static struct bpf_link *attach_pthread_symbol(struct bpf_program *prog,
                                               const char *symbol,
                                               bool retprobe)
{
    static const char *candidates[] = {
        "/lib/x86_64-linux-gnu/libpthread.so.0",
        "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
    };
    size_t i;

    for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        struct bpf_link *link = attach_uprobe_symbol_path(prog, candidates[i], symbol, retprobe);

        if (link) {
            return link;
        }
    }

    return NULL;
}

static bool is_rust_comm(const char *comm)
{
    char lower[32];

    to_lower_copy(lower, sizeof(lower), comm);
    return strstr(lower, "rust") != NULL || strstr(lower, "cargo") != NULL ||
           strstr(lower, "tokio") != NULL || strstr(lower, "actix") != NULL ||
           strstr(lower, "axum") != NULL || strstr(lower, "async") != NULL ||
           strstr(lower, "smol") != NULL;
}

static bool is_async_runtime(const struct pid_profile *profile)
{
    char lower_runtime[32];

    if (!profile)
        return false;

    to_lower_copy(lower_runtime, sizeof(lower_runtime), profile->runtime);
    return strstr(lower_runtime, "tokio") != NULL ||
           strstr(lower_runtime, "actix") != NULL ||
           strstr(lower_runtime, "async-std") != NULL ||
           strstr(lower_runtime, "smol") != NULL;
}

static bool add_link(struct bpf_link **links, size_t *link_count, struct bpf_link *link)
{
    if (!link)
        return false;
    if (*link_count >= MAX_LINKS) {
        fprintf(stderr, "Too many links, increase MAX_LINKS\n");
        bpf_link__destroy(link);
        return false;
    }

    links[*link_count] = link;
    (*link_count)++;
    return true;
}

static size_t attach_custom_symbol_targets(struct bpf_program *prog,
                                           const char *source,
                                           const char *phase,
                                           bool retprobe,
                                           struct bpf_link **links,
                                           size_t *link_count)
{
    size_t i;
    size_t attached = 0;

    for (i = 0; i < custom_symbol_targets_count; i++) {
        struct bpf_link *link;

        if (strcmp(custom_symbol_targets[i].source, source) != 0)
            continue;
        if (strcmp(custom_symbol_targets[i].phase, phase) != 0)
            continue;

        link = attach_uprobe_symbol_path(prog,
                                         custom_symbol_targets[i].library,
                                         custom_symbol_targets[i].symbol,
                                         retprobe);
        if (!link)
            continue;
        if (!add_link(links, link_count, link))
            break;
        attached++;
    }

    return attached;
}

static bool is_filtered_noise(const struct lock_event *ev)
{
    if (!pid_allowed(ev->pid))
        return true;
    if (!cgroup_allowed(ev->cgroup_id))
        return true;
    if (!comm_allowed(ev->comm))
        return true;
    if (!allow_profiler_signals && is_profiler_comm(ev->comm))
        return true;
    if (ev->pid <= 2)
        return true;
    if (ev->owner_tid == ev->tid && ev->owner_tid != 0)
        return true;
    if (ev->lock_addr == 0)
        return true;
    if (strncmp(ev->comm, "kworker", 7) == 0 || strncmp(ev->comm, "rcu_", 4) == 0)
        return true;
    return false;
}

static struct alert_state *find_or_create_alert_state(uint32_t blocked_tid, uint32_t owner_tid,
                                                      uint64_t lock_addr)
{
    size_t i;

    for (i = 0; i < alert_states_count; i++) {
        if (alert_states[i].blocked_tid == blocked_tid &&
            alert_states[i].owner_tid == owner_tid &&
            alert_states[i].lock_addr == lock_addr) {
            return &alert_states[i];
        }
    }

    if (alert_states_count >= MAX_ALERT_STATES)
        return NULL;

    alert_states[alert_states_count].blocked_tid = blocked_tid;
    alert_states[alert_states_count].owner_tid = owner_tid;
    alert_states[alert_states_count].lock_addr = lock_addr;
    return &alert_states[alert_states_count++];
}

static int static_rule_score(const struct lock_event *ev, const struct pid_profile *profile,
                             uint64_t *min_wait_ns_out, const char **note_out)
{
    char lower_comm[32];
    char lower_exe[PATH_MAX];
    char lower_runtime[32];
    size_t i;
    int boost = 0;

    to_lower_copy(lower_comm, sizeof(lower_comm), ev->comm);
    to_lower_copy(lower_exe, sizeof(lower_exe), profile ? profile->exe_path : "");
    to_lower_copy(lower_runtime, sizeof(lower_runtime), profile ? profile->runtime : "");

    for (i = 0; i < finding_rules_count; i++) {
        char lower_pat[32];
        bool matched = false;

        to_lower_copy(lower_pat, sizeof(lower_pat), finding_rules[i].comm_pattern);
        if (strcmp(finding_rules[i].field, "exe") == 0) {
            matched = strstr(lower_exe, lower_pat) != NULL;
        } else if (strcmp(finding_rules[i].field, "runtime") == 0) {
            matched = strstr(lower_runtime, lower_pat) != NULL;
        } else {
            matched = strstr(lower_comm, lower_pat) != NULL;
        }

        if (matched) {
            if (finding_rules[i].min_wait_ns > *min_wait_ns_out)
                *min_wait_ns_out = finding_rules[i].min_wait_ns;
            boost += finding_rules[i].severity_boost;
            if (finding_rules[i].note[0] != '\0')
                *note_out = finding_rules[i].note;
        }
    }

    return boost;
}

static const char *severity_label(int score)
{
    if (score >= 8)
        return "critical";
    if (score >= 5)
        return "high";
    if (score >= 3)
        return "medium";
    return "low";
}

static struct lock_stat *find_or_create_lock_stat(uint64_t lock_addr)
{
    size_t i;

    for (i = 0; i < lock_stats_count; i++) {
        if (lock_stats[i].lock_addr == lock_addr)
            return &lock_stats[i];
    }

    if (lock_stats_count >= MAX_LOCK_STATS)
        return NULL;

    lock_stats[lock_stats_count].lock_addr = lock_addr;
    return &lock_stats[lock_stats_count++];
}

static void update_metrics(const struct lock_event *ev)
{
    struct lock_stat *st;

    st = find_or_create_lock_stat(ev->lock_addr);
    if (!st)
        return;

    if (ev->wait_ns > 0) {
        st->total_wait_ns += ev->wait_ns;
        st->wait_count++;
        if (ev->wait_ns > st->max_wait_ns)
            st->max_wait_ns = ev->wait_ns;
    }

    if (ev->hold_ns > 0) {
        st->total_hold_ns += ev->hold_ns;
        st->hold_count++;
        if (ev->hold_ns > st->max_hold_ns)
            st->max_hold_ns = ev->hold_ns;
    }
}

static int find_edge_idx_by_from(uint32_t from_tid)
{
    size_t i;

    for (i = 0; i < wait_edges_count; i++) {
        if (wait_edges[i].from_tid == from_tid)
            return (int)i;
    }

    return -1;
}

static int find_path_to(uint32_t current, uint32_t target, uint8_t depth)
{
    size_t i;

    if (depth > 32)
        return 0;
    if (current == target)
        return 1;

    for (i = 0; i < wait_edges_count; i++) {
        if (wait_edges[i].from_tid == current) {
            if (find_path_to(wait_edges[i].to_tid, target, depth + 1))
                return 1;
        }
    }

    return 0;
}

static void print_quality_alert(const struct lock_event *ev, int score, const char *severity,
                                bool rust, uint32_t repeats, const char *correlation_note)
{
    const struct lock_metadata *meta = find_lock_metadata(ev->lock_addr);
    char lock_desc[256];

    if (meta && meta->location[0] != '\0') {
        snprintf(lock_desc,
                 sizeof(lock_desc),
                 "0x%llx (%s @ %s)",
                 (unsigned long long)ev->lock_addr,
                 meta->type_name,
                 meta->location);
    } else if (meta) {
        snprintf(lock_desc,
                 sizeof(lock_desc),
                 "0x%llx (%s)",
                 (unsigned long long)ev->lock_addr,
                 meta->type_name);
    } else {
        snprintf(lock_desc, sizeof(lock_desc), "0x%llx", (unsigned long long)ev->lock_addr);
    }

    fprintf(stderr,
            "\n[ALERT/%s] deadlock-risk\n"
            "  comm=%s pid=%u blocked_tid=%u owner_tid=%u source=%s lock=%s\n"
            "  wait=%.3f ms score=%d repeats=%u rust=%s\n"
            "  action: capture stacks for blocked_tid=%u and owner_tid=%u\n"
            "  action: shrink critical section on owner_tid=%u and enforce lock order\n"
            "  correlation: %s\n\n",
            severity,
            ev->comm,
            ev->pid,
            ev->tid,
            ev->owner_tid,
            source_name(ev->source),
            lock_desc,
            (double)ev->wait_ns / 1000000.0,
            score,
            repeats,
            rust ? "yes" : "no",
            ev->tid,
            ev->owner_tid,
            ev->owner_tid,
            correlation_note ? correlation_note : "none");
}

static void add_block_edge_and_alert(const struct lock_event *ev)
{
    int idx;
    struct alert_state *state;

    if (is_filtered_noise(ev)) {
        filtered_counter++;
        return;
    }

    if (ev->owner_tid == 0 || ev->owner_tid == ev->tid)
        return;

    idx = find_edge_idx_by_from(ev->tid);
    if (idx >= 0) {
        wait_edges[idx].to_tid = ev->owner_tid;
        wait_edges[idx].lock_addr = ev->lock_addr;
        wait_edges[idx].blocked_since_ns = ev->timestamp_ns;
        wait_edges[idx].source = ev->source;
    } else if (wait_edges_count < MAX_EDGES) {
        wait_edges[wait_edges_count].from_tid = ev->tid;
        wait_edges[wait_edges_count].to_tid = ev->owner_tid;
        wait_edges[wait_edges_count].lock_addr = ev->lock_addr;
        wait_edges[wait_edges_count].blocked_since_ns = ev->timestamp_ns;
        wait_edges[wait_edges_count].source = ev->source;
        wait_edges_count++;
    }

    state = find_or_create_alert_state(ev->tid, ev->owner_tid, ev->lock_addr);
    if (state) {
        if (state->first_seen_ns == 0)
            state->first_seen_ns = ev->timestamp_ns;
        state->blocked_pid = ev->pid;
        state->cgroup_id = ev->cgroup_id;
        state->last_seen_ns = ev->timestamp_ns;
        state->source = ev->source;
        state->last_wait_ns = 0;
        snprintf(state->comm, sizeof(state->comm), "%s", ev->comm);
        state->repeats++;
        if (find_path_to(ev->owner_tid, ev->tid, 0))
            state->cycle_seen = 1;
    }
}

static void evaluate_alert_quality(const struct lock_event *ev)
{
    struct alert_state *state;
    struct pid_profile *profile;
    uint64_t min_wait_ns = MIN_WAIT_NS_DEFAULT;
    bool rust;
    int score = 0;
    const char *note = NULL;
    int static_boost;
    const char *sev;
    uint64_t now_ns = ev->timestamp_ns;
    uint32_t min_repeats = MIN_ALERT_REPEATS;

    if (is_filtered_noise(ev)) {
        filtered_counter++;
        return;
    }

    profile = get_pid_profile(ev->pid, ev->comm, now_ns);
    rust = (profile && profile->rust_like) || is_rust_comm(ev->comm);

    if (rust)
        min_wait_ns = MIN_WAIT_NS_RUST;

    static_boost = static_rule_score(ev, profile, &min_wait_ns, &note);
    if (is_async_runtime(profile))
        min_repeats = MIN_ALERT_REPEATS_ASYNC;

    if (ev->wait_ns < min_wait_ns) {
        filtered_counter++;
        return;
    }

    state = find_or_create_alert_state(ev->tid, ev->owner_tid, ev->lock_addr);
    if (!state)
        return;
    if (!state->cycle_seen)
        return;
    if (state->repeats < min_repeats)
        return;
    if (ev->timestamp_ns - state->last_emit_ns < ALERT_COOLDOWN_NS)
        return;

    if (ev->wait_ns >= 5ULL * 1000 * 1000)
        score += 1;
    if (ev->wait_ns >= 20ULL * 1000 * 1000)
        score += 2;
    if (ev->wait_ns >= 100ULL * 1000 * 1000)
        score += 3;
    if (ev->source == SRC_MUTEX)
        score += 1;
    if (state->repeats >= 3)
        score += 2;
    if (rust)
        score -= 1;
    score += static_boost;

    sev = severity_label(score);
    if (score >= 3) {
        print_quality_alert(ev, score, sev, rust, state->repeats, note);
        state->last_emit_ns = ev->timestamp_ns;
        state->last_wait_ns = ev->wait_ns;
        state->alerts_emitted++;
        alert_counter++;
    }
}

static void scan_active_blocked_alerts(uint64_t now_ns)
{
    size_t i;

    if (now_ns - last_active_scan_ns < 1000000000ULL)
        return;
    last_active_scan_ns = now_ns;

    for (i = 0; i < alert_states_count; i++) {
        struct alert_state *st = &alert_states[i];
        uint64_t active_wait_ns;
        int score;
        const char *sev;
        bool rust;
        struct pid_profile *profile;
        struct lock_event ev = {0};

        if (!st->cycle_seen)
            continue;
        if (st->last_seen_ns == 0 || st->last_seen_ns < st->last_emit_ns)
            continue;
        active_wait_ns = now_ns - st->first_seen_ns;
        if (active_wait_ns < ACTIVE_BLOCK_ALERT_NS)
            continue;
        if (st->repeats < (st->cycle_seen ? 1U : MIN_ALERT_REPEATS))
            continue;
        if (now_ns - st->last_emit_ns < ALERT_COOLDOWN_NS)
            continue;

        ev.pid = st->blocked_pid;
        ev.tid = st->blocked_tid;
        ev.owner_tid = st->owner_tid;
        ev.source = st->source;
        ev.cgroup_id = st->cgroup_id;
        ev.lock_addr = st->lock_addr;
        ev.wait_ns = active_wait_ns;
        snprintf(ev.comm, sizeof(ev.comm), "%s", st->comm);

        if (is_filtered_noise(&ev)) {
            filtered_counter++;
            continue;
        }

        profile = get_pid_profile(ev.pid, ev.comm, now_ns);
        rust = (profile && profile->rust_like) || is_rust_comm(ev.comm);
        score = 3;
        if (active_wait_ns >= 100ULL * 1000 * 1000)
            score += 2;
        if (active_wait_ns >= 1000ULL * 1000 * 1000)
            score += 2;
        if (st->repeats >= 4)
            score += 1;
        if (rust)
            score -= 1;
        sev = severity_label(score);

        print_quality_alert(&ev, score, sev, rust, st->repeats,
                            "active block persisted past threshold");
        st->last_emit_ns = now_ns;
        st->last_wait_ns = active_wait_ns;
        st->alerts_emitted++;
        alert_counter++;
    }
}

static void garbage_collect_state(uint64_t now_ns)
{
    size_t i;

    if (now_ns - last_gc_ns < 5000000000ULL)
        return;
    last_gc_ns = now_ns;

    i = 0;
    while (i < alert_states_count) {
        uint64_t age = now_ns - alert_states[i].last_seen_ns;
        if (alert_states[i].last_seen_ns != 0 && age > ALERT_STATE_TTL_NS) {
            alert_states[i] = alert_states[alert_states_count - 1];
            alert_states_count--;
        } else {
            i++;
        }
    }

    i = 0;
    while (i < wait_edges_count) {
        uint64_t age = now_ns - wait_edges[i].blocked_since_ns;
        if (age > WAIT_EDGE_TTL_NS) {
            wait_edges[i] = wait_edges[wait_edges_count - 1];
            wait_edges_count--;
        } else {
            i++;
        }
    }
}

static void remove_block_edge(uint32_t tid)
{
    int idx = find_edge_idx_by_from(tid);

    if (idx < 0)
        return;

    wait_edges[idx] = wait_edges[wait_edges_count - 1];
    wait_edges_count--;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct lock_event *ev = data;

    (void)ctx;

    if (data_sz < sizeof(*ev))
        return 0;

    event_counter++;
    update_metrics(ev);

    if (ev->op == OP_BLOCK) {
        add_block_edge_and_alert(ev);
    } else if (ev->op == OP_UNBLOCK) {
        evaluate_alert_quality(ev);
        remove_block_edge(ev->tid);
    } else if (ev->op == OP_ACQUIRE || ev->op == OP_RELEASE) {
        remove_block_edge(ev->tid);
    }

    scan_active_blocked_alerts(ev->timestamp_ns);
    garbage_collect_state(ev->timestamp_ns);

    if ((event_counter % 200) == 0) {
        size_t i;
        uint64_t best_wait = 0;
        uint64_t best_hold = 0;
        struct lock_stat *wait_lock = NULL;
        struct lock_stat *hold_lock = NULL;

        for (i = 0; i < lock_stats_count; i++) {
            if (lock_stats[i].max_wait_ns > best_wait) {
                best_wait = lock_stats[i].max_wait_ns;
                wait_lock = &lock_stats[i];
            }
            if (lock_stats[i].max_hold_ns > best_hold) {
                best_hold = lock_stats[i].max_hold_ns;
                hold_lock = &lock_stats[i];
            }
        }

        printf("[dashboard] events=%llu active_wait_edges=%zu\n",
               (unsigned long long)event_counter,
               wait_edges_count);
         printf("[dashboard] alerts=%llu filtered=%llu static_rules=%zu\n",
             (unsigned long long)alert_counter,
             (unsigned long long)filtered_counter,
             finding_rules_count);
        if (wait_lock) {
            printf("[dashboard] slowest wait lock=0x%llx max_wait=%.3f ms samples=%llu\n",
                   (unsigned long long)wait_lock->lock_addr,
                   (double)wait_lock->max_wait_ns / 1000000.0,
                   (unsigned long long)wait_lock->wait_count);
        }
        if (hold_lock) {
            printf("[dashboard] slowest hold lock=0x%llx max_hold=%.3f ms samples=%llu\n",
                   (unsigned long long)hold_lock->lock_addr,
                   (double)hold_lock->max_hold_ns / 1000000.0,
                   (unsigned long long)hold_lock->hold_count);
        }
        fflush(stdout);
    }

    return 0;
}

static void handle_external_preload_events(void)
{
    while (preload_sock_fd >= 0) {
        struct external_lock_event ext;
        ssize_t n;
        struct lock_event ev;

        n = recv(preload_sock_fd, &ext, sizeof(ext), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            return;
        }
        if ((size_t)n < sizeof(ext))
            continue;

        memset(&ev, 0, sizeof(ev));
        ev.pid = ext.pid;
        ev.tid = ext.tid;
        ev.owner_tid = ext.owner_tid;
        ev.op = ext.op;
        ev.source = ext.source ? ext.source : SRC_PRELOAD;
        ev.lock_addr = ext.lock_addr;
        ev.timestamp_ns = ext.timestamp_ns;
        ev.wait_ns = ext.wait_ns;
        ev.hold_ns = ext.hold_ns;
        snprintf(ev.comm, sizeof(ev.comm), "%s", ext.comm);

        if (ev.timestamp_ns == 0)
            ev.timestamp_ns = monotonic_ns();

        handle_event(NULL, &ev, sizeof(ev));
    }
}

int main(void)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *events_map;
    struct bpf_link *links[MAX_LINKS] = {0};
    struct ring_buffer *rb = NULL;
    int events_fd;
    int err;
    size_t link_count = 0;
    const char *rules_path = getenv("STATIC_FINDINGS_PATH");
    const char *profiler_patterns_path = getenv("PROFILER_PATTERNS_PATH");
    const char *rust_symbols_path = getenv("RUST_MUTEX_SYMBOLS_PATH");
    const char *lock_metadata_path = getenv("LOCK_DWARF_MAP_PATH");
    const char *allow_profiler_env = getenv("ALLOW_PROFILER_SIGNALS");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (!rules_path)
        rules_path = STATIC_FINDINGS_DEFAULT;
    if (!profiler_patterns_path)
        profiler_patterns_path = PROFILER_PATTERNS_DEFAULT;
    if (!rust_symbols_path)
        rust_symbols_path = RUST_SYMBOLS_DEFAULT;
    if (!lock_metadata_path)
        lock_metadata_path = LOCK_DWARF_MAP_DEFAULT;
    allow_profiler_signals = allow_profiler_env && strcmp(allow_profiler_env, "1") == 0;
    load_target_pids();
    load_target_cgroups();
    load_comm_filters();
    if (load_static_rules(rules_path) == 0)
        printf("[ok] loaded %zu static finding rules from %s\n", finding_rules_count, rules_path);
    else
        printf("[warn] no static findings loaded from %s (continuing)\n", rules_path);
    if (load_profiler_patterns(profiler_patterns_path) == 0)
        printf("[ok] loaded %zu profiler patterns from %s\n",
               profiler_patterns_count,
               profiler_patterns_path);
    else
        printf("[warn] no profiler pattern file at %s (using built-in defaults)\n",
               profiler_patterns_path);
    if (load_custom_symbol_targets(rust_symbols_path) == 0)
        printf("[ok] loaded %zu custom symbol targets from %s\n",
               custom_symbol_targets_count,
               rust_symbols_path);
    else
        printf("[warn] no custom symbol target file at %s (custom lock probes disabled)\n",
               rust_symbols_path);
    if (load_lock_metadata(lock_metadata_path) == 0)
        printf("[ok] loaded %zu lock metadata records from %s\n",
               lock_metadata_count,
               lock_metadata_path);
    else
        printf("[warn] no lock metadata file at %s (lock labels disabled)\n",
               lock_metadata_path);
        printf("[ok] scope: target_pids=%zu target_cgroups=%zu target_comm_filters=%zu\n",
           target_pids_count,
            target_cgroups_count,
           comm_filters_count);
        printf("[ok] profiler filtering: %s\n", allow_profiler_signals ? "disabled" : "enabled");

    obj = bpf_object__open_file("deadlock.bpf.o", NULL);
    if (!obj) {
        perror("bpf_object__open_file");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    configure_bpf_pid_scope(obj);
    configure_bpf_cgroup_scope(obj);

    printf("[ok] eBPF object loaded\n");

    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link;
        size_t attached_count;
        const char *name = bpf_program__name(prog);

        if (strcmp(name, "trace_pthread_mutex_lock_enter") == 0) {
            link = attach_pthread_symbol(prog, "pthread_mutex_lock", false);
        } else if (strcmp(name, "trace_pthread_mutex_lock_ret") == 0) {
            link = attach_pthread_symbol(prog, "pthread_mutex_lock", true);
        } else if (strcmp(name, "trace_pthread_mutex_unlock_enter") == 0) {
            link = attach_pthread_symbol(prog, "pthread_mutex_unlock", false);
        } else if (strcmp(name, "trace_rust_std_mutex_lock_enter") == 0) {
            attached_count = attach_custom_symbol_targets(prog,
                                                          "rust_std",
                                                          "lock",
                                                          false,
                                                          links,
                                                          &link_count);
            if (attached_count == 0)
                printf("[warn] no rust_std lock symbols configured for %s\n", name);
            continue;
        } else if (strcmp(name, "trace_rust_std_mutex_lock_ret") == 0) {
            attached_count = attach_custom_symbol_targets(prog,
                                                          "rust_std",
                                                          "lock",
                                                          true,
                                                          links,
                                                          &link_count);
            if (attached_count == 0)
                printf("[warn] no rust_std lock symbols configured for %s\n", name);
            continue;
        } else if (strcmp(name, "trace_rust_std_mutex_unlock_enter") == 0) {
            attached_count = attach_custom_symbol_targets(prog,
                                                          "rust_std",
                                                          "unlock",
                                                          false,
                                                          links,
                                                          &link_count);
            if (attached_count == 0)
                printf("[warn] no rust_std unlock symbols configured for %s\n", name);
            continue;
        } else if (strcmp(name, "trace_parking_lot_mutex_lock_enter") == 0) {
            attached_count = attach_custom_symbol_targets(prog,
                                                          "parking_lot",
                                                          "lock",
                                                          false,
                                                          links,
                                                          &link_count);
            if (attached_count == 0)
                printf("[warn] no parking_lot lock symbols configured for %s\n", name);
            continue;
        } else if (strcmp(name, "trace_parking_lot_mutex_lock_ret") == 0) {
            attached_count = attach_custom_symbol_targets(prog,
                                                          "parking_lot",
                                                          "lock",
                                                          true,
                                                          links,
                                                          &link_count);
            if (attached_count == 0)
                printf("[warn] no parking_lot lock symbols configured for %s\n", name);
            continue;
        } else if (strcmp(name, "trace_parking_lot_mutex_unlock_enter") == 0) {
            attached_count = attach_custom_symbol_targets(prog,
                                                          "parking_lot",
                                                          "unlock",
                                                          false,
                                                          links,
                                                          &link_count);
            if (attached_count == 0)
                printf("[warn] no parking_lot unlock symbols configured for %s\n", name);
            continue;
        } else {
            link = bpf_program__attach(prog);
        }

        if (!link) {
            err = -errno;
            fprintf(stderr, "Failed to attach %s: %d\n", name, err);
            goto cleanup;
        }

        if (!add_link(links, &link_count, link)) {
            err = -1;
            goto cleanup;
        }
        if (strcmp(name, "trace_pthread_mutex_lock_enter") != 0 &&
            strcmp(name, "trace_pthread_mutex_lock_ret") != 0 &&
            strcmp(name, "trace_pthread_mutex_unlock_enter") != 0) {
            printf("[ok] attached %s\n", name);
        }
    }

    events_map = bpf_object__find_map_by_name(obj, "events_map");
    if (!events_map) {
        fprintf(stderr, "events_map not found\n");
        err = -1;
        goto cleanup;
    }

    events_fd = bpf_map__fd(events_map);
    rb = ring_buffer__new(events_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("[ok] userspace graph engine active\n");
    preload_sock_fd = setup_preload_socket();
    if (preload_sock_fd >= 0)
        printf("[ok] preload event socket listening at %s\n", PRELOAD_SOCKET_PATH);
    else
        printf("[warn] preload event socket unavailable at %s\n", PRELOAD_SOCKET_PATH);
    printf("[*] monitoring with filters, rust-aware handling, correlation, and scoring...\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 250);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
        handle_external_preload_events();
        scan_active_blocked_alerts(monotonic_ns());
        garbage_collect_state(monotonic_ns());
    }

    err = 0;

cleanup:
    if (rb)
        ring_buffer__free(rb);

    close_preload_socket();

    while (link_count > 0) {
        link_count--;
        bpf_link__destroy(links[link_count]);
    }

    bpf_object__close(obj);
    return err ? 1 : 0;
}