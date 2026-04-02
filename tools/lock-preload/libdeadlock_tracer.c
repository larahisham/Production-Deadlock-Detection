#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define OP_ACQUIRE 1
#define OP_RELEASE 2
#define OP_BLOCK 3
#define OP_UNBLOCK 4
#define SRC_PRELOAD 6

#define OWNER_TABLE_SIZE 8192
#define PRELOAD_SOCKET_PATH "/tmp/deadlock-detector.sock"

typedef int (*pthread_mutex_lock_fn)(pthread_mutex_t *mutex);
typedef int (*pthread_mutex_unlock_fn)(pthread_mutex_t *mutex);

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

struct owner_entry {
    uint64_t lock_addr;
    uint32_t owner_tid;
    uint64_t acquired_ns;
    uint8_t in_use;
};

static pthread_mutex_lock_fn real_pthread_mutex_lock;
static pthread_mutex_unlock_fn real_pthread_mutex_unlock;
static pthread_mutex_t state_mu = PTHREAD_MUTEX_INITIALIZER;
static struct owner_entry owner_table[OWNER_TABLE_SIZE];
static int sock_fd = -1;

static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint32_t get_tid(void)
{
    return (uint32_t)syscall(SYS_gettid);
}

static void fill_comm(char *dst, size_t sz)
{
    if (sz == 0)
        return;
    memset(dst, 0, sz);
    if (prctl(PR_GET_NAME, dst, 0, 0, 0) != 0)
        snprintf(dst, sz, "%s", "unknown");
}

static size_t owner_idx(uint64_t lock_addr)
{
    return (size_t)(lock_addr % OWNER_TABLE_SIZE);
}

static struct owner_entry *find_owner_slot(uint64_t lock_addr)
{
    size_t i;
    size_t start = owner_idx(lock_addr);

    for (i = 0; i < OWNER_TABLE_SIZE; i++) {
        size_t idx = (start + i) % OWNER_TABLE_SIZE;
        if (!owner_table[idx].in_use || owner_table[idx].lock_addr == lock_addr)
            return &owner_table[idx];
    }

    return NULL;
}

static uint32_t get_owner_tid(uint64_t lock_addr)
{
    struct owner_entry *slot;
    uint32_t owner = 0;

    pthread_mutex_lock(&state_mu);
    slot = find_owner_slot(lock_addr);
    if (slot && slot->in_use && slot->lock_addr == lock_addr)
        owner = slot->owner_tid;
    pthread_mutex_unlock(&state_mu);

    return owner;
}

static uint64_t clear_owner(uint64_t lock_addr, uint32_t tid)
{
    struct owner_entry *slot;
    uint64_t hold_ns = 0;

    pthread_mutex_lock(&state_mu);
    slot = find_owner_slot(lock_addr);
    if (slot && slot->in_use && slot->lock_addr == lock_addr && slot->owner_tid == tid) {
        uint64_t now = monotonic_ns();
        hold_ns = now > slot->acquired_ns ? now - slot->acquired_ns : 0;
        memset(slot, 0, sizeof(*slot));
    }
    pthread_mutex_unlock(&state_mu);

    return hold_ns;
}

static void set_owner(uint64_t lock_addr, uint32_t tid)
{
    struct owner_entry *slot;

    pthread_mutex_lock(&state_mu);
    slot = find_owner_slot(lock_addr);
    if (slot) {
        slot->lock_addr = lock_addr;
        slot->owner_tid = tid;
        slot->acquired_ns = monotonic_ns();
        slot->in_use = 1;
    }
    pthread_mutex_unlock(&state_mu);
}

static void emit_event(uint8_t op, uint32_t owner_tid, uint64_t lock_addr, uint64_t wait_ns, uint64_t hold_ns)
{
    struct external_lock_event ev;

    if (sock_fd < 0)
        return;

    memset(&ev, 0, sizeof(ev));
    ev.pid = (uint32_t)getpid();
    ev.tid = get_tid();
    ev.owner_tid = owner_tid;
    ev.op = op;
    ev.source = SRC_PRELOAD;
    ev.lock_addr = lock_addr;
    ev.timestamp_ns = monotonic_ns();
    ev.wait_ns = wait_ns;
    ev.hold_ns = hold_ns;
    fill_comm(ev.comm, sizeof(ev.comm));

    (void)send(sock_fd, &ev, sizeof(ev), MSG_DONTWAIT);
}

static void init_tracer(void)
{
    struct sockaddr_un addr;

    real_pthread_mutex_lock = (pthread_mutex_lock_fn)dlsym(RTLD_NEXT, "pthread_mutex_lock");
    real_pthread_mutex_unlock = (pthread_mutex_unlock_fn)dlsym(RTLD_NEXT, "pthread_mutex_unlock");

    sock_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock_fd < 0)
        return;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", PRELOAD_SOCKET_PATH);

    if (connect(sock_fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock_fd);
        sock_fd = -1;
    }
}

static void shutdown_tracer(void)
{
    if (sock_fd >= 0) {
        close(sock_fd);
        sock_fd = -1;
    }
}

__attribute__((constructor)) static void constructor_tracer(void)
{
    init_tracer();
}

__attribute__((destructor)) static void destructor_tracer(void)
{
    shutdown_tracer();
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    uint64_t lock_addr;
    uint32_t owner_tid;
    uint64_t start_ns;
    int rc;

    if (!real_pthread_mutex_lock)
        init_tracer();
    if (!real_pthread_mutex_lock)
        return EINVAL;

    lock_addr = (uint64_t)(uintptr_t)mutex;
    owner_tid = get_owner_tid(lock_addr);
    start_ns = monotonic_ns();

    if (owner_tid != 0 && owner_tid != get_tid())
        emit_event(OP_BLOCK, owner_tid, lock_addr, 0, 0);

    rc = real_pthread_mutex_lock(mutex);
    if (rc == 0) {
        uint64_t wait_ns = monotonic_ns();
        wait_ns = wait_ns > start_ns ? wait_ns - start_ns : 0;

        if (owner_tid != 0 && owner_tid != get_tid())
            emit_event(OP_UNBLOCK, owner_tid, lock_addr, wait_ns, 0);

        set_owner(lock_addr, get_tid());
        emit_event(OP_ACQUIRE, 0, lock_addr, wait_ns, 0);
    }

    return rc;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    uint64_t lock_addr;
    uint64_t hold_ns;
    int rc;

    if (!real_pthread_mutex_unlock)
        init_tracer();
    if (!real_pthread_mutex_unlock)
        return EINVAL;

    lock_addr = (uint64_t)(uintptr_t)mutex;
    hold_ns = clear_owner(lock_addr, get_tid());

    rc = real_pthread_mutex_unlock(mutex);
    if (rc == 0)
        emit_event(OP_RELEASE, 0, lock_addr, 0, hold_ns);

    return rc;
}
