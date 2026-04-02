
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define OP_ACQUIRE 1
#define OP_RELEASE 2
#define OP_BLOCK 3
#define OP_UNBLOCK 4

#define SRC_MUTEX 1
#define SRC_FUTEX 2
#define SRC_PTHREAD 3

#define FUTEX_CMD_MASK 0x7f
#define FUTEX_WAIT_CMD 0
#define FUTEX_WAIT_BITSET_CMD 9

struct lock_event {
    __u32 pid;
    __u32 tid;
    __u32 owner_tid;
    __u8 op;
    __u8 source;
    __u16 reserved;
    char comm[16];
    __u64 cgroup_id;
    __u64 lock_addr;
    __u64 timestamp_ns;
    __u64 wait_ns;
    __u64 hold_ns;
};

struct lock_edge {
    __u64 from_lock;
    __u64 to_lock;
};

struct acquire_state {
    __u64 lock_addr;
    __u64 start_ns;
    __u64 prev_lock;
    __u32 owner_tid;
    __u8 blocked;
    __u8 source;
    __u16 pad2;
};

struct hold_state {
    __u64 lock_addr;
    __u64 start_ns;
};

struct wait_state {
    __u64 lock_addr;
    __u64 start_ns;
    __u32 owner_tid;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} current_locks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u32);
} lock_owners_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} target_pids_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} target_cgroups_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct lock_edge);
    __type(value, __u8);
} lock_order_graph_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} thread_waits_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct acquire_state);
} acquire_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct hold_state);
} hold_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct wait_state);
} wait_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events_map SEC(".maps");

static __always_inline __u64 get_current_lock(__u32 tid)
{
    __u64 *lock_addr = bpf_map_lookup_elem(&current_locks_map, &tid);
    return lock_addr ? *lock_addr : 0;
}

static __always_inline void set_current_lock(__u32 tid, __u64 lock_addr)
{
    if (lock_addr)
        bpf_map_update_elem(&current_locks_map, &tid, &lock_addr, BPF_ANY);
    else
        bpf_map_delete_elem(&current_locks_map, &tid);
}

static __always_inline void emit_event(__u32 pid, __u32 tid, __u32 owner_tid, __u8 op,
                                       __u8 source, __u64 lock_addr, __u64 wait_ns,
                                       __u64 hold_ns)
{
    struct lock_event *event = bpf_ringbuf_reserve(&events_map, sizeof(*event), 0);

    if (!event)
        return;

    event->pid = pid;
    event->tid = tid;
    event->owner_tid = owner_tid;
    event->op = op;
    event->source = source;
    event->reserved = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->lock_addr = lock_addr;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->wait_ns = wait_ns;
    event->hold_ns = hold_ns;

    bpf_ringbuf_submit(event, 0);
}

static __always_inline bool should_trace_pid(__u32 pid)
{
    __u32 control_key = 0;
    __u8 *enabled = bpf_map_lookup_elem(&target_pids_map, &control_key);

    if (!enabled)
        return true;

    return bpf_map_lookup_elem(&target_pids_map, &pid) != NULL;
}

static __always_inline bool should_trace_cgroup(__u64 cgroup_id)
{
    __u64 control_key = 0;
    __u8 *enabled = bpf_map_lookup_elem(&target_cgroups_map, &control_key);

    if (!enabled)
        return true;

    return bpf_map_lookup_elem(&target_cgroups_map, &cgroup_id) != NULL;
}

static __always_inline bool should_trace_scope(__u32 pid)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!should_trace_pid(pid))
        return false;
    if (!should_trace_cgroup(cgroup_id))
        return false;
    return true;
}

SEC("kprobe/mutex_lock")
int BPF_KPROBE(trace_mutex_lock, struct mutex *lock)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (!should_trace_scope(pid))
        return 0;

    __u32 tid = (__u32)pid_tgid;
    __u64 lock_addr = (__u64)lock;
    __u64 now = bpf_ktime_get_ns();
    __u64 prev_lock = get_current_lock(tid);
    __u32 owner_tid = 0;
    __u32 *owner_ptr = bpf_map_lookup_elem(&lock_owners_map, &lock_addr);
    struct acquire_state state = {};

    if (owner_ptr && *owner_ptr != tid) {
        struct wait_state wait = {};

        owner_tid = *owner_ptr;
        wait.lock_addr = lock_addr;
        wait.start_ns = now;
        wait.owner_tid = owner_tid;

        bpf_map_update_elem(&wait_state_map, &tid, &wait, BPF_ANY);
        bpf_map_update_elem(&thread_waits_map, &tid, &lock_addr, BPF_ANY);
        emit_event(pid, tid, owner_tid, OP_BLOCK, SRC_MUTEX, lock_addr, 0, 0);
        state.blocked = 1;
    }

    state.lock_addr = lock_addr;
    state.start_ns = now;
    state.prev_lock = prev_lock;
    state.owner_tid = owner_tid;
    state.source = SRC_MUTEX;
    bpf_map_update_elem(&acquire_state_map, &tid, &state, BPF_ANY);

    return 0;
}

SEC("kretprobe/mutex_lock")
int BPF_KRETPROBE(trace_mutex_lock_ret, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (!should_trace_scope(pid))
        return 0;

    __u32 tid = (__u32)pid_tgid;
    __u64 now = bpf_ktime_get_ns();
    struct acquire_state *state = bpf_map_lookup_elem(&acquire_state_map, &tid);

    if (!state)
        return 0;

    if (state->source != SRC_MUTEX) {
        bpf_map_delete_elem(&acquire_state_map, &tid);
        return 0;
    }

    if (ret == 0) {
        __u8 one = 1;
        __u64 wait_ns = now - state->start_ns;
        struct lock_edge edge = {};
        struct hold_state hold = {};

        set_current_lock(tid, state->lock_addr);
        bpf_map_update_elem(&lock_owners_map, &state->lock_addr, &tid, BPF_ANY);

        hold.lock_addr = state->lock_addr;
        hold.start_ns = now;
        bpf_map_update_elem(&hold_state_map, &tid, &hold, BPF_ANY);

        if (state->prev_lock && state->prev_lock != state->lock_addr) {
            edge.from_lock = state->prev_lock;
            edge.to_lock = state->lock_addr;
            bpf_map_update_elem(&lock_order_graph_map, &edge, &one, BPF_ANY);
        }

        if (state->blocked) {
            emit_event(pid, tid, state->owner_tid, OP_UNBLOCK, SRC_MUTEX,
                       state->lock_addr, wait_ns, 0);
            bpf_map_delete_elem(&wait_state_map, &tid);
            bpf_map_delete_elem(&thread_waits_map, &tid);
        }

        emit_event(pid, tid, 0, OP_ACQUIRE, SRC_MUTEX, state->lock_addr, wait_ns, 0);
    } else {
        if (state->blocked) {
            bpf_map_delete_elem(&wait_state_map, &tid);
            bpf_map_delete_elem(&thread_waits_map, &tid);
        }
    }

    bpf_map_delete_elem(&acquire_state_map, &tid);
    return 0;
}

SEC("kprobe/mutex_unlock")
int BPF_KPROBE(trace_mutex_unlock, struct mutex *lock)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (!should_trace_scope(pid))
        return 0;

    __u32 tid = (__u32)pid_tgid;
    __u64 lock_addr = (__u64)lock;
    __u64 now = bpf_ktime_get_ns();
    __u64 hold_ns = 0;
    struct hold_state *hold = bpf_map_lookup_elem(&hold_state_map, &tid);

    if (hold && hold->lock_addr == lock_addr)
        hold_ns = now - hold->start_ns;

    set_current_lock(tid, 0);
    bpf_map_delete_elem(&lock_owners_map, &lock_addr);
    bpf_map_delete_elem(&hold_state_map, &tid);

    emit_event(pid, tid, 0, OP_RELEASE, SRC_MUTEX, lock_addr, 0, hold_ns);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(trace_pthread_mutex_lock_enter, void *mutex)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (!should_trace_scope(pid))
        return 0;

    __u32 tid = (__u32)pid_tgid;
    __u64 lock_addr = (__u64)mutex;
    __u64 now = bpf_ktime_get_ns();
    __u64 prev_lock = get_current_lock(tid);
    __u32 owner_tid = 0;
    __u32 *owner_ptr = bpf_map_lookup_elem(&lock_owners_map, &lock_addr);
    struct acquire_state state = {};

    if (owner_ptr && *owner_ptr != tid) {
        struct wait_state wait = {};

        owner_tid = *owner_ptr;
        wait.lock_addr = lock_addr;
        wait.start_ns = now;
        wait.owner_tid = owner_tid;

        bpf_map_update_elem(&wait_state_map, &tid, &wait, BPF_ANY);
        bpf_map_update_elem(&thread_waits_map, &tid, &lock_addr, BPF_ANY);
        emit_event(pid, tid, owner_tid, OP_BLOCK, SRC_PTHREAD, lock_addr, 0, 0);
        state.blocked = 1;
    }

    state.lock_addr = lock_addr;
    state.start_ns = now;
    state.prev_lock = prev_lock;
    state.owner_tid = owner_tid;
    state.source = SRC_PTHREAD;
    bpf_map_update_elem(&acquire_state_map, &tid, &state, BPF_ANY);

    return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(trace_pthread_mutex_lock_ret, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (!should_trace_scope(pid))
        return 0;

    __u32 tid = (__u32)pid_tgid;
    __u64 now = bpf_ktime_get_ns();
    struct acquire_state *state = bpf_map_lookup_elem(&acquire_state_map, &tid);

    if (!state)
        return 0;

    if (state->source != SRC_PTHREAD) {
        bpf_map_delete_elem(&acquire_state_map, &tid);
        return 0;
    }

    if (ret == 0) {
        __u8 one = 1;
        __u64 wait_ns = now - state->start_ns;
        struct lock_edge edge = {};
        struct hold_state hold = {};

        set_current_lock(tid, state->lock_addr);
        bpf_map_update_elem(&lock_owners_map, &state->lock_addr, &tid, BPF_ANY);

        hold.lock_addr = state->lock_addr;
        hold.start_ns = now;
        bpf_map_update_elem(&hold_state_map, &tid, &hold, BPF_ANY);

        if (state->prev_lock && state->prev_lock != state->lock_addr) {
            edge.from_lock = state->prev_lock;
            edge.to_lock = state->lock_addr;
            bpf_map_update_elem(&lock_order_graph_map, &edge, &one, BPF_ANY);
        }

        if (state->blocked) {
            emit_event(pid, tid, state->owner_tid, OP_UNBLOCK, SRC_PTHREAD,
                       state->lock_addr, wait_ns, 0);
            bpf_map_delete_elem(&wait_state_map, &tid);
            bpf_map_delete_elem(&thread_waits_map, &tid);
        }

        emit_event(pid, tid, 0, OP_ACQUIRE, SRC_PTHREAD, state->lock_addr, wait_ns, 0);
    } else {
        if (state->blocked) {
            bpf_map_delete_elem(&wait_state_map, &tid);
            bpf_map_delete_elem(&thread_waits_map, &tid);
        }
    }

    bpf_map_delete_elem(&acquire_state_map, &tid);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(trace_pthread_mutex_unlock_enter, void *mutex)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (!should_trace_scope(pid))
        return 0;

    __u32 tid = (__u32)pid_tgid;
    __u64 lock_addr = (__u64)mutex;
    __u64 now = bpf_ktime_get_ns();
    __u64 hold_ns = 0;
    struct hold_state *hold = bpf_map_lookup_elem(&hold_state_map, &tid);

    if (hold && hold->lock_addr == lock_addr)
        hold_ns = now - hold->start_ns;

    set_current_lock(tid, 0);
    bpf_map_delete_elem(&lock_owners_map, &lock_addr);
    bpf_map_delete_elem(&hold_state_map, &tid);

    emit_event(pid, tid, 0, OP_RELEASE, SRC_PTHREAD, lock_addr, 0, hold_ns);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_futex")
int trace_futex_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (!should_trace_scope(pid))
        return 0;

    __u32 tid = (__u32)pid_tgid;
    __u32 op = (__u32)ctx->args[1] & FUTEX_CMD_MASK;

    if (op == FUTEX_WAIT_CMD || op == FUTEX_WAIT_BITSET_CMD) {
        __u64 lock_addr = (__u64)ctx->args[0];
        __u64 now = bpf_ktime_get_ns();
        __u32 owner_tid = 0;
        __u32 *owner_ptr = bpf_map_lookup_elem(&lock_owners_map, &lock_addr);
        struct wait_state wait = {};

        if (owner_ptr)
            owner_tid = *owner_ptr;

        wait.lock_addr = lock_addr;
        wait.start_ns = now;
        wait.owner_tid = owner_tid;

        bpf_map_update_elem(&wait_state_map, &tid, &wait, BPF_ANY);
        bpf_map_update_elem(&thread_waits_map, &tid, &lock_addr, BPF_ANY);
        emit_event(pid, tid, owner_tid, OP_BLOCK, SRC_FUTEX, lock_addr, 0, 0);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int trace_futex_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (!should_trace_scope(pid))
        return 0;

    __u32 tid = (__u32)pid_tgid;
    __u64 now = bpf_ktime_get_ns();
    struct wait_state *wait = bpf_map_lookup_elem(&wait_state_map, &tid);

    if (wait) {
        __u64 wait_ns = now - wait->start_ns;
        emit_event(pid, tid, wait->owner_tid, OP_UNBLOCK, SRC_FUTEX,
                   wait->lock_addr, wait_ns, 0);
        bpf_map_delete_elem(&wait_state_map, &tid);
        bpf_map_delete_elem(&thread_waits_map, &tid);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
