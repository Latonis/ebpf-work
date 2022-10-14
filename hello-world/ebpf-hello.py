#!/usr/bin/python3
from collections import defaultdict
from concurrent.futures import process
from bcc import BPF
from bcc.utils import printb
import json

program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128
#define MAXARG   20

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    u32 uid;
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int hello_world (struct pt_regs *ctx, const char __user *filename, const char __user *const __user *__argv, const char __user *const __user *__envp) {
  
    struct data_t data = {};
    struct task_struct *task;
    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();

    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             return 0;
    }

    return 0;  
}
"""

class EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1

processes = {}
processDetails = {}
args = defaultdict(list)

def parse_event(cpu, data, size):
    event = b["events"].event(data)
    if (event.type == EventType.EVENT_ARG):
        args[event.pid].append(event.argv)
    else:
        ppid = event.ppid
        pid = event.pid
        binary = str(event.comm.decode('utf-8'))
        if (ppid not in processes):
            processes[ppid] = [pid]
        else:
            processes[ppid].append(pid)
        if (pid not in processes):
            processes[pid] = []
        if (pid not in processDetails):
            processDetails[pid] = {"Parent PID": ppid, "binary": binary}
        
        print(f"Parent PID: {event.ppid}")
        print(f"PID: {event.pid}")
        print(binary)
        print(f"ARGV: {args[pid]}")

        print()


b = BPF(text=program)
eventt = b.get_syscall_fnname("execve")
b.attach_kprobe(event=eventt, fn_name="hello_world")

b["events"].open_perf_buffer(parse_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print(processes)
        print(json.dumps(processDetails, indent=2))
        exit()
