#!/usr/bin/python3
from collections import defaultdict
from concurrent.futures import process
from bcc import BPF
from bcc.utils import printb
import json

## This relies heavily on the example code provided in execsnoop.py from bcc (https://github.com/iovisor/bcc/blob/master/tools/execsnoop.py)
program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#define ARGSIZE  128
enum event_type {
    EVENT_ARG,
    EVENT_RET,
};
struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};
BPF_PERF_OUTPUT(events);
static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}
static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}
int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;
    __submit_arg(ctx, (void *)filename, &data);
    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < 20; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}
int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct task_struct *task;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

class EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1

processes = {}
processDetails = {}
argv = defaultdict(list)

def parse_event(cpu, data, size):
    event = b["events"].event(data)
    if (event.type == EventType.EVENT_ARG):
        argv[event.pid].append(event.argv.decode('utf-8'))
    elif (event.type == EventType.EVENT_RET):
        ppid = event.ppid
        pid = event.pid
        binary = str(event.comm.decode('utf-8'))
        path = ''
        arguments = " ".join(argv[pid][1:])
        if (argv[pid]):
            path = argv[pid][0]
        if (pid not in processDetails):
            processDetails[pid] = {"Parent PID": ppid, "PID": pid, "path": path,"binary": binary, "arguments": arguments, "children": []}
        if (ppid not in processes):
            processes[ppid] = [pid]
        else:
            processes[ppid].append(pid)
        if (ppid in processDetails):
            processDetails[ppid]["children"].append(pid)
        if (pid not in processes):
            processes[pid] = []
    

        # TODO: add children to pid if in dictionary       
        # print(f"Parent PID: {event.ppid}")
        # print(f"PID: {event.pid}")
        # print(binary)
        # print(f"ARGV: {argv[pid]}")

        # print()



b = BPF(text=program, cflags=["-Wno-macro-redefined"])
eventt = b.get_syscall_fnname("execve")
b.attach_kprobe(event=eventt, fn_name="syscall__execve")
b.attach_kretprobe(event=eventt, fn_name="do_ret_sys_execve")

b["events"].open_perf_buffer(parse_event)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print(processes)
        print(json.dumps(processDetails, indent=2))
        exit()
