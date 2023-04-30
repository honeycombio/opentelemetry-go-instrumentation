#include "arguments.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// This instrumentation attaches uprobe to the following function:
// func foobar(input string)
SEC("uprobe/foobar")
int uprobe_foobar(struct pt_regs *ctx) {
    u64 input_arg_position = 1;
    void *input_arg_ptr = get_argument(ctx, input_arg_position);

    char new_input[17] = "ohai";
    long result = bpf_probe_write_user(input_arg_ptr, new_input, sizeof(new_input));

    if (result != 0) {
        bpf_printk("uprobe/foobar failed with error code: %d", result);
    }
    return 0;
}