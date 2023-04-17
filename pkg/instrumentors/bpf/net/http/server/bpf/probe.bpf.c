// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "arguments.h"
#include "span_context.h"
#include "go_context.h"
#include "go_types.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define PATH_MAX_LEN 100
#define METHOD_MAX_LEN 6 // Longer method: DELETE
#define MAX_CONCURRENT 50
#define MAX_HEADERS 20
#define W3C_KEY_LENGTH 11
#define W3C_VAL_LENGTH 55

struct http_request_t
{
    u64 start_time;
    u64 end_time;
    char method[METHOD_MAX_LEN];
    char path[PATH_MAX_LEN];
    struct span_context sc;
    struct span_context psc;
};

// map key: pointer to the goroutine that handles the request
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *);
    __type(value, struct http_request_t);
    __uint(max_entries, MAX_CONCURRENT);
} context_to_http_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct header_field
{
    struct go_string name;
    struct go_string value;
    bool sensitive;
};

// Injected in init
volatile const u64 method_ptr_pos;
volatile const u64 url_ptr_pos;
volatile const u64 path_ptr_pos;
volatile const u64 header_ptr_pos;

// This instrumentation attaches uprobe to the following function:
// func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request)
SEC("uprobe/ServerMux_ServeHTTP")
int uprobe_ServerMux_ServeHTTP(struct pt_regs *ctx)
{
    u64 request_pos = 4;
    struct http_request_t httpReq = {};
    httpReq.start_time = bpf_ktime_get_ns();

    // Get request struct
    void *req_ptr = get_argument(ctx, request_pos);

    // Get method from request
    void *method_ptr = 0;
    bpf_probe_read(&method_ptr, sizeof(method_ptr), (void *)(req_ptr + method_ptr_pos));
    u64 method_len = 0;
    bpf_probe_read(&method_len, sizeof(method_len), (void *)(req_ptr + (method_ptr_pos + 8)));
    u64 method_size = sizeof(httpReq.method);
    method_size = method_size < method_len ? method_size : method_len;
    bpf_probe_read(&httpReq.method, method_size, method_ptr);

    // get path from Request.URL
    void *url_ptr = 0;
    bpf_probe_read(&url_ptr, sizeof(url_ptr), (void *)(req_ptr + url_ptr_pos));
    void *path_ptr = 0;
    bpf_probe_read(&path_ptr, sizeof(path_ptr), (void *)(url_ptr + path_ptr_pos));
    u64 path_len = 0;
    bpf_probe_read(&path_len, sizeof(path_len), (void *)(url_ptr + (path_ptr_pos + 8)));
    u64 path_size = sizeof(httpReq.path);
    path_size = path_size < path_len ? path_size : path_len;
    bpf_probe_read(&httpReq.path, path_size, path_ptr);

    // get headers from request
    void *header_ptr = 0;
    bpf_probe_read(&header_ptr, sizeof(header_ptr), (void *)(req_ptr + header_ptr_pos));
    struct go_slice header_fields = {};
    bpf_probe_read(&header_fields, sizeof(header_fields), (void *)(req_ptr + header_ptr_pos));
    char key[11] = "traceparent";
    for (s32 i = 0; i < header_fields.len && i < MAX_HEADERS; i++)
    {
        struct header_field hf = {};
        bpf_probe_read(&hf, sizeof(hf), (void *)(header_fields.array + (i * sizeof(hf))));
        if (hf.name.len == W3C_KEY_LENGTH && hf.value.len == W3C_VAL_LENGTH)
        {
            char current_key[W3C_KEY_LENGTH];
            bpf_probe_read(current_key, sizeof(current_key), hf.name.str);
            if (current_key == key)
            {
                char val[W3C_VAL_LENGTH];
                bpf_probe_read(val, W3C_VAL_LENGTH, hf.value.str);
                w3c_string_to_span_context(val, &httpReq.psc);
            }
        }
    }

    // Get goroutine pointer
    void *goroutine = get_goroutine_address(ctx);

    // Setup span context
    if (&httpReq.psc != NULL)
    {
        copy_byte_arrays(httpReq.psc.TraceID, httpReq.sc.TraceID, TRACE_ID_SIZE);
        generate_random_bytes(httpReq.sc.SpanID, SPAN_ID_SIZE);
    }
    else
    {
        httpReq.sc = generate_span_context();
    }

    // Write event
    httpReq.sc = generate_span_context();
    bpf_map_update_elem(&context_to_http_events, &goroutine, &httpReq, 0);
    long res = bpf_map_update_elem(&spans_in_progress, &goroutine, &httpReq.sc, 0);
    return 0;
}

SEC("uprobe/ServerMux_ServeHTTP")
int uprobe_ServerMux_ServeHTTP_Returns(struct pt_regs *ctx)
{
    u64 request_pos = 4;
    void *req_ptr = get_argument(ctx, request_pos);
    void *goroutine = get_goroutine_address(ctx);

    void *httpReq_ptr = bpf_map_lookup_elem(&context_to_http_events, &goroutine);
    struct http_request_t httpReq = {};
    bpf_probe_read(&httpReq, sizeof(httpReq), httpReq_ptr);
    httpReq.end_time = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &httpReq, sizeof(httpReq));
    bpf_map_delete_elem(&context_to_http_events, &goroutine);
    bpf_map_delete_elem(&spans_in_progress, &goroutine);
    return 0;
}