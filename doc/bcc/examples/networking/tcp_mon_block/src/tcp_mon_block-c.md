Response:
### 功能概述
该程序通过 eBPF 实现了一个进程级 TCP 防火墙，主要功能包括：
1. **监控指定 PID 的 TCP 连接**：通过跟踪 `connect` 系统调用捕获连接请求。
2. **动态阻断非法连接**：若目标地址不在 `allow_list` 中，则拦截该连接的所有数据包。
3. **连接状态跟踪**：自动清理已关闭连接的监控状态。
4. **事件上报**：输出阻断事件和详细状态变更日志。

---

### 执行顺序（分 10 步）
1. **用户态初始化**：加载 eBPF 程序，配置 `pid_list`（监控的 PID）和 `allow_list`（允许的 IP）。
2. **进程发起连接**：被监控的进程调用 `connect()` 系统调用。
3. **触发 `trace_connect_entry`**：在 `connect` 执行时捕获连接四元组（源 IP/端口、目标 IP/端口）。
4. **策略检查**：检查目标 IP 是否在 `allow_list`，若不在则记录到 `monitored_connections` 哈希表。
5. **数据包出口处理**：被阻断连接的数据包经过 TC（Traffic Control）出口时触发 `handle_egress`。
6. **包过滤决策**：检查数据包是否在 `monitored_connections` 中，存在则丢弃（`TC_ACT_SHOT`）。
7. **连接状态变更**：当 TCP 连接进入 `CLOSE` 或 `CLOSE_WAIT` 状态时触发 `inet_sock_set_state` 跟踪点。
8. **清理监控状态**：从 `monitored_connections` 删除已关闭连接的记录。
9. **事件上报**：通过 `blocked_events` 和 `verbose_events` 向用户态上报阻断和状态事件。
10. **用户态处理事件**：用户态程序读取 `perf_event` 输出，记录日志或告警。

---

### Hook 点与关键信息
| Hook 点                     | 函数/跟踪点               | 读取的有效信息                          | 信息说明                     |
|-----------------------------|--------------------------|----------------------------------------|----------------------------|
| **TC 出口流量处理**          | `handle_egress`          | 数据包的源/目标 IP、端口、TCP 标志       | 用于判断是否阻断数据包       |
| **TCP 连接状态变更**         | `sock:inet_sock_set_state` | 连接四元组、新状态（如 `TCP_CLOSE`）     | 清理已关闭连接的监控状态     |
| **`connect` 系统调用入口**   | `trace_connect_entry`     | 进程 PID、进程名、连接四元组             | 记录连接请求并决策是否阻断   |

---

### 逻辑推理示例
**假设输入**：  
- 监控 PID `1234`，允许列表包含 `1.1.1.1`。
- PID `1234` 的进程发起 `connect()` 到 `2.2.2.2:80`。

**输出**：  
1. `trace_connect_entry` 检测到目标 IP `2.2.2.2` 不在 `allow_list`，记录到 `monitored_connections`。
2. 后续该连接的 TCP 数据包经过 TC 出口时被 `handle_egress` 拦截（返回 `TC_ACT_SHOT`）。
3. `blocked_events` 上报阻断事件，包含 PID、进程名和连接四元组。

---

### 常见使用错误
1. **未正确配置 PID 列表**：  
   **示例**：用户忘记将目标进程 PID 加入 `pid_list`，导致连接未被监控。  
   **现象**：非法连接未被阻断。

2. **允许列表配置错误**：  
   **示例**：允许列表使用主机字节序而非网络字节序（如 `127.0.0.1` 写为 `0x7f000001`）。  
   **现象**：合法连接被误阻断。

3. **TC 未正确挂载**：  
   **示例**：未将 eBPF 程序附加到网络设备出口。  
   **现象**：`handle_egress` 未被触发，数据包未被过滤。

---

### Syscall 调试线索
1. **`connect()` 系统调用路径**：  
   - 用户态调用 `connect()` → 内核态 `sys_connect()` → `inet_stream_connect()` → `tcp_v4_connect()`。
   - `trace_connect_entry` 可能挂载在 `tcp_v4_connect` 或 `inet_stream_connect` 的 kprobe 上。

2. **关键调试点**：  
   - 检查 `trace_connect_entry` 是否捕获到 PID 和连接四元组。
   - 检查 `monitored_connections` 是否包含目标连接。
   - 确认 `handle_egress` 在 TC 出口被触发并返回 `TC_ACT_SHOT`。

---

### 总结
该程序通过多层级 Hook 实现动态 TCP 连接监控与阻断，需确保 PID 列表、允许列表和 TC 挂载正确。调试时可借助 `blocked_events` 和 `verbose_events` 定位问题。
### 提示词
```
这是目录为bcc/examples/networking/tcp_mon_block/src/tcp_mon_block.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。
```

### 源代码
```c
/*author: https://github.com/agentzex
Licensed under the Apache License, Version 2.0 (the "License")

tcp_mon_block.c - uses netlink TC, kernel tracepoints and kprobes to monitor outgoing connections from given PIDs
and block connections to all addresses initiated from them (acting like an in-process firewall), unless they are listed in allow_list
*/

#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <linux/tcp.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>


typedef struct
{
    u32 src_ip;
    u16 src_port;
    u32 dst_ip;
    u16 dst_port;
    u32 pid;
    u8 tcp_flags;
    char comm[TASK_COMM_LEN];
} full_packet;


typedef struct
{
    u8 state;
    u32 src_ip;
    u16 src_port;
    u32 dst_ip;
    u16 dst_port;
    u32 pid;
    char comm[TASK_COMM_LEN];
} verbose_event;


typedef struct
{
    u32 src_ip;
    u16 src_port;
    u32 dst_ip;
    u16 dst_port;
} key_hash;


BPF_HASH(monitored_connections, key_hash, full_packet);
BPF_HASH(allow_list, u32, u32);
BPF_HASH(pid_list, u32, u32);
BPF_PERF_OUTPUT(blocked_events);
BPF_PERF_OUTPUT(verbose_events);


#ifndef tcp_flag_byte
#define tcp_flag_byte(th) (((u_int8_t *)th)[13])
#endif


static bool VERBOSE_OUTPUT = false;


static __always_inline int tcp_header_bound_check(struct tcphdr* tcp, void* data_end)
{
    if ((void *)tcp + sizeof(*tcp) > data_end)
    {
        return -1;
    }

    return 0;
}


static void make_verbose_event(verbose_event *v, u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u32 pid, u8 state)
{
    v->src_ip = src_ip;
    v->src_port = src_port;
    v->dst_ip = dst_ip;
    v->dst_port = dst_port;
    v->pid = pid;
    v->state = state;
    bpf_get_current_comm(&v->comm, sizeof(v->comm));
}


int handle_egress(struct __sk_buff *ctx)
{
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    struct tcphdr *tcp;
    key_hash key = {};

    /* length check */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
    {
        return TC_ACT_OK;
    }

    if (eth->h_proto != htons(ETH_P_IP))
    {
        return TC_ACT_OK;
    }

    if (ip->protocol != IPPROTO_TCP)
    {
        return TC_ACT_OK;
    }

    tcp = (void *)ip + sizeof(*ip);
    if (tcp_header_bound_check(tcp, data_end))
    {
        return TC_ACT_OK;
    }

    u8 tcpflags = ((u_int8_t *)tcp)[13];
    u16 src_port = bpf_ntohs(tcp->source);
    u16 dst_port = bpf_ntohs(tcp->dest);

    key.src_ip = ip->saddr;
    key.src_port = src_port;
    key.dst_ip = ip->daddr;
    key.dst_port = dst_port;

    full_packet *packet_value;
    packet_value = monitored_connections.lookup(&key);
    if (packet_value != 0)
    {
        packet_value->tcp_flags = tcpflags;
        blocked_events.perf_submit(ctx, packet_value, sizeof(full_packet));
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}


// Removing the entry from monitored_connections when the socket closes after failed connection
TRACEPOINT_PROBE(sock, inet_sock_set_state)
{
    if (args->protocol != IPPROTO_TCP)
    {
        return 0;
    }

    if (args->newstate != TCP_CLOSE && args->newstate != TCP_CLOSE_WAIT)
    {
        return 0;
    }

    if (args->family == AF_INET)
    {
        key_hash key = {};
        struct sock *sk = (struct sock *)args->skaddr;

        key.src_port = args->sport;
        key.dst_port = args->dport;
        __builtin_memcpy(&key.src_ip, args->saddr, sizeof(key.src_ip));
        __builtin_memcpy(&key.dst_ip, args->daddr, sizeof(key.dst_ip));

        full_packet *packet_value;
        packet_value = monitored_connections.lookup(&key);
        if (packet_value != 0)
        {
            monitored_connections.delete(&key);
            if (VERBOSE_OUTPUT)
            {
                verbose_event v = {};
                make_verbose_event(&v, packet_value->src_ip, packet_value->dst_ip, packet_value->src_port, packet_value->dst_port, packet_value->pid, 3);
                verbose_events.perf_submit(args, &v, sizeof(v));
            }

        }
    }

    return 0;
}




int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    key_hash key = {};
    full_packet packet_value = {};
    u8 verbose_state = 0;

    u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET)
    {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u16 dst_port = sk->__sk_common.skc_dport;
    dst_port = ntohs(dst_port);
    u16 src_port = sk->__sk_common.skc_num;
    u32 src_ip = sk->__sk_common.skc_rcv_saddr;
    u32 dst_ip = sk->__sk_common.skc_daddr;

    u32 *monitored_pid = pid_list.lookup(&pid);
    if (!monitored_pid)
    {
        return 0;
    }

    u32 *allowed_ip = allow_list.lookup(&dst_ip);
    if (!allowed_ip)
    {
        key.src_ip = src_ip;
        key.src_port = src_port;
        key.dst_ip = dst_ip;
        key.dst_port = dst_port;

        packet_value.src_ip = src_ip;
        packet_value.src_port = src_port;
        packet_value.dst_ip = dst_ip;
        packet_value.dst_port = dst_port;
        packet_value.pid = pid;
        bpf_get_current_comm(&packet_value.comm, sizeof(packet_value.comm));
        verbose_state = 1;
        monitored_connections.update(&key, &packet_value);
    }
    else
    {
        verbose_state = 2;
    }

    if (VERBOSE_OUTPUT)
    {
        verbose_event v = {};
        make_verbose_event(&v, src_ip, dst_ip, src_port, dst_port, pid, verbose_state);
        verbose_events.perf_submit(ctx, &v, sizeof(v));
    }

    return 0;
}
```