Response:
### 功能总结
该 eBPF 程序是一个基于 **HTTP 协议特征过滤**的网络流量过滤器，核心功能包括：
1. **过滤非 HTTP 流量**：丢弃非 IPv4、非 TCP 或不符合 HTTP 协议特征的数据包。
2. **会话跟踪**：通过四元组（源 IP、目的 IP、源端口、目的端口）跟踪 HTTP 会话，确保同一会话的后续数据包（如分片的 HTTP 请求）也能被捕获。
3. **HTTP 方法识别**：检查 TCP 负载前 7 字节，识别 `HTTP`、`GET`、`POST` 等关键字。
4. **用户空间协作**：将匹配的包传递到用户空间，由用户态程序进一步处理（如重组 URL）。

---

### 执行顺序（10 步）
1. **检查以太网类型**：过滤非 IPv4 包（`ethernet->type == 0x0800`）。
2. **检查 IP 协议**：过滤非 TCP 包（`ip->nextp == IP_TCP`）。
3. **验证 IP 头长度**：确保 IP 头长度合法（`ip_header_length >= sizeof(*ip)`）。
4. **解析 TCP 头**：提取四元组（`src_ip`, `dst_ip`, `src_port`, `dst_port`）作为会话 Key。
5. **计算 TCP 头长度**：确定负载起始偏移（`payload_offset`）。
6. **检查负载长度**：若负载长度小于 7 字节，丢弃（HTTP 方法至少需要 3 字节）。
7. **检查 HTTP 方法**：匹配 `GET`/`POST`/`HTTP` 等关键字。
8. **会话表查询**：未匹配 HTTP 方法时，检查会话表中是否存在该 Key。
9. **更新会话表**：若匹配 HTTP 方法，插入 Key 到 BPF_HASH 表 `sessions`。
10. **决定包去向**：返回 `-1`（保留包到用户空间）或 `0`（丢弃）。

---

### Hook 点与关键信息
| **Hook 点**       | **函数名**    | **读取的有效信息**                | **信息说明**                          |
|--------------------|---------------|-----------------------------------|---------------------------------------|
| Socket 过滤器      | `http_filter` | 以太网帧类型 (`ethernet->type`)    | 确定是否为 IPv4 包（0x0800）。         |
|                    |               | IP 协议 (`ip->nextp`)              | 确定是否为 TCP 包（6）。               |
|                    |               | 四元组 (`src_ip`, `dst_ip`, 端口)  | 标识网络会话，用于会话跟踪。           |
|                    |               | TCP 负载前 7 字节 (`p[0]-p[6]`)    | 检测 HTTP 方法（如 `GET`、`POST`）。   |

---

### 逻辑推理示例
#### 假设输入：
1. **有效 HTTP 请求包**：TCP 负载以 `GET /index.html` 开头。
   - **输出**：匹配 `GET`，插入会话表，返回 `-1`（用户空间接收）。
2. **同一会话的非 HTTP 包**：TCP 负载为后续数据（如 HTTP 响应体）。
   - **输出**：通过会话表查询命中 Key，返回 `-1`（用户空间接收）。
3. **无效包**：UDP 包或 TCP 负载长度不足 7 字节。
   - **输出**：丢弃（返回 `0`）。

---

### 常见使用错误
1. **字节序问题**：未转换网络字节序（如直接使用 `tcp->src_port`）。
   - **示例**：`key.src_port = tcp->src_port;`（应为 `bpf_ntohs(tcp->src_port)`）。
2. **负载偏移计算错误**：因 IP/TCP 头长度计算错误导致越界。
   - **示例**：`payload_offset = ETH_HLEN + ip_header_length + tcp_header_length` 中若 `ip_header_length` 错误，会导致 `load_byte` 访问非法内存。
3. **未处理分片包**：程序假设 TCP 负载连续，可能漏检分片 HTTP 请求。

---

### Syscall 调试线索
1. **程序加载**：用户态通过 `bpf_prog_load` 加载 eBPF 程序，类型为 `BPF_PROG_TYPE_SOCKET_FILTER`。
2. **Socket 绑定**：用户态调用 `setsockopt(fd, SOL_SOCKET, SO_ATTACH_BPF, ...)` 将程序附加到原始 Socket（如 `AF_PACKET`）。
3. **包到达内核**：网卡收到包后，经内核网络栈处理，触发 Socket 过滤器。
4. **eBPF 执行**：`http_filter` 函数被调用，处理 `skb` 数据，决定包去向。
5. **用户态读取**：用户态程序通过 `recvfrom` 或 `libpcap` 读取保留的包。

---

### 关键调试点
1. **检查 Hook 是否生效**：通过 `bpftool prog list` 确认程序加载。
2. **会话表状态**：通过 `bpftool map dump` 查看 `sessions` 表内容，确认 Key 正确插入。
3. **负载偏移验证**：确保 `payload_offset` 计算正确（可通过 `bpf_trace_printk` 调试输出）。
### 提示词
```
这是目录为bcc/examples/networking/http_filter/http-parse-complete.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。
```

### 源代码
```c
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IP_TCP 	6
#define ETH_HLEN 14

struct Key {
	u32 src_ip;               //source ip
	u32 dst_ip;               //destination ip
	unsigned short src_port;  //source port
	unsigned short dst_port;  //destination port
};

struct Leaf {
	int timestamp;            //timestamp in ns
};

//BPF_TABLE(map_type, key_type, leaf_type, table_name, num_entry)
//map <Key, Leaf>
//tracing sessions having same Key(dst_ip, src_ip, dst_port,src_port)
BPF_HASH(sessions, struct Key, struct Leaf, 1024);

/*eBPF program.
  Filter IP and TCP packets, having payload not empty
  and containing "HTTP", "GET", "POST"  as first bytes of payload.
  AND ALL the other packets having same (src_ip,dst_ip,src_port,dst_port)
  this means belonging to the same "session"
  this additional check avoids url truncation, if url is too long
  userspace script, if necessary, reassembles urls split in 2 or more packets.
  if the program is loaded as PROG_TYPE_SOCKET_FILTER
  and attached to a socket
  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/
int http_filter(struct __sk_buff *skb) {

	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	//filter IP packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800)) {
		goto DROP;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	//filter TCP packets (ip next protocol = 0x06)
	if (ip->nextp != IP_TCP) {
		goto DROP;
	}

	u32  tcp_header_length = 0;
	u32  ip_header_length = 0;
	u32  payload_offset = 0;
	u32  payload_length = 0;
	struct Key 	key;
	struct Leaf zero = {0};

        //calculate ip header length
        //value to multiply * 4
        //e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
        ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply

        //check ip header length against minimum
        if (ip_header_length < sizeof(*ip)) {
                goto DROP;
        }

        //shift cursor forward for dynamic ip header size
        void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

	struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

	//retrieve ip src/dest and port src/dest of current packet
	//and save it into struct Key
	key.dst_ip = ip->dst;
	key.src_ip = ip->src;
	key.dst_port = tcp->dst_port;
	key.src_port = tcp->src_port;

	//calculate tcp header length
	//value to multiply *4
	//e.g. tcp->offset = 5 ; TCP Header Length = 5 x 4 byte = 20 byte
	tcp_header_length = tcp->offset << 2; //SHL 2 -> *4 multiply

	//calculate payload offset and length
	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
	payload_length = ip->tlen - ip_header_length - tcp_header_length;

	//http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
	//minimum length of http request is always geater than 7 bytes
	//avoid invalid access memory
	//include empty payload
	if(payload_length < 7) {
		goto DROP;
	}

	//load first 7 byte of payload into p (payload_array)
	//direct access to skb not allowed
	unsigned long p[7];
	int i = 0;
	for (i = 0; i < 7; i++) {
		p[i] = load_byte(skb, payload_offset + i);
	}

	//find a match with an HTTP message
	//HTTP
	if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
		goto HTTP_MATCH;
	}
	//GET
	if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
		goto HTTP_MATCH;
	}
	//POST
	if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
		goto HTTP_MATCH;
	}
	//PUT
	if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
		goto HTTP_MATCH;
	}
	//DELETE
	if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
		goto HTTP_MATCH;
	}
	//HEAD
	if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
		goto HTTP_MATCH;
	}

	//no HTTP match
	//check if packet belong to an HTTP session
	struct Leaf * lookup_leaf = sessions.lookup(&key);
	if(lookup_leaf) {
		//send packet to userspace
		goto KEEP;
	}
	goto DROP;

	//keep the packet and send it to userspace returning -1
	HTTP_MATCH:
	//if not already present, insert into map <Key, Leaf>
	sessions.lookup_or_try_init(&key,&zero);

	//send packet to userspace returning -1
	KEEP:
	return -1;

	//drop the packet returning 0
	DROP:
	return 0;

}
```