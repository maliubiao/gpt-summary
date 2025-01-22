Response:
### 功能与执行顺序
该程序是一个基于 **eBPF 的 Socket Filter**，用于过滤网络流量中的 HTTP 请求（如 GET、POST 等），仅允许匹配的 HTTP 数据包传递到用户空间，其他数据包直接丢弃。

#### 执行顺序（10 步）：
1. **解析以太网帧**：验证是否为 IPv4 数据包（以太网类型 `0x0800`）。
2. **解析 IP 头**：验证协议是否为 TCP（`ip->nextp == 6`）。
3. **计算 IP 头部长度**：`ip->hlen << 2`，确保长度合法（不小于标准 IP 头大小）。
4. **跳过动态 IP 头部**：移动游标到 IP 头末尾。
5. **解析 TCP 头**：提取 TCP 头部信息。
6. **计算 TCP 头部长度**：`tcp->offset << 2`。
7. **计算负载偏移与长度**：基于以太网、IP、TCP 头部长度。
8. **验证负载长度**：若负载长度小于 7 字节，直接丢弃。
9. **读取负载前 7 字节**：检查是否包含 HTTP 方法（如 `GET`、`POST`）。
10. **决策保留或丢弃**：匹配 HTTP 方法则保留（返回 `-1`），否则丢弃（返回 `0`）。

---

### eBPF Hook 点与关键信息
- **Hook 点**: `BPF_PROG_TYPE_SOCKET_FILTER`  
  - 挂载方式：通过 `setsockopt(fd, SOL_SOCKET, SO_ATTACH_BPF, ...)` 附加到原始套接字（如 `AF_PACKET`）。
- **函数名**: `http_filter(struct __sk_buff *skb)`
- **读取的关键信息**：
  1. **以太网帧类型**：过滤非 IPv4 流量（`ethernet->type`）。
  2. **IP 协议类型**：过滤非 TCP 流量（`ip->nextp`）。
  3. **IP/TCP 头部长度**：用于计算负载偏移（`ip_header_length`, `tcp_header_length`）。
  4. **负载内容**：前 7 字节用于匹配 HTTP 方法（如 `GET`）。

---

### 假设输入与输出
- **输入 1**：TCP 数据包，负载以 `GET / HTTP/1.1` 开头。
  - **输出**：保留（返回 `-1`），用户态程序可读取完整数据包。
- **输入 2**：TCP 数据包，负载为 `123456`（长度 6 字节）。
  - **输出**：丢弃（返回 `0`），因长度不足 7 字节。
- **输入 3**：UDP 数据包，负载为 `GET / HTTP/1.1`。
  - **输出**：丢弃（返回 `0`），因协议非 TCP。

---

### 常见使用错误与示例
1. **负载偏移计算错误**：
   - **错误示例**：未正确处理 IP/TCP 头部长度，导致 `payload_offset` 错误。
   - **后果**：读取错误的负载内容，可能误过滤或误保留数据包。
2. **未验证头部长度合法性**：
   - **错误示例**：若 `ip->hlen` 为 0，`ip_header_length` 将为 0，导致后续计算错误。
   - **后果**：程序崩溃或读取非法内存（但代码中已通过 `if (ip_header_length < sizeof(*ip))` 规避）。
3. **负载长度不足时越界访问**：
   - **错误示例**：未检查 `payload_length` 直接读取 7 字节。
   - **后果**：访问非法内存（代码中通过 `if (payload_length < 7)` 规避）。

---

### Syscall 路径与调试线索
1. **用户态程序**：创建原始套接字（如 `AF_PACKET`）并附加 eBPF 程序：
   ```c
   int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   setsockopt(fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
   ```
2. **内核路径**：
   - 数据包到达网卡后，经内核网络栈处理。
   - 到达 Socket Filter 钩子点时，调用 `http_filter` 函数。
   - 根据返回值决定是否将数据包传递到用户态（`-1` 保留，`0` 丢弃）。
3. **调试线索**：
   - **检查 Hook 是否生效**：确认 `setsockopt` 调用成功。
   - **验证协议过滤**：发送非 TCP 数据包，确认被丢弃。
   - **检查负载匹配逻辑**：构造不同 HTTP 方法的数据包，确认匹配结果。
Prompt: 
```
这是目录为bcc/examples/networking/http_filter/http-parse-simple.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IP_TCP 	6
#define ETH_HLEN 14

/*eBPF program.
  Filter IP and TCP packets, having payload not empty
  and containing "HTTP", "GET", "POST" ... as first bytes of payload
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
		goto KEEP;
	}
	//GET
	if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
		goto KEEP;
	}
	//POST
	if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
		goto KEEP;
	}
	//PUT
	if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
		goto KEEP;
	}
	//DELETE
	if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
		goto KEEP;
	}
	//HEAD
	if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
		goto KEEP;
	}

	//no HTTP match
	goto DROP;

	//keep the packet and send it to userspace returning -1
	KEEP:
	return -1;

	//drop the packet returning 0
	DROP:
	return 0;

}

"""

```