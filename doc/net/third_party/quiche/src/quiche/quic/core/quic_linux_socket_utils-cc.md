Response:
Let's break down the thought process for analyzing this C++ file and answering the prompt.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `quic_linux_socket_utils.cc`, its relation to JavaScript (if any), common usage errors, and how a user might end up interacting with this code. This requires analyzing the code's purpose and its interaction with the operating system.

**2. Initial Code Scan and Keyword Identification:**

First, a quick scan of the code reveals some important keywords and concepts:

* **`linux`:** This immediately tells us the code is platform-specific and deals with Linux socket APIs.
* **`socket`:** This is central. The file deals with low-level network operations using sockets.
* **`sendmsg`, `sendmmsg`, `getsockopt`, `setsockopt`:** These are standard Linux system calls for socket operations.
* **`msghdr`, `mmsghdr`, `cmsghdr`:** These are structures related to sending and receiving messages on sockets, including ancillary data (control messages).
* **`IPPROTO_IP`, `IP_TTL`, `IP_PKTINFO`, `IPPROTO_IPV6`, `IPV6_PKTINFO`, `UDP_SEGMENT`, `SO_TXTIME`:** These are constants and options related to IP and UDP protocols, further confirming the network focus.
* **`QuicIpAddress`, `QuicSocketAddress`:**  These are Quiche's internal representations of IP addresses and socket addresses, indicating an abstraction layer.
* **`BufferedWrite`:**  Suggests handling of outgoing data in a buffered manner.
* **`WriteResult`:**  A custom structure for reporting the result of write operations.
* **`errno`:** Standard error handling, confirming interaction with system calls.
* **`QUICHE_DCHECK`, `QUIC_LOG_EVERY_N_SEC`, `QUIC_BUG`:** Quiche's logging and assertion mechanisms, helpful for understanding intent and potential issues.

**3. Deconstructing the Functionality (Grouping Related Code):**

Based on the keywords and structure, we can group the functionality into logical blocks:

* **`QuicMsgHdr` and `QuicMMsgHdr`:** These classes are clearly wrappers around the Linux `msghdr` and `mmsghdr` structures. They provide Quiche-specific methods for setting peer addresses, IP information in control messages, and managing the control buffer. The "M" in `QuicMMsgHdr` likely stands for "multiple," indicating it handles sending multiple packets at once.

* **Socket Option Management (`GetUDPSegmentSize`, `EnableReleaseTime`):**  These functions directly manipulate socket options using `getsockopt` and `setsockopt`. `UDP_SEGMENT` relates to UDP fragmentation offload (GSO/USO), and `SO_TXTIME` deals with scheduling packet transmission.

* **Control Message Handling (`GetTtlFromMsghdr`, `SetIpInfoInCmsgData`, `SetIpInfoInCmsg`):** These functions are about working with ancillary data attached to socket messages (control messages). They specifically handle retrieving the TTL (Time-to-Live) and setting IP-related information.

* **Packet Sending (`WritePacket`, `WriteMultiplePackets`):**  These functions encapsulate the `sendmsg` and `sendmmsg` system calls, using the `QuicMsgHdr` and `QuicMMsgHdr` structures. They also handle error conditions like `EINTR`, `EAGAIN`, and `EWOULDBLOCK`.

**4. Identifying the Core Purpose:**

Putting the pieces together, the file's primary purpose is to provide a platform-specific (Linux) abstraction layer over raw socket system calls, specifically for sending UDP packets, including the ability to set advanced options and attach ancillary data. This is crucial for implementing QUIC's reliable and efficient transport protocol.

**5. Addressing the JavaScript Relationship:**

At this stage, it's crucial to recognize that this is *low-level C++ code*. Direct interaction with JavaScript is highly unlikely. However, the *network functionality* it provides is essential for web applications and APIs that *do* use JavaScript. This leads to the indirect relationship through higher-level APIs.

**6. Crafting Examples and Scenarios:**

Now, think about concrete examples:

* **JavaScript initiating a QUIC connection:**  A user clicking a link in a web browser triggers network activity. The browser's networking stack (which includes Chromium's QUIC implementation) will eventually use these low-level functions to send QUIC packets.
* **Setting socket options:**  The example of enabling `SO_TXTIME` demonstrates how the code interacts with the kernel's network scheduler.

**7. Considering User/Programming Errors:**

Think about common pitfalls when working with sockets:

* **Incorrect buffer sizes:**  This is a classic C/C++ problem. The control buffer (`cbuf_`) needs to be large enough.
* **Uninitialized addresses:**  The code has checks for this, but it's still a potential error.
* **Incorrect socket options:**  Trying to set unsupported options or setting them incorrectly.

**8. Tracing User Interaction (Debugging):**

Start from a user action and work backward:

* User clicks a link -> Browser initiates a network request -> QUIC is negotiated -> QUIC needs to send packets ->  `WritePacket` or `WriteMultiplePackets` are called -> The code in this file is executed.

**9. Refining the Explanation:**

Finally, organize the information into a clear and structured answer, addressing each part of the prompt. Use clear language and avoid overly technical jargon where possible. Highlight the key functionalities, explain the indirect JavaScript relationship, provide illustrative examples, and clearly outline potential errors and debugging steps.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe there's a direct way JavaScript calls this C++ code.
* **Correction:**  Realize this is unlikely in a standard web browser environment. The interaction is through higher-level APIs within the browser.
* **Initial thought:** Focus only on the technical details of the structures.
* **Refinement:**  Explain the *purpose* of these structures in the context of network communication and QUIC.
* **Initial thought:** Provide highly technical, code-level examples of errors.
* **Refinement:**  Offer more user-centric examples of how these errors might manifest (e.g., connection failures).

By following this thought process, combining code analysis with an understanding of the larger system and common programming practices, we can generate a comprehensive and accurate answer to the prompt.
这个C++源代码文件 `quic_linux_socket_utils.cc` 属于 Chromium 网络栈中的 QUIC (Quick UDP Internet Connections) 协议实现。它的主要功能是提供 Linux 平台上与 socket 操作相关的实用工具函数和类，用于更方便、更安全地操作 socket，特别是针对 QUIC 协议的需求。

以下是该文件的详细功能列表：

**核心功能：封装和简化 Linux Socket API**

1. **`QuicMsgHdr` 类:**
   - 这是一个对 Linux 系统调用 `sendmsg` 中使用的 `msghdr` 结构的封装。
   - 它的作用是构建用于发送单个数据包的消息头，包括：
     - 设置目标地址 (`SetPeerAddress`)。
     - 设置辅助数据（控制消息，control message），例如源 IP 地址 (`SetIpInNextCmsg`)。
   - 提供了方便的方法来管理控制缓冲区 (`cbuf_`) 和控制消息头 (`cmsg_`)。

2. **`QuicMMsgHdr` 类:**
   - 这是一个对 Linux 系统调用 `sendmmsg` 中使用的 `mmsghdr` 结构的封装。
   - 它的作用是构建用于批量发送多个数据包的消息头，可以提高发送效率。
   - 内部维护了一个 `mmsghdr` 数组，每个元素对应一个要发送的数据包。
   - 提供了初始化单个消息头 (`InitOneHeader`) 和设置辅助数据的方法。
   - 可以计算已发送的字节数 (`num_bytes_sent`)。

3. **辅助数据管理:**
   - `SetIpInfoInCmsgData`: 设置 IP 相关的辅助数据，例如指定发送数据包的本地 IP 地址（多网卡场景下有用）。
   - `SetIpInfoInCmsg`: 类似 `SetIpInfoInCmsgData`，但直接操作 `cmsghdr` 结构。
   - `GetNextCmsgDataInternal`: 获取下一个可用的控制消息数据块的指针。

4. **Socket Option 操作:**
   - `GetUDPSegmentSize`: 获取 UDP 分片大小 (UDP Segmentation Offload, USO) 的信息。
   - `EnableReleaseTime`: 启用 socket 的发送时间戳功能 (SO_TXTIME)，允许应用程序更精确地控制数据包的发送时间。
   - `GetTtlFromMsghdr`: 从接收到的消息头中提取 TTL (Time To Live) 值。

5. **数据包发送:**
   - `WritePacket`: 使用 `sendmsg` 系统调用发送单个数据包，处理 `EINTR` 中断错误。
   - `WriteMultiplePackets`: 使用 `sendmmsg` 系统调用批量发送多个数据包，处理 `EINTR` 中断错误。

**与 JavaScript 的关系:**

该文件是 C++ 代码，与 JavaScript 没有直接的交互。然而，它在 Chromium 浏览器中扮演着关键角色，而浏览器正是 JavaScript 代码的运行环境。

**举例说明:**

当一个使用 JavaScript 的网页通过 QUIC 协议与服务器建立连接并发送数据时，底层的 Chromium 网络栈会使用这里的 C++ 代码来执行实际的网络操作。

**假设输入与输出 (逻辑推理):**

**场景 1: 使用 `QuicMsgHdr` 发送一个 UDP 包**

* **假设输入:**
    - `peer_address`: 目标服务器的 IP 地址和端口号 (例如：`192.168.1.100:4433`)。
    - `iov`: 指向要发送的数据的 `iovec` 结构。
    - `self_address`: 本机用于发送数据包的 IP 地址 (例如：`192.168.1.50`)。

* **操作流程:**
    1. 创建 `QuicMsgHdr` 对象。
    2. 调用 `SetPeerAddress` 设置目标地址。
    3. 如果需要指定源 IP，调用 `SetIpInNextCmsg` 设置源 IP 地址到控制消息。
    4. 调用 `QuicLinuxSocketUtils::WritePacket`，传入 socket 文件描述符和 `QuicMsgHdr` 对象。

* **可能输出:**
    - `WriteResult` 对象，包含 `WRITE_STATUS_OK` 和发送的字节数，表示发送成功。
    - `WriteResult` 对象，包含 `WRITE_STATUS_BLOCKED`，表示 socket 非阻塞，需要稍后重试。
    - `WriteResult` 对象，包含 `WRITE_STATUS_ERROR` 和错误码，表示发送失败。

**场景 2: 使用 `QuicMMsgHdr` 批量发送多个 UDP 包**

* **假设输入:**
    - 一个包含多个 `BufferedWrite` 对象的数组，每个对象包含要发送的数据和目标地址。
    - `self_address`: 本机用于发送数据包的 IP 地址 (如果需要指定)。

* **操作流程:**
    1. 创建 `QuicMMsgHdr` 对象，指定要发送的数据包数量。
    2. 循环遍历 `BufferedWrite` 数组，调用 `InitOneHeader` 初始化 `QuicMMsgHdr` 中的每个消息头。
    3. 如果需要指定源 IP，调用 `SetIpInNextCmsg` 为每个消息头设置源 IP 地址。
    4. 调用 `QuicLinuxSocketUtils::WriteMultiplePackets`，传入 socket 文件描述符和 `QuicMMsgHdr` 对象。

* **可能输出:**
    - `WriteResult` 对象，包含 `WRITE_STATUS_OK` 和发送的总字节数，以及 `num_packets_sent` 指针指向实际发送的数据包数量。
    - `WriteResult` 对象，包含 `WRITE_STATUS_BLOCKED`。
    - `WriteResult` 对象，包含 `WRITE_STATUS_ERROR` 和错误码。

**用户或编程常见的使用错误:**

1. **控制缓冲区不足:** 在使用 `QuicMsgHdr` 或 `QuicMMsgHdr` 设置辅助数据时，如果分配的控制缓冲区 (`cbuf_`) 大小不足以容纳所有控制消息，会导致 `GetNextCmsgDataInternal` 返回 `nullptr`，进而引发断言失败或程序崩溃。

   * **例子:** 尝试设置多个辅助数据（例如源 IP 和时间戳），但 `cbuf_size_` 设置过小。

2. **未初始化地址:** 在调用 `SetPeerAddress` 之前，`peer_address` 对象未正确初始化（例如，IP 地址和端口号未设置）。这会导致断言失败。

   * **例子:**  `QuicSocketAddress peer_addr;`  然后直接调用 `SetPeerAddress(peer_addr)`.

3. **在未连接的 socket 上使用 `QuicMMsgHdr` 但未设置目标地址:** `QuicMMsgHdr` 的 `InitOneHeader` 中断言 `buffered_write.peer_address.IsInitialized()`，这意味着在使用 `sendmmsg` 发送数据时，必须为每个数据包指定目标地址。

   * **例子:**  创建了一个 UDP socket，但 `BufferedWrite` 对象没有设置 `peer_address`。

4. **错误地使用 Socket Options:**  尝试设置不支持的 socket option 或者使用错误的参数。

   * **例子:**  尝试在不支持 `SO_TXTIME` 的内核上调用 `EnableReleaseTime`。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在 Chrome 浏览器中访问一个使用了 QUIC 协议的网站：

1. **用户在地址栏输入网址并按下回车，或点击一个链接。**
2. **浏览器开始解析域名，并尝试与服务器建立连接。**
3. **如果服务器支持 QUIC，浏览器会尝试使用 QUIC 协议进行连接。** 这涉及到 DNS 查询、TLS 握手等过程。
4. **一旦 QUIC 连接建立，当浏览器需要发送 HTTP/3 请求或接收 HTTP/3 响应数据时，底层的 QUIC 实现会负责将数据封装成 QUIC 数据包。**
5. **QUIC 实现会调用操作系统的 socket API 发送数据包。**  在 Linux 平台上，`quic_linux_socket_utils.cc` 中的 `WritePacket` 或 `WriteMultiplePackets` 函数会被调用。
6. **在调用 `WritePacket` 或 `WriteMultiplePackets` 之前，QUIC 实现会构建 `QuicMsgHdr` 或 `QuicMMsgHdr` 对象，设置目标地址、数据内容以及可能的辅助数据（例如源 IP 地址）。** 这就涉及到了 `SetPeerAddress`、`SetIpInNextCmsg` 等函数的调用。
7. **系统调用 `sendmsg` 或 `sendmmsg` 将数据包发送出去。**

**调试线索:**

- 如果网络连接出现问题，例如连接超时、数据传输失败等，可以怀疑是否是 socket 操作层面出现了错误。
- 可以使用网络抓包工具 (如 Wireshark) 观察发送和接收的数据包，检查目标地址、源地址等信息是否正确。
- 可以使用 Chromium 提供的内部日志工具 (如 `chrome://net-internals/#quic`) 查看 QUIC 连接的详细信息，包括发送和接收的数据包数量、错误信息等。
- 如果怀疑是特定 socket option 的问题，可以检查相关函数的返回值和错误码。
- 如果程序崩溃或出现断言失败，可以检查 `QuicMsgHdr` 或 `QuicMMsgHdr` 的使用是否正确，例如控制缓冲区大小是否足够，地址是否已初始化等。

总而言之，`quic_linux_socket_utils.cc` 是 Chromium QUIC 协议在 Linux 平台上进行底层 socket 操作的关键组件，它封装了复杂的系统调用，并提供了更易用、更安全的接口供 QUIC 上层模块使用。虽然 JavaScript 代码本身不会直接调用这个文件中的代码，但它所依赖的网络功能最终是由这些底层的 C++ 代码实现的。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_linux_socket_utils.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_linux_socket_utils.h"

#include <linux/net_tstamp.h>
#include <netinet/in.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "quiche/quic/core/quic_syscall_wrapper.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

QuicMsgHdr::QuicMsgHdr(iovec* iov, size_t iov_len, char* cbuf, size_t cbuf_size)
    : cbuf_(cbuf), cbuf_size_(cbuf_size), cmsg_(nullptr) {
  hdr_.msg_name = nullptr;
  hdr_.msg_namelen = 0;

  hdr_.msg_iov = iov;
  hdr_.msg_iovlen = iov_len;
  hdr_.msg_flags = 0;

  hdr_.msg_control = nullptr;
  hdr_.msg_controllen = 0;
}

void QuicMsgHdr::SetPeerAddress(const QuicSocketAddress& peer_address) {
  QUICHE_DCHECK(peer_address.IsInitialized());

  raw_peer_address_ = peer_address.generic_address();
  hdr_.msg_name = &raw_peer_address_;
  hdr_.msg_namelen = raw_peer_address_.ss_family == AF_INET
                         ? sizeof(sockaddr_in)
                         : sizeof(sockaddr_in6);
}

void QuicMsgHdr::SetIpInNextCmsg(const QuicIpAddress& self_address) {
  if (!self_address.IsInitialized()) {
    return;
  }

  if (self_address.IsIPv4()) {
    QuicLinuxSocketUtils::SetIpInfoInCmsgData(
        self_address, GetNextCmsgData<in_pktinfo>(IPPROTO_IP, IP_PKTINFO));
  } else {
    QuicLinuxSocketUtils::SetIpInfoInCmsgData(
        self_address, GetNextCmsgData<in6_pktinfo>(IPPROTO_IPV6, IPV6_PKTINFO));
  }
}

void* QuicMsgHdr::GetNextCmsgDataInternal(int cmsg_level, int cmsg_type,
                                          size_t data_size) {
  // msg_controllen needs to be increased first, otherwise CMSG_NXTHDR will
  // return nullptr.
  hdr_.msg_controllen += CMSG_SPACE(data_size);
  QUICHE_DCHECK_LE(hdr_.msg_controllen, cbuf_size_);

  if (cmsg_ == nullptr) {
    QUICHE_DCHECK_EQ(nullptr, hdr_.msg_control);
    memset(cbuf_, 0, cbuf_size_);
    hdr_.msg_control = cbuf_;
    cmsg_ = CMSG_FIRSTHDR(&hdr_);
  } else {
    QUICHE_DCHECK_NE(nullptr, hdr_.msg_control);
    cmsg_ = CMSG_NXTHDR(&hdr_, cmsg_);
  }

  QUICHE_DCHECK_NE(nullptr, cmsg_) << "Insufficient control buffer space";

  cmsg_->cmsg_len = CMSG_LEN(data_size);
  cmsg_->cmsg_level = cmsg_level;
  cmsg_->cmsg_type = cmsg_type;

  return CMSG_DATA(cmsg_);
}

void QuicMMsgHdr::InitOneHeader(int i, const BufferedWrite& buffered_write) {
  mmsghdr* mhdr = GetMMsgHdr(i);
  msghdr* hdr = &mhdr->msg_hdr;
  iovec* iov = GetIov(i);

  iov->iov_base = const_cast<char*>(buffered_write.buffer);
  iov->iov_len = buffered_write.buf_len;
  hdr->msg_iov = iov;
  hdr->msg_iovlen = 1;
  hdr->msg_control = nullptr;
  hdr->msg_controllen = 0;

  // Only support unconnected sockets.
  QUICHE_DCHECK(buffered_write.peer_address.IsInitialized());

  sockaddr_storage* peer_address_storage = GetPeerAddressStorage(i);
  *peer_address_storage = buffered_write.peer_address.generic_address();
  hdr->msg_name = peer_address_storage;
  hdr->msg_namelen = peer_address_storage->ss_family == AF_INET
                         ? sizeof(sockaddr_in)
                         : sizeof(sockaddr_in6);
}

void QuicMMsgHdr::SetIpInNextCmsg(int i, const QuicIpAddress& self_address) {
  if (!self_address.IsInitialized()) {
    return;
  }

  if (self_address.IsIPv4()) {
    QuicLinuxSocketUtils::SetIpInfoInCmsgData(
        self_address, GetNextCmsgData<in_pktinfo>(i, IPPROTO_IP, IP_PKTINFO));
  } else {
    QuicLinuxSocketUtils::SetIpInfoInCmsgData(
        self_address,
        GetNextCmsgData<in6_pktinfo>(i, IPPROTO_IPV6, IPV6_PKTINFO));
  }
}

void* QuicMMsgHdr::GetNextCmsgDataInternal(int i, int cmsg_level, int cmsg_type,
                                           size_t data_size) {
  mmsghdr* mhdr = GetMMsgHdr(i);
  msghdr* hdr = &mhdr->msg_hdr;
  cmsghdr*& cmsg = *GetCmsgHdr(i);

  // msg_controllen needs to be increased first, otherwise CMSG_NXTHDR will
  // return nullptr.
  hdr->msg_controllen += CMSG_SPACE(data_size);
  QUICHE_DCHECK_LE(hdr->msg_controllen, cbuf_size_);

  if (cmsg == nullptr) {
    QUICHE_DCHECK_EQ(nullptr, hdr->msg_control);
    hdr->msg_control = GetCbuf(i);
    cmsg = CMSG_FIRSTHDR(hdr);
  } else {
    QUICHE_DCHECK_NE(nullptr, hdr->msg_control);
    cmsg = CMSG_NXTHDR(hdr, cmsg);
  }

  QUICHE_DCHECK_NE(nullptr, cmsg) << "Insufficient control buffer space";

  cmsg->cmsg_len = CMSG_LEN(data_size);
  cmsg->cmsg_level = cmsg_level;
  cmsg->cmsg_type = cmsg_type;

  return CMSG_DATA(cmsg);
}

int QuicMMsgHdr::num_bytes_sent(int num_packets_sent) {
  QUICHE_DCHECK_LE(0, num_packets_sent);
  QUICHE_DCHECK_LE(num_packets_sent, num_msgs_);

  int bytes_sent = 0;
  iovec* iov = GetIov(0);
  for (int i = 0; i < num_packets_sent; ++i) {
    bytes_sent += iov[i].iov_len;
  }
  return bytes_sent;
}

// static
int QuicLinuxSocketUtils::GetUDPSegmentSize(int fd) {
  int optval;
  socklen_t optlen = sizeof(optval);
  int rc = getsockopt(fd, SOL_UDP, UDP_SEGMENT, &optval, &optlen);
  if (rc < 0) {
    QUIC_LOG_EVERY_N_SEC(INFO, 10)
        << "getsockopt(UDP_SEGMENT) failed: " << strerror(errno);
    return -1;
  }
  QUIC_LOG_EVERY_N_SEC(INFO, 10)
      << "getsockopt(UDP_SEGMENT) returned segment size: " << optval;
  return optval;
}

// static
bool QuicLinuxSocketUtils::EnableReleaseTime(int fd, clockid_t clockid) {
  // TODO(wub): Change to sock_txtime once it is available in linux/net_tstamp.h
  struct LinuxSockTxTime {
    clockid_t clockid; /* reference clockid */
    uint32_t flags;    /* flags defined by enum txtime_flags */
  };

  LinuxSockTxTime so_txtime_val{clockid, 0};

  if (setsockopt(fd, SOL_SOCKET, SO_TXTIME, &so_txtime_val,
                 sizeof(so_txtime_val)) != 0) {
    QUIC_LOG_EVERY_N_SEC(INFO, 10)
        << "setsockopt(SOL_SOCKET,SO_TXTIME) failed: " << strerror(errno);
    return false;
  }

  return true;
}

// static
bool QuicLinuxSocketUtils::GetTtlFromMsghdr(struct msghdr* hdr, int* ttl) {
  if (hdr->msg_controllen > 0) {
    struct cmsghdr* cmsg;
    for (cmsg = CMSG_FIRSTHDR(hdr); cmsg != nullptr;
         cmsg = CMSG_NXTHDR(hdr, cmsg)) {
      if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL) ||
          (cmsg->cmsg_level == IPPROTO_IPV6 &&
           cmsg->cmsg_type == IPV6_HOPLIMIT)) {
        *ttl = *(reinterpret_cast<int*>(CMSG_DATA(cmsg)));
        return true;
      }
    }
  }
  return false;
}

// static
void QuicLinuxSocketUtils::SetIpInfoInCmsgData(
    const QuicIpAddress& self_address, void* cmsg_data) {
  QUICHE_DCHECK(self_address.IsInitialized());
  const std::string& address_str = self_address.ToPackedString();
  if (self_address.IsIPv4()) {
    in_pktinfo* pktinfo = static_cast<in_pktinfo*>(cmsg_data);
    pktinfo->ipi_ifindex = 0;
    memcpy(&pktinfo->ipi_spec_dst, address_str.c_str(), address_str.length());
  } else if (self_address.IsIPv6()) {
    in6_pktinfo* pktinfo = static_cast<in6_pktinfo*>(cmsg_data);
    memcpy(&pktinfo->ipi6_addr, address_str.c_str(), address_str.length());
  } else {
    QUIC_BUG(quic_bug_10598_1) << "Unrecognized IPAddress";
  }
}

// static
size_t QuicLinuxSocketUtils::SetIpInfoInCmsg(const QuicIpAddress& self_address,
                                             cmsghdr* cmsg) {
  std::string address_string;
  if (self_address.IsIPv4()) {
    cmsg->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    in_pktinfo* pktinfo = reinterpret_cast<in_pktinfo*>(CMSG_DATA(cmsg));
    memset(pktinfo, 0, sizeof(in_pktinfo));
    pktinfo->ipi_ifindex = 0;
    address_string = self_address.ToPackedString();
    memcpy(&pktinfo->ipi_spec_dst, address_string.c_str(),
           address_string.length());
    return sizeof(in_pktinfo);
  } else if (self_address.IsIPv6()) {
    cmsg->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    in6_pktinfo* pktinfo = reinterpret_cast<in6_pktinfo*>(CMSG_DATA(cmsg));
    memset(pktinfo, 0, sizeof(in6_pktinfo));
    address_string = self_address.ToPackedString();
    memcpy(&pktinfo->ipi6_addr, address_string.c_str(),
           address_string.length());
    return sizeof(in6_pktinfo);
  } else {
    QUIC_BUG(quic_bug_10598_2) << "Unrecognized IPAddress";
    return 0;
  }
}

// static
WriteResult QuicLinuxSocketUtils::WritePacket(int fd, const QuicMsgHdr& hdr) {
  int rc;
  do {
    rc = GetGlobalSyscallWrapper()->Sendmsg(fd, hdr.hdr(), 0);
  } while (rc < 0 && errno == EINTR);
  if (rc >= 0) {
    return WriteResult(WRITE_STATUS_OK, rc);
  }
  return WriteResult((errno == EAGAIN || errno == EWOULDBLOCK)
                         ? WRITE_STATUS_BLOCKED
                         : WRITE_STATUS_ERROR,
                     errno);
}

// static
WriteResult QuicLinuxSocketUtils::WriteMultiplePackets(int fd,
                                                       QuicMMsgHdr* mhdr,
                                                       int* num_packets_sent) {
  *num_packets_sent = 0;

  if (mhdr->num_msgs() <= 0) {
    return WriteResult(WRITE_STATUS_ERROR, EINVAL);
  }

  int rc;
  do {
    rc = GetGlobalSyscallWrapper()->Sendmmsg(fd, mhdr->mhdr(), mhdr->num_msgs(),
                                             0);
  } while (rc < 0 && errno == EINTR);

  if (rc > 0) {
    *num_packets_sent = rc;

    return WriteResult(WRITE_STATUS_OK, mhdr->num_bytes_sent(rc));
  } else if (rc == 0) {
    QUIC_BUG(quic_bug_10598_3)
        << "sendmmsg returned 0, returning WRITE_STATUS_ERROR. errno: "
        << errno;
    errno = EIO;
  }

  return WriteResult((errno == EAGAIN || errno == EWOULDBLOCK)
                         ? WRITE_STATUS_BLOCKED
                         : WRITE_STATUS_ERROR,
                     errno);
}

}  // namespace quic
```