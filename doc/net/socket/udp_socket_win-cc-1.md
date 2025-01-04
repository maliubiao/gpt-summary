Response:
Let's break down the thought process for analyzing this code and generating the response.

**1. Initial Understanding & Context:**

* **File Location:** `net/socket/udp_socket_win.cc` - This immediately tells us we're dealing with UDP socket implementation on Windows within the Chromium network stack.
* **Part 2 of 2:**  This implies we've already processed some of the file and this section continues the implementation. The previous part likely covered core socket creation, connection, and basic I/O.
* **Key Classes:**  The code heavily features `UDPSocketWin`, `DscpManager`, `QwaveApi`, and interacts with Windows socket APIs (winsock). Understanding the role of each is crucial.

**2. High-Level Functionality Identification (Iterative Reading):**

* **Multicast:**  I scanned for keywords like "multicast," "JoinGroup," "LeaveGroup," "multicast_interface," etc. This clearly indicates functionality for joining and leaving multicast groups and configuring multicast behavior.
* **Quality of Service (QoS) / DSCP:**  The presence of `DscpManager`, `SetDiffServCodePoint`, `SetTos`, and `QwaveApi` points to QoS configuration and setting the DiffServ Code Point (DSCP) for packets.
* **Non-Blocking I/O:**  The `UseNonBlockingIO()` method and the internal `InternalRecvFromNonBlocking` and `InternalSendToNonBlocking` functions highlight support for asynchronous socket operations.
* **IPv6 Specifics:**  Methods like `SetIPv6Only` indicate handling of IPv6 specific socket options.
* **Error Handling:**  Calls to `MapSystemError` are prevalent, indicating a mapping between Windows socket errors and Chromium's error codes.
* **Internal Operations:** Functions prefixed with `Internal` suggest low-level, non-public methods for send and receive.

**3. Deep Dive into Specific Functionalities (Detailed Code Analysis):**

* **Multicast Functions:** I examined `JoinGroup` and `LeaveGroup` and noted the different implementations for IPv4 and IPv6, including the use of `ip_mreq` and `ipv6_mreq` structures and `setsockopt`. I also looked at `SetMulticastInterface`, `SetMulticastTimeToLive`, and `SetMulticastLoopbackMode` and how they manipulate socket options.
* **QoS/DSCP:** I focused on `SetDiffServCodePoint` and `SetTos`. I recognized the dependency on `QwaveApi` and the `DscpManager`. The logic within `DscpManager::PrepareForSend` – checking for existing configurations, adding the socket to a flow, and potentially setting the DSCP value – was a key area. The asynchronous handle creation in `DscpManager` was also noted.
* **Non-Blocking I/O:**  I examined `InternalRecvFromNonBlocking` and `InternalSendToNonBlocking`. The use of `WSAEWOULDBLOCK` and the setting of `read_iobuffer_` and `write_iobuffer_` when an operation is pending confirmed the non-blocking nature.
* **Other Functions:** I briefly reviewed `SetIPv6Only` and `DetachFromThread` for their basic purpose.

**4. Identifying Relationships with JavaScript:**

* **Network Requests:** The primary link is through JavaScript's `fetch` API or `XMLHttpRequest`. These APIs ultimately rely on the underlying network stack, including this UDP socket implementation, for sending and receiving data.
* **WebSockets (Less Direct):** While this specific file is about UDP, WebSockets use TCP. However, the underlying socket infrastructure principles are similar, and Chromium's network stack manages both.

**5. Logic Inference (Hypothetical Scenarios):**

* **Multicast Join:** I imagined a scenario where a JavaScript application wants to receive multicast data. The steps involve obtaining the multicast group address and calling a Chromium API (likely exposed through a C++ interface) that would eventually call `UDPSocketWin::JoinGroup`.
* **Sending with DSCP:** I envisioned a JavaScript application wanting to prioritize its UDP traffic. This would involve calling a Chromium API that maps to `UDPSocketWin::SetDiffServCodePoint` and then sending data, triggering the `DscpManager` logic.

**6. Common User/Programming Errors:**

* **Multicast:** Incorrect multicast address, forgetting to bind to an address, firewall issues.
* **QoS/DSCP:** Trying to set DSCP without administrator privileges (for `SetFlow`), unsupported Windows version.
* **Non-Blocking I/O:** Not handling `ERR_IO_PENDING` correctly, leading to busy-waiting.

**7. Debugging Scenario:**

I traced a hypothetical user action (e.g., joining a multicast group on a webpage) down through the potential call stack, starting from the JavaScript event handler, moving to Chromium's C++ network APIs, and finally arriving at the `UDPSocketWin::JoinGroup` function.

**8. Summarization (Key Functionalities):**

Based on the detailed analysis, I listed the core functionalities provided by this code snippet.

**Self-Correction/Refinement during the Process:**

* Initially, I might have just listed the functions. However, rereading the prompt and focusing on "functionality" led me to describe *what* the code achieves rather than just listing the methods.
* I considered the level of detail required for the JavaScript relationship. I opted for a high-level explanation of how network APIs in JavaScript interact with the underlying C++ implementation.
* I made sure to tie the hypothetical scenarios and common errors back to the specific functions analyzed.

By following these steps, combining high-level understanding with detailed code inspection, and addressing each point in the prompt systematically, I was able to generate a comprehensive and accurate response.
好的，这是`net/socket/udp_socket_win.cc` 文件（第二部分）的功能归纳：

**核心功能归纳:**

这部分 `UDPSocketWin` 类的代码主要负责以下功能，并延续了第一部分关于 UDP socket 在 Windows 平台上的实现：

1. **非阻塞 I/O 操作:**
   - 实现了非阻塞的 `RecvFrom` (`InternalRecvFromNonBlocking`) 和 `SendTo` (`InternalSendToNonBlocking`) 操作。
   - 当 socket 无法立即完成读取或写入时，会返回 `ERR_IO_PENDING`，并设置内部状态以便在 socket 可读或可写时收到通知。
   - 涉及到使用 Windows 的 Overlapped I/O 机制 (`WSASendTo`, `WSARecvMsg`) 或标准的非阻塞 socket 操作 (`sendto`, `recvfrom`)。

2. **多播 (Multicast) 支持:**
   - 提供了加入多播组 (`JoinGroup`) 和离开多播组 (`LeaveGroup`) 的功能。
   - 允许设置多播接口 (`SetMulticastInterface`)、生存时间 (TTL, `SetMulticastTimeToLive`) 和环回模式 (`SetMulticastLoopbackMode`)。
   - 针对 IPv4 和 IPv6 多播使用了不同的 socket 选项 (`IP_ADD_MEMBERSHIP`, `IPV6_ADD_MEMBERSHIP` 等)。

3. **服务质量 (QoS) 和差分服务代码点 (DSCP) 设置:**
   - 允许设置 socket 的 DSCP 值 (`SetDiffServCodePoint`)，用于网络流量优先级控制。
   - 更底层的 `SetTos` 方法允许同时设置 DSCP 和显式拥塞通知 (ECN)。
   - 使用了 `QwaveApi` (Windows 的 QoS API) 来实现 DSCP 的设置。
   - 引入了 `DscpManager` 类来管理与 QoS 相关的状态和操作，例如创建 QoS 流、将 socket 添加到流中以及设置 DSCP 值。

4. **其他 Socket 选项:**
   - 实现了设置 IPv6-only 模式 (`SetIPv6Only`)，控制 socket 是否只允许 IPv6 连接。
   - `DetachFromThread` 用于解除 socket 与当前线程的关联。
   - `UseNonBlockingIO` 用于显式声明使用非阻塞 I/O。
   - `ApplySocketTag`  在 Windows 平台上当前实现为空操作，因为 Windows 没有特定的 SocketTag 支持。

**与 JavaScript 的关系举例说明:**

JavaScript 本身无法直接操作底层的 socket。Chromium 的渲染进程中的 JavaScript 需要通过 Chromium 提供的 C++ API 来执行网络操作。

**假设输入与输出 (逻辑推理):**

**场景 1: JavaScript 请求加入多播组**

* **假设输入:**
    * JavaScript 代码调用 Chromium 提供的 API，请求加入多播组地址 "239.0.0.1:5000"。
    * 假设 `UDPSocketWin` 实例已经创建并绑定到一个本地地址。
* **内部处理:**
    * Chromium 的 C++ 网络代码会将多播组地址转换为 `IPAddress` 对象。
    * 调用 `UDPSocketWin::JoinGroup` 方法，传入该 `IPAddress`。
    * `JoinGroup` 方法根据地址族 (IPv4) 调用 `setsockopt`，设置 `IP_ADD_MEMBERSHIP` 选项。
* **可能输出:**
    * 如果 `setsockopt` 成功，`JoinGroup` 返回 `OK` (0)。
    * 如果失败（例如，无效的多播地址），返回相应的错误码 (例如，`ERR_ADDRESS_INVALID`)。

**场景 2: JavaScript 发送带有特定 DSCP 值的 UDP 包**

* **假设输入:**
    * JavaScript 代码请求发送数据到目标地址，并指定 DSCP 值为 `DSCP_EF` (加速转发)。
    * 假设 `UDPSocketWin` 实例已经连接到目标地址。
* **内部处理:**
    * Chromium 的 C++ 网络代码会调用 `UDPSocketWin::SetDiffServCodePoint` 或 `SetTos` 方法设置 DSCP 值。
    * `SetDiffServCodePoint` 会调用 `DscpManager::Set` 来记录 DSCP 值。
    * 在实际发送数据时（调用 `InternalSendTo` 或其非阻塞版本），`DscpManager::PrepareForSend` 会被调用。
    * `PrepareForSend` 会使用 `QwaveApi` 将 socket 添加到一个 QoS 流，并设置相应的 DSCP 值。
    * 最终通过 Windows socket API 发送数据。
* **可能输出:**
    * 如果 QoS 设置和数据发送都成功，`SendTo` 操作返回发送的字节数。
    * 如果 QoS API 调用失败（例如，权限问题），`PrepareForSend` 可能会返回一个错误码。

**用户或编程常见的使用错误举例说明:**

1. **多播组操作错误:**
   - **错误:**  在 socket 未绑定到任何地址的情况下尝试加入多播组。
   - **结果:** `JoinGroup` 可能会返回 `ERR_SOCKET_NOT_CONNECTED` 或相关的错误。

2. **QoS/DSCP 设置错误:**
   - **错误:**  尝试在不支持 QoS 的 Windows 版本上设置 DSCP 值。
   - **结果:** `SetDiffServCodePoint` 或 `SetTos` 可能会返回 `ERR_NOT_IMPLEMENTED`。
   - **错误:**  在没有管理员权限的情况下尝试设置 QoS 流相关的选项。
   - **结果:** `DscpManager::PrepareForSend` 中调用 `QwaveApi` 可能会失败，导致数据包无法按预期的 DSCP 值发送。

3. **非阻塞 I/O 使用错误:**
   - **错误:**  在非阻塞 `RecvFromNonBlocking` 返回 `ERR_IO_PENDING` 后，没有正确地等待 socket 可读的事件，而是立即再次调用 `RecvFromNonBlocking`。
   - **结果:**  可能会导致 CPU 占用过高（忙等待）。
   - **正确做法:**  当返回 `ERR_IO_PENDING` 时，应该注册一个回调，当 socket 变得可读时再进行读取操作。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在浏览器中访问一个需要接收 UDP 多播数据的网页应用：

1. **用户操作:** 用户打开一个网页，该网页包含使用 JavaScript WebSocket API 或一个自定义的 UDP 通信模块的功能。
2. **JavaScript 调用:** 网页上的 JavaScript 代码会调用一个自定义的 JavaScript API 或使用浏览器的扩展 API，来请求加入特定的 UDP 多播组。
3. **Chromium 内部 API 调用:** JavaScript 的请求会通过 Chromium 的消息传递机制传递到浏览器进程的 C++ 代码中。
4. **`UDPSocket` 或其子类创建:**  Chromium 的网络栈会创建一个 `UDPSocketWin` 的实例来处理 UDP 通信。
5. **`JoinGroup` 调用:**  处理多播加入请求的 C++ 代码最终会调用 `UDPSocketWin::JoinGroup` 方法，并将目标多播组地址作为参数传递进来。
6. **Winsock API 调用:**  `JoinGroup` 方法内部会调用 Windows 的 socket API `setsockopt`，并设置 `IP_ADD_MEMBERSHIP` 或 `IPV6_ADD_MEMBERSHIP` 选项。

在调试过程中，你可能会在以下位置设置断点来跟踪执行流程：

* JavaScript 中发起多播加入请求的代码。
* Chromium C++ 网络栈中处理该请求的代码（可能在 `net/` 目录下）。
* `UDPSocketWin::JoinGroup` 方法的入口。
* `setsockopt` 函数的调用。

**总结本部分的功能:**

这部分代码为 `UDPSocketWin` 类添加了关键的高级 UDP 功能，包括非阻塞 I/O、全面的多播支持以及 QoS 和 DSCP 的配置能力。它利用了 Windows 平台提供的 socket API 和 QoS API，并将其封装成 Chromium 网络栈的一部分，为上层的网络应用提供更丰富和灵活的 UDP 通信选项。`DscpManager` 的引入是本部分的一个亮点，它专门负责处理与 QoS 相关的复杂逻辑。

Prompt: 
```
这是目录为net/socket/udp_socket_win.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
ntrol_buffer.buf = raw_control_buffer;
    control_buffer.len = sizeof(raw_control_buffer);
    WSAMSG message;
    bool temp_address = !remote_address_.get();
    if (temp_address) {
      remote_address_ = std::make_unique<IPEndPoint>(*address);
    }
    PopulateWSAMSG(message, storage, &write_buffer, control_buffer, true);
    if (temp_address) {
      remote_address_.reset();
    }
    rv = wsa_send_msg_(socket_, &message, flags, &num,
                       &core_->write_overlapped_, nullptr);
  } else {
    rv = WSASendTo(socket_, &write_buffer, 1, &num, flags, addr,
                   storage.addr_len, &core_->write_overlapped_, nullptr);
  }
  if (rv == 0) {
    if (ResetEventIfSignaled(core_->write_overlapped_.hEvent)) {
      int result = num;
      LogWrite(result, buf->data(), address);
      return result;
    }
  } else {
    int os_error = WSAGetLastError();
    if (os_error != WSA_IO_PENDING) {
      int result = MapSystemError(os_error);
      LogWrite(result, nullptr, nullptr);
      return result;
    }
  }

  core_->WatchForWrite();
  core_->write_iobuffer_ = buf;
  return ERR_IO_PENDING;
}

int UDPSocketWin::InternalRecvFromNonBlocking(IOBuffer* buf,
                                              int buf_len,
                                              IPEndPoint* address) {
  DCHECK(!read_iobuffer_ || read_iobuffer_.get() == buf);
  SockaddrStorage storage;
  storage.addr_len = sizeof(storage.addr_storage);

  CHECK_NE(INVALID_SOCKET, socket_);

  int rv;
  if (report_ecn_) {
    WSABUF read_buffer;
    read_buffer.buf = buf->data();
    read_buffer.len = buf_len;
    WSABUF control_buffer;
    char raw_control_buffer[WSA_CMSG_SPACE(sizeof(INT))];
    control_buffer.buf = raw_control_buffer;
    control_buffer.len = sizeof(raw_control_buffer);
    WSAMSG message;
    DWORD bytes_read;
    PopulateWSAMSG(message, storage, &read_buffer, control_buffer, false);
    rv = wsa_recv_msg_(socket_, &message, &bytes_read, nullptr, nullptr);
    if (rv == 0) {
      SetLastTosFromWSAMSG(message);
      rv = bytes_read;  // WSARecvMsg() returns zero on delivery, but recvfrom
                        // returns the number of bytes received.
    }
  } else {
    rv = recvfrom(socket_, buf->data(), buf_len, 0, storage.addr,
                  &storage.addr_len);
  }
  if (rv == SOCKET_ERROR) {
    int os_error = WSAGetLastError();
    if (os_error == WSAEWOULDBLOCK) {
      read_iobuffer_ = buf;
      read_iobuffer_len_ = buf_len;
      WatchForReadWrite();
      return ERR_IO_PENDING;
    }
    rv = MapSystemError(os_error);
    LogRead(rv, nullptr, nullptr);
    return rv;
  }
  IPEndPoint address_storage;
  IPEndPoint* address_to_log = nullptr;
  if (rv >= 0) {
    if (address_storage.FromSockAddr(storage.addr, storage.addr_len)) {
      if (address) {
        *address = address_storage;
      }
      address_to_log = &address_storage;
    } else {
      rv = ERR_ADDRESS_INVALID;
    }
  }
  LogRead(rv, buf->data(), address_to_log);
  return rv;
}

int UDPSocketWin::InternalSendToNonBlocking(IOBuffer* buf,
                                            int buf_len,
                                            const IPEndPoint* address) {
  DCHECK(!write_iobuffer_ || write_iobuffer_.get() == buf);
  SockaddrStorage storage;
  struct sockaddr* addr = storage.addr;
  // Convert address.
  if (address) {
    if (!address->ToSockAddr(addr, &storage.addr_len)) {
      int result = ERR_ADDRESS_INVALID;
      LogWrite(result, nullptr, nullptr);
      return result;
    }
  } else {
    addr = nullptr;
    storage.addr_len = 0;
  }

  int rv;
  if (send_ecn_ != ECN_NOT_ECT) {
    char raw_control_buffer[WSA_CMSG_SPACE(sizeof(INT))];
    WSABUF write_buffer;
    write_buffer.buf = buf->data();
    write_buffer.len = buf_len;
    WSABUF control_buffer;
    control_buffer.buf = raw_control_buffer;
    control_buffer.len = sizeof(raw_control_buffer);
    WSAMSG message;
    DWORD bytes_read;
    PopulateWSAMSG(message, storage, &write_buffer, control_buffer, true);
    rv = wsa_send_msg_(socket_, &message, 0, &bytes_read, nullptr, nullptr);
    if (rv == 0) {
      rv = bytes_read;
    }
  } else {
    rv = sendto(socket_, buf->data(), buf_len, 0, addr, storage.addr_len);
  }
  if (rv == SOCKET_ERROR) {
    int os_error = WSAGetLastError();
    if (os_error == WSAEWOULDBLOCK) {
      write_iobuffer_ = buf;
      write_iobuffer_len_ = buf_len;
      WatchForReadWrite();
      return ERR_IO_PENDING;
    }
    rv = MapSystemError(os_error);
    LogWrite(rv, nullptr, nullptr);
    return rv;
  }
  LogWrite(rv, buf->data(), address);
  return rv;
}

int UDPSocketWin::SetMulticastOptions() {
  if (!(socket_options_ & SOCKET_OPTION_MULTICAST_LOOP)) {
    DWORD loop = 0;
    int protocol_level = addr_family_ == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    int option =
        addr_family_ == AF_INET ? IP_MULTICAST_LOOP : IPV6_MULTICAST_LOOP;
    int rv = setsockopt(socket_, protocol_level, option,
                        reinterpret_cast<const char*>(&loop), sizeof(loop));
    if (rv < 0) {
      return MapSystemError(WSAGetLastError());
    }
  }
  if (multicast_time_to_live_ != 1) {
    DWORD hops = multicast_time_to_live_;
    int protocol_level = addr_family_ == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    int option =
        addr_family_ == AF_INET ? IP_MULTICAST_TTL : IPV6_MULTICAST_HOPS;
    int rv = setsockopt(socket_, protocol_level, option,
                        reinterpret_cast<const char*>(&hops), sizeof(hops));
    if (rv < 0) {
      return MapSystemError(WSAGetLastError());
    }
  }
  if (multicast_interface_ != 0) {
    switch (addr_family_) {
      case AF_INET: {
        in_addr address;
        address.s_addr = htonl(multicast_interface_);
        int rv = setsockopt(socket_, IPPROTO_IP, IP_MULTICAST_IF,
                            reinterpret_cast<const char*>(&address),
                            sizeof(address));
        if (rv) {
          return MapSystemError(WSAGetLastError());
        }
        break;
      }
      case AF_INET6: {
        uint32_t interface_index = multicast_interface_;
        int rv = setsockopt(socket_, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                            reinterpret_cast<const char*>(&interface_index),
                            sizeof(interface_index));
        if (rv) {
          return MapSystemError(WSAGetLastError());
        }
        break;
      }
      default:
        NOTREACHED() << "Invalid address family";
    }
  }
  return OK;
}

int UDPSocketWin::DoBind(const IPEndPoint& address) {
  SockaddrStorage storage;
  if (!address.ToSockAddr(storage.addr, &storage.addr_len)) {
    return ERR_ADDRESS_INVALID;
  }
  int rv = bind(socket_, storage.addr, storage.addr_len);
  if (rv == 0) {
    return OK;
  }
  int last_error = WSAGetLastError();
  // Map some codes that are special to bind() separately.
  // * WSAEACCES: If a port is already bound to a socket, WSAEACCES may be
  //   returned instead of WSAEADDRINUSE, depending on whether the socket
  //   option SO_REUSEADDR or SO_EXCLUSIVEADDRUSE is set and whether the
  //   conflicting socket is owned by a different user account. See the MSDN
  //   page "Using SO_REUSEADDR and SO_EXCLUSIVEADDRUSE" for the gory details.
  if (last_error == WSAEACCES || last_error == WSAEADDRNOTAVAIL) {
    return ERR_ADDRESS_IN_USE;
  }
  return MapSystemError(last_error);
}

QwaveApi* UDPSocketWin::GetQwaveApi() const {
  return QwaveApi::GetDefault();
}

int UDPSocketWin::JoinGroup(const IPAddress& group_address) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!is_connected()) {
    return ERR_SOCKET_NOT_CONNECTED;
  }

  switch (group_address.size()) {
    case IPAddress::kIPv4AddressSize: {
      if (addr_family_ != AF_INET) {
        return ERR_ADDRESS_INVALID;
      }
      ip_mreq mreq;
      mreq.imr_interface.s_addr = htonl(multicast_interface_);
      memcpy(&mreq.imr_multiaddr, group_address.bytes().data(),
             IPAddress::kIPv4AddressSize);
      int rv = setsockopt(socket_, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                          reinterpret_cast<const char*>(&mreq), sizeof(mreq));
      if (rv) {
        return MapSystemError(WSAGetLastError());
      }
      return OK;
    }
    case IPAddress::kIPv6AddressSize: {
      if (addr_family_ != AF_INET6) {
        return ERR_ADDRESS_INVALID;
      }
      ipv6_mreq mreq;
      mreq.ipv6mr_interface = multicast_interface_;
      memcpy(&mreq.ipv6mr_multiaddr, group_address.bytes().data(),
             IPAddress::kIPv6AddressSize);
      int rv = setsockopt(socket_, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
                          reinterpret_cast<const char*>(&mreq), sizeof(mreq));
      if (rv) {
        return MapSystemError(WSAGetLastError());
      }
      return OK;
    }
    default:
      NOTREACHED() << "Invalid address family";
  }
}

int UDPSocketWin::LeaveGroup(const IPAddress& group_address) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!is_connected()) {
    return ERR_SOCKET_NOT_CONNECTED;
  }

  switch (group_address.size()) {
    case IPAddress::kIPv4AddressSize: {
      if (addr_family_ != AF_INET) {
        return ERR_ADDRESS_INVALID;
      }
      ip_mreq mreq;
      mreq.imr_interface.s_addr = htonl(multicast_interface_);
      memcpy(&mreq.imr_multiaddr, group_address.bytes().data(),
             IPAddress::kIPv4AddressSize);
      int rv = setsockopt(socket_, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                          reinterpret_cast<const char*>(&mreq), sizeof(mreq));
      if (rv) {
        return MapSystemError(WSAGetLastError());
      }
      return OK;
    }
    case IPAddress::kIPv6AddressSize: {
      if (addr_family_ != AF_INET6) {
        return ERR_ADDRESS_INVALID;
      }
      ipv6_mreq mreq;
      mreq.ipv6mr_interface = multicast_interface_;
      memcpy(&mreq.ipv6mr_multiaddr, group_address.bytes().data(),
             IPAddress::kIPv6AddressSize);
      int rv = setsockopt(socket_, IPPROTO_IPV6, IP_DROP_MEMBERSHIP,
                          reinterpret_cast<const char*>(&mreq), sizeof(mreq));
      if (rv) {
        return MapSystemError(WSAGetLastError());
      }
      return OK;
    }
    default:
      NOTREACHED() << "Invalid address family";
  }
}

int UDPSocketWin::SetMulticastInterface(uint32_t interface_index) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (is_connected()) {
    return ERR_SOCKET_IS_CONNECTED;
  }
  multicast_interface_ = interface_index;
  return OK;
}

int UDPSocketWin::SetMulticastTimeToLive(int time_to_live) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (is_connected()) {
    return ERR_SOCKET_IS_CONNECTED;
  }

  if (time_to_live < 0 || time_to_live > 255) {
    return ERR_INVALID_ARGUMENT;
  }
  multicast_time_to_live_ = time_to_live;
  return OK;
}

int UDPSocketWin::SetMulticastLoopbackMode(bool loopback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (is_connected()) {
    return ERR_SOCKET_IS_CONNECTED;
  }

  if (loopback) {
    socket_options_ |= SOCKET_OPTION_MULTICAST_LOOP;
  } else {
    socket_options_ &= ~SOCKET_OPTION_MULTICAST_LOOP;
  }
  return OK;
}

QOS_TRAFFIC_TYPE DscpToTrafficType(DiffServCodePoint dscp) {
  QOS_TRAFFIC_TYPE traffic_type = QOSTrafficTypeBestEffort;
  switch (dscp) {
    case DSCP_CS0:
      traffic_type = QOSTrafficTypeBestEffort;
      break;
    case DSCP_CS1:
      traffic_type = QOSTrafficTypeBackground;
      break;
    case DSCP_AF11:
    case DSCP_AF12:
    case DSCP_AF13:
    case DSCP_CS2:
    case DSCP_AF21:
    case DSCP_AF22:
    case DSCP_AF23:
    case DSCP_CS3:
    case DSCP_AF31:
    case DSCP_AF32:
    case DSCP_AF33:
    case DSCP_CS4:
      traffic_type = QOSTrafficTypeExcellentEffort;
      break;
    case DSCP_AF41:
    case DSCP_AF42:
    case DSCP_AF43:
    case DSCP_CS5:
      traffic_type = QOSTrafficTypeAudioVideo;
      break;
    case DSCP_EF:
    case DSCP_CS6:
      traffic_type = QOSTrafficTypeVoice;
      break;
    case DSCP_CS7:
      traffic_type = QOSTrafficTypeControl;
      break;
    case DSCP_NO_CHANGE:
      NOTREACHED();
  }
  return traffic_type;
}

int UDPSocketWin::SetDiffServCodePoint(DiffServCodePoint dscp) {
  return SetTos(dscp, ECN_NO_CHANGE);
}

int UDPSocketWin::SetTos(DiffServCodePoint dscp, EcnCodePoint ecn) {
  if (!is_connected()) {
    return ERR_SOCKET_NOT_CONNECTED;
  }

  if (dscp != DSCP_NO_CHANGE) {
    QwaveApi* api = GetQwaveApi();

    if (!api->qwave_supported()) {
      return ERR_NOT_IMPLEMENTED;
    }

    if (!dscp_manager_) {
      dscp_manager_ = std::make_unique<DscpManager>(api, socket_);
    }

    dscp_manager_->Set(dscp);
    if (remote_address_) {
      int rv = dscp_manager_->PrepareForSend(*remote_address_.get());
      if (rv != OK) {
        return rv;
      }
    }
  }
  if (ecn == ECN_NO_CHANGE) {
    return OK;
  }
  if (wsa_send_msg_ == nullptr) {
    wsa_send_msg_ = GetSendMsgPointer();
  }
  send_ecn_ = ecn;
  return OK;
}

int UDPSocketWin::SetIPv6Only(bool ipv6_only) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (is_connected()) {
    return ERR_SOCKET_IS_CONNECTED;
  }
  return net::SetIPv6Only(socket_, ipv6_only);
}

void UDPSocketWin::DetachFromThread() {
  DETACH_FROM_THREAD(thread_checker_);
}

void UDPSocketWin::UseNonBlockingIO() {
  DCHECK(!core_);
  use_non_blocking_io_ = true;
}

void UDPSocketWin::ApplySocketTag(const SocketTag& tag) {
  // Windows does not support any specific SocketTags so fail if any
  // non-default tag is applied.
  CHECK(tag == SocketTag());
}

DscpManager::DscpManager(QwaveApi* api, SOCKET socket)
    : api_(api), socket_(socket) {
  RequestHandle();
}

DscpManager::~DscpManager() {
  if (!qos_handle_) {
    return;
  }

  if (flow_id_ != 0) {
    api_->RemoveSocketFromFlow(qos_handle_, NULL, flow_id_, 0);
  }

  api_->CloseHandle(qos_handle_);
}

void DscpManager::Set(DiffServCodePoint dscp) {
  if (dscp == DSCP_NO_CHANGE || dscp == dscp_value_) {
    return;
  }

  dscp_value_ = dscp;

  // TODO(zstein): We could reuse the flow when the value changes
  // by calling QOSSetFlow with the new traffic type and dscp value.
  if (flow_id_ != 0 && qos_handle_) {
    api_->RemoveSocketFromFlow(qos_handle_, NULL, flow_id_, 0);
    configured_.clear();
    flow_id_ = 0;
  }
}

int DscpManager::PrepareForSend(const IPEndPoint& remote_address) {
  if (dscp_value_ == DSCP_NO_CHANGE) {
    // No DSCP value has been set.
    return OK;
  }

  if (!api_->qwave_supported()) {
    return ERR_NOT_IMPLEMENTED;
  }

  if (!qos_handle_) {
    return ERR_INVALID_HANDLE;  // The closest net error to try again later.
  }

  if (configured_.find(remote_address) != configured_.end()) {
    return OK;
  }

  SockaddrStorage storage;
  if (!remote_address.ToSockAddr(storage.addr, &storage.addr_len)) {
    return ERR_ADDRESS_INVALID;
  }

  // We won't try this address again if we get an error.
  configured_.emplace(remote_address);

  // We don't need to call SetFlow if we already have a qos flow.
  bool new_flow = flow_id_ == 0;

  const QOS_TRAFFIC_TYPE traffic_type = DscpToTrafficType(dscp_value_);

  if (!api_->AddSocketToFlow(qos_handle_, socket_, storage.addr, traffic_type,
                             QOS_NON_ADAPTIVE_FLOW, &flow_id_)) {
    DWORD err = ::GetLastError();
    if (err == ERROR_DEVICE_REINITIALIZATION_NEEDED) {
      // Reset. PrepareForSend is called for every packet.  Once RequestHandle
      // completes asynchronously the next PrepareForSend call will
      // re-register the address with the new QoS Handle.  In the meantime,
      // sends will continue without DSCP.
      RequestHandle();
      configured_.clear();
      flow_id_ = 0;
      return ERR_INVALID_HANDLE;
    }
    return MapSystemError(err);
  }

  if (new_flow) {
    DWORD buf = dscp_value_;
    // This requires admin rights, and may fail, if so we ignore it
    // as AddSocketToFlow should still do *approximately* the right thing.
    api_->SetFlow(qos_handle_, flow_id_, QOSSetOutgoingDSCPValue, sizeof(buf),
                  &buf, 0, nullptr);
  }

  return OK;
}

void DscpManager::RequestHandle() {
  if (handle_is_initializing_) {
    return;
  }

  if (qos_handle_) {
    api_->CloseHandle(qos_handle_);
    qos_handle_ = nullptr;
  }

  handle_is_initializing_ = true;
  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE, {base::MayBlock()},
      base::BindOnce(&DscpManager::DoCreateHandle, api_),
      base::BindOnce(&DscpManager::OnHandleCreated, api_,
                     weak_ptr_factory_.GetWeakPtr()));
}

HANDLE DscpManager::DoCreateHandle(QwaveApi* api) {
  QOS_VERSION version;
  version.MajorVersion = 1;
  version.MinorVersion = 0;

  HANDLE handle = nullptr;

  // No access to net_log_ so swallow any errors here.
  api->CreateHandle(&version, &handle);
  return handle;
}

void DscpManager::OnHandleCreated(QwaveApi* api,
                                  base::WeakPtr<DscpManager> dscp_manager,
                                  HANDLE handle) {
  if (!handle) {
    api->OnFatalError();
  }

  if (!dscp_manager) {
    api->CloseHandle(handle);
    return;
  }

  DCHECK(dscp_manager->handle_is_initializing_);
  DCHECK(!dscp_manager->qos_handle_);

  dscp_manager->qos_handle_ = handle;
  dscp_manager->handle_is_initializing_ = false;
}

}  // namespace net

"""


```