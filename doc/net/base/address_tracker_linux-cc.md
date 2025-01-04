Response:
Let's break down the thought process for analyzing the `address_tracker_linux.cc` file.

**1. Understanding the Goal:**

The request asks for the functionality of the file, its relationship to JavaScript, examples of logical reasoning (input/output), common user errors, and debugging steps to reach this code.

**2. Initial Skim and Keyword Spotting:**

I'd first quickly scan the code, looking for keywords and patterns:

* **Headers:** `linux/if.h`, `sys/ioctl.h`, `AF_NETLINK`, `RTM_NEWADDR`, `RTM_DELLINK`, `RTM_NEWLINK`, `RTM_DELLINK`. These strongly suggest interaction with the Linux network stack at a low level.
* **Class Name:** `AddressTrackerLinux`. This immediately hints at tracking network addresses.
* **Member Variables:** `address_map_`, `online_links_`, `netlink_fd_`, `address_callback_`, `link_callback_`, `tunnel_callback_`. These provide clues about what the class manages and how it communicates.
* **Functions:** `Init()`, `ReadMessages()`, `HandleMessage()`, `GetAddressMap()`, `GetOnlineLinks()`, `UpdateCurrentConnectionType()`. These reveal the core actions of the class.
* **`NETLINK_ROUTE` and `socket(AF_NETLINK, ...)`:**  This confirms the use of Netlink sockets for receiving kernel network events.
* **Callbacks:** The presence of `address_callback_`, `link_callback_`, and `tunnel_callback_` suggests that this class informs other parts of the Chromium network stack about changes.
* **`ioctl()`:**  Indicates direct interaction with device drivers.
* **`base::RepeatingClosure`:**  Reinforces the idea of callbacks.
* **`base::FileDescriptorWatcher`:** Suggests asynchronous monitoring of the Netlink socket.

**3. Inferring Core Functionality:**

Based on the keywords and structure, I'd infer the primary function:

* **Monitoring Network Changes:** The file listens for network interface changes (address additions/removals, link status changes) using Netlink sockets.
* **Maintaining State:** It stores the current network address configuration (`address_map_`) and the status of network links (`online_links_`).
* **Notifying Changes:** It uses callbacks to inform other parts of the system about these changes.

**4. Relationship to JavaScript:**

This is where a bit of domain knowledge is crucial. JavaScript in a browser cannot directly interact with low-level OS network interfaces like Netlink. Therefore, the connection is indirect:

* **Chromium's Architecture:**  Chromium's networking stack is implemented in C++. This C++ code provides the underlying network information.
* **IPC:**  Chromium uses Inter-Process Communication (IPC) to communicate between the browser process (where this C++ code runs) and the renderer processes (where JavaScript executes).
* **Network APIs:** JavaScript interacts with network resources using Web APIs (like `fetch`, `XMLHttpRequest`, WebSockets). These APIs are implemented using the underlying C++ networking stack.

Therefore, the relationship is that this C++ code *provides the data* that eventually influences the behavior of network-related JavaScript APIs.

**5. Logical Reasoning (Input/Output):**

To illustrate logical reasoning, I'd pick a core function like `HandleMessage()` and consider a specific message type:

* **Input (Hypothetical):** A Netlink message of type `RTM_NEWADDR` arrives, indicating a new IP address has been assigned to a network interface. The message contains the IP address and interface index.
* **Processing:** The code parses the message, extracts the IP address and interface index, checks if the interface is ignored, and then updates the `address_map_`.
* **Output:** The `address_map_` is updated to include the new IP address. If `tracking_` is enabled, a diff is recorded, and the `address_callback_` might be triggered.

**6. Common User/Programming Errors:**

Here, I'd think about common pitfalls when dealing with network monitoring or using this type of code (if it were exposed more directly, which it isn't to typical users):

* **Incorrect Interface Ignoring:**  Users might try to ignore an interface using the wrong name.
* **Resource Leaks:**  If the Netlink socket isn't closed properly in error scenarios (though the code seems to handle this well with RAII via `base::ScopedFD`).
* **Blocking Issues:**  If the `ReadMessages()` loop were to block indefinitely (though `MSG_DONTWAIT` is used after the initial read).

**7. Debugging Steps:**

To trace how execution reaches this code, I'd outline a typical network operation:

1. **User Action:** User navigates to a website in the browser.
2. **JavaScript API Call:** The browser uses a JavaScript API (e.g., `fetch`) to request a resource.
3. **C++ Network Request:** The JavaScript call triggers a corresponding C++ network request.
4. **Network Stack Involvement:**  Chromium's network stack needs to know the current network configuration.
5. **AddressTrackerLinux Initialization:** `AddressTrackerLinux::Init()` is called during Chromium startup.
6. **Netlink Monitoring:** The class starts listening for Netlink messages.
7. **Network Change:**  The operating system signals a network change (e.g., a new IP address is assigned).
8. **Netlink Message Received:** The `netlink_fd_` receives the message.
9. **`OnFileCanReadWithoutBlocking()`:** The file descriptor watcher detects readability and calls this function.
10. **`ReadMessages()` and `HandleMessage()`:**  The Netlink message is processed, and the internal state is updated.
11. **Callbacks:**  If necessary, the `address_callback_`, `link_callback_`, or `tunnel_callback_` are invoked, potentially triggering further actions within the Chromium network stack.

**8. Refining and Structuring the Answer:**

Finally, I'd organize the information logically, using clear headings and examples, as demonstrated in the provided good answer. I'd ensure that all parts of the original request are addressed. I'd also pay attention to code comments and the overall structure of the C++ code to provide accurate details.
好的，让我们来详细分析一下 `net/base/address_tracker_linux.cc` 这个文件。

**功能概述:**

`address_tracker_linux.cc` 文件的核心功能是**监控 Linux 系统上的网络地址和链路状态的变化**。它通过以下方式实现：

1. **使用 Netlink Socket:**  它创建一个 `AF_NETLINK` 类型的 socket，并绑定到 `NETLINK_ROUTE` 协议族。Netlink 是一种 Linux 内核与用户空间进程通信的机制，`NETLINK_ROUTE` 专门用于接收路由和链路相关的通知。
2. **监听 Netlink 消息:**  通过 `recv()` 系统调用监听 Netlink socket 上接收到的消息。这些消息包含了网络接口地址的添加、删除以及链路状态（例如，接口上线、下线）的变化。
3. **解析 Netlink 消息:**  接收到的 Netlink 消息需要被解析，以提取出有用的信息，例如：
    * 接口索引 (`ifi_index`)
    * IP 地址 (`IFA_ADDRESS`, `IFA_LOCAL`)
    * 地址族 (`ifa_family`)
    * 接口标志 (`ifi_flags`)，例如 `IFF_UP` (接口已启动), `IFF_LOWER_UP` (物理链路已连接), `IFF_RUNNING` (接口正在运行)
4. **维护内部状态:**  文件内部维护了两个主要的映射：
    * `address_map_`:  存储当前系统上所有网络接口的 IP 地址信息。键是 `IPAddress` 对象，值是 `ifaddrmsg` 结构体，包含了地址的详细信息（例如，是否被废弃）。
    * `online_links_`:  存储当前处于 "上线" 状态的网络接口的索引。
5. **提供回调机制:**  当网络地址或链路状态发生变化时，它会触发预先注册的回调函数 (`address_callback_`, `link_callback_`, `tunnel_callback_`)，通知 Chromium 网络栈的其他部分。
6. **忽略特定接口:**  它允许配置需要忽略的网络接口，这些接口的变化不会触发回调。
7. **获取当前连接类型:**  通过分析当前的 IP 地址和链路状态，可以推断出当前的连接类型 (例如，NONE, WIFI, ETHERNET, UNKNOWN)。

**与 JavaScript 的关系:**

`address_tracker_linux.cc` 本身是用 C++ 编写的，与 JavaScript 没有直接的代码级别的交互。然而，它提供的底层网络状态信息对于浏览器中运行的 JavaScript 代码至关重要。

**举例说明:**

* **JavaScript 获取网络连接状态:**  当网页中的 JavaScript 代码使用 `navigator.onLine` API 或通过尝试建立网络连接来检查网络状态时，浏览器底层的 C++ 网络栈会查询 `AddressTrackerLinux` 维护的状态。如果 `AddressTrackerLinux` 检测到网络连接断开（例如，通过 `RTM_DELLINK` 消息），它会更新内部状态，Chromium 的其他部分会捕获到这个变化，并最终影响 `navigator.onLine` 的返回值。
* **JavaScript 发起网络请求:**  当 JavaScript 使用 `fetch` 或 `XMLHttpRequest` 发起网络请求时，Chromium 的网络栈需要知道可用的网络接口和分配的 IP 地址。`AddressTrackerLinux` 提供的信息用于选择合适的网络接口进行连接。例如，如果系统同时连接了 Wi-Fi 和有线网络，`AddressTrackerLinux` 提供的 IP 地址信息可以帮助确定使用哪个接口。
* **WebRTC:** 在 WebRTC 应用中，JavaScript 需要获取本地设备的 IP 地址用于建立 P2P 连接。Chromium 会调用 C++ 代码来获取这些信息，而 `AddressTrackerLinux` 是提供这些信息的重要来源。

**逻辑推理和假设输入/输出:**

假设输入一个 `RTM_NEWADDR` 类型的 Netlink 消息，指示一个名为 `eth0` 的接口分配了一个新的 IPv4 地址 `192.168.1.100`。

**假设输入:** 一个包含以下数据的 Netlink 消息 (简化表示):

```
nlmsg_type: RTM_NEWADDR
ifi_index:  指向 eth0 接口的索引 (假设为 2)
ifa_family: AF_INET
IFA_ADDRESS: 192.168.1.100 (原始字节)
```

**逻辑推理过程:**

1. `AddressTrackerLinux` 的 `ReadMessages()` 函数接收到这个 Netlink 消息。
2. `HandleMessage()` 函数根据 `nlmsg_type` 判断这是一个新的地址通知。
3. 它会提取出接口索引 `2` 和 IP 地址 `192.168.1.100`。
4. 它会检查接口索引 `2` (对应 `eth0`) 是否在 `ignored_interfaces_` 中。假设不在。
5. 它会尝试从 Netlink 消息中解析出 IP 地址，并创建一个 `IPAddress` 对象。
6. 它会获取 `address_map_` 的锁。
7. 它会在 `address_map_` 中查找是否存在 `192.168.1.100` 这个地址。
8. 如果不存在，它会将 `192.168.1.100` 和相关的 `ifaddrmsg` 信息添加到 `address_map_` 中。
9. 它会设置 `address_changed` 为 `true`。
10. 如果 `tracking_` 为 `true` 并且设置了 `diff_callback_`，它会将这个变化记录到 `address_map_diff_` 中。
11. 释放 `address_map_` 的锁。
12. 在 `ReadMessages()` 返回后，如果 `address_changed` 为 `true`，它会调用 `address_callback_`。

**假设输出:**

* `address_map_` 中会新增或更新一个条目，键为 `IPAddress("192.168.1.100")`，值为包含该地址信息的 `ifaddrmsg` 结构体。
* `address_changed` 变量会被设置为 `true`。
* 如果注册了 `address_callback_`，该回调函数会被执行。

**用户或编程常见的使用错误:**

由于 `AddressTrackerLinux` 是 Chromium 内部的组件，普通用户无法直接与其交互。编程错误主要发生在 Chromium 的开发过程中：

1. **忘记注册回调函数:**  如果 Chromium 的某个模块需要监听网络地址变化，但忘记注册 `address_callback_`，那么它将无法接收到通知。
2. **错误地处理回调:**  即使注册了回调，如果回调函数的实现有误，例如，没有正确地更新自身的状态，可能会导致 Chromium 的行为不正确。
3. **忽略了某些 Netlink 消息类型:**  如果代码只处理了 `RTM_NEWADDR` 和 `RTM_DELADDR`，而忽略了其他重要的消息类型（例如，与路由变化相关的消息），可能会导致网络状态跟踪不完整。
4. **在错误的线程访问内部状态:**  `address_map_` 和 `online_links_` 受锁保护。如果在没有获取锁的情况下，在非预期线程访问这些数据，可能会导致数据竞争和崩溃。
5. **没有正确处理接口忽略逻辑:**  如果 `ignored_interfaces_` 的配置不正确，可能会导致本应被忽略的接口变化被错误地处理，或者反之。
6. **假设网络状态变化会立即反映:**  网络状态的变化可能需要一些时间才能被内核检测到并通过 Netlink 发送通知。代码需要考虑到这种延迟。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在 Chrome 浏览器中访问一个需要建立 WebSocket 连接的网站。

1. **用户在地址栏输入网址并回车。**
2. **Chrome 的 UI 进程接收到用户的请求。**
3. **UI 进程指示渲染器进程加载网页。**
4. **网页中的 JavaScript 代码尝试创建一个 WebSocket 连接。**
5. **渲染器进程将 WebSocket 连接请求发送给浏览器进程的网络服务 (Network Service)。**
6. **网络服务需要确定本地的网络配置信息。**
7. **网络服务会使用 `AddressTrackerLinux` 来获取当前的 IP 地址和链路状态。**  如果 `AddressTrackerLinux` 尚未初始化，它会被初始化。
8. **`AddressTrackerLinux` 初始化时，会创建 Netlink socket 并开始监听消息。**
9. **如果用户的网络配置发生变化（例如，连接了新的 Wi-Fi 网络），Linux 内核会通过 Netlink socket 发送相应的消息（例如，`RTM_NEWADDR`, `RTM_NEWLINK`）。**
10. **`AddressTrackerLinux` 的 `ReadMessages()` 函数接收并处理这些消息，更新 `address_map_` 和 `online_links_`。**
11. **当网络服务查询本地 IP 地址时，`AddressTrackerLinux` 会从 `address_map_` 中提供最新的信息。**
12. **网络服务使用这些信息来建立 WebSocket 连接。**

**调试线索:**

* **抓取 Netlink 消息:** 可以使用 `tcpdump` 或 `wireshark` 等工具抓取 Netlink 消息，查看内核发送了哪些网络状态变化通知。这可以帮助验证内核是否正确地检测到了网络变化。
* **查看 Chrome 的内部网络状态:** Chrome 提供了 `chrome://net-internals/#events` 和 `chrome://net-internals/#sockets` 等页面，可以查看实时的网络事件和 socket 连接状态，这可以帮助了解 Chromium 如何响应网络状态的变化。
* **在 `AddressTrackerLinux` 中添加日志:**  可以在 `HandleMessage()` 函数中添加 `LOG()` 语句，打印接收到的 Netlink 消息类型、接口索引、IP 地址等信息，以便跟踪消息的处理过程。
* **断点调试:**  可以在 `ReadMessages()` 和 `HandleMessage()` 等关键函数中设置断点，逐步执行代码，查看内部状态的变化。
* **检查回调函数的执行:**  在 `address_callback_` 和 `link_callback_` 等回调函数中添加日志，确认它们是否在网络状态变化时被正确地调用。

总而言之，`address_tracker_linux.cc` 是 Chromium 在 Linux 系统上感知网络环境变化的关键组件，它通过监听底层的 Netlink 消息，维护网络状态信息，并提供回调机制，使得 Chromium 的其他部分能够及时响应网络配置的改变。虽然 JavaScript 代码不能直接调用它，但其提供的底层信息直接影响着浏览器中网络相关 JavaScript API 的行为。

Prompt: 
```
这是目录为net/base/address_tracker_linux.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/base/address_tracker_linux.h"

#include <errno.h>
#include <linux/if.h>
#include <stdint.h>
#include <sys/ioctl.h>

#include <optional>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/dcheck_is_on.h"
#include "base/files/scoped_file.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/memory/page_size.h"
#include "base/posix/eintr_wrapper.h"
#include "base/sequence_checker.h"
#include "base/task/current_thread.h"
#include "base/threading/scoped_blocking_call.h"
#include "base/threading/thread_restrictions.h"
#include "build/build_config.h"
#include "net/base/network_interfaces_linux.h"

#if BUILDFLAG(IS_ANDROID)
#include "base/android/build_info.h"
#endif

namespace net::internal {

namespace {

// Some kernel functions such as wireless_send_event and rtnetlink_ifinfo_prep
// may send spurious messages over rtnetlink. RTM_NEWLINK messages where
// ifi_change == 0 and rta_type == IFLA_WIRELESS should be ignored.
bool IgnoreWirelessChange(const struct ifinfomsg* msg, int length) {
  for (const struct rtattr* attr = IFLA_RTA(msg); RTA_OK(attr, length);
       attr = RTA_NEXT(attr, length)) {
    if (attr->rta_type == IFLA_WIRELESS && msg->ifi_change == 0)
      return true;
  }
  return false;
}

// Retrieves address from NETLINK address message.
// Sets |really_deprecated| for IPv6 addresses with preferred lifetimes of 0.
// Precondition: |header| must already be validated with NLMSG_OK.
bool GetAddress(const struct nlmsghdr* header,
                int header_length,
                IPAddress* out,
                bool* really_deprecated) {
  if (really_deprecated)
    *really_deprecated = false;

  // Extract the message and update |header_length| to be the number of
  // remaining bytes.
  const struct ifaddrmsg* msg =
      reinterpret_cast<const struct ifaddrmsg*>(NLMSG_DATA(header));
  header_length -= NLMSG_HDRLEN;

  size_t address_length = 0;
  switch (msg->ifa_family) {
    case AF_INET:
      address_length = IPAddress::kIPv4AddressSize;
      break;
    case AF_INET6:
      address_length = IPAddress::kIPv6AddressSize;
      break;
    default:
      // Unknown family.
      return false;
  }
  // Use IFA_ADDRESS unless IFA_LOCAL is present. This behavior here is based on
  // getaddrinfo in glibc (check_pf.c). Judging from kernel implementation of
  // NETLINK, IPv4 addresses have only the IFA_ADDRESS attribute, while IPv6
  // have the IFA_LOCAL attribute.
  uint8_t* address = nullptr;
  uint8_t* local = nullptr;
  int length = IFA_PAYLOAD(header);
  if (length > header_length) {
    LOG(ERROR) << "ifaddrmsg length exceeds bounds";
    return false;
  }
  for (const struct rtattr* attr =
           reinterpret_cast<const struct rtattr*>(IFA_RTA(msg));
       RTA_OK(attr, length); attr = RTA_NEXT(attr, length)) {
    switch (attr->rta_type) {
      case IFA_ADDRESS:
        if (RTA_PAYLOAD(attr) < address_length) {
          LOG(ERROR) << "attr does not have enough bytes to read an address";
          return false;
        }
        address = reinterpret_cast<uint8_t*>(RTA_DATA(attr));
        break;
      case IFA_LOCAL:
        if (RTA_PAYLOAD(attr) < address_length) {
          LOG(ERROR) << "attr does not have enough bytes to read an address";
          return false;
        }
        local = reinterpret_cast<uint8_t*>(RTA_DATA(attr));
        break;
      case IFA_CACHEINFO: {
        if (RTA_PAYLOAD(attr) < sizeof(struct ifa_cacheinfo)) {
          LOG(ERROR)
              << "attr does not have enough bytes to read an ifa_cacheinfo";
          return false;
        }
        const struct ifa_cacheinfo* cache_info =
            reinterpret_cast<const struct ifa_cacheinfo*>(RTA_DATA(attr));
        if (really_deprecated)
          *really_deprecated = (cache_info->ifa_prefered == 0);
      } break;
      default:
        break;
    }
  }
  if (local)
    address = local;
  if (!address)
    return false;
  // SAFETY: `address` is only set above after `RTA_PAYLOAD` is checked against
  // `address_length`.
  *out = IPAddress(UNSAFE_BUFFERS(base::span(address, address_length)));
  return true;
}

// SafelyCastNetlinkMsgData<T> performs a bounds check before casting |header|'s
// data to a |T*|. When the bounds check fails, returns nullptr.
template <typename T>
T* SafelyCastNetlinkMsgData(const struct nlmsghdr* header, int length) {
  DCHECK(NLMSG_OK(header, static_cast<__u32>(length)));
  if (length <= 0 || static_cast<size_t>(length) < NLMSG_HDRLEN + sizeof(T))
    return nullptr;
  return reinterpret_cast<const T*>(NLMSG_DATA(header));
}

}  // namespace

// static
char* AddressTrackerLinux::GetInterfaceName(int interface_index, char* buf) {
  memset(buf, 0, IFNAMSIZ);
  base::ScopedFD ioctl_socket = GetSocketForIoctl();
  if (!ioctl_socket.is_valid())
    return buf;

  struct ifreq ifr = {};
  ifr.ifr_ifindex = interface_index;

  if (ioctl(ioctl_socket.get(), SIOCGIFNAME, &ifr) == 0)
    strncpy(buf, ifr.ifr_name, IFNAMSIZ - 1);
  return buf;
}

AddressTrackerLinux::AddressTrackerLinux()
    : get_interface_name_(GetInterfaceName),
      address_callback_(base::DoNothing()),
      link_callback_(base::DoNothing()),
      tunnel_callback_(base::DoNothing()),
      ignored_interfaces_(),
      connection_type_initialized_cv_(&connection_type_lock_),
      tracking_(false) {}

AddressTrackerLinux::AddressTrackerLinux(
    const base::RepeatingClosure& address_callback,
    const base::RepeatingClosure& link_callback,
    const base::RepeatingClosure& tunnel_callback,
    const std::unordered_set<std::string>& ignored_interfaces,
    scoped_refptr<base::SequencedTaskRunner> blocking_thread_runner)
    : get_interface_name_(GetInterfaceName),
      address_callback_(address_callback),
      link_callback_(link_callback),
      tunnel_callback_(tunnel_callback),
      ignored_interfaces_(ignored_interfaces),
      connection_type_initialized_cv_(&connection_type_lock_),
      tracking_(true),
      sequenced_task_runner_(std::move(blocking_thread_runner)) {
  DCHECK(!address_callback.is_null());
  DCHECK(!link_callback.is_null());
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

AddressTrackerLinux::~AddressTrackerLinux() = default;

void AddressTrackerLinux::InitWithFdForTesting(base::ScopedFD fd) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  netlink_fd_ = std::move(fd);
  DumpInitialAddressesAndWatch();
}

void AddressTrackerLinux::Init() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
#if BUILDFLAG(IS_ANDROID)
  // RTM_GETLINK stopped working in Android 11 (see
  // https://developer.android.com/preview/privacy/mac-address),
  // so AddressTrackerLinux should not be used in later versions
  // of Android.  Chromium code doesn't need it past Android P.
  DCHECK_LT(base::android::BuildInfo::GetInstance()->sdk_int(),
            base::android::SDK_VERSION_P);
#endif
  netlink_fd_.reset(socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE));
  if (!netlink_fd_.is_valid()) {
    PLOG(ERROR) << "Could not create NETLINK socket";
    AbortAndForceOnline();
    return;
  }

  int rv;

  if (tracking_) {
    // Request notifications.
    struct sockaddr_nl addr = {};
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = 0;  // Let the kernel select a unique value.
    // TODO(szym): Track RTMGRP_LINK as well for ifi_type,
    // http://crbug.com/113993
    addr.nl_groups =
        RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_NOTIFY | RTMGRP_LINK;
    rv = bind(netlink_fd_.get(), reinterpret_cast<struct sockaddr*>(&addr),
              sizeof(addr));
    if (rv < 0) {
      PLOG(ERROR) << "Could not bind NETLINK socket";
      AbortAndForceOnline();
      return;
    }
  }

  DumpInitialAddressesAndWatch();
}

bool AddressTrackerLinux::DidTrackingInitSucceedForTesting() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(tracking_);
  return watcher_ != nullptr;
}

void AddressTrackerLinux::AbortAndForceOnline() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  watcher_.reset();
  netlink_fd_.reset();
  AddressTrackerAutoLock lock(*this, connection_type_lock_);
  current_connection_type_ = NetworkChangeNotifier::CONNECTION_UNKNOWN;
  connection_type_initialized_ = true;
  connection_type_initialized_cv_.Broadcast();
}

AddressTrackerLinux::AddressMap AddressTrackerLinux::GetAddressMap() const {
  AddressTrackerAutoLock lock(*this, address_map_lock_);
  return address_map_;
}

std::unordered_set<int> AddressTrackerLinux::GetOnlineLinks() const {
  AddressTrackerAutoLock lock(*this, online_links_lock_);
  return online_links_;
}

AddressTrackerLinux* AddressTrackerLinux::GetAddressTrackerLinux() {
  return this;
}

std::pair<AddressTrackerLinux::AddressMap, std::unordered_set<int>>
AddressTrackerLinux::GetInitialDataAndStartRecordingDiffs() {
  DCHECK(tracking_);
  AddressTrackerAutoLock lock_address_map(*this, address_map_lock_);
  AddressTrackerAutoLock lock_online_links(*this, online_links_lock_);
  address_map_diff_ = AddressMapDiff();
  online_links_diff_ = OnlineLinksDiff();
  return {address_map_, online_links_};
}

void AddressTrackerLinux::SetDiffCallback(DiffCallback diff_callback) {
  DCHECK(tracking_);
  DCHECK(sequenced_task_runner_);

  if (!sequenced_task_runner_->RunsTasksInCurrentSequence()) {
    sequenced_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&AddressTrackerLinux::SetDiffCallback,
                                  weak_ptr_factory_.GetWeakPtr(),
                                  std::move(diff_callback)));
    return;
  }

  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
#if DCHECK_IS_ON()
  {
    // GetInitialDataAndStartRecordingDiffs() must be called before
    // SetDiffCallback().
    AddressTrackerAutoLock lock_address_map(*this, address_map_lock_);
    AddressTrackerAutoLock lock_online_links(*this, online_links_lock_);
    DCHECK(address_map_diff_.has_value());
    DCHECK(online_links_diff_.has_value());
  }
#endif  // DCHECK_IS_ON()
  diff_callback_ = std::move(diff_callback);
  RunDiffCallback();
}

bool AddressTrackerLinux::IsInterfaceIgnored(int interface_index) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (ignored_interfaces_.empty())
    return false;

  char buf[IFNAMSIZ] = {0};
  const char* interface_name = get_interface_name_(interface_index, buf);
  return ignored_interfaces_.find(interface_name) != ignored_interfaces_.end();
}

NetworkChangeNotifier::ConnectionType
AddressTrackerLinux::GetCurrentConnectionType() {
  // http://crbug.com/125097
  base::ScopedAllowBaseSyncPrimitivesOutsideBlockingScope allow_wait;
  AddressTrackerAutoLock lock(*this, connection_type_lock_);
  // Make sure the initial connection type is set before returning.
  threads_waiting_for_connection_type_initialization_++;
  while (!connection_type_initialized_) {
    connection_type_initialized_cv_.Wait();
  }
  threads_waiting_for_connection_type_initialization_--;
  return current_connection_type_;
}

void AddressTrackerLinux::DumpInitialAddressesAndWatch() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Request dump of addresses.
  struct sockaddr_nl peer = {};
  peer.nl_family = AF_NETLINK;

  struct {
    struct nlmsghdr header;
    struct rtgenmsg msg;
  } request = {};

  request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.msg));
  request.header.nlmsg_type = RTM_GETADDR;
  request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  request.header.nlmsg_pid = 0;  // This field is opaque to netlink.
  request.msg.rtgen_family = AF_UNSPEC;

  int rv = HANDLE_EINTR(
      sendto(netlink_fd_.get(), &request, request.header.nlmsg_len, 0,
             reinterpret_cast<struct sockaddr*>(&peer), sizeof(peer)));
  if (rv < 0) {
    PLOG(ERROR) << "Could not send NETLINK request";
    AbortAndForceOnline();
    return;
  }

  // Consume pending message to populate the AddressMap, but don't notify.
  // Sending another request without first reading responses results in EBUSY.
  bool address_changed;
  bool link_changed;
  bool tunnel_changed;
  ReadMessages(&address_changed, &link_changed, &tunnel_changed);

  // Request dump of link state
  request.header.nlmsg_type = RTM_GETLINK;

  rv = HANDLE_EINTR(
      sendto(netlink_fd_.get(), &request, request.header.nlmsg_len, 0,
             reinterpret_cast<struct sockaddr*>(&peer), sizeof(peer)));
  if (rv < 0) {
    PLOG(ERROR) << "Could not send NETLINK request";
    AbortAndForceOnline();
    return;
  }

  // Consume pending message to populate links_online_, but don't notify.
  ReadMessages(&address_changed, &link_changed, &tunnel_changed);
  {
    AddressTrackerAutoLock lock(*this, connection_type_lock_);
    connection_type_initialized_ = true;
    connection_type_initialized_cv_.Broadcast();
  }

  if (tracking_) {
    DCHECK(!sequenced_task_runner_ ||
           sequenced_task_runner_->RunsTasksInCurrentSequence());

    watcher_ = base::FileDescriptorWatcher::WatchReadable(
        netlink_fd_.get(),
        base::BindRepeating(&AddressTrackerLinux::OnFileCanReadWithoutBlocking,
                            base::Unretained(this)));
  }
}

void AddressTrackerLinux::ReadMessages(bool* address_changed,
                                       bool* link_changed,
                                       bool* tunnel_changed) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  *address_changed = false;
  *link_changed = false;
  *tunnel_changed = false;
  bool first_loop = true;

  // Varying sources have different opinions regarding the buffer size needed
  // for netlink messages to avoid truncation:
  // - The official documentation on netlink says messages are generally 8kb
  //   or the system page size, whichever is *larger*:
  //   https://www.kernel.org/doc/html/v6.2/userspace-api/netlink/intro.html#buffer-sizing
  // - The kernel headers would imply that messages are generally the system
  //   page size or 8kb, whichever is *smaller*:
  //   https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/linux/netlink.h?h=v6.2.2#n226
  //   (libmnl follows this.)
  // - The netlink(7) man page's example always uses a fixed size 8kb buffer:
  //   https://man7.org/linux/man-pages/man7/netlink.7.html
  // Here, we follow the guidelines in the documentation, for two primary
  // reasons:
  // - Erring on the side of a larger size is the safer way to go to avoid
  //   MSG_TRUNC.
  // - Since this is heap-allocated anyway, there's no risk to the stack by
  //   using the larger size.

  constexpr size_t kMinNetlinkBufferSize = 8 * 1024;
  std::vector<char> buffer(
      std::max(base::GetPageSize(), kMinNetlinkBufferSize));

  {
    std::optional<base::ScopedBlockingCall> blocking_call;
    if (tracking_) {
      // If the loop below takes a long time to run, a new thread should added
      // to the current thread pool to ensure forward progress of all tasks.
      blocking_call.emplace(FROM_HERE, base::BlockingType::MAY_BLOCK);
    }

    for (;;) {
      int rv =
          HANDLE_EINTR(recv(netlink_fd_.get(), buffer.data(), buffer.size(),
                            // Block the first time through loop.
                            first_loop ? 0 : MSG_DONTWAIT));
      first_loop = false;
      if (rv == 0) {
        LOG(ERROR) << "Unexpected shutdown of NETLINK socket.";
        return;
      }
      if (rv < 0) {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
          break;
        PLOG(ERROR) << "Failed to recv from netlink socket";
        return;
      }
      HandleMessage(buffer.data(), rv, address_changed, link_changed,
                    tunnel_changed);
    }
  }
  if (*link_changed || *address_changed)
    UpdateCurrentConnectionType();
}

void AddressTrackerLinux::HandleMessage(const char* buffer,
                                        int length,
                                        bool* address_changed,
                                        bool* link_changed,
                                        bool* tunnel_changed) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(buffer);
  // Note that NLMSG_NEXT decrements |length| to reflect the number of bytes
  // remaining in |buffer|.
  for (const struct nlmsghdr* header =
           reinterpret_cast<const struct nlmsghdr*>(buffer);
       length >= 0 && NLMSG_OK(header, static_cast<__u32>(length));
       header = NLMSG_NEXT(header, length)) {
    // The |header| pointer should never precede |buffer|.
    DCHECK_LE(buffer, reinterpret_cast<const char*>(header));
    switch (header->nlmsg_type) {
      case NLMSG_DONE:
        return;
      case NLMSG_ERROR: {
        const struct nlmsgerr* msg =
            SafelyCastNetlinkMsgData<const struct nlmsgerr>(header, length);
        if (msg == nullptr)
          return;
        LOG(ERROR) << "Unexpected netlink error " << msg->error << ".";
      } return;
      case RTM_NEWADDR: {
        IPAddress address;
        bool really_deprecated;
        const struct ifaddrmsg* msg =
            SafelyCastNetlinkMsgData<const struct ifaddrmsg>(header, length);
        if (msg == nullptr)
          return;
        if (IsInterfaceIgnored(msg->ifa_index))
          break;
        if (GetAddress(header, length, &address, &really_deprecated)) {
          struct ifaddrmsg msg_copy = *msg;
          AddressTrackerAutoLock lock(*this, address_map_lock_);
          // Routers may frequently (every few seconds) output the IPv6 ULA
          // prefix which can cause the linux kernel to frequently output two
          // back-to-back messages, one without the deprecated flag and one with
          // the deprecated flag but both with preferred lifetimes of 0. Avoid
          // interpreting this as an actual change by canonicalizing the two
          // messages by setting the deprecated flag based on the preferred
          // lifetime also.  http://crbug.com/268042
          if (really_deprecated)
            msg_copy.ifa_flags |= IFA_F_DEPRECATED;
          // Only indicate change if the address is new or ifaddrmsg info has
          // changed.
          auto it = address_map_.find(address);
          if (it == address_map_.end()) {
            address_map_.insert(it, std::pair(address, msg_copy));
            *address_changed = true;
          } else if (memcmp(&it->second, &msg_copy, sizeof(msg_copy))) {
            it->second = msg_copy;
            *address_changed = true;
          }
          if (*address_changed && address_map_diff_.has_value()) {
            (*address_map_diff_)[address] = msg_copy;
          }
        }
      } break;
      case RTM_DELADDR: {
        IPAddress address;
        const struct ifaddrmsg* msg =
            SafelyCastNetlinkMsgData<const struct ifaddrmsg>(header, length);
        if (msg == nullptr)
          return;
        if (IsInterfaceIgnored(msg->ifa_index))
          break;
        if (GetAddress(header, length, &address, nullptr)) {
          AddressTrackerAutoLock lock(*this, address_map_lock_);
          if (address_map_.erase(address)) {
            *address_changed = true;
            if (address_map_diff_.has_value()) {
              (*address_map_diff_)[address] = std::nullopt;
            }
          }
        }
      } break;
      case RTM_NEWLINK: {
        const struct ifinfomsg* msg =
            SafelyCastNetlinkMsgData<const struct ifinfomsg>(header, length);
        if (msg == nullptr)
          return;
        if (IsInterfaceIgnored(msg->ifi_index))
          break;
        if (IgnoreWirelessChange(msg, IFLA_PAYLOAD(header))) {
          VLOG(2) << "Ignoring RTM_NEWLINK message";
          break;
        }
        if (!(msg->ifi_flags & IFF_LOOPBACK) && (msg->ifi_flags & IFF_UP) &&
            (msg->ifi_flags & IFF_LOWER_UP) && (msg->ifi_flags & IFF_RUNNING)) {
          AddressTrackerAutoLock lock(*this, online_links_lock_);
          if (online_links_.insert(msg->ifi_index).second) {
            *link_changed = true;
            if (online_links_diff_.has_value()) {
              (*online_links_diff_)[msg->ifi_index] = true;
            }
            if (IsTunnelInterface(msg->ifi_index))
              *tunnel_changed = true;
          }
        } else {
          AddressTrackerAutoLock lock(*this, online_links_lock_);
          if (online_links_.erase(msg->ifi_index)) {
            *link_changed = true;
            if (online_links_diff_.has_value()) {
              (*online_links_diff_)[msg->ifi_index] = false;
            }
            if (IsTunnelInterface(msg->ifi_index))
              *tunnel_changed = true;
          }
        }
      } break;
      case RTM_DELLINK: {
        const struct ifinfomsg* msg =
            SafelyCastNetlinkMsgData<const struct ifinfomsg>(header, length);
        if (msg == nullptr)
          return;
        if (IsInterfaceIgnored(msg->ifi_index))
          break;
        AddressTrackerAutoLock lock(*this, online_links_lock_);
        if (online_links_.erase(msg->ifi_index)) {
          *link_changed = true;
          if (online_links_diff_.has_value()) {
            (*online_links_diff_)[msg->ifi_index] = false;
          }
          if (IsTunnelInterface(msg->ifi_index))
            *tunnel_changed = true;
        }
      } break;
      default:
        break;
    }
  }
}

void AddressTrackerLinux::OnFileCanReadWithoutBlocking() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  bool address_changed;
  bool link_changed;
  bool tunnel_changed;
  ReadMessages(&address_changed, &link_changed, &tunnel_changed);
  if (diff_callback_) {
    RunDiffCallback();
  }
  if (address_changed) {
    address_callback_.Run();
  }
  if (link_changed) {
    link_callback_.Run();
  }
  if (tunnel_changed) {
    tunnel_callback_.Run();
  }
}

bool AddressTrackerLinux::IsTunnelInterface(int interface_index) const {
  char buf[IFNAMSIZ] = {0};
  return IsTunnelInterfaceName(get_interface_name_(interface_index, buf));
}

// static
bool AddressTrackerLinux::IsTunnelInterfaceName(const char* name) {
  // Linux kernel drivers/net/tun.c uses "tun" name prefix.
  return strncmp(name, "tun", 3) == 0;
}

void AddressTrackerLinux::UpdateCurrentConnectionType() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AddressTrackerLinux::AddressMap address_map = GetAddressMap();
  std::unordered_set<int> online_links = GetOnlineLinks();

  // Strip out tunnel interfaces from online_links
  for (auto it = online_links.cbegin(); it != online_links.cend();) {
    if (IsTunnelInterface(*it)) {
      it = online_links.erase(it);
    } else {
      ++it;
    }
  }

  NetworkInterfaceList networks;
  NetworkChangeNotifier::ConnectionType type =
      NetworkChangeNotifier::CONNECTION_NONE;
  if (GetNetworkListImpl(&networks, 0, online_links, address_map,
                         get_interface_name_)) {
    type = NetworkChangeNotifier::ConnectionTypeFromInterfaceList(networks);
  } else {
    type = online_links.empty() ? NetworkChangeNotifier::CONNECTION_NONE
                                : NetworkChangeNotifier::CONNECTION_UNKNOWN;
  }

  AddressTrackerAutoLock lock(*this, connection_type_lock_);
  current_connection_type_ = type;
}

void AddressTrackerLinux::RunDiffCallback() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(tracking_);
  DCHECK(address_map_diff_.has_value());
  DCHECK(online_links_diff_.has_value());
  // It's fine to access `address_map_diff_` and `online_links_diff_` without
  // any locking here, as the only time they are ever accessed on another thread
  // is in GetInitialDataAndStartRecordingDiffs(). But
  // GetInitialDataAndStartRecordingDiffs() must be called before
  // SetDiffCallback(), which must be called before RunDiffCallback(), so this
  // function cannot overlap with any modifications on another thread.

  // There should be a diff or the DiffCallback shouldn't be run.
  if (address_map_diff_->empty() && online_links_diff_->empty()) {
    return;
  }
  diff_callback_.Run(address_map_diff_.value(), online_links_diff_.value());
  address_map_diff_->clear();
  online_links_diff_->clear();
}

int AddressTrackerLinux::GetThreadsWaitingForConnectionTypeInitForTesting() {
  AddressTrackerAutoLock lock(*this, connection_type_lock_);
  return threads_waiting_for_connection_type_initialization_;
}

AddressTrackerLinux::AddressTrackerAutoLock::AddressTrackerAutoLock(
    const AddressTrackerLinux& tracker,
    base::Lock& lock)
    : tracker_(tracker), lock_(lock) {
  if (tracker_->tracking_) {
    lock_->Acquire();
  } else {
    DCHECK_CALLED_ON_VALID_SEQUENCE(tracker_->sequence_checker_);
  }
}

AddressTrackerLinux::AddressTrackerAutoLock::~AddressTrackerAutoLock() {
  if (tracker_->tracking_) {
    lock_->AssertAcquired();
    lock_->Release();
  } else {
    DCHECK_CALLED_ON_VALID_SEQUENCE(tracker_->sequence_checker_);
  }
}

}  // namespace net::internal

"""

```