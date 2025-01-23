Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Core Task:**

The primary goal is to understand the functionality of `mdns_client_impl.cc` within the Chromium networking stack, specifically focusing on:

* **Core Functionality:** What does this code *do*?
* **JavaScript Relationship:** How does it interact with the JavaScript side of a web browser?
* **Logical Reasoning:** Can we infer input/output behavior based on the code?
* **Common Errors:** What mistakes can developers or users make that relate to this code?
* **Debugging Clues:** How does a user's action lead to this code being executed?

**2. Initial Code Scan and Key Components Identification:**

The first step is a quick read-through to identify the major classes and their apparent roles. Keywords like "MDns," "Client," "Listener," "Transaction," "Socket," and "Cache" immediately stand out.

* **`MDnsClientImpl`:** This looks like the central class managing the mDNS client. It likely handles starting, stopping, and creating listeners/transactions.
* **`MDnsConnection`:** This seems responsible for the low-level network communication, managing sockets and sending/receiving data.
* **`MDnsListenerImpl`:** This likely represents an active request for specific mDNS records and manages updates.
* **`MDnsTransactionImpl`:** This represents a single request for mDNS records, possibly with a timeout.
* **`MDnsCache`:**  Though not directly in this file, its use is evident, suggesting it stores discovered mDNS records.
* **`SocketHandler`:**  A helper class within `MDnsConnection` to manage individual sockets.

**3. Deeper Dive into Functionality - Class by Class:**

Now, go through each significant class and its methods, trying to deduce their purpose.

* **`MDnsClientImpl`:**
    * `StartListening/StopListening`: Obvious starting/stopping points.
    * `CreateListener/CreateTransaction`: Factories for creating specific request types.
    *  The existence of a `Core` class suggests a common implementation pattern (separation of interface and implementation).
* **`MDnsClientImpl::Core`:**
    * `Init`: Initializes the connection.
    * `SendQuery`: Sends mDNS queries over the network.
    * `HandlePacket`: Processes incoming mDNS responses. This is a crucial part for understanding how data is received and parsed.
    * `AddListener/RemoveListener`: Manages the list of active listeners.
    * `QueryCache`: Retrieves data from the local cache.
    * `ScheduleCleanup/DoCleanup`:  Manages cache expiration and removal.
* **`MDnsConnection`:**
    * `Init`: Sets up the sockets.
    * `Send`: Sends data through the sockets.
    * `OnDatagramReceived`:  Handles incoming data on the socket.
* **`MDnsConnection::SocketHandler`:**
    * `Start`:  Starts listening on a specific socket.
    * `Send/SendDone`: Handles sending data asynchronously.
    * `OnDatagramReceived`: Callback when data is received.
* **`MDnsListenerImpl`:**
    * `Start`: Registers the listener with the client.
    * `SetActiveRefresh`:  Determines if the listener should proactively refresh its cached data.
    * `HandleRecordUpdate`:  Handles updates to the watched records.
    * `ScheduleNextRefresh/DoRefresh`: Manages the refresh mechanism.
* **`MDnsTransactionImpl`:**
    * `Start`: Initiates the transaction (querying cache and/or network).
    * `ServeRecordsFromCache`:  Retrieves and processes records from the cache.
    * `QueryAndListen`:  Sends a network query and sets up a listener for responses.
    * `OnRecordUpdate/OnNsecRecord`: Handles responses.
    * `TriggerCallback`:  Executes the user-provided callback.

**4. Identifying JavaScript Connections:**

Think about where mDNS functionality is likely used in a browser context. Service discovery for local network devices is the primary use case. APIs like the Network Service Discovery API (though not directly mentioned in the code) are the bridge.

* **Hypothesize:** JavaScript uses a browser API to request information about local devices (e.g., printers, smart devices). This request likely triggers the creation of an `MDnsTransaction`.
* **Example:**  A user wants to print to a network printer. The browser needs to discover available printers using mDNS. The JavaScript calls an API, which internally leads to the creation of an `MDnsTransaction` for "_printer._tcp.local".

**5. Logical Reasoning - Input/Output:**

Consider the flow of information:

* **Input:** A request for a specific mDNS record (name and type). This can come from a `CreateListener` or `CreateTransaction` call. Incoming network packets are also input.
* **Processing:** The `Core` class manages the cache, sends queries, and parses responses. Listeners and transactions are notified of updates.
* **Output:**  The `MDnsListener::Delegate` or `MDnsTransaction::ResultCallback` receives updates (new records, changes, removals, or the final transaction result). For network queries, the output is the mDNS response packets.

**6. Common Errors:**

Think about how things could go wrong:

* **Incorrect Service Name:**  Users or developers might enter the wrong service name (e.g., a typo).
* **Network Issues:**  mDNS relies on multicast. Firewalls or network configurations can block mDNS traffic.
* **Permissions:** The browser might lack permissions to use network sockets for mDNS.
* **Misunderstanding Asynchronous Nature:**  Callbacks are used, so failing to handle them correctly is a common mistake.

**7. Debugging Clues - User Actions:**

Trace a user action to the code:

* **User Action:** User types a local hostname (e.g., `my-printer.local`) in the address bar or tries to connect to a local device.
* **Browser Processing:** The browser's address bar logic or a related service (like printing) needs to resolve this local hostname.
* **mDNS Invocation:** The browser's DNS resolver (or a specific mDNS module) realizes it's a `.local` domain and uses the `MDnsClientImpl` to query for the IP address. This would likely involve creating an `MDnsTransaction` for the A or AAAA record of the hostname.

**8. Refinement and Structuring:**

Organize the findings into clear sections as requested by the prompt: Functionality, JavaScript Relation, Logical Reasoning, Common Errors, and Debugging. Use code snippets or examples where appropriate.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this code directly interacts with JavaScript.
* **Correction:** Realize that there are likely intermediate layers (browser APIs, potentially a separate mDNS service) between this C++ code and the JavaScript environment.
* **Initial thought:** Focus solely on the happy path.
* **Correction:**  Consider error handling and failure scenarios, which leads to identifying common user/developer errors.
* **Initial thought:**  Only consider direct user actions.
* **Correction:**  Think about how other browser subsystems might trigger mDNS queries indirectly.

By following this systematic approach, combining code reading with domain knowledge about networking and browser architecture, we can effectively analyze the given C++ code and provide a comprehensive answer to the prompt.
这个文件 `net/dns/mdns_client_impl.cc` 是 Chromium 网络栈中负责 **Multicast DNS (mDNS)** 客户端实现的核心部分。它的主要功能是：

**1. mDNS 查询和响应的发送与接收:**

*   **发送 mDNS 查询:**  它能够构建和发送 mDNS 查询报文，以查找本地网络上的服务或主机。查询可以针对特定的记录类型（例如 A 记录表示 IPv4 地址，AAAA 记录表示 IPv6 地址，SRV 记录表示服务信息等）。
*   **接收 mDNS 响应:**  它监听 mDNS 多播地址，接收来自本地网络设备的 mDNS 响应报文。
*   **解析 mDNS 报文:**  它解析接收到的 mDNS 报文，提取出 DNS 记录信息，例如主机名、IP 地址、TTL（Time To Live）等。

**2. mDNS 缓存管理:**

*   **维护 mDNS 缓存:**  它维护一个本地的 mDNS 缓存，存储从接收到的响应中解析出的 DNS 记录。
*   **缓存记录的添加、更新和删除:**  当收到新的响应时，会更新缓存中的记录；当记录的 TTL 过期时，会从缓存中删除。
*   **缓存记录的查找:**  当需要查找本地网络上的服务或主机时，首先会查询本地缓存，以避免不必要的网络请求。
*   **缓存清理:** 定期清理过期的缓存记录，保持缓存的新鲜度。

**3. mDNS 监听器 (Listener) 的管理:**

*   **注册监听器:** 允许其他模块注册对特定 mDNS 查询的监听。例如，一个模块可能想监听 "_http._tcp.local" 服务，以便发现本地网络上的 HTTP 服务。
*   **通知监听器:** 当接收到与监听器匹配的 mDNS 响应时，通知相关的监听器，并将解析出的 DNS 记录传递给它们。
*   **主动刷新:**  对于活动的监听器，它会在记录的 TTL 到期前主动发送刷新查询，以保持缓存数据的有效性。

**4. mDNS 事务 (Transaction) 的管理:**

*   **创建事务:** 允许发起一次性的 mDNS 查询请求。例如，应用程序可能需要查找特定的主机名对应的 IP 地址。
*   **处理事务结果:** 当事务完成（收到响应或超时）时，通过回调函数将结果返回给请求者。

**5. Socket 管理:**

*   **创建和绑定 Socket:**  创建 UDP socket 并绑定到 mDNS 多播地址，用于发送和接收 mDNS 报文。它会根据网络接口配置创建 IPv4 和 IPv6 的 socket。
*   **处理 Socket 的发送和接收:**  管理 socket 的异步发送和接收操作。

**与 JavaScript 的关系以及举例说明:**

`mdns_client_impl.cc` 本身是 C++ 代码，运行在 Chromium 浏览器的网络进程中。它不直接与 JavaScript 代码交互。然而，它提供的 mDNS 功能会被浏览器的高层 API 使用，而这些 API 最终可以被 JavaScript 调用。

**举例说明:**

1. **Chromecast 发现:** 当 JavaScript 代码 (例如在 Google Home 应用或 Chrome 浏览器中) 想要发现本地网络上的 Chromecast 设备时，它可能会使用一个底层的浏览器 API，这个 API 内部会使用 `MDnsClientImpl` 来发送对 "_googlecast._tcp.local" 服务的 mDNS 查询。接收到的响应会被解析，并将设备信息传递回 JavaScript，从而在界面上显示可用的 Chromecast 设备。

2. **本地网络打印机发现:** 当用户想要添加本地网络打印机时，浏览器可以使用 mDNS 来发现可用的打印机。JavaScript 可以调用 `chrome.networkingPrivate.getNetworkInterfaces` (或其他相关 API) 获取网络接口信息，然后浏览器内部的网络栈会利用 `MDnsClientImpl` 发送针对打印机服务的 mDNS 查询 (例如 "_ipp._tcp.local", "_ipps._tcp.local")。找到的打印机信息会被返回给 JavaScript，展示在打印机添加界面。

3. **本地网站访问 (`.local` 域名):**  当用户在地址栏输入一个 `.local` 结尾的域名 (例如 `my-device.local`) 时，浏览器的 DNS 解析器会尝试使用 mDNS 来解析这个域名。这会触发 `MDnsClientImpl` 发送相应的 A 或 AAAA 记录查询。

**逻辑推理，假设输入与输出:**

**假设输入:**

*   调用 `MDnsClientImpl::CreateTransaction` 创建一个事务，查询 "_my-service._tcp.local" 的 SRV 记录。
*   本地网络上有一个设备广播了包含 "_my-service._tcp.local" SRV 记录的 mDNS 响应，该记录指向主机 `my-server.local`，端口 `1234`。

**输出:**

*   `MDnsTransactionImpl` 的回调函数会被调用，`result` 参数为 `MDnsTransaction::RESULT_RECORD`。
*   回调函数接收到的 `record` 参数是一个指向解析出的 SRV 记录的指针，其中包含了 `my-server.local` 和 `1234` 等信息。

**用户或编程常见的使用错误，举例说明:**

1. **用户错误:**
    *   **网络配置问题:** 用户的网络环境没有正确配置 mDNS 多播。例如，防火墙阻止了 UDP 端口 5353 的通信，导致无法接收到 mDNS 响应。
    *   **错误的 `.local` 域名:** 用户在地址栏输入了错误的 `.local` 域名，导致 mDNS 查询无法找到对应的设备。

2. **编程错误:**
    *   **未启动监听:**  开发者忘记调用 `MDnsClientImpl::StartListening` 就尝试创建监听器或事务，导致 mDNS 功能无法正常工作。
    *   **错误的查询名称或类型:** 开发者创建监听器或事务时，使用了错误的 mDNS 服务名称或记录类型，导致无法匹配到期望的响应。
    *   **未处理异步回调:**  mDNS 查询是异步的，开发者没有正确处理 `MDnsListener::Delegate::OnRecordUpdate` 或 `MDnsTransaction::ResultCallback`，导致无法获取查询结果。
    *   **过度依赖缓存:**  开发者假设 mDNS 响应会立即到达并缓存，而没有考虑网络延迟或设备离线的情况。

**用户操作如何一步步地到达这里，作为调试线索:**

以下是一些用户操作可能触发 `mdns_client_impl.cc` 中的代码执行：

1. **在 Chrome 地址栏中输入 `.local` 域名:**
    *   用户在 Chrome 浏览器的地址栏中输入一个以 `.local` 结尾的域名，例如 `my-printer.local`。
    *   浏览器的 DNS 解析器识别到 `.local` 后缀，确定需要使用 mDNS 进行解析。
    *   浏览器进程（或网络进程）调用 `MDnsClientImpl::CreateTransaction` 创建一个事务，查询该域名的 A 或 AAAA 记录。
    *   `MDnsClientImpl::Core::SendQuery` 被调用，发送 mDNS 查询报文。
    *   `MDnsConnection::Send` 通过 socket 发送报文。
    *   接收到响应后，`MDnsConnection::OnDatagramReceived` 被调用。
    *   `MDnsClientImpl::Core::HandlePacket` 解析响应报文，并更新缓存。
    *   如果找到了对应的记录，事务的回调函数会被调用，将 IP 地址返回给浏览器，最终浏览器可以连接到该地址。

2. **使用 Chromecast 功能:**
    *   用户点击 Chrome 浏览器或支持 Chromecast 的应用程序中的 "投射" 按钮。
    *   JavaScript 代码调用浏览器提供的 Chromecast API。
    *   浏览器内部使用 `MDnsClientImpl` 创建一个监听器，监听 "_googlecast._tcp.local" 服务。
    *   `MDnsClientImpl::Core::AddListener` 添加监听器。
    *   `MDnsClientImpl::Core::SendQuery` 发送 mDNS 查询。
    *   接收到 Chromecast 设备的响应后，`MDnsClientImpl::Core::HandlePacket` 解析报文。
    *   `MDnsClientImpl::Core::AlertListeners` 通知监听器。
    *   `MDnsListenerImpl::HandleRecordUpdate` 被调用，将 Chromecast 设备的信息传递给上层代码，最终显示在投射设备列表中。

3. **添加本地网络打印机:**
    *   用户在操作系统或 Chrome 浏览器的设置中选择添加打印机。
    *   系统或浏览器会扫描本地网络上的可用打印机。
    *   浏览器内部使用 `MDnsClientImpl` 创建事务或监听器，查询打印机相关的服务类型，例如 "_ipp._tcp.local", "_ipps._tcp.local"。
    *   流程类似于 Chromecast 发现，通过 mDNS 查询找到打印机的信息，并展示给用户。

通过仔细查看网络请求日志 (例如 Chrome 的 `chrome://net-export/`)，以及在 `mdns_client_impl.cc` 中添加调试日志，可以更清晰地追踪用户操作如何触发这些代码的执行，并观察 mDNS 查询和响应的详细信息，从而帮助调试 mDNS 相关的问题。

### 提示词
```
这是目录为net/dns/mdns_client_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/mdns_client_impl.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "base/containers/fixed_flat_set.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/metrics/histogram_functions.h"
#include "base/not_fatal_until.h"
#include "base/observer_list.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_util.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/clock.h"
#include "base/time/default_clock.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/base/net_errors.h"
#include "net/base/rand_callback.h"
#include "net/dns/dns_names_util.h"
#include "net/dns/public/dns_protocol.h"
#include "net/dns/public/util.h"
#include "net/dns/record_rdata.h"
#include "net/socket/datagram_socket.h"

// TODO(gene): Remove this temporary method of disabling NSEC support once it
// becomes clear whether this feature should be
// supported. http://crbug.com/255232
#define ENABLE_NSEC

namespace net {

namespace {

// The fractions of the record's original TTL after which an active listener
// (one that had |SetActiveRefresh(true)| called) will send a query to refresh
// its cache. This happens both at 85% of the original TTL and again at 95% of
// the original TTL.
const double kListenerRefreshRatio1 = 0.85;
const double kListenerRefreshRatio2 = 0.95;

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class mdnsQueryType {
  kInitial = 0,  // Initial mDNS query sent.
  kRefresh = 1,  // Refresh mDNS query sent.
  kMaxValue = kRefresh,
};

void RecordQueryMetric(mdnsQueryType query_type, std::string_view host) {
  constexpr auto kPrintScanServices = base::MakeFixedFlatSet<std::string_view>({
      "_ipps._tcp.local",
      "_ipp._tcp.local",
      "_pdl-datastream._tcp.local",
      "_printer._tcp.local",
      "_print._sub._ipps._tcp.local",
      "_print._sub._ipp._tcp.local",
      "_scanner._tcp.local",
      "_uscans._tcp.local",
      "_uscan._tcp.local",
  });

  if (host.ends_with("_googlecast._tcp.local")) {
    base::UmaHistogramEnumeration("Network.Mdns.Googlecast", query_type);
  } else if (base::ranges::any_of(kPrintScanServices,
                                  [&host](std::string_view service) {
                                    return host.ends_with(service);
                                  })) {
    base::UmaHistogramEnumeration("Network.Mdns.PrintScan", query_type);
  } else {
    base::UmaHistogramEnumeration("Network.Mdns.Other", query_type);
  }
}

}  // namespace

void MDnsSocketFactoryImpl::CreateSockets(
    std::vector<std::unique_ptr<DatagramServerSocket>>* sockets) {
  InterfaceIndexFamilyList interfaces(GetMDnsInterfacesToBind());
  for (const auto& interface : interfaces) {
    DCHECK(interface.second == ADDRESS_FAMILY_IPV4 ||
           interface.second == ADDRESS_FAMILY_IPV6);
    std::unique_ptr<DatagramServerSocket> socket(
        CreateAndBindMDnsSocket(interface.second, interface.first, net_log_));
    if (socket)
      sockets->push_back(std::move(socket));
  }
}

MDnsConnection::SocketHandler::SocketHandler(
    std::unique_ptr<DatagramServerSocket> socket,
    MDnsConnection* connection)
    : socket_(std::move(socket)),
      connection_(connection),
      response_(dns_protocol::kMaxMulticastSize) {}

MDnsConnection::SocketHandler::~SocketHandler() = default;

int MDnsConnection::SocketHandler::Start() {
  IPEndPoint end_point;
  int rv = socket_->GetLocalAddress(&end_point);
  if (rv != OK)
    return rv;
  DCHECK(end_point.GetFamily() == ADDRESS_FAMILY_IPV4 ||
         end_point.GetFamily() == ADDRESS_FAMILY_IPV6);
  multicast_addr_ = dns_util::GetMdnsGroupEndPoint(end_point.GetFamily());
  return DoLoop(0);
}

int MDnsConnection::SocketHandler::DoLoop(int rv) {
  do {
    if (rv > 0)
      connection_->OnDatagramReceived(&response_, recv_addr_, rv);

    rv = socket_->RecvFrom(
        response_.io_buffer(), response_.io_buffer_size(), &recv_addr_,
        base::BindOnce(&MDnsConnection::SocketHandler::OnDatagramReceived,
                       base::Unretained(this)));
  } while (rv > 0);

  if (rv != ERR_IO_PENDING)
    return rv;

  return OK;
}

void MDnsConnection::SocketHandler::OnDatagramReceived(int rv) {
  if (rv >= OK)
    rv = DoLoop(rv);

  if (rv != OK)
    connection_->PostOnError(this, rv);
}

void MDnsConnection::SocketHandler::Send(const scoped_refptr<IOBuffer>& buffer,
                                         unsigned size) {
  if (send_in_progress_) {
    send_queue_.emplace(buffer, size);
    return;
  }
  int rv =
      socket_->SendTo(buffer.get(), size, multicast_addr_,
                      base::BindOnce(&MDnsConnection::SocketHandler::SendDone,
                                     base::Unretained(this)));
  if (rv == ERR_IO_PENDING) {
    send_in_progress_ = true;
  } else if (rv < OK) {
    connection_->PostOnError(this, rv);
  }
}

void MDnsConnection::SocketHandler::SendDone(int rv) {
  DCHECK(send_in_progress_);
  send_in_progress_ = false;
  if (rv != OK)
    connection_->PostOnError(this, rv);
  while (!send_in_progress_ && !send_queue_.empty()) {
    std::pair<scoped_refptr<IOBuffer>, unsigned> buffer = send_queue_.front();
    send_queue_.pop();
    Send(buffer.first, buffer.second);
  }
}

MDnsConnection::MDnsConnection(MDnsConnection::Delegate* delegate)
    : delegate_(delegate) {}

MDnsConnection::~MDnsConnection() = default;

int MDnsConnection::Init(MDnsSocketFactory* socket_factory) {
  std::vector<std::unique_ptr<DatagramServerSocket>> sockets;
  socket_factory->CreateSockets(&sockets);

  for (std::unique_ptr<DatagramServerSocket>& socket : sockets) {
    socket_handlers_.push_back(std::make_unique<MDnsConnection::SocketHandler>(
        std::move(socket), this));
  }

  // All unbound sockets need to be bound before processing untrusted input.
  // This is done for security reasons, so that an attacker can't get an unbound
  // socket.
  int last_failure = ERR_FAILED;
  for (size_t i = 0; i < socket_handlers_.size();) {
    int rv = socket_handlers_[i]->Start();
    if (rv != OK) {
      last_failure = rv;
      socket_handlers_.erase(socket_handlers_.begin() + i);
      VLOG(1) << "Start failed, socket=" << i << ", error=" << rv;
    } else {
      ++i;
    }
  }
  VLOG(1) << "Sockets ready:" << socket_handlers_.size();
  DCHECK_NE(ERR_IO_PENDING, last_failure);
  return socket_handlers_.empty() ? last_failure : OK;
}

void MDnsConnection::Send(const scoped_refptr<IOBuffer>& buffer,
                          unsigned size) {
  for (std::unique_ptr<SocketHandler>& handler : socket_handlers_)
    handler->Send(buffer, size);
}

void MDnsConnection::PostOnError(SocketHandler* loop, int rv) {
  int id = 0;
  for (const auto& it : socket_handlers_) {
    if (it.get() == loop)
      break;
    id++;
  }
  VLOG(1) << "Socket error. id=" << id << ", error=" << rv;
  // Post to allow deletion of this object by delegate.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&MDnsConnection::OnError,
                                weak_ptr_factory_.GetWeakPtr(), rv));
}

void MDnsConnection::OnError(int rv) {
  // TODO(noamsml): Specific handling of intermittent errors that can be handled
  // in the connection.
  delegate_->OnConnectionError(rv);
}

void MDnsConnection::OnDatagramReceived(
    DnsResponse* response,
    const IPEndPoint& recv_addr,
    int bytes_read) {
  // TODO(noamsml): More sophisticated error handling.
  DCHECK_GT(bytes_read, 0);
  delegate_->HandlePacket(response, bytes_read);
}

MDnsClientImpl::Core::Core(base::Clock* clock, base::OneShotTimer* timer)
    : clock_(clock),
      cleanup_timer_(timer),
      connection_(
          std::make_unique<MDnsConnection>((MDnsConnection::Delegate*)this)) {
  DCHECK(cleanup_timer_);
  DCHECK(!cleanup_timer_->IsRunning());
}

MDnsClientImpl::Core::~Core() {
  cleanup_timer_->Stop();
}

int MDnsClientImpl::Core::Init(MDnsSocketFactory* socket_factory) {
  CHECK(!cleanup_timer_->IsRunning());
  return connection_->Init(socket_factory);
}

bool MDnsClientImpl::Core::SendQuery(uint16_t rrtype, const std::string& name) {
  std::optional<std::vector<uint8_t>> name_dns =
      dns_names_util::DottedNameToNetwork(name);
  if (!name_dns.has_value())
    return false;

  DnsQuery query(0, name_dns.value(), rrtype);
  query.set_flags(0);  // Remove the RD flag from the query. It is unneeded.

  connection_->Send(query.io_buffer(), query.io_buffer()->size());
  return true;
}

void MDnsClientImpl::Core::HandlePacket(DnsResponse* response,
                                        int bytes_read) {
  unsigned offset;
  // Note: We store cache keys rather than record pointers to avoid
  // erroneous behavior in case a packet contains multiple exclusive
  // records with the same type and name.
  std::map<MDnsCache::Key, MDnsCache::UpdateType> update_keys;
  DCHECK_GT(bytes_read, 0);
  if (!response->InitParseWithoutQuery(bytes_read)) {
    DVLOG(1) << "Could not understand an mDNS packet.";
    return;  // Message is unreadable.
  }

  // TODO(noamsml): duplicate query suppression.
  if (!(response->flags() & dns_protocol::kFlagResponse))
    return;  // Message is a query. ignore it.

  DnsRecordParser parser = response->Parser();
  unsigned answer_count = response->answer_count() +
      response->additional_answer_count();

  for (unsigned i = 0; i < answer_count; i++) {
    offset = parser.GetOffset();
    std::unique_ptr<const RecordParsed> record =
        RecordParsed::CreateFrom(&parser, clock_->Now());

    if (!record) {
      DVLOG(1) << "Could not understand an mDNS record.";

      if (offset == parser.GetOffset()) {
        DVLOG(1) << "Abandoned parsing the rest of the packet.";
        return;  // The parser did not advance, abort reading the packet.
      } else {
        continue;  // We may be able to extract other records from the packet.
      }
    }

    if ((record->klass() & dns_protocol::kMDnsClassMask) !=
        dns_protocol::kClassIN) {
      DVLOG(1) << "Received an mDNS record with non-IN class. Ignoring.";
      continue;  // Ignore all records not in the IN class.
    }

    MDnsCache::Key update_key = MDnsCache::Key::CreateFor(record.get());
    MDnsCache::UpdateType update = cache_.UpdateDnsRecord(std::move(record));

    // Cleanup time may have changed.
    ScheduleCleanup(cache_.next_expiration());

    update_keys.emplace(update_key, update);
  }

  for (const auto& update_key : update_keys) {
    const RecordParsed* record = cache_.LookupKey(update_key.first);
    if (!record)
      continue;

    if (record->type() == dns_protocol::kTypeNSEC) {
#if defined(ENABLE_NSEC)
      NotifyNsecRecord(record);
#endif
    } else {
      AlertListeners(update_key.second,
                     ListenerKey(record->name(), record->type()), record);
    }
  }
}

void MDnsClientImpl::Core::NotifyNsecRecord(const RecordParsed* record) {
  DCHECK_EQ(dns_protocol::kTypeNSEC, record->type());
  const NsecRecordRdata* rdata = record->rdata<NsecRecordRdata>();
  DCHECK(rdata);

  // Remove all cached records matching the nonexistent RR types.
  std::vector<const RecordParsed*> records_to_remove;

  cache_.FindDnsRecords(0, record->name(), &records_to_remove, clock_->Now());

  for (const auto* record_to_remove : records_to_remove) {
    if (record_to_remove->type() == dns_protocol::kTypeNSEC)
      continue;
    if (!rdata->GetBit(record_to_remove->type())) {
      std::unique_ptr<const RecordParsed> record_removed =
          cache_.RemoveRecord(record_to_remove);
      DCHECK(record_removed);
      OnRecordRemoved(record_removed.get());
    }
  }

  // Alert all listeners waiting for the nonexistent RR types.
  ListenerKey key(record->name(), 0);
  auto i = listeners_.upper_bound(key);
  for (; i != listeners_.end() &&
         i->first.name_lowercase() == key.name_lowercase();
       i++) {
    if (!rdata->GetBit(i->first.type())) {
      for (auto& observer : *i->second)
        observer.AlertNsecRecord();
    }
  }
}

void MDnsClientImpl::Core::OnConnectionError(int error) {
  // TODO(noamsml): On connection error, recreate connection and flush cache.
  VLOG(1) << "MDNS OnConnectionError (code: " << error << ")";
}

MDnsClientImpl::Core::ListenerKey::ListenerKey(const std::string& name,
                                               uint16_t type)
    : name_lowercase_(base::ToLowerASCII(name)), type_(type) {}

bool MDnsClientImpl::Core::ListenerKey::operator<(
    const MDnsClientImpl::Core::ListenerKey& key) const {
  if (name_lowercase_ == key.name_lowercase_)
    return type_ < key.type_;
  return name_lowercase_ < key.name_lowercase_;
}

void MDnsClientImpl::Core::AlertListeners(
    MDnsCache::UpdateType update_type,
    const ListenerKey& key,
    const RecordParsed* record) {
  auto listener_map_iterator = listeners_.find(key);
  if (listener_map_iterator == listeners_.end()) return;

  for (auto& observer : *listener_map_iterator->second)
    observer.HandleRecordUpdate(update_type, record);
}

void MDnsClientImpl::Core::AddListener(
    MDnsListenerImpl* listener) {
  ListenerKey key(listener->GetName(), listener->GetType());

  auto& observer_list = listeners_[key];
  if (!observer_list)
    observer_list = std::make_unique<ObserverListType>();

  observer_list->AddObserver(listener);
}

void MDnsClientImpl::Core::RemoveListener(MDnsListenerImpl* listener) {
  ListenerKey key(listener->GetName(), listener->GetType());
  auto observer_list_iterator = listeners_.find(key);

  CHECK(observer_list_iterator != listeners_.end(), base::NotFatalUntil::M130);
  DCHECK(observer_list_iterator->second->HasObserver(listener));

  observer_list_iterator->second->RemoveObserver(listener);

  // Remove the observer list from the map if it is empty
  if (observer_list_iterator->second->empty()) {
    // Schedule the actual removal for later in case the listener removal
    // happens while iterating over the observer list.
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&MDnsClientImpl::Core::CleanupObserverList,
                                  weak_ptr_factory_.GetWeakPtr(), key));
  }
}

void MDnsClientImpl::Core::CleanupObserverList(const ListenerKey& key) {
  auto found = listeners_.find(key);
  if (found != listeners_.end() && found->second->empty()) {
    listeners_.erase(found);
  }
}

void MDnsClientImpl::Core::ScheduleCleanup(base::Time cleanup) {
  // If cache is overfilled. Force an immediate cleanup.
  if (cache_.IsCacheOverfilled())
    cleanup = clock_->Now();

  // Cleanup is already scheduled, no need to do anything.
  if (cleanup == scheduled_cleanup_) {
    return;
  }
  scheduled_cleanup_ = cleanup;

  // This cancels the previously scheduled cleanup.
  cleanup_timer_->Stop();

  // If |cleanup| is empty, then no cleanup necessary.
  if (cleanup != base::Time()) {
    cleanup_timer_->Start(FROM_HERE,
                          std::max(base::TimeDelta(), cleanup - clock_->Now()),
                          base::BindOnce(&MDnsClientImpl::Core::DoCleanup,
                                         base::Unretained(this)));
  }
}

void MDnsClientImpl::Core::DoCleanup() {
  cache_.CleanupRecords(
      clock_->Now(), base::BindRepeating(&MDnsClientImpl::Core::OnRecordRemoved,
                                         base::Unretained(this)));

  ScheduleCleanup(cache_.next_expiration());
}

void MDnsClientImpl::Core::OnRecordRemoved(
    const RecordParsed* record) {
  AlertListeners(MDnsCache::RecordRemoved,
                 ListenerKey(record->name(), record->type()), record);
}

void MDnsClientImpl::Core::QueryCache(
    uint16_t rrtype,
    const std::string& name,
    std::vector<const RecordParsed*>* records) const {
  cache_.FindDnsRecords(rrtype, name, records, clock_->Now());
}

MDnsClientImpl::MDnsClientImpl()
    : clock_(base::DefaultClock::GetInstance()),
      cleanup_timer_(std::make_unique<base::OneShotTimer>()) {}

MDnsClientImpl::MDnsClientImpl(base::Clock* clock,
                               std::unique_ptr<base::OneShotTimer> timer)
    : clock_(clock), cleanup_timer_(std::move(timer)) {}

MDnsClientImpl::~MDnsClientImpl() {
  StopListening();
}

int MDnsClientImpl::StartListening(MDnsSocketFactory* socket_factory) {
  DCHECK(!core_.get());
  core_ = std::make_unique<Core>(clock_, cleanup_timer_.get());
  int rv = core_->Init(socket_factory);
  if (rv != OK) {
    DCHECK_NE(ERR_IO_PENDING, rv);
    core_.reset();
  }
  return rv;
}

void MDnsClientImpl::StopListening() {
  core_.reset();
}

bool MDnsClientImpl::IsListening() const {
  return core_.get() != nullptr;
}

std::unique_ptr<MDnsListener> MDnsClientImpl::CreateListener(
    uint16_t rrtype,
    const std::string& name,
    MDnsListener::Delegate* delegate) {
  return std::make_unique<MDnsListenerImpl>(rrtype, name, clock_, delegate,
                                            this);
}

std::unique_ptr<MDnsTransaction> MDnsClientImpl::CreateTransaction(
    uint16_t rrtype,
    const std::string& name,
    int flags,
    const MDnsTransaction::ResultCallback& callback) {
  return std::make_unique<MDnsTransactionImpl>(rrtype, name, flags, callback,
                                               this);
}

MDnsListenerImpl::MDnsListenerImpl(uint16_t rrtype,
                                   const std::string& name,
                                   base::Clock* clock,
                                   MDnsListener::Delegate* delegate,
                                   MDnsClientImpl* client)
    : rrtype_(rrtype),
      name_(name),
      clock_(clock),
      client_(client),
      delegate_(delegate) {}

MDnsListenerImpl::~MDnsListenerImpl() {
  if (started_) {
    DCHECK(client_->core());
    client_->core()->RemoveListener(this);
  }
}

bool MDnsListenerImpl::Start() {
  DCHECK(!started_);

  started_ = true;

  DCHECK(client_->core());
  client_->core()->AddListener(this);

  return true;
}

void MDnsListenerImpl::SetActiveRefresh(bool active_refresh) {
  active_refresh_ = active_refresh;

  if (started_) {
    if (!active_refresh_) {
      next_refresh_.Cancel();
    } else if (last_update_ != base::Time()) {
      ScheduleNextRefresh();
    }
  }
}

const std::string& MDnsListenerImpl::GetName() const {
  return name_;
}

uint16_t MDnsListenerImpl::GetType() const {
  return rrtype_;
}

void MDnsListenerImpl::HandleRecordUpdate(MDnsCache::UpdateType update_type,
                                          const RecordParsed* record) {
  DCHECK(started_);

  if (update_type != MDnsCache::RecordRemoved) {
    ttl_ = record->ttl();
    last_update_ = record->time_created();

    ScheduleNextRefresh();
  }

  if (update_type != MDnsCache::NoChange) {
    MDnsListener::UpdateType update_external;

    switch (update_type) {
      case MDnsCache::RecordAdded:
        update_external = MDnsListener::RECORD_ADDED;
        break;
      case MDnsCache::RecordChanged:
        update_external = MDnsListener::RECORD_CHANGED;
        break;
      case MDnsCache::RecordRemoved:
        update_external = MDnsListener::RECORD_REMOVED;
        break;
      case MDnsCache::NoChange:
      default:
        NOTREACHED();
    }

    delegate_->OnRecordUpdate(update_external, record);
  }
}

void MDnsListenerImpl::AlertNsecRecord() {
  DCHECK(started_);
  delegate_->OnNsecRecord(name_, rrtype_);
}

void MDnsListenerImpl::ScheduleNextRefresh() {
  DCHECK(last_update_ != base::Time());

  if (!active_refresh_)
    return;

  // A zero TTL is a goodbye packet and should not be refreshed.
  if (ttl_ == 0) {
    next_refresh_.Cancel();
    return;
  }

  next_refresh_.Reset(base::BindRepeating(&MDnsListenerImpl::DoRefresh,
                                          weak_ptr_factory_.GetWeakPtr()));

  // Schedule refreshes at both 85% and 95% of the original TTL. These will both
  // be canceled and rescheduled if the record's TTL is updated due to a
  // response being received.
  base::Time next_refresh1 =
      last_update_ +
      base::Milliseconds(static_cast<int>(base::Time::kMillisecondsPerSecond *
                                          kListenerRefreshRatio1 * ttl_));

  base::Time next_refresh2 =
      last_update_ +
      base::Milliseconds(static_cast<int>(base::Time::kMillisecondsPerSecond *
                                          kListenerRefreshRatio2 * ttl_));

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, next_refresh_.callback(), next_refresh1 - clock_->Now());

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, next_refresh_.callback(), next_refresh2 - clock_->Now());
}

void MDnsListenerImpl::DoRefresh() {
  RecordQueryMetric(mdnsQueryType::kRefresh, name_);
  client_->core()->SendQuery(rrtype_, name_);
}

MDnsTransactionImpl::MDnsTransactionImpl(
    uint16_t rrtype,
    const std::string& name,
    int flags,
    const MDnsTransaction::ResultCallback& callback,
    MDnsClientImpl* client)
    : rrtype_(rrtype),
      name_(name),
      callback_(callback),
      client_(client),
      flags_(flags) {
  DCHECK((flags_ & MDnsTransaction::FLAG_MASK) == flags_);
  DCHECK(flags_ & MDnsTransaction::QUERY_CACHE ||
         flags_ & MDnsTransaction::QUERY_NETWORK);
}

MDnsTransactionImpl::~MDnsTransactionImpl() {
  timeout_.Cancel();
}

bool MDnsTransactionImpl::Start() {
  DCHECK(!started_);
  started_ = true;

  base::WeakPtr<MDnsTransactionImpl> weak_this = weak_ptr_factory_.GetWeakPtr();
  if (flags_ & MDnsTransaction::QUERY_CACHE) {
    ServeRecordsFromCache();

    if (!weak_this || !is_active()) return true;
  }

  if (flags_ & MDnsTransaction::QUERY_NETWORK) {
    return QueryAndListen();
  }

  // If this is a cache only query, signal that the transaction is over
  // immediately.
  SignalTransactionOver();
  return true;
}

const std::string& MDnsTransactionImpl::GetName() const {
  return name_;
}

uint16_t MDnsTransactionImpl::GetType() const {
  return rrtype_;
}

void MDnsTransactionImpl::CacheRecordFound(const RecordParsed* record) {
  DCHECK(started_);
  OnRecordUpdate(MDnsListener::RECORD_ADDED, record);
}

void MDnsTransactionImpl::TriggerCallback(MDnsTransaction::Result result,
                                          const RecordParsed* record) {
  DCHECK(started_);
  if (!is_active()) return;

  // Ensure callback is run after touching all class state, so that
  // the callback can delete the transaction.
  MDnsTransaction::ResultCallback callback = callback_;

  // Reset the transaction if it expects a single result, or if the result
  // is a final one (everything except for a record).
  if (flags_ & MDnsTransaction::SINGLE_RESULT ||
      result != MDnsTransaction::RESULT_RECORD) {
    Reset();
  }

  callback.Run(result, record);
}

void MDnsTransactionImpl::Reset() {
  callback_.Reset();
  listener_.reset();
  timeout_.Cancel();
}

void MDnsTransactionImpl::OnRecordUpdate(MDnsListener::UpdateType update,
                                         const RecordParsed* record) {
  DCHECK(started_);
  if (update ==  MDnsListener::RECORD_ADDED ||
      update == MDnsListener::RECORD_CHANGED)
    TriggerCallback(MDnsTransaction::RESULT_RECORD, record);
}

void MDnsTransactionImpl::SignalTransactionOver() {
  DCHECK(started_);
  if (flags_ & MDnsTransaction::SINGLE_RESULT) {
    TriggerCallback(MDnsTransaction::RESULT_NO_RESULTS, nullptr);
  } else {
    TriggerCallback(MDnsTransaction::RESULT_DONE, nullptr);
  }
}

void MDnsTransactionImpl::ServeRecordsFromCache() {
  std::vector<const RecordParsed*> records;
  base::WeakPtr<MDnsTransactionImpl> weak_this = weak_ptr_factory_.GetWeakPtr();

  if (client_->core()) {
    client_->core()->QueryCache(rrtype_, name_, &records);
    for (auto i = records.begin(); i != records.end() && weak_this; ++i) {
      weak_this->TriggerCallback(MDnsTransaction::RESULT_RECORD, *i);
    }

#if defined(ENABLE_NSEC)
    if (records.empty()) {
      DCHECK(weak_this);
      client_->core()->QueryCache(dns_protocol::kTypeNSEC, name_, &records);
      if (!records.empty()) {
        const NsecRecordRdata* rdata =
            records.front()->rdata<NsecRecordRdata>();
        DCHECK(rdata);
        if (!rdata->GetBit(rrtype_))
          weak_this->TriggerCallback(MDnsTransaction::RESULT_NSEC, nullptr);
      }
    }
#endif
  }
}

bool MDnsTransactionImpl::QueryAndListen() {
  listener_ = client_->CreateListener(rrtype_, name_, this);
  if (!listener_->Start())
    return false;

  DCHECK(client_->core());
  RecordQueryMetric(mdnsQueryType::kInitial, name_);
  if (!client_->core()->SendQuery(rrtype_, name_))
    return false;

  timeout_.Reset(base::BindOnce(&MDnsTransactionImpl::SignalTransactionOver,
                                weak_ptr_factory_.GetWeakPtr()));
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, timeout_.callback(), kTransactionTimeout);

  return true;
}

void MDnsTransactionImpl::OnNsecRecord(const std::string& name, unsigned type) {
  TriggerCallback(RESULT_NSEC, nullptr);
}

void MDnsTransactionImpl::OnCachePurged() {
  // TODO(noamsml): Cache purge situations not yet implemented
}

}  // namespace net
```