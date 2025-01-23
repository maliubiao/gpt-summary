Response:
Let's break down the thought process for analyzing the C++ code and fulfilling the request.

**1. Understanding the Goal:**

The request asks for:
* Functionality of the C++ code (`address_sorter_posix_unittest.cc`).
* Relation to JavaScript (if any).
* Logical inference examples (input/output).
* Common user/programming errors.
* Steps to reach the code (debugging).

**2. Initial Code Scan - High-Level Purpose:**

Quickly read through the code to get the gist. Keywords like `unittest`, `AddressSorterPosix`, `IPAddress`, `IPEndPoint`, `Sort`, `TestUDPClientSocket`, `TestSocketFactory` immediately jump out. This strongly suggests:

* **Unit Testing:** The file is designed to test the `AddressSorterPosix` class.
* **Network Functionality:** The class being tested likely sorts IP addresses based on some criteria.
* **Mocking/Stubbing:** `TestUDPClientSocket` and `TestSocketFactory` are likely mock implementations to simulate network behavior without real network calls.

**3. Deeper Dive - Identifying Key Components and Their Roles:**

* **`AddressSorterPosix`:** This is the class under test. The core function is `Sort`. It likely takes a list of `IPEndPoint` and returns a sorted list.
* **`TestUDPClientSocket`:**  A mock UDP socket. Crucially, it has a `Connect` method that simulates connecting to a remote address. The `AddressMapping` within it allows simulating successful or failed connections based on predefined mappings. The `ConnectMode` enum hints at different ways the connection can be simulated (synchronous, asynchronous).
* **`TestSocketFactory`:**  A mock socket factory that creates `TestUDPClientSocket` instances. It holds the `AddressMapping` used by the mock sockets and allows setting the `ConnectMode`.
* **`AddressMapping`:**  A `std::map` that links destination IP addresses to source IP addresses. This is the core mechanism for simulating network reachability. If a destination IP exists as a key, a connection to it (via the mock socket) will succeed and bind to the corresponding source IP.
* **Test Cases (e.g., `Rule1`, `Rule2`, etc.):**  These are individual test functions that exercise different sorting rules implemented within `AddressSorterPosix`. Each test sets up specific `AddressMapping` and input `IPEndPoint` lists and then uses `Verify` to check if the `Sort` method produces the expected output order.
* **`Verify` function:** This helper function takes an array of IP address strings and an expected order of indices. It converts the strings to `IPEndPoint`, calls `sorter_->Sort`, and then compares the sorted result against the expected order.
* **`OnSortComplete`:** A callback function used with the asynchronous `Sort` method.

**4. Analyzing the Sorting Logic (Inferred from Test Cases):**

While the exact sorting algorithm isn't in this *unittest* file, the *test cases* reveal the sorting *rules* being tested. Reading the test names and the setup within each test (the `AddMapping` calls) provides clues:

* **Rule 1: Avoid unusable destinations:**  Connecting to certain addresses might fail.
* **Rule 2: Prefer matching scope:**  Source and destination addresses with the same scope (e.g., both global, both link-local) are preferred.
* **Rule 3: Avoid deprecated addresses:**  Addresses marked as deprecated are lower priority.
* **Rule 4: Prefer home addresses:** Addresses marked as "home" are higher priority.
* ... and so on for the other rules.

**5. Connecting to JavaScript (or lack thereof):**

Think about how this C++ code might relate to a web browser's behavior. DNS resolution and address selection are crucial for making network requests. While the *unittest* itself isn't directly used in JavaScript, the *underlying logic* of `AddressSorterPosix` likely *influences* how Chrome chooses which IP address to connect to when a website has multiple IP addresses. This choice impacts connection speed and reliability. However, the *direct* code isn't used in JavaScript.

**6. Logical Inference (Input/Output Examples):**

Based on understanding the rules, create simple examples. Pick a rule and demonstrate its effect. For instance, Rule 2:

* **Input:** Two destination IPs: "3002::2" (global) and "3002::1" (global). Assume the source IP for "3002::1" is also global, and the source IP for "3002::2" is link-local.
* **Output:** "3002::1" will be preferred because its source and destination have matching scopes.

**7. Common Errors:**

Think about mistakes developers might make when *using* or *testing* this kind of functionality:

* **Incorrect Mappings:**  Setting up the `AddressMapping` incorrectly in tests.
* **Forgetting Asynchronous Completion:** Not calling `FinishConnect` in asynchronous tests.
* **Incorrect Assertions:**  Mistakes in the `Verify` function or the assertions within the tests.
* **Real Network Dependency (in a real implementation):**  If not using mocks, relying on the actual network state can lead to flaky tests.

**8. Debugging Steps:**

Imagine you encounter an issue where the browser isn't connecting to the "best" IP address. How might you trace it?

* **Start with Network Logs:** Chrome's internal logging (`chrome://net-export/`) is essential.
* **DNS Resolution:** Check the resolved IP addresses.
* **Address Selection Logic:**  If you suspect the sorting is wrong, you'd need to delve into the `AddressSorterPosix` code. Setting breakpoints in the `Sort` method and examining the `source_map_` and the applied rules would be necessary. The test cases themselves provide clues about what rules are being applied.

**Self-Correction/Refinement:**

* **Initial thought:** Maybe there's a direct JavaScript API for influencing address sorting. **Correction:**  While JavaScript can trigger network requests, the *low-level* address selection is handled by the browser's networking stack (C++). The connection to JavaScript is indirect.
* **Initial thought:**  Focus heavily on the code syntax. **Correction:**  The request asks for *functionality* and *implications*. Understanding the purpose and the logic is more important than dissecting every line of C++.
* **Initial thought:** Provide very complex input/output examples. **Correction:**  Simple, illustrative examples are better for demonstrating the core concepts.

By following this kind of structured approach, combining code reading with logical reasoning and understanding of the domain (network programming, unit testing), one can effectively analyze the provided C++ code and address the different aspects of the request.
这个文件 `net/dns/address_sorter_posix_unittest.cc` 是 Chromium 网络栈的一部分，它是一个单元测试文件，专门用于测试 `net::AddressSorterPosix` 类的功能。 `AddressSorterPosix` 类的主要职责是根据一系列规则对 IP 地址列表进行排序，以选择最佳的连接目标。

以下是该文件的详细功能分解：

**1. 功能概述:**

* **测试 `AddressSorterPosix` 类的 IP 地址排序功能:**  该文件通过编写各种测试用例，验证 `AddressSorterPosix` 类是否按照预期的规则对 IP 地址进行排序。
* **模拟网络环境:**  为了进行单元测试，它创建了模拟的 `DatagramClientSocket` (TestUDPClientSocket) 和 `ClientSocketFactory` (TestSocketFactory)。这些模拟对象允许测试在不进行真实网络连接的情况下验证排序逻辑。
* **定义排序规则的测试用例:**  每个 `TEST_P` 函数（Parameterized Test）代表一个或多个排序规则的测试。这些规则基于 RFC 3484 中定义的 IPv6 地址选择算法 (尽管 Chromium 的实现可能有所不同)。
* **验证排序结果:**  测试用例会创建一组待排序的 IP 地址，调用 `AddressSorterPosix::Sort` 方法，并使用 `EXPECT_TRUE` 等断言来验证排序后的地址顺序是否符合预期。
* **支持同步和异步连接模式测试:**  使用了参数化测试 (`AddressSorterPosixSyncOrAsyncTest`) 来覆盖同步和异步的 UDP 连接场景。
* **模拟 IP 地址变更:**  测试用例 `IPAddressChangedSort` 模拟了网络 IP 地址变更的情况，以验证 `AddressSorterPosix` 在这种场景下的行为。

**2. 与 JavaScript 的关系:**

这个 C++ 文件本身不包含 JavaScript 代码，但它测试的网络栈功能 **直接影响** 到 Chromium (包括 Chrome 浏览器) 如何处理来自 JavaScript 的网络请求。

* **`navigator.connect()` API 和 `fetch()` API:** 当 JavaScript 代码使用 `navigator.connect()` (实验性 API) 或 `fetch()` API 发起网络请求时，如果域名解析返回多个 IP 地址，Chromium 的网络栈会使用类似 `AddressSorterPosix` 这样的组件来决定尝试连接哪个 IP 地址。
* **性能和可靠性:**  正确的 IP 地址排序对于提供良好的用户体验至关重要。例如，优先选择本地网络范围内的 IP 地址可以提高连接速度，避免使用已弃用的地址可以提高连接的成功率。
* **透明性:**  对于 JavaScript 开发者来说，IP 地址排序通常是透明的。他们发起请求，浏览器会自动选择最佳的连接方式。但是，理解这种底层的排序逻辑有助于理解网络请求的行为。

**举例说明:**

假设一个网站 `example.com` 解析到以下两个 IP 地址：

* `2001:db8::1` (IPv6 全局地址)
* `192.0.2.1` (IPv4 地址)

当 JavaScript 代码执行 `fetch('https://example.com')` 时，Chromium 的网络栈会获取这两个 IP 地址。`AddressSorterPosix` (或类似的组件) 会根据规则对这两个地址进行排序。例如，如果用户的网络环境优先支持 IPv6 并且没有其他更优先的规则适用，那么 `2001:db8::1` 可能会被排在前面，浏览器会尝试先连接到这个 IPv6 地址。

**3. 逻辑推理 (假设输入与输出):**

让我们基于 Rule 2 的测试用例进行逻辑推理：

**假设输入:**

* 待排序的 IP 地址列表: `["3002::2", "3002::1"]` (都是 IPv6 全局地址)
* `AddressMapping`:
    * 目标 `3002::1` 映射到源地址 `4000::10` (假设也是全局地址)
    * 目标 `3002::2` 映射到源地址 `::1` (IPv6 环回地址，属于链路本地范围)

**排序规则 (Rule 2: Prefer matching scope):**

会优先选择目标地址，其对应的源地址和目标地址具有相同的网络范围。

**预期输出:**

排序后的 IP 地址列表为 `["3002::1", "3002::2"]`。

**推理过程:**

1. 连接到 `3002::1` 时，使用的源地址 `4000::10` 和目标地址 `3002::1` 都是全局范围，范围匹配。
2. 连接到 `3002::2` 时，使用的源地址 `::1` 是链路本地范围，而目标地址 `3002::2` 是全局范围，范围不匹配。
3. 根据 Rule 2，优先选择范围匹配的地址，因此 `3002::1` 排在 `3002::2` 前面。

**4. 用户或编程常见的使用错误:**

虽然用户通常不会直接与 `AddressSorterPosix` 交互，但与网络配置相关的错误可能会影响其行为：

* **错误的系统网络配置:**  如果用户的操作系统网络配置不正确 (例如，错误的 IPv6 设置，错误的路由表)，可能会导致 `AddressSorterPosix` 基于错误的本地地址信息进行排序，从而选择次优的连接目标。
* **防火墙配置:**  防火墙可能会阻止连接到某些 IP 地址，导致即使 `AddressSorterPosix` 选择了某个地址，连接也无法建立。这并非 `AddressSorterPosix` 的错误，而是网络环境问题。
* **编程错误 (针对 Chromium 开发人员):**
    * **在 `TestSocketFactory` 中配置错误的 `AddressMapping`:**  如果测试用例的映射配置不正确，会导致测试结果不可靠。例如，忘记为某个目标地址添加映射，会导致模拟连接失败，从而影响排序逻辑的验证。
    * **在异步测试中忘记调用 `FinishConnect()`:**  在模拟异步连接时，必须手动调用 `FinishConnect()` 来触发回调。如果忘记调用，异步测试可能会hang住或产生错误的结论。
    * **断言错误:**  在 `Verify` 函数中进行断言时，如果期望的排序顺序与实际情况不符，会导致测试失败。需要仔细检查期望的排序顺序是否正确。

**5. 用户操作到达这里的步骤 (作为调试线索):**

通常，用户不会直接触发 `AddressSorterPosix` 的执行。它是 Chromium 网络栈在后台自动运行的。但是，当用户遇到网络问题时，调试过程可能会涉及到查看与地址排序相关的日志或代码：

1. **用户遇到网络连接问题:** 例如，网页加载缓慢、连接超时、无法访问特定网站等。
2. **开启 Chrome 的网络日志 (net-internals):**  用户或开发人员可能会访问 `chrome://net-export/` 捕获网络事件日志。
3. **查看 DNS 查询结果:** 在网络日志中，可以查看域名解析的结果，即返回的 IP 地址列表。
4. **检查连接尝试:** 网络日志会显示 Chromium 尝试连接的 IP 地址顺序以及连接状态。
5. **怀疑地址排序问题:** 如果发现 Chromium 尝试连接的 IP 地址顺序不合理，或者总是连接失败的 IP 地址，可能会怀疑 `AddressSorterPosix` 的行为。
6. **查看 `AddressSorterPosix` 相关代码和日志:**  Chromium 开发人员可能会查看 `net/dns/address_sorter_posix.cc` 的代码，以及网络栈的更详细日志，以了解地址排序的决策过程。
7. **运行或修改单元测试:**  开发人员可能会运行 `address_sorter_posix_unittest.cc` 中的测试用例，或者添加新的测试用例来复现和调试问题。

**简而言之，`net/dns/address_sorter_posix_unittest.cc` 是 Chromium 网络栈中一个至关重要的测试文件，它确保了 IP 地址排序功能的正确性，从而直接影响用户的网络浏览体验。虽然 JavaScript 开发者不会直接操作这个文件，但其测试的功能是 JavaScript 网络请求得以高效可靠执行的基础。**

### 提示词
```
这是目录为net/dns/address_sorter_posix_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/dns/address_sorter_posix.h"

#include <memory>
#include <string>
#include <vector>

#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/notreached.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/network_change_notifier.h"
#include "net/base/test_completion_callback.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/datagram_client_socket.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/stream_socket.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

// Used to map destination address to source address.
typedef std::map<IPAddress, IPAddress> AddressMapping;

IPAddress ParseIP(const std::string& str) {
  IPAddress addr;
  CHECK(addr.AssignFromIPLiteral(str));
  return addr;
}

// A mock socket which binds to source address according to AddressMapping.
class TestUDPClientSocket : public DatagramClientSocket {
 public:
  enum class ConnectMode { kSynchronous, kAsynchronous, kAsynchronousManual };
  explicit TestUDPClientSocket(const AddressMapping* mapping,
                               ConnectMode connect_mode)
      : mapping_(mapping), connect_mode_(connect_mode) {}

  TestUDPClientSocket(const TestUDPClientSocket&) = delete;
  TestUDPClientSocket& operator=(const TestUDPClientSocket&) = delete;

  ~TestUDPClientSocket() override = default;

  int Read(IOBuffer*, int, CompletionOnceCallback) override {
    NOTIMPLEMENTED();
    return OK;
  }
  int Write(IOBuffer*,
            int,
            CompletionOnceCallback,
            const NetworkTrafficAnnotationTag& traffic_annotation) override {
    NOTIMPLEMENTED();
    return OK;
  }
  int SetReceiveBufferSize(int32_t) override { return OK; }
  int SetSendBufferSize(int32_t) override { return OK; }
  int SetDoNotFragment() override { return OK; }
  int SetRecvTos() override { return OK; }
  int SetTos(DiffServCodePoint dscp, EcnCodePoint ecn) override { return OK; }

  void Close() override {}
  int GetPeerAddress(IPEndPoint* address) const override {
    NOTIMPLEMENTED();
    return OK;
  }
  int GetLocalAddress(IPEndPoint* address) const override {
    if (!connected_)
      return ERR_UNEXPECTED;
    *address = local_endpoint_;
    return OK;
  }
  void UseNonBlockingIO() override {}
  int SetMulticastInterface(uint32_t interface_index) override {
    NOTIMPLEMENTED();
    return ERR_NOT_IMPLEMENTED;
  }

  int ConnectUsingNetwork(handles::NetworkHandle network,
                          const IPEndPoint& address) override {
    NOTIMPLEMENTED();
    return ERR_NOT_IMPLEMENTED;
  }

  int ConnectUsingDefaultNetwork(const IPEndPoint& address) override {
    NOTIMPLEMENTED();
    return ERR_NOT_IMPLEMENTED;
  }

  int ConnectAsync(const IPEndPoint& address,
                   CompletionOnceCallback callback) override {
    DCHECK(callback);
    int rv = Connect(address);
    finish_connect_callback_ =
        base::BindOnce(&TestUDPClientSocket::RunConnectCallback,
                       weak_ptr_factory_.GetWeakPtr(), std::move(callback), rv);
    if (connect_mode_ == ConnectMode::kAsynchronous) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, std::move(finish_connect_callback_));
      return ERR_IO_PENDING;
    } else if (connect_mode_ == ConnectMode::kAsynchronousManual) {
      return ERR_IO_PENDING;
    }
    return rv;
  }

  int ConnectUsingNetworkAsync(handles::NetworkHandle network,
                               const IPEndPoint& address,
                               CompletionOnceCallback callback) override {
    NOTIMPLEMENTED();
    return ERR_NOT_IMPLEMENTED;
  }

  int ConnectUsingDefaultNetworkAsync(
      const IPEndPoint& address,
      CompletionOnceCallback callback) override {
    NOTIMPLEMENTED();
    return ERR_NOT_IMPLEMENTED;
  }

  handles::NetworkHandle GetBoundNetwork() const override {
    return handles::kInvalidNetworkHandle;
  }
  void ApplySocketTag(const SocketTag& tag) override {}
  void SetMsgConfirm(bool confirm) override {}

  int Connect(const IPEndPoint& remote) override {
    if (connected_)
      return ERR_UNEXPECTED;
    auto it = mapping_->find(remote.address());
    if (it == mapping_->end())
      return ERR_FAILED;
    connected_ = true;
    local_endpoint_ = IPEndPoint(it->second, 39874 /* arbitrary port */);
    return OK;
  }

  const NetLogWithSource& NetLog() const override { return net_log_; }

  void FinishConnect() { std::move(finish_connect_callback_).Run(); }

  DscpAndEcn GetLastTos() const override { return {DSCP_DEFAULT, ECN_DEFAULT}; }

 private:
  void RunConnectCallback(CompletionOnceCallback callback, int rv) {
    std::move(callback).Run(rv);
  }
  NetLogWithSource net_log_;
  raw_ptr<const AddressMapping> mapping_;
  bool connected_ = false;
  IPEndPoint local_endpoint_;
  ConnectMode connect_mode_;
  base::OnceClosure finish_connect_callback_;

  base::WeakPtrFactory<TestUDPClientSocket> weak_ptr_factory_{this};
};

// Creates TestUDPClientSockets and maintains an AddressMapping.
class TestSocketFactory : public ClientSocketFactory {
 public:
  TestSocketFactory() = default;

  TestSocketFactory(const TestSocketFactory&) = delete;
  TestSocketFactory& operator=(const TestSocketFactory&) = delete;

  ~TestSocketFactory() override = default;

  std::unique_ptr<DatagramClientSocket> CreateDatagramClientSocket(
      DatagramSocket::BindType,
      NetLog*,
      const NetLogSource&) override {
    auto new_socket =
        std::make_unique<TestUDPClientSocket>(&mapping_, connect_mode_);
    if (socket_create_callback_) {
      socket_create_callback_.Run(new_socket.get());
    }
    return new_socket;
  }
  std::unique_ptr<TransportClientSocket> CreateTransportClientSocket(
      const AddressList&,
      std::unique_ptr<SocketPerformanceWatcher>,
      net::NetworkQualityEstimator*,
      NetLog*,
      const NetLogSource&) override {
    NOTIMPLEMENTED();
    return nullptr;
  }
  std::unique_ptr<SSLClientSocket> CreateSSLClientSocket(
      SSLClientContext*,
      std::unique_ptr<StreamSocket>,
      const HostPortPair&,
      const SSLConfig&) override {
    NOTIMPLEMENTED();
    return nullptr;
  }
  void AddMapping(const IPAddress& dst, const IPAddress& src) {
    mapping_[dst] = src;
  }
  void SetConnectMode(TestUDPClientSocket::ConnectMode connect_mode) {
    connect_mode_ = connect_mode;
  }
  void SetSocketCreateCallback(
      base::RepeatingCallback<void(TestUDPClientSocket*)>
          socket_create_callback) {
    socket_create_callback_ = std::move(socket_create_callback);
  }

 private:
  AddressMapping mapping_;
  TestUDPClientSocket::ConnectMode connect_mode_;
  base::RepeatingCallback<void(TestUDPClientSocket*)> socket_create_callback_;
};

void OnSortComplete(bool& completed,
                    std::vector<IPEndPoint>* sorted_buf,
                    CompletionOnceCallback callback,
                    bool success,
                    std::vector<IPEndPoint> sorted) {
  EXPECT_TRUE(success);
  completed = true;
  if (success)
    *sorted_buf = std::move(sorted);
  std::move(callback).Run(OK);
}

}  // namespace

// TaskEnvironment is required to register an IPAddressObserver from the
// constructor of AddressSorterPosix.
class AddressSorterPosixTest : public TestWithTaskEnvironment {
 protected:
  AddressSorterPosixTest()
      : sorter_(std::make_unique<AddressSorterPosix>(&socket_factory_)) {}

  void AddMapping(const std::string& dst, const std::string& src) {
    socket_factory_.AddMapping(ParseIP(dst), ParseIP(src));
  }

  void SetSocketCreateCallback(
      base::RepeatingCallback<void(TestUDPClientSocket*)>
          socket_create_callback) {
    socket_factory_.SetSocketCreateCallback(std::move(socket_create_callback));
  }

  void SetConnectMode(TestUDPClientSocket::ConnectMode connect_mode) {
    socket_factory_.SetConnectMode(connect_mode);
  }

  AddressSorterPosix::SourceAddressInfo* GetSourceInfo(
      const std::string& addr) {
    IPAddress address = ParseIP(addr);
    AddressSorterPosix::SourceAddressInfo* info =
        &sorter_->source_map_[address];
    if (info->scope == AddressSorterPosix::SCOPE_UNDEFINED)
      sorter_->FillPolicy(address, info);
    return info;
  }

  TestSocketFactory socket_factory_;
  std::unique_ptr<AddressSorterPosix> sorter_;
  bool completed_ = false;

 private:
  friend class AddressSorterPosixSyncOrAsyncTest;
};

// Parameterized subclass of AddressSorterPosixTest. Necessary because not every
// test needs to be parameterized.
class AddressSorterPosixSyncOrAsyncTest
    : public AddressSorterPosixTest,
      public testing::WithParamInterface<TestUDPClientSocket::ConnectMode> {
 protected:
  AddressSorterPosixSyncOrAsyncTest() { SetConnectMode(GetParam()); }

  // Verify that NULL-terminated |addresses| matches (-1)-terminated |order|
  // after sorting.
  void Verify(const char* const addresses[], const int order[]) {
    std::vector<IPEndPoint> endpoints;
    for (const char* const* addr = addresses; *addr != nullptr; ++addr)
      endpoints.emplace_back(ParseIP(*addr), 80);
    for (size_t i = 0; order[i] >= 0; ++i)
      CHECK_LT(order[i], static_cast<int>(endpoints.size()));

    std::vector<IPEndPoint> sorted;
    TestCompletionCallback callback;
    sorter_->Sort(endpoints,
                  base::BindOnce(&OnSortComplete, std::ref(completed_), &sorted,
                                 callback.callback()));
    callback.WaitForResult();

    for (size_t i = 0; (i < sorted.size()) || (order[i] >= 0); ++i) {
      IPEndPoint expected = order[i] >= 0 ? endpoints[order[i]] : IPEndPoint();
      IPEndPoint actual = i < sorted.size() ? sorted[i] : IPEndPoint();
      EXPECT_TRUE(expected == actual)
          << "Endpoint out of order at position " << i << "\n"
          << "  Actual: " << actual.ToString() << "\n"
          << "Expected: " << expected.ToString();
    }
    EXPECT_TRUE(completed_);
  }
};

INSTANTIATE_TEST_SUITE_P(
    AddressSorterPosix,
    AddressSorterPosixSyncOrAsyncTest,
    ::testing::Values(TestUDPClientSocket::ConnectMode::kSynchronous,
                      TestUDPClientSocket::ConnectMode::kAsynchronous));

// Rule 1: Avoid unusable destinations.
TEST_P(AddressSorterPosixSyncOrAsyncTest, Rule1) {
  AddMapping("10.0.0.231", "10.0.0.1");
  const char* const addresses[] = {"::1", "10.0.0.231", "127.0.0.1", nullptr};
  const int order[] = { 1, -1 };
  Verify(addresses, order);
}

// Rule 2: Prefer matching scope.
TEST_P(AddressSorterPosixSyncOrAsyncTest, Rule2) {
  AddMapping("3002::1", "4000::10");      // matching global
  AddMapping("ff32::1", "fe81::10");      // matching link-local
  AddMapping("fec1::1", "fec1::10");      // matching node-local
  AddMapping("3002::2", "::1");           // global vs. link-local
  AddMapping("fec1::2", "fe81::10");      // site-local vs. link-local
  AddMapping("8.0.0.1", "169.254.0.10");  // global vs. link-local
  // In all three cases, matching scope is preferred.
  const int order[] = { 1, 0, -1 };
  const char* const addresses1[] = {"3002::2", "3002::1", nullptr};
  Verify(addresses1, order);
  const char* const addresses2[] = {"fec1::2", "ff32::1", nullptr};
  Verify(addresses2, order);
  const char* const addresses3[] = {"8.0.0.1", "fec1::1", nullptr};
  Verify(addresses3, order);
}

// Rule 3: Avoid deprecated addresses.
TEST_P(AddressSorterPosixSyncOrAsyncTest, Rule3) {
  // Matching scope.
  AddMapping("3002::1", "4000::10");
  GetSourceInfo("4000::10")->deprecated = true;
  AddMapping("3002::2", "4000::20");
  const char* const addresses[] = {"3002::1", "3002::2", nullptr};
  const int order[] = { 1, 0, -1 };
  Verify(addresses, order);
}

// Rule 4: Prefer home addresses.
TEST_P(AddressSorterPosixSyncOrAsyncTest, Rule4) {
  AddMapping("3002::1", "4000::10");
  AddMapping("3002::2", "4000::20");
  GetSourceInfo("4000::20")->home = true;
  const char* const addresses[] = {"3002::1", "3002::2", nullptr};
  const int order[] = { 1, 0, -1 };
  Verify(addresses, order);
}

// Rule 5: Prefer matching label.
TEST_P(AddressSorterPosixSyncOrAsyncTest, Rule5) {
  AddMapping("::1", "::1");                       // matching loopback
  AddMapping("::ffff:1234:1", "::ffff:1234:10");  // matching IPv4-mapped
  AddMapping("2001::1", "::ffff:1234:10");        // Teredo vs. IPv4-mapped
  AddMapping("2002::1", "2001::10");              // 6to4 vs. Teredo
  const int order[] = { 1, 0, -1 };
  {
    const char* const addresses[] = {"2001::1", "::1", nullptr};
    Verify(addresses, order);
  }
  {
    const char* const addresses[] = {"2002::1", "::ffff:1234:1", nullptr};
    Verify(addresses, order);
  }
}

// Rule 6: Prefer higher precedence.
TEST_P(AddressSorterPosixSyncOrAsyncTest, Rule6) {
  AddMapping("::1", "::1");                       // loopback
  AddMapping("ff32::1", "fe81::10");              // multicast
  AddMapping("::ffff:1234:1", "::ffff:1234:10");  // IPv4-mapped
  AddMapping("2001::1", "2001::10");              // Teredo
  const char* const addresses[] = {"2001::1", "::ffff:1234:1", "ff32::1", "::1",
                                   nullptr};
  const int order[] = { 3, 2, 1, 0, -1 };
  Verify(addresses, order);
}

// Rule 7: Prefer native transport.
TEST_P(AddressSorterPosixSyncOrAsyncTest, Rule7) {
  AddMapping("3002::1", "4000::10");
  AddMapping("3002::2", "4000::20");
  GetSourceInfo("4000::20")->native = true;
  const char* const addresses[] = {"3002::1", "3002::2", nullptr};
  const int order[] = { 1, 0, -1 };
  Verify(addresses, order);
}

// Rule 8: Prefer smaller scope.
TEST_P(AddressSorterPosixSyncOrAsyncTest, Rule8) {
  // Matching scope. Should precede the others by Rule 2.
  AddMapping("fe81::1", "fe81::10");  // link-local
  AddMapping("3000::1", "4000::10");  // global
  // Mismatched scope.
  AddMapping("ff32::1", "4000::10");  // link-local
  AddMapping("ff35::1", "4000::10");  // site-local
  AddMapping("ff38::1", "4000::10");  // org-local
  const char* const addresses[] = {"ff38::1", "3000::1", "ff35::1",
                                   "ff32::1", "fe81::1", nullptr};
  const int order[] = { 4, 1, 3, 2, 0, -1 };
  Verify(addresses, order);
}

// Rule 9: Use longest matching prefix.
TEST_P(AddressSorterPosixSyncOrAsyncTest, Rule9) {
  AddMapping("3000::1", "3000:ffff::10");  // 16 bit match
  GetSourceInfo("3000:ffff::10")->prefix_length = 16;
  AddMapping("4000::1", "4000::10");       // 123 bit match, limited to 15
  GetSourceInfo("4000::10")->prefix_length = 15;
  AddMapping("4002::1", "4000::10");       // 14 bit match
  AddMapping("4080::1", "4000::10");       // 8 bit match
  const char* const addresses[] = {"4080::1", "4002::1", "4000::1", "3000::1",
                                   nullptr};
  const int order[] = { 3, 2, 1, 0, -1 };
  Verify(addresses, order);
}

// Rule 10: Leave the order unchanged.
TEST_P(AddressSorterPosixSyncOrAsyncTest, Rule10) {
  AddMapping("4000::1", "4000::10");
  AddMapping("4000::2", "4000::10");
  AddMapping("4000::3", "4000::10");
  const char* const addresses[] = {"4000::1", "4000::2", "4000::3", nullptr};
  const int order[] = { 0, 1, 2, -1 };
  Verify(addresses, order);
}

TEST_P(AddressSorterPosixSyncOrAsyncTest, MultipleRules) {
  AddMapping("::1", "::1");           // loopback
  AddMapping("ff32::1", "fe81::10");  // link-local multicast
  AddMapping("ff3e::1", "4000::10");  // global multicast
  AddMapping("4000::1", "4000::10");  // global unicast
  AddMapping("ff32::2", "fe81::20");  // deprecated link-local multicast
  GetSourceInfo("fe81::20")->deprecated = true;
  const char* const addresses[] = {"ff3e::1", "ff32::2", "4000::1", "ff32::1",
                                   "::1",     "8.0.0.1", nullptr};
  const int order[] = { 4, 3, 0, 2, 1, -1 };
  Verify(addresses, order);
}

TEST_P(AddressSorterPosixSyncOrAsyncTest, InputPortsAreMaintained) {
  AddMapping("::1", "::1");
  AddMapping("::2", "::2");
  AddMapping("::3", "::3");

  IPEndPoint endpoint1(ParseIP("::1"), /*port=*/111);
  IPEndPoint endpoint2(ParseIP("::2"), /*port=*/222);
  IPEndPoint endpoint3(ParseIP("::3"), /*port=*/333);

  std::vector<IPEndPoint> input = {endpoint1, endpoint2, endpoint3};
  std::vector<IPEndPoint> sorted;
  TestCompletionCallback callback;
  sorter_->Sort(input, base::BindOnce(&OnSortComplete, std::ref(completed_),
                                      &sorted, callback.callback()));
  callback.WaitForResult();

  EXPECT_THAT(sorted, testing::ElementsAre(endpoint1, endpoint2, endpoint3));
}

TEST_P(AddressSorterPosixSyncOrAsyncTest, AddressSorterPosixDestroyed) {
  AddMapping("::1", "::1");
  AddMapping("::2", "::2");
  AddMapping("::3", "::3");

  IPEndPoint endpoint1(ParseIP("::1"), /*port=*/111);
  IPEndPoint endpoint2(ParseIP("::2"), /*port=*/222);
  IPEndPoint endpoint3(ParseIP("::3"), /*port=*/333);

  std::vector<IPEndPoint> input = {endpoint1, endpoint2, endpoint3};
  std::vector<IPEndPoint> sorted;
  TestCompletionCallback callback;
  sorter_->Sort(input, base::BindOnce(&OnSortComplete, std::ref(completed_),
                                      &sorted, callback.callback()));
  sorter_.reset();
  base::RunLoop().RunUntilIdle();

  TestUDPClientSocket::ConnectMode connect_mode = GetParam();
  if (connect_mode == TestUDPClientSocket::ConnectMode::kAsynchronous) {
    EXPECT_FALSE(completed_);
  } else {
    EXPECT_TRUE(completed_);
  }
}

TEST_F(AddressSorterPosixTest, RandomAsyncSocketOrder) {
  SetConnectMode(TestUDPClientSocket::ConnectMode::kAsynchronousManual);
  std::vector<TestUDPClientSocket*> created_sockets;
  SetSocketCreateCallback(base::BindRepeating(
      [](std::vector<TestUDPClientSocket*>& created_sockets,
         TestUDPClientSocket* socket) { created_sockets.push_back(socket); },
      std::ref(created_sockets)));

  AddMapping("::1", "::1");
  AddMapping("::2", "::2");
  AddMapping("::3", "::3");

  IPEndPoint endpoint1(ParseIP("::1"), /*port=*/111);
  IPEndPoint endpoint2(ParseIP("::2"), /*port=*/222);
  IPEndPoint endpoint3(ParseIP("::3"), /*port=*/333);

  std::vector<IPEndPoint> input = {endpoint1, endpoint2, endpoint3};
  std::vector<IPEndPoint> sorted;
  TestCompletionCallback callback;
  sorter_->Sort(input, base::BindOnce(&OnSortComplete, std::ref(completed_),
                                      &sorted, callback.callback()));

  ASSERT_EQ(created_sockets.size(), 3u);
  created_sockets[1]->FinishConnect();
  created_sockets[2]->FinishConnect();
  created_sockets[0]->FinishConnect();

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(completed_);
}

// Regression test for https://crbug.com/1374387
TEST_F(AddressSorterPosixTest, IPAddressChangedSort) {
  SetConnectMode(TestUDPClientSocket::ConnectMode::kAsynchronousManual);
  std::vector<TestUDPClientSocket*> created_sockets;
  SetSocketCreateCallback(base::BindRepeating(
      [](std::vector<TestUDPClientSocket*>& created_sockets,
         TestUDPClientSocket* socket) { created_sockets.push_back(socket); },
      std::ref(created_sockets)));

  AddMapping("::1", "::1");
  AddMapping("::2", "::2");
  AddMapping("::3", "::3");

  IPEndPoint endpoint1(ParseIP("::1"), /*port=*/111);
  IPEndPoint endpoint2(ParseIP("::2"), /*port=*/222);
  IPEndPoint endpoint3(ParseIP("::3"), /*port=*/333);

  std::vector<IPEndPoint> input = {endpoint1, endpoint2, endpoint3};
  std::vector<IPEndPoint> sorted;
  TestCompletionCallback callback;
  sorter_->Sort(input, base::BindOnce(&OnSortComplete, std::ref(completed_),
                                      &sorted, callback.callback()));

  ASSERT_EQ(created_sockets.size(), 3u);
  created_sockets[0]->FinishConnect();
  // Trigger OnIPAddressChanged() to reset `source_map_`
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  base::RunLoop().RunUntilIdle();
  created_sockets[1]->FinishConnect();
  created_sockets[2]->FinishConnect();

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(completed_);
}

}  // namespace net
```