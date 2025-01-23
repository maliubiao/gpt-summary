Response:
My thinking process to analyze the provided C++ code snippet and generate the summary involved the following steps:

1. **Identify the Core Purpose:** The file name `host_resolver_manager_unittest.cc` immediately signals that this is a unit test file. The `net/dns` path points to the DNS resolution functionality within Chromium's network stack. Therefore, the primary function is to test the `HostResolverManager` class.

2. **Scan for Key Components and Patterns:** I quickly scanned the code for recurring elements:
    * `#include` directives:  These reveal the dependencies and the types of functionalities being tested. Headers related to testing (`gtest`, `gmock`, `base/test`), network operations (`net/base`, `net/dns`, `net/socket`), and core Chromium utilities (`base/`, `url/`) are prominent.
    * Class definitions: The `HostResolverManagerTest` class is central. Helper classes like `ResolveHostResponseHelper` and `LookupAttemptHostResolverProc` indicate testing of asynchronous operations and specific resolution scenarios. `TestHostResolverManager` suggests mocking or overriding the standard `HostResolverManager`.
    * Test macros: `TEST_F` is the standard Google Test macro, confirming the unit test nature.
    * Member variables in `HostResolverManagerTest`: `proc_`, `resolver_`, `request_context_`, `resolve_context_`. These hint at mocking the resolution process, the class under test, and the context in which resolutions happen.
    * Assertions and Expectations: `EXPECT_THAT`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE` are used to verify the behavior of the code under test. The arguments to `EXPECT_THAT` (e.g., `IsOk()`, `ElementsAre()`) provide specific criteria for success.
    * Asynchronous handling: The use of `base::RunLoop`, callbacks (`base::BindOnce`), and helper classes dealing with completion strongly indicate testing of asynchronous resolution.

3. **Analyze Key Functionalities and Concepts:** Based on the components identified above, I focused on understanding the key functionalities being tested:
    * **Basic Asynchronous Resolution:** The `AsynchronousLookup`, `AsynchronousIpv6Lookup`, and `AsynchronousAllFamilyLookup` tests demonstrate how the `HostResolverManager` handles successful DNS lookups for different address families.
    * **Error Handling:**  The `JobsClearedOnCompletion_Failure` test checks how the manager handles resolution failures.
    * **Cancellation and Network Changes:** The `JobsClearedOnCompletion_Abort` test verifies that ongoing resolutions are cancelled and cleaned up when a network change occurs.
    * **DNS Query Types:** The `DnsQueryType` test specifically targets the ability to request specific DNS record types (A, AAAA).
    * **Caching:**  While not explicitly a separate test in this snippet, the presence of `resolve_context_->host_resolver_cache()` and checks for `GetCacheHit` indicate that caching behavior is being tested implicitly within other tests. The `kUseHostResolverCache` feature flag further reinforces this.
    * **Localhost Resolution:** The `LocalhostIPV4IPV6LookupTest` specifically checks the correct resolution of "localhost".
    * **Concurrency Control:** The `CreateSerialResolver` method and tests involving multiple requests point to the testing of concurrency limits.
    * **Retries:** Although the default is to have retries, the `CreateSerialResolver` demonstrates the ability to test scenarios without retries.
    * **IPv6 Reachability:** The `TestHostResolverManager` class, overriding `StartGloballyReachableCheck`, is a clear indicator that testing IPv6 reachability detection is a feature.
    * **Stale DNS Cache:** The reference to `GetStaleInfo()` indicates tests are being performed around stale DNS entries.

4. **Consider JavaScript Relevance:** I looked for features that directly relate to how JavaScript interacts with DNS resolution in a browser environment:
    * `HostResolverManager` is the core component that the browser uses when JavaScript makes network requests (e.g., `fetch`, `XMLHttpRequest`). The tests ensure this component works correctly.
    * The handling of different address families (IPv4/IPv6) is relevant to ensuring websites are reachable regardless of the user's network configuration.
    * Caching is a key performance optimization for web browsing, and these tests help ensure the DNS cache works as expected, reducing latency for subsequent requests to the same domain.
    * Error handling is important for providing informative error messages to web pages when DNS resolution fails.

5. **Infer Input/Output and Usage Errors:**
    * **Input/Output:**  The tests implicitly demonstrate inputs (hostnames, DNS query types) and expected outputs (IP addresses, error codes). The `ResolveHostResponseHelper` provides a structured way to access the results.
    * **User/Programming Errors:**  I considered common mistakes developers might make when dealing with DNS or network requests:
        * Incorrect hostnames leading to `ERR_NAME_NOT_RESOLVED`.
        * Assuming immediate synchronous resolution when it's asynchronous.
        * Not handling potential DNS resolution errors in their code.
        * Issues with network connectivity.

6. **Trace User Steps (Debugging Clues):** I thought about how a user action in a browser might lead to this code being executed:
    * Typing a URL into the address bar.
    * Clicking a link.
    * A web page making a request using JavaScript (e.g., `fetch`).
    * The browser needing to resolve the hostname in the URL before establishing a connection.

7. **Structure the Summary:**  Finally, I organized my findings into the requested categories:
    * **Functionality:**  A high-level overview of what the code does.
    * **JavaScript Relation:** Specific examples of how the tested functionality relates to web browsing and JavaScript.
    * **Logical Inference (Input/Output):** Concrete examples based on the test cases.
    * **User/Programming Errors:** Practical examples of potential mistakes.
    * **User Operations/Debugging:**  A step-by-step trace of how a user action can trigger this code.
    * **Overall Function:** A concise summary for the "Part 1 of 21" context.

By following these steps, I could analyze the C++ code, understand its purpose within the Chromium network stack, and generate a comprehensive summary addressing all aspects of the prompt.
好的，这是对提供的 Chromium 网络栈源代码文件 `net/dns/host_resolver_manager_unittest.cc` 第一部分的分析：

**功能归纳:**

这个 C++ 代码文件是 Chromium 网络栈中 `HostResolverManager` 类的单元测试文件。它的主要功能是测试 `HostResolverManager` 类的各种行为和功能，包括：

* **异步主机名解析:** 测试 `HostResolverManager` 如何异步地解析主机名到 IP 地址，包括 IPv4 和 IPv6 地址。
* **DNS 查询类型:** 测试指定不同的 DNS 查询类型（例如 A 记录，AAAA 记录）是否能得到正确的结果。
* **缓存机制:**  虽然在此部分没有明确的测试用例，但代码中包含了与缓存相关的逻辑 (`resolve_context_->host_resolver_cache()`, `GetCacheHit`)，暗示了对 DNS 缓存机制的测试。
* **并发控制:** 测试 `HostResolverManager` 如何处理并发的 DNS 解析请求，以及最大并发连接数的限制。
* **错误处理:** 测试在 DNS 解析失败时的处理机制，例如 `ERR_NAME_NOT_RESOLVED`。
* **请求取消:** 测试在网络状态变化时（例如网络断开或 IP 地址变化）如何取消正在进行的 DNS 解析请求。
* **本地主机解析:** 测试对 "localhost" 等本地主机的特殊解析处理。
* **IPv6 可达性检测:**  通过 `TestHostResolverManager` 模拟 IPv6 的可达性，并影响解析器的行为。
* **DNS 别名 (CNAME):** 虽然在此部分没有明确的测试用例，但 `GetDnsAliasResults()` 的存在暗示了对 DNS 别名解析的测试。

**与 JavaScript 功能的关系及举例:**

`HostResolverManager` 是浏览器网络栈的核心组件之一，当 JavaScript 代码发起网络请求时（例如使用 `fetch` API 或 `XMLHttpRequest` 对象），浏览器会使用 `HostResolverManager` 来解析目标主机名。

**举例说明:**

假设一个 JavaScript 代码尝试访问 `https://www.example.com`:

1. **JavaScript 发起请求:**  JavaScript 代码调用 `fetch("https://www.example.com")`。
2. **URL 解析:** 浏览器解析 URL，提取出主机名 `www.example.com`。
3. **DNS 解析请求:**  浏览器的网络栈会调用 `HostResolverManager` 来解析 `www.example.com` 的 IP 地址。这里就会涉及到 `host_resolver_manager_unittest.cc` 中测试的异步解析逻辑。
4. **缓存检查:** `HostResolverManager` 可能会先检查本地 DNS 缓存，看是否已经解析过该主机名。
5. **系统 DNS 查询:** 如果缓存未命中，`HostResolverManager` 会发起系统 DNS 查询。
6. **IP 地址返回:**  系统 DNS 返回 `www.example.com` 的 IP 地址。
7. **连接建立:** 浏览器使用解析到的 IP 地址建立 TCP 连接，然后进行 TLS 握手等后续操作。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **测试用例 1:**  尝试解析主机名 "just.testing"。`proc_` (MockHostResolverProc) 被配置为返回 IP 地址 "192.168.1.42"。
* **测试用例 2:** 尝试解析主机名 "foo.test"，并指定 DNS 查询类型为 AAAA。`proc_` 被配置为返回 IPv6 地址 "2001:db8:2::"。
* **测试用例 3:**  尝试解析不存在的主机名 "nonexistent.test"。`proc_` 未配置该主机名。

**预期输出:**

* **测试用例 1:**  解析成功，返回包含 IP 地址 "192.168.1.42" 的 `AddressList` 或 `EndpointResults`。
* **测试用例 2:** 解析成功，返回包含 IPv6 地址 "2001:db8:2::" 的 `AddressList` 或 `EndpointResults`。
* **测试用例 3:** 解析失败，返回错误码 `ERR_NAME_NOT_RESOLVED`。

**用户或编程常见的使用错误:**

* **错误地假设 DNS 解析是同步的:** 开发者可能会错误地认为调用 DNS 解析后会立即得到结果，而实际上它是异步的，需要使用回调函数或者 Promise 来处理结果。
* **没有处理 DNS 解析失败的情况:** 开发者可能没有妥善处理 DNS 解析失败的情况，导致程序在无法解析主机名时崩溃或出现意外行为。例如，当网络不稳定或目标主机不存在时。
* **不合理地依赖本地 DNS 缓存:**  开发者可能会过度依赖本地 DNS 缓存，而没有考虑到缓存过期或者 DNS 记录更新的情况，导致访问到过时的 IP 地址。
* **在性能敏感的场景下进行大量的 DNS 解析:**  频繁地进行 DNS 解析会消耗资源并引入延迟。开发者应该尽量利用缓存机制来减少不必要的 DNS 查询。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 并回车:** 例如，用户输入 `www.example.com` 并按下回车键。
2. **浏览器解析 URL:** 浏览器解析输入的 URL，提取出协议、主机名和端口号等信息。
3. **发起 DNS 解析请求:** 浏览器网络栈中的相关代码（通常在 URLRequest 或其关联的类中）会调用 `HostResolverManager` 的方法来解析 `www.example.com` 的 IP 地址。
4. **`HostResolverManager` 创建解析任务:** `HostResolverManager` 根据请求参数创建一个解析任务，并可能将其放入待执行队列中。
5. **系统 DNS 查询 (如果缓存未命中):** 如果本地缓存没有对应的记录，`HostResolverManager` 会调用底层的操作系统 DNS 解析接口，或者使用配置的 DNS 服务器进行查询。
6. **MockHostResolverProc 的介入 (在测试环境中):**  在单元测试环境中，`MockHostResolverProc` ( `proc_` ) 会拦截实际的系统 DNS 查询，并根据预先配置的规则返回模拟的 IP 地址或错误。 这使得测试可以独立于实际的网络环境运行。
7. **测试断言:**  单元测试代码会使用 `EXPECT_THAT` 等断言宏来验证 `HostResolverManager` 的行为是否符合预期，例如是否成功解析了主机名，返回了正确的 IP 地址，或者在解析失败时返回了预期的错误码。

**总结一下它的功能:**

这个代码文件是 `HostResolverManager` 类的单元测试，它通过模拟不同的网络场景和 DNS 响应，来验证 `HostResolverManager` 在异步主机名解析、DNS 查询类型处理、错误处理、并发控制以及与缓存相关的各个方面的功能是否正常。  它是确保 Chromium 网络栈中 DNS 解析功能稳定可靠的重要组成部分。

### 提示词
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共21部分，请归纳一下它的功能
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

#include "net/dns/host_resolver_manager_unittest.h"

#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "base/auto_reset.h"
#include "base/containers/contains.h"
#include "base/containers/to_vector.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/numerics/safe_conversions.h"
#include "base/rand_util.h"
#include "base/ranges/algorithm.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/mock_callback.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_clock.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/test/test_timeouts.h"
#include "base/threading/thread_restrictions.h"
#include "base/time/time.h"
#include "base/timer/mock_timer.h"
#include "base/values.h"
#include "build/build_config.h"
#include "net/base/address_family.h"
#include "net/base/address_list.h"
#include "net/base/connection_endpoint_metadata_test_util.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/mock_network_change_notifier.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_change_notifier.h"
#include "net/base/network_interfaces.h"
#include "net/base/schemeful_site.h"
#include "net/dns/address_sorter.h"
#include "net/dns/dns_client.h"
#include "net/dns/dns_config.h"
#include "net/dns/dns_test_util.h"
#include "net/dns/dns_util.h"
#include "net/dns/host_resolver.h"
#include "net/dns/host_resolver_cache.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/host_resolver_internal_result_test_util.h"
#include "net/dns/host_resolver_results_test_util.h"
#include "net/dns/host_resolver_system_task.h"
#include "net/dns/mock_host_resolver.h"
#include "net/dns/mock_mdns_client.h"
#include "net/dns/mock_mdns_socket_factory.h"
#include "net/dns/public/dns_config_overrides.h"
#include "net/dns/public/dns_over_https_config.h"
#include "net/dns/public/dns_protocol.h"
#include "net/dns/public/dns_query_type.h"
#include "net/dns/public/doh_provider_entry.h"
#include "net/dns/public/mdns_listener_update_type.h"
#include "net/dns/public/resolve_error_info.h"
#include "net/dns/public/secure_dns_mode.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/dns/resolve_context.h"
#include "net/dns/test_dns_config_service.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

#if BUILDFLAG(ENABLE_MDNS)
#include "net/dns/mdns_client_impl.h"
#endif  // BUILDFLAG(ENABLE_MDNS)

using net::test::IsError;
using net::test::IsOk;
using ::testing::_;
using ::testing::AllOf;
using ::testing::AnyOf;
using ::testing::Between;
using ::testing::ByMove;
using ::testing::Contains;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::Optional;
using ::testing::Pair;
using ::testing::Pointee;
using ::testing::Property;
using ::testing::Return;
using ::testing::UnorderedElementsAre;

namespace net {

namespace {

const size_t kMaxJobs = 10u;
const size_t kMaxRetryAttempts = 4u;

HostResolverSystemTask::Params DefaultParams(
    scoped_refptr<HostResolverProc> resolver_proc) {
  return HostResolverSystemTask::Params(std::move(resolver_proc),
                                        kMaxRetryAttempts);
}

class ResolveHostResponseHelper {
 public:
  using Callback =
      base::OnceCallback<void(CompletionOnceCallback completion_callback,
                              int error)>;

  ResolveHostResponseHelper() = default;
  explicit ResolveHostResponseHelper(
      std::unique_ptr<HostResolver::ResolveHostRequest> request)
      : request_(std::move(request)) {
    top_level_result_error_ = request_->Start(base::BindOnce(
        &ResolveHostResponseHelper::OnComplete, base::Unretained(this)));
  }
  ResolveHostResponseHelper(
      std::unique_ptr<HostResolver::ResolveHostRequest> request,
      Callback custom_callback)
      : request_(std::move(request)) {
    top_level_result_error_ = request_->Start(
        base::BindOnce(std::move(custom_callback),
                       base::BindOnce(&ResolveHostResponseHelper::OnComplete,
                                      base::Unretained(this))));
  }

  ResolveHostResponseHelper(const ResolveHostResponseHelper&) = delete;
  ResolveHostResponseHelper& operator=(const ResolveHostResponseHelper&) =
      delete;

  bool complete() const { return top_level_result_error_ != ERR_IO_PENDING; }

  int top_level_result_error() {
    WaitForCompletion();
    return top_level_result_error_;
  }

  int result_error() {
    WaitForCompletion();
    return request_->GetResolveErrorInfo().error;
  }

  HostResolver::ResolveHostRequest* request() { return request_.get(); }

  void CancelRequest() {
    DCHECK(request_);
    DCHECK(!complete());

    request_ = nullptr;
  }

  void OnComplete(int error) {
    DCHECK(!complete());
    top_level_result_error_ = error;

    run_loop_.Quit();
  }

 private:
  void WaitForCompletion() {
    DCHECK(request_);
    if (complete()) {
      return;
    }
    run_loop_.Run();
    DCHECK(complete());
  }

  std::unique_ptr<HostResolver::ResolveHostRequest> request_;
  int top_level_result_error_ = ERR_IO_PENDING;
  base::RunLoop run_loop_;
};

// Using LookupAttemptHostResolverProc simulate very long lookups, and control
// which attempt resolves the host.
class LookupAttemptHostResolverProc : public HostResolverProc {
 public:
  LookupAttemptHostResolverProc(HostResolverProc* previous,
                                int attempt_number_to_resolve,
                                int total_attempts)
      : HostResolverProc(previous),
        attempt_number_to_resolve_(attempt_number_to_resolve),
        total_attempts_(total_attempts),
        all_done_(&lock_),
        blocked_attempt_signal_(&lock_) {}

  // Test harness will wait for all attempts to finish before checking the
  // results.
  void WaitForAllAttemptsToFinish() {
    base::AutoLock auto_lock(lock_);
    while (total_attempts_resolved_ != total_attempts_) {
      all_done_.Wait();
    }
  }

  void WaitForNAttemptsToBeBlocked(int n) {
    base::AutoLock auto_lock(lock_);
    while (num_attempts_waiting_ < n) {
      blocked_attempt_signal_.Wait();
    }
  }

  // All attempts will wait for an attempt to resolve the host.
  void WaitForAnAttemptToComplete() {
    {
      base::AutoLock auto_lock(lock_);
      base::ScopedAllowBaseSyncPrimitivesForTesting
          scoped_allow_base_sync_primitives;
      while (resolved_attempt_number_ == 0)
        all_done_.Wait();
    }
    all_done_.Broadcast();  // Tell all waiting attempts to proceed.
  }

  // Returns the number of attempts that have finished the Resolve() method.
  int GetTotalAttemptsResolved() {
    base::AutoLock auto_lock(lock_);
    return total_attempts_resolved_;
  }

  // Sets the resolved attempt number and unblocks waiting
  // attempts.
  void SetResolvedAttemptNumber(int n) {
    base::AutoLock auto_lock(lock_);
    EXPECT_EQ(0, resolved_attempt_number_);
    resolved_attempt_number_ = n;
    all_done_.Broadcast();
  }

  // HostResolverProc methods.
  int Resolve(const std::string& host,
              AddressFamily address_family,
              HostResolverFlags host_resolver_flags,
              AddressList* addrlist,
              int* os_error) override {
    bool wait_for_right_attempt_to_complete = true;
    {
      base::AutoLock auto_lock(lock_);
      ++current_attempt_number_;
      ++num_attempts_waiting_;
      if (current_attempt_number_ == attempt_number_to_resolve_) {
        resolved_attempt_number_ = current_attempt_number_;
        wait_for_right_attempt_to_complete = false;
      }
    }

    blocked_attempt_signal_.Broadcast();

    if (wait_for_right_attempt_to_complete)
      // Wait for the attempt_number_to_resolve_ attempt to resolve.
      WaitForAnAttemptToComplete();

    int result = ResolveUsingPrevious(host, address_family, host_resolver_flags,
                                      addrlist, os_error);

    {
      base::AutoLock auto_lock(lock_);
      ++total_attempts_resolved_;
      --num_attempts_waiting_;
    }

    all_done_.Broadcast();  // Tell all attempts to proceed.

    // Since any negative number is considered a network error, with -1 having
    // special meaning (ERR_IO_PENDING). We could return the attempt that has
    // resolved the host as a negative number. For example, if attempt number 3
    // resolves the host, then this method returns -4.
    if (result == OK)
      return -1 - resolved_attempt_number_;
    else
      return result;
  }

 protected:
  ~LookupAttemptHostResolverProc() override = default;

 private:
  int attempt_number_to_resolve_;
  int current_attempt_number_ = 0;  // Incremented whenever Resolve is called.
  int total_attempts_;
  int total_attempts_resolved_ = 0;
  int resolved_attempt_number_ = 0;
  int num_attempts_waiting_ = 0;

  // All attempts wait for right attempt to be resolve.
  base::Lock lock_;
  base::ConditionVariable all_done_;
  base::ConditionVariable blocked_attempt_signal_;
};

// TestHostResolverManager's sole purpose is to mock the IPv6 reachability test.
// By default, this pretends that IPv6 is globally reachable.
// This class is necessary so unit tests run the same on dual-stack machines as
// well as IPv4 only machines.
class TestHostResolverManager : public HostResolverManager {
 public:
  TestHostResolverManager(const HostResolver::ManagerOptions& options,
                          SystemDnsConfigChangeNotifier* notifier,
                          NetLog* net_log,
                          bool ipv6_reachable = true,
                          bool ipv4_reachable = true,
                          bool is_async = false)
      : HostResolverManager(options, notifier, net_log),
        ipv6_reachable_(ipv6_reachable),
        ipv4_reachable_(ipv4_reachable),
        is_async_(is_async) {}

  ~TestHostResolverManager() override = default;

 private:
  const bool ipv6_reachable_;
  const bool ipv4_reachable_;
  const bool is_async_;

  int StartGloballyReachableCheck(const IPAddress& dest,
                                  const NetLogWithSource& net_log,
                                  ClientSocketFactory* client_socket_factory,
                                  CompletionOnceCallback callback) override {
    int rv = OK;
    if (dest.IsIPv6()) {
      rv = ipv6_reachable_ ? OK : ERR_FAILED;
    } else {
      rv = ipv4_reachable_ ? OK : ERR_FAILED;
    }
    if (is_async_) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(std::move(callback), rv));
      return ERR_IO_PENDING;
    }
    return rv;
  }
};

bool HasAddress(const IPAddress& search_address,
                const std::vector<IPEndPoint>& addresses) {
  for (const auto& address : addresses) {
    if (search_address == address.address())
      return true;
  }
  return false;
}

void TestBothLoopbackIPs(const std::string& host) {
  std::vector<IPEndPoint> addresses;
  EXPECT_TRUE(ResolveLocalHostname(host, &addresses));
  EXPECT_EQ(2u, addresses.size());
  EXPECT_TRUE(HasAddress(IPAddress::IPv4Localhost(), addresses));
  EXPECT_TRUE(HasAddress(IPAddress::IPv6Localhost(), addresses));
}

// Returns the DoH provider entry in `DohProviderEntry::GetList()` that matches
// `provider`. Crashes if there is no matching entry.
const DohProviderEntry& GetDohProviderEntryForTesting(
    std::string_view provider) {
  auto provider_list = DohProviderEntry::GetList();
  auto it =
      base::ranges::find(provider_list, provider, &DohProviderEntry::provider);
  CHECK(it != provider_list.end());
  return **it;
}

void DisableHostResolverCache(base::test::ScopedFeatureList& feature_list) {
  // The HappyEyeballsV3 feature depends on the UseHostResolverCache feature.
  // Disable them together for tests that disables the UseHostResolverCache
  // feature.
  feature_list.InitWithFeatures(
      /*enabled_features=*/{},
      /*disabled_features=*/{features::kUseHostResolverCache,
                             features::kHappyEyeballsV3});
}

}  // namespace

HostResolverManagerTest::HostResolverManagerTest(
    base::test::TaskEnvironment::TimeSource time_source)
    : TestWithTaskEnvironment(time_source),
      proc_(base::MakeRefCounted<MockHostResolverProc>()) {}

HostResolverManagerTest::~HostResolverManagerTest() = default;

void HostResolverManagerTest::CreateResolver(bool check_ipv6_on_wifi) {
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    true /* ipv6_reachable */,
                                    check_ipv6_on_wifi);
}

void HostResolverManagerTest::DestroyResolver() {
  if (!resolver_) {
    return;
  }

  resolver_->DeregisterResolveContext(resolve_context_.get());
  resolver_ = nullptr;
}

  // This HostResolverManager will only allow 1 outstanding resolve at a time
  // and perform no retries.
void HostResolverManagerTest::CreateSerialResolver(bool check_ipv6_on_wifi,
                                                   bool ipv6_reachable,
                                                   bool is_async) {
  HostResolverSystemTask::Params params = DefaultParams(proc_);
  params.max_retry_attempts = 0u;
  CreateResolverWithLimitsAndParams(1u, params, ipv6_reachable,
                                    check_ipv6_on_wifi, is_async);
}

void HostResolverManagerTest::SetUp() {
  request_context_ = CreateTestURLRequestContextBuilder()->Build();
  resolve_context_ = std::make_unique<ResolveContext>(
      request_context_.get(), true /* enable_caching */);
  CreateResolver();
}

void HostResolverManagerTest::TearDown() {
  if (resolver_) {
    EXPECT_EQ(0u, resolver_->num_running_dispatcher_jobs_for_tests());
  }
  DestroyResolver();
  EXPECT_FALSE(proc_->HasBlockedRequests());
}

void HostResolverManagerTest::CreateResolverWithLimitsAndParams(
    size_t max_concurrent_resolves,
    const HostResolverSystemTask::Params& params,
    bool ipv6_reachable,
    bool check_ipv6_on_wifi,
    bool is_async) {
  HostResolver::ManagerOptions options = DefaultOptions();
  options.max_concurrent_resolves = max_concurrent_resolves;
  options.check_ipv6_on_wifi = check_ipv6_on_wifi;

  CreateResolverWithOptionsAndParams(std::move(options), params, ipv6_reachable,
                                     is_async);
}

HostResolver::ManagerOptions HostResolverManagerTest::DefaultOptions() {
  HostResolver::ManagerOptions options;
  options.max_concurrent_resolves = kMaxJobs;
  options.max_system_retry_attempts = kMaxRetryAttempts;
  return options;
}

void HostResolverManagerTest::CreateResolverWithOptionsAndParams(
    HostResolver::ManagerOptions options,
    const HostResolverSystemTask::Params& params,
    bool ipv6_reachable,
    bool is_async,
    bool ipv4_reachable) {
  // Use HostResolverManagerDnsTest if enabling DNS client.
  DCHECK(!options.insecure_dns_client_enabled);

  DestroyResolver();

  resolver_ = std::make_unique<TestHostResolverManager>(
      options, nullptr /* notifier */, nullptr /* net_log */, ipv6_reachable,
      ipv4_reachable, is_async);
  resolver_->set_host_resolver_system_params_for_test(params);
  resolver_->RegisterResolveContext(resolve_context_.get());
}

size_t HostResolverManagerTest::num_running_dispatcher_jobs() const {
  DCHECK(resolver_.get());
  return resolver_->num_running_dispatcher_jobs_for_tests();
}

void HostResolverManagerTest::set_allow_fallback_to_systemtask(
    bool allow_fallback_to_systemtask) {
  DCHECK(resolver_.get());
  resolver_->allow_fallback_to_systemtask_ = allow_fallback_to_systemtask;
}

int HostResolverManagerTest::StartIPv6ReachabilityCheck(
    const NetLogWithSource& net_log,
    raw_ptr<ClientSocketFactory> client_socket_factory,
    CompletionOnceCallback callback) {
  return resolver_->StartIPv6ReachabilityCheck(net_log, client_socket_factory,
                                               std::move(callback));
}

bool HostResolverManagerTest::GetLastIpv6ProbeResult() {
  return resolver_->last_ipv6_probe_result_;
}

void HostResolverManagerTest::PopulateCache(const HostCache::Key& key,
                                            IPEndPoint endpoint) {
  resolver_->CacheResult(resolve_context_->host_cache(), key,
                         HostCache::Entry(OK, {endpoint}, /*aliases=*/{},
                                          HostCache::Entry::SOURCE_UNKNOWN),
                         base::Seconds(1));
}

const std::pair<const HostCache::Key, HostCache::Entry>*
HostResolverManagerTest::GetCacheHit(const HostCache::Key& key) {
  DCHECK(resolve_context_->host_cache());
  return resolve_context_->host_cache()->LookupStale(
      key, base::TimeTicks(), nullptr, false /* ignore_secure */);
}

void HostResolverManagerTest::MakeCacheStale() {
  DCHECK(resolve_context_->host_cache());
  resolve_context_->host_cache()->Invalidate();
}

IPEndPoint HostResolverManagerTest::CreateExpected(
    const std::string& ip_literal,
    uint16_t port) {
  IPAddress ip;
  bool result = ip.AssignFromIPLiteral(ip_literal);
  DCHECK(result);
  return IPEndPoint(ip, port);
}

TEST_F(HostResolverManagerTest, AsynchronousLookup) {
  base::test::ScopedFeatureList feature_list(features::kUseHostResolverCache);

  proc_->AddRuleForAllFamilies("just.testing", "192.168.1.42");
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.top_level_result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.42", 80)));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.1.42", 80))))));
  EXPECT_FALSE(response.request()->GetStaleInfo());

  EXPECT_EQ("just.testing", proc_->GetCaptureList()[0].hostname);

  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result =
      GetCacheHit(HostCache::Key("just.testing", DnsQueryType::UNSPECIFIED,
                                 0 /* host_resolver_flags */,
                                 HostResolverSource::ANY,
                                 NetworkAnonymizationKey()));
  EXPECT_TRUE(cache_result);

  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  "just.testing", NetworkAnonymizationKey(), DnsQueryType::A,
                  HostResolverSource::SYSTEM, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  "just.testing", DnsQueryType::A,
                  HostResolverInternalResult::Source::kUnknown, _, _,
                  ElementsAre(CreateExpected("192.168.1.42", 0)))));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  "just.testing", NetworkAnonymizationKey(), DnsQueryType::AAAA,
                  HostResolverSource::SYSTEM, /*secure=*/false),
              Pointee(ExpectHostResolverInternalErrorResult(
                  "just.testing", DnsQueryType::AAAA,
                  HostResolverInternalResult::Source::kUnknown, _, _,
                  ERR_NAME_NOT_RESOLVED)));
}

// TODO(crbug.com/40181080): Confirm scheme behavior once it affects behavior.
TEST_F(HostResolverManagerTest, AsynchronousLookupWithScheme) {
  proc_->AddRuleForAllFamilies("host.test", "192.168.1.42");
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpScheme, "host.test", 80),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.top_level_result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.42", 80)));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.1.42", 80))))));
  EXPECT_FALSE(response.request()->GetStaleInfo());

  EXPECT_EQ("host.test", proc_->GetCaptureList()[0].hostname);

  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result =
      GetCacheHit(
          HostCache::Key(url::SchemeHostPort(url::kHttpScheme, "host.test", 80),
                         DnsQueryType::UNSPECIFIED, 0 /* host_resolver_flags */,
                         HostResolverSource::ANY, NetworkAnonymizationKey()));
  EXPECT_TRUE(cache_result);
}

TEST_F(HostResolverManagerTest, AsynchronousIpv6Lookup) {
  base::test::ScopedFeatureList feature_list(features::kUseHostResolverCache);

  proc_->AddRuleForAllFamilies("foo.test", "2001:db8:1::");
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpScheme, "foo.test", 80),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              Pointee(ElementsAre(ExpectEndpointResult(
                  ElementsAre(CreateExpected("2001:db8:1::", 80))))));

  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  "foo.test", NetworkAnonymizationKey(), DnsQueryType::A,
                  HostResolverSource::SYSTEM, /*secure=*/false),
              Pointee(ExpectHostResolverInternalErrorResult(
                  "foo.test", DnsQueryType::A,
                  HostResolverInternalResult::Source::kUnknown, _, _,
                  ERR_NAME_NOT_RESOLVED)));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  "foo.test", NetworkAnonymizationKey(), DnsQueryType::AAAA,
                  HostResolverSource::SYSTEM, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  "foo.test", DnsQueryType::AAAA,
                  HostResolverInternalResult::Source::kUnknown, _, _,
                  ElementsAre(CreateExpected("2001:db8:1::", 0)))));
}

TEST_F(HostResolverManagerTest, AsynchronousAllFamilyLookup) {
  base::test::ScopedFeatureList feature_list(features::kUseHostResolverCache);

  proc_->AddRuleForAllFamilies("foo.test", "192.168.1.43,2001:db8:2::");
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpScheme, "foo.test", 80),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              Pointee(ElementsAre(ExpectEndpointResult(
                  UnorderedElementsAre(CreateExpected("2001:db8:2::", 80),
                                       CreateExpected("192.168.1.43", 80))))));

  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  "foo.test", NetworkAnonymizationKey(), DnsQueryType::A,
                  HostResolverSource::SYSTEM, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  "foo.test", DnsQueryType::A,
                  HostResolverInternalResult::Source::kUnknown, _, _,
                  ElementsAre(CreateExpected("192.168.1.43", 0)))));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  "foo.test", NetworkAnonymizationKey(), DnsQueryType::AAAA,
                  HostResolverSource::SYSTEM, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  "foo.test", DnsQueryType::AAAA,
                  HostResolverInternalResult::Source::kUnknown, _, _,
                  ElementsAre(CreateExpected("2001:db8:2::", 0)))));
}

TEST_F(HostResolverManagerTest, JobsClearedOnCompletion) {
  proc_->AddRuleForAllFamilies("just.testing", "192.168.1.42");
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_EQ(1u, resolver_->num_jobs_for_testing());

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_EQ(0u, resolver_->num_jobs_for_testing());
}

TEST_F(HostResolverManagerTest, JobsClearedOnCompletion_MultipleRequests) {
  proc_->AddRuleForAllFamilies("just.testing", "192.168.1.42");
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response1(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ResolveHostResponseHelper response2(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_EQ(1u, resolver_->num_jobs_for_testing());

  EXPECT_THAT(response1.result_error(), IsOk());
  EXPECT_THAT(response2.result_error(), IsOk());
  EXPECT_EQ(0u, resolver_->num_jobs_for_testing());
}

TEST_F(HostResolverManagerTest, JobsClearedOnCompletion_Failure) {
  proc_->AddRuleForAllFamilies(std::string(),
                               "0.0.0.1");  // Default to failures.
  proc_->SignalMultiple(1u);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_EQ(1u, resolver_->num_jobs_for_testing());

  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_EQ(0u, resolver_->num_jobs_for_testing());
}

TEST_F(HostResolverManagerTest, JobsClearedOnCompletion_Abort) {
  proc_->AddRuleForAllFamilies("just.testing", "192.168.1.42");

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("just.testing", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_EQ(1u, resolver_->num_jobs_for_testing());

  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  proc_->SignalMultiple(1u);

  EXPECT_THAT(response.result_error(), IsError(ERR_NETWORK_CHANGED));
  EXPECT_EQ(0u, resolver_->num_jobs_for_testing());
}

TEST_F(HostResolverManagerTest, DnsQueryType) {
  proc_->AddRule("host", ADDRESS_FAMILY_IPV4, "192.168.1.20");
  proc_->AddRule("host", ADDRESS_FAMILY_IPV6, "::5");

  HostResolver::ResolveHostParameters parameters;

  parameters.dns_query_type = DnsQueryType::A;
  ResolveHostResponseHelper v4_response(resolver_->CreateRequest(
      HostPortPair("host", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));

  parameters.dns_query_type = DnsQueryType::AAAA;
  ResolveHostResponseHelper v6_response(resolver_->CreateRequest(
      HostPortPair("host", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));

  proc_->SignalMultiple(2u);

  EXPECT_THAT(v4_response.result_error(), IsOk());
  EXPECT_THAT(v4_response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.20", 80)));
  EXPECT_THAT(v4_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.1.20", 80))))));

  EXPECT_THAT(v6_response.result_error(), IsOk());
  EXPECT_THAT(v6_response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("::5", 80)));
  EXPECT_THAT(v6_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("::5", 80))))));
}

TEST_F(HostResolverManagerTest, DnsQueryWithoutAliases) {
  proc_->AddRule("host", ADDRESS_FAMILY_IPV4, "192.168.1.20");

  HostResolver::ResolveHostParameters parameters;

  parameters.dns_query_type = DnsQueryType::A;
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));

  proc_->SignalMultiple(1u);

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.20", 80)));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.1.20", 80))))));
  EXPECT_THAT(response.request()->GetDnsAliasResults(),
              testing::Pointee(testing::IsEmpty()));
}

void HostResolverManagerTest::LocalhostIPV4IPV6LookupTest(bool is_async) {
  CreateResolverWithLimitsAndParams(kMaxJobs, DefaultParams(proc_),
                                    true /* ipv6_reachable */,
                                    true /* check_ipv6_on_wifi */, is_async);
  HostResolver::ResolveHostParameters parameters;

  parameters.dns_query_type = DnsQueryType::A;
  ResolveHostResponseHelper v4_v4_response(resolver_->CreateRequest(
      HostPortPair("localhost", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  EXPECT_THAT(v4_v4_response.result_error(), IsOk());
  EXPECT_THAT(v4_v4_response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("127.0.0.1", 80)));
  EXPECT_THAT(v4_v4_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("127.0.0.1", 80))))));

  parameters.dns_query_type = DnsQueryType::AAAA;
  ResolveHostResponseHelper v4_v6_response(resolver_->CreateRequest(
      HostPortPair("localhost", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  EXPECT_THAT(v4_v6_response.result_error(), IsOk());
  EXPECT_THAT(v4_v6_response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("::1", 80)));
  EXPECT_THAT(v4_v6_response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("::1", 80))))));

  ResolveHostResponseHelper v4_unsp_response(resolver_->CreateRequest(
      HostPortPair("localhost", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(v4_unsp_response.result_error(), IsOk());
  EXPECT_THAT(v4_unsp_response.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
```