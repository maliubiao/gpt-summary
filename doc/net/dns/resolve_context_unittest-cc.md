Response:
Let's break down the thought process for analyzing this C++ unittest file and generating the summary.

**1. Understanding the Request:**

The core of the request is to analyze the functionality of `net/dns/resolve_context_unittest.cc`. The request also asks for specific points like:

* Relationship to JavaScript.
* Logical inference with input/output.
* Common user/programming errors.
* Debugging steps to reach this code.
* A summary of its functionality (for this first part).

**2. Initial Code Scan and Keyword Identification:**

The first step is to skim the code and look for key terms and patterns. Keywords like `TEST_F`, `EXPECT_TRUE`, `EXPECT_FALSE`, `ASSERT_TRUE`, `ASSERT_EQ`, `DnsConfig`, `DnsSession`, `ResolveContext`, `RecordServerSuccess`, `RecordServerFailure`, `DohServerAvailability`, `InvalidateCachesAndPerSessionData`, `GetDohIterator`, `GetClassicDnsIterator`, `HostCache`, `HostResolverCache`, and various classes related to DNS and networking are immediately apparent. These provide strong hints about the file's purpose.

**3. Identifying the Core Subject: `ResolveContext`:**

The class `ResolveContextTest` clearly focuses on testing the `ResolveContext` class. This becomes the central point of the analysis.

**4. Deciphering the Tests:**

Each `TEST_F` function represents a specific test case. Analyzing the names and the operations within each test case reveals different aspects of `ResolveContext`'s functionality:

* **`ReusedSessionPointer`:** Deals with how `ResolveContext` handles a `DnsSession` pointer being reused after the original session is invalidated.
* **`DohServerAvailability_*`:** A series of tests focusing on how `ResolveContext` tracks the availability of DNS-over-HTTPS (DoH) servers based on successes and failures. Pay attention to `RecordServerSuccess`, `RecordServerFailure`, and `GetDohServerAvailability`.
* **`DohServerIndexToUse_*`:** These tests explore how `ResolveContext` selects which DoH server to use in different scenarios, including secure mode.
* **`StartDohAutoupgradeSuccessTimer`:**  Tests the timer used for tracking successful DoH autoupgrades.
* **`DohServerAvailabilityNotification`:** Checks if `ResolveContext` correctly notifies observers about changes in DoH server availability.
* **`InvalidateCachesAndPerSessionData*`:** Examines the behavior of invalidating caches and per-session data, both with a new session and the same session. This highlights the distinction between global caches and session-specific data.
* **`Failures_*`:** A set of tests dedicated to how `ResolveContext` handles failures of traditional DNS servers, including consecutive and non-consecutive failures, and scenarios with different or no sessions.
* **`TwoFailures`:** A more specific test of how server preference changes with multiple server failures.

**5. Relating to Networking Concepts:**

The test cases clearly demonstrate features related to DNS resolution, including:

* **DNS-over-HTTPS (DoH):**  A significant portion of the tests focuses on DoH server management.
* **DNS Session Management:** The concept of a `DnsSession` and its lifecycle is important.
* **Server Availability Tracking:** `ResolveContext` keeps track of which DNS servers (both traditional and DoH) are considered available.
* **Server Selection/Preference:** The tests show how failures influence which server is tried next.
* **Caching:**  The `InvalidateCachesAndPerSessionData` tests directly deal with the Host Cache and Host Resolver Cache.
* **Network Change Notifications:** The `DohServerAvailabilityNotification` test uses the `NetworkChangeNotifier`.

**6. Addressing Specific Questions in the Request:**

* **JavaScript Relationship:**  While the C++ code itself doesn't directly interact with JavaScript, the functionality it tests (DNS resolution) is crucial for web browsing, which JavaScript heavily relies on. JavaScript uses browser APIs to make network requests, and the underlying DNS resolution is handled by code like this.
* **Logical Inference:** Choose a specific test case (e.g., `DohServerAvailability_RecordedSuccess`) and describe the setup, the actions, and the expected outcomes.
* **User/Programming Errors:** Think about what could go wrong when using or interacting with this kind of system. Incorrect DNS configurations, network issues, and assumptions about caching are good examples.
* **Debugging Steps:** Consider the user's perspective (e.g., a website not loading) and trace back the steps that might lead to investigating the DNS resolution process.

**7. Summarizing Functionality (for Part 1):**

Based on the analysis of the tests, the core functionality of the file (and thus `ResolveContext`) is centered around managing DNS resolution, especially concerning DoH servers. This includes tracking their availability, handling successes and failures, and managing the lifecycle of DNS sessions.

**8. Structuring the Output:**

Organize the findings logically, starting with the main purpose of the file, then elaborating on specific functionalities, addressing the specific questions in the request, and finally providing the summary. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus too much on individual tests in isolation.
* **Correction:**  Shift focus to the overall purpose of `ResolveContext` and how the tests collectively demonstrate its features.
* **Initial thought:**  Overlook the connection to JavaScript.
* **Correction:**  Realize the indirect but crucial relationship through web browsing and network requests.
* **Initial thought:**  Provide too technical an explanation for user errors.
* **Correction:** Frame user errors in terms of common user experiences and misconfigurations.

By following this structured thought process,  the detailed analysis and summary presented in the example answer can be effectively generated.这是 `net/dns/resolve_context_unittest.cc` 文件的第一部分，该文件是 Chromium 网络栈的一部分，专门用于测试 `net::ResolveContext` 类的功能。

**它的主要功能是：**

1. **测试 `ResolveContext` 类对 DNS-over-HTTPS (DoH) 服务器可用性的管理:**
   - 测试如何记录 DoH 服务器的成功和失败状态 (`RecordServerSuccess`, `RecordServerFailure`)。
   - 测试如何根据成功和失败状态判断 DoH 服务器是否可用 (`GetDohServerAvailability`, `NumAvailableDohServers`)。
   - 测试在不同 `DnsSession` 情况下 DoH 服务器可用性的隔离。
   - 测试在自动升级到 DoH 时的计时器功能 (`StartDohAutoupgradeSuccessTimer`)。
   - 测试 DoH 服务器可用性变化时是否会发出通知 (`DohServerAvailabilityNotification`)。
   - 测试如何选择可用的 DoH 服务器进行连接 (`GetDohIterator`)，包括在安全模式下的选择。

2. **测试 `ResolveContext` 类对 DNS 会话 (`DnsSession`) 的管理:**
   - 测试当同一个内存地址被用于新的 `DnsSession` 时，`ResolveContext` 如何处理旧会话数据的失效 (`ReusedSessionPointer`)。
   - 测试 `InvalidateCachesAndPerSessionData` 函数如何清理缓存和与特定会话相关的数据，以及网络变化是否会影响清理行为。

3. **测试 `ResolveContext` 类对传统 DNS 服务器故障的处理:**
   - 测试在连续多次请求传统 DNS 服务器失败后，`ResolveContext` 如何调整服务器选择策略，避免一直尝试失败的服务器 (`Failures_Consecutive`)。
   - 测试在非连续失败的情况下，`ResolveContext` 如何处理服务器选择 (`Failures_NonConsecutive`)。
   - 测试在没有 `DnsSession` 或 `DnsSession` 不匹配的情况下，记录服务器故障是否会产生影响 (`Failures_NoSession`, `Failures_DifferentSession`)。
   - 测试当多个 DNS 服务器发生故障时，`ResolveContext` 的行为 (`TwoFailures`)。

**与 JavaScript 功能的关系：**

虽然此 C++ 代码本身不直接与 JavaScript 交互，但 `ResolveContext` 负责管理底层的 DNS 解析过程，这对于基于浏览器的 JavaScript 应用程序至关重要。

**举例说明:**

当 JavaScript 代码尝试加载一个网页 (例如，通过 `fetch` API 或直接访问 URL)，浏览器需要将域名解析为 IP 地址。 `ResolveContext` 就参与了这个过程，它会根据配置（包括是否启用 DoH）以及服务器的可用性状态来选择合适的 DNS 服务器进行查询。

例如，如果 JavaScript 代码尝试访问 `https://www.example.com`，以下是可能涉及 `ResolveContext` 的过程：

1. **JavaScript 发起请求:** JavaScript 代码调用 `fetch("https://www.example.com")`。
2. **URL 解析:** 浏览器解析 URL，提取域名 `www.example.com`。
3. **DNS 解析:** 浏览器需要获取 `www.example.com` 的 IP 地址。这会触发 DNS 解析过程，而 `ResolveContext` 负责管理这个过程。
4. **选择 DNS 服务器:** `ResolveContext` 根据当前的 DNS 配置（可能包含 DoH 服务器）和之前记录的服务器可用性信息，选择要使用的 DNS 服务器。
   - 如果启用了 DoH 并且有可用的 DoH 服务器，`ResolveContext` 可能会选择一个 DoH 服务器。
   - 如果没有可用的 DoH 服务器或者 DoH 未启用，则会选择传统的 DNS 服务器。
5. **发起 DNS 查询:** 浏览器向选定的 DNS 服务器发送 DNS 查询请求。
6. **处理 DNS 响应:** 浏览器接收 DNS 服务器的响应，包含 `www.example.com` 的 IP 地址。
7. **建立连接:** 浏览器使用解析到的 IP 地址与服务器建立 TCP 连接，然后进行后续的 HTTP 通信。

**逻辑推理（假设输入与输出）：**

**假设输入:**

* `DnsConfig` 配置了两个 DoH 服务器：`https://doh1.example/dns-query` 和 `https://doh2.example/dns-query`。
* 一个 `DnsSession` 对象 `session` 与当前网络关联。
* `ResolveContext` 对象 `context` 正在管理 DNS 解析。
* 初始状态下，两个 DoH 服务器都被认为是可用的。
* 调用 `context.RecordServerFailure(0u, true, ERR_FAILED, session.get())`，记录索引为 0 的 DoH 服务器（`https://doh1.example/dns-query`）发生故障。
* 调用 `context.RecordServerSuccess(1u, true, session.get())`，记录索引为 1 的 DoH 服务器（`https://doh2.example/dns-query`）请求成功。

**输出:**

* `context.GetDohServerAvailability(0u, session.get())` 将返回 `false`，因为该服务器被标记为失败。
* `context.GetDohServerAvailability(1u, session.get())` 将返回 `true`，因为该服务器请求成功。
* `context.NumAvailableDohServers(session.get())` 将返回 `1u`。
* 当后续需要进行 DoH 查询时，`context.GetDohIterator(session->config(), SecureDnsMode::kAutomatic, session.get())` 返回的迭代器 `doh_itr`，在调用 `doh_itr->AttemptAvailable()` 时，首次会返回 `true` 并且 `doh_itr->GetNextAttemptIndex()` 会返回 `1u`（指向 `https://doh2.example/dns-query`），因为它是当前唯一可用的 DoH 服务器。

**用户或编程常见的使用错误：**

1. **不正确的 `DnsConfig` 配置:** 用户或程序可能错误地配置了 DoH 服务器地址，导致连接失败。例如，DoH 模板格式不正确，或者 DoH 服务器地址无法访问。
2. **网络问题导致 DoH 连接失败:** 用户的网络环境可能阻止了与 DoH 服务器的连接，例如防火墙阻止了 HTTPS 连接到特定的 DoH 服务器端口。
3. **假设 DoH 服务器总是可用:** 开发者可能会假设配置的 DoH 服务器总是可用的，而没有考虑到网络波动或服务器故障的情况。`ResolveContext` 帮助处理这种情况，但如果开发者没有正确处理 DNS 解析失败的情况，仍然可能导致问题。
4. **缓存问题:**  不理解 DNS 缓存机制可能导致困惑。例如，在 DNS 配置更改后，旧的 DNS 记录可能仍然被缓存，导致应用程序行为不符合预期。`InvalidateCachesAndPerSessionData` 函数可以用于清理缓存，但开发者需要知道何时以及如何使用它。

**用户操作如何一步步的到达这里作为调试线索：**

假设用户在浏览器中访问一个网站 `https://problematic.example.com`，并遇到了 DNS 解析问题，导致网站无法加载。以下是可能到达 `net/dns/resolve_context_unittest.cc` 的调试路径：

1. **用户尝试访问网站:** 用户在浏览器地址栏输入 `https://problematic.example.com` 并按下回车。
2. **浏览器发起请求:** 浏览器开始处理请求，首先需要解析域名 `problematic.example.com`。
3. **DNS 解析失败 (可能):**  如果网站无法加载，可能是因为 DNS 解析失败。这可能是因为：
   - 传统的 DNS 服务器无法解析该域名。
   - 配置的 DoH 服务器不可用或解析失败。
   - 网络连接问题阻止了与 DNS 服务器的通信。
4. **网络工程师/开发者介入:** 为了诊断问题，网络工程师或 Chromium 开发者可能会查看 Chromium 的网络日志（通过 `chrome://net-export/` 或其他调试工具）。
5. **分析网络日志:** 网络日志可能会显示 DNS 解析的详细信息，包括尝试连接的 DNS 服务器、DoH 服务器的状态、以及发生的错误。
6. **定位 `ResolveContext`:**  如果日志显示与 DoH 服务器连接或传统 DNS 服务器选择有关的问题，开发者可能会查看 `net/dns` 目录下的相关代码，包括 `resolve_context.cc` 和 `resolve_context_unittest.cc`。
7. **查看单元测试:** `resolve_context_unittest.cc` 文件中的测试用例可以帮助开发者理解 `ResolveContext` 的预期行为以及可能出现的故障场景。通过阅读测试用例，开发者可以更好地理解 `ResolveContext` 如何管理 DNS 服务器、处理故障，并从中找到与用户遇到的问题相关的线索。例如，如果测试用例中涵盖了 DoH 服务器连续失败的情况，开发者可能会怀疑用户遇到了类似的问题。
8. **本地复现和调试:**  开发者可能会尝试在本地环境中复现用户遇到的问题，并使用调试器单步执行 `ResolveContext` 相关的代码，以更深入地了解问题发生的具体原因。

**功能归纳 (第 1 部分):**

这部分 `resolve_context_unittest.cc` 文件的主要功能是**测试 `net::ResolveContext` 类对 DNS 服务器的管理和故障处理机制，重点在于 DNS-over-HTTPS (DoH) 服务器的可用性追踪、选择以及与传统 DNS 服务器的协同工作。** 它验证了在各种场景下，`ResolveContext` 是否能够正确地记录服务器的成功和失败状态，并基于这些状态来选择合适的 DNS 服务器进行查询，同时还测试了缓存失效和会话管理等功能。

### 提示词
```
这是目录为net/dns/resolve_context_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/resolve_context.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>

#include "base/functional/bind.h"
#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "base/strings/stringprintf.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/simple_test_clock.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/time/time.h"
#include "host_resolver_internal_result.h"
#include "net/base/address_list.h"
#include "net/base/features.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/mock_network_change_notifier.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_change_notifier.h"
#include "net/base/network_isolation_key.h"
#include "net/dns/dns_config.h"
#include "net/dns/dns_server_iterator.h"
#include "net/dns/dns_session.h"
#include "net/dns/dns_util.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver_cache.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/public/dns_over_https_config.h"
#include "net/dns/public/dns_over_https_server_config.h"
#include "net/dns/public/dns_protocol.h"
#include "net/dns/public/dns_query_type.h"
#include "net/dns/public/host_resolver_source.h"
#include "net/dns/public/secure_dns_mode.h"
#include "net/socket/socket_test_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

class ResolveContextTest : public ::testing::Test, public WithTaskEnvironment {
 protected:
  ResolveContextTest()
      : WithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

  scoped_refptr<DnsSession> CreateDnsSession(const DnsConfig& config) {
    auto null_random_callback =
        base::BindRepeating([](int, int) -> int { base::ImmediateCrash(); });
    return base::MakeRefCounted<DnsSession>(config, null_random_callback,
                                            nullptr /* netlog */);
  }

 protected:
  test::ScopedMockNetworkChangeNotifier mock_notifier_;

 private:
  std::unique_ptr<MockClientSocketFactory> socket_factory_ =
      std::make_unique<MockClientSocketFactory>();
};

DnsConfig CreateDnsConfig(int num_servers, int num_doh_servers) {
  DnsConfig config;
  for (int i = 0; i < num_servers; ++i) {
    IPEndPoint dns_endpoint(IPAddress(192, 168, 1, static_cast<uint8_t>(i)),
                            dns_protocol::kDefaultPort);
    config.nameservers.push_back(dns_endpoint);
  }
  std::vector<std::string> templates;
  templates.reserve(num_doh_servers);
  for (int i = 0; i < num_doh_servers; ++i) {
    templates.push_back(
        base::StringPrintf("https://mock.http/doh_test_%d{?dns}", i));
  }
  config.doh_config =
      *DnsOverHttpsConfig::FromTemplatesForTesting(std::move(templates));
  config.secure_dns_mode = SecureDnsMode::kAutomatic;

  return config;
}

DnsConfig CreateDnsConfigWithKnownDohProviderConfig() {
  DnsConfig config;

  // TODO(crbug.com/40218379): Refactor this to not rely on an entry
  // for 8.8.8.8 existing in the DoH provider list.
  IPEndPoint dns_endpoint(IPAddress(8, 8, 8, 8), dns_protocol::kDefaultPort);
  config.nameservers.push_back(dns_endpoint);

  config.doh_config = DnsOverHttpsConfig(
      GetDohUpgradeServersFromNameservers(config.nameservers));
  EXPECT_FALSE(config.doh_config.servers().empty());

  config.secure_dns_mode = SecureDnsMode::kAutomatic;

  return config;
}

// Simulate a new session with the same pointer as an old deleted session by
// invalidating WeakPtrs.
TEST_F(ResolveContextTest, ReusedSessionPointer) {
  DnsConfig config =
      CreateDnsConfig(1 /* num_servers */, 3 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);

  auto request_context = CreateTestURLRequestContextBuilder()->Build();
  ResolveContext context(request_context.get(), true /* enable_caching */);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  // Mark probe success for the "original" (pre-invalidation) session.
  context.RecordServerSuccess(1u /* server_index */, true /* is_doh_server */,
                              session.get());
  ASSERT_TRUE(context.GetDohServerAvailability(1u, session.get()));

  // Simulate session destruction and recreation on the same pointer.
  session->InvalidateWeakPtrsForTesting();

  // Expect |session| should now be treated as a new session, not matching
  // |context|'s "current" session. Expect availability from the "old" session
  // should not be read and RecordServerSuccess() should have no effect because
  // the "new" session has not yet been marked as "current" through
  // InvalidateCaches().
  EXPECT_FALSE(context.GetDohServerAvailability(1u, session.get()));
  context.RecordServerSuccess(1u /* server_index */, true /* is_doh_server */,
                              session.get());
  EXPECT_FALSE(context.GetDohServerAvailability(1u, session.get()));
}

TEST_F(ResolveContextTest, DohServerAvailability_InitialAvailability) {
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);

  auto request_context = CreateTestURLRequestContextBuilder()->Build();
  ResolveContext context(request_context.get(), true /* enable_caching */);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  EXPECT_EQ(context.NumAvailableDohServers(session.get()), 0u);
  std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
      session->config(), SecureDnsMode::kAutomatic, session.get());

  EXPECT_FALSE(doh_itr->AttemptAvailable());

  base::HistogramTester histogram_tester;
  context.StartDohAutoupgradeSuccessTimer(session.get());
  // Fast-forward by enough time for the timer to trigger. Add one millisecond
  // just to make it clear that afterwards the timeout should definitely have
  // occurred (although this may not be strictly necessary).
  FastForwardBy(ResolveContext::kDohAutoupgradeSuccessMetricTimeout +
                base::Milliseconds(1));
  histogram_tester.ExpectTotalCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status", 0);
}

TEST_F(ResolveContextTest, DohServerAvailability_RecordedSuccess) {
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);

  auto request_context = CreateTestURLRequestContextBuilder()->Build();
  ResolveContext context(request_context.get(), true /* enable_caching */);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  ASSERT_EQ(context.NumAvailableDohServers(session.get()), 0u);

  context.RecordServerSuccess(1u /* server_index */, true /* is_doh_server */,
                              session.get());
  EXPECT_EQ(context.NumAvailableDohServers(session.get()), 1u);
  std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
      session->config(), SecureDnsMode::kAutomatic, session.get());

  ASSERT_TRUE(doh_itr->AttemptAvailable());
  EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 1u);

  base::HistogramTester histogram_tester;
  context.StartDohAutoupgradeSuccessTimer(session.get());
  // Fast-forward by enough time for the timer to trigger. Add one millisecond
  // just to make it clear that afterwards the timeout should definitely have
  // occurred (although this may not be strictly necessary).
  FastForwardBy(ResolveContext::kDohAutoupgradeSuccessMetricTimeout +
                base::Milliseconds(1));
  histogram_tester.ExpectTotalCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status", 1);
  histogram_tester.ExpectBucketCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      DohServerAutoupgradeStatus::kSuccessWithNoPriorFailures, 1);
}

TEST_F(ResolveContextTest, DohServerAvailability_NoCurrentSession) {
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);

  auto request_context = CreateTestURLRequestContextBuilder()->Build();
  ResolveContext context(request_context.get(), true /* enable_caching */);

  context.RecordServerSuccess(1u /* server_index */, true /* is_doh_server */,
                              session.get());

  std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
      session->config(), SecureDnsMode::kAutomatic, session.get());

  EXPECT_FALSE(doh_itr->AttemptAvailable());
  EXPECT_EQ(0u, context.NumAvailableDohServers(session.get()));
  EXPECT_FALSE(context.GetDohServerAvailability(1, session.get()));
}

TEST_F(ResolveContextTest, DohServerAvailability_DifferentSession) {
  DnsConfig config1 =
      CreateDnsConfig(1 /* num_servers */, 3 /* num_doh_servers */);
  scoped_refptr<DnsSession> session1 = CreateDnsSession(config1);

  DnsConfig config2 =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session2 = CreateDnsSession(config2);

  auto request_context = CreateTestURLRequestContextBuilder()->Build();
  ResolveContext context(request_context.get(), true /* enable_caching */);
  context.InvalidateCachesAndPerSessionData(session2.get(),
                                            true /* network_change */);

  // Use current session to set a probe result.
  context.RecordServerSuccess(1u /* server_index */, true /* is_doh_server */,
                              session2.get());

  std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
      session1->config(), SecureDnsMode::kAutomatic, session1.get());

  EXPECT_FALSE(doh_itr->AttemptAvailable());
  EXPECT_EQ(0u, context.NumAvailableDohServers(session1.get()));
  EXPECT_FALSE(context.GetDohServerAvailability(1u, session1.get()));

  // Different session for RecordServerFailure() should have no effect.
  ASSERT_TRUE(context.GetDohServerAvailability(1u, session2.get()));
  for (int i = 0; i < ResolveContext::kAutomaticModeFailureLimit; ++i) {
    context.RecordServerFailure(1u /* server_index */, true /* is_doh_server */,
                                ERR_FAILED, session1.get());
  }
  EXPECT_TRUE(context.GetDohServerAvailability(1u, session2.get()));
}

TEST_F(ResolveContextTest, DohServerIndexToUse) {
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);

  auto request_context = CreateTestURLRequestContextBuilder()->Build();
  ResolveContext context(request_context.get(), true /* enable_caching */);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  context.RecordServerSuccess(0u /* server_index */, true /* is_doh_server */,
                              session.get());
  EXPECT_EQ(context.NumAvailableDohServers(session.get()), 1u);
  std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
      session->config(), SecureDnsMode::kAutomatic, session.get());

  ASSERT_TRUE(doh_itr->AttemptAvailable());
  EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
  EXPECT_FALSE(doh_itr->AttemptAvailable());
}

TEST_F(ResolveContextTest, DohServerIndexToUse_NoneEligible) {
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);

  auto request_context = CreateTestURLRequestContextBuilder()->Build();
  ResolveContext context(request_context.get(), true /* enable_caching */);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
      session->config(), SecureDnsMode::kAutomatic, session.get());

  EXPECT_FALSE(doh_itr->AttemptAvailable());
}

TEST_F(ResolveContextTest, DohServerIndexToUse_SecureMode) {
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);

  auto request_context = CreateTestURLRequestContextBuilder()->Build();
  ResolveContext context(request_context.get(), true /* enable_caching */);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
      session->config(), SecureDnsMode::kSecure, session.get());

  ASSERT_TRUE(doh_itr->AttemptAvailable());
  EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
  ASSERT_TRUE(doh_itr->AttemptAvailable());
  EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 1u);
}

TEST_F(ResolveContextTest, StartDohAutoupgradeSuccessTimer) {
  DnsConfig config = CreateDnsConfig(/*num_servers=*/2, /*num_doh_servers=*/2);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);

  auto request_context = CreateTestURLRequestContextBuilder()->Build();
  ResolveContext context(request_context.get(), /*enable_caching=*/true);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            /*network_change=*/false);

  EXPECT_FALSE(context.doh_autoupgrade_metrics_timer_is_running_for_testing());

  // Calling with a valid session should start the timer.
  context.StartDohAutoupgradeSuccessTimer(session.get());
  EXPECT_TRUE(context.doh_autoupgrade_metrics_timer_is_running_for_testing());

  // Making a second call should have no effect.
  context.StartDohAutoupgradeSuccessTimer(session.get());
  EXPECT_TRUE(context.doh_autoupgrade_metrics_timer_is_running_for_testing());

  // Fast-forward by enough time for the timer to trigger. Add one millisecond
  // just to make it clear that afterwards the timeout should definitely have
  // occurred (although this may not be strictly necessary).
  FastForwardBy(ResolveContext::kDohAutoupgradeSuccessMetricTimeout +
                base::Milliseconds(1));
  EXPECT_FALSE(context.doh_autoupgrade_metrics_timer_is_running_for_testing());
}

class TestDnsObserver : public NetworkChangeNotifier::DNSObserver {
 public:
  void OnDNSChanged() override { ++dns_changed_calls_; }

  int dns_changed_calls() const { return dns_changed_calls_; }

 private:
  int dns_changed_calls_ = 0;
};

TEST_F(ResolveContextTest, DohServerAvailabilityNotification) {
  TestDnsObserver config_observer;
  NetworkChangeNotifier::AddDNSObserver(&config_observer);

  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);

  auto request_context = CreateTestURLRequestContextBuilder()->Build();
  ResolveContext context(request_context.get(), true /* enable_caching */);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  base::RunLoop().RunUntilIdle();  // Notifications are async.
  EXPECT_EQ(0, config_observer.dns_changed_calls());

  // Expect notification on first available DoH server.
  ASSERT_EQ(0u, context.NumAvailableDohServers(session.get()));
  context.RecordServerSuccess(0u /* server_index */, true /* is_doh_server */,
                              session.get());
  ASSERT_EQ(1u, context.NumAvailableDohServers(session.get()));
  base::RunLoop().RunUntilIdle();  // Notifications are async.
  EXPECT_EQ(1, config_observer.dns_changed_calls());

  // No notifications as additional servers are available or unavailable.
  context.RecordServerSuccess(1u /* server_index */, true /* is_doh_server */,
                              session.get());
  base::RunLoop().RunUntilIdle();  // Notifications are async.
  EXPECT_EQ(1, config_observer.dns_changed_calls());
  for (int i = 0; i < ResolveContext::kAutomaticModeFailureLimit; ++i) {
    ASSERT_EQ(2u, context.NumAvailableDohServers(session.get()));
    context.RecordServerFailure(0u /* server_index */, true /* is_doh_server */,
                                ERR_FAILED, session.get());
    base::RunLoop().RunUntilIdle();  // Notifications are async.
    EXPECT_EQ(1, config_observer.dns_changed_calls());
  }
  ASSERT_EQ(1u, context.NumAvailableDohServers(session.get()));

  // Expect notification on last server unavailable.
  for (int i = 0; i < ResolveContext::kAutomaticModeFailureLimit; ++i) {
    ASSERT_EQ(1u, context.NumAvailableDohServers(session.get()));
    base::RunLoop().RunUntilIdle();  // Notifications are async.
    EXPECT_EQ(1, config_observer.dns_changed_calls());

    context.RecordServerFailure(1u /* server_index */, true /* is_doh_server */,
                                ERR_FAILED, session.get());
  }
  ASSERT_EQ(0u, context.NumAvailableDohServers(session.get()));
  base::RunLoop().RunUntilIdle();  // Notifications are async.
  EXPECT_EQ(2, config_observer.dns_changed_calls());

  NetworkChangeNotifier::RemoveDNSObserver(&config_observer);
}

TEST_F(ResolveContextTest, InvalidateCachesAndPerSessionData) {
  base::SimpleTestClock clock;
  base::SimpleTestTickClock tick_clock;
  ResolveContext context(/*url_request_context=*/nullptr,
                         /*enable_caching=*/true, clock, tick_clock);

  NetworkAnonymizationKey anonymization_key;

  HostCache::Key key("example.com", DnsQueryType::UNSPECIFIED, 0,
                     HostResolverSource::ANY, anonymization_key);
  context.host_cache()->Set(
      key,
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN),
      tick_clock.NowTicks(), base::Seconds(10));
  ASSERT_TRUE(context.host_cache()->Lookup(key, tick_clock.NowTicks()));

  context.host_resolver_cache()->Set(
      std::make_unique<HostResolverInternalErrorResult>(
          "domain.test", DnsQueryType::AAAA,
          tick_clock.NowTicks() + base::Seconds(10),
          clock.Now() + base::Seconds(10),
          HostResolverInternalResult::Source::kDns, ERR_NAME_NOT_RESOLVED),
      anonymization_key, HostResolverSource::DNS, /*secure=*/false);
  ASSERT_TRUE(
      context.host_resolver_cache()->Lookup("domain.test", anonymization_key));

  DnsConfig config = CreateDnsConfig(/*num_servers=*/2, /*num_doh_servers=*/2);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            /*network_change=*/false);

  EXPECT_FALSE(context.host_cache()->Lookup(key, tick_clock.NowTicks()));
  EXPECT_FALSE(
      context.host_resolver_cache()->Lookup("domain.test", anonymization_key));

  // Re-add to the caches and now add some DoH server status.
  context.host_cache()->Set(
      key,
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN),
      tick_clock.NowTicks(), base::Seconds(10));
  context.host_resolver_cache()->Set(
      std::make_unique<HostResolverInternalErrorResult>(
          "domain2.test", DnsQueryType::AAAA,
          tick_clock.NowTicks() + base::Seconds(10),
          clock.Now() + base::Seconds(10),
          HostResolverInternalResult::Source::kDns, ERR_NAME_NOT_RESOLVED),
      anonymization_key, HostResolverSource::DNS, /*secure=*/false);
  context.RecordServerSuccess(/*server_index=*/0u, /*is_doh_server=*/true,
                              session.get());
  ASSERT_TRUE(context.host_cache()->Lookup(key, tick_clock.NowTicks()));
  ASSERT_TRUE(
      context.host_resolver_cache()->Lookup("domain2.test", anonymization_key));
  ASSERT_TRUE(context.GetDohServerAvailability(0u, session.get()));

  // Invalidate again.
  DnsConfig config2 = CreateDnsConfig(/*num_servers=*/2, /*num_doh_servers=*/2);
  scoped_refptr<DnsSession> session2 = CreateDnsSession(config2);
  context.InvalidateCachesAndPerSessionData(session2.get(),
                                            /*network_change=*/true);

  EXPECT_FALSE(context.host_cache()->Lookup(key, tick_clock.NowTicks()));
  EXPECT_FALSE(
      context.host_resolver_cache()->Lookup("domain2.test", anonymization_key));
  EXPECT_FALSE(context.GetDohServerAvailability(0u, session.get()));
  EXPECT_FALSE(context.GetDohServerAvailability(0u, session2.get()));
}

TEST_F(ResolveContextTest, InvalidateCachesAndPerSessionDataSameSession) {
  base::SimpleTestClock clock;
  base::SimpleTestTickClock tick_clock;
  ResolveContext context(/*url_request_context=*/nullptr,
                         /*enable_caching=*/true, clock, tick_clock);
  DnsConfig config = CreateDnsConfig(/*num_servers=*/2, /*num_doh_servers=*/2);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);

  // Initial invalidation just to set the session.
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            /*network_change=*/false);

  // Add to the caches and add some DoH server status.
  NetworkAnonymizationKey anonymization_key;
  HostCache::Key key("example.com", DnsQueryType::UNSPECIFIED, 0,
                     HostResolverSource::ANY, anonymization_key);
  context.host_cache()->Set(
      key,
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{"example.com"},
                       HostCache::Entry::SOURCE_UNKNOWN),
      tick_clock.NowTicks(), base::Seconds(10));
  context.host_resolver_cache()->Set(
      std::make_unique<HostResolverInternalErrorResult>(
          "domain.test", DnsQueryType::AAAA,
          tick_clock.NowTicks() + base::Seconds(10),
          clock.Now() + base::Seconds(10),
          HostResolverInternalResult::Source::kDns, ERR_NAME_NOT_RESOLVED),
      anonymization_key, HostResolverSource::DNS, /*secure=*/false);
  context.RecordServerSuccess(/*server_index=*/0u, /*is_doh_server=*/true,
                              session.get());
  ASSERT_TRUE(context.host_cache()->Lookup(key, tick_clock.NowTicks()));
  ASSERT_TRUE(
      context.host_resolver_cache()->Lookup("domain.test", anonymization_key));
  ASSERT_TRUE(context.GetDohServerAvailability(0u, session.get()));

  // Invalidate again with the same session.
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            /*network_change=*/false);

  // Expect host cache to be invalidated but not the per-session data.
  EXPECT_FALSE(context.host_cache()->Lookup(key, tick_clock.NowTicks()));
  EXPECT_FALSE(
      context.host_resolver_cache()->Lookup("domain.test", anonymization_key));
  EXPECT_TRUE(context.GetDohServerAvailability(0u, session.get()));
}

TEST_F(ResolveContextTest, Failures_Consecutive) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  // Expect server preference to change after |config.attempts| failures.
  for (int i = 0; i < config.attempts; i++) {
    std::unique_ptr<DnsServerIterator> classic_itr =
        context.GetClassicDnsIterator(session->config(), session.get());

    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 1u);

    context.RecordServerFailure(1u /* server_index */,
                                false /* is_doh_server */, ERR_FAILED,
                                session.get());
  }

  {
    std::unique_ptr<DnsServerIterator> classic_itr =
        context.GetClassicDnsIterator(session->config(), session.get());

    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
  }

  // Expect failures to be reset on successful request.
  context.RecordServerSuccess(1u /* server_index */, false /* is_doh_server */,
                              session.get());
  {
    std::unique_ptr<DnsServerIterator> classic_itr =
        context.GetClassicDnsIterator(session->config(), session.get());

    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 1u);
  }
}

TEST_F(ResolveContextTest, Failures_NonConsecutive) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  for (int i = 0; i < config.attempts - 1; i++) {
    std::unique_ptr<DnsServerIterator> classic_itr =
        context.GetClassicDnsIterator(session->config(), session.get());

    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 1u);

    context.RecordServerFailure(1u /* server_index */,
                                false /* is_doh_server */, ERR_FAILED,
                                session.get());
  }

  {
    std::unique_ptr<DnsServerIterator> classic_itr =
        context.GetClassicDnsIterator(session->config(), session.get());

    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 1u);
  }

  context.RecordServerSuccess(1u /* server_index */, false /* is_doh_server */,
                              session.get());
  {
    std::unique_ptr<DnsServerIterator> classic_itr =
        context.GetClassicDnsIterator(session->config(), session.get());

    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 1u);
  }

  // Expect server stay preferred through non-consecutive failures.
  context.RecordServerFailure(1u /* server_index */, false /* is_doh_server */,
                              ERR_FAILED, session.get());
  {
    std::unique_ptr<DnsServerIterator> classic_itr =
        context.GetClassicDnsIterator(session->config(), session.get());

    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 1u);
  }
}

TEST_F(ResolveContextTest, Failures_NoSession) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);

  // No expected change from recording failures.
  for (int i = 0; i < config.attempts; i++) {
    std::unique_ptr<DnsServerIterator> classic_itr =
        context.GetClassicDnsIterator(session->config(), session.get());

    EXPECT_FALSE(classic_itr->AttemptAvailable());

    context.RecordServerFailure(1u /* server_index */,
                                false /* is_doh_server */, ERR_FAILED,
                                session.get());
  }
  std::unique_ptr<DnsServerIterator> classic_itr =
      context.GetClassicDnsIterator(session->config(), session.get());

  EXPECT_FALSE(classic_itr->AttemptAvailable());
}

TEST_F(ResolveContextTest, Failures_DifferentSession) {
  DnsConfig config1 =
      CreateDnsConfig(1 /* num_servers */, 3 /* num_doh_servers */);
  scoped_refptr<DnsSession> session1 = CreateDnsSession(config1);

  DnsConfig config2 =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session2 = CreateDnsSession(config2);

  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  context.InvalidateCachesAndPerSessionData(session2.get(),
                                            true /* network_change */);

  // No change from recording failures to wrong session.
  for (int i = 0; i < config1.attempts; i++) {
    std::unique_ptr<DnsServerIterator> classic_itr =
        context.GetClassicDnsIterator(session2->config(), session2.get());

    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 1u);

    context.RecordServerFailure(1u /* server_index */,
                                false /* is_doh_server */, ERR_FAILED,
                                session1.get());
  }
  std::unique_ptr<DnsServerIterator> classic_itr =
      context.GetClassicDnsIterator(session2->config(), session2.get());

  ASSERT_TRUE(classic_itr->AttemptAvailable());
  EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
  ASSERT_TRUE(classic_itr->AttemptAvailable());
  EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 1u);
}

// Test 2 of 3 servers failing.
TEST_F(ResolveContextTest, TwoFailures) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(3 /* num_servers */, 2 /* num_doh_servers */);
  config.attempts = 1;
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  // Expect server preference to change after |config.attempts| failures.
  for (int i = 0; i < config.attempts; i++) {
    std::unique_ptr<DnsServerIterator> classic_itr =
        context.GetClassicDnsIterator(session->config(), session.get());

    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 1u);
    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 2u);

    context.RecordServerFailure(0u /* server_index */,
                                false /* is_doh_server */, ERR_FAILED,
                                session.get());
    context.RecordServerFailure(1u /* server_index */,
                                false /* is_doh_server */, ERR_FAILED,
                                session.get());
  }
  {
    std::unique_ptr<DnsServerIterator> classic_itr =
        context.GetClassicDnsIterator(session->config(), session.get());

    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 2u);
    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 1u);
  }

  // Expect failures to be reset on successful request.
  context.RecordServerSuccess(0u /* server_index */, false /* is_doh_server */,
                              session.get());
  context.RecordServerSuccess(1u /* server_index */, false /* is_doh_server */,
                              session.get());
  {
    std::unique_ptr<DnsServerIterator> classic_itr =
        context.GetClassicDnsIterator(session->config(), session.get());

    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 1u);
    ASSERT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 2u);
  }
}

class TestDohStatusObserver : public ResolveContext::DohStatusObserver {
 public:
  void OnSessionChanged() override { ++session_changes_; }
  void OnDohServerUnavailable(bool network_change) override {
    ++server
```