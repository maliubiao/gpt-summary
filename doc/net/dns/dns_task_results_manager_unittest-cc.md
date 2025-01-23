Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Understanding the Goal:**

The primary goal is to understand what the code *does*, not just what it *is*. This involves figuring out the purpose of the tests and the functionality being tested. The prompt specifically asks about function, relationships to JavaScript, logical reasoning (input/output), user errors, and debugging context.

**2. Initial Scan and Identification of Key Elements:**

First, a quick skim of the code reveals several important elements:

* **Includes:**  Headers like `<memory>`, `<optional>`, `<string_view>`, `gtest/gtest.h`, and specific Chromium headers like `net/dns/dns_task_results_manager.h`. These tell us the file deals with memory management, optional values, string manipulation, unit testing, and a specific Chromium component: `DnsTaskResultsManager`.
* **Namespaces:**  The code is within the `net` namespace. This confirms it's part of the Chromium network stack.
* **Test Fixture:** The `DnsTaskResultsManagerTest` class inherits from `TestWithTaskEnvironment`. This is a standard pattern in Chromium unit tests, indicating that tests will be run within a controlled environment allowing for asynchronous operations and time manipulation.
* **`FakeDelegate`:**  A simple class implementing the `DnsTaskResultsManager::Delegate` interface. This is a common testing technique to isolate the class under test from its dependencies. It does nothing significant in this specific test file.
* **Helper Functions:** Functions like `MakeIPEndPoint`, `CreateDataResult`, `CreateNoData`, `CreateMetadata`, and `CreateAlias`. These are clearly for constructing test data, making the tests more readable and less verbose. They create instances of `HostResolverInternalResult` and related structures.
* **`ManagerFactory`:**  A helper class to create instances of `DnsTaskResultsManager`. This promotes consistency in object creation across tests.
* **`TEST_F` Macros:**  These are the actual test cases. Their names (e.g., `IsMetadataReady`, `IPv6NotQueried`, `MetadataFirst`) provide strong hints about what each test is verifying.
* **Assertions and Expectations:**  Macros like `ASSERT_TRUE`, `ASSERT_FALSE`, `EXPECT_THAT`, `ElementsAre`, `IsEmpty`, and `UnorderedElementsAre` are used to verify the behavior of the `DnsTaskResultsManager`.
* **Constants:** `kHostName`, `kAliasTarget1`, etc., define test data values.

**3. Deeper Dive into Functionality (Test by Test):**

Now, go through each `TEST_F` to understand its specific purpose. For example:

* **`IsMetadataReady`:**  Checks if the manager correctly tracks whether metadata (HTTPS records) has been received.
* **`IPv6NotQueried`:** Verifies behavior when only IPv4 resolution is done.
* **`IPv4First` and `IPv6First`:** Test the order in which IPv4 and IPv6 address results arrive and how the manager handles it. This reveals a potential optimization where IPv6 arrival might trigger quicker endpoint availability.
* **Tests involving `Timedout`:** Explore how the manager handles delays in receiving IPv6 results.
* **Tests involving `NoData`:** Examine scenarios where DNS queries return "no such name."
* **Tests involving `Metadata`:**  Focus on how HTTPS records (metadata) are processed and combined with IP addresses.
* **`EndpointOrdering`:**  Specifically checks the order of the `ServiceEndpoint` objects based on the arrival of different types of DNS records.
* **`Aliases`:** Tests how CNAME records are handled and stored.
* **`Ipv4MappedIpv6`:**  A specific edge case test related to IPv6 addresses that encode IPv4 addresses.

**4. Identifying Key Functionality of `DnsTaskResultsManager`:**

By analyzing the tests, the core functionality of `DnsTaskResultsManager` emerges:

* **Aggregating DNS Results:** It takes individual DNS query results (A, AAAA, HTTPS, CNAME) and combines them.
* **Managing Service Endpoints:** It creates `ServiceEndpoint` objects, which bundle IPv4 addresses, IPv6 addresses, and associated metadata (like ALPN protocols from HTTPS records).
* **Handling Asynchronous Operations:**  The tests demonstrate how it deals with results arriving at different times. The "resolution delay" concept is important here.
* **Handling Aliases (CNAMEs):** It tracks DNS aliases.
* **Determining Metadata Readiness:** It knows if HTTPS records have been processed.

**5. Considering the Relationship to JavaScript:**

This requires thinking about where DNS resolution fits into the browser's lifecycle.

* **Fetching Resources:** When JavaScript (or the browser in general) needs to fetch a resource from a website (e.g., an image, a script, an API endpoint), it needs to know the IP address of the server. This involves DNS resolution.
* **`fetch()` API:**  JavaScript's `fetch()` API is a primary way to make network requests. Behind the scenes, the browser uses components like the DNS resolver (which `DnsTaskResultsManager` is a part of) to get the necessary IP addresses.
* **`XMLHttpRequest`:**  The older `XMLHttpRequest` API also relies on DNS resolution.
* **Navigation:** When a user types a URL into the address bar or clicks a link, the browser needs to resolve the hostname to an IP address.

**6. Logical Reasoning (Input/Output):**

For this, pick a specific test case and consider a simplified version of the input and the expected output. The helper functions are crucial for defining this input. The `EXPECT_THAT` assertions define the output.

**7. User and Programming Errors:**

Think about common mistakes developers or users might make that could lead to the scenarios tested in this file:

* **Website Configuration Errors:** Incorrect DNS records (e.g., missing A or AAAA records, misconfigured HTTPS records).
* **Network Connectivity Issues:** Temporary network problems could lead to timeouts or DNS resolution failures.
* **Browser Bugs:** Although less likely, bugs in the DNS resolution logic itself could cause issues.

**8. Debugging Context:**

Imagine you're a developer investigating a network issue. How would you arrive at this code?

* **Network Error Reports:** A user might report a website loading slowly or failing to load. This could point to DNS issues.
* **Browser Developer Tools:** The Network tab in Chrome's DevTools shows the timing of network requests, including DNS resolution. If DNS resolution takes a long time or fails, this could be a clue.
* **Internal Logging:** Chromium has extensive logging. Searching the logs for DNS-related messages might lead you to the DNS resolution code.
* **Code Inspection:** If you suspect a bug in the DNS resolution logic, you might start by looking at the code responsible for handling DNS results, which is where `DnsTaskResultsManager` comes in.

**Self-Correction/Refinement During the Process:**

* **Initial Over-Simplification:**  Initially, you might think `DnsTaskResultsManager` just stores IP addresses. But looking at the tests involving `Metadata` reveals a more complex role in handling HTTPS records.
* **Focusing on the "Why":** Don't just describe what the code does; explain *why* it does it. For example, why is there a "resolution delay"?  (To wait for IPv6 results if IPv4 comes first.)
* **Connecting the Dots:**  Actively try to link the C++ code to higher-level concepts like JavaScript APIs and user interactions.

By following these steps, you can systematically analyze the C++ unittest file and address all the points raised in the prompt.
这个 C++ 源代码文件 `dns_task_results_manager_unittest.cc` 是 Chromium 网络栈中 `net/dns/dns_task_results_manager.h` 头的单元测试文件。它的主要功能是 **测试 `DnsTaskResultsManager` 类的各种功能和逻辑**。

以下是更详细的功能分解：

**1. 测试 `DnsTaskResultsManager` 的核心功能:**

   * **管理 DNS 查询结果:**  `DnsTaskResultsManager` 负责接收、处理和聚合来自不同 DNS 查询类型（例如 A 记录、AAAA 记录、HTTPS 记录）的结果。这些测试用例模拟了各种结果到达的顺序和情况。
   * **创建和管理服务端点 (Service Endpoints):**  `DnsTaskResultsManager` 的核心职责之一是根据收到的 A 和 AAAA 记录生成服务端的 IP 地址列表，并将其与 HTTPS 记录中的元数据（例如支持的协议 ALPN）关联起来，形成 `ServiceEndpoint` 对象。测试用例验证了在不同情况下服务端点的创建和更新。
   * **处理 IPv4 和 IPv6 地址:**  测试用例涵盖了 IPv4 和 IPv6 地址结果的各种组合和到达顺序，包括只有 IPv4、只有 IPv6、IPv4 先到、IPv6 先到、以及其中一种超时的情况。
   * **处理 HTTPS 记录 (Metadata):**  测试用例验证了 `DnsTaskResultsManager` 如何处理 HTTPS 记录，并将这些记录中的元数据与相应的 IP 地址关联。它测试了元数据先到、后到，以及目标名称不匹配的情况。
   * **处理 DNS 别名 (Aliases/CNAMEs):**  测试用例模拟了 DNS 别名的解析过程，并验证 `DnsTaskResultsManager` 能正确记录这些别名。
   * **处理超时和无数据响应:**  测试用例涵盖了 DNS 查询超时和返回“无数据”的情况，以及 `DnsTaskResultsManager` 如何根据这些情况更新其状态和生成服务端点。
   * **控制服务点生成的延迟 (Resolution Delay):**  当 IPv4 地址先到达时，`DnsTaskResultsManager` 可能会延迟生成服务端点，以等待 IPv6 地址的到来，从而提供更好的连接体验。测试用例验证了这种延迟机制。
   * **判断元数据是否准备就绪:**  测试 `IsMetadataReady()` 方法，该方法用于指示是否已收到 HTTPS 记录。

**2. 模拟不同的 DNS 响应场景:**

   * 测试用例使用辅助函数（例如 `CreateDataResult`, `CreateNoData`, `CreateMetadata`, `CreateAlias`）来方便地创建各种类型的 `HostResolverInternalResult` 对象，模拟真实的 DNS 响应。
   * 测试用例使用 `ProcessDnsTransactionResults` 方法将这些模拟的 DNS 响应传递给 `DnsTaskResultsManager` 进行处理。

**3. 使用断言 (Assertions) 验证预期行为:**

   * 测试用例使用 Google Test 框架提供的断言宏（例如 `ASSERT_TRUE`, `ASSERT_FALSE`, `EXPECT_THAT`, `ElementsAre`, `IsEmpty`, `UnorderedElementsAre`）来验证 `DnsTaskResultsManager` 在各种场景下的行为是否符合预期。

**与 JavaScript 的关系及举例说明:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能 **直接影响到浏览器中 JavaScript 发起的网络请求的行为**。

* **`fetch()` API 和 `XMLHttpRequest`:** 当 JavaScript 代码使用 `fetch()` API 或 `XMLHttpRequest` 发起网络请求时，浏览器需要解析域名以获取服务器的 IP 地址。`DnsTaskResultsManager` 负责管理这些 DNS 查询的结果。
* **HTTPS 连接和 ALPN:**  `DnsTaskResultsManager` 处理的 HTTPS 记录中包含了 ALPN (Application-Layer Protocol Negotiation) 信息，这决定了浏览器和服务器之间使用的 HTTP 版本（例如 HTTP/2, HTTP/3）。JavaScript 发起的 HTTPS 请求会受到此信息的影响。

**举例说明:**

假设 JavaScript 代码发起一个 `fetch()` 请求到 `https://www.example.com`:

1. **DNS 查询:** 浏览器会发起 DNS 查询来获取 `www.example.com` 的 IP 地址。这可能涉及到查询 A 记录、AAAA 记录和 HTTPS 记录。
2. **`DnsTaskResultsManager` 的工作:** `DnsTaskResultsManager` 会接收这些 DNS 查询的结果。
   * 如果 A 记录返回 IPv4 地址，AAAA 记录返回 IPv6 地址，HTTPS 记录返回支持 HTTP/3 的信息，`DnsTaskResultsManager` 会创建一个包含 IPv4 地址、IPv6 地址和 HTTP/3 元数据的 `ServiceEndpoint`。
3. **连接建立:** 浏览器会根据 `DnsTaskResultsManager` 提供的信息，尝试连接到服务器的 IP 地址，并使用 HTTPS 记录中协商的协议（例如 HTTP/3）。
4. **JavaScript 请求:** 一旦连接建立，JavaScript 的 `fetch()` 请求才能真正发送到服务器。

**逻辑推理、假设输入与输出:**

以 `TEST_F(DnsTaskResultsManagerTest, IPv4First)` 为例：

**假设输入:**

* **初始状态:** `DnsTaskResultsManager` 没有任何 DNS 结果。
* **第一次调用 `ProcessDnsTransactionResults` (A 记录):**  传入一个包含 `www.example.com` 的 IPv4 地址 `192.0.2.1` 的 `HostResolverInternalResult`。
* **第二次调用 `ProcessDnsTransactionResults` (AAAA 记录):** 传入一个包含 `www.example.com` 的 IPv6 地址 `2001:db8::1` 的 `HostResolverInternalResult`。

**逻辑推理:**

1. 当只收到 A 记录时，`DnsTaskResultsManager` 会延迟创建 `ServiceEndpoint`，因为可能还有 IPv6 地址可用，等待可以提供更好的连接体验。
2. 当收到 AAAA 记录后，`DnsTaskResultsManager` 会将 IPv4 和 IPv6 地址组合起来，创建一个包含两个地址的 `ServiceEndpoint`。

**预期输出:**

* 在第一次调用后，`manager->GetCurrentEndpoints()` 应该为空。
* 在第二次调用后，`manager->GetCurrentEndpoints()` 应该包含一个 `ServiceEndpoint`，其中包含 IPv4 地址 `192.0.2.1:443` 和 IPv6 地址 `2001:db8::1:443`。

**用户或编程常见的使用错误及举例说明:**

这个单元测试主要关注 `DnsTaskResultsManager` 内部逻辑的正确性，而不是用户或开发者直接使用这个类的场景。 然而，理解测试覆盖的场景有助于避免一些与 DNS 相关的常见问题：

* **网站配置错误:** 如果网站的 DNS 配置不正确（例如，缺少 A 或 AAAA 记录，或者 HTTPS 记录配置错误），`DnsTaskResultsManager` 会反映这些错误。例如，如果只有 A 记录，那么访问该网站的客户端将只能使用 IPv4 连接。测试用例覆盖了这种情况。
* **网络问题导致 DNS 解析失败:** 如果用户的网络存在问题，导致 DNS 解析超时或失败，`DnsTaskResultsManager` 会接收到相应的错误信息。开发者在处理网络请求时需要考虑到 DNS 解析失败的情况，并提供合适的错误处理机制。测试用例中 `CreateNoData` 和超时相关的测试就模拟了这种情况。
* **不理解 IPv6 的重要性:**  一些开发者可能认为只配置 IPv4 就可以了。然而，测试用例中对 IPv4 和 IPv6 的处理逻辑表明，Chromium 网络栈会尝试同时获取 IPv4 和 IPv6 地址，以提供更好的连接体验。没有 IPv6 配置可能会影响某些用户的访问体验。

**用户操作如何一步步到达这里，作为调试线索:**

作为一个最终用户，你的操作不会直接触发 `dns_task_results_manager_unittest.cc` 的执行。这是一个开发和测试阶段使用的文件。然而，当你在浏览器中进行以下操作时，可能会间接地涉及到 `DnsTaskResultsManager` 的代码执行，如果出现问题，开发者可能会通过调试来查看相关代码：

1. **在地址栏输入网址并回车:**
   * 浏览器会解析输入的域名。
   * 网络栈会发起 DNS 查询，`DnsTaskResultsManager` 会处理返回的结果。
   * 如果网站配置了 HTTPS，还会查询 HTTPS 记录。
   * 如果 DNS 解析失败或返回不期望的结果，会导致页面加载失败或出现网络错误。
   * **调试线索:** 如果用户报告某个网站无法访问或加载缓慢，开发者可能会检查 DNS 解析过程，查看 `DnsTaskResultsManager` 是否按预期工作。

2. **点击网页上的链接:**
   * 与输入网址类似，浏览器需要解析链接指向的域名。
   * 如果链接指向的资源使用了 HTTPS，还会涉及到 HTTPS 记录的查询。
   * **调试线索:** 如果用户点击链接后页面加载异常，开发者可能会分析 DNS 解析结果，尤其是 HTTPS 记录是否正确。

3. **JavaScript 发起 `fetch()` 或 `XMLHttpRequest` 请求:**
   * 当 JavaScript 代码请求服务器资源时，浏览器需要解析目标域名。
   * `DnsTaskResultsManager` 负责管理这些 DNS 查询的结果。
   * **调试线索:** 如果 JavaScript 发起的网络请求失败或返回错误的数据，开发者可能会检查 DNS 解析是否成功，以及 `DnsTaskResultsManager` 是否提供了正确的 IP 地址和元数据。

**总而言之， `dns_task_results_manager_unittest.cc` 是一个至关重要的测试文件，用于确保 Chromium 网络栈中 DNS 结果管理的核心组件 `DnsTaskResultsManager` 的正确性和健壮性。它的正常工作直接影响到用户浏览网页和进行网络交互的体验。**

### 提示词
```
这是目录为net/dns/dns_task_results_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_task_results_manager.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <string_view>

#include "base/check.h"
#include "base/functional/callback_forward.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/net_errors.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/host_resolver_results_test_util.h"
#include "net/dns/https_record_rdata.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"

using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::UnorderedElementsAre;

namespace net {

namespace {

class FakeDelegate : public DnsTaskResultsManager::Delegate {
 public:
  FakeDelegate() = default;
  ~FakeDelegate() override = default;

 private:
  void OnServiceEndpointsUpdated() override {
    // Do nothing for now.
  }
};

IPEndPoint MakeIPEndPoint(std::string_view ip_literal, uint16_t port = 0) {
  std::optional<IPAddress> ip = IPAddress::FromIPLiteral(std::move(ip_literal));
  return IPEndPoint(*ip, port);
}

std::unique_ptr<HostResolverInternalDataResult> CreateDataResult(
    std::string_view domain_name,
    std::vector<IPEndPoint> ip_endpoints,
    DnsQueryType query_type) {
  return std::make_unique<HostResolverInternalDataResult>(
      std::string(domain_name), query_type, /*expiration=*/base::TimeTicks(),
      /*timed_expiration=*/base::Time(),
      HostResolverInternalResult::Source::kDns, std::move(ip_endpoints),
      std::vector<std::string>(), std::vector<HostPortPair>());
}

std::unique_ptr<HostResolverInternalErrorResult> CreateNoData(
    std::string_view domain_name,
    DnsQueryType query_type) {
  return std::make_unique<HostResolverInternalErrorResult>(
      std::string(domain_name), query_type, /*expiration=*/base::TimeTicks(),
      /*timed_expiration=*/base::Time(),
      HostResolverInternalResult::Source::kDns, ERR_NAME_NOT_RESOLVED);
}

std::unique_ptr<HostResolverInternalMetadataResult> CreateMetadata(
    std::string_view domain_name,
    std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata> metadatas) {
  return std::make_unique<HostResolverInternalMetadataResult>(
      std::string(domain_name), DnsQueryType::HTTPS,
      /*expiration=*/base::TimeTicks(), /*timed_expiration=*/base::Time(),
      HostResolverInternalResult::Source::kDns, std::move(metadatas));
}

std::unique_ptr<HostResolverInternalAliasResult> CreateAlias(
    std::string_view domain_name,
    DnsQueryType query_type,
    std::string_view alias_target) {
  return std::make_unique<HostResolverInternalAliasResult>(
      std::string(domain_name), query_type, /*expiration=*/base::TimeTicks(),
      /*timed_expiration=*/base::Time(),
      HostResolverInternalResult::Source::kDns, std::string(alias_target));
}

std::vector<IPEndPoint> WithPort(const std::vector<IPEndPoint>& endpoints,
                                 uint16_t port) {
  std::vector<IPEndPoint> out_endpoints;
  for (const auto& endpoint : endpoints) {
    out_endpoints.emplace_back(endpoint.address(), port);
  }
  return out_endpoints;
}

static constexpr std::string_view kHostName = "www.example.com";
static constexpr std::string_view kAliasTarget1 = "alias1.example.net";
static constexpr std::string_view kAliasTarget2 = "alias2.example.net";

static const ConnectionEndpointMetadata kMetadata1(
    /*supported_protocol_alpns=*/{"h3"},
    /*ech_config_list=*/{},
    std::string(kHostName));

static const ConnectionEndpointMetadata kMetadata2(
    /*supported_protocol_alpns=*/{"h2", "http/1.1"},
    /*ech_config_list=*/{},
    std::string(kHostName));

static const std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
    kMetadatas{{1, kMetadata1}, {2, kMetadata2}};

// A helper class to create a DnsTaskResultsManager.
class ManagerFactory {
 public:
  explicit ManagerFactory(DnsTaskResultsManager::Delegate* delegate)
      : delegate_(delegate),
        host_(
            HostResolver::Host(url::SchemeHostPort("https", kHostName, 443))) {}

  std::unique_ptr<DnsTaskResultsManager> Create() {
    return std::make_unique<DnsTaskResultsManager>(
        delegate_, host_, query_types_, NetLogWithSource());
  }

  ManagerFactory& query_types(DnsQueryTypeSet query_types) {
    query_types_ = query_types;
    return *this;
  }

 private:
  raw_ptr<DnsTaskResultsManager::Delegate> delegate_;
  HostResolver::Host host_;
  DnsQueryTypeSet query_types_ = {DnsQueryType::A, DnsQueryType::AAAA,
                                  DnsQueryType::HTTPS};
};

}  // namespace

class DnsTaskResultsManagerTest : public TestWithTaskEnvironment {
 public:
  DnsTaskResultsManagerTest()
      : TestWithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

  void SetUp() override { delegate_ = std::make_unique<FakeDelegate>(); }

 protected:
  ManagerFactory factory() { return ManagerFactory(delegate_.get()); }

 private:
  std::unique_ptr<FakeDelegate> delegate_;
};

TEST_F(DnsTaskResultsManagerTest, IsMetadataReady) {
  // HTTPS RR is not queried.
  std::unique_ptr<DnsTaskResultsManager> manager =
      factory().query_types({DnsQueryType::A, DnsQueryType::AAAA}).Create();
  ASSERT_TRUE(manager->IsMetadataReady());

  // HTTPS RR is queried.
  manager = factory()
                .query_types(
                    {DnsQueryType::A, DnsQueryType::AAAA, DnsQueryType::HTTPS})
                .Create();
  ASSERT_FALSE(manager->IsMetadataReady());

  manager->ProcessDnsTransactionResults(DnsQueryType::HTTPS, /*results=*/{});
  ASSERT_TRUE(manager->IsMetadataReady());
}

TEST_F(DnsTaskResultsManagerTest, IPv6NotQueried) {
  std::unique_ptr<DnsTaskResultsManager> manager =
      factory().query_types({DnsQueryType::A, DnsQueryType::HTTPS}).Create();

  std::unique_ptr<HostResolverInternalResult> result = CreateDataResult(
      kHostName, {MakeIPEndPoint("192.0.2.1")}, DnsQueryType::A);
  manager->ProcessDnsTransactionResults(DnsQueryType::A, {result.get()});

  EXPECT_THAT(manager->GetCurrentEndpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("192.0.2.1", 443)))));
  EXPECT_THAT(manager->GetAliases(), UnorderedElementsAre(kHostName));
}

TEST_F(DnsTaskResultsManagerTest, IPv4First) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  // A comes first. Service endpoints creation should be delayed.
  std::unique_ptr<HostResolverInternalResult> result1 = CreateDataResult(
      kHostName, {MakeIPEndPoint("192.0.2.1")}, DnsQueryType::A);
  manager->ProcessDnsTransactionResults(DnsQueryType::A, {result1.get()});

  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());

  // AAAA is responded. Service endpoints should be available.
  std::unique_ptr<HostResolverInternalResult> result2 = CreateDataResult(
      kHostName, {MakeIPEndPoint("2001:db8::1")}, DnsQueryType::AAAA);
  manager->ProcessDnsTransactionResults(DnsQueryType::AAAA, {result2.get()});

  EXPECT_THAT(manager->GetCurrentEndpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("192.0.2.1", 443)),
                  ElementsAre(MakeIPEndPoint("2001:db8::1", 443)))));
}

TEST_F(DnsTaskResultsManagerTest, IPv6First) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  // AAAA comes first. Service endpoints should be available immediately.
  std::unique_ptr<HostResolverInternalResult> result1 = CreateDataResult(
      kHostName, {MakeIPEndPoint("2001:db8::1")}, DnsQueryType::AAAA);
  manager->ProcessDnsTransactionResults(DnsQueryType::AAAA, {result1.get()});

  EXPECT_THAT(manager->GetCurrentEndpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  IsEmpty(), ElementsAre(MakeIPEndPoint("2001:db8::1", 443)))));

  // A is responded. Service endpoints should be updated.
  std::unique_ptr<HostResolverInternalResult> result2 = CreateDataResult(
      kHostName, {MakeIPEndPoint("192.0.2.1"), MakeIPEndPoint("192.0.2.2")},
      DnsQueryType::A);
  manager->ProcessDnsTransactionResults(DnsQueryType::A, {result2.get()});

  EXPECT_THAT(manager->GetCurrentEndpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("192.0.2.1", 443),
                              MakeIPEndPoint("192.0.2.2", 443)),
                  ElementsAre(MakeIPEndPoint("2001:db8::1", 443)))));
}

TEST_F(DnsTaskResultsManagerTest, IPv6Timedout) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  // A comes first. Service endpoints creation should be delayed.
  std::unique_ptr<HostResolverInternalResult> result1 = CreateDataResult(
      kHostName, {MakeIPEndPoint("192.0.2.1")}, DnsQueryType::A);
  manager->ProcessDnsTransactionResults(DnsQueryType::A, {result1.get()});

  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());

  // AAAA is timed out. Service endpoints should be available after timeout.
  FastForwardBy(DnsTaskResultsManager::kResolutionDelay +
                base::Milliseconds(1));

  EXPECT_THAT(manager->GetCurrentEndpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("192.0.2.1", 443)))));

  // AAAA is responded after timeout. Service endpoints should be updated.
  std::unique_ptr<HostResolverInternalResult> result2 = CreateDataResult(
      kHostName, {MakeIPEndPoint("2001:db8::1")}, DnsQueryType::AAAA);
  manager->ProcessDnsTransactionResults(DnsQueryType::AAAA, {result2.get()});

  EXPECT_THAT(manager->GetCurrentEndpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("192.0.2.1", 443)),
                  ElementsAre(MakeIPEndPoint("2001:db8::1", 443)))));
}

TEST_F(DnsTaskResultsManagerTest, IPv6NoDataBeforeIPv4) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  // AAAA is responded with no data. Service endpoints should not be available.
  std::unique_ptr<HostResolverInternalResult> result1 =
      CreateNoData(kHostName, DnsQueryType::AAAA);
  manager->ProcessDnsTransactionResults(DnsQueryType::AAAA, {result1.get()});

  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());

  // A is responded. Service endpoints creation should happen without resolution
  // delay.
  std::unique_ptr<HostResolverInternalResult> result2 = CreateDataResult(
      kHostName, {MakeIPEndPoint("192.0.2.1")}, DnsQueryType::A);
  manager->ProcessDnsTransactionResults(DnsQueryType::A, {result2.get()});

  EXPECT_THAT(manager->GetCurrentEndpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("192.0.2.1", 443)))));
}

TEST_F(DnsTaskResultsManagerTest, IPv6NoDataAfterIPv4) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  // A is responded. Service endpoints creation should be delayed.
  std::unique_ptr<HostResolverInternalResult> result1 = CreateDataResult(
      kHostName, {MakeIPEndPoint("192.0.2.1")}, DnsQueryType::A);
  manager->ProcessDnsTransactionResults(DnsQueryType::A, {result1.get()});

  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());

  // AAAA is responded with no data before the resolution delay timer. Service
  // endpoints should be available without waiting for the timeout.
  std::unique_ptr<HostResolverInternalResult> result2 =
      CreateNoData(kHostName, DnsQueryType::AAAA);
  manager->ProcessDnsTransactionResults(DnsQueryType::AAAA, {result2.get()});

  EXPECT_THAT(manager->GetCurrentEndpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("192.0.2.1", 443)))));
}

TEST_F(DnsTaskResultsManagerTest, IPv6EmptyDataAfterIPv4) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  // A is responded. Service endpoints creation should be delayed.
  std::unique_ptr<HostResolverInternalResult> result1 = CreateDataResult(
      kHostName, {MakeIPEndPoint("192.0.2.1")}, DnsQueryType::A);
  manager->ProcessDnsTransactionResults(DnsQueryType::A, {result1.get()});

  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());

  // AAAA is responded with a non-cacheable result (an empty result) before the
  // resolution delay timer. Service endpoints should be available without
  // waiting for the timeout.
  manager->ProcessDnsTransactionResults(DnsQueryType::AAAA, {});

  EXPECT_THAT(manager->GetCurrentEndpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("192.0.2.1", 443)))));
}

TEST_F(DnsTaskResultsManagerTest, IPv4AndIPv6NoData) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  // AAAA is responded with no data. Service endpoints should not be available.
  std::unique_ptr<HostResolverInternalResult> result1 =
      CreateNoData(kHostName, DnsQueryType::AAAA);
  manager->ProcessDnsTransactionResults(DnsQueryType::AAAA, {result1.get()});

  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());

  // A is responded with no data. Service endpoints should not be available.
  std::unique_ptr<HostResolverInternalResult> result2 =
      CreateNoData(kHostName, DnsQueryType::A);
  manager->ProcessDnsTransactionResults(DnsQueryType::A, {result2.get()});

  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());
}

TEST_F(DnsTaskResultsManagerTest, IPv4NoDataIPv6AfterResolutionDelay) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  // A comes first with no data. Service endpoints creation should be delayed
  // and the resolution delay timer should not start.
  std::unique_ptr<HostResolverInternalResult> result1 =
      CreateNoData(kHostName, DnsQueryType::A);
  manager->ProcessDnsTransactionResults(DnsQueryType::A, {result1.get()});

  ASSERT_FALSE(manager->IsResolutionDelayTimerRunningForTest());
  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());

  // The resolution delay passed. Service endpoints should not be available yet.
  FastForwardBy(DnsTaskResultsManager::kResolutionDelay +
                base::Milliseconds(1));

  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());

  // AAAA is responded. Service endpoints should be updated.
  std::unique_ptr<HostResolverInternalResult> result2 = CreateDataResult(
      kHostName, {MakeIPEndPoint("2001:db8::1")}, DnsQueryType::AAAA);
  manager->ProcessDnsTransactionResults(DnsQueryType::AAAA, {result2.get()});

  EXPECT_THAT(manager->GetCurrentEndpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  IsEmpty(), ElementsAre(MakeIPEndPoint("2001:db8::1", 443)))));
}

TEST_F(DnsTaskResultsManagerTest, MetadataFirst) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  // HTTPS comes first. Service endpoints should not be available yet since
  // Chrome doesn't support ipv{4,6}hint yet.
  std::unique_ptr<HostResolverInternalResult> result1 =
      CreateMetadata(kHostName, kMetadatas);
  manager->ProcessDnsTransactionResults(DnsQueryType::HTTPS, {result1.get()});

  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());
  ASSERT_TRUE(manager->IsMetadataReady());

  // A is responded. Service endpoints creation should be delayed.
  std::unique_ptr<HostResolverInternalResult> result2 = CreateDataResult(
      kHostName, {MakeIPEndPoint("192.0.2.1")}, DnsQueryType::A);
  manager->ProcessDnsTransactionResults(DnsQueryType::A, {result2.get()});

  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());

  // AAAA is responded. Service endpoints should be available with metadatas.
  std::unique_ptr<HostResolverInternalResult> result3 = CreateDataResult(
      kHostName, {MakeIPEndPoint("2001:db8::1")}, DnsQueryType::AAAA);
  manager->ProcessDnsTransactionResults(DnsQueryType::AAAA, {result3.get()});

  EXPECT_THAT(
      manager->GetCurrentEndpoints(),
      ElementsAre(
          ExpectServiceEndpoint(ElementsAre(MakeIPEndPoint("192.0.2.1", 443)),
                                ElementsAre(MakeIPEndPoint("2001:db8::1", 443)),
                                kMetadata1),
          ExpectServiceEndpoint(ElementsAre(MakeIPEndPoint("192.0.2.1", 443)),
                                ElementsAre(MakeIPEndPoint("2001:db8::1", 443)),
                                kMetadata2)));
}

TEST_F(DnsTaskResultsManagerTest, MetadataDifferentTargetName) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  // HTTPS is responded and the target name is different from QNAME.
  const ConnectionEndpointMetadata kMetadataDifferentTargetName(
      /*supported_protocol_alpns=*/{"h2", "http/1.1"},
      /*ech_config_list=*/{},
      /*target_name=*/"other.example.net.");
  std::unique_ptr<HostResolverInternalResult> result1 =
      CreateMetadata(kHostName, {{1, kMetadataDifferentTargetName}});
  manager->ProcessDnsTransactionResults(DnsQueryType::HTTPS, {result1.get()});

  ASSERT_TRUE(manager->IsMetadataReady());

  // AAAA is responded. Service endpoints should be available without metadatas
  // since the target name is different.
  std::unique_ptr<HostResolverInternalResult> result2 = CreateDataResult(
      kHostName, {MakeIPEndPoint("2001:db8::1")}, DnsQueryType::AAAA);
  manager->ProcessDnsTransactionResults(DnsQueryType::AAAA, {result2.get()});

  ASSERT_TRUE(manager->IsMetadataReady());
  EXPECT_THAT(manager->GetCurrentEndpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  IsEmpty(), ElementsAre(MakeIPEndPoint("2001:db8::1", 443)))));
}

TEST_F(DnsTaskResultsManagerTest, MetadataAfterIPv6) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  // AAAA comes first. Service endpoints should be available without metadatas.
  std::unique_ptr<HostResolverInternalResult> result1 = CreateDataResult(
      kHostName, {MakeIPEndPoint("2001:db8::1")}, DnsQueryType::AAAA);
  manager->ProcessDnsTransactionResults(DnsQueryType::AAAA, {result1.get()});

  ASSERT_FALSE(manager->IsMetadataReady());
  EXPECT_THAT(manager->GetCurrentEndpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  IsEmpty(), ElementsAre(MakeIPEndPoint("2001:db8::1", 443)))));

  // HTTPS is responded. Metadata should be available.
  std::unique_ptr<HostResolverInternalResult> result2 =
      CreateMetadata(kHostName, kMetadatas);
  manager->ProcessDnsTransactionResults(DnsQueryType::HTTPS, {result2.get()});

  ASSERT_TRUE(manager->IsMetadataReady());
  EXPECT_THAT(
      manager->GetCurrentEndpoints(),
      ElementsAre(
          ExpectServiceEndpoint(IsEmpty(),
                                ElementsAre(MakeIPEndPoint("2001:db8::1", 443)),
                                kMetadata1),
          ExpectServiceEndpoint(IsEmpty(),
                                ElementsAre(MakeIPEndPoint("2001:db8::1", 443)),
                                kMetadata2)));
}

TEST_F(DnsTaskResultsManagerTest, IPv6TimedoutAfterMetadata) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  // A comes first. Service endpoints creation should be delayed.
  std::unique_ptr<HostResolverInternalResult> result1 = CreateDataResult(
      kHostName, {MakeIPEndPoint("192.0.2.1")}, DnsQueryType::A);
  manager->ProcessDnsTransactionResults(DnsQueryType::A, {result1.get()});

  ASSERT_FALSE(manager->IsMetadataReady());
  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());

  // HTTPS is responded. Service endpoints should not be available because
  // the manager is waiting for the resolution delay and Chrome doesn't support
  // ipv6hint yet.
  std::unique_ptr<HostResolverInternalResult> result2 =
      CreateMetadata(kHostName, kMetadatas);
  manager->ProcessDnsTransactionResults(DnsQueryType::HTTPS, {result2.get()});

  ASSERT_TRUE(manager->IsMetadataReady());
  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());

  // AAAA is timed out. Service endpoints should be available with metadatas.
  FastForwardBy(DnsTaskResultsManager::kResolutionDelay +
                base::Milliseconds(1));

  ASSERT_TRUE(manager->IsMetadataReady());
  EXPECT_THAT(
      manager->GetCurrentEndpoints(),
      ElementsAre(
          ExpectServiceEndpoint(ElementsAre(MakeIPEndPoint("192.0.2.1", 443)),
                                IsEmpty(), kMetadata1),
          ExpectServiceEndpoint(ElementsAre(MakeIPEndPoint("192.0.2.1", 443)),
                                IsEmpty(), kMetadata2)));
}

TEST_F(DnsTaskResultsManagerTest, IPv4NoDataIPv6TimedoutAfterMetadata) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  // HTTPS is responded. Service endpoints should not be available because
  // the manager is waiting for the resolution delay and Chrome doesn't support
  // address hints yet.
  std::unique_ptr<HostResolverInternalResult> result1 =
      CreateMetadata(kHostName, kMetadatas);
  manager->ProcessDnsTransactionResults(DnsQueryType::HTTPS, {result1.get()});

  ASSERT_TRUE(manager->IsMetadataReady());
  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());

  // A is responded with no address. Service endpoints should not be available
  // since there are no addresses.
  std::unique_ptr<HostResolverInternalResult> result2 =
      CreateNoData(kHostName, DnsQueryType::A);
  manager->ProcessDnsTransactionResults(DnsQueryType::A, {result2.get()});

  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());

  // AAAA is timed out. Service endpoints should not be available since there
  // are no addresses.
  FastForwardBy(DnsTaskResultsManager::kResolutionDelay +
                base::Milliseconds(1));

  ASSERT_TRUE(manager->GetCurrentEndpoints().empty());
}

TEST_F(DnsTaskResultsManagerTest, EndpointOrdering) {
  // Has both IPv4/v6 addresses and metadata.
  constexpr static const std::string_view kSvcbHost1 = "svc1.example.com";
  // Has both IPv4/v6 addresses but no metadata.
  constexpr static const std::string_view kSvcbHost2 = "svc2.example.com";
  // Only has IPv4 addresses.
  constexpr static const std::string_view kSvcbHost3 = "svc3.example.com";

  const std::vector<IPEndPoint> kSvcbHost1IPv4s = {MakeIPEndPoint("192.0.2.1")};
  const std::vector<IPEndPoint> kSvcbHost2IPv4s = {MakeIPEndPoint("192.0.2.2")};
  const std::vector<IPEndPoint> kSvcbHost3IPv4s = {MakeIPEndPoint("192.0.2.3")};

  const std::vector<IPEndPoint> kSvcbHost1IPv6s = {
      MakeIPEndPoint("2001:db8::1")};
  const std::vector<IPEndPoint> kSvcbHost2IPv6s = {
      MakeIPEndPoint("2001:db8::2")};

  const ConnectionEndpointMetadata kSvcbHost1Metadata1(
      /*supported_protocol_alpns=*/{"h2", "http/1.1"},
      /*ech_config_list=*/{},
      /*target_name=*/std::string(kSvcbHost1));
  const ConnectionEndpointMetadata kSvcbHost1Metadata2(
      /*supported_protocol_alpns=*/{"h3"},
      /*ech_config_list=*/{},
      /*target_name=*/std::string(kSvcbHost1));

  const std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
      kSvcbHost1Metadatas{{1, kSvcbHost1Metadata1}, {2, kSvcbHost1Metadata2}};

  struct TestData {
    std::string_view host;
    std::vector<IPEndPoint> ipv4_endpoints;
    std::vector<IPEndPoint> ipv6_endpoints;
    std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata> metadatas;
  };
  const TestData kTestDatas[] = {
      {kSvcbHost1,
       /*ipv4_addresses=*/kSvcbHost1IPv4s,
       /*ipv6_addresses=*/kSvcbHost1IPv6s,
       /*metadatas=*/kSvcbHost1Metadatas},
      {kSvcbHost2,
       /*ipv4_addresses=*/kSvcbHost2IPv4s,
       /*ipv6_addresses=*/kSvcbHost2IPv6s,
       /*metadatas=*/{}},
      {kSvcbHost3, /*ipv4_addresses=*/kSvcbHost3IPv4s,
       /*ipv6_addresses=*/{}, /*metadatas=*/{}},
  };

  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  for (const auto& testdata : kTestDatas) {
    if (!testdata.ipv4_endpoints.empty()) {
      std::unique_ptr<HostResolverInternalResult> result = CreateDataResult(
          testdata.host, testdata.ipv4_endpoints, DnsQueryType::A);
      manager->ProcessDnsTransactionResults(DnsQueryType::A, {result.get()});
    }
    if (!testdata.ipv6_endpoints.empty()) {
      std::unique_ptr<HostResolverInternalResult> result = CreateDataResult(
          testdata.host, testdata.ipv6_endpoints, DnsQueryType::AAAA);
      manager->ProcessDnsTransactionResults(DnsQueryType::AAAA, {result.get()});
    }
    if (!testdata.metadatas.empty()) {
      std::unique_ptr<HostResolverInternalResult> result =
          CreateMetadata(testdata.host, testdata.metadatas);
      manager->ProcessDnsTransactionResults(DnsQueryType::HTTPS,
                                            {result.get()});
    }
  }

  const std::vector<ServiceEndpoint> kExpects = {
      ServiceEndpoint(WithPort(kSvcbHost1IPv4s, 443),
                      WithPort(kSvcbHost1IPv6s, 443), kSvcbHost1Metadata1),
      ServiceEndpoint(WithPort(kSvcbHost1IPv4s, 443),
                      WithPort(kSvcbHost1IPv6s, 443), kSvcbHost1Metadata2),
      ServiceEndpoint(WithPort(kSvcbHost2IPv4s, 443),
                      WithPort(kSvcbHost2IPv6s, 443),
                      ConnectionEndpointMetadata()),
      ServiceEndpoint(WithPort(kSvcbHost3IPv4s, 443), {},
                      ConnectionEndpointMetadata()),
  };

  ASSERT_EQ(manager->GetCurrentEndpoints().size(), kExpects.size());
  for (size_t i = 0; i < manager->GetCurrentEndpoints().size(); ++i) {
    SCOPED_TRACE(i);
    EXPECT_THAT(manager->GetCurrentEndpoints()[i], kExpects[i]);
  }
}

TEST_F(DnsTaskResultsManagerTest, Aliases) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  // AAAA is responded with aliases.
  std::unique_ptr<HostResolverInternalResult> result1 =
      CreateAlias(kHostName, DnsQueryType::AAAA, kAliasTarget1);
  std::unique_ptr<HostResolverInternalResult> result2 =
      CreateAlias(kAliasTarget1, DnsQueryType::AAAA, kAliasTarget2);
  std::unique_ptr<HostResolverInternalResult> result3 = CreateDataResult(
      kHostName, {MakeIPEndPoint("2001:db8::1")}, DnsQueryType::AAAA);
  manager->ProcessDnsTransactionResults(
      DnsQueryType::AAAA, {result1.get(), result2.get(), result3.get()});

  EXPECT_THAT(manager->GetCurrentEndpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  IsEmpty(), ElementsAre(MakeIPEndPoint("2001:db8::1", 443)))));
  EXPECT_THAT(manager->GetAliases(),
              UnorderedElementsAre(kHostName, kAliasTarget1, kAliasTarget2));
}

// Regression test for crbug.com/369232963. An IPv4 mapped IPv6 address should
// be handled without crashing.
TEST_F(DnsTaskResultsManagerTest, Ipv4MappedIpv6) {
  std::unique_ptr<DnsTaskResultsManager> manager = factory().Create();

  auto ip_address = *IPAddress::FromIPLiteral("::ffff:192.0.2.1");
  IPEndPoint endpoint(ConvertIPv4MappedIPv6ToIPv4(ip_address), /*port=*/0);
  std::unique_ptr<HostResolverInternalResult> result =
      CreateDataResult(kHostName, {endpoint}, DnsQueryType::AAAA);
  manager->ProcessDnsTransactionResults(DnsQueryType::AAAA, {result.get()});
  EXPECT_THAT(manager->GetCurrentEndpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("192.0.2.1", 443)), IsEmpty())));
}

}  // namespace net
```