Response:
The user wants a summary of the functionality of the C++ code provided. I need to analyze the code and identify its purpose and key operations. The code seems to be a unit test for the `HostResolver::ServiceEndpointRequest` functionality in Chromium's networking stack.

Here's a breakdown of the code's components and their likely purpose:

- **Includes:** Standard C++ library headers and Chromium-specific headers related to networking, DNS, and testing.
- **Helper Functions:** `MakeIPEndPoint` to create `IPEndPoint` objects, `FakeAddressSorter` to simulate IP address sorting.
- **`Requester` Class:** A test fixture to manage and interact with `ServiceEndpointRequest` objects, allowing for starting, cancelling, waiting for completion, and retrieving results.
- **`LegacyRequester` Class:** A test fixture similar to `Requester` but for older `ResolveHostRequest`.
- **`HostResolverServiceEndpointRequestTest` Class:** The main test fixture, inheriting from `HostResolverManagerDnsTest`, which likely provides a mocked DNS environment.
- **Test Cases:**  Various `TEST_F` macros defining individual test scenarios for different aspects of `ServiceEndpointRequest` behavior, such as resolving names, handling timeouts, cancellation, sorting, and interactions with multiple requests.

Therefore, the core functionality of this file is to **test the `HostResolver::ServiceEndpointRequest` class**, ensuring it behaves correctly under various conditions and scenarios.

Now, let's address the specific points requested by the user:

- **Functionality:**  As stated above, the file tests `HostResolver::ServiceEndpointRequest`.
- **Relationship with JavaScript:**  While this is C++ code, it's part of Chromium's networking stack, which directly supports web browsing initiated by JavaScript in web pages. When a JavaScript makes a network request (e.g., using `fetch` or `XMLHttpRequest`), the browser's networking stack, including the DNS resolver, is involved.
- **Logical Reasoning (Hypothetical Input/Output):** Test cases often involve setting up specific DNS configurations and then initiating a `ServiceEndpointRequest`. For example, a test case might set up a DNS rule that delays the IPv4 response and then check if the `ServiceEndpointRequest` correctly provides IPv6 endpoints first.
- **User/Programming Errors:** The tests implicitly cover potential errors. For instance, a test might check how the system handles a DNS timeout, which could be due to network issues or misconfiguration. A common programming error could be not handling the asynchronous nature of DNS resolution correctly.
- **User Steps to Reach Here (Debugging):**  A developer debugging a network issue in a web page might trace the execution flow through the Chromium source code and eventually reach the DNS resolution components, including this test file, to understand how DNS requests are handled.
这是目录为 `net/dns/host_resolver_service_endpoint_request_unittest.cc` 的 chromium 网络栈的源代码文件。根据其内容，我们可以归纳一下它的功能：

**功能归纳：**

该文件是 **`HostResolver::ServiceEndpointRequest` 类的单元测试文件**。它旨在测试在 Chromium 网络栈中，用于解析服务终端节点（Service Endpoint，通常用于 HTTPS SVCB 记录）请求的功能是否正常工作。

**更具体的功能点包括：**

1. **测试基本的域名解析成功和失败场景：** 验证 `ServiceEndpointRequest` 能否正确处理域名解析成功（返回 IP 地址和端口）和失败（如域名不存在、超时）的情况。
2. **测试异步解析流程：**  验证请求的启动、更新（中间结果）和完成回调是否按预期工作，尤其是在 DNS 查询需要一段时间才能完成的情况下。
3. **测试请求的取消功能：**  验证在请求进行中时取消请求是否能正确停止解析过程，并触发相应的回调。
4. **测试 Happy Eyeballs V3 功能：**  验证在启用 Happy Eyeballs V3 功能时，`ServiceEndpointRequest` 如何处理 IPv4 和 IPv6 地址的并行解析，以及在部分解析完成后是否能及时提供可用终端节点。
5. **测试 DNS 缓存交互：**  验证 `ServiceEndpointRequest` 如何与 DNS 缓存交互，包括本地缓存命中和未命中的情况。
6. **测试地址排序功能：** 验证解析出的 IP 地址是否按照期望的顺序排列（通过 `FakeAddressSorter` 模拟）。
7. **测试在解析过程中销毁 Resolver 的情况：**  验证在请求进行中或即将完成时销毁 `HostResolver` 对象是否会导致崩溃或未定义的行为。
8. **测试多并发请求的处理：**  验证多个 `ServiceEndpointRequest` 请求同一个域名时，是否能共享底层的 DNS 解析任务，避免重复查询。
9. **测试不同 DNS 延迟场景：**  模拟 IPv4、IPv6 和 HTTPS 记录的不同延迟情况，验证 `ServiceEndpointRequest` 的处理逻辑是否正确。
10. **测试 `EndpointsCryptoReady()` 方法：** 验证在不同的解析阶段，`EndpointsCryptoReady()` 方法的返回值是否符合预期。

**与 JavaScript 的功能关系：**

该文件中的 C++ 代码直接支撑着浏览器中 JavaScript 发起的网络请求。当 JavaScript 代码（例如使用 `fetch()` 或 `XMLHttpRequest`）请求一个 HTTPS 资源时，浏览器会调用底层的网络栈进行域名解析，其中包括查询 SVCB 记录以获取服务的终端节点信息。

**举例说明：**

假设 JavaScript 代码尝试访问 `https://example.com`:

```javascript
fetch('https://example.com')
  .then(response => {
    console.log('请求成功', response);
  })
  .catch(error => {
    console.error('请求失败', error);
  });
```

当执行这段 JavaScript 代码时，Chromium 浏览器的网络栈会创建一个 `ServiceEndpointRequest` 对象来解析 `example.com` 的终端节点。该测试文件就是用来验证这个 `ServiceEndpointRequest` 对象在各种情况下是否能正确完成解析，例如：

* **假设 `example.com` 配置了 SVCB 记录：**  `ServiceEndpointRequest` 应该能够解析出 SVCB 记录中指定的 IP 地址、端口和 ALPN 等信息。测试用例会模拟这种情况，并验证解析结果是否符合预期。
* **假设 `example.com` 没有配置 SVCB 记录：** `ServiceEndpointRequest` 应该回退到传统的 A 和 AAAA 记录解析。测试用例会验证这种回退机制是否正确。
* **假设 DNS 解析超时：** 测试用例会模拟 DNS 服务器无响应的情况，验证 `ServiceEndpointRequest` 是否能正确处理超时错误，并将错误信息传递给上层。

**逻辑推理（假设输入与输出）：**

**假设输入：**

1. **主机名：** "test.example"
2. **DNS 规则配置：**
    *   `test.example` 的 A 记录解析延迟 50ms，返回 IP 地址 "192.0.2.1"。
    *   `test.example` 的 AAAA 记录立即返回 IP 地址 "2001:db8::1"。
    *   `test.example` 的 HTTPS 记录立即返回一个 SVCB 记录，指定端口 443 和 ALPN "h3"。

**预期输出：**

1. `ServiceEndpointRequest` 启动后，会先获得 IPv6 地址 "2001:db8::1:443"。
2. 在 50ms 后，获得 IPv4 地址 "192.0.2.1:443"。
3. 最终完成解析，返回的终端节点列表包含：
    *   `[192.0.2.1:443]` (IPv4)
    *   `[2001:db8::1:443]` (IPv6)
    *   一个包含 SVCB 信息的终端节点，例如：`[192.0.2.1:443, 2001:db8::1:443]`，并带有 ALPN "h3"。

**涉及用户或编程常见的使用错误：**

1. **未处理异步回调：** 开发者可能会忘记等待 `ServiceEndpointRequest` 的完成回调，就尝试使用解析结果，导致数据未就绪。测试用例中的 `WaitForFinished()` 就是用来模拟这种等待。
2. **过早取消请求：**  在请求完成之前意外地取消了 `ServiceEndpointRequest`，导致请求失败。测试用例 `CancelRequestOnUpdated` 和 `CancelRequestOnFinished` 模拟了这种情况。
3. **假设解析总是同步的：** 开发者可能会错误地假设 DNS 解析会立即完成，而没有考虑到网络延迟等因素。测试用例中使用了延迟的 DNS 规则来模拟这种情况。
4. **资源泄漏：** 如果 `ServiceEndpointRequest` 对象没有被正确销毁，可能会导致资源泄漏。测试用例中模拟了在解析过程中销毁 `HostResolver` 的情况，以检查是否会发生错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在浏览器中访问一个 HTTPS 网站 `https://slow.example.com`，该网站的 DNS 解析很慢。作为调试线索，可以按以下步骤追踪到 `host_resolver_service_endpoint_request_unittest.cc`：

1. **用户在浏览器地址栏输入 `https://slow.example.com` 并回车。**
2. **浏览器开始进行 URL 解析和导航流程。**
3. **浏览器需要获取 `slow.example.com` 的 IP 地址和端口信息。** 这时，网络栈会创建一个 `HostResolver::ServiceEndpointRequest` 对象。
4. **`ServiceEndpointRequest` 对象会向 DNS 服务器发起 DNS 查询，包括 A、AAAA 和 HTTPS (SVCB) 记录查询。**
5. **由于 `slow.example.com` 的 DNS 解析很慢，`ServiceEndpointRequest` 会处于等待状态。**
6. **如果开发者想要调试这个过程，可能会：**
    *   **使用 Chromium 的网络事件查看器 (chrome://net-export/)** 捕获网络日志，查看 DNS 查询的状态和耗时。
    *   **在 Chromium 源代码中设置断点，跟踪 `HostResolver` 和 `ServiceEndpointRequest` 的执行流程。**  可能会在 `net/dns/host_resolver_impl.cc` 中找到创建 `ServiceEndpointRequest` 的代码，然后逐步进入 `net/dns/host_resolver_manager_service_endpoint_request_impl.cc` 和相关的 DNS 查询代码。
    *   **查看单元测试文件，如 `host_resolver_service_endpoint_request_unittest.cc`，以了解 `ServiceEndpointRequest` 的预期行为和各种测试场景。** 这有助于理解在 DNS 解析缓慢的情况下，代码的逻辑和状态变化。测试用例中模拟的延迟 DNS 规则 (`UseIpv4DelayedDnsRules` 等) 就可能与用户遇到的实际情况类似。

**这是第1部分，共2部分，请归纳一下它的功能：**

总结来说，作为第一部分，这个文件主要 **定义了一些辅助类和测试基础设施，用于创建和管理 `HostResolver::ServiceEndpointRequest` 对象，并提供了用于进行各种单元测试的基本框架**。它包含了 `Requester` 和 `LegacyRequester` 辅助类，以及 `HostResolverServiceEndpointRequestTest` 测试 fixture，并定义了一些基础的测试用例，例如测试域名不存在和超时的场景。它为后续更复杂的测试场景奠定了基础。

Prompt: 
```
这是目录为net/dns/host_resolver_service_endpoint_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "base/functional/callback.h"
#include "base/run_loop.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "net/base/address_family.h"
#include "net/base/features.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/request_priority.h"
#include "net/dns/address_sorter.h"
#include "net/dns/dns_task_results_manager.h"
#include "net/dns/dns_test_util.h"
#include "net/dns/host_resolver.h"
#include "net/dns/host_resolver_manager_service_endpoint_request_impl.h"
#include "net/dns/host_resolver_manager_unittest.h"
#include "net/dns/host_resolver_results_test_util.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/public/host_resolver_source.h"
#include "net/dns/resolve_context.h"
#include "net/log/net_log_with_source.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/scheme_host_port.h"

using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::Optional;
using ::testing::UnorderedElementsAre;

using net::test::IsError;
using net::test::IsOk;

namespace net {

using ServiceEndpointRequest = HostResolver::ServiceEndpointRequest;
using ResolveHostRequest = HostResolver::ResolveHostRequest;
using ResolveHostParameters = HostResolver::ResolveHostParameters;

namespace {

IPEndPoint MakeIPEndPoint(std::string_view ip_literal, uint16_t port = 0) {
  std::optional<IPAddress> ip = IPAddress::FromIPLiteral(std::move(ip_literal));
  return IPEndPoint(*ip, port);
}

// Sorts endpoints using IPAddress's comparator.
class FakeAddressSorter : public AddressSorter {
 public:
  void Sort(const std::vector<IPEndPoint>& endpoints,
            CallbackType callback) const override {
    std::vector<IPEndPoint> sorted = endpoints;
    std::sort(sorted.begin(), sorted.end(),
              [](const IPEndPoint& a, const IPEndPoint& b) {
                return a.address() < b.address();
              });
    std::move(callback).Run(true, sorted);
  }
};

class Requester : public ServiceEndpointRequest::Delegate {
 public:
  explicit Requester(std::unique_ptr<ServiceEndpointRequest> request)
      : request_(std::move(request)) {}

  ~Requester() override = default;

  // ServiceEndpointRequest::Delegate overrides:

  void OnServiceEndpointsUpdated() override {
    if (on_updated_callback_) {
      std::move(on_updated_callback_).Run();
    }
  }

  void OnServiceEndpointRequestFinished(int rv) override {
    SetFinishedResult(rv);

    if (on_finished_callback_) {
      std::move(on_finished_callback_).Run();
    }

    if (wait_for_finished_callback_) {
      std::move(wait_for_finished_callback_).Run();
    }
  }

  int Start() {
    int rv = request_->Start(this);
    if (rv != ERR_IO_PENDING) {
      SetFinishedResult(rv);
    }
    return rv;
  }

  void CancelRequest() { request_.reset(); }

  void CancelRequestOnUpdated() {
    SetOnUpdatedCallback(base::BindLambdaForTesting([&] { CancelRequest(); }));
  }

  void CancelRequestOnFinished() {
    SetOnFinishedCallback(base::BindLambdaForTesting([&] { CancelRequest(); }));
  }

  void SetOnUpdatedCallback(base::OnceClosure callback) {
    CHECK(!finished_result_);
    CHECK(!on_updated_callback_);
    on_updated_callback_ = std::move(callback);
  }

  void SetOnFinishedCallback(base::OnceClosure callback) {
    CHECK(!finished_result_);
    CHECK(!on_finished_callback_);
    on_finished_callback_ = std::move(callback);
  }

  void WaitForFinished() {
    CHECK(!finished_result_);
    CHECK(!wait_for_finished_callback_);
    base::RunLoop run_loop;
    wait_for_finished_callback_ = run_loop.QuitClosure();
    run_loop.Run();
  }

  void WaitForOnUpdated() {
    base::RunLoop run_loop;
    SetOnUpdatedCallback(run_loop.QuitClosure());
    run_loop.Run();
  }

  ServiceEndpointRequest* request() const { return request_.get(); }

  std::optional<int> finished_result() const { return finished_result_; }

  const std::vector<ServiceEndpoint>& finished_endpoints() const {
    CHECK(finished_result_.has_value());
    return finished_endpoints_;
  }

 private:
  void SetFinishedResult(int rv) {
    CHECK(!finished_result_);
    finished_result_ = rv;

    if (request_) {
      finished_endpoints_ = request_->GetEndpointResults();
    }
  }

  std::unique_ptr<ServiceEndpointRequest> request_;

  std::optional<int> finished_result_;
  std::vector<ServiceEndpoint> finished_endpoints_;

  base::OnceClosure wait_for_finished_callback_;
  base::OnceClosure on_updated_callback_;
  base::OnceClosure on_finished_callback_;
};

class LegacyRequester {
 public:
  explicit LegacyRequester(std::unique_ptr<ResolveHostRequest> request)
      : request_(std::move(request)) {}

  ~LegacyRequester() = default;

  int Start() {
    return request_->Start(
        base::BindOnce(&LegacyRequester::OnComplete, base::Unretained(this)));
  }

  void CancelRequest() { request_.reset(); }

  std::optional<int> complete_result() const { return complete_result_; }

 private:
  void OnComplete(int rv) { complete_result_ = rv; }

  std::unique_ptr<ResolveHostRequest> request_;
  std::optional<int> complete_result_;
};

}  // namespace

class HostResolverServiceEndpointRequestTest
    : public HostResolverManagerDnsTest {
 public:
  HostResolverServiceEndpointRequestTest() {
    feature_list_.InitAndEnableFeature(features::kHappyEyeballsV3);
  }

  ~HostResolverServiceEndpointRequestTest() override = default;

 protected:
  void SetUp() override {
    HostResolverManagerDnsTest::SetUp();

    // MockHostResolverProc resolves all requests to "127.0.0.1" when there is
    // no rule. Add a rule to prevent the default behavior.
    proc_->AddRule(std::string(), ADDRESS_FAMILY_UNSPECIFIED, "192.0.2.1");
  }

  void set_globally_reachable_check_is_async(bool is_async) {
    globally_reachable_check_is_async_ = is_async;
  }

  void set_ipv6_reachable(bool reachable) { ipv6_reachable_ = reachable; }

  void SetDnsRules(MockDnsClientRuleList rules) {
    CreateResolverWithOptionsAndParams(
        DefaultOptions(),
        HostResolverSystemTask::Params(proc_,
                                       /*max_retry_attempts=*/1),
        ipv6_reachable_,
        /*is_async=*/globally_reachable_check_is_async_,
        /*ipv4_reachable=*/true);
    UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  }

  void UseNoDomanDnsRules(const std::string& host) {
    MockDnsClientRuleList rules;
    AddDnsRule(&rules, host, dns_protocol::kTypeA,
               MockDnsClientRule::ResultType::kNoDomain, /*delay=*/false);
    AddDnsRule(&rules, host, dns_protocol::kTypeAAAA,
               MockDnsClientRule::ResultType::kNoDomain, /*delay=*/false);
    SetDnsRules(std::move(rules));
  }

  void UseTimedOutDnsRules(const std::string& host) {
    MockDnsClientRuleList rules;
    AddDnsRule(&rules, host, dns_protocol::kTypeA,
               MockDnsClientRule::ResultType::kTimeout, /*delay=*/false);
    AddDnsRule(&rules, host, dns_protocol::kTypeAAAA,
               MockDnsClientRule::ResultType::kTimeout, /*delay=*/false);
    SetDnsRules(std::move(rules));
  }

  void UseNonDelayedDnsRules(const std::string& host) {
    MockDnsClientRuleList rules;
    AddDnsRule(&rules, host, dns_protocol::kTypeA,
               MockDnsClientRule::ResultType::kOk, /*delay=*/false);
    AddDnsRule(&rules, host, dns_protocol::kTypeAAAA,
               MockDnsClientRule::ResultType::kOk, /*delay=*/false);
    SetDnsRules(std::move(rules));
  }

  void UseIpv4DelayedDnsRules(const std::string& host) {
    MockDnsClientRuleList rules;
    AddDnsRule(&rules, host, dns_protocol::kTypeA,
               MockDnsClientRule::ResultType::kOk, /*delay=*/true);
    AddDnsRule(&rules, host, dns_protocol::kTypeAAAA,
               MockDnsClientRule::ResultType::kOk, /*delay=*/false);
    SetDnsRules(std::move(rules));
  }

  void UseIpv6DelayedDnsRules(const std::string& host) {
    MockDnsClientRuleList rules;
    AddDnsRule(&rules, host, dns_protocol::kTypeA,
               MockDnsClientRule::ResultType::kOk, /*delay=*/false);
    AddDnsRule(&rules, host, dns_protocol::kTypeAAAA,
               MockDnsClientRule::ResultType::kOk, /*delay=*/true);
    SetDnsRules(std::move(rules));
  }

  void UseHttpsDelayedDnsRules(const std::string& host) {
    MockDnsClientRuleList rules;
    AddDnsRule(&rules, host, dns_protocol::kTypeA,
               MockDnsClientRule::ResultType::kOk, /*delay=*/false);
    AddDnsRule(&rules, host, dns_protocol::kTypeAAAA,
               MockDnsClientRule::ResultType::kOk, /*delay=*/false);

    std::vector<DnsResourceRecord> records = {
        BuildTestHttpsServiceRecord(host, /*priority=*/1, /*service_name=*/".",
                                    /*params=*/{})};
    rules.emplace_back(host, dns_protocol::kTypeHttps,
                       /*secure=*/false,
                       MockDnsClientRule::Result(BuildTestDnsResponse(
                           host, dns_protocol::kTypeHttps, records)),
                       /*delay=*/true);
    SetDnsRules(std::move(rules));
  }

  std::unique_ptr<ServiceEndpointRequest> CreateRequest(
      std::string_view host,
      ResolveHostParameters parameters = ResolveHostParameters()) {
    return resolver_->CreateServiceEndpointRequest(
        url::SchemeHostPort(GURL(host)), NetworkAnonymizationKey(),
        NetLogWithSource(), std::move(parameters), resolve_context_.get());
  }

  Requester CreateRequester(
      std::string_view host,
      ResolveHostParameters parameters = ResolveHostParameters()) {
    return Requester(CreateRequest(host, std::move(parameters)));
  }

  LegacyRequester CreateLegacyRequester(std::string_view host) {
    return LegacyRequester(resolver_->CreateRequest(
        url::SchemeHostPort(GURL(host)), NetworkAnonymizationKey(),
        NetLogWithSource(), ResolveHostParameters(), resolve_context_.get()));
  }

 private:
  base::test::ScopedFeatureList feature_list_;

  bool ipv6_reachable_ = true;
  bool globally_reachable_check_is_async_ = false;
};

TEST_F(HostResolverServiceEndpointRequestTest, NameNotResolved) {
  UseNoDomanDnsRules("nodomain");

  proc_->SignalMultiple(1u);
  Requester requester = CreateRequester("https://nodomain");
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  requester.WaitForFinished();
  EXPECT_THAT(*requester.finished_result(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(requester.request()->GetResolveErrorInfo(),
              ResolveErrorInfo(ERR_NAME_NOT_RESOLVED));
}

TEST_F(HostResolverServiceEndpointRequestTest, TimedOut) {
  UseTimedOutDnsRules("timeout");
  set_allow_fallback_to_systemtask(false);

  proc_->SignalMultiple(1u);
  Requester requester = CreateRequester("https://timeout");
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  requester.WaitForFinished();
  EXPECT_THAT(requester.finished_result(),
              Optional(IsError(ERR_NAME_NOT_RESOLVED)));
  EXPECT_THAT(requester.request()->GetResolveErrorInfo().error,
              IsError(ERR_DNS_TIMED_OUT));
}

// Tests that a request returns valid endpoints and DNS aliases after DnsTasks
// are aborted.
TEST_F(HostResolverServiceEndpointRequestTest, KillDnsTask) {
  UseIpv4DelayedDnsRules("4slow_ok");

  proc_->SignalMultiple(1u);
  Requester requester = CreateRequester("https://4slow_ok");
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  requester.WaitForOnUpdated();

  // Simulate the case when the preference or policy has disabled the insecure
  // DNS client causing AbortInsecureDnsTasks.
  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/false, /*additional_dns_types_enabled=*/false);
  ASSERT_TRUE(requester.request()->GetEndpointResults().empty());
  ASSERT_TRUE(requester.request()->GetDnsAliasResults().empty());
}

TEST_F(HostResolverServiceEndpointRequestTest, Ok) {
  UseNonDelayedDnsRules("ok");

  Requester requester = CreateRequester("https://ok");
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  requester.WaitForFinished();
  EXPECT_THAT(*requester.finished_result(), IsOk());
  EXPECT_THAT(requester.finished_endpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                  ElementsAre(MakeIPEndPoint("::1", 443)))));
}

TEST_F(HostResolverServiceEndpointRequestTest,
       Ipv6GloballyReachableCheckAsyncOk) {
  set_globally_reachable_check_is_async(true);
  UseNonDelayedDnsRules("ok");

  Requester requester = CreateRequester("https://ok");
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  requester.WaitForFinished();
  EXPECT_THAT(*requester.finished_result(), IsOk());
  EXPECT_THAT(requester.finished_endpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                  ElementsAre(MakeIPEndPoint("::1", 443)))));
}

TEST_F(HostResolverServiceEndpointRequestTest, Ipv6GloballyReachableCheckFail) {
  set_ipv6_reachable(false);
  set_globally_reachable_check_is_async(true);
  UseNonDelayedDnsRules("ok");

  Requester requester = CreateRequester("https://ok");
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  requester.WaitForFinished();
  EXPECT_THAT(*requester.finished_result(), IsOk());
  EXPECT_THAT(requester.finished_endpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)))));
  EXPECT_FALSE(GetLastIpv6ProbeResult());
}

TEST_F(HostResolverServiceEndpointRequestTest, ResolveLocally) {
  UseNonDelayedDnsRules("ok");

  // The first local only request should complete synchronously with a cache
  // miss.
  {
    ResolveHostParameters parameters;
    parameters.source = HostResolverSource::LOCAL_ONLY;
    Requester requester = CreateRequester("https://ok", std::move(parameters));
    int rv = requester.Start();
    EXPECT_THAT(rv, IsError(ERR_DNS_CACHE_MISS));
    EXPECT_THAT(requester.request()->GetResolveErrorInfo(),
                ResolveErrorInfo(ERR_DNS_CACHE_MISS));
  }

  // Populate the cache.
  {
    Requester requester = CreateRequester("https://ok");
    int rv = requester.Start();
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    requester.WaitForFinished();
    EXPECT_THAT(*requester.finished_result(), IsOk());
    EXPECT_THAT(requester.finished_endpoints(),
                ElementsAre(ExpectServiceEndpoint(
                    ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                    ElementsAre(MakeIPEndPoint("::1", 443)))));
  }

  // The second local only request should complete synchronously with a cache
  // hit.
  {
    ResolveHostParameters parameters;
    parameters.source = HostResolverSource::LOCAL_ONLY;
    Requester requester = CreateRequester("https://ok", std::move(parameters));
    int rv = requester.Start();
    EXPECT_THAT(rv, IsOk());
    EXPECT_THAT(requester.finished_endpoints(),
                ElementsAre(ExpectServiceEndpoint(
                    ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                    ElementsAre(MakeIPEndPoint("::1", 443)))));
  }
}

// Test that a local only request fails due to a blocked reachability check.
TEST_F(HostResolverServiceEndpointRequestTest,
       Ipv6GloballyReachableCheckAsyncLocalOnly) {
  set_globally_reachable_check_is_async(true);
  UseNonDelayedDnsRules("ok");

  ResolveHostParameters parameters;
  parameters.source = HostResolverSource::LOCAL_ONLY;
  Requester requester = CreateRequester("https://ok", std::move(parameters));
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_NAME_NOT_RESOLVED));
}

TEST_F(HostResolverServiceEndpointRequestTest, EndpointsAreSorted) {
  MockDnsClientRuleList rules;
  constexpr const char* kHost = "multiple";

  DnsResponse a_response = BuildTestDnsResponse(
      kHost, dns_protocol::kTypeA,
      {BuildTestAddressRecord(kHost, *IPAddress::FromIPLiteral("192.0.2.2")),
       BuildTestAddressRecord(kHost, *IPAddress::FromIPLiteral("192.0.2.1"))});
  DnsResponse aaaa_response = BuildTestDnsResponse(
      kHost, dns_protocol::kTypeAAAA,
      {BuildTestAddressRecord(kHost, *IPAddress::FromIPLiteral("2001:db8::2")),
       BuildTestAddressRecord(kHost,
                              *IPAddress::FromIPLiteral("2001:db8::1"))});
  AddDnsRule(&rules, kHost, dns_protocol::kTypeA, std::move(a_response),
             /*delay=*/false);
  AddDnsRule(&rules, kHost, dns_protocol::kTypeAAAA, std::move(aaaa_response),
             /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  mock_dns_client_->SetAddressSorterForTesting(
      std::make_unique<FakeAddressSorter>());

  Requester requester = CreateRequester("https://multiple");
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  requester.WaitForFinished();
  EXPECT_THAT(*requester.finished_result(), IsOk());
  EXPECT_THAT(requester.finished_endpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("192.0.2.1", 443),
                              MakeIPEndPoint("192.0.2.2", 443)),
                  ElementsAre(MakeIPEndPoint("2001:db8::1", 443),
                              MakeIPEndPoint("2001:db8::2", 443)))));
}

TEST_F(HostResolverServiceEndpointRequestTest, CancelRequestOnUpdated) {
  UseIpv4DelayedDnsRules("4slow_ok");

  Requester requester = CreateRequester("https://4slow_ok");
  requester.CancelRequestOnUpdated();
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  RunUntilIdle();
  // The finished callback should not be called because the request was
  // already cancelled.
  ASSERT_FALSE(requester.finished_result().has_value());
  ASSERT_FALSE(requester.request());
}

TEST_F(HostResolverServiceEndpointRequestTest, CancelRequestOnFinished) {
  UseIpv4DelayedDnsRules("4slow_ok");

  Requester requester = CreateRequester("https://4slow_ok");
  requester.CancelRequestOnFinished();
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  mock_dns_client_->CompleteDelayedTransactions();
  requester.WaitForFinished();
  // The result should be OK because we cancel the request after completing the
  // associated Job.
  EXPECT_THAT(*requester.finished_result(), IsOk());
}

TEST_F(HostResolverServiceEndpointRequestTest, Ipv4Slow) {
  UseIpv4DelayedDnsRules("4slow_ok");

  Requester requester = CreateRequester("https://4slow_ok");
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ(3u, resolver_->num_running_dispatcher_jobs_for_tests());

  // AAAA and HTTPS should complete.
  RunUntilIdle();
  EXPECT_EQ(1u, resolver_->num_running_dispatcher_jobs_for_tests());
  ASSERT_FALSE(requester.finished_result().has_value());
  ASSERT_TRUE(requester.request()->EndpointsCryptoReady());
  EXPECT_THAT(requester.request()->GetEndpointResults(),
              ElementsAre(ExpectServiceEndpoint(
                  IsEmpty(), ElementsAre(MakeIPEndPoint("::1", 443)))));
  EXPECT_THAT(requester.request()->GetDnsAliasResults(),
              UnorderedElementsAre("4slow_ok"));

  // Complete A request, which finishes the request synchronously.
  mock_dns_client_->CompleteDelayedTransactions();
  ASSERT_TRUE(requester.request()->EndpointsCryptoReady());
  EXPECT_THAT(*requester.finished_result(), IsOk());
  EXPECT_THAT(requester.finished_endpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                  ElementsAre(MakeIPEndPoint("::1", 443)))));
  EXPECT_THAT(requester.request()->GetDnsAliasResults(),
              UnorderedElementsAre("4slow_ok"));
}

TEST_F(HostResolverServiceEndpointRequestTest, Ipv6Slow) {
  UseIpv6DelayedDnsRules("6slow_ok");

  Requester requester = CreateRequester("https://6slow_ok");
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ(3u, resolver_->num_running_dispatcher_jobs_for_tests());

  // A and HTTPS should complete, but no endpoints should be available since
  // waiting for AAAA response.
  RunUntilIdle();
  EXPECT_EQ(1u, resolver_->num_running_dispatcher_jobs_for_tests());
  ASSERT_FALSE(requester.finished_result().has_value());
  ASSERT_TRUE(requester.request()->EndpointsCryptoReady());
  EXPECT_THAT(requester.request()->GetEndpointResults(), IsEmpty());

  // Complete AAAA request, which finishes the request synchronously.
  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_THAT(*requester.finished_result(), IsOk());
  EXPECT_THAT(requester.finished_endpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                  ElementsAre(MakeIPEndPoint("::1", 443)))));
}

TEST_F(HostResolverServiceEndpointRequestTest, Ipv6SlowResolutionDelayPassed) {
  UseIpv6DelayedDnsRules("6slow_ok");

  Requester requester = CreateRequester("https://6slow_ok");
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ(3u, resolver_->num_running_dispatcher_jobs_for_tests());

  // A and HTTPS should complete, but no endpoints should be available since
  // waiting for AAAA response.
  RunUntilIdle();
  EXPECT_EQ(1u, resolver_->num_running_dispatcher_jobs_for_tests());
  ASSERT_FALSE(requester.finished_result().has_value());
  ASSERT_TRUE(requester.request()->EndpointsCryptoReady());
  EXPECT_THAT(requester.request()->GetEndpointResults(), IsEmpty());

  // The resolution delay timer fired, IPv4 endpoints should be available.
  FastForwardBy(DnsTaskResultsManager::kResolutionDelay +
                base::Milliseconds(1));
  RunUntilIdle();
  EXPECT_EQ(1u, resolver_->num_running_dispatcher_jobs_for_tests());
  ASSERT_FALSE(requester.finished_result().has_value());
  EXPECT_THAT(requester.request()->GetEndpointResults(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)), IsEmpty())));

  // Complete AAAA request, which finishes the request synchronously.
  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_THAT(*requester.finished_result(), IsOk());
  EXPECT_THAT(requester.finished_endpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                  ElementsAre(MakeIPEndPoint("::1", 443)))));
}

TEST_F(HostResolverServiceEndpointRequestTest, HttpsSlow) {
  UseHttpsDelayedDnsRules("https_slow_ok");

  Requester requester = CreateRequester("https://https_slow_ok");
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ(3u, resolver_->num_running_dispatcher_jobs_for_tests());

  // A and AAAA should complete.
  RunUntilIdle();
  EXPECT_EQ(1u, resolver_->num_running_dispatcher_jobs_for_tests());
  ASSERT_FALSE(requester.finished_result().has_value());
  ASSERT_FALSE(requester.request()->EndpointsCryptoReady());
  EXPECT_THAT(requester.request()->GetEndpointResults(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                  ElementsAre(MakeIPEndPoint("::1", 443)))));

  // Complete HTTPS request, which finishes the request synchronously.
  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_THAT(*requester.finished_result(), IsOk());
  EXPECT_THAT(
      requester.finished_endpoints(),
      ElementsAre(
          ExpectServiceEndpoint(
              ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
              ElementsAre(MakeIPEndPoint("::1", 443)),
              ConnectionEndpointMetadata(
                  /*supported_protocol_alpns=*/{"http/1.1"},
                  /*ech_config_list=*/{}, std::string("https_slow_ok"))),
          // Non-SVCB endpoints.
          ExpectServiceEndpoint(ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                                ElementsAre(MakeIPEndPoint("::1", 443)))));
}

TEST_F(HostResolverServiceEndpointRequestTest, DestroyResolverWhileUpdating) {
  // Using 4slow_ok not to complete transactions at once.
  UseIpv4DelayedDnsRules("4slow_ok");

  Requester requester = CreateRequester("https://4slow_ok");
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  requester.SetOnUpdatedCallback(
      base::BindLambdaForTesting([&]() { DestroyResolver(); }));

  RunUntilIdle();
  EXPECT_THAT(requester.finished_result(),
              Optional(IsError(ERR_NAME_NOT_RESOLVED)));
  EXPECT_THAT(requester.request()->GetResolveErrorInfo().error,
              IsError(ERR_DNS_REQUEST_CANCELLED));
}

TEST_F(HostResolverServiceEndpointRequestTest, DestroyResolverWhileFinishing) {
  UseNonDelayedDnsRules("ok");

  Requester requester = CreateRequester("https://ok");
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  requester.SetOnFinishedCallback(
      base::BindLambdaForTesting([&]() { DestroyResolver(); }));

  RunUntilIdle();
  EXPECT_THAT(*requester.finished_result(), IsOk());
}

TEST_F(HostResolverServiceEndpointRequestTest,
       EndpointsCryptoReadySystemTaskOnly) {
  proc_->AddRuleForAllFamilies("a.test", "192.0.2.1");
  ResolveHostParameters parameters;
  parameters.source = HostResolverSource::SYSTEM;
  Requester requester =
      CreateRequester("https://a.test", std::move(parameters));
  int rv = requester.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Should not crash when calling EndpointsCryptoReady().
  ASSERT_FALSE(requester.request()->EndpointsCryptoReady());

  proc_->SignalMultiple(1u);
  requester.WaitForFinished();
  EXPECT_THAT(requester.finished_result(), Optional(IsOk()));
  ASSERT_TRUE(requester.request()->EndpointsCryptoReady());
}

TEST_F(HostResolverServiceEndpointRequestTest, MultipleRequestsOk) {
  UseIpv4DelayedDnsRules("4slow_ok");

  constexpr std::string_view kHost = "https://4slow_ok";
  Requester requester1 = CreateRequester(kHost);
  EXPECT_THAT(requester1.Start(), IsError(ERR_IO_PENDING));
  EXPECT_EQ(3u, resolver_->num_running_dispatcher_jobs_for_tests());

  Requester requester2 = CreateRequester(kHost);
  EXPECT_THAT(requester2.Start(), IsError(ERR_IO_PENDING));
  // The second request should share the same job with the first request.
  EXPECT_EQ(3u, resolver_->num_running_dispatcher_jobs_for_tests());

  RunUntilIdle();
  EXPECT_EQ(1u, resolver_->num_running_dispatcher_jobs_for_tests());

  // Complete the delayed transaction, which finishes requests synchronously.
  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_THAT(*requester1.finished_result(), IsOk());
  EXPECT_THAT(requester1.finished_endpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                  ElementsAre(MakeIPEndPoint("::1", 443)))));

  EXPECT_THAT(*requester2.finished_result(), IsOk());
  EXPECT_THAT(requester2.finished_endpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                  ElementsAre(MakeIPEndPoint("::1", 443)))));
}

TEST_F(HostResolverServiceEndpointRequestTest,
       MultipleRequestsAddRequestInTheMiddleOfResolution) {
  UseIpv4DelayedDnsRules("4slow_ok");

  constexpr std::string_view kHost = "https://4slow_ok";
  Requester requester1 = CreateRequester(kHost);
  EXPECT_THAT(requester1.Start(), IsError(ERR_IO_PENDING));
  EXPECT_EQ(3u, resolver_->num_running_dispatcher_jobs_for_tests());

  // Partially complete transactions. Only IPv6 endpoints should be available.
  RunUntilIdle();
  EXPECT_EQ(1u, resolver_->num_running_dispatcher_jobs_for_tests());
  ASSERT_FALSE(requester1.finished_result().has_value());
  EXPECT_THAT(requester1.request()->GetEndpointResults(),
              ElementsAre(ExpectServiceEndpoint(
                  IsEmpty(), ElementsAre(MakeIPEndPoint("::1", 443)))));

  // Add a new request in the middle of resolution. The request should be
  // attached to the ongoing job.
  Requester requester2 = CreateRequester(kHost);
  requester2.CancelRequestOnFinished();
  EXPECT_THAT(requester2.Start(), IsError(ERR_IO_PENDING));
  EXPECT_EQ(1u, resolver_->num_running_dispatcher_jobs_for_tests());

  // The second request should have the same intermediate results as the first
  // request.
  ASSERT_FALSE(requester2.finished_result().has_value());
  EXPECT_THAT(requester2.request()->GetEndpointResults(),
              ElementsAre(ExpectServiceEndpoint(
                  IsEmpty(), ElementsAre(MakeIPEndPoint("::1", 443)))));

  // Complete all transactions. Both requests should finish and have the same
  // results.
  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_EQ(0u, resolver_->num_running_dispatcher_jobs_for_tests());

  EXPECT_THAT(*requester1.finished_result(), IsOk());
  EXPECT_THAT(requester1.finished_endpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                  ElementsAre(MakeIPEndPoint("::1", 443)))));

  EXPECT_THAT(*requester2.finished_result(), IsOk());
  EXPECT_THAT(requester2.finished_endpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                  ElementsAre(MakeIPEndPoint("::1", 443)))));
}

TEST_F(HostResolverServiceEndpointRequestTest,
       MultipleRequestsAddAndCancelRequestInUpdatedCallback) {
  UseIpv4DelayedDnsRules("4slow_ok");

  constexpr std::string_view kHost = "https://4slow_ok";
  Requester requester1 = CreateRequester(kHost);
  Requester requester2 = CreateRequester(kHost);

  requester1.SetOnUpdatedCallback(base::BindLambdaForTesting([&] {
    EXPECT_THAT(requester2.Start(), IsError(ERR_IO_PENDING));
    requester1.CancelRequest();
  }));

  EXPECT_THAT(requester1.Start(), IsError(ERR_IO_PENDING));
  EXPECT_EQ(3u, resolver_->num_running_dispatcher_jobs_for_tests());

  // Partially complete transactions. The update callback of the first request
  // should start the second request and then cancel the first request.
  RunUntilIdle();
  EXPECT_EQ(1u, resolver_->num_running_dispatcher_jobs_for_tests());

  ASSERT_FALSE(requester1.finished_result().has_value());
  ASSERT_FALSE(requester1.request());

  ASSERT_FALSE(requester2.finished_result().has_value());
  EXPECT_THAT(requester2.request()->GetEndpointResults(),
              ElementsAre(ExpectServiceEndpoint(
                  IsEmpty(), ElementsAre(MakeIPEndPoint("::1", 443)))));

  // Complete all transactions. The second request should finish successfully.
  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_EQ(0u, resolver_->num_running_dispatcher_jobs_for_tests());

  ASSERT_FALSE(requester1.finished_result().has_value());
  ASSERT_FALSE(requester1.request());

  EXPECT_THAT(*requester2.finished_result(), IsOk());
  EXPECT_THAT(requester2.finished_endpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                  ElementsAre(MakeIPEndPoint("::1", 443)))));
}

TEST_F(HostResolverServiceEndpointRequestTest,
       MultipleRequestsAddRequestInFinishedCallback) {
  UseNonDelayedDnsRules("ok");

  constexpr std::string_view kHost = "https://ok";
  Requester requester1 = CreateRequester(kHost);
  Requester requester2 = CreateRequester(kHost);

  requester1.SetOnFinishedCallback(base::BindLambdaForTesting([&] {
    // The second request should finish synchronously because it should
    // share the same job as the first one and the job has finished already.
    EXPECT_THAT(requester2.Start(), IsOk());
  }));

  EXPECT_THAT(requester1.Start(), IsError(ERR_IO_PENDING));
  EXPECT_EQ(3u, resolver_->num_running_dispatcher_jobs_for_tests());

  RunUntilIdle();
  EXPECT_EQ(0u, resolver_->num_running_dispatcher_jobs_for_tests());

  EXPECT_THAT(*requester1.finished_result(), IsOk());
  EXPECT_THAT(requester1.finished_endpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                  ElementsAre(MakeIPEndPoint("::1", 443)))));

  EXPECT_THAT(*requester2.finished_result(), IsOk());
  EXPECT_THAT(requester2.finished_endpoints(),
              ElementsAre(ExpectServiceEndpoint(
                  ElementsAre(MakeIPEndPoint("127.0.0.1", 443)),
                  ElementsAre(MakeIPEndPoint("::1",
"""


```