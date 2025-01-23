Response:
Let's break down the thought process for analyzing this C++ unit test file for Chromium's Network Error Logging (NEL) service.

**1. Initial Scan and Keyword Recognition:**

* **File Name:** `network_error_logging_service_unittest.cc` immediately tells us this is a unit test file for the `NetworkErrorLoggingService`.
* **Includes:**  The included headers provide clues about the functionality being tested:
    * `memory`, `string`, `vector`: Basic C++ utilities.
    * `base/functional/bind.h`, `base/functional/callback.h`:  Indicates asynchronous operations and callbacks are involved.
    * `base/strings/stringprintf.h`: String formatting.
    * `base/test/...`:  Signifies a test environment. `scoped_feature_list` points to feature flags.
    * `base/time/time.h`: Time-related operations.
    * `base/values.h`: Working with structured data (likely JSON-like).
    * `net/base/...`: Core networking concepts like errors, IP addresses, network isolation keys, and sites.
    * `net/network_error_logging/...`:  Crucially, the NEL service itself and a mock persistent store.
    * `net/reporting/...`: Interaction with the Reporting API.
    * `testing/gtest/...`: The Google Test framework.
    * `url/...`: Handling URLs and origins.
* **Namespace:** `net` further confirms the networking context.

**2. Identifying the Core Class Under Test:**

* The file name and includes clearly point to `NetworkErrorLoggingService` as the primary class being tested.

**3. Analyzing the Test Fixture (`NetworkErrorLoggingServiceTest`):**

* **Parametrization:** `::testing::TestWithParam<bool>` reveals that the tests run twice, once with `MockPersistentNelStore` enabled and once without. This suggests the tests are concerned with both in-memory and persistent storage scenarios.
* **Setup (`NetworkErrorLoggingServiceTest()`):**
    * Feature Flag: `features::kPartitionConnectionsByNetworkIsolationKey` is enabled. This indicates the tests cover scenarios with and without network isolation.
    * `MockPersistentNelStore`:  Conditional creation of a mock persistent store. This is a key aspect for testing asynchronous loading and persistence.
    * `NetworkErrorLoggingService::Create()`:  Instantiation of the service.
    * `CreateReportingService()`: Creation of a mock reporting service. This shows that NEL's interaction with reporting is being tested.
* **Helper Methods:**  The numerous helper methods are essential for constructing test scenarios:
    * `MakeRequestDetails()`: Creates structured data representing a network request with details like URL, error, method, etc.
    * `MakeSignedExchangeReportDetails()`: Creates data for signed exchange reports.
    * `MakeOrigin()`, `MakeNetworkAnonymizationKey()`:  Generates different origins and network isolation keys to test scoping.
    * `MakePolicy()`: Creates NEL policies.
    * `HasPolicy()`, `PolicyCount()`: Inspects the internal state of the service.
    * `FinishLoading()`:  Crucially important for the mock persistent store. It allows simulating the completion of asynchronous loading, making tests synchronous when needed.

**4. Examining Individual Test Cases (Examples):**

* **`CreateService`:** A basic test to ensure the service can be created.
* **`NoReportingService`:** Tests how the service behaves when there's no reporting service configured (shouldn't crash).
* **`NoPolicy`:**  Verifies that no reports are generated if there's no matching policy.
* **`PolicyKeyMatchesNakAndOrigin`:**  Tests the core logic of matching policies based on NetworkAnonymizationKey (NAK) and origin. It covers scenarios with correct and incorrect keys.
* **Tests with `IncludeSubdomains`:**  Focus on the behavior of the `include_subdomains` policy directive.
* **`NetworkAnonymizationKeyDisabled`:** Specifically tests the service's behavior when the NAK feature is disabled.
* **Tests related to JSON size and depth:** Checks for handling of invalid header formats.
* **Tests with ETLD:**  Explores how the service handles policies for top-level domains.
* **Tests for Success and Failure Reports:** Examines the content of generated NEL reports for both successful and failed requests, including the different fields and how they are populated.
* **Tests with Downgrading:**  Focuses on scenarios where a successful request after a failure triggers a "downgrade" report.

**5. Identifying Relationships to JavaScript:**

* **NEL as a Web Standard:**  Recall that NEL is a web standard that browsers implement. JavaScript running in a web page interacts with NEL indirectly through browser APIs and network requests.
* **`OnHeader()`:** This function is called when the browser receives an HTTP header related to NEL (e.g., `NEL` or `Report-To`). JavaScript making a request could cause this header to be received.
* **Report Generation:** When network errors occur for requests initiated by JavaScript, or when successful requests match certain policy criteria, NEL reports are generated. These reports are then sent to configured reporting endpoints.
* **Configuration via Headers:**  The NEL policy itself is configured using HTTP headers, which are part of the response to JavaScript-initiated requests.

**6. Logic Inference and Examples (Hypothetical):**

* **Input (JavaScript):**  A user navigates to `https://example.com`. The server responds with a `NEL` header: `NEL: {"report_to":"group","max_age":86400}`. Later, JavaScript on the page makes an `XMLHttpRequest` to `https://example.com/api`. This request fails with a `Connection Refused` error.
* **Output (NEL):** The `NetworkErrorLoggingService` would generate a NEL report (if the mock store is loaded and the test allows it), which would eventually be sent via the Reporting API. The test cases like `PolicyKeyMatchesNakAndOrigin` verify this behavior.

**7. Common User/Programming Errors:**

* **Incorrect Header Syntax:**  The tests for `JsonTooLong` and `JsonTooDeep` demonstrate how the service handles malformed NEL headers. A web developer might accidentally create an invalid header.
* **Misunderstanding `includeSubdomains`:** A developer might set `includeSubdomains` incorrectly, leading to reports being generated or suppressed unexpectedly for subdomains.
* **Not Handling Asynchronous Operations (in the context of the persistent store):** If the tests didn't use `FinishLoading()`, they might run into issues where the service tries to access data from the store before it's loaded. This mirrors a real-world scenario where asynchronous operations need to be handled correctly.

**8. Debugging Clues (User Operations):**

* **User Navigation:**  A user visits a website.
* **Resource Loading:** The browser tries to load resources (images, scripts, etc.).
* **API Calls:** JavaScript on the page makes API calls.
* **Network Errors:** Any of these operations can result in network errors that trigger NEL. The specific error (e.g., `ERR_CONNECTION_REFUSED`, `ERR_NAME_NOT_RESOLVED`) provides crucial debugging information.
* **Inspecting Network Logs:**  Browser developer tools' network tab can show NEL-related headers and reporting activity.

**9. Summarizing Functionality (Part 1):**

Based on the analysis of the first part of the code, the core functionality being tested revolves around:

* **Policy Handling:** Parsing and storing NEL policies received via HTTP headers. The tests verify that policies are correctly associated with origins and NetworkAnonymizationKeys.
* **Report Generation for Network Errors:** Triggering the creation of NEL reports when network requests fail (e.g., connection refused, DNS resolution errors).
* **Report Content:**  Ensuring that the generated reports contain the correct information, such as URL, error type, server IP, and timestamps.
* **Interaction with Reporting Service:**  Verifying that generated reports are correctly passed to the Reporting API.
* **Handling of `includeSubdomains`:** Testing the scope of NEL policies to include subdomains.
* **Resilience to Invalid Headers:** Checking how the service handles malformed NEL headers.
* **Feature Flag Control:**  Testing behavior with and without the NetworkAnonymizationKey feature enabled.
* **Asynchronous Storage (with Mock):**  Simulating and testing interactions with a persistent storage mechanism for NEL policies.

This detailed breakdown reflects the kind of thorough analysis needed to understand the purpose and function of a unit test file like this.
这是 Chromium 网络栈中 `net/network_error_logging/network_error_logging_service_unittest.cc` 文件的第一部分，其主要功能是**测试 `NetworkErrorLoggingService` 类的各种功能**。

更具体地说，这部分代码主要涵盖了以下功能点的测试：

**核心功能测试：**

* **策略（Policy）的获取和匹配:**  测试 `NetworkErrorLoggingService` 如何解析和存储从 HTTP 头部获取的 NEL 策略，并确保后续的网络请求能够根据正确的策略生成报告。这包括基于 `NetworkAnonymizationKey` 和 `Origin` 的策略匹配。
* **网络错误报告的生成:** 测试在发生各种网络错误（例如连接被拒绝、DNS 解析失败等）时，`NetworkErrorLoggingService` 是否能够正确地生成 NEL 报告。
* **报告内容的正确性:** 测试生成的 NEL 报告是否包含预期的信息，例如发生错误的 URL、错误类型、服务器 IP 地址、用户代理等。
* **与 Reporting Service 的交互:** 测试 `NetworkErrorLoggingService` 如何将生成的 NEL 报告传递给 `ReportingService` 进行上报。

**特定场景和配置的测试：**

* **`includeSubdomains` 指令:** 测试 NEL 策略中 `includeSubdomains` 指令是否按预期工作，即是否会为子域名生成报告。
* **`success_fraction` 和 `failure_fraction`:** 测试根据成功和失败的采样率生成报告的机制。
* **不启用 `NetworkAnonymizationKey` 特性时的行为:** 测试在禁用 `kPartitionConnectionsByNetworkIsolationKey` 特性时，NEL 服务的行为是否符合预期。
* **处理格式错误的 NEL 头部:** 测试当接收到过长或结构过于复杂的 NEL 头部时，`NetworkErrorLoggingService` 的处理方式。
* **顶级域名 (ETLD) 的处理:** 测试对于顶级域名设置 `includeSubdomains` 策略时的拒绝行为。
* **成功报告的生成:** 测试在符合策略的情况下，对于成功的请求是否会生成报告（当 `success_fraction` 大于 0 时）。
* **报告降级（Downgrading）机制:** 测试当请求的 IP 地址发生变化时，NEL 报告如何从应用层面的错误降级为 DNS 层面错误。

**与 JavaScript 的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的网络功能 **Network Error Logging (NEL)** 与 JavaScript 的功能密切相关。

* **NEL 策略的下发:** 当浏览器加载网页或资源时，服务器可以通过 HTTP 头部（如 `NEL` 或 `Report-To`）下发 NEL 策略。这些头部会被浏览器解析，并传递给 `NetworkErrorLoggingService` 进行处理，就像这里测试的 `OnHeader()` 方法。
* **网络请求的触发:**  JavaScript 代码通过 `fetch` API、`XMLHttpRequest` 等发起网络请求。当这些请求失败或成功时，`NetworkErrorLoggingService` 会根据配置的 NEL 策略和请求结果决定是否生成报告，就像这里测试的 `OnRequest()` 方法。
* **错误信息的捕获和上报:** NEL 提供了一种机制，允许网站开发者捕获用户浏览器中发生的网络错误，并将这些错误信息上报到指定的服务器，以便进行监控和分析。这可以帮助开发者了解用户体验中遇到的网络问题。

**举例说明:**

假设一个网站 `https://example.com` 的服务器响应了一个包含以下 NEL 头部信息的请求：

```
NEL: {"report_to":"my-group","max_age":3600,"include_subdomains":true}
```

1. **用户操作:** 用户通过浏览器访问 `https://sub.example.com/page.html`。
2. **NEL 策略生效:** 浏览器接收到上述 NEL 头部，`NetworkErrorLoggingService::OnHeader()` 方法会被调用，解析并存储该策略。
3. **JavaScript 发起请求:**  页面 `page.html` 中的 JavaScript 代码通过 `fetch` API 请求 `https://api.sub.example.com/data`。
4. **请求失败:**  假设由于某种原因，这个请求失败了（例如，服务器无响应，连接超时）。
5. **NEL 报告生成:**  `NetworkErrorLoggingService::OnRequest()` 方法会被调用，检测到错误，并且由于之前收到的策略匹配该域名（包括子域名），因此会生成一个 NEL 报告。
6. **报告上报:** 生成的报告会被传递给 `ReportingService`，最终上报到配置的服务器。

**逻辑推理、假设输入与输出：**

**假设输入：**

* 调用 `service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);`，其中 `kHeader_` 的值为 `{"report_to":"group","max_age":86400}`。
* 随后调用 `service()->OnRequest(MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED));`。

**逻辑推理：**

1. `OnHeader` 方法会解析 `kHeader_` 并存储与 `kNak_` 和 `kOrigin_` 关联的 NEL 策略。
2. `OnRequest` 方法接收到一个针对 `kUrl_` 的请求，并且发生了 `ERR_CONNECTION_REFUSED` 错误。
3. 由于存在与 `kNak_` 和 `kOrigin_` 匹配的有效策略，并且发生的是网络错误，`NetworkErrorLoggingService` 应该会生成一个 NEL 报告。

**输出：**

* `reports()` 集合中会包含一个 `TestReportingService::Report` 对象。
* 该报告的 `url` 应该等于 `kUrl_`。
* 该报告的 `network_anonymization_key` 应该等于 `kNak_`。
* 该报告的 `group` 应该等于 "group"。
* 该报告的 `type` 应该等于 `NetworkErrorLoggingService::kReportType`。
* 该报告的 `body` 中应该包含关于该错误的详细信息，例如错误类型、服务器 IP 等。

**用户或编程常见的使用错误：**

* **NEL 头部语法错误:**  开发者可能在服务器配置中错误地编写了 NEL 头部，例如缺少必要的字段、JSON 格式错误等。测试中的 `JsonTooLong` 和 `JsonTooDeep` 就是模拟这种情况。
* **对 `includeSubdomains` 的误解:** 开发者可能错误地认为设置了 `includeSubdomains` 就能为所有子域名生效，但实际上它受到顶级域名的限制，正如 `IncludeSubdomainsEtldRejected` 测试所展示的。
* **没有正确配置 Reporting API:**  即使 NEL 策略配置正确，如果浏览器或网站没有正确配置 Reporting API，NEL 报告也无法成功上报。这在测试中通过使用 `TestReportingService` 来模拟。
* **过度依赖客户端 NEL 配置:**  开发者应该意识到，客户端（浏览器）对 NEL 的支持和配置可能会影响 NEL 的实际效果。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在浏览器中输入网址并访问一个网站。**
2. **服务器响应用户的请求，并在 HTTP 头部中包含了 NEL 策略。** 浏览器的网络栈会解析这些头部，并将信息传递给 `NetworkErrorLoggingService`，触发 `OnHeader` 方法。
3. **用户在网站上进行操作，例如点击链接、提交表单，或者页面上的 JavaScript 代码发起异步请求。**
4. **在这些网络请求的过程中，可能发生各种网络错误，例如 DNS 解析失败、连接超时、服务器返回错误状态码等。**
5. **当发生网络错误时，浏览器的网络栈会检测到这些错误，并调用 `NetworkErrorLoggingService::OnRequest()` 方法，将请求的详细信息和错误类型传递给它。**
6. **`NetworkErrorLoggingService` 会检查是否存在与当前请求的域名和网络隔离键匹配的有效 NEL 策略。**
7. **如果存在匹配的策略，并且错误类型符合策略的配置，`NetworkErrorLoggingService` 就会生成一个 NEL 报告。**
8. **生成的报告会被传递给 `ReportingService`，等待上报到配置的服务器。**

作为调试线索，如果开发者怀疑 NEL 功能有问题，可以：

* **检查服务器返回的 HTTP 头部，确认 NEL 策略是否正确配置。**
* **使用浏览器的开发者工具（Network 选项卡）查看网络请求的详细信息，包括请求头和响应头，以及是否生成了 NEL 报告。**
* **检查浏览器是否正确配置了 Reporting API。**
* **在 Chromium 的源代码中，可以设置断点在 `NetworkErrorLoggingService::OnHeader()` 和 `NetworkErrorLoggingService::OnRequest()` 等方法中，来追踪 NEL 策略的接收和报告的生成过程。**

**归纳一下它的功能（第 1 部分）：**

总而言之，`network_error_logging_service_unittest.cc` 的第一部分主要测试了 `NetworkErrorLoggingService` 接收和处理 NEL 策略，以及根据这些策略在发生网络错误时生成基本 NEL 报告的功能。它涵盖了策略的匹配、报告内容的生成，以及与 Reporting Service 的基本交互。 同时也测试了一些边缘情况和配置选项，例如 `includeSubdomains` 指令、非 `NetworkAnonymizationKey` 场景和处理格式错误的头部等。

### 提示词
```
这是目录为net/network_error_logging/network_error_logging_service_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <vector>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/strings/stringprintf.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_clock.h"
#include "base/test/values_test_util.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/schemeful_site.h"
#include "net/network_error_logging/mock_persistent_nel_store.h"
#include "net/network_error_logging/network_error_logging_service.h"
#include "net/reporting/reporting_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {
namespace {

// The tests are parametrized on a boolean value which represents whether or not
// to use a MockPersistentNelStore.
// If a MockPersistentNelStore is used, then calls to
// NetworkErrorLoggingService::OnHeader(), OnRequest(),
// QueueSignedExchangeReport(), RemoveBrowsingData(), and
// RemoveAllBrowsingData() will block until the store finishes loading.
// Therefore, for tests that should run synchronously (i.e. tests that don't
// specifically test the asynchronous/deferred task behavior), FinishLoading()
// must be called after the first call to one of the above methods.
class NetworkErrorLoggingServiceTest : public ::testing::TestWithParam<bool> {
 protected:
  using NelPolicyKey = NetworkErrorLoggingService::NelPolicyKey;

  NetworkErrorLoggingServiceTest() {
    feature_list_.InitAndEnableFeature(
        features::kPartitionConnectionsByNetworkIsolationKey);

    if (GetParam()) {
      store_ = std::make_unique<MockPersistentNelStore>();
    } else {
      store_.reset(nullptr);
    }
    service_ = NetworkErrorLoggingService::Create(store_.get());
    CreateReportingService();
  }

  void CreateReportingService() {
    DCHECK(!reporting_service_);

    reporting_service_ = std::make_unique<TestReportingService>();
    service_->SetReportingService(reporting_service_.get());
  }

  NetworkErrorLoggingService::RequestDetails MakeRequestDetails(
      const NetworkAnonymizationKey& network_anonymization_key,
      const GURL& url,
      Error error_type,
      std::string method = "GET",
      int status_code = 0,
      IPAddress server_ip = IPAddress()) {
    NetworkErrorLoggingService::RequestDetails details;

    details.network_anonymization_key = network_anonymization_key;
    details.uri = url;
    details.referrer = kReferrer_;
    details.user_agent = kUserAgent_;
    details.server_ip = server_ip.IsValid() ? server_ip : kServerIP_;
    details.method = std::move(method);
    details.status_code = status_code;
    details.elapsed_time = base::Seconds(1);
    details.type = error_type;
    details.reporting_upload_depth = 0;

    return details;
  }

  NetworkErrorLoggingService::SignedExchangeReportDetails
  MakeSignedExchangeReportDetails(
      const NetworkAnonymizationKey& network_anonymization_key,
      bool success,
      const std::string& type,
      const GURL& outer_url,
      const GURL& inner_url,
      const GURL& cert_url,
      const IPAddress& server_ip_address) {
    NetworkErrorLoggingService::SignedExchangeReportDetails details;
    details.network_anonymization_key = network_anonymization_key;
    details.success = success;
    details.type = type;
    details.outer_url = outer_url;
    details.inner_url = inner_url;
    details.cert_url = cert_url;
    details.referrer = kReferrer_.spec();
    details.server_ip_address = server_ip_address;
    details.protocol = "http/1.1";
    details.method = "GET";
    details.status_code = 200;
    details.elapsed_time = base::Milliseconds(1234);
    details.user_agent = kUserAgent_;
    return details;
  }
  NetworkErrorLoggingService* service() { return service_.get(); }
  MockPersistentNelStore* store() { return store_.get(); }
  const std::vector<TestReportingService::Report>& reports() {
    return reporting_service_->reports();
  }

  // These methods are design so that using them together will create unique
  // Origin, NetworkAnonymizationKey pairs, but they do return repeated values
  // when called separately, so they can be used to ensure that reports are
  // keyed on both NAK and Origin.
  url::Origin MakeOrigin(size_t index) {
    GURL url(base::StringPrintf("https://example%zd.com/", index / 2));
    return url::Origin::Create(url);
  }
  NetworkAnonymizationKey MakeNetworkAnonymizationKey(size_t index) {
    SchemefulSite site(
        GURL(base::StringPrintf("https://example%zd.com/", (index + 1) / 2)));
    return NetworkAnonymizationKey::CreateSameSite(site);
  }

  NetworkErrorLoggingService::NelPolicy MakePolicy(
      const NetworkAnonymizationKey& network_anonymization_key,
      const url::Origin& origin,
      base::Time expires = base::Time(),
      base::Time last_used = base::Time()) {
    NetworkErrorLoggingService::NelPolicy policy;
    policy.key = NelPolicyKey(network_anonymization_key, origin);
    policy.expires = expires;
    policy.last_used = last_used;

    return policy;
  }

  // Returns whether the NetworkErrorLoggingService has a policy corresponding
  // to |network_anonymization_key| and |origin|. Returns true if so, even if
  // the policy is expired.
  bool HasPolicy(const NetworkAnonymizationKey& network_anonymization_key,
                 const url::Origin& origin) {
    std::set<NelPolicyKey> all_policy_keys =
        service_->GetPolicyKeysForTesting();
    return all_policy_keys.find(NelPolicyKey(network_anonymization_key,
                                             origin)) != all_policy_keys.end();
  }

  size_t PolicyCount() { return service_->GetPolicyKeysForTesting().size(); }

  // Makes the rest of the test run synchronously.
  void FinishLoading(bool load_success) {
    if (store())
      store()->FinishLoading(load_success);
  }

  base::test::ScopedFeatureList feature_list_;

  const GURL kUrl_ = GURL("https://example.com/path");
  const GURL kUrlDifferentPort_ = GURL("https://example.com:4433/path");
  const GURL kUrlSubdomain_ = GURL("https://subdomain.example.com/path");
  const GURL kUrlDifferentHost_ = GURL("https://somewhere-else.com/path");
  const GURL kUrlEtld_ = GURL("https://co.uk/foo.html");

  const GURL kInnerUrl_ = GURL("https://example.net/path");
  const GURL kCertUrl_ = GURL("https://example.com/cert_path");

  const IPAddress kServerIP_ = IPAddress(192, 168, 0, 1);
  const IPAddress kOtherServerIP_ = IPAddress(192, 168, 0, 2);
  const url::Origin kOrigin_ = url::Origin::Create(kUrl_);
  const url::Origin kOriginDifferentPort_ =
      url::Origin::Create(kUrlDifferentPort_);
  const url::Origin kOriginSubdomain_ = url::Origin::Create(kUrlSubdomain_);
  const url::Origin kOriginDifferentHost_ =
      url::Origin::Create(kUrlDifferentHost_);
  const url::Origin kOriginEtld_ = url::Origin::Create(kUrlEtld_);
  const NetworkAnonymizationKey kNak_ =
      NetworkAnonymizationKey::CreateSameSite(SchemefulSite(kOrigin_));
  const NetworkAnonymizationKey kOtherNak_ =
      NetworkAnonymizationKey::CreateSameSite(
          SchemefulSite(kOriginDifferentHost_));

  const std::string kHeader_ = "{\"report_to\":\"group\",\"max_age\":86400}";
  const std::string kHeaderSuccessFraction0_ =
      "{\"report_to\":\"group\",\"max_age\":86400,\"success_fraction\":0.0}";
  const std::string kHeaderSuccessFraction1_ =
      "{\"report_to\":\"group\",\"max_age\":86400,\"success_fraction\":1.0}";
  const std::string kHeaderIncludeSubdomains_ =
      "{\"report_to\":\"group\",\"max_age\":86400,\"include_subdomains\":true}";
  const std::string kHeaderIncludeSubdomainsAndSuccess_ =
      "{\"report_to\":\"group\",\"max_age\":86400,\"include_subdomains\":true,"
      "\"success_fraction\":1.0}";
  const std::string kHeaderMaxAge0_ = "{\"max_age\":0}";
  const std::string kHeaderTooLong_ =
      "{\"report_to\":\"group\",\"max_age\":86400,\"junk\":\"" +
      std::string(32 * 1024, 'a') + "\"}";
  const std::string kHeaderTooDeep_ =
      "{\"report_to\":\"group\",\"max_age\":86400,\"junk\":[[[[[[[[[[]]]]]]]]]]"
      "}";

  const std::string kUserAgent_ = "Mozilla/1.0";
  const std::string kGroup_ = "group";

  const std::string kType_ = NetworkErrorLoggingService::kReportType;

  const GURL kReferrer_ = GURL("https://referrer.com/");

  // `store_` and `reporting_service_` need to outlive `service_`.
  std::unique_ptr<MockPersistentNelStore> store_;
  std::unique_ptr<TestReportingService> reporting_service_;
  std::unique_ptr<NetworkErrorLoggingService> service_;
};

void ExpectDictDoubleValue(double expected_value,
                           const base::Value::Dict& value,
                           const std::string& key) {
  std::optional<double> double_value = value.FindDouble(key);
  ASSERT_TRUE(double_value) << key;
  EXPECT_DOUBLE_EQ(expected_value, *double_value) << key;
}

TEST_P(NetworkErrorLoggingServiceTest, CreateService) {
  // Service is created by default in the test fixture..
  EXPECT_TRUE(service());
}

TEST_P(NetworkErrorLoggingServiceTest, NoReportingService) {
  service_ = NetworkErrorLoggingService::Create(store_.get());

  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  // Should not crash.
  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED));
}

TEST_P(NetworkErrorLoggingServiceTest, NoPolicy) {
  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED));

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, PolicyKeyMatchesNakAndOrigin) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  // Wrong NAK and origin.
  service()->OnRequest(MakeRequestDetails(kOtherNak_, kUrlDifferentHost_,
                                          ERR_CONNECTION_REFUSED));
  EXPECT_TRUE(reports().empty());

  // Wrong NAK.
  service()->OnRequest(
      MakeRequestDetails(kOtherNak_, kUrl_, ERR_CONNECTION_REFUSED));
  EXPECT_TRUE(reports().empty());

  // Wrong origin.
  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlDifferentHost_, ERR_CONNECTION_REFUSED));
  EXPECT_TRUE(reports().empty());

  // Correct key.
  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED));
  EXPECT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(kNak_, reports()[0].network_anonymization_key);
  EXPECT_EQ(kUserAgent_, reports()[0].user_agent);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);
}

TEST_P(NetworkErrorLoggingServiceTest,
       PolicyKeyMatchesNakAndOriginIncludeSubdomains) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderIncludeSubdomains_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  // Wrong NAK and origin.
  service()->OnRequest(MakeRequestDetails(kOtherNak_, kUrlDifferentHost_,
                                          ERR_CONNECTION_REFUSED));
  EXPECT_TRUE(reports().empty());

  // Wrong NAK (same origin).
  service()->OnRequest(
      MakeRequestDetails(kOtherNak_, kUrl_, ERR_CONNECTION_REFUSED));
  EXPECT_TRUE(reports().empty());

  // Wrong NAK (subdomain).
  service()->OnRequest(
      MakeRequestDetails(kOtherNak_, kUrlSubdomain_, ERR_CONNECTION_REFUSED));
  EXPECT_TRUE(reports().empty());

  // Wrong origin.
  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlDifferentHost_, ERR_CONNECTION_REFUSED));
  EXPECT_TRUE(reports().empty());

  // Correct key, successful request (same origin).
  service()->OnRequest(MakeRequestDetails(kNak_, kUrl_, OK));
  EXPECT_TRUE(reports().empty());

  // Correct key, non-DNS error (same origin).
  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED));
  EXPECT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(kNak_, reports()[0].network_anonymization_key);
  EXPECT_EQ(kUserAgent_, reports()[0].user_agent);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);

  // Correct key, successful request (subdomain).
  service()->OnRequest(MakeRequestDetails(kNak_, kUrlSubdomain_, OK));
  EXPECT_EQ(1u, reports().size());

  // Correct key, non-DNS error (subdomain).
  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlSubdomain_, ERR_CONNECTION_REFUSED));
  EXPECT_EQ(1u, reports().size());

  // Correct key, DNS error (subdomain).
  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlSubdomain_, ERR_NAME_NOT_RESOLVED));
  EXPECT_EQ(2u, reports().size());
  EXPECT_EQ(kUrlSubdomain_, reports()[1].url);
  EXPECT_EQ(kNak_, reports()[1].network_anonymization_key);
  EXPECT_EQ(kUserAgent_, reports()[1].user_agent);
  EXPECT_EQ(kGroup_, reports()[1].group);
  EXPECT_EQ(kType_, reports()[1].type);
}

TEST_P(NetworkErrorLoggingServiceTest,
       PolicyKeyMatchesNakAndOriginIncludeSubdomainsAndSuccess) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_,
                      kHeaderIncludeSubdomainsAndSuccess_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  // Wrong NAK and origin.
  service()->OnRequest(MakeRequestDetails(kOtherNak_, kUrlDifferentHost_,
                                          ERR_CONNECTION_REFUSED));
  EXPECT_TRUE(reports().empty());

  // Wrong NAK (same origin).
  service()->OnRequest(
      MakeRequestDetails(kOtherNak_, kUrl_, ERR_CONNECTION_REFUSED));
  EXPECT_TRUE(reports().empty());

  // Wrong NAK (subdomain).
  service()->OnRequest(
      MakeRequestDetails(kOtherNak_, kUrlSubdomain_, ERR_CONNECTION_REFUSED));
  EXPECT_TRUE(reports().empty());

  // Wrong origin.
  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlDifferentHost_, ERR_CONNECTION_REFUSED));
  EXPECT_TRUE(reports().empty());

  // Correct key, successful request (same origin).
  service()->OnRequest(MakeRequestDetails(kNak_, kUrl_, OK));
  EXPECT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(kNak_, reports()[0].network_anonymization_key);
  EXPECT_EQ(kUserAgent_, reports()[0].user_agent);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);

  // Correct key, non-DNS error (same origin).
  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED));
  EXPECT_EQ(2u, reports().size());
  EXPECT_EQ(kUrl_, reports()[1].url);
  EXPECT_EQ(kNak_, reports()[1].network_anonymization_key);
  EXPECT_EQ(kUserAgent_, reports()[1].user_agent);
  EXPECT_EQ(kGroup_, reports()[1].group);
  EXPECT_EQ(kType_, reports()[1].type);

  // Correct key (subdomain).
  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlSubdomain_, ERR_NAME_NOT_RESOLVED));
  EXPECT_EQ(3u, reports().size());
  EXPECT_EQ(kUrlSubdomain_, reports()[2].url);
  EXPECT_EQ(kNak_, reports()[2].network_anonymization_key);
  EXPECT_EQ(kUserAgent_, reports()[2].user_agent);
  EXPECT_EQ(kGroup_, reports()[2].group);
  EXPECT_EQ(kType_, reports()[2].type);

  // Correct key, successful request (subdomain).
  service()->OnRequest(MakeRequestDetails(kNak_, kUrlSubdomain_, OK));
  EXPECT_EQ(3u, reports().size());

  // Correct key, successful request on mismatched IP (subdomain).
  service()->OnRequest(MakeRequestDetails(kNak_, kUrlSubdomain_, OK, "GET", 200,
                                          kOtherServerIP_));
  ASSERT_EQ(3u, reports().size());
}

TEST_P(NetworkErrorLoggingServiceTest, NetworkAnonymizationKeyDisabled) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  // Need to re-create the service, since it caches the feature value on
  // creation.
  service_ = NetworkErrorLoggingService::Create(store_.get());
  reporting_service_ = std::make_unique<TestReportingService>();
  service_->SetReportingService(reporting_service_.get());

  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeader_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  // Wrong NAK, but a report should be generated anyways.
  service()->OnRequest(
      MakeRequestDetails(kOtherNak_, kUrl_, ERR_CONNECTION_REFUSED));
  EXPECT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(NetworkAnonymizationKey(), reports()[0].network_anonymization_key);
  EXPECT_EQ(kUserAgent_, reports()[0].user_agent);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);
}

TEST_P(NetworkErrorLoggingServiceTest, JsonTooLong) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderTooLong_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED));

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, JsonTooDeep) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderTooDeep_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED));

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, IncludeSubdomainsEtldRejected) {
  service()->OnHeader(kNak_, kOriginEtld_, kServerIP_,
                      kHeaderIncludeSubdomains_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  EXPECT_EQ(0u, PolicyCount());

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlEtld_, ERR_CONNECTION_REFUSED));

  EXPECT_TRUE(reports().empty());
}

TEST_P(NetworkErrorLoggingServiceTest, NonIncludeSubdomainsEtldAccepted) {
  service()->OnHeader(kNak_, kOriginEtld_, kServerIP_, kHeader_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  EXPECT_EQ(1u, PolicyCount());

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrlEtld_, ERR_CONNECTION_REFUSED));

  EXPECT_EQ(1u, reports().size());
  EXPECT_EQ(kUrlEtld_, reports()[0].url);
}

TEST_P(NetworkErrorLoggingServiceTest, SuccessReportQueued) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderSuccessFraction1_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(MakeRequestDetails(kNak_, kUrl_, OK));

  ASSERT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(kNak_, reports()[0].network_anonymization_key);
  EXPECT_EQ(kUserAgent_, reports()[0].user_agent);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);
  EXPECT_EQ(0, reports()[0].depth);

  const base::Value* body = reports()[0].body.get();
  ASSERT_TRUE(body);
  ASSERT_TRUE(body->is_dict());
  const base::Value::Dict& body_dict = body->GetDict();

  base::ExpectDictStringValue(kReferrer_.spec(), body_dict,
                              NetworkErrorLoggingService::kReferrerKey);
  // TODO(juliatuttle): Extract these constants.
  ExpectDictDoubleValue(1.0, body_dict,
                        NetworkErrorLoggingService::kSamplingFractionKey);
  base::ExpectDictStringValue(kServerIP_.ToString(), body_dict,
                              NetworkErrorLoggingService::kServerIpKey);
  base::ExpectDictStringValue("", body_dict,
                              NetworkErrorLoggingService::kProtocolKey);
  base::ExpectDictStringValue("GET", body_dict,
                              NetworkErrorLoggingService::kMethodKey);
  base::ExpectDictIntegerValue(0, body_dict,
                               NetworkErrorLoggingService::kStatusCodeKey);
  base::ExpectDictIntegerValue(1000, body_dict,
                               NetworkErrorLoggingService::kElapsedTimeKey);
  base::ExpectDictStringValue("application", body_dict,
                              NetworkErrorLoggingService::kPhaseKey);
  base::ExpectDictStringValue("ok", body_dict,
                              NetworkErrorLoggingService::kTypeKey);
}

TEST_P(NetworkErrorLoggingServiceTest, FailureReportQueued) {
  static const std::string kHeaderFailureFraction1 =
      "{\"report_to\":\"group\",\"max_age\":86400,\"failure_fraction\":1.0}";
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderFailureFraction1);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED));

  ASSERT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(kNak_, reports()[0].network_anonymization_key);
  EXPECT_EQ(kUserAgent_, reports()[0].user_agent);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);
  EXPECT_EQ(0, reports()[0].depth);

  const base::Value* body = reports()[0].body.get();
  ASSERT_TRUE(body);
  ASSERT_TRUE(body->is_dict());
  const base::Value::Dict& body_dict = body->GetDict();

  base::ExpectDictStringValue(kReferrer_.spec(), body_dict,
                              NetworkErrorLoggingService::kReferrerKey);
  // TODO(juliatuttle): Extract these constants.
  ExpectDictDoubleValue(1.0, body_dict,
                        NetworkErrorLoggingService::kSamplingFractionKey);
  base::ExpectDictStringValue(kServerIP_.ToString(), body_dict,
                              NetworkErrorLoggingService::kServerIpKey);
  base::ExpectDictStringValue("", body_dict,
                              NetworkErrorLoggingService::kProtocolKey);
  base::ExpectDictStringValue("GET", body_dict,
                              NetworkErrorLoggingService::kMethodKey);
  base::ExpectDictIntegerValue(0, body_dict,
                               NetworkErrorLoggingService::kStatusCodeKey);
  base::ExpectDictIntegerValue(1000, body_dict,
                               NetworkErrorLoggingService::kElapsedTimeKey);
  base::ExpectDictStringValue("connection", body_dict,
                              NetworkErrorLoggingService::kPhaseKey);
  base::ExpectDictStringValue("tcp.refused", body_dict,
                              NetworkErrorLoggingService::kTypeKey);
}

TEST_P(NetworkErrorLoggingServiceTest, UnknownFailureReportQueued) {
  static const std::string kHeaderFailureFraction1 =
      "{\"report_to\":\"group\",\"max_age\":86400,\"failure_fraction\":1.0}";
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderFailureFraction1);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  // This error code happens to not be mapped to a NEL report `type` field
  // value.
  service()->OnRequest(MakeRequestDetails(kNak_, kUrl_, ERR_FILE_NO_SPACE));

  ASSERT_EQ(1u, reports().size());
  const base::Value* body = reports()[0].body.get();
  ASSERT_TRUE(body);
  ASSERT_TRUE(body->is_dict());
  const base::Value::Dict& body_dict = body->GetDict();
  base::ExpectDictStringValue("application", body_dict,
                              NetworkErrorLoggingService::kPhaseKey);
  base::ExpectDictStringValue("unknown", body_dict,
                              NetworkErrorLoggingService::kTypeKey);
}

TEST_P(NetworkErrorLoggingServiceTest, UnknownCertFailureReportQueued) {
  static const std::string kHeaderFailureFraction1 =
      "{\"report_to\":\"group\",\"max_age\":86400,\"failure_fraction\":1.0}";
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderFailureFraction1);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  // This error code happens to not be mapped to a NEL report `type` field
  // value.  Because it's a certificate error, we'll set the `phase` to be
  // `connection`.
  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrl_, ERR_CERT_NON_UNIQUE_NAME));

  ASSERT_EQ(1u, reports().size());
  const base::Value* body = reports()[0].body.get();
  ASSERT_TRUE(body);
  ASSERT_TRUE(body->is_dict());
  const base::Value::Dict& body_dict = body->GetDict();
  base::ExpectDictStringValue("connection", body_dict,
                              NetworkErrorLoggingService::kPhaseKey);
  base::ExpectDictStringValue("unknown", body_dict,
                              NetworkErrorLoggingService::kTypeKey);
}

TEST_P(NetworkErrorLoggingServiceTest, HttpErrorReportQueued) {
  static const std::string kHeaderFailureFraction1 =
      "{\"report_to\":\"group\",\"max_age\":86400,\"failure_fraction\":1.0}";
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderFailureFraction1);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(MakeRequestDetails(kNak_, kUrl_, OK, "GET", 504));

  ASSERT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(kNak_, reports()[0].network_anonymization_key);
  EXPECT_EQ(kUserAgent_, reports()[0].user_agent);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);
  EXPECT_EQ(0, reports()[0].depth);

  const base::Value* body = reports()[0].body.get();
  ASSERT_TRUE(body);
  ASSERT_TRUE(body->is_dict());
  const base::Value::Dict& body_dict = body->GetDict();

  base::ExpectDictStringValue(kReferrer_.spec(), body_dict,
                              NetworkErrorLoggingService::kReferrerKey);
  // TODO(juliatuttle): Extract these constants.
  ExpectDictDoubleValue(1.0, body_dict,
                        NetworkErrorLoggingService::kSamplingFractionKey);
  base::ExpectDictStringValue(kServerIP_.ToString(), body_dict,
                              NetworkErrorLoggingService::kServerIpKey);
  base::ExpectDictStringValue("", body_dict,
                              NetworkErrorLoggingService::kProtocolKey);
  base::ExpectDictStringValue("GET", body_dict,
                              NetworkErrorLoggingService::kMethodKey);
  base::ExpectDictIntegerValue(504, body_dict,
                               NetworkErrorLoggingService::kStatusCodeKey);
  base::ExpectDictIntegerValue(1000, body_dict,
                               NetworkErrorLoggingService::kElapsedTimeKey);
  base::ExpectDictStringValue("application", body_dict,
                              NetworkErrorLoggingService::kPhaseKey);
  base::ExpectDictStringValue("http.error", body_dict,
                              NetworkErrorLoggingService::kTypeKey);
}

TEST_P(NetworkErrorLoggingServiceTest, SuccessReportDowngraded) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderSuccessFraction1_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrl_, OK, "GET", 200, kOtherServerIP_));

  ASSERT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(kNak_, reports()[0].network_anonymization_key);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);
  EXPECT_EQ(0, reports()[0].depth);

  const base::Value* body = reports()[0].body.get();
  ASSERT_TRUE(body);
  ASSERT_TRUE(body->is_dict());
  const base::Value::Dict& body_dict = body->GetDict();

  base::ExpectDictStringValue(kReferrer_.spec(), body_dict,
                              NetworkErrorLoggingService::kReferrerKey);
  ExpectDictDoubleValue(1.0, body_dict,
                        NetworkErrorLoggingService::kSamplingFractionKey);
  base::ExpectDictStringValue(kOtherServerIP_.ToString(), body_dict,
                              NetworkErrorLoggingService::kServerIpKey);
  base::ExpectDictStringValue("", body_dict,
                              NetworkErrorLoggingService::kProtocolKey);
  base::ExpectDictStringValue("GET", body_dict,
                              NetworkErrorLoggingService::kMethodKey);
  base::ExpectDictIntegerValue(0, body_dict,
                               NetworkErrorLoggingService::kStatusCodeKey);
  base::ExpectDictIntegerValue(0, body_dict,
                               NetworkErrorLoggingService::kElapsedTimeKey);
  base::ExpectDictStringValue("dns", body_dict,
                              NetworkErrorLoggingService::kPhaseKey);
  base::ExpectDictStringValue("dns.address_changed", body_dict,
                              NetworkErrorLoggingService::kTypeKey);
}

TEST_P(NetworkErrorLoggingServiceTest, FailureReportDowngraded) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderSuccessFraction1_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(MakeRequestDetails(kNak_, kUrl_, ERR_CONNECTION_REFUSED,
                                          "GET", 200, kOtherServerIP_));

  ASSERT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(kNak_, reports()[0].network_anonymization_key);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);
  EXPECT_EQ(0, reports()[0].depth);

  const base::Value* body = reports()[0].body.get();
  ASSERT_TRUE(body);
  ASSERT_TRUE(body->is_dict());
  const base::Value::Dict& body_dict = body->GetDict();

  base::ExpectDictStringValue(kReferrer_.spec(), body_dict,
                              NetworkErrorLoggingService::kReferrerKey);
  ExpectDictDoubleValue(1.0, body_dict,
                        NetworkErrorLoggingService::kSamplingFractionKey);
  base::ExpectDictStringValue(kOtherServerIP_.ToString(), body_dict,
                              NetworkErrorLoggingService::kServerIpKey);
  base::ExpectDictStringValue("", body_dict,
                              NetworkErrorLoggingService::kProtocolKey);
  base::ExpectDictStringValue("GET", body_dict,
                              NetworkErrorLoggingService::kMethodKey);
  base::ExpectDictIntegerValue(0, body_dict,
                               NetworkErrorLoggingService::kStatusCodeKey);
  base::ExpectDictIntegerValue(0, body_dict,
                               NetworkErrorLoggingService::kElapsedTimeKey);
  base::ExpectDictStringValue("dns", body_dict,
                              NetworkErrorLoggingService::kPhaseKey);
  base::ExpectDictStringValue("dns.address_changed", body_dict,
                              NetworkErrorLoggingService::kTypeKey);
}

TEST_P(NetworkErrorLoggingServiceTest, HttpErrorReportDowngraded) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderSuccessFraction1_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(
      MakeRequestDetails(kNak_, kUrl_, OK, "GET", 504, kOtherServerIP_));

  ASSERT_EQ(1u, reports().size());
  EXPECT_EQ(kUrl_, reports()[0].url);
  EXPECT_EQ(kNak_, reports()[0].network_anonymization_key);
  EXPECT_EQ(kGroup_, reports()[0].group);
  EXPECT_EQ(kType_, reports()[0].type);
  EXPECT_EQ(0, reports()[0].depth);

  const base::Value* body = reports()[0].body.get();
  ASSERT_TRUE(body);
  ASSERT_TRUE(body->is_dict());
  const base::Value::Dict& body_dict = body->GetDict();

  base::ExpectDictStringValue(kReferrer_.spec(), body_dict,
                              NetworkErrorLoggingService::kReferrerKey);
  ExpectDictDoubleValue(1.0, body_dict,
                        NetworkErrorLoggingService::kSamplingFractionKey);
  base::ExpectDictStringValue(kOtherServerIP_.ToString(), body_dict,
                              NetworkErrorLoggingService::kServerIpKey);
  base::ExpectDictStringValue("", body_dict,
                              NetworkErrorLoggingService::kProtocolKey);
  base::ExpectDictStringValue("GET", body_dict,
                              NetworkErrorLoggingService::kMethodKey);
  base::ExpectDictIntegerValue(0, body_dict,
                               NetworkErrorLoggingService::kStatusCodeKey);
  base::ExpectDictIntegerValue(0, body_dict,
                               NetworkErrorLoggingService::kElapsedTimeKey);
  base::ExpectDictStringValue("dns", body_dict,
                              NetworkErrorLoggingService::kPhaseKey);
  base::ExpectDictStringValue("dns.address_changed", body_dict,
                              NetworkErrorLoggingService::kTypeKey);
}

TEST_P(NetworkErrorLoggingServiceTest, DNSFailureReportNotDowngraded) {
  service()->OnHeader(kNak_, kOrigin_, kServerIP_, kHeaderSuccessFraction1_);

  // Make the rest of the test run synchronously.
  FinishLoading(true /* load_success */);

  service()->OnRequest(MakeRequestDetails(kNak_, kUrl_, ERR_NAME_NOT_RESOLVED,
                                          "
```