Response:
The user wants a summary of the functionality of the provided C++ code file. I need to analyze the code and identify its main purpose and how it interacts with other parts of the Chromium/Blink engine, especially in relation to Javascript, HTML, and CSS.

**Plan:**

1. Identify the main class under test: `AttributionSrcLoaderTest`.
2. Analyze the setup and test methods within `AttributionSrcLoaderTest`.
3. Determine the functionality of `AttributionSrcLoader`.
4. Check for relationships with Javascript, HTML, and CSS.
5. Identify logical inferences with input and output.
6. Look for common usage errors.这是对 `blink/renderer/core/frame/attribution_src_loader_test.cc` 文件的功能归纳。

**功能归纳：**

该文件是 Chromium Blink 引擎中 `AttributionSrcLoader` 类的单元测试。`AttributionSrcLoader` 负责处理 HTTP 响应头中的归因报告 (Attribution Reporting) 相关信息，并根据这些信息进行后续操作，例如注册事件源或触发器。

具体来说，该测试文件主要测试了以下 `AttributionSrcLoader` 的功能：

1. **注册触发器 (Register Trigger):** 测试当响应头包含 `Attribution-Reporting-Register-Trigger` 时，`AttributionSrcLoader` 能否正确解析并注册触发器数据。
2. **忽略 `attribution-src` 请求:** 测试 `AttributionSrcLoader` 是否会忽略由自身发起的请求的响应头。
3. **处理无效的符合条件的头部:** 测试当 `attribution-src` 请求返回无效的符合条件的头部信息时，`AttributionSrcLoader` 的行为。
4. **记录直方图 (Histograms Recorded):** 测试 `AttributionSrcLoader` 在处理归因请求时，是否正确记录了相关的性能指标到直方图中。这些指标包括请求状态（例如，已请求、已接收、失败）。
5. **设置引用 (Referrer):** 测试 `AttributionSrcLoader` 发起的归因请求是否设置了正确的 `Referrer-Policy`。
6. **不设置引用 (No Referrer):** 测试当明确指定不发送引用时，`AttributionSrcLoader` 的行为。
7. **设置符合条件的头部 (Eligible Header):** 测试 `AttributionSrcLoader` 发起的请求是否设置了 `Attribution-Reporting-Eligible` 头部，用于标识该请求是为了归因目的而发送的。
8. **设置用于导航的符合条件的头部 (Eligible Header for Navigation):** 测试在导航场景下，`AttributionSrcLoader` 发起的请求是否设置了正确的符合条件的头部，并携带了 `Attribution-Reporting-Attribution-Source` 令牌。
9. **提前关闭远程连接 (Eagerly Closes Remote):** 测试当没有更多数据需要接收时，`AttributionSrcLoader` 是否会主动断开与远程数据宿主的连接。
10. **禁用归因功能 (None Support):** 测试当页面禁用归因功能时，`AttributionSrcLoader` 不会发起归因请求。
11. **Web 功能禁用时，不注册触发器 (Web Disabled):** 测试当 Web 平台的归因功能被禁用时，即使响应头包含触发器信息，也不会进行注册。
12. **记录头部大小 (Headers Size):** 测试 `AttributionSrcLoader` 是否记录了归因报告相关头部的大小。
13. **跨应用 Web 功能禁用 (Cross App Web Runtime Disabled):** 测试当 `AttributionReportingCrossAppWeb` 功能被禁用时，不会注册操作系统级别的触发器。
14. **跨应用 Web 功能启用 (Cross App Web Enabled):**
    *   测试在启用跨应用 Web 功能后，`AttributionSrcLoader` 发起的请求会设置 `Attribution-Reporting-Support` 头部。
    *   测试可以注册操作系统级别的触发器。
    *   测试记录操作系统级别注册请求的头部大小。
15. **浏览器内迁移功能启用 (In Browser Migration Enabled):**
    *   测试当启用浏览器内迁移功能后，对于 `keep-alive` 的请求，即使响应头包含归因信息也会被忽略。
    *   测试对于非 `keep-alive` 的请求，即使是通过 Service Worker 返回的响应，也会处理其中的归因信息。
16. **首选平台 (Preferred Platform):**  测试当同时存在 Web 平台和操作系统平台的注册信息时，根据 `Attribution-Reporting-Info` 头部中的 `preferred-platform` 指令，选择注册哪个平台的归因信息。

**与 Javascript, HTML, CSS 的关系：**

该文件直接测试的是 C++ 代码的逻辑，但其功能与 Web 标准中的归因报告 API 密切相关，而这些 API 可以通过 Javascript 在网页中使用。

*   **Javascript:**  Javascript 代码可以使用归因报告 API (例如 `attributionReporting.registerSource()` 和 `attributionReporting.registerTrigger()`) 来指示浏览器发送包含归因信息的请求。`AttributionSrcLoader` 负责处理这些请求的响应头。
    *   **举例:**  一个广告平台可能会使用 Javascript 调用 `navigator.attributionReporting.registerTrigger()` 来注册一个转化事件。当包含此调用的页面发送请求，并且响应头包含 `Attribution-Reporting-Register-Trigger` 时，`AttributionSrcLoader` 会解析并处理这个头部。
*   **HTML:** HTML 元素（例如 `<a>` 标签）的属性可以触发归因请求。例如，带有 `attributionreporting` 属性的 `<a>` 标签可以发起一个用于注册归因源的请求。
    *   **举例:**  一个 HTML 链接 `<a href="https://destination.example" attributionreporting>` 被点击后，浏览器会发送一个请求，其响应头可能包含 `Attribution-Reporting-Register-Source`，`AttributionSrcLoader` 将负责处理。
*   **CSS:**  CSS 本身与归因报告功能没有直接的交互。

**逻辑推理的假设输入与输出：**

*   **假设输入:**  一个 HTTP 响应头包含 `Attribution-Reporting-Register-Trigger: {"event_trigger_data":[{"trigger_data": "123"}]}`。
*   **输出:**  `AttributionSrcLoader` 解析该头部，并调用相应的接口将触发器数据 `{reporting_origin: <响应的来源>, trigger_data: 123}` 传递给归因报告服务。

*   **假设输入:** 一个导航请求的响应头包含 `Attribution-Reporting-Register-Source: {"source_event_id": "456", "destination": "https://example.com"}`。
*   **输出:** `AttributionSrcLoader` 解析该头部，并将源数据 `{reporting_origin: <响应的来源>, source_event_id: 456, destination: https://example.com}` 传递给归因报告服务。

**涉及用户或者编程常见的使用错误：**

*   **错误地配置 HTTP 响应头:**  开发者可能会错误地配置 `Attribution-Reporting-Register-Source` 或 `Attribution-Reporting-Register-Trigger` 头部，例如 JSON 格式错误或缺少必要的字段。
    *   **举例:**  响应头设置为 `Attribution-Reporting-Register-Trigger: {"trigger_data": "abc"}` (缺少 `event_trigger_data` 数组)。`AttributionSrcLoader` 会检测到这个错误，并可能记录一个错误信息，但不会注册无效的触发器。
*   **在不应该设置的请求上设置归因相关的头部:**  开发者可能会在不希望触发归因行为的请求上错误地设置了 `Attribution-Reporting-Eligible` 头部。虽然这不会导致功能上的错误，但可能会产生不必要的网络请求。
*   **与权限策略 (Permissions Policy) 的冲突:**  页面可能没有获得使用归因报告功能的权限，但仍然尝试使用该功能。`AttributionSrcLoader` 会检查权限策略，并在权限不足时阻止归因请求。

总而言之，`attribution_src_loader_test.cc` 通过各种测试用例，确保 `AttributionSrcLoader` 能够正确可靠地处理 HTTP 响应头中的归因报告信息，这是 Chromium 浏览器实现 Web 标准归因报告功能的重要组成部分。

### 提示词
```
这是目录为blink/renderer/core/frame/attribution_src_loader_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/attribution_src_loader.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/functional/callback_helpers.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/uuid.h"
#include "build/build_config.h"
#include "build/buildflag.h"
#include "components/attribution_reporting/attribution_src_request_status.h"
#include "components/attribution_reporting/data_host.mojom-blink.h"
#include "components/attribution_reporting/os_registration.h"
#include "components/attribution_reporting/os_registration_error.mojom-shared.h"
#include "components/attribution_reporting/registration_eligibility.mojom-shared.h"
#include "components/attribution_reporting/registration_header_error.h"
#include "components/attribution_reporting/source_registration.h"
#include "components/attribution_reporting/source_registration_error.mojom-shared.h"
#include "components/attribution_reporting/suitable_origin.h"
#include "components/attribution_reporting/test_utils.h"
#include "components/attribution_reporting/trigger_registration.h"
#include "components/attribution_reporting/trigger_registration_error.mojom-shared.h"
#include "mojo/public/cpp/bindings/associated_receiver.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/mojom/attribution.mojom-blink.h"
#include "services/network/public/mojom/referrer_policy.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/conversions/conversions.mojom-blink.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/testing/fake_local_frame_host.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_factory.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/referrer.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

using ::attribution_reporting::AttributionSrcRequestStatus;

using ::network::mojom::AttributionReportingEligibility;
using ::network::mojom::AttributionSupport;

using blink::url_test_helpers::RegisterMockedErrorURLLoad;
using blink::url_test_helpers::RegisterMockedURLLoad;
using blink::url_test_helpers::ToKURL;

const char kAttributionReportingSupport[] = "Attribution-Reporting-Support";

const char kAttributionSrcRequestStatusMetric[] =
    "Conversions.AttributionSrcRequestStatus.All";
const char kAttributionSrcNavigationRequestStatusMetric[] =
    "Conversions.AttributionSrcRequestStatus.Navigation";

const char kUrl[] = "https://example1.com/foo.html";

ResourceRequest GetAttributionRequest(
    const KURL& url,
    AttributionSupport support = AttributionSupport::kWeb) {
  ResourceRequest request(url);
  request.SetAttributionReportingSupport(support);
  return request;
}

class AttributionSrcLocalFrameClient : public EmptyLocalFrameClient {
 public:
  AttributionSrcLocalFrameClient() = default;

  std::unique_ptr<URLLoader> CreateURLLoaderForTesting() override {
    return URLLoaderMockFactory::GetSingletonInstance()->CreateURLLoader();
  }

  void DispatchFinalizeRequest(ResourceRequest& request) override {
    if (request.GetRequestContext() ==
        mojom::blink::RequestContextType::ATTRIBUTION_SRC) {
      request_head_ = request;
    }
  }

  const ResourceRequestHead& request_head() const { return request_head_; }

 private:
  ResourceRequestHead request_head_;
};

class MockDataHost : public attribution_reporting::mojom::blink::DataHost {
 public:
  explicit MockDataHost(
      mojo::PendingReceiver<attribution_reporting::mojom::blink::DataHost>
          data_host) {
    receiver_.Bind(std::move(data_host));
    receiver_.set_disconnect_handler(
        WTF::BindOnce(&MockDataHost::OnDisconnect, WTF::Unretained(this)));
  }

  ~MockDataHost() override = default;

  const Vector<attribution_reporting::SourceRegistration>& source_data() const {
    return source_data_;
  }

  const Vector<attribution_reporting::TriggerRegistration>& trigger_data()
      const {
    return trigger_data_;
  }

  const std::vector<std::vector<attribution_reporting::OsRegistrationItem>>&
  os_sources() const {
    return os_sources_;
  }
  const std::vector<std::vector<attribution_reporting::OsRegistrationItem>>&
  os_triggers() const {
    return os_triggers_;
  }

  const Vector<attribution_reporting::RegistrationHeaderError>& header_errors()
      const {
    return header_errors_;
  }

  size_t disconnects() const { return disconnects_; }

  void Flush() { receiver_.FlushForTesting(); }

 private:
  void OnDisconnect() { disconnects_++; }

  // attribution_reporting::mojom::blink::DataHost:
  void SourceDataAvailable(
      attribution_reporting::SuitableOrigin reporting_origin,
      attribution_reporting::SourceRegistration data,
      bool was_fetched_via_serivce_worker) override {
    source_data_.push_back(std::move(data));
  }

  void TriggerDataAvailable(
      attribution_reporting::SuitableOrigin reporting_origin,
      attribution_reporting::TriggerRegistration data,
      bool was_fetched_via_serivce_worker) override {
    trigger_data_.push_back(std::move(data));
  }

  void OsSourceDataAvailable(
      std::vector<attribution_reporting::OsRegistrationItem> registration_items,
      bool was_fetched_via_serivce_worker) override {
    os_sources_.emplace_back(std::move(registration_items));
  }

  void OsTriggerDataAvailable(
      std::vector<attribution_reporting::OsRegistrationItem> registration_items,
      bool was_fetched_via_serivce_worker) override {
    os_triggers_.emplace_back(std::move(registration_items));
  }

  void ReportRegistrationHeaderError(
      attribution_reporting::SuitableOrigin reporting_origin,
      attribution_reporting::RegistrationHeaderError error) override {
    header_errors_.emplace_back(std::move(error));
  }

  Vector<attribution_reporting::SourceRegistration> source_data_;

  Vector<attribution_reporting::TriggerRegistration> trigger_data_;

  std::vector<std::vector<attribution_reporting::OsRegistrationItem>>
      os_sources_;
  std::vector<std::vector<attribution_reporting::OsRegistrationItem>>
      os_triggers_;

  Vector<attribution_reporting::RegistrationHeaderError> header_errors_;

  size_t disconnects_ = 0;
  mojo::Receiver<attribution_reporting::mojom::blink::DataHost> receiver_{this};
};

class MockAttributionHost : public mojom::blink::AttributionHost {
 public:
  explicit MockAttributionHost(blink::AssociatedInterfaceProvider* provider)
      : provider_(provider) {
    provider_->OverrideBinderForTesting(
        mojom::blink::AttributionHost::Name_,
        WTF::BindRepeating(&MockAttributionHost::BindReceiver,
                           WTF::Unretained(this)));
  }

  ~MockAttributionHost() override {
    CHECK(provider_);
    provider_->OverrideBinderForTesting(mojom::blink::AttributionHost::Name_,
                                        base::NullCallback());
  }

  void WaitUntilBoundAndFlush() {
    if (receiver_.is_bound()) {
      return;
    }
    base::RunLoop wait_loop;
    quit_ = wait_loop.QuitClosure();
    wait_loop.Run();
    receiver_.FlushForTesting();
  }

  MockDataHost* mock_data_host() { return mock_data_host_.get(); }

 private:
  void BindReceiver(mojo::ScopedInterfaceEndpointHandle handle) {
    receiver_.Bind(
        mojo::PendingAssociatedReceiver<mojom::blink::AttributionHost>(
            std::move(handle)));
    if (quit_) {
      std::move(quit_).Run();
    }
  }

  void RegisterDataHost(
      mojo::PendingReceiver<attribution_reporting::mojom::blink::DataHost>
          data_host,
      attribution_reporting::mojom::RegistrationEligibility eligibility,
      bool is_for_background_requests) override {
    mock_data_host_ = std::make_unique<MockDataHost>(std::move(data_host));
  }

  void RegisterNavigationDataHost(
      mojo::PendingReceiver<attribution_reporting::mojom::blink::DataHost>
          data_host,
      const blink::AttributionSrcToken& attribution_src_token) override {}

  void NotifyNavigationWithBackgroundRegistrationsWillStart(
      const blink::AttributionSrcToken& attribution_src_token,
      uint32_t expected_registrations) override {}

  mojo::AssociatedReceiver<mojom::blink::AttributionHost> receiver_{this};
  base::OnceClosure quit_;
  blink::AssociatedInterfaceProvider* provider_;

  std::unique_ptr<MockDataHost> mock_data_host_;
};

class AttributionSrcLoaderTest : public PageTestBase {
 public:
  AttributionSrcLoaderTest() = default;

  ~AttributionSrcLoaderTest() override = default;

  void SetUp() override {
    client_ = MakeGarbageCollected<AttributionSrcLocalFrameClient>();
    PageTestBase::SetupPageWithClients(nullptr, client_);

    SecurityContext& security_context =
        GetFrame().DomWindow()->GetSecurityContext();
    security_context.SetSecurityOriginForTesting(nullptr);
    security_context.SetSecurityOrigin(
        SecurityOrigin::CreateFromString("https://example.com"));

    attribution_src_loader_ =
        MakeGarbageCollected<AttributionSrcLoader>(&GetFrame());

    GetPage().SetAttributionSupport(AttributionSupport::kWeb);
  }

  void TearDown() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
    PageTestBase::TearDown();
  }

 protected:
  Persistent<AttributionSrcLocalFrameClient> client_;
  Persistent<AttributionSrcLoader> attribution_src_loader_;
};

TEST_F(AttributionSrcLoaderTest, RegisterTrigger) {
  const struct {
    const std::optional<AttributionReportingEligibility> eligibility;
    const std::string name;
  } kTestCases[] = {
      {std::nullopt, "unset"},
      {AttributionReportingEligibility::kTrigger, "kTrigger"},
      {AttributionReportingEligibility::kEventSourceOrTrigger,
       "kEventSourceOrTrigger"},
  };
  for (const auto& test_case : kTestCases) {
    SCOPED_TRACE("Eligibility: " + test_case.name);
    KURL test_url = ToKURL("https://example1.com/foo.html");

    ResourceRequest request = GetAttributionRequest(test_url);
    if (test_case.eligibility) {
      request.SetAttributionReportingEligibility(test_case.eligibility.value());
    }

    ResourceResponse response(test_url);
    response.SetHttpStatusCode(200);
    response.SetHttpHeaderField(
        http_names::kAttributionReportingRegisterTrigger,
        AtomicString(R"({"event_trigger_data":[{"trigger_data": "7"}]})"));

    MockAttributionHost host(
        GetFrame().GetRemoteNavigationAssociatedInterfaces());
    attribution_src_loader_->MaybeRegisterAttributionHeaders(request, response);
    host.WaitUntilBoundAndFlush();

    auto* mock_data_host = host.mock_data_host();
    ASSERT_TRUE(mock_data_host);

    mock_data_host->Flush();
    EXPECT_EQ(mock_data_host->trigger_data().size(), 1u);
  }
}

TEST_F(AttributionSrcLoaderTest, AttributionSrcRequestsIgnored) {
  KURL test_url = ToKURL("https://example1.com/foo.html");
  ResourceRequest request(test_url);
  request.SetRequestContext(mojom::blink::RequestContextType::ATTRIBUTION_SRC);

  ResourceResponse response(test_url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(
      http_names::kAttributionReportingRegisterTrigger,
      AtomicString(R"({"event_trigger_data":[{"trigger_data": "7"}]})"));

  EXPECT_FALSE(attribution_src_loader_->MaybeRegisterAttributionHeaders(
      request, response));
}

TEST_F(AttributionSrcLoaderTest, AttributionSrcRequestsInvalidEligibleHeaders) {
  KURL test_url = ToKURL("https://example1.com/foo.html");
  ResourceRequest request(test_url);
  request.SetRequestContext(mojom::blink::RequestContextType::ATTRIBUTION_SRC);

  ResourceResponse response(test_url);
  response.SetHttpStatusCode(200);

  const char* header_values[] = {"navigation-source, event-source, trigger",
                                 "!!!", ""};

  for (const char* header : header_values) {
    response.SetHttpHeaderField(
        http_names::kAttributionReportingRegisterTrigger, AtomicString(header));

    EXPECT_FALSE(attribution_src_loader_->MaybeRegisterAttributionHeaders(
        request, response))
        << header;
  }
}

TEST_F(AttributionSrcLoaderTest, AttributionSrcRequest_HistogramsRecorded) {
  base::HistogramTester histograms;

  KURL url1 = ToKURL(kUrl);
  RegisterMockedURLLoad(url1, test::CoreTestDataPath("foo.html"));

  attribution_src_loader_->Register(AtomicString(kUrl), /*element=*/nullptr,
                                    network::mojom::ReferrerPolicy::kDefault);

  static constexpr char kUrl2[] = "https://example2.com/foo.html";
  KURL url2 = ToKURL(kUrl2);
  RegisterMockedErrorURLLoad(url2);

  attribution_src_loader_->Register(AtomicString(kUrl2), /*element=*/nullptr,
                                    network::mojom::ReferrerPolicy::kDefault);

  // True = 1.
  histograms.ExpectBucketCount("Conversions.AllowedByPermissionPolicy", 1, 2);

  // kRequested = 0.
  histograms.ExpectUniqueSample(kAttributionSrcRequestStatusMetric, 0, 2);

  url_test_helpers::ServeAsynchronousRequests();

  // kReceived = 1.
  histograms.ExpectBucketCount(kAttributionSrcRequestStatusMetric, 1, 1);

  // kFailed = 2.
  histograms.ExpectBucketCount(kAttributionSrcRequestStatusMetric, 2, 1);
}

TEST_F(AttributionSrcLoaderTest, Referrer) {
  KURL url = ToKURL("https://example1.com/foo.html");
  RegisterMockedURLLoad(url, test::CoreTestDataPath("foo.html"));

  attribution_src_loader_->Register(AtomicString(kUrl), /*element=*/nullptr,
                                    network::mojom::ReferrerPolicy::kDefault);

  url_test_helpers::ServeAsynchronousRequests();

  EXPECT_EQ(client_->request_head().GetReferrerPolicy(),
            network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin);
}

TEST_F(AttributionSrcLoaderTest, NoReferrer) {
  KURL url = ToKURL("https://example1.com/foo.html");
  RegisterMockedURLLoad(url, test::CoreTestDataPath("foo.html"));

  attribution_src_loader_->Register(AtomicString(kUrl), /*element=*/nullptr,
                                    network::mojom::ReferrerPolicy::kNever);

  url_test_helpers::ServeAsynchronousRequests();

  EXPECT_EQ(client_->request_head().GetReferrerPolicy(),
            network::mojom::ReferrerPolicy::kNever);
}

TEST_F(AttributionSrcLoaderTest, EligibleHeader_Register) {
  KURL url = ToKURL(kUrl);
  RegisterMockedURLLoad(url, test::CoreTestDataPath("foo.html"));

  attribution_src_loader_->Register(AtomicString(kUrl), /*element=*/nullptr,
                                    network::mojom::ReferrerPolicy::kDefault);

  url_test_helpers::ServeAsynchronousRequests();

  EXPECT_EQ(client_->request_head().GetAttributionReportingEligibility(),
            AttributionReportingEligibility::kEventSourceOrTrigger);

  EXPECT_FALSE(client_->request_head().GetAttributionSrcToken());

  EXPECT_TRUE(client_->request_head()
                  .HttpHeaderField(AtomicString(kAttributionReportingSupport))
                  .IsNull());
}

TEST_F(AttributionSrcLoaderTest, EligibleHeader_RegisterNavigation) {
  KURL url = ToKURL(kUrl);
  RegisterMockedURLLoad(url, test::CoreTestDataPath("foo.html"));

  std::ignore = attribution_src_loader_->RegisterNavigation(
      /*navigation_url=*/KURL(), /*attribution_src=*/AtomicString(kUrl),
      /*element=*/MakeGarbageCollected<HTMLAnchorElement>(GetDocument()),
      /*has_transient_user_activation=*/true,
      network::mojom::ReferrerPolicy::kDefault);

  url_test_helpers::ServeAsynchronousRequests();

  EXPECT_EQ(client_->request_head().GetAttributionReportingEligibility(),
            AttributionReportingEligibility::kNavigationSource);

  EXPECT_TRUE(client_->request_head().GetAttributionSrcToken());

  EXPECT_TRUE(client_->request_head()
                  .HttpHeaderField(AtomicString(kAttributionReportingSupport))
                  .IsNull());
}

// Regression test for crbug.com/1336797, where we didn't eagerly disconnect a
// source-eligible data host even if we knew there is no more data to be
// received on that channel. This test confirms the channel properly
// disconnects in this case.
TEST_F(AttributionSrcLoaderTest, EagerlyClosesRemote) {
  KURL url = ToKURL(kUrl);
  RegisterMockedURLLoad(url, test::CoreTestDataPath("foo.html"));

  MockAttributionHost host(
      GetFrame().GetRemoteNavigationAssociatedInterfaces());
  attribution_src_loader_->Register(AtomicString(kUrl), /*element=*/nullptr,
                                    network::mojom::ReferrerPolicy::kDefault);
  host.WaitUntilBoundAndFlush();
  url_test_helpers::ServeAsynchronousRequests();

  auto* mock_data_host = host.mock_data_host();
  ASSERT_TRUE(mock_data_host);
  EXPECT_EQ(mock_data_host->disconnects(), 1u);
}

TEST_F(AttributionSrcLoaderTest, NoneSupport_NoAttributionSrcRequest) {
  GetPage().SetAttributionSupport(AttributionSupport::kNone);

  base::HistogramTester histograms;

  KURL url = ToKURL(kUrl);
  RegisterMockedURLLoad(url, test::CoreTestDataPath("foo.html"));

  attribution_src_loader_->Register(AtomicString(kUrl), /*element=*/nullptr,
                                    network::mojom::ReferrerPolicy::kDefault);

  histograms.ExpectTotalCount(kAttributionSrcRequestStatusMetric, 0);
}

TEST_F(AttributionSrcLoaderTest, WebDisabled_TriggerNotRegistered) {
  KURL test_url = ToKURL("https://example1.com/foo.html");

  for (auto attribution_support :
       {AttributionSupport::kNone, AttributionSupport::kOs}) {
    ResourceRequest request =
        GetAttributionRequest(test_url, attribution_support);
    ResourceResponse response(test_url);
    response.SetHttpStatusCode(200);
    response.SetHttpHeaderField(
        http_names::kAttributionReportingRegisterTrigger,
        AtomicString(R"({"event_trigger_data":[{"trigger_data": "7"}]})"));

    MockAttributionHost host(
        GetFrame().GetRemoteNavigationAssociatedInterfaces());
    EXPECT_TRUE(attribution_src_loader_->MaybeRegisterAttributionHeaders(
        request, response));
    host.WaitUntilBoundAndFlush();

    auto* mock_data_host = host.mock_data_host();
    ASSERT_TRUE(mock_data_host);

    mock_data_host->Flush();
    EXPECT_THAT(mock_data_host->trigger_data(), testing::IsEmpty());
  }
}

TEST_F(AttributionSrcLoaderTest, HeadersSize_RecordsMetrics) {
  base::HistogramTester histograms;
  KURL test_url = ToKURL("https://example1.com/foo.html");
  AtomicString register_trigger_json(
      R"({"event_trigger_data":[{"trigger_data": "7"}]})");
  AtomicString register_source_json(
      R"({"source_event_id":"5","destination":"https://destination.example"})");

  ResourceRequest request = GetAttributionRequest(test_url);
  request.SetAttributionReportingEligibility(
      AttributionReportingEligibility::kTrigger);
  ResourceResponse response(test_url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(http_names::kAttributionReportingRegisterTrigger,
                              register_trigger_json);

  attribution_src_loader_->MaybeRegisterAttributionHeaders(request, response);
  histograms.ExpectUniqueSample("Conversions.HeadersSize.RegisterTrigger",
                                register_trigger_json.length(), 1);

  request.SetAttributionReportingEligibility(
      AttributionReportingEligibility::kEventSource);
  response.SetHttpHeaderField(http_names::kAttributionReportingRegisterSource,
                              register_source_json);

  attribution_src_loader_->MaybeRegisterAttributionHeaders(request, response);
  histograms.ExpectUniqueSample("Conversions.HeadersSize.RegisterSource",
                                register_source_json.length(), 1);
}

class AttributionSrcLoaderCrossAppWebRuntimeDisabledTest
    : public AttributionSrcLoaderTest {
 public:
  AttributionSrcLoaderCrossAppWebRuntimeDisabledTest() {
    WebRuntimeFeatures::EnableFeatureFromString(
        /*name=*/"AttributionReportingCrossAppWeb", /*enable=*/false);
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_{
      network::features::kAttributionReportingCrossAppWeb};
};

TEST_F(AttributionSrcLoaderCrossAppWebRuntimeDisabledTest,
       OsTriggerNotRegistered) {
  GetPage().SetAttributionSupport(AttributionSupport::kWebAndOs);

  KURL test_url = ToKURL("https://example1.com/foo.html");

  ResourceRequest request(test_url);
  ResourceResponse response(test_url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(
      http_names::kAttributionReportingRegisterOSTrigger,
      AtomicString(R"("https://r.test/x")"));

  EXPECT_FALSE(attribution_src_loader_->MaybeRegisterAttributionHeaders(
      request, response));
}

class AttributionSrcLoaderCrossAppWebEnabledTest
    : public AttributionSrcLoaderTest {
 public:
  AttributionSrcLoaderCrossAppWebEnabledTest() {
    WebRuntimeFeatures::EnableFeatureFromString(
        /*name=*/"AttributionReportingCrossAppWeb", /*enable=*/true);
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_{
      network::features::kAttributionReportingCrossAppWeb};
};

TEST_F(AttributionSrcLoaderCrossAppWebEnabledTest, SupportHeader_Register) {
  auto attribution_support = AttributionSupport::kWebAndOs;

  GetPage().SetAttributionSupport(attribution_support);

  KURL url = ToKURL(kUrl);
  RegisterMockedURLLoad(url, test::CoreTestDataPath("foo.html"));

  attribution_src_loader_->Register(AtomicString(kUrl), /*element=*/nullptr,
                                    network::mojom::ReferrerPolicy::kDefault);

  url_test_helpers::ServeAsynchronousRequests();

  EXPECT_EQ(client_->request_head().GetAttributionReportingSupport(),
            attribution_support);
}

TEST_F(AttributionSrcLoaderCrossAppWebEnabledTest,
       SupportHeader_RegisterNavigation) {
  auto attribution_support = AttributionSupport::kWebAndOs;

  GetPage().SetAttributionSupport(attribution_support);

  KURL url = ToKURL(kUrl);
  RegisterMockedURLLoad(url, test::CoreTestDataPath("foo.html"));

  std::ignore = attribution_src_loader_->RegisterNavigation(
      /*navigation_url=*/KURL(), /*attribution_src=*/AtomicString(kUrl),
      /*element=*/MakeGarbageCollected<HTMLAnchorElement>(GetDocument()),
      /*has_transient_user_activation=*/true,
      network::mojom::ReferrerPolicy::kDefault);

  url_test_helpers::ServeAsynchronousRequests();

  EXPECT_EQ(client_->request_head().GetAttributionReportingSupport(),
            attribution_support);
}

TEST_F(AttributionSrcLoaderCrossAppWebEnabledTest, RegisterOsTrigger) {
  KURL test_url = ToKURL("https://example1.com/foo.html");

  ResourceRequest request =
      GetAttributionRequest(test_url, AttributionSupport::kWebAndOs);
  ResourceResponse response(test_url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(
      http_names::kAttributionReportingRegisterOSTrigger,
      AtomicString(R"("https://r.test/x")"));

  MockAttributionHost host(
      GetFrame().GetRemoteNavigationAssociatedInterfaces());
  EXPECT_TRUE(attribution_src_loader_->MaybeRegisterAttributionHeaders(
      request, response));
  host.WaitUntilBoundAndFlush();

  auto* mock_data_host = host.mock_data_host();
  ASSERT_TRUE(mock_data_host);

  mock_data_host->Flush();
  EXPECT_THAT(mock_data_host->os_triggers(),
              ::testing::ElementsAre(::testing::ElementsAre(
                  attribution_reporting::OsRegistrationItem{
                      .url = GURL("https://r.test/x")})));
}

TEST_F(AttributionSrcLoaderCrossAppWebEnabledTest,
       HeadersSize_OsMetricsRecorded) {
  base::HistogramTester histograms;

  KURL test_url = ToKURL("https://example1.com/foo.html");
  AtomicString os_registration(R"("https://r.test/x")");

  ResourceRequest request =
      GetAttributionRequest(test_url, AttributionSupport::kWebAndOs);
  request.SetAttributionReportingEligibility(
      AttributionReportingEligibility::kTrigger);
  ResourceResponse response(test_url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(
      http_names::kAttributionReportingRegisterOSTrigger, os_registration);

  EXPECT_TRUE(attribution_src_loader_->MaybeRegisterAttributionHeaders(
      request, response));
  histograms.ExpectUniqueSample("Conversions.HeadersSize.RegisterOsTrigger",
                                os_registration.length(), 1);

  request.SetAttributionReportingEligibility(
      AttributionReportingEligibility::kEventSource);
  response.SetHttpHeaderField(http_names::kAttributionReportingRegisterOSSource,
                              os_registration);

  EXPECT_TRUE(attribution_src_loader_->MaybeRegisterAttributionHeaders(
      request, response));
  histograms.ExpectUniqueSample("Conversions.HeadersSize.RegisterOsSource",
                                os_registration.length(), 1);
}

class AttributionSrcLoaderInBrowserMigrationEnabledTest
    : public AttributionSrcLoaderTest {
 public:
  AttributionSrcLoaderInBrowserMigrationEnabledTest() {
    scoped_feature_list_.InitWithFeatures(
        {blink::features::kKeepAliveInBrowserMigration,
         blink::features::kAttributionReportingInBrowserMigration},
        {});
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_F(AttributionSrcLoaderInBrowserMigrationEnabledTest,
       MaybeRegisterAttributionHeaders_KeepAliveRequestsResponseIgnored) {
  KURL test_url = ToKURL("https://example1.com/foo.html");

  for (bool is_keep_alive : {true, false}) {
    ResourceRequest request = GetAttributionRequest(test_url);
    request.SetKeepalive(is_keep_alive);
    request.SetAttributionReportingEligibility(
        AttributionReportingEligibility::kTrigger);
    ResourceResponse response(test_url);
    response.SetHttpStatusCode(200);
    response.SetHttpHeaderField(
        http_names::kAttributionReportingRegisterTrigger,
        AtomicString(R"({"event_trigger_data":[{"trigger_data": "7"}]})"));

    EXPECT_EQ(attribution_src_loader_->MaybeRegisterAttributionHeaders(
                  request, response),
              is_keep_alive ? false : true);
  }
}

TEST_F(
    AttributionSrcLoaderInBrowserMigrationEnabledTest,
    MaybeRegisterAttributionHeadersNonKeepAlive_ResponseViaServiceWorkerProcessed) {
  KURL test_url = ToKURL("https://example1.com/foo.html");

  ResourceRequest request = GetAttributionRequest(test_url);
  request.SetKeepalive(true);
  request.SetAttributionReportingEligibility(
      AttributionReportingEligibility::kTrigger);
  ResourceResponse response(test_url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(
      http_names::kAttributionReportingRegisterTrigger,
      AtomicString(R"({"event_trigger_data":[{"trigger_data": "7"}]})"));
  response.SetWasFetchedViaServiceWorker(true);

  EXPECT_TRUE(attribution_src_loader_->MaybeRegisterAttributionHeaders(
      request, response));
}

struct PreferredPlatformTestCase {
  bool feature_enabled = true;
  const char* info_header;
  bool has_web_header;
  bool has_os_header;
  AttributionSupport support;
  bool expected_web;
  bool expected_os;
};

const PreferredPlatformTestCase kPreferredPlatformTestCases[] = {
    {
        .info_header = nullptr,
        .has_web_header = true,
        .has_os_header = true,
        .support = AttributionSupport::kWebAndOs,
        .expected_web = false,
        .expected_os = false,
    },
    {
        .info_header = "preferred-platform=os",
        .has_web_header = true,
        .has_os_header = true,
        .support = AttributionSupport::kWebAndOs,
        .expected_web = false,
        .expected_os = true,
    },
    {
        .info_header = "preferred-platform=os",
        .has_web_header = true,
        .has_os_header = true,
        .support = AttributionSupport::kOs,
        .expected_web = false,
        .expected_os = true,
    },
    {
        .info_header = "preferred-platform=os",
        .has_web_header = true,
        .has_os_header = true,
        .support = AttributionSupport::kWeb,
        .expected_web = true,
        .expected_os = false,
    },
    {
        .info_header = "preferred-platform=os",
        .has_web_header = true,
        .has_os_header = true,
        .support = AttributionSupport::kNone,
        .expected_web = false,
        .expected_os = false,
    },
    {
        .info_header = "preferred-platform=os",
        .has_web_header = false,
        .has_os_header = true,
        .support = AttributionSupport::kWeb,
        .expected_web = false,
        .expected_os = false,
    },
    {
        .info_header = "preferred-platform=os",
        .has_web_header = true,
        .has_os_header = false,
        .support = AttributionSupport::kWeb,
        .expected_web = false,
        .expected_os = false,
    },
    {
        .info_header = "preferred-platform=web",
        .has_web_header = true,
        .has_os_header = true,
        .support = AttributionSupport::kWebAndOs,
        .expected_web = true,
        .expected_os = false,
    },
    {
        .info_header = "preferred-platform=web",
        .has_web_header = true,
        .has_os_header = true,
        .support = AttributionSupport::kWeb,
        .expected_web = true,
        .expected_os = false,
    },
    {
        .info_header = "preferred-platform=web",
        .has_web_header = true,
        .has_os_header = true,
        .support = AttributionSupport::kOs,
        .expected_web = false,
        .expected_os = true,
    },
    {
        .info_header = "preferred-platform=web",
        .has_web_header = true,
        .has_os_header = true,
        .support = AttributionSupport::kNone,
        .expected_web = false,
        .expected_os = false,
    },
    {
        .info_header = "preferred-platform=web",
        .has_web_header = true,
        .has_os_header = false,
        .support = AttributionSupport::kOs,
        .expected_web = false,
        .expected_os = false,
    },
    {
        .info_header = "preferred-platform=web",
        .has_web_header = false,
        .has_os_header = true,
        .support = AttributionSupport::kOs,
        .expected_web = false,
        .expected_os = false,
    },
};

class AttributionSrcLoaderPreferredPlatformEnabledTest
    : public AttributionSrcLoaderCrossAppWebEnabledTest,
      public ::testing::WithParamInterface<PreferredPlatformTestCase> {};

class AttributionSrcLoaderPreferredPlatformSourceTest
    : public AttributionSrcLoaderPreferredPlatformEnabledTest {};

INSTANTIATE_TEST_SUITE_P(All,
                         AttributionSrcLoaderPreferredPlatformSourceTest,
                         ::testing::ValuesIn(kPreferredPlatformTestCases));

TEST_P(AttributionSrcLoaderPreferredPlatformSourceTest, PreferredPlatform) {
  KURL test_url = ToKURL("https://example1.com/foo.html");

  const auto& test_case = GetParam();

  ResourceRequest request = GetAttributionRequest(test_url, test_case.support);
  request.SetAttributionReportingEligibility(
      AttributionReportingEligibility::kEventSourceOrTrigger);
  ResourceResponse response(test_url);
  response.SetHttpStatusCode(200);
  if (test_case.has_web_header) {
    response.SetHttpHeaderField(
        http_names::kAttributionReportingRegisterSource,
        AtomicString(R"({"destination":"https://destination.example"})"));
  }
  if (test_case.has_os_header) {
    response.SetHttpH
```