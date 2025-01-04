Response:
The user wants to understand the functionality of the `frame_fetch_context_test.cc` file in the Chromium Blink engine.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core purpose:** The filename ends with `_test.cc`, strongly suggesting this file contains unit tests. The presence of includes like `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h` confirms this.

2. **Determine the subject of the tests:** The first include is `"third_party/blink/renderer/core/loader/frame_fetch_context.h"`. This tells us the tests are specifically for the `FrameFetchContext` class.

3. **Infer the role of `FrameFetchContext`:** Based on its name and location (within `core/loader`), `FrameFetchContext` likely manages the fetching of resources within the context of a frame. This involves handling requests, applying security policies, and interacting with the network stack.

4. **Analyze the included headers to understand the scope of testing:**  The included headers provide clues about the functionalities being tested. Look for keywords and categories:
    * **`services/network/...`**:  Indicates testing of interactions with the network service (e.g., client hints, features).
    * **`third_party/blink/public/mojom/...`**:  Points to testing of interfaces and data structures used for communication between different parts of Blink (e.g., fetch API requests, request context types, security policies).
    * **`third_party/blink/renderer/core/dom/...`**: Suggests testing of how fetching interacts with the DOM (e.g., `Document`).
    * **`third_party/blink/renderer/core/frame/...`**:  Highlights testing of frame-related functionalities (e.g., `LocalFrame`, `FrameOwner`, settings).
    * **`third_party/blink/renderer/core/loader/...`**:  Confirms testing of loader-specific features (e.g., `DocumentLoader`, `SubresourceFilter`).
    * **`third_party/blink/renderer/platform/loader/fetch/...`**: Indicates testing of the underlying fetch mechanism (e.g., `ResourceRequest`, `ResourceLoaderOptions`).
    * **`third_party/blink/renderer/platform/testing/...`**: Confirms the use of testing utilities.

5. **Identify key areas of functionality being tested based on the includes and the test file's content (even without the full content, the includes give significant clues):**
    * **Subresource filtering:** The inclusion of `web_document_subresource_filter.h` and the `FrameFetchContextSubresourceFilterTest` class strongly suggest testing of how the fetch context interacts with subresource filters to block or allow requests.
    * **Client hints:** The presence of `services/network/public/mojom/web_client_hints_types.mojom-blink.h` and the `FrameFetchContextHintsTest` class point to tests for how the fetch context handles client hints.
    * **Content Security Policy (CSP) and Upgrade Insecure Requests:** The `FrameFetchContextModifyRequestTest` class and mentions of `http_names::kUpgradeInsecureRequests` suggest testing of how CSP directives and the "Upgrade Insecure Requests" mechanism affect resource fetching.
    * **First-party cookies:** The `SetFirstPartyCookie` method indicates testing of how the fetch context handles first-party cookies.

6. **Consider the relationship to web technologies (JavaScript, HTML, CSS):**  Since `FrameFetchContext` is part of the rendering engine, its functionality is crucial for loading web content.
    * **JavaScript:** When JavaScript code initiates a fetch request (e.g., using `fetch()` or `XMLHttpRequest`), the `FrameFetchContext` is involved in processing and executing that request.
    * **HTML:** When the browser parses HTML and encounters tags that require fetching resources (e.g., `<img>`, `<link>`, `<script>`), the `FrameFetchContext` is responsible for initiating those fetches.
    * **CSS:**  Similarly, when CSS rules reference external resources (e.g., background images, fonts), the `FrameFetchContext` manages their retrieval.

7. **Think about potential user/developer errors:**  Common mistakes related to resource loading can be tied back to the `FrameFetchContext`. This includes:
    * **Mixed content errors:** Trying to load insecure resources on a secure page.
    * **CORS errors:**  Attempting cross-origin requests without proper headers.
    * **Subresource blocking:**  Filters or browser settings preventing resources from loading.
    * **Incorrect CSP directives:**  Writing CSP rules that unintentionally block necessary resources.

8. **Consider the debugging perspective:** How would a developer end up looking at this test file?  It would likely be during debugging of resource loading issues, security policy enforcement, or when adding new features related to fetching. Tracing the execution flow during a resource load might lead a developer here.

9. **Summarize the functionality for Part 1:** Based on the analysis, the primary function of the file is to test the `FrameFetchContext` class. It covers aspects like subresource filtering, client hints, security policy enforcement (CSP, mixed content), and potentially cookie handling.

By following these steps, we can create a comprehensive answer that addresses the user's request and provides valuable insights into the purpose and functionality of the `frame_fetch_context_test.cc` file.
这个文件 `blink/renderer/core/loader/frame_fetch_context_test.cc` 是 Chromium Blink 引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `FrameFetchContext` 类的各种功能和行为**。

`FrameFetchContext` 类在 Blink 渲染引擎中扮演着重要的角色，它负责管理和处理与 **帧（frame）相关的资源获取（fetching）过程**。这包括决定如何发起请求、应用各种安全策略、处理缓存、以及与网络层进行交互等等。

由于这是一个测试文件，它的主要目的是 **验证 `FrameFetchContext` 类的实现是否正确，是否按照预期工作**。  它通过编写各种测试用例，模拟不同的场景和输入，来检查 `FrameFetchContext` 的输出和副作用是否符合预期。

**与 JavaScript, HTML, CSS 的关系：**

`FrameFetchContext` 的功能与 JavaScript, HTML, CSS 的功能息息相关，因为它直接参与了这些技术所需要的资源的加载过程。

* **HTML:** 当浏览器解析 HTML 页面时，遇到需要加载外部资源的标签，例如 `<img>`, `<link>`, `<script>`, `<iframe>` 等，`FrameFetchContext` 负责发起对这些资源的请求。
    * **举例：** 当 HTML 中包含 `<img src="https://example.com/image.png">` 时，Blink 引擎会创建一个资源请求，`FrameFetchContext` 会参与处理这个请求，例如检查是否需要添加特定的请求头（如客户端提示），是否需要应用内容安全策略（CSP），是否需要进行混合内容检查等。
* **CSS:** CSS 文件中可能包含对外部资源的引用，例如 `background-image: url(image.png);` 或者 `@font-face { src: url(font.woff2); }`。`FrameFetchContext` 同样负责加载这些 CSS 资源。
    * **举例：** 当浏览器解析包含 `background-image: url(image.png);` 的 CSS 规则时，`FrameFetchContext` 会处理对 `image.png` 的请求。它可能会检查这个请求是否违反了 CSP 策略，或者是否应该发送客户端提示头。
* **JavaScript:** JavaScript 代码可以使用 `fetch()` API 或者 `XMLHttpRequest` 来发起网络请求。这些请求最终也会由 Blink 引擎的加载机制处理，`FrameFetchContext` 在其中扮演着关键角色。
    * **举例：** 当 JavaScript 代码执行 `fetch('https://api.example.com/data')` 时，`FrameFetchContext` 会参与处理这个请求。它会根据当前帧的安全上下文、CSP 策略等来配置请求，并与网络层进行交互。

**逻辑推理 (假设输入与输出):**

虽然这是一个测试文件，但我们可以从测试用例的结构推断出 `FrameFetchContext` 的一些行为。以下是一些假设的输入和预期的输出：

* **假设输入：** 一个 HTTPS 页面尝试加载一个 HTTP 的图片资源。
* **预期输出：** 如果启用了混合内容阻止策略，`FrameFetchContext` 应该阻止该请求，并可能在控制台中输出警告信息。测试用例可能会验证 `FrameFetchContext` 是否返回了指示请求被阻止的状态。
* **假设输入：**  一个页面设置了客户端提示策略，要求发送 `Device-Memory` 头。发起一个对同源 HTTPS 资源的请求。
* **预期输出：** `FrameFetchContext` 应该在请求头中添加 `Device-Memory` 头，其值为设备的内存大小。测试用例会创建一个请求，然后断言请求头中是否包含了预期的 `Device-Memory` 头。
* **假设输入：**  一个 iframe 尝试加载一个被父页面 CSP 策略禁止的资源。
* **预期输出：** `FrameFetchContext` 应该阻止 iframe 加载该资源。测试用例可能会创建一个模拟的 iframe 和资源请求，并验证 `FrameFetchContext` 是否阻止了加载。

**涉及用户或编程常见的使用错误：**

虽然 `FrameFetchContext` 是引擎内部的组件，但其行为直接影响用户和开发者的体验。以下是一些可能的使用错误，可以通过测试 `FrameFetchContext` 的行为来发现：

* **混合内容错误：** 开发者在 HTTPS 网站上引用了 HTTP 资源，导致浏览器阻止加载。测试用例会验证 `FrameFetchContext` 是否正确地阻止了混合内容。
* **CORS 错误：**  开发者进行跨域请求时，服务端没有设置正确的 CORS 头，导致请求失败。尽管 `FrameFetchContext` 本身不直接处理 CORS，但它会受到 CORS 策略的影响，测试可以验证它是否按照 CORS 策略工作。
* **CSP 错误：** 开发者设置了过于严格的 CSP 策略，导致网站的某些资源无法加载。测试用例可以验证 `FrameFetchContext` 是否按照 CSP 策略正确地阻止或允许资源加载。
* **客户端提示配置错误：** 开发者没有正确配置客户端提示策略，导致需要的客户端提示头没有被发送。测试用例会验证 `FrameFetchContext` 是否按照配置发送了客户端提示头。

**用户操作是如何一步步的到达这里，作为调试线索：**

通常情况下，用户不会直接操作到 `FrameFetchContext`。它是在浏览器内部默默工作的。但是，当用户执行某些操作时，会触发资源加载，从而间接地使用到 `FrameFetchContext`。作为调试线索，以下步骤可能会引导开发者查看 `frame_fetch_context_test.cc`：

1. **用户访问一个网页：**  当用户在地址栏输入网址或点击链接时，浏览器开始加载 HTML 页面。
2. **浏览器解析 HTML：**  Blink 引擎解析 HTML 代码，发现需要加载的各种资源（图片、CSS、JS、iframe 等）。
3. **创建资源请求：** 对于每个需要加载的资源，Blink 会创建一个 `ResourceRequest` 对象。
4. **调用 `FrameFetchContext`：**  `FrameFetchContext` 参与处理这些 `ResourceRequest`，例如检查安全策略、添加必要的头部信息等。
5. **网络请求：**  `FrameFetchContext` 将处理后的请求传递给网络层，发起实际的网络请求。
6. **资源加载完成/失败：**  网络层返回资源的响应，或者指示请求失败。
7. **渲染页面：**  Blink 引擎根据加载的资源渲染页面。

**调试线索：** 如果在上述过程中出现问题，例如资源加载失败、混合内容错误、CSP 阻止等，开发者可能会：

* **查看开发者工具的网络面板：**  检查请求的状态、头部信息等，可能会发现请求被阻止或者缺少某些头部。
* **查看开发者工具的控制台：**  可能会看到混合内容警告或 CSP 错误信息。
* **查阅 Blink 引擎的源代码：**  如果开发者需要深入了解资源加载的细节，或者怀疑是 Blink 引擎的 Bug，可能会查看 `FrameFetchContext` 相关的代码，包括测试文件 `frame_fetch_context_test.cc`，来理解其内部逻辑和测试覆盖范围。例如，如果怀疑某个 CSP 指令没有生效，可能会查看相关的测试用例，看看是否已经覆盖了这种情况。

**功能归纳 (第 1 部分):**

`blink/renderer/core/loader/frame_fetch_context_test.cc` 的主要功能是 **单元测试 `FrameFetchContext` 类**。`FrameFetchContext` 负责处理帧内的资源获取过程，包括发起请求、应用安全策略（如 CSP、混合内容检查）、处理客户端提示等。  这个测试文件通过模拟各种场景和输入，验证 `FrameFetchContext` 的行为是否符合预期，确保了 Blink 引擎资源加载功能的正确性和稳定性。它与 JavaScript, HTML, CSS 的资源加载紧密相关，并可以帮助发现和避免与资源加载相关的常见用户或编程错误。

Prompt: 
```
这是目录为blink/renderer/core/loader/frame_fetch_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (c) 2015, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/loader/frame_fetch_context.h"

#include <memory>
#include <optional>

#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/mojom/web_client_hints_types.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/device_memory/approximated_device_memory.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/request_context_frame_type.mojom-blink.h"
#include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-blink.h"
#include "third_party/blink/public/mojom/timing/resource_timing.mojom-blink-forward.h"
#include "third_party/blink/public/platform/scheduler/web_scoped_virtual_time_pauser.h"
#include "third_party/blink/public/platform/web_document_subresource_filter.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/ad_tracker.h"
#include "third_party/blink/renderer/core/frame/frame_owner.h"
#include "third_party/blink/renderer/core/frame/frame_types.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/loader/frame_resource_fetcher_properties.h"
#include "third_party/blink/renderer/core/loader/subresource_filter.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_info.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_timing_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#include "third_party/blink/renderer/platform/loader/testing/mock_resource.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/reporting_disposition.h"

namespace blink {

namespace {

class DummyFrameOwner final : public GarbageCollected<DummyFrameOwner>,
                              public FrameOwner {
 public:
  void Trace(Visitor* visitor) const override { FrameOwner::Trace(visitor); }

  // FrameOwner overrides:
  Frame* ContentFrame() const override { return nullptr; }
  void SetContentFrame(Frame&) override {}
  void ClearContentFrame() override {}
  const FramePolicy& GetFramePolicy() const override {
    DEFINE_STATIC_LOCAL(FramePolicy, frame_policy, ());
    return frame_policy;
  }
  void AddResourceTiming(mojom::blink::ResourceTimingInfoPtr) override {}
  void DispatchLoad() override {}
  void IntrinsicSizingInfoChanged() override {}
  void SetNeedsOcclusionTracking(bool) override {}
  AtomicString BrowsingContextContainerName() const override {
    return AtomicString();
  }
  mojom::blink::ScrollbarMode ScrollbarMode() const override {
    return mojom::blink::ScrollbarMode::kAuto;
  }
  int MarginWidth() const override { return -1; }
  int MarginHeight() const override { return -1; }
  bool AllowFullscreen() const override { return false; }
  bool AllowPaymentRequest() const override { return false; }
  bool IsDisplayNone() const override { return false; }
  mojom::blink::ColorScheme GetColorScheme() const override {
    return mojom::blink::ColorScheme::kLight;
  }
  mojom::blink::PreferredColorScheme GetPreferredColorScheme() const override {
    return mojom::blink::PreferredColorScheme::kLight;
  }
  bool ShouldLazyLoadChildren() const override { return false; }

 private:
  // Intentionally private to prevent redundant checks when the type is
  // already DummyFrameOwner.
  bool IsLocal() const override { return false; }
  bool IsRemote() const override { return false; }
};

}  // namespace

using Checkpoint = testing::StrictMock<testing::MockFunction<void(int)>>;

class FrameFetchContextMockLocalFrameClient : public EmptyLocalFrameClient {
 public:
  FrameFetchContextMockLocalFrameClient() : EmptyLocalFrameClient() {}
  MOCK_METHOD0(DidDisplayContentWithCertificateErrors, void());
  MOCK_METHOD2(DispatchDidLoadResourceFromMemoryCache,
               void(const ResourceRequest&, const ResourceResponse&));
  MOCK_METHOD0(UserAgent, String());
  MOCK_METHOD0(MayUseClientLoFiForImageRequests, bool());
};

class FixedPolicySubresourceFilter : public WebDocumentSubresourceFilter {
 public:
  FixedPolicySubresourceFilter(LoadPolicy policy,
                               int* filtered_load_counter,
                               bool is_associated_with_ad_subframe)
      : policy_(policy), filtered_load_counter_(filtered_load_counter) {}

  LoadPolicy GetLoadPolicy(const WebURL& resource_url,
                           network::mojom::RequestDestination) override {
    return policy_;
  }

  LoadPolicy GetLoadPolicyForWebSocketConnect(const WebURL& url) override {
    return policy_;
  }

  LoadPolicy GetLoadPolicyForWebTransportConnect(const WebURL&) override {
    return policy_;
  }
  void ReportDisallowedLoad() override { ++*filtered_load_counter_; }

  bool ShouldLogToConsole() override { return false; }

 private:
  const LoadPolicy policy_;
  int* filtered_load_counter_;
};

class FrameFetchContextTest : public testing::Test {
 protected:
  void SetUp() override { RecreateFetchContext(); }

  void RecreateFetchContext(
      const KURL& url = KURL(),
      const String& permissions_policy_header = String()) {
    dummy_page_holder = nullptr;
    dummy_page_holder = std::make_unique<DummyPageHolder>(gfx::Size(500, 500));
    if (url.IsValid()) {
      auto params = WebNavigationParams::CreateWithEmptyHTMLForTesting(url);
      if (!permissions_policy_header.empty()) {
        params->response.SetHttpHeaderField(http_names::kFeaturePolicy,
                                            permissions_policy_header);
      }
      dummy_page_holder->GetFrame().Loader().CommitNavigation(
          std::move(params), nullptr /* extra_data */);
      blink::test::RunPendingTasks();
      ASSERT_EQ(url.GetString(),
                dummy_page_holder->GetDocument().Url().GetString());
    }
    document = &dummy_page_holder->GetDocument();
    owner = MakeGarbageCollected<DummyFrameOwner>();
  }

  FrameFetchContext* GetFetchContext() {
    return static_cast<FrameFetchContext*>(&document->Fetcher()->Context());
  }

  // Call the method for the actual test cases as only this fixture is specified
  // as a friend class.
  void SetFirstPartyCookie(ResourceRequest& request) {
    GetFetchContext()->SetFirstPartyCookie(request);
  }

  scoped_refptr<const SecurityOrigin> GetTopFrameOrigin() {
    return GetFetchContext()->GetTopFrameOrigin();
  }

  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> dummy_page_holder;
  // We don't use the DocumentLoader directly in any tests, but need to keep it
  // around as long as the ResourceFetcher and Document live due to indirect
  // usage.
  Persistent<Document> document;

  Persistent<DummyFrameOwner> owner;
};

class FrameFetchContextSubresourceFilterTest : public FrameFetchContextTest {
 protected:
  void SetUp() override {
    FrameFetchContextTest::SetUp();
    filtered_load_callback_counter_ = 0;
  }

  int GetFilteredLoadCallCount() const {
    return filtered_load_callback_counter_;
  }

  void SetFilterPolicy(WebDocumentSubresourceFilter::LoadPolicy policy,
                       bool is_associated_with_ad_subframe = false) {
    document->Loader()->SetSubresourceFilter(new FixedPolicySubresourceFilter(
        policy, &filtered_load_callback_counter_,
        is_associated_with_ad_subframe));
  }

  std::optional<ResourceRequestBlockedReason> CanRequest() {
    return CanRequestInternal(ReportingDisposition::kReport);
  }

  std::optional<ResourceRequestBlockedReason> CanRequestKeepAlive() {
    return CanRequestInternal(ReportingDisposition::kReport,
                              true /* keepalive */);
  }

  std::optional<ResourceRequestBlockedReason> CanRequestPreload() {
    return CanRequestInternal(ReportingDisposition::kSuppressReporting);
  }

  std::optional<ResourceRequestBlockedReason> CanRequestAndVerifyIsAd(
      bool expect_is_ad) {
    std::optional<ResourceRequestBlockedReason> reason =
        CanRequestInternal(ReportingDisposition::kReport);
    ResourceRequest request(KURL("http://example.com/"));
    FetchInitiatorInfo initiator_info;
    EXPECT_EQ(expect_is_ad, GetFetchContext()->CalculateIfAdSubresource(
                                request, std::nullopt /* alias_url */,
                                ResourceType::kMock, initiator_info));
    return reason;
  }

 private:
  std::optional<ResourceRequestBlockedReason> CanRequestInternal(
      ReportingDisposition reporting_disposition,
      bool keepalive = false) {
    const KURL input_url("http://example.com/");
    ResourceRequest resource_request(input_url);
    resource_request.SetKeepalive(keepalive);
    resource_request.SetRequestorOrigin(document->Fetcher()
                                            ->GetProperties()
                                            .GetFetchClientSettingsObject()
                                            .GetSecurityOrigin());
    ResourceLoaderOptions options(nullptr /* world */);
    // DJKim
    return GetFetchContext()->CanRequest(ResourceType::kImage, resource_request,
                                         input_url, options,
                                         reporting_disposition, std::nullopt);
  }

  int filtered_load_callback_counter_;
};

// This test class sets up a mock frame loader client.
class FrameFetchContextMockedLocalFrameClientTest
    : public FrameFetchContextTest {
 protected:
  void SetUp() override {
    url = KURL("https://example.test/foo");
    http_url = KURL("http://example.test/foo");
    main_resource_url = KURL("https://example.test");
    different_host_url = KURL("https://different.example.test/foo");
    client = MakeGarbageCollected<
        testing::NiceMock<FrameFetchContextMockLocalFrameClient>>();
    dummy_page_holder =
        std::make_unique<DummyPageHolder>(gfx::Size(500, 500), nullptr, client);
    Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
    document = &dummy_page_holder->GetDocument();
    document->SetURL(main_resource_url);
    owner = MakeGarbageCollected<DummyFrameOwner>();
  }

  KURL url;
  KURL http_url;
  KURL main_resource_url;
  KURL different_host_url;

  Persistent<testing::NiceMock<FrameFetchContextMockLocalFrameClient>> client;
};

class FrameFetchContextModifyRequestTest : public FrameFetchContextTest {
 public:
  FrameFetchContextModifyRequestTest()
      : example_origin(SecurityOrigin::Create(KURL("https://example.test/"))) {}

 protected:
  void ModifyRequestForCSP(ResourceRequest& resource_request,
                           mojom::RequestContextFrameType frame_type) {
    document->GetFrame()->Loader().ModifyRequestForCSP(
        resource_request,
        &document->Fetcher()->GetProperties().GetFetchClientSettingsObject(),
        document->domWindow(), frame_type);
  }

  void ExpectUpgrade(const char* input, const char* expected) {
    ExpectUpgrade(input, mojom::blink::RequestContextType::SCRIPT,
                  mojom::RequestContextFrameType::kNone, expected);
  }

  void ExpectUpgrade(const char* input,
                     mojom::blink::RequestContextType request_context,
                     mojom::RequestContextFrameType frame_type,
                     const char* expected) {
    const KURL input_url(input);
    const KURL expected_url(expected);

    ResourceRequest resource_request(input_url);
    resource_request.SetRequestContext(request_context);

    ModifyRequestForCSP(resource_request, frame_type);

    EXPECT_EQ(expected_url.GetString(), resource_request.Url().GetString());
    EXPECT_EQ(expected_url.Protocol(), resource_request.Url().Protocol());
    EXPECT_EQ(expected_url.Host(), resource_request.Url().Host());
    EXPECT_EQ(expected_url.Port(), resource_request.Url().Port());
    EXPECT_EQ(expected_url.HasPort(), resource_request.Url().HasPort());
    EXPECT_EQ(expected_url.GetPath(), resource_request.Url().GetPath());
  }

  void ExpectUpgradeInsecureRequestHeader(
      const char* input,
      mojom::RequestContextFrameType frame_type,
      bool should_prefer) {
    const KURL input_url(input);

    ResourceRequest resource_request(input_url);
    resource_request.SetRequestContext(
        mojom::blink::RequestContextType::SCRIPT);

    ModifyRequestForCSP(resource_request, frame_type);

    EXPECT_EQ(
        should_prefer ? String("1") : String(),
        resource_request.HttpHeaderField(http_names::kUpgradeInsecureRequests));

    // Calling modifyRequestForCSP more than once shouldn't affect the
    // header.
    if (should_prefer) {
      GetFetchContext()->ModifyRequestForCSP(resource_request);
      EXPECT_EQ("1", resource_request.HttpHeaderField(
                         http_names::kUpgradeInsecureRequests));
    }
  }

  void ExpectIsAutomaticUpgradeSet(const char* input,
                                   const char* main_frame,
                                   mojom::blink::InsecureRequestPolicy policy,
                                   bool expected_value) {
    const KURL input_url(input);
    const KURL main_frame_url(main_frame);
    ResourceRequest resource_request(input_url);
    // TODO(crbug.com/1026464, carlosil): Default behavior currently is to not
    // autoupgrade images, setting the context to AUDIO to ensure the upgrade
    // flow runs, this can be switched back to IMAGE once autoupgrades launch
    // for them.
    resource_request.SetRequestContext(mojom::blink::RequestContextType::AUDIO);

    RecreateFetchContext(main_frame_url);
    document->domWindow()->GetSecurityContext().SetInsecureRequestPolicy(
        policy);

    ModifyRequestForCSP(resource_request,
                        mojom::RequestContextFrameType::kNone);

    EXPECT_EQ(expected_value, resource_request.IsAutomaticUpgrade());
  }

  void SetFrameOwnerBasedOnFrameType(mojom::RequestContextFrameType frame_type,
                                     HTMLIFrameElement* iframe,
                                     const AtomicString& potential_value) {
    if (frame_type != mojom::RequestContextFrameType::kNested) {
      document->GetFrame()->SetOwner(nullptr);
      return;
    }

    iframe->setAttribute(html_names::kCspAttr, potential_value);
    document->GetFrame()->SetOwner(iframe);
  }

  scoped_refptr<const SecurityOrigin> example_origin;
};

TEST_F(FrameFetchContextModifyRequestTest, UpgradeInsecureResourceRequests) {
  struct TestCase {
    const char* original;
    const char* upgraded;
  } tests[] = {
      {"http://example.test/image.png", "https://example.test/image.png"},
      {"http://example.test:80/image.png",
       "https://example.test:443/image.png"},
      {"http://example.test:1212/image.png",
       "https://example.test:1212/image.png"},

      {"https://example.test/image.png", "https://example.test/image.png"},
      {"https://example.test:80/image.png",
       "https://example.test:80/image.png"},
      {"https://example.test:1212/image.png",
       "https://example.test:1212/image.png"},

      {"ftp://example.test/image.png", "ftp://example.test/image.png"},
      {"ftp://example.test:21/image.png", "ftp://example.test:21/image.png"},
      {"ftp://example.test:1212/image.png",
       "ftp://example.test:1212/image.png"},
  };

  document->domWindow()->GetSecurityContext().SetInsecureRequestPolicy(
      mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests);

  for (const auto& test : tests) {
    document->domWindow()
        ->GetSecurityContext()
        .ClearInsecureNavigationsToUpgradeForTest();

    // We always upgrade for FrameTypeNone.
    ExpectUpgrade(test.original, mojom::blink::RequestContextType::SCRIPT,
                  mojom::RequestContextFrameType::kNone, test.upgraded);

    // We never upgrade for FrameTypeNested. This is done on the browser
    // process.
    ExpectUpgrade(test.original, mojom::blink::RequestContextType::SCRIPT,
                  mojom::RequestContextFrameType::kNested, test.original);

    // We do not upgrade for FrameTypeTopLevel or FrameTypeAuxiliary...
    ExpectUpgrade(test.original, mojom::blink::RequestContextType::SCRIPT,
                  mojom::RequestContextFrameType::kTopLevel, test.original);
    ExpectUpgrade(test.original, mojom::blink::RequestContextType::SCRIPT,
                  mojom::RequestContextFrameType::kAuxiliary, test.original);

    // unless the request context is RequestContextForm.
    ExpectUpgrade(test.original, mojom::blink::RequestContextType::FORM,
                  mojom::RequestContextFrameType::kTopLevel, test.upgraded);
    ExpectUpgrade(test.original, mojom::blink::RequestContextType::FORM,
                  mojom::RequestContextFrameType::kAuxiliary, test.upgraded);

    // Or unless the host of the resource is in the document's
    // InsecureNavigationsSet:
    document->domWindow()->GetSecurityContext().AddInsecureNavigationUpgrade(
        example_origin->Host().Impl()->GetHash());
    ExpectUpgrade(test.original, mojom::blink::RequestContextType::SCRIPT,
                  mojom::RequestContextFrameType::kTopLevel, test.upgraded);
    ExpectUpgrade(test.original, mojom::blink::RequestContextType::SCRIPT,
                  mojom::RequestContextFrameType::kAuxiliary, test.upgraded);
  }
}

TEST_F(FrameFetchContextModifyRequestTest,
       DoNotUpgradeInsecureResourceRequests) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(blink::features::kMixedContentAutoupgrade);

  RecreateFetchContext(KURL("https://secureorigin.test/image.png"));
  document->domWindow()->GetSecurityContext().SetInsecureRequestPolicy(
      mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone);

  ExpectUpgrade("http://example.test/image.png",
                "http://example.test/image.png");
  ExpectUpgrade("http://example.test:80/image.png",
                "http://example.test:80/image.png");
  ExpectUpgrade("http://example.test:1212/image.png",
                "http://example.test:1212/image.png");

  ExpectUpgrade("https://example.test/image.png",
                "https://example.test/image.png");
  ExpectUpgrade("https://example.test:80/image.png",
                "https://example.test:80/image.png");
  ExpectUpgrade("https://example.test:1212/image.png",
                "https://example.test:1212/image.png");

  ExpectUpgrade("ftp://example.test/image.png", "ftp://example.test/image.png");
  ExpectUpgrade("ftp://example.test:21/image.png",
                "ftp://example.test:21/image.png");
  ExpectUpgrade("ftp://example.test:1212/image.png",
                "ftp://example.test:1212/image.png");
}

TEST_F(FrameFetchContextModifyRequestTest, IsAutomaticUpgradeSet) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(features::kMixedContentAutoupgrade);
  ExpectIsAutomaticUpgradeSet(
      "http://example.test/image.png", "https://example.test",
      mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone, true);
}

TEST_F(FrameFetchContextModifyRequestTest, IsAutomaticUpgradeNotSet) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(features::kMixedContentAutoupgrade);
  // Upgrade shouldn't happen if the resource is already https.
  ExpectIsAutomaticUpgradeSet(
      "https://example.test/image.png", "https://example.test",
      mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone, false);
  // Upgrade shouldn't happen if the site is http.
  ExpectIsAutomaticUpgradeSet(
      "http://example.test/image.png", "http://example.test",
      mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone, false);

  // Flag shouldn't be set if upgrade was due to upgrade-insecure-requests.
  ExpectIsAutomaticUpgradeSet(
      "http://example.test/image.png", "https://example.test",
      mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests, false);
}

TEST_F(FrameFetchContextModifyRequestTest, SendUpgradeInsecureRequestHeader) {
  struct TestCase {
    const char* to_request;
    mojom::RequestContextFrameType frame_type;
    bool should_prefer;
  } tests[] = {{"http://example.test/page.html",
                mojom::RequestContextFrameType::kAuxiliary, true},
               {"http://example.test/page.html",
                mojom::RequestContextFrameType::kNested, true},
               {"http://example.test/page.html",
                mojom::RequestContextFrameType::kNone, false},
               {"http://example.test/page.html",
                mojom::RequestContextFrameType::kTopLevel, true},
               {"https://example.test/page.html",
                mojom::RequestContextFrameType::kAuxiliary, true},
               {"https://example.test/page.html",
                mojom::RequestContextFrameType::kNested, true},
               {"https://example.test/page.html",
                mojom::RequestContextFrameType::kNone, false},
               {"https://example.test/page.html",
                mojom::RequestContextFrameType::kTopLevel, true}};

  // This should work correctly both when the FrameFetchContext has a Document,
  // and when it doesn't (e.g. during main frame navigations), so run through
  // the tests both before and after providing a document to the context.
  for (const auto& test : tests) {
    document->domWindow()->GetSecurityContext().SetInsecureRequestPolicy(
        mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone);
    ExpectUpgradeInsecureRequestHeader(test.to_request, test.frame_type,
                                       test.should_prefer);

    document->domWindow()->GetSecurityContext().SetInsecureRequestPolicy(
        mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests);
    ExpectUpgradeInsecureRequestHeader(test.to_request, test.frame_type,
                                       test.should_prefer);
  }

  for (const auto& test : tests) {
    document->domWindow()->GetSecurityContext().SetInsecureRequestPolicy(
        mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone);
    ExpectUpgradeInsecureRequestHeader(test.to_request, test.frame_type,
                                       test.should_prefer);

    document->domWindow()->GetSecurityContext().SetInsecureRequestPolicy(
        mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests);
    ExpectUpgradeInsecureRequestHeader(test.to_request, test.frame_type,
                                       test.should_prefer);
  }
}

class FrameFetchContextHintsTest : public FrameFetchContextTest,
                                   public testing::WithParamInterface<bool> {
 public:
  FrameFetchContextHintsTest() {
    std::vector<base::test::FeatureRef> enabled_features = {};
    std::vector<base::test::FeatureRef> disabled_features = {};
    if (GetParam()) {
      enabled_features.push_back(
          blink::features::kQuoteEmptySecChUaStringHeadersConsistently);
    } else {
      disabled_features.push_back(
          blink::features::kQuoteEmptySecChUaStringHeadersConsistently);
    }
    scoped_feature_list_.InitWithFeatures(enabled_features, disabled_features);
  }

  void SetUp() override {
    // Set the document URL to a secure document.
    RecreateFetchContext(KURL("https://www.example.com/"));
    Settings* settings = document->GetSettings();
    settings->SetScriptEnabled(true);
  }

 protected:
  void ExpectHeader(const char* input,
                    const char* header_name,
                    bool is_present,
                    const char* header_value,
                    float width = 0) {
    SCOPED_TRACE(testing::Message() << header_name);

    std::optional<float> resource_width;
    if (width > 0) {
      resource_width = width;
    }

    const KURL input_url(input);
    ResourceRequest resource_request(input_url);

    GetFetchContext()->AddClientHintsIfNecessary(resource_width,
                                                 resource_request);

    String expected = is_present ? String(header_value) : String();
    EXPECT_EQ(expected,
              resource_request.HttpHeaderField(AtomicString(header_name)));
  }

  // Returns the expected value for a header containing an empty string. This
  // should be `""`, but if !kQuoteEmptySecChUaStringHeadersConsistently then
  // it is instead an empty string.
  const char* EmptyString() {
    if (base::FeatureList::IsEnabled(
            blink::features::kQuoteEmptySecChUaStringHeadersConsistently)) {
      return "\"\"";
    } else {
      return "";
    }
  }

  String GetHeaderValue(const char* input, const char* header_name) {
    const KURL input_url(input);
    ResourceRequest resource_request(input_url);
    GetFetchContext()->AddClientHintsIfNecessary(
        std::nullopt /* resource_width */, resource_request);
    return resource_request.HttpHeaderField(AtomicString(header_name));
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         FrameFetchContextHintsTest,
                         testing::ValuesIn({false, true}));
// Verify that the client hints should be attached for subresources fetched
// over secure transport. Tests when the persistent client hint feature is
// enabled.
TEST_P(FrameFetchContextHintsTest, MonitorDeviceMemorySecureTransport) {
  ExpectHeader("https://www.example.com/1.gif", "Device-Memory", false, "");
  ClientHintsPreferences preferences;
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kDeviceMemory_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kDeviceMemory);
  document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);
  ApproximatedDeviceMemory::SetPhysicalMemoryMBForTesting(4096);
  ExpectHeader("https://www.example.com/1.gif", "Device-Memory", true, "4");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Device-Memory", true,
               "4");
  ExpectHeader("https://www.example.com/1.gif", "DPR", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-DPR", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Width", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Width", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Viewport-Width", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Viewport-Width", false,
               "");
  ExpectHeader("https://www.someother-example.com/1.gif", "Device-Memory",
               false, "");
  ExpectHeader("https://www.someother-example.com/1.gif",
               "Sec-CH-Device-Memory", false, "");
}

// Verify that client hints are not attached when the resources do not belong to
// a secure context.
TEST_P(FrameFetchContextHintsTest, MonitorDeviceMemoryHintsInsecureContext) {
  // Verify that client hints are not attached when the resources do not belong
  // to a secure context and the persistent client hint features is enabled.
  ExpectHeader("http://www.example.com/1.gif", "Device-Memory", false, "");
  ClientHintsPreferences preferences;
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kDeviceMemory_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kDeviceMemory);
  document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);
  ApproximatedDeviceMemory::SetPhysicalMemoryMBForTesting(4096);
  ExpectHeader("http://www.example.com/1.gif", "Device-Memory", false, "");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-Device-Memory", false,
               "");
  ExpectHeader("http://www.example.com/1.gif", "DPR", false, "");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-DPR", false, "");
  ExpectHeader("http://www.example.com/1.gif", "Width", false, "");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-Width", false, "");
  ExpectHeader("http://www.example.com/1.gif", "Viewport-Width", false, "");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-Viewport-Width", false,
               "");
}

// Verify that client hints are attched when the resources belong to a local
// context.
TEST_P(FrameFetchContextHintsTest, MonitorDeviceMemoryHintsLocalContext) {
  RecreateFetchContext(KURL("http://localhost/"));
  document->GetSettings()->SetScriptEnabled(true);
  ExpectHeader("http://localhost/1.gif", "Device-Memory", false, "");
  ClientHintsPreferences preferences;
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kDeviceMemory_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kDeviceMemory);
  document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);
  ApproximatedDeviceMemory::SetPhysicalMemoryMBForTesting(4096);
  ExpectHeader("http://localhost/1.gif", "Device-Memory", true, "4");
  ExpectHeader("http://localhost/1.gif", "Sec-CH-Device-Memory", true, "4");
  ExpectHeader("http://localhost/1.gif", "DPR", false, "");
  ExpectHeader("http://localhost/1.gif", "Sec-CH-DPR", false, "");
  ExpectHeader("http://localhost/1.gif", "Width", false, "");
  ExpectHeader("http://localhost/1.gif", "Sec-CH-Width", false, "");
  ExpectHeader("http://localhost/1.gif", "Viewport-Width", false, "");
  ExpectHeader("http://localhost/1.gif", "Sec-CH-Viewport-Width", false, "");
}

TEST_P(FrameFetchContextHintsTest, MonitorDeviceMemoryHints) {
  ExpectHeader("https://www.example.com/1.gif", "Device-Memory", false, "");
  ClientHintsPreferences preferences;
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kDeviceMemory_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kDeviceMemory);
  document->GetFrame()->GetClientHintsPreferences().U
"""


```