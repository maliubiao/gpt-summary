Response:
The user is asking for a summary of the functionality of the provided C++ code file `link_loader_test.cc`. This file appears to be a unit test file for the `LinkLoader` class in the Chromium Blink rendering engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Subject:** The filename `link_loader_test.cc` and the inclusion of `#include "third_party/blink/renderer/core/loader/link_loader.h"` strongly indicate that this file is testing the `LinkLoader` class.

2. **Recognize the Testing Framework:** The presence of `#include "testing/gtest/include/gtest/gtest.h"` confirms that Google Test is being used for unit testing.

3. **Analyze Included Headers:** The other included headers provide clues about the functionalities being tested:
    * `base/task/single_thread_task_runner.h`, `base/test/scoped_feature_list.h`, `base/test/test_mock_time_task_runner.h`: Indicate testing of asynchronous operations, feature flags, and time-related logic.
    * `third_party/blink/public/common/features.h`, `third_party/blink/public/common/loader/referrer_utils.h`, `third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h`, `third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h`, `third_party/blink/public/platform/web_prescient_networking.h`:  Suggest testing of fetch requests, referrer policies, scheduler interactions, and network hinting (prefetch, preconnect).
    * Headers in `renderer/core/`: Point to testing the integration of `LinkLoader` with core rendering components like the DOM (`LocalDOMWindow`, `LocalFrame`), HTML (`LinkRelAttribute`), loading process (`DocumentLoader`), and security (`ContentSecurityPolicy`).
    * Headers in `renderer/platform/`: Highlight testing platform-specific aspects like memory cache, resource fetching, and threading.
    * Headers in `renderer/core/testing/`: Indicate the use of test utilities like `DummyPageHolder` and `SimTest`.

4. **Examine Test Fixtures and Test Cases:**  The code defines several test fixtures (classes inheriting from `testing::Test` or `LinkLoaderPreloadTestBase`) and numerous test cases (functions starting with `TEST_`). This is where the specific functionalities being tested are implemented. The names of the test cases and fixtures are very informative:
    * `LinkLoaderPreloadTest`:  Focuses on testing the "preload" link relation.
    * `LinkLoaderPreloadMimeTypeTest`: Tests preloading with specific MIME types.
    * `LinkLoaderPreloadMediaTest`:  Tests preloading based on media queries.
    * `LinkLoaderPreloadReferrerPolicyTest`: Tests the handling of referrer policies in preloads.
    * `LinkLoaderPreloadNonceTest`: Tests preloads with Content Security Policy nonces.
    * `LinkLoaderPreloadImageSrcsetTest`: Tests preloads with `srcset` and `sizes` attributes for images.
    * `LinkLoaderModulePreloadTest`: Specifically tests the "modulepreload" link relation for JavaScript modules.
    * `LinkLoaderTestPrefetchPrivacyChanges`: Tests how privacy changes affect "prefetch".
    * `LinkLoaderTest`: Covers general `LinkLoader` functionality, including "prefetch", "dns-prefetch", and "preconnect".

5. **Identify Mock Objects:** The presence of `MockLinkLoaderClient` and `NetworkHintsMock` indicates the use of mock objects to isolate and control the behavior of dependencies during testing. This helps in verifying specific interactions.

6. **Infer Functionality from Test Case Logic:**  By looking at the parameters and assertions within the test cases, it's possible to infer what aspects of `LinkLoader` are being verified. For example, the `PreloadTestParams` structure clearly shows testing different `as` values and their impact on resource loading priority and context.

7. **Relate to Web Technologies:**  The "preload", "prefetch", "dns-prefetch", "preconnect", and "modulepreload" link relations are all directly related to HTML and web performance. The tests involving MIME types, media queries, `srcset`, `sizes`, and CSP nonces further solidify the connection to HTML, CSS, and web security features. JavaScript is involved through the testing of "modulepreload".

8. **Consider User/Developer Errors:** Test cases that check for unresolved priorities or non-loading scenarios often implicitly cover cases where developers might make mistakes in specifying the `as` attribute or MIME types.

9. **Trace User Operations (Debugging Clues):** While the test file itself doesn't directly show user interaction, it tests the code that *responds* to HTML link elements. So, a user adding a `<link rel="preload" ...>` tag to their HTML would eventually trigger the code being tested here. Debugging would involve stepping through the parsing of this tag and how it leads to the `LinkLoader` being invoked.

10. **Synthesize a Summary:** Based on the above analysis, the core functionality of the test file is to verify the correct behavior of the `LinkLoader` class, specifically focusing on how it handles various link relations to optimize resource loading and improve page performance.

Following these steps leads to the detailed and accurate summary provided in the initial good answer.
这是对 Chromium Blink 引擎中 `blink/renderer/core/loader/link_loader_test.cc` 文件（第一部分）的功能的归纳总结。

**功能归纳：**

该文件是 `LinkLoader` 类的单元测试文件。`LinkLoader` 负责处理 HTML 中 `<link>` 标签的各种 `rel` 属性，例如 `preload`、`prefetch`、`dns-prefetch` 和 `preconnect`。  这个测试文件的主要目的是验证 `LinkLoader` 在不同场景下是否按照预期的方式工作，包括：

* **预加载 (Preload):**  测试 `LinkLoader` 如何处理 `rel="preload"` 的链接，包括：
    * **资源优先级 (Resource Priority):** 验证根据 `as` 属性（例如 "image"、"script"、"style"）设置正确的资源加载优先级。
    * **请求上下文 (Request Context):** 验证根据 `as` 属性设置正确的请求上下文类型（例如 `IMAGE`、`SCRIPT`、`STYLE`）。
    * **MIME 类型 (MIME Type):**  验证 `type` 属性是否影响资源的预加载。如果 `type` 与 `as` 不匹配，是否会阻止预加载。
    * **媒体查询 (Media Queries):** 验证 `media` 属性是否影响资源的预加载，只有当媒体查询匹配时才预加载。
    * **Referrer Policy:** 验证 `referrerpolicy` 属性是否正确地应用到预加载请求中。
    * **Nonce (CSP):** 验证 `nonce` 属性是否按照内容安全策略 (CSP) 的要求工作，只有当 nonce 值匹配时才预加载。
    * **srcset 和 sizes (响应式图片):** 验证 `srcset` 和 `sizes` 属性是否正确地解析并选择合适的图片 URL 进行预加载。
* **模块预加载 (Module Preload):** 测试 `rel="modulepreload"` 的链接，用于预加载 JavaScript 模块。验证请求的各种参数，如 `nonce`、`integrity`、`crossorigin` 和 `referrerpolicy`。
* **预取 (Prefetch):** 测试 `rel="prefetch"` 的链接，验证其基本功能和 `referrerpolicy` 的应用。同时测试了“预取隐私更改”功能是否按预期影响预取请求的行为（例如，设置 `redirectMode` 和 `referrerPolicy`）。
* **DNS 预解析 (DNS Prefetch):** 测试 `rel="dns-prefetch"` 的链接，验证是否触发了 DNS 预解析。
* **预连接 (Preconnect):** 测试 `rel="preconnect"` 的链接，验证是否触发了与指定域名的预连接，并验证 `crossorigin` 属性的影响。

**与 Javascript, HTML, CSS 的关系：**

* **HTML:**  `LinkLoader` 的核心功能是处理 HTML 中的 `<link>` 标签。测试用例模拟了各种 `<link>` 标签的属性组合，例如 `rel="preload" as="image" href="cat.jpg"`。
    * **举例:**  当 HTML 中存在 `<link rel="preload" href="style.css" as="style">` 时，测试会验证 `LinkLoader` 是否会以高优先级加载 `style.css`。
* **CSS:**  `rel="preload"` 可以用于预加载 CSS 样式表，提高页面渲染速度。测试用例中包含了验证预加载 CSS 的场景。
    * **举例:**  测试用例会验证当 `<link rel="preload" href="style.css" as="style">` 存在时，`LinkLoader` 创建的资源请求的 `RequestContextType` 是否为 `STYLE`。
* **Javascript:** `rel="preload"` 可以用于预加载 Javascript 文件，而 `rel="modulepreload"` 则专门用于预加载 Javascript 模块。测试用例会验证这两种场景。
    * **举例:**  当 HTML 中存在 `<link rel="preload" href="script.js" as="script">` 时，测试会验证 `LinkLoader` 创建的资源请求的 `RequestContextType` 是否为 `SCRIPT`。对于 `<link rel="modulepreload" href="module.js">`，测试会验证模块加载请求的参数是否正确设置。

**逻辑推理 (假设输入与输出):**

* **假设输入:** 一个包含 `<link rel="preload" href="image.png" as="image">` 的 HTML 文档被加载。
* **输出:**  `LinkLoader` 会创建一个资源请求，该请求的 URL 为 `image.png`，优先级为低优先级（图像的默认优先级），请求上下文类型为 `IMAGE`。资源加载器会将此请求添加到预加载队列中。

* **假设输入:** 一个包含 `<link rel="preload" href="script.js" as="script" type="text/javascript">` 的 HTML 文档被加载。
* **输出:** `LinkLoader` 会创建一个资源请求，该请求的 URL 为 `script.js`，优先级为高优先级（脚本的默认优先级），请求上下文类型为 `SCRIPT`。

* **假设输入:** 一个包含 `<link rel="preload" href="style.css" as="style" type="text/sass">` 的 HTML 文档被加载。
* **输出:** 由于 `type` 属性 "text/sass" 与 `as` 属性 "style" 不匹配，`LinkLoader` 不会发起预加载请求（优先级为 `kUnresolved`）。

**用户或编程常见的使用错误举例:**

* **`as` 属性使用错误:**  开发者可能会错误地使用 `as` 属性，例如 `<link rel="preload" href="font.woff" as="image">`。这将导致资源以错误的优先级和上下文加载，甚至可能加载失败。测试用例会验证这种情况是否会导致预加载失败。
* **MIME 类型不匹配:**  开发者可能指定了错误的 `type` 属性，导致浏览器无法识别资源类型，例如 `<link rel="preload" href="script.js" as="script" type="text/coffeescript">`。测试用例会验证这种情况是否会阻止预加载。
* **媒体查询错误:**  开发者可能编写了永远不会匹配的媒体查询，导致资源永远不会被预加载。例如 `<link rel="preload" href="image.png" as="image" media="(width: 0px)">`。测试用例会验证这种情况。
* **CSP nonce 错误:** 当使用了内容安全策略时，如果 `<link>` 标签上的 `nonce` 属性与 CSP 策略中的不匹配，资源将不会被加载。测试用例会模拟这种情况。

**用户操作到达这里的调试线索:**

1. **用户在浏览器地址栏输入 URL 并访问一个网页。**
2. **浏览器开始解析 HTML 文档。**
3. **当解析器遇到 `<link>` 标签时，会创建对应的 DOM 元素。**
4. **`LinkLoader` 类会被调用来处理这些 `<link>` 标签，特别是当 `rel` 属性为 `preload`、`prefetch`、`dns-prefetch` 或 `preconnect` 时。**
5. **`LinkLoader` 会根据标签的属性（如 `href`、`as`、`type`、`media`、`referrerpolicy`、`nonce` 等）决定是否发起资源加载或执行相应的操作（如 DNS 预解析或预连接）。**

作为调试线索，如果你怀疑预加载、预取或连接功能有问题，你可以：

* **检查 HTML 源代码:** 查看 `<link>` 标签的属性是否正确设置。
* **使用浏览器的开发者工具:**
    * **Network 面板:** 观察资源的加载优先级、请求头（例如 Referer Policy）和加载时序。
    * **Application 面板:**  查看预加载的资源是否在预加载缓存中。
    * **Console 面板:**  查看是否有与资源加载相关的错误或警告信息（例如 CSP 错误）。
* **断点调试 Blink 渲染引擎的代码:**  在 `blink/renderer/core/loader/link_loader.cc` 或相关的代码中设置断点，跟踪 `LinkLoader` 的执行流程，查看它如何处理特定的 `<link>` 标签。

总而言之，`link_loader_test.cc` 的第一部分全面地测试了 `LinkLoader` 类的核心功能，特别是关于资源预加载的各种场景和属性组合，确保 Blink 引擎能够正确地利用这些技术来优化网页加载性能和安全性。

### 提示词
```
这是目录为blink/renderer/core/loader/link_loader_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/link_loader.h"

#include <memory>

#include "base/task/single_thread_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/test_mock_time_task_runner.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_prescient_networking.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/link_rel_attribute.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/link_loader_client.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_fetch_request.h"
#include "third_party/blink/renderer/core/loader/pending_link_preload.h"
#include "third_party/blink/renderer/core/loader/resource/link_dictionary_resource.h"
#include "third_party/blink/renderer/core/testing/dummy_modulator.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/scoped_mock_overlay_scrollbars.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_priority.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

namespace blink {

namespace {

class MockLinkLoaderClient final
    : public GarbageCollected<MockLinkLoaderClient>,
      public LinkLoaderClient {
 public:
  explicit MockLinkLoaderClient(bool should_load) : should_load_(should_load) {}

  void Trace(Visitor* visitor) const override {
    LinkLoaderClient::Trace(visitor);
  }

  bool ShouldLoadLink() override { return should_load_; }
  bool IsLinkCreatedByParser() override { return true; }

  void LinkLoaded() override {}
  void LinkLoadingErrored() override {}

 private:
  const bool should_load_;
};

class NetworkHintsMock : public WebPrescientNetworking {
 public:
  NetworkHintsMock() = default;

  void PrefetchDNS(const WebURL& url) override { did_dns_prefetch_ = true; }
  void Preconnect(const WebURL& url, bool allow_credentials) override {
    did_preconnect_ = true;
    is_https_ = url.ProtocolIs("https");
    allow_credentials_ = allow_credentials;
  }

  bool DidDnsPrefetch() { return did_dns_prefetch_; }
  bool DidPreconnect() { return did_preconnect_; }
  bool IsHTTPS() { return is_https_; }
  bool AllowCredentials() { return allow_credentials_; }

 private:
  mutable bool did_dns_prefetch_ = false;
  mutable bool did_preconnect_ = false;
  mutable bool is_https_ = false;
  mutable bool allow_credentials_ = false;
};

class LinkLoaderPreloadTestBase : public testing::Test,
                                  private ScopedMockOverlayScrollbars {
 public:
  struct Expectations {
    ResourceLoadPriority priority;
    mojom::blink::RequestContextType context;
    bool link_loader_should_load_value;
    KURL load_url;
    network::mojom::ReferrerPolicy referrer_policy;
  };

  LinkLoaderPreloadTestBase() {
    dummy_page_holder_ = std::make_unique<DummyPageHolder>(gfx::Size(500, 500));
  }

  ~LinkLoaderPreloadTestBase() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

 protected:
  void TestPreload(const LinkLoadParameters& params,
                   const Expectations& expected) {
    ResourceFetcher* fetcher = dummy_page_holder_->GetDocument().Fetcher();
    ASSERT_TRUE(fetcher);
    dummy_page_holder_->GetFrame().GetSettings()->SetScriptEnabled(true);
    Persistent<MockLinkLoaderClient> loader_client =
        MakeGarbageCollected<MockLinkLoaderClient>(
            expected.link_loader_should_load_value);
    auto* loader = MakeGarbageCollected<LinkLoader>(loader_client.Get());
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |dummy_page_holder_|.
    url_test_helpers::RegisterMockedErrorURLLoad(params.href);
    loader->LoadLink(params, dummy_page_holder_->GetDocument());
    if (!expected.load_url.IsNull() &&
        expected.priority != ResourceLoadPriority::kUnresolved) {
      ASSERT_EQ(1, fetcher->CountPreloads());
      Resource* resource = loader->GetResourceForTesting();
      ASSERT_NE(resource, nullptr);
      EXPECT_EQ(expected.load_url.GetString(), resource->Url().GetString());
      EXPECT_TRUE(fetcher->ContainsAsPreload(resource));
      EXPECT_EQ(expected.priority, resource->GetResourceRequest().Priority());
      EXPECT_EQ(expected.context,
                resource->GetResourceRequest().GetRequestContext());
      if (expected.referrer_policy !=
          network::mojom::ReferrerPolicy::kDefault) {
        EXPECT_EQ(expected.referrer_policy,
                  resource->GetResourceRequest().GetReferrerPolicy());
      }
    } else {
      ASSERT_EQ(0, fetcher->CountPreloads());
    }
  }

  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> dummy_page_holder_;
};

struct PreloadTestParams {
  const char* href;
  const char* as;
  const ResourceLoadPriority priority;
  const mojom::blink::RequestContextType context;
  const bool expecting_load;
};

constexpr PreloadTestParams kPreloadTestParams[] = {
    {"http://example.test/cat.jpg", "image", ResourceLoadPriority::kLow,
     mojom::blink::RequestContextType::IMAGE, true},
    {"http://example.test/cat.js", "script", ResourceLoadPriority::kHigh,
     mojom::blink::RequestContextType::SCRIPT, true},
    {"http://example.test/cat.css", "style", ResourceLoadPriority::kVeryHigh,
     mojom::blink::RequestContextType::STYLE, true},
    // TODO(yoav): It doesn't seem like the audio context is ever used. That
    // should probably be fixed (or we can consolidate audio and video).
    //
    // Until the preload cache is defined in terms of range requests and media
    // fetches we can't reliably preload audio/video content and expect it to be
    // served from the cache correctly. Until
    // https://github.com/w3c/preload/issues/97 is resolved and implemented we
    // need to disable these preloads.
    {"http://example.test/cat.wav", "audio", ResourceLoadPriority::kLow,
     mojom::blink::RequestContextType::AUDIO, false},
    {"http://example.test/cat.mp4", "video", ResourceLoadPriority::kLow,
     mojom::blink::RequestContextType::VIDEO, false},
    {"http://example.test/cat.vtt", "track", ResourceLoadPriority::kLow,
     mojom::blink::RequestContextType::TRACK, true},
    {"http://example.test/cat.woff", "font", ResourceLoadPriority::kHigh,
     mojom::blink::RequestContextType::FONT, true},
    // TODO(yoav): subresource should be *very* low priority (rather than
    // low).
    {"http://example.test/cat.empty", "fetch", ResourceLoadPriority::kHigh,
     mojom::blink::RequestContextType::SUBRESOURCE, true},
    {"http://example.test/cat.blob", "blabla", ResourceLoadPriority::kLow,
     mojom::blink::RequestContextType::SUBRESOURCE, false},
    {"http://example.test/cat.blob", "", ResourceLoadPriority::kLow,
     mojom::blink::RequestContextType::SUBRESOURCE, false},
    {"bla://example.test/cat.gif", "image", ResourceLoadPriority::kUnresolved,
     mojom::blink::RequestContextType::IMAGE, false}};

class LinkLoaderPreloadTest
    : public LinkLoaderPreloadTestBase,
      public testing::WithParamInterface<PreloadTestParams> {};

TEST_P(LinkLoaderPreloadTest, Preload) {
  const auto& test_case = GetParam();
  LinkLoadParameters params(
      LinkRelAttribute("preload"), kCrossOriginAttributeNotSet, String(),
      test_case.as, String(), String(), String(), String(),
      network::mojom::ReferrerPolicy::kDefault, KURL(NullURL(), test_case.href),
      String(), String(), String());
  Expectations expectations = {
      test_case.priority, test_case.context, test_case.expecting_load,
      test_case.expecting_load ? params.href : NullURL(),
      network::mojom::ReferrerPolicy::kDefault};
  TestPreload(params, expectations);
}

INSTANTIATE_TEST_SUITE_P(LinkLoaderPreloadTest,
                         LinkLoaderPreloadTest,
                         testing::ValuesIn(kPreloadTestParams));

struct PreloadMimeTypeTestParams {
  const char* href;
  const char* as;
  const char* type;
  const ResourceLoadPriority priority;
  const mojom::blink::RequestContextType context;
  const bool expecting_load;
};

constexpr PreloadMimeTypeTestParams kPreloadMimeTypeTestParams[] = {
    {"http://example.test/cat.webp", "image", "image/webp",
     ResourceLoadPriority::kLow, mojom::blink::RequestContextType::IMAGE, true},
    {"http://example.test/cat.svg", "image", "image/svg+xml",
     ResourceLoadPriority::kLow, mojom::blink::RequestContextType::IMAGE, true},
    {"http://example.test/cat.jxr", "image", "image/jxr",
     ResourceLoadPriority::kUnresolved, mojom::blink::RequestContextType::IMAGE,
     false},
    {"http://example.test/cat.js", "script", "text/javascript",
     ResourceLoadPriority::kHigh, mojom::blink::RequestContextType::SCRIPT,
     true},
    {"http://example.test/cat.js", "script", "text/coffeescript",
     ResourceLoadPriority::kUnresolved,
     mojom::blink::RequestContextType::SCRIPT, false},
    {"http://example.test/cat.css", "style", "text/css",
     ResourceLoadPriority::kVeryHigh, mojom::blink::RequestContextType::STYLE,
     true},
    {"http://example.test/cat.css", "style", "text/sass",
     ResourceLoadPriority::kUnresolved, mojom::blink::RequestContextType::STYLE,
     false},
    // Until the preload cache is defined in terms of range requests and media
    // fetches we can't reliably preload audio/video content and expect it to be
    // served from the cache correctly. Until
    // https://github.com/w3c/preload/issues/97 is resolved and implemented we
    // need to disable these preloads.
    {"http://example.test/cat.wav", "audio", "audio/wav",
     ResourceLoadPriority::kLow, mojom::blink::RequestContextType::AUDIO,
     false},
    {"http://example.test/cat.wav", "audio", "audio/mp57",
     ResourceLoadPriority::kUnresolved, mojom::blink::RequestContextType::AUDIO,
     false},
    {"http://example.test/cat.webm", "video", "video/webm",
     ResourceLoadPriority::kLow, mojom::blink::RequestContextType::VIDEO,
     false},
    {"http://example.test/cat.mp199", "video", "video/mp199",
     ResourceLoadPriority::kUnresolved, mojom::blink::RequestContextType::VIDEO,
     false},
    {"http://example.test/cat.vtt", "track", "text/vtt",
     ResourceLoadPriority::kLow, mojom::blink::RequestContextType::TRACK, true},
    {"http://example.test/cat.vtt", "track", "text/subtitlething",
     ResourceLoadPriority::kUnresolved, mojom::blink::RequestContextType::TRACK,
     false},
    {"http://example.test/cat.woff", "font", "font/woff2",
     ResourceLoadPriority::kHigh, mojom::blink::RequestContextType::FONT, true},
    {"http://example.test/cat.woff", "font", "font/woff84",
     ResourceLoadPriority::kUnresolved, mojom::blink::RequestContextType::FONT,
     false},
    {"http://example.test/cat.empty", "fetch", "foo/bar",
     ResourceLoadPriority::kHigh, mojom::blink::RequestContextType::SUBRESOURCE,
     true},
    {"http://example.test/cat.blob", "blabla", "foo/bar",
     ResourceLoadPriority::kLow, mojom::blink::RequestContextType::SUBRESOURCE,
     false},
    {"http://example.test/cat.blob", "", "foo/bar", ResourceLoadPriority::kLow,
     mojom::blink::RequestContextType::SUBRESOURCE, false}};

class LinkLoaderPreloadMimeTypeTest
    : public LinkLoaderPreloadTestBase,
      public testing::WithParamInterface<PreloadMimeTypeTestParams> {};

TEST_P(LinkLoaderPreloadMimeTypeTest, Preload) {
  const auto& test_case = GetParam();
  LinkLoadParameters params(
      LinkRelAttribute("preload"), kCrossOriginAttributeNotSet, test_case.type,
      test_case.as, String(), String(), String(), String(),
      network::mojom::ReferrerPolicy::kDefault, KURL(NullURL(), test_case.href),
      String(), String(), String());
  Expectations expectations = {
      test_case.priority, test_case.context, test_case.expecting_load,
      test_case.expecting_load ? params.href : NullURL(),
      network::mojom::ReferrerPolicy::kDefault};
  TestPreload(params, expectations);
}

INSTANTIATE_TEST_SUITE_P(LinkLoaderPreloadMimeTypeTest,
                         LinkLoaderPreloadMimeTypeTest,
                         testing::ValuesIn(kPreloadMimeTypeTestParams));

struct PreloadMediaTestParams {
  const char* media;
  const ResourceLoadPriority priority;
  const bool link_loader_should_load_value;
  const bool expecting_load;
};

constexpr PreloadMediaTestParams kPreloadMediaTestParams[] = {
    {"(max-width: 600px)", ResourceLoadPriority::kLow, true, true},
    {"(max-width: 400px)", ResourceLoadPriority::kUnresolved, true, false},
    {"(max-width: 600px)", ResourceLoadPriority::kLow, false, false}};

class LinkLoaderPreloadMediaTest
    : public LinkLoaderPreloadTestBase,
      public testing::WithParamInterface<PreloadMediaTestParams> {};

TEST_P(LinkLoaderPreloadMediaTest, Preload) {
  const auto& test_case = GetParam();
  LinkLoadParameters params(LinkRelAttribute("preload"),
                            kCrossOriginAttributeNotSet, "image/gif", "image",
                            test_case.media, String(), String(), String(),
                            network::mojom::ReferrerPolicy::kDefault,
                            KURL(NullURL(), "http://example.test/cat.gif"),
                            String(), String(), String());
  Expectations expectations = {
      test_case.priority, mojom::blink::RequestContextType::IMAGE,
      test_case.link_loader_should_load_value,
      test_case.expecting_load ? params.href : NullURL(),
      network::mojom::ReferrerPolicy::kDefault};
  TestPreload(params, expectations);
}

INSTANTIATE_TEST_SUITE_P(LinkLoaderPreloadMediaTest,
                         LinkLoaderPreloadMediaTest,
                         testing::ValuesIn(kPreloadMediaTestParams));

constexpr network::mojom::ReferrerPolicy kPreloadReferrerPolicyTestParams[] = {
    network::mojom::ReferrerPolicy::kOrigin,
    network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin,
    network::mojom::ReferrerPolicy::kSameOrigin,
    network::mojom::ReferrerPolicy::kStrictOrigin,
    network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin,
    network::mojom::ReferrerPolicy::kNever};

class LinkLoaderPreloadReferrerPolicyTest
    : public LinkLoaderPreloadTestBase,
      public testing::WithParamInterface<network::mojom::ReferrerPolicy> {};

TEST_P(LinkLoaderPreloadReferrerPolicyTest, Preload) {
  const network::mojom::ReferrerPolicy referrer_policy = GetParam();
  LinkLoadParameters params(
      LinkRelAttribute("preload"), kCrossOriginAttributeNotSet, "image/gif",
      "image", String(), String(), String(), String(), referrer_policy,
      KURL(NullURL(), "http://example.test/cat.gif"), String(), String(),
      String());
  Expectations expectations = {ResourceLoadPriority::kLow,
                               mojom::blink::RequestContextType::IMAGE, true,
                               params.href, referrer_policy};
  TestPreload(params, expectations);
}

INSTANTIATE_TEST_SUITE_P(LinkLoaderPreloadReferrerPolicyTest,
                         LinkLoaderPreloadReferrerPolicyTest,
                         testing::ValuesIn(kPreloadReferrerPolicyTestParams));

struct PreloadNonceTestParams {
  const char* nonce;
  const char* content_security_policy;
  const bool expecting_load;
};

constexpr PreloadNonceTestParams kPreloadNonceTestParams[] = {
    {"abc", "script-src 'nonce-abc'", true},
    {"", "script-src 'nonce-abc'", false},
    {"def", "script-src 'nonce-abc'", false},
};

class LinkLoaderPreloadNonceTest
    : public LinkLoaderPreloadTestBase,
      public testing::WithParamInterface<PreloadNonceTestParams> {};

TEST_P(LinkLoaderPreloadNonceTest, Preload) {
  const auto& test_case = GetParam();
  dummy_page_holder_->GetFrame()
      .DomWindow()
      ->GetContentSecurityPolicy()
      ->AddPolicies(ParseContentSecurityPolicies(
          test_case.content_security_policy,
          network::mojom::ContentSecurityPolicyType::kEnforce,
          network::mojom::ContentSecurityPolicySource::kHTTP,
          *(dummy_page_holder_->GetFrame().DomWindow()->GetSecurityOrigin())));
  LinkLoadParameters params(LinkRelAttribute("preload"),
                            kCrossOriginAttributeNotSet, String(), "script",
                            String(), test_case.nonce, String(), String(),
                            network::mojom::ReferrerPolicy::kDefault,
                            KURL(NullURL(), "http://example.test/cat.js"),
                            String(), String(), String());
  Expectations expectations = {
      ResourceLoadPriority::kHigh, mojom::blink::RequestContextType::SCRIPT,
      test_case.expecting_load,
      test_case.expecting_load ? params.href : NullURL(),
      network::mojom::ReferrerPolicy::kDefault};
  TestPreload(params, expectations);
}

INSTANTIATE_TEST_SUITE_P(LinkLoaderPreloadNonceTest,
                         LinkLoaderPreloadNonceTest,
                         testing::ValuesIn(kPreloadNonceTestParams));

struct PreloadImageSrcsetTestParams {
  const char* href;
  const char* image_srcset;
  const char* image_sizes;
  float scale_factor;
  const char* expected_url;
};

constexpr PreloadImageSrcsetTestParams kPreloadImageSrcsetTestParams[] = {
    {"http://example.test/cat.gif",
     "http://example.test/cat1x.gif 1x, http://example.test/cat2x.gif 2x",
     nullptr, 1.0, "http://example.test/cat1x.gif"},
    {"http://example.test/cat.gif",
     "http://example.test/cat1x.gif 1x, http://example.test/cat2x.gif 2x",
     nullptr, 2.0, "http://example.test/cat2x.gif"},
    {"http://example.test/cat.gif",
     "http://example.test/cat400.gif 400w, http://example.test/cat800.gif 800w",
     "400px", 1.0, "http://example.test/cat400.gif"},
    {"http://example.test/cat.gif",
     "http://example.test/cat400.gif 400w, http://example.test/cat800.gif 800w",
     "400px", 2.0, "http://example.test/cat800.gif"},
    {"http://example.test/cat.gif",
     "cat200.gif 200w, cat400.gif 400w, cat800.gif 800w", "200px", 1.0,
     "http://example.test/cat200.gif"},
};

class LinkLoaderPreloadImageSrcsetTest
    : public LinkLoaderPreloadTestBase,
      public testing::WithParamInterface<PreloadImageSrcsetTestParams> {};

TEST_P(LinkLoaderPreloadImageSrcsetTest, Preload) {
  const auto& test_case = GetParam();
  dummy_page_holder_->GetDocument().SetBaseURLOverride(
      KURL("http://example.test/"));
  dummy_page_holder_->GetDocument().GetFrame()->SetLayoutZoomFactor(
      test_case.scale_factor);
  LinkLoadParameters params(
      LinkRelAttribute("preload"), kCrossOriginAttributeNotSet, "image/gif",
      "image", String(), String(), String(), String(),
      network::mojom::ReferrerPolicy::kDefault, KURL(NullURL(), test_case.href),
      test_case.image_srcset, test_case.image_sizes, String());
  Expectations expectations = {ResourceLoadPriority::kLow,
                               mojom::blink::RequestContextType::IMAGE, true,
                               KURL(NullURL(), test_case.expected_url),
                               network::mojom::ReferrerPolicy::kDefault};
  TestPreload(params, expectations);
}

INSTANTIATE_TEST_SUITE_P(LinkLoaderPreloadImageSrcsetTest,
                         LinkLoaderPreloadImageSrcsetTest,
                         testing::ValuesIn(kPreloadImageSrcsetTestParams));

struct ModulePreloadTestParams {
  const char* href;
  const char* nonce;
  const char* integrity;
  CrossOriginAttributeValue cross_origin;
  network::mojom::ReferrerPolicy referrer_policy;
  bool expecting_load;
  network::mojom::CredentialsMode expected_credentials_mode;
};

constexpr ModulePreloadTestParams kModulePreloadTestParams[] = {
    {"", nullptr, nullptr, kCrossOriginAttributeNotSet,
     network::mojom::ReferrerPolicy::kDefault, false,
     network::mojom::CredentialsMode::kSameOrigin},
    {"http://example.test/cat.js", nullptr, nullptr,
     kCrossOriginAttributeNotSet, network::mojom::ReferrerPolicy::kDefault,
     true, network::mojom::CredentialsMode::kSameOrigin},
    {"http://example.test/cat.js", nullptr, nullptr,
     kCrossOriginAttributeAnonymous, network::mojom::ReferrerPolicy::kDefault,
     true, network::mojom::CredentialsMode::kSameOrigin},
    {"http://example.test/cat.js", "nonce", nullptr,
     kCrossOriginAttributeNotSet, network::mojom::ReferrerPolicy::kNever, true,
     network::mojom::CredentialsMode::kSameOrigin},
    {"http://example.test/cat.js", nullptr, "sha384-abc",
     kCrossOriginAttributeNotSet, network::mojom::ReferrerPolicy::kDefault,
     true, network::mojom::CredentialsMode::kSameOrigin}};

class LinkLoaderModulePreloadTest
    : public testing::TestWithParam<ModulePreloadTestParams>,
      private ScopedMockOverlayScrollbars {
 private:
  test::TaskEnvironment task_environment_;
};

class ModulePreloadTestModulator final : public DummyModulator {
 public:
  ModulePreloadTestModulator(const ModulePreloadTestParams* params)
      : params_(params), fetched_(false) {}

  void FetchSingle(const ModuleScriptFetchRequest& request,
                   ResourceFetcher*,
                   ModuleGraphLevel,
                   ModuleScriptCustomFetchType custom_fetch_type,
                   SingleModuleClient*) override {
    fetched_ = true;

    EXPECT_EQ(KURL(NullURL(), params_->href), request.Url());
    EXPECT_EQ(params_->nonce, request.Options().Nonce());
    EXPECT_EQ(kNotParserInserted, request.Options().ParserState());
    EXPECT_EQ(params_->expected_credentials_mode,
              request.Options().CredentialsMode());
    EXPECT_EQ(Referrer::NoReferrer(), request.ReferrerString());
    EXPECT_EQ(params_->referrer_policy, request.Options().GetReferrerPolicy());
    EXPECT_EQ(params_->integrity,
              request.Options().GetIntegrityAttributeValue());
    EXPECT_EQ(ModuleScriptCustomFetchType::kNone, custom_fetch_type);
  }

  bool fetched() const { return fetched_; }

 private:
  const ModulePreloadTestParams* params_;
  bool fetched_;
};

TEST_P(LinkLoaderModulePreloadTest, ModulePreload) {
  const auto& test_case = GetParam();
  auto dummy_page_holder = std::make_unique<DummyPageHolder>();
  ModulePreloadTestModulator* modulator =
      MakeGarbageCollected<ModulePreloadTestModulator>(&test_case);
  Modulator::SetModulator(
      ToScriptStateForMainWorld(dummy_page_holder->GetDocument().GetFrame()),
      modulator);
  Persistent<MockLinkLoaderClient> loader_client =
      MakeGarbageCollected<MockLinkLoaderClient>(true);
  auto* loader = MakeGarbageCollected<LinkLoader>(loader_client.Get());
  KURL href_url = KURL(NullURL(), test_case.href);
  LinkLoadParameters params(
      LinkRelAttribute("modulepreload"), test_case.cross_origin,
      String() /* type */, String() /* as */, String() /* media */,
      test_case.nonce, test_case.integrity, String(), test_case.referrer_policy,
      href_url, String() /* image_srcset */, String() /* image_sizes */,
      String() /* blocking */);
  loader->LoadLink(params, dummy_page_holder->GetDocument());
  ASSERT_EQ(test_case.expecting_load, modulator->fetched());
}

INSTANTIATE_TEST_SUITE_P(LinkLoaderModulePreloadTest,
                         LinkLoaderModulePreloadTest,
                         testing::ValuesIn(kModulePreloadTestParams));

class LinkLoaderTestPrefetchPrivacyChanges
    : public testing::Test,
      public testing::WithParamInterface<bool>,
      private ScopedMockOverlayScrollbars {
 public:
  LinkLoaderTestPrefetchPrivacyChanges()
      : privacy_changes_enabled_(GetParam()) {}
  void SetUp() override {
    std::vector<base::test::FeatureRef> enable_features;
    std::vector<base::test::FeatureRef> disabled_features;
    if (GetParam()) {
      enable_features.push_back(features::kPrefetchPrivacyChanges);
    } else {
      disabled_features.push_back(features::kPrefetchPrivacyChanges);
    }
    feature_list_.InitWithFeatures(enable_features, disabled_features);
  }

 protected:
  const bool privacy_changes_enabled_;
  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<TestingPlatformSupport> platform_;

 private:
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(LinkLoaderTestPrefetchPrivacyChanges,
                         LinkLoaderTestPrefetchPrivacyChanges,
                         testing::Values(false, true));

TEST_P(LinkLoaderTestPrefetchPrivacyChanges, PrefetchPrivacyChanges) {
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(500, 500));
  dummy_page_holder->GetFrame().GetSettings()->SetScriptEnabled(true);
  Persistent<MockLinkLoaderClient> loader_client =
      MakeGarbageCollected<MockLinkLoaderClient>(true);
  auto* loader = MakeGarbageCollected<LinkLoader>(loader_client.Get());
  KURL href_url = KURL(NullURL(), "http://example.test/cat.jpg");
  // TODO(crbug.com/751425): We should use the mock functionality
  // via |dummy_page_holder|.
  url_test_helpers::RegisterMockedErrorURLLoad(href_url);
  LinkLoadParameters params(
      LinkRelAttribute("prefetch"), kCrossOriginAttributeNotSet, "image/jpg",
      "", "", "", "", String(), network::mojom::ReferrerPolicy::kDefault,
      href_url, String() /* image_srcset */, String() /* image_sizes */,
      String() /* blocking */);
  loader->LoadLink(params, dummy_page_holder->GetDocument());
  ASSERT_TRUE(dummy_page_holder->GetDocument().Fetcher());
  Resource* resource = loader->GetResourceForTesting();
  EXPECT_TRUE(resource);

  if (privacy_changes_enabled_) {
    EXPECT_EQ(resource->GetResourceRequest().GetRedirectMode(),
              network::mojom::RedirectMode::kError);
    EXPECT_EQ(resource->GetResourceRequest().GetReferrerPolicy(),
              network::mojom::ReferrerPolicy::kNever);
  } else {
    EXPECT_EQ(resource->GetResourceRequest().GetRedirectMode(),
              network::mojom::RedirectMode::kFollow);
    EXPECT_EQ(resource->GetResourceRequest().GetReferrerPolicy(),
              ReferrerUtils::MojoReferrerPolicyResolveDefault(
                  network::mojom::ReferrerPolicy::kDefault));
  }

  URLLoaderMockFactory::GetSingletonInstance()
      ->UnregisterAllURLsAndClearMemoryCache();
}

class LinkLoaderTest : public testing::Test,
                       private ScopedMockOverlayScrollbars {
 protected:
  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<TestingPlatformSupport> platform_;
};

TEST_F(LinkLoaderTest, Prefetch) {
  struct TestCase {
    const char* href;
    // TODO(yoav): Add support for type and media crbug.com/662687
    const char* type;
    const char* media;
    const network::mojom::ReferrerPolicy referrer_policy;
    const bool link_loader_should_load_value;
    const bool expecting_load;
    const network::mojom::ReferrerPolicy expected_referrer_policy;
  } cases[] = {
      // Referrer Policy
      {"http://example.test/cat.jpg", "image/jpg", "",
       network::mojom::ReferrerPolicy::kOrigin, true, true,
       network::mojom::ReferrerPolicy::kOrigin},
      {"http://example.test/cat.jpg", "image/jpg", "",
       network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin, true, true,
       network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin},
      {"http://example.test/cat.jpg", "image/jpg", "",
       network::mojom::ReferrerPolicy::kNever, true, true,
       network::mojom::ReferrerPolicy::kNever},
  };

  // Test the cases with a single header
  for (const auto& test_case : cases) {
    auto dummy_page_holder =
        std::make_unique<DummyPageHolder>(gfx::Size(500, 500));
    dummy_page_holder->GetFrame().GetSettings()->SetScriptEnabled(true);
    Persistent<MockLinkLoaderClient> loader_client =
        MakeGarbageCollected<MockLinkLoaderClient>(
            test_case.link_loader_should_load_value);
    auto* loader = MakeGarbageCollected<LinkLoader>(loader_client.Get());
    KURL href_url = KURL(NullURL(), test_case.href);
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |dummy_page_holder|.
    url_test_helpers::RegisterMockedErrorURLLoad(href_url);
    LinkLoadParameters params(
        LinkRelAttribute("prefetch"), kCrossOriginAttributeNotSet,
        test_case.type, "", test_case.media, "", "", String(),
        test_case.referrer_policy, href_url, String() /* image_srcset */,
        String() /* image_sizes */, String() /* blocking */);
    loader->LoadLink(params, dummy_page_holder->GetDocument());
    ASSERT_TRUE(dummy_page_holder->GetDocument().Fetcher());
    Resource* resource = loader->GetResourceForTesting();
    if (test_case.expecting_load) {
      EXPECT_TRUE(resource);
    } else {
      EXPECT_FALSE(resource);
    }
    if (resource) {
      if (test_case.expected_referrer_policy !=
          network::mojom::ReferrerPolicy::kDefault) {
        EXPECT_EQ(test_case.expected_referrer_policy,
                  resource->GetResourceRequest().GetReferrerPolicy());
      }
    }
    URLLoaderMockFactory::GetSingletonInstance()
        ->UnregisterAllURLsAndClearMemoryCache();
  }
}

TEST_F(LinkLoaderTest, DNSPrefetch) {
  struct {
    const char* href;
    const bool should_load;
  } cases[] = {
      {"http://example.com/", true},
      {"https://example.com/", true},
      {"//example.com/", true},
      {"//example.com/", false},
  };

  // Test the cases with a single header
  for (const auto& test_case : cases) {
    auto dummy_page_holder =
        std::make_unique<DummyPageHolder>(gfx::Size(500, 500));
    dummy_page_holder->GetDocument().GetSettings()->SetDNSPrefetchingEnabled(
        true);
    dummy_page_holder->GetFrame().SetPrescientNetworkingForTesting(
        std::make_unique<NetworkHintsMock>());
    auto* mock_network_hints = static_cast<NetworkHintsMock*>(
        dummy_page_holder->GetFrame().PrescientNetworking());
    Persistent<MockLinkLoaderClient> loader_client =
        MakeGarbageCollected<MockLinkLoaderClient>(test_case.should_load);
    auto* loader = MakeGarbageCollected<LinkLoader>(loader_client.Get());
    KURL href_url = KURL(KURL(String("http://example.com")), test_case.href);
    LinkLoadParameters params(
        LinkRelAttribute("dns-prefetch"), kCrossOriginAttributeNotSet, String(),
        String(), String(), String(), String(), String(),
        network::mojom::ReferrerPolicy::kDefault, href_url,
        String() /* image_srcset */, String() /* image_sizes */,
        String() /* blocking */);
    loader->LoadLink(params, dummy_page_holder->GetDocument());
    EXPECT_FALSE(mock_network_hints->DidPreconnect());
    EXPECT_EQ(test_case.should_load, mock_network_hints->DidDnsPrefetch());
  }
}

TEST_F(LinkLoaderTest, Preconnect) {
  struct {
    const char* href;
    CrossOriginAttributeValue cross_origin;
    const bool should_load;
    const bool is_https;
    const bool is_cross_origin;
  } cases[] = {
      {"http://example.com/", kCrossOriginAttributeNotSet, true, false, false},
      {"https://example.com/", kCrossOriginAttributeNotSet, true, true, false},
      {"http://example.com/", kCrossOriginAttributeAnonymous, true, false,
       true},
      {"//example.com/", kCrossOriginAttributeNotSet, true, false, false},
      {"http://example.com/", kCrossOriginAttributeNotSet, false, false, false},
  };

  // T
```