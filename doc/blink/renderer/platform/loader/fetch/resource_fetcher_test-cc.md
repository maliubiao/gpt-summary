Response:
The user wants a summary of the functionalities implemented in the C++ source code file `blink/renderer/platform/loader/fetch/resource_fetcher_test.cc`. This file appears to contain unit tests for the `ResourceFetcher` class in the Chromium Blink engine.

Here's a breakdown of how to approach the request:

1. **Identify the Core Functionality:** The filename itself, `resource_fetcher_test.cc`, strongly suggests the file is primarily focused on testing the `ResourceFetcher`.

2. **Scan the Imports:**  The included headers provide clues about the `ResourceFetcher`'s responsibilities. We see imports related to:
    * `ResourceFetcher` itself.
    * Fetching concepts like `ResourceRequest`, `ResourceResponse`, `FetchParameters`, `ResourceLoader`, `MemoryCache`.
    * Network interaction (`url_loader/url_loader.h`).
    * Testing utilities (`gtest/gtest.h`, mock objects).

3. **Examine the Test Cases:** The `TEST_F` macros define individual test cases. Analyzing these tests will reveal specific functionalities being tested. Look for patterns and keywords in the test names and the code within each test.

4. **Look for Interactions with Web Technologies (JavaScript, HTML, CSS):**  While this is a C++ test file, the underlying functionality of `ResourceFetcher` is crucial for loading web resources. Look for tests that indirectly touch upon how resources like images, scripts, and stylesheets are fetched and handled.

5. **Identify Logical Inferences:** Some tests might involve setting up specific conditions and verifying expected outcomes. These scenarios can be presented as input/output examples.

6. **Pinpoint Potential User/Programming Errors:** Tests that check error conditions or edge cases can highlight common mistakes developers might make when interacting with or extending the resource fetching mechanism.

7. **Focus on the Provided Snippet (Part 1):** Since this is part 1 of 3, concentrate only on the code provided in this section. Avoid making assumptions about what might be in the subsequent parts.

**Mental Walkthrough of the Code Snippet:**

* **Includes:**  Confirm the initial understanding of `ResourceFetcher`'s dependencies.
* **Helper Classes/Namespaces:**  The `PartialResourceRequest` struct seems to capture a subset of `ResourceRequest` for easier comparison in tests.
* **`ResourceFetcherTest` Class:**  This is the main test fixture.
    * **Setup (`ResourceFetcherTest()`):** Initializes the test environment, including a mock clock.
    * **Teardown (`~ResourceFetcherTest()`):** Cleans up resources, especially the memory cache.
    * **`TestResourceLoadObserver`:**  A custom observer to inspect the details of resource loads, particularly the requests being sent. This is a strong indicator of testing request manipulation or observation.
    * **Helper Methods (`CreateTaskRunner`, `CreateFetcher`, `AddResourceToMemoryCache`, `RegisterMockedURLLoad`):** These simplify the creation and setup of test scenarios.
* **Individual Tests:**
    * `StartLoadAfterFrameDetach`: Tests how the fetcher handles requests after a frame is detached (related to browser lifecycle).
    * `UseExistingResource`: Focuses on the memory cache and reuse of cached resources. It involves checking HTTP caching headers like `Cache-Control`.
    * `MetricsPerTopFrameSite`: Examines how caching and fetching behave based on the top-level frame's origin, relevant to site isolation and security.
    * `MetricsPerTopFrameSiteOpaqueOrigins`: Similar to the above, but specifically for opaque origins.
    * `WillSendRequestAdBit`: Checks if metadata (the "ad bit") is correctly preserved when serving from the cache, related to ad blocking or privacy features.
    * `Vary`: Tests the handling of the `Vary` HTTP header, crucial for correct caching behavior when responses depend on request headers.
    * `VaryOnBack`: Specifically tests `Vary` in the context of back/forward navigation (using the cache).
    * `VaryResource`: Another test for `Vary`, possibly focusing on a different aspect.
    * `RequestSameResourceOnComplete`:  A test involving requesting the same resource after a previous load completes, likely checking for race conditions or reentrancy issues.
    * `DISABLED_RevalidateWhileFinishingLoading`:  A disabled test hinting at a potential bug or complex scenario related to revalidation during the loading process.
    * `MAYBE_DontReuseMediaDataUrl`:  Tests how `data:` URLs are handled for media resources, ensuring they are not inappropriately reused.
    * `ServeRequestsOnCompleteClient` and `ResponseOnCancel`: Focuses on the cancellation process and preventing issues when responses arrive after a cancellation.
    * `ScopedMockRedirectRequester`: A helper class for setting up mocked redirects, indicating tests for redirection scenarios.

**Synthesizing the Summary:** Based on this analysis, I can now formulate a concise summary of the functionalities.
这是`blink/renderer/platform/loader/fetch/resource_fetcher_test.cc`文件的第一部分，它主要包含对Blink引擎中 `ResourceFetcher` 类的单元测试。`ResourceFetcher` 负责发起和管理网络资源的请求。

**归纳其功能:**

这部分代码主要关注 `ResourceFetcher` 在以下方面的功能测试：

1. **资源请求的生命周期管理:**
   - 测试在frame detach后发起资源加载的处理 ( `StartLoadAfterFrameDetach` )。
   - 测试如何利用已存在的缓存资源 ( `UseExistingResource` )。
   - 测试在资源加载完成时请求相同资源的行为 ( `RequestSameResourceOnComplete` )。
   - 测试在资源加载过程中进行缓存再验证的场景 ( `DISABLED_RevalidateWhileFinishingLoading` )。
   - 测试取消资源加载时的行为，以及避免在取消后收到响应导致状态错误的问题 ( `ResponseOnCancel` )。

2. **缓存机制的测试:**
   - 测试基于顶级frame站点 (top-frame site) 的缓存策略和指标收集 ( `MetricsPerTopFrameSite`, `MetricsPerTopFrameSiteOpaqueOrigins` )。
   - 测试从缓存中返回资源时，`WillSendRequest` 回调中是否保留了资源的ad标记 ( `WillSendRequestAdBit` )。
   - 测试 `Vary` HTTP 头部的处理，确保在请求头变化时，缓存不会被错误地使用 ( `Vary`, `VaryOnBack`, `VaryResource` )。

3. **特定资源类型的处理:**
   - 测试 `data:` URL 对于媒体资源的处理方式，确保它们不会被不恰当地重用 ( `MAYBE_DontReuseMediaDataUrl` )。

4. **资源请求的观察:**
   - 通过 `TestResourceLoadObserver` 观察资源请求的发送，可以验证请求的属性，例如是否为广告资源，以及优先级。

**与 JavaScript, HTML, CSS 的功能关系举例说明:**

* **JavaScript:** 当 JavaScript 代码通过 `fetch()` API 或 `XMLHttpRequest` 发起网络请求时，Blink 引擎会使用 `ResourceFetcher` 来执行这些请求。例如，一个 JavaScript 脚本可能请求一个 JSON 数据文件：
   ```javascript
   fetch('https://example.com/data.json')
     .then(response => response.json())
     .then(data => console.log(data));
   ```
   `ResourceFetcher` 会处理这个请求，并根据缓存策略和服务器响应来返回数据。相关的测试用例是关于缓存利用的测试 ( `UseExistingResource` )。

* **HTML:**  当浏览器解析 HTML 文档时，遇到 `<img>`, `<link rel="stylesheet">`, `<script src="...">` 等标签时，会触发资源请求。例如，一个 HTML 页面包含一个图片：
   ```html
   <img src="image.png" alt="My Image">
   ```
   `ResourceFetcher` 负责下载 `image.png` 文件。与此相关的测试用例是测试资源加载的生命周期管理，例如在 frame detach 后的处理 ( `StartLoadAfterFrameDetach` )。

* **CSS:**  CSS 文件通常通过 `<link>` 标签引入。当浏览器遇到这样的标签时，`ResourceFetcher` 会发起对 CSS 文件的请求。例如：
   ```html
   <link rel="stylesheet" href="style.css">
   ```
   `ResourceFetcher` 需要正确处理 CSS 文件的缓存，并且要根据 `Vary` 头部来决定是否可以使用缓存。相关的测试用例是关于 `Vary` 头部的测试 ( `Vary`, `VaryOnBack`, `VaryResource` )。

**逻辑推理的假设输入与输出:**

**假设输入:** 一个已经加载到内存缓存的图片资源，其 `Cache-Control` 头为 `max-age=3600`。

**输出:** 当在 3600 秒内再次请求该图片资源时，`ResourceFetcher` 会直接从内存缓存返回该资源，而不会发起新的网络请求。相关的测试用例是 `UseExistingResource`。

**涉及用户或者编程常见的使用错误举例说明:**

* **用户错误:** 用户可能会通过浏览器的开发者工具强制刷新页面 (hard reload)。这通常会绕过缓存，导致 `ResourceFetcher` 重新请求所有资源，即使它们在缓存中有效。这可以通过测试用例中模拟网络请求和缓存行为来间接体现。

* **编程错误:**  开发者可能在设置 HTTP 头部时犯错，例如设置了错误的 `Cache-Control` 或 `Vary` 头部。这可能导致资源无法被正确缓存或重用。例如，如果服务器返回的响应包含 `Vary: User-Agent`，但后续请求的 `User-Agent` 没有变化，`ResourceFetcher` 应该能够重用缓存的资源。如果开发者错误地配置了服务器，可能导致不必要的资源重新下载。相关的测试用例是关于 `Vary` 头部的测试。

总而言之，这部分代码定义了针对 `ResourceFetcher` 核心功能的单元测试，涵盖了资源请求的生命周期、缓存机制、特定资源类型处理以及资源请求的观察。这些测试对于确保 Blink 引擎能够高效、正确地加载网络资源至关重要，并间接地关系到网页的性能和用户体验。

Prompt: 
```
这是目录为blink/renderer/platform/loader/fetch/resource_fetcher_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"

#include <memory>
#include <optional>

#include "base/memory/raw_ptr.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "services/network/public/mojom/ip_address_space.mojom-blink.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/lcp_critical_path_predictor_util.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/request_context_frame_type.mojom-blink.h"
#include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/loader/fetch/console_logger.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_info.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/raw_resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_error.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_observer.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_timing_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/unique_identifier.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader.h"
#include "third_party/blink/renderer/platform/loader/testing/fetch_testing_platform_support.h"
#include "third_party/blink/renderer/platform/loader/testing/mock_fetch_context.h"
#include "third_party/blink/renderer/platform/loader/testing/mock_resource.h"
#include "third_party/blink/renderer/platform/loader/testing/mock_resource_client.h"
#include "third_party/blink/renderer/platform/loader/testing/test_loader_factory.h"
#include "third_party/blink/renderer/platform/loader/testing/test_resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/testing/mock_context_lifecycle_notifier.h"
#include "third_party/blink/renderer/platform/testing/scoped_mocked_url.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory_impl.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"

namespace blink {

namespace {

constexpr char kTestResourceFilename[] = "white-1x1.png";
constexpr char kTestResourceMimeType[] = "image/png";

class PartialResourceRequest {
 public:
  PartialResourceRequest() : PartialResourceRequest(ResourceRequest()) {}
  PartialResourceRequest(const ResourceRequest& request)
      : is_ad_resource_(request.IsAdResource()),
        priority_(request.Priority()) {}

  bool IsAdResource() const { return is_ad_resource_; }
  ResourceLoadPriority Priority() const { return priority_; }

 private:
  bool is_ad_resource_;
  ResourceLoadPriority priority_;
};

}  // namespace

class ResourceFetcherTest : public testing::Test {
 public:
  ResourceFetcherTest()
      : task_environment_(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {
    Resource::SetClockForTesting(task_environment_.GetMockClock());
    // The state of global LcppEnabled flag depends on several feature flags
    // which can be enabled/disabled in tests. Clear the global flag value.
    ResetLcppEnabledForTesting();
  }
  ~ResourceFetcherTest() override {
    MemoryCache::Get()->EvictResources();
    Resource::SetClockForTesting(nullptr);
  }

  ResourceFetcherTest(const ResourceFetcherTest&) = delete;
  ResourceFetcherTest& operator=(const ResourceFetcherTest&) = delete;

  class TestResourceLoadObserver final : public ResourceLoadObserver {
   public:
    // ResourceLoadObserver implementation.
    void DidStartRequest(const FetchParameters&, ResourceType) override {}
    void WillSendRequest(const ResourceRequest& request,
                         const ResourceResponse& redirect_response,
                         ResourceType,
                         const ResourceLoaderOptions&,
                         RenderBlockingBehavior,
                         const Resource*) override {
      request_ = PartialResourceRequest(request);
    }
    void DidChangePriority(uint64_t identifier,
                           ResourceLoadPriority,
                           int intra_priority_value) override {}
    void DidReceiveResponse(uint64_t identifier,
                            const ResourceRequest& request,
                            const ResourceResponse& response,
                            const Resource* resource,
                            ResponseSource source) override {}
    void DidReceiveData(uint64_t identifier,
                        base::SpanOrSize<const char> chunk) override {}
    void DidReceiveTransferSizeUpdate(uint64_t identifier,
                                      int transfer_size_diff) override {}
    void DidDownloadToBlob(uint64_t identifier, BlobDataHandle*) override {}
    void DidFinishLoading(uint64_t identifier,
                          base::TimeTicks finish_time,
                          int64_t encoded_data_length,
                          int64_t decoded_body_length) override {}
    void DidFailLoading(const KURL&,
                        uint64_t identifier,
                        const ResourceError&,
                        int64_t encoded_data_length,
                        IsInternalRequest is_internal_request) override {}
    void DidChangeRenderBlockingBehavior(
        Resource* resource,
        const FetchParameters& params) override {}
    bool InterestedInAllRequests() override {
      return interested_in_all_requests_;
    }
    void SetInterestedInAllRequests(bool interested_in_all_requests) {
      interested_in_all_requests_ = interested_in_all_requests;
    }
    const std::optional<PartialResourceRequest>& GetLastRequest() const {
      return request_;
    }

    void ClearLastRequest() { request_ = std::nullopt; }

   private:
    std::optional<PartialResourceRequest> request_;
    bool interested_in_all_requests_ = false;
  };

 protected:
  scoped_refptr<scheduler::FakeTaskRunner> CreateTaskRunner() {
    return base::MakeRefCounted<scheduler::FakeTaskRunner>();
  }

  ResourceFetcher* CreateFetcher(
      const TestResourceFetcherProperties& properties,
      FetchContext* context) {
    return MakeGarbageCollected<ResourceFetcher>(ResourceFetcherInit(
        properties.MakeDetachable(), context, CreateTaskRunner(),
        CreateTaskRunner(),
        MakeGarbageCollected<TestLoaderFactory>(
            platform_->GetURLLoaderMockFactory()),
        MakeGarbageCollected<MockContextLifecycleNotifier>(),
        nullptr /* back_forward_cache_loader_helper */));
  }

  ResourceFetcher* CreateFetcher(
      const TestResourceFetcherProperties& properties) {
    return CreateFetcher(properties, MakeGarbageCollected<MockFetchContext>());
  }

  ResourceFetcher* CreateFetcher() {
    return CreateFetcher(
        *MakeGarbageCollected<TestResourceFetcherProperties>());
  }

  void AddResourceToMemoryCache(Resource* resource) {
    MemoryCache::Get()->Add(resource);
  }

  void RegisterMockedURLLoad(const KURL& url) {
    url_test_helpers::RegisterMockedURLLoad(
        url, test::PlatformTestDataPath(kTestResourceFilename),
        kTestResourceMimeType, platform_->GetURLLoaderMockFactory());
  }

  base::test::SingleThreadTaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<FetchTestingPlatformSupport> platform_;
};

TEST_F(ResourceFetcherTest, StartLoadAfterFrameDetach) {
  KURL secure_url("https://secureorigin.test/image.png");
  // Try to request a url. The request should fail, and a resource in an error
  // state should be returned, and no resource should be present in the cache.
  auto* fetcher = CreateFetcher();
  fetcher->ClearContext();
  ResourceRequest resource_request(secure_url);
  resource_request.SetRequestContext(
      mojom::blink::RequestContextType::INTERNAL);
  FetchParameters fetch_params =
      FetchParameters::CreateForTest(std::move(resource_request));
  Resource* resource = RawResource::Fetch(fetch_params, fetcher, nullptr);
  ASSERT_TRUE(resource);
  EXPECT_TRUE(resource->ErrorOccurred());
  EXPECT_TRUE(resource->GetResourceError().IsAccessCheck());
  EXPECT_FALSE(MemoryCache::Get()->ResourceForURLForTesting(secure_url));

  // Start by calling StartLoad() directly, rather than via RequestResource().
  // This shouldn't crash. Setting the resource type to image, as StartLoad with
  // a single argument is only called on images or fonts.
  fetcher->StartLoad(RawResource::CreateForTest(
      secure_url, SecurityOrigin::CreateUniqueOpaque(), ResourceType::kImage));
}

TEST_F(ResourceFetcherTest, UseExistingResource) {
  base::HistogramTester histogram_tester;
  auto* fetcher = CreateFetcher();

  KURL url("http://127.0.0.1:8000/foo.html");
  ResourceResponse response(url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(http_names::kCacheControl,
                              AtomicString("max-age=3600"));
  platform_->GetURLLoaderMockFactory()->RegisterURL(
      url, WrappedResourceResponse(response),
      test::PlatformTestDataPath(kTestResourceFilename));

  FetchParameters fetch_params =
      FetchParameters::CreateForTest(ResourceRequest(url));
  Resource* resource = MockResource::Fetch(fetch_params, fetcher, nullptr);
  ASSERT_TRUE(resource);
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();
  EXPECT_TRUE(resource->IsLoaded());
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource));

  Resource* new_resource = MockResource::Fetch(fetch_params, fetcher, nullptr);
  EXPECT_EQ(resource, new_resource);

  // Test histograms.
  histogram_tester.ExpectTotalCount("Blink.MemoryCache.RevalidationPolicy.Mock",
                                    2);
  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Mock",
      3 /* RevalidationPolicy::kLoad */, 1);
  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Mock",
      0 /* RevalidationPolicy::kUse */, 1);

  // Create a new fetcher and load the same resource.
  auto* new_fetcher = CreateFetcher();
  Resource* new_fetcher_resource =
      MockResource::Fetch(fetch_params, new_fetcher, nullptr);
  EXPECT_EQ(resource, new_fetcher_resource);
  histogram_tester.ExpectTotalCount("Blink.MemoryCache.RevalidationPolicy.Mock",
                                    3);
  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Mock",
      3 /* RevalidationPolicy::kLoad */, 1);
  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Mock",
      0 /* RevalidationPolicy::kUse */, 2);
}

TEST_F(ResourceFetcherTest, MetricsPerTopFrameSite) {
  base::HistogramTester histogram_tester;

  KURL url("http://127.0.0.1:8000/foo.html");
  ResourceResponse response(url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(http_names::kCacheControl,
                              AtomicString("max-age=3600"));
  platform_->GetURLLoaderMockFactory()->RegisterURL(
      url, WrappedResourceResponse(response),
      test::PlatformTestDataPath(kTestResourceFilename));

  ResourceRequestHead request_head(url);
  scoped_refptr<const SecurityOrigin> origin_a =
      SecurityOrigin::Create(KURL("https://a.test"));
  request_head.SetTopFrameOrigin(origin_a);
  request_head.SetRequestorOrigin(origin_a);
  FetchParameters fetch_params =
      FetchParameters::CreateForTest(ResourceRequest(request_head));
  auto* fetcher_1 = CreateFetcher();
  Resource* resource_1 = MockResource::Fetch(fetch_params, fetcher_1, nullptr);
  ASSERT_TRUE(resource_1);
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();
  EXPECT_TRUE(resource_1->IsLoaded());
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource_1));

  auto* fetcher_2 = CreateFetcher();
  ResourceRequestHead request_head_2(url);
  scoped_refptr<const SecurityOrigin> origin_b =
      SecurityOrigin::Create(KURL("https://b.test"));
  request_head_2.SetTopFrameOrigin(origin_b);
  request_head_2.SetRequestorOrigin(origin_a);
  FetchParameters fetch_params_2 =
      FetchParameters::CreateForTest(ResourceRequest(request_head_2));
  Resource* resource_2 =
      MockResource::Fetch(fetch_params_2, fetcher_2, nullptr);
  EXPECT_EQ(resource_1, resource_2);

  // Test histograms.
  histogram_tester.ExpectTotalCount("Blink.MemoryCache.RevalidationPolicy.Mock",
                                    2);

  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Mock",
      3 /* RevalidationPolicy::kLoad */, 1);
  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Mock",
      0 /* RevalidationPolicy::kUse */, 1);

  // Now load the same resource with origin_b as top-frame site. The
  // histograms should be incremented.
  auto* fetcher_3 = CreateFetcher();
  ResourceRequestHead request_head_3(url);
  scoped_refptr<const SecurityOrigin> foo_origin_b =
      SecurityOrigin::Create(KURL("https://foo.b.test"));
  request_head_3.SetTopFrameOrigin(foo_origin_b);
  request_head_3.SetRequestorOrigin(origin_a);
  FetchParameters fetch_params_3 =
      FetchParameters::CreateForTest(ResourceRequest(request_head_3));
  Resource* resource_3 =
      MockResource::Fetch(fetch_params_2, fetcher_3, nullptr);
  EXPECT_EQ(resource_1, resource_3);
  histogram_tester.ExpectTotalCount("Blink.MemoryCache.RevalidationPolicy.Mock",
                                    3);
  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Mock",
      0 /* RevalidationPolicy::kUse */, 2);
}

TEST_F(ResourceFetcherTest, MetricsPerTopFrameSiteOpaqueOrigins) {
  base::HistogramTester histogram_tester;

  KURL url("http://127.0.0.1:8000/foo.html");
  ResourceResponse response(url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(http_names::kCacheControl,
                              AtomicString("max-age=3600"));
  platform_->GetURLLoaderMockFactory()->RegisterURL(
      url, WrappedResourceResponse(response),
      test::PlatformTestDataPath(kTestResourceFilename));

  ResourceRequestHead request_head(url);
  scoped_refptr<const SecurityOrigin> origin_a =
      SecurityOrigin::Create(KURL("https://a.test"));
  scoped_refptr<const SecurityOrigin> opaque_origin1 =
      SecurityOrigin::CreateUniqueOpaque();
  request_head.SetTopFrameOrigin(opaque_origin1);
  request_head.SetRequestorOrigin(origin_a);
  FetchParameters fetch_params =
      FetchParameters::CreateForTest(ResourceRequest(request_head));
  auto* fetcher_1 = CreateFetcher();
  Resource* resource_1 = MockResource::Fetch(fetch_params, fetcher_1, nullptr);
  ASSERT_TRUE(resource_1);
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();
  EXPECT_TRUE(resource_1->IsLoaded());
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource_1));

  // Create a 2nd opaque top-level origin.
  auto* fetcher_2 = CreateFetcher();
  ResourceRequestHead request_head_2(url);
  scoped_refptr<const SecurityOrigin> opaque_origin2 =
      SecurityOrigin::CreateUniqueOpaque();
  request_head_2.SetTopFrameOrigin(opaque_origin2);
  request_head_2.SetRequestorOrigin(origin_a);
  FetchParameters fetch_params_2 =
      FetchParameters::CreateForTest(ResourceRequest(request_head_2));
  Resource* resource_2 =
      MockResource::Fetch(fetch_params_2, fetcher_2, nullptr);
  EXPECT_EQ(resource_1, resource_2);

  // Test histograms.
  histogram_tester.ExpectTotalCount("Blink.MemoryCache.RevalidationPolicy.Mock",
                                    2);

  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Mock",
      3 /* RevalidationPolicy::kLoad */, 1);
  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Mock",
      0 /* RevalidationPolicy::kUse */, 1);

  // Now load the same resource with opaque_origin1 as top-frame site. The
  // histograms should be incremented.
  auto* fetcher_3 = CreateFetcher();
  ResourceRequestHead request_head_3(url);
  request_head_3.SetTopFrameOrigin(opaque_origin2);
  request_head_3.SetRequestorOrigin(origin_a);
  FetchParameters fetch_params_3 =
      FetchParameters::CreateForTest(ResourceRequest(request_head_3));
  Resource* resource_3 =
      MockResource::Fetch(fetch_params_2, fetcher_3, nullptr);
  EXPECT_EQ(resource_1, resource_3);
  histogram_tester.ExpectTotalCount("Blink.MemoryCache.RevalidationPolicy.Mock",
                                    3);
  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Mock",
      0 /* RevalidationPolicy::kUse */, 2);
}

// Verify that the ad bit is copied to WillSendRequest's request when the
// response is served from the memory cache.
TEST_F(ResourceFetcherTest, WillSendRequestAdBit) {
  // Add a resource to the memory cache.
  scoped_refptr<const SecurityOrigin> source_origin =
      SecurityOrigin::CreateUniqueOpaque();
  auto* properties =
      MakeGarbageCollected<TestResourceFetcherProperties>(source_origin);
  MockFetchContext* context = MakeGarbageCollected<MockFetchContext>();
  KURL url("http://127.0.0.1:8000/foo.html");
  Resource* resource =
      RawResource::CreateForTest(url, source_origin, ResourceType::kRaw);
  AddResourceToMemoryCache(resource);
  ResourceResponse response(url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(http_names::kCacheControl,
                              AtomicString("max-age=3600"));
  resource->ResponseReceived(response);
  resource->FinishForTest();

  auto* observer = MakeGarbageCollected<TestResourceLoadObserver>();
  // Fetch the cached resource. The request to DispatchWillSendRequest should
  // preserve the ad bit.
  auto* fetcher = CreateFetcher(*properties, context);
  fetcher->SetResourceLoadObserver(observer);
  ResourceRequest resource_request(url);
  resource_request.SetIsAdResource();
  resource_request.SetRequestContext(
      mojom::blink::RequestContextType::INTERNAL);
  FetchParameters fetch_params =
      FetchParameters::CreateForTest(std::move(resource_request));
  platform_->GetURLLoaderMockFactory()->RegisterURL(url, WebURLResponse(), "");
  Resource* new_resource = RawResource::Fetch(fetch_params, fetcher, nullptr);

  EXPECT_EQ(resource, new_resource);
  std::optional<PartialResourceRequest> new_request =
      observer->GetLastRequest();
  EXPECT_TRUE(new_request.has_value());
  EXPECT_TRUE(new_request.value().IsAdResource());
}

TEST_F(ResourceFetcherTest, Vary) {
  scoped_refptr<const SecurityOrigin> source_origin =
      SecurityOrigin::CreateUniqueOpaque();
  KURL url("http://127.0.0.1:8000/foo.html");
  Resource* resource =
      RawResource::CreateForTest(url, source_origin, ResourceType::kRaw);
  AddResourceToMemoryCache(resource);

  ResourceResponse response(url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(http_names::kCacheControl,
                              AtomicString("max-age=3600"));
  response.SetHttpHeaderField(http_names::kVary, AtomicString("*"));
  resource->ResponseReceived(response);
  resource->FinishForTest();
  ASSERT_TRUE(resource->MustReloadDueToVaryHeader(ResourceRequest(url)));

  auto* fetcher = CreateFetcher(
      *MakeGarbageCollected<TestResourceFetcherProperties>(source_origin));
  ResourceRequest resource_request(url);
  resource_request.SetRequestContext(
      mojom::blink::RequestContextType::INTERNAL);
  FetchParameters fetch_params =
      FetchParameters::CreateForTest(std::move(resource_request));
  platform_->GetURLLoaderMockFactory()->RegisterURL(url, WebURLResponse(), "");
  Resource* new_resource = RawResource::Fetch(fetch_params, fetcher, nullptr);
  EXPECT_NE(resource, new_resource);
  new_resource->Loader()->Cancel();
}

TEST_F(ResourceFetcherTest, VaryOnBack) {
  scoped_refptr<const SecurityOrigin> source_origin =
      SecurityOrigin::CreateUniqueOpaque();
  auto* fetcher = CreateFetcher(
      *MakeGarbageCollected<TestResourceFetcherProperties>(source_origin));

  KURL url("http://127.0.0.1:8000/foo.html");
  Resource* resource =
      RawResource::CreateForTest(url, source_origin, ResourceType::kRaw);
  AddResourceToMemoryCache(resource);

  ResourceResponse response(url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(http_names::kCacheControl,
                              AtomicString("max-age=3600"));
  response.SetHttpHeaderField(http_names::kVary, AtomicString("*"));
  resource->ResponseReceived(response);
  resource->FinishForTest();
  ASSERT_TRUE(resource->MustReloadDueToVaryHeader(ResourceRequest(url)));

  ResourceRequest resource_request(url);
  resource_request.SetCacheMode(mojom::FetchCacheMode::kForceCache);
  resource_request.SetRequestContext(
      mojom::blink::RequestContextType::INTERNAL);
  FetchParameters fetch_params =
      FetchParameters::CreateForTest(std::move(resource_request));
  Resource* new_resource = RawResource::Fetch(fetch_params, fetcher, nullptr);
  EXPECT_EQ(resource, new_resource);
}

TEST_F(ResourceFetcherTest, VaryResource) {
  auto* fetcher = CreateFetcher();

  KURL url("http://127.0.0.1:8000/foo.html");
  ResourceResponse response(url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(http_names::kCacheControl,
                              AtomicString("max-age=3600"));
  response.SetHttpHeaderField(http_names::kVary, AtomicString("*"));
  platform_->GetURLLoaderMockFactory()->RegisterURL(
      url, WrappedResourceResponse(response),
      test::PlatformTestDataPath(kTestResourceFilename));

  FetchParameters fetch_params_original =
      FetchParameters::CreateForTest(ResourceRequest(url));
  Resource* resource =
      MockResource::Fetch(fetch_params_original, fetcher, nullptr);
  ASSERT_TRUE(resource);
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();
  ASSERT_TRUE(resource->MustReloadDueToVaryHeader(ResourceRequest(url)));

  FetchParameters fetch_params =
      FetchParameters::CreateForTest(ResourceRequest(url));
  Resource* new_resource = MockResource::Fetch(fetch_params, fetcher, nullptr);
  EXPECT_EQ(resource, new_resource);
}

class RequestSameResourceOnComplete
    : public GarbageCollected<RequestSameResourceOnComplete>,
      public RawResourceClient {
 public:
  RequestSameResourceOnComplete(URLLoaderMockFactory* mock_factory,
                                FetchParameters& params,
                                ResourceFetcher* fetcher)
      : mock_factory_(mock_factory),
        source_origin_(fetcher->GetProperties()
                           .GetFetchClientSettingsObject()
                           .GetSecurityOrigin()) {
    MockResource::Fetch(params, fetcher, this);
  }

  void NotifyFinished(Resource* resource) override {
    EXPECT_EQ(GetResource(), resource);
    auto* properties =
        MakeGarbageCollected<TestResourceFetcherProperties>(source_origin_);
    MockFetchContext* context = MakeGarbageCollected<MockFetchContext>();
    auto* fetcher2 = MakeGarbageCollected<ResourceFetcher>(ResourceFetcherInit(
        properties->MakeDetachable(), context,
        base::MakeRefCounted<scheduler::FakeTaskRunner>(),
        base::MakeRefCounted<scheduler::FakeTaskRunner>(),
        MakeGarbageCollected<TestLoaderFactory>(mock_factory_),
        MakeGarbageCollected<MockContextLifecycleNotifier>(),
        nullptr /* back_forward_cache_loader_helper */));
    ResourceRequest resource_request2(GetResource()->Url());
    resource_request2.SetCacheMode(mojom::FetchCacheMode::kValidateCache);
    FetchParameters fetch_params2 =
        FetchParameters::CreateForTest(std::move(resource_request2));
    Resource* resource2 = MockResource::Fetch(fetch_params2, fetcher2, nullptr);
    EXPECT_EQ(GetResource(), resource2);
    notify_finished_called_ = true;
    ClearResource();
  }
  bool NotifyFinishedCalled() const { return notify_finished_called_; }

  void Trace(Visitor* visitor) const override {
    RawResourceClient::Trace(visitor);
  }

  String DebugName() const override { return "RequestSameResourceOnComplete"; }

 private:
  raw_ptr<URLLoaderMockFactory> mock_factory_;
  bool notify_finished_called_ = false;
  scoped_refptr<const SecurityOrigin> source_origin_;
};

TEST_F(ResourceFetcherTest, DISABLED_RevalidateWhileFinishingLoading) {
  scoped_refptr<const SecurityOrigin> source_origin =
      SecurityOrigin::CreateUniqueOpaque();
  KURL url("http://127.0.0.1:8000/foo.png");

  ResourceResponse response(url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(http_names::kCacheControl,
                              AtomicString("max-age=3600"));
  response.SetHttpHeaderField(http_names::kETag, AtomicString("1234567890"));
  platform_->GetURLLoaderMockFactory()->RegisterURL(
      url, WrappedResourceResponse(response),
      test::PlatformTestDataPath(kTestResourceFilename));

  ResourceFetcher* fetcher1 = CreateFetcher(
      *MakeGarbageCollected<TestResourceFetcherProperties>(source_origin));
  ResourceRequest request1(url);
  request1.SetHttpHeaderField(http_names::kCacheControl,
                              AtomicString("no-cache"));
  FetchParameters fetch_params1 =
      FetchParameters::CreateForTest(std::move(request1));
  Persistent<RequestSameResourceOnComplete> client =
      MakeGarbageCollected<RequestSameResourceOnComplete>(
          platform_->GetURLLoaderMockFactory(), fetch_params1, fetcher1);
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();
  EXPECT_TRUE(client->NotifyFinishedCalled());
}

// TODO(crbug.com/850785): Reenable this.
#if BUILDFLAG(IS_ANDROID)
#define MAYBE_DontReuseMediaDataUrl DISABLED_DontReuseMediaDataUrl
#else
#define MAYBE_DontReuseMediaDataUrl DontReuseMediaDataUrl
#endif
TEST_F(ResourceFetcherTest, MAYBE_DontReuseMediaDataUrl) {
  auto* fetcher = CreateFetcher();
  ResourceRequest request(KURL("data:text/html,foo"));
  request.SetRequestContext(mojom::blink::RequestContextType::VIDEO);
  ResourceLoaderOptions options(nullptr /* world */);
  options.data_buffering_policy = kDoNotBufferData;
  options.initiator_info.name = fetch_initiator_type_names::kInternal;
  FetchParameters fetch_params(std::move(request), options);
  Resource* resource1 = RawResource::FetchMedia(fetch_params, fetcher, nullptr);
  Resource* resource2 = RawResource::FetchMedia(fetch_params, fetcher, nullptr);
  EXPECT_NE(resource1, resource2);
}

class ServeRequestsOnCompleteClient final
    : public GarbageCollected<ServeRequestsOnCompleteClient>,
      public RawResourceClient {
 public:
  explicit ServeRequestsOnCompleteClient(URLLoaderMockFactory* mock_factory)
      : mock_factory_(mock_factory) {}

  void NotifyFinished(Resource*) override {
    mock_factory_->ServeAsynchronousRequests();
    ClearResource();
  }

  // No callbacks should be received except for the NotifyFinished() triggered
  // by ResourceLoader::Cancel().
  void DataSent(Resource*, uint64_t, uint64_t) override { ASSERT_TRUE(false); }
  void ResponseReceived(Resource*, const ResourceResponse&) override {
    ASSERT_TRUE(false);
  }
  void CachedMetadataReceived(Resource*, mojo_base::BigBuffer) override {
    ASSERT_TRUE(false);
  }
  void DataReceived(Resource*, base::span<const char>) override {
    ASSERT_TRUE(false);
  }
  bool RedirectReceived(Resource*,
                        const ResourceRequest&,
                        const ResourceResponse&) override {
    ADD_FAILURE();
    return true;
  }
  void DataDownloaded(Resource*, uint64_t) override { ASSERT_TRUE(false); }

  void Trace(Visitor* visitor) const override {
    RawResourceClient::Trace(visitor);
  }

  String DebugName() const override { return "ServeRequestsOnCompleteClient"; }

 private:
  raw_ptr<URLLoaderMockFactory, DanglingUntriaged> mock_factory_;
};

// Regression test for http://crbug.com/594072.
// This emulates a modal dialog triggering a nested run loop inside
// ResourceLoader::Cancel(). If the ResourceLoader doesn't promptly cancel its
// URLLoader before notifying its clients, a nested run loop  may send a network
// response, leading to an invalid state transition in ResourceLoader.
TEST_F(ResourceFetcherTest, ResponseOnCancel) {
  KURL url("http://127.0.0.1:8000/foo.png");
  RegisterMockedURLLoad(url);

  auto* fetcher = CreateFetcher();
  ResourceRequest resource_request(url);
  resource_request.SetRequestContext(
      mojom::blink::RequestContextType::INTERNAL);
  FetchParameters fetch_params =
      FetchParameters::CreateForTest(std::move(resource_request));
  Persistent<ServeRequestsOnCompleteClient> client =
      MakeGarbageCollected<ServeRequestsOnCompleteClient>(
          platform_->GetURLLoaderMockFactory());
  Resource* resource = RawResource::Fetch(fetch_params, fetcher, client);
  resource->Loader()->Cancel();
}

class ScopedMockRedirectRequester {
  STACK_ALLOCATED();

 public:
  ScopedMockRedirectRequester(
      URLLoaderMockFactory* mock_factory,
      MockFetchContext* context,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : mock_factory_(mock_factory),
        context_(context),
        task_runner_(std::move(task_runner)) {}
  ScopedMockRedirectRequester(const ScopedMockRedirectRequester&) = delete;
  ScopedMockRedirectRequester& operator=(const ScopedMockRedirectRequester&) =
      delete;

  void RegisterRedirect(const WebString& from_url, const WebString& to_url) {
    KURL redirect_url(from_url);
    WebURLResponse redirect_response;
    redirect_response.SetCurrentRequestUrl(redirect_url);
    redirect_response.SetHttpStatusCode(301);
    redirect_response.SetHttpHeaderField(http_names::kLocation, to_url);
    redirect_response.SetEncodedDataLength(kRedirectResponseOverheadBytes);

    mock_factory_->RegisterURL(redirect_url, redirect_response, "");
  }

  void RegisterFin
"""


```