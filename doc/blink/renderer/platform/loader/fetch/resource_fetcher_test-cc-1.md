Response:
My thinking process for summarizing the provided code snippet went through these steps:

1. **Understand the Goal:** The prompt asks for a summary of the functionality of the provided C++ code, specifically focusing on its relationship to web technologies (JavaScript, HTML, CSS), logical deductions with examples, common user/programming errors, and ultimately a concise summary of the code's purpose within the `ResourceFetcherTest` context. The fact that it's "part 2 of 3" suggests a larger test suite.

2. **Identify the Core Class Under Test:** The filename `resource_fetcher_test.cc` and the test fixture `TEST_F(ResourceFetcherTest, ...)` immediately point to the `ResourceFetcher` class as the primary target of these tests.

3. **Analyze Helper Functions and Setup:** I first looked at the functions defined *within* the provided snippet:
    * `RegisterMockedURLLoad`: This clearly sets up mock network responses for testing purposes. It takes a URL and associates it with a local test file and MIME type.
    * `Request`: This function seems to initiate a resource fetch using the `ResourceFetcher`. It constructs `ResourceRequest` and `FetchParameters`, and then calls `RawResource::Fetch`. The key here is that it's an *asynchronous* request due to `mock_factory_->ServeAsynchronousRequests()`.

4. **Break Down Individual Tests:**  I then examined each `TEST_F` block individually, focusing on the actions performed and the assertions made:
    * **`SynchronousRequest`:**  Fetches a resource synchronously and verifies it's loaded with the highest priority.
    * **`PingPriority`:**  Fetches a resource with `RequestContextType::PING` and checks if it's assigned `kVeryLow` priority.
    * **`PreloadResourceTwice`:** Tests preloading the same resource twice and verifies that the existing preloaded resource is reused. It also checks the behavior after clearing preloads.
    * **`LinkPreloadResourceAndUse`:** Simulates a link preload scenario where a preloaded resource is subsequently requested by the parser. It checks if the same resource is used and how clearing preloads affects it.
    * **`PreloadMatchWithBypassingCache`:** Tests if a preloaded resource is matched even when a subsequent request tries to bypass the cache.
    * **`CrossFramePreloadMatchIsNotAllowed`:**  Confirms that preloads are not shared across different `ResourceFetcher` instances (simulating cross-frame scenarios).
    * **`RepetitiveLinkPreloadShouldBeMerged`:** Checks that multiple link preload requests for the same resource are merged into a single request.
    * **`RepetitiveSpeculativePreloadShouldBeMerged`:** Similar to the above, but for speculative preloads.
    * **`SpeculativePreloadShouldBePromotedToLinkPreload`:**  Verifies that a speculative preload can be "upgraded" to a link preload if a link preload request arrives for the same resource.
    * **`Revalidate304`:**  Tests the scenario where a cached resource receives a 304 (Not Modified) response during revalidation.
    * **`LinkPreloadResourceMultipleFetchersAndMove`:** Examines link preloading across multiple fetchers, focusing on whether the preloaded resource is moved or duplicated.
    * **`ContentTypeDataURL`:** Tests fetching a data URL and verifies the correct MIME type is extracted.
    * **`ContentIdURL`:**  Checks that requests with the `cid:` scheme are not canceled, which is important for certain Android WebView scenarios.
    * **`StaleWhileRevalidate`:** Tests the "stale-while-revalidate" caching mechanism, ensuring background revalidation occurs and the cache is updated.
    * **`CachedResourceShouldNotCrashByNullURL`:**  A safety check to ensure the `CachedResource` method handles null URLs gracefully.
    * **`DeprioritizeSubframe`:** Tests how resource priorities are adjusted for subframes when the subframe deprioritization feature is enabled.
    * **`BoostImagePriority`:**  Examines the logic for boosting the priority of certain "non-small" images.
    * **`IsPotentiallyLCPElement`:** Tests whether resources identified as potential Largest Contentful Paint (LCP) elements receive a priority boost.
    * **`Detach`:**  Tests the detachment mechanism of the `ResourceFetcher`, ensuring its properties are correctly detached.
    * **`DuplicatePreloadAllowsPriorityChange`:** Verifies that if a duplicate preload request arrives with a higher priority, the existing preload's priority is updated.

5. **Identify Relationships to Web Technologies:**  While the code is C++, it directly deals with concepts crucial to web browsing:
    * **HTML:**  Link preloads (`<link rel="preload">`), resource fetching initiated by HTML parsing.
    * **CSS:**  Fetching CSS stylesheets.
    * **JavaScript:** Fetching JavaScript files, although not explicitly shown in this snippet, the `ResourceFetcher` handles these.
    * **HTTP:**  HTTP requests, caching (`max-age`, `stale-while-revalidate`), HTTP status codes (304).
    * **URLs:** Handling different URL schemes (HTTP, data:, cid:).
    * **Resource Priority:**  The concept of prioritizing resource loading is fundamental to web performance.

6. **Look for Logical Deductions and Examples:** For each test, I considered:
    * **Input (Implicit):**  The specific setup within the `TEST_F` block (mocked URLs, fetch parameters).
    * **Output (Assertions):** The `EXPECT_...` statements that verify the expected behavior.
    * **Logical Flow:** How the code under test should behave based on the input.

7. **Identify Potential User/Programming Errors:**  I considered common mistakes related to resource loading:
    * Incorrect cache control settings.
    * Not understanding how preloads work.
    * Issues with cross-origin requests (although not directly tested here, the concept of separate fetchers hints at it).
    * Incorrectly assuming synchronous behavior for network requests.

8. **Synthesize the Summary:**  Finally, I combined my observations into a concise summary, grouping related functionalities and highlighting the overall purpose of the tests. I emphasized that it's a test file for `ResourceFetcher`, focusing on its core responsibilities like fetching, caching, and prioritizing resources. I also noted the specific aspects being tested, like preloads, caching strategies, and priority handling. The "part 2 of 3" was also included as a contextual piece of information.
这是对`blink/renderer/platform/loader/fetch/resource_fetcher_test.cc` 文件第二部分的分析和功能归纳。

**功能概括 (基于第二部分代码):**

这部分代码主要集中在测试 `ResourceFetcher` 类在处理各种资源请求场景时的行为，特别是关于 **预加载 (Preload)** 和 **缓存 (Cache)** 相关的逻辑。 它测试了 `ResourceFetcher` 如何管理和优化资源的获取，以及如何与浏览器的缓存机制交互。

**具体功能和举例说明:**

1. **同步请求 (Synchronous Request):**
   - **功能:** 测试 `ResourceFetcher` 是否能同步地获取资源。
   - **假设输入:** 一个需要同步加载的资源 URL。
   - **预期输出:** 资源被成功加载，并且具有最高的优先级。
   - **与 Web 技术关系:** 当 JavaScript 代码中明确要求同步加载资源时（不推荐的做法），`ResourceFetcher` 需要能够处理。

2. **Ping 请求优先级 (Ping Priority):**
   - **功能:** 测试 `ResourceFetcher` 对于 "ping" 请求的优先级处理。 Ping 请求通常用于发送统计数据，优先级较低。
   - **假设输入:** 一个 `RequestContextType` 设置为 `PING` 的资源请求。
   - **预期输出:** 资源请求的优先级被设置为 `kVeryLow`。
   - **与 Web 技术关系:** 一些 Web API (例如 `Navigator.sendBeacon()`) 会发起 ping 请求。

3. **预加载资源两次 (PreloadResourceTwice):**
   - **功能:** 测试当同一个资源被预加载两次时，`ResourceFetcher` 的行为。
   - **假设输入:** 两次针对相同 URL 的预加载请求。
   - **预期输出:** 第二次预加载会返回第一次预加载创建的相同资源对象，避免重复加载。当清除预加载后，资源不再被认为是预加载的。
   - **与 Web 技术关系:** HTML 的 `<link rel="preload">` 标签会触发预加载。如果页面中出现重复的预加载声明，浏览器应该能够优化。

4. **预加载资源并使用 (LinkPreloadResourceAndUse):**
   - **功能:** 测试通过预加载加载的资源如何被后续的实际请求使用。
   - **假设输入:** 一个资源的预加载请求，以及后续对相同资源的请求。
   - **预期输出:** 后续请求会使用预加载的资源，而不是重新加载。在特定时机（例如 DCL 到达），预加载状态会被更新。
   - **与 Web 技术关系:** 模拟了浏览器处理 `<link rel="preload">` 标签，并在渲染过程中重用预加载资源的过程。

5. **预加载匹配与绕过缓存 (PreloadMatchWithBypassingCache):**
   - **功能:** 测试即使后续请求明确要求绕过缓存，预加载的资源是否仍然可以被匹配使用。
   - **假设输入:** 一个资源的预加载请求，以及后续一个设置了 `kBypassCache` 的相同资源请求。
   - **预期输出:** 后续请求仍然匹配到预加载的资源。
   - **与 Web 技术关系:** 当开发者希望确保获取最新的资源时，可能会使用绕过缓存的策略。但预加载的资源通常是期望能立即使用的。

6. **跨帧预加载不匹配 (CrossFramePreloadMatchIsNotAllowed):**
   - **功能:** 测试预加载的资源是否会在不同的 `ResourceFetcher` 实例（通常对应于不同的 frame）之间共享。
   - **假设输入:** 在两个不同的 `ResourceFetcher` 中对相同资源进行预加载和请求。
   - **预期输出:**  来自不同 `ResourceFetcher` 的请求不会匹配到对方预加载的资源，会创建新的资源请求。
   - **与 Web 技术关系:** 确保不同 iframe 或 frame 之间的资源加载隔离性。

7. **重复的 Link 预加载应该被合并 (RepetitiveLinkPreloadShouldBeMerged):**
   - **功能:** 测试重复的 `<link rel="preload">` 声明是否会被合并处理。
   - **假设输入:** 先发起一个普通的资源请求，然后再发起一个相同的资源的预加载请求（或者反过来）。
   - **预期输出:**  重复的预加载请求会引用已存在的资源，避免重复加载。当真正的请求到来时，预加载状态会被更新。
   - **与 Web 技术关系:** 浏览器优化重复预加载声明，提高页面加载效率。

8. **重复的推测性预加载应该被合并 (RepetitiveSpeculativePreloadShouldBeMerged):**
   - **功能:**  类似于 Link 预加载，但针对推测性的预加载 (Speculative Preload)。
   - **假设输入:**  多次对同一资源发起推测性预加载请求。
   - **预期输出:** 重复的推测性预加载请求会引用已存在的资源。
   - **与 Web 技术关系:** 推测性预加载是浏览器根据一定的预测策略进行的预加载，例如对文档中可能出现的资源进行预先加载。

9. **推测性预加载应该被提升为 Link 预加载 (SpeculativePreloadShouldBePromotedToLinkPreload):**
   - **功能:** 测试当一个资源先被推测性预加载，然后又被显式地通过 `<link rel="preload">` 声明预加载时，`ResourceFetcher` 的行为。
   - **假设输入:** 先发起一个推测性预加载请求，然后发起一个相同的资源的 Link 预加载请求。
   - **预期输出:**  Link 预加载请求会使用已有的推测性预加载资源，并将该资源标记为 Link 预加载。
   - **与 Web 技术关系:** 浏览器能够根据更明确的预加载指示更新已有的推测性预加载状态。

10. **验证 304 响应 (Revalidate304):**
    - **功能:** 测试当从缓存中获取资源，并向服务器发送验证请求时，服务器返回 304 (Not Modified) 响应的情况。
    - **假设输入:** 缓存中存在一个资源，发起验证请求，模拟服务器返回 304 响应。
    - **预期输出:**  `ResourceFetcher` 会创建一个新的资源对象，即使内容没有改变。
    - **与 Web 技术关系:** HTTP 缓存机制，浏览器会使用缓存的资源，并根据 `ETag` 或 `Last-Modified` 头部进行验证。

11. **多 Fetcher 实例下的 Link 预加载和移动 (LinkPreloadResourceMultipleFetchersAndMove):**
    - **功能:** 测试当在不同的 `ResourceFetcher` 实例中进行 Link 预加载和资源请求时，资源的处理方式。
    - **假设输入:** 一个 `ResourceFetcher` 预加载资源，另一个 `ResourceFetcher` 请求相同的资源。
    - **预期输出:**  请求不会直接使用第一个 `Fetcher` 预加载的资源，表明预加载资源可能不会在不同 fetcher 之间直接“移动”。
    - **与 Web 技术关系:**  可能涉及到不同 browsing context 或 iframe 之间的资源隔离。

12. **Data URL 的 Content-Type (ContentTypeDataURL):**
    - **功能:** 测试 `ResourceFetcher` 如何处理 `data:` URL，特别是提取和设置正确的 MIME 类型。
    - **假设输入:** 一个 `data:` URL。
    - **预期输出:**  资源状态为已缓存，并且响应的 MIME 类型被正确解析和设置。
    - **与 Web 技术关系:** `data:` URL 允许在文档中嵌入小型的资源，例如图片或文本。

13. **Content-ID URL (ContentIdURL):**
    - **功能:** 测试 `ResourceFetcher` 如何处理 `cid:` (Content-ID) URL。
    - **假设输入:** 一个 `cid:` URL。
    - **预期输出:**  即使没有 MHTMLArchive 来服务，请求也不会被取消。
    - **与 Web 技术关系:** `cid:` URL 用于引用 MHTML (MIME HTML) 档案中的资源。

14. **Stale-While-Revalidate (StaleWhileRevalidate):**
    - **功能:** 测试 HTTP 的 `stale-while-revalidate` 缓存指令的处理。
    - **假设输入:**  一个带有 `stale-while-revalidate` 头的资源响应，以及后续对该资源的请求。
    - **预期输出:**  在后台发起重新验证请求的同时，会先使用缓存中过期的资源。重新验证完成后，缓存会被更新。
    - **与 Web 技术关系:**  一种缓存策略，允许用户更快地看到内容，同时在后台更新资源。

15. **缓存资源不应因 Null URL 而崩溃 (CachedResourceShouldNotCrashByNullURL):**
    - **功能:**  测试 `ResourceFetcher::CachedResource()` 方法在接收到空 URL 时是否能安全处理，防止崩溃。
    - **假设输入:**  调用 `CachedResource()` 并传入一个空 URL。
    - **预期输出:**  方法应该返回 `nullptr` 而不是导致崩溃。
    - **与编程常见的使用错误关系:**  开发者可能会错误地传递空 URL 给这个方法。

16. **降级子帧优先级 (DeprioritizeSubframe):**
    - **功能:** 测试当启用子帧优先级降级功能时，`ResourceFetcher` 如何调整子帧中资源的加载优先级。
    - **假设输入:**  不同类型的资源请求，分别在主帧和子帧环境下，并开启/关闭子帧优先级降级功能。
    - **预期输出:**  当子帧优先级降级启用时，子帧中的某些资源类型的优先级会降低。
    - **与 Web 技术关系:** 浏览器优化页面加载性能的一种策略，降低非关键子帧资源的加载优先级。

17. **提升图片优先级 (BoostImagePriority):**
    - **功能:** 测试当启用图片优先级提升功能时，`ResourceFetcher` 如何提升某些图片的加载优先级。
    - **假设输入:** 不同尺寸的图片资源请求。
    - **预期输出:**  特定尺寸（非小尺寸）的图片，在一定数量内，会被提升到 `Medium` 优先级。
    - **与 Web 技术关系:**  提高用户感知的页面加载速度，优先加载重要的图片资源。

18. **潜在 LCP 元素 (IsPotentiallyLCPElement):**
    - **功能:** 测试对于被标记为潜在 Largest Contentful Paint (LCP) 元素的资源，`ResourceFetcher` 是否会给予更高的加载优先级。
    - **假设输入:**  一个被标记为潜在 LCP 元素的图片资源请求。
    - **预期输出:**  该资源的加载优先级会被提升到配置的值 (例如 `Medium` 或 `High`).
    - **与 Web 技术关系:** LCP 是一个重要的 Web 指标，优化 LCP 可以提升用户体验。

19. **分离 (Detach):**
    - **功能:** 测试 `ResourceFetcher` 的分离 (Detach) 机制，以及分离后其属性的行为。
    - **假设输入:** 创建一个 `ResourceFetcher` 并执行分离操作。
    - **预期输出:**  分离后，`ResourceFetcher` 仍然可以访问其属性，并且属性对象被标记为已分离。
    - **与内部实现相关:**  可能涉及到对象生命周期管理和资源清理。

20. **重复预加载允许优先级改变 (DuplicatePreloadAllowsPriorityChange):**
    - **功能:** 测试当重复的预加载请求到达时，是否允许更改已有预加载资源的优先级。
    - **假设输入:** 先发起一个低优先级的推测性预加载，然后发起一个相同资源的高优先级的推测性预加载。
    - **预期输出:**  后来的高优先级请求会更新已有预加载资源的优先级。
    - **与 Web 技术关系:**  允许开发者在后续的预加载声明中调整资源的加载优先级。

**用户或编程常见的使用错误示例:**

- **错误地假设预加载会立即完成并阻塞后续操作:** 预加载是异步的，不能依赖其立即完成。
- **在不需要同步加载的场景下使用同步请求:** 会阻塞浏览器渲染，影响用户体验。
- **不理解缓存控制策略，导致资源无法正确缓存或更新。**
- **在跨域场景下错误地认为预加载的资源可以被直接访问，需要注意 CORS 设置。**
- **重复声明相同的预加载资源，可能造成性能浪费，虽然浏览器会进行一定的优化。**

**总结:**

这部分 `ResourceFetcherTest` 重点测试了 `ResourceFetcher` 在处理各种预加载场景下的行为，包括 Link 预加载和推测性预加载。 它验证了预加载的合并、优先级管理、与缓存的交互，以及在不同 browsing context 下的隔离性。 此外，还涵盖了对特定 URL 类型（如 data: 和 cid:）以及 HTTP 缓存策略（如 stale-while-revalidate）的处理。 这些测试确保了 `ResourceFetcher` 能够高效、正确地管理资源的获取，从而提升网页加载性能和用户体验。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/resource_fetcher_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
alResource(const WebString& url) {
    url_test_helpers::RegisterMockedURLLoad(
        KURL(url), test::PlatformTestDataPath(kTestResourceFilename),
        kTestResourceMimeType, mock_factory_);
  }

  void Request(const WebString& url) {
    auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
    auto* fetcher = MakeGarbageCollected<ResourceFetcher>(ResourceFetcherInit(
        properties->MakeDetachable(), context_, task_runner_,
        base::MakeRefCounted<scheduler::FakeTaskRunner>(),
        MakeGarbageCollected<TestLoaderFactory>(mock_factory_),
        MakeGarbageCollected<MockContextLifecycleNotifier>(),
        nullptr /* back_forward_cache_loader_helper */));
    ResourceRequest resource_request(url);
    resource_request.SetRequestContext(
        mojom::blink::RequestContextType::INTERNAL);
    FetchParameters fetch_params =
        FetchParameters::CreateForTest(std::move(resource_request));
    RawResource::Fetch(fetch_params, fetcher, nullptr);
    mock_factory_->ServeAsynchronousRequests();
  }

 private:
  URLLoaderMockFactory* mock_factory_;
  MockFetchContext* context_;
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};

TEST_F(ResourceFetcherTest, SynchronousRequest) {
  KURL url("http://127.0.0.1:8000/foo.png");
  RegisterMockedURLLoad(url);

  auto* fetcher = CreateFetcher();
  ResourceRequest resource_request(url);
  resource_request.SetRequestContext(
      mojom::blink::RequestContextType::INTERNAL);
  FetchParameters fetch_params =
      FetchParameters::CreateForTest(std::move(resource_request));
  fetch_params.MakeSynchronous();
  Resource* resource = RawResource::Fetch(fetch_params, fetcher, nullptr);
  EXPECT_TRUE(resource->IsLoaded());
  EXPECT_EQ(ResourceLoadPriority::kHighest,
            resource->GetResourceRequest().Priority());
}

TEST_F(ResourceFetcherTest, PingPriority) {
  KURL url("http://127.0.0.1:8000/foo.png");
  RegisterMockedURLLoad(url);

  auto* fetcher = CreateFetcher();
  ResourceRequest resource_request(url);
  resource_request.SetRequestContext(mojom::blink::RequestContextType::PING);
  FetchParameters fetch_params =
      FetchParameters::CreateForTest(std::move(resource_request));
  Resource* resource = RawResource::Fetch(fetch_params, fetcher, nullptr);
  EXPECT_EQ(ResourceLoadPriority::kVeryLow,
            resource->GetResourceRequest().Priority());
}

TEST_F(ResourceFetcherTest, PreloadResourceTwice) {
  auto* fetcher = CreateFetcher();

  KURL url("http://127.0.0.1:8000/foo.png");
  RegisterMockedURLLoad(url);

  FetchParameters fetch_params_original =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_params_original.SetLinkPreload(true);
  Resource* resource =
      MockResource::Fetch(fetch_params_original, fetcher, nullptr);
  ASSERT_TRUE(resource);
  EXPECT_TRUE(resource->IsLinkPreload());
  EXPECT_TRUE(fetcher->ContainsAsPreload(resource));
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();

  FetchParameters fetch_params =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_params.SetLinkPreload(true);
  Resource* new_resource = MockResource::Fetch(fetch_params, fetcher, nullptr);
  EXPECT_EQ(resource, new_resource);
  EXPECT_TRUE(fetcher->ContainsAsPreload(resource));

  fetcher->ClearPreloads(ResourceFetcher::kClearAllPreloads);
  EXPECT_FALSE(fetcher->ContainsAsPreload(resource));
  EXPECT_FALSE(MemoryCache::Get()->Contains(resource));
  EXPECT_TRUE(resource->IsUnusedPreload());
}

TEST_F(ResourceFetcherTest, LinkPreloadResourceAndUse) {
  auto* fetcher = CreateFetcher();

  KURL url("http://127.0.0.1:8000/foo.png");
  RegisterMockedURLLoad(url);

  // Link preload preload scanner
  FetchParameters fetch_params_original =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_params_original.SetLinkPreload(true);
  Resource* resource =
      MockResource::Fetch(fetch_params_original, fetcher, nullptr);
  ASSERT_TRUE(resource);
  EXPECT_TRUE(resource->IsLinkPreload());
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();

  // Resource created by preload scanner
  FetchParameters fetch_params_preload_scanner =
      FetchParameters::CreateForTest(ResourceRequest(url));
  Resource* preload_scanner_resource =
      MockResource::Fetch(fetch_params_preload_scanner, fetcher, nullptr);
  EXPECT_EQ(resource, preload_scanner_resource);
  EXPECT_TRUE(resource->IsLinkPreload());

  // Resource created by parser
  FetchParameters fetch_params =
      FetchParameters::CreateForTest(ResourceRequest(url));
  Persistent<MockResourceClient> client =
      MakeGarbageCollected<MockResourceClient>();
  Resource* new_resource = MockResource::Fetch(fetch_params, fetcher, client);
  EXPECT_EQ(resource, new_resource);
  EXPECT_TRUE(resource->IsLinkPreload());

  // DCL reached
  fetcher->ClearPreloads(ResourceFetcher::kClearSpeculativeMarkupPreloads);
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource));
  EXPECT_FALSE(resource->IsUnusedPreload());
}

TEST_F(ResourceFetcherTest, PreloadMatchWithBypassingCache) {
  auto* fetcher = CreateFetcher();
  KURL url("http://127.0.0.1:8000/foo.png");
  RegisterMockedURLLoad(url);

  FetchParameters fetch_params_original =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_params_original.SetLinkPreload(true);
  Resource* resource =
      MockResource::Fetch(fetch_params_original, fetcher, nullptr);
  ASSERT_TRUE(resource);
  EXPECT_TRUE(resource->IsLinkPreload());
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();

  FetchParameters fetch_params_second =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_params_second.MutableResourceRequest().SetCacheMode(
      mojom::FetchCacheMode::kBypassCache);
  Resource* second_resource =
      MockResource::Fetch(fetch_params_second, fetcher, nullptr);
  EXPECT_EQ(resource, second_resource);
  EXPECT_TRUE(resource->IsLinkPreload());
}

TEST_F(ResourceFetcherTest, CrossFramePreloadMatchIsNotAllowed) {
  auto* fetcher = CreateFetcher();
  auto* fetcher2 = CreateFetcher();

  KURL url("http://127.0.0.1:8000/foo.png");
  RegisterMockedURLLoad(url);

  FetchParameters fetch_params_original =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_params_original.SetLinkPreload(true);
  Resource* resource =
      MockResource::Fetch(fetch_params_original, fetcher, nullptr);
  ASSERT_TRUE(resource);
  EXPECT_TRUE(resource->IsLinkPreload());
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();

  FetchParameters fetch_params_second =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_params_second.MutableResourceRequest().SetCacheMode(
      mojom::FetchCacheMode::kBypassCache);
  Resource* second_resource =
      MockResource::Fetch(fetch_params_second, fetcher2, nullptr);

  EXPECT_NE(resource, second_resource);
  EXPECT_TRUE(resource->IsLinkPreload());
}

TEST_F(ResourceFetcherTest, RepetitiveLinkPreloadShouldBeMerged) {
  auto* fetcher = CreateFetcher();

  KURL url("http://127.0.0.1:8000/foo.png");
  RegisterMockedURLLoad(url);

  FetchParameters fetch_params_for_request =
      FetchParameters::CreateForTest(ResourceRequest(url));
  FetchParameters fetch_params_for_preload =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_params_for_preload.SetLinkPreload(true);

  Resource* resource1 =
      MockResource::Fetch(fetch_params_for_preload, fetcher, nullptr);
  ASSERT_TRUE(resource1);
  EXPECT_TRUE(resource1->IsUnusedPreload());
  EXPECT_TRUE(fetcher->ContainsAsPreload(resource1));
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();

  // The second preload fetch returns the first preload.
  Resource* resource2 =
      MockResource::Fetch(fetch_params_for_preload, fetcher, nullptr);
  EXPECT_TRUE(fetcher->ContainsAsPreload(resource1));
  EXPECT_TRUE(resource1->IsUnusedPreload());
  EXPECT_EQ(resource1, resource2);

  // preload matching
  Resource* resource3 =
      MockResource::Fetch(fetch_params_for_request, fetcher, nullptr);
  EXPECT_EQ(resource1, resource3);
  EXPECT_FALSE(fetcher->ContainsAsPreload(resource1));
  EXPECT_FALSE(resource1->IsUnusedPreload());
}

TEST_F(ResourceFetcherTest, RepetitiveSpeculativePreloadShouldBeMerged) {
  auto* fetcher = CreateFetcher();

  KURL url("http://127.0.0.1:8000/foo.png");
  RegisterMockedURLLoad(url);

  FetchParameters fetch_params_for_request =
      FetchParameters::CreateForTest(ResourceRequest(url));
  FetchParameters fetch_params_for_preload =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_params_for_preload.SetSpeculativePreloadType(
      FetchParameters::SpeculativePreloadType::kInDocument);

  Resource* resource1 =
      MockResource::Fetch(fetch_params_for_preload, fetcher, nullptr);
  ASSERT_TRUE(resource1);
  EXPECT_TRUE(resource1->IsUnusedPreload());
  EXPECT_TRUE(fetcher->ContainsAsPreload(resource1));
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();

  // The second preload fetch returns the first preload.
  Resource* resource2 =
      MockResource::Fetch(fetch_params_for_preload, fetcher, nullptr);
  EXPECT_TRUE(fetcher->ContainsAsPreload(resource1));
  EXPECT_TRUE(resource1->IsUnusedPreload());
  EXPECT_EQ(resource1, resource2);

  // preload matching
  Resource* resource3 =
      MockResource::Fetch(fetch_params_for_request, fetcher, nullptr);
  EXPECT_EQ(resource1, resource3);
  EXPECT_FALSE(fetcher->ContainsAsPreload(resource1));
  EXPECT_FALSE(resource1->IsUnusedPreload());
}

TEST_F(ResourceFetcherTest, SpeculativePreloadShouldBePromotedToLinkPreload) {
  auto* fetcher = CreateFetcher();

  KURL url("http://127.0.0.1:8000/foo.png");
  RegisterMockedURLLoad(url);

  FetchParameters fetch_params_for_request =
      FetchParameters::CreateForTest(ResourceRequest(url));
  FetchParameters fetch_params_for_speculative_preload =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_params_for_speculative_preload.SetSpeculativePreloadType(
      FetchParameters::SpeculativePreloadType::kInDocument);
  FetchParameters fetch_params_for_link_preload =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_params_for_link_preload.SetLinkPreload(true);

  Resource* resource1 = MockResource::Fetch(
      fetch_params_for_speculative_preload, fetcher, nullptr);
  ASSERT_TRUE(resource1);
  EXPECT_TRUE(resource1->IsUnusedPreload());
  EXPECT_FALSE(resource1->IsLinkPreload());
  EXPECT_TRUE(fetcher->ContainsAsPreload(resource1));
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();

  // The second preload fetch returns the first preload.
  Resource* resource2 =
      MockResource::Fetch(fetch_params_for_link_preload, fetcher, nullptr);
  EXPECT_TRUE(fetcher->ContainsAsPreload(resource1));
  EXPECT_TRUE(resource1->IsUnusedPreload());
  EXPECT_TRUE(resource1->IsLinkPreload());
  EXPECT_EQ(resource1, resource2);

  // preload matching
  Resource* resource3 =
      MockResource::Fetch(fetch_params_for_request, fetcher, nullptr);
  EXPECT_EQ(resource1, resource3);
  EXPECT_FALSE(fetcher->ContainsAsPreload(resource1));
  EXPECT_FALSE(resource1->IsUnusedPreload());
  EXPECT_TRUE(resource1->IsLinkPreload());
}

TEST_F(ResourceFetcherTest, Revalidate304) {
  scoped_refptr<const SecurityOrigin> source_origin =
      SecurityOrigin::CreateUniqueOpaque();

  KURL url("http://127.0.0.1:8000/foo.html");
  Resource* resource =
      RawResource::CreateForTest(url, source_origin, ResourceType::kRaw);
  AddResourceToMemoryCache(resource);

  ResourceResponse response(url);
  response.SetHttpStatusCode(304);
  response.SetHttpHeaderField(http_names::kETag, AtomicString("1234567890"));
  resource->ResponseReceived(response);
  resource->FinishForTest();

  auto* fetcher = CreateFetcher(
      *MakeGarbageCollected<TestResourceFetcherProperties>(source_origin));
  ResourceRequest resource_request(url);
  resource_request.SetRequestContext(
      mojom::blink::RequestContextType::INTERNAL);
  FetchParameters fetch_params =
      FetchParameters::CreateForTest(std::move(resource_request));
  platform_->GetURLLoaderMockFactory()->RegisterURL(url, WebURLResponse(), "");
  Resource* new_resource = RawResource::Fetch(fetch_params, fetcher, nullptr);
  fetcher->StopFetching();

  EXPECT_NE(resource, new_resource);
}

TEST_F(ResourceFetcherTest, LinkPreloadResourceMultipleFetchersAndMove) {
  auto* fetcher = CreateFetcher();
  auto* fetcher2 = CreateFetcher();

  KURL url("http://127.0.0.1:8000/foo.png");
  RegisterMockedURLLoad(url);

  FetchParameters fetch_params_original =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_params_original.SetLinkPreload(true);
  Resource* resource =
      MockResource::Fetch(fetch_params_original, fetcher, nullptr);
  ASSERT_TRUE(resource);
  EXPECT_TRUE(resource->IsLinkPreload());
  EXPECT_EQ(0, fetcher->BlockingRequestCount());

  // Resource created by parser on the second fetcher
  FetchParameters fetch_params2 =
      FetchParameters::CreateForTest(ResourceRequest(url));
  Persistent<MockResourceClient> client2 =
      MakeGarbageCollected<MockResourceClient>();
  Resource* new_resource2 =
      MockResource::Fetch(fetch_params2, fetcher2, client2);
  EXPECT_NE(resource, new_resource2);
  EXPECT_EQ(0, fetcher2->BlockingRequestCount());
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();
}

// TODO(crbug.com/850785): Reenable this.
#if BUILDFLAG(IS_ANDROID)
#define MAYBE_ContentTypeDataURL DISABLED_ContentTypeDataURL
#else
#define MAYBE_ContentTypeDataURL ContentTypeDataURL
#endif
TEST_F(ResourceFetcherTest, MAYBE_ContentTypeDataURL) {
  auto* fetcher = CreateFetcher();
  FetchParameters fetch_params = FetchParameters::CreateForTest(
      ResourceRequest("data:text/testmimetype,foo"));
  Resource* resource = MockResource::Fetch(fetch_params, fetcher, nullptr);
  ASSERT_TRUE(resource);
  EXPECT_EQ(ResourceStatus::kCached, resource->GetStatus());
  EXPECT_EQ("text/testmimetype", resource->GetResponse().MimeType());
  EXPECT_EQ("text/testmimetype", resource->GetResponse().HttpContentType());
}

// Request with the Content-ID scheme must not be canceled, even if there is no
// MHTMLArchive to serve them.
// Note: Not blocking it is important because there are some embedders of
// Android WebView that are intercepting Content-ID URLs and serve their own
// resources. Please see https://crbug.com/739658.
TEST_F(ResourceFetcherTest, ContentIdURL) {
  KURL url("cid:0123456789@example.com");
  ResourceResponse response(url);
  response.SetHttpStatusCode(200);
  platform_->GetURLLoaderMockFactory()->RegisterURL(
      url, WrappedResourceResponse(response),
      test::PlatformTestDataPath(kTestResourceFilename));

  auto* fetcher = CreateFetcher();

  // Subresource case.
  {
    ResourceRequest resource_request(url);
    resource_request.SetRequestContext(mojom::blink::RequestContextType::VIDEO);
    FetchParameters fetch_params =
        FetchParameters::CreateForTest(std::move(resource_request));
    RawResource* resource =
        RawResource::FetchMedia(fetch_params, fetcher, nullptr);
    ASSERT_NE(nullptr, resource);
    EXPECT_FALSE(resource->ErrorOccurred());
  }
}

TEST_F(ResourceFetcherTest, StaleWhileRevalidate) {
  scoped_refptr<const SecurityOrigin> source_origin =
      SecurityOrigin::CreateUniqueOpaque();
  auto* observer = MakeGarbageCollected<TestResourceLoadObserver>();
  MockFetchContext* context = MakeGarbageCollected<MockFetchContext>();
  auto* fetcher = CreateFetcher(
      *MakeGarbageCollected<TestResourceFetcherProperties>(source_origin),
      context);
  fetcher->SetResourceLoadObserver(observer);

  KURL url("http://127.0.0.1:8000/foo.html");
  FetchParameters fetch_params =
      FetchParameters::CreateForTest(ResourceRequest(url));

  ResourceResponse response(url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(
      http_names::kCacheControl,
      AtomicString("max-age=0, stale-while-revalidate=40"));

  platform_->GetURLLoaderMockFactory()->RegisterURL(
      url, WrappedResourceResponse(response),
      test::PlatformTestDataPath(kTestResourceFilename));
  Resource* resource = MockResource::Fetch(fetch_params, fetcher, nullptr);
  ASSERT_TRUE(resource);

  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();
  EXPECT_TRUE(resource->IsLoaded());
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource));

  ResourceRequest resource_request(url);
  resource_request.SetRequestContext(
      mojom::blink::RequestContextType::INTERNAL);
  FetchParameters fetch_params2 =
      FetchParameters::CreateForTest(std::move(resource_request));
  Resource* new_resource = MockResource::Fetch(fetch_params2, fetcher, nullptr);
  EXPECT_EQ(resource, new_resource);
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();
  EXPECT_TRUE(resource->IsLoaded());

  // Advance the clock, make sure the original resource gets removed from the
  // memory cache after the revalidation completes.
  task_environment_.AdvanceClock(base::Seconds(1));
  ResourceResponse revalidate_response(url);
  revalidate_response.SetHttpStatusCode(200);
  platform_->GetURLLoaderMockFactory()->UnregisterURL(url);
  platform_->GetURLLoaderMockFactory()->RegisterURL(
      url, WrappedResourceResponse(revalidate_response),
      test::PlatformTestDataPath(kTestResourceFilename));
  new_resource = MockResource::Fetch(fetch_params2, fetcher, nullptr);
  EXPECT_EQ(resource, new_resource);
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource));
  static_cast<scheduler::FakeTaskRunner*>(fetcher->GetTaskRunner().get())
      ->RunUntilIdle();
  std::optional<PartialResourceRequest> swr_request =
      observer->GetLastRequest();
  ASSERT_TRUE(swr_request.has_value());
  EXPECT_EQ(ResourceLoadPriority::kVeryLow, swr_request->Priority());
  platform_->GetURLLoaderMockFactory()->ServeAsynchronousRequests();
  EXPECT_FALSE(MemoryCache::Get()->Contains(resource));
}

TEST_F(ResourceFetcherTest, CachedResourceShouldNotCrashByNullURL) {
  auto* fetcher = CreateFetcher();

  // Make sure |cached_resources_map_| is not empty, so that HashMap lookup
  // won't take a fast path.
  KURL url("http://127.0.0.1:8000/foo.html");
  ResourceResponse response(url);
  response.SetHttpStatusCode(200);
  platform_->GetURLLoaderMockFactory()->RegisterURL(
      url, WrappedResourceResponse(response),
      test::PlatformTestDataPath(kTestResourceFilename));
  FetchParameters fetch_params =
      FetchParameters::CreateForTest(ResourceRequest(url));
  MockResource::Fetch(fetch_params, fetcher, nullptr);
  ASSERT_NE(fetcher->CachedResource(url), nullptr);

  ASSERT_EQ(fetcher->CachedResource(KURL()), nullptr);
}

TEST_F(ResourceFetcherTest, DeprioritizeSubframe) {
  auto& properties = *MakeGarbageCollected<TestResourceFetcherProperties>();
  auto* fetcher = CreateFetcher(properties);
  ResourceRequest request(KURL("https://www.example.com/"));

  {
    // Subframe deprioritization is disabled (main frame case).
    properties.SetIsOutermostMainFrame(true);
    properties.SetIsSubframeDeprioritizationEnabled(false);
    const auto priority = fetcher->ComputeLoadPriorityForTesting(
        ResourceType::kScript, request, ResourcePriority::kNotVisible,
        FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kNotSpeculative,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false /* is_link_preload */);
    EXPECT_EQ(priority, ResourceLoadPriority::kHigh);
  }

  {
    // Subframe deprioritization is disabled (nested frame case).
    properties.SetIsOutermostMainFrame(false);
    properties.SetIsSubframeDeprioritizationEnabled(false);
    const auto priority = fetcher->ComputeLoadPriorityForTesting(
        ResourceType::kScript, request, ResourcePriority::kNotVisible,
        FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kNotSpeculative,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false /* is_link_preload */);
    EXPECT_EQ(priority, ResourceLoadPriority::kHigh);
  }

  {
    // Subframe deprioritization is enabled (main frame case), kHigh.
    properties.SetIsOutermostMainFrame(true);
    properties.SetIsSubframeDeprioritizationEnabled(true);
    const auto priority = fetcher->ComputeLoadPriorityForTesting(
        ResourceType::kScript, request, ResourcePriority::kNotVisible,
        FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kNotSpeculative,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false /* is_link_preload */);
    EXPECT_EQ(priority, ResourceLoadPriority::kHigh);
  }

  {
    // Subframe deprioritization is enabled (nested frame case), kHigh => kLow.
    properties.SetIsOutermostMainFrame(false);
    properties.SetIsSubframeDeprioritizationEnabled(true);
    const auto priority = fetcher->ComputeLoadPriorityForTesting(
        ResourceType::kScript, request, ResourcePriority::kNotVisible,
        FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kNotSpeculative,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false /* is_link_preload */);
    EXPECT_EQ(priority, ResourceLoadPriority::kLow);
  }
  {
    // Subframe deprioritization is enabled (main frame case), kMedium.
    properties.SetIsOutermostMainFrame(true);
    properties.SetIsSubframeDeprioritizationEnabled(true);
    const auto priority = fetcher->ComputeLoadPriorityForTesting(
        ResourceType::kMock, request, ResourcePriority::kNotVisible,
        FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kNotSpeculative,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false /* is_link_preload */);
    EXPECT_EQ(priority, ResourceLoadPriority::kMedium);
  }

  {
    // Subframe deprioritization is enabled (nested frame case), kMedium =>
    // kLowest.
    properties.SetIsOutermostMainFrame(false);
    properties.SetIsSubframeDeprioritizationEnabled(true);
    const auto priority = fetcher->ComputeLoadPriorityForTesting(
        ResourceType::kMock, request, ResourcePriority::kNotVisible,
        FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kNotSpeculative,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false /* is_link_preload */);
    EXPECT_EQ(priority, ResourceLoadPriority::kLowest);
  }
}

TEST_F(ResourceFetcherTest, BoostImagePriority) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(features::kBoostImagePriority);
  auto& properties = *MakeGarbageCollected<TestResourceFetcherProperties>();
  auto* fetcher = CreateFetcher(properties);
  ResourceRequest request(KURL("https://www.example.com/"));

  // A "small" image should not get a priority boost or count against the
  // 5-image limit.
  {
    properties.SetIsOutermostMainFrame(true);
    properties.SetIsSubframeDeprioritizationEnabled(false);
    const auto priority = fetcher->ComputeLoadPriorityForTesting(
        ResourceType::kImage, request, ResourcePriority::kNotVisible,
        FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kInDocument,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false /* is_link_preload */,
        10 /* resource_width*/, 10 /* resource_height*/);
    EXPECT_EQ(priority, ResourceLoadPriority::kLow);
  }

  // Test an image with just one of width or height set to zero but the other
  // dimension not specified to make sure it is also treated as "small"
  {
    properties.SetIsOutermostMainFrame(true);
    properties.SetIsSubframeDeprioritizationEnabled(false);
    const auto priority = fetcher->ComputeLoadPriorityForTesting(
        ResourceType::kImage, request, ResourcePriority::kNotVisible,
        FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kInDocument,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false /* is_link_preload */,
        0 /* resource_width*/, std::nullopt /* resource_height*/);
    EXPECT_EQ(priority, ResourceLoadPriority::kLow);
  }
  {
    properties.SetIsOutermostMainFrame(true);
    properties.SetIsSubframeDeprioritizationEnabled(false);
    const auto priority = fetcher->ComputeLoadPriorityForTesting(
        ResourceType::kImage, request, ResourcePriority::kNotVisible,
        FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kInDocument,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false /* is_link_preload */,
        std::nullopt /* resource_width*/, 0 /* resource_height*/);
    EXPECT_EQ(priority, ResourceLoadPriority::kLow);
  }

  // The next 5 images that are not-small should be boosted to Medium priority.
  // Test both an explicit size over 10,000px^2 as well as no size specified
  // which defaults to not-small.
  // #1 - 200x200 = 40000px^2.
  {
    properties.SetIsOutermostMainFrame(true);
    properties.SetIsSubframeDeprioritizationEnabled(false);
    const auto priority = fetcher->ComputeLoadPriorityForTesting(
        ResourceType::kImage, request, ResourcePriority::kNotVisible,
        FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kInDocument,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false /* is_link_preload */,
        200 /* resource_width*/, 200 /* resource_height*/);
    EXPECT_EQ(priority, ResourceLoadPriority::kMedium);
  }
  // #2 - non-zero width but no height.
  {
    properties.SetIsOutermostMainFrame(true);
    properties.SetIsSubframeDeprioritizationEnabled(false);
    const auto priority = fetcher->ComputeLoadPriorityForTesting(
        ResourceType::kImage, request, ResourcePriority::kNotVisible,
        FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kInDocument,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false /* is_link_preload */,
        200 /* resource_width*/, std::nullopt /* resource_height*/);
    EXPECT_EQ(priority, ResourceLoadPriority::kMedium);
  }
  // #3 - non-zero height but no width.
  {
    properties.SetIsOutermostMainFrame(true);
    properties.SetIsSubframeDeprioritizationEnabled(false);
    const auto priority = fetcher->ComputeLoadPriorityForTesting(
        ResourceType::kImage, request, ResourcePriority::kNotVisible,
        FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kInDocument,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false /* is_link_preload */,
        std::nullopt /* resource_width*/, 200 /* resource_height*/);
    EXPECT_EQ(priority, ResourceLoadPriority::kMedium);
  }
  // #4-5 - neither height nor width.
  for (int i = 4; i <= 5; i++) {
    properties.SetIsOutermostMainFrame(true);
    properties.SetIsSubframeDeprioritizationEnabled(false);
    const auto priority = fetcher->ComputeLoadPriorityForTesting(
        ResourceType::kImage, request, ResourcePriority::kNotVisible,
        FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kInDocument,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false /* is_link_preload */);
    EXPECT_EQ(priority, ResourceLoadPriority::kMedium);
  }

  // After the 5th non-small image, images should get the default Low priority.
  {
    properties.SetIsOutermostMainFrame(true);
    properties.SetIsSubframeDeprioritizationEnabled(false);
    const auto priority = fetcher->ComputeLoadPriorityForTesting(
        ResourceType::kImage, request, ResourcePriority::kNotVisible,
        FetchParameters::DeferOption::kNoDefer,
        FetchParameters::SpeculativePreloadType::kInDocument,
        RenderBlockingBehavior::kNonBlocking,
        mojom::blink::ScriptType::kClassic, false /* is_link_preload */);
    EXPECT_EQ(priority, ResourceLoadPriority::kLow);
  }
}

TEST_F(ResourceFetcherTest, IsPotentiallyLCPElement) {
  for (const auto& test_cases :
       {std::make_pair("medium", ResourceLoadPriority::kMedium),
        std::make_pair("high", ResourceLoadPriority::kHigh),
        std::make_pair("very_high", ResourceLoadPriority::kVeryHigh)}) {
    const char* kPrioritySetting = test_cases.first;
    const ResourceLoadPriority kExpectedPriority = test_cases.second;
    base::test::ScopedFeatureList scoped_feature_list;
    scoped_feature_list.InitWithFeaturesAndParameters(
        {{features::kLCPCriticalPathPredictor,
          {{features::kLCPCriticalPathAdjustImageLoadPriority.name, "true"},
           {features::kLCPCriticalPathPredictorImageLoadPriority.name,
            kPrioritySetting}}}},
        {});
    auto& properties = *MakeGarbageCollected<TestResourceFetcherProperties>();
    auto* fetcher = CreateFetcher(properties);
    ResourceRequest request(KURL("https://www.example.com/"));

    // Resources for Potentially LCP Elements get a `kExpectedPriority`.
    {
      properties.SetIsOutermostMainFrame(true);
      properties.SetIsSubframeDeprioritizationEnabled(false);
      const auto priority = fetcher->ComputeLoadPriorityForTesting(
          ResourceType::kImage, request, ResourcePriority::kNotVisible,
          FetchParameters::DeferOption::kNoDefer,
          FetchParameters::SpeculativePreloadType::kInDocument,
          RenderBlockingBehavior::kNonBlocking,
          mojom::blink::ScriptType::kClassic, /* is_link_preload=*/false,
          /* resource_width=*/10, /* resource_height=*/10,
          /* is_potentially_lcp_element=*/true);
      EXPECT_EQ(priority, kExpectedPriority)
          << "priority_setting: " << kPrioritySetting;
    }
  }
}

TEST_F(ResourceFetcherTest, Detach) {
  DetachableResourceFetcherProperties& properties =
      MakeGarbageCollected<TestResourceFetcherProperties>()->MakeDetachable();
  auto* const fetcher = MakeGarbageCollected<ResourceFetcher>(
      ResourceFetcherInit(properties, MakeGarbageCollected<MockFetchContext>(),
                          CreateTaskRunner(), CreateTaskRunner(),
                          MakeGarbageCollected<TestLoaderFactory>(
                              platform_->GetURLLoaderMockFactory()),
                          MakeGarbageCollected<MockContextLifecycleNotifier>(),
                          nullptr /* back_forward_cache_loader_helper */));

  EXPECT_EQ(&properties, &fetcher->GetProperties());
  EXPECT_FALSE(properties.IsDetached());

  fetcher->ClearContext();
  // ResourceFetcher::GetProperties always returns the same object.
  EXPECT_EQ(&properties, &fetcher->GetProperties());

  EXPECT_TRUE(properties.IsDetached());
}

TEST_F(ResourceFetcherTest, DuplicatePreloadAllowsPriorityChange) {
  auto* fetcher = CreateFetcher();

  KURL url("http://127.0.0.1:8000/foo.png");
  RegisterMockedURLLoad(url);

  FetchParameters fetch_params_for_request =
      FetchParameters::CreateForTest(ResourceRequest(url));
  FetchParameters fetch_params_for_preload =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_params_for_preload.SetSpeculativePreloadType(
      FetchParameters::SpeculativePreloadType::kInDocument);
  fetch_params_for_preload.SetFetchPriorityHint(
      mojom::blink::FetchPriorityHint::kLow);

  Resource* resource1 =
      MockResource::Fetch(fetch_params_for_preload, fetcher, nullptr);
  ASSERT_TRUE(resource1);
  EXPECT_TRUE(resource1->IsUnusedPreload());
  EXPECT_TRUE(fetcher->ContainsAsPreload(resource1));
  EXPECT_EQ(ResourceLoadPriority::kLow,
            resource1->GetResourceRequest().Priority());

  // The second preload fetch returns the first preload but boosts the priority.
  FetchParameters fetch_params_for_preload2 =
      FetchParameters::CreateForTest(ResourceRequest(url));
  fetch_params_for_preload2.SetSpeculativePreloadType(
      FetchParameters::SpeculativePreloadType::kInDocument);
  fetch_params_for_preload2.SetFetchPriorityHint(
      mojom::blink::FetchPriorityHint::kHigh);
  Resource* resource2 =
      MockResource::Fetch(fetch_params_for_preload2, fetcher, nullptr);

  EXPECT_TRUE(fetcher->ContainsAsPreload(resource1));
  EXPECT_TRUE(resource1->IsUnusedPreload());
  EXPECT_EQ(resource1, resource2);
  EXPECT_EQ(ResourceLoadPriority::kHigh,
            resource1->GetResourceRequest().Priority());

  platform_->GetURLLoaderMockFactory()->ServeAsynchronousReques
```