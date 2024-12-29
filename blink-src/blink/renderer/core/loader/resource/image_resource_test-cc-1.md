Response:
The user wants to understand the functionality of the `image_resource_test.cc` file in the Chromium Blink engine, focusing on its relation to web technologies (JavaScript, HTML, CSS), logical reasoning through input/output examples, common user/programming errors, debugging scenarios, and a summary of its purpose as the second part of a two-part request.

**Plan:**

1. **General Functionality:** Identify the primary purpose of the file based on its name and content (unit testing for `ImageResource`).
2. **Web Technology Relationship:** Analyze the test cases for interactions with image loading, which is crucial for HTML (displaying images) and CSS (background images, etc.). Determine if JavaScript interaction is directly tested (likely not, as it's a unit test).
3. **Logical Reasoning (Input/Output):**  Examine specific test cases that demonstrate a clear input (e.g., a specific image type, a revalidation scenario) and the expected output (e.g., image dimensions, successful load, error status).
4. **Common Errors:** Identify test cases that simulate error scenarios, such as decode errors, and relate them to potential user/programming mistakes (e.g., broken image URLs, incorrect image formats).
5. **Debugging Scenario:**  Infer how the test cases could be used as debugging clues, particularly when image loading issues arise. This involves understanding the step-by-step nature of the tests.
6. **Summary:** Condense the identified functionalities into a concise summary.

**Detailed Steps:**

* **Functionality:** The file name strongly suggests it's for testing the `ImageResource` class. The content confirms this with numerous `TEST_F` blocks.
* **Web Technology Relationship:**
    * **HTML:** Images are fundamental to HTML (`<img>` tag). The tests implicitly cover this by verifying successful loading and decoding.
    * **CSS:** CSS can use images for backgrounds (`background-image`), list markers, etc. While not directly tested, the image loading mechanism is the same.
    * **JavaScript:** JavaScript can manipulate images (e.g., creating `Image` objects, dynamically changing `src`). This file primarily tests the core loading logic, not direct JS interaction.
* **Logical Reasoning:**
    * **Input:** Providing different image formats (JPEG, SVG, WebP), simulating network responses (success, failure, partial content), triggering revalidation.
    * **Output:** Verifying image properties (width, height), checking for errors (`ErrorOccurred`), observing state changes (loading, finished), checking image type (`IsA<BitmapImage>`).
* **Common Errors:**
    * `CancelOnDecodeError`, `DecodeErrorWithEmptyBody`, `PartialContentWithoutDimensions`: These tests explicitly simulate scenarios leading to decoding failures, which can happen due to corrupted image data, incorrect file formats, or incomplete downloads.
* **Debugging Scenario:** Imagine a user reports an image not displaying. A developer could use these tests to:
    1. Verify basic loading of different image types (JPEG, SVG, WebP).
    2. Check revalidation logic if the image is cached.
    3. Investigate potential decode errors if the image appears broken.
    4. Look at partial content handling if the image loads incompletely.
* **Summary:** Combine the identified functionalities into a brief overview of the file's purpose.
这是对 `blink/renderer/core/loader/resource/image_resource_test.cc` 文件功能的归纳总结。基于您提供的代码片段，我们可以总结出以下功能：

**主要功能:**

这个测试文件主要用于测试 `ImageResource` 类的各种功能和行为。`ImageResource` 类在 Blink 渲染引擎中负责管理图像资源的加载、解码、缓存和通知等操作。

**具体测试的功能点 (基于提供的代码片段):**

* **资源重新验证 (Revalidation):**
    * 测试了在资源重新验证过程中，图像从一种格式成功切换到另一种格式的情况 (例如从 SVG 切换到 JPEG)。
    * 测试了在资源重新验证过程中，图像从一种格式切换到另一种格式但最终是相同格式的情况 (例如从 SVG 切换到 SVG)。
    * 测试了资源重新验证失败的情况，并验证了图像资源的状态和通知是否正确。

* **资源修剪 (Pruning):**
    * 测试了当 `ImageResource` 不再被使用时（`IsAlive()` 返回 false），调用 `Prune()` 方法后，图像数据是否仍然存在。这涉及到内存管理和资源回收的策略。

* **解码错误处理 (Decode Error Handling):**
    * 测试了在解码过程中发生错误的情况，例如当接收到的数据不是有效的图像数据时，`ImageResource` 如何处理，包括设置错误状态、通知观察者等。
    * 测试了当接收到图像响应但没有接收到任何数据时（空 Body）的解码错误处理。
    * 测试了接收到部分图像数据但无法解码出图像尺寸时的解码错误处理。

* **周期性刷新 (Periodic Flush):**
    * 测试了在接收到图像数据时，`ImageResource` 如何周期性地触发图像更新通知，即使图像数据尚未完全加载完成。这对于渐进式 JPEG 或动画图像等场景非常重要。

* **延迟失效 (Deferred Invalidation):**
    * 测试了图像资源加载完成和动画更新时，观察者是否可以延迟失效通知。这涉及到渲染优化的策略。

* **WebP 嗅探 (WebP Sniffing):**
    * 测试了 `ImageResource` 是否能够正确识别不同类型的 WebP 图像（有损、无损、扩展格式）。这依赖于对图像文件头的解析。

* **实例计数器 (Instance Counters):**
    * 测试了 `ImageResource` 实例的创建和销毁是否正确地更新了全局计数器，用于监控资源使用情况。
    * 特别测试了来自用户代理样式表的图像资源是否被单独计数。

* **重新验证策略指标 (Revalidation Policy Metrics):**
    * 测试了不同加载场景下（例如预加载、延迟加载）的图像资源如何影响缓存的重新验证策略，并记录相应的直方图数据用于性能分析。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML (`<img>` 标签):**  当 HTML 中使用 `<img>` 标签加载图片时，Blink 引擎会创建 `ImageResource` 对象来管理该图片的加载。这个测试文件中的测试用例模拟了各种加载和重新验证的场景，确保 `ImageResource` 能正确处理不同情况，最终让图片在页面上正确显示。
    * **假设输入:**  一个包含 `<img src="image.jpg">` 的 HTML 页面。
    * **输出:**  `ImageResource` 成功加载并解码 `image.jpg`，并在渲染树中创建对应的图像节点，最终在浏览器窗口中显示该图片。

* **CSS (`background-image` 属性):**  CSS 的 `background-image` 属性也可以加载图片。与 HTML 的 `<img>` 类似，Blink 同样会使用 `ImageResource` 来管理这些背景图片的加载。
    * **假设输入:**  一个包含 CSS 规则 `body { background-image: url("bg.png"); }` 的页面。
    * **输出:**  `ImageResource` 尝试加载 `bg.png`。如果加载失败（例如解码错误），背景图片将不会显示。

* **JavaScript (`Image` 对象):**  JavaScript 可以使用 `Image` 对象来预加载或动态创建图片。这些操作也会触发 `ImageResource` 的创建和管理。
    * **假设输入:**  JavaScript 代码 `const img = new Image(); img.src = "logo.gif";`
    * **输出:**  `ImageResource` 开始加载 `logo.gif`。测试文件中的周期性刷新测试就模拟了这种加载过程，确保即使在数据未完全加载时，也能及时通知渲染引擎进行更新，对于 GIF 等动画图片尤其重要。

**逻辑推理的假设输入与输出:**

* **测试用例: `FailedRevalidationSvgToJpeg`**
    * **假设输入:**
        1. 首先加载一个 SVG 图像资源。
        2. 发起重新验证请求，但服务器返回的是一个 JPEG 图像。
    * **预期输出:**
        1. 初始加载 SVG 成功，`image_resource->GetContent()->GetImage()` 返回一个 SVG 图像对象。
        2. 重新验证后，`image_resource->GetContent()->GetImage()` 返回一个 JPEG 图像对象 (`IsA<BitmapImage>` 为 true)。
        3. 图像的尺寸更新为 JPEG 图像的尺寸 (`kJpegImageWidth`, `kJpegImageHeight`)。
        4. `observer->ImageChangedCount()` 的值会增加，表示图像内容发生了变化。

**涉及用户或者编程常见的使用错误举例说明:**

* **解码错误 (`CancelOnDecodeError`, `DecodeErrorWithEmptyBody`):**
    * **用户错误:**  用户可能下载了损坏的图片文件，或者尝试访问一个返回非图像数据的 URL。
    * **编程错误:**  开发者可能在后端配置错误，导致服务器返回的 Content-Type 不匹配实际的文件内容，或者网络传输过程中发生了数据损坏。

* **部分内容无法解码 (`PartialContentWithoutDimensions`):**
    * **用户错误:**  网络连接不稳定导致图片下载不完整。
    * **编程错误:**  服务器端实现了分段传输 (Range Request) 但返回的数据不符合预期，或者客户端处理分段数据时出现逻辑错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入网址或点击链接。**
2. **浏览器解析 HTML 代码。**
3. **当浏览器遇到 `<img>` 标签或 CSS 的 `background-image` 属性时，会发起图片资源的请求。**
4. **Blink 渲染引擎中的资源加载器 (ResourceFetcher) 负责发起网络请求。**
5. **如果请求的资源是图片，则会创建 `ImageResource` 对象来处理该资源。**
6. **`ImageResource` 对象接收网络响应的数据。**
7. **`ImageResource` 尝试解码接收到的数据。**
8. **如果解码成功，`ImageResource` 会通知相关的观察者 (例如渲染树中的 Image 节点)，以便更新页面显示。**
9. **如果解码失败 (例如测试用例 `CancelOnDecodeError`)，`ImageResource` 会设置错误状态，观察者会收到加载失败的通知，最终可能导致页面上图片显示为 broken image 图标。**
10. **如果需要重新验证图片资源 (例如浏览器缓存过期)，`ImageResource` 会发起新的请求，并可能触发类似 `FailedRevalidationSvgToJpeg` 这样的测试场景。**

当开发者在调试图片加载问题时，`image_resource_test.cc` 中的测试用例可以作为重要的参考：

* **如果图片显示为 broken image：** 可以查看 `CancelOnDecodeError` 或 `DecodeErrorWithEmptyBody` 相关的测试用例，验证是否是解码错误导致。
* **如果图片在重新加载后显示异常：** 可以参考 `FailedRevalidationSvgToJpeg` 等测试用例，检查资源重新验证的逻辑是否正确。
* **如果动画图片显示不正常：** 可以查看周期性刷新相关的测试用例，确认是否及时触发了渲染更新。

**归纳总结 (第2部分):**

总而言之，`blink/renderer/core/loader/resource/image_resource_test.cc` 文件是 Blink 引擎中至关重要的单元测试文件，它全面地测试了 `ImageResource` 类的核心功能，包括资源的加载、解码、重新验证、错误处理、内存管理以及与渲染引擎的交互机制。这些测试用例覆盖了各种正常和异常情况，确保了 Blink 引擎能够可靠地处理各种类型的图像资源，为网页上正确显示图片提供了坚实的基础。通过这些测试，开发者可以验证和保证图片加载逻辑的正确性，并为调试实际应用中遇到的图片加载问题提供有力的线索。

Prompt: 
```
这是目录为blink/renderer/core/loader/resource/image_resource_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
n(kJpegImage)));

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(2, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_TRUE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
  EXPECT_EQ(kJpegImageWidth, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(kJpegImageHeight,
            image_resource->GetContent()->GetImage()->height());

  image_resource->SetRevalidatingRequest(ResourceRequest(url));
  ReceiveResponse(image_resource, url, "image/svg+xml", kSvgImage);

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(3, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_FALSE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
  EXPECT_EQ(200, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(200, image_resource->GetContent()->GetImage()->height());
}

TEST_F(ImageResourceTest, FailedRevalidationSvgToJpeg) {
  KURL url("http://127.0.0.1:8000/foo");
  ImageResource* image_resource = ImageResource::CreateForTest(url);
  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  ReceiveResponse(image_resource, url, "image/svg+xml", kSvgImage);

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(1, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_FALSE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
  EXPECT_EQ(200, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(200, image_resource->GetContent()->GetImage()->height());

  image_resource->SetRevalidatingRequest(ResourceRequest(url));
  ReceiveResponse(image_resource, url, "image/jpeg",
                  base::as_chars(base::span(kJpegImage)));

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(3, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_TRUE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
  EXPECT_EQ(kJpegImageWidth, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(kJpegImageHeight,
            image_resource->GetContent()->GetImage()->height());
}

TEST_F(ImageResourceTest, FailedRevalidationSvgToSvg) {
  KURL url("http://127.0.0.1:8000/foo");
  ImageResource* image_resource = ImageResource::CreateForTest(url);
  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  ReceiveResponse(image_resource, url, "image/svg+xml", kSvgImage);

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(1, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_FALSE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
  EXPECT_EQ(200, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(200, image_resource->GetContent()->GetImage()->height());

  image_resource->SetRevalidatingRequest(ResourceRequest(url));
  ReceiveResponse(image_resource, url, "image/svg+xml", kSvgImage2);

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(2, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_FALSE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
  EXPECT_EQ(300, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(300, image_resource->GetContent()->GetImage()->height());
}

// Tests for pruning.

TEST_F(ImageResourceTest, Prune) {
  KURL url("http://127.0.0.1:8000/foo");
  ImageResource* image_resource = ImageResource::CreateForTest(url);

  ReceiveResponse(image_resource, url, "image/jpeg",
                  base::as_chars(base::span(kJpegImage)));

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(kJpegImageWidth, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(kJpegImageHeight,
            image_resource->GetContent()->GetImage()->height());

  EXPECT_FALSE(image_resource->IsAlive());

  image_resource->Prune();

  EXPECT_TRUE(image_resource->GetContent()->HasImage());

  blink::test::RunPendingTasks();
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(kJpegImageWidth, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(kJpegImageHeight,
            image_resource->GetContent()->GetImage()->height());
}

TEST_F(ImageResourceTest, CancelOnDecodeError) {
  KURL test_url(kTestURL);
  ScopedMockedURLLoad scoped_mocked_url_load(test_url, GetTestFilePath());

  ResourceFetcher* fetcher = CreateFetcher();
  FetchParameters params =
      FetchParameters::CreateForTest(ResourceRequest(test_url));
  ImageResource* image_resource = ImageResource::Fetch(params, fetcher);
  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  ResourceResponse resource_response(test_url);
  resource_response.SetMimeType(AtomicString("image/jpeg"));
  resource_response.SetExpectedContentLength(18);
  image_resource->Loader()->DidReceiveResponse(
      WrappedResourceResponse(resource_response),
      /*body=*/mojo::ScopedDataPipeConsumerHandle(),
      /*cached_metadata=*/std::nullopt);

  EXPECT_EQ(0, observer->ImageChangedCount());

  image_resource->Loader()->DidReceiveDataForTesting(
      base::span_from_cstring("notactuallyanimage"));

  EXPECT_EQ(ResourceStatus::kDecodeError, image_resource->GetStatus());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_EQ(ResourceStatus::kDecodeError,
            observer->StatusOnImageNotifyFinished());
  EXPECT_EQ(1, observer->ImageChangedCount());
  EXPECT_FALSE(image_resource->IsLoading());
}

TEST_F(ImageResourceTest, DecodeErrorWithEmptyBody) {
  KURL test_url(kTestURL);
  ScopedMockedURLLoad scoped_mocked_url_load(test_url, GetTestFilePath());

  ResourceFetcher* fetcher = CreateFetcher();
  FetchParameters params =
      FetchParameters::CreateForTest(ResourceRequest(test_url));
  ImageResource* image_resource = ImageResource::Fetch(params, fetcher);
  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  ResourceResponse resource_response(test_url);
  resource_response.SetMimeType(AtomicString("image/jpeg"));
  image_resource->Loader()->DidReceiveResponse(
      WrappedResourceResponse(resource_response),
      /*body=*/mojo::ScopedDataPipeConsumerHandle(),
      /*cached_metadata=*/std::nullopt);

  EXPECT_EQ(ResourceStatus::kPending, image_resource->GetStatus());
  EXPECT_FALSE(observer->ImageNotifyFinishedCalled());
  EXPECT_EQ(0, observer->ImageChangedCount());

  image_resource->Loader()->DidFinishLoading(base::TimeTicks(), 0, 0, 0);

  EXPECT_EQ(ResourceStatus::kDecodeError, image_resource->GetStatus());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_EQ(ResourceStatus::kDecodeError,
            observer->StatusOnImageNotifyFinished());
  EXPECT_EQ(1, observer->ImageChangedCount());
  EXPECT_FALSE(image_resource->IsLoading());
}

// Testing DecodeError that occurs in didFinishLoading().
// This is similar to DecodeErrorWithEmptyBody, but with non-empty body.
TEST_F(ImageResourceTest, PartialContentWithoutDimensions) {
  KURL test_url(kTestURL);
  ScopedMockedURLLoad scoped_mocked_url_load(test_url, GetTestFilePath());

  ResourceRequest resource_request(test_url);
  resource_request.SetHttpHeaderField(http_names::kLowerRange,
                                      AtomicString("bytes=0-2"));
  FetchParameters params =
      FetchParameters::CreateForTest(std::move(resource_request));
  ResourceFetcher* fetcher = CreateFetcher();
  ImageResource* image_resource = ImageResource::Fetch(params, fetcher);
  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  ResourceResponse partial_response(test_url);
  partial_response.SetMimeType(AtomicString("image/jpeg"));
  partial_response.SetExpectedContentLength(
      kJpegImageSubrangeWithoutDimensionsLength);
  partial_response.SetHttpStatusCode(206);
  partial_response.SetHttpHeaderField(
      http_names::kLowerContentRange,
      BuildContentRange(kJpegImageSubrangeWithoutDimensionsLength,
                        sizeof(kJpegImage)));

  image_resource->Loader()->DidReceiveResponse(
      WrappedResourceResponse(partial_response),
      /*body=*/mojo::ScopedDataPipeConsumerHandle(),
      /*cached_metadata=*/std::nullopt);
  image_resource->Loader()->DidReceiveDataForTesting(
      base::make_span(reinterpret_cast<const char*>(kJpegImage),
                      kJpegImageSubrangeWithoutDimensionsLength));

  EXPECT_EQ(ResourceStatus::kPending, image_resource->GetStatus());
  EXPECT_FALSE(observer->ImageNotifyFinishedCalled());
  EXPECT_EQ(0, observer->ImageChangedCount());

  image_resource->Loader()->DidFinishLoading(
      base::TimeTicks(), kJpegImageSubrangeWithoutDimensionsLength,
      kJpegImageSubrangeWithoutDimensionsLength,
      kJpegImageSubrangeWithoutDimensionsLength);

  EXPECT_EQ(ResourceStatus::kDecodeError, image_resource->GetStatus());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_EQ(ResourceStatus::kDecodeError,
            observer->StatusOnImageNotifyFinished());
  EXPECT_EQ(1, observer->ImageChangedCount());
  EXPECT_FALSE(image_resource->IsLoading());
}

TEST_F(ImageResourceTest, PeriodicFlushTest) {
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform;

  std::unique_ptr<DummyPageHolder> page_holder =
      std::make_unique<DummyPageHolder>(
          gfx::Size(800, 600), /*chrome_client=*/nullptr,
          MakeGarbageCollected<EmptyLocalFrameClient>());

  KURL test_url(kTestURL);
  ScopedMockedURLLoad scoped_mocked_url_load(test_url, GetTestFilePath());

  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      page_holder->GetFrame().GetTaskRunner(TaskType::kInternalTest);
  scoped_refptr<base::SingleThreadTaskRunner> unfreezable_task_runner =
      page_holder->GetFrame().GetTaskRunner(TaskType::kInternalTest);
  auto* context = MakeGarbageCollected<MockFetchContext>();
  auto& properties =
      MakeGarbageCollected<TestResourceFetcherProperties>()->MakeDetachable();
  auto* fetcher = MakeGarbageCollected<ResourceFetcher>(ResourceFetcherInit(
      properties, context, task_runner, unfreezable_task_runner,
      MakeGarbageCollected<TestLoaderFactory>(),
      page_holder->GetFrame().DomWindow(),
      nullptr /* back_forward_cache_loader_helper */));
  auto frame_scheduler = std::make_unique<scheduler::FakeFrameScheduler>();
  auto* scheduler = MakeGarbageCollected<ResourceLoadScheduler>(
      ResourceLoadScheduler::ThrottlingPolicy::kNormal,
      ResourceLoadScheduler::ThrottleOptionOverride::kNone, properties,
      frame_scheduler.get(), *MakeGarbageCollected<DetachableConsoleLogger>(),
      /*loading_behavior_observer=*/nullptr);
  ImageResource* image_resource = ImageResource::CreateForTest(test_url);

  // Ensure that |image_resource| has a loader.
  [[maybe_unused]] auto* loader = MakeGarbageCollected<ResourceLoader>(
      fetcher, scheduler, image_resource, page_holder->GetFrame().DomWindow());

  image_resource->NotifyStartLoad();

  auto* observer = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  // Send the image response.
  ResourceResponse resource_response(NullURL());
  resource_response.SetMimeType(AtomicString("image/jpeg"));
  resource_response.SetExpectedContentLength(sizeof(kJpegImage2));
  image_resource->ResponseReceived(resource_response);

  // This is number is sufficiently large amount of bytes necessary for the
  // image to be created (since the size is known). This was determined by
  // appending one byte at a time (with flushes) until the image was decoded.
  size_t meaningful_image_size = 280;
  base::span<const char> remaining = base::as_chars(base::span(kJpegImage2));
  image_resource->AppendData(remaining.first(meaningful_image_size));
  remaining = remaining.subspan(meaningful_image_size);

  EXPECT_FALSE(image_resource->ErrorOccurred());
  EXPECT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_EQ(1, observer->ImageChangedCount());

  platform->RunForPeriodSeconds(1.);
  platform->AdvanceClockSeconds(1.);

  // Sanity check that we created an image after appending |meaningfulImageSize|
  // bytes just once.
  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_EQ(1, observer->ImageChangedCount());

  for (int flush_count = 1; flush_count <= 3; ++flush_count) {
    // For each of the iteration that appends data, we don't expect
    // |imageChangeCount()| to change, since the time is adjusted by 0.2001
    // seconds (it's greater than 0.2 to avoid double precision problems).
    // After 5 appends, we breach the flush interval and the flush count
    // increases.
    for (int i = 0; i < 5; ++i) {
      SCOPED_TRACE(i);
      image_resource->AppendData(remaining.first(1u));
      remaining = remaining.subspan(1u);

      EXPECT_FALSE(image_resource->ErrorOccurred());
      ASSERT_TRUE(image_resource->GetContent()->HasImage());
      EXPECT_EQ(flush_count, observer->ImageChangedCount());

      platform->RunForPeriodSeconds(0.2001);
    }
  }

  // Increasing time by a large number only causes one extra flush.
  platform->RunForPeriodSeconds(10.);
  platform->AdvanceClockSeconds(10.);
  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(4, observer->ImageChangedCount());

  // Append the rest of the data and finish (which causes another flush).
  image_resource->AppendData(remaining);
  image_resource->FinishForTest();

  EXPECT_FALSE(image_resource->ErrorOccurred());
  ASSERT_TRUE(image_resource->GetContent()->HasImage());
  EXPECT_FALSE(image_resource->GetContent()->GetImage()->IsNull());
  EXPECT_EQ(5, observer->ImageChangedCount());
  EXPECT_TRUE(observer->ImageNotifyFinishedCalled());
  EXPECT_TRUE(IsA<BitmapImage>(image_resource->GetContent()->GetImage()));
  EXPECT_EQ(50, image_resource->GetContent()->GetImage()->width());
  EXPECT_EQ(50, image_resource->GetContent()->GetImage()->height());
}

TEST_F(ImageResourceTest, DeferredInvalidation) {
  ImageResource* image_resource = ImageResource::CreateForTest(NullURL());
  auto* obs = MakeGarbageCollected<MockImageResourceObserver>(
      image_resource->GetContent());

  // Image loaded.
  ReceiveResponse(image_resource, NullURL(), "image/jpeg",
                  base::as_chars(base::span(kJpegImage)));
  EXPECT_EQ(obs->ImageChangedCount(), 2);
  EXPECT_EQ(obs->Defer(), ImageResourceObserver::CanDeferInvalidation::kNo);

  // Image animated.
  static_cast<ImageObserver*>(image_resource->GetContent())
      ->Changed(image_resource->GetContent()->GetImage());
  EXPECT_EQ(obs->ImageChangedCount(), 3);
  EXPECT_EQ(obs->Defer(), ImageResourceObserver::CanDeferInvalidation::kYes);
}

// A lossy 2x2 WebP image.
constexpr unsigned char kLossyWebPImage[] = {
    0x52, 0x49, 0x46, 0x46, 0x40, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50,
    0x56, 0x50, 0x38, 0x20, 0x34, 0x00, 0x00, 0x00, 0xB0, 0x01, 0x00, 0x9D,
    0x01, 0x2A, 0x02, 0x00, 0x02, 0x00, 0x00, 0xC0, 0x12, 0x25, 0x00, 0x4E,
    0x80, 0x21, 0xDF, 0xC0, 0x5D, 0x80, 0x00, 0xFE, 0x9B, 0x87, 0xFA, 0x8F,
    0xF8, 0xA0, 0x1E, 0xD7, 0xC8, 0x70, 0x88, 0x0B, 0x6C, 0x54, 0x7F, 0xC0,
    0x7F, 0x12, 0xFE, 0xC0, 0xBC, 0x70, 0x65, 0xB6, 0xC1, 0x00, 0x00, 0x00};

// A lossless 2x2 WebP image.
constexpr unsigned char kLosslessWebPImage[] = {
    0x52, 0x49, 0x46, 0x46, 0x3A, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42,
    0x50, 0x56, 0x50, 0x38, 0x4C, 0x2E, 0x00, 0x00, 0x00, 0x2F, 0x01,
    0x40, 0x00, 0x00, 0x1F, 0x20, 0x10, 0x20, 0x72, 0xCC, 0x09, 0x13,
    0x27, 0x48, 0x40, 0x42, 0xB8, 0xE3, 0xB9, 0x95, 0x12, 0x12, 0x10,
    0x2B, 0x0C, 0xB4, 0xD8, 0x1C, 0x75, 0xFE, 0x03, 0xDB, 0xBA, 0x09,
    0x40, 0x26, 0x6D, 0x1B, 0x6A, 0xBB, 0x6B, 0x11, 0xFD, 0x8F, 0x1D};

// An extended lossy 2x2 WebP image.
constexpr unsigned char kExtendedWebPImage[] = {
    0x52, 0x49, 0x46, 0x46, 0x60, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50,
    0x56, 0x50, 0x38, 0x58, 0x0A, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x41, 0x4C, 0x50, 0x48, 0x05, 0x00,
    0x00, 0x00, 0x00, 0xFF, 0xFF, 0xE9, 0xAE, 0x00, 0x56, 0x50, 0x38, 0x20,
    0x34, 0x00, 0x00, 0x00, 0xB0, 0x01, 0x00, 0x9D, 0x01, 0x2A, 0x02, 0x00,
    0x02, 0x00, 0x00, 0xC0, 0x12, 0x25, 0x94, 0x02, 0x74, 0x01, 0x0E, 0xFE,
    0x02, 0xEC, 0x00, 0xFE, 0x9B, 0x87, 0xFA, 0x8F, 0xF8, 0xA0, 0x1E, 0xD7,
    0xC8, 0x70, 0x88, 0x0B, 0x6C, 0x54, 0x7A, 0xFB, 0xCA, 0x1D, 0x89, 0x90,
    0xDD, 0x27, 0xEA, 0x7F, 0x28, 0x00, 0x00, 0x00};

TEST_F(ImageResourceTest, WebPSniffing) {
  KURL test_url(kTestURL);

  // Test lossy WebP image.
  ImageResource* image_resource = ImageResource::CreateForTest(test_url);
  image_resource->AppendData(base::as_chars(base::span(kLossyWebPImage)));
  EXPECT_EQ(1, image_resource->GetContent()->GetCompressionFormat());

  // Test lossless WebP image.
  image_resource = ImageResource::CreateForTest(test_url);
  image_resource->AppendData(base::as_chars(base::span(kLosslessWebPImage)));
  EXPECT_EQ(2, image_resource->GetContent()->GetCompressionFormat());

  // Test extended WebP image.
  image_resource = ImageResource::CreateForTest(test_url);
  image_resource->AppendData(base::as_chars(base::span(kExtendedWebPImage)));
  EXPECT_EQ(1, image_resource->GetContent()->GetCompressionFormat());
}

}  // namespace

class ImageResourceCounterTest : public testing::Test {
 public:
  ImageResourceCounterTest() = default;
  ~ImageResourceCounterTest() override = default;

  void CreateImageResource(const char* url_part, bool ua_resource) {
    // Create a unique fake data url.
    String url = StringView("data:image/png;base64,") + url_part;

    // Setup the fetcher and request.
    ResourceFetcher* fetcher = CreateFetcher();
    KURL test_url(url);
    ResourceRequest request = ResourceRequest(test_url);
    FetchParameters fetch_params =
        FetchParameters::CreateForTest(std::move(request));
    scheduler::FakeTaskRunner* task_runner =
        static_cast<scheduler::FakeTaskRunner*>(fetcher->GetTaskRunner().get());
    task_runner->SetTime(1);

    // Mark it as coming from a UA stylesheet (if needed).
    if (ua_resource) {
      fetch_params.MutableOptions().initiator_info.name =
          fetch_initiator_type_names::kUacss;
    }

    // Fetch the ImageResource.
    ImageResource::Fetch(fetch_params, fetcher);
    task_runner->RunUntilIdle();
  }

  int GetResourceCount() const {
    return InstanceCounters::CounterValue(InstanceCounters::kResourceCounter);
  }

  int GetUACSSResourceCount() const {
    return InstanceCounters::CounterValue(
        InstanceCounters::kUACSSResourceCounter);
  }

  test::TaskEnvironment task_environment_;
};

TEST_F(ImageResourceCounterTest, InstanceCounters) {
  // Get the current resource count.
  int current_count = GetResourceCount();
  int current_ua_count = GetUACSSResourceCount();

  // Create a non-UA sourced image.
  CreateImageResource("a", false);

  // Check the instance counters have been updated.
  EXPECT_EQ(++current_count, GetResourceCount());
  EXPECT_EQ(current_ua_count, GetUACSSResourceCount());

  // Create another non-UA sourced image.
  CreateImageResource("b", false);

  // Check the instance counters have been updated.
  EXPECT_EQ(++current_count, GetResourceCount());
  EXPECT_EQ(current_ua_count, GetUACSSResourceCount());
}

TEST_F(ImageResourceCounterTest, InstanceCounters_UserAgent) {
  // Get the current resource count.
  int current_count = GetResourceCount();
  int current_ua_count = GetUACSSResourceCount();

  // Create a non-UA sourced image.
  CreateImageResource("c", false);

  // Check the instance counters have been updated.
  EXPECT_EQ(++current_count, GetResourceCount());
  EXPECT_EQ(current_ua_count, GetUACSSResourceCount());

  // Create a UA sourced image.
  CreateImageResource("d", true);

  // Check the instance counters have been updated.
  EXPECT_EQ(++current_count, GetResourceCount());
  EXPECT_EQ(++current_ua_count, GetUACSSResourceCount());
}

TEST_F(ImageResourceCounterTest, RevalidationPolicyMetrics) {
  base::HistogramTester histogram_tester;
  auto* fetcher = CreateFetcher();

  KURL test_url("http://127.0.0.1:8000/img.png");
  ScopedMockedURLLoad url_load(test_url, GetTestFilePath());

  // Test image preloads are immediately loaded.
  FetchParameters fetch_params =
      FetchParameters::CreateForTest(ResourceRequest(test_url));
  fetch_params.SetLinkPreload(true);

  Resource* resource = ImageResource::Fetch(fetch_params, fetcher);
  ASSERT_TRUE(resource);
  EXPECT_TRUE(MemoryCache::Get()->Contains(resource));

  Resource* new_resource = ImageResource::Fetch(fetch_params, fetcher);
  EXPECT_EQ(resource, new_resource);

  // Test histograms.
  histogram_tester.ExpectTotalCount(
      "Blink.MemoryCache.RevalidationPolicy.Preload.Image", 2);
  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Preload.Image",
      static_cast<int>(ResourceFetcher::RevalidationPolicyForMetrics::kLoad),
      1);
  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Preload.Image",
      static_cast<int>(ResourceFetcher::RevalidationPolicyForMetrics::kUse), 1);

  KURL test_url_deferred("http://127.0.0.1:8000/img_deferred.ttf");
  ScopedMockedURLLoad url_load_deferred(test_url_deferred, GetTestFilePath());

  // Test deferred image loads are correctly counted.
  FetchParameters fetch_params_deferred =
      FetchParameters::CreateForTest(ResourceRequest(test_url_deferred));
  fetch_params_deferred.SetLazyImageDeferred();
  resource = ImageResource::Fetch(fetch_params_deferred, fetcher);
  ASSERT_TRUE(resource);
  histogram_tester.ExpectTotalCount(
      "Blink.MemoryCache.RevalidationPolicy.Image", 1);
  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Image",
      static_cast<int>(ResourceFetcher::RevalidationPolicyForMetrics::kDefer),
      1);
  fetcher->StartLoad(resource);
  histogram_tester.ExpectTotalCount(
      "Blink.MemoryCache.RevalidationPolicy.Image", 2);
  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Image",
      static_cast<int>(ResourceFetcher::RevalidationPolicyForMetrics::
                           kPreviouslyDeferredLoad),
      1);
  // Load the same deferred image again. Already-loaded resources shall be
  // counted as kUse.
  resource = ImageResource::Fetch(fetch_params_deferred, fetcher);
  histogram_tester.ExpectTotalCount(
      "Blink.MemoryCache.RevalidationPolicy.Image", 3);
  histogram_tester.ExpectBucketCount(
      "Blink.MemoryCache.RevalidationPolicy.Image",
      static_cast<int>(ResourceFetcher::RevalidationPolicyForMetrics::kUse), 1);
}

}  // namespace blink

"""


```