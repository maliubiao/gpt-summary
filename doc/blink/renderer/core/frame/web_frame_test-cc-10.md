Response:
The user wants a summary of the functionality of the provided C++ code snippet from `web_frame_test.cc`. I need to identify the main purposes of the test cases present in this section and relate them to web technologies like JavaScript, HTML, and CSS where applicable. I also need to look for examples of logical reasoning with potential inputs and outputs, and common user/programming errors that these tests might be preventing. Finally, I need to note that this is part 11 of 19.

Here's a breakdown of the tests and their functionalities:

1. **`ReloadIframe`**: Tests how iframe reloads are handled, particularly regarding caching and the creation of new `WebLocalFrame` instances.
2. **`TestMainFrameIntersectionChanged` and `MainFrameIntersectionChanged`**: Focuses on how the main frame's intersection with the viewport is calculated and communicated.
3. **`TestSameDocumentWithImageWebFrameClient` and `NavigateToSameNoConditionalRequestForSubresource`**: Checks if image subresource requests are made when navigating to the same document, and confirms default caching behavior.
4. **`WebNodeImageContents`**: Verifies the ability to extract image data (as a `SkBitmap`) from a `WebNode` representing an image, including data URLs.
5. **`WebNodeImageContentsWithOrientation`**: Similar to the previous test, but specifically handles images with EXIF orientation metadata, ensuring the extracted bitmap is correctly oriented.
6. **`TestStartStopCallbackWebFrameClient` and `PushStateStartsAndStops`**: Examines if `DidStartLoading` and `DidStopLoading` callbacks are correctly triggered during `pushState` navigation.
7. **`CommitSynchronousNavigationForAboutBlankAndCheckStorageKeyNonce`**: Checks if a synchronous navigation to `about:blank` preserves the original storage key nonce of a child frame.
8. **`TestDidNavigateCommitTypeWebFrameClient` and `SameDocumentHistoryNavigationCommitType`**:  Verifies that the correct `WebHistoryCommitType` is reported for same-document history navigations (like back/forward).
9. **`SameDocumentHistoryNavigationPropagatesSequenceNumber`**: Confirms that the history item's sequence number is correctly propagated during same-document history navigations.
10. **`FirstNonBlankSubframeNavigation`**: Tests that navigating a subframe with a non-blank initial URL creates a new history item.
11. **`overflowHiddenRewrite`**: Checks if JavaScript can dynamically change the scrollable attributes of a layer (using CSS `overflow: hidden`).
12. **`CurrentHistoryItem`**: Ensures that `currentHistoryItem` reflects the current page and not a provisional load.
13. **`FailCreateChildFrame` and `CreateChildFrameFailure`**: Tests the behavior when the `CreateChildFrame` method returns null, ensuring no crashes occur.
14. **`fixedPositionInFixedViewport`**: Examines how fixed-position elements are rendered within a fixed viewport, considering viewport scaling.
15. **`FrameViewMoveWithSetFrameRect`**:  Verifies that the frame's rectangle can be programmatically changed using `SetFrameRect`.
16. **`FrameViewScrollAccountsForBrowserControls`**: Tests how browser controls (like the address bar) affect the scrollable area of the frame.
17. **`MaximumScrollPositionCanBeNegative`**: Checks that the maximum scroll position can be negative in cases like RTL layouts with overview mode.
18. **`FullscreenLayerSize`**:  Ensures that when an element goes fullscreen, its size matches the viewport dimensions, and updates on device rotation.
19. **`FullscreenLayerNonScrollable`**: Verifies that viewports become non-scrollable when an element is in fullscreen mode and become scrollable again upon exiting fullscreen.
20. **`FullscreenMainFrame`**: Checks the scrollability of the main frame when the entire document goes into fullscreen.

Now, I will synthesize this information into the requested format.
这个代码片段是 Chromium Blink 引擎中 `web_frame_test.cc` 文件的一部分，主要功能是 **测试 `WebFrame` 及其相关功能**。因为它属于测试文件，所以它的核心功能是验证引擎在处理各种 Web 页面和交互时的行为是否符合预期。

由于这是第 11 部分，共 19 部分，可以推断这个文件相当庞大，包含了针对 `WebFrame` 各个方面的测试。

以下是这段代码中包含的测试用例的功能以及与 JavaScript、HTML、CSS 的关系，逻辑推理，以及可能的用户/编程错误：

**1. `ReloadIframe` 测试**

* **功能:**  测试 iframe 的重新加载行为。它验证了在重新加载包含 iframe 的页面时，新的 `WebLocalFrame` 对象是否被创建，并且使用了新的客户端（`TestCachePolicyWebFrameClient`）。同时，它也检查了重新加载时子帧的缓存策略 (`FetchCacheMode`)。
* **与 Web 技术的关系:**
    * **HTML:** 测试了 `<iframe>` 标签的重新加载行为。
    * **JavaScript:**  可能涉及到通过 JavaScript 触发 iframe 的重新加载，虽然这段代码没有直接展示，但 reload 操作通常可以通过 JavaScript 进行。
* **逻辑推理:**
    * **假设输入:** 一个包含 iframe 的 HTML 页面地址。
    * **输出:** 重新加载后，主框架客户端的子框架创建计数器会增加，并且会创建一个新的子框架客户端实例。旧的子框架和客户端实例会被替换。子框架的 `BeginNavigationCallCount` 会是 1，`CacheMode` 是 `kDefault`。
* **用户/编程常见错误:**
    *  开发者可能错误地假设重新加载 iframe 会重用旧的 `WebLocalFrame` 对象，导致状态管理上的问题。
    *  开发者可能不清楚 iframe 重新加载时的缓存策略，导致页面资源加载不符合预期。

**2. `TestMainFrameIntersectionChanged` 和 `MainFrameIntersectionChanged` 测试**

* **功能:** 测试主框架的可视区域交叉状态变化通知机制 (`OnMainFrameIntersectionChanged`)。当主框架的可视区域与其他区域（例如浏览器窗口）发生交叉变化时，会触发此回调。
* **与 Web 技术的关系:**
    * **CSS:**  CSS 布局和滚动会影响框架的可视区域。
    * **JavaScript:**  JavaScript 可以监听和处理可视区域变化事件 (Intersection Observer API)。这个测试验证了底层引擎是否正确计算并通知了这些变化。
* **逻辑推理:**
    * **假设输入:**  创建一个包含子框架的页面，并模拟主框架的可视区域交叉矩形和变换。
    * **输出:**  `OnMainFrameIntersectionChanged` 回调会被调用，并且 `MainFrameIntersection()` 方法返回的矩形应该与模拟的变换相匹配。
* **用户/编程常见错误:**
    *  开发者可能依赖于不准确的可视区域信息进行布局或性能优化，导致在不同滚动状态或设备上出现问题。

**3. `TestSameDocumentWithImageWebFrameClient` 和 `NavigateToSameNoConditionalRequestForSubresource` 测试**

* **功能:** 测试当导航到同一个文档时，子资源（例如图片）的请求行为。这个测试验证了在这种情况下，是否会发送新的请求，以及请求的缓存模式是否为默认值。
* **与 Web 技术的关系:**
    * **HTML:**  测试了包含 `<img>` 标签的 HTML 页面的导航行为。
    * **HTTP:**  涉及到 HTTP 请求的缓存策略 (`FetchCacheMode`)。
* **逻辑推理:**
    * **假设输入:**  一个包含图片的 HTML 页面地址。
    * **输出:** 首次加载页面后，图片资源会被请求。再次加载相同的页面时，如果缓存被清除，图片资源会再次被请求。`FinalizeRequest` 回调中 `request.GetCacheMode()` 应该返回 `kDefault`。
* **用户/编程常见错误:**
    *  开发者可能不理解浏览器在同文档导航时的资源加载策略，导致不必要的资源请求，影响性能。

**4. `WebNodeImageContents` 测试**

* **功能:** 测试从 `WebNode` 对象中提取图片内容的功能 (`ImageContents()`)。这个测试使用了 data URL 表示的图片。
* **与 Web 技术的关系:**
    * **HTML:** 测试了 `<img>` 标签和 data URL。
    * **JavaScript:**  虽然测试代码没有直接展示，但 JavaScript 可以操作 DOM 并获取节点信息。
* **逻辑推理:**
    * **假设输入:**  一个包含使用 data URL 的 `<img>` 标签的 HTML 片段。
    * **输出:**  `ImageContents()` 方法应该返回一个非空的 `SkBitmap` 对象，其尺寸和颜色与 data URL 中定义的图片一致。
* **用户/编程常见错误:**
    *  开发者可能错误地认为无法直接从 DOM 节点中获取图片像素数据。

**5. `WebNodeImageContentsWithOrientation` 测试**

* **功能:**  类似于上一个测试，但专门测试了处理带有 EXIF 旋转信息的 JPEG 图片的能力。它验证了 `ImageContents()` 方法是否能正确地根据 EXIF 信息旋转图片。
* **与 Web 技术的关系:**
    * **HTML:** 测试了 `<img>` 标签和 data URL。
    * **图片格式:** 涉及到 JPEG 图片的 EXIF 元数据。
* **逻辑推理:**
    * **假设输入:**  一个包含使用 data URL 的 `<img>` 标签，并且 data URL 指向一个带有旋转信息的 JPEG 图片。
    * **输出:** `ImageContents()` 方法应该返回一个旋转后的 `SkBitmap` 对象，其尺寸和颜色与原始图片旋转后的结果一致。
* **用户/编程常见错误:**
    *  开发者可能忽略图片中的 EXIF 旋转信息，导致图片显示方向错误。

**6. `TestStartStopCallbackWebFrameClient` 和 `PushStateStartsAndStops` 测试**

* **功能:** 测试在使用 `pushState` 进行导航时，`DidStartLoading()` 和 `DidStopLoading()` 回调是否会被正确调用。
* **与 Web 技术的关系:**
    * **JavaScript:**  测试了 `history.pushState()` API 的行为。
* **逻辑推理:**
    * **假设输入:**  一个包含 JavaScript 代码，使用 `pushState` 进行导航的 HTML 页面地址。
    * **输出:**  在 `pushState` 导航完成后，`StartLoadingCount()` 和 `StopLoadingCount()` 应该都为 2，表示导航开始和结束的回调都被调用了两次。
* **用户/编程常见错误:**
    *  开发者可能依赖 `DidStartLoading` 和 `DidStopLoading` 来追踪页面加载状态，如果这些回调没有按预期触发，可能会导致应用程序逻辑错误。

**7. `CommitSynchronousNavigationForAboutBlankAndCheckStorageKeyNonce` 测试**

* **功能:** 测试对于 `about:blank` 的同步导航是否会改变子框架的 `StorageKey` 的 `nonce` 值。
* **与 Web 技术的关系:**
    * **HTML:** 涉及到 `<iframe>` 标签和 `about:blank` URL。
    * **Storage API:** 测试了浏览器的存储机制。
* **逻辑推理:**
    * **假设输入:**  创建一个包含 iframe 的页面，并设置子框架的 `StorageKey` 的 `nonce` 值。然后，对子框架进行同步的 `about:blank` 导航。
    * **输出:**  同步导航后，子框架的 `StorageKey` 的 `nonce` 值应该保持不变。
* **用户/编程常见错误:**
    *  开发者可能错误地认为同步导航会重置或更改 `StorageKey`，导致在存储数据时出现意外行为。

**8. `TestDidNavigateCommitTypeWebFrameClient` 和 `SameDocumentHistoryNavigationCommitType` 测试**

* **功能:** 测试同文档历史导航（例如点击浏览器的后退/前进按钮）的提交类型 (`WebHistoryCommitType`) 是否正确。
* **与 Web 技术的关系:**
    * **JavaScript:**  涉及到 `history.pushState()` 和浏览器的后退/前进功能。
* **逻辑推理:**
    * **假设输入:**  加载一个使用 `pushState` 的页面，然后模拟后退操作。
    * **输出:**  `DidFinishSameDocumentNavigation` 回调会被调用，并且 `LastCommitType()` 应该返回 `kWebBackForwardCommit`。
* **用户/编程常见错误:**
    *  开发者可能需要根据不同的提交类型执行不同的逻辑，如果提交类型信息不正确，会导致应用程序行为异常。

**9. `SameDocumentHistoryNavigationPropagatesSequenceNumber` 测试**

* **功能:** 测试同文档历史导航是否会传播 `HistoryItem` 的序列号。
* **与 Web 技术的关系:**
    * **JavaScript:** 涉及到 `history.pushState()` 和浏览器的后退/前进功能。
* **逻辑推理:**
    * **假设输入:** 加载一个使用 `pushState` 的页面，然后模拟后退操作。
    * **输出:**  `HistoryItem` 的 `ItemSequenceNumber()` 应该与 `LayerTreeHost` 的 `primary_main_frame_item_sequence_number_for_testing()` 返回值相同。
* **用户/编程常见错误:**
    * 序列号用于跟踪历史记录，确保状态的一致性。不正确的传播可能导致状态同步问题。

**10. `FirstNonBlankSubframeNavigation` 测试**

* **功能:** 测试当一个具有非空初始 URL 的子框架进行导航时，是否会创建一个新的历史记录项。
* **与 Web 技术的关系:**
    * **HTML:** 涉及到 `<iframe>` 标签。
    * **JavaScript:**  可能涉及到通过 JavaScript 设置 iframe 的 `src` 属性。
* **逻辑推理:**
    * **假设输入:**  加载一个空白页面，然后通过 JavaScript 创建一个 `<iframe>` 并设置一个非空的 `src`。接着，再次导航该 iframe 到另一个 URL。
    * **输出:**  第二次导航后，`GetDocumentLoader()->ReplacesCurrentHistoryItem()` 应该返回 `false`，表示创建了一个新的历史记录项。
* **用户/编程常见错误:**
    *  开发者可能错误地认为子框架的首次非空导航会替换当前的历史记录项，导致历史记录管理上的混淆。

**11. `overflowHiddenRewrite` 测试**

* **功能:** 测试通过 JavaScript 动态修改元素的 `overflow: hidden` 样式是否会正确更新渲染层的滚动属性。
* **与 Web 技术的关系:**
    * **HTML:**  涉及到 HTML 元素的样式。
    * **CSS:**  测试了 `overflow: hidden` 属性的效果。
    * **JavaScript:**  测试了通过 JavaScript 修改 CSS 样式的能力。
* **逻辑推理:**
    * **假设输入:**  加载一个初始状态下不可滚动的页面，然后通过 JavaScript 修改某个元素的样式，使其可以滚动。
    * **输出:**  在修改样式之前，元素的 `cc::Layer` 应该不可滚动。修改样式之后，该 `cc::Layer` 应该变为可滚动。
* **用户/编程常见错误:**
    *  开发者可能认为修改 CSS 属性后，渲染层的属性会自动同步更新，但实际可能需要触发重新布局等操作。

**12. `CurrentHistoryItem` 测试**

* **功能:** 测试 `currentHistoryItem` 是否反映当前页面，而不是临时的加载状态。
* **与 Web 技术的关系:**
    * **JavaScript:**  涉及到 JavaScript 获取当前历史记录项。
* **逻辑推理:**
    * **假设输入:**  开始加载一个新页面。
    * **输出:**  在导航完成之前，`GetDocumentLoader()->GetHistoryItem()` 应该返回空。导航完成后，应该返回当前页面的历史记录项。
* **用户/编程常见错误:**
    * 开发者可能在页面加载过程中错误地访问 `currentHistoryItem`，导致获取到不完整或不准确的历史记录信息。

**13. `FailCreateChildFrame` 和 `CreateChildFrameFailure` 测试**

* **功能:** 测试当 `WebLocalFrameClient::createChildFrame()` 方法返回 `nullptr` 时，程序是否会崩溃。
* **与 Web 技术的关系:**
    * **HTML:** 涉及到 `<iframe>` 标签。
* **逻辑推理:**
    * **假设输入:** 加载一个包含创建子框架的 HTML 页面，并且模拟 `createChildFrame` 方法返回失败。
    * **输出:**  程序不应该崩溃，并且 `client.CallCount()` 应该为 1。
* **用户/编程常见错误:**
    *  这是一个防御性编程的测试，确保在子框架创建失败的情况下，浏览器不会发生崩溃。

**14. `fixedPositionInFixedViewport` 测试**

* **功能:** 测试在固定视口中，固定定位 (`position: fixed`) 的元素如何渲染。这涉及到 Android 平台的特定配置。
* **与 Web 技术的关系:**
    * **HTML:**  涉及到元素的结构。
    * **CSS:**  测试了 `position: fixed` 属性和视口单位。
* **逻辑推理:**
    * **假设输入:** 加载一个包含固定定位元素的 HTML 页面，并调整视口大小。
    * **输出:**  固定定位的元素的位置和尺寸应该根据视口大小进行调整，并符合固定定位的规则。
* **用户/编程常见错误:**
    *  开发者在移动端开发时，可能会遇到固定定位元素在不同视口大小下显示不正确的问题。

**15. `FrameViewMoveWithSetFrameRect` 测试**

* **功能:** 测试通过 `SetFrameRect` 方法移动 `FrameView` 的能力。
* **与 Web 技术的关系:**
    *  涉及到浏览器的渲染和布局。
* **逻辑推理:**
    * **假设输入:**  加载一个空白页面，获取主框架的 `FrameView`，然后使用 `SetFrameRect` 设置一个新的位置和尺寸。
    * **输出:**  `FrameView` 的 `FrameRect()` 方法应该返回新设置的矩形。
* **用户/编程常见错误:**
    *  开发者可能不清楚如何以编程方式改变 `FrameView` 的位置和尺寸。

**16. `FrameViewScrollAccountsForBrowserControls` 测试**

* **功能:** 测试 `FrameView` 的滚动行为是否考虑了浏览器控件（例如地址栏）的影响。这主要针对 Android 平台。
* **与 Web 技术的关系:**
    *  涉及到浏览器的渲染、布局和滚动。
* **逻辑推理:**
    * **假设输入:**  加载一个长页面，并模拟浏览器控件的显示和隐藏。
    * **输出:**  `FrameView` 的滚动偏移量和最大滚动偏移量应该根据浏览器控件的状态进行调整。
* **用户/编程常见错误:**
    *  开发者在移动端开发时，需要考虑浏览器控件对页面布局和滚动的影响。

**17. `MaximumScrollPositionCanBeNegative` 测试**

* **功能:** 测试在某些情况下，最大滚动位置可以是负数，例如在 RTL (Right-to-Left) 布局和 overview mode 下。
* **与 Web 技术的关系:**
    * **HTML:**  涉及到页面结构。
    * **CSS:**  涉及到 RTL 布局。
* **逻辑推理:**
    * **假设输入:**  加载一个 RTL 布局的页面，并启用 overview mode。
    * **输出:**  布局视口的 `MaximumScrollOffset().x()` 应该小于 0。
* **用户/编程常见错误:**
    *  开发者可能假设最大滚动位置总是非负的，导致在处理 RTL 布局时出现错误。

**18. `FullscreenLayerSize` 测试**

* **功能:** 测试当一个元素进入全屏模式时，其尺寸是否会调整为视口大小，并且在设备旋转后是否会更新。
* **与 Web 技术的关系:**
    * **HTML:** 涉及到元素结构。
    * **JavaScript:** 涉及到全屏 API (`requestFullscreen`)。
* **逻辑推理:**
    * **假设输入:**  加载一个包含可全屏元素的页面，请求元素进入全屏，然后模拟设备旋转。
    * **输出:**  全屏元素的逻辑宽度和高度应该与当前的视口尺寸一致。
* **用户/编程常见错误:**
    *  开发者可能不清楚全屏元素的尺寸调整行为，导致全屏显示不正确。

**19. `FullscreenLayerNonScrollable` 测试**

* **功能:** 测试当一个元素进入全屏模式时，视口是否变为不可滚动，并在退出全屏后恢复可滚动。
* **与 Web 技术的关系:**
    * **HTML:** 涉及到元素结构。
    * **JavaScript:** 涉及到全屏 API (`requestFullscreen`)。
* **逻辑推理:**
    * **假设输入:**  加载一个包含可全屏元素的页面，请求元素进入全屏，然后退出全屏。
    * **输出:**  在全屏模式下，布局视口和视觉视口的滚动节点都应该不可滚动。退出全屏后，它们应该变为可滚动。
* **用户/编程常见错误:**
    *  开发者可能错误地认为全屏模式下的页面仍然可以滚动。

**归纳一下它的功能:**

这段代码是 `web_frame_test.cc` 的一部分，专门用于测试 `WebFrame` 及其相关功能，例如 iframe 的重新加载、可视区域变化通知、同文档导航的资源请求、从 DOM 节点提取图片内容、`pushState` 导航、`about:blank` 同步导航、同文档历史导航的提交类型和序列号传播、子框架首次非空导航、动态修改 CSS 引起的滚动属性变化、当前历史记录项的正确性、子框架创建失败的处理、固定定位元素在固定视口中的渲染、`FrameView` 的移动和滚动、以及全屏模式下的行为。这些测试覆盖了 `WebFrame` 的多个重要方面，确保了 Chromium Blink 引擎在处理各种 Web 页面和用户交互时的稳定性和正确性。

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第11部分，共19部分，请归纳一下它的功能
```

### 源代码
```cpp
finish_creation);
  }
  void BeginNavigation(std::unique_ptr<WebNavigationInfo> info) override {
    cache_mode_ = info->url_request.GetCacheMode();
    begin_navigation_call_count_++;
    TestWebFrameClient::BeginNavigation(std::move(info));
  }

 private:
  mojom::FetchCacheMode cache_mode_;
  Vector<std::unique_ptr<TestCachePolicyWebFrameClient>> child_clients_;
  int begin_navigation_call_count_;
};

TEST_F(WebFrameTest, ReloadIframe) {
  RegisterMockedHttpURLLoad("iframe_reload.html");
  RegisterMockedHttpURLLoad("visible_iframe.html");

  TestCachePolicyWebFrameClient main_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "iframe_reload.html",
                                    &main_frame_client);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();

  ASSERT_EQ(1U, main_frame_client.ChildFrameCreationCount());
  TestCachePolicyWebFrameClient* child_client =
      &main_frame_client.ChildClient(0);
  auto* child_frame = To<WebLocalFrameImpl>(main_frame->FirstChild());
  EXPECT_EQ(child_client, child_frame->Client());
  EXPECT_EQ(1u, main_frame->GetFrame()->Tree().ScopedChildCount());
  EXPECT_EQ(1, child_client->BeginNavigationCallCount());
  EXPECT_EQ(mojom::FetchCacheMode::kDefault, child_client->GetCacheMode());

  frame_test_helpers::ReloadFrame(main_frame);

  // A new child WebLocalFrame should have been created with a new client.
  ASSERT_EQ(2U, main_frame_client.ChildFrameCreationCount());
  TestCachePolicyWebFrameClient* new_child_client =
      &main_frame_client.ChildClient(1);
  auto* new_child_frame = To<WebLocalFrameImpl>(main_frame->FirstChild());
  EXPECT_EQ(new_child_client, new_child_frame->Client());
  ASSERT_NE(child_client, new_child_client);
  ASSERT_NE(child_frame, new_child_frame);
  // But there should still only be one subframe.
  EXPECT_EQ(1u, main_frame->GetFrame()->Tree().ScopedChildCount());

  EXPECT_EQ(1, new_child_client->BeginNavigationCallCount());
  // Sub-frames should not be forcibly revalidated.
  // TODO(toyoshim): Will consider to revalidate main resources in sub-frames
  // on reloads. Or will do only for bypassingCache.
  EXPECT_EQ(mojom::FetchCacheMode::kDefault, new_child_client->GetCacheMode());
}

class TestMainFrameIntersectionChanged
    : public frame_test_helpers::TestWebFrameClient {
 public:
  TestMainFrameIntersectionChanged() = default;
  ~TestMainFrameIntersectionChanged() override = default;

  // frame_test_helpers::TestWebFrameClient:
  void OnMainFrameIntersectionChanged(
      const gfx::Rect& intersection_rect) override {
    main_frame_intersection_ = intersection_rect;
  }

  gfx::Rect MainFrameIntersection() const { return main_frame_intersection_; }

 private:
  gfx::Rect main_frame_intersection_;
};

TEST_F(WebFrameTest, MainFrameIntersectionChanged) {
  TestMainFrameIntersectionChanged client;
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeRemote();

  WebLocalFrameImpl* local_frame =
      helper.CreateLocalChild(*helper.RemoteMainFrame(), "frameName",
                              WebFrameOwnerProperties(), nullptr, &client);

  WebFrameWidget* widget = local_frame->FrameWidget();
  ASSERT_TRUE(widget);

  gfx::Rect viewport_intersection(0, 11, 200, 89);
  gfx::Rect mainframe_intersection(0, 0, 200, 140);
  blink::mojom::FrameOcclusionState occlusion_state =
      blink::mojom::FrameOcclusionState::kUnknown;
  gfx::Transform transform;
  transform.Translate(100, 100);

  auto intersection_state = blink::mojom::blink::ViewportIntersectionState::New(
      viewport_intersection, mainframe_intersection, gfx::Rect(),
      occlusion_state, gfx::Size(), gfx::Point(), transform);
  static_cast<WebFrameWidgetImpl*>(widget)->ApplyViewportIntersectionForTesting(
      std::move(intersection_state));
  EXPECT_EQ(client.MainFrameIntersection(), gfx::Rect(100, 100, 200, 140));
}

class TestSameDocumentWithImageWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  TestSameDocumentWithImageWebFrameClient() : num_of_image_requests_(0) {}
  ~TestSameDocumentWithImageWebFrameClient() override = default;

  // frame_test_helpers::TestWebFrameClient:
  void FinalizeRequest(WebURLRequest& request) override {
    if (request.GetRequestContext() ==
        mojom::blink::RequestContextType::IMAGE) {
      num_of_image_requests_++;
      EXPECT_EQ(mojom::FetchCacheMode::kDefault, request.GetCacheMode());
    }
  }

  int NumOfImageRequests() const { return num_of_image_requests_; }

 private:
  int num_of_image_requests_;
};

TEST_F(WebFrameTest, NavigateToSameNoConditionalRequestForSubresource) {
  RegisterMockedHttpURLLoad("foo_with_image.html");
  RegisterMockedHttpURLLoad("white-1x1.png");
  TestSameDocumentWithImageWebFrameClient client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&client, nullptr,
                             &ConfigureLoadsImagesAutomatically);
  // TODO(crbug.com/1329535): Remove if threaded preload scanner doesn't launch.
  // Disable preload scanner so it doesn't make any requests.
  web_view_helper.LocalMainFrame()
      ->GetFrame()
      ->GetDocument()
      ->GetSettings()
      ->SetDoHtmlPreloadScanning(false);
  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                base_url_ + "foo_with_image.html");
  EXPECT_EQ(client.NumOfImageRequests(), 1);

  WebCache::Clear();
  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                base_url_ + "foo_with_image.html");
  EXPECT_EQ(client.NumOfImageRequests(), 2);
}

TEST_F(WebFrameTest, WebNodeImageContents) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  static const char kBluePNG[] =
      "<img "
      "src=\"data:image/"
      "png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+"
      "9AAAAGElEQVQYV2NkYPj/n4EIwDiqEF8oUT94AFIQE/cCn90IAAAAAElFTkSuQmCC\">";

  // Load up the image and test that we can extract the contents.
  KURL test_url = ToKURL("about:blank");
  frame_test_helpers::LoadHTMLString(frame, kBluePNG, test_url);

  WebNode node = frame->GetDocument().Body().FirstChild();
  EXPECT_TRUE(node.IsElementNode());
  WebElement element = node.To<WebElement>();
  SkBitmap image = element.ImageContents();
  ASSERT_FALSE(image.isNull());
  EXPECT_EQ(image.width(), 10);
  EXPECT_EQ(image.height(), 10);
  EXPECT_EQ(image.getColor(0, 0), SK_ColorBLUE);
}

TEST_F(WebFrameTest, WebNodeImageContentsWithOrientation) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  // 4x8 jpg with orientation = 6 ( 90 degree CW rotation ).
  // w - white, b - blue.
  //   raw      =>       oriented
  // w w w w          b b b b w w w w
  // w w w w          b b b b w w w w
  // w w w w          b b b b w w w w
  // w w w w          b b b b w w w w
  // b b b b
  // b b b b
  // b b b b
  // b b b b
  static const char kBlueJPGWithOrientation[] =
      "<img "
      "src=\"data:image/"
      "jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD/4QBiRXhpZgAATU0AKgAAAAgABQESAAM"
      "AAAABAAYAAAEaAAUAAAABAAAASgEbAAUAAAABAAAAUgEoAAMAAAABAAIAAAITAAMAAAABAA"
      "EAAAAAAAAAAABgAAAAAQAAAGAAAAAB/9sAQwACAQECAQECAgICAgICAgMFAwMDAwMGBAQDB"
      "QcGBwcHBgcHCAkLCQgICggHBwoNCgoLDAwMDAcJDg8NDA4LDAwM/9sAQwECAgIDAwMGAwMG"
      "DAgHCAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw"
      "M/8AAEQgACAAEAwEiAAIRAQMRAf/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC/"
      "/EALUQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJ"
      "DNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3"
      "eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tf"
      "Y2drh4uPk5ebn6Onq8fLz9PX29/j5+v/EAB8BAAMBAQEBAQEBAQEAAAAAAAABAgMEBQYHCA"
      "kKC//EALURAAIBAgQEAwQHBQQEAAECdwABAgMRBAUhMQYSQVEHYXETIjKBCBRCkaGxwQkjM"
      "1LwFWJy0QoWJDThJfEXGBkaJicoKSo1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpz"
      "dHV2d3h5eoKDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytL"
      "T1NXW19jZ2uLj5OXm5+jp6vLz9PX29/j5+v/aAAwDAQACEQMRAD8A7j/iMz/6tv8A/Mgf/e"
      "2iiiv9ff8AiVzwx/6Fn/lbEf8Ay0+A/tvG/wA/4L/I/9k=\">";

  // Load up the image and test that we can extract the contents.
  KURL test_url = ToKURL("about:blank");
  frame_test_helpers::LoadHTMLString(frame, kBlueJPGWithOrientation, test_url);

  WebNode node = frame->GetDocument().Body().FirstChild();
  EXPECT_TRUE(node.IsElementNode());
  WebElement element = node.To<WebElement>();

  SkBitmap image_with_orientation = element.ImageContents();
  ASSERT_FALSE(image_with_orientation.isNull());
  EXPECT_EQ(image_with_orientation.width(), 8);
  EXPECT_EQ(image_with_orientation.height(), 4);
  // Should be almost blue.
  SkColor oriented_color = image_with_orientation.getColor(0, 0);
  EXPECT_NEAR(SkColorGetR(oriented_color), SkColorGetR(SK_ColorBLUE), 5);
  EXPECT_NEAR(SkColorGetG(oriented_color), SkColorGetG(SK_ColorBLUE), 5);
  EXPECT_NEAR(SkColorGetB(oriented_color), SkColorGetB(SK_ColorBLUE), 5);
  EXPECT_NEAR(SkColorGetA(oriented_color), SkColorGetA(SK_ColorBLUE), 5);
}

class TestStartStopCallbackWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  TestStartStopCallbackWebFrameClient()
      : start_loading_count_(0), stop_loading_count_(0) {}
  ~TestStartStopCallbackWebFrameClient() override = default;

  // frame_test_helpers::TestWebFrameClient:
  void DidStartLoading() override {
    TestWebFrameClient::DidStartLoading();
    start_loading_count_++;
  }
  void DidStopLoading() override {
    TestWebFrameClient::DidStopLoading();
    stop_loading_count_++;
  }

  int StartLoadingCount() const { return start_loading_count_; }
  int StopLoadingCount() const { return stop_loading_count_; }

 private:
  int start_loading_count_;
  int stop_loading_count_;
};

TEST_F(WebFrameTest, PushStateStartsAndStops) {
  RegisterMockedHttpURLLoad("push_state.html");
  TestStartStopCallbackWebFrameClient client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "push_state.html", &client);

  // Wait for push state navigation to complete.
  frame_test_helpers::PumpPendingRequestsForFrameToLoad(
      web_view_helper.LocalMainFrame());
  EXPECT_EQ(client.StartLoadingCount(), 2);
  EXPECT_EQ(client.StopLoadingCount(), 2);
}

TEST_F(WebFrameTest,
       CommitSynchronousNavigationForAboutBlankAndCheckStorageKeyNonce) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("data:text/html,<iframe></iframe>");

  StorageKey storage_key = StorageKey::CreateWithNonce(
      url::Origin(), base::UnguessableToken::Create());

  auto* child_frame =
      To<WebLocalFrameImpl>(web_view_helper.LocalMainFrame()->FirstChild());
  child_frame->GetFrame()->DomWindow()->SetStorageKey(storage_key);

  auto params = std::make_unique<WebNavigationParams>();
  params->url = url_test_helpers::ToKURL("about:blank");
  params->navigation_timings.navigation_start = base::TimeTicks::Now();
  params->navigation_timings.fetch_start = base::TimeTicks::Now();
  params->is_browser_initiated = true;
  MockPolicyContainerHost mock_policy_container_host;
  params->policy_container = std::make_unique<WebPolicyContainer>(
      WebPolicyContainerPolicies(),
      mock_policy_container_host.BindNewEndpointAndPassDedicatedRemote());
  params->is_synchronous_commit_for_bug_778318 = true;

  child_frame->CommitNavigation(std::move(params), nullptr);
  frame_test_helpers::PumpPendingRequestsForFrameToLoad(child_frame);

  // The synchronous commit for bug 778318 should not change the storage key.
  EXPECT_EQ(storage_key.nonce(),
            child_frame->GetFrame()->DomWindow()->GetStorageKey().GetNonce());
}

class TestDidNavigateCommitTypeWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  TestDidNavigateCommitTypeWebFrameClient()
      : last_commit_type_(kWebHistoryInertCommit) {}
  ~TestDidNavigateCommitTypeWebFrameClient() override = default;

  // frame_test_helpers::TestWebFrameClient:
  void DidFinishSameDocumentNavigation(
      WebHistoryCommitType type,
      bool is_synchronously_committed,
      mojom::blink::SameDocumentNavigationType,
      bool is_client_redirect,
      const std::optional<blink::SameDocNavigationScreenshotDestinationToken>&
          screenshot_destination) override {
    last_commit_type_ = type;
  }

  WebHistoryCommitType LastCommitType() const { return last_commit_type_; }

 private:
  WebHistoryCommitType last_commit_type_;
};

TEST_F(WebFrameTest, SameDocumentHistoryNavigationCommitType) {
  RegisterMockedHttpURLLoad("push_state.html");
  TestDidNavigateCommitTypeWebFrameClient client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeAndLoad(base_url_ + "push_state.html", &client);
  auto* local_frame = To<LocalFrame>(web_view_impl->GetPage()->MainFrame());
  Persistent<HistoryItem> item =
      local_frame->Loader().GetDocumentLoader()->GetHistoryItem();
  RunPendingTasks();

  local_frame->Loader().GetDocumentLoader()->CommitSameDocumentNavigation(
      item->Url(), WebFrameLoadType::kBackForward, item.Get(),
      ClientRedirectPolicy::kNotClientRedirect,
      false /* has_transient_user_activation */, /*initiator_origin=*/nullptr,
      /*is_synchronously_committed=*/false, /*source_element=*/nullptr,
      mojom::blink::TriggeringEventInfo::kNotFromEvent,
      /*is_browser_initiated=*/true,
      /*has_ua_visual_transition,=*/false,
      /*soft_navigation_heuristics_task_id=*/std::nullopt);
  EXPECT_EQ(kWebBackForwardCommit, client.LastCommitType());
}

TEST_F(WebFrameTest, SameDocumentHistoryNavigationPropagatesSequenceNumber) {
  RegisterMockedHttpURLLoad("push_state_empty.html");
  frame_test_helpers::TestWebFrameClient client;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "push_state_empty.html", &client);
  auto* local_frame = To<LocalFrame>(web_view_impl->GetPage()->MainFrame());
  Persistent<HistoryItem> item =
      local_frame->Loader().GetDocumentLoader()->GetHistoryItem();
  RunPendingTasks();

  local_frame->Loader().GetDocumentLoader()->CommitSameDocumentNavigation(
      item->Url(), WebFrameLoadType::kBackForward, item.Get(),
      ClientRedirectPolicy::kNotClientRedirect,
      false /* has_transient_user_activation */, /*initiator_origin=*/nullptr,
      /*is_synchronously_committed=*/false, /*source_element=*/nullptr,
      mojom::blink::TriggeringEventInfo::kNotFromEvent,
      /*is_browser_initiated=*/true,
      /*has_ua_visual_transition,=*/false,
      /*soft_navigation_heuristics_task_id=*/std::nullopt);

  EXPECT_EQ(item->ItemSequenceNumber(),
            web_view_helper.GetLayerTreeHost()
                ->primary_main_frame_item_sequence_number_for_testing());
}

// Tests that a navigation in a frame with a non-blank initial URL will create
// a new history item, unlike the case above.
TEST_F(WebFrameTest, FirstNonBlankSubframeNavigation) {
  RegisterMockedHttpURLLoad("history.html");
  RegisterMockedHttpURLLoad("find.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");

  WebLocalFrame* frame = web_view_helper.LocalMainFrame();

  std::string url1 = base_url_ + "history.html";
  std::string load_frame_js =
      "javascript:var f = document.createElement('iframe'); "
      "f.src = '";
  load_frame_js += url1 + "';" + "document.body.appendChild(f)";
  frame_test_helpers::LoadFrame(frame, load_frame_js);

  WebLocalFrame* iframe = frame->FirstChild()->ToWebLocalFrame();
  EXPECT_EQ(url1, iframe->GetDocument().Url().GetString().Utf8());

  std::string url2 = base_url_ + "find.html";
  frame_test_helpers::LoadFrame(iframe, url2);
  EXPECT_EQ(url2, iframe->GetDocument().Url().GetString().Utf8());
  EXPECT_FALSE(iframe->GetDocumentLoader()->ReplacesCurrentHistoryItem());
}

// Test verifies that layout will change a layer's scrollable attibutes
TEST_F(WebFrameTest, overflowHiddenRewrite) {
  RegisterMockedHttpURLLoad("non-scrollable.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetPreferCompositingToLCDTextForTesting(true);

  web_view_helper.Resize(gfx::Size(100, 100));
  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                base_url_ + "non-scrollable.html");

  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  auto* layout_view =
      web_view_helper.LocalMainFrame()->GetFrameView()->GetLayoutView();
  // Verify that the cc::Layer is not scrollable initially.
  auto* scroll_node = GetScrollNode(*layout_view);
  ASSERT_TRUE(scroll_node);
  ASSERT_FALSE(scroll_node->UserScrollableHorizontal());
  ASSERT_FALSE(scroll_node->UserScrollableVertical());

  // Call javascript to make the layer scrollable, and verify it.
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  frame->ExecuteScript(WebScriptSource("allowScroll();"));
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  scroll_node = GetScrollNode(*layout_view);
  ASSERT_TRUE(scroll_node);
  ASSERT_TRUE(scroll_node->UserScrollableHorizontal());
  ASSERT_TRUE(scroll_node->UserScrollableVertical());
}

// Test that currentHistoryItem reflects the current page, not the provisional
// load.
TEST_F(WebFrameTest, CurrentHistoryItem) {
  RegisterMockedHttpURLLoad("fixed_layout.html");
  std::string url = base_url_ + "fixed_layout.html";

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();
  FrameLoader& main_frame_loader =
      web_view_helper.LocalMainFrame()->GetFrame()->Loader();

  // Before navigation, there is no history item.
  EXPECT_FALSE(main_frame_loader.GetDocumentLoader()->GetHistoryItem());

  FrameLoadRequest frame_load_request(nullptr, ResourceRequest(ToKURL(url)));
  main_frame_loader.StartNavigation(frame_load_request);
  frame_test_helpers::PumpPendingRequestsForFrameToLoad(
      web_view_helper.LocalMainFrame());

  // After navigation, there is.
  HistoryItem* item = main_frame_loader.GetDocumentLoader()->GetHistoryItem();
  ASSERT_TRUE(item);
  EXPECT_EQ(WTF::String(url.data()), item->UrlString());
}

class FailCreateChildFrame : public frame_test_helpers::TestWebFrameClient {
 public:
  FailCreateChildFrame() : call_count_(0) {}
  ~FailCreateChildFrame() override = default;

  // frame_test_helpers::TestWebFrameClient:
  WebLocalFrame* CreateChildFrame(
      mojom::blink::TreeScopeType scope,
      const WebString& name,
      const WebString& fallback_name,
      const FramePolicy&,
      const WebFrameOwnerProperties& frame_owner_properties,
      FrameOwnerElementType,
      WebPolicyContainerBindParams policy_container_bind_params,
      ukm::SourceId document_ukm_source_id,
      FinishChildFrameCreationFn finish_creation) override {
    ++call_count_;
    return nullptr;
  }

  int CallCount() const { return call_count_; }

 private:
  int call_count_;
};

// Test that we don't crash if WebLocalFrameClient::createChildFrame() fails.
TEST_F(WebFrameTest, CreateChildFrameFailure) {
  RegisterMockedHttpURLLoad("create_child_frame_fail.html");
  FailCreateChildFrame client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "create_child_frame_fail.html",
                                    &client);

  EXPECT_EQ(1, client.CallCount());
}

TEST_F(WebFrameTest, fixedPositionInFixedViewport) {
  RegisterMockedHttpURLLoad("fixed-position-in-fixed-viewport.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "fixed-position-in-fixed-viewport.html", nullptr, nullptr,
      ConfigureAndroid);

  WebViewImpl* web_view = web_view_helper.GetWebView();
  web_view_helper.Resize(gfx::Size(100, 100));

  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  Element* bottom_fixed =
      document->getElementById(AtomicString("bottom-fixed"));
  Element* top_bottom_fixed =
      document->getElementById(AtomicString("top-bottom-fixed"));
  Element* right_fixed = document->getElementById(AtomicString("right-fixed"));
  Element* left_right_fixed =
      document->getElementById(AtomicString("left-right-fixed"));

  // The layout viewport will hit the min-scale limit of 0.25, so it'll be
  // 400x800.
  web_view_helper.Resize(gfx::Size(100, 200));
  EXPECT_EQ(800, bottom_fixed->OffsetTop() + bottom_fixed->OffsetHeight());
  EXPECT_EQ(800, top_bottom_fixed->OffsetHeight());

  // Now the layout viewport hits the content width limit of 500px so it'll be
  // 500x500.
  web_view_helper.Resize(gfx::Size(200, 200));
  EXPECT_EQ(500, right_fixed->OffsetLeft() + right_fixed->OffsetWidth());
  EXPECT_EQ(500, left_right_fixed->OffsetWidth());
}

TEST_F(WebFrameTest, FrameViewMoveWithSetFrameRect) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  web_view_helper.Resize(gfx::Size(200, 200));
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  LocalFrameView* frame_view = web_view_helper.LocalMainFrame()->GetFrameView();
  EXPECT_EQ(gfx::Rect(0, 0, 200, 200), frame_view->FrameRect());
  frame_view->SetFrameRect(gfx::Rect(100, 100, 200, 200));
  EXPECT_EQ(gfx::Rect(100, 100, 200, 200), frame_view->FrameRect());
}

TEST_F(WebFrameTest, FrameViewScrollAccountsForBrowserControls) {
  RegisterMockedHttpURLLoad("long_scroll.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "long_scroll.html", nullptr,
                                    nullptr, ConfigureAndroid);

  WebViewImpl* web_view = web_view_helper.GetWebView();
  LocalFrameView* frame_view = web_view_helper.LocalMainFrame()->GetFrameView();

  float browser_controls_height = 40;
  web_view->ResizeWithBrowserControls(gfx::Size(100, 100),
                                      browser_controls_height, 0, false);
  web_view->SetPageScaleFactor(2.0f);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  web_view->MainFrameImpl()->SetScrollOffset(gfx::PointF(0, 2000));
  EXPECT_EQ(ScrollOffset(0, 1900),
            frame_view->LayoutViewport()->GetScrollOffset());

  // Simulate the browser controls showing by 20px, thus shrinking the viewport
  // and allowing it to scroll an additional 20px.
  web_view->MainFrameWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1.0f, false,
       20.0f / browser_controls_height, 0, cc::BrowserControlsState::kBoth});
  EXPECT_EQ(ScrollOffset(0, 1920),
            frame_view->LayoutViewport()->MaximumScrollOffset());

  // Show more, make sure the scroll actually gets clamped.
  web_view->MainFrameWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1.0f, false,
       20.0f / browser_controls_height, 0, cc::BrowserControlsState::kBoth});
  web_view->MainFrameImpl()->SetScrollOffset(gfx::PointF(0, 2000));
  EXPECT_EQ(ScrollOffset(0, 1940),
            frame_view->LayoutViewport()->GetScrollOffset());

  // Hide until there's 10px showing.
  web_view->MainFrameWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1.0f, false,
       -30.0f / browser_controls_height, 0, cc::BrowserControlsState::kBoth});
  EXPECT_EQ(ScrollOffset(0, 1910),
            frame_view->LayoutViewport()->MaximumScrollOffset());

  // Simulate a LayoutEmbeddedContent::resize. The frame is resized to
  // accommodate the browser controls and Blink's view of the browser controls
  // matches that of the CC
  web_view->MainFrameWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1.0f, false,
       30.0f / browser_controls_height, 0, cc::BrowserControlsState::kBoth});
  web_view->ResizeWithBrowserControls(gfx::Size(100, 60), 40.0f, 0, true);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  EXPECT_EQ(ScrollOffset(0, 1940),
            frame_view->LayoutViewport()->MaximumScrollOffset());

  // Now simulate hiding.
  web_view->MainFrameWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1.0f, false,
       -10.0f / browser_controls_height, 0, cc::BrowserControlsState::kBoth});
  EXPECT_EQ(ScrollOffset(0, 1930),
            frame_view->LayoutViewport()->MaximumScrollOffset());

  // Reset to original state: 100px widget height, browser controls fully
  // hidden.
  web_view->MainFrameWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1.0f, false,
       -30.0f / browser_controls_height, 0, cc::BrowserControlsState::kBoth});
  web_view->ResizeWithBrowserControls(gfx::Size(100, 100),
                                      browser_controls_height, 0, false);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  EXPECT_EQ(ScrollOffset(0, 1900),
            frame_view->LayoutViewport()->MaximumScrollOffset());

  // Show the browser controls by just 1px, since we're zoomed in to 2X, that
  // should allow an extra 0.5px of scrolling in the visual viewport. Make
  // sure we're not losing any pixels when applying the adjustment on the
  // main frame.
  web_view->MainFrameWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1.0f, false,
       1.0f / browser_controls_height, 0, cc::BrowserControlsState::kBoth});
  EXPECT_EQ(ScrollOffset(0, 1901),
            frame_view->LayoutViewport()->MaximumScrollOffset());

  web_view->MainFrameWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), 1.0f, false,
       2.0f / browser_controls_height, 0, cc::BrowserControlsState::kBoth});
  EXPECT_EQ(ScrollOffset(0, 1903),
            frame_view->LayoutViewport()->MaximumScrollOffset());
}

TEST_F(WebFrameTest, MaximumScrollPositionCanBeNegative) {
  RegisterMockedHttpURLLoad("rtl-overview-mode.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "rtl-overview-mode.html",
                                    nullptr, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetInitialPageScaleOverride(-1);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetLoadWithOverviewMode(true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  LocalFrameView* frame_view = web_view_helper.LocalMainFrame()->GetFrameView();
  ScrollableArea* layout_viewport = frame_view->LayoutViewport();
  EXPECT_LT(layout_viewport->MaximumScrollOffset().x(), 0);
}

TEST_F(WebFrameTest, FullscreenLayerSize) {
  RegisterMockedHttpURLLoad("fullscreen_div.html");
  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  //  client.screen_info_.rect = gfx::Rect(viewport_width, viewport_height);
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "fullscreen_div.html", nullptr, nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  UpdateAllLifecyclePhases(web_view_impl);

  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  Document* document = frame->GetDocument();
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Element* div_fullscreen = document->getElementById(AtomicString("div1"));
  Fullscreen::RequestFullscreen(*div_fullscreen);
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*document));
  web_view_impl->DidEnterFullscreen();
  EXPECT_EQ(div_fullscreen, Fullscreen::FullscreenElementFrom(*document));
  UpdateAllLifecyclePhases(web_view_impl);
  EXPECT_EQ(div_fullscreen, Fullscreen::FullscreenElementFrom(*document));

  // Verify that the element is sized to the viewport.
  auto* fullscreen_layout_object =
      To<LayoutBox>(div_fullscreen->GetLayoutObject());
  EXPECT_EQ(viewport_width, fullscreen_layout_object->LogicalWidth().ToInt());
  EXPECT_EQ(viewport_height, fullscreen_layout_object->LogicalHeight().ToInt());

  // Verify it's updated after a device rotation.
  UpdateScreenInfoAndResizeView(&web_view_helper, viewport_height,
                                viewport_width);
  UpdateAllLifecyclePhases(web_view_impl);
  EXPECT_EQ(viewport_height, fullscreen_layout_object->LogicalWidth().ToInt());
  EXPECT_EQ(viewport_width, fullscreen_layout_object->LogicalHeight().ToInt());
}

TEST_F(WebFrameTest, FullscreenLayerNonScrollable) {
  RegisterMockedHttpURLLoad("fullscreen_div.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  int viewport_width = 640;
  int viewport_height = 480;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "fullscreen_div.html", nullptr, nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  UpdateAllLifecyclePhases(web_view_impl);

  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  Document* document = frame->GetDocument();
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Element* div_fullscreen = document->getElementById(AtomicString("div1"));
  Fullscreen::RequestFullscreen(*div_fullscreen);
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*document));
  web_view_impl->DidEnterFullscreen();
  EXPECT_EQ(div_fullscreen, Fullscreen::FullscreenElementFrom(*document));
  UpdateAllLifecyclePhases(web_view_impl);
  EXPECT_EQ(div_fullscreen, Fullscreen::FullscreenElementFrom(*document));

  // Verify that the viewports are nonscrollable.
  auto* frame_view = web_view_helper.LocalMainFrame()->GetFrameView();
  auto* layout_viewport_scroll_node =
      GetScrollNode(*frame_view->GetLayoutView());
  ASSERT_FALSE(layout_viewport_scroll_node->UserScrollableHorizontal());
  ASSERT_FALSE(layout_viewport_scroll_node->UserScrollableVertical());
  auto* visual_viewport_scroll_node =
      frame_view->GetPage()->GetVisualViewport().GetScrollNode();
  ASSERT_FALSE(visual_viewport_scroll_node->UserScrollableHorizontal());
  ASSERT_FALSE(visual_viewport_scroll_node->UserScrollableVertical());

  // Verify that the viewports are scrollable upon exiting fullscreen.
  EXPECT_EQ(div_fullscreen, Fullscreen::FullscreenElementFrom(*document));
  web_view_impl->DidExitFullscreen();
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*document));
  UpdateAllLifecyclePhases(web_view_impl);
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*document));
  layout_viewport_scroll_node = GetScrollNode(*frame_view->GetLayoutView());
  ASSERT_TRUE(layout_viewport_scroll_node->UserScrollableHorizontal());
  ASSERT_TRUE(layout_viewport_scroll_node->UserScrollableVertical());
  visual_viewport_scroll_node =
      frame_view->GetPage()->GetVisualViewport().GetScrollNode();
  ASSERT_TRUE(visual_viewport_scroll_node->UserScrollableHorizontal());
  ASSERT_TRUE(visual_viewport_scroll_node->UserScrollableVertical());
}

TEST_F(WebFrameTest, FullscreenMainFrame) {
  RegisterMockedHttpURLLoad("fullscreen_div.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  int viewport_width = 640;
  int viewport_height = 480;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "fullscreen_div.html", nullptr, nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  UpdateAllLifecyclePhases(web_view_impl);

  auto* layout_view =
      web_view_impl->MainFrameImpl()->GetFrame()->View()->GetLayoutView();
  auto* scroll_node = GetScrollNode(*layout_view);
  ASSERT_TRUE(scroll_node->UserScrollableHorizontal());
  ASSERT_TRUE(scroll_node->UserScrollableVertical());

  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  Document* document = frame->GetDocument();
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*document->documentElement());
  EXPECT_EQ(nullptr, Fullscreen::FullscreenElementFrom(*document));
  web_view_impl->DidEnterFullscreen();
  EXPECT_EQ(document->do
```