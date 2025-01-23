Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is part of a test file (`browser_controls_test.cc`) within the Chromium Blink engine, specifically focusing on the behavior of browser controls.

Here's a breakdown of the code's functionality:

1. **Focus on Browser Controls:** The tests revolve around the interaction between the web page content and the browser controls (like the address bar or toolbar) that can appear at the top or bottom of the browser window.

2. **Scrolling and Content Offset:**  A key aspect is how scrolling affects the browser controls' visibility and the content offset (how much the browser controls are currently shown/hidden).

3. **Test Scenarios:** The tests cover various scenarios, including:
    * Basic showing and hiding of browser controls through scrolling.
    * Scrolling within subregions (overflow divs and iframes) and how it interacts with browser controls.
    * Interaction with page scale and visual viewport.
    * Effects of dynamic safe area insets (notches, etc.).
    * Behavior in fullscreen mode and with subframes.
    * Handling of browser control state constraints (e.g., forcing controls to be always shown or hidden).
    * Impact on the layout of different HTML elements (fixed, absolute, sticky positioning) when browser controls are shown or hidden.
    * Influence on viewport units (vh, svh, lvh).

4. **Simulated Events:** The tests use simulated input events (like `GestureScrollBegin`, `GestureScrollUpdate`) to trigger scrolling and observe the resulting behavior.

5. **Assertions and Expectations:** The tests use `EXPECT_FLOAT_EQ` and `EXPECT_EQ` to verify the expected content offset and scroll positions after certain actions.

6. **HTML Test Pages:** The tests often load specific HTML files (e.g., "overflow-scrolling.html", "iframe-scrolling.html", "percent-height.html") to create the necessary conditions for the tests.

7. **Assumptions and Inferences:** I need to infer the intended behavior based on the code and the test names. For example, `ScrollableSubregionScrollFirst` implies that scrolling in a subregion should happen before the browser controls are affected.

Plan for the summary:

* **Core Functionality:** State that the code tests the behavior of browser controls in Blink.
* **Key Areas:** List the main aspects being tested (scrolling, content offset, subregions, safe area insets, fullscreen, layout).
* **Relationship to Web Technologies:**  Explain how the tests relate to JavaScript (event handling), HTML (structure and different positioning types), and CSS (viewport units).
* **Logic Inference Examples:** Provide concrete examples of input and expected output for some of the test cases.
* **Common Errors:**  Mention potential developer errors related to browser control handling (though the code itself doesn't directly show *user* errors).
这个代码片段主要的功能是**测试 Blink 引擎中浏览器控件（Browser Controls，例如地址栏、工具栏等）在各种场景下的行为和状态管理**。 这些测试用例验证了浏览器控件与网页内容以及用户交互之间的正确协同工作。

以下是更详细的归纳：

**主要功能:**

* **测试浏览器控件的显示和隐藏逻辑:**  验证通过用户手势（例如滑动）或程序控制，浏览器控件能够正确地显示和隐藏。
* **测试浏览器控件对页面滚动的影响:**  检查当浏览器控件显示或隐藏时，页面内容的滚动偏移（content offset）和页面的实际滚动位置是否按照预期进行调整。
* **测试可滚动子区域和 iframe 对浏览器控件行为的影响:**  验证当页面中存在可滚动的 `<div>` 元素或 `<iframe>` 元素时，这些子区域的滚动是否会优先于浏览器控件的显示/隐藏。
* **测试动态安全区域内嵌 (Dynamic Safe Area Insets) 的处理:**  验证当设备的屏幕有安全区域（例如 iPhone 的“刘海”）时，浏览器控件如何与这些区域协同工作，并确保内容不会被遮挡。
* **测试全屏模式下浏览器控件的行为:**  检查当页面进入全屏模式时，浏览器控件的行为和安全区域内嵌的处理。
* **测试浏览器控件的高度变化和状态保持:**  验证当浏览器控件的高度发生变化时，其显示状态是否能够正确保持，并且内容偏移是否能够相应调整。
* **测试零高度浏览器控件的情况:**  验证当浏览器控件的高度设置为零时，滚动操作是否不会对其产生影响。
* **测试超出滚动极限时的浏览器控件行为:**  检查当用户尝试向上滚动超出页面顶部时，浏览器控件是否不会意外隐藏。
* **测试浏览器控件的状态约束 (State Constraints):** 验证通过程序设置浏览器控件的允许状态（例如只允许显示、只允许隐藏、允许显示或隐藏）时，其行为是否符合约束。
* **测试浏览器控件对页面布局的影响:**  验证浏览器控件的显示和隐藏是否会影响页面元素的布局，特别是对于 `position: fixed` 和 `position: absolute` 的元素。
* **测试浏览器控件对视口单位 (Viewport Units) 的影响:**  验证浏览器控件的显示和隐藏是否会影响使用视口单位 (如 `vh`, `svh`, `lvh`) 定义的元素的大小。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:** 测试用例中加载了不同的 HTML 文件（例如 `overflow-scrolling.html`, `iframe-scrolling.html`, `percent-height.html`），这些文件定义了页面结构，包含了可滚动的 `<div>`、`<iframe>` 以及使用不同定位方式的元素，用于测试浏览器控件在不同页面结构下的行为。例如，`percent-height.html` 用于测试浏览器控件显示/隐藏时，百分比高度的元素如何响应视口大小的变化。
* **CSS:** HTML 文件中包含了 CSS 样式，用于定义元素的布局和外观，例如 `position: fixed` 用于创建固定定位的元素，`position: absolute` 用于创建绝对定位的元素，`position: sticky` 用于创建粘性定位的元素。测试验证了浏览器控件与这些 CSS 属性的交互。例如，测试用例会检查当浏览器控件显示时，`position: fixed` 元素的表现是否符合预期。
* **JavaScript:** 虽然这段代码本身是 C++，但它模拟了用户交互（例如滑动），这些交互在实际浏览器中通常是通过 JavaScript 事件处理来实现的。测试用例通过 `DispatchThroughCcInputHandler` 发送模拟的输入事件，来触发浏览器控件的行为变化，这与 JavaScript 处理滚动事件类似。

**逻辑推理示例 (假设输入与输出):**

* **假设输入:** 用户在页面上进行向下滑动操作。
* **预期输出:**  如果页面内容足够长，浏览器控件会开始向上收起（`web_view->GetBrowserControls().ContentOffset()` 的值会逐渐减小）。当浏览器控件完全收起后，页面的滚动位置会继续变化 (`GetFrame()->View()->GetScrollableArea()->GetScrollOffset()` 会继续增加）。
* **假设输入:** 用户在页面上进行向上滑动操作，且浏览器控件处于隐藏状态。
* **预期输出:** 浏览器控件会开始向下展开（`web_view->GetBrowserControls().ContentOffset()` 的值会逐渐增大）。当浏览器控件完全展开后，页面的滚动位置可能会根据滚动方向进行调整。

**用户或编程常见的使用错误示例:**

虽然这段测试代码本身不直接涉及用户错误，但可以推断出一些与浏览器控件相关的常见编程错误：

* **错误地假设固定定位元素的行为:**  开发者可能错误地认为固定定位元素的高度始终等于整个视口高度，而忽略了浏览器控件显示时会占用部分视口空间。测试用例 `DontAffectLayoutHeight` 和 `AffectLayoutHeightWhenConstrained` 就覆盖了这种情况。
* **错误地计算视口单位:** 开发者可能没有考虑到动态浏览器控件对视口大小的影响，从而在使用 `vh` 等视口单位时得到意外的结果。测试用例 `DontAffectStaticUnits` 验证了静态视口单位的行为。
* **没有正确处理可滚动子区域的滚动事件:**  开发者可能没有考虑到页面中存在可滚动子区域时，滚动事件的传播顺序以及如何避免与浏览器控件的滚动行为冲突。测试用例 `ScrollableSubregionScrollFirst` 和 `ScrollableIframeScrollFirst` 就是为了验证这种场景。

**总结这段代码的功能:**

这段代码是 Chromium Blink 引擎中用于测试浏览器控件核心功能的关键部分。它通过模拟各种用户交互和页面状态，验证了浏览器控件在不同场景下的行为是否符合预期，包括显示/隐藏、与页面滚动的协同、与可滚动子区域的交互、以及对页面布局和视口单位的影响。这些测试确保了浏览器控件能够正确地工作，为用户提供一致且良好的浏览体验。

### 提示词
```
这是目录为blink/renderer/core/frame/browser_controls_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
vent::Type::kGestureScrollBegin));
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 20),
            GetFrame()->View()->GetScrollableArea()->GetScrollOffset());

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 50.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(50.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 20),
            GetFrame()->View()->GetScrollableArea()->GetScrollOffset());

  // At 0.5x scale scrolling 10px should take us to the top of the page.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 10.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(50.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 0),
            GetFrame()->View()->GetScrollableArea()->GetScrollOffset());
}

// Scrollable subregions should scroll before browser controls
TEST_F(BrowserControlsTest, MAYBE(ScrollableSubregionScrollFirst)) {
  WebViewImpl* web_view = Initialize("overflow-scrolling.html");
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      50.f, 0, true);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  GetFrame()->View()->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0, 50), mojom::blink::ScrollType::kProgrammatic);
  CompositeForTest();

  // Test scroll down
  // A full scroll down should scroll the overflow div first but browser
  // controls and main frame should not scroll.
  VerticalScroll(-800.f);
  EXPECT_FLOAT_EQ(50.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 50),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Now scroll down should start hiding browser controls but main frame
  // should not scroll.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin, 0, -40.f));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -40.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(10.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 50),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Continued scroll down should scroll down the main frame
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -40.f));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  CompositeForTest();
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 80),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Test scroll up
  // A full scroll up should scroll overflow div first
  VerticalScroll(800.f);
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 80),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Now scroll up should start showing browser controls but main frame
  // should not scroll.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin, 0, 40.f));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 40.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(40.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 80),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Continued scroll up scroll up the main frame
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 40.f));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  CompositeForTest();
  EXPECT_FLOAT_EQ(50.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 50),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());
}

// Scrollable iframes should scroll before browser controls
TEST_F(BrowserControlsTest, MAYBE(ScrollableIframeScrollFirst)) {
  WebViewImpl* web_view = Initialize("iframe-scrolling.html");
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      50.f, 0, true);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  GetFrame()->View()->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0, 50), mojom::blink::ScrollType::kProgrammatic);
  CompositeForTest();

  // Test scroll down
  // A full scroll down should scroll the iframe first but browser controls and
  // main frame should not scroll.
  VerticalScroll(-800.f);
  EXPECT_FLOAT_EQ(50.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 50),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Now scroll down should start hiding browser controls but main frame
  // should not scroll.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin, 0, -40.f));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -40.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(10.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 50),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Continued scroll down should scroll down the main frame
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -40.f));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  CompositeForTest();
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 80),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Test scroll up
  // A full scroll up should scroll iframe first
  VerticalScroll(800.f);
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 80),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Now scroll up should start showing browser controls but main frame
  // should not scroll.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin, 0, 40.f));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 40.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(40.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 80),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  // Continued scroll up scroll up the main frame
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 40.f));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  CompositeForTest();
  EXPECT_FLOAT_EQ(50.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 50),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());
}

TEST_F(BrowserControlsTest,
       MAYBE(SetMaxSafeAreaInsetWithDynamicSafeAreaInsets)) {
  ScopedDynamicSafeAreaInsetsForTest dynamic_safe_area_insets(true);

  WebViewImpl* web_view = Initialize();
  web_view->GetSettings()->SetDynamicSafeAreaInsetsEnabled(true);
  SetSafeAreaInsets(GetFrame(), gfx::Insets().set_bottom(30));

  // initialize browser controls to be shown.
  web_view->GetBrowserControls().SetShownRatio(0.0, 1);
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      0, 50.f, true);
  CompositeForTest();
  // Bottom insets should be 0, as browser control is presented and it's taller
  // than the bottom of the insets.
  EXPECT_EQ("0px", ResolveSafeAreaInsetsBottom());

  // Simulate setting a new safe area inset (e.g. screen rotation).
  SetSafeAreaInsets(GetFrame(), gfx::Insets().set_bottom(60));

  // New safe area 10px = 60px - 50px.
  EXPECT_EQ("10px", ResolveSafeAreaInsetsBottom(GetFrame()));
}

TEST_F(BrowserControlsTest, MAYBE(SetMaxSafeAreaInsetWithSubFrames)) {
  WebViewImpl* web_view = Initialize("fullscreen_iframe.html");
  web_view->GetSettings()->SetDynamicSafeAreaInsetsEnabled(false);
  SetSafeAreaInsets(GetFrame(), gfx::Insets().set_bottom(30));

  // initialize browser controls to be shown.
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      0, 50.f, true);
  web_view->GetBrowserControls().SetShownRatio(0, 0);
  CompositeForTest();
  EXPECT_EQ("30px", ResolveSafeAreaInsetsBottom());

  // Find the sub frame, and request entering fullscreen.
  LocalFrame* iframe =
      To<WebLocalFrameImpl>(web_view->MainFrame()->FirstChild())->GetFrame();
  Document* document = iframe->GetDocument();
  LocalFrame::NotifyUserActivation(
      iframe, mojom::UserActivationNotificationType::kTest);
  Element* div_fullscreen = document->getElementById(AtomicString("div1"));
  Fullscreen::RequestFullscreen(*div_fullscreen);
  web_view->DidEnterFullscreen();
  UpdateAllLifecyclePhases();

  // Main frame's SAI should remain the same.
  SetSafeAreaInsets(iframe, gfx::Insets().set_bottom(40));
  EXPECT_EQ("30px", ResolveSafeAreaInsetsBottom(GetFrame()));
  EXPECT_EQ("40px", ResolveSafeAreaInsetsBottom(iframe));
}

TEST_F(BrowserControlsTest,
       MAYBE(SetMaxSafeAreaInsetWithSubFramesWithDynamicSafeAreaInsets)) {
  ScopedDynamicSafeAreaInsetsForTest dynamic_safe_area_insets(true);

  WebViewImpl* web_view = Initialize("fullscreen_iframe.html");
  web_view->GetSettings()->SetDynamicSafeAreaInsetsEnabled(true);
  SetSafeAreaInsets(GetFrame(), gfx::Insets().set_bottom(30));

  // initialize browser controls to be shown.
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      0, 50.f, true);
  web_view->GetBrowserControls().SetShownRatio(0, 0);
  CompositeForTest();
  EXPECT_EQ("30px", ResolveSafeAreaInsetsBottom());

  // Find the sub frame, and request entering fullscreen.
  LocalFrame* iframe =
      To<WebLocalFrameImpl>(web_view->MainFrame()->FirstChild())->GetFrame();
  Document* document = iframe->GetDocument();
  LocalFrame::NotifyUserActivation(
      iframe, mojom::UserActivationNotificationType::kTest);
  Element* div_fullscreen = document->getElementById(AtomicString("div1"));
  Fullscreen::RequestFullscreen(*div_fullscreen);
  web_view->DidEnterFullscreen();
  UpdateAllLifecyclePhases();

  // Main frame's SAI should remain the same.
  SetSafeAreaInsets(iframe, gfx::Insets().set_bottom(40));
  EXPECT_EQ("30px", ResolveSafeAreaInsetsBottom(GetFrame()));
  EXPECT_EQ("40px", ResolveSafeAreaInsetsBottom(iframe));

  // Simulate setting the main frame with a different SAI - the main frame's SAI
  // is forced to go through even there's a fullscreen element.
  SetSafeAreaInsets(GetFrame(), gfx::Insets().set_bottom(40));
  EXPECT_EQ("40px", ResolveSafeAreaInsetsBottom(GetFrame()));
  EXPECT_EQ("40px", ResolveSafeAreaInsetsBottom(iframe));
}

// Browser controls visibility should remain consistent when height is changed.
TEST_F(BrowserControlsTest, MAYBE(HeightChangeMaintainsVisibility)) {
  WebViewImpl* web_view = Initialize();
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      20.f, 0, false);
  web_view->GetBrowserControls().SetShownRatio(0, 0);

  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      20.f, 0, false);
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());

  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      40.f, 0, false);
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  CompositeForTest();

  // Scroll up to show browser controls.
  VerticalScroll(40.f);
  EXPECT_FLOAT_EQ(40.f, web_view->GetBrowserControls().ContentOffset());

  // Changing height of a fully shown browser controls should correctly adjust
  // content offset
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      30.f, 0, false);
  EXPECT_FLOAT_EQ(30.f, web_view->GetBrowserControls().ContentOffset());
}

// Zero delta should not have any effect on browser controls.
TEST_F(BrowserControlsTest, MAYBE(ZeroHeightMeansNoEffect)) {
  WebViewImpl* web_view = Initialize();
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      0, 0, false);
  web_view->GetBrowserControls().SetShownRatio(0, 0);
  GetFrame()->View()->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0, 100), mojom::blink::ScrollType::kProgrammatic);
  CompositeForTest();

  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());

  VerticalScroll(20.f);
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 80),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  VerticalScroll(-30.f);
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 110),
            GetFrame()->View()->LayoutViewport()->GetScrollOffset());

  web_view->GetBrowserControls().SetShownRatio(1, 1);
  EXPECT_FLOAT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
}

// Browser controls should not hide when scrolling up past limit
TEST_F(BrowserControlsTest, MAYBE(ScrollUpPastLimitDoesNotHide)) {
  WebViewImpl* web_view = Initialize();
  // Initialize browser controls to be shown
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      50.f, 0, true);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  // Use 2x scale so that both visual viewport and frameview are scrollable
  web_view->SetPageScaleFactor(2.0);

  // Fully scroll frameview but visualviewport remains scrollable
  web_view->MainFrameImpl()->SetScrollOffset(gfx::PointF(0, 10000));
  GetVisualViewport().SetLocation(gfx::PointF(0, 0));
  CompositeForTest();
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin, 0, -10.f));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -10.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(40, web_view->GetBrowserControls().ContentOffset());

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  FinishAnimation();
  EXPECT_FLOAT_EQ(50, web_view->GetBrowserControls().ContentOffset());

  web_view->GetBrowserControls().SetShownRatio(1, 1);
  // Fully scroll visual veiwport but frameview remains scrollable
  web_view->MainFrameImpl()->SetScrollOffset(gfx::PointF(0, 0));
  GetVisualViewport().SetLocation(gfx::PointF(0, 10000));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin, 0, -20.f));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -20.f));
  CompositeForTest();
  EXPECT_FLOAT_EQ(30, web_view->GetBrowserControls().ContentOffset());

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  FinishAnimation();
  EXPECT_FLOAT_EQ(50, web_view->GetBrowserControls().ContentOffset());

  web_view->GetBrowserControls().SetShownRatio(1, 1);
  // Fully scroll both frameview and visual viewport
  web_view->MainFrameImpl()->SetScrollOffset(gfx::PointF(0, 10000));
  GetVisualViewport().SetLocation(gfx::PointF(0, 10000));
  CompositeForTest();
  VerticalScroll(-30.f);
  // Browser controls should not move because neither frameview nor visual
  // viewport
  // are scrollable
  EXPECT_FLOAT_EQ(50.f, web_view->GetBrowserControls().ContentOffset());
}

// Browser controls should honor its constraints
TEST_F(BrowserControlsSimTest, MAYBE(StateConstraints)) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
        <!DOCTYPE html>
        <meta name="viewport" content="width=device-width">
        <style>
          body {
            margin: 0;
            height: 1000px;
          }
        </style>
      )HTML");
  Compositor().BeginFrame();

  WebView().ResizeWithBrowserControls(gfx::Size(400, 400), 50.f, 0, false);
  Compositor().BeginFrame();

  GetDocument().View()->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0, 100), mojom::blink::ScrollType::kProgrammatic);
  // Setting permitted state should change the content offset to match the
  // constraint.
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kShown, cc::BrowserControlsState::kShown, false,
      std::nullopt);
  Compositor().BeginFrame();
  EXPECT_FLOAT_EQ(50.f, WebView().GetBrowserControls().ContentOffset());

  WebView().ResizeWithBrowserControls(gfx::Size(400, 400), 50.f, 50.f, false);
  Compositor().BeginFrame();
  // Bottom controls shouldn't affect the content offset.
  EXPECT_FLOAT_EQ(50.f, WebView().GetBrowserControls().ContentOffset());

  // Only shown state is permitted so controls cannot hide.
  VerticalScroll(-20.f);
  EXPECT_FLOAT_EQ(50, WebView().GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 120),
            GetDocument().View()->LayoutViewport()->GetScrollOffset());

  // Setting permitted state should change content offset to match the
  // constraint.
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kHidden, cc::BrowserControlsState::kHidden,
      false, std::nullopt);
  Compositor().BeginFrame();
  EXPECT_FLOAT_EQ(0, WebView().GetBrowserControls().ContentOffset());

  // Only hidden state is permitted so controls cannot show
  VerticalScroll(30.f);
  EXPECT_FLOAT_EQ(0, WebView().GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 90),
            GetDocument().View()->LayoutViewport()->GetScrollOffset());

  // Setting permitted state to "both" should not change content offset.
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kBoth, false,
      std::nullopt);
  Compositor().BeginFrame();
  EXPECT_FLOAT_EQ(0, WebView().GetBrowserControls().ContentOffset());

  // Both states are permitted so controls can either show or hide
  VerticalScroll(50.f);
  EXPECT_FLOAT_EQ(50, WebView().GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 90),
            GetDocument().View()->LayoutViewport()->GetScrollOffset());

  VerticalScroll(-50.f);
  EXPECT_FLOAT_EQ(0, WebView().GetBrowserControls().ContentOffset());
  EXPECT_EQ(ScrollOffset(0, 90),
            GetDocument().View()->LayoutViewport()->GetScrollOffset());

  // Setting permitted state to "both" should not change an in-flight offset.
  GetWebFrameWidget().DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin, 0, 20.f));
  GetWebFrameWidget().DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 20.f));
  Compositor().BeginFrame();
  EXPECT_FLOAT_EQ(20, WebView().GetBrowserControls().ContentOffset());

  GetWebFrameWidget().DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  Compositor().BeginFrame();
  Compositor().BeginFrame(kShowHideMaxDurationMs / 1000.0);

  EXPECT_FLOAT_EQ(0, WebView().GetBrowserControls().ContentOffset());
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kBoth, false,
      std::nullopt);
  Compositor().BeginFrame();
  EXPECT_FLOAT_EQ(0, WebView().GetBrowserControls().ContentOffset());

  // Setting just the constraint should affect the content offset.
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kHidden, cc::BrowserControlsState::kBoth, false,
      std::nullopt);
  Compositor().BeginFrame();
  EXPECT_FLOAT_EQ(0, WebView().GetBrowserControls().ContentOffset());

  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kShown, cc::BrowserControlsState::kBoth, false,
      std::nullopt);
  Compositor().BeginFrame();
  EXPECT_FLOAT_EQ(50, WebView().GetBrowserControls().ContentOffset());
}

// Ensure that browser controls do not affect the layout by showing and hiding
// except for position: fixed elements.
TEST_F(BrowserControlsTest, MAYBE(DontAffectLayoutHeight)) {
  // Initialize with the browser controls showing.
  WebViewImpl* web_view = Initialize("percent-height.html");
  web_view->ResizeWithBrowserControls(gfx::Size(400, 300), 100.f, 0, true);
  web_view->GetBrowserControls().UpdateConstraintsAndState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kShown);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  CompositeForTest();

  ASSERT_EQ(100.f, web_view->GetBrowserControls().ContentOffset());

  // When the browser controls are showing, there's 300px for the layout height
  // so
  // 50% should result in both the position:fixed and position: absolute divs
  // having 150px of height.
  Element* abs_pos = GetElementById(WebString::FromUTF8("abs"));
  Element* fixed_pos = GetElementById(WebString::FromUTF8("fixed"));
  EXPECT_FLOAT_EQ(150.f, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(150.f, fixed_pos->GetBoundingClientRect()->height());

  // The layout size on the LocalFrameView should not include the browser
  // controls.
  EXPECT_EQ(300, GetFrame()->View()->GetLayoutSize().height());

  // Hide the browser controls.
  VerticalScroll(-100.f);
  web_view->ResizeWithBrowserControls(gfx::Size(400, 400), 100.f, 0, false);
  UpdateAllLifecyclePhases();

  ASSERT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());

  // Hiding the browser controls shouldn't change the height of the initial
  // containing block for non-position: fixed. Position: fixed however should
  // use the entire height of the viewport however.
  EXPECT_FLOAT_EQ(150.f, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(200.f, fixed_pos->GetBoundingClientRect()->height());

  // The layout size should not change as a result of browser controls hiding.
  EXPECT_EQ(300, GetFrame()->View()->GetLayoutSize().height());
}

// Ensure that browser controls do not affect the layout by showing and hiding
// except for position: fixed elements.
TEST_F(BrowserControlsSimTest, MAYBE(AffectLayoutHeightWhenConstrained)) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
        <!DOCTYPE html>
          <style>
            #abs {
              position: absolute;
              left: 0px;
              top: 0px;
              width: 100px;
              height: 50%;
            }

            #fixed {
              position: fixed;
              right: 0px;
              top: 0px;
              width: 100px;
              height: 50%;
            }

            #spacer {
              height: 1000px;
            }
          </style>
        <div id="abs"></div>
        <div id="fixed"></div>
        <div id="spacer"></div>
      )HTML");
  Compositor().BeginFrame();

  WebView().ResizeWithBrowserControls(gfx::Size(400, 300), 100.f, 0, true);
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kShown, false,
      std::nullopt);
  Compositor().BeginFrame();

  Element* abs_pos = GetDocument().getElementById(WebString::FromUTF8("abs"));
  Element* fixed_pos =
      GetDocument().getElementById(WebString::FromUTF8("fixed"));

  ASSERT_EQ(100.f, WebView().GetBrowserControls().ContentOffset());

  // Hide the browser controls.
  VerticalScroll(-100.f);
  WebView().ResizeWithBrowserControls(gfx::Size(400, 400), 100.f, 0, false);
  Compositor().BeginFrame();
  ASSERT_EQ(300, GetDocument().GetFrame()->View()->GetLayoutSize().height());

  // Now lock the controls in a hidden state. The layout and elements should
  // resize without a WebView::resize.
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kHidden, cc::BrowserControlsState::kBoth, false,
      std::nullopt);
  Compositor().BeginFrame();

  EXPECT_FLOAT_EQ(200.f, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(200.f, fixed_pos->GetBoundingClientRect()->height());

  EXPECT_EQ(400, GetDocument().GetFrame()->View()->GetLayoutSize().height());

  // Unlock the controls, the sizes should change even though the controls are
  // still hidden.
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kBoth, false,
      std::nullopt);
  Compositor().BeginFrame();

  EXPECT_FLOAT_EQ(150.f, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(200.f, fixed_pos->GetBoundingClientRect()->height());

  EXPECT_EQ(300, GetDocument().GetFrame()->View()->GetLayoutSize().height());

  // Now lock the controls in a shown state.
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kShown, cc::BrowserControlsState::kBoth, false,
      std::nullopt);
  WebView().ResizeWithBrowserControls(gfx::Size(400, 300), 100.f, 0, true);
  Compositor().BeginFrame();

  EXPECT_FLOAT_EQ(150.f, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(150.f, fixed_pos->GetBoundingClientRect()->height());

  EXPECT_EQ(300, GetDocument().GetFrame()->View()->GetLayoutSize().height());

  // Shown -> Hidden
  WebView().ResizeWithBrowserControls(gfx::Size(400, 400), 100.f, 0, false);
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kHidden, cc::BrowserControlsState::kBoth, false,
      std::nullopt);
  Compositor().BeginFrame();

  EXPECT_FLOAT_EQ(200.f, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(200.f, fixed_pos->GetBoundingClientRect()->height());

  EXPECT_EQ(400, GetDocument().GetFrame()->View()->GetLayoutSize().height());

  // Go from Unlocked and showing, to locked and hidden but issue the resize
  // before the constraint update to check for race issues.
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kShown, false,
      std::nullopt);
  WebView().ResizeWithBrowserControls(gfx::Size(400, 300), 100.f, 0, true);
  Compositor().BeginFrame();
  ASSERT_EQ(300, GetDocument().GetFrame()->View()->GetLayoutSize().height());

  WebView().ResizeWithBrowserControls(gfx::Size(400, 400), 100.f, 0, false);
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kHidden, cc::BrowserControlsState::kHidden,
      false, std::nullopt);
  Compositor().BeginFrame();

  EXPECT_FLOAT_EQ(200.f, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(200.f, fixed_pos->GetBoundingClientRect()->height());

  EXPECT_EQ(400, GetDocument().GetFrame()->View()->GetLayoutSize().height());
}

// Ensure that browser controls affect layout of viewport constrained
// position: sticky elements.
TEST_F(BrowserControlsSimTest, MAYBE(AffectViewportConstrainedSticky)) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
      <style>
        #sticky {
          position: sticky;
          bottom: 0px;
        }
        .spacer {
          height: 1000px;
        }
      </style>
    <div class="spacer"></div>
    <div id="sticky"></div>
    <div class="spacer"></div>
  )HTML");
  Compositor().BeginFrame();

  WebView().ResizeWithBrowserControls(gfx::Size(400, 300), 100.f, 0, true);
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kShown, false,
      std::nullopt);
  Compositor().BeginFrame();

  Element* sticky_pos =
      GetDocument().getElementById(WebString::FromUTF8("sticky"));
  ASSERT_EQ(100.f, WebView().GetBrowserControls().ContentOffset());
  ASSERT_EQ(300, GetDocument().GetFrame()->View()->GetLayoutSize().height());
  EXPECT_FLOAT_EQ(300.f, sticky_pos->GetBoundingClientRect()->bottom());

  // Hide the browser controls.
  VerticalScroll(-100.f);
  WebView().ResizeWithBrowserControls(gfx::Size(400, 400), 100.f, 0, false);
  Compositor().BeginFrame();
  ASSERT_EQ(300, GetDocument().GetFrame()->View()->GetLayoutSize().height());
  EXPECT_FLOAT_EQ(400.f, sticky_pos->GetBoundingClientRect()->bottom());

  // Now lock the controls in a hidden state. The layout and elements should
  // resize without a WebView::resize.
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kHidden, cc::BrowserControlsState::kBoth, false,
      std::nullopt);
  Compositor().BeginFrame();
  EXPECT_EQ(400, GetDocument().GetFrame()->View()->GetLayoutSize().height());
  EXPECT_FLOAT_EQ(400.f, sticky_pos->GetBoundingClientRect()->bottom());

  // Unlock the controls, the sizes should change even though the controls are
  // still hidden.
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kBoth, false,
      std::nullopt);
  Compositor().BeginFrame();
  EXPECT_EQ(300, GetDocument().GetFrame()->View()->GetLayoutSize().height());
  EXPECT_FLOAT_EQ(400.f, sticky_pos->GetBoundingClientRect()->bottom());

  // Now lock the controls in a shown state.
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kShown, cc::BrowserControlsState::kBoth, false,
      std::nullopt);
  WebView().ResizeWithBrowserControls(gfx::Size(400, 300), 100.f, 0, true);
  Compositor().BeginFrame();
  EXPECT_EQ(300, GetDocument().GetFrame()->View()->GetLayoutSize().height());
  EXPECT_FLOAT_EQ(300.f, sticky_pos->GetBoundingClientRect()->bottom());
}

// Ensure that browser controls do not affect "static" viewport units
// (vh, svh, lvh).
TEST_P(BrowserControlsViewportUnitTest, MAYBE(DontAffectStaticUnits)) {
  auto param = GetParam();
  SCOPED_TRACE(param.filename);

  // Initialize with the browser controls showing.
  WebViewImpl* web_view = Initialize(param.filename);
  web_view->GetPage()->GetChromeClient().SetBrowserControlsState(100.0f, 0.0f,
                                                                 true);
  web_view->GetBrowserControls().UpdateConstraintsAndState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kShown);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  CompositeForTest();

  ASSERT_EQ(100.f, web_view->GetBrowserControls().ContentOffset());

  // Static '*vh' units should be based on the viewport when the browser
  // controls are hidden.
  Element* abs_pos = GetElementById(WebString::FromUTF8("abs"));
  Element* fixed_pos = GetElementById(WebString::FromUTF8("fixed"));
  EXPECT_FLOAT_EQ(param.height, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(param.height, fixed_pos->GetBoundingClientRect()->height());

  // The size used for viewport units should not be reduced by the top
  // controls.
  EXPECT_EQ(400,
            GetFrame()->View()->LargeViewportSizeForViewportUnits().height());

  // Hide the browser controls.
  VerticalScroll(-100.f);
  web_view->GetPage()->GetChromeClient().SetBrowserControlsState(100.0f, 0.0f,
                                                                 false);
  UpdateAllLifecyclePhases();

  ASSERT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());

  // Static *vh units should be static with respect to the browser controls so
  // neither <div> should change size as a result of the browser controls
  // hiding.
  EXPECT_FLOAT_EQ(param.height, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(param.height, fixed_pos->GetBoundingClientRect()->height());

  // The viewport size used for static *vh units should not change as a result
  // of top controls hiding.
  EXPECT_EQ(400,
            GetFrame()->View()->LargeViewportSizeForViewportUnits().height());

  // Static *vw uni
```