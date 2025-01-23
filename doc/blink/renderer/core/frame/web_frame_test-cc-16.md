Response:
My thought process to analyze the provided code snippet goes like this:

1. **Understand the Context:** The initial instruction clearly states this is part of a Chromium Blink engine test file (`web_frame_test.cc`) located in the `blink/renderer/core/frame` directory. This immediately tells me it's testing the functionality of `WebFrame` and related components within Blink's rendering engine. The fact it's a `_test.cc` file means it contains unit tests. The "part 17 of 19" indicates it's a substantial file with various test cases.

2. **Identify the Core Functionality:**  Based on the test names and the code within them, I start recognizing patterns. Many tests involve loading HTML, manipulating the DOM (Document Object Model), interacting with the viewport and scrolling, focusing elements, and simulating user interactions like keyboard events and double-taps. Keywords like "Scroll," "Focus," "Resize," "Find," and "Print" become important indicators of the tested features.

3. **Group Related Tests:**  I mentally group tests by their apparent purpose:
    * **Find in Page:** The first test with `FindInPage`.
    * **Focus and DOM Manipulation:**  Tests involving `FocusOnBlurRemoveBubblingCrash`.
    * **Scrolling and Keyboard Events:** Tests related to scrolling, especially from within iframes (`ScrollToEndBubblingCrash`).
    * **Scrolling Focused Elements into View:** Several tests focus on making sure a focused editable element is visible, including handling edge cases like clipping and different scroller contexts (`TestScrollFocusedEditableElementIntoView`, `TestScrollFocusedEditableInRootScroller`, `ScrollFocusedIntoViewClipped`).
    * **Zooming and Panning:** Tests dealing with double-tap zoom functionality (`DoubleTapZoomWhileScrolled`).
    * **Background Color:** A simple test for changing the background color (`ChangeBackgroundColor`).
    * **Handling Elements without Layout Objects:** Tests ensuring robustness when interacting with elements that don't have a visual representation (`ScrollFocusedEditableIntoViewNoLayoutObject`).
    * **EditContext and Scrolling:**  A specific test for scrolling related to `EditContext` (`ScrollEditContextIntoView`).
    * **Iframe Behavior:** Several tests specifically address how iframes are handled, including those with `display: none` (`DisplayNoneIFrameHasNoLayoutObjects`, `DisplayNoneIFramePrints`, `NormalIFrameHasLayoutObjects`).
    * **RTL and Viewport:** Testing right-to-left layout and viewport behavior (`RtlInitialScrollOffsetWithViewport`, `LayoutViewportExceedsLayoutOverflow`).
    * **Frame Naming:** Testing how frames are looked up by name (`NamedLookupIgnoresEmptyNames`).
    * **Frame Detachment:** A test related to callbacks during frame detachment (`NoLoadingCompletionCallbacksInDetach`, `ClearClosedOpener`).

4. **Analyze Individual Tests:**  For each test, I look at:
    * **Setup:** How the test environment is initialized (e.g., `SimRequest`, `LoadURL`).
    * **Actions:** What actions are being performed (e.g., focusing, scrolling, resizing).
    * **Assertions:** What the test expects to happen (using `EXPECT_TRUE`, `EXPECT_EQ`, `ASSERT_EQ`, etc.).
    * **HTML/CSS/JS Snippets:**  How these elements contribute to setting up the test scenario.

5. **Identify Relationships to Web Technologies:**  This involves connecting the C++ code with its impact on JavaScript, HTML, and CSS:
    * **HTML:** Tests load HTML, manipulate DOM elements (`document.getElementById`, creating elements), and rely on HTML structure for layout and behavior.
    * **CSS:** Tests use CSS to style elements (`style` attributes, `<style>` blocks), control visibility (`display: none`), and affect layout (positioning, sizing).
    * **JavaScript:** Some tests directly embed JavaScript (`<script>`) to set up specific conditions, like event handlers (`onblur`), or to manipulate the DOM programmatically.

6. **Look for Logic and Assumptions:**  When I see tests involving calculations or comparisons, I try to understand the underlying logic. For example, the `ScrollEditContextIntoView` test has specific expected scroll offsets, which are based on the zoom level and the position of the edit control. I identify the assumptions made in these calculations (e.g., device scale factor, padding).

7. **Consider Common Errors:** Based on the test scenarios, I can infer potential user or programming errors that these tests are designed to prevent. Crashes related to focusing and removing elements, incorrect scrolling behavior, or issues with iframes are examples.

8. **Synthesize a Summary:** Finally, I combine all the observations into a concise summary of the file's functionality, highlighting its connections to web technologies, providing examples, and noting common errors addressed by the tests. The "part 17 of 19" reinforces the idea that this section likely builds upon concepts tested in earlier parts and contributes to the overall testing of the `WebFrame` component.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive description of its functionality, as demonstrated in the provided good answer. The key is to break down the code into manageable parts, understand the context, and connect the C++ testing code to the underlying web technologies it's exercising.
这个 `web_frame_test.cc` 文件（的第 17 部分）主要包含了一系列针对 `WebFrame` 及其相关组件的功能测试。这些测试覆盖了浏览器框架在渲染网页和处理用户交互时的各种场景，尤其关注以下方面：

**主要功能归纳 (基于提供的代码片段):**

* **查找功能 (Find in Page):** 测试了在页面中查找文本的功能，包括高亮显示所有匹配项和通过点击匹配项来滚动到相应位置。
* **焦点和 DOM 操作的安全性:**  测试了在元素获得焦点后，通过脚本移除该元素是否会导致崩溃，以此保证浏览器的稳定性。
* **iframe 之间的事件冒泡:** 测试了来自 iframe 的滚动事件（例如按下 End 键）是否能正确冒泡到主框架，确保跨框架交互的正确性。
* **将获得焦点的可编辑元素滚动到视野内:**  这是本部分测试的重点，涵盖了多种场景：
    * **基本滚动:** 确保当一个可编辑元素获得焦点时，浏览器能自动滚动页面，使其可见。
    * **页面缩放:**  测试了在页面缩放的情况下，滚动到视野内的逻辑是否正确。
    * **根滚动器:**  测试了当可编辑元素位于根滚动器中时，滚动到视野内的逻辑。
    * **被裁剪的情况:**  测试了当可编辑元素被父元素裁剪时，滚动到视野内的逻辑，尤其是在 Android 系统键盘弹出导致窗口大小变化的情况下。
    * **选中状态:** 测试了当获得焦点的可编辑元素处于选中状态时，滚动到视野内的逻辑。
* **双击缩放:** 测试了在页面滚动后，双击屏幕进行缩放的功能，确保缩放中心和缩放比例的正确性。
* **背景颜色变化:** 测试了通过 JavaScript 修改 `<body>` 元素的背景颜色，浏览器能否正确更新背景色。
* **没有布局对象的可编辑元素:** 测试了当获得焦点的可编辑元素由于某些原因（例如 CSS `display: none`）没有布局对象时，尝试滚动到视野内是否会崩溃。
* **EditContext 的滚动:**  测试了与 `EditContext` API 相关的滚动功能，`EditContext` 用于更精细地控制文本编辑体验。
* **iframe 的显示属性和布局对象:** 测试了 `display: none` 的 iframe 是否会创建布局对象，以及在 `display` 属性变化时布局对象的创建和销毁。
* **`display: none` 的 iframe 的打印:**  虽然规范不允许，但测试了 `display: none` 的 iframe 是否可以被打印，以兼容一些网站的实现。
* **RTL 布局的初始滚动偏移:** 测试了在 RTL (Right-to-Left) 布局下，页面的初始滚动位置是否正确。
* **布局视口和溢出:** 测试了布局视口的大小和内容大小的关系，以及在浏览器控件显示/隐藏时视口大小的调整。
* **命名查找忽略空名称:** 测试了通过空字符串或空 `AtomicString` 查找 frame 是否返回空指针。
* **frame detach 时的回调:** 测试了在 frame 被 detach 时，是否会触发某些加载完成相关的回调，以避免不必要的执行。
* **清除关闭的 opener:**  测试了当 opener window 被关闭后，被打开的 window 能否正确清除对 opener 的引用。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这些测试与 JavaScript, HTML, CSS 的功能紧密相关，因为它们测试的是浏览器如何渲染和交互网页。

* **HTML:**  大多数测试都加载了 HTML 片段来创建测试场景。例如，创建包含文本、输入框、iframe 等元素的页面结构。
    ```html
    <!DOCTYPE html>
    <input type="text" id="target">
    ```
* **CSS:**  测试使用 CSS 来控制元素的样式和布局，例如设置元素的位置、大小、`display` 属性等。
    ```css
    <style>
      input {
        position: absolute;
        top: 1000px;
        left: 800px;
      }
    </style>
    ```
* **JavaScript:**  部分测试使用 JavaScript 来动态修改 DOM 结构、设置事件处理程序、获取元素属性或调用浏览器 API。
    ```javascript
    window.onload = function (){
      document.getElementById('id0').onblur=function() {
        var o=document.getElementById('id6');
        var n=document.createElement(undefined);
        o.parentNode.replaceChild(n,o);
      };
      // ...
    }
    ```
    在 `ScrollEditContextIntoView` 的测试中，JavaScript 代码创建了一个 `EditContext` 对象，并更新了其控制边界。

**逻辑推理及假设输入与输出:**

* **查找功能 (Find in Page):**
    * **假设输入:**  HTML 中包含文本 "test"，查找字符串为 "test"。
    * **预期输出:**  `FindInternal` 返回 `true`，找到两个匹配项，点击匹配项后页面滚动到相应位置，并且视口包含匹配项所在的矩形区域。
* **将获得焦点的可编辑元素滚动到视野内:**
    * **假设输入:**  HTML 中包含一个位于视口下方的输入框，该输入框获得焦点。
    * **预期输出:**  浏览器会自动滚动页面，使得输入框完全或部分可见，`VisibleContentRect()` 包含输入框的矩形区域。在某些情况下，可能还会触发页面缩放动画。
* **双击缩放:**
    * **假设输入:**  一个可以缩放的页面，用户在某个特定位置双击。
    * **预期输出:**  页面会进行缩放，缩放中心位于双击的位置附近，缩放比例会根据当前的缩放级别进行调整。

**用户或编程常见的使用错误及举例说明:**

* **在元素获得焦点后立即移除:**  `FocusOnBlurRemoveBubblingCrash` 测试正是为了防止这种错误导致浏览器崩溃。开发者可能会在 `onblur` 事件中移除焦点元素，如果处理不当会导致空指针解引用。
* **假设 `display: none` 的 iframe 不会执行任何脚本或参与渲染:** `DisplayNoneIFramePrints` 测试说明，即使 iframe 设置为 `display: none`，其内部的脚本仍然可能执行，并且在某些情况下（例如打印）会参与渲染。开发者不能完全忽略 `display: none` 的 iframe。
* **没有考虑不同滚动容器的情况:**  `TestScrollFocusedEditableInRootScroller` 测试提醒开发者，滚动到视野内的逻辑需要考虑元素所在的滚动容器，可能是默认的视口滚动条，也可能是其他具有 `overflow: auto` 或 `overflow: scroll` 属性的元素。
* **在 Android 等移动端不考虑键盘弹出对视口的影响:** `ScrollFocusedIntoViewClipped` 测试模拟了 Android 键盘弹出的场景，开发者需要意识到键盘可能会遮挡部分视口，导致元素不可见，需要采取额外的滚动措施。

**第 17 部分的功能归纳:**

总而言之，`web_frame_test.cc` 的第 17 部分着重测试了 `WebFrame` 组件在处理用户交互（如查找、聚焦、点击）、DOM 操作、以及在不同布局和视口状态下正确渲染和呈现页面的能力。尤其关注了**滚动到视野内**这个核心功能在各种复杂场景下的正确性和鲁棒性，并涵盖了 iframe 的特殊行为以及一些与移动端特性相关的测试。这些测试旨在确保浏览器的稳定性和符合预期的用户体验。

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第17部分，共19部分，请归纳一下它的功能
```

### 源代码
```cpp
);
  const int kFindIdentifier = 12345;
  EXPECT_TRUE(frame->GetFindInPage()->FindInternal(kFindIdentifier, search_text,
                                                   *options, false));

  frame->EnsureTextFinder().ResetMatchCount();
  frame->EnsureTextFinder().StartScopingStringMatches(kFindIdentifier,
                                                      search_text, *options);

  WebVector<gfx::RectF> web_match_rects =
      frame->EnsureTextFinder().FindMatchRects();
  ASSERT_EQ(2ul, web_match_rects.size());

  gfx::RectF result_rect = web_match_rects[0];
  frame->EnsureTextFinder().SelectNearestFindMatch(result_rect.CenterPoint(),
                                                   nullptr);

  EXPECT_TRUE(frame_view->GetScrollableArea()->VisibleContentRect().Contains(
      box1_rect));
  result_rect = web_match_rects[1];
  frame->EnsureTextFinder().SelectNearestFindMatch(result_rect.CenterPoint(),
                                                   nullptr);

  EXPECT_TRUE(
      frame_view->GetScrollableArea()->VisibleContentRect().Contains(box2_rect))
      << "Box [" << box2_rect.ToString() << "] is not visible in viewport ["
      << frame_view->GetScrollableArea()->VisibleContentRect().ToString()
      << "]";
}
#endif  // BUILDFLAG(IS_ANDROID)

// Check that removing an element whilst focusing it does not cause a null
// pointer deference. This test passes if it does not crash.
// https://crbug.com/1184546
TEST_F(WebFrameSimTest, FocusOnBlurRemoveBubblingCrash) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <script>
      window.onload = function (){
        document.getElementById('id0').onblur=function() {
          var o=document.getElementById('id6');
          var n=document.createElement(undefined);
          o.parentNode.replaceChild(n,o);
        };
        var o=document.getElementById('id7');
        o.focus();
      }
      </script>
      <body id='id0'>
      <strong id='id6'>
      <iframe id='id7'src=''></iframe>
      <textarea id='id35' autofocus='false'>
  )HTML");

  Compositor().BeginFrame();
  RunPendingTasks();
}

// Test bubbling a document (End key) scroll from an inner iframe. This test
// passes if it does not crash. https://crbug.com/904247.
TEST_F(WebFrameSimTest, ScrollToEndBubblingCrash) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  WebView().GetPage()->GetSettings().SetScrollAnimatorEnabled(false);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        body, html {
          width: 100%;
          height: 100%;
          margin: 0;
        }
        #frame {
          width: 100%;
          height: 100%;
          border: 0;
        }
      </style>
      <iframe id="frame" srcdoc="
          <!DOCTYPE html>
          <style>html {height: 300%;}</style>
      "></iframe>
  )HTML");

  Compositor().BeginFrame();
  RunPendingTasks();

  // Focus the iframe.
  WebView().AdvanceFocus(false);

  WebKeyboardEvent key_event(WebInputEvent::Type::kRawKeyDown,
                             WebInputEvent::kNoModifiers,
                             WebInputEvent::GetStaticTimeStampForTests());
  key_event.windows_key_code = VKEY_END;

  // Scroll the iframe to the end.
  key_event.SetType(WebInputEvent::Type::kRawKeyDown);
  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));
  key_event.SetType(WebInputEvent::Type::kKeyUp);
  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));

  Compositor().BeginFrame();

  // End key should now bubble from the iframe up to the main viewport.
  key_event.SetType(WebInputEvent::Type::kRawKeyDown);
  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));
  key_event.SetType(WebInputEvent::Type::kKeyUp);
  WebView().MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(key_event, ui::LatencyInfo()));
}

TEST_F(WebFrameSimTest, TestScrollFocusedEditableElementIntoView) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  WebView().SetDefaultPageScaleLimits(1.f, 4);
  WebView().EnableFakePageScaleAnimationForTesting(true);
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);
  WebView().GetPage()->GetSettings().SetViewportEnabled(false);
  WebView().GetSettings()->SetAutoZoomFocusedEditableToLegibleScale(true);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        ::-webkit-scrollbar {
          width: 0px;
          height: 0px;
        }
        body {
          margin: 0px;
        }
        input {
          border: 0;
          padding: 0;
          position: absolute;
          left: 200px;
          top: 600px;
          width: 100px;
          height: 20px;
        }
        #content {
          background: silver;
          width: 500px;
          height: 600px;
        }
      </style>
      <div id="content">a</div>
      <input type="text">
  )HTML");

  Compositor().BeginFrame();

  WebView().AdvanceFocus(false);

  auto* frame = To<LocalFrame>(WebView().GetPage()->MainFrame());
  LocalFrameView* frame_view = frame->View();
  gfx::Rect inputRect(200, 600, 100, 20);

  frame_view->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0, 0), mojom::blink::ScrollType::kProgrammatic);

  ASSERT_EQ(gfx::Point(),
            frame_view->GetScrollableArea()->VisibleContentRect().origin());

  WebView()
      .MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();

  EXPECT_EQ(1, WebView().FakePageScaleAnimationPageScaleForTesting());

  frame_view->LayoutViewport()->SetScrollOffset(
      ScrollOffset(WebView()
                       .FakePageScaleAnimationTargetPositionForTesting()
                       .OffsetFromOrigin()),
      mojom::blink::ScrollType::kProgrammatic);

  EXPECT_TRUE(frame_view->GetScrollableArea()->VisibleContentRect().Contains(
      inputRect));

  // Reset the testing getters.
  WebView().EnableFakePageScaleAnimationForTesting(true);

  // This input is already in view, this shouldn't cause a scroll.
  WebView()
      .MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();

  EXPECT_EQ(0, WebView().FakePageScaleAnimationPageScaleForTesting());
  EXPECT_EQ(gfx::Point(),
            WebView().FakePageScaleAnimationTargetPositionForTesting());

  // Now resize the visual viewport so that the input box is no longer in view
  // (e.g. a keyboard is overlaid).
  WebView().ResizeVisualViewport(gfx::Size(200, 100));
  ASSERT_FALSE(frame_view->GetScrollableArea()->VisibleContentRect().Contains(
      inputRect));

  WebView()
      .MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();
  frame_view->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(WebView()
                       .FakePageScaleAnimationTargetPositionForTesting()
                       .OffsetFromOrigin()),
      mojom::blink::ScrollType::kProgrammatic);

  EXPECT_TRUE(frame_view->GetScrollableArea()->VisibleContentRect().Contains(
      inputRect));
  EXPECT_EQ(1, WebView().FakePageScaleAnimationPageScaleForTesting());
}

// Ensures scrolling a focused editable text into view that's located in the
// root scroller works by scrolling the root scroller.
TEST_F(WebFrameSimTest, TestScrollFocusedEditableInRootScroller) {
  ScopedImplicitRootScrollerForTest implicit_root_scroller(true);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  WebView().SetDefaultPageScaleLimits(1.f, 4);
  WebView().EnableFakePageScaleAnimationForTesting(true);
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);
  WebView().GetPage()->GetSettings().SetViewportEnabled(false);
  WebView().GetSettings()->SetAutoZoomFocusedEditableToLegibleScale(true);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        ::-webkit-scrollbar {
          width: 0px;
          height: 0px;
        }
        body,html {
          width: 100%;
          height: 100%;
          margin: 0px;
        }
        input {
          border: 0;
          padding: 0;
          margin-left: 200px;
          margin-top: 700px;
          width: 100px;
          height: 20px;
        }
        #scroller {
          background: silver;
          width: 100%;
          height: 100%;
          overflow: auto;
        }
      </style>
      <div id="scroller" tabindex="-1">
        <input type="text">
      </div>
  )HTML");

  Compositor().BeginFrame();

  TopDocumentRootScrollerController& rs_controller =
      GetDocument().GetPage()->GlobalRootScrollerController();

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  ASSERT_EQ(scroller, rs_controller.GlobalRootScroller());

  auto* frame = To<LocalFrame>(WebView().GetPage()->MainFrame());
  VisualViewport& visual_viewport = frame->GetPage()->GetVisualViewport();

  WebView().AdvanceFocus(false);

  rs_controller.RootScrollerArea()->SetScrollOffset(
      ScrollOffset(0, 300), mojom::blink::ScrollType::kProgrammatic);

  LocalFrameView* frame_view = frame->View();
  gfx::Rect inputRect(200, 700, 100, 20);
  ASSERT_EQ(1, visual_viewport.Scale());
  ASSERT_EQ(gfx::Point(0, 300),
            frame_view->GetScrollableArea()->VisibleContentRect().origin());
  ASSERT_FALSE(frame_view->GetScrollableArea()->VisibleContentRect().Contains(
      inputRect));

  WebView()
      .MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();

  EXPECT_EQ(1, WebView().FakePageScaleAnimationPageScaleForTesting());

  ScrollOffset target_offset(
      WebView()
          .FakePageScaleAnimationTargetPositionForTesting()
          .OffsetFromOrigin());

  rs_controller.RootScrollerArea()->SetScrollOffset(
      target_offset, mojom::blink::ScrollType::kProgrammatic);

  EXPECT_TRUE(frame_view->GetScrollableArea()->VisibleContentRect().Contains(
      inputRect));
}

TEST_F(WebFrameSimTest, ScrollFocusedIntoViewClipped) {
  // The Android On-Screen Keyboard (OSK) resizes the Widget Blink is hosted
  // in. When the keyboard is shown, we scroll and zoom in on the currently
  // focused editable element. However, the scroll and zoom is a smoothly
  // animated "PageScaleAnimation" that's performed in CC only on the viewport
  // layers. There are some situations in which the widget resize causes the
  // focued input to be hidden by clipping parents that aren't the main frame.
  // In these cases, there's no way to scroll just the viewport to make the
  // input visible, we need to also scroll those clip/scroller elements  This
  // test ensures we do so. https://crbug.com/270018.
  UseAndroidSettings();
  WebView().MainFrameViewWidget()->Resize(gfx::Size(400, 600));
  WebView().EnableFakePageScaleAnimationForTesting(true);
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        ::-webkit-scrollbar {
          width: 0px;
          height: 0px;
        }
        body, html {
          margin: 0px;
          width: 100%;
          height: 100%;
        }
        input {
          padding: 0;
          position: relative;
          top: 1400px;
          width: 100px;
          height: 20px;
        }
        #clip {
          width: 100%;
          height: 100%;
          overflow: hidden;
        }
        #container {
          width: 980px;
          height: 1470px;
        }
      </style>
      <div id="clip">
        <div id="container">
          <input type="text" id="target">
        </div>
      </div>
  )HTML");

  Compositor().BeginFrame();
  WebView().AdvanceFocus(false);

  auto* frame = To<LocalFrame>(WebView().GetPage()->MainFrame());
  LocalFrameView* frame_view = frame->View();
  VisualViewport& visual_viewport = frame->GetPage()->GetVisualViewport();

  ASSERT_EQ(gfx::Point(),
            frame_view->GetScrollableArea()->VisibleContentRect().origin());

  // Simulate the keyboard being shown and resizing the widget. Cause a scroll
  // into view after.
  WebView().MainFrameViewWidget()->Resize(gfx::Size(400, 300));

  float scale_before = visual_viewport.Scale();
  WebView()
      .MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();

  Element* input = GetDocument().getElementById(AtomicString("target"));
  gfx::Rect input_rect(input->GetBoundingClientRect()->top(),
                       input->GetBoundingClientRect()->left(),
                       input->GetBoundingClientRect()->width(),
                       input->GetBoundingClientRect()->height());

  gfx::Rect visible_content_rect(frame_view->Size());
  EXPECT_TRUE(visible_content_rect.Contains(input_rect))
      << "Layout viewport [" << visible_content_rect.ToString()
      << "] does not contain input rect [" << input_rect.ToString()
      << "] after scroll into view.";

  EXPECT_TRUE(visual_viewport.VisibleRect().Contains(gfx::RectF(input_rect)))
      << "Visual viewport [" << visual_viewport.VisibleRect().ToString()
      << "] does not contain input rect [" << input_rect.ToString()
      << "] after scroll into view.";

  // Make sure we also zoomed in on the input.
  EXPECT_GT(WebView().FakePageScaleAnimationPageScaleForTesting(),
            scale_before);

  // Additional gut-check that we actually scrolled the non-user-scrollable
  // clip element to make sure the input is in view.
  Element* clip = GetDocument().getElementById(AtomicString("clip"));
  EXPECT_GT(clip->scrollTop(), 0);
}

// This test ensures that we scroll to the correct scale when the focused
// element has a selection rather than a caret.
TEST_F(WebFrameSimTest, ScrollFocusedSelectionIntoView) {
  UseAndroidSettings();
  WebView().MainFrameViewWidget()->Resize(gfx::Size(400, 600));
  WebView().EnableFakePageScaleAnimationForTesting(true);
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        ::-webkit-scrollbar {
          width: 0px;
          height: 0px;
        }
        body, html {
          margin: 0px;
          width: 100%;
          height: 100%;
        }
        input {
          padding: 0;
          width: 100px;
          height: 20px;
        }
      </style>
      <input type="text" id="target" value="test">
  )HTML");

  Compositor().BeginFrame();
  WebView().AdvanceFocus(false);

  auto* input = To<HTMLInputElement>(
      GetDocument().getElementById(AtomicString("target")));
  input->select();

  // Simulate the keyboard being shown and resizing the widget. Cause a scroll
  // into view after.
  ASSERT_EQ(WebView().FakePageScaleAnimationPageScaleForTesting(), 0.f);
  WebFrameWidget* widget = WebView().MainFrameImpl()->FrameWidgetImpl();
  widget->ScrollFocusedEditableElementIntoView();

  // Make sure zoomed in but only up to a legible scale. The bounds are
  // arbitrary and fuzzy since we don't specifically care to constrain the
  // amount of zooming (that should be tested elsewhere), we just care that it
  // zooms but not off to infinity.
  EXPECT_GT(WebView().FakePageScaleAnimationPageScaleForTesting(), .75f);
  EXPECT_LT(WebView().FakePageScaleAnimationPageScaleForTesting(), 2.f);
}

TEST_F(WebFrameSimTest, DoubleTapZoomWhileScrolled) {
  UseAndroidSettings();
  WebView().MainFrameViewWidget()->Resize(gfx::Size(490, 500));
  WebView().EnableFakePageScaleAnimationForTesting(true);
  WebView().GetSettings()->SetTextAutosizingEnabled(false);
  WebView().SetDefaultPageScaleLimits(0.5f, 4);

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        ::-webkit-scrollbar {
          width: 0px;
          height: 0px;
        }
        body {
          margin: 0px;
          width: 10000px;
          height: 10000px;
        }
        #target {
          position: absolute;
          left: 2000px;
          top: 3000px;
          width: 100px;
          height: 100px;
          background-color: blue;
        }
      </style>
      <div id="target"></div>
  )HTML");

  Compositor().BeginFrame();

  auto* frame = To<LocalFrame>(WebView().GetPage()->MainFrame());
  LocalFrameView* frame_view = frame->View();
  VisualViewport& visual_viewport = frame->GetPage()->GetVisualViewport();
  gfx::Rect target_rect_in_document(2000, 3000, 100, 100);

  ASSERT_EQ(0.5f, visual_viewport.Scale());

  // Center the target in the screen.
  frame_view->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(2000 - 440, 3000 - 450),
      mojom::blink::ScrollType::kProgrammatic);
  Element* target = GetDocument().QuerySelector(AtomicString("#target"));
  DOMRect* rect = target->GetBoundingClientRect();
  ASSERT_EQ(440, rect->left());
  ASSERT_EQ(450, rect->top());

  // Double-tap on the target. Expect that we zoom in and the target is
  // contained in the visual viewport.
  {
    gfx::Point point(445, 455);
    gfx::Rect block_bounds = ComputeBlockBoundHelper(&WebView(), point, false);
    WebView().AnimateDoubleTapZoom(point, block_bounds);
    EXPECT_TRUE(WebView().FakeDoubleTapAnimationPendingForTesting());
    ScrollOffset new_offset(
        WebView()
            .FakePageScaleAnimationTargetPositionForTesting()
            .OffsetFromOrigin());
    float new_scale = WebView().FakePageScaleAnimationPageScaleForTesting();
    visual_viewport.SetScale(new_scale);
    frame_view->GetScrollableArea()->SetScrollOffset(
        new_offset, mojom::blink::ScrollType::kProgrammatic);

    EXPECT_FLOAT_EQ(1, visual_viewport.Scale());
    EXPECT_TRUE(frame_view->GetScrollableArea()->VisibleContentRect().Contains(
        target_rect_in_document));
  }

  // Reset the testing getters.
  WebView().EnableFakePageScaleAnimationForTesting(true);

  // Double-tap on the target again. We should zoom out and the target should
  // remain on screen.
  {
    gfx::Point point(445, 455);
    gfx::Rect block_bounds = ComputeBlockBoundHelper(&WebView(), point, false);
    WebView().AnimateDoubleTapZoom(point, block_bounds);
    EXPECT_TRUE(WebView().FakeDoubleTapAnimationPendingForTesting());
    gfx::Point target_offset(
        WebView().FakePageScaleAnimationTargetPositionForTesting());
    float new_scale = WebView().FakePageScaleAnimationPageScaleForTesting();

    EXPECT_FLOAT_EQ(0.5f, new_scale);
    EXPECT_TRUE(target_rect_in_document.Contains(target_offset));
  }
}

TEST_F(WebFrameSimTest, ChangeBackgroundColor) {
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");
  main_resource.Complete("<!DOCTYPE html><body></body>");

  Element* body = GetDocument().QuerySelector(AtomicString("body"));
  EXPECT_TRUE(!!body);

  Compositor().BeginFrame();
  // White is the default background of a web page.
  EXPECT_EQ(SK_ColorWHITE, Compositor().background_color());

  // Setting the background of the body to red will cause the background
  // color of the WebView to switch to red.
  body->SetInlineStyleProperty(CSSPropertyID::kBackgroundColor, "red");
  Compositor().BeginFrame();
  EXPECT_EQ(SK_ColorRED, Compositor().background_color());
}

// Ensure we don't crash if we try to scroll into view the focused editable
// element which doesn't have a LayoutObject.
TEST_F(WebFrameSimTest, ScrollFocusedEditableIntoViewNoLayoutObject) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 600));
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);

  SimRequest r("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  r.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        input {
          position: absolute;
          top: 1000px;
          left: 800px;
        }

        @media (max-height: 500px) {
          input {
            display: none;
          }
        }
      </style>
      <input id="target" type="text"></input>
  )HTML");

  Compositor().BeginFrame();

  Element* input = GetDocument().getElementById(AtomicString("target"));
  input->Focus();

  ScrollableArea* area = GetDocument().View()->LayoutViewport();
  area->SetScrollOffset(ScrollOffset(0, 0),
                        mojom::blink::ScrollType::kProgrammatic);

  ASSERT_TRUE(input->GetLayoutObject());
  ASSERT_EQ(input, WebView().FocusedElement());
  ASSERT_EQ(ScrollOffset(0, 0), area->GetScrollOffset());

  // The resize should cause the focused element to lose its LayoutObject. If
  // this resize came from the Android on-screen keyboard, this would be
  // followed by a ScrollFocusedEditableElementIntoView. Ensure we don't crash.
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 300));

  ASSERT_FALSE(input->GetLayoutObject());
  ASSERT_EQ(input, WebView().FocusedElement());

  WebFrameWidget* widget = WebView().MainFrameImpl()->FrameWidgetImpl();
  widget->ScrollFocusedEditableElementIntoView();
  Compositor().BeginFrame();

  // Shouldn't cause any scrolling either.
  EXPECT_EQ(ScrollOffset(0, 0), area->GetScrollOffset());
}

TEST_F(WebFrameSimTest, ScrollEditContextIntoView) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(500, 600));
  WebView().GetPage()->GetSettings().SetTextAutosizingEnabled(false);
  WebView().SetZoomFactorForDeviceScaleFactor(2.0f);

  SimRequest r("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  r.Complete(R"HTML(
      <!DOCTYPE html>
      <div id="target" style='width:2000px;height:2000px'></div>
      <script>
        const editContext = new EditContext();
        const target = document.getElementById('target');
        target.editContext = editContext;
        target.focus();
        let controlBounds = new DOMRect(500, 850, 1, 20);
        editContext.updateControlBounds(controlBounds);
      </script>
  )HTML");

  WebView().EnableFakePageScaleAnimationForTesting(true);

  WebView()
      .MainFrameImpl()
      ->FrameWidgetImpl()
      ->ScrollFocusedEditableElementIntoView();

  // scrollOffset.x = controlBound.x * zoom - left padding = 500 * 2 - 150 = 850
  // scrollOffset.y = controlBound.y * zoom - (viewport.height -
  // controlBound.height * 2)/2
  //                = 850 * 2 - (600 - 20 * 2) / 2 = 1420
  EXPECT_EQ(gfx::Point(850, 1420),
            WebView().FakePageScaleAnimationTargetPositionForTesting());
}

TEST_F(WebFrameSimTest, DisplayNoneIFrameHasNoLayoutObjects) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");

  LoadURL("https://example.com/test.html");
  main_resource.Complete(
      "<!DOCTYPE html>"
      "<iframe src=frame.html style='display: none'></iframe>");
  frame_resource.Complete(
      "<!DOCTYPE html>"
      "<html><body>This is a visible iframe.</body></html>");

  Element* element = GetDocument().QuerySelector(AtomicString("iframe"));
  auto* frame_owner_element = To<HTMLFrameOwnerElement>(element);
  Document* iframe_doc = frame_owner_element->contentDocument();
  EXPECT_FALSE(iframe_doc->documentElement()->GetLayoutObject());

  // Changing the display from 'none' -> 'block' should cause layout objects to
  // appear.
  element->SetInlineStyleProperty(CSSPropertyID::kDisplay, CSSValueID::kBlock);
  Compositor().BeginFrame();
  EXPECT_TRUE(iframe_doc->documentElement()->GetLayoutObject());

  // Changing the display from 'block' -> 'none' should cause layout objects to
  // disappear.
  element->SetInlineStyleProperty(CSSPropertyID::kDisplay, CSSValueID::kNone);

  Compositor().BeginFrame();
  EXPECT_FALSE(iframe_doc->documentElement()->GetLayoutObject());
}

// Although it is not spec compliant, many websites intentionally call
// Window.print() on display:none iframes. https://crbug.com/819327.
TEST_F(WebFrameSimTest, DisplayNoneIFramePrints) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");

  LoadURL("https://example.com/test.html");
  main_resource.Complete(
      "<!DOCTYPE html>"
      "<iframe src=frame.html style='display: none'></iframe>");
  frame_resource.Complete(
      "<!DOCTYPE html>"
      "<html><body>This is a visible iframe.</body></html>");

  Element* element = GetDocument().QuerySelector(AtomicString("iframe"));
  auto* frame_owner_element = To<HTMLFrameOwnerElement>(element);
  Document* iframe_doc = frame_owner_element->contentDocument();
  EXPECT_FALSE(iframe_doc->documentElement()->GetLayoutObject());

  gfx::SizeF page_size(400, 400);
  float maximum_shrink_ratio = 1.0;
  iframe_doc->GetFrame()->StartPrinting(WebPrintParams(page_size),
                                        maximum_shrink_ratio);
  EXPECT_TRUE(iframe_doc->documentElement()->GetLayoutObject());

  iframe_doc->GetFrame()->EndPrinting();
  EXPECT_FALSE(iframe_doc->documentElement()->GetLayoutObject());
}

TEST_F(WebFrameSimTest, NormalIFrameHasLayoutObjects) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");

  LoadURL("https://example.com/test.html");
  main_resource.Complete(
      "<!DOCTYPE html>"
      "<iframe src=frame.html style='display: block'></iframe>");
  frame_resource.Complete(
      "<!DOCTYPE html>"
      "<html><body>This is a visible iframe.</body></html>");

  Element* element = GetDocument().QuerySelector(AtomicString("iframe"));
  auto* frame_owner_element = To<HTMLFrameOwnerElement>(element);
  Document* iframe_doc = frame_owner_element->contentDocument();
  EXPECT_TRUE(iframe_doc->documentElement()->GetLayoutObject());

  // Changing the display from 'block' -> 'none' should cause layout objects to
  // disappear.
  element->SetInlineStyleProperty(CSSPropertyID::kDisplay, CSSValueID::kNone);
  Compositor().BeginFrame();
  EXPECT_FALSE(iframe_doc->documentElement()->GetLayoutObject());
}

TEST_F(WebFrameSimTest, RtlInitialScrollOffsetWithViewport) {
  UseAndroidSettings();

  WebView().MainFrameViewWidget()->Resize(gfx::Size(400, 400));
  WebView().SetDefaultPageScaleLimits(0.25f, 2);

  SimRequest main_resource("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_resource.Complete(R"HTML(
    <meta name='viewport' content='width=device-width, minimum-scale=1'>
    <body dir='rtl'>
    <div style='width: 3000px; height: 20px'></div>
  )HTML");

  Compositor().BeginFrame();
  ScrollableArea* area = GetDocument().View()->LayoutViewport();
  ASSERT_EQ(ScrollOffset(0, 0), area->GetScrollOffset());
}

TEST_F(WebFrameSimTest, LayoutViewportExceedsLayoutOverflow) {
  UseAndroidSettings();

  WebView().ResizeWithBrowserControls(gfx::Size(400, 540), 60, 0, true);
  WebView().SetDefaultPageScaleLimits(0.25f, 2);

  SimRequest main_resource("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_resource.Complete(R"HTML(
    <meta name='viewport' content='width=device-width, minimum-scale=1'>
    <body style='margin: 0; height: 95vh'>
  )HTML");

  Compositor().BeginFrame();
  ScrollableArea* area = GetDocument().View()->LayoutViewport();
  ASSERT_EQ(540, area->VisibleHeight());
  ASSERT_EQ(gfx::Size(400, 570), area->ContentsSize());

  // Hide browser controls, growing layout viewport without affecting ICB.
  WebView().ResizeWithBrowserControls(gfx::Size(400, 600), 60, 0, false);
  Compositor().BeginFrame();

  // ContentsSize() should grow to accommodate new visible size.
  ASSERT_EQ(600, area->VisibleHeight());
  ASSERT_EQ(gfx::Size(400, 600), area->ContentsSize());
}

TEST_F(WebFrameSimTest, NamedLookupIgnoresEmptyNames) {
  SimRequest main_resource("https://example.com/main.html", "text/html");
  LoadURL("https://example.com/main.html");
  main_resource.Complete(R"HTML(
    <body>
    <iframe name="" src="data:text/html,"></iframe>
    </body>)HTML");

  EXPECT_EQ(nullptr, MainFrame().GetFrame()->Tree().ScopedChild(g_empty_atom));
  EXPECT_EQ(nullptr,
            MainFrame().GetFrame()->Tree().ScopedChild(AtomicString()));
  EXPECT_EQ(nullptr, MainFrame().GetFrame()->Tree().ScopedChild(g_empty_atom));
}

TEST_F(WebFrameTest, NoLoadingCompletionCallbacksInDetach) {
  class LoadingObserverFrameClient
      : public frame_test_helpers::TestWebFrameClient {
   public:
    LoadingObserverFrameClient() = default;
    ~LoadingObserverFrameClient() override = default;

    // frame_test_helpers::TestWebFrameClient:
    void FrameDetached(DetachReason detach_reason) override {
      did_call_frame_detached_ = true;
      TestWebFrameClient::FrameDetached(detach_reason);
    }

    void DidStopLoading() override {
      // TODO(dcheng): Investigate not calling this as well during frame detach.
      did_call_did_stop_loading_ = true;
      TestWebFrameClient::DidStopLoading();
    }

    void DidDispatchDOMContentLoadedEvent() override {
      // TODO(dcheng): Investigate not calling this as well during frame detach.
      did_call_did_dispatch_dom_content_loaded_event_ = true;
    }

    void DidHandleOnloadEvents() override {
      // TODO(dcheng): Investigate not calling this as well during frame detach.
      did_call_did_handle_onload_events_ = true;
    }

    void DidFinishLoad() override {
      EXPECT_TRUE(false) << "didFinishLoad() should not have been called.";
    }

    bool DidCallFrameDetached() const { return did_call_frame_detached_; }
    bool DidCallDidStopLoading() const { return did_call_did_stop_loading_; }
    bool DidCallDidDispatchDOMContentLoadedEvent() const {
      return did_call_did_dispatch_dom_content_loaded_event_;
    }
    bool DidCallDidHandleOnloadEvents() const {
      return did_call_did_handle_onload_events_;
    }

   private:
    bool did_call_frame_detached_ = false;
    bool did_call_did_stop_loading_ = false;
    bool did_call_did_dispatch_dom_content_loaded_event_ = false;
    bool did_call_did_handle_onload_events_ = false;
  };

  class MainFrameClient : public frame_test_helpers::TestWebFrameClient {
   public:
    MainFrameClient() = default;
    ~MainFrameClient() override = default;

    // frame_test_helpers::TestWebFrameClient:
    WebLocalFrame* CreateChildFrame(
        mojom::blink::TreeScopeType scope,
        const WebString& name,
        const WebString& fallback_name,
        const FramePolicy&,
        const WebFrameOwnerProperties&,
        FrameOwnerElementType,
        WebPolicyContainerBindParams policy_container_bind_params,
        ukm::SourceId document_ukm_source_id,
        FinishChildFrameCreationFn finish_creation) override {
      return CreateLocalChild(*Frame(), scope, &child_client_,
                              std::move(policy_container_bind_params),
                              finish_creation);
    }

    LoadingObserverFrameClient& ChildClient() { return child_client_; }

   private:
    LoadingObserverFrameClient child_client_;
  };

  RegisterMockedHttpURLLoad("single_iframe.html");
  url_test_helpers::RegisterMockedURLLoad(
      ToKURL(base_url_ + "visible_iframe.html"),
      test::CoreTestDataPath("frame_with_frame.html"));
  RegisterMockedHttpURLLoad("parent_detaching_frame.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  MainFrameClient main_frame_client;
  web_view_helper.InitializeAndLoad(base_url_ + "single_iframe.html",
                                    &main_frame_client);

  EXPECT_TRUE(main_frame_client.ChildClient().DidCallFrameDetached());
  EXPECT_TRUE(main_frame_client.ChildClient().DidCallDidStopLoading());
  EXPECT_TRUE(main_frame_client.ChildClient()
                  .DidCallDidDispatchDOMContentLoadedEvent());
  EXPECT_TRUE(main_frame_client.ChildClient().DidCallDidHandleOnloadEvents());

  web_view_helper.Reset();
}

TEST_F(WebFrameTest, ClearClosedOpener) {
  frame_test_helpers::WebViewHelper opener_helper;
  opener_helper.Initialize();
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeWithOpener(opener_helper.GetWebView()->MainFrame());

  opener_helper.Reset();
  EXPECT_EQ(nullptr, helper.LocalM
```