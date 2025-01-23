Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a test file for the Chromium Blink engine. Specifically, this part focuses on testing the behavior of root scrollers, especially in the context of iframes and implicitly selected root scrollers.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Topic:** The filename `root_scroller_test.cc` and the keywords "rootScroller" and "iframe" appearing frequently clearly indicate the central theme.

2. **Analyze Individual Tests:** Go through each `TEST_F` block and understand its purpose. Look for setup steps (like `Initialize` or loading HTML), actions performed (like resizing the WebView or manipulating DOM elements), and assertions (`ASSERT_EQ`, `EXPECT_EQ`, `EXPECT_FALSE`, `EXPECT_TRUE`).

3. **Group Related Tests:** Notice patterns in the tests. Some tests deal with explicit iframe root scrollers, others with implicit root scrollers (where Blink automatically chooses a scrolling element). Within implicit root scroller tests, some focus on basic functionality, others on specific edge cases like visibility, overflow, or interactions with layout.

4. **Extract Key Functionalities Being Tested:**  Based on the analysis of individual tests and their grouping, identify the core functionalities being verified. For example:
    * How the layout and size of an iframe-as-root-scroller are managed during browser control changes (URL bar visibility, rotation).
    * How removing an iframe root scroller affects the layout viewport.
    * The conditions under which an element becomes an *implicit* root scroller (overflow properties, viewport filling, visibility).
    * How dynamic changes (adding/removing overflow, changing visibility, resizing) affect the selection of the implicit root scroller.
    * Handling edge cases like removing the content frame of a root scroller or dealing with plugin views.
    * The impact of root scrollers on visual viewport properties.
    * Use counting for implicit root scroller activation.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**  Many tests manipulate the DOM using methods like `getElementById`, `querySelector`, `remove()`, and modify CSS styles using the `style()` object. This directly links the tests to how JavaScript, HTML, and CSS interact in a browser environment to control layout and scrolling. Provide examples of how these technologies are used in the tests.

6. **Identify Potential User/Developer Errors:** Think about what could go wrong when developers are working with iframes and scrolling. For instance, misunderstanding how iframe sizes are managed when they are root scrollers, or expecting a specific element to become a root scroller without meeting the necessary CSS criteria.

7. **Consider Debugging Scenarios:** How would a developer end up looking at this test file?  Likely if they are encountering issues related to iframe scrolling, unexpected layout behavior when using `overflow`, or problems with the visual viewport. Describe user actions that could lead to these scenarios.

8. **Formulate Assumptions and Outputs (Logical Reasoning):** For tests that demonstrate a cause-and-effect relationship (like changing a style and observing the root scroller), provide a simplified "if this input, then this output" explanation.

9. **Synthesize the Summary:**  Combine the extracted functionalities, web technology connections, potential errors, debugging scenarios, and logical reasoning into a concise summary of the code snippet's purpose.

10. **Address the "Part 2" Instruction:**  Specifically state that the provided code focuses on a subset of root scroller tests, mainly concerning iframe root scrollers and implicit root scroller selection.

**(Self-Correction during thought process):** Initially, I might have focused too much on the low-level C++ aspects. However, the prompt specifically asks about the relationship to JavaScript, HTML, and CSS. Therefore, the emphasis should be on how these web technologies are used *within* the tests to verify the root scroller behavior. Also, ensuring the examples are clear and directly related to the code snippets is crucial.
这是 `blink/renderer/core/page/scrolling/root_scroller_test.cc` 文件的第二部分，它主要关注以下功能：

**主要功能归纳：**

* **测试 iframe 作为根滚动器的行为：**  这部分测试了当一个 `<iframe>` 元素被设置为根滚动器时，其布局和尺寸如何受到浏览器控制（例如，地址栏的显示与隐藏）和设备旋转的影响。它验证了 iframe 的 `layoutSize` (用于布局计算的尺寸) 和 `Size` (实际占据的屏幕尺寸) 之间的关系在不同场景下的正确性。
* **测试移除根滚动器后的行为：**  包含一个测试用例，验证了当一个 iframe 作为根滚动器被移除后，主框架的布局视口会立即更新，因为它不再是分离的布局层级的一部分。
* **测试隐式根滚动器的选择机制：**  这部分引入了 `ImplicitRootScrollerSimTest` 类，用于测试 Blink 引擎自动选择根滚动器的机制。它涵盖了多种场景，包括：
    * **Document 成为隐式根滚动器：** 测试在文档拥有 LayoutView 之前成为根滚动器的情况。
    * **非生命周期布局不会触发根滚动器重选：**  验证在不完整的生命周期更新中进行布局不会导致重新选择根滚动器。
    * **处理 `ContentFrame` 不存在的情况：**  测试在根滚动器的 `ContentFrame` 不存在时重新计算根滚动器是否会导致崩溃。
    * **使用 padding box 判断视口填充：**  验证只有当元素的 padding box 填充视口时，该元素才被认为是视口填充元素，这意味着元素不能有边框 (border)。
    * **根滚动器不影响 `visualViewport` 的 `pageLeft` 和 `pageTop`：** 确认即使存在自定义的根滚动器，`visualViewport` 的偏移量仍然相对于文档的起始位置。
    * **在布局中调整大小：**  测试在布局过程中进行大小调整是否会导致崩溃或违反生命周期假设。
    * **基本的隐式根滚动器选择：**  通过设置不同的 CSS `overflow` 属性来测试 `<div>` 元素是否能被正确地提升为隐式根滚动器。
    * **添加 `overflow` 属性触发隐式根滚动器提升：**  验证向一个符合条件但没有 `overflow` 属性的元素添加 `overflow` 属性后，它会被提升为隐式根滚动器。
    * **候选元素失去布局盒子时的处理：**  测试当一个作为隐式根滚动器候选的元素不再是盒子（例如，`display: inline`）时，不会发生崩溃。
    * **考虑插件 (embed) 元素作为隐式根滚动器：**  确保在考虑插件元素作为隐式根滚动器时不会发生崩溃。
    * **当主文档存在滚动溢出时，阻止隐式根滚动器的提升/降级：**  验证当主文档自身可以滚动时，即使其他元素符合条件，也不会被提升为隐式根滚动器，反之亦然。
    * **元素的可见性作为隐式根滚动器的条件：**  测试只有可见的元素才能被提升为隐式根滚动器 (`opacity` 和 `visibility` 属性的影响)。
    * **iframe 的隐式根滚动器：**  测试 `<iframe>` 元素在特定样式下如何成为隐式根滚动器。
    * **隐式根滚动器的使用计数器：**  测试是否正确记录了页面是否使用了隐式根滚动器。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:**  测试用例中使用了 HTML 结构，例如创建 `<iframe>` 元素和 `<div>` 元素。例如，`Initialize("root-scroller-iframe.html")` 加载了一个包含 iframe 的 HTML 文件。
* **CSS:**  测试大量使用了 CSS 属性来控制元素的样式和布局，特别是与滚动相关的属性，如 `overflow`, `overflow-x`, `overflow-y`, `width`, `height`, `border`, `opacity`, `visibility` 等。例如，通过 `ExecuteScript("document.querySelector('#iframe').style.opacity = '0.5'")`  使用 JavaScript 修改了 iframe 的 CSS `opacity` 属性。
* **JavaScript:**  测试中使用了 JavaScript 代码来与 DOM 交互，例如使用 `document.getElementById` 获取元素，使用 `remove()` 移除元素，以及修改元素的样式。例如，`ExecuteScript` 函数用于执行 JavaScript 代码。

**逻辑推理与假设输入输出：**

**假设输入:**  一个包含如下 HTML 的页面：

```html
<!DOCTYPE html>
<html>
<head>
<style>
  #container {
    width: 100%;
    height: 100%;
    overflow: auto;
  }
  #spacer {
    width: 2000px;
    height: 2000px;
  }
</style>
</head>
<body>
  <div id="container">
    <div id="spacer"></div>
  </div>
</body>
</html>
```

**输出:**  在 `ImplicitRootScrollerSimTest` 中的相关测试用例中，如果执行 `Compositor().BeginFrame()`，并且满足隐式根滚动器的条件，那么 `#container` 元素会被识别为有效的根滚动器。

**用户或编程常见使用错误举例：**

* **错误地认为 iframe 的 `layoutSize` 会自动跟随其 `Size`：**  当 iframe 被设置为根滚动器时，其 `layoutSize` 可能由浏览器控制，而不是直接由 iframe 的尺寸决定。开发者可能会因为不理解这种机制而遇到布局问题。
* **期望一个设置了 `border` 的元素成为隐式根滚动器：**  根据测试，只有当元素的 padding box 填充视口时，它才能成为隐式根滚动器。添加 `border` 会导致 padding box 缩小，从而可能阻止元素成为根滚动器。
* **不理解 `opacity` 和 `visibility` 对隐式根滚动器的影响：**  开发者可能期望一个设置了 `opacity: 0.5` 或 `visibility: hidden` 的可滚动元素成为隐式根滚动器，但测试表明这些属性会阻止元素被提升。

**用户操作到达此处的调试线索：**

一个开发者可能因为以下用户操作或场景而需要调试根滚动器的行为，并最终查看此测试文件：

1. **用户报告页面滚动异常：**  用户可能会发现页面无法正常滚动，或者滚动行为与预期不符，尤其是在包含 `<iframe>` 元素或者有复杂的 CSS 布局的页面上。
2. **开发者在实现自定义滚动效果时遇到问题：**  开发者可能尝试使用特定的 HTML 结构和 CSS 属性来创建一个具有自定义滚动行为的区域，但发现根滚动器的选择或行为阻止了他们的实现。
3. **在不同浏览器窗口大小或设备方向上布局错乱：**  由于根滚动器在不同环境下的行为可能不同，开发者可能会在调整浏览器窗口大小或在移动设备上旋转屏幕时遇到布局问题。
4. **使用 `<iframe>` 嵌入第三方内容时出现滚动问题：**  当一个页面嵌入了其他页面时，根滚动器的处理变得复杂，开发者可能需要调试以确保滚动行为符合预期。
5. **性能问题与滚动相关：**  不正确的根滚动器配置可能导致不必要的重绘和重排，影响页面性能。开发者可能会调查根滚动器的行为以优化性能。

为了调试这些问题，开发者可能会：

* 使用浏览器的开发者工具检查元素的滚动属性和布局信息。
* 使用 "Paint flashing" 或 "Layout Shift Regions" 等工具来可视化渲染过程和布局变化。
* 断点调试 Blink 引擎的渲染代码，特别是与滚动和布局相关的部分。
* 查看和理解相关的测试用例，例如 `root_scroller_test.cc`，以了解 Blink 引擎内部对根滚动器的预期行为。

**总结 (针对第二部分):**

这部分 `root_scroller_test.cc` 主要集中在测试 **iframe 作为根滚动器** 和 **隐式根滚动器的选择机制**。它详细验证了在各种场景下，包括浏览器控制、动态 DOM 操作和 CSS 属性变化时，根滚动器的行为是否符合预期。这些测试覆盖了与 HTML 结构、CSS 样式和 JavaScript DOM 操作的交互，并帮助开发者理解可能导致滚动问题的常见错误。

### 提示词
```
这是目录为blink/renderer/core/page/scrolling/root_scroller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
itialize("root-scroller-iframe.html");
  UpdateAllLifecyclePhases(MainFrameView());

  auto* iframe = To<HTMLFrameOwnerElement>(
      MainFrame()->GetDocument()->getElementById(AtomicString("iframe")));
  auto* iframe_view = To<LocalFrame>(iframe->ContentFrame())->View();

  ASSERT_EQ(gfx::Size(400, 400), iframe_view->GetLayoutSize());
  ASSERT_EQ(gfx::Size(400, 400), iframe_view->Size());

  // Make the iframe the rootscroller. This should cause the iframe's layout
  // size to be manually controlled.
  {
    ASSERT_EQ(iframe, EffectiveRootScroller(MainFrame()->GetDocument()));
    EXPECT_FALSE(iframe_view->LayoutSizeFixedToFrameSize());
    EXPECT_EQ(gfx::Size(400, 400), iframe_view->GetLayoutSize());
    EXPECT_EQ(gfx::Size(400, 400), iframe_view->Size());
  }

  // Hide the URL bar, the iframe's frame rect should expand but the layout
  // size should remain the same.
  {
    GetWebView()->ResizeWithBrowserControls(gfx::Size(400, 450), 50, 0, false);
    UpdateAllLifecyclePhases(MainFrameView());
    EXPECT_EQ(gfx::Size(400, 400), iframe_view->GetLayoutSize());
    EXPECT_EQ(gfx::Size(400, 450), iframe_view->Size());
  }

  // Simulate a rotation. This time the layout size should reflect the resize.
  {
    GetWebView()->ResizeWithBrowserControls(gfx::Size(450, 400), 50, 0, false);
    UpdateAllLifecyclePhases(MainFrameView());
    EXPECT_EQ(gfx::Size(450, 350), iframe_view->GetLayoutSize());
    EXPECT_EQ(gfx::Size(450, 400), iframe_view->Size());

    // "Un-rotate" for following tests.
    GetWebView()->ResizeWithBrowserControls(gfx::Size(400, 450), 50, 0, false);
    UpdateAllLifecyclePhases(MainFrameView());
  }

  // Show the URL bar again. The frame rect should match the viewport.
  {
    GetWebView()->ResizeWithBrowserControls(gfx::Size(400, 400), 50, 0, true);
    UpdateAllLifecyclePhases(MainFrameView());
    EXPECT_EQ(gfx::Size(400, 400), iframe_view->GetLayoutSize());
    EXPECT_EQ(gfx::Size(400, 400), iframe_view->Size());
  }

  // Hide the URL bar and reset the rootScroller. The iframe should go back to
  // tracking layout size by frame rect.
  {
    GetWebView()->ResizeWithBrowserControls(gfx::Size(400, 450), 50, 0, false);
    UpdateAllLifecyclePhases(MainFrameView());
    EXPECT_EQ(gfx::Size(400, 400), iframe_view->GetLayoutSize());
    EXPECT_EQ(gfx::Size(400, 450), iframe_view->Size());
    ExecuteScript("document.querySelector('#iframe').style.opacity = '0.5'");
    ASSERT_EQ(MainFrame()->GetDocument(),
              EffectiveRootScroller(MainFrame()->GetDocument()));
    EXPECT_TRUE(iframe_view->LayoutSizeFixedToFrameSize());
    EXPECT_EQ(gfx::Size(400, 400), iframe_view->GetLayoutSize());
    EXPECT_EQ(gfx::Size(400, 400), iframe_view->Size());
  }
}

// Ensure that removing the root scroller element causes an update to the
// RootFrameViewport's layout viewport immediately since old layout viewport is
// now part of a detached layout hierarchy.
TEST_F(RootScrollerTest, ImmediateUpdateOfLayoutViewport) {
  Initialize("root-scroller-iframe.html");

  auto* iframe = To<HTMLFrameOwnerElement>(
      MainFrame()->GetDocument()->getElementById(AtomicString("iframe")));

  ASSERT_EQ(iframe, EffectiveRootScroller(MainFrame()->GetDocument()));

  RootScrollerController& main_controller =
      MainFrame()->GetDocument()->GetRootScrollerController();

  auto* iframe_local_frame = To<LocalFrame>(iframe->ContentFrame());
  EXPECT_EQ(iframe, &main_controller.EffectiveRootScroller());
  EXPECT_EQ(iframe_local_frame->View()->LayoutViewport(),
            &MainFrameView()->GetRootFrameViewport()->LayoutViewport());

  // Remove the <iframe> and make sure the layout viewport reverts to the
  // LocalFrameView without a layout.
  iframe->remove();

  EXPECT_EQ(MainFrameView()->LayoutViewport(),
            &MainFrameView()->GetRootFrameViewport()->LayoutViewport());
}

class ImplicitRootScrollerSimTest : public SimTest {
 public:
  ImplicitRootScrollerSimTest() : implicit_root_scroller_for_test_(true) {}
  ~ImplicitRootScrollerSimTest() override {
    // TODO(crbug.com/1315595): Consider moving this to MainThreadIsolate.
    MemoryCache::Get()->EvictResources();
    // Clear lazily loaded style sheets.
    CSSDefaultStyleSheets::Instance().PrepareForLeakDetection();
  }
  void SetUp() override {
    SimTest::SetUp();
    WebView().GetPage()->GetSettings().SetViewportEnabled(true);
  }

 private:
  ScopedImplicitRootScrollerForTest implicit_root_scroller_for_test_;
};

// Test that the cached IsEffectiveRootScroller bit on LayoutObject is set
// correctly when the Document is the effective root scroller. It becomes the
// root scroller before Document has a LayoutView.
TEST_F(ImplicitRootScrollerSimTest, DocumentEffectiveSetsCachedBit) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
          <!DOCTYPE html>
      )HTML");
  Compositor().BeginFrame();

  EXPECT_TRUE(GetDocument().GetLayoutView()->IsEffectiveRootScroller());
}

// Test that layout from outside a lifecycle wont select a new effective root
// scroller.
TEST_F(ImplicitRootScrollerSimTest, NonLifecycleLayoutDoesntCauseReselection) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
          <!DOCTYPE html>
          <style>
            body, html {
              margin: 0;
              width: 100%;
              height: 100%;
            }
            #container {
              width: 100%;
              height: 100%;
              overflow: scroll;
            }
            #spacer {
              width: 200vw;
              height: 200vh;
            }
          </style>
          <div id="container">
            <div id="spacer"></div>
          </div>
      )HTML");
  Element* container = GetDocument().getElementById(AtomicString("container"));
  Compositor().BeginFrame();
  ASSERT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  container->style()->setProperty(GetDocument().GetExecutionContext(), "width",
                                  "95%", String(), ASSERT_NO_EXCEPTION);

  ASSERT_TRUE(Compositor().NeedsBeginFrame());

  // Cause a layout.
  container->scrollTop();
  ASSERT_TRUE(Compositor().NeedsBeginFrame());

  // Shouldn't yet cause a change since we haven't done a full lifecycle update.
  EXPECT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  Compositor().BeginFrame();

  EXPECT_EQ(GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller());
}

// Tests that we don't explode when a layout occurs and the effective
// rootScroller no longer has a ContentFrame(). We setup the frame tree such
// that the first iframe is the effective root scroller. The second iframe has
// an unload handler that reaches back to the common parent and causes a
// layout. This will cause us to recalculate the effective root scroller while
// the current one is valid in all ways except that it no longer has a content
// frame. This test passes if it doesn't crash. https://crbug.com/805317.
TEST_F(ImplicitRootScrollerSimTest, RecomputeEffectiveWithNoContentFrame) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  SimRequest first_request("https://example.com/first.html", "text/html");
  SimRequest second_request("https://example.com/second.html", "text/html");
  SimRequest final_request("https://newdomain.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
          <!DOCTYPE html>
          <style>
            ::-webkit-scrollbar {
              width: 0px;
              height: 0px;
            }
            body, html {
              width: 100%;
              height: 100%;
              margin: 0px;
            }
            #first {
              width: 100%;
              height: 100%;
              border: 0;
            }
            #second {
              width: 10px;
              height: 10px;
              position: absolute;
              left: 0px;
              top: 0px;
            }
          </style>
          <iframe id="first" src="https://example.com/first.html">
          </iframe>
          <iframe id="second" src="https://example.com/second.html">
          </iframe>
          <script>
            // Dirty layout on unload
            window.addEventListener('unload', function() {
                document.getElementById("first").style.width="0";
            });
          </script>
      )HTML");

  first_request.Complete(R"HTML(
          <!DOCTYPE html>
          <style>
            body {
              height: 300vh;
            }
          </style>
      )HTML");

  second_request.Complete(R"HTML(
          <!DOCTYPE html>
          <body></body>
          <script>
            window.addEventListener('unload', function() {
                // This will do a layout.
                window.top.document.getElementById("first").clientWidth;
            });
          </script>
      )HTML");

  Element* container = GetDocument().getElementById(AtomicString("first"));
  Compositor().BeginFrame();

  ASSERT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // This will unload first the root, then the first frame, then the second.
  LoadURL("https://newdomain.com/test.html");
  final_request.Complete(R"HTML(
          <!DOCTYPE html>
      )HTML");
}

// Test that the element is considered to be viewport filling only if its
// padding box fills the viewport. That means it must have no border.
TEST_F(ImplicitRootScrollerSimTest, UsePaddingBoxForViewportFillingCondition) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
          <!DOCTYPE html>
          <style>
            html,body {
              margin: 0;
              width: 100%;
              height: 100%;
            }
            #container {
              position: absolute;
              width: 100%;
              height: 100%;
              box-sizing: border-box;
              overflow: scroll;
            }
            #spacer {
              width: 200vw;
              height: 200vh;
            }
          </style>
          <div id="container">
            <div id="spacer"></div>
          </div>
      )HTML");

  Element* container = GetDocument().getElementById(AtomicString("container"));
  Compositor().BeginFrame();

  ASSERT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // Setting a border should cause the element to no longer be valid as its
  // padding box doesn't fill the viewport exactly.
  container->setAttribute(html_names::kStyleAttr,
                          AtomicString("border: 1px solid black"));
  Compositor().BeginFrame();
  EXPECT_EQ(&GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller());
}

// Tests that the root scroller doesn't affect visualViewport pageLeft and
// pageTop.
TEST_F(ImplicitRootScrollerSimTest, RootScrollerDoesntAffectVisualViewport) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Write(R"HTML(
          <!DOCTYPE html>
          <style>
            body, html {
              width: 100%;
              height: 100%;
              margin: 0px;
            }

            #spacer {
              width: 1000px;
              height: 1000px;
            }

            #container {
              width: 100%;
              height: 100%;
              overflow: auto;
            }
          </style>
          <div id="container">
            <div id="spacer"></div>
          </div>
      )HTML");

  GetDocument().GetPage()->GetVisualViewport().SetScale(2);
  GetDocument().GetPage()->GetVisualViewport().SetLocation(
      gfx::PointF(100, 120));

  auto* frame = To<LocalFrame>(GetDocument().GetPage()->MainFrame());
  EXPECT_EQ(100, frame->DomWindow()->visualViewport()->pageLeft());
  EXPECT_EQ(120, frame->DomWindow()->visualViewport()->pageTop());

  request.Finish();
  Compositor().BeginFrame();

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());
  container->setScrollTop(50);
  container->setScrollLeft(60);

  ASSERT_EQ(50, container->scrollTop());
  ASSERT_EQ(60, container->scrollLeft());
  ASSERT_EQ(100, frame->DomWindow()->visualViewport()->pageLeft());
  EXPECT_EQ(120, frame->DomWindow()->visualViewport()->pageTop());
}

// Tests that we don't crash or violate lifecycle assumptions when we resize
// from within layout.
TEST_F(ImplicitRootScrollerSimTest, ResizeFromResizeAfterLayout) {
  WebView().GetSettings()->SetShrinksViewportContentToFit(true);
  WebView().SetDefaultPageScaleLimits(0.25f, 5);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Write(R"HTML(
          <!DOCTYPE html>
          <style>
            body, html {
              width: 100%;
              height: 100%;
              margin: 0px;
            }

            #container {
              width: 100%;
              height: 100%;
              border: 0;
            }
          </style>
          <iframe id="container"
                  srcdoc="<!DOCTYPE html>
                          <style>html {height: 300%;}</style>">
          </iframe>
      )HTML");
  RunPendingTasks();
  Compositor().BeginFrame();

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());
  ASSERT_EQ(gfx::Size(800, 600), GetDocument().View()->Size());

  request.Write(R"HTML(
          <div style="width:2000px;height:1000px"></div>
      )HTML");
  request.Finish();
  Compositor().BeginFrame();

  ASSERT_EQ(gfx::Size(2000, 1500), GetDocument().View()->Size());
}

// Tests basic implicit root scroller mode with a <div>.
TEST_F(ImplicitRootScrollerSimTest, ImplicitRootScroller) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
          <!DOCTYPE html>
          <style>
            ::-webkit-scrollbar {
              width: 0px;
              height: 0px;
            }
            html {
              overflow: hidden;
            }
            body, html {
              width: 100%;
              height: 100%;
              margin: 0px;
            }
            #spacer {
              width: 1000px;
              height: 1000px;
            }
            #container {
              width: 100%;
              height: 100%;
            }
          </style>
          <div id="container">
            <div id="spacer"></div>
          </div>
      )HTML");
  Compositor().BeginFrame();

  ASSERT_EQ(&GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller());
  Element* container = GetDocument().getElementById(AtomicString("container"));

  // overflow: auto and overflow: scroll should cause a valid element to be
  // promoted to root scroller. Otherwise, they shouldn't, even if they're
  // otherwise a valid root scroller element.
  Vector<std::tuple<String, String, Node*>> test_cases = {
      {"overflow", "hidden", &GetDocument()},
      {"overflow", "auto", container},
      {"overflow", "scroll", container},
      {"overflow", "visible", &GetDocument()},
      // Overflow: hidden in one axis forces the other axis to auto so it should
      // be promoted.
      {"overflow-x", "hidden", container},
      {"overflow-x", "auto", container},
      {"overflow-x", "scroll", container},
      {"overflow-x", "visible", &GetDocument()},
      {"overflow-y", "hidden", container},
      {"overflow-y", "auto", container},
      {"overflow-y", "scroll", container},
      {"overflow-y", "visible", &GetDocument()}};

  for (auto test_case : test_cases) {
    String& style = std::get<0>(test_case);
    String& style_val = std::get<1>(test_case);
    Node* expected_root_scroller = std::get<2>(test_case);

    container->style()->setProperty(GetDocument().GetExecutionContext(), style,
                                    style_val, String(), ASSERT_NO_EXCEPTION);
    Compositor().BeginFrame();
    ASSERT_EQ(expected_root_scroller,
              GetDocument().GetRootScrollerController().EffectiveRootScroller())
        << "Failed to set rootScroller after setting " << std::get<0>(test_case)
        << ": " << std::get<1>(test_case);
    container->style()->setProperty(GetDocument().GetExecutionContext(),
                                    std::get<0>(test_case), String(), String(),
                                    ASSERT_NO_EXCEPTION);
    Compositor().BeginFrame();
    ASSERT_EQ(&GetDocument(),
              GetDocument().GetRootScrollerController().EffectiveRootScroller())
        << "Failed to reset rootScroller after setting "
        << std::get<0>(test_case) << ": " << std::get<1>(test_case);
  }

  // Now remove the overflowing element and rerun the tests. The container
  // element should no longer be implicitly promoted as it doesn't have any
  // overflow.
  Element* spacer = GetDocument().getElementById(AtomicString("spacer"));
  spacer->remove();

  for (auto test_case : test_cases) {
    String& style = std::get<0>(test_case);
    String& style_val = std::get<1>(test_case);
    Node* expected_root_scroller = &GetDocument();

    container->style()->setProperty(GetDocument().GetExecutionContext(), style,
                                    style_val, String(), ASSERT_NO_EXCEPTION);
    Compositor().BeginFrame();
    ASSERT_EQ(expected_root_scroller,
              GetDocument().GetRootScrollerController().EffectiveRootScroller())
        << "Failed to set rootScroller after setting " << std::get<0>(test_case)
        << ": " << std::get<1>(test_case);

    container->style()->setProperty(GetDocument().GetExecutionContext(),
                                    std::get<0>(test_case), String(), String(),
                                    ASSERT_NO_EXCEPTION);
    Compositor().BeginFrame();
    ASSERT_EQ(&GetDocument(),
              GetDocument().GetRootScrollerController().EffectiveRootScroller())
        << "Failed to reset rootScroller after setting "
        << std::get<0>(test_case) << ": " << std::get<1>(test_case);
  }
}

// Test that adding overflow to an element that would otherwise be eligable to
// be implicitly pomoted causes promotion.
TEST_F(ImplicitRootScrollerSimTest, ImplicitRootScrollerAddOverflow) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
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
              width: 100%;
              height: 100%;
              margin: 0px;
            }
            #container {
              width: 100%;
              height: 100%;
              overflow: auto;
            }
          </style>
          <div id="container">
            <div id="spacer"></div>
          </div>
      )HTML");
  Compositor().BeginFrame();

  ASSERT_EQ(&GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "Shouldn't promote 'container' since it has no overflow.";

  Element* spacer = GetDocument().getElementById(AtomicString("spacer"));
  spacer->style()->setProperty(GetDocument().GetExecutionContext(), "height",
                               "2000px", String(), ASSERT_NO_EXCEPTION);
  spacer->style()->setProperty(GetDocument().GetExecutionContext(), "width",
                               "2000px", String(), ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  Element* container = GetDocument().getElementById(AtomicString("container"));
  EXPECT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "Adding overflow should cause 'container' to be promoted.";
}

// Tests that we don't crash if an implicit candidate is no longer a box. This
// test passes if it doesn't crash.
TEST_F(ImplicitRootScrollerSimTest, CandidateLosesLayoutBoxDontCrash) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
          <!DOCTYPE html>
          <style>
            #spacer {
              width: 300px;
              height: 300px;
            }

            .box {
              width: 200px;
              height: 200px;
              overflow: scroll;
              display: block;
            }

            .nonbox {
              display: inline;
            }
          </style>
          <b id="container">
            <div id="spacer"></div>
          </b>
      )HTML");
  Element* container = GetDocument().getElementById(AtomicString("container"));

  // An overflowing box will be added to the implicit candidates list.
  container->setAttribute(html_names::kClassAttr, AtomicString("box"));
  Compositor().BeginFrame();

  // This will make change from a box to an inline. Ensure we don't crash when
  // we reevaluate the candidates list.
  container->setAttribute(html_names::kClassAttr, AtomicString("nonbox"));
  Compositor().BeginFrame();
}

// Ensure that a plugin view being considered for implicit promotion doesn't
// cause a crash. https://crbug.com/903440.
TEST_F(ImplicitRootScrollerSimTest, ConsiderEmbedCrash) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
          <!DOCTYPE html>
          <embed id="embed" height="1" src="data:video/mp4,">
          <script>
           embed.type = "JavaScript 1.5";
           embed.src = "x";
          </script>
      )HTML");
  Compositor().BeginFrame();
  Element* embed = GetDocument().getElementById(AtomicString("embed"));
  GetDocument().GetRootScrollerController().ConsiderForImplicit(*embed);
}

// Test that a valid implicit root scroller wont be promoted/will be demoted if
// the main document has overflow.
TEST_F(ImplicitRootScrollerSimTest,
       ImplicitRootScrollerDocumentScrollsOverflow) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
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
              width: 100%;
              height: 100%;
              margin: 0px;
            }
            #container {
              width: 100%;
              height: 100%;
              overflow: auto;
            }
            #spacer {
              width: 2000px;
              height: 2000px;
            }
          </style>
          <div id="container">
            <div id="spacer"></div>
          </div>
          <div id="overflow"></div>
      )HTML");
  Compositor().BeginFrame();

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  Element* overflow = GetDocument().getElementById(AtomicString("overflow"));
  overflow->style()->setProperty(GetDocument().GetExecutionContext(), "height",
                                 "10px", String(), ASSERT_NO_EXCEPTION);
  overflow->style()->setProperty(GetDocument().GetExecutionContext(), "width",
                                 "10px", String(), ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(&GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "Adding overflow to document should cause 'container' to be demoted.";

  overflow->remove();
  Compositor().BeginFrame();
  EXPECT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "Removing document overflow should cause 'container' to be promoted.";
}

// Test that we'll only implicitly promote an element if its visible.
TEST_F(ImplicitRootScrollerSimTest, ImplicitRootScrollerVisibilityCondition) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
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
              width: 100%;
              height: 100%;
              margin: 0px;
            }
            #container {
              width: 100%;
              height: 100%;
              overflow: auto;
            }
            #spacer {
              width: 2000px;
              height: 2000px;
            }
          </style>
          <div id="container">
            <div id="spacer"></div>
          </div>
      )HTML");
  Compositor().BeginFrame();

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  container->style()->setProperty(GetDocument().GetExecutionContext(),
                                  "opacity", "0.5", String(),
                                  ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(&GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "Adding opacity to 'container' causes it to be demoted.";

  container->style()->setProperty(GetDocument().GetExecutionContext(),
                                  "opacity", "", String(), ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "Removing opacity from 'container' causes it to be promoted.";

  container->style()->setProperty(GetDocument().GetExecutionContext(),
                                  "visibility", "hidden", String(),
                                  ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(&GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "visibility:hidden causes 'container' to be demoted.";

  container->style()->setProperty(GetDocument().GetExecutionContext(),
                                  "visibility", "collapse", String(),
                                  ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(&GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "visibility:collapse doesn't cause 'container' to be promoted.";

  container->style()->setProperty(GetDocument().GetExecutionContext(),
                                  "visibility", "visible", String(),
                                  ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "visibility:visible causes promotion";
}

// Tests implicit root scroller mode for iframes.
TEST_F(ImplicitRootScrollerSimTest, ImplicitRootScrollerIframe) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
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
              width: 100%;
              height: 100%;
              margin: 0px;
            }
            iframe {
              width: 100%;
              height: 100%;
              border: 0;
            }
          </style>
          <iframe id="container"
                  srcdoc="<!DOCTYPE html><style>html {height: 300%;}</style>">
          </iframe>
      )HTML");
  // srcdoc iframe loads via posted tasks.
  RunPendingTasks();
  Compositor().BeginFrame();

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  container->style()->setProperty(GetDocument().GetExecutionContext(), "height",
                                  "95%", String(), ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();

  ASSERT_EQ(&GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller());
}

// Tests use counter for implicit root scroller. Ensure it's not counted on a
// page without an implicit root scroller.
TEST_F(ImplicitRootScrollerSimTest, UseCounterNegative) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
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
              width: 100%;
              height: 100%;
              margin: 0px;
            }
            div {
              width: 100%;
              height: 100%;
            }
          </style>
          <div id="container"></div>
      )HTML");
  Compositor().BeginFrame();

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_NE(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kActivatedImplicitRootScroller));

  container->style()->setProperty(GetDocument().GetExecutionContext(), "height",
                                  "150%", String(), ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();

  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kActivatedImplicitRootScroller));
}

// Tests use counter for implicit root scroller. Ensure it's counted on a
// page that loads with an implicit root scroller.
TEST_F(ImplicitRootScrollerSimTest, UseCounterPositive) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
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
              width: 100%;
              height: 100%;
              margin: 0px;
            }
            #container {
              width: 100%;
              height: 100%;
              overflow: auto;
            }
            #spacer {
              height: 2000px;
            }
          </style>
          <div id="container">
            <div id="spacer"></div>
          </div>
      )HTML");
  Compositor().BeginFrame();

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kActivatedImplicitRootScroller));

  container->style()->setProperty(GetDocument().GetExecutionContext(), "height",
                                  "150%", String(), ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();

  ASSERT_NE(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kActivatedImplicitRootScroller));
}

// Tests use counter for implicit root scroller. Ensure it's counted on a
// page that loads without an implicit r
```