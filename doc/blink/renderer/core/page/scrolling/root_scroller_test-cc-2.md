Response:
The user wants a summary of the functionality of the provided C++ code snippet from `root_scroller_test.cc`. The summary should include:

1. **General Functionality:** What does the code do?
2. **Relationship to Web Technologies:** How does it relate to JavaScript, HTML, and CSS?  Provide examples.
3. **Logical Reasoning:**  Are there any tests with clear inputs and expected outputs?
4. **Common Usage Errors:** Does the code test for or prevent common mistakes made by users or programmers?
5. **Debugging Clues:** How can a user's actions lead to this code being executed?
6. **Overall Summary:** A concise recap of the code's purpose.

Let's break down the code snippet:

* **Test Fixtures:**  The code uses `TEST_F` which indicates it's part of a testing framework (likely Google Test). The tests belong to the `ImplicitRootScrollerSimTest` fixture. This suggests the tests are focused on the "implicit root scroller" functionality.
* **Simulated Environment:** The test fixture name includes "SimTest," and the tests use `WebView()`, `SimRequest`, `LoadURL`, and `Compositor().BeginFrame()`. This strongly implies the tests run in a simulated browser environment, not a real browser instance.
* **HTML/CSS Manipulation:** The tests load HTML strings (using `R"HTML(...)HTML"`) and manipulate CSS properties using methods like `setProperty`. They also interact with DOM elements using `GetDocument().getElementById()`.
* **Root Scroller Assertion:**  The core of the tests revolves around verifying the "effective root scroller" using `GetDocument().GetRootScrollerController().EffectiveRootScroller()`. This is the key functionality being tested.
* **Implicit Promotion/Demotion:** Many tests explore scenarios where an element (often an iframe or a div) becomes the root scroller implicitly based on its properties (like `overflow: auto`, dimensions, etc.). Conversely, they also test when these elements are no longer considered the root scroller.
* **Specific Scenarios:** The tests cover various edge cases like:
    * Initial state with no explicit root scroller.
    * Changing element properties to become the root scroller.
    * Layout tree reattachments.
    * Multiple valid candidates for implicit promotion.
    * Iframe loading and navigation.
    * Scroll restoration.
    * Browser controls (URL bar).
    * Dynamic style changes.
    * Iframe scrolling behavior.
    * Iframe sizing and borders/padding.
    * Impact of main document scrolling.
    * Impact of `overflow: hidden` on the main document.

**Plan:**

1. **General Functionality:** State that it's a test file for the implicit root scroller logic in Blink.
2. **Web Technologies:** Explain how it uses HTML to create page structure, CSS to style elements (especially `overflow`), and JavaScript indirectly through the simulated environment and DOM manipulation. Give concrete examples from the tests.
3. **Logical Reasoning:**  Pick a couple of tests and outline the assumed HTML structure, CSS, and the expected outcome regarding the effective root scroller.
4. **Common Errors:** Discuss scenarios where developers might incorrectly assume which element is the root scroller, leading to unexpected scrolling behavior. Frame it around the conditions tested in the code (e.g., forgetting `overflow: auto`, incorrect sizing).
5. **Debugging Clues:** Describe a user action (e.g., a page with an iframe that becomes scrollable) and how the browser's internal logic (tested by this code) would determine the root scroller.
6. **Overall Summary:**  Reiterate that the file tests the automatic selection of the root scrolling element based on specific criteria.
这是对 `blink/renderer/core/page/scrolling/root_scroller_test.cc` 文件功能的归纳总结，基于你提供的第三部分内容。

**功能归纳：**

这部分测试用例主要集中在测试 **隐式根滚动器 (Implicit Root Scroller)** 的功能。具体来说，它验证了在各种场景下，Blink 引擎如何自动识别并选择页面中的哪个元素作为根滚动容器。  重点在于测试在不同 HTML 结构、CSS 样式和 iframe 交互的情况下，隐式根滚动器的提升（成为根滚动器）和降级（不再是根滚动器）的逻辑是否正确。

**与 JavaScript, HTML, CSS 的关系：**

该测试文件直接与 HTML 和 CSS 功能紧密相关，并通过模拟环境间接涉及 JavaScript 的影响。

* **HTML:** 测试用例通过构建不同的 HTML 结构来模拟各种网页布局，例如包含 `div` 元素、`iframe` 元素，并设置不同的 id 以便在测试中进行选择和操作。
    * **例子:**  `<div id="container">`， `<iframe id="container" src="child.html">`
* **CSS:** 测试用例大量使用 CSS 属性来影响元素的滚动行为和布局，这是隐式根滚动器判断的关键依据。例如：
    * `overflow: auto;`:  使元素在内容超出时出现滚动条，是成为隐式根滚动器的常见条件。
    * `width: 100%; height: 100%;`:  使元素填充视口，也是成为隐式根滚动器的重要条件。
    * `position: absolute;`:  影响元素的布局和是否可能成为根滚动器。
    * `transform`:  影响元素是否填充视口。
    * `border`, `padding`:  影响 iframe 的尺寸计算，进而影响其是否能被提升为根滚动器。
* **JavaScript:** 虽然测试代码本身是 C++，但它模拟了 JavaScript 对 DOM 和 CSS 的操作可能导致的结果。例如，通过 `container->style()->setProperty(...)` 来模拟 JavaScript 修改 CSS 属性，触发重新布局和隐式根滚动器的重新评估。  `onresize` 事件处理程序也出现在代码中，虽然在 C++ 测试中直接设置，但它模拟了 JavaScript 对窗口大小变化的处理。

**逻辑推理（假设输入与输出）：**

* **假设输入:**
    * HTML 结构包含一个 `div` 元素，其 id 为 "container"。
    * CSS 样式初始时，该 `div` 元素的 `overflow` 为非 `auto` 或 `scroll`，且高度不是 100%。
    * 浏览器视口大小为 800x600。
* **操作:**
    * 通过 C++ 代码模拟 JavaScript 将该 `div` 元素的 `overflow` 属性设置为 `"auto"`，并将 `height` 属性设置为 `"100%"`。
    * 触发布局更新 (`Compositor().BeginFrame();`)。
* **预期输出:**
    * 在修改 CSS 之前，根滚动器应该是文档本身 (`GetDocument()`)。
    * 在修改 CSS 之后，该 `div` 元素应该成为有效的根滚动器 (`ASSERT_EQ(container, GetDocument().GetRootScrollerController().EffectiveRootScroller());`)。

* **假设输入:**
    * HTML 结构包含一个 `iframe` 元素，初始时 `srcdoc` 或 `src` 指向的文档内容较少，不足以产生滚动条。
* **操作:**
    * `iframe` 加载完成。
    * 通过 C++ 代码模拟 `iframe` 内部的 HTML 或 `body` 元素的高度增加，使其内容超出 `iframe` 的视口。
    * 触发布局更新。
* **预期输出:**
    * 在 `iframe` 内容不足以滚动时，根滚动器是主文档。
    * 一旦 `iframe` 内部内容超出，并且满足其他成为根滚动器的条件（例如，填充视口），该 `iframe` 元素应该成为根滚动器。

**涉及用户或者编程常见的使用错误：**

* **开发者错误地假设根滚动器：**  开发者可能没有意识到隐式根滚动器的存在和工作方式，错误地假设 `document` 或 `body` 始终是根滚动器。例如，他们可能在 CSS 中设置了某个 `div` 的 `overflow: auto` 和 100% 的宽高，但没有预期到这个 `div` 会变成根滚动器，导致一些依赖于根滚动器的 JavaScript 或 CSS 行为出现异常。
* **CSS 属性冲突导致意外的根滚动器：**  开发者可能设置了相互冲突的 CSS 属性，导致浏览器意外地选择某个元素作为根滚动器。例如，一个元素同时设置了 `position: absolute` 和 `overflow: auto`，可能会影响其是否能成为根滚动器。
* **动态修改样式导致根滚动器变化未被预期：**  JavaScript 动态修改元素的 CSS 属性可能会导致根滚动器发生变化，如果开发者没有考虑到这一点，可能会导致页面滚动行为的突变。例如，一个 initially 不是根滚动器的 `div`，通过 JavaScript 修改其 `height` 为 `100%` 并设置 `overflow: auto` 后，可能会变成根滚动器。
* **iframe 内容加载顺序导致根滚动器判断错误：**  在使用 `iframe` 时，开发者可能没有考虑到 `iframe` 内容的加载顺序和异步性，导致在某些时刻根滚动器的判断与预期不符。测试用例中就包含了对 `iframe` 加载完成时，即使没有触发父页面的布局，`iframe` 也能被提升为根滚动器的测试。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户打开一个包含复杂布局的网页:**  网页可能包含多个可滚动的 `div` 元素或 `iframe` 元素。
2. **网页的 CSS 样式使得某些元素满足成为隐式根滚动器的条件:** 例如，某个 `div` 元素设置了 `overflow: auto` 并且占据了整个视口。
3. **浏览器渲染引擎 (Blink) 在布局过程中会评估哪些元素可以作为根滚动器:** `RootScrollerController` 会根据元素的 CSS 属性和布局信息进行判断。
4. **如果满足条件，某个元素会被提升为隐式根滚动器:**  用户的滚动操作实际上是在滚动这个被提升的元素，而不是整个文档。
5. **如果用户的操作或网页的动态变化导致根滚动器的条件不再满足:** 例如，通过 JavaScript 修改了该元素的尺寸或 `overflow` 属性，该元素可能会被降级，根滚动器又变回文档本身。

**调试线索:** 当开发者遇到与页面滚动相关的 bug 时，例如：

* 预期页面滚动，但实际滚动的是页面内的某个容器。
* 在某些操作后，滚动行为发生意外变化。
* 固定定位元素行为异常。

可以检查以下方面，这些都与该测试文件覆盖的功能相关：

* **检查页面中是否有元素设置了 `overflow: auto` 或 `overflow: scroll`，并且占据了较大的视口区域。** 这些元素很可能是隐式根滚动器的候选者。
* **使用浏览器的开发者工具，查看页面的渲染树或布局信息，确认当前的根滚动元素是哪个。**
* **排查 JavaScript 代码中是否有动态修改元素样式，特别是与 `overflow` 和尺寸相关的属性，这可能导致根滚动器的变化。**
* **如果页面包含 `iframe`，需要检查 `iframe` 的样式和内容，以及其父页面的滚动行为，因为 `iframe` 也有可能成为根滚动器。**
* **使用浏览器的性能分析工具，观察布局和合成层的变化，特别是当滚动行为出现异常时，这有助于理解根滚动器切换的时机。**

总而言之，`root_scroller_test.cc` 的这部分内容专注于验证 Blink 引擎在各种复杂的网页场景下，能否正确地识别和管理隐式根滚动器，确保页面的滚动行为符合预期。这对于提供流畅且符合用户期望的网页浏览体验至关重要。

Prompt: 
```
这是目录为blink/renderer/core/page/scrolling/root_scroller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
oot scroller but later gets one.
TEST_F(ImplicitRootScrollerSimTest, UseCounterPositiveAfterLoad) {
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
              height: 40%;
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
  ASSERT_NE(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kActivatedImplicitRootScroller));

  container->style()->setProperty(GetDocument().GetExecutionContext(), "height",
                                  "100%", String(), ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();

  ASSERT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kActivatedImplicitRootScroller));
}

// Test that we correctly recompute the cached bits and thus the root scroller
// properties in the event of a layout tree reattachment which causes the
// LayoutObject to be disposed and replaced with a new one.
TEST_F(ImplicitRootScrollerSimTest, LayoutTreeReplaced) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
          <style>
            ::-webkit-scrollbar {
            }
            #rootscroller {
              width: 100%;
              height: 100%;
              overflow: auto;
              position: absolute;
              left: 0;
              top: 0;
            }
            #spacer {
              height: 20000px;
              width: 10px;
            }
          </style>
          <div id="rootscroller">
            <div id="spacer"></div>
          </div>
      )HTML");
  Compositor().BeginFrame();

  Element* scroller =
      GetDocument().getElementById(AtomicString("rootscroller"));
  ASSERT_EQ(scroller,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());
  ASSERT_TRUE(scroller->GetLayoutObject()->IsEffectiveRootScroller());
  ASSERT_TRUE(scroller->GetLayoutObject()->IsGlobalRootScroller());

  // This will cause the layout tree to be rebuilt and reattached which creates
  // new LayoutObjects. Ensure the bits are reapplied to the new layout
  // objects after they're recreated.
  GetDocument().setDesignMode("on");
  Compositor().BeginFrame();

  EXPECT_TRUE(scroller->GetLayoutObject()->IsEffectiveRootScroller());
  EXPECT_TRUE(scroller->GetLayoutObject()->IsGlobalRootScroller());
}

// Tests that if we have multiple valid candidates for implicit promotion, we
// don't promote either.
TEST_F(ImplicitRootScrollerSimTest, DontPromoteWhenMultipleAreValid) {
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
              position: absolute;
              left: 0;
              top: 0;
              width: 100%;
              height: 100%;
              border: 0;
            }
          </style>
          <iframe id="container"
                  srcdoc="<!DOCTYPE html><style>html {height: 300%;}</style>">
          </iframe>
          <iframe id="container2"
                  srcdoc="<!DOCTYPE html><style>html {height: 300%;}</style>">
          </iframe>
      )HTML");
  // srcdoc iframe loads via posted tasks.
  RunPendingTasks();
  Compositor().BeginFrame();

  // Since both iframes are valid candidates, neither should be promoted.
  ASSERT_EQ(&GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // Now make the second one invalid, that should cause the first to be
  // promoted.
  Element* container2 =
      GetDocument().getElementById(AtomicString("container2"));
  container2->style()->setProperty(GetDocument().GetExecutionContext(),
                                   "height", "95%", String(),
                                   ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());
}

// Test that when a valid iframe becomes loaded and thus should be promoted, it
// becomes the root scroller, without needing an intervening layout.
TEST_F(ImplicitRootScrollerSimTest, IframeLoadedWithoutLayout) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_request("https://example.com/test.html", "text/html");
  SimRequest child_request("https://example.com/child.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_request.Complete(R"HTML(
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
          <iframe id="container" src="child.html">
          </iframe>
      )HTML");
  Compositor().BeginFrame();
  ASSERT_EQ(GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "The iframe isn't yet scrollable.";

  // Ensure that it gets promoted when the new FrameView is connected even
  // though there's no layout in the parent to trigger it.
  child_request.Complete(R"HTML(
        <!DOCTYPE html>
        <style>
          body {
            height: 1000px;
          }
        </style>
  )HTML");

  Compositor().BeginFrame();
  EXPECT_EQ(GetDocument().getElementById(AtomicString("container")),
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "Once loaded, the iframe should be promoted.";
}

// Ensure that navigating an iframe while it is the effective root scroller,
// causes it to remain the effective root scroller after the navigation (to a
// page where it remains valid) is finished.
TEST_F(ImplicitRootScrollerSimTest, NavigateToValidRemainsRootScroller) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_request("https://example.com/test.html", "text/html");
  SimRequest child_request("https://example.com/child.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_request.Complete(R"HTML(
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
          <iframe id="container" src="child.html">
          </iframe>
      )HTML");
  child_request.Complete(R"HTML(
        <!DOCTYPE html>
        <style>
          body {
            height: 1000px;
          }
        </style>
  )HTML");
  Compositor().BeginFrame();
  ASSERT_EQ(GetDocument().getElementById(AtomicString("container")),
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // Navigate the child frame. When it's loaded, the FrameView should swap.
  // Ensure that we remain the root scroller even though there's no layout in
  // the parent.
  SimRequest child_request2("https://example.com/child-next.html", "text/html");
  frame_test_helpers::LoadFrameDontWait(
      WebView().MainFrameImpl()->FirstChild()->ToWebLocalFrame(),
      KURL("https://example.com/child-next.html"));

  child_request2.Write(R"HTML(
        <!DOCTYPE html>
  )HTML");
  Compositor().BeginFrame();
  EXPECT_EQ(GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "The iframe should be demoted once a navigation is committed";

  // Ensure that it gets promoted when the new FrameView is connected even
  // though there's no layout in the parent to trigger it.
  child_request2.Write(R"HTML(
        <style>
          body {
            height: 2000px;
          }
        </style>
  )HTML");
  child_request2.Finish();
  Compositor().BeginFrame();

  EXPECT_EQ(GetDocument().getElementById(AtomicString("container")),
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "Once loaded, the iframe should be promoted again.";
}

// Ensure that scroll restoration logic in the document does not apply
// to the implicit root scroller, but rather to the document's LayoutViewport.
TEST_F(ImplicitRootScrollerSimTest, ScrollRestorationIgnoresImplicit) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_request("https://example.com/test.html", "text/html");
  SimRequest child_request("https://example.com/child.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_request.Complete(R"HTML(
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
          <iframe id="container" src="child.html">
          </iframe>
      )HTML");
  child_request.Complete(R"HTML(
        <!DOCTYPE html>
        <style>
          body {
            height: 1000px;
          }
        </style>
  )HTML");
  Compositor().BeginFrame();
  ASSERT_EQ(GetDocument().getElementById(AtomicString("container")),
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  HistoryItem::ViewState view_state;
  view_state.scroll_offset_ = ScrollOffset(10, 20);

  GetDocument()
      .View()
      ->GetScrollableArea()
      ->SetPendingHistoryRestoreScrollOffset(
          view_state, true, mojom::blink::ScrollBehavior::kAuto);
  GetDocument().View()->LayoutViewport()->SetPendingHistoryRestoreScrollOffset(
      view_state, true, mojom::blink::ScrollBehavior::kAuto);
  GetDocument().View()->ScheduleAnimation();

  Compositor().BeginFrame();
  EXPECT_EQ(ScrollOffset(0, 0),
            GetDocument().View()->GetScrollableArea()->GetScrollOffset());

  GetDocument().domWindow()->scrollTo(0, 20);
  GetDocument().View()->ScheduleAnimation();
  // Check that an implicit scroll offset is not saved.
  // TODO(chrishtr): probably it should?
  Compositor().BeginFrame();
  EXPECT_FALSE(GetDocument()
                   .GetFrame()
                   ->Loader()
                   .GetDocumentLoader()
                   ->GetHistoryItem()
                   ->GetViewState());
}

// Test that a root scroller is considered to fill the viewport at both the URL
// bar shown and URL bar hidden height.
TEST_F(ImplicitRootScrollerSimTest,
       RootScrollerFillsViewportAtBothURLBarStates) {
  WebView().ResizeWithBrowserControls(gfx::Size(800, 600), 50, 0, true);
  SimRequest main_request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_request.Complete(R"HTML(
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
              border: 0;
            }
          </style>
          <div id="container">
            <div style="height: 2000px;"></div>
          </div>
          <script>
            onresize = () => {
              document.getElementById("container").style.height =
                  window.innerHeight + "px";
            };
          </script>
      )HTML");
  Element* container = GetDocument().getElementById(AtomicString("container"));
  Compositor().BeginFrame();

  ASSERT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // Simulate hiding the top controls. The root scroller should remain valid at
  // the new height.
  WebView().GetPage()->GetBrowserControls().SetShownRatio(0, 0);
  WebView().ResizeWithBrowserControls(gfx::Size(800, 650), 50, 50, false);
  Compositor().BeginFrame();
  EXPECT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // Simulate showing the top controls. The root scroller should remain valid.
  WebView().GetPage()->GetBrowserControls().SetShownRatio(1, 1);
  WebView().ResizeWithBrowserControls(gfx::Size(800, 600), 50, 50, true);
  Compositor().BeginFrame();
  EXPECT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // Set the height explicitly to a new value in-between. The root scroller
  // should be demoted.
  container->style()->setProperty(GetDocument().GetExecutionContext(), "height",
                                  "601px", String(), ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // Reset back to valid and hide the top controls. Zoom to 2x. Ensure we're
  // still considered valid.
  container->style()->setProperty(GetDocument().GetExecutionContext(), "height",
                                  "", String(), ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());
  EXPECT_EQ(To<LayoutBox>(container->GetLayoutObject())->Size().height, 600);
  WebView().MainFrameWidget()->SetZoomLevel(ZoomFactorToZoomLevel(2.0));
  WebView().GetPage()->GetBrowserControls().SetShownRatio(0, 0);
  WebView().ResizeWithBrowserControls(gfx::Size(800, 650), 50, 50, false);
  Compositor().BeginFrame();
  EXPECT_EQ(container->clientHeight(), 325);
  EXPECT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());
}

// Tests that implicit is continually reevaluating whether to promote or demote
// a scroller.
TEST_F(ImplicitRootScrollerSimTest, ContinuallyReevaluateImplicitPromotion) {
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
            #container {
              width: 100%;
              height: 100%;
            }
            #parent {
              width: 100%;
              height: 100%;
            }
          </style>
          <div id="parent">
            <div id="container">
              <div id="spacer"></div>
            </div>
          </div>
      )HTML");
  Compositor().BeginFrame();

  Element* parent = GetDocument().getElementById(AtomicString("parent"));
  Element* container = GetDocument().getElementById(AtomicString("container"));
  Element* spacer = GetDocument().getElementById(AtomicString("spacer"));

  // The container isn't yet scrollable.
  ASSERT_EQ(GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // The container now has overflow but still doesn't scroll.
  spacer->style()->setProperty(GetDocument().GetExecutionContext(), "height",
                               "2000px", String(), ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // The container is now scrollable and should be promoted.
  container->style()->setProperty(GetDocument().GetExecutionContext(),
                                  "overflow", "auto", String(),
                                  ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // The container is now not viewport-filling so it should be demoted.
  container->style()->setProperty(GetDocument().GetExecutionContext(),
                                  "transform", "translateX(-50px)", String(),
                                  ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // The container is viewport-filling again so it should be promoted.
  parent->style()->setProperty(GetDocument().GetExecutionContext(), "transform",
                               "translateX(50px)", String(),
                               ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // No longer scrollable so demote.
  container->style()->setProperty(GetDocument().GetExecutionContext(),
                                  "overflow", "hidden", String(),
                                  ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller());
}

// Tests that implicit mode correctly recognizes when an iframe becomes
// scrollable.
TEST_F(ImplicitRootScrollerSimTest, IframeScrollingAffectsPromotion) {
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
                  srcdoc="<!DOCTYPE html><style>html {overflow: hidden; height: 300%;}</style>">
          </iframe>
      )HTML");

  // srcdoc iframe loads via posted tasks.
  RunPendingTasks();
  Compositor().BeginFrame();

  auto* container = To<HTMLFrameOwnerElement>(
      GetDocument().getElementById(AtomicString("container")));
  Element* inner_html_element = container->contentDocument()->documentElement();

  // Shouldn't be promoted since it's not scrollable.
  EXPECT_EQ(GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // Allows scrolling now so promote.
  inner_html_element->style()->setProperty(
      To<LocalDOMWindow>(container->contentWindow()), "overflow", "auto",
      String(), ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(container,
            GetDocument().GetRootScrollerController().EffectiveRootScroller());

  // Demote again.
  inner_html_element->style()->setProperty(
      To<LocalDOMWindow>(container->contentWindow()), "overflow", "hidden",
      String(), ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();
  EXPECT_EQ(GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller());
}

// Loads with a larger than the ICB (but otherwise valid) implicit root
// scrolling iframe. When the iframe is promoted (which happens at the end of
// layout) its layout size is changed which makes it easy to violate lifecycle
// assumptions.  (e.g. NeedsLayout at the end of layout)
TEST_F(ImplicitRootScrollerSimTest, PromotionChangesLayoutSize) {
  WebView().ResizeWithBrowserControls(gfx::Size(800, 650), 50, 0, false);
  SimRequest main_request("https://example.com/test.html", "text/html");
  SimRequest child_request("https://example.com/child.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_request.Complete(R"HTML(
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
              height: 650px;
              border: 0;
            }
          </style>
          <iframe id="container" src="child.html">
          </iframe>
      )HTML");
  child_request.Complete(R"HTML(
        <!DOCTYPE html>
        <style>
          body {
            height: 1000px;
          }
        </style>
  )HTML");

  Compositor().BeginFrame();
  EXPECT_EQ(GetDocument().getElementById(AtomicString("container")),
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "Once loaded, the iframe should be promoted.";
}

// Tests that bottom-fixed objects inside of an iframe root scroller and frame
// are marked as being affected by top controls movement. Those inside a
// non-rootScroller iframe should not be marked as such.
TEST_F(ImplicitRootScrollerSimTest, BottomFixedAffectedByTopControls) {
  WebView().ResizeWithBrowserControls(gfx::Size(800, 650), 50, 0, false);
  SimRequest main_request("https://example.com/test.html", "text/html");
  SimRequest child_request1("https://example.com/child1.html", "text/html");
  SimRequest child_request2("https://example.com/child2.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_request.Complete(R"HTML(
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
            #container1 {
              width: 100%;
              height: 100%;
              border: 0;
            }
            #container2 {
              position: absolute;
              width: 10px;
              height: 10px;
              left: 100px;
              top: 100px;
              border: 0;
            }
            #fixed {
              position: fixed;
              bottom: 10px;
              left: 10px;
              width: 10px;
              height: 10px;
              background-color: red;
            }
          </style>
          <iframe id="container1" src="child1.html">
          </iframe>
          <iframe id="container2" src="child2.html">
          </iframe>
          <div id="fixed"></div>
      )HTML");
  child_request1.Complete(R"HTML(
        <!DOCTYPE html>
        <style>
          body {
            height: 1000px;
          }
          #fixed {
            width: 50px;
            height: 50px;
            position: fixed;
            bottom: 0px;
            left: 0px;
          }
        </style>
        <div id="fixed"></div>
  )HTML");
  child_request2.Complete(R"HTML(
        <!DOCTYPE html>
        <style>
          body {
            height: 1000px;
          }
          #fixed {
            width: 50px;
            height: 50px;
            position: fixed;
            bottom: 0px;
            left: 0px;
          }
        </style>
        <div id="fixed"></div>
  )HTML");

  Compositor().BeginFrame();

  Element* container1 =
      GetDocument().getElementById(AtomicString("container1"));
  Element* container2 =
      GetDocument().getElementById(AtomicString("container2"));
  ASSERT_EQ(container1,
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "The #container1 iframe must be promoted.";

  Document* child1_document =
      To<HTMLFrameOwnerElement>(container1)->contentDocument();
  Document* child2_document =
      To<HTMLFrameOwnerElement>(container2)->contentDocument();
  LayoutObject* fixed_layout =
      GetDocument().getElementById(AtomicString("fixed"))->GetLayoutObject();
  LayoutObject* fixed_layout1 =
      child1_document->getElementById(AtomicString("fixed"))->GetLayoutObject();
  LayoutObject* fixed_layout2 =
      child2_document->getElementById(AtomicString("fixed"))->GetLayoutObject();

  EXPECT_TRUE(fixed_layout->FirstFragment()
                  .PaintProperties()
                  ->PaintOffsetTranslation()
                  ->IsAffectedByOuterViewportBoundsDelta());
  EXPECT_TRUE(fixed_layout1->FirstFragment()
                  .PaintProperties()
                  ->PaintOffsetTranslation()
                  ->IsAffectedByOuterViewportBoundsDelta());
  EXPECT_FALSE(fixed_layout2->FirstFragment()
                   .PaintProperties()
                   ->PaintOffsetTranslation()
                   ->IsAffectedByOuterViewportBoundsDelta());
}

// Ensure that we're using the content box for an iframe. Promotion will cause
// the content to use the layout size of the parent frame so having padding or
// a border would cause us to relayout.
TEST_F(ImplicitRootScrollerSimTest, IframeUsesContentBox) {
  WebView().ResizeWithBrowserControls(gfx::Size(800, 600), 0, 0, false);
  SimRequest main_request("https://example.com/test.html", "text/html");
  SimRequest child_request("https://example.com/child.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_request.Complete(R"HTML(
          <!DOCTYPE>
          <style>
            iframe {
              position: absolute;
              top: 0;
              left: 0;
              width: 100%;
              height: 100%;
              border: none;
              box-sizing: border-box;

            }
            body, html {
              margin: 0;
              width: 100%;
              height: 100%;
              overflow:hidden;
            }

          </style>
          <iframe id="container" src="child.html">
      )HTML");
  child_request.Complete(R"HTML(
        <!DOCTYPE html>
        <style>
          div {
            border: 5px solid black;
            background-color: red;
            width: 99%;
            height: 100px;
          }
          html {
            height: 200%;
          }
        </style>
        <div></div>
  )HTML");

  Compositor().BeginFrame();

  Element* iframe = GetDocument().getElementById(AtomicString("container"));

  ASSERT_EQ(iframe,
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "The iframe should start off promoted.";

  // Adding padding should cause the iframe to be demoted.
  {
    iframe->setAttribute(html_names::kStyleAttr,
                         AtomicString("padding-left: 20%"));
    Compositor().BeginFrame();

    EXPECT_NE(iframe,
              GetDocument().GetRootScrollerController().EffectiveRootScroller())
        << "The iframe should be demoted once it has padding.";
  }

  // Replacing padding with a border should also ensure the iframe remains
  // demoted.
  {
    iframe->setAttribute(html_names::kStyleAttr,
                         AtomicString("border: 5px solid black"));
    Compositor().BeginFrame();

    EXPECT_NE(iframe,
              GetDocument().GetRootScrollerController().EffectiveRootScroller())
        << "The iframe should be demoted once it has border.";
  }

  // Removing the border should now cause the iframe to be promoted once again.
  iframe->setAttribute(html_names::kStyleAttr, g_empty_atom);
  Compositor().BeginFrame();

  ASSERT_EQ(iframe,
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "The iframe should once again be promoted when border is removed";
}

// Test that we don't promote any elements implicitly if the main document has
// vertical scrolling.
TEST_F(ImplicitRootScrollerSimTest, OverflowInMainDocumentRestrictsImplicit) {
  WebView().ResizeWithBrowserControls(gfx::Size(800, 600), 50, 0, true);
  SimRequest main_request("https://example.com/test.html", "text/html");
  SimRequest child_request("https://example.com/child.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_request.Complete(R"HTML(
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
            div {
              position: absolute;
              left: 0;
              top: 0;
              height: 150%;
              width: 150%;
            }
          </style>
          <iframe id="container" src="child.html">
          </iframe>
          <div id="spacer"></div>
      )HTML");
  child_request.Complete(R"HTML(
        <!DOCTYPE html>
        <style>
          body {
            height: 1000px;
          }
        </style>
  )HTML");

  Compositor().BeginFrame();
  EXPECT_EQ(GetDocument(),
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "iframe shouldn't be promoted due to overflow in the main document.";

  Element* spacer = GetDocument().getElementById(AtomicString("spacer"));
  spacer->style()->setProperty(GetDocument().GetExecutionContext(), "height",
                               "100%", String(), ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();

  EXPECT_EQ(GetDocument().getElementById(AtomicString("container")),
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "Once vertical overflow is removed, the iframe should be promoted.";
}

// Test that we overflow in the document allows promotion only so long as the
// document isn't scrollable.
TEST_F(ImplicitRootScrollerSimTest, OverflowHiddenDoesntRestrictImplicit) {
  WebView().ResizeWithBrowserControls(gfx::Size(800, 600), 50, 0, true);
  SimRequest main_request("https://example.com/test.html", "text/html");
  SimRequest child_request("https://example.com/child.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_request.Complete(R"HTML(
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
            iframe {
              width: 100%;
              height: 100%;
              border: 0;
            }
            #spacer {
              position: absolute;
              left: 0;
              top: 0;
              height: 150%;
              width: 150%;
            }
          </style>
          <iframe id="container" src="child.html">
          </iframe>
          <div id="spacer"></div>
      )HTML");
  child_request.Complete(R"HTML(
        <!DOCTYPE html>
        <style>
          body {
            height: 1000px;
          }
        </style>
  )HTML");

  Compositor().BeginFrame();
  EXPECT_EQ(GetDocument().getElementById(AtomicString("container")),
            GetDocument().GetRootScrollerController().EffectiveRootScroller())
      << "iframe should be promoted since document's overflow is hidden.";

  Element* html = GetDocument().documentElement();
  html->style()->setProperty(GetDocument().GetExecutionContext(), "overflow",
                             "auto", String(), ASSERT_NO_EXCEPTION);
  Compositor().BeginFrame();

  EXPECT_EQ
"""


```