Response:
The user wants a summary of the provided C++ code, specifically focusing on its functionality, relationships with web technologies (JavaScript, HTML, CSS), logical reasoning with examples, common user/programming errors, and a general conclusion.

Here's a breakdown of the code and its implications:

1. **Core Functionality:** The code tests the `TextFragmentAnchor` feature in the Chromium Blink rendering engine. This feature allows navigating to specific text on a page using a URL fragment (the `#:~:text=...` part). The tests verify that the correct text is found, highlighted, and scrolled into view.

2. **Relationship with Web Technologies:**
    *   **HTML:** The tests load HTML documents to simulate web pages. They use HTML elements (`<p>`, `<div>`, `<span>`, `<img>`) and attributes (`id`, `hidden="until-found"`) to structure the content and test different scenarios.
    *   **CSS:** CSS is used for styling elements, primarily to set the height of the `body` to ensure scrolling can be tested. It also positions elements absolutely to control their location for testing viewport visibility.
    *   **JavaScript:**  Some tests include JavaScript code within the HTML to simulate dynamic content loading (`onload`, `requestAnimationFrame`, `setInterval`), manipulate the DOM (`document.getElementById`, `firstChild.data`, `setAttribute`, `appendChild`), and interact with browser history (`history.scrollRestoration`, `history.replaceState`).

3. **Logical Reasoning and Examples:** The tests use `EXPECT_TRUE`, `EXPECT_FALSE`, and `EXPECT_EQ` assertions to check the outcomes of different scenarios. I need to formulate example inputs (URLs, HTML content) and the expected outputs (whether an element is targeted, scrolled into view, highlighted, etc.).

4. **Common User/Programming Errors:** These errors often relate to how text fragments are used in URLs or how web pages are structured. For example, incorrect encoding of the text fragment, or dynamic changes to the page content that might interfere with the text fragment matching.

5. **Overall Summary:**  The code is a comprehensive suite of tests for the `TextFragmentAnchor` feature, ensuring its robustness and correctness in various scenarios, including interactions with JavaScript, dynamic content, and specific browser behaviors.

**Plan:**

*   For each test case, identify its specific goal.
*   Extract examples of how it relates to HTML, CSS, and JavaScript.
*   Formulate input and expected output examples for the logical reasoning.
*   Identify potential user or programming errors based on the test scenarios.
*   Combine these points into a cohesive summary.
这是对 `blink/renderer/core/fragment_directive/text_fragment_anchor_test.cc` 文件功能的归纳总结， 基于之前提供的第1和第2部分内容。

**总功能归纳:**

`text_fragment_anchor_test.cc` 文件包含了一系列单元测试，用于验证 Chromium Blink 引擎中 **Text Fragment Anchors** 功能的正确性和可靠性。Text Fragment Anchors 允许用户通过 URL 中的特定片段（`#:~:text=...`）直接链接到网页上的特定文本内容。

该测试文件旨在覆盖 Text Fragment Anchors 功能的各种场景，包括：

*   **基本匹配和滚动:** 验证当 URL 包含文本片段时，浏览器能够正确识别并滚动到匹配的文本位置。
*   **高亮显示:** 验证匹配到的文本是否被正确高亮显示。
*   **边界情况处理:** 测试匹配跨越不同 HTML 元素、注释节点、以及包含特殊字符的文本的情况。
*   **与 JavaScript 的交互:** 测试当页面包含 JavaScript 代码，例如修改页面内容、控制滚动行为、或者操作历史记录时，Text Fragment Anchors 的行为是否符合预期。
*   **与页面加载状态的交互:**  测试在页面加载的不同阶段（初始加载、加载完成后）Text Fragment Anchors 的处理方式。
*   **用户交互:** 模拟用户点击行为，测试在 Text Fragment Anchors 激活时，上下文菜单和文本选择的行为。
*   **性能优化:** 验证在特定情况下，例如匹配到 `hidden="until-found"` 的元素时，性能表现是否良好。
*   **回归测试:** 修复 bug 后，添加测试用例以防止 bug 再次出现。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **HTML:** 测试用例会加载不同的 HTML 结构，验证在各种 HTML 结构下 Text Fragment Anchors 的匹配能力。
    *   **例子:**  测试匹配跨越 `<span>` 标签的文本：
        ```html
        <div id="text"><span>abc</span><span>def</span></div>
        ```
        对应测试用例 `MatchAcrossSpans`。
*   **CSS:** CSS 用于控制页面的布局和元素的显示，测试用例会使用 CSS 来设置页面高度，以便测试滚动行为。
    *   **例子:** 设置 `body` 的高度为 `1200px`，确保页面可以滚动：
        ```css
        body {
          height: 1200px;
        }
        ```
        这在多个测试用例中都有使用，例如 `Basic`。
*   **JavaScript:** 测试用例会包含 JavaScript 代码，模拟动态修改页面内容或者与浏览器历史记录交互的情况，验证 Text Fragment Anchors 在这些情况下的行为。
    *   **例子:** 使用 `history.scrollRestoration = 'manual'` 阻止自动滚动，测试 Text Fragment Anchors 是否仍然能触发滚动：
        ```html
        <script>
          history.scrollRestoration = 'manual';
        </script>
        ```
        对应测试用例 `ManualRestorationDoesntBlockFragment`。
    *   **例子:**  在页面加载后通过 JavaScript 动态添加匹配的文本内容：
        ```javascript
        onload = () => {
          requestAnimationFrame(() => requestAnimationFrame(() => {
            document.getElementById('match').firstChild.data = 'A test page';
          }));
        }
        ```
        对应测试用例 `ContentAddedPostLoad`。

**逻辑推理及假设输入与输出:**

*   **假设输入:** URL 为 `https://example.com/test.html#:~:text=This%20is%20a%20test`，页面内容包含 `<p id="text">This is a test page</p>`。
*   **逻辑推理:**  Text Fragment Anchors 功能应该能找到 `<p>` 标签内的文本 "This is a test"，并将该元素滚动到视图中并高亮显示。
*   **预期输出:**  `GetDocument().CssTarget()` 返回指向 `<p>` 元素的指针，`ViewportRect().Contains(BoundingRectInFrame(p))` 返回 `true`，`GetDocument().Markers().Markers().size()` 大于 0。

*   **假设输入:** URL 为 `https://example.com/test.html#:~:text=abc,def`，页面内容包含 `<div>abcdef</div>`。
*   **逻辑推理:**  Text Fragment Anchors 功能应该能找到 `<div>` 标签内的文本 "abcdef"，并将该元素滚动到视图中并高亮显示。
*   **预期输出:** `GetDocument().CssTarget()` 返回指向 `<div>` 元素的指针，`ViewportRect().Contains(BoundingRectInFrame(div))` 返回 `true`，`GetDocument().Markers().Markers().size()` 大于 0。

**涉及用户或编程常见的使用错误举例说明:**

*   **错误的 URL 编码:** 用户可能在 URL 中错误地编码了特殊字符，导致 Text Fragment Anchors 无法正确匹配。例如，将空格编码为 `+` 而不是 `%20`。
*   **动态修改页面内容导致匹配失败:** 开发者可能在页面加载后通过 JavaScript 动态修改了文本内容，导致原本应该匹配的文本不再存在或者位置发生变化，使得 Text Fragment Anchors 无法找到目标。例如，在 `onload` 事件后修改了文本内容。
*   **依赖错误的页面加载时机:** 开发者可能假设 Text Fragment Anchors 在页面完全加载完成后才生效，但实际上它在某些情况下可能会在页面加载过程中尝试匹配。如果匹配的文本在初始加载时不存在，则可能导致匹配失败。
*   **误用 `history.scrollRestoration = 'manual'`:**  开发者可能为了控制页面的滚动行为设置了 `history.scrollRestoration = 'manual'`，但如果没有考虑到 Text Fragment Anchors 的需求，可能会阻止 Text Fragment Anchors 的自动滚动行为，导致用户无法直接看到目标文本。

**总结:**

作为第三部分，结合前两部分的内容，可以确认 `text_fragment_anchor_test.cc` 文件的主要功能是 **全面测试 Chromium Blink 引擎中 Text Fragment Anchors 功能的各种方面**。它通过模拟不同的 HTML 结构、CSS 样式、JavaScript 交互和用户行为，来验证该功能在各种场景下的正确性和鲁棒性，并防止出现回归错误。这些测试用例覆盖了从基本的匹配和滚动到复杂的与 JavaScript 和页面加载状态的交互，以及用户交互的各种情况，确保了 Text Fragment Anchors 功能能够稳定可靠地工作，为用户提供更好的网页导航体验。

### 提示词
```
这是目录为blink/renderer/core/fragment_directive/text_fragment_anchor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
me(p)));
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
  EXPECT_EQ(p, *GetDocument().CssTarget());
}

// Regression test for https://crbug.com/1147568. Make sure a page setting
// manual scroll restoration doesn't cause the fragment to avoid scrolling on
// the initial load.
TEST_F(TextFragmentAnchorTest, ManualRestorationDoesntBlockFragment) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  LoadURL("https://example.com/test.html#:~:text=test");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <script>
      history.scrollRestoration = 'manual';
    </script>
    <p id="text">This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& p = *GetDocument().getElementById(AtomicString("text"));
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)));
}

// Regression test for https://crbug.com/1147453. Ensure replaceState doesn't
// clobber the text fragment token and allows fragment to scroll.
TEST_F(TextFragmentAnchorTest, ReplaceStateDoesntBlockFragment) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  LoadURL("https://example.com/test.html#:~:text=test");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
    </style>
    <script>
      history.replaceState({}, 'test', '');
    </script>
    <p id="text">This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& p = *GetDocument().getElementById(AtomicString("text"));
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)));
}

// Test that a text directive can match across comment nodes
TEST_F(TextFragmentAnchorTest, MatchAcrossCommentNode) {
  SimRequest request("https://example.com/test.html#:~:text=abcdef",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=abcdef");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      div {
        position: absolute;
        top: 1000px;
      }
    </style>
    <div id="text"><span>abc</span><!--comment--><span>def</span></div>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& div = *GetDocument().getElementById(AtomicString("text"));

  EXPECT_EQ(div, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(div)));
  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());
}

// Test that selection is successful for same prefix and text start.
TEST_F(TextFragmentAnchorTest, SamePrefixAndText) {
  SimRequest request("https://example.com/test.html#:~:text=foo-,foo,-bar",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=foo-,foo,-bar");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      div {
        position: absolute;
        top: 1000px;
      }
    </style>
    <div id="text">foo foo foo bar bar bar</div>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& div = *GetDocument().getElementById(AtomicString("text"));

  EXPECT_EQ(div, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(div)));
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

// Checks that selection in the same text node is considerered uninterrupted.
TEST_F(TextFragmentAnchorTest, IsInSameUninterruptedBlock_OneTextNode) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='first'>First paragraph text</div>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = PositionInFlatTree(first_paragraph, 0);
  const auto& end = PositionInFlatTree(first_paragraph, 15);
  ASSERT_EQ("First paragraph", PlainText(EphemeralRangeInFlatTree(start, end)));

  EXPECT_TRUE(TextFragmentFinder::IsInSameUninterruptedBlock(start, end));
}

// Checks that selection in the same text node with nested non-block element is
// considerered uninterrupted.
TEST_F(TextFragmentAnchorTest,
       IsInSameUninterruptedBlock_NonBlockInterruption) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='first'>First <i>styled text</i> paragraph text</div>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = PositionInFlatTree(first_paragraph, 0);
  const auto& end =
      PositionInFlatTree(first_paragraph->nextSibling()->nextSibling(), 10);
  ASSERT_EQ("First styled text paragraph",
            PlainText(EphemeralRangeInFlatTree(start, end)));

  EXPECT_TRUE(TextFragmentFinder::IsInSameUninterruptedBlock(start, end));
}

// Checks that selection in the same text node with nested block element is
// considerered interrupted.
TEST_F(TextFragmentAnchorTest, IsInSameUninterruptedBlock_BlockInterruption) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <div id='first'>First <div>block text</div> paragraph text</div>
  )HTML");
  Node* first_paragraph =
      GetDocument().getElementById(AtomicString("first"))->firstChild();
  const auto& start = PositionInFlatTree(first_paragraph, 0);
  const auto& end =
      PositionInFlatTree(first_paragraph->nextSibling()->nextSibling(), 10);
  ASSERT_EQ("First\nblock text\nparagraph",
            PlainText(EphemeralRangeInFlatTree(start, end)));

  EXPECT_FALSE(TextFragmentFinder::IsInSameUninterruptedBlock(start, end));
}

TEST_F(TextFragmentAnchorTest, OpenedFromHighlightDoesNotSelectAdditionalText) {
  SimRequest request("https://www.test.com/#:~:text=First%20test,page%20three",
                     "text/html");
  LoadURL("https://www.test.com/#:~:text=First%20test,page%20three");
  request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
      p {
        font-size: 12px;
      }
      </style>
      <p id="one">First test page one</p>
      <p id="two">Second test page two</p>
      <p id="three">Third test page three</p>
      <p id="four">Fourth test page four</p>
      </html>)HTML");
  RunUntilTextFragmentFinalization();

  Element* middle_element = GetDocument().getElementById(AtomicString("two"));
  Element* last_element = GetDocument().getElementById(AtomicString("four"));

  WebView().GetSettings()->SetEditingBehavior(
      mojom::EditingBehavior::kEditingMacBehavior);

  // Create a mouse event in the middle of <p> two.
  WebMouseEvent mouse_down_event(WebInputEvent::Type::kMouseDown,
                                 WebInputEvent::kNoModifiers,
                                 WebInputEvent::GetStaticTimeStampForTests());
  const DOMRect* middle_rect = middle_element->GetBoundingClientRect();
  gfx::PointF middle_elem_point(((middle_rect->left() + 1)),
                                ((middle_rect->top() + 1)));
  mouse_down_event.SetPositionInWidget(middle_elem_point.x(),
                                       middle_elem_point.y());
  mouse_down_event.SetPositionInScreen(middle_elem_point.x(),
                                       middle_elem_point.y());
  mouse_down_event.click_count = 1;
  mouse_down_event.button = WebMouseEvent::Button::kRight;

  // Corresponding release event (Windows shows context menu on release).
  WebMouseEvent mouse_up_event(mouse_down_event);
  mouse_up_event.SetType(WebInputEvent::Type::kMouseUp);

  WebView().MainFrameViewWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_down_event, ui::LatencyInfo()));
  WebView().MainFrameViewWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_up_event, ui::LatencyInfo()));

  // No additional text should be selected.
  FrameSelection& selection = GetDocument().GetFrame()->Selection();
  EXPECT_TRUE(selection.SelectedText().empty());

  // Create a mouse event at the center of <p> four.
  const DOMRect* last_rect = last_element->GetBoundingClientRect();
  gfx::PointF last_elem_point(((last_rect->left() + 1)),
                              ((last_rect->top() + 1)));
  mouse_down_event.SetPositionInWidget(last_elem_point.x(),
                                       last_elem_point.y());
  mouse_down_event.SetPositionInScreen(last_elem_point.x(),
                                       last_elem_point.y());

  // Corresponding release event (Windows shows context menu on release).
  WebMouseEvent last_mouse_up_event(mouse_down_event);
  last_mouse_up_event.SetType(WebInputEvent::Type::kMouseUp);

  WebView().MainFrameViewWidget()->HandleInputEvent(
      WebCoalescedInputEvent(mouse_down_event, ui::LatencyInfo()));
  WebView().MainFrameViewWidget()->HandleInputEvent(
      WebCoalescedInputEvent(last_mouse_up_event, ui::LatencyInfo()));

  // The text underneath the cursor should be selected.
  EXPECT_FALSE(selection.SelectedText().empty());
}

// Test that on Android, a user can display a context menu by tapping on
// a text fragment, when the TextFragmentTapOpensContextMenu
// RuntimeEnabledFeature is enabled.
TEST_F(TextFragmentAnchorTest, ShouldOpenContextMenuOnTap) {
  LoadAhem();
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=this%20is%20a%20test%20page",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=this%20is%20a%20test%20page");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>p { font: 10px/1 Ahem; }</style>
    <p id="first">This is a test page</p>
    <p id="two">Second test page two</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  ContextMenuAllowedScope context_menu_allowed_scope;

  EXPECT_FALSE(GetDocument()
                   .GetPage()
                   ->GetContextMenuController()
                   .ContextMenuNodeForFrame(GetDocument().GetFrame()));

  Range* range = Range::Create(GetDocument());
  range->setStart(GetDocument().getElementById(AtomicString("first")), 0,
                  IGNORE_EXCEPTION_FOR_TESTING);
  range->setEnd(GetDocument().getElementById(AtomicString("first")), 1,
                IGNORE_EXCEPTION_FOR_TESTING);
  ASSERT_EQ("This is a test page", range->GetText());

  gfx::Point tap_point = range->BoundingBox().CenterPoint();
  SimulateTap(tap_point.x(), tap_point.y());

  if (RuntimeEnabledFeatures::TextFragmentTapOpensContextMenuEnabled()) {
    EXPECT_TRUE(GetDocument()
                    .GetPage()
                    ->GetContextMenuController()
                    .ContextMenuNodeForFrame(GetDocument().GetFrame()));
  } else {
    EXPECT_FALSE(GetDocument()
                     .GetPage()
                     ->GetContextMenuController()
                     .ContextMenuNodeForFrame(GetDocument().GetFrame()));
  }

  GetDocument().GetPage()->GetContextMenuController().ClearContextMenu();

  range->setStart(GetDocument().getElementById(AtomicString("two")), 0,
                  IGNORE_EXCEPTION_FOR_TESTING);
  range->setEndAfter(GetDocument().getElementById(AtomicString("two")),
                     IGNORE_EXCEPTION_FOR_TESTING);
  ASSERT_EQ("Second test page two", range->GetText());

  tap_point = range->BoundingBox().CenterPoint();
  SimulateTap(tap_point.x(), tap_point.y());

  EXPECT_FALSE(GetDocument()
                   .GetPage()
                   ->GetContextMenuController()
                   .ContextMenuNodeForFrame(GetDocument().GetFrame()));
}

#if BUILDFLAG(ENABLE_UNHANDLED_TAP)
// Mock implementation of the UnhandledTapNotifier Mojo receiver, for testing
// the ShowUnhandledTapUIIfNeeded notification.
class MockUnhandledTapNotifierImpl : public mojom::blink::UnhandledTapNotifier {
 public:
  MockUnhandledTapNotifierImpl() = default;

  void Bind(mojo::ScopedMessagePipeHandle handle) {
    receiver_.Bind(mojo::PendingReceiver<mojom::blink::UnhandledTapNotifier>(
        std::move(handle)));
  }

  void ShowUnhandledTapUIIfNeeded(
      mojom::blink::UnhandledTapInfoPtr unhandled_tap_info) override {
    was_unhandled_tap_ = true;
  }
  bool WasUnhandledTap() const { return was_unhandled_tap_; }
  bool ReceiverIsBound() const { return receiver_.is_bound(); }
  void Reset() {
    was_unhandled_tap_ = false;
    receiver_.reset();
  }

 private:
  bool was_unhandled_tap_ = false;

  mojo::Receiver<mojom::blink::UnhandledTapNotifier> receiver_{this};
};
#endif  // BUILDFLAG(ENABLE_UNHANDLED_TAP)

#if BUILDFLAG(ENABLE_UNHANDLED_TAP)
// Test that on Android, when a user taps on a text, ShouldNotRequestUnhandled
// does not get triggered. When a user taps on a highlight, no text should be
// selected. RuntimeEnabledFeature is enabled.
TEST_F(TextFragmentAnchorTest,
       ShouldNotRequestUnhandledTapNotifierWhenTapOnTextFragment) {
  LoadAhem();
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=this%20is%20a%20test%20page",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=this%20is%20a%20test%20page");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>p { font: 10px/1 Ahem; }</style>
    <p id="first">This is a test page</p>
    <p id="two">Second test page two</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  MockUnhandledTapNotifierImpl mock_notifier;
  GetDocument().GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      mojom::blink::UnhandledTapNotifier::Name_,
      WTF::BindRepeating(&MockUnhandledTapNotifierImpl::Bind,
                         WTF::Unretained(&mock_notifier)));

  Range* range = Range::Create(GetDocument());
  range->setStart(GetDocument().getElementById(AtomicString("first")), 0,
                  IGNORE_EXCEPTION_FOR_TESTING);
  range->setEnd(GetDocument().getElementById(AtomicString("first")), 1,
                IGNORE_EXCEPTION_FOR_TESTING);
  ASSERT_EQ("This is a test page", range->GetText());

  mock_notifier.Reset();
  gfx::Point tap_point = range->BoundingBox().CenterPoint();
  SimulateTap(tap_point.x(), tap_point.y());

  base::RunLoop().RunUntilIdle();
  if (RuntimeEnabledFeatures::TextFragmentTapOpensContextMenuEnabled()) {
    EXPECT_FALSE(mock_notifier.WasUnhandledTap());
    EXPECT_FALSE(mock_notifier.ReceiverIsBound());
  } else {
    EXPECT_TRUE(mock_notifier.WasUnhandledTap());
    EXPECT_TRUE(mock_notifier.ReceiverIsBound());
  }

  range->setStart(GetDocument().getElementById(AtomicString("two")), 0,
                  IGNORE_EXCEPTION_FOR_TESTING);
  range->setEndAfter(GetDocument().getElementById(AtomicString("two")),
                     IGNORE_EXCEPTION_FOR_TESTING);
  ASSERT_EQ("Second test page two", range->GetText());

  mock_notifier.Reset();
  tap_point = range->BoundingBox().CenterPoint();
  SimulateTap(tap_point.x(), tap_point.y());

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_notifier.WasUnhandledTap());
  EXPECT_TRUE(mock_notifier.ReceiverIsBound());
}
#endif  // BUILDFLAG(ENABLE_UNHANDLED_TAP)

TEST_F(TextFragmentAnchorTest, TapOpeningContextMenuWithDirtyLifecycleNoCrash) {
  ScopedTextFragmentTapOpensContextMenuForTest tap_opens_context_menu(true);

  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=This%20is%20just%20example",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=This%20is%20just%20example");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        .content {
          width: 1000px;
          height: 2000px;
          background-color: silver;
        }
      </style>
      <script>
        // Dirty lifecycle inside the click event.
        addEventListener('click', () => {
          document.body.style.width = '500px';
        });
        // This prevents calling HandleMouseReleaseEvent which has an
        // UpdateLifecycle call inside it but it also prevents showing the
        // context menu.
        addEventListener('mouseup', (e) => { e.preventDefault(); });
      </script>
    </head>

    <body>
      This is just example text that will wrap.
      <div class="content"></div>
    </body>
    </html>
  )HTML");
  RunUntilTextFragmentFinalization();

  ContextMenuAllowedScope context_menu_allowed_scope;

  EXPECT_FALSE(GetDocument()
                   .GetPage()
                   ->GetContextMenuController()
                   .ContextMenuNodeForFrame(GetDocument().GetFrame()));

  Node* first_paragraph = GetDocument().body()->firstChild();
  const auto& start = Position(first_paragraph, 0);
  const auto& end = Position(first_paragraph, 27);
  ASSERT_EQ("This is just example", PlainText(EphemeralRange(start, end)));

  Range* range = CreateRange(EphemeralRange(start, end));

  gfx::Point tap_point = range->BoundingBox().CenterPoint();
  SimulateTap(tap_point.x(), tap_point.y());

  // Expect that we won't see the context menu because we preventDefaulted the
  // mouseup but this test passes if it doesn't crash.
  EXPECT_FALSE(GetDocument()
                   .GetPage()
                   ->GetContextMenuController()
                   .ContextMenuNodeForFrame(GetDocument().GetFrame()));
}

// Test for https://crbug.com/1453658. Trips a CHECK because an AnnotationAgent
// unexpectedly calls Attach a second time after initially succeeding because
// the matched range becomes collapsed.
TEST_F(TextFragmentAnchorTest, InitialMatchingIsCollapsedCrash) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  SimSubresourceRequest sub_request("https://example.com/null.png",
                                    "image/png");
  LoadURL("https://example.com/test.html#:~:text=test");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      div {
        position: absolute;
        top: 1000px;
      }
    </style>
    <div id="text">test</div>
    <img src="null.png">
  )HTML");
  // Parsing completed but load is still waiting on the <img>, this will run
  // matching and match "test".
  Compositor().BeginFrame();

  // Ensure we've attached the annotation for the text fragment.
  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
  auto annotations = container->GetAgentsOfType(
      mojom::blink::AnnotationType::kSharedHighlight);
  ASSERT_EQ(annotations.size(), 1ul);
  ASSERT_TRUE((*annotations.begin())->IsAttached());

  // Remove the matched text node; this will collapse the matched range.
  Element& div = *GetDocument().getElementById(AtomicString("text"));
  div.firstChild()->remove();
  ASSERT_FALSE((*annotations.begin())->IsAttached());

  // Complete the <img> request (with an error). This will fire the load event
  // and perform another matching pass. Test passes if this doesn't crash.
  sub_request.Complete("");
  Compositor().BeginFrame();
}

// Test the behavior of removing matched text while waiting to expand a
// hidden=until-found section. We mostly care that this doesn't crash or
// violate any state CHECKs.
TEST_F(TextFragmentAnchorTest, InitialMatchPendingBecomesCollapsed) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  SimSubresourceRequest sub_request("https://example.com/null.png",
                                    "image/png");
  LoadURL("https://example.com/test.html#:~:text=test");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      div {
        position: absolute;
        top: 1000px;
      }
    </style>
    <div id="text" hidden="until-found">test</div>
    <img src="null.png">
    <div id="second">test (will match on second pass)</div>
  )HTML");
  // Parsing completed but load is still waiting on the <img>, this will run
  // matching and match "test" but queue a rAF task to show the hidden <div>.
  Compositor().BeginFrame();

  // Ensure we've queued the "DomMutation" rAF task.
  auto* container = AnnotationAgentContainerImpl::CreateIfNeeded(GetDocument());
  auto annotations = container->GetAgentsOfType(
      mojom::blink::AnnotationType::kSharedHighlight);
  ASSERT_EQ(annotations.size(), 1ul);
  ASSERT_TRUE((*annotations.begin())->IsAttachmentPending());

  // Remove the matched text node; this will collapse the matched range.
  Element& div = *GetDocument().getElementById(AtomicString("text"));
  div.firstChild()->remove();

  // Complete the <img> request (with an error). This will fire the load event
  // and the UpdateStyleAndLayout will perform another matching pass but this
  // shouldn't re-search the pending match.
  sub_request.Complete("");
  RunPendingTasks();
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  // This will run the "DomMutation" rAF task from the first match.
  Compositor().BeginFrame();

  // The directive should not have scrolled or created a marker.
  EXPECT_EQ(ScrollOffset(), LayoutViewport()->GetScrollOffset());
  EXPECT_TRUE(GetDocument().Markers().Markers().empty());
}

// These tests are specifically testing the post-load timer task so use
// the real clock to faithfully reproduce real-world behavior.
class TextFragmentAnchorPostLoadTest : public TextFragmentAnchorTestController {
 public:
  TextFragmentAnchorPostLoadTest() = default;
  void SetUp() override {
    TextFragmentAnchorTestController::SetUp();
    DisableVirtualTimeIfSet();
  }
};

// Ensure a content added shortly after load is found.
TEST_F(TextFragmentAnchorPostLoadTest, ContentAddedPostLoad) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  LoadURL("https://example.com/test.html#:~:text=test");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #spacer {
        height: 1000px;
      }
    </style>
    <body>
      <div id="spacer"></div>
      <p id="match">Loading...</p>
    </body>
    <script>
      onload = () => {
        requestAnimationFrame(() => requestAnimationFrame(() => {
          document.getElementById('match').firstChild.data = 'A test page';
        }));
      }
    </script>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& match = *GetDocument().getElementById(AtomicString("match"));
  ASSERT_TRUE(GetDocument().CssTarget());
  EXPECT_EQ(match, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(match)))
      << "<p> wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();
}

// Ensure a content added shortly after load is found.
TEST_F(TextFragmentAnchorPostLoadTest, HiddenAfterFoundPostLoad) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  LoadURL("https://example.com/test.html#:~:text=test");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #spacer {
        height: 1000px;
      }
    </style>
    <body>
      <div id="spacer"></div>
      <p id="match" hidden>A test page</p>
    </body>
    <script>
      onload = () => {
        requestAnimationFrame(() => requestAnimationFrame(() => {
          document.getElementById('match').setAttribute('hidden', 'until-found');
        }));
      }
    </script>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& match = *GetDocument().getElementById(AtomicString("match"));
  ASSERT_TRUE(GetDocument().CssTarget());
  EXPECT_EQ(match, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(match)))
      << "<p> wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();
}

// Ensure that the text fragment is searched within the delay time after load if
// DOM hasn't been mutated.
TEST_F(TextFragmentAnchorPostLoadTest, PostLoadSearchEndsWithoutDomMutation) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  LoadURL("https://example.com/test.html#:~:text=test");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #spacer {
        height: 1000px;
      }
    </style>
    <body>
      <div id="spacer"></div>
      <p id="match">Loading...</p>
    </body>
  )HTML");
  // Ensure the load event is run.
  test::RunPendingTasks();
  Compositor().BeginFrame();

  ASSERT_TRUE(GetDocument().View()->GetFragmentAnchor());

  test::RunDelayedTasks(TextFragmentAnchor::PostLoadTaskDelay());
  Compositor().BeginFrame();

  // Final frame for finalization.
  Compositor().BeginFrame();

  EXPECT_FALSE(GetDocument().View()->GetFragmentAnchor());
  EXPECT_TRUE(GetDocument().Markers().Markers().empty());
}

// Ensure that the post-load text fragment search is pushed back each time DOM
// is mutated.
TEST_F(TextFragmentAnchorPostLoadTest, PostLoadSearchTimesOut) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  LoadURL("https://example.com/test.html#:~:text=test");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #spacer {
        height: 1000px;
      }
    </style>
    <body>
      <div id="spacer"></div>
      <p id="match">Loading...</p>
    </body>
    <script>
      onload = () => {
        requestAnimationFrame(() => {
          document.getElementById('match').innerText = 'A test page';

          setInterval(() => {
            let p = document.createElement('p');
            document.body.appendChild(p);
          }, 50);
        });
      }
    </script>
  )HTML");
  // Ensure the load event is run.
  test::RunPendingTasks();

  // The fragment anchor is created but the search fails because the text
  // is still hidden.
  ASSERT_TRUE(GetDocument().View()->GetFragmentAnchor());
  ASSERT_TRUE(GetDocument().Markers().Markers().empty());

  // The text should now be available.
  Compositor().BeginFrame();
  Element& match = *GetDocument().getElementById(AtomicString("match"));
  ASSERT_EQ("A test page", match.innerText());

  // Waiting for the delay period shouldn't find the text because the DOM is
  // constantly being appended to. However, the search is still active and the
  // FragmentAnchor alive.
  test::RunDelayedTasks(TextFragmentAnchor::PostLoadTaskDelay());
  Compositor().BeginFrame();
  ASSERT_TRUE(GetDocument().View()->GetFragmentAnchor());
  EXPECT_TRUE(GetDocument().Markers().Markers().empty());

  // If we wait for the full timeout amount it should eventually
  // perform the search.
  test::RunDelayedTasks(TextFragmentAnchor::PostLoadTaskTimeout() -
                        TextFragmentAnchor::PostLoadTaskDelay());
  Compositor().BeginFrame();
  EXPECT_FALSE(GetDocument().Markers().Markers().empty());
  EXPECT_EQ(match, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(match)))
      << "<p> wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();
}

}  // namespace

}  // namespace blink
```