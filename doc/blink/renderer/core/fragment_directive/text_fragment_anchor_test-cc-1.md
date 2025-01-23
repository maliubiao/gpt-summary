Response:
The user wants to understand the functionality of the given C++ code snippet from `text_fragment_anchor_test.cc`. This is the second part of a three-part file.

Here's a breakdown of how to address the request:

1. **Identify the Core Functionality:**  The code consists of various test cases related to the Text Fragment API in Chromium. The overarching goal is to verify that this API correctly identifies, highlights, and scrolls to specified text on a webpage.

2. **Categorize Test Cases:** The tests cover several aspects of the Text Fragment API. I need to group similar tests together to summarize their purpose efficiently. The categories seem to include:
    * Basic text fragment matching and highlighting.
    * Interaction with scrolling (user vs. programmatic scrolls).
    * Restrictions in iframes and window.open.
    * Behavior during same-page navigations.
    * Case-insensitivity of matching.
    * Behavior during page loading.
    * Handling of overlapping text ranges.
    * Matching with special characters (like `&nbsp;`).
    * Matching with CSS text transformations.
    * Fallback to element fragments when no text match is found.
    * Word boundary matching.
    * Keeping highlights on clicks/taps.
    * Interaction with the `:target` CSS selector.
    * Handling of page visibility.
    * Interaction with fragment directive delimiters.
    * Matching within SVG elements.
    * Combination of text and non-text directives.

3. **Explain Relationships to Web Technologies:**  The Text Fragment API directly relates to:
    * **HTML:** It targets specific text content within HTML documents.
    * **JavaScript:**  While not directly manipulating JavaScript in these tests, the Text Fragment API can influence how JavaScript interacts with the page (e.g., through `location.hash`).
    * **CSS:**  The tests verify that the highlighted text receives `:target` styling and that CSS `text-transform` doesn't prevent matching.

4. **Provide Examples:**  For each category, I can give a simplified example of an HTML structure and a corresponding text fragment URL to illustrate the test scenario.

5. **Address Logical Reasoning (Input/Output):**  For specific test cases, especially those involving scrolling or highlighting, I can describe the expected state of the page (scrolled position, highlighted text) given a particular HTML structure and text fragment URL.

6. **Identify Common Errors:**  Think about how a developer might misuse or misunderstand the Text Fragment API. Examples could include:
    * Expecting it to work in iframes.
    * Forgetting about case sensitivity (though the tests show it's *insensitive*).
    * Not understanding word boundary matching.

7. **Summarize Functionality:**  Since this is part 2 of 3, I need to provide a concise summary of the features tested in this specific section of the code.

**Mental Walkthrough:**

I'll go through each test case and mentally categorize it. For example, the `ScrollCancelled` test clearly falls under "interaction with scrolling."  The `DisabledInIframes` test is about "restrictions."  `CaseInsensitive` is about "matching behavior."

I'll pay attention to the test names as they often provide a good summary of what's being tested.

For the examples, I'll use simple HTML snippets to keep them clear.

For the assumptions and outputs, I'll focus on the observable changes on the webpage (scrolling, highlighting).

Regarding common errors, I'll consider the constraints and limitations highlighted by the tests themselves (e.g., not in iframes, word boundaries).

Finally, I'll synthesize all the observations into a concise summary for part 2.

**(Self-Correction):**  Initially, I might focus too much on the C++ testing framework specifics. However, the user's question is about the *functionality being tested*, which is related to web technologies. I need to keep the focus on the web-facing aspects of the Text Fragment API.

By following these steps, I can provide a comprehensive and helpful answer to the user's request.
这是 `blink/renderer/core/fragment_directive/text_fragment_anchor_test.cc` 文件的第二部分，它主要包含了一系列的单元测试，用于验证 Blink 引擎中 Text Fragment Anchor 功能的正确性和各种边界情况。

**功能归纳：**

这部分代码主要测试了 Text Fragment Anchor 功能在以下方面的表现：

1. **滚动行为与用户交互:**
   - 测试用户手动滚动是否会取消 Text Fragment 触发的自动滚动。
   - 测试用户滚动是否会移除文本高亮显示。

2. **禁用场景:**
   - 测试 Text Fragment Anchor 功能在 `<iframe>` 元素中是否被禁用（出于安全考虑）。
   - 测试 Text Fragment Anchor 功能在 `window.open` 打开的新窗口中是否被禁用。
   - 测试 Text Fragment Anchor 功能是否不会被同页面内的脚本导航激活。

3. **匹配规则和特性:**
   - 测试文本匹配是否是大小写不敏感的。
   - 测试在页面加载过程中，目标文本片段是否始终保持在视野内。
   - 测试当多个文本片段重叠时，是否能正确合并高亮显示。
   - 测试空格字符是否能匹配 `&nbsp;` 字符。
   - 测试是否能正确匹配应用了 CSS `text-transform` 属性的文本。
   - 测试当没有找到匹配的文本片段时，是否会回退到元素片段滚动。
   - 测试文本匹配是否遵循单词边界，不会匹配部分单词。

4. **用户交互与高亮显示:**
   - 测试点击操作是否会保持文本高亮显示。
   - 测试点击操作是否不会移除文本高亮显示。
   - 测试触摸操作是否会保持文本高亮显示。
   - 测试触摸操作是否不会移除文本高亮显示。
   - 测试在文本片段滚动到视野内外，高亮显示是否能正确保持。

5. **URL 处理:**
   - 测试片段指令分隔符 `:~:` 是否能正常工作，并从最终的 URL 中移除。
   - 测试当 URL 中同时存在元素片段和片段指令时，片段指令是否能正确处理并移除。
   - 测试即使片段指令不是文本指令，也会被从 URL 中移除。

6. **在特定 HTML 结构中的匹配:**
   - 测试是否能在 `<svg>` 元素内部的 `<text>` 元素中匹配文本。

7. **页面重载:**
   -  **(已禁用测试)** 测试页面重新加载后是否能恢复文本高亮显示。（该功能已被抑制）

8. **与其他指令的组合:**
   - 测试文本指令是否能与其他非文本指令组合使用。

9. **CSS 样式:**
   - 测试文本指令是否会应用 `:target` CSS 伪类样式。

10. **页面可见性:**
    - 测试文本片段的匹配是否只在页面变为可见时发生。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  Text Fragment Anchor 的核心功能是定位和高亮显示 HTML 文档中的特定文本内容。
    * **例子:**  如果 HTML 中有 `<p>This is a test page</p>`，而 URL 是 `example.com#:~:text=test%20page`，则 "test page" 这部分文本会被高亮显示。

* **JavaScript:**  虽然这部分测试代码主要是 C++，但 Text Fragment Anchor 的行为会影响 JavaScript 可以获取到的信息和执行的操作。
    * **例子:**  `window.location.hash` 会因为 Text Fragment Anchor 的处理而被修改（`:~:text=...` 部分会被移除）。JavaScript 可以监听 `hashchange` 事件来感知这种变化。

* **CSS:** Text Fragment Anchor 会影响 CSS 的 `:target` 伪类，被匹配到的文本或包含该文本的元素会应用 `:target` 样式。
    * **例子:** 如果 CSS 中有 `:target { background-color: yellow; }`，当 URL 中包含匹配的文本片段时，该文本的背景色会变为黄色。

**逻辑推理 (假设输入与输出):**

* **假设输入:**
    * HTML 内容: `<p id="target-paragraph">This is the target text.</p>`
    * URL: `example.com#:~:text=target%20text`
* **预期输出:**
    * 页面滚动到包含 "target text" 的 `<p>` 元素附近。
    * "target text" 这部分文本被高亮显示。
    * `<p id="target-paragraph">` 元素（或包含该文本的最小元素）匹配 CSS 的 `:target` 选择器。
    * `window.location.hash` 变为 `#target-paragraph` (如果元素片段也存在) 或者为空（如果只有文本片段）。

**用户或编程常见的使用错误举例:**

* **期望在 `<iframe>` 中工作:** 用户可能会尝试使用 Text Fragment Anchor 定位 `<iframe>` 中的文本，但这会被浏览器阻止，因为存在安全风险。
* **忽略大小写:** 虽然 Text Fragment Anchor 是大小写不敏感的，但用户可能会错误地认为需要精确匹配大小写。
* **不理解单词边界:** 用户可能期望匹配 "test"，但在 "testing" 中不会被匹配到，因为有单词边界的限制。
* **认为可以通过 JavaScript 直接控制高亮:** 用户可能会尝试使用 JavaScript API 来创建或移除 Text Fragment Anchor 的高亮，但这个高亮是由浏览器根据 URL 中的片段指令自动管理的。

总而言之，这部分测试代码专注于验证 Text Fragment Anchor 功能在各种场景下的行为，特别是与用户交互、页面加载、URL 处理以及与其他 Web 技术（HTML, CSS）的集成方面。它旨在确保该功能按照预期工作，并处理各种潜在的边界情况和安全问题。

### 提示词
```
这是目录为blink/renderer/core/fragment_directive/text_fragment_anchor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ild());
  markers = GetDocument().Markers().MarkersFor(
      *text2, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(6u, markers.at(0)->StartOffset());
  EXPECT_EQ(10u, markers.at(0)->EndOffset());
}

class TextFragmentAnchorScrollTest
    : public TextFragmentAnchorTest,
      public testing::WithParamInterface<mojom::blink::ScrollType> {
 protected:
  bool IsUserScrollType() {
    return GetParam() == mojom::blink::ScrollType::kCompositor ||
           GetParam() == mojom::blink::ScrollType::kUser;
  }
};

INSTANTIATE_TEST_SUITE_P(
    ScrollTypes,
    TextFragmentAnchorScrollTest,
    testing::Values(mojom::blink::ScrollType::kUser,
                    mojom::blink::ScrollType::kProgrammatic,
                    mojom::blink::ScrollType::kClamping,
                    mojom::blink::ScrollType::kCompositor,
                    mojom::blink::ScrollType::kAnchoring,
                    mojom::blink::ScrollType::kSequenced));

// Test that a user scroll cancels the scroll into view.
TEST_P(TextFragmentAnchorScrollTest, ScrollCancelled) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  SimSubresourceRequest css_request("https://example.com/test.css", "text/css");
  SimSubresourceRequest img_request("https://example.com/test.png",
                                    "image/png");
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
        visibility: hidden;
      }
    </style>
    <link rel=stylesheet href=test.css>
    <p id="text">This is a test page</p>
    <img src="test.png">
  )HTML");

  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  mojom::blink::ScrollType scroll_type = GetParam();

  GetDocument().View()->LayoutViewport()->ScrollBy(ScrollOffset(0, 100),
                                                   scroll_type);
  // Set the target text to visible and change its position to cause a layout
  // and invoke the fragment anchor in the next begin frame.
  css_request.Complete("p { visibility: visible; top: 1001px; }");
  img_request.Complete("");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  Element& p = *GetDocument().getElementById(AtomicString("text"));

  // If the scroll was a user scroll then we shouldn't try to keep the fragment
  // in view. Otherwise, we should.
  if (IsUserScrollType()) {
    EXPECT_FALSE(ViewportRect().Contains(BoundingRectInFrame(p)));
  } else {
    EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)));
  }

  EXPECT_EQ(p, *GetDocument().CssTarget());
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Expect marker on "test"
  auto* text = To<Text>(p.firstChild());
  DocumentMarkerVector markers = GetDocument().Markers().MarkersFor(
      *text, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(10u, markers.at(0)->StartOffset());
  EXPECT_EQ(14u, markers.at(0)->EndOffset());
}

// Test that user scrolling doesn't dismiss the highlight.
TEST_P(TextFragmentAnchorScrollTest, DontDismissTextHighlightOnUserScroll) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      #first {
        position: absolute;
        top: 1000px;
      }
      #second {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p id="first">This is a test page</p>
    <p id="second">With some more text</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_FALSE(GetDocument().View()->GetFragmentAnchor());

  ASSERT_EQ(2u, GetDocument().Markers().Markers().size());

  mojom::blink::ScrollType scroll_type = GetParam();
  LayoutViewport()->ScrollBy(ScrollOffset(0, -10), scroll_type);

  Compositor().BeginFrame();

  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());
}

// Ensure that the text fragment anchor has no effect in an iframe. This is
// disabled in iframes by design, for security reasons.
TEST_F(TextFragmentAnchorTest, DisabledInIframes) {
  SimRequest main_request("https://example.com/test.html", "text/html");
  SimRequest child_request("https://example.com/child.html#:~:text=test",
                           "text/html");
  LoadURL("https://example.com/test.html");
  main_request.Complete(R"HTML(
    <!DOCTYPE html>
    <iframe id="iframe" src="child.html#:~:text=test"></iframe>
  )HTML");

  child_request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        margin-top: 1000px;
      }
    </style>
    <p>
      test
    </p>
  )HTML");
  RunPendingTasks();
  Compositor().BeginFrame();

  Element* iframe = GetDocument().getElementById(AtomicString("iframe"));
  auto* child_frame =
      To<LocalFrame>(To<HTMLFrameOwnerElement>(iframe)->ContentFrame());

  EXPECT_FALSE(child_frame->View()->GetFragmentAnchor());
  EXPECT_EQ(nullptr, GetDocument().CssTarget());
  EXPECT_EQ(ScrollOffset(),
            child_frame->View()->GetScrollableArea()->GetScrollOffset());
}

// Similarly to the iframe case, we also want to prevent activating a text
// fragment anchor inside a window.opened window.
TEST_F(TextFragmentAnchorTest, DisabledInWindowOpen) {
  String destination = "https://example.com/child.html#:~:text=test";

  SimRequest main_request("https://example.com/test.html", "text/html");
  SimRequest child_request(destination, "text/html");
  LoadURL("https://example.com/test.html");
  main_request.Complete(R"HTML(
    <!DOCTYPE html>
  )HTML");
  Compositor().BeginFrame();

  LocalDOMWindow* main_window = GetDocument().GetFrame()->DomWindow();

  ScriptState* script_state =
      ToScriptStateForMainWorld(main_window->GetFrame());
  ScriptState::Scope entered_context_scope(script_state);
  LocalDOMWindow* child_window = To<LocalDOMWindow>(
      main_window->open(script_state->GetIsolate(), destination,
                        AtomicString("frame1"), "", ASSERT_NO_EXCEPTION));
  ASSERT_TRUE(child_window);

  RunPendingTasks();
  child_request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        margin-top: 1000px;
      }
    </style>
    <p>
      test
    </p>
  )HTML");

  RunAsyncMatchingTasks();

  EXPECT_EQ(nullptr, child_window->document()->CssTarget());

  LocalFrameView* child_view = child_window->GetFrame()->View();
  EXPECT_EQ(ScrollOffset(), child_view->GetScrollableArea()->GetScrollOffset());
}

// Ensure that the text fragment anchor is not activated by same-document script
// navigations.
TEST_F(TextFragmentAnchorTest, DisabledInSamePageNavigation) {
  SimRequest main_request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  main_request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        margin-top: 1000px;
      }
    </style>
    <p>
      test
    </p>
  )HTML");
  RunPendingTasks();
  Compositor().BeginFrame();

  ASSERT_EQ(ScrollOffset(),
            GetDocument().View()->GetScrollableArea()->GetScrollOffset());

  ScriptState* script_state =
      ToScriptStateForMainWorld(GetDocument().GetFrame());
  ScriptState::Scope entered_context_scope(script_state);
  GetDocument().GetFrame()->DomWindow()->location()->setHash(
      script_state->GetIsolate(), ":~:text=test", ASSERT_NO_EXCEPTION);
  RunAsyncMatchingTasks();

  EXPECT_EQ(nullptr, GetDocument().CssTarget());
  EXPECT_EQ(ScrollOffset(), LayoutViewport()->GetScrollOffset());
}

// Ensure matching is case insensitive.
TEST_F(TextFragmentAnchorTest, CaseInsensitive) {
  SimRequest request("https://example.com/test.html#:~:text=Test", "text/html");
  LoadURL("https://example.com/test.html#:~:text=Test");
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
    <p id="text">test</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& p = *GetDocument().getElementById(AtomicString("text"));

  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)))
      << "<p> Element wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

// Test that the fragment anchor stays centered in view throughout loading.
TEST_F(TextFragmentAnchorTest, TargetStaysInView) {
  SimRequest main_request("https://example.com/test.html#:~:text=test",
                          "text/html");
  SimRequest image_request("https://example.com/image.svg", "image/svg+xml");
  LoadURL("https://example.com/test.html#:~:text=test");
  main_request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        margin-top: 1000px;
      }
    </style>
    <img src="image.svg">
    <p id="text">test</p>
  )HTML");
  RunAsyncMatchingTasks();
  Compositor().BeginFrame();

  EXPECT_FALSE(GetDocument().IsLoadCompleted());
  EXPECT_TRUE(GetDocument().HasFinishedParsing());

  ScrollOffset first_scroll_offset = LayoutViewport()->GetScrollOffset();
  ASSERT_NE(ScrollOffset(), first_scroll_offset);

  Element& p = *GetDocument().getElementById(AtomicString("text"));
  gfx::Rect first_bounding_rect = BoundingRectInFrame(p);
  EXPECT_TRUE(ViewportRect().Contains(first_bounding_rect));

  // Load an image that pushes the target text out of view
  image_request.Complete(R"SVG(
    <svg xmlns="http://www.w3.org/2000/svg" width="200" height="2000">
      <rect fill="green" width="200" height="2000"/>
    </svg>
  )SVG");
  RunPendingTasks();
  EXPECT_TRUE(GetDocument().IsLoadCompleted());
  EXPECT_TRUE(GetDocument().HasFinishedParsing());

  Compositor().BeginFrame();

  // Ensure the target text is still in view and stayed centered
  ASSERT_NE(first_scroll_offset, LayoutViewport()->GetScrollOffset());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)));
  EXPECT_EQ(first_bounding_rect, BoundingRectInFrame(p));

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

// Test that overlapping text ranges results in both highlights with
// a merged highlight.
TEST_F(TextFragmentAnchorTest, OverlappingTextRanges) {
  SimRequest request(
      "https://example.com/test.html#:~:text=This,test&text=is,page",
      "text/html");
  LoadURL("https://example.com/test.html#:~:text=This,test&text=is,page");
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
    <p id="text">This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Expect marker on "This is a test page".
  auto* text = To<Text>(
      GetDocument().getElementById(AtomicString("text"))->firstChild());
  DocumentMarkerVector markers = GetDocument().Markers().MarkersFor(
      *text, DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(0u, markers.at(0)->StartOffset());
  EXPECT_EQ(19u, markers.at(0)->EndOffset());
}

// Test matching a space to &nbsp character.
TEST_F(TextFragmentAnchorTest, SpaceMatchesNbsp) {
  SimRequest request("https://example.com/test.html#:~:text=test%20page",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=test%20page");
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
    <p id="text">This is a test&nbsp;page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& p = *GetDocument().getElementById(AtomicString("text"));

  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)))
      << "<p> Element wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

// Test matching text with a CSS text transform.
TEST_F(TextFragmentAnchorTest, CSSTextTransform) {
  SimRequest request("https://example.com/test.html#:~:text=test%20page",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=test%20page");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 1000px;
        text-transform: uppercase;
      }
    </style>
    <p id="text">This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& p = *GetDocument().getElementById(AtomicString("text"));

  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)))
      << "<p> Element wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

// Test that we scroll the element fragment into view if we don't find a match.
TEST_F(TextFragmentAnchorTest, NoMatchFoundFallsBackToElementFragment) {
  SimRequest request("https://example.com/test.html#element:~:text=cats",
                     "text/html");
  LoadURL("https://example.com/test.html#element:~:text=cats");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      #text {
        position: absolute;
        top: 1000px;
      }
      #element {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p>This is a test page</p>
    <div id="element">Some text</div>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& p = *GetDocument().getElementById(AtomicString("element"));

  // At this point, the anchor should have been cleaned up.
  EXPECT_FALSE(GetDocument().View()->GetFragmentAnchor());

  // The text directive should be removed from the URL.
  EXPECT_EQ(GetDocument().Url(), "https://example.com/test.html#element");

  // Ensure the element was scrolled into view.
  ASSERT_TRUE(GetDocument().CssTarget());
  EXPECT_EQ(p, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)))
      << "<p> Element wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();
}

// Test that we don't match partial words at the beginning or end of the text.
TEST_F(TextFragmentAnchorTest, CheckForWordBoundary) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=This%20is%20a%20te&tagetText=st%20page",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=This%20is%20a%20te&tagetText=st%20page");
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
    <p id="text">This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(nullptr, GetDocument().CssTarget());
  EXPECT_EQ(ScrollOffset(), LayoutViewport()->GetScrollOffset());
  EXPECT_TRUE(GetDocument().Markers().Markers().empty());
}

// Test that we don't match partial words with context
TEST_F(TextFragmentAnchorTest, CheckForWordBoundaryWithContext) {
  SimRequest request("https://example.com/test.html#:~:text=est-,page",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=est-,page");
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
    <p id="text">This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(nullptr, GetDocument().CssTarget());
  EXPECT_EQ(ScrollOffset(), LayoutViewport()->GetScrollOffset());
  EXPECT_TRUE(GetDocument().Markers().Markers().empty());
}

// Test that we correctly match a whole word when it appears as a partial word
// earlier in the page.
TEST_F(TextFragmentAnchorTest, CheckForWordBoundaryWithPartialWord) {
  SimRequest request("https://example.com/test.html#:~:text=tes,age",
                     "text/html");
  LoadURL("https://example.com/test.html#:~:text=tes,age");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      #first {
        position: absolute;
        top: 1000px;
      }
      #second {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p id="first">This is a test page</p>
    <p id="second">This is a tes age</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& p = *GetDocument().getElementById(AtomicString("second"));

  EXPECT_EQ(p, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)))
      << "Should have scrolled <p> into view but didn't, scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();

  // Expect marker on only "tes age"
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
  DocumentMarkerVector markers = GetDocument().Markers().MarkersFor(
      *To<Text>(p.firstChild()), DocumentMarker::MarkerTypes::TextFragment());
  ASSERT_EQ(1u, markers.size());
  EXPECT_EQ(10u, markers.at(0)->StartOffset());
  EXPECT_EQ(17u, markers.at(0)->EndOffset());
}

// Test click keeps the text highlight
TEST_F(TextFragmentAnchorTest, DismissTextHighlightWithClick) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      #first {
        position: absolute;
        top: 1000px;
      }
      #second {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p id="first">This is a test page</p>
    <p id="second">With some more text</p>
  )HTML");
  RunUntilTextFragmentFinalization();
  EXPECT_FALSE(GetDocument().View()->GetFragmentAnchor());

  KURL url = GetDocument()
                 .GetFrame()
                 ->Loader()
                 .GetDocumentLoader()
                 ->GetHistoryItem()
                 ->Url();
  EXPECT_EQ(
      "https://example.com/test.html#:~:text=test%20page&text=more%20text",
      url.GetString());
  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());

  SimulateClick(100, 100);

  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());

  url = GetDocument()
            .GetFrame()
            ->Loader()
            .GetDocumentLoader()
            ->GetHistoryItem()
            ->Url();
  EXPECT_EQ(
      "https://example.com/test.html#:~:text=test%20page&text=more%20text",
      url.GetString());
}

// Test not dismissing the text highlight with a click.
TEST_F(TextFragmentAnchorTest, DontDismissTextHighlightWithClick) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      #first {
        position: absolute;
        top: 1000px;
      }
      #second {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p id="first">This is a test page</p>
    <p id="second">With some more text</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());

  SimulateClick(100, 100);

  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());
}

// Test that a tap keeps the text highlight
TEST_F(TextFragmentAnchorTest, KeepsTextHighlightWithTap) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      #first {
        position: absolute;
        top: 1000px;
      }
      #second {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p id="first">This is a test page</p>
    <p id="second">With some more text</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  KURL url = GetDocument()
                 .GetFrame()
                 ->Loader()
                 .GetDocumentLoader()
                 ->GetHistoryItem()
                 ->Url();
  EXPECT_EQ(
      "https://example.com/test.html#:~:text=test%20page&text=more%20text",
      url.GetString());
  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());

  SimulateTap(100, 100);

  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());

  url = GetDocument()
            .GetFrame()
            ->Loader()
            .GetDocumentLoader()
            ->GetHistoryItem()
            ->Url();
  EXPECT_EQ(
      "https://example.com/test.html#:~:text=test%20page&text=more%20text",
      url.GetString());
}

// Test not dismissing the text highlight with a tap.
TEST_F(TextFragmentAnchorTest, DontDismissTextHighlightWithTap) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      #first {
        position: absolute;
        top: 1000px;
      }
      #second {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p id="first">This is a test page</p>
    <p id="second">With some more text</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());

  SimulateTap(100, 100);

  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());
}

// Test that we don't dismiss a text highlight before and after it's scrolled
// into view
TEST_F(TextFragmentAnchorTest, KeepsTextHighlightOutOfView) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  SimSubresourceRequest css_request("https://example.com/test.css", "text/css");
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
        visibility: hidden;
      }
    </style>
    <link rel=stylesheet href=test.css>
    <p id="text">This is a test page</p>
  )HTML");

  ASSERT_EQ(0u, GetDocument().Markers().Markers().size());
  SimulateClick(100, 100);

  // Set the target text to visible and change its position to cause a layout
  // and invoke the fragment anchor.
  css_request.Complete("p { visibility: visible; top: 1001px; }");
  RunAsyncMatchingTasks();

  Compositor().BeginFrame();

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Click
  SimulateClick(100, 100);
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

// Test that a text highlight that didn't require a scroll into view is kept on
// tap
TEST_F(TextFragmentAnchorTest, KeepsTextHighlightInView) {
  SimRequest request(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text",
      "text/html");
  LoadURL(
      "https://example.com/"
      "test.html#:~:text=test%20page&text=more%20text");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      p {
        position: absolute;
        top: 100px;
      }
    </style>
    <p>This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(ScrollOffset(), LayoutViewport()->GetScrollOffset());
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  SimulateTap(100, 100);

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

// Test that the fragment directive delimiter :~: works properly and is stripped
// from the URL.
TEST_F(TextFragmentAnchorTest, FragmentDirectiveDelimiter) {
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
    <p id="text">This is a test page</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  EXPECT_EQ(GetDocument().Url(), "https://example.com/test.html");
}

// Test that a :~: fragment directive is scrolled into view and is stripped from
// the URL when there's also a valid element fragment.
TEST_F(TextFragmentAnchorTest, FragmentDirectiveDelimiterWithElementFragment) {
  SimRequest request("https://example.com/test.html#element:~:text=test",
                     "text/html");
  LoadURL("https://example.com/test.html#element:~:text=test");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      #text {
        position: absolute;
        top: 1000px;
      }
      #element {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p id="text">This is a test page</p>
    <div id="element">Some text</div>
  )HTML");
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(GetDocument().Url(), "https://example.com/test.html#element");

  Element& p = *GetDocument().getElementById(AtomicString("text"));

  EXPECT_EQ(p, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)))
      << "<p> Element wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();
}

// Test that a fragment directive is stripped from the URL even if it is not a
// text directive.
TEST_F(TextFragmentAnchorTest, IdFragmentWithFragmentDirective) {
  SimRequest request("https://example.com/test.html#element:~:id", "text/html");
  LoadURL("https://example.com/test.html#element:~:id");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      p {
        position: absolute;
        top: 1000px;
      }
      div {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p id="element">This is a test page</p>
    <div id="element:~:id">Some text</div>
  )HTML");
  RunPendingTasks();
  Compositor().BeginFrame();

  Element& p = *GetDocument().getElementById(AtomicString("element"));

  EXPECT_EQ(p, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)))
      << "Should have scrolled <div> into view but didn't, scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();
}

// Ensure we can match <text> inside of a <svg> element.
TEST_F(TextFragmentAnchorTest, TextDirectiveInSvg) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  LoadURL("https://example.com/test.html#:~:text=test");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 1200px;
      }
      svg {
        position: absolute;
        top: 1000px;
      }
    </style>
    <svg><text id="text" x="0" y="15">This is a test page</text></svg>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& text = *GetDocument().getElementById(AtomicString("text"));

  EXPECT_EQ(text, *GetDocument().CssTarget());
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(text)))
      << "<text> Element wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

// Ensure we restore the text highlight on page reload
// TODO(bokan): This test is disabled as this functionality was suppressed in
// https://crrev.com/c/2135407; it would be better addressed by providing a
// highlight-only function. See the TODO in
// https://wicg.github.io/ScrollToTextFragment/#restricting-the-text-fragment
TEST_F(TextFragmentAnchorTest, DISABLED_HighlightOnReload) {
  SimRequest request("https://example.com/test.html#:~:text=test", "text/html");
  LoadURL("https://example.com/test.html#:~:text=test");
  const String& html = R"HTML(
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
    <p id="text">This is a test page</p>
  )HTML";
  request.Complete(html);
  RunUntilTextFragmentFinalization();

  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());

  // Tap to dismiss the highlight.
  SimulateClick(10, 10);
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());

  // Reload the page and expect the highlight to be restored.
  SimRequest reload_request("https://example.com/test.html#:~:text=test",
                            "text/html");
  MainFrame().StartReload(WebFrameLoadType::kReload);
  reload_request.Complete(html);

  Compositor().BeginFrame();

  EXPECT_EQ(*GetDocument().getElementById(AtomicString("text")),
            *GetDocument().CssTarget());
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

// Ensure that we can have text directives combined with non-text directives
TEST_F(TextFragmentAnchorTest, NonTextDirectives) {
  SimRequest request(
      "https://example.com/test.html#:~:text=test&directive&text=more",
      "text/html");
  LoadURL("https://example.com/test.html#:~:text=test&directive&text=more");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        height: 2200px;
      }
      #first {
        position: absolute;
        top: 1000px;
      }
      #second {
        position: absolute;
        top: 2000px;
      }
    </style>
    <p id="first">This is a test page</p>
    <p id="second">This is some more text</p>
  )HTML");
  RunUntilTextFragmentFinalization();

  Element& first = *GetDocument().getElementById(AtomicString("first"));

  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(first)))
      << "First <p> wasn't scrolled into view, viewport's scroll offset: "
      << LayoutViewport()->GetScrollOffset().ToString();

  EXPECT_EQ(2u, GetDocument().Markers().Markers().size());
}

// Test that the text directive applies :target styling
TEST_F(TextFragmentAnchorTest, CssTarget) {
  SimRequest main_request("https://example.com/test.html#:~:text=test",
                          "text/html");
  SimRequest css_request("https://example.com/test.css", "text/css");
  LoadURL("https://example.com/test.html#:~:text=test");
  main_request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      p {
        margin-top: 1000px;
      }
    </style>
    <link rel="stylesheet" href="test.css">
    <p id="text">test</p>
  )HTML");

  css_request.Complete(R"CSS(
    :target {
      margin-top: 2000px;
    }
  )CSS");
  RunUntilTextFragmentFinalization();

  Element& p = *GetDocument().getElementById(AtomicString("text"));
  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFrame(p)));
  EXPECT_EQ(1u, GetDocument().Markers().Markers().size());
}

// Ensure the text fragment anchor matching only occurs after the page becomes
// visible.
TEST_F(TextFragmentAnchorTest, PageVisibility) {
  WebView().SetVisibilityState(mojom::blink::PageVisibilityState::kHidden,
                               /*initial_state=*/true);
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
    <p id="text">This is a test page</p>
  )HTML");
  test::RunPendingTasks();

  // Render two frames and ensure matching and scrolling does not occur.
  BeginEmptyFrame();
  BeginEmptyFrame();

  Element& p = *GetDocument().getElementById(AtomicString("text"));
  EXPECT_FALSE(ViewportRect().Contains(BoundingRectInFrame(p)));
  EXPECT_EQ(0u, GetDocument().Markers().Markers().size());
  EXPECT_EQ(nullptr, GetDocument().CssTarget());

  // Set the page visible and verify the match.
  WebView().SetVisibilityState(mojom::blink::PageVisibilityState::kVisible,
                               /*initial_state=*/false);
  BeginEmptyFrame();
  BeginEmptyFrame();

  EXPECT_TRUE(ViewportRect().Contains(BoundingRectInFra
```