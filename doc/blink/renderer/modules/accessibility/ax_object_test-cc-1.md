Response:
The user wants to understand the functionality of the provided C++ code snippet from `ax_object_test.cc`. This file seems to contain unit tests for accessibility features in the Chromium Blink engine.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core purpose:** The filename `ax_object_test.cc` strongly suggests that this code is testing accessibility-related functionalities. The tests use the `AccessibilityTest` fixture, further confirming this.

2. **Analyze individual tests:** Go through each `TEST_F` block and determine what specific aspect of accessibility it's verifying. Look for patterns in the HTML setup and the `EXPECT_*` assertions.

3. **Relate to web technologies (JavaScript, HTML, CSS):**  Consider how the tested accessibility features interact with these core web technologies. For example, URL extraction relates to HTML `<a>` and `<img>` tags. Line breaking relates to CSS `display` and `white-space` properties. ARIA attributes directly influence accessibility.

4. **Look for logic and assumptions:**  Identify any conditional logic within the tests. Think about what inputs would lead to the observed outputs. For example, testing `NextOnLine` makes assumptions about the layout of elements on the same line.

5. **Consider user/developer errors:** Based on the tested scenarios, think about common mistakes developers might make that these tests are designed to catch. For instance, forgetting to set a URL for a link, or misusing ARIA attributes.

6. **Trace user actions:**  Imagine a user interacting with a webpage and how that interaction might trigger the code being tested. For example, clicking on a link, navigating with a screen reader, or interacting with form controls.

7. **Synthesize a summary:**  Combine the findings from the individual tests into a concise overview of the file's overall purpose.

**Detailed analysis of each test block:**

* **`AxNodeObjectContainsAnchorElementUrl` and `AxNodeObjectContainsSvgAnchorElementUrl`:** These tests check if the `AXObject` representing an anchor (`<a>`) element correctly extracts its URL, both in standard HTML and within an SVG context. This is directly related to HTML `<a>` tags and their `href` attribute.

* **`AxNodeObjectContainsImageUrl`:** Similar to the anchor tests, this verifies URL extraction for `<img>` elements. Related to HTML `<img>` tags and their `src` attribute.

* **`AxNodeObjectContainsInPageLinkTarget` and `AxNodeObjectInPageLinkTargetNonAscii`:** These tests focus on in-page links (using `#`). They verify that the `AXObject` correctly identifies the target element and extracts the full URL, including the hash. The "NonAscii" test specifically handles non-ASCII characters in the target ID, showcasing URL encoding considerations. Related to HTML `<a>` tags and the `href` attribute with fragment identifiers.

* **`NextOnLine` and `NextOnLineInlineBlock`:** These tests examine how accessibility objects determine the "next" element on the same line. This is crucial for screen reader navigation. It's tied to the visual layout of elements, influenced by CSS `display` properties (inline, inline-block).

* **`NextAndPreviousOnLineInert` and `NextOnLineAriaHidden`:** These tests demonstrate how `inert` and `aria-hidden` attributes affect the "next on line" calculation. Inert elements and elements hidden from assistive technology should be skipped. Directly related to the `inert` HTML attribute and the `aria-hidden` ARIA attribute.

* **`TableRowAndCellIsLineBreakingObject`:** This verifies that table rows (`<tr>`) and cells (`<td>`) are considered line-breaking elements for accessibility purposes. Related to HTML `<table>`, `<tr>`, and `<td>` elements.

* **`TestSetRangeValueVideoControlSlider`:** This test simulates setting the value of a video control slider, demonstrating interaction with form elements and ARIA roles. Related to HTML `<video>` elements, their internal controls, and ARIA `role="slider"`.

* **`PreservedWhitespaceWithInitialLineBreakIsLineBreakingObject`:** This tests how whitespace and line breaks are handled within elements with `white-space: pre-line`. It ensures that line breaks are correctly identified as paragraph boundaries for accessibility. Related to CSS `white-space: pre-line`.

* **`DivWithFirstLetterIsLineBreakingObject`:** This checks if a `<div>` element with a `::first-letter` pseudo-element is considered line-breaking. Related to CSS pseudo-elements.

* **`SlotIsLineBreakingObject`:** This test verifies line-breaking behavior within Shadow DOM slots, important for component-based web development. Related to Shadow DOM and `<slot>` elements.

* **`LineBreakInDisplayLockedIsLineBreakingObject`:** This tests how line breaks (`<br>`) are handled within elements that are "display locked" (optimized for offscreen rendering). Related to the browser's rendering optimizations and HTML `<br>` elements.

* **`ListMarkerIsNotLineBreakingObject`:** This confirms that list markers (the bullets or numbers in lists) are *not* treated as line-breaking objects. Related to HTML `<ul>`, `<ol>`, and `<li>` elements, and CSS list markers.

* **`CheckNoDuplicateChildren`:** This test seems to address a bug where accessibility trees might have duplicate children in certain scenarios (like with `<select>` elements). It's more of an internal consistency check.

* **`InitRelationCacheLabelFor` and `InitRelationCacheAriaOwns`:** These tests check the initialization of the accessibility relation cache, specifically for `label for` and `aria-owns` attributes when accessibility is enabled *after* the page has loaded. Related to HTML `<label>` and `<input>` elements, and the ARIA `aria-owns` attribute.

* **`IsSelectedFromFocusSupported`:** This tests a specific condition where an element can be considered "selected" based on focus support, often in complex widgets like comboboxes. Related to ARIA roles like `combobox`, `listbox`, and `option`.

* **`GetBoundsInFrameCoordinatesSvgText`:** This verifies that the bounding box calculations for SVG text elements are correct and respect positioning attributes. Related to SVG `<text>` elements and their attributes.

* **`ComputeIsInertReason` and `ComputeIsInertWithNonHTMLElements`:** These tests explore how the `inert` attribute affects the accessibility tree and how the browser determines the reason why an element is considered inert. The latter test specifically looks at non-HTML elements within an inert subtree. Related to the HTML `inert` attribute.

* **`CanSetFocusInCanvasFallbackContent`:** This test checks if elements within the fallback content of a `<canvas>` element can be focusable, depending on their attributes and whether they are hidden or inert. Related to HTML `<canvas>` elements and their fallback content.

* **`ScrollerFocusability`:** This test seems incomplete, but the intention is likely to verify the focusability of scrollable elements. Related to CSS `overflow` and scrollable containers.

By following these steps, a comprehensive and accurate answer can be constructed. The decomposed thoughts help ensure all aspects of the request are addressed.
这是名为 `ax_object_test.cc` 的 Chromium Blink 引擎源代码文件的第二部分，主要功能是 **测试 `AXObject` 类的一些核心功能，特别是与 URL 获取、行内元素定位、以及元素是否为行分隔对象相关的特性。** 这些特性对于辅助技术（如屏幕阅读器）理解和呈现网页内容至关重要。

**归纳其功能：**

这部分测试着重于验证 `AXObject` 对象是否能正确地：

* **提取各种元素的 URL：** 包括普通 `<a>` 链接、SVG 中的 `<a>` 链接、`<img>` 图片以及页面内部链接。
* **确定同一行内的下一个和上一个 `AXObject`：** 这对于屏幕阅读器等工具按行导航至关重要，并考虑了 `inline-block` 元素、`inert` 属性和 `aria-hidden` 属性的影响。
* **判断元素是否为行分隔对象：**  这有助于辅助技术理解内容的结构，例如表格的行和单元格、带有 `white-space: pre-line` 样式的文本、以及带有 `::first-letter` 伪元素的 `div` 元素等。
* **测试视频控制滑块的值设置：** 模拟用户操作设置滑块的值，并验证 `AXObject` 能正确反映该变化。
* **检查在特定情况下（例如 accessibility 后期初始化）关系缓存的初始化是否正确。**
* **判断元素是否可以通过焦点支持而被选中。**
* **获取 SVG 文本元素的帧内坐标。**
* **计算元素被认为是 `inert` 的原因。**
* **测试 `<canvas>` 元素回退内容中的元素是否可以设置焦点。**

**与 JavaScript, HTML, CSS 的关系及举例说明：**

1. **HTML：**
   * **URL 获取：** 测试从 HTML 元素（如 `<a>` 和 `<img>`）中提取 `href` 和 `src` 属性的值。
     * **假设输入 HTML：** `<a id="mylink" href="https://example.com">Click me</a>`
     * **预期输出：** `anchor->Url()` 返回 `KURL("https://example.com")`。
   * **行分隔对象：** 测试 `<table>`、`<tr>`、`<td>` 等 HTML 结构元素是否被识别为行分隔对象。
     * **假设输入 HTML：** `<table><tr><td>Cell 1</td><td>Cell 2</td></tr></table>`
     * **预期结果：** `row->IsLineBreakingObject()` 和 `cell->IsLineBreakingObject()` 均为 `true`。
   * **`inert` 属性：** 测试 `inert` 属性对 `AXObject` 以及其子树的影响。
     * **假设输入 HTML：** `<div id="inertDiv" inert>This is inert</div>`
     * **预期结果：** `div1->ComputeIsInert()` 返回 `true`，且原因是 `kAXInertElement`。

2. **CSS：**
   * **行内元素定位：**  测试 CSS 的 `display` 属性（如 `inline` 和 `inline-block`) 如何影响 `NextOnLine()` 和 `PreviousOnLine()` 的结果。
     * **假设输入 HTML/CSS：** `<span id="span1">a</span><span id="span2">b</span>` (无特殊 CSS)
     * **预期结果：** `span1->NextOnLine()` 返回 `span2` 对应的 `AXObject`。
   * **`white-space: pre-line`：** 测试 CSS 的 `white-space: pre-line` 属性如何影响文本节点是否被认为是行分隔对象。
     * **假设输入 HTML/CSS：** `<span style="white-space: pre-line">Line 1\nLine 2</span>`
     * **预期结果：** 包含换行符的文本节点会被认为是行分隔对象。
   * **`::first-letter` 伪元素：** 测试带有 `::first-letter` 伪元素的元素是否被认为是行分隔对象。
     * **假设输入 HTML/CSS：** `<style>div::first-letter { color: red; }</style><div id="first">First</div>`
     * **预期结果：** `div->IsLineBreakingObject()` 为 `true`。

3. **JavaScript (间接关系)：**
   * **动态内容和 ARIA：** 虽然这段代码本身不直接涉及 JavaScript，但 JavaScript 经常用于动态修改 HTML 结构和 ARIA 属性，这些修改会影响到 `AXObject` 的状态和测试结果。例如，JavaScript 可以动态地设置 `aria-owns` 属性，这些测试会验证在这种情况下 `AXObject` 能否正确处理。
   * **视频控制：** `TestSetRangeValueVideoControlSlider` 模拟了用户与视频控制的交互，这种交互在实际应用中通常是通过 JavaScript 来处理的。

**逻辑推理、假设输入与输出：**

* **`NextOnLine` 测试：**
    * **假设输入 HTML：** `<div><span id="a">A</span><span id="b">B</span></div>`
    * **预期输出：** `GetAXObjectByElementId("a")->NextOnLine()` 会返回 `GetAXObjectByElementId("b")` 对应的 `AXObject`。

* **`AxNodeObjectContainsInPageLinkTarget` 测试：**
    * **假设输入 HTML：** `<a id="link1" href="#target">Link</a><div id="target">Target</div>`
    * **预期输出：** `GetAXObjectByElementId("link1")->InPageLinkTarget()` 会返回 `GetAXObjectByElementId("target")` 对应的 `AXObject`。

**用户或编程常见的使用错误：**

* **忘记为链接或图片设置 `href` 或 `src` 属性：** 测试用例 `AxNodeObjectContainsAnchorElementUrl` 和 `AxNodeObjectContainsImageUrl` 通过断言 `Url().IsEmpty()` 为 `false` 来确保开发者不会犯这个错误。如果 URL 为空，辅助技术将无法正确导航或显示图片。
* **错误地使用 `aria-hidden="true"`：**  `NextOnLineAriaHidden` 测试验证了被 `aria-hidden="true"` 隐藏的元素不会被认为是同一行内的下一个元素。开发者可能错误地隐藏了需要被辅助技术访问的内容。
* **在动态添加内容后，没有触发 accessibility 树的更新：**  `InitRelationCacheLabelFor` 和 `InitRelationCacheAriaOwns` 测试了 accessibility 后期初始化的情况，强调了在动态修改 DOM 结构或 ARIA 属性后，需要确保 accessibility 树能够正确更新，否则可能导致辅助技术无法正确理解页面。
* **错误地假设所有内联元素都在同一行：** `NextOnLineInlineBlock` 测试强调了 `inline-block` 元素的行为，开发者需要理解元素是如何布局的，才能正确预期 `NextOnLine()` 的结果。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户访问一个包含链接、图片、表格等复杂结构的网页。**
2. **用户使用屏幕阅读器等辅助技术进行导航。**
3. **屏幕阅读器会请求 accessibility 树的信息，其中包括 `AXObject` 及其属性。**
4. **为了获取链接的 URL，屏幕阅读器会调用 `AXObject::Url()` 方法。**  测试用例 `AxNodeObjectContainsAnchorElementUrl` 确保了这个方法能正确返回 URL。
5. **为了按行导航，屏幕阅读器会调用 `AXObject::NextOnLine()` 和 `AXObject::PreviousOnLine()` 方法。**  相关的测试用例验证了这些方法的正确性，包括处理 `inert` 和 `aria-hidden` 属性的情况。
6. **如果页面包含视频，用户可能会与时间轴滑块进行交互。** 测试用例 `TestSetRangeValueVideoControlSlider` 模拟了这种交互，确保 accessibility 信息能够正确反映滑块值的变化。
7. **如果 accessibility 功能在页面加载后才被启用，相关的初始化代码会被执行。** `InitRelationCacheLabelFor` 和 `InitRelationCacheAriaOwns` 测试了这种场景，确保关系缓存能正确初始化。

作为调试线索，如果用户在使用辅助技术时遇到以下问题，可以考虑与这些测试相关的代码：

* **屏幕阅读器无法读取链接的 URL。**  检查 `AXObject::Url()` 的实现和相关的测试用例。
* **屏幕阅读器按行导航时跳过了某些元素或导航顺序不正确。**  检查 `AXObject::NextOnLine()` 和 `AXObject::PreviousOnLine()` 的实现以及相关的测试用例，特别是关于 `inert` 和 `aria-hidden` 的处理。
* **屏幕阅读器无法正确识别表格的结构。** 检查 `AXObject::IsLineBreakingObject()` 对于表格行和单元格的判断。
* **与视频控制交互后，屏幕阅读器没有更新进度信息。**  检查与 `AXObject` 和视频控制滑块相关的属性和方法。

总而言之，这部分测试是确保 Chromium Blink 引擎的 accessibility 功能正确实现的关键组成部分，它直接关系到辅助技术用户如何理解和操作网页内容。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_object_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
non-empty first to catch errors in the test itself.
  EXPECT_FALSE(anchor->Url().IsEmpty());
  EXPECT_EQ(anchor->Url(), KURL("http://test.com"));
}

TEST_F(AccessibilityTest, AxNodeObjectContainsSvgAnchorElementUrl) {
  SetBodyInnerHTML(R"HTML(
    <svg>
      <a id="anchor" xlink:href="http://test.com"></a>
    </svg>
  )HTML");

  const AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);
  const AXObject* anchor = GetAXObjectByElementId("anchor");
  ASSERT_NE(nullptr, anchor);

  EXPECT_FALSE(anchor->Url().IsEmpty());
  EXPECT_EQ(anchor->Url(), KURL("http://test.com"));
}

TEST_F(AccessibilityTest, AxNodeObjectContainsImageUrl) {
  SetBodyInnerHTML(R"HTML(<img id="anchor" src="http://test.png" />)HTML");

  const AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);
  const AXObject* anchor = GetAXObjectByElementId("anchor");
  ASSERT_NE(nullptr, anchor);

  EXPECT_FALSE(anchor->Url().IsEmpty());
  EXPECT_EQ(anchor->Url(), KURL("http://test.png"));
}

TEST_F(AccessibilityTest, AxNodeObjectContainsInPageLinkTarget) {
  GetDocument().SetBaseURLOverride(KURL("http://test.com"));
  SetBodyInnerHTML(R"HTML(<a id="anchor" href="#target">link</a>)HTML");

  const AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);
  const AXObject* anchor = GetAXObjectByElementId("anchor");
  ASSERT_NE(nullptr, anchor);

  EXPECT_FALSE(anchor->Url().IsEmpty());
  EXPECT_EQ(anchor->Url(), KURL("http://test.com/#target"));
}

TEST_F(AccessibilityTest, AxNodeObjectInPageLinkTargetNonAscii) {
  GetDocument().SetURL(KURL("http://test.com"));
  // ö is U+00F6 which URI encodes to %C3%B6
  //
  // This file is forced to be UTF-8 by the build system,
  // the uR"" will create char16_t[] of UTF-16,
  // WTF::String will wrap the char16_t* as UTF-16.
  // All this is checked by ensuring a match against u"\u00F6".
  //
  // TODO(1117212): The escaped version currently takes precedence.
  //  <h1 id="%C3%B6">O2</h1>
  SetBodyInnerHTML(
      uR"HTML(
    <a href="#ö" id="anchor">O</a>
    <h1 id="ö">O</h1>"
    <a href="#t%6Fp" id="top_test">top</a>"
    <a href="#" id="empty_test">also top</a>");
  )HTML");

  {
    // anchor
    const AXObject* anchor = GetAXObjectByElementId("anchor");
    ASSERT_NE(nullptr, anchor);

    EXPECT_FALSE(anchor->Url().IsEmpty());
    EXPECT_EQ(anchor->Url(), KURL(u"http://test.com/#\u00F6"));

    const AXObject* target = anchor->InPageLinkTarget();
    ASSERT_NE(nullptr, target);

    auto* targetElement = DynamicTo<Element>(target->GetNode());
    ASSERT_NE(nullptr, target);
    ASSERT_TRUE(targetElement->HasID());
    EXPECT_EQ(targetElement->IdForStyleResolution(), String(u"\u00F6"));
  }

  {
    // top_test
    const AXObject* anchor = GetAXObjectByElementId("top_test");
    ASSERT_NE(nullptr, anchor);

    EXPECT_FALSE(anchor->Url().IsEmpty());
    EXPECT_EQ(anchor->Url(), KURL(u"http://test.com/#t%6Fp"));

    const AXObject* target = anchor->InPageLinkTarget();
    ASSERT_NE(nullptr, target);

    EXPECT_EQ(&GetDocument(), target->GetNode());
  }

  {
    // empty_test
    const AXObject* anchor = GetAXObjectByElementId("empty_test");
    ASSERT_NE(nullptr, anchor);

    EXPECT_FALSE(anchor->Url().IsEmpty());
    EXPECT_EQ(anchor->Url(), KURL(u"http://test.com/#"));

    const AXObject* target = anchor->InPageLinkTarget();
    ASSERT_NE(nullptr, target);

    EXPECT_EQ(&GetDocument(), target->GetNode());
  }
}

TEST_F(AccessibilityTest, NextOnLine) {
  SetBodyInnerHTML(R"HTML(
    <style>
    html {
      font-size: 10px;
    }
    /* TODO(kojii): |NextOnLine| doesn't work for culled-inline.
       Ensure spans are not culled to avoid hitting the case. */
    span {
      background: gray;
    }
    </style>
    <div><span id="span1">a</span><span>b</span></div>
  )HTML");
  const AXObject* span1 = GetAXObjectByElementId("span1");
  ScopedFreezeAXCache freeze(GetAXObjectCache());

  // Force computation of next/previous on line data, since this is not the
  // regular flow.
  GetAXObjectCache().ComputeNodesOnLine(span1->GetLayoutObject());
  ASSERT_NE(nullptr, span1);

  const AXObject* next = span1->NextOnLine();
  ASSERT_NE(nullptr, next);
  EXPECT_EQ("b", next->GetClosestNode()->textContent());
}

TEST_F(AccessibilityTest, NextOnLineInlineBlock) {
  // Note the spans must be in the same line or we could get other unwanted
  // behavior. See https://crbug.com/1511390 for details.
  SetBodyInnerHTML(R"HTML(
    <div contenteditable="true" style="outline: 1px solid;">
        <div>first line</div>
        <span id="this">this line </span><span style="display: inline-block"><span style="display: block;">is</span></span><span> broken.</span>
        <div>last line</div>
    </div>
  )HTML");
  const AXObject* this_object = GetAXObjectByElementId("this");
  ScopedFreezeAXCache freeze(GetAXObjectCache());

  // Force computation of next/previous on line data, since this is not the
  // regular flow.
  GetAXObjectCache().ComputeNodesOnLine(this_object->GetLayoutObject());
  ASSERT_NE(nullptr, this_object);

  const AXObject* next = this_object->NextOnLine();
  ASSERT_NE(nullptr, next);
  EXPECT_EQ("is", next->GetNode()->textContent());

  next = next->NextOnLine();
  ASSERT_NE(nullptr, next);
  EXPECT_EQ(" broken.", next->GetClosestNode()->textContent());

  AXObject* prev = next->PreviousOnLine();
  ASSERT_NE(nullptr, prev);
  EXPECT_EQ("is", prev->GetNode()->textContent());

  prev = prev->PreviousOnLine();
  ASSERT_NE(nullptr, prev);
  EXPECT_EQ("this line ", prev->GetClosestNode()->textContent());
}

TEST_F(AccessibilityTest, NextAndPreviousOnLineInert) {
  // Spans need to be in the same line: see https://crbug.com/1511390.
  SetBodyInnerHTML(R"HTML(
    <div>
    <div>first line</div>
    <span id="span1">go </span><span inert>inert1</span><span inert>inert2</span><span>blue</span>
    <div>last line</div>
    </div>
  )HTML");
  const AXObject* span1 = GetAXObjectByElementId("span1");
  ScopedFreezeAXCache freeze(GetAXObjectCache());

  // Force computation of next/previous on line data, since this is not the
  // regular flow.
  GetAXObjectCache().ComputeNodesOnLine(span1->GetLayoutObject());
  ASSERT_NE(nullptr, span1);
  EXPECT_EQ("go ", span1->GetNode()->textContent());

  const AXObject* next = span1->NextOnLine();
  ASSERT_NE(nullptr, next);
  EXPECT_EQ("blue", next->GetClosestNode()->textContent());

  // Now we go backwards.

  const AXObject* previous = next->PreviousOnLine();
  EXPECT_EQ("go ", previous->GetClosestNode()->textContent());
}

TEST_F(AccessibilityTest, NextOnLineAriaHidden) {
  // Note the spans must be in the same line or we could get other unwanted
  // behavior. See https://crbug.com/1511390 for details.
  SetBodyInnerHTML(R"HTML(
    <div contenteditable="true" style="outline: 1px solid;">
        <div>first line</div>
        <span id="this">this line </span><span aria-hidden="true">is</span><span> broken.</span>
        <div>last line</div>
    </div>
  )HTML");
  const AXObject* this_object = GetAXObjectByElementId("this");
  ScopedFreezeAXCache freeze(GetAXObjectCache());

  // Force computation of next/previous on line data, since this is not the
  // regular flow.
  GetAXObjectCache().ComputeNodesOnLine(this_object->GetLayoutObject());
  ASSERT_NE(nullptr, this_object);

  const AXObject* next = this_object->NextOnLine();
  ASSERT_NE(nullptr, next);
  EXPECT_EQ(" broken.", next->GetClosestNode()->textContent());

  const AXObject* prev = next->PreviousOnLine();
  ASSERT_NE(nullptr, prev);
  EXPECT_EQ("this line ", prev->GetClosestNode()->textContent());
}

TEST_F(AccessibilityTest, TableRowAndCellIsLineBreakingObject) {
  SetBodyInnerHTML(R"HTML(
      <table id="table">
      <caption>Caption</caption>
        <tr id="row">
          <td id="cell">Cell</td>
        </tr>
      </table>
      )HTML");

  const AXObject* table = GetAXObjectByElementId("table");
  ASSERT_NE(nullptr, table);
  ASSERT_EQ(ax::mojom::Role::kTable, table->RoleValue());
  EXPECT_TRUE(table->IsLineBreakingObject());

  const AXObject* row = GetAXObjectByElementId("row");
  ASSERT_NE(nullptr, row);
  ASSERT_EQ(ax::mojom::Role::kRow, row->RoleValue());
  EXPECT_TRUE(row->IsLineBreakingObject());

  const AXObject* cell = GetAXObjectByElementId("cell");
  ASSERT_NE(nullptr, cell);
  ASSERT_EQ(ax::mojom::Role::kCell, cell->RoleValue());
  EXPECT_TRUE(cell->IsLineBreakingObject());
}

TEST_F(AccessibilityTest, TestSetRangeValueVideoControlSlider) {
  SetBodyInnerHTML(R"HTML(
      <body>
        <video id="vid" src="bear.webm"></video>
      </body>
      )HTML");

  AXObject* video = GetAXObjectByElementId("vid");

  Node* video_node = video->GetNode();
  ASSERT_NE(nullptr, video_node);
  auto* video_element = DynamicTo<HTMLMediaElement>(video_node);
  ASSERT_NE(nullptr, video_node);
  Node* timeline_node =
      video_element->GetMediaControls()->TimelineLayoutObject()->GetNode();
  ASSERT_NE(nullptr, timeline_node);
  AXObjectCache* cache = timeline_node->GetDocument().ExistingAXObjectCache();
  ASSERT_NE(nullptr, cache);
  AXObject* video_slider = cache->ObjectFromAXID(timeline_node->GetDomNodeId());

  ASSERT_NE(nullptr, video_slider);
  ASSERT_EQ(video_slider->RoleValue(), ax::mojom::blink::Role::kSlider);

  float value = 0.0f;
  EXPECT_TRUE(video_slider->ValueForRange(&value));
  EXPECT_EQ(0.0f, value);

  std::string value_to_set("1.0");
  ui::AXActionData action_data;
  action_data.action = ax::mojom::Action::kSetValue;
  action_data.value = value_to_set;
  action_data.target_node_id = video_slider->AXObjectID();

  EXPECT_TRUE(video_slider->PerformAction(action_data));

  EXPECT_TRUE(video_slider->ValueForRange(&value));
  EXPECT_EQ(1.0f, value);
}

TEST_F(AccessibilityTest,
       PreservedWhitespaceWithInitialLineBreakIsLineBreakingObject) {
  SetBodyInnerHTML(R"HTML(
      <span style="white-space: pre-line" id="preserved">
        First Paragraph
        Second Paragraph
        Third Paragraph
      </span>)HTML");

  const AXObject* preserved_span = GetAXObjectByElementId("preserved");
  ASSERT_NE(nullptr, preserved_span);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, preserved_span->RoleValue());
  ASSERT_EQ(1, preserved_span->UnignoredChildCount());
  EXPECT_FALSE(preserved_span->IsLineBreakingObject());

  AXObject* preserved_text = preserved_span->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, preserved_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, preserved_text->RoleValue());
  EXPECT_TRUE(preserved_text->IsLineBreakingObject())
      << "This text node starts with a line break character, so it should be a "
         "paragraph boundary.";

  // Expect 7 kInlineTextBox children.
  // 3 lines of text, and 4 newlines including one a the start of the text.
  preserved_text->LoadInlineTextBoxes();
  ASSERT_EQ(7, preserved_text->UnignoredChildCount());
  ASSERT_THAT(preserved_text->UnignoredChildren(),
              Each(SafeMatcherCast<AXObject*>(
                  Property("AXObject::RoleValue()", &AXObject::RoleValue,
                           ax::mojom::Role::kInlineTextBox))));

  ASSERT_EQ(preserved_text->UnignoredChildAt(0)->ComputedName(), "\n");
  EXPECT_TRUE(preserved_text->UnignoredChildAt(0)->IsLineBreakingObject());
  ASSERT_EQ(preserved_text->UnignoredChildAt(1)->ComputedName(),
            "First Paragraph");
  EXPECT_FALSE(preserved_text->UnignoredChildAt(1)->IsLineBreakingObject());
  ASSERT_EQ(preserved_text->UnignoredChildAt(2)->ComputedName(), "\n");
  EXPECT_TRUE(preserved_text->UnignoredChildAt(2)->IsLineBreakingObject());
  ASSERT_EQ(preserved_text->UnignoredChildAt(3)->ComputedName(),
            "Second Paragraph");
  EXPECT_FALSE(preserved_text->UnignoredChildAt(3)->IsLineBreakingObject());
  ASSERT_EQ(preserved_text->UnignoredChildAt(4)->ComputedName(), "\n");
  EXPECT_TRUE(preserved_text->UnignoredChildAt(4)->IsLineBreakingObject());
  ASSERT_EQ(preserved_text->UnignoredChildAt(5)->ComputedName(),
            "Third Paragraph");
  EXPECT_FALSE(preserved_text->UnignoredChildAt(5)->IsLineBreakingObject());
  ASSERT_EQ(preserved_text->UnignoredChildAt(6)->ComputedName(), "\n");
  EXPECT_TRUE(preserved_text->UnignoredChildAt(6)->IsLineBreakingObject());
}

TEST_F(AccessibilityTest, DivWithFirstLetterIsLineBreakingObject) {
  SetBodyInnerHTML(R"HTML(
      <style>div::first-letter { color: "red"; }</style>
      <div id="firstLetter">First letter</div>)HTML");

  const AXObject* div = GetAXObjectByElementId("firstLetter");
  ASSERT_NE(nullptr, div);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, div->RoleValue());
  ASSERT_EQ(1, div->UnignoredChildCount());
  EXPECT_TRUE(div->IsLineBreakingObject());

  AXObject* div_text = div->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, div_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, div_text->RoleValue());
  EXPECT_FALSE(div_text->IsLineBreakingObject());

  div_text->LoadInlineTextBoxes();
  ASSERT_EQ(1, div_text->UnignoredChildCount());
  ASSERT_EQ(ax::mojom::Role::kInlineTextBox,
            div_text->UnignoredChildAt(0)->RoleValue());
  ASSERT_EQ(div_text->UnignoredChildAt(0)->ComputedName(), "First letter");
  EXPECT_FALSE(div_text->UnignoredChildAt(0)->IsLineBreakingObject());
}

TEST_F(AccessibilityTest, SlotIsLineBreakingObject) {
  // Even though a <span>, <b> and <i> element are not line-breaking, a
  // paragraph element in the shadow DOM should be.
  const char* body_content = R"HTML(
      <span id="host">
        <b slot="slot1" id="slot1">slot1</b>
        <i slot="slot2" id="slot2">slot2</i>
      </span>)HTML";
  const char* shadow_content = R"HTML(
      <p><slot name="slot1"></slot></p>
      <p><slot name="slot2"></slot></p>
      )HTML";
  SetBodyContent(body_content);
  ShadowRoot& shadow_root =
      GetElementById("host")->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(String::FromUTF8(shadow_content),
                           ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  const AXObject* host = GetAXObjectByElementId("host");
  ASSERT_NE(nullptr, host);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, host->RoleValue());
  EXPECT_FALSE(host->IsLineBreakingObject());
  EXPECT_TRUE(host->ParentObjectUnignored()->IsLineBreakingObject());

  const AXObject* slot1 = GetAXObjectByElementId("slot1");
  ASSERT_NE(nullptr, slot1);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, slot1->RoleValue());
  EXPECT_FALSE(slot1->IsLineBreakingObject());
  EXPECT_TRUE(slot1->ParentObjectUnignored()->IsLineBreakingObject());

  const AXObject* slot2 = GetAXObjectByElementId("slot2");
  ASSERT_NE(nullptr, slot2);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, slot2->RoleValue());
  EXPECT_FALSE(slot2->IsLineBreakingObject());
  EXPECT_TRUE(slot2->ParentObjectUnignored()->IsLineBreakingObject());
}

TEST_F(AccessibilityTest, LineBreakInDisplayLockedIsLineBreakingObject) {
  SetBodyInnerHTML(R"HTML(
      <div id="spacer"
          style="height: 30000px; contain-intrinsic-size: 1px 30000px;"></div>
      <p id="lockedContainer" style="content-visibility: auto">
        Line 1
        <br id="br" style="content-visibility: hidden">
        Line 2
      </p>
      )HTML");

  const AXObject* paragraph = GetAXObjectByElementId("lockedContainer");
  ASSERT_NE(nullptr, paragraph);
  ASSERT_EQ(ax::mojom::Role::kParagraph, paragraph->RoleValue());
  ASSERT_EQ(3, paragraph->UnignoredChildCount());
  ASSERT_EQ(paragraph->GetNode(),
            DisplayLockUtilities::LockedInclusiveAncestorPreventingPaint(
                *paragraph->GetNode()))
      << "The <p> element should be display locked.";
  EXPECT_TRUE(paragraph->IsLineBreakingObject());

  const AXObject* br = GetAXObjectByElementId("br");
  ASSERT_NE(nullptr, br);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, br->RoleValue())
      << "The <br> child should be display locked and thus have a generic "
         "role.";
  ASSERT_EQ(paragraph->GetNode(),
            DisplayLockUtilities::LockedInclusiveAncestorPreventingPaint(
                *br->GetNode()))
      << "The <br> child should be display locked.";
  EXPECT_TRUE(br->IsLineBreakingObject());
}

TEST_F(AccessibilityTest, ListMarkerIsNotLineBreakingObject) {
  SetBodyInnerHTML(R"HTML(
      <style>
        ul li::marker {
          content: "X";
        }
      </style>
      <ul id="unorderedList">
        <li id="unorderedListItem">.....
          Unordered item 1
        </li>
      </ul>
      <ol id="orderedList">
        <li id="orderedListItem">
          Ordered item 1
        </li>
      </ol>
      )HTML");

  const AXObject* unordered_list = GetAXObjectByElementId("unorderedList");
  ASSERT_NE(nullptr, unordered_list);
  ASSERT_EQ(ax::mojom::Role::kList, unordered_list->RoleValue());
  EXPECT_TRUE(unordered_list->IsLineBreakingObject());

  const AXObject* unordered_list_item =
      GetAXObjectByElementId("unorderedListItem");
  ASSERT_NE(nullptr, unordered_list_item);
  ASSERT_EQ(ax::mojom::Role::kListItem, unordered_list_item->RoleValue());
  EXPECT_TRUE(unordered_list_item->IsLineBreakingObject());

  const AXObject* unordered_list_marker =
      unordered_list_item->UnignoredChildAt(0);
  ASSERT_NE(nullptr, unordered_list_marker);
  ASSERT_EQ(ax::mojom::Role::kListMarker, unordered_list_marker->RoleValue());
  EXPECT_FALSE(unordered_list_marker->IsLineBreakingObject());

  const AXObject* ordered_list = GetAXObjectByElementId("orderedList");
  ASSERT_NE(nullptr, ordered_list);
  ASSERT_EQ(ax::mojom::Role::kList, ordered_list->RoleValue());
  EXPECT_TRUE(ordered_list->IsLineBreakingObject());

  const AXObject* ordered_list_item = GetAXObjectByElementId("orderedListItem");
  ASSERT_NE(nullptr, ordered_list_item);
  ASSERT_EQ(ax::mojom::Role::kListItem, ordered_list_item->RoleValue());
  EXPECT_TRUE(ordered_list_item->IsLineBreakingObject());

  const AXObject* ordered_list_marker = ordered_list_item->UnignoredChildAt(0);
  ASSERT_NE(nullptr, ordered_list_marker);
  ASSERT_EQ(ax::mojom::Role::kListMarker, ordered_list_marker->RoleValue());
  EXPECT_FALSE(ordered_list_marker->IsLineBreakingObject());
}

TEST_F(AccessibilityTest, CheckNoDuplicateChildren) {
  // Clear inline text boxes and refresh the tree.
  ui::AXMode mode(ui::kAXModeComplete);
  mode.set_mode(ui::AXMode::kInlineTextBoxes, false);
  ax_context_->SetAXMode(mode);
  GetAXObjectCache().MarkDocumentDirty();
  GetAXObjectCache().UpdateAXForAllDocuments();

  SetBodyInnerHTML(R"HTML(
     <select id="sel"><option>1</option></select>
    )HTML");

  AXObject* ax_select = GetAXObjectByElementId("sel");
  ax_select->SetNeedsToUpdateChildren();
  GetAXObjectCache().UpdateAXForAllDocuments();

  ASSERT_EQ(
      ax_select->FirstChildIncludingIgnored()->ChildCountIncludingIgnored(), 1);
}

TEST_F(AccessibilityTest, InitRelationCacheLabelFor) {
  // Most other tests already have accessibility initialized
  // first, but we don't want to in this test.
  //
  // Get rid of the AXContext so the AXObjectCache is destroyed.
  ax_context_.reset(nullptr);

  SetBodyInnerHTML(R"HTML(
      <label for="a"></label>
      <input id="a">
      <input id="b">
    )HTML");

  // Now recreate an AXContext, simulating what happens if accessibility
  // is enabled after the document is loaded.
  ax_context_ = std::make_unique<AXContext>(GetDocument(), ui::kAXModeComplete);

  const AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);
  const AXObject* input_a = GetAXObjectByElementId("a");
  ASSERT_NE(nullptr, input_a);
  const AXObject* input_b = GetAXObjectByElementId("b");
  ASSERT_NE(nullptr, input_b);
}

TEST_F(AccessibilityTest, InitRelationCacheAriaOwns) {
  // Most other tests already have accessibility initialized
  // first, but we don't want to in this test.
  //
  // Get rid of the AXContext so the AXObjectCache is destroyed.
  ax_context_.reset(nullptr);

  SetBodyInnerHTML(R"HTML(
      <ul id="ul" aria-owns="li"></ul>
      <div role="section" id="div">
        <li id="li"></li>
      </div>
    )HTML");

  // Now recreate an AXContext, simulating what happens if accessibility
  // is enabled after the document is loaded.
  ax_context_ = std::make_unique<AXContext>(GetDocument(), ui::kAXModeComplete);

  const AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);

  // Note: retrieve the LI first and check that its parent is not
  // the paragraph element. If we were to retrieve the UL element,
  // that would trigger the aria-owns check and wouln't allow us to
  // test whether the relation cache was initialized.
  const AXObject* li = GetAXObjectByElementId("li");
  ASSERT_NE(nullptr, li);

  const AXObject* div = GetAXObjectByElementId("div");
  ASSERT_NE(nullptr, div);
  EXPECT_NE(li->ParentObjectUnignored(), div);

  const AXObject* ul = GetAXObjectByElementId("ul");
  ASSERT_NE(nullptr, ul);

  EXPECT_EQ(li->ParentObjectUnignored(), ul);
}

TEST_F(AccessibilityTest, IsSelectedFromFocusSupported) {
  SetBodyInnerHTML(R"HTML(
      <input role="combobox" type="search" aria-expanded="true"
              aria-haspopup="true" aria-autocomplete="list1" aria-owns="list1">
      <ul id="list1" role="listbox">
        <li id="option1" role="option" tabindex="-1">Apple</li>
      </ul>
      <input role="combobox" type="search" aria-expanded="true"
              aria-haspopup="true" aria-autocomplete="list2" aria-owns="list2">
      <ul id="list2" role="listbox">
        <li id="option2" role="row" tabindex="-1">Apple</li>
      </ul>
      <input role="combobox" type="search" aria-expanded="true"
              aria-haspopup="true" aria-autocomplete="list3" aria-owns="list3">
      <ul id="list3" role="listbox">
        <li id="option3" role="option" tabindex="-1"
            aria-selected="false">Apple</li>
      </ul>
      <input role="combobox" type="search" aria-expanded="true"
              aria-haspopup="true" aria-autocomplete="list4" aria-owns="list4">
      <ul id="list4" role="listbox">
        <li id="option4" role="option" tabindex="-1"
            aria-selected="true">Apple</li>
        <li id="option5" role="option" tabindex="-1">Orange</li>
      </ul>
    )HTML");

  const AXObject* option1 = GetAXObjectByElementId("option1");
  ASSERT_NE(option1, nullptr);
  const AXObject* option2 = GetAXObjectByElementId("option2");
  ASSERT_NE(option2, nullptr);
  const AXObject* option3 = GetAXObjectByElementId("option3");
  ASSERT_NE(option3, nullptr);
  const AXObject* option4 = GetAXObjectByElementId("option4");
  ASSERT_NE(option4, nullptr);
  const AXObject* option5 = GetAXObjectByElementId("option5");
  ASSERT_NE(option5, nullptr);

  EXPECT_TRUE(option1->IsSelectedFromFocusSupported());
  EXPECT_FALSE(option2->IsSelectedFromFocusSupported());
  EXPECT_FALSE(option3->IsSelectedFromFocusSupported());
  EXPECT_FALSE(option4->IsSelectedFromFocusSupported());
  EXPECT_FALSE(option5->IsSelectedFromFocusSupported());
}

TEST_F(AccessibilityTest, GetBoundsInFrameCoordinatesSvgText) {
  SetBodyInnerHTML(R"HTML(
  <svg width="800" height="600" xmlns="http://www.w3.org/2000/svg">
    <text id="t1" x="100">Text1</text>
    <text id="t2" x="50">Text1</text>
  </svg>)HTML");

  AXObject* text1 = GetAXObjectByElementId("t1");
  ASSERT_NE(text1, nullptr);
  AXObject* text2 = GetAXObjectByElementId("t2");
  ASSERT_NE(text2, nullptr);
  PhysicalRect bounds1 = text1->GetBoundsInFrameCoordinates();
  PhysicalRect bounds2 = text2->GetBoundsInFrameCoordinates();

  // Check if bounding boxes for SVG <text> respect to positioning
  // attributes such as 'x'.
  EXPECT_GT(bounds1.X(), bounds2.X());
}

TEST_F(AccessibilityTest, ComputeIsInertReason) {
  NonThrowableExceptionState exception_state;
  SetBodyInnerHTML(R"HTML(
    <div id="div1" inert>inert</div>
    <dialog id="dialog1">dialog</dialog>
    <dialog id="dialog2" inert>inert dialog</dialog>
    <p id="p1">fullscreen</p>
    <p id="p2" inert>inert fullscreen</p>
  )HTML");

  Document& document = GetDocument();
  Element* body = document.body();
  Element* div1 = GetElementById("div1");
  Node* div1_text = div1->firstChild();
  auto* dialog1 = To<HTMLDialogElement>(GetElementById("dialog1"));
  Node* dialog1_text = dialog1->firstChild();
  auto* dialog2 = To<HTMLDialogElement>(GetElementById("dialog2"));
  Node* dialog2_text = dialog2->firstChild();
  Element* p1 = GetElementById("p1");
  Node* p1_text = p1->firstChild();
  Element* p2 = GetElementById("p2");
  Node* p2_text = p2->firstChild();

  auto AssertInertReasons = [&](Node* node, AXIgnoredReason expectation) {
    AXObject* object = GetAXObjectCache().Get(node);
    ASSERT_NE(object, nullptr);
    AXObject::IgnoredReasons reasons;
    ASSERT_TRUE(object->ComputeIsInert(&reasons));
    ASSERT_EQ(reasons.size(), 1u);
    ASSERT_EQ(reasons[0].reason, expectation);
  };
  auto AssertNotInert = [&](Node* node) {
    AXObject* object = GetAXObjectCache().Get(node);
    ASSERT_NE(object, nullptr);
    AXObject::IgnoredReasons reasons;
    ASSERT_FALSE(object->ComputeIsInert(&reasons));
    ASSERT_EQ(reasons.size(), 0u);
  };
  auto EnterFullscreen = [&](Element* element) {
    LocalFrame::NotifyUserActivation(
        document.GetFrame(), mojom::UserActivationNotificationType::kTest);
    Fullscreen::RequestFullscreen(*element);
    Fullscreen::DidResolveEnterFullscreenRequest(document, /*granted*/ true);
  };
  auto ExitFullscreen = [&]() {
    Fullscreen::FullyExitFullscreen(document);
    Fullscreen::DidExitFullscreen(document);
  };

  AssertNotInert(body);
  AssertInertReasons(div1, kAXInertElement);
  AssertInertReasons(div1_text, kAXInertSubtree);
  AssertNotInert(dialog1);
  AssertNotInert(dialog1_text);
  AssertInertReasons(dialog2, kAXInertElement);
  AssertInertReasons(dialog2_text, kAXInertSubtree);
  AssertNotInert(p1);
  AssertNotInert(p1_text);
  AssertInertReasons(p2, kAXInertElement);
  AssertInertReasons(p2_text, kAXInertSubtree);

  dialog1->showModal(exception_state);

  AssertInertReasons(body, kAXActiveModalDialog);
  AssertInertReasons(div1, kAXInertElement);
  AssertInertReasons(div1_text, kAXInertSubtree);
  AssertNotInert(dialog1);
  AssertNotInert(dialog1_text);
  AssertInertReasons(dialog2, kAXInertElement);
  AssertInertReasons(dialog2_text, kAXInertSubtree);
  AssertInertReasons(p1, kAXActiveModalDialog);
  AssertInertReasons(p1_text, kAXActiveModalDialog);
  AssertInertReasons(p2, kAXInertElement);
  AssertInertReasons(p2_text, kAXInertSubtree);

  dialog2->showModal(exception_state);

  AssertInertReasons(body, kAXActiveModalDialog);
  AssertInertReasons(div1, kAXInertElement);
  AssertInertReasons(div1_text, kAXInertSubtree);
  AssertInertReasons(dialog1, kAXActiveModalDialog);
  AssertInertReasons(dialog1_text, kAXActiveModalDialog);
  AssertInertReasons(dialog2, kAXInertElement);
  AssertInertReasons(dialog2_text, kAXInertSubtree);
  AssertInertReasons(p1, kAXActiveModalDialog);
  AssertInertReasons(p1_text, kAXActiveModalDialog);
  AssertInertReasons(p2, kAXInertElement);
  AssertInertReasons(p2_text, kAXInertSubtree);

  EnterFullscreen(p1);

  AssertInertReasons(body, kAXActiveModalDialog);
  AssertInertReasons(div1, kAXInertElement);
  AssertInertReasons(div1_text, kAXInertSubtree);
  AssertInertReasons(dialog1, kAXActiveModalDialog);
  AssertInertReasons(dialog1_text, kAXActiveModalDialog);
  AssertInertReasons(dialog2, kAXInertElement);
  AssertInertReasons(dialog2_text, kAXInertSubtree);
  AssertInertReasons(p1, kAXActiveModalDialog);
  AssertInertReasons(p1_text, kAXActiveModalDialog);
  AssertInertReasons(p2, kAXInertElement);
  AssertInertReasons(p2_text, kAXInertSubtree);

  dialog1->close();
  dialog2->close();

  AssertInertReasons(body, kAXActiveFullscreenElement);
  AssertInertReasons(div1, kAXInertElement);
  AssertInertReasons(div1_text, kAXInertSubtree);
  AssertInertReasons(dialog1, kAXActiveFullscreenElement);
  AssertInertReasons(dialog1_text, kAXActiveFullscreenElement);
  AssertInertReasons(dialog2, kAXInertElement);
  AssertInertReasons(dialog2_text, kAXInertSubtree);
  AssertNotInert(p1);
  AssertNotInert(p1_text);
  AssertInertReasons(p2, kAXInertElement);
  AssertInertReasons(p2_text, kAXInertSubtree);

  ExitFullscreen();
  EnterFullscreen(p2);

  AssertInertReasons(body, kAXActiveFullscreenElement);
  AssertInertReasons(div1, kAXInertElement);
  AssertInertReasons(div1_text, kAXInertSubtree);
  AssertInertReasons(dialog1, kAXActiveFullscreenElement);
  AssertInertReasons(dialog1_text, kAXActiveFullscreenElement);
  AssertInertReasons(dialog2, kAXInertElement);
  AssertInertReasons(dialog2_text, kAXInertSubtree);
  AssertInertReasons(p1, kAXActiveFullscreenElement);
  AssertInertReasons(p1_text, kAXActiveFullscreenElement);
  AssertInertReasons(p2, kAXInertElement);
  AssertInertReasons(p2_text, kAXInertSubtree);

  ExitFullscreen();

  AssertNotInert(body);
  AssertInertReasons(div1, kAXInertElement);
  AssertInertReasons(div1_text, kAXInertSubtree);
  AssertNotInert(dialog1);
  AssertNotInert(dialog1_text);
  AssertInertReasons(dialog2, kAXInertElement);
  AssertInertReasons(dialog2_text, kAXInertSubtree);
  AssertNotInert(p1);
  AssertNotInert(p1_text);
  AssertInertReasons(p2, kAXInertElement);
  AssertInertReasons(p2_text, kAXInertSubtree);
}

TEST_F(AccessibilityTest, ComputeIsInertWithNonHTMLElements) {
  SetBodyInnerHTML(R"HTML(
    <main inert>
      main
      <foo inert>
        foo
        <svg inert>
          foo
          <foreignObject inert>
            foo
            <div inert>
              div
              <math inert>
                div
                <mi inert>
                  div
                  <span inert>
                    span
                  </span>
                </mi>
              </math>
            </div>
          </foreignObject>
        </svg>
      </foo>
    </main>
  )HTML");

  Document& document = GetDocument();
  Element* element = document.QuerySelector(AtomicString("main"));
  while (element) {
    Node* node = element->firstChild();
    AXObject* ax_node = GetAXObjectCache().Get(node);

    // The text indicates the expected inert root, which is the nearest HTML
    // element ancestor with the 'inert' attribute.
    AtomicString selector(node->textContent().Impl());
    Element* inert_root = document.QuerySelector(selector);
    AXObject* ax_inert_root = GetAXObjectCache().Get(inert_root);

    AXObject::IgnoredReasons reasons;
    ASSERT_TRUE(ax_node->ComputeIsInert(&reasons));
    ASSERT_EQ(reasons.size(), 1u);
    ASSERT_EQ(reasons[0].reason, kAXInertSubtree);
    ASSERT_EQ(reasons[0].related_object.Get(), ax_inert_root);

    element = ElementTraversal::FirstChild(*element);
  }
}

TEST_F(AccessibilityTest, CanSetFocusInCanvasFallbackContent) {
  SetBodyInnerHTML(R"HTML(
    <canvas>
      <section>
        <div tabindex="-1" id="div"></div>
        <span tabindex="-1" id="span"></div>
        <a tabindex="-1" id="a"></a>
      </section>
      <section hidden>
        <div tabindex="-1" id="div-hidden"></div>
        <span tabindex="-1" id="span-hidden"></div>
        <a tabindex="-1" id="a-hidden"></a>
      </section>
      <section inert>
        <div tabindex="-1" id="div-inert"></div>
        <span tabindex="-1" id="span-inert"></div>
        <a tabindex="-1" id="a-inert"></a>
      </section>
      <section hidden inert>
        <div tabindex="-1" id="div-hidden-inert"></div>
        <span tabindex="-1" id="span-hidden-inert"></div>
        <a tabindex="-1" id="a-hidden-inert"></a>
      </section>
    </div>
  )HTML");

  // Elements being used as relevant canvas fallback content can be focusable.
  ASSERT_TRUE(GetAXObjectByElementId("div")->CanSetFocusAttribute());
  ASSERT_TRUE(GetAXObjectByElementId("span")->CanSetFocusAttribute());
  ASSERT_TRUE(GetAXObjectByElementId("a")->CanSetFocusAttribute());

  // But they are not focusable if in a display:none subtree...
  ASSERT_FALSE(GetAXObjectByElementId("div-hidden")->CanSetFocusAttribute());
  ASSERT_FALSE(GetAXObjectByElementId("span-hidden")->CanSetFocusAttribute());
  ASSERT_FALSE(GetAXObjectByElementId("a-hidden")->CanSetFocusAttribute());

  // ...nor if inert...
  ASSERT_FALSE(GetAXObjectByElementId("div-inert")->CanSetFocusAttribute());
  ASSERT_FALSE(GetAXObjectByElementId("span-inert")->CanSetFocusAttribute());
  ASSERT_FALSE(GetAXObjectByElementId("a-inert")->CanSetFocusAttribute());

  // ...nor a combination of both.
  ASSERT_FALSE(
      GetAXObjectByElementId("div-hidden-inert")->CanSetFocusAttribute());
  ASSERT_FALSE(
      GetAXObjectByElementId("span-hidden-inert")->CanSetFocusAttribute());
  ASSERT_FALSE(
      GetAXObjectByElementId("a-hidden-inert")->CanSetFocusAttribute());
}

TEST_F(AccessibilityTest, ScrollerFocusability) {
  SetBodyInnerHTML(R"HTML(
    <div id=scroller style="overflow:scroll;height:50px;">
      <div id=content style="
"""


```