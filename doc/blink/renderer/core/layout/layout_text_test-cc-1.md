Response:
The user wants me to summarize the functionality of the provided C++ code snippet. This code snippet is a test file for the `LayoutText` class in the Chromium Blink engine. It tests various aspects of how text is laid out and rendered in the browser.

Here's a breakdown of the functionalities being tested:

1. **Caret positioning and snapping:** Tests how the caret (the text cursor) behaves around whitespace and line breaks.
2. **Absolute positioning of text fragments:**  Verifies the correct calculation of the absolute position and dimensions of text within the layout.
3. **Bounding boxes:**  Checks how the bounding box of text spans across lines and with different styling (like padding and writing modes).
4. **Word break elements:** Examines how `<wbr>` elements (which suggest line break opportunities) are handled in the layout.
5. **Selection rectangles:** Tests the calculation of the visual rectangle representing a text selection, considering factors like line breaks, RTL text, vertical writing modes, and line height.
6. **Positioning for a given point:** Tests the ability to determine the correct text position corresponding to a specific point on the screen, especially around line breaks and leading.
7. **Handling of first-letter pseudo-elements:** Checks how the layout handles floating first letters in plain text.
8. **Modifying text content:**  Tests various methods for modifying the text content of a `LayoutText` object, including appending, deleting, inserting, and replacing text. This includes testing the behavior with bidirectional text, control characters, whitespace, and complex characters like emojis.
9. **Performance considerations:** Some tests implicitly touch upon performance by examining when layout objects need to be re-created or updated.

Now, let's formulate the summary and address the specific points requested by the user.
This C++ 代码文件 `layout_text_test.cc` 是 Chromium Blink 引擎中 `LayoutText` 类的单元测试，用于验证该类在文本布局方面的各种功能是否正常工作。 `LayoutText` 类负责在渲染过程中处理文本内容的布局。

**主要功能归纳:**

该测试文件的主要功能是验证 `LayoutText` 类在以下方面的行为：

1. **光标 (Caret) 定位和吸附 (Snapping):**  测试光标在文本中不同位置（例如，空格前后）的定位逻辑是否正确。它检查在空格被折叠和不被折叠的情况下，光标是否能准确地放置在空格的前后。
2. **文本片段的绝对位置 (Absolute Quads):**  测试 `LayoutText` 类计算文本片段在页面上的绝对位置和尺寸是否正确，包括水平和垂直书写模式。
3. **物理行边界框 (Physical Lines Bounding Box):**  测试如何计算文本在不同行中的物理边界框，并考虑各种因素，如内边距 (padding) 和换行。
4. **软换行符 (`<wbr>`) 的处理:** 验证 `LayoutText` 类如何处理 `<wbr>` 元素，这种元素表示一个潜在的换行点。
5. **选区矩形 (Local Selection Rect):**  测试如何计算文本选区的局部矩形，并考虑各种因素，例如换行、从右到左 (RTL) 的文本、垂直书写模式和行高 (line-height)。
6. **给定点的文本位置 (Position For Point At Leading):**  测试给定屏幕上的一个点，如何找到该点对应的文本位置，尤其是在行首 (leading) 的情况下。
7. **首字母伪元素 (First-Letter Pseudo-Element):**  测试当对首字母应用 `float: left` 样式时，文本的布局是否正确。
8. **动态修改文本内容:**  测试通过 `appendData`, `deleteData`, `insertData`, `replaceData` 等方法修改 `LayoutText` 对象的文本内容时，布局是否能正确更新。这包括对双向文本 (Bidi)、控制字符、空格以及包含 Zero-Width Joiner (ZWJ) 的 Emoji 表情的处理。

**与 JavaScript, HTML, CSS 的关系举例说明:**

*   **HTML:**
    *   测试中使用了各种 HTML 结构来创建不同的文本布局场景，例如 `<span>`, `<br>`, `<p>`, `<div>`, `<pre>`, `<wbr>` 等。这些 HTML 元素直接影响 `LayoutText` 对象的内容和结构。
    *   **例子:**  `SetBasicBody("foo<span id=space> </span>bar");`  这行代码创建了一个包含 `<span>` 元素的 HTML 结构，用于测试空格的布局。
*   **CSS:**
    *   测试中使用了 CSS 样式来影响文本的渲染和布局，例如 `font-family`, `font-size`, `line-height`, `white-space`, `writing-mode`, `direction`, `float` 等。这些 CSS 属性会改变 `LayoutText` 对象的布局行为。
    *   **例子:**
        *   `InsertStyleElement("body { margin: 0 } div { font: 10px/1 Ahem; width: 5em; } }</style>");`  设置了 `div` 元素的字体和宽度，影响了文本的绝对位置计算。
        *   `InsertStyleElement("#target { white-space:pre-wrap; }");`  设置了 `white-space` 属性，影响了空格和换行的处理方式。
*   **JavaScript:**
    *   虽然这个测试文件是 C++ 代码，但它模拟了 JavaScript 对 DOM 进行操作，并观察 `LayoutText` 对象的行为。例如，测试 `appendData` 和 `deleteData` 方法就模拟了 JavaScript 中对文本节点进行修改的操作。
    *   **隐式关系:** 当 JavaScript 修改 DOM 结构或文本内容时，Blink 引擎会重新计算布局。这个测试文件验证了在这些情况下 `LayoutText` 类的行为是否符合预期。

**逻辑推理的假设输入与输出举例:**

*   **假设输入 (针对空格折叠测试):**
    *   HTML: `"foo<span id=space> </span>bar"`
    *   CSS: 默认的空格处理规则 (可能折叠空格)
    *   光标位置: `"| "` (在 `<span>` 元素后的空格前) 和 `" |"` (在 `<span>` 元素后的空格后)
*   **预期输出:**
    *   `EXPECT_EQ("BC-", GetSnapCode("space", "| "));`  (B 表示在前面，C 表示在内容中，- 表示在后面；这里表示光标可以放在空格前面)
    *   `EXPECT_EQ("-CA", GetSnapCode("space", " |"));`  (这里表示光标可以放在空格后面)

    *   **变化输入 (针对空格不折叠测试):**
        *   HTML: `"foo <span id=space> </span>bar"` (`<span>` 前后都有空格)
        *   CSS: 默认的空格处理规则
        *   光标位置: `"| "` 和 `" |"`
    *   **预期输出:**
        *   `EXPECT_EQ("---", GetSnapCode("space", "| "));` (空格被折叠，光标无法吸附)
        *   `EXPECT_EQ("---", GetSnapCode("space", " |"));` (空格被折叠，光标无法吸附)

**涉及用户或编程常见的使用错误举例:**

*   **错误地假设空格总是可见的:**  用户可能期望在 HTML 中输入的多个空格在页面上都会显示出来，但 CSS 的默认行为是折叠连续的空格。这个测试中的一些用例就验证了 `LayoutText` 类在处理空格折叠时的行为，提醒开发者需要了解 CSS 的 `white-space` 属性来控制空格的显示。
*   **不理解不同书写模式对布局的影响:**  开发者可能在处理垂直书写模式或 RTL 文本时，错误地假设文本的布局方式与水平 LTR 模式相同。测试文件中关于 `AbsoluteQuadsVRL`, `LocalSelectionRectRTL`, `LocalSelectionRectVertical` 等的用例，强调了 `LayoutText` 类对不同书写模式的支持，并帮助开发者避免相关的布局错误。
*   **动态修改文本后未正确更新布局:**  在 JavaScript 中动态修改文本内容后，开发者需要确保浏览器能够正确地重新计算布局。测试文件中关于 `SetTextWithOffsetAppend`, `SetTextWithOffsetDelete`, `SetTextWithOffsetInsert`, `SetTextWithOffsetReplace` 等的用例，验证了 `LayoutText` 类在文本内容发生变化时，能否正确地更新其内部状态和布局信息。如果 `LayoutText` 类的实现有缺陷，可能会导致页面显示不同步或渲染错误。

**总结 `layout_text_test.cc` 的功能 (作为第 2 部分):**

作为测试套件的一部分，`layout_text_test.cc` 的主要功能是**全面地验证 `LayoutText` 类的正确性和健壮性**。它通过创建各种复杂的文本布局场景，并针对 `LayoutText` 类的核心功能进行细致的测试，确保该类能够准确地处理各种文本布局需求，并为 Chromium 浏览器的正确渲染提供基础保障。这些测试覆盖了文本的定位、选区、换行、不同书写模式以及动态修改等多个关键方面，旨在尽早发现并修复潜在的 bug，从而提升浏览器的稳定性和用户体验。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_text_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
xt node
  SetBasicBody("foo<span id=space> </span>bar");
  EXPECT_EQ("BC-", GetSnapCode("space", "| "));
  EXPECT_EQ("-CA", GetSnapCode("space", " |"));

  // Collapsed whitespace text node
  SetBasicBody("foo <span id=space> </span>bar");
  EXPECT_EQ("---", GetSnapCode("space", "| "));
  EXPECT_EQ("---", GetSnapCode("space", " |"));
}

TEST_F(LayoutTextTest, IsBeforeAfterNonCollapsedLineWrapSpace) {
  LoadAhem();

  // Note: Because we can place a caret before soft line wrap, "ab| cd",
  // |GetSnapCode()| should return "BC-" for both NG and legacy.

  // Line wrapping inside node
  SetAhemBody("ab  cd", 2);
  // text_content = "ab cd"
  // [0] I DOM:0-3 TC:0-3 "ab "
  // [1] C DOM:3-4 TC:3-3 " "
  // [2] I DOM:4-6 TC:3-5 "cd"
  EXPECT_EQ("BC-", GetSnapCode("|ab  cd"));
  EXPECT_EQ("BCA", GetSnapCode("a|b  cd"));
  EXPECT_EQ("BCA", GetSnapCode("ab|  cd"));
  // After soft line wrap.
  EXPECT_EQ("-CA", GetSnapCode("ab | cd"));
  EXPECT_EQ("BC-", GetSnapCode("ab  |cd"));
  EXPECT_EQ("BCA", GetSnapCode("ab  c|d"));
  EXPECT_EQ("-CA", GetSnapCode("ab  cd|"));

  // Line wrapping at node start
  // text_content = "xx"
  // [0] I DOM:0-2 TC:0-2 "xx"
  // [1] I DOM:0-1 TC:2-3 " "
  // [2] C DOM:1-2 TC:3-3 " "
  // [3] I DOM:2-3 TC:3-5 "xx"
  SetAhemBody("ab<span id=span>  cd</span>", 2);
  // Before soft line wrap.
  EXPECT_EQ("BC-", GetSnapCode("span", "|  cd"));
  // After soft line wrap.
  EXPECT_EQ("-CA", GetSnapCode("span", " | cd"));
  EXPECT_EQ("BC-", GetSnapCode("span", "  |cd"));
  EXPECT_EQ("BCA", GetSnapCode("span", "  c|d"));
  EXPECT_EQ("-CA", GetSnapCode("span", "  cd|"));

  // Line wrapping at node end
  SetAhemBody("ab  <span>cd</span>", 2);
  // text_content = "ab cd"
  // [0] I DOM:0-3 TC:0-3 "ab "
  // [1] C DOM:3-4 TC:3-3 " "
  // [2] I DOM:0-2 TC:3-5 "cd"
  EXPECT_EQ("BC-", GetSnapCode("|ab "));
  EXPECT_EQ("BCA", GetSnapCode("a|b "));
  // Before soft line wrap.
  EXPECT_EQ("BCA", GetSnapCode("ab|  "));
  // After soft line wrap.
  EXPECT_EQ("-CA", GetSnapCode("ab | "));
  EXPECT_EQ("---", GetSnapCode("ab  |"));

  // Entire node as line wrapping
  SetAhemBody("ab<span id=space>  </span>cd", 2);
  // text_content = "ab cd"
  // [0] I DOM:0-2 TC:0-2 "ab"
  // [1] I DOM:0-1 TC:2-3 " "
  // [2] C DOM:1-2 TC:3-3 " "
  // [3] I DOM:0-2 TC:3-5 "cd"

  // Before soft line wrap.
  EXPECT_EQ("BC-", GetSnapCode("space", "|  "));
  // After soft line wrap.
  EXPECT_EQ("-CA", GetSnapCode("space", " | "));
  EXPECT_EQ("---", GetSnapCode("space", "  |"));
}

TEST_F(LayoutTextTest, IsBeforeAfterNonCollapsedCharacterBR) {
  SetBasicBody("<br>");
  EXPECT_EQ("BC-", GetSnapCode(*GetBasicText(), 0));
  EXPECT_EQ("--A", GetSnapCode(*GetBasicText(), 1));
}

TEST_F(LayoutTextTest, AbsoluteQuads) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
    body { margin: 0 }
    div {
      font: 10px/1 Ahem;
      width: 5em;
    }
    </style>
    <div>012<span id=target>345 67</span></div>
  )HTML");
  LayoutText* layout_text = GetLayoutTextById("target");
  Vector<gfx::QuadF> quads;
  layout_text->AbsoluteQuads(quads);
  EXPECT_THAT(quads,
              testing::ElementsAre(gfx::QuadF(gfx::RectF(30, 0, 30, 10)),
                                   gfx::QuadF(gfx::RectF(0, 10, 20, 10))));
}

TEST_F(LayoutTextTest, AbsoluteQuadsVRL) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
    body { margin: 0 }
    div {
      font: 10px/1 Ahem;
      width: 10em;
      height: 5em;
      writing-mode: vertical-rl;
    }
    </style>
    <div>012<span id=target>345 67</span></div>
  )HTML");
  LayoutText* layout_text = GetLayoutTextById("target");
  Vector<gfx::QuadF> quads;
  layout_text->AbsoluteQuads(quads);
  EXPECT_THAT(quads,
              testing::ElementsAre(gfx::QuadF(gfx::RectF(90, 30, 10, 30)),
                                   gfx::QuadF(gfx::RectF(80, 0, 10, 20))));
}

TEST_F(LayoutTextTest, PhysicalLinesBoundingBox) {
  LoadAhem();
  SetBasicBody(
      "<style>"
      "div {"
      "  font-family:Ahem;"
      "  font-size: 13px;"
      "  line-height: 19px;"
      "  padding: 3px;"
      "}"
      "</style>"
      "<div id=div>"
      "  012"
      "  <span id=one>345</span>"
      "  <br>"
      "  <span style='padding: 20px'>"
      "    <span id=two style='padding: 5px'>678</span>"
      "  </span>"
      "</div>");
  // Layout NG Physical Fragment Tree
  // Box offset:3,3 size:778x44
  //   LineBox offset:3,3 size:91x19
  //     Text offset:0,3 size:52x13 start: 0 end: 4
  //     Box offset:52,3 size:39x13
  //       Text offset:0,0 size:39x13 start: 4 end: 7
  //       Text offset:91,3 size:0x13 start: 7 end: 8
  //   LineBox offset:3,22 size:89x19
  //     Box offset:0,-17 size:89x53
  //       Box offset:20,15 size:49x23
  //         Text offset:5,5 size:39x13 start: 8 end: 11
  const Element& div = *GetElementById("div");
  const Element& one = *GetElementById("one");
  const Element& two = *GetElementById("two");
  EXPECT_EQ(PhysicalRect(3, 6, 52, 13),
            To<LayoutText>(div.firstChild()->GetLayoutObject())
                ->PhysicalLinesBoundingBox());
  EXPECT_EQ(PhysicalRect(55, 6, 39, 13),
            To<LayoutText>(one.firstChild()->GetLayoutObject())
                ->PhysicalLinesBoundingBox());
  EXPECT_EQ(PhysicalRect(28, 25, 39, 13),
            To<LayoutText>(two.firstChild()->GetLayoutObject())
                ->PhysicalLinesBoundingBox());
}

TEST_F(LayoutTextTest, PhysicalLinesBoundingBoxTextCombine) {
  LoadAhem();
  InsertStyleElement(
      "body { font: 100px/130px Ahem; }"
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div>a<c id=target>01234</c>b</div>");
  const auto& target = *GetElementById("target");
  const auto& text_a = *To<Text>(target.previousSibling())->GetLayoutObject();
  const auto& text_01234 = *To<Text>(target.firstChild())->GetLayoutObject();
  const auto& text_b = *To<Text>(target.nextSibling())->GetLayoutObject();

  //   LayoutBlockFlow {HTML} at (0,0) size 800x600
  //     LayoutBlockFlow {BODY} at (8,8) size 784x584
  //       LayoutBlockFlow {DIV} at (0,0) size 130x300
  //         LayoutText {#text} at (15,0) size 100x100
  //           text run at (15,0) width 100: "a"
  //         LayoutInline {C} at (15,100) size 100x100
  //           LayoutTextCombine (anonymous) at (15,100) size 100x100
  //             LayoutText {#text} at (-5,0) size 110x100
  //               text run at (0,0) width 500: "01234"
  //         LayoutText {#text} at (15,200) size 100x100
  //           text run at (15,200) width 100: "b"
  //

  EXPECT_EQ(PhysicalRect(15, 0, 100, 100), text_a.PhysicalLinesBoundingBox());
  // Note: Width 110 comes from |100px * kTextCombineMargin| in
  // |LayoutTextCombine::DesiredWidth()|.
  EXPECT_EQ(PhysicalRect(-5, 0, 110, 100),
            text_01234.PhysicalLinesBoundingBox());
  EXPECT_EQ(PhysicalRect(15, 200, 100, 100), text_b.PhysicalLinesBoundingBox());
}

TEST_F(LayoutTextTest, PhysicalLinesBoundingBoxVerticalRL) {
  LoadAhem();
  SetBasicBody(R"HTML(
    <style>
    div {
      font-family:Ahem;
      font-size: 13px;
      line-height: 19px;
      padding: 3px;
      writing-mode: vertical-rl;
    }
    </style>
    <div id=div>
      012
      <span id=one>345</span>
      <br>
      <span style='padding: 20px'>
        <span id=two style='padding: 5px'>678</span>
      </span>
    </div>
  )HTML");
  // Similar to the previous test, with logical coordinates converted to
  // physical coordinates.
  const Element& div = *GetElementById("div");
  const Element& one = *GetElementById("one");
  const Element& two = *GetElementById("two");
  EXPECT_EQ(PhysicalRect(25, 3, 13, 52),
            To<LayoutText>(div.firstChild()->GetLayoutObject())
                ->PhysicalLinesBoundingBox());
  EXPECT_EQ(PhysicalRect(25, 55, 13, 39),
            To<LayoutText>(one.firstChild()->GetLayoutObject())
                ->PhysicalLinesBoundingBox());
  EXPECT_EQ(PhysicalRect(6, 28, 13, 39),
            To<LayoutText>(two.firstChild()->GetLayoutObject())
                ->PhysicalLinesBoundingBox());
}

TEST_F(LayoutTextTest, WordBreakElement) {
  SetBasicBody("foo <wbr> bar");

  const Element* wbr = GetDocument().QuerySelector(AtomicString("wbr"));
  DCHECK(wbr->GetLayoutObject()->IsText());
  const auto* layout_wbr = To<LayoutText>(wbr->GetLayoutObject());

  EXPECT_EQ(0u, layout_wbr->ResolvedTextLength());
  EXPECT_EQ(0, layout_wbr->CaretMinOffset());
  EXPECT_EQ(0, layout_wbr->CaretMaxOffset());
}

TEST_F(LayoutTextTest, LocalSelectionRect) {
  LoadAhem();
  // TODO(yoichio): Fix LayoutNG incompatibility.
  EXPECT_EQ(PhysicalRect(10, 0, 50, 10), GetSelectionRectFor("f^oo ba|r"));
  EXPECT_EQ(PhysicalRect(0, 0, 40, 20),
            GetSelectionRectFor("<div style='width: 2em'>f^oo ba|r</div>"));
  EXPECT_EQ(PhysicalRect(30, 0, 10, 10),
            GetSelectionRectFor("foo^<br id='target'>|bar"));
  EXPECT_EQ(PhysicalRect(10, 0, 20, 10), GetSelectionRectFor("f^oo<br>b|ar"));
  EXPECT_EQ(PhysicalRect(10, 0, 30, 10),
            GetSelectionRectFor("<div>f^oo</div><div>b|ar</div>"));
  EXPECT_EQ(PhysicalRect(30, 0, 10, 10), GetSelectionRectFor("foo^ |bar"));
  EXPECT_EQ(PhysicalRect(0, 0, 0, 0), GetSelectionRectFor("^ |foo"));
  EXPECT_EQ(PhysicalRect(0, 0, 0, 0),
            GetSelectionRectFor("fo^o<wbr id='target'>ba|r"));
  EXPECT_EQ(
      PhysicalRect(0, 0, 10, 10),
      GetSelectionRectFor("<style>:first-letter { float: right}</style>^fo|o"));
  // Since we don't paint trimed white spaces on LayoutNG,  we don't need fix
  // this case.
  EXPECT_EQ(PhysicalRect(0, 0, 0, 0), GetSelectionRectFor("foo^ |"));
}

TEST_F(LayoutTextTest, LocalSelectionRectLineBreak) {
  LoadAhem();
  EXPECT_EQ(PhysicalRect(30, 0, 10, 10),
            GetSelectionRectFor("f^oo<br id='target'><br>ba|r"));
  EXPECT_EQ(PhysicalRect(0, 10, 10, 10),
            GetSelectionRectFor("f^oo<br><br id='target'>ba|r"));
}

TEST_F(LayoutTextTest, LocalSelectionRectLineBreakPre) {
  LoadAhem();
  EXPECT_EQ(
      PhysicalRect(30, 0, 10, 10),
      GetSelectionRectFor("<div style='white-space:pre;'>foo^\n|\nbar</div>"));
  EXPECT_EQ(
      PhysicalRect(0, 10, 10, 10),
      GetSelectionRectFor("<div style='white-space:pre;'>foo\n^\n|bar</div>"));
}

TEST_F(LayoutTextTest, LocalSelectionRectRTL) {
  LoadAhem();
  // TODO(yoichio) : Fix LastLogicalLeafIgnoringLineBreak so that 'foo' is the
  // last fragment.
  EXPECT_EQ(PhysicalRect(-10, 0, 30, 20),
            GetSelectionRectFor("<div style='width: 2em' dir=rtl>"
                                "f^oo ba|r baz</div>"));
  EXPECT_EQ(PhysicalRect(0, 0, 40, 20),
            GetSelectionRectFor("<div style='width: 2em' dir=ltr>"
                                "f^oo ba|r baz</div>"));
}

TEST_F(LayoutTextTest, LocalSelectionRectVertical) {
  LoadAhem();
  EXPECT_EQ(
      PhysicalRect(0, 0, 20, 40),
      GetSelectionRectFor("<div style='writing-mode: vertical-lr; height: 2em'>"
                          "f^oo ba|r baz</div>"));
  EXPECT_EQ(
      PhysicalRect(10, 0, 20, 40),
      GetSelectionRectFor("<div style='writing-mode: vertical-rl; height: 2em'>"
                          "f^oo ba|r baz</div>"));
}

TEST_F(LayoutTextTest, LocalSelectionRectVerticalRTL) {
  LoadAhem();
  // TODO(yoichio): Investigate diff (maybe soft line break treatment).
  EXPECT_EQ(PhysicalRect(0, -10, 20, 30),
            GetSelectionRectFor(
                "<div style='writing-mode: vertical-lr; height: 2em' dir=rtl>"
                "f^oo ba|r baz</div>"));
  EXPECT_EQ(PhysicalRect(10, -10, 20, 30),
            GetSelectionRectFor(
                "<div style='writing-mode: vertical-rl; height: 2em' dir=rtl>"
                "f^oo ba|r baz</div>"));
}

TEST_F(LayoutTextTest, LocalSelectionRectLineHeight) {
  LoadAhem();
  EXPECT_EQ(PhysicalRect(10, 0, 10, 50),
            GetSelectionRectFor("<div style='line-height: 50px; width:1em;'>"
                                "f^o|o bar baz</div>"));
  EXPECT_EQ(PhysicalRect(10, 50, 10, 50),
            GetSelectionRectFor("<div style='line-height: 50px; width:1em;'>"
                                "foo b^a|r baz</div>"));
  EXPECT_EQ(PhysicalRect(10, 100, 10, 50),
            GetSelectionRectFor("<div style='line-height: 50px; width:1em;'>"
                                "foo bar b^a|</div>"));
}

TEST_F(LayoutTextTest, LocalSelectionRectNegativeLeading) {
  LoadAhem();
  SetSelectionAndUpdateLayoutSelection(R"HTML(
    <div id="container" style="font: 10px/10px Ahem">
      ^
      <span id="span" style="display: inline-block; line-height: 1px">
        Text
      </span>
      |
    </div>
  )HTML");
  LayoutObject* span = GetLayoutObjectByElementId("span");
  LayoutObject* text = span->SlowFirstChild();
  EXPECT_EQ(PhysicalRect(0, -5, 40, 10), text->LocalSelectionVisualRect());
}

TEST_F(LayoutTextTest, LocalSelectionRectLineHeightVertical) {
  LoadAhem();
  EXPECT_EQ(PhysicalRect(0, 10, 50, 10),
            GetSelectionRectFor("<div style='line-height: 50px; height:1em; "
                                "writing-mode:vertical-lr'>"
                                "f^o|o bar baz</div>"));
  EXPECT_EQ(PhysicalRect(50, 10, 50, 10),
            GetSelectionRectFor("<div style='line-height: 50px; height:1em; "
                                "writing-mode:vertical-lr'>"
                                "foo b^a|r baz</div>"));
  EXPECT_EQ(PhysicalRect(100, 10, 50, 10),
            GetSelectionRectFor("<div style='line-height: 50px; height:1em; "
                                "writing-mode:vertical-lr'>"
                                "foo bar b^a|z</div>"));
}

TEST_F(LayoutTextTest, PositionForPointAtLeading) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
    body {
      margin: 0;
      font-size: 10px;
      line-height: 3;
      font-family: Ahem;
    }
    #container {
      width: 5ch;
    }
    </style>
    <div id="container">line1 line2</div>
  )HTML");
  LayoutObject* container = GetLayoutObjectByElementId("container");
  auto* text = To<LayoutText>(container->SlowFirstChild());
  // The 1st line is at {0, 0}x{50,30} and 2nd line is {0,30}x{50,30}, with
  // 10px half-leading, 10px text, and  10px half-leading. {10, 30} is the
  // middle of the two lines, at the half-leading.

  // line 1
  // Note: All |PositionForPoint()| should return "line1"[1].
  EXPECT_EQ(Position(text->GetNode(), 1),
            text->PositionForPoint({10, 0}).GetPosition());
  EXPECT_EQ(Position(text->GetNode(), 1),
            text->PositionForPoint({10, 5}).GetPosition());
  EXPECT_EQ(Position(text->GetNode(), 1),
            text->PositionForPoint({10, 10}).GetPosition());
  EXPECT_EQ(Position(text->GetNode(), 1),
            text->PositionForPoint({10, 15}).GetPosition());
  EXPECT_EQ(Position(text->GetNode(), 1),
            text->PositionForPoint({10, 20}).GetPosition());
  EXPECT_EQ(Position(text->GetNode(), 1),
            text->PositionForPoint({10, 25}).GetPosition());
  // line 2
  EXPECT_EQ(Position(text->GetNode(), 7),
            text->PositionForPoint({10, 30}).GetPosition());
  EXPECT_EQ(Position(text->GetNode(), 7),
            text->PositionForPoint({10, 35}).GetPosition());
  EXPECT_EQ(Position(text->GetNode(), 7),
            text->PositionForPoint({10, 40}).GetPosition());
  EXPECT_EQ(Position(text->GetNode(), 7),
            text->PositionForPoint({10, 45}).GetPosition());
  EXPECT_EQ(Position(text->GetNode(), 7),
            text->PositionForPoint({10, 50}).GetPosition());
  EXPECT_EQ(Position(text->GetNode(), 7),
            text->PositionForPoint({10, 55}).GetPosition());
}

// https://crbug.com/2654312
TEST_F(LayoutTextTest, FloatFirstLetterPlainText) {
  SetBodyInnerHTML(R"HTML(
    <style>
    div::first-letter { float: left; }
    </style>
    <div id="target">Foo</div>
  )HTML");

  LayoutText* text =
      To<LayoutText>(GetElementById("target")->firstChild()->GetLayoutObject());
  EXPECT_EQ("Foo", text->PlainText());
}

TEST_F(LayoutTextTest, SetTextWithOffsetAppendBidi) {
  SetBodyInnerHTML(u"<div dir=rtl id=target>\u05D0\u05D1\u05BC\u05D2</div>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.appendData(u"\u05D0\u05D1\u05BC\u05D2");

  EXPECT_EQ(
      "*{'\u05D0\u05D1\u05BC\u05D2\u05D0\u05D1\u05BC\u05D2', "
      "ShapeResult=0+8 #glyphs=6}\n",
      GetItemsAsString(*text.GetLayoutObject(), 6));
}

TEST_F(LayoutTextTest, SetTextWithOffsetAppendControl) {
  SetBodyInnerHTML(u"<pre id=target>a</pre>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  // Note: "\n" is control character instead of text character.
  text.appendData("\nX");

  EXPECT_EQ(
      "*{'a', ShapeResult=0+1}\n"
      "*{'X', ShapeResult=2+1}\n",
      GetItemsAsString(*text.GetLayoutObject()));
}

TEST_F(LayoutTextTest, SetTextWithOffsetAppendCollapseWhiteSpace) {
  SetBodyInnerHTML(u"<p id=target>abc </p>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.appendData("XYZ");

  EXPECT_EQ("*{'abc XYZ', ShapeResult=0+7}\n",
            GetItemsAsString(*text.GetLayoutObject()));
}

TEST_F(LayoutTextTest, SetTextWithOffsetAppend) {
  SetBodyInnerHTML(u"<pre id=target><a>abc</a>XYZ<b>def</b></pre>");
  Text& text = To<Text>(*GetElementById("target")->firstChild()->nextSibling());
  text.appendData("xyz");

  EXPECT_EQ(
      "{'abc', ShapeResult=0+3}\n"
      "*{'XYZxyz', ShapeResult=3+6}\n"
      "{'def', ShapeResult=9+3}\n",
      GetItemsAsString(*text.GetLayoutObject()));
}

// http://crbug.com/1213235
TEST_F(LayoutTextTest, SetTextWithOffsetAppendEmojiWithZWJ) {
  // Compose "Woman Shrugging"
  //    U+1F937 Shrug (U+D83E U+0xDD37)
  //    U+200D  ZWJ
  //    U+2640  Female Sign
  //    U+FE0F  Variation Selector-16
  SetBodyInnerHTML(
      u"<pre id=target>&#x1F937;</pre>"
      "<p id=checker>&#x1F937;&#x200D;&#x2640;&#xFE0F</p>");

  // Check whether we have "Woman Shrug glyph or not.
  const auto& checker = *To<LayoutText>(
      GetElementById("checker")->firstChild()->GetLayoutObject());
  if (CountNumberOfGlyphs(checker) != 1) {
    return;
  }

  Text& text = To<Text>(*GetElementById("target")->firstChild());
  UpdateAllLifecyclePhasesForTest();
  text.appendData(u"\u200D");
  EXPECT_EQ("*{'\U0001F937\u200D', ShapeResult=0+3 #glyphs=2}\n",
            GetItemsAsString(*text.GetLayoutObject(), 2));

  UpdateAllLifecyclePhasesForTest();
  text.appendData(u"\u2640");
  EXPECT_EQ("*{'\U0001F937\u200D\u2640', ShapeResult=0+4 #glyphs=1}\n",
            GetItemsAsString(*text.GetLayoutObject(), 1));

  UpdateAllLifecyclePhasesForTest();
  text.appendData(u"\uFE0F");
  EXPECT_EQ("*{'\U0001F937\u200D\u2640\uFE0F', ShapeResult=0+5 #glyphs=1}\n",
            GetItemsAsString(*text.GetLayoutObject(), 1));
}

TEST_F(LayoutTextTest, SetTextWithOffsetDelete) {
  SetBodyInnerHTML(u"<pre id=target><a>abc</a>xXYZyz<b>def</b></pre>");
  Text& text = To<Text>(*GetElementById("target")->firstChild()->nextSibling());
  text.deleteData(1, 3, ASSERT_NO_EXCEPTION);

  EXPECT_EQ(
      "{'abc', ShapeResult=0+3}\n"
      "*{'xyz', ShapeResult=3+3}\n"
      "{'def', ShapeResult=6+3}\n",
      GetItemsAsString(*text.GetLayoutObject()));
}

TEST_F(LayoutTextTest, SetTextWithOffsetDeleteCollapseWhiteSpace) {
  SetBodyInnerHTML(u"<p id=target>ab  XY  cd</p>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.deleteData(4, 2, ASSERT_NO_EXCEPTION);  // remove "XY"

  EXPECT_EQ("*{'ab cd', ShapeResult=0+5}\n",
            GetItemsAsString(*text.GetLayoutObject()));
}

TEST_F(LayoutTextTest, SetTextWithOffsetDeleteCollapseWhiteSpaceEnd) {
  SetBodyInnerHTML(u"<p id=target>a bc</p>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.deleteData(2, 2, ASSERT_NO_EXCEPTION);  // remove "bc"

  EXPECT_EQ("*{'a', ShapeResult=0+1}\n",
            GetItemsAsString(*text.GetLayoutObject()));
}

// http://crbug.com/1253931
TEST_F(LayoutTextTest, SetTextWithOffsetCopyItemBefore) {
  SetBodyInnerHTML(u"<p id=target><img> a</p>");

  auto& target = *GetElementById("target");
  const auto& text = *To<Text>(target.lastChild());

  target.appendChild(Text::Create(GetDocument(), "YuGFkVSKiG"));
  UpdateAllLifecyclePhasesForTest();

  // Combine Text nodes "a " and "YuGFkVSKiG".
  target.normalize();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ("*{' aYuGFkVSKiG', ShapeResult=1+12}\n",
            GetItemsAsString(*text.GetLayoutObject()));
}

// web_tests/external/wpt/editing/run/delete.html?993-993
// web_tests/external/wpt/editing/run/forwarddelete.html?1193-1193
TEST_F(LayoutTextTest, SetTextWithOffsetDeleteNbspInPreWrap) {
  InsertStyleElement("#target { white-space:pre-wrap; }");
  SetBodyInnerHTML(u"<p id=target>&nbsp; abc</p>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.deleteData(0, 1, ASSERT_NO_EXCEPTION);

  EXPECT_EQ(
      "*{' ', ShapeResult=0+1}\n"
      "*{'abc', ShapeResult=2+3}\n",
      GetItemsAsString(*text.GetLayoutObject()));
}

TEST_F(LayoutTextTest, SetTextWithOffsetDeleteRTL) {
  SetBodyInnerHTML(u"<p id=target dir=rtl>0 234</p>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.deleteData(2, 2, ASSERT_NO_EXCEPTION);  // remove "23"

  EXPECT_EQ(
      "*{'0', ShapeResult=0+1}\n"
      "*{' ', ShapeResult=1+1}\n"
      "*{'4', ShapeResult=2+1}\n",
      GetItemsAsString(*text.GetLayoutObject()));
}

// http://crbug.com/1000685
TEST_F(LayoutTextTest, SetTextWithOffsetDeleteRTL2) {
  SetBodyInnerHTML(u"<p id=target dir=rtl>0(xy)5</p>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.deleteData(0, 1, ASSERT_NO_EXCEPTION);  // remove "0"

  EXPECT_EQ(
      "*{'(', ShapeResult=0+1}\n"
      "*{'xy', ShapeResult=1+2}\n"
      "*{')', ShapeResult=3+1}\n"
      "*{'5', ShapeResult=4+1}\n",
      GetItemsAsString(*text.GetLayoutObject()));
}

// editing/deleting/delete_ws_fixup.html
TEST_F(LayoutTextTest, SetTextWithOffsetDeleteThenNonCollapse) {
  SetBodyInnerHTML(u"<div id=target>abc def<b> </b>ghi</div>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.deleteData(4, 3, ASSERT_NO_EXCEPTION);  // remove "def"

  EXPECT_EQ(
      "*{'abc ', ShapeResult=0+4}\n"
      "{''}\n"
      "{'ghi', ShapeResult=4+3}\n",
      GetItemsAsString(*text.GetLayoutObject()));
}

// editing/deleting/delete_ws_fixup.html
TEST_F(LayoutTextTest, SetTextWithOffsetDeleteThenNonCollapse2) {
  SetBodyInnerHTML(u"<div id=target>abc def<b> X </b>ghi</div>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.deleteData(4, 3, ASSERT_NO_EXCEPTION);  // remove "def"

  EXPECT_EQ(
      "*{'abc ', ShapeResult=0+4}\n"
      "{'X ', ShapeResult=4+2}\n"
      "{'ghi', ShapeResult=6+3}\n",
      GetItemsAsString(*text.GetLayoutObject()));
}

// http://crbug.com/1039143
TEST_F(LayoutTextTest, SetTextWithOffsetDeleteWithBidiControl) {
  // In text content, we have bidi control codes:
  // U+2066 U+2069 \n U+2066 abc U+2066
  SetBodyInnerHTML(u"<pre><b id=target dir=ltr>\nabc</b></pre>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.deleteData(0, 1, ASSERT_NO_EXCEPTION);  // remove "\n"

  // FirstLetterPseudoElement::FirstLetterLength() change (due to \n removed)
  // makes ShouldUpdateLayoutByReattaching() (in text.cc) return true.
  EXPECT_TRUE(text.GetForceReattachLayoutTree());
}

// http://crbug.com/1125262
TEST_F(LayoutTextTest, SetTextWithOffsetDeleteWithGeneratedBreakOpportunity) {
  InsertStyleElement("#target { white-space:nowrap; }");
  SetBodyInnerHTML(u"<p><b><i id=target>ab\n</i>\n</b>\n</div>");
  // We have two ZWS for "</i>\n" and "</b>\n".
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.deleteData(2, 1, ASSERT_NO_EXCEPTION);  // remove "\n"

  EXPECT_EQ(
      "*{'ab', ShapeResult=0+2}\n"
      "{''}\n"
      "{''}\n",
      GetItemsAsString(*text.GetLayoutObject()));
}

// http://crbug.com/1123251
TEST_F(LayoutTextTest, SetTextWithOffsetEditingTextCollapsedSpace) {
  SetBodyInnerHTML(u"<p id=target></p>");
  // Simulate: insertText("A") + InsertHTML("X ")
  Text& text = *GetDocument().CreateEditingTextNode("AX ");
  GetElementById("target")->appendChild(&text);
  UpdateAllLifecyclePhasesForTest();

  text.replaceData(0, 2, " ", ASSERT_NO_EXCEPTION);

  EXPECT_EQ("*{''}\n", GetItemsAsString(*text.GetLayoutObject()));
}

TEST_F(LayoutTextTest, SetTextWithOffsetInsert) {
  SetBodyInnerHTML(u"<pre id=target><a>abc</a>XYZ<b>def</b></pre>");
  Text& text = To<Text>(*GetElementById("target")->firstChild()->nextSibling());
  text.insertData(1, "xyz", ASSERT_NO_EXCEPTION);

  EXPECT_EQ(
      "{'abc', ShapeResult=0+3}\n"
      "*{'XxyzYZ', ShapeResult=3+6}\n"
      "{'def', ShapeResult=9+3}\n",
      GetItemsAsString(*text.GetLayoutObject()));
}

TEST_F(LayoutTextTest, SetTextWithOffsetInsertAfterSpace) {
  SetBodyInnerHTML(u"<p id=target>ab cd</p>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.insertData(3, " XYZ ", ASSERT_NO_EXCEPTION);

  EXPECT_EQ("*{'ab XYZ cd', ShapeResult=0+9}\n",
            GetItemsAsString(*text.GetLayoutObject()));
}

TEST_F(LayoutTextTest, SetTextWithOffsetInserBeforetSpace) {
  SetBodyInnerHTML(u"<p id=target>ab cd</p>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.insertData(2, " XYZ ", ASSERT_NO_EXCEPTION);

  EXPECT_EQ("*{'ab XYZ cd', ShapeResult=0+9}\n",
            GetItemsAsString(*text.GetLayoutObject()));
}

// https://crbug.com/1391668
TEST_F(LayoutTextTest, SetTextWithOffsetInsertSameCharacters) {
  LoadAhem();
  InsertStyleElement("body { font: 10px/15px Ahem; } b { font-size: 50px; }");
  SetBodyInnerHTML(u"<p><b id=target>a</b>aa</p>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.insertData(0, "aa", ASSERT_NO_EXCEPTION);

  EXPECT_EQ(
      "*{'aaa', ShapeResult=0+3 width=150}\n"
      "{'aa', ShapeResult=3+2 width=20}\n",
      GetItemsAsString(*text.GetLayoutObject(), 0, kIncludeSnappedWidth));
}

TEST_F(LayoutTextTest, SetTextWithOffsetNoRelocation) {
  SetBodyInnerHTML(u"<pre id=target><a>abc</a>XYZ<b>def</b></pre>");
  Text& text = To<Text>(*GetElementById("target")->firstChild()->nextSibling());
  // Note: |CharacterData::setData()| is implementation of Node::setNodeValue()
  // for |CharacterData|.
  text.setData("xyz");

  EXPECT_EQ("LayoutText has NeedsCollectInlines",
            GetItemsAsString(*text.GetLayoutObject()))
      << "There are no optimization for setData()";
}

TEST_F(LayoutTextTest, SetTextWithOffsetPrepend) {
  SetBodyInnerHTML(u"<pre id=target><a>abc</a>XYZ<b>def</b></pre>");
  Text& text = To<Text>(*GetElementById("target")->firstChild()->nextSibling());
  text.insertData(1, "xyz", ASSERT_NO_EXCEPTION);

  EXPECT_EQ(
      "{'abc', ShapeResult=0+3}\n"
      "*{'XxyzYZ', ShapeResult=3+6}\n"
      "{'def', ShapeResult=9+3}\n",
      GetItemsAsString(*text.GetLayoutObject()));
}

TEST_F(LayoutTextTest, SetTextWithOffsetReplace) {
  SetBodyInnerHTML(u"<pre id=target><a>abc</a>XYZW<b>def</b></pre>");
  Text& text = To<Text>(*GetElementById("target")->firstChild()->nextSibling());
  text.replaceData(1, 2, "yz", ASSERT_NO_EXCEPTION);

  EXPECT_EQ(
      "{'abc', ShapeResult=0+3}\n"
      "*{'XyzW', ShapeResult=3+4}\n"
      "{'def', ShapeResult=7+3}\n",
      GetItemsAsString(*text.GetLayoutObject()));
}

TEST_F(LayoutTextTest, SetTextWithOffsetReplaceCollapseWhiteSpace) {
  SetBodyInnerHTML(u"<p id=target>ab  XY  cd</p>");
  Text& text = To<Text>(*GetElementById("target")->firstChild());
  text.replaceData(4, 2, " ", ASSERT_NO_EXCEPTION);  // replace "XY" to " "

  EXPECT_EQ("*{'ab cd', ShapeResult=0+5}\n",
            GetItemsAsString(*text.GetLayoutObject()));
}

TEST_F(LayoutTextTest, SetTextWithOffsetReplaceToExtend) {
  SetBodyInnerHTML(u"<pre id=target><a>abc</a>XYZW<b>def</b></pre>");
  Text& text = To<Text>(*GetElementById("target")->firstChild()->nextSibling());
  text.replaceData(1, 2, "xyz", ASSERT_NO_EXCEPTION);

  EXPECT_EQ(
      "{'abc', ShapeResult=0+3}\n"
      "*{'XxyzW', ShapeResult=3+5}\n"
      "{'def', ShapeResult=8+3}\n",
      GetItemsAsString(*text.GetLayoutObject()));
}

TEST_F(LayoutTextTest, SetTextWithOffsetReplaceToShrink) {
  SetBodyInnerHTML(u"<pre id=target><a>abc</a>XYZW<b>def</b></pre>");
  Text& text = To<Text>(*GetElementById("target")->firstChild()->nextSibling());
  text.replaceData(1, 2, "y", ASSERT_NO_EXCEPTION);

  EXPECT_EQ(
      "{'abc', ShapeResult=0+3}\n"
      "*{'XyW', ShapeResult=3+3}\n"
      "{'def', ShapeResult=6+3}\n",
      GetItemsAsString(*text.GetLayoutObject()));
}

TEST_F(LayoutTextTest, SetTextWithOffsetToEmpty) {
  SetBodyInnerHTML(u"<pre id=target><a>abc</a>XYZ<b>def</b></pre>");
  Text& text = To<Text>(*GetElementById("target")->firstChild()->nextSibling());
  // Note: |CharacterData::setData()| is implementation of Node::setNodeValue()
  // for |CharacterData|.
  // Note: |setData()| detaches layout object from |Text| node since
  // |Text::TextLayoutObjectIsNeeded()| returns false for empty text.
  text.setData("");
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(nullptr, text.GetLayoutObject());
}

}  // namespace blink
```