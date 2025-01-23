Response:
The user wants a summary of the provided C++ code snippet, which is part of a test file for the Blink rendering engine. Specifically, the file `inline_cursor_test.cc` tests the functionality of the `InlineCursor` class.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The filename `inline_cursor_test.cc` and the presence of `TEST_F` macros immediately indicate that this is a unit test file. The `InlineCursorTest` and `InlineCursorBlockFragmentationTest` classes further specify the target of these tests.

2. **Determine the class under test:** The names of the test classes clearly point to the `InlineCursor` class as the primary focus.

3. **Analyze the individual tests:** Go through each `TEST_F` function and understand what it's verifying. Look for patterns and categorize the functionalities being tested. Keywords like `PositionForPointInChild`, `MoveTo`, `Previous`, `Next`, `CursorForDescendants`, and `MoveToVisualFirstOrLast` are good indicators of the tested features.

4. **Relate to web technologies (JavaScript, HTML, CSS):** Consider how the tested functionalities relate to how web pages are rendered and interacted with. For instance, positioning relates to how elements are laid out on the screen, which is influenced by CSS. Cursor movement is essential for text selection and editing, which are user interactions within an HTML document. JavaScript can trigger actions that involve the layout and rendering of elements.

5. **Identify logic and assumptions:** When a test involves specific input and expected output (e.g., testing `PositionForPointInChild` with different offsets), note these down as potential examples of logical reasoning within the tests. The CSS styles applied in the tests are also part of the assumed input for the layout engine.

6. **Look for user/programming errors:** Consider what mistakes a developer or user might make that these tests could potentially catch. While these are *unit tests*, they indirectly guard against errors in the underlying layout logic that could lead to incorrect rendering or unexpected behavior. For example, incorrect cursor positioning could lead to problems with text selection.

7. **Distinguish between the two test classes:** Notice the `InlineCursorTest` and `InlineCursorBlockFragmentationTest`. The latter focuses specifically on how the `InlineCursor` behaves in the context of block fragmentation (e.g., multi-column layouts).

8. **Structure the summary:** Organize the findings into logical sections, such as "Core Functionality," "Relationship to Web Technologies," "Logical Reasoning Examples," and "Potential Errors."

9. **Address the "Part 2" instruction:**  Since this is part 2 of the analysis, focus on summarizing the *specific* functionalities covered in this particular code snippet. The overall purpose was established in part 1, so this should refine and elaborate on the details.

10. **Refine and clarify:** Review the summary for clarity, accuracy, and completeness. Ensure that the examples are relevant and easy to understand. Use precise language to describe the technical concepts involved. For instance, mentioning "text affinity" and "writing modes" provides more detail.

By following these steps, we can create a comprehensive and informative summary of the provided code snippet, as demonstrated in the desired output.这是对`blink/renderer/core/layout/inline/inline_cursor_test.cc` 文件（第二部分）功能的归纳总结。

**总体功能归纳：**

这部分 `inline_cursor_test.cc` 文件主要包含针对 `InlineCursor` 类的单元测试，旨在验证其在各种布局场景下定位和移动光标的能力。重点测试了以下功能：

* **`PositionForPointInChild()` 方法的测试:**  验证了在不同的书写模式（水平LTR、水平RTL、垂直LTR、垂直RTL）下，根据子元素内的指定点位准确返回文本位置的能力，包括正确的文本偏移量和文本亲和性（upstream/downstream）。
* **处理块级子元素:**  测试了当光标移动到包含块级子元素的行内元素时，`PositionForPointInChild()` 方法的行为。
* **光标的向后移动 (`Previous()` 系列方法):**
    * `Previous()`:  测试了光标向前遍历布局树节点的能力，包括文本节点、行盒、行内元素等。
    * `PreviousIncludingFragmentainer()`:  测试了在分栏布局中，光标向前遍历不同列（fragmentainer）的能力。
    * `PreviousInlineLeaf()`: 测试了光标向前跳过非叶子的行内元素，直接定位到行内叶子节点（通常是文本或替换元素）的能力。
    * `PreviousInlineLeafIgnoringLineBreak()`:  类似于 `PreviousInlineLeaf()`，但会忽略换行符节点。
    * `PreviousInlineLeafOnLine()`:  测试了在同一行内向前移动到前一个行内叶子节点的能力。
* **光标在不同行之间的移动 (`PreviousLine()`):** 验证了光标在相邻行之间移动的能力。
* **获取子孙光标 (`CursorForDescendants()`):** 测试了获取一个只遍历当前光标所在布局对象子孙节点的新的 `InlineCursor` 的能力。
* **在视觉顺序上移动 (`MoveToVisualFirstOrLast()`):**  测试了在双向文本（Bidi）环境中，将光标移动到同一布局对象视觉顺序上的第一个或最后一个元素的能力。
* **块级分片场景下的光标移动 (`InlineCursorBlockFragmentationTest`):**  专门针对分栏布局等块级分片场景测试了光标的移动和定位能力，包括：
    * `MoveTo()`: 测试了在分片布局中，光标是否能正确移动到指定的 `LayoutText` 对象的所有分片上。
    * `MoveToIncludingCulledInline()`:  测试了即使行内元素被裁剪（culled），光标仍然可以移动到它的后代节点。
    * 行级光标 (`CursorForDescendants()` on line boxes): 测试了行级光标是否能正确找到当前行内的文本分片。
    * 基于 `PhysicalBoxFragment` 的光标:  测试了基于特定分片容器的光标是否能正确遍历该分片容器内的元素。

**与 JavaScript, HTML, CSS 的关系举例：**

这些测试直接关系到浏览器如何渲染和处理网页内容，特别是文本的布局和用户交互。

* **HTML:**  测试用例中使用了 HTML 结构来创建不同的布局场景，例如 `<p>`, `<div>`, `<b>`, `<br>`, `<bdo>`, `<span>` 等元素，这些元素的嵌套和属性决定了渲染树的结构。
* **CSS:** 测试用例中使用了 CSS 样式来控制元素的布局属性，例如 `direction` (用于 RTL 文本)、`font`、`padding`、`writing-mode` (用于垂直书写模式)、`display: inline-block`、`column-count`、`column-width` 等。这些 CSS 属性直接影响了 `InlineCursor` 需要处理的布局情况。
* **JavaScript:** 虽然这个测试文件本身是 C++ 代码，但 `InlineCursor` 的功能是 JavaScript 中文本选择、光标定位等功能的基础。例如，当用户在网页上点击鼠标时，浏览器需要计算点击位置对应的文本节点和偏移量，这与 `PositionForPointInChild()` 的功能类似。JavaScript 可以通过 DOM API 来获取和操作光标位置，而底层的实现就依赖于像 `InlineCursor` 这样的类。

**逻辑推理的假设输入与输出举例：**

**测试 `PositionForPointInChildHorizontalLTR`:**

* **假设输入:**
    * HTML: `<p id=root>ab</p>`
    * CSS: `p { direction: ltr; font: 10px/20px Ahem; padding: 10px; writing-mode: horizontal-tb; }`
    * 光标已移动到文本节点 "ab" 的布局对象。
    * `left_top` (文本布局对象的左上角偏移量)
    * 一系列相对于 `left_top` 的点坐标，例如 `left_top + PhysicalOffset(5, 0)`。
* **预期输出:**
    * 对于 `left_top + PhysicalOffset(5, 0)`，预期返回 `PositionWithAffinity(Position(text, 0))`，表示光标位于字符 'a' 之后。
    * 对于 `left_top + PhysicalOffset(10, 0)`，预期返回 `PositionWithAffinity(Position(text, 1))`，表示光标位于字符 'b' 之后。
    * 对于 `left_top + PhysicalOffset(20, 0)`，预期返回 `PositionWithAffinity(Position(text, 2), TextAffinity::kUpstream)`，表示光标位于文本末尾之前。

**涉及用户或者编程常见的使用错误举例：**

虽然这些是底层的渲染引擎测试，但它们间接防止了一些可能导致用户或开发者困惑的错误：

* **文本选择错误:** 如果 `PositionForPointInChild()` 的逻辑不正确，用户在网页上拖动鼠标选择文本时，实际选中的文本范围可能会与用户期望的不同。
* **光标定位不准确:** 在富文本编辑器等场景中，JavaScript 代码可能会依赖浏览器的光标定位功能。如果 `InlineCursor` 的移动逻辑有误，会导致光标跳跃或定位到错误的位置。
* **双向文本处理错误:**  如果 RTL 文本的处理逻辑不正确，用户在编辑或选择 RTL 文本时可能会遇到光标移动方向或选择范围与预期相反的问题。

**这部分的功能归纳：**

这部分测试代码专注于 **`InlineCursor` 在各种布局场景下的精细化光标定位和移动能力** 的验证，特别是针对不同书写模式、双向文本以及分栏布局等复杂情况。它确保了浏览器内核能够准确地计算和操作文本光标的位置，这是实现正确的文本渲染、选择和编辑等功能的基础。特别强调了在分片布局中对光标移动的测试，保证了在多列等复杂布局下光标行为的正确性。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/inline_cursor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ion(text, 0)),
            cursor.PositionForPointInChild(left_top));
  EXPECT_EQ(PositionWithAffinity(Position(text, 0)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(5, 0)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 1)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(10, 0)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 1)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(15, 0)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 2), TextAffinity::kUpstream),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(20, 0)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 2), TextAffinity::kUpstream),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(25, 0)));
}

TEST_F(InlineCursorTest, PositionForPointInChildHorizontalRTL) {
  LoadAhem();
  InsertStyleElement(
      "p {"
      "direction: rtl;"
      "font: 10px/20px Ahem;"
      "padding: 10px;"
      "writing-mode: horizontal-tb;"
      "}");
  InlineCursor cursor = SetupCursor("<p id=root><bdo dir=rtl>AB</bdo></p>");
  const auto& text =
      *To<Text>(GetElementById("root")->firstChild()->firstChild());
  ASSERT_TRUE(cursor.Current().IsLineBox());
  EXPECT_EQ(PhysicalRect(PhysicalOffset(754, 10), PhysicalSize(20, 20)),
            cursor.Current().RectInContainerFragment());

  cursor.MoveTo(*text.GetLayoutObject());
  EXPECT_EQ(PhysicalRect(PhysicalOffset(754, 15), PhysicalSize(20, 10)),
            cursor.Current().RectInContainerFragment());
  const PhysicalOffset left_top = cursor.Current().OffsetInContainerFragment();

  EXPECT_EQ(PositionWithAffinity(Position(text, 2), TextAffinity::kUpstream),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(-5, 0)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 2), TextAffinity::kUpstream),
            cursor.PositionForPointInChild(left_top));
  EXPECT_EQ(PositionWithAffinity(Position(text, 2), TextAffinity::kUpstream),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(5, 0)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 1)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(10, 0)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 1)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(15, 0)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 0)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(20, 0)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 0)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(25, 0)));
}

TEST_F(InlineCursorTest, PositionForPointInChildVerticalLTR) {
  LoadAhem();
  InsertStyleElement(
      "p {"
      "direction: ltr;"
      "font: 10px/20px Ahem;"
      "padding: 10px;"
      "writing-mode: vertical-lr;"
      "}");
  InlineCursor cursor = SetupCursor("<p id=root>ab</p>");
  const auto& text = *To<Text>(GetElementById("root")->firstChild());
  ASSERT_TRUE(cursor.Current().IsLineBox());
  EXPECT_EQ(PhysicalRect(PhysicalOffset(10, 10), PhysicalSize(20, 20)),
            cursor.Current().RectInContainerFragment());

  cursor.MoveTo(*text.GetLayoutObject());
  EXPECT_EQ(PhysicalRect(PhysicalOffset(15, 10), PhysicalSize(10, 20)),
            cursor.Current().RectInContainerFragment());
  const PhysicalOffset left_top = cursor.Current().OffsetInContainerFragment();

  EXPECT_EQ(PositionWithAffinity(Position(text, 0)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(0, -5)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 0)),
            cursor.PositionForPointInChild(left_top));
  EXPECT_EQ(PositionWithAffinity(Position(text, 0)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(0, 5)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 1)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(0, 10)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 1)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(0, 15)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 2), TextAffinity::kUpstream),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(0, 20)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 2), TextAffinity::kUpstream),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(0, 25)));
}

TEST_F(InlineCursorTest, PositionForPointInChildVerticalRTL) {
  LoadAhem();
  InsertStyleElement(
      "p {"
      "direction: rtl;"
      "font: 10px/20px Ahem;"
      "padding: 10px;"
      "writing-mode: vertical-rl;"
      "}");
  InlineCursor cursor = SetupCursor("<p id=root><bdo dir=rtl>AB</bdo></p>");
  const auto& text =
      *To<Text>(GetElementById("root")->firstChild()->firstChild());
  ASSERT_TRUE(cursor.Current().IsLineBox());
  EXPECT_EQ(PhysicalRect(PhysicalOffset(10, 10), PhysicalSize(20, 20)),
            cursor.Current().RectInContainerFragment());

  cursor.MoveTo(*text.GetLayoutObject());
  EXPECT_EQ(PhysicalRect(PhysicalOffset(15, 10), PhysicalSize(10, 20)),
            cursor.Current().RectInContainerFragment());
  const PhysicalOffset left_top = cursor.Current().OffsetInContainerFragment();

  EXPECT_EQ(PositionWithAffinity(Position(text, 2), TextAffinity::kUpstream),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(0, -5)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 2), TextAffinity::kUpstream),
            cursor.PositionForPointInChild(left_top));
  EXPECT_EQ(PositionWithAffinity(Position(text, 2), TextAffinity::kUpstream),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(0, 5)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 1)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(0, 10)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 1)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(0, 15)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 0)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(0, 20)));
  EXPECT_EQ(PositionWithAffinity(Position(text, 0)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(0, 25)));
}

// For http://crbug.com/1096110
TEST_F(InlineCursorTest, PositionForPointInChildBlockChildren) {
  InsertStyleElement("b { display: inline-block; }");
  // Note: <b>.ChildrenInline() == false
  InlineCursor cursor =
      SetupCursor("<div id=root>a<b id=target><div>x</div></b></div>");
  const Element& target = *GetElementById("target");
  cursor.MoveTo(*target.GetLayoutObject());
  EXPECT_EQ(PositionWithAffinity(Position::FirstPositionInNode(target)),
            cursor.PositionForPointInChild(PhysicalOffset()));
}

TEST_F(InlineCursorTest, Previous) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("b { background: gray; }");
  InlineCursor cursor = SetupCursor("<div id=root>abc<b>DEF</b><br>xyz</div>");
  cursor.MoveTo(*cursor.GetLayoutBlockFlow()->LastChild());
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToPrevious();
  }
  EXPECT_THAT(list, ElementsAre("xyz", "#linebox", "", "DEF", "LayoutInline B",
                                "abc", "#linebox"));
}

TEST_F(InlineCursorTest, PreviousIncludingFragmentainer) {
  // TDOO(yosin): Remove style for <b> once FragmentItem don't do culled
  // inline.
  LoadAhem();
  InsertStyleElement(
      "b { background: gray; }"
      "div { font: 10px/15px Ahem; column-count: 2; width: 20ch; }");
  SetBodyInnerHTML("<div id=m>abc<br>def<br><b>ghi</b><br>jkl</div>");
  InlineCursor cursor;
  cursor.MoveTo(*GetElementById("m")->lastChild()->GetLayoutObject());
  ASSERT_TRUE(cursor.IsBlockFragmented()) << cursor;
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToPreviousIncludingFragmentainer();
  }
  EXPECT_THAT(list, ElementsAre("jkl", "#linebox", "", "ghi", "LayoutInline B",
                                "#linebox", "", "def", "#linebox", "", "abc",
                                "#linebox"));
}

TEST_F(InlineCursorTest, PreviousInlineLeaf) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("b { background: gray; }");
  InlineCursor cursor = SetupCursor("<div id=root>abc<b>DEF</b><br>xyz</div>");
  cursor.MoveTo(*cursor.GetLayoutBlockFlow()->LastChild());
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToPreviousInlineLeaf();
  }
  EXPECT_THAT(list, ElementsAre("xyz", "", "DEF", "abc"));
}

TEST_F(InlineCursorTest, PreviousInlineLeafIgnoringLineBreak) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("b { background: gray; }");
  InlineCursor cursor = SetupCursor("<div id=root>abc<b>DEF</b><br>xyz</div>");
  cursor.MoveTo(*cursor.GetLayoutBlockFlow()->LastChild());
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToPreviousInlineLeafIgnoringLineBreak();
  }
  EXPECT_THAT(list, ElementsAre("xyz", "DEF", "abc"));
}

TEST_F(InlineCursorTest, PreviousInlineLeafOnLineFromLayoutInline) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("b { background: gray; }");
  InlineCursor cursor = SetupCursor(
      "<div id=root>"
      "<b>abc</b> def<br>"
      "<b>ABC</b> <b id=start>DEF</b><br>"
      "</div>");
  cursor.MoveTo(*GetElementById("start")->GetLayoutObject());
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToPreviousInlineLeafOnLine();
  }
  EXPECT_THAT(list, ElementsAre("#start", "", "ABC"))
      << "We don't have 'DEF' and items in first line.";
}

TEST_F(InlineCursorTest, PreviousInlineLeafOnLineFromNestedLayoutInline) {
  // Never return a descendant for AXLayoutObject::PreviousOnLine().
  // Instead, if PreviousOnLine() is called on a container, return a previpus
  // item from the previous siblings subtree.
  InlineCursor cursor = SetupCursor(
      "<div id=root>"
      "<span>previous</span>"
      "<span id=start>"
      "Test<span style=font-size:13px>descendant</span>"
      "</span>"
      "</div>");
  cursor.MoveToIncludingCulledInline(
      *GetElementById("start")->GetLayoutObject());
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToPreviousInlineLeafOnLine();
  }
  EXPECT_THAT(list, ElementsAre("#start", "previous"))
      << "previous on line doesn't return descendant.";
}

TEST_F(InlineCursorTest, PreviousInlineLeafOnLineFromLayoutText) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("b { background: gray; }");
  InlineCursor cursor = SetupCursor(
      "<div id=root>"
      "<b>abc</b> def<br>"
      "<b>ABC</b> <b id=start>DEF</b><br>"
      "</div>");
  cursor.MoveTo(*GetElementById("start")->firstChild()->GetLayoutObject());
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToPreviousInlineLeafOnLine();
  }
  EXPECT_THAT(list, ElementsAre("DEF", "", "ABC"))
      << "We don't have items in first line.";
}

TEST_F(InlineCursorTest, PreviousLine) {
  InlineCursor cursor = SetupCursor("<div id=root>abc<br>xyz</div>");
  InlineCursor line1(cursor);
  while (line1 && !line1.Current().IsLineBox())
    line1.MoveToNext();
  ASSERT_TRUE(line1.IsNotNull());
  InlineCursor line2(line1);
  line2.MoveToNext();
  while (line2 && !line2.Current().IsLineBox())
    line2.MoveToNext();
  ASSERT_NE(line1, line2);

  InlineCursor should_be_null(line1);
  should_be_null.MoveToPreviousLine();
  EXPECT_TRUE(should_be_null.IsNull());

  InlineCursor should_be_line1(line2);
  should_be_line1.MoveToPreviousLine();
  EXPECT_EQ(line1, should_be_line1);
}

TEST_F(InlineCursorTest, CursorForDescendants) {
  SetBodyInnerHTML(R"HTML(
    <style>
    span { background: yellow; }
    </style>
    <div id=root>
      text1
      <span id="span1">
        text2
        <span id="span2">
          text3
        </span>
        text4
      </span>
      text5
      <span id="span3">
        text6
      </span>
      text7
    </div>
  )HTML");

  LayoutBlockFlow* block_flow =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("root"));
  InlineCursor cursor(*block_flow);
  EXPECT_TRUE(cursor.Current().IsLineBox());
  cursor.MoveToNext();
  EXPECT_TRUE(cursor.Current().IsText());
  EXPECT_THAT(ToDebugStringList(cursor.CursorForDescendants()), ElementsAre());
  cursor.MoveToNext();
  EXPECT_EQ(ToDebugString(cursor), "#span1");
  EXPECT_THAT(ToDebugStringList(cursor.CursorForDescendants()),
              ElementsAre("text2", "#span2", "text3", "text4"));
  cursor.MoveToNext();
  EXPECT_EQ(ToDebugString(cursor), "text2");
  EXPECT_THAT(ToDebugStringList(cursor.CursorForDescendants()), ElementsAre());
  cursor.MoveToNext();
  EXPECT_EQ(ToDebugString(cursor), "#span2");
  EXPECT_THAT(ToDebugStringList(cursor.CursorForDescendants()),
              ElementsAre("text3"));
}

TEST_F(InlineCursorTest, MoveToVisualFirstOrLast) {
  SetBodyInnerHTML(R"HTML(
    <div id=root dir="rtl">
      here is
      <span id="span1">some <bdo dir="rtl">MIXED</bdo></span>
      <bdo dir="rtl">TEXT</bdo>
    </div>
  )HTML");

  //          _here_is_some_MIXED_TEXT_
  // visual:  _TXET_DEXIM_here_is_some_
  // in span:       ______        ____

  InlineCursor cursor1;
  cursor1.MoveToIncludingCulledInline(*GetLayoutObjectByElementId("span1"));
  cursor1.MoveToVisualFirstForSameLayoutObject();
  EXPECT_EQ("FragmentItem Text \"MIXED\"", cursor1.Current()->ToString());

  InlineCursor cursor2;
  cursor2.MoveToIncludingCulledInline(*GetLayoutObjectByElementId("span1"));
  cursor2.MoveToVisualLastForSameLayoutObject();
  EXPECT_EQ("FragmentItem Text \"some\"", cursor2.Current()->ToString());
}

class InlineCursorBlockFragmentationTest : public RenderingTest {};

TEST_F(InlineCursorBlockFragmentationTest, MoveToLayoutObject) {
  // This creates 3 columns, 1 line in each column.
  SetBodyInnerHTML(R"HTML(
    <style>
    #container {
      column-width: 6ch;
      font-family: monospace;
      font-size: 10px;
      height: 1.5em;
    }
    </style>
    <div id="container">
      <span id="span1">1111 22</span><span id="span2">33 4444</span>
    </div>
  )HTML");
  const LayoutObject* span1 = GetLayoutObjectByElementId("span1");
  const LayoutObject* text1 = span1->SlowFirstChild();
  const LayoutObject* span2 = GetLayoutObjectByElementId("span2");
  const LayoutObject* text2 = span2->SlowFirstChild();

  // Enumerate all fragments for |LayoutText|.
  {
    InlineCursor cursor;
    cursor.MoveTo(*text1);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor),
                ElementsAre("1111", "22"));
  }
  {
    InlineCursor cursor;
    cursor.MoveTo(*text2);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor),
                ElementsAre("33", "4444"));
  }
  // |MoveTo| can find no fragments for culled inline.
  {
    InlineCursor cursor;
    cursor.MoveTo(*span1);
    EXPECT_FALSE(cursor);
  }
  {
    InlineCursor cursor;
    cursor.MoveTo(*span2);
    EXPECT_FALSE(cursor);
  }
  // But |MoveToIncludingCulledInline| should find its descendants.
  {
    InlineCursor cursor;
    cursor.MoveToIncludingCulledInline(*span1);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor),
                ElementsAre("1111", "22"));
  }
  {
    InlineCursor cursor;
    cursor.MoveToIncludingCulledInline(*span2);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor),
                ElementsAre("33", "4444"));
  }

  // Line-ranged cursors can find fragments only in the line.
  // The 1st line has "1111", from "text1".
  const LayoutBlockFlow* block_flow = span1->FragmentItemsContainer();
  InlineCursor cursor(*block_flow);
  EXPECT_TRUE(cursor.Current().IsLineBox());
  InlineCursor line1 = cursor.CursorForDescendants();
  const auto TestFragment1 = [&](const InlineCursor& initial_cursor) {
    InlineCursor cursor = initial_cursor;
    cursor.MoveTo(*text1);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre("1111"));
    cursor = initial_cursor;
    cursor.MoveToIncludingCulledInline(*span1);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre("1111"));
    cursor = initial_cursor;
    cursor.MoveTo(*text2);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre());
    cursor = initial_cursor;
    cursor.MoveToIncludingCulledInline(*span2);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre());
  };
  TestFragment1(line1);

  // The 2nd line has "22" from "text1" and "33" from text2.
  cursor.MoveToNextFragmentainer();
  EXPECT_TRUE(cursor);
  EXPECT_TRUE(cursor.Current().IsLineBox());
  InlineCursor line2 = cursor.CursorForDescendants();
  const auto TestFragment2 = [&](const InlineCursor& initial_cursor) {
    InlineCursor cursor = initial_cursor;
    cursor.MoveTo(*text1);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre("22"));
    cursor = initial_cursor;
    cursor.MoveToIncludingCulledInline(*span1);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre("22"));
    cursor = initial_cursor;
    cursor.MoveTo(*text2);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre("33"));
    cursor = initial_cursor;
    cursor.MoveToIncludingCulledInline(*span2);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre("33"));
  };
  TestFragment2(line2);

  // The 3rd line has "4444" from text2.
  cursor.MoveToNextFragmentainer();
  EXPECT_TRUE(cursor);
  EXPECT_TRUE(cursor.Current().IsLineBox());
  InlineCursor line3 = cursor.CursorForDescendants();
  const auto TestFragment3 = [&](const InlineCursor& initial_cursor) {
    InlineCursor cursor = initial_cursor;
    cursor.MoveTo(*text1);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre());
    cursor = initial_cursor;
    cursor.MoveToIncludingCulledInline(*span1);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre());
    cursor = initial_cursor;
    cursor.MoveTo(*text2);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre("4444"));
    cursor = initial_cursor;
    cursor.MoveToIncludingCulledInline(*span2);
    EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre("4444"));
  };
  TestFragment3(line3);

  // Test cursors rooted at |FragmentItems|.
  // They can enumerate fragments only in the specified fragmentainer.
  HeapVector<Member<const PhysicalBoxFragment>> fragments;
  for (const PhysicalBoxFragment& fragment : block_flow->PhysicalFragments()) {
    DCHECK(fragment.HasItems());
    fragments.push_back(&fragment);
  }
  EXPECT_EQ(fragments.size(), 3u);
  TestFragment1(InlineCursor(*fragments[0], *fragments[0]->Items()));
  TestFragment2(InlineCursor(*fragments[1], *fragments[1]->Items()));
  TestFragment3(InlineCursor(*fragments[2], *fragments[2]->Items()));
}

}  // namespace

}  // namespace blink
```