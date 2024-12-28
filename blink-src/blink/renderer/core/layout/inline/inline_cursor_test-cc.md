Response:
The user wants me to analyze a C++ source code file from the Chromium Blink rendering engine. Specifically, the file `inline_cursor_test.cc` located in the `blink/renderer/core/layout/inline/` directory.

Here's a breakdown of what I need to do:

1. **Identify the file's purpose:** Based on the name and the included headers, it's clearly a unit test file for the `InlineCursor` class. The `InlineCursor` likely helps navigate and inspect inline layout structures.

2. **List the functionalities tested:** I need to go through the test cases (functions starting with `TEST_F`) and understand what aspects of `InlineCursor` they are verifying. These will likely include methods for moving the cursor, accessing data at the cursor position, and handling different inline layout scenarios.

3. **Analyze relationships with web technologies:** I need to determine if the tested functionalities directly relate to how JavaScript, HTML, and CSS are rendered and how they affect the layout. For example, tests involving `dir` attributes relate to HTML and CSS's text directionality features.

4. **Provide examples for relationships:** For each relevant relationship identified in step 3, I need to give concrete examples of how the `InlineCursor` functionality interacts with or is influenced by HTML, CSS, or JavaScript.

5. **Offer logic inference examples:** If any test cases demonstrate logical reasoning within the `InlineCursor` implementation, I should describe a hypothetical input and the expected output.

6. **Highlight potential usage errors:** I need to look for test cases that implicitly reveal common mistakes developers might make when working with inline layout or related concepts.

7. **Summarize the file's function (for Part 1):**  Based on the analysis above, I need to provide a concise summary of the overall purpose of `inline_cursor_test.cc`.

**Mental Walkthrough of the Code:**

* **Includes:**  The included headers indicate that the tests involve editing positions, text affinity, fragment items, inline node data, layout of images and text, and physical box fragments. This reinforces the idea that `InlineCursor` is for navigating inline layout.
* **Helper Functions:**  Functions like `ToDebugString` and `LayoutObjectToDebugStringList` suggest that the tests rely on inspecting the state of the `InlineCursor` and the layout objects it points to.
* **Test Structure:**  The `InlineCursorTest` class uses Google Test (`TEST_F`), indicating standard unit testing practices. Each `TEST_F` function likely focuses on a specific aspect of `InlineCursor`.
* **Bidi Tests:** Tests like `BidiLevelInlineBoxLTR` and `BidiLevelSimpleRTL` clearly relate to how the cursor handles bidirectional text, a feature controlled by HTML attributes and CSS.
* **Parent/Child Navigation:** Tests like `Parent`, `FirstChild`, `LastChild` focus on the cursor's ability to move up and down the inline layout tree.
* **Culled Inline:** Tests related to "CulledInline" probably deal with how the cursor behaves when encountering elements that don't directly contribute to the inline flow (e.g., absolutely positioned elements).
* **Fragmentainer:** The `CursorForMovingAcrossFragmentainer` test relates to how the cursor operates within CSS multi-column layouts.
* **Logical Order:** Tests involving "FirstLogicalLeaf" and "LastLogicalLeaf" likely verify the cursor's ability to traverse the layout in the correct logical order, which might be different from the DOM order in cases of bidirectional text.
* **Line Handling:** Tests like `MoveToEndOfLineWithNoCharsLtr` and `NextLine` focus on how the cursor interacts with line breaks and moves between lines.
* **Ellipsis and Soft Hyphens:** Tests involving ellipsis and soft hyphens check how the cursor handles these specific text rendering features.
* **Siblings:** The `Sibling` tests verify the cursor's ability to move between elements at the same level in the inline layout.

By systematically examining the test cases, I can extract the necessary information to fulfill the user's request.
这是位于 `blink/renderer/core/layout/inline/inline_cursor_test.cc` 的 Chromium Blink 引擎源代码文件，它主要的功能是 **测试 `InlineCursor` 类的各种功能和行为**。

`InlineCursor` 类本身是 Blink 渲染引擎中用于在 **行内布局（inline layout）** 的结构中进行遍历和定位的关键组件。行内布局是指文本、图片、行内块等元素在同一行内排列的布局方式。

以下列举一下 `inline_cursor_test.cc` 中测试的主要功能，并说明其与 JavaScript、HTML、CSS 的关系：

**1. 基本光标移动和状态检查:**

* **`MoveToNext()`**: 测试光标是否能正确移动到下一个行内布局项（FragmentItem）。
    * **HTML:**  考虑如下 HTML： `<div><span>text1</span><span>text2</span></div>`。`MoveToNext()` 测试会验证光标能否从 "text1" 的布局对象移动到 "text2" 的布局对象。
    * **CSS:** CSS 的 `display: inline` 或默认行为会使 `span` 元素进行行内布局，从而使 `MoveToNext()` 的测试有意义。
* **`MoveToPreviousSibling()`/`MoveToNextSibling()`**: 测试光标是否能正确移动到同级的布局项。
    * **HTML:**  同上例，测试能否从 "text1" 移动到 "text2"，或者反向移动。
* **`MoveToFirstChild()`/`MoveToLastChild()`**: 测试光标能否进入到一个容器布局项（如 `<span>`）并定位到它的第一个或最后一个子布局项。
    * **HTML:** `<div><span><b>bold</b>italic</span></div>`。测试会验证能否从 `<span>` 光标移动到 `<b>` 的布局对象。
* **`MoveToParent()`**: 测试光标能否从一个子布局项移动到其父布局项。
    * **HTML:** 同上例，测试能否从 `<b>` 的布局对象移动回 `<span>`。
* **`Current()`**: 测试光标当前是否指向有效的布局项。
* **`IsNull()`/`IsNotNull()`**: 测试光标是否为空。

**2. 处理不同类型的行内布局项:**

* **文本节点 (`LayoutText`)**: 测试光标能否正确指向文本内容。
    * **HTML:** `<div>abc</div>`。测试会验证光标能否指向包含 "abc" 的 `LayoutText` 对象。
* **行内元素 (`LayoutInline`)**: 测试光标能否正确指向行内元素，例如 `<span>`、`<a>` 等。
    * **HTML:** `<div><span>text</span></div>`。测试会验证光标能否指向 `<span>` 的 `LayoutInline` 对象。
* **行内块元素 (`LayoutBox` with `display: inline-block`)**: 测试光标能否正确处理行内块元素。
    * **HTML:** `<div><b style="display: inline-block;">block</b></div>`。测试会验证光标能否指向 `<b>` 的 `LayoutBox` 对象。
    * **CSS:** `display: inline-block` 是关键。
* **图片 (`LayoutImage`)**: 测试光标能否正确指向图片元素。
    * **HTML:** `<div><img src="image.png"></div>`。测试会验证光标能否指向 `<img>` 的 `LayoutImage` 对象。
* **自动生成的文本 (`LayoutGeneratedText`)**: 例如列表项的 marker。
    * **HTML:** `<ul><li>item</li></ul>`。测试会验证光标能否指向表示列表 marker 的 `LayoutGeneratedText` 对象。
* **换行符 (`br`)**: 测试光标能否正确处理换行符，将其视为一个布局项。
    * **HTML:** `<div>line1<br>line2</div>`。

**3. 处理双向文本 (Bidi):**

* **`BidiLevelInlineBoxLTR` / `BidiLevelInlineBoxRTL` / `BidiLevelSimpleLTR` / `BidiLevelSimpleRTL`**: 测试光标在包含从左到右 (LTR) 和从右到左 (RTL) 文本的复杂场景下的行为，以及如何处理 `bdo` 元素。
    * **HTML:** 使用 `dir="rtl"` 或 `dir="ltr"` 属性来指定文本方向。 `<bdo dir="rtl">` 元素会强制其内容以 RTL 方向渲染。
    * **CSS:**  CSS 的 `direction` 属性也会影响文本方向。

**4. 处理被裁剪的行内元素 (Culled Inline):**

* **`CulledInlineWithAtomicInline` / `CulledInlineWithFloat` / `CulledInlineWithOOF` / `CulledInlineNested` / `CulledInlineBlockChild` / `CulledInlineWithRoot` / `CulledInlineWithoutRoot`**: 测试当一个行内元素由于某种原因（例如包含浮动元素、绝对定位元素或自身被设置为 `display: none` 等）而被裁剪时，光标的行为。
    * **HTML:** 这些测试会创建包含各种嵌套和定位的 HTML 结构。
    * **CSS:** `float`, `position: absolute`, `display: none` 等属性会触发元素的裁剪。

**5. 处理分栏布局 (Fragmentainer):**

* **`CursorForMovingAcrossFragmentainer` / `NextIncludingFragmentainer`**: 测试光标在 CSS 分栏布局中的移动能力。
    * **HTML:**  需要一个设置了 `column-count` 的容器元素。
    * **CSS:**  `column-count` 属性用于创建分栏布局。

**6. 处理省略号 (`text-overflow: ellipsis`):**

* **`NextWithEllipsis` / `NextInlineLeafWithEllipsis`**: 测试光标如何处理由于文本溢出而被省略号替换的部分。
    * **CSS:** `text-overflow: ellipsis` 属性用于在文本溢出时显示省略号。

**7. 处理软连字符 (`&shy;`):**

* **`NextWithSoftHyphens` / `NextInlineLeafWithSoftHyphens`**: 测试光标如何处理软连字符，它允许浏览器在必要时进行断行。
    * **HTML:** 使用 `&shy;` 插入软连字符。

**8. 处理列表项:**

* **`NextWithListItem`**: 测试光标如何处理列表项及其 marker。
    * **HTML:** 使用 `<ul>` 和 `<li>` 创建列表。

**9. 定位到行首/行尾:**

* **`MoveToEndOfLineWithNoCharsLtr` / `MoveToEndOfLineWithNoCharsRtl`**: 测试光标定位到行尾的能力，尤其是在空行的情况下。

**10. 逻辑叶子节点:**

* **`FirstLastLogicalLeafInSimpleText` / `FirstLastLogicalLeafInRtlText` / `FirstLastLogicalLeafInTextAsDeepDescendants` / `FirstLastLogicalLeafWithInlineBlock` / `FirstLastLogicalLeafWithImages` / `FirstNonPseudoLeafWithBlockImage`**:  测试光标能否找到行内布局的第一个和最后一个“逻辑”叶子节点。逻辑顺序可能与 DOM 树的顺序不同，尤其是在双向文本或包含行内块元素的情况下。

**11. 判断是否为空行盒:**

* **`IsEmptyLineBox`**: 测试光标能否判断当前是否位于一个空的行盒中。

**假设输入与输出 (逻辑推理示例):**

假设我们有如下 HTML 和 CSS：

**HTML:** `<div id="root"><span>abc</span>def</div>`

**CSS:**  (默认行内布局)

**假设输入:** 一个 `InlineCursor` 对象，初始时指向 `#root` 的起始位置（行盒的开始）。

**测试的逻辑推理 (例如针对 `MoveToNextInlineLeaf()`):**

1. 光标首先位于行盒的开始。
2. 调用 `MoveToNextInlineLeaf()`。
3. 光标应该移动到第一个行内叶子节点，即包含文本 "abc" 的 `LayoutText` 对象。
4. 再次调用 `MoveToNextInlineLeaf()`。
5. 光标应该移动到下一个行内叶子节点，即包含文本 "def" 的 `LayoutText` 对象。
6. 再次调用 `MoveToNextInlineLeaf()`。
7. 光标应该移动到行尾。

**预期输出 (使用 `ToDebugString()`):**

初始状态: `#linebox`
第一次 `MoveToNextInlineLeaf()` 后: `abc`
第二次 `MoveToNextInlineLeaf()` 后: `def`
第三次 `MoveToNextInlineLeaf()` 后: (光标变为 null 或指向行尾，`ToDebugString()` 可能返回空字符串或特定标识)

**用户或编程常见的使用错误 (示例):**

* **假设光标始终按照 DOM 树顺序移动:** 在复杂的行内布局中（尤其是包含双向文本或浮动元素时），布局顺序可能与 DOM 树顺序不同。 开发者可能会错误地假设 `MoveToNext()` 会简单地移动到 DOM 树中的下一个节点，但实际上它移动的是布局顺序中的下一个项目。
    * **HTML:** `<div dir="rtl"><span>ghi</span><span>abc</span></div>`
    * **错误假设:**  开发者可能认为从 "ghi" 的 `span` 开始调用 `MoveToNext()` 会移动到 "abc" 的 `span`。
    * **实际行为:** 由于 `dir="rtl"`，布局顺序可能是 "abc" 在前，"ghi" 在后。

* **忘记处理 `nullptr` 或空光标:**  在循环遍历光标时，开发者可能会忘记检查光标是否已经到达末尾 (`cursor.IsNull()`)，从而导致访问无效内存。

**功能归纳 (第 1 部分):**

`inline_cursor_test.cc` 的主要功能是 **全面地测试 `InlineCursor` 类在各种行内布局场景下的行为和功能**。它涵盖了基本的光标移动、对不同类型行内布局项的处理、双向文本、裁剪元素、分栏布局、省略号、软连字符以及列表项等复杂情况的测试。 这些测试确保了 `InlineCursor` 能够可靠地在行内布局结构中进行导航和定位，这对于 Blink 渲染引擎的文本编辑、选择、辅助功能等功能至关重要。 这些测试与 HTML、CSS 紧密相关，因为它们验证了 `InlineCursor` 如何根据 HTML 结构和 CSS 样式进行布局遍历。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/inline_cursor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node_data.h"
#include "third_party/blink/renderer/core/layout/layout_image.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

namespace {

using ::testing::ElementsAre;

String ToDebugString(const InlineCursor& cursor) {
  if (cursor.Current().IsLineBox())
    return "#linebox";

  if (cursor.Current().IsLayoutGeneratedText()) {
    StringBuilder result;
    result.Append("#'");
    result.Append(cursor.CurrentText());
    result.Append("'");
    return result.ToString();
  }

  if (cursor.Current().IsText())
    return cursor.CurrentText().ToString().StripWhiteSpace();

  if (const LayoutObject* layout_object = cursor.Current().GetLayoutObject()) {
    if (const Element* element = DynamicTo<Element>(layout_object->GetNode())) {
      if (const AtomicString& id = element->GetIdAttribute())
        return "#" + id;
    }

    return layout_object->DebugName();
  }

  return "#null";
}

Vector<String> LayoutObjectToDebugStringList(InlineCursor cursor) {
  Vector<String> list;
  for (; cursor; cursor.MoveToNextForSameLayoutObject())
    list.push_back(ToDebugString(cursor));
  return list;
}

class InlineCursorTest : public RenderingTest {
 protected:
  InlineCursor SetupCursor(const String& html) {
    SetBodyInnerHTML(html);
    const LayoutBlockFlow& block_flow =
        *To<LayoutBlockFlow>(GetLayoutObjectByElementId("root"));
    return InlineCursor(block_flow);
  }

  Vector<String> ToDebugStringList(const InlineCursor& start) {
    Vector<String> list;
    for (InlineCursor cursor(start); cursor; cursor.MoveToNext()) {
      list.push_back(ToDebugString(cursor));
    }
    return list;
  }

  Vector<String> SiblingsToDebugStringList(const InlineCursor& start) {
    Vector<String> list;
    for (InlineCursor cursor(start); cursor;
         cursor.MoveToNextSkippingChildren()) {
      list.push_back(ToDebugString(cursor));
    }
    return list;
  }

  // Test |MoveToNextSibling| and |InlineBackwardCursor| return the same
  // instances, except that the order is reversed.
  void TestPrevoiusSibling(const InlineCursor& start) {
    DCHECK(start.HasRoot());
    Vector<const FragmentItem*> forwards;
    for (InlineCursor cursor(start); cursor;
         cursor.MoveToNextSkippingChildren()) {
      forwards.push_back(cursor.CurrentItem());
    }
    Vector<const FragmentItem*> backwards;
    for (InlineBackwardCursor cursor(start); cursor;
         cursor.MoveToPreviousSibling()) {
      backwards.push_back(cursor.Current().Item());
    }
    backwards.Reverse();
    EXPECT_THAT(backwards, forwards);
  }

  Vector<String> ToDebugStringListWithBidiLevel(const InlineCursor& start) {
    Vector<String> list;
    for (InlineCursor cursor(start); cursor; cursor.MoveToNext()) {
      // Inline boxes do not have bidi level.
      if (cursor.Current().IsInlineBox())
        continue;
      list.push_back(ToDebugStringWithBidiLevel(cursor));
    }
    return list;
  }

  String ToDebugStringWithBidiLevel(const InlineCursor& cursor) {
    if (!cursor.Current().IsText() && !cursor.Current().IsAtomicInline())
      return ToDebugString(cursor);
    StringBuilder result;
    result.Append(ToDebugString(cursor));
    result.Append(':');
    result.AppendNumber(cursor.Current().BidiLevel());
    return result.ToString();
  }
};

TEST_F(InlineCursorTest, BidiLevelInlineBoxLTR) {
  InsertStyleElement("b { display: inline-block; }");
  InlineCursor cursor = SetupCursor(
      "<div id=root dir=ltr>"
      "abc<b id=def>def</b><bdo dir=rtl><b id=ghi>GHI</b></bdo>jkl</div>");
  Vector<String> list = ToDebugStringListWithBidiLevel(cursor);
  EXPECT_THAT(list,
              ElementsAre("#linebox", "abc:0", "#def:0", "#ghi:3", "jkl:0"));
}

TEST_F(InlineCursorTest, BidiLevelInlineBoxRTL) {
  InsertStyleElement("b { display: inline-block; }");
  InlineCursor cursor = SetupCursor(
      "<div id=root dir=rtl>"
      "abc<b id=def>def</b><bdo dir=rtl><b id=ghi>GHI</b></bdo>jkl</div>");
  Vector<String> list = ToDebugStringListWithBidiLevel(cursor);
  EXPECT_THAT(list,
              ElementsAre("#linebox", "abc:2", "#def:2", "#ghi:3", "jkl:2"));
}

TEST_F(InlineCursorTest, BidiLevelSimpleLTR) {
  InlineCursor cursor = SetupCursor(
      "<div id=root dir=ltr>"
      "<bdo dir=rtl>GHI<bdo dir=ltr>abc</bdo>DEF</bdo><br>"
      "123, jkl <bdo dir=rtl>MNO</bdo></div>");
  Vector<String> list = ToDebugStringListWithBidiLevel(cursor);
  EXPECT_THAT(list, ElementsAre("#linebox", "DEF:3", "abc:6", "GHI:3", ":0",
                                "#linebox", "123, jkl:0", "MNO:3"));
}

TEST_F(InlineCursorTest, BidiLevelSimpleRTL) {
  InlineCursor cursor = SetupCursor(
      "<div id=root dir=rtl>"
      "<bdo dir=rtl>GHI<bdo dir=ltr>abc</bdo>DEF</bdo><br>"
      "123, jkl <bdo dir=rtl>MNO</bdo></div>");
  Vector<String> list = ToDebugStringListWithBidiLevel(cursor);
  EXPECT_THAT(
      list, ElementsAre("#linebox", ":0", "DEF:3", "abc:6", "GHI:3", "#linebox",
                        "MNO:3", ":1", "jkl:2", ",:1", "123:2"));
}

TEST_F(InlineCursorTest, GetLayoutBlockFlowWithScopedCursor) {
  InlineCursor line = SetupCursor("<div id=root>line1<br>line2</div>");
  ASSERT_TRUE(line.Current().IsLineBox()) << line;
  InlineCursor cursor = line.CursorForDescendants();
  EXPECT_EQ(line.GetLayoutBlockFlow(), cursor.GetLayoutBlockFlow());
}

TEST_F(InlineCursorTest, Parent) {
  InlineCursor cursor = SetupCursor(R"HTML(
    <style>
    span { background: yellow; } /* Ensure not culled. */
    </style>
    <body>
      <div id="root">
        text1
        <span id="span1">
          span1
          <span></span>
          <span id="span2">
            span2
            <span style="display: inline-block"></span>
            <span id="span3">
              span3
            </span>
          </span>
        </span>
      </div>
    <body>
)HTML");
  cursor.MoveTo(*GetLayoutObjectByElementId("span3"));
  ASSERT_TRUE(cursor);
  Vector<AtomicString> ids;
  for (;;) {
    cursor.MoveToParent();
    if (!cursor)
      break;
    const auto* element = To<Element>(cursor.Current()->GetNode());
    ids.push_back(element->GetIdAttribute());
  }
  EXPECT_THAT(ids, testing::ElementsAre("span2", "span1", "root"));
}

TEST_F(InlineCursorTest, ContainingLine) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("a, b { background: gray; }");
  InlineCursor cursor =
      SetupCursor("<div id=root>abc<a id=target>def</a>ghi<br>xyz</div>");
  const LayoutBlockFlow& block_flow = *cursor.GetLayoutBlockFlow();
  InlineCursor line1(cursor);
  ASSERT_TRUE(line1.Current().IsLineBox());

  InlineCursor line2(line1);
  line2.MoveToNextSkippingChildren();
  ASSERT_TRUE(line2.Current().IsLineBox());

  cursor.MoveTo(*block_flow.FirstChild());
  cursor.MoveToContainingLine();
  EXPECT_EQ(line1, cursor);

  const auto& target = To<LayoutInline>(*GetLayoutObjectByElementId("target"));
  cursor.MoveTo(target);
  cursor.MoveToContainingLine();
  EXPECT_EQ(line1, cursor);

  cursor.MoveTo(*target.FirstChild());
  cursor.MoveToContainingLine();
  EXPECT_EQ(line1, cursor);

  cursor.MoveTo(*block_flow.LastChild());
  cursor.MoveToContainingLine();
  EXPECT_EQ(line2, cursor);
}

TEST_F(InlineCursorTest, CulledInlineWithAtomicInline) {
  SetBodyInnerHTML(
      "<div id=root>"
      "<b id=culled>abc<div style=display:inline>ABC<br>XYZ</div>xyz</b>"
      "</div>");
  InlineCursor cursor;
  cursor.MoveToIncludingCulledInline(*GetLayoutObjectByElementId("culled"));
  EXPECT_THAT(LayoutObjectToDebugStringList(cursor),
              ElementsAre("abc", "ABC", "", "XYZ", "xyz"));
}

// We should not have float:right fragment, because it isn't in-flow in
// an inline formatting context.
// For https://crbug.com/1026022
TEST_F(InlineCursorTest, CulledInlineWithFloat) {
  SetBodyInnerHTML(
      "<div id=root>"
      "<b id=culled>abc<div style=float:right></div>xyz</b>"
      "</div>");
  InlineCursor cursor;
  cursor.MoveToIncludingCulledInline(*GetLayoutObjectByElementId("culled"));
  EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre("abc", "xyz"));
}

TEST_F(InlineCursorTest, CulledInlineWithOOF) {
  SetBodyInnerHTML(R"HTML(
    <div id=root>
      <b id=culled>abc<span style="position:absolute"></span>xyz</b>
    </div>
  )HTML");
  InlineCursor cursor;
  cursor.MoveToIncludingCulledInline(*GetLayoutObjectByElementId("culled"));
  EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre("abc", "xyz"));
}

TEST_F(InlineCursorTest, CulledInlineNested) {
  SetBodyInnerHTML(R"HTML(
    <div id=root>
      <b id=culled><span>abc</span> xyz</b>
    </div>
  )HTML");
  InlineCursor cursor;
  cursor.MoveToIncludingCulledInline(*GetLayoutObjectByElementId("culled"));
  EXPECT_THAT(LayoutObjectToDebugStringList(cursor), ElementsAre("abc", "xyz"));
}

TEST_F(InlineCursorTest, CulledInlineBlockChild) {
  SetBodyInnerHTML(R"HTML(
    <div id=root>
      <b id=culled>
        <div>block</div>
        <span>abc</span> xyz
      </b>
    </div>
  )HTML");
  InlineCursor cursor;
  cursor.MoveToIncludingCulledInline(*GetLayoutObjectByElementId("culled"));
  EXPECT_THAT(LayoutObjectToDebugStringList(cursor),
              ElementsAre("#culled", "#culled", "#culled"));
}

TEST_F(InlineCursorTest, CulledInlineWithRoot) {
  InlineCursor cursor = SetupCursor(R"HTML(
    <div id="root"><a id="a"><b>abc</b><br><i>xyz</i></a></div>
  )HTML");
  const LayoutObject* layout_inline_a = GetLayoutObjectByElementId("a");
  cursor.MoveToIncludingCulledInline(*layout_inline_a);
  EXPECT_THAT(LayoutObjectToDebugStringList(cursor),
              ElementsAre("abc", "", "xyz"));
}

TEST_F(InlineCursorTest, CulledInlineWithoutRoot) {
  SetBodyInnerHTML(R"HTML(
    <div id="root"><a id="a"><b>abc</b><br><i>xyz</i></a></div>
  )HTML");
  const LayoutObject* layout_inline_a = GetLayoutObjectByElementId("a");
  InlineCursor cursor;
  cursor.MoveToIncludingCulledInline(*layout_inline_a);
  EXPECT_THAT(LayoutObjectToDebugStringList(cursor),
              ElementsAre("abc", "", "xyz"));
}

TEST_F(InlineCursorTest, CursorForMovingAcrossFragmentainer) {
  LoadAhem();
  InsertStyleElement(
      "div { font: 10px/15px Ahem; column-count: 2; width: 20ch; }");
  SetBodyInnerHTML("<div id=m>abc<br>def<br><b id=t>ghi</b><br>jkl<br></div>");
  // The HTML is rendered as:
  //    abc ghi
  //    def jkl

  // MoveTo(LayoutObject) makes |InlineCursor| to be able to move across
  // fragmentainer.
  InlineCursor cursor;
  cursor.MoveTo(*GetElementById("t")->firstChild()->GetLayoutObject());
  ASSERT_TRUE(cursor.IsBlockFragmented()) << cursor;

  InlineCursor cursor2(cursor.ContainerFragment());
  ASSERT_FALSE(cursor2.IsBlockFragmented()) << cursor2;
  cursor2.MoveTo(*cursor.CurrentItem());
  ASSERT_FALSE(cursor2.IsBlockFragmented());

  InlineCursor cursor3 = cursor2.CursorForMovingAcrossFragmentainer();
  EXPECT_TRUE(cursor3.IsBlockFragmented()) << cursor3;
  EXPECT_EQ(&cursor2.ContainerFragment(), &cursor3.ContainerFragment());
  EXPECT_EQ(cursor2.CurrentItem(), cursor3.CurrentItem());
}

TEST_F(InlineCursorTest, FirstChild) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("a, b { background: gray; }");
  InlineCursor cursor =
      SetupCursor("<div id=root>abc<a>DEF<b>GHI</b></a>xyz</div>");
  cursor.MoveToFirstChild();
  EXPECT_EQ("abc", ToDebugString(cursor));
  EXPECT_FALSE(cursor.TryMoveToFirstChild());
}

TEST_F(InlineCursorTest, FirstChild2) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("a, b { background: gray; }");
  InlineCursor cursor = SetupCursor(
      "<div id=root><b id=first>abc</b><a>DEF<b>GHI</b></a><a "
      "id=last>xyz</a></div>");
  cursor.MoveToFirstChild();
  EXPECT_EQ("#first", ToDebugString(cursor));
  cursor.MoveToFirstChild();
  EXPECT_EQ("abc", ToDebugString(cursor));
  EXPECT_FALSE(cursor.TryMoveToFirstChild());
}

TEST_F(InlineCursorTest, FirstLastLogicalLeafInSimpleText) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("b { background: gray; }");
  InlineCursor cursor =
      SetupCursor("<div id=root><b>first</b><b>middle</b><b>last</b></div>");

  InlineCursor first_logical_leaf(cursor);
  first_logical_leaf.MoveToFirstLogicalLeaf();
  EXPECT_EQ("first", ToDebugString(first_logical_leaf));

  InlineCursor last_logical_leaf(cursor);
  last_logical_leaf.MoveToLastLogicalLeaf();
  EXPECT_EQ("last", ToDebugString(last_logical_leaf));
}

TEST_F(InlineCursorTest, FirstLastLogicalLeafInRtlText) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("b { background: gray; }");
  InlineCursor cursor = SetupCursor(
      "<bdo id=root dir=rtl style=display:block>"
      "<b>first</b><b>middle</b><b>last</b>"
      "</bdo>");

  InlineCursor first_logical_leaf(cursor);
  first_logical_leaf.MoveToFirstLogicalLeaf();
  EXPECT_EQ("first", ToDebugString(first_logical_leaf));

  InlineCursor last_logical_leaf(cursor);
  last_logical_leaf.MoveToLastLogicalLeaf();
  EXPECT_EQ("last", ToDebugString(last_logical_leaf));
}

TEST_F(InlineCursorTest, FirstLastLogicalLeafInTextAsDeepDescendants) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("b { background: gray; }");
  InlineCursor cursor = SetupCursor(
      "<div id=root>"
      "<b><b>first</b>ABC</b>"
      "<b>middle</b>"
      "<b>DEF<b>last</b></b>"
      "</div>");

  InlineCursor first_logical_leaf(cursor);
  first_logical_leaf.MoveToFirstLogicalLeaf();
  EXPECT_EQ("first", ToDebugString(first_logical_leaf));

  InlineCursor last_logical_leaf(cursor);
  last_logical_leaf.MoveToLastLogicalLeaf();
  EXPECT_EQ("last", ToDebugString(last_logical_leaf));
}

TEST_F(InlineCursorTest, MoveToEndOfLineWithNoCharsLtr) {
  SetBodyContent(
      "<textarea rows=\"3\" cols=\"50\">foo&#10;&#10;bar</textarea>");
  const auto& textarea =
      ToTextControl(*GetDocument().QuerySelector(AtomicString("textarea")));
  const LayoutObject* textarea_layout =
      textarea.InnerEditorElement()->GetLayoutObject();
  const LayoutBlockFlow& block_flow = *To<LayoutBlockFlow>(textarea_layout);

  InlineCursor move_to_end_of_line(block_flow);
  // Preparing the InlineCursor to start from beginning
  // of second line(Empty Line).
  move_to_end_of_line.MoveToNextLine();
  InlineCursor next_line = move_to_end_of_line.CursorForDescendants();
  // Verify if it has been successfully placed at the correct position.
  EXPECT_EQ(4u, next_line.Current().TextStartOffset());
  const PositionWithAffinity end_position =
      move_to_end_of_line.PositionForEndOfLine();
  EXPECT_EQ(4, end_position.GetPosition().OffsetInContainerNode());
}

TEST_F(InlineCursorTest, MoveToEndOfLineWithNoCharsRtl) {
  SetBodyContent(
      "<textarea rows=\"3\" cols=\"50\" "
      "dir=\"rtl\">foo&#10;&#10;bar</textarea>");
  const auto& textarea =
      ToTextControl(*GetDocument().QuerySelector(AtomicString("textarea")));
  const LayoutObject* textarea_layout =
      textarea.InnerEditorElement()->GetLayoutObject();
  const LayoutBlockFlow& block_flow = *To<LayoutBlockFlow>(textarea_layout);

  InlineCursor move_to_end_of_line(block_flow);
  // Preparing the InlineCursor to start from beginning
  // of second line(Empty Line).
  move_to_end_of_line.MoveToNextLine();
  InlineCursor next_line = move_to_end_of_line.CursorForDescendants();
  // Verify if it has been successfully placed at the correct position.
  EXPECT_EQ(4u, next_line.Current().TextStartOffset());
  const PositionWithAffinity end_position =
      move_to_end_of_line.PositionForEndOfLine();
  EXPECT_EQ(4, end_position.GetPosition().OffsetInContainerNode());
}

TEST_F(InlineCursorTest, FirstLastLogicalLeafWithInlineBlock) {
  InsertStyleElement("b { display: inline-block; }");
  InlineCursor cursor = SetupCursor(
      "<div id=root>"
      "<b id=first>first</b>middle<b id=last>last</b>"
      "</div>");

  InlineCursor first_logical_leaf(cursor);
  first_logical_leaf.MoveToFirstLogicalLeaf();
  EXPECT_EQ("#first", ToDebugString(first_logical_leaf))
      << "stop at inline-block";

  InlineCursor last_logical_leaf(cursor);
  last_logical_leaf.MoveToLastLogicalLeaf();
  EXPECT_EQ("#last", ToDebugString(last_logical_leaf))
      << "stop at inline-block";
}

TEST_F(InlineCursorTest, FirstLastLogicalLeafWithImages) {
  InlineCursor cursor =
      SetupCursor("<div id=root><img id=first>middle<img id=last></div>");

  InlineCursor first_logical_leaf(cursor);
  first_logical_leaf.MoveToFirstLogicalLeaf();
  EXPECT_EQ("#first", ToDebugString(first_logical_leaf));

  InlineCursor last_logical_leaf(cursor);
  last_logical_leaf.MoveToLastLogicalLeaf();
  EXPECT_EQ("#last", ToDebugString(last_logical_leaf));
}

// http://crbug.com/1295087
TEST_F(InlineCursorTest, FirstNonPseudoLeafWithBlockImage) {
  InsertStyleElement("img { display: block; }");
  InlineCursor cursor = SetupCursor("<p id=root><b><img id=target></b></p>");

  // Note: The first child of block-in-inline can be |LayoutImage|.
  // LayoutBlockFlow P id="root"
  //   +--LayoutInline SPAN
  //   |  +--LayoutBlockFlow (anonymous)  # block-in-inline
  //   |  |  +--LayoutImage IMG id="target" # first child of block-in-inline
  //   +--LayoutText #text ""
  const auto& target =
      *To<LayoutImage>(GetElementById("target")->GetLayoutObject());

  cursor.MoveToFirstNonPseudoLeaf();
  ASSERT_TRUE(cursor.Current());
  EXPECT_EQ(target.Parent(), cursor.Current().GetLayoutObject());
  ASSERT_TRUE(cursor.Current()->IsBlockInInline());
  EXPECT_EQ(&target, cursor.Current()->BlockInInline());
}

TEST_F(InlineCursorTest, IsEmptyLineBox) {
  InsertStyleElement("b { margin-bottom: 1px; }");
  InlineCursor cursor = SetupCursor("<div id=root>abc<br><b></b></div>");

  EXPECT_FALSE(cursor.Current().IsEmptyLineBox())
      << "'abc\\n' is in non-empty line box.";
  cursor.MoveToNextLine();
  EXPECT_TRUE(cursor.Current().IsEmptyLineBox())
      << "<b></b> with margin produces empty line box.";
}

TEST_F(InlineCursorTest, LastChild) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("a, b { background: gray; }");
  InlineCursor cursor =
      SetupCursor("<div id=root>abc<a>DEF<b>GHI</b></a>xyz</div>");
  cursor.MoveToLastChild();
  EXPECT_EQ("xyz", ToDebugString(cursor));
  EXPECT_FALSE(cursor.TryMoveToLastChild());
}

TEST_F(InlineCursorTest, LastChild2) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("a, b { background: gray; }");
  InlineCursor cursor = SetupCursor(
      "<div id=root><b id=first>abc</b><a>DEF<b>GHI</b></a>"
      "<a id=last>xyz</a></div>");
  cursor.MoveToLastChild();
  EXPECT_EQ("#last", ToDebugString(cursor));
  cursor.MoveToLastChild();
  EXPECT_EQ("xyz", ToDebugString(cursor));
  EXPECT_FALSE(cursor.TryMoveToLastChild());
}

TEST_F(InlineCursorTest, Next) {
  SetBodyInnerHTML(R"HTML(
    <style>
    span { background: gray; }
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
    </div>
  )HTML");

  LayoutBlockFlow* block_flow =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("root"));
  InlineCursor cursor(*block_flow);
  Vector<String> list = ToDebugStringList(cursor);
  EXPECT_THAT(list, ElementsAre("#linebox", "text1", "#span1", "text2",
                                "#span2", "text3", "text4", "text5"));
}

TEST_F(InlineCursorTest, NextIncludingFragmentainer) {
  // TDOO(yosin): Remove style for <b> once FragmentItem don't do culled
  // inline.
  LoadAhem();
  InsertStyleElement(
      "b { background: gray; }"
      "div { font: 10px/15px Ahem; column-count: 2; width: 20ch; }");
  SetBodyInnerHTML("<div id=m>abc<br>def<br><b>ghi</b><br>jkl</div>");
  InlineCursor cursor;
  cursor.MoveTo(*GetElementById("m")->firstChild()->GetLayoutObject());
  ASSERT_TRUE(cursor.IsBlockFragmented()) << cursor;
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToNextIncludingFragmentainer();
  }
  EXPECT_THAT(list,
              ElementsAre("abc", "", "#linebox", "def", "", "#linebox",
                          "LayoutInline B", "ghi", "", "#linebox", "jkl"));
}

TEST_F(InlineCursorTest, NextWithEllipsis) {
  LoadAhem();
  InsertStyleElement(
      "#root {"
      "font: 10px/10px Ahem;"
      "width: 5ch;"
      "overflow-x: hidden;"
      "text-overflow: ellipsis;"
      "}");
  InlineCursor cursor = SetupCursor("<div id=root>abcdefghi</div>");
  Vector<String> list = ToDebugStringList(cursor);
  // Note: "abcdefghi" is hidden for paint.
  EXPECT_THAT(list, ElementsAre("#linebox", "abcdefghi", "abcd", u"#'\u2026'"));
}

TEST_F(InlineCursorTest, NextWithEllipsisInlineBoxOnly) {
  LoadAhem();
  InsertStyleElement(
      "#root {"
      "font: 10px/1 Ahem;"
      "width: 5ch;"
      "overflow: hidden;"
      "text-overflow: ellipsis;"
      "}"
      "span { border: solid 10ch blue; }");
  InlineCursor cursor = SetupCursor("<div id=root><span></span></div>");
  Vector<String> list = ToDebugStringList(cursor);
  EXPECT_THAT(list, ElementsAre("#linebox", "LayoutInline SPAN"));
}

TEST_F(InlineCursorTest, NextWithListItem) {
  InlineCursor cursor = SetupCursor("<ul><li id=root>abc</li></ul>");
  Vector<String> list = ToDebugStringList(cursor);
  EXPECT_THAT(
      list,
      ElementsAre("LayoutOutsideListMarker (inline, children-inline) ::marker",
                  "#linebox", "abc"));
  EXPECT_EQ(GetLayoutObjectByElementId("root"), cursor.GetLayoutBlockFlow());
}

TEST_F(InlineCursorTest, NextWithSoftHyphens) {
  // Use "Ahem" font to get U+2010 as soft hyphen instead of U+002D
  LoadAhem();
  InsertStyleElement("#root {width: 3ch; font: 10px/10px Ahem;}");
  InlineCursor cursor = SetupCursor("<div id=root>abc&shy;def</div>");
  Vector<String> list = ToDebugStringList(cursor);
  EXPECT_THAT(list, ElementsAre("#linebox", u"abc\u00AD", u"#'\u2010'",
                                "#linebox", "def"));
}

TEST_F(InlineCursorTest, NextInlineLeaf) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("b { background: gray; }");
  InlineCursor cursor = SetupCursor("<div id=root>abc<b>DEF</b><br>xyz</div>");
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToNextInlineLeaf();
  }
  EXPECT_THAT(list, ElementsAre("#linebox", "abc", "DEF", "", "xyz"));
}

// Note: This is for AccessibilityLayoutTest.NextOnLine.
TEST_F(InlineCursorTest, NextInlineLeafOnLineFromLayoutInline) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("b { background: gray; }");
  InlineCursor cursor = SetupCursor(
      "<div id=root>"
      "<b id=start>abc</b> def<br>"
      "<b>ABC</b> DEF<br>"
      "</div>");
  cursor.MoveTo(*GetElementById("start")->GetLayoutObject());
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToNextInlineLeafOnLine();
  }
  EXPECT_THAT(list, ElementsAre("#start", "def", ""))
      << "we don't have 'abc' and items in second line.";
}

TEST_F(InlineCursorTest, NextInlineLeafOnLineFromNestedLayoutInline) {
  // Never return a descendant for AXLayoutObject::NextOnLine().
  // Instead, if NextOnLine() is called on a container, return the first
  // content from a sibling subtree.
  InlineCursor cursor = SetupCursor(
      "<div id=root>"
      "<span id=start>"
      "Test<span style=font-size:13px>descendant</span>"
      "</span>"
      "<span>next</span>"
      "</div>");
  cursor.MoveToIncludingCulledInline(
      *GetElementById("start")->GetLayoutObject());
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToNextInlineLeafOnLine();
  }
  EXPECT_THAT(list, ElementsAre("#start", "next"))
      << "next on line doesn't return descendant.";
}

TEST_F(InlineCursorTest, NextInlineLeafOnLineFromLayoutText) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("b { background: gray; }");
  InlineCursor cursor = SetupCursor(
      "<div id=root>"
      "<b id=start>abc</b> def<br>"
      "<b>ABC</b> DEF<br>"
      "</div>");
  cursor.MoveTo(*GetElementById("start")->firstChild()->GetLayoutObject());
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToNextInlineLeafOnLine();
  }
  EXPECT_THAT(list, ElementsAre("abc", "def", ""))
      << "We don't have items from second line.";
}

TEST_F(InlineCursorTest, NextInlineLeafWithEllipsis) {
  LoadAhem();
  InsertStyleElement(
      "#root {"
      "font: 10px/10px Ahem;"
      "width: 5ch;"
      "overflow-x: hidden;"
      "text-overflow: ellipsis;"
      "}");
  InlineCursor cursor = SetupCursor("<div id=root>abcdefghi</div>");
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToNextInlineLeaf();
  }
  // Note: We don't see hidden for paint and generated soft hyphen.
  // See also |NextWithEllipsis|.
  EXPECT_THAT(list, ElementsAre("#linebox", "abcd"));
}

TEST_F(InlineCursorTest, NextInlineLeafWithSoftHyphens) {
  InlineCursor cursor =
      SetupCursor("<div id=root style='width:3ch'>abc&shy;def</div>");
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToNextInlineLeaf();
  }
  // Note: We don't see generated soft hyphen. See also |NextWithSoftHyphens|.
  EXPECT_THAT(list, ElementsAre("#linebox", u"abc\u00AD", "def"));
}

TEST_F(InlineCursorTest, NextInlineLeafIgnoringLineBreak) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("b { background: gray; }");
  InlineCursor cursor = SetupCursor("<div id=root>abc<b>DEF</b><br>xyz</div>");
  Vector<String> list;
  while (cursor) {
    list.push_back(ToDebugString(cursor));
    cursor.MoveToNextInlineLeafIgnoringLineBreak();
  }
  EXPECT_THAT(list, ElementsAre("#linebox", "abc", "DEF", "xyz"));
}

TEST_F(InlineCursorTest, NextLine) {
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

  InlineCursor should_be_line2(line1);
  should_be_line2.MoveToNextLine();
  EXPECT_EQ(line2, should_be_line2);

  InlineCursor should_be_null(line2);
  should_be_null.MoveToNextLine();
  EXPECT_TRUE(should_be_null.IsNull());
}

TEST_F(InlineCursorTest, NextWithImage) {
  InlineCursor cursor = SetupCursor("<div id=root>abc<img id=img>xyz</div>");
  Vector<String> list = ToDebugStringList(cursor);
  EXPECT_THAT(list, ElementsAre("#linebox", "abc", "#img", "xyz"));
}

TEST_F(InlineCursorTest, NextWithInlineBox) {
  InsertStyleElement("b { display: inline-block; }");
  InlineCursor cursor =
      SetupCursor("<div id=root>abc<b id=ib>def</b>xyz</div>");
  Vector<String> list = ToDebugStringList(cursor);
  EXPECT_THAT(list, ElementsAre("#linebox", "abc", "#ib", "xyz"));

  InlineCursor cursor2;
  cursor2.MoveTo(*GetElementById("ib")->firstChild()->GetLayoutObject());
  EXPECT_EQ(GetLayoutObjectByElementId("ib"), cursor2.GetLayoutBlockFlow());
}

TEST_F(InlineCursorTest, NextForSameLayoutObject) {
  InlineCursor cursor = SetupCursor("<pre id=root>abc\ndef\nghi</pre>");
  cursor.MoveTo(*GetLayoutObjectByElementId("root")->SlowFirstChild());
  EXPECT_THAT(LayoutObjectToDebugStringList(cursor),
              ElementsAre("abc", "", "def", "", "ghi"));
}

// Test |NextForSameLayoutObject| with limit range set.
TEST_F(InlineCursorTest, NextForSameLayoutObjectWithRange) {
  // In this snippet, `<span>` wraps to 3 lines, and that there are 3 fragments
  // for `<span>`.
  SetBodyInnerHTML(R"HTML(
    <style>
    div {
      font-size: 10px;
      width: 5ch;
    }
    span {
      background: orange;
    }
    </style>
    <div id="root">
      <span id="span1">
        1111
        2222
        3333
      </span>
    </div>
  )HTML");
  LayoutBlockFlow* root =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("root"));
  InlineCursor cursor(*root);
  cursor.MoveToFirstLine();
  cursor.MoveToNextLine();
  InlineCursor line2 = cursor.CursorForDescendants();

  // Now |line2| is limited to the 2nd line. There should be only one framgnet
  // for `<span>` if we search using `line2`.
  LayoutObject* span1 = GetLayoutObjectByElementId("span1");
  line2.MoveTo(*span1);
  EXPECT_THAT(LayoutObjectToDebugStringList(line2), ElementsAre("#span1"));
}

TEST_F(InlineCursorTest, Sibling) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("a, b { background: gray; }");
  InlineCursor cursor =
      SetupCursor("<div id=root>abc<a>DEF<b>GHI</b></a>xyz</div>");
  TestPrevoiusSibling(cursor.CursorForDescendants());
  cursor.MoveToFirstChild();  // go to "abc"
  Vector<String> list = SiblingsToDebugStringList(cursor);
  EXPECT_THAT(list, ElementsAre("abc", "LayoutInline A", "xyz"));
}

TEST_F(InlineCursorTest, Sibling2) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("a, b { background: gray; }");
  InlineCursor cursor =
      SetupCursor("<div id=root><a>abc<b>def</b>xyz</a></div>");
  cursor.MoveToFirstChild();  // go to <a>abc</a>
  TestPrevoiusSibling(cursor.CursorForDescendants());
  cursor.MoveToFirstChild();  // go to "abc"
  Vector<String> list = SiblingsToDebugStringList(cursor);
  EXPECT_THAT(list, ElementsAre("abc", "LayoutInline B", "xyz"));
}

TEST_F(InlineCursorTest, NextSkippingChildren) {
  // TDOO(yosin): Remove <style> once FragmentItem don't do culled inline.
  InsertStyleElement("span { background: gray; }");
  SetBodyInnerHTML(R"HTML(
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
    </div>
  )HTML");

  LayoutBlockFlow* block_flow =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("root"));
  InlineCursor cursor(*block_flow);
  for (unsigned i = 0; i < 3; ++i)
    cursor.MoveToNext();
  EXPECT_EQ("text2", ToDebugString(cursor));
  Vector<String> list;
  while (true) {
    cursor.MoveToNextSkippingChildren();
    if (!cursor)
      break;
    list.push_back(ToDebugString(cursor));
  }
  EXPECT_THAT(list, ElementsAre("#span2", "text4", "text5"));
}

TEST_F(InlineCursorTest, EmptyOutOfFlow) {
  SetBodyInnerHTML(R"HTML(
    <div id=root>
      <span style="position: absolute"></span>
    </div>
  )HTML");

  LayoutBlockFlow* block_flow =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("root"));
  InlineCursor cursor(*block_flow);
  Vector<String> list = ToDebugStringList(cursor);
  EXPECT_THAT(list, ElementsAre());
}

TEST_F(InlineCursorTest, PositionForPointInChildHorizontalLTR) {
  LoadAhem();
  InsertStyleElement(
      "p {"
      "direction: ltr;"
      "font: 10px/20px Ahem;"
      "padding: 10px;"
      "writing-mode: horizontal-tb;"
      "}");
  InlineCursor cursor = SetupCursor("<p id=root>ab</p>");
  const auto& text = *To<Text>(GetElementById("root")->firstChild());
  ASSERT_TRUE(cursor.Current().IsLineBox());
  EXPECT_EQ(PhysicalRect(PhysicalOffset(10, 10), PhysicalSize(20, 20)),
            cursor.Current().RectInContainerFragment());

  cursor.MoveTo(*text.GetLayoutObject());
  EXPECT_EQ(PhysicalRect(PhysicalOffset(10, 15), PhysicalSize(20, 10)),
            cursor.Current().RectInContainerFragment());
  const PhysicalOffset left_top = cursor.Current().OffsetInContainerFragment();

  EXPECT_EQ(PositionWithAffinity(Position(text, 0)),
            cursor.PositionForPointInChild(left_top + PhysicalOffset(-5, 0)));
  EXPECT_EQ(PositionWithAffinity(Posit
"""


```