Response:
The user wants me to analyze a C++ source code file for the Chromium Blink engine. Specifically, the file `inline_layout_algorithm_test.cc`.

I need to address the following points in my response:

1. **List the functions of the file:** This involves understanding the purpose of the code and the tests it contains.
2. **Explain its relation to JavaScript, HTML, and CSS:**  I need to identify how the code interacts with these web technologies, providing specific examples.
3. **Provide examples of logical reasoning:** This requires finding parts of the code where assumptions are made and then illustrating them with hypothetical inputs and outputs.
4. **Illustrate common user/programming errors:** I need to identify potential pitfalls related to the functionality tested in the code.
5. **Summarize the file's functionality:** This will be a high-level overview of the file's purpose based on the analysis.

**Analysis of the provided code snippet:**

The code is a test suite (`InlineLayoutAlgorithmTest`) for the inline layout algorithm in Blink. It uses the Google Test framework. The tests cover various aspects of inline layout, including:

* **Line breaking:** How lines are broken and represented.
* **Inline box properties:** Borders, padding, and their application across line breaks.
* **Floats:** How inline content flows around floated elements.
* **`text-combine-upright`:** Handling of vertical text composition.
* **`initial-letter`:** Styling of the first letter of a block.
* **Text alignment and hanging punctuation:**  Specific tests for RTL text alignment in textareas.
* **`text-box-trim`:**  Testing the effect of this CSS property.

**Planning the response:**

I will structure the response as follows:

1. **General Functionality:** Describe the primary purpose of the file as a test suite for the inline layout algorithm.
2. **Relation to Web Technologies:** Provide examples for HTML (structure of test cases), CSS (styling properties tested), and indirectly JavaScript (as the layout engine supports the rendering of content manipulated by JS).
3. **Logical Reasoning:** Focus on a specific test case and outline the assumptions and expected outcomes.
4. **Common Errors:** Discuss potential issues users/developers might encounter related to the features being tested (e.g., unexpected line breaks, float behavior).
5. **Summary:** Concisely summarize the file's role.
这是对 `blink/renderer/core/layout/inline/inline_layout_algorithm_test.cc` 文件功能的归纳（第 1 部分）：

**主要功能:**

该文件是 Chromium Blink 引擎中 `inline` 布局算法的单元测试文件。它的主要功能是 **测试和验证 `inline` 布局算法的正确性和各种场景下的行为**。

具体来说，它包含了一系列的测试用例（以 `TEST_F` 开头），用于检验 `inline` 布局算法在处理不同 HTML 结构和 CSS 样式时的输出是否符合预期。这些测试涵盖了：

* **基本类型:**  测试空行和非空行的 `LineBoxFragment` 的类型判断。
* **`::first-line` 伪元素:** 验证 `::first-line` 伪元素对 `LineBoxFragment` 的类型和样式变体的影响。
* **行内块级元素 (`block-in-inline`):** 测试当块级元素嵌入到行内元素中时的布局行为，包括空块和有高度的块的情况。
* **断点标记 (`BreakToken`):**  测试布局算法如何使用断点标记在多次布局过程中进行迭代，以处理文本换行。
* **行内包含块中的浮动元素:** 验证当行内包含块中存在浮动元素时，空行的处理以及 box fragment 的生成。
* **内联盒子的边距和内边距 (`BoxForEndMargin`, `InlineBoxBorderPadding`):**  测试内联盒子的边框和内边距在多行布局中的应用，确保跨行的一致性。
* **容器的边距和内边距 (`ContainerBorderPadding`):**  测试包含行内元素的块级容器的边框和内边距的应用。
* **`vertical-align: bottom` 对替换元素的影响 (`VerticalAlignBottomReplaced`):**  测试 `vertical-align: bottom` 样式对行内替换元素（如 `<img>`）的垂直对齐方式的影响。
* **文本环绕浮动元素 (`TextFloatsAroundFloatsBefore`, `TextFloatsAroundInlineFloatThatFitsOnLine`, `TextFloatsAroundInlineFloatThatDoesNotFitOnLine`, `FloatsArePositionedWithRespectToTopEdgeAlignmentRule`):** 测试文本如何正确地环绕在不同位置和大小的浮动元素周围。
* **浮动元素的边距 (`PositionFloatsWithMargins`):**  验证布局算法在定位浮动元素时是否考虑了其边距。
* **墨水溢出 (`InkOverflow`):**  测试字形边界框导致墨水溢出的情况。
* **文本组合 (`TextCombineBasic`, `TextCombineFake`):** 测试 `text-combine-upright` 属性在垂直书写模式下的文本组合行为。
* **初始字母 (`InitialLetterEmpty`, `InitialLetterWithEmptyInline`):** 测试 `::first-letter` 伪元素和 `initial-letter` 属性在处理空内容或空行内元素时的行为。
* **行盒子的悬挂宽度 (`LineBoxWithHangingWidthRTLRightAligned`, `LineBoxWithHangingWidthRTLCenterAligned`):**  测试在 RTL（从右到左）文本对齐方式下，`textarea` 元素中尾随空格的悬挂宽度计算和行盒子的定位。
* **`text-box-trim` 属性和约束空间 (`TextBoxTrimConstraintSpace`):** 测试 `text-box-trim` CSS 属性对约束空间的影响，以及如何确定是否应该裁剪文本框的起始或结束空格。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:** 测试用例通过 `SetBodyInnerHTML` 函数设置不同的 HTML 结构，这些结构包含各种元素（如 `div`, `span`, `textarea`, `img`），用于模拟真实的网页内容。 例如，在测试 `Types` 时，设置了包含文本和包含空 `span` 的 `div` 元素：

  ```html
  <div id="normal">normal</div>
  <div id="empty"><span></span></div>
  ```

* **CSS:**  测试用例通过 `<style>` 标签或 `InsertStyleElement` 函数添加 CSS 样式，来影响元素的布局。例如，在测试 `TypesForFirstLine` 时，使用了 `::first-line` 伪元素来设置字体大小：

  ```css
  div::first-line { font-size: 2em; }
  ```

  测试还直接针对特定的 CSS 属性，如 `vertical-align`, `float`, `text-combine-upright`, `initial-letter`, `text-align`, 和 `text-box-trim`。

* **JavaScript:** 虽然这个测试文件本身是 C++ 代码，它测试的布局算法是浏览器渲染引擎的核心部分，负责将 HTML、CSS 转换为用户看到的页面。JavaScript 可以动态地修改 DOM 结构和 CSS 样式，而这个测试文件验证了在这些修改发生后，布局引擎是否能正确地重新计算和渲染页面。例如，在测试 `BlockInInlineAppend` 中，使用 JavaScript 的 DOM API (`appendChild`) 向容器中添加内容，并观察布局结果的变化。

**逻辑推理的假设输入与输出:**

以 `TEST_F(InlineLayoutAlgorithmTest, Types)` 为例：

**假设输入:**

```html
<!DOCTYPE html>
<div id="normal">normal</div>
<div id="empty"><span></span></div>
```

**逻辑推理:**

1. 布局引擎会为 `#normal` 和 `#empty` 这两个 `div` 元素创建 `LayoutBlockFlow` 对象。
2. 对于 `#normal`，由于它包含文本内容，其第一行的 `LineBoxFragment` 应该是非空的。
3. 对于 `#empty`，虽然它包含一个空的 `span`，但由于 `span` 是行内元素，且没有实际内容产生宽度，因此其第一行的 `LineBoxFragment` 应该是空的。

**预期输出:**

*   `normal.Current()->LineBoxFragment()->IsEmptyLineBox()` 返回 `false`。
*   `empty.Current()->LineBoxFragment()->IsEmptyLineBox()` 返回 `true`。

**涉及用户或编程常见的使用错误举例说明:**

* **CSS 属性理解错误:**  开发者可能错误地理解 `vertical-align` 属性对非替换元素的影响，例如认为它会像在表格单元格中一样工作。`MAYBE_VerticalAlignBottomReplaced` 测试用例验证了 `vertical-align: bottom` 对替换元素（如 `<img>`）的对齐行为，有助于开发者理解其正确用法。如果开发者期望对普通文本使用 `vertical-align: bottom` 来使其底部对齐，可能会得到意想不到的结果。

* **浮动元素布局误解:**  开发者可能不清楚浮动元素的行为，例如，当行内元素包含浮动元素时，浮动元素可能会被“提升”到行盒子的顶部。`TextFloatsAroundInlineFloatThatFitsOnLine` 和其他浮动相关的测试用例帮助验证了在各种情况下浮动元素的布局行为。一个常见的错误是期望浮动元素会像绝对定位元素一样不影响周围元素的布局，但实际上浮动元素会使周围的行内内容环绕它。

* **文本组合属性使用错误:**  开发者可能不熟悉 `text-combine-upright` 属性，并错误地假设它会像简单的文本旋转一样工作。`TextCombineBasic` 和 `TextCombineFake` 测试用例展示了 `text-combine-upright` 在垂直书写模式下的行为，帮助开发者正确使用该属性来实现文本组合效果。

**总结:**

总而言之，`inline_layout_algorithm_test.cc` 文件的主要功能是 **作为 Chromium Blink 引擎中 `inline` 布局算法的测试套件，通过大量的测试用例来确保该算法在各种 HTML 结构和 CSS 样式下都能正确地进行布局计算和渲染**。 这些测试覆盖了行内布局的各种细节，包括基本类型、伪元素、行内块级元素、浮动、文本对齐、文本组合等，并间接地与 JavaScript, HTML, CSS 的功能相关联。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/inline_layout_algorithm_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sstream>

#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/core/dom/tag_collection.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/layout/base_layout_algorithm_test.h"
#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/inline/inline_box_state.h"
#include "third_party/blink/renderer/core/layout/inline/inline_break_token.h"
#include "third_party/blink/renderer/core/layout/inline/inline_child_layout_context.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/physical_line_box_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {
namespace {

// Compute the result of the effects of the `text-box-trim` property.
struct TextBoxTrimResult {
  explicit TextBoxTrimResult(const LayoutBox& layout_object) {
    const LayoutResult* result = layout_object.GetCachedLayoutResult(nullptr);
    const ConstraintSpace& space = result->GetConstraintSpaceForCaching();
    should_trim_start = space.ShouldTextBoxTrimNodeStart();
    should_trim_end = space.ShouldTextBoxTrimNodeEnd();
  }

  bool should_trim_start;
  bool should_trim_end;
};

const PhysicalLineBoxFragment* FindBlockInInlineLineBoxFragment(
    Element* container) {
  InlineCursor cursor(*To<LayoutBlockFlow>(container->GetLayoutObject()));
  for (cursor.MoveToFirstLine(); cursor; cursor.MoveToNextLine()) {
    const PhysicalLineBoxFragment* fragment =
        cursor.Current()->LineBoxFragment();
    DCHECK(fragment);
    if (fragment->IsBlockInInline())
      return fragment;
  }
  return nullptr;
}

class InlineLayoutAlgorithmTest : public BaseLayoutAlgorithmTest {
 protected:
  static std::string AsFragmentItemsString(const LayoutBlockFlow& root) {
    std::ostringstream ostream;
    ostream << std::endl;
    for (InlineCursor cursor(root); cursor; cursor.MoveToNext()) {
      const auto& item = *cursor.CurrentItem();
      ostream << item << " " << item.RectInContainerFragment() << std::endl;
    }
    return ostream.str();
  }

  PhysicalRect TextAreaFirstLineRect(const char* id) {
    HTMLTextAreaElement* textarea = To<HTMLTextAreaElement>(GetElementById(id));
    DCHECK(textarea);

    InlineCursor cursor(*To<LayoutBlockFlow>(
        textarea->InnerEditorElement()->GetLayoutObject()));
    cursor.MoveToFirstLine();
    EXPECT_TRUE(cursor.IsNotNull());

    return PhysicalRect(cursor.Current().OffsetInContainerFragment(),
                        cursor.Current().Size());
  }
};

TEST_F(InlineLayoutAlgorithmTest, Types) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div id="normal">normal</div>
    <div id="empty"><span></span></div>
  )HTML");
  InlineCursor normal(
      *To<LayoutBlockFlow>(GetLayoutObjectByElementId("normal")));
  normal.MoveToFirstLine();
  EXPECT_FALSE(normal.Current()->LineBoxFragment()->IsEmptyLineBox());

  InlineCursor empty(*To<LayoutBlockFlow>(GetLayoutObjectByElementId("empty")));
  empty.MoveToFirstLine();
  EXPECT_TRUE(empty.Current()->LineBoxFragment()->IsEmptyLineBox());
}

TEST_F(InlineLayoutAlgorithmTest, TypesForFirstLine) {
  SetBodyInnerHTML(R"HTML(
    <style>
    div::first-line { font-size: 2em; }
    </style>
    <div id="normal">normal</div>
    <div id="empty"><span></span></div>
  )HTML");
  InlineCursor normal(
      *To<LayoutBlockFlow>(GetLayoutObjectByElementId("normal")));
  normal.MoveToFirstLine();
  EXPECT_FALSE(normal.Current()->LineBoxFragment()->IsEmptyLineBox());
  EXPECT_EQ(normal.Current().GetStyleVariant(), StyleVariant::kFirstLine);
  EXPECT_EQ(normal.Current()->LineBoxFragment()->GetStyleVariant(),
            StyleVariant::kFirstLine);

  InlineCursor empty(*To<LayoutBlockFlow>(GetLayoutObjectByElementId("empty")));
  empty.MoveToFirstLine();
  EXPECT_TRUE(empty.Current()->LineBoxFragment()->IsEmptyLineBox());
  EXPECT_EQ(empty.Current().GetStyleVariant(), StyleVariant::kFirstLine);
  EXPECT_EQ(empty.Current()->LineBoxFragment()->GetStyleVariant(),
            StyleVariant::kFirstLine);
}

TEST_F(InlineLayoutAlgorithmTest, TypesForBlockInInline) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div id="block-in-inline">
      <span><div>normal</div></span>
    </div>
    <div id="block-in-inline-empty">
      <span><div></div></span>
    </div>
    <div id="block-in-inline-height">
      <span><div style="height: 100px"></div></span>
    </div>
  )HTML");
  // Regular block-in-inline.
  InlineCursor block_in_inline(
      *To<LayoutBlockFlow>(GetLayoutObjectByElementId("block-in-inline")));
  block_in_inline.MoveToFirstLine();
  EXPECT_TRUE(block_in_inline.Current()->LineBoxFragment()->IsEmptyLineBox());
  EXPECT_FALSE(block_in_inline.Current()->LineBoxFragment()->IsBlockInInline());
  block_in_inline.MoveToNextLine();
  EXPECT_FALSE(block_in_inline.Current()->LineBoxFragment()->IsEmptyLineBox());
  EXPECT_TRUE(block_in_inline.Current()->LineBoxFragment()->IsBlockInInline());
  int block_count = 0;
  for (InlineCursor children = block_in_inline.CursorForDescendants(); children;
       children.MoveToNext()) {
    if (children.Current()->BoxFragment() &&
        children.Current()->BoxFragment()->IsBlockInInline())
      ++block_count;
  }
  EXPECT_EQ(block_count, 1);
  block_in_inline.MoveToNextLine();
  EXPECT_TRUE(block_in_inline.Current()->LineBoxFragment()->IsEmptyLineBox());
  EXPECT_FALSE(block_in_inline.Current()->LineBoxFragment()->IsBlockInInline());

  // If the block is empty and self-collapsing, |IsEmptyLineBox| should be set.
  InlineCursor block_in_inline_empty(*To<LayoutBlockFlow>(
      GetLayoutObjectByElementId("block-in-inline-empty")));
  block_in_inline_empty.MoveToFirstLine();
  block_in_inline_empty.MoveToNextLine();
  EXPECT_TRUE(
      block_in_inline_empty.Current()->LineBoxFragment()->IsEmptyLineBox());
  EXPECT_TRUE(
      block_in_inline_empty.Current()->LineBoxFragment()->IsBlockInInline());

  // Test empty but non-self-collapsing block in an inline box.
  InlineCursor block_in_inline_height(*To<LayoutBlockFlow>(
      GetLayoutObjectByElementId("block-in-inline-height")));
  block_in_inline_height.MoveToFirstLine();
  block_in_inline_height.MoveToNextLine();
  EXPECT_FALSE(
      block_in_inline_height.Current()->LineBoxFragment()->IsEmptyLineBox());
  EXPECT_TRUE(
      block_in_inline_height.Current()->LineBoxFragment()->IsBlockInInline());
}

TEST_F(InlineLayoutAlgorithmTest, BreakToken) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      html {
        font: 10px/1 Ahem;
      }
      #container {
        width: 50px; height: 20px;
      }
    </style>
    <div id=container>123 456 789</div>
  )HTML");

  // Perform 1st Layout.
  auto* block_flow =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  InlineNode inline_node(block_flow);
  LogicalSize size(LayoutUnit(50), LayoutUnit(20));

  ConstraintSpaceBuilder builder(
      WritingMode::kHorizontalTb,
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      /* is_new_fc */ false);
  builder.SetAvailableSize(size);
  ConstraintSpace constraint_space = builder.ToConstraintSpace();

  BoxFragmentBuilder container_builder(
      block_flow, block_flow->Style(), constraint_space,
      block_flow->Style()->GetWritingDirection());
  SimpleInlineChildLayoutContext context(inline_node, &container_builder);
  const LayoutResult* layout_result =
      inline_node.Layout(constraint_space, nullptr, nullptr, &context);
  const auto& line1 = layout_result->GetPhysicalFragment();
  EXPECT_TRUE(line1.GetBreakToken());

  // Perform 2nd layout with the break token from the 1st line.
  const LayoutResult* layout_result2 = inline_node.Layout(
      constraint_space, line1.GetBreakToken(), nullptr, &context);
  const auto& line2 = layout_result2->GetPhysicalFragment();
  EXPECT_TRUE(line2.GetBreakToken());

  // Perform 3rd layout with the break token from the 2nd line.
  const LayoutResult* layout_result3 = inline_node.Layout(
      constraint_space, line2.GetBreakToken(), nullptr, &context);
  const auto& line3 = layout_result3->GetPhysicalFragment();
  EXPECT_FALSE(line3.GetBreakToken());
}

// This test ensures box fragments are generated when necessary, even when the
// line is empty. One such case is when the line contains a containing box of an
// out-of-flow object.
TEST_F(InlineLayoutAlgorithmTest,
       EmptyLineWithOutOfFlowInInlineContainingBlock) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    oof-container {
      position: relative;
    }
    oof {
      position: absolute;
      width: 100px;
      height: 100px;
    }
    html, body { margin: 0; }
    html {
      font-size: 10px;
    }
    </style>
    <div id=container>
      <oof-container id=target>
        <oof></oof>
      </oof-container>
    </div>
  )HTML");
  auto* block_flow =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  const PhysicalBoxFragment* container = block_flow->GetPhysicalFragment(0);
  ASSERT_TRUE(container);
  EXPECT_EQ(LayoutUnit(), container->Size().height);

  InlineCursor line_box(*block_flow);
  ASSERT_TRUE(line_box);
  ASSERT_TRUE(line_box.Current().IsLineBox());
  EXPECT_EQ(PhysicalSize(), line_box.Current().Size());

  InlineCursor off_container(line_box);
  off_container.MoveToNext();
  ASSERT_TRUE(off_container);
  ASSERT_EQ(GetLayoutObjectByElementId("target"),
            off_container.Current().GetLayoutObject());
  EXPECT_EQ(PhysicalSize(), off_container.Current().Size());
}

// This test ensures that if an inline box generates (or does not generate) box
// fragments for a wrapped line, it should consistently do so for other lines
// too, when the inline box is fragmented to multiple lines.
TEST_F(InlineLayoutAlgorithmTest, BoxForEndMargin) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    html, body { margin: 0; }
    #container {
      font: 10px/1 Ahem;
      width: 50px;
    }
    span {
      border-right: 10px solid blue;
    }
    </style>
    <!-- This line wraps, and only 2nd line has a border. -->
    <div id=container>12 <span id=span>3 45</span> 6</div>
  )HTML");
  auto* block_flow =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  InlineCursor line_box(*block_flow);
  ASSERT_TRUE(line_box) << "line_box is at start of first line.";
  ASSERT_TRUE(line_box.Current().IsLineBox());
  line_box.MoveToNextLine();
  ASSERT_TRUE(line_box) << "line_box is at start of second line.";
  InlineCursor cursor(line_box);
  ASSERT_TRUE(line_box.Current().IsLineBox());
  cursor.MoveToNext();
  ASSERT_TRUE(cursor);
  EXPECT_EQ(GetLayoutObjectByElementId("span"),
            cursor.Current().GetLayoutObject());

  // The <span> generates a box fragment for the 2nd line because it has a
  // right border. It should also generate a box fragment for the 1st line even
  // though there's no borders on the 1st line.
  const PhysicalBoxFragment* box_fragment = cursor.Current().BoxFragment();
  ASSERT_TRUE(box_fragment);
  EXPECT_EQ(PhysicalFragment::kFragmentBox, box_fragment->Type());

  line_box.MoveToNextLine();
  ASSERT_FALSE(line_box) << "block_flow has two lines.";
}

TEST_F(InlineLayoutAlgorithmTest, InlineBoxBorderPadding) {
  SetBodyInnerHTML(R"HTML(
    <style>
    div {
      font-size: 10px;
      line-height: 10px;
    }
    span {
      border-left: 1px solid blue;
      border-top: 2px solid blue;
      border-right: 3px solid blue;
      border-bottom: 4px solid blue;
      padding-left: 5px;
      padding-top: 6px;
      padding-right: 7px;
      padding-bottom: 8px;
    }
    </style>
    <div id="container">
      <span id="span">test<br>test</span>
    </div>
  )HTML");
  auto* block_flow =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  InlineCursor cursor(*block_flow);
  const LayoutObject* span = GetLayoutObjectByElementId("span");
  cursor.MoveTo(*span);
  const FragmentItem& item1 = *cursor.Current();
  const PhysicalBoxFragment* box1 = item1.BoxFragment();
  ASSERT_TRUE(box1);
  const PhysicalBoxStrut borders1 = box1->Borders();
  const PhysicalBoxStrut padding1 = box1->Padding();
  int borders_and_padding1[] = {
      borders1.left.ToInt(),   borders1.top.ToInt(),   borders1.right.ToInt(),
      borders1.bottom.ToInt(), padding1.left.ToInt(),  padding1.top.ToInt(),
      padding1.right.ToInt(),  padding1.bottom.ToInt()};
  EXPECT_THAT(borders_and_padding1,
              testing::ElementsAre(1, 2, 0, 4, 5, 6, 0, 8));
  EXPECT_EQ(box1->ContentOffset(), PhysicalOffset(6, 8));
  EXPECT_EQ(item1.ContentOffsetInContainerFragment(),
            item1.OffsetInContainerFragment() + box1->ContentOffset());

  cursor.MoveToNextForSameLayoutObject();
  const FragmentItem& item2 = *cursor.Current();
  const PhysicalBoxFragment* box2 = item2.BoxFragment();
  ASSERT_TRUE(box2);
  const PhysicalBoxStrut borders2 = box2->Borders();
  const PhysicalBoxStrut padding2 = box2->Padding();
  int borders_and_padding2[] = {
      borders2.left.ToInt(),   borders2.top.ToInt(),   borders2.right.ToInt(),
      borders2.bottom.ToInt(), padding2.left.ToInt(),  padding2.top.ToInt(),
      padding2.right.ToInt(),  padding2.bottom.ToInt()};
  EXPECT_THAT(borders_and_padding2,
              testing::ElementsAre(0, 2, 3, 4, 0, 6, 7, 8));
  EXPECT_EQ(box2->ContentOffset(), PhysicalOffset(0, 8));
  EXPECT_EQ(item2.ContentOffsetInContainerFragment(),
            item2.OffsetInContainerFragment() + box2->ContentOffset());
}

// A block with inline children generates fragment tree as follows:
// - A box fragment created by BlockNode
//   - A wrapper box fragment created by InlineNode
//     - Line box fragments.
// This test verifies that borders/paddings are applied to the wrapper box.
TEST_F(InlineLayoutAlgorithmTest, ContainerBorderPadding) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    html, body { margin: 0; }
    div {
      padding-left: 5px;
      padding-top: 10px;
      display: flow-root;
    }
    </style>
    <div id=container>test</div>
  )HTML");

  const auto* layout_result =
      GetLayoutBoxByElementId("container")->GetSingleCachedLayoutResult();

  EXPECT_TRUE(layout_result->BfcBlockOffset().has_value());
  EXPECT_EQ(0, *layout_result->BfcBlockOffset());
  EXPECT_EQ(0, layout_result->BfcLineOffset());

  const auto& fragment =
      To<PhysicalBoxFragment>(layout_result->GetPhysicalFragment());
  EXPECT_EQ(fragment.ContentOffset(), PhysicalOffset(5, 10));
  PhysicalOffset line_offset = fragment.Children()[0].Offset();
  EXPECT_EQ(line_offset, PhysicalOffset(5, 10));
}

// The test leaks memory. crbug.com/721932
#if defined(ADDRESS_SANITIZER)
#define MAYBE_VerticalAlignBottomReplaced DISABLED_VerticalAlignBottomReplaced
#else
#define MAYBE_VerticalAlignBottomReplaced VerticalAlignBottomReplaced
#endif
TEST_F(InlineLayoutAlgorithmTest, MAYBE_VerticalAlignBottomReplaced) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    html { font-size: 10px; }
    img { vertical-align: bottom; }
    #container { display: flow-root; }
    </style>
    <div id=container><img src="#" width="96" height="96"></div>
  )HTML");
  auto* block_flow =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  InlineCursor cursor(*block_flow);
  ASSERT_TRUE(cursor);
  EXPECT_EQ(LayoutUnit(96), cursor.Current().Size().height);
  cursor.MoveToNext();
  ASSERT_TRUE(cursor);
  EXPECT_EQ(LayoutUnit(0), cursor.Current().OffsetInContainerFragment().top)
      << "Offset top of <img> should be zero.";
}

// Verifies that text can flow correctly around floats that were positioned
// before the inline block.
TEST_F(InlineLayoutAlgorithmTest, TextFloatsAroundFloatsBefore) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      * {
        font-family: "Arial", sans-serif;
        font-size: 20px;
      }
      #container {
        height: 200px; width: 200px; outline: solid blue;
      }
      #left-float1 {
        float: left; width: 30px; height: 30px; background-color: blue;
      }
      #left-float2 {
        float: left; width: 10px; height: 10px;
        background-color: purple;
      }
      #right-float {
        float: right; width: 40px; height: 40px; background-color: yellow;
      }
    </style>
    <div id="container">
      <div id="left-float1"></div>
      <div id="left-float2"></div>
      <div id="right-float"></div>
      <span id="text">The quick brown fox jumps over the lazy dog</span>
    </div>
  )HTML");

  const auto& html_fragment =
      To<LayoutBox>(GetDocument()
                        .getElementsByTagName(AtomicString("html"))
                        ->item(0)
                        ->GetLayoutObject())
          ->GetSingleCachedLayoutResult()
          ->GetPhysicalFragment();

  auto* body_fragment =
      To<PhysicalBoxFragment>(html_fragment.Children()[0].get());
  auto* container_fragment =
      To<PhysicalBoxFragment>(body_fragment->Children()[0].get());
  Vector<PhysicalOffset> line_offsets;
  for (const auto& child : container_fragment->Children()) {
    if (!child->IsLineBox())
      continue;

    line_offsets.push_back(child.Offset());
  }

  // Line break points may vary by minor differences in fonts.
  // The test is valid as long as we have 3 or more lines and their positions
  // are correct.
  EXPECT_GE(line_offsets.size(), 3UL);

  // 40 = #left-float1' width 30 + #left-float2 10
  EXPECT_EQ(LayoutUnit(40), line_offsets[0].left);

  // 40 = #left-float1' width 30
  EXPECT_EQ(LayoutUnit(30), line_offsets[1].left);
  EXPECT_EQ(LayoutUnit(), line_offsets[2].left);
}

// Verifies that text correctly flows around the inline float that fits on
// the same text line.
TEST_F(InlineLayoutAlgorithmTest, TextFloatsAroundInlineFloatThatFitsOnLine) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      * {
        font-family: "Arial", sans-serif;
        font-size: 18px;
      }
      #container {
        height: 200px; width: 200px; outline: solid orange;
      }
      #narrow-float {
        float: left; width: 30px; height: 30px; background-color: blue;
      }
    </style>
    <div id="container">
      <span id="text">
        The quick <div id="narrow-float"></div> brown fox jumps over the lazy
      </span>
    </div>
  )HTML");

  auto* block_flow =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  const PhysicalBoxFragment* block_box = block_flow->GetPhysicalFragment(0);
  ASSERT_TRUE(block_box);

  // Two lines.
  ASSERT_EQ(2u, block_box->Children().size());
  PhysicalOffset first_line_offset = block_box->Children()[1].Offset();

  // 30 == narrow-float's width.
  EXPECT_EQ(LayoutUnit(30), first_line_offset.left);

  Element* span = GetElementById("text");
  // 38 == narrow-float's width + body's margin.
  EXPECT_EQ(LayoutUnit(38), span->OffsetLeft());

  Element* narrow_float = GetElementById("narrow-float");
  // 8 == body's margin.
  EXPECT_EQ(8, narrow_float->OffsetLeft());
  EXPECT_EQ(8, narrow_float->OffsetTop());
}

// Verifies that the inline float got pushed to the next line if it doesn't
// fit the current line.
TEST_F(InlineLayoutAlgorithmTest,
       TextFloatsAroundInlineFloatThatDoesNotFitOnLine) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      * {
        font-family: "Arial", sans-serif;
        font-size: 19px;
      }
      #container {
        height: 200px; width: 200px; outline: solid orange;
      }
      #wide-float {
        float: left; width: 160px; height: 30px; background-color: red;
      }
    </style>
    <div id="container">
      <span id="text">
        The quick <div id="wide-float"></div> brown fox jumps over the lazy dog
      </span>
    </div>
  )HTML");

  Element* wide_float = GetElementById("wide-float");
  // 8 == body's margin.
  EXPECT_EQ(8, wide_float->OffsetLeft());
}

// Verifies that if an inline float pushed to the next line then all others
// following inline floats positioned with respect to the float's top edge
// alignment rule.
TEST_F(InlineLayoutAlgorithmTest,
       FloatsArePositionedWithRespectToTopEdgeAlignmentRule) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      * {
        font-family: "Arial", sans-serif;
        font-size: 19px;
      }
      #container {
        height: 200px; width: 200px; outline: solid orange;
      }
      #left-narrow {
        float: left; width: 5px; height: 30px; background-color: blue;
      }
      #left-wide {
        float: left; width: 160px; height: 30px; background-color: red;
      }
    </style>
    <div id="container">
      <span id="text">
        The quick <div id="left-wide"></div> brown <div id="left-narrow"></div>
        fox jumps over the lazy dog
      </span>
    </div>
  )HTML");
  Element* wide_float = GetElementById("left-wide");
  // 8 == body's margin.
  EXPECT_EQ(8, wide_float->OffsetLeft());

  Element* narrow_float = GetElementById("left-narrow");
  // 160 float-wide's width + 8 body's margin.
  EXPECT_EQ(160 + 8, narrow_float->OffsetLeft());

  // On the same line.
  EXPECT_EQ(wide_float->OffsetTop(), narrow_float->OffsetTop());
}

// Block-in-inline is not reusable. See |EndOfReusableItems|.
TEST_F(InlineLayoutAlgorithmTest, BlockInInlineAppend) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      :root {
        font-size: 10px;
      }
      #container {
        width: 10ch;
      }
    </style>
    <div id="container">
      <span id="span">
        12345678
        <div>block</div>
        12345678
      </span>
      12345678
    </div>
  )HTML");
  Element* container_element = GetElementById("container");
  const PhysicalLineBoxFragment* before_append =
      FindBlockInInlineLineBoxFragment(container_element);
  ASSERT_TRUE(before_append);

  Document& doc = GetDocument();
  container_element->appendChild(doc.createTextNode("12345678"));
  UpdateAllLifecyclePhasesForTest();
  const PhysicalLineBoxFragment* after_append =
      FindBlockInInlineLineBoxFragment(container_element);
  EXPECT_NE(before_append, after_append);
}

// Verifies that InlineLayoutAlgorithm positions floats with respect to their
// margins.
TEST_F(InlineLayoutAlgorithmTest, PositionFloatsWithMargins) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      #container {
        height: 200px; width: 200px; outline: solid orange;
      }
      #left {
        float: left; width: 5px; height: 30px; background-color: blue;
        margin: 10%;
      }
    </style>
    <div id="container">
      <span id="text">
        The quick <div id="left"></div> brown fox jumps over the lazy dog
      </span>
    </div>
  )HTML");
  Element* span = GetElementById("text");
  // 53 = sum of left's inline margins: 40 + left's width: 5 + body's margin: 8
  EXPECT_EQ(LayoutUnit(53), span->OffsetLeft());
}

// Test glyph bounding box causes ink overflow.
TEST_F(InlineLayoutAlgorithmTest, InkOverflow) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      #container {
        font: 20px/.5 Ahem;
        display: flow-root;
      }
    </style>
    <div id="container">Hello</div>
  )HTML");
  auto* block_flow =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  const PhysicalBoxFragment& box_fragment = *block_flow->GetPhysicalFragment(0);
  EXPECT_EQ(LayoutUnit(10), box_fragment.Size().height);

  InlineCursor cursor(*block_flow);
  PhysicalRect ink_overflow = cursor.Current().InkOverflowRect();
  EXPECT_EQ(LayoutUnit(-5), ink_overflow.offset.top);
  EXPECT_EQ(LayoutUnit(20), ink_overflow.size.height);
}

// See also InlineLayoutAlgorithmTest.TextCombineFake
TEST_F(InlineLayoutAlgorithmTest, TextCombineBasic) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 100px/110px Ahem; }"
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>a<c id=target>01234</c>b</div>");

  EXPECT_EQ(R"DUMP(
{Line #descendants=5 LTR Standard} "0,0 110x300"
{Text 0-1 LTR Standard} "5,0 100x100"
{Box #descendants=2 Standard} "5,100 100x100"
{Box #descendants=1 AtomicInlineLTR Standard} "5,100 100x100"
{Text 2-3 LTR Standard} "5,200 100x100"
)DUMP",
            AsFragmentItemsString(
                *To<LayoutBlockFlow>(GetLayoutObjectByElementId("root"))));

  EXPECT_EQ(R"DUMP(
{Line #descendants=2 LTR Standard} "0,0 100x100"
{Text 0-5 LTR Standard} "0,0 500x100"
)DUMP",
            AsFragmentItemsString(*To<LayoutBlockFlow>(
                GetLayoutObjectByElementId("target")->SlowFirstChild())));
}

// See also InlineLayoutAlgorithmTest.TextCombineBasic
TEST_F(InlineLayoutAlgorithmTest, TextCombineFake) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 100px/110px Ahem; }"
      "c {"
      "  display: inline-block;"
      "  width: 1em; height: 1em;"
      "  writing-mode: horizontal-tb;"
      "}"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div id=root>a<c id=target>0</c>b</div>");

  EXPECT_EQ(R"DUMP(
{Line #descendants=4 LTR Standard} "0,0 110x300"
{Text 0-1 LTR Standard} "5,0 100x100"
{Box #descendants=1 AtomicInlineLTR Standard} "5,100 100x100"
{Text 2-3 LTR Standard} "5,200 100x100"
)DUMP",
            AsFragmentItemsString(
                *To<LayoutBlockFlow>(GetLayoutObjectByElementId("root"))));

  EXPECT_EQ(R"DUMP(
{Line #descendants=2 LTR Standard} "0,0 100x110"
{Text 0-1 LTR Standard} "0,5 100x100"
)DUMP",
            AsFragmentItemsString(
                *To<LayoutBlockFlow>(GetLayoutObjectByElementId("target"))));
}

// http://crbug.com/1413969
TEST_F(InlineLayoutAlgorithmTest, InitialLetterEmpty) {
  LoadAhem();
  InsertStyleElement(
      "body { font: 10px/15px Ahem; }"
      "#sample::first-letter { initial-letter: 3; }");
  SetBodyInnerHTML("<div id=sample><span> </span></div>");
  const char* const expected = R"DUMP(
{Line #descendants=2 LTR Standard} "0,0 0x0"
{Box #descendants=1 Standard} "0,0 0x0"
)DUMP";
  EXPECT_EQ(expected, AsFragmentItemsString(*To<LayoutBlockFlow>(
                          GetLayoutObjectByElementId("sample"))));
}

// http://crbug.com/1420168
TEST_F(InlineLayoutAlgorithmTest, InitialLetterWithEmptyInline) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  LoadAhem();
  InsertStyleElement(
      "body { font: 20px/24px Ahem; }"
      "div::first-letter { initial-letter: 3; }");
  SetBodyInnerHTML("<div id=sample>x<span></span></div>");
  const char* const expected = R"DUMP(
{Line #descendants=3 LTR Standard} "0,0 80x0"
{Box #descendants=1 AtomicInlineLTR Standard} "0,2 80x80"
{Box #descendants=1 Standard} "80,-16 0x20"
)DUMP";
  EXPECT_EQ(expected, AsFragmentItemsString(*To<LayoutBlockFlow>(
                          GetLayoutObjectByElementId("sample"))));
}

TEST_F(InlineLayoutAlgorithmTest, LineBoxWithHangingWidthRTLRightAligned) {
  LoadAhem();
  InsertStyleElement(
      "textarea {"
      "  width: 100px;"
      "  text-align: right;"
      "  font: 10px/10px Ahem;"
      "}");
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <textarea dir="rtl" id="a">abc  </textarea>
    <textarea dir="rtl" id="b">abc  nextLine</textarea>
    <textarea dir="rtl" id="c">abc        </textarea>
    <textarea dir="rtl" id="d">abc        nextLine</textarea>
  )HTML");

  // Trailing spaces conditionally hang since the line is followed by a line
  // break, and the line doesn't overflow, so they as treated as not hanging.
  EXPECT_EQ(PhysicalRect(50, 0, 50, 10), TextAreaFirstLineRect("a"));

  // The hanging width doesn't overflow, and it unconditionally hangs because
  // it's not followed by a line break.
  EXPECT_EQ(PhysicalRect(70, 0, 30, 10), TextAreaFirstLineRect("b"));

  // Trailing spaces conditionally hang since the line is followed by a line
  // break, and the line overflows, so only the overflowing width hangs.
  EXPECT_EQ(PhysicalRect(0, 0, 100, 10), TextAreaFirstLineRect("c"));

  // The hanging width overflows, and it unconditionally hangs because
  // it's not followed by a line break.
  EXPECT_EQ(PhysicalRect(70, 0, 30, 10), TextAreaFirstLineRect("d"));
}

TEST_F(InlineLayoutAlgorithmTest, LineBoxWithHangingWidthRTLCenterAligned) {
  LoadAhem();
  InsertStyleElement(
      "textarea {"
      "  width: 100px;"
      "  text-align: center;"
      "  font: 10px/10px Ahem;"
      "}");
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <textarea dir="rtl" id="a">abc  </textarea>
    <textarea dir="rtl" id="b">abc  nextLine</textarea>
    <textarea dir="rtl" id="c">abc      </textarea>
    <textarea dir="rtl" id="d">abc      nextLine</textarea>
    <textarea dir="rtl" id="e">abc        </textarea>
    <textarea dir="rtl" id="f">abc        nextLine</textarea>
  )HTML");

  // The line size is 30px and the trailing spaces are 20px. For a, those spaces
  // conditionally hang, and since the line doesn't overflow, they don't
  // actually hang. Therefore, the rectangle containing the line and trailing
  // spaces is centered, so its left edge is at (100 - 30 - 20)/2 = 25.
  // For b, those spaces hang unconditionally, so the rectangle containing the
  // line without the trailing spaces is centered, with its left edge at
  // (100 - 30)/2 = 35.
  EXPECT_EQ(PhysicalRect(25, 0, 50, 10), TextAreaFirstLineRect("a"));
  EXPECT_EQ(PhysicalRect(35, 0, 30, 10), TextAreaFirstLineRect("b"));

  // The line size is 30px and the trailing spaces are 60px. For c, those spaces
  // conditionally hang, and since the line doesn't overflow, they don't
  // actually hang. Therefore, the rectangle containing the line and trailing
  // spaces is centered, so its left edge is at (100 - 30 - 60)/2 = 5.
  // For d, those spaces hang unconditionally, so the rectangle containing the
  // line without the trailing spaces is centered, with its left edge at
  // (100 - 30)/2 = 35.
  EXPECT_EQ(PhysicalRect(5, 0, 90, 10), TextAreaFirstLineRect("c"));
  EXPECT_EQ(PhysicalRect(35, 0, 30, 10), TextAreaFirstLineRect("d"));

  // The line size is 30px and the trailing spaces are 80px. For e, those spaces
  // conditionally hang, so only the 10px that overflow the line actually hang.
  // Therefore, the rectangle containing the line and non-hanging spaces is
  // centered, so its left edge is at (100 - 30 - 70)/2 = 0.
  // For b, those spaces hang unconditionally, so the rectangle containing the
  // line without the trailing spaces is centered, with its left edge at
  // (100 - 30)/2 = 35.
  EXPECT_EQ(PhysicalRect(0, 0, 100, 10), TextAreaFirstLineRect("e"));
  EXPECT_EQ(PhysicalRect(35, 0, 30, 10), TextAreaFirstLineRect("f"));
}

TEST_F(InlineLayoutAlgorithmTest, TextBoxTrimConstraintSpace) {
  ScopedCSSTextBoxTrimForTest enable_text_box_trim(true);
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div id="parent" style="text-box-trim: trim-both; position: relative">
      <div id="abs1" style="position: absolute">abs1</div>
      <div id="float1" style="float: left">float1</div>
      <div id="empty_before"> </div>
      <div id="nested_empty_before">
        <div id="nested_empty_before_child"> </div>
      </div>
      <div>
        <div id="middle">middle<br>middle L2</div>
      </div>
      <div id="nested_empty_after">
        <div id="nested_empty_after_child"> </div>
      </div>
      <div id="empty_after"> </div>
      <div id="abs2" style="position: absolute">abs1</div>
      <div id="float2" style="float: left">float1</div>
    </div>
  )HTML");

  const TextBoxTrimResult parent{*GetLayoutBlockFlowByElementId("parent")};
  EXPECT_FALSE(parent.should_trim_start);
  EXPECT_FALSE(parent.should_trim_end);

  // `ShouldTextBoxTrim*` should be set only to in-flow children.
  for (const char* id : {"abs1", "abs2", "float1", "float2"}) {
    const TextBoxTrimResult result{*GetLayoutBlockFlowByElementId(id)};
    EXPECT_FALSE(result.should_trim_start) << id;
    EXPECT_FALSE(result.should_trim_end) << id;
  }

  // The first formatted line has to be inside the first in-flow block child, or
  // there is no first formatted line.
  const TextBoxTrimResult empty_before{
      *GetLayoutBlockFlowByElementId("empty_before")};
  EXPECT_TRUE(empty_befor
```