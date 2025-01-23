Response:
The user wants to understand the functionality of the C++ source code file `fragment_item_test.cc`. I need to analyze the code and explain its purpose, highlighting connections to web technologies (HTML, CSS, JavaScript), logical deductions (if any), and potential user/programming errors.

**Plan:**

1. **Identify the core purpose of the file:**  The file name and `#include` statements clearly indicate it's a unit test file for the `FragmentItem` class in the Blink rendering engine.
2. **Break down the test structure:**  The file uses the Google Test framework. I need to identify the test fixtures (`FragmentItemTest`, `FragmentItemInsertTest`, `FragmentItemRemoveTest`) and individual test cases (e.g., `CopyMove`, `BasicText`).
3. **Analyze individual test cases:** For each test case, determine what aspects of `FragmentItem` functionality it's verifying.
4. **Connect to web technologies:**  Relate the tested `FragmentItem` features to how they manifest in HTML, CSS, and JavaScript interactions.
5. **Identify logical reasoning:**  If a test case involves setting up a specific scenario and asserting expected outcomes, explain the underlying logic.
6. **Pinpoint potential errors:**  Based on the tested functionalities, consider common mistakes developers might make when working with layout and rendering concepts.
这个文件 `fragment_item_test.cc` 是 Chromium Blink 引擎中的一个单元测试文件。它的主要功能是 **测试 `FragmentItem` 类的各种功能和行为**。`FragmentItem` 是 Blink 渲染引擎中用于表示在布局过程中生成的内联内容的片段的类。

以下是该文件功能的详细说明，并结合了与 JavaScript、HTML 和 CSS 的关系：

**1. 测试 `FragmentItem` 的基本操作:**

*   **复制和移动 (CopyMove):** 测试 `FragmentItem` 对象的拷贝构造函数和移动构造函数是否正确工作，包括其内部成员，如 `LineBoxFragment` (用于表示行盒子的片段) 和 `TextShapeResult` (用于表示文本的形状)。
    *   **关系:**  当浏览器渲染 HTML 并进行布局时，会创建 `FragmentItem` 对象来表示文本、行框和其他内联元素。正确的复制和移动语义对于性能和内存管理至关重要。
    *   **假设输入与输出:** 创建一个包含文本内容的 `div` 元素，布局后会生成对应的 `FragmentItem`。测试复制和移动操作后，新的 `FragmentItem` 对象应该拥有与原始对象相同的 `LineBoxFragment` 或 `TextShapeResult`。
*   **基本文本处理 (BasicText):** 测试对于简单的文本内容，`FragmentItem` 是否能正确创建，并记录其在容器片段中的偏移量，以及是否为节点（例如 `LayoutText`）的第一个或最后一个片段。
    *   **关系:** 当 HTML 中包含文本节点时，渲染引擎会为这些文本生成 `FragmentItem`。这个测试确保了 `FragmentItem` 能正确表示文本在布局中的位置。
    *   **假设输入与输出:**  一个包含多行文本的 `div` 元素。输出会检查每个文本 `FragmentItem` 的 `OffsetInContainerFragment` 是否与其在布局中的位置对应，并检查 `IsFirstForNode` 和 `IsLastForNode` 标记是否正确。
*   **RTL 文本处理 (RtlText):** 测试对于从右到左 (RTL) 的文本，`FragmentItem` 是否能正确处理文本的顺序和片段的标记。
    *   **关系:**  处理如阿拉伯语或希伯来语等 RTL 语言时，文本的渲染顺序与 LTR 语言不同。此测试确保 `FragmentItem` 能正确处理这种情况。
    *   **假设输入与输出:**  包含 RTL 文本的 `span` 元素。输出会检查文本 `FragmentItem` 的顺序和内容是否符合 RTL 布局规则。
*   **基本内联盒子处理 (BasicInlineBox):** 测试对于 `<span>` 等内联盒子元素，`FragmentItem` 是否能正确创建，并记录其在容器片段中的偏移量和墨水溢出区域 (`InkOverflowRect`)。
    *   **关系:**  `<span>` 元素是常见的内联元素。此测试验证了 `FragmentItem` 能正确表示这些元素的布局信息。
    *   **假设输入与输出:**  包含多个 `<span>` 元素的 `div`。输出会检查每个 `<span>` 的 `FragmentItem` 的位置和大小信息。
*   **被裁剪的内联盒子处理 (CulledInlineBox):** 测试当内联盒子由于某些原因（例如没有背景）被裁剪时，`FragmentItem` 的处理情况。
    *   **关系:** 某些情况下，内联盒子可能不会生成 `FragmentItem`，但其布局信息仍然需要计算。此测试验证了即使没有 `FragmentItem`，相关的布局计算仍然正确。
    *   **假设输入与输出:** 类似于 `BasicInlineBox`，但 `<span>` 没有背景色。输出会检查是否没有为 `<span>` 创建 `FragmentItem`，但其绝对包围盒 (`AbsoluteBoundingBoxRect`) 仍然正确。
*   **自绘制内联盒子处理 (SelfPaintingInlineBox):** 测试当一个内联盒子（例如，设置了 `opacity`）需要自身绘制时，`FragmentItem` 的墨水溢出是否能正确计算。
    *   **关系:**  对于需要创建独立绘制层的元素，其墨水溢出计算可能需要特殊处理。此测试确保 `FragmentItem` 在这种情况下能正确工作。
    *   **假设输入与输出:** 一个设置了 `opacity` 的 `<span>` 元素。测试会修改其子元素的视觉溢出，并检查父 `<span>` 的 `FragmentItem` 是否重新计算了墨水溢出。
*   **起始偏移量 (StartOffsetInContainer):** 测试 `FragmentItem` 的 `StartOffsetInContainer` 方法是否能正确返回片段在容器中的起始偏移量，尤其是在存在软连字符 (`&shy;`) 的情况下。
    *   **关系:**  在处理文本布局时，需要知道每个片段在容器中的准确位置。此测试确保 `FragmentItem` 能提供正确的信息。
    *   **假设输入与输出:** 包含软连字符和内联元素的文本。输出会检查不同 `FragmentItem` 的 `StartOffsetInContainer` 的返回值是否正确。
*   **省略号原子内联元素处理 (EllipsizedAtomicInline):** 测试当一个原子内联元素（如 `inline-block`）被省略号裁剪时，`FragmentItem` 的 `IsLastForNode` 标记是否正确设置。
    *   **关系:**  当文本溢出并显示省略号时，需要正确标记元素的最后一个片段。此测试验证了 `FragmentItem` 在这种复杂情况下也能正确处理。
    *   **假设输入与输出:**  一个包含宽度超出容器的 `inline-block` 元素的 `div`，并设置了 `text-overflow: ellipsis;`。输出会检查代表 `inline-block` 元素的 `FragmentItem` 的 `IsLastForNode` 标记是否正确。
*   **行片段 ID (LineFragmentId):** 测试对于多列布局，每一行的 `FragmentItem` 是否分配了正确的唯一 ID。
    *   **关系:**  在多列布局中，需要区分不同列中的行。此测试确保 `FragmentItem` 能正确标识每一行。
    *   **假设输入与输出:**  一个使用 `columns` CSS 属性的多列布局。输出会检查每一行对应的 `FragmentItem` 的 `FragmentId` 是否按顺序递增。
*   **轮廓矩形 (Outline):** 测试 `FragmentItem` 是否能正确计算包含内联盒子的轮廓矩形。
    *   **关系:**  在绘制轮廓或处理焦点等视觉效果时，需要知道元素的轮廓范围。此测试验证了 `FragmentItem` 能提供正确的轮廓信息。
    *   **假设输入与输出:** 包含嵌套内联盒子的结构。输出会检查计算出的轮廓矩形是否覆盖了所有相关的盒子。

**2. 测试插入和删除节点时 `FragmentItem` 的行为:**

*   **标记行盒子为脏 (MarkLineBoxesDirtyOnInsert/OnAppend/OnRemove):** 这部分测试当在包含内联内容的容器中插入或删除节点时，渲染引擎是否正确地将相关的行盒子标记为需要重新布局（"脏"）。
    *   **关系:**  DOM 结构的改变会影响布局。这些测试确保了当 DOM 发生变化时，渲染引擎能正确识别需要重新布局的区域。
    *   **假设输入与输出:**  包含文本和内联元素的 `div` 元素。分别测试在不同位置插入和删除各种类型的节点（文本节点、`<span>` 元素、浮动元素、绝对定位元素）。输出会检查 `TestFirstDirtyLineIndex` 函数的结果，该函数会检查需要重新布局的起始行索引。
*   **标记行盒子为脏的其他情况:**  还测试了由于空格折叠、元素需要重新布局 (`NeedsLayout`) 等情况导致行盒子需要重新布局的情况。
    *   **关系:**  这些测试涵盖了更复杂的布局场景，确保渲染引擎在各种情况下都能正确处理布局失效。
    *   **假设输入与输出:**  各种复杂的 HTML 结构和 CSS 样式，用于触发不同的布局失效情况。输出同样会检查 `TestFirstDirtyLineIndex` 的结果。

**3. 辅助函数和测试基础设施:**

*   **`RenderingTest`:**  继承自 `RenderingTest` 类，提供了创建和操作 Blink 渲染树的测试环境。
*   **`GetLayoutBlockFlowByElementId` 和 `GetLayoutObjectByElementId`:**  辅助函数，用于根据元素的 ID 获取对应的 `LayoutBlockFlow` 或 `LayoutObject` 对象。
*   **`GetLines`:**  辅助函数，用于遍历内联光标并获取所有行的位置信息。
*   **`IndexOf`:**  辅助函数，用于在 `InlineCursorPosition` 列表中查找特定的 `FragmentItem`。
*   **`TestFirstDirtyLineIndex`:**  关键的辅助函数，用于测试在发生布局失效后，第一个需要重新布局的行的索引是否正确。
*   **`ItemsForAsVector`:** 辅助函数，用于获取特定 `LayoutObject` 的所有 `FragmentItem`。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **HTML:**  测试用例通过 `SetBodyInnerHTML` 函数设置 HTML 内容，模拟浏览器加载 HTML 页面的过程。`FragmentItem` 对象正是用于表示 HTML 元素在布局中的片段。例如，在 `BasicText` 测试中，HTML 文本节点会被转换为 `FragmentItem::kText` 类型的 `FragmentItem`。
*   **CSS:** 测试用例中使用了 CSS 样式来控制元素的布局，例如 `width`, `line-height`, `display`, `direction`, `text-overflow`, `columns` 等。这些 CSS 属性会直接影响 `FragmentItem` 的创建和属性，例如 `BasicInlineBox` 测试中 `<span>` 的背景色会影响是否生成对应的 `FragmentItem`。
*   **JavaScript:** 虽然这个测试文件本身是用 C++ 编写的，主要测试 Blink 引擎的内部逻辑，但 `FragmentItem` 的行为直接影响 JavaScript 与页面交互的结果。例如，通过 JavaScript 获取元素的位置和尺寸信息时，底层依赖于 Blink 引擎的布局计算，而 `FragmentItem` 是布局过程中的关键数据结构。如果 `FragmentItem` 的计算有误，JavaScript 获取到的信息也会不准确。此外，JavaScript 可以通过 DOM 操作（如 `appendChild`, `insertBefore`, `remove`) 来改变页面的结构，这些操作会触发布局的重新计算，而 `fragment_item_test.cc` 中的插入和删除测试正是模拟了这些场景。

**逻辑推理举例:**

在 `MarkLineBoxesDirtyOnInsert` 测试中，假设输入是以下 HTML：

```html
<div id=container style="font-size: 10px; width: 10ch">
  12345678
</div>
```

并且使用 `node_creators` 中的一个函数创建一个新的 `<span>` 元素并插入到 `container` 的开头。

**假设输入:**  插入一个新的 `<span>` 元素到 `container` 的开头。

**逻辑推理:**  由于在容器的开头插入了一个新元素，这可能会影响到第一行的布局，因此第一个需要重新布局的行索引应该是 0。

**预期输出:**  `TestFirstDirtyLineIndex("container", 0)`  应该通过测试。

**用户或编程常见的使用错误举例:**

*   **错误地假设 `FragmentItem` 的生命周期:**  开发者可能会错误地缓存 `FragmentItem` 指针，而没有意识到当布局发生变化时，这些指针可能会失效。`fragment_item_test.cc` 中的测试确保了当布局失效时，相关的状态会被正确标记，以便在后续操作中重新计算 `FragmentItem`。
*   **没有考虑到 RTL 布局:**  在处理文本内容时，开发者可能会忘记处理 RTL 语言的情况，导致文本渲染顺序错误。`RtlText` 测试验证了 `FragmentItem` 对 RTL 布局的支持，提醒开发者需要考虑这种情况。
*   **错误地计算元素的边界:**  开发者可能手动计算元素的边界，而没有考虑到行内元素的复杂布局情况，例如换行和内联盒子的存在。`BasicInlineBox` 和 `CulledInlineBox` 等测试用例展示了 `FragmentItem` 如何准确地表示这些元素的布局信息，帮助开发者理解布局的复杂性。
*   **忽略布局失效的影响:**  开发者可能在修改 DOM 结构或 CSS 样式后，立即访问布局信息，而没有等待布局完成，导致获取到的信息不准确。`MarkLineBoxesDirtyOnInsert/OnAppend/OnRemove` 等测试强调了 DOM 操作会触发布局失效，提醒开发者需要注意布局的更新时机。

总而言之，`fragment_item_test.cc` 是一个至关重要的测试文件，它确保了 Blink 渲染引擎中负责内联内容布局的核心类 `FragmentItem` 的功能正确性和稳定性。这些测试覆盖了各种常见的和复杂的布局场景，有助于防止与 HTML, CSS 和 JavaScript 交互相关的渲染错误。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/fragment_item_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_items.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

using testing::ElementsAre;

namespace blink {

class FragmentItemTest : public RenderingTest {
 public:
  void ForceLayout() { RunDocumentLifecycle(); }

  LayoutBlockFlow* GetLayoutBlockFlowByElementId(const char* id) {
    return To<LayoutBlockFlow>(GetLayoutObjectByElementId(id));
  }

  Vector<InlineCursorPosition> GetLines(InlineCursor* cursor) {
    Vector<InlineCursorPosition> lines;
    for (cursor->MoveToFirstLine(); *cursor; cursor->MoveToNextLine())
      lines.push_back(cursor->Current());
    return lines;
  }

  wtf_size_t IndexOf(const Vector<InlineCursorPosition>& items,
                     const FragmentItem* target) {
    wtf_size_t index = 0;
    for (const auto& item : items) {
      if (item.Item() == target)
        return index;
      ++index;
    }
    return kNotFound;
  }

  void TestFirstDirtyLineIndex(const char* id, wtf_size_t expected_index) {
    LayoutBlockFlow* block_flow = GetLayoutBlockFlowByElementId(id);
    const PhysicalBoxFragment* fragment = block_flow->GetPhysicalFragment(0);
    const FragmentItems* items = fragment->Items();
    FragmentItems::DirtyLinesFromNeedsLayout(*block_flow);
    const FragmentItem* end_reusable_item =
        items->EndOfReusableItems(*fragment);

    InlineCursor cursor(*fragment, *items);
    const auto lines = GetLines(&cursor);
    EXPECT_EQ(IndexOf(lines, end_reusable_item), expected_index);
  }

  Vector<const FragmentItem*> ItemsForAsVector(
      const LayoutObject& layout_object) {
    Vector<const FragmentItem*> list;
    InlineCursor cursor;
    for (cursor.MoveTo(layout_object); cursor;
         cursor.MoveToNextForSameLayoutObject()) {
      DCHECK(cursor.Current().Item());
      const FragmentItem& item = *cursor.Current().Item();
      EXPECT_EQ(item.GetLayoutObject(), &layout_object);
      list.push_back(&item);
    }
    return list;
  }
};

TEST_F(FragmentItemTest, CopyMove) {
  SetBodyInnerHTML(R"HTML(
    <style>
    div {
      font-size: 20px;
      line-height: 10px;
    }
    </style>
    <div id="container">
      1234567
    </div>
  )HTML");
  LayoutBlockFlow* container =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  InlineCursor cursor(*container);

  // Test copying a line item.
  cursor.MoveToFirstLine();
  const FragmentItem* line_item = cursor.Current().Item();
  EXPECT_EQ(line_item->Type(), FragmentItem::kLine);
  EXPECT_NE(line_item->LineBoxFragment(), nullptr);
  FragmentItem copy_of_line(*line_item);
  EXPECT_EQ(copy_of_line.LineBoxFragment(), line_item->LineBoxFragment());
  EXPECT_TRUE(copy_of_line.IsInkOverflowComputed());

  // Test moving a line item.
  FragmentItem move_of_line(std::move(copy_of_line));
  EXPECT_EQ(move_of_line.LineBoxFragment(), line_item->LineBoxFragment());
  EXPECT_TRUE(move_of_line.IsInkOverflowComputed());

  // To test moving ink overflow, add an ink overflow to |move_of_line|.
  PhysicalRect not_small_ink_overflow_rect(0, 0, 5000, 100);
  move_of_line.ink_overflow_type_ =
      static_cast<int>(move_of_line.ink_overflow_.SetContents(
          move_of_line.InkOverflowType(), not_small_ink_overflow_rect,
          line_item->Size()));
  EXPECT_EQ(move_of_line.InkOverflowType(), InkOverflow::Type::kContents);
  FragmentItem move_of_line2(std::move(move_of_line));
  EXPECT_EQ(move_of_line2.InkOverflowType(), InkOverflow::Type::kContents);
  EXPECT_EQ(move_of_line2.InkOverflowRect(), not_small_ink_overflow_rect);

  // Test copying a text item.
  cursor.MoveToFirstChild();
  const FragmentItem* text_item = cursor.Current().Item();
  EXPECT_EQ(text_item->Type(), FragmentItem::kText);
  EXPECT_NE(text_item->TextShapeResult(), nullptr);
  FragmentItem copy_of_text(*text_item);
  EXPECT_EQ(copy_of_text.TextShapeResult(), text_item->TextShapeResult());
  // Ink overflow is copied for text items. See |FragmentItem| copy ctor.
  EXPECT_TRUE(copy_of_text.IsInkOverflowComputed());

  // Test moving a text item.
  FragmentItem move_of_text(std::move(copy_of_text));
  EXPECT_EQ(move_of_text.TextShapeResult(), text_item->TextShapeResult());
  // After the move, the source ShapeResult should be released.
  EXPECT_EQ(copy_of_text.TextShapeResult(), nullptr);
  EXPECT_TRUE(move_of_text.IsInkOverflowComputed());
}

TEST_F(FragmentItemTest, BasicText) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
      font-family: Ahem;
      font-size: 10px;
      line-height: 1;
    }
    div {
      width: 10ch;
    }
    </style>
    <div id="container">
      1234567 98765
    </div>
  )HTML");

  auto* container =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  auto* layout_text = To<LayoutText>(container->FirstChild());
  const PhysicalBoxFragment* box = container->GetPhysicalFragment(0);
  EXPECT_NE(box, nullptr);
  const FragmentItems* items = box->Items();
  EXPECT_NE(items, nullptr);
  EXPECT_EQ(items->Items().size(), 4u);

  // The text node wraps, produces two fragments.
  Vector<const FragmentItem*> items_for_text = ItemsForAsVector(*layout_text);
  EXPECT_EQ(items_for_text.size(), 2u);

  const FragmentItem& text1 = *items_for_text[0];
  EXPECT_EQ(text1.Type(), FragmentItem::kText);
  EXPECT_EQ(text1.GetLayoutObject(), layout_text);
  EXPECT_EQ(text1.OffsetInContainerFragment(), PhysicalOffset());
  EXPECT_TRUE(text1.IsFirstForNode());
  EXPECT_FALSE(text1.IsLastForNode());

  const FragmentItem& text2 = *items_for_text[1];
  EXPECT_EQ(text2.Type(), FragmentItem::kText);
  EXPECT_EQ(text2.GetLayoutObject(), layout_text);
  EXPECT_EQ(text2.OffsetInContainerFragment(), PhysicalOffset(0, 10));
  EXPECT_FALSE(text2.IsFirstForNode());
  EXPECT_TRUE(text2.IsLastForNode());
}

TEST_F(FragmentItemTest, RtlText) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
    div {
      font-family: Ahem;
      font-size: 10px;
      width: 10ch;
      direction: rtl;
    }
    </style>
    <div id="container">
      <span id="span" style="background:hotpink;">
        11111. 22222.
      </span>
    </div>
  )HTML");

  auto* container =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  LayoutObject* span = GetLayoutObjectByElementId("span");
  auto* layout_text = To<LayoutText>(span->SlowFirstChild());
  const PhysicalBoxFragment* box = container->GetPhysicalFragment(0);
  EXPECT_NE(box, nullptr);
  const FragmentItems* items = box->Items();
  EXPECT_NE(items, nullptr);
  EXPECT_EQ(items->Items().size(), 8u);

  Vector<const FragmentItem*> items_for_span = ItemsForAsVector(*span);
  EXPECT_EQ(items_for_span.size(), 2u);
  const FragmentItem* item = items_for_span[0];
  EXPECT_TRUE(item->IsFirstForNode());
  EXPECT_FALSE(item->IsLastForNode());

  item = items_for_span[1];
  EXPECT_FALSE(item->IsFirstForNode());
  EXPECT_TRUE(item->IsLastForNode());

  Vector<const FragmentItem*> items_for_text = ItemsForAsVector(*layout_text);
  EXPECT_EQ(items_for_text.size(), 4u);

  item = items_for_text[0];
  EXPECT_EQ(item->Text(*items).ToString(), String("."));
  EXPECT_TRUE(item->IsFirstForNode());
  EXPECT_FALSE(item->IsLastForNode());

  item = items_for_text[1];
  EXPECT_EQ(item->Text(*items).ToString(), String("11111"));
  EXPECT_FALSE(item->IsFirstForNode());
  EXPECT_FALSE(item->IsLastForNode());

  item = items_for_text[2];
  EXPECT_EQ(item->Text(*items).ToString(), String("."));
  EXPECT_FALSE(item->IsFirstForNode());
  EXPECT_FALSE(item->IsLastForNode());

  item = items_for_text[3];
  EXPECT_EQ(item->Text(*items).ToString(), String("22222"));
  EXPECT_FALSE(item->IsFirstForNode());
  EXPECT_TRUE(item->IsLastForNode());
}

TEST_F(FragmentItemTest, BasicInlineBox) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
      font-family: Ahem;
      font-size: 10px;
      line-height: 1;
    }
    #container {
      width: 10ch;
    }
    #span1, #span2 {
      background: gray;
    }
    </style>
    <div id="container">
      000
      <span id="span1">1234 5678</span>
      999
      <span id="span2">12345678</span>
    </div>
  )HTML");

  // "span1" wraps, produces two fragments.
  const LayoutObject* span1 = GetLayoutObjectByElementId("span1");
  ASSERT_NE(span1, nullptr);
  Vector<const FragmentItem*> items_for_span1 = ItemsForAsVector(*span1);
  EXPECT_EQ(items_for_span1.size(), 2u);
  EXPECT_TRUE(items_for_span1[0]->IsFirstForNode());
  EXPECT_FALSE(items_for_span1[0]->IsLastForNode());
  EXPECT_EQ(PhysicalOffset(40, 0),
            items_for_span1[0]->OffsetInContainerFragment());
  EXPECT_EQ(PhysicalRect(0, 0, 40, 10), items_for_span1[0]->InkOverflowRect());
  EXPECT_FALSE(items_for_span1[1]->IsFirstForNode());
  EXPECT_TRUE(items_for_span1[1]->IsLastForNode());
  EXPECT_EQ(PhysicalOffset(0, 10),
            items_for_span1[1]->OffsetInContainerFragment());
  EXPECT_EQ(PhysicalRect(0, 0, 40, 10), items_for_span1[1]->InkOverflowRect());

  // "span2" doesn't wrap, produces only one fragment.
  const LayoutObject* span2 = GetLayoutObjectByElementId("span2");
  ASSERT_NE(span2, nullptr);
  Vector<const FragmentItem*> items_for_span2 = ItemsForAsVector(*span2);
  EXPECT_EQ(items_for_span2.size(), 1u);
  EXPECT_TRUE(items_for_span2[0]->IsFirstForNode());
  EXPECT_TRUE(items_for_span2[0]->IsLastForNode());
  EXPECT_EQ(PhysicalOffset(0, 20),
            items_for_span2[0]->OffsetInContainerFragment());
  EXPECT_EQ(PhysicalRect(0, 0, 80, 10), items_for_span2[0]->InkOverflowRect());
}

// Same as |BasicInlineBox| but `<span>`s do not have background.
// They will not produce fragment items, but all operations should work the
// same.
TEST_F(FragmentItemTest, CulledInlineBox) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
    html, body {
      margin: 0;
      font-family: Ahem;
      font-size: 10px;
      line-height: 1;
    }
    #container {
      width: 10ch;
    }
    </style>
    <div id="container">
      000
      <span id="span1">1234 5678</span>
      999
      <span id="span2">12345678</span>
    </div>
  )HTML");

  // "span1" wraps, produces two fragments.
  const LayoutObject* span1 = GetLayoutObjectByElementId("span1");
  ASSERT_NE(span1, nullptr);
  Vector<const FragmentItem*> items_for_span1 = ItemsForAsVector(*span1);
  EXPECT_EQ(items_for_span1.size(), 0u);
  EXPECT_EQ(gfx::Rect(0, 0, 80, 20), span1->AbsoluteBoundingBoxRect());

  // "span2" doesn't wrap, produces only one fragment.
  const LayoutObject* span2 = GetLayoutObjectByElementId("span2");
  ASSERT_NE(span2, nullptr);
  Vector<const FragmentItem*> items_for_span2 = ItemsForAsVector(*span2);
  EXPECT_EQ(items_for_span2.size(), 0u);
  EXPECT_EQ(gfx::Rect(0, 20, 80, 10), span2->AbsoluteBoundingBoxRect());
}

TEST_F(FragmentItemTest, SelfPaintingInlineBox) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #self_painting_inline_box {
      opacity: .2;
    }
    </style>
    <div>
      <span id="self_painting_inline_box">self painting inline box</span>
    </div>
  )HTML");

  // Invalidate the ink overflow of a child in `#self_painting_inline_box`.
  auto* self_painting_inline_box =
      To<LayoutInline>(GetLayoutObjectByElementId("self_painting_inline_box"));
  ASSERT_TRUE(self_painting_inline_box->HasSelfPaintingLayer());
  auto* text = To<LayoutText>(self_painting_inline_box->FirstChild());
  text->InvalidateVisualOverflow();

  // Mark the |PaintLayer| to need to recalc visual overflow.
  self_painting_inline_box->Layer()->SetNeedsVisualOverflowRecalc();
  RunDocumentLifecycle();

  // Test if it recalculated the ink overflow.
  InlineCursor cursor;
  for (cursor.MoveTo(*text); cursor; cursor.MoveToNextForSameLayoutObject())
    EXPECT_TRUE(cursor.Current()->IsInkOverflowComputed());
}

TEST_F(FragmentItemTest, StartOffsetInContainer) {
  SetBodyInnerHTML(R"HTML(
    <style>
    atomic {
      display: inline-block;
      width: 3ch;
    }
    </style>
    <div id="container" style="font-size: 10px; width: 3ch">
      012&shy;456&shy;<span>8</span>90&shy;<atomic></atomic>
    </div>
  )HTML");
  auto* container =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  InlineCursor cursor(*container);
  while (!cursor.Current()->IsLayoutGeneratedText())
    cursor.MoveToNext();
  EXPECT_EQ(4u, cursor.Current()->StartOffsetInContainer(cursor));
  for (cursor.MoveToNext(); !cursor.Current()->IsLayoutGeneratedText();)
    cursor.MoveToNext();
  EXPECT_EQ(8u, cursor.Current()->StartOffsetInContainer(cursor));
  for (cursor.MoveToNext(); !cursor.Current()->IsLayoutGeneratedText();)
    cursor.MoveToNext();
  EXPECT_EQ(12u, cursor.Current()->StartOffsetInContainer(cursor));
}

TEST_F(FragmentItemTest, EllipsizedAtomicInline) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #container {
      width: 100px;
      white-space: pre;
      text-overflow: ellipsis;
      overflow: hidden;
    }
    #atomic {
      display: inline-block;
      width: 200px;
    }
    </style>
    <div id="container"><span id="atomic"> </span>XXXXXX</div>
  )HTML");
  auto* container =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  auto* atomic = GetLayoutObjectByElementId("atomic");
  InlineCursor cursor(*container);
  cursor.MoveToNext();
  EXPECT_EQ(cursor.Current().GetLayoutObject(), atomic);
  EXPECT_EQ(cursor.Current()->Type(), FragmentItem::kBox);
  // When atomic inline is ellipsized, |IsLastForNode| should be set to the last
  // |kBox| item, even if ellipses follow.
  EXPECT_TRUE(cursor.Current()->IsLastForNode());
  cursor.MoveToNext();
  EXPECT_EQ(cursor.Current()->Type(), FragmentItem::kText);
  cursor.MoveToNext();
  EXPECT_EQ(cursor.Current().GetLayoutObject(), atomic);
  EXPECT_EQ(cursor.Current()->Type(), FragmentItem::kGeneratedText);
  EXPECT_TRUE(cursor.Current()->IsLastForNode());
}

TEST_F(FragmentItemTest, LineFragmentId) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #columns {
      columns: 2;
      column-fill: auto;
      line-height: 1em;
      height: 3em;
    }
    </style>
    <body>
      <div id="columns">
        <div id="target">
          1<br>
          2<br>
          3<br>
          4<br>
          5<br>
          6
        </div>
      </div>
    </body>
  )HTML");
  auto* target = To<LayoutBlockFlow>(GetLayoutObjectByElementId("target"));
  InlineCursor cursor(*target);
  wtf_size_t line_index = 0;
  for (cursor.MoveToFirstLine(); cursor;
       cursor.MoveToNextLineIncludingFragmentainer(), ++line_index) {
    EXPECT_EQ(cursor.Current()->FragmentId(),
              line_index + FragmentItem::kInitialLineFragmentId);
  }
  EXPECT_EQ(line_index, 6u);
}

TEST_F(FragmentItemTest, Outline) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
    #target {
      font-family: Ahem;
      font-size: 10px;
      width: 200px;
    }
    .inline-box {
      border: 5px solid blue;
    }
    .inline-block {
      display: inline-block;
    }
    </style>
    <div id="target">
      <span class="inline-box">
        <span class="inline-block">X<span>
      </span>
    </div>
  )HTML");
  auto* target = To<LayoutBlockFlow>(GetLayoutObjectByElementId("target"));
  Vector<PhysicalRect> rects = target->OutlineRects(
      nullptr, PhysicalOffset(), OutlineType::kIncludeBlockInkOverflow);
  EXPECT_THAT(rects,
              testing::ElementsAre(
                  PhysicalRect(0, 0, 200, 10),   // <div id="target">
                  PhysicalRect(5, 0, 10, 10),    // <span class="inline-box">
                  PhysicalRect(5, 0, 10, 10)));  // <span class="inline-block">
}

// Various nodes/elements to test insertions.
using CreateNode = Node* (*)(Document&);
static CreateNode node_creators[] = {
    [](Document& document) -> Node* { return document.createTextNode("new"); },
    [](Document& document) -> Node* {
      return document.CreateRawElement(html_names::kSpanTag);
    },
    [](Document& document) -> Node* {
      Element* element = document.CreateRawElement(html_names::kSpanTag);
      element->classList().Add(AtomicString("abspos"));
      return element;
    },
    [](Document& document) -> Node* {
      Element* element = document.CreateRawElement(html_names::kSpanTag);
      element->classList().Add(AtomicString("float"));
      return element;
    }};

class FragmentItemInsertTest : public FragmentItemTest,
                               public testing::WithParamInterface<CreateNode> {
};

INSTANTIATE_TEST_SUITE_P(FragmentItemTest,
                         FragmentItemInsertTest,
                         testing::ValuesIn(node_creators));

// Various nodes/elements to test removals.
class FragmentItemRemoveTest : public FragmentItemTest,
                               public testing::WithParamInterface<const char*> {
};

INSTANTIATE_TEST_SUITE_P(
    FragmentItemTest,
    FragmentItemRemoveTest,
    testing::Values("text",
                    "<span>span</span>",
                    "<span>1234 12345678</span>",
                    "<span style='display: inline-block'>box</span>",
                    "<img>",
                    "<div style='float: left'>float</div>",
                    "<div style='position: absolute'>abs</div>"));

// Test marking line boxes when inserting a span before the first child.
TEST_P(FragmentItemInsertTest, MarkLineBoxesDirtyOnInsert) {
  SetBodyInnerHTML(R"HTML(
    <style>
    .abspos { position: absolute; }
    .float { float: left; }
    </style>
    <div id=container style="font-size: 10px; width: 10ch">
      12345678
    </div>
  )HTML");
  Node* insert = (*GetParam())(GetDocument());
  Element* container = GetElementById("container");
  container->insertBefore(insert, container->firstChild());
  TestFirstDirtyLineIndex("container", 0);
}

// Test marking line boxes when appending a span.
TEST_P(FragmentItemInsertTest, MarkLineBoxesDirtyOnAppend) {
  SetBodyInnerHTML(R"HTML(
    <style>
    .abspos { position: absolute; }
    .float { float: left; }
    </style>
    <div id=container style="font-size: 10px; width: 10ch">
      12345678
    </div>
  )HTML");
  Node* insert = (*GetParam())(GetDocument());
  Element* container = GetElementById("container");
  container->appendChild(insert);
  TestFirstDirtyLineIndex("container", 0);
}

// Test marking line boxes when appending a span on 2nd line.
TEST_P(FragmentItemInsertTest, MarkLineBoxesDirtyOnAppend2) {
  SetBodyInnerHTML(R"HTML(
    <style>
    .abspos { position: absolute; }
    .float { float: left; }
    </style>
    <div id=container style="font-size: 10px; width: 10ch">
      12345678
      2234
    </div>
  )HTML");
  Node* insert = (*GetParam())(GetDocument());
  Element* container = GetElementById("container");
  container->appendChild(insert);
  TestFirstDirtyLineIndex("container", 1);
}

// Test marking line boxes when appending a span on 2nd line.
TEST_P(FragmentItemInsertTest, MarkLineBoxesDirtyOnAppendAfterBR) {
  SetBodyInnerHTML(R"HTML(
    <style>
    .abspos { position: absolute; }
    .float { float: left; }
    </style>
    <div id=container style="font-size: 10px; width: 10ch">
      <br>
      <br>
    </div>
  )HTML");
  Node* insert = (*GetParam())(GetDocument());
  Element* container = GetElementById("container");
  container->appendChild(insert);
  TestFirstDirtyLineIndex("container", 1);
}

// Test marking line boxes when removing a span.
TEST_F(FragmentItemTest, MarkLineBoxesDirtyOnRemove) {
  SetBodyInnerHTML(R"HTML(
    <div id=container style="font-size: 10px; width: 10ch">
      1234<span id=t>5678</span>
    </div>
  )HTML");
  Element* span = GetElementById("t");
  span->remove();
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 0);
}

// Test marking line boxes when removing a span.
TEST_P(FragmentItemRemoveTest, MarkLineBoxesDirtyOnRemoveFirst) {
  SetBodyInnerHTML(String(R"HTML(
    <div id=container style="font-size: 10px; width: 10ch">)HTML") +
                   GetParam() + R"HTML(<span>after</span>
    </div>
  )HTML");

  Element* container = GetElementById("container");
  Node* node = container->firstChild();
  ASSERT_TRUE(node);
  node->remove();
  TestFirstDirtyLineIndex("container", 0);
}

// Test marking line boxes when removing a span on 2nd line.
TEST_F(FragmentItemTest, MarkLineBoxesDirtyOnRemove2) {
  SetBodyInnerHTML(R"HTML(
    <div id=container style="font-size: 10px; width: 10ch">
      12345678
      2234<span id=t>5678 3334</span>
    </div>
  )HTML");
  Element* span = GetElementById("t");
  span->remove();
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 0);
}

// Test marking line boxes when removing a text node on 2nd line.
TEST_P(FragmentItemRemoveTest, MarkLineBoxesDirtyOnRemoveAfterBR) {
  SetBodyInnerHTML(String(R"HTML(
    <div id=container style="font-size: 10px; width: 10ch">
      line 1
      <br>)HTML") + GetParam() +
                   "</div>");
  Element* container = GetElementById("container");
  Node* node = container->lastChild();
  ASSERT_TRUE(node);
  node->remove();
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 0);

  ForceLayout();  // Ensure running layout does not crash.
}

TEST_F(FragmentItemTest, MarkLineBoxesDirtyOnEndSpaceCollapsed) {
  SetBodyInnerHTML(R"HTML(
    <style>
    div {
      font-size: 10px;
      width: 8ch;
    }
    #empty {
      background: yellow; /* ensure fragment is created */
    }
    #target {
      display: inline-block;
    }
    </style>
    <div id=container>
      1234567890
      1234567890
      <span id=empty> </span>
      <span id=target></span></div>
  )HTML");
  // Removing #target makes the spaces before it to be collapsed.
  Element* target = GetElementById("target");
  target->remove();
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 1);

  ForceLayout();  // Ensure running layout does not crash.
}

// Test marking line boxes when the first span has NeedsLayout. The span is
// culled.
TEST_F(FragmentItemTest, MarkLineBoxesDirtyOnNeedsLayoutFirst) {
  SetBodyInnerHTML(R"HTML(
    <div id=container style="font-size: 10px; width: 10ch">
      <span id=t>1234</span>5678
    </div>
  )HTML");
  LayoutObject* span = GetLayoutObjectByElementId("t");
  span->SetNeedsLayout("");
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 0);
}

// Test marking line boxes when the first span has NeedsLayout. The span has a
// box fragment.
TEST_F(FragmentItemTest, MarkLineBoxesDirtyOnNeedsLayoutFirstWithBox) {
  SetBodyInnerHTML(R"HTML(
    <div id=container style="font-size: 10px; width: 10ch">
      <span id=t style="background: blue">1234</span>5678
    </div>
  )HTML");
  LayoutObject* span = GetLayoutObjectByElementId("t");
  span->SetNeedsLayout("");
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 0);
}

// Test marking line boxes when a span has NeedsLayout. The span is culled.
TEST_F(FragmentItemTest, MarkLineBoxesDirtyOnNeedsLayout) {
  SetBodyInnerHTML(R"HTML(
    <div id=container style="font-size: 10px; width: 10ch">
      12345678
      2234<span id=t>5678 3334</span>
    </div>
  )HTML");
  LayoutObject* span = GetLayoutObjectByElementId("t");
  span->SetNeedsLayout("");
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 0);
}

// Test marking line boxes when a span has NeedsLayout. The span has a box
// fragment.
TEST_F(FragmentItemTest, MarkLineBoxesDirtyOnNeedsLayoutWithBox) {
  SetBodyInnerHTML(R"HTML(
    <div id=container style="font-size: 10px; width: 10ch">
      12345678
      2234<span id=t style="background: blue">5678 3334</span>
    </div>
  )HTML");
  LayoutObject* span = GetLayoutObjectByElementId("t");
  span->SetNeedsLayout("");
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 0);
}

// Test marking line boxes when a span inside a span has NeedsLayout.
// The parent span has a box fragment, and wraps, so that its fragment
// is seen earlier in pre-order DFS.
TEST_F(FragmentItemTest, MarkLineBoxesDirtyOnChildOfWrappedBox) {
  SetBodyInnerHTML(R"HTML(
    <div id=container style="font-size: 10px">
      <span style="background: yellow">
        <span id=t>target</span>
        <br>
        12345678
      </span>
    </div>
  )HTML");
  LayoutObject* span = GetLayoutObjectByElementId("t");
  span->SetNeedsLayout("");
  TestFirstDirtyLineIndex("container", 0);
}

// Test marking line boxes when a span has NeedsLayout. The span has a box
// fragment.
TEST_F(FragmentItemTest, MarkLineBoxesDirtyInInlineBlock) {
  SetBodyInnerHTML(R"HTML(
    <div id=container style="display: inline-block; font-size: 10px">
      12345678<br>
      12345678<br>
    </div>
  )HTML");
  Element* container = GetElementById("container");
  container->appendChild(GetDocument().createTextNode("append"));
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 1);
}

TEST_F(FragmentItemTest, MarkLineBoxesDirtyByRemoveChildAfterForcedBreak) {
  SetBodyInnerHTML(R"HTML(
    <div id=container>
      line 1<br>
      <b id=target>line 2</b><br>
      line 3<br>
    </div>
  )HTML");
  Element& target = *GetElementById("target");
  target.remove();
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 0);
}

TEST_F(FragmentItemTest, MarkLineBoxesDirtyByRemoveForcedBreak) {
  SetBodyInnerHTML(R"HTML(
    <div id=container>
      line 1<br>
      line 2<br id=target>
      line 3<br>
    </div>"
  )HTML");
  Element& target = *GetElementById("target");
  target.remove();
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 0);
}

TEST_F(FragmentItemTest, MarkLineBoxesDirtyByRemoveSpanWithForcedBreak) {
  SetBodyInnerHTML(R"HTML(
    <div id=container>
      line 1<br>
      line 2<span id=target><br>
      </span>line 3<br>
    </div>
  )HTML");
  // |target| is a culled inline box. There is no fragment in fragment tree.
  Element& target = *GetElementById("target");
  target.remove();
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 0);
}

TEST_F(FragmentItemTest, MarkLineBoxesDirtyByInsertAtStart) {
  SetBodyInnerHTML(R"HTML(
    <div id=container>
      line 1<br>
      <b id=target>line 2</b><br>
      line 3<br>
    </div>
  )HTML");
  Element& target = *GetElementById("target");
  target.parentNode()->insertBefore(Text::Create(GetDocument(), "XYZ"),
                                    &target);
  GetDocument().UpdateStyleAndLayoutTree();
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 0);
}

TEST_F(FragmentItemTest, MarkLineBoxesDirtyByInsertAtLast) {
  SetBodyInnerHTML(R"HTML(
    <div id=container>
      line 1<br>
      <b id=target>line 2</b><br>
      line 3<br>
    </div>
  )HTML");
  Element& target = *GetElementById("target");
  target.parentNode()->appendChild(Text::Create(GetDocument(), "XYZ"));
  GetDocument().UpdateStyleAndLayoutTree();
  TestFirstDirtyLineIndex("container", 1);
}

TEST_F(FragmentItemTest, MarkLineBoxesDirtyByInsertAtMiddle) {
  SetBodyInnerHTML(R"HTML(
    <div id=container>
      line 1<br>
      <b id=target>line 2</b><br>
      line 3<br>
    </div>
  )HTML");
  Element& target = *GetElementById("target");
  target.parentNode()->insertBefore(Text::Create(GetDocument(), "XYZ"),
                                    target.nextSibling());
  GetDocument().UpdateStyleAndLayoutTree();
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 0);
}

TEST_F(FragmentItemTest, MarkLineBoxesDirtyByTextSetData) {
  SetBodyInnerHTML(R"HTML(
    <div id=container>
      line 1<br>
      <b id=target>line 2</b><br>
      line 3<br>
    </div>
  )HTML");
  Element& target = *GetElementById("target");
  To<Text>(*target.firstChild()).setData("abc");
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 0);
}

TEST_F(FragmentItemTest, MarkLineBoxesDirtyWrappedLine) {
  SetBodyInnerHTML(R"HTML(
    <style>
    #container {
      font-size: 10px;
      width: 10ch;
    }
    </style>
    <div id=container>
      1234567
      123456<span id="target">7</span>
    </div>
  )HTML");
  Element& target = *GetElementById("target");
  target.remove();
  // TODO(kojii): This can be optimized more.
  TestFirstDirtyLineIndex("container", 0);
}

TEST_F(FragmentItemTest, MarkLineBoxesDirtyInsideInlineBlock) {
  SetBodyInnerHTML(R"HTML(
    <div id=container>
      <div id="inline-block" style="display: inline-block">
        <span id="target">DELETE ME</span>
      </div>
    </div>
  )HTML");
  Element& target = *GetElementById("target");
  target.remove();
  TestFirstDirtyLineIndex("container", 0);
}

// This test creates various types of |FragmentItem| to check "natvis" (Native
// DebugVisualizers) for Windows Visual Studio.
TEST_F(FragmentItemTest, Disabled_DebugVisualizers) {
  SetBodyInnerHTML(R"HTML(
    <div id=container>
      text
      <span style="display: inline-block"></span>
    </div>
  )HTML");
  auto* container =
      To<LayoutBlockFlow>(GetLayoutObjectByElementId("container"));
  InlineCursor cursor(*container);
  cursor.MoveToFirstLine();
  const FragmentItem* line = cursor.Current().Item();
  EXPECT_NE(line, nullptr);
  cursor.MoveToNext();
  const FragmentItem* text = cursor.Current().Item();
  EXPECT_NE(text, nullptr);
  cursor.MoveToNext();
  const FragmentItem* box = cursor.Current().Item();
  EXPECT_NE(box, nullptr);
}

}  // namespace blink
```