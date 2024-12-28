Response:
Let's break down the thought process for analyzing the `layout_multi_column_set.cc` file.

1. **Understand the Context:** The file path `blink/renderer/core/layout/layout_multi_column_set.cc` immediately tells us this is part of the Blink rendering engine, specifically dealing with the layout of multi-column content. The `.cc` extension indicates C++ code.

2. **Initial Code Scan (Keywords and Structure):**  A quick scan reveals key terms like `multi-column`, `fragment`, `column`, `flow thread`, `geometry`, `fragmentainer`, `spanner`. The presence of `#include` directives points to dependencies on other layout-related classes. The `namespace blink` and nested anonymous namespace are standard C++ practices.

3. **Identify the Core Class:** The name `LayoutMultiColumnSet` strongly suggests this is the central class we need to focus on.

4. **Analyze the Class Members and Methods:**  Go through the class definition, examining the member variables and methods. Try to infer their purpose from their names:
    * `fragmentainer_groups_`:  Likely manages the rows of columns.
    * `flow_thread_`:  Connects the column set to the overall layout process.
    * `CreateAnonymous()`: Creates an instance without a direct HTML element.
    * `FragmentainerGroupIndexAtFlowThreadOffset()`, `FragmentainerGroupAtVisualPoint()`:  Methods for locating specific column rows based on position.
    * `AppendNewFragmentainerGroup()`:  Adds a new row of columns.
    * `LogicalTopInFlowThread()`, `LogicalBottomInFlowThread()`:  Get the vertical extent within the overall layout flow.
    * `UpdateGeometryIfNeeded()`, `UpdateGeometry()`:  Handles the calculation of the column set's position and size. This seems crucial.
    * `AttachToFlowThread()`, `DetachFromFlowThread()`:  Manages the connection to the layout process.
    * `StyleDidChange()`: Reacts to CSS style changes.
    * `ColumnGap()`:  Calculates the space between columns.
    * `ActualColumnCount()`:  (Note the comment "FIXME: remove this method")  Indicates the number of columns.
    * `FragmentsBoundingBox()`:  Calculates the overall area occupied by the columns.

5. **Focus on Key Functionality:** Based on the names and structure, several core functions emerge:
    * **Creation and Management of Column Rows (Fragmentainer Groups):**  The methods related to `fragmentainer_groups_` are central.
    * **Positioning and Sizing:** The `UpdateGeometry` method is clearly responsible for this.
    * **Interaction with the Layout Flow (Flow Thread):** The methods involving `flow_thread_` are important.
    * **Handling Style Changes:** `StyleDidChange` connects to CSS.

6. **Relate to HTML, CSS, and JavaScript:**
    * **HTML:** The existence of this class implies it's responsible for rendering content structured using multi-column layouts (like `<div style="columns: 3">`).
    * **CSS:** The `StyleDidChange` and `ColumnGap` methods explicitly link to CSS properties like `column-count`, `column-width`, and `column-gap`. The comment about `column-rule` in `StyleDidChange` is a direct connection.
    * **JavaScript:**  While this C++ code doesn't directly execute JavaScript, it's part of the rendering process triggered by changes to the DOM or CSS, which can be initiated by JavaScript. Consider how JavaScript might change CSS properties that would then trigger `StyleDidChange`.

7. **Identify Logical Inferences and Potential Issues:**
    * **`UpdateGeometry` Logic:**  The code iterates through fragments and calculates positions. Consider edge cases like empty columns or content spanning multiple columns (`column-span: all`). The comments within `UpdateGeometry` provide valuable insights into the logic, especially the handling of `LayoutMultiColumnSpannerPlaceholder`.
    * **User/Programming Errors:** Think about what mistakes a web developer might make when using multi-column layouts. Incorrect CSS syntax, trying to apply multi-column to elements where it doesn't make sense, or issues with content flow exceeding column boundaries are potential problems. The code's comments about legacy vs. NG engine differences highlight potential internal complexities and edge cases.

8. **Construct Examples:**  Based on the understanding of the class and its relation to web technologies, create concrete examples of HTML, CSS, and potential JavaScript interactions. These examples should illustrate how the code in `layout_multi_column_set.cc` plays a role.

9. **Refine and Organize:** Structure the findings logically, starting with the core functionalities and then moving to the relationships with web technologies, logical inferences, and potential errors. Use clear language and provide specific code snippets where appropriate. The use of headings and bullet points helps in organization.

10. **Review and Iterate:**  Read through the analysis, ensuring accuracy and completeness. Double-check the understanding of the code and its implications. For instance, the comment about the "FIXME" for `ActualColumnCount` suggests that method's purpose isn't well-defined or might be problematic, which is worth noting. The explanation about how `column-rule` is handled is another important detail.

By following these steps, one can effectively analyze and understand the functionality of a complex source code file like `layout_multi_column_set.cc`. The key is to combine code inspection with an understanding of the broader context of web rendering and the underlying technologies involved.
好的，让我们详细分析一下 `blink/renderer/core/layout/layout_multi_column_set.cc` 文件的功能。

**核心功能：**

`LayoutMultiColumnSet` 类是 Blink 渲染引擎中用于处理 CSS 多列布局的关键组件。它的主要职责是：

1. **表示多列布局中的一个列集合 (Column Set)：**  在多列布局中，内容会被分割到多个列中。一个 `LayoutMultiColumnSet` 对象代表了这些列的一个逻辑分组，通常对应于在布局流程中占据相同垂直空间的一行或多行列。

2. **管理列容器组 (Fragmentainer Groups)：** 它内部维护着 `MultiColumnFragmentainerGroup` 对象的集合。每个 `MultiColumnFragmentainerGroup` 代表多列布局中的一行，包含该行中的所有列。这有助于处理跨页或跨区域的列布局。

3. **计算和缓存几何信息：**  `LayoutMultiColumnSet` 负责计算其自身的位置（`frame_location_`）和大小（`frame_size_`），这些信息用于后续的渲染和布局计算。它会缓存这些信息，并在需要时更新。

4. **与布局流程线程 (LayoutFlowThread) 交互：** 它与 `LayoutFlowThread` 类关联，后者负责管理整个文档的布局过程。`LayoutMultiColumnSet` 会在被添加到或从布局树移除时通知 `LayoutFlowThread`。

5. **处理样式变化：** 当与多列布局相关的 CSS 样式发生变化时（例如 `column-gap`，`column-rule`），`LayoutMultiColumnSet` 会收到通知并进行相应的调整。

6. **确定指定位置的列容器组：** 它提供了方法（如 `FragmentainerGroupIndexAtFlowThreadOffset` 和 `FragmentainerGroupAtVisualPoint`）来根据给定的偏移量或视觉坐标找到对应的 `MultiColumnFragmentainerGroup`。

**与 JavaScript, HTML, CSS 的关系及举例：**

`LayoutMultiColumnSet` 直接参与 CSS 多列布局的实现，并间接地与 HTML 和 JavaScript 发生关联。

* **CSS:**
    * **`column-count` 和 `column-width`:**  虽然 `LayoutMultiColumnSet` 自身不直接处理这些属性的解析，但其行为受到这些属性的影响。例如，如果 CSS 设置了 `column-count: 3;`，那么渲染引擎会创建相应的列，并由 `LayoutMultiColumnSet` 来组织和布局这些列。
    * **`column-gap`:** `LayoutMultiColumnSet::ColumnGap()` 方法负责计算列之间的间距，这个间距直接来源于 CSS 的 `column-gap` 属性。
        ```css
        .multicolumn {
          column-count: 2;
          column-gap: 20px;
        }
        ```
        在这个例子中，`LayoutMultiColumnSet` 会计算出 20px 的列间距。
    * **`column-rule`:** `LayoutMultiColumnSet::StyleDidChange()` 方法中提到，虽然 `column-rule` 是定义在多列容器上的，但列集合负责绘制它们。当 `column-rule` 发生变化时，`LayoutMultiColumnSet` 需要标记自身需要重绘。
        ```css
        .multicolumn {
          column-count: 2;
          column-rule: 1px solid black;
        }
        ```
        `LayoutMultiColumnSet` 会负责渲染列之间的那条黑色的分隔线。
    * **`column-span`:**  代码中提到了 `LayoutMultiColumnSpannerPlaceholder`，这是处理跨越多列的元素（使用 `column-span: all;`）的关键。`LayoutMultiColumnSet` 需要感知这些跨列元素，并在布局时进行特殊处理，确保它们占据正确的空间。
        ```html
        <div class="multicolumn">
          <p>第一列内容</p>
          <p style="column-span: all;">跨越所有列的内容</p>
          <p>第二列内容</p>
        </div>
        ```
        在这个例子中，中间的 `<p>` 元素会跨越两列。`LayoutMultiColumnSet` 需要计算出它应该占据的宽度和位置。

* **HTML:**
    * `LayoutMultiColumnSet` 对应于应用了多列布局的 HTML 元素。当浏览器解析 HTML 时，如果遇到带有 `column-count` 或 `column-width` 样式的元素，就会创建相应的 `LayoutMultiColumnSet` 对象来处理其布局。
    ```html
    <div style="column-count: 3;">
      <p>这是第一段内容。</p>
      <p>这是第二段内容。</p>
      <p>这是第三段内容。</p>
      </div>
    ```
    对于这个 `<div>` 元素，Blink 会创建一个 `LayoutMultiColumnSet` 实例来将其内容分成三列布局。

* **JavaScript:**
    * JavaScript 可以动态地修改元素的 CSS 样式，包括多列布局相关的属性。当 JavaScript 修改了这些属性时，会导致样式重新计算，并最终影响到 `LayoutMultiColumnSet` 的行为。例如，JavaScript 可以动态地改变 `column-count`，导致列的数目发生变化，`LayoutMultiColumnSet` 需要重新计算布局。
    ```javascript
    const multicolDiv = document.querySelector('.multicolumn');
    multicolumnDiv.style.columnCount = '4'; // JavaScript 动态修改列数
    ```
    这段 JavaScript 代码会将应用了 `.multicolumn` 类的元素的列数修改为 4，这将触发 Blink 重新布局，`LayoutMultiColumnSet` 会参与这个过程。

**逻辑推理的假设输入与输出：**

假设输入一个包含多列布局的 HTML 结构和相应的 CSS 样式：

**假设输入:**

```html
<div id="container" style="column-count: 2; column-gap: 10px; width: 300px;">
  <p>第一段文字内容，比较长，会超出单列的宽度。</p>
  <p>第二段文字。</p>
  <p>第三段文字，也很长，会填充到下一列。</p>
</div>
```

**逻辑推理过程 (`LayoutMultiColumnSet` 的可能行为):**

1. **创建 `LayoutMultiColumnSet` 对象:** 当渲染引擎遇到 `id="container"` 的 `div` 元素时，会创建一个 `LayoutMultiColumnSet` 对象来负责其多列布局。
2. **解析样式:** `LayoutMultiColumnSet` 会获取到 `column-count: 2`，`column-gap: 10px`，`width: 300px` 等样式信息。
3. **计算列宽:**  根据容器宽度和列数及列间距，`LayoutMultiColumnSet` 会计算出每列的可用宽度：`(300px - 10px) / 2 = 145px`。
4. **布局内容:**  `LayoutMultiColumnSet` 会将 `div` 内部的段落元素分配到不同的列中。
    * "第一段文字内容，比较长，会超出单列的宽度。" 会填充到第一列，超出部分会顺延到第二列。
    * "第二段文字。" 会填充到第一列或第二列，取决于第一列的剩余空间。
    * "第三段文字，也很长，会填充到下一列。" 会填充到第二列。
5. **确定自身大小:** `LayoutMultiColumnSet` 的 `frame_size_` 会根据内容的高度和容器的宽度来确定。高度取决于最高的列的高度。
6. **输出布局信息 (简化):**  `LayoutMultiColumnSet` 会提供每个子元素（段落）在多列布局中的位置和大小信息，以便渲染引擎进行绘制。

**假设输出 (简化的位置信息):**

* 第一段文字（部分在第一列）：`x: 0, y: 0, width: 145px, height: ...`
* 第一段文字（部分在第二列）：`x: 155px, y: 0, width: 145px, height: ...`
* 第二段文字： `x: 0 或 155px, y: ..., width: ..., height: ...`
* 第三段文字： `x: 155px, y: ..., width: 145px, height: ...`

**涉及用户或编程常见的使用错误：**

1. **忘记设置容器宽度或列数:** 如果没有设置容器的宽度或者列数，多列布局可能无法正常工作，或者表现出意外的行为。
    ```html
    <div style="column-count: 2;"> <!-- 缺少宽度，列的宽度可能无法确定 -->
      <p>内容...</p>
    </div>
    ```

2. **内容溢出导致布局混乱:** 如果内容过多，超出了容器的高度，可能会导致布局溢出或重叠。开发者需要考虑内容量和容器尺寸的匹配。

3. **误用 `column-span`:**  不正确地使用 `column-span: all;` 可能导致元素占据整个宽度，打断预期的多列布局。例如，在一个多列容器中间的一个元素设置了 `column-span: all;`，它会跨越所有列，后续内容会从新的一行开始。

4. **与浮动元素或绝对定位元素冲突:** 多列布局与浮动元素和绝对定位元素的交互可能比较复杂，容易出现布局问题。需要仔细考虑这些元素的定位上下文和相互影响。

5. **动态修改内容导致性能问题:** 如果 JavaScript 频繁地修改多列容器的内容，会导致浏览器频繁地进行重新布局，可能影响性能。

6. **浏览器兼容性问题:** 虽然多列布局是标准 CSS，但不同浏览器在实现细节上可能存在差异，导致在某些浏览器上出现布局不一致的情况。开发者需要进行兼容性测试。

**总结:**

`LayoutMultiColumnSet` 是 Blink 渲染引擎中负责实现 CSS 多列布局的核心类。它管理列的组织、计算布局信息，并与布局流程和样式系统紧密协作。理解其功能对于深入了解浏览器如何渲染多列布局以及排查相关的布局问题至关重要。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_multi_column_set.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2012 Apple Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/layout/layout_multi_column_set.h"

#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_flow_thread.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_spanner_placeholder.h"
#include "third_party/blink/renderer/core/layout/multi_column_fragmentainer_group.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"

namespace blink {

namespace {

// A helper class to access all child fragments of all fragments of a single
// multi-column container. This class ignores repeated fragments.
class ChildFragmentIterator {
  STACK_ALLOCATED();

 public:
  explicit ChildFragmentIterator(const LayoutBlockFlow& container)
      : container_(container) {
    DCHECK(container.IsFragmentationContextRoot());
    SkipEmptyFragments();
  }

  bool IsValid() const {
    if (fragment_index_ >= container_.PhysicalFragmentCount()) {
      return false;
    }
    const auto* break_token = CurrentFragment()->GetBreakToken();
    return !break_token || !break_token->IsRepeated();
  }

  bool NextChild() {
    DCHECK(IsValid());
    if (++child_index_ >= CurrentFragment()->Children().size()) {
      child_index_ = 0;
      ++fragment_index_;
      SkipEmptyFragments();
    }
    return IsValid();
  }

  const PhysicalBoxFragment* operator->() const {
    DCHECK(IsValid());
    return To<PhysicalBoxFragment>(
        CurrentFragment()->Children()[child_index_].get());
  }
  const PhysicalBoxFragment& operator*() const {
    DCHECK(IsValid());
    return To<PhysicalBoxFragment>(
        *CurrentFragment()->Children()[child_index_]);
  }
  PhysicalOffset Offset() const {
    DCHECK(IsValid());
    return CurrentFragment()->Children()[child_index_].Offset();
  }

  wtf_size_t FragmentIndex() const { return fragment_index_; }

 private:
  const PhysicalBoxFragment* CurrentFragment() const {
    return container_.GetPhysicalFragment(fragment_index_);
  }

  void SkipEmptyFragments() {
    DCHECK_EQ(child_index_, 0u);
    while (IsValid() && CurrentFragment()->Children().size() == 0u) {
      ++fragment_index_;
    }
  }

  const LayoutBlockFlow& container_;
  wtf_size_t fragment_index_ = 0;
  wtf_size_t child_index_ = 0;
};

LayoutPoint ComputeLocation(const PhysicalBoxFragment& column_box,
                            PhysicalOffset column_offset,
                            LayoutUnit set_inline_size,
                            const LayoutBlockFlow& container,
                            wtf_size_t fragment_index,
                            const PhysicalBoxStrut& border_padding_scrollbar) {
  const PhysicalBoxFragment* container_fragment =
      container.GetPhysicalFragment(fragment_index);
  WritingModeConverter converter(
      container_fragment->Style().GetWritingDirection(),
      container_fragment->Size());
  // The inline-offset will be the content-box edge of the multicol container,
  // and the block-offset will be the block-offset of the column itself. It
  // doesn't matter which column from the same row we use, since all columns
  // have the same block-offset and block-size (so just use the first one).
  LogicalOffset logical_offset(
      border_padding_scrollbar.ConvertToLogical(converter.GetWritingDirection())
          .inline_start,
      converter.ToLogical(column_offset, column_box.Size()).block_offset);
  LogicalSize column_set_logical_size(
      set_inline_size, converter.ToLogical(column_box.Size()).block_size);
  PhysicalOffset physical_offset = converter.ToPhysical(
      logical_offset, converter.ToPhysical(column_set_logical_size));
  const BlockBreakToken* previous_container_break_token = nullptr;
  if (fragment_index > 0) {
    previous_container_break_token =
        container.GetPhysicalFragment(fragment_index - 1)->GetBreakToken();
  }
  // We have calculated the physical offset relative to the border edge of
  // this multicol container fragment. We'll now convert it to a legacy
  // engine LayoutPoint, which will also take care of converting it into the
  // flow thread coordinate space, if we happen to be nested inside another
  // fragmentation context.
  return LayoutBoxUtils::ComputeLocation(
      column_box, physical_offset,
      *container.GetPhysicalFragment(fragment_index),
      previous_container_break_token);
}

}  // namespace

LayoutMultiColumnSet::LayoutMultiColumnSet(LayoutFlowThread* flow_thread)
    : LayoutBlockFlow(nullptr),
      fragmentainer_groups_(*this),
      flow_thread_(flow_thread) {}

LayoutMultiColumnSet* LayoutMultiColumnSet::CreateAnonymous(
    LayoutFlowThread& flow_thread,
    const ComputedStyle& parent_style) {
  Document& document = flow_thread.GetDocument();
  LayoutMultiColumnSet* layout_object =
      MakeGarbageCollected<LayoutMultiColumnSet>(&flow_thread);
  layout_object->SetDocumentForAnonymous(&document);
  layout_object->SetStyle(
      document.GetStyleResolver().CreateAnonymousStyleWithDisplay(
          parent_style, EDisplay::kBlock));
  return layout_object;
}

void LayoutMultiColumnSet::Trace(Visitor* visitor) const {
  visitor->Trace(fragmentainer_groups_);
  visitor->Trace(flow_thread_);
  LayoutBlockFlow::Trace(visitor);
}

bool LayoutMultiColumnSet::IsLayoutNGObject() const {
  NOT_DESTROYED();
  return false;
}

unsigned LayoutMultiColumnSet::FragmentainerGroupIndexAtFlowThreadOffset(
    LayoutUnit flow_thread_offset,
    PageBoundaryRule rule) const {
  NOT_DESTROYED();
  UpdateGeometryIfNeeded();
  DCHECK_GT(fragmentainer_groups_.size(), 0u);
  if (flow_thread_offset <= 0)
    return 0;
  for (unsigned index = 0; index < fragmentainer_groups_.size(); index++) {
    const auto& row = fragmentainer_groups_[index];
    if (rule == kAssociateWithLatterPage) {
      if (row.LogicalTopInFlowThread() <= flow_thread_offset &&
          row.LogicalBottomInFlowThread() > flow_thread_offset)
        return index;
    } else if (row.LogicalTopInFlowThread() < flow_thread_offset &&
               row.LogicalBottomInFlowThread() >= flow_thread_offset) {
      return index;
    }
  }
  return fragmentainer_groups_.size() - 1;
}

const MultiColumnFragmentainerGroup&
LayoutMultiColumnSet::FragmentainerGroupAtVisualPoint(
    const LogicalOffset& visual_point) const {
  NOT_DESTROYED();
  UpdateGeometryIfNeeded();
  DCHECK_GT(fragmentainer_groups_.size(), 0u);
  LayoutUnit block_offset = visual_point.block_offset;
  for (unsigned index = 0; index < fragmentainer_groups_.size(); index++) {
    const auto& row = fragmentainer_groups_[index];
    if (row.LogicalTop() + row.GroupLogicalHeight() > block_offset)
      return row;
  }
  return fragmentainer_groups_.Last();
}

bool LayoutMultiColumnSet::IsPageLogicalHeightKnown() const {
  NOT_DESTROYED();
  return FirstFragmentainerGroup().IsLogicalHeightKnown();
}

LayoutMultiColumnSet* LayoutMultiColumnSet::NextSiblingMultiColumnSet() const {
  NOT_DESTROYED();
  for (LayoutObject* sibling = NextSibling(); sibling;
       sibling = sibling->NextSibling()) {
    if (sibling->IsLayoutMultiColumnSet())
      return To<LayoutMultiColumnSet>(sibling);
  }
  return nullptr;
}

LayoutMultiColumnSet* LayoutMultiColumnSet::PreviousSiblingMultiColumnSet()
    const {
  NOT_DESTROYED();
  for (LayoutObject* sibling = PreviousSibling(); sibling;
       sibling = sibling->PreviousSibling()) {
    if (sibling->IsLayoutMultiColumnSet())
      return To<LayoutMultiColumnSet>(sibling);
  }
  return nullptr;
}

MultiColumnFragmentainerGroup&
LayoutMultiColumnSet::AppendNewFragmentainerGroup() {
  NOT_DESTROYED();
  MultiColumnFragmentainerGroup new_group(*this);
  {  // Extra scope here for previousGroup; it's potentially invalid once we
     // modify the m_fragmentainerGroups Vector.
    MultiColumnFragmentainerGroup& previous_group =
        fragmentainer_groups_.Last();

    // This is the flow thread block offset where |previousGroup| ends and
    // |newGroup| takes over.
    LayoutUnit block_offset_in_flow_thread =
        previous_group.LogicalTopInFlowThread() +
        FragmentainerGroupCapacity(previous_group);
    previous_group.SetLogicalBottomInFlowThread(block_offset_in_flow_thread);
    new_group.SetLogicalTopInFlowThread(block_offset_in_flow_thread);
    new_group.SetLogicalTop(previous_group.LogicalTop() +
                            previous_group.GroupLogicalHeight());
    new_group.ResetColumnHeight();
  }
  fragmentainer_groups_.Append(new_group);
  return fragmentainer_groups_.Last();
}

LayoutUnit LayoutMultiColumnSet::LogicalTopInFlowThread() const {
  NOT_DESTROYED();
  return FirstFragmentainerGroup().LogicalTopInFlowThread();
}

LayoutUnit LayoutMultiColumnSet::LogicalBottomInFlowThread() const {
  NOT_DESTROYED();
  return LastFragmentainerGroup().LogicalBottomInFlowThread();
}

PhysicalOffset LayoutMultiColumnSet::FlowThreadTranslationAtOffset(
    LayoutUnit block_offset,
    PageBoundaryRule rule) const {
  NOT_DESTROYED();
  return FragmentainerGroupAtFlowThreadOffset(block_offset, rule)
      .FlowThreadTranslationAtOffset(block_offset, rule);
}

LogicalOffset LayoutMultiColumnSet::VisualPointToFlowThreadPoint(
    const PhysicalOffset& visual_point) const {
  NOT_DESTROYED();
  LogicalOffset logical_point =
      CreateWritingModeConverter().ToLogical(visual_point, {});
  const MultiColumnFragmentainerGroup& row =
      FragmentainerGroupAtVisualPoint(logical_point);
  return row.VisualPointToFlowThreadPoint(logical_point -
                                          row.OffsetFromColumnSet());
}

void LayoutMultiColumnSet::ResetColumnHeight() {
  NOT_DESTROYED();
  fragmentainer_groups_.DeleteExtraGroups();
  fragmentainer_groups_.First().ResetColumnHeight();
}

void LayoutMultiColumnSet::StyleDidChange(StyleDifference diff,
                                          const ComputedStyle* old_style) {
  NOT_DESTROYED();
  LayoutBlockFlow::StyleDidChange(diff, old_style);

  // column-rule is specified on the parent (the multicol container) of this
  // object, but it's the column sets that are in charge of painting them.
  // A column rule is pretty much like any other box decoration, like borders.
  // We need to say that we have box decorations here, so that the columnn set
  // is invalidated when it gets laid out. We cannot check here whether the
  // multicol container actually has a visible column rule or not, because we
  // may not have been inserted into the tree yet. Painting a column set is
  // cheap anyway, because the only thing it can paint is the column rule, while
  // actual multicol content is handled by the flow thread.
  SetHasBoxDecorationBackground(true);
}

LayoutUnit LayoutMultiColumnSet::ColumnGap() const {
  NOT_DESTROYED();
  LayoutBlockFlow* parent_block = MultiColumnBlockFlow();

  if (const std::optional<Length>& column_gap =
          parent_block->StyleRef().ColumnGap()) {
    return ValueForLength(*column_gap, AvailableLogicalWidth());
  }

  // "1em" is recommended as the normal gap setting. Matches <p> margins.
  return LayoutUnit(
      parent_block->StyleRef().GetFontDescription().ComputedPixelSize());
}

unsigned LayoutMultiColumnSet::ActualColumnCount() const {
  NOT_DESTROYED();
  // FIXME: remove this method. It's a meaningless question to ask the set "how
  // many columns do you actually have?", since that may vary for each row.
  return FirstFragmentainerGroup().ActualColumnCount();
}

PhysicalRect LayoutMultiColumnSet::FragmentsBoundingBox(
    const PhysicalRect& bounding_box_in_flow_thread) const {
  NOT_DESTROYED();
  UpdateGeometryIfNeeded();
  PhysicalRect result;
  for (const auto& group : fragmentainer_groups_)
    result.Unite(group.FragmentsBoundingBox(bounding_box_in_flow_thread));
  return result;
}

void LayoutMultiColumnSet::InsertedIntoTree() {
  NOT_DESTROYED();
  LayoutBlockFlow::InsertedIntoTree();
  AttachToFlowThread();
}

void LayoutMultiColumnSet::WillBeRemovedFromTree() {
  NOT_DESTROYED();
  LayoutBlockFlow::WillBeRemovedFromTree();
  DetachFromFlowThread();
}

LayoutPoint LayoutMultiColumnSet::LocationInternal() const {
  NOT_DESTROYED();
  UpdateGeometryIfNeeded();
  return frame_location_;
}

PhysicalSize LayoutMultiColumnSet::Size() const {
  NOT_DESTROYED();
  UpdateGeometryIfNeeded();
  return frame_size_;
}

void LayoutMultiColumnSet::UpdateGeometryIfNeeded() const {
  if (!HasValidCachedGeometry() && EverHadLayout()) {
    // const_cast in order to update the cached value.
    const_cast<LayoutMultiColumnSet*>(this)->UpdateGeometry();
  }
}

void LayoutMultiColumnSet::UpdateGeometry() {
  NOT_DESTROYED();
  DCHECK(!HasValidCachedGeometry());
  SetHasValidCachedGeometry(true);
  frame_location_ = LayoutPoint();
  ResetColumnHeight();
  const LayoutBlockFlow* container = MultiColumnBlockFlow();
  DCHECK_GT(container->PhysicalFragmentCount(), 0u);

  const auto* first_fragment = container->GetPhysicalFragment(0);
  WritingMode writing_mode = first_fragment->Style().GetWritingMode();
  PhysicalBoxStrut border_padding_scrollbar = first_fragment->Borders() +
                                              first_fragment->Padding() +
                                              container->ComputeScrollbars();

  // Set the inline-size to that of the content-box of the multicol container.
  PhysicalSize content_size =
      first_fragment->Size() -
      PhysicalSize(border_padding_scrollbar.HorizontalSum(),
                   border_padding_scrollbar.VerticalSum());
  LogicalSize logical_size;
  logical_size.inline_size =
      content_size.ConvertToLogical(writing_mode).inline_size;

  // TODO(layout-dev): Ideally we should not depend on the layout tree structure
  // because it may be different from the tree for the physical fragments.
  const auto* previous_placeholder =
      DynamicTo<LayoutMultiColumnSpannerPlaceholder>(PreviousSibling());
  bool seen_previous_placeholder = !previous_placeholder;
  ChildFragmentIterator iter(*container);
  LayoutUnit flow_thread_offset;

  // Skip until a column box after previous_placeholder.
  for (; iter.IsValid(); iter.NextChild()) {
    if (!iter->IsFragmentainerBox()) {
      if (iter->IsLayoutObjectDestroyedOrMoved()) {
        continue;
      }
      const auto* child_box = To<LayoutBox>(iter->GetLayoutObject());
      if (child_box->IsColumnSpanAll()) {
        if (seen_previous_placeholder) {
          // The legacy tree builder (the flow thread code) sometimes
          // incorrectly keeps column sets that shouldn't be there anymore. If
          // we have two column spanners, that are in fact adjacent, even though
          // there's a spurious column set between them, the column set hasn't
          // been initialized correctly (since we still have a
          // pending_column_set at this point). Say hello to the column set that
          // shouldn't exist, so that it gets some initialization.
          SetIsIgnoredByNG();
          frame_size_ = ToPhysicalSize(logical_size, writing_mode);
          return;
        }
        if (previous_placeholder &&
            child_box == previous_placeholder->LayoutObjectInFlowThread()) {
          seen_previous_placeholder = true;
        }
      }
      continue;
    }
    if (seen_previous_placeholder) {
      break;
    }
    flow_thread_offset += FragmentainerLogicalCapacity(*iter).block_size;
  }
  if (!iter.IsValid()) {
    SetIsIgnoredByNG();
    frame_size_ = ToPhysicalSize(logical_size, writing_mode);
    return;
  }
  // Found the first column box after previous_placeholder.

  frame_location_ = ComputeLocation(
      *iter, iter.Offset(), logical_size.inline_size, *container,
      iter.FragmentIndex(), border_padding_scrollbar);

  while (true) {
    LogicalSize fragmentainer_logical_size =
        FragmentainerLogicalCapacity(*iter);
    LastFragmentainerGroup().SetLogicalTopInFlowThread(flow_thread_offset);
    logical_size.block_size += fragmentainer_logical_size.block_size;
    flow_thread_offset += fragmentainer_logical_size.block_size;
    LastFragmentainerGroup().SetColumnBlockSizeFromNG(
        fragmentainer_logical_size.block_size);

    // Handle following fragmentainer boxes in the current container fragment.
    wtf_size_t fragment_index = iter.FragmentIndex();
    bool should_expand_last_set = false;
    while (iter.NextChild() && iter.FragmentIndex() == fragment_index) {
      if (iter->IsFragmentainerBox()) {
        LayoutUnit column_size = FragmentainerLogicalCapacity(*iter).block_size;
        flow_thread_offset += column_size;
        if (should_expand_last_set) {
          LastFragmentainerGroup().ExtendColumnBlockSizeFromNG(column_size);
          should_expand_last_set = false;
        }
      } else {
        if (iter->IsColumnSpanAll()) {
          const auto* placeholder =
              iter->GetLayoutObject()->SpannerPlaceholder();
          // If there is no column set after the spanner, we should expand the
          // last column set (if any) to encompass any columns that were created
          // after the spanner. Only do this if we're actually past the last
          // column set, though. We may have adjacent spanner placeholders,
          // because the legacy and NG engines disagree on whether there's
          // column content in-between (NG will create column content if the
          // parent block of a spanner has trailing margin / border / padding,
          // while legacy does not).
          if (placeholder && !placeholder->NextSiblingMultiColumnBox()) {
            should_expand_last_set = true;
            continue;
          }
        }
        break;
      }
    }
    LastFragmentainerGroup().SetLogicalBottomInFlowThread(flow_thread_offset);

    if (!iter.IsValid()) {
      break;
    }
    if (iter.FragmentIndex() == fragment_index || !iter->IsFragmentainerBox()) {
      // Found a physical fragment with !IsFragmentainerBox().
      break;
    }
    AppendNewFragmentainerGroup();
  }
  frame_size_ = ToPhysicalSize(logical_size, writing_mode);
}

void LayoutMultiColumnSet::AttachToFlowThread() {
  NOT_DESTROYED();
  if (DocumentBeingDestroyed())
    return;

  if (!flow_thread_)
    return;

  flow_thread_->AddColumnSetToThread(this);
}

void LayoutMultiColumnSet::DetachFromFlowThread() {
  NOT_DESTROYED();
  if (flow_thread_) {
    flow_thread_->RemoveColumnSetFromThread(this);
    flow_thread_ = nullptr;
  }
}

void LayoutMultiColumnSet::SetIsIgnoredByNG() {
  NOT_DESTROYED();
  fragmentainer_groups_.First().SetColumnBlockSizeFromNG(LayoutUnit());
}

}  // namespace blink

"""

```