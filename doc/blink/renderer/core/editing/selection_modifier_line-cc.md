Response:
Let's break down the thought process to analyze this C++ code and generate the explanation.

**1. Initial Understanding and Goal Identification:**

The first step is to recognize the core purpose of the file. The file path `blink/renderer/core/editing/selection_modifier_line.cc` and the class name `SelectionModifier` strongly suggest it's about modifying text selections, specifically related to moving the selection by lines. The copyright notice indicates it's part of the Chromium Blink engine.

**2. Decomposition of the Code:**

The next step is to divide the code into manageable parts. The code has a clear structure:

* **Copyright and License:**  Standard licensing information.
* **Includes:**  Headers providing necessary classes and functions. These give clues about the functionality. Look for terms like "editing", "selection", "position", "layout", "inline".
* **Namespace `blink` and Anonymous Namespace:**  Standard C++ organization. The anonymous namespace indicates internal utility.
* **`AbstractLineBox` Class:** This looks like a key component. Its methods (`CreateFor`, `PreviousLine`, `NextLine`, `PositionForPoint`, etc.) hint at operations on individual lines of text. The name itself suggests an abstraction over the underlying layout representation of a line.
* **Helper Functions:**  Functions like `HighestEditableRootOfNode`, `PreviousNodeConsideringAtomicNodes`, `NextAtomicLeafNode`, `InSameLine`, `FindNodeInPreviousLine`, `PreviousRootInlineBoxCandidatePosition`, `NextRootInlineBoxCandidatePosition`. These seem to deal with traversing the DOM tree and identifying relevant nodes based on editability and line breaks.
* **`SelectionModifier` Class (static methods):**  The core functionality is within `PreviousLinePosition` and `NextLinePosition`. These are the entry points for moving the selection by lines.

**3. Analyzing Key Components:**

* **`AbstractLineBox`:** Focus on what it *does* rather than how it *does it* initially. It represents a line, can find previous/next lines, and can determine the position within the line based on a point. The `InlineCursor` member suggests it interacts with Blink's internal representation of inline layout.
* **Helper Functions:**  Try to infer their purpose from their names and parameters. For example, `HighestEditableRootOfNode` likely finds the topmost editable container. `PreviousAtomicLeafNode` deals with traversing "atomic" (non-splittable) leaf nodes. The "SameEditability" functions likely manage selection boundaries.
* **`PreviousLinePosition` and `NextLinePosition`:** These orchestrate the process. They first try to use `AbstractLineBox` to find the previous/next line. If that fails, they use the helper functions to find "candidate" positions and then create `AbstractLineBox` from those. The logic seems to handle cases where there isn't a clear "previous" or "next" line (e.g., at the beginning or end of a block). The handling of `IsEditablePosition` is important for preventing selections from crossing editability boundaries.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **HTML:** The code directly manipulates the DOM (Document Object Model) represented by `Node` objects. The concept of "editable" content is fundamental to HTML forms and elements with the `contenteditable` attribute. The code considers elements like `<br>`.
* **CSS:** The code interacts with layout information (`LayoutObject`, `LayoutBlockFlow`, `PhysicalOffset`, `LogicalRect`, `WritingMode`). CSS styles the visual presentation of HTML, including line breaks and text flow. The code needs to understand the geometry and directionality of text as defined by CSS.
* **JavaScript:**  JavaScript often triggers actions that lead to selection changes. User interactions like pressing the up/down arrow keys are typically handled by JavaScript, which then calls browser APIs that might eventually invoke code like this. The `Selection` and `Range` APIs in JavaScript are the high-level interfaces for working with selections.

**5. Logical Reasoning and Examples:**

Think about common scenarios and how the code might handle them:

* **Moving up/down in a simple paragraph:**  `AbstractLineBox` will likely be the primary mechanism.
* **Moving across editable/non-editable boundaries:** The `IsEditablePosition` checks and the adjustment functions come into play.
* **Moving at the beginning/end of a block:** The fallback logic using `FirstPositionInNode` and `LastPositionInNode` is relevant.
* **Moving in complex layouts (tables, floats):**  The helper functions for finding candidate positions become important.

Create simple HTML examples to illustrate these scenarios. For instance, a paragraph with inline elements or a mix of editable and non-editable content.

**6. User Errors and Debugging:**

Consider common user actions that might trigger this code and potential issues:

* **Incorrectly nested editable regions:**  This can lead to unexpected selection behavior.
* **CSS that makes line boxes difficult to determine:**  Complex layouts or unusual CSS properties might cause problems.
* **Unexpected DOM structure:**  JavaScript manipulations or malformed HTML can create situations the code doesn't handle well.

Think about how a developer would debug issues related to line-based selection. Setting breakpoints in this C++ code and inspecting the values of variables like `line`, `candidate`, and the positions would be crucial. The provided user interaction steps offer a basic debugging scenario.

**7. Structuring the Output:**

Organize the information logically using headings and bullet points. Start with a high-level summary, then go into details about the functionality, relationships to web technologies, examples, and debugging.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe `AbstractLineBox` directly maps to a CSS line box.
* **Correction:**  Realize it's likely an *abstraction* over the internal layout representation, which might be more complex than a simple CSS line box.
* **Initial thought:** Focus heavily on the low-level details of `InlineCursor`.
* **Refinement:**  Focus on the *purpose* of `AbstractLineBox` and its methods first, then delve into the implementation details if necessary for a deeper understanding.
* **Initial thought:**  Only consider simple text.
* **Refinement:**  Remember to consider more complex scenarios like tables, images, and editable regions.

By following these steps, breaking down the code, thinking about its purpose and interactions, and generating concrete examples, we can create a comprehensive and accurate explanation of the given C++ source code.
这个文件 `blink/renderer/core/editing/selection_modifier_line.cc` 的主要功能是**在 Blink 渲染引擎中，实现基于行的光标或选区移动逻辑。**  它定义了 `SelectionModifier` 类的静态方法 `PreviousLinePosition` 和 `NextLinePosition`，这两个方法分别负责计算在文本中向上或向下移动一行后，光标应该放置的新位置。

更具体地说，这个文件：

1. **处理跨行的光标/选区移动：** 当用户按下向上或向下箭头键，并且光标当前不在文本块的起始或结束行时，这两个函数会被调用来确定目标位置。
2. **考虑复杂的布局：**  它需要处理各种复杂的 HTML 结构和 CSS 样式，例如：
    * **不同的书写模式 (writing-mode)：** 从左到右、从右到左、垂直书写等。
    * **行内元素和块级元素混合：** 需要找到正确的行边界。
    * **可编辑区域 (contenteditable)：** 需要考虑编辑边界，避免光标移动到不可编辑区域。
    * **表格 (table)、浮动 (float) 等布局：**  需要正确判断上一行和下一行。
3. **使用 Blink 内部的布局和编辑相关的类：**  例如 `PositionInFlatTreeWithAffinity` (扁平树中的位置和粘性)， `VisiblePosition` (可见位置)， `AbstractLineBox` (抽象的行框，封装了行的信息)， `LayoutBlockFlow` (块级布局对象) 等。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:** 当用户在网页上按下向上或向下箭头键时，浏览器通常会触发一个 `keydown` 或 `keyup` 事件。JavaScript 代码可以监听这些事件，并调用浏览器的 API 来移动光标或修改选区。Blink 引擎内部会调用 `SelectionModifier::PreviousLinePosition` 或 `SelectionModifier::NextLinePosition` 来计算新的光标位置。
    * **举例:**  假设用户在一个 `<textarea>` 元素中输入了多行文本，然后点击了中间某一行，并按下向上箭头键。浏览器会执行 JavaScript 相关的事件处理，最终调用 Blink 的代码，其中就包括这个文件中的函数来确定光标应该移动到上一行的哪个位置。

* **HTML:** HTML 结构定义了文本的组织方式和可编辑性。`SelectionModifier` 需要理解 HTML 结构才能正确地定位行和边界。例如，`<br>` 标签会强制换行，`contenteditable` 属性会影响光标的移动范围。
    * **举例:**  考虑如下 HTML：
      ```html
      <p>第一行文本<br>第二行文本</p>
      ```
      当光标在“第二行文本”的开头，调用 `PreviousLinePosition` 应该能正确地将光标移动到“第一行文本”的末尾（`<br>` 标签之前）。

* **CSS:** CSS 样式决定了文本的渲染方式，包括行高、字体大小、书写方向等，这些都直接影响到行的划分和光标的定位。`SelectionModifier` 需要考虑这些样式信息。
    * **举例:** 如果 CSS 设置了较大的 `line-height`，那么即使文本内容不多，每行也会占据较大的垂直空间。`NextLinePosition` 需要根据渲染后的布局信息来找到下一行的起始位置，而不是简单地向下移动固定的像素距离。
    * **再举例:**  如果 CSS 设置了 `direction: rtl;` (从右到左书写)， `PreviousLinePosition` 和 `NextLinePosition` 需要反向理解“上一行”和“下一行”。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **`position`:** 光标当前的 `PositionInFlatTreeWithAffinity` 对象，指向一个多行 `<p>` 元素的第二行中间的某个字符。
* **`line_direction_point`:** 一个 `LayoutUnit` 值，表示当前光标位置的水平坐标（相对于包含块）。这个值用于在目标行上找到与当前位置水平对齐的点。

**逻辑推理过程 (简化):**

1. **获取当前行的 `AbstractLineBox`。**
2. **调用 `PreviousLine()` 获取上一行的 `AbstractLineBox`。**
3. **如果找到了上一行，则使用 `AbsoluteLineDirectionPointToLocalPointInBlock()` 将 `line_direction_point` 转换为上一行坐标系下的点。**
4. **调用 `PositionForPoint()` 在上一行中找到与转换后的点最接近的文本位置。**
5. **返回找到的 `PositionInFlatTreeWithAffinity` 对象。**

**假设输出:**

* 一个 `PositionInFlatTreeWithAffinity` 对象，指向 `<p>` 元素第一行中，与输入位置水平方向大致对齐的那个字符的位置。

**涉及用户或编程常见的使用错误举例说明:**

* **用户操作错误:**
    * **在单行文本框中尝试上下移动:**  如果光标在一个没有换行的输入框中，`PreviousLinePosition` 和 `NextLinePosition` 可能会将光标移动到文本框的开头或结尾，或者不做任何操作，这取决于具体的实现和边界条件处理。
    * **在内容为空的元素中移动:**  如果光标在一个空的 `<div>` 或 `<p>` 元素中，这两个函数可能不会产生预期的效果，因为没有实际的行可以移动。

* **编程错误 (Blink 引擎内部或相关代码):**
    * **布局信息计算错误:** 如果 Blink 的布局引擎计算的行框信息不正确，`AbstractLineBox` 获取到的行边界可能错误，导致光标移动到错误的位置。
    * **可编辑边界处理不当:**  如果代码没有正确判断可编辑区域的边界，可能会出现光标从可编辑区域跳到不可编辑区域，或者反过来的错误。
    * **书写模式处理遗漏:**  在某些复杂的书写模式下，例如垂直书写和横向书写混合的情况下，计算上一行和下一行可能会出现错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户打开一个包含多行可编辑文本的网页。** 例如，一个带有 `<textarea>` 元素或者设置了 `contenteditable="true"` 的 `<div>` 元素。
2. **用户使用鼠标点击或键盘操作将光标放置在文本的中间某一行。**
3. **用户按下键盘上的向上或向下箭头键。**
4. **浏览器接收到键盘事件。**
5. **浏览器的事件处理机制（通常是 JavaScript 代码）会调用相关的 API 来移动光标。**
6. **Blink 渲染引擎接收到移动光标的请求。**
7. **Blink 的选择管理模块 (Selection) 判断需要进行跨行移动。**
8. **根据移动方向，调用 `SelectionModifier::PreviousLinePosition` 或 `SelectionModifier::NextLinePosition` 函数。**
9. **这个文件中的代码根据当前的布局信息和光标位置，计算出目标行的位置。**

**调试线索:**

* **断点设置:** 可以在 `SelectionModifier::PreviousLinePosition` 和 `SelectionModifier::NextLinePosition` 函数的开头设置断点，观察函数的调用情况和输入参数。
* **查看 `position` 参数:**  检查当前的 `PositionInFlatTreeWithAffinity` 对象，确认光标的起始位置是否正确。
* **检查 `AbstractLineBox` 的创建和使用:**  查看 `AbstractLineBox::CreateFor()` 是否成功创建了当前行的行框对象，以及 `PreviousLine()` 和 `NextLine()` 方法是否返回了预期的行框。
* **分析布局信息:**  如果怀疑是布局问题，可以使用 Blink 提供的调试工具查看相关的布局对象 (`LayoutObject`) 和行框信息。
* **测试不同的 HTML 结构和 CSS 样式:**  创建一个最小的可复现问题的 HTML 页面，逐步修改 HTML 和 CSS，观察光标移动的行为，从而定位问题。

总而言之，`selection_modifier_line.cc` 文件在 Blink 引擎中扮演着关键的角色，它负责处理用户在文本中进行基于行的导航操作，并且需要考虑到各种复杂的网页结构和样式。 理解这个文件的功能有助于理解浏览器是如何处理文本编辑和光标移动的。

### 提示词
```
这是目录为blink/renderer/core/editing/selection_modifier_line.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009 Apple Inc. All rights
 * reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
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

// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/selection_modifier.h"

#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/inline_box_position.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_rect.h"
#include "third_party/blink/renderer/core/layout/inline/line_utils.h"

namespace blink {

namespace {

// TODO(1229581): Get rid of this.
class AbstractLineBox {
  STACK_ALLOCATED();

 public:
  AbstractLineBox() = default;

  static AbstractLineBox CreateFor(const PositionInFlatTreeWithAffinity&);

  explicit operator bool() const { return IsNotNull(); }
  bool IsNotNull() const { return !IsNull(); }
  bool IsNull() const { return type_ == Type::kNull; }

  bool CanBeCaretContainer() const {
    DCHECK(IsNotNull());
    // We want to skip zero height boxes.
    if (cursor_.Current().IsEmptyLineBox())
      return false;
    const PhysicalSize physical_size = cursor_.Current().Size();
    const LogicalSize logical_size = physical_size.ConvertToLogical(
        cursor_.Current().Style().GetWritingMode());
    if (!logical_size.block_size)
      return false;
    for (InlineCursor cursor(cursor_); cursor; cursor.MoveToNext()) {
      const InlineCursorPosition& current = cursor.Current();
      if (current.GetLayoutObject() && current.IsInlineLeaf())
        return true;
    }
    return false;
  }

  AbstractLineBox PreviousLine() const {
    DCHECK(IsNotNull());
    InlineCursor previous_line = cursor_;
    do {
      previous_line.MoveToPreviousIncludingFragmentainer();
    } while (previous_line && !previous_line.Current().IsLineBox());
    if (!previous_line || previous_line.Current()->IsBlockInInline())
      return AbstractLineBox();
    return AbstractLineBox(previous_line);
  }

  AbstractLineBox NextLine() const {
    DCHECK(IsNotNull());
    InlineCursor next_line = cursor_;
    do {
      next_line.MoveToNextIncludingFragmentainer();
    } while (next_line && !next_line.Current().IsLineBox());
    if (!next_line || next_line.Current()->IsBlockInInline())
      return AbstractLineBox();
    return AbstractLineBox(next_line);
  }

  PhysicalOffset AbsoluteLineDirectionPointToLocalPointInBlock(
      LayoutUnit line_direction_point) {
    DCHECK(IsNotNull());
    const LayoutBlockFlow& containing_block = GetBlock();
    // TODO(yosin): Is kIgnoreTransforms correct here?
    PhysicalOffset absolute_block_point = containing_block.LocalToAbsolutePoint(
        PhysicalOffset(), kIgnoreTransforms);
    if (containing_block.IsScrollContainer())
      absolute_block_point -= containing_block.ScrolledContentOffset();

    if (containing_block.IsHorizontalWritingMode()) {
      return PhysicalOffset(line_direction_point - absolute_block_point.left,
                            PhysicalBlockOffset());
    }
    return PhysicalOffset(PhysicalBlockOffset(),
                          line_direction_point - absolute_block_point.top);
  }

  PositionInFlatTreeWithAffinity PositionForPoint(
      const PhysicalOffset& point_in_container,
      bool only_editable_leaves) const {
    return PositionForPoint(cursor_, point_in_container, only_editable_leaves);
  }

 private:
  explicit AbstractLineBox(const InlineCursor& cursor)
      : cursor_(cursor), type_(Type::kLayoutNG) {
    DCHECK(cursor_.Current().IsLineBox());
  }

  const LayoutBlockFlow& GetBlock() const {
    DCHECK(IsNotNull());
    return *cursor_.GetLayoutBlockFlow();
  }

  LayoutUnit PhysicalBlockOffset() const {
    DCHECK(IsNotNull());
    const PhysicalOffset physical_offset =
        cursor_.Current().OffsetInContainerFragment();
    return cursor_.Current().Style().IsHorizontalWritingMode()
               ? physical_offset.top
               : physical_offset.left;
  }

  bool IsLayoutNG() const { return type_ == Type::kLayoutNG; }

  static bool IsEditable(const InlineCursor& cursor) {
    const LayoutObject* const layout_object =
        cursor.Current().GetLayoutObject();
    return layout_object && layout_object->GetNode() &&
           blink::IsEditable(*layout_object->GetNode());
  }

  static PositionInFlatTreeWithAffinity PositionForPoint(
      const InlineCursor& line,
      const PhysicalOffset& point,
      bool only_editable_leaves) {
    DCHECK(line.Current().IsLineBox());
    const PhysicalSize unit_square(LayoutUnit(1), LayoutUnit(1));
    const LogicalOffset logical_point =
        point.ConvertToLogical({line.Current().Style().GetWritingMode(),
                                line.Current().BaseDirection()},
                               line.Current().Size(), unit_square);
    const LayoutUnit inline_offset = logical_point.inline_offset;
    InlineCursor closest_leaf_child;
    LayoutUnit closest_leaf_distance;
    for (InlineCursor cursor = line.CursorForDescendants(); cursor;
         cursor.MoveToNext()) {
      if (!cursor.Current().GetLayoutObject())
        continue;
      if (!cursor.Current().IsInlineLeaf())
        continue;
      if (only_editable_leaves && !IsEditable(cursor)) {
        // This condition allows us to move editable to editable with skipping
        // non-editable element.
        // [1] editing/selection/modify_move/move_backward_line_table.html
        continue;
      }

      const LogicalRect fragment_logical_rect =
          line.Current().ConvertChildToLogical(
              cursor.Current().RectInContainerFragment());
      const LayoutUnit inline_min = fragment_logical_rect.offset.inline_offset;
      const LayoutUnit inline_max = fragment_logical_rect.offset.inline_offset +
                                    fragment_logical_rect.size.inline_size;
      if (inline_offset >= inline_min && inline_offset < inline_max) {
        closest_leaf_child = cursor;
        break;
      }

      const LayoutUnit distance =
          inline_offset < inline_min
              ? inline_min - inline_offset
              : inline_offset - inline_max + LayoutUnit(1);
      if (!closest_leaf_child || distance < closest_leaf_distance) {
        closest_leaf_child = cursor;
        closest_leaf_distance = distance;
      }
    }
    if (!closest_leaf_child)
      return PositionInFlatTreeWithAffinity();
    const Node* const node = closest_leaf_child.Current().GetNode();
    if (!node)
      return PositionInFlatTreeWithAffinity();
    if (EditingIgnoresContent(*node)) {
      return PositionInFlatTreeWithAffinity(
          PositionInFlatTree::BeforeNode(*node));
    }
    return ToPositionInFlatTreeWithAffinity(
        closest_leaf_child.PositionForPointInChild(point));
  }

  enum class Type { kNull, kLayoutNG };

  InlineCursor cursor_;
  Type type_ = Type::kNull;
};

// static
AbstractLineBox AbstractLineBox::CreateFor(
    const PositionInFlatTreeWithAffinity& position) {
  if (position.IsNull() ||
      !position.GetPosition().AnchorNode()->GetLayoutObject()) {
    return AbstractLineBox();
  }

  const PositionWithAffinity adjusted =
      ToPositionInDOMTreeWithAffinity(ComputeInlineAdjustedPosition(position));
  if (adjusted.IsNull())
    return AbstractLineBox();

  const InlineCursor& line = NGContainingLineBoxOf(adjusted);
  if (line)
    return AbstractLineBox(line);
  return AbstractLineBox();
}

ContainerNode* HighestEditableRootOfNode(const Node& node) {
  return HighestEditableRoot(FirstPositionInOrBeforeNode(node));
}

Node* PreviousNodeConsideringAtomicNodes(const Node& start) {
  if (Node* previous_sibling = FlatTreeTraversal::PreviousSibling(start)) {
    Node* node = previous_sibling;
    while (!IsAtomicNodeInFlatTree(node)) {
      if (Node* last_child = FlatTreeTraversal::LastChild(*node))
        node = last_child;
    }
    return node;
  }
  return FlatTreeTraversal::Parent(start);
}

Node* NextNodeConsideringAtomicNodes(const Node& start) {
  if (!IsAtomicNodeInFlatTree(&start) && FlatTreeTraversal::HasChildren(start))
    return FlatTreeTraversal::FirstChild(start);
  if (Node* next_sibling = FlatTreeTraversal::NextSibling(start))
    return next_sibling;
  const Node* node = &start;
  while (node && !FlatTreeTraversal::NextSibling(*node))
    node = FlatTreeTraversal::Parent(*node);
  if (node)
    return FlatTreeTraversal::NextSibling(*node);
  return nullptr;
}

// Returns the previous leaf node or nullptr if there are no more. Delivers leaf
// nodes as if the whole DOM tree were a linear chain of its leaf nodes.
Node* PreviousAtomicLeafNode(const Node& start) {
  Node* node = PreviousNodeConsideringAtomicNodes(start);
  while (node) {
    if (IsAtomicNodeInFlatTree(node))
      return node;
    node = PreviousNodeConsideringAtomicNodes(*node);
  }
  return nullptr;
}

// Returns the next leaf node or nullptr if there are no more. Delivers leaf
// nodes as if the whole DOM tree were a linear chain of its leaf nodes.
Node* NextAtomicLeafNode(const Node& start) {
  Node* node = NextNodeConsideringAtomicNodes(start);
  while (node) {
    if (IsAtomicNodeInFlatTree(node))
      return node;
    node = NextNodeConsideringAtomicNodes(*node);
  }
  return nullptr;
}

Node* PreviousLeafWithSameEditability(const Node& node) {
  const bool editable = IsEditable(node);
  for (Node* runner = PreviousAtomicLeafNode(node); runner;
       runner = PreviousAtomicLeafNode(*runner)) {
    if (editable == IsEditable(*runner))
      return runner;
  }
  return nullptr;
}

Node* NextLeafWithGivenEditability(Node* node, bool editable) {
  if (!node)
    return nullptr;

  for (Node* runner = NextAtomicLeafNode(*node); runner;
       runner = NextAtomicLeafNode(*runner)) {
    if (editable == IsEditable(*runner))
      return runner;
  }
  return nullptr;
}

bool InSameLine(const Node& node,
                const PositionInFlatTreeWithAffinity& position) {
  if (!node.GetLayoutObject())
    return true;
  return InSameLine(CreateVisiblePosition(
                        PositionInFlatTree::FirstPositionInOrBeforeNode(node))
                        .ToPositionWithAffinity(),
                    position);
}

Node* FindNodeInPreviousLine(const Node& start_node,
                             const PositionInFlatTreeWithAffinity& position) {
  for (Node* runner = PreviousLeafWithSameEditability(start_node); runner;
       runner = PreviousLeafWithSameEditability(*runner)) {
    if (!InSameLine(*runner, position))
      return runner;
  }
  return nullptr;
}

// FIXME: consolidate with code in previousLinePosition.
PositionInFlatTree PreviousRootInlineBoxCandidatePosition(
    Node* node,
    const PositionInFlatTreeWithAffinity& position) {
  ContainerNode* highest_root = HighestEditableRoot(position.GetPosition());
  Node* const previous_node = FindNodeInPreviousLine(*node, position);
  for (Node* runner = previous_node; runner && !runner->IsShadowRoot();
       runner = PreviousLeafWithSameEditability(*runner)) {
    if (HighestEditableRootOfNode(*runner) != highest_root)
      break;

    const PositionInFlatTree& candidate =
        IsA<HTMLBRElement>(*runner) ? PositionInFlatTree::BeforeNode(*runner)
                                    : PositionInFlatTree::EditingPositionOf(
                                          runner, CaretMaxOffset(runner));
    if (IsVisuallyEquivalentCandidate(candidate))
      return candidate;
  }
  return PositionInFlatTree();
}

PositionInFlatTree NextRootInlineBoxCandidatePosition(
    Node* node,
    const PositionInFlatTreeWithAffinity& position) {
  ContainerNode* highest_root = HighestEditableRoot(position.GetPosition());
  // TODO(xiaochengh): We probably also need to pass in the starting editability
  // to |PreviousLeafWithSameEditability|.
  const bool is_editable =
      IsEditable(*position.GetPosition().ComputeContainerNode());
  Node* next_node = NextLeafWithGivenEditability(node, is_editable);
  while (next_node && InSameLine(*next_node, position)) {
    next_node = NextLeafWithGivenEditability(next_node, is_editable);
  }

  for (Node* runner = next_node; runner && !runner->IsShadowRoot();
       runner = NextLeafWithGivenEditability(runner, is_editable)) {
    if (HighestEditableRootOfNode(*runner) != highest_root)
      break;

    const PositionInFlatTree& candidate =
        PositionInFlatTree::EditingPositionOf(runner, CaretMinOffset(runner));
    if (IsVisuallyEquivalentCandidate(candidate))
      return candidate;
  }
  return PositionInFlatTree();
}

}  // namespace

// static
PositionInFlatTreeWithAffinity SelectionModifier::PreviousLinePosition(
    const PositionInFlatTreeWithAffinity& position,
    LayoutUnit line_direction_point) {
  // TODO(xiaochengh): Make all variables |const|.

  PositionInFlatTree p = position.GetPosition();
  Node* node = p.AnchorNode();

  if (!node)
    return PositionInFlatTreeWithAffinity();

  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object)
    return PositionInFlatTreeWithAffinity();

  AbstractLineBox line = AbstractLineBox::CreateFor(position);
  if (line) {
    line = line.PreviousLine();
    if (!line || !line.CanBeCaretContainer())
      line = AbstractLineBox();
  }

  if (!line) {
    PositionInFlatTree candidate =
        PreviousRootInlineBoxCandidatePosition(node, position);
    if (candidate.IsNotNull()) {
      line = AbstractLineBox::CreateFor(
          CreateVisiblePosition(candidate).ToPositionWithAffinity());
      if (!line) {
        // TODO(editing-dev): Investigate if this is correct for null
        // |CreateVisiblePosition(candidate)|.
        return PositionInFlatTreeWithAffinity(candidate);
      }
    }
  }

  if (line) {
    // FIXME: Can be wrong for multi-column layout and with transforms.
    PhysicalOffset point_in_line =
        line.AbsoluteLineDirectionPointToLocalPointInBlock(
            line_direction_point);
    if (auto candidate =
            line.PositionForPoint(point_in_line, IsEditablePosition(p))) {
      // If the current position is inside an editable position, then the next
      // shouldn't end up inside non-editable as that would cross the editing
      // boundaries which would be an invalid selection.
      if (IsEditablePosition(p) &&
          !IsEditablePosition(candidate.GetPosition())) {
        return AdjustBackwardPositionToAvoidCrossingEditingBoundaries(candidate,
                                                                      p);
      }
      return candidate;
    }
  }

  // Could not find a previous line. This means we must already be on the first
  // line. Move to the start of the content in this block, which effectively
  // moves us to the start of the line we're on.
  Element* root_element = IsEditable(*node)
                              ? RootEditableElement(*node)
                              : node->GetDocument().documentElement();
  if (!root_element)
    return PositionInFlatTreeWithAffinity();
  return PositionInFlatTreeWithAffinity(
      PositionInFlatTree::FirstPositionInNode(*root_element));
}

// static
PositionInFlatTreeWithAffinity SelectionModifier::NextLinePosition(
    const PositionInFlatTreeWithAffinity& position,
    LayoutUnit line_direction_point) {
  // TODO(xiaochengh): Make all variables |const|.

  PositionInFlatTree p = position.GetPosition();
  Node* node = p.AnchorNode();

  if (!node)
    return PositionInFlatTreeWithAffinity();

  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object)
    return PositionInFlatTreeWithAffinity();

  AbstractLineBox line = AbstractLineBox::CreateFor(position);
  if (line) {
    line = line.NextLine();
    if (!line || !line.CanBeCaretContainer())
      line = AbstractLineBox();
  }

  if (!line) {
    // FIXME: We need do the same in previousLinePosition.
    Node* child = FlatTreeTraversal::ChildAt(*node, p.ComputeEditingOffset());
    Node* search_start_node =
        child ? child : &FlatTreeTraversal::LastWithinOrSelf(*node);
    PositionInFlatTree candidate =
        NextRootInlineBoxCandidatePosition(search_start_node, position);
    if (candidate.IsNotNull()) {
      line = AbstractLineBox::CreateFor(
          CreateVisiblePosition(candidate).ToPositionWithAffinity());
      if (!line) {
        // TODO(editing-dev): Investigate if this is correct for null
        // |CreateVisiblePosition(candidate)|.
        return PositionInFlatTreeWithAffinity(candidate);
      }
    }
  }

  if (line) {
    // FIXME: Can be wrong for multi-column layout and with transforms.
    PhysicalOffset point_in_line =
        line.AbsoluteLineDirectionPointToLocalPointInBlock(
            line_direction_point);
    if (auto candidate =
            line.PositionForPoint(point_in_line, IsEditablePosition(p))) {
      // If the current position is inside an editable position, then the next
      // shouldn't end up inside non-editable as that would cross the editing
      // boundaries which would be an invalid selection.
      if (IsEditablePosition(p) &&
          !IsEditablePosition(candidate.GetPosition())) {
        return AdjustForwardPositionToAvoidCrossingEditingBoundaries(candidate,
                                                                     p);
      }
      return candidate;
    }
  }

  // Could not find a next line. This means we must already be on the last line.
  // Move to the end of the content in this block, which effectively moves us
  // to the end of the line we're on.
  Element* root_element = IsEditable(*node)
                              ? RootEditableElement(*node)
                              : node->GetDocument().documentElement();
  if (!root_element)
    return PositionInFlatTreeWithAffinity();
  return PositionInFlatTreeWithAffinity(
      PositionInFlatTree::LastPositionInNode(*root_element));
}

}  // namespace blink
```