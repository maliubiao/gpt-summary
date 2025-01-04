Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the `position_iterator.cc` file in the Chromium Blink engine, specifically how it relates to web technologies (JavaScript, HTML, CSS), common errors, debugging, and a high-level summary. The prompt also indicates this is the first part of a two-part analysis.

2. **Identify Key Components and Concepts:**  The code contains several important elements:
    * **Copyright Notice:**  Indicates the origin and licensing. While not a function, it's a standard part of source files.
    * **Includes:**  Lists necessary header files (`position_iterator.h`, `text.h`, `editing_utilities.h`, `position.h`). This gives clues about dependencies and related functionalities.
    * **Namespaces:** The code is within the `blink` namespace, and has an anonymous namespace `namespace { ... }`. This is standard C++ for organization.
    * **Templates:** The use of `template <typename Strategy>` suggests the code is designed to be flexible and work with different strategies for traversing the DOM tree.
    * **`SlowPositionIteratorAlgorithm`:**  A class with methods like `Increment()`, `Decrement()`, `ComputePosition()`, `AtStart()`, `AtEnd()`, etc. These strongly indicate the class is for iterating through positions in the DOM.
    * **`FastPositionIteratorAlgorithm`:** Another class with similar methods, likely offering a more optimized way to achieve the same goal. The names suggest a performance trade-off.
    * **DOM-related terms:**  `Node`, `Text`, `ContainerNode`, `Parent`, `FirstChild`, `LastChild`, `NextSibling`, `PreviousSibling`, `Offset`, `LayoutObject`. These confirm the file deals with manipulating the Document Object Model.
    * **Editing-related terms:** `EditingStrategy`, `EditingInFlatTreeStrategy`, `EditingIgnoresContent`, `IsUserSelectContain`. These point to the file's relevance in the context of content editing.
    * **`PositionTemplate`:** A class representing a specific location within the DOM.
    * **Grapheme Boundaries:**  Functions like `NextGraphemeBoundaryOf` and `PreviousGraphemeBoundaryOf` suggest handling of complex characters.

3. **Infer Functionality Based on Code Structure and Names:**
    * The presence of `Increment()` and `Decrement()` strongly suggests an iterator.
    * The `ComputePosition()` methods are likely responsible for returning a `Position` object representing the current iterator position.
    * `AtStart()` and `AtEnd()` are typical iterator boundary checks.
    * The "Slow" and "Fast" prefixes suggest different implementation approaches for the same core task.

4. **Connect to Web Technologies:**
    * **HTML:** The DOM is the fundamental representation of an HTML document. The iterator traverses this structure.
    * **CSS:**  While not directly manipulated, CSS properties like `user-select: contain` influence how the iterator behaves (the `IsUserSelectContain` checks). The presence of `GetLayoutObject()` suggests interaction with the rendering engine, which is influenced by CSS.
    * **JavaScript:** JavaScript often manipulates the DOM. The `PositionIterator` is a low-level engine component that makes it possible for higher-level JavaScript APIs related to selections, ranges, and editing to function.

5. **Develop Examples:**  To illustrate the connections, create concrete examples:
    * **HTML:** A simple HTML structure with nested elements.
    * **JavaScript:** A JavaScript snippet that might trigger the use of the iterator (e.g., `window.getSelection()`).
    * **CSS:** An example using `user-select: contain`.

6. **Consider Common Errors and Debugging:**
    * **User Errors:** Think about what actions a user might take in a web page that would involve editing or selecting text.
    * **Programming Errors:**  Consider how a developer using Blink's API might misuse the iterator or related classes.
    * **Debugging:**  Relate the iterator's behavior to the debugging process (stepping through code, examining state).

7. **Formulate Assumptions for Input/Output:** Since the code is about iteration, a natural assumption is to start with a given position and then show how `Increment()` or `Decrement()` would change that position. Use the provided DOM tree example from the code comments.

8. **Address the "Part 1" Request:** The prompt explicitly asks for a summary of the functionality for this first part. Focus on the core purpose of the `PositionIterator` and its variations.

9. **Structure the Answer:**  Organize the information logically with clear headings and bullet points. This makes the answer easier to read and understand.

10. **Refine and Review:**  Read through the answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might not explicitly mention grapheme boundaries, but seeing the functions in the code reminds me to include that detail. I also want to emphasize the "low-level" nature of this code within the browser engine.

By following this structured approach, I can systematically analyze the code snippet and generate a comprehensive and informative answer that addresses all aspects of the user's request. The iterative nature of the process (infer, example, refine) helps to build a complete understanding.
好的，让我们来分析一下 `blink/renderer/core/editing/position_iterator.cc` 文件的功能。

**功能归纳 (针对第 1 部分):**

这个文件的主要功能是**提供一种在 Blink 渲染引擎中遍历 DOM 树中编辑位置的能力。** 它定义了两种主要的迭代器算法：

* **`SlowPositionIteratorAlgorithm`**:  一种较为简单但可能效率较低的迭代算法。
* **`FastPositionIteratorAlgorithm`**:  一种可能更复杂但更高效的迭代算法。

这两个算法都允许在 DOM 树中向前和向后移动，并确定当前位置的相关信息，例如是否在节点的开始或结尾。它们的核心目的是为编辑操作提供精细的位置控制。

**详细功能拆解及关联说明:**

1. **DOM 树遍历:**
   - 这两个迭代器都旨在遍历 DOM 树的结构，从一个位置移动到另一个位置。
   - 它们考虑了父节点、子节点、兄弟节点之间的关系。
   - **与 HTML 的关系:** HTML 结构被解析成 DOM 树，这是迭代器遍历的基础。例如，迭代器可以从一个 `<div>` 的起始位置移动到其内部的 `<p>` 标签的起始位置，再到 `<p>` 标签内的文本节点的某个字符位置。

2. **编辑位置抽象:**
   - `PositionTemplate` 类用于表示 DOM 树中的一个特定编辑位置，包括锚点节点和偏移量。
   - 迭代器的目标是生成和操作 `PositionTemplate` 对象。
   - **与 JavaScript 的关系:**  JavaScript 中与选区 (Selection) 和范围 (Range) 相关的 API，例如 `window.getSelection()` 和 `document.createRange()`，在底层会依赖这种位置迭代机制来确定选区的起始和结束位置。

3. **前进和后退迭代:**
   - `Increment()` 方法用于将迭代器向前移动到下一个编辑位置。
   - `Decrement()` 方法用于将迭代器向后移动到上一个编辑位置。
   - 算法需要考虑不同类型的节点（元素节点、文本节点等）和它们的子节点。

4. **位置判断:**
   - `AtStart()`: 判断是否位于文档的起始位置。
   - `AtEnd()`: 判断是否位于文档的结束位置。
   - `AtStartOfNode()`: 判断是否位于当前节点的起始位置。
   - `AtEndOfNode()`: 判断是否位于当前节点的结束位置。

5. **处理 `user-select: contain` 属性:**
   - 代码中多次出现 `IsUserSelectContain()` 的检查。
   - **与 CSS 的关系:** `user-select: contain` 是一个 CSS 属性，用于控制是否可以将元素的内部内容作为单个原子进行选择。迭代器需要考虑这种特殊的选择行为，避免进入到 `user-select: contain` 元素的内部进行逐个子节点的遍历，而是将其视为一个整体。

6. **处理被忽略的内容 (`EditingIgnoresContent`)**:
   - 代码中也有 `EditingIgnoresContent()` 的检查。
   - 这可能与一些特殊类型的元素或编辑规则有关，例如某些被标记为不可编辑的区域。迭代器需要跳过这些被忽略的内容。

7. **区分慢速和快速算法:**
   - `SlowPositionIteratorAlgorithm` 是一种更直观的实现，可能更容易理解其逻辑。
   - `FastPositionIteratorAlgorithm`  旨在提高效率，可能通过缓存或更复杂的逻辑来优化遍历过程。

**逻辑推理的假设输入与输出 (以 `SlowPositionIteratorAlgorithm::Increment()` 为例):**

**假设输入:**

* DOM 树结构如下:
  ```html
  <div>
    <p>Text Node 1</p>
    <span>Text Node 2</span>
  </div>
  ```
* 当前迭代器的状态:
    * `anchor_node_`: 指向 `<p>` 元素
    * `node_after_position_in_anchor_`: 指向 `<p>` 元素内的 "Text Node 1" 文本节点
    * `offset_in_anchor_`: 0 (表示在文本节点 "Text Node 1" 的起始位置之前)

**输出:**

* 迭代器状态更新为:
    * `anchor_node_`: 指向 "Text Node 1" 文本节点
    * `node_after_position_in_anchor_`: `nullptr`
    * `offset_in_anchor_`: 0 (移动到文本节点的起始位置)

**用户或编程常见的使用错误示例:**

* **错误地假设迭代器不会跳过某些节点:**  如果开发者没有意识到 `user-select: contain` 或 `EditingIgnoresContent` 的影响，可能会错误地认为迭代器会遍历所有节点，从而导致逻辑错误。
* **在 DOM 结构改变后继续使用迭代器:**  如果在使用迭代器的过程中，DOM 树的结构发生了改变（例如，节点被添加或删除），迭代器的状态可能会变得无效，导致崩溃或不可预测的行为。代码中通过 `dom_tree_version_` 进行一定的检查，但开发者仍然需要注意这一点。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在网页上进行文本选择:**  用户可能通过鼠标拖拽或键盘操作 (Shift + 方向键) 在网页上选中了一段文本。
2. **浏览器引擎响应选择操作:**  当用户进行选择操作时，浏览器引擎需要记录选区的起始和结束位置。
3. **调用 Blink 渲染引擎的选区管理模块:**  选区管理模块会使用 `PositionIterator` 或相关的类来确定选区的边界。
4. **创建 `PositionIterator` 对象并初始化:** 根据选区的起始或结束位置，会创建一个 `PositionIterator` 对象，并将其初始化到对应的 DOM 节点和偏移量。
5. **调用 `Increment()` 或 `Decrement()` 方法进行遍历:** 为了找到选区的另一个边界，或者为了执行其他编辑操作（例如光标移动），可能会多次调用 `Increment()` 或 `Decrement()` 方法来在 DOM 树中移动。
6. **在调试器中查看 `PositionIterator` 的状态:**  当出现与选区或编辑相关的 bug 时，开发者可能会在调试器中单步执行代码，查看 `PositionIterator` 对象的内部状态（例如 `anchor_node_`, `offset_in_anchor_` 等），以理解迭代器的移动过程和定位是否正确。

**总结:**

`position_iterator.cc` 文件的核心在于提供了在 DOM 树中进行精细位置遍历的机制，这是 Blink 渲染引擎中实现文本选择、光标移动、编辑操作等功能的基础。它需要处理各种复杂的 DOM 结构和特殊属性的影响，以确保编辑位置的准确性和一致性。  `SlowPositionIteratorAlgorithm` 和 `FastPositionIteratorAlgorithm` 提供了不同的实现策略，以满足不同的性能需求。

Prompt: 
```
这是目录为blink/renderer/core/editing/position_iterator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2007, 2008 Apple Inc. All rights reserved.
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
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/position_iterator.h"

#include "base/numerics/safe_conversions.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/position.h"

namespace blink {

namespace {

// TODO(editing-dev): We should replace usages of |hasChildren()| in
// |PositionIterator| to |shouldTraverseChildren()|.
template <typename Strategy>
bool ShouldTraverseChildren(const Node& node) {
  return Strategy::HasChildren(node) && !IsUserSelectContain(node);
}

template <typename Strategy>
int LastOffsetForPositionIterator(const Node* node) {
  return IsUserSelectContain(*node) ? 1 : Strategy::LastOffsetForEditing(node);
}

// TODO(editing-dev): We should replace usages of |parent()| in
// |PositionIterator| to |selectableParentOf()|.
template <typename Strategy>
ContainerNode* SelectableParentOf(const Node& node) {
  ContainerNode* const parent = Strategy::Parent(node);
  return parent && !IsUserSelectContain(*parent) ? parent : nullptr;
}

}  // namespace

static constexpr int kInvalidOffset = -1;

template <typename Strategy>
SlowPositionIteratorAlgorithm<Strategy>::SlowPositionIteratorAlgorithm(
    const PositionTemplate<Strategy>& pos) {
  if (pos.IsNull())
    return;
  anchor_node_ = pos.AnchorNode();
  const int offset_in_anchor = pos.ComputeEditingOffset();

  node_after_position_in_anchor_ =
      Strategy::ChildAt(*anchor_node_, offset_in_anchor);
  offset_in_anchor_ = node_after_position_in_anchor_ ? 0 : offset_in_anchor;
  dom_tree_version_ = anchor_node_->GetDocument().DomTreeVersion();

  for (Node* node = SelectableParentOf<Strategy>(*anchor_node_); node;
       node = SelectableParentOf<Strategy>(*node)) {
    // Each offsets_in_anchor_node_[offset] should be an index of node in
    // parent, but delay to calculate the index until it is needed for
    // performance.
    offsets_in_anchor_node_.push_back(kInvalidOffset);
    ++depth_to_anchor_node_;
  }
  if (node_after_position_in_anchor_)
    offsets_in_anchor_node_.push_back(offset_in_anchor);
}

template <typename Strategy>
PositionTemplate<Strategy>
SlowPositionIteratorAlgorithm<Strategy>::DeprecatedComputePosition() const {
  // TODO(yoichio): Share code to check domTreeVersion with EphemeralRange.
  DCHECK(IsValid());
  if (node_after_position_in_anchor_) {
    DCHECK(anchor_node_);
    DCHECK_EQ(Strategy::Parent(*node_after_position_in_anchor_), anchor_node_);
    DCHECK_NE(offsets_in_anchor_node_[depth_to_anchor_node_], kInvalidOffset);
    // FIXME: This check is inadaquete because any ancestor could be ignored by
    // editing
    if (EditingIgnoresContent(
            *Strategy::Parent(*node_after_position_in_anchor_)))
      return PositionTemplate<Strategy>::BeforeNode(*anchor_node_);
    return PositionTemplate<Strategy>(
        anchor_node_, offsets_in_anchor_node_[depth_to_anchor_node_]);
  }
  if (!anchor_node_)
    return PositionTemplate<Strategy>();
  if (Strategy::HasChildren(*anchor_node_)) {
    return PositionTemplate<Strategy>::LastPositionInOrAfterNode(*anchor_node_);
  }
  return PositionTemplate<Strategy>::EditingPositionOf(anchor_node_,
                                                       offset_in_anchor_);
}

template <typename Strategy>
PositionTemplate<Strategy>
SlowPositionIteratorAlgorithm<Strategy>::ComputePosition() const {
  DCHECK(IsValid());
  // Assume that we have the following DOM tree:
  // A
  // |-B
  // | |-E
  // | +-F
  // |
  // |-C
  // +-D
  //   |-G
  //   +-H
  if (node_after_position_in_anchor_) {
    // For example, position is before E, F.
    DCHECK(anchor_node_);
    DCHECK_EQ(Strategy::Parent(*node_after_position_in_anchor_), anchor_node_);
    DCHECK_NE(offsets_in_anchor_node_[depth_to_anchor_node_], kInvalidOffset);
    // TODO(yoichio): This should be equivalent to PositionTemplate<Strategy>(
    // anchor_node_, PositionAnchorType::kBeforeAnchor).
    return PositionTemplate<Strategy>(
        anchor_node_, offsets_in_anchor_node_[depth_to_anchor_node_]);
  }
  if (!anchor_node_)
    return PositionTemplate<Strategy>();
  if (ShouldTraverseChildren<Strategy>(*anchor_node_)) {
    // For example, position is the end of B.
    return PositionTemplate<Strategy>::LastPositionInOrAfterNode(*anchor_node_);
  }
  if (anchor_node_->IsTextNode())
    return PositionTemplate<Strategy>(anchor_node_, offset_in_anchor_);
  if (offset_in_anchor_)
    // For example, position is after G.
    return PositionTemplate<Strategy>(anchor_node_,
                                      PositionAnchorType::kAfterAnchor);
  // For example, position is before G.
  return PositionTemplate<Strategy>(anchor_node_,
                                    PositionAnchorType::kBeforeAnchor);
}

template <typename Strategy>
void SlowPositionIteratorAlgorithm<Strategy>::Increment() {
  DCHECK(IsValid());
  if (!anchor_node_)
    return;

  // Assume that we have the following DOM tree:
  // A
  // |-B
  // | |-E
  // | +-F
  // |
  // |-C
  // +-D
  //   |-G
  //   +-H
  // Let |anchor| as |anchor_node_| and
  // |child| as |node_after_position_in_anchor_|.
  if (node_after_position_in_anchor_) {
    // Case #1: Move to position before the first child of
    // |node_after_position_in_anchor_|.
    // This is a point just before |child|.
    // Let |anchor| is A and |child| is B,
    // then next |anchor| is B and |child| is E.
    anchor_node_ = node_after_position_in_anchor_;
    node_after_position_in_anchor_ =
        ShouldTraverseChildren<Strategy>(*anchor_node_)
            ? Strategy::FirstChild(*anchor_node_)
            : nullptr;
    offset_in_anchor_ = 0;
    // Increment depth intializing with 0.
    ++depth_to_anchor_node_;
    if (depth_to_anchor_node_ == offsets_in_anchor_node_.size())
      offsets_in_anchor_node_.push_back(0);
    else
      offsets_in_anchor_node_[depth_to_anchor_node_] = 0;
    return;
  }

  if (anchor_node_->GetLayoutObject() &&
      !ShouldTraverseChildren<Strategy>(*anchor_node_) &&
      offset_in_anchor_ <
          LastOffsetForPositionIterator<Strategy>(anchor_node_)) {
    // Case #2. This is the next of Case #1 or #2 itself.
    // Position is (|anchor|, |offset_in_anchor_|).
    // In this case |anchor| is a leaf(E,F,C,G or H) and
    // |offset_in_anchor_| is not on the end of |anchor|.
    // Then just increment |offset_in_anchor_|.
    offset_in_anchor_ =
        NextGraphemeBoundaryOf(*anchor_node_, offset_in_anchor_);
  } else {
    // Case #3. This is the next of Case #2 or #3.
    // Position is the end of |anchor|.
    // 3-a. If |anchor| has next sibling (let E),
    //      next |anchor| is B and |child| is F (next is Case #1.)
    // 3-b. If |anchor| doesn't have next sibling (let F),
    //      next |anchor| is B and |child| is null. (next is Case #3.)
    node_after_position_in_anchor_ = anchor_node_;
    anchor_node_ =
        SelectableParentOf<Strategy>(*node_after_position_in_anchor_);
    if (!anchor_node_)
      return;
    DCHECK_GT(depth_to_anchor_node_, 0u);
    --depth_to_anchor_node_;
    // Increment offset of |child| or initialize if it have never been
    // used.
    if (offsets_in_anchor_node_[depth_to_anchor_node_] == kInvalidOffset)
      offsets_in_anchor_node_[depth_to_anchor_node_] =
          Strategy::Index(*node_after_position_in_anchor_) + 1;
    else
      ++offsets_in_anchor_node_[depth_to_anchor_node_];
    node_after_position_in_anchor_ =
        Strategy::NextSibling(*node_after_position_in_anchor_);
    offset_in_anchor_ = offsets_in_anchor_node_[depth_to_anchor_node_];
  }
}

template <typename Strategy>
void SlowPositionIteratorAlgorithm<Strategy>::Decrement() {
  DCHECK(IsValid());
  if (!anchor_node_)
    return;

  // Assume that we have the following DOM tree:
  // A
  // |-B
  // | |-E
  // | +-F
  // |
  // |-C
  // +-D
  //   |-G
  //   +-H
  // Let |anchor| as |anchor_node_| and
  // |child| as |node_after_position_in_anchor_|.
  // Decrement() is complex but logically reverse of Increment(), of course:)
  if (node_after_position_in_anchor_) {
    anchor_node_ = Strategy::PreviousSibling(*node_after_position_in_anchor_);
    if (anchor_node_) {
      // Case #1-a. This is a revese of Increment()::Case#3-a.
      // |child| has a previous sibling.
      // Let |anchor| is B and |child| is F,
      // next |anchor| is E and |child| is null.
      node_after_position_in_anchor_ = nullptr;
      offset_in_anchor_ =
          ShouldTraverseChildren<Strategy>(*anchor_node_)
              ? 0
              : LastOffsetForPositionIterator<Strategy>(anchor_node_);
      // Decrement offset of |child| or initialize if it have never been
      // used.
      if (offsets_in_anchor_node_[depth_to_anchor_node_] == kInvalidOffset)
        offsets_in_anchor_node_[depth_to_anchor_node_] =
            Strategy::Index(*node_after_position_in_anchor_);
      else
        --offsets_in_anchor_node_[depth_to_anchor_node_];
      DCHECK_GE(offsets_in_anchor_node_[depth_to_anchor_node_], 0);
      // Increment depth intializing with last offset.
      ++depth_to_anchor_node_;
      if (depth_to_anchor_node_ >= offsets_in_anchor_node_.size())
        offsets_in_anchor_node_.push_back(offset_in_anchor_);
      else
        offsets_in_anchor_node_[depth_to_anchor_node_] = offset_in_anchor_;
      return;
    } else {
      // Case #1-b. This is a revese of Increment()::Case#1.
      // |child| doesn't have a previous sibling.
      // Let |anchor| is B and |child| is E,
      // next |anchor| is A and |child| is B.
      node_after_position_in_anchor_ =
          Strategy::Parent(*node_after_position_in_anchor_);
      anchor_node_ =
          SelectableParentOf<Strategy>(*node_after_position_in_anchor_);
      if (!anchor_node_)
        return;
      offset_in_anchor_ = 0;
      // Decrement depth and intialize if needs.
      DCHECK_GT(depth_to_anchor_node_, 0u);
      --depth_to_anchor_node_;
      if (offsets_in_anchor_node_[depth_to_anchor_node_] == kInvalidOffset)
        offsets_in_anchor_node_[depth_to_anchor_node_] =
            Strategy::Index(*node_after_position_in_anchor_);
    }
    return;
  }

  if (ShouldTraverseChildren<Strategy>(*anchor_node_)) {
    // Case #2. This is a reverse of increment()::Case3-b.
    // Let |anchor| is B, next |anchor| is F.
    anchor_node_ = Strategy::LastChild(*anchor_node_);
    offset_in_anchor_ =
        ShouldTraverseChildren<Strategy>(*anchor_node_)
            ? 0
            : LastOffsetForPositionIterator<Strategy>(anchor_node_);
    // Decrement depth initializing with -1 because
    // |node_after_position_in_anchor_| is null so still unneeded.
    if (depth_to_anchor_node_ >= offsets_in_anchor_node_.size())
      offsets_in_anchor_node_.push_back(kInvalidOffset);
    else
      offsets_in_anchor_node_[depth_to_anchor_node_] = kInvalidOffset;
    ++depth_to_anchor_node_;
    return;
  }
  if (offset_in_anchor_ && anchor_node_->GetLayoutObject()) {
    // Case #3-a. This is a reverse of Increment()::Case#2.
    // In this case |anchor| is a leaf(E,F,C,G or H) and
    // |offset_in_anchor_| is not on the beginning of |anchor|.
    // Then just decrement |offset_in_anchor_|.
    offset_in_anchor_ =
        PreviousGraphemeBoundaryOf(*anchor_node_, offset_in_anchor_);
    return;
  }
  // Case #3-b. This is a reverse of Increment()::Case#1.
  // In this case |anchor| is a leaf(E,F,C,G or H) and
  // |offset_in_anchor_| is on the beginning of |anchor|.
  // Let |anchor| is E,
  // next |anchor| is B and |child| is E.
  node_after_position_in_anchor_ = anchor_node_;
  anchor_node_ = SelectableParentOf<Strategy>(*anchor_node_);
  if (!anchor_node_)
    return;
  DCHECK_GT(depth_to_anchor_node_, 0u);
  --depth_to_anchor_node_;
  if (offsets_in_anchor_node_[depth_to_anchor_node_] != kInvalidOffset)
    return;
  offset_in_anchor_ = Strategy::Index(*node_after_position_in_anchor_);
  offsets_in_anchor_node_[depth_to_anchor_node_] = offset_in_anchor_;
}

template <typename Strategy>
bool SlowPositionIteratorAlgorithm<Strategy>::AtStart() const {
  DCHECK(IsValid());
  if (!anchor_node_)
    return true;
  if (Strategy::Parent(*anchor_node_))
    return false;
  return (!Strategy::HasChildren(*anchor_node_) && !offset_in_anchor_) ||
         (node_after_position_in_anchor_ &&
          !Strategy::PreviousSibling(*node_after_position_in_anchor_));
}

template <typename Strategy>
bool SlowPositionIteratorAlgorithm<Strategy>::AtEnd() const {
  DCHECK(IsValid());
  if (!anchor_node_)
    return true;
  if (node_after_position_in_anchor_)
    return false;
  return !Strategy::Parent(*anchor_node_) &&
         (Strategy::HasChildren(*anchor_node_) ||
          offset_in_anchor_ >= Strategy::LastOffsetForEditing(anchor_node_));
}

template <typename Strategy>
bool SlowPositionIteratorAlgorithm<Strategy>::AtStartOfNode() const {
  DCHECK(IsValid());
  if (!anchor_node_)
    return true;
  if (!node_after_position_in_anchor_) {
    return !ShouldTraverseChildren<Strategy>(*anchor_node_) &&
           !offset_in_anchor_;
  }
  return !Strategy::PreviousSibling(*node_after_position_in_anchor_);
}

template <typename Strategy>
bool SlowPositionIteratorAlgorithm<Strategy>::AtEndOfNode() const {
  DCHECK(IsValid());
  if (!anchor_node_)
    return true;
  if (node_after_position_in_anchor_)
    return false;
  return Strategy::HasChildren(*anchor_node_) ||
         offset_in_anchor_ >= Strategy::LastOffsetForEditing(anchor_node_);
}

template class CORE_TEMPLATE_EXPORT
    SlowPositionIteratorAlgorithm<EditingStrategy>;
template class CORE_TEMPLATE_EXPORT
    SlowPositionIteratorAlgorithm<EditingInFlatTreeStrategy>;

// ---

// static
template <typename Strategy>
typename FastPositionIteratorAlgorithm<Strategy>::ContainerType
FastPositionIteratorAlgorithm<Strategy>::ContainerToContainerType(
    const Node* node) {
  if (!node)
    return kNullNode;
  if (IsA<Text>(node) && node->GetLayoutObject())
    return kTextNode;
  if (IsA<CharacterData>(node))
    return kCharacterData;
  if (!Strategy::HasChildren(*node))
    return kNoChildren;
  if (::blink::IsUserSelectContain(*node))
    return kUserSelectContainNode;
  return kContainerNode;
}

template <typename Strategy>
FastPositionIteratorAlgorithm<Strategy>::FastPositionIteratorAlgorithm(
    const PositionType& position) {
  Initialize(position);
  AssertOffsetInContainerIsValid();
}

template <typename Strategy>
void FastPositionIteratorAlgorithm<Strategy>::Initialize(
    const PositionType& position) {
  container_node_ = position.AnchorNode();
  if (!container_node_)
    return;
  dom_tree_version_ = container_node_->GetDocument().DomTreeVersion();
  container_type_ = ContainerToContainerType(container_node_);

  switch (container_type_) {
    case kNullNode:
      NOTREACHED();
    case kNoChildren:
      switch (position.AnchorType()) {
        case PositionAnchorType::kAfterChildren:
        case PositionAnchorType::kAfterAnchor:
          offset_in_container_ = IgnoresChildren() ? 1 : 0;
          return;
        case PositionAnchorType::kBeforeAnchor:
          offset_in_container_ = 0;
          return;
        case PositionAnchorType::kOffsetInAnchor:
          DCHECK(!position.OffsetInContainerNode());
          offset_in_container_ = 0;
          return;
      }
      NOTREACHED() << "Invalid PositionAnchorType";
    case kCharacterData:
    case kTextNode:
      // Note: `Position::ComputeOffsetInContainer()` for `kAfterAnchor`
      // returns `container_node_->Index() + 1` instead of `Text::length()`.
      switch (position.AnchorType()) {
        case PositionAnchorType::kAfterChildren:
          NOTREACHED();
        case PositionAnchorType::kAfterAnchor:
          offset_in_container_ = To<CharacterData>(container_node_)->length();
          return;
        case PositionAnchorType::kBeforeAnchor:
          offset_in_container_ = 0;
          return;
        case PositionAnchorType::kOffsetInAnchor:
          offset_in_container_ = position.OffsetInContainerNode();
          return;
      }
      NOTREACHED() << "Invalid PositionAnchorType";
    case kContainerNode:
    case kUserSelectContainNode:
      container_type_ = kContainerNode;
      switch (position.AnchorType()) {
        case PositionAnchorType::kAfterChildren:
        case PositionAnchorType::kAfterAnchor:
          child_before_position_ = Strategy::LastChild(*container_node_);
          offset_in_container_ = child_before_position_ ? kInvalidOffset : 0;
          container_type_ = kContainerNode;
          return;
        case PositionAnchorType::kBeforeAnchor:
          child_before_position_ = nullptr;
          offset_in_container_ = 0;
          container_type_ = kContainerNode;
          return;
        case PositionAnchorType::kOffsetInAnchor:
          // This takes `O(position.OffsetInContainerNode())`.
          child_before_position_ = position.ComputeNodeBeforePosition();
          offset_in_container_ = position.OffsetInContainerNode();
          container_type_ = kContainerNode;
          return;
      }
      NOTREACHED() << " Invalid PositionAnchorType=" << position.AnchorType();
  }
  NOTREACHED() << " Invalid container_type_=" << container_type_;
}

template <typename Strategy>
FastPositionIteratorAlgorithm<Strategy>::FastPositionIteratorAlgorithm() =
    default;

template <typename Strategy>
void FastPositionIteratorAlgorithm<Strategy>::AssertOffsetInContainerIsValid()
    const {
#if DCHECK_IS_ON()
  switch (container_type_) {
    case kNullNode:
      DCHECK(!child_before_position_);
      DCHECK_EQ(offset_in_container_, kInvalidOffset);
      return;
    case kNoChildren:
      DCHECK(!child_before_position_);
      DCHECK(offset_in_container_ == 0 || offset_in_container_ == 1);
      return;
    case kCharacterData:
    case kTextNode:
      DCHECK(!child_before_position_);
      DCHECK_LE(offset_in_container_,
                To<CharacterData>(container_node_)->length());
      return;
    case kContainerNode:
    case kUserSelectContainNode:
      if (!child_before_position_) {
        DCHECK(!offset_in_container_);
        return;
      }
      if (offset_in_container_ == kInvalidOffset)
        return;
      DCHECK_EQ(offset_in_container_,
                Strategy::Index(*child_before_position_) + 1);
      return;
  }
  NOTREACHED() << " Invalid container_type_=" << container_type_;
#endif
}

template <typename Strategy>
void FastPositionIteratorAlgorithm<Strategy>::AssertOffsetStackIsValid() const {
#if DCHECK_IS_ON()
  auto it = offset_stack_.CheckedBegin();
  for (const Node& ancestor : Strategy::AncestorsOf(*container_node_)) {
    if (it == offset_stack_.CheckedEnd()) {
      break;
    }
    DCHECK_EQ(*it, Strategy::Index(ancestor)) << " " << ancestor;
    ++it;
  }
#endif
}

template <typename Strategy>
bool FastPositionIteratorAlgorithm<Strategy>::IsValid() const {
  if (container_node_ &&
      container_node_->GetDocument().DomTreeVersion() != dom_tree_version_)
    return false;
  AssertOffsetInContainerIsValid();
  return true;
}

template <typename Strategy>
Node* FastPositionIteratorAlgorithm<Strategy>::ChildAfterPosition() const {
  DCHECK(container_type_ == kContainerNode ||
         container_type_ == kUserSelectContainNode);
  return child_before_position_ ? Strategy::NextSibling(*child_before_position_)
                                : Strategy::FirstChild(*container_node_);
}

template <typename Strategy>
bool FastPositionIteratorAlgorithm<Strategy>::HasChildren() const {
  DCHECK(container_node_);
  return Strategy::HasChildren(*container_node_);
}

template <typename Strategy>
bool FastPositionIteratorAlgorithm<Strategy>::IgnoresChildren() const {
  DCHECK(container_node_);
  return EditingIgnoresContent(*container_node_);
}

template <typename Strategy>
bool FastPositionIteratorAlgorithm<Strategy>::IsUserSelectContain() const {
  DCHECK(container_node_);
  return ::blink::IsUserSelectContain(*container_node_);
}

template <typename Strategy>
void FastPositionIteratorAlgorithm<Strategy>::Decrement() {
  AssertOffsetInContainerIsValid();
  DecrementInternal();
  AssertOffsetInContainerIsValid();
}

template <typename Strategy>
void FastPositionIteratorAlgorithm<Strategy>::Increment() {
  AssertOffsetInContainerIsValid();
  IncrementInternal();
  AssertOffsetInContainerIsValid();
}

template <typename Strategy>
void FastPositionIteratorAlgorithm<Strategy>::DecrementInternal() {
  DCHECK(IsValid());
  switch (container_type_) {
    case kNullNode:
      return;
    case kNoChildren:
      if (!offset_in_container_ || !container_node_->GetLayoutObject())
        return MoveToPreviousContainer();
      offset_in_container_ = 0;
      return;
    case kCharacterData:
      return MoveToPreviousContainer();
    case kContainerNode:
      if (!child_before_position_)
        return MoveToPreviousContainer();

      if (IsUserSelectContain()) {
        if (!container_node_->GetLayoutObject())
          return MoveToPreviousContainer();
        if (!ChildAfterPosition()) {
          container_type_ = kUserSelectContainNode;
          return MoveToPreviousSkippingChildren();
        }
        // TODO(crbug.com/1132412): We should move to before children.
      }

      MoveOffsetInContainerBy(-1);
      SetContainer(child_before_position_);
      switch (container_type_) {
        case kNoChildren:
          child_before_position_ = nullptr;
          PushThenSetOffset(IgnoresChildren() ? 1 : 0);
          return;
        case kCharacterData:
        case kTextNode:
          child_before_position_ = nullptr;
          PushThenSetOffset(To<CharacterData>(container_node_)->length());
          return;
        case kContainerNode:
          child_before_position_ = Strategy::LastChild(*container_node_);
          PushThenSetOffset(kInvalidOffset);
          return;
        case kUserSelectContainNode:
          // TODO(crbug.com/1132412): We should move to before children.
          child_before_position_ = Strategy::FirstChild(*container_node_);
          PushThenSetOffset(child_before_position_ ? 1 : 0);
          return;
        case kNullNode:
          NOTREACHED() << " Unexpected container_type_=" << container_type_;
      }
      NOTREACHED() << " Invalid container_type_=" << container_type_;

    case kTextNode:
      if (!offset_in_container_)
        return MoveToPreviousContainer();
      offset_in_container_ =
          PreviousGraphemeBoundaryOf(*container_node_, offset_in_container_);
      return;
    case kUserSelectContainNode:
      // TODO(crbug.com/1132412): We should move to next container
      // unconditionally.
      if (!container_node_->GetLayoutObject())
        return MoveToPreviousContainer();
      return MoveToPreviousSkippingChildren();
  }
  NOTREACHED() << " Invalid container_type_=" << container_type_;
}

template <typename Strategy>
void FastPositionIteratorAlgorithm<Strategy>::IncrementInternal() {
  DCHECK(IsValid());
  switch (container_type_) {
    case kNullNode:
      return;
    case kNoChildren:
      if (offset_in_container_ || !container_node_->GetLayoutObject() ||
          !IgnoresChildren())
        return MoveToNextContainer();
      offset_in_container_ = 1;
      return;
    case kCharacterData:
      return MoveToNextContainer();
    case kContainerNode:
      if (!ChildAfterPosition())
        return MoveToNextContainer();
      MoveOffsetInContainerBy(1);
      child_before_position_ = ChildAfterPosition();
      SetContainer(child_before_position_);
      child_before_position_ = nullptr;
      return PushThenSetOffset(0);
    case kTextNode:
      if (offset_in_container_ == To<Text>(container_node_)->length())
        return MoveToNextContainer();
      offset_in_container_ =
          NextGraphemeBoundaryOf(*container_node_, offset_in_container_);
      return;
    case kUserSelectContainNode:
      // TODO(crbug.com/1132412): We should move to next container
      // unconditionally.
      if (!container_node_->GetLayoutObject())
        return MoveToNextContainer();
      // Note: We should skip to next container after visiting first child,
      // because `LastOffsetForPositionIterator()` returns 1.
      if (child_before_position_ == Strategy::FirstChild(*container_node_))
        return MoveToNextContainer();
      return MoveToNextSkippingChildren();
  }
  NOTREACHED() << " Invalid container_type_=" << container_type_;
}

template <typename Strategy>
void FastPositionIteratorAlgorithm<Strategy>::MoveToNextContainer() {
  PopOffsetStack();
  child_before_position_ = container_node_;
  SetContainer(SelectableParentOf<Strategy>(*container_node_));
}

template <typename Strategy>
void FastPositionIteratorAlgorithm<Strategy>::MoveToNextSkippingChildren() {
  if (child_before_position_ == Strategy::LastChild(*container_node_)) {
    PopOffsetStack();
    child_before_position_ = container_node_;
    return SetContainer(SelectableParentOf<Strategy>(*container_node_));
  }
  MoveOffsetInContainerBy(1);
  child_before_position_ = ChildAfterPosition();
}

template <typename Strategy>
void FastPositionIteratorAlgorithm<Strategy>::MoveToPreviousContainer() {
  PopOffsetStack();
  SetChildBeforePositionToPreviosuSigblingOf(*container_node_);
  SetContainer(SelectableParentOf<Strategy>(*container_node_));
}

template <typename Strategy>
void FastPositionIteratorAlgorithm<Strategy>::MoveToPreviousSkippingChildren() {
  if (!child_before_position_) {
    PopOffsetStack();
    SetChildBeforePositionToPreviosuSigblingOf(*container_node_);
    return SetContainer(SelectableParentOf<Strategy>(*container_node_));
  }
  MoveOffsetInContainerBy(-1);
  SetChildBeforePositionToPreviosuSigblingOf(*child_before_position_);
}

template <typename Strategy>
void FastPositionIteratorAlgorithm<
    Strategy>::SetChildBeforePositionToPreviosuSigblingOf(const Node& node) {
  child_before_position_ = Strategy::PreviousSibling(node);
  if (child_before_position_) {
    DCHECK(offset_in_container_);
    return;
  }
  DCHECK(offset_in_container_ == kInvalidOffset || !offset_in_container_);
  offset_in_container_ = 0;
}

template <typename Strategy>
void FastPositionIteratorAlgorithm<Strategy>::SetContainer(Node* node) {
  container_node_ = node;
  container_type_ = ContainerToContainerType(node);
  if (container_type_ == kNullNode) {
    child_before_position_ = nullptr;
    offset_in_container_ = kInvalidOffset;
    container_type_ = kNullNode;
  }
}

template <typename Strategy>
PositionTemplate<Strategy>
FastPositionIteratorAlgorithm<Strategy>::BeforeOrAfterPosition() const {
  DCHECK(IsValid());
  return IsBeforePosition() ? PositionType::BeforeNode(*container_node_)
                            : PositionType::AfterNode(*container_node_);
}

template <typename Strategy>
bool FastPositionIteratorAlgorithm<Strategy>::IsBeforePosition() const {
  DCHECK(IsValid());
  switch (container_type_) {
    case kNullNode:
    case kTextNode:
      NOTREACHED() << " Unexpected container_type_=" << container_type_;
    case kNoChildren:
    case kCharacterData:
    case kUserSelectContainNode:
      return !offset_in_container_;
    case kContainerNode:
      return !child_before_position_;
  }
  NOTREACHED() << " Invalid container_type_=" << container_type_;
}

template <typename Strategy>
PositionTemplate<Strategy>
FastPositionIteratorAlgorithm<Strategy>::DeprecatedComputePosition() const {
  DCHECK(IsValid());
  switch (container_type_) {
    case kNullNode:
      return PositionType();
    case kNoChildren:
      if (IgnoresChildren())
        return BeforeOrAfterPosition();
      DCHECK(!offset_in_container_);
      return PositionType(*container_node_, 0);
    case kCharacterData:
      if (IsA<Text>(*container_node_))
        return PositionType(*container_node_, offset_in_container_);
      return BeforeOrAfterPosition();
    case kContainerNode:
      if (Node* child_after_position = ChildAfterPosition()) {
        if (EditingIgnoresContent(*Strategy::Parent(*child_after_position)))
          return PositionType::BeforeNode(*container_node_);
        EnsureOffsetInContainer();
        return PositionType(*container_node_, offset_in_container_);
      }
      return PositionType::LastPositionInOrAfterNode(*container_node_);
    case kTextNode:
      return PositionType(*container_node_, offset_in_container_);
    case kUserSelectContainNode:
      return PositionType::LastPositionInOrAfterNode(*container_node_);
  }
  NOTREACHED() << " Invalid container_type_=" << container_type_;
}

template <typename Strategy>
PositionTemplate<Strategy>
FastPositionIteratorAlgorithm<Strategy>::ComputePosition() const {
  DCHECK(IsValid());
  switch (container_type_) {
    case kNullNode:
      return PositionType();
    case kNoChildren:
      return BeforeOrAfterPosition();
    case kCharacterData:
      if (IsA<Text>(*container_node_))
        return PositionType(*container_node_, offset_in_container_);
      return BeforeOrAfterPosition();
    case kContainerNode:
      if (ChildAfterPosition()) {
        EnsureOffsetInContainer();
        return PositionType(*container_node_, offset_in_container_);
      }
      if (IsUserSelectContain())
        return BeforeOrAfterPosition();
      return PositionType::LastPositionInOrAfterNode(*container_node_);
    case kTextNode:
      return PositionType(*container_node_, offset_in_container_);
    case kUserSelectContainNode:
      return BeforeOrAfterPosition();
  }
  NOTREACHED() << " Invalid container_type_=" << container_type_;
}

template <typename Strategy>
int FastPositionIteratorAlgorithm<Strategy>::OffsetInTextNode() const {
  DCHECK(IsValid());
  //`VisiblePositionTest.PlaceholderBRWithCollapsedSpace` calls this function
  // with `kCharacterData`.
  DCHECK(container_type_ == kTextNode || container_type_ == kCharacterData)
      << container_type_;
  DCHECK(IsA<Text>(container_node_)) << container_node_;
  return base::saturated_cast<int>(offset_in_container_);
}

template <typename Strategy>
bool FastPositionIteratorAlgorithm<Strategy>::AtStart() const {
  DCHECK(IsValid());
  if (!container_node_)
    return true;
  return !Strategy::Parent(*container_node_) && AtStartOfNode();
}

template <typename Strategy>
bool FastPositionIteratorAlgorithm<Strategy>::AtEnd() const {
  DCHECK(IsValid());
  if (!container_node_)
    return true;
  return !Strategy::Parent(*container_node_) && AtEndOfNode();
}

template <typename Strategy>
bool FastPositionIteratorAlgorithm<Strategy>::AtStartOfNode() const {
  DCHECK(IsValid());
  switch (container_type_) {
    case kNullNode:
      return true;
    case kContainerNode:
      return !child_before_position_;
    case kNoChildren:
    case kCharacterData:
    case kTextNode:
      return !offset_in_container_;
    case kUserSelectContainNode:
      return !child_before_position_;
  }
  NOTREACHED() << " Invalid container_type_=" << container_type_;
}

template <typename Strategy>
bool FastPositionIteratorAlgorithm<Strategy>::AtEndOfNode() const {
  DCHECK(IsValid());
  switch (container_type_) {
    case kNullNode:
      return true;
    case kContainerNode:
      return !ChildAfterPosition();
    case kNoChildren:
      return !IgnoresChildren() || offset_in_container_;
    case kCharacterData:
    case kTextNode:
      return offset_in_container_ =
"""


```