Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/dom/range.cc`.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Class:** The code heavily revolves around the `Range` class. The first step is to understand that this file defines the behavior of a `Range` object in the Blink rendering engine.

2. **Analyze Includes:** The included headers provide clues about the `Range` class's purpose and relationships:
    * **DOM:**  `character_data.h`, `container_node.h`, `document_fragment.h`, `node.h`, `text.h` clearly indicate the `Range` class interacts with the DOM tree structure.
    * **Editing:** `editing_utilities.h`, `ephemeral_range.h`, `frame_selection.h`, `text_iterator.h`, `selection_template.h`, `set_selection_options.h`, `visible_position.h`, `visible_units.h` suggest that `Range` is fundamental to text editing and selection within the browser.
    * **Frame:** `local_dom_window.h`, `local_frame.h`, `settings.h` imply the `Range` is tied to the browsing context and its configurations.
    * **Geometry:** `dom_rect.h`, `dom_rect_list.h` suggest the `Range` can be used to determine the visual boundaries of selected content.
    * **Highlight:** `highlight_registry.h` indicates involvement in text highlighting.
    * **HTML/SVG:** `html_body_element.h`, `html_element.h`, `html_html_element.h`, `svg_svg_element.h` show it can span across different types of DOM elements.
    * **Layout:** `layout_object.h`, `layout_text.h`, `layout_text_fragment.h` connect the `Range` to the rendering of the content.

3. **Examine Class Members and Methods:**  Skimming through the methods within the `Range` class itself reveals its main functionalities:
    * **Creation and Management:** Constructors (`Range(...)`), `Create()`, `Dispose()`, `SetDocument()`.
    * **Boundary Manipulation:** `setStart()`, `setEnd()`, `collapse()`.
    * **Comparison:** `compareBoundaryPoints()`, `comparePoint()`, `isPointInRange()`.
    * **Content Manipulation:** `deleteContents()`, `extractContents()`, `cloneContents()`, `insertNode()`.
    * **Intersection:** `intersectsNode()`.
    * **Ancestor Retrieval:** `commonAncestorContainer()`.

4. **Identify Key Concepts:**  Several key concepts emerge from the code:
    * **Boundary Points:** The `start_` and `end_` members represent the start and end points of the range within the DOM tree.
    * **Document Association:**  A `Range` is always associated with a specific `Document`.
    * **Tree Scope:** The concept of tree scopes is important for ensuring ranges are within the same document.
    * **Selection:** The code interacts with the browser's selection mechanism.
    * **Content Modification:** The methods allow for deleting, extracting, cloning, and inserting content within the range.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `Range` object in JavaScript directly corresponds to this C++ implementation. JavaScript can create and manipulate `Range` objects to interact with the DOM. Examples include `document.createRange()`, `selection.getRangeAt()`, and methods like `range.setStart()`, `range.deleteContents()`, etc.
    * **HTML:** The `Range` represents a selection within the HTML structure. It can span across different HTML elements.
    * **CSS:** While not directly manipulating CSS, the `Range` indirectly affects how CSS is applied because changes to the DOM structure can trigger style recalculations. Furthermore, the visual representation of a selection (often with a background color) is styled using CSS.

6. **Consider Logic and Error Handling:** The code includes checks for valid nodes, offsets, and document associations. It also throws exceptions for invalid operations.

7. **Infer User Interaction:**  User actions like selecting text with the mouse or keyboard, or JavaScript code manipulating the DOM and selection, can ultimately trigger the execution of the code within `range.cc`.

8. **Structure the Summary:** Organize the identified functionalities into logical groups for clarity.

9. **Refine and Clarify:**  Review the summary for accuracy, completeness, and clarity. Ensure the language is accessible and avoids overly technical jargon where possible. Add specific examples to illustrate the connections to web technologies.

By following this thought process, we can create a comprehensive and informative summary of the `blink/renderer/core/dom/range.cc` file's functionality.
## blink/renderer/core/dom/range.cc 功能归纳 (第1部分)

根据提供的代码片段，`blink/renderer/core/dom/range.cc` 文件主要负责实现 **DOM Range** 接口的功能。DOM Range 代表文档中的一段连续区域，可以包含节点和节点的一部分文本。

**核心功能可以归纳为以下几点：**

1. **表示文档中的选区：**  `Range` 对象用于表示文档中的一段连续区域，可以从一个节点的特定偏移量开始，到另一个节点的特定偏移量结束。这使得它可以选择文档中的一部分文本、一个或多个完整的节点，或者两者的组合。

2. **管理选区的边界：**  文件定义了如何创建、设置和修改 `Range` 对象的起始和结束边界点 (`start_` 和 `end_`)。这些边界点由一个容器节点和一个偏移量组成。

3. **提供选区信息的查询方法：**  提供了诸如 `commonAncestorContainer()` (获取起始和结束节点的最近公共祖先容器)、`isPointInRange()` (判断一个指定点是否在 Range 内)、`comparePoint()` (比较指定点与 Range 的位置关系)、`compareBoundaryPoints()` (比较两个 Range 的边界点) 等方法，用于获取 Range 的各种属性和与其他位置或 Range 的关系。

4. **支持对选区内容的操作：**  提供了诸如 `deleteContents()` (删除 Range 包含的内容)、`extractContents()` (提取 Range 包含的内容并返回一个 DocumentFragment)、`cloneContents()` (克隆 Range 包含的内容并返回一个 DocumentFragment)、`insertNode()` (在 Range 的起始位置插入一个节点) 等方法，允许开发者对 Range 代表的选区进行修改。

5. **维护与文档和选择的关联：**  `Range` 对象与特定的 `Document` 对象关联，并且在某些操作中会影响浏览器的文本选择 (selection)。代码中可以看到 `UpdateSelectionIfAddedToSelection()` 和 `RemoveFromSelectionIfInDifferentRoot()` 等与 selection 相关的操作。

6. **处理 DOM 变动的影响：**  通过 `RangeUpdateScope` 类，管理在修改 Range 时可能引起的 DOM 变动，并确保相关的状态更新，例如更新 selection 或触发视觉更新。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  该 C++ 文件实现了 Web 浏览器中 JavaScript `Range` API 的底层逻辑。JavaScript 代码可以通过 `document.createRange()` 创建 Range 对象，并调用其方法来操作文档的选区。
    * **举例:**  JavaScript 代码可以使用 `range.setStart(node, offset)` 和 `range.setEnd(node, offset)` 来设置选区的起始和结束位置。使用 `range.deleteContents()` 可以删除 JavaScript 中选定的内容。
* **HTML:** `Range` 对象操作的是 HTML 文档的内容和结构。它可以选择 HTML 元素、文本节点等。
    * **举例:** 一个 Range 可以跨越多个 HTML 标签，例如从一个 `<p>` 元素的中间开始，到另一个 `<div>` 元素的末尾结束。
* **CSS:**  虽然 `Range` 本身不直接操作 CSS，但通过修改 DOM 结构或文本内容，它可以间接地影响 CSS 的应用和渲染效果。浏览器在渲染选区时，也可能会应用特定的 CSS 样式 (例如选中文本的背景色)。

**逻辑推理 (假设输入与输出):**

假设有以下简单的 HTML 结构：

```html
<p id="para">这是一段<b>加粗</b>的文字。</p>
```

**假设输入：**

* `start_container`:  `Text` 节点，内容为 "这是一段"
* `start_offset`: 2 (指向 "是" 字后面)
* `end_container`: `Text` 节点，内容为 "的文字。"
* `end_offset`: 1 (指向 "的" 字后面)

**逻辑推理 (基于 `setStart` 和 `setEnd` 方法的逻辑):**

1. 创建一个 `Range` 对象。
2. 调用 `setStart(start_container, start_offset)`：会将 `start_` 设置为指向 "这是一段" 文本节点的偏移量 2 处。
3. 调用 `setEnd(end_container, end_offset)`：会将 `end_` 设置为指向 "的文字。" 文本节点的偏移量 1 处。
4. `CollapseIfNeeded()` 方法会检查起始位置是否在结束位置之后。在本例中，"是段" 的位置在 "的" 之前，因此不会折叠。

**预期输出 (Range 表示的选区):**

选区会包含 "段<b>加粗</b>的"。

**用户或编程常见的使用错误:**

* **提供的节点为空 (null):**  代码中可以看到对 `ref_node` 是否为空的检查，如果为空会抛出 `TypeError`。这是用户在 JavaScript 中调用 `range.setStart(null, 0)` 或类似方法时可能发生的错误。
* **偏移量超出范围:**  `CheckNodeWOffset` 函数会检查偏移量是否超出容器节点的范围。例如，对一个文本节点调用 `range.setStart(textNode, textNode.length + 1)` 会导致错误。
* **跨文档操作:**  `comparePoint` 和 `compareBoundaryPoints` 等方法会检查节点是否属于同一个文档。尝试比较或操作属于不同文档的 Range 或节点会抛出 `WrongDocumentError`。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户进行文本选择:** 用户使用鼠标拖拽或键盘快捷键 (例如 Shift + 箭头键) 在浏览器中选择了一段文本。
2. **浏览器创建 Range 对象:**  浏览器内部会创建一个或多个 `Range` 对象来表示用户的选择。这可能涉及到调用 `document.createRange()` 或 `selection.getRangeAt()` 等 JavaScript API。
3. **JavaScript 操作 Range 对象:**  开发者可能通过 JavaScript 获取到这个 Range 对象，并调用其方法进行操作，例如 `deleteContents()`, `extractContents()`, `cloneContents()`, `insertNode()` 等。
4. **Blink 引擎调用 C++ 代码:**  JavaScript 对 Range 对象的方法调用最终会映射到 Blink 引擎中 `blink/renderer/core/dom/range.cc` 文件中对应的方法实现。

**总结:**

`blink/renderer/core/dom/range.cc` 的第 1 部分主要定义了 `Range` 类的基本结构和用于创建、设置、查询选区边界的方法。它为后续对选区内容进行操作 (例如删除、提取、克隆) 提供了基础，并且与 JavaScript 的 `Range` API 和浏览器的文本选择功能紧密相关。它也包含了对常见用户错误的预防和处理机制。

Prompt: 
```
这是目录为blink/renderer/core/dom/range.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * (C) 1999 Lars Knoll (knoll@kde.org)
 * (C) 2000 Gunnstein Lye (gunnstein@netcom.no)
 * (C) 2000 Frederik Holljen (frederik.holljen@hig.no)
 * (C) 2001 Peter Kelly (pmk@post.com)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2011 Motorola Mobility. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/dom/range.h"

#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/character_data.h"
#include "third_party/blink/renderer/core/dom/container_node.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/node_with_index.h"
#include "third_party/blink/renderer/core/dom/processing_instruction.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/editing/set_selection_options.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/geometry/dom_rect_list.h"
#include "third_party/blink/renderer/core/highlight/highlight_registry.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/page/scrolling/sync_scroll_attempt_heuristic.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_types_util.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ui/gfx/geometry/quad_f.h"

namespace blink {

class RangeUpdateScope {
  STACK_ALLOCATED();

 public:
  explicit RangeUpdateScope(Range* range) {
    DCHECK(range);
    if (++scope_count_ == 1) {
      range_ = range;
      old_document_ = &range->OwnerDocument();
#if DCHECK_IS_ON()
      current_range_ = range;
    } else {
      DCHECK_EQ(current_range_, range);
#endif
    }
  }
  RangeUpdateScope(const RangeUpdateScope&) = delete;
  RangeUpdateScope& operator=(const RangeUpdateScope&) = delete;

  ~RangeUpdateScope() {
    DCHECK_GE(scope_count_, 1);
    if (--scope_count_ > 0)
      return;
    Settings* settings = old_document_->GetFrame()
                             ? old_document_->GetFrame()->GetSettings()
                             : nullptr;
    if (!settings ||
        !settings->GetDoNotUpdateSelectionOnMutatingSelectionRange()) {
      range_->RemoveFromSelectionIfInDifferentRoot(*old_document_);
      range_->UpdateSelectionIfAddedToSelection();
    }

    range_->ScheduleVisualUpdateIfInRegisteredHighlight(
        range_->OwnerDocument());
    if (*old_document_ != range_->OwnerDocument()) {
      range_->ScheduleVisualUpdateIfInRegisteredHighlight(*old_document_);
    }
#if DCHECK_IS_ON()
    current_range_ = nullptr;
#endif
  }

 private:
  static int scope_count_;
#if DCHECK_IS_ON()
  // This raw pointer is safe because
  //  - s_currentRange has a valid pointer only if RangeUpdateScope instance is
  //  live.
  //  - RangeUpdateScope is used only in Range member functions.
  static Range* current_range_;
#endif
  Range* range_ = nullptr;
  Document* old_document_ = nullptr;

};

int RangeUpdateScope::scope_count_ = 0;
#if DCHECK_IS_ON()
Range* RangeUpdateScope::current_range_;
#endif

Range::Range(Document& owner_document)
    : owner_document_(&owner_document),
      start_(*owner_document_),
      end_(*owner_document_) {
  owner_document_->AttachRange(this);
}

Range* Range::Create(Document& owner_document) {
  return MakeGarbageCollected<Range>(owner_document);
}

Range::Range(Document& owner_document,
             Node* start_container,
             unsigned start_offset,
             Node* end_container,
             unsigned end_offset)
    : owner_document_(&owner_document),
      start_(*owner_document_),
      end_(*owner_document_) {
  owner_document_->AttachRange(this);

  // Simply setting the containers and offsets directly would not do any of the
  // checking that setStart and setEnd do, so we call those functions.
  setStart(start_container, start_offset);
  setEnd(end_container, end_offset);
}

Range::Range(Document& owner_document,
             const Position& start,
             const Position& end)
    : Range(owner_document,
            start.ComputeContainerNode(),
            start.ComputeOffsetInContainerNode(),
            end.ComputeContainerNode(),
            end.ComputeOffsetInContainerNode()) {}

void Range::Dispose() {
  // A prompt detach from the owning Document helps avoid GC overhead.
  owner_document_->DetachRange(this);
}

bool Range::IsConnected() const {
  DCHECK_EQ(start_.IsConnected(), end_.IsConnected());
  return start_.IsConnected();
}

void Range::SetDocument(Document& document) {
  DCHECK_NE(owner_document_, document);
  DCHECK(owner_document_);
  owner_document_->DetachRange(this);
  owner_document_ = &document;
  start_.SetToStartOfNode(document);
  end_.SetToStartOfNode(document);
  owner_document_->AttachRange(this);
}

Node* Range::commonAncestorContainer() const {
  return commonAncestorContainer(&start_.Container(), &end_.Container());
}

Node* Range::commonAncestorContainer(const Node* container_a,
                                     const Node* container_b) {
  if (!container_a || !container_b)
    return nullptr;
  return container_a->CommonAncestor(*container_b, NodeTraversal::Parent);
}

void Range::setStart(Node* ref_node,
                     unsigned offset,
                     ExceptionState& exception_state) {
  if (!ref_node) {
    // FIXME: Generated bindings code never calls with null, and neither should
    // other callers!
    exception_state.ThrowTypeError("The node provided is null.");
    return;
  }

  RangeUpdateScope scope(this);
  bool did_move_document = false;
  if (ref_node->GetDocument() != owner_document_) {
    SetDocument(ref_node->GetDocument());
    did_move_document = true;
  }

  Node* child_node = CheckNodeWOffset(ref_node, offset, exception_state);
  if (exception_state.HadException())
    return;

  start_.Set(*ref_node, offset, child_node);

  CollapseIfNeeded(did_move_document, /*collapse_to_start=*/true);
}

void Range::setEnd(Node* ref_node,
                   unsigned offset,
                   ExceptionState& exception_state) {
  if (!ref_node) {
    // FIXME: Generated bindings code never calls with null, and neither should
    // other callers!
    exception_state.ThrowTypeError("The node provided is null.");
    return;
  }

  RangeUpdateScope scope(this);
  bool did_move_document = false;
  if (ref_node->GetDocument() != owner_document_) {
    SetDocument(ref_node->GetDocument());
    did_move_document = true;
  }

  Node* child_node = CheckNodeWOffset(ref_node, offset, exception_state);
  if (exception_state.HadException())
    return;

  end_.Set(*ref_node, offset, child_node);

  CollapseIfNeeded(did_move_document, /*collapse_to_start=*/false);
}

void Range::setStart(const Position& start, ExceptionState& exception_state) {
  Position parent_anchored = start.ParentAnchoredEquivalent();
  setStart(parent_anchored.ComputeContainerNode(),
           parent_anchored.OffsetInContainerNode(), exception_state);
}

void Range::setEnd(const Position& end, ExceptionState& exception_state) {
  Position parent_anchored = end.ParentAnchoredEquivalent();
  setEnd(parent_anchored.ComputeContainerNode(),
         parent_anchored.OffsetInContainerNode(), exception_state);
}

void Range::collapse(bool to_start) {
  RangeUpdateScope scope(this);
  if (to_start) {
    end_ = start_;
  } else {
    start_ = end_;
  }
}

void Range::CollapseIfNeeded(bool did_move_document, bool collapse_to_start) {
  RangeBoundaryPoint original_start(start_);
  RangeBoundaryPoint original_end(end_);

  bool different_tree_scopes =
      HasDifferentRootContainer(&start_.Container(), &end_.Container());
  // If document moved, we are in different tree scopes, or start boundary point
  // is after end boundary point, we should collapse the range.
  if (did_move_document || different_tree_scopes ||
      compareBoundaryPoints(start_, end_, ASSERT_NO_EXCEPTION) > 0) {
    collapse(collapse_to_start);
  }
}

bool Range::HasSameRoot(const Node& node) const {
  if (node.GetDocument() != owner_document_)
    return false;
  // commonAncestorContainer() is O(depth). We should avoid to call it in common
  // cases.
  if (node.IsInTreeScope() && start_.Container().IsInTreeScope() &&
      &node.GetTreeScope() == &start_.Container().GetTreeScope())
    return true;
  return node.CommonAncestor(start_.Container(), NodeTraversal::Parent);
}

bool Range::isPointInRange(Node* ref_node,
                           unsigned offset,
                           ExceptionState& exception_state) const {
  if (!ref_node) {
    // FIXME: Generated bindings code never calls with null, and neither should
    // other callers!
    exception_state.ThrowTypeError("The node provided is null.");
    return false;
  }
  if (!HasSameRoot(*ref_node))
    return false;

  CheckNodeWOffset(ref_node, offset, exception_state);
  if (exception_state.HadException())
    return false;

  return compareBoundaryPoints(ref_node, offset, &start_.Container(),
                               start_.Offset(), exception_state) >= 0 &&
         !exception_state.HadException() &&
         compareBoundaryPoints(ref_node, offset, &end_.Container(),
                               end_.Offset(), exception_state) <= 0 &&
         !exception_state.HadException();
}

int16_t Range::comparePoint(Node* ref_node,
                            unsigned offset,
                            ExceptionState& exception_state) const {
  // http://developer.mozilla.org/en/docs/DOM:range.comparePoint
  // This method returns -1, 0 or 1 depending on if the point described by the
  // refNode node and an offset within the node is before, same as, or after the
  // range respectively.

  if (!HasSameRoot(*ref_node)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kWrongDocumentError,
        "The node provided and the Range are not in the same tree.");
    return 0;
  }

  CheckNodeWOffset(ref_node, offset, exception_state);
  if (exception_state.HadException())
    return 0;

  // compare to start, and point comes before
  if (compareBoundaryPoints(ref_node, offset, &start_.Container(),
                            start_.Offset(), exception_state) < 0)
    return -1;

  if (exception_state.HadException())
    return 0;

  // compare to end, and point comes after
  bool start_after_end =
      compareBoundaryPoints(ref_node, offset, &end_.Container(), end_.Offset(),
                            exception_state) > 0;
  if (start_after_end && !exception_state.HadException()) {
    return 1;
  }

  // point is in the middle of this range, or on the boundary points
  return 0;
}

int16_t Range::compareBoundaryPoints(unsigned how,
                                     const Range* source_range,
                                     ExceptionState& exception_state) const {
  if (!(how == kStartToStart || how == kStartToEnd || how == kEndToEnd ||
        how == kEndToStart)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The comparison method provided must be "
        "one of 'START_TO_START', 'START_TO_END', "
        "'END_TO_END', or 'END_TO_START'.");
    return 0;
  }

  Node* this_cont = commonAncestorContainer();
  Node* source_cont = source_range->commonAncestorContainer();
  if (this_cont->GetDocument() != source_cont->GetDocument()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kWrongDocumentError,
        "The source range is in a different document than this range.");
    return 0;
  }

  Node* this_top = this_cont;
  Node* source_top = source_cont;
  while (this_top->parentNode())
    this_top = this_top->parentNode();
  while (source_top->parentNode())
    source_top = source_top->parentNode();
  if (this_top != source_top) {  // in different DocumentFragments
    exception_state.ThrowDOMException(
        DOMExceptionCode::kWrongDocumentError,
        "The source range is in a different document than this range.");
    return 0;
  }

  switch (how) {
    case kStartToStart:
      return compareBoundaryPoints(start_, source_range->start_,
                                   exception_state);
    case kStartToEnd:
      return compareBoundaryPoints(end_, source_range->start_, exception_state);
    case kEndToEnd:
      return compareBoundaryPoints(end_, source_range->end_, exception_state);
    case kEndToStart:
      return compareBoundaryPoints(start_, source_range->end_, exception_state);
  }

  NOTREACHED();
}

int16_t Range::compareBoundaryPoints(Node* container_a,
                                     unsigned offset_a,
                                     Node* container_b,
                                     unsigned offset_b,
                                     ExceptionState& exception_state) {
  bool disconnected = false;
  int16_t result = ComparePositionsInDOMTree(container_a, offset_a, container_b,
                                             offset_b, &disconnected);
  if (disconnected) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kWrongDocumentError,
        "The two ranges are in separate tree scopes.");
    return 0;
  }
  return result;
}

int16_t Range::compareBoundaryPoints(const RangeBoundaryPoint& boundary_a,
                                     const RangeBoundaryPoint& boundary_b,
                                     ExceptionState& exception_state) {
  return compareBoundaryPoints(&boundary_a.Container(), boundary_a.Offset(),
                               &boundary_b.Container(), boundary_b.Offset(),
                               exception_state);
}

bool Range::BoundaryPointsValid() const {
  DummyExceptionStateForTesting exception_state;
  bool start_after_end =
      compareBoundaryPoints(start_, end_, exception_state) > 0;
  return !start_after_end && !exception_state.HadException();
}

void Range::deleteContents(ExceptionState& exception_state) {
  DCHECK(BoundaryPointsValid());

  {
    EventQueueScope event_queue_scope;
    ProcessContents(kDeleteContents, exception_state);
  }
}

bool Range::intersectsNode(Node* ref_node, ExceptionState& exception_state) {
  // http://developer.mozilla.org/en/docs/DOM:range.intersectsNode
  // Returns a bool if the node intersects the range.
  if (!ref_node) {
    // FIXME: Generated bindings code never calls with null, and neither should
    // other callers!
    exception_state.ThrowTypeError("The node provided is null.");
    return false;
  }
  if (!HasSameRoot(*ref_node))
    return false;

  ContainerNode* parent_node = ref_node->parentNode();
  if (!parent_node)
    return true;

  int node_index = ref_node->NodeIndex();
  return Position(parent_node, node_index) < end_.ToPosition() &&
         Position(parent_node, node_index + 1) > start_.ToPosition();
}

static inline Node* HighestAncestorUnderCommonRoot(Node* node,
                                                   Node* common_root) {
  if (node == common_root)
    return nullptr;

  DCHECK(common_root->contains(node));

  while (node->parentNode() != common_root)
    node = node->parentNode();

  return node;
}

static inline Node* ChildOfCommonRootBeforeOffset(Node* container,
                                                  unsigned offset,
                                                  Node* common_root) {
  DCHECK(container);
  DCHECK(common_root);

  if (!common_root->contains(container))
    return nullptr;

  if (container == common_root) {
    container = container->firstChild();
    for (unsigned i = 0; container && i < offset; i++)
      container = container->nextSibling();
  } else {
    while (container->parentNode() != common_root)
      container = container->parentNode();
  }

  return container;
}

DocumentFragment* Range::ProcessContents(ActionType action,
                                         ExceptionState& exception_state) {
  DocumentFragment* fragment = nullptr;
  if (action == kExtractContents || action == kCloneContents)
    fragment = DocumentFragment::Create(*owner_document_.Get());

  if (collapsed())
    return fragment;

  Node* common_root = commonAncestorContainer();
  DCHECK(common_root);

  if (start_.Container() == end_.Container()) {
    ProcessContentsBetweenOffsets(action, fragment, &start_.Container(),
                                  start_.Offset(), end_.Offset(),
                                  exception_state);
    return fragment;
  }

  // Since mutation observers can modify the range during the process, the
  // boundary points need to be saved.
  const RangeBoundaryPoint original_start(start_);
  const RangeBoundaryPoint original_end(end_);

  // what is the highest node that partially selects the start / end of the
  // range?
  Node* partial_start =
      HighestAncestorUnderCommonRoot(&original_start.Container(), common_root);
  Node* partial_end =
      HighestAncestorUnderCommonRoot(&original_end.Container(), common_root);

  // Start and end containers are different.
  // There are three possibilities here:
  // 1. Start container == commonRoot (End container must be a descendant)
  // 2. End container == commonRoot (Start container must be a descendant)
  // 3. Neither is commonRoot, they are both descendants
  //
  // In case 3, we grab everything after the start (up until a direct child
  // of commonRoot) into leftContents, and everything before the end (up until
  // a direct child of commonRoot) into rightContents. Then we process all
  // commonRoot children between leftContents and rightContents
  //
  // In case 1 or 2, we skip either processing of leftContents or rightContents,
  // in which case the last lot of nodes either goes from the first or last
  // child of commonRoot.
  //
  // These are deleted, cloned, or extracted (i.e. both) depending on action.

  // Note that we are verifying that our common root hierarchy is still intact
  // after any DOM mutation event, at various stages below. See webkit bug
  // 60350.

  Node* left_contents = nullptr;
  if (original_start.Container() != common_root &&
      common_root->contains(&original_start.Container())) {
    left_contents = ProcessContentsBetweenOffsets(
        action, nullptr, &original_start.Container(), original_start.Offset(),
        AbstractRange::LengthOfContents(&original_start.Container()),
        exception_state);
    left_contents = ProcessAncestorsAndTheirSiblings(
        action, &original_start.Container(), kProcessContentsForward,
        left_contents, common_root, exception_state);
  }

  Node* right_contents = nullptr;
  if (end_.Container() != common_root &&
      common_root->contains(&original_end.Container())) {
    right_contents = ProcessContentsBetweenOffsets(
        action, nullptr, &original_end.Container(), 0, original_end.Offset(),
        exception_state);
    right_contents = ProcessAncestorsAndTheirSiblings(
        action, &original_end.Container(), kProcessContentsBackward,
        right_contents, common_root, exception_state);
  }

  if (exception_state.HadException()) {
    return nullptr;
  }

  // delete all children of commonRoot between the start and end container
  Node* process_start = ChildOfCommonRootBeforeOffset(
      &original_start.Container(), original_start.Offset(), common_root);
  // process_start contains nodes before start_.
  if (process_start && original_start.Container() != common_root)
    process_start = process_start->nextSibling();
  Node* process_end = ChildOfCommonRootBeforeOffset(
      &original_end.Container(), original_end.Offset(), common_root);

  // Collapse the range, making sure that the result is not within a node that
  // was partially selected.
  if (action == kExtractContents || action == kDeleteContents) {
    if (partial_start && common_root->contains(partial_start)) {
      setStart(partial_start->parentNode(), partial_start->NodeIndex() + 1,
               exception_state);
    } else if (partial_end && common_root->contains(partial_end)) {
      setStart(partial_end->parentNode(), partial_end->NodeIndex(),
               exception_state);
    }
    if (exception_state.HadException())
      return nullptr;
    end_ = start_;
  }

  // Now add leftContents, stuff in between, and rightContents to the fragment
  // (or just delete the stuff in between)

  if ((action == kExtractContents || action == kCloneContents) && left_contents)
    fragment->AppendChild(left_contents, exception_state);

  if (process_start) {
    NodeVector nodes;
    for (Node* n = process_start; n && n != process_end; n = n->nextSibling())
      nodes.push_back(n);
    ProcessNodes(action, nodes, common_root, fragment, exception_state);
  }

  if ((action == kExtractContents || action == kCloneContents) &&
      right_contents)
    fragment->AppendChild(right_contents, exception_state);

  return fragment;
}

static inline void DeleteCharacterData(CharacterData* data,
                                       unsigned start_offset,
                                       unsigned end_offset,
                                       ExceptionState& exception_state) {
  if (data->length() - end_offset)
    data->deleteData(end_offset, data->length() - end_offset, exception_state);
  if (start_offset)
    data->deleteData(0, start_offset, exception_state);
}

Node* Range::ProcessContentsBetweenOffsets(ActionType action,
                                           DocumentFragment* fragment,
                                           Node* container,
                                           unsigned start_offset,
                                           unsigned end_offset,
                                           ExceptionState& exception_state) {
  DCHECK(container);
  DCHECK_LE(start_offset, end_offset);

  // This switch statement must be consistent with that of
  // lengthOfContents.
  Node* result = nullptr;
  switch (container->getNodeType()) {
    case Node::kTextNode:
    case Node::kCdataSectionNode:
    case Node::kCommentNode:
    case Node::kProcessingInstructionNode:
      end_offset = std::min(end_offset, To<CharacterData>(container)->length());
      if (action == kExtractContents || action == kCloneContents) {
        CharacterData* c =
            static_cast<CharacterData*>(container->cloneNode(true));
        DeleteCharacterData(c, start_offset, end_offset, exception_state);
        if (fragment) {
          result = fragment;
          result->appendChild(c, exception_state);
        } else {
          result = c;
        }
      }
      if (action == kExtractContents || action == kDeleteContents)
        To<CharacterData>(container)->deleteData(
            start_offset, end_offset - start_offset, exception_state);
      break;
    case Node::kElementNode:
    case Node::kAttributeNode:
    case Node::kDocumentNode:
    case Node::kDocumentTypeNode:
    case Node::kDocumentFragmentNode:
      // FIXME: Should we assert that some nodes never appear here?
      if (action == kExtractContents || action == kCloneContents) {
        if (fragment)
          result = fragment;
        else
          result = container->cloneNode(false);
      }

      Node* n = container->firstChild();
      NodeVector nodes;
      for (unsigned i = start_offset; n && i; i--)
        n = n->nextSibling();
      for (unsigned i = start_offset; n && i < end_offset;
           i++, n = n->nextSibling())
        nodes.push_back(n);

      ProcessNodes(action, nodes, container, result, exception_state);
      break;
  }

  return result;
}

void Range::ProcessNodes(ActionType action,
                         NodeVector& nodes,
                         Node* old_container,
                         Node* new_container,
                         ExceptionState& exception_state) {
  for (auto& node : nodes) {
    switch (action) {
      case kDeleteContents:
        old_container->removeChild(node.Get(), exception_state);
        break;
      case kExtractContents:
        new_container->appendChild(
            node.Release(), exception_state);  // Will remove n from its parent.
        break;
      case kCloneContents:
        new_container->appendChild(node->cloneNode(true), exception_state);
        break;
    }
  }
}

Node* Range::ProcessAncestorsAndTheirSiblings(
    ActionType action,
    Node* container,
    ContentsProcessDirection direction,
    Node* cloned_container,
    Node* common_root,
    ExceptionState& exception_state) {
  NodeVector ancestors;
  for (Node& runner : NodeTraversal::AncestorsOf(*container)) {
    if (runner == common_root)
      break;
    ancestors.push_back(runner);
  }
  // Both https://dom.spec.whatwg.org/#concept-range-clone and
  // https://dom.spec.whatwg.org/#concept-range-extract specify (in various
  // ways) that nodes are to be processed in tree order. But the algorithm below
  // processes in depth first order instead. So clone the nodes first here,
  // in reverse order, so upgrades happen in the proper order.
  HeapVector<Member<Node>> cloned_ancestors(ancestors.size(), nullptr);
  auto clone_ptr = cloned_ancestors.rbegin();
  for (auto it = ancestors.rbegin(); it != ancestors.rend(); ++it) {
    *(clone_ptr++) = (*it)->cloneNode(false);
  }

  Node* first_child_in_ancestor_to_process =
      direction == kProcessContentsForward ? container->nextSibling()
                                           : container->previousSibling();
  for (wtf_size_t i = 0; i < ancestors.size(); ++i) {
    const auto& ancestor = ancestors[i];
    if (action == kExtractContents || action == kCloneContents) {
      // Might have been removed already during mutation event.
      if (auto cloned_ancestor = cloned_ancestors[i]) {
        cloned_ancestor->appendChild(cloned_container, exception_state);
        cloned_container = cloned_ancestor;
      }
    }

    // Copy siblings of an ancestor of start/end containers
    // FIXME: This assertion may fail if DOM is modified during mutation event
    // FIXME: Share code with Range::processNodes
    DCHECK(!first_child_in_ancestor_to_process ||
           first_child_in_ancestor_to_process->parentNode() == ancestor);

    NodeVector nodes;
    for (Node* child = first_child_in_ancestor_to_process; child;
         child = (direction == kProcessContentsForward)
                     ? child->nextSibling()
                     : child->previousSibling())
      nodes.push_back(child);

    for (const auto& node : nodes) {
      Node* child = node.Get();
      switch (action) {
        case kDeleteContents:
          // Prior call of ancestor->removeChild() may cause a tree change due
          // to DOMSubtreeModified event.  Therefore, we need to make sure
          // |ancestor| is still |child|'s parent.
          if (ancestor == child->parentNode())
            ancestor->removeChild(child, exception_state);
          break;
        case kExtractContents:  // will remove child from ancestor
          if (direction == kProcessContentsForward)
            cloned_container->appendChild(child, exception_state);
          else
            cloned_container->insertBefore(
                child, cloned_container->firstChild(), exception_state);
          break;
        case kCloneContents:
          if (direction == kProcessContentsForward)
            cloned_container->appendChild(child->cloneNode(true),
                                          exception_state);
          else
            cloned_container->insertBefore(child->cloneNode(true),
                                           cloned_container->firstChild(),
                                           exception_state);
          break;
      }
    }
    first_child_in_ancestor_to_process = direction == kProcessContentsForward
                                             ? ancestor->nextSibling()
                                             : ancestor->previousSibling();
  }

  return cloned_container;
}

DocumentFragment* Range::extractContents(ExceptionState& exception_state) {
  CheckExtractPrecondition(exception_state);
  if (exception_state.HadException())
    return nullptr;

  EventQueueScope scope;
  DocumentFragment* fragment =
      ProcessContents(kExtractContents, exception_state);
  // |extractContents| has extended attributes [NewObject, DoNotTestNewObject],
  // so it's better to have a test that exercises the following condition:
  //
  //   !fragment || DOMDataStore::GetWrapper(fragment, isolate).IsEmpty()
  //
  // however, there is no access to |isolate| so far.  So, we simply omit the
  // test so far.
  return fragment;
}

DocumentFragment* Range::cloneContents(ExceptionState& exception_state) {
  return ProcessContents(kCloneContents, exception_state);
}

// https://dom.spec.whatwg.org/#concept-range-insert
void Range::insertNode(Node* new_node, ExceptionState& exception_state) {
  if (!new_node) {
    // FIXME: Generated bindings code never calls with null, and neither should
    // other callers!
    exception_state.ThrowTypeError("The node provided is null.");
    return;
  }

  // 1. If range’s start node is a ProcessingInstruction or Comment node, is a
  // Text node whose parent is null, or is node, then throw a
  // HierarchyRequestError.
  Node& start_node = start_.Container();
  if (start_node.getNodeType() == Node::kProcessingInstructionNode ||
      start_node.getNodeType() == Node::kCommentNode) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kHierarchyRequestError,
        "Nodes of type '" + new_node->nodeName() +
            "' may not be inserted inside nodes of type '" +
            start_node.nodeName() + "'.");
    return;
  }
  const bool start_is_text = start_node.IsTextNode();
  if (start_is_text && !start_node.parentNode()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kHierarchyRequestError,
                                      "This operation would split a text node, "
                                      "but there's no parent into which to "
                                      "insert.");
    return;
  }
  if (start_node == new_node) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kHierarchyRequestError,
        "Unable to insert a node into a Range starting from the 
"""


```