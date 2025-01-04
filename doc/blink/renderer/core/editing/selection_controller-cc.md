Response:
The user wants a summary of the functionality of the `selection_controller.cc` file in the Chromium Blink engine. They are interested in its relationship with Javascript, HTML, and CSS, and want examples of how it interacts with these technologies. They also want to understand potential user errors and how user actions lead to the code in this file.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Functionality:**  The filename "selection_controller.cc" strongly suggests that this file is responsible for managing text selection within the Blink rendering engine. The included headers like `frame_selection.h`, `editing/ephemeral_range.h`, and `editing/visible_position.h` reinforce this idea. The copyright notices indicate it's a mature piece of code with contributions from multiple entities, likely dealing with complex aspects of web page rendering and interaction.

2. **Deconstruct the Code:** Scan through the code, paying attention to the class name (`SelectionController`), its methods, and the included headers. Look for keywords and concepts related to selection: `SetSelection`, `ExtendSelection`, `Collapse`, `Anchor`, `Focus`, `Caret`, `MouseEvents`, `TouchEvents`, `selectstart`, `user-select`.

3. **Categorize Functionality:** Group the identified functionalities into logical categories. Based on the code, key areas seem to be:
    * **Basic Selection Manipulation:** Creating, modifying, clearing selections.
    * **Mouse Interaction:** Handling mouse clicks, drags, and their impact on selection.
    * **Touch Interaction:** Handling taps and gestures for selection on touch devices.
    * **Keyboard Interaction (Implied):** Although not explicitly detailed in *this part* of the file, the existence of a selection controller inherently suggests it will interact with keyboard events for selection (Shift+Arrow keys, etc.). It's important to mention this as a likely function even if it's not the focus of this specific code snippet.
    * **Integration with Browser Features:** Interacting with spell checking, text suggestions, and context menus.
    * **CSS `user-select` Property:** Handling the behavior defined by the `user-select` CSS property.
    * **Event Handling:** Dispatching and responding to `selectstart` events.

4. **Connect to Web Technologies (Javascript, HTML, CSS):** For each functionality category, think about how it relates to the core web technologies:
    * **Javascript:** Javascript can read and manipulate the current selection using the `Selection` API. This code likely *implements* the underlying behavior for those API calls. Event handlers in Javascript can trigger changes in selection.
    * **HTML:** The structure of the HTML document provides the context for selection. The selection controller operates on the DOM tree. Certain HTML elements (like `<input>` and `<textarea>`) have inherent selection behaviors. The `contenteditable` attribute makes elements selectable.
    * **CSS:** The `user-select` property directly influences how selections are made. This file clearly handles this property. Other CSS properties like `cursor` can provide visual feedback related to selection.

5. **Provide Examples:**  Concrete examples are crucial for understanding. Think of common user interactions and how they would trigger the functionality in the code:
    * Mouse click and drag to select text.
    * Double-clicking to select a word.
    * Shift-clicking to extend a selection.
    * Tapping on text on a touch screen.
    * The impact of `user-select: none`.

6. **Consider Logical Inference (Assumptions and Outputs):** While the provided code snippet doesn't show explicit logical branching with clear inputs and outputs, it's possible to infer some basic logic:
    * **Input:** Mouse click coordinates.
    * **Output:** A specific selection range in the DOM.
    * **Input:**  A selection and a new mouse position during a drag.
    * **Output:** An updated selection range.

7. **Identify Potential User/Programming Errors:** Think about common mistakes developers or users might make that would involve this part of the engine:
    * Incorrectly using `user-select: none` and hindering desired selection behavior.
    * Javascript code that interferes with the browser's default selection behavior.
    * Issues with event handling that prevent selection from working correctly.

8. **Describe the User Journey (Debugging Clues):**  Outline the steps a user might take that would eventually lead to the execution of code within `selection_controller.cc`. This helps in understanding the context and debugging potential issues. Start with basic user interactions like clicking, dragging, tapping, and then consider the underlying browser mechanisms.

9. **Summarize the Functionality (for Part 1):** Based on the analysis, provide a concise summary of the file's purpose, focusing on the aspects covered in the provided snippet. Highlight its central role in handling user-initiated text selection within the Blink rendering engine.

10. **Structure the Response:** Organize the information clearly using headings and bullet points for readability. Ensure the language is understandable to someone with a general understanding of web development concepts.
这是 `blink/renderer/core/editing/selection_controller.cc` 文件的第一部分，主要负责处理用户在网页上的文本选择操作。 它的核心功能是管理和维护当前页面的文本选择状态，并响应用户的各种交互（例如鼠标点击、拖动、触摸等）来更新选择。

以下是根据提供的代码片段归纳的功能点，并解释了它与 JavaScript, HTML, CSS 的关系，以及可能的用户错误和调试线索：

**核心功能归纳:**

1. **管理选择状态:**  `SelectionController` 维护着当前文档的文本选择状态，包括选择的起始位置（anchor）和结束位置（focus），以及选择的方向。它使用 `SelectionInFlatTree` 对象来表示选择范围。
2. **响应鼠标事件:**
   - **单次点击 (`HandleSingleClick`):**  处理鼠标单次点击，可能用于创建新的选择，移动光标，或者在 Shift 键按下时扩展现有选择。
   - **鼠标拖动 (`UpdateSelectionForMouseDrag`):** 处理鼠标拖动事件，动态更新选择范围。
3. **响应触摸事件:**  处理触摸事件，例如在可编辑区域的 tap 操作来显示/隐藏光标手柄或触发上下文菜单 (`HandleTapOnCaret`, `HandleTapInsideSelection`).
4. **处理 `selectstart` 事件:** 在开始选择时触发 `selectstart` 事件，允许 JavaScript 阻止默认的选择行为。
5. **处理 `user-select` CSS 属性:** 尊重 CSS 的 `user-select` 属性，决定哪些元素可以被选中。
6. **处理不同粒度的选择:** 支持不同粒度的选择，例如字符、单词、段落等。
7. **与拼写检查集成:**  可以根据点击位置找到附近的拼写错误标记 (`SpellCheckMarkerGroupAtPosition`).
8. **处理用户选择全部 (`user-select: all`):** 当元素设置了 `user-select: all` 时，能够扩展选择以包含整个元素。
9. **处理非可选元素:**  能够识别和跳过不能被选择的元素。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**
    * **`selectstart` 事件:**  `SelectionController` 会触发 `selectstart` 事件，JavaScript 可以监听并阻止默认的选择行为，例如：
      ```javascript
      document.addEventListener('selectstart', function(event) {
        event.preventDefault(); // 阻止默认的选择行为
      });
      ```
    * **Selection API:**  JavaScript 可以通过 `window.getSelection()` 获取当前的 Selection 对象，并对其进行操作。 `SelectionController` 负责维护这个 Selection 对象的状态。
    * **用户交互:**  JavaScript 可以监听用户的鼠标和触摸事件，并可能间接地导致 `SelectionController` 的方法被调用，例如通过 `dispatchEvent` 模拟点击事件。

* **HTML:**
    * **文本内容:**  `SelectionController` 的核心功能是选择 HTML 文档中的文本内容。
    * **可编辑属性 (`contenteditable`):**  对于设置了 `contenteditable` 属性的元素，`SelectionController` 会允许用户进行文本选择和编辑。
    * **`user-select` CSS 属性:**  HTML 元素可以通过 CSS 的 `user-select` 属性来控制是否允许用户选择其中的文本。`SelectionController` 中的代码会检查和遵守这个属性的设置。 例如：
      ```html
      <div style="user-select: none;">这段文字不能被选中</div>
      <div style="user-select: text;">这段文字可以被选中</div>
      ```

* **CSS:**
    * **`user-select` 属性:**  如上所述，`SelectionController` 会读取和应用 CSS 的 `user-select` 属性来决定是否允许选择特定元素的文本。
    * **光标样式 (`cursor`):** CSS 的 `cursor` 属性可以影响鼠标在不同元素上的显示效果，这与选择操作有一定的关联。
    * **样式更新:**  当选择发生变化时，可能需要更新某些元素的样式，例如选中文本的高亮显示。`SelectionController` 可能会触发布局和渲染更新，从而影响 CSS 的应用。

**逻辑推理的假设输入与输出:**

**假设输入 (鼠标单次点击):**

* 用户在文档的某个位置进行了鼠标左键单击。
* 提供点击事件的详细信息，例如鼠标坐标、目标节点、按下的按键（Shift 等）。

**输出:**

* 如果点击在一个可以被选择的区域，并且没有按下 Shift 键，则会在点击位置创建一个光标（Caret）。
* 如果点击在一个已经有选择的区域，并且没有按下 Shift 键，则可能会取消当前选择并在点击位置创建一个光标。
* 如果点击时按下了 Shift 键，则会尝试扩展或缩小当前的选择范围，基于点击的位置。
* 可能会触发 `selectstart` 事件。

**假设输入 (鼠标拖动):**

* 用户在按下鼠标左键的情况下移动鼠标。
* 提供拖动过程中鼠标位置的实时信息。

**输出:**

*  选择范围会随着鼠标的移动动态更新，从鼠标按下时的位置延伸到当前鼠标所在的位置。

**用户或编程常见的使用错误:**

1. **错误地使用 `user-select: none`:**  开发者可能会在不希望用户选择文本的区域设置 `user-select: none`，但有时可能会过度使用，导致用户无法选择本应可选择的文本。
2. **JavaScript 代码干扰默认选择行为:**  JavaScript 代码可能会意外地阻止 `selectstart` 事件的默认行为，或者在鼠标事件处理中出现错误，导致选择功能异常。 例如：
   ```javascript
   document.addEventListener('mousedown', function(event) {
     // 错误地阻止了 mousedown 事件的默认行为，可能影响选择
     event.preventDefault();
   });
   ```
3. **在动态内容加载后选择失效:** 如果在 JavaScript 动态加载内容后，没有正确地更新选择相关的状态或事件监听，可能会导致选择功能在新的内容上失效。
4. **在复杂的布局或嵌套元素中选择不准确:** 在复杂的 HTML 结构中，特别是存在浮动、定位等 CSS 属性时，`SelectionController` 在计算选择范围时可能会遇到一些边界情况，导致选择不准确。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户发起选择操作:** 用户通过鼠标点击并拖动，或者双击、三击等操作，试图在网页上选择文本。
2. **浏览器捕获用户输入事件:**  浏览器内核（Blink）会捕获用户的鼠标事件（`mousedown`, `mousemove`, `mouseup`）或触摸事件（`touchstart`, `touchmove`, `touchend`）。
3. **事件分发:**  捕获到的事件会被分发到相应的事件处理逻辑。 对于与选择相关的事件，会传递到 `SelectionController` 进行处理。
4. **`SelectionController` 的方法被调用:**
   - `mousedown` 事件通常会触发 `SelectionController::HandleSingleClick` (如果是一次简单的点击) 或开始一个可能的选择过程。
   - `mousemove` 事件（在 `mousedown` 之后）会触发 `SelectionController::UpdateSelectionForMouseDrag` 来更新选择范围。
   - 触摸事件可能会触发 `HandleTapOnCaret` 或 `HandleTapInsideSelection` 等方法。
5. **内部状态更新和事件触发:**  `SelectionController` 在其方法中会更新内部的选择状态 (`SelectionInFlatTree`)，并可能触发 `selectstart` 等事件。
6. **渲染更新:** 选择的改变会导致浏览器重新渲染页面，以高亮显示选中的文本。

**总结 (针对第 1 部分):**

`blink/renderer/core/editing/selection_controller.cc` 文件的第一部分主要负责处理用户发起的文本选择操作，包括响应鼠标和触摸事件，管理选择状态，以及处理与选择相关的浏览器事件。它与 JavaScript, HTML, CSS 紧密相关，需要遵守 CSS 的 `user-select` 属性，并能通过触发 `selectstart` 事件与 JavaScript 进行交互。 理解这个文件的功能对于调试网页中与文本选择相关的问题至关重要。

Prompt: 
```
这是目录为blink/renderer/core/editing/selection_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc. All rights
 * reserved.
 * Copyright (C) 2006 Alexey Proskuryakov (ap@webkit.org)
 * Copyright (C) 2012 Digia Plc. and/or its subsidiary(-ies)
 * Copyright (C) 2015 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/editing/selection_controller.h"

#include "base/auto_reset.h"
#include "third_party/blink/public/common/input/web_menu_source_type.h"
#include "third_party/blink/public/platform/web_input_event_result.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/node_computed_style.h"
#include "third_party/blink/renderer/core/editing/bidi_adjustment.h"
#include "third_party/blink/renderer/core/editing/editing_behavior.h"
#include "third_party/blink/renderer/core/editing/editing_boundary.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/set_selection_options.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/editing/suggestion/text_suggestion_controller.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_handler.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "ui/gfx/geometry/point_conversions.h"

namespace blink {

SelectionController::SelectionController(LocalFrame& frame)
    : ExecutionContextLifecycleObserver(frame.DomWindow()),
      frame_(&frame),
      mouse_down_may_start_select_(false),
      mouse_down_was_single_click_in_selection_(false),
      mouse_down_allows_multi_click_(false),
      selection_state_(SelectionState::kHaveNotStartedSelection) {}

void SelectionController::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(original_anchor_in_flat_tree_);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

namespace {

DispatchEventResult DispatchSelectStart(Node* node) {
  if (!node || !node->GetLayoutObject())
    return DispatchEventResult::kNotCanceled;

  return node->DispatchEvent(
      *Event::CreateCancelableBubble(event_type_names::kSelectstart));
}

SelectionInFlatTree ExpandSelectionToRespectUserSelectAll(
    Node* target_node,
    const SelectionInFlatTree& selection) {
  if (selection.IsNone())
    return SelectionInFlatTree();
  Node* const root_user_select_all =
      EditingInFlatTreeStrategy::RootUserSelectAllForNode(target_node);
  if (!root_user_select_all)
    return selection;
  return SelectionInFlatTree::Builder(selection)
      .Collapse(MostBackwardCaretPosition(
          PositionInFlatTree::BeforeNode(*root_user_select_all),
          kCanCrossEditingBoundary))
      .Extend(MostForwardCaretPosition(
          PositionInFlatTree::AfterNode(*root_user_select_all),
          kCanCrossEditingBoundary))
      .Build();
}

static int TextDistance(const PositionInFlatTree& start,
                        const PositionInFlatTree& end) {
  return TextIteratorInFlatTree::RangeLength(
      start, end,
      TextIteratorBehavior::AllVisiblePositionsRangeLengthBehavior());
}

bool CanMouseDownStartSelect(Node* node) {
  if (!node || !node->GetLayoutObject())
    return true;

  if (!node->CanStartSelection())
    return false;

  return true;
}

PositionInFlatTreeWithAffinity PositionWithAffinityOfHitTestResult(
    const HitTestResult& hit_test_result) {
  return FromPositionInDOMTree<EditingInFlatTreeStrategy>(
      hit_test_result.GetPosition());
}

DocumentMarkerGroup* SpellCheckMarkerGroupAtPosition(
    DocumentMarkerController& document_marker_controller,
    const PositionInFlatTree& position) {
  return document_marker_controller.FirstMarkerGroupAroundPosition(
      position, DocumentMarker::MarkerTypes::Misspelling());
}

void MarkSelectionEndpointsForRepaint(const SelectionInFlatTree& selection) {
  LayoutObject* anchor_layout_object =
      selection.Anchor().AnchorNode()->GetLayoutObject();
  if (anchor_layout_object) {
    if (auto* layer = anchor_layout_object->PaintingLayer())
      layer->SetNeedsRepaint();
  }

  LayoutObject* focus_layout_object =
      selection.Focus().AnchorNode()->GetLayoutObject();
  if (focus_layout_object) {
    if (auto* layer = focus_layout_object->PaintingLayer()) {
      layer->SetNeedsRepaint();
    }
  }
}

bool IsNonSelectable(const Node* node) {
  LayoutObject* layout_object = node ? node->GetLayoutObject() : nullptr;
  return layout_object && !layout_object->IsSelectable();
}

inline bool ShouldIgnoreNodeForCheckSelectable(const Node* enclosing_block,
                                               const Node* node) {
  return node == enclosing_block || (node && node->IsTextNode());
}

}  // namespace

SelectionInFlatTree AdjustSelectionWithTrailingWhitespace(
    const SelectionInFlatTree& selection) {
  if (selection.IsNone())
    return selection;
  if (!selection.IsRange())
    return selection;
  const PositionInFlatTree& end = selection.ComputeEndPosition();
  const PositionInFlatTree& new_end = SkipWhitespace(end);
  if (end == new_end)
    return selection;
  if (selection.IsAnchorFirst()) {
    return SelectionInFlatTree::Builder(selection)
        .SetBaseAndExtent(selection.Anchor(), new_end)
        .Build();
  }
  return SelectionInFlatTree::Builder(selection)
      .SetBaseAndExtent(new_end, selection.Focus())
      .Build();
}

SelectionInFlatTree AdjustSelectionByUserSelect(
    Node* anchor_node,
    const SelectionInFlatTree& selection) {
  DCHECK(anchor_node);

  if (selection.IsNone())
    return SelectionInFlatTree();

  SelectionInFlatTree expanded_selection =
      ExpandSelectionToRespectUserSelectAll(anchor_node, selection);
  Element* enclosing_block = EnclosingBlock(anchor_node);

  PositionInFlatTree anchor = expanded_selection.Anchor();
  PositionInFlatTree new_start_pos =
      PositionInFlatTree::FirstPositionInNode(*anchor_node);
  for (PositionIteratorInFlatTree iter =
           PositionIteratorInFlatTree(new_start_pos);
       !iter.AtStart(); iter.Decrement()) {
    PositionInFlatTree current_pos = iter.ComputePosition();
    if (current_pos <= anchor) {
      new_start_pos = anchor;
      break;
    }

    if (!ShouldIgnoreNodeForCheckSelectable(enclosing_block, iter.GetNode()) &&
        IsNonSelectable(iter.GetNode())) {
      new_start_pos = current_pos;
      break;
    }
  }

  PositionInFlatTree focus = expanded_selection.Focus();
  PositionInFlatTree new_end_pos =
      PositionInFlatTree::LastPositionInNode(*anchor_node);
  for (PositionIteratorInFlatTree iter =
           PositionIteratorInFlatTree(new_end_pos);
       !iter.AtEnd(); iter.Increment()) {
    PositionInFlatTree current_pos = iter.ComputePosition();
    if (current_pos >= focus) {
      new_end_pos = focus;
      break;
    }

    if (!ShouldIgnoreNodeForCheckSelectable(enclosing_block, iter.GetNode()) &&
        IsNonSelectable(iter.GetNode())) {
      new_end_pos = current_pos;
      break;
    }
  }

  return SelectionInFlatTree::Builder()
      .SetBaseAndExtent(new_start_pos, new_end_pos)
      .Build();
}

SelectionController::~SelectionController() = default;

Document& SelectionController::GetDocument() const {
  DCHECK(frame_->GetDocument());
  return *frame_->GetDocument();
}

void SelectionController::ContextDestroyed() {
  original_anchor_in_flat_tree_ = PositionInFlatTreeWithAffinity();
}

static PositionInFlatTreeWithAffinity AdjustPositionRespectUserSelectAll(
    Node* inner_node,
    const PositionInFlatTree& selection_start,
    const PositionInFlatTree& selection_end,
    const PositionInFlatTreeWithAffinity& position) {
  const SelectionInFlatTree selection_in_user_select_all =
      CreateVisibleSelection(
          ExpandSelectionToRespectUserSelectAll(
              inner_node,
              position.IsNull()
                  ? SelectionInFlatTree()
                  : SelectionInFlatTree::Builder().Collapse(position).Build()))
          .AsSelection();
  if (!selection_in_user_select_all.IsRange())
    return position;
  if (selection_in_user_select_all.ComputeStartPosition().CompareTo(
          selection_start) < 0) {
    return PositionInFlatTreeWithAffinity(
        selection_in_user_select_all.ComputeStartPosition());
  }
  // TODO(xiaochengh): Do we need to use upstream affinity for end?
  if (selection_end.CompareTo(
          selection_in_user_select_all.ComputeEndPosition()) < 0) {
    return PositionInFlatTreeWithAffinity(
        selection_in_user_select_all.ComputeEndPosition());
  }
  return position;
}

static PositionInFlatTree ComputeStartFromEndForExtendForward(
    const PositionInFlatTree& end,
    TextGranularity granularity) {
  if (granularity == TextGranularity::kCharacter)
    return end;
  // |ComputeStartRespectingGranularity()| returns next word/paragraph for
  // end of word/paragraph position. To get start of word/paragraph at |end|,
  // we pass previous position of |end|.
  return ComputeStartRespectingGranularity(
      PositionInFlatTreeWithAffinity(
          PreviousPositionOf(CreateVisiblePosition(end),
                             kCannotCrossEditingBoundary)
              .DeepEquivalent()),
      granularity);
}

static SelectionInFlatTree ExtendSelectionAsDirectional(
    const PositionInFlatTreeWithAffinity& position,
    const SelectionInFlatTree& selection,
    TextGranularity granularity) {
  DCHECK(!selection.IsNone());
  DCHECK(position.IsNotNull());
  const PositionInFlatTree& anchor = selection.Anchor();
  if (position.GetPosition() < anchor) {
    // Extend backward yields backward selection
    //  - forward selection:  *abc ^def ghi| => |abc def^ ghi
    //  - backward selection: *abc |def ghi^ => |abc def ghi^
    const PositionInFlatTree& new_start = ComputeStartRespectingGranularity(
        PositionInFlatTreeWithAffinity(position), granularity);
    const PositionInFlatTree& new_end =
        selection.IsAnchorFirst()
            ? ComputeEndRespectingGranularity(
                  new_start, PositionInFlatTreeWithAffinity(anchor),
                  granularity)
            : anchor;
    if (new_start.IsNull() || new_end.IsNull()) {
      // By some reasons, we fail to extend `selection`.
      // TODO(crbug.com/1386012) We want to have a test case of this.
      return selection;
    }
    SelectionInFlatTree::Builder builder;
    builder.SetBaseAndExtent(new_end, new_start);
    if (new_start == new_end)
      builder.SetAffinity(position.Affinity());
    return builder.Build();
  }

  // Extend forward yields forward selection
  //  - forward selection:  ^abc def| ghi* => ^abc def ghi|
  //  - backward selection: |abc def^ ghi* => abc ^def ghi|
  const PositionInFlatTree& new_start =
      selection.IsAnchorFirst()
          ? anchor
          : ComputeStartFromEndForExtendForward(anchor, granularity);
  const PositionInFlatTree& new_end = ComputeEndRespectingGranularity(
      new_start, PositionInFlatTreeWithAffinity(position), granularity);
  if (new_start.IsNull() || new_end.IsNull()) {
    // By some reasons, we fail to extend `selection`.
    // TODO(crbug.com/1386012) We want to have a test case of this.
    return selection;
  }
  SelectionInFlatTree::Builder builder;
  builder.SetBaseAndExtent(new_start, new_end);
  if (new_start == new_end)
    builder.SetAffinity(position.Affinity());
  return builder.Build();
}

static SelectionInFlatTree ExtendSelectionAsNonDirectional(
    const PositionInFlatTree& position,
    const SelectionInFlatTree& selection,
    TextGranularity granularity) {
  DCHECK(!selection.IsNone());
  DCHECK(position.IsNotNull());
  // Shift+Click deselects when selection was created right-to-left
  const PositionInFlatTree& start = selection.ComputeStartPosition();
  const PositionInFlatTree& end = selection.ComputeEndPosition();
  if (start == end && position == start)
    return selection;
  if (position < start) {
    return SelectionInFlatTree::Builder()
        .SetBaseAndExtent(
            end, ComputeStartRespectingGranularity(
                     PositionInFlatTreeWithAffinity(position), granularity))
        .Build();
  }
  if (end < position) {
    return SelectionInFlatTree::Builder()
        .SetBaseAndExtent(
            start,
            ComputeEndRespectingGranularity(
                start, PositionInFlatTreeWithAffinity(position), granularity))
        .Build();
  }
  const int distance_to_start = TextDistance(start, position);
  const int distance_to_end = TextDistance(position, end);
  if (distance_to_start <= distance_to_end) {
    return SelectionInFlatTree::Builder()
        .SetBaseAndExtent(
            end, ComputeStartRespectingGranularity(
                     PositionInFlatTreeWithAffinity(position), granularity))
        .Build();
  }
  return SelectionInFlatTree::Builder()
      .SetBaseAndExtent(
          start,
          ComputeEndRespectingGranularity(
              start, PositionInFlatTreeWithAffinity(position), granularity))
      .Build();
}

// Updating the selection is considered side-effect of the event and so it
// doesn't impact the handled state.
bool SelectionController::HandleSingleClick(
    const MouseEventWithHitTestResults& event) {
  TRACE_EVENT0("blink",
               "SelectionController::handleMousePressEventSingleClick");

  DCHECK(!frame_->GetDocument()->NeedsLayoutTreeUpdate());
  Node* inner_node = event.InnerNode();
  Node* inner_pseudo = event.GetHitTestResult().InnerPossiblyPseudoNode();
  if (!(inner_node && inner_node->GetLayoutObject() && inner_pseudo &&
        inner_pseudo->GetLayoutObject() && mouse_down_may_start_select_))
    return false;

  // Extend the selection if the Shift key is down, unless the click is in a
  // link or image.
  bool extend_selection = IsExtendingSelection(event);

  const PositionInFlatTreeWithAffinity visible_hit_position =
      CreateVisiblePosition(
          PositionWithAffinityOfHitTestResult(event.GetHitTestResult()))
          .ToPositionWithAffinity();
  const PositionInFlatTreeWithAffinity& position_to_use =
      visible_hit_position.IsNull()
          ? CreateVisiblePosition(
                PositionInFlatTree::FirstPositionInOrBeforeNode(*inner_node))
                .ToPositionWithAffinity()
          : visible_hit_position;
  const VisibleSelectionInFlatTree& selection =
      Selection().ComputeVisibleSelectionInFlatTree();
  const bool is_editable = IsEditable(*inner_node);

  if (frame_->GetEditor().Behavior().ShouldToggleMenuWhenCaretTapped() &&
      is_editable && event.Event().FromTouch() && selection.IsCaret() &&
      selection.Anchor() == position_to_use.GetPosition()) {
    mouse_down_was_single_click_on_caret_ = true;
    HandleTapOnCaret(event, selection.AsSelection());
    return false;
  }

  // Don't restart the selection when the mouse is pressed on an
  // existing selection so we can allow for text dragging.
  if (LocalFrameView* view = frame_->View()) {
    const PhysicalOffset v_point(view->ConvertFromRootFrame(
        gfx::ToFlooredPoint(event.Event().PositionInRootFrame())));
    if (!extend_selection && Selection().Contains(v_point)) {
      mouse_down_was_single_click_in_selection_ = true;
      if (!event.Event().FromTouch())
        return false;

      if (HandleTapInsideSelection(event, selection.AsSelection()))
        return false;
    }
  }

  if (extend_selection && !selection.IsNone()) {
    // Note: "fast/events/shift-click-user-select-none.html" makes
    // |pos.isNull()| true.
    const PositionInFlatTreeWithAffinity adjusted_position =
        AdjustPositionRespectUserSelectAll(inner_node, selection.Start(),
                                           selection.End(), position_to_use);
    const TextGranularity granularity = Selection().Granularity();
    if (adjusted_position.IsNull()) {
      UpdateSelectionForMouseDownDispatchingSelectStart(
          inner_node, selection.AsSelection(),
          SetSelectionOptions::Builder().SetGranularity(granularity).Build());
      return false;
    }
    UpdateSelectionForMouseDownDispatchingSelectStart(
        inner_node,
        frame_->GetEditor().Behavior().ShouldConsiderSelectionAsDirectional()
            ? ExtendSelectionAsDirectional(adjusted_position,
                                           selection.AsSelection(), granularity)
            : ExtendSelectionAsNonDirectional(adjusted_position.GetPosition(),
                                              selection.AsSelection(),
                                              granularity),
        SetSelectionOptions::Builder().SetGranularity(granularity).Build());
    return false;
  }

  if (selection_state_ == SelectionState::kExtendedSelection) {
    UpdateSelectionForMouseDownDispatchingSelectStart(
        inner_node, selection.AsSelection(), SetSelectionOptions());
    return false;
  }

  if (position_to_use.IsNull()) {
    UpdateSelectionForMouseDownDispatchingSelectStart(
        inner_node, SelectionInFlatTree(), SetSelectionOptions());
    return false;
  }

  bool is_handle_visible = false;
  if (is_editable) {
    const bool is_text_box_empty =
        !RootEditableElement(*inner_node)->HasChildren();
    const bool not_left_click =
        event.Event().button != WebPointerProperties::Button::kLeft;
    if (!is_text_box_empty || not_left_click)
      is_handle_visible = event.Event().FromTouch();
  }

  // This applies the JavaScript selectstart handler, which can change the DOM.
  // SelectionControllerTest_SelectStartHandlerRemovesElement makes this return
  // false.
  if (!UpdateSelectionForMouseDownDispatchingSelectStart(
          inner_node,
          ExpandSelectionToRespectUserSelectAll(
              inner_node,
              SelectionInFlatTree::Builder().Collapse(position_to_use).Build()),
          SetSelectionOptions::Builder()
              .SetShouldShowHandle(is_handle_visible)
              .Build())) {
    // UpdateSelectionForMouseDownDispatchingSelectStart() returns false when
    // the selectstart handler has prevented the default selection behavior from
    // occurring.
    return false;
  }

  // SelectionControllerTest_SetCaretAtHitTestResultWithDisconnectedPosition
  // makes the IsValidFor() check fail.
  if (is_editable && event.Event().FromTouch() &&
      position_to_use.IsValidFor(*frame_->GetDocument())) {
    frame_->GetTextSuggestionController().HandlePotentialSuggestionTap(
        position_to_use.GetPosition());
  }

  return false;
}

// Returns true if the tap is processed.
void SelectionController::HandleTapOnCaret(
    const MouseEventWithHitTestResults& event,
    const SelectionInFlatTree& selection) {
  Node* inner_node = event.InnerNode();
  const bool is_text_box_empty =
      !RootEditableElement(*inner_node)->HasChildren();

  // If the textbox is empty, tapping the caret should toggle showing/hiding the
  // handle. Otherwise, always show the handle.
  const bool should_show_handle =
      !is_text_box_empty || !Selection().IsHandleVisible();

  // Repaint the caret to ensure that the handle is shown if needed.
  MarkSelectionEndpointsForRepaint(selection);
  const bool did_select = UpdateSelectionForMouseDownDispatchingSelectStart(
      inner_node, selection,
      SetSelectionOptions::Builder()
          .SetShouldShowHandle(should_show_handle)
          .Build());
  if (did_select) {
    frame_->GetEventHandler().ShowNonLocatedContextMenu(nullptr,
                                                        kMenuSourceTouch);
  }
}

// Returns true if the tap is processed.
bool SelectionController::HandleTapInsideSelection(
    const MouseEventWithHitTestResults& event,
    const SelectionInFlatTree& selection) {
  if (Selection().ShouldShrinkNextTap()) {
    const bool did_select = SelectClosestWordFromHitTestResult(
        event.GetHitTestResult(), AppendTrailingWhitespace::kDontAppend,
        SelectInputEventType::kTouch);
    if (did_select) {
      frame_->GetEventHandler().ShowNonLocatedContextMenu(
          nullptr, kMenuSourceAdjustSelectionReset);
    }
    return true;
  }

  if (Selection().IsHandleVisible())
    return false;

  // We need to trigger a repaint on the selection endpoints if the selection is
  // tapped when the selection handle was previously not visible. Repainting
  // will record the painted selection bounds and send it through the pipeline
  // so the handles show up in the next frame after the tap.
  MarkSelectionEndpointsForRepaint(selection);

  const bool did_select = UpdateSelectionForMouseDownDispatchingSelectStart(
      event.InnerNode(), selection,
      SetSelectionOptions::Builder().SetShouldShowHandle(true).Build());
  if (did_select) {
    frame_->GetEventHandler().ShowNonLocatedContextMenu(nullptr,
                                                        kMenuSourceTouch);
  }
  return true;
}

WebInputEventResult SelectionController::UpdateSelectionForMouseDrag(
    const HitTestResult& hit_test_result,
    const PhysicalOffset& last_known_mouse_position) {
  if (!mouse_down_may_start_select_)
    return WebInputEventResult::kNotHandled;

  Node* target = hit_test_result.InnerPossiblyPseudoNode();
  if (!target)
    return WebInputEventResult::kNotHandled;

  // TODO(editing-dev): Use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  frame_->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kSelection);

  const PositionWithAffinity& raw_target_position =
      Selection().SelectionHasFocus()
          ? PositionRespectingEditingBoundary(
                Selection().ComputeVisibleSelectionInDOMTree().Start(),
                hit_test_result)
          : PositionWithAffinity();
  const PositionInFlatTreeWithAffinity target_position =
      CreateVisiblePosition(
          FromPositionInDOMTree<EditingInFlatTreeStrategy>(raw_target_position))
          .ToPositionWithAffinity();

  // Don't modify the selection if we're not on a node.
  if (target_position.IsNull())
    return WebInputEventResult::kNotHandled;

  // Restart the selection if this is the first mouse move. This work is usually
  // done in handleMousePressEvent, but not if the mouse press was on an
  // existing selection.

  if (selection_state_ == SelectionState::kHaveNotStartedSelection &&
      DispatchSelectStart(target) != DispatchEventResult::kNotCanceled) {
    return WebInputEventResult::kHandledApplication;
  }

  // |DispatchSelectStart()| can change |GetDocument()| or invalidate
  // target_position by 'selectstart' event handler.
  // TODO(editing-dev): We should also add a regression test when above
  // behaviour happens. See crbug.com/775149.
  if (!Selection().IsAvailable() || !target_position.IsValidFor(GetDocument()))
    return WebInputEventResult::kNotHandled;

  const bool should_extend_selection =
      selection_state_ == SelectionState::kExtendedSelection;
  // Always extend selection here because it's caused by a mouse drag
  selection_state_ = SelectionState::kExtendedSelection;

  const VisibleSelectionInFlatTree& visible_selection =
      Selection().ComputeVisibleSelectionInFlatTree();
  if (visible_selection.IsNone()) {
    // TODO(editing-dev): This is an urgent fix to crbug.com/745501. We should
    // find the root cause and replace this by a proper fix.
    return WebInputEventResult::kNotHandled;
  }

  const PositionInFlatTreeWithAffinity adjusted_position =
      AdjustPositionRespectUserSelectAll(target, visible_selection.Start(),
                                         visible_selection.End(),
                                         target_position);
  const SelectionInFlatTree& adjusted_selection =
      should_extend_selection
          ? ExtendSelectionAsDirectional(adjusted_position,
                                         visible_selection.AsSelection(),
                                         Selection().Granularity())
          : SelectionInFlatTree::Builder().Collapse(adjusted_position).Build();

  // When |adjusted_selection| is caret, it's already canonical. No need to re-
  // canonicalize it.
  const SelectionInFlatTree new_visible_selection =
      adjusted_selection.IsRange()
          ? CreateVisibleSelection(adjusted_selection).AsSelection()
          : adjusted_selection;
  if (new_visible_selection.IsNone()) {
    // See http://crbug.com/1412880
    return WebInputEventResult::kNotHandled;
  }
  const bool selection_is_directional =
      should_extend_selection ? Selection().IsDirectional() : false;
  SetNonDirectionalSelectionIfNeeded(
      new_visible_selection,
      SetSelectionOptions::Builder()
          .SetGranularity(Selection().Granularity())
          .SetIsDirectional(selection_is_directional)
          .Build(),
      kAdjustEndpointsAtBidiBoundary);

  return WebInputEventResult::kHandledSystem;
}

bool SelectionController::UpdateSelectionForMouseDownDispatchingSelectStart(
    Node* target_node,
    const SelectionInFlatTree& selection,
    const SetSelectionOptions& set_selection_options) {
  if (target_node && target_node->GetLayoutObject() &&
      !target_node->GetLayoutObject()->IsSelectable())
    return false;

  {
    SelectionInFlatTree::InvalidSelectionResetter resetter(selection);
    if (DispatchSelectStart(target_node) != DispatchEventResult::kNotCanceled)
      return false;
  }

  // |DispatchSelectStart()| can change document hosted by |frame_|.
  if (!Selection().IsAvailable())
    return false;

  // TODO(editing-dev): Use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  const SelectionInFlatTree visible_selection =
      CreateVisibleSelection(selection).AsSelection();

  if (visible_selection.IsRange()) {
    selection_state_ = SelectionState::kExtendedSelection;
    SetNonDirectionalSelectionIfNeeded(visible_selection, set_selection_options,
                                       kDoNotAdjustEndpoints);
    return true;
  }

  selection_state_ = SelectionState::kPlacedCaret;
  SetNonDirectionalSelectionIfNeeded(visible_selection, set_selection_options,
                                     kDoNotAdjustEndpoints);
  return true;
}

bool SelectionController::SelectClosestWordFromHitTestResult(
    const HitTestResult& result,
    AppendTrailingWhitespace append_trailing_whitespace,
    SelectInputEventType select_input_event_type) {
  Node* const inner_node = result.InnerPossiblyPseudoNode();

  if (!inner_node || !inner_node->GetLayoutObject() ||
      !inner_node->GetLayoutObject()->IsSelectable())
    return false;

  // Special-case image local offset to always be zero, to avoid triggering
  // LayoutReplaced::positionFromPoint's advancement of the position at the
  // mid-point of the the image (which was intended for mouse-drag selection
  // and isn't desirable for touch).
  HitTestResult adjusted_hit_test_result = result;
  if (select_input_event_type == SelectInputEventType::kTouch &&
      result.GetImage()) {
    adjusted_hit_test_result.SetNodeAndPosition(
        result.InnerPossiblyPseudoNode(), PhysicalOffset());
  }

  const PositionInFlatTreeWithAffinity pos =
      CreateVisiblePosition(
          PositionWithAffinityOfHitTestResult(adjusted_hit_test_result))
          .ToPositionWithAffinity();
  const SelectionInFlatTree new_selection =
      pos.IsNotNull()
          ? ExpandWithGranularity(
                SelectionInFlatTree::Builder().Collapse(pos).Build(),
                TextGranularity::kWord)
          : SelectionInFlatTree();

  // TODO(editing-dev): Fix CreateVisibleSelectionWithGranularity() to not
  // return invalid ranges. Until we do that, we need this check here to avoid a
  // renderer crash when we call PlainText() below (see crbug.com/735774).
  if (new_selection.IsNone() ||
      new_selection.ComputeStartPosition() > new_selection.ComputeEndPosition())
    return false;

  if (select_input_event_type == SelectInputEventType::kTouch) {
    // If node doesn't have text except space, tab or line break, do not
    // select that 'empty' area.
    EphemeralRangeInFlatTree range = new_selection.ComputeRange();
    const String word = PlainText(
        range, TextIteratorBehavior::Builder()
                   .SetEmitsObjectReplacementCharacter(
                       IsEditable(*range.StartPosition().AnchorNode()))
                   .Build());
    if (word.length() >= 1 && word[0] == '\n') {
      // We should not select word from end of line, e.g.
      // "(1)|\n(2)" => "(1)^\n(|2)". See http://crbug.com/974569
      return false;
    }
    if (word.SimplifyWhiteSpace().ContainsOnlyWhitespaceOrEmpty())
      return false;

    Element* const editable =
        RootEditableElementOf(new_selection.ComputeStartPosition());
    if (editable && pos.GetPosition() ==
                        VisiblePositionInFlatTree::LastPositionInNode(*editable)
                            .DeepEquivalent())
      return false;
  }

  const SelectionInFlatTree& adjusted_selection =
      append_trailing_whitespace == AppendTrailingWhitespace::kShouldAppend
          ? AdjustSelectionWithTrailingWhitespace(new_selection)
          : new_selection;

  return UpdateSelectionForMouseDownDispatchingSelectStart(
      inner_node,
      ExpandSelectionToRespectUserSelectAll(inner_node, adjusted_selection),
      SetSelectionOptions::Builder()
          .SetGranularity(TextGranularity::kWord)
          .SetShouldShowHandle(select_input_event_type ==
                               SelectInputEventType::kTouch)
          .Build());
}

void SelectionController::SelectClosestMisspellingFromHitTestResult(
    const HitTestResult& result,
    AppendTrailingWhitespace append_trailing_whitespace) {
  Node* inner_node = result.InnerPossiblyPseudoNode();

  if (!inner_node || !inner_node->GetLayoutObject())
    return;

  const PositionInFlatTreeWithAffinity pos =
      CreateVisiblePosition(PositionWithAffinityOfHitTestResult(result))
          .ToPositionWithAffinity();
  if (pos.IsNull()) {
    UpdateSelectionForMouseDownDispatchingSelectStart(
        inner_node, SelectionInFlatTree(),
        SetSelectionOptions::Builder()
            .SetGr
"""


```