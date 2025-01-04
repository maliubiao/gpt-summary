Response:
The user wants to understand the functionality of the `frame_selection.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet and identify its core responsibilities. I should then explain these functionalities in a clear and concise manner, focusing on the following aspects:

1. **Core Functionality:** What are the main tasks performed by this file?
2. **Relationship with Web Technologies:** How does this code interact with JavaScript, HTML, and CSS? Provide specific examples.
3. **Logical Reasoning:** Are there any logical inferences or decisions made within this code? If so, illustrate with input and output examples.
4. **Common User/Programming Errors:** What potential mistakes could users or developers make that relate to this code?
5. **User Interaction Flow:** How does user interaction lead to the execution of code within this file?
6. **Summary:**  Provide a concise summary of the file's functionality as part 1 of a 2-part explanation.

Based on the included headers and the class name `FrameSelection`, it's clear that this file is responsible for managing the **selection of content within a frame** in the Blink rendering engine. This includes tracking the selection's start and end points, visually representing the selection (like the caret), and handling user interactions related to selection.

Here's a breakdown of the functionalities I can identify from the provided code:

*   **Maintaining Selection State:**  Storing the anchor and focus points of the selection.
*   **Visual Representation:**  Managing the caret (the blinking cursor) and selection highlights.
*   **User Interaction Handling:**  Responding to mouse clicks, keyboard input, and other user actions that modify the selection.
*   **Integration with Editing:**  Working with editing commands and other editing-related components.
*   **Accessibility:**  Providing information about the selection to accessibility tools.
*   **Event Handling:**  Dispatching events related to selection changes.
*   **Scrolling:**  Ensuring the selected content is visible by scrolling if necessary.

I will now elaborate on each of these aspects and connect them to JavaScript, HTML, and CSS where applicable.
```
这是目录为blink/renderer/core/editing/frame_selection.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

根据提供的代码片段，`blink/renderer/core/editing/frame_selection.cc` 文件的主要功能是**管理和维护网页中一个特定 `LocalFrame` 内的文本和元素的选中状态 (Selection)**。它处理了与用户选择操作相关的各种逻辑，并与渲染引擎的其他部分进行交互。

以下是该文件功能的详细列举：

**核心功能:**

1. **维护选择状态:**  `FrameSelection` 类负责存储和管理当前帧的选择状态，包括选择的起始位置 (anchor) 和结束位置 (focus)。它内部使用 `SelectionInDOMTree` 来表示 DOM 树中的选择，并用 `VisibleSelection` 和 `VisibleSelectionInFlatTree` 来表示在渲染树中的可视选择。
2. **处理用户选择操作:** 响应用户的鼠标和键盘操作，例如点击、拖拽、Shift+点击、方向键等，以创建、修改和清除选择。
3. **控制光标 (Caret) 的显示和行为:**  `FrameSelection` 包含了 `FrameCaret` 成员，负责光标的绘制、位置更新和闪烁动画。
4. **与编辑功能集成:**  与 `Editor` 类和编辑命令 (例如 `TypingCommand`) 协同工作，处理插入、删除等编辑操作。
5. **处理文本粒度选择:** 支持不同粒度的选择，例如字符、单词、行、段落等。
6. **处理方向性选择:**  区分向前和向后的选择方向。
7. **触发和响应选择相关事件:**  在选择发生变化时，触发 `selectstart` 和 `selectionchange` 等 DOM 事件。
8. **与无障碍功能 (Accessibility) 集成:**  向辅助技术提供关于选择的信息。
9. **与渲染引擎交互:**  通知渲染引擎更新选择区域的视觉效果，例如高亮显示。
10. **处理跨帧选择:** 虽然代码片段主要关注单个帧，但 `FrameSelection` 的设计也需要考虑跨多个 iframe 的选择。
11. **处理焦点:**  确定选择是否具有焦点，以及在选择发生变化时如何设置焦点。
12. **滚动到可视区域:**  在选择发生变化时，确保选中的内容在视图中可见。

**与 Javascript, HTML, CSS 的关系:**

*   **Javascript:**
    *   JavaScript 可以通过 `window.getSelection()` API 获取当前的选择对象，这个对象最终会关联到 `FrameSelection` 的实例。
    *   JavaScript 可以监听 `selectstart` 和 `selectionchange` 事件，这些事件由 `FrameSelection` 在选择发生变化时触发。
    *   JavaScript 可以使用 `document.execCommand()` 等方法来执行与选择相关的编辑操作，这些操作会影响 `FrameSelection` 的状态。
    *   **例子:** 用户在文本框中用鼠标拖动来选择一段文字，会触发 JavaScript 的 `selectionchange` 事件，该事件的处理函数可以获取到被选中的文本。

*   **HTML:**
    *   HTML 定义了文本和可编辑元素，用户可以在这些元素上进行选择。
    *   `FrameSelection` 需要知道哪些 HTML 元素是可编辑的，以便允许在其内部进行选择。
    *   **例子:**  用户在一个 `<p contenteditable="true">` 元素中进行选择。`FrameSelection` 会根据用户的操作更新选择的起始和结束位置。

*   **CSS:**
    *   CSS 样式可以影响选择的外观，例如选中文字的背景颜色和文本颜色。
    *   `FrameSelection` 需要与渲染引擎协作，以便根据 CSS 样式来绘制选择高亮。
    *   **例子:**  网页 CSS 定义了选中文字的背景色为黄色。当用户进行选择时，`FrameSelection` 会指示渲染引擎以黄色背景绘制选中的区域。

**逻辑推理的例子:**

*   **假设输入:** 用户在文本 "Hello World" 中，光标位于 "W" 之前。用户按下 "Shift" + "向右方向键"。
*   **FrameSelection 的逻辑:**
    1. 检测到 Shift 键被按下，表示需要扩展选择。
    2. 检测到向右方向键被按下，表示选择的焦点需要向右移动一个字符。
    3. 根据当前的焦点位置和移动方向，计算新的选择焦点位置（移动到 "o" 之后）。
    4. 更新 `SelectionInDOMTree` 的 focus 位置。
    5. 通知渲染引擎更新选择高亮，将 "W" 包含在选择中。
*   **输出:** 文本 "Hello World" 中的 "W" 被高亮显示。

**用户或编程常见的使用错误:**

*   **用户错误:**  用户可能在不可编辑的元素上尝试进行选择，例如静态的图片或标题。`FrameSelection` 会判断元素的编辑性，不会在不可编辑的区域创建有效的选择。
*   **编程错误:**
    *   开发者可能错误地操作 DOM 结构，导致 `FrameSelection` 的状态与实际 DOM 不一致，从而引发崩溃或不可预测的行为。
    *   开发者可能在 JavaScript 中尝试手动设置无效的选择范围，例如起始位置在结束位置之后。`FrameSelection` 内部会进行校验，避免出现这种情况。
    *   **例子:**  JavaScript 代码试图将选择的起始节点设置为一个已经被移除的 DOM 节点。`FrameSelection` 在处理时可能会抛出异常或产生错误的选择状态。

**用户操作到达这里的步骤 (调试线索):**

1. **用户与网页交互:** 用户在浏览器中打开一个网页。
2. **用户发起选择操作:** 用户使用鼠标点击并拖动，或者使用键盘按住 Shift 键并移动光标，在网页的某个可编辑区域或文本内容上进行选择。
3. **浏览器事件捕获:** 浏览器的事件处理机制捕获用户的鼠标或键盘事件。
4. **事件传递到 Blink 渲染引擎:**  浏览器将这些事件传递给 Blink 渲染引擎进行处理.
5. **事件分发到 Frame:**  Blink 引擎确定事件发生的目标 `LocalFrame`。
6. **事件处理:**  `LocalFrame` 的事件处理程序 (例如 `EventHandler`) 接收到事件。
7. **选择逻辑处理:**  对于与选择相关的事件 (如鼠标按下、鼠标移动、键盘按下)，`EventHandler` 会调用 `FrameSelection` 相应的方法，例如 `MoveCaretSelection` 或 `Modify`。
8. **`FrameSelection` 更新状态:**  `FrameSelection` 根据用户操作更新内部的选择状态，包括 anchor 和 focus 的位置。
9. **通知渲染更新:**  `FrameSelection` 通知渲染引擎 (例如 `LayoutView`) 需要更新选择区域的显示。
10. **绘制选择:**  渲染引擎根据 `FrameSelection` 提供的信息，绘制选择高亮和光标。

**归纳其功能 (第 1 部分):**

总而言之，`blink/renderer/core/editing/frame_selection.cc` 文件的核心职责在于**管理和维护一个 `LocalFrame` 内的文本和元素的选中状态**。它负责响应用户的选择操作，控制光标的行为，并与编辑功能、渲染引擎和无障碍功能进行协作，以确保用户能够正确地进行文本选择和编辑。它是浏览器渲染引擎中处理用户交互和文本编辑的关键组件之一。

Prompt: 
```
这是目录为blink/renderer/core/editing/frame_selection.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2004, 2008, 2009, 2010 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/editing/frame_selection.h"

#include <stdio.h>

#include <optional>

#include "base/auto_reset.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/accessibility/blink_ax_event_intent.h"
#include "third_party/blink/renderer/core/accessibility/scoped_blink_ax_event_intent.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/character_data.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/node_with_index.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/caret_display_item_client.h"
#include "third_party/blink/renderer/core/editing/commands/typing_command.h"
#include "third_party/blink/renderer/core/editing/editing_behavior.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_caret.h"
#include "third_party/blink/renderer/core/editing/granularity_strategy.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/layout_selection.h"
#include "third_party/blink/renderer/core/editing/local_caret_rect.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/selection_controller.h"
#include "third_party/blink/renderer/core/editing/selection_editor.h"
#include "third_party/blink/renderer/core/editing/selection_modifier.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/context_menu_allowed_scope.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/hit_test_request.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/page/spatial_navigation.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/text/text_direction.h"
#include "third_party/blink/renderer/platform/text/unicode_utilities.h"
#include "ui/gfx/geometry/quad_f.h"

#define EDIT_DEBUG 0

namespace blink {

static inline bool ShouldAlwaysUseDirectionalSelection(LocalFrame* frame) {
  return frame->GetEditor().Behavior().ShouldConsiderSelectionAsDirectional();
}

FrameSelection::FrameSelection(LocalFrame& frame)
    : frame_(frame),
      layout_selection_(MakeGarbageCollected<LayoutSelection>(*this)),
      selection_editor_(MakeGarbageCollected<SelectionEditor>(frame)),
      granularity_(TextGranularity::kCharacter),
      x_pos_for_vertical_arrow_navigation_(NoXPosForVerticalArrowNavigation()),
      focused_(frame.GetPage() &&
               frame.GetPage()->GetFocusController().FocusedFrame() == frame),
      is_directional_(ShouldAlwaysUseDirectionalSelection(frame_)),
      frame_caret_(
          MakeGarbageCollected<FrameCaret>(frame, *selection_editor_)) {}

FrameSelection::~FrameSelection() = default;

const EffectPaintPropertyNode& FrameSelection::CaretEffectNode() const {
  return frame_caret_->CaretEffectNode();
}

bool FrameSelection::IsAvailable() const {
  return SynchronousMutationObserver::GetDocument();
}

Document& FrameSelection::GetDocument() const {
  DCHECK(IsAvailable());
  return *SynchronousMutationObserver::GetDocument();
}

VisibleSelection FrameSelection::ComputeVisibleSelectionInDOMTree() const {
  return selection_editor_->ComputeVisibleSelectionInDOMTree();
}

VisibleSelectionInFlatTree FrameSelection::ComputeVisibleSelectionInFlatTree()
    const {
  return selection_editor_->ComputeVisibleSelectionInFlatTree();
}

const SelectionInDOMTree& FrameSelection::GetSelectionInDOMTree() const {
  return selection_editor_->GetSelectionInDOMTree();
}

Element* FrameSelection::RootEditableElementOrDocumentElement() const {
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);

  Element* selection_root =
      ComputeVisibleSelectionInDOMTree().RootEditableElement();
  // Note that RootEditableElementOrDocumentElement can return null if the
  // documentElement is null.
  return selection_root ? selection_root : GetDocument().documentElement();
}

wtf_size_t FrameSelection::CharacterIndexForPoint(
    const gfx::Point& point) const {
  const EphemeralRange range = GetFrame()->GetEditor().RangeForPoint(point);
  if (range.IsNull())
    return kNotFound;
  Element* const editable = RootEditableElementOrDocumentElement();
  if (!editable) {
    return kNotFound;
  }
  PlainTextRange plain_text_range = PlainTextRange::Create(*editable, range);
  if (plain_text_range.IsNull())
    return kNotFound;
  return plain_text_range.Start();
}

VisibleSelection FrameSelection::ComputeVisibleSelectionInDOMTreeDeprecated()
    const {
  // TODO(editing-dev): Hoist UpdateStyleAndLayout
  // to caller. See http://crbug.com/590369 for more details.
  Position anchor = GetSelectionInDOMTree().Anchor();
  Position focus = GetSelectionInDOMTree().Focus();
  std::optional<DisplayLockUtilities::ScopedForcedUpdate> force_locks;
  if (anchor != focus && anchor.ComputeContainerNode() &&
      focus.ComputeContainerNode()) {
    force_locks = DisplayLockUtilities::ScopedForcedUpdate(
        MakeGarbageCollected<Range>(GetDocument(), anchor, focus),
        DisplayLockContext::ForcedPhase::kLayout);
  } else {
    force_locks = DisplayLockUtilities::ScopedForcedUpdate(
        anchor.AnchorNode(), DisplayLockContext::ForcedPhase::kLayout);
  }
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  return ComputeVisibleSelectionInDOMTree();
}

void FrameSelection::MoveCaretSelection(const gfx::Point& point) {
  DCHECK(!GetDocument().NeedsLayoutTreeUpdate());

  Element* const editable =
      ComputeVisibleSelectionInDOMTree().RootEditableElement();
  if (!editable)
    return;

  const VisiblePosition position = CreateVisiblePosition(
      PositionForContentsPointRespectingEditingBoundary(point, GetFrame()));
  SelectionInDOMTree::Builder builder;
  if (position.IsNotNull())
    builder.Collapse(position.ToPositionWithAffinity());
  SetSelection(builder.Build(), SetSelectionOptions::Builder()
                                    .SetShouldCloseTyping(true)
                                    .SetShouldClearTypingStyle(true)
                                    .SetSetSelectionBy(SetSelectionBy::kUser)
                                    .SetShouldShowHandle(true)
                                    .SetIsDirectional(IsDirectional())
                                    .Build());
}

void FrameSelection::SetSelection(const SelectionInDOMTree& selection,
                                  const SetSelectionOptions& data) {
  if (SetSelectionDeprecated(selection, data))
    DidSetSelectionDeprecated(selection, data);
}

void FrameSelection::SetSelectionAndEndTyping(
    const SelectionInDOMTree& selection) {
  SetSelection(selection, SetSelectionOptions::Builder()
                              .SetShouldCloseTyping(true)
                              .SetShouldClearTypingStyle(true)
                              .Build());
}

static void AssertUserSelection(const SelectionInDOMTree& selection,
                                const SetSelectionOptions& options) {
// User's selection start/end should have same editability.
#if DCHECK_IS_ON()
  if (!options.ShouldShowHandle() &&
      options.GetSetSelectionBy() != SetSelectionBy::kUser)
    return;
  Node* anchor_editable_root = RootEditableElementOf(selection.Anchor());
  Node* focus_editable_root = RootEditableElementOf(selection.Focus());
  DCHECK_EQ(anchor_editable_root, focus_editable_root) << selection;
#endif
}

bool FrameSelection::SetSelectionDeprecated(
    const SelectionInDOMTree& new_selection,
    const SetSelectionOptions& passed_options) {
  SetSelectionOptions::Builder options_builder(passed_options);
  if (ShouldAlwaysUseDirectionalSelection(frame_)) {
    options_builder.SetIsDirectional(true);
  }
  const SetSelectionOptions options = options_builder.Build();

  if (granularity_strategy_ && !options.DoNotClearStrategy())
    granularity_strategy_->Clear();
  granularity_ = options.Granularity();

  // TODO(yosin): We should move to call |TypingCommand::closeTyping()| to
  // |Editor| class.
  if (options.ShouldCloseTyping())
    TypingCommand::CloseTyping(frame_);

  if (options.ShouldClearTypingStyle())
    frame_->GetEditor().ClearTypingStyle();

  const SelectionInDOMTree old_selection_in_dom_tree =
      selection_editor_->GetSelectionInDOMTree();
  const bool is_changed = old_selection_in_dom_tree != new_selection;
  const bool should_show_handle = options.ShouldShowHandle();
  if (!is_changed && is_handle_visible_ == should_show_handle &&
      is_directional_ == options.IsDirectional())
    return false;
  Document& current_document = GetDocument();
  if (is_changed) {
    AssertUserSelection(new_selection, options);
    selection_editor_->SetSelectionAndEndTyping(new_selection);
    NotifyDisplayLockForSelectionChange(
        current_document, old_selection_in_dom_tree, new_selection);
  }
  is_directional_ = options.IsDirectional();
  should_shrink_next_tap_ = options.ShouldShrinkNextTap();
  is_handle_visible_ = should_show_handle;
  ScheduleVisualUpdateForVisualOverflowIfNeeded();

  frame_->GetEditor().RespondToChangedSelection();
  DCHECK_EQ(current_document, GetDocument());
  return true;
}

void FrameSelection::DidSetSelectionDeprecated(
    const SelectionInDOMTree& new_selection,
    const SetSelectionOptions& options) {
  Document& current_document = GetDocument();
  const SetSelectionBy set_selection_by = options.GetSetSelectionBy();

  // Provides details to accessibility about the selection change throughout the
  // current call stack.
  //
  // If the selection is currently being modified via the "Modify" method, we
  // should already have more detailed information on the stack than can be
  // deduced in this method.
  std::optional<ScopedBlinkAXEventIntent> scoped_blink_ax_event_intent;
  if (current_document.ExistingAXObjectCache()) {
    scoped_blink_ax_event_intent.emplace(
        is_being_modified_ ? BlinkAXEventIntent()
        : new_selection.IsNone()
            ? BlinkAXEventIntent::FromClearedSelection(set_selection_by)
            : BlinkAXEventIntent::FromNewSelection(
                  options.Granularity(), new_selection.IsAnchorFirst(),
                  set_selection_by),
        &current_document);
  }

  if (!new_selection.IsNone() && !options.DoNotSetFocus()) {
    SetFocusedNodeIfNeeded();
    // |setFocusedNodeIfNeeded()| dispatches sync events "FocusOut" and
    // "FocusIn", |frame_| may associate to another document.
    if (!IsAvailable() || GetDocument() != current_document) {
      // editing/selection/move-selection-detached-frame-crash.html reaches
      // here. See http://crbug.com/1015710.
      return;
    }
  }

  frame_caret_->StopCaretBlinkTimer();
  UpdateAppearance();

  // Always clear the x position used for vertical arrow navigation.
  // It will be restored by the vertical arrow navigation code if necessary.
  x_pos_for_vertical_arrow_navigation_ = NoXPosForVerticalArrowNavigation();

  // TODO(yosin): Can we move this to at end of this function?
  // This may dispatch a synchronous focus-related events.
  if (!options.DoNotSetFocus()) {
    SelectFrameElementInParentIfFullySelected();
    if (!IsAvailable() || GetDocument() != current_document) {
      // editing/selection/selectallchildren-crash.html and
      // editing/selection/longpress-selection-in-iframe-removed-crash.html
      // reach here.
      return;
    }
  }

  NotifyTextControlOfSelectionChange(set_selection_by);
  if (set_selection_by == SetSelectionBy::kUser) {
    const CursorAlignOnScroll align = options.GetCursorAlignOnScroll();
    mojom::blink::ScrollAlignment alignment;

    if (frame_->GetEditor()
            .Behavior()
            .ShouldCenterAlignWhenSelectionIsRevealed()) {
      alignment = (align == CursorAlignOnScroll::kAlways)
                      ? ScrollAlignment::CenterAlways()
                      : ScrollAlignment::CenterIfNeeded();
    } else {
      alignment = (align == CursorAlignOnScroll::kAlways)
                      ? ScrollAlignment::TopAlways()
                      : ScrollAlignment::ToEdgeIfNeeded();
    }

    RevealSelection(alignment, kRevealExtent);
  }

  NotifyAccessibilityForSelectionChange();
  NotifyCompositorForSelectionChange();
  NotifyEventHandlerForSelectionChange();

  // Dispatch selectionchange events per element based on the new spec:
  // https://w3c.github.io/selection-api/#selectionchange-event
  if (RuntimeEnabledFeatures::DispatchSelectionchangeEventPerElementEnabled()) {
    TextControlElement* text_control =
        EnclosingTextControl(GetSelectionInDOMTree().Anchor());
    if (text_control && !text_control->IsInShadowTree()) {
      text_control->ScheduleSelectionchangeEvent();
    } else {
      GetDocument().ScheduleSelectionchangeEvent();
    }
  }
  // When DispatchSelectionchangeEventPerElement is disabled, fall back to old
  // path.
  else {
    // The task source should be kDOMManipulation, but the spec doesn't say
    // anything about this.
    frame_->DomWindow()->EnqueueDocumentEvent(
        *Event::Create(event_type_names::kSelectionchange),
        TaskType::kMiscPlatformAPI);
  }
}

void FrameSelection::SetSelectionForAccessibility(
    const SelectionInDOMTree& selection,
    const SetSelectionOptions& options) {
  ClearDocumentCachedRange();

  const bool did_set = SetSelectionDeprecated(selection, options);
  CacheRangeOfDocument(CreateRange(selection.ComputeRange()));
  if (did_set)
    DidSetSelectionDeprecated(selection, options);
}

void FrameSelection::NodeChildrenWillBeRemoved(ContainerNode& container) {
  if (!container.InActiveDocument())
    return;
  // TODO(yosin): We should move to call |TypingCommand::CloseTypingIfNeeded()|
  // to |Editor| class.
  TypingCommand::CloseTypingIfNeeded(frame_);
}

void FrameSelection::NodeWillBeRemoved(Node& node) {
  // There can't be a selection inside a fragment, so if a fragment's node is
  // being removed, the selection in the document that created the fragment
  // needs no adjustment.
  if (!node.InActiveDocument())
    return;
  // TODO(yosin): We should move to call |TypingCommand::CloseTypingIfNeeded()|
  // to |Editor| class.
  TypingCommand::CloseTypingIfNeeded(frame_);
}

void FrameSelection::DidChangeFocus() {
  UpdateAppearance();
}

static DispatchEventResult DispatchSelectStart(
    const VisibleSelection& selection) {
  Node* select_start_target = selection.Focus().ComputeContainerNode();
  if (!select_start_target)
    return DispatchEventResult::kNotCanceled;

  return select_start_target->DispatchEvent(
      *Event::CreateCancelableBubble(event_type_names::kSelectstart));
}

// The return value of |FrameSelection::modify()| is different based on
// value of |userTriggered| parameter.
// When |userTriggered| is |userTriggered|, |modify()| returns false if
// "selectstart" event is dispatched and canceled, otherwise returns true.
// When |userTriggered| is |NotUserTrigged|, return value specifies whether
// selection is modified or not.
bool FrameSelection::Modify(SelectionModifyAlteration alter,
                            SelectionModifyDirection direction,
                            TextGranularity granularity,
                            SetSelectionBy set_selection_by) {
  SelectionModifier selection_modifier(*GetFrame(), GetSelectionInDOMTree(),
                                       x_pos_for_vertical_arrow_navigation_);
  selection_modifier.SetSelectionIsDirectional(IsDirectional());
  const bool modified =
      selection_modifier.Modify(alter, direction, granularity);
  if (set_selection_by == SetSelectionBy::kUser &&
      selection_modifier.Selection().IsRange() &&
      ComputeVisibleSelectionInDOMTree().IsCaret() &&
      DispatchSelectStart(ComputeVisibleSelectionInDOMTree()) !=
          DispatchEventResult::kNotCanceled) {
    return false;
  }

  // |DispatchSelectStart()| can change document hosted by |frame_|.
  if (!IsAvailable()) {
    return false;
  }

  if (!modified) {
    if (set_selection_by == SetSelectionBy::kSystem)
      return false;
    // If spatial navigation enabled, focus navigator will move focus to
    // another element. See snav-input.html and snav-textarea.html
    if (IsSpatialNavigationEnabled(frame_))
      return false;
    // Even if selection isn't changed, we prevent to default action, e.g.
    // scroll window when caret is at end of content editable.
    return true;
  }

  // Provides details to accessibility about the selection change throughout the
  // current call stack.
  base::AutoReset<bool> is_being_modified_resetter(&is_being_modified_, true);
  const PlatformWordBehavior platform_word_behavior =
      frame_->GetEditor().Behavior().ShouldSkipSpaceWhenMovingRight()
          ? PlatformWordBehavior::kWordSkipSpaces
          : PlatformWordBehavior::kWordDontSkipSpaces;
  Document& document = GetDocument();
  std::optional<ScopedBlinkAXEventIntent> scoped_blink_ax_event_intent;
  if (document.ExistingAXObjectCache()) {
    scoped_blink_ax_event_intent.emplace(
        BlinkAXEventIntent::FromModifiedSelection(
            alter, direction, granularity, set_selection_by,
            selection_modifier.DirectionOfSelection(), platform_word_behavior),
        &document);
  }

  // For MacOS only selection is directionless at the beginning.
  // Selection gets direction on extent.
  const bool selection_is_directional =
      alter == SelectionModifyAlteration::kExtend ||
      ShouldAlwaysUseDirectionalSelection(frame_);

  SetSelection(selection_modifier.Selection().AsSelection(),
               SetSelectionOptions::Builder()
                   .SetShouldCloseTyping(true)
                   .SetShouldClearTypingStyle(true)
                   .SetSetSelectionBy(set_selection_by)
                   .SetIsDirectional(selection_is_directional)
                   .Build());

  if (granularity == TextGranularity::kLine ||
      granularity == TextGranularity::kParagraph)
    x_pos_for_vertical_arrow_navigation_ =
        selection_modifier.XPosForVerticalArrowNavigation();

  if (set_selection_by == SetSelectionBy::kUser)
    granularity_ = TextGranularity::kCharacter;

  ScheduleVisualUpdateForVisualOverflowIfNeeded();

  return true;
}

void FrameSelection::Clear() {
  granularity_ = TextGranularity::kCharacter;
  if (granularity_strategy_)
    granularity_strategy_->Clear();
  SetSelectionAndEndTyping(SelectionInDOMTree());
  is_handle_visible_ = false;
  is_directional_ = ShouldAlwaysUseDirectionalSelection(frame_);
}

bool FrameSelection::SelectionHasFocus() const {
  // TODO(editing-dev): Hoist UpdateStyleAndLayout
  // to caller. See http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  if (ComputeVisibleSelectionInFlatTree().IsNone())
    return false;
  const Node* current =
      ComputeVisibleSelectionInFlatTree().Start().ComputeContainerNode();
  if (!current)
    return false;

  // No focused element means document root has focus.
  Element* const focused_element = GetDocument().FocusedElement()
                                       ? GetDocument().FocusedElement()
                                       : GetDocument().documentElement();
  if (!focused_element || focused_element->IsScrollControlPseudoElement()) {
    return false;
  }
  if (RuntimeEnabledFeatures::SelectionOnShadowDOMWithDelegatesFocusEnabled()) {
    // If focus is on the delegated target of a shadow host with delegatesFocus,
    // selection could be on focus even if focused element does not contain
    // current selection start.
    if (focused_element->IsTextControl() &&
        focused_element->ContainsIncludingHostElements(*current)) {
      return true;
    }
  } else {
    if (focused_element->IsTextControl()) {
      return focused_element->ContainsIncludingHostElements(*current);
    }
  }

  // Selection has focus if it contains the focused element.
  const PositionInFlatTree& focused_position =
      PositionInFlatTree::FirstPositionInNode(*focused_element);
  if (ComputeVisibleSelectionInFlatTree().Start() <= focused_position &&
      ComputeVisibleSelectionInFlatTree().End() >= focused_position)
    return true;

  bool is_editable = IsEditable(*current);
  const TreeScope* tree_scope = &current->GetTreeScope();
  do {
    // If the selection is within an editable sub tree and that sub tree
    // doesn't have focus, the selection doesn't have focus either.
    if (is_editable && !IsEditable(*current)) {
      // An element can be not editable because -webkit-user-modify is inherited
      // on the DOM tree instead of the flat tree. This is done in
      // ComputedStyleBuilder::ComputedStyleBuilder and
      // StyleResolver::InitStyle. We should check editability only if we are in
      // the same tree scope.
      if (!RuntimeEnabledFeatures::MouseFocusFlatTreeParentEnabled() ||
          tree_scope == &current->GetTreeScope()) {
        return false;
      }
    }

    // Selection has focus if its sub tree has focus.
    if (current == focused_element)
      return true;
    if (RuntimeEnabledFeatures::
            SelectionOnShadowDOMWithDelegatesFocusEnabled()) {
      // If current is a shadow host with delegatesFocus, then it cannot be the
      // focused element and we should compare with its focusable area instead.
      if (const Element* el = DynamicTo<Element>(current);
          el && el->IsShadowHostWithDelegatesFocus() &&
          el->GetFocusableArea() == focused_element) {
        return true;
      }
    }
    if (RuntimeEnabledFeatures::MouseFocusFlatTreeParentEnabled()) {
      // If we are stepping out of a shadow tree, the tree scope should be
      // updated to the tree we step into.
      bool stepping_out_of_shadow_tree =
          tree_scope == &current->GetTreeScope() &&
          DynamicTo<ShadowRoot>(current->parentNode());
      current = FlatTreeTraversal::Parent(*current);
      if (stepping_out_of_shadow_tree && current) {
        tree_scope = &current->GetTreeScope();
      }
    } else {
      current = current->ParentOrShadowHostNode();
    }
  } while (current);

  return false;
}

bool FrameSelection::IsHidden() const {
  if (SelectionHasFocus())
    return false;

  const Node* start =
      ComputeVisibleSelectionInDOMTree().Start().ComputeContainerNode();
  if (!start)
    return true;

  // The selection doesn't have focus, so hide everything but range selections.
  if (!GetSelectionInDOMTree().IsRange())
    return true;

  // Here we know we have an unfocused range selection. Let's say that
  // selection resides inside a text control. Since the selection doesn't have
  // focus neither does the text control. Meaning, if the selection indeed
  // resides inside a text control, it should be hidden.
  return EnclosingTextControl(start);
}

void FrameSelection::DidAttachDocument(Document* document) {
  DCHECK(document);
  selection_editor_->DidAttachDocument(document);
  SetDocument(document);
}

void FrameSelection::ContextDestroyed() {
  granularity_ = TextGranularity::kCharacter;

  layout_selection_->ContextDestroyed();

  frame_->GetEditor().ClearTypingStyle();
}

void FrameSelection::LayoutBlockWillBeDestroyed(const LayoutBlock& block) {
  frame_caret_->LayoutBlockWillBeDestroyed(block);
}

void FrameSelection::UpdateStyleAndLayoutIfNeeded() {
  frame_caret_->UpdateStyleAndLayoutIfNeeded();
}

void FrameSelection::InvalidatePaint(const LayoutBlock& block,
                                     const PaintInvalidatorContext& context) {
  frame_caret_->InvalidatePaint(block, context);
}

void FrameSelection::EnsureInvalidationOfPreviousLayoutBlock() {
  frame_caret_->EnsureInvalidationOfPreviousLayoutBlock();
}

bool FrameSelection::ShouldPaintCaret(const LayoutBlock& block) const {
  DCHECK_GE(GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kLayoutClean);
  bool result = frame_caret_->ShouldPaintCaret(block);
  DCHECK(!result ||
         (ComputeVisibleSelectionInDOMTree().IsCaret() &&
          (IsEditablePosition(ComputeVisibleSelectionInDOMTree().Start()) ||
           frame_->IsCaretBrowsingEnabled())));
  return result;
}

bool FrameSelection::ShouldPaintCaret(
    const PhysicalBoxFragment& box_fragment) const {
  DCHECK_GE(GetDocument().Lifecycle().GetState(),
            DocumentLifecycle::kLayoutClean);
  bool result = frame_caret_->ShouldPaintCaret(box_fragment);
  DCHECK(!result ||
         (ComputeVisibleSelectionInDOMTree().IsCaret() &&
          (IsEditablePosition(ComputeVisibleSelectionInDOMTree().Start()) ||
           frame_->IsCaretBrowsingEnabled())));
  return result;
}

gfx::Rect FrameSelection::AbsoluteCaretBounds() const {
  DCHECK(ComputeVisibleSelectionInDOMTree().IsValidFor(*frame_->GetDocument()));
  return frame_caret_->AbsoluteCaretBounds();
}

bool FrameSelection::ComputeAbsoluteBounds(gfx::Rect& anchor,
                                           gfx::Rect& focus) const {
  if (!IsAvailable() || GetSelectionInDOMTree().IsNone())
    return false;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  frame_->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
  if (ComputeVisibleSelectionInDOMTree().IsNone()) {
    // plugins/mouse-capture-inside-shadow.html reaches here.
    return false;
  }

  return selection_editor_->ComputeAbsoluteBounds(anchor, focus);
}

void FrameSelection::PaintCaret(GraphicsContext& context,
                                const PhysicalOffset& paint_offset) {
  frame_caret_->PaintCaret(context, paint_offset);
}

bool FrameSelection::Contains(const PhysicalOffset& point) {
  if (!GetDocument().GetLayoutView())
    return false;

  // This is a workaround of the issue that we sometimes get null from
  // ComputeVisibleSelectionInDOMTree(), but non-null from flat tree.
  // By running this, in case we get null, we also set the cached result in flat
  // tree into null, so that this function can return false correctly.
  // See crbug.com/846527 for details.
  // TODO(editing-dev): Fix the inconsistency and then remove this call.
  ComputeVisibleSelectionInDOMTree();

  // Treat a collapsed selection like no selection.
  const VisibleSelectionInFlatTree& visible_selection =
      ComputeVisibleSelectionInFlatTree();
  if (!visible_selection.IsRange())
    return false;

  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location(point);
  HitTestResult result(request, location);
  GetDocument().GetLayoutView()->HitTest(location, result);
  const PositionInFlatTreeWithAffinity pos_with_affinity =
      FromPositionInDOMTree<EditingInFlatTreeStrategy>(result.GetPosition());
  if (pos_with_affinity.IsNull())
    return false;

  const VisiblePositionInFlatTree& visible_start =
      visible_selection.VisibleStart();
  const VisiblePositionInFlatTree& visible_end = visible_selection.VisibleEnd();
  if (visible_start.IsNull() || visible_end.IsNull())
    return false;

  const PositionInFlatTree& start = visible_start.DeepEquivalent();
  const PositionInFlatTree& end = visible_end.DeepEquivalent();
  const PositionInFlatTree& pos = pos_with_affinity.GetPosition();
  return start.CompareTo(pos) <= 0 && pos.CompareTo(end) <= 0;
}

// Workaround for the fact that it's hard to delete a frame.
// Call this after doing user-triggered selections to make it easy to delete the
// frame you entirely selected. Can't do this implicitly as part of every
// setSelection call because in some contexts it might not be good for the focus
// to move to another frame. So instead we call it from places where we are
// selecting with the mouse or the keyboard after setting the selection.
void FrameSelection::SelectFrameElementInParentIfFullySelected() {
  // Find the parent frame; if there is none, then we have nothing to do.
  Frame* parent = frame_->Tree().Parent();
  if (!parent)
    return;
  Page* page = frame_->GetPage();
  if (!page)
    return;

  // Check if the selection contains the entire frame contents; if not, then
  // there is nothing to do.
  if (!GetSelectionInDOMTree().IsRange())
    return;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);

  if (!IsStartOfDocument(ComputeVisibleSelectionInDOMTree().VisibleStart()))
    return;
  if (!IsEndOfDocument(ComputeVisibleSelectionInDOMTree().VisibleEn
"""


```