Response:
Let's break down the thought process for analyzing the `ax_selection.cc` file.

1. **Understand the Goal:** The request asks for the functionality of this file, its relation to web technologies (JavaScript, HTML, CSS), examples, potential user/programming errors, and how a user action might lead to this code.

2. **Initial Code Scan and Keyword Identification:**  Read through the code looking for key terms and patterns. The filename itself (`ax_selection`) is a strong indicator. Keywords like `Selection`, `Anchor`, `Focus`, `Position`, `DOM`, `TextControlElement`, `Event`, `Document`, `Frame`, and namespaces like `accessibility` jump out. The `#include` directives also give clues about dependencies.

3. **Identify the Core Abstraction:** The name `AXSelection` is central. The code clearly defines a class representing a selection in the Accessibility Tree. This suggests the primary function of the file is to manage and manipulate these accessibility selections.

4. **Analyze Key Methods:** Focus on the public methods of the `AXSelection` class and its builder:
    * **Builder:** `SetAnchor`, `SetFocus`, `SetSelection`, `Build`. This clearly points to a builder pattern for creating `AXSelection` objects.
    * **Static Methods:** `ClearCurrentSelection`, `FromCurrentSelection` (multiple overloads), `FromSelection`. These suggest ways to create `AXSelection` objects from existing DOM selections or text control states.
    * **Instance Methods:** `IsValid`, `AsSelection`, `UpdateSelectionIfNecessary`, `Select`, `ToString`, `AsTextControlSelection`. These methods indicate operations on existing `AXSelection` objects, such as validation, conversion to DOM selection, updating, and applying the selection.

5. **Map Functionality to Web Technologies:**  Now, connect the identified functionalities to JavaScript, HTML, and CSS:
    * **HTML:**  Selections inherently operate on the HTML structure. The `TextControlElement` interaction directly relates to HTML input fields and textareas.
    * **CSS:** While this file doesn't directly *manipulate* CSS, the concept of selection can be influenced by CSS (e.g., `user-select`). The code comments even mention this.
    * **JavaScript:**  JavaScript can trigger selection changes via user interaction or programmatic manipulation. Events like `select`, `selectstart` are key bridges. The file explicitly deals with dispatching these events.

6. **Construct Examples:** Based on the identified functionalities and connections, create concrete examples:
    * **JavaScript:** How a JavaScript function could get the current selection and potentially interact with accessibility.
    * **HTML:**  The basic structure of a text input where selections would occur.
    * **CSS:** A brief example of how CSS can affect selection.

7. **Consider Logic and Assumptions:** Analyze the code for conditional logic and assumptions. The `IsValid` method is crucial here. Pay attention to:
    * **Document Boundaries:** Selections don't cross documents.
    * **Shadow DOM:**  Special handling for selections within text controls (which use shadow DOM).
    * **AXPosition Adjustment:** How accessibility positions are adjusted based on selection behavior.

8. **Identify Potential Errors:** Think about common mistakes developers or users might make that relate to this code:
    * **Invalid Positions:** Creating an `AXSelection` with invalid anchor/focus points.
    * **Incorrect `AXSelectionBehavior`:**  Using the wrong behavior and getting unexpected results.
    * **Assuming Immediate Selection:** Forgetting that selection might be asynchronous or depend on layout.

9. **Trace User Actions (Debugging):**  Consider how a user interaction translates into the execution of this code. Start with a simple user action:
    * **Mouse Dragging:**  How this leads to changes in the browser's selection, which then might be reflected in the `AXSelection` object, especially if accessibility features are enabled or the browser's internal accessibility tree is being built/updated.
    * **Keyboard Navigation:** Similar to mouse dragging, but triggered by keyboard events.
    * **Programmatic Selection:** JavaScript code explicitly setting the selection.

10. **Structure the Answer:** Organize the findings logically. Start with a high-level summary of the file's purpose. Then delve into specific functionalities, relationships with web technologies, examples, logic/assumptions, errors, and finally, the debugging perspective. Use clear headings and bullet points for readability.

11. **Refine and Elaborate:** Review the generated answer for clarity, accuracy, and completeness. Add more details or examples where needed. For instance, explain *why* selections might not cross documents or the role of shadow DOM in text controls. Ensure the technical terms are explained adequately. For example, explicitly mentioning the builder pattern makes the code's structure clearer.

This iterative process of reading, analyzing, connecting, and exemplifying helps to thoroughly understand the purpose and function of the given source code file. The focus is not just on what the code *does*, but also *why* it does it in the context of the broader web ecosystem.好的，让我们来分析一下 `blink/renderer/modules/accessibility/ax_selection.cc` 这个文件。

**文件功能概览:**

`ax_selection.cc` 文件的核心功能是管理和表示 Chromium Blink 引擎中**辅助功能树 (Accessibility Tree)** 中的文本选择（selection）。 它提供了一种将 DOM 树中的选择（`SelectionInDOMTree`）映射到辅助功能树表示的方法，并允许在辅助功能树上进行选择操作，最终反映回 DOM 树。

**具体功能列举:**

1. **构建辅助功能选择对象 (AXSelection):**
   - 提供 `AXSelection::Builder` 类，用于方便地创建 `AXSelection` 对象。
   - 允许设置选择的锚点 (anchor) 和焦点 (focus)，这两个点都以 `AXPosition` 对象表示，指向辅助功能树中的位置。
   - 可以从 DOM 树的选择对象 (`SelectionInDOMTree`) 构建 `AXSelection`。

2. **从 DOM 选择创建辅助功能选择:**
   - 提供静态方法 `AXSelection::FromCurrentSelection(const Document&, AXSelectionBehavior)` 和 `AXSelection::FromSelection(const SelectionInDOMTree&, AXSelectionBehavior)`，将 DOM 树中的选择信息转换为辅助功能树中的选择。
   - `AXSelectionBehavior` 枚举定义了在 DOM 选择无法完全映射到辅助功能树时，如何调整选择范围（例如，收缩到有效范围或扩展到有效范围）。

3. **从文本控件 (TextControlElement) 创建辅助功能选择:**
   - 提供静态方法 `AXSelection::FromCurrentSelection(const TextControlElement&)`，专门处理文本输入框和文本域的选择。
   - 由于文本控件内部使用 Shadow DOM，该方法需要特殊处理来获取正确的选择范围。

4. **将辅助功能选择转换为 DOM 选择:**
   - 提供方法 `AXSelection::AsSelection(AXSelectionBehavior)`，将辅助功能树中的选择转换回 DOM 树中的 `SelectionInDOMTree` 对象。

5. **执行选择操作:**
   - 提供方法 `AXSelection::Select(AXSelectionBehavior)`，根据当前的 `AXSelection` 对象更新 DOM 树中的实际选择。
   - 对于文本控件，它会调用 `TextControlElement::SetSelectionRange` 来设置文本框的选择范围。
   - 对于其他类型的元素，它会操作 `FrameSelection` 对象来设置选择。
   - 在设置选择前后，会触发 `selectstart` 和 `select` 事件。

6. **验证辅助功能选择:**
   - 提供方法 `AXSelection::IsValid()`，检查 `AXSelection` 对象是否有效，例如，锚点和焦点是否指向同一个文档，是否跨越了不支持的边界（如 Shadow DOM）。

7. **更新辅助功能选择 (如果需要):**
   - 提供方法 `AXSelection::UpdateSelectionIfNecessary()`，在布局发生变化后，更新 `AXSelection` 对象中缓存的文档树和样式信息。

**与 Javascript, HTML, CSS 的关系及举例说明:**

* **Javascript:**
    - **事件触发:** `AXSelection::Select` 方法会触发 `selectstart` 和 `select` 事件。JavaScript 代码可以监听这些事件来响应用户的选择操作。
    ```javascript
    const inputElement = document.getElementById('myInput');
    inputElement.addEventListener('select', (event) => {
      console.log('Text selected:', inputElement.value.substring(inputElement.selectionStart, inputElement.selectionEnd));
    });
    ```
    - **获取和设置选择:** 虽然 `ax_selection.cc` 是 C++ 代码，但它处理的逻辑最终影响了 JavaScript 中 `window.getSelection()` 返回的 `Selection` 对象，以及像 `HTMLInputElement.selectionStart` 和 `HTMLInputElement.selectionEnd` 这样的属性。  JavaScript 可以通过这些 API 获取或设置文本框的选择，这些操作在底层可能会涉及到 `ax_selection.cc` 中的逻辑。

* **HTML:**
    - **文本控件:**  `AXSelection` 特别关注 `TextControlElement` (例如 `<input type="text">`, `<textarea>`)。 用户在这些 HTML 元素中进行的选择操作，会触发浏览器内部的逻辑，最终可能调用到 `ax_selection.cc` 中的代码来同步辅助功能树的选择状态。
    ```html
    <input type="text" id="myInput" value="可选择的文本">
    ```
    用户拖拽鼠标选中 "可选择的文本" 时，`ax_selection.cc` 中的 `AXSelection::FromCurrentSelection(const TextControlElement&)` 方法会被调用，创建一个表示该选择的 `AXSelection` 对象。

* **CSS:**
    - **`user-select` 属性:** CSS 的 `user-select` 属性可以控制元素是否可被用户选择。虽然 `ax_selection.cc` 本身不直接解析 CSS，但 `user-select: none` 会影响用户的选择行为，从而间接地影响到 `ax_selection.cc` 处理的选择范围。如果一个元素设置了 `user-select: none`，用户无法选中它，那么相关的 `AXSelection` 对象可能不会被创建或为空。
    ```css
    #unselectable {
      user-select: none;
    }
    ```
    如果用户尝试选择带有 `id="unselectable"` 的元素，`ax_selection.cc` 可能会检测到无法进行有效的选择。

**逻辑推理，假设输入与输出:**

**假设输入 1 (文本框选择):**

* 用户在 `<input type="text" value="Hello World">` 中选中了 "World"。
* `TextControlElement` 对象和其对应的 DOM 树信息作为输入传递给 `AXSelection::FromCurrentSelection(const TextControlElement&)`。

**预期输出 1:**

* 创建一个 `AXSelection` 对象，其 `anchor_` 指向 "World" 的起始位置，`focus_` 指向 "World" 的结束位置。
* `AXSelection::AsTextControlSelection()` 返回一个 `TextControlSelection` 对象，`start` 为 6，`end` 为 11，`direction` 为 `kSelectionHasForwardDirection`。

**假设输入 2 (跨越多个 DOM 节点的选择):**

* 用户选中了以下 HTML 片段中的 "中间的":
  ```html
  <div>开头的 <span>中间的</span> 结尾</div>
  ```
* `SelectionInDOMTree` 对象，包含跨越 `<span>` 节点的选择范围，作为输入传递给 `AXSelection::FromSelection(const SelectionInDOMTree&, AXSelectionBehavior::kShrinkToValidRange)`。

**预期输出 2:**

* 创建一个 `AXSelection` 对象，其 `anchor_` 和 `focus_` 可能会被调整到包含 "中间的" 的 `<span>` 元素的边界，因为 `kShrinkToValidRange` 会尝试将选择收缩到辅助功能树中有效的对象。 具体取决于辅助功能树的结构，选择可能锚定在 `<span>` 的文本内容的开始和结束位置。

**用户或编程常见的使用错误:**

1. **尝试创建无效的 `AXSelection` 对象:**
   - **错误示例:** 手动构建 `AXSelection` 时，锚点和焦点指向不同的文档。
   - **结果:** `AXSelection::IsValid()` 返回 `false`，后续的 `Select()` 操作会失败。
   - **调试线索:** 检查 `AXSelection` 对象的 `Anchor().ContainerObject()->GetDocument()` 和 `Focus().ContainerObject()->GetDocument()` 是否一致。

2. **错误地使用 `AXSelectionBehavior`:**
   - **错误示例:**  在需要精确映射 DOM 选择到辅助功能树时，使用了 `kShrinkToValidRange`，导致选择范围缩小。
   - **结果:** 辅助功能 API 获取到的选择范围与用户的实际选择不一致。
   - **调试线索:**  理解不同 `AXSelectionBehavior` 的含义，根据具体场景选择合适的行为。

3. **假设 `AXSelection` 对象在 DOM 结构变化后仍然有效:**
   - **错误示例:**  创建一个 `AXSelection` 对象后，DOM 结构发生了改变（例如，节点被删除），然后尝试使用该 `AXSelection` 进行操作。
   - **结果:**  `AXSelection::IsValid()` 可能返回 `false`，或者操作导致崩溃或未定义的行为。
   - **调试线索:** 在进行可能修改 DOM 结构的操作后，重新获取或更新 `AXSelection` 对象。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户交互 (例如，在浏览器中):**
   - **鼠标拖拽选择文本:** 用户用鼠标在一个可编辑的区域（如文本框、网页文本）拖拽以选中一段文本。
   - **键盘操作选择文本:** 用户使用 Shift 键加上方向键来选择文本。
   - **双击/三击选择文本:** 用户双击选中一个词，或三击选中一段文本。
   - **使用辅助技术:** 屏幕阅读器或其他辅助技术可能会发出请求来获取或设置当前的选择。

2. **浏览器事件处理:**
   - 用户的操作会触发浏览器底层的事件（例如，`mousedown`, `mousemove`, `mouseup`, `keydown`, `keyup`）。
   - 浏览器会根据这些事件更新内部的选择状态 (`FrameSelection`)。

3. **辅助功能树更新:**
   - 当选择状态发生变化时，Blink 引擎需要更新辅助功能树以反映这个变化。
   - `ax_selection.cc` 中的代码会被调用，将 DOM 树中的 `FrameSelection` 转换为 `AXSelection` 对象。

4. **`AXSelection` 对象的创建和使用:**
   - `AXSelection::FromCurrentSelection` 等方法会被调用，根据当前的 DOM 选择创建一个 `AXSelection` 对象。
   - 这个 `AXSelection` 对象会被用于更新辅助功能树中相应的选择信息。

5. **辅助技术获取选择信息:**
   - 辅助技术（如屏幕阅读器）可以通过 Chromium 的 Accessibility API 获取当前的选择信息。
   - 这些 API 可能会调用到 `AXSelection::ToString()` 或其他方法来获取选择的文本内容和位置信息。

6. **`AXSelection::Select()` 的调用 (反向操作):**
   - 有时，辅助技术或自动化测试可能会尝试通过 Accessibility API 设置选择。
   - 这会调用 `AXSelection::Select()` 方法，将辅助功能树中的选择同步回 DOM 树，最终导致 `FrameSelection` 的更新，以及可能的 `TextControlElement::SetSelectionRange` 调用。

**调试线索:**

* **断点:** 在 `AXSelection::FromCurrentSelection`, `AXSelection::FromSelection`, `AXSelection::Select`, `AXSelection::IsValid` 等关键方法中设置断点，观察 `AXSelection` 对象的创建和操作过程。
* **日志输出:** 在这些方法中添加 `LOG(INFO)` 或 `DLOG(INFO)` 输出，记录 `AXPosition` 的信息、选择范围等。
* **检查 `FrameSelection`:** 在 `ax_selection.cc` 的调用前后，检查 `FrameSelection` 对象的状态，确认 DOM 树中的选择是否与预期的 `AXSelection` 对象一致。
* **辅助功能检查器:** 使用 Chromium 的辅助功能检查器 (Accessibility Inspector) 查看辅助功能树的结构和选择状态，对比其与 DOM 树的选择状态。
* **事件监听:** 使用 JavaScript 监听 `selectstart` 和 `select` 事件，观察事件触发的时机和参数，验证 `AXSelection::Select()` 是否正确触发了这些事件。

希望以上分析能够帮助你理解 `blink/renderer/modules/accessibility/ax_selection.cc` 的功能和作用。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_selection.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/accessibility/ax_selection.h"

#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/set_selection_options.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"

namespace blink {

namespace {

// TODO(nektar): Add Web tests for this event.
void ScheduleSelectEvent(TextControlElement& text_control) {
  Event* event = Event::CreateBubble(event_type_names::kSelect);
  event->SetTarget(&text_control);
  text_control.GetDocument().EnqueueAnimationFrameEvent(event);
}

// TODO(nektar): Add Web tests for this event.
DispatchEventResult DispatchSelectStart(Node* node) {
  if (!node)
    return DispatchEventResult::kNotCanceled;

  return node->DispatchEvent(
      *Event::CreateCancelableBubble(event_type_names::kSelectstart));
}

}  // namespace

//
// AXSelection::Builder
//

AXSelection::Builder& AXSelection::Builder::SetAnchor(
    const AXPosition& anchor) {
  DCHECK(anchor.IsValid());
  selection_.anchor_ = anchor;
  return *this;
}

AXSelection::Builder& AXSelection::Builder::SetAnchor(const Position& anchor) {
  const auto ax_anchor = AXPosition::FromPosition(anchor);
  DCHECK(ax_anchor.IsValid());
  selection_.anchor_ = ax_anchor;
  return *this;
}

AXSelection::Builder& AXSelection::Builder::SetFocus(const AXPosition& focus) {
  DCHECK(focus.IsValid());
  selection_.focus_ = focus;
  return *this;
}

AXSelection::Builder& AXSelection::Builder::SetFocus(const Position& focus) {
  const auto ax_focus = AXPosition::FromPosition(focus);
  DCHECK(ax_focus.IsValid());
  selection_.focus_ = ax_focus;
  return *this;
}

AXSelection::Builder& AXSelection::Builder::SetSelection(
    const SelectionInDOMTree& selection) {
  if (selection.IsNone())
    return *this;

  selection_.anchor_ = AXPosition::FromPosition(selection.Anchor());
  selection_.focus_ = AXPosition::FromPosition(selection.Focus());
  return *this;
}

const AXSelection AXSelection::Builder::Build() {
  if (!selection_.Anchor().IsValid() || !selection_.Focus().IsValid()) {
    return {};
  }

  const Document* document =
      selection_.Anchor().ContainerObject()->GetDocument();
  DCHECK(document);
  DCHECK(document->IsActive());
  DCHECK(!document->NeedsLayoutTreeUpdate());
  // We don't support selections that span across documents.
  if (selection_.Focus().ContainerObject()->GetDocument() != document) {
    return {};
  }

#if DCHECK_IS_ON()
  selection_.dom_tree_version_ = document->DomTreeVersion();
  selection_.style_version_ = document->StyleVersion();
#endif
  return selection_;
}

//
// AXSelection
//

// static
void AXSelection::ClearCurrentSelection(Document& document) {
  LocalFrame* frame = document.GetFrame();
  if (!frame)
    return;

  FrameSelection& frame_selection = frame->Selection();
  if (!frame_selection.IsAvailable())
    return;

  frame_selection.Clear();
}

// static
AXSelection AXSelection::FromCurrentSelection(
    const Document& document,
    const AXSelectionBehavior selection_behavior) {
  const LocalFrame* frame = document.GetFrame();
  if (!frame)
    return {};

  const FrameSelection& frame_selection = frame->Selection();
  if (!frame_selection.IsAvailable())
    return {};

  return FromSelection(frame_selection.GetSelectionInDOMTree(),
                       selection_behavior);
}

// static
AXSelection AXSelection::FromCurrentSelection(
    const TextControlElement& text_control) {
  const Document& document = text_control.GetDocument();
  AXObjectCache* ax_object_cache = document.ExistingAXObjectCache();
  if (!ax_object_cache)
    return {};

  auto* ax_object_cache_impl = static_cast<AXObjectCacheImpl*>(ax_object_cache);
  const AXObject* ax_text_control = ax_object_cache_impl->Get(&text_control);
  DCHECK(ax_text_control);

  // We can't directly use "text_control.Selection()" because the selection it
  // returns is inside the shadow DOM and it's not anchored to the text field
  // itself.
  const TextAffinity focus_affinity = text_control.Selection().Affinity();
  const TextAffinity anchor_affinity =
      text_control.selectionStart() == text_control.selectionEnd()
          ? focus_affinity
          : TextAffinity::kDownstream;

  const bool is_backward = (text_control.selectionDirection() == "backward");
  const auto ax_anchor = AXPosition::CreatePositionInTextObject(
      *ax_text_control,
      static_cast<int>(is_backward ? text_control.selectionEnd()
                                   : text_control.selectionStart()),
      anchor_affinity);
  const auto ax_focus = AXPosition::CreatePositionInTextObject(
      *ax_text_control,
      static_cast<int>(is_backward ? text_control.selectionStart()
                                   : text_control.selectionEnd()),
      focus_affinity);

  if (!ax_anchor.IsValid() || !ax_focus.IsValid()) {
    return {};
  }

  AXSelection::Builder selection_builder;
  selection_builder.SetAnchor(ax_anchor).SetFocus(ax_focus);
  return selection_builder.Build();
}

// static
AXSelection AXSelection::FromSelection(
    const SelectionInDOMTree& selection,
    const AXSelectionBehavior selection_behavior) {
  if (selection.IsNone())
    return {};
  DCHECK(selection.AssertValid());

  const Position dom_anchor = selection.Anchor();
  const Position dom_focus = selection.Focus();
  const TextAffinity focus_affinity = selection.Affinity();
  const TextAffinity anchor_affinity =
      selection.IsCaret() ? focus_affinity : TextAffinity::kDownstream;

  AXPositionAdjustmentBehavior anchor_adjustment =
      AXPositionAdjustmentBehavior::kMoveRight;
  AXPositionAdjustmentBehavior focus_adjustment =
      AXPositionAdjustmentBehavior::kMoveRight;
  // If the selection is not collapsed, extend or shrink the DOM selection if
  // there is no equivalent selection in the accessibility tree, i.e. if the
  // corresponding endpoints are either ignored or unavailable in the
  // accessibility tree. If the selection is collapsed, move both endpoints to
  // the next valid position in the accessibility tree but do not extend or
  // shrink the selection, because this will result in a non-collapsed selection
  // in the accessibility tree.
  if (!selection.IsCaret()) {
    switch (selection_behavior) {
      case AXSelectionBehavior::kShrinkToValidRange:
        if (selection.IsAnchorFirst()) {
          anchor_adjustment = AXPositionAdjustmentBehavior::kMoveRight;
          focus_adjustment = AXPositionAdjustmentBehavior::kMoveLeft;
        } else {
          anchor_adjustment = AXPositionAdjustmentBehavior::kMoveLeft;
          focus_adjustment = AXPositionAdjustmentBehavior::kMoveRight;
        }
        break;
      case AXSelectionBehavior::kExtendToValidRange:
        if (selection.IsAnchorFirst()) {
          anchor_adjustment = AXPositionAdjustmentBehavior::kMoveLeft;
          focus_adjustment = AXPositionAdjustmentBehavior::kMoveRight;
        } else {
          anchor_adjustment = AXPositionAdjustmentBehavior::kMoveRight;
          focus_adjustment = AXPositionAdjustmentBehavior::kMoveLeft;
        }
        break;
    }
  }

  const auto ax_anchor =
      AXPosition::FromPosition(dom_anchor, anchor_affinity, anchor_adjustment);
  const auto ax_focus =
      AXPosition::FromPosition(dom_focus, focus_affinity, focus_adjustment);

  if (!ax_anchor.IsValid() || !ax_focus.IsValid()) {
    return {};
  }

  AXSelection::Builder selection_builder;
  selection_builder.SetAnchor(ax_anchor).SetFocus(ax_focus);
  return selection_builder.Build();
}

AXSelection::AXSelection() : anchor_(), focus_() {
#if DCHECK_IS_ON()
  dom_tree_version_ = 0;
  style_version_ = 0;
#endif
}

bool AXSelection::IsValid() const {
  if (!anchor_.IsValid() || !focus_.IsValid()) {
    return false;
  }

  // We don't support selections that span across documents.
  if (anchor_.ContainerObject()->GetDocument() !=
      focus_.ContainerObject()->GetDocument()) {
    return false;
  }

  //
  // The following code checks if a text position in a text control is valid.
  // Since the contents of a text control are implemented using user agent
  // shadow DOM, we want to prevent users from selecting across the shadow DOM
  // boundary.
  //
  // TODO(nektar): Generalize this logic to adjust user selection if it crosses
  // disallowed shadow DOM boundaries such as user agent shadow DOM, editing
  // boundaries, replaced elements, CSS user-select, etc.
  //

  if (anchor_.IsTextPosition() &&
      anchor_.ContainerObject()->IsAtomicTextField() &&
      !(anchor_.ContainerObject() == focus_.ContainerObject() &&
        focus_.IsTextPosition() &&
        focus_.ContainerObject()->IsAtomicTextField())) {
    return false;
  }

  if (focus_.IsTextPosition() &&
      focus_.ContainerObject()->IsAtomicTextField() &&
      !(anchor_.ContainerObject() == focus_.ContainerObject() &&
        anchor_.IsTextPosition() &&
        anchor_.ContainerObject()->IsAtomicTextField())) {
    return false;
  }

  DCHECK(!anchor_.ContainerObject()->GetDocument()->NeedsLayoutTreeUpdate());
#if DCHECK_IS_ON()
  DCHECK_EQ(anchor_.ContainerObject()->GetDocument()->DomTreeVersion(),
            dom_tree_version_);
  DCHECK_EQ(anchor_.ContainerObject()->GetDocument()->StyleVersion(),
            style_version_);
#endif  // DCHECK_IS_ON()
  return true;
}

const SelectionInDOMTree AXSelection::AsSelection(
    const AXSelectionBehavior selection_behavior) const {
  if (!IsValid())
    return {};

  AXPositionAdjustmentBehavior anchor_adjustment =
      AXPositionAdjustmentBehavior::kMoveLeft;
  AXPositionAdjustmentBehavior focus_adjustment =
      AXPositionAdjustmentBehavior::kMoveLeft;
  switch (selection_behavior) {
    case AXSelectionBehavior::kShrinkToValidRange:
      if (anchor_ < focus_) {
        anchor_adjustment = AXPositionAdjustmentBehavior::kMoveRight;
        focus_adjustment = AXPositionAdjustmentBehavior::kMoveLeft;
      } else if (anchor_ > focus_) {
        anchor_adjustment = AXPositionAdjustmentBehavior::kMoveLeft;
        focus_adjustment = AXPositionAdjustmentBehavior::kMoveRight;
      }
      break;
    case AXSelectionBehavior::kExtendToValidRange:
      if (anchor_ < focus_) {
        anchor_adjustment = AXPositionAdjustmentBehavior::kMoveLeft;
        focus_adjustment = AXPositionAdjustmentBehavior::kMoveRight;
      } else if (anchor_ > focus_) {
        anchor_adjustment = AXPositionAdjustmentBehavior::kMoveRight;
        focus_adjustment = AXPositionAdjustmentBehavior::kMoveLeft;
      }
      break;
  }

  const auto dom_anchor = anchor_.ToPositionWithAffinity(anchor_adjustment);
  const auto dom_focus = focus_.ToPositionWithAffinity(focus_adjustment);
  SelectionInDOMTree::Builder selection_builder;
  selection_builder.SetBaseAndExtent(dom_anchor.GetPosition(),
                                     dom_focus.GetPosition());
  if (focus_.IsTextPosition()) {
    selection_builder.SetAffinity(focus_.Affinity());
  }
  return selection_builder.Build();
}

void AXSelection::UpdateSelectionIfNecessary() {
  Document* document = anchor_.ContainerObject()->GetDocument();
  if (!document)
    return;

  LocalFrameView* view = document->View();
  if (!view || !view->LayoutPending())
    return;

  document->UpdateStyleAndLayout(DocumentUpdateReason::kSelection);
#if DCHECK_IS_ON()
  anchor_.dom_tree_version_ = focus_.dom_tree_version_ = dom_tree_version_ =
      document->DomTreeVersion();
  anchor_.style_version_ = focus_.style_version_ = style_version_ =
      document->StyleVersion();
#endif  // DCHECK_IS_ON()
}

bool AXSelection::Select(const AXSelectionBehavior selection_behavior) {
  if (!IsValid()) {
    // By the time the selection action gets here, content could have
    // changed from the content the action was initially prepared for.
    return false;
  }

  std::optional<AXSelection::TextControlSelection> text_control_selection =
      AsTextControlSelection();

  // We need to make sure we only go into here if we're dealing with a position
  // in the atomic text field. This is because the offsets are being assumed
  // to be on the atomic text field, and not on the descendant inline text
  // boxes.
  if (text_control_selection.has_value() &&
      *anchor_.ContainerObject() ==
          *anchor_.ContainerObject()->GetAtomicTextFieldAncestor() &&
      *focus_.ContainerObject() ==
          *focus_.ContainerObject()->GetAtomicTextFieldAncestor()) {
    DCHECK_LE(text_control_selection->start, text_control_selection->end);
    TextControlElement& text_control = ToTextControl(
        *anchor_.ContainerObject()->GetAtomicTextFieldAncestor()->GetNode());
    if (!text_control.SetSelectionRange(text_control_selection->start,
                                        text_control_selection->end,
                                        text_control_selection->direction)) {
      return false;
    }

    // TextControl::SetSelectionRange deliberately does not set focus. But if
    // we're updating the selection, the text control should be focused.
    ScheduleSelectEvent(text_control);
    text_control.Focus(FocusParams(FocusTrigger::kUserGesture));
    return true;
  }

  const SelectionInDOMTree old_selection = AsSelection(selection_behavior);
  DCHECK(old_selection.AssertValid());
  Document* document = old_selection.Anchor().GetDocument();
  if (!document) {
    // By the time the selection action gets here, content could have
    // changed from the content the action was initially prepared for.
    return false;
  }

  LocalFrame* frame = document->GetFrame();
  if (!frame) {
    NOTREACHED();
  }

  FrameSelection& frame_selection = frame->Selection();
  if (!frame_selection.IsAvailable())
    return false;

  // See the following section in the Selection API Specification:
  // https://w3c.github.io/selection-api/#selectstart-event
  if (DispatchSelectStart(old_selection.Anchor().ComputeContainerNode()) !=
      DispatchEventResult::kNotCanceled) {
    return false;
  }

  UpdateSelectionIfNecessary();
  if (!IsValid())
    return false;

  // Dispatching the "selectstart" event could potentially change the document
  // associated with the current frame.
  if (!frame_selection.IsAvailable())
    return false;

  // Re-retrieve the SelectionInDOMTree in case a DOM mutation took place.
  // That way it will also have the updated DOM tree and Style versions,
  // and the SelectionTemplate checks for each won't fail.
  const SelectionInDOMTree selection = AsSelection(selection_behavior);

  SetSelectionOptions::Builder options_builder;
  options_builder.SetIsDirectional(true)
      .SetShouldCloseTyping(true)
      .SetShouldClearTypingStyle(true)
      .SetSetSelectionBy(SetSelectionBy::kUser);
  frame_selection.SetSelectionForAccessibility(selection,
                                               options_builder.Build());
  return true;
}

String AXSelection::ToString() const {
  String prefix = IsValid() ? "" : "Invalid ";
  return prefix + "AXSelection from " + Anchor().ToString() + " to " +
         Focus().ToString();
}

std::optional<AXSelection::TextControlSelection>
AXSelection::AsTextControlSelection() const {
  if (!IsValid() || !anchor_.IsTextPosition() || !focus_.IsTextPosition() ||
      anchor_.ContainerObject() != focus_.ContainerObject()) {
    return {};
  }

  const AXObject* text_control =
      anchor_.ContainerObject()->GetAtomicTextFieldAncestor();
  if (!text_control)
    return {};

  DCHECK(IsTextControl(text_control->GetNode()));

  if (anchor_ <= focus_) {
    return TextControlSelection(anchor_.TextOffset(), focus_.TextOffset(),
                                kSelectionHasForwardDirection);
  }
  return TextControlSelection(focus_.TextOffset(), anchor_.TextOffset(),
                              kSelectionHasBackwardDirection);
}

bool operator==(const AXSelection& a, const AXSelection& b) {
  DCHECK(a.IsValid() && b.IsValid());
  return a.Anchor() == b.Anchor() && a.Focus() == b.Focus();
}

bool operator!=(const AXSelection& a, const AXSelection& b) {
  return !(a == b);
}

std::ostream& operator<<(std::ostream& ostream, const AXSelection& selection) {
  return ostream << selection.ToString().Utf8();
}

}  // namespace blink

"""

```