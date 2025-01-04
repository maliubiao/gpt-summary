Response:
The user wants to understand the functionality of the `HTMLDialogElement.cc` file in the Chromium Blink engine. I need to break down its responsibilities and explain how it interacts with web technologies like JavaScript, HTML, and CSS.

Here's a plan:

1. **Identify the core purpose:** The file implements the behavior of the `<dialog>` HTML element.
2. **List key functionalities:**  Based on the code, I'll extract the main actions the `HTMLDialogElement` class handles (showing, closing, managing focus, handling modal behavior, etc.).
3. **Explain interaction with JavaScript:**  Describe how JavaScript APIs are used to control the dialog (e.g., `show()`, `showModal()`, `close()`).
4. **Explain interaction with HTML:** Detail how HTML attributes like `open` and `closedby` affect the dialog's state and behavior.
5. **Explain interaction with CSS:** Describe how CSS pseudo-classes like `:modal` are used to style modal dialogs and the role of the backdrop.
6. **Provide examples of logical reasoning:** Illustrate scenarios and expected outcomes based on function calls and attribute changes.
7. **Highlight common user/programming errors:** Point out potential pitfalls when using the `<dialog>` element.
这个文件 `blink/renderer/core/html/html_dialog_element.cc` 是 Chromium Blink 渲染引擎中实现 HTML `<dialog>` 元素的核心代码。它定义了 `<dialog>` 元素的行为和功能。

以下是它的一些主要功能：

1. **显示和关闭对话框:**
   - `show()`:  以非模态方式显示对话框。
   - `showModal()`: 以模态方式显示对话框，阻止用户与页面其他部分交互。
   - `close()`: 关闭对话框。
   - `requestClose()`: 请求关闭对话框，用于轻量级关闭 (light dismiss) 机制。

2. **管理对话框的打开状态:**
   - 通过 `open` HTML 属性来表示对话框是否打开。
   - 维护一个全局列表 `GetDocument().AllOpenDialogs()` 来跟踪所有打开的对话框。

3. **处理模态行为:**
   - `is_modal_` 成员变量跟踪对话框是否以模态方式打开。
   - 当模态对话框打开时，会将其添加到顶层 (top layer)，并使其成为 `document.ActiveModalDialog()`。
   - 模态对话框会阻止与页面其他部分的交互，并可能渲染一个遮罩层 (backdrop)。

4. **管理焦点:**
   - `SetFocusForDialogLegacy()` 和 `SetFocusForDialog()`:  负责在对话框打开时将焦点设置到对话框内的第一个可聚焦元素。如果对话框内没有可聚焦元素，则焦点会设置到对话框本身。
   - `previously_focused_element_`:  存储在对话框打开前拥有焦点的元素，以便在对话框关闭后将焦点返回。

5. **处理轻量级关闭 (Light Dismiss):**
   - `HandleDialogLightDismiss()`:  处理点击模态对话框外部区域的事件，从而关闭对话框。
   - `ClosedBy()` 和 `closedBy` 属性：指示对话框是如何关闭的 (例如，通过脚本调用 `close()`，还是通过轻量级关闭)。
   - `close_watcher_`:  一个 `CloseWatcher` 对象，用于监听来自浏览器的关闭请求（例如，按下 Esc 键）。

6. **处理表单提交:**
   - 虽然代码中没有直接体现表单提交的逻辑，但 `<dialog>` 元素可以与 `<form>` 元素一起使用，用于收集用户输入。当 `<form>` 提交时，可以设置对话框的返回值。

7. **触发事件:**
   - 触发 `toggle` 事件 (如果 `DialogElementToggleEventsEnabled` 功能启用) 来通知对话框状态的变化。
   - 触发 `close` 事件，表示对话框已关闭。
   - 触发 `cancel` 事件，通常由用户按下 Esc 键触发（通过 `CloseWatcher`）。

8. **与 `invokeaction` 机制集成:**
   - `HandleCommandInternal()`: 处理通过 `invokeaction` 属性触发的与对话框相关的命令，例如 `showModal` 和 `close`。

9. **辅助功能 (Accessibility):**
   - 当模态对话框打开或关闭时，会调用 `document.RefreshAccessibilityTree()` 来更新辅助功能树，确保屏幕阅读器等辅助技术能够正确理解页面结构。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    - **示例:**  JavaScript 代码可以使用 `dialogElem.show()` 来显示一个 ID 为 `myDialog` 的对话框：
      ```javascript
      const dialogElem = document.getElementById('myDialog');
      dialogElem.show();
      ```
    - **示例:** 可以使用 `dialogElem.close('submitted')` 关闭对话框并设置返回值：
      ```javascript
      dialogElem.close('submitted');
      console.log(dialogElem.returnValue); // 输出 "submitted"
      ```
    - **示例:**  监听 `close` 事件：
      ```javascript
      dialogElem.addEventListener('close', () => {
        console.log('Dialog closed with return value:', dialogElem.returnValue);
      });
      ```

* **HTML:**
    - **示例:** 使用 `<dialog>` 标签创建对话框：
      ```html
      <dialog id="myDialog">
        <p>这是一个对话框。</p>
        <button onclick="document.getElementById('myDialog').close('cancel')">取消</button>
        <button onclick="document.getElementById('myDialog').close('ok')">确定</button>
      </dialog>
      ```
    - **示例:** 使用 `open` 属性立即显示非模态对话框 (不推荐，通常通过 JavaScript 控制)：
      ```html
      <dialog open>这是一个默认打开的对话框。</dialog>
      ```
    - **示例:** 使用 `closedby` 属性 (需要启用 `HTMLDialogLightDismissEnabled` 特性) 来控制轻量级关闭的行为：
      ```html
      <dialog id="modalDialog" closedby="any">
        <p>这是一个模态对话框，点击外部区域可以关闭。</p>
      </dialog>
      ```

* **CSS:**
    - **示例:** 可以使用 CSS 来设置对话框的样式：
      ```css
      dialog {
        border: 1px solid black;
        padding: 20px;
        background-color: white;
      }
      ```
    - **示例:**  使用 `::backdrop` 伪元素来设置模态对话框的遮罩层样式：
      ```css
      dialog::backdrop {
        background-color: rgba(0, 0, 0, 0.5);
      }
      ```
    - **示例:**  使用 `:modal` 伪类来为模态对话框应用特定的样式：
      ```css
      dialog:modal {
        /* 模态对话框的特定样式 */
      }
      ```

**逻辑推理的举例 (假设输入与输出):**

假设有一个 ID 为 `myModal` 的模态对话框：

* **假设输入:** JavaScript 调用 `document.getElementById('myModal').showModal();`
* **输出:**
    - 对话框会显示在屏幕上。
    - 页面上的其他内容会变为不可交互状态。
    - 可能渲染一个半透明的遮罩层覆盖在页面其他内容之上。
    - 焦点会移动到对话框内的第一个可聚焦元素。
    - `document.ActiveModalDialog()` 将返回该对话框元素。

* **假设输入:** 用户点击模态对话框外部的遮罩层 (并且 `closedby` 属性设置为允许轻量级关闭)。
* **输出:**
    - 对话框会关闭。
    - 焦点会返回到对话框打开前拥有焦点的元素。
    - 会触发 `close` 事件。

* **假设输入:**  在对话框打开后，JavaScript 代码执行 `dialogElem.setAttribute('open', '');`  (并且 `DialogCloseWhenOpenRemovedEnabled` 功能启用)。
* **输出:**
    - 控制台会输出一个警告信息，建议使用 `close()` 方法。
    - 对话框会被关闭。

**用户或编程常见的使用错误举例：**

1. **尝试在非模态对话框打开时调用 `showModal()`:**
   - **错误:**  这样做会导致一个 `InvalidStateError` 异常。
   - **原因:**  一个对话框不能同时以模态和非模态方式打开。

2. **忘记处理 `close` 事件:**
   - **错误:**  关闭对话框后，可能需要执行一些清理或后续操作，如果没有监听 `close` 事件，这些操作就不会发生。
   - **示例:**  用户提交表单后关闭对话框，但没有监听 `close` 事件来处理表单数据。

3. **在模态对话框打开时尝试与页面其他部分交互:**
   - **错误:**  模态对话框旨在阻止与页面其他部分的交互，用户无法直接操作背景内容。
   - **原因:**  模态对话框会捕获用户输入。

4. **在未连接到文档的元素上调用 `showModal()`:**
   - **错误:**  会抛出一个 `InvalidStateError` 异常。
   - **原因:**  模态对话框需要在文档的上下文中才能正确显示和管理。

5. **在已经作为 Popover 打开的元素上调用 `showModal()`:**
   - **错误:**  会抛出一个 `InvalidStateError` 异常。
   - **原因:**  一个元素不能同时作为模态对话框和 Popover 打开。

理解 `html_dialog_element.cc` 的功能对于理解浏览器如何实现和渲染 `<dialog>` 元素至关重要，这对于前端开发人员调试和优化涉及对话框的 Web 应用很有帮助。

Prompt: 
```
这是目录为blink/renderer/core/html/html_dialog_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/html/html_dialog_element.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_focus_options.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/events/pointer_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

// static
void HTMLDialogElement::SetFocusForDialogLegacy(HTMLDialogElement* dialog) {
  Element* control = nullptr;
  Node* next = nullptr;

  if (!dialog->isConnected())
    return;

  auto& document = dialog->GetDocument();
  dialog->previously_focused_element_ = document.FocusedElement();

  // TODO(kochi): How to find focusable element inside Shadow DOM is not
  // currently specified.  This may change at any time.
  // See crbug/383230 and https://github.com/whatwg/html/issues/2393 .
  for (Node* node = FlatTreeTraversal::FirstChild(*dialog); node; node = next) {
    next = IsA<HTMLDialogElement>(*node)
               ? FlatTreeTraversal::NextSkippingChildren(*node, dialog)
               : FlatTreeTraversal::Next(*node, dialog);

    auto* element = DynamicTo<Element>(node);
    if (!element)
      continue;
    if (element->IsAutofocusable() && element->IsFocusable()) {
      control = element;
      break;
    }
    if (!control && element->IsFocusable())
      control = element;
  }
  if (!control)
    control = dialog;

  // 3. Run the focusing steps for control.
  if (control->IsFocusable())
    control->Focus();
  else
    document.ClearFocusedElement();

  // 4. Let topDocument be the active document of control's node document's
  // browsing context's top-level browsing context.
  // 5. If control's node document's origin is not the same as the origin of
  // topDocument, then return.
  Document& doc = control->GetDocument();
  if (!doc.IsActive())
    return;
  if (!doc.IsInMainFrame() &&
      !doc.TopFrameOrigin()->CanAccess(
          doc.GetExecutionContext()->GetSecurityOrigin())) {
    return;
  }

  // 6. Empty topDocument's autofocus candidates.
  // 7. Set topDocument's autofocus processed flag to true.
  doc.TopDocument().FinalizeAutofocus();
}

static void InertSubtreesChanged(Document& document,
                                 Element* old_modal_dialog) {
  Element* new_modal_dialog = document.ActiveModalDialog();
  if (old_modal_dialog == new_modal_dialog)
    return;

  // Update IsInert() flags.
  const StyleChangeReasonForTracing& reason =
      StyleChangeReasonForTracing::Create(style_change_reason::kDialog);
  if (old_modal_dialog && new_modal_dialog) {
    old_modal_dialog->SetNeedsStyleRecalc(kLocalStyleChange, reason);
    new_modal_dialog->SetNeedsStyleRecalc(kLocalStyleChange, reason);
  } else {
    if (Element* root = document.documentElement())
      root->SetNeedsStyleRecalc(kLocalStyleChange, reason);
    if (Element* fullscreen = Fullscreen::FullscreenElementFrom(document))
      fullscreen->SetNeedsStyleRecalc(kLocalStyleChange, reason);
  }

  // When a modal dialog opens or closes, nodes all over the accessibility
  // tree can change inertness which means they must be added or removed from
  // the tree. The most foolproof way is to clear the entire tree and rebuild
  // it, though a more clever way is probably possible.
  document.RefreshAccessibilityTree();
}

HTMLDialogElement::HTMLDialogElement(Document& document)
    : HTMLElement(html_names::kDialogTag, document),
      is_modal_(false),
      return_value_(""),
      request_close_return_value_(""),
      previously_focused_element_(nullptr) {
  UseCounter::Count(document, WebFeature::kDialogElement);
}

void HTMLDialogElement::close(const String& return_value,
                              bool ignore_open_attribute) {
  // https://html.spec.whatwg.org/C/#close-the-dialog
  if (is_closing_) {
    return;
  }
  base::AutoReset<bool> reset_close(&is_closing_, true);

  if (!ignore_open_attribute && !IsOpen()) {
    return;
  }

  Document& document = GetDocument();
  HTMLDialogElement* old_modal_dialog = document.ActiveModalDialog();

  DispatchToggleEvents(/*opening=*/false);
  if (!ignore_open_attribute && !IsOpen()) {
    return;
  }
  SetBooleanAttribute(html_names::kOpenAttr, false);
  bool was_modal = IsModal();
  SetIsModal(false);
  GetDocument().AllOpenDialogs().erase(this);

  // If this dialog is open as a non-modal dialog and open as a popover at the
  // same time, then we shouldn't remove it from the top layer because it is
  // still open as a popover.
  if (was_modal) {
    document.ScheduleForTopLayerRemoval(this,
                                        Document::TopLayerReason::kDialog);
  }
  InertSubtreesChanged(document, old_modal_dialog);

  if (!return_value.IsNull())
    return_value_ = return_value;

  ScheduleCloseEvent();

  // We should call focus() last since it will fire a focus event which could
  // modify this element.
  if (previously_focused_element_) {
    FocusOptions* focus_options = FocusOptions::Create();
    focus_options->setPreventScroll(true);
    Element* previously_focused_element = previously_focused_element_;
    previously_focused_element_ = nullptr;

    bool descendant_is_focused = GetDocument().FocusedElement() &&
                                 FlatTreeTraversal::IsDescendantOf(
                                     *GetDocument().FocusedElement(), *this);
    if (previously_focused_element && (was_modal || descendant_is_focused)) {
      previously_focused_element->Focus(FocusParams(
          SelectionBehaviorOnFocus::kNone, mojom::blink::FocusType::kScript,
          nullptr, focus_options));
    }
  }

  if (close_watcher_) {
    close_watcher_->destroy();
    close_watcher_ = nullptr;
  }
}

void HTMLDialogElement::requestClose(const String& return_value,
                                     ExceptionState& exception_state) {
  CHECK(RuntimeEnabledFeatures::HTMLDialogLightDismissEnabled());
  if (!IsOpen()) {
    return;
  }
  if (ClosedBy() == ClosedByState::kNone) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "To use requestClose, the dialog's closedBy state must not be 'none'.");
    return;
  }
  CHECK(close_watcher_);
  request_close_return_value_ = return_value;
  close_watcher_->requestClose();
  SetCloseWatcherEnabledState();
}

ClosedByState HTMLDialogElement::ClosedBy() const {
  CHECK(RuntimeEnabledFeatures::HTMLDialogLightDismissEnabled());
  auto attribute_value =
      FastGetAttribute(html_names::kClosedbyAttr).LowerASCII();
  if (attribute_value == keywords::kAny) {
    return ClosedByState::kAny;
  } else if (attribute_value == keywords::kNone) {
    return ClosedByState::kNone;
  } else if (attribute_value == keywords::kCloserequest) {
    return ClosedByState::kCloseRequest;
  } else {
    // The closedby attribute's invalid value default and missing value default
    // are both the Auto state. The Auto state matches closerequest when the
    // element is modal; otherwise none.
    return IsModal() ? ClosedByState::kCloseRequest : ClosedByState::kNone;
  }
}

String HTMLDialogElement::closedBy() const {
  CHECK(RuntimeEnabledFeatures::HTMLDialogLightDismissEnabled());
  switch (ClosedBy()) {
    case ClosedByState::kAny:
      return keywords::kAny;
    case ClosedByState::kCloseRequest:
      return keywords::kCloserequest;
    case ClosedByState::kNone:
      return keywords::kNone;
  }
}

void HTMLDialogElement::setClosedBy(const String& new_value) {
  CHECK(RuntimeEnabledFeatures::HTMLDialogLightDismissEnabled());
  setAttribute(html_names::kClosedbyAttr, AtomicString(new_value));
}

namespace {

const HTMLDialogElement* FindNearestDialog(const Node& target_node,
                                           const PointerEvent& pointer_event) {
  // First check if this is a click on a dialog's backdrop, which will show up
  // as a click on the dialog directly.
  if (auto* dialog = DynamicTo<HTMLDialogElement>(target_node);
      dialog && dialog->IsOpen() && dialog->IsModal()) {
    DOMRect* dialog_rect =
        const_cast<HTMLDialogElement*>(dialog)->GetBoundingClientRect();
    if (!dialog_rect->IsPointInside(pointer_event.clientX(),
                                    pointer_event.clientY())) {
      CHECK(dialog->GetPseudoElement(kPseudoIdBackdrop));
      return nullptr;  // Return nullptr for a backdrop click.
    }
  }
  // Otherwise, walk up the tree looking for an open dialog.
  for (const Node* node = &target_node; node;
       node = FlatTreeTraversal::Parent(*node)) {
    if (auto* dialog = DynamicTo<HTMLDialogElement>(node);
        dialog && dialog->IsOpen()) {
      return dialog;
    }
  }
  return nullptr;
}

}  // namespace

// static
// https://html.spec.whatwg.org/interactive-elements.html#light-dismiss-open-dialogs
void HTMLDialogElement::HandleDialogLightDismiss(const Event& event,
                                                 const Node& target_node) {
  if (!RuntimeEnabledFeatures::HTMLDialogLightDismissEnabled()) {
    return;
  }
  CHECK(event.isTrusted());
  auto& document = target_node.GetDocument();
  if (document.AllOpenDialogs().empty()) {
    return;
  }

  const PointerEvent* pointer_event = DynamicTo<PointerEvent>(event);
  if (!pointer_event) {
    return;
  }
  // PointerEventManager will call this function before actually dispatching
  // the event.
  CHECK(!event.HasEventPath());
  CHECK_EQ(Event::PhaseType::kNone, event.eventPhase());
  const AtomicString& event_type = event.type();
  const HTMLDialogElement* ancestor_dialog =
      FindNearestDialog(target_node, *pointer_event);
  if (event_type == event_type_names::kPointerdown) {
    document.SetDialogPointerdownTarget(ancestor_dialog);
  } else if (event_type == event_type_names::kPointerup) {
    // See the comment in HTMLElement::HandlePopoverLightDismiss() for details
    // on why this works the way it does.
    bool same_target = ancestor_dialog == document.DialogPointerdownTarget();
    document.SetDialogPointerdownTarget(nullptr);
    if (!same_target) {
      return;
    }
    // Make a copy of the list, because closed dialogs will be removed as we go.
    VectorOf<HTMLDialogElement> dialog_list{document.AllOpenDialogs()};
    for (auto index = dialog_list.size(); index-- != 0;) {
      auto& dialog = dialog_list.at(index);
      if (dialog != ancestor_dialog &&
          dialog->ClosedBy() == ClosedByState::kAny) {
        dialog->requestClose(String(), ASSERT_NO_EXCEPTION);
      }
    }
  }
}

bool HTMLDialogElement::IsValidBuiltinCommand(HTMLElement& invoker,
                                              CommandEventType command) {
  return HTMLElement::IsValidBuiltinCommand(invoker, command) ||
         command == CommandEventType::kShowModal ||
         command == CommandEventType::kClose;
}

bool HTMLDialogElement::HandleCommandInternal(HTMLElement& invoker,
                                              CommandEventType command) {
  CHECK(IsValidBuiltinCommand(invoker, command));

  if (HTMLElement::HandleCommandInternal(invoker, command)) {
    return true;
  }

  // Dialog actions conflict with popovers. We should avoid trying do anything
  // with a dialog that is an open popover.
  if (HasPopoverAttribute() && popoverOpen()) {
    AddConsoleMessage(mojom::blink::ConsoleMessageSource::kOther,
                      mojom::blink::ConsoleMessageLevel::kError,
                      "Dialog invokeactions are ignored on open popovers.");
    return false;
  }

  bool open = IsOpen();

  if (command == CommandEventType::kClose) {
    if (open) {
      close();
      return true;
    } else {
      AddConsoleMessage(
          mojom::blink::ConsoleMessageSource::kOther,
          mojom::blink::ConsoleMessageLevel::kWarning,
          "A closing invokeaction attempted to close an already closed Dialog");
    }
  } else if (command == CommandEventType::kShowModal) {
    if (isConnected() && !open) {
      showModal(ASSERT_NO_EXCEPTION);
      return true;
    } else {
      AddConsoleMessage(
          mojom::blink::ConsoleMessageSource::kOther,
          mojom::blink::ConsoleMessageLevel::kWarning,
          "An invokeaction attempted to open an already open Dialog as modal");
    }
  }

  return false;
}

void HTMLDialogElement::SetIsModal(bool is_modal) {
  if (is_modal != is_modal_)
    PseudoStateChanged(CSSSelector::kPseudoModal);
  is_modal_ = is_modal;
}

void HTMLDialogElement::ScheduleCloseEvent() {
  Event* event = Event::Create(event_type_names::kClose);
  event->SetTarget(this);
  GetDocument().EnqueueAnimationFrameEvent(event);
}

void HTMLDialogElement::show(ExceptionState& exception_state) {
  if (IsOpen()) {
    if (IsModal()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "The dialog is already open as a modal dialog, and therefore "
          "cannot be opened as a non-modal dialog.");
    }
    return;
  }

  if (!DispatchToggleEvents(/*opening=*/true)) {
    return;
  }
  SetBooleanAttribute(html_names::kOpenAttr, true);
  DCHECK(!GetDocument().AllOpenDialogs().Contains(this));
  GetDocument().AllOpenDialogs().insert(this);

  if (RuntimeEnabledFeatures::HTMLDialogLightDismissEnabled()) {
    CreateCloseWatcher();
  }

  // The layout must be updated here because setFocusForDialog calls
  // Element::isFocusable, which requires an up-to-date layout.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);

  // Top layer elements like dialogs and fullscreen elements can be nested
  // inside popovers.
  auto* hide_until = HTMLElement::TopLayerElementPopoverAncestor(
      *this, TopLayerElementType::kDialog);
  HTMLElement::HideAllPopoversUntil(
      hide_until, GetDocument(), HidePopoverFocusBehavior::kNone,
      HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions);

  if (RuntimeEnabledFeatures::DialogNewFocusBehaviorEnabled()) {
    SetFocusForDialog();
  } else {
    SetFocusForDialogLegacy(this);
  }
}

bool HTMLDialogElement::IsKeyboardFocusable(
    UpdateBehavior update_behavior) const {
  if (!IsFocusable(update_behavior)) {
    return false;
  }
  // This handles cases such as <dialog tabindex=0>, <dialog contenteditable>,
  // etc.
  return Element::SupportsFocus(update_behavior) !=
             FocusableState::kNotFocusable &&
         GetIntegralAttribute(html_names::kTabindexAttr, 0) >= 0;
}

class DialogCloseWatcherEventListener : public NativeEventListener {
 public:
  explicit DialogCloseWatcherEventListener(HTMLDialogElement* dialog)
      : dialog_(dialog) {}

  void Invoke(ExecutionContext*, Event* event) override {
    if (!dialog_)
      return;
    if (event->type() == event_type_names::kCancel)
      dialog_->CloseWatcherFiredCancel(event);
    if (event->type() == event_type_names::kClose)
      dialog_->CloseWatcherFiredClose();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(dialog_);
    NativeEventListener::Trace(visitor);
  }

 private:
  WeakMember<HTMLDialogElement> dialog_;
};

void HTMLDialogElement::SetCloseWatcherEnabledState() {
  CHECK(RuntimeEnabledFeatures::HTMLDialogLightDismissEnabled());
  if (!IsOpen()) {
    return;
  }
  CHECK(close_watcher_);
  ClosedByState closed_by = ClosedBy();
  close_watcher_->setEnabled(closed_by != ClosedByState::kNone);
}

void HTMLDialogElement::CreateCloseWatcher() {
  CHECK(!close_watcher_);
  LocalDOMWindow* window = GetDocument().domWindow();
  if (!window) {
    return;
  }
  CHECK(IsOpen());
  close_watcher_ = CloseWatcher::Create(*window);
  if (!close_watcher_) {
    return;
  }
  if (RuntimeEnabledFeatures::HTMLDialogLightDismissEnabled()) {
    SetCloseWatcherEnabledState();
  }
  auto* event_listener =
      MakeGarbageCollected<DialogCloseWatcherEventListener>(this);
  close_watcher_->addEventListener(event_type_names::kClose, event_listener);
  close_watcher_->addEventListener(event_type_names::kCancel, event_listener);
}

void HTMLDialogElement::showModal(ExceptionState& exception_state) {
  if (IsOpen()) {
    if (!IsModal()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "The dialog is already open as a non-modal dialog, and therefore "
          "cannot be opened as a modal dialog.");
    }
    return;
  }
  if (!isConnected()) {
    return exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The element is not in a Document.");
  }
  if (HasPopoverAttribute() && popoverOpen()) {
    return exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The dialog is already open as a Popover, and therefore cannot be "
        "opened as a modal dialog.");
  }
  if (!GetDocument().IsActive() &&
      RuntimeEnabledFeatures::TopLayerInactiveDocumentExceptionsEnabled()) {
    return exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Invalid for dialogs within documents that are not fully active.");
  }
  if (!DispatchToggleEvents(/*opening=*/true, /*asModal=*/true)) {
    return;
  }

  Document& document = GetDocument();
  HTMLDialogElement* old_modal_dialog = document.ActiveModalDialog();

  // See comment in |Fullscreen::RequestFullscreen|.
  if (Fullscreen::IsInFullscreenElementStack(*this)) {
    UseCounter::Count(document,
                      WebFeature::kShowModalForElementInFullscreenStack);
  }

  document.AddToTopLayer(this);
  SetBooleanAttribute(html_names::kOpenAttr, true);
  SetIsModal(true);
  DCHECK(!GetDocument().AllOpenDialogs().Contains(this));
  GetDocument().AllOpenDialogs().insert(this);

  // Refresh the AX cache first, because most of it is changing.
  InertSubtreesChanged(document, old_modal_dialog);
  document.UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);

  CreateCloseWatcher();

  // Proposed new behavior: top layer elements like dialogs and fullscreen
  // elements can be nested inside popovers.
  // Old/existing behavior: showing a modal dialog or fullscreen
  // element should hide all open popovers.
  auto* hide_until = HTMLElement::TopLayerElementPopoverAncestor(
      *this, TopLayerElementType::kDialog);
  HTMLElement::HideAllPopoversUntil(
      hide_until, document, HidePopoverFocusBehavior::kNone,
      HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions);

  if (RuntimeEnabledFeatures::DialogNewFocusBehaviorEnabled()) {
    SetFocusForDialog();
  } else {
    SetFocusForDialogLegacy(this);
  }
}

void HTMLDialogElement::RemovedFrom(ContainerNode& insertion_point) {
  Document& document = GetDocument();
  HTMLDialogElement* old_modal_dialog = document.ActiveModalDialog();
  HTMLElement::RemovedFrom(insertion_point);
  InertSubtreesChanged(document, old_modal_dialog);

  if (GetDocument().StatePreservingAtomicMoveInProgress()) {
    return;
  }

  SetIsModal(false);

  if (close_watcher_) {
    close_watcher_->destroy();
    close_watcher_ = nullptr;
  }
}

void HTMLDialogElement::CloseWatcherFiredCancel(Event* close_watcher_event) {
  // https://wicg.github.io/close-watcher/#patch-dialog cancelAction

  Event* dialog_event = close_watcher_event->cancelable()
                            ? Event::CreateCancelable(event_type_names::kCancel)
                            : Event::Create(event_type_names::kCancel);
  DispatchEvent(*dialog_event);
  if (dialog_event->defaultPrevented())
    close_watcher_event->preventDefault();
  dialog_event->SetDefaultHandled();
}

void HTMLDialogElement::CloseWatcherFiredClose() {
  // https://wicg.github.io/close-watcher/#patch-dialog closeAction

  close(request_close_return_value_);
}

// https://html.spec.whatwg.org#dialog-focusing-steps
void HTMLDialogElement::SetFocusForDialog() {
  previously_focused_element_ = GetDocument().FocusedElement();

  Element* control = GetFocusDelegate(/*autofocus_only=*/false);
  if (IsAutofocusable()) {
    control = this;
  }
  if (!control) {
    control = this;
  }

  if (control->IsFocusable()) {
    control->Focus();
  } else if (IsModal()) {
    control->GetDocument().ClearFocusedElement();
  }

  // 4. Let topDocument be the active document of control's node document's
  // browsing context's top-level browsing context.
  // 5. If control's node document's origin is not the same as the origin of
  // topDocument, then return.
  Document& doc = control->GetDocument();
  if (!doc.IsActive())
    return;
  if (!doc.IsInMainFrame() &&
      !doc.TopFrameOrigin()->CanAccess(
          doc.GetExecutionContext()->GetSecurityOrigin())) {
    return;
  }

  // 6. Empty topDocument's autofocus candidates.
  // 7. Set topDocument's autofocus processed flag to true.
  doc.TopDocument().FinalizeAutofocus();
}

// Returns false if beforetoggle was canceled, otherwise true. Queues a toggle
// event if beforetoggle was not canceled.
bool HTMLDialogElement::DispatchToggleEvents(bool opening, bool asModal) {
  if (!RuntimeEnabledFeatures::DialogElementToggleEventsEnabled()) {
    return true;
  }

  String old_state = opening ? "closed" : "open";
  String new_state = opening ? "open" : "closed";

  if (DispatchEvent(*ToggleEvent::Create(
          event_type_names::kBeforetoggle,
          opening ? Event::Cancelable::kYes : Event::Cancelable::kNo, old_state,
          new_state)) != DispatchEventResult::kNotCanceled) {
    return false;
  }
  if (opening) {
    if (IsOpen()) {
      return false;
    }
    if (asModal &&
        (!isConnected() || (HasPopoverAttribute() && popoverOpen()))) {
      return false;
    }
  }

  if (pending_toggle_event_) {
    old_state = pending_toggle_event_->oldState();
  }
  pending_toggle_event_ = ToggleEvent::Create(
      event_type_names::kToggle, Event::Cancelable::kNo, old_state, new_state);
  pending_toggle_event_task_ = PostCancellableTask(
      *GetDocument().GetTaskRunner(TaskType::kDOMManipulation), FROM_HERE,
      WTF::BindOnce(&HTMLDialogElement::DispatchPendingToggleEvent,
                    WrapPersistent(this)));
  return true;
}

void HTMLDialogElement::DispatchPendingToggleEvent() {
  if (!pending_toggle_event_) {
    return;
  }
  DispatchEvent(*pending_toggle_event_);
  pending_toggle_event_ = nullptr;
}

void HTMLDialogElement::Trace(Visitor* visitor) const {
  visitor->Trace(previously_focused_element_);
  visitor->Trace(close_watcher_);
  visitor->Trace(pending_toggle_event_);
  HTMLElement::Trace(visitor);
}

void HTMLDialogElement::AttributeChanged(
    const AttributeModificationParams& params) {
  HTMLElement::AttributeChanged(params);

  if (RuntimeEnabledFeatures::HTMLDialogLightDismissEnabled() &&
      params.name == html_names::kClosedbyAttr && IsOpen() &&
      params.old_value != params.new_value) {
    SetCloseWatcherEnabledState();
  }
}

void HTMLDialogElement::ParseAttribute(
    const AttributeModificationParams& params) {
  if (params.name == html_names::kOpenAttr && params.new_value.IsNull() &&
      !is_closing_) {
    // The open attribute has been removed explicitly, without calling close().
    if (RuntimeEnabledFeatures::DialogCloseWhenOpenRemovedEnabled()) {
      auto* console_message = MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kOther,
          mojom::blink::ConsoleMessageLevel::kWarning,
          "The open attribute was removed from a dialog element while it was "
          "open. This is not recommended. Please close it using the "
          "dialog.close() method instead.");
      console_message->SetNodes(GetDocument().GetFrame(), {GetDomNodeId()});
      GetDocument().AddConsoleMessage(console_message);
      close(/*return_value=*/String(), /*ignore_open_attribute=*/true);
    } else {
      GetDocument().AllOpenDialogs().erase(this);
      if (close_watcher_) {
        close_watcher_->destroy();
        close_watcher_ = nullptr;
      }
    }
  }

  HTMLElement::ParseAttribute(params);
}

}  // namespace blink

"""

```