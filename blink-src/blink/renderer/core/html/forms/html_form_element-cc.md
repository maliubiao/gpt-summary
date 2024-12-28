Response:
The user wants a summary of the functionality of the `HTMLFormElement` class in the Chromium Blink engine, based on the provided C++ source code. I need to identify the key responsibilities of this class and how it interacts with other parts of the rendering engine, especially JavaScript, HTML, and CSS. I also need to look for user or programming errors related to form handling.

Here's a breakdown of the code's functionalities:

1. **Form Submission:** The code clearly deals with form submission, including handling submit events, validation, constructing form data, and navigating to the target URL.
2. **Form Reset:**  It includes logic for resetting form controls to their initial values.
3. **Form Element Management:** The code manages collections of form elements (inputs, buttons, etc.) within the form.
4. **Form State Tracking:** It keeps track of the form's state, such as whether it's currently submitting or resetting.
5. **Integration with other Blink components:** The code includes headers for various Blink components like `Document`, `LocalFrame`, `ScriptController`, `LayoutObject`, etc., indicating its integration.
6. **Validation:**  The code implements interactive form validation.
7. **Attributes:** It handles form-specific attributes like `action`, `method`, `target`, etc.
8. **Event Handling:** It handles `submit` and `reset` events.
9. **Shadow DOM support:** The code includes logic for handling form elements within shadow DOM.

I will organize the summary by grouping related functionalities and providing examples for JavaScript, HTML, and CSS interactions, along with potential error scenarios.
这是对 Chromium Blink 引擎中 `blink/renderer/core/html/forms/html_form_element.cc` 文件功能的归纳，重点在理解其核心职责。

**核心功能归纳:**

`HTMLFormElement.cc` 文件定义了 `HTMLFormElement` 类，该类是 Blink 渲染引擎中代表 HTML `<form>` 元素的 C++ 类。其核心功能可以归纳为以下几点：

1. **管理 HTML 表单元素及其子元素:**  该类负责维护和管理 `<form>` 元素内部包含的各种表单控件（如 `<input>`, `<button>`, `<select>` 等）。它跟踪这些元素的添加、移除以及它们与表单的关联关系（通过 `form` 属性或作为表单的子元素）。
2. **处理表单提交:** 这是 `HTMLFormElement` 的核心职责之一。它处理用户触发的表单提交事件（例如点击提交按钮，按下回车键），包括：
    *   **构建提交数据:** 将表单控件的值组合成 `FormData` 对象。
    *   **执行表单验证:**  在提交前检查表单控件是否有效。
    *   **触发 `submit` 事件:**  允许 JavaScript 代码拦截和处理提交事件。
    *   **执行实际提交:**  将表单数据发送到服务器（或指定的 `action` URL）。
3. **处理表单重置:**  当用户触发表单重置操作时，该类负责将表单控件恢复到它们的初始状态。
4. **管理表单状态:**  该类维护表单的各种状态，例如是否正在提交、是否正在重置。
5. **与浏览上下文交互:**  它负责确定表单提交的目标浏览上下文（例如，当前窗口、新窗口、iframe）。
6. **处理表单属性:**  它解析和管理 `<form>` 元素的各种 HTML 属性，如 `action`, `method`, `target`, `enctype`, `accept-charset`, `novalidate` 等。
7. **支持 Shadow DOM:**  该类考虑到 Shadow DOM 的存在，能够正确地枚举和处理位于 Shadow DOM 中的表单控件。
8. **与 JavaScript 交互:**  该类提供了 JavaScript 可以访问和操作的接口，例如 `form.submit()`, `form.reset()`, `form.elements` 等。
9. **与 CSS 交互:**  虽然该 C++ 文件本身不直接处理 CSS，但它所管理的表单元素会受到 CSS 样式的渲染。此外，表单的验证状态会影响某些 CSS 伪类的应用（例如 `:valid`, `:invalid`).

在接下来的部分中，将会详细介绍这些功能，并结合 JavaScript、HTML 和 CSS 给出具体的例子。

Prompt: 
```
这是目录为blink/renderer/core/html/forms/html_form_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009 Apple Inc. All rights
 * reserved.
 *           (C) 2006 Alexey Proskuryakov (ap@nypop.com)
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
 *
 */

#include "third_party/blink/renderer/core/html/forms/html_form_element.h"

#include <limits>

#include "base/auto_reset.h"
#include "third_party/blink/public/common/security_context/insecure_request_policy.h"
#include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-blink.h"
#include "third_party/blink/public/web/web_form_related_change_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_submit_event_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_element_radionodelist.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/dom/node_lists_node_data.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/custom/element_internals.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/html/forms/form_data_event.h"
#include "third_party/blink/renderer/core/html/forms/html_form_controls_collection.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/radio_node_list.h"
#include "third_party/blink/renderer/core/html/forms/submit_event.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/rel_list.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/loader/form_submission.h"
#include "third_party/blink/renderer/core/loader/mixed_content_checker.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

using mojom::blink::FormControlType;

namespace {

// Invalidates the cache of all form elements that are ancestors of
// `starting_node` or `starting_node` itself.
void InvalidateShadowIncludingAncestorForms(ContainerNode* starting_node) {
  for (ContainerNode* node = starting_node; node;
       node = node->ParentOrShadowHostNode()) {
    if (HTMLFormElement* form = DynamicTo<HTMLFormElement>(node)) {
      form->InvalidateListedElementsIncludingShadowTrees();
    }
  }
}

}  // namespace

HTMLFormElement::HTMLFormElement(Document& document)
    : HTMLElement(html_names::kFormTag, document),
      listed_elements_are_dirty_(false),
      listed_elements_including_shadow_trees_are_dirty_(false),
      image_elements_are_dirty_(false),
      has_elements_associated_by_parser_(false),
      has_elements_associated_by_form_attribute_(false),
      did_finish_parsing_children_(false),
      is_in_reset_function_(false),
      rel_list_(MakeGarbageCollected<RelList>(this)) {
  UseCounter::Count(document, WebFeature::kFormElement);
}

HTMLFormElement::~HTMLFormElement() = default;

void HTMLFormElement::Trace(Visitor* visitor) const {
  visitor->Trace(past_names_map_);
  visitor->Trace(radio_button_group_scope_);
  visitor->Trace(listed_elements_);
  visitor->Trace(listed_elements_including_shadow_trees_);
  visitor->Trace(image_elements_);
  visitor->Trace(rel_list_);
  HTMLElement::Trace(visitor);
}

bool HTMLFormElement::MatchesValidityPseudoClasses() const {
  return true;
}

bool HTMLFormElement::IsValidElement() {
  for (const auto& element : ListedElements()) {
    if (!element->IsNotCandidateOrValid())
      return false;
  }
  return true;
}

Node::InsertionNotificationRequest HTMLFormElement::InsertedInto(
    ContainerNode& insertion_point) {
  HTMLElement::InsertedInto(insertion_point);
  LogAddElementIfIsolatedWorldAndInDocument("form", html_names::kMethodAttr,
                                            html_names::kActionAttr);
  if (insertion_point.isConnected()) {
    InvalidateShadowIncludingAncestorForms(ParentElementOrShadowRoot());
    GetDocument().MarkTopLevelFormsDirty();
    GetDocument().DidChangeFormRelatedElementDynamically(
        this, WebFormRelatedChangeType::kAdd);
  }
  return kInsertionDone;
}

template <class T>
void NotifyFormRemovedFromTree(const T& elements, Node& root) {
  for (const auto& element : elements)
    element->FormRemovedFromTree(root);
}

void HTMLFormElement::RemovedFrom(ContainerNode& insertion_point) {
  // We don't need to take care of form association by 'form' content
  // attribute becuse IdTargetObserver handles it.
  if (has_elements_associated_by_parser_) {
    Node& root = NodeTraversal::HighestAncestorOrSelf(*this);
    if (!listed_elements_are_dirty_) {
      ListedElement::List elements(ListedElements());
      NotifyFormRemovedFromTree(elements, root);
    } else {
      ListedElement::List elements;
      CollectListedElements(
          &NodeTraversal::HighestAncestorOrSelf(insertion_point), elements);
      NotifyFormRemovedFromTree(elements, root);
      CollectListedElements(&root, elements);
      NotifyFormRemovedFromTree(elements, root);
    }

    if (!image_elements_are_dirty_) {
      HeapVector<Member<HTMLImageElement>> images(ImageElements());
      NotifyFormRemovedFromTree(images, root);
    } else {
      HeapVector<Member<HTMLImageElement>> images;
      CollectImageElements(
          NodeTraversal::HighestAncestorOrSelf(insertion_point), images);
      NotifyFormRemovedFromTree(images, root);
      CollectImageElements(root, images);
      NotifyFormRemovedFromTree(images, root);
    }
  }
  GetDocument().GetFormController().WillDeleteForm(this);
  HTMLElement::RemovedFrom(insertion_point);

  if (insertion_point.isConnected()) {
    InvalidateShadowIncludingAncestorForms(&insertion_point);
    GetDocument().MarkTopLevelFormsDirty();
    GetDocument().DidChangeFormRelatedElementDynamically(
        this, WebFormRelatedChangeType::kRemove);
  }
}

void HTMLFormElement::HandleLocalEvents(Event& event) {
  Node* target_node = event.target()->ToNode();
  if (event.eventPhase() != Event::PhaseType::kCapturingPhase && target_node &&
      target_node != this &&
      (event.type() == event_type_names::kSubmit ||
       event.type() == event_type_names::kReset)) {
    event.stopPropagation();
    return;
  }
  HTMLElement::HandleLocalEvents(event);
}

unsigned HTMLFormElement::length() const {
  unsigned len = 0;
  for (const auto& element : ListedElements()) {
    if (element->IsEnumeratable())
      ++len;
  }
  return len;
}

HTMLElement* HTMLFormElement::item(unsigned index) {
  return elements()->item(index);
}

void HTMLFormElement::SubmitImplicitly(const Event& event,
                                       bool from_implicit_submission_trigger) {
  int submission_trigger_count = 0;
  bool seen_default_button = false;
  for (ListedElement* element : ListedElements()) {
    auto* control = DynamicTo<HTMLFormControlElement>(element);
    if (!control)
      continue;
    if (!seen_default_button && control->CanBeSuccessfulSubmitButton()) {
      if (from_implicit_submission_trigger)
        seen_default_button = true;
      if (control->IsSuccessfulSubmitButton()) {
        control->DispatchSimulatedClick(&event);
        return;
      }
      if (from_implicit_submission_trigger) {
        // Default (submit) button is not activated; no implicit submission.
        return;
      }
    } else if (control->CanTriggerImplicitSubmission()) {
      ++submission_trigger_count;
    }
  }
  if (from_implicit_submission_trigger && submission_trigger_count == 1)
    PrepareForSubmission(&event, nullptr);
}

bool HTMLFormElement::ValidateInteractively() {
  UseCounter::Count(GetDocument(), WebFeature::kFormValidationStarted);
  for (const auto& element : ListedElements())
    element->HideVisibleValidationMessage();

  ListedElement::List unhandled_invalid_controls;
  if (!CheckInvalidControlsAndCollectUnhandled(&unhandled_invalid_controls))
    return true;
  UseCounter::Count(GetDocument(),
                    WebFeature::kFormValidationAbortedSubmission);
  // Because the form has invalid controls, we abort the form submission and
  // show a validation message on a focusable form control.

  // Needs to update layout now because we'd like to call isFocusable(), which
  // has !layoutObject()->needsLayout() assertion.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kFocus);

  // Focus on the first focusable control and show a validation message.
  for (const auto& unhandled : unhandled_invalid_controls) {
    if (unhandled->ValidationAnchorOrHostIsFocusable()) {
      unhandled->ShowValidationMessage();
      UseCounter::Count(GetDocument(),
                        WebFeature::kFormValidationShowedMessage);
      break;
    }
  }
  // Warn about all of unfocusable controls.
  if (GetDocument().GetFrame()) {
    for (const auto& unhandled : unhandled_invalid_controls) {
      if (unhandled->ValidationAnchorOrHostIsFocusable())
        continue;
      String message(
          "An invalid form control with name='%name' is not focusable.");
      message.Replace("%name", unhandled->GetName());

      unhandled->ToHTMLElement().AddConsoleMessage(
          mojom::blink::ConsoleMessageSource::kRendering,
          mojom::blink::ConsoleMessageLevel::kError, message);
    }
  }
  return false;
}

void HTMLFormElement::PrepareForSubmission(
    const Event* event,
    HTMLFormControlElement* submit_button) {
  LocalFrame* frame = GetDocument().GetFrame();
  if (!frame || is_submitting_ || in_user_js_submit_event_)
    return;

  if (!isConnected()) {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kWarning,
        "Form submission canceled because the form is not connected"));
    return;
  }

  if (GetExecutionContext()->IsSandboxed(
          network::mojom::blink::WebSandboxFlags::kForms)) {
    GetExecutionContext()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kSecurity,
            mojom::blink::ConsoleMessageLevel::kError,
            "Blocked form submission to '" + attributes_.Action() +
                "' because the form's frame is sandboxed and the 'allow-forms' "
                "permission is not set."));
    return;
  }

  // https://github.com/whatwg/html/issues/2253
  for (ListedElement* element : ListedElements()) {
    auto* form_control_element = DynamicTo<HTMLFormControlElement>(element);
    if (form_control_element && form_control_element->BlocksFormSubmission()) {
      UseCounter::Count(GetDocument(),
                        WebFeature::kFormSubmittedWithUnclosedFormControl);
      if (RuntimeEnabledFeatures::UnclosedFormControlIsInvalidEnabled()) {
        String tag_name = To<HTMLFormControlElement>(element)->tagName();
        GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kSecurity,
            mojom::ConsoleMessageLevel::kError,
            "Form submission failed, as the <" + tag_name +
                "> element named "
                "'" +
                element->GetName() +
                "' was implicitly closed by reaching "
                "the end of the file. Please add an explicit end tag "
                "('</" +
                tag_name + ">')"));
        DispatchEvent(*Event::Create(event_type_names::kError));
        return;
      }
    }
  }

  for (ListedElement* element : ListedElements()) {
    if (auto* form_control =
            DynamicTo<HTMLFormControlElementWithState>(element)) {
      // After attempting form submission we have to make the controls start
      // matching :user-valid/:user-invalid. We could do this by calling
      // SetUserHasEditedTheFieldAndBlurred() even though the user has not
      // actually taken those actions, but that would have side effects on
      // autofill.
      form_control->ForceUserValid();
    }
  }

  bool should_submit;
  {
    base::AutoReset<bool> submit_event_handler_scope(&in_user_js_submit_event_,
                                                     true);

    bool skip_validation = !GetDocument().GetPage() || NoValidate();
    if (submit_button && submit_button->FormNoValidate())
      skip_validation = true;

    UseCounter::Count(GetDocument(), WebFeature::kFormSubmissionStarted);
    // Interactive validation must be done before dispatching the submit event.
    if (!skip_validation && !ValidateInteractively()) {
      should_submit = false;
    } else {
      frame->Client()->DispatchWillSendSubmitEvent(this);
      SubmitEventInit* submit_event_init = SubmitEventInit::Create();
      submit_event_init->setBubbles(true);
      submit_event_init->setCancelable(true);
      submit_event_init->setSubmitter(
          submit_button ? &submit_button->ToHTMLElement() : nullptr);
      should_submit = DispatchEvent(*MakeGarbageCollected<SubmitEvent>(
                          event_type_names::kSubmit, submit_event_init)) ==
                      DispatchEventResult::kNotCanceled;
    }
  }
  if (should_submit) {
    // If this form already made a request to navigate another frame which is
    // still pending, then we should cancel that one.
    if (cancel_last_submission_)
      std::move(cancel_last_submission_).Run();
    ScheduleFormSubmission(event, submit_button);
  }
}

void HTMLFormElement::submitFromJavaScript() {
  ScheduleFormSubmission(nullptr, nullptr);
}

void HTMLFormElement::requestSubmit(ExceptionState& exception_state) {
  requestSubmit(nullptr, exception_state);
}

// https://html.spec.whatwg.org/multipage/forms.html#dom-form-requestsubmit
void HTMLFormElement::requestSubmit(HTMLElement* submitter,
                                    ExceptionState& exception_state) {
  HTMLFormControlElement* control = nullptr;
  // 1. If submitter was given, then:
  if (submitter) {
    // 1.1. If submitter is not a submit button, then throw a TypeError.
    control = DynamicTo<HTMLFormControlElement>(submitter);
    if (!control || !control->CanBeSuccessfulSubmitButton()) {
      exception_state.ThrowTypeError(
          "The specified element is not a submit button.");
      return;
    }
    // 1.2. If submitter's form owner is not this form element, then throw a
    // "NotFoundError" DOMException.
    if (control->formOwner() != this) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotFoundError,
          "The specified element is not owned by this form element.");
      return;
    }
  }
  // 3. Submit this form element, from submitter.
  PrepareForSubmission(nullptr, control);
}

void HTMLFormElement::SubmitDialog(FormSubmission* form_submission) {
  for (Node* node = this; node; node = node->ParentOrShadowHostNode()) {
    if (auto* dialog = DynamicTo<HTMLDialogElement>(*node)) {
      dialog->close(form_submission->Result());
      return;
    }
  }
}

void HTMLFormElement::ScheduleFormSubmission(
    const Event* event,
    HTMLFormControlElement* submit_button) {
  LocalFrameView* view = GetDocument().View();
  LocalFrame* frame = GetDocument().GetFrame();
  if (!view || !frame || !frame->GetPage())
    return;

  // https://html.spec.whatwg.org/C/#form-submission-algorithm
  // 2. If form document is not connected, has no associated browsing context,
  // or its active sandboxing flag set has its sandboxed forms browsing
  // context flag set, then abort these steps without doing anything.
  if (!isConnected()) {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kWarning,
        "Form submission canceled because the form is not connected"));
    return;
  }

  if (is_constructing_entry_list_) {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kWarning,
        "Form submission canceled because the form is "
        "constructing entry list"));
    return;
  }

  if (is_submitting_)
    return;

  // Delay dispatching 'close' to dialog until done submitting.
  EventQueueScope scope_for_dialog_close;
  base::AutoReset<bool> submit_scope(&is_submitting_, true);

  if (event && !submit_button) {
    // In a case of implicit submission without a submit button, 'submit'
    // event handler might add a submit button. We search for a submit
    // button again.
    // TODO(tkent): Do we really need to activate such submit button?
    for (ListedElement* listed_element : ListedElements()) {
      auto* control = DynamicTo<HTMLFormControlElement>(listed_element);
      if (!control)
        continue;
      DCHECK(!control->IsActivatedSubmit());
      if (control->IsSuccessfulSubmitButton()) {
        submit_button = control;
        break;
      }
    }
  }

  FormSubmission* form_submission =
      FormSubmission::Create(this, attributes_, event, submit_button);
  if (!form_submission) {
    // Form submission is not allowed for some NavigationPolicies, e.g. Link
    // Preview. If an user triggered such user event for form submission, just
    // ignores it.
    return;
  }
  Frame* target_frame = form_submission->TargetFrame();

  // 'formdata' event handlers might disconnect the form.
  if (!isConnected()) {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kWarning,
        "Form submission canceled because the form is not connected"));
    return;
  }

  if (form_submission->Method() == FormSubmission::kDialogMethod) {
    SubmitDialog(form_submission);
    return;
  }

  DCHECK(form_submission->Method() == FormSubmission::kPostMethod ||
         form_submission->Method() == FormSubmission::kGetMethod);
  DCHECK(form_submission->Data());
  if (form_submission->Action().IsEmpty())
    return;
  if (GetExecutionContext()->IsSandboxed(
          network::mojom::blink::WebSandboxFlags::kForms)) {
    // FIXME: This message should be moved off the console once a solution to
    // https://bugs.webkit.org/show_bug.cgi?id=103274 exists.
    GetExecutionContext()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kSecurity,
            mojom::blink::ConsoleMessageLevel::kError,
            "Blocked form submission to '" +
                form_submission->Action().ElidedString() +
                "' because the form's frame is sandboxed and the 'allow-forms' "
                "permission is not set."));
    return;
  }

  if (form_submission->Action().ProtocolIsJavaScript()) {
    // For javascript URLs we need to do the CSP check for 'form-action' here.
    // All other schemes are checked in the browser.
    //
    // TODO(antoniosartori): Should we keep the 'form-action' check for
    // javascript: URLs? For 'frame-src', we do not check javascript: URLs.
    // Reading the specification, it looks like 'form-action' should not apply
    // to javascript: URLs.
    if (!GetExecutionContext()->GetContentSecurityPolicy()->AllowFormAction(
            form_submission->Action())) {
      return;
    }
  }

  UseCounter::Count(GetDocument(), WebFeature::kFormsSubmitted);
  if (MixedContentChecker::IsMixedFormAction(GetDocument().GetFrame(),
                                             form_submission->Action())) {
    UseCounter::Count(GetDocument(), WebFeature::kMixedContentFormsSubmitted);
  }
  if (FastHasAttribute(html_names::kDisabledAttr)) {
    UseCounter::Count(GetDocument(),
                      WebFeature::kFormDisabledAttributePresentAndSubmit);
  }

  if (!target_frame)
    return;

  if (form_submission->Action().ProtocolIsJavaScript()) {
    // For javascript urls, don't post a task to execute the form submission
    // because we already get another task posted for it in
    // Document::ProcessJavascriptUrl. If we post two tasks, the javascript will
    // be run too late according to some tests.
    form_submission->Navigate();
    return;
  }

  FrameScheduler* scheduler = GetDocument().GetFrame()->GetFrameScheduler();

  if (auto* target_local_frame = DynamicTo<LocalFrame>(target_frame)) {
    if (!target_local_frame->IsNavigationAllowed())
      return;

    // Cancel parsing if the form submission is targeted at this frame.
    if (target_local_frame == GetDocument().GetFrame() &&
        !form_submission->Action().ProtocolIsJavaScript()) {
      target_local_frame->GetDocument()->CancelParsing();
    }

    // Use the target frame's frame scheduler. If we can't due to targeting a
    // RemoteFrame, then use the frame scheduler from the frame this form is in.
    scheduler = target_local_frame->GetFrameScheduler();

    // Cancel pending javascript url navigations for the target frame. This new
    // form submission should take precedence over them.
    target_local_frame->GetDocument()->CancelPendingJavaScriptUrls();

    // Cancel any pre-existing attempt to navigate the target frame which was
    // already sent to the browser process so this form submission will take
    // precedence over it.
    target_local_frame->Loader().CancelClientNavigation();
  }

  cancel_last_submission_ =
      target_frame->ScheduleFormSubmission(scheduler, form_submission);
}

FormData* HTMLFormElement::ConstructEntryList(
    HTMLFormControlElement* submit_button,
    const WTF::TextEncoding& encoding) {
  if (is_constructing_entry_list_) {
    return nullptr;
  }
  auto& form_data = *MakeGarbageCollected<FormData>(encoding);
  base::AutoReset<bool> entry_list_scope(&is_constructing_entry_list_, true);
  if (submit_button)
    submit_button->SetActivatedSubmit(true);
  for (ListedElement* control : ListedElements()) {
    DCHECK(control);
    HTMLElement& element = control->ToHTMLElement();
    if (!element.IsDisabledFormControl())
      control->AppendToFormData(form_data);
    if (auto* input = DynamicTo<HTMLInputElement>(element)) {
      if (input->FormControlType() == FormControlType::kInputPassword &&
          !input->Value().empty()) {
        form_data.SetContainsPasswordData(true);
      }
    }
  }
  DispatchEvent(*MakeGarbageCollected<FormDataEvent>(form_data));

  if (submit_button)
    submit_button->SetActivatedSubmit(false);
  return &form_data;
}

void HTMLFormElement::reset() {
  LocalFrame* frame = GetDocument().GetFrame();
  if (is_in_reset_function_ || !frame)
    return;

  is_in_reset_function_ = true;

  if (DispatchEvent(*Event::CreateCancelableBubble(event_type_names::kReset)) !=
      DispatchEventResult::kNotCanceled) {
    is_in_reset_function_ = false;
    return;
  }

  // Copy the element list because |reset()| implementation can update DOM
  // structure.
  ListedElement::List elements(ListedElements());
  for (ListedElement* element : elements) {
    if (auto* html_form_element = DynamicTo<HTMLFormControlElement>(element)) {
      html_form_element->Reset();
    } else if (element->IsElementInternals()) {
      CustomElement::EnqueueFormResetCallback(element->ToHTMLElement());
    }
  }

  is_in_reset_function_ = false;
  if (frame->GetPage())
    frame->GetPage()->GetChromeClient().FormElementReset(*this);
}

void HTMLFormElement::AttachLayoutTree(AttachContext& context) {
  HTMLElement::AttachLayoutTree(context);
  if (!GetLayoutObject()) {
    FocusabilityLost();
  }
}

void HTMLFormElement::DetachLayoutTree(bool performing_reattach) {
  HTMLElement::DetachLayoutTree(performing_reattach);
  if (!performing_reattach) {
    FocusabilityLost();
  }
}

void HTMLFormElement::ParseAttribute(
    const AttributeModificationParams& params) {
  const QualifiedName& name = params.name;
  if (name == html_names::kActionAttr) {
    attributes_.ParseAction(params.new_value);
    LogUpdateAttributeIfIsolatedWorldAndInDocument("form", params);

    // If we're not upgrading insecure requests, and the new action attribute is
    // pointing to an insecure "action" location from a secure page it is marked
    // as "passive" mixed content.
    if (GetExecutionContext() &&
        (GetExecutionContext()
             ->GetSecurityContext()
             .GetInsecureRequestPolicy() &
         mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests) !=
            mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone)
      return;
    KURL action_url = GetDocument().CompleteURL(
        attributes_.Action().empty() ? GetDocument().Url().GetString()
                                     : attributes_.Action());
    if (MixedContentChecker::IsMixedFormAction(GetDocument().GetFrame(),
                                               action_url)) {
      UseCounter::Count(GetDocument(), WebFeature::kMixedContentFormPresent);
    }
  } else if (name == html_names::kTargetAttr) {
    attributes_.SetTarget(params.new_value);
  } else if (name == html_names::kMethodAttr) {
    attributes_.UpdateMethodType(params.new_value);
  } else if (name == html_names::kEnctypeAttr) {
    attributes_.UpdateEncodingType(params.new_value);
  } else if (name == html_names::kAcceptCharsetAttr) {
    attributes_.SetAcceptCharset(params.new_value);
  } else if (name == html_names::kDisabledAttr) {
    UseCounter::Count(GetDocument(), WebFeature::kFormDisabledAttributePresent);
  } else if (name == html_names::kRelAttr) {
    rel_attribute_ = RelAttribute::kNone;
    rel_list_->DidUpdateAttributeValue(params.old_value, params.new_value);
    if (rel_list_->contains(AtomicString("noreferrer")))
      rel_attribute_ |= RelAttribute::kNoReferrer;
    if (rel_list_->contains(AtomicString("noopener")))
      rel_attribute_ |= RelAttribute::kNoOpener;
    if (rel_list_->contains(AtomicString("opener")))
      rel_attribute_ |= RelAttribute::kOpener;

  } else {
    HTMLElement::ParseAttribute(params);
  }
}

void HTMLFormElement::Associate(ListedElement& e) {
  listed_elements_are_dirty_ = true;
  listed_elements_.clear();
  listed_elements_including_shadow_trees_are_dirty_ = true;
  listed_elements_including_shadow_trees_.clear();
  if (e.ToHTMLElement().FastHasAttribute(html_names::kFormAttr))
    has_elements_associated_by_form_attribute_ = true;
}

void HTMLFormElement::Disassociate(ListedElement& e) {
  listed_elements_are_dirty_ = true;
  listed_elements_.clear();
  listed_elements_including_shadow_trees_are_dirty_ = true;
  listed_elements_including_shadow_trees_.clear();
  RemoveFromPastNamesMap(e.ToHTMLElement());
}

bool HTMLFormElement::IsURLAttribute(const Attribute& attribute) const {
  return attribute.GetName() == html_names::kActionAttr ||
         HTMLElement::IsURLAttribute(attribute);
}

bool HTMLFormElement::HasLegalLinkAttribute(const QualifiedName& name) const {
  return name == html_names::kActionAttr ||
         HTMLElement::HasLegalLinkAttribute(name);
}

void HTMLFormElement::Associate(HTMLImageElement& e) {
  image_elements_are_dirty_ = true;
  image_elements_.clear();
}

void HTMLFormElement::Disassociate(HTMLImageElement& e) {
  image_elements_are_dirty_ = true;
  image_elements_.clear();
  RemoveFromPastNamesMap(e);
}

void HTMLFormElement::DidAssociateByParser() {
  if (!did_finish_parsing_children_)
    return;
  has_elements_associated_by_parser_ = true;
  UseCounter::Count(GetDocument(), WebFeature::kFormAssociationByParser);
}

HTMLFormControlsCollection* HTMLFormElement::elements() {
  return EnsureCachedCollection<HTMLFormControlsCollection>(kFormControls);
}

void HTMLFormElement::CollectListedElements(
    const Node* root,
    ListedElement::List& elements,
    ListedElement::List* elements_including_shadow_trees,
    bool in_shadow_tree) const {
  CHECK(root);
  DCHECK(!in_shadow_tree || elements_including_shadow_trees);
  HeapVector<Member<HTMLFormElement>> nested_forms;
  if (!in_shadow_tree) {
    elements.clear();
    if (elements_including_shadow_trees) {
      for (HTMLFormElement& nested_form :
           Traversal<HTMLFormElement>::DescendantsOf(*this)) {
        nested_forms.push_back(nested_form);
      }
    }
  }

  // We flatten elements of nested forms into `elements_including_shadow_trees`.
  // If one of the nested forms has an element associated by form attribute,
  // that element may be outside of `root`'s subtree and we need to start at the
  // root node.
  const bool nested_forms_have_form_associated_elements =
      base::ranges::any_of(nested_forms, [](const auto& form) {
        return form->has_elements_associated_by_form_attribute_ ||
               (form->has_elements_associated_by_parser_ &&
                base::FeatureList::IsEnabled(
                    features::
                        kAutofillFixFieldsAssociatedWithNestedFormsByParser));
      });
  if (nested_forms_have_form_associated_elements && isConnected()) {
    root = &GetTreeScope().RootNode();
  }

  // A performance optimization - if `root_is_descendant` is true,
  // then we can save some checks whether elements that we are traversing are
  // descendants of `this`.
  const bool root_is_descendant = in_shadow_tree || root == this;

  for (HTMLElement& element : Traversal<HTMLElement>::DescendantsOf(*root)) {
    if (ListedElement* listed_element = ListedElement::From(element)) {
      // Autofill only considers top level forms. We therefore include all form
      // control descendants of the form whose elements we collect in
      // `elements_including_shadow_trees`, even if their closest ancestor is a
      // different form.
      // `elements` does not have this complication because it can check
      // `listed_element->Form()`.
      if (in_shadow_tree) {
        elements_including_shadow_trees->push_back(listed_element);
      } else if (listed_element->Form() == this) {
        elements.push_back(listed_element);
        if (elements_including_shadow_trees)
          elements_including_shadow_trees->push_back(listed_element);
      } else if (base::Contains(nested_forms, listed_element->Form())) {
        elements_including_shadow_trees->push_back(listed_element);
      }
    }
    // Descend recursively into shadow DOM if the following conditions are met:
    // - We are supposed to gather elements in shadow trees.
    // - `element` is a shadow root.
    // - `element` is a shadow-including descendant of 
"""


```