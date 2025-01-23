Response:
My thinking process to answer the request about `listed_element.cc` went through these stages:

1. **Understanding the Request:** I first broke down the request into key questions:
    * What are the functionalities of this file?
    * How does it relate to JavaScript, HTML, and CSS?
    * Are there logical inferences with input/output examples?
    * What common user/programming errors are involved?
    * How does a user's interaction lead to this code being executed?

2. **Initial Code Scan (Keywords and Structure):** I scanned the code for prominent keywords and structural elements:
    * **Includes:**  I noted the included headers like `html_form_control_element.h`, `html_form_element.h`, `event.h`, `element_internals.h`, suggesting this file deals with form elements and their interactions, including custom elements.
    * **Class Declaration:** The central class `ListedElement` immediately stood out as the primary subject.
    * **Member Variables:**  Variables like `form_`, `validity_state_`, `will_validate_`, `custom_validation_message_`, and `form_attribute_target_observer_` hinted at its core responsibilities: managing form associations, validation, and attribute tracking.
    * **Methods:**  Methods like `InsertedInto`, `RemovedFrom`, `SetForm`, `checkValidity`, `reportValidity`, `UpdateVisibleValidationMessage`, `DisabledAttributeChanged`, and `ReadonlyAttributeChanged` provided direct clues about the element's lifecycle and behavior.
    * **Namespaces:** The `blink` namespace confirmed this is part of the Blink rendering engine.

3. **Inferring Core Functionality (Connecting the Dots):** Based on the includes and member variables/methods, I started connecting the dots to infer the main purpose of `ListedElement`:
    * **Abstract Base Class:** The name "ListedElement" and its role in handling common form element behaviors suggested it's an abstract base class for elements that participate in form submissions and validation.
    * **Form Association:** The presence of `form_` and methods like `SetForm`, `ResetFormOwner`, and handling the `form` attribute clearly indicated its responsibility for managing the association of an element with a form.
    * **Validation:** The `validity_state_`, `WillValidate`, `checkValidity`, `reportValidity`, and message-related methods pointed to its role in handling form validation, including custom validation.
    * **Disabled State:** The `is_element_disabled_`, `ancestor_disabled_state_`, and `DisabledAttributeChanged` methods showed it tracks and manages the disabled state of the element, considering ancestor fieldsets.
    * **Readonly State:** Similar to disabled, `is_readonly_` and `ReadonlyAttributeChanged` manage the readonly state.
    * **Lifecycle Management:**  `InsertedInto` and `RemovedFrom` suggested it handles the element's attachment and detachment from the DOM, updating its internal state accordingly.
    * **Event Handling:**  The mention of `DispatchEvent` and the `invalid` event highlighted its involvement in triggering and responding to browser events.

4. **Relating to JavaScript, HTML, and CSS:**  Once the core functionalities were established, I considered how they interact with web technologies:
    * **HTML:**  The association with forms, attributes like `form`, `disabled`, `readonly`, and validation attributes directly link to HTML form elements.
    * **JavaScript:**  Methods like `checkValidity()` and `reportValidity()` are directly exposed and callable from JavaScript. Setting custom validity messages using `setCustomValidity()` is another key interaction. The event dispatching also connects to JavaScript event listeners.
    * **CSS:** Pseudo-classes like `:valid`, `:invalid`, `:disabled`, and `:enabled` are directly influenced by the internal state managed by `ListedElement`. Changes in validity and disabled state trigger style recalculations.

5. **Logical Inference and Examples:**  For logical inference, I considered common scenarios and how the `ListedElement` might behave:
    * **Input:**  Setting the `required` attribute on an input field (HTML).
    * **Output:**  The `ValueMissing()` method returning `true`, causing `Valid()` to be `false`, and potentially triggering the display of a validation message (handled by `UpdateVisibleValidationMessage`).
    * **Input:** Calling `element.checkValidity()` in JavaScript.
    * **Output:**  The `checkValidity()` method in `ListedElement` would be invoked, potentially dispatching an `invalid` event if validation fails.

6. **Common Errors:** I brainstormed potential errors users or programmers might make:
    * Forgetting to associate a form control with a form.
    * Incorrectly setting custom validity messages.
    * Not handling the `invalid` event properly.
    * Relying on validation logic in JavaScript without understanding the browser's built-in validation.

7. **User Interaction Flow:** I traced a simple user interaction:
    * User types in a form field.
    * User attempts to submit the form.
    * The browser's form submission process would trigger validation checks, potentially involving the methods in `ListedElement`.
    * If validation fails, the `invalid` event is fired, and the browser might display a validation message using the logic within `ListedElement`.

8. **Structuring the Answer:** Finally, I organized the information into the requested categories, providing clear explanations and concrete examples for each point. I made sure to address all parts of the original prompt. I used headings and bullet points for readability.

This iterative process of code analysis, inference, and connecting to web standards allowed me to provide a comprehensive answer about the functionality and context of the `listed_element.cc` file.
这个文件 `blink/renderer/core/html/forms/listed_element.cc` 是 Chromium Blink 引擎中负责处理**表单中可列出的元素 (listed elements)** 的核心代码。这些元素通常是指可以参与表单提交、验证和状态管理的 HTML 元素。

**主要功能:**

1. **表单关联管理 (Form Association Management):**
   - **跟踪所属表单:** `ListedElement` 维护了对它所属的 `HTMLFormElement` 的引用 (`form_`)。
   - **处理 `form` 属性:**  它监听和处理 HTML 元素的 `form` 属性的变化，根据该属性将元素关联到特定的表单。如果 `form` 属性指定了表单的 ID，则会查找具有该 ID 的表单。
   - **动态关联和解除关联:** 当元素被插入或移除 DOM 树时，或者当 `form` 属性改变时，`ListedElement` 负责更新与表单的关联。
   - **`ResetFormOwner()`:**  这个方法是核心，它根据元素的 `form` 属性和 DOM 树结构，重新确定元素应该关联到哪个表单。

2. **表单验证 (Form Validation):**
   - **`WillValidate()`:**  确定元素是否参与表单验证。这取决于元素的属性 (如 `disabled`, `readonly`) 以及它是否在 `<datalist>` 元素内。
   - **`ValidityState`:**  管理元素的验证状态，包括 `valueMissing`, `typeMismatch`, `patternMismatch` 等各种验证错误。
   - **`checkValidity()` 和 `reportValidity()`:**  实现了 JavaScript 中 `checkValidity()` 和 `reportValidity()` 方法的底层逻辑，用于检查元素的有效性并显示验证消息。
   - **自定义验证:** 支持通过 `setCustomValidity()` 方法设置自定义的验证消息。
   - **显示/隐藏验证消息:**  负责显示和隐藏浏览器原生的验证提示气泡 (`UpdateVisibleValidationMessage()`, `HideVisibleValidationMessage()`).

3. **禁用状态管理 (Disabled State Management):**
   - **`DisabledAttributeChanged()`:**  响应 `disabled` 属性的变化，更新内部状态。
   - **祖先禁用状态:**  考虑元素祖先中 `<fieldset>` 元素的禁用状态，如果祖先 `<fieldset>` 被禁用，则该元素也会被视为禁用。
   - **`IsActuallyDisabled()`:**  判断元素是否真正被禁用（自身禁用或祖先禁用）。

4. **只读状态管理 (Readonly State Management):**
   - **`ReadonlyAttributeChanged()`:** 响应 `readonly` 属性的变化，更新内部状态。

5. **状态保存与恢复 (State Saving and Restoring):**
   -  虽然默认情况下 `ListedElement` 返回 `false` 表示不支持状态保存和恢复，但子类可以重写 `ClassSupportsStateRestore()` 和相关方法来实现表单状态的持久化。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    - **`form` 属性:** `ListedElement` 直接处理 HTML 元素的 `form` 属性，例如 `<input type="text" form="myForm">` 会使得这个输入框关联到 ID 为 "myForm" 的表单。
    - **`disabled` 属性:**  `ListedElement` 的 `DisabledAttributeChanged()` 方法会在 HTML 元素的 `disabled` 属性改变时被调用，例如 `<input type="text" disabled>`。
    - **`readonly` 属性:**  `ListedElement` 的 `ReadonlyAttributeChanged()` 方法会在 HTML 元素的 `readonly` 属性改变时被调用，例如 `<input type="text" readonly>`。
    - **表单验证属性:**  虽然 `ListedElement` 本身不直接解析如 `required`, `pattern` 等验证属性，但它是验证流程的核心，这些属性会影响 `ValidityState` 的计算。例如 `<input type="text" required>` 会使得 `ValueMissing()` 返回 `true` 当输入为空时。
    - **`<fieldset>` 和 `<legend>`:**  `ListedElement` 考虑了 `<fieldset>` 的禁用状态，例如在一个禁用的 `<fieldset>` 内的输入框也会被禁用，除非它属于 `<legend>` 元素的子节点。

* **JavaScript:**
    - **`HTMLInputElement.form`:**  JavaScript 可以访问表单控件的 `form` 属性来获取其关联的表单。`ListedElement` 维护的 `form_` 成员变量最终会影响到这个 JavaScript 属性的值。
    - **`HTMLInputElement.checkValidity()`:**  JavaScript 可以调用元素的 `checkValidity()` 方法来触发验证。`ListedElement::checkValidity()` 实现了这个方法的底层逻辑.
    - **`HTMLInputElement.reportValidity()`:**  JavaScript 可以调用元素的 `reportValidity()` 方法来触发验证并显示验证消息。`ListedElement::reportValidity()` 实现了这个方法的底层逻辑。
    - **`HTMLInputElement.setCustomValidity()`:** JavaScript 可以调用元素的 `setCustomValidity()` 方法来设置自定义的验证消息。`ListedElement::setCustomValidity()` 实现了这个方法的底层逻辑。
    - **`invalid` 事件:** 当元素的验证失败时，会触发 `invalid` 事件。`ListedElement::checkValidity()` 中会 dispatch 这个事件。

* **CSS:**
    - **`:valid` 和 `:invalid` 伪类:**  CSS 可以使用 `:valid` 和 `:invalid` 伪类来根据表单控件的验证状态设置样式。`ListedElement::SetNeedsValidityCheck()` 和相关的状态更新方法会触发样式的重新计算。例如，可以设置当输入框验证失败时显示红色边框。
    - **`:disabled` 和 `:enabled` 伪类:** CSS 可以使用 `:disabled` 和 `:enabled` 伪类来根据表单控件的禁用状态设置样式。`ListedElement::DisabledAttributeChanged()` 会触发样式的重新计算。

**逻辑推理和假设输入/输出:**

假设我们有以下 HTML 片段：

```html
<form id="myForm">
  <input type="text" id="name" required>
  <button type="submit">提交</button>
</form>
```

1. **假设输入:** 用户尝试点击 "提交" 按钮，触发表单提交。
   **输出:**  浏览器会首先对表单中的可列出元素进行验证。对于 `<input id="name">` 元素，由于设置了 `required` 属性，`ListedElement::ValueMissing()` 方法会返回 `true`，导致 `ListedElement::Valid()` 返回 `false`。

2. **假设输入:** JavaScript 调用 `document.getElementById('name').checkValidity()`.
   **输出:** `ListedElement::checkValidity()` 方法会被调用。如果输入框为空，该方法会返回 `false`，并且会 dispatch 一个 `invalid` 事件到该输入框。

3. **假设输入:** JavaScript 调用 `document.getElementById('name').setCustomValidity('请输入您的姓名')`.
   **输出:** `ListedElement::SetCustomValidationMessage()` 方法会被调用，将自定义验证消息存储起来。后续调用 `validationMessage()` 将返回这个自定义消息。

**用户或编程常见的使用错误:**

1. **忘记将表单控件与表单关联:** 如果一个表单控件没有放在 `<form>` 元素内部，也没有使用 `form` 属性指定关联的表单，那么它将不会参与表单的提交和验证。
   ```html
   <input type="text" name="username">  <!-- 错误：未关联表单 -->
   <form>
     <!-- ... -->
   </form>
   ```

2. **在 JavaScript 中手动验证，但没有阻止表单的默认提交行为:**  即使在 JavaScript 中使用了 `checkValidity()`，如果没有使用 `event.preventDefault()` 阻止表单的默认提交行为，表单仍然会被提交。

3. **自定义验证逻辑与浏览器原生验证逻辑冲突:**  开发者可能会编写 JavaScript 代码进行额外的验证，但这可能会与浏览器内置的验证逻辑产生冲突，导致用户体验不一致。

4. **错误地使用 `setCustomValidity('')`:**  调用 `setCustomValidity('')` 会清除自定义验证消息，但不会清除其他类型的验证错误（例如 `required` 导致的 `valueMissing`）。

**用户操作如何一步步到达这里:**

1. **用户在浏览器中打开一个包含表单的网页。**
2. **浏览器解析 HTML 代码，创建 DOM 树。** 对于表单中的每个可列出元素（例如 `<input>`, `<select>`, `<button>` 等），都会创建对应的 Blink C++ 对象，其中就包括继承自 `ListedElement` 的子类对象。
3. **用户与表单元素进行交互:**
   - **输入内容:**  用户在输入框中输入内容，这可能会触发一些事件，最终导致对元素状态的更新。
   - **尝试提交表单:** 用户点击提交按钮或按下 Enter 键。
4. **表单提交过程:**
   - **浏览器触发表单验证:** 在表单提交之前，浏览器会检查表单的有效性。这个过程会调用 `ListedElement` 及其子类中实现的验证相关方法 (`checkValidity()`, `ValueMissing()` 等)。
   - **显示验证消息:** 如果验证失败，`ListedElement` 会负责显示验证消息气泡。
   - **JavaScript 事件处理:** 如果有 JavaScript 代码监听了 `invalid` 事件，那么这些事件处理函数会被执行。
5. **`form` 属性变化:** 用户可能通过 JavaScript 动态修改元素的 `form` 属性，这会导致 `ListedElement::FormAttributeChanged()` 被调用，从而重新建立与表单的关联。
6. **`disabled` 或 `readonly` 属性变化:** 用户或者 JavaScript 代码可能修改元素的 `disabled` 或 `readonly` 属性，这会触发 `ListedElement::DisabledAttributeChanged()` 或 `ListedElement::ReadonlyAttributeChanged()`，并影响元素的验证和交互行为。

总而言之，`listed_element.cc` 文件是 Blink 引擎中处理表单交互的核心组件，它负责管理表单元素的关联、验证、禁用/只读状态，并与 HTML 结构、JavaScript API 以及 CSS 样式选择器紧密配合，共同实现 Web 表单的功能。

### 提示词
```
这是目录为blink/renderer/core/html/forms/listed_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/html/forms/listed_element.h"

#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/id_target_observer.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/html/custom/element_internals.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/core/html/forms/html_data_list_element.h"
#include "third_party/blink/renderer/core/html/forms/html_field_set_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element_with_state.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_legend_element.h"
#include "third_party/blink/renderer/core/html/forms/validity_state.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/validation_message_client.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/text/bidi_paragraph.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

void InvalidateShadowIncludingAncestorForms(ContainerNode& insertion_point) {
  // Let any forms in the shadow including ancestors know that this
  // ListedElement has changed. We also cache listed elements inside
  // (descendant) nested forms and therefore need to invalidate the caches also
  // inside the same `TreeScope`.
  ContainerNode* starting_node = insertion_point.ParentOrShadowHostNode();
  for (ContainerNode* parent = starting_node; parent;
       parent = parent->ParentOrShadowHostNode()) {
    if (HTMLFormElement* form = DynamicTo<HTMLFormElement>(parent)) {
      form->InvalidateListedElementsIncludingShadowTrees();
    }
  }
}

}  // namespace

class FormAttributeTargetObserver : public IdTargetObserver {
 public:
  FormAttributeTargetObserver(const AtomicString& id, ListedElement*);

  void Trace(Visitor*) const override;
  void IdTargetChanged() override;

 private:
  Member<ListedElement> element_;
};

ListedElement::ListedElement()
    : has_validation_message_(false),
      form_was_set_by_parser_(false),
      will_validate_initialized_(false),
      will_validate_(true),
      is_valid_(true),
      validity_is_dirty_(false),
      is_element_disabled_(false),
      is_readonly_(false) {}

ListedElement::~ListedElement() {
  // We can't call setForm here because it contains virtual calls.
}

void ListedElement::Trace(Visitor* visitor) const {
  visitor->Trace(form_attribute_target_observer_);
  visitor->Trace(form_);
  visitor->Trace(validity_state_);
}

ValidityState* ListedElement::validity() {
  if (!validity_state_)
    validity_state_ = MakeGarbageCollected<ValidityState>(this);

  return validity_state_.Get();
}

void ListedElement::DidMoveToNewDocument(Document& old_document) {
  if (ToHTMLElement().FastHasAttribute(html_names::kFormAttr))
    SetFormAttributeTargetObserver(nullptr);
}

void ListedElement::InsertedInto(ContainerNode& insertion_point) {
  ancestor_disabled_state_ = AncestorDisabledState::kUnknown;
  // Force traversal to find ancestor
  may_have_fieldset_ancestor_ = true;
  data_list_ancestor_state_ = DataListAncestorState::kUnknown;
  UpdateWillValidateCache(WillValidateReason::kForInsertionOrRemoval);

  if (!form_was_set_by_parser_ || !form_ ||
      NodeTraversal::HighestAncestorOrSelf(insertion_point) !=
          NodeTraversal::HighestAncestorOrSelf(*form_.Get()))
    ResetFormOwner();

  HTMLElement& element = ToHTMLElement();
  if (insertion_point.isConnected()) {
    if (element.FastHasAttribute(html_names::kFormAttr))
      ResetFormAttributeTargetObserver();
  }

  FieldSetAncestorsSetNeedsValidityCheck(&insertion_point,
                                         StartingNodeType::IS_INSERTION_POINT);
  DisabledStateMightBeChanged();

  if (ClassSupportsStateRestore() && insertion_point.isConnected() &&
      !element.ContainingShadowRoot()) {
    element.GetDocument()
        .GetFormController()
        .InvalidateStatefulFormControlList();
  }

  // Trigger for elements outside of forms.
  if (!form_ && insertion_point.isConnected()) {
    element.GetDocument().DidChangeFormRelatedElementDynamically(
        &element, WebFormRelatedChangeType::kAdd);
  }

  InvalidateShadowIncludingAncestorForms(insertion_point);
}

void ListedElement::RemovedFrom(ContainerNode& insertion_point) {
  FieldSetAncestorsSetNeedsValidityCheck(&insertion_point,
                                         StartingNodeType::IS_INSERTION_POINT);
  HideVisibleValidationMessage();
  has_validation_message_ = false;
  // Two values that might change as a result of being removed are
  // `ancestor_disabled_state_` and `data_list_ancestor_state_`. Both of
  // these values feed into the WillValidate cache. If this ListedElement is
  // not in a fieldset and not in a data-list, then it won't be in a fieldset
  // or fieldset after the removal, so that the cache does not need to be
  // updated.
  if (ancestor_disabled_state_ == AncestorDisabledState::kEnabled &&
      data_list_ancestor_state_ == DataListAncestorState::kNotInsideDataList) {
    DCHECK_EQ(will_validate_, RecalcWillValidate());
  } else {
    ancestor_disabled_state_ = AncestorDisabledState::kUnknown;
    data_list_ancestor_state_ = DataListAncestorState::kUnknown;
    UpdateWillValidateCache(WillValidateReason::kForInsertionOrRemoval);
  }

  HTMLElement& element = ToHTMLElement();
  if (insertion_point.isConnected() &&
      element.FastHasAttribute(html_names::kFormAttr)) {
    SetFormAttributeTargetObserver(nullptr);
    ResetFormOwner();
  } else if (!form_ && insertion_point.isConnected()) {
    // If there is no associated form, then there won't be one after removing,
    // so don't need to call ResetFormOwner(). While this doesn't need to call
    // ResetFormOwner(), it needs to call SetForm() to ensure Document level
    // state is updated.
    form_was_set_by_parser_ = false;
    SetForm(nullptr);
  } else if (form_ && NodeTraversal::HighestAncestorOrSelf(element) !=
                          NodeTraversal::HighestAncestorOrSelf(*form_.Get())) {
    // If the form and element are both in the same tree, preserve the
    // connection to the form.  Otherwise, null out our form and remove
    // ourselves from the form's list of elements.
    ResetFormOwner();
  }

  DisabledStateMightBeChanged();

  if (ClassSupportsStateRestore() && insertion_point.isConnected() &&
      !element.ContainingShadowRoot() &&
      !insertion_point.ContainingShadowRoot()) {
    element.GetDocument()
        .GetFormController()
        .InvalidateStatefulFormControlList();
  }

  InvalidateShadowIncludingAncestorForms(insertion_point);

  if (insertion_point.isConnected()) {
    // We don't insist on form_ being non-null as the form does not take care of
    // reporting the removal.
    element.GetDocument().DidChangeFormRelatedElementDynamically(
        &element, WebFormRelatedChangeType::kRemove);
  }
}

void ListedElement::FormRemovedFromTree(const Node& form_root) {
  DCHECK(form_);
  if (NodeTraversal::HighestAncestorOrSelf(ToHTMLElement()) == form_root)
    return;
  ResetFormOwner();
}

void ListedElement::AssociateByParser(HTMLFormElement* form) {
  if (form && form->isConnected()) {
    form_was_set_by_parser_ = true;
    SetForm(form);
    form->DidAssociateByParser();
  }
}

void ListedElement::SetForm(HTMLFormElement* new_form) {
  if (!form_ || !new_form) {
    // Element was unassociated, or is becoming unassociated.
    ToHTMLElement().GetDocument().MarkUnassociatedListedElementsDirty();
  }
  if (form_.Get() == new_form)
    return;
  WillChangeForm();
  if (form_)
    form_->Disassociate(*this);
  if (new_form) {
    form_ = new_form;
    form_->Associate(*this);
  } else {
    form_ = nullptr;
  }
  DidChangeForm();
}

void ListedElement::WillChangeForm() {
  FormOwnerSetNeedsValidityCheck();
}

void ListedElement::DidChangeForm() {
  if (!form_was_set_by_parser_ && form_ && form_->isConnected()) {
    auto& element = ToHTMLElement();
    element.GetDocument().DidChangeFormRelatedElementDynamically(
        &element, WebFormRelatedChangeType::kReassociate);
  }
  FormOwnerSetNeedsValidityCheck();
}

void ListedElement::FormOwnerSetNeedsValidityCheck() {
  if (HTMLFormElement* form = Form()) {
    form->PseudoStateChanged(CSSSelector::kPseudoValid);
    form->PseudoStateChanged(CSSSelector::kPseudoInvalid);
    form->PseudoStateChanged(CSSSelector::kPseudoUserValid);
    form->PseudoStateChanged(CSSSelector::kPseudoUserInvalid);
  }
}

void ListedElement::FieldSetAncestorsSetNeedsValidityCheck(
    Node* node,
    StartingNodeType starting_type) {
  if (!node)
    return;
  if (!may_have_fieldset_ancestor_)
    return;
  auto* field_set = Traversal<HTMLFieldSetElement>::FirstAncestorOrSelf(*node);
  if (!field_set) {
    if (starting_type == StartingNodeType::IS_PARENT) {
      may_have_fieldset_ancestor_ = false;
    }
    return;
  }
  do {
    field_set->PseudoStateChanged(CSSSelector::kPseudoValid);
    field_set->PseudoStateChanged(CSSSelector::kPseudoInvalid);
    field_set->PseudoStateChanged(CSSSelector::kPseudoUserValid);
    field_set->PseudoStateChanged(CSSSelector::kPseudoUserInvalid);
  } while (
      (field_set = Traversal<HTMLFieldSetElement>::FirstAncestor(*field_set)));
}

// https://html.spec.whatwg.org/multipage/C#reset-the-form-owner
void ListedElement::ResetFormOwner() {
  // 1. Unset element's parser inserted flag.
  form_was_set_by_parser_ = false;
  HTMLElement& element = ToHTMLElement();
  const AtomicString& form_id(element.FastGetAttribute(html_names::kFormAttr));
  HTMLFormElement* nearest_form = element.FindFormAncestor();
  // 2. If all of the following are true:
  //    - element's form owner is not null;
  //    - element is not listed or its form content attribute is not present;
  //      and
  //    - element's form owner is its nearest form element ancestor after the
  //      change to the ancestor chain,
  // then return.
  if (form_ && form_id.IsNull() && form_.Get() == nearest_form)
    return;

  // 3. Set element's form owner to null.
  // 4. If element is listed, has a form content attribute, and is connected,
  //    then:
  //    1. If the first element in element's tree, in tree order, to have an
  //       ID that is identical to element's form content attribute's value,
  //       is a form element, then associate the element with that form
  //       element.
  HTMLFormElement* new_form = nullptr;
  if (!form_id.IsNull() && element.isConnected()) {
    Element* new_form_candidate =
        element.GetTreeScope().getElementById(form_id);
    new_form = DynamicTo<HTMLFormElement>(new_form_candidate);
  } else {
    // 5. Otherwise, if element has an ancestor form element, then associate
    //    element with the nearest such ancestor form element.
    new_form = nearest_form;
  }

  SetForm(new_form);
}

void ListedElement::FormAttributeChanged() {
  ResetFormOwner();
  ResetFormAttributeTargetObserver();
}

bool ListedElement::RecalcWillValidate() const {
  const HTMLElement& element = ToHTMLElement();
  if (data_list_ancestor_state_ == DataListAncestorState::kUnknown) {
    if (element.GetDocument().HasAtLeastOneDataList() &&
        Traversal<HTMLDataListElement>::FirstAncestor(element)) {
      data_list_ancestor_state_ = DataListAncestorState::kInsideDataList;
    } else {
      data_list_ancestor_state_ = DataListAncestorState::kNotInsideDataList;
    }
  }
  return data_list_ancestor_state_ ==
             DataListAncestorState::kNotInsideDataList &&
         !element.IsDisabledFormControl() && !is_readonly_;
}

bool ListedElement::WillValidate() const {
  if (!will_validate_initialized_ ||
      data_list_ancestor_state_ == DataListAncestorState::kUnknown) {
    const_cast<ListedElement*>(this)->UpdateWillValidateCache();
  } else {
    // If the following assertion fails, UpdateWillValidateCache() is not
    // called correctly when something which changes RecalcWillValidate() result
    // is updated.
    DCHECK_EQ(will_validate_, RecalcWillValidate());
  }
  return will_validate_;
}

void ListedElement::UpdateWillValidateCache(WillValidateReason reason) {
  // We need to recalculate willValidate immediately because willValidate change
  // can causes style change.
  bool new_will_validate = RecalcWillValidate();
  if (will_validate_initialized_ && will_validate_ == new_will_validate)
    return;
  will_validate_initialized_ = true;
  will_validate_ = new_will_validate;

  if (reason != WillValidateReason::kForInsertionOrRemoval) {
    // Needs to force SetNeedsValidityCheck() to invalidate validity state of
    // FORM/FIELDSET. If this element updates willValidate twice and
    // IsValidElement() is not called between them, the second call of this
    // function still has validity_is_dirty_==true, which means
    // SetNeedsValidityCheck() doesn't invalidate validity state of
    // FORM/FIELDSET.
    validity_is_dirty_ = false;
    SetNeedsValidityCheck();
    // No need to trigger style recalculation here because
    // SetNeedsValidityCheck() does it in the right away. This relies on
    // the assumption that Valid() is always true if willValidate() is false.

    if (!will_validate_) {
      HideVisibleValidationMessage();
    }
  } else {
    // We don't need to do any of the work above for insertion or removal,
    // because:
    //
    // * We don't need to notify that pseudo-states on this element have
    //   changed because it wasn't previously in the tree (or won't be in the
    //   tree shortly).
    // * FormOwnerSetNeedsValidityCheck is also called when changing the form
    // * FieldSetAncestorsSetNeedsValidityCheck is also called on insertion
    //   and removal
    // * RemovedFrom already hides the validation message, so we don't need to
    //   update or hide it.
    validity_is_dirty_ = true;
  }
}

bool ListedElement::CustomError() const {
  return !custom_validation_message_.empty();
}

bool ListedElement::HasBadInput() const {
  return false;
}

bool ListedElement::PatternMismatch() const {
  return false;
}

bool ListedElement::RangeOverflow() const {
  return false;
}

bool ListedElement::RangeUnderflow() const {
  return false;
}

bool ListedElement::StepMismatch() const {
  return false;
}

bool ListedElement::TooLong() const {
  return false;
}

bool ListedElement::TooShort() const {
  return false;
}

bool ListedElement::TypeMismatch() const {
  return false;
}

bool ListedElement::Valid() const {
  bool some_error = TypeMismatch() || StepMismatch() || RangeUnderflow() ||
                    RangeOverflow() || TooLong() || TooShort() ||
                    PatternMismatch() || ValueMissing() || HasBadInput() ||
                    CustomError();
  return !some_error;
}

bool ListedElement::ValueMissing() const {
  return false;
}

String ListedElement::CustomValidationMessage() const {
  return custom_validation_message_;
}

void ListedElement::SetCustomValidationMessage(const String& message) {
  custom_validation_message_ = message;
}

String ListedElement::validationMessage() const {
  return ToHTMLElement().willValidate() && CustomError()
             ? custom_validation_message_
             : String();
}

String ListedElement::ValidationSubMessage() const {
  return String();
}

void ListedElement::setCustomValidity(const String& error) {
  SetCustomValidationMessage(error);
  SetNeedsValidityCheck();
}

void ListedElement::FindCustomValidationMessageTextDirection(
    const String& message,
    TextDirection& message_dir,
    String& sub_message,
    TextDirection& sub_message_dir) {
  message_dir = BidiParagraph::BaseDirectionForStringOrLtr(message);
  if (!sub_message.empty()) {
    sub_message_dir = ToHTMLElement().GetLayoutObject()->Style()->Direction();
  }
}

void ListedElement::UpdateVisibleValidationMessage() {
  Element& element = ValidationAnchor();
  Page* page = element.GetDocument().GetPage();
  if (!page || !page->IsPageVisible() || element.GetDocument().UnloadStarted())
    return;
  if (page->Paused())
    return;
  String message;
  if (element.GetLayoutObject() && WillValidate() &&
      ToHTMLElement().IsShadowIncludingInclusiveAncestorOf(element))
    message = validationMessage().StripWhiteSpace();

  has_validation_message_ = true;
  ValidationMessageClient* client = &page->GetValidationMessageClient();
  TextDirection message_dir = TextDirection::kLtr;
  TextDirection sub_message_dir = TextDirection::kLtr;
  String sub_message = ValidationSubMessage().StripWhiteSpace();
  if (message.empty()) {
    client->HideValidationMessage(element);
  } else {
    FindCustomValidationMessageTextDirection(message, message_dir, sub_message,
                                             sub_message_dir);
  }
  client->ShowValidationMessage(element, message, message_dir, sub_message,
                                sub_message_dir);
}

void ListedElement::HideVisibleValidationMessage() {
  if (!has_validation_message_)
    return;

  if (auto* client = GetValidationMessageClient())
    client->HideValidationMessage(ValidationAnchor());
}

bool ListedElement::IsValidationMessageVisible() const {
  if (!has_validation_message_)
    return false;

  if (auto* client = GetValidationMessageClient()) {
    return client->IsValidationMessageVisible(ValidationAnchor());
  }
  return false;
}

ValidationMessageClient* ListedElement::GetValidationMessageClient() const {
  if (Page* page = ToHTMLElement().GetDocument().GetPage())
    return &page->GetValidationMessageClient();
  return nullptr;
}

Element& ListedElement::ValidationAnchor() const {
  return const_cast<HTMLElement&>(ToHTMLElement());
}

bool ListedElement::ValidationAnchorOrHostIsFocusable() const {
  const Element& anchor = ValidationAnchor();
  const HTMLElement& host = ToHTMLElement();
  if (anchor.IsFocusable())
    return true;
  if (&anchor == &host)
    return false;
  return host.IsFocusable();
}

bool ListedElement::checkValidity(List* unhandled_invalid_controls) {
  if (IsNotCandidateOrValid())
    return true;
  HTMLElement& element = ToHTMLElement();
  Document* original_document = &element.GetDocument();
  DispatchEventResult dispatch_result = element.DispatchEvent(
      *Event::CreateCancelable(event_type_names::kInvalid));
  if (dispatch_result == DispatchEventResult::kNotCanceled &&
      unhandled_invalid_controls && element.isConnected() &&
      original_document == element.GetDocument())
    unhandled_invalid_controls->push_back(this);
  return false;
}

void ListedElement::ShowValidationMessage() {
  Element& element = ValidationAnchor();
  element.scrollIntoViewIfNeeded(false);
  if (element.IsFocusable())
    element.Focus();
  else
    ToHTMLElement().Focus();
  UpdateVisibleValidationMessage();
}

bool ListedElement::reportValidity() {
  List unhandled_invalid_controls;
  bool is_valid = checkValidity(&unhandled_invalid_controls);
  if (is_valid || unhandled_invalid_controls.empty())
    return is_valid;
  DCHECK_EQ(unhandled_invalid_controls.size(), 1u);
  DCHECK_EQ(unhandled_invalid_controls[0].Get(), this);
  ShowValidationMessage();
  return false;
}

bool ListedElement::IsValidElement() {
  if (validity_is_dirty_) {
    is_valid_ = !WillValidate() || Valid();
    validity_is_dirty_ = false;
  } else {
    // If the following assertion fails, SetNeedsValidityCheck() is not
    // called correctly when something which changes validity is updated.
    DCHECK_EQ(is_valid_, (!WillValidate() || Valid()));
  }
  return is_valid_;
}

bool ListedElement::IsNotCandidateOrValid() {
  // Apply Element::willValidate(), not ListedElement::WillValidate(), because
  // some elements override willValidate().
  return !ToHTMLElement().willValidate() || IsValidElement();
}

void ListedElement::SetNeedsValidityCheck() {
  HTMLElement& element = ToHTMLElement();
  if (!validity_is_dirty_) {
    validity_is_dirty_ = true;
    FormOwnerSetNeedsValidityCheck();
    FieldSetAncestorsSetNeedsValidityCheck(element.parentNode(),
                                           StartingNodeType::IS_PARENT);
    element.PseudoStateChanged(CSSSelector::kPseudoValid);
    element.PseudoStateChanged(CSSSelector::kPseudoInvalid);
    element.PseudoStateChanged(CSSSelector::kPseudoUserValid);
    element.PseudoStateChanged(CSSSelector::kPseudoUserInvalid);
  }

  // Updates only if this control already has a validation message.
  if (IsValidationMessageVisible()) {
    // Calls UpdateVisibleValidationMessage() even if is_valid_ is not
    // changed because a validation message can be changed.
    element.GetDocument()
        .GetTaskRunner(TaskType::kDOMManipulation)
        ->PostTask(FROM_HERE,
                   WTF::BindOnce(&ListedElement::UpdateVisibleValidationMessage,
                                 WrapPersistent(this)));
  }
}

void ListedElement::DisabledAttributeChanged() {
  HTMLElement& element = ToHTMLElement();
  is_element_disabled_ = element.FastHasAttribute(html_names::kDisabledAttr);
  UpdateWillValidateCache();
  element.PseudoStateChanged(CSSSelector::kPseudoDisabled);
  element.PseudoStateChanged(CSSSelector::kPseudoEnabled);
  DisabledStateMightBeChanged();
}

void ListedElement::ReadonlyAttributeChanged() {
  is_readonly_ = ToHTMLElement().FastHasAttribute(html_names::kReadonlyAttr);
  UpdateWillValidateCache();
}

void ListedElement::UpdateAncestorDisabledState() const {
  ancestor_disabled_state_ = AncestorDisabledState::kEnabled;
  const HTMLElement& element = ToHTMLElement();
  if (may_have_fieldset_ancestor_ &&
      element.GetDocument().HasAtLeastOneDisabledFieldset()) {
    may_have_fieldset_ancestor_ = false;
    ContainerNode* last_legend_ancestor = nullptr;
    for (auto* ancestor = Traversal<HTMLElement>::FirstAncestor(element);
         ancestor;
         ancestor = Traversal<HTMLElement>::FirstAncestor(*ancestor)) {
      if (IsA<HTMLLegendElement>(*ancestor)) {
        last_legend_ancestor = ancestor;
        continue;
      }
      if (HTMLFieldSetElement* fieldset_ancestor =
              DynamicTo<HTMLFieldSetElement>(ancestor)) {
        may_have_fieldset_ancestor_ = true;
        if (fieldset_ancestor->is_element_disabled_) {
          if (last_legend_ancestor &&
              last_legend_ancestor == fieldset_ancestor->Legend()) {
            continue;
          }
          ancestor_disabled_state_ = AncestorDisabledState::kDisabled;
          break;
        }
      }
    }
  }
}

void ListedElement::AncestorDisabledStateWasChanged() {
  ancestor_disabled_state_ = AncestorDisabledState::kUnknown;
  DisabledAttributeChanged();
}

bool ListedElement::IsActuallyDisabled() const {
  if (is_element_disabled_)
    return true;
  if (ancestor_disabled_state_ == AncestorDisabledState::kUnknown)
    UpdateAncestorDisabledState();
  return ancestor_disabled_state_ == AncestorDisabledState::kDisabled;
}

bool ListedElement::ClassSupportsStateRestore() const {
  return false;
}

bool ListedElement::ShouldSaveAndRestoreFormControlState() const {
  return false;
}

FormControlState ListedElement::SaveFormControlState() const {
  return FormControlState();
}

void ListedElement::RestoreFormControlState(const FormControlState& state) {}

void ListedElement::NotifyFormStateChanged() {
  Document& doc = ToHTMLElement().GetDocument();
  // This can be called during fragment parsing as a result of option
  // selection before the document is active (or even in a frame).
  if (!doc.IsActive())
    return;
  doc.GetFrame()->Client()->DidUpdateCurrentHistoryItem();
}

void ListedElement::TakeStateAndRestore() {
  if (ClassSupportsStateRestore()) {
    ToHTMLElement().GetDocument().GetFormController().RestoreControlStateFor(
        *this);
  }
}

void ListedElement::SetFormAttributeTargetObserver(
    FormAttributeTargetObserver* new_observer) {
  if (form_attribute_target_observer_)
    form_attribute_target_observer_->Unregister();
  form_attribute_target_observer_ = new_observer;
}

void ListedElement::ResetFormAttributeTargetObserver() {
  HTMLElement& element = ToHTMLElement();
  const AtomicString& form_id(element.FastGetAttribute(html_names::kFormAttr));
  if (!form_id.IsNull() && element.isConnected()) {
    SetFormAttributeTargetObserver(
        MakeGarbageCollected<FormAttributeTargetObserver>(form_id, this));
  } else {
    SetFormAttributeTargetObserver(nullptr);
  }
}

void ListedElement::FormAttributeTargetChanged() {
  ResetFormOwner();
}

const AtomicString& ListedElement::GetName() const {
  const AtomicString& name = ToHTMLElement().GetNameAttribute();
  return name.IsNull() ? g_empty_atom : name;
}

bool ListedElement::IsFormControlElement() const {
  return false;
}

bool ListedElement::IsFormControlElementWithState() const {
  return false;
}

bool ListedElement::IsElementInternals() const {
  return false;
}

bool ListedElement::IsObjectElement() const {
  return false;
}

ListedElement* ListedElement::From(Element& element) {
  auto* html_element = DynamicTo<HTMLElement>(element);
  if (!html_element)
    return nullptr;
  if (auto* form_control_element = DynamicTo<HTMLFormControlElement>(element))
    return form_control_element;
  if (html_element->IsFormAssociatedCustomElement())
    return &element.EnsureElementInternals();
  if (auto* object = DynamicTo<HTMLObjectElement>(html_element))
    return object;
  return nullptr;
}

const HTMLElement& ListedElement::ToHTMLElement() const {
  if (auto* form_control_element = DynamicTo<HTMLFormControlElement>(*this)) {
    return *form_control_element;
  }
  if (auto* element_internals = DynamicTo<ElementInternals>(*this)) {
    return element_internals->Target();
  }
  return To<HTMLObjectElement>(*this);
}

HTMLElement& ListedElement::ToHTMLElement() {
  return const_cast<HTMLElement&>(
      static_cast<const ListedElement&>(*this).ToHTMLElement());
}

FormAttributeTargetObserver::FormAttributeTargetObserver(const AtomicString& id,
                                                         ListedElement* element)
    : IdTargetObserver(element->ToHTMLElement()
                           .GetTreeScope()
                           .EnsureIdTargetObserverRegistry(),
                       id),
      element_(element) {}

void FormAttributeTargetObserver::Trace(Visitor* visitor) const {
  visitor->Trace(element_);
  IdTargetObserver::Trace(visitor);
}

void FormAttributeTargetObserver::IdTargetChanged() {
  element_->FormAttributeTargetChanged();
}

}  // namespace blink
```