Response:
Let's break down the thought process to generate the detailed explanation of `element_internals.cc`.

1. **Understand the Core Purpose:** The first step is to recognize the file name `element_internals.cc` and its location within the Blink rendering engine. The name strongly suggests it's about the internal workings of HTML elements, specifically in the context of custom elements. The `custom` directory further reinforces this.

2. **Identify Key Concepts from Includes:**  The `#include` directives are crucial for understanding the file's functionality. I'd scan these and mentally categorize them:

    * **Binding/V8:**  `FrozenArray.h`, `V8_union_file_formdata_usvstring.h`, `V8_validity_state_flags.h`  ->  Indicates interaction with JavaScript, specifically handling data types and validation.
    * **Core DOM:** `Node_lists_node_data.h`, `execution_context.h`, `dom/node_lists_node_data.h` -> General DOM manipulation and execution context.
    * **File API:** `file.h` -> Handling file uploads.
    * **Custom Elements:** `custom_element.h`, `custom_element_registry.h`, `custom_state_set.h` -> The central focus: managing custom element behavior.
    * **Forms:** `form_controller.h`, `form_data.h`, `html_field_set_element.h`, `html_form_element.h`, `validity_state.h` -> How custom elements integrate with HTML forms.
    * **Accessibility:** `ax_object_cache.h` ->  Accessibility implications.
    * **Base HTML:** `html_element.h` -> The fundamental HTML element class.

3. **Analyze Class Structure:**  The file defines the `ElementInternals` class. This is the primary entity to understand. I'd look at its members and methods.

4. **Categorize Member Variables:**  Group the member variables by their apparent purpose:

    * **Target Element:** `target_` -  The HTML element this `ElementInternals` object is associated with.
    * **Form Data:** `value_`, `state_` -  Representing the value and state of the element within a form.
    * **Validation:** `validity_flags_`, `validation_anchor_` - Handling custom validation logic.
    * **Custom State:** `custom_states_` - Managing custom states for the element.
    * **Accessibility Attributes:** `accessibility_semantics_map_`, `explicitly_set_attr_elements_map_` - Storing ARIA attributes and element references.
    * **Disabled State:** `is_disabled_` - Tracking the disabled state.

5. **Categorize Methods:**  Group the methods based on their function:

    * **Form Integration:** `setFormValue`, `form`, `AppendToFormData`, `DidChangeForm`, `SaveFormControlState`, `RestoreFormControlState`.
    * **Validation:** `setValidity`, `willValidate`, `validity`, `ValidationMessageForBinding`, `validationMessage`, `ValidationSubMessage`, `ValidationAnchor`, `checkValidity`, `reportValidity`.
    * **Custom State:** `states`, `HasState`.
    * **Accessibility:** `FastGetAttribute`, `GetAttributes`, `setAttribute`, `HasAttribute`, (and the specific ARIA attribute setters/getters).
    * **Shadow DOM:** `shadowRoot`.
    * **Lifecycle/Upgrades:** `DidUpgrade`, `DisabledStateMightBeChanged`.
    * **Internal Helpers:**  The anonymous namespace functions like `IsValidityStateFlagsValid`, `AppendToFormControlState`, `RestoreFromFormControlState`.
    * **Type Checking:** `IsTargetFormAssociated`, `IsElementInternals`, `IsEnumeratable`, `ClassSupportsStateRestore`, `ShouldSaveAndRestoreFormControlState`.

6. **Connect Concepts to Web Technologies:**  For each category of methods/members, consider how they relate to JavaScript, HTML, and CSS:

    * **JavaScript:**  The setters and getters for form values, validity, and ARIA attributes are directly accessible from JavaScript. The `states()` API allows JavaScript to manipulate custom element states. The callbacks (`EnqueueFormAssociatedCallback`, `EnqueueFormDisabledCallback`, `EnqueueFormStateRestoreCallback`) are triggered by JavaScript actions or DOM changes.
    * **HTML:**  The form integration is central to how custom elements participate in HTML forms. The ARIA attributes directly correspond to HTML attributes. The shadow DOM interaction affects how elements are rendered.
    * **CSS:** The custom states can be targeted by CSS pseudo-classes (`:state(...)`).

7. **Illustrate with Examples:**  Concrete examples are essential for clarity. For each area of functionality, create simple HTML/JavaScript snippets to demonstrate how the `ElementInternals` API is used indirectly through the custom element.

8. **Consider User/Developer Errors:** Think about common mistakes developers might make when working with custom elements and form integration, such as forgetting to implement form-associated callbacks, setting invalid validity states, or mishandling ARIA attributes.

9. **Infer User Actions:**  Trace back how a user's interaction with a web page (e.g., filling out a form, clicking a button) might lead to the execution of code within `element_internals.cc`. This involves understanding the event flow and how form submissions work.

10. **Structure the Explanation:** Organize the information logically, starting with a high-level overview and then diving into specific functionalities. Use clear headings and bullet points to improve readability. Emphasize the relationships between the C++ code and the web technologies.

11. **Review and Refine:** After drafting the explanation, review it for accuracy, clarity, and completeness. Ensure the examples are correct and easy to understand. Check for any technical jargon that needs further explanation. Make sure the assumed inputs and outputs for logical reasoning are clear and representative.

Self-Correction Example during the process:

* **Initial thought:** "This file just handles form submission for custom elements."
* **Correction:** "While form submission is a key part, the includes and methods related to validity, ARIA attributes, and custom states show it's much broader than just form submission. It's about the *internal* management of a form-associated custom element's properties and behavior within the rendering engine."  This correction leads to a more comprehensive explanation.

By following this systematic approach, which combines code analysis, conceptual understanding, and illustrative examples, a detailed and informative explanation of `element_internals.cc` can be generated.
这个文件 `blink/renderer/core/html/custom/element_internals.cc` 是 Chromium Blink 渲染引擎中关于自定义元素内部实现的核心组件。它为自定义元素提供了与浏览器内置元素相似的功能，特别是与 HTML 表单相关的能力和可访问性支持。

以下是它的主要功能，以及与 JavaScript、HTML 和 CSS 的关系：

**主要功能:**

1. **表单集成 (Form Integration):**
   - **管理表单值 (Form Value Management):** 允许自定义元素像标准的表单控件一样参与表单提交。它存储和管理自定义元素的当前值 (`value_`) 和状态 (`state_`)。
   - **关联到表单 (Form Association):** 确定自定义元素是否与某个 HTML 表单关联 (`IsTargetFormAssociated`)，并获取关联的表单元素 (`form()`).
   - **自定义校验 (Custom Validation):** 允许自定义元素定义自己的验证逻辑，设置验证状态 (`setValidity`)，获取验证消息 (`validationMessage`)，并触发校验 (`checkValidity`, `reportValidity`).
   - **与 `<label>` 元素关联 (Label Association):** 支持通过 `<label>` 元素关联自定义元素 (`labels()`).
   - **保存和恢复表单状态 (Save and Restore Form State):**  允许浏览器在页面导航或刷新时保存和恢复自定义元素的表单状态 (`SaveFormControlState`, `RestoreFormControlState`).
   - **`FormData` 集成 (FormData Integration):**  提供将自定义元素的值添加到 `FormData` 对象的方法，用于表单提交 (`AppendToFormData`).
   - **禁用状态 (Disabled State):** 管理自定义元素的禁用状态，并触发相应的回调 (`DisabledStateMightBeChanged`).
   - **`formAssociated` 生命周期回调:**  在自定义元素关联或解除关联表单时触发 JavaScript 回调 (`DidChangeForm`).
   - **`formDisabledCallback` 生命周期回调:** 在自定义元素禁用状态改变时触发 JavaScript 回调.
   - **`formStateRestoreCallback` 生命周期回调:** 在表单状态恢复时触发 JavaScript 回调.

2. **可访问性 (Accessibility):**
   - **管理 ARIA 属性 (ARIA Attribute Management):** 允许通过 `ElementInternals` 对象设置和获取 ARIA 属性，从而增强自定义元素的可访问性 (`setAttribute`, `GetAttribute`, 以及 `ariaControlsElements`, `ariaDescribedByElements` 等具体的 ARIA 属性访问器). 这些属性会影响浏览器辅助技术（如屏幕阅读器）如何理解和呈现自定义元素。
   - **关联元素 (Element Association):**  支持关联其他元素作为 ARIA 属性的值 (例如 `aria-labelledby`, `aria-describedby`)，通过 `SetElementAttribute` 和 `GetElementAttribute` 等方法实现。

3. **自定义状态 (Custom States):**
   - **管理自定义状态 (Custom State Management):** 允许自定义元素定义和管理自己的状态，这些状态可以通过 CSS 伪类 `:state(...)` 进行样式化 (`states()`, `HasState`).

4. **Shadow DOM 集成 (Shadow DOM Integration):**
   - **访问 Shadow Root:** 提供访问自定义元素 Shadow DOM 的能力 (`shadowRoot()`).

**与 JavaScript, HTML, CSS 的关系和举例说明:**

* **JavaScript:**
    - **API 暴露:** `ElementInternals` 实例可以通过自定义元素的 `attachInternals()` 方法获取，从而让 JavaScript 代码能够调用其上的方法。
    - **表单值操作:** JavaScript 可以使用 `elementInternals.setFormValue(value, state)` 来设置自定义元素的表单值和状态。
    - **自定义验证:** JavaScript 可以使用 `elementInternals.setValidity(flags, message, anchor)` 来设置自定义元素的验证状态、消息以及关联的锚点元素。
    - **可访问性属性:** JavaScript 可以使用 `elementInternals.setAttribute('aria-label', 'my label')` 或 `elementInternals.ariaLabelledByElements = [otherElement]` 来设置 ARIA 属性。
    - **自定义状态:** JavaScript 可以使用 `elementInternals.states.add('active')` 来添加自定义状态。

    **假设输入与输出 (逻辑推理):**
    ```javascript
    // HTML: <my-element></my-element>
    const myElement = document.querySelector('my-element');
    const internals = myElement.attachInternals();

    // 假设输入：设置表单值为 "hello"
    internals.setFormValue("hello");

    // 预期输出：当表单提交时，该自定义元素的值会作为 "hello" 提交。
    ```

* **HTML:**
    - **自定义元素定义:**  `ElementInternals` 的功能是为自定义元素服务的，因此它与自定义元素的声明和使用息息相关。
    - **表单关联:**  自定义元素可以通过设置 `formAssociated` 静态属性为 `true` 来表明其与表单的关联。
    - **ARIA 属性:**  通过 `ElementInternals` 设置的 ARIA 属性会反映在 HTML 元素上，影响辅助技术的解析。

    **用户操作如何到达这里:**
    1. **开发者定义自定义元素:**  开发者使用 JavaScript 定义了一个 `formAssociated` 为 `true` 的自定义元素。
    2. **用户在 HTML 中使用自定义元素:** 用户在一个包含表单的 HTML 页面中使用了这个自定义元素 `<my-custom-input name="myInput"></my-custom-input>`.
    3. **JavaScript 操作 `ElementInternals`:** 自定义元素的 JavaScript 代码通过 `this.attachInternals()` 获取 `ElementInternals` 实例，并调用其方法来管理表单值、验证或 ARIA 属性。
    4. **用户与页面交互:** 用户与包含该自定义元素的表单进行交互，例如输入内容。
    5. **表单提交:** 用户点击提交按钮，浏览器会调用 `ElementInternals` 中定义的逻辑来获取自定义元素的值并将其包含在表单数据中。

* **CSS:**
    - **自定义状态选择器:** CSS 可以使用 `:state(...)` 伪类来根据自定义元素的状态应用样式。例如，`my-element:state(active) { color: red; }`。

    **假设输入与输出 (逻辑推理):**
    ```javascript
    // JavaScript:
    const myElement = document.querySelector('my-element');
    const internals = myElement.attachInternals();
    internals.states.add('loading');

    // CSS:
    my-element:state(loading) {
      background-color: yellow;
    }

    // 假设输入：JavaScript 代码添加了 'loading' 状态。
    // 预期输出：该自定义元素的背景颜色会变为黄色。
    ```

**用户或编程常见的使用错误举例:**

1. **忘记设置 `formAssociated`:**  如果自定义元素需要参与表单提交，但开发者忘记在自定义元素类上设置 `static formAssociated = true;`，那么 `ElementInternals` 的表单相关功能将不会生效。
2. **在构造函数中调用 `ElementInternals` 的表单相关方法:** 在自定义元素的构造函数中过早地调用 `ElementInternals` 的表单相关方法可能会导致错误，因为元素可能尚未完全连接到 DOM 或与表单关联。
3. **不正确地使用 `setValidity`:**  错误地设置 `ValidityStateFlags` 或不提供清晰的错误消息，会导致用户体验不佳。例如，设置了 `valueMissing` 但没有提供提示用户缺少值的消息。
4. **混淆 ARIA 属性的使用:**  错误地使用 ARIA 属性可能会导致可访问性问题，例如使用了不合适的 ARIA 角色或属性。
5. **没有正确处理 `formDisabledCallback`:**  自定义元素可能需要根据其禁用状态更新其内部状态或外观，如果开发者没有正确实现 `formDisabledCallback`，可能会导致 UI 不一致。
6. **在 `RestoreFormControlState` 中假设数据格式:**  在恢复表单状态时，如果假设了特定的数据格式但实际数据不匹配，可能会导致恢复失败或错误行为。

**用户操作一步步到达这里 (以表单提交为例):**

1. **用户打开一个包含自定义表单元素的网页。**
2. **自定义元素的 JavaScript 代码在元素连接到 DOM 后 (通常在 `connectedCallback` 中) 调用 `this.attachInternals()` 获取 `ElementInternals` 实例。**
3. **用户在自定义表单元素中输入数据。**  自定义元素的内部逻辑可能会使用 `elementInternals.setFormValue()` 更新其值。
4. **用户点击表单的提交按钮。**
5. **浏览器开始处理表单提交。**
6. **对于每个表单控件（包括自定义元素），浏览器会调用其相应的逻辑来获取其值。** 对于自定义元素，会调用 `ElementInternals` 的 `AppendToFormData()` 方法。
7. **`AppendToFormData()` 方法会根据自定义元素存储的 `value_` 将其值添加到 `FormData` 对象中。**
8. **浏览器将 `FormData` 对象发送到服务器。**

总而言之，`element_internals.cc` 是连接自定义元素与浏览器核心功能（特别是表单和可访问性）的关键桥梁，它提供了让自定义元素表现得像内置 HTML 元素所需的底层机制。开发者通过 `attachInternals()` API 与这个 C++ 组件进行交互，从而增强自定义元素的功能和互操作性。

### 提示词
```
这是目录为blink/renderer/core/html/custom/element_internals.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/custom/element_internals.h"

#include "third_party/blink/renderer/bindings/core/v8/frozen_array.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_file_formdata_usvstring.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_validity_state_flags.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/node_lists_node_data.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_registry.h"
#include "third_party/blink/renderer/core/html/custom/custom_state_set.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/html/forms/html_field_set_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/validity_state.h"
#include "third_party/blink/renderer/core/html/html_element.h"

namespace blink {

namespace {

bool IsValidityStateFlagsValid(const ValidityStateFlags* flags) {
  if (!flags)
    return true;
  if (flags->badInput() || flags->customError() || flags->patternMismatch() ||
      flags->rangeOverflow() || flags->rangeUnderflow() ||
      flags->stepMismatch() || flags->tooLong() || flags->tooShort() ||
      flags->typeMismatch() || flags->valueMissing())
    return false;
  return true;
}

void AppendToFormControlState(const V8ControlValue& value,
                              FormControlState& state) {
  switch (value.GetContentType()) {
    case V8ControlValue::ContentType::kFile: {
      state.Append("File");
      value.GetAsFile()->AppendToControlState(state);
      break;
    }
    case V8ControlValue::ContentType::kFormData: {
      state.Append("FormData");
      value.GetAsFormData()->AppendToControlState(state);
      break;
    }
    case V8ControlValue::ContentType::kUSVString: {
      state.Append("USVString");
      state.Append(value.GetAsUSVString());
      break;
    }
  }
}

const V8ControlValue* RestoreFromFormControlState(
    ExecutionContext& execution_context,
    const FormControlState& state,
    const StringView& section_title,
    wtf_size_t& index) {
  if (state.ValueSize() < index + 3) {
    return nullptr;
  }
  if (state[index] != section_title) {
    return nullptr;
  }
  const V8ControlValue* restored_value = nullptr;
  const String& entry_type = state[index + 1];
  index += 2;
  if (entry_type == "USVString") {
    restored_value = MakeGarbageCollected<V8ControlValue>(state[index++]);
  } else if (entry_type == "File") {
    if (auto* file =
            File::CreateFromControlState(&execution_context, state, index)) {
      restored_value = MakeGarbageCollected<V8ControlValue>(file);
    }
  } else if (entry_type == "FormData") {
    if (auto* form_data =
            FormData::CreateFromControlState(execution_context, state, index)) {
      restored_value = MakeGarbageCollected<V8ControlValue>(form_data);
    }
  } else {
    NOTREACHED();
  }
  return restored_value;
}

}  // namespace

ElementInternals::ElementInternals(HTMLElement& target) : target_(target) {
}

void ElementInternals::Trace(Visitor* visitor) const {
  visitor->Trace(target_);
  visitor->Trace(value_);
  visitor->Trace(state_);
  visitor->Trace(validity_flags_);
  visitor->Trace(validation_anchor_);
  visitor->Trace(custom_states_);
  visitor->Trace(explicitly_set_attr_elements_map_);
  ListedElement::Trace(visitor);
  ScriptWrappable::Trace(visitor);
  ElementRareDataField::Trace(visitor);
}

void ElementInternals::setFormValue(const V8ControlValue* value,
                                    ExceptionState& exception_state) {
  setFormValue(value, value, exception_state);
}

void ElementInternals::setFormValue(const V8ControlValue* value,
                                    const V8ControlValue* state,
                                    ExceptionState& exception_state) {
  if (!IsTargetFormAssociated()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The target element is not a form-associated custom element.");
    return;
  }

  if (value && value->IsFormData()) {
    value_ = MakeGarbageCollected<V8ControlValue>(
        MakeGarbageCollected<FormData>(*value->GetAsFormData()));
  } else {
    value_ = value;
  }

  if (value == state) {
    state_ = value_;
  } else if (state && state->IsFormData()) {
    state_ = MakeGarbageCollected<V8ControlValue>(
        MakeGarbageCollected<FormData>(*state->GetAsFormData()));
  } else {
    state_ = state;
  }
  NotifyFormStateChanged();
}

HTMLFormElement* ElementInternals::form(ExceptionState& exception_state) const {
  if (!IsTargetFormAssociated()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The target element is not a form-associated custom element.");
    return nullptr;
  }
  return ListedElement::Form();
}

void ElementInternals::setValidity(ValidityStateFlags* flags,
                                   ExceptionState& exception_state) {
  setValidity(flags, String(), nullptr, exception_state);
}

void ElementInternals::setValidity(ValidityStateFlags* flags,
                                   const String& message,
                                   ExceptionState& exception_state) {
  setValidity(flags, message, nullptr, exception_state);
}

void ElementInternals::setValidity(ValidityStateFlags* flags,
                                   const String& message,
                                   HTMLElement* anchor,
                                   ExceptionState& exception_state) {
  if (!IsTargetFormAssociated()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The target element is not a form-associated custom element.");
    return;
  }
  // Custom element authors should provide a message. They can omit the message
  // argument only if nothing if | flags| is true.
  if (!IsValidityStateFlagsValid(flags) && message.empty()) {
    exception_state.ThrowTypeError(
        "The second argument should not be empty if one or more flags in the "
        "first argument are true.");
    return;
  }
  if (anchor && !Target().IsShadowIncludingAncestorOf(*anchor)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "The Element argument should be a shadow-including descendant of the "
        "target element.");
    return;
  }

  if (validation_anchor_ && validation_anchor_ != anchor) {
    HideVisibleValidationMessage();
  }
  validity_flags_ = flags;
  validation_anchor_ = anchor;
  SetCustomValidationMessage(message);
  SetNeedsValidityCheck();
}

bool ElementInternals::willValidate(ExceptionState& exception_state) const {
  if (!IsTargetFormAssociated()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The target element is not a form-associated custom element.");
    return false;
  }
  return WillValidate();
}

ValidityState* ElementInternals::validity(ExceptionState& exception_state) {
  if (!IsTargetFormAssociated()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The target element is not a form-associated custom element.");
    return nullptr;
  }
  return ListedElement::validity();
}

String ElementInternals::ValidationMessageForBinding(
    ExceptionState& exception_state) {
  if (!IsTargetFormAssociated()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The target element is not a form-associated custom element.");
    return String();
  }
  return validationMessage();
}

String ElementInternals::validationMessage() const {
  if (IsValidityStateFlagsValid(validity_flags_))
    return String();
  return CustomValidationMessage();
}

String ElementInternals::ValidationSubMessage() const {
  if (PatternMismatch())
    return Target().FastGetAttribute(html_names::kTitleAttr).GetString();
  return String();
}

Element& ElementInternals::ValidationAnchor() const {
  return validation_anchor_ ? *validation_anchor_ : Target();
}

bool ElementInternals::checkValidity(ExceptionState& exception_state) {
  if (!IsTargetFormAssociated()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The target element is not a form-associated custom element.");
    return false;
  }
  return ListedElement::checkValidity();
}

bool ElementInternals::reportValidity(ExceptionState& exception_state) {
  if (!IsTargetFormAssociated()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The target element is not a form-associated custom element.");
    return false;
  }
  return ListedElement::reportValidity();
}

LabelsNodeList* ElementInternals::labels(ExceptionState& exception_state) {
  if (!IsTargetFormAssociated()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The target element is not a form-associated custom element.");
    return nullptr;
  }
  return Target().labels();
}

CustomStateSet* ElementInternals::states() {
  if (!custom_states_)
    custom_states_ = MakeGarbageCollected<CustomStateSet>(Target());
  return custom_states_.Get();
}

bool ElementInternals::HasState(const AtomicString& state) const {
  return custom_states_ && custom_states_->Has(state);
}

ShadowRoot* ElementInternals::shadowRoot() const {
  if (ShadowRoot* shadow_root = Target().AuthorShadowRoot()) {
    return shadow_root->IsAvailableToElementInternals() ? shadow_root : nullptr;
  }
  return nullptr;
}

const AtomicString& ElementInternals::FastGetAttribute(
    const QualifiedName& attribute) const {
  const auto it = accessibility_semantics_map_.find(attribute);
  if (it == accessibility_semantics_map_.end())
    return g_null_atom;
  return it->value;
}

const HashMap<QualifiedName, AtomicString>& ElementInternals::GetAttributes()
    const {
  return accessibility_semantics_map_;
}

void ElementInternals::setAttribute(const QualifiedName& attribute,
                                    const AtomicString& value) {
  accessibility_semantics_map_.Set(attribute, value);
  if (AXObjectCache* cache = Target().GetDocument().ExistingAXObjectCache())
    cache->HandleAttributeChanged(attribute, &Target());
}

bool ElementInternals::HasAttribute(const QualifiedName& attribute) const {
  return accessibility_semantics_map_.Contains(attribute);
}

void ElementInternals::DidUpgrade() {
  ContainerNode* parent = Target().parentNode();
  if (!parent)
    return;
  InsertedInto(*parent);
  if (auto* owner_form = Form()) {
    if (auto* lists = owner_form->NodeLists())
      lists->InvalidateCaches(nullptr);
  }
  for (ContainerNode* node = parent; node; node = node->parentNode()) {
    if (IsA<HTMLFieldSetElement>(node)) {
      // TODO(tkent): Invalidate only HTMLFormControlsCollections.
      if (auto* lists = node->NodeLists())
        lists->InvalidateCaches(nullptr);
    }
  }
  Target().GetDocument().GetFormController().RestoreControlStateOnUpgrade(
      *this);
}

void ElementInternals::SetElementAttribute(const QualifiedName& attribute,
                                           Element* element) {
  if (!element) {
    explicitly_set_attr_elements_map_.erase(attribute);
    setAttribute(attribute, g_null_atom);
    return;
  }

  HeapVector<Member<Element>> vector;
  vector.push_back(element);
  FrozenArray<Element>* array =
      MakeGarbageCollected<FrozenArray<Element>>(std::move(vector));
  explicitly_set_attr_elements_map_.Set(attribute, array);

  // Ensure that the appropriate updates are made in the AXObjectCache, and that
  // these attributes are serialized to the browser.
  setAttribute(attribute, g_empty_atom);
}

Element* ElementInternals::GetElementAttribute(
    const QualifiedName& attribute) const {
  auto it = explicitly_set_attr_elements_map_.find(attribute);
  if (it == explicitly_set_attr_elements_map_.end()) {
    return nullptr;
  }

  FrozenArray<Element>* stored_elements = it->value.Get();
  DCHECK_EQ(stored_elements->size(), 1u);
  return stored_elements->front();
}

void ElementInternals::SetElementArrayAttribute(
    const QualifiedName& attribute,
    const HeapVector<Member<Element>>* given_elements) {
  if (!given_elements) {
    explicitly_set_attr_elements_map_.erase(attribute);
    setAttribute(attribute, g_empty_atom);
    return;
  }

  FrozenArray<Element>* frozen_elements =
      MakeGarbageCollected<FrozenArray<Element>>((std::move(*given_elements)));
  explicitly_set_attr_elements_map_.Set(attribute, frozen_elements);

  // Ensure that the appropriate updates are made in the AXObjectCache, and that
  // these attributes are serialized to the browser.
  setAttribute(attribute, g_empty_atom);
}

const FrozenArray<Element>* ElementInternals::GetElementArrayAttribute(
    const QualifiedName& attribute) const {
  auto it = explicitly_set_attr_elements_map_.find(attribute);
  if (it == explicitly_set_attr_elements_map_.end()) {
    return nullptr;
  }
  return it->value.Get();
}

const FrozenArray<Element>* ElementInternals::ariaControlsElements() const {
  return GetElementArrayAttribute(html_names::kAriaControlsAttr);
}
void ElementInternals::setAriaControlsElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaControlsAttr, given_elements);
}

const FrozenArray<Element>* ElementInternals::ariaDescribedByElements() const {
  return GetElementArrayAttribute(html_names::kAriaDescribedbyAttr);
}
void ElementInternals::setAriaDescribedByElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaDescribedbyAttr, given_elements);
}

const FrozenArray<Element>* ElementInternals::ariaDetailsElements() const {
  return GetElementArrayAttribute(html_names::kAriaDetailsAttr);
}
void ElementInternals::setAriaDetailsElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaDetailsAttr, given_elements);
}

const FrozenArray<Element>* ElementInternals::ariaErrorMessageElements() const {
  return GetElementArrayAttribute(html_names::kAriaErrormessageAttr);
}
void ElementInternals::setAriaErrorMessageElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaErrormessageAttr, given_elements);
}

const FrozenArray<Element>* ElementInternals::ariaFlowToElements() const {
  return GetElementArrayAttribute(html_names::kAriaFlowtoAttr);
}
void ElementInternals::setAriaFlowToElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaFlowtoAttr, given_elements);
}

const FrozenArray<Element>* ElementInternals::ariaLabelledByElements() const {
  return GetElementArrayAttribute(html_names::kAriaLabelledbyAttr);
}
void ElementInternals::setAriaLabelledByElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaLabelledbyAttr, given_elements);
}

const FrozenArray<Element>* ElementInternals::ariaOwnsElements() const {
  return GetElementArrayAttribute(html_names::kAriaOwnsAttr);
}
void ElementInternals::setAriaOwnsElements(
    HeapVector<Member<Element>>* given_elements) {
  SetElementArrayAttribute(html_names::kAriaOwnsAttr, given_elements);
}

bool ElementInternals::IsTargetFormAssociated() const {
  if (Target().IsFormAssociatedCustomElement())
    return true;
  // Custom element could be in the process of upgrading here, during which
  // it will have state kFailed or kPreCustomized according to:
  // https://html.spec.whatwg.org/multipage/custom-elements.html#upgrades
  if (Target().GetCustomElementState() != CustomElementState::kUndefined &&
      Target().GetCustomElementState() != CustomElementState::kFailed &&
      Target().GetCustomElementState() != CustomElementState::kPreCustomized) {
    return false;
  }
  // An element is in "undefined" state in its constructor JavaScript code.
  // ElementInternals needs to handle elements to be form-associated same as
  // form-associated custom elements because web authors want to call
  // form-related operations of ElementInternals in constructors.
  CustomElementRegistry* registry = CustomElement::Registry(Target());
  if (!registry)
    return false;
  auto* definition = registry->DefinitionForName(Target().localName());
  return definition && definition->IsFormAssociated();
}

bool ElementInternals::IsElementInternals() const {
  return true;
}

bool ElementInternals::IsEnumeratable() const {
  return true;
}

void ElementInternals::AppendToFormData(FormData& form_data) {
  if (Target().IsDisabledFormControl())
    return;

  if (!value_)
    return;

  const AtomicString& name = Target().FastGetAttribute(html_names::kNameAttr);
  if (!value_->IsFormData() && name.empty())
    return;

  switch (value_->GetContentType()) {
    case V8ControlValue::ContentType::kFile: {
      form_data.AppendFromElement(name, value_->GetAsFile());
      break;
    }
    case V8ControlValue::ContentType::kUSVString: {
      form_data.AppendFromElement(name, value_->GetAsUSVString());
      break;
    }
    case V8ControlValue::ContentType::kFormData: {
      for (const auto& entry : value_->GetAsFormData()->Entries()) {
        if (entry->isFile())
          form_data.append(entry->name(), entry->GetFile());
        else
          form_data.append(entry->name(), entry->Value());
      }
      break;
    }
  }
}

void ElementInternals::DidChangeForm() {
  ListedElement::DidChangeForm();
  CustomElement::EnqueueFormAssociatedCallback(Target(), Form());
}

bool ElementInternals::HasBadInput() const {
  return validity_flags_ && validity_flags_->badInput();
}

bool ElementInternals::PatternMismatch() const {
  return validity_flags_ && validity_flags_->patternMismatch();
}

bool ElementInternals::RangeOverflow() const {
  return validity_flags_ && validity_flags_->rangeOverflow();
}

bool ElementInternals::RangeUnderflow() const {
  return validity_flags_ && validity_flags_->rangeUnderflow();
}

bool ElementInternals::StepMismatch() const {
  return validity_flags_ && validity_flags_->stepMismatch();
}

bool ElementInternals::TooLong() const {
  return validity_flags_ && validity_flags_->tooLong();
}

bool ElementInternals::TooShort() const {
  return validity_flags_ && validity_flags_->tooShort();
}

bool ElementInternals::TypeMismatch() const {
  return validity_flags_ && validity_flags_->typeMismatch();
}

bool ElementInternals::ValueMissing() const {
  return validity_flags_ && validity_flags_->valueMissing();
}

bool ElementInternals::CustomError() const {
  return validity_flags_ && validity_flags_->customError();
}

void ElementInternals::DisabledStateMightBeChanged() {
  bool new_disabled = IsActuallyDisabled();
  if (is_disabled_ == new_disabled)
    return;
  is_disabled_ = new_disabled;
  CustomElement::EnqueueFormDisabledCallback(Target(), new_disabled);
}

bool ElementInternals::ClassSupportsStateRestore() const {
  return true;
}

bool ElementInternals::ShouldSaveAndRestoreFormControlState() const {
  // We don't save/restore control state in a form with autocomplete=off.
  return Target().isConnected() && (!Form() || Form()->ShouldAutocomplete());
}

FormControlState ElementInternals::SaveFormControlState() const {
  FormControlState state;
  if (value_) {
    state.Append("Value");
    AppendToFormControlState(*value_, state);
  }
  if (state_) {
    state.Append("State");
    AppendToFormControlState(*state_, state);
  }
  return state;
}

void ElementInternals::RestoreFormControlState(const FormControlState& state) {
  ExecutionContext* execution_context = target_->GetExecutionContext();
  wtf_size_t index = 0;

  // Per spec, the submission value shouldn't be automatically restored by the
  // UA, but Blink has been doing that.
  if (const V8ControlValue* restored_value = RestoreFromFormControlState(
          *execution_context, state, "Value", index)) {
    value_ = restored_value;
  }

  const V8ControlValue* restored_state =
      RestoreFromFormControlState(*execution_context, state, "State", index);
  if (restored_state) {
    CustomElement::EnqueueFormStateRestoreCallback(Target(), restored_state,
                                                   "restore");
  }
}

}  // namespace blink
```