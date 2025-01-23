Response:
My thought process to analyze the `HTMLFormControlElement.cc` file and generate the detailed explanation goes through several stages:

1. **Understanding the Goal:** The request asks for a comprehensive analysis of the file, including its functionality, relationships with web technologies (HTML, CSS, JavaScript), logic, potential user/programming errors, and how user actions lead to this code.

2. **Initial Scan and Keyword Identification:** I start by quickly reading through the code, looking for keywords and familiar concepts related to form controls. Keywords like "form," "input," "button," "select," "disabled," "readonly," "validation," "autofill," "popover," "event," and "attribute" immediately stand out. The includes also provide clues about dependencies and related functionalities (e.g., `HTMLFormElement.h`, `ValidityState.h`, `Event.h`).

3. **Deconstructing the File's Purpose:** Based on the initial scan, the file clearly defines the base class `HTMLFormControlElement`. This suggests it's a foundational class for all interactive form elements. I infer its core responsibilities revolve around:
    * Representing common properties and behaviors of form controls.
    * Handling attributes specific to form interaction.
    * Managing state related to forms (disabled, readonly, validation, autofill).
    * Interacting with the form element it belongs to.
    * Participating in form submission.
    * Handling events related to form controls.
    * Providing accessibility information.

4. **Identifying Key Functionalities (Listing):** I go through the public methods of the `HTMLFormControlElement` class, trying to categorize their functionalities. This leads to the initial list of functionalities provided in the answer, grouping related methods (e.g., form-related attributes, validation, state management).

5. **Connecting to Web Technologies (HTML, CSS, JavaScript):**  This is a crucial part. I consider how the methods and attributes defined in this C++ file relate to the corresponding concepts in HTML, CSS, and JavaScript.
    * **HTML:** The file directly handles HTML attributes like `formaction`, `formmethod`, `disabled`, `readonly`, `required`, `autofocus`, `autocomplete`, `popovertarget`, etc. I connect these C++ methods to their HTML counterparts and explain their purpose in the HTML context.
    * **CSS:** The code uses pseudo-classes like `:disabled`, `:read-only`, `:read-write`, `:required`, `:optional`, `:autofill`, `:autofill-selected`, and `:autofill-previewed`. I explain how these CSS pseudo-classes are affected by the state managed in this C++ file.
    * **JavaScript:**  The file doesn't directly execute JavaScript, but it provides the underlying implementation for form control behaviors that JavaScript can interact with. I mention how JavaScript can get and set properties, trigger validation, and handle events related to form controls.

6. **Illustrative Examples:** To make the connections to web technologies clearer, I create concrete examples of how these functionalities manifest in HTML, CSS, and JavaScript. These examples help demonstrate the practical implications of the code.

7. **Logic and Input/Output:** For methods with clear logical operations (like `formAction()`, `formEnctype()`, `IsDisabledFormControl()`, `willValidate()`), I try to infer the input (e.g., the value of an HTML attribute) and the output (e.g., a string, a boolean). This helps illustrate the data flow within the code.

8. **Identifying User/Programming Errors:**  I think about common mistakes developers might make when working with form controls. This includes:
    * Incorrectly setting form-related attributes.
    * Not handling form submission properly.
    * Confusing `disabled` and `readonly`.
    * Misunderstanding form validation.
    * Incorrectly using JavaScript to manipulate form controls.

9. **Tracing User Actions:** This requires imagining the user interacting with a webpage containing form elements. I consider actions like:
    * Typing in input fields.
    * Selecting options from dropdowns.
    * Clicking buttons.
    * Submitting forms.
    * Focusing and blurring elements.
    * Hovering over elements (especially relevant for popovers).

    Then, I try to connect these user actions to the code execution within `HTMLFormControlElement.cc`. For instance, clicking a submit button will eventually lead to form submission logic, which involves checking the `disabled` state of form controls. Hovering over an element with `popovertarget` triggers the logic within `HandlePopoverInvokerHovered`.

10. **Structuring the Answer:** I organize the information logically using headings and bullet points to make it easy to read and understand. I start with a summary of the file's purpose and then delve into the specifics.

11. **Refinement and Review:** After drafting the initial answer, I review it for accuracy, clarity, and completeness. I ensure the examples are correct and the explanations are easy to grasp. I also check if I've addressed all aspects of the original request. For example, making sure to mention the accessibility implications (`AXObjectCache`).

By following these steps, I can dissect the given C++ source file and generate a comprehensive explanation that addresses all the points raised in the prompt. The key is to connect the low-level C++ implementation to the higher-level concepts of web development.
这个文件 `blink/renderer/core/html/forms/html_form_control_element.cc` 是 Chromium Blink 渲染引擎中一个核心的文件，它定义了 `HTMLFormControlElement` 类。这个类是所有可参与表单交互的 HTML 元素的基类。简单来说，它为 `<input>`, `<textarea>`, `<select>`, `<button>`, `<fieldset>`, 和 `<output>` 等表单控件提供了通用的功能和行为。

以下是 `HTMLFormControlElement.cc` 的主要功能：

**1. 作为所有表单控件的基类:**

*   它定义了所有表单控件元素共有的属性和方法，例如与表单关联、禁用状态、只读状态、验证、自动填充等。
*   具体的表单控件元素（如 `HTMLInputElement`, `HTMLSelectElement`）会继承自这个基类，并实现特定于自身的功能。

**2. 处理与 HTML 表单的关联:**

*   **`form` 属性:**  通过 `form` 属性，表单控件可以显式地与一个 `<form>` 元素关联，即使它没有被包含在 `<form>` 标签内部。`FormAttributeChanged()` 方法处理 `form` 属性的变更。
    *   **HTML 示例:** `<input type="text" name="username" form="myForm">` 和 `<form id="myForm"></form>`，这里的 input 元素通过 `form="myForm"` 与 id 为 `myForm` 的表单关联。
*   **表单所有者:**  维护对所属 `HTMLFormElement` 的引用。`WillChangeForm()` 和 `DidChangeForm()` 在表单关联发生变化时被调用。

**3. 管理表单控件的状态:**

*   **`disabled` 属性:**  控制表单控件是否被禁用，禁用状态的控件无法交互。`DisabledAttributeChanged()` 处理 `disabled` 属性的变更，并会触发 `blur()` 事件如果被禁用的元素恰好是当前焦点元素。
    *   **HTML 示例:** `<input type="text" disabled>`，这个输入框将变成灰色且无法输入。
    *   **JavaScript 示例:** `document.getElementById("myInput").disabled = true;`
*   **`readonly` 属性:**  控制文本输入控件是否只读，只读状态下可以选中和复制，但不能编辑。`ReadonlyAttributeChanged()` 处理 `readonly` 属性的变更，并更新相应的 CSS 伪类（`:read-only` 和 `:read-write`）。
    *   **HTML 示例:** `<input type="text" value="不可修改" readonly>`
    *   **CSS 示例:** `input:read-only { background-color: #eee; }`
*   **`required` 属性:**  标记表单控件为必填项，在表单提交时会进行校验。`RequiredAttributeChanged()` 处理 `required` 属性的变更，并更新 CSS 伪类（`:required` 和 `:optional`）。
    *   **HTML 示例:** `<input type="text" required>`，如果未填写此项，表单提交会失败。
    *   **CSS 示例:** `input:required { border-left: 5px solid red; }`
*   **`autofocus` 属性:**  指定页面加载完成后该表单控件应自动获得焦点。`ParseAttribute()` 中处理 `autofocus` 属性。
    *   **HTML 示例:** `<input type="text" autofocus>`，页面加载后光标会自动定位到这个输入框。
*   **自动填充 (`autofill`) 状态:**  管理浏览器自动填充功能的状态。`SetAutofillState()` 方法用于设置自动填充状态，并更新相应的 CSS 伪类（`:autofill`, `:-webkit-autofill`, `:-webkit-autofill-selected`, `:-webkit-autofill-previewed`）。
    *   **CSS 示例:** `input:-webkit-autofill { ... }` 可以自定义自动填充时的样式。

**4. 处理表单提交相关的属性:**

*   **`formaction` 属性:**  覆盖表单本身的 `action` 属性，指定提交该控件所属表单时使用的 URL。
    *   **HTML 示例:** `<button formaction="/submit_special">特殊提交</button>`
*   **`formenctype` 属性:**  覆盖表单本身的 `enctype` 属性，指定提交该控件所属表单时使用的编码类型。
    *   **HTML 示例:** `<button formenctype="multipart/form-data">上传文件</button>`
*   **`formmethod` 属性:**  覆盖表单本身的 `method` 属性，指定提交该控件所属表单时使用的 HTTP 方法（GET 或 POST）。
    *   **HTML 示例:** `<button formmethod="get">使用 GET 提交</button>`
*   **`formnovalidate` 属性:**  覆盖表单本身的 `novalidate` 属性，指定提交该控件所属表单时不进行客户端验证。
    *   **HTML 示例:** `<button formnovalidate>跳过验证提交</button>`

**5. 处理验证:**

*   **`willValidate()` 方法:**  判断该控件是否会参与表单验证。
*   **`MatchesValidityPseudoClasses()` 方法:**  用于匹配 CSS 的 `:valid` 和 `:invalid` 伪类。
*   **`IsValidElement()` 方法:**  检查元素是否有效。
*   **`SetNeedsValidityCheck()` 方法:**  标记需要进行验证。

**6. 处理焦点:**

*   **`SupportsFocus()` 方法:**  判断该控件是否可以获得焦点。禁用的控件不可获得焦点。
*   **`IsKeyboardFocusable()` 方法:**  判断该控件是否可以通过键盘导航获得焦点。
*   **`ShouldHaveFocusAppearance()` 方法:**  判断该控件是否应该有焦点时的视觉效果（例如，外发光）。

**7. 处理弹出框 (`popover`) 目标:**

*   **`popovertarget` 属性:**  指定一个要切换其显示状态的弹出框元素 ID。
*   **`popoverTargetElement()` 方法:**  获取 `popovertarget` 属性指向的弹出框元素。
*   **`popoverTargetAction()` 方法:**  获取或设置 `popovertargetaction` 属性的值（"toggle", "show", "hide", "hover"）。
*   **`setPopoverTargetAction()` 方法:** 设置 `popovertargetaction` 属性。
*   **`HandlePopoverInvokerHovered()` 方法:**  处理鼠标悬停在作为弹出框触发器的表单控件上时的逻辑，用于实现 `popovertargetaction="hover"` 的效果。
    *   **HTML 示例:** `<button popovertarget="myPopover">切换弹出框</button> <div id="myPopover" popover>这是一个弹出框</div>`

**8. 处理非活动命令目标 (`interesttarget`):**

*   **`interestTargetElement()` 方法:** 获取 `interesttarget` 属性指向的元素。
*   **`interestAction()` 方法:** 获取 `interestaction` 属性的值。

**9. 处理默认事件 (`DefaultEventHandler`):**

*   处理 `DOMActivate` 事件，当表单控件被激活（例如，点击按钮）时触发。
*   如果按钮有 `popovertarget` 属性，则会根据 `popovertargetaction` 的值来显示或隐藏相应的弹出框。

**10. 其他功能:**

*   **`Reset()` 方法:**  重置表单控件到初始状态。
*   **`NameForAutofill()` 方法:**  返回用于自动填充的名称。
*   **`CloneNonAttributePropertiesFrom()` 方法:**  在克隆节点时复制非属性相关的属性。
*   **`AssociateWith()` 方法:**  将表单控件与指定的表单元素关联。
*   **`GetAxId()` 方法:**  获取辅助功能树的 ID。

**与 JavaScript, HTML, CSS 的关系及举例:**

*   **HTML:**  `HTMLFormControlElement` 直接对应于 HTML 中用于创建表单控件的各种标签。
    *   **例子:**  `<input type="text">`, `<button>`, `<select>`, `<textarea>` 等。文件中的方法和属性直接操作或反映这些 HTML 标签的属性。
*   **CSS:**  该文件通过 CSS 伪类（例如 `:disabled`, `:read-only`, `:required`, `:autofill`）来反映表单控件的状态，从而允许开发者使用 CSS 来定制不同状态下的样式。
    *   **例子:**
        ```css
        input:disabled {
            background-color: #ccc;
            cursor: not-allowed;
        }
        input:required {
            border-left: 3px solid red;
        }
        ```
*   **JavaScript:**  JavaScript 可以通过 DOM API 与这些表单控件进行交互，例如获取和设置属性值、监听事件、触发验证等。`HTMLFormControlElement` 提供了底层实现，使得 JavaScript 的操作能够生效。
    *   **例子:**
        ```javascript
        const inputElement = document.getElementById('myInput');
        inputElement.value = '新的值';
        inputElement.disabled = true;
        inputElement.addEventListener('change', function() {
            console.log('输入框的值已更改');
        });
        ```

**逻辑推理与假设输入输出:**

*   **假设输入:**  一个 `<input type="text" required>` 元素被添加到 DOM 中。
*   **输出:**  `RequiredAttributeChanged()` 方法会被调用，设置内部状态，并且如果存在布局对象，可能会触发样式重新计算，导致该输入框在某些浏览器中可能显示红色边框（通过 CSS 的 `:required` 伪类）。

*   **假设输入:**  用户点击了一个带有 `popovertarget="myPopover"` 的 `<button>` 元素。
*   **输出:**  `DefaultEventHandler()` 会被调用，检测到 `DOMActivate` 事件和 `popovertarget` 属性。它会找到 ID 为 `myPopover` 的元素，并根据 `popovertargetaction` 的值（默认为 "toggle"）来显示或隐藏该弹出框。

**用户或编程常见的使用错误:**

*   **混淆 `disabled` 和 `readonly`:**  新手开发者可能会混淆这两个属性的作用。`disabled` 完全禁用控件，使其无法交互，而 `readonly` 只禁止用户修改文本输入控件的值，但仍然可以选中和复制。
    *   **错误示例:**  希望用户不能修改输入框内容，但仍然希望其可以被表单提交，错误地使用了 `disabled` 而不是 `readonly`。
*   **忘记处理表单提交:**  即使 HTML 结构正确，如果没有在 JavaScript 中监听表单的 `submit` 事件并处理提交逻辑，表单数据可能无法正确发送到服务器。
*   **不理解表单控件的关联:**  不清楚 `form` 属性的作用，导致表单控件无法正确地与指定的表单关联。
*   **错误地使用验证属性:**  例如，将 `required` 属性添加到不应该必填的字段上，或者依赖客户端验证而忽略服务器端验证。
*   **在 JavaScript 中错误地修改表单控件的状态:**  例如，在不应该禁用的情况下禁用了表单控件，导致用户无法操作。

**用户操作如何一步步到达这里:**

1. **用户在浏览器中打开一个包含表单的网页。**
2. **浏览器解析 HTML 代码，创建 DOM 树。**  在这个过程中，会创建 `HTMLFormControlElement` 及其子类的对象来表示表单控件。
3. **用户与表单控件进行交互:**
    *   **输入文本:**  这可能会触发 `change` 或 `input` 事件，最终调用到与输入相关的 C++ 代码，这些代码可能会更新 `HTMLFormControlElement` 的内部状态。
    *   **点击按钮:**  如果按钮是提交按钮，可能会触发表单提交流程，涉及到 `HTMLFormControlElement` 的验证逻辑。如果按钮有 `popovertarget` 属性，则会触发 `DefaultEventHandler` 中的弹出框处理逻辑.
    *   **更改选择框的选项:**  会触发 `change` 事件，并可能影响到 `HTMLFormControlElement` 的状态。
    *   **将焦点移动到表单控件或从表单控件移开:**  会触发 `focus` 和 `blur` 事件，`HTMLFormControlElement` 会更新其焦点状态。
    *   **鼠标悬停在带有 `popovertargetaction="hover"` 的元素上:**  会触发 `mouseover` 事件，最终调用到 `HandlePopoverInvokerHovered` 来处理弹出框的显示。
4. **表单提交:**
    *   用户点击提交按钮或按下 Enter 键。
    *   浏览器会检查表单的验证状态，这会调用到 `HTMLFormControlElement` 的验证相关方法。
    *   如果验证通过，浏览器会根据表单的 `action` 和 `method` 属性发送请求。

总而言之，`HTMLFormControlElement.cc` 文件是 Blink 引擎中处理 HTML 表单控件的核心部分，它定义了所有表单控件共享的基础行为和属性，并与 HTML、CSS 和 JavaScript 紧密关联，共同实现了网页的表单交互功能。

### 提示词
```
这是目录为blink/renderer/core/html/forms/html_form_control_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"

#include "base/feature_list.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/web/web_form_related_change_type.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/css/selector_checker.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/popover_data.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/command_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_data_list_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/listed_element.h"
#include "third_party/blink/renderer/core/html/forms/validity_state.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

HTMLFormControlElement::HTMLFormControlElement(const QualifiedName& tag_name,
                                               Document& document)
    : HTMLElement(tag_name, document),
      autofill_state_(WebAutofillState::kNotFilled),
      blocks_form_submission_(false) {
  SetHasCustomStyleCallbacks();
}

HTMLFormControlElement::~HTMLFormControlElement() = default;

void HTMLFormControlElement::Trace(Visitor* visitor) const {
  ListedElement::Trace(visitor);
  HTMLElement::Trace(visitor);
}

String HTMLFormControlElement::formAction() const {
  const AtomicString& action = FastGetAttribute(html_names::kFormactionAttr);
  if (action.empty()) {
    return GetDocument().Url();
  }
  return GetDocument().CompleteURL(StripLeadingAndTrailingHTMLSpaces(action));
}

void HTMLFormControlElement::setFormAction(const AtomicString& value) {
  setAttribute(html_names::kFormactionAttr, value);
}

String HTMLFormControlElement::formEnctype() const {
  const AtomicString& form_enctype_attr =
      FastGetAttribute(html_names::kFormenctypeAttr);
  if (form_enctype_attr.IsNull())
    return g_empty_string;
  return FormSubmission::Attributes::ParseEncodingType(form_enctype_attr);
}

void HTMLFormControlElement::setFormEnctype(const AtomicString& value) {
  setAttribute(html_names::kFormenctypeAttr, value);
}

String HTMLFormControlElement::formMethod() const {
  const AtomicString& form_method_attr =
      FastGetAttribute(html_names::kFormmethodAttr);
  if (form_method_attr.IsNull())
    return g_empty_string;
  return FormSubmission::Attributes::MethodString(
      FormSubmission::Attributes::ParseMethodType(form_method_attr));
}

void HTMLFormControlElement::setFormMethod(const AtomicString& value) {
  setAttribute(html_names::kFormmethodAttr, value);
}

bool HTMLFormControlElement::FormNoValidate() const {
  return FastHasAttribute(html_names::kFormnovalidateAttr);
}

void HTMLFormControlElement::Reset() {
  SetAutofillState(WebAutofillState::kNotFilled);
  ResetImpl();
}

void HTMLFormControlElement::AttachLayoutTree(AttachContext& context) {
  HTMLElement::AttachLayoutTree(context);
  if (!GetLayoutObject()) {
    FocusabilityLost();
  }
}

void HTMLFormControlElement::DetachLayoutTree(bool performing_reattach) {
  HTMLElement::DetachLayoutTree(performing_reattach);
  if (!performing_reattach) {
    FocusabilityLost();
  }
}

void HTMLFormControlElement::AttributeChanged(
    const AttributeModificationParams& params) {
  HTMLElement::AttributeChanged(params);
  if (params.name == html_names::kDisabledAttr &&
      params.old_value.IsNull() != params.new_value.IsNull()) {
    DisabledAttributeChanged();
    if (params.reason == AttributeModificationReason::kDirectly &&
        IsDisabledFormControl() && AdjustedFocusedElementInTreeScope() == this)
      blur();
  }
}

void HTMLFormControlElement::ParseAttribute(
    const AttributeModificationParams& params) {
  const QualifiedName& name = params.name;
  if (name == html_names::kFormAttr) {
    FormAttributeChanged();
    UseCounter::Count(GetDocument(), WebFeature::kFormAttribute);
  } else if (name == html_names::kReadonlyAttr) {
    if (params.old_value.IsNull() != params.new_value.IsNull()) {
      ReadonlyAttributeChanged();
      PseudoStateChanged(CSSSelector::kPseudoReadOnly);
      PseudoStateChanged(CSSSelector::kPseudoReadWrite);
      InvalidateIfHasEffectiveAppearance();
    }
  } else if (name == html_names::kRequiredAttr) {
    if (params.old_value.IsNull() != params.new_value.IsNull())
      RequiredAttributeChanged();
    UseCounter::Count(GetDocument(), WebFeature::kRequiredAttribute);
  } else if (name == html_names::kAutofocusAttr) {
    HTMLElement::ParseAttribute(params);
    UseCounter::Count(GetDocument(), WebFeature::kAutoFocusAttribute);
  } else {
    HTMLElement::ParseAttribute(params);
  }
}

void HTMLFormControlElement::DisabledAttributeChanged() {
  // Don't blur in this function because this is called for descendants of
  // <fieldset> while tree traversal.
  EventDispatchForbiddenScope event_forbidden;

  ListedElement::DisabledAttributeChanged();
  InvalidateIfHasEffectiveAppearance();

  // TODO(dmazzoni): http://crbug.com/699438.
  // Replace |CheckedStateChanged| with a generic tree changed event.
  if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache())
    cache->CheckedStateChanged(this);
}

void HTMLFormControlElement::RequiredAttributeChanged() {
  SetNeedsValidityCheck();
  PseudoStateChanged(CSSSelector::kPseudoRequired);
  PseudoStateChanged(CSSSelector::kPseudoOptional);
  // TODO(dmazzoni): http://crbug.com/699438.
  // Replace |CheckedStateChanged| with a generic tree changed event.
  if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache())
    cache->CheckedStateChanged(this);
}

bool HTMLFormControlElement::IsReadOnly() const {
  return FastHasAttribute(html_names::kReadonlyAttr);
}

bool HTMLFormControlElement::IsDisabledOrReadOnly() const {
  return IsDisabledFormControl() || IsReadOnly();
}

void HTMLFormControlElement::SetAutofillState(WebAutofillState autofill_state) {
  if (autofill_state == autofill_state_)
    return;

  autofill_state_ = autofill_state;
  PseudoStateChanged(CSSSelector::kPseudoAutofill);
  PseudoStateChanged(CSSSelector::kPseudoWebKitAutofill);
  PseudoStateChanged(CSSSelector::kPseudoAutofillSelected);
  PseudoStateChanged(CSSSelector::kPseudoAutofillPreviewed);
}

bool HTMLFormControlElement::IsAutocompleteEmailUrlOrPassword() const {
  DEFINE_STATIC_LOCAL(HashSet<AtomicString>, values,
                      ({AtomicString("username"), AtomicString("new-password"),
                        AtomicString("current-password"), AtomicString("url"),
                        AtomicString("email"), AtomicString("impp")}));
  const AtomicString& autocomplete =
      FastGetAttribute(html_names::kAutocompleteAttr);
  if (autocomplete.IsNull())
    return false;
  return values.Contains(autocomplete.LowerASCII());
}

const AtomicString& HTMLFormControlElement::autocapitalize() const {
  if (!FastGetAttribute(html_names::kAutocapitalizeAttr).empty())
    return HTMLElement::autocapitalize();

  // If the form control itself does not have the autocapitalize attribute set,
  // but the form owner is non-null and does have the autocapitalize attribute
  // set, we inherit from the form owner.
  if (HTMLFormElement* form = Form())
    return form->autocapitalize();

  return g_empty_atom;
}

void HTMLFormControlElement::DidMoveToNewDocument(Document& old_document) {
  ListedElement::DidMoveToNewDocument(old_document);
  HTMLElement::DidMoveToNewDocument(old_document);
}

Node::InsertionNotificationRequest HTMLFormControlElement::InsertedInto(
    ContainerNode& insertion_point) {
  HTMLElement::InsertedInto(insertion_point);
  ListedElement::InsertedInto(insertion_point);
  return kInsertionDone;
}

void HTMLFormControlElement::RemovedFrom(ContainerNode& insertion_point) {
  HTMLElement::RemovedFrom(insertion_point);
  ListedElement::RemovedFrom(insertion_point);
}

void HTMLFormControlElement::WillChangeForm() {
  ListedElement::WillChangeForm();
  if (formOwner() && CanBeSuccessfulSubmitButton())
    formOwner()->InvalidateDefaultButtonStyle();
}

void HTMLFormControlElement::DidChangeForm() {
  ListedElement::DidChangeForm();
  if (formOwner() && isConnected() && CanBeSuccessfulSubmitButton())
    formOwner()->InvalidateDefaultButtonStyle();
}

HTMLFormElement* HTMLFormControlElement::formOwner() const {
  return ListedElement::Form();
}

bool HTMLFormControlElement::IsDisabledFormControl() const {
  // When an MHTML page is loaded through a HTTPS URL, it's considered a trusted
  // offline page. This can only happen on Android, and happens automatically
  // sometimes to show cached pages rather than an error page.
  // For this circumstance, it's beneficial to disable form controls so that
  // users do not waste time trying to edit them.
  //
  // For MHTML pages loaded through other means, we do not disable forms. This
  // avoids modification of the original page, and more closely matches other
  // saved page formats.
  if (GetDocument().Fetcher()->Archive()) {
    if (base::FeatureList::IsEnabled(blink::features::kMHTML_Improvements)) {
      if (GetDocument().Url().ProtocolIsInHTTPFamily()) {
        return true;
      }
    } else {
      // Without `kMHTML_Improvements`, MHTML forms are always disabled.
      return true;
    }
  }

  return IsActuallyDisabled();
}

bool HTMLFormControlElement::MatchesEnabledPseudoClass() const {
  return !IsDisabledFormControl();
}

bool HTMLFormControlElement::IsRequired() const {
  return FastHasAttribute(html_names::kRequiredAttr);
}

String HTMLFormControlElement::ResultForDialogSubmit() {
  return FastGetAttribute(html_names::kValueAttr);
}

FocusableState HTMLFormControlElement::SupportsFocus(UpdateBehavior) const {
  return IsDisabledFormControl() ? FocusableState::kNotFocusable
                                 : FocusableState::kFocusable;
}

bool HTMLFormControlElement::IsKeyboardFocusable(
    UpdateBehavior update_behavior) const {
  // Form control elements are always keyboard focusable if they are focusable
  // at all, and don't have a negative tabindex set.
  return IsFocusable(update_behavior) && tabIndex() >= 0;
}

bool HTMLFormControlElement::MayTriggerVirtualKeyboard() const {
  return false;
}

bool HTMLFormControlElement::ShouldHaveFocusAppearance() const {
  return SelectorChecker::MatchesFocusVisiblePseudoClass(*this);
}

bool HTMLFormControlElement::willValidate() const {
  return ListedElement::WillValidate();
}

bool HTMLFormControlElement::MatchesValidityPseudoClasses() const {
  return willValidate();
}

bool HTMLFormControlElement::IsValidElement() {
  return ListedElement::IsValidElement();
}

bool HTMLFormControlElement::IsSuccessfulSubmitButton() const {
  return CanBeSuccessfulSubmitButton() && !IsDisabledFormControl();
}

// The element referenced by the `popovertarget` attribute is returned if a)
// that element exists, b) it is a valid Popover element, and c) this form
// control supports popover triggering. The return value will include the
// behavior, which is taken from the `popovertargetaction` attribute, and will
// be kNone unless there is a valid popover target.
HTMLFormControlElement::PopoverTargetElement
HTMLFormControlElement::popoverTargetElement() {
  const PopoverTargetElement no_element{.popover = nullptr,
                                        .action = PopoverTriggerAction::kNone};
  if (!IsInTreeScope() ||
      SupportsPopoverTriggering() == PopoverTriggerSupport::kNone ||
      IsDisabledFormControl() || (Form() && IsSuccessfulSubmitButton())) {
    return no_element;
  }

  Element* target_element;
  target_element = GetElementAttributeResolvingReferenceTarget(
      html_names::kPopovertargetAttr);


  if (!target_element) {
    return no_element;
  }
  auto* target_popover = DynamicTo<HTMLElement>(target_element);
  if (!target_popover || !target_popover->HasPopoverAttribute()) {
    return no_element;
  }
  // The default action is "toggle".
  PopoverTriggerAction action = PopoverTriggerAction::kToggle;
  auto action_value =
      getAttribute(html_names::kPopovertargetactionAttr).LowerASCII();
  if (action_value == "show") {
    action = PopoverTriggerAction::kShow;
  } else if (action_value == "hide") {
    action = PopoverTriggerAction::kHide;
  } else if (RuntimeEnabledFeatures::HTMLPopoverActionHoverEnabled() &&
             action_value == "hover") {
    action = PopoverTriggerAction::kHover;
  }
  return PopoverTargetElement{.popover = target_popover, .action = action};
}

Element* HTMLFormControlElement::interestTargetElement() {
  CHECK(RuntimeEnabledFeatures::HTMLInvokeTargetAttributeEnabled());

  if (!IsInTreeScope() || IsDisabledFormControl()) {
    return nullptr;
  }

  return GetElementAttribute(html_names::kInteresttargetAttr);
}

AtomicString HTMLFormControlElement::popoverTargetAction() const {
  auto attribute_value =
      FastGetAttribute(html_names::kPopovertargetactionAttr).LowerASCII();
  // ReflectEmpty="toggle", ReflectMissing="toggle"
  if (attribute_value.IsNull() || attribute_value.empty()) {
    return keywords::kToggle;
  } else if (attribute_value == keywords::kToggle ||
             attribute_value == keywords::kShow ||
             attribute_value == keywords::kHide) {
    return attribute_value;  // ReflectOnly
  } else if (RuntimeEnabledFeatures::HTMLPopoverActionHoverEnabled() &&
             attribute_value == keywords::kHover) {
    return attribute_value;  // ReflectOnly (with HTMLPopoverHint enabled)
  } else {
    return keywords::kToggle;  // ReflectInvalid = "toggle"
  }
}
void HTMLFormControlElement::setPopoverTargetAction(const AtomicString& value) {
  setAttribute(html_names::kPopovertargetactionAttr, value);
}

AtomicString HTMLFormControlElement::interestAction() const {
  CHECK(RuntimeEnabledFeatures::HTMLInterestTargetAttributeEnabled());
  const AtomicString& attribute_value =
      FastGetAttribute(html_names::kInterestactionAttr);
  if (attribute_value && !attribute_value.IsNull() &&
      !attribute_value.empty()) {
    return attribute_value;
  }
  return g_empty_atom;
}

void HTMLFormControlElement::DefaultEventHandler(Event& event) {
  // Buttons that aren't form participants might be Invoker buttons or Popover
  // buttons.
  if (event.type() == event_type_names::kDOMActivate && IsInTreeScope() &&
      !IsDisabledFormControl() && (!Form() || !IsSuccessfulSubmitButton())) {
    auto popover = popoverTargetElement();

    // CommandFor should have been handled in
    // HTMLButtonElement::DefaultEventHandler
    DCHECK(!IsA<HTMLButtonElement>(this) ||
           !DynamicTo<HTMLButtonElement>(this)->commandForElement());

    if (popover.popover) {
      bool event_target_was_nested_popover = false;
      if (RuntimeEnabledFeatures::PopoverButtonNestingBehaviorEnabled()) {
        if (auto* target_node = event.target()->ToNode()) {
          bool button_is_ancestor_of_popover =
              IsShadowIncludingAncestorOf(*popover.popover);
          event_target_was_nested_popover =
              button_is_ancestor_of_popover &&
              popover.popover->IsShadowIncludingInclusiveAncestorOf(
                  *target_node);
        }
      }

      if (!event_target_was_nested_popover) {
        // Buttons with a popovertarget will invoke popovers, which is the same
        // logic as an invoketarget with an appropriate command (e.g.
        // togglePopover), sans the `CommandEvent` dispatch. Calling
        // `HandleCommandInternal()` does not dispatch the event but can handle
        // the popover triggering logic. `popovertargetaction` must also be
        // mapped to the equivalent `command` string:
        //  popovertargetaction=toggle -> command=togglePopover
        //  popovertargetaction=show -> command=showPopover
        //  popovertargetaction=hide -> command=hidePopover
        // We must check to ensure the action is one of the available popover
        // invoker actions so that popovertargetaction cannot be set to
        // something like showModal.
        auto trigger_support = SupportsPopoverTriggering();
        CHECK_NE(trigger_support, PopoverTriggerSupport::kNone);
        CHECK_NE(popover.action, PopoverTriggerAction::kNone);
        CommandEventType action;

        switch (popover.action) {
          case PopoverTriggerAction::kToggle:
            action = CommandEventType::kTogglePopover;
            break;
          case PopoverTriggerAction::kShow:
            action = CommandEventType::kShowPopover;
            break;
          case PopoverTriggerAction::kHide:
            action = CommandEventType::kHidePopover;
            break;
          case PopoverTriggerAction::kHover:
            CHECK(RuntimeEnabledFeatures::HTMLPopoverActionHoverEnabled());
            action = CommandEventType::kShowPopover;
            break;
          case PopoverTriggerAction::kNone:
            NOTREACHED();
        }

        CHECK(popover.popover->IsValidBuiltinCommand(*this, action));
        popover.popover->HandleCommandInternal(*this, action);
      }
    }
  }
  HTMLElement::DefaultEventHandler(event);
}

void HTMLFormControlElement::SetHovered(bool hovered) {
  HandlePopoverInvokerHovered(hovered);
  HTMLElement::SetHovered(hovered);
}

void HTMLFormControlElement::HandlePopoverInvokerHovered(bool hovered) {
  if (!IsInTreeScope()) {
    return;
  }
  if (auto* button = DynamicTo<HTMLButtonElement>(this)) {
    if (button->commandForElement()) {
      return;
    }
  }
  if (RuntimeEnabledFeatures::HTMLInvokeTargetAttributeEnabled() &&
      interestTargetElement()) {
    return;
  }
  auto target_info = popoverTargetElement();
  auto target_popover = target_info.popover;
  if (!target_popover || target_info.action != PopoverTriggerAction::kHover) {
    return;
  }
  CHECK(RuntimeEnabledFeatures::HTMLPopoverActionHoverEnabled());

  if (hovered) {
    // If we've just hovered an element (or the descendant of an element), see
    // if it has a popovertarget element set for hover triggering. If so, queue
    // a task to show the popover after a timeout.
    auto& hover_tasks = target_popover->GetPopoverData()->hoverShowTasks();
    CHECK(!hover_tasks.Contains(this));
    const ComputedStyle* computed_style = GetComputedStyle();
    if (!computed_style) {
      return;
    }
    float hover_delay_seconds = computed_style->PopoverShowDelay();
    // If the value is infinite or NaN, don't queue a task at all.
    CHECK_GE(hover_delay_seconds, 0);
    if (!std::isfinite(hover_delay_seconds)) {
      return;
    }
    // It's possible that multiple nested elements have popoverhovertarget
    // attributes pointing to the same popover, and in that case, we want to
    // trigger on the first of them that reaches its timeout threshold.
    hover_tasks.insert(
        this,
        PostDelayedCancellableTask(
            *GetExecutionContext()->GetTaskRunner(TaskType::kInternalDefault),
            FROM_HERE,
            WTF::BindOnce(
                [](HTMLFormControlElement* trigger_element,
                   HTMLElement* popover_element) {
                  if (!popover_element ||
                      !popover_element->HasPopoverAttribute()) {
                    return;
                  }
                  // Remove this element from hoverShowTasks always.
                  popover_element->GetPopoverData()->hoverShowTasks().erase(
                      trigger_element);
                  // Only trigger the popover if the popovertarget attribute
                  // still points to the same popover, and the popover is in the
                  // tree and still not showing.
                  auto current_target =
                      trigger_element->popoverTargetElement().popover;
                  if (popover_element->IsInTreeScope() &&
                      !popover_element->popoverOpen() &&
                      popover_element == current_target) {
                    popover_element->InvokePopover(*trigger_element);
                  }
                },
                WrapWeakPersistent(this),
                WrapWeakPersistent(target_popover.Get())),
            base::Seconds(hover_delay_seconds)));
  } else {
    // If we have a hover show task still waiting, cancel it. Based on this
    // logic, if you hover a popovertargetaction=hover element, then remove the
    // popovertarget attribute, there will be no way to stop the popover from
    // being shown after the delay, even if you subsequently de-hover the
    // element.
    if (auto& hover_tasks = target_popover->GetPopoverData()->hoverShowTasks();
        hover_tasks.Contains(this)) {
      hover_tasks.Take(this).Cancel();
    }
  }
}

// static
const HTMLFormControlElement*
HTMLFormControlElement::EnclosingFormControlElement(const Node* node) {
  if (!node)
    return nullptr;
  return Traversal<HTMLFormControlElement>::FirstAncestorOrSelf(*node);
}

String HTMLFormControlElement::NameForAutofill() const {
  String full_name = GetName();
  String trimmed_name = full_name.StripWhiteSpace();
  if (!trimmed_name.empty())
    return trimmed_name;
  full_name = GetIdAttribute();
  trimmed_name = full_name.StripWhiteSpace();
  return trimmed_name;
}

void HTMLFormControlElement::CloneNonAttributePropertiesFrom(
    const Element& source,
    NodeCloningData& data) {
  HTMLElement::CloneNonAttributePropertiesFrom(source, data);
  SetNeedsValidityCheck();
}

void HTMLFormControlElement::AssociateWith(HTMLFormElement* form) {
  AssociateByParser(form);
}

int32_t HTMLFormControlElement::GetAxId() const {
  Document& document = GetDocument();
  if (!document.IsActive() || !document.View()) {
    return 0;
  }
  // The AXId is the same as the DOM node id.
  int32_t result = DOMNodeIds::ExistingIdForNode(this);
  CHECK(result) << "May need to call GetDomNodeId() from a non-const function";
  return result;
}

}  // namespace blink
```