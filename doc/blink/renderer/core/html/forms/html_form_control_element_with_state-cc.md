Response:
Let's break down the thought process for analyzing this C++ file.

1. **Understand the Goal:** The request is to understand the functionality of `html_form_control_element_with_state.cc` in Chromium's Blink rendering engine. Key aspects include its relationship to HTML, JavaScript, and CSS, logic reasoning, and common usage errors.

2. **Initial Scan and Keyword Identification:**  Quickly read through the file, noting important keywords and concepts. These immediately jump out:
    * `HTMLFormControlElementWithState` (the class itself)
    * `autocomplete` (appears frequently)
    * `input`, `change`, `cancel` (event dispatching)
    * `Form` (interaction with form elements)
    * `UserHasEditedTheField` (tracking user interaction)
    * `PseudoStateChanged` (CSS pseudo-class management)
    * `IsValidElement` (validation related)
    *  Copyright notices (context)
    *  Includes (`.h` files)

3. **Infer Class Purpose from Name and Includes:** The name `HTMLFormControlElementWithState` strongly suggests this class represents form controls that maintain some kind of internal state. The included header file `html_form_control_element.h` indicates inheritance. This tells us it's a more specialized type of form control. The inclusion of `dom/events/event.h` points to event handling, and `html_names.h` suggests interaction with HTML attributes.

4. **Analyze Key Methods:** Focus on the prominent methods:

    * **`ShouldAutocomplete()`:**  This seems straightforward – it checks if autocompletion should be enabled, possibly delegating to the parent form.

    * **`IDLExposedAutofillValue()` and `setIDLExposedAutofillValue()`:** The "IDL-exposed" terminology hints at how this C++ code interacts with the JavaScript representation of the DOM. This method is clearly involved in parsing and managing the `autocomplete` attribute. The detailed logic within this function is a core piece of functionality and warrants careful examination. The comments within this function also point to the HTML specification, which is a crucial reference.

    * **Event Dispatching (`DispatchInputEvent`, `DispatchChangeEvent`, `DispatchCancelEvent`):** These methods are directly related to JavaScript's event handling mechanism. They show how actions within the C++ engine trigger events that JavaScript can listen for.

    * **`ShouldSaveAndRestoreFormControlState()`:** This method deals with persistence and how form control values are saved and restored, potentially when navigating back or forth in the browser history. The `autocomplete="off"` check is significant here.

    * **`SetUserHasEditedTheField()` and related methods:**  These methods manage the `interacted_state_` and how it influences CSS pseudo-classes like `:user-invalid` and `:user-valid`. This is the core connection to dynamic styling based on user interaction.

    * **`MatchesUserInvalidPseudo()` and `MatchesUserValidPseudo()`:** These methods implement the logic for determining if the element matches these CSS pseudo-classes, connecting the internal state to the styling engine.

5. **Connect to Web Technologies:**  Now explicitly link the observed functionality to HTML, JavaScript, and CSS:

    * **HTML:** The class directly manages attributes like `autocomplete`, interacts with `<form>` elements, and represents HTML form controls.

    * **JavaScript:** The dispatching of `input`, `change`, and `cancel` events is the primary interaction point. JavaScript event listeners can react to these events. The "IDL-exposed" prefix signifies the bridge between C++ and the JavaScript DOM.

    * **CSS:** The management of `:user-invalid` and `:user-valid` pseudo-classes directly impacts CSS styling based on user interaction and form validation.

6. **Logical Reasoning and Examples:**  For the more complex methods like `IDLExposedAutofillValue()`,  think about input and output:

    * **Input:** Various values of the `autocomplete` attribute.
    * **Output:** The parsed and interpreted "IDL-exposed" value.

    Construct examples that demonstrate different scenarios, especially around the parsing logic with multiple tokens in the `autocomplete` attribute.

7. **Identify Potential Usage Errors:** Consider how developers might misuse these features:

    * Incorrectly using `autocomplete="off"` and expecting state to be saved.
    * Misunderstanding the nuances of the `autocomplete` attribute's syntax.
    * Not being aware of the `:user-invalid` and `:user-valid` pseudo-classes and their connection to user interaction.

8. **Structure the Answer:** Organize the findings logically:

    * Start with a high-level summary of the file's purpose.
    * Detail the key functionalities.
    * Provide specific examples for HTML, JavaScript, and CSS interaction.
    * Illustrate logical reasoning with input/output examples.
    * Outline common usage errors.

9. **Refine and Clarify:** Review the answer for clarity and accuracy. Ensure the examples are easy to understand and directly relate to the code's functionality. Use precise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the class just manages basic form control properties.
* **Correction:** The "with state" part of the name is crucial. The methods related to user interaction (`UserHasEditedTheField`) and state saving confirm that it's about managing the *dynamic* state of the control.

* **Initial thought:** The `autocomplete` parsing is simple.
* **Correction:**  The detailed logic in `IDLExposedAutofillValue()` shows it's more complex and follows a specific specification with multiple tokens and categories.

* **Initial thought:** The CSS pseudo-class interaction is just about styling.
* **Correction:** It's driven by the internal state (`interacted_state_`) and validation status (`IsValidElement`), making it a dynamic connection between user behavior, validation, and presentation.

By following this structured approach, combining code analysis with knowledge of web technologies, and iteratively refining the understanding, a comprehensive and accurate explanation can be generated.
这个C++文件 `html_form_control_element_with_state.cc` 是 Chromium Blink 引擎中负责处理具有内部状态的 HTML 表单控制元素的核心代码。 它继承自 `HTMLFormControlElement`，并添加了管理和维护元素状态的功能，特别是与用户交互、自动填充以及表单状态保存和恢复相关的逻辑。

以下是它的主要功能：

**1. 管理表单控件的状态:**

* **跟踪用户交互:**  通过 `interacted_state_` 成员变量跟踪用户是否已经与表单控件进行过交互（编辑或失去焦点）。这用于触发诸如 `:user-invalid` 和 `:user-valid` 伪类的样式更新。
* **支持自动填充 (Autocomplete):**  实现了与 `autocomplete` 属性相关的逻辑，包括解析 `autocomplete` 属性的值，判断是否应该进行自动填充，并暴露自动填充的值给 JavaScript。
* **支持表单状态的保存和恢复:**  实现了 `ShouldSaveAndRestoreFormControlState()` 方法，决定是否应该保存和恢复表单控件的状态，例如输入框的值或单选框的选中状态。这对于浏览器的前进和后退功能至关重要。

**2. 与 JavaScript、HTML 和 CSS 的关系：**

* **JavaScript:**
    * **事件触发:**  该文件负责触发 `input`、`change` 和 `cancel` 等事件。当用户修改表单控件的值时，会触发 `input` 事件；当值发生最终改变并失去焦点时，会触发 `change` 事件；对于某些类型的控件（例如 `<dialog>` 中的 `<form method="dialog">`），会触发 `cancel` 事件。
        * **举例:** 当用户在一个 `<input>` 字段中输入内容时，JavaScript 可以监听 `input` 事件并实时更新其他页面元素或进行数据验证。
        ```html
        <input type="text" id="myInput">
        <script>
          document.getElementById('myInput').addEventListener('input', function() {
            console.log('输入框内容已改变:', this.value);
          });
        </script>
        ```
    * **IDL 接口:**  提供了 `IDLExposedAutofillValue()` 和 `setIDLExposedAutofillValue()` 方法，允许 JavaScript 通过 IDL (Interface Definition Language) 接口访问和设置 `autocomplete` 属性的解析后的值。
        * **举例:** JavaScript 可以读取或设置元素的 `autocomplete` 属性。
        ```javascript
        const inputElement = document.getElementById('myInput');
        console.log(inputElement.autocomplete); // 获取 autocomplete 属性值
        inputElement.autocomplete = 'email'; // 设置 autocomplete 属性值
        ```

* **HTML:**
    * **解析 `autocomplete` 属性:**  该文件中的 `IDLExposedAutofillValue()` 方法负责解析 HTML 元素上的 `autocomplete` 属性，根据其不同的取值（例如 "on", "off", "name", "email" 等）来决定自动填充的行为。
        * **举例:**  `<input type="email" autocomplete="email">` 告诉浏览器这个输入框期望用户输入邮箱地址，并且可以利用浏览器存储的邮箱地址进行自动填充。
    * **表单行为:**  该类作为表单控件的一部分，参与表单的提交和重置等行为。

* **CSS:**
    * **伪类 `:user-invalid` 和 `:user-valid`:**  该文件通过 `SetUserHasEditedTheFieldAndBlurred()` 方法和 `MatchesUserInvalidPseudo()`/`MatchesUserValidPseudo()` 方法来控制 `:user-invalid` 和 `:user-valid` 这两个 CSS 伪类的应用。当用户与表单控件交互并失去焦点后，如果控件的值无效，则应用 `:user-invalid` 样式，如果有效则应用 `:user-valid` 样式。
        * **举例:** 可以使用 CSS 来高亮显示无效的表单字段。
        ```html
        <input type="email" required>
        <style>
          input:user-invalid {
            border-color: red;
          }
          input:user-valid {
            border-color: green;
          }
        </style>
        ```

**3. 逻辑推理和假设输入/输出：**

假设我们有一个 `<input type="text" autocomplete="name shipping family-name section-billing">` 元素：

* **输入 (属性值):** `autocomplete="name shipping family-name section-billing"`
* **`IDLExposedAutofillValue()` 的处理过程 (推断):**
    1. 将属性值按空格分割成 tokens: `["name", "shipping", "family-name", "section-billing"]`
    2. 从最后一个 token 开始处理: `"section-billing"` 属于 `AutoCompleteCategory::kNone` (假设没有定义这个类别)，会返回空字符串。
    * **更可能的处理过程:** 如果 `section-billing` 被识别为有效的 section 前缀，它会被添加到 IDL 值中。假设 `family-name` 是主要的字段，根据规则，会向前查找修饰符。`shipping` 会被识别为 shipping 模式。
* **输出 (可能的 `IDLExposedAutofillValue()`):** `"section-billing shipping family-name"` (具体的输出取决于 `GetAutoCompleteCategory` 的实现和优先级规则)。

假设用户在一个 `required` 的 `<input type="email">` 字段中输入了无效的邮箱地址 "test"，然后失去了焦点：

* **假设输入 (用户操作):** 用户输入 "test" 并失去焦点。
* **内部状态变化:** `UserHasEditedTheField()` 会被调用，然后 `SetUserHasEditedTheFieldAndBlurred()` 会被调用。由于邮箱格式不正确，`ListedElement::IsValidElement()` 返回 false。
* **输出 (CSS 伪类):**  元素会匹配 `:user-invalid` 伪类，但不匹配 `:user-valid` 伪类。

**4. 用户或编程常见的使用错误：**

* **错误地认为 `autocomplete="off"` 会禁用状态保存:**  在某些旧版本或特定配置下，即使设置了 `autocomplete="off"`，浏览器仍然可能会保存和恢复表单状态。开发者应该依赖其他机制来阻止状态保存，例如在表单提交后清除字段。
* **误解 `autocomplete` 属性的语法:**  `autocomplete` 属性可以有多个空格分隔的 token，并且顺序很重要。开发者可能会错误地使用或排序这些 token，导致自动填充行为不符合预期。例如，将 "name" 放在 "family-name" 之后可能不会有预期的效果。
* **没有理解 `:user-invalid` 和 `:user-valid` 伪类的触发时机:**  这两个伪类只有在用户与字段交互 *并且失去焦点后* 才会生效。如果只是简单地加载页面，即使字段初始状态无效，也不会立即应用 `:user-invalid` 样式。
* **依赖 `ShouldAutocomplete()` 来完全阻止自动填充:**  虽然 `ShouldAutocomplete()` 返回 false 会阻止某些自动填充行为，但浏览器可能仍然会基于其他因素提供自动填充建议。要更彻底地阻止自动填充，可能需要结合其他技术，例如使用随机的字段名称或者特定的浏览器扩展。

总而言之，`html_form_control_element_with_state.cc` 是 Blink 引擎中一个关键的文件，它负责管理带有状态的 HTML 表单控件的核心逻辑，并与 JavaScript、HTML 和 CSS 紧密配合，实现了诸如用户交互跟踪、自动填充和表单状态管理等重要功能。理解这个文件的功能有助于深入了解浏览器如何处理 HTML 表单。

Prompt: 
```
这是目录为blink/renderer/core/html/forms/html_form_control_element_with_state.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
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

#include "third_party/blink/renderer/core/html/forms/html_form_control_element_with_state.h"

#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

using mojom::blink::FormControlType;

namespace {

enum class AutoCompleteCategory {
  kNone,
  kOff,
  kAutomatic,
  kNormal,
  kContact,
  kCredential,
};

AutoCompleteCategory GetAutoCompleteCategory(const AtomicString& token) {
  using Map = HashMap<AtomicString, AutoCompleteCategory>;
  DEFINE_STATIC_LOCAL(
      Map, category_map,
      ({
          {"off", AutoCompleteCategory::kOff},
          {"on", AutoCompleteCategory::kAutomatic},

          {"name", AutoCompleteCategory::kNormal},
          {"honorific-prefix", AutoCompleteCategory::kNormal},
          {"given-name", AutoCompleteCategory::kNormal},
          {"additional-name", AutoCompleteCategory::kNormal},
          {"family-name", AutoCompleteCategory::kNormal},
          {"honorific-suffix", AutoCompleteCategory::kNormal},
          {"nickname", AutoCompleteCategory::kNormal},
          {"organization-title", AutoCompleteCategory::kNormal},
          {"username", AutoCompleteCategory::kNormal},
          {"new-password", AutoCompleteCategory::kNormal},
          {"current-password", AutoCompleteCategory::kNormal},
          {"one-time-code", AutoCompleteCategory::kNormal},
          {"organization", AutoCompleteCategory::kNormal},
          {"street-address", AutoCompleteCategory::kNormal},
          {"address-line1", AutoCompleteCategory::kNormal},
          {"address-line2", AutoCompleteCategory::kNormal},
          {"address-line3", AutoCompleteCategory::kNormal},
          {"address-level4", AutoCompleteCategory::kNormal},
          {"address-level3", AutoCompleteCategory::kNormal},
          {"address-level2", AutoCompleteCategory::kNormal},
          {"address-level1", AutoCompleteCategory::kNormal},
          {"country", AutoCompleteCategory::kNormal},
          {"country-name", AutoCompleteCategory::kNormal},
          {"postal-code", AutoCompleteCategory::kNormal},
          {"cc-name", AutoCompleteCategory::kNormal},
          {"cc-given-name", AutoCompleteCategory::kNormal},
          {"cc-additional-name", AutoCompleteCategory::kNormal},
          {"cc-family-name", AutoCompleteCategory::kNormal},
          {"cc-number", AutoCompleteCategory::kNormal},
          {"cc-exp", AutoCompleteCategory::kNormal},
          {"cc-exp-month", AutoCompleteCategory::kNormal},
          {"cc-exp-year", AutoCompleteCategory::kNormal},
          {"cc-csc", AutoCompleteCategory::kNormal},
          {"cc-type", AutoCompleteCategory::kNormal},
          {"transaction-currency", AutoCompleteCategory::kNormal},
          {"transaction-amount", AutoCompleteCategory::kNormal},
          {"language", AutoCompleteCategory::kNormal},
          {"bday", AutoCompleteCategory::kNormal},
          {"bday-day", AutoCompleteCategory::kNormal},
          {"bday-month", AutoCompleteCategory::kNormal},
          {"bday-year", AutoCompleteCategory::kNormal},
          {"sex", AutoCompleteCategory::kNormal},
          {"url", AutoCompleteCategory::kNormal},
          {"photo", AutoCompleteCategory::kNormal},

          {"tel", AutoCompleteCategory::kContact},
          {"tel-country-code", AutoCompleteCategory::kContact},
          {"tel-national", AutoCompleteCategory::kContact},
          {"tel-area-code", AutoCompleteCategory::kContact},
          {"tel-local", AutoCompleteCategory::kContact},
          {"tel-local-prefix", AutoCompleteCategory::kContact},
          {"tel-local-suffix", AutoCompleteCategory::kContact},
          {"tel-extension", AutoCompleteCategory::kContact},
          {"email", AutoCompleteCategory::kContact},
          {"impp", AutoCompleteCategory::kContact},

          {"webauthn", AutoCompleteCategory::kCredential},
      }));

  auto iter = category_map.find(token);
  return iter == category_map.end() ? AutoCompleteCategory::kNone : iter->value;
}

wtf_size_t GetMaxTokensForCategory(AutoCompleteCategory category) {
  switch (category) {
    case AutoCompleteCategory::kNone:
      return 0;
    case AutoCompleteCategory::kOff:
    case AutoCompleteCategory::kAutomatic:
      return 1;
    case AutoCompleteCategory::kNormal:
      return 3;
    case AutoCompleteCategory::kContact:
      return 4;
    case AutoCompleteCategory::kCredential:
      return 5;
  }
}

}  // anonymous namespace

HTMLFormControlElementWithState::HTMLFormControlElementWithState(
    const QualifiedName& tag_name,
    Document& doc)
    : HTMLFormControlElement(tag_name, doc) {}

HTMLFormControlElementWithState::~HTMLFormControlElementWithState() = default;

bool HTMLFormControlElementWithState::ShouldAutocomplete() const {
  if (!Form())
    return true;
  return Form()->ShouldAutocomplete();
}

bool HTMLFormControlElementWithState::IsWearingAutofillAnchorMantle() const {
  return FormControlType() == FormControlType::kInputHidden;
}

String HTMLFormControlElementWithState::IDLExposedAutofillValue() const {
  // TODO(tkent): Share the code with `autofill::ParseAutocompleteAttribute()`.

  // https://html.spec.whatwg.org/C/#autofill-processing-model
  // 1. If the element has no autocomplete attribute, then jump to the step
  // labeled default.
  const AtomicString& value = FastGetAttribute(html_names::kAutocompleteAttr);
  if (value.IsNull())
    return g_empty_string;

  // 2. Let tokens be the result of splitting the attribute's value on ASCII
  // whitespace.
  SpaceSplitString tokens(value.LowerASCII());

  // 3. If tokens is empty, then jump to the step labeled default.
  if (tokens.size() == 0)
    return g_empty_string;

  // 4. Let index be the index of the last token in tokens.
  wtf_size_t index = tokens.size() - 1;

  // 5. Let field be the indexth token in tokens.
  AtomicString field = tokens[index];

  // 6. Let the category, maximum tokens pair be the result of executing the
  // algorithm to determine a field's category with field.
  AtomicString token = tokens[index];
  AutoCompleteCategory category = GetAutoCompleteCategory(token);
  wtf_size_t max_tokens = GetMaxTokensForCategory(category);

  // 7. If category is empty, then jump to the step labeled default.
  if (category == AutoCompleteCategory::kNone) {
    return g_empty_string;
  }

  // 8. If the number of tokens in tokens is greater than maximum tokens, then
  // jump to the step labeled default.
  if (tokens.size() > max_tokens)
    return g_empty_string;

  // 9. If category is Off or Automatic but the element's autocomplete attribute
  // is wearing the autofill anchor mantle, then jump to the step labeled
  // default.
  if ((category == AutoCompleteCategory::kOff ||
       category == AutoCompleteCategory::kAutomatic) &&
      IsWearingAutofillAnchorMantle()) {
    return g_empty_string;
  }

  // 10. If category is Off, let the element's autofill field name be the string
  // "off", let its autofill hint set be empty, and let its IDL-exposed autofill
  // value be the string "off". Then, return.
  if (category == AutoCompleteCategory::kOff)
    return "off";

  // 11. If category is Automatic, let the element's autofill field name be the
  // string "on", let its autofill hint set be empty, and let its IDL-exposed
  // autofill value be the string "on". Then, return.
  if (category == AutoCompleteCategory::kAutomatic)
    return "on";

  // 15. Let IDL value have the same value as field.
  String idl_value = field;

  // 16. If category is Credential and the indexth token in tokens is an ASCII
  // case-insensitive match for "webauthn", then run the substeps that follow:
  if (category == AutoCompleteCategory::kCredential) {
    // 16.2 If the indexth token in tokens is the first entry, then skip to the
    // step labeled done.
    if (index != 0) {
      // 16.3 Decrement index by one.
      --index;
      // 16.4 Let the category, maximum tokens pair be the result of executing
      // the algorithm to determine a field's category with the indexth token in
      // tokens.
      category = GetAutoCompleteCategory(tokens[index]);
      // 16.5 If category is not Normal and category is not Contact, then jump
      // to the step labeled default.
      if (category != AutoCompleteCategory::kNormal &&
          category != AutoCompleteCategory::kContact) {
        return g_empty_string;
      }
      // 16.6 If index is greater than maximum tokens minus one (i.e. if the
      // number of remaining tokens is greater than maximum tokens), then jump
      // to the step labeled default.
      if (index > GetMaxTokensForCategory(category) - 1) {
        return g_empty_string;
      }
      // 16.7 Let IDL value be the concatenation of the indexth token in tokens,
      // a U+0020 SPACE character, and the previous value of IDL value.
      idl_value = tokens[index] + " " + idl_value;
    }
  }

  // 17. If the indexth token in tokens is the first entry, then skip to the
  // step labeled done.
  if (index != 0) {
    // 18. Decrement index by one.
    --index;
    // 19. If category is Contact and the indexth token in tokens is an ASCII
    // case-insensitive match for one of the strings in the following list, ...
    if (category == AutoCompleteCategory::kContact) {
      AtomicString contact = tokens[index];
      if (contact == "home" || contact == "work" || contact == "mobile" ||
          contact == "fax" || contact == "pager") {
        // 19.4. Let IDL value be the concatenation of contact, a U+0020 SPACE
        // character, and the previous value of IDL value (which at this point
        // will always be field).
        idl_value = contact + " " + idl_value;
        // 19.5. If the indexth entry in tokens is the first entry, then skip to
        // the step labeled done.
        if (index == 0) {
          return idl_value;
        }
        // 19.6. Decrement index by one.
        --index;
      }
    }

    // 20. If the indexth token in tokens is an ASCII case-insensitive match for
    // one of the strings in the following list, ...
    AtomicString mode = tokens[index];
    if (mode == "shipping" || mode == "billing") {
      // 20.4. Let IDL value be the concatenation of mode, a U+0020 SPACE
      // character, and the previous value of IDL value (which at this point
      // will either be field or the concatenation of contact, a space, and
      // field).
      idl_value = mode + " " + idl_value;
      // 20.5 If the indexth entry in tokens is the first entry, then skip to
      // the step labeled done.
      if (index == 0) {
        return idl_value;
      }
      // 20.6. Decrement index by one.
      --index;
    }

    // 21. If the indexth entry in tokens is not the first entry, then jump to
    // the step labeled default.
    if (index != 0)
      return g_empty_string;
    // 22. If the first eight characters of the indexth token in tokens are not
    // an ASCII case-insensitive match for the string "section-", then jump to
    // the step labeled default.
    AtomicString section = tokens[index];
    if (!section.StartsWith("section-"))
      return g_empty_string;
    // 25. Let IDL value be the concatenation of section, a U+0020 SPACE
    // character, and the previous value of IDL value.
    idl_value = section + " " + idl_value;
  }
  // 30. Let the element's IDL-exposed autofill value be IDL value.
  return idl_value;
}

void HTMLFormControlElementWithState::setIDLExposedAutofillValue(
    const String& autocomplete_value) {
  setAttribute(html_names::kAutocompleteAttr, AtomicString(autocomplete_value));
}

bool HTMLFormControlElementWithState::ClassSupportsStateRestore() const {
  return true;
}

bool HTMLFormControlElementWithState::ShouldSaveAndRestoreFormControlState()
    const {
  if (!isConnected()) {
    return false;
  }
  // TODO(crbug.com/1419161): remove this after M113 has been stable for a bit.
  if (RuntimeEnabledFeatures::
          FormControlRestoreStateIfAutocompleteOffEnabled()) {
    return ShouldAutocomplete();
  }
  if (Form() && !Form()->ShouldAutocomplete()) {
    return false;
  }
  if (EqualIgnoringASCIICase(FastGetAttribute(html_names::kAutocompleteAttr),
                             "off")) {
    return false;
  }
  return true;
}

void HTMLFormControlElementWithState::DispatchInputEvent() {
  // Legacy 'input' event for forms set value and checked.
  Event* event = Event::CreateBubble(event_type_names::kInput);
  event->SetComposed(true);
  DispatchScopedEvent(*event);
}

void HTMLFormControlElementWithState::DispatchChangeEvent() {
  if (UserHasEditedTheField()) {
    // Start matching :user-valid, but only if the user has already edited the
    // field.
    SetUserHasEditedTheFieldAndBlurred();
  }
  DispatchScopedEvent(*Event::CreateBubble(event_type_names::kChange));
}

void HTMLFormControlElementWithState::DispatchCancelEvent() {
  DispatchScopedEvent(*Event::CreateBubble(event_type_names::kCancel));
}

void HTMLFormControlElementWithState::FinishParsingChildren() {
  HTMLFormControlElement::FinishParsingChildren();
  ListedElement::TakeStateAndRestore();
}

bool HTMLFormControlElementWithState::IsFormControlElementWithState() const {
  return true;
}

void HTMLFormControlElementWithState::ResetImpl() {
  ClearUserHasEditedTheField();
}

int HTMLFormControlElementWithState::DefaultTabIndex() const {
  return 0;
}

void HTMLFormControlElementWithState::SetUserHasEditedTheField() {
  if (interacted_state_ < InteractedState::kInteractedAndStillFocused) {
    interacted_state_ = InteractedState::kInteractedAndStillFocused;
  }
}

void HTMLFormControlElementWithState::SetUserHasEditedTheFieldAndBlurred() {
  if (interacted_state_ >= InteractedState::kInteractedAndBlurred) {
    return;
  }
  interacted_state_ = InteractedState::kInteractedAndBlurred;
  PseudoStateChanged(CSSSelector::kPseudoUserInvalid);
  PseudoStateChanged(CSSSelector::kPseudoUserValid);
}

void HTMLFormControlElementWithState::ForceUserValid() {
  force_user_valid_ = true;
  PseudoStateChanged(CSSSelector::kPseudoUserInvalid);
  PseudoStateChanged(CSSSelector::kPseudoUserValid);
}

bool HTMLFormControlElementWithState::MatchesUserInvalidPseudo() {
  return (UserHasEditedTheFieldAndBlurred() || force_user_valid_) &&
         MatchesValidityPseudoClasses() && !ListedElement::IsValidElement();
}

bool HTMLFormControlElementWithState::MatchesUserValidPseudo() {
  return (UserHasEditedTheFieldAndBlurred() || force_user_valid_) &&
         MatchesValidityPseudoClasses() && ListedElement::IsValidElement();
}

}  // namespace blink

"""

```