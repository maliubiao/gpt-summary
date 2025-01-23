Response:
Let's break down the thought process for analyzing the `HTMLOptionElement.cc` file.

**1. Initial Understanding of the File's Purpose:**

The file path itself, `blink/renderer/core/html/forms/html_option_element.cc`, is the biggest clue. It clearly indicates this code is part of the Blink rendering engine, specifically dealing with the `<option>` HTML element within forms. The `.cc` extension signifies a C++ source file.

**2. Examining the Header Inclusion:**

The `#include` directives are the next important pieces of information. They tell us what other parts of the Blink engine this file interacts with:

* `"third_party/blink/renderer/core/html/forms/html_option_element.h"`: This is the corresponding header file for this source file, containing the class declaration.
* Various `mojom` includes:  These likely define interfaces for communication with other parts of Chromium, perhaps related to metrics or features. `web_feature.mojom-shared.h` suggests usage tracking.
* Bindings (`v8_mutation_observer_init.h`): Interaction with V8, the JavaScript engine, specifically related to `MutationObserver`.
* Core DOM elements (`document.h`, `events/...`, `dom/...`): This confirms the file's central role in the DOM structure and event handling. Specific includes like `simulated_click_options.h`, `focus_params.h`, `mutation_observer.h`, `node_traversal.h`, `shadow_root.h`, `text.h` point to interactions with these core DOM concepts.
* Form-related elements (`html_data_list_element.h`, `html_opt_group_element.h`, `html_select_element.h`):  Highlights the context of `<option>` within `<select>` and `<datalist>` elements.
* Layout and Styling (`layout_theme.h`, `computed_style.h`): Indicates the file's involvement in how `<option>` elements are rendered and styled.
* Platform-level concerns (`exception_state.h`, `keyboard_codes.h`, `string_builder.h`): Hints at error handling, keyboard input management, and string manipulation.

**3. Analyzing the `OptionTextObserver` Class:**

This inner class immediately stands out. Its name suggests it monitors text changes within the `<option>` element. The usage of `MutationObserver` confirms this. The `Deliver` method, which calls `option_->DidChangeTextContent()`, shows how text changes are propagated.

**4. Deconstructing the `HTMLOptionElement` Class Implementation:**

Iterate through the methods, paying attention to their names and what they do:

* **Constructor/Destructor:**  Standard C++ practice. The comment about the destructor is noteworthy, highlighting a potential MSVC-specific compilation issue.
* **`CreateForJSConstructor`:**  Indicates how `<option>` elements are created from JavaScript. The parameters (`data`, `value`, `default_selected`, `selected`) map directly to HTML attributes and content.
* **`Trace`:** Part of Blink's garbage collection mechanism.
* **`SupportsFocus`:** Determines if the `<option>` can receive focus, considering its context within a `<select>` (especially `appearance:base-select`).
* **`MatchesDefaultPseudoClass`, `MatchesEnabledPseudoClass`:** Relates to CSS pseudo-classes (`:default`, `:enabled`) and how the `<option>`'s state affects styling.
* **`DisplayLabel`, `text`, `setText`:**  Methods for getting and setting the visible text of the option, considering the `label` attribute. The handling of `selectedIndex` preservation is interesting.
* **`AccessKeyAction`:**  Deals with keyboard accessibility.
* **`index`, `ListIndex`:** Methods to determine the position of the `<option>` within its parent `<select>`.
* **`ParseAttribute`:**  This is crucial! It describes how changes to HTML attributes of the `<option>` (like `value`, `disabled`, `selected`, `label`) are handled and what side effects they have (e.g., triggering validity checks, pseudo-state changes, updates to the parent `<select>`).
* **`value`, `setValue`:** Getting and setting the `value` attribute.
* **`Selected`, `SetSelected`, `selectedForBinding`, `setSelectedForBinding`, `SetSelectedState`:**  Core logic for managing the selected state of the `<option>`, including interactions with the parent `<select>` and accessibility notifications. The "dirtiness" concept is important for form submission.
* **`SetMultiSelectFocusedState`, `IsMultiSelectFocused`:** Specific to multi-select scenarios.
* **`SetDirty`:**  Manually setting the "dirty" state.
* **`ChildrenChanged`, `DidChangeTextContent`:** Handling changes to the `<option>`'s child nodes, especially text content, and propagating these changes to parent elements.
* **`OwnerDataListElement`, `OwnerSelectElement`:** Methods to find the parent `<datalist>` or `<select>` element. The conditional logic with `RuntimeEnabledFeatures::SelectParserRelaxationEnabled()` is a key detail.
* **`label`, `setLabel`:** Getting and setting the `label` attribute.
* **`TextIndentedToRespectGroupLabel`:**  Handles indentation for options within `<optgroup>`.
* **`OwnElementDisabled`, `IsDisabledFormControl`:** Determining if the option is disabled, considering both its own `disabled` attribute and the parent `<optgroup>`'s state.
* **`DefaultToolTip`:**  Retrieves the default tooltip, usually from the parent `<select>`.
* **`CollectOptionInnerText`:**  Extracts the textual content of the `<option>`, excluding script elements.
* **`form`:**  Finds the form the `<option>` belongs to.
* **`DidAddUserAgentShadowRoot`, `UpdateLabel`:**  Deals with the user-agent shadow DOM used to render the `<option>`, especially its label. The conditional logic based on `CustomizableSelectEnabled` is important.
* **`InsertedInto`, `RemovedFrom`:** Crucial methods for handling the insertion and removal of `<option>` elements into/from the DOM tree, especially their relationship with `<select>` elements. The logic around `SelectParserRelaxationEnabled` and `CustomizableSelectEnabled` is complex and requires careful attention.
* **`SetTextOnlyRendering`:** Controls whether the `<option>` renders only text content or its full children, depending on the context (especially for `appearance:base-select`).
* **`SpatialNavigationFocused`:** Deals with focus during spatial navigation.
* **`IsDisplayNone`:** Checks if the option is hidden via CSS.
* **`DefaultEventHandler`, `DefaultEventHandlerInternal`:** Handles default events (mouse clicks, key presses) on the `<option>`, particularly within the context of `appearance:base-select`.
* **`FinishParsingChildren`:**  Called after the `<option>`'s children have been parsed.

**5. Identifying Relationships with JavaScript, HTML, and CSS:**

As you go through the methods, explicitly note connections to these technologies. For example:

* **JavaScript:** `CreateForJSConstructor`, `selectedForBinding`, `setSelectedForBinding`, interactions with events.
* **HTML:** The handling of attributes (`value`, `disabled`, `selected`, `label`), the overall DOM structure, and the context within `<select>` and `<datalist>`.
* **CSS:**  `MatchesDefaultPseudoClass`, `MatchesEnabledPseudoClass`, `PseudoStateChanged`, `IsDisplayNone`, and the user-agent shadow DOM for styling.

**6. Inferring Logic and Providing Examples:**

For each method or significant section, consider:

* **Input:** What are the preconditions or inputs to this code? (e.g., attribute changes, user interactions, DOM manipulation).
* **Output:** What is the result or side effect of this code? (e.g., updating the selected state, triggering events, modifying the DOM, changing styling).
* **Assumptions:** What assumptions does the code make about the environment or other parts of the system?

Then, create concrete examples to illustrate the functionality.

**7. Considering Common Errors:**

Think about common mistakes developers make when working with `<option>` elements and how the Blink implementation might handle or be affected by those errors. This involves understanding the constraints and expected behavior of `<option>` elements.

**8. Structuring the Output:**

Organize your findings logically. Start with a high-level summary of the file's purpose, then delve into specific functionalities, relationships with web technologies, logic examples, and common errors. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file just handles the `<option>` element."
* **Correction:**  "It does that, but also has complex logic for interactions with `<select>`, `<datalist>`, accessibility, styling, JavaScript, and the rendering engine."
* **Initial thought:** "The `ParseAttribute` method just updates internal state."
* **Correction:** "It updates state *and* triggers significant side effects, like validity checks and updates to parent elements."
* **Initial thought:**  "The `InsertedInto` and `RemovedFrom` methods are straightforward."
* **Correction:** "They are quite complex, especially with the flags for select parser relaxation and customizable select, and require careful consideration of the DOM hierarchy."

By following this detailed and iterative process, you can thoroughly analyze a complex source code file like `html_option_element.cc` and extract meaningful information.
这个文件是 Chromium Blink 引擎中负责处理 HTML `<option>` 元素的核心逻辑的 C++ 源代码文件。它定义了 `HTMLOptionElement` 类，该类继承自 `HTMLElement`，并实现了与 `<option>` 元素相关的各种功能。

以下是 `html_option_element.cc` 文件的主要功能，以及与 JavaScript、HTML 和 CSS 的关系，逻辑推理示例，以及常见使用错误：

**主要功能：**

1. **表示 HTML `<option>` 元素:**  `HTMLOptionElement` 类是 `<option>` 元素在 Blink 渲染引擎中的 C++ 表示。它存储了与该元素相关的各种属性和状态。
2. **处理属性:**  管理 `<option>` 元素的 HTML 属性，例如 `value`、`label`、`selected`、`disabled` 等。`ParseAttribute` 方法负责解析和处理这些属性的变化。
3. **管理选中状态:**  维护 `<option>` 元素的选中状态 (`is_selected_`)，并提供方法 (`SetSelected`, `Selected`) 来设置和获取该状态。
4. **获取和设置文本内容:**  提供方法 (`text`, `setText`, `CollectOptionInnerText`) 来获取和设置 `<option>` 元素显示的文本内容。这包括处理 `label` 属性的影响。
5. **与 `<select>` 元素交互:**  实现 `<option>` 元素与父级 `<select>` 元素的交互，例如：
    * 通知 `<select>` 元素选项的选中状态变化 (`OptionSelectionStateChanged`)。
    * 获取所属的 `<select>` 元素 (`OwnerSelectElement`)。
    * 在插入和移除时通知 `<select>` 元素 (`OptionInserted`, `OptionRemoved`)。
    * 在文本内容或子元素变化时通知 `<select>` 元素 (`OptionElementChildrenChanged`).
6. **与 `<datalist>` 元素交互:**  实现 `<option>` 元素与父级 `<datalist>` 元素的交互，例如在 `value` 属性或子元素变化时通知 `<datalist>` 元素。
7. **处理用户交互:**  响应用户的鼠标点击和键盘操作，例如在 `appearance:base-select` 模式下处理选项的选择。
8. **支持无障碍功能 (Accessibility):**  通过 `AXObjectCache` 与无障碍 API 交互，通知选项状态的改变。
9. **支持 CSS 样式:**  通过 `PseudoStateChanged` 方法通知伪类的变化（例如 `:selected`, `:disabled`），从而影响 CSS 样式。
10. **处理 Shadow DOM:**  在用户代理 Shadow DOM 中渲染选项的标签，特别是当 `appearance:base-select` 时。
11. **处理 `MutationObserver`:**  使用 `OptionTextObserver` 监听 `<option>` 元素文本内容的变化。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:**
    * **创建 `<option>` 元素:** JavaScript 可以使用 `document.createElement('option')` 创建 `<option>` 元素，Blink 会创建对应的 `HTMLOptionElement` 对象。 `CreateForJSConstructor` 方法就是处理 JavaScript 创建 `<option>` 时的逻辑。
    * **访问和修改属性:** JavaScript 可以通过 DOM API 访问和修改 `<option>` 元素的属性（例如 `option.value = 'new value'`, `option.selected = true`）。这些操作最终会调用 `HTMLOptionElement` 的相应方法，例如 `setValue` 和 `SetSelected`。
    * **事件处理:** JavaScript 可以监听 `<option>` 元素上的事件（虽然通常直接监听 `<select>` 元素上的 `change` 事件），例如 `click` 事件。`DefaultEventHandler` 处理了某些情况下的默认事件行为。
    * **示例:**
        ```javascript
        const selectElement = document.getElementById('mySelect');
        const optionElement = document.createElement('option');
        optionElement.value = 'javascript_value';
        optionElement.text = 'JavaScript Text';
        selectElement.appendChild(optionElement);
        ```
        这段 JavaScript 代码创建了一个新的 `<option>` 元素，设置了它的 `value` 和 `text` 属性，并将其添加到 ID 为 `mySelect` 的 `<select>` 元素中。 `HTMLOptionElement` 的实例会相应地被创建和配置。

* **HTML:**
    * **声明 `<option>` 元素:** HTML 代码直接定义了 `<option>` 元素及其属性。
    * **属性映射:**  HTML 属性（例如 `<option value="html_value" selected>HTML Text</option>`）会被解析并映射到 `HTMLOptionElement` 对象的成员变量和状态。`ParseAttribute` 方法负责处理这个过程。
    * **示例:**
        ```html
        <select id="mySelect">
          <option value="html_value" selected>HTML Text</option>
          <option value="another_value">Another Option</option>
        </select>
        ```
        在这个 HTML 代码中，浏览器会为每个 `<option>` 标签创建一个 `HTMLOptionElement` 对象，并将 `value` 和 `selected` 属性的值存储在相应的对象中。

* **CSS:**
    * **样式化 `<option>` 元素:** CSS 可以使用选择器来样式化 `<option>` 元素，例如改变其字体、颜色等。
    * **伪类:** CSS 伪类（例如 `:checked`, `:disabled`, `:default`) 可以根据 `<option>` 元素的状态应用不同的样式。 `PseudoStateChanged` 方法负责通知 Blink 引擎这些伪类的状态变化，从而触发样式的重新计算。
    * **用户代理 Shadow DOM:**  对于某些 `<select>` 元素的渲染模式（例如 `appearance:base-select`），浏览器会创建 Shadow DOM 来渲染 `<option>` 元素。 `DidAddUserAgentShadowRoot` 和 `UpdateLabel` 与此相关。
    * **示例:**
        ```css
        option:checked {
          background-color: lightblue;
        }

        option:disabled {
          color: gray;
        }
        ```
        当 `<option>` 元素的 `selected` 属性被设置时，`:checked` 伪类会生效，背景色会变为浅蓝色。当 `disabled` 属性被设置时，`:disabled` 伪类会生效，文本颜色会变为灰色。

**逻辑推理示例：**

假设输入以下 HTML 代码：

```html
<select id="mySelect">
  <option value="1">Option 1</option>
  <option value="2" selected>Option 2</option>
</select>
```

1. **解析 HTML:** 当浏览器解析这段 HTML 时，会创建两个 `HTMLOptionElement` 对象。
2. **属性设置:**
   * 第一个 `HTMLOptionElement` 对象的 `value` 属性会被设置为 "1"，`is_selected_` 会是 `false`。
   * 第二个 `HTMLOptionElement` 对象的 `value` 属性会被设置为 "2"，`is_selected_` 会被设置为 `true`，因为有 `selected` 属性。
3. **通知 `<select>`:**  当第二个 `<option>` 元素被解析并设置 `selected` 属性时，`ParseAttribute` 方法会检测到 `selected` 属性的变化，并调用 `SetSelected(true)`。
4. **`<select>` 的反应:** `SetSelected` 方法会调用 `OwnerSelectElement()->OptionSelectionStateChanged(this, true)`，通知父级的 `<select>` 元素其选中状态发生了变化。 `<select>` 元素会更新其内部的选中状态并可能触发 `change` 事件。

**常见使用错误：**

1. **直接修改 `<option>` 的文本节点而没有通知 `<select>`:**  虽然可以操作 `<option>` 元素的子节点来修改其文本内容，但直接这样做可能不会触发 `<select>` 元素的更新。应该使用 `setText` 方法来确保 `<select>` 元素能正确感知变化。
    * **假设输入:** JavaScript 直接修改了 `<option>` 的文本节点：
      ```javascript
      const option = document.querySelector('option');
      option.firstChild.nodeValue = 'New Text';
      ```
    * **可能输出:**  虽然 `<option>` 元素显示的文本会改变，但 `<select>` 元素可能没有意识到这个变化，其显示的选中项文本可能仍然是旧的。

2. **在 JavaScript 中创建 `<option>` 时忘记设置 `value` 属性:**  `<option>` 元素的 `value` 属性对于表单提交非常重要。如果没有设置 `value`，提交表单时可能无法正确传递数据。
    * **假设输入:** JavaScript 创建 `<option>` 时没有设置 `value`：
      ```javascript
      const option = document.createElement('option');
      option.text = 'An option without value';
      ```
    * **可能输出:**  当包含此 `<select>` 的表单被提交时，如果用户选择了这个选项，提交的数据中可能不会包含与此选项对应的值。 `HTMLOptionElement::value()` 在没有显式 `value` 属性时会返回文本内容，但这可能不是期望的行为。

3. **误解 `label` 属性的作用:**  `label` 属性提供了一个更友好的标签，用于在 UI 中显示，而 `text` 属性（或者子节点的文本内容）则是默认的标签。如果没有 `label` 属性，则使用文本内容。容易混淆这两者的用途。
    * **假设输入:**  HTML 中设置了 `label` 属性：
      ```html
      <option value="val" label="Friendly Label">Actual Text</option>
      ```
    * **用户可能错误地认为 `option.text` 会返回 "Friendly Label"，但实际上它会返回 "Actual Text"**。 `DisplayLabel()` 方法才会返回 "Friendly Label"。

4. **在不支持 `appearance:base-select` 的浏览器中假设其行为:**  `appearance:base-select` 是一个较新的 CSS 属性，用于自定义 `<select>` 元素的渲染。在不支持该属性的浏览器中，`<option>` 元素的行为和渲染可能不同。

理解 `html_option_element.cc` 的功能对于理解 Blink 引擎如何处理 HTML 表单元素至关重要。它涉及到浏览器内部如何将 HTML 结构映射到对象，以及如何处理用户交互和样式应用。

### 提示词
```
这是目录为blink/renderer/core/html/forms/html_option_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 *           (C) 2006 Alexey Proskuryakov (ap@nypop.com)
 * Copyright (C) 2004, 2005, 2006, 2010 Apple Inc. All rights reserved.
 * Copyright (C) 2010 Google Inc. All rights reserved.
 * Copyright (C) 2011 Motorola Mobility, Inc.  All rights reserved.
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

#include "third_party/blink/renderer/core/html/forms/html_option_element.h"

#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mutation_observer_init.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/simulated_click_options.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/mutation_observer.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/events/gesture_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/html/forms/html_data_list_element.h"
#include "third_party/blink/renderer/core/html/forms/html_opt_group_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

class OptionTextObserver : public MutationObserver::Delegate {
 public:
  explicit OptionTextObserver(HTMLOptionElement& option)
      : option_(option), observer_(MutationObserver::Create(this)) {
    MutationObserverInit* init = MutationObserverInit::Create();
    init->setCharacterData(true);
    init->setChildList(true);
    init->setSubtree(true);
    observer_->observe(option_, init, ASSERT_NO_EXCEPTION);
  }

  ExecutionContext* GetExecutionContext() const override {
    return option_->GetExecutionContext();
  }

  void Deliver(const MutationRecordVector& records,
               MutationObserver&) override {
    option_->DidChangeTextContent();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(option_);
    visitor->Trace(observer_);
    MutationObserver::Delegate::Trace(visitor);
  }

 private:
  Member<HTMLOptionElement> option_;
  Member<MutationObserver> observer_;
};

HTMLOptionElement::HTMLOptionElement(Document& document)
    : HTMLElement(html_names::kOptionTag, document), is_selected_(false) {
  EnsureUserAgentShadowRoot();
}

// An explicit empty destructor should be in html_option_element.cc, because
// if an implicit destructor is used or an empty destructor is defined in
// html_option_element.h, when including html_option_element.h,
// msvc tries to expand the destructor and causes
// a compile error because of lack of ComputedStyle definition.
HTMLOptionElement::~HTMLOptionElement() = default;

HTMLOptionElement* HTMLOptionElement::CreateForJSConstructor(
    Document& document,
    const String& data,
    const AtomicString& value,
    bool default_selected,
    bool selected,
    ExceptionState& exception_state) {
  HTMLOptionElement* element =
      MakeGarbageCollected<HTMLOptionElement>(document);
  element->EnsureUserAgentShadowRoot();
  if (!data.empty()) {
    element->AppendChild(Text::Create(document, data), exception_state);
    if (exception_state.HadException())
      return nullptr;
  }

  if (!value.IsNull())
    element->setValue(value);
  if (default_selected)
    element->setAttribute(html_names::kSelectedAttr, g_empty_atom);
  element->SetSelected(selected);

  return element;
}

void HTMLOptionElement::Trace(Visitor* visitor) const {
  visitor->Trace(text_observer_);
  HTMLElement::Trace(visitor);
}

FocusableState HTMLOptionElement::SupportsFocus(
    UpdateBehavior update_behavior) const {
  HTMLSelectElement* select = OwnerSelectElement();
  if (select && select->UsesMenuList()) {
    if (select->IsAppearanceBasePicker()) {
      // If this option is being rendered as regular web content inside a
      // base-select <select> popover, then we need this element to be
      // focusable.
      return IsDisabledFormControl() ? FocusableState::kNotFocusable
                                     : FocusableState::kFocusable;
    }
    return FocusableState::kNotFocusable;
  }
  return HTMLElement::SupportsFocus(update_behavior);
}

bool HTMLOptionElement::MatchesDefaultPseudoClass() const {
  return FastHasAttribute(html_names::kSelectedAttr);
}

bool HTMLOptionElement::MatchesEnabledPseudoClass() const {
  return !IsDisabledFormControl();
}

String HTMLOptionElement::DisplayLabel() const {
  String label_attr = String(FastGetAttribute(html_names::kLabelAttr))
    .StripWhiteSpace(IsHTMLSpace<UChar>).SimplifyWhiteSpace(IsHTMLSpace<UChar>);
  String inner_text = CollectOptionInnerText()
    .StripWhiteSpace(IsHTMLSpace<UChar>).SimplifyWhiteSpace(IsHTMLSpace<UChar>);
  // FIXME: The following treats an element with the label attribute set to
  // the empty string the same as an element with no label attribute at all.
  // Is that correct? If it is, then should the label function work the same
  // way?
  return label_attr.empty() ? inner_text : label_attr;
}

String HTMLOptionElement::text() const {
  return CollectOptionInnerText()
      .StripWhiteSpace(IsHTMLSpace<UChar>)
      .SimplifyWhiteSpace(IsHTMLSpace<UChar>);
}

void HTMLOptionElement::setText(const String& text) {
  // Changing the text causes a recalc of a select's items, which will reset the
  // selected index to the first item if the select is single selection with a
  // menu list.  We attempt to preserve the selected item.
  HTMLSelectElement* select = OwnerSelectElement();
  bool select_is_menu_list = select && select->UsesMenuList();
  int old_selected_index = select_is_menu_list ? select->selectedIndex() : -1;

  setTextContent(text);

  if (select_is_menu_list && select->selectedIndex() != old_selected_index)
    select->setSelectedIndex(old_selected_index);
}

void HTMLOptionElement::AccessKeyAction(SimulatedClickCreationScope) {
  // TODO(crbug.com/1176745): why creation_scope arg is not used at all?
  if (HTMLSelectElement* select = OwnerSelectElement())
    select->SelectOptionByAccessKey(this);
}

int HTMLOptionElement::index() const {
  // It would be faster to cache the index, but harder to get it right in all
  // cases.

  HTMLSelectElement* select_element = OwnerSelectElement();
  if (!select_element)
    return 0;

  int option_index = 0;
  for (auto* const option : select_element->GetOptionList()) {
    if (option == this)
      return option_index;
    ++option_index;
  }

  return 0;
}

int HTMLOptionElement::ListIndex() const {
  if (HTMLSelectElement* select_element = OwnerSelectElement())
    return select_element->ListIndexForOption(*this);
  return -1;
}

void HTMLOptionElement::ParseAttribute(
    const AttributeModificationParams& params) {
  const QualifiedName& name = params.name;
  if (name == html_names::kValueAttr) {
    if (HTMLDataListElement* data_list = OwnerDataListElement()) {
      data_list->OptionElementChildrenChanged();
    }
    if (HTMLSelectElement* select = OwnerSelectElement()) {
      select->SetNeedsValidityCheck();
    }
  } else if (name == html_names::kDisabledAttr) {
    if (params.old_value.IsNull() != params.new_value.IsNull()) {
      PseudoStateChanged(CSSSelector::kPseudoDisabled);
      PseudoStateChanged(CSSSelector::kPseudoEnabled);
      InvalidateIfHasEffectiveAppearance();
    }
  } else if (name == html_names::kSelectedAttr) {
    if (params.old_value.IsNull() != params.new_value.IsNull() && !is_dirty_)
      SetSelected(!params.new_value.IsNull());
    PseudoStateChanged(CSSSelector::kPseudoDefault);
  } else if (name == html_names::kLabelAttr) {
    if (HTMLSelectElement* select = OwnerSelectElement())
      select->OptionElementChildrenChanged(*this);
    UpdateLabel();
  } else {
    HTMLElement::ParseAttribute(params);
  }
}

String HTMLOptionElement::value() const {
  const AtomicString& value = FastGetAttribute(html_names::kValueAttr);
  if (!value.IsNull())
    return value;
  return CollectOptionInnerText()
      .StripWhiteSpace(IsHTMLSpace<UChar>)
      .SimplifyWhiteSpace(IsHTMLSpace<UChar>);
}

void HTMLOptionElement::setValue(const AtomicString& value) {
  setAttribute(html_names::kValueAttr, value);
}

bool HTMLOptionElement::Selected() const {
  return is_selected_;
}

void HTMLOptionElement::SetSelected(bool selected) {
  if (is_selected_ == selected)
    return;

  SetSelectedState(selected);

  if (HTMLSelectElement* select = OwnerSelectElement()) {
    select->OptionSelectionStateChanged(this, selected);
  }
}

bool HTMLOptionElement::selectedForBinding() const {
  return Selected();
}

void HTMLOptionElement::setSelectedForBinding(bool selected) {
  bool was_selected = is_selected_;
  SetSelected(selected);

  // As of December 2015, the HTML specification says the dirtiness becomes
  // true by |selected| setter unconditionally. However it caused a real bug,
  // crbug.com/570367, and is not compatible with other browsers.
  // Firefox seems not to set dirtiness if an option is owned by a select
  // element and selectedness is not changed.
  if (OwnerSelectElement() && was_selected == is_selected_)
    return;

  is_dirty_ = true;
}

void HTMLOptionElement::SetSelectedState(bool selected) {
  if (is_selected_ == selected)
    return;

  is_selected_ = selected;
  PseudoStateChanged(CSSSelector::kPseudoChecked);

  if (HTMLSelectElement* select = OwnerSelectElement()) {
    select->InvalidateSelectedItems();

    if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache()) {
      // If there is a layoutObject (most common), fire accessibility
      // notifications only when it's a listbox (and not a menu list). If
      // there's no layoutObject, fire them anyway just to be safe (to make sure
      // the AX tree is in sync).
      if (!select->GetLayoutObject() || !select->UsesMenuList()) {
        cache->ListboxOptionStateChanged(this);
        cache->ListboxSelectedChildrenChanged(select);
      }
    }
  }
}

void HTMLOptionElement::SetMultiSelectFocusedState(bool focused) {
  if (is_multi_select_focused_ == focused)
    return;

  if (auto* select = OwnerSelectElement()) {
    DCHECK(select->IsMultiple());
    is_multi_select_focused_ = focused;
    PseudoStateChanged(CSSSelector::kPseudoMultiSelectFocus);
  }
}

bool HTMLOptionElement::IsMultiSelectFocused() const {
  return is_multi_select_focused_;
}

void HTMLOptionElement::SetDirty(bool value) {
  is_dirty_ = value;
}

void HTMLOptionElement::ChildrenChanged(const ChildrenChange& change) {
  HTMLElement::ChildrenChanged(change);
  DidChangeTextContent();

  // If an element is inserted, We need to use MutationObserver to detect
  // textContent changes.
  if (change.type == ChildrenChangeType::kElementInserted && !text_observer_)
    text_observer_ = MakeGarbageCollected<OptionTextObserver>(*this);
}

void HTMLOptionElement::DidChangeTextContent() {
  if (HTMLDataListElement* data_list = OwnerDataListElement()) {
    data_list->OptionElementChildrenChanged();
  }
  if (HTMLSelectElement* select = OwnerSelectElement()) {
    select->OptionElementChildrenChanged(*this);
  }
  UpdateLabel();
}

HTMLDataListElement* HTMLOptionElement::OwnerDataListElement() const {
  return Traversal<HTMLDataListElement>::FirstAncestor(*this);
}

HTMLSelectElement* HTMLOptionElement::OwnerSelectElement() const {
  if (RuntimeEnabledFeatures::SelectParserRelaxationEnabled()) {
    // TODO(crbug.com/1511354): Consider using a flat tree traversal here
    // instead of a node traversal. That would probably also require
    // changing HTMLOptionsCollection to support flat tree traversals as well.
    // TODO(crbug.com/351990825): Cache the owner select ancestor on insertion
    // rather than doing a tree traversal here every time OwnerSelectElement is
    // called, which may be a lot.
    for (Node& ancestor : NodeTraversal::AncestorsOf(*this)) {
      if (IsA<HTMLOptionElement>(ancestor)) {
        // Don't associate nested <option>s with <select>s. This matches the
        // traversals in OptionList and HTMLOptionElement::InsertedInto.
        return nullptr;
      }
      if (auto* select = DynamicTo<HTMLSelectElement>(ancestor)) {
        return select;
      }
    }
  } else {
    if (!parentNode()) {
      return nullptr;
    }
    if (auto* select = DynamicTo<HTMLSelectElement>(*parentNode())) {
      return select;
    }
    if (IsA<HTMLOptGroupElement>(*parentNode())) {
      return DynamicTo<HTMLSelectElement>(parentNode()->parentNode());
    }
  }
  return nullptr;
}

String HTMLOptionElement::label() const {
  const AtomicString& label = FastGetAttribute(html_names::kLabelAttr);
  if (!label.IsNull())
    return label;
  return CollectOptionInnerText()
      .StripWhiteSpace(IsHTMLSpace<UChar>)
      .SimplifyWhiteSpace(IsHTMLSpace<UChar>);
}

void HTMLOptionElement::setLabel(const AtomicString& label) {
  setAttribute(html_names::kLabelAttr, label);
}

String HTMLOptionElement::TextIndentedToRespectGroupLabel() const {
  ContainerNode* parent = parentNode();
  if (parent && IsA<HTMLOptGroupElement>(*parent))
    return "    " + DisplayLabel();
  return DisplayLabel();
}

bool HTMLOptionElement::OwnElementDisabled() const {
  return FastHasAttribute(html_names::kDisabledAttr);
}

bool HTMLOptionElement::IsDisabledFormControl() const {
  if (OwnElementDisabled())
    return true;
  if (Element* parent = parentElement())
    return IsA<HTMLOptGroupElement>(*parent) && parent->IsDisabledFormControl();
  return false;
}

String HTMLOptionElement::DefaultToolTip() const {
  if (HTMLSelectElement* select = OwnerSelectElement())
    return select->DefaultToolTip();
  return String();
}

String HTMLOptionElement::CollectOptionInnerText() const {
  StringBuilder text;
  for (Node* node = firstChild(); node;) {
    if (node->IsTextNode())
      text.Append(node->nodeValue());
    // Text nodes inside script elements are not part of the option text.
    auto* element = DynamicTo<Element>(node);
    if (element && element->IsScriptElement())
      node = NodeTraversal::NextSkippingChildren(*node, this);
    else
      node = NodeTraversal::Next(*node, this);
  }
  return text.ToString();
}

HTMLFormElement* HTMLOptionElement::form() const {
  if (HTMLSelectElement* select_element = OwnerSelectElement())
    return select_element->formOwner();

  return nullptr;
}

void HTMLOptionElement::DidAddUserAgentShadowRoot(ShadowRoot& root) {
  UpdateLabel();
}

void HTMLOptionElement::UpdateLabel() {
  // For appearance:base-select <select> we also need to render all children. We
  // only check UsesMenuList and not computed style because we don't want to
  // change DOM content based on computed style and because appearance:auto/none
  // don't render the UA shadowroot when UsesMenuList is true.
  if (RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
    if (auto* select = OwnerSelectElement()) {
      if (select->UsesMenuList()) {
        return;
      }
    }
  }

  if (ShadowRoot* root = UserAgentShadowRoot())
    root->setTextContent(DisplayLabel());
}

Node::InsertionNotificationRequest HTMLOptionElement::InsertedInto(
    ContainerNode& insertion_point) {
  auto return_value = HTMLElement::InsertedInto(insertion_point);
  if (!RuntimeEnabledFeatures::SelectParserRelaxationEnabled()) {
    CHECK(!RuntimeEnabledFeatures::CustomizableSelectEnabled());
    return return_value;
  }

  auto* parent_select = DynamicTo<HTMLSelectElement>(parentNode());
  if (!parent_select) {
    if (auto* optgroup = DynamicTo<HTMLOptGroupElement>(parentNode())) {
      parent_select = DynamicTo<HTMLSelectElement>(optgroup->parentNode());
    }
  }
  if (parent_select) {
    // Don't call OptionInserted because HTMLSelectElement::ChildrenChanged or
    // HTMLOptGroupElement::ChildrenChanged will call it for us in this case. If
    // insertion_point is an ancestor of parent_select, then we shouldn't really
    // be doing anything here and OptionInserted was already called in a
    // previous insertion.
    // TODO(crbug.com/1511354): When the CustomizableSelect flag is removed, we
    // can remove the code in HTMLSelectElement::ChildrenChanged and
    // HTMLOptGroupElement::ChildrenChanged which handles this case as well as
    // the code here which avoids handling it.
    // TODO(crbug.com/1511354): This UsesMenuList check doesn't account for
    // the case when the select's rendering is changed after insertion.
    SetTextOnlyRendering(!parent_select->UsesMenuList());
    return return_value;
  }

  // If there is a <select> in between this and insertion_point, then don't call
  // OptionInserted. Otherwise, if this option is being inserted into a <select>
  // ancestor, then we must call OptionInserted on it.
  bool passed_insertion_point = false;
  for (Node& ancestor : NodeTraversal::AncestorsOf(*this)) {
    if (IsA<HTMLOptionElement>(ancestor)) {
      // Don't call OptionInserted() on nested <option>s. This matches the
      // traversals in OptionList and OwnerSelectElement.
      break;
    }
    if (&ancestor == &insertion_point) {
      passed_insertion_point = true;
    }
    if (auto* select = DynamicTo<HTMLSelectElement>(ancestor)) {
      if (passed_insertion_point) {
        // TODO(crbug.com/1511354): This UsesMenuList check doesn't account for
        // the case when the select's rendering is changed after insertion.
        SetTextOnlyRendering(!select->UsesMenuList());
        select->OptionInserted(*this, Selected());
      }
      break;
    }
  }

  return return_value;
}

void HTMLOptionElement::RemovedFrom(ContainerNode& insertion_point) {
  HTMLElement::RemovedFrom(insertion_point);
  if (!RuntimeEnabledFeatures::SelectParserRelaxationEnabled()) {
    CHECK(!RuntimeEnabledFeatures::CustomizableSelectEnabled());
    return;
  }

  // This code determines the value of was_removed_from_select_parent, which
  // should be true in the case that this <option> was a child of a <select> and
  // got removed, or there was an <optgroup> directly in between this <option>
  // and a <select> and either the optgroup-option or select-optgroup child
  // relationship was disconnected.
  bool insertion_point_passed = false;
  bool is_parent_select_or_optgroup = false;
  ContainerNode* parent = parentNode();
  if (!parent) {
    parent = &insertion_point;
    insertion_point_passed = true;
  }
  if (IsA<HTMLSelectElement>(parent)) {
    is_parent_select_or_optgroup = true;
  } else if (IsA<HTMLOptGroupElement>(parent)) {
    parent = parent->parentNode();
    if (!parent) {
      parent = &insertion_point;
      insertion_point_passed = true;
    }
    is_parent_select_or_optgroup = IsA<HTMLSelectElement>(parent);
  }
  bool was_removed_from_select_parent =
      insertion_point_passed && is_parent_select_or_optgroup;

  if (was_removed_from_select_parent) {
    // Don't call select->OptionRemoved() in this case because
    // HTMLSelectElement::ChildrenChanged or
    // HTMLOptGroupElement::ChildrenChanged will call it for us.
    SetTextOnlyRendering(true);
    return;
  }

  for (Node& ancestor : NodeTraversal::AncestorsOf(*this)) {
    // If this option is still associated with a <select> inside the detached
    // subtree, then we should not call OptionRemoved() because we don't call
    // OptionInserted() in the corresponding attachment case. Also, APIs like
    // select.options should still work when the <select> is detached.
    // Nested options should not be associated with selects.
    if (IsA<HTMLSelectElement>(ancestor) || IsA<HTMLOptionElement>(ancestor)) {
      return;
    }
  }

  for (Node& ancestor : NodeTraversal::InclusiveAncestorsOf(insertion_point)) {
    if (IsA<HTMLOptionElement>(ancestor)) {
      // Nested options should not be associated with selects.
      return;
    }
    if (auto* select = DynamicTo<HTMLSelectElement>(ancestor)) {
      SetTextOnlyRendering(true);
      select->OptionRemoved(*this);
      break;
    }
  }
}

void HTMLOptionElement::SetTextOnlyRendering(bool text_only) {
  if (!RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
    return;
  }

#if DCHECK_IS_ON()
  {
    // Double-check to make sure that we are setting the correct state according
    // to the DOM tree. If there is a nearest ancestor <select> and it
    // UsesMenuList, then we should be rendering all content rather than
    // text-only.
    auto* select = OwnerSelectElement();
    DCHECK_EQ(select && select->UsesMenuList(), !text_only);
  }
#endif

  // If the label attribute is present, then we should be rendering that
  // instead, even in appearance:base-select mode:
  // https://github.com/openui/open-ui/issues/1115
  if (!FastGetAttribute(html_names::kLabelAttr).empty()) {
    text_only = true;
  }

  if (auto* first_child = GetShadowRoot()->firstChild()) {
    bool currently_text_only = first_child->getNodeType() == kTextNode;
    CHECK_NE(currently_text_only, IsA<HTMLSlotElement>(first_child))
        << " <option>'s UA ShadowRoot should either be text or a <slot>.";
    if (currently_text_only == text_only) {
      return;
    }
  }

  GetShadowRoot()->RemoveChildren();
  if (!text_only) {
    // Render all child content by just having an unnamed <slot>.
    GetShadowRoot()->AppendChild(
        MakeGarbageCollected<HTMLSlotElement>(GetDocument()));
  } else {
    // Render only text content by only having a text node inside the
    // shadowroot.
    UpdateLabel();
  }
}

bool HTMLOptionElement::SpatialNavigationFocused() const {
  HTMLSelectElement* select = OwnerSelectElement();
  if (!select || !select->IsFocused())
    return false;
  return select->SpatialNavigationFocusedOption() == this;
}

bool HTMLOptionElement::IsDisplayNone() const {
  const ComputedStyle* style = GetComputedStyle();
  return !style || style->Display() == EDisplay::kNone;
}

void HTMLOptionElement::DefaultEventHandler(Event& event) {
  DefaultEventHandlerInternal(event);
  HTMLElement::DefaultEventHandler(event);
}

void HTMLOptionElement::DefaultEventHandlerInternal(Event& event) {
  auto* select = OwnerSelectElement();
  if (select && !select->IsAppearanceBasePicker()) {
    // We only want to apply mouse/keyboard behavior for appearance:base-select
    // select pickers.
    select = nullptr;
  }

  if (select) {
    // This logic to determine if we should select the option is copied from
    // ListBoxSelectType::DefaultEventHandler. It will likely change when we try
    // to spec it.
    const auto* mouse_event = DynamicTo<MouseEvent>(event);
    const auto* gesture_event = DynamicTo<GestureEvent>(event);
    if ((event.type() == event_type_names::kGesturetap && gesture_event) ||
        (event.type() == event_type_names::kMousedown && mouse_event &&
         mouse_event->button() ==
             static_cast<int16_t>(WebPointerProperties::Button::kLeft))) {
      select->SelectOptionByPopup(this);
      select->HidePopup();
      event.SetDefaultHandled();
      return;
    }
  }

  auto* keyboard_event = DynamicTo<KeyboardEvent>(event);
  int tab_ignore_modifiers = WebInputEvent::kControlKey |
                             WebInputEvent::kAltKey | WebInputEvent::kMetaKey;
  int ignore_modifiers = WebInputEvent::kShiftKey | tab_ignore_modifiers;

  if (keyboard_event && event.type() == event_type_names::kKeydown) {
    const AtomicString key(keyboard_event->key());

    if (!(keyboard_event->GetModifiers() & ignore_modifiers)) {
      if (key == keywords::kArrowUp && select) {
        OptionListIterator option_list_iterator =
            select->GetOptionList().begin();
        while (*option_list_iterator && *option_list_iterator != this) {
          ++option_list_iterator;
        }

        if (*option_list_iterator) {
          CHECK_EQ(*option_list_iterator, this);

          HTMLOptionElement* previous_option = nullptr;
          do {
            --option_list_iterator;
            previous_option = *option_list_iterator;

            if (previous_option && previous_option->IsFocusable()) {
              previous_option->Focus(FocusParams(FocusTrigger::kUserGesture));
              break;
            }
          } while (previous_option);

          event.SetDefaultHandled();
          return;
        }
      } else if (key == keywords::kArrowDown && select) {
        OptionListIterator option_list_iterator =
            select->GetOptionList().begin();
        while (*option_list_iterator && *option_list_iterator != this) {
          ++option_list_iterator;
        }

        if (*option_list_iterator) {
          CHECK_EQ(*option_list_iterator, this);

          HTMLOptionElement* next_option = nullptr;
          do {
            ++option_list_iterator;
            next_option = *option_list_iterator;

            if (next_option && next_option->IsFocusable()) {
              next_option->Focus(FocusParams(FocusTrigger::kUserGesture));
              break;
            }
          } while (next_option);

          event.SetDefaultHandled();
          return;
        }
      } else if ((key == " " || key == keywords::kCapitalEnter) && select) {
        select->SelectOptionByPopup(this);
        select->HidePopup();
        event.SetDefaultHandled();
        return;
      }
    }

    if (key == keywords::kTab &&
        !(keyboard_event->GetModifiers() & tab_ignore_modifiers)) {
      if (select) {
        // TODO(http://crbug.com/1511354): Consider focusing something in this
        // case. https://github.com/openui/open-ui/issues/1016
        select->HidePopup();
        event.SetDefaultHandled();
        return;
      }
    }
  }
}

void HTMLOptionElement::FinishParsingChildren() {
  HTMLElement::FinishParsingChildren();
  if (RuntimeEnabledFeatures::CustomizableSelectEnabled() && Selected()) {
    auto* select = OwnerSelectElement();
    if (select && select->UsesMenuList() && !select->IsMultiple()) {
      CHECK_EQ(this, select->SelectedOption());
      select->UpdateAllSelectedcontents();
    }
  }
}

}  // namespace blink
```