Response:
My thought process for analyzing the provided code snippet and generating the summary goes like this:

1. **Understand the Request:** The request asks for a summary of the `HTMLSelectElement.cc` file's functionality, focusing on its relationships with JavaScript, HTML, and CSS, as well as potential user errors and how user actions might lead to the execution of this code. It's explicitly marked as Part 1 of 3, indicating a need for a general overview in this part.

2. **Initial Code Scan and Keyword Recognition:** I first scanned the code, looking for key terms and patterns that indicate the file's purpose. I noticed:
    * `#include "third_party/blink/renderer/core/html/forms/html_select_element.h"`: This confirms the file implements the `HTMLSelectElement` class.
    * Copyright notices: Indicate the long history and multiple contributors to this code.
    * Inclusion of various header files: These provide clues about the functionalities the class depends on (e.g., `mojom::input::FocusType`, `bindings/core/v8/...`, `core/accessibility/`, `core/css/`, `core/dom/`, `core/html/forms/`, `core/layout/`, `core/page/`).
    * `namespace blink`:  Confirms it's part of the Blink rendering engine.
    * Mentions of "multiple" attribute, "size" attribute, "options", "selectedOptions", "value".
    * Functions like `add`, `remove`, `setValueForBinding`, `SetValue`, `ParseAttribute`, `CreateLayoutObject`, `selectedOptions`, `options`, `OptionElementChildrenChanged`, `AccessKeyAction`, `namedItem`, `item`, `setLength`, `SelectAll`, `GetListItems`, `RecalcListItems`, `ResetToDefaultSelection`, `SelectOption`.

3. **Core Functionality Identification (High-Level):** Based on the keywords and header inclusions, I deduced the primary function is to manage the behavior and rendering of the `<select>` HTML element within the Blink rendering engine. This includes:
    * Handling attributes like `multiple` and `size`.
    * Managing the list of `<option>` elements within the `<select>`.
    * Keeping track of selected options.
    * Integrating with the form submission process.
    * Interacting with accessibility features.
    * Potentially influencing layout and styling.

4. **Relationship with HTML, CSS, and JavaScript:**
    * **HTML:** The file directly relates to the `<select>` element and its child elements (`<option>`, `<optgroup>`). It parses HTML attributes (`size`, `multiple`, etc.) and manages the structure of the `<select>` element's content.
    * **CSS:** The code interacts with the CSS engine (`core/css/`) for styling and layout. The `UsesMenuList()` function and the creation of `LayoutFlexibleBox` or `LayoutBlockFlow` indicate how the rendering changes based on CSS and attributes.
    * **JavaScript:** The file provides the underlying implementation for JavaScript APIs related to the `<select>` element, such as accessing and modifying options (`options()`, `add()`, `remove()`), getting and setting the selected value (`value`, `setValueForBinding()`), and handling events. The inclusion of `bindings/core/v8/...` headers is a strong indicator of this.

5. **Logic and Data Flow (Simplified):** I started sketching a simplified flow:
    * HTML is parsed, creating an `HTMLSelectElement` object.
    * Attributes are parsed and influence the object's state.
    * Child `<option>` and `<optgroup>` elements are added and managed.
    * User interaction (clicks, keyboard input) triggers methods within this class.
    * JavaScript can interact with the object through its API.
    * The class determines how the `<select>` element is rendered (e.g., dropdown or listbox).
    * Changes to the selection trigger events.

6. **User/Programming Errors:**  I considered common mistakes:
    * Incorrectly nested elements within `<select>` (though the code snippet shows some leniency for backward compatibility).
    * Manipulating the `<select>`'s content via JavaScript in ways that violate the expected structure.
    * Not handling events correctly when the selection changes.

7. **User Actions:**  I thought about how a user interacts with a `<select>`:
    * Clicking to open the dropdown or select an option.
    * Using the keyboard to navigate and select options.
    * Submitting a form containing the `<select>` element.

8. **Structuring the Summary:**  I decided to organize the summary by directly addressing the prompt's points:
    * **Core Functionality:**  Provide a concise overview.
    * **HTML Relationship:** Explain how it handles HTML structure and attributes.
    * **CSS Relationship:** Explain its role in rendering and layout.
    * **JavaScript Relationship:**  Explain how it provides the underlying implementation for JavaScript APIs.
    * **Assumptions and Logic:** Detail how it manages options and selection (though the prompt explicitly asked for this, the snippet doesn't show complex logic *yet*).
    * **User/Programming Errors:**  Give concrete examples.
    * **User Actions:** Describe how user interaction leads to this code's execution.

9. **Refinement and Language:** I aimed for clear and concise language, avoiding overly technical jargon where possible while still accurately reflecting the code's purpose. I used terms like "manages," "handles," "provides," and "interacts" to convey the different aspects of its functionality.

This iterative process of scanning, identifying key elements, deducing functionality, considering relationships, and structuring the information allowed me to create the comprehensive summary. The "Part 1" designation in the prompt reminded me to keep the summary at a higher level, anticipating more specific details in the subsequent parts.
```cpp
/*
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2009, 2010, 2011 Apple Inc. All rights
 * reserved.
 *           (C) 2006 Alexey Proskuryakov (ap@nypop.com)
 * Copyright (C) 2010 Google Inc. All rights reserved.
 * Copyright (C) 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB. If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "third_party/blink/renderer/core/html/forms/html_select_element.h"

// ... other includes ...

namespace blink {

// ... some static constants ...

// Observer class to monitor changes within a <select> element for specific content model rules.
class SelectDescendantsObserver : public MutationObserver::Delegate {
 public:
  explicit SelectDescendantsObserver(HTMLSelectElement& select)
      : select_(select), observer_(MutationObserver::Create(this)) { /* ... */ }

  ExecutionContext* GetExecutionContext() const override { /* ... */ }

  void Deliver(const MutationRecordVector& records,
               MutationObserver&) override { /* ... */ }

  void Disconnect() { /* ... */ }

  void Trace(Visitor* visitor) const override { /* ... */ }

 private:
  void TraverseDescendants() { /* ... */ }
  void AddWarningToElement(Element* element) { /* ... */ }
  bool IsDescendantAllowed(const Element* element) { /* ... */ }

  Member<HTMLSelectElement> select_;
  Member<MutationObserver> observer_;
};

HTMLSelectElement::HTMLSelectElement(Document& document)
    : HTMLFormControlElementWithState(html_names::kSelectTag, document),
      type_ahead_(this),
      size_(0),
      last_on_change_option_(nullptr),
      is_multiple_(false),
      should_recalc_list_items_(false),
      index_to_select_on_cancel_(-1) {
  // ... initialization ...
}

HTMLSelectElement::~HTMLSelectElement() = default;

FormControlType HTMLSelectElement::FormControlType() const { /* ... */ }
const AtomicString& HTMLSelectElement::FormControlTypeAsString() const { /* ... */ }
bool HTMLSelectElement::HasPlaceholderLabelOption() const { /* ... */ }
String HTMLSelectElement::validationMessage() const { /* ... */ }
bool HTMLSelectElement::ValueMissing() const { /* ... */ }
String HTMLSelectElement::DefaultToolTip() const { /* ... */ }
void HTMLSelectElement::SelectMultipleOptionsByPopup(
    const Vector<int>& list_indices) { /* ... */ }
unsigned HTMLSelectElement::ListBoxSize() const { /* ... */ }
void HTMLSelectElement::UpdateUsesMenuList() { /* ... */ }
int HTMLSelectElement::ActiveSelectionEndListIndex() const { /* ... */ }
HTMLOptionElement* HTMLSelectElement::ActiveSelectionEnd() const { /* ... */ }
void HTMLSelectElement::add(
    const V8UnionHTMLOptGroupElementOrHTMLOptionElement* element,
    const V8UnionHTMLElementOrLong* before,
    ExceptionState& exception_state) { /* ... */ }
void HTMLSelectElement::remove(int option_index) { /* ... */ }
String HTMLSelectElement::Value() const { /* ... */ }
void HTMLSelectElement::setValueForBinding(const String& value) { /* ... */ }
void HTMLSelectElement::SetValue(const String& value,
                                 bool send_events,
                                 WebAutofillState autofill_state) { /* ... */ }
void HTMLSelectElement::SetAutofillValue(const String& value,
                                         WebAutofillState autofill_state) { /* ... */ }
String HTMLSelectElement::SuggestedValue() const { /* ... */ }
void HTMLSelectElement::SetSuggestedValue(const String& value) { /* ... */ }
bool HTMLSelectElement::IsPresentationAttribute(
    const QualifiedName& name) const { /* ... */ }
void HTMLSelectElement::ParseAttribute(
    const AttributeModificationParams& params) { /* ... */ }
bool HTMLSelectElement::MayTriggerVirtualKeyboard() const { /* ... */ }
bool HTMLSelectElement::ShouldHaveFocusAppearance() const { /* ... */ }
bool HTMLSelectElement::CanSelectAll() const { /* ... */ }
LayoutObject* HTMLSelectElement::CreateLayoutObject(
    const ComputedStyle& style) { /* ... */ }
HTMLCollection* HTMLSelectElement::selectedOptions() { /* ... */ }
HTMLOptionsCollection* HTMLSelectElement::options() { /* ... */ }
void HTMLSelectElement::OptionElementChildrenChanged(
    const HTMLOptionElement& option) { /* ... */ }
void HTMLSelectElement::AccessKeyAction(
    SimulatedClickCreationScope creation_scope) { /* ... */ }
HTMLOptionElement* HTMLSelectElement::namedItem(const AtomicString& name) { /* ... */ }
HTMLOptionElement* HTMLSelectElement::item(unsigned index) { /* ... */ }
void HTMLSelectElement::SetOption(unsigned index,
                                  HTMLOptionElement* option,
                                  ExceptionState& exception_state) { /* ... */ }
void HTMLSelectElement::setLength(unsigned new_len,
                                  ExceptionState& exception_state) { /* ... */ }
bool HTMLSelectElement::IsRequiredFormControl() const { /* ... */ }
HTMLOptionElement* HTMLSelectElement::OptionAtListIndex(int list_index) const { /* ... */ }
void HTMLSelectElement::SelectAll() { /* ... */ }
const HTMLSelectElement::ListItems& HTMLSelectElement::GetListItems() const { /* ... */ }
void HTMLSelectElement::InvalidateSelectedItems() { /* ... */ }
void HTMLSelectElement::SetRecalcListItems() { /* ... */ }
void HTMLSelectElement::RecalcListItems() const { /* ... */ }
void HTMLSelectElement::ResetToDefaultSelection(ResetReason reason) { /* ... */ }
void HTMLSelectElement::SelectOption(
    HTMLOptionElement* option,
    SelectOptionFlags flags,
    WebAutofillState autofill_state) { /* ... */ }
void HTMLSelectElement::SetSelectedIndex(int index,
                                         bool send_events) { /* ... */ }
int HTMLSelectElement::selectedIndex() const { /* ... */ }
void HTMLSelectElement::SetMultiple(bool multiple) { /* ... */ }
bool HTMLSelectElement::IsMultiple() const { /* ... */ }
void HTMLSelectElement::focus(mojom::blink::FocusType focus_type) { /* ... */ }
void HTMLSelectElement::blur() { /* ... */ }
bool HTMLSelectElement::ShouldParticipateInTabIndexNavigation() const { /* ... */ }
void HTMLSelectElement::UpdateUserAgentShadowTree(ShadowRoot& root) { /* ... */ }
void HTMLSelectElement::UpdateMutationObserver() { /* ... */ }
void HTMLSelectElement::InsertedInto(ContainerNode& parent) { /* ... */ }
void HTMLSelectElement::RemovedFrom(ContainerNode& parent) { /* ... */ }
void HTMLSelectElement::ChildrenChanged(bool changed_by_parser,
                                        Node* before_child,
                                        Node* added_child,
                                        unsigned count,
                                        Node* removed_child) { /* ... */ }
bool HTMLSelectElement::supportsFocus() const { /* ... */ }
bool HTMLSelectElement::IsMouseFocusable() const { /* ... */ }
void HTMLSelectElement::DefaultEventHandler(Event* event) { /* ... */ }
void HTMLSelectElement::Trace(Visitor* visitor) const { /* ... */ }

// ... closing namespace ...
```

## 功能归纳 (第1部分)

`blink/renderer/core/html/forms/html_select_element.cc` 文件是 Chromium Blink 渲染引擎中实现 **`<select>` HTML 元素** 行为和功能的关键源代码文件。 它的主要职责是：

**1. 实现 HTMLSelectElement 类:**
   - 该文件定义了 `HTMLSelectElement` 类，该类继承自 `HTMLFormControlElementWithState`，代表了 DOM 树中的 `<select>` 元素。
   - 它包含了 `<select>` 元素的状态管理、属性处理、事件处理以及与其他 Blink 组件交互的逻辑。

**2. 管理 `<select>` 元素的内部状态:**
   - 维护了关于 `<select>` 元素各种属性的状态，例如 `size` (显示的选项数量), `multiple` (是否允许多选), 以及当前选中的选项。
   - 使用了 `type_ahead_` 成员变量来实现输入预测功能。
   - 记录了上一次触发 `onchange` 事件的选项 (`last_on_change_option_`)。
   - 使用 `should_recalc_list_items_` 标记来控制何时重新计算选项列表。

**3. 处理 `<select>` 元素的属性:**
   - 实现了 `ParseAttribute` 方法来解析和处理 `<select>` 元素的 HTML 属性，如 `size`, `multiple`, `accesskey` 等。
   - 针对 `size` 和 `multiple` 属性的修改，会触发相应的渲染更新和状态改变。

**4. 管理 `<option>` 元素:**
   - 提供了添加 (`add`) 和删除 (`remove`) `<option>` 元素的方法。
   - 实现了获取和设置选项的功能，例如通过索引 (`item`) 或名称 (`namedItem`) 获取 `<option>` 元素。
   - 提供了设置选项列表长度 (`setLength`) 的功能。
   - 维护了选项列表 (`list_items_`)，并提供了方法来重新计算该列表 (`RecalcListItems`).

**5. 处理选项的选择和取消选择:**
   - 实现了选择特定选项 (`SelectOption`) 和设置选中索引 (`SetSelectedIndex`) 的逻辑。
   - 提供了获取当前选中选项 (`Value`, `SelectedOption`) 和所有选中选项 (`selectedOptions`) 的方法。
   - 针对多选 `<select>` 元素，提供了通过弹出窗口选择多个选项 (`SelectMultipleOptionsByPopup`) 的功能。
   - 实现了重置到默认选择的功能 (`ResetToDefaultSelection`).

**6. 与表单功能集成:**
   - 实现了 `FormControlType` 和 `FormControlTypeAsString` 方法来标识 `<select>` 元素的表单控件类型。
   - 提供了获取验证消息 (`validationMessage`) 和检查是否缺少值 (`ValueMissing`) 的功能，用于表单验证。

**7. 与渲染引擎集成:**
   - 决定了 `<select>` 元素的布局对象类型 (`CreateLayoutObject`)，根据 `UsesMenuList` 的状态选择 `LayoutFlexibleBox` 或 `LayoutBlockFlow`。
   - 提供了更新用户代理阴影树 (`UpdateUserAgentShadowTree`) 的方法，用于自定义 `<select>` 元素的默认外观。

**8. 处理焦点和键盘交互:**
   - 实现了获取焦点 (`focus`) 和失去焦点 (`blur`) 的方法。
   - 提供了判断是否参与 Tab 键导航 (`ShouldParticipateInTabIndexNavigation`) 和是否支持焦点 (`supportsFocus`) 的功能。
   - 实现了访问键操作 (`AccessKeyAction`)。

**9. 与 JavaScript 绑定:**
   - 提供了 JavaScript 可访问的属性和方法，例如 `value`, `selectedIndex`, `options`, `add`, `remove` 等。
   - `setValueForBinding` 方法用于从 JavaScript 设置 `<select>` 元素的值。

**10. 监听子元素变化:**
    - 使用 `SelectDescendantsObserver` 类来监控 `<select>` 元素及其子元素的结构变化，并对不符合规范的内容模型发出警告。

**11. 自动填充支持:**
    - 提供了 `SetAutofillValue` 和 `SetSuggestedValue` 方法来支持浏览器的自动填充功能。

**总而言之，`html_select_element.cc` 负责 `<select>` 元素在 Blink 渲染引擎中的核心行为和逻辑实现，包括状态管理、属性处理、选项管理、选择逻辑、与表单和渲染引擎的集成，以及与 JavaScript 的交互。**

### 提示词
```
这是目录为blink/renderer/core/html/forms/html_select_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2009, 2010, 2011 Apple Inc. All rights
 * reserved.
 *           (C) 2006 Alexey Proskuryakov (ap@nypop.com)
 * Copyright (C) 2010 Google Inc. All rights reserved.
 * Copyright (C) 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
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

#include "third_party/blink/renderer/core/html/forms/html_select_element.h"

#include "build/build_config.h"
#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mutation_observer_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_htmlelement_long.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_htmloptgroupelement_htmloptionelement.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/dom/events/simulated_click_options.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/mutation_observer.h"
#include "third_party/blink/renderer/core/dom/mutation_record.h"
#include "third_party/blink/renderer/core/dom/node_lists_node_data.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_data_list_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_opt_group_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_options_collection.h"
#include "third_party/blink/renderer/core/html/forms/html_selected_content_element.h"
#include "third_party/blink/renderer/core/html/forms/select_type.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_hr_element.h"
#include "third_party/blink/renderer/core/html/html_no_script_element.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/flex/layout_flexible_box.h"
#include "third_party/blink/renderer/core/layout/hit_test_request.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/spatial_navigation.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "ui/base/ui_base_features.h"

namespace blink {

using mojom::blink::FormControlType;

// https://html.spec.whatwg.org/#dom-htmloptionscollection-length
static const unsigned kMaxListItems = 100000;

// Default size when the multiple attribute is present but size attribute is
// absent.
const int kDefaultListBoxSize = 4;

class SelectDescendantsObserver : public MutationObserver::Delegate {
 public:
  explicit SelectDescendantsObserver(HTMLSelectElement& select)
      : select_(select), observer_(MutationObserver::Create(this)) {
    CHECK(RuntimeEnabledFeatures::CustomizableSelectEnabled());
    DCHECK(select_->IsAppearanceBasePicker());

    MutationObserverInit* init = MutationObserverInit::Create();
    init->setChildList(true);
    init->setSubtree(true);
    observer_->observe(select_, init, ASSERT_NO_EXCEPTION);
    // Traverse descendants that have been added to the select so far.
    TraverseDescendants();
  }

  ExecutionContext* GetExecutionContext() const override {
    return select_->GetExecutionContext();
  }

  void Deliver(const MutationRecordVector& records,
               MutationObserver&) override {
    for (const auto& record : records) {
      if (record->type() == "childList") {
        auto* added_nodes = record->addedNodes();
        for (unsigned i = 0; i < added_nodes->length(); ++i) {
          auto* descendant = added_nodes->item(i);
          if (!descendant ||
              (descendant->IsTextNode() &&
               descendant->textContent().ContainsOnlyWhitespaceOrEmpty())) {
            continue;
          }
          if (auto* descendant_element = DynamicTo<Element>(descendant)) {
#if DCHECK_IS_ON()
            if (!descendant_element->parentElement()) {
              // If the descendant doesn't have a parent element, verify that
              // the target is `HTMLSelectedContentElement`.
              auto* target_element = DynamicTo<Element>(record->target());
              DCHECK(target_element);
              auto* target_html_element =
                  DynamicTo<HTMLElement>(target_element);
              DCHECK(IsA<HTMLSelectedContentElement>(*target_html_element));
            }
#endif
            AddWarningToElement(descendant_element);
          }
        }
      }
    }
  }

  void Disconnect() { observer_->disconnect(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(select_);
    visitor->Trace(observer_);
    MutationObserver::Delegate::Trace(visitor);
  }

 private:
  void TraverseDescendants() {
    for (Element* current_element = ElementTraversal::FirstWithin(*select_);
         current_element;
         current_element = ElementTraversal::Next(*current_element, select_)) {
      AddWarningToElement(current_element);
    }
  }

  void AddWarningToElement(Element* element) {
    if (element && !IsDescendantAllowed(element)) {
      // TODO(ansollan): Report an Issue to the DevTools' Issue Panel as well.
      element->AddConsoleMessage(
          mojom::blink::ConsoleMessageSource::kRecommendation,
          mojom::blink::ConsoleMessageLevel::kError,
          "A descendant of a <select> does not follow the content "
          "model.");
    }
  }

  bool IsDescendantAllowed(const Element* element) {
    DCHECK(element);
    auto* descendant_html_element = DynamicTo<HTMLElement>(*element);
    if (!descendant_html_element) {
      return false;
    }
    // Get the parent of the element.
    Element* parent_element = element->parentElement();
    if (!parent_element) {
      // Assume descendant is being appended to a `HTMLSelectedContentElement`.
      // TODO(ansollan): Add content model checks for <selectedcontent>
      // descendants.
      return !descendant_html_element->IsInteractiveContent();
    }
    auto* ancestor_html_element = DynamicTo<HTMLElement>(*parent_element);
    if (!ancestor_html_element) {
      return false;
    }

    if (IsA<HTMLSelectElement>(*ancestor_html_element)) {
      return IsA<HTMLButtonElement>(*descendant_html_element) ||
             IsA<HTMLOptionElement>(*descendant_html_element) ||
             IsA<HTMLOptGroupElement>(*descendant_html_element) ||
             IsA<HTMLHRElement>(*descendant_html_element) ||
             IsA<HTMLDivElement>(*descendant_html_element) ||
             IsA<HTMLNoScriptElement>(*descendant_html_element) ||
             IsA<HTMLScriptElement>(*descendant_html_element) ||
             IsA<HTMLTemplateElement>(*descendant_html_element);
    }
    // TODO(ansollan): Add content model checks for <option>, <optgroup>, <div>,
    // <svg>, and phrasing content descendants.
    if (IsA<HTMLOptGroupElement>(*ancestor_html_element) ||
        IsA<HTMLOptionElement>(*ancestor_html_element) ||
        IsA<HTMLDivElement>(*ancestor_html_element) ||
        IsA<HTMLNoScriptElement>(*ancestor_html_element) ||
        IsA<HTMLScriptElement>(*ancestor_html_element) ||
        IsA<HTMLTemplateElement>(*ancestor_html_element)) {
      return !descendant_html_element->IsInteractiveContent();
    }
    return false;
  }

  Member<HTMLSelectElement> select_;
  Member<MutationObserver> observer_;
};

HTMLSelectElement::HTMLSelectElement(Document& document)
    : HTMLFormControlElementWithState(html_names::kSelectTag, document),
      type_ahead_(this),
      size_(0),
      last_on_change_option_(nullptr),
      is_multiple_(false),
      should_recalc_list_items_(false),
      index_to_select_on_cancel_(-1) {
  // Make sure SelectType is created after initializing |uses_menu_list_|.
  select_type_ = SelectType::Create(*this);
  SetHasCustomStyleCallbacks();
  EnsureUserAgentShadowRoot(SlotAssignmentMode::kManual);
}

HTMLSelectElement::~HTMLSelectElement() = default;

FormControlType HTMLSelectElement::FormControlType() const {
  return is_multiple_ ? FormControlType::kSelectMultiple
                      : FormControlType::kSelectOne;
}

const AtomicString& HTMLSelectElement::FormControlTypeAsString() const {
  DEFINE_STATIC_LOCAL(const AtomicString, select_multiple, ("select-multiple"));
  DEFINE_STATIC_LOCAL(const AtomicString, select_one, ("select-one"));
  return is_multiple_ ? select_multiple : select_one;
}

bool HTMLSelectElement::HasPlaceholderLabelOption() const {
  // The select element has no placeholder label option if it has an attribute
  // "multiple" specified or a display size of non-1.
  //
  // The condition "size() > 1" is not compliant with the HTML5 spec as of Dec
  // 3, 2010. "size() != 1" is correct.  Using "size() > 1" here because
  // size() may be 0 in WebKit.  See the discussion at
  // https://bugs.webkit.org/show_bug.cgi?id=43887
  //
  // "0 size()" happens when an attribute "size" is absent or an invalid size
  // attribute is specified.  In this case, the display size should be assumed
  // as the default.  The default display size is 1 for non-multiple select
  // elements, and 4 for multiple select elements.
  //
  // Finally, if size() == 0 and non-multiple, the display size can be assumed
  // as 1.
  if (IsMultiple() || size() > 1)
    return false;

  // TODO(tkent): This function is called in CSS selector matching. Using
  // listItems() might have performance impact.
  if (GetListItems().size() == 0)
    return false;

  auto* option_element = DynamicTo<HTMLOptionElement>(GetListItems()[0].Get());
  if (!option_element)
    return false;

  return option_element->value().empty();
}

String HTMLSelectElement::validationMessage() const {
  if (!willValidate())
    return String();
  if (CustomError())
    return CustomValidationMessage();
  if (ValueMissing()) {
    return GetLocale().QueryString(IDS_FORM_VALIDATION_VALUE_MISSING_SELECT);
  }
  return String();
}

bool HTMLSelectElement::ValueMissing() const {
  if (!IsRequired())
    return false;

  int first_selection_index = selectedIndex();

  // If a non-placeholder label option is selected (firstSelectionIndex > 0),
  // it's not value-missing.
  return first_selection_index < 0 ||
         (!first_selection_index && HasPlaceholderLabelOption());
}

String HTMLSelectElement::DefaultToolTip() const {
  if (Form() && Form()->NoValidate())
    return String();
  return validationMessage();
}

void HTMLSelectElement::SelectMultipleOptionsByPopup(
    const Vector<int>& list_indices) {
  DCHECK(UsesMenuList());
  DCHECK(IsMultiple());

  HeapHashSet<Member<HTMLOptionElement>> old_selection;
  for (auto* option : GetOptionList()) {
    if (option->Selected()) {
      old_selection.insert(option);
      option->SetSelectedState(false);
    }
  }

  bool has_new_selection = false;
  for (int list_index : list_indices) {
    if (auto* option = OptionAtListIndex(list_index)) {
      option->SetSelectedState(true);
      option->SetDirty(true);
      auto iter = old_selection.find(option);
      if (iter != old_selection.end())
        old_selection.erase(iter);
      else
        has_new_selection = true;
    }
  }

  select_type_->UpdateTextStyleAndContent();
  SetNeedsValidityCheck();
  if (has_new_selection || !old_selection.empty()) {
    DispatchInputEvent();
    DispatchChangeEvent();
  }
}

unsigned HTMLSelectElement::ListBoxSize() const {
  DCHECK(!UsesMenuList());
  const unsigned specified_size = size();
  if (specified_size >= 1)
    return specified_size;
  return kDefaultListBoxSize;
}

void HTMLSelectElement::UpdateUsesMenuList() {
  if (LayoutTheme::GetTheme().DelegatesMenuListRendering())
    uses_menu_list_ = true;
  else
    uses_menu_list_ = !is_multiple_ && size_ <= 1;
}

int HTMLSelectElement::ActiveSelectionEndListIndex() const {
  HTMLOptionElement* option = ActiveSelectionEnd();
  return option ? option->ListIndex() : -1;
}

HTMLOptionElement* HTMLSelectElement::ActiveSelectionEnd() const {
  return select_type_->ActiveSelectionEnd();
}

void HTMLSelectElement::add(
    const V8UnionHTMLOptGroupElementOrHTMLOptionElement* element,
    const V8UnionHTMLElementOrLong* before,
    ExceptionState& exception_state) {
  DCHECK(element);

  HTMLElement* element_to_insert = nullptr;
  switch (element->GetContentType()) {
    case V8UnionHTMLOptGroupElementOrHTMLOptionElement::ContentType::
        kHTMLOptGroupElement:
      element_to_insert = element->GetAsHTMLOptGroupElement();
      break;
    case V8UnionHTMLOptGroupElementOrHTMLOptionElement::ContentType::
        kHTMLOptionElement:
      element_to_insert = element->GetAsHTMLOptionElement();
      break;
  }

  HTMLElement* before_element = nullptr;
  ContainerNode* target_container = this;
  if (before) {
    switch (before->GetContentType()) {
      case V8UnionHTMLElementOrLong::ContentType::kHTMLElement:
        before_element = before->GetAsHTMLElement();
        break;
      case V8UnionHTMLElementOrLong::ContentType::kLong:
        before_element = options()->item(before->GetAsLong());
        if (before_element && before_element->parentNode()) {
          target_container = before_element->parentNode();
        }
        break;
    }
  }

  target_container->InsertBefore(element_to_insert, before_element,
                                 exception_state);
  SetNeedsValidityCheck();
}

void HTMLSelectElement::remove(int option_index) {
  if (HTMLOptionElement* option = item(option_index))
    option->remove(IGNORE_EXCEPTION_FOR_TESTING);
}

String HTMLSelectElement::Value() const {
  if (HTMLOptionElement* option = SelectedOption())
    return option->value();
  return "";
}

void HTMLSelectElement::setValueForBinding(const String& value) {
  String old_value = this->Value();
  bool was_autofilled = IsAutofilled();
  bool value_changed = old_value != value;
  SetValue(value, false,
           was_autofilled && !value_changed ? WebAutofillState::kAutofilled
                                            : WebAutofillState::kNotFilled);
  if (Page* page = GetDocument().GetPage(); page && value_changed) {
    page->GetChromeClient().JavaScriptChangedValue(*this, old_value,
                                                   was_autofilled);
  }
}

void HTMLSelectElement::SetValue(const String& value,
                                 bool send_events,
                                 WebAutofillState autofill_state) {
  HTMLOptionElement* option = nullptr;
  // Find the option with value() matching the given parameter and make it the
  // current selection.
  for (auto* const item : GetOptionList()) {
    if (item->value() == value) {
      option = item;
      break;
    }
  }

  HTMLOptionElement* previous_selected_option = SelectedOption();
  SetSuggestedOption(nullptr);
  SelectOptionFlags flags = kDeselectOtherOptionsFlag | kMakeOptionDirtyFlag;
  if (send_events)
    flags |= kDispatchInputAndChangeEventFlag;
  SelectOption(option, flags, autofill_state);

  if (send_events && previous_selected_option != option)
    select_type_->ListBoxOnChange();
}

void HTMLSelectElement::SetAutofillValue(const String& value,
                                         WebAutofillState autofill_state) {
  auto interacted_state = interacted_state_;
  SetValue(value, true, autofill_state);
  interacted_state_ = interacted_state;
}

String HTMLSelectElement::SuggestedValue() const {
  return suggested_option_ ? suggested_option_->value() : "";
}

void HTMLSelectElement::SetSuggestedValue(const String& value) {
  if (value.IsNull()) {
    SetSuggestedOption(nullptr);
    return;
  }

  for (auto* const option : GetOptionList()) {
    if (option->value() == value) {
      SetSuggestedOption(option);
      return;
    }
  }

  SetSuggestedOption(nullptr);
}

bool HTMLSelectElement::IsPresentationAttribute(
    const QualifiedName& name) const {
  if (name == html_names::kAlignAttr) {
    // Don't map 'align' attribute. This matches what Firefox, Opera and IE do.
    // See http://bugs.webkit.org/show_bug.cgi?id=12072
    return false;
  }

  return HTMLFormControlElementWithState::IsPresentationAttribute(name);
}

void HTMLSelectElement::ParseAttribute(
    const AttributeModificationParams& params) {
  if (params.name == html_names::kSizeAttr) {
    unsigned old_size = size_;
    if (!ParseHTMLNonNegativeInteger(params.new_value, size_)) {
      size_ = 0;
    }
    SetNeedsValidityCheck();
    if (size_ != old_size) {
      ChangeRendering();
      UpdateUserAgentShadowTree(*UserAgentShadowRoot());
      UpdateMutationObserver();
      ResetToDefaultSelection();
      select_type_->UpdateTextStyleAndContent();
      select_type_->SaveListboxActiveSelection();
    }
  } else if (params.name == html_names::kMultipleAttr) {
    ParseMultipleAttribute(params.new_value);
  } else if (params.name == html_names::kAccesskeyAttr) {
    // FIXME: ignore for the moment.
    //
  } else if (params.name == html_names::kSelectedcontentelementAttr) {
    if (RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
      HTMLSelectedContentElement* old_selectedcontent =
          DynamicTo<HTMLSelectedContentElement>(
              getElementByIdIncludingDisconnected(*this, params.old_value));
      HTMLSelectedContentElement* new_selectedcontent =
          DynamicTo<HTMLSelectedContentElement>(
              getElementByIdIncludingDisconnected(*this, params.new_value));
      if (old_selectedcontent != new_selectedcontent) {
        if (old_selectedcontent) {
          // Clear out the contents of any <selectedcontent> which we are
          // removing the association from.
          old_selectedcontent->CloneContentsFromOptionElement(nullptr);
        }
        if (new_selectedcontent) {
          new_selectedcontent->CloneContentsFromOptionElement(SelectedOption());
        }
      }
    }
  } else {
    HTMLFormControlElementWithState::ParseAttribute(params);
  }
}

bool HTMLSelectElement::MayTriggerVirtualKeyboard() const {
  return true;
}

bool HTMLSelectElement::ShouldHaveFocusAppearance() const {
  // Don't draw focus ring for a select that has its popup open.
  if (PopupIsVisible())
    return false;

  return HTMLFormControlElementWithState::ShouldHaveFocusAppearance();
}

bool HTMLSelectElement::CanSelectAll() const {
  return !UsesMenuList();
}

LayoutObject* HTMLSelectElement::CreateLayoutObject(
    const ComputedStyle& style) {
  if (UsesMenuList()) {
    return MakeGarbageCollected<LayoutFlexibleBox>(this);
  }
  return MakeGarbageCollected<LayoutBlockFlow>(this);
}

HTMLCollection* HTMLSelectElement::selectedOptions() {
  return EnsureCachedCollection<HTMLCollection>(kSelectedOptions);
}

HTMLOptionsCollection* HTMLSelectElement::options() {
  return EnsureCachedCollection<HTMLOptionsCollection>(kSelectOptions);
}

void HTMLSelectElement::OptionElementChildrenChanged(
    const HTMLOptionElement& option) {
  SetNeedsValidityCheck();

  if (option.Selected())
    select_type_->UpdateTextStyleAndContent();
  if (GetLayoutObject()) {
    if (AXObjectCache* cache =
            GetLayoutObject()->GetDocument().ExistingAXObjectCache())
      cache->ChildrenChanged(this);
  }
}

void HTMLSelectElement::AccessKeyAction(
    SimulatedClickCreationScope creation_scope) {
  Focus(FocusParams(FocusTrigger::kUserGesture));
  DispatchSimulatedClick(nullptr, creation_scope);
}

HTMLOptionElement* HTMLSelectElement::namedItem(const AtomicString& name) {
  return To<HTMLOptionElement>(options()->namedItem(name));
}

HTMLOptionElement* HTMLSelectElement::item(unsigned index) {
  return options()->item(index);
}

void HTMLSelectElement::SetOption(unsigned index,
                                  HTMLOptionElement* option,
                                  ExceptionState& exception_state) {
  int diff = index - length();
  // If we are adding options, we should check |index > maxListItems| first to
  // avoid integer overflow.
  if (index > length() && (index >= kMaxListItems ||
                           GetListItems().size() + diff + 1 > kMaxListItems)) {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kWarning,
        String::Format(
            "Unable to expand the option list and set an option at index=%u. "
            "The maximum allowed list length is %u.",
            index, kMaxListItems)));
    return;
  }
  auto* element =
      MakeGarbageCollected<V8UnionHTMLOptGroupElementOrHTMLOptionElement>(
          option);
  V8UnionHTMLElementOrLong* before = nullptr;
  // Out of array bounds? First insert empty dummies.
  if (diff > 0) {
    setLength(index, exception_state);
    if (exception_state.HadException())
      return;
    // Replace an existing entry?
  } else if (diff < 0) {
    if (auto* before_element = options()->item(index + 1))
      before = MakeGarbageCollected<V8UnionHTMLElementOrLong>(before_element);
    remove(index);
  }
  // Finally add the new element.
  EventQueueScope scope;
  add(element, before, exception_state);
  if (exception_state.HadException())
    return;
  if (diff >= 0 && option->Selected())
    OptionSelectionStateChanged(option, true);
}

void HTMLSelectElement::setLength(unsigned new_len,
                                  ExceptionState& exception_state) {
  // If we are adding options, we should check |index > maxListItems| first to
  // avoid integer overflow.
  if (new_len > length() &&
      (new_len > kMaxListItems ||
       GetListItems().size() + new_len - length() > kMaxListItems)) {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kWarning,
        String::Format("Unable to expand the option list to length %u. "
                       "The maximum allowed list length is %u.",
                       new_len, kMaxListItems)));
    return;
  }
  int diff = length() - new_len;

  if (diff < 0) {  // Add dummy elements.
    do {
      AppendChild(MakeGarbageCollected<HTMLOptionElement>(GetDocument()),
                  exception_state);
      if (exception_state.HadException())
        break;
    } while (++diff);
  } else {
    // Removing children fires mutation events, which might mutate the DOM
    // further, so we first copy out a list of elements that we intend to
    // remove then attempt to remove them one at a time.
    HeapVector<Member<HTMLOptionElement>> items_to_remove;
    size_t option_index = 0;
    for (auto* const option : GetOptionList()) {
      if (option_index++ >= new_len) {
        DCHECK(option->parentNode());
        items_to_remove.push_back(option);
      }
    }

    for (auto& item : items_to_remove) {
      if (item->parentNode())
        item->parentNode()->RemoveChild(item.Get(), exception_state);
    }
  }
  SetNeedsValidityCheck();
}

bool HTMLSelectElement::IsRequiredFormControl() const {
  return IsRequired();
}

HTMLOptionElement* HTMLSelectElement::OptionAtListIndex(int list_index) const {
  if (list_index < 0)
    return nullptr;
  const ListItems& items = GetListItems();
  if (static_cast<wtf_size_t>(list_index) >= items.size())
    return nullptr;
  return DynamicTo<HTMLOptionElement>(items[list_index].Get());
}

void HTMLSelectElement::SelectAll() {
  select_type_->SelectAll();
}

const HTMLSelectElement::ListItems& HTMLSelectElement::GetListItems() const {
  if (should_recalc_list_items_) {
    RecalcListItems();
  } else {
#if DCHECK_IS_ON()
    HeapVector<Member<HTMLElement>> items = list_items_;
    RecalcListItems();
    DCHECK(items == list_items_);
#endif
  }

  return list_items_;
}

void HTMLSelectElement::InvalidateSelectedItems() {
  if (HTMLCollection* collection =
          CachedCollection<HTMLCollection>(kSelectedOptions))
    collection->InvalidateCache();
}

void HTMLSelectElement::SetRecalcListItems() {
  // FIXME: This function does a bunch of confusing things depending on if it
  // is in the document or not.

  should_recalc_list_items_ = true;

  select_type_->MaximumOptionWidthMightBeChanged();
  if (!isConnected()) {
    if (HTMLOptionsCollection* collection =
            CachedCollection<HTMLOptionsCollection>(kSelectOptions))
      collection->InvalidateCache();
    InvalidateSelectedItems();
  }

  if (GetLayoutObject()) {
    if (AXObjectCache* cache =
            GetLayoutObject()->GetDocument().ExistingAXObjectCache())
      cache->ChildrenChanged(this);
  }
}

void HTMLSelectElement::RecalcListItems() const {
  TRACE_EVENT0("blink", "HTMLSelectElement::recalcListItems");
  list_items_.resize(0);

  should_recalc_list_items_ = false;

  HTMLOptGroupElement* current_ancestor_optgroup = nullptr;

  for (Element* current_element = ElementTraversal::FirstWithin(*this);
       current_element && list_items_.size() < kMaxListItems;) {
    auto* current_html_element = DynamicTo<HTMLElement>(current_element);
    if (!current_html_element) {
      current_element =
          RuntimeEnabledFeatures::SelectParserRelaxationEnabled()
              ? ElementTraversal::Next(*current_element, this)
              : ElementTraversal::NextSkippingChildren(*current_element, this);
      continue;
    }

    // If there is a nested <select>, then its descendant <option>s belong to
    // it, not this.
    if (IsA<HTMLSelectElement>(current_html_element)) {
      current_element =
          ElementTraversal::NextSkippingChildren(*current_element, this);
      continue;
    }

    if (RuntimeEnabledFeatures::SelectParserRelaxationEnabled()) {
      bool skip_children = false;
      // If the parser is allowed to have more than just <option>s and
      // <optgroup>s, then we need to iterate over all descendants.
      if (auto* current_optgroup =
              DynamicTo<HTMLOptGroupElement>(*current_html_element)) {
        if (current_ancestor_optgroup) {
          // For compat, don't look at descendants of a nested <optgroup>.
          skip_children = true;
        } else {
          current_ancestor_optgroup = current_optgroup;
          list_items_.push_back(current_html_element);
        }
      } else if (IsA<HTMLOptionElement>(*current_html_element) ||
                 IsA<HTMLHRElement>(*current_html_element)) {
        list_items_.push_back(current_html_element);
      }

      Element* (*next_element_fn)(const Node&, const Node*) =
          &ElementTraversal::Next;
      if (skip_children) {
        next_element_fn = &ElementTraversal::NextSkippingChildren;
      }
      if (current_ancestor_optgroup) {
        // In order to keep current_ancestor_optgroup up to date, try traversing
        // to the next element within it. If we can't, then we have reached the
        // end of the optgroup and should set it to nullptr.
        auto* next_within_optgroup =
            next_element_fn(*current_element, current_ancestor_optgroup);
        if (!next_within_optgroup) {
          current_ancestor_optgroup = nullptr;
          current_element = next_element_fn(*current_element, this);
        } else {
          current_element = next_within_optgroup;
        }
      } else {
        current_element = next_element_fn(*current_element, this);
      }

      continue;
    }

    // We should ignore nested optgroup elements. The HTML parser flatten
    // them. However we need to ignore nested optgroups built by DOM APIs.
    // This behavior matches to IE and Firefox.
    if (IsA<HTMLOptGroupElement>(*current_html_element)) {
      if (current_html_element->parentNode() != this) {
        current_element =
            ElementTraversal::NextSkippingChildren(*current_html_element, this);
        continue;
      }
      list_items_.push_back(current_html_element);
      if (Element* next_element =
              ElementTraversal::FirstWithin(*current_html_element)) {
        current_element = next_element;
        continue;
      }
    }

    if (IsA<HTMLOptionElement>(*current_html_element))
      list_items_.push_back(current_html_element);

    if (IsA<HTMLHRElement>(*current_html_element))
      list_items_.push_back(current_html_element);

    // In conforming HTML code, only <optgroup> and <option> will be found
    // within a <select>. We call NodeTraversal::nextSkippingChildren so
    // that we only step into those tags that we choose to. For web-compat,
    // we should cope with the case where odd tags like a <div> have been
    // added but we handle this because such tags have already been removed
    // from the <select>'s subtree at this point.
    current_element =
        ElementTraversal::NextSkippingChildren(*current_element, this);
  }
}

void HTMLSelectElement::ResetToDefaultSelection(ResetReason reason) {
  // https://html.spec.whatwg.org/C/#ask-for-a-reset
  if (IsMultiple())
    return;
  HTMLOptionElement* first_enabled_option = nullptr;
  HTMLOptionElement* last_selected_option = nullptr;
  bool did_change = false;
  // We can't use HTMLSelectElement::options here because this function is
  // called in Node::insertedInto and Node::removedFrom before invalidating
  // node collections.
  for (auto* const option : GetOptionList()) {
    if (option->Selected()) {
      if (last_selected_option) {
        last_selected_option->SetSelectedState(false);
        did_change = true;
      }
      last_selected_option = option;
    }
    if (!first_enabled_option && !option->IsDisabledFormControl()) {
      first_enabled_option = option;
      if (reason == kResetReasonSelectedOptionRemoved) {
        // There must be no selected OPTIONs.
        break;
      }
    }
  }
  if (!last_selected_option && size_ <= 1 &&
      (!first_enabled_option ||
       (first_enabled_option && !first_enabled_option->Selected()))) {
    SelectOption(first_enabled_opti
```