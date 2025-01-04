Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. This code pertains to the `HTMLSelectElement` class, which represents the `<select>` HTML element.

Here's a breakdown of the code's functionality:

1. **Option Selection and Management:**
    - Selecting options (single or multiple).
    - Deselecting options.
    - Handling changes in selection.
    - Getting the currently selected option(s).
    - Setting the selected option programmatically.
    - Managing the `selected` attribute of `<option>` elements.
    - Handling the addition and removal of `<option>` and `<optgroup>` elements.
    - Resetting the selection to the default state.

2. **Event Handling:**
    - Handling focus and blur events.
    - Handling click and change events.
    - Handling keypress events for type-ahead find functionality.

3. **Form Interaction:**
    - Saving and restoring the form control state (selected options).
    - Appending selected values to form data on submission.
    - Resetting the element to its initial state.

4. **Accessibility:**
    -  Interacting with the Accessibility (AX) tree.

5. **Rendering and Layout:**
    - Managing the user-agent shadow DOM.
    - Updating the display of the selected option.
    - Handling changes to the `multiple` attribute.
    - Handling the `size` attribute (implicitly through `UsesMenuList`).
    - Implementing type-ahead find.
    - Supporting `appearance: none`.
    - Handling customizable select elements (`appearance: base-select`).

6. **Autofill:**
    - Setting and managing the autofill state of the element.
    - Handling suggested options.

7. **JavaScript API:**
    - Implementing JavaScript properties and methods like `selectedIndex`, `options`, `length`, `add()`, `remove()`.
    - Implementing the `showPicker()` method for programmatically opening the select dropdown.

8. **Internal Mechanisms:**
    - Managing a list of `ListItems` (options and optgroups).
    - Using a `SelectType` object to handle platform-specific rendering and behavior.
    - Using a `TypeAhead` object for type-ahead find functionality.

**Relationship to Web Technologies:**

- **JavaScript:** The code provides the underlying implementation for JavaScript APIs related to the `<select>` element, allowing scripts to interact with and manipulate the selection.
- **HTML:** The code directly implements the behavior defined for the `<select>` element and its child elements (`<option>`, `<optgroup>`).
- **CSS:** The code interacts with CSS through the `ComputedStyle` object to determine the element's rendering and behavior (e.g., `appearance: none`, visibility).

**Hypothetical Scenarios:**

- **Input:** User clicks on an option in a `<select>` element.
  - **Output:** The `SelectOption` method is called, the selected state of the clicked option is updated, other options might be deselected, and a `change` event is dispatched.
- **Input:** JavaScript calls `selectElement.selectedIndex = 2;`.
  - **Output:** The `setSelectedIndex` method is called, which in turn calls `SelectOption` to select the option at the specified index.

**Common User/Programming Errors:**

- **Incorrectly setting the `selected` attribute via JavaScript without triggering the appropriate events.** The code ensures that setting the selected state programmatically also updates the internal state and triggers events.
- **Adding or removing `<option>` elements without updating the internal data structures.** The `ChildrenChanged`, `ElementInserted`, and `OptionRemoved` methods handle these scenarios to keep the internal state consistent.

**User Interaction Flow:**

1. The user interacts with a webpage containing a `<select>` element.
2. The browser renders the `<select>` element based on its attributes and CSS styles.
3. The user might click on the `<select>` element to open the dropdown list (if it's a regular select).
4. The user might use the keyboard to navigate the list or type characters for type-ahead find.
5. When the user selects an option, the browser triggers events (like `click` or `change`) that are handled by the JavaScript on the page and also internally by the Blink engine code.
6. The Blink engine code in `html_select_element.cc` updates the internal state of the `<select>` element, manages the selection, and potentially updates the UI.
7. If the form containing the `<select>` element is submitted, the selected values are extracted by the `AppendToFormData` method.
这是 `blink/renderer/core/html/forms/html_select_element.cc` 文件功能的第二部分，主要涵盖了 `HTMLSelectElement` 类中关于选项选择、状态管理、事件处理以及与底层渲染和辅助功能交互的实现细节。

**核心功能归纳：**

* **选项的设置与取消：** 这部分代码负责实现 `HTMLSelectElement` 中选项的选中和取消选中逻辑。它考虑了单选和多选的情况，以及通过用户操作、脚本设置或内部逻辑触发的选择变化。
* **状态管理：**  维护了 `HTMLSelectElement` 的内部状态，包括当前选中的选项、最后触发 `onchange` 事件的选项、以及是否需要进行有效性检查。
* **事件处理：** 处理与选项选择相关的事件，例如 `option` 元素的选中状态变化。
* **子节点变化处理：** 监听并响应 `HTMLSelectElement` 子节点（`<option>` 和 `<optgroup>`）的插入和删除，并相应地更新内部状态和触发必要的重绘和有效性检查。

**更具体的细分功能：**

* **`ResetToDefaultSelection(ResetReason reason = kResetReasonNone)`:**  实现了将 `select` 元素的选择状态重置为其默认状态的逻辑。默认状态通常是第一个没有 `disabled` 属性的 `option` 元素，除非有 `selected` 属性显式指定了其他选项。
    * **与 HTML 的关系：**  直接对应了 HTML 规范中 `<select>` 元素的默认选择行为。
    * **假设输入与输出：**
        * **假设输入：** 一个 `<select>` 元素，没有任何 `option` 元素带有 `selected` 属性。
        * **输出：** 第一个非 `disabled` 的 `option` 元素被选中（如果存在）。
        * **假设输入：** 一个 `<select>` 元素，其中第二个 `option` 元素带有 `selected` 属性。
        * **输出：** 第二个 `option` 元素被选中。
        * **假设输入：** 一个 `<select multiple>` 元素，其中第一个和第三个 `option` 元素带有 `selected` 属性。
        * **输出：** 第一个和第三个 `option` 元素都被选中。
    * **用户/编程常见的使用错误：**  开发者可能期望在动态添加 `option` 后，`select` 元素会自动选择某些选项，但如果没有显式设置 `selected` 属性或调用相关方法，则不会发生。
* **`SelectedOption() const`:** 返回当前选中的单个 `HTMLOptionElement`。
    * **与 JavaScript 的关系：**  对应 JavaScript 中 `selectElement.selectedOptions[0]` 的行为（对于单选 `select`）。
* **`selectedIndex() const` 和 `setSelectedIndex(int index)`:**  获取和设置当前选中选项的索引。
    * **与 JavaScript 的关系：**  直接对应 JavaScript 中 `selectElement.selectedIndex` 属性。
    * **假设输入与输出：**
        * **假设输入：** `select` 元素有三个 `option`，第二个被选中。
        * **`selectedIndex()` 输出：** 1
        * **假设输入：** `select` 元素有三个 `option`，调用 `setSelectedIndex(2)`。
        * **输出：** 第三个 `option` 被选中。
    * **用户/编程常见的使用错误：**  传递超出 `option` 范围的索引会导致未定义行为或错误。
* **`SelectedListIndex() const`:** 返回当前选中选项在 `list_items_` 中的索引，该列表包含了 `option` 和 `optgroup` 元素。
* **`SetSuggestedOption(HTMLOptionElement* option)`:**  用于设置自动填充建议的选项。
    * **与自动填充功能相关。**
* **`OptionSelectionStateChanged(HTMLOptionElement* option, bool option_is_selected)`:**  当 `option` 元素的选中状态发生变化时被调用。
* **`ChildrenChanged(const ChildrenChange& change)`:**  当 `select` 元素的子节点发生变化时被调用，处理插入、删除等情况。
    * **与 HTML 的关系：**  响应 HTML DOM 树的变化。
    * **用户操作如何到达这里：** 用户通过 JavaScript 操作 DOM，例如 `selectElement.appendChild(newOption)` 或 `selectElement.removeChild(oldOption)`。
* **`ElementInserted(Node& node)` 和 `OptionInserted(HTMLOptionElement& option, bool option_is_selected)`:**  处理 `option` 元素插入时的逻辑，包括更新内部列表和根据 `selected` 属性设置选中状态。
* **`OptionRemoved(HTMLOptionElement& option)`:**  处理 `option` 元素移除时的逻辑，包括更新内部列表和重新计算默认选择。
* **`OptGroupInsertedOrRemoved(HTMLOptGroupElement& optgroup)` 和 `HrInsertedOrRemoved(HTMLHRElement& hr)`:**  处理 `optgroup` 和 `<hr>` 元素的插入和移除，更新内部列表。
* **`SelectOption(HTMLOptionElement* element, SelectOptionFlags flags, WebAutofillState autofill_state = WebAutofillState::kNotFilled)`:**  核心方法，用于设置或取消选中一个 `option` 元素。它负责更新内部状态、触发事件、并与自动填充机制交互。
    * **假设输入与输出：**
        * **假设输入：**  用户点击一个未选中的 `option` 元素（单选 `select`）。
        * **输出：** 该 `option` 被选中，之前选中的 `option` 被取消选中，触发 `change` 事件。
        * **假设输入：**  JavaScript 调用 `selectElement.options[1].selected = true;` （单选 `select`）。
        * **输出：**  索引为 1 的 `option` 被选中，之前选中的 `option` 被取消选中，触发 `change` 事件。
* **`DispatchFocusEvent(...)` 和 `DispatchBlurEvent(...)`:** 处理 `select` 元素获得和失去焦点时的事件。
* **`DeselectItemsWithoutValidation(HTMLOptionElement* exclude_element)`:**  取消选中所有 `option` 元素，但可以排除指定的元素。
* **`SaveFormControlState() const` 和 `RestoreFormControlState(const FormControlState& state)`:**  用于保存和恢复表单控件的状态，以便在页面导航或重新加载后恢复选中状态。
    * **与 HTML 的关系：**  与浏览器保存和恢复表单数据的机制相关。
* **`SearchOptionsForValue(...) const`:**  在 `option` 列表中根据 `value` 属性查找 `option` 元素的索引。
* **`ParseMultipleAttribute(const AtomicString& value)`:**  处理 `multiple` 属性的变化，并更新内部状态和触发必要的重置选择。
    * **与 HTML 的关系：**  直接对应 `<select>` 元素的 `multiple` 属性。
    * **用户操作如何到达这里：**  开发者通过 JavaScript 修改 `multiple` 属性，例如 `selectElement.multiple = true;`。
* **`UpdateMutationObserver()`:**  用于管理 MutationObserver，以便在自定义 `<select>` 元素（`appearance: base-select`）中监听子节点变化。
* **`AppendToFormData(FormData& form_data)`:**  在表单提交时，将选中的 `option` 的 `value` 添加到表单数据中。
    * **与 HTML 的关系：**  与 HTML 表单提交过程密切相关。
* **`ResetImpl()`:**  实现 `select` 元素的重置行为，将其恢复到初始状态（根据 `selected` 属性）。
    * **与 HTML 的关系：**  对应表单的 `reset` 事件。

**用户操作如何一步步的到达这里（举例说明 `SelectOption` 方法）：**

1. **用户在浏览器中加载一个包含 `<select>` 元素的网页。**
2. **浏览器渲染页面，`HTMLSelectElement` 对象被创建并与 DOM 树关联。**
3. **用户点击 `<select>` 元素打开下拉列表（如果不是 `multiple` 类型的 `select`）。**
4. **用户点击下拉列表中的一个 `<option>` 元素。**
5. **浏览器接收到点击事件，并将其传递给 `HTMLSelectElement` 对象。**
6. **`HTMLSelectElement` 对象内部的事件处理逻辑（例如，在 `DefaultEventHandler` 中）会调用 `SelectOption` 方法，并将被点击的 `HTMLOptionElement` 对象作为参数传递进去。**
7. **`SelectOption` 方法根据当前 `select` 元素的 `multiple` 属性和被点击 `option` 的状态，执行相应的选择或取消选择操作，并更新内部状态和触发相关事件。**

总而言之，这部分代码是 `HTMLSelectElement` 核心功能的实现，负责管理选项的选择状态、响应用户操作和 DOM 变化，并与浏览器的其他部分（例如表单处理、渲染引擎和辅助功能）进行交互。

Prompt: 
```
这是目录为blink/renderer/core/html/forms/html_select_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
这是第2部分，共3部分，请归纳一下它的功能

"""
on,
                 reason == kResetReasonSelectedOptionRemoved
                     ? 0
                     : kDeselectOtherOptionsFlag);
    last_selected_option = first_enabled_option;
    did_change = true;
  }
  if (did_change)
    SetNeedsValidityCheck();
  last_on_change_option_ = last_selected_option;
}

HTMLOptionElement* HTMLSelectElement::SelectedOption() const {
  for (auto* const option : GetOptionList()) {
    if (option->Selected())
      return option;
  }
  return nullptr;
}

int HTMLSelectElement::selectedIndex() const {
  unsigned index = 0;

  // Return the number of the first option selected.
  for (auto* const option : GetOptionList()) {
    if (option->Selected())
      return index;
    ++index;
  }

  return -1;
}

void HTMLSelectElement::setSelectedIndex(int index) {
  SelectOption(item(index), kDeselectOtherOptionsFlag | kMakeOptionDirtyFlag);
}

int HTMLSelectElement::SelectedListIndex() const {
  int index = 0;
  for (const auto& item : GetListItems()) {
    auto* option_element = DynamicTo<HTMLOptionElement>(item.Get());
    if (option_element && option_element->Selected())
      return index;
    ++index;
  }
  return -1;
}

void HTMLSelectElement::SetSuggestedOption(HTMLOptionElement* option) {
  if (suggested_option_ == option)
    return;
  SetAutofillState(option ? WebAutofillState::kPreviewed
                          : WebAutofillState::kNotFilled);
  suggested_option_ = option;

  select_type_->DidSetSuggestedOption(option);
}

void HTMLSelectElement::OptionSelectionStateChanged(HTMLOptionElement* option,
                                                    bool option_is_selected) {
  DCHECK_EQ(option->OwnerSelectElement(), this);
  if (option_is_selected)
    SelectOption(option, IsMultiple() ? 0 : kDeselectOtherOptionsFlag);
  else if (!UsesMenuList() || IsMultiple())
    SelectOption(nullptr, IsMultiple() ? 0 : kDeselectOtherOptionsFlag);
  else
    ResetToDefaultSelection();
}

void HTMLSelectElement::ChildrenChanged(const ChildrenChange& change) {
  HTMLFormControlElementWithState::ChildrenChanged(change);
  if (change.type ==
      ChildrenChangeType::kFinishedBuildingDocumentFragmentTree) {
    for (Node& node : NodeTraversal::ChildrenOf(*this)) {
      ElementInserted(node);
    }
  } else if (change.type == ChildrenChangeType::kElementInserted) {
    ElementInserted(*change.sibling_changed);
  } else if (change.type == ChildrenChangeType::kElementRemoved) {
    if (auto* option = DynamicTo<HTMLOptionElement>(change.sibling_changed)) {
      OptionRemoved(*option);
    } else if (auto* optgroup =
                   DynamicTo<HTMLOptGroupElement>(change.sibling_changed)) {
      for (auto& child_option :
           Traversal<HTMLOptionElement>::ChildrenOf(*optgroup))
        OptionRemoved(child_option);
    }
  } else if (change.type == ChildrenChangeType::kAllChildrenRemoved) {
    for (Node* node : change.removed_nodes) {
      if (auto* option = DynamicTo<HTMLOptionElement>(node)) {
        OptionRemoved(*option);
      } else if (auto* optgroup = DynamicTo<HTMLOptGroupElement>(node)) {
        for (auto& child_option :
             Traversal<HTMLOptionElement>::ChildrenOf(*optgroup))
          OptionRemoved(child_option);
      }
    }
  }
}

bool HTMLSelectElement::ChildrenChangedAllChildrenRemovedNeedsList() const {
  return true;
}

void HTMLSelectElement::ElementInserted(Node& node) {
  if (auto* option = DynamicTo<HTMLOptionElement>(&node)) {
    OptionInserted(*option, option->Selected());
  } else if (auto* optgroup = DynamicTo<HTMLOptGroupElement>(&node)) {
    for (auto& child_option :
         Traversal<HTMLOptionElement>::ChildrenOf(*optgroup)) {
      OptionInserted(child_option, child_option.Selected());
    }
  }
}

void HTMLSelectElement::OptionInserted(HTMLOptionElement& option,
                                       bool option_is_selected) {
  DCHECK_EQ(option.OwnerSelectElement(), this);
  option.SetWasOptionInsertedCalled(true);
  SetRecalcListItems();
  if (option_is_selected) {
    SelectOption(&option, IsMultiple() ? 0 : kDeselectOtherOptionsFlag);
  } else if (!last_on_change_option_) {
    // The newly added option is not selected and we do not already have a
    // selected option. We should re-run the selection algorithm if there is a
    // chance that the newly added option can become the selected option.
    // However, we should not re-run the algorithm if either of these is true:
    //
    // 1. The new option is disabled because disabled options can never be
    // selected.
    // 2. The size attribute is greater than 1 because the HTML spec does not
    // mention a default value for that case.
    //
    // https://html.spec.whatwg.org/multipage/form-elements.html#selectedness-setting-algorithm
    if (size_ <= 1 && !option.IsDisabledFormControl()) {
      ResetToDefaultSelection();
    }
  }
  SetNeedsValidityCheck();
  select_type_->ClearLastOnChangeSelection();

  if (!GetDocument().IsActive())
    return;

  GetDocument()
      .GetFrame()
      ->GetPage()
      ->GetChromeClient()
      .SelectFieldOptionsChanged(*this);
}

void HTMLSelectElement::OptionRemoved(HTMLOptionElement& option) {
  option.SetWasOptionInsertedCalled(false);
  SetRecalcListItems();
  if (option.Selected())
    ResetToDefaultSelection(kResetReasonSelectedOptionRemoved);
  else if (!last_on_change_option_)
    ResetToDefaultSelection();
  if (last_on_change_option_ == &option)
    last_on_change_option_.Clear();
  select_type_->OptionRemoved(option);
  if (suggested_option_ == &option)
    SetSuggestedOption(nullptr);
  if (option.Selected())
    SetAutofillState(WebAutofillState::kNotFilled);
  SetNeedsValidityCheck();
  select_type_->ClearLastOnChangeSelection();

  if (!GetDocument().IsActive())
    return;

  GetDocument()
      .GetFrame()
      ->GetPage()
      ->GetChromeClient()
      .SelectFieldOptionsChanged(*this);
}

void HTMLSelectElement::OptGroupInsertedOrRemoved(
    HTMLOptGroupElement& optgroup) {
  SetRecalcListItems();
  SetNeedsValidityCheck();
  select_type_->ClearLastOnChangeSelection();
}

void HTMLSelectElement::HrInsertedOrRemoved(HTMLHRElement& hr) {
  SetRecalcListItems();
  select_type_->ClearLastOnChangeSelection();
}

// TODO(tkent): This function is not efficient.  It contains multiple O(N)
// operations. crbug.com/577989.
void HTMLSelectElement::SelectOption(HTMLOptionElement* element,
                                     SelectOptionFlags flags,
                                     WebAutofillState autofill_state) {
  TRACE_EVENT0("blink", "HTMLSelectElement::selectOption");

  bool should_update_popup = false;

  SetAutofillState(element ? autofill_state : WebAutofillState::kNotFilled);

  if (element) {
    if (!element->Selected())
      should_update_popup = true;
    element->SetSelectedState(true);
    if (flags & kMakeOptionDirtyFlag)
      element->SetDirty(true);
  }

  // DeselectItemsWithoutValidation() is O(N).
  if (flags & kDeselectOtherOptionsFlag)
    should_update_popup |= DeselectItemsWithoutValidation(element);

  select_type_->DidSelectOption(element, flags, should_update_popup);
  NotifyFormStateChanged();
  if (GetDocument().IsActive()) {
    GetDocument()
        .GetPage()
        ->GetChromeClient()
        .DidChangeSelectionInSelectControl(*this);
  }

  if (!RuntimeEnabledFeatures::AllowJavaScriptToResetAutofillStateEnabled()) {
    // We set the Autofilled state again because setting the autofill value
    // triggers JavaScript events and the site may override the autofilled
    // value, which resets the autofill state. Even if the website modifies the
    // from control element's content during the autofill operation, we want the
    // state to show as as autofilled.
    SetAutofillState(element ? autofill_state : WebAutofillState::kNotFilled);
  }

  UpdateAllSelectedcontents();
}

bool HTMLSelectElement::DispatchFocusEvent(
    Element* old_focused_element,
    mojom::blink::FocusType type,
    InputDeviceCapabilities* source_capabilities) {
  // Save the selection so it can be compared to the new selection when
  // dispatching change events during blur event dispatch.
  if (UsesMenuList())
    select_type_->SaveLastSelection();
  return HTMLFormControlElementWithState::DispatchFocusEvent(
      old_focused_element, type, source_capabilities);
}

void HTMLSelectElement::DispatchBlurEvent(
    Element* new_focused_element,
    mojom::blink::FocusType type,
    InputDeviceCapabilities* source_capabilities) {
  type_ahead_.ResetSession();
  select_type_->DidBlur();
  HTMLFormControlElementWithState::DispatchBlurEvent(new_focused_element, type,
                                                     source_capabilities);
}

// Returns true if selection state of any OPTIONs is changed.
bool HTMLSelectElement::DeselectItemsWithoutValidation(
    HTMLOptionElement* exclude_element) {
  if (!IsMultiple() && UsesMenuList() && last_on_change_option_ &&
      last_on_change_option_ != exclude_element) {
    last_on_change_option_->SetSelectedState(false);
    return true;
  }
  bool did_update_selection = false;
  for (auto* const option : GetOptionList()) {
    if (option == exclude_element)
      continue;
    if (!option->WasOptionInsertedCalled())
      continue;
    if (option->Selected())
      did_update_selection = true;
    option->SetSelectedState(false);
  }
  return did_update_selection;
}

FormControlState HTMLSelectElement::SaveFormControlState() const {
  const ListItems& items = GetListItems();
  wtf_size_t length = items.size();
  FormControlState state;
  for (wtf_size_t i = 0; i < length; ++i) {
    auto* option = DynamicTo<HTMLOptionElement>(items[i].Get());
    if (!option || !option->Selected())
      continue;
    state.Append(option->value());
    state.Append(String::Number(i));
    if (!IsMultiple())
      break;
  }
  return state;
}

wtf_size_t HTMLSelectElement::SearchOptionsForValue(
    const String& value,
    wtf_size_t list_index_start,
    wtf_size_t list_index_end) const {
  const ListItems& items = GetListItems();
  wtf_size_t loop_end_index = std::min(items.size(), list_index_end);
  for (wtf_size_t i = list_index_start; i < loop_end_index; ++i) {
    auto* option_element = DynamicTo<HTMLOptionElement>(items[i].Get());
    if (!option_element)
      continue;
    if (option_element->value() == value)
      return i;
  }
  return kNotFound;
}

void HTMLSelectElement::RestoreFormControlState(const FormControlState& state) {
  RecalcListItems();

  const ListItems& items = GetListItems();
  wtf_size_t items_size = items.size();
  if (items_size == 0)
    return;

  SelectOption(nullptr, kDeselectOtherOptionsFlag);

  // The saved state should have at least one value and an index.
  DCHECK_GE(state.ValueSize(), 2u);
  if (!IsMultiple()) {
    unsigned index = state[1].ToUInt();
    auto* option_element =
        index < items_size ? DynamicTo<HTMLOptionElement>(items[index].Get())
                           : nullptr;
    if (option_element && option_element->value() == state[0]) {
      option_element->SetSelectedState(true);
      option_element->SetDirty(true);
      last_on_change_option_ = option_element;
    } else {
      wtf_size_t found_index = SearchOptionsForValue(state[0], 0, items_size);
      if (found_index != kNotFound) {
        auto* found_option_element =
            To<HTMLOptionElement>(items[found_index].Get());
        found_option_element->SetSelectedState(true);
        found_option_element->SetDirty(true);
        last_on_change_option_ = found_option_element;
      }
    }
  } else {
    wtf_size_t start_index = 0;
    for (wtf_size_t i = 0; i < state.ValueSize(); i += 2) {
      const String& value = state[i];
      const unsigned index = state[i + 1].ToUInt();
      auto* option_element =
          index < items_size ? DynamicTo<HTMLOptionElement>(items[index].Get())
                             : nullptr;
      if (option_element && option_element->value() == value) {
        option_element->SetSelectedState(true);
        option_element->SetDirty(true);
        start_index = index + 1;
      } else {
        wtf_size_t found_index =
            SearchOptionsForValue(value, start_index, items_size);
        if (found_index == kNotFound)
          found_index = SearchOptionsForValue(value, 0, start_index);
        if (found_index == kNotFound)
          continue;
        auto* found_option_element =
            To<HTMLOptionElement>(items[found_index].Get());
        found_option_element->SetSelectedState(true);
        found_option_element->SetDirty(true);
        start_index = found_index + 1;
      }
    }
  }

  UpdateAllSelectedcontents();
  SetNeedsValidityCheck();
  select_type_->UpdateTextStyleAndContent();
}

void HTMLSelectElement::ParseMultipleAttribute(const AtomicString& value) {
  bool old_multiple = is_multiple_;
  HTMLOptionElement* old_selected_option = SelectedOption();
  is_multiple_ = !value.IsNull();
  SetNeedsValidityCheck();
  ChangeRendering();
  UpdateUserAgentShadowTree(*UserAgentShadowRoot());
  UpdateMutationObserver();
  // Restore selectedIndex after changing the multiple flag to preserve
  // selection as single-line and multi-line has different defaults.
  if (old_multiple != is_multiple_) {
    // Preserving the first selection is compatible with Firefox and
    // WebKit. However Edge seems to "ask for a reset" simply.  As of 2016
    // March, the HTML specification says nothing about this.
    if (old_selected_option) {
      // Clear last_on_change_option_ in order to disable an optimization in
      // DeselectItemsWithoutValidation().
      last_on_change_option_ = nullptr;
      SelectOption(old_selected_option, kDeselectOtherOptionsFlag);
    } else {
      ResetToDefaultSelection();
    }
  }
  select_type_->UpdateTextStyleAndContent();
}

void HTMLSelectElement::UpdateMutationObserver() {
  if (!RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
    return;
  }
  if (UsesMenuList() && isConnected() && IsAppearanceBasePicker()) {
    if (!descendants_observer_) {
      descendants_observer_ =
          MakeGarbageCollected<SelectDescendantsObserver>(*this);
    }
  } else if (descendants_observer_) {
    descendants_observer_->Disconnect();
    descendants_observer_ = nullptr;
  }
}

void HTMLSelectElement::AppendToFormData(FormData& form_data) {
  const AtomicString& name = GetName();
  if (name.empty())
    return;

  for (auto* const option : GetOptionList()) {
    if (option->Selected() && !option->IsDisabledFormControl())
      form_data.AppendFromElement(name, option->value());
  }
}

void HTMLSelectElement::ResetImpl() {
  for (auto* const option : GetOptionList()) {
    option->SetSelectedState(
        option->FastHasAttribute(html_names::kSelectedAttr));
    option->SetDirty(false);
  }
  ResetToDefaultSelection();
  select_type_->UpdateTextStyleAndContent();
  SetNeedsValidityCheck();
  HTMLFormControlElementWithState::ResetImpl();
}

bool HTMLSelectElement::PopupIsVisible() const {
  return select_type_->PopupIsVisible();
}

int HTMLSelectElement::ListIndexForOption(const HTMLOptionElement& option) {
  const ListItems& items = GetListItems();
  wtf_size_t length = items.size();
  for (wtf_size_t i = 0; i < length; ++i) {
    if (items[i].Get() == &option)
      return i;
  }
  return -1;
}

AutoscrollController* HTMLSelectElement::GetAutoscrollController() const {
  if (Page* page = GetDocument().GetPage())
    return &page->GetAutoscrollController();
  return nullptr;
}

LayoutBox* HTMLSelectElement::AutoscrollBox() {
  return !UsesMenuList() ? GetLayoutBox() : nullptr;
}

void HTMLSelectElement::StopAutoscroll() {
  if (!IsDisabledFormControl())
    select_type_->HandleMouseRelease();
}

void HTMLSelectElement::DefaultEventHandler(Event& event) {
  if (!GetLayoutObject())
    return;

  if (event.type() == event_type_names::kClick ||
      event.type() == event_type_names::kChange ||
      event.type() == event_type_names::kKeydown) {
    SetUserHasEditedTheField();
  }

  if (IsDisabledFormControl()) {
    HTMLFormControlElementWithState::DefaultEventHandler(event);
    return;
  }

  if (select_type_->DefaultEventHandler(event)) {
    event.SetDefaultHandled();
    return;
  }

  auto* keyboard_event = DynamicTo<KeyboardEvent>(event);
  if (event.type() == event_type_names::kKeypress && keyboard_event) {
    if (!keyboard_event->ctrlKey() && !keyboard_event->altKey() &&
        !keyboard_event->metaKey() &&
        WTF::unicode::IsPrintableChar(keyboard_event->charCode())) {
      TypeAheadFind(*keyboard_event);
      event.SetDefaultHandled();
      return;
    }
  }
  HTMLFormControlElementWithState::DefaultEventHandler(event);
}

HTMLOptionElement* HTMLSelectElement::LastSelectedOption() const {
  const ListItems& items = GetListItems();
  for (wtf_size_t i = items.size(); i;) {
    if (HTMLOptionElement* option = OptionAtListIndex(--i)) {
      if (option->Selected())
        return option;
    }
  }
  return nullptr;
}

int HTMLSelectElement::IndexOfSelectedOption() const {
  return SelectedListIndex();
}

int HTMLSelectElement::OptionCount() const {
  return GetListItems().size();
}

String HTMLSelectElement::OptionAtIndex(int index) const {
  if (HTMLOptionElement* option = OptionAtListIndex(index)) {
    if (!option->IsDisabledFormControl())
      return option->DisplayLabel();
  }
  return String();
}

void HTMLSelectElement::TypeAheadFind(const KeyboardEvent& event) {
  int index = type_ahead_.HandleEvent(
      event, event.charCode(),
      TypeAhead::kMatchPrefix | TypeAhead::kCycleFirstChar);
  if (index < 0) {
    return;
  }

  HTMLOptionElement* option_at_index = OptionAtListIndex(index);

  if (RuntimeEnabledFeatures::CustomizableSelectEnabled() &&
      select_type_->IsAppearanceBasePicker() &&
      select_type_->PopupIsVisible()) {
    option_at_index->Focus(FocusParams(FocusTrigger::kScript));
    return;
  }

  SelectOption(option_at_index, kDeselectOtherOptionsFlag |
                                    kMakeOptionDirtyFlag |
                                    kDispatchInputAndChangeEventFlag);

  select_type_->ListBoxOnChange();
}

void HTMLSelectElement::SelectOptionByAccessKey(HTMLOptionElement* option) {
  // First bring into focus the list box.
  if (!IsFocused())
    AccessKeyAction(SimulatedClickCreationScope::kFromUserAgent);

  if (!option || option->OwnerSelectElement() != this)
    return;
  EventQueueScope scope;
  // If this index is already selected, unselect. otherwise update the
  // selected index.
  SelectOptionFlags flags = kDispatchInputAndChangeEventFlag |
                            (IsMultiple() ? 0 : kDeselectOtherOptionsFlag);
  if (option->Selected()) {
    if (UsesMenuList())
      SelectOption(nullptr, flags);
    else
      option->SetSelectedState(false);
  } else {
    SelectOption(option, flags);
  }
  option->SetDirty(true);
  select_type_->ListBoxOnChange();
  select_type_->ScrollToSelection();
}

unsigned HTMLSelectElement::length() const {
  unsigned options = 0;
  for ([[maybe_unused]] auto* const option : GetOptionList()) {
    ++options;
  }
  return options;
}

void HTMLSelectElement::FinishParsingChildren() {
  HTMLFormControlElementWithState::FinishParsingChildren();
  if (UsesMenuList())
    return;
  select_type_->ScrollToOption(SelectedOption());
  if (AXObjectCache* cache = GetDocument().ExistingAXObjectCache())
    cache->ListboxActiveIndexChanged(this);
}

IndexedPropertySetterResult HTMLSelectElement::AnonymousIndexedSetter(
    unsigned index,
    HTMLOptionElement* value,
    ExceptionState& exception_state) {
  if (!value) {  // undefined or null
    remove(index);
    return IndexedPropertySetterResult::kIntercepted;
  }
  SetOption(index, value, exception_state);
  return IndexedPropertySetterResult::kIntercepted;
}

bool HTMLSelectElement::IsInteractiveContent() const {
  return true;
}

void HTMLSelectElement::Trace(Visitor* visitor) const {
  visitor->Trace(list_items_);
  visitor->Trace(option_slot_);
  visitor->Trace(last_on_change_option_);
  visitor->Trace(suggested_option_);
  visitor->Trace(descendant_selectedcontents_);
  visitor->Trace(select_type_);
  visitor->Trace(descendants_observer_);
  HTMLFormControlElementWithState::Trace(visitor);
}

void HTMLSelectElement::DidAddUserAgentShadowRoot(ShadowRoot& root) {
  UpdateUserAgentShadowTree(root);
  select_type_->UpdateTextStyleAndContent();
}

void HTMLSelectElement::ManuallyAssignSlots() {
  select_type_->ManuallyAssignSlots();
}

void HTMLSelectElement::UpdateUserAgentShadowTree(ShadowRoot& root) {
  // Remove all children of the ShadowRoot so that select_type_ can set it up
  // however it wants.
  Node* node = root.firstChild();
  while (node) {
    auto* will_be_removed = node;
    node = node->nextSibling();
    will_be_removed->remove();
  }
  select_type_->CreateShadowSubtree(root);
}

Element& HTMLSelectElement::InnerElement() const {
  return select_type_->InnerElement();
}

AXObject* HTMLSelectElement::PopupRootAXObject() const {
  return select_type_->PopupRootAXObject();
}

HTMLOptionElement* HTMLSelectElement::SpatialNavigationFocusedOption() {
  return select_type_->SpatialNavigationFocusedOption();
}

String HTMLSelectElement::ItemText(const Element& element) const {
  String item_string;
  if (auto* optgroup = DynamicTo<HTMLOptGroupElement>(element))
    item_string = optgroup->GroupLabelText();
  else if (auto* option = DynamicTo<HTMLOptionElement>(element))
    item_string = option->TextIndentedToRespectGroupLabel();

  if (GetLayoutObject() && GetLayoutObject()->Style()) {
    return GetLayoutObject()->Style()->ApplyTextTransform(item_string);
  }
  return item_string;
}

bool HTMLSelectElement::ItemIsDisplayNone(Element& element) const {
  if (auto* option = DynamicTo<HTMLOptionElement>(element))
    return option->IsDisplayNone();
  const ComputedStyle* style = ItemComputedStyle(element);
  return !style || style->Display() == EDisplay::kNone;
}

const ComputedStyle* HTMLSelectElement::ItemComputedStyle(
    Element& element) const {
  return element.GetComputedStyle() ? element.GetComputedStyle()
                                    : element.EnsureComputedStyle();
}

LayoutUnit HTMLSelectElement::ClientPaddingLeft() const {
  DCHECK(UsesMenuList());
  auto* this_box = GetLayoutBox();
  if (!this_box || !InnerElement().GetLayoutBox()) {
    return LayoutUnit();
  }
  LayoutTheme& theme = LayoutTheme::GetTheme();
  const ComputedStyle& style = this_box->StyleRef();
  int inner_padding =
      style.IsLeftToRightDirection()
          ? theme.PopupInternalPaddingStart(style)
          : theme.PopupInternalPaddingEnd(GetDocument().GetFrame(), style);
  return this_box->PaddingLeft() + inner_padding;
}

LayoutUnit HTMLSelectElement::ClientPaddingRight() const {
  DCHECK(UsesMenuList());
  auto* this_box = GetLayoutBox();
  if (!this_box || !InnerElement().GetLayoutBox()) {
    return LayoutUnit();
  }
  LayoutTheme& theme = LayoutTheme::GetTheme();
  const ComputedStyle& style = this_box->StyleRef();
  int inner_padding =
      style.IsLeftToRightDirection()
          ? theme.PopupInternalPaddingEnd(GetDocument().GetFrame(), style)
          : theme.PopupInternalPaddingStart(style);
  return this_box->PaddingRight() + inner_padding;
}

void HTMLSelectElement::PopupDidHide() {
  select_type_->PopupDidHide();
}

void HTMLSelectElement::SetIndexToSelectOnCancel(int list_index) {
  index_to_select_on_cancel_ = list_index;
  select_type_->UpdateTextStyleAndContent();
}

HTMLOptionElement* HTMLSelectElement::OptionToBeShown() const {
  DCHECK(!IsMultiple());
  return select_type_->OptionToBeShown();
}

void HTMLSelectElement::SelectOptionByPopup(int list_index) {
  SelectOptionByPopup(OptionAtListIndex(list_index));
}

void HTMLSelectElement::SelectOptionByPopup(HTMLOptionElement* option) {
  DCHECK(UsesMenuList());
  // Check to ensure a page navigation has not occurred while the popup was
  // up.
  Document& doc = GetDocument();
  if (&doc != doc.GetFrame()->GetDocument())
    return;

  SetIndexToSelectOnCancel(-1);

  // Bail out if this index is already the selected one, to avoid running
  // unnecessary JavaScript that can mess up autofill when there is no actual
  // change (see https://bugs.webkit.org/show_bug.cgi?id=35256 and
  // <rdar://7467917>).  The selectOption function does not behave this way,
  // possibly because other callers need a change event even in cases where
  // the selected option is not change.
  if (option == SelectedOption())
    return;
  SelectOption(option, kDeselectOtherOptionsFlag | kMakeOptionDirtyFlag |
                           kDispatchInputAndChangeEventFlag);
}

void HTMLSelectElement::PopupDidCancel() {
  if (index_to_select_on_cancel_ >= 0)
    SelectOptionByPopup(index_to_select_on_cancel_);
}

void HTMLSelectElement::ProvisionalSelectionChanged(unsigned list_index) {
  SetIndexToSelectOnCancel(list_index);
}

void HTMLSelectElement::ShowPopup() {
  select_type_->ShowPopup(PopupMenu::kOther);
}

void HTMLSelectElement::HidePopup() {
  select_type_->HidePopup();
}

PopupMenu* HTMLSelectElement::PopupForTesting() const {
  return select_type_->PopupForTesting();
}

void HTMLSelectElement::DidRecalcStyle(const StyleRecalcChange change) {
  HTMLFormControlElementWithState::DidRecalcStyle(change);
  if (auto* style = GetComputedStyle()) {
    if (style->EffectiveAppearance() == ControlPart::kNoControlPart) {
      UseCounter::Count(GetDocument(),
                        WebFeature::kSelectElementAppearanceNone);
    }
  }
  select_type_->DidRecalcStyle(change);
  UpdateMutationObserver();
}

void HTMLSelectElement::AttachLayoutTree(AttachContext& context) {
  HTMLFormControlElementWithState::AttachLayoutTree(context);
  // The call to UpdateTextStyle() needs to go after the call through
  // to the base class's AttachLayoutTree() because that can sometimes do a
  // close on the LayoutObject.
  select_type_->UpdateTextStyle();

  if (const ComputedStyle* style = GetComputedStyle()) {
    if (style->Visibility() != EVisibility::kHidden) {
      if (IsMultiple())
        UseCounter::Count(GetDocument(), WebFeature::kSelectElementMultiple);
      else
        UseCounter::Count(GetDocument(), WebFeature::kSelectElementSingle);
    }
  }
}

void HTMLSelectElement::DetachLayoutTree(bool performing_reattach) {
  HTMLFormControlElementWithState::DetachLayoutTree(performing_reattach);
  select_type_->DidDetachLayoutTree();
}

void HTMLSelectElement::ResetTypeAheadSessionForTesting() {
  type_ahead_.ResetSession();
}

void HTMLSelectElement::CloneNonAttributePropertiesFrom(const Element& source,
                                                        NodeCloningData& data) {
  const auto& source_element = static_cast<const HTMLSelectElement&>(source);
  interacted_state_ = source_element.interacted_state_;
  HTMLFormControlElement::CloneNonAttributePropertiesFrom(source, data);
}

void HTMLSelectElement::ChangeRendering() {
  select_type_->DidDetachLayoutTree();
  bool old_uses_menu_list = UsesMenuList();
  UpdateUsesMenuList();
  if (UsesMenuList() != old_uses_menu_list) {
    select_type_->WillBeDestroyed();
    select_type_ = SelectType::Create(*this);

    if (RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
      // Make <option>s render all child content when in MenuList mode in order
      // to support appearance:base-select.
      for (HTMLOptionElement* option : GetOptionList()) {
        option->SetTextOnlyRendering(!UsesMenuList());
      }
    }
  }
  if (!InActiveDocument())
    return;
  SetForceReattachLayoutTree();
  SetNeedsStyleRecalc(kLocalStyleChange, StyleChangeReasonForTracing::Create(
                                             style_change_reason::kControl));
}

const ComputedStyle* HTMLSelectElement::OptionStyle() const {
  return select_type_->OptionStyle();
}

// Show the option list for this select element.
// https://html.spec.whatwg.org/multipage/input.html#dom-select-showpicker
void HTMLSelectElement::showPicker(ExceptionState& exception_state) {
  Document& document = GetDocument();
  LocalFrame* frame = document.GetFrame();
  // In cross-origin iframes it should throw a "SecurityError" DOMException
  if (frame) {
    if (!frame->IsSameOrigin()) {
      exception_state.ThrowSecurityError(
          "showPicker() called from cross-origin iframe.");
      return;
    }
  }

  if (IsDisabledFormControl()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "showPicker() cannot "
                                      "be used on immutable controls.");
    return;
  }

  if (!LocalFrame::HasTransientUserActivation(frame)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotAllowedError,
                                      "showPicker() requires a user gesture.");
    return;
  }

  document.UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);
  if (DisplayLockUtilities::LockedAncestorPreventingPaint(*this) ||
      !GetLayoutBox()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "showPicker() requires the select is rendered.");
    return;
  }

  LocalFrame::ConsumeTransientUserActivation(frame);

  select_type_->ShowPicker();
}

bool HTMLSelectElement::IsValidBuiltinCommand(HTMLElement& invoker,
                                              CommandEventType command) {
  bool parent_is_valid = HTMLElement::IsValidBuiltinCommand(invoker, command);
  if (!RuntimeEnabledFeatures::HTMLInvokeActionsV2Enabled()) {
    return parent_is_valid;
  }
  return parent_is_valid || command == CommandEventType::kShowPicker;
}

bool HTMLSelectElement::HandleCommandInternal(HTMLElement& invoker,
                                              CommandEventType command) {
  CHECK(IsValidBuiltinCommand(invoker, command));

  if (HTMLElement::HandleCommandInternal(invoker, command)) {
    return true;
  }

  if (command != CommandEventType::kShowPicker) {
    return false;
  }

  // Step 1. If this is not mutable, then return.
  if (IsDisabledFormControl()) {
    return false;
  }

  // Step 2. If this's relevant settings object's origin is not same origin with
  // this's relevant settings object's top-level origin, [...], then return.
  Document& document = GetDocument();
  LocalFrame* frame = document.GetFrame();
  if (frame && !frame->IsSameOrigin()) {
    String message = "Select cannot be invoked from cross-origin iframe.";
    document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kWarning, message));
    return false;
  }

  // If this's relevant global object does not have transient
  // activation, then return.
  if (!LocalFrame::HasTransientUserActivation(frame)) {
    String message = "Select cannot be invoked without a user gesture.";
    document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kWarning, message));
    return false;
  }

  document.UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);
  if (DisplayLockUtilities::LockedAncestorPreventingPaint(*this) ||
      !GetLayoutBox()) {
    String message = "Select cannot be invoked when not being rendered.";
    document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kWarning, message));
    return false;
  }

  // Step 3. ... show the picker, if applicable, for this.
  select_type_->ShowPicker();

  return true;
}

HTMLButtonElement* HTMLSelectElement::SlottedButton() const {
  return select_type_->SlottedButton();
}

HTMLElement* HTMLSelectElement::PopoverForAppearanceBase() const {
  return select_type_->PopoverForAppearanceBase();
}

// static
bool HTMLSelectElement::IsPopoverForAppearanceBase(const Element* element) {
  if (auto* root = DynamicTo<ShadowRoot>(element->parentNode())) {
    return IsA<HTMLSelectElement>(root->host()) &&
           element->FastHasAttribute(html_names::kPopoverAttr);
  }
  return false;
}

bool HTMLSelectElement::IsAppearanceBaseButton() const {
  return select_type_->IsAppearanceBaseButton();
}

bool HTMLSelectElement::IsAppearanceBasePicker() const {
  return select_type_->IsAppearanceBasePicker();
}

void HTMLSelectElement::SelectedContentElementInserted(
    HTMLSelectedContentElement* selectedcontent) {
  descendant_selectedcontents_.insert(selectedcontent);
  selectedcontent->CloneContentsFromOptionElement(SelectedOption());
}

void HTMLSelectElement::SelectedContentElementRemoved(
    HTMLSelectedContentElement* selectedcontent) {
  descendant_selectedcontents_.erase(selectedc
"""


```