Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/html/forms/select_type.cc`. This is part 2 of a 3-part file. The code focuses on the behavior of `<select>` elements in HTML, specifically the `MenuListSelectType` and `ListBoxSelectType` classes, which handle different visual representations of the select dropdown.

To provide a good summary, I need to identify the key responsibilities of each class and how they interact with HTML, CSS, and JavaScript. I also need to consider common user or programming errors.

**Plan:**

1. **Identify the classes:** The code snippet primarily concerns `MenuListSelectType` and `ListBoxSelectType`.
2. **Summarize `MenuListSelectType` functionality:** Focus on how it handles the menu-style dropdown, including:
    *   Showing/hiding the popup.
    *   Updating the displayed text.
    *   Handling option selection (via mouse or keyboard).
    *   Dispatching `input` and `change` events.
    *   Accessibility considerations.
    *   Handling style updates and how they affect the popup.
    *   Observing DOM mutations to update the popup.
3. **Summarize `ListBoxSelectType` functionality:** Focus on how it handles the listbox-style selection, including:
    *   Handling mouse interactions (click, drag).
    *   Handling keyboard interactions (arrow keys, space, home/end, page up/down).
    *   Selection logic (single and multiple selections, range selection, toggling).
    *   Scrolling to selected options.
    *   Dispatching `input` and `change` events.
    *   Accessibility considerations for multi-select.
4. **Identify relationships with HTML, CSS, and JavaScript:**
    *   **HTML:** `<select>`, `<option>`, events (click, change, input, blur, keydown, keypress, mouse events).
    *   **CSS:** `appearance` property, styling of the dropdown and options.
    *   **JavaScript:** Dispatching events that JavaScript can listen to, potential interaction with JavaScript for dynamic updates.
5. **Consider logic and examples:** Provide simple scenarios to illustrate the behavior of each class.
6. **Consider common errors:**  Think about common mistakes developers might make when working with `<select>` elements.
7. **Focus on Part 2:** Since this is part 2, the summary should primarily cover the code in this snippet, but acknowledging the context of a larger file is also important.
这是 Chromium Blink 引擎源代码文件 `blink/renderer/core/html/forms/select_type.cc` 的第二部分，主要包含了 `MenuListSelectType` 和 `ListBoxSelectType` 两个类的实现细节。这两个类负责 `<select>` 元素的不同呈现和交互方式。

**总的来说，这部分代码的功能是定义了两种 `<select>` 元素行为模式的具体实现：菜单列表模式 (`MenuListSelectType`) 和列表框模式 (`ListBoxSelectType`)。它处理了用户与 `<select>` 元素的交互，包括打开/关闭下拉菜单、选择选项、触发事件以及更新元素的显示状态。**

以下是这两个类的具体功能归纳：

**1. `MenuListSelectType` 的功能:**

*   **下拉菜单的显示和隐藏:**  负责显示和隐藏 `<select>` 元素的下拉菜单 (`ShowPopup`, `HidePopup`)。
*   **选项选择处理:**  响应用户的选择操作 (`DidSelectOption`)，更新 `<select>` 元素的状态，并根据需要更新下拉菜单的显示。
*   **事件派发:**  在选项改变时派发 `input` 和 `change` 事件 (`DispatchEventsIfSelectedOptionChanged`)，通知 JavaScript 代码。
*   **焦点处理:**  在 `<select>` 元素失去焦点时 (`DidBlur`) 触发 `change` 事件。
*   **建议选项处理:**  处理自动填充等设置的建议选项 (`DidSetSuggestedOption`)，并可能更新显示的文本或弹出提示框。
*   **记录上次选择:**  保存上次选择的选项 (`SaveLastSelection`)，用于比较选项是否发生了变化。
*   **布局树分离处理:**  在布局树分离时 (`DidDetachLayoutTree`) 断开与弹出菜单的连接，清理资源。
*   **样式重算处理:**  响应样式的变化 (`DidRecalcStyle`)，例如 `appearance` 属性的改变，并更新元素的显示。
*   **文本内容更新:**  根据当前选择的选项更新 `<select>` 元素显示的文本 (`UpdateTextStyleInternal`, `UpdateTextStyleAndContent`)。对于多选 `<select>`，可以显示选中的数量。
*   **辅助功能更新:**  通知辅助功能树 актив 选项的变化 (`DidUpdateActiveOption`)。
*   **确定要显示的选项:**  根据当前状态（例如，是否有建议选项）确定要在 `<select>` 元素中显示的选项 (`OptionToBeShown`)。
*   **最大选项宽度改变处理:**  通知布局对象，选项的最大宽度可能已改变 (`MaximumOptionWidthMightBeChanged`)，以便重新计算布局。
*   **观察 DOM 变化:**  使用 `MutationObserver` 观察 `<select>` 元素子树的变化 (`ObserveTreeMutation`, `UnobserveTreeMutation`, `DidMutateSubtree`)，以便在下拉菜单打开时同步更新其内容。

**2. `ListBoxSelectType` 的功能:**

*   **处理鼠标事件:**  响应鼠标按下 (`kMousedown`)、移动 (`kMousemove`) 和释放 (`kMouseup`) 事件，处理选项的选择和范围选择。
*   **处理键盘事件:**  响应键盘按下 (`kKeydown`) 和按压 (`kKeypress`) 事件，允许用户使用方向键、空格键、Home/End、Page Up/Down 等键来导航和选择选项。
*   **选项选择处理:**  根据用户的操作（鼠标点击、键盘操作）更新选项的选择状态 (`UpdateSelectedState`)。
*   **多选支持:**  处理多选 `<select>` 元素的多种选择方式，包括单击选择、Shift 范围选择、Ctrl/Cmd 非连续选择。
*   **滚动处理:**  确保选中的选项可见 (`ScrollToSelection`, `ScrollToOption`, `ScrollToOptionTask`)。
*   **事件派发:**  在选项改变时触发 `input` 和 `change` 事件 (`ListBoxOnChange`)。
*   **焦点处理:**  在失去焦点时 (`DidBlur`) 清除上次的 change 事件选择状态。
*   **建议选项处理:**  处理建议选项的显示和滚动 (`DidSetSuggestedOption`)。
*   **记录上次选择:**  保存上次选择的选项状态 (`SaveLastSelection`)。
*   **多选焦点状态更新:**  更新多选列表框中选项的焦点状态 (`UpdateMultiSelectFocus`)，用于视觉指示。
*   **空间导航支持:**  为空间导航确定焦点选项 (`SpatialNavigationFocusedOption`)。
*   **全选功能:**  实现全选列表框中所有选项的功能 (`SelectAll`)。
*   **列表框大小改变处理:**  处理列表框大小的改变，用于分页导航 (`NextSelectableOptionPageAway`)。
*   **创建 Shadow DOM 子树:** 为列表框类型的 select 元素创建 Shadow DOM 子树 (`CreateShadowSubtree`)，并手动分配 slots (`ManuallyAssignSlots`)。
*   **获取相关的 DOM 元素:** 提供方法获取 Shadow DOM 中的按钮元素 (`SlottedButton`) 和用于 appearance:base 的浮层元素 (`PopoverForAppearanceBase`)。
*   **判断 appearance 属性:**  判断是否使用了 `appearance: base-button` 或 `appearance: base-picker` 样式 (`IsAppearanceBaseButton`, `IsAppearanceBasePicker`)。
*   **获取自动填充预览元素:**  获取用于自动填充预览的元素 (`GetAutofillPreviewElement`)。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

*   **HTML:**
    *   **`<select>` 元素:**  这两个类的核心功能就是控制 `<select>` 元素的行为和展示。例如，`MenuListSelectType::ShowPopup()` 的功能就是让与 `<select>` 元素关联的下拉菜单在 HTML 页面上显示出来。
    *   **`<option>` 元素:**  这两个类处理用户对 `<option>` 元素的选择。例如，`ListBoxSelectType::UpdateSelectedState(HTMLOptionElement* clicked_option, ...)` 会根据用户的点击操作更新 `<option>` 元素的 `selected` 属性。
    *   **事件:**  这两个类会触发 JavaScript 可以监听的事件，例如 `input` 和 `change`。当用户在下拉菜单或列表框中选择了一个新的选项后，`MenuListSelectType::DispatchChangeEvent()` 或 `ListBoxSelectType::ListBoxOnChange()` 会派发 `change` 事件，JavaScript 可以通过 `addEventListener('change', ...)` 来监听并执行相应的操作。

*   **CSS:**
    *   **`appearance` 属性:** `MenuListSelectType::DidRecalcStyle()` 会检查 `<select>` 元素的 `appearance` 属性是否为 `base-select`，这会影响其渲染方式和行为。
    *   **样式影响布局:** 样式变化会触发 `DidRecalcStyle`，进而可能导致布局重算。例如，更改选项的字体大小可能会影响下拉菜单的宽度，`MenuListSelectType::MaximumOptionWidthMightBeChanged()` 会通知布局系统进行更新。

*   **JavaScript:**
    *   **事件监听:** JavaScript 可以监听 `<select>` 元素的 `input` 和 `change` 事件，这些事件由 `MenuListSelectType` 和 `ListBoxSelectType` 在用户交互时触发。
    *   **动态修改 `<select>` 内容:** JavaScript 可以动态添加、删除或修改 `<option>` 元素，`MenuListSelectType` 中的 `PopupUpdater` 类会观察这些变化，并更新下拉菜单的显示。

**逻辑推理的假设输入与输出:**

**假设输入（针对 `ListBoxSelectType`）：**

1. 用户在一个多选的 `<select>` 列表框中，按住 Shift 键并点击了第一个选项 "A"。
2. 然后用户按住 Shift 键并点击了第三个选项 "C"。

**逻辑推理与输出：**

*   `ListBoxSelectType::UpdateSelectedState()` 会被调用。
*   由于按下了 Shift 键，`SelectionMode` 为 `kRange`。
*   从第一个点击的选项 "A" 到第二个点击的选项 "C" 之间的所有选项（包括 "A" 和 "C"）的 `selected` 属性将被设置为 `true`。
*   `ListBoxSelectType::ListBoxOnChange()` 会被调用，触发 `change` 事件。

**用户或编程常见的使用错误举例说明:**

*   **忘记监听 `change` 事件:** 开发者可能会在 JavaScript 中动态修改 `<select>` 元素的选项，但忘记监听 `change` 事件来处理用户的选择，导致交互逻辑不完整。例如，用户选择了一个新的选项，但页面上的其他部分没有根据这个选择进行更新。
*   **在 `input` 事件中进行高开销操作:** 开发者可能会在 `<select>` 元素的 `input` 事件处理函数中执行耗时的操作，由于 `input` 事件在每次值改变时都会触发，频繁的耗时操作会导致页面卡顿。应该考虑在 `change` 事件中执行更重要的逻辑，因为 `change` 事件只在用户完成选择并提交时触发。
*   **手动修改 `<option>` 的 `selected` 属性后忘记触发事件:** 开发者可能会使用 JavaScript 直接修改 `<option>` 元素的 `selected` 属性，但忘记手动触发 `input` 或 `change` 事件，导致框架内部的状态没有同步更新，可能导致行为不一致。

这部分代码是 Blink 引擎处理 HTML 表单元素交互的核心部分，确保了 `<select>` 元素在不同场景下的正确行为和用户体验。

Prompt: 
```
这是目录为blink/renderer/core/html/forms/select_type.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
he selection so it can be compared to the new selection
  // when we call onChange during selectOption, which gets called
  // from selectOptionByPopup, which gets called after the user
  // makes a selection from the menu.
  SaveLastSelection();
  ShowPopup(PopupMenu::kOther);
}

void MenuListSelectType::DidSelectOption(
    HTMLOptionElement* element,
    HTMLSelectElement::SelectOptionFlags flags,
    bool should_update_popup) {
  // Need to update last_on_change_option_ before UpdateFromElement().
  const bool should_dispatch_events =
      (flags & HTMLSelectElement::kDispatchInputAndChangeEventFlag) &&
      select_->last_on_change_option_ != element;
  select_->last_on_change_option_ = element;

  UpdateTextStyleAndContent();
  // PopupMenu::UpdateFromElement() posts an O(N) task.
  if (native_popup_is_visible_ && should_update_popup) {
    popup_->UpdateFromElement(PopupMenu::kBySelectionChange);
  }

  select_->SetNeedsValidityCheck();

  if (should_dispatch_events) {
    select_->DispatchInputEvent();
    select_->DispatchChangeEvent();
  }
  if (select_->GetLayoutObject()) {
    // Need to check will_be_destroyed_ because event handlers might
    // disassociate |this| and select_.
    if (!will_be_destroyed_) {
      // DidUpdateActiveOption() is O(N) because of HTMLOptionElement::index().
      DidUpdateActiveOption(element);
    }
  }
}

void MenuListSelectType::DispatchEventsIfSelectedOptionChanged() {
  HTMLOptionElement* selected_option = select_->SelectedOption();
  if (select_->last_on_change_option_.Get() != selected_option) {
    select_->last_on_change_option_ = selected_option;
    select_->DispatchInputEvent();
    select_->DispatchChangeEvent();
  }
}

void MenuListSelectType::DidBlur() {
  // We only need to fire change events here for menu lists, because we fire
  // change events for list boxes whenever the selection change is actually
  // made.  This matches other browsers' behavior.
  DispatchEventsIfSelectedOptionChanged();
  // Check native_popup_is_visible_ instead of PopupIsVisible because we don't
  // want to hide the popover in the case that the user just opened it and we
  // focused the first option in it.
  if (native_popup_is_visible_) {
    HidePopup();
  }
}

void MenuListSelectType::DidSetSuggestedOption(HTMLOptionElement* option) {
  UpdateTextStyleAndContent();
  if (native_popup_is_visible_) {
    popup_->UpdateFromElement(PopupMenu::kBySelectionChange);
  }
  if (IsAppearanceBaseButton()) {
    if (option) {
      autofill_popover_->ShowPopoverInternal(select_, &ASSERT_NO_EXCEPTION);
      autofill_popover_text_->setInnerText(option->label());
    } else {
      autofill_popover_text_->setInnerText(g_empty_string);
      autofill_popover_->HidePopoverInternal(
          HidePopoverFocusBehavior::kNone,
          HidePopoverTransitionBehavior::kNoEventsNoWaiting,
          /*exception_state=*/nullptr);
    }
  }
}

void MenuListSelectType::SaveLastSelection() {
  select_->last_on_change_option_ = select_->SelectedOption();
}

void MenuListSelectType::DidDetachLayoutTree() {
  if (popup_)
    popup_->DisconnectClient();
  SetNativePopupIsVisible(false);
  popup_ = nullptr;
  UnobserveTreeMutation();
}

void MenuListSelectType::DidRecalcStyle(const StyleRecalcChange change) {
  if (auto* style = select_->GetComputedStyle()) {
    bool is_appearance_base_select =
        style->EffectiveAppearance() == ControlPart::kBaseSelectPart;
    if (is_appearance_base_select_ != is_appearance_base_select) {
      is_appearance_base_select_ = is_appearance_base_select;
      // Switching appearance needs layout to be rebuilt because of special
      // logic in LayoutFlexibleBox::IsChildAllowed which ignores children in
      // appearance:auto mode. We also call SetNeedsReattachLayoutTree every
      // time that the size and multiple attributes are changed.
      select_->SetNeedsReattachLayoutTree();
    }
    if (is_appearance_base_select) {
      UseCounter::Count(select_->GetDocument(),
                        WebFeature::kSelectElementAppearanceBaseSelect);
    }
  }

  if (change.ReattachLayoutTree())
    return;
  UpdateTextStyle();
  if (auto* layout_object = select_->GetLayoutObject()) {
    // Invalidate paint to ensure that the focus ring is updated.
    layout_object->SetShouldDoFullPaintInvalidation();
  }
  if (popup_ && native_popup_is_visible_) {
    popup_->UpdateFromElement(PopupMenu::kByStyleChange);
  }
}

String MenuListSelectType::UpdateTextStyleInternal() {
  HTMLOptionElement* option_to_be_shown = OptionToBeShown();
  String text = g_empty_string;
  const ComputedStyle* option_style = nullptr;

  if (select_->IsMultiple()) {
    unsigned selected_count = 0;
    HTMLOptionElement* selected_option_element = nullptr;
    for (auto* const option : select_->GetOptionList()) {
      if (option->Selected()) {
        if (++selected_count == 1)
          selected_option_element = option;
      }
    }

    if (selected_count == 1) {
      text = selected_option_element->TextIndentedToRespectGroupLabel();
      option_style = selected_option_element->GetComputedStyle();
    } else {
      Locale& locale = select_->GetLocale();
      String localized_number_string =
          locale.ConvertToLocalizedNumber(String::Number(selected_count));
      text = locale.QueryString(IDS_FORM_SELECT_MENU_LIST_TEXT,
                                localized_number_string);
      DCHECK(!option_style);
    }
  } else {
    if (option_to_be_shown) {
      text = option_to_be_shown->TextIndentedToRespectGroupLabel();
      option_style = option_to_be_shown->GetComputedStyle();
    }
  }
  option_style_ = option_style;

  // In appearance:base-select mode, we are still using InnerElement for
  // rendering but we don't want to apply any special non-standard styles to it.
  // TODO(crbug.com/1511354): Ensure that this runs after switching appearance
  // modes or consider splitting InnerElement into two elements, one for
  // appearance:base-select and one for appearance:auto.
  if (!IsAppearanceBaseButton()) {
    Element& inner_element = select_->InnerElement();
    const ComputedStyle* inner_style = inner_element.GetComputedStyle();
    if (inner_style && option_style &&
        ((option_style->Direction() != inner_style->Direction() ||
          option_style->GetUnicodeBidi() != inner_style->GetUnicodeBidi() ||
          option_style->GetTextAlign(true) !=
              inner_style->GetTextAlign(true)))) {
      ComputedStyleBuilder builder(*inner_style);
      builder.SetDirection(option_style->Direction());
      builder.SetUnicodeBidi(option_style->GetUnicodeBidi());
      builder.SetTextAlign(option_style->GetTextAlign(true));
      const ComputedStyle* new_style = builder.TakeStyle();
      if (auto* inner_layout = inner_element.GetLayoutObject()) {
        inner_layout->SetModifiedStyleOutsideStyleRecalc(
            new_style, LayoutObject::ApplyStyleChanges::kYes);
      } else {
        inner_element.SetComputedStyle(std::move(new_style));
      }
    }
  }

  if (select_->GetLayoutObject())
    DidUpdateActiveOption(option_to_be_shown);

  return text.StripWhiteSpace();
}

void MenuListSelectType::UpdateTextStyleAndContent() {
  String text = UpdateTextStyleInternal();
  select_->InnerElement().firstChild()->setNodeValue(text);
  if (auto* box = select_->GetLayoutBox()) {
    if (auto* cache = select_->GetDocument().ExistingAXObjectCache())
      cache->TextChanged(box);
  }
}

void MenuListSelectType::DidUpdateActiveOption(HTMLOptionElement* option) {
  Document& document = select_->GetDocument();
  if (!document.ExistingAXObjectCache())
    return;

  int option_index = option ? option->index() : -1;
  if (ax_menulist_last_active_index_ == option_index)
    return;

  HTMLOptionElement* prev_selected_option =
      select_->OptionAtListIndex(ax_menulist_last_active_index_);
  ax_menulist_last_active_index_ = option_index;

  // We skip sending accessiblity notifications for the very first option,
  // otherwise we get extra focus and select events that are undesired.
  if (!has_updated_menulist_active_option_) {
    has_updated_menulist_active_option_ = true;
    return;
  }

  document.ExistingAXObjectCache()->MarkElementDirty(prev_selected_option);
  document.ExistingAXObjectCache()->HandleUpdateActiveMenuOption(select_);
}

HTMLOptionElement* MenuListSelectType::OptionToBeShown() const {
  if (auto* option =
          select_->OptionAtListIndex(select_->index_to_select_on_cancel_))
    return option;
  // In appearance:base-select mode, we don't want to reveal the suggested
  // option anywhere except in autofill_popover_.
  if (select_->suggested_option_ && !IsAppearanceBaseButton()) {
    return select_->suggested_option_.Get();
  }
  // TODO(tkent): We should not call OptionToBeShown() in IsMultiple() case.
  if (select_->IsMultiple())
    return select_->SelectedOption();
  DCHECK_EQ(select_->SelectedOption(), select_->last_on_change_option_);
  return select_->last_on_change_option_.Get();
}

void MenuListSelectType::MaximumOptionWidthMightBeChanged() const {
  if (LayoutObject* layout_object = select_->GetLayoutObject()) {
    layout_object->SetNeedsLayoutAndIntrinsicWidthsRecalc(
        layout_invalidation_reason::kMenuOptionsChanged);
  }
}

// PopupUpdater notifies updates of the specified SELECT element subtree to
// a PopupMenu object.
class PopupUpdater : public MutationObserver::Delegate {
 public:
  explicit PopupUpdater(MenuListSelectType& select_type,
                        HTMLSelectElement& select)
      : select_type_(select_type),
        select_(select),
        observer_(MutationObserver::Create(this)) {
    MutationObserverInit* init = MutationObserverInit::Create();
    init->setAttributeOldValue(true);
    init->setAttributes(true);
    // Observe only attributes which affect popup content.
    init->setAttributeFilter({"disabled", "label", "selected", "value"});
    init->setCharacterData(true);
    init->setCharacterDataOldValue(true);
    init->setChildList(true);
    init->setSubtree(true);
    observer_->observe(select_, init, ASSERT_NO_EXCEPTION);
  }

  ExecutionContext* GetExecutionContext() const override {
    return select_->GetExecutionContext();
  }

  void Deliver(const MutationRecordVector& records,
               MutationObserver&) override {
    // We disconnect the MutationObserver when a popup is closed.  However
    // MutationObserver can call back after disconnection.
    if (!select_type_->PopupIsVisible())
      return;
    for (const auto& record : records) {
      if (record->type() == "attributes") {
        const auto& element = *To<Element>(record->target());
        if (record->oldValue() == element.getAttribute(record->attributeName()))
          continue;
      } else if (record->type() == "characterData") {
        if (record->oldValue() == record->target()->nodeValue())
          continue;
      }
      select_type_->DidMutateSubtree();
      return;
    }
  }

  void Dispose() { observer_->disconnect(); }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(select_type_);
    visitor->Trace(select_);
    visitor->Trace(observer_);
    MutationObserver::Delegate::Trace(visitor);
  }

 private:
  Member<MenuListSelectType> select_type_;
  Member<HTMLSelectElement> select_;
  Member<MutationObserver> observer_;
};

void MenuListSelectType::ObserveTreeMutation() {
  DCHECK(!popup_updater_);
  popup_updater_ = MakeGarbageCollected<PopupUpdater>(*this, *select_);
}

void MenuListSelectType::UnobserveTreeMutation() {
  if (!popup_updater_)
    return;
  popup_updater_->Dispose();
  popup_updater_ = nullptr;
}

void MenuListSelectType::DidMutateSubtree() {
  DCHECK(native_popup_is_visible_);
  DCHECK(popup_);
  popup_->UpdateFromElement(PopupMenu::kByDOMChange);
}

// ============================================================================

// TODO(crbug.com/1511354): Rename this class to InPageSelectType
class ListBoxSelectType final : public SelectType {
 public:
  explicit ListBoxSelectType(HTMLSelectElement& select) : SelectType(select) {}
  void Trace(Visitor* visitor) const override;

  bool DefaultEventHandler(const Event& event) override;
  void DidSelectOption(HTMLOptionElement* element,
                       HTMLSelectElement::SelectOptionFlags flags,
                       bool should_update_popup) override;
  void OptionRemoved(HTMLOptionElement& option) override;
  void DidBlur() override;
  void DidSetSuggestedOption(HTMLOptionElement* option) override;
  void SaveLastSelection() override;
  HTMLOptionElement* SpatialNavigationFocusedOption() override;
  HTMLOptionElement* ActiveSelectionEnd() const override;
  void ScrollToSelection() override;
  void ScrollToOption(HTMLOptionElement* option) override;
  void SelectAll() override;
  void SaveListboxActiveSelection() override;
  void HandleMouseRelease() override;
  void ListBoxOnChange() override;
  void ClearLastOnChangeSelection() override;
  void CreateShadowSubtree(ShadowRoot&) override;
  void ManuallyAssignSlots() override;
  HTMLButtonElement* SlottedButton() const override;
  HTMLElement* PopoverForAppearanceBase() const override;
  bool IsAppearanceBaseButton() const override;
  bool IsAppearanceBasePicker() const override;
  HTMLSelectElement::SelectAutofillPreviewElement* GetAutofillPreviewElement()
      const override;

 private:
  HTMLOptionElement* NextSelectableOptionPageAway(HTMLOptionElement*,
                                                  SkipDirection) const;
  // Update :-internal-multi-select-focus state of selected OPTIONs.
  void UpdateMultiSelectFocus();
  void ToggleSelection(HTMLOptionElement& option);
  enum class SelectionMode {
    kDeselectOthers,
    kRange,
    kNotChangeOthers,
  };
  void UpdateSelectedState(HTMLOptionElement* clicked_option,
                           SelectionMode mode);
  void UpdateListBoxSelection(bool deselect_other_options, bool scroll = true);
  void SetActiveSelectionAnchor(HTMLOptionElement*);
  void SetActiveSelectionEnd(HTMLOptionElement*);
  void ScrollToOptionTask();

  Vector<bool> cached_state_for_active_selection_;
  Vector<bool> last_on_change_selection_;
  Member<HTMLOptionElement> option_to_scroll_to_;
  Member<HTMLOptionElement> active_selection_anchor_;
  Member<HTMLOptionElement> active_selection_end_;
  // TODO(crbug.com/1511354): Remove option_slot_ when the CustomizableSelect
  // flag is enabled and removed. It is only used when CustomizableSelect is
  // disabled.
  Member<HTMLSlotElement> option_slot_;
  bool is_in_non_contiguous_selection_ = false;
  bool active_selection_state_ = false;
};

void ListBoxSelectType::Trace(Visitor* visitor) const {
  visitor->Trace(option_to_scroll_to_);
  visitor->Trace(active_selection_anchor_);
  visitor->Trace(active_selection_end_);
  visitor->Trace(option_slot_);
  SelectType::Trace(visitor);
}

bool ListBoxSelectType::DefaultEventHandler(const Event& event) {
  const auto* mouse_event = DynamicTo<MouseEvent>(event);
  const auto* gesture_event = DynamicTo<GestureEvent>(event);
  if (event.type() == event_type_names::kGesturetap && gesture_event) {
    select_->Focus(FocusParams(FocusTrigger::kUserGesture));
    // Calling focus() may cause us to lose our layoutObject or change the
    // layoutObject type, in which case do not want to handle the event.
    if (!select_->GetLayoutObject() || will_be_destroyed_)
      return false;

    // Convert to coords relative to the list box if needed.
    if (HTMLOptionElement* option = EventTargetOption(*gesture_event)) {
      if (!select_->IsDisabledFormControl()) {
        UpdateSelectedState(option, gesture_event->shiftKey()
                                        ? SelectionMode::kRange
                                        : SelectionMode::kNotChangeOthers);
        ListBoxOnChange();
      }
      return true;
    }
    return false;
  }

  if (event.type() == event_type_names::kMousedown && mouse_event &&
      mouse_event->button() ==
          static_cast<int16_t>(WebPointerProperties::Button::kLeft)) {
    select_->Focus(FocusParams(FocusTrigger::kUserGesture));
    // Calling focus() may cause us to lose our layoutObject, in which case
    // do not want to handle the event.
    if (!select_->GetLayoutObject() || will_be_destroyed_ ||
        select_->IsDisabledFormControl())
      return false;

    // Convert to coords relative to the list box if needed.
    if (HTMLOptionElement* option = EventTargetOption(*mouse_event)) {
      if (!option->IsDisabledFormControl()) {
#if BUILDFLAG(IS_MAC)
        const bool meta_or_ctrl = mouse_event->metaKey();
#else
        const bool meta_or_ctrl = mouse_event->ctrlKey();
#endif
        UpdateSelectedState(option, mouse_event->shiftKey()
                                        ? SelectionMode::kRange
                                        : meta_or_ctrl
                                              ? SelectionMode::kNotChangeOthers
                                              : SelectionMode::kDeselectOthers);
      }
      if (LocalFrame* frame = select_->GetDocument().GetFrame())
        frame->GetEventHandler().SetMouseDownMayStartAutoscroll();

      return true;
    }
    return false;
  }

  if (event.type() == event_type_names::kMousemove && mouse_event) {
    if (mouse_event->button() !=
            static_cast<int16_t>(WebPointerProperties::Button::kLeft) ||
        !mouse_event->ButtonDown())
      return false;

    if (auto* layout_object = select_->GetLayoutObject()) {
      layout_object->GetFrameView()->UpdateAllLifecyclePhasesExceptPaint(
          DocumentUpdateReason::kScroll);
    }
    // Lifecycle update could have detached the layout object.
    if (auto* layout_object = select_->GetLayoutObject()) {
      if (Page* page = select_->GetDocument().GetPage()) {
        page->GetAutoscrollController().StartAutoscrollForSelection(
            layout_object);
      }
    }
    // Mousedown didn't happen in this element.
    if (last_on_change_selection_.empty())
      return false;

    if (HTMLOptionElement* option = EventTargetOption(*mouse_event)) {
      if (!select_->IsDisabledFormControl()) {
        if (select_->is_multiple_) {
          // Only extend selection if there is something selected.
          if (!active_selection_anchor_)
            return false;

          SetActiveSelectionEnd(option);
          UpdateListBoxSelection(false);
        } else {
          SetActiveSelectionAnchor(option);
          SetActiveSelectionEnd(option);
          UpdateListBoxSelection(true);
        }
      }
    }
    return false;
  }

  if (event.type() == event_type_names::kMouseup && mouse_event &&
      mouse_event->button() ==
          static_cast<int16_t>(WebPointerProperties::Button::kLeft) &&
      select_->GetLayoutObject()) {
    auto* page = select_->GetDocument().GetPage();
    if (page && page->GetAutoscrollController().AutoscrollInProgressFor(
                    select_->GetLayoutBox()))
      page->GetAutoscrollController().StopAutoscroll();
    else
      HandleMouseRelease();
    return false;
  }

  if (event.type() == event_type_names::kKeydown) {
    const auto* keyboard_event = DynamicTo<KeyboardEvent>(event);
    if (!keyboard_event)
      return false;
    const AtomicString key(keyboard_event->key());

    bool handled = false;
    HTMLOptionElement* end_option = nullptr;
    const PhysicalToLogical<const AtomicString*> key_mapper(
        select_->GetComputedStyle()->GetWritingDirection(), &keywords::kArrowUp,
        &keywords::kArrowRight, &keywords::kArrowDown, &keywords::kArrowLeft);
    const AtomicString* key_next = key_mapper.BlockEnd();
    const AtomicString* key_previous = key_mapper.BlockStart();
    if (!active_selection_end_) {
      // Initialize the end index
      if (key == *key_next || key == keywords::kPageDown) {
        HTMLOptionElement* start_option = select_->LastSelectedOption();
        handled = true;
        if (key == *key_next) {
          end_option = NextSelectableOption(start_option);
        } else {
          end_option =
              NextSelectableOptionPageAway(start_option, kSkipForwards);
        }
      } else if (key == *key_previous || key == keywords::kPageUp) {
        HTMLOptionElement* start_option = select_->SelectedOption();
        handled = true;
        if (key == *key_previous) {
          end_option = PreviousSelectableOption(start_option);
        } else {
          end_option =
              NextSelectableOptionPageAway(start_option, kSkipBackwards);
        }
      }
    } else {
      // Set the end index based on the current end index.
      if (key == *key_next) {
        end_option = NextSelectableOption(active_selection_end_);
        handled = true;
      } else if (key == *key_previous) {
        end_option = PreviousSelectableOption(active_selection_end_);
        handled = true;
      } else if (key == keywords::kPageDown) {
        end_option =
            NextSelectableOptionPageAway(active_selection_end_, kSkipForwards);
        handled = true;
      } else if (key == keywords::kPageUp) {
        end_option =
            NextSelectableOptionPageAway(active_selection_end_, kSkipBackwards);
        handled = true;
      }
    }
    if (key == keywords::kHome) {
      end_option = FirstSelectableOption();
      handled = true;
    } else if (key == keywords::kEnd) {
      end_option = LastSelectableOption();
      handled = true;
    }

    if (IsSpatialNavigationEnabled(select_->GetDocument().GetFrame())) {
      // Check if the selection moves to the boundary.
      if (key == keywords::kArrowLeft || key == keywords::kArrowRight ||
          ((key == keywords::kArrowDown || key == keywords::kArrowUp) &&
           end_option == active_selection_end_)) {
        return false;
      }
    }

    bool is_control_key = false;
#if BUILDFLAG(IS_MAC)
    is_control_key = keyboard_event->metaKey();
#else
    is_control_key = keyboard_event->ctrlKey();
#endif

    if (select_->is_multiple_ && keyboard_event->keyCode() == ' ' &&
        is_control_key && active_selection_end_) {
      // Use ctrl+space to toggle selection change.
      ToggleSelection(*active_selection_end_);
      return true;
    }

    if (end_option && handled) {
      // Save the selection so it can be compared to the new selection
      // when dispatching change events immediately after making the new
      // selection.
      SaveLastSelection();

      SetActiveSelectionEnd(end_option);

      is_in_non_contiguous_selection_ = select_->is_multiple_ && is_control_key;
      bool select_new_item =
          !select_->is_multiple_ || keyboard_event->shiftKey() ||
          (!IsSpatialNavigationEnabled(select_->GetDocument().GetFrame()) &&
           !is_in_non_contiguous_selection_);
      if (select_new_item)
        active_selection_state_ = true;
      // If the anchor is uninitialized, or if we're going to deselect all
      // other options, then set the anchor index equal to the end index.
      bool deselect_others = !select_->is_multiple_ ||
                             (!keyboard_event->shiftKey() && select_new_item);
      if (!active_selection_anchor_ || deselect_others) {
        if (deselect_others)
          select_->DeselectItemsWithoutValidation();
        SetActiveSelectionAnchor(active_selection_end_.Get());
      }

      ScrollToOption(end_option);
      if (select_new_item || is_in_non_contiguous_selection_) {
        if (select_new_item) {
          UpdateListBoxSelection(deselect_others);
          ListBoxOnChange();
        }
        UpdateMultiSelectFocus();
      } else {
        ScrollToSelection();
      }

      return true;
    }
    return false;
  }

  if (event.type() == event_type_names::kKeypress) {
    auto* keyboard_event = DynamicTo<KeyboardEvent>(event);
    if (!keyboard_event)
      return false;
    int key_code = keyboard_event->keyCode();

    if (key_code == '\r') {
      if (HTMLFormElement* form = select_->Form())
        form->SubmitImplicitly(event, false);
      return true;
    } else if (select_->is_multiple_ && key_code == ' ' &&
               (IsSpatialNavigationEnabled(select_->GetDocument().GetFrame()) ||
                is_in_non_contiguous_selection_)) {
      HTMLOptionElement* option = active_selection_end_;
      // If there's no active selection,
      // act as if "ArrowDown" had been pressed.
      if (!option)
        option = NextSelectableOption(select_->LastSelectedOption());
      if (option) {
        // Use space to toggle selection change.
        ToggleSelection(*option);
        return true;
      }
    }
    return false;
  }
  return false;
}

void ListBoxSelectType::DidSelectOption(
    HTMLOptionElement* element,
    HTMLSelectElement::SelectOptionFlags flags,
    bool should_update_popup) {
  // We should update active selection after finishing OPTION state change
  // because SetActiveSelectionAnchor() stores OPTION's selection state.
  if (element) {
    const bool is_single = !select_->IsMultiple();
    const bool deselect_other_options =
        flags & HTMLSelectElement::kDeselectOtherOptionsFlag;
    // SetActiveSelectionAnchor is O(N).
    if (!active_selection_anchor_ || is_single || deselect_other_options)
      SetActiveSelectionAnchor(element);
    if (!active_selection_end_ || is_single || deselect_other_options)
      SetActiveSelectionEnd(element);
  }

  ScrollToSelection();
  select_->SetNeedsValidityCheck();
}

void ListBoxSelectType::OptionRemoved(HTMLOptionElement& option) {
  if (option_to_scroll_to_ == &option)
    option_to_scroll_to_.Clear();
  if (active_selection_anchor_ == &option)
    active_selection_anchor_.Clear();
  if (active_selection_end_ == &option)
    active_selection_end_.Clear();
}

void ListBoxSelectType::DidBlur() {
  ClearLastOnChangeSelection();
}

void ListBoxSelectType::DidSetSuggestedOption(HTMLOptionElement* option) {
  if (!select_->GetLayoutObject())
    return;
  // When ending preview state, don't leave the scroll position at the
  // previewed element but return to the active selection end if it is
  // defined or to the first selectable option. See crbug.com/1261689.
  if (!option)
    option = ActiveSelectionEnd();
  if (!option)
    option = FirstSelectableOption();
  ScrollToOption(option);
}

void ListBoxSelectType::SaveLastSelection() {
  last_on_change_selection_.clear();
  for (auto& element : select_->GetListItems()) {
    auto* option_element = DynamicTo<HTMLOptionElement>(element.Get());
    last_on_change_selection_.push_back(option_element &&
                                        option_element->Selected());
  }
}

void ListBoxSelectType::UpdateMultiSelectFocus() {
  if (!select_->is_multiple_)
    return;

  for (auto* const option : select_->GetOptionList()) {
    if (option->IsDisabledFormControl() || !option->GetLayoutObject())
      continue;
    bool is_focused =
        (option == active_selection_end_) && is_in_non_contiguous_selection_;
    option->SetMultiSelectFocusedState(is_focused);
  }
  ScrollToSelection();
}

HTMLOptionElement* ListBoxSelectType::SpatialNavigationFocusedOption() {
  if (!IsSpatialNavigationEnabled(select_->GetDocument().GetFrame()))
    return nullptr;
  if (HTMLOptionElement* option = ActiveSelectionEnd())
    return option;
  return FirstSelectableOption();
}

void ListBoxSelectType::SetActiveSelectionAnchor(HTMLOptionElement* option) {
  active_selection_anchor_ = option;
  SaveListboxActiveSelection();
}

void ListBoxSelectType::SetActiveSelectionEnd(HTMLOptionElement* option) {
  active_selection_end_ = option;
}

HTMLOptionElement* ListBoxSelectType::ActiveSelectionEnd() const {
  if (active_selection_end_)
    return active_selection_end_.Get();
  return select_->LastSelectedOption();
}

void ListBoxSelectType::ScrollToSelection() {
  if (!select_->IsFinishedParsingChildren())
    return;
  ScrollToOption(ActiveSelectionEnd());
  if (AXObjectCache* cache = select_->GetDocument().ExistingAXObjectCache())
    cache->ListboxActiveIndexChanged(select_);
}

void ListBoxSelectType::ScrollToOption(HTMLOptionElement* option) {
  if (!option)
    return;
  bool has_pending_task = option_to_scroll_to_ != nullptr;
  // We'd like to keep an HTMLOptionElement reference rather than the index of
  // the option because the task should work even if unselected option is
  // inserted before executing ScrollToOptionTask().
  option_to_scroll_to_ = option;
  if (!has_pending_task) {
    select_->GetDocument()
        .GetTaskRunner(TaskType::kUserInteraction)
        ->PostTask(FROM_HERE,
                   WTF::BindOnce(&ListBoxSelectType::ScrollToOptionTask,
                                 WrapPersistent(this)));
  }
}

void ListBoxSelectType::ScrollToOptionTask() {
  HTMLOptionElement* option = option_to_scroll_to_.Release();
  if (!option || !select_->isConnected() || will_be_destroyed_)
    return;
  // OptionRemoved() makes sure option_to_scroll_to_ doesn't have an option
  // with another owner.
  DCHECK_EQ(option->OwnerSelectElement(), select_);
  select_->GetDocument().UpdateStyleAndLayoutForNode(
      select_, DocumentUpdateReason::kScroll);
  if (!select_->GetLayoutObject())
    return;
  PhysicalRect bounds = option->BoundingBoxForScrollIntoView();

  // The following code will not scroll parent boxes unlike ScrollRectToVisible.
  auto* box = select_->GetLayoutBox();
  if (!box->IsScrollContainer())
    return;
  DCHECK(box->Layer());
  DCHECK(box->Layer()->GetScrollableArea());
  box->Layer()->GetScrollableArea()->ScrollIntoView(
      bounds, PhysicalBoxStrut(),
      scroll_into_view_util::CreateScrollIntoViewParams(
          ScrollAlignment::ToEdgeIfNeeded(), ScrollAlignment::ToEdgeIfNeeded(),
          mojom::blink::ScrollType::kProgrammatic, false,
          mojom::blink::ScrollBehavior::kInstant));
}

void ListBoxSelectType::SelectAll() {
  if (!select_->GetLayoutObject() || !select_->is_multiple_)
    return;

  // Save the selection so it can be compared to the new selectAll selection
  // when dispatching change events.
  SaveLastSelection();

  active_selection_state_ = true;
  SetActiveSelectionAnchor(NextSelectableOption(nullptr));
  SetActiveSelectionEnd(PreviousSelectableOption(nullptr));

  UpdateListBoxSelection(false, false);
  ListBoxOnChange();
  select_->SetNeedsValidityCheck();
}

// Returns the index of the next valid item one page away from |start_option|
// in direction |direction|.
HTMLOptionElement* ListBoxSelectType::NextSelectableOptionPageAway(
    HTMLOptionElement* start_option,
    SkipDirection direction) const {
  const auto& items = select_->GetListItems();
  // -1 so we still show context.
  int page_size = select_->ListBoxSize() - 1;

  // One page away, but not outside valid bounds.
  // If there is a valid option item one page away, the index is chosen.
  // If there is no exact one page away valid option, returns start_index or
  // the most far index.
  int start_index = start_option ? start_option->ListIndex() : -1;
  int edge_index = (direction == kSkipForwards) ? 0 : (items.size() - 1);
  int skip_amount =
      page_size +
      ((direction == kSkipForwards) ? start_index : (edge_index - start_index));
  return NextValidOption(edge_index, direction, skip_amount);
}

void ListBoxSelectType::ToggleSelection(HTMLOptionElement& option) {
  active_selection_state_ = !active_selection_state_;
  UpdateSelectedState(&option, SelectionMode::kNotChangeOthers);
  ListBoxOnChange();
}

void ListBoxSelectType::UpdateSelectedState(HTMLOptionElement* clicked_option,
                                            SelectionMode mode) {
  DCHECK(clicked_option);
  // Save the selection so it can be compared to the new selection when
  // dispatching change events during mouseup, or after autoscroll finishes.
  SaveLastSelection();

  if (!select_->is_multiple_)
    mode = SelectionMode::kDeselectOthers;

  // Keep track of whether an active selection (like during drag selection),
  // should select or deselect.
  active_selection_state_ =
      !(clicked_option->Selected() && mode == SelectionMode::kNotChangeOthers);

  // If we're not in any special multiple selection mode, then deselect all
  // other items, excluding the clicked OPTION. If no option was clicked,
  // then this will deselect all items in the list.
  if (mode == SelectionMode::kDeselectOthers) {
    bool did_deselect_others =
        select_->DeselectItemsWithoutValidation(clicked_option);
    // In a multi-select, if nothing else could be deselected,
    // deselect the (already selected) clicked option instead.
    if (select_->is_multiple_ && !did_deselect_others &&
        clicked_option->Selected() &&
        RuntimeEnabledFeatures::MultiSelectDeselectWhenOnlyOptionEnabled()) {
  
"""


```