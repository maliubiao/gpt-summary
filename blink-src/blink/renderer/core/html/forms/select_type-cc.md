Response:
The user wants a summary of the functionality of the provided C++ code file `select_type.cc`. I need to identify the main purpose of the code, how it interacts with web technologies (HTML, CSS, JavaScript), and common usage errors.

Here's a breakdown of the thought process:

1. **Identify the core component:** The file is named `select_type.cc` and located within the `blink/renderer/core/html/forms/` directory. This strongly suggests it's related to the `<select>` HTML element and its different behaviors.

2. **Analyze the includes:** The included headers provide valuable clues. Keywords like `HTMLSelectElement`, `HTMLOptionElement`, `PopupMenu`, `ShadowRoot`, `Event`, `KeyboardEvent`, `MouseEvent`, `CSSSelector`, and `AXObjectCache` are prominent. This indicates the file manages the behavior and rendering of the `<select>` element, including its dropdown menu, accessibility, and event handling.

3. **Focus on the main class:** The code defines a class named `MenuListSelectType` which inherits from `SelectType`. This is likely a concrete implementation for a specific type of `<select>` behavior (the standard dropdown menu).

4. **Examine the methods of `MenuListSelectType`:**  The methods provide insight into its responsibilities:
    * **Event Handling:** `DefaultEventHandler`,  `ShouldOpenPopupForKeyDownEvent`, `ShouldOpenPopupForKeyPressEvent`, `HandlePopupOpenKeyboardEvent`. This section manages how user interactions (keyboard and mouse) affect the `<select>` element, particularly opening and closing the dropdown.
    * **Option Selection:** `DidSelectOption`, `DidSetSuggestedOption`. Deals with selecting options within the `<select>`.
    * **Popup Management:** `ShowPopup`, `HidePopup`, `PopupDidHide`, `PopupIsVisible`, `PopupForTesting`, `PopupRootAXObject`. These methods control the display and behavior of the dropdown menu.
    * **Shadow DOM:** `CreateShadowSubtree`, `ManuallyAssignSlots`, `SlottedButton`. This indicates the use of Shadow DOM to encapsulate the internal structure and styling of the `<select>` element. The slot assignment is important for how `<option>` elements are rendered within the shadow DOM.
    * **Appearance Customization:** `PopoverForAppearanceBase`, `IsAppearanceBaseButton`, `IsAppearanceBasePicker`. These methods deal with a newer, customizable appearance feature for `<select>`, potentially using popovers.
    * **Accessibility:** The inclusion of `AXObjectCache` and methods like `PopupRootAXObject` point to accessibility considerations.
    * **Styling:** `UpdateTextStyle`, `UpdateTextStyleAndContent`, `OptionStyle`, `DidRecalcStyle`. These methods handle how the visual appearance of the `<select>` element and its options are updated.
    * **Autofill:** `GetAutofillPreviewElement`. Indicates support for browser autofill functionality within the `<select>` element.
    * **Mutation Observation:** `DidMutateSubtree`, `ObserveTreeMutation`, `UnobserveTreeMutation`. Suggests the code monitors changes to the `<select>` element's children.

5. **Identify relationships with web technologies:**
    * **HTML:** The code directly manipulates and responds to events related to `<select>`, `<option>`, and related form elements. The shadow DOM structure and slotting directly affect how the HTML is rendered.
    * **CSS:** Methods like `UpdateTextStyle` and `DidRecalcStyle` indicate interaction with CSS to style the `<select>` element. The `appearance` CSS property is explicitly mentioned in the context of `IsAppearanceBaseButton` and `IsAppearanceBasePicker`. The use of pseudo-classes like `:open` and `:closed` is also evident.
    * **JavaScript:** While the code is C++, it provides the underlying implementation for the behavior that JavaScript interacts with. JavaScript can trigger events on the `<select>` element, modify its attributes, and observe changes.

6. **Infer logical flow and potential errors:** The code manages the state of the `<select>` element (e.g., whether the popup is open). Common errors could arise from:
    * Incorrectly handling events, leading to the popup not opening or closing as expected.
    * Issues with slot assignment, causing `<option>` elements not to be displayed correctly.
    * Accessibility problems if the ARIA attributes or the structure are not correctly managed.
    * Incorrectly implementing the customizable appearance feature.

7. **Structure the summary:** Organize the findings into logical categories (functionality, relationship with web technologies, logical inference, common errors). Use clear and concise language.

By following this process, I can generate a comprehensive and accurate summary of the `select_type.cc` file. The key is to leverage the information within the code itself (class names, method names, included headers) to understand its purpose and interactions.
这是 Chromium Blink 引擎中负责处理 HTML `<select>` 元素默认下拉列表行为的核心代码文件 `select_type.cc`。 它主要实现了 `MenuListSelectType` 类，该类定义了 `<select>` 元素在默认情况下（即非 `appearance: none` 或自定义外观时）如何响应用户交互、渲染以及与其他 web 技术交互。

**主要功能归纳:**

1. **事件处理 (Event Handling):**  处理用户与 `<select>` 元素的交互事件，包括鼠标点击 (`mousedown`) 和键盘事件 (`keydown`, `keypress`)。  决定这些事件是否应该触发下拉列表的打开或关闭，以及如何改变选中的选项。

2. **下拉列表 (Popup Menu) 管理:**  负责创建、显示和隐藏 `<select>` 元素的下拉列表 (PopupMenu)。这包括确定下拉列表的位置和内容，并与 Chromium 的 ChromeClient 交互来显示原生下拉列表。

3. **选项 (Option) 选择:**  管理 `<select>` 元素中选项的选中状态，包括响应用户的选择操作，更新内部状态，并触发相应的事件（如 `input` 和 `change`）。

4. **Shadow DOM 实现:**  使用 Shadow DOM 来封装 `<select>` 元素的内部结构，包括用于显示当前选中项的内部元素 (`MenuListInnerElement`) 和用于放置 `<option>` 元素的插槽 (`HTMLSlotElement`)。

5. **无障碍性 (Accessibility):**  与无障碍对象缓存 (`AXObjectCache`) 交互，以便浏览器和辅助技术能够正确理解和操作 `<select>` 元素及其下拉列表。

6. **样式 (Style) 更新:**  负责更新 `<select>` 元素及其选项的文本样式和内容，例如当选中的选项发生变化时。

7. **自定义外观支持 (Customizable Select Support):**  为 `<select>` 元素提供实验性的自定义外观支持，通过 `appearance: base-select` CSS 属性启用。 这部分涉及到使用 Popover API 来实现自定义的下拉列表。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * 该文件处理的核心是 HTML `<select>` 元素。它监听并响应与 `<select>` 元素及其子元素（`<option>`, `<optgroup>`) 相关的事件。
    * **举例:** 当用户在 HTML 中点击一个 `<select>` 元素时，`DefaultEventHandler` 中的鼠标事件处理逻辑会被触发，可能会调用 `ShowPopup` 来显示下拉列表。
    * **举例:**  `<option>` 元素的内容和属性会影响 `MenuListSelectType` 如何渲染下拉列表中的选项。

* **JavaScript:**
    * JavaScript 可以通过编程方式与 `<select>` 元素交互，例如设置其 `value` 属性，触发 `focus` 或 `blur` 事件。`MenuListSelectType` 的代码会响应这些操作。
    * **举例:**  JavaScript 可以调用 `<selectElement>.focus()` 方法，导致 `MenuListSelectType::DidBlur` 在失去焦点时被调用。
    * **举例:**  JavaScript 可以监听 `<select>` 元素的 `change` 事件，该事件由 `MenuListSelectType::DidSelectOption` 在用户选择新选项后触发。

* **CSS:**
    * CSS 样式会影响 `<select>` 元素的渲染外观。虽然 `MenuListSelectType` 主要处理逻辑，但它需要考虑元素的样式信息。
    * **举例:**  CSS 的 `display: none` 可能会阻止下拉列表的显示，`MenuListSelectType` 的代码会检查元素的布局状态。
    * **举例:**  新的 CSS 属性 `appearance: base-select` 会改变 `<select>` 元素的行为，使其使用 Popover API 进行渲染，相关的逻辑在 `MenuListSelectType` 中有体现。 该文件会根据 `appearance` 的值来选择不同的渲染和事件处理方式。  `DidRecalcStyle` 方法会在样式重新计算后被调用。

**逻辑推理及假设输入与输出:**

假设输入一个 `keydown` 事件，按下的键是 "ArrowDown"，并且当前 `<select>` 元素拥有焦点：

* **假设输入:** 一个 `KeyboardEvent` 对象，其 `type` 为 "keydown"， `key` 为 "ArrowDown"，目标元素是一个 `<select>` 元素。
* **逻辑推理:** `DefaultEventHandler` 会被调用 -> 检查 `ShouldOpenPopupForKeyDownEvent`，如果条件满足（例如，没有使用 spatial navigation 且主题允许用箭头键弹出菜单），可能会调用 `HandlePopupOpenKeyboardEvent` 来显示下拉列表。或者，如果下拉列表已经打开，它可能会调用 `NextValidOption` 来移动选中项。
* **预期输出:** 如果下拉列表之前未打开，则会显示下拉列表。如果已打开，则下拉列表中选中的选项可能会向下移动。

假设输入一个 `mousedown` 事件，点击的是 `<select>` 元素本身：

* **假设输入:** 一个 `MouseEvent` 对象，其 `type` 为 "mousedown"，目标元素是一个 `<select>` 元素。
* **逻辑推理:** `DefaultEventHandler` 会被调用 -> 检查鼠标按钮是否是左键 -> 元素获得焦点（如果尚未获得） -> 如果下拉列表当前可见，则隐藏它；否则，显示下拉列表 (`ShowPopup`)。
* **预期输出:** 如果下拉列表之前可见，则会隐藏。如果之前不可见，则会显示出来。

**用户或编程常见的使用错误举例:**

1. **阻止默认事件导致下拉列表无法打开:** 如果 JavaScript 代码中为 `<select>` 元素绑定了 `mousedown` 或 `keydown` 事件，并且错误地调用了 `event.preventDefault()`，可能会阻止 `MenuListSelectType` 的 `DefaultEventHandler` 执行，从而导致下拉列表无法正常打开。
    ```javascript
    const selectElement = document.querySelector('select');
    selectElement.addEventListener('mousedown', (event) => {
      event.preventDefault(); // 错误地阻止了默认行为
      console.log('mousedown事件被捕获');
    });
    ```
    **结果:** 点击该 `<select>` 元素时，控制台会输出信息，但下拉列表不会打开。

2. **在自定义组件中错误地处理 `<select>` 的事件:**  如果开发者创建了一个包含 `<select>` 元素的自定义组件，并且没有正确地将事件委托或冒泡到 `<select>` 元素本身，可能会导致 `MenuListSelectType` 无法接收到事件。

3. **误解 `appearance: none` 的作用:** 开发者可能会误认为设置 `appearance: none` 后，`MenuListSelectType` 的所有逻辑都会失效。虽然默认的下拉列表行为会被禁用，但 `<select>` 元素仍然会接收事件，只是需要开发者自己实现下拉列表的逻辑。

4. **在 Shadow DOM 中错误地使用 Slot:** 如果自定义的 Shadow DOM 结构没有正确地使用 `<slot>` 元素来放置 `<option>` 元素，`MenuListSelectType` 可能无法正确地渲染下拉列表的内容。

**总结 `select_type.cc` 的功能 (Part 1):**

`blink/renderer/core/html/forms/select_type.cc` 文件中的 `MenuListSelectType` 类是 Chromium Blink 引擎中负责实现 HTML `<select>` 元素默认下拉列表行为的关键组件。它处理用户交互事件、管理下拉列表的显示和隐藏、处理选项的选择、利用 Shadow DOM 封装内部结构，并与浏览器的无障碍功能和 CSS 样式系统进行交互。 此外，它还为实验性的自定义外观功能提供支持。 该文件是理解 `<select>` 元素在浏览器中如何工作的基础。

Prompt: 
```
这是目录为blink/renderer/core/html/forms/select_type.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
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

#include "third_party/blink/renderer/core/html/forms/select_type.h"

#include "build/build_config.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mutation_observer_init.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/mutation_observer.h"
#include "third_party/blink/renderer/core/dom/mutation_record.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/events/gesture_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_data_list_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_opt_group_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/menu_list_inner_element.h"
#include "third_party/blink/renderer/core/html/forms/popup_menu.h"
#include "third_party/blink/renderer/core/html/html_hr_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input/input_device_capabilities.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/page/autoscroll_controller.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/spatial_navigation.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scroll_alignment.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "ui/base/ui_base_features.h"

namespace blink {

class PopupUpdater;

namespace {

HTMLOptionElement* EventTargetOption(const Event& event) {
  return DynamicTo<HTMLOptionElement>(event.target()->ToNode());
}

bool CanAssignToSelectSlot(const Node& node) {
  // Even if options/optgroups are not rendered as children of menulist SELECT,
  // we still need to add them to the flat tree through slotting since we need
  // their ComputedStyle for popup rendering.
  return node.HasTagName(html_names::kOptionTag) ||
         node.HasTagName(html_names::kOptgroupTag) ||
         node.HasTagName(html_names::kHrTag);
}

bool CanAssignToCustomizableSelectSlot(const Node& node) {
  // Elements which are valid in <select>'s new content model as proposed for
  // customizable select.
  return IsA<HTMLOptionElement>(node) || IsA<HTMLOptGroupElement>(node) ||
         IsA<HTMLHRElement>(node) || IsA<HTMLSpanElement>(node) ||
         IsA<HTMLDivElement>(node);
}

class PopoverElementForAppearanceBase : public HTMLDivElement {
 public:
  explicit PopoverElementForAppearanceBase(Document& document)
      : HTMLDivElement(document) {
    CHECK(RuntimeEnabledFeatures::CustomizableSelectEnabled());
    SetHasCustomStyleCallbacks();
  }

  void ShowPopoverInternal(Element* invoker,
                           ExceptionState* exception_state) override {
    HTMLElement::ShowPopoverInternal(invoker, exception_state);
    if (exception_state && exception_state->HadException()) {
      return;
    }

    if (auto* select = ParentSelect()) {
      // MenuListSelectType::ManuallyAssignSlots changes behavior based on
      // whether the popover is opened or closed.
      select->GetShadowRoot()->SetNeedsAssignmentRecalc();
      // This is a CustomizableSelect popup. When it is shown, we should focus
      // the selected option.
      HTMLOptionElement* option_to_focus = select->SelectedOption();
      if (!option_to_focus || !option_to_focus->IsFocusable()) {
        for (auto* option : select->GetOptionList()) {
          if (option->IsFocusable()) {
            option_to_focus = option;
            break;
          }
        }
      }
      if (option_to_focus) {
        option_to_focus->Focus(FocusParams(FocusTrigger::kScript));
      }
      if (AXObjectCache* cache =
              select->GetDocument().ExistingAXObjectCache()) {
        cache->DidShowMenuListPopup(select);
      }
    }
  }

  void HidePopoverInternal(HidePopoverFocusBehavior focus_behavior,
                           HidePopoverTransitionBehavior event_firing,
                           ExceptionState* exception_state) override {
    HTMLDivElement::HidePopoverInternal(focus_behavior, event_firing,
                                        exception_state);
    if (auto* select = ParentSelect()) {
      // MenuListSelectType::ManuallyAssignSlots changes behavior based on
      // whether the popover is opened or closed.
      select->GetShadowRoot()->SetNeedsAssignmentRecalc();

      // Focus the select when the popover is hidden.
      if (focus_behavior == HidePopoverFocusBehavior::kFocusPreviousElement) {
        select->Focus(FocusParams(FocusTrigger::kScript));
      }

      if (AXObjectCache* cache =
              select->GetDocument().ExistingAXObjectCache()) {
        cache->DidHideMenuListPopup(select);
      }
    }
  }

  InsertionNotificationRequest InsertedInto(ContainerNode& container) override {
    InsertionNotificationRequest return_value =
        HTMLDivElement::InsertedInto(container);
    if (container == parentNode()) {
      CHECK(ParentSelect());
      ParentSelect()->IncrementImplicitlyAnchoredElementCount();
    }
    return return_value;
  }

  void RemovedFrom(ContainerNode& container) override {
    if (!parentNode()) {
      auto* shadowroot = DynamicTo<ShadowRoot>(container);
      CHECK(shadowroot);
      auto* select = DynamicTo<HTMLSelectElement>(shadowroot->host());
      CHECK(select);
      select->DecrementImplicitlyAnchoredElementCount();
    }
    HTMLDivElement::RemovedFrom(container);
  }

  void DidRecalcStyle(const StyleRecalcChange change) override {
    HTMLDivElement::DidRecalcStyle(change);
    if (auto* style = GetComputedStyle()) {
      if (style->EffectiveAppearance() == ControlPart::kBaseSelectPart) {
        UseCounter::Count(GetDocument(),
                          WebFeature::kSelectElementPickerAppearanceBaseSelect);
      }
    }
  }

 private:
  HTMLSelectElement* ParentSelect() {
    if (auto* shadowroot = DynamicTo<ShadowRoot>(parentNode())) {
      HTMLSelectElement* select =
          DynamicTo<HTMLSelectElement>(shadowroot->host());
      CHECK(select);
      return select;
    }
    return nullptr;
  }
};

}  // anonymous namespace

// TODO(crbug.com/1511354): Rename this class to PopUpSelectType
class MenuListSelectType final : public SelectType {
 public:
  explicit MenuListSelectType(HTMLSelectElement& select) : SelectType(select) {}
  void Trace(Visitor* visitor) const override;

  bool DefaultEventHandler(const Event& event) override;
  void DidSelectOption(HTMLOptionElement* element,
                       HTMLSelectElement::SelectOptionFlags flags,
                       bool should_update_popup) override;
  void DidBlur() override;
  void DidDetachLayoutTree() override;
  void DidRecalcStyle(const StyleRecalcChange change) override;
  void DidSetSuggestedOption(HTMLOptionElement* option) override;
  void SaveLastSelection() override;

  void UpdateTextStyle() override { UpdateTextStyleInternal(); }
  void UpdateTextStyleAndContent() override;
  HTMLOptionElement* OptionToBeShown() const override;
  const ComputedStyle* OptionStyle() const override {
    return option_style_.Get();
  }
  void MaximumOptionWidthMightBeChanged() const override;

  void CreateShadowSubtree(ShadowRoot& root) override;
  void ManuallyAssignSlots() override;
  HTMLButtonElement* SlottedButton() const override;
  HTMLElement* PopoverForAppearanceBase() const override;
  bool IsAppearanceBaseButton() const override;
  bool IsAppearanceBasePicker() const override;
  HTMLSelectElement::SelectAutofillPreviewElement* GetAutofillPreviewElement()
      const override;
  Element& InnerElement() const override;
  void ShowPopup(PopupMenu::ShowEventType type) override;
  void HidePopup() override;
  void PopupDidHide() override;
  bool PopupIsVisible() const override;
  PopupMenu* PopupForTesting() const override;
  AXObject* PopupRootAXObject() const override;
  void ShowPicker() override;

  void DidMutateSubtree();

 private:
  bool ShouldOpenPopupForKeyDownEvent(const KeyboardEvent& event);
  bool ShouldOpenPopupForKeyPressEvent(const KeyboardEvent& event);
  // Returns true if this function handled the event.
  bool HandlePopupOpenKeyboardEvent();
  void SetNativePopupIsVisible(bool popup_is_visible);
  void DispatchEventsIfSelectedOptionChanged();
  String UpdateTextStyleInternal();
  void DidUpdateActiveOption(HTMLOptionElement* option);
  void ObserveTreeMutation();
  void UnobserveTreeMutation();

  Member<PopupMenu> popup_;
  Member<PopupUpdater> popup_updater_;
  Member<const ComputedStyle> option_style_;
  Member<HTMLSlotElement> button_slot_;
  Member<PopoverElementForAppearanceBase> popover_;
  Member<HTMLSelectElement::SelectAutofillPreviewElement> autofill_popover_;
  Member<HTMLDivElement> autofill_popover_text_;
  Member<HTMLSlotElement> popover_options_slot_;
  Member<HTMLSlotElement> option_slot_;
  Member<MenuListInnerElement> inner_element_;
  int ax_menulist_last_active_index_ = -1;
  bool has_updated_menulist_active_option_ = false;
  bool native_popup_is_visible_ = false;
  bool snav_arrow_key_selection_ = false;
  bool is_appearance_base_select_ = false;
};

void MenuListSelectType::Trace(Visitor* visitor) const {
  visitor->Trace(popup_);
  visitor->Trace(popup_updater_);
  visitor->Trace(option_style_);
  visitor->Trace(button_slot_);
  visitor->Trace(popover_);
  visitor->Trace(autofill_popover_);
  visitor->Trace(autofill_popover_text_);
  visitor->Trace(popover_options_slot_);
  visitor->Trace(option_slot_);
  visitor->Trace(inner_element_);
  SelectType::Trace(visitor);
}

bool MenuListSelectType::DefaultEventHandler(const Event& event) {
  // We need to make the layout tree up-to-date to have GetLayoutObject() give
  // the correct result below. An author event handler may have set display to
  // some element to none which will cause a layout tree detach.
  select_->GetDocument().UpdateStyleAndLayoutTree();

  // TODO(crbug.com/379241451): This can be removed once new behavior ships.
  // The purpose of this method is to handle events on the in-page part of the
  // select and determining whether they should toggle the picker. However, it
  // will also pick up events on the base appearance picker popover, and we
  // don't want to do anything about those events, so the following code will
  // return early in the case that the events are targeting nodes in the picker.
  if (!RuntimeEnabledFeatures::PopoverButtonNestingBehaviorEnabled() &&
      IsAppearanceBasePicker() && event.HasEventPath()) {
    bool target_is_button =
        event.target() == select_ || event.target() == &InnerElement();
    auto* button = SlottedButton();
    if (!target_is_button && button) {
      // If the author provided a button, then also check to see if the event
      // target is something inside the author provided button.
      for (unsigned i = 0; i < event.GetEventPath().size(); i++) {
        Node& node = event.GetEventPath()[i].GetNode();
        if (node == select_) {
          break;
        } else if (node == button) {
          target_is_button = true;
          break;
        }
      }
    }
    if (!target_is_button) {
      return false;
    }
  }

  const int ignore_modifiers = WebInputEvent::kShiftKey |
                               WebInputEvent::kControlKey |
                               WebInputEvent::kAltKey | WebInputEvent::kMetaKey;

  const auto* key_event = DynamicTo<KeyboardEvent>(event);
  if (event.type() == event_type_names::kKeydown) {
    if (!select_->GetLayoutObject() || !key_event)
      return false;

    if (ShouldOpenPopupForKeyDownEvent(*key_event))
      return HandlePopupOpenKeyboardEvent();

    // When using spatial navigation, we want to be able to navigate away
    // from the select element when the user hits any of the arrow keys,
    // instead of changing the selection.
    if (IsSpatialNavigationEnabled(select_->GetDocument().GetFrame())) {
      if (!snav_arrow_key_selection_)
        return false;
    }

    // The key handling below shouldn't be used for non spatial navigation
    // mode Mac
    if (LayoutTheme::GetTheme().PopsMenuByArrowKeys() &&
        !IsSpatialNavigationEnabled(select_->GetDocument().GetFrame()))
      return false;

    if (key_event->GetModifiers() & ignore_modifiers)
      return false;

    const AtomicString key(key_event->key());
    bool handled = true;
    HTMLOptionElement* option = select_->SelectedOption();
    int list_index = option ? option->ListIndex() : -1;

    if (key == keywords::kArrowDown || key == keywords::kArrowRight) {
      option = NextValidOption(list_index, kSkipForwards, 1);
    } else if (key == keywords::kArrowUp || key == keywords::kArrowLeft) {
      option = NextValidOption(list_index, kSkipBackwards, 1);
    } else if (key == keywords::kPageDown) {
      option = NextValidOption(list_index, kSkipForwards, 3);
    } else if (key == keywords::kPageUp) {
      option = NextValidOption(list_index, kSkipBackwards, 3);
    } else if (key == keywords::kHome) {
      option = FirstSelectableOption();
    } else if (key == keywords::kEnd) {
      option = LastSelectableOption();
    } else {
      handled = false;
    }

    if (handled && option) {
      select_->SelectOption(
          option, HTMLSelectElement::kDeselectOtherOptionsFlag |
                      HTMLSelectElement::kMakeOptionDirtyFlag |
                      HTMLSelectElement::kDispatchInputAndChangeEventFlag);
    }
    return handled;
  }

  if (event.type() == event_type_names::kKeypress) {
    if (!select_->GetLayoutObject() || !key_event)
      return false;

    int key_code = key_event->keyCode();
    if (key_code == ' ' &&
        IsSpatialNavigationEnabled(select_->GetDocument().GetFrame())) {
      // Use space to toggle arrow key handling for selection change or
      // spatial navigation.
      snav_arrow_key_selection_ = !snav_arrow_key_selection_;
      return true;
    }

    if (ShouldOpenPopupForKeyPressEvent(*key_event))
      return HandlePopupOpenKeyboardEvent();

    // TODO(crbug.com/1511354): Reconsider making appearance:base-select affect
    // keyboard behavior after a resolution here:
    // https://github.com/openui/open-ui/issues/1087
    if (IsAppearanceBaseButton() && key_code == '\r') {
      // TODO(crbug.com/1511354): Consider making form->SubmitImplicitly work
      // here instead of PrepareForSubmission and combine with the subsequent
      // code.
      if (HTMLFormElement* form = select_->Form()) {
        form->PrepareForSubmission(&event, select_);
        return true;
      }
    }

    if (!LayoutTheme::GetTheme().PopsMenuByReturnKey() && key_code == '\r') {
      if (HTMLFormElement* form = select_->Form())
        form->SubmitImplicitly(event, false);
      DispatchEventsIfSelectedOptionChanged();
      return true;
    }
    return false;
  }

  const auto* mouse_event = DynamicTo<MouseEvent>(event);
  if (event.type() == event_type_names::kMousedown && mouse_event &&
      mouse_event->button() ==
          static_cast<int16_t>(WebPointerProperties::Button::kLeft)) {
    InputDeviceCapabilities* source_capabilities =
        select_->GetDocument()
            .domWindow()
            ->GetInputDeviceCapabilities()
            ->FiresTouchEvents(mouse_event->FromTouch());
    select_->Focus(FocusParams(SelectionBehaviorOnFocus::kRestore,
                               mojom::blink::FocusType::kMouse,
                               source_capabilities, FocusOptions::Create(),
                               FocusTrigger::kUserGesture));
    if (select_->GetLayoutObject() && !will_be_destroyed_ &&
        !select_->IsDisabledFormControl()) {
      if (PopupIsVisible()) {
        if (!IsAppearanceBasePicker()) {
          HidePopup();
        }
      } else {
        // Save the selection so it can be compared to the new selection
        // when we call onChange during selectOption, which gets called
        // from selectOptionByPopup, which gets called after the user
        // makes a selection from the menu.
        SaveLastSelection();
        // TODO(lanwei): Will check if we need to add
        // InputDeviceCapabilities here when select menu list gets
        // focus, see https://crbug.com/476530.
        if (IsAppearanceBasePicker()) {
          // Because we're activating the <select> on mousedown, not mouseup
          // or click, this code will immediately show the popover, and the
          // following mouseup will activate popover light dismiss, which will
          // immediately close the popover unless we disable it by doing this.
          select_->GetDocument().SetPopoverPointerdownTarget(popover_);
        }
        ShowPopup(mouse_event->FromTouch() ? PopupMenu::kTouch
                                           : PopupMenu::kOther);
      }
    }
    return true;
  }
  return false;
}

bool MenuListSelectType::ShouldOpenPopupForKeyDownEvent(
    const KeyboardEvent& event) {
  const AtomicString key(event.key());
  LayoutTheme& layout_theme = LayoutTheme::GetTheme();

  if (IsSpatialNavigationEnabled(select_->GetDocument().GetFrame()))
    return false;

  // TODO(crbug.com/1511354): Reconsider making appearance:base-select affect
  // keyboard behavior after a resolution here:
  // https://github.com/openui/open-ui/issues/1087
  if (IsAppearanceBaseButton() &&
      (key == keywords::kArrowDown || key == keywords::kArrowUp ||
       key == keywords::kArrowLeft || key == keywords::kArrowRight)) {
    return true;
  }

  return ((layout_theme.PopsMenuByArrowKeys() &&
           (key == keywords::kArrowDown || key == keywords::kArrowUp)) ||
          ((key == keywords::kArrowDown || key == keywords::kArrowUp) &&
           event.altKey()) ||
          ((!event.altKey() && !event.ctrlKey() && key == "F4")));
}

bool MenuListSelectType::ShouldOpenPopupForKeyPressEvent(
    const KeyboardEvent& event) {
  LayoutTheme& layout_theme = LayoutTheme::GetTheme();
  int key_code = event.keyCode();

  // TODO(crbug.com/1511354): Reconsider making appearance:base-select affect
  // keyboard behavior after a resolution here:
  // https://github.com/openui/open-ui/issues/1087
  if (IsAppearanceBaseButton() && key_code == '\r') {
    return false;
  }

  return ((key_code == ' ' && !select_->type_ahead_.HasActiveSession(event)) ||
          (layout_theme.PopsMenuByReturnKey() && key_code == '\r'));
}

bool MenuListSelectType::HandlePopupOpenKeyboardEvent() {
  select_->Focus(FocusParams(FocusTrigger::kUserGesture));
  // Calling focus() may cause us to lose our LayoutObject. Return true so
  // that our caller doesn't process the event further, but don't set
  // the event as handled.
  if (!select_->GetLayoutObject() || will_be_destroyed_ ||
      select_->IsDisabledFormControl())
    return false;
  // Save the selection so it can be compared to the new selection when
  // dispatching change events during SelectOption, which gets called from
  // SelectOptionByPopup, which gets called after the user makes a selection
  // from the menu.
  SaveLastSelection();
  ShowPopup(PopupMenu::kOther);
  return true;
}

void MenuListSelectType::CreateShadowSubtree(ShadowRoot& root) {
  Document& doc = select_->GetDocument();

  inner_element_ = MakeGarbageCollected<MenuListInnerElement>(doc);
  inner_element_->setAttribute(html_names::kAriaHiddenAttr, keywords::kTrue);
  // Make sure InnerElement() always has a Text node.
  inner_element_->appendChild(Text::Create(doc, g_empty_string));
  root.AppendChild(inner_element_);

  // Even in MenuList mode, slotting <option>s is necessary to have
  // ComputedStyles for <option>s. LayoutFlexibleBox::IsChildAllowed() rejects
  // all of LayoutObject children except for MenuListInnerElement's.
  // This slot does not have anything slotted into it in the CustomizableSelect
  // mode because the UA popover containing all the <option>s is slotted in
  // instead.
  option_slot_ = MakeGarbageCollected<HTMLSlotElement>(doc);
  option_slot_->SetIdAttribute(shadow_element_names::kSelectOptions);
  root.appendChild(option_slot_);

  if (RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
    button_slot_ = MakeGarbageCollected<HTMLSlotElement>(doc);
    button_slot_->SetIdAttribute(shadow_element_names::kSelectButton);
    root.appendChild(button_slot_);

    popover_ = MakeGarbageCollected<PopoverElementForAppearanceBase>(doc);
    popover_->SetShadowPseudoId(shadow_element_names::kPickerSelect);
    popover_->setAttribute(html_names::kPopoverAttr, AtomicString("auto"));
    if (!RuntimeEnabledFeatures::PopoverAnchorRelationshipsEnabled()) {
      popover_->SetImplicitAnchor(select_);
    }
    root.appendChild(popover_);

    popover_options_slot_ = MakeGarbageCollected<HTMLSlotElement>(doc);
    popover_options_slot_->SetIdAttribute(
        shadow_element_names::kSelectPopoverOptions);
    popover_->AppendChild(popover_options_slot_);

    autofill_popover_ =
        MakeGarbageCollected<HTMLSelectElement::SelectAutofillPreviewElement>(
            doc, select_);
    autofill_popover_->setAttribute(html_names::kPopoverAttr,
                                    keywords::kManual);
    if (!RuntimeEnabledFeatures::PopoverAnchorRelationshipsEnabled()) {
      autofill_popover_->SetImplicitAnchor(select_);
    }
    autofill_popover_->SetShadowPseudoId(
        shadow_element_names::kSelectAutofillPreview);
    root.appendChild(autofill_popover_);

    autofill_popover_text_ = MakeGarbageCollected<HTMLDivElement>(doc);
    autofill_popover_text_->SetShadowPseudoId(
        shadow_element_names::kSelectAutofillPreviewText);
    autofill_popover_->appendChild(autofill_popover_text_);
  }
}

void MenuListSelectType::ManuallyAssignSlots() {
  VectorOf<Node> option_nodes;
  HTMLButtonElement* first_button = nullptr;
  VectorOf<Node> all_children_except_first_button;
  bool after_first_element = false;
  for (Node& child : NodeTraversal::ChildrenOf(*select_)) {
    if (!child.IsSlotable()) {
      continue;
    }
    if (!after_first_element) {
      if (IsA<Element>(child)) {
        after_first_element = true;
        first_button = DynamicTo<HTMLButtonElement>(child);
        if (first_button) {
          continue;
        }
      }
    }
    all_children_except_first_button.push_back(child);
    if (CanAssignToSelectSlot(child)) {
      option_nodes.push_back(child);
    }
  }

  CHECK(option_slot_);
  if (RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
    CHECK(button_slot_);
    button_slot_->Assign(first_button);
    // The IsInTopLayer check here is needed in order to support the case that a
    // top layer exit animation is running, in which case popoverOpen() will
    // return false but the popover is still being rendered.
    // TODO(crbug.com/1511354): It would be a good idea to invalidate slot
    // assignment after being removed from the top layer, but this is an edge
    // case which would require switching appearance values after the user has
    // opened the select.
    if (popover_->IsInTopLayer()) {
      popover_options_slot_->Assign(all_children_except_first_button);
      option_slot_->Assign(nullptr);
    } else {
      // When the popover is closed, we need to assign the <option>s into
      // option_slot_ in order to prevent the closed popover's display:none from
      // preventing computed style reaching the <option>s which is needed for
      // appearance:auto.
      popover_options_slot_->Assign(nullptr);
      option_slot_->Assign(option_nodes);
    }
  } else {
    option_slot_->Assign(option_nodes);
  }
}

HTMLButtonElement* MenuListSelectType::SlottedButton() const {
  if (!RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
    return nullptr;
  }
  // This code may be called while slot recalc is forbidden, so instead of
  // looking at button_slot_'s FirstAssignedNode, just return the
  // firstElementChild which will be the same thing.
  return DynamicTo<HTMLButtonElement>(select_->firstElementChild());
}

HTMLElement* MenuListSelectType::PopoverForAppearanceBase() const {
  // LayoutFlexibleBox::IsChildAllowed needs to access popover_ even when the
  // author doesn't put appearance:base-select on ::picker(select). In order to
  // return popover_ in this case, we check IsAppearanceBaseButton instead of
  // IsAppearanceBaseSelect.
  if (!IsAppearanceBaseButton()) {
    return nullptr;
  }
  return popover_;
}

bool MenuListSelectType::IsAppearanceBaseButton() const {
  if (!RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
    return false;
  }
  // TODO(crbug.com/364348901): Update style and layout here.
  DCHECK(select_);
  if (auto* style = select_->GetComputedStyle()) {
    return style->EffectiveAppearance() == ControlPart::kBaseSelectPart;
  }
  return false;
}

bool MenuListSelectType::IsAppearanceBasePicker() const {
  if (!IsAppearanceBaseButton()) {
    // The author is required to put appearance:base-select on the <select>
    // before the ::picker is allowed to have appearance:base-select.
    return false;
  }
  CHECK(RuntimeEnabledFeatures::CustomizableSelectEnabled());
  // TODO(crbug.com/364348901): Consider using EnsureComputedStyle() here to get
  // more reliable results, though it has the risk of causing more style
  // computation, sometimes at bad times.
  DCHECK(popover_);
  if (auto* style = popover_->GetComputedStyle()) {
    return style->EffectiveAppearance() == ControlPart::kBaseSelectPart;
  }
  return false;
}

HTMLSelectElement::SelectAutofillPreviewElement*
MenuListSelectType::GetAutofillPreviewElement() const {
  return autofill_popover_;
}

Element& MenuListSelectType::InnerElement() const {
  return *inner_element_;
}

void MenuListSelectType::ShowPopup(PopupMenu::ShowEventType type) {
  if (PopupIsVisible()) {
    return;
  }

  if (IsAppearanceBasePicker()) {
    popover_->ShowPopoverInternal(select_, /*exception_state=*/nullptr);
    return;
  }

  Document& document = select_->GetDocument();
  if (document.GetPage()->GetChromeClient().HasOpenedPopup())
    return;
  if (!select_->GetLayoutObject())
    return;

  gfx::Rect local_root_rect = select_->VisibleBoundsInLocalRoot();

  if (document.GetFrame()->LocalFrameRoot().IsOutermostMainFrame()) {
    gfx::Rect visual_viewport_rect =
        document.GetPage()->GetVisualViewport().RootFrameToViewport(
            local_root_rect);
    visual_viewport_rect.Intersect(
        gfx::Rect(document.GetPage()->GetVisualViewport().Size()));
    if (visual_viewport_rect.IsEmpty())
      return;
  } else {
    // TODO(bokan): If we're in a remote frame, we cannot access the active
    // visual viewport. VisibleBoundsInLocalRoot will clip to the outermost
    // main frame but if the user is pinch-zoomed this won't be accurate.
    // https://crbug.com/840944.
    if (local_root_rect.IsEmpty())
      return;
  }

  // SetNativePopupIsVisible(true) will start matching :open, and we need to run
  // a style update before we show the native popup because select:open rules in
  // the UA sheet need to remove display:none from the UA popover which may be
  // wrapping the <option>s.
  // We also need to update style before calling OpenPopupMenu in order to avoid
  // an expensive call to popup_->UpdateFromElement in DidRecalcStyle.
  if (RuntimeEnabledFeatures::SelectPopupLessUpdatesEnabled()) {
    SetNativePopupIsVisible(true);
    if (RuntimeEnabledFeatures::CSSPseudoOpenClosedEnabled()) {
      select_->GetDocument().UpdateStyleAndLayoutForNode(
          select_, DocumentUpdateReason::kPagePopup);
    }
  }

  if (!popup_) {
    popup_ = document.GetPage()->GetChromeClient().OpenPopupMenu(
        *document.GetFrame(), *select_);
  }
  if (!popup_) {
    if (RuntimeEnabledFeatures::SelectPopupLessUpdatesEnabled()) {
      SetNativePopupIsVisible(false);
    }
    return;
  }

  if (!RuntimeEnabledFeatures::SelectPopupLessUpdatesEnabled()) {
    SetNativePopupIsVisible(true);
    if (RuntimeEnabledFeatures::CSSPseudoOpenClosedEnabled()) {
      select_->GetDocument().UpdateStyleAndLayoutForNode(
          select_, DocumentUpdateReason::kPagePopup);
    }
  }

  ObserveTreeMutation();

  popup_->Show(type);
  if (AXObjectCache* cache = document.ExistingAXObjectCache())
    cache->DidShowMenuListPopup(select_);
}

void MenuListSelectType::HidePopup() {
  if (IsAppearanceBasePicker()) {
    popover_->HidePopoverInternal(
        HidePopoverFocusBehavior::kFocusPreviousElement,
        HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions,
        /*exception_state=*/nullptr);
    return;
  }
  if (popup_)
    popup_->Hide();
}

void MenuListSelectType::PopupDidHide() {
  SetNativePopupIsVisible(false);
  UnobserveTreeMutation();
  if (AXObjectCache* cache = select_->GetDocument().ExistingAXObjectCache()) {
    cache->DidHideMenuListPopup(select_);
  }
}

bool MenuListSelectType::PopupIsVisible() const {
  if (IsAppearanceBasePicker()) {
    return popover_->popoverOpen();
  } else {
    return native_popup_is_visible_;
  }
}

void MenuListSelectType::SetNativePopupIsVisible(bool popup_is_visible) {
  native_popup_is_visible_ = popup_is_visible;
  if (RuntimeEnabledFeatures::CSSPseudoOpenClosedEnabled()) {
    select_->PseudoStateChanged(CSSSelector::kPseudoOpen);
    select_->PseudoStateChanged(CSSSelector::kPseudoClosed);
  }
  if (auto* layout_object = select_->GetLayoutObject()) {
    // Invalidate paint to ensure that the focus ring is updated.
    layout_object->SetShouldDoFullPaintInvalidation();
  }
}

PopupMenu* MenuListSelectType::PopupForTesting() const {
  return popup_.Get();
}

AXObject* MenuListSelectType::PopupRootAXObject() const {
  return popup_ ? popup_->PopupRootAXObject() : nullptr;
}

void MenuListSelectType::ShowPicker() {
  // We need to make the layout tree up-to-date to have GetLayoutObject() give
  // the correct result below. An author event handler may have set display to
  // some element to none which will cause a layout tree detach.
  select_->GetDocument().UpdateStyleAndLayoutTree();
  // Save t
"""


```