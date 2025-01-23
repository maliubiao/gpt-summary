Response:
Let's break down the thought process for analyzing this C++ file. The request asks for a comprehensive overview of its functionality and its relationship to web technologies.

**1. Initial Understanding - What is this?**

The filename `radio_input_type.cc` and the `blink` namespace immediately suggest this is part of the Chromium rendering engine, specifically responsible for handling the `<input type="radio">` HTML element. The copyright notices reinforce this.

**2. Core Functionality - What does it *do*?**

The core purpose is to manage the behavior of radio buttons. This includes:

* **State Management:**  Keeping track of which radio button in a group is checked.
* **User Interaction:** Handling clicks, keyboard navigation (arrow keys, spacebar, enter), and focus.
* **Form Submission:**  Ensuring only one radio button in a group is submitted.
* **Accessibility:**  Making radio buttons navigable and understandable for users with disabilities.
* **Validation:**  Determining if a required radio button group has a selection.

**3. Deeper Dive - Examining the Code Structure**

The code is structured within the `blink` namespace and defines a class `RadioInputType` inheriting from `BaseCheckableInputType`. This inheritance suggests shared functionality with other checkable input types (like checkboxes).

Key methods and their purposes (as discovered through skimming and more focused reading):

* `CountUsage()`: Likely for internal Chromium metrics.
* `AutoAppearance()`: Determines the default rendering style.
* `ValueMissing()`:  Implements the HTML5 required attribute validation for radio buttons.
* `ValueMissingText()`: Provides the localized error message for missing values.
* `HandleClickEvent()`:  Handles click events (though it mostly defers to other logic).
* `FindNextFocusableRadioButtonInGroup()`:  Crucial for keyboard navigation within a radio group.
* `HandleKeydownEvent()`:  Handles arrow key navigation to select the next/previous radio button.
* `HandleKeyupEvent()`: Handles Spacebar and Enter key presses for selecting a radio button.
* `IsKeyboardFocusable()`: Determines if a radio button can receive focus via Tab. This has important logic to prevent tabbing *between* radio buttons in the same group unless the current group has no selection.
* `ShouldSendChangeEventAfterCheckedChanged()`: Determines if a 'change' event should be fired.
* `WillDispatchClick()`:  Prepares the state before a click is processed, handling the checking of the radio button.
* `DidDispatchClick()`:  Handles the aftermath of a click, including potentially reverting the selection if the default action was prevented.
* `ShouldAppearIndeterminate()`:  Determines if the radio button should have an indeterminate state (not used for standard radio buttons).
* `NextRadioButtonInGroup()`:  A helper function to find the next or previous radio button in the group.
* `CheckedRadioButtonForGroup()`: Returns the currently checked radio button in the group.
* `WillUpdateCheckedness()`: Called before the checked state changes, allowing for logic like unchecking other radios in the group.

**4. Relationship to Web Technologies (HTML, CSS, JavaScript)**

This is where the "connecting the dots" happens.

* **HTML:** The code directly implements the behavior of the `<input type="radio">` element defined in HTML. The `name` attribute is key for grouping radio buttons. The `required` attribute is also handled.
* **CSS:** The `AutoAppearance()` method returns `kRadioPart`, which likely ties into the default styling of radio buttons. While this C++ code doesn't directly manipulate CSS, it informs the rendering engine how to style the element by default.
* **JavaScript:**  JavaScript can interact with radio buttons by:
    * Setting and getting the `checked` property.
    * Handling `click` and `change` events.
    * Using `focus()` to programmatically focus on a radio button.
    * Querying the DOM to find the checked radio button. The C++ code ensures these JavaScript interactions behave correctly.

**5. Logic and Reasoning (Hypothetical Inputs and Outputs)**

Consider the `HandleKeydownEvent()` function.

* **Input:** A `KeyboardEvent` with `key` = "ArrowDown" while a radio button is focused.
* **Assumption:** There are other radio buttons in the same group that are focusable.
* **Output:** The focus will shift to the next focusable radio button in the group, and that radio button will be selected (simulated click).

**6. Common User/Programming Errors**

* **Missing `name` attribute:** Radio buttons without the same `name` are not part of the same group.
* **Incorrect `form` association:**  Radio buttons belonging to different forms are treated as separate groups.
* **JavaScript `preventDefault()`:**  Understanding how `preventDefault()` in JavaScript event handlers can interact with the default behavior implemented in this C++ code is important.

**7. User Operations Leading to this Code**

Think about the user experience:

1. **Page Load:**  The browser parses the HTML and creates the DOM, including `HTMLInputElement` objects with `type="radio"`.
2. **Rendering:** The layout engine uses the `AutoAppearance()` information to render the radio buttons visually.
3. **Clicking:** A user clicks on a radio button. This triggers a `click` event that eventually reaches `RadioInputType::HandleClickEvent()`.
4. **Keyboard Navigation:** A user presses the Tab key to focus on a radio button group, or uses arrow keys to navigate within the group, triggering `RadioInputType::HandleKeydownEvent()`.
5. **Form Submission:** When a form is submitted, the browser uses the information managed by this code to determine which radio button is checked and its value.

**8. Refinement and Organization**

After the initial analysis, organize the findings into clear categories as demonstrated in the final answer. Use bullet points and clear language to make the information easily digestible. Highlight the connections to HTML, CSS, and JavaScript with concrete examples.

This systematic approach allows for a thorough understanding of the C++ code's role in the broader context of a web browser.
This C++ source code file, `radio_input_type.cc`, within the Chromium Blink rendering engine, is specifically responsible for handling the behavior and functionality of **`<input type="radio">` elements** in HTML. It defines the class `RadioInputType`, which inherits from `BaseCheckableInputType`, indicating it shares common functionality with other checkable input types like checkboxes.

Here's a breakdown of its functionalities and connections:

**Core Functionalities:**

1. **Determining the visual appearance:**
   - `AutoAppearance()`: Returns `kRadioPart`, which dictates the default visual appearance of a radio button. This is linked to the browser's internal styling for form controls.

2. **Implementing the "one selection in a group" behavior:**
   -  A core function is ensuring that within a group of radio buttons (sharing the same `name` attribute), only one can be selected at any given time. This code manages the logic for unchecking other radio buttons in the same group when one is selected.
   - `CheckedRadioButtonForGroup()`:  Finds and returns the currently checked radio button within the same group as the current element.
   - `WillUpdateCheckedness(bool new_checked)`: This method is called before the checked state of the radio button changes. If the button is being checked (`new_checked` is true), it ensures that any other radio button in the same group is unchecked.

3. **Handling user interaction (clicks and keyboard events):**
   - `HandleClickEvent(MouseEvent& event)`:  While currently it just sets the event as default handled, this is a point where specific click behavior could be implemented. The core selection logic happens in `WillDispatchClick` and `DidDispatchClick`.
   - `HandleKeydownEvent(KeyboardEvent& event)`:  Implements keyboard navigation within a radio button group using arrow keys (Up, Down, Left, Right). It moves focus to the next or previous focusable radio button in the group and selects it (simulating a click). It respects text direction (LTR/RTL).
   - `HandleKeyupEvent(KeyboardEvent& event)`:  Handles the Spacebar and Enter key presses. Pressing Space on an unchecked radio button will check it. If Spatial Navigation is enabled, Enter also triggers a click.

4. **Managing focus and tab navigation:**
   - `IsKeyboardFocusable(Element::UpdateBehavior update_behavior) const`: Determines if a radio button is focusable via the Tab key. It has specific logic to prevent tabbing *between* radio buttons in the same group unless the current group has no selection. This improves usability by ensuring users don't get stuck within a radio group.
   - `FindNextFocusableRadioButtonInGroup(HTMLInputElement* current_element, bool forward)`:  Used by keyboard navigation to find the next focusable radio button in the group.

5. **Implementing form validation:**
   - `ValueMissing(const String&) const`: Determines if the radio button group violates the `required` attribute. If a radio button group has the `required` attribute, and none of the buttons in the group are checked, this method returns `true`. It considers both radio buttons within the same form and those outside any form but within the same document tree with the same name.
   - `ValueMissingText() const`: Returns the localized error message to display when a required radio button group has no selection.

6. **Handling the "change" event:**
   - `ShouldSendChangeEventAfterCheckedChanged()`: Determines whether a `change` event should be dispatched after the checked state of the radio button changes. Specifically, it returns `true` only when a radio button is being *checked*, not when it's being unchecked. This matches the behavior of other browsers.

7. **Supporting Spatial Navigation:**
   - The code includes checks for `IsSpatialNavigationEnabled()`. Spatial Navigation allows users to navigate between elements on a page using directional keys, even if they are not sequentially ordered in the DOM. The logic adjusts keyboard navigation and focus behavior when this feature is enabled.

8. **Handling the click lifecycle (important for event bubbling and `preventDefault()`):**
   - `WillDispatchClick()`: This is called *before* the click event is dispatched to JavaScript. It checks the current state and sets the radio button as checked. It also stores the previous checked state and the previously checked radio button in the group.
   - `DidDispatchClick(Event& event, const ClickHandlingState& state)`: This is called *after* the click event has been dispatched. It checks if `event.defaultPrevented()` was called in JavaScript. If so, it reverts the changes made in `WillDispatchClick` to maintain consistency. If not, and the checked state has changed, it dispatches the necessary `input` and `change` events.

9. **Determining the indeterminate state:**
   - `ShouldAppearIndeterminate() const`:  While not directly applicable to standard radio buttons (they are either checked or unchecked), this method is part of the interface and returns `false` because radio buttons don't have a standard indeterminate state. However, this might be used for custom implementations or future extensions.

**Relationship to JavaScript, HTML, and CSS:**

* **HTML:** This C++ code directly implements the behavior defined for the `<input type="radio">` element in HTML specifications. It interprets attributes like `name` (for grouping) and `required` (for validation).

   * **Example:** When the HTML contains `<input type="radio" name="gender" value="male">` and `<input type="radio" name="gender" value="female">`, this code ensures that selecting one will deselect the other.

* **JavaScript:** JavaScript interacts with radio buttons through:
    * **Setting and getting the `checked` property:**  JavaScript can directly manipulate the `checked` state. This C++ code ensures that when JavaScript sets `checked = true` on one radio button, others in the group are unchecked.
    * **Handling `click` and `change` events:**  The C++ code dispatches these events based on user interactions. JavaScript can listen for these events to perform actions.
    * **Using `focus()`:** JavaScript can programmatically focus on a radio button. The `IsKeyboardFocusable()` logic influences whether a radio button can receive focus.
    * **Form submission:** When a form is submitted, the browser uses the state managed by this code to determine which radio button's value should be included in the submitted data.

   * **Example:**  A JavaScript function might listen for the `change` event on a radio button group to update a displayed summary based on the selected option.

* **CSS:** While this C++ code doesn't directly manipulate CSS, it informs the rendering engine about the type of element (`kRadioPart`). This allows the browser's stylesheet (or custom CSS) to apply the appropriate visual styling for radio buttons.

   * **Example:** The default circular appearance of a radio button is determined by the browser's internal styling, which is associated with the `kRadioPart` identified here.

**Logical Reasoning (Hypothetical Input and Output):**

**Scenario:** A user navigates through a form using the Tab key and reaches an unchecked radio button in a group where no other button is currently checked.

* **Input:**  The `IsKeyboardFocusable()` method is called.
* **Assumption:** No other radio button in the group is currently checked.
* **Output:** `IsKeyboardFocusable()` returns `true`, allowing the radio button to receive focus.

**Scenario:** A user presses the Down Arrow key while a radio button in a group is focused.

* **Input:** `HandleKeydownEvent()` receives a `KeyboardEvent` with `key` set to "ArrowDown".
* **Assumption:** There is another focusable radio button in the same group below the currently focused one in the DOM order.
* **Output:**
    1. `FindNextFocusableRadioButtonInGroup()` finds the next focusable radio button.
    2. `SetFocusedElement()` is called to move focus to the next radio button.
    3. `DispatchSimulatedClick()` is called on the newly focused radio button, causing it to become checked and unchecking the previously selected one (if any).
    4. The `change` event will be fired if the checked state changed.
    5. `event.SetDefaultHandled()` is called to prevent the browser's default behavior for arrow keys.

**User or Programming Common Usage Errors:**

1. **Forgetting the `name` attribute:** If radio buttons don't share the same `name` attribute, they won't behave as a group, and multiple can be selected. This is a common HTML mistake.

   ```html
   <!-- Incorrect: Missing name attribute -->
   <input type="radio" value="option1"> Option 1<br>
   <input type="radio" value="option2"> Option 2<br>

   <!-- Correct: Same name attribute -->
   <input type="radio" name="choice" value="option1"> Option 1<br>
   <input type="radio" name="choice" value="option2"> Option 2<br>
   ```

2. **Incorrectly associating radio buttons with forms:**  While less common, if radio buttons with the same `name` are in different forms, they will act as separate groups. The `form` attribute can explicitly associate a radio button with a form even if it's not nested within it. Misusing this can lead to unexpected behavior.

3. **JavaScript errors preventing default behavior:** If JavaScript code attached to the `click` or `change` event calls `event.preventDefault()`, it can interfere with the default behavior implemented in this C++ code, potentially leading to situations where no radio button is selected in a group.

**User Operations to Reach This Code:**

1. **Loading a web page:** When a user loads a web page containing `<input type="radio">` elements, the browser's HTML parser creates the corresponding `HTMLInputElement` objects, and the `RadioInputType` class is associated with them.

2. **Clicking a radio button:** When a user clicks on a radio button:
   - The browser's event system captures the click.
   - The event is dispatched to the relevant `HTMLInputElement`.
   - The `HandleClickEvent()` method (though currently minimal) is called.
   - `WillDispatchClick()` is executed to prepare the state.
   - JavaScript event listeners for the `click` event are executed.
   - `DidDispatchClick()` is executed to finalize the changes, potentially reverting if `preventDefault()` was called.
   - If the checked state changed, a `change` event is fired.

3. **Using the Tab key to navigate:** When a user presses the Tab key, the browser determines the next focusable element. The `IsKeyboardFocusable()` method of `RadioInputType` is consulted to decide if a radio button should receive focus.

4. **Using arrow keys while a radio button is focused:** When a user has focus on a radio button and presses an arrow key:
   - The `HandleKeydownEvent()` method is invoked.
   - The logic within this method determines the next focusable radio button in the group.
   - Focus is moved, and the new radio button is selected.

5. **Submitting a form:** When a user submits a form containing radio buttons, the browser iterates through the form elements. For radio buttons, it uses the `Checked()` state (managed by this C++ code) to determine which radio button's value (if any) should be included in the form data.

In essence, this C++ file is a crucial part of the Chromium rendering engine responsible for ensuring the correct and expected behavior of HTML radio buttons, bridging the gap between the HTML markup and the user's interactions.

### 提示词
```
这是目录为blink/renderer/core/html/forms/radio_input_type.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
```

### 源代码
```cpp
/*
 * Copyright (C) 2005, 2011 Apple Inc. All rights reserved.
 * Copyright (C) 2010 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/html/forms/radio_input_type.h"

#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/page/spatial_navigation.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"

namespace blink {

using mojom::blink::FormControlType;

namespace {

HTMLInputElement* NextInputElement(const HTMLInputElement& element,
                                   const HTMLFormElement* stay_within,
                                   bool forward) {
  return forward ? Traversal<HTMLInputElement>::Next(element, stay_within)
                 : Traversal<HTMLInputElement>::Previous(element, stay_within);
}

}  // namespace

void RadioInputType::CountUsage() {
  CountUsageIfVisible(WebFeature::kInputTypeRadio);
}

ControlPart RadioInputType::AutoAppearance() const {
  return kRadioPart;
}

bool RadioInputType::ValueMissing(const String&) const {
  HTMLInputElement& input = GetElement();
  if (auto* scope = input.GetRadioButtonGroupScope())
    return scope->IsInRequiredGroup(&input) && !CheckedRadioButtonForGroup();

  // This element is not managed by a RadioButtonGroupScope. We need to traverse
  // the tree from TreeRoot.
  DCHECK(!input.isConnected());
  DCHECK(!input.formOwner());
  const AtomicString& name = input.GetName();
  if (name.empty())
    return false;
  bool is_required = false;
  bool is_checked = false;
  Node& root = input.TreeRoot();
  for (auto* another = Traversal<HTMLInputElement>::InclusiveFirstWithin(root);
       another; another = Traversal<HTMLInputElement>::Next(*another, &root)) {
    if (another->FormControlType() != FormControlType::kInputRadio ||
        another->GetName() != name || another->formOwner()) {
      continue;
    }
    if (another->Checked())
      is_checked = true;
    if (another->FastHasAttribute(html_names::kRequiredAttr))
      is_required = true;
    if (is_checked && is_required)
      return false;
  }
  return is_required && !is_checked;
}

String RadioInputType::ValueMissingText() const {
  return GetLocale().QueryString(IDS_FORM_VALIDATION_VALUE_MISSING_RADIO);
}

void RadioInputType::HandleClickEvent(MouseEvent& event) {
  event.SetDefaultHandled();
}

HTMLInputElement* RadioInputType::FindNextFocusableRadioButtonInGroup(
    HTMLInputElement* current_element,
    bool forward) {
  for (HTMLInputElement* input_element =
           NextRadioButtonInGroup(current_element, forward);
       input_element;
       input_element = NextRadioButtonInGroup(input_element, forward)) {
    if (input_element->IsFocusable())
      return input_element;
  }
  return nullptr;
}

void RadioInputType::HandleKeydownEvent(KeyboardEvent& event) {
  // TODO(tkent): We should return more earlier.
  if (!GetElement().GetLayoutObject())
    return;
  BaseCheckableInputType::HandleKeydownEvent(event);
  if (event.DefaultHandled())
    return;
  const AtomicString key(event.key());
  if (key != keywords::kArrowUp && key != keywords::kArrowDown &&
      key != keywords::kArrowLeft && key != keywords::kArrowRight) {
    return;
  }

  if (event.ctrlKey() || event.metaKey() || event.altKey())
    return;

  // Left and up mean "previous radio button".
  // Right and down mean "next radio button".
  // Tested in WinIE, and even for RTL, left still means previous radio button
  // (and so moves to the right). Seems strange, but we'll match it. However,
  // when using Spatial Navigation, we need to be able to navigate without
  // changing the selection.
  Document& document = GetElement().GetDocument();
  if (IsSpatialNavigationEnabled(document.GetFrame()))
    return;
  bool forward =
      ComputedTextDirection() == TextDirection::kRtl
          ? (key == keywords::kArrowDown || key == keywords::kArrowLeft)
          : (key == keywords::kArrowDown || key == keywords::kArrowRight);

  // Force layout for isFocusable() in findNextFocusableRadioButtonInGroup().
  document.UpdateStyleAndLayout(DocumentUpdateReason::kInput);

  // We can only stay within the form's children if the form hasn't been demoted
  // to a leaf because of malformed HTML.
  HTMLInputElement* input_element =
      FindNextFocusableRadioButtonInGroup(&GetElement(), forward);
  if (!input_element) {
    // Traverse in reverse direction till last or first radio button
    forward = !(forward);
    HTMLInputElement* next_input_element =
        FindNextFocusableRadioButtonInGroup(&GetElement(), forward);
    while (next_input_element) {
      input_element = next_input_element;
      next_input_element =
          FindNextFocusableRadioButtonInGroup(next_input_element, forward);
    }
  }
  if (input_element) {
    document.SetFocusedElement(
        input_element, FocusParams(SelectionBehaviorOnFocus::kRestore,
                                   mojom::blink::FocusType::kNone, nullptr));
    input_element->DispatchSimulatedClick(&event);
    event.SetDefaultHandled();
    return;
  }
}

void RadioInputType::HandleKeyupEvent(KeyboardEvent& event) {
  // Use Space key simulated click by default.
  // Use Enter key simulated click when Spatial Navigation enabled.
  if (event.key() == " " ||
      (IsSpatialNavigationEnabled(GetElement().GetDocument().GetFrame()) &&
       event.key() == keywords::kCapitalEnter)) {
    // If an unselected radio is tabbed into (because the entire group has
    // nothing checked, or because of some explicit .focus() call), then allow
    // space to check it.
    if (GetElement().Checked()) {
      // If we are going to skip DispatchSimulatedClick, then at least call
      // SetActive(false) to prevent the radio from being stuck in the active
      // state.
      GetElement().SetActive(false);
    } else {
      DispatchSimulatedClickIfActive(event);
    }
  }
}

bool RadioInputType::IsKeyboardFocusable(
    Element::UpdateBehavior update_behavior) const {
  if (!InputType::IsKeyboardFocusable(update_behavior)) {
    return false;
  }

  // When using Spatial Navigation, every radio button should be focusable.
  if (IsSpatialNavigationEnabled(GetElement().GetDocument().GetFrame()))
    return true;

  // Never allow keyboard tabbing to leave you in the same radio group. Always
  // skip any other elements in the group.
  Element* current_focused_element =
      GetElement().GetDocument().FocusedElement();
  if (auto* focused_input =
          DynamicTo<HTMLInputElement>(current_focused_element)) {
    if (focused_input->FormControlType() == FormControlType::kInputRadio &&
        focused_input->GetTreeScope() == GetElement().GetTreeScope() &&
        focused_input->Form() == GetElement().Form() &&
        focused_input->GetName() == GetElement().GetName()) {
      return false;
    }
  }

  // Allow keyboard focus if we're checked or if nothing in the group is
  // checked.
  return GetElement().Checked() || !CheckedRadioButtonForGroup();
}

bool RadioInputType::ShouldSendChangeEventAfterCheckedChanged() {
  // Don't send a change event for a radio button that's getting unchecked.
  // This was done to match the behavior of other browsers.
  return GetElement().Checked();
}

ClickHandlingState* RadioInputType::WillDispatchClick() {
  // An event handler can use preventDefault or "return false" to reverse the
  // selection we do here.  The ClickHandlingState object contains what we need
  // to undo what we did here in didDispatchClick.

  // We want radio groups to end up in sane states, i.e., to have something
  // checked.  Therefore if nothing is currently selected, we won't allow the
  // upcoming action to be "undone", since we want some object in the radio
  // group to actually get selected.

  ClickHandlingState* state = MakeGarbageCollected<ClickHandlingState>();

  state->checked = GetElement().Checked();
  state->checked_radio_button = CheckedRadioButtonForGroup();
  GetElement().SetChecked(true, TextFieldEventBehavior::kDispatchChangeEvent);
  is_in_click_handler_ = true;
  return state;
}

void RadioInputType::DidDispatchClick(Event& event,
                                      const ClickHandlingState& state) {
  if (event.defaultPrevented() || event.DefaultHandled()) {
    // Restore the original selected radio button if possible.
    // Make sure it is still a radio button and only do the restoration if it
    // still belongs to our group.
    HTMLInputElement* checked_radio_button = state.checked_radio_button.Get();
    if (!checked_radio_button) {
      GetElement().SetChecked(false);
    } else if (checked_radio_button->FormControlType() ==
                   FormControlType::kInputRadio &&
               checked_radio_button->Form() == GetElement().Form() &&
               checked_radio_button->GetName() == GetElement().GetName()) {
      checked_radio_button->SetChecked(true);
    }
  } else if (state.checked != GetElement().Checked()) {
    GetElement().DispatchInputAndChangeEventIfNeeded();
  }
  is_in_click_handler_ = false;
  // The work we did in willDispatchClick was default handling.
  event.SetDefaultHandled();
}

bool RadioInputType::ShouldAppearIndeterminate() const {
  return !CheckedRadioButtonForGroup();
}

HTMLInputElement* RadioInputType::NextRadioButtonInGroup(
    HTMLInputElement* current,
    bool forward) {
  // TODO(https://crbug.com/323953913): Staying within form() is
  // incorrect.  This code ignore input elements associated by |form|
  // content attribute.
  // TODO(tkent): Comparing name() with == is incorrect.  It should be
  // case-insensitive.
  for (HTMLInputElement* input_element =
           NextInputElement(*current, current->Form(), forward);
       input_element; input_element = NextInputElement(
                          *input_element, current->Form(), forward)) {
    if (current->Form() == input_element->Form() &&
        input_element->GetTreeScope() == current->GetTreeScope() &&
        input_element->FormControlType() == FormControlType::kInputRadio &&
        input_element->GetName() == current->GetName()) {
      return input_element;
    }
  }
  return nullptr;
}

HTMLInputElement* RadioInputType::CheckedRadioButtonForGroup() const {
  HTMLInputElement& input = GetElement();
  if (input.Checked())
    return &input;
  if (auto* scope = input.GetRadioButtonGroupScope())
    return scope->CheckedButtonForGroup(input.GetName());

  // This element is not managed by a RadioButtonGroupScope. We need to traverse
  // the tree from TreeRoot.
  DCHECK(!input.isConnected());
  DCHECK(!input.formOwner());
  const AtomicString& name = input.GetName();
  if (name.empty())
    return nullptr;
  Node& root = input.TreeRoot();
  for (auto* another = Traversal<HTMLInputElement>::InclusiveFirstWithin(root);
       another; another = Traversal<HTMLInputElement>::Next(*another, &root)) {
    if (another->FormControlType() != FormControlType::kInputRadio ||
        another->GetName() != name || another->formOwner()) {
      continue;
    }
    if (another->Checked())
      return another;
  }
  return nullptr;
}

void RadioInputType::WillUpdateCheckedness(bool new_checked) {
  if (!new_checked)
    return;
  if (GetElement().GetRadioButtonGroupScope()) {
    // Buttons in RadioButtonGroupScope are handled in
    // HTMLInputElement::SetChecked().
    return;
  }
  if (auto* input = CheckedRadioButtonForGroup())
    input->SetChecked(false);
}

}  // namespace blink
```