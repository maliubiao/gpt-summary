Response:
Let's break down the thought process for analyzing the provided `HTMLLabelElement` source code.

1. **Understanding the Goal:** The request asks for the functionality of this specific C++ file within the Chromium Blink rendering engine. It also wants to understand its relationship to web technologies (HTML, CSS, JavaScript), common errors, user interaction, and logical reasoning within the code.

2. **Initial Code Scan (High-Level):** I'll quickly scan the `#include` statements and the class definition (`HTMLLabelElement`). This gives me immediate clues:
    * **`#include`s:**  Keywords like "forms," "html," "dom," "events," "editing," "layout," and "input" strongly suggest this file is involved in handling the behavior of `<label>` elements within a web page. The presence of `mojom/input/focus_type.mojom-blink.h` indicates interaction with the input system.
    * **`HTMLLabelElement`:**  This confirms the file's core purpose. The inheritance from `HTMLElement` is also important, meaning it's a specific type of HTML element.

3. **Function-by-Function Analysis (Detailed):** Now, I'll go through each method within the `HTMLLabelElement` class and try to understand its purpose.

    * **`HTMLLabelElement(Document& document)`:**  Constructor. Sets up the basic `HTMLLabelElement` object, linking it to a specific document.
    * **`controlForBinding()`:**  This method is crucial. The comments and the logic around `FastGetAttribute(html_names::kForAttr)` and iterating through descendants strongly suggest it's responsible for finding the *associated* control element (like an `<input>`, `<select>`, etc.) that the `<label>` is linked to. The "binding" in the name suggests it's for internal use, perhaps different from the direct interaction logic. The special handling for elements *within* the label when `for` is absent is important to note. The `UseCounter` calls point to tracking usage of this feature.
    * **`Control()`:**  This seems like the public interface for getting the associated control. The check for `GetShadowReferenceTarget` implies handling of Shadow DOM, a more advanced web technology.
    * **`form()`:**  Straightforward. Returns the form that the associated control belongs to. Handles both standard form controls and custom form elements.
    * **`SetActive(bool active)` and `SetHovered(bool hovered)`:** These methods manage the active and hovered states of the label and, importantly, propagate these states to the associated control. This explains how labels visually interact with their controls.
    * **`IsInteractiveContent()` and `IsInInteractiveContent(Node* node)`:** These are likely related to event handling and determining if an element or its descendants can trigger interactive behavior. The shadow DOM considerations are again present.
    * **`DefaultEventHandler(Event& evt)` and `DefaultEventHandlerInternal(Event& evt)`:**  This is the heart of the label's behavior. It handles events, particularly `click` events. The logic to find the control, check if the click target is within the control, and the detailed handling of selection and focus are key. The `processing_click_` flag suggests preventing recursive calls.
    * **`HasActivationBehavior()`:**  Indicates the label can be "activated" (like being clicked).
    * **`WillRespondToMouseClickEvents()`:**  Determines if the label will handle mouse clicks, often delegating to the control.
    * **`Focus(const FocusParams& params)`:**  Handles focusing the label. If the label itself isn't focusable, it focuses the associated control. The special handling of access keys is noted.
    * **`AccessKeyAction(SimulatedClickCreationScope creation_scope)`:**  Handles activation when an access key is pressed, again often delegating to the control.

4. **Relating to Web Technologies:** Now, I connect the C++ code to HTML, CSS, and JavaScript:

    * **HTML:** The entire file is about the `<label>` element, a fundamental HTML form element. The `for` attribute is directly handled. The concept of associated controls (`<input>`, `<select>`, etc.) is HTML-specific.
    * **CSS:** The `SetActive` and `SetHovered` methods directly relate to CSS pseudo-classes like `:active` and `:hover`. When the label's state changes, this can trigger CSS style updates on both the label and its associated control.
    * **JavaScript:** The `controlForBinding()` method is specifically mentioned as being used for JavaScript binding. This means JavaScript can access the associated control element through the label, allowing for dynamic manipulation and event handling.

5. **Logical Reasoning (Assumptions and Outputs):**  For each complex method (especially `controlForBinding` and `DefaultEventHandler`), I'll consider:

    * **Assumptions:** What are the preconditions for the code to work as intended? (e.g., the HTML structure is valid, the label has a valid `for` attribute or contains a labelable element).
    * **Inputs:** What data does the method receive? (e.g., the `click` event object, the `FocusParams` object, the label's attributes).
    * **Outputs:** What does the method produce or do? (e.g., return the associated control, trigger a click on the control, set focus).

6. **Common Errors and User Interaction:**

    * **Common Errors:** I think about how developers might misuse the `<label>` element. Examples:  Incorrect or missing `for` attributes, nested interactive elements causing unexpected behavior, relying on label clicks when JavaScript events are also involved.
    * **User Interaction:** I trace the steps a user takes that might lead to this code being executed. Simple clicks on labels are the primary trigger. Access key usage is another path. Even just hovering over a label can trigger code in this file.

7. **Structuring the Output:** Finally, I organize the information clearly, using headings and bullet points. I provide code examples where necessary to illustrate the concepts. I make sure to connect the C++ code back to the user's web experience. I try to anticipate what a developer reading this analysis would want to know.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file just finds the associated control."  **Correction:** While finding the control is central, the event handling, especially the click behavior and focus management, is equally important.
* **Realization:** The `processing_click_` flag is a defensive mechanism to prevent infinite loops or double-processing of clicks. This highlights the complexity of event handling.
* **Emphasis:**  The interaction with Shadow DOM is a key detail that needs to be highlighted, as it affects how the associated control is found.
* **Clarity:** Ensure the distinction between `controlForBinding()` (for internal/JS use) and `Control()` (the potentially Shadow DOM-aware version) is clear.

By following these steps, combining code analysis with an understanding of web technologies and user behavior, I can generate a comprehensive explanation of the `HTMLLabelElement` functionality.
这个文件 `blink/renderer/core/html/forms/html_label_element.cc` 是 Chromium Blink 引擎中负责处理 HTML `<label>` 元素的核心代码。它的主要功能是：

**核心功能：关联 Label 与可标注控件**

`<label>` 元素的主要目的是为其关联的表单控件（例如 `<input>`, `<select>`, `<textarea>` 等）提供一个描述性的标签。这个 C++ 文件实现了将 `<label>` 元素与对应的控件关联起来的逻辑，并处理用户与 `<label>` 交互时触发的行为。

**具体功能分解：**

1. **查找关联控件 (`Control()`, `controlForBinding()`):**
   -  **通过 `for` 属性:**  `<label>` 元素通常使用 `for` 属性来指定它关联的表单控件的 `id`。代码会查找 `id` 与 `for` 属性值匹配的元素。
   -  **作为后代元素:** 如果没有 `for` 属性，代码会查找 `<label>` 元素内部的第一个可标注的后代元素。
   -  `controlForBinding()` 方法主要用于 JavaScript 绑定，它返回未解析引用目标的控件，以避免向 JS 暴露 Shadow DOM 内容。
   -  `Control()` 方法是获取关联控件的公共接口，它会考虑 Shadow DOM 的引用目标。

2. **状态同步 (`SetActive()`, `SetHovered()`):**
   -  当 `<label>` 元素的状态（例如是否被激活、是否被鼠标悬停）发生变化时，这些方法会将这些状态同步到关联的控件。这确保了用户与标签的交互能直观地反映在相关的表单控件上。

3. **处理点击事件 (`DefaultEventHandlerInternal()`):**
   -  这是该文件最核心的功能之一。当用户点击 `<label>` 元素时，该方法会执行以下操作：
     - **查找关联控件:** 确定要操作的控件。
     - **检查点击目标:**  确保点击事件不是发生在关联控件本身或其内部的交互内容上，以避免重复触发事件。
     - **处理文本选区:**  如果用户通过拖动鼠标在标签的文本上进行了选择，则根据情况决定是否将点击事件传递给控件。例如，如果是单击拖动选择，则不传递；如果是双击或多击，则传递。
     - **聚焦控件:** 如果关联控件是可聚焦的，且点击不是发生在标签的文本选区上，则将焦点设置到该控件上。
     - **模拟点击控件:**  最重要的步骤，它会模拟在关联控件上发生了一次点击事件。这使得点击 `<label>` 元素就像直接点击了对应的表单控件一样。

4. **处理焦点 (`Focus()`):**
   -  当 `<label>` 元素自身获得焦点时（通常是通过 Tab 键导航），如果该标签没有定义自己的焦点行为，则会将焦点传递给关联的控件。
   -  特殊处理了通过访问键（accesskey）触发焦点的情况。

5. **处理访问键 (`AccessKeyAction()`):**
   -  当用户按下与 `<label>` 元素的访问键关联的按键时，会触发此方法。它会模拟点击关联的控件，从而激活该控件。

6. **判断交互行为 (`IsInteractiveContent()`, `IsInInteractiveContent()`):**
   -  用于判断 `<label>` 元素自身是否是交互内容，以及给定的节点是否是 `<label>` 元素内的交互内容。这在处理事件时用于判断是否应该将点击事件传递给关联的控件。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    -  `<label>` 元素本身就是 HTML 的一部分。
    -  `for` 属性是 HTML 中定义 `<label>` 与表单控件关联的标准方式。
    -  `<input>`, `<select>`, `<textarea>` 等表单控件是 `<label>` 元素关联的目标。
    -  **例子:**
       ```html
       <label for="username">用户名：</label>
       <input type="text" id="username">
       ```
       在这个例子中，`html_label_element.cc` 的代码会解析 `for="username"`，找到 `id="username"` 的 `<input>` 元素，并将它们关联起来。点击 "用户名：" 这个标签，就会像点击输入框一样，将焦点移到输入框。

* **CSS:**
    -  CSS 可以用来样式化 `<label>` 元素，例如改变其颜色、字体、背景等。
    -  `:hover` 和 `:focus` 等 CSS 伪类可以用于在鼠标悬停或标签获得焦点时改变其样式。
    -  由于 `SetActive()` 和 `SetHovered()` 方法会将状态同步到关联的控件，因此可以通过 CSS 影响关联控件的样式。
    -  **例子:**
       ```css
       label:hover {
           color: blue;
           cursor: pointer;
       }

       input:focus + label { /*  + 选择器选择紧跟 input 元素的 label (不常用) */
           font-weight: bold;
       }
       ```
       虽然 CSS 不直接与 `html_label_element.cc` 交互，但该文件同步的状态变化会影响 CSS 样式的应用。

* **JavaScript:**
    -  JavaScript 可以通过 DOM API 获取 `<label>` 元素及其关联的控件。
    -  可以使用 JavaScript 监听 `<label>` 元素的事件，例如 `click` 事件。
    -  `controlForBinding()` 方法的存在就是为了方便 JavaScript 获取关联的控件。
    -  **例子:**
       ```javascript
       const label = document.querySelector('label[for="username"]');
       const input = document.getElementById('username');

       label.addEventListener('click', () => {
           console.log('Label clicked!');
       });

       console.log(label.control); // 通过 label 元素的 control 属性可以获取关联的 input 元素
       ```
       JavaScript 可以通过 `label.control` 属性（由 `controlForBinding()` 实现）直接访问关联的输入框。

**逻辑推理的假设输入与输出:**

**假设输入 1:**

* HTML:
  ```html
  <label for="myInput">点击我</label>
  <input type="checkbox" id="myInput">
  ```
* 用户操作: 点击 "点击我" 这个标签。

**输出 1:**

* `DefaultEventHandlerInternal()` 方法被调用。
* 代码找到 `id="myInput"` 的复选框元素。
* 代码判断点击目标不是复选框本身。
* 代码模拟在复选框上发生了一次点击事件，导致复选框的状态切换（选中或取消选中）。
* 如果复选框是可聚焦的，焦点会被设置到复选框上。

**假设输入 2:**

* HTML:
  ```html
  <label>
      <span>这是标签文字</span>
      <input type="radio" name="group1"> 选项一
  </label>
  ```
* 用户操作: 点击 "这是标签文字"。

**输出 2:**

* `DefaultEventHandlerInternal()` 方法被调用。
* 因为没有 `for` 属性，代码会找到 `<label>` 内部的第一个可标注元素，即 `<input type="radio">`。
* 代码判断点击目标不是单选按钮本身。
* 代码模拟在单选按钮上发生了一次点击事件，导致该单选按钮被选中。
* 如果单选按钮是可聚焦的，焦点会被设置到单选按钮上。

**用户或编程常见的使用错误:**

1. **`for` 属性值错误或缺失:**
   - **错误:**  `<label for="wrongId">...</label> <input type="text" id="correctId">`
   - **后果:**  点击标签不会聚焦或激活对应的输入框。
   - **`html_label_element.cc` 的行为:** `Control()` 方法会返回 `nullptr`，点击事件不会传递到错误的控件。
2. **在一个标签内嵌套另一个交互元素:**
   - **错误:** `<label><button>点击</button> 也点击这里</label>`
   - **后果:**  点击按钮可能会触发按钮自身的事件，而不会激活标签关联的控件（如果存在）。 `IsInInteractiveContent()` 方法会影响事件传递逻辑。
3. **误解 `for` 属性的优先级:** 开发者可能认为如果 `<label>` 内有可标注元素，`for` 属性就会被忽略，但实际上，如果 `for` 属性存在且能找到匹配的元素，它会优先被使用。
4. **JavaScript 阻止了默认行为但期望标签仍然有效:**  如果 JavaScript 代码中阻止了标签的 `click` 事件的默认行为，那么 `html_label_element.cc` 中的模拟点击行为可能不会发生。

**用户操作是如何一步步到达这里的:**

1. **用户在浏览器中打开一个包含 `<label>` 元素的网页。**
2. **Blink 引擎解析 HTML 代码，创建 DOM 树，包括 `HTMLLabelElement` 对象。**
3. **用户将鼠标光标移动到 `<label>` 元素上方。**
   -  这可能会触发 `HTMLLabelElement::SetHovered(true)`，并将悬停状态同步到关联的控件。
4. **用户点击 `<label>` 元素。**
   -  浏览器捕获到 `click` 事件。
   -  事件冒泡到 `<label>` 元素。
   -  `HTMLLabelElement::DefaultEventHandler()` 被调用，并最终调用 `DefaultEventHandlerInternal()`。
   -  `DefaultEventHandlerInternal()` 中的逻辑会查找关联的控件，判断是否需要聚焦，并模拟点击事件。
5. **如果 `<label>` 元素有 `accesskey` 属性，用户按下对应的快捷键。**
   -  浏览器捕获到访问键事件。
   -  `HTMLLabelElement::AccessKeyAction()` 被调用，它会模拟点击关联的控件。
6. **用户通过 Tab 键导航到 `<label>` 元素。**
   -  这可能会触发 `HTMLLabelElement::Focus()`，如果标签自身不可聚焦，则焦点会转移到关联的控件。

总而言之，`blink/renderer/core/html/forms/html_label_element.cc` 文件是 Blink 引擎中至关重要的组成部分，它确保了 HTML `<label>` 元素能够正确地与其关联的表单控件协同工作，提供良好的用户交互体验。它处理了用户与标签的各种交互行为，并将这些行为转化为对关联控件的操作。

### 提示词
```
这是目录为blink/renderer/core/html/forms/html_label_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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
 * Copyright (C) 2004, 2005, 2006, 2007, 2010 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/html/forms/html_label_element.h"

#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/simulated_click_options.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_controller.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/custom/element_internals.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/listed_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

namespace blink {

HTMLLabelElement::HTMLLabelElement(Document& document)
    : HTMLElement(html_names::kLabelTag, document), processing_click_(false) {}

// For JavaScript binding, return the control element without resolving the
// reference target, to avoid exposing shadow root content to JS.
HTMLElement* HTMLLabelElement::controlForBinding() const {
  // https://html.spec.whatwg.org/C/#labeled-control
  const AtomicString& control_id = FastGetAttribute(html_names::kForAttr);
  if (control_id.IsNull()) {
    // "If the for attribute is not specified, but the label element has a
    // labelable element descendant, then the first such descendant in tree
    // order is the label element's labeled control."
    for (HTMLElement& element : Traversal<HTMLElement>::DescendantsOf(*this)) {
      if (element.IsLabelable()) {
        if (!element.IsFormControlElement()) {
          UseCounter::Count(
              GetDocument(),
              WebFeature::kHTMLLabelElementControlForNonFormAssociatedElement);
        }
        return &element;
      }
    }
    return nullptr;
  }

  if (!IsInTreeScope())
    return nullptr;

  if (Element* element = GetTreeScope().getElementById(control_id)) {
    if (auto* html_element = DynamicTo<HTMLElement>(*element)) {
      if (html_element->IsLabelable()) {
        if (!html_element->IsFormControlElement()) {
          UseCounter::Count(
              GetDocument(),
              WebFeature::kHTMLLabelElementControlForNonFormAssociatedElement);
        }
        return html_element;
      }
    }
  }

  return nullptr;
}

HTMLElement* HTMLLabelElement::Control() const {
  HTMLElement* control = controlForBinding();
  if (!control) {
    return nullptr;
  }

  if (auto* reference_target =
          control->GetShadowReferenceTarget(html_names::kForAttr)) {
    return DynamicTo<HTMLElement>(reference_target);
  }

  return control;
}

HTMLFormElement* HTMLLabelElement::form() const {
  if (HTMLElement* control = Control()) {
    if (auto* form_control_element = DynamicTo<HTMLFormControlElement>(control))
      return form_control_element->Form();
    if (control->IsFormAssociatedCustomElement())
      return control->EnsureElementInternals().Form();
  }
  return nullptr;
}

void HTMLLabelElement::SetActive(bool active) {
  if (active != IsActive()) {
    // Update our status first.
    HTMLElement::SetActive(active);
  }

  // Also update our corresponding control.
  HTMLElement* control_element = Control();
  if (control_element && control_element->IsActive() != IsActive())
    control_element->SetActive(IsActive());
}

void HTMLLabelElement::SetHovered(bool hovered) {
  if (hovered != IsHovered()) {
    // Update our status first.
    HTMLElement::SetHovered(hovered);
  }

  // Also update our corresponding control.
  HTMLElement* element = Control();
  if (element && element->IsHovered() != IsHovered())
    element->SetHovered(IsHovered());
}

bool HTMLLabelElement::IsInteractiveContent() const {
  return true;
}

bool HTMLLabelElement::IsInInteractiveContent(Node* node) const {
  if (!node || !IsShadowIncludingInclusiveAncestorOf(*node))
    return false;
  while (node && this != node) {
    auto* html_element = DynamicTo<HTMLElement>(node);
    if (html_element && html_element->IsInteractiveContent())
      return true;
    node = node->ParentOrShadowHostNode();
  }
  return false;
}

void HTMLLabelElement::DefaultEventHandler(Event& evt) {
  DefaultEventHandlerInternal(evt);
  HTMLElement::DefaultEventHandler(evt);
}

void HTMLLabelElement::DefaultEventHandlerInternal(Event& evt) {
  if (evt.type() == event_type_names::kClick && !processing_click_) {
    HTMLElement* element = Control();

    // If we can't find a control or if the control received the click
    // event, then there's no need for us to do anything.
    if (!element)
      return;
    Node* target_node = evt.target() ? evt.target()->ToNode() : nullptr;
    if (target_node) {
      if (element->IsShadowIncludingInclusiveAncestorOf(*target_node))
        return;

      if (IsInInteractiveContent(target_node))
        return;
    }

    //   Behaviour of label element is as follows:
    //     - If there is double click, two clicks will be passed to control
    //       element. Control element will *not* be focused.
    //     - If there is selection of label element by dragging, no click
    //       event is passed. Also, no focus on control element.
    //     - If there is already a selection on label element and then label
    //       is clicked, then click event is passed to control element and
    //       control element is focused.

    bool is_label_text_selected = false;

    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kInput);

    // If the click is not simulated and the text of the label element
    // is selected by dragging over it, then return without passing the
    // click event to control element.
    // Note: check if it is a MouseEvent because a click event may
    // not be an instance of a MouseEvent if created by document.createEvent().
    auto* mouse_event = DynamicTo<MouseEvent>(evt);
    if (mouse_event && mouse_event->HasPosition()) {
      if (LocalFrame* frame = GetDocument().GetFrame()) {
        // Check if there is a selection and click is not on the
        // selection.
        if (GetLayoutObject() && GetLayoutObject()->IsSelectable() &&
            frame->Selection().ComputeVisibleSelectionInDOMTree().IsRange() &&
            !frame->GetEventHandler()
                 .GetSelectionController()
                 .MouseDownWasSingleClickInSelection() &&
            target_node->CanStartSelection()) {
          is_label_text_selected = true;

          // If selection is there and is single click i.e. text is
          // selected by dragging over label text, then return.
          // Click count >=2, meaning double click or triple click,
          // should pass click event to control element.
          // Only in case of drag, *neither* we pass the click event,
          // *nor* we focus the control element.
          if (mouse_event->ClickCount() == 1)
            return;
        }
      }
    }

    processing_click_ = true;
    if (element->IsMouseFocusable() ||
        (element->IsShadowHostWithDelegatesFocus() &&
         RuntimeEnabledFeatures::LabelAndDelegatesFocusNewHandlingEnabled())) {
      // If the label is *not* selected, or if the click happened on
      // selection of label, only then focus the control element.
      // In case of double click or triple click, selection will be there,
      // so do not focus the control element.
      if (!is_label_text_selected) {
        element->Focus(FocusParams(SelectionBehaviorOnFocus::kRestore,
                                   mojom::blink::FocusType::kMouse, nullptr,
                                   FocusOptions::Create()));
      }
    }

    // Click the corresponding control.
    element->DispatchSimulatedClick(&evt);

    processing_click_ = false;

    evt.SetDefaultHandled();
  }
}

bool HTMLLabelElement::HasActivationBehavior() const {
  return true;
}

bool HTMLLabelElement::WillRespondToMouseClickEvents() {
  if (Control() && Control()->WillRespondToMouseClickEvents()) {
    return true;
  }

  return HTMLElement::WillRespondToMouseClickEvents();
}

void HTMLLabelElement::Focus(const FocusParams& params) {
  GetDocument().UpdateStyleAndLayoutTreeForElement(
      this, DocumentUpdateReason::kFocus);
  if (IsFocusable()) {
    HTMLElement::Focus(params);
    return;
  }

  if (params.type == blink::mojom::blink::FocusType::kAccessKey)
    return;

  // To match other browsers, always restore previous selection.
  if (HTMLElement* element = Control()) {
    element->Focus(FocusParams(SelectionBehaviorOnFocus::kRestore, params.type,
                               params.source_capabilities, params.options,
                               params.focus_trigger));
  }
}

void HTMLLabelElement::AccessKeyAction(
    SimulatedClickCreationScope creation_scope) {
  if (HTMLElement* element = Control()) {
    element->AccessKeyAction(creation_scope);
  } else
    HTMLElement::AccessKeyAction(creation_scope);
}

}  // namespace blink
```