Response:
Let's break down the thought process for analyzing the `TextFieldInputType.cc` file. The goal is to understand its functionality and how it interacts with the browser's rendering engine.

**1. Initial Skim and Identification of Core Purpose:**

The first step is a quick read-through of the code, paying attention to:

* **File path:** `blink/renderer/core/html/forms/text_field_input_type.cc` immediately suggests this file is responsible for the behavior of text-based input fields (`<input type="text">`, `<input type="password">`, etc.) within the Blink rendering engine.
* **Copyright notices and includes:** These give context about ownership and dependencies on other parts of the Blink engine. Seeing includes like `HTMLInputElement.h`, `KeyboardEvent.h`, `MouseEvent.h`, `ComputedStyleBuilder.h` confirms the interaction with HTML elements, events, and styling.
* **Class name:** `TextFieldInputType` strongly indicates this is a class defining the *type* of input, handling its specific behaviors.
* **Constructor and destructor:**  Basic class management.
* **Methods with keywords:** Look for keywords like `Handle`, `Create`, `Set`, `Get`, `Dispatch`, `Update`, `Sanitize`. These are strong indicators of the file's actions.

**2. Categorizing Functionality (Mental Grouping):**

As you read through the methods, start mentally grouping them by their apparent function. Some initial categories might be:

* **Input Handling:**  Methods like `HandleKeydownEvent`, `HandleBeforeTextInsertedEvent`, `ForwardEvent`.
* **Value Management:**  Methods like `SetValue`, `SanitizeValue`, `ConvertFromVisibleValue`.
* **Shadow DOM Management:** Methods like `CreateShadowSubtree`, `DestroyShadowSubtree`, `ListAttributeTargetChanged`.
* **Spin Button Interaction:** Methods like `GetSpinButtonElement`, `HandleKeydownEventForSpinButton`, `SpinButtonStepUp`, `SpinButtonStepDown`.
* **Event Dispatching:**  Methods that dispatch events like `DispatchInputEvent`, `DispatchFormControlChangeEvent`.
* **Styling and Layout:**  Methods like `AdjustStyle`, `CreateLayoutObject`.
* **Focus and Blur:** `HandleBlurEvent`.
* **Form Submission:** `ShouldSubmitImplicitly`.
* **Placeholder Handling:** `UpdatePlaceholderText`.
* **Data List Interaction:**  Methods related to `DataListIndicatorElement`.

**3. Analyzing Key Methods in Detail:**

Once you have a rough categorization, dive deeper into the more important methods. Focus on what they *do* and *why*. For example:

* **`HandleKeydownEvent`:** It checks if the input is focused and delegates handling to the `ChromeClient`. This hints at browser-level integration for things like autofill or custom input methods.
* **`SetValue`:**  This is crucial for understanding how the input's value is updated. Note the different `TextFieldEventBehavior` options and how events are dispatched.
* **`CreateShadowSubtree`:** This explains how the internal structure of the input element (including the spin button and data list indicator) is built using Shadow DOM.
* **`SanitizeValue`:** This highlights the importance of data cleaning and validation. The removal of line breaks is a key detail.
* **`HandleBeforeTextInsertedEvent`:**  This reveals how `maxLength` is enforced and how the input text is processed before being inserted.

**4. Identifying Relationships with Web Technologies:**

As you understand the methods, connect them to the core web technologies:

* **HTML:**  The file directly manipulates and responds to HTML input elements (`HTMLInputElement`). The presence of methods related to attributes (`list`, `placeholder`, `maxLength`, `readonly`, `disabled`) confirms this connection.
* **CSS:**  Methods like `AdjustStyle` and references to `ComputedStyleBuilder` and CSS property IDs (`CSSPropertyID::kDisplay`) show how the visual presentation is controlled. The use of shadow DOM and pseudo-elements (`kPseudoCalendarPickerIndicator`, `kPseudoInputPlaceholder`) is also a CSS-related concept.
* **JavaScript:**  Event dispatching (`DispatchInputEvent`, `DispatchFormControlChangeEvent`) is fundamental for JavaScript interaction. JavaScript event listeners would respond to these events triggered by the native code. The methods related to value changes and user interaction are often driven by JavaScript.

**5. Considering User Interactions and Potential Issues:**

Think about how a user interacts with a text input and how this code plays a role:

* **Typing:**  `HandleKeydownEvent`, `HandleBeforeTextInsertedEvent`.
* **Pasting:** `HandleBeforeTextInsertedEvent`, the handling of newlines.
* **Clicking on the spin button:**  Methods related to spin buttons.
* **Selecting from a datalist:**  The `DataListIndicatorElement` and the interaction with `ChromeClient`.
* **Focusing and Blurring:** `HandleFocusEvent` (implicitly through `ForwardEvent`), `HandleBlurEvent`.
* **Form submission:** `ShouldSubmitImplicitly`.
* **Setting the value programmatically:** `SetValue`.

From these interactions, potential user or programming errors emerge:

* **Exceeding `maxLength`:** The code explicitly handles this.
* **Pasting invalid data:**  The sanitization process is important here.
* **Incorrectly setting the value programmatically:**  Understanding the different `TextFieldEventBehavior` options is key.
* **Assuming events are always dispatched in a specific order:** The code has logic to handle cases where the user is still editing.

**6. Tracing User Operations:**

Consider a specific user action and trace how it might lead to this code being executed. For example:

* **User types in an input field:**
    1. User presses a key.
    2. The browser captures the key press.
    3. An event (e.g., `keydown`, `keypress`, `textInput`) is generated.
    4. This event is dispatched to the relevant HTML element (`<input>`).
    5. The `TextFieldInputType::HandleKeydownEvent` or other event handlers in this file are called.
    6. Further processing might involve `HandleBeforeTextInsertedEvent` if it's a text insertion.
    7. The value of the input might be updated via `SetValue`.
    8. Events like `input` are dispatched, potentially triggering JavaScript listeners.

**7. Iterative Refinement:**

The process isn't strictly linear. You might go back and forth between analyzing methods, identifying relationships, and considering user interactions. As your understanding grows, you refine your mental model of the code.

By following these steps, you can systematically analyze a complex source code file like `TextFieldInputType.cc` and understand its purpose, its interactions with other parts of the system, and potential areas for errors or interesting behavior.
好的，让我们来详细分析一下 `blink/renderer/core/html/forms/text_field_input_type.cc` 文件的功能。

**核心功能:**

这个文件定义了 Blink 渲染引擎中 `input` 元素的文本类型（`type="text"`, `type="password"`, `type="search"` 等，但不包括像 `number`, `date` 等有特殊行为的类型）的核心行为逻辑。它负责处理这些文本输入框的各种交互、属性变化、以及与浏览器其他组件的协同。

**具体功能点:**

1. **事件处理:**
    *   **键盘事件 (`HandleKeydownEvent`, `HandleKeydownEventForSpinButton`):**  处理用户在文本框中按下按键的操作。例如，方向键的移动、删除键的删除等。如果存在 `spin button` (例如 `type="number"`，但这里的文件处理的主要是 `text` 类型，`spin button` 的处理可能涉及到一些共享的逻辑)，也会处理其键盘事件。
    *   **鼠标事件 (`ForwardEvent` 中处理 MouseEvent):**  转发鼠标事件到相关的子元素，例如 `spin button`。
    *   **拖拽事件 (`ForwardEvent` 中处理 DragEvent):**  处理文本框的拖拽操作。
    *   **焦点和失焦事件 (`ForwardEvent` 中处理 `blur`, `focus`, `HandleBlurEvent`):**  处理文本框获得和失去焦点的事件，例如在失焦时结束编辑。
    *   **文本插入前事件 (`HandleBeforeTextInsertedEvent`):**  在文本被插入到输入框之前进行处理，例如检查 `maxLength` 限制。
    *   **其他事件 (例如 `WheelEvent` 在 `ForwardEvent` 中):**  处理其他可能影响文本框的事件。

2. **值管理 (`SetValue`, `SanitizeValue`, `ConvertFromVisibleValue`):**
    *   **设置值 (`SetValue`):**  以不同的方式设置文本框的值，并根据 `event_behavior` 参数决定是否触发 `input` 或 `change` 事件。
    *   **清理值 (`SanitizeValue`):**  对用户输入的值进行清理，例如移除换行符，限制长度。
    *   **可见值转换 (`ConvertFromVisibleValue`):**  将用户在编辑器中看到的“可见”值转换为内部表示的值。对于普通的文本框，通常是直接返回。

3. **Shadow DOM 管理 (`CreateShadowSubtree`, `DestroyShadowSubtree`, `ListAttributeTargetChanged`):**
    *   **创建 Shadow DOM (`CreateShadowSubtree`):**  为文本框创建用户代理 Shadow DOM，用于实现一些内置的 UI 组件，例如 `spin button` (如果适用) 和 `datalist` 的指示器。
    *   **销毁 Shadow DOM (`DestroyShadowSubtree`):**  清理文本框的 Shadow DOM。
    *   **`list` 属性变化 (`ListAttributeTargetChanged`):**  当文本框的 `list` 属性指向的 `datalist` 元素发生变化时，更新 UI (例如显示或隐藏下拉指示器)。

4. **布局和样式 (`AdjustStyle`, `CreateLayoutObject`):**
    *   **调整样式 (`AdjustStyle`):**  在计算样式时进行特定的调整，例如处理 `overflow` 属性对基线的影响。
    *   **创建布局对象 (`CreateLayoutObject`):**  为文本框创建对应的布局对象 (`LayoutTextControlSingleLine`)，用于渲染。

5. **表单交互 (`ShouldSubmitImplicitly`):**
    *   **隐式提交判断 (`ShouldSubmitImplicitly`):**  判断在某些事件发生时是否应该隐式地提交表单（例如在单行文本框中按下回车键）。

6. **辅助功能 (`MayTriggerVirtualKeyboard`):**
    *   **虚拟键盘触发 (`MayTriggerVirtualKeyboard`):**  表明文本类型的输入框通常可以触发虚拟键盘。

7. **验证 (`ValueMissing`):**
    *   **缺失值判断 (`ValueMissing`):**  判断文本框的值是否为空，这与 `required` 属性相关。

8. **建议值 (`CanSetSuggestedValue`):**
    *   **支持建议值 (`CanSetSuggestedValue`):**  表明文本类型的输入框可以设置建议值（例如来自浏览器的自动填充）。

9. **`datalist` 支持 (`DataListIndicatorElement`, `OpenPopupView`):**
    *   **`DataListIndicatorElement`:**  定义了 `datalist` 下拉指示器的行为，例如点击时打开下拉列表。
    *   **`OpenPopupView`:**  打开与 `datalist` 关联的下拉列表。

10. **`spin button` 支持 (`GetSpinButtonElement`, `SpinButtonStepUp`, `SpinButtonStepDown`):**
    *   虽然这个文件主要处理文本类型，但包含了一些与 `spin button` 相关的逻辑，这可能是为了代码复用或者处理某些边缘情况。`spin button` 通常与 `type="number"` 等类型关联。

11. **占位符 (`UpdatePlaceholderText`):**
    *   **更新占位符 (`UpdatePlaceholderText`):**  根据 `placeholder` 属性的值和当前状态更新占位符的显示。

12. **值更改通知 (`SubtreeHasChanged`, `DidSetValueByUserEdit`):**
    *   **子树变化 (`SubtreeHasChanged`):**  当内部编辑器（例如 Shadow DOM 中的 `<input>` 元素）的子树发生变化时调用，用于更新模型值和占位符的可见性。
    *   **用户编辑值 (`DidSetValueByUserEdit`):**  当用户编辑了文本框的值后通知浏览器，可能会触发自动填充等功能。

13. **更新视图 (`UpdateView`):**
    *   **更新视图 (`UpdateView`):**  将内部模型的值同步到用户可见的编辑器中。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **HTML:**  这个文件是 `input` 元素行为的核心实现，直接关联到 HTML 中 `<input type="text">` 等标签的渲染和交互。
    *   **举例:** 当 HTML 中定义 `<input type="text" value="初始值" maxlength="10">` 时，`TextFieldInputType` 会处理 `value` 属性的初始设置，并通过 `HandleBeforeTextInsertedEvent` 来限制用户输入不超过 10 个字符。
*   **CSS:**  通过 `AdjustStyle` 方法影响文本框的样式，并且使用 Shadow DOM 来组织内部结构，这些内部结构的样式也可以通过 CSS 进行控制（例如 `::shadow`, `::part` 等）。
    *   **举例:** `CreateShadowSubtree` 中设置了 `DataListIndicatorElement` 的内联样式，控制了下拉指示器的显示方式。开发者也可以通过 CSS 来自定义这个指示器的样式。
*   **JavaScript:**  这个文件通过事件（如 `input`, `change`) 与 JavaScript 交互。当用户在文本框中输入时，`SetValue` 方法可能会触发 `input` 事件，JavaScript 可以监听这个事件并执行相应的逻辑。
    *   **举例:**  JavaScript 可以监听 `input` 事件来实时验证用户输入：
        ```javascript
        const inputElement = document.getElementById('myInput');
        inputElement.addEventListener('input', function(event) {
          console.log('输入框的值已更改:', event.target.value);
        });
        ```

**逻辑推理的假设输入与输出:**

假设用户在一个空的 `<input type="text" maxlength="5">` 中输入 "hello world"。

*   **假设输入:** 用户输入 "h", "e", "l", "l", "o", " ", "w", "o", "r", "l", "d" (每个字符的输入都可能触发事件)。
*   **处理过程:**
    *   每次按键，`HandleKeydownEvent` 会被调用。
    *   `HandleBeforeTextInsertedEvent` 会在文本插入前被调用。
    *   当输入 "hello" 时，长度为 5，符合 `maxlength` 限制，`event.GetText()` 为当前输入的字符。
    *   当输入空格 " " 时，总长度变为 6，超过 `maxlength`，`HandleBeforeTextInsertedEvent` 中的逻辑会截断输入，`event.SetText("")`，阻止空格的插入。
    *   后续的 "world" 也因为超出长度限制而被阻止。
*   **最终输出:** 输入框的值最终为 "hello"。

**用户或编程常见的使用错误:**

1. **错误地假设事件触发顺序:**  开发者可能假设 `change` 事件会在每次输入后立即触发，但实际上 `change` 事件通常在输入框失去焦点时触发，而 `input` 事件会在每次值改变时触发。
2. **没有考虑到 `maxlength` 限制:**  开发者可能允许用户在 JavaScript 中设置超过 `maxlength` 的值，但浏览器会根据 `TextFieldInputType` 中的逻辑进行截断。
3. **混淆 `value` 属性和内部编辑器值:**  在某些情况下，`value` 属性和内部编辑器显示的值可能不一致，例如在输入校验失败时。直接操作内部编辑器元素可能导致状态不一致。
4. **错误地处理 `datalist` 事件:**  开发者可能没有正确监听 `input` 事件或者使用 JavaScript 来同步更新 `datalist` 的选项，导致 `datalist` 的建议不准确。

**用户操作如何一步步到达这里:**

1. **用户在浏览器中打开一个包含 `<input type="text">` 元素的网页。**
2. **渲染引擎 (Blink) 解析 HTML 并创建对应的 DOM 树。**
3. **当渲染引擎需要处理该 `input` 元素时，会创建 `TextFieldInputType` 的实例。**
4. **用户点击该输入框，使其获得焦点。这可能会触发 `ForwardEvent` 处理 `focus` 事件。**
5. **用户开始在输入框中输入字符。**
6. **每次按键，浏览器会生成键盘事件 (`keydown`, `keypress`, `textInput`)。**
7. **这些事件会被分发到 `input` 元素，`TextFieldInputType` 的 `HandleKeydownEvent` 会被调用。**
8. **在文本真正插入之前，`HandleBeforeTextInsertedEvent` 会被调用，检查 `maxlength` 等限制。**
9. **如果允许插入，输入的值会更新，`SetValue` 方法被调用，并可能触发 `input` 事件。**
10. **用户完成输入，点击页面其他地方使输入框失去焦点。这会触发 `ForwardEvent` 处理 `blur` 事件，并调用 `HandleBlurEvent`，此时可能会触发 `change` 事件。**
11. **如果 `input` 元素关联了 `datalist` 并且用户点击了下拉指示器，`DataListIndicatorElement` 的事件处理函数会被调用，并通过 `GetDocument().GetPage()->GetChromeClient().OpenTextDataListChooser(*host)` 打开下拉列表。**

总而言之，`blink/renderer/core/html/forms/text_field_input_type.cc` 文件是 Blink 渲染引擎中处理文本类型输入框核心逻辑的关键部分，它连接了 HTML 结构、CSS 样式和 JavaScript 交互，并负责处理用户输入、数据校验和 UI 更新等关键任务。

Prompt: 
```
这是目录为blink/renderer/core/html/forms/text_field_input_type.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。

"""
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
 * Copyright (C) 2011 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/html/forms/text_field_input_type.h"

#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/events/before_text_inserted_event.h"
#include "third_party/blink/renderer/core/events/drag_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/events/text_event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/text_control_inner_elements.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/layout/forms/layout_text_control_single_line.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class DataListIndicatorElement final : public HTMLDivElement {
 private:
  inline HTMLInputElement* HostInput() const {
    return To<HTMLInputElement>(OwnerShadowHost());
  }

  EventDispatchHandlingState* PreDispatchEventHandler(Event& event) override {
    // Chromium opens autofill popup in a mousedown event listener
    // associated to the document. We don't want to open it in this case
    // because we opens a datalist chooser later.
    // FIXME: We should dispatch mousedown events even in such case.
    if (event.type() == event_type_names::kMousedown)
      event.stopPropagation();
    return nullptr;
  }

  void DefaultEventHandler(Event& event) override {
    DCHECK(GetDocument().IsActive());
    if (event.type() != event_type_names::kClick)
      return;
    HTMLInputElement* host = HostInput();
    if (host && !host->IsDisabledOrReadOnly()) {
      GetDocument().GetPage()->GetChromeClient().OpenTextDataListChooser(*host);
      event.SetDefaultHandled();
    }
  }

  bool WillRespondToMouseClickEvents() override {
    return HostInput() && !HostInput()->IsDisabledOrReadOnly() &&
           GetDocument().IsActive();
  }

 public:
  explicit DataListIndicatorElement(Document& document)
      : HTMLDivElement(document) {}

  // This function should be called after appending |this| to a UA ShadowRoot.
  void InitializeInShadowTree() {
    DCHECK(ContainingShadowRoot());
    DCHECK(ContainingShadowRoot()->IsUserAgent());
    SetShadowPseudoId(shadow_element_names::kPseudoCalendarPickerIndicator);
    setAttribute(html_names::kIdAttr, shadow_element_names::kIdPickerIndicator);
    SetInlineStyleProperty(CSSPropertyID::kDisplay, CSSValueID::kListItem);
    SetInlineStyleProperty(CSSPropertyID::kListStyle, "disclosure-open inside");
    SetInlineStyleProperty(CSSPropertyID::kCounterIncrement, "list-item 0");
    SetInlineStyleProperty(CSSPropertyID::kBlockSize, 1.0,
                           CSSPrimitiveValue::UnitType::kEms);
    // Do not expose list-item role.
    setAttribute(html_names::kAriaHiddenAttr, keywords::kTrue);
  }
};

TextFieldInputType::TextFieldInputType(Type type, HTMLInputElement& element)
    : InputType(type, element), InputTypeView(element) {}

TextFieldInputType::~TextFieldInputType() = default;

void TextFieldInputType::Trace(Visitor* visitor) const {
  InputTypeView::Trace(visitor);
  InputType::Trace(visitor);
}

InputTypeView* TextFieldInputType::CreateView() {
  return this;
}

InputType::ValueMode TextFieldInputType::GetValueMode() const {
  return ValueMode::kValue;
}

SpinButtonElement* TextFieldInputType::GetSpinButtonElement() const {
  if (!HasCreatedShadowSubtree()) {
    return nullptr;
  }
  auto* element = GetElement().UserAgentShadowRoot()->getElementById(
      shadow_element_names::kIdSpinButton);
  CHECK(!element || IsA<SpinButtonElement>(element));
  return To<SpinButtonElement>(element);
}

bool TextFieldInputType::MayTriggerVirtualKeyboard() const {
  return true;
}

bool TextFieldInputType::ValueMissing(const String& value) const {
  // For text-mode input elements, the value is missing only if it is mutable.
  // https://html.spec.whatwg.org/multipage/input.html#the-required-attribute
  return GetElement().IsRequired() && value.empty() &&
         !GetElement().IsDisabledOrReadOnly();
}

bool TextFieldInputType::CanSetSuggestedValue() {
  return true;
}

void TextFieldInputType::SetValue(const String& sanitized_value,
                                  bool value_changed,
                                  TextFieldEventBehavior event_behavior,
                                  TextControlSetValueSelection selection) {
  // We don't use InputType::setValue.  TextFieldInputType dispatches events
  // different way from InputType::setValue.
  if (event_behavior == TextFieldEventBehavior::kDispatchNoEvent)
    GetElement().SetNonAttributeValue(sanitized_value);
  else
    GetElement().SetNonAttributeValueByUserEdit(sanitized_value);

  // Visible value needs update if it differs from sanitized value,
  // if it was set with setValue().
  // event_behavior == kDispatchNoEvent usually means this call is
  // not a user edit.
  bool need_editor_update =
      value_changed ||
      (event_behavior == TextFieldEventBehavior::kDispatchNoEvent &&
       sanitized_value != GetElement().InnerEditorValue());

  if (need_editor_update)
    GetElement().UpdateView();
  // The following early-return can't be moved to the beginning of this
  // function. We need to update non-attribute value even if the value is not
  // changed.  For example, <input type=number> has a badInput string, that is
  // to say, IDL value=="", and new value is "", which should clear the badInput
  // string and update validity.
  if (!value_changed)
    return;

  if (selection == TextControlSetValueSelection::kSetSelectionToEnd) {
    unsigned max = VisibleValue().length();
    GetElement().SetSelectionRange(max, max);
  }

  switch (event_behavior) {
    case TextFieldEventBehavior::kDispatchChangeEvent:
      // If the user is still editing this field, dispatch an input event rather
      // than a change event.  The change event will be dispatched when editing
      // finishes.
      if (GetElement().IsFocused())
        GetElement().DispatchInputEvent();
      else
        GetElement().DispatchFormControlChangeEvent();
      break;

    case TextFieldEventBehavior::kDispatchInputEvent:
      GetElement().DispatchInputEvent();
      break;

    case TextFieldEventBehavior::kDispatchInputAndChangeEvent:
      GetElement().DispatchInputEvent();
      GetElement().DispatchFormControlChangeEvent();
      break;

    case TextFieldEventBehavior::kDispatchNoEvent:
      break;
  }
}

void TextFieldInputType::HandleKeydownEvent(KeyboardEvent& event) {
  if (!GetElement().IsFocused())
    return;
  if (ChromeClient* chrome_client = GetChromeClient()) {
    chrome_client->HandleKeyboardEventOnTextField(GetElement(), event);
    return;
  }
  event.SetDefaultHandled();
}

void TextFieldInputType::HandleKeydownEventForSpinButton(KeyboardEvent& event) {
  if (GetElement().IsDisabledOrReadOnly())
    return;
  const AtomicString key(event.key());
  const PhysicalToLogical<const AtomicString*> key_mapper(
      GetElement().GetComputedStyle()
          ? GetElement().GetComputedStyle()->GetWritingDirection()
          : WritingDirectionMode(WritingMode::kHorizontalTb,
                                 TextDirection::kLtr),
      &keywords::kArrowUp, &keywords::kArrowRight, &keywords::kArrowDown,
      &keywords::kArrowLeft);
  const AtomicString* key_up = key_mapper.LineOver();
  const AtomicString* key_down = key_mapper.LineUnder();

  if (key == *key_up) {
    SpinButtonStepUp();
  } else if (key == *key_down && !event.altKey()) {
    SpinButtonStepDown();
  } else {
    return;
  }
  GetElement().DispatchFormControlChangeEvent();
  event.SetDefaultHandled();
}

void TextFieldInputType::ForwardEvent(Event& event) {
  if (SpinButtonElement* spin_button = GetSpinButtonElement()) {
    spin_button->ForwardEvent(event);
    if (event.DefaultHandled())
      return;
  }

  // Style and layout may be dirty at this point. E.g. if an event handler for
  // the input element has modified its type attribute. If so, the LayoutObject
  // and the input type is out of sync. Avoid accessing the LayoutObject if we
  // have scheduled a forced re-attach (GetForceReattachLayoutTree()) for the
  // input element.
  if (GetElement().GetLayoutObject() &&
      !GetElement().GetForceReattachLayoutTree() &&
      (IsA<MouseEvent>(event) || IsA<DragEvent>(event) ||
       event.HasInterface(event_interface_names::kWheelEvent) ||
       event.type() == event_type_names::kBlur ||
       event.type() == event_type_names::kFocus)) {
    if (event.type() == event_type_names::kBlur) {
      if (LayoutBox* inner_editor_layout_object =
              GetElement().InnerEditorElement()->GetLayoutBox()) {
        // FIXME: This class has no need to know about PaintLayer!
        if (PaintLayer* inner_layer = inner_editor_layout_object->Layer()) {
          if (PaintLayerScrollableArea* inner_scrollable_area =
                  inner_layer->GetScrollableArea()) {
            inner_scrollable_area->SetScrollOffset(
                ScrollOffset(0, 0), mojom::blink::ScrollType::kProgrammatic);
          }
        }
      }
    }

    GetElement().ForwardEvent(event);
  }
}

void TextFieldInputType::HandleBlurEvent() {
  InputTypeView::HandleBlurEvent();
  GetElement().EndEditing();
  if (SpinButtonElement* spin_button = GetSpinButtonElement())
    spin_button->ReleaseCapture();
}

bool TextFieldInputType::ShouldSubmitImplicitly(const Event& event) {
  if (const TextEvent* text_event = DynamicTo<TextEvent>(event)) {
    if (!text_event->IsPaste() && !text_event->IsDrop() &&
        text_event->data() == "\n") {
      return true;
    }
  }
  return InputTypeView::ShouldSubmitImplicitly(event);
}

void TextFieldInputType::AdjustStyle(ComputedStyleBuilder& builder) {
  // The flag is necessary in order that a text field <input> with non-'visible'
  // overflow property doesn't change its baseline.
  builder.SetShouldIgnoreOverflowPropertyForInlineBlockBaseline();
}

LayoutObject* TextFieldInputType::CreateLayoutObject(
    const ComputedStyle&) const {
  return MakeGarbageCollected<LayoutTextControlSingleLine>(&GetElement());
}

ControlPart TextFieldInputType::AutoAppearance() const {
  return kTextFieldPart;
}

bool TextFieldInputType::IsInnerEditorValueEmpty() const {
  if (!HasCreatedShadowSubtree()) {
    return VisibleValue().empty();
  }
  return GetElement().InnerEditorValue().empty();
}

void TextFieldInputType::CreateShadowSubtree() {
  DCHECK(IsShadowHost(GetElement()));
  ShadowRoot* shadow_root = GetElement().UserAgentShadowRoot();
  DCHECK(!shadow_root->HasChildren());

  bool should_have_spin_button = GetElement().IsSteppable();
  bool should_have_data_list_indicator = GetElement().HasValidDataListOptions();
  bool creates_container = should_have_spin_button ||
                           should_have_data_list_indicator || NeedsContainer();

  HTMLElement* inner_editor = GetElement().CreateInnerEditorElement();
  if (!creates_container) {
    shadow_root->AppendChild(inner_editor);
    return;
  }

  Document& document = GetElement().GetDocument();
  auto* container = MakeGarbageCollected<HTMLDivElement>(document);
  container->SetInlineStyleProperty(CSSPropertyID::kUnicodeBidi,
                                    CSSValueID::kNormal);
  container->SetIdAttribute(shadow_element_names::kIdTextFieldContainer);
  container->SetShadowPseudoId(
      shadow_element_names::kPseudoTextFieldDecorationContainer);
  shadow_root->AppendChild(container);

  auto* editing_view_port =
      MakeGarbageCollected<EditingViewPortElement>(document);
  editing_view_port->AppendChild(inner_editor);
  container->AppendChild(editing_view_port);

  if (should_have_data_list_indicator) {
    auto* data_list = MakeGarbageCollected<DataListIndicatorElement>(document);
    container->AppendChild(data_list);
    data_list->InitializeInShadowTree();
  }
  // FIXME: Because of a special handling for a spin button in
  // LayoutTextControlSingleLine, we need to put it to the last position. It's
  // inconsistent with multiple-fields date/time types.
  if (should_have_spin_button) {
    container->AppendChild(
        MakeGarbageCollected<SpinButtonElement, Document&,
                             SpinButtonElement::SpinButtonOwner&>(document,
                                                                  *this));
  }

  // See listAttributeTargetChanged too.
}

Element* TextFieldInputType::ContainerElement() const {
  return GetElement().EnsureShadowSubtree()->getElementById(
      shadow_element_names::kIdTextFieldContainer);
}

void TextFieldInputType::DestroyShadowSubtree() {
  InputTypeView::DestroyShadowSubtree();
  if (SpinButtonElement* spin_button = GetSpinButtonElement())
    spin_button->RemoveSpinButtonOwner();
}

void TextFieldInputType::ListAttributeTargetChanged() {
  if (!HasCreatedShadowSubtree()) {
    return;
  }
  if (ChromeClient* chrome_client = GetChromeClient())
    chrome_client->TextFieldDataListChanged(GetElement());
  Element* picker = GetElement().UserAgentShadowRoot()->getElementById(
      shadow_element_names::kIdPickerIndicator);
  bool did_have_picker_indicator = picker;
  bool will_have_picker_indicator = GetElement().HasValidDataListOptions();
  if (did_have_picker_indicator == will_have_picker_indicator)
    return;
  EventDispatchForbiddenScope::AllowUserAgentEvents allow_events;
  if (will_have_picker_indicator) {
    Document& document = GetElement().GetDocument();
    if (Element* container = ContainerElement()) {
      auto* data_list =
          MakeGarbageCollected<DataListIndicatorElement>(document);
      container->InsertBefore(data_list, GetSpinButtonElement());
      data_list->InitializeInShadowTree();
    } else {
      // FIXME: The following code is similar to createShadowSubtree(),
      // but they are different. We should simplify the code by making
      // containerElement mandatory.
      auto* rp_container = MakeGarbageCollected<HTMLDivElement>(document);
      rp_container->SetIdAttribute(shadow_element_names::kIdTextFieldContainer);
      rp_container->SetShadowPseudoId(
          shadow_element_names::kPseudoTextFieldDecorationContainer);
      Element* inner_editor = GetElement().InnerEditorElement();
      inner_editor->parentNode()->ReplaceChild(rp_container, inner_editor);
      auto* editing_view_port =
          MakeGarbageCollected<EditingViewPortElement>(document);
      editing_view_port->AppendChild(inner_editor);
      rp_container->AppendChild(editing_view_port);
      auto* data_list =
          MakeGarbageCollected<DataListIndicatorElement>(document);
      rp_container->AppendChild(data_list);
      data_list->InitializeInShadowTree();
      Element& input = GetElement();
      if (input.GetDocument().FocusedElement() == input)
        input.UpdateSelectionOnFocus(SelectionBehaviorOnFocus::kRestore);
    }
  } else {
    picker->remove(ASSERT_NO_EXCEPTION);
  }
}

void TextFieldInputType::ValueAttributeChanged() {
  UpdateView();
}

void TextFieldInputType::DisabledOrReadonlyAttributeChanged() {
  if (SpinButtonElement* spin_button = GetSpinButtonElement())
    spin_button->ReleaseCapture();
}

void TextFieldInputType::DisabledAttributeChanged() {
  if (!HasCreatedShadowSubtree()) {
    return;
  }
  DisabledOrReadonlyAttributeChanged();
}

void TextFieldInputType::ReadonlyAttributeChanged() {
  if (!HasCreatedShadowSubtree()) {
    return;
  }
  DisabledOrReadonlyAttributeChanged();
}

bool TextFieldInputType::SupportsReadOnly() const {
  return true;
}

static bool IsASCIILineBreak(UChar c) {
  return c == '\r' || c == '\n';
}

// Returns true if `c` may contain a line break. This is an inexact comparison.
// This is used as the common case is the text does not contain a newline.
static bool MayBeASCIILineBreak(UChar c) {
  static_assert('\n' < '\r');
  return c <= '\r';
}

static String LimitLength(const String& string, unsigned max_length) {
  unsigned new_length = std::min(max_length, string.length());
  if (new_length == string.length())
    return string;
  if (new_length > 0 && U16_IS_LEAD(string[new_length - 1]))
    --new_length;
  return string.Left(new_length);
}

String TextFieldInputType::SanitizeValue(const String& proposed_value) const {
  // Typical case is the string doesn't contain a break and fits. The Find()
  // is not exact (meaning it'll match many other characters), but is a good
  // approximation for a fast path.
  if (proposed_value.Find(MayBeASCIILineBreak) == kNotFound &&
      proposed_value.length() < std::numeric_limits<int>::max()) {
    return proposed_value;
  }
  return LimitLength(proposed_value.RemoveCharacters(IsASCIILineBreak),
                     std::numeric_limits<int>::max());
}

void TextFieldInputType::HandleBeforeTextInsertedEvent(
    BeforeTextInsertedEvent& event) {
  // Make sure that the text to be inserted will not violate the maxLength.

  // We use HTMLInputElement::innerEditorValue() instead of
  // HTMLInputElement::value() because they can be mismatched by
  // sanitizeValue() in HTMLInputElement::subtreeHasChanged() in some cases.
  unsigned old_length = GetElement().InnerEditorValue().length();

  // selectionLength represents the selection length of this text field to be
  // removed by this insertion.
  // If the text field has no focus, we don't need to take account of the
  // selection length. The selection is the source of text drag-and-drop in
  // that case, and nothing in the text field will be removed.
  unsigned selection_length = 0;
  if (GetElement().IsFocused()) {
    // TODO(editing-dev): Use of UpdateStyleAndLayout
    // needs to be audited.  See http://crbug.com/590369 for more details.
    GetElement().GetDocument().UpdateStyleAndLayout(
        DocumentUpdateReason::kEditing);

    selection_length = GetElement()
                           .GetDocument()
                           .GetFrame()
                           ->Selection()
                           .SelectedText()
                           .length();
  }
  DCHECK_GE(old_length, selection_length);

  // Selected characters will be removed by the next text event.
  unsigned base_length = old_length - selection_length;
  unsigned max_length;
  if (MaxLength() < 0)
    max_length = std::numeric_limits<int>::max();
  else
    max_length = static_cast<unsigned>(MaxLength());
  unsigned appendable_length =
      max_length > base_length ? max_length - base_length : 0;

  // Truncate the inserted text to avoid violating the maxLength and other
  // constraints.
  String event_text = event.GetText();
  unsigned text_length = event_text.length();
  while (text_length > 0 && IsASCIILineBreak(event_text[text_length - 1]))
    text_length--;
  event_text.Truncate(text_length);
  event_text.Replace("\r\n", " ");
  event_text.Replace('\r', ' ');
  event_text.Replace('\n', ' ');

  event.SetText(LimitLength(event_text, appendable_length));

  if (ChromeClient* chrome_client = GetChromeClient()) {
    if (selection_length == old_length && selection_length != 0 &&
        !event_text.empty()) {
      chrome_client->DidClearValueInTextField(GetElement());
    }
  }
}

bool TextFieldInputType::ShouldRespectListAttribute() {
  return true;
}

HTMLElement* TextFieldInputType::UpdatePlaceholderText(
    bool is_suggested_value) {
  if (!HasCreatedShadowSubtree() &&
      RuntimeEnabledFeatures::CreateInputShadowTreeDuringLayoutEnabled()) {
    return nullptr;
  }
  if (!SupportsPlaceholder()) {
    return nullptr;
  }
  HTMLElement* placeholder = GetElement().PlaceholderElement();
  if (!is_suggested_value &&
      !GetElement().FastHasAttribute(html_names::kPlaceholderAttr)) {
    if (placeholder)
      placeholder->remove(ASSERT_NO_EXCEPTION);
    return nullptr;
  }
  if (!placeholder) {
    GetElement().EnsureShadowSubtree();
    auto* new_element =
        MakeGarbageCollected<HTMLDivElement>(GetElement().GetDocument());
    placeholder = new_element;
    placeholder->SetShadowPseudoId(
        shadow_element_names::kPseudoInputPlaceholder);
    placeholder->SetInlineStyleProperty(CSSPropertyID::kDisplay,
                                        GetElement().IsPlaceholderVisible()
                                            ? CSSValueID::kBlock
                                            : CSSValueID::kNone,
                                        true);
    placeholder->setAttribute(html_names::kIdAttr,
                              shadow_element_names::kIdPlaceholder);
    Element* container = ContainerElement();
    Node* previous = container ? container : GetElement().InnerEditorElement();
    previous->parentNode()->InsertBefore(placeholder, previous);
    SECURITY_DCHECK(placeholder->parentNode() == previous->parentNode());
  }
  if (is_suggested_value) {
    placeholder->SetInlineStyleProperty(CSSPropertyID::kUserSelect,
                                        CSSValueID::kNone, true);
  } else {
    placeholder->RemoveInlineStyleProperty(CSSPropertyID::kUserSelect);
  }
  placeholder->setTextContent(GetElement().GetPlaceholderValue());
  return placeholder;
}

String TextFieldInputType::ConvertFromVisibleValue(
    const String& visible_value) const {
  return visible_value;
}

void TextFieldInputType::SubtreeHasChanged() {
  GetElement().SetValueFromRenderer(SanitizeUserInputValue(
      ConvertFromVisibleValue(GetElement().InnerEditorValue())));
  GetElement().UpdatePlaceholderVisibility();
  GetElement().PseudoStateChanged(CSSSelector::kPseudoValid);
  GetElement().PseudoStateChanged(CSSSelector::kPseudoInvalid);
  GetElement().PseudoStateChanged(CSSSelector::kPseudoUserValid);
  GetElement().PseudoStateChanged(CSSSelector::kPseudoUserInvalid);
  GetElement().PseudoStateChanged(CSSSelector::kPseudoInRange);
  GetElement().PseudoStateChanged(CSSSelector::kPseudoOutOfRange);

  DidSetValueByUserEdit();
}

void TextFieldInputType::OpenPopupView() {
  if (GetElement().IsDisabledOrReadOnly())
    return;
  if (ChromeClient* chrome_client = GetChromeClient())
    chrome_client->OpenTextDataListChooser(GetElement());
}

void TextFieldInputType::DidSetValueByUserEdit() {
  if (!GetElement().IsFocused())
    return;
  if (ChromeClient* chrome_client = GetChromeClient()) {
    if (GetElement().Value().empty()) {
      chrome_client->DidClearValueInTextField(GetElement());
    }
    chrome_client->DidChangeValueInTextField(GetElement());
  }
}

void TextFieldInputType::SpinButtonStepDown() {
  StepUpFromLayoutObject(-1);
}

void TextFieldInputType::SpinButtonStepUp() {
  StepUpFromLayoutObject(1);
}

void TextFieldInputType::UpdateView() {
  if (GetElement().SuggestedValue().empty() &&
      GetElement().NeedsToUpdateViewValue()) {
    // Update the view only if needsToUpdateViewValue is true. It protects
    // an unacceptable view value from being overwritten with the DOM value.
    //
    // e.g. <input type=number> has a view value "abc", and input.max is
    // updated. In this case, updateView() is called but we should not
    // update the view value.
    GetElement().SetInnerEditorValue(VisibleValue());
    GetElement().UpdatePlaceholderVisibility();
  }
}

void TextFieldInputType::FocusAndSelectSpinButtonOwner() {
  GetElement().Focus(FocusParams(FocusTrigger::kUserGesture));
  GetElement().SetSelectionRange(0, std::numeric_limits<int>::max());
}

bool TextFieldInputType::ShouldSpinButtonRespondToMouseEvents() {
  return !GetElement().IsDisabledOrReadOnly();
}

bool TextFieldInputType::ShouldSpinButtonRespondToWheelEvents() {
  return ShouldSpinButtonRespondToMouseEvents() && GetElement().IsFocused();
}

void TextFieldInputType::SpinButtonDidReleaseMouseCapture(
    SpinButtonElement::EventDispatch event_dispatch) {
  if (event_dispatch == SpinButtonElement::kEventDispatchAllowed)
    GetElement().DispatchFormControlChangeEvent();
}

}  // namespace blink

"""

```