Response:
My thought process for analyzing the `edit_context.cc` file went something like this:

1. **Understand the Goal:** The primary goal is to understand the functionality of this C++ file within the Chromium Blink rendering engine. Specifically, I need to identify its core responsibilities, its relationships with web technologies (JavaScript, HTML, CSS), any logical inferences it makes, common usage errors, and how a user interaction leads to this code.

2. **Initial Code Scan (Keywords and Includes):** I started by scanning the `#include` directives and the overall structure of the code. This gives clues about the file's dependencies and purpose.

    * **Includes related to IME:** `InputMethodController`, `TextFormat`, `TextUpdateEvent`, `CompositionEvent`, `ui/base/ime/ime_text_span.h` immediately suggest this file deals with Input Method Engine (IME) functionality.
    * **Includes related to DOM/Rendering:** `Document`, `LocalDOMWindow`, `LocalFrame`, `HTMLElement`, `DOMRect` indicate interaction with the Document Object Model and rendering aspects of the browser.
    * **Includes related to JavaScript Binding:** `ScriptState`, `V8_EDIT_CONTEXT_INIT` point to how this C++ code is exposed to JavaScript.
    * **Other Includes:** `base/containers/contains.h`, `base/ranges/algorithm.h`, `base/trace_event/trace_event.h`, `third_party/blink/public/platform/WebString.h`, etc., are general utility and platform-specific includes.

3. **Class Structure and Key Methods:** I then focused on the `EditContext` class itself, looking at its constructor, destructor, and public methods.

    * **Constructor:** Takes `ScriptState` and `EditContextInit` as arguments. The `EditContextInit` suggests initialization data passed from JavaScript. It initializes `text_`, `selection_start_`, and `selection_end_`.
    * **Key Methods (Categorization):** I mentally grouped the methods based on their apparent function:
        * **Creation and Lifetime:** `Create`, destructor.
        * **Information Retrieval:** `text`, `selectionStart`, `selectionEnd`, `characterBounds`, `GetLayoutBounds`, `TextInputInfo`, `CompositionRange`.
        * **State Management (Focus/Blur):** `Focus`, `Blur`.
        * **Selection Manipulation:** `updateSelection`, `SetSelection`.
        * **Text Manipulation:** `updateText`, `InsertText`, `DeleteBackward`, `DeleteForward`, `DeleteWordBackward`, `DeleteWordForward`, `DeleteCurrentSelection`.
        * **Composition Handling (IME Specific):** `SetComposition`, `SetCompositionFromExistingText`, `CancelComposition`, `CommitText`, `FinishComposingText`, `ClearCompositionState`, `GetCompositionCharacterBounds`, `FirstRectForCharacterRange`.
        * **Event Dispatching:**  Methods starting with `Dispatch` (e.g., `DispatchCompositionEndEvent`, `DispatchTextUpdateEvent`, `DispatchTextFormatEvent`, `DispatchCharacterBoundsUpdateEvent`). These are crucial for communication with the rendering engine and potentially JavaScript.
        * **Bounds Updates:** `updateCharacterBounds`, `updateControlBounds`, `updateSelectionBounds`.
        * **Element Association:** `AttachElement`, `DetachElement`.

4. **Relating to Web Technologies (JavaScript, HTML, CSS):**  This is where the "why" becomes important.

    * **JavaScript:** The constructor taking `ScriptState` and the existence of event dispatching mechanisms strongly indicate interaction with JavaScript. The `EditContext` is likely an object that JavaScript can interact with to get and set text, selection, and trigger IME operations. The `EditContextInit` dictionary directly links to how JavaScript provides initial data.
    * **HTML:** The methods for attaching and detaching `HTMLElement`s show a clear connection to HTML elements. The `EditContext` likely manages the text editing state for a specific HTML element or a region within it.
    * **CSS:** The methods related to bounds (`updateCharacterBounds`, `updateControlBounds`, `updateSelectionBounds`, `GetLayoutBounds`, `FirstRectForCharacterRange`) and the use of `DOMRect` indicate that CSS layout and styling influence the positioning and rendering of text within the `EditContext`. The conversion from CSS pixels to physical pixels in `GetLayoutBounds` and `GetCompositionCharacterBounds` is a key point.

5. **Logical Inferences and Assumptions:** I looked for code that made decisions based on state or input.

    * **Composition State:** The `has_composition_` flag is central to how the `EditContext` handles IME input. Many methods have conditional logic based on this flag.
    * **Selection Handling:** Methods like `OrderedSelectionStart` and `OrderedSelectionEnd` ensure consistent handling of forward and backward selections.
    * **Boundary Finding:** The use of `BackwardGraphemeBoundaryStateMachine` and `ForwardGraphemeBoundaryStateMachine` highlights the logic for handling text segmentation for deletion operations.

6. **User and Programming Errors:** I considered common mistakes developers might make when using or interacting with this component.

    * **Incorrect Selection Ranges:**  Methods like `updateSelection` and `updateText` have checks to prevent out-of-bounds access and handle cases where `start > end`.
    * **Mismatched Composition State:**  Calling IME-related methods when no composition is active or vice versa can lead to unexpected behavior. The code has checks for this (e.g., `DCHECK(has_composition_)` in `DispatchTextFormatEvent`).
    * **Assuming Pixel Units:**  Forgetting the CSS pixel to physical pixel conversion when dealing with bounds could lead to layout issues.

7. **User Interaction and Debugging:** I thought about the steps a user takes that would eventually involve this code.

    * **Focusing an Editable Area:**  Clicking or tabbing into an input field or a content-editable element is the starting point. This likely triggers the `Focus()` method.
    * **Typing:**  Pressing keys, especially when using an IME, will trigger various IME-related methods (`SetComposition`, `CommitText`).
    * **Selection Changes:**  Using the mouse or keyboard to change the text selection will call `updateSelection`.
    * **Cut/Copy/Paste:** These actions might interact with the `EditContext` to modify the text buffer.
    * **Debugging:**  The `TRACE_EVENT` calls provide valuable information for tracking the execution flow and the values of key variables during debugging.

8. **Summarization:** Finally, I synthesized my understanding into a concise summary, highlighting the core functionalities and relationships. I focused on the "why" and the big picture, rather than just listing the methods. I made sure to address all the specific points requested in the prompt.

This iterative process of code scanning, analysis, and connecting the code to higher-level concepts allowed me to build a comprehensive understanding of the `edit_context.cc` file's role within the Blink rendering engine.
好的，这是对 `blink/renderer/core/editing/ime/edit_context.cc` 文件（第一部分）的功能进行归纳：

**功能归纳:**

`EditContext.cc` 文件定义了 `EditContext` 类，该类在 Chromium Blink 渲染引擎中扮演着**文本编辑上下文**的角色，主要负责管理和维护一个可编辑区域的文本内容、选区以及与输入法引擎（IME）的交互。  它可以被看作是 Web 内容中一个独立的、可编程控制的文本编辑区域。

**主要功能点:**

1. **文本存储与管理:**
   -  拥有一个字符串 `text_` 来存储当前编辑区域的文本内容。
   -  提供方法 `text()` 获取当前文本内容。
   -  提供方法 `updateText()` 修改文本内容。

2. **选区管理:**
   -  维护选区的起始位置 `selection_start_` 和结束位置 `selection_end_`。
   -  提供方法 `selectionStart()` 和 `selectionEnd()` 获取选区信息。
   -  提供方法 `updateSelection()` 修改选区。
   -  提供方法 `SetSelection()` 更细粒度地设置选区，并可选择是否触发文本更新事件。

3. **输入法（IME）支持:**
   -  **Composition 管理:**  处理输入法 composing 状态的文本（例如，输入拼音时的中间状态）。
     -  使用 `has_composition_` 标志跟踪是否有正在进行的 composition。
     -  记录 composition 的起始位置 `composition_range_start_` 和结束位置 `composition_range_end_`。
     -  提供 `SetComposition()` 用于设置或更新 composition 文本和样式。
     -  提供 `CancelComposition()` 取消 composition。
     -  提供 `CommitText()` 提交最终的输入文本。
     -  提供 `FinishComposingText()` 结束 composition。
     -  提供 `ClearCompositionState()` 清理 composition 相关状态。
   -  **事件派发:**  向 JavaScript 发送与 IME 相关的事件，例如：
     -  `DispatchCompositionStartEvent()`:  composition 开始事件。
     -  `DispatchCompositionEndEvent()`: composition 结束事件。
     -  `DispatchTextUpdateEvent()`:  文本更新事件。
     -  `DispatchTextFormatEvent()`:  文本格式更新事件（用于高亮显示等）。
     -  `DispatchCharacterBoundsUpdateEvent()`: 字符边界更新事件。
   -  **获取布局信息:** 提供方法获取编辑区域、选区、以及 composition 文本的边界信息，用于 IME 正确渲染候选项等。
     -  `updateCharacterBounds()`: 更新字符边界信息。
     -  `updateControlBounds()`: 更新控件边界信息。
     -  `updateSelectionBounds()`: 更新选区边界信息。
     -  `GetLayoutBounds()`: 获取控件和选区的布局边界（转换到物理像素）。
     -  `GetCompositionCharacterBounds()`: 获取 composition 文本的字符边界。
     -  `FirstRectForCharacterRange()`: 获取指定字符范围内第一个字符的矩形区域。

4. **焦点管理:**
   -  提供 `Focus()` 方法获取焦点，成为当前活动的 `EditContext`，并处理与其他 `EditContext` 的焦点切换。
   -  提供 `Blur()` 方法失去焦点。

5. **文本编辑操作:**
   -  提供方法执行常见的文本编辑操作，例如：
     -  `InsertText()`: 插入文本。
     -  `DeleteBackward()`: 向后删除字符。
     -  `DeleteForward()`: 向前删除字符。
     -  `DeleteWordBackward()`: 向后删除单词。
     -  `DeleteWordForward()`: 向前删除单词。
     -  `DeleteCurrentSelection()`: 删除当前选区。
     -  `ExtendSelectionAndDelete()`: 扩展选区并删除。
     -  `DeleteSurroundingText()`: 删除选区周围的文本。

6. **与 JavaScript 的交互:**
   -  通过 `ScriptState` 和 `ExecutionContext` 与 JavaScript 环境关联。
   -  派发各种事件通知 JavaScript 文本和状态的变化。
   -  可以通过 JavaScript 创建和操作 `EditContext` 对象（从代码中的 `EditContext::Create` 可以推断）。

7. **元素关联:**
   -  可以与 HTML 元素关联，通过 `AttachElement()` 和 `DetachElement()` 方法。  一个 `EditContext` 目前只能关联一个元素。

8. **输入信息提供:**
   -  提供 `TextInputInfo()` 方法，返回一个包含当前文本输入相关信息的结构体 (`WebTextInputInfo`)，例如文本内容、选区、composition 状态等，这些信息可以被浏览器用于输入处理。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  `EditContext` 是一个可以被 JavaScript 操作的对象。
    * **创建:**  JavaScript 可以使用类似 `new EditContext(init)` 的方式创建 `EditContext` 实例，`init` 对象对应 C++ 中的 `EditContextInit`。
    * **事件监听:**  JavaScript 可以监听 `EditContext` 派发的事件，例如 `textupdate`, `compositionstart`, `compositionend`, `textformatupdate`, `characterboundsupdate`。
        ```javascript
        const editContext = new EditContext({ text: 'initial text' });
        editContext.addEventListener('textupdate', (event) => {
          console.log('Text updated:', event.text, event.updateRangeStart, event.updateRangeEnd);
        });
        // ... 对 editContext 进行操作，例如插入文本
        ```
    * **方法调用:** JavaScript 可以调用 `EditContext` 上的方法，例如 `updateText()`, `updateSelection()`, `setComposition()` 等。

* **HTML:** `EditContext` 可以与特定的 HTML 元素关联。
    * **关联:**  当一个 `EditContext` 与一个 HTML 元素关联后，它可能负责管理该元素内的文本编辑行为。例如，用户在一个 `<div>` 元素上启用 `contenteditable` 属性后，可能会创建一个关联的 `EditContext` 来处理输入。
    * **边界信息:** `EditContext` 需要知道其关联的 HTML 元素在页面上的布局位置，以便正确处理 IME 输入和显示。`updateControlBounds()` 就是用于更新这种边界信息。

* **CSS:** CSS 影响着 `EditContext` 中文本的渲染和布局。
    * **边界计算:**  `EditContext` 需要考虑 CSS 的影响来计算字符、选区和控件的边界。例如，字体大小、行高等 CSS 属性会影响字符的 `DOMRect`。
    * **IME 提示位置:** IME 的候选词窗口的显示位置需要参考 `EditContext` 提供的字符边界信息，这些边界信息是基于 CSS 渲染结果计算出来的。

**逻辑推理的假设输入与输出示例:**

假设输入：
- 当前 `EditContext` 的 `text_` 为 "hello world"。
- `selection_start_` 为 6， `selection_end_` 为 11 (选中 "world")。
- 调用 `DeleteCurrentSelection()` 方法。

输出：
- `text_` 变为 "hello "。
- `selection_start_` 变为 6， `selection_end_` 变为 6 (光标在删除的位置)。
- 触发 `DispatchTextUpdateEvent()`，事件携带的信息可能包括：`text: ""`, `updateRangeStart: 6`, `updateRangeEnd: 11`, `new_selection_start: 6`, `new_selection_end: 6`。

**用户或编程常见的使用错误示例:**

1. **选区范围错误:**  编程时可能传递不合法的选区范围，例如 `start > end` 或者超出文本长度的范围。 `EditContext` 中有检查逻辑 (`if (start > end) { std::swap(start, end); }` 以及使用 `std::min` 来限制范围)。
2. **Composition 状态不一致:**  在没有启动 Composition 的情况下调用与 Composition 相关的方法，或者在 Composition 过程中进行了非法的状态修改，可能导致程序错误或行为异常。例如，在 `has_composition_` 为 `false` 时调用 `DispatchTextFormatEvent()` 可能会导致 `DCHECK` 失败。
3. **忘记更新边界信息:** 在 HTML 元素的布局发生变化后，如果没有及时调用 `updateControlBounds()`, `updateCharacterBounds()` 等方法更新 `EditContext` 的边界信息，可能会导致 IME 的显示位置错误。

**用户操作如何一步步到达这里（作为调试线索）:**

1. **用户聚焦一个可编辑区域:** 用户点击或使用 Tab 键将焦点移动到一个 `contenteditable` 的 HTML 元素或者 `<input>`、`<textarea>` 等表单元素。这可能会触发创建或激活一个关联的 `EditContext`，并调用其 `Focus()` 方法。
2. **用户开始输入:** 用户开始通过键盘输入文本。
3. **使用输入法:** 如果用户使用中文、日文等需要输入法的语言，输入法会启动，开始 composing 过程。
    -  输入法将用户的按键转换为拼音或其他中间状态的文本。
    -  输入法可能会调用 `EditContext` 的 `SetComposition()` 方法来显示这些中间状态的文本，并可能通过 `ime_text_spans` 参数指定样式（例如下划线）。
    -  `EditContext` 会派发 `compositionstart` 和 `textformatupdate` 等事件。
4. **用户选择候选项或完成输入:**
    -  用户从输入法的候选词列表中选择一个词，或者直接按下空格或回车确认输入。
    -  输入法会调用 `EditContext` 的 `CommitText()` 方法，将最终的文本提交到 `EditContext` 中。
    -  `EditContext` 会派发 `textupdate` 和 `compositionend` 等事件。
5. **用户修改已输入的文本:** 用户可以使用退格键、删除键或者鼠标选择文本进行删除或替换。
    -  删除操作会调用 `DeleteBackward()`, `DeleteForward()`, `DeleteWordBackward()`, `DeleteWordForward()` 等方法。
    -  选择文本并输入新内容会涉及到选区的更新 (`updateSelection()`) 和文本的替换 (`updateText()` 或通过 `SetComposition()` 覆盖)。

在调试过程中，可以通过以下方式跟踪：

- **设置断点:** 在 `EditContext.cc` 的关键方法入口处设置断点，例如 `SetComposition()`, `CommitText()`, `DispatchTextUpdateEvent()` 等。
- **查看日志:** Chromium 的 tracing 工具 (chrome://tracing) 可以记录 `TRACE_EVENT` 宏输出的日志信息，可以查看 `ime` 类别下的事件。
- **检查事件派发:** 确认在用户操作后，是否按照预期派发了相应的 JavaScript 事件，以及事件携带的数据是否正确。

**总结:**

`EditContext.cc` 文件中的 `EditContext` 类是 Blink 渲染引擎中处理文本编辑和 IME 输入的核心组件，它管理着文本内容、选区状态，并负责与输入法引擎和 JavaScript 环境进行交互，以实现富文本编辑功能。

Prompt: 
```
这是目录为blink/renderer/core/editing/ime/edit_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/ime/edit_context.h"

#include "base/containers/contains.h"
#include "base/ranges/algorithm.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_range.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_edit_context_init.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/editing/ime/character_bounds_update_event.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/ime/text_format.h"
#include "third_party/blink/renderer/core/editing/ime/text_format_update_event.h"
#include "third_party/blink/renderer/core/editing/ime/text_update_event.h"
#include "third_party/blink/renderer/core/editing/state_machines/backward_grapheme_boundary_state_machine.h"
#include "third_party/blink/renderer/core/editing/state_machines/forward_grapheme_boundary_state_machine.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/events/composition_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/text/text_boundaries.h"
#include "third_party/blink/renderer/platform/wtf/decimal.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ui/base/ime/ime_text_span.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

EditContext::EditContext(ScriptState* script_state, const EditContextInit* dict)
    : ActiveScriptWrappable<EditContext>({}),
      execution_context_(ExecutionContext::From(script_state)) {
  DCHECK(IsMainThread());
  UseCounter::Count(GetExecutionContext(), WebFeature::kEditContext);

  if (dict->hasText())
    text_ = dict->text();

  if (dict->hasSelectionStart())
    selection_start_ = std::min(dict->selectionStart(), text_.length());

  if (dict->hasSelectionEnd())
    selection_end_ = std::min(dict->selectionEnd(), text_.length());
}

EditContext* EditContext::Create(ScriptState* script_state,
                                 const EditContextInit* dict) {
  return MakeGarbageCollected<EditContext>(script_state, dict);
}

EditContext::~EditContext() = default;

const AtomicString& EditContext::InterfaceName() const {
  return event_target_names::kEditContext;
}

ExecutionContext* EditContext::GetExecutionContext() const {
  return execution_context_;
}

LocalDOMWindow* EditContext::DomWindow() const {
  return To<LocalDOMWindow>(GetExecutionContext());
}

bool EditContext::HasPendingActivity() const {
  return GetExecutionContext() && HasEventListeners();
}

InputMethodController& EditContext::GetInputMethodController() const {
  return DomWindow()->GetFrame()->GetInputMethodController();
}

bool EditContext::IsEditContextActive() const {
  return true;
}

ui::mojom::VirtualKeyboardVisibilityRequest
EditContext::GetLastVirtualKeyboardVisibilityRequest() const {
  return GetInputMethodController().GetLastVirtualKeyboardVisibilityRequest();
}

void EditContext::SetVirtualKeyboardVisibilityRequest(
    ui::mojom::VirtualKeyboardVisibilityRequest vk_visibility_request) {
  GetInputMethodController().SetVirtualKeyboardVisibilityRequest(
      vk_visibility_request);
}

void EditContext::DispatchCompositionEndEvent(const String& text) {
  auto* event = MakeGarbageCollected<CompositionEvent>(
      event_type_names::kCompositionend, DomWindow(), text);
  DispatchEvent(*event);
}

bool EditContext::DispatchCompositionStartEvent(const String& text) {
  auto* event = MakeGarbageCollected<CompositionEvent>(
      event_type_names::kCompositionstart, DomWindow(), text);
  DispatchEvent(*event);
  return DomWindow();
}

void EditContext::DispatchCharacterBoundsUpdateEvent(uint32_t range_start,
                                                     uint32_t range_end) {
  auto* event = MakeGarbageCollected<CharacterBoundsUpdateEvent>(
      event_type_names::kCharacterboundsupdate, range_start, range_end);
  DispatchEvent(*event);
}

void EditContext::DispatchTextUpdateEvent(const String& text,
                                          uint32_t update_range_start,
                                          uint32_t update_range_end,
                                          uint32_t new_selection_start,
                                          uint32_t new_selection_end) {
  TextUpdateEvent* event = MakeGarbageCollected<TextUpdateEvent>(
      event_type_names::kTextupdate, text, update_range_start, update_range_end,
      new_selection_start, new_selection_end);
  DispatchEvent(*event);
}

void EditContext::DispatchTextFormatEvent(
    const WebVector<ui::ImeTextSpan>& ime_text_spans) {
  // Loop through IME text spans to prepare an array of TextFormat and
  // fire textformateupdate event.
  DCHECK(has_composition_);
  HeapVector<Member<TextFormat>> text_formats;
  text_formats.reserve(base::checked_cast<wtf_size_t>(ime_text_spans.size()));

  for (const auto& ime_text_span : ime_text_spans) {
    const auto range_start = base::checked_cast<wtf_size_t>(
        ime_text_span.start_offset + composition_range_start_);
    const auto range_end = base::checked_cast<wtf_size_t>(
        ime_text_span.end_offset + composition_range_start_);

    String underline_thickness;
    String underline_style;
    switch (ime_text_span.thickness) {
      case ui::ImeTextSpan::Thickness::kNone:
        underline_thickness = "None";
        break;
      case ui::ImeTextSpan::Thickness::kThin:
        underline_thickness = "Thin";
        break;
      case ui::ImeTextSpan::Thickness::kThick:
        underline_thickness = "Thick";
        break;
    }
    switch (ime_text_span.underline_style) {
      case ui::ImeTextSpan::UnderlineStyle::kNone:
        underline_style = "None";
        break;
      case ui::ImeTextSpan::UnderlineStyle::kSolid:
        underline_style = "Solid";
        break;
      case ui::ImeTextSpan::UnderlineStyle::kDot:
        underline_style = "Dotted";
        break;
      case ui::ImeTextSpan::UnderlineStyle::kDash:
        underline_style = "Dashed";
        break;
      case ui::ImeTextSpan::UnderlineStyle::kSquiggle:
        underline_style = "Squiggle";
        break;
    }

    text_formats.push_back(TextFormat::Create(
        range_start, range_end,
        underline_style, underline_thickness));
  }

  TextFormatUpdateEvent* event = MakeGarbageCollected<TextFormatUpdateEvent>(
      event_type_names::kTextformatupdate, text_formats);
  DispatchEvent(*event);
}

void EditContext::Focus() {
  TRACE_EVENT0("ime", "EditContext::Focus");

  EditContext* current_active_edit_context =
      GetInputMethodController().GetActiveEditContext();
  if (current_active_edit_context && current_active_edit_context != this) {
    // Reset the state of the EditContext if there is
    // an active composition in progress.
    current_active_edit_context->FinishComposingText(
        ConfirmCompositionBehavior::kKeepSelection);
  }
  GetInputMethodController().SetActiveEditContext(this);
}

void EditContext::Blur() {
  TRACE_EVENT0("ime", "EditContext::Blur");

  if (GetInputMethodController().GetActiveEditContext() != this)
    return;
  // Clean up the state of the |this| EditContext.
  FinishComposingText(ConfirmCompositionBehavior::kKeepSelection);
  GetInputMethodController().SetActiveEditContext(nullptr);
}

void EditContext::updateSelection(uint32_t start,
                                  uint32_t end,
                                  ExceptionState& exception_state) {
  TRACE_EVENT2("ime", "EditContext::updateSelection", "start",
               std::to_string(start), "end", std::to_string(end));

  SetSelection(std::min(start, text_.length()), std::min(end, text_.length()));
  if (!has_composition_)
    return;

  // There is an active composition so need to set the range of the
  // composition too so that we can commit the string properly.
  if (composition_range_start_ == 0 && composition_range_end_ == 0) {
    composition_range_start_ = OrderedSelectionStart();
    composition_range_end_ = OrderedSelectionEnd();
  }
}

void EditContext::updateCharacterBounds(
    uint32_t range_start,
    const HeapVector<Member<DOMRect>>& character_bounds) {
  character_bounds_range_start_ = range_start;

  TRACE_EVENT1("ime", "EditContext::updateCharacterBounds", "range_start, size",
               std::to_string(range_start) + ", " +
                   std::to_string(character_bounds.size()));

  character_bounds_.clear();
  base::ranges::for_each(character_bounds, [this](const auto& bounds) {
    auto result_bounds = gfx::ToEnclosingRect(
        gfx::RectF(ClampToWithNaNTo0<float>(bounds->x()),
                   ClampToWithNaNTo0<float>(bounds->y()),
                   ClampToWithNaNTo0<float>(bounds->width()),
                   ClampToWithNaNTo0<float>(bounds->height())));
    TRACE_EVENT1("ime", "EditContext::updateCharacterBounds", "charBounds",
                 result_bounds.ToString());
    character_bounds_.push_back(result_bounds);
  });
}

void EditContext::updateControlBounds(DOMRect* control_bounds) {
  control_bounds_ = gfx::ToEnclosingRect(
      gfx::RectF(ClampToWithNaNTo0<float>(control_bounds->x()),
                 ClampToWithNaNTo0<float>(control_bounds->y()),
                 ClampToWithNaNTo0<float>(control_bounds->width()),
                 ClampToWithNaNTo0<float>(control_bounds->height())));
  TRACE_EVENT1("ime", "EditContext::updateControlBounds", "control_bounds",
               control_bounds_.ToString());
}

void EditContext::updateSelectionBounds(DOMRect* selection_bounds) {
  selection_bounds_ = gfx::ToEnclosingRect(
      gfx::RectF(ClampToWithNaNTo0<float>(selection_bounds->x()),
                 ClampToWithNaNTo0<float>(selection_bounds->y()),
                 ClampToWithNaNTo0<float>(selection_bounds->width()),
                 ClampToWithNaNTo0<float>(selection_bounds->height())));
  TRACE_EVENT1("ime", "EditContext::updateSelectionBounds", "selection_bounds",
               selection_bounds_.ToString());
}

void EditContext::updateText(uint32_t start,
                             uint32_t end,
                             const String& new_text,
                             ExceptionState& exception_state) {
  TRACE_EVENT2("ime", "EditContext::updateText", "start, end",
               std::to_string(start) + ", " + std::to_string(end), "new_text",
               new_text);
  if (start > end) {
    std::swap(start, end);
  }
  end = std::min(end, text_.length());
  start = std::min(start, end);
  text_ = text_.Substring(0, start) + new_text + text_.Substring(end);
}

String EditContext::text() const {
  return text_;
}

uint32_t EditContext::selectionStart() const {
  return selection_start_;
}

uint32_t EditContext::selectionEnd() const {
  return selection_end_;
}

uint32_t EditContext::characterBoundsRangeStart() const {
  return character_bounds_range_start_;
}

const HeapVector<Member<HTMLElement>>& EditContext::attachedElements() {
  return attached_elements_;
}

const HeapVector<Member<DOMRect>> EditContext::characterBounds() {
  HeapVector<Member<DOMRect>> dom_rects;
  base::ranges::transform(
      character_bounds_, std::back_inserter(dom_rects), [](const auto& bound) {
        return DOMRect::Create(bound.x(), bound.y(), bound.width(),
                               bound.height());
      });
  return dom_rects;
}

void EditContext::GetLayoutBounds(gfx::Rect* control_bounds,
                                  gfx::Rect* selection_bounds) {
  // EditContext's coordinates are in CSS pixels, which need to be converted to
  // physical pixels before return.
  *control_bounds = gfx::ScaleToEnclosingRect(
      control_bounds_, DomWindow()->GetFrame()->DevicePixelRatio());
  *selection_bounds = gfx::ScaleToEnclosingRect(
      selection_bounds_, DomWindow()->GetFrame()->DevicePixelRatio());

  TRACE_EVENT2("ime", "EditContext::GetLayoutBounds", "control",
               control_bounds->ToString(), "selection",
               selection_bounds->ToString());
}

bool EditContext::SetComposition(
    const WebString& text,
    const WebVector<ui::ImeTextSpan>& ime_text_spans,
    const WebRange& replacement_range,
    int selection_start,
    int selection_end) {
  TRACE_EVENT2(
      "ime", "EditContext::SetComposition", "start, end",
      std::to_string(selection_start) + ", " + std::to_string(selection_end),
      "text", text.Utf8());

  if (!text.IsEmpty() && !has_composition_) {
    if (!DispatchCompositionStartEvent(text))
      return false;
    has_composition_ = true;
  }
  if (text.IsEmpty()) {
    if (has_composition_) {
      // Receiving an empty text string is a signal to delete any text in the
      // composition range and terminate the composition
      CancelComposition();
    }
    return true;
  }

  WebRange actual_replacement_range = replacement_range;
  if (actual_replacement_range.IsEmpty()) {
    // If no composition range, the current selection will be replaced.
    if (composition_range_start_ == 0 && composition_range_end_ == 0) {
      actual_replacement_range = GetSelectionOffsets();
    }
    // Otherwise, the current composition range will be replaced.
    else {
      actual_replacement_range =
          WebRange(composition_range_start_,
                   composition_range_end_ - composition_range_start_);
    }
  }

  // Update the selection and buffer if the composition range has changed.
  String update_text(text);
  text_ = text_.Substring(0, actual_replacement_range.StartOffset()) +
          update_text + text_.Substring(actual_replacement_range.EndOffset());

  // Fire textupdate and textformatupdate events to JS.
  // Note the EditContext's internal selection start is a global offset while
  // selection_start is a local offset computed from the beginning of the
  // inserted string.
  SetSelection(actual_replacement_range.StartOffset() + selection_start,
               actual_replacement_range.StartOffset() + selection_end);
  DispatchTextUpdateEvent(update_text, actual_replacement_range.StartOffset(),
                          actual_replacement_range.EndOffset(),
                          selection_start_, selection_end_);

  composition_range_start_ = actual_replacement_range.StartOffset();
  composition_range_end_ =
      actual_replacement_range.StartOffset() + update_text.length();
  DispatchTextFormatEvent(ime_text_spans);
  DispatchCharacterBoundsUpdateEvent(composition_range_start_,
                                     composition_range_end_);
  return true;
}

void EditContext::ClearCompositionState() {
  has_composition_ = false;
  composition_range_start_ = 0;
  composition_range_end_ = 0;
}

uint32_t EditContext::OrderedSelectionStart() const {
  return std::min(selection_start_, selection_end_);
}

uint32_t EditContext::OrderedSelectionEnd() const {
  return std::max(selection_start_, selection_end_);
}

bool EditContext::SetCompositionFromExistingText(
    int composition_start,
    int composition_end,
    const WebVector<ui::ImeTextSpan>& ime_text_spans) {
  TRACE_EVENT1("ime", "EditContext::SetCompositionFromExistingText",
               "start, end",
               std::to_string(composition_start) + ", " +
                   std::to_string(composition_end));

  if (composition_start < 0 || composition_end < 0)
    return false;

  CHECK_GE(composition_end, composition_start);

  if (!has_composition_) {
    if (!DispatchCompositionStartEvent(""))
      return false;
    has_composition_ = true;
  }
  // composition_start and composition_end offsets are relative to the current
  // composition unit which should be smaller than the text's length.
  composition_start =
      std::min(composition_start, static_cast<int>(text_.length()));
  composition_end = std::min(composition_end, static_cast<int>(text_.length()));
  String update_text(
      text_.Substring(composition_start, composition_end - composition_start));
  if (composition_range_start_ == 0 && composition_range_end_ == 0) {
    composition_range_start_ = composition_start;
    composition_range_end_ = composition_end;
  }

  DispatchTextUpdateEvent(update_text, composition_range_start_,
                          composition_range_end_, selection_start_,
                          selection_end_);
  DispatchTextFormatEvent(ime_text_spans);
  DispatchCharacterBoundsUpdateEvent(composition_range_start_,
                                     composition_range_end_);
  return true;
}

void EditContext::CancelComposition() {
  DCHECK(has_composition_);

  // Delete the text in the composition range
  text_ = text_.Substring(0, composition_range_start_) +
          text_.Substring(composition_range_end_);

  // Place the selection where the deleted composition had been
  SetSelection(composition_range_start_, composition_range_start_);
  DispatchTextUpdateEvent(g_empty_string, composition_range_start_,
                          composition_range_end_, selection_start_,
                          selection_end_);

  DispatchTextFormatEvent(WebVector<ui::ImeTextSpan>());
  DispatchCompositionEndEvent(g_empty_string);
  ClearCompositionState();
}

bool EditContext::InsertText(const WebString& text) {
  TRACE_EVENT1("ime", "EditContext::InsertText", "text", text.Utf8());

  String update_text(text);
  text_ = text_.Substring(0, OrderedSelectionStart()) + update_text +
          text_.Substring(OrderedSelectionEnd());
  uint32_t update_range_start = OrderedSelectionStart();
  uint32_t update_range_end = OrderedSelectionEnd();
  SetSelection(OrderedSelectionStart() + update_text.length(),
               OrderedSelectionStart() + update_text.length());
  DispatchTextUpdateEvent(update_text, update_range_start, update_range_end,
                          selection_start_, selection_end_);
  return true;
}

void EditContext::DeleteCurrentSelection() {
  if (selection_start_ == selection_end_)
    return;

  StringBuilder stringBuilder;
  stringBuilder.Append(StringView(text_, 0, OrderedSelectionStart()));
  stringBuilder.Append(StringView(text_, OrderedSelectionEnd()));
  text_ = stringBuilder.ToString();

  DispatchTextUpdateEvent(g_empty_string, OrderedSelectionStart(),
                          OrderedSelectionEnd(), OrderedSelectionStart(),
                          OrderedSelectionStart());

  SetSelection(selection_start_, selection_start_);
}

template <typename StateMachine>
int FindNextBoundaryOffset(const String& str, int current);

void EditContext::DeleteBackward() {
  // If the current selection is collapsed, delete one grapheme, otherwise,
  // delete whole selection.
  if (selection_start_ == selection_end_) {
    SetSelection(FindNextBoundaryOffset<BackwardGraphemeBoundaryStateMachine>(
                     text_, selection_start_),
                 selection_end_);
  }

  DeleteCurrentSelection();
}

void EditContext::DeleteForward() {
  if (selection_start_ == selection_end_) {
    SetSelection(selection_start_,
                 FindNextBoundaryOffset<ForwardGraphemeBoundaryStateMachine>(
                     text_, selection_start_));
  }

  DeleteCurrentSelection();
}

void EditContext::DeleteWordBackward() {
  if (selection_start_ == selection_end_) {
    String text16bit(text_);
    text16bit.Ensure16Bit();
    // TODO(shihken): implement platform behaviors when the spec is finalized.
    SetSelection(FindNextWordBackward(text16bit.Span16(), selection_end_),
                 selection_end_);
  }

  DeleteCurrentSelection();
}

void EditContext::DeleteWordForward() {
  if (selection_start_ == selection_end_) {
    String text16bit(text_);
    text16bit.Ensure16Bit();
    // TODO(shihken): implement platform behaviors when the spec is finalized.
    SetSelection(selection_start_,
                 FindNextWordForward(text16bit.Span16(), selection_start_));
  }

  DeleteCurrentSelection();
}

bool EditContext::CommitText(const WebString& text,
                             const WebVector<ui::ImeTextSpan>& ime_text_spans,
                             const WebRange& replacement_range,
                             int relative_caret_position) {
  TRACE_EVENT2("ime", "EditContext::CommitText", "range, ralative_caret",
               "(" + std::to_string(replacement_range.StartOffset()) + "," +
                   std::to_string(replacement_range.EndOffset()) + ")" + ", " +
                   std::to_string(relative_caret_position),
               "text", text.Utf8());

  // Fire textupdate and textformatupdate events to JS.
  // ime_text_spans can have multiple format updates so loop through and fire
  // events accordingly.
  // Update the cached selection too.
  String update_text(text);

  WebRange actual_replacement_range = replacement_range;
  if (actual_replacement_range.IsEmpty()) {
    if (has_composition_) {
      CHECK_GE(composition_range_end_, composition_range_start_);
      actual_replacement_range =
          WebRange(composition_range_start_,
                   composition_range_end_ - composition_range_start_);
    } else {
      actual_replacement_range = GetSelectionOffsets();
    }
  }

  text_ = text_.Substring(0, actual_replacement_range.StartOffset()) +
          update_text + text_.Substring(actual_replacement_range.EndOffset());
  SetSelection(actual_replacement_range.StartOffset() + update_text.length(),
               actual_replacement_range.StartOffset() + update_text.length());

  DispatchTextUpdateEvent(update_text, actual_replacement_range.StartOffset(),
                          actual_replacement_range.EndOffset(),
                          selection_start_, selection_end_);
  // Fire composition end event.
  if (!text.IsEmpty() && has_composition_) {
    DispatchTextFormatEvent(WebVector<ui::ImeTextSpan>());
    DispatchCompositionEndEvent(text);
  }

  ClearCompositionState();
  return true;
}

bool EditContext::FinishComposingText(
    ConfirmCompositionBehavior selection_behavior) {
  TRACE_EVENT0("ime", "EditContext::FinishComposingText");
  int text_length = 0;
  if (has_composition_) {
    String text =
        text_.Substring(composition_range_start_,
                        composition_range_end_ - composition_range_start_);
    text_length = text.length();
    DispatchTextFormatEvent(WebVector<ui::ImeTextSpan>());
    DispatchCompositionEndEvent(text);
  } else {
    text_length = OrderedSelectionEnd() - OrderedSelectionStart();
  }

  if (selection_behavior == kDoNotKeepSelection) {
    SetSelection(selection_start_ + text_length, selection_end_ + text_length);
  }

  ClearCompositionState();
  return true;
}

void EditContext::ExtendSelectionAndDelete(int before, int after) {
  TRACE_EVENT1("ime", "EditContext::ExtendSelectionAndDelete", "before, after",
               std::to_string(before) + ", " + std::to_string(after));
  before = std::min(before, static_cast<int>(OrderedSelectionStart()));
  after = std::min(after, static_cast<int>(text_.length()));
  text_ = text_.Substring(0, OrderedSelectionStart() - before) +
          text_.Substring(OrderedSelectionEnd() + after);
  const uint32_t update_range_start = OrderedSelectionStart() - before;
  const uint32_t update_range_end = OrderedSelectionEnd() + after;
  SetSelection(OrderedSelectionStart() - before,
               OrderedSelectionStart() - before);
  DispatchTextUpdateEvent(g_empty_string, update_range_start, update_range_end,
                          selection_start_, selection_end_);
}

void EditContext::DeleteSurroundingText(int before, int after) {
  TRACE_EVENT1("ime", "EditContext::DeleteSurroundingText", "before, after",
               std::to_string(before) + ", " + std::to_string(after));
  const bool is_backwards_selection = selection_start_ > selection_end_;
  const uint32_t update_range_start =
      std::max(OrderedSelectionStart() - before, 0U);
  const uint32_t update_range_end =
      std::min(OrderedSelectionEnd() + after, text_.length());
  SetSelection(
      update_range_start,
      OrderedSelectionEnd() - (OrderedSelectionStart() - update_range_start));
  CHECK_GE(selection_end_, selection_start_);
  text_ = text_.Substring(0, update_range_start) +
          text_.Substring(selection_start_, selection_end_ - selection_start_) +
          text_.Substring(update_range_end);
  String update_event_text(
      text_.Substring(selection_start_, selection_end_ - selection_start_));

  if (is_backwards_selection) {
    SetSelection(selection_end_, selection_start_);
  }

  DispatchTextUpdateEvent(update_event_text, update_range_start,
                          update_range_end, selection_start_, selection_end_);
}

void EditContext::SetSelection(int start,
                               int end,
                               bool dispatch_text_update_event) {
  TRACE_EVENT1("ime", "EditContext::SetSelection", "start, end",
               std::to_string(start) + ", " + std::to_string(end));

  selection_start_ = start;
  selection_end_ = end;

  if (DomWindow() && DomWindow()->GetFrame()) {
    DomWindow()->GetFrame()->Client()->DidChangeSelection(
        /*is_selection_empty=*/selection_start_ == selection_end_,
        blink::SyncCondition::kNotForced);
  }

  if (dispatch_text_update_event) {
    DispatchTextUpdateEvent(g_empty_string, /*update_range_start=*/0,
                            /*update_range_end=*/0, selection_start_,
                            selection_end_);
  }
}

void EditContext::AttachElement(HTMLElement* element_to_attach) {
  if (base::Contains(attached_elements_, element_to_attach,
                     &Member<HTMLElement>::Get)) {
    return;
  }

  // Currently an EditContext can only have one associated element.
  // However, the spec is written with the expectation that this limit may be
  // relaxed in the future; e.g. attachedElements() returns a list. For now, the
  // EditContext implementation still uses a list of attached_elements_, but
  // this could be changed to just a single Element pointer. See
  // https://w3c.github.io/edit-context/#editcontext-interface
  CHECK(attached_elements_.empty())
      << "An EditContext can be only be associated with a single element";

  // We assume throughout this class that since EditContext is only associated
  // with at most one element, it can only have one ExecutionContext. If things
  // change such that an EditContext can be associated with multiple elements,
  // the way we manage the ExecutionContext will need to be reworked such
  // that we return the ExecutionContext of the element that has most recently
  // received focus.
  execution_context_ = element_to_attach->GetExecutionContext();

  attached_elements_.push_back(element_to_attach);
}

void EditContext::DetachElement(HTMLElement* element_to_detach) {
  auto it = base::ranges::find(attached_elements_, element_to_detach,
                               &Member<HTMLElement>::Get);

  if (it != attached_elements_.end())
    attached_elements_.erase(it);
}

WebTextInputInfo EditContext::TextInputInfo() {
  WebTextInputInfo info;
  // Fetch all the text input info from edit context.
  info.node_id = GetInputMethodController().NodeIdOfFocusedElement();
  info.action = GetInputMethodController().InputActionOfFocusedElement();
  info.input_mode = GetInputMethodController().InputModeOfFocusedElement();
  info.type = GetInputMethodController().TextInputType();
  info.virtual_keyboard_policy =
      GetInputMethodController().VirtualKeyboardPolicyOfFocusedElement();
  info.value = text();
  info.flags = GetInputMethodController().TextInputFlags();
  info.selection_start = OrderedSelectionStart();
  info.selection_end = OrderedSelectionEnd();
  if (has_composition_) {
    info.composition_start = composition_range_start_;
    info.composition_end = composition_range_end_;
  }
  return info;
}

WebRange EditContext::CompositionRange() const {
  return WebRange(composition_range_start_,
                  composition_range_end_ - composition_range_start_);
}

bool EditContext::GetCompositionCharacterBounds(WebVector<gfx::Rect>& bounds) {
  if (!HasValidCompositionBounds()) {
    return false;
  }

  TRACE_EVENT1("ime", "EditContext::GetCompositionCharacterBounds", "size",
               std::to_string(character_bounds_.size()));

  bounds.clear();
  base::ranges::for_each(
      character_bounds_, [&bounds, this](auto& bound_in_css_pixels) {
        // EditContext's coordinates are in CSS pixels, which need to be
        // converted to physical pixels before return.
        auto result_bounds = gfx::ScaleToEnclosingRect(
            bound_in_css_pixels, DomWindow()->GetFrame()->DevicePixelRatio());
        bounds.push_back(result_bounds);
        TRACE_EVENT1("ime", "EditContext::GetCompositionCharacterBounds",
                     "charBounds", result_bounds.ToString());
      });

  return true;
}

bool EditContext::FirstRectForCharacterRange(uint32_t location,
                                             uint32_t length,
                                             gfx::Rect& rect_in_viewport) {
  gfx::Rect rect_in_css_pixels;
  bool found_rect = false;

  if (HasValidCompositionBounds()) {
    WebRange range = this->CompositionRange();
    CHECK_GE(range.StartOffset(), 0);
    CHECK_GE(range.EndOffset(), 0);

    // If the requested range is within the current composition range,
    // we'll use that to provide the result.
    if (base::saturated_cast<int>(location) >= range.StartOffset() &&
        base::saturated_cast<int>(location + length) <= range.EndOffset()) {
      const size_t start_in_composition = location - range.StartOffset();
      const size_t end_in_composition = location + length - range.StartOffset();
      if (length == 0) {
        if (start_in_composition == character_bounds_.size()) {
          // Zero-width rect after the last character in the composition range
          rect_in_css_pixels =
              gfx::Rect(character_bounds_[start_in_composition - 1].right(),
                        character_bounds_[start_in_composition - 1].y(), 0,
                        character_bounds_[start_in_composition - 1].height());
        } else {
          // Zero-width rect before the next character in the composition range
          rect_in_css_pixels =
              gfx::Rect(character_bounds_[start_in_composition].x(),
                        character_bounds_[start_in_composition].y(), 0,
                        character_bounds_[start_in_composition].height());
        }
      } else {
        rect_in_css_pixels = character_bounds_[start_in_composition];
        for (size_t i = start_in_composition + 1; i < end_in_composition; ++i) {
          rect_in_css_pixels.Union(character_bounds_[i]);
        }
      }
      found_rect = true;
    }
  }

  // If we couldn't get a result from the composition bounds then we'll fall
  // back to using the selection bounds, since these will generally be close to
  // where the composition is happening.
  if (!found_rect && selection_bounds_ != gfx::Rect()) {
    rect_in_css_pixels = selection_bounds_;
    found_rect = true;
  }

  // If we have neither composition bounds nor selection bounds, we'll fall back
  // to using the control bounds. In this case the IME might not be drawn
  // exactly in the right spot, but will at least be adjacent to the editable
  // region rather than in the corner of the screen.
  if (!found_rect && control_bounds_ != gfx::Rect()) {
    rect_in_css_pixels = control_bounds_;
    found_rect = true;
  }

  if (found_rect) {
    // EditContext's coordinates are in CSS pixels, which need to be converted
    // to physical pixels before return.
    rect_in_viewport = gfx::ScaleToEnclosingRect(
        rect_in_css_pixels, DomWindow()->GetFrame()->DevicePixelRatio());
  }

  return found_rect;
}

bool EditContext::HasValidCompositionBounds() const {
  WebRange composition_range = CompositionRange();
  if (composition_range.IsEmpty()) {
    return false;
  }

  // The number of character bounds provided by the authors has to be the same
  // as the length of the composition (as we request 
"""


```