Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `style_commands.cc` file, its relation to web technologies (JavaScript, HTML, CSS), examples, common usage errors, and debugging context.

2. **Initial Scan and High-Level Understanding:**  The filename "style_commands.cc" and the included headers (`ApplyStyleCommand.h`, `EditingStyleUtilities.h`, `FrameSelection.h`, CSS-related headers, etc.) strongly suggest this file deals with applying and querying text styles within the Blink rendering engine. The copyright notices indicate a long history and contributions from various entities.

3. **Identify Key Functions and Their Purpose:** Start by reading the function signatures and their names. Look for patterns and keywords:
    * `ApplyStyle`: This seems fundamental and likely the core responsibility. It takes a `CSSPropertyValueSet` (which holds CSS properties) and applies it.
    * `Execute...`:  These functions (e.g., `ExecuteBackColor`, `ExecuteFontName`, `ExecuteToggleBold`) clearly correspond to specific styling commands. They often call `ExecuteApplyStyle` or `ExecuteToggleStyle`.
    * `State...`: Functions like `StateBold`, `StateItalic` suggest querying the current style state.
    * `Value...`: Functions like `ValueBackColor`, `ValueFontName` likely retrieve the current style values.
    * `TextDirection...`:  These functions deal with text directionality (LTR/RTL).

4. **Analyze Core Logic (ApplyStyle):**  The `ApplyStyle` function handles both caret (insertion point) and range selections. For carets, it sets the "typing style" (the style that will be applied to the next typed characters). For ranges, it creates an `ApplyStyleCommand` and executes it. This command pattern is a common way to encapsulate actions within an undo/redo framework.

5. **Analyze Specific Command Handlers (Execute...):**
    * Notice how `ExecuteBackColor`, `ExecuteForeColor`, `ExecuteFontName` directly call `ExecuteApplyStyle` with the corresponding CSS property ID and provided value.
    * `ExecuteFontSize` has a conversion step using `HTMLFontElement::CssValueFromFontSizeNumber`. This suggests handling legacy `<font>` tag sizes.
    * `ExecuteToggleBold`, `ExecuteToggleItalic`, etc., use `ExecuteToggleStyle`, which checks the current state and applies the opposite style.
    * The text direction commands (`ExecuteMakeTextWritingDirection...`) directly set `unicode-bidi` and `direction` CSS properties.
    * The list manipulation functions (`ExecuteToggleStyleInList`) demonstrate handling CSS properties that can have multiple values (like `text-decoration`).

6. **Analyze State and Value Functions:**
    * `State...` functions often call `SelectionStartHasStyle` (or `EditingStyle::SelectionHasStyle`) to determine if a style is present. The logic might differ slightly depending on the platform (Mac vs. others) for toggling styles.
    * `Value...` functions usually call `SelectionStartCSSPropertyValue` to get the current value of a CSS property at the beginning of the selection.

7. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:**  JavaScript can trigger these commands through the `document.execCommand()` method. The command names in JavaScript often map directly to the `Execute...` function names (e.g., `document.execCommand('bold')` would trigger `ExecuteToggleBold`).
    * **HTML:**  HTML elements and attributes define the structure and initial styles. The styling applied by these commands modifies the rendered output of HTML. The example of the `<font>` tag in `ExecuteFontSize` is a direct HTML connection.
    * **CSS:** The core of this file revolves around CSS properties and values. The code manipulates `CSSPropertyValueSet` objects and uses CSS property IDs extensively. The examples of toggling `font-weight`, `font-style`, `text-decoration`, etc., are direct CSS manipulations.

8. **Identify Potential Usage Errors:** Think about how a developer or user might interact with these commands and what could go wrong:
    * Providing invalid CSS values (e.g., a non-numeric value for `font-size`).
    * Calling commands when the selection is empty or in a non-editable area.
    * Issues with conflicting styles or how toggling works.
    * Incorrectly assuming how `document.execCommand()` maps to these internal functions.

9. **Consider Debugging Scenarios:**  How would a developer end up in this code?
    * Setting breakpoints in the `Execute...` functions when investigating styling issues triggered by `document.execCommand()`.
    * Tracing the execution flow from a JavaScript call to `document.execCommand()`.
    * Inspecting the values of `CSSPropertyValueSet` during debugging.

10. **Structure the Answer:** Organize the findings logically:
    * Start with a concise summary of the file's purpose.
    * Group related functionalities (applying styles, toggling styles, querying state, getting values).
    * Clearly explain the relationship with JavaScript, HTML, and CSS, providing specific examples.
    * Dedicate sections to logical reasoning (input/output), common errors, and debugging.

11. **Refine and Elaborate:**  Review the generated answer, adding more detail and clarity where needed. Ensure the examples are concrete and easy to understand. For instance, explicitly mention `document.execCommand()` as the primary JavaScript entry point.

By following these steps, a comprehensive understanding of the `style_commands.cc` file and its role within the Chromium rendering engine can be achieved. The process involves a combination of code reading, pattern recognition, logical deduction, and knowledge of web technologies.
这个文件 `blink/renderer/core/editing/commands/style_commands.cc` 是 Chromium Blink 引擎中负责处理与 **文本样式** 相关的编辑命令的核心组件。它的主要功能是：

**1. 应用和修改文本样式:**

*   **核心功能:** 提供各种命令来应用和修改选定文本或插入符位置的样式。这些样式包括字体、颜色、大小、粗体、斜体、下划线、删除线、上标、下标、文本方向等。
*   **与 CSS 的关系非常密切:** 它通过操作内部的 CSS 属性来改变文本样式。例如，`ExecuteBold` 函数会修改 `font-weight` 属性，`ExecuteForeColor` 会修改 `color` 属性。
*   **与 HTML 的关系:** 这些命令通常是用户在富文本编辑器中操作（例如，点击“加粗”按钮）或通过 JavaScript 调用 `document.execCommand()` 方法触发的。它们最终会影响 HTML 元素的样式属性或通过创建新的 HTML 元素（例如 `<b>` 或 `<span>`）来应用样式。

**2. 查询文本样式状态:**

*   **功能:** 提供方法来查询当前选中文本或插入符位置的样式状态。例如，判断当前选中文本是否加粗、斜体等。
*   **与 CSS 的关系:**  通过读取和分析当前元素的计算样式（computed style）来确定样式状态。例如，`StateBold` 函数会检查 `font-weight` 属性的值是否为 "bold"。

**3. 处理文本方向:**

*   **功能:** 提供命令来设置和查询文本的书写方向（从左到右 LTR 或从右到左 RTL）。
*   **与 CSS 的关系:**  通过设置 `direction` 和 `unicode-bidi` CSS 属性来实现。

**4. 与 JavaScript 和 HTML 的关系举例说明:**

*   **JavaScript 触发样式修改:**
    ```javascript
    document.execCommand('bold', false, null); // 切换选中文本的粗体
    document.execCommand('foreColor', false, 'red'); // 将选中文本颜色设置为红色
    ```
    当 JavaScript 调用 `document.execCommand()` 并传入像 'bold' 或 'foreColor' 这样的命令时，Blink 引擎会找到 `style_commands.cc` 中对应的 `ExecuteToggleBold` 或 `ExecuteForeColor` 函数来执行。

*   **HTML 元素和样式:**
    假设 HTML 中有以下内容：
    ```html
    <p>这是一段 <span style="font-weight: bold;">加粗</span> 的文字。</p>
    ```
    当用户选中 "加粗" 这两个字时，`style_commands.cc` 中的 `StateBold` 函数会检查该选中区域的样式，发现 `font-weight` 为 "bold"，从而返回 "true"。

*   **CSS 样式规则影响:**
    页面上的 CSS 样式规则会影响文本的初始样式。`style_commands.cc` 中的函数在应用新样式时，会考虑已存在的 CSS 规则，并可能创建内联样式或修改已有的样式。

**5. 逻辑推理举例说明:**

*   **假设输入:** 用户选中一段文本 "hello"，然后点击了 "加粗" 按钮。
*   **执行流程:**
    1. 浏览器 UI 捕获到 "加粗" 操作。
    2. JavaScript 调用 `document.execCommand('bold', false, null)` (可能由框架或浏览器内部处理)。
    3. Blink 引擎找到 `StyleCommands::ExecuteToggleBold` 函数。
    4. `ExecuteToggleBold` 调用 `StyleCommands::ExecuteToggleStyle`，并传入 `CSSPropertyID::kFontWeight`, "normal", "bold"。
    5. `ExecuteToggleStyle` 检测到当前选中文本的 `font-weight` 不是 "bold" (假设是 "normal" 或没有设置)。
    6. `ExecuteToggleStyle` 创建一个 `CSSPropertyValueSet` 对象，并将 `font-weight` 设置为 "bold"。
    7. `ExecuteToggleStyle` 调用 `StyleCommands::ApplyCommandToFrame`，最终调用 `StyleCommands::ApplyStyle`。
    8. `ApplyStyle` 创建 `ApplyStyleCommand` 来实际修改 DOM 结构和样式，例如将选中文本包裹在 `<b>` 标签中或者添加内联样式 `style="font-weight: bold;"`。
*   **输出:**  选中的文本 "hello" 在页面上显示为粗体。

**6. 用户或编程常见的使用错误举例说明:**

*   **错误地假设 `document.execCommand` 的行为:** 开发者可能错误地认为某些命令会直接修改 HTML 结构，而实际上它可能只是修改样式。例如，一些旧的浏览器或编辑器可能使用 `<b>` 标签来实现加粗，而现代浏览器更倾向于使用 `font-weight: bold`。
*   **在非可编辑区域执行命令:** 如果尝试在用户无法编辑的区域（例如，静态文本内容）执行样式修改命令，这些命令通常不会生效，或者可能会抛出错误（取决于浏览器的实现）。
*   **与内容安全策略 (CSP) 的冲突:** 如果 CSP 阻止了内联样式的应用，那么通过 `style_commands.cc` 应用的某些样式可能无法生效。
*   **与富文本编辑器的状态不一致:**  开发者在自定义富文本编辑器时，可能没有正确同步编辑器的状态和 `document.execCommand` 的行为，导致样式应用出现意外。

**7. 用户操作如何一步步的到达这里，作为调试线索:**

以下是一些用户操作可能触发 `style_commands.cc` 中的代码，以及如何作为调试线索：

1. **用户在富文本编辑器中点击样式按钮 (例如 "加粗", "斜体", "颜色"):**
    *   **调试线索:** 在浏览器开发者工具中设置断点在 `StyleCommands::ExecuteToggleBold` 或 `StyleCommands::ExecuteForeColor` 等函数上，观察函数是否被调用，以及传入的参数。检查 `frame` 参数，确认是预期的 `LocalFrame` 对象。

2. **用户使用快捷键 (例如 Ctrl+B, Ctrl+I):**
    *   **调试线索:**  追踪浏览器的快捷键处理逻辑，通常会映射到特定的编辑命令。在 `ExecuteToggleBold` 等函数设置断点，确认快捷键操作最终调用了这些函数。

3. **JavaScript 代码调用 `document.execCommand()`:**
    *   **调试线索:**  在 JavaScript 代码中设置断点，查看 `document.execCommand()` 的调用参数。然后在 `style_commands.cc` 中对应的 `Execute...` 函数设置断点，确认 JavaScript 的调用是否正确地触发了 Blink 引擎的命令处理。

4. **用户进行粘贴操作，并保留了样式:**
    *   **调试线索:**  粘贴操作涉及到对粘贴内容的解析和样式应用。可以尝试在与粘贴相关的命令处理函数（可能不在 `style_commands.cc` 中，但会调用它）设置断点，逐步跟踪样式是如何被应用的。

5. **浏览器内部某些功能自动应用样式 (例如，自动链接检测):**
    *   **调试线索:**  这通常发生在 Blink 引擎的更底层。可以尝试在与文本渲染和布局相关的代码中设置断点，或者搜索与自动样式应用相关的代码路径。

**总结:**

`blink/renderer/core/editing/commands/style_commands.cc` 文件是 Blink 引擎中处理文本样式编辑命令的关键部分。它连接了用户操作、JavaScript API (特别是 `document.execCommand`) 和底层的 CSS 属性操作，负责应用、修改和查询文本的各种样式。理解这个文件的功能对于理解浏览器如何处理富文本编辑至关重要，并且在调试相关的渲染和编辑问题时非常有价值。

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/style_commands.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2006, 2007, 2008 Apple Inc. All rights reserved.
 * Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2009 Igalia S.L.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/commands/style_commands.h"

#include "mojo/public/mojom/base/text_direction.mojom-blink.h"
#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/editing/commands/apply_style_command.h"
#include "third_party/blink/renderer/core/editing/editing_behavior.h"
#include "third_party/blink/renderer/core/editing/editing_style_utilities.h"
#include "third_party/blink/renderer/core/editing/editing_tri_state.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_font_element.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

void StyleCommands::ApplyStyle(LocalFrame& frame,
                               CSSPropertyValueSet* style,
                               InputEvent::InputType input_type) {
  const VisibleSelection& selection =
      frame.Selection().ComputeVisibleSelectionInDOMTreeDeprecated();
  if (selection.IsNone())
    return;
  if (selection.IsCaret()) {
    frame.GetEditor().ComputeAndSetTypingStyle(style, input_type);
    return;
  }
  DCHECK(selection.IsRange()) << selection;
  if (!style)
    return;
  DCHECK(frame.GetDocument());
  MakeGarbageCollected<ApplyStyleCommand>(
      *frame.GetDocument(), MakeGarbageCollected<EditingStyle>(style),
      input_type)
      ->Apply();
}

void StyleCommands::ApplyStyleToSelection(LocalFrame& frame,
                                          CSSPropertyValueSet* style,
                                          InputEvent::InputType input_type) {
  if (!style || style->IsEmpty() || !frame.GetEditor().CanEditRichly())
    return;

  ApplyStyle(frame, style, input_type);
}

bool StyleCommands::ApplyCommandToFrame(LocalFrame& frame,
                                        EditorCommandSource source,
                                        InputEvent::InputType input_type,
                                        CSSPropertyValueSet* style) {
  // TODO(editing-dev): We don't call shouldApplyStyle when the source is DOM;
  // is there a good reason for that?
  switch (source) {
    case EditorCommandSource::kMenuOrKeyBinding:
      ApplyStyleToSelection(frame, style, input_type);
      return true;
    case EditorCommandSource::kDOM:
      ApplyStyle(frame, style, input_type);
      return true;
  }
  NOTREACHED();
}

bool StyleCommands::ExecuteApplyStyle(LocalFrame& frame,
                                      EditorCommandSource source,
                                      InputEvent::InputType input_type,
                                      CSSPropertyID property_id,
                                      const String& property_value) {
  DCHECK(frame.GetDocument());
  auto* const style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  style->ParseAndSetProperty(property_id, property_value, /* important */ false,
                             frame.DomWindow()->GetSecureContextMode());
  return ApplyCommandToFrame(frame, source, input_type, style);
}

bool StyleCommands::ExecuteApplyStyle(LocalFrame& frame,
                                      EditorCommandSource source,
                                      InputEvent::InputType input_type,
                                      CSSPropertyID property_id,
                                      CSSValueID property_value) {
  auto* const style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  style->SetLonghandProperty(property_id, property_value);
  return ApplyCommandToFrame(frame, source, input_type, style);
}

bool StyleCommands::ExecuteBackColor(LocalFrame& frame,
                                     Event*,
                                     EditorCommandSource source,
                                     const String& value) {
  return ExecuteApplyStyle(frame, source, InputEvent::InputType::kNone,
                           CSSPropertyID::kBackgroundColor, value);
}

bool StyleCommands::ExecuteForeColor(LocalFrame& frame,
                                     Event*,
                                     EditorCommandSource source,
                                     const String& value) {
  return ExecuteApplyStyle(frame, source, InputEvent::InputType::kNone,
                           CSSPropertyID::kColor, value);
}

bool StyleCommands::ExecuteFontName(LocalFrame& frame,
                                    Event*,
                                    EditorCommandSource source,
                                    const String& value) {
  return ExecuteApplyStyle(frame, source, InputEvent::InputType::kNone,
                           CSSPropertyID::kFontFamily, value);
}

bool StyleCommands::ExecuteFontSize(LocalFrame& frame,
                                    Event*,
                                    EditorCommandSource source,
                                    const String& value) {
  CSSValueID size;
  if (!HTMLFontElement::CssValueFromFontSizeNumber(value, size))
    return false;
  return ExecuteApplyStyle(frame, source, InputEvent::InputType::kNone,
                           CSSPropertyID::kFontSize, size);
}

bool StyleCommands::ExecuteFontSizeDelta(LocalFrame& frame,
                                         Event*,
                                         EditorCommandSource source,
                                         const String& value) {
  // TODO(hjkim3323@gmail.com): Directly set EditingStyle::font_size_delta_
  // instead of setting it via CSS property
  return ExecuteApplyStyle(frame, source, InputEvent::InputType::kNone,
                           CSSPropertyID::kInternalFontSizeDelta, value);
}

bool StyleCommands::ExecuteMakeTextWritingDirectionLeftToRight(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  auto* const style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  style->SetLonghandProperty(CSSPropertyID::kUnicodeBidi, CSSValueID::kIsolate);
  style->SetLonghandProperty(CSSPropertyID::kDirection, CSSValueID::kLtr);
  ApplyStyle(frame, style, InputEvent::InputType::kFormatSetBlockTextDirection);
  return true;
}

bool StyleCommands::ExecuteMakeTextWritingDirectionNatural(LocalFrame& frame,
                                                           Event*,
                                                           EditorCommandSource,
                                                           const String&) {
  auto* const style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  style->SetLonghandProperty(CSSPropertyID::kUnicodeBidi, CSSValueID::kNormal);
  ApplyStyle(frame, style, InputEvent::InputType::kFormatSetBlockTextDirection);
  return true;
}

bool StyleCommands::ExecuteMakeTextWritingDirectionRightToLeft(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  auto* const style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  style->SetLonghandProperty(CSSPropertyID::kUnicodeBidi, CSSValueID::kIsolate);
  style->SetLonghandProperty(CSSPropertyID::kDirection, CSSValueID::kRtl);
  ApplyStyle(frame, style, InputEvent::InputType::kFormatSetBlockTextDirection);
  return true;
}

bool StyleCommands::SelectionStartHasStyle(LocalFrame& frame,
                                           CSSPropertyID property_id,
                                           const String& value) {
  const SecureContextMode secure_context_mode =
      frame.DomWindow()->GetSecureContextMode();

  EditingStyle* const style_to_check = MakeGarbageCollected<EditingStyle>(
      property_id, value, secure_context_mode);
  EditingStyle* const style_at_start =
      EditingStyleUtilities::CreateStyleAtSelectionStart(
          frame.Selection().ComputeVisibleSelectionInDOMTreeDeprecated(),
          property_id == CSSPropertyID::kBackgroundColor,
          style_to_check->Style());
  return style_to_check->TriStateOfStyle(frame.DomWindow(), style_at_start,
                                         secure_context_mode) !=
         EditingTriState::kFalse;
}

bool StyleCommands::ExecuteToggleStyle(LocalFrame& frame,
                                       EditorCommandSource source,
                                       InputEvent::InputType input_type,
                                       CSSPropertyID property_id,
                                       const char* off_value,
                                       const char* on_value) {
  // Style is considered present when
  // Mac: present at the beginning of selection
  // other: present throughout the selection
  const bool style_is_present =
      frame.GetEditor().Behavior().ShouldToggleStyleBasedOnStartOfSelection()
          ? SelectionStartHasStyle(frame, property_id, on_value)
          : EditingStyle::SelectionHasStyle(frame, property_id, on_value) ==
                EditingTriState::kTrue;

  EditingStyle* const style = MakeGarbageCollected<EditingStyle>(
      property_id, style_is_present ? off_value : on_value,
      frame.DomWindow()->GetSecureContextMode());
  return ApplyCommandToFrame(frame, source, input_type, style->Style());
}

bool StyleCommands::ExecuteToggleBold(LocalFrame& frame,
                                      Event*,
                                      EditorCommandSource source,
                                      const String&) {
  return ExecuteToggleStyle(frame, source, InputEvent::InputType::kFormatBold,
                            CSSPropertyID::kFontWeight, "normal", "bold");
}

bool StyleCommands::ExecuteToggleItalic(LocalFrame& frame,
                                        Event*,
                                        EditorCommandSource source,
                                        const String&) {
  return ExecuteToggleStyle(frame, source, InputEvent::InputType::kFormatItalic,
                            CSSPropertyID::kFontStyle, "normal", "italic");
}

bool StyleCommands::ExecuteSubscript(LocalFrame& frame,
                                     Event*,
                                     EditorCommandSource source,
                                     const String&) {
  return ExecuteToggleStyle(frame, source,
                            InputEvent::InputType::kFormatSubscript,
                            CSSPropertyID::kVerticalAlign, "baseline", "sub");
}

bool StyleCommands::ExecuteSuperscript(LocalFrame& frame,
                                       Event*,
                                       EditorCommandSource source,
                                       const String&) {
  return ExecuteToggleStyle(frame, source,
                            InputEvent::InputType::kFormatSuperscript,
                            CSSPropertyID::kVerticalAlign, "baseline", "super");
}

bool StyleCommands::ExecuteUnscript(LocalFrame& frame,
                                    Event*,
                                    EditorCommandSource source,
                                    const String&) {
  return ExecuteApplyStyle(frame, source, InputEvent::InputType::kNone,
                           CSSPropertyID::kVerticalAlign, "baseline");
}

String StyleCommands::ComputeToggleStyleInList(EditingStyle& selection_style,
                                               CSSPropertyID property_id,
                                               const CSSValue& value) {
  const CSSValue& selected_css_value =
      *selection_style.Style()->GetPropertyCSSValue(property_id);
  if (auto* selected_value_list_original =
          DynamicTo<CSSValueList>(selected_css_value)) {
    CSSValueList& selected_css_value_list =
        *selected_value_list_original->Copy();
    if (!selected_css_value_list.RemoveAll(value))
      selected_css_value_list.Append(value);
    if (selected_css_value_list.length())
      return selected_css_value_list.CssText();
  } else if (selected_css_value.CssText() == "none") {
    return value.CssText();
  }
  return "none";
}

bool StyleCommands::ExecuteToggleStyleInList(LocalFrame& frame,
                                             EditorCommandSource source,
                                             InputEvent::InputType input_type,
                                             CSSPropertyID property_id,
                                             const CSSValue& value) {
  EditingStyle* const selection_style =
      EditingStyleUtilities::CreateStyleAtSelectionStart(
          frame.Selection().ComputeVisibleSelectionInDOMTree());
  if (!selection_style || !selection_style->Style())
    return false;

  const String new_style =
      ComputeToggleStyleInList(*selection_style, property_id, value);

  // TODO(editing-dev): We shouldn't be having to convert new style into text.
  // We should have setPropertyCSSValue.
  auto* const new_mutable_style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  new_mutable_style->ParseAndSetProperty(
      property_id, new_style, /* important */ false,
      frame.DomWindow()->GetSecureContextMode());
  return ApplyCommandToFrame(frame, source, input_type, new_mutable_style);
}

bool StyleCommands::ExecuteStrikethrough(LocalFrame& frame,
                                         Event*,
                                         EditorCommandSource source,
                                         const String&) {
  const CSSIdentifierValue& line_through =
      *CSSIdentifierValue::Create(CSSValueID::kLineThrough);
  return ExecuteToggleStyleInList(
      frame, source, InputEvent::InputType::kFormatStrikeThrough,
      CSSPropertyID::kWebkitTextDecorationsInEffect, line_through);
}

bool StyleCommands::ExecuteUnderline(LocalFrame& frame,
                                     Event*,
                                     EditorCommandSource source,
                                     const String&) {
  const CSSIdentifierValue& underline =
      *CSSIdentifierValue::Create(CSSValueID::kUnderline);
  return ExecuteToggleStyleInList(
      frame, source, InputEvent::InputType::kFormatUnderline,
      CSSPropertyID::kWebkitTextDecorationsInEffect, underline);
}

bool StyleCommands::ExecuteStyleWithCSS(LocalFrame& frame,
                                        Event*,
                                        EditorCommandSource,
                                        const String& value) {
  frame.GetEditor().SetShouldStyleWithCSS(
      !EqualIgnoringASCIICase(value, "false"));
  return true;
}

bool StyleCommands::ExecuteUseCSS(LocalFrame& frame,
                                  Event*,
                                  EditorCommandSource,
                                  const String& value) {
  frame.GetEditor().SetShouldStyleWithCSS(
      EqualIgnoringASCIICase(value, "false"));
  return true;
}

// State functions
EditingTriState StyleCommands::StateStyle(LocalFrame& frame,
                                          CSSPropertyID property_id,
                                          const char* desired_value) {
  if (frame.GetInputMethodController().GetActiveEditContext()) {
    return EditingTriState::kFalse;
  }

  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  if (frame.GetEditor().Behavior().ShouldToggleStyleBasedOnStartOfSelection()) {
    return SelectionStartHasStyle(frame, property_id, desired_value)
               ? EditingTriState::kTrue
               : EditingTriState::kFalse;
  }
  return EditingStyle::SelectionHasStyle(frame, property_id, desired_value);
}

EditingTriState StyleCommands::StateBold(LocalFrame& frame, Event*) {
  return StateStyle(frame, CSSPropertyID::kFontWeight, "bold");
}

EditingTriState StyleCommands::StateItalic(LocalFrame& frame, Event*) {
  return StateStyle(frame, CSSPropertyID::kFontStyle, "italic");
}

EditingTriState StyleCommands::StateStrikethrough(LocalFrame& frame, Event*) {
  return StateStyle(frame, CSSPropertyID::kWebkitTextDecorationsInEffect,
                    "line-through");
}

EditingTriState StyleCommands::StateStyleWithCSS(LocalFrame& frame, Event*) {
  if (frame.GetInputMethodController().GetActiveEditContext()) {
    return EditingTriState::kFalse;
  }

  return frame.GetEditor().ShouldStyleWithCSS() ? EditingTriState::kTrue
                                                : EditingTriState::kFalse;
}

EditingTriState StyleCommands::StateSubscript(LocalFrame& frame, Event*) {
  return StateStyle(frame, CSSPropertyID::kVerticalAlign, "sub");
}

EditingTriState StyleCommands::StateSuperscript(LocalFrame& frame, Event*) {
  return StateStyle(frame, CSSPropertyID::kVerticalAlign, "super");
}

bool StyleCommands::IsUnicodeBidiNestedOrMultipleEmbeddings(
    CSSValueID value_id) {
  return value_id == CSSValueID::kEmbed ||
         value_id == CSSValueID::kBidiOverride ||
         value_id == CSSValueID::kWebkitIsolate ||
         value_id == CSSValueID::kWebkitIsolateOverride ||
         value_id == CSSValueID::kWebkitPlaintext ||
         value_id == CSSValueID::kIsolate ||
         value_id == CSSValueID::kIsolateOverride ||
         value_id == CSSValueID::kPlaintext;
}

mojo_base::mojom::blink::TextDirection StyleCommands::TextDirectionForSelection(
    const VisibleSelection& selection,
    EditingStyle* typing_style,
    bool& has_nested_or_multiple_embeddings) {
  has_nested_or_multiple_embeddings = true;

  if (selection.IsNone())
    return mojo_base::mojom::blink::TextDirection::UNKNOWN_DIRECTION;

  const Position position = MostForwardCaretPosition(selection.Start());

  const Node* anchor_node = position.AnchorNode();
  if (!anchor_node)
    return mojo_base::mojom::blink::TextDirection::UNKNOWN_DIRECTION;

  Position end;
  if (selection.IsRange()) {
    end = MostBackwardCaretPosition(selection.End());

    DCHECK(end.GetDocument());
    const EphemeralRange caret_range(position.ParentAnchoredEquivalent(),
                                     end.ParentAnchoredEquivalent());
    for (Node& node : caret_range.Nodes()) {
      if (!node.IsStyledElement())
        continue;

      Element& element = To<Element>(node);
      const CSSComputedStyleDeclaration& style =
          *MakeGarbageCollected<CSSComputedStyleDeclaration>(&element);
      const CSSValue* unicode_bidi =
          style.GetPropertyCSSValue(CSSPropertyID::kUnicodeBidi);
      auto* unicode_bidi_identifier_value =
          DynamicTo<CSSIdentifierValue>(unicode_bidi);
      if (!unicode_bidi_identifier_value)
        continue;

      const CSSValueID unicode_bidi_value =
          unicode_bidi_identifier_value->GetValueID();
      if (IsUnicodeBidiNestedOrMultipleEmbeddings(unicode_bidi_value))
        return mojo_base::mojom::blink::TextDirection::UNKNOWN_DIRECTION;
    }
  }

  if (selection.IsCaret()) {
    mojo_base::mojom::blink::TextDirection direction;
    if (typing_style && typing_style->GetTextDirection(direction)) {
      has_nested_or_multiple_embeddings = false;
      return direction;
    }
    anchor_node = selection.VisibleStart().DeepEquivalent().AnchorNode();
  }
  DCHECK(anchor_node);

  // The selection is either a caret with no typing attributes or a range in
  // which no embedding is added, so just use the start position to decide.
  const Node* block = EnclosingBlock(anchor_node);
  mojo_base::mojom::blink::TextDirection found_direction =
      mojo_base::mojom::blink::TextDirection::UNKNOWN_DIRECTION;

  for (Node& runner : NodeTraversal::InclusiveAncestorsOf(*anchor_node)) {
    if (runner == block)
      break;
    if (!runner.IsStyledElement())
      continue;

    auto* element = To<Element>(&runner);
    const CSSComputedStyleDeclaration& style =
        *MakeGarbageCollected<CSSComputedStyleDeclaration>(element);
    const CSSValue* unicode_bidi =
        style.GetPropertyCSSValue(CSSPropertyID::kUnicodeBidi);
    auto* unicode_bidi_identifier_value =
        DynamicTo<CSSIdentifierValue>(unicode_bidi);
    if (!unicode_bidi_identifier_value)
      continue;

    const CSSValueID unicode_bidi_value =
        unicode_bidi_identifier_value->GetValueID();
    if (unicode_bidi_value == CSSValueID::kNormal)
      continue;

    if (unicode_bidi_value == CSSValueID::kBidiOverride)
      return mojo_base::mojom::blink::TextDirection::UNKNOWN_DIRECTION;

    DCHECK(EditingStyleUtilities::IsEmbedOrIsolate(unicode_bidi_value))
        << static_cast<int>(unicode_bidi_value);
    const CSSValue* direction =
        style.GetPropertyCSSValue(CSSPropertyID::kDirection);
    auto* direction_identifier_value = DynamicTo<CSSIdentifierValue>(direction);
    if (!direction_identifier_value)
      continue;

    const CSSValueID direction_value = direction_identifier_value->GetValueID();
    if (direction_value != CSSValueID::kLtr &&
        direction_value != CSSValueID::kRtl)
      continue;

    if (found_direction !=
        mojo_base::mojom::blink::TextDirection::UNKNOWN_DIRECTION)
      return mojo_base::mojom::blink::TextDirection::UNKNOWN_DIRECTION;

    // In the range case, make sure that the embedding element persists until
    // the end of the range.
    if (selection.IsRange() && !end.AnchorNode()->IsDescendantOf(element))
      return mojo_base::mojom::blink::TextDirection::UNKNOWN_DIRECTION;

    found_direction =
        direction_value == CSSValueID::kLtr
            ? mojo_base::mojom::blink::TextDirection::LEFT_TO_RIGHT
            : mojo_base::mojom::blink::TextDirection::RIGHT_TO_LEFT;
  }
  has_nested_or_multiple_embeddings = false;
  return found_direction;
}

EditingTriState StyleCommands::StateTextWritingDirection(
    LocalFrame& frame,
    mojo_base::mojom::blink::TextDirection direction) {
  if (frame.GetInputMethodController().GetActiveEditContext()) {
    return EditingTriState::kFalse;
  }

  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  bool has_nested_or_multiple_embeddings;
  mojo_base::mojom::blink::TextDirection selection_direction =
      TextDirectionForSelection(
          frame.Selection().ComputeVisibleSelectionInDOMTreeDeprecated(),
          frame.GetEditor().TypingStyle(), has_nested_or_multiple_embeddings);
  // TODO(editing-dev): We should be returning MixedTriState when
  // selectionDirection == direction && hasNestedOrMultipleEmbeddings
  return (selection_direction == direction &&
          !has_nested_or_multiple_embeddings)
             ? EditingTriState::kTrue
             : EditingTriState::kFalse;
}

EditingTriState StyleCommands::StateTextWritingDirectionLeftToRight(
    LocalFrame& frame,
    Event*) {
  return StateTextWritingDirection(
      frame, mojo_base::mojom::blink::TextDirection::LEFT_TO_RIGHT);
}

EditingTriState StyleCommands::StateTextWritingDirectionNatural(
    LocalFrame& frame,
    Event*) {
  return StateTextWritingDirection(
      frame, mojo_base::mojom::blink::TextDirection::UNKNOWN_DIRECTION);
}

EditingTriState StyleCommands::StateTextWritingDirectionRightToLeft(
    LocalFrame& frame,
    Event*) {
  return StateTextWritingDirection(
      frame, mojo_base::mojom::blink::TextDirection::RIGHT_TO_LEFT);
}

EditingTriState StyleCommands::StateUnderline(LocalFrame& frame, Event*) {
  return StateStyle(frame, CSSPropertyID::kWebkitTextDecorationsInEffect,
                    "underline");
}

// Value functions
String StyleCommands::SelectionStartCSSPropertyValue(
    LocalFrame& frame,
    CSSPropertyID property_id) {
  EditingStyle* const selection_style =
      EditingStyleUtilities::CreateStyleAtSelectionStart(
          frame.Selection().ComputeVisibleSelectionInDOMTreeDeprecated(),
          property_id == CSSPropertyID::kBackgroundColor);
  if (!selection_style || !selection_style->Style())
    return String();

  if (property_id == CSSPropertyID::kFontSize)
    return String::Number(selection_style->LegacyFontSize(frame.GetDocument()));
  return selection_style->Style()->GetPropertyValue(property_id);
}

String StyleCommands::ValueStyle(LocalFrame& frame, CSSPropertyID property_id) {
  if (frame.GetInputMethodController().GetActiveEditContext()) {
    return g_empty_string;
  }

  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  // TODO(editing-dev): Rather than retrieving the style at the start of the
  // current selection, we should retrieve the style present throughout the
  // selection for non-Mac platforms.
  return SelectionStartCSSPropertyValue(frame, property_id);
}

String StyleCommands::ValueBackColor(const EditorInternalCommand&,
                                     LocalFrame& frame,
                                     Event*) {
  return ValueStyle(frame, CSSPropertyID::kBackgroundColor);
}

String StyleCommands::ValueForeColor(const EditorInternalCommand&,
                                     LocalFrame& frame,
                                     Event*) {
  return ValueStyle(frame, CSSPropertyID::kColor);
}

String StyleCommands::ValueFontName(const EditorInternalCommand&,
                                    LocalFrame& frame,
                                    Event*) {
  return ValueStyle(frame, CSSPropertyID::kFontFamily);
}

String StyleCommands::ValueFontSize(const EditorInternalCommand&,
                                    LocalFrame& frame,
                                    Event*) {
  return ValueStyle(frame, CSSPropertyID::kFontSize);
}

String StyleCommands::ValueFontSizeDelta(const EditorInternalCommand&,
                                         LocalFrame& frame,
                                         Event*) {
  return ValueStyle(frame, CSSPropertyID::kInternalFontSizeDelta);
}

}  // namespace blink

"""

```