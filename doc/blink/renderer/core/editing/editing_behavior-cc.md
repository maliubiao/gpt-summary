Response:
Let's break down the thought process for analyzing the `editing_behavior.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to web technologies (HTML, CSS, JS), examples, logical reasoning, common errors, and debugging steps.

2. **Initial Code Scan (Keywords and Structure):**  I'd first quickly scan the code looking for keywords and structural elements that give clues about its purpose:
    * `#include`:  Indicates dependencies on other modules. `web_input_event.h`, `web_settings.h`, `keyboard_event.h`, `keyboard_codes.h` strongly suggest it deals with keyboard input and how it affects the editor.
    * `namespace blink`: Confirms this is part of the Blink rendering engine.
    * `struct KeyboardCodeKeyDownEntry`, `struct KeyboardCodeKeyPressEntry`, `struct DomKeyKeyDownEntry`:  These structures clearly define mappings between keyboard events (key down, key press) and actions (represented by strings like "MoveLeft", "ToggleBold", etc.). This is a central piece of the file's functionality.
    * `InterpretKeyEvent`: This function name is highly suggestive. It likely takes a keyboard event and determines the corresponding editor command.
    * `ShouldInsertCharacter`:  Another key function name indicating a decision-making process about whether a character should be inserted.
    * Conditional compilation (`#if BUILDFLAG(...)`): Shows OS-specific handling of keyboard shortcuts and behavior. This hints at platform differences in how editing is managed.
    * Comments:  The initial copyright notice and comments like "The below code was adapted from the WebKit file webview.cpp" provide context.

3. **Deciphering the Core Logic (Mapping Keyboard Events to Actions):**  The core of the file lies in the `kKeyboardCodeKeyDownEntries`, `kKeyboardCodeKeyPressEntries`, and `kDomKeyKeyDownEntries` arrays and the `InterpretKeyEvent` function.

    * **Mapping Arrays:** These arrays are lookup tables. Each entry maps a combination of key code (like `VKEY_LEFT`) and modifiers (like `kCtrlKey`, `kShiftKey`) to a specific editor command name (e.g., "MoveLeft"). The `DomKeyKeyDownEntry` uses the `key` string from the DOM event.
    * **`InterpretKeyEvent`:** This function performs the lookup. It takes a `KeyboardEvent`, extracts the key code and modifiers, and then searches the mapping arrays for a matching entry. It handles both `keydown` and `keypress` events. The `TransposeArrowKey` function indicates that the meaning of arrow keys can change based on the writing direction (important for internationalization).
    * **`LookupCommandNameFromDomKeyKeyDown`:** A helper function for looking up commands based on the `DomKey`.

4. **Relating to Web Technologies:**  Now, connect the file's functionality to HTML, CSS, and JavaScript:

    * **HTML:** The editing behavior directly affects how users interact with `contenteditable` elements in HTML. The commands defined in this file are the underlying actions that occur when a user types, deletes, or uses keyboard shortcuts in an editable area.
    * **CSS:** CSS styles the *appearance* of the text, but this file determines the *editing actions*. For example, pressing Ctrl+B (or Cmd+B on macOS) triggers the "ToggleBold" command, and CSS will then render the selected text as bold.
    * **JavaScript:** JavaScript can trigger keyboard events programmatically or listen for them. Scripts might use `document.execCommand()` to directly execute the commands defined (or related to) in this file. User actions in a web page that lead to text editing (typing, pressing keys) are the initial triggers that eventually reach this C++ code.

5. **Logical Reasoning and Examples:**  Illustrate the mapping with concrete examples:

    * **Input:**  User presses the left arrow key.
    * **Output:** The `InterpretKeyEvent` function, based on the `kKeyboardCodeKeyDownEntries` array, will return "MoveLeft".
    * **Input:** User presses Ctrl+C.
    * **Output:** `InterpretKeyEvent` returns "Copy".

6. **Common Errors and Debugging:** Think about what could go wrong and how a developer might investigate:

    * **Incorrect Shortcut Behavior:** A user reports that Ctrl+B isn't working for bolding. This leads to checking the mapping in `kKeyboardCodeKeyDownEntries` and verifying that the browser is correctly capturing the key combination.
    * **Unexpected Character Insertion:**  A strange character appears when a specific key combination is pressed. This might involve looking at the `ShouldInsertCharacter` function and the logic around handling control keys and different operating systems.
    * **Debugging Steps:** Describe how a developer would trace the event flow, potentially using breakpoints in the C++ code or using browser developer tools to inspect keyboard events.

7. **User Actions Leading to the Code:**  Outline the sequence of user interactions:

    * User opens a web page with a text field or a `contenteditable` element.
    * User focuses on the editable area.
    * User presses a key.
    * The browser captures the key event.
    * The event is passed down to the rendering engine, eventually reaching the `EditingBehavior::InterpretKeyEvent` function.

8. **Refine and Structure:** Organize the information logically with clear headings and examples. Ensure the explanations are easy to understand. Use the provided code snippets as necessary to illustrate points.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe this file directly implements the editing logic.
* **Correction:**  The file *interprets* the input and identifies *commands*. The actual *execution* of those commands likely happens in other parts of the Blink engine.
* **Initial thought:** Focus heavily on individual key codes.
* **Refinement:** Recognize the importance of modifiers (Ctrl, Shift, Alt) and how they create different commands for the same base key.
* **Initial thought:** Only consider the `InterpretKeyEvent` function.
* **Refinement:**  Understand the role of `ShouldInsertCharacter` in filtering character input.

By following this kind of structured analysis, combining code inspection with knowledge of web technologies and common debugging practices, one can effectively understand the functionality and role of a complex source code file like `editing_behavior.cc`.
好的，让我们来分析一下 `blink/renderer/core/editing/editing_behavior.cc` 这个文件。

**功能概述**

这个文件的核心功能是 **定义和解释编辑行为**，特别是与键盘输入相关的行为。它负责将用户的键盘操作（按下某个键，同时按下修饰键等）映射到 Blink 渲染引擎中相应的编辑命令。

简单来说，当用户在网页的可编辑区域（如 `<textarea>` 或设置了 `contenteditable` 属性的元素）进行输入操作时，这个文件中的代码会判断用户按下了哪些键，并决定应该执行哪个编辑命令。

**与 JavaScript, HTML, CSS 的关系**

这个文件主要处理的是浏览器引擎的底层逻辑，但它与 JavaScript, HTML, CSS 的功能息息相关：

* **HTML:**
    * **关系：** 这个文件定义的编辑行为直接作用于 HTML 文档中的可编辑内容。用户在 HTML 元素中进行的文本输入、光标移动、复制粘贴等操作，其背后的逻辑很大一部分由这个文件来驱动。
    * **举例：** 当用户在一个 `<textarea>` 元素中按下 "Ctrl + B" (或 macOS 上的 "Cmd + B") 时，这个文件中的代码会识别出这个组合键，并将其映射到 "ToggleBold"（切换粗体）编辑命令。这个命令最终会修改 HTML 结构或样式，使得选中的文本变为粗体。
* **CSS:**
    * **关系：** CSS 负责控制网页内容的样式，而这个文件定义的编辑行为可以修改内容的样式。例如，通过键盘快捷键设置文本为粗体、斜体或添加下划线等。
    * **举例：** 上述 "ToggleBold" 命令的执行可能会修改 HTML 元素的样式属性（例如，添加 `<strong>` 标签或设置 `font-weight: bold` 的 CSS 样式）。
* **JavaScript:**
    * **关系：** JavaScript 可以监听键盘事件，并且可以通过 `document.execCommand()` 方法执行各种编辑命令。这个文件定义了这些编辑命令的名称和触发方式。
    * **举例：**  一个 JavaScript 脚本可以监听 `keydown` 事件，当用户按下某个特定的组合键时，调用 `document.execCommand('insertText', false, 'Hello')` 来插入文本。虽然 JavaScript 直接调用 `execCommand`，但浏览器引擎内部仍然会使用类似 `editing_behavior.cc` 中定义的映射关系来处理和执行这些命令。
    * **用户操作影响：** 用户在网页上进行文本输入、复制、粘贴等操作，会触发浏览器底层的事件处理机制，最终可能会调用到 JavaScript 注册的事件监听器。反过来，JavaScript 的操作也可能影响到 `editing_behavior.cc` 中定义的行为。

**逻辑推理、假设输入与输出**

假设用户在一个可编辑的 `<div>` 中进行操作：

**场景 1：移动光标**

* **假设输入：** 用户按下 "左箭头" 键 (`VKEY_LEFT`)。
* **逻辑推理：** `InterpretKeyEvent` 函数会接收到 `keydown` 事件，并根据 `kKeyboardCodeKeyDownEntries` 表查找对应的命令。
* **预期输出：**  `InterpretKeyEvent` 函数返回字符串 `"MoveLeft"`。引擎会执行移动光标向左的动作。

**场景 2：选择文本并设置为粗体**

* **假设输入：**
    1. 用户按住 "Shift" 键并按下 "右箭头" 键 (`VKEY_RIGHT` + `kShiftKey`) 多次，选中一段文本。
    2. 用户按下 "Ctrl + B" (`'B'` + `kCtrlKey`)。
* **逻辑推理：**
    1. 对于第一步，`InterpretKeyEvent` 函数会返回 `"MoveRightAndModifySelection"`，引擎会扩展文本选择。
    2. 对于第二步，`InterpretKeyEvent` 函数会返回 `"ToggleBold"`。
* **预期输出：**  选中的文本会被设置为粗体。

**场景 3：输入字符**

* **假设输入：** 用户按下字母键 "A"。
* **逻辑推理：** `ShouldInsertCharacter` 函数会判断是否应该插入该字符。对于普通字母，它会返回 `true`。
* **预期输出：** 字母 "A" 会被插入到光标所在的位置。

**用户或编程常见的使用错误**

1. **快捷键冲突：** 开发者可能会在 JavaScript 中定义与浏览器默认编辑快捷键相同的快捷键，导致行为不一致或冲突。例如，开发者可能使用 "Ctrl + B" 来触发自定义的功能，而浏览器默认用它来切换粗体。
2. **`contenteditable` 属性使用不当：**  开发者可能在不希望用户编辑的元素上设置了 `contenteditable="true"`，导致用户意外地可以修改内容。
3. **误解编辑命令：**  开发者可能错误地使用了 `document.execCommand()` 方法，传递了错误的命令名称或参数，导致编辑行为不符合预期。例如，误拼写了命令名称。
4. **跨浏览器兼容性问题：**  虽然这个文件是 Blink 引擎的一部分，但不同浏览器对于某些编辑行为的实现可能存在差异。开发者需要注意跨浏览器兼容性问题。

**用户操作如何一步步的到达这里，作为调试线索**

假设用户在一个网页的 `<textarea>` 中输入字母 "A"：

1. **用户操作：** 用户按下键盘上的 "A" 键。
2. **操作系统事件：** 操作系统捕捉到键盘事件，并将其传递给浏览器进程。
3. **浏览器进程事件处理：** 浏览器进程接收到键盘事件。
4. **渲染进程事件传递：**  浏览器进程将键盘事件传递给负责渲染当前网页的渲染进程。
5. **Blink 引擎事件处理：** 在渲染进程中，Blink 引擎接收到该键盘事件。
6. **`EventHandler` 处理：**  事件会被传递给 `EventHandler`（通常在 `blink/renderer/core/dom/event_handler.cc` 中）。
7. **`KeyboardEvent` 创建：**  `EventHandler` 会创建一个 `KeyboardEvent` 对象，封装了这次键盘事件的信息。
8. **`Document::dispatchKeyEvent`：**  事件会被分发到 `Document` 对象。
9. **`HTMLTextFormControlElement::defaultEventHandler` (或类似)：** 对于可编辑元素，特定的元素会处理这些事件。例如，对于 `<textarea>`，`HTMLTextFormControlElement` 会处理。
10. **`LocalFrame::eventHandler().keyPress` 或 `keyDown`：**  事件最终会到达 `LocalFrame` 的事件处理器。
11. **`EditingBehavior::InterpretKeyEvent` 调用：** 在处理 `keydown` 或 `keypress` 事件时，相关的代码会调用 `EditingBehavior::InterpretKeyEvent` 函数，并将 `KeyboardEvent` 对象和当前的书写模式传递给它。
12. **查找编辑命令：** `InterpretKeyEvent` 函数根据按下的键和修饰键，在预定义的映射表（如 `kKeyboardCodeKeyDownEntries`）中查找对应的编辑命令。
13. **执行编辑命令：**  根据查找到的命令，Blink 引擎会执行相应的编辑操作，例如在 `<textarea>` 中插入字符 "A"。

**调试线索：**

* **断点设置：** 开发者可以在 `blink/renderer/core/editing/editing_behavior.cc` 文件的 `InterpretKeyEvent` 和 `ShouldInsertCharacter` 等关键函数中设置断点。
* **事件监听：**  可以使用浏览器的开发者工具监听键盘事件 (`keydown`, `keypress`, `keyup`)，查看事件的 `keyCode`, `charCode`, `key`, `modifiers` 等属性，以确定浏览器接收到的原始键盘输入是什么。
* **日志输出：**  可以在 `InterpretKeyEvent` 函数中添加日志输出，记录接收到的键码和最终解析出的编辑命令，以便追踪键盘事件的处理流程。
* **检查元素属性：**  检查目标 HTML 元素是否设置了 `contenteditable` 属性，以及其值是否正确。
* **JavaScript 代码审查：**  检查是否有 JavaScript 代码监听了键盘事件并阻止了默认行为，或者使用了 `document.execCommand()` 方法进行了自定义的编辑操作。

总而言之，`blink/renderer/core/editing/editing_behavior.cc` 是 Blink 渲染引擎中负责键盘输入与编辑行为映射的关键文件，它连接了用户的键盘操作和浏览器底层的编辑功能，与 JavaScript, HTML, CSS 共同协作，实现了网页的文本编辑能力。理解这个文件的工作原理对于调试与编辑相关的浏览器行为至关重要。

### 提示词
```
这是目录为blink/renderer/core/editing/editing_behavior.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2006, 2007 Apple, Inc.  All rights reserved.
 * Copyright (C) 2012 Google, Inc.  All rights reserved.
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

#include "third_party/blink/renderer/core/editing/editing_behavior.h"

#include "build/build_config.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/text/writing_mode_utils.h"

namespace blink {

namespace {

//
// The below code was adapted from the WebKit file webview.cpp
//

const unsigned kCtrlKey = WebInputEvent::kControlKey;
const unsigned kAltKey = WebInputEvent::kAltKey;
const unsigned kShiftKey = WebInputEvent::kShiftKey;
const unsigned kMetaKey = WebInputEvent::kMetaKey;
#if BUILDFLAG(IS_MAC)
// Aliases for the generic key defintions to make kbd shortcuts definitions more
// readable on OS X.
const unsigned kOptionKey = kAltKey;

// Do not use this constant for anything but cursor movement commands. Keys
// with cmd set have their |isSystemKey| bit set, so chances are the shortcut
// will not be executed. Another, less important, reason is that shortcuts
// defined in the layoutObject do not blink the menu item that they triggered.
// See http://crbug.com/25856 and the bugs linked from there for details.
const unsigned kCommandKey = kMetaKey;
#endif

// Keys with special meaning. These will be delegated to the editor using
// the execCommand() method
struct KeyboardCodeKeyDownEntry {
  unsigned virtual_key;
  unsigned modifiers;
  const char* name;
};

struct KeyboardCodeKeyPressEntry {
  unsigned char_code;
  unsigned modifiers;
  const char* name;
};

// DomKey has a broader range than KeyboardCode, we need DomKey to handle some
// special keys.
// Note: We cannot use DomKey for printable keys since it may vary based on
// locale.
struct DomKeyKeyDownEntry {
  const char* key;
  unsigned modifiers;
  const char* name;
};

#if BUILDFLAG(IS_MAC)
#define OPTION_OR_CTRL_KEY kOptionKey
#else
#define OPTION_OR_CTRL_KEY kCtrlKey
#endif

// Key bindings with command key on Mac and alt key on other platforms are
// marked as system key events and will be ignored (with the exception
// of Command-B and Command-I) so they shouldn't be added here.
const KeyboardCodeKeyDownEntry kKeyboardCodeKeyDownEntries[] = {
    {VKEY_LEFT, 0, "MoveLeft"},
    {VKEY_LEFT, kShiftKey, "MoveLeftAndModifySelection"},
    {VKEY_LEFT, OPTION_OR_CTRL_KEY, "MoveWordLeft"},
    {VKEY_LEFT, OPTION_OR_CTRL_KEY | kShiftKey,
     "MoveWordLeftAndModifySelection"},
    {VKEY_RIGHT, 0, "MoveRight"},
    {VKEY_RIGHT, kShiftKey, "MoveRightAndModifySelection"},
    {VKEY_RIGHT, OPTION_OR_CTRL_KEY, "MoveWordRight"},
    {VKEY_RIGHT, OPTION_OR_CTRL_KEY | kShiftKey,
     "MoveWordRightAndModifySelection"},
    {VKEY_UP, 0, "MoveUp"},
    {VKEY_UP, kShiftKey, "MoveUpAndModifySelection"},
    {VKEY_PRIOR, kShiftKey, "MovePageUpAndModifySelection"},
    {VKEY_DOWN, 0, "MoveDown"},
    {VKEY_DOWN, kShiftKey, "MoveDownAndModifySelection"},
    {VKEY_NEXT, kShiftKey, "MovePageDownAndModifySelection"},
    {VKEY_UP, OPTION_OR_CTRL_KEY, "MoveParagraphBackward"},
    {VKEY_DOWN, OPTION_OR_CTRL_KEY, "MoveParagraphForward"},
#if !BUILDFLAG(IS_MAC)
    {VKEY_UP, kCtrlKey | kShiftKey, "MoveParagraphBackwardAndModifySelection"},
    {VKEY_DOWN, kCtrlKey | kShiftKey, "MoveParagraphForwardAndModifySelection"},
    {VKEY_PRIOR, 0, "MovePageUp"},
    {VKEY_NEXT, 0, "MovePageDown"},
#endif
    {VKEY_HOME, 0, "MoveToBeginningOfLine"},
    {VKEY_HOME, kShiftKey, "MoveToBeginningOfLineAndModifySelection"},
#if BUILDFLAG(IS_MAC)
    {VKEY_PRIOR, kOptionKey, "MovePageUp"},
    {VKEY_NEXT, kOptionKey, "MovePageDown"},
#endif
#if !BUILDFLAG(IS_MAC)
    {VKEY_HOME, kCtrlKey, "MoveToBeginningOfDocument"},
    {VKEY_HOME, kCtrlKey | kShiftKey,
     "MoveToBeginningOfDocumentAndModifySelection"},
#endif
    {VKEY_END, 0, "MoveToEndOfLine"},
    {VKEY_END, kShiftKey, "MoveToEndOfLineAndModifySelection"},
#if !BUILDFLAG(IS_MAC)
    {VKEY_END, kCtrlKey, "MoveToEndOfDocument"},
    {VKEY_END, kCtrlKey | kShiftKey, "MoveToEndOfDocumentAndModifySelection"},
#endif
    {VKEY_BACK, 0, "DeleteBackward"},
    {VKEY_BACK, kShiftKey, "DeleteBackward"},
    {VKEY_DELETE, 0, "DeleteForward"},
    {VKEY_BACK, OPTION_OR_CTRL_KEY, "DeleteWordBackward"},
    {VKEY_DELETE, OPTION_OR_CTRL_KEY, "DeleteWordForward"},
#if BUILDFLAG(IS_MAC)
    {'B', kCommandKey, "ToggleBold"},
    {'I', kCommandKey, "ToggleItalic"},
    {'U', kCommandKey, "ToggleUnderline"},
#else
    {'B', kCtrlKey, "ToggleBold"},
    {'I', kCtrlKey, "ToggleItalic"},
    {'U', kCtrlKey, "ToggleUnderline"},
#endif
    {VKEY_ESCAPE, 0, "Cancel"},
    {VKEY_OEM_PERIOD, kCtrlKey, "Cancel"},
    {VKEY_TAB, 0, "InsertTab"},
    {VKEY_TAB, kShiftKey, "InsertBacktab"},
    {VKEY_RETURN, 0, "InsertNewline"},
    {VKEY_RETURN, kCtrlKey, "InsertNewline"},
    {VKEY_RETURN, kAltKey, "InsertNewline"},
    {VKEY_RETURN, kAltKey | kShiftKey, "InsertNewline"},
    {VKEY_RETURN, kShiftKey, "InsertLineBreak"},
    {VKEY_INSERT, kCtrlKey, "Copy"},
    {VKEY_INSERT, kShiftKey, "Paste"},
    {VKEY_DELETE, kShiftKey, "Cut"},
#if !BUILDFLAG(IS_MAC)
    // On OS X, we pipe these back to the browser, so that it can do menu item
    // blinking.
    {'C', kCtrlKey, "Copy"},
    {'V', kCtrlKey, "Paste"},
    {'V', kCtrlKey | kShiftKey, "PasteAndMatchStyle"},
    {'X', kCtrlKey, "Cut"},
    {'A', kCtrlKey, "SelectAll"},
    {'Z', kCtrlKey, "Undo"},
    {'Z', kCtrlKey | kShiftKey, "Redo"},
    {'Y', kCtrlKey, "Redo"},
#endif
#if BUILDFLAG(IS_WIN)
    {VKEY_BACK, kAltKey, "Undo"},
    {VKEY_BACK, kAltKey | kShiftKey, "Redo"},
#endif
    {VKEY_INSERT, 0, "OverWrite"},
#if BUILDFLAG(IS_ANDROID)
    {VKEY_BACK, kAltKey, "DeleteToBeginningOfLine"},
#endif
};

const KeyboardCodeKeyPressEntry kKeyboardCodeKeyPressEntries[] = {
    {'\t', 0, "InsertTab"},
    {'\t', kShiftKey, "InsertBacktab"},
    {'\r', 0, "InsertNewline"},
    {'\r', kShiftKey, "InsertLineBreak"},
};

const DomKeyKeyDownEntry kDomKeyKeyDownEntries[] = {
    {"Copy", 0, "Copy"},
    {"Cut", 0, "Cut"},
    {"Paste", 0, "Paste"},
};

#undef OPTION_OR_CTRL_KEY

const char* LookupCommandNameFromDomKeyKeyDown(const String& key,
                                               unsigned modifiers) {
  // This table is not likely to grow, so sequential search is fine here.
  for (const auto& entry : kDomKeyKeyDownEntries) {
    if (key == entry.key && modifiers == entry.modifiers)
      return entry.name;
  }
  return nullptr;
}

const int kVkeyForwardChar = VKEY_RIGHT;
const int kVkeyBackwardChar = VKEY_LEFT;
const int kVkeyNextLine = VKEY_DOWN;
const int kVkeyPreviousLine = VKEY_UP;

int TransposeArrowKey(int key_code, WritingMode writing_mode) {
  LogicalToPhysical<int> key_map({writing_mode, TextDirection::kLtr},
                                 kVkeyBackwardChar, kVkeyForwardChar,
                                 kVkeyPreviousLine, kVkeyNextLine);
  switch (key_code) {
    case VKEY_LEFT:
      return key_map.Left();
    case VKEY_RIGHT:
      return key_map.Right();
    case VKEY_UP:
      return key_map.Top();
    case VKEY_DOWN:
      return key_map.Bottom();
  }
  return key_code;
}

}  // anonymous namespace

const char* EditingBehavior::InterpretKeyEvent(const KeyboardEvent& event,
                                               WritingMode writing_mode) const {
  const WebKeyboardEvent* key_event = event.KeyEvent();
  if (!key_event)
    return "";

  static HashMap<int, const char*>* key_down_commands_map = nullptr;
  static HashMap<int, const char*>* key_press_commands_map = nullptr;

  if (!key_down_commands_map) {
    key_down_commands_map = new HashMap<int, const char*>;
    key_press_commands_map = new HashMap<int, const char*>;

    for (const auto& entry : kKeyboardCodeKeyDownEntries) {
      key_down_commands_map->Set(entry.modifiers << 16 | entry.virtual_key,
                                 entry.name);
    }

    for (const auto& entry : kKeyboardCodeKeyPressEntries) {
      key_press_commands_map->Set(entry.modifiers << 16 | entry.char_code,
                                  entry.name);
    }
  }

  unsigned modifiers =
      key_event->GetModifiers() & (kShiftKey | kAltKey | kCtrlKey | kMetaKey);

  auto FindName = [=](HashMap<int, const char*>* map, int code) -> const char* {
    int map_key = modifiers << 16 | code;
    if (!map_key)
      return nullptr;
    auto it = map->find(map_key);
    if (it == map->end())
      return nullptr;
    DCHECK(it->value);
    return it->value;
  };

  if (key_event->GetType() == WebInputEvent::Type::kRawKeyDown) {
    const char* name =
        FindName(key_down_commands_map,
                 TransposeArrowKey(event.keyCode(), writing_mode));
    return name ? name
                : LookupCommandNameFromDomKeyKeyDown(event.key(), modifiers);
  }
  return FindName(key_press_commands_map, event.charCode());
}

bool EditingBehavior::ShouldInsertCharacter(const KeyboardEvent& event) const {
  if (event.KeyEvent()->text[1] != 0)
    return true;

  // On Gtk/Linux, it emits key events with ASCII text and ctrl on for ctrl-<x>.
  // In Webkit, EditorClient::handleKeyboardEvent in
  // WebKit/gtk/WebCoreSupport/EditorClientGtk.cpp drop such events.
  // On Mac, it emits key events with ASCII text and meta on for Command-<x>.
  // These key events should not emit text insert event.
  // Alt key would be used to insert alternative character, so we should let
  // through. Also note that Ctrl-Alt combination equals to AltGr key which is
  // also used to insert alternative character.
  // http://code.google.com/p/chromium/issues/detail?id=10846
  // Windows sets both alt and meta are on when "Alt" key pressed.
  // http://code.google.com/p/chromium/issues/detail?id=2215
  // Also, we should not rely on an assumption that keyboards don't
  // send ASCII characters when pressing a control key on Windows,
  // which may be configured to do it so by user.
  // See also http://en.wikipedia.org/wiki/Keyboard_Layout
  // FIXME(ukai): investigate more detail for various keyboard layout.
  UChar ch = event.KeyEvent()->text[0U];

  // Don't insert null or control characters as they can result in
  // unexpected behaviour
  if (ch < ' ')
    return false;
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
  // According to XKB map no keyboard combinations with ctrl key are mapped to
  // printable characters, however we need the filter as the DomKey/text could
  // contain printable characters.
  if (event.ctrlKey())
    return false;
#elif !BUILDFLAG(IS_WIN)
  // Don't insert ASCII character if ctrl w/o alt or meta is on.
  // On Mac, we should ignore events when meta is on (Command-<x>).
  if (ch < 0x80) {
    if (event.ctrlKey() && !event.altKey())
      return false;
#if BUILDFLAG(IS_MAC)
    if (event.metaKey())
      return false;
#endif
  }
#endif

  return true;
}

}  // namespace blink
```