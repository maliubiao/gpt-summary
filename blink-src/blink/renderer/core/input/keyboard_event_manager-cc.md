Response:
Let's break down the thought process for analyzing this C++ source code and generating the explanation.

1. **Understand the Goal:** The primary goal is to explain the functionality of `keyboard_event_manager.cc` in the Chromium Blink rendering engine, focusing on its relationship with web technologies (JavaScript, HTML, CSS), providing examples, explaining user interactions, and suggesting debugging approaches.

2. **Initial Code Scan (High-Level):**
   - Look at the includes: This gives a broad overview of what the file interacts with. See terms like `WebInputEvent`, `KeyboardEvent`, `Element`, `LocalFrame`, `Page`, `Editor`, `ScrollManager`, etc. This hints at the file's responsibility in handling keyboard input and its connection to the DOM, frames, and scrolling.
   - Look for the main class: `KeyboardEventManager`. This is the central piece of functionality.
   - Look at the methods:  Methods like `KeyEvent`, `HandleAccessKey`, `DefaultKeyboardEventHandler`, `DefaultTabEventHandler`, etc., suggest different aspects of keyboard event processing.

3. **Decomposition by Functionality (Mid-Level):**  Go through the methods and group them by their apparent purpose.

   - **Event Handling:**  `KeyEvent`, `DispatchEvent` (implicit). These seem to be the core of processing keyboard events.
   - **Access Keys:** `HandleAccessKey`. Clearly related to the HTML `accesskey` attribute.
   - **Default Actions:** `DefaultKeyboardEventHandler`, `DefaultTabEventHandler`, `DefaultEscapeEventHandler`, etc. These handle browser-level default behaviors for certain keys.
   - **Scrolling:** The presence of `ScrollManager` and methods like `MapKeyCodeForScroll`, and handling of arrow keys, spacebar, Page Up/Down suggests involvement in keyboard-driven scrolling.
   - **Focus Management:**  `DefaultTabEventHandler` and mentions of `FocusController` indicate interaction with the browser's focus mechanism.
   - **IME Handling:**  Mention of `kVKeyProcessKey` and `DefaultImeSubmitHandler` shows it deals with Input Method Editors.
   - **Modifier Keys:** `KeyEventModifierMayHaveChanged`, `GetCurrentModifierState`. Indicates tracking and reacting to modifier key presses.
   - **Caps Lock:** `CapsLockStateMayHaveChanged`, `CurrentCapsLockState`. Handling of the Caps Lock key.
   - **PWA/Drive-by Web:**  Logic around `GetDontSendKeyEventsToJavascript` and PWA scope indicates security/behavior considerations for different types of web content.

4. **Connecting to Web Technologies (Detailed):**  For each functional area identified above, think about how it relates to JavaScript, HTML, and CSS.

   - **JavaScript:** Keyboard events (`keydown`, `keypress`, `keyup`) are directly dispatched to JavaScript event listeners. The file manages the creation and dispatch of these events. The handling of whether events are cancellable is also important for JavaScript's `preventDefault()`.
   - **HTML:**
     - Access keys:  Directly linked to the `accesskey` attribute.
     - Focus:  The `tabindex` attribute and the natural focus order are affected by tab navigation handled here. Form elements (`input`, `textarea`, `button`) are key players.
     - Scrolling:  Overflow properties in CSS determine scrollable areas.
     - `<dialog>` element: The escape key handling directly relates to closing dialogs.
   - **CSS:**  While not directly manipulating CSS, the file's actions can trigger CSS behavior, such as `:focus-visible` based on keyboard interaction.

5. **Logical Inference and Examples:** For areas with complex logic, create hypothetical scenarios to illustrate the input and output. Think about common use cases.

   - **Scrolling:** What happens when the user presses the down arrow key?  Trace the logic through `MapKeyCodeForScroll` and the call to `scroll_manager_`.
   - **Tab Navigation:** What happens when the user presses Tab?  Consider different focusable elements and the role of `tabindex`.
   - **Access Keys:**  Provide a simple HTML example and explain how the key press triggers the action.
   - **PWA/Drive-by Web:** Explain the scenario where a website might try to intercept certain keys and how the browser restricts this.

6. **User/Programming Errors:**  Consider common mistakes developers or users might make related to keyboard interactions.

   - **JavaScript `preventDefault()`:**  Explain how misuse can break default browser behavior.
   - **Access Key Conflicts:**  Point out potential issues with duplicate access keys.
   - **Focus Traps:**  Explain how incorrect `tabindex` values can create navigation problems.

7. **Debugging Clues (User Interaction -> Code):**  Think about the steps a user takes that would lead to this code being executed. This helps in understanding the context and identifying entry points.

   - **Basic Key Press:** The most fundamental interaction.
   - **Tab Navigation:** A common navigation method.
   - **Using Access Keys:** A less common but supported interaction.
   - **Scrolling with Keyboard:**  Arrow keys, spacebar, etc.
   - **IME Input:**  For languages requiring input method editors.

8. **Structure and Refinement:** Organize the information logically with clear headings and bullet points. Use code snippets where appropriate. Ensure the language is clear and concise, avoiding overly technical jargon where possible. Review and refine the explanation for accuracy and completeness. Initially, I might have just listed the functions, but realizing the prompt asked for *functionality*, I elaborated on *what* these functions do and *why* they matter. I also made sure to connect back to the core request of linking it with web technologies.

**(Self-Correction Example):**  Initially, I might have focused too much on the low-level details of the `WebKeyboardEvent` structure. However, the prompt emphasizes the connection to web technologies. So, I shifted the focus to explaining *how* these low-level events translate into JavaScript events and affect HTML elements and CSS behavior. I also realized the importance of illustrating with concrete examples rather than just describing the abstract logic.
好的，这是一份关于 `blink/renderer/core/input/keyboard_event_manager.cc` 文件的功能分析：

**核心功能：**

`KeyboardEventManager` 负责处理浏览器接收到的键盘事件，并将其分发到相应的 DOM 节点进行处理。  它处于浏览器输入事件处理流程的关键位置，将底层的操作系统键盘事件转化为浏览器内部可以理解和操作的事件。

**主要功能点:**

1. **接收和初步处理键盘事件:**
   - 接收来自浏览器进程的 `WebKeyboardEvent` 类型的键盘事件（包括 `keydown`, `keyup`, `keypress`/`char`, `rawkeydown`）。
   - 进行一些初步的判断和状态更新，例如：
     - 检测 Caps Lock 状态是否可能改变 (`CapsLockStateMayHaveChanged`)。
     - 更新修饰键状态 (`KeyEventModifierMayHaveChanged`)，用于触发例如链接预览等功能。
     - 检查是否处于鼠标中键自动滚动状态，如果是，则可能阻止或处理键盘事件。

2. **决定是否将事件发送给 JavaScript:**
   - 根据当前 Frame 的设置 (`GetDontSendKeyEventsToJavascript`) 和应用是否是 PWA (`IsInWebAppScope`) 等因素，决定是否应该将键盘事件发送给 JavaScript 处理。
   - 对于某些特定的系统级快捷键或非可取消事件，即使在不允许发送 JavaScript 事件的情况下，也可能进行特殊处理。

3. **创建和分发 `KeyboardEvent` 对象:**
   - 将 `WebKeyboardEvent` 转换为 Blink 内部的 `KeyboardEvent` 对象。
   - 设置事件的目标节点 (`SetTarget`)。
   - 设置事件是否可以停止传播 (`SetStopPropagation`)，这取决于是否允许将事件发送给 JavaScript。
   - 使用 `node->DispatchEvent(*event)` 将事件分发到 DOM 树中的目标节点。

4. **处理访问键 (Access Keys):**
   - `HandleAccessKey` 函数检查按下的键是否匹配当前文档中某个元素的访问键 (`accesskey` 属性)。
   - 如果匹配，则将焦点移动到该元素，并触发其默认行为（例如点击链接或按钮）。

5. **默认键盘事件处理 (Default Keyboard Event Handling):**
   - `DefaultKeyboardEventHandler` 函数处理当键盘事件未被 JavaScript 或其他更具体的处理器处理时，浏览器的默认行为。
   - 针对不同的按键（例如 Tab, Escape, Enter, 空格, 方向键），调用相应的默认处理函数。

6. **默认 Tab 键处理 (Default Tab Handling):**
   - `DefaultTabEventHandler` 函数处理 Tab 键的按下，负责在可聚焦元素之间移动焦点。
   - 它会考虑 Shift 键的状态（向前或向后移动焦点），以及当前页面的设置 (`TabKeyCyclesThroughElements`)。

7. **默认 Escape 键处理 (Default Escape Handling):**
   - `DefaultEscapeEventHandler` 函数处理 Escape 键的按下，通常用于关闭模态对话框、取消操作等。
   - 它还会调用 `closewatcher_stack()->EscapeKeyHandler` 来处理注册的关闭监听器。

8. **默认 Enter 键处理 (Default Enter Handling):**
   - `DefaultEnterEventHandler` 函数处理 Enter 键的按下，通常用于提交表单或触发元素的默认行为。

9. **默认空格键处理 (Default Space Handling):**
   - `DefaultSpaceEventHandler` 函数处理空格键的按下，通常用于页面滚动。

10. **默认方向键处理 (Default Arrow Key Handling):**
    - `DefaultArrowEventHandler` 函数处理方向键的按下，主要用于页面滚动。
    - 它使用 `MapKeyCodeForScroll` 函数将按键映射到滚动方向和粒度。
    - 还会考虑空间导航 (`SpatialNavigation`) 和焦点组 (`Focusgroup`) 的处理。

11. **IME 提交处理 (Default IME Submit Handling):**
    - `DefaultImeSubmitHandler` 函数处理输入法编辑器 (IME) 的提交事件。

12. **滚动管理:**
    - 与 `ScrollManager` 交互，根据键盘事件触发页面滚动。
    - 记录最后触发滚动的按键，并在 `keyup` 事件时检查是否需要触发 `scrollend` 事件。

13. **Caps Lock 状态管理:**
    - 提供获取当前 Caps Lock 状态的功能 (`CurrentCapsLockState`)。
    - 在 Mac 系统上，直接获取系统 Caps Lock 状态。
    - 在其他平台上，通常返回 false，除非被特定功能覆盖（例如密码输入框）。

14. **修饰键状态管理:**
    - 提供获取当前修饰键状态的功能 (`GetCurrentModifierState`)。
    - 用于一些需要根据修饰键状态执行不同操作的场景。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    - `KeyboardEventManager` 的核心职责之一就是将键盘事件传递给 JavaScript 代码。
    - 当用户按下或释放键盘按键时，这个类会创建 `KeyboardEvent` 对象，这些对象最终会被分发到 JavaScript 事件监听器中（例如 `element.addEventListener('keydown', function(event) { ... });`）。
    - JavaScript 可以通过 `event.preventDefault()` 阻止浏览器的默认行为，`KeyboardEventManager` 在处理默认行为时会检查事件是否已被阻止。

* **HTML:**
    - **`accesskey` 属性:** `HandleAccessKey` 函数直接关联到 HTML 元素的 `accesskey` 属性。用户按下包含访问键的组合键时，浏览器会将焦点转移到对应的元素并触发其行为。
    * **可聚焦元素:**  Tab 键的默认行为是在可聚焦元素之间移动焦点，这些元素通常是通过 HTML 结构和 `tabindex` 属性定义的。
    * **`<dialog>` 元素:** Escape 键的默认行为通常用于关闭 `<dialog>` 元素。
    * **表单元素 (`<input>`, `<button>`, 等):** Enter 键在表单中通常触发提交行为。空格键在某些可点击元素上也会触发点击行为。

* **CSS:**
    * **`:focus` 和 `:focus-visible` 伪类:**  `KeyboardEventManager` 的操作（例如 Tab 键移动焦点）会直接影响 `:focus` 伪类的状态。 `node->UpdateHadKeyboardEvent(*event)` 用于跟踪是否通过键盘事件触发了焦点，从而影响 `:focus-visible` 伪类的行为。
    * **滚动行为:** 键盘事件触发的滚动最终会影响页面的布局和 CSS 的 `overflow` 属性。

**逻辑推理、假设输入与输出：**

**假设输入：** 用户在文本输入框中按下 "A" 键。

**输出 (简化流程):**

1. 操作系统捕获到键盘按下事件。
2. 浏览器进程接收到该事件，并将其转换为 `WebKeyboardEvent`。
3. `KeyboardEventManager::KeyEvent` 接收到 `WebKeyboardEvent` (Type: `kKeyDown`, `windows_key_code`: 65, `text`: "A", `unmodified_text`: "A", 等)。
4. 检查 Caps Lock 状态。
5. 检查是否需要发送给 JavaScript (假设允许)。
6. 创建 `KeyboardEvent` 对象 (Type: "keydown", `key`: "a", `code`: "KeyA", 等)。
7. 将 `KeyboardEvent` 分发到焦点所在的文本输入框 (`<input>`)。
8. 如果 JavaScript 没有阻止默认行为，`DefaultKeyboardEventHandler` 不会执行与 "A" 键相关的特殊默认行为。
9. 可能会触发 `keypress`/`char` 事件 (取决于浏览器和操作系统)。
10. 文本输入框接收到事件，并将 "A" 添加到其内容中。
11. 操作系统捕获到键盘释放事件。
12. 浏览器进程接收到释放事件，转换为 `WebKeyboardEvent` (Type: `kKeyUp`)。
13. `KeyboardEventManager::KeyEvent` 接收到 `kKeyUp` 事件。
14. 创建并分发 `keyup` 事件到文本输入框。

**用户或编程常见的使用错误：**

1. **JavaScript 中错误地使用 `preventDefault()`:**
   - **错误示例:**  在 `keydown` 事件监听器中，无条件地调用 `event.preventDefault()`，即使对于非功能键。
   - **后果:** 这可能会阻止浏览器的默认行为，例如无法在输入框中输入文本，无法使用 Tab 键切换焦点，甚至可能阻止浏览器的快捷键。

2. **HTML 中重复的 `accesskey` 属性:**
   - **错误示例:** 多个元素具有相同的 `accesskey` 属性。
   - **后果:**  当用户按下访问键时，浏览器的行为可能不确定，通常会聚焦到文档中出现的第一个匹配元素。

3. **不正确的 `tabindex` 属性使用:**
   - **错误示例:**  `tabindex` 的值不符合逻辑（例如跳跃的数字，或者负数）。
   - **后果:**  导致 Tab 键的焦点顺序混乱，用户无法按照期望的方式导航页面。

4. **过度依赖键盘事件监听器，而忽略了语义化 HTML:**
   - **错误示例:**  使用 `div` 元素模拟按钮，并使用 JavaScript 监听键盘事件来实现其功能，而不是使用 `<button>` 元素。
   - **后果:**  可能导致可访问性问题，例如屏幕阅读器无法正确识别元素的功能，以及浏览器默认的键盘行为（例如空格键点击按钮）无法工作。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户按下键盘上的一个键。** 这是最直接的入口点。
2. **操作系统 (OS) 捕获到硬件中断，识别按下的键，并生成一个底层的键盘事件。**  例如，在 Windows 上可能是 `WM_KEYDOWN` 或 `WM_SYSKEYDOWN` 消息。
3. **操作系统的输入系统将该事件传递给浏览器进程。**
4. **浏览器的渲染器进程（Blink）接收到来自浏览器进程的原始输入事件。**
5. **输入处理管道开始工作，将操作系统特定的事件转换为平台无关的 `WebInputEvent`。**
6. **`KeyboardEventManager` 的 `KeyEvent` 方法被调用，接收到 `WebKeyboardEvent` 对象。**
7. **根据事件类型 (`keydown`, `keyup`, `keypress`) 和其他状态，`KeyEvent` 方法会执行相应的处理逻辑：**
   - 判断是否发送给 JavaScript。
   - 创建 `KeyboardEvent` 对象。
   - 分发事件到目标 DOM 节点。
   - 如果没有被阻止，则调用默认事件处理函数 (`DefaultKeyboardEventHandler`)。
8. **`DefaultKeyboardEventHandler` 根据按下的键调用更具体的处理函数，例如 `DefaultTabEventHandler`，`DefaultArrowEventHandler` 等。**
9. **这些默认处理函数可能会与浏览器的其他组件交互，例如 `ScrollManager`（进行页面滚动）或 `FocusController`（移动焦点）。**

**调试线索:**

* **检查 `WebKeyboardEvent` 的内容:**  在 `KeyboardEventManager::KeyEvent` 方法的入口处打断点，查看 `WebKeyboardEvent` 的属性（例如 `type`, `windows_key_code`, `modifiers`, `text`, `unmodified_text`）是否符合预期。这可以帮助你确认操作系统级别的键盘事件是否正确传递到了 Blink。
* **查看事件目标节点:**  确认事件被分发到了正确的 DOM 节点。可以使用开发者工具的事件监听器面板来查看元素上注册的键盘事件监听器。
* **检查 JavaScript 是否阻止了默认行为:**  如果在 JavaScript 中注册了键盘事件监听器，并且调用了 `event.preventDefault()`，这会阻止浏览器的默认行为。在 JavaScript 代码中设置断点，检查是否发生了这种情况。
* **逐步执行默认事件处理逻辑:**  在 `DefaultKeyboardEventHandler` 和其调用的其他默认处理函数中设置断点，逐步执行代码，了解浏览器的默认行为是如何工作的。
* **使用 `console.log` 输出事件信息:**  在 JavaScript 事件监听器中输出 `KeyboardEvent` 对象的属性（例如 `key`, `code`, `keyCode`, `ctrlKey`, `shiftKey`, `altKey`, `metaKey`），以便了解事件的详细信息。

希望这份分析对您有所帮助！

Prompt: 
```
这是目录为blink/renderer/core/input/keyboard_event_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/input/keyboard_event_manager.h"

#include <memory>

#include "base/auto_reset.h"
#include "base/notreached.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/web_link_preview_triggerer.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/events/simulated_click_options.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/input/event_handling_util.h"
#include "third_party/blink/renderer/core/input/input_device_capabilities.h"
#include "third_party/blink/renderer/core/input/keyboard_shortcut_recorder.h"
#include "third_party/blink/renderer/core/input/scroll_manager.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/focusgroup_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/spatial_navigation.h"
#include "third_party/blink/renderer/core/page/spatial_navigation_controller.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"
#include "third_party/blink/renderer/platform/windows_keyboard_codes.h"
#include "ui/events/keycodes/dom/keycode_converter.h"

#if BUILDFLAG(IS_WIN)
#include <windows.h>
#elif BUILDFLAG(IS_MAC)
#import <Carbon/Carbon.h>
#endif

namespace blink {

namespace {

const int kVKeyProcessKey = 229;

bool IsPageUpOrDownKeyEvent(int key_code, WebInputEvent::Modifiers modifiers) {
  if (modifiers & WebInputEvent::kAltKey) {
    // Alt-Up/Down should behave like PageUp/Down on Mac. (Note that Alt-keys
    // on other platforms are suppressed due to isSystemKey being set.)
    return key_code == VKEY_UP || key_code == VKEY_DOWN;
  } else if (key_code == VKEY_PRIOR || key_code == VKEY_NEXT) {
    return modifiers == WebInputEvent::kNoModifiers;
  }

  return false;
}

bool MapKeyCodeForScroll(int key_code,
                         WebInputEvent::Modifiers modifiers,
                         mojom::blink::ScrollDirection* scroll_direction,
                         ui::ScrollGranularity* scroll_granularity,
                         WebFeature* scroll_use_uma) {
  if (modifiers & WebInputEvent::kShiftKey ||
      modifiers & WebInputEvent::kMetaKey)
    return false;

  if (modifiers & WebInputEvent::kAltKey) {
    // Alt-Up/Down should behave like PageUp/Down on Mac.  (Note that Alt-keys
    // on other platforms are suppressed due to isSystemKey being set.)
    if (key_code == VKEY_UP)
      key_code = VKEY_PRIOR;
    else if (key_code == VKEY_DOWN)
      key_code = VKEY_NEXT;
    else
      return false;
  }

  if (modifiers & WebInputEvent::kControlKey) {
    // Match FF behavior in the sense that Ctrl+home/end are the only Ctrl
    // key combinations which affect scrolling.
    if (key_code != VKEY_HOME && key_code != VKEY_END)
      return false;
  }

#if BUILDFLAG(IS_ANDROID)
  switch (key_code) {
    case VKEY_PRIOR:
      RecordKeyboardShortcutForAndroid(KeyboardShortcut::kPageUp);
      break;
    case VKEY_NEXT:
      RecordKeyboardShortcutForAndroid(KeyboardShortcut::kPageDown);
      break;
  }
#endif

  switch (key_code) {
    case VKEY_LEFT:
      *scroll_direction =
          mojom::blink::ScrollDirection::kScrollLeftIgnoringWritingMode;
      *scroll_granularity =
          RuntimeEnabledFeatures::PercentBasedScrollingEnabled()
              ? ui::ScrollGranularity::kScrollByPercentage
              : ui::ScrollGranularity::kScrollByLine;
      *scroll_use_uma = WebFeature::kScrollByKeyboardArrowKeys;
      break;
    case VKEY_RIGHT:
      *scroll_direction =
          mojom::blink::ScrollDirection::kScrollRightIgnoringWritingMode;
      *scroll_granularity =
          RuntimeEnabledFeatures::PercentBasedScrollingEnabled()
              ? ui::ScrollGranularity::kScrollByPercentage
              : ui::ScrollGranularity::kScrollByLine;
      *scroll_use_uma = WebFeature::kScrollByKeyboardArrowKeys;
      break;
    case VKEY_UP:
      *scroll_direction =
          mojom::blink::ScrollDirection::kScrollUpIgnoringWritingMode;
      *scroll_granularity =
          RuntimeEnabledFeatures::PercentBasedScrollingEnabled()
              ? ui::ScrollGranularity::kScrollByPercentage
              : ui::ScrollGranularity::kScrollByLine;
      *scroll_use_uma = WebFeature::kScrollByKeyboardArrowKeys;
      break;
    case VKEY_DOWN:
      *scroll_direction =
          mojom::blink::ScrollDirection::kScrollDownIgnoringWritingMode;
      *scroll_granularity =
          RuntimeEnabledFeatures::PercentBasedScrollingEnabled()
              ? ui::ScrollGranularity::kScrollByPercentage
              : ui::ScrollGranularity::kScrollByLine;
      *scroll_use_uma = WebFeature::kScrollByKeyboardArrowKeys;
      break;
    case VKEY_HOME:
      *scroll_direction =
          mojom::blink::ScrollDirection::kScrollUpIgnoringWritingMode;
      *scroll_granularity = ui::ScrollGranularity::kScrollByDocument;
      *scroll_use_uma = WebFeature::kScrollByKeyboardHomeEndKeys;
      break;
    case VKEY_END:
      *scroll_direction =
          mojom::blink::ScrollDirection::kScrollDownIgnoringWritingMode;
      *scroll_granularity = ui::ScrollGranularity::kScrollByDocument;
      *scroll_use_uma = WebFeature::kScrollByKeyboardHomeEndKeys;
      break;
    case VKEY_PRIOR:  // page up
      *scroll_direction =
          mojom::blink::ScrollDirection::kScrollUpIgnoringWritingMode;
      *scroll_granularity = ui::ScrollGranularity::kScrollByPage;
      *scroll_use_uma = WebFeature::kScrollByKeyboardPageUpDownKeys;
      break;
    case VKEY_NEXT:  // page down
      *scroll_direction =
          mojom::blink::ScrollDirection::kScrollDownIgnoringWritingMode;
      *scroll_granularity = ui::ScrollGranularity::kScrollByPage;
      *scroll_use_uma = WebFeature::kScrollByKeyboardPageUpDownKeys;
      break;
    default:
      return false;
  }

  return true;
}

}  // namespace

KeyboardEventManager::KeyboardEventManager(LocalFrame& frame,
                                           ScrollManager& scroll_manager)
    : frame_(frame), scroll_manager_(scroll_manager) {}

void KeyboardEventManager::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(scroll_manager_);
  visitor->Trace(scrollend_event_target_);
}

bool KeyboardEventManager::HandleAccessKey(const WebKeyboardEvent& evt) {
  base::AutoReset<bool> is_handling_key_event(&is_handling_key_event_, true);
  // TODO: Ignoring the state of Shift key is what neither IE nor Firefox do.
  // IE matches lower and upper case access keys regardless of Shift key state -
  // but if both upper and lower case variants are present in a document, the
  // correct element is matched based on Shift key state.  Firefox only matches
  // an access key if Shift is not pressed, and does that case-insensitively.
  DCHECK(!(kAccessKeyModifiers & WebInputEvent::kShiftKey));
  if ((evt.GetModifiers() & (WebKeyboardEvent::kKeyModifiers &
                             ~WebInputEvent::kShiftKey)) != kAccessKeyModifiers)
    return false;
  String key = String(evt.unmodified_text.data());
  Element* elem =
      frame_->GetDocument()->GetElementByAccessKey(key.DeprecatedLower());
  if (!elem)
    return false;
  elem->Focus(FocusParams(SelectionBehaviorOnFocus::kReset,
                          mojom::blink::FocusType::kAccessKey, nullptr,
                          FocusOptions::Create(), FocusTrigger::kUserGesture));
  elem->AccessKeyAction(SimulatedClickCreationScope::kFromUserAgent);
  return true;
}

WebInputEventResult KeyboardEventManager::KeyEvent(
    const WebKeyboardEvent& initial_key_event) {
  base::AutoReset<bool> is_handling_key_event(&is_handling_key_event_, true);
  if (initial_key_event.windows_key_code == VK_CAPITAL)
    CapsLockStateMayHaveChanged();

  KeyEventModifierMayHaveChanged(initial_key_event.GetModifiers());

  if (scroll_manager_->MiddleClickAutoscrollInProgress()) {
    DCHECK(RuntimeEnabledFeatures::MiddleClickAutoscrollEnabled());
    // If a key is pressed while the middleClickAutoscroll is in progress then
    // we want to stop.
    if (initial_key_event.GetType() == WebInputEvent::Type::kKeyDown ||
        initial_key_event.GetType() == WebInputEvent::Type::kRawKeyDown)
      scroll_manager_->StopMiddleClickAutoscroll();

    // If we were in panscroll mode, we swallow the key event
    return WebInputEventResult::kHandledSuppressed;
  }

  // Check for cases where we are too early for events -- possible unmatched key
  // up from pressing return in the location bar.
  Node* node = EventTargetNodeForDocument(frame_->GetDocument());
  if (!node)
    return WebInputEventResult::kNotHandled;

  // To be meaningful enough to indicate user intention, a keyboard event needs
  // - not to be a modifier event
  // https://crbug.com/709765
  bool is_modifier = ui::KeycodeConverter::IsDomKeyForModifier(
      static_cast<ui::DomKey>(initial_key_event.dom_key));

  if (!is_modifier && initial_key_event.dom_key != ui::DomKey::ESCAPE &&
      (initial_key_event.GetType() == WebInputEvent::Type::kKeyDown ||
       initial_key_event.GetType() == WebInputEvent::Type::kRawKeyDown)) {
    LocalFrame::NotifyUserActivation(
        frame_, mojom::blink::UserActivationNotificationType::kInteraction,
        RuntimeEnabledFeatures::BrowserVerifiedUserActivationKeyboardEnabled());
  }

  // Don't expose key events to pages while browsing on the drive-by web. This
  // is to prevent pages from accidentally interfering with the built-in
  // behavior eg. spatial-navigation. Installed PWAs are a signal from the user
  // that they trust the app more than a random page on the drive-by web so we
  // allow PWAs to receive and override key events. The only exception is the
  // browser display mode since it must always behave like the the drive-by web.
  bool should_send_key_events_to_js =
      !frame_->GetSettings()->GetDontSendKeyEventsToJavascript();

  if (!should_send_key_events_to_js &&
      frame_->GetDocument()->IsInWebAppScope()) {
    mojom::blink::DisplayMode display_mode =
        frame_->GetWidgetForLocalRoot()->DisplayMode();
    should_send_key_events_to_js =
        display_mode == blink::mojom::DisplayMode::kMinimalUi ||
        display_mode == blink::mojom::DisplayMode::kStandalone ||
        display_mode == blink::mojom::DisplayMode::kFullscreen ||
        display_mode == blink::mojom::DisplayMode::kBorderless ||
        display_mode == blink::mojom::DisplayMode::kWindowControlsOverlay;
  }

  // We have 2 level of not exposing key event to js, not send and send but not
  // cancellable.
  bool send_key_event = true;
  bool event_cancellable = true;

  if (!should_send_key_events_to_js) {
    // TODO(bokan) Should cleanup these magic number. https://crbug.com/949766.
    const int kDomKeysDontSend[] = {0x00200309, 0x00200310};
    const int kDomKeysNotCancellabelUnlessInEditor[] = {0x00400031, 0x00400032,
                                                        0x00400033};
    for (uint32_t dom_key : kDomKeysDontSend) {
      if (initial_key_event.dom_key == dom_key)
        send_key_event = false;
    }

    for (uint32_t dom_key : kDomKeysNotCancellabelUnlessInEditor) {
      auto* text_control = ToTextControlOrNull(node);
      auto* element = DynamicTo<Element>(node);
      bool is_editable =
          IsEditable(*node) ||
          (text_control && !text_control->IsDisabledOrReadOnly()) ||
          (element &&
           EqualIgnoringASCIICase(
               element->FastGetAttribute(html_names::kRoleAttr), "textbox"));
      if (initial_key_event.dom_key == dom_key && !is_editable)
        event_cancellable = false;
    }
  } else {
    // TODO(bokan) Should cleanup these magic numbers. https://crbug.com/949766.
    const int kDomKeyNeverSend = 0x00200309;
    send_key_event = initial_key_event.dom_key != kDomKeyNeverSend;
  }

  DispatchEventResult dispatch_result = DispatchEventResult::kNotCanceled;
  switch (initial_key_event.GetType()) {
    // TODO: it would be fair to let an input method handle KeyUp events
    // before DOM dispatch.
    case WebInputEvent::Type::kKeyUp: {
      KeyboardEvent* event = KeyboardEvent::Create(
          initial_key_event, frame_->GetDocument()->domWindow(),
          event_cancellable);
      event->SetTarget(node);
      event->SetStopPropagation(!send_key_event);

      dispatch_result = node->DispatchEvent(*event);
      break;
    }
    case WebInputEvent::Type::kRawKeyDown:
    case WebInputEvent::Type::kKeyDown: {
      WebKeyboardEvent web_event = initial_key_event;
      web_event.SetType(WebInputEvent::Type::kRawKeyDown);

      KeyboardEvent* event = KeyboardEvent::Create(
          web_event, frame_->GetDocument()->domWindow(), event_cancellable);
      event->SetTarget(node);
      event->SetStopPropagation(!send_key_event);

      // In IE, access keys are special, they are handled after default keydown
      // processing, but cannot be canceled - this is hard to match.  On Mac OS
      // X, we process them before dispatching keydown, as the default keydown
      // handler implements Emacs key bindings, which may conflict with access
      // keys. Then we dispatch keydown, but suppress its default handling. On
      // Windows, WebKit explicitly calls handleAccessKey() instead of
      // dispatching a keypress event for WM_SYSCHAR messages.  Other platforms
      // currently match either Mac or Windows behavior, depending on whether
      // they send combined KeyDown events.
      if (initial_key_event.GetType() == WebInputEvent::Type::kKeyDown &&
          HandleAccessKey(initial_key_event)) {
        event->preventDefault();
      }

      // If this keydown did not involve a meta-key press, update the keyboard
      // event state and trigger :focus-visible matching if necessary.
      if (!event->ctrlKey() && !event->altKey() && !event->metaKey()) {
        node->UpdateHadKeyboardEvent(*event);
      }

      if (dispatch_result = node->DispatchEvent(*event);
          dispatch_result != DispatchEventResult::kNotCanceled) {
        break;
      }

      // If frame changed as a result of keydown dispatch, then return early to
      // avoid sending a subsequent keypress message to the new frame.
      if (frame_->GetPage() &&
          frame_ !=
              frame_->GetPage()->GetFocusController().FocusedOrMainFrame()) {
        return WebInputEventResult::kHandledSystem;
      }

      // kRawKeyDown doesn't trigger `keypress`es, so we end the logic here.
      if (initial_key_event.GetType() != WebInputEvent::Type::kKeyDown) {
        return WebInputEventResult::kNotHandled;
      }

      // Focus may have changed during keydown handling, so refetch node.
      // But if we are dispatching a fake backward compatibility keypress, then
      // we pretend that the keypress happened on the original node.
      node = EventTargetNodeForDocument(frame_->GetDocument());
      if (!node) {
        return WebInputEventResult::kNotHandled;
      }

#if BUILDFLAG(IS_MAC)
      // According to NSEvents.h, OpenStep reserves the range 0xF700-0xF8FF for
      // function keys. However, some actual private use characters happen to be
      // in this range, e.g. the Apple logo (Option+Shift+K). 0xF7FF is an
      // arbitrary cut-off.
      if (initial_key_event.text[0U] >= 0xF700 &&
          initial_key_event.text[0U] <= 0xF7FF) {
        return WebInputEventResult::kNotHandled;
      }
#endif
      if (initial_key_event.text[0] == 0) {
        return WebInputEventResult::kNotHandled;
      }
      [[fallthrough]];
    }
    case WebInputEvent::Type::kChar: {
      WebKeyboardEvent char_event = initial_key_event;
      char_event.SetType(WebInputEvent::Type::kChar);

      KeyboardEvent* event = KeyboardEvent::Create(
          char_event, frame_->GetDocument()->domWindow(), event_cancellable);
      event->SetTarget(node);
      event->SetStopPropagation(!send_key_event);

      dispatch_result = node->DispatchEvent(*event);
      break;
    }
    default:
      NOTREACHED();
  }
  return event_handling_util::ToWebInputEventResult(dispatch_result);
}

void KeyboardEventManager::CapsLockStateMayHaveChanged() {
  if (Element* element = frame_->GetDocument()->FocusedElement()) {
    if (auto* text_control = DynamicTo<HTMLInputElement>(element))
      text_control->CapsLockStateMayHaveChanged();
  }
}

void KeyboardEventManager::KeyEventModifierMayHaveChanged(int modifiers) {
  WebLinkPreviewTriggerer* triggerer =
      frame_->GetOrCreateLinkPreviewTriggerer();
  if (!triggerer) {
    return;
  }

  triggerer->MaybeChangedKeyEventModifier(modifiers);
}

void KeyboardEventManager::DefaultKeyboardEventHandler(
    KeyboardEvent* event,
    Node* possible_focused_node) {
  if (event->type() == event_type_names::kKeydown) {
    frame_->GetEditor().HandleKeyboardEvent(event);
    if (event->DefaultHandled())
      return;

    // Do not perform the default action when inside a IME composition context.
    // TODO(dtapuska): Replace this with isComposing support. crbug.com/625686
    if (event->keyCode() == kVKeyProcessKey)
      return;

    const AtomicString key(event->key());
    if (key == keywords::kTab) {
      DefaultTabEventHandler(event);
    } else if (key == keywords::kEscape) {
      DefaultEscapeEventHandler(event);
    } else if (key == keywords::kCapitalEnter) {
      DefaultEnterEventHandler(event);
    } else if (event->KeyEvent() &&
               static_cast<int>(event->KeyEvent()->dom_key) == 0x00200310) {
      // TODO(bokan): Cleanup magic numbers once https://crbug.com/949766 lands.
      DefaultImeSubmitHandler(event);
    } else {
      // TODO(bokan): Seems odd to call the default _arrow_ event handler on
      // events that aren't necessarily arrow keys.
      DefaultArrowEventHandler(event, possible_focused_node);
    }
  } else if (event->type() == event_type_names::kKeypress) {
    frame_->GetEditor().HandleKeyboardEvent(event);
    if (event->DefaultHandled())
      return;
    if (event->key() == keywords::kCapitalEnter) {
      DefaultEnterEventHandler(event);
    } else if (event->charCode() == ' ') {
      DefaultSpaceEventHandler(event, possible_focused_node);
    }
  } else if (event->type() == event_type_names::kKeyup) {
    if (event->DefaultHandled())
      return;
    if (event->key() == keywords::kCapitalEnter) {
      DefaultEnterEventHandler(event);
    }
    if (event->keyCode() == last_scrolling_keycode_) {
      if (scrollend_event_target_ && has_pending_scrollend_on_key_up_) {
        scrollend_event_target_->OnScrollFinished(true);
      }
      scrollend_event_target_.Clear();
      last_scrolling_keycode_ = VKEY_UNKNOWN;
      has_pending_scrollend_on_key_up_ = false;
    }
  }
}

void KeyboardEventManager::DefaultSpaceEventHandler(
    KeyboardEvent* event,
    Node* possible_focused_node) {
  DCHECK_EQ(event->type(), event_type_names::kKeypress);

  if (event->ctrlKey() || event->metaKey() || event->altKey())
    return;

  mojom::blink::ScrollDirection direction =
      event->shiftKey()
          ? mojom::blink::ScrollDirection::kScrollBlockDirectionBackward
          : mojom::blink::ScrollDirection::kScrollBlockDirectionForward;

  // We must clear |scrollend_event_target_| at the beginning of each scroll
  // so that we don't fire scrollend based on a prior scroll if a newer scroll
  // begins before the keyup event associated with the prior scroll/keydown.
  // If a newer scroll begins before the keyup event and ends after it,
  // we should fire scrollend at the end of that newer scroll rather than at
  // the keyup event.
  scrollend_event_target_.Clear();
  // TODO(bokan): enable scroll customization in this case. See
  // crbug.com/410974.
  if (scroll_manager_->LogicalScroll(direction,
                                     ui::ScrollGranularity::kScrollByPage,
                                     nullptr, possible_focused_node, true)) {
    UseCounter::Count(frame_->GetDocument(),
                      WebFeature::kScrollByKeyboardSpacebarKey);
    last_scrolling_keycode_ = event->keyCode();
    has_pending_scrollend_on_key_up_ = true;
    event->SetDefaultHandled();
    return;
  }
}

void KeyboardEventManager::DefaultArrowEventHandler(
    KeyboardEvent* event,
    Node* possible_focused_node) {
  DCHECK_EQ(event->type(), event_type_names::kKeydown);

  Page* page = frame_->GetPage();
  if (!page)
    return;

  ExecutionContext* context = frame_->GetDocument()->GetExecutionContext();
  if (RuntimeEnabledFeatures::FocusgroupEnabled(context) &&
      FocusgroupController::HandleArrowKeyboardEvent(event, frame_)) {
    event->SetDefaultHandled();
    return;
  }

  if (IsSpatialNavigationEnabled(frame_) &&
      !frame_->GetDocument()->InDesignMode() &&
      !IsPageUpOrDownKeyEvent(event->keyCode(), event->GetModifiers())) {
    if (page->GetSpatialNavigationController().HandleArrowKeyboardEvent(
            event)) {
      event->SetDefaultHandled();
      return;
    }
  }

  if (event->KeyEvent() && event->KeyEvent()->is_system_key)
    return;

  mojom::blink::ScrollDirection scroll_direction;
  ui::ScrollGranularity scroll_granularity;
  WebFeature scroll_use_uma;
  if (!MapKeyCodeForScroll(event->keyCode(), event->GetModifiers(),
                           &scroll_direction, &scroll_granularity,
                           &scroll_use_uma))
    return;

  // See KeyboardEventManager::DefaultSpaceEventHandler for the reason for
  // this Clear.
  scrollend_event_target_.Clear();
  if (scroll_manager_->BubblingScroll(scroll_direction, scroll_granularity,
                                      nullptr, possible_focused_node, true)) {
    UseCounter::Count(frame_->GetDocument(), scroll_use_uma);
    last_scrolling_keycode_ = event->keyCode();
    has_pending_scrollend_on_key_up_ = true;
    event->SetDefaultHandled();
    return;
  }
}

void KeyboardEventManager::DefaultTabEventHandler(KeyboardEvent* event) {
  // TODO (liviutinta) remove TRACE after fixing crbug.com/1063548
  TRACE_EVENT0("input", "KeyboardEventManager::DefaultTabEventHandler");
  DCHECK_EQ(event->type(), event_type_names::kKeydown);
  // We should only advance focus on tabs if no special modifier keys are held
  // down.
  if (event->ctrlKey() || event->metaKey()) {
    // TODO (liviutinta) remove TRACE after fixing crbug.com/1063548
    TRACE_EVENT_INSTANT1(
        "input", "KeyboardEventManager::DefaultTabEventHandler",
        TRACE_EVENT_SCOPE_THREAD, "reason_tab_does_not_advance_focus",
        (event->ctrlKey() ? (event->metaKey() ? "Ctrl+MetaKey+Tab" : "Ctrl+Tab")
                          : "MetaKey+Tab"));
    return;
  }

#if !BUILDFLAG(IS_MAC)
  // Option-Tab is a shortcut based on a system-wide preference on Mac but
  // should be ignored on all other platforms.
  if (event->altKey()) {
    // TODO (liviutinta) remove TRACE after fixing crbug.com/1063548
    TRACE_EVENT_INSTANT1("input",
                         "KeyboardEventManager::DefaultTabEventHandler",
                         TRACE_EVENT_SCOPE_THREAD,
                         "reason_tab_does_not_advance_focus", "Alt+Tab");
    return;
  }
#endif

  Page* page = frame_->GetPage();
  if (!page) {
    // TODO (liviutinta) remove TRACE after fixing crbug.com/1063548
    TRACE_EVENT_INSTANT1("input",
                         "KeyboardEventManager::DefaultTabEventHandler",
                         TRACE_EVENT_SCOPE_THREAD,
                         "reason_tab_does_not_advance_focus", "Page is null");
    return;
  }
  if (!page->TabKeyCyclesThroughElements()) {
    // TODO (liviutinta) remove TRACE after fixing crbug.com/1063548
    TRACE_EVENT_INSTANT1(
        "input", "KeyboardEventManager::DefaultTabEventHandler",
        TRACE_EVENT_SCOPE_THREAD, "reason_tab_does_not_advance_focus",
        "TabKeyCyclesThroughElements is false");
    return;
  }

  mojom::blink::FocusType focus_type = event->shiftKey()
                                           ? mojom::blink::FocusType::kBackward
                                           : mojom::blink::FocusType::kForward;

  // Tabs can be used in design mode editing.
  if (frame_->GetDocument()->InDesignMode()) {
    // TODO (liviutinta) remove TRACE after fixing crbug.com/1063548
    TRACE_EVENT_INSTANT1(
        "input", "KeyboardEventManager::DefaultTabEventHandler",
        TRACE_EVENT_SCOPE_THREAD, "reason_tab_does_not_advance_focus",
        "DesignMode is true");
    return;
  }

  if (page->GetFocusController().AdvanceFocus(focus_type,
                                              frame_->GetDocument()
                                                  ->domWindow()
                                                  ->GetInputDeviceCapabilities()
                                                  ->FiresTouchEvents(false))) {
    event->SetDefaultHandled();
  } else {
    // TODO (liviutinta) remove TRACE after fixing crbug.com/1063548
    TRACE_EVENT_INSTANT1(
        "input", "KeyboardEventManager::DefaultTabEventHandler",
        TRACE_EVENT_SCOPE_THREAD, "reason_tab_does_not_advance_focus",
        "AdvanceFocus returned false");
    return;
  }
}

void KeyboardEventManager::DefaultEscapeEventHandler(KeyboardEvent* event) {
  Page* page = frame_->GetPage();
  if (!page)
    return;

  if (IsSpatialNavigationEnabled(frame_) &&
      !frame_->GetDocument()->InDesignMode()) {
    page->GetSpatialNavigationController().HandleEscapeKeyboardEvent(event);
  }

  frame_->DomWindow()->closewatcher_stack()->EscapeKeyHandler(event);
}

void KeyboardEventManager::DefaultEnterEventHandler(KeyboardEvent* event) {
  Page* page = frame_->GetPage();
  if (!page)
    return;

  if (IsSpatialNavigationEnabled(frame_) &&
      !frame_->GetDocument()->InDesignMode()) {
    page->GetSpatialNavigationController().HandleEnterKeyboardEvent(event);
  }
}

void KeyboardEventManager::DefaultImeSubmitHandler(KeyboardEvent* event) {
  Page* page = frame_->GetPage();
  if (!page)
    return;

  if (IsSpatialNavigationEnabled(frame_) &&
      !frame_->GetDocument()->InDesignMode()) {
    page->GetSpatialNavigationController().HandleImeSubmitKeyboardEvent(event);
  }
}

static OverrideCapsLockState g_override_caps_lock_state;

void KeyboardEventManager::SetCurrentCapsLockState(
    OverrideCapsLockState state) {
  g_override_caps_lock_state = state;
}

bool KeyboardEventManager::CurrentCapsLockState() {
  switch (g_override_caps_lock_state) {
    case OverrideCapsLockState::kDefault:
#if BUILDFLAG(IS_MAC)
      return GetCurrentKeyModifiers() & alphaLock;
#else
      // Caps lock state use is limited to Mac password input
      // fields, so just return false. See http://crbug.com/618739.
      return false;
#endif
    case OverrideCapsLockState::kOn:
      return true;
    case OverrideCapsLockState::kOff:
    default:
      return false;
  }
}

WebInputEvent::Modifiers KeyboardEventManager::GetCurrentModifierState() {
#if BUILDFLAG(IS_MAC)
  unsigned modifiers = 0;
  UInt32 current_modifiers = GetCurrentKeyModifiers();
  if (current_modifiers & ::shiftKey)
    modifiers |= WebInputEvent::kShiftKey;
  if (current_modifiers & ::controlKey)
    modifiers |= WebInputEvent::kControlKey;
  if (current_modifiers & ::optionKey)
    modifiers |= WebInputEvent::kAltKey;
  if (current_modifiers & ::cmdKey)
    modifiers |= WebInputEvent::kMetaKey;
  return static_cast<WebInputEvent::Modifiers>(modifiers);
#else
  // TODO(crbug.com/538289): Implement on other platforms.
  return static_cast<WebInputEvent::Modifiers>(0);
#endif
}

}  // namespace blink

"""

```