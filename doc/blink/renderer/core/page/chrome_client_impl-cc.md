Response:
My thought process for analyzing the `chrome_client_impl.cc` code and generating the response goes through these stages:

1. **Understanding the Request:** I first broke down the request's key components:
    * Identify the file's purpose.
    * Explain its relationship to JavaScript, HTML, and CSS.
    * Provide examples of these relationships.
    * Offer logical inferences (input/output scenarios).
    * Illustrate common usage errors.
    * Detail the user actions leading to this code.
    * Focus on summarizing the file's functionality (for Part 1).

2. **Initial Code Scan (High-Level):** I quickly scanned the `#include` directives and the class name `ChromeClientImpl`. This immediately tells me:
    * It's a C++ implementation file.
    * It interacts with other Blink/Chromium components (indicated by the included headers).
    * It implements an interface called `ChromeClient`.
    * The `Impl` suffix suggests this is a concrete implementation.

3. **Identifying Key Responsibilities (Based on Includes and Method Names):**  I looked for recurring patterns in the includes and method names. This helped me identify the major areas of responsibility:
    * **Window Management:**  `SetWindowRect`, `Minimize`, `Maximize`, `Restore`, `SetResizable`, `CreateWindowDelegate`, `Show`, `CloseWindow`. These point to managing the browser window's properties and creation.
    * **Focus Management:** `FocusPage`, `DidFocusPage`, `CanTakeFocus`, `TakeFocus`, `SetKeyboardFocusURL`. This deals with the active element within the page and interactions with the browser's focus.
    * **Drag and Drop:** `StartDragging`, `AcceptsLoadDrops`. Handles drag-and-drop operations.
    * **Dialogs:** `OpenJavaScriptAlertDelegate`, `OpenJavaScriptConfirmDelegate`, `OpenJavaScriptPromptDelegate`, `OpenBeforeUnloadConfirmPanelDelegate`. Manages JavaScript dialogs.
    * **Console Logging:** `AddMessageToConsole`, `ShouldReportDetailedMessageForSourceAndSeverity`. Deals with reporting console messages.
    * **Tooltips:** `ShowMouseOverURL`, `UpdateTooltipUnderCursor`, `UpdateTooltipFromKeyboard`, `ClearKeyboardTriggeredTooltip`. Manages the display of tooltips.
    * **Popups (General UI):** The presence of `NotifyPopupOpeningObservers` and methods related to color and date/time choosers and file choosers indicate involvement in managing general UI popups.
    * **Scrolling and Zooming:** `InjectScrollbarGestureScroll`, `FinishScrollFocusedEditableIntoView`, `SetOverscrollBehavior`, `ZoomToFindInPageRect`, `PageScaleFactorChanged`. Deals with scrolling and zooming behaviors.
    * **Screen Information:** `GetScreenInfo`, `GetScreenInfos`. Provides information about the user's screen(s).
    * **Resizing and Layout:** `ContentsSizeChanged`, `EnablePreferredSizeChangedMode`, `ResizeAfterLayout`, `MainFrameLayoutUpdated`. Handles content resizing and layout updates.
    * **Drag Regions:** `SupportsDraggableRegions`, `DraggableRegionsChanged`. Manages draggable areas of the window.
    * **Printing:** `PrintDelegate`. Handles print requests.
    * **DevTools Integration:** `InputEventsScaleForEmulation`. Provides support for developer tools.

4. **Connecting to JavaScript, HTML, and CSS:** With the key responsibilities identified, I started thinking about how each area interacts with the core web technologies:
    * **JavaScript:**  JavaScript code directly triggers actions handled by `ChromeClientImpl` like opening dialogs (`alert()`, `confirm()`, `prompt()`), opening new windows (`window.open()`), interacting with form elements (file choosers, date/time pickers, color pickers), and sometimes influencing focus or drag-and-drop.
    * **HTML:**  HTML elements and attributes trigger behaviors handled here. Links (`<a>`) trigger navigation and URL display (`ShowMouseOverURL`). Form elements (`<input type="file">`, `<input type="date">`, `<input type="color">`) directly use the chooser functionalities. Draggable regions are defined in HTML/CSS.
    * **CSS:** CSS affects rendering and layout, which are indirectly connected. For example, the size and position of elements impact scrolling behavior. CSS `cursor` property could potentially relate to cursor overrides. Draggable regions can be styled with CSS.

5. **Developing Examples:** For each connection to JavaScript, HTML, and CSS, I crafted specific examples to illustrate the interaction. I focused on clear and concise code snippets that directly relate to the functions in `ChromeClientImpl`.

6. **Inferring Logical Behavior (Input/Output):** I considered what would happen given certain inputs. For example, calling `window.open()` in JavaScript leads to `CreateWindowDelegate`. Clicking a link leads to `ShowMouseOverURL`. These are direct cause-and-effect relationships.

7. **Identifying Common Errors:** I thought about typical mistakes developers might make that would involve this code:
    * Over-reliance on synchronous dialogs.
    * Incorrectly handling file chooser results.
    * Misunderstanding the timing of window open events.

8. **Tracing User Actions:** I reconstructed the steps a user would take in a browser to reach the execution of code within `chrome_client_impl.cc`. This involves starting with basic actions like opening a webpage and progressing to more specific interactions.

9. **Summarizing Functionality (For Part 1):** Finally, I synthesized the information gathered into a concise summary, emphasizing the role of `ChromeClientImpl` as the intermediary between the rendering engine (Blink) and the browser's UI and functionality. I highlighted its role in managing windows, dialogs, and other browser-level interactions.

**Self-Correction/Refinement During the Process:**

* **Initial Broadness:** My initial thoughts might have been too broad. I needed to focus specifically on the *functions* of the class as presented in the code snippet, rather than general web browser behavior.
* **Specificity of Examples:**  I made sure the examples were directly tied to the methods in the provided code. Vague examples wouldn't be as helpful.
* **Clarity of Explanations:** I aimed for clear and concise explanations, avoiding overly technical jargon where possible. The goal is to be understandable to someone familiar with web development concepts.
* **Emphasis on "Part 1":** Since the request explicitly mentioned "Part 1," I concentrated on summarizing the overall *functionality* as evidenced by the provided code, leaving deeper dives into specific method implementations for a potential "Part 2."
好的，让我们来分析一下 `blink/renderer/core/page/chrome_client_impl.cc` 文件的功能。

**文件功能归纳 (第 1 部分):**

`ChromeClientImpl.cc` 文件是 Chromium Blink 渲染引擎中 `ChromeClient` 接口的一个具体实现。`ChromeClient` 接口定义了渲染引擎与浏览器宿主环境（Chrome 浏览器本身）进行通信的方式。`ChromeClientImpl` 负责处理来自 Blink 渲染引擎的各种请求，并将这些请求转发给浏览器宿主环境进行处理。

简单来说，`ChromeClientImpl` 就像一个**渲染引擎的特派员**，它代表渲染引擎与浏览器进行各种交互，例如：

* **窗口管理:**  创建、显示、调整、最小化、最大化和关闭浏览器窗口。
* **焦点管理:**  请求获得或失去键盘焦点。
* **拖放操作:**  启动拖放操作。
* **弹窗处理:**  创建和管理新的浏览器窗口或标签页。
* **JavaScript 对话框:**  显示 `alert`、`confirm` 和 `prompt` 对话框。
* **控制台消息:**  将 JavaScript 控制台消息传递给浏览器进行显示。
* **打印:**  发起打印操作。
* **UI 组件:**  打开颜色选择器、日期/时间选择器和文件选择器等 UI 组件。
* **工具提示:**  显示鼠标悬停时的工具提示。
* **视口控制:**  通知浏览器视口属性的更改。
* **页面缩放:**  通知浏览器页面缩放因子的变化。
* **鼠标事件 URL:**  通知浏览器鼠标悬停的链接 URL。
* **BeforeUnload 处理:**  处理 `beforeunload` 事件，允许用户取消页面卸载。
* **DevTools 集成:**  提供与开发者工具集成的功能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`ChromeClientImpl` 在连接渲染引擎和浏览器宿主方面扮演着关键角色，因此它与 JavaScript, HTML, CSS 都有密切关系，因为这些技术都是在渲染引擎中解析和执行的。

**1. 与 JavaScript 的关系:**

* **`OpenJavaScriptAlertDelegate`, `OpenJavaScriptConfirmDelegate`, `OpenJavaScriptPromptDelegate`:**
    * **功能:** 当 JavaScript 代码调用 `alert()`, `confirm()`, 或 `prompt()` 函数时，Blink 引擎会调用 `ChromeClientImpl` 中相应的函数。
    * **举例:**
        ```javascript
        // JavaScript 代码
        alert("这是一个警告消息！");
        let confirmed = confirm("你确定要继续吗？");
        let name = prompt("请输入你的名字：", "默认名字");
        ```
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** JavaScript 执行 `alert("Hello");`
        * **输出:** `ChromeClientImpl::OpenJavaScriptAlertDelegate` 被调用，浏览器会弹出一个显示 "Hello" 的警告框。
* **`CreateWindowDelegate`:**
    * **功能:** 当 JavaScript 代码调用 `window.open()` 方法时，Blink 引擎会调用此函数，请求浏览器创建一个新的窗口或标签页。
    * **举例:**
        ```javascript
        // JavaScript 代码
        window.open("https://www.example.com", "_blank", "width=600,height=400");
        ```
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** JavaScript 执行 `window.open("https://new.page");`
        * **输出:** `ChromeClientImpl::CreateWindowDelegate` 被调用，浏览器会尝试打开一个新的标签页或窗口加载 `https://new.page`。
* **`AddMessageToConsole`:**
    * **功能:** 当 JavaScript 代码中使用 `console.log()`, `console.warn()`, `console.error()` 等函数时，Blink 引擎会将消息传递给 `ChromeClientImpl`，最终显示在浏览器的开发者工具控制台中。
    * **举例:**
        ```javascript
        // JavaScript 代码
        console.log("这是一条日志消息");
        console.warn("这是一个警告");
        console.error("发生错误了！");
        ```

**2. 与 HTML 的关系:**

* **文件选择器 (`OpenFileChooser`):**
    * **功能:** 当用户点击 `<input type="file">` 元素时，Blink 引擎会调用 `ChromeClientImpl::OpenFileChooser`，请求浏览器显示文件选择对话框。
    * **举例:**
        ```html
        <!-- HTML 代码 -->
        <input type="file" id="fileInput">
        ```
    * **用户操作到达这里:** 用户在网页上点击了 `<input type="file">` 元素。
* **颜色选择器 (`OpenColorChooser`):**
    * **功能:** 当 JavaScript 调用显示颜色选择器的 API，或者某些 HTML 元素（例如 `<input type="color">`）触发颜色选择时，Blink 引擎会调用 `ChromeClientImpl::OpenColorChooser`。
    * **举例:**
        ```html
        <!-- HTML 代码 -->
        <input type="color" id="colorPicker">
        ```
    * **用户操作到达这里:** 用户在网页上与颜色相关的元素交互，或者 JavaScript 代码请求显示颜色选择器。
* **日期/时间选择器 (`OpenDateTimeChooser`):**
    * **功能:** 类似于颜色选择器，当用户与日期或时间相关的 HTML 元素（例如 `<input type="date">`, `<input type="time">` 等）交互时，或者 JavaScript 代码请求显示日期/时间选择器时，`ChromeClientImpl::OpenDateTimeChooser` 会被调用。
    * **举例:**
        ```html
        <!-- HTML 代码 -->
        <input type="date" id="datePicker">
        ```
    * **用户操作到达这里:** 用户在网页上与日期或时间相关的元素交互。
* **拖放 (`StartDragging`, `AcceptsLoadDrops`):**
    * **功能:** 当用户在页面上拖动元素时，或者将文件拖放到浏览器窗口时，`ChromeClientImpl` 负责启动拖放操作或判断是否接受拖放的文件。
    * **用户操作到达这里:** 用户在页面上长按并移动某个元素，或者将文件从桌面拖放到浏览器窗口。
* **链接和工具提示 (`ShowMouseOverURL`, `UpdateTooltipUnderCursor`):**
    * **功能:** 当鼠标悬停在链接或其他元素上时，Blink 引擎会通知 `ChromeClientImpl` 显示链接 URL 或工具提示。
    * **举例:**
        ```html
        <!-- HTML 代码 -->
        <a href="https://www.example.com">点击这里</a>
        <span title="这是工具提示">鼠标悬停在这里</span>
        ```
    * **用户操作到达这里:** 用户将鼠标指针移动到链接或带有 `title` 属性的元素上。

**3. 与 CSS 的关系:**

* **窗口大小和位置 (`SetWindowRect`, `Minimize`, `Maximize`, `Restore`):**
    * **功能:** 虽然 CSS 主要控制元素的样式，但某些 JavaScript 操作（例如使用 `window.resizeTo()`, `window.moveTo()` 等）会间接影响浏览器窗口的大小和位置，这些操作最终会通过 `ChromeClientImpl` 与浏览器进行通信。
    * **用户操作到达这里:** 某些网页上的 JavaScript 代码尝试调整窗口大小或位置。
* **拖拽区域 (`SupportsDraggableRegions`, `DraggableRegionsChanged`):**
    * **功能:** CSS 可以定义允许用户拖拽的区域 (`-webkit-app-region: drag;`)，`ChromeClientImpl` 会根据这些定义来处理拖拽事件。
    * **用户操作到达这里:** 用户尝试拖拽使用 CSS 定义的可拖拽区域。

**逻辑推理的例子:**

* **假设输入:** 用户点击一个链接，该链接的目标是下载一个文件。
* **输出:** Blink 引擎会创建一个下载请求，`ChromeClientImpl` 会将此请求转发给浏览器宿主环境，由浏览器启动下载过程。

**用户或编程常见的使用错误举例:**

* **过度使用同步对话框 (`alert`, `confirm`, `prompt`):**  这些对话框会阻塞用户界面的渲染线程，导致用户体验变差。开发者应尽量避免大量或不必要的同步对话框。
* **没有正确处理文件选择器的回调:**  开发者可能忘记处理用户选择的文件，或者在用户取消选择后没有进行相应的处理。
* **在不适当的时机调用 `window.open()`:**  浏览器通常会阻止在非用户手势触发的情况下打开弹窗，这可能导致 `CreateWindowDelegate` 没有被调用，或者弹窗被阻止。

**用户操作是如何一步步的到达这里 (作为调试线索):**

以下是一些用户操作如何最终触发 `ChromeClientImpl` 中代码执行的例子：

1. **打开新标签页:**
   * 用户点击浏览器上的 "新建标签页" 按钮。
   * 浏览器进程指示渲染器进程创建一个新的渲染进程。
   * 在新的渲染进程中，会创建 `ChromeClientImpl` 的实例。

2. **访问网页并点击链接:**
   * 用户在地址栏输入 URL 或点击书签。
   * 浏览器请求网页内容。
   * 渲染引擎解析 HTML, CSS 和 JavaScript。
   * 用户点击网页上的一个 `<a>` 链接。
   * Blink 引擎确定导航行为。
   * 如果是同窗口导航，可能不会直接涉及到 `ChromeClientImpl` 的窗口管理功能。
   * 如果是 `target="_blank"` 或需要打开新窗口的场景，会调用 `ChromeClientImpl::CreateWindowDelegate`。
   * 当鼠标悬停在链接上时，会调用 `ChromeClientImpl::ShowMouseOverURL`。

3. **网页执行 JavaScript 代码:**
   * 用户访问一个包含 JavaScript 代码的网页。
   * JavaScript 代码执行 `alert("Hello");`
   * Blink 引擎的 JavaScript 引擎会调用 `ChromeClientImpl::OpenJavaScriptAlertDelegate`。

4. **与表单元素交互:**
   * 用户访问一个包含 `<input type="file">` 的网页。
   * 用户点击该输入框。
   * Blink 引擎会调用 `ChromeClientImpl::OpenFileChooser`。

**总结 (针对第 1 部分):**

`ChromeClientImpl` 是 Blink 渲染引擎与 Chrome 浏览器宿主环境之间的关键桥梁。它负责处理各种由渲染引擎发起的、需要浏览器层面支持的操作，包括窗口管理、用户交互（例如对话框、文件选择）、以及一些浏览器级别的功能（例如打印、控制台消息）。理解 `ChromeClientImpl` 的功能对于理解 Blink 引擎如何与浏览器协同工作至关重要。

希望这个详细的解释能够帮助你理解 `ChromeClientImpl.cc` 的作用！如果你有关于第 2 部分的问题，请随时提出。

### 提示词
```
这是目录为blink/renderer/core/page/chrome_client_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
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

#include "third_party/blink/renderer/core/page/chrome_client_impl.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/debug/alias.h"
#include "build/build_config.h"
#include "cc/animation/animation_host.h"
#include "cc/animation/animation_timeline.h"
#include "cc/layers/picture_layer.h"
#include "cc/trees/paint_holding_reason.h"
#include "third_party/blink/public/common/page/page_zoom.h"
#include "third_party/blink/public/common/widget/constants.h"
#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/public/mojom/manifest/display_mode.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/public/web/web_autofill_client.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_form_element.h"
#include "third_party/blink/public/web/web_input_element.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_node.h"
#include "third_party/blink/public/web/web_plugin.h"
#include "third_party/blink/public/web/web_popup_menu_info.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/public/web/web_window_features.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"
#include "third_party/blink/renderer/core/exported/web_dev_tools_agent_impl.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/exported/web_settings_impl.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/browser_controls.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/frame/web_remote_frame_impl.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/forms/color_chooser.h"
#include "third_party/blink/renderer/core/html/forms/color_chooser_client.h"
#include "third_party/blink/renderer/core/html/forms/color_chooser_popup_ui_controller.h"
#include "third_party/blink/renderer/core/html/forms/color_chooser_ui_controller.h"
#include "third_party/blink/renderer/core/html/forms/date_time_chooser.h"
#include "third_party/blink/renderer/core/html/forms/date_time_chooser_client.h"
#include "third_party/blink/renderer/core/html/forms/date_time_chooser_impl.h"
#include "third_party/blink/renderer/core/html/forms/external_date_time_chooser.h"
#include "third_party/blink/renderer/core/html/forms/external_popup_menu.h"
#include "third_party/blink/renderer/core/html/forms/file_chooser.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/internal_popup_menu.h"
#include "third_party/blink/renderer/core/html/html_embed_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/inspector/dev_tools_emulator.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/loader/navigation_policy.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/popup_opening_observer.h"
#include "third_party/blink/renderer/core/page/validation_message_client.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_request.h"
#include "third_party/blink/renderer/platform/graphics/compositor_element_id.h"
#include "third_party/blink/renderer/platform/graphics/touch_action.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/resource_coordinator/document_resource_coordinator.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/text_direction.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_concatenate.h"
#include "ui/gfx/geometry/rect.h"

namespace blink {

namespace {

const char* UIElementTypeToString(ChromeClient::UIElementType ui_element_type) {
  switch (ui_element_type) {
    case ChromeClient::UIElementType::kAlertDialog:
      return "alert";
    case ChromeClient::UIElementType::kConfirmDialog:
      return "confirm";
    case ChromeClient::UIElementType::kPromptDialog:
      return "prompt";
    case ChromeClient::UIElementType::kPrintDialog:
      return "print";
    case ChromeClient::UIElementType::kPopup:
      return "popup";
  }
  NOTREACHED();
}

const char* DismissalTypeToString(Document::PageDismissalType dismissal_type) {
  switch (dismissal_type) {
    case Document::kBeforeUnloadDismissal:
      return "beforeunload";
    case Document::kPageHideDismissal:
      return "pagehide";
    case Document::kUnloadVisibilityChangeDismissal:
      return "visibilitychange";
    case Document::kUnloadDismissal:
      return "unload";
    case Document::kNoDismissal:
      NOTREACHED();
  }
  NOTREACHED();
}

String TruncateDialogMessage(const String& message) {
  if (message.IsNull())
    return g_empty_string;

  // 10k ought to be enough for anyone.
  const wtf_size_t kMaxMessageSize = 10 * 1024;
  return message.Substring(0, kMaxMessageSize);
}

bool DisplayModeIsBorderless(LocalFrame& frame) {
  FrameWidget* widget = frame.GetWidgetForLocalRoot();
  return widget->DisplayMode() == mojom::blink::DisplayMode::kBorderless;
}

}  // namespace

static bool g_can_browser_handle_focus = false;

// Function defined in third_party/blink/public/web/blink.h.
void SetBrowserCanHandleFocusForWebTest(bool value) {
  g_can_browser_handle_focus = value;
}

ChromeClientImpl::ChromeClientImpl(WebViewImpl* web_view)
    : web_view_(web_view),
      cursor_overridden_(false),
      did_request_non_empty_tool_tip_(false) {
  DCHECK(web_view_);
}

ChromeClientImpl::~ChromeClientImpl() {
  DCHECK(file_chooser_queue_.empty());
}

void ChromeClientImpl::Trace(Visitor* visitor) const {
  visitor->Trace(popup_opening_observers_);
  visitor->Trace(external_date_time_chooser_);
  visitor->Trace(commit_observers_);
  ChromeClient::Trace(visitor);
}

WebViewImpl* ChromeClientImpl::GetWebView() const {
  return web_view_;
}

void ChromeClientImpl::ChromeDestroyed() {
  // Clear |web_view_| since it is refcounted and this class is a GC'd object
  // and may outlive the WebViewImpl.
  web_view_ = nullptr;
}

void ChromeClientImpl::SetWindowRect(const gfx::Rect& requested_rect,
                                     LocalFrame& frame) {
  DCHECK(web_view_);
  DCHECK_EQ(&frame, web_view_->MainFrameImpl()->GetFrame());

  int minimum_size = DisplayModeIsBorderless(frame)
                         ? blink::kMinimumBorderlessWindowSize
                         : blink::kMinimumWindowSize;

  // TODO(crbug.com/1515106): Refactor so that the limits only live browser-side
  // instead of now partly being duplicated browser-side and renderer side.
  const gfx::Rect rect_adjusted_for_minimum =
      AdjustWindowRectForMinimum(requested_rect, minimum_size);
  const gfx::Rect adjusted_rect = AdjustWindowRectForDisplay(
      rect_adjusted_for_minimum, frame, minimum_size);
  // Request the unadjusted rect if the browser may honor cross-screen bounds.
  // Permission state is not readily available, so adjusted bounds are clamped
  // to the same-screen, to retain legacy behavior of synchronous pending values
  // and to avoid exposing other screen details to frames without permission.
  // TODO(crbug.com/897300): Use permission state for better sync estimates or
  // store unadjusted pending window rects if that will not break many sites.
  web_view_->MainFrameViewWidget()->SetWindowRect(rect_adjusted_for_minimum,
                                                  adjusted_rect);
}

void ChromeClientImpl::Minimize(LocalFrame&) {
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  DCHECK(web_view_);
  web_view_->Minimize();
#endif
}

void ChromeClientImpl::Maximize(LocalFrame&) {
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  DCHECK(web_view_);
  web_view_->Maximize();
#endif
}

void ChromeClientImpl::Restore(LocalFrame&) {
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  DCHECK(web_view_);
  web_view_->Restore();
#endif
}

void ChromeClientImpl::SetResizable(bool resizable, LocalFrame& frame) {
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  DCHECK(web_view_);
  web_view_->SetResizable(resizable);
#endif
}

gfx::Rect ChromeClientImpl::RootWindowRect(LocalFrame& frame) {
  // The WindowRect() for each WebFrameWidget will be the same rect of the top
  // level window.
  return frame.GetWidgetForLocalRoot()->WindowRect();
}

void ChromeClientImpl::DidAccessInitialMainDocument() {
  DCHECK(web_view_);
  web_view_->DidAccessInitialMainDocument();
}

void ChromeClientImpl::FocusPage() {
  DCHECK(web_view_);
  web_view_->Focus();
}

void ChromeClientImpl::DidFocusPage() {
  DCHECK(web_view_);
  if (web_view_->Client())
    web_view_->Client()->DidFocus();
}

bool ChromeClientImpl::CanTakeFocus(mojom::blink::FocusType) {
  // For now the browser can always take focus if we're not running layout
  // tests.
  if (!WebTestSupport::IsRunningWebTest())
    return true;
  return g_can_browser_handle_focus;
}

void ChromeClientImpl::TakeFocus(mojom::blink::FocusType type) {
  DCHECK(web_view_);
  web_view_->TakeFocus(type == mojom::blink::FocusType::kBackward);
}

void ChromeClientImpl::SetKeyboardFocusURL(Element* new_focus_element) {
  DCHECK(web_view_);
  KURL focus_url;
  if (new_focus_element && new_focus_element->IsLiveLink() &&
      new_focus_element->ShouldHaveFocusAppearance())
    focus_url = new_focus_element->HrefURL();
  web_view_->SetKeyboardFocusURL(focus_url);
}

bool ChromeClientImpl::SupportsDraggableRegions() {
  return web_view_->SupportsDraggableRegions();
}

void ChromeClientImpl::DraggableRegionsChanged() {
  return web_view_->DraggableRegionsChanged();
}

void ChromeClientImpl::StartDragging(LocalFrame* frame,
                                     const WebDragData& drag_data,
                                     DragOperationsMask mask,
                                     const SkBitmap& drag_image,
                                     const gfx::Vector2d& cursor_offset,
                                     const gfx::Rect& drag_obj_rect) {
  WebLocalFrameImpl* web_frame = WebLocalFrameImpl::FromFrame(frame);
  web_frame->LocalRootFrameWidget()->StartDragging(
      frame, drag_data, mask, drag_image, cursor_offset, drag_obj_rect);
}

bool ChromeClientImpl::AcceptsLoadDrops() const {
  DCHECK(web_view_);
  return web_view_->GetRendererPreferences().can_accept_load_drops;
}

Page* ChromeClientImpl::CreateWindowDelegate(
    LocalFrame* frame,
    const FrameLoadRequest& r,
    const AtomicString& name,
    const WebWindowFeatures& features,
    network::mojom::blink::WebSandboxFlags sandbox_flags,
    const SessionStorageNamespaceId& session_storage_namespace_id,
    bool& consumed_user_gesture) {
  if (!frame->GetPage() || frame->GetPage()->Paused())
    return nullptr;

  WebLocalFrameImpl* web_frame = WebLocalFrameImpl::FromFrame(frame);
  if (!web_frame)
    return nullptr;

  NotifyPopupOpeningObservers();
  const AtomicString& frame_name =
      !EqualIgnoringASCIICase(name, "_blank") ? name : g_empty_atom;
  WebViewImpl* new_view =
      static_cast<WebViewImpl*>(web_frame->Client()->CreateNewWindow(
          WrappedResourceRequest(r.GetResourceRequest()), features, frame_name,
          static_cast<WebNavigationPolicy>(r.GetNavigationPolicy()),
          sandbox_flags, session_storage_namespace_id, consumed_user_gesture,
          r.Impression(), r.GetPictureInPictureWindowOptions(),
          r.GetRequestorBaseURL()));
  if (!new_view)
    return nullptr;
  return new_view->GetPage();
}

void ChromeClientImpl::InjectScrollbarGestureScroll(
    LocalFrame& local_frame,
    const gfx::Vector2dF& delta,
    ui::ScrollGranularity granularity,
    CompositorElementId scrollable_area_element_id,
    WebInputEvent::Type injected_type) {
  local_frame.GetWidgetForLocalRoot()->InjectScrollbarGestureScroll(
      delta, granularity, scrollable_area_element_id, injected_type);
}

void ChromeClientImpl::FinishScrollFocusedEditableIntoView(
    const gfx::RectF& caret_rect_in_root_frame,
    mojom::blink::ScrollIntoViewParamsPtr params) {
  DCHECK(web_view_);
  DCHECK(web_view_->MainFrameImpl());
  DCHECK(!web_view_->IsFencedFrameRoot());
  web_view_->FinishScrollFocusedEditableIntoView(caret_rect_in_root_frame,
                                                 std::move(params));
}

void ChromeClientImpl::SetOverscrollBehavior(
    LocalFrame& main_frame,
    const cc::OverscrollBehavior& overscroll_behavior) {
  DCHECK(main_frame.IsOutermostMainFrame());
  main_frame.GetWidgetForLocalRoot()->SetOverscrollBehavior(
      overscroll_behavior);
}

void ChromeClientImpl::Show(LocalFrame& frame,
                            LocalFrame& opener_frame,
                            NavigationPolicy navigation_policy,
                            bool user_gesture) {
  DCHECK(web_view_);
  const WebWindowFeatures& features = frame.GetPage()->GetWindowFeatures();
  gfx::Rect bounds(features.x, features.y, features.width, features.height);

  // The minimum size from popups opened from borderless apps differs from
  // normal apps. When window.open is called, display-mode for the new frame is
  // still undefined as the app hasn't loaded yet, thus opener frame is used.
  int minimum_size =
      navigation_policy == NavigationPolicy::kNavigationPolicyNewPopup &&
              DisplayModeIsBorderless(opener_frame)
          ? blink::kMinimumBorderlessWindowSize
          : blink::kMinimumWindowSize;

  // TODO(crbug.com/1515106): Refactor so that the limits only live browser-side
  // instead of now partly being duplicated browser-side and renderer side.
  const gfx::Rect rect_adjusted_for_minimum =
      AdjustWindowRectForMinimum(bounds, minimum_size);
  const gfx::Rect adjusted_rect = AdjustWindowRectForDisplay(
      rect_adjusted_for_minimum, frame, minimum_size);
  // Request the unadjusted rect if the browser may honor cross-screen bounds.
  // Permission state is not readily available, so adjusted bounds are clamped
  // to the same-screen, to retain legacy behavior of synchronous pending values
  // and to avoid exposing other screen details to frames without permission.
  // TODO(crbug.com/897300): Use permission state for better sync estimates or
  // store unadjusted pending window rects if that will not break many sites.
  web_view_->Show(opener_frame.GetLocalFrameToken(), navigation_policy,
                  rect_adjusted_for_minimum, adjusted_rect, user_gesture);
}

bool ChromeClientImpl::ShouldReportDetailedMessageForSourceAndSeverity(
    LocalFrame& local_frame,
    mojom::blink::ConsoleMessageLevel log_level,
    const String& url) {
  WebLocalFrameImpl* webframe =
      WebLocalFrameImpl::FromFrame(local_frame.LocalFrameRoot());
  return webframe && webframe->Client() &&
         webframe->Client()->ShouldReportDetailedMessageForSourceAndSeverity(
             log_level, url);
}

void ChromeClientImpl::AddMessageToConsole(LocalFrame* local_frame,
                                           mojom::ConsoleMessageSource source,
                                           mojom::ConsoleMessageLevel level,
                                           const String& message,
                                           unsigned line_number,
                                           const String& source_id,
                                           const String& stack_trace) {
  if (!message.IsNull()) {
    local_frame->GetLocalFrameHostRemote().DidAddMessageToConsole(
        level, message, static_cast<int32_t>(line_number), source_id,
        stack_trace);
  }

  WebLocalFrameImpl* frame = WebLocalFrameImpl::FromFrame(local_frame);
  if (frame && frame->Client()) {
    frame->Client()->DidAddMessageToConsole(
        WebConsoleMessage(static_cast<mojom::ConsoleMessageLevel>(level),
                          message),
        source_id, line_number, stack_trace);
  }
}

bool ChromeClientImpl::CanOpenBeforeUnloadConfirmPanel() {
  DCHECK(web_view_);
  return !!web_view_->Client();
}

bool ChromeClientImpl::OpenBeforeUnloadConfirmPanelDelegate(LocalFrame* frame,
                                                            bool is_reload) {
  NotifyPopupOpeningObservers();

  if (before_unload_confirm_panel_result_for_testing_.has_value()) {
    bool success = before_unload_confirm_panel_result_for_testing_.value();
    before_unload_confirm_panel_result_for_testing_.reset();
    return success;
  }
  bool success = false;
  // Synchronous mojo call.
  frame->GetLocalFrameHostRemote().RunBeforeUnloadConfirm(is_reload, &success);
  return success;
}

void ChromeClientImpl::SetBeforeUnloadConfirmPanelResultForTesting(
    bool result) {
  before_unload_confirm_panel_result_for_testing_ = result;
}

void ChromeClientImpl::CloseWindow() {
  DCHECK(web_view_);
  web_view_->CloseWindow();
}

bool ChromeClientImpl::OpenJavaScriptAlertDelegate(LocalFrame* frame,
                                                   const String& message) {
  NotifyPopupOpeningObservers();
  bool disable_suppression = false;
  if (frame && frame->GetDocument()) {
    disable_suppression = RuntimeEnabledFeatures::
        DisableDifferentOriginSubframeDialogSuppressionEnabled(
            frame->GetDocument()->GetExecutionContext());
  }
  // Synchronous mojo call.
  frame->GetLocalFrameHostRemote().RunModalAlertDialog(
      TruncateDialogMessage(message), disable_suppression);
  return true;
}

bool ChromeClientImpl::OpenJavaScriptConfirmDelegate(LocalFrame* frame,
                                                     const String& message) {
  NotifyPopupOpeningObservers();
  bool success = false;
  bool disable_suppression = false;
  if (frame && frame->GetDocument()) {
    disable_suppression = RuntimeEnabledFeatures::
        DisableDifferentOriginSubframeDialogSuppressionEnabled(
            frame->GetDocument()->GetExecutionContext());
  }
  // Synchronous mojo call.
  frame->GetLocalFrameHostRemote().RunModalConfirmDialog(
      TruncateDialogMessage(message), disable_suppression, &success);
  return success;
}

bool ChromeClientImpl::OpenJavaScriptPromptDelegate(LocalFrame* frame,
                                                    const String& message,
                                                    const String& default_value,
                                                    String& result) {
  NotifyPopupOpeningObservers();
  bool success = false;
  bool disable_suppression = false;
  if (frame && frame->GetDocument()) {
    disable_suppression = RuntimeEnabledFeatures::
        DisableDifferentOriginSubframeDialogSuppressionEnabled(
            frame->GetDocument()->GetExecutionContext());
  }
  // Synchronous mojo call.
  frame->GetLocalFrameHostRemote().RunModalPromptDialog(
      TruncateDialogMessage(message),
      default_value.IsNull() ? g_empty_string : default_value,
      disable_suppression, &success, &result);
  return success;
}
bool ChromeClientImpl::TabsToLinks() {
  DCHECK(web_view_);
  return web_view_->TabsToLinks();
}

void ChromeClientImpl::InvalidateContainer() {
  DCHECK(web_view_);
  web_view_->InvalidateContainer();
}

void ChromeClientImpl::ScheduleAnimation(const LocalFrameView* frame_view,
                                         base::TimeDelta delay) {
  LocalFrame& frame = frame_view->GetFrame();
  // If the frame is still being created, it might not yet have a WebWidget.
  // TODO(dcheng): Is this the right thing to do? Is there a way to avoid having
  // a local frame root that doesn't have a WebWidget? During initialization
  // there is no content to draw so this call serves no purpose. Maybe the
  // WebFrameWidget needs to be initialized before initializing the core frame?
  FrameWidget* widget = frame.GetWidgetForLocalRoot();
  if (widget) {
    widget->RequestAnimationAfterDelay(delay);
  }
}

gfx::Rect ChromeClientImpl::LocalRootToScreenDIPs(
    const gfx::Rect& rect_in_local_root,
    const LocalFrameView* frame_view) const {
  LocalFrame& frame = frame_view->GetFrame();

  WebFrameWidgetImpl* widget =
      WebLocalFrameImpl::FromFrame(frame)->LocalRootFrameWidget();

  gfx::Rect rect_in_widget;
  if (widget->ForTopMostMainFrame()) {
    rect_in_widget = frame.GetPage()->GetVisualViewport().RootFrameToViewport(
        rect_in_local_root);
  } else {
    // TODO(bokan): This method needs to account for the visual viewport
    // transform when in a non-top-most local frame root. Unfortunately, the
    // widget's ViewRect doesn't include the visual viewport so this cannot be
    // done from here yet. See: https://crbug.com/928825,
    // https://crbug.com/840944.
    rect_in_widget = rect_in_local_root;
  }

  gfx::Rect view_rect = widget->ViewRect();

  gfx::Rect screen_rect = widget->BlinkSpaceToEnclosedDIPs(rect_in_widget);
  screen_rect.Offset(view_rect.x(), view_rect.y());

  return screen_rect;
}

float ChromeClientImpl::WindowToViewportScalar(LocalFrame* frame,
                                               const float scalar_value) const {

  // TODO(darin): Clean up callers to not pass null. E.g., VisualViewport::
  // ScrollbarThickness() is one such caller. See https://pastebin.com/axgctw0N
  // for a sample call stack.
  if (!frame) {
    DLOG(WARNING) << "LocalFrame is null!";
    return scalar_value;
  }

  if (auto* widget = frame->GetWidgetForLocalRoot()) {
    return widget->DIPsToBlinkSpace(scalar_value);
  }
  return scalar_value;
}

const display::ScreenInfo& ChromeClientImpl::GetScreenInfo(
    LocalFrame& frame) const {
  return frame.GetWidgetForLocalRoot()->GetScreenInfo();
}

const display::ScreenInfos& ChromeClientImpl::GetScreenInfos(
    LocalFrame& frame) const {
  return frame.GetWidgetForLocalRoot()->GetScreenInfos();
}

float ChromeClientImpl::InputEventsScaleForEmulation() const {
  DCHECK(web_view_);
  return web_view_->GetDevToolsEmulator()->InputEventsScaleForEmulation();
}

void ChromeClientImpl::ContentsSizeChanged(LocalFrame* frame,
                                           const gfx::Size& size) const {
  DCHECK(web_view_);
  web_view_->DidChangeContentsSize();

  WebLocalFrameImpl* webframe = WebLocalFrameImpl::FromFrame(frame);
  webframe->DidChangeContentsSize(size);
}

bool ChromeClientImpl::DoubleTapToZoomEnabled() const {
  DCHECK(web_view_);
  return web_view_->SettingsImpl()->DoubleTapToZoomEnabled();
}

void ChromeClientImpl::EnablePreferredSizeChangedMode() {
  DCHECK(web_view_);
  web_view_->EnablePreferredSizeChangedMode();
}

void ChromeClientImpl::ZoomToFindInPageRect(
    const gfx::Rect& rect_in_root_frame) {
  DCHECK(web_view_);
  web_view_->ZoomToFindInPageRect(rect_in_root_frame);
}

void ChromeClientImpl::PageScaleFactorChanged() const {
  DCHECK(web_view_);
  web_view_->PageScaleFactorChanged();
}

void ChromeClientImpl::OutermostMainFrameScrollOffsetChanged() const {
  web_view_->OutermostMainFrameScrollOffsetChanged();
}

float ChromeClientImpl::ClampPageScaleFactorToLimits(float scale) const {
  DCHECK(web_view_);
  return web_view_->ClampPageScaleFactorToLimits(scale);
}

void ChromeClientImpl::ResizeAfterLayout() const {
  DCHECK(web_view_);
  web_view_->ResizeAfterLayout();
}

void ChromeClientImpl::MainFrameLayoutUpdated() const {
  DCHECK(web_view_);
  web_view_->MainFrameLayoutUpdated();
}

void ChromeClientImpl::ShowMouseOverURL(const HitTestResult& result) {
  DCHECK(web_view_);
  if (!web_view_->Client())
    return;

  KURL url;

  // Ignore URL if hitTest include scrollbar since we might have both a
  // scrollbar and an element in the case of overlay scrollbars.
  if (!result.GetScrollbar()) {
    // Find out if the mouse is over a link, and if so, let our UI know...
    if (result.IsLiveLink() && !result.AbsoluteLinkURL().GetString().empty()) {
      url = result.AbsoluteLinkURL();
    } else if (result.InnerNode() &&
               (IsA<HTMLObjectElement>(*result.InnerNode()) ||
                IsA<HTMLEmbedElement>(*result.InnerNode()))) {
      if (auto* embedded = DynamicTo<LayoutEmbeddedContent>(
              result.InnerNode()->GetLayoutObject())) {
        if (WebPluginContainerImpl* plugin_view = embedded->Plugin()) {
          url = plugin_view->Plugin()->LinkAtPosition(
              result.RoundedPointInInnerNodeFrame());
        }
      }
    }
  }

  web_view_->SetMouseOverURL(url);
}

void ChromeClientImpl::UpdateTooltipUnderCursor(LocalFrame& frame,
                                                const String& tooltip_text,
                                                TextDirection dir) {
  WebFrameWidgetImpl* widget =
      WebLocalFrameImpl::FromFrame(frame)->LocalRootFrameWidget();
  if (!tooltip_text.empty()) {
    widget->UpdateTooltipUnderCursor(tooltip_text, dir);
    did_request_non_empty_tool_tip_ = true;
  } else if (did_request_non_empty_tool_tip_) {
    // WebFrameWidgetImpl::UpdateTooltipUnderCursor will send a Mojo message via
    // mojom::blink::WidgetHost. We'd like to reduce the number of
    // UpdateTooltipUnderCursor calls.
    widget->UpdateTooltipUnderCursor(tooltip_text, dir);
    did_request_non_empty_tool_tip_ = false;
  }
}

void ChromeClientImpl::UpdateTooltipFromKeyboard(LocalFrame& frame,
                                                 const String& tooltip_text,
                                                 TextDirection dir,
                                                 const gfx::Rect& bounds) {
  if (!RuntimeEnabledFeatures::KeyboardAccessibleTooltipEnabled())
    return;

  WebLocalFrameImpl::FromFrame(frame)
      ->LocalRootFrameWidget()
      ->UpdateTooltipFromKeyboard(tooltip_text, dir, bounds);
}

void ChromeClientImpl::ClearKeyboardTriggeredTooltip(LocalFrame& frame) {
  if (!RuntimeEnabledFeatures::KeyboardAccessibleTooltipEnabled())
    return;

  WebLocalFrameImpl::FromFrame(frame)
      ->LocalRootFrameWidget()
      ->ClearKeyboardTriggeredTooltip();
}

void ChromeClientImpl::DispatchViewportPropertiesDidChange(
    const ViewportDescription& description) const {
  DCHECK(web_view_);
  web_view_->UpdatePageDefinedViewportConstraints(description);
}

void ChromeClientImpl::PrintDelegate(LocalFrame* frame) {
  NotifyPopupOpeningObservers();
  WebLocalFrameImpl* web_frame = WebLocalFrameImpl::FromFrame(frame);
  web_frame->Client()->ScriptedPrint();
}

ColorChooser* ChromeClientImpl::OpenColorChooser(
    LocalFrame* frame,
    ColorChooserClient* chooser_client,
    const Color&) {
  NotifyPopupOpeningObservers();
  ColorChooserUIController* controller = nullptr;

  if (RuntimeEnabledFeatures::PagePopupEnabled()) {
    controller = MakeGarbageCollected<ColorChooserPopupUIController>(
        frame, this, chooser_client);
  } else {
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
    NOTREACHED() << "Page popups should be enabled on all but Android or iOS";
#else
    controller =
        MakeGarbageCollected<ColorChooserUIController>(frame, chooser_client);
#endif
  }
  controller->OpenUI();
  return controller;
}

DateTimeChooser* ChromeClientImpl::OpenDateTimeChooser(
    LocalFrame* frame,
    DateTimeChooserClient* picker_client,
    const DateTimeChooserParameters& parameters) {
  NotifyPopupOpeningObservers();
  if (RuntimeEnabledFeatures::InputMultipleFieldsUIEnabled()) {
    return MakeGarbageCollected<DateTimeChooserImpl>(frame, picker_client,
                                                     parameters);
  }

  // JavaScript may try to open a date time chooser while one is already open.
  if (external_date_time_chooser_ &&
      external_date_time_chooser_->IsShowingDateTimeChooserUI())
    return nullptr;

  external_date_time_chooser_ =
      MakeGarbageCollected<ExternalDateTimeChooser>(picker_client);
  external_date_time_chooser_->OpenDateTimeChooser(frame, parameters);
  return external_date_time_chooser_.Get();
}

ExternalDateTimeChooser*
ChromeClientImpl::GetExternalDateTimeChooserForTesting() {
  return external_date_time_chooser_.Get();
}

void ChromeClientImpl::OpenFileChooser(
    LocalFrame* frame,
    scoped_refptr<FileChooser> file_chooser) {
  NotifyPopupOpeningObservers();

  static const wtf_size_t kMaximumPendingFileChooseRequests = 4;
  if (file_chooser_queue_.size() > kMaximumPendingFileChooseRequests) {
    // This check prevents too many file choose requests from getting
    // queued which could DoS the user. Getting these is most likely a
    // programming error (there are many ways to DoS the user so it's not
    // considered a "real" security check), either in JS requesting many file
    // choosers to pop up, or in a plugin.
    //
    // TODO(brettw): We might possibly want to require a user gesture to open
    // a file picker, which will address this issue in a better way.
    return;
  }
  file_chooser_queue_.push_back(file_chooser.get());
  if (file_chooser_queue_.size() == 1) {
    // Actually show the browse dialog when this is the first request.
    if (file_chooser->OpenFileChooser(*this))
      return;
    // Choosing failed, so try the next chooser.
    DidCompleteFileChooser(*file_chooser);
  }
}

void ChromeClientImpl::DidCompleteFileC
```