Response:
Let's break down the thought process for analyzing the `create_window.cc` file.

**1. Initial Understanding of the File's Purpose (Based on Filename and Path):**

* **Filename:** `create_window.cc` strongly suggests this file is responsible for the logic of creating new browser windows or tabs.
* **Path:** `blink/renderer/core/page/` indicates this is a core part of the Blink rendering engine, specifically within the "page" management component. This suggests a lower-level involvement in the window creation process.

**2. High-Level Functional Breakdown (Skimming the Code):**

* Look for key function names: `GetWindowFeaturesFromString` and `CreateNewWindow` are immediately apparent. These seem to be the primary functions.
* Identify included headers: Headers like `WebWindowFeatures`, `LocalDOMWindow`, `LocalFrame`, `Page`, `FrameLoadRequest`, and `KURL` give clues about the data structures and concepts involved.
* Note namespaces: The code is within the `blink` namespace, confirming its Blink engine origin.

**3. Analyzing `GetWindowFeaturesFromString`:**

* **Purpose:** The function name and the comment above it clearly indicate it parses a string of window features (like `width=800,height=600,menubar=no`) and converts it into a structured `WebWindowFeatures` object.
* **Relationship to web technologies:** This directly relates to JavaScript's `window.open()` method, where the third argument is the features string. It also connects to HTML's `<a>` tag with `target="_blank"` and potentially `rel="noopener"` or `rel="noreferrer"`.
* **Logic:**  It iterates through the string, tokenizes it into key-value pairs, and sets corresponding fields in the `window_features` object. Notice the handling of "yes" or "true" for boolean values.
* **Assumptions/Inputs/Outputs:**
    * **Input:** A string of window features (e.g., "width=400,height=300").
    * **Assumptions:** The input string generally follows the HTML specification for window features. It handles variations in separators.
    * **Output:** A `WebWindowFeatures` object with the parsed settings.
* **Potential errors:** Incorrectly formatted feature strings (e.g., missing equals signs, typos in feature names) would lead to incorrect parsing or ignored features.

**4. Analyzing `CreateNewWindow`:**

* **Purpose:** This function is responsible for the actual creation of a new browser context (window or tab).
* **Relationship to web technologies:** This function is the core implementation behind JavaScript's `window.open()` and HTML's `target="_blank"`.
* **Logic:**
    * It performs security checks (e.g., checking for JavaScript URLs, local resource access).
    * It determines the navigation policy (new tab, new window, etc.) based on the features.
    * It handles sandboxed frames and their popup restrictions.
    * It deals with session storage isolation (`noopener`).
    * It calls into the `ChromeClient` (the browser shell integration point) to actually create the window.
    * It handles cases where the navigation might happen in the same tab.
* **Assumptions/Inputs/Outputs:**
    * **Inputs:**  A `LocalFrame` (the opener), a `FrameLoadRequest` (containing the URL and features), and an optional `frame_name`.
    * **Assumptions:** The opener frame is in a valid state.
    * **Output:** A pointer to the newly created `Frame` object, or `nullptr` if creation fails.
* **User/programming errors:**
    * Calling `window.open()` from a sandboxed iframe without `allow-popups`.
    * Trying to open a `javascript:` URL with incorrect syntax.
    * Violating security restrictions (e.g., cross-origin issues).
* **Debugging Clues:**  The function logs console messages for security errors. It interacts with `ChromeClient`, which is a key point for browser-specific behavior.

**5. Tracing User Actions:**

* Start with the most obvious trigger: clicking an `<a target="_blank">` link.
* Consider JavaScript: `window.open()` is the direct way to invoke this functionality.
* Think about related scenarios: form submissions with `target="_blank"`.
* Follow the execution flow conceptually:  User action -> Event handler (click/submit) -> JavaScript/HTML interpretation -> Call to Blink's rendering engine -> `CreateNewWindow`.

**6. Connecting to the Bigger Picture:**

* Recognize that `create_window.cc` is a low-level implementation detail. Users and even most web developers don't directly interact with this code.
* Understand that it's part of a complex process involving multiple layers of the browser (rendering engine, browser shell, operating system).

**Self-Correction/Refinement During Analysis:**

* Initially, I might have focused solely on `CreateNewWindow`. However, recognizing the importance of `GetWindowFeaturesFromString` and its role in parsing the feature string is crucial for a complete understanding.
* I paid attention to the comments in the code, which provided valuable context.
* I considered the security implications and the error handling within the code.
* I made sure to explicitly link the code's functionality back to concrete web technologies like JavaScript and HTML.

By following these steps, I could systematically dissect the `create_window.cc` file and arrive at a comprehensive understanding of its purpose, functionalities, relationships to web technologies, potential errors, and debugging clues.
好的，让我们来分析一下 `blink/renderer/core/page/create_window.cc` 这个 Chromium Blink 引擎的源代码文件。

**功能概述**

`create_window.cc` 文件的主要功能是实现浏览器中创建新窗口或标签页的逻辑。 它处理了当页面中的脚本或用户操作请求打开一个新的浏览上下文（browsing context）时发生的事情。 这包括：

1. **解析窗口特性字符串：**  `GetWindowFeaturesFromString` 函数负责解析由 JavaScript 的 `window.open()` 方法或者 HTML `<a>` 标签的 `target="_blank"` 属性提供的窗口特性字符串，例如 "width=800,height=600,menubar=no"。
2. **创建新的浏览上下文：** `CreateNewWindow` 函数是创建新窗口或标签页的核心。它接收来自现有 `LocalFrame` 的请求，并根据请求的 URL、窗口特性等信息，创建一个新的 `Frame` 对象（代表一个渲染的帧）。
3. **处理安全性和权限：** 该文件包含了检查，以确保新的窗口创建操作是合法的，例如检查 `allow-popups` 沙箱标志，以及验证 JavaScript URL 的安全性。
4. **管理会话存储：**  它处理了新窗口是否应该继承 opener 窗口的会话存储（session storage），这受到 `noopener` 窗口特性的影响。
5. **与浏览器进程通信：**  它通过 `ChromeClient` 接口与浏览器的上层（例如 Chrome 浏览器本身）进行通信，实际创建浏览器窗口并进行显示。
6. **记录指标：** 它可能包含用于记录窗口打开事件的逻辑，例如使用 UKM (User Keyed Metrics)。

**与 JavaScript, HTML, CSS 的关系及举例说明**

* **JavaScript:**
    * **功能关联：**  该文件直接实现了 `window.open()` JavaScript 方法的核心逻辑。当 JavaScript 代码调用 `window.open(url, target, features)` 时，`create_window.cc` 中的代码会被执行。
    * **举例说明：**
        ```javascript
        // JavaScript 代码尝试打开一个新的窗口
        window.open('https://www.example.com', '_blank', 'width=600,height=400');
        ```
        在这个例子中，`GetWindowFeaturesFromString` 会解析 `'width=600,height=400'` 字符串，而 `CreateNewWindow` 会根据解析出的特性和提供的 URL 创建新的窗口或标签页。

* **HTML:**
    * **功能关联：**  当 HTML 中的 `<a>` 标签设置了 `target="_blank"` 属性时，浏览器会触发创建新窗口的行为，这也会最终调用到 `create_window.cc` 中的代码。
    * **举例说明：**
        ```html
        <!-- HTML 链接，点击后在新标签页打开 -->
        <a href="https://www.example.com" target="_blank">在新标签页打开</a>
        ```
        当用户点击这个链接时，`CreateNewWindow` 会被调用，创建一个新的浏览上下文来加载 `https://www.example.com`。

    * **功能关联：** `rel="noopener"` 和 `rel="noreferrer"` 属性也会影响新窗口的创建方式，例如是否允许新窗口访问 opener 窗口的对象。`GetWindowFeaturesFromString` 会解析这些属性的影响。
    * **举例说明：**
        ```html
        <!-- HTML 链接，使用 noopener，阻止新窗口访问 opener -->
        <a href="https://www.example.com" target="_blank" rel="noopener">在新标签页打开 (noopener)</a>
        ```

* **CSS:**
    * **功能关联：**  CSS 本身不直接触发窗口创建。然而，CSS 可能会影响页面布局，而页面布局可能会间接导致 JavaScript 代码调用 `window.open()`。例如，一个按钮的样式可以使用 CSS 定义，而点击该按钮的事件监听器可能会调用 `window.open()`。
    * **举例说明：**  虽然 CSS 不直接参与，但可以想象一个场景：一个按钮被 CSS 设置了样式，并且 JavaScript 代码监听了该按钮的点击事件，并在点击时使用 `window.open()` 打开新窗口。

**逻辑推理的假设输入与输出**

假设输入一个包含窗口特性字符串的 `feature_string` 到 `GetWindowFeaturesFromString` 函数：

* **假设输入：** `feature_string = "width=800, height=600, menubar=yes, resizable=no"`
* **逻辑推理：** 函数会遍历字符串，识别出 "width"、"height"、"menubar" 和 "resizable" 这些键，并解析它们对应的值。它会处理空格和逗号作为分隔符。对于没有明确值的键（虽然这个例子没有），会默认为 "yes" 或 "true"。
* **输出：**  一个 `WebWindowFeatures` 对象，其成员变量会被设置为：
    * `width_set = true;`
    * `width = 800;`
    * `height_set = true;`
    * `height = 600;`
    * `menubar = true;`
    * `resizable = 0;` (因为 "no" 会被解析为 0)

假设一个 `LocalFrame` 调用 `CreateNewWindow` 函数，请求打开一个新的 URL：

* **假设输入：**
    * `opener_frame`: 指向发起请求的 `LocalFrame` 对象的指针。
    * `request`: 一个 `FrameLoadRequest` 对象，其中包含了要加载的 URL (例如 `https://new.example.com`)，以及通过 `GetWindowFeaturesFromString` 解析后的 `WebWindowFeatures` 对象。
    * `frame_name`: 新窗口的名称（可选）。
* **逻辑推理：**
    1. 函数会检查 opener 窗口的沙箱标志，看是否允许弹出窗口。
    2. 它会检查 URL 的协议，如果是 `javascript:` URL，会进行安全检查。
    3. 它会根据 `WebWindowFeatures` 中的 `noopener` 属性决定是否克隆 opener 窗口的会话存储。
    4. 它会调用 `opener_frame.GetPage()->GetChromeClient().CreateWindow(...)` 来请求浏览器创建一个新的窗口或标签页。
    5. 如果创建成功，会返回新创建的 `Frame` 对象的指针。
* **输出：**
    * 如果创建成功，返回指向新创建的 `LocalFrame` 对象的指针。
    * 如果由于安全原因或浏览器限制无法创建，返回 `nullptr`。

**用户或编程常见的使用错误举例说明**

* **用户错误：** 用户可能会在浏览器的设置中阻止弹出窗口。在这种情况下，即使 JavaScript 代码尝试调用 `window.open()`，`CreateNewWindow` 可能会返回 `nullptr`，导致新窗口无法打开。
* **编程错误：**
    * **在沙箱化的 iframe 中调用 `window.open()` 但未设置 `allow-popups`：**  如果一个 `<iframe>` 标签带有 `sandbox` 属性，并且没有包含 `allow-popups` 关键字，那么该 iframe 内的脚本调用 `window.open()` 将会被阻止。`CreateNewWindow` 会检查这种情况并返回 `nullptr`，并在控制台输出错误消息。
    * **不正确的窗口特性字符串：**  传递给 `window.open()` 的特性字符串格式不正确，例如拼写错误或使用了未知的特性名称，会导致 `GetWindowFeaturesFromString` 无法正确解析，从而可能导致新窗口的显示效果不符合预期。例如，写成 `widht=800` 而不是 `width=800`。
    * **尝试打开本地资源但权限不足：**  如果脚本尝试使用 `window.open()` 加载本地文件（例如 `file:///path/to/local.html`），但浏览器的安全策略不允许，`CreateNewWindow` 会进行检查并阻止该操作。

**用户操作是如何一步步的到达这里，作为调试线索**

以下是一些用户操作触发 `create_window.cc` 代码执行的步骤，以及作为调试线索的思路：

1. **用户点击了一个带有 `target="_blank"` 的链接：**
    * **步骤：** 用户在页面上点击了一个 `<a>` 标签，并且该标签的 `target` 属性设置为 `"_blank"`。
    * **调试线索：**  在浏览器的开发者工具中，查看 "Elements" 面板找到对应的 `<a>` 标签，确认 `target="_blank"` 是否存在。可以设置断点在 Blink 引擎处理点击事件的相关代码处，逐步追踪执行流程，最终会到达处理 `target="_blank"` 逻辑的地方，并调用到 `CreateNewWindow`。

2. **页面中的 JavaScript 代码调用了 `window.open()`：**
    * **步骤：** 页面中的 JavaScript 代码执行了 `window.open(url, target, features)`。
    * **调试线索：**
        * 在开发者工具的 "Sources" 面板中，找到执行 `window.open()` 的 JavaScript 代码行，设置断点。
        * 当代码执行到断点时，可以查看传递给 `window.open()` 的参数（URL、target、features），确认这些参数是否正确。
        * 可以逐步执行代码，观察调用 `window.open()` 后，浏览器的行为。

3. **表单提交时使用了 `target="_blank"`：**
    * **步骤：** 用户提交了一个 HTML 表单，该表单的 `target` 属性设置为 `"_blank"`。
    * **调试线索：**  在开发者工具的 "Network" 面板中，观察表单提交的网络请求。同时，可以设置断点在 Blink 引擎处理表单提交逻辑的代码处，追踪新窗口的创建过程。

**作为调试线索的更细致的步骤：**

1. **确定触发点：**  首先需要明确是哪个用户操作或脚本调用触发了新窗口的创建。这可能是点击链接、JavaScript 调用或者表单提交。

2. **设置断点：**
   * **对于 HTML 触发：**  可以在 Blink 引擎中处理点击事件和 `target` 属性的相关代码处设置断点。搜索 Blink 源码中处理 `HTMLAnchorElement` 或 `target` 属性的模块。
   * **对于 JavaScript 触发：**  可以在 `create_window.cc` 文件的 `CreateNewWindow` 函数入口处设置断点。也可以在 JavaScriptCore 引擎中 `window.open` 的实现处设置断点，观察参数传递。

3. **逐步执行：**  当断点命中时，使用调试器的单步执行功能，逐步跟踪代码的执行流程。观察变量的值，例如 `request` 对象中的 URL 和窗口特性，以及 `opener_frame` 的状态。

4. **检查调用栈：**  查看调用栈，了解 `CreateNewWindow` 是被哪些函数调用的，这有助于理解代码的执行路径。

5. **查看日志和控制台消息：**  `create_window.cc` 中可能会输出一些日志或控制台消息，例如关于安全错误的提示。查看浏览器的开发者工具控制台可以提供有用的信息。

6. **分析 `WebWindowFeatures`：**  重点关注 `GetWindowFeaturesFromString` 函数的执行结果，确保窗口特性字符串被正确解析。如果新窗口的行为不符合预期，很可能是这里解析出了问题。

7. **理解沙箱标志的影响：**  如果新窗口无法打开，检查 opener 窗口的 `sandbox` 属性以及是否设置了 `allow-popups`。

通过以上分析，我们可以深入了解 `blink/renderer/core/page/create_window.cc` 文件的功能、它与 Web 技术的关系，并掌握一些调试技巧，以便在遇到与新窗口创建相关的问题时能够进行有效地排查。

### 提示词
```
这是目录为blink/renderer/core/page/create_window.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2006, 2007, 2008, 2010 Apple Inc. All rights reserved.
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies)
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

#include "third_party/blink/renderer/core/page/create_window.h"

#include "base/check.h"
#include "base/check_op.h"
#include "base/feature_list.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/public/common/dom_storage/session_storage_namespace_id.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/loader/request_context_frame_type.mojom-blink.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/public/web/web_window_features.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/ad_tracker.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/frame_client.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/number_parsing_options.h"
#include "third_party/blink/renderer/platform/wtf/text/string_to_number.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

// Though absl::ascii_isspace() considers \t and \v to be whitespace, Win IE
// doesn't when parsing window features.
static bool IsWindowFeaturesSeparator(UChar c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '=' ||
         c == ',' || c == '\f';
}

WebWindowFeatures GetWindowFeaturesFromString(const String& feature_string,
                                              LocalDOMWindow* dom_window) {
  WebWindowFeatures window_features;

  const bool attribution_reporting_enabled =
      dom_window &&
      (RuntimeEnabledFeatures::AttributionReportingEnabled(dom_window) ||
       RuntimeEnabledFeatures::AttributionReportingCrossAppWebEnabled(
           dom_window));
  const bool explicit_opener_enabled =
      RuntimeEnabledFeatures::RelOpenerBcgDependencyHintEnabled(dom_window);

  // This code follows the HTML spec, specifically
  // https://html.spec.whatwg.org/C/#concept-window-open-features-tokenize
  if (feature_string.empty())
    return window_features;

  bool ui_features_were_disabled = false;
  bool menu_bar = true;
  bool status_bar = true;
  bool tool_bar = true;
  bool scrollbars = true;
  enum class PopupState { kUnknown, kPopup, kWindow };
  PopupState popup_state = PopupState::kUnknown;
  unsigned key_begin, key_end;
  unsigned value_begin, value_end;

  const String buffer = feature_string.LowerASCII();
  const unsigned length = buffer.length();
  for (unsigned i = 0; i < length;) {
    // skip to first non-separator (start of key name), but don't skip
    // past the end of the string
    while (i < length && IsWindowFeaturesSeparator(buffer[i]))
      i++;
    key_begin = i;

    // skip to first separator (end of key name), but don't skip past
    // the end of the string
    while (i < length && !IsWindowFeaturesSeparator(buffer[i]))
      i++;
    key_end = i;

    SECURITY_DCHECK(i <= length);

    // skip separators past the key name, except '=', and don't skip past
    // the end of the string
    while (i < length && buffer[i] != '=') {
      if (buffer[i] == ',' || !IsWindowFeaturesSeparator(buffer[i]))
        break;

      i++;
    }

    if (i < length && IsWindowFeaturesSeparator(buffer[i])) {
      // skip to first non-separator (start of value), but don't skip
      // past a ',' or the end of the string.
      while (i < length && IsWindowFeaturesSeparator(buffer[i])) {
        if (buffer[i] == ',')
          break;

        i++;
      }

      value_begin = i;

      SECURITY_DCHECK(i <= length);

      // skip to first separator (end of value)
      while (i < length && !IsWindowFeaturesSeparator(buffer[i]))
        i++;

      value_end = i;

      SECURITY_DCHECK(i <= length);
    } else {
      // No value given.
      value_begin = i;
      value_end = i;
    }

    if (key_begin == key_end)
      continue;

    StringView key_string(buffer, key_begin, key_end - key_begin);
    StringView value_string(buffer, value_begin, value_end - value_begin);

    // Listing a key with no value is shorthand for key=yes
    int value;
    if (value_string.empty() || value_string == "yes" ||
        value_string == "true") {
      value = 1;
    } else {
      value = CharactersToInt(value_string, WTF::NumberParsingOptions::Loose(),
                              /*ok=*/nullptr);
    }

    if (!ui_features_were_disabled && key_string != "noopener" &&
        (!explicit_opener_enabled || key_string != "opener") &&
        key_string != "noreferrer" &&
        (!attribution_reporting_enabled || key_string != "attributionsrc")) {
      ui_features_were_disabled = true;
      menu_bar = false;
      status_bar = false;
      tool_bar = false;
      scrollbars = false;
    }

    if (key_string == "left" || key_string == "screenx") {
      window_features.x_set = true;
      window_features.x = value;
    } else if (key_string == "top" || key_string == "screeny") {
      window_features.y_set = true;
      window_features.y = value;
    } else if (key_string == "width" || key_string == "innerwidth") {
      window_features.width_set = true;
      window_features.width = value;
    } else if (key_string == "popup") {
      // The 'popup' property explicitly triggers a popup.
      popup_state = value ? PopupState::kPopup : PopupState::kWindow;
    } else if (key_string == "height" || key_string == "innerheight") {
      window_features.height_set = true;
      window_features.height = value;
    } else if (key_string == "menubar") {
      menu_bar = value;
    } else if (key_string == "toolbar" || key_string == "location") {
      tool_bar |= static_cast<bool>(value);
    } else if (key_string == "status") {
      status_bar = value;
    } else if (key_string == "scrollbars") {
      scrollbars = value;
    } else if (key_string == "resizable") {
      window_features.resizable = value;
    } else if (key_string == "noopener") {
      window_features.noopener = value;
    } else if (explicit_opener_enabled && key_string == "opener") {
      window_features.explicit_opener = value;
    } else if (key_string == "noreferrer") {
      window_features.noreferrer = value;
    } else if (key_string == "background") {
      window_features.background = true;
    } else if (key_string == "persistent") {
      window_features.persistent = true;
    } else if (RuntimeEnabledFeatures::PartitionedPopinsEnabled(dom_window) &&
               key_string == "popin") {
      window_features.is_partitioned_popin = true;
    } else if (attribution_reporting_enabled &&
               key_string == "attributionsrc") {
      if (!window_features.attribution_srcs.has_value()) {
        window_features.attribution_srcs.emplace();
      }

      if (!value_string.empty()) {
        // attributionsrc values are URLs, and as such their original case needs
        // to be retained for correctness. Positions in both `feature_string`
        // and `buffer` correspond because ASCII-lowercasing doesn't add,
        // remove, or swap character positions; it only does in-place
        // transformations of capital ASCII characters. See crbug.com/1338698
        // for details.
        DCHECK_EQ(feature_string.length(), buffer.length());
        const StringView original_case_value_string(feature_string, value_begin,
                                                    value_end - value_begin);

        // attributionsrc values are encoded in order to support embedded
        // special characters, such as '='.
        window_features.attribution_srcs->emplace_back(DecodeURLEscapeSequences(
            original_case_value_string.ToString(), DecodeURLMode::kUTF8));
      }
    }
  }

  window_features.is_popup =
      popup_state == PopupState::kPopup || window_features.is_partitioned_popin;
  if (popup_state == PopupState::kUnknown) {
    window_features.is_popup = !tool_bar || !menu_bar || !scrollbars ||
                               !status_bar || !window_features.resizable;
  }

  if (window_features.noreferrer)
    window_features.noopener = true;

  if (window_features.noopener) {
    window_features.explicit_opener = false;
  }

  return window_features;
}

static void MaybeLogWindowOpen(LocalFrame& opener_frame) {
  AdTracker* ad_tracker = opener_frame.GetAdTracker();
  if (!ad_tracker)
    return;

  bool is_ad_frame = opener_frame.IsAdFrame();
  bool is_ad_script_in_stack =
      ad_tracker->IsAdScriptInStack(AdTracker::StackType::kBottomAndTop);

  // Log to UKM.
  ukm::UkmRecorder* ukm_recorder = opener_frame.GetDocument()->UkmRecorder();
  ukm::SourceId source_id = opener_frame.GetDocument()->UkmSourceID();
  if (source_id != ukm::kInvalidSourceId) {
    ukm::builders::AbusiveExperienceHeuristic_WindowOpen(source_id)
        .SetFromAdSubframe(is_ad_frame)
        .SetFromAdScript(is_ad_script_in_stack)
        .Record(ukm_recorder);
  }
}

Frame* CreateNewWindow(LocalFrame& opener_frame,
                       FrameLoadRequest& request,
                       const AtomicString& frame_name) {
  LocalDOMWindow& opener_window = *opener_frame.DomWindow();
  DCHECK(request.GetResourceRequest().RequestorOrigin() ||
         opener_window.Url().IsEmpty());
  DCHECK_EQ(kNavigationPolicyCurrentTab, request.GetNavigationPolicy());

  if (opener_window.document()->PageDismissalEventBeingDispatched() !=
      Document::kNoDismissal) {
    return nullptr;
  }

  request.SetFrameType(mojom::RequestContextFrameType::kAuxiliary);

  const KURL& url = request.GetResourceRequest().Url();
  if (url.ProtocolIsJavaScript()) {
    if (opener_window
            .CheckAndGetJavascriptUrl(request.JavascriptWorld(), url,
                                      nullptr /* element */)
            .empty()) {
      return nullptr;
    }
  }

  if (!opener_window.GetSecurityOrigin()->CanDisplay(url)) {
    opener_window.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kSecurity,
        mojom::blink::ConsoleMessageLevel::kError,
        "Not allowed to load local resource: " + url.ElidedString()));
    return nullptr;
  }

  const WebWindowFeatures& features = request.GetWindowFeatures();
  const auto& picture_in_picture_window_options =
      request.GetPictureInPictureWindowOptions();
  if (picture_in_picture_window_options.has_value()) {
    request.SetNavigationPolicy(kNavigationPolicyPictureInPicture);
  } else {
    request.SetNavigationPolicy(NavigationPolicyForCreateWindow(features));
    probe::WindowOpen(&opener_window, url, frame_name, features,
                      LocalFrame::HasTransientUserActivation(&opener_frame));
  }

  // Sandboxed frames cannot open new auxiliary browsing contexts.
  if (opener_window.IsSandboxed(
          network::mojom::blink::WebSandboxFlags::kPopups)) {
    // FIXME: This message should be moved off the console once a solution to
    // https://bugs.webkit.org/show_bug.cgi?id=103274 exists.
    opener_window.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kSecurity,
        mojom::blink::ConsoleMessageLevel::kError,
        "Blocked opening '" + url.ElidedString() +
            "' in a new window because the request was made in a sandboxed "
            "frame whose 'allow-popups' permission is not set."));
    return nullptr;
  }

  network::mojom::blink::WebSandboxFlags sandbox_flags =
      opener_window.IsSandboxed(network::mojom::blink::WebSandboxFlags::
                                    kPropagatesToAuxiliaryBrowsingContexts)
          ? opener_window.GetSandboxFlags()
          : network::mojom::blink::WebSandboxFlags::kNone;

  SessionStorageNamespaceId new_namespace_id =
      AllocateSessionStorageNamespaceId();

  Page* old_page = opener_frame.GetPage();
  if (!features.noopener) {
    CoreInitializer::GetInstance().CloneSessionStorage(old_page,
                                                       new_namespace_id);
  }

  bool consumed_user_gesture = false;
  Page* page = old_page->GetChromeClient().CreateWindow(
      &opener_frame, request, frame_name, features, sandbox_flags,
      new_namespace_id, consumed_user_gesture);
  if (!page)
    return nullptr;

  if (page == old_page) {
    Frame* frame = &opener_frame.Tree().Top();
    if (!opener_frame.CanNavigate(*frame))
      return nullptr;
    if (!features.noopener)
      frame->SetOpener(&opener_frame);
    return frame;
  }

  DCHECK(page->MainFrame());
  LocalFrame& frame = *To<LocalFrame>(page->MainFrame());

  page->SetWindowFeatures(features);

  frame.View()->SetCanHaveScrollbars(!features.is_popup);

  page->GetChromeClient().Show(frame, opener_frame,
                               request.GetNavigationPolicy(),
                               consumed_user_gesture);
  MaybeLogWindowOpen(opener_frame);
  return &frame;
}

}  // namespace blink
```