Response:
Let's break down the thought process for analyzing this `WebSettingsImpl.cc` file.

1. **Understanding the Goal:** The request asks for the functionality of the file, its relation to web technologies (JavaScript, HTML, CSS), examples, logical reasoning, potential errors, and debugging steps.

2. **Initial Scan - Identifying Key Elements:**  I started by scanning the code for keywords and structural patterns:
    * **Includes:** `#include` statements indicate dependencies and the general area of functionality. I noticed includes like `<web_string.h>`, `<web_url.h>`, `<settings.h>`, and `<dev_tools_emulator.h>`. This suggests the file deals with web page settings and has some connection to developer tools.
    * **Class Definition:** The `class WebSettingsImpl` declaration is the core.
    * **Constructor:** The constructor `WebSettingsImpl(Settings* settings, DevToolsEmulator* dev_tools_emulator)` reveals that this class *wraps* or *manages* existing `Settings` and `DevToolsEmulator` objects. This is a crucial piece of information.
    * **Member Variables:**  The private member variables (`settings_`, `dev_tools_emulator_`, and various boolean flags) reinforce the idea of managing settings.
    * **Methods:** The numerous `Set...` methods are the most prominent feature. They suggest the primary function is to *set* various browser or rendering settings.

3. **Categorizing Functionality:**  The sheer number of `Set...` methods screams out for categorization. I mentally grouped them based on the setting they control:
    * **Fonts:** `SetStandardFontFamily`, `SetFixedFontFamily`, etc.
    * **Font Sizes:** `SetDefaultFontSize`, `SetMinimumFontSize`.
    * **URLs:** `SetDefaultVideoPosterURL`.
    * **Autoplay:** `SetAutoplayPolicy`.
    * **Accessibility:** `SetAccessibilityFontScaleFactor`, `SetAccessibilityAlwaysShowFocus`, etc.
    * **Device/Viewport:** `SetDeviceScaleAdjustment`, `SetViewportMeta...`.
    * **JavaScript:** `SetJavaScriptEnabled`.
    * **Web Security:** `SetWebSecurityEnabled`.
    * **Image Loading:** `SetLoadsImagesAutomatically`, `SetImagesEnabled`.
    * **Plugins:** `SetPluginsEnabled`.
    * **User Interaction:** `SetSpatialNavigationEnabled`, `SetDoubleTapToZoomEnabled`.
    * **Text Tracks (Subtitles/Captions):**  `SetTextTrack...`.
    * **Storage:** `SetLocalStorageEnabled`.
    * **Geolocation:** `SetAllowGeolocationOnInsecureOrigins`.
    * **WebGL:** `SetWebGL1Enabled`, `SetWebGL2Enabled`.
    * **Rendering/Performance:** `SetRenderVSyncNotificationEnabled`, `SetLazyLoadEnabled`.
    * **Dark Mode/Color Schemes:** `SetForceDarkModeEnabled`, `SetPreferredColorScheme`.
    * **Experimental/Quirks:** Many methods deal with specific "quirks" or browser-specific behaviors.

4. **Relating to Web Technologies (HTML, CSS, JavaScript):** This is where the understanding of what these settings *do* comes in. I went through the categories and considered their impact:
    * **Fonts:** Directly affects how text is rendered based on CSS `font-family` rules.
    * **Font Sizes:** Affects CSS font sizing and accessibility.
    * **URLs:**  Used in HTML (e.g., `<video poster="...">`).
    * **Autoplay:** Controls behavior of HTML5 `<video>` and `<audio>` elements, impacting user experience and potentially JavaScript interactions.
    * **Accessibility:** Directly influences how assistive technologies interpret and present web content, interacting with HTML structure and potentially ARIA attributes, and affecting CSS rendering.
    * **Device/Viewport:**  Critical for responsive web design, influencing how HTML content is laid out and scaled based on the viewport meta tag in HTML.
    * **JavaScript:** Enables/disables JavaScript execution.
    * **Web Security:**  Affects how JavaScript interacts with different origins and resources, preventing cross-site scripting (XSS) attacks.
    * **Image Loading:** Controls how and when `<img>` elements and CSS background images are loaded.
    * **Plugins:**  Impacts the ability to load and run plugins embedded in HTML (e.g., `<embed>`, `<object>`).
    * **User Interaction:**  Controls browser features related to touch, mouse, and keyboard events, which are fundamental to JavaScript interactions.
    * **Text Tracks:**  Styling of subtitles/captions associated with HTML5 media elements, controlled via `<track>` elements or JavaScript APIs.
    * **Storage:**  Controls the browser's ability to use JavaScript APIs like `localStorage`.
    * **Geolocation:**  Permissions for JavaScript to access the user's location.
    * **WebGL:** Enables JavaScript APIs for 3D graphics rendering in `<canvas>` elements.
    * **Rendering/Performance:** Affects how the browser optimizes rendering, potentially impacting the performance of JavaScript animations and interactions.
    * **Dark Mode/Color Schemes:**  Affects how the browser renders elements based on user or system preferences, potentially interacting with CSS media queries.

5. **Logical Reasoning and Examples:**  For each relevant setting, I tried to think of a simple scenario:
    * **Input:** A user interacts with the browser or a website tries to use a specific feature.
    * **Processing:** The browser checks the relevant setting managed by this file.
    * **Output:** The behavior of the browser or website is modified based on the setting. This led to the "Assume a website..." examples.

6. **User/Programming Errors:**  I considered common mistakes related to these settings:
    * Conflicting settings.
    * Misunderstanding the impact of a setting.
    * Not considering accessibility implications.
    * Incorrectly configuring settings in development/testing.

7. **Debugging Steps:** I imagined how a developer might end up looking at this file:
    * A bug related to a specific setting.
    * Wanting to understand how a feature is controlled.
    * Tracing the flow of control when a setting is changed. This led to the step-by-step user actions that might trigger a change.

8. **Structuring the Output:** Finally, I organized the information into clear sections as requested in the prompt: Functionality, Relationship to Web Technologies, Logical Reasoning, Common Errors, and Debugging. I used bullet points and examples to make it easier to read and understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file *implements* the settings directly.
* **Correction:**  The constructor and the delegation to `settings_` and `dev_tools_emulator_` indicate it's more of a *facade* or *interface* for managing existing settings. This is a key distinction.
* **Initial thought:** Focus only on the code present in the snippet.
* **Refinement:** Realized that understanding the *purpose* of the settings requires broader knowledge of web technologies and browser behavior.
* **Initial thought:** Just list the `Set...` methods.
* **Refinement:**  Categorized them for better clarity and to highlight the different areas of functionality.

By following this iterative process of scanning, categorizing, relating to concepts, and generating examples, I could arrive at a comprehensive explanation of the `WebSettingsImpl.cc` file's purpose and its role in the Blink rendering engine.
好的，我们来详细分析 `blink/renderer/core/exported/web_settings_impl.cc` 文件的功能。

**文件功能概览:**

`WebSettingsImpl.cc` 文件是 Chromium Blink 渲染引擎中一个重要的组件，它实现了 `WebSettings` 接口。其主要功能是：

1. **作为 Blink 内部 `Settings` 类和外部（通常是 Chromium 浏览器进程）之间的桥梁:**  它将外部对渲染设置的请求转换为对 Blink 内部 `Settings` 对象的调用。这有助于解耦 Blink 渲染引擎和宿主环境。
2. **暴露各种渲染相关的配置选项:**  它提供了大量的 `Set...` 方法，允许外部代码配置 Blink 引擎的各种行为，例如 JavaScript 是否启用、图片是否自动加载、字体设置、设备特性模拟等等。
3. **部分功能委托给 `DevToolsEmulator`:** 一些与设备模拟和开发者工具相关的设置被委托给了 `DevToolsEmulator` 对象进行处理。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`WebSettingsImpl.cc` 中管理的设置项与 JavaScript、HTML 和 CSS 的功能有着非常密切的关系，因为它直接影响着网页的解析、渲染和行为。

**1. JavaScript:**

* **`SetJavaScriptEnabled(bool enabled)`:**  **功能:**  启用或禁用 JavaScript 的执行。
    * **举例说明:**
        * **HTML:** `<script>alert('Hello');</script>`
        * **假设输入:**  在浏览器地址栏输入一个包含上述 JavaScript 的 HTML 文件的 URL。
        * **输出:**
            * `enabled = true`: 浏览器会执行 JavaScript 代码，弹出一个包含 "Hello" 的警告框。
            * `enabled = false`: 浏览器会忽略 JavaScript 代码，不会弹出警告框。
* **`SetJavaScriptCanAccessClipboard(bool enabled)`:** **功能:** 控制 JavaScript 是否可以访问剪贴板。
    * **举例说明:**
        * **JavaScript:** `navigator.clipboard.writeText("Text to copy");`
        * **假设输入:** 用户点击一个按钮，该按钮触发上述 JavaScript 代码。
        * **输出:**
            * `enabled = true`: JavaScript 代码成功将 "Text to copy" 写入剪贴板。
            * `enabled = false`:  JavaScript 代码尝试访问剪贴板会失败，可能抛出异常或无响应。
* **`SetAllowScriptsToCloseWindows(bool allow)`:** **功能:** 允许或禁止 JavaScript 代码关闭窗口。
    * **举例说明:**
        * **JavaScript:** `window.close();`
        * **假设输入:** 用户点击一个链接或按钮，该操作触发上述 JavaScript 代码。
        * **输出:**
            * `allow = true`: 浏览器窗口可能会被关闭（取决于浏览器的其他安全策略）。
            * `allow = false`: 浏览器会阻止 JavaScript 代码关闭窗口。

**2. HTML:**

* **`SetLoadsImagesAutomatically(bool loads_images_automatically)`:** **功能:** 控制是否自动加载 HTML 中的图片。
    * **举例说明:**
        * **HTML:** `<img src="image.png">`
        * **假设输入:** 在浏览器地址栏输入一个包含上述 HTML 代码的文件的 URL。
        * **输出:**
            * `loads_images_automatically = true`:  浏览器会自动下载并显示 `image.png`。
            * `loads_images_automatically = false`: 浏览器不会自动下载图片，可能会显示一个占位符，用户可能需要手动点击加载。
* **`SetDefaultVideoPosterURL(const WebString& url)`:** **功能:** 设置 HTML `<video>` 元素的默认海报图像 URL。
    * **举例说明:**
        * **HTML:** `<video controls></video>` (没有指定 `poster` 属性)
        * **假设输入:** 在浏览器地址栏输入一个包含上述 HTML 代码的文件的 URL。
        * **输出:**  如果 `SetDefaultVideoPosterURL` 设置了一个 URL，则该 URL 指向的图片会作为视频的默认海报显示。
* **与 viewport meta 标签相关的设置 (例如 `SetViewportMetaMergeContentQuirk`, `SetViewportMetaNonUserScalableQuirk` 等):** **功能:**  影响浏览器如何解析和应用 HTML 中 `<meta name="viewport" ...>` 标签的设置。这些设置可以用来处理不同网站或浏览器版本的兼容性问题。
    * **举例说明:**
        * **HTML:** `<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">`
        * **假设输入:**  浏览器加载一个包含上述 viewport meta 标签的网页。
        * **输出:** 这些设置会影响浏览器是否允许用户缩放页面 (`user-scalable=no`)，以及如何处理 `width` 和 `initial-scale` 等属性。例如，`SetViewportMetaNonUserScalableQuirk` 可能会影响浏览器是否严格遵守 `user-scalable=no` 指令。

**3. CSS:**

* **与字体相关的设置 (例如 `SetStandardFontFamily`, `SetSerifFontFamily`, `SetDefaultFontSize` 等):** **功能:**  影响浏览器如何渲染文本，可以设置不同类型的默认字体和字号。
    * **举例说明:**
        * **CSS:** `body { font-family: sans-serif; font-size: 16px; }`
        * **假设输入:**  浏览器加载一个包含上述 CSS 规则的网页。
        * **输出:**
            * `SetSansSerifFontFamily` 设置了 "Arial": 网页中的无衬线字体将会以 Arial 显示。
            * `SetDefaultFontSize` 设置为 `18`:  网页中没有明确指定字号的文本将以 18px 显示。
* **`SetTextAutosizingEnabled(bool enabled)`:** **功能:**  控制是否启用文本自动调整大小功能，这可以影响在移动设备上文本的渲染效果。
    * **举例说明:**
        * **CSS:**  没有明确设置 viewport 或字体大小，依赖浏览器自动调整。
        * **假设输入:** 在移动设备上浏览一个没有良好适配的网页。
        * **输出:**
            * `enabled = true`: 浏览器可能会自动调整字体大小，使文本更易读。
            * `enabled = false`: 浏览器可能不会自动调整，导致文本在小屏幕上难以阅读。
* **与 Text Track 相关的设置 (例如 `SetTextTrackTextColor`, `SetTextTrackFontFamily` 等):** **功能:**  影响 HTML5 视频字幕（Text Tracks）的样式。
    * **举例说明:**
        * **HTML:** `<video><track src="subtitles.vtt" kind="subtitles" srclang="en"></video>`
        * **假设输入:** 用户观看包含字幕的视频。
        * **输出:**  `SetTextTrackTextColor` 设置了 "yellow"，字幕的文字颜色将为黄色。

**逻辑推理的假设输入与输出:**

大多数 `WebSettingsImpl` 中的方法都是直接设置内部状态，逻辑推理相对简单。以下是一个例子：

* **方法:** `SetJavaScriptEnabled(bool enabled)`
* **假设输入:**
    * 外部调用 `SetJavaScriptEnabled(true)`，然后加载一个包含 JavaScript 的网页。
    * 外部调用 `SetJavaScriptEnabled(false)`，然后加载同一个包含 JavaScript 的网页。
* **输出:**
    * 输入 `true`: JavaScript 代码会被执行。
    * 输入 `false`: JavaScript 代码不会被执行。

**用户或编程常见的使用错误举例说明:**

* **错误配置导致功能失效:**  例如，错误地将 `SetJavaScriptEnabled(false)` 设置为全局默认值，导致所有网页的 JavaScript 功能失效。用户可能会报告网页交互异常，例如按钮无法点击，动态内容无法加载。
* **忽略设置间的相互影响:**  例如，同时设置了 `SetUseWideViewport(true)` 和某些会导致窄 viewport 的 quirks，可能会导致网页渲染出现意外的结果。开发者可能会困惑于为什么 viewport 没有按照预期工作。
* **在不适当的时机修改设置:**  例如，在网页加载过程中动态修改某些设置，可能会导致渲染过程出现混乱或性能问题。开发者可能会遇到难以复现的渲染 bug。
* **没有考虑到不同平台的差异:** 某些设置可能在不同的操作系统或设备上表现不同。开发者可能会在某个平台上测试通过，但在其他平台上出现问题。
* **滥用 quirks 设置:**  过度依赖特定的 quirk 设置来解决兼容性问题，而不是修复根本原因，可能会在未来版本的浏览器中引发新的问题。

**用户操作如何一步步地到达这里作为调试线索:**

通常，普通用户不会直接操作到 `WebSettingsImpl.cc` 中的代码。这些设置主要由浏览器或者嵌入 Blink 的应用程序来控制。以下是一些可能导致这些设置被修改的场景，可以作为调试线索：

1. **用户更改浏览器设置:**
   * **步骤:** 用户打开浏览器设置 -> 找到与网页内容或辅助功能相关的选项（例如，JavaScript 启用/禁用，字体大小，图片加载设置，辅助功能设置等） -> 修改这些选项。
   * **调试线索:** 如果用户报告某个网页功能异常，可以询问用户是否更改过浏览器的相关设置。

2. **浏览器扩展或插件修改设置:**
   * **步骤:** 用户安装了一个浏览器扩展，该扩展具有修改网页渲染行为的权限 -> 该扩展在后台调用 Blink 提供的 API 来修改设置。
   * **调试线索:**  检查用户是否安装了相关的浏览器扩展，并尝试禁用这些扩展来排除干扰。

3. **开发者工具 (DevTools) 的设备模拟功能:**
   * **步骤:** 开发者打开浏览器的开发者工具 ->  选择设备模拟模式 -> 调整设备类型、屏幕尺寸、用户代理等参数。
   * **调试线索:** 如果在开发者工具的设备模拟模式下出现问题，需要检查模拟器的配置，`DevToolsEmulator` 类在此过程中起作用。

4. **通过命令行参数或配置文件启动浏览器:**
   * **步骤:** 开发者或高级用户使用特定的命令行参数启动 Chromium 浏览器，或者修改浏览器的配置文件，这些参数或配置会影响 Blink 的初始设置。
   * **调试线索:** 检查浏览器启动时的命令行参数或配置文件。

5. **嵌入 Blink 的应用程序的配置:**
   * **步骤:**  如果 Blink 被嵌入到其他应用程序中（例如 Electron 应用），该应用程序的代码会负责配置 `WebSettingsImpl`。
   * **调试线索:**  检查嵌入 Blink 的应用程序的源代码，查找设置 Blink 配置的地方。

**总结:**

`WebSettingsImpl.cc` 是 Blink 渲染引擎配置的核心枢纽，它连接了外部环境和内部渲染机制。理解其功能和与 Web 技术的关系，对于调试网页渲染问题以及理解浏览器的工作原理至关重要。当你遇到与网页显示、JavaScript 行为、CSS 样式等相关的 bug 时，可以考虑检查相关的设置项是否被正确配置，并根据上述调试线索来定位问题。

### 提示词
```
这是目录为blink/renderer/core/exported/web_settings_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/exported/web_settings_impl.h"

#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/inspector/dev_tools_emulator.h"
#include "third_party/blink/renderer/platform/graphics/deferred_image_decoder.h"

namespace blink {

WebSettingsImpl::WebSettingsImpl(Settings* settings,
                                 DevToolsEmulator* dev_tools_emulator)
    : settings_(settings),
      dev_tools_emulator_(dev_tools_emulator),
      render_v_sync_notification_enabled_(false),
      auto_zoom_focused_editable_to_legible_scale_(false),
      support_deprecated_target_density_dpi_(false),
      viewport_meta_non_user_scalable_quirk_(false),
      clobber_user_agent_initial_scale_quirk_(false) {
  DCHECK(settings);
}

void WebSettingsImpl::SetFromStrings(const WebString& name,
                                     const WebString& value) {
  settings_->SetFromStrings(name, value);
}

void WebSettingsImpl::SetStandardFontFamily(const WebString& font,
                                            UScriptCode script) {
  if (settings_->GetGenericFontFamilySettings().UpdateStandard(font, script))
    settings_->NotifyGenericFontFamilyChange();
}

void WebSettingsImpl::SetFixedFontFamily(const WebString& font,
                                         UScriptCode script) {
  if (settings_->GetGenericFontFamilySettings().UpdateFixed(font, script))
    settings_->NotifyGenericFontFamilyChange();
}

void WebSettingsImpl::SetNetworkQuietTimeout(double timeout) {
  settings_->SetNetworkQuietTimeout(timeout);
}

void WebSettingsImpl::SetForceMainWorldInitialization(bool enabled) {
  settings_->SetForceMainWorldInitialization(enabled);
}

void WebSettingsImpl::SetForceZeroLayoutHeight(bool enabled) {
  settings_->SetForceZeroLayoutHeight(enabled);
}

void WebSettingsImpl::SetFullscreenSupported(bool enabled) {
  settings_->SetFullscreenSupported(enabled);
}

void WebSettingsImpl::SetSerifFontFamily(const WebString& font,
                                         UScriptCode script) {
  if (settings_->GetGenericFontFamilySettings().UpdateSerif(font, script))
    settings_->NotifyGenericFontFamilyChange();
}

void WebSettingsImpl::SetSansSerifFontFamily(const WebString& font,
                                             UScriptCode script) {
  if (settings_->GetGenericFontFamilySettings().UpdateSansSerif(font, script))
    settings_->NotifyGenericFontFamilyChange();
}

void WebSettingsImpl::SetCursiveFontFamily(const WebString& font,
                                           UScriptCode script) {
  if (settings_->GetGenericFontFamilySettings().UpdateCursive(font, script))
    settings_->NotifyGenericFontFamilyChange();
}

void WebSettingsImpl::SetFantasyFontFamily(const WebString& font,
                                           UScriptCode script) {
  if (settings_->GetGenericFontFamilySettings().UpdateFantasy(font, script))
    settings_->NotifyGenericFontFamilyChange();
}

void WebSettingsImpl::SetMathFontFamily(const WebString& font,
                                        UScriptCode script) {
  if (settings_->GetGenericFontFamilySettings().UpdateMath(font, script))
    settings_->NotifyGenericFontFamilyChange();
}

void WebSettingsImpl::SetDefaultFontSize(int size) {
  settings_->SetDefaultFontSize(size);
}

void WebSettingsImpl::SetDefaultFixedFontSize(int size) {
  settings_->SetDefaultFixedFontSize(size);
}

void WebSettingsImpl::SetDefaultVideoPosterURL(const WebString& url) {
  settings_->SetDefaultVideoPosterURL(url);
}

void WebSettingsImpl::SetMinimumFontSize(int size) {
  settings_->SetMinimumFontSize(size);
}

void WebSettingsImpl::SetMinimumLogicalFontSize(int size) {
  settings_->SetMinimumLogicalFontSize(size);
}

void WebSettingsImpl::SetAutoplayPolicy(mojom::blink::AutoplayPolicy policy) {
  settings_->SetAutoplayPolicy(
      static_cast<blink::AutoplayPolicy::Type>(policy));
}

void WebSettingsImpl::SetRequireTransientActivationForGetDisplayMedia(
    bool required) {
  settings_->SetRequireTransientActivationForGetDisplayMedia(required);
}

void WebSettingsImpl::SetRequireTransientActivationForShowFileOrDirectoryPicker(
    bool required) {
  settings_->SetRequireTransientActivationForShowFileOrDirectoryPicker(
      required);
}

void WebSettingsImpl::SetAutoZoomFocusedEditableToLegibleScale(
    bool auto_zoom_focused_editable_to_legible_scale) {
  auto_zoom_focused_editable_to_legible_scale_ =
      auto_zoom_focused_editable_to_legible_scale;
}

void WebSettingsImpl::SetTextAutosizingEnabled(bool enabled) {
  dev_tools_emulator_->SetTextAutosizingEnabled(enabled);
}

void WebSettingsImpl::SetAccessibilityFontScaleFactor(float font_scale_factor) {
  settings_->SetAccessibilityFontScaleFactor(font_scale_factor);
}

void WebSettingsImpl::SetAccessibilityTextSizeContrastFactor(
    int text_size_contrast_factor) {
  settings_->SetAccessibilityTextSizeContrastFactor(text_size_contrast_factor);
}

void WebSettingsImpl::SetAccessibilityAlwaysShowFocus(bool always_show_focus) {
  settings_->SetAccessibilityAlwaysShowFocus(always_show_focus);
}

void WebSettingsImpl::SetAccessibilityPasswordValuesEnabled(bool enabled) {
  settings_->SetAccessibilityPasswordValuesEnabled(enabled);
}

void WebSettingsImpl::SetAccessibilityFontWeightAdjustment(int size) {
  settings_->SetAccessibilityFontWeightAdjustment(size);
}

void WebSettingsImpl::SetDeviceScaleAdjustment(float device_scale_adjustment) {
  dev_tools_emulator_->SetDeviceScaleAdjustment(device_scale_adjustment);
}

void WebSettingsImpl::SetDefaultTextEncodingName(const WebString& encoding) {
  settings_->SetDefaultTextEncodingName((String)encoding);
}

void WebSettingsImpl::SetJavaScriptEnabled(bool enabled) {
  dev_tools_emulator_->SetScriptEnabled(enabled);
}

void WebSettingsImpl::SetWebSecurityEnabled(bool enabled) {
  settings_->SetWebSecurityEnabled(enabled);
}

void WebSettingsImpl::SetSupportDeprecatedTargetDensityDPI(
    bool support_deprecated_target_density_dpi) {
  support_deprecated_target_density_dpi_ =
      support_deprecated_target_density_dpi;
}

void WebSettingsImpl::SetViewportMetaMergeContentQuirk(
    bool viewport_meta_merge_content_quirk) {
  settings_->SetViewportMetaMergeContentQuirk(
      viewport_meta_merge_content_quirk);
}

void WebSettingsImpl::SetViewportMetaNonUserScalableQuirk(
    bool viewport_meta_non_user_scalable_quirk) {
  viewport_meta_non_user_scalable_quirk_ =
      viewport_meta_non_user_scalable_quirk;
}

void WebSettingsImpl::SetViewportMetaZeroValuesQuirk(
    bool viewport_meta_zero_values_quirk) {
  settings_->SetViewportMetaZeroValuesQuirk(viewport_meta_zero_values_quirk);
}

void WebSettingsImpl::SetIgnoreMainFrameOverflowHiddenQuirk(
    bool ignore_main_frame_overflow_hidden_quirk) {
  settings_->SetIgnoreMainFrameOverflowHiddenQuirk(
      ignore_main_frame_overflow_hidden_quirk);
}

void WebSettingsImpl::SetReportScreenSizeInPhysicalPixelsQuirk(
    bool report_screen_size_in_physical_pixels_quirk) {
  settings_->SetReportScreenSizeInPhysicalPixelsQuirk(
      report_screen_size_in_physical_pixels_quirk);
}

void WebSettingsImpl::SetRubberBandingOnCompositorThread(
    bool rubber_banding_on_compositor_thread) {}

void WebSettingsImpl::SetClobberUserAgentInitialScaleQuirk(
    bool clobber_user_agent_initial_scale_quirk) {
  clobber_user_agent_initial_scale_quirk_ =
      clobber_user_agent_initial_scale_quirk;
}

void WebSettingsImpl::SetSupportsMultipleWindows(
    bool supports_multiple_windows) {
  settings_->SetSupportsMultipleWindows(supports_multiple_windows);
}

void WebSettingsImpl::SetLoadsImagesAutomatically(
    bool loads_images_automatically) {
  settings_->SetLoadsImagesAutomatically(loads_images_automatically);
}

void WebSettingsImpl::SetImageAnimationPolicy(
    mojom::blink::ImageAnimationPolicy policy) {
  settings_->SetImageAnimationPolicy(policy);
}

void WebSettingsImpl::SetImagesEnabled(bool enabled) {
  settings_->SetImagesEnabled(enabled);
}

void WebSettingsImpl::SetLoadWithOverviewMode(bool enabled) {
  settings_->SetLoadWithOverviewMode(enabled);
}

void WebSettingsImpl::SetShouldReuseGlobalForUnownedMainFrame(bool enabled) {
  settings_->SetShouldReuseGlobalForUnownedMainFrame(enabled);
}

void WebSettingsImpl::SetPluginsEnabled(bool enabled) {
  dev_tools_emulator_->SetPluginsEnabled(enabled);
}

void WebSettingsImpl::SetAvailablePointerTypes(int pointers) {
  dev_tools_emulator_->SetAvailablePointerTypes(pointers);
}

void WebSettingsImpl::SetPrimaryPointerType(mojom::blink::PointerType pointer) {
  dev_tools_emulator_->SetPrimaryPointerType(pointer);
}

void WebSettingsImpl::SetAvailableHoverTypes(int types) {
  dev_tools_emulator_->SetAvailableHoverTypes(types);
}

void WebSettingsImpl::SetPrimaryHoverType(mojom::blink::HoverType type) {
  dev_tools_emulator_->SetPrimaryHoverType(type);
}

void WebSettingsImpl::SetOutputDeviceUpdateAbilityType(
    mojom::blink::OutputDeviceUpdateAbilityType type) {
  dev_tools_emulator_->SetOutputDeviceUpdateAbilityType(type);
}

void WebSettingsImpl::SetPreferHiddenVolumeControls(bool enabled) {
  settings_->SetPreferHiddenVolumeControls(enabled);
}

void WebSettingsImpl::SetShouldProtectAgainstIpcFlooding(bool enabled) {
  settings_->SetShouldProtectAgainstIpcFlooding(enabled);
}

void WebSettingsImpl::SetDOMPasteAllowed(bool enabled) {
  settings_->SetDOMPasteAllowed(enabled);
}

void WebSettingsImpl::SetShrinksViewportContentToFit(
    bool shrink_viewport_content) {
  dev_tools_emulator_->SetShrinksViewportContentToFit(shrink_viewport_content);
}

void WebSettingsImpl::SetSpatialNavigationEnabled(bool enabled) {
  settings_->SetSpatialNavigationEnabled(enabled);
}

void WebSettingsImpl::SetSpellCheckEnabledByDefault(bool enabled) {
  settings_->SetSpellCheckEnabledByDefault(enabled);
}

void WebSettingsImpl::SetTextAreasAreResizable(bool are_resizable) {
  settings_->SetTextAreasAreResizable(are_resizable);
}

void WebSettingsImpl::SetAllowScriptsToCloseWindows(bool allow) {
  settings_->SetAllowScriptsToCloseWindows(allow);
}

void WebSettingsImpl::SetWideViewportQuirkEnabled(
    bool wide_viewport_quirk_enabled) {
  settings_->SetWideViewportQuirkEnabled(wide_viewport_quirk_enabled);
}

void WebSettingsImpl::SetUseWideViewport(bool use_wide_viewport) {
  settings_->SetUseWideViewport(use_wide_viewport);
}

void WebSettingsImpl::SetDontSendKeyEventsToJavascript(
    bool dont_send_key_events_to_javascript) {
  settings_->SetDontSendKeyEventsToJavascript(
      dont_send_key_events_to_javascript);
}

void WebSettingsImpl::SetDoubleTapToZoomEnabled(
    bool double_tap_to_zoom_enabled) {
  dev_tools_emulator_->SetDoubleTapToZoomEnabled(double_tap_to_zoom_enabled);
}

void WebSettingsImpl::SetDownloadableBinaryFontsEnabled(bool enabled) {
  settings_->SetDownloadableBinaryFontsEnabled(enabled);
}

void WebSettingsImpl::SetDynamicSafeAreaInsetsEnabled(bool enabled) {
  settings_->SetDynamicSafeAreaInsetsEnabled(enabled);
}

void WebSettingsImpl::SetJavaScriptCanAccessClipboard(bool enabled) {
  settings_->SetJavaScriptCanAccessClipboard(enabled);
}

void WebSettingsImpl::SetTextTrackKindUserPreference(
    TextTrackKindUserPreference preference) {
  settings_->SetTextTrackKindUserPreference(
      static_cast<blink::TextTrackKindUserPreference>(preference));
}

void WebSettingsImpl::SetTextTrackBackgroundColor(const WebString& color) {
  settings_->SetTextTrackBackgroundColor(color);
}

void WebSettingsImpl::SetTextTrackFontFamily(const WebString& font_family) {
  settings_->SetTextTrackFontFamily(font_family);
}

void WebSettingsImpl::SetTextTrackFontStyle(const WebString& font_style) {
  settings_->SetTextTrackFontStyle(font_style);
}

void WebSettingsImpl::SetTextTrackFontVariant(const WebString& font_variant) {
  settings_->SetTextTrackFontVariant(font_variant);
}

void WebSettingsImpl::SetTextTrackMarginPercentage(float percentage) {
  settings_->SetTextTrackMarginPercentage(percentage);
}

void WebSettingsImpl::SetTextTrackTextColor(const WebString& color) {
  settings_->SetTextTrackTextColor(color);
}

void WebSettingsImpl::SetTextTrackTextShadow(const WebString& shadow) {
  settings_->SetTextTrackTextShadow(shadow);
}

void WebSettingsImpl::SetTextTrackTextSize(const WebString& size) {
  settings_->SetTextTrackTextSize(size);
}

void WebSettingsImpl::SetTextTrackWindowColor(const WebString& color) {
  settings_->SetTextTrackWindowColor(color);
}

void WebSettingsImpl::SetTextTrackWindowRadius(const WebString& radius) {
  settings_->SetTextTrackWindowRadius(radius);
}

void WebSettingsImpl::SetDNSPrefetchingEnabled(bool enabled) {
  settings_->SetDNSPrefetchingEnabled(enabled);
}

void WebSettingsImpl::SetLocalStorageEnabled(bool enabled) {
  settings_->SetLocalStorageEnabled(enabled);
}

void WebSettingsImpl::SetMainFrameClipsContent(bool enabled) {
  settings_->SetMainFrameClipsContent(enabled);
}

void WebSettingsImpl::SetMaxTouchPoints(int max_touch_points) {
  settings_->SetMaxTouchPoints(max_touch_points);
}

void WebSettingsImpl::SetAllowUniversalAccessFromFileURLs(bool allow) {
  settings_->SetAllowUniversalAccessFromFileURLs(allow);
}

void WebSettingsImpl::SetAllowFileAccessFromFileURLs(bool allow) {
  settings_->SetAllowFileAccessFromFileURLs(allow);
}

void WebSettingsImpl::SetAllowGeolocationOnInsecureOrigins(bool allow) {
  settings_->SetAllowGeolocationOnInsecureOrigins(allow);
}

void WebSettingsImpl::SetTouchDragDropEnabled(bool enabled) {
  settings_->SetTouchDragDropEnabled(enabled);
}

void WebSettingsImpl::SetTouchDragEndContextMenu(bool enabled) {
  settings_->SetTouchDragEndContextMenu(enabled);
}

void WebSettingsImpl::SetBarrelButtonForDragEnabled(bool enabled) {
  settings_->SetBarrelButtonForDragEnabled(enabled);
}

void WebSettingsImpl::SetWebGL1Enabled(bool enabled) {
  settings_->SetWebGL1Enabled(enabled);
}

void WebSettingsImpl::SetWebGL2Enabled(bool enabled) {
  settings_->SetWebGL2Enabled(enabled);
}

void WebSettingsImpl::SetRenderVSyncNotificationEnabled(bool enabled) {
  render_v_sync_notification_enabled_ = enabled;
}

void WebSettingsImpl::SetWebGLErrorsToConsoleEnabled(bool enabled) {
  settings_->SetWebGLErrorsToConsoleEnabled(enabled);
}

void WebSettingsImpl::SetAlwaysShowContextMenuOnTouch(bool enabled) {
  settings_->SetAlwaysShowContextMenuOnTouch(enabled);
}

void WebSettingsImpl::SetSmoothScrollForFindEnabled(bool enabled) {
  settings_->SetSmoothScrollForFindEnabled(enabled);
}

void WebSettingsImpl::SetShowContextMenuOnMouseUp(bool enabled) {
  settings_->SetShowContextMenuOnMouseUp(enabled);
}

void WebSettingsImpl::SetEditingBehavior(
    mojom::blink::EditingBehavior behavior) {
  settings_->SetEditingBehaviorType(behavior);
}

void WebSettingsImpl::SetHideScrollbars(bool enabled) {
  dev_tools_emulator_->SetHideScrollbars(enabled);
}

void WebSettingsImpl::SetPrefersDefaultScrollbarStyles(bool enabled) {
  settings_->SetPrefersDefaultScrollbarStyles(enabled);
}

void WebSettingsImpl::SetMockGestureTapHighlightsEnabled(bool enabled) {
  settings_->SetMockGestureTapHighlightsEnabled(enabled);
}

void WebSettingsImpl::SetAccelerated2dCanvasMSAASampleCount(int count) {
  settings_->SetAccelerated2dCanvasMSAASampleCount(count);
}

void WebSettingsImpl::SetAntialiased2dCanvasEnabled(bool enabled) {
  settings_->SetAntialiased2dCanvasEnabled(enabled);
}

void WebSettingsImpl::SetAntialiasedClips2dCanvasEnabled(bool enabled) {
  settings_->SetAntialiasedClips2dCanvasEnabled(enabled);
}

void WebSettingsImpl::SetLCDTextPreference(LCDTextPreference preference) {
  dev_tools_emulator_->SetLCDTextPreference(preference);
}

void WebSettingsImpl::SetHideDownloadUI(bool hide) {
  settings_->SetHideDownloadUI(hide);
}

void WebSettingsImpl::SetPresentationReceiver(bool enabled) {
  settings_->SetPresentationReceiver(enabled);
}

void WebSettingsImpl::SetHighlightAds(bool enabled) {
  settings_->SetHighlightAds(enabled);
}

void WebSettingsImpl::SetHyperlinkAuditingEnabled(bool enabled) {
  settings_->SetHyperlinkAuditingEnabled(enabled);
}

void WebSettingsImpl::SetValidationMessageTimerMagnification(int new_value) {
  settings_->SetValidationMessageTimerMagnification(new_value);
}

void WebSettingsImpl::SetAllowRunningOfInsecureContent(bool enabled) {
  settings_->SetAllowRunningOfInsecureContent(enabled);
}

void WebSettingsImpl::SetDisableReadingFromCanvas(bool enabled) {
  settings_->SetDisableReadingFromCanvas(enabled);
}

void WebSettingsImpl::SetStrictMixedContentChecking(bool enabled) {
  settings_->SetStrictMixedContentChecking(enabled);
}

void WebSettingsImpl::SetStrictMixedContentCheckingForPlugin(bool enabled) {
  settings_->SetStrictMixedContentCheckingForPlugin(enabled);
}

void WebSettingsImpl::SetStrictPowerfulFeatureRestrictions(bool enabled) {
  settings_->SetStrictPowerfulFeatureRestrictions(enabled);
}

void WebSettingsImpl::SetStrictlyBlockBlockableMixedContent(bool enabled) {
  settings_->SetStrictlyBlockBlockableMixedContent(enabled);
}

void WebSettingsImpl::SetPasswordEchoEnabled(bool flag) {
  settings_->SetPasswordEchoEnabled(flag);
}

void WebSettingsImpl::SetPasswordEchoDurationInSeconds(
    double duration_in_seconds) {
  settings_->SetPasswordEchoDurationInSeconds(duration_in_seconds);
}

void WebSettingsImpl::SetShouldPrintBackgrounds(bool enabled) {
  settings_->SetShouldPrintBackgrounds(enabled);
}

void WebSettingsImpl::SetShouldClearDocumentBackground(bool enabled) {
  settings_->SetShouldClearDocumentBackground(enabled);
}

void WebSettingsImpl::SetEnableScrollAnimator(bool enabled) {
  settings_->SetScrollAnimatorEnabled(enabled);
}

void WebSettingsImpl::SetPrefersReducedMotion(bool enabled) {
  settings_->SetPrefersReducedMotion(enabled);
}

void WebSettingsImpl::SetPrefersReducedTransparency(bool enabled) {
  settings_->SetPrefersReducedTransparency(enabled);
}

void WebSettingsImpl::SetInvertedColors(bool enabled) {
  settings_->SetInvertedColors(enabled);
}

bool WebSettingsImpl::ViewportEnabled() const {
  return settings_->GetViewportEnabled();
}

bool WebSettingsImpl::ViewportMetaEnabled() const {
  return settings_->GetViewportMetaEnabled();
}

bool WebSettingsImpl::DoubleTapToZoomEnabled() const {
  return dev_tools_emulator_->DoubleTapToZoomEnabled();
}

bool WebSettingsImpl::MockGestureTapHighlightsEnabled() const {
  return settings_->GetMockGestureTapHighlightsEnabled();
}

bool WebSettingsImpl::ShrinksViewportContentToFit() const {
  return settings_->GetShrinksViewportContentToFit();
}

void WebSettingsImpl::SetPictureInPictureEnabled(bool enabled) {
  settings_->SetPictureInPictureEnabled(enabled);
}

void WebSettingsImpl::SetWebAppScope(const WebString& scope) {
  settings_->SetWebAppScope(scope);
}

void WebSettingsImpl::SetPresentationRequiresUserGesture(bool required) {
  settings_->SetPresentationRequiresUserGesture(required);
}

void WebSettingsImpl::SetEmbeddedMediaExperienceEnabled(bool enabled) {
  settings_->SetEmbeddedMediaExperienceEnabled(enabled);
}

void WebSettingsImpl::SetImmersiveModeEnabled(bool enabled) {
  settings_->SetImmersiveModeEnabled(enabled);
}

void WebSettingsImpl::SetViewportEnabled(bool enabled) {
  dev_tools_emulator_->SetViewportEnabled(enabled);
}

void WebSettingsImpl::SetViewportMetaEnabled(bool enabled) {
  dev_tools_emulator_->SetViewportMetaEnabled(enabled);
}

void WebSettingsImpl::SetSyncXHRInDocumentsEnabled(bool enabled) {
  settings_->SetSyncXHRInDocumentsEnabled(enabled);
}

void WebSettingsImpl::SetTargetBlankImpliesNoOpenerEnabledWillBeRemoved(
    bool enabled) {
  settings_->SetTargetBlankImpliesNoOpenerEnabledWillBeRemoved(enabled);
}

void WebSettingsImpl::SetAllowNonEmptyNavigatorPlugins(bool enabled) {
  settings_->SetAllowNonEmptyNavigatorPlugins(enabled);
}

void WebSettingsImpl::SetCaretBrowsingEnabled(bool enabled) {
  settings_->SetCaretBrowsingEnabled(enabled);
}

void WebSettingsImpl::SetCookieEnabled(bool enabled) {
  dev_tools_emulator_->SetCookieEnabled(enabled);
}

void WebSettingsImpl::SetAllowCustomScrollbarInMainFrame(bool enabled) {
  settings_->SetAllowCustomScrollbarInMainFrame(enabled);
}

void WebSettingsImpl::SetSelectTrailingWhitespaceEnabled(bool enabled) {
  settings_->SetSelectTrailingWhitespaceEnabled(enabled);
}

void WebSettingsImpl::SetSelectionIncludesAltImageText(bool enabled) {
  settings_->SetSelectionIncludesAltImageText(enabled);
}

void WebSettingsImpl::SetSelectionStrategy(SelectionStrategyType strategy) {
  settings_->SetSelectionStrategy(static_cast<SelectionStrategy>(strategy));
}

void WebSettingsImpl::SetSmartInsertDeleteEnabled(bool enabled) {
  settings_->SetSmartInsertDeleteEnabled(enabled);
}

void WebSettingsImpl::SetMainFrameResizesAreOrientationChanges(bool enabled) {
  dev_tools_emulator_->SetMainFrameResizesAreOrientationChanges(enabled);
}

void WebSettingsImpl::SetV8CacheOptions(mojom::blink::V8CacheOptions options) {
  settings_->SetV8CacheOptions(options);
}

void WebSettingsImpl::SetViewportStyle(mojom::blink::ViewportStyle style) {
  dev_tools_emulator_->SetViewportStyle(style);
}

void WebSettingsImpl::SetMediaControlsEnabled(bool enabled) {
  settings_->SetMediaControlsEnabled(enabled);
}

void WebSettingsImpl::SetDoNotUpdateSelectionOnMutatingSelectionRange(
    bool enabled) {
  settings_->SetDoNotUpdateSelectionOnMutatingSelectionRange(enabled);
}

void WebSettingsImpl::SetLowPriorityIframesThreshold(
    WebEffectiveConnectionType effective_connection_type) {
  settings_->SetLowPriorityIframesThreshold(effective_connection_type);
}

void WebSettingsImpl::SetLazyLoadEnabled(bool enabled) {
  settings_->SetLazyLoadEnabled(enabled);
}

void WebSettingsImpl::SetLazyLoadingFrameMarginPxUnknown(int distance_px) {
  settings_->SetLazyLoadingFrameMarginPxUnknown(distance_px);
}

void WebSettingsImpl::SetLazyLoadingFrameMarginPxOffline(int distance_px) {
  settings_->SetLazyLoadingFrameMarginPxOffline(distance_px);
}

void WebSettingsImpl::SetLazyLoadingFrameMarginPxSlow2G(int distance_px) {
  settings_->SetLazyLoadingFrameMarginPxSlow2G(distance_px);
}

void WebSettingsImpl::SetLazyLoadingFrameMarginPx2G(int distance_px) {
  settings_->SetLazyLoadingFrameMarginPx2G(distance_px);
}

void WebSettingsImpl::SetLazyLoadingFrameMarginPx3G(int distance_px) {
  settings_->SetLazyLoadingFrameMarginPx3G(distance_px);
}

void WebSettingsImpl::SetLazyLoadingFrameMarginPx4G(int distance_px) {
  settings_->SetLazyLoadingFrameMarginPx4G(distance_px);
}

void WebSettingsImpl::SetLazyLoadingImageMarginPxUnknown(int distance_px) {
  settings_->SetLazyLoadingImageMarginPxUnknown(distance_px);
}

void WebSettingsImpl::SetLazyLoadingImageMarginPxOffline(int distance_px) {
  settings_->SetLazyLoadingImageMarginPxOffline(distance_px);
}

void WebSettingsImpl::SetLazyLoadingImageMarginPxSlow2G(int distance_px) {
  settings_->SetLazyLoadingImageMarginPxSlow2G(distance_px);
}

void WebSettingsImpl::SetLazyLoadingImageMarginPx2G(int distance_px) {
  settings_->SetLazyLoadingImageMarginPx2G(distance_px);
}

void WebSettingsImpl::SetLazyLoadingImageMarginPx3G(int distance_px) {
  settings_->SetLazyLoadingImageMarginPx3G(distance_px);
}

void WebSettingsImpl::SetLazyLoadingImageMarginPx4G(int distance_px) {
  settings_->SetLazyLoadingImageMarginPx4G(distance_px);
}

void WebSettingsImpl::SetForceDarkModeEnabled(bool enabled) {
  settings_->SetForceDarkModeEnabled(enabled);
}

void WebSettingsImpl::SetInForcedColors(bool in_forced_colors) {
  settings_->SetInForcedColors(in_forced_colors);
}

void WebSettingsImpl::SetIsForcedColorsDisabled(
    bool is_forced_colors_disabled) {
  settings_->SetIsForcedColorsDisabled(is_forced_colors_disabled);
}

void WebSettingsImpl::SetPreferredRootScrollbarColorScheme(
    mojom::blink::PreferredColorScheme color_scheme) {
  settings_->SetPreferredRootScrollbarColorScheme(color_scheme);
}

void WebSettingsImpl::SetPreferredColorScheme(
    mojom::blink::PreferredColorScheme color_scheme) {
  settings_->SetPreferredColorScheme(color_scheme);
}

void WebSettingsImpl::SetPreferredContrast(
    mojom::blink::PreferredContrast contrast) {
  settings_->SetPreferredContrast(contrast);
}

void WebSettingsImpl::SetNavigationControls(
    NavigationControls navigation_controls) {
  settings_->SetNavigationControls(navigation_controls);
}

void WebSettingsImpl::SetAriaModalPrunesAXTree(bool enabled) {
  settings_->SetAriaModalPrunesAXTree(enabled);
}

void WebSettingsImpl::SetSelectionClipboardBufferAvailable(bool available) {
  settings_->SetSelectionClipboardBufferAvailable(available);
}

void WebSettingsImpl::SetAccessibilityIncludeSvgGElement(bool include) {
  settings_->SetAccessibilityIncludeSvgGElement(include);
}

void WebSettingsImpl::SetWebXRImmersiveArAllowed(
    bool webxr_immersive_ar_allowed) {
  settings_->SetWebXRImmersiveArAllowed(webxr_immersive_ar_allowed);
}

void WebSettingsImpl::SetModalContextMenu(bool is_available) {
  settings_->SetModalContextMenu(is_available);
}

void WebSettingsImpl::
    SetRequireTransientActivationAndAuthorizationForSubAppsAPIs(
        bool is_required) {
  settings_->SetRequireTransientActivationAndAuthorizationForSubAppsAPI(
      is_required);
}

}  // namespace blink
```