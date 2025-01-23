Response:
Let's break down the thought process to analyze the `internal_settings.cc` file.

**1. Understanding the Request:**

The core request is to analyze a specific Chromium Blink engine source file (`internal_settings.cc`) and describe its functionality, connections to web technologies (JavaScript, HTML, CSS), provide examples, potential errors, and how a user might trigger its execution.

**2. Initial Code Scan and Keyword Identification:**

The first step is to read through the code, looking for keywords and structural elements that give clues about its purpose. Key observations:

* **Copyright:** Indicates ownership and potentially related projects.
* **Includes:**  `settings.h`, `page.h`, `exception_state.h`, `supplementable.h`, `locale_to_script_mapping.h`. These headers suggest the file interacts with core Blink functionalities like page settings, error handling, and potentially locale/font handling. The `mojom` namespace hints at inter-process communication (IPC), although the file itself doesn't directly use it much.
* **Namespace `blink`:** Confirms this is a Blink-specific file.
* **Class `InternalSettings`:**  This is the central class, and its methods likely define the file's functionality.
* **`From(Page& page)`:**  A static method to get an instance of `InternalSettings`, suggesting a singleton-like or per-page association. The use of `Supplement` reinforces this idea.
* **Constructor and Destructor:** Standard class lifecycle management.
* **`ResetToConsistentState()`:**  Indicates the class manages configurable settings that can be reset.
* **`setViewportStyle()`, `SetFontFamily()`, `setStandardFontFamily()`, etc.:** A series of `set...` methods suggests this class is primarily for *setting* internal configurations. The variety of settings (viewport, fonts, text autosizing, text tracks, editing behavior, pointer/hover types, display mode, image animation, autoplay, compositing) provides a good overview of the features being controlled.
* **`ExceptionState& exception_state`:**  Many `set...` methods take this argument, indicating they can throw exceptions if invalid input is provided.
* **`GetSettings()`:**  A method likely accessing the core `Settings` object associated with the page.
* **Enums/Constants (e.g., `mojom::blink::ViewportStyle`, `TextTrackKindUserPreference`, `mojom::EditingBehavior`, `PointerType`, `HoverType`, `mojom::DisplayMode`, `mojom::ImageAnimationPolicy`, `AutoplayPolicy::Type`):** These hint at the possible values and the underlying data types used for the settings.

**3. Deducing Functionality:**

Based on the keywords and method names, it's clear that `InternalSettings` is a class responsible for managing various internal settings of a web page within the Blink rendering engine. It provides an interface to modify these settings programmatically.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

The core idea here is to think about *how* these internal settings affect what web developers can achieve with JavaScript, HTML, and CSS.

* **HTML:** Viewport settings directly influence how the HTML content is rendered on different devices. Text track preferences affect how `<track>` elements are handled.
* **CSS:** Font family settings override the default or specified CSS font families. Display mode can affect the styling of web apps. Pointer and hover types impact how CSS media queries related to interaction work.
* **JavaScript:**  While the file itself isn't directly executed by JavaScript, the *effects* of these settings are visible to JavaScript code. For instance, JavaScript could query the computed styles which are influenced by the font settings. The `InternalSettings` class itself is likely exposed to testing frameworks (as its name suggests) which might be controlled via JavaScript-like test scripts.

**5. Providing Examples and Logical Reasoning:**

The examples should illustrate the connection between the `InternalSettings` methods and their effect on web content. The "assumed input/output" approach helps clarify how the `set...` methods modify the underlying `Settings` object.

**6. Identifying User/Programming Errors:**

The `ExceptionState` argument in many methods is a strong indicator of potential errors. Invalid string inputs for settings are the most common type of error.

**7. Tracing User Actions (Debugging):**

This is where we need to consider *how* these internal settings get changed in practice. The filename "testing" strongly suggests that this class is primarily used for *testing* the Blink rendering engine. Therefore, the most common path to this code is through automated tests. Developer tools (DevTools) are another plausible way these settings might be modified, although this file doesn't implement the DevTools interface itself; rather, DevTools would interact with a higher-level API that *uses* `InternalSettings`.

**8. Structuring the Answer:**

Finally, organize the findings into clear sections as requested: Functionality, Relationship to Web Technologies, Examples, User Errors, and Debugging. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file is directly exposed to JavaScript. **Correction:** The name "internal_settings" suggests it's likely an *internal* API not directly accessible from web pages. It's more likely used by testing infrastructure.
* **Considering IPC:** The `mojom` namespace initially might suggest direct IPC interaction. **Correction:** While `mojom` is present, this specific file primarily interacts with the in-process `Settings` object. The `mojom` types are likely used for representing the settings' values.
* **Focusing on the "testing" aspect:** The directory `testing` is a crucial hint. Emphasize that this file is primarily for internal testing and not day-to-day web development.

By following this structured approach, combining code analysis with an understanding of web technologies and the Chromium architecture, we can generate a comprehensive and accurate description of the `internal_settings.cc` file.
好的，让我们来分析一下 `blink/renderer/core/testing/internal_settings.cc` 这个文件。

**文件功能：**

`internal_settings.cc` 文件在 Chromium Blink 渲染引擎中扮演着一个关键的角色，它提供了一种 **程序化的方式来修改和控制网页的各种内部设置**。这些设置通常与渲染、行为、以及一些实验性功能相关。由于它位于 `testing` 目录下，可以推断出它的主要用途是 **为了方便进行功能测试和调试**。它允许测试代码在运行时动态地调整浏览器的内部状态，以便覆盖各种不同的场景和配置，从而更彻底地测试 Blink 引擎的各个方面。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

虽然 `internal_settings.cc` 是一个 C++ 文件，不直接与 JavaScript, HTML, CSS 代码交互，但它所修改的内部设置会 **直接影响** 这些前端技术在浏览器中的行为和渲染结果。

以下是一些具体的例子：

1. **字体设置 (Font Settings):**
   - **功能:**  `setStandardFontFamily`, `setSerifFontFamily`, 等方法允许修改不同类型文本使用的默认字体。
   - **与 CSS 的关系:** CSS 中定义的 `font-family` 属性会受到这些内部设置的影响。例如，如果通过 `setSerifFontFamily` 将衬线字体设置为 "Times New Roman"，那么 HTML 中使用 `serif` 关键字的文本将使用这个字体。
   - **假设输入与输出:**
     - **输入 (C++ 调用):** `internalSettings->setSerifFontFamily(AtomicString("Times New Roman"), "en");`
     - **HTML:** `<p style="font-family: serif;">This is serif text.</p>`
     - **输出 (渲染结果):**  该段落的文字将以 Times New Roman 字体显示。

2. **视口样式 (Viewport Style):**
   - **功能:** `setViewportStyle` 方法可以模拟不同的视口模式，如 "default" (桌面), "mobile", "television"。
   - **与 HTML 的关系:**  这会影响浏览器如何解释和应用 HTML 中的 `<meta name="viewport" ...>` 标签。
   - **假设输入与输出:**
     - **输入 (C++ 调用):** `internalSettings->setViewportStyle("mobile", exceptionState);`
     - **HTML:**  任何网页
     - **输出 (渲染结果):**  浏览器会以移动设备的视口模式渲染网页，例如，可能启用默认的触摸事件处理，并且初始缩放可能不同。

3. **文本轨道首选项 (Text Track Preference):**
   - **功能:** `setTextTrackKindUserPreference` 方法可以模拟用户对字幕、副标题等文本轨道的偏好。
   - **与 HTML 的关系:** 这会影响浏览器如何自动显示或选择 HTML5 `<video>` 或 `<audio>` 元素中的 `<track>` 元素。
   - **假设输入与输出:**
     - **输入 (C++ 调用):** `internalSettings->setTextTrackKindUserPreference("captions", exceptionState);`
     - **HTML:**
       ```html
       <video controls>
         <source src="video.mp4" type="video/mp4">
         <track kind="captions" src="captions_en.vtt" srclang="en" label="English">
         <track kind="subtitles" src="subtitles_fr.vtt" srclang="fr" label="French">
       </video>
       ```
     - **输出 (渲染结果):** 浏览器可能会自动显示英文的字幕轨道。

4. **编辑行为 (Editing Behavior):**
   - **功能:** `setEditingBehavior` 方法可以模拟不同操作系统下的文本编辑行为 (例如，Windows, Mac, Unix)。
   - **与 HTML 的关系:** 这会影响 `contenteditable` 属性元素的行为，例如光标移动、文本选择等。
   - **假设输入与输出:**
     - **输入 (C++ 调用):** `internalSettings->setEditingBehavior("mac", exceptionState);`
     - **HTML:** `<div contenteditable>Edit this text</div>`
     - **输出 (渲染结果):**  当用户编辑该 `div` 元素时，浏览器的行为会更接近 macOS 上的文本编辑体验。

5. **可用指针类型 (Available Pointer Types):**
   - **功能:** `setAvailablePointerTypes` 可以模拟设备支持的指针类型 (coarse: 粗略，如触摸屏；fine: 精细，如鼠标)。
   - **与 CSS 的关系:** 这会影响 CSS 媒体查询 `@media (pointer: coarse)` 和 `@media (pointer: fine)` 的匹配结果。
   - **假设输入与输出:**
     - **输入 (C++ 调用):** `internalSettings->setAvailablePointerTypes("coarse", exceptionState);`
     - **CSS:**
       ```css
       @media (pointer: coarse) {
         body { background-color: lightblue; }
       }
       ```
     - **输出 (渲染结果):**  网页的背景色会变为浅蓝色，因为浏览器认为当前环境主要使用粗略指针（如触摸屏）。

6. **显示模式覆盖 (Display Mode Override):**
   - **功能:** `setDisplayModeOverride` 可以模拟不同的应用显示模式 (browser, standalone, fullscreen 等)。
   - **与 HTML 的关系:** 这会影响 Web App Manifest 中 `display` 属性的效果，以及浏览器窗口的装饰和行为。
   - **假设输入与输出:**
     - **输入 (C++ 调用):** `internalSettings->setDisplayModeOverride("standalone", exceptionState);`
     - **HTML:**  一个包含 Web App Manifest 的网页。
     - **输出 (渲染结果):**  即使在普通的浏览器标签页中打开，网页也可能以类似独立应用程序的模式渲染，没有地址栏等浏览器 UI 元素。

7. **图像动画策略 (Image Animation Policy):**
   - **功能:** `setImageAnimationPolicy` 控制 GIF 等动画图像的播放策略 (allowed, once, none)。
   - **与 HTML 的关系:** 这直接影响 `<img>` 标签中动画图像的播放行为。
   - **假设输入与输出:**
     - **输入 (C++ 调用):** `internalSettings->setImageAnimationPolicy("once", exceptionState);`
     - **HTML:** `<img src="animated.gif">`
     - **输出 (渲染结果):**  `animated.gif` 只会播放一次，然后停止。

**逻辑推理：**

该文件中的大部分方法都遵循类似的逻辑模式：

- **输入:** 接收一个字符串或枚举值，代表要设置的内部属性。
- **验证:**  通常会检查输入值的有效性，如果无效则抛出 `DOMException`。
- **设置:**  调用 `GetSettings()` 获取当前页面的 `Settings` 对象，然后调用其相应的 `Set...` 方法来修改内部状态。
- **通知 (可能):**  有些设置的修改可能会触发通知，例如 `NotifyGenericFontFamilyChange()`，以便让渲染引擎知道需要更新。

**假设输入与输出示例 (以 `setViewportStyle` 为例):**

- **假设输入:**  `style = "mobile"`
- **逻辑:**  `EqualIgnoringASCIICase(style, "mobile")` 返回 true。
- **输出:** `GetSettings().SetViewportStyle(mojom::blink::ViewportStyle::kMobile);`  页面的视口样式被设置为移动模式。

- **假设输入:** `style = "invalid-style"`
- **逻辑:**  所有 `if` 条件都不满足。
- **输出:** `exception_state.ThrowDOMException(...)` 抛出一个语法错误异常。

**用户或编程常见的使用错误：**

1. **传递无效的字符串参数:**  许多 `set...` 方法都期望特定的字符串值。例如，`setViewportStyle` 只能接受 "default", "mobile", 或 "television"。传递其他字符串会导致 `DOMException`。
   - **错误示例:** `internalSettings->setViewportStyle("desktop", exceptionState);`

2. **在错误的生命周期阶段调用:**  `InternalSettings` 对象通常与 `Page` 对象关联。如果在 `Page` 对象被销毁后尝试访问或修改 `InternalSettings`，可能会导致程序崩溃或未定义的行为。

3. **类型不匹配:** 尽管方法参数通常是字符串，但最终会转换为枚举或特定的内部类型。确保传递的字符串能够正确映射到期望的类型。

**用户操作如何一步步到达这里，作为调试线索：**

`internal_settings.cc` 的主要用途是 **内部测试和调试**，普通用户操作不太可能直接触发这里的代码。以下是一些可能的路径，更多的是开发和测试人员的操作：

1. **Blink 引擎的单元测试或集成测试:**
   - **操作:**  开发者编写 C++ 测试代码，使用 Blink 提供的测试框架来模拟各种场景。
   - **步骤:** 测试代码会获取 `InternalSettings` 对象，并调用其 `set...` 方法来配置测试环境。例如，在测试不同视口模式下的渲染行为时，会调用 `setViewportStyle`。

2. **Chromium Content Shell 或其他基于 Blink 的嵌入式环境的测试:**
   - **操作:**  开发者在 Content Shell 或其他嵌入式浏览器环境中运行测试。
   - **步骤:**  这些环境可能会提供一些接口或命令行参数，允许在启动时或运行时修改内部设置，最终会调用到 `InternalSettings` 中的方法。

3. **开发者工具 (DevTools) 中的实验性功能 (可能间接):**
   - **操作:**  开发者使用 Chrome DevTools 中的 "Experiments" 或 "Rendering" 面板来启用或禁用某些实验性功能。
   - **步骤:**  DevTools 的实现可能会调用到 Blink 内部的 API，这些 API 可能会使用 `InternalSettings` 来修改相应的设置。但这通常是间接的，用户操作不会直接调用 `internal_settings.cc` 中的代码。

4. **自动化测试框架 (如 WebDriver 或 Puppeteer) 的底层实现:**
   - **操作:** 自动化测试脚本通过 WebDriver 或 Puppeteer 控制浏览器。
   - **步骤:**  虽然 WebDriver 和 Puppeteer 通常提供更高层次的 API，但其底层实现可能会涉及到修改浏览器的内部状态，某些情况下可能会间接地使用到 `InternalSettings`。

**总结:**

`blink/renderer/core/testing/internal_settings.cc` 是一个用于 **测试和调试 Blink 渲染引擎** 的关键文件。它提供了一组方法，允许程序化地修改影响网页渲染和行为的内部设置。虽然普通用户不会直接接触到这些代码，但它在确保 Blink 引擎的稳定性和正确性方面发挥着重要作用。理解这个文件的功能有助于理解 Blink 引擎的内部工作原理，并为开发和调试 Blink 相关的功能提供线索。

### 提示词
```
这是目录为blink/renderer/core/testing/internal_settings.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 * Copyright (C) 2013 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/testing/internal_settings.h"

#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/supplementable.h"
#include "third_party/blink/renderer/platform/text/locale_to_script_mapping.h"

namespace blink {

using mojom::blink::HoverType;
using mojom::blink::PointerType;

InternalSettings* InternalSettings::From(Page& page) {
  InternalSettings* supplement = Supplement<Page>::From<InternalSettings>(page);
  if (!supplement) {
    supplement = MakeGarbageCollected<InternalSettings>(page);
    ProvideTo(page, supplement);
  }
  return supplement;
}

InternalSettings::InternalSettings(Page& page)
    : InternalSettingsGenerated(page),
      generic_font_family_settings_backup_(
          GetSettings().GetGenericFontFamilySettings()) {}

InternalSettings::~InternalSettings() = default;

void InternalSettings::ResetToConsistentState() {
  InternalSettingsGenerated::ResetToConsistentState();
  GetSettings().GetGenericFontFamilySettings() =
      generic_font_family_settings_backup_;
}

void InternalSettings::setViewportStyle(const String& style,
                                        ExceptionState& exception_state) {
  if (EqualIgnoringASCIICase(style, "default")) {
    GetSettings().SetViewportStyle(mojom::blink::ViewportStyle::kDefault);
  } else if (EqualIgnoringASCIICase(style, "mobile")) {
    GetSettings().SetViewportStyle(mojom::blink::ViewportStyle::kMobile);
  } else if (EqualIgnoringASCIICase(style, "television")) {
    GetSettings().SetViewportStyle(mojom::blink::ViewportStyle::kTelevision);
  } else {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The viewport style type provided ('" + style + "') is invalid.");
  }
}

void InternalSettings::SetFontFamily(
    const AtomicString& family,
    const String& script,
    bool (GenericFontFamilySettings::*update_method)(const AtomicString&,
                                                     UScriptCode)) {
  UScriptCode code = ScriptNameToCode(script);
  if (code == USCRIPT_INVALID_CODE) {
    return;
  }
  if ((GetSettings().GetGenericFontFamilySettings().*update_method)(family,
                                                                    code)) {
    GetSettings().NotifyGenericFontFamilyChange();
  }
}

void InternalSettings::setStandardFontFamily(const AtomicString& family,
                                             const String& script) {
  SetFontFamily(family, script, &GenericFontFamilySettings::UpdateStandard);
}

void InternalSettings::setSerifFontFamily(const AtomicString& family,
                                          const String& script) {
  SetFontFamily(family, script, &GenericFontFamilySettings::UpdateSerif);
}

void InternalSettings::setSansSerifFontFamily(const AtomicString& family,
                                              const String& script) {
  SetFontFamily(family, script, &GenericFontFamilySettings::UpdateSansSerif);
}

void InternalSettings::setFixedFontFamily(const AtomicString& family,
                                          const String& script) {
  SetFontFamily(family, script, &GenericFontFamilySettings::UpdateFixed);
}

void InternalSettings::setCursiveFontFamily(const AtomicString& family,
                                            const String& script) {
  SetFontFamily(family, script, &GenericFontFamilySettings::UpdateCursive);
}

void InternalSettings::setFantasyFontFamily(const AtomicString& family,
                                            const String& script) {
  SetFontFamily(family, script, &GenericFontFamilySettings::UpdateFantasy);
}

void InternalSettings::setMathFontFamily(const AtomicString& family,
                                         const String& script) {
  SetFontFamily(family, script, &GenericFontFamilySettings::UpdateMath);
}

void InternalSettings::setTextAutosizingWindowSizeOverride(int width,
                                                           int height) {
  GetSettings().SetTextAutosizingWindowSizeOverride(gfx::Size(width, height));
}

void InternalSettings::setTextTrackKindUserPreference(
    const String& preference,
    ExceptionState& exception_state) {
  String token = preference.StripWhiteSpace();
  TextTrackKindUserPreference user_preference =
      TextTrackKindUserPreference::kDefault;
  if (token == "default") {
    user_preference = TextTrackKindUserPreference::kDefault;
  } else if (token == "captions") {
    user_preference = TextTrackKindUserPreference::kCaptions;
  } else if (token == "subtitles") {
    user_preference = TextTrackKindUserPreference::kSubtitles;
  } else {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The user preference for text track kind " + preference +
            ")' is invalid.");
    return;
  }

  GetSettings().SetTextTrackKindUserPreference(user_preference);
}

void InternalSettings::setEditingBehavior(const String& editing_behavior,
                                          ExceptionState& exception_state) {
  if (EqualIgnoringASCIICase(editing_behavior, "win")) {
    GetSettings().SetEditingBehaviorType(
        mojom::EditingBehavior::kEditingWindowsBehavior);
  } else if (EqualIgnoringASCIICase(editing_behavior, "mac")) {
    GetSettings().SetEditingBehaviorType(
        mojom::EditingBehavior::kEditingMacBehavior);
  } else if (EqualIgnoringASCIICase(editing_behavior, "unix")) {
    GetSettings().SetEditingBehaviorType(
        mojom::EditingBehavior::kEditingUnixBehavior);
  } else if (EqualIgnoringASCIICase(editing_behavior, "android")) {
    GetSettings().SetEditingBehaviorType(
        mojom::EditingBehavior::kEditingAndroidBehavior);
  } else if (EqualIgnoringASCIICase(editing_behavior, "chromeos")) {
    GetSettings().SetEditingBehaviorType(
        mojom::EditingBehavior::kEditingChromeOSBehavior);
  } else {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "The editing behavior type provided ('" +
                                          editing_behavior + "') is invalid.");
  }
}

void InternalSettings::setAvailablePointerTypes(
    const String& pointers,
    ExceptionState& exception_state) {
  // Allow setting multiple pointer types by passing comma seperated list
  // ("coarse,fine").
  Vector<String> tokens;
  pointers.Split(",", false, tokens);

  int pointer_types = 0;
  for (const String& split_token : tokens) {
    String token = split_token.StripWhiteSpace();

    if (token == "coarse") {
      pointer_types |= static_cast<int>(PointerType::kPointerCoarseType);
    } else if (token == "fine") {
      pointer_types |= static_cast<int>(PointerType::kPointerFineType);
    } else if (token == "none") {
      pointer_types |= static_cast<int>(PointerType::kPointerNone);
    } else {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kSyntaxError,
          "The pointer type token ('" + token + ")' is invalid.");
      return;
    }
  }

  GetSettings().SetAvailablePointerTypes(pointer_types);
}

void InternalSettings::setDisplayModeOverride(const String& display_mode,
                                              ExceptionState& exception_state) {
  String token = display_mode.StripWhiteSpace();
  auto mode = blink::mojom::DisplayMode::kBrowser;
  if (token == "browser") {
    mode = blink::mojom::DisplayMode::kBrowser;
  } else if (token == "minimal-ui") {
    mode = blink::mojom::DisplayMode::kMinimalUi;
  } else if (token == "standalone") {
    mode = blink::mojom::DisplayMode::kStandalone;
  } else if (token == "fullscreen") {
    mode = blink::mojom::DisplayMode::kFullscreen;
  } else if (token == "window-controls-overlay") {
    mode = blink::mojom::DisplayMode::kWindowControlsOverlay;
  } else if (token == "borderless") {
    mode = blink::mojom::DisplayMode::kBorderless;
  } else {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The display-mode token ('" + token + ")' is invalid.");
    return;
  }

  GetSettings().SetDisplayModeOverride(mode);
}

void InternalSettings::setPrimaryPointerType(const String& pointer,
                                             ExceptionState& exception_state) {
  String token = pointer.StripWhiteSpace();
  PointerType type = PointerType::kPointerNone;
  if (token == "coarse") {
    type = PointerType::kPointerCoarseType;
  } else if (token == "fine") {
    type = PointerType::kPointerFineType;
  } else if (token == "none") {
    type = PointerType::kPointerNone;
  } else {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The pointer type token ('" + token + ")' is invalid.");
    return;
  }

  GetSettings().SetPrimaryPointerType(type);
}

void InternalSettings::setAvailableHoverTypes(const String& types,
                                              ExceptionState& exception_state) {
  // Allow setting multiple hover types by passing comma seperated list
  // ("on-demand,none").
  Vector<String> tokens;
  types.Split(",", false, tokens);

  int hover_types = 0;
  for (const String& split_token : tokens) {
    String token = split_token.StripWhiteSpace();
    if (token == "none") {
      hover_types |= static_cast<int>(HoverType::kHoverNone);
    } else if (token == "hover") {
      hover_types |= static_cast<int>(HoverType::kHoverHoverType);
    } else {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kSyntaxError,
          "The hover type token ('" + token + ")' is invalid.");
      return;
    }
  }

  GetSettings().SetAvailableHoverTypes(hover_types);
}

void InternalSettings::setPrimaryHoverType(const String& type,
                                           ExceptionState& exception_state) {
  String token = type.StripWhiteSpace();
  HoverType hover_type = HoverType::kHoverNone;
  if (token == "none") {
    hover_type = HoverType::kHoverNone;
  } else if (token == "hover") {
    hover_type = HoverType::kHoverHoverType;
  } else {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The hover type token ('" + token + ")' is invalid.");
    return;
  }

  GetSettings().SetPrimaryHoverType(hover_type);
}

void InternalSettings::setImageAnimationPolicy(
    const String& policy,
    ExceptionState& exception_state) {
  if (EqualIgnoringASCIICase(policy, "allowed")) {
    GetSettings().SetImageAnimationPolicy(
        mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyAllowed);
  } else if (EqualIgnoringASCIICase(policy, "once")) {
    GetSettings().SetImageAnimationPolicy(
        mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyAnimateOnce);
  } else if (EqualIgnoringASCIICase(policy, "none")) {
    GetSettings().SetImageAnimationPolicy(
        mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyNoAnimation);
  } else {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The image animation policy provided ('" + policy + "') is invalid.");
    return;
  }
}

void InternalSettings::setAutoplayPolicy(const String& policy_str,
                                         ExceptionState& exception_state) {
  AutoplayPolicy::Type policy = AutoplayPolicy::Type::kNoUserGestureRequired;
  if (policy_str == "no-user-gesture-required") {
    policy = AutoplayPolicy::Type::kNoUserGestureRequired;
  } else if (policy_str == "user-gesture-required") {
    policy = AutoplayPolicy::Type::kUserGestureRequired;
  } else if (policy_str == "document-user-activation-required") {
    policy = AutoplayPolicy::Type::kDocumentUserActivationRequired;
  } else {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The autoplay policy ('" + policy_str + ")' is invalid.");
  }

  GetSettings().SetAutoplayPolicy(policy);
}

void InternalSettings::setPreferCompositingToLCDTextEnabled(bool enabled) {
  GetSettings().SetPreferCompositingToLCDTextForTesting(enabled);
}

}  // namespace blink
```