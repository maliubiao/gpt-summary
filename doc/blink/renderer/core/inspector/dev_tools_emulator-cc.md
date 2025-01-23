Response:
Let's break down the thought process to analyze the provided C++ code and fulfill the request.

**1. Understanding the Goal:**

The primary goal is to analyze the `DevToolsEmulator.cc` file within the Chromium Blink rendering engine and explain its functionality, focusing on its relationship with web technologies (JavaScript, HTML, CSS) and potential user/programming errors.

**2. Initial Code Scan and Keyword Identification:**

A quick scan reveals several key terms and patterns:

* **`DevToolsEmulator`:** This is the central class, suggesting it's about simulating different devices or environments within the DevTools context.
* **`Set...` methods:**  Numerous methods like `SetTextAutosizingEnabled`, `SetDeviceScaleAdjustment`, `SetViewportEnabled`, `SetTouchEventEmulationEnabled`, etc. These clearly indicate the ability to modify various browser settings.
* **`DeviceEmulationParams`:** This struct likely holds parameters defining the emulated device (screen size, device scale, etc.).
* **`WebViewImpl`:**  The emulator interacts with a `WebViewImpl`, which is a core Blink class responsible for rendering web content.
* **`Page` and `Settings`:**  The code frequently accesses and modifies settings associated with a `Page`, indicating control over the rendering behavior.
* **`gfx::Transform`:** This suggests manipulations of the rendering layers, potentially for scaling or offsetting content.
* **`MemoryCache`:**  Cache eviction is mentioned in relation to device scale changes.
* **`ScriptEnabled`, `CookieEnabled`, `PluginsEnabled`:** These are clearly related to enabling/disabling web features.
* **`TouchEvent`, `PointerType`, `HoverType`:**  Indicates handling of input events and their simulation.
* **`Viewport`:**  Several mentions of viewport-related settings suggest control over how the webpage is displayed on different screen sizes.
* **`MobileEmulation`:** Explicit functions for enabling and disabling mobile emulation.

**3. Grouping Functionality by Category:**

Based on the identified keywords, I can start grouping the functionalities:

* **Device Metrics Emulation:**  Controlling screen size, device pixel ratio, scaling.
* **Viewport Emulation:**  Manipulating the viewport meta tag behavior, offset, and scaling.
* **Input Event Emulation:** Simulating touch events, pointer types, and hover states.
* **Feature Flags/Settings Overrides:**  Enabling/disabling JavaScript, cookies, plugins, text autosizing, dark mode, scrollbar appearance, etc.
* **Mobile Emulation Preset:** A higher-level abstraction that applies a set of settings typically associated with mobile devices.
* **Internal Management:**  Handling global overrides and shutdown procedures.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now, I need to link these functionalities to how they affect the web page:

* **JavaScript:**  `SetScriptEnabled` directly controls whether JavaScript code in the HTML will execute. Device metrics and touch emulation can affect how JavaScript event listeners behave (e.g., `touchstart` vs. `click`).
* **HTML:**  Viewport settings directly influence how the HTML layout is rendered on different screen sizes, especially with the `<meta name="viewport">` tag. The availability of touch events and pointer types influences the types of input events the HTML can receive.
* **CSS:** Device pixel ratio and viewport settings affect how CSS media queries are evaluated and which styles are applied. Mobile emulation often triggers different CSS rules designed for smaller screens. The visibility of scrollbars is also a CSS-related feature.

**5. Developing Examples:**

Concrete examples are crucial for understanding. For each category of functionality, I should think of:

* **How it's configured in DevTools:** (While the code doesn't show the UI, knowing the *purpose* helps in framing the examples).
* **What the corresponding HTML/CSS/JS behavior would be.**

For instance, for device metrics:

* **Input:** Setting a specific width and height in DevTools.
* **Output:** The webpage renders as if on a device with that screen size. CSS media queries based on screen width will be triggered accordingly. JavaScript that checks `window.innerWidth` will return the emulated width.

For touch emulation:

* **Input:** Enabling touch emulation in DevTools.
* **Output:**  The browser starts sending touch events instead of mouse events. JavaScript event listeners for `touchstart`, `touchmove`, etc., will be triggered. CSS `:hover` styles might not be applied in the same way.

**6. Identifying Potential User/Programming Errors:**

This requires thinking about how these features might be misused or cause unexpected behavior:

* **Inconsistent settings:**  Emulating a mobile device with mouse input enabled could lead to confusing scenarios.
* **Forgetting to disable emulation:**  A developer might test in an emulated environment and forget to disable it, leading to incorrect assumptions about the page's behavior in a normal browser.
* **Overriding critical settings:**  Disabling JavaScript or cookies unintentionally during development could mask bugs.
* **Misunderstanding viewport behavior:** Incorrectly setting viewport parameters can lead to layout issues.

**7. Logic and Assumptions (if applicable):**

The code itself contains some logic, such as the `calculateDeviceScaleAdjustment` function. For such cases, I should:

* **Identify the inputs:** `width`, `height`, `deviceScaleFactor`.
* **Identify the output:** The adjusted device scale factor.
* **Explain the logic:** The function adjusts the scale based on screen size to improve font legibility on smaller screens.
* **Give example inputs and outputs:**  Provide concrete values to illustrate the function's behavior.

**8. Structuring the Output:**

Finally, I need to organize the information clearly:

* **Start with a concise summary of the file's purpose.**
* **List the main functionalities in a structured way.**
* **Provide clear explanations and examples for each functionality, emphasizing the connection to web technologies.**
* **Dedicate a section to potential errors.**
* **Clearly present any logical deductions or assumptions with input/output examples.**

**Self-Correction/Refinement:**

During the process, I might realize:

* **I've missed a key functionality:**  Go back and analyze the code for overlooked aspects.
* **An explanation is unclear:**  Rephrase and provide more details or different examples.
* **The connection to web technologies isn't explicit enough:**  Strengthen the links to HTML, CSS, and JavaScript concepts.
* **An example is confusing:**  Simplify or choose a different example.

By following these steps, combining code analysis with an understanding of web technologies and potential pitfalls, I can produce a comprehensive and informative explanation of the `DevToolsEmulator.cc` file.
这个文件 `blink/renderer/core/inspector/dev_tools_emulator.cc` 的主要功能是 **模拟各种设备和浏览器环境供开发者工具使用**。它允许开发者在不实际拥有这些设备的情况下，在桌面浏览器上模拟它们的特性，从而方便进行网页的调试和优化。

以下是其功能的详细列举，并附带与 JavaScript, HTML, CSS 功能相关的举例说明：

**主要功能:**

1. **模拟设备指标 (Device Metrics Emulation):**
   - **功能:** 允许设置模拟设备的屏幕尺寸（宽度和高度）、设备像素比 (deviceScaleFactor)、以及缩放比例 (scale)。这会影响页面的布局和渲染方式，使其看起来像是在目标设备上显示。
   - **与 HTML, CSS 的关系:**  屏幕尺寸和设备像素比直接影响 CSS 媒体查询 (Media Queries) 的匹配结果。例如，如果模拟一个小屏幕设备，那么为小屏幕设备定义的 CSS 样式将会生效。
     - **举例:**  假设 CSS 中有如下媒体查询：
       ```css
       @media (max-width: 768px) {
         body {
           font-size: 14px;
         }
       }
       ```
       当 DevTools Emulator 设置的宽度小于等于 768px 时，上述 CSS 规则将会应用。
   - **与 JavaScript 的关系:** JavaScript 可以通过 `window.innerWidth` 和 `window.innerHeight` 获取当前的视口尺寸，而这些值会被设备指标模拟影响。`window.devicePixelRatio` 也会反映模拟的设备像素比。
     - **举例:**  如果 JavaScript 代码中有如下逻辑：
       ```javascript
       if (window.innerWidth < 768) {
         console.log("Running on a small screen.");
       }
       ```
       当 DevTools Emulator 设置的宽度小于 768px 时，控制台会输出 "Running on a small screen."。
   - **假设输入与输出:**
     - **假设输入:**  在 DevTools 中设置模拟设备的宽度为 375px，高度为 667px，deviceScaleFactor 为 2。
     - **输出:**  页面渲染时，浏览器会认为其视口宽度是 375px，高度是 667px，设备像素比是 2。CSS 媒体查询和 JavaScript 中获取的尺寸信息都会反映这些模拟值。

2. **模拟视口 (Viewport Emulation):**
   - **功能:**  允许强制设置页面的视口位置 (viewport_offset) 和缩放 (viewport_scale)。这模拟了用户在移动设备上通过捏合手势进行缩放和滚动的情况。
   - **与 HTML 的关系:**  这会影响浏览器对 HTML 中 `<meta name="viewport">` 标签的处理。模拟的视口设置会覆盖或补充 `<meta>` 标签的设置。
   - **与 CSS 的关系:** 影响页面的布局和尺寸计算，特别是当使用基于视口的单位 (vw, vh, vmin, vmax) 时。
   - **与 JavaScript 的关系:**  JavaScript 中与视口相关的属性，如 `window.scrollX`, `window.scrollY`, `visualViewport.width`, `visualViewport.height`, 会受到视口模拟的影响。
   - **假设输入与输出:**
     - **假设输入:** 在 DevTools 中设置视口偏移 x 为 100px，y 为 50px，视口缩放为 1.5。
     - **输出:**  页面的可视区域会向右偏移 100px，向下偏移 50px，并且内容会被放大 1.5 倍。JavaScript 获取的滚动位置和视口尺寸也会相应变化。

3. **移动设备特定模拟 (Mobile Emulation):**
   - **功能:**  激活一系列针对移动设备的默认设置，例如启用覆盖滚动条 (overlay scrollbars)、启用 `orientationchange` 事件、启用移动布局主题、禁用插件等。
   - **与 HTML, CSS 的关系:**  启用移动布局主题可能会影响浏览器默认的样式渲染。覆盖滚动条会改变滚动条的显示方式，使其不占用布局空间。
   - **与 JavaScript 的关系:** 启用 `orientationchange` 事件后，JavaScript 可以监听设备的横竖屏切换事件。
   - **用户或编程常见的使用错误:**
     - **错误:**  在桌面浏览器上开启移动设备模拟后，期望所有移动设备的特性都能完美复现。
     - **说明:**  DevTools Emulator 尽力模拟，但有些底层硬件或操作系统级别的特性可能无法完全模拟。例如，某些设备特定的 API 或性能特征。

4. **触摸事件模拟 (Touch Event Emulation):**
   - **功能:**  允许将鼠标事件转换为触摸事件，模拟触摸设备的交互。可以设置模拟的最大触点数 (max_touch_points)。
   - **与 JavaScript 的关系:**  当启用触摸事件模拟后，页面会接收 `touchstart`, `touchmove`, `touchend`, `touchcancel` 等触摸事件，而不是鼠标事件 (如 `click`, `mousedown`, `mousemove`, `mouseup`)。这对于测试针对触摸设备优化的网页非常重要。
     - **举例:**  一个网站可能使用 JavaScript 监听 `touchstart` 事件来触发某个动画效果，只有在启用触摸事件模拟后，这个效果才能在桌面浏览器上被触发。
   - **用户或编程常见的使用错误:**
     - **错误:** 在触摸事件模拟开启的情况下，仍然使用鼠标事件的监听器进行测试。
     - **说明:**  需要确保 JavaScript 代码同时处理鼠标事件和触摸事件，或者根据环境判断使用哪种事件监听器。可以使用 `('ontouchstart' in window)` 来检测是否支持触摸事件。

5. **禁用 JavaScript 执行 (Disable Script Execution):**
   - **功能:**  允许临时禁用页面的 JavaScript 执行。
   - **与 JavaScript 的关系:**  禁用 JavaScript 后，页面上的所有 JavaScript 代码将不会执行，包括内联脚本和外部脚本文件。
   - **用户或编程常见的使用错误:**
     - **错误:**  禁用 JavaScript 后，期望依赖 JavaScript 实现的功能仍然正常工作。
     - **说明:**  禁用 JavaScript 可以用于测试页面在没有 JavaScript 支持下的可访问性，或者排查由 JavaScript 引起的错误。

6. **隐藏滚动条 (Hide Scrollbars):**
   - **功能:**  允许隐藏页面的滚动条。
   - **与 CSS 的关系:**  这相当于应用了 CSS 属性 `overflow: hidden` 或者使用了自定义的滚动条样式。
   - **用户或编程常见的使用错误:**
     - **错误:**  隐藏滚动条后，内容超出容器时用户无法滚动查看。
     - **说明:**  隐藏滚动条时，需要确保有其他的交互方式让用户访问超出容器的内容，或者使用 CSS 自定义滚动条样式。

7. **禁用 Cookie (Disable Cookies):**
   - **功能:**  允许禁用页面的 Cookie 功能。
   - **与 JavaScript 的关系:**  禁用 Cookie 后，JavaScript 无法通过 `document.cookie` 读取或设置 Cookie。
   - **与 HTML 的关系:**  浏览器发送请求时不会携带 Cookie，服务器也无法通过 HTTP 响应头设置 Cookie。
   - **用户或编程常见的使用错误:**
     - **错误:**  禁用 Cookie 后，期望依赖 Cookie 进行状态管理或用户认证的功能仍然正常工作。
     - **说明:**  禁用 Cookie 可以用于测试网站在没有 Cookie 支持下的行为，或者排查与 Cookie 相关的安全问题。

8. **强制黑暗模式 (Force Dark Mode):**
   - **功能:** 允许强制页面以黑暗模式渲染。
   - **与 CSS 的关系:**  这会触发浏览器应用黑暗模式的样式，如果页面没有提供黑暗模式的样式，浏览器可能会进行反色处理。开发者可以使用 CSS 媒体查询 `@media (prefers-color-scheme: dark)` 来定义黑暗模式下的样式。
     - **举例:**  CSS 中可以定义在黑暗模式下的颜色：
       ```css
       @media (prefers-color-scheme: dark) {
         body {
           background-color: #333;
           color: #eee;
         }
       }
       ```
       当 DevTools Emulator 开启强制黑暗模式后，如果用户的操作系统也设置为黑暗模式或者浏览器支持，上述 CSS 规则将会应用。

9. **设置可用指针类型和悬停类型 (Set Available Pointer Types and Hover Types):**
   - **功能:**  模拟浏览器支持的指针类型（如鼠标、触摸、触控笔）和悬停能力（支持悬停、不支持悬停）。这影响浏览器发送的 Pointer Events 和媒体查询的匹配。
   - **与 JavaScript 的关系:**  影响 JavaScript 中 Pointer Event API 的行为。例如，如果模拟为不支持悬停，那么 `pointerover` 和 `pointerout` 事件可能不会触发。
   - **与 CSS 的关系:**  影响 CSS 媒体查询 `@media (pointer: coarse)`, `@media (pointer: fine)`, `@media (hover: hover)`, `@media (hover: none)` 的匹配结果。

**逻辑推理示例:**

- **假设输入:** DevTools Emulator 设置设备宽度为 600px，设备像素比为 2。CSS 中有媒体查询 `@media (max-width: 700px) and (min-resolution: 192dpi)`。
- **逻辑推理:**
    - 设备宽度 600px 满足 `max-width: 700px` 的条件。
    - 设备像素比为 2，换算成 DPI 为 2 * 96 = 192dpi (假设默认 DPI 为 96)，满足 `min-resolution: 192dpi` 的条件。
- **输出:**  该媒体查询对应的 CSS 规则将会被应用。

**总结:**

`DevToolsEmulator.cc` 是 Chromium 开发者工具中一个核心组件，它通过修改 Blink 渲染引擎的各种设置，模拟不同设备和浏览器的行为，帮助开发者在开发过程中更好地进行调试、测试和优化，确保网页在各种环境下都能正常工作。它与 JavaScript、HTML 和 CSS 的交互非常密切，通过影响浏览器的渲染行为、事件处理和 API 返回值来达到模拟的目的。

### 提示词
```
这是目录为blink/renderer/core/inspector/dev_tools_emulator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/inspector/dev_tools_emulator.h"

#include <algorithm>

#include "third_party/blink/public/mojom/widget/device_emulation_params.mojom-blink.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/ref_counted.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/geometry/size_f.h"

namespace {

static float calculateDeviceScaleAdjustment(int width,
                                            int height,
                                            float deviceScaleFactor) {
  // Chromium on Android uses a device scale adjustment for fonts used in text
  // autosizing for improved legibility. This function computes this adjusted
  // value for text autosizing.
  // For a description of the Android device scale adjustment algorithm, see:
  // chrome/browser/chrome_content_browser_client.cc,
  // GetDeviceScaleAdjustment(...)
  if (!width || !height || !deviceScaleFactor)
    return 1;

  static const float kMinFSM = 1.05f;
  static const int kWidthForMinFSM = 320;
  static const float kMaxFSM = 1.3f;
  static const int kWidthForMaxFSM = 800;

  float minWidth = std::min(width, height) / deviceScaleFactor;
  if (minWidth <= kWidthForMinFSM)
    return kMinFSM;
  if (minWidth >= kWidthForMaxFSM)
    return kMaxFSM;

  // The font scale multiplier varies linearly between kMinFSM and kMaxFSM.
  float ratio = static_cast<float>(minWidth - kWidthForMinFSM) /
                (kWidthForMaxFSM - kWidthForMinFSM);
  return ratio * (kMaxFSM - kMinFSM) + kMinFSM;
}

}  // namespace

namespace blink {

class DevToolsEmulator::ScopedGlobalOverrides
    : public WTF::RefCounted<ScopedGlobalOverrides> {
 public:
  static scoped_refptr<ScopedGlobalOverrides> AssureInstalled() {
    return g_instance_ ? g_instance_
                       : base::AdoptRef(new ScopedGlobalOverrides());
  }

 private:
  friend class WTF::RefCounted<ScopedGlobalOverrides>;

  ScopedGlobalOverrides()
      : overlay_scrollbars_enabled_(
            ScrollbarThemeSettings::OverlayScrollbarsEnabled()),
        orientation_event_enabled_(
            RuntimeEnabledFeatures::OrientationEventEnabled()),
        mobile_layout_theme_enabled_(
            RuntimeEnabledFeatures::MobileLayoutThemeEnabled()) {
    ScrollbarThemeSettings::SetOverlayScrollbarsEnabled(true);
    Page::UsesOverlayScrollbarsChanged();
    RuntimeEnabledFeatures::SetOrientationEventEnabled(true);
    RuntimeEnabledFeatures::SetMobileLayoutThemeEnabled(true);
    Page::PlatformColorsChanged();

    CHECK(!g_instance_);
    g_instance_ = this;
  }

  ~ScopedGlobalOverrides() {
    CHECK(g_instance_);
    g_instance_ = nullptr;

    ScrollbarThemeSettings::SetOverlayScrollbarsEnabled(
        overlay_scrollbars_enabled_);
    Page::UsesOverlayScrollbarsChanged();
    RuntimeEnabledFeatures::SetOrientationEventEnabled(
        orientation_event_enabled_);
    RuntimeEnabledFeatures::SetMobileLayoutThemeEnabled(
        mobile_layout_theme_enabled_);
    Page::PlatformColorsChanged();
  }

  static ScopedGlobalOverrides* g_instance_;

  const bool overlay_scrollbars_enabled_;
  const bool orientation_event_enabled_;
  const bool mobile_layout_theme_enabled_;
};

DevToolsEmulator::ScopedGlobalOverrides*
    DevToolsEmulator::ScopedGlobalOverrides::g_instance_ = nullptr;

DevToolsEmulator::DevToolsEmulator(WebViewImpl* web_view)
    : web_view_(web_view),
      device_metrics_enabled_(false),
      embedder_text_autosizing_enabled_(
          web_view->GetPage()->GetSettings().GetTextAutosizingEnabled()),
      embedder_device_scale_adjustment_(
          web_view->GetPage()->GetSettings().GetDeviceScaleAdjustment()),
      embedder_lcd_text_preference_(
          web_view->GetPage()->GetSettings().GetLCDTextPreference()),
      embedder_viewport_style_(
          web_view->GetPage()->GetSettings().GetViewportStyle()),
      embedder_plugins_enabled_(
          web_view->GetPage()->GetSettings().GetPluginsEnabled()),
      embedder_available_pointer_types_(
          web_view->GetPage()->GetSettings().GetAvailablePointerTypes()),
      embedder_primary_pointer_type_(
          web_view->GetPage()->GetSettings().GetPrimaryPointerType()),
      embedder_available_hover_types_(
          web_view->GetPage()->GetSettings().GetAvailableHoverTypes()),
      embedder_primary_hover_type_(
          web_view->GetPage()->GetSettings().GetPrimaryHoverType()),
      embedder_main_frame_resizes_are_orientation_changes_(
          web_view->GetPage()
              ->GetSettings()
              .GetMainFrameResizesAreOrientationChanges()),
      embedder_min_page_scale_(web_view->DefaultMinimumPageScaleFactor()),
      embedder_max_page_scale_(web_view->DefaultMaximumPageScaleFactor()),
      embedder_shrink_viewport_content_(
          web_view->GetPage()->GetSettings().GetShrinksViewportContentToFit()),
      embedder_viewport_enabled_(
          web_view->GetPage()->GetSettings().GetViewportEnabled()),
      embedder_viewport_meta_enabled_(
          web_view->GetPage()->GetSettings().GetViewportMetaEnabled()),
      touch_event_emulation_enabled_(false),
      double_tap_to_zoom_enabled_(false),
      original_max_touch_points_(0),
      embedder_script_enabled_(
          web_view->GetPage()->GetSettings().GetScriptEnabled()),
      script_execution_disabled_(false),
      embedder_hide_scrollbars_(
          web_view->GetPage()->GetSettings().GetHideScrollbars()),
      scrollbars_hidden_(false),
      embedder_cookie_enabled_(
          web_view->GetPage()->GetSettings().GetCookieEnabled()),
      document_cookie_disabled_(false),
      embedder_force_dark_mode_enabled_(
          web_view->GetPage()->GetSettings().GetForceDarkModeEnabled()),
      auto_dark_overriden_(false) {}

DevToolsEmulator::~DevToolsEmulator() {
  // This class is GarbageCollected, so desturctor may run at any time, hence
  // we need to ensure the RAII handle for global overrides did its business
  // before the destructor runs (i.e. Shutdown() has been called)
  CHECK(!global_overrides_);
  CHECK(is_shutdown_);
}

void DevToolsEmulator::Trace(Visitor* visitor) const {}

void DevToolsEmulator::Shutdown() {
  CHECK(!is_shutdown_);
  is_shutdown_ = true;
  // Restore global overrides, but do not restore any page overrides, since
  // the page may already be in an inconsistent state at this moment.
  global_overrides_.reset();
}

void DevToolsEmulator::SetTextAutosizingEnabled(bool enabled) {
  embedder_text_autosizing_enabled_ = enabled;
  if (!emulate_mobile_enabled()) {
    web_view_->GetPage()->GetSettings().SetTextAutosizingEnabled(enabled);
  }
}

void DevToolsEmulator::SetDeviceScaleAdjustment(float device_scale_adjustment) {
  embedder_device_scale_adjustment_ = device_scale_adjustment;
  if (!emulate_mobile_enabled()) {
    web_view_->GetPage()->GetSettings().SetDeviceScaleAdjustment(
        device_scale_adjustment);
  }
}

void DevToolsEmulator::SetLCDTextPreference(LCDTextPreference preference) {
  if (embedder_lcd_text_preference_ == preference) {
    return;
  }

  embedder_lcd_text_preference_ = preference;
  if (!emulate_mobile_enabled()) {
    web_view_->GetPage()->GetSettings().SetLCDTextPreference(preference);
  }
}

void DevToolsEmulator::SetViewportStyle(mojom::blink::ViewportStyle style) {
  embedder_viewport_style_ = style;
  if (!emulate_mobile_enabled()) {
    web_view_->GetPage()->GetSettings().SetViewportStyle(style);
  }
}

void DevToolsEmulator::SetPluginsEnabled(bool enabled) {
  embedder_plugins_enabled_ = enabled;
  if (!emulate_mobile_enabled()) {
    web_view_->GetPage()->GetSettings().SetPluginsEnabled(enabled);
  }
}

void DevToolsEmulator::SetScriptEnabled(bool enabled) {
  embedder_script_enabled_ = enabled;
  if (!script_execution_disabled_)
    web_view_->GetPage()->GetSettings().SetScriptEnabled(enabled);
}

void DevToolsEmulator::SetHideScrollbars(bool hide) {
  embedder_hide_scrollbars_ = hide;
  if (!scrollbars_hidden_)
    web_view_->GetPage()->GetSettings().SetHideScrollbars(hide);
}

void DevToolsEmulator::SetCookieEnabled(bool enabled) {
  embedder_cookie_enabled_ = enabled;
  if (!document_cookie_disabled_)
    web_view_->GetPage()->GetSettings().SetCookieEnabled(enabled);
}

void DevToolsEmulator::SetDoubleTapToZoomEnabled(bool enabled) {
  double_tap_to_zoom_enabled_ = enabled;
}

bool DevToolsEmulator::DoubleTapToZoomEnabled() const {
  return touch_event_emulation_enabled_ ? true : double_tap_to_zoom_enabled_;
}

void DevToolsEmulator::SetMainFrameResizesAreOrientationChanges(bool value) {
  embedder_main_frame_resizes_are_orientation_changes_ = value;
  if (!emulate_mobile_enabled()) {
    web_view_->GetPage()
        ->GetSettings()
        .SetMainFrameResizesAreOrientationChanges(value);
  }
}

void DevToolsEmulator::SetDefaultPageScaleLimits(float min_scale,
                                                 float max_scale) {
  embedder_min_page_scale_ = min_scale;
  embedder_max_page_scale_ = max_scale;
  if (!emulate_mobile_enabled()) {
    web_view_->GetPage()->SetDefaultPageScaleLimits(min_scale, max_scale);
  }
}

void DevToolsEmulator::SetShrinksViewportContentToFit(
    bool shrink_viewport_content) {
  embedder_shrink_viewport_content_ = shrink_viewport_content;
  if (!emulate_mobile_enabled()) {
    web_view_->GetPage()->GetSettings().SetShrinksViewportContentToFit(
        shrink_viewport_content);
  }
}

void DevToolsEmulator::SetViewportEnabled(bool enabled) {
  embedder_viewport_enabled_ = enabled;
  if (!emulate_mobile_enabled()) {
    web_view_->GetPage()->GetSettings().SetViewportEnabled(enabled);
  }
}

void DevToolsEmulator::SetViewportMetaEnabled(bool enabled) {
  embedder_viewport_meta_enabled_ = enabled;
  if (!emulate_mobile_enabled()) {
    web_view_->GetPage()->GetSettings().SetViewportMetaEnabled(enabled);
  }
}

void DevToolsEmulator::SetAvailablePointerTypes(int types) {
  embedder_available_pointer_types_ = types;
  if (!touch_event_emulation_enabled_)
    web_view_->GetPage()->GetSettings().SetAvailablePointerTypes(types);
}

void DevToolsEmulator::SetPrimaryPointerType(
    mojom::blink::PointerType pointer_type) {
  embedder_primary_pointer_type_ = pointer_type;
  if (!touch_event_emulation_enabled_)
    web_view_->GetPage()->GetSettings().SetPrimaryPointerType(pointer_type);
}

void DevToolsEmulator::SetAvailableHoverTypes(int types) {
  embedder_available_hover_types_ = types;
  if (!touch_event_emulation_enabled_)
    web_view_->GetPage()->GetSettings().SetAvailableHoverTypes(types);
}

void DevToolsEmulator::SetPrimaryHoverType(mojom::blink::HoverType hover_type) {
  embedder_primary_hover_type_ = hover_type;
  if (!touch_event_emulation_enabled_)
    web_view_->GetPage()->GetSettings().SetPrimaryHoverType(hover_type);
}

void DevToolsEmulator::SetOutputDeviceUpdateAbilityType(
    mojom::blink::OutputDeviceUpdateAbilityType type) {
  embedder_output_device_update_ability_type_ = type;
  web_view_->GetPage()->GetSettings().SetOutputDeviceUpdateAbilityType(type);
}

gfx::Transform DevToolsEmulator::EnableDeviceEmulation(
    const DeviceEmulationParams& params) {
  if (device_metrics_enabled_ &&
      emulation_params_.view_size == params.view_size &&
      emulation_params_.screen_type == params.screen_type &&
      emulation_params_.device_scale_factor == params.device_scale_factor &&
      emulation_params_.scale == params.scale &&
      emulation_params_.viewport_offset == params.viewport_offset &&
      emulation_params_.viewport_scale == params.viewport_scale) {
    return ComputeRootLayerTransform();
  }
  if (emulation_params_.device_scale_factor != params.device_scale_factor ||
      !device_metrics_enabled_)
    MemoryCache::Get()->EvictResources();

  emulation_params_ = params;
  device_metrics_enabled_ = true;

  web_view_->GetPage()->GetSettings().SetDeviceScaleAdjustment(
      calculateDeviceScaleAdjustment(params.view_size.width(),
                                     params.view_size.height(),
                                     params.device_scale_factor));

  if (params.screen_type == mojom::blink::EmulatedScreenType::kMobile)
    EnableMobileEmulation();
  else
    DisableMobileEmulation();

  web_view_->SetCompositorDeviceScaleFactorOverride(params.device_scale_factor);

  // TODO(wjmaclean): Tell all local frames in the WebView's frame tree, not
  // just a local main frame.
  if (web_view_->MainFrameImpl()) {
    if (Document* document =
            web_view_->MainFrameImpl()->GetFrame()->GetDocument())
      document->MediaQueryAffectingValueChanged(MediaValueChange::kOther);
  }

  if (params.viewport_offset.x() >= 0)
    return ForceViewport(params.viewport_offset, params.viewport_scale);
  else
    return ResetViewport();
}

void DevToolsEmulator::DisableDeviceEmulation() {
  CHECK(!is_shutdown_);
  if (!device_metrics_enabled_)
    return;

  MemoryCache::Get()->EvictResources();
  device_metrics_enabled_ = false;
  web_view_->GetPage()->GetSettings().SetDeviceScaleAdjustment(
      embedder_device_scale_adjustment_);
  DisableMobileEmulation();
  web_view_->SetCompositorDeviceScaleFactorOverride(0.f);
  web_view_->SetPageScaleFactor(1.f);

  // TODO(wjmaclean): Tell all local frames in the WebView's frame tree, not
  // just a local main frame.
  if (web_view_->MainFrameImpl()) {
    if (Document* document =
            web_view_->MainFrameImpl()->GetFrame()->GetDocument())
      document->MediaQueryAffectingValueChanged(MediaValueChange::kOther);
  }

  gfx::Transform matrix = ResetViewport();
  DCHECK(matrix.IsIdentity());
}

void DevToolsEmulator::EnableMobileEmulation() {
  if (global_overrides_) {
    return;
  }
  CHECK(!is_shutdown_);
  CHECK(!emulate_mobile_enabled());
  global_overrides_ = ScopedGlobalOverrides::AssureInstalled();
  web_view_->GetPage()->GetSettings().SetForceAndroidOverlayScrollbar(true);
  web_view_->GetPage()->GetSettings().SetViewportStyle(
      mojom::blink::ViewportStyle::kMobile);
  web_view_->GetPage()->GetSettings().SetViewportEnabled(true);
  web_view_->GetPage()->GetSettings().SetViewportMetaEnabled(true);
  web_view_->GetPage()->GetSettings().SetShrinksViewportContentToFit(true);
  web_view_->GetPage()->GetSettings().SetTextAutosizingEnabled(true);
  web_view_->GetPage()->GetSettings().SetLCDTextPreference(
      LCDTextPreference::kIgnored);
  web_view_->GetPage()->GetSettings().SetPluginsEnabled(false);
  web_view_->GetPage()->GetSettings().SetMainFrameResizesAreOrientationChanges(
      true);
  web_view_->SetZoomFactorOverride(1);
  web_view_->GetPage()->SetDefaultPageScaleLimits(0.25f, 5);

  // If the viewport is active, refresh the scrollbar layers to reflect the
  // emulated viewport style. If it's not active, either we're in an embedded
  // frame and we don't have visual viewport scrollbars or the scrollbars will
  // initialize as part of their regular lifecycle.
  if (web_view_->GetPage()->GetVisualViewport().IsActiveViewport())
    web_view_->GetPage()->GetVisualViewport().InitializeScrollbars();

  if (web_view_->MainFrameImpl()) {
    web_view_->MainFrameImpl()->GetFrameView()->UpdateLifecycleToLayoutClean(
        DocumentUpdateReason::kInspector);
  }
}

void DevToolsEmulator::DisableMobileEmulation() {
  if (!global_overrides_) {
    return;
  }
  global_overrides_.reset();
  web_view_->GetPage()->GetSettings().SetForceAndroidOverlayScrollbar(false);
  web_view_->GetPage()->GetSettings().SetViewportEnabled(
      embedder_viewport_enabled_);
  web_view_->GetPage()->GetSettings().SetViewportMetaEnabled(
      embedder_viewport_meta_enabled_);
  web_view_->GetPage()->GetVisualViewport().InitializeScrollbars();
  web_view_->GetSettings()->SetShrinksViewportContentToFit(
      embedder_shrink_viewport_content_);
  web_view_->GetPage()->GetSettings().SetTextAutosizingEnabled(
      embedder_text_autosizing_enabled_);
  web_view_->GetPage()->GetSettings().SetLCDTextPreference(
      embedder_lcd_text_preference_);
  web_view_->GetPage()->GetSettings().SetViewportStyle(
      embedder_viewport_style_);
  web_view_->GetPage()->GetSettings().SetPluginsEnabled(
      embedder_plugins_enabled_);
  web_view_->GetPage()->GetSettings().SetMainFrameResizesAreOrientationChanges(
      embedder_main_frame_resizes_are_orientation_changes_);
  web_view_->SetZoomFactorOverride(0);
  web_view_->GetPage()->SetDefaultPageScaleLimits(embedder_min_page_scale_,
                                                  embedder_max_page_scale_);
  // MainFrameImpl() could be null during cleanup or remote <-> local swap.
  if (web_view_->MainFrameImpl()) {
    web_view_->MainFrameImpl()->GetFrameView()->UpdateLifecycleToLayoutClean(
        DocumentUpdateReason::kInspector);
  }
}

gfx::Transform DevToolsEmulator::ForceViewport(const gfx::PointF& position,
                                               float scale) {
  if (!viewport_override_)
    viewport_override_ = ViewportOverride();

  viewport_override_->position = position;
  viewport_override_->scale = scale;

  // Move the correct (scaled) content area to show in the top left of the
  // CompositorFrame via the root transform.
  return ComputeRootLayerTransform();
}

gfx::Transform DevToolsEmulator::ResetViewport() {
  viewport_override_ = std::nullopt;
  return ComputeRootLayerTransform();
}

gfx::Transform DevToolsEmulator::OutermostMainFrameScrollOrScaleChanged() {
  // Viewport override has to take current page scale and scroll offset into
  // account. Update the transform if override is active.
  DCHECK(viewport_override_);
  return ComputeRootLayerTransform();
}

void DevToolsEmulator::ApplyViewportOverride(gfx::Transform* transform) {
  if (!viewport_override_)
    return;

  // Transform operations follow in reverse application.
  // Last, scale positioned area according to override.
  transform->Scale(viewport_override_->scale);

  // Translate while taking into account current scroll offset.
  // TODO(lukasza): https://crbug.com/734201: Add OOPIF support.
  gfx::PointF scroll_offset =
      web_view_->MainFrame()->IsWebLocalFrame()
          ? web_view_->MainFrame()->ToWebLocalFrame()->GetScrollOffset()
          : gfx::PointF();
  gfx::PointF visual_offset = web_view_->VisualViewportOffset();
  float scroll_x = scroll_offset.x() + visual_offset.x();
  float scroll_y = scroll_offset.y() + visual_offset.y();
  transform->Translate(-viewport_override_->position.x() + scroll_x,
                       -viewport_override_->position.y() + scroll_y);

  // First, reverse page scale, so we don't have to take it into account for
  // calculation of the translation.
  transform->Scale(1. / web_view_->PageScaleFactor());
}

gfx::Transform DevToolsEmulator::ComputeRootLayerTransform() {
  gfx::Transform transform;
  // Apply device emulation transform first, so that it is affected by the
  // viewport override.
  ApplyViewportOverride(&transform);
  if (device_metrics_enabled_)
    transform.Scale(emulation_params_.scale);
  return transform;
}

float DevToolsEmulator::InputEventsScaleForEmulation() {
  return device_metrics_enabled_ ? emulation_params_.scale : 1.0;
}

void DevToolsEmulator::SetTouchEventEmulationEnabled(bool enabled,
                                                     int max_touch_points) {
  if (!touch_event_emulation_enabled_) {
    original_max_touch_points_ =
        web_view_->GetPage()->GetSettings().GetMaxTouchPoints();
  }
  touch_event_emulation_enabled_ = enabled;
  web_view_->GetPage()
      ->GetSettings()
      .SetForceTouchEventFeatureDetectionForInspector(enabled);
  web_view_->GetPage()->GetSettings().SetMaxTouchPoints(
      enabled ? max_touch_points : original_max_touch_points_);
  web_view_->GetPage()->GetSettings().SetAvailablePointerTypes(
      enabled ? static_cast<int>(mojom::blink::PointerType::kPointerCoarseType)
              : embedder_available_pointer_types_);
  web_view_->GetPage()->GetSettings().SetPrimaryPointerType(
      enabled ? mojom::blink::PointerType::kPointerCoarseType
              : embedder_primary_pointer_type_);
  web_view_->GetPage()->GetSettings().SetAvailableHoverTypes(
      enabled ? static_cast<int>(mojom::blink::HoverType::kHoverNone)
              : embedder_available_hover_types_);
  web_view_->GetPage()->GetSettings().SetPrimaryHoverType(
      enabled ? mojom::blink::HoverType::kHoverNone
              : embedder_primary_hover_type_);
  WebLocalFrameImpl* frame = web_view_->MainFrameImpl();
  if (enabled && frame)
    frame->GetFrame()->GetEventHandler().ClearMouseEventManager();
}

void DevToolsEmulator::SetScriptExecutionDisabled(
    bool script_execution_disabled) {
  script_execution_disabled_ = script_execution_disabled;
  web_view_->GetPage()->GetSettings().SetScriptEnabled(
      script_execution_disabled_ ? false : embedder_script_enabled_);
}

void DevToolsEmulator::SetScrollbarsHidden(bool hidden) {
  if (scrollbars_hidden_ == hidden)
    return;
  scrollbars_hidden_ = hidden;
  web_view_->GetPage()->GetSettings().SetHideScrollbars(
      scrollbars_hidden_ ? true : embedder_hide_scrollbars_);
}

void DevToolsEmulator::SetDocumentCookieDisabled(bool disabled) {
  if (document_cookie_disabled_ == disabled)
    return;
  document_cookie_disabled_ = disabled;
  web_view_->GetPage()->GetSettings().SetCookieEnabled(
      document_cookie_disabled_ ? false : embedder_cookie_enabled_);
}

void DevToolsEmulator::SetAutoDarkModeOverride(bool enabled) {
  if (!auto_dark_overriden_) {
    auto_dark_overriden_ = true;
    embedder_force_dark_mode_enabled_ =
        web_view_->GetPage()->GetSettings().GetForceDarkModeEnabled();
  }
  web_view_->GetPage()->GetSettings().SetForceDarkModeEnabled(enabled);
}

void DevToolsEmulator::ResetAutoDarkModeOverride() {
  if (auto_dark_overriden_) {
    web_view_->GetPage()->GetSettings().SetForceDarkModeEnabled(
        embedder_force_dark_mode_enabled_);
    auto_dark_overriden_ = false;
  }
}

}  // namespace blink
```