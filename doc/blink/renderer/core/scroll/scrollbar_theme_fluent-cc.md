Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The primary goal is to explain the functionality of `scrollbar_theme_fluent.cc` within the Chromium Blink rendering engine. This involves identifying its purpose, its relation to web technologies, common usage errors, and how a user might trigger its execution.

2. **Initial Code Scan (Keywords and Structure):**  Quickly scan the code for keywords and structural elements that provide clues:
    * `#include`: Indicates dependencies on other modules. Notice `scrollbar.h`, `ScrollableArea.h`, suggesting scrollbar management. `WebThemeEngine` points to interaction with the operating system's theme.
    * `namespace blink`:  Confirms this is part of the Blink rendering engine.
    * `class ScrollbarThemeFluent`: The core class, suggesting it implements a specific theme for scrollbars (the "Fluent" theme).
    * `GetInstance()`:  A common singleton pattern, meaning there's only one instance of this theme.
    * Member variables (e.g., `scrollbar_thumb_thickness_`, `is_fluent_overlay_scrollbar_enabled_`, `style_`): These hold configuration data for the theme.
    * Methods with names like `ThumbRect`, `ButtonSize`, `PaintTrackBackground`, `PaintButton`: These clearly relate to the visual rendering and layout of scrollbar components.
    * Methods like `UsesOverlayScrollbars`, `UsesFluentScrollbars`: Indicate features of this specific theme.

3. **Identify Core Functionality - Focus on Key Methods:**  Delve into the important methods to understand their roles:
    * **Constructor (`ScrollbarThemeFluent()`):**  Crucial for initialization. Notice it gets theme data from `WebThemeEngine`. It also handles special behavior for web tests. The logic around `is_fluent_overlay_scrollbar_enabled_` is important.
    * **`ScrollbarThickness()`:** Determines the overall thickness of the scrollbar, considering scaling and different width modes.
    * **`ThumbRect()`:** Calculates the position and size of the scrollbar thumb. The logic for positioning based on track dimensions is key.
    * **`ButtonSize()`:** Determines the size of the scrollbar buttons, taking into account available space.
    * **`PaintTrackBackground()` and `PaintButton()`:** Delegate painting to `ScrollbarThemeAura`, potentially with modifications for overlay scrollbars.
    * **`UsesOverlayScrollbars()`, `UsesFluentScrollbars()`, `UsesFluentOverlayScrollbars()`:** Boolean flags indicating feature support.
    * **`InsetTrackRect()` and `InsetButtonRect()`:** Adjust the rectangles for overlay scrollbars to account for hit-testing areas.
    * **`ShrinkMainThreadedMinimalModeThumbRect()`:**  Deals with the visual appearance of the thumb in minimal overlay mode.

4. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** Scrollbars appear on scrollable HTML elements. The presence of overflow (e.g., `overflow: auto`, `overflow-x: scroll`) triggers the display of scrollbars, and thus the involvement of this theme.
    * **CSS:** CSS properties directly influence scrollbar appearance:
        * `scrollbar-width`:  The `Proportion()` method hints at this.
        * `scrollbar-color`, `scrollbar-track-color`, `scrollbar-thumb-color`: The `BuildScrollbarThumbExtraParams` method interacts with these.
        * `-webkit-overflow-scrolling: touch`: Could relate to the overlay scrollbar behavior.
    * **JavaScript:** JavaScript can manipulate the scrolling position and potentially trigger reflows that lead to scrollbar updates. Events like `scroll` directly interact with scrollbars.

5. **Logical Reasoning (Assumptions and Outputs):**
    * **Assumption:** The browser is running on a system with Fluent scrollbars enabled.
    * **Input:** A div with `overflow: auto` and enough content to cause scrolling.
    * **Output:** The `ThumbRect()` method will calculate the position of the scrollbar thumb based on the current scroll position. The `PaintTrackBackground()` and `PaintButton()` methods will be called to draw the scrollbar elements with the Fluent theme.
    * **Assumption:** Web tests are being run.
    * **Input:** The same div with overflow.
    * **Output:** The constructor will initialize button sizes differently, and overlay scrollbar fading will be disabled.

6. **Identify User/Programming Errors:**
    * **User Error:**  Not realizing that system settings can override browser scrollbar appearance.
    * **Programming Error:** Incorrectly calculating or setting CSS properties related to scrollable areas, leading to unexpected scrollbar behavior or rendering. Over-reliance on specific theme behavior without checking for feature support.

7. **Trace User Operations (Debugging Clues):** Think about the steps a user takes to make scrollbars visible:
    * Open a web page.
    * The page has content exceeding the viewport dimensions.
    * CSS styles (either author-defined or browser defaults) trigger the display of scrollbars.
    * The rendering engine (Blink) needs to draw these scrollbars, and it uses the appropriate `ScrollbarTheme` implementation based on the platform and settings. This leads to the execution of code within `scrollbar_theme_fluent.cc`.

8. **Refine and Organize:**  Structure the information logically with clear headings and examples. Ensure the explanation is accessible to someone with some web development knowledge but potentially less familiarity with the inner workings of a browser engine. Use clear and concise language.

9. **Self-Correction/Review:** Reread the explanation. Does it make sense? Are there any ambiguities? Have all the key aspects of the code been addressed? For example, initially, I might not have explicitly mentioned the singleton pattern; on review, I'd add that detail as it's a relevant structural aspect. Similarly, ensuring the connection to `WebThemeEngine` is clearly articulated is important.
这个文件 `scrollbar_theme_fluent.cc` 是 Chromium Blink 渲染引擎中负责实现 **Fluent 设计风格** 的滚动条主题。Fluent Design System 是微软推出的一种用户界面设计语言，其特点包括轻盈、动画效果和深度感。

以下是该文件的主要功能：

**1. 定义 Fluent 滚动条的外观和行为：**

*   **尺寸和间距：**  它确定了滚动条各个部分的尺寸，例如滚动条轨道（track）的宽度、滚动滑块（thumb）的厚度、以及按钮的大小。这些尺寸的获取通常依赖于操作系统或浏览器自身的默认设置，并通过 `WebThemeEngine` 进行查询。
*   **滑块的形状和位置：**  它计算并确定了滚动滑块在滚动条轨道中的位置和形状。`ThumbRect` 方法负责计算滑块的矩形区域。
*   **按钮的形状和位置：**  它计算并确定了滚动条上的按钮（如果有）的大小和位置。`ButtonSize` 方法负责计算按钮的大小。
*   **Overlay 滚动条支持：**  它实现了 Fluent 设计中常见的 Overlay 滚动条样式，即滚动条平时是隐藏的，只在滚动时或鼠标悬停时显示。通过 `is_fluent_overlay_scrollbar_enabled_` 变量来控制是否启用 Overlay 滚动条。
*   **动画效果：**  虽然代码本身没有直接展示动画的实现，但它包含了 `OverlayScrollbarFadeOutDelay` 和 `OverlayScrollbarFadeOutDuration` 等与 Overlay 滚动条淡出效果相关的参数。
*   **最小化模式：**  对于 Overlay 滚动条，它还实现了最小化模式，即滚动条在非活跃状态下会变得更细。`ShrinkMainThreadedMinimalModeThumbRect` 方法负责计算最小化模式下滚动滑块的矩形。

**2. 与 WebThemeEngine 交互：**

*   该文件通过 `WebThemeEngineHelper::GetNativeThemeEngine()` 获取平台原生的主题引擎接口。
*   它使用 `WebThemeEngine` 提供的方法来获取各种滚动条元素的默认尺寸（例如 `GetSize(WebThemeEngine::kPartScrollbarVerticalThumb)`）。
*   它还使用 `WebThemeEngine::IsFluentOverlayScrollbarEnabled()` 来判断当前平台是否启用了 Fluent Overlay 滚动条。
*   `WebThemeEngineHelper::GetNativeThemeEngine()->GetOverlayScrollbarStyle(&style_)` 用于获取更详细的 Overlay 滚动条样式信息。

**3. 处理 Web 测试：**

*   代码中使用了 `WebTestSupport::IsRunningWebTest()` 来判断是否在运行 Web 测试。
*   在 Web 测试环境下，滚动条按钮的长度会被设置为与轨道厚度相同，并且 Overlay 滚动条的淡入淡出效果会被禁用（设置为 0），以便于测试的稳定性和可预测性。

**4. 提供接口供 Blink 渲染引擎使用：**

*   `ScrollbarThemeFluent::GetInstance()` 提供了一个获取该主题单例实例的接口。
*   其他方法，如 `ScrollbarThickness`、`ThumbRect`、`ButtonSize` 等，被 Blink 渲染引擎调用，用于布局和绘制滚动条。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`scrollbar_theme_fluent.cc` 的功能最终体现在用户在浏览器中看到的滚动条样式和行为上，因此与 HTML、CSS 和 JavaScript 都有关系：

*   **HTML:** HTML 元素的内容超出其容器大小时，浏览器会根据 `overflow` 等 CSS 属性决定是否显示滚动条。`scrollbar_theme_fluent.cc` 负责渲染这些滚动条。
    *   **例子：** 一个 `<div>` 元素设置了 `overflow: auto` 并且内容超出其高度，就会触发滚动条的显示，这时 `ScrollbarThemeFluent` 就会参与到滚动条的绘制过程中。

    ```html
    <div style="width: 100px; height: 50px; overflow: auto;">
        This is some long text that will cause a scrollbar to appear.
        This is some long text that will cause a scrollbar to appear.
    </div>
    ```

*   **CSS:** CSS 属性可以影响滚动条的外观，虽然大部分样式控制是由浏览器内核和操作系统主题决定的，但一些新的 CSS 标准允许开发者对滚动条进行更细致的样式控制。
    *   **例子：**  CSS 属性 `scrollbar-width` 可以影响滚动条的宽度，而 `scrollbar-color`、`scrollbar-track-color`、`scrollbar-thumb-color` 可以设置滚动条的颜色。这些 CSS 属性的值最终会影响到 `ScrollbarThemeFluent` 如何绘制滚动条。尽管 `scrollbar_theme_fluent.cc` 自身可能不直接解析 CSS，但它会响应 Blink 传递的相关信息。

    ```css
    /* 可能会影响到 Fluent 滚动条的渲染（具体支持程度取决于浏览器） */
    ::-webkit-scrollbar {
        width: 10px;
    }

    ::-webkit-scrollbar-thumb {
        background-color: rgba(0, 0, 0, 0.5);
    }

    ::-webkit-scrollbar-track {
        background-color: rgba(0, 0, 0, 0.1);
    }
    ```

*   **JavaScript:** JavaScript 可以通过操作 DOM 元素和滚动位置来间接地影响滚动条的显示和行为。例如，通过 JavaScript 设置元素的 `scrollTop` 或 `scrollLeft` 属性会触发滚动事件，并可能导致滚动条的更新和重绘，而 `ScrollbarThemeFluent` 负责执行这些重绘。
    *   **例子：**  JavaScript 代码可以平滑地滚动到页面某个位置，这个滚动过程会导致滚动条滑块的移动，而滑块的绘制是由 `ScrollbarThemeFluent` 控制的。

    ```javascript
    const element = document.getElementById('myDiv');
    element.scrollTo({ top: 100, behavior: 'smooth' });
    ```

**逻辑推理的假设输入与输出：**

**假设输入：**

1. 用户在一个启用了 Fluent Overlay 滚动条的 Windows 系统上浏览网页。
2. 网页中有一个 `<div>` 元素，其内容超出了容器的高度，导致垂直滚动条出现。
3. 用户的鼠标悬停在滚动条区域。

**逻辑推理过程（部分，关注 `scrollbar_theme_fluent.cc` 的作用）：**

1. Blink 渲染引擎检测到需要绘制垂直滚动条。
2. 由于系统启用了 Fluent Overlay 滚动条，`ScrollbarThemeFluent::GetInstance()` 返回 Fluent 主题的单例。
3. `UsesOverlayScrollbars()` 返回 `true`。
4. 当鼠标悬停在滚动条区域时，可能触发滚动条从隐藏状态变为显示状态（具体逻辑可能在其他模块，但 `scrollbar_theme_fluent.cc` 提供了相关的淡入淡出时间参数）。
5. `ThumbRect()` 方法会被调用，根据当前的滚动位置计算出滚动滑块的矩形区域。计算过程会考虑 Fluent 风格的滑块尺寸和在轨道中的位置。
6. `PaintTrackBackground()` 和 `PaintButton()` 方法会被调用，使用 Fluent 风格绘制滚动条的轨道和按钮（如果有）。`InsetTrackRect` 和 `InsetButtonRect` 可能会被用于调整 Overlay 滚动条的绘制区域。
7. 如果滚动条处于非活跃状态，`ShrinkMainThreadedMinimalModeThumbRect()` 可能会被调用来缩小滑块的尺寸，实现最小化模式的效果。

**假设输出：**

*   呈现一个符合 Fluent 设计风格的 Overlay 垂直滚动条。
*   滚动条平时可能处于隐藏状态。
*   当鼠标悬停时，滚动条会平滑地淡入显示。
*   滚动滑块具有 Fluent 风格的圆角和颜色。
*   在非活跃状态下，滚动滑块可能更细。

**用户或编程常见的使用错误：**

1. **用户错误：期望在所有操作系统上看到 Fluent 滚动条。** Fluent 滚动条的实现依赖于操作系统和浏览器是否启用了该特性。用户可能会发现在某些平台上看不到 Fluent 风格的滚动条，因为使用的是平台默认的滚动条样式。

2. **编程错误：过度依赖特定主题的样式细节。**  开发者不应该直接依赖 `ScrollbarThemeFluent` 中具体的像素值或渲染细节，因为这些可能会随着 Chromium 的更新或操作系统主题的变化而改变。应该使用标准的 CSS 属性来控制滚动条的样式，并做好在不同平台和主题下样式表现可能不同的准备。

3. **编程错误：误解 Overlay 滚动条的行为。**  开发者可能会假设 Overlay 滚动条始终可见，或者忽略其在不同状态下的显示逻辑，导致布局或交互上的问题。例如，在计算元素尺寸时，需要考虑 Overlay 滚动条平时不占用空间，但在激活时会覆盖部分内容。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户打开一个网页：** 用户在浏览器中输入网址或点击链接，加载一个包含内容的网页。
2. **网页内容超出容器：** 网页的某些元素，例如 `<div>` 或 `<iframe>`，其内容长度或宽度超过了元素自身的尺寸限制，并且 CSS 样式（如 `overflow: auto` 或 `overflow: scroll`) 允许显示滚动条。
3. **Blink 布局引擎计算滚动条：** Blink 的布局引擎在渲染网页时，会检测到需要显示滚动条的元素。
4. **Blink 请求绘制滚动条：**  布局引擎通知绘制引擎需要绘制滚动条。
5. **选择合适的滚动条主题：**  Blink 会根据当前的平台和设置，选择合适的 `ScrollbarTheme` 实现。如果启用了 Fluent 设计，且当前平台支持，则会选择 `ScrollbarThemeFluent`。
6. **调用 `ScrollbarThemeFluent` 的方法：**  绘制引擎会调用 `ScrollbarThemeFluent` 的各种方法，如 `ThumbRect`、`PaintTrackBackground` 等，来获取滚动条的尺寸、位置和绘制方式。
7. **用户交互（例如滚动）：** 当用户滚动鼠标滚轮、拖动滚动条滑块或点击滚动条按钮时，会触发滚动事件。这些事件会导致 Blink 重新计算滚动条的位置和状态，并再次调用 `ScrollbarThemeFluent` 的方法进行更新和重绘。

**作为调试线索：**

*   如果用户报告滚动条样式不正确或行为异常，开发者可以检查当前操作系统和浏览器是否启用了 Fluent 设计。
*   可以通过 Chromium 的 DevTools 中的 "Rendering" 标签页，查看 "Show composited layer borders" 或 "Show paint rectangles" 等选项，来观察滚动条的绘制过程。
*   如果需要深入调试 `ScrollbarThemeFluent` 的具体逻辑，可以在相关的方法中设置断点，例如 `ThumbRect` 或 `PaintTrackBackground`，来跟踪滚动条的布局和绘制流程。
*   检查 `WebThemeEngine` 的实现，了解它是如何获取平台相关的滚动条信息的，可能有助于理解不同平台下滚动条表现的差异。

Prompt: 
```
这是目录为blink/renderer/core/scroll/scrollbar_theme_fluent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/scroll/scrollbar_theme_fluent.h"

#include "base/numerics/safe_conversions.h"
#include "third_party/blink/public/common/css/forced_colors.h"
#include "third_party/blink/public/platform/web_theme_engine.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scrollbar.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/theme/web_theme_engine_helper.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

ScrollbarThemeFluent& ScrollbarThemeFluent::GetInstance() {
  DEFINE_STATIC_LOCAL(ScrollbarThemeFluent, theme, ());
  return theme;
}

ScrollbarThemeFluent::ScrollbarThemeFluent() {
  WebThemeEngine* theme_engine = WebThemeEngineHelper::GetNativeThemeEngine();
  scrollbar_thumb_thickness_ =
      theme_engine->GetSize(WebThemeEngine::kPartScrollbarVerticalThumb)
          .width();
  scrollbar_track_thickness_ =
      theme_engine->GetSize(WebThemeEngine::kPartScrollbarVerticalTrack)
          .width();
  // Web tests expect buttons to be squares with the length of the track.
  scrollbar_button_length_ =
      WebTestSupport::IsRunningWebTest()
          ? scrollbar_track_thickness_
          : theme_engine->GetSize(WebThemeEngine::kPartScrollbarUpArrow)
                .height();

  is_fluent_overlay_scrollbar_enabled_ =
      theme_engine->IsFluentOverlayScrollbarEnabled();
  if (!is_fluent_overlay_scrollbar_enabled_) {
    return;
  }
  // Hit testable invisible border around the scrollbar's track.
  scrollbar_track_inset_ = theme_engine->GetPaintedScrollbarTrackInset();

  WebThemeEngineHelper::GetNativeThemeEngine()->GetOverlayScrollbarStyle(
      &style_);
  if (WebTestSupport::IsRunningWebTest()) {
    style_.fade_out_delay = base::TimeDelta();
    style_.fade_out_duration = base::TimeDelta();
  }
}

int ScrollbarThemeFluent::ScrollbarThickness(
    float scale_from_dip,
    EScrollbarWidth scrollbar_width) const {
  return base::ClampRound(scrollbar_track_thickness_ *
                          Proportion(scrollbar_width) * scale_from_dip);
}

gfx::Rect ScrollbarThemeFluent::ThumbRect(const Scrollbar& scrollbar) const {
  gfx::Rect thumb_rect = ScrollbarTheme::ThumbRect(scrollbar);
  const int thumb_thickness =
      ThumbThickness(scrollbar.ScaleFromDIP(), scrollbar.CSSScrollbarWidth());
  if (scrollbar.Orientation() == kHorizontalScrollbar) {
    thumb_rect.set_height(thumb_thickness);
  } else {
    thumb_rect.set_width(thumb_thickness);
  }

  const gfx::Rect track_rect = TrackRect(scrollbar);
  const float offset_from_viewport =
      scrollbar.Orientation() == kHorizontalScrollbar
          ? (track_rect.height() - thumb_thickness) / 2.0f
          : (track_rect.width() - thumb_thickness) / 2.0f;

  // Thumb rect position is relative to the inner edge of the scrollbar
  // track. Therefore the thumb is translated to the opposite end (towards
  // viewport border) of the track with the offset deducted.
  if (scrollbar.Orientation() == kHorizontalScrollbar) {
    thumb_rect.Offset(
        0, track_rect.height() - thumb_rect.height() - offset_from_viewport);
  } else {
    thumb_rect.Offset(
        track_rect.width() - thumb_rect.width() - offset_from_viewport, 0);
  }

  return thumb_rect;
}

gfx::Size ScrollbarThemeFluent::ButtonSize(const Scrollbar& scrollbar) const {
  // In cases when scrollbar's frame rect is too small to contain buttons and
  // track, buttons should take all the available space.
  if (scrollbar.Orientation() == kVerticalScrollbar) {
    const int button_width = scrollbar.Width();
    const int desired_button_height = base::ClampRound(
        scrollbar_button_length_ * Proportion(scrollbar.CSSScrollbarWidth()) *
        scrollbar.ScaleFromDIP());
    const int button_height = scrollbar.Height() < 2 * desired_button_height
                                  ? scrollbar.Height() / 2
                                  : desired_button_height;
    return gfx::Size(button_width, button_height);
  } else {
    const int button_height = scrollbar.Height();
    const int desired_button_width = base::ClampRound(
        scrollbar_button_length_ * Proportion(scrollbar.CSSScrollbarWidth()) *
        scrollbar.ScaleFromDIP());
    const int button_width = scrollbar.Width() < 2 * desired_button_width
                                 ? scrollbar.Width() / 2
                                 : desired_button_width;
    return gfx::Size(button_width, button_height);
  }
}

bool ScrollbarThemeFluent::UsesOverlayScrollbars() const {
  return is_fluent_overlay_scrollbar_enabled_;
}

bool ScrollbarThemeFluent::UsesFluentScrollbars() const {
  return true;
}

bool ScrollbarThemeFluent::UsesFluentOverlayScrollbars() const {
  return UsesOverlayScrollbars();
}

base::TimeDelta ScrollbarThemeFluent::OverlayScrollbarFadeOutDelay() const {
  return style_.fade_out_delay;
}

base::TimeDelta ScrollbarThemeFluent::OverlayScrollbarFadeOutDuration() const {
  return style_.fade_out_duration;
}

ScrollbarPart ScrollbarThemeFluent::PartsToInvalidateOnThumbPositionChange(
    const Scrollbar& scrollbar,
    float old_position,
    float new_position) const {
  return ScrollbarPart::kNoPart;
}

int ScrollbarThemeFluent::ThumbThickness(
    const float scale_from_dip,
    const EScrollbarWidth scrollbar_width) const {
  // The difference between track's and thumb's thicknesses should always be
  // even to have equal thumb offsets from both sides so the thumb can remain
  // in the middle of the track. Subtract one pixel if the difference is odd.
  const int thumb_thickness =
      base::ClampRound(scrollbar_thumb_thickness_ *
                       Proportion(scrollbar_width) * scale_from_dip);
  const int scrollbar_thickness =
      ScrollbarThickness(scale_from_dip, scrollbar_width);
  return thumb_thickness - ((scrollbar_thickness - thumb_thickness) % 2);
}

void ScrollbarThemeFluent::PaintTrackBackground(GraphicsContext& context,
                                                const Scrollbar& scrollbar,
                                                const gfx::Rect& rect) {
  if (rect.IsEmpty()) {
    return;
  }
  ScrollbarThemeAura::PaintTrackBackground(
      context, scrollbar,
      UsesOverlayScrollbars() ? InsetTrackRect(scrollbar, rect) : rect);
}

void ScrollbarThemeFluent::PaintButton(GraphicsContext& context,
                                       const Scrollbar& scrollbar,
                                       const gfx::Rect& rect,
                                       ScrollbarPart part) {
  ScrollbarThemeAura::PaintButton(
      context, scrollbar,
      UsesOverlayScrollbars() ? InsetButtonRect(scrollbar, rect, part) : rect,
      part);
}
WebThemeEngine::ScrollbarThumbExtraParams
ScrollbarThemeFluent::BuildScrollbarThumbExtraParams(
    const Scrollbar& scrollbar) const {
  WebThemeEngine::ScrollbarThumbExtraParams scrollbar_thumb;
  if (scrollbar.ScrollbarThumbColor().has_value()) {
    scrollbar_thumb.thumb_color =
        scrollbar.ScrollbarThumbColor().value().toSkColor4f().toSkColor();
  }
  scrollbar_thumb.is_thumb_minimal_mode =
      scrollbar.IsFluentOverlayScrollbarMinimalMode();
  scrollbar_thumb.is_web_test = WebTestSupport::IsRunningWebTest();
  return scrollbar_thumb;
}

gfx::Rect ScrollbarThemeFluent::InsetTrackRect(const Scrollbar& scrollbar,
                                               gfx::Rect rect) const {
  int scaled_track_inset = ScrollbarTrackInsetPx(scrollbar.ScaleFromDIP());
  if (scrollbar.Orientation() == kHorizontalScrollbar) {
    rect.Inset(gfx::Insets::TLBR(scaled_track_inset, 0, scaled_track_inset, 0));
  } else {
    rect.Inset(gfx::Insets::TLBR(0, scaled_track_inset, 0, scaled_track_inset));
  }
  return rect;
}

gfx::Rect ScrollbarThemeFluent::InsetButtonRect(const Scrollbar& scrollbar,
                                                gfx::Rect rect,
                                                ScrollbarPart part) const {
  int scaled_track_inset = ScrollbarTrackInsetPx(scrollbar.ScaleFromDIP());
  // Inset all sides of the button *except* the one that borders with the
  // scrollbar track.
  if (scrollbar.Orientation() == kHorizontalScrollbar) {
    if (part == kBackButtonStartPart) {
      rect.Inset(gfx::Insets::TLBR(scaled_track_inset, scaled_track_inset,
                                   scaled_track_inset, 0));
    } else {
      rect.Inset(gfx::Insets::TLBR(scaled_track_inset, 0, scaled_track_inset,
                                   scaled_track_inset));
    }
  } else {
    if (part == kBackButtonStartPart) {
      rect.Inset(gfx::Insets::TLBR(scaled_track_inset, scaled_track_inset, 0,
                                   scaled_track_inset));
    } else {
      rect.Inset(gfx::Insets::TLBR(0, scaled_track_inset, scaled_track_inset,
                                   scaled_track_inset));
    }
  }
  return rect;
}

int ScrollbarThemeFluent::ScrollbarTrackInsetPx(float scale) const {
  return base::ClampRound(scale * scrollbar_track_inset_);
}

gfx::Rect ScrollbarThemeFluent::ShrinkMainThreadedMinimalModeThumbRect(
    const Scrollbar& scrollbar,
    const gfx::Rect& rect) const {
  CHECK(UsesOverlayScrollbars());
  const float idle_thickness_scale = style_.idle_thickness_scale;
  gfx::RectF thumb_rect(rect);
  if (scrollbar.Orientation() == kHorizontalScrollbar) {
    thumb_rect.set_y(rect.y() + rect.height() * (1 - idle_thickness_scale));
    thumb_rect.set_height(rect.height() * idle_thickness_scale);
  } else {
    if (!scrollbar.IsLeftSideVerticalScrollbar()) {
      thumb_rect.set_x(rect.x() + rect.width() * (1 - idle_thickness_scale));
    }
    thumb_rect.set_width(rect.width() * idle_thickness_scale);
  }
  return gfx::ToEnclosingRect(thumb_rect);
}

bool ScrollbarThemeFluent::UsesNinePatchTrackAndButtonsResource() const {
  return RuntimeEnabledFeatures::FluentScrollbarUsesNinePatchTrackEnabled();
}

}  // namespace blink

"""

```