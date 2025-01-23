Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Initial Understanding: File Name and Context**

The file name `scrollbar_theme_overlay.cc` immediately suggests that this code is responsible for handling the visual appearance and behavior of overlay scrollbars in the Chromium Blink rendering engine. The `overlay` part is key, hinting that these scrollbars likely don't occupy dedicated space but appear on top of content.

**2. Deciphering the `#include` Directives**

These lines tell us what other parts of the Blink/Chromium ecosystem this code interacts with:

* `web_theme_engine.h`:  Crucial. It's the interface to the underlying operating system's theme engine. This is where the actual drawing of the scrollbar elements likely happens.
* `scrollable_area.h`: Deals with the overall scrolling mechanism and containers that have scrollbars.
* `scrollbar.h`:  Defines the `Scrollbar` class itself, which this overlay theme will customize.
* `graphics_context.h`, `paint/drawing_recorder.h`:  Related to the graphics rendering pipeline in Blink. `GraphicsContext` is the core object for drawing, and `DrawingRecorder` is for optimization (caching drawing commands).
* `web_theme_engine_helper.h`: Provides utility functions to interact with `WebThemeEngine`.
* `wtf/math_extras.h`: Likely contains mathematical helper functions.
* `ui/gfx/geometry/transform.h`:  For applying transformations (like flipping) to drawn elements.

**3. Analyzing the `ScrollbarThemeOverlay` Class**

This is the core of the file. We need to go through its members and methods:

* **`GetInstance()`:**  A static method, indicating a singleton pattern. There's only one `ScrollbarThemeOverlay` instance. It initializes the object with default thumb thicknesses, likely retrieved from the native theme.
* **Constructor:**  Takes default and "thin" scrollbar dimensions as arguments, suggesting different visual styles.
* **`ShouldRepaintAllPartsOnInvalidation()`:** Returns `false`. This is a performance optimization – only necessary parts are repainted when something changes.
* **`PartsToInvalidateOnThumbPositionChange()`:** Returns `kNoPart`. For overlay scrollbars, moving the thumb doesn't require repainting other parts (like the track). This is a key characteristic of overlay scrollbars.
* **`ScrollbarThickness()`, `ScrollbarMargin()`, `ThumbThickness()`:** These methods calculate the dimensions of the scrollbar based on the scaling factor and the `EScrollbarWidth` (normal or thin). This shows responsiveness to different zoom levels and potentially CSS styling.
* **`UsesOverlayScrollbars()`:** Returns `true`, confirming the purpose of this class.
* **`OverlayScrollbarFadeOutDelay()`, `OverlayScrollbarFadeOutDuration()`:** These retrieve fade-out timings from the native theme, indicating the overlay scrollbar will fade away after inactivity.
* **`ThumbLength()`:**  Calculates the length of the scrollbar thumb based on the visible content size and the total content size. This is standard scrollbar behavior.
* **`HasThumb()`:** Returns `true`, as overlay scrollbars still have a thumb.
* **`BackButtonRect()`, `ForwardButtonRect()`:** Return empty rectangles. Overlay scrollbars typically don't have separate back/forward buttons.
* **`TrackRect()`:** Calculates the bounding rectangle of the scrollbar track, taking margins into account.
* **`ThumbRect()`:** Calculates the bounding rectangle of the thumb, adjusting its position based on whether it's a left-side vertical scrollbar.
* **`PaintThumb()`:** This is where the actual drawing of the thumb happens. It uses the `WebThemeEngine` to delegate the drawing to the operating system's theme. It handles different states (normal, disabled, pressed, hovered) and potentially custom thumb colors. The flipping logic for left-side vertical scrollbars is important.
* **`HitTest()`:** Determines which part of the scrollbar (if any) was clicked at a given point. For overlay scrollbars, only the thumb is interactive.
* **`UsesNinePatchThumbResource()`, `NinePatchThumbCanvasSize()`, `NinePatchThumbAperture()`:** These methods deal with nine-patch images, a technique to create resizable images without distortion. This suggests that the thumb may be drawn using such a technique.
* **`MinimumThumbLength()`:** Retrieves the minimum allowed size for the scrollbar thumb from the native theme.

**4. Identifying Connections to Web Technologies (JavaScript, HTML, CSS)**

* **CSS:** The `EScrollbarWidth` enum (thin, default, none) directly relates to the `::-webkit-scrollbar` CSS pseudo-element and its width properties (`thin`, `auto`, or explicit values). The `scrollbar-color` CSS property influences the `scrollbar_thumb.thumb_color`. The overlay behavior itself is a CSS feature.
* **HTML:**  When an HTML element's content overflows its container, the browser will create scrollbars. This code is responsible for the *appearance* of those scrollbars when they are the overlay type.
* **JavaScript:** JavaScript can trigger scrolling programmatically (e.g., using `element.scrollTop = ...`). This code will then be involved in rendering the overlay scrollbar as the user scrolls via JavaScript. JavaScript event listeners can also interact with the scrollbar (though this code primarily *paints* the scrollbar, not handles events directly).

**5. Formulating Examples, Assumptions, and User Errors**

* **Assumptions:**  We assume the user has a mouse or trackpad and is interacting with a web page in a browser that uses the Blink engine. We assume the operating system provides a theme engine.
* **Input/Output:** When scrolling occurs (input), the `PaintThumb()` method is called to redraw the thumb at its new position (output).
* **User Errors:** Incorrect CSS can lead to unexpected scrollbar behavior (e.g., setting `overflow: hidden` will prevent scrollbars from appearing). Trying to style non-overlay scrollbars with overlay-specific CSS might have no effect.
* **Debugging:** Understanding this code helps debug why an overlay scrollbar looks or behaves a certain way. For example, if the thumb is too small, checking `MinimumThumbLength()` and the native theme settings would be a starting point.

**6. Tracing User Actions**

The step-by-step user action explanation ties everything together, showing how a simple act of scrolling can lead to this specific code being executed.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This file just draws the scrollbar."  **Correction:** It's more than just drawing. It also determines the size, hit-testing, and fading behavior, all based on the native theme.
* **Overlooking details:**  Initially, I might miss the significance of the left-side vertical scrollbar handling. Reviewing the code carefully reveals the canvas transformations.
* **Connecting to web technologies:**  I might initially focus too much on the C++ code. Actively thinking about how CSS, HTML, and JavaScript interact with scrolling helps provide a more complete picture.

By following these steps, we can systematically analyze the provided C++ code and generate a comprehensive explanation of its functionality and its relationship to web technologies.
好的，我们来分析一下 `blink/renderer/core/scroll/scrollbar_theme_overlay.cc` 这个 Chromium Blink 引擎源代码文件的功能。

**功能概述**

`scrollbar_theme_overlay.cc` 文件实现了 **覆盖层滚动条（Overlay Scrollbar）** 的主题绘制和行为逻辑。覆盖层滚动条是一种不占用布局空间的滚动条，它覆盖在内容之上，通常在用户交互时显示，一段时间不活动后会逐渐淡出。

**核心功能点：**

1. **定义覆盖层滚动条的视觉外观：**
   -  它使用操作系统提供的原生主题引擎（通过 `WebThemeEngineHelper` 和 `WebThemeEngine` 接口）来绘制滚动条的各个部分，例如滚动槽（track）和滚动滑块（thumb）。
   -  它可以根据不同的状态（例如，正常、悬停、按下、禁用）绘制不同的视觉效果。
   -  它处理不同尺寸的滚动条（例如，默认尺寸和细滚动条）。
   -  它支持使用九宫格（Nine-Patch）技术来绘制可伸缩的滚动滑块。

2. **处理覆盖层滚动条的行为：**
   -  它定义了覆盖层滚动条的厚度、边距等尺寸。
   -  它计算滚动滑块的长度，基于可见内容的大小和总内容的大小。
   -  它确定鼠标点击的位置是否在滚动条的某个部分（例如，滚动滑块）。
   -  它管理覆盖层滚动条的淡入淡出效果的延迟和持续时间。
   -  它确定滚动滑块的最小长度。

3. **作为 `ScrollbarTheme` 接口的实现：**
   -  `ScrollbarThemeOverlay` 类继承自或实现了 `ScrollbarTheme` 接口，该接口定义了滚动条主题的基本行为。
   -  它重写了父类的一些方法，以提供覆盖层滚动条特有的行为。

**与 JavaScript, HTML, CSS 的关系及举例说明**

虽然此文件是用 C++ 编写的，但它直接影响着 Web 开发者使用 JavaScript、HTML 和 CSS 创建的网页的视觉呈现和用户交互。

* **CSS:**
    * **`::-webkit-scrollbar` 伪元素:**  Web 开发者可以使用 CSS 的 `::-webkit-scrollbar` 及其相关伪元素（如 `::-webkit-scrollbar-thumb`, `::-webkit-scrollbar-track` 等）来定制滚动条的样式。`ScrollbarThemeOverlay` 负责根据这些样式信息（例如，宽度、颜色等）以及操作系统的默认主题来绘制覆盖层滚动条。
        * **举例:**  CSS 中设置 `::-webkit-scrollbar { width: 10px; }` 会影响 `ScrollbarThemeOverlay::ScrollbarThickness` 方法返回的值。
        * **举例:**  CSS 中设置 `::-webkit-scrollbar-thumb { background-color: blue; }` 可能会影响 `ScrollbarThemeOverlay::PaintThumb` 中传递给 `WebThemeEngine` 的参数，尽管此文件自身更依赖于操作系统的主题。
    * **`overflow` 属性:**  HTML 元素的 `overflow`, `overflow-x`, `overflow-y` 属性决定了是否显示滚动条。当这些属性设置为 `auto` 或 `scroll` 且内容溢出时，会触发滚动条的显示，并由 `ScrollbarThemeOverlay` 负责绘制覆盖层滚动条（如果浏览器启用了覆盖层滚动条）。
        * **举例:**  一个 `div` 元素的 CSS 设置为 `overflow: auto;` 且其内容超出 `div` 的边界，浏览器会创建一个滚动条，如果满足条件，则会使用 `ScrollbarThemeOverlay` 来绘制。
    * **`scrollbar-width` 属性:**  CSS 的 `scrollbar-width` 属性（如 `thin`, `auto`）会影响 `ScrollbarThemeOverlay::ScrollbarThickness` 和 `ScrollbarThemeOverlay::ThumbThickness` 方法中根据 `EScrollbarWidth` 参数返回不同的值。
        * **举例:** 设置 `scrollbar-width: thin;` 会使得 `ScrollbarThemeOverlay` 使用 `thumb_thickness_thin_dip_` 等变量来计算尺寸。
    * **`scrollbar-color` 属性:**  CSS 的 `scrollbar-color` 属性允许指定滚动条滑块和轨迹的颜色。 这会影响 `ScrollbarThemeOverlay::PaintThumb` 中 `scrollbar.ScrollbarThumbColor()` 的返回值，并传递给底层的 `WebThemeEngine` 进行绘制。
        * **假设输入:**  CSS 设置 `scrollbar-color: red blue;`
        * **逻辑推理:**  `ScrollbarThemeOverlay::PaintThumb` 会获取到 `scrollbar.ScrollbarThumbColor()` 的值为红色，并将其传递给 `WebThemeEngine` 来绘制滑块。

* **HTML:**
    * **可滚动元素:** 任何 HTML 元素，如果其内容超出其边界，并且 CSS 的 `overflow` 属性允许滚动，就会产生滚动条。`ScrollbarThemeOverlay` 负责这些元素的覆盖层滚动条的绘制。
        * **举例:** 一个带有大量文本的 `<div>` 元素，如果设置了 `overflow: auto;`，就会出现滚动条。

* **JavaScript:**
    * **滚动事件:** JavaScript 可以监听元素的滚动事件（`scroll` 事件）。当用户与覆盖层滚动条交互导致滚动发生时，会触发这些事件。
    * **程序化滚动:** JavaScript 可以通过修改元素的 `scrollTop` 或 `scrollLeft` 属性来程序化地滚动元素。当发生程序化滚动时，`ScrollbarThemeOverlay` 可能会被调用来更新滚动条的滑块位置。
    * **交互反馈:** JavaScript 可以根据滚动条的状态（例如，是否正在拖动滑块）来执行相应的操作。

**逻辑推理、假设输入与输出**

* **假设输入:** 用户在一个内容溢出的 `<div>` 元素上开始拖动垂直覆盖层滚动条的滑块。
* **逻辑推理:**
    1. 鼠标事件被捕获，确定用户点击了滚动条的滑块部分（`ScrollbarThemeOverlay::HitTest` 返回 `kThumbPart`）。
    2. 当鼠标移动时，`ScrollbarThemeOverlay` 根据鼠标位置和滚动条的属性计算新的滑块位置。
    3. Blink 引擎会调用 `ScrollbarThemeOverlay::PaintThumb` 方法来重绘滑块，反映新的位置。
    4. 随着滑块的移动，关联的 `<div>` 元素的滚动位置也会更新，导致内容视图的滚动。
* **输出:** 滚动条滑块平滑地跟随鼠标移动，`<div>` 元素的内容也相应地滚动。

**用户或编程常见的使用错误举例**

1. **错误地认为覆盖层滚动条会占用布局空间:**  覆盖层滚动条不会影响元素的布局，它们覆盖在内容之上。如果开发者期望滚动条占用空间并影响其他元素的定位，可能会导致布局问题。
2. **过度定制滚动条样式导致可用性问题:**  虽然 CSS 允许定制滚动条样式，但过度修改颜色、大小等可能会导致滚动条难以辨认或操作，影响用户体验。
3. **在不支持覆盖层滚动条的浏览器上进行假设:**  并非所有浏览器或操作系统都默认启用覆盖层滚动条。开发者应该考虑到这一点，并可能需要提供回退方案。
4. **在强制颜色模式下样式失效:** 当操作系统处于高对比度等强制颜色模式时，某些自定义的滚动条样式可能会被忽略，以保证可访问性。开发者需要理解这种行为。
5. **JavaScript 与滚动条状态同步错误:**  如果 JavaScript 代码需要根据滚动条的状态（例如，是否显示）来执行某些操作，需要确保代码能够正确地检测和响应滚动条状态的变化。

**用户操作如何一步步到达这里 (作为调试线索)**

假设用户在一个网页上看到了一个垂直的覆盖层滚动条，并开始拖动滚动滑块：

1. **页面加载和渲染:** 用户在浏览器中打开一个包含可滚动内容的网页。Blink 引擎解析 HTML、CSS 和 JavaScript，构建 DOM 树和渲染树。
2. **滚动条创建:** 当 Blink 引擎发现某个元素的内容溢出并且 `overflow` 属性允许滚动时，会创建相应的 `Scrollbar` 对象。
3. **选择滚动条主题:**  Blink 引擎根据当前平台和浏览器设置，选择合适的 `ScrollbarTheme` 实现，对于启用了覆盖层滚动条的系统，会选择 `ScrollbarThemeOverlay`。
4. **滚动条绘制 (初始):**  `ScrollbarThemeOverlay` 的 `PaintThumb` 等方法被调用，使用操作系统的主题绘制初始状态的滚动条。
5. **用户交互 (鼠标按下):** 用户将鼠标指针移动到滚动条的滑块上并按下鼠标左键。
6. **命中测试:**  鼠标事件被传递到 Blink 引擎，`ScrollbarThemeOverlay::HitTest` 方法被调用，判断鼠标点击的位置是否在滚动条的滑块区域内。
7. **开始拖动:** 如果命中测试成功，并且用户开始移动鼠标，则进入拖动状态。
8. **滑块位置更新:**  Blink 引擎会根据鼠标的移动距离和滚动条的属性，计算出新的滑块位置。
9. **滚动条重绘:**  `ScrollbarThemeOverlay::PaintThumb` 方法再次被调用，使用新的滑块位置信息来重绘滚动条滑块。
10. **内容滚动:**  滑块位置的改变会触发关联元素的内容滚动。
11. **用户交互结束 (鼠标释放):** 用户释放鼠标按键，拖动操作结束。
12. **可能发生的淡出:** 如果滚动条一段时间没有活动，`ScrollbarThemeOverlay` 会根据配置的延迟和持续时间，启动淡出动画。

**调试线索:** 如果开发者想调试覆盖层滚动条的特定行为或外观问题，可以在 Chromium 的源代码中设置断点，例如：

* `ScrollbarThemeOverlay::GetInstance()`: 查看单例对象的初始化。
* `ScrollbarThemeOverlay::PaintThumb()`: 观察滑块的绘制过程和参数。
* `ScrollbarThemeOverlay::HitTest()`: 检查命中测试逻辑是否正确。
* `ScrollbarThemeOverlay::ThumbRect()`: 查看滑块的计算出的矩形区域。

通过分析这些方法中的变量值和执行流程，可以更好地理解覆盖层滚动条的工作原理，并定位可能存在的问题。

### 提示词
```
这是目录为blink/renderer/core/scroll/scrollbar_theme_overlay.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/scroll/scrollbar_theme_overlay.h"

#include "third_party/blink/public/platform/web_theme_engine.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scrollbar.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/theme/web_theme_engine_helper.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "ui/gfx/geometry/transform.h"

#include <algorithm>

namespace blink {

ScrollbarThemeOverlay& ScrollbarThemeOverlay::GetInstance() {
  DEFINE_STATIC_LOCAL(
      ScrollbarThemeOverlay, theme,
      (WebThemeEngineHelper::GetNativeThemeEngine()
           ->GetSize(WebThemeEngine::kPartScrollbarVerticalThumb)
           .width(),
       0,
       WebThemeEngineHelper::GetNativeThemeEngine()
           ->GetSize(WebThemeEngine::kPartScrollbarVerticalThumb)
           .width(),
       0));
  return theme;
}

ScrollbarThemeOverlay::ScrollbarThemeOverlay(int thumb_thickness_default_dip,
                                             int scrollbar_margin_default_dip,
                                             int thumb_thickness_thin_dip,
                                             int scrollbar_margin_thin_dip)
    : thumb_thickness_default_dip_(thumb_thickness_default_dip),
      scrollbar_margin_default_dip_(scrollbar_margin_default_dip),
      thumb_thickness_thin_dip_(thumb_thickness_thin_dip),
      scrollbar_margin_thin_dip_(scrollbar_margin_thin_dip) {}

bool ScrollbarThemeOverlay::ShouldRepaintAllPartsOnInvalidation() const {
  return false;
}

ScrollbarPart ScrollbarThemeOverlay::PartsToInvalidateOnThumbPositionChange(
    const Scrollbar&,
    float old_position,
    float new_position) const {
  return kNoPart;
}

int ScrollbarThemeOverlay::ScrollbarThickness(
    float scale_from_dip,
    EScrollbarWidth scrollbar_width) const {
  return ThumbThickness(scale_from_dip, scrollbar_width) +
         ScrollbarMargin(scale_from_dip, scrollbar_width);
}

int ScrollbarThemeOverlay::ScrollbarMargin(
    float scale_from_dip,
    EScrollbarWidth scrollbar_width) const {
  if (scrollbar_width == EScrollbarWidth::kNone)
    return 0;
  else if (scrollbar_width == EScrollbarWidth::kThin)
    return scrollbar_margin_thin_dip_ * scale_from_dip;
  else
    return scrollbar_margin_default_dip_ * scale_from_dip;
}

bool ScrollbarThemeOverlay::UsesOverlayScrollbars() const {
  return true;
}

base::TimeDelta ScrollbarThemeOverlay::OverlayScrollbarFadeOutDelay() const {
  WebThemeEngine::ScrollbarStyle style;
  WebThemeEngineHelper::GetNativeThemeEngine()->GetOverlayScrollbarStyle(
      &style);
  return style.fade_out_delay;
}

base::TimeDelta ScrollbarThemeOverlay::OverlayScrollbarFadeOutDuration() const {
  WebThemeEngine::ScrollbarStyle style;
  WebThemeEngineHelper::GetNativeThemeEngine()->GetOverlayScrollbarStyle(
      &style);
  return style.fade_out_duration;
}

int ScrollbarThemeOverlay::ThumbLength(const Scrollbar& scrollbar) const {
  int track_len = TrackLength(scrollbar);

  if (!scrollbar.TotalSize())
    return track_len;

  float proportion =
      static_cast<float>(scrollbar.VisibleSize()) / scrollbar.TotalSize();
  int length = round(proportion * track_len);
  int min_len = std::min(MinimumThumbLength(scrollbar), track_len);
  length = ClampTo(length, min_len, track_len);
  return length;
}

int ScrollbarThemeOverlay::ThumbThickness(
    float scale_from_dip,
    EScrollbarWidth scrollbar_width) const {
  if (scrollbar_width == EScrollbarWidth::kNone)
    return 0;
  else if (scrollbar_width == EScrollbarWidth::kThin)
    return thumb_thickness_thin_dip_ * scale_from_dip;
  else
    return thumb_thickness_default_dip_ * scale_from_dip;
}

bool ScrollbarThemeOverlay::HasThumb(const Scrollbar& scrollbar) const {
  return true;
}

gfx::Rect ScrollbarThemeOverlay::BackButtonRect(const Scrollbar&) const {
  return gfx::Rect();
}

gfx::Rect ScrollbarThemeOverlay::ForwardButtonRect(const Scrollbar&) const {
  return gfx::Rect();
}

gfx::Rect ScrollbarThemeOverlay::TrackRect(const Scrollbar& scrollbar) const {
  gfx::Rect rect = scrollbar.FrameRect();
  int scrollbar_margin =
      ScrollbarMargin(scrollbar.ScaleFromDIP(), scrollbar.CSSScrollbarWidth());
  if (scrollbar.Orientation() == kHorizontalScrollbar)
    rect.Inset(gfx::Insets::VH(0, scrollbar_margin));
  else
    rect.Inset(gfx::Insets::VH(scrollbar_margin, 0));
  return rect;
}

gfx::Rect ScrollbarThemeOverlay::ThumbRect(const Scrollbar& scrollbar) const {
  gfx::Rect rect = ScrollbarTheme::ThumbRect(scrollbar);
  EScrollbarWidth scrollbar_width = scrollbar.CSSScrollbarWidth();
  if (scrollbar.Orientation() == kHorizontalScrollbar) {
    rect.set_height(ThumbThickness(scrollbar.ScaleFromDIP(), scrollbar_width));
  } else {
    if (scrollbar.IsLeftSideVerticalScrollbar()) {
      rect.Offset(ScrollbarMargin(scrollbar.ScaleFromDIP(), scrollbar_width),
                  0);
    }
    rect.set_width(ThumbThickness(scrollbar.ScaleFromDIP(), scrollbar_width));
  }
  return rect;
}

void ScrollbarThemeOverlay::PaintThumb(GraphicsContext& context,
                                       const Scrollbar& scrollbar,
                                       const gfx::Rect& rect) {
  if (DrawingRecorder::UseCachedDrawingIfPossible(context, scrollbar,
                                                  DisplayItem::kScrollbarThumb))
    return;

  DrawingRecorder recorder(context, scrollbar, DisplayItem::kScrollbarThumb,
                           rect);

  WebThemeEngine::State state = WebThemeEngine::kStateNormal;

  if (!scrollbar.Enabled())
    state = WebThemeEngine::kStateDisabled;
  else if (scrollbar.PressedPart() == kThumbPart)
    state = WebThemeEngine::kStatePressed;
  else if (scrollbar.HoveredPart() == kThumbPart)
    state = WebThemeEngine::kStateHover;

  cc::PaintCanvas* canvas = context.Canvas();

  WebThemeEngine::Part part = WebThemeEngine::kPartScrollbarHorizontalThumb;
  if (scrollbar.Orientation() == kVerticalScrollbar)
    part = WebThemeEngine::kPartScrollbarVerticalThumb;

  blink::WebThemeEngine::ScrollbarThumbExtraParams scrollbar_thumb;
  if (scrollbar.ScrollbarThumbColor().has_value()) {
    scrollbar_thumb.thumb_color =
        scrollbar.ScrollbarThumbColor().value().toSkColor4f().toSkColor();
  }

  // Horizontally flip the canvas if it is left vertical scrollbar.
  if (scrollbar.IsLeftSideVerticalScrollbar()) {
    canvas->save();
    canvas->translate(rect.width(), 0);
    canvas->scale(-1, 1);
  }

  blink::WebThemeEngine::ExtraParams params(scrollbar_thumb);

  mojom::blink::ColorScheme color_scheme = scrollbar.UsedColorScheme();
  WebThemeEngineHelper::GetNativeThemeEngine()->Paint(
      canvas, part, state, rect, &params, color_scheme,
      scrollbar.InForcedColorsMode(), scrollbar.GetColorProvider(color_scheme));

  if (scrollbar.IsLeftSideVerticalScrollbar())
    canvas->restore();
}

ScrollbarPart ScrollbarThemeOverlay::HitTest(const Scrollbar& scrollbar,
                                             const gfx::Point& position) const {
  ScrollbarPart part = ScrollbarTheme::HitTest(scrollbar, position);
  if (part != kThumbPart)
    return kNoPart;

  return kThumbPart;
}

bool ScrollbarThemeOverlay::UsesNinePatchThumbResource() const {
  // Thumb orientation doesn't matter here.
  return WebThemeEngineHelper::GetNativeThemeEngine()->SupportsNinePatch(
      WebThemeEngine::kPartScrollbarVerticalThumb);
}

gfx::Size ScrollbarThemeOverlay::NinePatchThumbCanvasSize(
    const Scrollbar& scrollbar) const {
  DCHECK(UsesNinePatchThumbResource());

  WebThemeEngine::Part part =
      scrollbar.Orientation() == kVerticalScrollbar
          ? WebThemeEngine::kPartScrollbarVerticalThumb
          : WebThemeEngine::kPartScrollbarHorizontalThumb;

  return WebThemeEngineHelper::GetNativeThemeEngine()->NinePatchCanvasSize(
      part);
}

gfx::Rect ScrollbarThemeOverlay::NinePatchThumbAperture(
    const Scrollbar& scrollbar) const {
  DCHECK(UsesNinePatchThumbResource());

  WebThemeEngine::Part part = WebThemeEngine::kPartScrollbarHorizontalThumb;
  if (scrollbar.Orientation() == kVerticalScrollbar)
    part = WebThemeEngine::kPartScrollbarVerticalThumb;

  return WebThemeEngineHelper::GetNativeThemeEngine()->NinePatchAperture(part);
}

int ScrollbarThemeOverlay::MinimumThumbLength(
    const Scrollbar& scrollbar) const {
  if (scrollbar.Orientation() == kVerticalScrollbar) {
    return WebThemeEngineHelper::GetNativeThemeEngine()
        ->GetSize(WebThemeEngine::kPartScrollbarVerticalThumb)
        .height();
  }

  return WebThemeEngineHelper::GetNativeThemeEngine()
      ->GetSize(WebThemeEngine::kPartScrollbarHorizontalThumb)
      .width();
}

}  // namespace blink
```