Response:
My thought process to answer the request went something like this:

1. **Understand the Goal:** The request asks for a summary of the provided C++ code snippet, focusing on its functionality, connections to web technologies (JavaScript, HTML, CSS), logical inferences, potential errors, debugging hints, and overall purpose. It's the *first part* of a larger file.

2. **Initial Scan for Keywords and Structure:** I quickly scanned the code for familiar keywords and structures related to rendering and web technologies. Things like:
    * `#include`: Indicates dependencies and core functionalities.
    * `blink`:  Confirms it's part of the Blink rendering engine.
    * `paint`, `theme`, `canvas`, `graphics`:  Strongly suggest rendering and visual appearance management.
    * `WebThemeEngine`:  A crucial class hinting at interaction with the operating system's native theme.
    * `HTMLInputElement`, `LayoutObject`, `ComputedStyle`:  Key data structures for representing DOM elements and their styling.
    * Function names like `PaintCheckbox`, `PaintButton`, `PaintSliderTrack`:  Directly indicate the types of elements being rendered.

3. **Identify Core Functionality - The "What":** Based on the includes and function names, I deduced the primary function of `ThemePainterDefault` is to *draw* various HTML form controls and related elements using the underlying operating system's theme. It's a bridge between Blink's layout and the platform's native rendering capabilities.

4. **Analyze Connections to Web Technologies - The "How":**
    * **HTML:** The code directly interacts with HTML elements like `<input>`, `<button>`, `<progress>`, etc. The `Paint` functions are called when these elements need to be displayed.
    * **CSS:**  The `ComputedStyle` object is used extensively to determine the visual properties of the elements (like zoom level, writing direction, border radius, background color, accent color). This is where CSS styles influence the native rendering.
    * **JavaScript:** While the code itself is C++, it's part of the rendering pipeline triggered by changes in the DOM (which can be manipulated by JavaScript). User interactions handled by JavaScript might lead to repainting, involving this code.

5. **Look for Logical Inferences and Input/Output - The "Why":** The code makes decisions about how to render elements based on their state (checked, disabled, hovered), writing direction, and other factors. I looked for specific logic:
    * Conditional rendering (`if` statements based on element state).
    * Calculations for positioning and sizing elements.
    * The `GetColorSchemeForAccentColor` function is a clear example of logical deduction based on color contrast.
    * **Hypothetical Input/Output:** I imagined a simple scenario, like rendering a checked checkbox. The input would be the `HTMLInputElement` representing the checkbox and its `ComputedStyle`. The output would be the drawing commands sent to the `GraphicsContext` to render the native checkbox appearance.

6. **Consider User/Programming Errors - The "Potential Issues":**  I thought about common mistakes when working with web forms and styling:
    * Incorrect CSS leading to unexpected appearances (e.g., a custom background conflicting with native rendering).
    * Relying too heavily on native appearance and forgetting cross-browser compatibility.
    * Issues with forced colors mode.

7. **Trace User Interaction - The "Debugging Clues":**  I outlined the sequence of events that could lead to this code being executed during rendering:
    * User loads a page.
    * Browser parses HTML and CSS.
    * Layout is calculated.
    * During the paint phase, `ThemePainterDefault` is called to render specific elements.
    * User interaction triggers a repaint.

8. **Focus on the "First Part" Constraint:**  Since it's only the first part, I focused on the core painting functionalities and the setup. I avoided speculating too deeply into what might come in the second part.

9. **Structure the Summary:**  I organized the information into clear categories based on the request's prompts: functionality, relationships with web technologies, logical inferences, errors, debugging, and a final summary of the first part. This makes the answer easier to understand.

10. **Refine and Iterate:** I reviewed my initial thoughts and refined the explanations, adding more specific examples and elaborating on key concepts like `WebThemeEngine` and `ComputedStyle`. I made sure to use clear and concise language.

Essentially, I tried to "think like a developer" who wrote or is trying to understand this code. I looked for the purpose, the inputs, the outputs, the logic, and potential problems. The keywords and structure of the code itself provided strong hints, and my existing knowledge of web rendering helped me connect the pieces.
这是对 `blink/renderer/core/paint/theme_painter_default.cc` 文件（第一部分）的功能的归纳：

**核心功能： 默认平台主题绘制器**

`ThemePainterDefault` 类是 Chromium Blink 引擎中负责使用操作系统或平台的默认主题来绘制各种用户界面控件（例如按钮、复选框、单选按钮、文本框、滑块、进度条等）的组件。  它作为 `ThemePainter` 接口的一个具体实现，提供了在没有自定义样式或强制样式时，如何绘制这些控件的默认行为。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件是 Blink 渲染引擎的核心部分，它负责将 HTML 结构和 CSS 样式转化为屏幕上的视觉呈现。它与 JavaScript, HTML, CSS 的关系如下：

* **HTML (结构):**  该文件中的函数（例如 `PaintCheckbox`, `PaintButton` 等）直接对应于 HTML 中的各种表单控件元素（`<input type="checkbox">`，`<button>` 等）。当 Blink 渲染引擎遇到这些元素时，会调用 `ThemePainterDefault` 中相应的绘制函数。

    * **举例：** 当浏览器解析到 `<input type="checkbox">` 标签时，布局引擎会创建一个对应的布局对象。在绘制阶段，`ThemePainterDefault::PaintCheckbox` 函数会被调用来绘制这个复选框。

* **CSS (样式):**  `ThemePainterDefault` 会考虑 CSS 样式，但其主要职责是在没有或很少自定义样式的情况下提供默认外观。它会读取 `ComputedStyle` 对象来获取一些关键的样式信息，例如：
    * **元素状态:**  是否禁用 (`IsDisabledFormControl`)，是否激活 (`IsActive`)，是否悬停 (`IsHovered`)，这些状态会影响控件的绘制状态。
    * **缩放级别 (`style.EffectiveZoom()`):**  用于调整绘制尺寸。
    * **书写模式 (`style.GetWritingDirection()`):** 影响某些控件的绘制方向，例如滑块。
    * **背景色 (`style.VisitedDependentColor(GetCSSPropertyBackgroundColor())`) 和边框:**  虽然 `ThemePainterDefault` 通常使用原生主题，但在某些情况下（例如文本框有圆角或背景图），它会返回 `true`，指示上层绘制器处理 CSS 边框和背景。
    * **强调色 (`style.AccentColorResolved()`):**  用于某些控件（如复选框、单选按钮、滑块、进度条）的着色，以提升用户体验和可访问性。
    * **外观属性 (`style.EffectiveAppearance()`):**  允许控制某些控件的特定变体，例如垂直滑块。

    * **举例：**  如果一个 `<button>` 元素没有设置任何自定义样式，`ThemePainterDefault::PaintButton` 会使用操作系统默认的按钮样式进行绘制。如果 CSS 设置了 `zoom: 2;`，`style.EffectiveZoom()` 将返回 2，`PaintButton` 会相应地放大按钮的绘制。

* **JavaScript (交互和动态):**  JavaScript 可以动态地修改 HTML 结构和 CSS 样式，这些修改最终会触发 Blink 渲染引擎的重新布局和重绘。当涉及到表单控件时，`ThemePainterDefault` 就会参与到这个重绘过程中。例如，JavaScript 可以改变复选框的选中状态，这会导致 `PaintCheckbox` 函数在下一次绘制时使用不同的参数 (`button.checked`) 来呈现选中或未选中的状态。

    * **举例：** 用户点击一个复选框时，JavaScript 可能会修改其 `checked` 属性。浏览器会重新渲染，`PaintCheckbox` 函数会被调用，并且 `IsChecked(element)` 将返回 `true`，从而绘制被选中的复选框。

**逻辑推理与假设输入/输出：**

* **假设输入 (PaintCheckbox):**
    * `element`:  一个代表 `<input type="checkbox">` 的 `Element` 对象。
    * `document`:  该元素所属的 `Document` 对象。
    * `style`:  该元素的 `ComputedStyle` 对象，包含应用到该元素的 CSS 样式信息。
    * `paint_info`:  包含绘制上下文 (`GraphicsContext`) 和其他绘制信息的对象。
    * `rect`:  该复选框需要绘制的矩形区域。
    * **假设 `IsChecked(element)` 返回 `true` (复选框被选中)**
    * **假设 `GetWebThemeState(element)` 返回 `WebThemeEngine::kStateNormal` (正常状态，未禁用，未激活，未悬停)**

* **逻辑推理 (PaintCheckbox):**
    1. 获取 `WebThemeEngine::ButtonExtraParams` 并设置 `checked` 为 `true`，`indeterminate` 为 `false` (因为假设不是不确定状态)。
    2. 获取元素的缩放级别。
    3. 调用 `WebThemeEngineHelper::GetNativeThemeEngine()->Paint`，传入 `WebThemeEngine::kPartCheckbox`（表示绘制复选框），`WebThemeEngine::kStateNormal`，以及其他参数，包括是否选中。
    4. 特别注意 `GetColorSchemeForAccentColor` 的逻辑。如果复选框被选中且未禁用，则会基于强调色和复选框背景色的对比度来动态选择颜色方案，以保证对比度。

* **假设输出 (PaintCheckbox):**
    * 调用底层平台的主题引擎 (例如 Windows 的 GDI 或 macOS 的 Quartz) 的相应函数，绘制一个平台默认样式的、被选中的复选框在其指定的矩形区域内。

* **假设输入 (GetColorSchemeForAccentColor):**
    * `accent_color`:  一个 `std::optional<SkColor>`，假设存在一个有效的强调色。
    * `color_scheme`:  当前的颜色方案，例如 `mojom::ColorScheme::kLight`。
    * `light_contrasting_color`:  在浅色模式下复选框的背景色。
    * `dark_contrasting_color`:   在深色模式下复选框的背景色。
    * **假设强调色与浅色模式下的复选框背景色对比度不足，但与深色模式下的背景色对比度足够。**

* **逻辑推理 (GetColorSchemeForAccentColor):**
    1. 计算强调色分别与浅色和深色背景色的对比度。
    2. 由于与浅色背景色对比度不足，但与深色背景色足够，并且当前颜色方案是浅色，因此推断为了保证对比度，需要切换到深色方案。

* **假设输出 (GetColorSchemeForAccentColor):**
    * 返回 `mojom::ColorScheme::kDark`。

**用户或编程常见的使用错误：**

* **过度依赖自定义样式而忽略了平台主题的默认行为。** 这可能导致在不同的操作系统或浏览器上控件的外观不一致。
* **在强制颜色模式下，自定义样式可能被忽略，而 `ThemePainterDefault` 会使用高对比度的系统颜色。**  开发者需要注意这种情况下的可访问性。
* **误解了 `accent-color` CSS 属性的作用范围。**  `ThemePainterDefault` 会尝试利用强调色来提升控件的视觉效果，但如果开发者没有正确理解其工作原理，可能会导致意料之外的颜色。
* **在调试样式问题时，忽略了平台主题的影响。** 有时候控件的特定外观是平台主题提供的，而不是 CSS 样式直接控制的。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户打开一个网页：** 用户在浏览器中输入网址或点击链接。
2. **浏览器加载 HTML、CSS 和 JavaScript：** 浏览器开始解析接收到的网页资源。
3. **构建 DOM 树和 CSSOM 树：** 浏览器解析 HTML 构建 DOM 树，解析 CSS 构建 CSSOM 树。
4. **创建渲染树 (Render Tree)：** 将 DOM 树和 CSSOM 树合并，创建渲染树，只包含需要渲染的节点及其样式信息。
5. **布局 (Layout)：** 计算渲染树中每个节点的位置和大小。
6. **绘制 (Paint)：**  遍历渲染树，对于每个需要绘制的元素，调用相应的绘制逻辑。
7. **遇到表单控件：** 当绘制过程遇到 HTML 表单控件（例如 `<input type="checkbox">`）时，并且该控件没有被完全自定义样式覆盖，Blink 渲染引擎会调用 `ThemePainterDefault` 中对应的 `Paint...` 函数。
8. **`GetWebThemeState` 调用：** 在绘制函数中，通常会先调用 `GetWebThemeState` 来确定控件的当前状态（正常、悬停、激活、禁用）。
9. **`WebThemeEngineHelper::GetNativeThemeEngine()->Paint` 调用：** 最终，会调用 `WebThemeEngineHelper` 来获取平台的主题引擎，并调用其 `Paint` 方法，将绘制指令传递给底层操作系统进行渲染。

**归纳第一部分的功能：**

总而言之，`blink/renderer/core/paint/theme_painter_default.cc` 的第一部分定义了 `ThemePainterDefault` 类，它负责使用操作系统或平台的默认主题来绘制各种基本的 HTML 表单控件。它考虑了元素的状态、缩放级别、书写模式和强调色等因素，并利用平台提供的原生主题引擎来实现绘制。它的核心作用是提供用户界面控件的基础视觉呈现，并在没有或很少自定义样式的情况下确保用户界面的一致性和平台原生感。 它通过与 `WebThemeEngine` 接口交互，充当了 Blink 渲染引擎和底层平台绘制能力之间的桥梁。

### 提示词
```
这是目录为blink/renderer/core/paint/theme_painter_default.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2007 Apple Inc.
 * Copyright (C) 2007 Alp Toker <alp@atoker.com>
 * Copyright (C) 2008 Collabora Ltd.
 * Copyright (C) 2008, 2009 Google Inc.
 * Copyright (C) 2009 Kenneth Rohde Christiansen
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "third_party/blink/renderer/core/paint/theme_painter_default.h"

#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/public/platform/web_theme_engine.h"
#include "third_party/blink/public/resources/grit/blink_image_resources.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/slider_thumb_element.h"
#include "third_party/blink/renderer/core/html/forms/spin_button_element.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_progress.h"
#include "third_party/blink/renderer/core/layout/layout_theme_default.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/text/writing_mode.h"
#include "third_party/blink/renderer/platform/theme/web_theme_engine_helper.h"
#include "ui/base/ui_base_features.h"
#include "ui/color/color_provider.h"
#include "ui/gfx/color_utils.h"
#include "ui/native_theme/native_theme.h"

namespace blink {

namespace {

bool IsIndeterminate(const Element& element) {
  if (const auto* input = DynamicTo<HTMLInputElement>(element))
    return input->ShouldAppearIndeterminate();
  return false;
}

bool IsChecked(const Element& element) {
  if (const auto* input = DynamicTo<HTMLInputElement>(element))
    return input->ShouldAppearChecked();
  return false;
}

WebThemeEngine::State GetWebThemeState(const Element& element) {
  if (element.IsDisabledFormControl())
    return WebThemeEngine::kStateDisabled;
  if (element.IsActive())
    return WebThemeEngine::kStatePressed;
  if (element.IsHovered())
    return WebThemeEngine::kStateHover;

  return WebThemeEngine::kStateNormal;
}

SkColor GetContrastingColorFor(const Element& element,
                               const mojom::ColorScheme color_scheme,
                               WebThemeEngine::Part part) {
  WebThemeEngine::State state = GetWebThemeState(element);

  const ui::ColorProvider* color_provider =
      element.GetDocument().GetColorProviderForPainting(color_scheme);

  const bool is_disabled = (state == WebThemeEngine::kStateDisabled);
  switch (part) {
    case WebThemeEngine::kPartCheckbox:
    case WebThemeEngine::kPartRadio:
      return is_disabled ? color_provider->GetColor(
                               ui::kColorWebNativeControlBackgroundDisabled)
                         : color_provider->GetColor(
                               ui::kColorWebNativeControlBackground);
    case WebThemeEngine::kPartSliderTrack:
    case WebThemeEngine::kPartSliderThumb:
    case WebThemeEngine::kPartProgressBar:
      // We use `kStateNormal` here because the user hovering or clicking on the
      // slider will change the state to something else, and we don't want the
      // color-scheme to flicker back and forth when the user interacts with it.
      return color_provider->GetColor(ui::kColorWebNativeControlFill);
    default:
      NOTREACHED();
  }
}

mojom::ColorScheme CalculateColorSchemeForAccentColor(
    std::optional<SkColor> accent_color,
    mojom::ColorScheme color_scheme,
    SkColor light_contrasting_color,
    SkColor dark_contrasting_color) {
  if (!accent_color) {
    return color_scheme;
  }

  const float contrast_with_light =
      color_utils::GetContrastRatio(*accent_color, light_contrasting_color);
  const float contrast_with_dark =
      color_utils::GetContrastRatio(*accent_color, dark_contrasting_color);

  // If there is enough contrast between `accent_color` and `color_scheme`, then
  // let's keep it the same. Otherwise, flip the `color_scheme` to guarantee
  // contrast.
  if (color_scheme == mojom::ColorScheme::kDark) {
    if (contrast_with_dark < color_utils::kMinimumVisibleContrastRatio &&
        contrast_with_dark < contrast_with_light) {
      // TODO(crbug.com/1216137): what if `contrast_with_light` is less than
      // `kMinimumContrast`? Should we modify `accent_color`...?
      return mojom::ColorScheme::kLight;
    }
  } else {
    if (contrast_with_light < color_utils::kMinimumVisibleContrastRatio &&
        contrast_with_light < contrast_with_dark) {
      return mojom::ColorScheme::kDark;
    }
  }

  return color_scheme;
}

mojom::blink::ColorScheme GetColorSchemeForAccentColor(
    const Element& element,
    const mojom::blink::ColorScheme color_scheme,
    const std::optional<SkColor> accent_color,
    WebThemeEngine::Part part) {
  return CalculateColorSchemeForAccentColor(
      accent_color, color_scheme,
      GetContrastingColorFor(element, mojom::blink::ColorScheme::kLight, part),
      GetContrastingColorFor(element, mojom::blink::ColorScheme::kDark, part));
}

class DirectionFlippingScope {
  STACK_ALLOCATED();

 public:
  DirectionFlippingScope(const LayoutObject&,
                         const PaintInfo&,
                         const gfx::Rect&);
  ~DirectionFlippingScope();

 private:
  bool needs_horizontal_flipping_;
  bool needs_vertical_flipping_;
  const PaintInfo& paint_info_;
};

DirectionFlippingScope::DirectionFlippingScope(
    const LayoutObject& layout_object,
    const PaintInfo& paint_info,
    const gfx::Rect& rect)
    : paint_info_(paint_info) {
  PhysicalDirection inline_end =
      layout_object.StyleRef().GetWritingDirection().InlineEnd();
  needs_horizontal_flipping_ = inline_end == PhysicalDirection::kLeft;
  needs_vertical_flipping_ = inline_end == PhysicalDirection::kUp;
  if (needs_horizontal_flipping_) {
    paint_info_.context.Save();
    paint_info_.context.Translate(2 * rect.x() + rect.width(), 0);
    paint_info_.context.Scale(-1, 1);
  } else if (needs_vertical_flipping_) {
    paint_info_.context.Save();
    paint_info_.context.Translate(0, 2 * rect.y() + rect.height());
    paint_info_.context.Scale(1, -1);
  }
}

DirectionFlippingScope::~DirectionFlippingScope() {
  if (!needs_horizontal_flipping_ && !needs_vertical_flipping_) {
    return;
  }
  paint_info_.context.Restore();
}

gfx::Rect DeterminateProgressValueRectFor(const LayoutProgress& layout_progress,
                                          const gfx::Rect& rect) {
  int dx = rect.width();
  int dy = rect.height();
  if (layout_progress.IsHorizontalWritingMode()) {
    dx *= layout_progress.GetPosition();
  } else {
    dy *= layout_progress.GetPosition();
  }
  return gfx::Rect(rect.x(), rect.y(), dx, dy);
}

gfx::Rect IndeterminateProgressValueRectFor(
    const LayoutProgress& layout_progress,
    const gfx::Rect& rect) {
  // Value comes from default of GTK+.
  static const int kProgressActivityBlocks = 5;

  int x = rect.x();
  int y = rect.y();
  int value_width = rect.width();
  int value_height = rect.height();
  double progress = layout_progress.AnimationProgress();

  if (layout_progress.IsHorizontalWritingMode()) {
    value_width = value_width / kProgressActivityBlocks;
    int movable_width = rect.width() - value_width;
    if (movable_width <= 0)
      return gfx::Rect();
    x = progress < 0.5 ? x + progress * 2 * movable_width
                       : rect.x() + (1.0 - progress) * 2 * movable_width;
  } else {
    value_height = value_height / kProgressActivityBlocks;
    int movable_height = rect.height() - value_height;
    if (movable_height <= 0)
      return gfx::Rect();
    y = progress < 0.5 ? y + progress * 2 * movable_height
                       : rect.y() + (1.0 - progress) * 2 * movable_height;
  }

  return gfx::Rect(x, y, value_width, value_height);
}

gfx::Rect ProgressValueRectFor(const LayoutProgress& layout_progress,
                               const gfx::Rect& rect) {
  return layout_progress.IsDeterminate()
             ? DeterminateProgressValueRectFor(layout_progress, rect)
             : IndeterminateProgressValueRectFor(layout_progress, rect);
}

gfx::Rect ConvertToPaintingRect(const LayoutObject& input_layout_object,
                                const LayoutObject& part_layout_object,
                                PhysicalRect part_rect,
                                const gfx::Rect& local_offset) {
  // Compute an offset between the partLayoutObject and the inputLayoutObject.
  PhysicalOffset offset_from_input_layout_object =
      -part_layout_object.OffsetFromAncestor(&input_layout_object);
  // Move the rect into partLayoutObject's coords.
  part_rect.Move(offset_from_input_layout_object);
  // Account for the local drawing offset.
  part_rect.Move(PhysicalOffset(local_offset.origin()));

  return ToPixelSnappedRect(part_rect);
}

std::optional<SkColor> GetAccentColor(const ComputedStyle& style,
                                      const Document& document) {
  std::optional<Color> css_accent_color = style.AccentColorResolved();
  if (css_accent_color)
    return css_accent_color->Rgb();

  // We should not allow the system accent color to be rendered in image
  // contexts because it could be read back by the page and used for
  // fingerprinting.
  if (!document.GetPage()->GetChromeClient().IsIsolatedSVGChromeClient()) {
    mojom::blink::ColorScheme color_scheme = style.UsedColorScheme();
    LayoutTheme& layout_theme = LayoutTheme::GetTheme();
    if (!document.InForcedColorsMode() &&
        RuntimeEnabledFeatures::CSSSystemAccentColorEnabled() &&
        layout_theme.IsAccentColorCustomized(color_scheme)) {
      return layout_theme.GetSystemAccentColor(color_scheme).Rgb();
    }
  }

  return std::nullopt;
}

}  // namespace

ThemePainterDefault::ThemePainterDefault(LayoutThemeDefault& theme)
    : ThemePainter(), theme_(theme) {}

bool ThemePainterDefault::PaintCheckbox(const Element& element,
                                        const Document& document,
                                        const ComputedStyle& style,
                                        const PaintInfo& paint_info,
                                        const gfx::Rect& rect) {
  WebThemeEngine::ButtonExtraParams button;
  button.checked = IsChecked(element);
  button.indeterminate = IsIndeterminate(element);

  float zoom_level = style.EffectiveZoom();
  button.zoom = zoom_level;
  GraphicsContextStateSaver state_saver(paint_info.context, false);
  gfx::Rect unzoomed_rect =
      ApplyZoomToRect(rect, paint_info, state_saver, zoom_level);
  WebThemeEngine::ExtraParams extra_params(button);
  mojom::blink::ColorScheme color_scheme = style.UsedColorScheme();

  // This is used for `kPartCheckbox`, which gets drawn adjacent to
  // `accent_color`. In order to guarantee contrast between `kPartCheckbox` and
  // `accent_color`, we choose the `color_scheme` here based on the two possible
  // color values for `kPartCheckbox`.
  bool accent_color_affects_color_scheme =
      button.checked &&
      GetWebThemeState(element) != WebThemeEngine::kStateDisabled;
  if (accent_color_affects_color_scheme) {
    color_scheme = GetColorSchemeForAccentColor(element, color_scheme,
                                                GetAccentColor(style, document),
                                                WebThemeEngine::kPartCheckbox);
  }

  const ui::ColorProvider* color_provider =
      document.GetColorProviderForPainting(color_scheme);
  WebThemeEngineHelper::GetNativeThemeEngine()->Paint(
      paint_info.context.Canvas(), WebThemeEngine::kPartCheckbox,
      GetWebThemeState(element), unzoomed_rect, &extra_params, color_scheme,
      document.InForcedColorsMode(), color_provider,
      GetAccentColor(style, document));
  return false;
}

bool ThemePainterDefault::PaintRadio(const Element& element,
                                     const Document& document,
                                     const ComputedStyle& style,
                                     const PaintInfo& paint_info,
                                     const gfx::Rect& rect) {
  WebThemeEngine::ButtonExtraParams button;
  button.checked = IsChecked(element);

  float zoom_level = style.EffectiveZoom();
  button.zoom = zoom_level;
  WebThemeEngine::ExtraParams extra_params(button);
  GraphicsContextStateSaver state_saver(paint_info.context, false);
  gfx::Rect unzoomed_rect =
      ApplyZoomToRect(rect, paint_info, state_saver, zoom_level);
  mojom::blink::ColorScheme color_scheme = style.UsedColorScheme();

  // This is used for `kPartRadio`, which gets drawn adjacent to `accent_color`.
  // In order to guarantee contrast between `kPartRadio` and `accent_color`, we
  // choose the `color_scheme` here based on the two possible color values for
  // `kPartRadio`.
  bool accent_color_affects_color_scheme =
      button.checked &&
      GetWebThemeState(element) != WebThemeEngine::kStateDisabled;
  if (accent_color_affects_color_scheme) {
    color_scheme = GetColorSchemeForAccentColor(element, color_scheme,
                                                GetAccentColor(style, document),
                                                WebThemeEngine::kPartRadio);
  }

  const ui::ColorProvider* color_provider =
      document.GetColorProviderForPainting(color_scheme);
  WebThemeEngineHelper::GetNativeThemeEngine()->Paint(
      paint_info.context.Canvas(), WebThemeEngine::kPartRadio,
      GetWebThemeState(element), unzoomed_rect, &extra_params, color_scheme,
      document.InForcedColorsMode(), color_provider,
      GetAccentColor(style, document));
  return false;
}

bool ThemePainterDefault::PaintButton(const Element& element,
                                      const Document& document,
                                      const ComputedStyle& style,
                                      const PaintInfo& paint_info,
                                      const gfx::Rect& rect) {
  WebThemeEngine::ButtonExtraParams button;
  button.has_border = true;
  button.zoom = style.EffectiveZoom();
  WebThemeEngine::ExtraParams extra_params(button);
  mojom::blink::ColorScheme color_scheme = style.UsedColorScheme();
  const ui::ColorProvider* color_provider =
      document.GetColorProviderForPainting(color_scheme);

  WebThemeEngineHelper::GetNativeThemeEngine()->Paint(
      paint_info.context.Canvas(), WebThemeEngine::kPartButton,
      GetWebThemeState(element), rect, &extra_params, color_scheme,
      document.InForcedColorsMode(), color_provider,
      GetAccentColor(style, document));
  return false;
}

bool ThemePainterDefault::PaintTextField(const Element& element,
                                         const ComputedStyle& style,
                                         const PaintInfo& paint_info,
                                         const gfx::Rect& rect) {
  // WebThemeEngine does not handle border rounded corner and background image
  // so return true to draw CSS border and background.
  if (style.HasBorderRadius() || style.HasBackgroundImage())
    return true;

  ControlPart part = style.EffectiveAppearance();

  WebThemeEngine::TextFieldExtraParams text_field;
  text_field.is_text_area = part == kTextAreaPart;
  text_field.is_listbox = part == kListboxPart;
  text_field.has_border = true;
  text_field.zoom = style.EffectiveZoom();

  Color background_color =
      style.VisitedDependentColor(GetCSSPropertyBackgroundColor());
  text_field.background_color = background_color.Rgb();
  text_field.auto_complete_active =
      DynamicTo<HTMLFormControlElement>(element)->IsAutofilled() ||
      DynamicTo<HTMLFormControlElement>(element)->IsPreviewed();

  WebThemeEngine::ExtraParams extra_params(text_field);
  mojom::blink::ColorScheme color_scheme = style.UsedColorScheme();
  const ui::ColorProvider* color_provider =
      element.GetDocument().GetColorProviderForPainting(color_scheme);

  WebThemeEngineHelper::GetNativeThemeEngine()->Paint(
      paint_info.context.Canvas(), WebThemeEngine::kPartTextField,
      GetWebThemeState(element), rect, &extra_params, color_scheme,
      element.GetDocument().InForcedColorsMode(), color_provider,
      GetAccentColor(style, element.GetDocument()));
  return false;
}

bool ThemePainterDefault::PaintMenuList(const Element& element,
                                        const Document& document,
                                        const ComputedStyle& style,
                                        const PaintInfo& paint_info,
                                        const gfx::Rect& rect) {
  WebThemeEngine::MenuListExtraParams menu_list;
  // Match Chromium Win behaviour of showing all borders if any are shown.
  menu_list.has_border = style.HasBorder();
  menu_list.has_border_radius = style.HasBorderRadius();
  menu_list.zoom = style.EffectiveZoom();
  // Fallback to transparent if the specified color object is invalid.
  Color background_color(Color::kTransparent);
  if (style.HasBackground()) {
    background_color =
        style.VisitedDependentColor(GetCSSPropertyBackgroundColor());
  }
  menu_list.background_color = background_color.Rgb();

  // If we have a background image, don't fill the content area to expose the
  // parent's background. Also, we shouldn't fill the content area if the
  // alpha of the color is 0. The API of Windows GDI ignores the alpha.
  // FIXME: the normal Aura theme doesn't care about this, so we should
  // investigate if we really need fillContentArea.
  menu_list.fill_content_area =
      !style.HasBackgroundImage() && !background_color.IsFullyTransparent();

  WebThemeEngine::ExtraParams extra_params(menu_list);

  SetupMenuListArrow(document, style, rect, extra_params);

  mojom::blink::ColorScheme color_scheme = style.UsedColorScheme();
  const ui::ColorProvider* color_provider =
      document.GetColorProviderForPainting(color_scheme);

  WebThemeEngineHelper::GetNativeThemeEngine()->Paint(
      paint_info.context.Canvas(), WebThemeEngine::kPartMenuList,
      GetWebThemeState(element), rect, &extra_params, color_scheme,
      document.InForcedColorsMode(), color_provider,
      GetAccentColor(style, document));
  return false;
}

bool ThemePainterDefault::PaintMenuListButton(const Element& element,
                                              const Document& document,
                                              const ComputedStyle& style,
                                              const PaintInfo& paint_info,
                                              const gfx::Rect& rect) {
  WebThemeEngine::MenuListExtraParams menu_list;
  menu_list.has_border = false;
  menu_list.has_border_radius = style.HasBorderRadius();
  menu_list.background_color = SK_ColorTRANSPARENT;
  menu_list.fill_content_area = false;
  WebThemeEngine::ExtraParams extra_params(menu_list);
  SetupMenuListArrow(document, style, rect, extra_params);
  mojom::blink::ColorScheme color_scheme = style.UsedColorScheme();
  const ui::ColorProvider* color_provider =
      document.GetColorProviderForPainting(color_scheme);

  WebThemeEngineHelper::GetNativeThemeEngine()->Paint(
      paint_info.context.Canvas(), WebThemeEngine::kPartMenuList,
      GetWebThemeState(element), rect, &extra_params, color_scheme,
      document.InForcedColorsMode(), color_provider,
      GetAccentColor(style, document));
  return false;
}

void ThemePainterDefault::SetupMenuListArrow(
    const Document& document,
    const ComputedStyle& style,
    const gfx::Rect& rect,
    WebThemeEngine::ExtraParams& extra_params) {
  auto& menu_list =
      absl::get<WebThemeEngine::MenuListExtraParams>(extra_params);
  WritingDirectionMode writing_direction = style.GetWritingDirection();
  PhysicalDirection block_end = writing_direction.BlockEnd();
  if (block_end == PhysicalDirection::kDown) {
    menu_list.arrow_direction = WebThemeEngine::ArrowDirection::kDown;
    const int left = rect.x() + floorf(style.BorderLeftWidth());
    const int right =
        rect.x() + rect.width() - floorf(style.BorderRightWidth());
    const int middle = rect.y() + rect.height() / 2;

    menu_list.arrow_y = middle;
    float arrow_box_width =
        theme_.ClampedMenuListArrowPaddingSize(document.GetFrame(), style);
    float arrow_scale_factor =
        arrow_box_width / theme_.MenuListArrowWidthInDIP();
    // TODO(tkent): This should be 7.0 to match scroll bar buttons.
    float arrow_size = 8.0 * arrow_scale_factor;
    // Put the arrow at the center of paddingForArrow area.
    // |arrow_x| is the left position for Aura theme engine.
    menu_list.arrow_x =
        (writing_direction.InlineEnd() == PhysicalDirection::kLeft)
            ? left + (arrow_box_width - arrow_size) / 2
            : right - (arrow_box_width + arrow_size) / 2;
    menu_list.arrow_size = arrow_size;
  } else {
    if (block_end == PhysicalDirection::kRight) {
      menu_list.arrow_direction = WebThemeEngine::ArrowDirection::kRight;
    } else {
      menu_list.arrow_direction = WebThemeEngine::ArrowDirection::kLeft;
    }
    const int bottom = rect.y() + floorf(style.BorderBottomWidth());
    const int top = rect.y() + rect.height() - floorf(style.BorderTopWidth());
    const int middle = rect.x() + rect.width() / 2;

    menu_list.arrow_x = middle;
    float arrow_box_height =
        theme_.ClampedMenuListArrowPaddingSize(document.GetFrame(), style);
    float arrow_scale_factor =
        arrow_box_height / theme_.MenuListArrowWidthInDIP();
    // TODO(tkent): This should be 7.0 to match scroll bar buttons.
    float arrow_size = 8.0 * arrow_scale_factor;
    // Put the arrow at the center of paddingForArrow area.
    // |arrow_y| is the bottom position for Aura theme engine.
    menu_list.arrow_y =
        (writing_direction.InlineEnd() == PhysicalDirection::kUp)
            ? bottom + (arrow_box_height - arrow_size) / 2
            : top - (arrow_box_height + arrow_size) / 2;
    menu_list.arrow_size = arrow_size;
  }

  // TODO: (https://crbug.com/1227305)This color still does not support forced
  // dark mode
  menu_list.arrow_color =
      style.VisitedDependentColor(GetCSSPropertyColor()).Rgb();
}

bool ThemePainterDefault::PaintSliderTrack(const Element& element,
                                           const LayoutObject& layout_object,
                                           const PaintInfo& paint_info,
                                           const gfx::Rect& rect,
                                           const ComputedStyle& style) {
  WebThemeEngine::SliderExtraParams slider;
  bool is_slider_vertical =
      RuntimeEnabledFeatures::
          NonStandardAppearanceValueSliderVerticalEnabled() &&
      style.EffectiveAppearance() == kSliderVerticalPart;
  const WritingMode writing_mode = style.GetWritingMode();
  bool is_writing_mode_vertical = !IsHorizontalWritingMode(writing_mode);
  slider.vertical = is_writing_mode_vertical || is_slider_vertical;
  slider.in_drag = false;

  PaintSliderTicks(layout_object, paint_info, rect);

  slider.zoom = style.EffectiveZoom();
  slider.thumb_x = 0;
  slider.thumb_y = 0;
  // If we do not allow direction support for vertical writing-mode or the
  // slider is vertical by computed appearance slider-vertical, then it should
  // behave like it has direction rtl and its value should be rendered
  // bottom-to-top.
  slider.right_to_left =
      (IsHorizontalWritingMode(writing_mode) && !is_slider_vertical) ||
              is_writing_mode_vertical
          ? !style.IsLeftToRightDirection()
          : true;
  if (writing_mode == WritingMode::kSidewaysLr) {
    slider.right_to_left = !slider.right_to_left;
  }
  if (auto* input = DynamicTo<HTMLInputElement>(element)) {
    Element* thumb_element = input->UserAgentShadowRoot()
                                 ? input->UserAgentShadowRoot()->getElementById(
                                       shadow_element_names::kIdSliderThumb)
                                 : nullptr;
    LayoutBox* thumb = thumb_element ? thumb_element->GetLayoutBox() : nullptr;
    LayoutBox* input_box = input->GetLayoutBox();
    if (thumb) {
      gfx::Rect thumb_rect = ToPixelSnappedRect(
          PhysicalRect(thumb->PhysicalLocation(), thumb->Size()));
      slider.thumb_x = thumb_rect.x() + input_box->PaddingLeft().ToInt() +
                       input_box->BorderLeft().ToInt();
      slider.thumb_y = thumb_rect.y() + input_box->PaddingTop().ToInt() +
                       input_box->BorderTop().ToInt();
    }
  }
  WebThemeEngine::ExtraParams extra_params(slider);
  mojom::blink::ColorScheme color_scheme = style.UsedColorScheme();

  // This is used for `kPartSliderTrack`, which gets drawn adjacent to
  // `accent_color`. In order to guarantee contrast between `kPartSliderTrack`
  // and `accent_color`, we choose the `color_scheme` here based on the two
  // possible color values for `kPartSliderTrack`.
  bool accent_color_affects_color_scheme =
      GetWebThemeState(element) != WebThemeEngine::kStateDisabled;
  if (accent_color_affects_color_scheme) {
    color_scheme = GetColorSchemeForAccentColor(
        element, color_scheme, GetAccentColor(style, element.GetDocument()),
        WebThemeEngine::kPartSliderTrack);
  }

  const ui::ColorProvider* color_provider =
      element.GetDocument().GetColorProviderForPainting(color_scheme);

  WebThemeEngineHelper::GetNativeThemeEngine()->Paint(
      paint_info.context.Canvas(), WebThemeEngine::kPartSliderTrack,
      GetWebThemeState(element), rect, &extra_params, color_scheme,
      element.GetDocument().InForcedColorsMode(), color_provider,
      GetAccentColor(style, element.GetDocument()));
  return false;
}

bool ThemePainterDefault::PaintSliderThumb(const Element& element,
                                           const ComputedStyle& style,
                                           const PaintInfo& paint_info,
                                           const gfx::Rect& rect) {
  WebThemeEngine::SliderExtraParams slider;
  slider.vertical = !style.IsHorizontalWritingMode() ||
                    (RuntimeEnabledFeatures::
                         NonStandardAppearanceValueSliderVerticalEnabled() &&
                     style.EffectiveAppearance() == kSliderThumbVerticalPart);
  slider.in_drag = element.IsActive();
  slider.zoom = style.EffectiveZoom();

  // The element passed in is inside the user agent shadow DOM of the input
  // element, so we have to access the parent input element in order to get the
  // accent-color style set by the page.
  const SliderThumbElement* slider_element =
      DynamicTo<SliderThumbElement>(&element);
  DCHECK(slider_element);  // PaintSliderThumb should always be passed a
                           // SliderThumbElement
  std::optional<SkColor> accent_color =
      GetAccentColor(*slider_element->HostInput()->EnsureComputedStyle(),
                     element.GetDocument());
  WebThemeEngine::ExtraParams extra_params(slider);
  mojom::blink::ColorScheme color_scheme = style.UsedColorScheme();

  // This is used for `kPartSliderThumb`, which gets drawn adjacent to
  // `accent_color`. In order to guarantee contrast between `kPartSliderThumb`
  // and `accent_color`, we choose the `color_scheme` here based on the two
  // possible color values for `kPartSliderThumb`.
  bool accent_color_affects_color_scheme =
      GetWebThemeState(element) != WebThemeEngine::kStateDisabled;
  if (accent_color_affects_color_scheme) {
    color_scheme = GetColorSchemeForAccentColor(
        element, color_scheme, GetAccentColor(style, element.GetDocument()),
        WebThemeEngine::kPartSliderThumb);
  }

  const ui::ColorProvider* color_provider =
      element.GetDocument().GetColorProviderForPainting(color_scheme);

  WebThemeEngineHelper::GetNativeThemeEngine()->Paint(
      paint_info.context.Canvas(), WebThemeEngine::kPartSliderThumb,
      GetWebThemeState(element), rect, &extra_params, color_scheme,
      element.GetDocument().InForcedColorsMode(), color_provider, accent_color);
  return false;
}

bool ThemePainterDefault::PaintInnerSpinButton(const Element& element,
                                               const ComputedStyle& style,
                                               const PaintInfo& paint_info,
                                               const gfx::Rect& rect) {
  WebThemeEngine::InnerSpinButtonExtraParams inner_spin;

  bool spin_up = false;
  if (const auto* spin_buttom = DynamicTo<SpinButtonElement>(element)) {
    if (spin_buttom->GetUpDownState() == SpinButtonElement::kUp)
      spin_up = element.IsHovered() || element.IsActive();
  }

  bool read_only = false;
  if (const auto* control = DynamicTo<HTMLFormControlElement>(element))
    read_only = control->IsReadOnly();

  inner_spin.spin_up = spin_up;
  inner_spin.read_only = read_only;
  inner_spin.spin_arrows_direction =
      style.IsHorizontalWritingMode()
          ? WebThemeEngine::SpinArrowsDirection::kUpDown
          : WebThemeEngine::SpinArrowsDirection::kLeftRight;

  WebThemeEngine::ExtraParams extra_params(inner_spin);
  mojom::blink::ColorScheme color_scheme = style.UsedColorScheme();
  const ui::ColorProvider* color_provider =
      element.GetDocument().GetColorProviderForPainting(color_scheme);

  WebThemeEngineHelper::GetNativeThemeEngine()->Paint(
      paint_info.context.Canvas(), WebThemeEngine::kPartInnerSpinButton,
      GetWebThemeState(element), rect, &extra_params, color_scheme,
      element.GetDocument().InForcedColorsMode(), color_provider,
      GetAccentColor(style, element.GetDocument()));
  return false;
}

bool ThemePainterDefault::PaintProgressBar(const Element& element,
                                           const LayoutObject& layout_object,
                                           const PaintInfo& paint_info,
                                           const gfx::Rect& rect,
                                           const ComputedStyle& style) {
  const auto* layout_progress = DynamicTo<LayoutProgress>(layout_object);
  if (!layout_progress)
    return true;

  gfx::Rect value_rect = ProgressValueRectFor(*layout_progress, rect);

  WebThemeEngine::ProgressBarExtraParams progress_bar;
  progress_bar.determinate = layout_progress->IsDeterminate();
  progress_bar.value_rect_x = value_rect.x();
  progress_bar.value_rect_y = value_rect.y();
  progress_bar.value_rect_width = value_rect.width();
  progress_bar.value_rect_height = value_rect.height();
  progress_bar.zoom = style.EffectiveZoom();
  progress_bar.is_horizontal = layout_progress->IsHorizontalWritingMode();
  WebThemeEngine::ExtraParams extra_params(progress_bar);
  DirectionFlippingScope scope(layout_object, paint_info, rect);
  mojom::blink::ColorScheme color_scheme = style.UsedColorScheme();

  // This is used for `kPartProgressBar`, which gets drawn adjacent to
  // `accent_color`. In order to guarantee contrast between `kPartProgressBar`
  // and `accent_color`, we choose the `color_scheme` here based on the two
  // possible color values for `kPartProgressBar`.
  color_scheme = GetColorSchemeForAccentColor(
      element, color_scheme, GetAccentColor(style, element.GetDocument()),
      WebThemeEngine::kPartProgressBar);

  const ui::ColorProvider* color_provider =
      element.GetDocument().GetColorProviderForPainting(color_scheme);
  WebThemeEngineHelper::GetNativeThemeEngine()->Paint(
      paint_info.context.Canvas(), WebThemeEngine::kPartProgressBar,
      GetWebThemeState(element), rect, &extra_params, color_sch
```