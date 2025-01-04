Response:
Let's break down the thought process to analyze the provided C++ code and generate the detailed explanation.

**1. Initial Understanding - What is the File About?**

The first step is to read the header comment and the namespace. This immediately tells us:

* **Location:** `blink/renderer/core/paint/text_decoration_info.cc` within the Chromium Blink rendering engine. This points to a crucial part of the rendering process, specifically related to painting.
* **Purpose:**  The name `TextDecorationInfo` strongly suggests this class is responsible for storing and calculating information about text decorations like underlines, overlines, and line-throughs.

**2. Core Class Functionality - Identifying Key Members and Methods:**

Next, I'd scan the class definition (`class TextDecorationInfo`) and its members and methods. I'd look for:

* **Constructor:** How is this object created?  What information is passed in? The constructor takes a significant number of arguments, including styling information, paint context, and decoration overrides. This hints at the complexity of text decoration.
* **Member Variables:** What data does the class hold?  I'd pay attention to variables like `target_style_`, `inline_context_`, `selection_decoration_line_`, `resolved_thickness_`, `has_underline_`, `has_overline_`, etc. These variables represent the core attributes of the text decoration.
* **Key Methods:** What are the important actions the class performs? Methods like `ComputeThickness()`, `SetLineData()`, `SetUnderlineLineData()`, `SetOverlineLineData()`, `ComputeWavyLineData()`, and `Bounds()` stand out. These methods calculate the visual properties of the decorations.

**3. Connecting to Web Technologies (HTML, CSS, JavaScript):**

This is where the "why" of the code becomes important. I'd consider how the properties and calculations in this class relate to web standards:

* **CSS Text Decoration Properties:**  Keywords like `text-decoration-line`, `text-decoration-style`, `text-decoration-color`, and `text-underline-position` are direct connections. I'd look for code that seems to be handling these properties. For example, the `ResolveUnderlinePosition()` function directly relates to the `text-underline-position` CSS property.
* **CSS Styling and Inheritance:**  The fact that the class takes `ComputedStyle` as input highlights the importance of CSS cascading and inheritance in determining the final appearance of text decorations.
* **JavaScript Interaction (Less Direct):** While not directly interacting with JavaScript, this code is part of the rendering pipeline that executes after the browser has parsed HTML, CSS, and potentially executed JavaScript that modifies the DOM and styles.

**4. Logical Reasoning and Input/Output:**

To understand the logic, I'd pick specific methods and think about their inputs and outputs. For example:

* **`ComputeThickness()`:** Input: `TextDecorationThickness` from CSS, font size, potentially font metrics. Output: A pixel value for the decoration thickness.
* **`SetUnderlineLineData()`:** Input: `TextDecorationOffset`, styling information. Output:  Updates internal `line_data_` with the calculated offset for the underline.
* **`ComputeWavyLineData()`:** Input: Decoration thickness, zoom level, color. Output: Calculates the path and tile information for a wavy underline.

I would mentally trace the flow of data through these methods, considering different CSS property values and their effects.

**5. Identifying Potential User/Programming Errors:**

Based on my understanding of the code and web standards, I'd consider common mistakes:

* **Incorrect CSS Syntax:** Although the C++ code doesn't *validate* CSS, it *reacts* to it. I'd think about how invalid CSS might affect the rendering process (often defaulting to standard behavior).
* **Conflicting CSS Properties:**  What happens if `text-decoration-line` and `text-decoration-style` are inconsistent? The code seems to handle different combinations, but some might lead to unexpected visual results.
* **Font Loading Issues:** The code relies on font metrics. If a font fails to load, the decorations might not be rendered correctly.

**6. Debugging and User Steps:**

To connect the code to user actions, I'd think about the typical web browsing workflow:

1. **User types in a URL or clicks a link.**
2. **Browser requests HTML, CSS, and JavaScript.**
3. **Parsing:** The browser parses these resources.
4. **Layout:** The browser calculates the layout of the page.
5. **Painting:** This is where `TextDecorationInfo` comes in. The rendering engine iterates through elements and their styles, creating `TextDecorationInfo` objects to handle the drawing of decorations.

For debugging, I'd imagine a scenario:

* **Problem:** A wavy underline is not appearing correctly.
* **Debugging Steps:**
    * **Inspect the element in the browser's DevTools:** Check the computed styles for `text-decoration-line`, `text-decoration-style`, `text-decoration-color`, and `text-underline-offset`.
    * **Look for JavaScript that might be modifying styles.**
    * **If necessary, dive into the Chromium source code:**  Set breakpoints in `TextDecorationInfo.cc` (or related painting code) to observe the values being calculated.

**7. Structuring the Explanation:**

Finally, I'd organize the information in a clear and logical manner, using headings, bullet points, and code examples. I'd start with a high-level overview and then delve into the specifics, making sure to connect the code back to the original request's prompts about JavaScript, HTML, CSS, logical reasoning, and debugging. The goal is to make the explanation understandable to someone who might not be deeply familiar with the Chromium rendering engine but has a basic understanding of web technologies.

By following these steps, I can systematically analyze the code and generate a comprehensive and informative explanation.
这个C++源代码文件 `text_decoration_info.cc` 属于 Chromium Blink 渲染引擎的一部分，它的主要功能是**管理和计算关于文本装饰（例如下划线、上划线、删除线以及拼写/语法错误标记）的各种信息，以便在屏幕上正确绘制这些装饰**。

以下是该文件的详细功能分解和与 Web 技术的关系：

**1. 功能概述:**

* **存储文本装饰相关属性:**  `TextDecorationInfo` 类会存储与特定文本片段相关的文本装饰样式信息，包括：
    * 装饰线类型 (`text-decoration-line`): 下划线、上划线、删除线。
    * 装饰样式 (`text-decoration-style`): 实线、双线、虚线、点线、波浪线。
    * 装饰颜色 (`text-decoration-color`).
    * 装饰粗细 (`text-decoration-thickness`).
    * 装饰偏移量 (`text-underline-offset`).
    * 是否是拼写或语法错误标记。
* **计算装饰线的位置和粗细:**  根据 CSS 样式、字体信息等计算装饰线在垂直方向上的偏移量和粗细。这涉及到考虑 `text-underline-position` 属性以及字体本身的指标。
* **处理波浪线装饰:** 特别处理波浪线装饰，生成用于绘制波浪的路径和 tile 信息。
* **处理虚线和点线装饰:**  生成用于绘制虚线和点线的路径信息。
* **考虑选择状态:** 能够处理文本被选中时的装饰样式，例如使用不同的颜色。
* **使用装饰盒 (Decorating Box):**  在某些情况下（例如非垂直书写模式），会使用一个“装饰盒”的概念来辅助计算装饰线的位置，尤其是在处理复杂的排版布局时。
* **缓存计算结果:**  为了性能优化，会缓存一些计算结果，例如波浪线的 tile 信息。

**2. 与 JavaScript, HTML, CSS 的关系及举例说明:**

该文件是渲染引擎内部实现的一部分，直接响应 CSS 样式的影响，并最终体现在用户看到的 HTML 内容的渲染结果上。

* **CSS 的 `text-decoration-line` 属性:**
    * **功能关系:**  `TextDecorationInfo` 会根据 `text-decoration-line` 的值（`underline`, `overline`, `line-through`, `none`）来决定是否以及如何绘制相应的装饰线。
    * **举例说明:**  如果 CSS 中设置了 `text-decoration-line: underline;`，那么 `TextDecorationInfo` 对象会知道需要绘制下划线。

* **CSS 的 `text-decoration-style` 属性:**
    * **功能关系:**  `TextDecorationInfo` 会根据 `text-decoration-style` 的值（`solid`, `double`, `dotted`, `dashed`, `wavy`）来选择不同的绘制方式。例如，如果是 `dotted`，则会生成点线的路径。
    * **举例说明:**  `text-decoration-style: wavy;` 会触发 `ComputeWavyLineData` 函数，生成绘制波浪线的路径和 tile 信息。

* **CSS 的 `text-decoration-color` 属性:**
    * **功能关系:**  `TextDecorationInfo` 会读取 `text-decoration-color` 的值，并将其用于装饰线的颜色。
    * **举例说明:**  `text-decoration-color: red;` 会使下划线、上划线或删除线以红色绘制。

* **CSS 的 `text-decoration-thickness` 属性:**
    * **功能关系:**  `TextDecorationInfo` 中的 `ComputeThickness` 函数会根据 `text-decoration-thickness` 的值（`auto`, `from-font`, 或具体的长度值）计算装饰线的粗细。
    * **举例说明:**  `text-decoration-thickness: 3px;` 会使装饰线的粗细为 3 像素。`text-decoration-thickness: from-font;` 会尝试使用字体本身定义的下划线粗细。

* **CSS 的 `text-underline-position` 属性:**
    * **功能关系:**  `ResolveUnderlinePosition` 函数会解析 `text-underline-position` 的值，决定下划线相对于文字基线的位置。这会影响下划线是绘制在文字下方还是穿过文字。
    * **举例说明:**  `text-underline-position: under;` 会强制下划线绘制在文字下方，避免与文字的下行部分重叠。

* **拼写和语法错误标记:**
    * **功能关系:**  该文件还处理拼写和语法错误标记的绘制，通常表现为特殊的下划线（例如，macOS 上的点线，其他平台上的波浪线）。
    * **举例说明:**  当浏览器检测到拼写错误时，会生成相应的装饰信息，`TextDecorationInfo` 会根据平台设置绘制相应的标记。

* **JavaScript 的 DOM 操作和样式修改:**
    * **功能关系:**  虽然 `TextDecorationInfo` 本身是 C++ 代码，但 JavaScript 可以通过 DOM API 修改元素的样式，包括文本装饰相关的 CSS 属性。这些修改最终会反映到 `TextDecorationInfo` 对象中的数据，从而影响渲染结果。
    * **举例说明:**  JavaScript 可以使用 `element.style.textDecorationLine = 'overline';` 来动态地给元素添加上划线。

* **HTML 结构:**
    * **功能关系:**  HTML 结构定义了文本内容，而 CSS 样式应用于这些内容。`TextDecorationInfo` 处理的是特定文本片段的装饰，因此它与 HTML 结构是间接相关的。它会根据应用于特定 HTML 元素的 CSS 样式来工作。

**3. 逻辑推理、假设输入与输出:**

假设我们有一个 `<span>` 元素，其 CSS 样式如下：

```css
span {
  text-decoration-line: underline wavy;
  text-decoration-style: wavy;
  text-decoration-color: blue;
  text-decoration-thickness: 2px;
}
```

并且该 `<span>` 元素包含文本 "Hello"。

* **假设输入:**
    * `target_style_`:  包含了上述 CSS 属性的 `ComputedStyle` 对象。
    * `local_origin_`:  该文本片段在容器中的起始坐标。
    * `width_`:  文本 "Hello" 的宽度。
* **逻辑推理:**
    * `TextDecorationInfo` 会识别出 `text-decoration-line` 包含了 `underline` 和 `wavy` (尽管 `text-decoration-style` 也是 `wavy`，但 `text-decoration-line` 的优先级更高)。
    * `ComputeThickness` 会计算出波浪线的粗细为 2px。
    * `ComputeWavyLineData` 会根据粗细、颜色 (蓝色) 等参数生成用于绘制蓝色波浪下划线的路径和 tile 信息。
    * `SetUnderlineLineData` 会计算出下划线的垂直偏移量。
* **预期输出:**
    * 在屏幕上，"Hello" 这个词下方会绘制一条蓝色、粗细为 2 像素的波浪线。

**4. 用户或编程常见的使用错误:**

* **CSS 语法错误:**  如果 CSS 中文本装饰属性的值拼写错误或者格式不正确，浏览器可能无法正确解析，导致装饰效果不生效或者使用默认样式。例如，`text-decoration-line: under-line;` 是错误的。
* **属性冲突:**  同时设置了相互冲突的文本装饰属性可能导致意想不到的结果。例如，同时设置 `text-decoration-line: none;` 和 `text-decoration-line: underline;`，前者会覆盖后者。
* **忘记设置颜色:**  如果只设置了 `text-decoration-line` 和 `text-decoration-style`，但没有设置 `text-decoration-color`，装饰线可能会使用默认的文本颜色，这在某些情况下可能看不清楚。
* **误解 `text-underline-position` 的作用:**  不理解 `text-underline-position` 可能会导致下划线的位置不符合预期，例如穿过文字。
* **JavaScript 操作错误:**  在使用 JavaScript 动态修改文本装饰样式时，如果属性名拼写错误或者赋值类型不匹配，可能不会生效。

**5. 用户操作如何一步步到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页 (HTML 文件)。**
2. **浏览器解析 HTML 结构，构建 DOM 树。**
3. **浏览器解析 CSS 样式表，包括外部 CSS 文件、`<style>` 标签内的 CSS 和内联样式。**
4. **浏览器将 CSS 样式应用于 DOM 树，生成渲染树 (Render Tree)。** 渲染树包含了需要绘制到屏幕上的元素以及它们的样式信息 (ComputedStyle)。
5. **对于渲染树中的每个文本节点，渲染引擎会创建 `TextDecorationInfo` 对象。**  在创建 `TextDecorationInfo` 对象时，会传入该文本节点对应的 `ComputedStyle` 对象，其中包含了文本装饰相关的 CSS 属性。
6. **在绘制阶段，渲染引擎会调用 `TextDecorationInfo` 对象的方法来获取装饰线的位置、粗细、样式等信息。**
7. **渲染引擎使用这些信息调用底层的图形库 (例如 Skia) 来绘制文本装饰。**

**调试线索:**

* **检查元素的 Computed Style:**  使用浏览器的开发者工具 (Elements 面板 -> Computed 标签) 可以查看元素最终生效的 CSS 样式，包括文本装饰相关的属性。这可以帮助确认 CSS 样式是否正确应用。
* **查看 Layout Tree 或 Render Tree:**  在 Chromium 的开发者工具中 (需要开启某些 flags)，可以查看 Layout Tree 或 Render Tree，了解元素的布局和渲染信息。这可以帮助理解文本装饰是如何布局的。
* **设置断点:**  对于 Chromium 开发人员，可以在 `text_decoration_info.cc` 文件中的关键函数 (例如 `ComputeThickness`, `ComputeWavyLineData`, `SetLineData`) 设置断点，观察程序执行流程和变量的值，以定位问题所在。
* **使用 `//ui/gfx/debug/` 工具:** Chromium 提供了一些图形调试工具，可以帮助分析绘制过程，查看绘制调用的参数。

总而言之，`text_decoration_info.cc` 是 Blink 渲染引擎中负责处理文本装饰的核心组件，它连接了 CSS 样式和最终的屏幕渲染，确保文本装饰能够按照预期的方式显示给用户。理解这个文件的功能有助于理解浏览器如何处理网页上的文本样式。

Prompt: 
```
这是目录为blink/renderer/core/paint/text_decoration_info.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/text_decoration_info.h"

#include <math.h>

#include "build/build_config.h"
#include "third_party/blink/renderer/core/layout/text_decoration_offset.h"
#include "third_party/blink/renderer/core/paint/decoration_line_painter.h"
#include "third_party/blink/renderer/core/paint/inline_paint_context.h"
#include "third_party/blink/renderer/core/paint/text_paint_style.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/stroke_data.h"
#include "third_party/blink/renderer/platform/graphics/styled_stroke_data.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {

inline float GetAscent(const ComputedStyle& style, const Font* font_override) {
  const Font& font = font_override ? *font_override : style.GetFont();
  if (const SimpleFontData* primary_font = font.PrimaryFont())
    return primary_font->GetFontMetrics().FloatAscent();
  return 0.f;
}

static ResolvedUnderlinePosition ResolveUnderlinePosition(
    const ComputedStyle& style) {
  const TextUnderlinePosition position = style.GetTextUnderlinePosition();

  // |auto| should resolve to |under| to avoid drawing through glyphs in
  // scripts where it would not be appropriate (e.g., ideographs.)
  // However, this has performance implications. For now, we only work with
  // vertical text.
  if (style.GetFontBaseline() != kCentralBaseline) {
    if (EnumHasFlags(position, TextUnderlinePosition::kUnder)) {
      return ResolvedUnderlinePosition::kUnder;
    }
    if (EnumHasFlags(position, TextUnderlinePosition::kFromFont)) {
      return ResolvedUnderlinePosition::kNearAlphabeticBaselineFromFont;
    }
    return ResolvedUnderlinePosition::kNearAlphabeticBaselineAuto;
  }
  // Compute language-appropriate default underline position.
  // https://drafts.csswg.org/css-text-decor-3/#default-stylesheet
  UScriptCode script = style.GetFontDescription().GetScript();
  if (script == USCRIPT_KATAKANA_OR_HIRAGANA || script == USCRIPT_HANGUL) {
    if (EnumHasFlags(position, TextUnderlinePosition::kLeft)) {
      return ResolvedUnderlinePosition::kUnder;
    }
    return ResolvedUnderlinePosition::kOver;
  }
  if (EnumHasFlags(position, TextUnderlinePosition::kRight)) {
    return ResolvedUnderlinePosition::kOver;
  }
  return ResolvedUnderlinePosition::kUnder;
}

inline bool ShouldUseDecoratingBox(const ComputedStyle& style) {
  // Disable the decorating box for styles not in the tree, because they can't
  // find the decorating box. For example, |HighlightPainter| creates a
  // |kPseudoIdHighlight| pseudo style on the fly.
  const PseudoId pseudo_id = style.StyleType();
  if (IsHighlightPseudoElement(pseudo_id))
    return false;
  return true;
}

static float ComputeDecorationThickness(
    const TextDecorationThickness text_decoration_thickness,
    float computed_font_size,
    float minimum_thickness,
    const SimpleFontData* font_data) {
  float auto_underline_thickness =
      std::max(minimum_thickness, computed_font_size / 10.f);

  if (text_decoration_thickness.IsAuto())
    return auto_underline_thickness;

  // In principle we would not need to test for font_data if
  // |text_decoration_thickness.Thickness()| is fixed, but a null font_data here
  // would be a rare / error situation anyway, so practically, we can
  // early out here.
  if (!font_data)
    return auto_underline_thickness;

  if (text_decoration_thickness.IsFromFont()) {
    std::optional<float> font_underline_thickness =
        font_data->GetFontMetrics().UnderlineThickness();

    if (!font_underline_thickness)
      return auto_underline_thickness;

    return std::max(minimum_thickness, font_underline_thickness.value());
  }

  DCHECK(!text_decoration_thickness.IsFromFont());

  const Length& thickness_length = text_decoration_thickness.Thickness();
  float text_decoration_thickness_pixels =
      FloatValueForLength(thickness_length, computed_font_size);

  return std::max(minimum_thickness, roundf(text_decoration_thickness_pixels));
}

static enum StrokeStyle TextDecorationStyleToStrokeStyle(
    ETextDecorationStyle decoration_style) {
  enum StrokeStyle stroke_style = kSolidStroke;
  switch (decoration_style) {
    case ETextDecorationStyle::kSolid:
      stroke_style = kSolidStroke;
      break;
    case ETextDecorationStyle::kDouble:
      stroke_style = kDoubleStroke;
      break;
    case ETextDecorationStyle::kDotted:
      stroke_style = kDottedStroke;
      break;
    case ETextDecorationStyle::kDashed:
      stroke_style = kDashedStroke;
      break;
    case ETextDecorationStyle::kWavy:
      stroke_style = kWavyStroke;
      break;
  }

  return stroke_style;
}

struct WavyParams {
  float resolved_thickness;
  float effective_zoom;
  bool spelling_grammar;
  Color color;
  DISALLOW_NEW();
};

float WavyControlPointDistance(const WavyParams& params) {
  // Distance between decoration's axis and Bezier curve's control points. The
  // height of the curve is based on this distance. Increases the curve's height
  // as strokeThickness increases to make the curve look better.
  if (params.spelling_grammar)
    return 5 * params.effective_zoom;

  // Setting the distance to half-pixel values gives better antialiasing
  // results, particularly for small values.
  return 0.5 + roundf(3 * std::max<float>(1, params.resolved_thickness) + 0.5);
}

float WavyStep(const WavyParams& params) {
  // Increment used to form the diamond shape between start point (p1), control
  // points and end point (p2) along the axis of the decoration. Makes the curve
  // wider as strokeThickness increases to make the curve look better.
  if (params.spelling_grammar)
    return 3 * params.effective_zoom;

  // Setting the step to half-pixel values gives better antialiasing
  // results, particularly for small values.
  return 0.5 + roundf(2 * std::max<float>(1, params.resolved_thickness) + 0.5);
}

// Computes the wavy pattern rect, which is where the desired wavy pattern would
// be found when painting the wavy stroke path at the origin, or in other words,
// how far PrepareWavyTileRecord needs to translate in the opposite direction
// when painting to ensure that nothing is painted at y<0.
gfx::RectF ComputeWavyPatternRect(const WavyParams& params,
                                  const Path& stroke_path) {
  StrokeData stroke_data;
  stroke_data.SetThickness(params.resolved_thickness);

  // Expand the stroke rect to integer y coordinates in both directions, to
  // avoid messing with the vertical antialiasing.
  gfx::RectF stroke_rect = stroke_path.StrokeBoundingRect(stroke_data);
  float top = floorf(stroke_rect.y());
  float bottom = ceilf(stroke_rect.bottom());
  return {0.f, top, 2.f * WavyStep(params), bottom - top};
}

// Prepares a path for a cubic Bezier curve repeated three times, yielding a
// wavy pattern that we can cut into a tiling shader (PrepareWavyTileRecord).
//
// The result ignores the local origin, line offset, and (wavy) double offset,
// so the midpoints are always at y=0.5, while the phase is shifted for either
// wavy or spelling/grammar decorations so the desired pattern starts at x=0.
//
// The start point, control points (cp1 and cp2), and end point of each curve
// form a diamond shape:
//
//            cp2                      cp2                      cp2
// ---         +                        +                        +
// |               x=0
// | control         |--- spelling/grammar ---|
// | point          . .                      . .                      . .
// | distance     .     .                  .     .                  .     .
// |            .         .              .         .              .         .
// +-- y=0.5   .            +           .            +           .            +
//  .         .              .         .              .         .
//    .     .                  .     .                  .     .
//      . .                      . .                      . .
//                          |-------- other ---------|
//                        x=0
//             +                        +                        +
//            cp1                      cp1                      cp1
// |-----------|------------|
//     step         step
Path PrepareWavyStrokePath(const WavyParams& params) {
  float control_point_distance = WavyControlPointDistance(params);
  float step = WavyStep(params);

  // We paint the wave before and after the text line (to cover the whole length
  // of the line) and then we clip it at
  // AppliedDecorationPainter::StrokeWavyTextDecoration().
  // Offset the start point, so the bezier curve starts before the current line,
  // that way we can clip it exactly the same way in both ends.
  // For spelling and grammar errors we offset by half a step less, to get a
  // result closer to Microsoft Word circa 2021.
  float phase_shift = (params.spelling_grammar ? -1.5f : -2.f) * step;

  // Midpoints at y=0.5, to reduce vertical antialiasing.
  gfx::PointF start{phase_shift, 0.5f};
  gfx::PointF end{start + gfx::Vector2dF(2.f * step, 0.0f)};
  gfx::PointF cp1{start + gfx::Vector2dF(step, +control_point_distance)};
  gfx::PointF cp2{start + gfx::Vector2dF(step, -control_point_distance)};

  Path result{};
  result.MoveTo(start);

  result.AddBezierCurveTo(cp1, cp2, end);
  cp1.set_x(cp1.x() + 2.f * step);
  cp2.set_x(cp2.x() + 2.f * step);
  end.set_x(end.x() + 2.f * step);
  result.AddBezierCurveTo(cp1, cp2, end);
  cp1.set_x(cp1.x() + 2.f * step);
  cp2.set_x(cp2.x() + 2.f * step);
  end.set_x(end.x() + 2.f * step);
  result.AddBezierCurveTo(cp1, cp2, end);

  return result;
}

cc::PaintRecord PrepareWavyTileRecord(const WavyParams& params,
                                      const Path& stroke_path,
                                      const gfx::RectF& pattern_rect) {
  cc::PaintFlags flags;
  flags.setAntiAlias(true);
  flags.setColor(params.color.Rgb());
  flags.setStyle(cc::PaintFlags::kStroke_Style);
  flags.setStrokeWidth(params.resolved_thickness);

  PaintRecorder recorder;
  cc::PaintCanvas* canvas = recorder.beginRecording();

  // Translate the wavy pattern so that nothing is painted at y<0.
  canvas->translate(-pattern_rect.x(), -pattern_rect.y());
  canvas->drawPath(stroke_path.GetSkPath(), flags);

  return recorder.finishRecordingAsPicture();
}

}  // anonymous namespace

TextDecorationInfo::TextDecorationInfo(
    LineRelativeOffset local_origin,
    LayoutUnit width,
    const ComputedStyle& target_style,
    const InlinePaintContext* inline_context,
    const TextDecorationLine selection_decoration_line,
    const Color selection_decoration_color,
    const AppliedTextDecoration* decoration_override,
    const Font* font_override,
    MinimumThickness1 minimum_thickness1,
    float scaling_factor)
    : target_style_(target_style),
      inline_context_(inline_context),
      selection_decoration_line_(selection_decoration_line),
      selection_decoration_color_(selection_decoration_color),
      decoration_override_(decoration_override),
      font_override_(font_override && font_override != &target_style.GetFont()
                         ? font_override
                         : nullptr),
      local_origin_(local_origin),
      width_(width),
      target_ascent_(GetAscent(target_style, font_override)),
      scaling_factor_(scaling_factor),
      use_decorating_box_(inline_context && !decoration_override_ &&
                          !font_override_ &&
                          ShouldUseDecoratingBox(target_style)),
      minimum_thickness_is_one_(minimum_thickness1) {
  for (wtf_size_t i = 0; i < AppliedDecorationCount(); i++)
    union_all_lines_ |= AppliedDecoration(i).Lines();
  for (wtf_size_t i = 0; i < AppliedDecorationCount(); i++) {
    if (AppliedDecoration(i).Style() == ETextDecorationStyle::kDotted ||
        AppliedDecoration(i).Style() == ETextDecorationStyle::kDashed) {
      antialias_ = true;
      break;
    }
  }

  UpdateForDecorationIndex();
}

wtf_size_t TextDecorationInfo::AppliedDecorationCount() const {
  if (HasDecorationOverride())
    return 1;
  return target_style_.AppliedTextDecorations().size();
}

const AppliedTextDecoration& TextDecorationInfo::AppliedDecoration(
    wtf_size_t index) const {
  if (HasDecorationOverride())
    return *decoration_override_;
  return target_style_.AppliedTextDecorations()[index];
}

void TextDecorationInfo::SetDecorationIndex(int decoration_index) {
  DCHECK_LT(decoration_index, static_cast<int>(AppliedDecorationCount()));
  if (decoration_index_ == decoration_index)
    return;
  decoration_index_ = decoration_index;
  UpdateForDecorationIndex();
}

// Update cached properties of |this| for the |decoration_index_|.
void TextDecorationInfo::UpdateForDecorationIndex() {
  DCHECK_LT(decoration_index_, static_cast<int>(AppliedDecorationCount()));
  applied_text_decoration_ = &AppliedDecoration(decoration_index_);
  lines_ = applied_text_decoration_->Lines();
  has_underline_ = EnumHasFlags(lines_, TextDecorationLine::kUnderline);
  has_overline_ = EnumHasFlags(lines_, TextDecorationLine::kOverline);

  // Compute the |ComputedStyle| of the decorating box.
  const ComputedStyle* decorating_box_style;
  if (use_decorating_box_) {
    DCHECK(inline_context_);
    DCHECK_EQ(inline_context_->DecoratingBoxes().size(),
              AppliedDecorationCount());
    decorating_box_ = &inline_context_->DecoratingBoxes()[decoration_index_];
    decorating_box_style = &decorating_box_->Style();

    // Disable the decorating box when the baseline is central, because the
    // decorating box doesn't produce the ideal position.
    // https://drafts.csswg.org/css-text-decor-3/#:~:text=text%20is%20not%20aligned%20to%20the%20alphabetic%20baseline
    // TODO(kojii): The vertical flow in alphabetic baseline may want to use the
    // decorating box. It needs supporting the rotated coordinate system text
    // painters use when painting vertical text.
    if (!decorating_box_style->IsHorizontalWritingMode()) [[unlikely]] {
      use_decorating_box_ = false;
      decorating_box_ = nullptr;
      decorating_box_style = &target_style_;
    }
  } else {
    DCHECK(!decorating_box_);
    decorating_box_style = &target_style_;
  }
  DCHECK(decorating_box_style);
  if (decorating_box_style != decorating_box_style_) {
    decorating_box_style_ = decorating_box_style;
    original_underline_position_ =
        ResolveUnderlinePosition(*decorating_box_style);

    // text-underline-position may flip underline and overline.
    flip_underline_and_overline_ =
        original_underline_position_ == ResolvedUnderlinePosition::kOver;
  }

  if (flip_underline_and_overline_) [[unlikely]] {
    flipped_underline_position_ = ResolvedUnderlinePosition::kUnder;
    std::swap(has_underline_, has_overline_);
  } else {
    flipped_underline_position_ = original_underline_position_;
  }

  // Compute the |Font| and its properties.
  const Font* font =
      font_override_ ? font_override_ : &decorating_box_style_->GetFont();
  DCHECK(font);
  if (font != font_) {
    font_ = font;
    computed_font_size_ = font->GetFontDescription().ComputedSize();

    const SimpleFontData* font_data = font->PrimaryFont();
    if (font_data != font_data_) {
      font_data_ = font_data;
      ascent_ = font_data ? font_data->GetFontMetrics().FloatAscent() : 0;
    }
  }

  resolved_thickness_ = ComputeThickness();
}

void TextDecorationInfo::SetLineData(TextDecorationLine line,
                                     float line_offset) {
  const float double_offset_from_thickness = ResolvedThickness() + 1.0f;
  float double_offset;
  int wavy_offset_factor;
  switch (line) {
    case TextDecorationLine::kUnderline:
    case TextDecorationLine::kSpellingError:
    case TextDecorationLine::kGrammarError:
      double_offset = double_offset_from_thickness;
      wavy_offset_factor = 1;
      break;
    case TextDecorationLine::kOverline:
      double_offset = -double_offset_from_thickness;
      wavy_offset_factor = 1;
      break;
    case TextDecorationLine::kLineThrough:
      // Floor double_offset in order to avoid double-line gap to appear
      // of different size depending on position where the double line
      // is drawn because of rounding downstream in
      // GraphicsContext::DrawLineForText.
      double_offset = floorf(double_offset_from_thickness);
      wavy_offset_factor = 0;
      break;
    default:
      NOTREACHED();
  }

  line_data_.line = line;
  line_data_.line_offset = line_offset;
  line_data_.double_offset = double_offset;
  line_data_.wavy_offset_factor = wavy_offset_factor;

  switch (DecorationStyle()) {
    case ETextDecorationStyle::kDotted:
    case ETextDecorationStyle::kDashed:
      line_data_.stroke_path = PrepareDottedOrDashedStrokePath();
      line_data_.wavy_tile_record = cc::PaintRecord();
      break;
    case ETextDecorationStyle::kWavy:
      line_data_.stroke_path.reset();
      ComputeWavyLineData(line_data_.wavy_pattern_rect,
                          line_data_.wavy_tile_record);
      break;
    default:
      line_data_.stroke_path.reset();
      line_data_.wavy_tile_record = cc::PaintRecord();
  }
}

// Returns the offset of the target text/box (|local_origin_|) from the
// decorating box.
LayoutUnit TextDecorationInfo::OffsetFromDecoratingBox() const {
  DCHECK(use_decorating_box_);
  DCHECK(inline_context_);
  DCHECK(decorating_box_);
  // Compute the paint offset of the decorating box. The |local_origin_| is
  // already adjusted to the paint offset.
  const LayoutUnit decorating_box_paint_offset =
      decorating_box_->ContentOffsetInContainer().top +
      inline_context_->PaintOffset().top;
  return decorating_box_paint_offset - local_origin_.line_over;
}

void TextDecorationInfo::SetUnderlineLineData(
    const TextDecorationOffset& decoration_offset) {
  DCHECK(HasUnderline());
  // Don't apply text-underline-offset to overlines. |line_offset| is zero.
  Length line_offset;
  if (flip_underline_and_overline_) [[unlikely]] {
    line_offset = Length();
  } else {
    line_offset = applied_text_decoration_->UnderlineOffset();
  }
  float paint_underline_offset = decoration_offset.ComputeUnderlineOffset(
      FlippedUnderlinePosition(), ComputedFontSize(), FontData(), line_offset,
      ResolvedThickness());
  if (use_decorating_box_) {
    // The offset is for the decorating box. Convert it for the target text/box.
    paint_underline_offset += OffsetFromDecoratingBox();
  }
  SetLineData(TextDecorationLine::kUnderline, paint_underline_offset);
}

void TextDecorationInfo::SetOverlineLineData(
    const TextDecorationOffset& decoration_offset) {
  DCHECK(HasOverline());
  // Don't apply text-underline-offset to overline.
  Length line_offset;
  FontVerticalPositionType position;
  if (flip_underline_and_overline_) [[unlikely]] {
    line_offset = applied_text_decoration_->UnderlineOffset();
    position = FontVerticalPositionType::TopOfEmHeight;
  } else {
    line_offset = Length();
    position = FontVerticalPositionType::TextTop;
  }
  const int paint_overline_offset =
      decoration_offset.ComputeUnderlineOffsetForUnder(
          line_offset, TargetStyle().ComputedFontSize(), FontData(),
          ResolvedThickness(), position);
  SetLineData(TextDecorationLine::kOverline, paint_overline_offset);
}

void TextDecorationInfo::SetLineThroughLineData() {
  DCHECK(HasLineThrough());
  // For increased line thickness, the line-through decoration needs to grow
  // in both directions from its origin, subtract half the thickness to keep
  // it centered at the same origin.
  const float line_through_offset = 2 * Ascent() / 3 - ResolvedThickness() / 2;
  SetLineData(TextDecorationLine::kLineThrough, line_through_offset);
}

void TextDecorationInfo::SetSpellingOrGrammarErrorLineData(
    const TextDecorationOffset& decoration_offset) {
  DCHECK(HasSpellingOrGrammerError());
  DCHECK(!HasUnderline());
  DCHECK(!HasOverline());
  DCHECK(!HasLineThrough());
  DCHECK(applied_text_decoration_);
  const int paint_underline_offset = decoration_offset.ComputeUnderlineOffset(
      FlippedUnderlinePosition(), TargetStyle().ComputedFontSize(), FontData(),
      Length(), ResolvedThickness());
  SetLineData(HasSpellingError() ? TextDecorationLine::kSpellingError
                                 : TextDecorationLine::kGrammarError,
              paint_underline_offset);
}

bool TextDecorationInfo::ShouldAntialias() const {
#if BUILDFLAG(IS_APPLE)
  if (line_data_.line == TextDecorationLine::kSpellingError ||
      line_data_.line == TextDecorationLine::kGrammarError) {
    return true;
  }
#endif
  return antialias_;
}

ETextDecorationStyle TextDecorationInfo::DecorationStyle() const {
  if (IsSpellingOrGrammarError()) {
#if BUILDFLAG(IS_APPLE)
    return ETextDecorationStyle::kDotted;
#else
    return ETextDecorationStyle::kWavy;
#endif
  }

  DCHECK(applied_text_decoration_);
  return applied_text_decoration_->Style();
}

Color TextDecorationInfo::LineColor() const {
  if (HasSpellingError()) {
    return LayoutTheme::GetTheme().PlatformSpellingMarkerUnderlineColor();
  }
  if (HasGrammarError()) {
    return LayoutTheme::GetTheme().PlatformGrammarMarkerUnderlineColor();
  }

  if (highlight_override_)
    return *highlight_override_;

  // Find the matched normal and selection |AppliedTextDecoration|
  // and use the text-decoration-color from selection when it is.
  DCHECK(applied_text_decoration_);
  if (applied_text_decoration_->Lines() == selection_decoration_line_) {
    return selection_decoration_color_;
  }

  return applied_text_decoration_->GetColor();
}

gfx::PointF TextDecorationInfo::StartPoint() const {
  return gfx::PointF(local_origin_) + gfx::Vector2dF(0, line_data_.line_offset);
}
float TextDecorationInfo::DoubleOffset() const {
  return line_data_.double_offset;
}

enum StrokeStyle TextDecorationInfo::StrokeStyle() const {
  return TextDecorationStyleToStrokeStyle(DecorationStyle());
}

float TextDecorationInfo::ComputeThickness() const {
  DCHECK(applied_text_decoration_);
  const AppliedTextDecoration& decoration = *applied_text_decoration_;
  if (HasSpellingOrGrammerError()) {
    // Spelling and grammar error thickness doesn't depend on the font size.
#if BUILDFLAG(IS_APPLE)
    return 2.f * decorating_box_style_->EffectiveZoom();
#else
    return 1.f * decorating_box_style_->EffectiveZoom();
#endif
  }
  return ComputeUnderlineThickness(decoration.Thickness(),
                                   decorating_box_style_);
}

float TextDecorationInfo::ComputeUnderlineThickness(
    const TextDecorationThickness& applied_decoration_thickness,
    const ComputedStyle* decorating_box_style) const {
  const float minimum_thickness = minimum_thickness_is_one_ ? 1.0f : 0.0f;
  float thickness = 0;
  if (flipped_underline_position_ ==
          ResolvedUnderlinePosition::kNearAlphabeticBaselineAuto ||
      flipped_underline_position_ ==
          ResolvedUnderlinePosition::kNearAlphabeticBaselineFromFont) {
    thickness = ComputeDecorationThickness(applied_decoration_thickness,
                                           computed_font_size_,
                                           minimum_thickness, font_data_);
  } else {
    // Compute decorating box. Position and thickness are computed from the
    // decorating box.
    // Only for non-Roman for now for the performance implications.
    // https:// drafts.csswg.org/css-text-decor-3/#decorating-box
    if (decorating_box_style) {
      thickness = ComputeDecorationThickness(
          applied_decoration_thickness,
          decorating_box_style->ComputedFontSize(), minimum_thickness,
          decorating_box_style->GetFont().PrimaryFont());
    } else {
      thickness = ComputeDecorationThickness(applied_decoration_thickness,
                                             computed_font_size_,
                                             minimum_thickness, font_data_);
    }
  }
  return thickness;
}

void TextDecorationInfo::ComputeWavyLineData(
    gfx::RectF& pattern_rect,
    cc::PaintRecord& tile_record) const {
  struct WavyCache {
    WavyParams key;
    gfx::RectF pattern_rect;
    cc::PaintRecord tile_record;
    DISALLOW_NEW();
  };

  DEFINE_STATIC_LOCAL(std::optional<WavyCache>, wavy_cache, (std::nullopt));

  if (wavy_cache && wavy_cache->key.resolved_thickness == ResolvedThickness() &&
      wavy_cache->key.effective_zoom ==
          decorating_box_style_->EffectiveZoom() &&
      wavy_cache->key.spelling_grammar == IsSpellingOrGrammarError() &&
      wavy_cache->key.color == LineColor()) {
    pattern_rect = wavy_cache->pattern_rect;
    tile_record = wavy_cache->tile_record;
    return;
  }

  WavyParams params{ResolvedThickness(), decorating_box_style_->EffectiveZoom(),
                    IsSpellingOrGrammarError(), LineColor()};
  Path stroke_path = PrepareWavyStrokePath(params);
  pattern_rect = ComputeWavyPatternRect(params, stroke_path);
  tile_record = PrepareWavyTileRecord(params, stroke_path, pattern_rect);
  wavy_cache = WavyCache{params, pattern_rect, tile_record};
}

gfx::RectF TextDecorationInfo::Bounds() const {
  gfx::PointF start_point = StartPoint();
  switch (DecorationStyle()) {
    case ETextDecorationStyle::kDotted:
    case ETextDecorationStyle::kDashed:
      return BoundsForDottedOrDashed();
    case ETextDecorationStyle::kWavy:
      return BoundsForWavy();
    case ETextDecorationStyle::kDouble:
      if (DoubleOffset() > 0) {
        return gfx::RectF(start_point.x(), start_point.y(), width_,
                          DoubleOffset() + ResolvedThickness());
      }
      return gfx::RectF(start_point.x(), start_point.y() + DoubleOffset(),
                        width_, -DoubleOffset() + ResolvedThickness());
    case ETextDecorationStyle::kSolid:
      return gfx::RectF(start_point.x(), start_point.y(), width_,
                        ResolvedThickness());
    default:
      break;
  }
  NOTREACHED();
}

gfx::RectF TextDecorationInfo::BoundsForDottedOrDashed() const {
  StyledStrokeData styled_stroke;
  styled_stroke.SetThickness(roundf(ResolvedThickness()));
  styled_stroke.SetStyle(TextDecorationStyleToStrokeStyle(DecorationStyle()));
  return line_data_.stroke_path.value().StrokeBoundingRect(
      styled_stroke.ConvertToStrokeData({}));
}

// Returns the wavy bounds, which is the same size as the wavy paint rect but
// at the origin needed by the actual decoration, for the global transform.
//
// The origin is the sum of the local origin, line offset, (wavy) double offset,
// and the origin of the wavy pattern rect (around minus half the amplitude).
gfx::RectF TextDecorationInfo::BoundsForWavy() const {
  gfx::SizeF size = WavyPaintRect().size();
  gfx::PointF origin = line_data_.wavy_pattern_rect.origin();
  origin += StartPoint().OffsetFromOrigin();
  origin += gfx::Vector2dF{0.f, DoubleOffset() * line_data_.wavy_offset_factor};
  return {origin, size};
}

// Returns the wavy paint rect, which has the height of the wavy tile rect but
// the width needed by the actual decoration, for the DrawRect operation.
//
// The origin is still (0,0) so that the shader local matrix is independent of
// the origin of the decoration, allowing Skia to cache the tile. To determine
// the origin of the decoration, use Bounds().origin().
gfx::RectF TextDecorationInfo::WavyPaintRect() const {
  gfx::RectF result = WavyTileRect();
  result.set_width(width_);
  return result;
}

// Returns the wavy tile rect, which is the same size as the wavy pattern rect
// but at origin (0,0), for converting the PaintRecord to a PaintShader.
gfx::RectF TextDecorationInfo::WavyTileRect() const {
  gfx::RectF result = line_data_.wavy_pattern_rect;
  result.set_x(0.f);
  result.set_y(0.f);
  return result;
}

cc::PaintRecord TextDecorationInfo::WavyTileRecord() const {
  return line_data_.wavy_tile_record;
}

void TextDecorationInfo::SetHighlightOverrideColor(
    const std::optional<Color>& color) {
  highlight_override_ = color;
}

Path TextDecorationInfo::PrepareDottedOrDashedStrokePath() const {
  // These coordinate transforms need to match what's happening in
  // GraphicsContext's drawLineForText and drawLine.
  gfx::PointF start_point = StartPoint();
  return DecorationLinePainter::GetPathForTextLine(
      start_point, width_, ResolvedThickness(),
      TextDecorationStyleToStrokeStyle(DecorationStyle()));
}

}  // namespace blink

"""

```