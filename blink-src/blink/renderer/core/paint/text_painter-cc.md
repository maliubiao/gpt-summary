Response:
Let's break down the thought process for analyzing this `text_painter.cc` file.

1. **Understand the Core Function:** The name "TextPainter" strongly suggests its primary responsibility is drawing text. The file path `blink/renderer/core/paint/` reinforces this, placing it within the rendering engine's painting phase.

2. **Identify Key Dependencies (Includes):**  The included headers provide significant clues about the file's functionality and interactions. I'd go through them and categorize their relevance:

    * **Fundamental Graphics:** `cc/paint/paint_flags.h`, `third_party/blink/renderer/platform/graphics/graphics_context.h`, `third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h`, `third_party/blink/renderer/platform/graphics/paint/paint_controller.h`, `third_party/blink/renderer/platform/graphics/draw_looper_builder.h`, `third_party/blink/renderer/platform/graphics/stroke_data.h`. These are essential for the low-level drawing operations, managing state, and applying effects like shadows.

    * **Layout and Styling:** `third_party/blink/renderer/core/layout/layout_object_inlines.h`, `third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h`, `third_party/blink/renderer/core/layout/svg/svg_layout_support.h`, `third_party/blink/renderer/core/layout/svg/svg_resources.h`, `third_party/blink/renderer/core/css/properties/longhands.h`, `third_party/blink/renderer/core/style/computed_style.h`, `third_party/blink/renderer/core/style/paint_order_array.h`, `third_party/blink/renderer/core/style/shadow_list.h`. This indicates the painter interacts with the layout of text elements and uses the computed styles (CSS) to determine how to draw them. The SVG-related headers suggest special handling for SVG text.

    * **Text Specifics:** `third_party/blink/renderer/core/paint/text_paint_style.h`, `third_party/blink/renderer/platform/fonts/font.h`, `third_party/blink/renderer/platform/fonts/text_fragment_paint_info.h`. These focus on the specific properties and information needed to render text, like font details and how the text is broken into fragments.

    * **Other Paint-Related Components:** `third_party/blink/renderer/core/paint/box_painter_base.h`, `third_party/blink/renderer/core/paint/decoration_line_painter.h`, `third_party/blink/renderer/core/paint/paint_info.h`, `third_party/blink/renderer/core/paint/svg_object_painter.h`, `third_party/blink/renderer/core/paint/timing/paint_timing_detector.h`. These show the painter works within a larger painting system and collaborates with other painters (like those for decorations).

    * **Utility and Base:** `base/auto_reset.h`, `base/types/optional_util.h`. These are general-purpose utility headers.

3. **Analyze Key Classes and Methods:** I'd scan the class definition and the key methods defined within the file:

    * `TextPainter::Paint()`: The primary function for drawing a text fragment. It takes `TextFragmentPaintInfo` and `TextPaintStyle` as input, indicating it uses pre-computed layout and style information. The `ShadowMode` parameter suggests it can handle drawing text with or without shadows.

    * `TextPainter::PaintSelectedText()`:  Handles drawing selected text, potentially with different styles for the selected portion. This immediately brings to mind the interaction with user selection in the browser.

    * `TextPainter::SetEmphasisMark()`:  Deals with drawing text emphasis marks (like small circles or triangles above/below characters).

    * `TextPainter::PaintDecorationLine()`:  Responsible for drawing text decorations like underlines, overlines, and line-throughs.

    * `TextPainter::ClipDecorationsStripe()`: A helper function for optimizing the drawing of text decorations by clipping out areas where glyphs are present, preventing overlap.

    * `TextPainter::PaintSvgTextFragment()` and `TextPainter::SetSvgState()`:  Indicate specific handling for SVG text elements, likely due to their unique styling and rendering requirements.

    * `TextPainter::TextPaintingStyle()`: A static method to determine the appropriate `TextPaintStyle` based on the current style and paint phase.

4. **Identify Relationships with Web Technologies (HTML, CSS, JavaScript):**

    * **HTML:** The `TextPainter` draws the content of HTML text elements (like `<p>`, `<span>`, `<h1>`, etc.). The structure of the HTML determines the layout and the text content itself.

    * **CSS:** The `ComputedStyle` objects passed to the `TextPainter` are the direct result of CSS styling applied to HTML elements. CSS properties like `color`, `font-family`, `font-size`, `text-decoration`, `text-shadow`, `text-emphasis`, and `paint-order` directly influence how the `TextPainter` renders the text.

    * **JavaScript:** While `TextPainter` itself is C++, JavaScript can indirectly trigger its execution. For example, JavaScript manipulations of the DOM (Document Object Model) or changes to CSS styles will eventually lead to a re-layout and repaint, which will involve the `TextPainter`. User interactions like selecting text (which triggers `PaintSelectedText`) are also often facilitated by JavaScript.

5. **Look for Logic and Conditional Execution:** Pay attention to `if` statements, loops, and helper functions. The code within `PaintSelectedText` that checks if the selection rect contains the entire text fragment is a good example of optimization logic. The handling of SVG text in separate functions also indicates conditional logic based on the type of element.

6. **Consider Potential Errors:** Think about what could go wrong during text painting:

    * **Incorrect Style Application:** If the `ComputedStyle` is somehow corrupted or doesn't reflect the CSS, the text might be rendered incorrectly.
    * **Font Loading Issues:** If the specified font is not available, a fallback font will be used, potentially leading to layout shifts.
    * **Performance Bottlenecks:** Complex text effects (like many shadows) or large amounts of text can slow down rendering.
    * **Edge Cases with Ligatures and Complex Scripts:**  Handling of ligatures and scripts that flow right-to-left or vertically can introduce subtle rendering bugs.

7. **Trace User Actions:**  Think about the sequence of events that leads to the `TextPainter` being invoked:

    * A user requests a web page in their browser.
    * The browser's rendering engine parses the HTML and CSS.
    * The layout engine determines the position and size of elements, including text.
    * The paint phase begins, and the `TextPainter` is called to draw the text content of specific elements.
    * User interactions like scrolling, resizing the window, or selecting text can trigger repaints, involving the `TextPainter` again.

8. **Structure the Explanation:**  Organize the findings into logical categories (functionality, relationships with web technologies, logic, errors, user actions). Use examples to illustrate the concepts. For the logical inference, create simple hypothetical inputs and outputs to demonstrate how specific code sections might behave.

By following these steps, one can systematically analyze a complex source code file like `text_painter.cc` and gain a good understanding of its purpose, interactions, and potential issues.
好的，让我们详细分析一下 `blink/renderer/core/paint/text_painter.cc` 这个文件。

**文件功能概览**

`text_painter.cc` 文件的核心职责是**在 Chromium Blink 渲染引擎中负责绘制文本内容**。 它接收布局（Layout）阶段计算好的文本信息和样式信息，然后将其转化为屏幕上的像素。 具体来说，它执行以下关键任务：

1. **绘制文本字形 (Glyphs):**  使用字体信息和文本内容，在指定的坐标上绘制出文本的形状。
2. **应用文本样式:**  根据 CSS 样式（如颜色、字体、大小、粗细等）来绘制文本。
3. **处理文本装饰:** 绘制下划线、上划线和删除线等文本装饰线。
4. **绘制文本阴影:** 根据 CSS `text-shadow` 属性绘制文本的阴影效果。
5. **处理文本选择:**  当用户选中部分文本时，使用不同的样式（通常是反色）绘制选中的部分。
6. **绘制文本强调标记:**  根据 CSS `text-emphasis` 属性绘制文本的强调标记（例如，小圆点）。
7. **处理 SVG 文本:**  对于 SVG 内联文本元素，进行特殊的绘制处理。
8. **考虑打印模式:**  在打印时，可能需要调整文本颜色以适应白色背景。
9. **进行性能优化:**  例如，通过裁剪不必要的绘制区域来提升性能。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`text_painter.cc` 是 Blink 渲染引擎的核心组成部分，它直接参与将 HTML、CSS 描述的内容转化为用户可见的图形。

* **HTML (结构):**
    * **关系:** `TextPainter` 负责绘制 HTML 文档中各种包含文本内容的元素，例如 `<p>`, `<span>`, `<h1>` 到 `<h6>`, `<li>`, `<div>` (包含文本时) 等。
    * **举例:**  当浏览器渲染以下 HTML 代码时，`TextPainter` 会被调用来绘制 "Hello, world!" 这段文本。
      ```html
      <!DOCTYPE html>
      <html>
      <body>
        <p>Hello, world!</p>
      </body>
      </html>
      ```

* **CSS (样式):**
    * **关系:** `TextPainter` 接收来自 `ComputedStyle` 对象的 CSS 样式信息，并根据这些信息来决定如何绘制文本。
    * **举例:**  考虑以下 CSS 样式：
      ```css
      .styled-text {
        color: blue;
        font-size: 20px;
        text-decoration: underline;
        text-shadow: 2px 2px 5px rgba(0, 0, 0, 0.5);
      }
      ```
      当 `TextPainter` 绘制应用了 `.styled-text` 类的 HTML 元素时，它会：
        * 使用蓝色 (`color: blue;`) 绘制文本。
        * 使用 20 像素 (`font-size: 20px;`) 的字体大小。
        * 绘制下划线 (`text-decoration: underline;`)。
        * 绘制阴影效果 (`text-shadow: 2px 2px 5px rgba(0, 0, 0, 0.5);`)。

* **JavaScript (动态交互):**
    * **关系:** 虽然 `TextPainter` 本身是用 C++ 编写的，但 JavaScript 可以通过修改 DOM 结构或 CSS 样式来间接地影响 `TextPainter` 的行为。
    * **举例:**  如果 JavaScript 代码动态地修改一个元素的 `textContent` 或 `innerHTML`，或者修改其 CSS 类名，导致其样式改变，那么当浏览器重新渲染时，`TextPainter` 会使用新的文本内容和样式来重新绘制。
      ```javascript
      // HTML: <p id="dynamic-text">Initial Text</p>

      // JavaScript:
      document.getElementById('dynamic-text').textContent = 'Updated Text';
      document.getElementById('dynamic-text').style.color = 'red';
      ```
      当这段 JavaScript 代码执行后，`TextPainter` 会被调用来绘制 "Updated Text"，颜色为红色。

**逻辑推理、假设输入与输出**

让我们看一个简单的逻辑推理的例子，关于 `PaintSelectedText` 函数的处理逻辑。

**假设输入:**

* **文本内容:** "Example Text"
* **选择范围:**  从索引 2 到 6 (选中 "ampl")
* **原始文本样式 (`text_style`):** 黑色
* **选择样式 (`selection_style`):** 白色背景，黑色文字

**逻辑推理:**

`PaintSelectedText` 函数的目标是使用 `selection_style` 绘制选中的部分，而使用 `text_style` 绘制未选中的部分。

1. **判断是否整个文本都被选中:** 如果选择范围覆盖整个文本，则直接用 `selection_style` 绘制。
2. **调整选择范围以包含完整字形:**  如果选择范围在连字 (ligature) 中间，则扩展范围以包含完整的连字。
3. **绘制选择阴影 (如果存在):**  使用 `selection_style` 的阴影效果绘制选中区域。
4. **裁剪选中区域，绘制未选中部分:**  使用 `text_style` 绘制选中区域之外的文本。
5. **裁剪未选中区域，绘制选中部分:** 使用 `selection_style` 绘制选中区域的文本。

**假设输出 (屏幕上的渲染效果):**

屏幕上会显示 "Ex[ampl]e Text"，其中 "ampl" 部分会以白色背景和黑色文字显示，而 "Ex" 和 "e Text" 部分会以黑色文字显示。

**用户或编程常见的使用错误**

1. **忘记设置字体:** 如果 CSS 中没有指定 `font-family`，浏览器会使用默认字体，这可能不是开发者期望的。这会导致 `TextPainter` 使用默认字体进行绘制。
2. **颜色值错误:**  提供无效的颜色值（例如，拼写错误的颜色名称）会导致浏览器使用默认颜色，`TextPainter` 也会使用这个默认颜色。
3. **文本阴影参数错误:**  `text-shadow` 属性的参数顺序或值不正确会导致阴影效果不符合预期或根本不显示。
4. **在 SVG 中混淆样式继承:**  在 SVG 中，文本的样式继承可能与 HTML 元素不同，开发者可能没有正确理解 SVG 元素的样式应用规则，导致 `TextPainter` 使用了错误的样式。
5. **动态修改样式导致频繁重绘:**  过度或不必要的 JavaScript 样式修改可能导致浏览器频繁调用 `TextPainter` 进行重绘，影响性能。

**用户操作是如何一步步到达这里 (作为调试线索)**

假设开发者想要调试为什么页面上的某个文本没有正确显示阴影效果。以下是可能的操作步骤，最终会涉及到 `text_painter.cc` 的代码执行：

1. **用户打开包含该文本的网页:** 浏览器开始解析 HTML、CSS 和 JavaScript。
2. **浏览器布局阶段:**  布局引擎计算出文本的位置和大小。
3. **浏览器绘制阶段:**
    * **调用 TextPainter:**  当需要绘制包含文本的元素时，渲染引擎会创建 `TextPainter` 对象。
    * **获取样式信息:** `TextPainter` 会从 `ComputedStyle` 对象中获取文本的样式信息，包括 `text-shadow` 属性。
    * **绘制文本和阴影:**  `TextPainter::Paint` 函数（或其内部调用的函数）会根据样式信息来绘制文本和阴影。如果 `text-shadow` 属性存在，并且参数正确，则会绘制阴影。
4. **开发者检查页面:** 用户（开发者）发现文本的阴影没有显示出来。
5. **开发者检查 CSS:**  开发者会检查与该文本元素相关的 CSS 规则，确认是否设置了 `text-shadow` 属性，以及属性值是否正确。
6. **使用开发者工具:** 开发者可能会使用浏览器的开发者工具（例如，Chrome DevTools）来检查元素的 `ComputedStyle`，查看 `text-shadow` 属性的值是否被正确解析。
7. **设置断点 (如果深入调试 Blink 引擎):**  如果开发者需要深入了解 Blink 引擎的运行过程，他们可能会在 `text_painter.cc` 相关的代码中设置断点，例如：
    * `TextPainter::Paint` 函数的入口。
    * 处理 `text-shadow` 属性的代码段（例如，`CreateDrawLooper` 函数）。
    * 查看 `ComputedStyle` 对象中 `TextShadow()` 的返回值。
8. **单步执行代码:**  通过单步执行代码，开发者可以观察 `TextPainter` 是如何获取样式信息，以及如何处理阴影效果的。这有助于确定问题是出在样式解析、绘制逻辑还是其他环节。

**总结**

`blink/renderer/core/paint/text_painter.cc` 是 Chromium Blink 引擎中至关重要的文件，它负责将抽象的文本信息和样式信息转化为用户可见的像素。理解其功能和与 Web 技术的关系，有助于开发者更好地理解浏览器的工作原理，并进行更有效的调试和性能优化。

Prompt: 
```
这是目录为blink/renderer/core/paint/text_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/text_painter.h"

#include "base/auto_reset.h"
#include "base/types/optional_util.h"
#include "cc/paint/paint_flags.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/layout/svg/svg_layout_support.h"
#include "third_party/blink/renderer/core/layout/svg/svg_resources.h"
#include "third_party/blink/renderer/core/paint/box_painter_base.h"
#include "third_party/blink/renderer/core/paint/decoration_line_painter.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/svg_object_painter.h"
#include "third_party/blink/renderer/core/paint/text_paint_style.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/paint_order_array.h"
#include "third_party/blink/renderer/core/style/shadow_list.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/text_fragment_paint_info.h"
#include "third_party/blink/renderer/platform/graphics/draw_looper_builder.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller.h"
#include "third_party/blink/renderer/platform/graphics/stroke_data.h"

namespace blink {

namespace {

// We usually use the text decoration thickness to determine how far
// ink-skipped text decorations should be away from the glyph
// contours. Cap this at 5 CSS px in each direction when thickness
// growths larger than that. A value of 13 closely matches FireFox'
// implementation.
constexpr float kDecorationClipMaxDilation = 13;

class SelectionStyleScope {
  STACK_ALLOCATED();

 public:
  SelectionStyleScope(const LayoutObject&,
                      const ComputedStyle& style,
                      const ComputedStyle& selection_style);
  SelectionStyleScope(const SelectionStyleScope&) = delete;
  SelectionStyleScope& operator=(const SelectionStyleScope) = delete;
  ~SelectionStyleScope();

 private:
  const LayoutObject& layout_object_;
  const ComputedStyle& selection_style_;
  const bool styles_are_equal_;
};

SelectionStyleScope::SelectionStyleScope(const LayoutObject& layout_object,
                                         const ComputedStyle& style,
                                         const ComputedStyle& selection_style)
    : layout_object_(layout_object),
      selection_style_(selection_style),
      styles_are_equal_(style == selection_style) {
  if (styles_are_equal_)
    return;
  DCHECK(!layout_object.IsSVGInlineText());
  SVGResources::UpdatePaints(layout_object_, nullptr, selection_style_);
}

SelectionStyleScope::~SelectionStyleScope() {
  if (styles_are_equal_)
    return;
  SVGResources::ClearPaints(layout_object_, &selection_style_);
}

sk_sp<cc::DrawLooper> CreateDrawLooper(
    const ShadowList* shadow_list,
    DrawLooperBuilder::ShadowAlphaMode alpha_mode,
    const Color& current_color,
    mojom::blink::ColorScheme color_scheme,
    TextPainter::ShadowMode shadow_mode) {
  DrawLooperBuilder draw_looper_builder;

  // ShadowList nullptr means there are no shadows.
  if (shadow_mode != TextPainter::kTextProperOnly && shadow_list) {
    for (wtf_size_t i = shadow_list->Shadows().size(); i--;) {
      const ShadowData& shadow = shadow_list->Shadows()[i];
      draw_looper_builder.AddShadow(
          shadow.Offset(), shadow.Blur(),
          shadow.GetColor().Resolve(current_color, color_scheme),
          DrawLooperBuilder::kShadowRespectsTransforms, alpha_mode);
    }
  }
  if (shadow_mode != TextPainter::kShadowsOnly) {
    draw_looper_builder.AddUnmodifiedContent();
  }
  return draw_looper_builder.DetachDrawLooper();
}

void UpdateGraphicsContext(GraphicsContext& context,
                           const TextPaintStyle& text_style,
                           GraphicsContextStateSaver& state_saver,
                           TextPainter::ShadowMode shadow_mode) {
  TextDrawingModeFlags mode = context.TextDrawingMode();
  if (text_style.stroke_width > 0) {
    TextDrawingModeFlags new_mode = mode | kTextModeStroke;
    if (mode != new_mode) {
      state_saver.SaveIfNeeded();
      context.SetTextDrawingMode(new_mode);
      mode = new_mode;
    }
  }

  if (mode & kTextModeFill && text_style.fill_color != context.FillColor()) {
    context.SetFillColor(text_style.fill_color);
  }

  if (mode & kTextModeStroke) {
    if (text_style.stroke_color != context.StrokeColor()) {
      context.SetStrokeColor(text_style.stroke_color);
    }
    if (text_style.stroke_width != context.StrokeThickness()) {
      context.SetStrokeThickness(text_style.stroke_width);
    }
  }

  switch (text_style.paint_order) {
    case kPaintOrderNormal:
    case kPaintOrderFillStrokeMarkers:
    case kPaintOrderFillMarkersStroke:
    case kPaintOrderMarkersFillStroke:
      context.SetTextPaintOrder(kFillStroke);
      break;
    case kPaintOrderStrokeFillMarkers:
    case kPaintOrderStrokeMarkersFill:
    case kPaintOrderMarkersStrokeFill:
      context.SetTextPaintOrder(kStrokeFill);
      break;
  }

  if (shadow_mode != TextPainter::kTextProperOnly) {
    DCHECK(shadow_mode == TextPainter::kBothShadowsAndTextProper ||
           shadow_mode == TextPainter::kShadowsOnly);

    // If there are shadows, we definitely need a cc::DrawLooper, but if there
    // are no shadows (nullptr), we still need one iff we’re in kShadowsOnly
    // mode, because we suppress text proper by omitting AddUnmodifiedContent
    // when building a looper (cf. CRC2DState::ShadowAndForegroundDrawLooper).
    if (text_style.shadow || shadow_mode == TextPainter::kShadowsOnly) {
      state_saver.SaveIfNeeded();
      context.SetDrawLooper(CreateDrawLooper(
          text_style.shadow.Get(), DrawLooperBuilder::kShadowIgnoresAlpha,
          text_style.current_color, text_style.color_scheme, shadow_mode));
    }
  }
}

enum class SvgPaintMode { kText, kTextDecoration };

void PrepareStrokeGeometry(const TextPainter::SvgTextPaintState& state,
                           const ComputedStyle& style,
                           const LayoutObject& layout_parent,
                           SvgPaintMode svg_paint_mode,
                           cc::PaintFlags& flags) {
  float stroke_scale_factor = 1;
  // The stroke geometry needs be generated based on the scaled font.
  if (style.VectorEffect() != EVectorEffect::kNonScalingStroke) {
    switch (svg_paint_mode) {
      case SvgPaintMode::kText:
        stroke_scale_factor = state.InlineText().ScalingFactor();
        break;
      case SvgPaintMode::kTextDecoration: {
        Font scaled_font;
        LayoutSVGInlineText::ComputeNewScaledFontForStyle(
            layout_parent, stroke_scale_factor, scaled_font);
        DCHECK(stroke_scale_factor);
        break;
      }
    }
  }

  StrokeData stroke_data;
  SVGLayoutSupport::ApplyStrokeStyleToStrokeData(
      stroke_data, style, layout_parent, stroke_scale_factor);
  if (stroke_scale_factor != 1) {
    stroke_data.SetThickness(stroke_data.Thickness() * stroke_scale_factor);
  }
  stroke_data.SetupPaint(&flags);
}

const ShadowList* GetTextShadows(const ComputedStyle& style,
                                 const LayoutObject& layout_parent) {
  // Text shadows are disabled when printing. http://crbug.com/258321
  if (layout_parent.GetDocument().Printing()) {
    return nullptr;
  }
  return style.TextShadow();
}

void PrepareTextShadow(const ShadowList* text_shadows,
                       const ComputedStyle& style,
                       cc::PaintFlags& flags) {
  if (!text_shadows) {
    return;
  }
  flags.setLooper(CreateDrawLooper(
      text_shadows, DrawLooperBuilder::kShadowRespectsAlpha,
      style.VisitedDependentColor(GetCSSPropertyColor()),
      style.UsedColorScheme(), TextPainter::kBothShadowsAndTextProper));
}

struct SvgPaints {
  std::optional<cc::PaintFlags> fill;
  std::optional<cc::PaintFlags> stroke;
};

void PrepareSvgPaints(const TextPainter::SvgTextPaintState& state,
                      const SvgContextPaints* context_paints,
                      SvgPaintMode paint_mode,
                      SvgPaints& paints) {
  if (state.IsRenderingClipPathAsMaskImage()) [[unlikely]] {
    cc::PaintFlags& flags = paints.fill.emplace();
    flags.setColor(SK_ColorBLACK);
    flags.setAntiAlias(true);
    return;
  }

  // https://svgwg.org/svg2-draft/text.html#TextDecorationProperties
  // The fill and stroke of the text decoration are given by the fill and stroke
  // of the text at the point where the text decoration is declared.
  const LayoutObject& layout_parent = paint_mode == SvgPaintMode::kText
                                          ? *state.InlineText().Parent()
                                          : state.TextDecorationObject();
  SVGObjectPainter object_painter(layout_parent, context_paints);
  if (state.IsPaintingTextMatch()) [[unlikely]] {
    const ComputedStyle& style = state.Style();

    cc::PaintFlags& fill_flags = paints.fill.emplace();
    fill_flags.setColor(state.TextMatchColor().Rgb());
    fill_flags.setAntiAlias(true);

    cc::PaintFlags unused_flags;
    if (SVGObjectPainter::HasVisibleStroke(style, context_paints)) {
      if (!object_painter.PreparePaint(state.GetPaintFlags(), style,
                                       kApplyToStrokeMode, unused_flags)) {
        return;
      }
      cc::PaintFlags& stroke_flags = paints.stroke.emplace(fill_flags);
      PrepareStrokeGeometry(state, style, layout_parent, paint_mode,
                            stroke_flags);
    }
    return;
  }

  const ComputedStyle& style = [&layout_parent,
                                &state]() -> const ComputedStyle& {
    if (state.IsPaintingSelection()) {
      if (const ComputedStyle* pseudo_selection_style =
              layout_parent.GetSelectionStyle()) {
        return *pseudo_selection_style;
      }
    }
    return layout_parent.StyleRef();
  }();

  std::optional<SelectionStyleScope> paint_resource_scope;
  if (&style != layout_parent.Style()) {
    paint_resource_scope.emplace(layout_parent, *layout_parent.Style(), style);
  }

  const ShadowList* text_shadows = GetTextShadows(style, layout_parent);
  const AffineTransform* shader_transform = state.GetShaderTransform();
  if (SVGObjectPainter::HasFill(style, context_paints)) {
    if (object_painter.PreparePaint(state.GetPaintFlags(), style,
                                    kApplyToFillMode, paints.fill.emplace(),
                                    shader_transform)) {
      PrepareTextShadow(text_shadows, style, *paints.fill);
      paints.fill->setAntiAlias(true);
    } else {
      paints.fill.reset();
    }
  }
  if (SVGObjectPainter::HasVisibleStroke(style, context_paints)) {
    if (object_painter.PreparePaint(state.GetPaintFlags(), style,
                                    kApplyToStrokeMode, paints.stroke.emplace(),
                                    shader_transform)) {
      PrepareTextShadow(text_shadows, style, *paints.stroke);
      paints.stroke->setAntiAlias(true);

      PrepareStrokeGeometry(state, style, layout_parent, paint_mode,
                            *paints.stroke);
    } else {
      paints.stroke.reset();
    }
  }
}

using OrderedPaints = std::array<const cc::PaintFlags*, 2>;

OrderedPaints OrderPaints(const SvgPaints& paints, EPaintOrder paint_order) {
  OrderedPaints ordered_paints = {
      base::OptionalToPtr(paints.fill),
      base::OptionalToPtr(paints.stroke),
  };
  const PaintOrderArray paint_order_array(paint_order,
                                          PaintOrderArray::Type::kNoMarkers);
  if (paint_order_array[0] == PT_STROKE) {
    std::swap(ordered_paints[0], ordered_paints[1]);
  }
  return ordered_paints;
}

template <typename PassFunction>
void DrawPaintOrderPasses(const OrderedPaints& ordered_paints,
                          PassFunction pass) {
  for (const auto* paint : ordered_paints) {
    if (!paint) {
      continue;
    }
    pass(*paint);
  }
}

}  // namespace

void TextPainter::Paint(const TextFragmentPaintInfo& fragment_paint_info,
                        const TextPaintStyle& text_style,
                        DOMNodeId node_id,
                        const AutoDarkMode& auto_dark_mode,
                        ShadowMode shadow_mode) {
  // TODO(layout-dev): We shouldn't be creating text fragments without text.
  if (!fragment_paint_info.shape_result) {
    return;
  }
  // Do not try to paint kShadowsOnly without a ShadowList, because we will
  // create an empty DrawLooper that effectively paints kTextProperOnly.
  if (shadow_mode == ShadowMode::kShadowsOnly && !text_style.shadow) {
    return;
  }
  DCHECK_LE(fragment_paint_info.from, fragment_paint_info.text.length());
  DCHECK_LE(fragment_paint_info.to, fragment_paint_info.text.length());

  GraphicsContextStateSaver state_saver(graphics_context_, false);
  UpdateGraphicsContext(graphics_context_, text_style, state_saver,
                        shadow_mode);
  // TODO(layout-dev): Handle combine text here or elsewhere.
  if (svg_text_paint_state_.has_value()) {
    const AutoDarkMode svg_text_auto_dark_mode(
        DarkModeFilter::ElementRole::kSVG,
        auto_dark_mode.enabled &&
            !svg_text_paint_state_->IsRenderingClipPathAsMaskImage());
    PaintSvgTextFragment(fragment_paint_info, node_id, svg_text_auto_dark_mode);
  } else {
    graphics_context_.DrawText(font_, fragment_paint_info,
                               gfx::PointF(text_origin_), node_id,
                               auto_dark_mode);
  }

  if (!emphasis_mark_.empty()) {
    if (text_style.emphasis_mark_color != text_style.fill_color)
      graphics_context_.SetFillColor(text_style.emphasis_mark_color);
    graphics_context_.DrawEmphasisMarks(
        font_, fragment_paint_info, emphasis_mark_,
        gfx::PointF(text_origin_) + gfx::Vector2dF(0, emphasis_mark_offset_),
        auto_dark_mode);
  }

  // TODO(sohom): SubstringContainsOnlyWhitespaceOrEmpty() does not check
  // for all whitespace characters as defined in the spec definition of
  // whitespace. See https://w3c.github.io/paint-timing/#non-empty
  // In particular 0xb and 0xc are not checked.
  if (!fragment_paint_info.text.SubstringContainsOnlyWhitespaceOrEmpty(
          fragment_paint_info.from, fragment_paint_info.to)) {
    graphics_context_.GetPaintController().SetTextPainted();
  }

  if (!font_.ShouldSkipDrawing()) {
    PaintTimingDetector::NotifyTextPaint(visual_rect_);
  }
}

// This function paints text twice with different styles in order to:
// 1. Paint glyphs inside of |selection_rect| using |selection_style|, and
//    outside using |text_style|.
// 2. Paint parts of a ligature glyph.
void TextPainter::PaintSelectedText(
    const TextFragmentPaintInfo& fragment_paint_info,
    unsigned selection_start,
    unsigned selection_end,
    const TextPaintStyle& text_style,
    const TextPaintStyle& selection_style,
    const LineRelativeRect& selection_rect,
    DOMNodeId node_id,
    const AutoDarkMode& auto_dark_mode) {
  if (!fragment_paint_info.shape_result)
    return;

  // Use fast path if all glyphs fit in |selection_rect|. |visual_rect_| is the
  // ink bounds of all glyphs of this text fragment, including characters before
  // |start_offset| or after |end_offset|. Computing exact bounds is expensive
  // that this code only checks bounds of all glyphs.
  gfx::Rect snapped_selection_rect(ToPixelSnappedRect(selection_rect));
  // Allowing 1px overflow is almost unnoticeable, while it can avoid two-pass
  // painting in most small text.
  snapped_selection_rect.Outset(1);
  // For SVG text, comparing with visual_rect_ does not work well because
  // selection_rect is in the scaled coordinate system and visual_rect_ is
  // in the unscaled coordinate system. Checks text offsets too.
  if (snapped_selection_rect.Contains(visual_rect_) ||
      (selection_start == fragment_paint_info.from &&
       selection_end == fragment_paint_info.to)) {
    std::optional<base::AutoReset<bool>> is_painting_selection_reset;
    if (TextPainter::SvgTextPaintState* state = GetSvgState()) {
      is_painting_selection_reset.emplace(&state->is_painting_selection_, true);
    }
    Paint(fragment_paint_info.Slice(selection_start, selection_end),
          selection_style, node_id, auto_dark_mode);
    return;
  }

  // Adjust start/end offset when they are in the middle of a ligature. e.g.,
  // when |start_offset| is between a ligature of "fi", it needs to be adjusted
  // to before "f".
  fragment_paint_info.shape_result->ExpandRangeToIncludePartialGlyphs(
      &selection_start, &selection_end);

  // Because only a part of the text glyph can be selected, we need to draw
  // the selection twice. First, draw any shadow for the selection clipped.
  gfx::RectF float_selection_rect(selection_rect);
  if (selection_style.shadow) [[unlikely]] {
    std::optional<base::AutoReset<bool>> is_painting_selection_reset;
    if (TextPainter::SvgTextPaintState* state = GetSvgState()) {
      is_painting_selection_reset.emplace(&state->is_painting_selection_, true);
    }
    GraphicsContextStateSaver state_saver(graphics_context_);
    gfx::RectF selection_shadow_rect = float_selection_rect;
    selection_style.shadow->AdjustRectForShadow(selection_shadow_rect);
    graphics_context_.Clip(selection_shadow_rect);
    Paint(fragment_paint_info.Slice(selection_start, selection_end),
          selection_style, node_id, auto_dark_mode, TextPainter::kShadowsOnly);
  }
  // Then draw the glyphs outside the selection area, with the original style.
  {
    GraphicsContextStateSaver state_saver(graphics_context_);
    graphics_context_.ClipOut(float_selection_rect);
    Paint(fragment_paint_info.Slice(selection_start, selection_end), text_style,
          node_id, auto_dark_mode, TextPainter::kTextProperOnly);
  }
  // Then draw the glyphs inside the selection area, with the selection style.
  {
    std::optional<base::AutoReset<bool>> is_painting_selection_reset;
    if (TextPainter::SvgTextPaintState* state = GetSvgState()) {
      is_painting_selection_reset.emplace(&state->is_painting_selection_, true);
    }
    GraphicsContextStateSaver state_saver(graphics_context_);
    graphics_context_.Clip(float_selection_rect);
    Paint(fragment_paint_info.Slice(selection_start, selection_end),
          selection_style, node_id, auto_dark_mode,
          TextPainter::kTextProperOnly);
  }
}

void TextPainter::SetEmphasisMark(const AtomicString& emphasis_mark,
                                  TextEmphasisPosition position) {
  emphasis_mark_ = emphasis_mark;
  const SimpleFontData* font_data = font_.PrimaryFont();
  DCHECK(font_data);

  if (!font_data || emphasis_mark.IsNull()) {
    emphasis_mark_offset_ = 0;
  } else if ((horizontal_ && IsOver(position)) ||
             (!horizontal_ && IsRight(position))) {
    emphasis_mark_offset_ = -font_data->GetFontMetrics().Ascent() -
                            font_.EmphasisMarkDescent(emphasis_mark);
  } else {
    DCHECK(!IsOver(position) || position == TextEmphasisPosition::kOverLeft);
    emphasis_mark_offset_ = font_data->GetFontMetrics().Descent() +
                            font_.EmphasisMarkAscent(emphasis_mark);
  }
}

void TextPainter::PaintDecorationLine(
    const TextDecorationInfo& decoration_info,
    const Color& line_color,
    const TextFragmentPaintInfo* fragment_paint_info) {
  DecorationLinePainter decoration_painter(graphics_context_, decoration_info);
  if (fragment_paint_info &&
      decoration_info.TargetStyle().TextDecorationSkipInk() ==
          ETextDecorationSkipInk::kAuto) {
    // In order to ignore intersects less than 0.5px, inflate by -0.5.
    gfx::RectF decoration_bounds = decoration_info.Bounds();
    decoration_bounds.Inset(gfx::InsetsF::VH(0.5, 0));
    ClipDecorationsStripe(
        *fragment_paint_info,
        decoration_info.InkSkipClipUpper(decoration_bounds.y()),
        decoration_bounds.height(),
        std::min(decoration_info.ResolvedThickness(),
                 kDecorationClipMaxDilation));
  }

  if (svg_text_paint_state_.has_value() &&
      !decoration_info.HasDecorationOverride()) {
    SvgPaints paints;
    const SvgTextPaintState& state = svg_text_paint_state_.value();
    PrepareSvgPaints(state, svg_context_paints_, SvgPaintMode::kTextDecoration,
                     paints);

    const OrderedPaints ordered_paints =
        OrderPaints(paints, state.Style().PaintOrder());
    DrawPaintOrderPasses(ordered_paints, [&](const cc::PaintFlags& flags) {
      decoration_painter.Paint(line_color, &flags);
    });
  } else {
    decoration_painter.Paint(line_color, nullptr);
  }
}

void TextPainter::ClipDecorationsStripe(
    const TextFragmentPaintInfo& fragment_paint_info,
    float upper,
    float stripe_width,
    float dilation) {
  if (fragment_paint_info.from >= fragment_paint_info.to ||
      !fragment_paint_info.shape_result)
    return;

  Vector<Font::TextIntercept> text_intercepts;
  font_.GetTextIntercepts(fragment_paint_info, graphics_context_.FillFlags(),
                          std::make_tuple(upper, upper + stripe_width),
                          text_intercepts);

  for (auto intercept : text_intercepts) {
    gfx::PointF clip_origin(text_origin_);
    gfx::RectF clip_rect(
        clip_origin + gfx::Vector2dF(intercept.begin_, upper),
        gfx::SizeF(intercept.end_ - intercept.begin_, stripe_width));
    // We need to ensure the clip rectangle is covering the full underline
    // extent. For horizontal drawing, using enclosingIntRect would be
    // sufficient, since we can clamp to full device pixels that way. However,
    // for vertical drawing, we have a transformation applied, which breaks the
    // integers-equal-device pixels assumption, so vertically inflating by 1
    // pixel makes sure we're always covering. This should only be done on the
    // clipping rectangle, not when computing the glyph intersects.
    clip_rect.Outset(gfx::OutsetsF::VH(1.0, dilation));

    if (!gfx::RectFToSkRect(clip_rect).isFinite()) {
      continue;
    }
    graphics_context_.ClipOut(clip_rect);
  }
}

void TextPainter::PaintSvgTextFragment(
    const TextFragmentPaintInfo& fragment_paint_info,
    DOMNodeId node_id,
    const AutoDarkMode& auto_dark_mode) {
  SvgPaints paints;
  const SvgTextPaintState& state = svg_text_paint_state_.value();
  PrepareSvgPaints(state, svg_context_paints_, SvgPaintMode::kText, paints);

  const OrderedPaints ordered_paints =
      OrderPaints(paints, state.Style().PaintOrder());
  DrawPaintOrderPasses(ordered_paints, [&](const cc::PaintFlags& flags) {
    graphics_context_.DrawText(font_, fragment_paint_info,
                               gfx::PointF(text_origin_), flags, node_id,
                               auto_dark_mode);
  });
}

TextPainter::SvgTextPaintState& TextPainter::SetSvgState(
    const LayoutSVGInlineText& svg_inline_text,
    const ComputedStyle& style,
    StyleVariant style_variant,
    PaintFlags paint_flags) {
  return svg_text_paint_state_.emplace(svg_inline_text, style, style_variant,
                                       paint_flags);
}

TextPainter::SvgTextPaintState& TextPainter::SetSvgState(
    const LayoutSVGInlineText& svg_inline_text,
    const ComputedStyle& style,
    Color text_match_color) {
  return svg_text_paint_state_.emplace(svg_inline_text, style,
                                       text_match_color);
}

TextPainter::SvgTextPaintState* TextPainter::GetSvgState() {
  return base::OptionalToPtr(svg_text_paint_state_);
}

// static
Color TextPainter::TextColorForWhiteBackground(Color text_color) {
  int distance_from_white = DifferenceSquared(text_color, Color::kWhite);
  // semi-arbitrarily chose 65025 (255^2) value here after a few tests;
  return distance_from_white > 65025 ? text_color : text_color.Dark();
}

// static
TextPaintStyle TextPainter::TextPaintingStyle(const Document& document,
                                              const ComputedStyle& style,
                                              const PaintInfo& paint_info) {
  TextPaintStyle text_style;
  text_style.stroke_width = style.TextStrokeWidth();
  text_style.color_scheme = style.UsedColorScheme();

  if (paint_info.phase == PaintPhase::kTextClip) {
    // When we use the text as a clip, we only care about the alpha, thus we
    // make all the colors black.
    text_style.current_color = Color::kBlack;
    text_style.fill_color = Color::kBlack;
    text_style.stroke_color = Color::kBlack;
    text_style.emphasis_mark_color = Color::kBlack;
    text_style.shadow = nullptr;
    text_style.paint_order = kPaintOrderNormal;
  } else {
    text_style.current_color =
        style.VisitedDependentColorFast(GetCSSPropertyColor());
    text_style.fill_color =
        style.VisitedDependentColorFast(GetCSSPropertyWebkitTextFillColor());
    text_style.stroke_color =
        style.VisitedDependentColorFast(GetCSSPropertyWebkitTextStrokeColor());
    text_style.emphasis_mark_color =
        style.VisitedDependentColorFast(GetCSSPropertyTextEmphasisColor());
    text_style.shadow = style.TextShadow();
    text_style.paint_order = style.PaintOrder();

    // Adjust text color when printing with a white background.
    bool force_background_to_white =
        BoxPainterBase::ShouldForceWhiteBackgroundForPrintEconomy(document,
                                                                  style);
    if (force_background_to_white) {
      text_style.fill_color =
          TextColorForWhiteBackground(text_style.fill_color);
      text_style.stroke_color =
          TextColorForWhiteBackground(text_style.stroke_color);
      text_style.emphasis_mark_color =
          TextColorForWhiteBackground(text_style.emphasis_mark_color);
    }
  }

  return text_style;
}

TextPainter::SvgTextPaintState::SvgTextPaintState(
    const LayoutSVGInlineText& layout_svg_inline_text,
    const ComputedStyle& style,
    StyleVariant style_variant,
    PaintFlags paint_flags)
    : layout_svg_inline_text_(layout_svg_inline_text),
      style_(style),
      style_variant_(style_variant),
      paint_flags_(paint_flags) {}

TextPainter::SvgTextPaintState::SvgTextPaintState(
    const LayoutSVGInlineText& layout_svg_inline_text,
    const ComputedStyle& style,
    Color text_match_color)
    : layout_svg_inline_text_(layout_svg_inline_text),
      style_(style),
      text_match_color_(text_match_color) {}

const LayoutSVGInlineText& TextPainter::SvgTextPaintState::InlineText() const {
  return layout_svg_inline_text_;
}

const LayoutObject& TextPainter::SvgTextPaintState::TextDecorationObject()
    const {
  // Lookup the first LayoutObject in parent hierarchy which has text-decoration
  // set.
  const LayoutObject* result = InlineText().Parent();
  while (result) {
    if (style_variant_ == StyleVariant::kFirstLine) {
      if (const ComputedStyle* style = result->FirstLineStyle()) {
        if (style->GetTextDecorationLine() != TextDecorationLine::kNone)
          break;
      }
    }
    if (const ComputedStyle* style = result->Style()) {
      if (style->GetTextDecorationLine() != TextDecorationLine::kNone)
        break;
    }

    result = result->Parent();
  }

  DCHECK(result);
  return *result;
}

const ComputedStyle& TextPainter::SvgTextPaintState::Style() const {
  return style_;
}

bool TextPainter::SvgTextPaintState::IsPaintingSelection() const {
  return is_painting_selection_;
}

PaintFlags TextPainter::SvgTextPaintState::GetPaintFlags() const {
  return paint_flags_;
}

bool TextPainter::SvgTextPaintState::IsRenderingClipPathAsMaskImage() const {
  return paint_flags_ & PaintFlag::kPaintingClipPathAsMask;
}

bool TextPainter::SvgTextPaintState::IsPaintingTextMatch() const {
  return text_match_color_.has_value();
}

Color TextPainter::SvgTextPaintState::TextMatchColor() const {
  return *text_match_color_;
}

AffineTransform& TextPainter::SvgTextPaintState::EnsureShaderTransform() {
  return shader_transform_ ? shader_transform_.value()
                           : shader_transform_.emplace();
}

const AffineTransform* TextPainter::SvgTextPaintState::GetShaderTransform()
    const {
  return base::OptionalToPtr(shader_transform_);
}

}  // namespace blink

"""

```