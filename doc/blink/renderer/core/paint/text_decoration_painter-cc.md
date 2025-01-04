Response:
Let's break down the thought process for analyzing this C++ code and generating the comprehensive answer.

**1. Initial Understanding of the File and its Purpose:**

* **File Location:** `blink/renderer/core/paint/text_decoration_painter.cc` immediately suggests this code is responsible for painting text decorations within the Blink rendering engine. The `paint` directory confirms it's related to the visual rendering process.
* **Class Name:** `TextDecorationPainter` reinforces the purpose: it paints decorations applied to text.

**2. Dissecting the Code - Functional Breakdown:**

* **Constructor and Destructor:**  The constructor initializes various member variables related to painting context, style, and decoration information. The destructor has a DCHECK, indicating an expectation about the object's state upon destruction.
* **`UpdateDecorationInfo`:** This function is crucial. It figures out *what* decorations need to be painted based on style, text item properties (like being an ellipsis or SVG text), and potential overrides (like selection styles). The logic for SVG text scaling is a notable detail.
* **`ExpandRectForSVGDecorations`:** This helper function addresses a known issue with SVG text's ink overflow calculation, indicating a workaround.
* **`Begin`:** This likely initiates the painting process for a given text fragment and phase (normal or selection). It updates `decoration_info_` and sets up clipping if necessary.
* **`PaintUnderOrOverLineDecorations`:** This function handles painting underlines, overlines, and potentially spelling/grammar error indicators. It iterates through applied decorations and uses `TextPainter` to do the actual drawing. It also considers text shadows.
* **`PaintLineThroughDecorations`:** This specifically handles painting strikethrough lines.
* **`PaintExceptLineThrough` (two versions):** These functions paint all decorations *except* line-through. One takes a `TextFragmentPaintInfo` (likely for regular painting), and the other takes a `TextDecorationInfo` and specific lines to paint.
* **`PaintOnlyLineThrough` (two versions):**  These functions *only* paint the line-through decoration.
* **`ClipIfNeeded`:** This function manages clipping the drawing area based on whether it's painting a selection or not.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **CSS Properties:**  Immediately, CSS properties like `text-decoration-line`, `text-decoration-color`, `text-decoration-style`, `text-decoration-thickness`, `text-underline-offset`, `text-overline-offset`, and potentially `text-shadow` come to mind. The code directly manipulates these concepts.
* **HTML Elements:**  Any HTML element containing text can have these decorations applied (e.g., `<p>`, `<span>`, `<h1>`, elements with inline styles). SVG `<text>` elements are handled specifically.
* **JavaScript Interaction:**  JavaScript can modify the CSS styles of elements, indirectly triggering the logic in this C++ file when the page is repainted. JavaScript doesn't directly interact with this low-level painting code.

**4. Logical Reasoning and Examples:**

* **Input/Output of `UpdateDecorationInfo`:**  Consider different scenarios: text with underline, text with strikethrough and selection, SVG text with decorations. This helps illustrate the function's behavior.
* **Conditional Painting:**  The `if` statements in the paint functions clearly show how different decoration types are handled.

**5. Identifying Potential User/Programming Errors:**

* **CSS Conflicts:**  Conflicting decoration styles might lead to unexpected results.
* **Incorrect SVG Scaling:**  The SVG scaling logic is complex, so mistakes in related code could cause issues.
* **Performance:** Unnecessary clipping can be a performance bottleneck.

**6. Tracing User Actions and Debugging:**

* **Step-by-Step User Actions:**  Think about how a user might cause these decorations to appear: typing text, applying CSS styles, selecting text.
* **Debugging Process:**  Consider using a debugger to step through the code, inspect variables like `decoration_info_`, and examine the `paint_info_.context`. The `DCHECK` statements are important for identifying unexpected states.

**7. Structuring the Answer:**

* **Start with a high-level summary of the file's purpose.**
* **Break down the functionality of each important function.**
* **Explicitly connect the code to JavaScript, HTML, and CSS with concrete examples.**
* **Provide illustrative input/output scenarios.**
* **Highlight common user/programming errors.**
* **Describe the user actions leading to this code and debugging strategies.**

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the file directly handles drawing primitives. **Correction:** Realized it delegates the actual drawing to `TextPainter` and focuses on *managing* which decorations to paint and how.
* **Overemphasis on direct JavaScript interaction:** **Correction:** JavaScript influences the *styles*, which then drive this C++ code. The interaction is indirect.
* **Not enough detail on SVG handling:** **Correction:**  The specific logic for SVG scaling and the `ExpandRectForSVGDecorations` function are key details that need emphasis.

By following this structured approach and constantly refining the understanding, a comprehensive and accurate answer can be generated. The key is to combine code analysis with knowledge of web technologies and debugging practices.
好的，让我们来详细分析 `blink/renderer/core/paint/text_decoration_painter.cc` 这个文件。

**文件功能概览:**

`TextDecorationPainter.cc` 文件的主要职责是在 Chromium Blink 渲染引擎中负责绘制文本的装饰线，例如下划线、上划线和删除线 (line-through)，以及拼写/语法错误标记。它与 `TextPainter` 类协作，`TextDecorationPainter` 负责准备和管理装饰线的绘制逻辑，而 `TextPainter` 负责实际的图形绘制操作。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件背后的逻辑直接对应于 CSS 中控制文本装饰效果的属性：

* **`text-decoration-line`:**  决定显示哪种装饰线（`underline`, `overline`, `line-through`, `none`, `spelling-error`, `grammar-error`）。
    * **C++ 代码体现:**  在 `TextDecorationPainter` 中，你可以看到对 `TextDecorationLine` 枚举类型的处理，例如在 `PaintUnderOrOverLineDecorations` 和 `PaintLineThroughDecorations` 函数中，会根据 `decoration_info_->HasUnderline()`, `decoration_info_->HasOverline()`, `EnumHasFlags(lines, TextDecorationLine::kLineThrough)` 等条件来判断是否需要绘制特定的装饰线。
    * **HTML/CSS 示例:**
      ```html
      <!DOCTYPE html>
      <html>
      <head>
      <style>
      .underline { text-decoration-line: underline; }
      .overline { text-decoration-line: overline; }
      .line-through { text-decoration-line: line-through; }
      </style>
      </head>
      <body>
        <p class="underline">这是一段带有下划线的文字。</p>
        <p class="overline">这是一段带有上划线的文字。</p>
        <p class="line-through">这是一段带有删除线的文字。</p>
      </body>
      </html>
      ```
      当浏览器渲染上述 HTML 时，Blink 引擎会解析 CSS，并将 `text-decoration-line` 的值传递到渲染流程中，最终由 `TextDecorationPainter` 来绘制这些线条。

* **`text-decoration-color`:**  设置装饰线的颜色。
    * **C++ 代码体现:** `LineColorForPhase` 函数根据绘制阶段（例如是否在绘制阴影）返回相应的颜色。最终，这个颜色会被传递给 `text_painter_.PaintDecorationLine` 函数进行绘制。
    * **HTML/CSS 示例:**
      ```html
      <!DOCTYPE html>
      <html>
      <head>
      <style>
      .custom-decoration { text-decoration-line: underline; text-decoration-color: red; }
      </style>
      </head>
      <body>
        <p class="custom-decoration">这段下划线是红色的。</p>
      </body>
      </html>
      ```

* **`text-decoration-style`:** 设置装饰线的样式（`solid`, `double`, `dotted`, `dashed`, `wavy`）。
    * **C++ 代码体现:**  虽然在这个文件中没有直接看到处理 `text-decoration-style` 的代码，但可以推断，`TextPainter::PaintDecorationLine` 函数会根据 `decoration_info_` 中存储的样式信息来选择不同的绘制方式。这些样式信息在更早的阶段，例如样式计算阶段，就已经被解析和存储。
    * **HTML/CSS 示例:**
      ```html
      <!DOCTYPE html>
      <html>
      <head>
      <style>
      .dotted-underline { text-decoration-line: underline; text-decoration-style: dotted; }
      </style>
      </head>
      <body>
        <p class="dotted-underline">这段下划线是点状的。</p>
      </body>
      </html>
      ```

* **`text-decoration-thickness`:**  设置装饰线的粗细。
    * **C++ 代码体现:**  在 `UpdateDecorationInfo` 函数中，`MinimumThickness1(!text_item.IsSvgText())`  可能与此属性有关，确保装饰线至少有一个像素的粗细，尤其是在非 SVG 文本中。更精细的粗细控制可能在 `TextPainter::PaintDecorationLine` 中实现。
    * **HTML/CSS 示例:**
      ```html
      <!DOCTYPE html>
      <html>
      <head>
      <style>
      .thick-underline { text-decoration-line: underline; text-decoration-thickness: 3px; }
      </style>
      </head>
      <body>
        <p class="thick-underline">这段下划线很粗。</p>
      </body>
      </html>
      ```

* **`text-underline-offset` 和 `text-overline-offset`:** 调整下划线和上划线相对于文本基线的偏移量。
    * **C++ 代码体现:**  `TextDecorationOffset decoration_offset(style_);`  这行代码表明 `TextDecorationPainter` 会使用 `TextDecorationOffset` 类来处理偏移量。 `decoration_info.SetUnderlineLineData(decoration_offset);` 和 `decoration_info.SetOverlineLineData(decoration_offset);`  显示了如何将偏移量信息传递给后续的绘制步骤。
    * **HTML/CSS 示例:**
      ```html
      <!DOCTYPE html>
      <html>
      <head>
      <style>
      .offset-underline { text-decoration-line: underline; text-underline-offset: 5px; }
      .offset-overline { text-decoration-line: overline; text-overline-offset: 2px; }
      </style>
      </head>
      <body>
        <p class="offset-underline">这段下划线有偏移。</p>
        <p class="offset-overline">这段上划线也有偏移。</p>
      </body>
      </html>
      ```

* **拼写和语法错误指示:**  浏览器内置的拼写和语法检查器会在文本下方显示特殊的装饰线。
    * **C++ 代码体现:**  `decoration_info.HasSpellingOrGrammerError()` 的检查以及对 `TextDecorationLine::kSpellingError` 和 `TextDecorationLine::kGrammarError` 的处理，表明了这个文件负责绘制这些指示线。
    * **用户操作:** 当用户在输入框或可编辑区域输入文本时，如果浏览器检测到拼写或语法错误，就会触发相应的绘制逻辑。

**逻辑推理与假设输入/输出:**

**假设输入:**

1. 一个 `FragmentItem` 对象，代表需要绘制装饰线的文本片段。
2. 一个 `ComputedStyle` 对象，包含了应用于该文本的 CSS 样式，包括 `text-decoration-line`, `text-decoration-color` 等。
3. `PaintInfo` 对象，提供绘制上下文信息。
4. `TextPaintStyle` 对象，包含文本绘制相关的样式信息。
5. `LineRelativeRect` 对象，定义了文本片段在行内的相对位置和大小。

**逻辑推理流程 (以绘制下划线为例):**

1. `Begin` 函数被调用，传入上述输入。
2. `UpdateDecorationInfo` 函数检查 `style.HasAppliedTextDecorations()` 是否为真，以及 `text_item.IsEllipsis()` 是否为假。
3. 如果 `ComputedStyle` 中 `text-decoration-line` 包含了 `underline`，则 `decoration_info_` 会被更新，包含下划线的信息。
4. `PaintExceptLineThrough` 函数被调用，因为下划线不是删除线。
5. `PaintUnderOrOverLineDecorations` 函数被调用。
6. 循环遍历 `decoration_info_` 中的装饰信息。
7. 如果检测到 `decoration_info_->HasUnderline()` 为真，并且 `EnumHasFlags(lines_to_paint, TextDecorationLine::kUnderline)` 也为真，则会调用 `decoration_info_->SetUnderlineLineData(decoration_offset);` 来设置下划线的位置和偏移量。
8. 最终，`text_painter_.PaintDecorationLine` 函数会被调用，传入 `decoration_info_` 和下划线的颜色等信息，进行实际的绘制。

**假设输出:**

在给定的 `GraphicsContext` 上绘制出一条与文本片段对齐的下划线，其颜色、样式和粗细由 `ComputedStyle` 中的 CSS 属性决定。

**用户或编程常见的使用错误:**

1. **CSS 属性值错误:**  例如，将 `text-decoration-line` 设置为无效值，可能导致装饰线无法正确显示或被忽略。
    * **例子:** `text-decoration-line: unknow-value;`
2. **CSS 优先级问题:**  如果多个 CSS 规则同时应用于同一个文本元素，并且定义了不同的 `text-decoration` 属性，可能会因为优先级问题导致最终的装饰效果不是预期的。
    * **例子:**
      ```html
      <style>
      .parent { text-decoration: underline red; }
      .child { text-decoration: none; }
      </style>
      <div class="parent">
        <span class="child">这段文字没有下划线</span>
      </div>
      ```
      如果期望子元素的文字有下划线，但由于 `.child` 的规则覆盖了父元素的规则，可能导致下划线不显示。
3. **JavaScript 动态修改样式错误:**  如果 JavaScript 代码在运行时动态修改元素的 `text-decoration` 属性，可能会因为逻辑错误导致样式更新不正确。
    * **例子:**
      ```javascript
      const element = document.getElementById('myText');
      if (someCondition) {
        element.style.textDecorationLine = 'underline';
      } else if (anotherCondition) {
        // 错误：忘记移除下划线
      }
      ```
      在某些条件下忘记移除下划线可能会导致意外的装饰效果。
4. **SVG 特殊性处理不当:**  代码中对 SVG 文本有特殊的处理 (`text_item.IsSvgText()`)，如果开发者在处理 SVG 文本的装饰时没有考虑到这些特殊性，可能会导致绘制错误。

**用户操作如何一步步到达这里 (调试线索):**

假设用户正在浏览一个网页，页面上有一个段落设置了下划线样式：

1. **用户访问网页:**  用户在浏览器地址栏输入 URL 或点击链接访问网页。
2. **浏览器解析 HTML:**  浏览器下载 HTML 代码并开始解析，构建 DOM 树。
3. **浏览器解析 CSS:**  浏览器下载并解析与页面关联的 CSS 样式表，构建 CSSOM 树。
4. **样式计算:**  Blink 引擎将 DOM 树和 CSSOM 树结合起来，计算出每个元素的最终样式（ComputedStyle）。对于设置了 `text-decoration-line: underline;` 的文本元素，其 `ComputedStyle` 对象会包含相应的装饰信息。
5. **布局 (Layout):**  根据计算出的样式和 DOM 结构，Blink 引擎进行布局计算，确定每个元素在页面上的位置和大小。文本内容会被分割成不同的 `FragmentItem`。
6. **绘制 (Paint):**  当需要绘制文本及其装饰时，会创建 `TextDecorationPainter` 对象。
7. **`Begin` 调用:**  对于每个需要绘制装饰线的文本片段 (`FragmentItem`)，`TextDecorationPainter::Begin` 函数会被调用，传入相关的上下文信息。
8. **`UpdateDecorationInfo` 调用:**  在 `Begin` 函数内部，`UpdateDecorationInfo` 会根据 `ComputedStyle` 中的 `text-decoration` 属性值来更新装饰信息。
9. **`PaintExceptLineThrough` 或 `PaintOnlyLineThrough` 调用:**  根据需要绘制的装饰线类型，会调用相应的绘制函数。例如，对于下划线，会调用 `PaintExceptLineThrough`。
10. **`PaintUnderOrOverLineDecorations` 调用:**  在 `PaintExceptLineThrough` 内部，会调用 `PaintUnderOrOverLineDecorations` 来处理下划线和上划线的绘制。
11. **`text_painter_.PaintDecorationLine` 调用:**  最终，`TextDecorationPainter` 会调用 `TextPainter::PaintDecorationLine` 函数，将装饰线的具体绘制操作委托给 `TextPainter`。`TextPainter` 会使用 `GraphicsContext` 进行实际的图形绘制。
12. **屏幕渲染:**  绘制完成后，浏览器会将结果渲染到屏幕上，用户就能看到带有下划线的文字。

**调试线索:**

*   **断点设置:** 在 `TextDecorationPainter::Begin`, `TextDecorationPainter::UpdateDecorationInfo`, `TextDecorationPainter::PaintUnderOrOverLineDecorations`, `TextPainter::PaintDecorationLine` 等关键函数设置断点，可以追踪装饰线绘制的流程。
*   **查看变量:**  在断点处查看 `decoration_info_` 对象，可以了解哪些装饰线被应用，以及其颜色、样式等信息。查看 `style_` 对象可以确认 CSS 样式是否被正确解析。
*   **图形调试工具:**  Chromium 提供了开发者工具，可以查看渲染树、合成层等信息，有助于理解绘制过程。
*   **Layer 边界查看:**  在开发者工具中开启 "Show layer borders"，可以帮助理解文本内容所在的层，以及可能的裁剪区域。
*   **性能分析:**  如果怀疑装饰线的绘制存在性能问题，可以使用 Chrome 的 Performance 面板进行分析，查看绘制相关的耗时。

希望以上分析能够帮助你理解 `blink/renderer/core/paint/text_decoration_painter.cc` 文件的功能和作用。

Prompt: 
```
这是目录为blink/renderer/core/paint/text_decoration_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/text_decoration_painter.h"

#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/layout/text_decoration_offset.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/text_painter.h"
#include "third_party/blink/renderer/core/paint/text_shadow_painter.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context_state_saver.h"

namespace blink {

namespace {

Color LineColorForPhase(TextDecorationInfo& decoration_info,
                        TextShadowPaintPhase phase) {
  if (phase == TextShadowPaintPhase::kShadow) {
    return Color::kBlack;
  }
  return decoration_info.LineColor();
}

}  // namespace

TextDecorationPainter::TextDecorationPainter(
    TextPainter& text_painter,
    const InlinePaintContext* inline_context,
    const PaintInfo& paint_info,
    const ComputedStyle& style,
    const TextPaintStyle& text_style,
    const LineRelativeRect& decoration_rect,
    HighlightPainter::SelectionPaintState* selection)
    : text_painter_(text_painter),
      inline_context_(inline_context),
      paint_info_(paint_info),
      style_(style),
      text_style_(text_style),
      decoration_rect_(decoration_rect),
      selection_(selection),
      step_(kBegin),
      phase_(kOriginating) {}

TextDecorationPainter::~TextDecorationPainter() {
  DCHECK(step_ == kBegin);
}

void TextDecorationPainter::UpdateDecorationInfo(
    std::optional<TextDecorationInfo>& result,
    const FragmentItem& text_item,
    const ComputedStyle& style,
    std::optional<LineRelativeRect> decoration_rect_override,
    const AppliedTextDecoration* decoration_override) {
  result.reset();

  if ((!style.HasAppliedTextDecorations() && !decoration_override) ||
      // Ellipsis should not have text decorations. This is not defined, but
      // 4 impls do this: <https://github.com/w3c/csswg-drafts/issues/6531>
      text_item.IsEllipsis()) {
    return;
  }

  TextDecorationLine effective_selection_decoration_lines =
      TextDecorationLine::kNone;
  Color effective_selection_decoration_color;
  if (phase_ == kSelection) [[unlikely]] {
    effective_selection_decoration_lines =
        selection_->GetSelectionStyle().selection_decoration_lines;
    effective_selection_decoration_color =
        selection_->GetSelectionStyle().selection_decoration_color;
  }

  if (text_item.IsSvgText() && paint_info_.IsRenderingResourceSubtree()) {
    // Need to recompute a scaled font and a scaling factor because they
    // depend on the scaling factor of an element referring to the text.
    float scaling_factor = 1;
    Font scaled_font;
    LayoutSVGInlineText::ComputeNewScaledFontForStyle(
        *text_item.GetLayoutObject(), scaling_factor, scaled_font);
    DCHECK(scaling_factor);
    // Adjust the origin of the decoration because
    // TextPainter::PaintDecorationsExceptLineThrough() will change the
    // scaling of the GraphicsContext.
    LayoutUnit top = decoration_rect_.offset.line_over;
    // In svg/text/text-decorations-in-scaled-pattern.svg, the size of
    // ScaledFont() is zero, and the top position is unreliable. So we
    // adjust the baseline position, then shift it for scaled_font.
    top += text_item.ScaledFont().PrimaryFont()->GetFontMetrics().FixedAscent();
    top *= scaling_factor / text_item.SvgScalingFactor();
    top -= scaled_font.PrimaryFont()->GetFontMetrics().FixedAscent();
    result.emplace(LineRelativeOffset{decoration_rect_.offset.line_left, top},
                   decoration_rect_.InlineSize(), style, inline_context_,
                   effective_selection_decoration_lines,
                   effective_selection_decoration_color, decoration_override,
                   &scaled_font, MinimumThickness1(false),
                   text_item.SvgScalingFactor() / scaling_factor);
  } else {
    LineRelativeRect decoration_rect =
        decoration_rect_override.value_or(decoration_rect_);
    result.emplace(decoration_rect.offset, decoration_rect.InlineSize(), style,
                   inline_context_, effective_selection_decoration_lines,
                   effective_selection_decoration_color, decoration_override,
                   &text_item.ScaledFont(),
                   MinimumThickness1(!text_item.IsSvgText()));
  }
}

gfx::RectF TextDecorationPainter::ExpandRectForSVGDecorations(
    const LineRelativeRect& rect) {
  // Until SVG text has correct InkOverflow, we need to hack it.
  gfx::RectF clip_rect{rect};
  clip_rect.set_y(clip_rect.y() - clip_rect.height());
  clip_rect.set_height(3 * clip_rect.height());
  return clip_rect;
}

void TextDecorationPainter::Begin(const FragmentItem& text_item, Phase phase) {
  DCHECK(step_ == kBegin);

  phase_ = phase;
  UpdateDecorationInfo(decoration_info_, text_item, style_);
  clip_rect_.reset();

  if (decoration_info_ && selection_) [[unlikely]] {
    if (text_item.IsSvgText()) [[unlikely]] {
      clip_rect_.emplace(
          ExpandRectForSVGDecorations(selection_->LineRelativeSelectionRect()));
    } else {
      const LineRelativeRect selection_rect =
          selection_->LineRelativeSelectionRect();
      const PhysicalRect& ink_overflow_rect = text_item.InkOverflowRect();
      clip_rect_.emplace(selection_rect.offset.line_left, ink_overflow_rect.Y(),
                         selection_rect.size.inline_size,
                         ink_overflow_rect.Height());
    }
  }

  step_ = kExcept;
}

void TextDecorationPainter::PaintUnderOrOverLineDecorations(
    TextDecorationInfo& decoration_info,
    const TextFragmentPaintInfo& fragment_paint_info,
    const TextPaintStyle& text_style,
    TextDecorationLine lines_to_paint) {
  if (paint_info_.IsRenderingResourceSubtree()) {
    paint_info_.context.Scale(1, decoration_info.ScalingFactor());
  }
  const TextDecorationOffset decoration_offset(style_);

  PaintWithTextShadow(
      [&](TextShadowPaintPhase phase) {
        for (wtf_size_t i = 0; i < decoration_info.AppliedDecorationCount();
             i++) {
          decoration_info.SetDecorationIndex(i);

          if (decoration_info.HasSpellingOrGrammerError() &&
              EnumHasFlags(lines_to_paint,
                           TextDecorationLine::kSpellingError |
                               TextDecorationLine::kGrammarError)) {
            decoration_info.SetSpellingOrGrammarErrorLineData(
                decoration_offset);
            // We ignore "text-decoration-skip-ink: auto" for spelling and
            // grammar error markers.
            text_painter_.PaintDecorationLine(
                decoration_info, LineColorForPhase(decoration_info, phase),
                nullptr);
            continue;
          }

          if (decoration_info.HasUnderline() && decoration_info.FontData() &&
              EnumHasFlags(lines_to_paint, TextDecorationLine::kUnderline)) {
            decoration_info.SetUnderlineLineData(decoration_offset);
            text_painter_.PaintDecorationLine(
                decoration_info, LineColorForPhase(decoration_info, phase),
                &fragment_paint_info);
          }

          if (decoration_info.HasOverline() && decoration_info.FontData() &&
              EnumHasFlags(lines_to_paint, TextDecorationLine::kOverline)) {
            decoration_info.SetOverlineLineData(decoration_offset);
            text_painter_.PaintDecorationLine(
                decoration_info, LineColorForPhase(decoration_info, phase),
                &fragment_paint_info);
          }
        }
      },
      paint_info_.context, text_style);
}

void TextDecorationPainter::PaintLineThroughDecorations(
    TextDecorationInfo& decoration_info,
    const TextPaintStyle& text_style) {
  if (paint_info_.IsRenderingResourceSubtree()) {
    paint_info_.context.Scale(1, decoration_info.ScalingFactor());
  }

  PaintWithTextShadow(
      [&](TextShadowPaintPhase phase) {
        for (wtf_size_t applied_decoration_index = 0;
             applied_decoration_index <
             decoration_info.AppliedDecorationCount();
             ++applied_decoration_index) {
          const AppliedTextDecoration& decoration =
              decoration_info.AppliedDecoration(applied_decoration_index);
          TextDecorationLine lines = decoration.Lines();
          if (EnumHasFlags(lines, TextDecorationLine::kLineThrough)) {
            decoration_info.SetDecorationIndex(applied_decoration_index);

            decoration_info.SetLineThroughLineData();

            // No skip: ink for line-through,
            // compare https://github.com/w3c/csswg-drafts/issues/711
            text_painter_.PaintDecorationLine(
                decoration_info, LineColorForPhase(decoration_info, phase),
                nullptr);
          }
        }
      },
      paint_info_.context, text_style);
}

void TextDecorationPainter::PaintExceptLineThrough(
    const TextFragmentPaintInfo& fragment_paint_info) {
  DCHECK(step_ == kExcept);

  // Clipping the canvas unnecessarily is expensive, so avoid doing it if the
  // only decoration was a ‘line-through’.
  if (decoration_info_ &&
      decoration_info_->HasAnyLine(~TextDecorationLine::kLineThrough)) {
    GraphicsContextStateSaver state_saver(paint_info_.context);
    ClipIfNeeded(state_saver);
    PaintUnderOrOverLineDecorations(*decoration_info_, fragment_paint_info,
                                    text_style_, ~TextDecorationLine::kNone);
  }

  step_ = kOnly;
}

void TextDecorationPainter::PaintOnlyLineThrough() {
  DCHECK(step_ == kOnly);

  // Clipping the canvas unnecessarily is expensive, so avoid doing it if there
  // are no ‘line-through’ decorations.
  if (decoration_info_ &&
      decoration_info_->HasAnyLine(TextDecorationLine::kLineThrough)) {
    GraphicsContextStateSaver state_saver(paint_info_.context);
    ClipIfNeeded(state_saver);
    PaintLineThroughDecorations(*decoration_info_, text_style_);
  }

  step_ = kBegin;
}

void TextDecorationPainter::PaintExceptLineThrough(
    TextDecorationInfo& decoration_info,
    const TextPaintStyle& text_style,
    const TextFragmentPaintInfo& fragment_paint_info,
    TextDecorationLine lines_to_paint) {
  if (!decoration_info.HasAnyLine(lines_to_paint &
                                  ~TextDecorationLine::kLineThrough)) {
    return;
  }
  GraphicsContextStateSaver state_saver(paint_info_.context);
  PaintUnderOrOverLineDecorations(decoration_info, fragment_paint_info,
                                  text_style, lines_to_paint);
}

void TextDecorationPainter::PaintOnlyLineThrough(
    TextDecorationInfo& decoration_info,
    const TextPaintStyle& text_style) {
  if (!decoration_info.HasAnyLine(TextDecorationLine::kLineThrough)) {
    return;
  }
  GraphicsContextStateSaver state_saver(paint_info_.context);
  PaintLineThroughDecorations(decoration_info, text_style);
}

void TextDecorationPainter::ClipIfNeeded(
    GraphicsContextStateSaver& state_saver) {
  DCHECK(step_ != kBegin);

  if (clip_rect_) {
    state_saver.SaveIfNeeded();
    if (phase_ == kSelection)
      paint_info_.context.Clip(*clip_rect_);
    else
      paint_info_.context.ClipOut(*clip_rect_);
  }
}

}  // namespace blink

"""

```