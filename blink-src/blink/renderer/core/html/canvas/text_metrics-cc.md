Response:
Let's break down the thought process for analyzing the provided `text_metrics.cc` file. The goal is to understand its functionality and how it relates to web technologies.

**1. Initial Skim and Keyword Identification:**

First, I'd quickly scan the code looking for recognizable keywords and patterns. Things that immediately jump out are:

* **`TextMetrics` class:** This is the central entity, likely holding data about text measurements.
* **`Font` and `FontMetrics`:** Clearly dealing with font information.
* **`Canvas`:**  The file path itself suggests a connection to the HTML `<canvas>` element.
* **`javascript`, `html`, `css` (from the prompt):**  I need to actively look for connections to these.
* **Methods like `Update`, `getSelectionRects`, `getTextClusters`, `caretPositionFromPoint`:**  These suggest specific functionalities related to measuring and manipulating text.
* **`ShapeResult`, `HarfBuzzShaper`:**  Indicates involvement in text shaping (complex text layout).
* **`BidiParagraph`:**  Deals with bidirectional text (like mixing left-to-right and right-to-left scripts).
* **`DOMRectReadOnly`:**  A DOM API object for representing rectangles, likely used for layout information.
* **Error handling with `ExceptionState`:**  Indicates interaction with the browser's error reporting mechanisms.

**2. High-Level Functionality Identification (Based on Class and Method Names):**

Based on the initial skim, I'd form a general idea of what the file does:

* **Measures Text:**  The name `TextMetrics` is a strong clue. Methods like `Update` likely calculate these metrics.
* **Calculates Bounding Boxes:** `getActualBoundingBox` clearly does this.
* **Handles Text Selection:** `getSelectionRects` suggests calculating the visual rectangles for text selections.
* **Deals with Text Clusters:** `getTextClusters` implies breaking down text into meaningful units (grapheme clusters).
* **Determines Caret Position:** `caretPositionFromPoint` maps a screen coordinate to a text offset.

**3. Analyzing Key Methods and Data Members:**

Next, I'd dive into the details of the most important methods and data members:

* **`TextMetrics::Update()`:** This is crucial. I'd analyze the steps involved:
    * Takes `Font`, `TextDirection`, `TextBaseline`, `TextAlign`, and the `text` itself as input.
    * Uses `BidiParagraph` for handling bidirectional text.
    * Iterates through text runs.
    * Uses `ShapeWord` (or `Font::Width` if shaping is disabled) to get the width of each run.
    * Calculates `width_`, `actual_bounding_box_left_`, `actual_bounding_box_right_`.
    * Determines vertical metrics like `font_bounding_box_ascent_`, `font_bounding_box_descent_`.
    * Calculates baseline offsets.
    * The presence of the `Canvas2dTextMetricsShapingEnabled()` check is important – indicating different paths for text measurement.

* **`TextMetrics::getSelectionRects()`:**
    * Handles start and end indices for the selection.
    * Iterates through text runs.
    * Uses `ShapeResult::CaretPositionForOffset` to determine the visual positions of the selection boundaries within each run.
    * Creates `DOMRectReadOnly` objects for the selection rectangles.

* **`TextMetrics::getTextClusters()`:**
    *  Deals with breaking text into grapheme clusters (user-perceived characters).
    *  Uses `ShapeResult::ForEachGraphemeClusters`.
    *  Creates `TextCluster` objects with position and character range information.
    *  Handles optional `TextClusterOptions` for alignment and baseline.

* **`TextMetrics::caretPositionFromPoint()`:**
    * Takes an `x` coordinate as input.
    *  Iterates through the text runs.
    *  Uses `ShapeResult::CaretOffsetForHitTest` to find the character offset corresponding to the given `x` coordinate within a run.
    *  Includes logic for `CorrectForMixedBidi` to handle caret positioning in bidirectional text.

* **Data Members:**  Understanding the data members is essential for grasping the state the `TextMetrics` object holds:
    * `text_`: The text string.
    * `font_`: The font object.
    * `direction_`: Text direction (LTR or RTL).
    * `width_`: The calculated width of the text.
    * `actual_bounding_box_left_`, `actual_bounding_box_right_`, etc.:  Bounding box dimensions.
    * `runs_with_offset_`: A vector of text runs with their visual offsets. This is key for handling complex layouts.
    * `shaping_needed_`:  A flag indicating whether text shaping needs to be performed.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This is where I explicitly try to link the code's functionality to the web platform:

* **JavaScript:** The code directly supports the `CanvasRenderingContext2D.measureText()` method, which returns a `TextMetrics` object. The methods in `text_metrics.cc` are the underlying implementation for getting the properties of this object. I'd provide examples of using `measureText()` and accessing its properties (width, ascent, descent, etc.).

* **HTML:** The `<canvas>` element is the context for this code. I'd explain how to create a canvas and get its 2D rendering context.

* **CSS:**  Font properties set in CSS (e.g., `font-family`, `font-size`, `font-style`) directly influence the `Font` object used by `TextMetrics`. Text direction set with CSS's `direction` property affects the `TextDirection` used here. `text-align` and `text-baseline` CSS properties map to the corresponding parameters in the `Update` method.

**5. Logical Reasoning and Examples:**

For logical reasoning, I'd pick a specific method (like `getSelectionRects`) and:

* **Assume an input:**  A string, a font, start and end indices.
* **Trace the code's logic (mentally or by stepping through it) with that input.**
* **Predict the output:** The `DOMRectReadOnly` objects representing the selection.
* **Provide a concrete example:**  A simple HTML canvas example with JavaScript that demonstrates this functionality.

**6. Common User/Programming Errors:**

I'd think about how developers might misuse the Canvas API related to text:

* **Incorrectly assuming the order of characters in bidirectional text.**
* **Not accounting for different font metrics.**
* **Making assumptions about text wrapping or line breaks (this file doesn't directly handle that, but it's a related error).**
* **Off-by-one errors with selection indices.**

**7. User Operations Leading to This Code:**

Finally, I'd trace back how a user interaction might trigger this code:

* **User loads a web page with a `<canvas>` element.**
* **JavaScript code on the page gets the 2D rendering context.**
* **The JavaScript code calls `context.fillText()` or `context.strokeText()` to draw text on the canvas.** (While `text_metrics.cc` doesn't directly *draw* the text, it's used to *measure* it, and measurement often precedes drawing).
* **Crucially, the JavaScript code calls `context.measureText()` to get the `TextMetrics` object.** This is the direct trigger.
* **If the JavaScript code then uses methods like `getSelectionRects` or `getTextClusters` on the `TextMetrics` object, those specific code paths within `text_metrics.cc` will be executed.**

By following these steps, I could systematically analyze the code and generate a comprehensive explanation covering its functionality, relationships to web technologies, logical reasoning, potential errors, and user interaction scenarios. The key is to start broad, identify the core purpose, then delve into the details and make connections to the wider web ecosystem.
好的，我们来详细分析一下 `blink/renderer/core/html/canvas/text_metrics.cc` 这个文件。

**文件功能概述**

`text_metrics.cc` 文件是 Chromium Blink 渲染引擎中，用于计算和提供文本度量信息的核心组件。它主要服务于 HTML5 Canvas 元素的文本渲染需求。当你在 Canvas 上绘制文本时，浏览器需要知道文本的宽度、高度、基线位置以及各个字符或字形的边界等信息。`TextMetrics` 类及其相关函数就是负责计算和存储这些信息的。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个文件直接关联到 HTML Canvas API 中的 `CanvasRenderingContext2D.measureText()` 方法。

1. **JavaScript:**
   - `CanvasRenderingContext2D.measureText(text)`: 这个 JavaScript 方法会调用 Blink 引擎底层的代码，最终会用到 `text_metrics.cc` 中的 `TextMetrics` 类来计算给定 `text` 的度量信息。
   - **举例:**
     ```javascript
     const canvas = document.getElementById('myCanvas');
     const ctx = canvas.getContext('2d');
     ctx.font = '16px Arial';
     const text = 'Hello World';
     const metrics = ctx.measureText(text);

     console.log(metrics.width); // 获取文本宽度，由 text_metrics.cc 计算
     console.log(metrics.actualBoundingBoxLeft); // 获取文本左侧边界
     console.log(metrics.actualBoundingBoxRight); // 获取文本右侧边界
     console.log(metrics.fontBoundingBoxAscent); // 获取字体上升高度
     console.log(metrics.fontBoundingBoxDescent); // 获取字体下降高度
     console.log(metrics.alphabeticBaseline); // 获取字母基线位置
     // ... 其他属性
     ```
   - 当 JavaScript 调用 `measureText()` 时，Blink 会创建一个 `TextMetrics` 对象，并使用 `text_metrics.cc` 中的 `Update()` 方法来计算各种度量值。

2. **HTML:**
   - `<canvas>` 元素是 `TextMetrics` 发挥作用的场景。`measureText()` 方法是在 Canvas 的 2D 渲染上下文中调用的。
   - **举例:**
     ```html
     <canvas id="myCanvas" width="200" height="100"></canvas>
     <script src="your_script.js"></script>
     ```
   - `text_metrics.cc` 负责处理在这个 Canvas 上绘制文本时需要的度量计算。

3. **CSS:**
   - Canvas 的文本渲染会受到 CSS `font` 属性的影响。`measureText()` 方法会考虑当前 Canvas 渲染上下文中设置的字体样式。
   - **举例:**
     ```javascript
     const canvas = document.getElementById('myCanvas');
     const ctx = canvas.getContext('2d');
     ctx.font = 'bold 20px "Times New Roman", serif'; // 设置字体样式
     const metrics = ctx.measureText('Sample Text');
     // metrics 的计算会基于上面设置的字体
     ```
   - `text_metrics.cc` 中的代码会使用 `Font` 对象（从 Canvas 上下文中获取）来获取字体的度量信息，例如 ascent, descent 等，这些信息会受到 CSS 字体属性的影响。

**逻辑推理及假设输入与输出**

假设我们有以下输入：

- **文本内容 (text):** "你好，世界"
- **字体样式 (font):** "16px sans-serif"
- **文本方向 (direction):** 默认 (LTR)
- **文本对齐方式 (align):** "left"
- **文本基线 (baseline):** "alphabetic"

`TextMetrics::Update()` 方法会执行以下逻辑（简化）：

1. **获取 `Font` 对象：**  根据提供的字体样式，获取对应的 `Font` 对象。
2. **进行双向文本分析 (Bidi)：**  对于包含从右到左文字的文本，会进行双向文本分析以确定渲染顺序。对于 "你好，世界"，方向是 LTR，这个步骤可能相对简单。
3. **逐个 Run 测量：** 将文本分成不同的运行 (runs)，每个 run 具有相同的文本方向。对于这个例子，可能只有一个 run。
4. **使用 Shaper 进行字形布局：**  `ShapeWord()` 函数会使用 HarfBuzz 等库进行字形布局，确定每个字形的形状和位置。
5. **计算宽度：**  累加每个字形的宽度，得到文本的总宽度。
6. **计算边界框：**  计算文本的实际边界框（包括字形超出常规 ascent/descent 的部分）。
7. **计算基线位置：**  根据指定的基线类型和字体度量信息，计算文本的基线位置。

**假设输出 (TextMetrics 对象的属性值)：**

- `width_`:  例如，可能是 40 像素（取决于实际字形宽度）。
- `actualBoundingBoxLeft_`: 例如，0 像素（如果文本从 0 开始）。
- `actualBoundingBoxRight_`: 例如，40 像素（等于 `width_`）。
- `fontBoundingBoxAscent_`:  例如，12 像素（`sans-serif` 字体的 ascent）。
- `fontBoundingBoxDescent_`: 例如，4 像素（`sans-serif` 字体的 descent）。
- `alphabeticBaseline_`:  例如，0 像素（通常字母基线作为参考）。

**用户或编程常见的使用错误及举例说明**

1. **假设 `measureText()` 返回的宽度是精确的像素宽度，不考虑亚像素渲染。**
   - 实际上，浏览器的渲染可能会使用亚像素精度，`metrics.width` 可能是一个浮点数。
   - **错误示例 (假设整数宽度)：**
     ```javascript
     const canvas = document.getElementById('myCanvas');
     const ctx = canvas.getContext('2d');
     ctx.font = '10.5px Arial'; // 亚像素字体大小
     const metrics = ctx.measureText('Test');
     canvas.width = parseInt(metrics.width) + 10; // 可能会截断文本
     ```
   - **正确做法：** 使用 `Math.ceil()` 或 `Math.floor()` 来处理亚像素宽度。

2. **忽略不同浏览器的字体度量差异。**
   - 不同浏览器或操作系统对于相同字体的度量信息可能略有不同。
   - **错误示例 (假设所有浏览器行为一致)：**
     ```javascript
     const canvas = document.getElementById('myCanvas');
     const ctx = canvas.getContext('2d');
     ctx.font = '16px MyCustomFont';
     const metrics = ctx.measureText('Important Text');
     // 在一个浏览器上完美对齐，但在另一个浏览器上可能错位
     ctx.fillText('Important Text', 100 - metrics.width / 2, 50);
     ```
   - **建议：**  进行跨浏览器测试，或者在布局时留有一定的余量。

3. **不理解 `actualBoundingBoxAscent` 和 `fontBoundingBoxAscent` 的区别。**
   - `fontBoundingBoxAscent` 是字体定义的上升高度，而 `actualBoundingBoxAscent` 是文本内容实际占用的最高高度（可能超出字体定义的上升高度）。
   - **错误示例 (假设 `fontBoundingBoxAscent` 总是够用)：**
     ```javascript
     const canvas = document.getElementById('myCanvas');
     const ctx = canvas.getContext('2d');
     ctx.font = 'Impact'; // Impact 字体可能超出 font bounding box
     const metrics = ctx.measureText('Tj');
     ctx.fillText('Tj', 10, metrics.fontBoundingBoxAscent); // 可能被裁剪
     ```
   - **正确做法：**  根据实际需求选择使用哪个属性，通常 `actualBoundingBoxAscent` 更适合确定文本的完整视觉边界。

**用户操作如何一步步到达这里**

1. **用户打开一个包含 `<canvas>` 元素的网页。**
2. **网页的 JavaScript 代码获取 Canvas 的 2D 渲染上下文 (`getContext('2d')`)。**
3. **JavaScript 代码设置 Canvas 的字体样式 (`ctx.font = '...'`) 和其他文本属性。**
4. **JavaScript 代码调用 `ctx.measureText(someText)` 来测量文本 "someText"。**
5. **浏览器接收到 `measureText()` 的调用，Blink 渲染引擎开始工作。**
6. **Blink 引擎会创建或重用一个 `TextMetrics` 对象。**
7. **`TextMetrics::Update()` 方法被调用，传入当前的字体、文本、方向等信息。**
8. **`Update()` 方法内部会调用字体库（如 HarfBuzz）进行字形布局和度量计算。**
9. **计算出的宽度、高度、基线等信息被存储在 `TextMetrics` 对象中。**
10. **`measureText()` 方法返回一个包含这些度量信息的 JavaScript 对象。**
11. **JavaScript 代码可以访问返回的度量信息，并用于后续的 Canvas 绘图或其他逻辑。**

总结来说，`text_metrics.cc` 是 Canvas 文本渲染的关键组成部分，它桥接了 JavaScript API 和底层的字体渲染机制，负责提供准确的文本度量信息，使得开发者能够在 Canvas 上精细地控制文本的布局和显示。

Prompt: 
```
这是目录为blink/renderer/core/html/canvas/text_metrics.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/canvas/text_metrics.h"

#include "base/numerics/checked_math.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_baselines.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_text_cluster_options.h"
#include "third_party/blink/renderer/core/geometry/dom_rect_read_only.h"
#include "third_party/blink/renderer/core/html/canvas/text_cluster.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/fonts/character_range.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/fonts/font_metrics.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_shaper.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_spacing.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/fonts/simple_font_data.h"
#include "third_party/blink/renderer/platform/graphics/graphics_types.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/bidi_paragraph.h"
#include "third_party/blink/renderer/platform/text/text_direction.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {

constexpr int kHangingAsPercentOfAscent = 80;

float TextMetrics::GetFontBaseline(const TextBaseline& text_baseline,
                                   const SimpleFontData& font_data) {
  FontMetrics font_metrics = font_data.GetFontMetrics();
  switch (text_baseline) {
    case kTopTextBaseline:
      return font_data.NormalizedTypoAscent().ToFloat();
    case kHangingTextBaseline:
      if (font_metrics.HangingBaseline().has_value()) {
        return font_metrics.HangingBaseline().value();
      }
      // According to
      // http://wiki.apache.org/xmlgraphics-fop/LineLayout/AlignmentHandling
      // "FOP (Formatting Objects Processor) puts the hanging baseline at 80% of
      // the ascender height"
      return font_metrics.FloatAscent(kAlphabeticBaseline,
                                      FontMetrics::ApplyBaselineTable(true)) *
             kHangingAsPercentOfAscent / 100.0;
    case kIdeographicTextBaseline:
      if (font_metrics.IdeographicBaseline().has_value()) {
        return font_metrics.IdeographicBaseline().value();
      }
      return -font_metrics.FloatDescent(kAlphabeticBaseline,
                                        FontMetrics::ApplyBaselineTable(true));
    case kBottomTextBaseline:
      return -font_data.NormalizedTypoDescent().ToFloat();
    case kMiddleTextBaseline: {
      const FontHeight metrics = font_data.NormalizedTypoAscentAndDescent();
      return (metrics.ascent.ToFloat() - metrics.descent.ToFloat()) / 2.0f;
    }
    case kAlphabeticTextBaseline:
      if (font_metrics.AlphabeticBaseline().has_value()) {
        return font_metrics.AlphabeticBaseline().value();
      }
      return 0;
    default:
      // Do nothing.
      return 0;
  }
}

void TextMetrics::Trace(Visitor* visitor) const {
  visitor->Trace(baselines_);
  visitor->Trace(font_);
  visitor->Trace(runs_with_offset_);
  ScriptWrappable::Trace(visitor);
}

TextMetrics::TextMetrics() : baselines_(Baselines::Create()) {}

TextMetrics::TextMetrics(const Font& font,
                         const TextDirection& direction,
                         const TextBaseline& baseline,
                         const TextAlign& align,
                         const String& text)
    : TextMetrics() {
  Update(font, direction, baseline, align, text);
}

namespace {
const ShapeResult* ShapeWord(const TextRun& word_run, const Font& font) {
  ShapeResultSpacing<TextRun> spacing(word_run);
  spacing.SetSpacingAndExpansion(font.GetFontDescription());
  HarfBuzzShaper shaper(word_run.NormalizedUTF16());
  ShapeResult* shape_result = shaper.Shape(&font, word_run.Direction());
  if (!spacing.HasSpacing()) {
    return shape_result;
  }
  return shape_result->ApplySpacingToCopy(spacing, word_run);
}
}  // namespace

void TextMetrics::Update(const Font& font,
                         const TextDirection& direction,
                         const TextBaseline& baseline,
                         const TextAlign& align,
                         const String& text) {
  const SimpleFontData* font_data = font.PrimaryFont();
  if (!font_data)
    return;

  text_ = text;
  font_ = font;
  direction_ = direction;
  runs_with_offset_.clear();
  if (!RuntimeEnabledFeatures::Canvas2dTextMetricsShapingEnabled()) {
    // If not enabled, Font::Width is called, which causes a shaping via
    // CachingWordShaper. Since we still need the ShapeResult objects, these are
    // lazily created the first time they are required.
    shaping_needed_ = true;
  }

  // x direction
  // Run bidi algorithm on the given text. Step 5 of:
  // https://html.spec.whatwg.org/multipage/canvas.html#text-preparation-algorithm
  gfx::RectF glyph_bounds;
  String text16 = text;
  text16.Ensure16Bit();
  BidiParagraph bidi;
  bidi.SetParagraph(text16, direction);
  BidiParagraph::Runs runs;
  bidi.GetVisualRuns(text16, &runs);
  float xpos = 0;
  runs_with_offset_.reserve(runs.size());
  for (const auto& run : runs) {
    // Measure each run.
    TextRun text_run(StringView(text, run.start, run.Length()), run.Direction(),
                     /* directional_override */ false);
    text_run.SetNormalizeSpace(true);

    // Save the run for computing additional metrics. Whether we calculate the
    // ShapeResult objects right away, or lazily when needed, depends on the
    // Canvas2dTextMetricsShaping feature.
    RunWithOffset run_with_offset = {
        .shape_result_ = nullptr,
        .text_ = text_run.ToStringView().ToString(),
        .direction_ = run.Direction(),
        .character_offset_ = run.start,
        .num_characters_ = run.Length(),
        .x_position_ = xpos};

    float run_width;
    gfx::RectF run_glyph_bounds;
    if (RuntimeEnabledFeatures::Canvas2dTextMetricsShapingEnabled()) {
      run_with_offset.shape_result_ = ShapeWord(text_run, font);
      run_width = run_with_offset.shape_result_->Width();
      run_glyph_bounds = run_with_offset.shape_result_->ComputeInkBounds();
    } else {
      run_width = font.Width(text_run, &run_glyph_bounds);
    }
    runs_with_offset_.push_back(run_with_offset);

    // Accumulate the position and the glyph bounding box.
    run_glyph_bounds.Offset(xpos, 0);
    glyph_bounds.Union(run_glyph_bounds);
    xpos += run_width;
  }
  double real_width = xpos;
  width_ = real_width;

  text_align_dx_ = 0.0f;
  if (align == kCenterTextAlign) {
    text_align_dx_ = real_width / 2.0f;
    ctx_text_align_ = kCenterTextAlign;
  } else if (align == kRightTextAlign ||
             (align == kStartTextAlign && direction == TextDirection::kRtl) ||
             (align == kEndTextAlign && direction != TextDirection::kRtl)) {
    text_align_dx_ = real_width;
    ctx_text_align_ = kRightTextAlign;
  } else {
    ctx_text_align_ = kLeftTextAlign;
  }
  ctx_text_baseline_ = baseline;
  actual_bounding_box_left_ = -glyph_bounds.x() + text_align_dx_;
  actual_bounding_box_right_ = glyph_bounds.right() - text_align_dx_;

  // y direction
  const FontMetrics& font_metrics = font_data->GetFontMetrics();
  const float ascent = font_metrics.FloatAscent(
      kAlphabeticBaseline, FontMetrics::ApplyBaselineTable(true));
  const float descent = font_metrics.FloatDescent(
      kAlphabeticBaseline, FontMetrics::ApplyBaselineTable(true));
  baseline_y = GetFontBaseline(baseline, *font_data);
  font_bounding_box_ascent_ = ascent - baseline_y;
  font_bounding_box_descent_ = descent + baseline_y;
  actual_bounding_box_ascent_ = -glyph_bounds.y() - baseline_y;
  actual_bounding_box_descent_ = glyph_bounds.bottom() + baseline_y;
  // TODO(kojii): We use normalized sTypoAscent/Descent here, but this should be
  // revisited when the spec evolves.
  const FontHeight normalized_typo_metrics =
      font_data->NormalizedTypoAscentAndDescent();
  em_height_ascent_ = normalized_typo_metrics.ascent - baseline_y;
  em_height_descent_ = normalized_typo_metrics.descent + baseline_y;

  // Setting baselines:
  if (font_metrics.AlphabeticBaseline().has_value()) {
    baselines_->setAlphabetic(font_metrics.AlphabeticBaseline().value() -
                              baseline_y);
  } else {
    baselines_->setAlphabetic(-baseline_y);
  }

  if (font_metrics.HangingBaseline().has_value()) {
    baselines_->setHanging(font_metrics.HangingBaseline().value() - baseline_y);
  } else {
    baselines_->setHanging(ascent * kHangingAsPercentOfAscent / 100.0f -
                           baseline_y);
  }

  if (font_metrics.IdeographicBaseline().has_value()) {
    baselines_->setIdeographic(font_metrics.IdeographicBaseline().value() -
                               baseline_y);
  } else {
    baselines_->setIdeographic(-descent - baseline_y);
  }
}

void TextMetrics::ShapeTextIfNeeded() {
  if (!shaping_needed_) {
    return;
  }
  for (auto& run : runs_with_offset_) {
    TextRun word_run(run.text_, run.direction_, false);
    run.shape_result_ = ShapeWord(word_run, font_);
  }
  shaping_needed_ = false;
}

const HeapVector<Member<DOMRectReadOnly>> TextMetrics::getSelectionRects(
    uint32_t start,
    uint32_t end,
    ExceptionState& exception_state) {
  HeapVector<Member<DOMRectReadOnly>> selection_rects;

  // Checks indexes that go over the maximum for the text. For indexes less than
  // 0, an exception is thrown by [EnforceRange] in the idl binding.
  if (start > text_.length() || end > text_.length()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        String::Format("The %s index is out of bounds.",
                       start > text_.length() ? "start" : "end"));
    return selection_rects;
  }

  ShapeTextIfNeeded();
  const double height = font_bounding_box_ascent_ + font_bounding_box_descent_;
  const double y = -font_bounding_box_ascent_;

  for (const auto& run_with_offset : runs_with_offset_) {
    const unsigned int run_start_index = run_with_offset.character_offset_;
    const unsigned int run_end_index =
        run_start_index + run_with_offset.num_characters_;

    // Handle start >= end case the same way the DOM does, returning a
    // zero-width rect after the advance of the character right before the end
    // position. If the position is mid-cluster, the whole cluster is added as a
    // rect.
    if (start >= end) {
      if (run_start_index <= end && end <= run_end_index) {
        const unsigned int index =
            base::CheckSub(end, run_start_index).ValueOrDie();
        float from_x =
            run_with_offset.shape_result_->CaretPositionForOffset(
                index, run_with_offset.text_, AdjustMidCluster::kToStart) +
            run_with_offset.x_position_;
        float to_x =
            run_with_offset.shape_result_->CaretPositionForOffset(
                index, run_with_offset.text_, AdjustMidCluster::kToEnd) +
            run_with_offset.x_position_;
        if (from_x < to_x) {
          selection_rects.push_back(DOMRectReadOnly::Create(
              from_x - text_align_dx_, y, to_x - from_x, height));
        } else {
          selection_rects.push_back(DOMRectReadOnly::Create(
              to_x - text_align_dx_, y, from_x - to_x, height));
        }
      }
      continue;
    }

    // Outside the required interval.
    if (run_end_index <= start || run_start_index >= end) {
      continue;
    }

    // Calculate the required indexes for this specific run.
    const unsigned int starting_index =
        start > run_start_index ? start - run_start_index : 0;
    const unsigned int ending_index = end < run_end_index
                                          ? end - run_start_index
                                          : run_with_offset.num_characters_;

    // Use caret positions to determine the start and end of the selection rect.
    float from_x =
        run_with_offset.shape_result_->CaretPositionForOffset(
            starting_index, run_with_offset.text_, AdjustMidCluster::kToStart) +
        run_with_offset.x_position_;
    float to_x =
        run_with_offset.shape_result_->CaretPositionForOffset(
            ending_index, run_with_offset.text_, AdjustMidCluster::kToEnd) +
        run_with_offset.x_position_;
    if (from_x < to_x) {
      selection_rects.push_back(DOMRectReadOnly::Create(
          from_x - text_align_dx_, y, to_x - from_x, height));
    } else {
      selection_rects.push_back(DOMRectReadOnly::Create(
          to_x - text_align_dx_, y, from_x - to_x, height));
    }
  }

  return selection_rects;
}

const DOMRectReadOnly* TextMetrics::getActualBoundingBox(
    uint32_t start,
    uint32_t end,
    ExceptionState& exception_state) {
  gfx::RectF bounding_box;

  // Checks indexes that go over the maximum for the text. For indexes less than
  // 0, an exception is thrown by [EnforceRange] in the idl binding.
  if (start >= text_.length() || end > text_.length()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        String::Format("The %s index is out of bounds.",
                       start >= text_.length() ? "start" : "end"));
    return DOMRectReadOnly::FromRectF(bounding_box);
  }

  ShapeTextIfNeeded();

  for (const auto& run_with_offset : runs_with_offset_) {
    const unsigned int run_start_index = run_with_offset.character_offset_;
    const unsigned int run_end_index =
        run_start_index + run_with_offset.num_characters_;

    // Outside the required interval.
    if (run_end_index <= start || run_start_index >= end) {
      continue;
    }

    // Position of the left border for this run.
    const double left_border = run_with_offset.x_position_;

    // Calculate the required indexes for this specific run.
    const unsigned int starting_index =
        start > run_start_index ? start - run_start_index : 0;
    const unsigned int ending_index = end < run_end_index
                                          ? end - run_start_index
                                          : run_with_offset.num_characters_;

    const ShapeResultView* view = ShapeResultView::Create(
        run_with_offset.shape_result_, 0, run_with_offset.num_characters_);
    view->ForEachGlyph(
        left_border, starting_index, ending_index, 0,
        [](void* context, unsigned character_index, Glyph glyph,
           gfx::Vector2dF glyph_offset, float total_advance, bool is_horizontal,
           CanvasRotationInVertical rotation, const SimpleFontData* font_data) {
          auto* bounding_box = static_cast<gfx::RectF*>(context);
          gfx::RectF glyph_bounds = font_data->BoundsForGlyph(glyph);
          glyph_bounds.Offset(total_advance, 0.0);
          glyph_bounds.Offset(glyph_offset);
          bounding_box->Union(glyph_bounds);
        },
        static_cast<void*>(&bounding_box));
  }
  bounding_box.Offset(-text_align_dx_, baseline_y);
  return DOMRectReadOnly::FromRectF(bounding_box);
}

namespace {
float getTextAlignDelta(float width,
                        const TextAlign& text_align,
                        const TextDirection& direction) {
  switch (text_align) {
    case kRightTextAlign:
      return width;
    case kCenterTextAlign:
      return width / 2.0f;
    case kLeftTextAlign:
      return 0;
    case kStartTextAlign:
      if (IsLtr(direction)) {
        return 0;
      }
      return width;
    case kEndTextAlign:
      if (IsLtr(direction)) {
        return width;
      }
      return 0;
  }
}

float getTextBaselineDelta(float baseline,
                           const TextBaseline& text_baseline,
                           const SimpleFontData& font_data) {
  float new_baseline = TextMetrics::GetFontBaseline(text_baseline, font_data);
  return baseline - new_baseline;
}

struct TextClusterCallbackContext {
  unsigned start_index_;
  float x_position_;
  float width_;

  void Trace(Visitor* visitor) const {}
};
}  // namespace

HeapVector<Member<TextCluster>> TextMetrics::getTextClusters(
    const TextClusterOptions* options) {
  return getTextClustersImpl(0, text_.length(), options,
                             /*exception_state=*/nullptr);
}

HeapVector<Member<TextCluster>> TextMetrics::getTextClusters(
    uint32_t start,
    uint32_t end,
    const TextClusterOptions* options,
    ExceptionState& exception_state) {
  return getTextClustersImpl(start, end, options, &exception_state);
}

HeapVector<Member<TextCluster>> TextMetrics::getTextClustersImpl(
    uint32_t start,
    uint32_t end,
    const TextClusterOptions* options,
    ExceptionState* exception_state) {
  HeapVector<Member<TextCluster>> minimal_clusters, clusters_for_range;
  // Checks indexes that go over the maximum for the text. For indexes less than
  // 0, an exception is thrown by [EnforceRange] in the idl binding.
  if (start >= text_.length() || end > text_.length()) {
    CHECK(exception_state != nullptr);
    exception_state->ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        String::Format("The %s index is out of bounds.",
                       start >= text_.length() ? "start" : "end"));
    return clusters_for_range;
  }

  TextAlign cluster_text_align;
  TextBaseline cluster_text_baseline;
  if (options == nullptr || !options->hasAlign() ||
      !ParseTextAlign(options->align(), cluster_text_align)) {
    cluster_text_align = ctx_text_align_;
  }
  if (options == nullptr || !options->hasBaseline() ||
      !ParseTextBaseline(options->baseline(), cluster_text_baseline)) {
    cluster_text_baseline = ctx_text_baseline_;
  }

  for (const auto& run_with_offset : runs_with_offset_) {
    HeapVector<TextClusterCallbackContext> clusters_for_run;

    run_with_offset.shape_result_->ForEachGraphemeClusters(
        StringView(run_with_offset.text_), run_with_offset.x_position_, 0,
        run_with_offset.num_characters_, 0,
        [](void* context, unsigned character_index, float total_advance,
           unsigned graphemes_in_cluster, float cluster_advance,
           CanvasRotationInVertical rotation) {
          auto* clusters =
              static_cast<HeapVector<TextClusterCallbackContext>*>(context);
          TextClusterCallbackContext cluster = {.start_index_ = character_index,
                                                .x_position_ = total_advance,
                                                .width_ = cluster_advance};
          clusters->push_back(cluster);
        },
        &clusters_for_run);

    std::sort(clusters_for_run.begin(), clusters_for_run.end(),
              [](TextClusterCallbackContext a, TextClusterCallbackContext b) {
                return a.start_index_ < b.start_index_;
              });

    for (wtf_size_t i = 0; i < clusters_for_run.size(); i++) {
      TextCluster* text_cluster;
      if (i + 1 < clusters_for_run.size()) {
        text_cluster = TextCluster::Create(
            text_, clusters_for_run[i].x_position_, 0,
            clusters_for_run[i].start_index_,
            clusters_for_run[i + 1].start_index_, cluster_text_align,
            cluster_text_baseline, *this);
      } else {
        text_cluster = TextCluster::Create(
            text_, clusters_for_run[i].x_position_, 0,
            clusters_for_run[i].start_index_, run_with_offset.num_characters_,
            cluster_text_align, cluster_text_baseline, *this);
      }
      text_cluster->OffsetCharacters(run_with_offset.character_offset_);
      text_cluster->OffsetPosition(
          getTextAlignDelta(clusters_for_run[i].width_, cluster_text_align,
                            direction_),
          getTextBaselineDelta(baseline_y, cluster_text_baseline,
                               *font_.PrimaryFont()));
      text_cluster->OffsetPosition(-text_align_dx_, 0);
      minimal_clusters.push_back(text_cluster);
    }
  }

  for (const auto& cluster : minimal_clusters) {
    if (cluster->end() <= start or end <= cluster->begin()) {
      continue;
    }
    clusters_for_range.push_back(cluster);
  }
  return clusters_for_range;
}

unsigned TextMetrics::caretPositionFromPoint(double x) {
  if (runs_with_offset_.empty()) {
    return 0;
  }

  // x is visual direction from the alignment point, regardless of the text
  // direction. Note x can be negative, to enable positions to the left of the
  // alignment point.
  float target_x = text_align_dx_ + x;

  // If to the left (or right), clamp to the left (or right) point
  if (target_x <= 0) {
    target_x = 0;
  }
  if (target_x >= width_) {
    target_x = width_;
  }

  ShapeTextIfNeeded();

  for (HeapVector<RunWithOffset>::reverse_iterator riter =
           runs_with_offset_.rbegin();
       riter != runs_with_offset_.rend(); riter++) {
    if (riter->x_position_ <= target_x) {
      float run_x = target_x - riter->x_position_;
      unsigned run_offset = riter->shape_result_->CaretOffsetForHitTest(
          run_x, StringView(riter->text_), BreakGlyphsOption(true));
      if (direction_ != riter->direction_) {
        return CorrectForMixedBidi(riter, run_offset);
      }
      return run_offset + riter->character_offset_;
    }
  }
  return 0;
}

unsigned TextMetrics::CorrectForMixedBidi(
    HeapVector<RunWithOffset>::reverse_iterator& riter,
    unsigned run_offset) {
  DCHECK(direction_ != riter->direction_);
  // Do our best to handle mixed direction strings. The decisions to adjust
  // are based on trying to get reasonable selection behavior when there
  // are LTR runs embedded in an RTL string or vice versa.
  if (IsRtl(direction_)) {
    if (run_offset == 0) {
      // Position is at the left edge of a LTR run within an RTL string.
      // Move it to the start of the next RTL run on its left.
      auto next_run = riter + 1;
      if (next_run != runs_with_offset_.rend()) {
        return next_run->character_offset_;
      }
    } else if (run_offset == riter->num_characters_) {
      // Position is at the right end of an LTR run embedded in RTL. Move
      // it to the last position of the RTL run to the right, which is the first
      // position of the LTR run, unless there is no run to the right.
      if (riter != runs_with_offset_.rbegin()) {
        return riter->character_offset_;
      }
    }
  } else {
    if (run_offset == 0) {
      // Position is at the right edge of a RTL run within an LTR string.
      // Move it to the start of the next LTR run on its right.
      if (riter != runs_with_offset_.rbegin()) {
        riter--;
        return riter->character_offset_;
      }
    } else if (run_offset == riter->num_characters_) {
      // Position is at the left end of an RTL run embedded in LTR. Move
      // it to the last position of the left side LTR run, unless there is
      // no run to the left.
      auto next_run = riter + 1;
      if (next_run != runs_with_offset_.rend()) {
        return next_run->character_offset_ + next_run->num_characters_;
      }
    }
  }
  return run_offset + riter->character_offset_;
}

}  // namespace blink

"""

```