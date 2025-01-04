Response:
Let's break down the thought process for analyzing this `font.cc` file and generating the comprehensive response.

**1. Initial Understanding & Scope:**

The first step is to recognize this is a C++ source file (`.cc`) within the Chromium/Blink rendering engine. The path `blink/renderer/platform/fonts/font.cc` immediately tells us it's related to font handling within the rendering pipeline. The provided copyright notices and license information are also important context but not directly functional.

**2. Core Functionality - Identifying Key Classes and Methods:**

The next step is to scan the `#include` directives. These are crucial clues to the file's purpose. We see includes for:

* `Font.h`:  This strongly suggests this file *implements* the `Font` class.
* `cc/paint/paint_canvas.h`, `cc/paint/paint_flags.h`:  Indicates drawing operations are a key part.
* `third_party/blink/renderer/platform/fonts/...`:  A whole suite of font-related classes like `FontCache`, `FontFallbackList`, `shaping` related classes, and `SimpleFontData`. This confirms the focus on font rendering.
* `third_party/blink/renderer/platform/text/...`: Classes like `TextRun`, `BidiParagraph`, `Character`. Signifies text layout and handling of bidirectional text.
* `third_party/skia/include/core/SkTextBlob.h`:  Skia is the graphics library Blink uses, and `SkTextBlob` is a key object for efficient text rendering.
* `ui/gfx/geometry/rect_f.h`:  Geometric calculations are involved.

Based on these includes, we can infer that `Font.cc` is responsible for the core logic of the `Font` class, dealing with:

* **Font selection and fallback:**  Managing which font to use.
* **Text shaping:**  Converting text into glyphs.
* **Text drawing:**  Actually rendering the glyphs to a canvas.
* **Measuring text:**  Calculating the width and bounds of text.
* **Handling bidirectional text.**
* **Emphasis marks.**
* **Selection rectangles.**
* **Hit testing (offset for position).**

**3. Analyzing Key Methods (Iterative Process):**

Now we start examining the methods defined within the `Font` class. For each method, we ask:

* **What does it do?** (Summarize its purpose)
* **What are its inputs and outputs?** (Identify key parameters and return values)
* **How does it relate to web technologies (JavaScript, HTML, CSS)?** (This is a critical part of the prompt)
* **Are there any potential user/programmer errors?** (Consider misuse or misunderstandings)
* **Does it perform any interesting logic that can be illustrated with examples?** (Hypothetical inputs/outputs)

Let's illustrate with a few examples of this iterative thought process:

* **`DrawText`:**  Clearly involves drawing text. The parameters `cc::PaintCanvas`, `TextRunPaintInfo`, `gfx::PointF`, `cc::PaintFlags` directly map to drawing on a canvas with specific style and position. The connection to CSS is evident (font styles, colors). An error could be attempting to draw with an invalid canvas.

* **`DrawBidiText`:**  The name suggests handling bidirectional text. The presence of `BidiParagraph` confirms this. The connection to HTML/CSS is in how text direction is specified (e.g., `dir` attribute). A user error could be incorrect markup leading to unexpected text ordering.

* **`Width` and `SubRunWidth`:**  These are about measuring text. They are used internally by the layout engine and can be accessed via JavaScript APIs like `measureText`. A programmer error could be assuming pixel-perfect measurements across different platforms.

* **`OffsetForPosition`:** This method does hit-testing – finding the character index at a given position. It's crucial for text selection and cursor placement. A tricky scenario is with complex scripts or combined characters.

* **Methods related to emphasis marks (`DrawEmphasisMarks`, `EmphasisMarkAscent`, etc.):** These directly relate to the CSS `text-emphasis` property.

**4. Identifying Connections to Web Technologies:**

This step requires knowledge of how the rendering engine connects to the web platform.

* **JavaScript:**  Methods like `Width` are directly exposed or used to implement JavaScript APIs related to text measurement (e.g., `CanvasRenderingContext2D.measureText()`).
* **HTML:**  The `Font` class is used to render text content from HTML elements. The `dir` attribute affects `DrawBidiText`.
* **CSS:**  CSS properties like `font-family`, `font-size`, `font-weight`, `font-style`, `color`, and `text-emphasis` directly influence the `FontDescription` and the drawing process.

**5. Considering Potential Errors:**

Think about common mistakes developers might make when dealing with fonts and text:

* **Missing fonts:**  The fallback mechanism handles this, but it's still a potential issue.
* **Incorrect character encoding:** Can lead to garbled text.
* **Assuming consistent rendering across platforms:** Font rendering can differ slightly.
* **Misunderstanding bidirectional text:**  Leading to incorrect text display for languages like Arabic or Hebrew.
* **Performance issues:**  Excessive font lookups or complex text shaping can be slow.

**6. Structuring the Response:**

Finally, organize the information into a clear and logical structure, as demonstrated in the provided example output. Use headings and bullet points for readability. Categorize the functionality, connections to web technologies, examples, and potential errors. This makes the information much easier to understand.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus only on drawing.
* **Correction:** Realize that measurement and font selection are equally important functions within `Font.cc`.
* **Initial thought:** Provide only high-level descriptions.
* **Refinement:**  Include specific examples of how methods relate to JavaScript, HTML, and CSS properties.
* **Initial thought:**  Focus on obvious errors like missing fonts.
* **Refinement:** Consider more subtle errors like platform inconsistencies or misunderstanding bidirectional text.

By following this structured and iterative process, we can effectively analyze a complex source code file and generate a comprehensive and informative response. The key is to understand the core purpose, identify key components, analyze individual functionalities, and connect them back to the broader context of web technologies.
好的，让我们来详细分析一下 `blink/renderer/platform/fonts/font.cc` 这个文件。

**文件功能概要：**

`font.cc` 文件是 Chromium Blink 渲染引擎中 `Font` 类的实现文件。`Font` 类是 Blink 中处理字体相关操作的核心类之一。它封装了特定字体的信息（如字体描述、字体选择器）并提供了执行与该字体相关的各种操作的方法。

其主要功能包括：

1. **字体信息的存储和管理:**  存储和管理字体的描述信息 (`FontDescription`) 和字体选择器 (`FontSelector`)。
2. **字体回退列表的管理:**  维护和获取字体的回退列表 (`FontFallbackList`)，用于在当前字体无法渲染某些字符时查找合适的替代字体。
3. **文本绘制:**  提供各种方法在 `cc::PaintCanvas` 上绘制文本，包括：
    * 单向文本绘制 (`DrawText`)
    * 双向文本绘制 (`DrawBidiText`)
    * 强调标记绘制 (`DrawEmphasisMarks`)
4. **文本度量:**  提供方法来测量文本的各种属性，如宽度 (`Width`, `SubRunWidth`)、墨迹边界 (`TextInkBounds`)。
5. **文本截取 (Text Intercepts):**  获取文本在指定垂直范围内的水平截取区间，用于绘制选中文本的背景。
6. **选择矩形计算:**  计算文本指定范围的选择矩形 (`SelectionRectForText`)。
7. **光标位置计算:**  根据给定的水平位置，计算文本中最接近的字符偏移量 (`OffsetForPosition`)，用于实现光标定位。
8. **字形缓存访问:**  提供访问字形缓存 (`NGShapeCache`, `ShapeCache`) 的接口，以提高文本渲染性能。
9. **字形缺失报告:**  提供报告字形缺失 (NotDef Glyph) 和 Emoji 字形覆盖率的机制，用于统计和分析字体支持情况。
10. **预热字体数据:**  提供预热字体数据的功能 (`WillUseFontData`)，以优化字体加载性能。
11. **制表符宽度计算:**  计算制表符的宽度 (`TabWidth`)。
12. **强调标记相关属性获取:**  获取强调标记的 ascent, descent, height 等属性。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`Font.cc` 文件中的 `Font` 类是渲染引擎内部实现，但其功能与 JavaScript, HTML, CSS 息息相关，因为网页上的文本最终需要通过这个类来渲染和度量。

* **CSS:**
    * **字体属性:** CSS 的 `font-family`, `font-size`, `font-weight`, `font-style` 等属性最终会被解析并传递给 `FontDescription`，从而影响 `Font` 对象的创建和文本渲染。
        * **举例:**  CSS 中定义 `font-family: "Arial", sans-serif;` 将导致 Blink 创建一个 `Font` 对象，其 `FontDescription` 中包含了 Arial 字体和 `sans-serif` 作为回退字体。
    * **文本绘制属性:** CSS 的 `color`, `text-decoration`, `text-shadow` 等属性会影响传递给 `DrawText` 等方法的 `cc::PaintFlags`，从而影响文本的颜色、下划线、阴影等外观。
        * **举例:** CSS 中定义 `color: blue;` 会在调用 `DrawText` 时，`cc::PaintFlags` 中包含蓝色信息，文本最终会以蓝色绘制。
    * **双向文本:** CSS 的 `direction` 和 `unicode-bidi` 属性会影响双向文本的布局和渲染，`DrawBidiText` 方法会根据这些信息正确地排列文本。
        * **举例:** HTML 中使用 `<p dir="rtl">مرحبا بالعالم</p>`，CSS 中可能设置 `unicode-bidi: bidi-override;`，`DrawBidiText` 会根据这些信息将阿拉伯文本从右向左绘制。
    * **强调标记:** CSS 的 `text-emphasis-style`, `text-emphasis-color`, `text-emphasis-position` 属性对应 `DrawEmphasisMarks` 方法的功能。
        * **举例:** CSS 中定义 `text-emphasis-style: dot;` 会调用 `DrawEmphasisMarks` 并使用点状标记来绘制强调符号。
    * **制表符:** CSS 的 `tab-size` 属性会影响 `TabWidth` 方法的计算结果。
        * **举例:** CSS 中定义 `tab-size: 4;` 将影响制表符的渲染宽度。

* **HTML:**
    * **文本内容:** HTML 标签中的文本内容是 `Font` 类渲染的主要对象。
        * **举例:** `<div>This is some text.</div>` 中的 "This is some text." 将被转换为 `TextRun` 对象，并最终由 `Font` 类进行渲染。
    * **语言属性:** HTML 的 `lang` 属性可以影响字体选择和文本的排版规则。
        * **举例:**  `<p lang="ja">こんにちは</p>` 可以帮助 Blink 选择更适合日语的字体进行渲染。

* **JavaScript:**
    * **Canvas API:** JavaScript 的 Canvas API 允许开发者直接控制像素级的绘制，`Font` 类的 `DrawText` 等方法与 Canvas API 的文本绘制功能紧密相关。
        * **举例:** JavaScript 中使用 `context.fillText("Hello", 10, 50);` 最终会调用 Blink 内部的文本绘制逻辑，其中会使用 `Font` 类来获取字形信息并进行绘制。
    * **Text Metrics API:** JavaScript 的 `CanvasRenderingContext2D.measureText()` 方法允许开发者获取文本的度量信息（如宽度）。这个方法在 Blink 内部会调用 `Font` 类的 `Width` 等方法来实现。
        * **举例:** JavaScript 中 `const width = context.measureText("Hello").width;`  会触发 Blink 调用 `Font::Width` 来计算 "Hello" 的宽度。

**逻辑推理举例：**

假设输入一段阿拉伯文本和一个支持阿拉伯语的字体。

* **假设输入:**
    * `TextRun`:  包含阿拉伯语文本 "مرحبا" (marhabaan)
    * `FontDescription`:  指定字体为 "Arial" (假设系统有合适的 Arial 字体支持阿拉伯语)
    * 调用 `DrawBidiText` 方法

* **逻辑推理:**
    1. `DrawBidiText` 会识别出文本是双向的（阿拉伯语是从右向左）。
    2. 它可能会调用 `BidiParagraph` 类来处理双向文本的布局。
    3. 它会使用 `FontFallbackList` 查找 "Arial" 字体中是否包含渲染 "مرحبا" 中字符的字形。
    4. 如果 "Arial" 字体支持，则会使用 "Arial" 的字形进行绘制，绘制顺序是从右到左。
    5. 如果 "Arial" 字体不支持某些字符，则会查找回退字体列表并尝试使用回退字体进行渲染。

* **假设输出:**
    * 在 Canvas 上正确地从右向左渲染出 "مرحبا" 这个词。

**用户或编程常见的使用错误举例：**

1. **字体缺失:**  用户在 CSS 中指定了系统中不存在的字体名称。
    * **后果:**  `FontFallbackList` 会尝试回退到其他字体，可能导致文本显示与预期不符。
    * **例子:**  CSS 中设置 `font-family: "MyCustomFont";` 但用户系统中没有安装 "MyCustomFont" 字体。浏览器可能会使用默认的 `serif` 或 `sans-serif` 字体来渲染。

2. **字符编码错误:**  文本的编码与字体支持的编码不一致，导致乱码。
    * **后果:**  即使字体存在，也可能无法正确显示字符。
    * **例子:**  HTML 文件编码为 UTF-8，但字体文件只支持 Latin-1 编码，显示一些非 ASCII 字符时会出现问题。

3. **错误的双向文本标记:**  对于需要从右向左显示的文本，没有正确使用 `dir="rtl"` 属性，或者 `unicode-bidi` 属性设置不当。
    * **后果:**  双向文本的显示顺序可能错误。
    * **例子:**  阿拉伯语文本没有设置 `dir="rtl"`，可能导致浏览器按照从左到右的顺序渲染。

4. **过度依赖特定字体:**  开发者在设计网页时过度依赖某种特定字体，而没有考虑用户系统中可能不存在该字体的情况。
    * **后果:**  在缺少该字体的系统中，网页的排版可能会变得很糟糕。
    * **建议:**  在 CSS 的 `font-family` 属性中提供多个回退字体，并使用通用的字体族名称 (如 `serif`, `sans-serif`) 作为最后的保障。

5. **在 Canvas 中绘制文本时未考虑字体加载完成:**  如果使用自定义字体，在字体加载完成之前就尝试在 Canvas 上绘制文本，可能导致绘制失败或使用回退字体绘制，然后在字体加载完成后重新绘制，造成闪烁。
    * **建议:**  监听字体加载事件 (例如使用 FontFace API)，确保字体加载完成后再进行绘制。

总而言之，`blink/renderer/platform/fonts/font.cc` 文件中的 `Font` 类是 Blink 渲染引擎中处理字体和文本渲染的核心组件，它与 CSS 样式、HTML 结构以及 JavaScript 的文本操作 API 都有着密切的联系，共同决定了网页上文本的最终呈现效果。理解其功能有助于我们更好地理解浏览器如何渲染文本，并能帮助开发者避免一些常见的文本显示问题。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/font.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2000 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2003, 2006, 2010, 2011 Apple Inc. All rights reserved.
 * Copyright (c) 2007, 2008, 2010 Google Inc. All rights reserved.
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/fonts/font.h"

#include "cc/paint/paint_canvas.h"
#include "cc/paint/paint_flags.h"
#include "third_party/blink/renderer/platform/fonts/character_range.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_fallback_list.h"
#include "third_party/blink/renderer/platform/fonts/font_fallback_map.h"
#include "third_party/blink/renderer/platform/fonts/shaping/caching_word_shaper.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_shaper.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_bloberizer.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_spacing.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/fonts/simple_font_data.h"
#include "third_party/blink/renderer/platform/fonts/text_fragment_paint_info.h"
#include "third_party/blink/renderer/platform/fonts/text_run_paint_info.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/text/bidi_paragraph.h"
#include "third_party/blink/renderer/platform/text/character.h"
#include "third_party/blink/renderer/platform/text/text_run.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"
#include "third_party/skia/include/core/SkTextBlob.h"
#include "ui/gfx/geometry/rect_f.h"

namespace blink {

namespace {

FontFallbackList* GetOrCreateFontFallbackList(
    const FontDescription& font_description,
    FontSelector* font_selector) {
  FontFallbackMap& fallback_map = font_selector
                                      ? font_selector->GetFontFallbackMap()
                                      : FontCache::Get().GetFontFallbackMap();
  return fallback_map.Get(font_description);
}

}  // namespace

Font::Font() = default;

Font::Font(const FontDescription& fd) : font_description_(fd) {}

Font::Font(const FontDescription& font_description, FontSelector* font_selector)
    : font_description_(font_description),
      font_fallback_list_(
          font_selector
              ? GetOrCreateFontFallbackList(font_description, font_selector)
              : nullptr) {}

FontFallbackList* Font::EnsureFontFallbackList() const {
  if (!font_fallback_list_ || !font_fallback_list_->IsValid()) {
    font_fallback_list_ =
        GetOrCreateFontFallbackList(font_description_, GetFontSelector());
  }
  return font_fallback_list_.Get();
}

bool Font::operator==(const Font& other) const {
  // Font objects with the same FontDescription and FontSelector should always
  // hold reference to the same FontFallbackList object, unless invalidated.
  if (font_fallback_list_ && font_fallback_list_->IsValid() &&
      other.font_fallback_list_ && other.font_fallback_list_->IsValid()) {
    return font_fallback_list_ == other.font_fallback_list_;
  }

  return GetFontSelector() == other.GetFontSelector() &&
         font_description_ == other.font_description_;
}

namespace {

void DrawBlobs(cc::PaintCanvas* canvas,
               const cc::PaintFlags& flags,
               const ShapeResultBloberizer::BlobBuffer& blobs,
               const gfx::PointF& point,
               cc::NodeId node_id = cc::kInvalidNodeId) {
  for (const auto& blob_info : blobs) {
    DCHECK(blob_info.blob);
    cc::PaintCanvasAutoRestore auto_restore(canvas, false);
    switch (blob_info.rotation) {
      case CanvasRotationInVertical::kRegular:
        break;
      case CanvasRotationInVertical::kRotateCanvasUpright: {
        canvas->save();

        SkMatrix m;
        m.setSinCos(-1, 0, point.x(), point.y());
        canvas->concat(SkM44(m));
        break;
      }
      case CanvasRotationInVertical::kRotateCanvasUprightOblique: {
        canvas->save();

        SkMatrix m;
        m.setSinCos(-1, 0, point.x(), point.y());
        // TODO(yosin): We should use angle specified in CSS instead of
        // constant value -15deg.
        // Note: We draw glyph in right-top corner upper.
        // See CSS "transform: skew(0, -15deg)"
        SkMatrix skewY;
        constexpr SkScalar kSkewY = -0.2679491924311227;  // tan(-15deg)
        skewY.setSkew(0, kSkewY, point.x(), point.y());
        m.preConcat(skewY);
        canvas->concat(SkM44(m));
        break;
      }
      case CanvasRotationInVertical::kOblique: {
        // TODO(yosin): We should use angle specified in CSS instead of
        // constant value 15deg.
        // Note: We draw glyph in right-top corner upper.
        // See CSS "transform: skew(0, -15deg)"
        canvas->save();
        SkMatrix skewX;
        constexpr SkScalar kSkewX = 0.2679491924311227;  // tan(15deg)
        skewX.setSkew(kSkewX, 0, point.x(), point.y());
        canvas->concat(SkM44(skewX));
        break;
      }
    }
    if (node_id != cc::kInvalidNodeId) {
      canvas->drawTextBlob(blob_info.blob, point.x(), point.y(), node_id,
                           flags);
    } else {
      canvas->drawTextBlob(blob_info.blob, point.x(), point.y(), flags);
    }
  }
}

}  // anonymous ns

void Font::DrawText(cc::PaintCanvas* canvas,
                    const TextRunPaintInfo& run_info,
                    const gfx::PointF& point,
                    const cc::PaintFlags& flags,
                    DrawType draw_type) const {
  DrawText(canvas, run_info, point, cc::kInvalidNodeId, flags, draw_type);
}

void Font::DrawText(cc::PaintCanvas* canvas,
                    const TextRunPaintInfo& run_info,
                    const gfx::PointF& point,
                    cc::NodeId node_id,
                    const cc::PaintFlags& flags,
                    DrawType draw_type) const {
  // Don't draw anything while we are using custom fonts that are in the process
  // of loading.
  if (ShouldSkipDrawing())
    return;

  CachingWordShaper word_shaper(*this);
  ShapeResultBuffer buffer;
  word_shaper.FillResultBuffer(run_info, &buffer);
  ShapeResultBloberizer::FillGlyphs bloberizer(
      GetFontDescription(), run_info, buffer,
      draw_type == Font::DrawType::kGlyphsOnly
          ? ShapeResultBloberizer::Type::kNormal
          : ShapeResultBloberizer::Type::kEmitText);
  DrawBlobs(canvas, flags, bloberizer.Blobs(), point, node_id);
}

void Font::DrawText(cc::PaintCanvas* canvas,
                    const TextFragmentPaintInfo& text_info,
                    const gfx::PointF& point,
                    cc::NodeId node_id,
                    const cc::PaintFlags& flags,
                    DrawType draw_type) const {
  // Don't draw anything while we are using custom fonts that are in the process
  // of loading.
  if (ShouldSkipDrawing())
    return;

  ShapeResultBloberizer::FillGlyphsNG bloberizer(
      GetFontDescription(), text_info.text, text_info.from, text_info.to,
      text_info.shape_result,
      draw_type == Font::DrawType::kGlyphsOnly
          ? ShapeResultBloberizer::Type::kNormal
          : ShapeResultBloberizer::Type::kEmitText);
  DrawBlobs(canvas, flags, bloberizer.Blobs(), point, node_id);
}

bool Font::DrawBidiText(cc::PaintCanvas* canvas,
                        const TextRunPaintInfo& run_info,
                        const gfx::PointF& point,
                        CustomFontNotReadyAction custom_font_not_ready_action,
                        const cc::PaintFlags& flags,
                        DrawType draw_type) const {
  // Don't draw anything while we are using custom fonts that are in the process
  // of loading, except if the 'force' argument is set to true (in which case it
  // will use a fallback font).
  if (ShouldSkipDrawing() &&
      custom_font_not_ready_action == kDoNotPaintIfFontNotReady)
    return false;

  const TextRun& run = run_info.run;
  if (!run.length()) {
    return true;
  }
  bool is_sub_run = (run_info.from != 0 || run_info.to != run.length());

  if (run.DirectionalOverride()) [[unlikely]] {
    // If directional override, create a new string with Unicode directional
    // override characters.
    const String text_with_override =
        BidiParagraph::StringWithDirectionalOverride(run.ToStringView(),
                                                     run.Direction());
    TextRun run_with_override = run_info.run;
    run_with_override.SetText(text_with_override);
    run_with_override.SetDirectionalOverride(false);
    return DrawBidiText(canvas, TextRunPaintInfo(run_with_override), point,
                        custom_font_not_ready_action, flags, draw_type);
  }

  BidiParagraph::Runs bidi_runs;
  if (run.Is8Bit() && IsLtr(run.Direction())) {
    // U+0000-00FF are L or neutral, it's unidirectional if 8 bits and LTR.
    bidi_runs.emplace_back(0, run.length(), 0);
  } else {
    String text = run.ToStringView().ToString();
    text.Ensure16Bit();
    BidiParagraph bidi(text, run.Direction());
    bidi.GetVisualRuns(text, &bidi_runs);
  }

  gfx::PointF curr_point = point;
  CachingWordShaper word_shaper(*this);
  for (const BidiParagraph::Run& bidi_run : bidi_runs) {
    if (bidi_run.end <= run_info.from || run_info.to <= bidi_run.start) {
      continue;
    }

    TextRun subrun = run.SubRun(bidi_run.start, bidi_run.Length());
    subrun.SetDirection(bidi_run.Direction());

    TextRunPaintInfo subrun_info(subrun);
    CharacterRange range(0, 0, 0, 0);
    if (is_sub_run) [[unlikely]] {
      // Calculate the required indexes for this specific run.
      subrun_info.from =
          run_info.from < bidi_run.start ? 0 : run_info.from - bidi_run.start;
      subrun_info.to = run_info.to > bidi_run.end
                           ? bidi_run.Length()
                           : run_info.to - bidi_run.start;
      // The range provides information required for positioning the subrun.
      range = word_shaper.GetCharacterRange(subrun, subrun_info.from,
                                            subrun_info.to);
    }

    ShapeResultBuffer buffer;
    word_shaper.FillResultBuffer(subrun_info, &buffer);

    // Fix regression with -ftrivial-auto-var-init=pattern. See
    // crbug.com/1055652.
    STACK_UNINITIALIZED ShapeResultBloberizer::FillGlyphs bloberizer(
        GetFontDescription(), subrun_info, buffer,
        draw_type == Font::DrawType::kGlyphsOnly
            ? ShapeResultBloberizer::Type::kNormal
            : ShapeResultBloberizer::Type::kEmitText);
    if (is_sub_run) [[unlikely]] {
      // Align the subrun with the point given.
      curr_point.Offset(-range.start, 0);
    }
    DrawBlobs(canvas, flags, bloberizer.Blobs(), curr_point);

    if (is_sub_run) [[unlikely]] {
      curr_point.Offset(range.Width(), 0);
    } else {
      curr_point.Offset(bloberizer.Advance(), 0);
    }
  }
  return true;
}

void Font::DrawEmphasisMarks(cc::PaintCanvas* canvas,
                             const TextRunPaintInfo& run_info,
                             const AtomicString& mark,
                             const gfx::PointF& point,
                             const cc::PaintFlags& flags) const {
  if (ShouldSkipDrawing())
    return;

  FontCachePurgePreventer purge_preventer;

  const auto emphasis_glyph_data = GetEmphasisMarkGlyphData(mark);
  if (!emphasis_glyph_data.font_data)
    return;

  CachingWordShaper word_shaper(*this);
  ShapeResultBuffer buffer;
  word_shaper.FillResultBuffer(run_info, &buffer);
  ShapeResultBloberizer::FillTextEmphasisGlyphs bloberizer(
      GetFontDescription(), run_info, buffer, emphasis_glyph_data);
  DrawBlobs(canvas, flags, bloberizer.Blobs(), point);
}

void Font::DrawEmphasisMarks(cc::PaintCanvas* canvas,
                             const TextFragmentPaintInfo& text_info,
                             const AtomicString& mark,
                             const gfx::PointF& point,
                             const cc::PaintFlags& flags) const {
  if (ShouldSkipDrawing())
    return;

  FontCachePurgePreventer purge_preventer;
  const auto emphasis_glyph_data = GetEmphasisMarkGlyphData(mark);
  if (!emphasis_glyph_data.font_data)
    return;

  ShapeResultBloberizer::FillTextEmphasisGlyphsNG bloberizer(
      GetFontDescription(), text_info.text, text_info.from, text_info.to,
      text_info.shape_result, emphasis_glyph_data);
  DrawBlobs(canvas, flags, bloberizer.Blobs(), point);
}

gfx::RectF Font::TextInkBounds(const TextFragmentPaintInfo& text_info) const {
  // No need to compute bounds if using custom fonts that are in the process
  // of loading as it won't be painted.
  if (ShouldSkipDrawing())
    return gfx::RectF();

  // NOTE(eae): We could use the SkTextBlob::bounds API [1] however by default
  // it returns conservative bounds (rather than tight bounds) which are
  // unsuitable for our needs. If we could get the tight bounds from Skia that
  // would be quite a bit faster than the two-stage approach employed by the
  // ShapeResultView::ComputeInkBounds method.
  // 1: https://skia.org/user/api/SkTextBlob_Reference#SkTextBlob_bounds
  return text_info.shape_result->ComputeInkBounds();
}

float Font::Width(const TextRun& run, gfx::RectF* glyph_bounds) const {
  FontCachePurgePreventer purge_preventer;
  CachingWordShaper shaper(*this);
  return shaper.Width(run, glyph_bounds);
}

float Font::SubRunWidth(const TextRun& run,
                        unsigned from,
                        unsigned to,
                        gfx::RectF* glyph_bounds) const {
  if (run.length() == 0) {
    return 0;
  }

  FontCachePurgePreventer purge_preventer;
  CachingWordShaper shaper(*this);

  // Run bidi algorithm on the given text. Step 5 of:
  // https://html.spec.whatwg.org/multipage/canvas.html#text-preparation-algorithm
  String text16 = run.ToStringView().ToString();
  text16.Ensure16Bit();
  BidiParagraph bidi;
  bidi.SetParagraph(text16, run.Direction());
  BidiParagraph::Runs runs;
  bidi.GetVisualRuns(text16, &runs);

  float x_pos = 0;
  for (const BidiParagraph::Run& visual_run : runs) {
    if (visual_run.end <= from || to <= visual_run.start) {
      continue;
    }
    // Calculate the required indexes for this specific run.
    unsigned run_from = from < visual_run.start ? 0 : from - visual_run.start;
    unsigned run_to =
        to > visual_run.end ? visual_run.Length() : to - visual_run.start;

    // Measure the subrun.
    TextRun text_run(
        StringView(run.ToStringView(), visual_run.start, visual_run.Length()),
        visual_run.Direction(), /* directional_override */ false);
    text_run.SetNormalizeSpace(true);
    CharacterRange character_range =
        shaper.GetCharacterRange(text_run, run_from, run_to);

    // Accumulate the position and the glyph bounding box.
    if (glyph_bounds) {
      gfx::RectF range_bounds(character_range.start, -character_range.ascent,
                              character_range.Width(),
                              character_range.Height());
      // GetCharacterRange() returns bounds positioned as if the whole run was
      // there, so the rect has to be moved to align with the current position.
      range_bounds.Offset(-range_bounds.x() + x_pos, 0);
      glyph_bounds->Union(range_bounds);
    }
    x_pos += character_range.Width();
  }
  if (glyph_bounds != nullptr) {
    glyph_bounds->Offset(-glyph_bounds->x(), 0);
  }
  return x_pos;
}

namespace {  // anonymous namespace

unsigned InterceptsFromBlobs(const ShapeResultBloberizer::BlobBuffer& blobs,
                             const SkPaint& paint,
                             const std::tuple<float, float>& bounds,
                             SkScalar* intercepts_buffer) {
  SkScalar bounds_array[2] = {std::get<0>(bounds), std::get<1>(bounds)};

  unsigned num_intervals = 0;
  for (const auto& blob_info : blobs) {
    DCHECK(blob_info.blob);

    // ShapeResultBloberizer splits for a new blob rotation, but does not split
    // for a change in font. A TextBlob can contain runs with differing fonts
    // and the getTextBlobIntercepts method handles multiple fonts for us. For
    // upright in vertical blobs we currently have to bail, see crbug.com/655154
    if (IsCanvasRotationInVerticalUpright(blob_info.rotation))
      continue;

    SkScalar* offset_intercepts_buffer = nullptr;
    if (intercepts_buffer)
      offset_intercepts_buffer = &intercepts_buffer[num_intervals];
    num_intervals += blob_info.blob->getIntercepts(
        bounds_array, offset_intercepts_buffer, &paint);
  }
  return num_intervals;
}

void GetTextInterceptsInternal(const ShapeResultBloberizer::BlobBuffer& blobs,
                               const cc::PaintFlags& flags,
                               const std::tuple<float, float>& bounds,
                               Vector<Font::TextIntercept>& intercepts) {
  // Get the number of intervals, without copying the actual values by
  // specifying nullptr for the buffer, following the Skia allocation model for
  // retrieving text intercepts.
  SkPaint paint = flags.ToSkPaint();
  unsigned num_intervals = InterceptsFromBlobs(blobs, paint, bounds, nullptr);
  if (!num_intervals)
    return;
  DCHECK_EQ(num_intervals % 2, 0u);
  intercepts.resize(num_intervals / 2u);

  InterceptsFromBlobs(blobs, paint, bounds,
                      reinterpret_cast<SkScalar*>(intercepts.data()));
}

}  // anonymous namespace

void Font::GetTextIntercepts(const TextRunPaintInfo& run_info,
                             const cc::PaintFlags& flags,
                             const std::tuple<float, float>& bounds,
                             Vector<TextIntercept>& intercepts) const {
  if (ShouldSkipDrawing())
    return;

  CachingWordShaper word_shaper(*this);
  ShapeResultBuffer buffer;
  word_shaper.FillResultBuffer(run_info, &buffer);
  ShapeResultBloberizer::FillGlyphs bloberizer(
      GetFontDescription(), run_info, buffer,
      ShapeResultBloberizer::Type::kTextIntercepts);

  GetTextInterceptsInternal(bloberizer.Blobs(), flags, bounds, intercepts);
}

void Font::GetTextIntercepts(const TextFragmentPaintInfo& text_info,
                             const cc::PaintFlags& flags,
                             const std::tuple<float, float>& bounds,
                             Vector<TextIntercept>& intercepts) const {
  if (ShouldSkipDrawing())
    return;

  ShapeResultBloberizer::FillGlyphsNG bloberizer(
      GetFontDescription(), text_info.text, text_info.from, text_info.to,
      text_info.shape_result, ShapeResultBloberizer::Type::kTextIntercepts);

  GetTextInterceptsInternal(bloberizer.Blobs(), flags, bounds, intercepts);
}

static inline gfx::RectF PixelSnappedSelectionRect(const gfx::RectF& rect) {
  // Using roundf() rather than ceilf() for the right edge as a compromise to
  // ensure correct caret positioning.
  float rounded_x = roundf(rect.x());
  return gfx::RectF(rounded_x, rect.y(), roundf(rect.right() - rounded_x),
                    rect.height());
}

gfx::RectF Font::SelectionRectForText(const TextRun& run,
                                      const gfx::PointF& point,
                                      float height,
                                      int from,
                                      int to) const {
  to = (to == -1 ? run.length() : to);

  FontCachePurgePreventer purge_preventer;

  CachingWordShaper shaper(*this);
  CharacterRange range = shaper.GetCharacterRange(run, from, to);

  return PixelSnappedSelectionRect(
      gfx::RectF(point.x() + range.start, point.y(), range.Width(), height));
}

int Font::OffsetForPosition(const TextRun& run,
                            float x_float,
                            IncludePartialGlyphsOption partial_glyphs,
                            BreakGlyphsOption break_glyphs) const {
  FontCachePurgePreventer purge_preventer;
  CachingWordShaper shaper(*this);
  return shaper.OffsetForPosition(run, x_float, partial_glyphs, break_glyphs);
}

NGShapeCache& Font::GetNGShapeCache() const {
  return EnsureFontFallbackList()->GetNGShapeCache(font_description_);
}

ShapeCache* Font::GetShapeCache() const {
  return EnsureFontFallbackList()->GetShapeCache(font_description_);
}

bool Font::CanShapeWordByWord() const {
  return EnsureFontFallbackList()->CanShapeWordByWord(GetFontDescription());
}

void Font::ReportNotDefGlyph() const {
  FontSelector* fontSelector = EnsureFontFallbackList()->GetFontSelector();
  // We have a few non-DOM usages of Font code, for example in DragImage::Create
  // and in EmbeddedObjectPainter::paintReplaced. In those cases, we can't
  // retrieve a font selector as our connection to a Document object to report
  // UseCounter metrics, and thus we cannot report notdef glyphs.
  if (fontSelector)
    fontSelector->ReportNotDefGlyph();
}

void Font::ReportEmojiSegmentGlyphCoverage(unsigned num_clusters,
                                           unsigned num_broken_clusters) const {
  FontSelector* fontSelector = EnsureFontFallbackList()->GetFontSelector();
  // See ReportNotDefGlyph(), sometimes no fontSelector is available in non-DOM
  // usages of Font.
  if (fontSelector) {
    fontSelector->ReportEmojiSegmentGlyphCoverage(num_clusters,
                                                  num_broken_clusters);
  }
}

void Font::WillUseFontData(const String& text) const {
  const FontDescription& font_description = GetFontDescription();
  const FontFamily& family = font_description.Family();
  if (family.FamilyName().empty()) [[unlikely]] {
    return;
  }
  if (FontSelector* font_selector = GetFontSelector()) {
    font_selector->WillUseFontData(font_description, family, text);
    return;
  }
  // Non-DOM usages can't resolve generic family.
  if (family.IsPrewarmed() || family.FamilyIsGeneric())
    return;
  family.SetIsPrewarmed();
  FontCache::PrewarmFamily(family.FamilyName());
}

GlyphData Font::GetEmphasisMarkGlyphData(const AtomicString& mark) const {
  if (mark.empty())
    return GlyphData();
  return CachingWordShaper(*this).EmphasisMarkGlyphData(TextRun(mark));
}

int Font::EmphasisMarkAscent(const AtomicString& mark) const {
  FontCachePurgePreventer purge_preventer;

  const auto mark_glyph_data = GetEmphasisMarkGlyphData(mark);
  const SimpleFontData* mark_font_data = mark_glyph_data.font_data;
  if (!mark_font_data)
    return 0;

  return mark_font_data->GetFontMetrics().Ascent();
}

int Font::EmphasisMarkDescent(const AtomicString& mark) const {
  FontCachePurgePreventer purge_preventer;

  const auto mark_glyph_data = GetEmphasisMarkGlyphData(mark);
  const SimpleFontData* mark_font_data = mark_glyph_data.font_data;
  if (!mark_font_data)
    return 0;

  return mark_font_data->GetFontMetrics().Descent();
}

int Font::EmphasisMarkHeight(const AtomicString& mark) const {
  FontCachePurgePreventer purge_preventer;

  const auto mark_glyph_data = GetEmphasisMarkGlyphData(mark);
  const SimpleFontData* mark_font_data = mark_glyph_data.font_data;
  if (!mark_font_data)
    return 0;

  return mark_font_data->GetFontMetrics().Height();
}

float Font::TabWidth(const SimpleFontData* font_data,
                     const TabSize& tab_size,
                     float position) const {
  float base_tab_width = TabWidth(font_data, tab_size);
  if (!base_tab_width)
    return GetFontDescription().LetterSpacing();

  float distance_to_tab_stop = base_tab_width - fmodf(position, base_tab_width);

  // Let the minimum width be the half of the space width so that it's always
  // recognizable.  if the distance to the next tab stop is less than that,
  // advance an additional tab stop.
  if (distance_to_tab_stop < font_data->SpaceWidth() / 2)
    distance_to_tab_stop += base_tab_width;

  return distance_to_tab_stop;
}

LayoutUnit Font::TabWidth(const TabSize& tab_size, LayoutUnit position) const {
  const SimpleFontData* font_data = PrimaryFont();
  if (!font_data)
    return LayoutUnit::FromFloatCeil(GetFontDescription().LetterSpacing());
  float base_tab_width = tab_size.GetPixelSize(font_data->SpaceWidth());
  if (!base_tab_width)
    return LayoutUnit::FromFloatCeil(GetFontDescription().LetterSpacing());

  LayoutUnit distance_to_tab_stop = LayoutUnit::FromFloatFloor(
      base_tab_width - fmodf(position, base_tab_width));

  // Let the minimum width be the half of the space width so that it's always
  // recognizable.  if the distance to the next tab stop is less than that,
  // advance an additional tab stop.
  if (distance_to_tab_stop < font_data->SpaceWidth() / 2)
    distance_to_tab_stop += base_tab_width;

  return distance_to_tab_stop;
}

bool Font::IsFallbackValid() const {
  return !font_fallback_list_ || font_fallback_list_->IsValid();
}

}  // namespace blink

"""

```