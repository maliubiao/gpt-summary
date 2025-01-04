Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The primary goal is to analyze the provided C++ code snippet (`han_kerning.cc`) and explain its functionality, its relationship to web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning with input/output, and highlight potential user or programming errors.

2. **Initial Code Scan (Keywords and Structure):**  I quickly scanned the code for keywords and structure to get a high-level understanding. Keywords like `HanKerning`, `CharType`, `FontData`, `Compute`, `OpenTypeFeatures`, `HarfBuzzShaper`, `SkRect`, and tags like `halt`, `vhal`, `chws` stood out. The presence of namespaces (`blink`), helper functions, and methods within the `HanKerning` class suggested a well-organized module. The `#include` directives confirmed its connection to font rendering and shaping within the Chromium project.

3. **Identify Core Functionality:** Based on the keywords and structure, I deduced the core functionality:  This code is responsible for **Han Kerning**, which is a technique to adjust spacing between East Asian (CJK) characters for better visual appearance. It looks at character types, font features, and glyph boundaries to decide if and how to adjust spacing.

4. **Dissect Key Components:** I then broke down the code into its major components and analyzed their purpose:

    * **`ExclusiveFeatures()` and `IsExclusiveFeature()`:**  These identify OpenType features that are mutually exclusive, meaning only one of them can be active at a time. This is important for preventing conflicting spacing adjustments.
    * **`GetAdvance()`:**  A simple helper to get the horizontal or vertical advance of a glyph.
    * **`CharTypeFromBounds()`:**  Crucial functions that determine the "character type" (Open, Close, Middle, etc.) based on the glyph's bounding box relative to its advance. This is the core of the Han kerning logic – categorizing characters based on their shape.
    * **`HanKerning::ResetFeatures()`:**  Resets the list of applied font features, likely for subsequent processing.
    * **`HanKerning::GetCharType()`:**  Determines the character type based on the Unicode character itself, consulting font-specific data for certain punctuation marks (dots, colons, quotes) where visual representation can vary.
    * **`HanKerning::MayApply()`:**  A quick check to see if Han kerning is potentially applicable to a given text segment.
    * **`HanKerning::ShouldKern()` and `HanKerning::ShouldKernLast()`:** Define the kerning rules – under what conditions should spacing adjustments be made based on the character types.
    * **`HanKerning::Compute()`:** The main function. It takes text, font information, and options, and then determines which font features (`halt` or `vhal`) to apply to achieve the desired kerning.
    * **`HanKerning::FontData::FontData()`:**  Constructor for the `FontData` class. It analyzes the font to see if it supports Han kerning (`halt`/`vhal`) and contextual spacing (`chws`/`vchw`), and then calculates the character types for specific punctuation marks based on glyph shapes. This is where HarfBuzz is used to get glyph information.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):** I considered how this C++ code, which is part of the rendering engine, interacts with web technologies:

    * **CSS:** The most direct relationship is with CSS properties like `text-spacing-trim`. This property influences whether Han kerning is applied. Also, the font specified in CSS is what `HanKerning` operates on.
    * **HTML:** The HTML provides the text content that needs to be rendered and potentially kerned.
    * **JavaScript:** While JavaScript doesn't directly interact with this low-level rendering code, it can manipulate the HTML content and CSS styles, indirectly triggering the Han kerning process.

6. **Logical Reasoning (Input/Output):** I devised a simple scenario:  Imagine two adjacent full-width parentheses. Based on the `ShouldKern` rules, kerning *should* be applied. I then considered the code's flow and what font features would likely be added.

7. **User/Programming Errors:** I thought about common mistakes:

    * **User:**  Not choosing a font that supports Han kerning, or using `text-spacing-trim: space-all`.
    * **Programmer:** Incorrectly setting font features, or assuming Han kerning will always apply.

8. **Structure and Refine the Answer:** Finally, I organized my thoughts into a clear and structured answer, addressing each part of the original request:

    * **Functionality:**  Provide a concise summary.
    * **Relationship to Web Technologies:**  Explain the connections with CSS, HTML, and JavaScript with examples.
    * **Logical Reasoning:**  Present a clear input/output scenario.
    * **User/Programming Errors:**  Give concrete examples.

This iterative process of scanning, dissecting, relating, reasoning, and structuring allowed me to produce a comprehensive and accurate answer to the request.
这个文件 `blink/renderer/platform/fonts/shaping/han_kerning.cc` 的主要功能是**实现对CJK（中日韩）文字的字偶间距调整（Kerning）**，以提高文本的视觉美观性和可读性。这种调整主要针对全角标点符号等特殊字符，通过缩小它们之间的间距，使得文本看起来更加紧凑和自然。

更具体地说，该文件实现了以下功能：

1. **定义字符类型 (CharType):**  定义了不同的字符类型，例如 `kOpen` (开放式标点，如左括号)，`kClose` (闭合式标点，如右括号)，`kMiddle`，`kOther` 等。这些类型用于判断相邻字符之间是否需要进行字偶间距调整。

2. **判断是否可以应用 Han Kerning (`MayApply`):**  通过检查文本内容，判断是否包含可能需要进行 Han Kerning 的字符。如果文本是纯 ASCII 或者不包含可能需要调整间距的 CJK 字符，则可以跳过后续的计算。

3. **获取字符类型 (`GetCharType`):**  根据 Unicode 字符和字体信息（特别是 `HanKerningData`），确定字符的 `CharType`。对于某些标点符号（如句号、逗号、冒号、引号等），其类型可能根据字体或地区设置而有所不同。

4. **判断是否需要进行 Kerning (`ShouldKern`, `ShouldKernLast`):**  定义了进行字偶间距调整的规则。例如，一个开放式标点后面跟着另一个开放式标点、中间型字符或闭合式标点时，可能需要进行调整。

5. **计算并应用字偶间距 (`Compute`):**
   - 接收文本、起始和结束位置、字体、字体描述和选项等参数。
   - 根据相邻字符的 `CharType`，判断是否需要在它们之间应用字偶间距调整。
   - 通过添加 OpenType 特性标签 (`halt` 或 `vhal`) 到 `FontFeatures` 对象中，告知 HarfBuzz 引擎在 shaping 过程中应用相应的字偶间距调整。`halt` 用于水平排版，`vhal` 用于垂直排版。
   - 考虑了 `text-spacing-trim` CSS 属性的影响，如果设置为 `space-all`，则不应用 Han Kerning。
   - 考虑了互斥的 OpenType 特性，如果已经存在互斥的特性，则不应用 Han Kerning。

6. **获取 Han Kerning 数据 (`HanKerning::FontData`):**
   - 检查字体是否支持 `halt` (水平) 或 `vhal` (垂直) OpenType 特性，这是应用 Han Kerning 的前提。
   - 检查字体是否支持 `chws` (水平) 或 `vchw` (垂直) OpenType 特性，这表示字体支持上下文相关的间距调整。
   - 对于特定的标点符号（如句号、逗号、冒号等），通过 HarfBuzzShaper 获取其字形 (glyph) 的边界信息，并根据边界信息确定其 `CharType`。这允许根据字体的实际设计来确定标点的类型。

**与 JavaScript, HTML, CSS 的关系：**

`han_kerning.cc` 是 Chromium 渲染引擎的一部分，它处理文本的渲染过程。它与 JavaScript, HTML, CSS 的关系如下：

* **HTML:** HTML 提供了需要渲染的文本内容。`han_kerning.cc` 处理的就是这些文本的排版和渲染。
* **CSS:**
    * **`font-family`:**  选择的字体决定了是否支持 Han Kerning 以及如何进行调整。
    * **`text-orientation`:**  影响是使用 `halt` (水平) 还是 `vhal` (垂直) 特性。
    * **`text-spacing-trim`:**  `space-all` 值会禁用 Han Kerning。
    * **其他字体特性 (font-feature-settings):**  用户或开发者可以通过 `font-feature-settings` 控制 OpenType 特性，可能会影响 Han Kerning 的应用。例如，如果设置了与 `halt` 或 `vhal` 互斥的特性，Han Kerning 可能不会生效。
* **JavaScript:** JavaScript 可以动态修改 HTML 内容和 CSS 样式，从而间接地触发 `han_kerning.cc` 中的逻辑。例如，通过 JavaScript 改变元素的文本内容或应用不同的 CSS 样式，可能会导致重新进行文本 shaping 和 Han Kerning 的计算。

**举例说明：**

**假设输入 (HTML):**

```html
<p style="font-family: '思源宋体';">（你好。）</p>
```

**CSS (默认情况):**

```css
p {
  /* 默认的文本渲染样式 */
}
```

**逻辑推理和输出:**

1. **输入:**  包含全角括号和汉字的文本 "（你好。)"，使用的字体是 "思源宋体"。
2. **`HanKerning::MayApply`:**  检测到非 ASCII 字符，特别是全角括号，`MayApply` 返回 true。
3. **`HanKerning::GetCharType`:**
   - 左括号 '(' 的 `CharType` 被判断为 `kOpen`。
   - 右括号 ')' 的 `CharType` 被判断为 `kClose`。
4. **`HanKerning::ShouldKernLast` (在处理右括号时):**  由于前一个字符（左括号）是 `kOpen`，当前字符（右括号）是 `kClose`，并且字体支持 Han Kerning，`ShouldKernLast` 返回 true。
5. **`HanKerning::Compute`:**
   -  `Compute` 函数会向 `FontFeatures` 对象添加 `halt` 特性（假设是水平排版），指示 HarfBuzz 在渲染这两个字符时缩小它们之间的间距。
6. **输出 (渲染结果):**  在屏幕上渲染时，左右括号之间的间距会比默认情况下更小，看起来更紧凑。

**用户或编程常见的使用错误：**

1. **用户错误：选择了不支持 Han Kerning 的字体。**
   - **示例：** 用户在 CSS 中指定了一个不包含 `halt` 或 `vhal` 特性的字体，例如某些仅包含拉丁字符的字体。
   - **结果：** 即使文本中包含应该进行 Han Kerning 的字符，也不会应用任何间距调整。

2. **用户错误：设置了 `text-spacing-trim: space-all;`。**
   - **示例：** 用户在 CSS 中设置了 `text-spacing-trim: space-all;`。
   - **结果：**  这将禁用所有的文本间距调整，包括 Han Kerning。

3. **编程错误：错误地设置了互斥的 OpenType 特性。**
   - **示例：** 开发者通过 `font-feature-settings` CSS 属性，显式地启用了与 `halt` 或 `vhal` 互斥的特性 (例如 `pwid`)。
   - **结果：** `HanKerning::Compute` 函数会检测到互斥特性已启用，从而跳过 Han Kerning 的应用。

4. **编程错误：假设 Han Kerning 会自动应用于所有 CJK 文本。**
   - **说明：**  Han Kerning 的应用依赖于字体是否支持相应的 OpenType 特性，以及文本内容是否包含需要调整的字符组合。开发者不能假设所有 CJK 文本都会自动应用 Han Kerning。

总而言之，`han_kerning.cc` 是 Chromium 渲染引擎中一个重要的模块，它专注于提升 CJK 文本的排版质量，通过智能地调整特定字符之间的间距，使得文本在视觉上更加舒适和专业。它的工作受到 CSS 样式的影响，并最终影响用户在浏览器中看到的文本渲染效果。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/shaping/han_kerning.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/fonts/shaping/han_kerning.h"

#include <unicode/uchar.h>

#include "third_party/blink/renderer/platform/fonts/opentype/open_type_features.h"
#include "third_party/blink/renderer/platform/fonts/shaping/font_features.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_shaper.h"
#include "third_party/blink/renderer/platform/fonts/simple_font_data.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"

namespace blink {

namespace {

HashSet<uint32_t> ExclusiveFeatures() {
  // https://learn.microsoft.com/en-us/typography/opentype/spec/features_ae#chws
  // https://learn.microsoft.com/en-us/typography/opentype/spec/features_uz#vchw
  return HashSet<uint32_t>{
      HB_TAG('h', 'a', 'l', 't'), HB_TAG('h', 'w', 'i', 'd'),
      HB_TAG('p', 'a', 'l', 't'), HB_TAG('p', 'w', 'i', 'd'),
      HB_TAG('q', 'w', 'i', 'd'), HB_TAG('t', 'w', 'i', 'd'),
      HB_TAG('v', 'a', 'l', 't'), HB_TAG('v', 'h', 'a', 'l'),
      HB_TAG('v', 'p', 'a', 'l'),
  };
}

bool IsExclusiveFeature(uint32_t tag) {
  DEFINE_STATIC_LOCAL(HashSet<uint32_t>, tags, (ExclusiveFeatures()));
  return tags.Contains(tag);
}

inline float GetAdvance(const HarfBuzzShaper::GlyphData& glyph,
                        bool is_horizontal) {
  return is_horizontal ? glyph.advance.x() : glyph.advance.y();
  ;
}

// Compute `CharType` from the glyph bounding box.
HanKerning::CharType CharTypeFromBounds(float half_em,
                                        const SkRect& bound,
                                        bool is_horizontal) {
  if (is_horizontal) {
    if (bound.right() <= half_em) {
      return HanKerning::CharType::kClose;
    }
    if (bound.left() >= half_em) {
      return HanKerning::CharType::kOpen;
    }
    if (bound.width() <= half_em && bound.left() >= half_em / 2) {
      return HanKerning::CharType::kMiddle;
    }
  } else {
    if (bound.bottom() <= half_em) {
      return HanKerning::CharType::kClose;
    }
    if (bound.top() >= half_em) {
      return HanKerning::CharType::kOpen;
    }
    if (bound.height() <= half_em && bound.top() >= half_em / 2) {
      return HanKerning::CharType::kMiddle;
    }
  }
  return HanKerning::CharType::kOther;
}

HanKerning::CharType CharTypeFromBounds(
    base::span<HarfBuzzShaper::GlyphData> glyphs,
    base::span<SkRect> bounds,
    unsigned index,
    bool is_horizontal) {
  const HarfBuzzShaper::GlyphData& glyph = glyphs[index];
  if (!glyph.glyph) [[unlikely]] {
    return HanKerning::CharType::kOther;
  }
  const float advance = GetAdvance(glyph, is_horizontal);
  return CharTypeFromBounds(advance / 2, bounds[index], is_horizontal);
}

HanKerning::CharType CharTypeFromBounds(
    base::span<HarfBuzzShaper::GlyphData> glyphs,
    base::span<SkRect> bounds,
    bool is_horizontal) {
  DCHECK_EQ(glyphs.size(), bounds.size());

  // Find the data from the first glyph.
  float advance0;
  float half_advance0;
  HanKerning::CharType type0 = HanKerning::CharType::kOther;
  unsigned i = 0;
  for (;; ++i) {
    if (i >= glyphs.size()) [[unlikely]] {
      return HanKerning::CharType::kOther;
    }
    const HarfBuzzShaper::GlyphData& glyph = glyphs[i];
    if (!glyph.glyph) [[unlikely]] {
      continue;
    }

    advance0 = GetAdvance(glyph, is_horizontal);
    half_advance0 = advance0 / 2;
    type0 = CharTypeFromBounds(half_advance0, bounds[i], is_horizontal);
    break;
  }

  // Check if all other glyphs have the same advances and types.
  for (++i; i < glyphs.size(); ++i) {
    const HarfBuzzShaper::GlyphData& glyph = glyphs[i];
    if (!glyph.glyph) [[unlikely]] {
      continue;
    }

    // If advances are not the same, `kOther`.
    const float advance = GetAdvance(glyph, is_horizontal);
    if (advance != advance0) {
      return HanKerning::CharType::kOther;
    }

    // If types are not the same, `kOther`.
    const HanKerning::CharType type =
        CharTypeFromBounds(half_advance0, bounds[i], is_horizontal);
    if (type != type0) {
      return HanKerning::CharType::kOther;
    }
  }
  return type0;
}

}  // namespace

void HanKerning::ResetFeatures() {
  DCHECK(features_);
#if EXPENSIVE_DCHECKS_ARE_ON()
  for (wtf_size_t i = num_features_before_; i < features_->size(); ++i) {
    const hb_feature_t& feature = (*features_)[i];
    DCHECK(feature.tag == HB_TAG('h', 'a', 'l', 't') ||
           feature.tag == HB_TAG('v', 'h', 'a', 'l'));
  }
#endif
  features_->Shrink(num_features_before_);
}

// Compute the character class.
// See Text Spacing Character Classes:
// https://drafts.csswg.org/css-text-4/#text-spacing-classes
HanKerning::CharType HanKerning::GetCharType(UChar ch,
                                             const FontData& font_data) {
  const CharType type = Character::GetHanKerningCharType(ch);
  switch (type) {
    case CharType::kOther:
    case CharType::kOpen:
    case CharType::kClose:
    case CharType::kMiddle:
    case CharType::kOpenNarrow:
    case CharType::kCloseNarrow:
      return type;
    case CharType::kDot:
      return font_data.type_for_dot;
    case CharType::kColon:
      return font_data.type_for_colon;
    case CharType::kSemicolon:
      return font_data.type_for_semicolon;
    case CharType::kOpenQuote:
      return font_data.is_quote_fullwidth ? CharType::kOpen
                                          : CharType::kOpenNarrow;
    case CharType::kCloseQuote:
      return font_data.is_quote_fullwidth ? CharType::kClose
                                          : CharType::kCloseNarrow;
  }
  NOTREACHED();
}

bool HanKerning::MayApply(StringView text) {
  return !text.Is8Bit() && !text.IsAllSpecialCharacters<[](UChar ch) {
    return !Character::MaybeHanKerningOpenOrCloseFast(ch);
  }>();
}

inline bool HanKerning::ShouldKern(CharType type, CharType last_type) {
  return type == CharType::kOpen &&
         (last_type == CharType::kOpen || last_type == CharType::kMiddle ||
          last_type == CharType::kClose || last_type == CharType::kOpenNarrow);
}

inline bool HanKerning::ShouldKernLast(CharType type, CharType last_type) {
  return last_type == CharType::kClose &&
         (type == CharType::kClose || type == CharType::kMiddle ||
          type == CharType::kCloseNarrow);
}

// Compute kerning and apply features.
// See Fullwidth Punctuation Collapsing:
// https://drafts.csswg.org/css-text-4/#fullwidth-collapsing
void HanKerning::Compute(const String& text,
                         wtf_size_t start,
                         wtf_size_t end,
                         const SimpleFontData& font,
                         const FontDescription& font_description,
                         Options options,
                         FontFeatures* features) {
  DCHECK(!features_);
  DCHECK_GT(end, start);
  if (!MayApply(StringView(text, start, end - start))) {
    return;
  }
  const LayoutLocale& locale = font_description.LocaleOrDefault();
  const FontData& font_data =
      font.HanKerningData(locale, options.is_horizontal);
  if (!font_data.has_alternate_spacing) {
    return;
  }
  if (font_description.GetTextSpacingTrim() == TextSpacingTrim::kSpaceAll)
      [[unlikely]] {
    return;
  }
  for (const hb_feature_t& feature : *features) {
    if (feature.value && IsExclusiveFeature(feature.tag)) {
      return;
    }
  }

  // Compute for the first character.
  Vector<wtf_size_t, 32> indices;
  CharType last_type;
  if (options.apply_start) [[unlikely]] {
    indices.push_back(start);
    unsafe_to_break_before_.push_back(start);
    last_type = GetCharType(text[start], font_data);
  } else if (start && !options.is_line_start) {
    last_type = GetCharType(text[start - 1], font_data);
    const CharType type = GetCharType(text[start], font_data);
    if (ShouldKern(type, last_type)) {
      indices.push_back(start);
      unsafe_to_break_before_.push_back(start);
    }
    last_type = type;
  } else {
    last_type = GetCharType(text[start], font_data);
  }

  if (font_data.has_contextual_spacing) {
    // The `chws` feature can handle charcters in a run.
    // Compute the end edge if there are following runs.
    if (options.apply_end) [[unlikely]] {
      indices.push_back(end - 1);
    } else if (end < text.length()) {
      if (end - 1 > start) {
        last_type = GetCharType(text[end - 1], font_data);
      }
      const CharType type = GetCharType(text[end], font_data);
      if (ShouldKernLast(type, last_type)) {
        indices.push_back(end - 1);
      }
    }
  } else {
    // Compute for characters in the middle.
    CharType type;
    for (wtf_size_t i = start + 1; i < end; ++i, last_type = type) {
      const UChar ch = text[i];
      type = GetCharType(ch, font_data);
      if (ShouldKernLast(type, last_type)) {
        DCHECK_GT(i, 0u);
        indices.push_back(i - 1);
        unsafe_to_break_before_.push_back(i);
      } else if (ShouldKern(type, last_type)) {
        indices.push_back(i);
        unsafe_to_break_before_.push_back(i);
      }
    }

    // Compute for the last character.
    if (options.apply_end) [[unlikely]] {
      indices.push_back(end - 1);
    } else if (end < text.length()) {
      type = GetCharType(text[end], font_data);
      if (ShouldKernLast(type, last_type)) {
        indices.push_back(end - 1);
      }
    }
  }

  // Append to `features`.
  if (indices.empty()) {
    return;
  }
  DCHECK(std::is_sorted(indices.begin(), indices.end(), std::less_equal<>()));
  const hb_tag_t tag = options.is_horizontal ? HB_TAG('h', 'a', 'l', 't')
                                             : HB_TAG('v', 'h', 'a', 'l');
  features_ = features;
  num_features_before_ = features->size();
  features->Reserve(features->size() + indices.size());
  for (const wtf_size_t i : indices) {
    features->Append({tag, 1, i, i + 1});
  }
}

HanKerning::FontData::FontData(const SimpleFontData& font,
                               const LayoutLocale& locale,
                               bool is_horizontal) {
  // Check if the font has `halt` (or `vhal` in vertical.)
  OpenTypeFeatures features(font);
  const hb_tag_t alt_tag =
      is_horizontal ? HB_TAG('h', 'a', 'l', 't') : HB_TAG('v', 'h', 'a', 'l');
  has_alternate_spacing = features.Contains(alt_tag);
  if (!has_alternate_spacing) {
    return;
  }

  // Check if the font has `chws` (or `vchw` in vertical.)
  const hb_tag_t chws_tag =
      is_horizontal ? HB_TAG('c', 'h', 'w', 's') : HB_TAG('v', 'c', 'h', 'w');
  has_contextual_spacing = features.Contains(chws_tag);

  // Some code points change their glyphs by languages, and it may change
  // `CharType` that depends on glyphs bounds as well.
  // https://drafts.csswg.org/css-text-4/#text-spacing-classes
  //
  // For example, the Adobe's common convention is to:
  // * Place full stop and comma at center only for Traditional Chinese.
  // * Place colon and semicolon on the left only for Simplified Chinese.
  // https://github.com/adobe-fonts/source-han-sans/raw/release/SourceHanSansReadMe.pdf
  const UChar kChars[] = {
      // Dot (full stop and comma) characters.
      // https://drafts.csswg.org/css-text-4/#fullwidth-dot-punctuation
      kIdeographicCommaCharacter, kIdeographicFullStopCharacter,
      kFullwidthComma, kFullwidthFullStop,
      // Colon characters.
      // https://drafts.csswg.org/css-text-4/#fullwidth-colon-punctuation
      kFullwidthColon, kFullwidthSemicolon,
      // Quote characters. In a common convention, they are proportional (Latin)
      // in Japanese, but fullwidth in Chinese.
      kLeftDoubleQuotationMarkCharacter, kLeftSingleQuotationMarkCharacter,
      kRightDoubleQuotationMarkCharacter, kRightSingleQuotationMarkCharacter};
  constexpr unsigned kDotSize = 4;
  constexpr unsigned kColonIndex = 4;
  constexpr unsigned kSemicolonIndex = 5;
  constexpr unsigned kQuoteStartIndex = 6;
  static_assert(kDotSize <= std::size(kChars));
  static_assert(kColonIndex < std::size(kChars));
  static_assert(kSemicolonIndex < std::size(kChars));

  // Use `HarfBuzzShaper` to find the correct glyph ID.
  //
  // The glyph changes are often done by different encodings (`cmap`) or by
  // OpenType features such as `calt`. In vertical flow, some glyphs change,
  // which is done by OpenType features such as `vert`. Shaping is needed to
  // apply these features.
  HarfBuzzShaper shaper{String(base::span(kChars))};
  HarfBuzzShaper::GlyphDataList glyph_data_list;
  shaper.GetGlyphData(font, locale, locale.GetScriptForHan(), is_horizontal,
                      glyph_data_list);

  // If the font doesn't have any of these glyphs, or uses multiple glyphs for a
  // code point, it's not applicable.
  if (glyph_data_list.size() != std::size(kChars)) {
    has_alternate_spacing = false;
    return;
  }

  Vector<Glyph, 256> glyphs;
  unsigned cluster = 0;
  for (const HarfBuzzShaper::GlyphData& glyph_data : glyph_data_list) {
    if (glyph_data.cluster != cluster) [[unlikely]] {
      has_alternate_spacing = false;
      return;
    }
    ++cluster;
    glyphs.push_back(glyph_data.glyph);
  }

  // Compute glyph bounds for all glyphs.
  Vector<SkRect, 256> bounds(glyphs.size());
  font.BoundsForGlyphs(glyphs, &bounds);

  // `bounds` are relative to the glyph origin. Adjust them to be relative to
  // the paint origin.
  DCHECK_LE(bounds.size(), glyph_data_list.size());
  for (wtf_size_t i = 0; i < bounds.size(); ++i) {
    const HarfBuzzShaper::GlyphData& glyph_data = glyph_data_list[i];
    bounds[i].offset({glyph_data.offset.x(), glyph_data.offset.y()});
  }

  // Compute types from glyph bounds.
  //
  // This logic allows each group of glyphs to have different advances, such as
  // when comma and full stop are narrower than `1ch`, as long as:
  // * The font has the `halt` feature.
  // * Glyphs in each group have the same advances.
  // * Glyphs have enough space to apply kerning.
  base::span<HarfBuzzShaper::GlyphData> glyph_data_span(glyph_data_list);
  base::span<SkRect> bounds_span(bounds);
  type_for_dot = CharTypeFromBounds(glyph_data_span.first(kDotSize),
                                    bounds_span.first(kDotSize), is_horizontal);
  type_for_colon = CharTypeFromBounds(glyph_data_span, bounds_span, kColonIndex,
                                      is_horizontal);
  type_for_semicolon = CharTypeFromBounds(glyph_data_span, bounds_span,
                                          kSemicolonIndex, is_horizontal);

  // Quotes not being fullwidth doesn't necessarily mean the font isn't
  // applicable. Quotes are unified by the Unicode unification process (i.e.,
  // Latin curly quotes and CJK quotes have the same code points,) and that they
  // can be either proportional or fullwidth. Japanese fonts oten have
  // proportional glyphs, prioritizing Latin usages, while Chinese fonts often
  // have fullwidth glyphs, prioritizing Chinese usages.
  //
  // Adobe has a convention to switch to CJK glyphs by the OpenType `fwid`
  // feature, but not all fonts follow this convention. The current logic
  // doesn't support this convention.
  //
  // Quotes are often misplaced, especially in Japanese vertical flow, due to
  // the lack of established conventions. In that case, treat such quotes the
  // same as narrow quotes. See `HanKerning::GetCharType`.
  is_quote_fullwidth = true;
  glyph_data_span = glyph_data_span.subspan(kQuoteStartIndex);
  bounds_span = bounds_span.subspan(kQuoteStartIndex);
  DCHECK_EQ(bounds_span.size(), 4u);
  if (CharTypeFromBounds(glyph_data_span.first(2u), bounds_span.first(2u),
                         is_horizontal) != CharType::kOpen ||
      CharTypeFromBounds(glyph_data_span.subspan(2u), bounds_span.subspan(2u),
                         is_horizontal) != CharType::kClose) {
    is_quote_fullwidth = false;
  }
}

}  // namespace blink

"""

```