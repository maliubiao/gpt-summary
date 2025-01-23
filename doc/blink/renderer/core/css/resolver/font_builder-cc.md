Response:
Let's break down the thought process for analyzing the `font_builder.cc` file.

1. **Understand the Goal:** The request asks for a breakdown of the file's functionality, its relation to web technologies (JavaScript, HTML, CSS), logical reasoning examples, potential user errors, and debugging tips.

2. **Initial Skim and Identification of Key Concepts:**  Read through the file quickly to get a high-level understanding. Keywords like "FontBuilder," "FontDescription," "ComputedStyle," "CSS," and the included headers (`css_font_selector.h`, `style_engine.h`, etc.) immediately suggest this file is related to how the browser determines and applies font styles.

3. **Focus on the `FontBuilder` Class:** The file seems centered around the `FontBuilder` class. Examine its constructor and member functions. Notice functions like `SetFamilyDescription`, `SetSize`, `SetWeight`, `SetStyle`, etc. These clearly correspond to CSS font properties.

4. **Identify Relationships to Web Technologies:**
    * **CSS:** The function names directly map to CSS font properties (`font-family`, `font-size`, `font-weight`, `font-style`, etc.). The file's purpose is to interpret and apply these CSS rules.
    * **HTML:**  CSS styles are applied to HTML elements. This class is part of the process that takes the CSS rules and applies them to the elements defined in the HTML.
    * **JavaScript:**  JavaScript can dynamically modify CSS styles (e.g., using `element.style.fontSize` or by manipulating CSS classes). This file plays a role when these JavaScript changes need to be reflected in the rendered output.

5. **Analyze Function Functionality:** Go through each public method of `FontBuilder` and determine its purpose.
    * **Setters:** Functions starting with `Set` are clearly modifying the internal state of the `FontBuilder` (specifically the `font_description_`).
    * **Getters:**  `StandardFontFamily`, `StandardFontFamilyName`, `GenericFontFamilyName`, `FontSizeForKeyword` retrieve information related to fonts.
    * **`CreateFont` and `CreateInitialFont`:** These are crucial for generating the final `Font` object based on the accumulated settings.
    * **`Update...` methods:** These functions seem to synchronize or calculate derived font properties based on parent styles or other factors.
    * **`ComputeFontSelector`:** This suggests a process for selecting the appropriate font resource.

6. **Logical Reasoning Examples:**  Consider how the `FontBuilder` would handle different CSS inputs.
    * **Assumption:** A CSS rule sets `font-size: 16px`.
    * **Input:** The `SetSize` function is called with the value 16.
    * **Output:**  The `font_description_`'s size information is updated. Later, `UpdateComputedSize` will use this value to calculate the actual rendered size, potentially factoring in zoom levels, etc.
    * **Another Assumption:** A CSS rule sets `font-family: serif, "Times New Roman"`.
    * **Input:** `SetFamilyDescription` is called.
    * **Output:** The `font_description_` will store both the generic family (`serif`) and the specific font name (`Times New Roman`).

7. **User Errors:** Think about common mistakes developers make with fonts.
    * **Incorrect Font Names:**  Specifying a font that doesn't exist or is misspelled. While `FontBuilder` itself might not *detect* this error, it will pass the information along, and the font rendering system will likely use a fallback font.
    * **Invalid Font Sizes:** Using negative or extremely large font sizes. The code explicitly checks for negative sizes and caps the maximum size.
    * **Overriding Styles:**  Unintentionally overriding font styles due to CSS specificity rules. This isn't an error *handled* by `FontBuilder`, but it's a common pitfall.

8. **Debugging Clues (User Operations):** Trace how user actions could lead to the execution of `font_builder.cc`.
    * **Loading a web page:**  Parsing HTML and CSS triggers the style resolution process, involving `FontBuilder`.
    * **User zooming:** The `DidChangeEffectiveZoom` function is called.
    * **Changing browser settings:** Modifications to default font settings can affect the values returned by `StandardFontFamilyName`.
    * **Dynamic CSS changes:** JavaScript manipulating font styles will eventually lead to updates within `FontBuilder`.

9. **Structure the Answer:** Organize the findings into logical sections based on the request's prompts: Functionality, Relationship to Web Technologies, Logical Reasoning, User Errors, and Debugging Clues. Use clear headings and examples.

10. **Refine and Elaborate:** Review the drafted answer for clarity and completeness. Add more detail where necessary. For instance, when discussing CSS, mention the cascade and inheritance. When talking about JavaScript, point out how dynamic changes impact font styles.

By following this structured approach, you can effectively analyze a complex source code file and address the different aspects of the given request. The key is to combine code-level understanding with knowledge of web technologies and common development practices.
好的，让我们来分析一下 `blink/renderer/core/css/resolver/font_builder.cc` 这个文件。

**文件功能概述:**

`font_builder.cc` 文件的主要功能是**构建和管理 `FontDescription` 对象**。`FontDescription` 是 Blink 引擎中用来描述字体属性（例如字体族、大小、粗细、样式等）的核心数据结构。 `FontBuilder` 提供了一系列方法，用于逐步设置 `FontDescription` 的各种属性，最终创建一个完整的、可用于字体选择和渲染的字体描述。

更具体地说，`FontBuilder` 负责：

1. **接收并存储字体属性值:**  它提供了一组 `Set...` 方法，用于接收来自 CSS 解析器或其他模块提供的字体属性值，例如 `SetFamilyDescription` (字体族), `SetSize` (字体大小), `SetWeight` (字体粗细) 等。
2. **处理字体属性之间的关联和影响:**  某些字体属性之间存在依赖关系或相互影响。`FontBuilder` 内部会处理这些逻辑，例如，当字体族更改时，可能需要重新评估某些默认值。
3. **考虑上下文信息:** `FontBuilder` 持有一个 `Document` 指针，可以访问文档的设置，例如默认字体、文本缩放比例等，以便在构建 `FontDescription` 时考虑这些上下文信息。
4. **与字体选择器交互:** `FontBuilder` 可以与 `FontSelector` 交互，以获取更高级的字体选择信息。
5. **创建最终的 `FontDescription` 对象:**  通过调用一系列 `Set...` 方法后，最终生成的 `FontDescription` 对象包含了所有必要的字体信息。
6. **处理继承和初始值:**  `FontBuilder` 可以在创建字体时考虑父元素的字体样式，并处理 CSS 属性的 `inherit` 和 `initial` 值。
7. **处理浏览器和用户设置:**  它会考虑浏览器的默认字体设置以及用户的自定义字体设置。

**与 Javascript, HTML, CSS 的关系及举例说明:**

`font_builder.cc` 在 Blink 引擎中处于 CSS 样式解析和应用的关键环节，直接关联到 HTML、CSS 和 Javascript 的功能：

* **CSS:**  `FontBuilder` 的核心职责就是解析和应用 CSS 中与字体相关的属性。
    * **举例:** 当浏览器解析到以下 CSS 规则时：
      ```css
      body {
        font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
        font-size: 16px;
        font-weight: bold;
        font-style: italic;
      }
      ```
      Blink 的 CSS 解析器会将这些属性值传递给 `FontBuilder` 的相应 `Set...` 方法：
      * `SetFamilyDescription` 会被调用多次，处理字体族列表。
      * `SetSize` 会被调用，设置字体大小为 16px。
      * `SetWeight` 会被调用，设置字体粗细为 bold。
      * `SetStyle` 会被调用，设置字体样式为 italic。

* **HTML:**  HTML 结构定义了需要应用样式的元素。`FontBuilder` 构建的 `FontDescription` 对象最终会与 HTML 元素关联，影响元素的文本渲染。
    * **举例:**  如果 HTML 中有一个 `<p>` 元素，并且 CSS 中为 `body` 元素设置了字体样式，那么 `FontBuilder` 会为 `<p>` 元素（如果它没有自己的字体样式）构建一个继承自 `body` 的 `FontDescription`。

* **Javascript:** Javascript 可以动态地修改元素的 CSS 样式。这些修改最终也会影响 `FontBuilder` 的工作。
    * **举例:**  如果 Javascript 代码执行了以下操作：
      ```javascript
      document.body.style.fontSize = '20px';
      ```
      浏览器会重新解析这个样式变更，并调用 `FontBuilder` 的 `SetSize` 方法，更新 `body` 及其子元素的字体大小。

**逻辑推理举例 (假设输入与输出):**

假设 `FontBuilder` 正在为一个 `<span>` 元素构建 `FontDescription`，并且该元素应用的 CSS 如下：

```css
.my-span {
  font-family: monospace;
  font-size: smaller;
}
```

* **假设输入:**
    * `FontBuilder` 接收到 `font-family: monospace`。
    * `FontBuilder` 接收到 `font-size: smaller`。
    * 当前文档的默认字体大小是 16px。
* **逻辑推理:**
    * `SetFamilyDescription` 被调用，设置 `generic_family` 为 `FontDescription::kMonospaceFamily`。
    * `SetSize` 被调用，`keyword` 参数为表示 "smaller" 的值。
    * `FontSizeForKeyword` 方法会被调用，根据当前默认字体大小 (16px) 和 "smaller" 关键字，计算出实际的像素大小，例如可能是 13px 或 14px (具体的计算规则在 `FontSizeFunctions` 中)。
* **假设输出:**
    * `FontDescription` 对象的 `generic_family` 被设置为 `FontDescription::kMonospaceFamily`。
    * `FontDescription` 对象的 `specified_size` 被设置为计算出的像素值 (例如 13px)。

**用户或编程常见的使用错误举例:**

以下是一些可能导致 `FontBuilder` 行为不符合预期的常见错误：

1. **拼写错误的字体族名称:**  如果在 CSS 中指定了一个不存在或拼写错误的字体族名称，`FontBuilder` 会使用默认的后备字体。这可能不是用户期望的结果。
    * **举例:**  `font-family: Helvetiva;` (正确的拼写是 "Helvetica")
2. **使用了无效的字体大小值:**  例如负的字体大小。 `FontBuilder::SetSize` 中有检查，负数会被忽略。
    * **举例:** `font-size: -10px;`
3. **过度依赖简写属性而忽略细节:**  例如，只使用了 `font` 简写属性，但没有正确地包含所有必要的子属性，导致某些字体特征没有被设置。
    * **举例:** `font: 12px "Arial";` (缺少字体粗细和样式信息)。
4. **CSS 优先级或继承问题:**  虽然 `FontBuilder` 本身不负责处理 CSS 优先级，但错误的 CSS 规则可能会导致最终传递给 `FontBuilder` 的属性值不是用户期望的。
5. **浏览器兼容性问题:** 某些 CSS 字体属性或取值在不同的浏览器中可能有不同的实现或支持程度。

**用户操作如何一步步到达这里 (作为调试线索):**

当开发者在调试与字体样式相关的问题时，了解用户操作如何触发 `font_builder.cc` 的执行非常重要。以下是一个可能的步骤：

1. **用户在浏览器中打开一个包含文本内容的网页。**
2. **Blink 引擎开始解析 HTML 代码，构建 DOM 树。**
3. **Blink 引擎解析网页中的 CSS 样式表 (包括外部样式表、`<style>` 标签和行内样式)。**
4. **CSS 解析器会识别出与字体相关的 CSS 属性 (例如 `font-family`, `font-size`, `font-weight` 等)。**
5. **对于每个需要计算样式的元素，Blink 的样式解析器会创建一个 `FontBuilder` 对象。**
6. **CSS 解析器将提取出的字体属性值传递给 `FontBuilder` 对象的相应的 `Set...` 方法。**
   * 例如，如果解析到 `font-size: 16px;`，则会调用 `FontBuilder::SetSize(FontDescription::Size(CSSValueKeyword::kNormal, 16.0f, true))`。
   * 如果解析到 `font-family: "Times New Roman", serif;`，则会调用 `FontBuilder::SetFamilyDescription(...)` 两次，分别处理每个字体族名称。
7. **`FontBuilder` 内部会进行逻辑处理，例如将关键字转换为具体的像素值，处理继承关系等。**
8. **最终，`FontBuilder` 会构建出一个 `FontDescription` 对象，该对象描述了该元素应该使用的字体样式。**
9. **这个 `FontDescription` 对象会被用于后续的字体选择和文本渲染过程。**

**调试线索:**

* **在 Blink 开发者工具中查看元素的 "Computed" 样式:**  可以查看最终应用于元素的字体属性值，这可以帮助判断 CSS 解析和应用是否正确。
* **使用 Blink 的调试日志:**  可以在编译 Blink 时启用调试日志，查看 `FontBuilder` 的 `Set...` 方法是否被正确调用，以及传递的参数值。
* **断点调试:**  在 `font_builder.cc` 中设置断点，可以跟踪字体属性是如何被设置和处理的。
* **检查 CSS 规则的优先级:** 确保没有更高优先级的 CSS 规则覆盖了你期望的字体样式。

希望以上分析能够帮助你理解 `blink/renderer/core/css/resolver/font_builder.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/core/css/resolver/font_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc.
 * All rights reserved.
 * Copyright (C) 2013 Google Inc. All rights reserved.
 * Copyright (C) 2015 Collabora Ltd. All rights reserved.
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

#include "third_party/blink/renderer/core/css/resolver/font_builder.h"

#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/font_family_names.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"

namespace blink {

FontBuilder::FontBuilder(Document* document) : document_(document) {
  DCHECK(!document || document->GetFrame());
}

void FontBuilder::DidChangeEffectiveZoom() {
  Set(PropertySetFlag::kEffectiveZoom);
}

void FontBuilder::DidChangeTextOrientation() {
  Set(PropertySetFlag::kTextOrientation);
}

void FontBuilder::DidChangeWritingMode() {
  Set(PropertySetFlag::kWritingMode);
}

void FontBuilder::DidChangeTextSizeAdjust() {
  // When `TextSizeAdjustImprovements` is enabled, text-size-adjust affects
  // font-size during style building, and needs to invalidate the font
  // description.
  if (RuntimeEnabledFeatures::TextSizeAdjustImprovementsEnabled()) {
    Set(PropertySetFlag::kTextSizeAdjust);
  }
}

FontFamily FontBuilder::StandardFontFamily() const {
  const AtomicString& standard_font_family = StandardFontFamilyName();
  return FontFamily(standard_font_family,
                    FontFamily::InferredTypeFor(standard_font_family));
}

AtomicString FontBuilder::StandardFontFamilyName() const {
  if (document_) {
    Settings* settings = document_->GetSettings();
    if (settings) {
      return settings->GetGenericFontFamilySettings().Standard();
    }
  }
  return AtomicString();
}

AtomicString FontBuilder::GenericFontFamilyName(
    FontDescription::GenericFamilyType generic_family) const {
  switch (generic_family) {
    case FontDescription::kNoFamily:
      return AtomicString();
    // While the intention is to phase out kWebkitBodyFamily, it should still
    // map to the standard font from user preference.
    case FontDescription::kWebkitBodyFamily:
      return StandardFontFamilyName();
    case FontDescription::kSerifFamily:
      return font_family_names::kSerif;
    case FontDescription::kSansSerifFamily:
      return font_family_names::kSansSerif;
    case FontDescription::kMonospaceFamily:
      return font_family_names::kMonospace;
    case FontDescription::kCursiveFamily:
      return font_family_names::kCursive;
    case FontDescription::kFantasyFamily:
      return font_family_names::kFantasy;
    default:
      NOTREACHED();
  }
}

float FontBuilder::FontSizeForKeyword(unsigned keyword,
                                      bool is_monospace) const {
  return FontSizeFunctions::FontSizeForKeyword(document_, keyword,
                                               is_monospace);
}

void FontBuilder::SetFamilyDescription(
    const FontDescription::FamilyDescription& family_description) {
  SetFamilyDescription(font_description_, family_description);
}

void FontBuilder::SetFamilyTreeScope(const TreeScope* tree_scope) {
  family_tree_scope_ = tree_scope;
}

void FontBuilder::SetWeight(FontSelectionValue weight) {
  Set(PropertySetFlag::kWeight);

  font_description_.SetWeight(weight);
}

void FontBuilder::SetStyle(FontSelectionValue slope) {
  Set(PropertySetFlag::kStyle);

  font_description_.SetStyle(slope);
}

void FontBuilder::SetStretch(FontSelectionValue stretch) {
  Set(PropertySetFlag::kStretch);

  font_description_.SetStretch(stretch);
}

void FontBuilder::SetSize(const FontDescription::Size& size) {
  SetSize(font_description_, size);
}

void FontBuilder::SetSizeAdjust(const FontSizeAdjust& size_adjust) {
  Set(PropertySetFlag::kSizeAdjust);

  font_description_.SetSizeAdjust(size_adjust);
}

void FontBuilder::SetLocale(scoped_refptr<const LayoutLocale> locale) {
  Set(PropertySetFlag::kLocale);

  font_description_.SetLocale(std::move(locale));
}

void FontBuilder::SetVariantCaps(FontDescription::FontVariantCaps caps) {
  Set(PropertySetFlag::kVariantCaps);

  font_description_.SetVariantCaps(caps);
}

void FontBuilder::SetVariantEastAsian(const FontVariantEastAsian east_asian) {
  Set(PropertySetFlag::kVariantEastAsian);

  font_description_.SetVariantEastAsian(east_asian);
}

void FontBuilder::SetVariantLigatures(
    const FontDescription::VariantLigatures& ligatures) {
  Set(PropertySetFlag::kVariantLigatures);

  font_description_.SetVariantLigatures(ligatures);
}

void FontBuilder::SetVariantNumeric(const FontVariantNumeric& variant_numeric) {
  Set(PropertySetFlag::kVariantNumeric);

  font_description_.SetVariantNumeric(variant_numeric);
}

void FontBuilder::SetFontSynthesisWeight(
    FontDescription::FontSynthesisWeight font_synthesis_weight) {
  Set(PropertySetFlag::kFontSynthesisWeight);

  font_description_.SetFontSynthesisWeight(font_synthesis_weight);
}

void FontBuilder::SetFontSynthesisStyle(
    FontDescription::FontSynthesisStyle font_synthesis_style) {
  Set(PropertySetFlag::kFontSynthesisStyle);

  font_description_.SetFontSynthesisStyle(font_synthesis_style);
}

void FontBuilder::SetFontSynthesisSmallCaps(
    FontDescription::FontSynthesisSmallCaps font_synthesis_small_caps) {
  Set(PropertySetFlag::kFontSynthesisSmallCaps);

  font_description_.SetFontSynthesisSmallCaps(font_synthesis_small_caps);
}

void FontBuilder::SetTextRendering(TextRenderingMode text_rendering_mode) {
  Set(PropertySetFlag::kTextRendering);

  font_description_.SetTextRendering(text_rendering_mode);
}

void FontBuilder::SetKerning(FontDescription::Kerning kerning) {
  Set(PropertySetFlag::kKerning);

  font_description_.SetKerning(kerning);
}

void FontBuilder::SetTextSpacingTrim(TextSpacingTrim text_spacing_trim) {
  Set(PropertySetFlag::kTextSpacingTrim);
  font_description_.SetTextSpacingTrim(text_spacing_trim);
}

void FontBuilder::SetFontOpticalSizing(OpticalSizing font_optical_sizing) {
  Set(PropertySetFlag::kFontOpticalSizing);

  font_description_.SetFontOpticalSizing(font_optical_sizing);
}

void FontBuilder::SetFontPalette(scoped_refptr<const FontPalette> palette) {
  Set(PropertySetFlag::kFontPalette);
  font_description_.SetFontPalette(std::move(palette));
}

void FontBuilder::SetFontVariantAlternates(
    scoped_refptr<const FontVariantAlternates> variant_alternates) {
  Set(PropertySetFlag::kFontVariantAlternates);
  font_description_.SetFontVariantAlternates(std::move(variant_alternates));
}

void FontBuilder::SetFontSmoothing(FontSmoothingMode font_smoothing_mode) {
  Set(PropertySetFlag::kFontSmoothing);
  font_description_.SetFontSmoothing(font_smoothing_mode);
}

void FontBuilder::SetFeatureSettings(
    scoped_refptr<const FontFeatureSettings> settings) {
  Set(PropertySetFlag::kFeatureSettings);
  font_description_.SetFeatureSettings(std::move(settings));
}

void FontBuilder::SetVariationSettings(
    scoped_refptr<const FontVariationSettings> settings) {
  Set(PropertySetFlag::kVariationSettings);
  font_description_.SetVariationSettings(std::move(settings));
}

void FontBuilder::SetFamilyDescription(
    FontDescription& font_description,
    const FontDescription::FamilyDescription& family_description) {
  Set(PropertySetFlag::kFamily);

  bool is_initial =
      family_description.generic_family == FontDescription::kStandardFamily &&
      family_description.family.FamilyName().empty();

  font_description.SetGenericFamily(family_description.generic_family);
  font_description.SetFamily(is_initial ? StandardFontFamily()
                                        : family_description.family);
}

void FontBuilder::SetSize(FontDescription& font_description,
                          const FontDescription::Size& size) {
  float specified_size = size.value;

  if (specified_size < 0) {
    return;
  }

  Set(PropertySetFlag::kSize);

  // Overly large font sizes will cause crashes on some platforms (such as
  // Windows).  Cap font size here to make sure that doesn't happen.
  specified_size = std::min(kMaximumAllowedFontSize, specified_size);

  font_description.SetKeywordSize(size.keyword);
  font_description.SetSpecifiedSize(specified_size);
  font_description.SetIsAbsoluteSize(size.is_absolute);
}

void FontBuilder::SetVariantPosition(
    FontDescription::FontVariantPosition variant_position) {
  Set(PropertySetFlag::kVariantPosition);

  font_description_.SetVariantPosition(variant_position);
}

void FontBuilder::SetVariantEmoji(FontVariantEmoji variant_emoji) {
  Set(PropertySetFlag::kVariantEmoji);

  font_description_.SetVariantEmoji(variant_emoji);
}

float FontBuilder::GetComputedSizeFromSpecifiedSize(
    const FontDescription& font_description,
    const ComputedStyleBuilder& builder,
    float specified_size) {
  DCHECK(document_);
  float zoom_factor = builder.EffectiveZoom();
  // Apply the text zoom factor preference. The preference is exposed in
  // accessibility settings in Chrome for Android to improve readability.
  if (LocalFrame* frame = document_->GetFrame()) {
    zoom_factor *= frame->TextZoomFactor();
  }

  if (!builder.GetTextSizeAdjust().IsAuto()) {
    if (RuntimeEnabledFeatures::TextSizeAdjustImprovementsEnabled()) {
      Settings* settings = document_->GetSettings();
      if (settings && settings->GetTextAutosizingEnabled()) {
        zoom_factor *= builder.GetTextSizeAdjust().Multiplier();
      }
    }
  }

  return FontSizeFunctions::GetComputedSizeFromSpecifiedSize(
      document_, zoom_factor, font_description.IsAbsoluteSize(),
      specified_size);
}

void FontBuilder::CheckForGenericFamilyChange(
    const FontDescription& parent_description,
    FontDescription& new_description) {
  DCHECK(document_);
  if (new_description.IsAbsoluteSize()) {
    return;
  }

  if (new_description.IsMonospace() == parent_description.IsMonospace()) {
    return;
  }

  // We know the parent is monospace or the child is monospace, and that font
  // size was unspecified. We want to scale our font size as appropriate.
  // If the font uses a keyword size, then we refetch from the table rather than
  // multiplying by our scale factor.
  float size;
  if (new_description.KeywordSize()) {
    size = FontSizeForKeyword(new_description.KeywordSize(),
                              new_description.IsMonospace());
  } else {
    Settings* settings = document_->GetSettings();
    float fixed_scale_factor =
        (settings && settings->GetDefaultFixedFontSize() &&
         settings->GetDefaultFontSize())
            ? static_cast<float>(settings->GetDefaultFixedFontSize()) /
                  settings->GetDefaultFontSize()
            : 1;
    size = parent_description.IsMonospace()
               ? new_description.SpecifiedSize() / fixed_scale_factor
               : new_description.SpecifiedSize() * fixed_scale_factor;
  }

  new_description.SetSpecifiedSize(size);
}

void FontBuilder::UpdateSpecifiedSize(
    FontDescription& font_description,
    const FontDescription& parent_description) {
  float specified_size = font_description.SpecifiedSize();

  if (!specified_size && font_description.KeywordSize()) {
    specified_size = FontSizeForKeyword(font_description.KeywordSize(),
                                        font_description.IsMonospace());
  }
  font_description.SetSpecifiedSize(specified_size);

  CheckForGenericFamilyChange(parent_description, font_description);
}

void FontBuilder::UpdateAdjustedSize(FontDescription& font_description,
                                     FontSelector* font_selector) {
  // Note: the computed_size has scale/zooming applied as well as text auto-
  // sizing and Android font scaling. That means we operate on the used value
  // without font-size-adjust applied and apply the font-size-adjust to end up
  // at a new adjusted_size.
  const float computed_size = font_description.ComputedSize();
  if (!font_description.HasSizeAdjust() || !computed_size) {
    return;
  }

  // We need to create a temporal Font to get xHeight of a primary font.
  // The aspect value is based on the xHeight of the font for the computed font
  // size, so we need to reset the adjusted_size to computed_size. See
  // FontDescription::EffectiveFontSize.
  font_description.SetAdjustedSize(computed_size);

  Font font(font_description, font_selector);

  const SimpleFontData* font_data = font.PrimaryFont();
  if (!font_data) {
    return;
  }

  FontSizeAdjust size_adjust = font_description.SizeAdjust();
  if (size_adjust.IsFromFont() &&
      size_adjust.Value() == FontSizeAdjust::kFontSizeAdjustNone) {
    std::optional<float> aspect_value = FontSizeFunctions::FontAspectValue(
        font_data, size_adjust.GetMetric(), font_description.ComputedSize());
    font_description.SetSizeAdjust(FontSizeAdjust(
        aspect_value.has_value() ? aspect_value.value()
                                 : FontSizeAdjust::kFontSizeAdjustNone,
        size_adjust.GetMetric(), FontSizeAdjust::ValueType::kFromFont));
  }

  if (auto adjusted_size = FontSizeFunctions::MetricsMultiplierAdjustedFontSize(
          font_data, font_description)) {
    font_description.SetAdjustedSize(adjusted_size.value());
  }
}

void FontBuilder::UpdateComputedSize(FontDescription& font_description,
                                     const ComputedStyleBuilder& builder) {
  float computed_size = GetComputedSizeFromSpecifiedSize(
      font_description, builder, font_description.SpecifiedSize());
  computed_size = TextAutosizer::ComputeAutosizedFontSize(
      computed_size, builder.TextAutosizingMultiplier(),
      builder.EffectiveZoom());
  font_description.SetComputedSize(computed_size);
}

bool FontBuilder::UpdateFontDescription(FontDescription& description,
                                        FontOrientation font_orientation) {
  bool modified = false;
  if (IsSet(PropertySetFlag::kFamily)) {
    if (description.GenericFamily() != font_description_.GenericFamily() ||
        description.Family() != font_description_.Family()) {
      modified = true;
      description.SetGenericFamily(font_description_.GenericFamily());
      description.SetFamily(font_description_.Family());
    }
  }
  if (IsSet(PropertySetFlag::kSize)) {
    if (description.KeywordSize() != font_description_.KeywordSize() ||
        description.SpecifiedSize() != font_description_.SpecifiedSize() ||
        description.IsAbsoluteSize() != font_description_.IsAbsoluteSize()) {
      modified = true;
      description.SetKeywordSize(font_description_.KeywordSize());
      description.SetSpecifiedSize(font_description_.SpecifiedSize());
      description.SetIsAbsoluteSize(font_description_.IsAbsoluteSize());
    }
  }

  if (IsSet(PropertySetFlag::kSizeAdjust)) {
    if (description.SizeAdjust() != font_description_.SizeAdjust()) {
      modified = true;
      description.SetSizeAdjust(font_description_.SizeAdjust());
    }
  }
  if (IsSet(PropertySetFlag::kWeight)) {
    if (description.Weight() != font_description_.Weight()) {
      modified = true;
      description.SetWeight(font_description_.Weight());
    }
  }
  if (IsSet(PropertySetFlag::kStretch)) {
    if (description.Stretch() != font_description_.Stretch()) {
      modified = true;
      description.SetStretch(font_description_.Stretch());
    }
  }
  if (IsSet(PropertySetFlag::kFeatureSettings)) {
    if (description.FeatureSettings() != font_description_.FeatureSettings()) {
      modified = true;
      description.SetFeatureSettings(font_description_.FeatureSettings());
    }
  }
  if (IsSet(PropertySetFlag::kLocale)) {
    if (description.Locale() != font_description_.Locale()) {
      modified = true;
      description.SetLocale(font_description_.Locale());
    }
  }
  if (IsSet(PropertySetFlag::kStyle)) {
    if (description.Style() != font_description_.Style()) {
      modified = true;
      description.SetStyle(font_description_.Style());
    }
  }
  if (IsSet(PropertySetFlag::kVariantCaps)) {
    if (description.VariantCaps() != font_description_.VariantCaps()) {
      modified = true;
      description.SetVariantCaps(font_description_.VariantCaps());
    }
  }
  if (IsSet(PropertySetFlag::kVariantEastAsian)) {
    if (description.VariantEastAsian() !=
        font_description_.VariantEastAsian()) {
      modified = true;
      description.SetVariantEastAsian(font_description_.VariantEastAsian());
    }
  }
  if (IsSet(PropertySetFlag::kVariantLigatures)) {
    if (description.GetVariantLigatures() !=
        font_description_.GetVariantLigatures()) {
      modified = true;
      description.SetVariantLigatures(font_description_.GetVariantLigatures());
    }
  }
  if (IsSet(PropertySetFlag::kVariantNumeric)) {
    if (description.VariantNumeric() != font_description_.VariantNumeric()) {
      modified = true;
      description.SetVariantNumeric(font_description_.VariantNumeric());
    }
  }
  if (IsSet(PropertySetFlag::kVariationSettings)) {
    if (description.VariationSettings() !=
        font_description_.VariationSettings()) {
      modified = true;
      description.SetVariationSettings(font_description_.VariationSettings());
    }
  }
  if (IsSet(PropertySetFlag::kFontSynthesisWeight)) {
    if (description.GetFontSynthesisWeight() !=
        font_description_.GetFontSynthesisWeight()) {
      modified = true;
      description.SetFontSynthesisWeight(
          font_description_.GetFontSynthesisWeight());
    }
  }
  if (IsSet(PropertySetFlag::kFontSynthesisStyle)) {
    if (description.GetFontSynthesisStyle() !=
        font_description_.GetFontSynthesisStyle()) {
      modified = true;
      description.SetFontSynthesisStyle(
          font_description_.GetFontSynthesisStyle());
    }
  }
  if (IsSet(PropertySetFlag::kFontSynthesisSmallCaps)) {
    if (description.GetFontSynthesisSmallCaps() !=
        font_description_.GetFontSynthesisSmallCaps()) {
      modified = true;
      description.SetFontSynthesisSmallCaps(
          font_description_.GetFontSynthesisSmallCaps());
    }
  }
  if (IsSet(PropertySetFlag::kTextRendering)) {
    if (description.TextRendering() != font_description_.TextRendering()) {
      modified = true;
      description.SetTextRendering(font_description_.TextRendering());
    }
  }
  if (IsSet(PropertySetFlag::kKerning)) {
    if (description.GetKerning() != font_description_.GetKerning()) {
      modified = true;
      description.SetKerning(font_description_.GetKerning());
    }
  }
  if (IsSet(PropertySetFlag::kTextSpacingTrim)) {
    if (description.GetTextSpacingTrim() !=
        font_description_.GetTextSpacingTrim()) {
      modified = true;
      description.SetTextSpacingTrim(font_description_.GetTextSpacingTrim());
    }
  }
  if (IsSet(PropertySetFlag::kFontOpticalSizing)) {
    if (description.FontOpticalSizing() !=
        font_description_.FontOpticalSizing()) {
      modified = true;
      description.SetFontOpticalSizing(font_description_.FontOpticalSizing());
    }
  }
  if (IsSet(PropertySetFlag::kFontPalette)) {
    if (description.GetFontPalette() != font_description_.GetFontPalette()) {
      modified = true;
      description.SetFontPalette(font_description_.GetFontPalette());
    }
  }
  if (IsSet(PropertySetFlag::kFontVariantAlternates)) {
    if (description.GetFontVariantAlternates() !=
        font_description_.GetFontVariantAlternates()) {
      modified = true;
      description.SetFontVariantAlternates(
          font_description_.GetFontVariantAlternates());
    }
  }
  if (IsSet(PropertySetFlag::kFontSmoothing)) {
    if (description.FontSmoothing() != font_description_.FontSmoothing()) {
      modified = true;
      description.SetFontSmoothing(font_description_.FontSmoothing());
    }
  }
  if (IsSet(PropertySetFlag::kTextOrientation) ||
      IsSet(PropertySetFlag::kWritingMode)) {
    if (description.Orientation() != font_orientation) {
      modified = true;
      description.SetOrientation(font_orientation);
    }
  }
  if (IsSet(PropertySetFlag::kVariantPosition)) {
    if (description.VariantPosition() != font_description_.VariantPosition()) {
      modified = true;
      description.SetVariantPosition(font_description_.VariantPosition());
    }
  }
  if (IsSet(PropertySetFlag::kVariantEmoji)) {
    if (description.VariantEmoji() != font_description_.VariantEmoji()) {
      modified = true;
      description.SetVariantEmoji(font_description_.VariantEmoji());
    }
  }
  if (!modified && !IsSet(PropertySetFlag::kEffectiveZoom) &&
      !IsSet(PropertySetFlag::kTextSizeAdjust)) {
    return false;
  }

  float size = description.SpecifiedSize();
  if (!size && description.KeywordSize()) {
    size = FontSizeForKeyword(description.KeywordSize(),
                              description.IsMonospace());
  }

  description.SetSpecifiedSize(size);
  description.SetComputedSize(size);
  if (size && description.HasSizeAdjust()) {
    description.SetAdjustedSize(size);
  }
  return true;
}

FontSelector* FontBuilder::FontSelectorFromTreeScope(
    const TreeScope* tree_scope) {
  // TODO(crbug.com/437837): The tree_scope may be from a different Document in
  // the case where we are resolving style for elements in a <svg:use> shadow
  // tree.
  DCHECK(!tree_scope || tree_scope->GetDocument() == document_ ||
         tree_scope->GetDocument().IsSVGDocument());
  // TODO(crbug.com/336876): Font selector should be based on tree_scope for
  // tree-scoped references.
  return document_->GetStyleEngine().GetFontSelector();
}

FontSelector* FontBuilder::ComputeFontSelector(
    const ComputedStyleBuilder& builder) {
  if (IsSet(PropertySetFlag::kFamily)) {
    return FontSelectorFromTreeScope(family_tree_scope_);
  } else {
    return builder.GetFont().GetFontSelector();
  }
}

void FontBuilder::CreateFont(ComputedStyleBuilder& builder,
                             const ComputedStyle* parent_style) {
  DCHECK(document_);

  if (!flags_) {
    return;
  }

  // TODO(crbug.com/1086680): Avoid nullptr parent style.
  const FontDescription& parent_description =
      parent_style ? parent_style->GetFontDescription()
                   : builder.GetFontDescription();

  FontDescription description = builder.GetFontDescription();
  if (!UpdateFontDescription(description, builder.ComputeFontOrientation())) {
    // Early exit; nothing was actually changed (i.e., everything that was set
    // already matched the initial/parent style).
    flags_ = 0;
    return;
  }
  UpdateSpecifiedSize(description, parent_description);
  UpdateComputedSize(description, builder);

  FontSelector* font_selector = ComputeFontSelector(builder);
  UpdateAdjustedSize(description, font_selector);

  builder.SetFont(Font(description, font_selector));
  flags_ = 0;
}

void FontBuilder::CreateInitialFont(ComputedStyleBuilder& builder) {
  DCHECK(document_);
  FontDescription font_description = FontDescription();
  font_description.SetLocale(builder.GetFontDescription().Locale());

  SetFamilyDescription(font_description,
                       FontBuilder::InitialFamilyDescription());
  SetSize(font_description,
          FontDescription::Size(FontSizeFunctions::InitialKeywordSize(), 0.0f,
                                false));
  UpdateSpecifiedSize(font_description, builder.GetFontDescription());
  UpdateComputedSize(font_description, builder);

  font_description.SetOrientation(builder.ComputeFontOrientation());

  FontSelector* font_selector = document_->GetStyleEngine().GetFontSelector();
  builder.SetFont(Font(font_description, font_selector));
}

}  // namespace blink
```