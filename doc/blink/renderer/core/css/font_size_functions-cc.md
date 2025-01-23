Response:
Let's break down the thought process for analyzing this C++ source code file.

**1. Understanding the Goal:**

The request asks for an analysis of `font_size_functions.cc`. Specifically, it wants to know:

* **Functionality:** What does this code do?
* **Relationship to Web Technologies:** How does it relate to JavaScript, HTML, and CSS?
* **Logic and Examples:** Can we illustrate its logic with inputs and outputs?
* **Common Errors:** What mistakes might users or programmers make that relate to this code?
* **Debugging Context:** How might a developer end up looking at this file during debugging?

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for keywords and structure. I'm looking for things like:

* `#include`:  Indicates dependencies on other parts of the Blink engine (CSS, DOM, Frame, Platform/Fonts). This immediately suggests a connection to rendering and layout.
* `namespace blink`:  Confirms this is Blink-specific code.
* `kFontSizeTableMax`, `kDefaultMediumFontSize`, `kFontSizeTableMin`, `kTotalKeywords`: These constants hint at tables and calculations related to font sizes.
* `kQuirksFontSizeTable`, `kStrictFontSizeTable`:  These strongly suggest handling different rendering modes (quirks vs. strict) for font sizes, tying directly into browser compatibility.
* `kFontSizeFactors`:  Looks like scaling factors for font sizes.
* Function names like `GetComputedSizeFromSpecifiedSize`, `FontSizeForKeyword`, `LegacyFontSize`, `FontAspectValue`, `MetricsMultiplierAdjustedFontSize`: These are the core actions this file performs. They directly relate to CSS `font-size` properties and related concepts.
* `Document*`, `Settings*`, `SimpleFontData*`, `FontDescription&`:  These parameter types tell us the functions interact with the DOM, browser settings, and font information.
* `ApplyMinimumFontSize`:  This suggests handling browser settings for minimum font sizes.

**3. Deeper Dive into Functionality (Function by Function):**

Now, I'll analyze each function individually:

* **`GetComputedSizeFromSpecifiedSize`:**  This is clearly the central function for calculating the final font size. It takes specified sizes, zoom factors, and considers minimum font size settings. The `is_absolute_size` parameter hints at how different CSS size units (e.g., `px` vs. keywords) are handled.
* **`FontSizeForKeyword`:** This function takes a keyword (like "small", "medium", "large") and returns the corresponding pixel size. The use of `kQuirksFontSizeTable` and `kStrictFontSizeTable` is prominent here, showing how browser mode affects keyword interpretation.
* **`LegacyFontSize`:** This seems to map a pixel font size back to the old HTML `<font size="...">` values (1-7). This is crucial for backward compatibility.
* **`FontAspectValue`:** This function calculates the aspect ratio of a font based on metrics like cap height or x-height. This connects to the CSS `font-size-adjust` property.
* **`MetricsMultiplierAdjustedFontSize`:**  This function implements the logic for `font-size-adjust`, using the aspect value to adjust the font size for better readability.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

With the function analysis done, I can now explicitly link these C++ functions to the web technologies:

* **CSS `font-size` property:**  All these functions are directly involved in processing CSS `font-size` values, including keywords, pixel values, and adjustments.
* **HTML `<font size="...">` tag:**  `LegacyFontSize` is the direct link here.
* **CSS `font-size-adjust` property:** `FontAspectValue` and `MetricsMultiplierAdjustedFontSize` are responsible for implementing this feature.
* **Browser Settings:** The code interacts with `Settings` to respect user preferences for default and minimum font sizes.
* **DOM:** The functions receive `Document*` as input, indicating they operate within the context of a web page.
* **JavaScript (Indirect):** While this C++ code isn't directly called by JavaScript, it's part of the rendering engine that *implements* the CSS features that JavaScript can manipulate (e.g., setting `element.style.fontSize`).

**5. Logic and Examples (Input/Output):**

For each key function, I can now create simple examples to illustrate their behavior, considering different scenarios like quirks mode, strict mode, and user settings. The tables themselves provide good examples of input and output for keyword-based sizes.

**6. Common Errors:**

Thinking about how developers might misuse font sizes helps identify common errors:

* **Assuming consistent keyword sizes across browsers:**  The existence of quirks and strict modes highlights this potential pitfall.
* **Ignoring user settings:** Developers might not realize that the browser can override their specified font sizes based on user preferences.
* **Misunderstanding `font-size-adjust`:** This is a less common but potentially confusing CSS property.

**7. Debugging Context:**

Finally, I consider scenarios where a developer might need to examine this code:

* **Layout issues:** If text isn't rendering at the expected size, this code is a prime suspect.
* **Cross-browser inconsistencies:** Differences in font rendering between browsers might lead a developer here.
* **Implementation of new CSS features:** Developers working on new CSS features related to fonts would need to understand this code.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus too much on the low-level C++ details.
* **Correction:**  Shift the focus to the *purpose* of the code and its connection to web technologies. The request is about understanding the *functionality*, not necessarily the intricate implementation details.
* **Initial thought:**  Overlook the impact of browser settings.
* **Correction:** Emphasize the role of `Settings` and how user preferences are taken into account.
* **Initial thought:** Not enough concrete examples.
* **Correction:** Add specific input/output examples to illustrate the behavior of the key functions.

By following this structured approach, breaking down the problem, and thinking from the perspective of a web developer, I can generate a comprehensive and informative analysis of the `font_size_functions.cc` file.
这个文件 `blink/renderer/core/css/font_size_functions.cc` 是 Chromium Blink 渲染引擎的一部分，专门负责处理 **CSS 字体大小**相关的计算和转换。  它的主要功能是：

**1. 计算和解析 CSS 字体大小值:**

*   **处理绝对和相对大小:**  该文件包含逻辑来处理各种 CSS 字体大小单位，例如像素 (`px`)、`em`、`rem`、百分比 (`%`) 以及关键字 (`xx-small`, `small`, `medium`, `large` 等)。
*   **考虑用户设置:** 它会读取浏览器的字体大小设置（例如用户设置的默认字体大小和最小字体大小），并将其纳入字体大小的计算中。
*   **处理缩放:**  它会考虑页面缩放因子（`zoom_factor`），以确保字体大小在缩放时能够正确调整。
*   **处理 `font-size-adjust` 属性:** 文件中包含了对 `font-size-adjust` CSS 属性的支持，该属性允许在字体不可用时保持文本的可读性。

**2. 提供 CSS 字体大小关键字的映射:**

*   **定义字体大小表格:**  文件中定义了两个关键的字体大小查找表 (`kQuirksFontSizeTable` 和 `kStrictFontSizeTable`)，分别用于 Quirks 模式和 Strict 模式。这些表格将 CSS 字体大小关键字（如 `small`, `medium`, `large`）映射到具体的像素值。
*   **考虑浏览器模式:**  根据文档的渲染模式（Quirks 模式或 Strict 模式），选择不同的字体大小表格进行映射。
*   **处理超出表格范围的情况:**  对于超出表格范围的字体大小，使用预定义的缩放因子 (`kFontSizeFactors`) 进行计算。

**3. 提供与旧版 HTML `<font>` 标签的兼容性:**

*   **映射到旧版字体大小:**  `LegacyFontSize` 函数可以将像素字体大小映射回旧版 HTML `<font size="...">` 标签的 1 到 7 的值，用于处理旧的网页。

**4. 提供字体度量值的访问:**

*   **计算字体纵横比:**  `FontAspectValue` 函数可以根据给定的字体数据和度量标准（例如 cap height, x-height）计算出字体的纵横比。这对于 `font-size-adjust` 的计算至关重要。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

这个文件直接参与了 CSS `font-size` 属性的实现，因此与这三个 Web 核心技术都有密切关系。

*   **CSS:**
    *   **`font-size` 属性:** 该文件最核心的功能就是处理 CSS 的 `font-size` 属性。例如，当浏览器解析到 `font-size: 16px;` 或 `font-size: large;` 时，会调用该文件中的函数来计算最终的像素大小。
    *   **`font-size-adjust` 属性:**  该文件实现了 `font-size-adjust` 属性的逻辑。例如，如果 CSS 中设置了 `font-size-adjust: 0.5 from cap-height;`，文件中的 `MetricsMultiplierAdjustedFontSize` 函数会被调用来根据字体实际的 cap height 调整字体大小。

*   **HTML:**
    *   **`<font size="...">` 标签 (遗留):**  `LegacyFontSize` 函数处理了与旧版 HTML `<font>` 标签的兼容性。例如，如果遇到 `<font size="4">`，该函数会将其转换为相应的像素字体大小。

*   **JavaScript:**
    *   **修改 `element.style.fontSize`:** 当 JavaScript 代码通过 `element.style.fontSize = '20px';` 或 `element.style.fontSize = 'larger';` 修改元素的字体大小时，Blink 引擎最终会调用这个文件中的函数来计算生效的像素值。
    *   **`getComputedStyle`:** 当 JavaScript 使用 `getComputedStyle(element).fontSize` 获取元素的最终计算后的字体大小时，该文件中计算出的值会被返回。

**逻辑推理、假设输入与输出:**

**假设输入:**

*   **CSS:** `font-size: small;`
*   **浏览器模式:** Strict 模式
*   **用户默认字体大小:** 16px (假设映射到表格的第 8 行，索引为 7)

**输出 (根据 `kStrictFontSizeTable`):**

*   `FontSizeForKeyword` 函数会被调用，`keyword` 参数对应 `small` (假设为索引 2)，`row` 参数为 7。
*   查找 `kStrictFontSizeTable[7][2]`，得到值为 13。
*   因此，最终计算出的字体大小为 `13px`。

**假设输入:**

*   **CSS:** `font-size: 1.2em;`
*   **父元素字体大小:** 10px
*   **缩放因子:** 1.0

**输出:**

*   `GetComputedSizeFromSpecifiedSize` 函数会被调用，`specified_size` 为 `1.2 * 10 = 12`。
*   如果没有最小字体大小限制，输出为 `12px`。

**用户或编程常见的使用错误:**

*   **假设字体大小关键字在所有浏览器中都一致:**  开发者可能会错误地认为 `small` 在所有浏览器中都呈现相同的大小。然而，Quirks 模式和 Strict 模式下，以及不同的浏览器实现，这些关键字的映射可能略有不同。
    *   **用户操作到达这里:** 用户可能会在一个 Quirks 模式的网页上看到字体大小与预期不符。开发者在调试时会检查 CSS 规则，最终可能会追踪到 Blink 引擎的字体大小计算逻辑。

*   **忽略用户的字体大小设置:**  开发者可能会设置一个非常小的固定字体大小，而忽略了用户在浏览器中设置的最小字体大小。
    *   **用户操作到达这里:** 用户在浏览器中设置了最小字体大小，但访问的网页上的文字仍然很小。用户可能会报告网页显示问题，开发者在调查时会发现 Blink 引擎因为用户设置而提升了字体大小。

*   **过度依赖像素单位，导致在不同设备上显示效果不佳:**  开发者可能只使用像素单位来定义字体大小，而没有考虑到不同屏幕密度和设备尺寸。
    *   **用户操作到达这里:** 用户在高清屏幕上看到字体过小，或者在小屏幕设备上看到字体过大。开发者在调试布局问题时，会发现字体大小的计算方式与预期不符。

*   **错误理解 `font-size-adjust` 的作用:** 开发者可能没有正确理解 `font-size-adjust` 的工作原理，导致在字体回退时出现意外的字体大小。
    *   **用户操作到达这里:** 用户使用的字体在网页上不可用，浏览器回退到其他字体，但由于 `font-size-adjust` 的影响，字体大小看起来不协调。开发者在检查字体渲染时，会深入研究 `font-size-adjust` 的实现。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户打开一个网页:** 用户在浏览器中输入网址或点击链接，加载一个包含 CSS 样式规则的 HTML 页面。
2. **Blink 引擎解析 HTML 和 CSS:**  Blink 引擎的 HTML 解析器和 CSS 解析器会分别解析 HTML 结构和 CSS 样式规则。
3. **遇到 `font-size` 属性:** 当 CSS 解析器遇到一个包含 `font-size` 属性的规则时（例如 `p { font-size: 16px; }` 或 `h1 { font-size: large; }`），它会记录下这个属性及其值。
4. **计算样式:**  Blink 引擎的样式计算模块会根据 CSS 规则、继承关系、层叠顺序等因素，计算出每个元素最终生效的样式，包括 `font-size`。
5. **调用 `font_size_functions.cc` 中的函数:**  在计算 `font-size` 的过程中，Blink 引擎会调用 `blink/renderer/core/css/font_size_functions.cc` 文件中的相应函数，例如：
    *   如果 `font-size` 是一个像素值，`GetComputedSizeFromSpecifiedSize` 函数会被调用。
    *   如果 `font-size` 是一个关键字，`FontSizeForKeyword` 函数会被调用。
    *   如果存在 `font-size-adjust` 属性，`MetricsMultiplierAdjustedFontSize` 函数会被调用。
6. **考虑用户设置和浏览器模式:**  在计算过程中，这些函数会读取浏览器的字体大小设置（通过 `Document::GetSettings()`）和文档的渲染模式（通过 `Document::InQuirksMode()`），以便应用正确的计算逻辑和查找表。
7. **返回计算后的像素值:**  最终，`font_size_functions.cc` 中的函数会返回计算后的字体大小的像素值。
8. **渲染文本:**  Blink 引擎的布局和绘制模块会使用计算出的字体大小来渲染页面上的文本。

**作为调试线索:**

当开发者遇到与字体大小相关的 Bug 时，例如：

*   **文本大小不正确:** 页面上的文字看起来比预期的更大或更小。
*   **不同浏览器字体大小不一致:** 同一个网页在不同的浏览器中字体大小显示不同。
*   **`font-size-adjust` 没有生效:** 字体回退时的显示效果不佳。

开发者可以通过以下步骤进行调试，并可能最终追踪到 `font_size_functions.cc`：

1. **检查 CSS 规则:** 使用浏览器的开发者工具检查元素的 CSS 规则，确认 `font-size` 属性的值是否正确。
2. **查看计算后的样式:**  在开发者工具中查看元素的 "Computed" (计算后) 样式，确认最终生效的 `font-size` 值是多少。
3. **对比不同浏览器的计算结果:**  如果怀疑是浏览器差异导致的问题，可以在不同的浏览器中查看计算后的 `font-size` 值。
4. **检查浏览器设置:**  确认用户的浏览器字体大小设置是否影响了页面的显示。
5. **源码调试:**  如果需要深入了解 Blink 引擎是如何计算字体大小的，开发者可以使用调试器 (例如 gdb) 附加到 Chromium 进程，并设置断点在 `blink/renderer/core/css/font_size_functions.cc` 中的相关函数上，例如 `GetComputedSizeFromSpecifiedSize` 或 `FontSizeForKeyword`，来跟踪代码的执行流程，查看输入参数和计算过程，从而定位问题所在。

总而言之，`blink/renderer/core/css/font_size_functions.cc` 是 Blink 引擎中一个核心的模块，负责将 CSS 中声明的各种字体大小值转换为浏览器最终用于渲染的像素值，并需要考虑用户设置、浏览器模式以及与旧版 HTML 的兼容性。理解这个文件的功能对于理解浏览器如何处理字体大小至关重要，也是调试相关问题的关键。

### 提示词
```
这是目录为blink/renderer/core/css/font_size_functions.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 2004-2005 Allan Sandfeld Jensen (kde@carewolf.com)
 * Copyright (C) 2006, 2007 Nicholas Shanks (webkit@nickshanks.com)
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013 Apple Inc.
 * All rights reserved.
 * Copyright (C) 2007 Alexey Proskuryakov <ap@webkit.org>
 * Copyright (C) 2007, 2008 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2008, 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (c) 2011, Code Aurora Forum. All rights reserved.
 * Copyright (C) Research In Motion Limited 2011. All rights reserved.
 * Copyright (C) 2012 Google Inc. All rights reserved.
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
 */

#include "third_party/blink/renderer/core/css/font_size_functions.h"

#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/fonts/simple_font_data.h"

namespace blink {

namespace {

const int kFontSizeTableMax = 16;
const int kDefaultMediumFontSize = 12;
const int kFontSizeTableMin = 9;
const int kTotalKeywords = 8;

constexpr auto kFontSizeTableSize = kFontSizeTableMax - kFontSizeTableMin + 1;

using FontSizeTableType =
    std::array<std::array<int, kTotalKeywords>, kFontSizeTableSize>;

// WinIE/Nav4 table for font sizes. Designed to match the legacy font mapping
// system of HTML.
const FontSizeTableType kQuirksFontSizeTable{{
    {9, 9, 9, 9, 11, 14, 18, 28},
    {9, 9, 9, 10, 12, 15, 20, 31},
    {9, 9, 9, 11, 13, 17, 22, 34},
    {9, 9, 10, 12, 14, 18, 24, 37},
    {9, 9, 10, 13, 16, 20, 26, 40},  // fixed font default (13)
    {9, 9, 11, 14, 17, 21, 28, 42},
    {9, 10, 12, 15, 17, 23, 30, 45},
    {9, 10, 13, 16, 18, 24, 32, 48}  // proportional font default (16)
}};
// HTML       1      2      3      4      5      6      7
// CSS  xxs   xs     s      m      l     xl     xxl
//                          |
//                      user pref

// Strict mode table matches MacIE and Mozilla's settings exactly.
const FontSizeTableType kStrictFontSizeTable{{
    {9, 9, 9, 9, 11, 14, 18, 27},
    {9, 9, 9, 10, 12, 15, 20, 30},
    {9, 9, 10, 11, 13, 17, 22, 33},
    {9, 9, 10, 12, 14, 18, 24, 36},
    {9, 10, 12, 13, 16, 20, 26, 39},  // fixed font default (13)
    {9, 10, 12, 14, 17, 21, 28, 42},
    {9, 10, 13, 15, 18, 23, 30, 45},
    {9, 10, 13, 16, 18, 24, 32, 48}  // proportional font default (16)
}};
// HTML       1      2      3      4      5      6      7
// CSS  xxs   xs     s      m      l     xl     xxl
//                          |
//                      user pref

// For values outside the range of the table, we use Todd Fahrner's suggested
// scale factors for each keyword value.
const std::array<float, kTotalKeywords> kFontSizeFactors{
    0.60f, 0.75f, 0.89f, 1.0f, 1.2f, 1.5f, 2.0f, 3.0f};

int inline RowFromMediumFontSizeInRange(const Settings* settings,
                                        bool quirks_mode,
                                        bool is_monospace,
                                        int& medium_size) {
  medium_size = settings ? (is_monospace ? settings->GetDefaultFixedFontSize()
                                         : settings->GetDefaultFontSize())
                         : kDefaultMediumFontSize;
  if (medium_size >= kFontSizeTableMin && medium_size <= kFontSizeTableMax) {
    return medium_size - kFontSizeTableMin;
  }
  return -1;
}

template <typename T>
int FindNearestLegacyFontSize(int pixel_font_size,
                              const std::array<T, kTotalKeywords>& table,
                              int multiplier) {
  // Ignore table[0] because xx-small does not correspond to any legacy font
  // size.
  for (int i = 1; i < kTotalKeywords - 1; i++) {
    if (pixel_font_size * 2 < (table[i] + table[i + 1]) * multiplier) {
      return i;
    }
  }
  return kTotalKeywords - 1;
}

float AspectValue(const SimpleFontData& font_data,
                  FontSizeAdjust::Metric metric,
                  float computed_size) {
  DCHECK(computed_size);
  const FontMetrics& font_metrics = font_data.GetFontMetrics();
  // We return fallback values for missing font metrics.
  // https://github.com/w3c/csswg-drafts/issues/6384
  float aspect_value = 1.0;
  switch (metric) {
    case FontSizeAdjust::Metric::kCapHeight:
      if (font_metrics.CapHeight() > 0) {
        aspect_value = font_metrics.CapHeight() / computed_size;
      }
      break;
    case FontSizeAdjust::Metric::kChWidth:
      if (font_metrics.HasZeroWidth()) {
        aspect_value = font_metrics.ZeroWidth() / computed_size;
      }
      break;
    case FontSizeAdjust::Metric::kIcWidth:
      if (const std::optional<float>& size =
              font_data.IdeographicAdvanceWidth()) {
        aspect_value = *size / computed_size;
      }
      break;
    case FontSizeAdjust::Metric::kIcHeight: {
      if (const std::optional<float>& size =
              font_data.IdeographicAdvanceHeight()) {
        aspect_value = *size / computed_size;
      }
      break;
    }
    case FontSizeAdjust::Metric::kExHeight:
    default:
      if (font_metrics.HasXHeight()) {
        aspect_value = font_metrics.XHeight() / computed_size;
      }
  }
  return aspect_value;
}

}  // namespace

float FontSizeFunctions::GetComputedSizeFromSpecifiedSize(
    const Document* document,
    float zoom_factor,
    bool is_absolute_size,
    float specified_size,
    ApplyMinimumFontSize apply_minimum_font_size) {
  // Text with a 0px font size should not be visible and therefore needs to be
  // exempt from minimum font size rules. Acid3 relies on this for pixel-perfect
  // rendering. This is also compatible with other browsers that have minimum
  // font size settings (e.g. Firefox).
  if (fabsf(specified_size) < std::numeric_limits<float>::epsilon()) {
    return 0.0f;
  }

  Settings* settings = document->GetSettings();
  if (apply_minimum_font_size && settings) {
    // We support two types of minimum font size. The first is a hard override
    // that applies to all fonts. This is "min_size." The second type of minimum
    // font size is a "smart minimum" that is applied only when the Web page
    // can't know what size it really asked for, e.g., when it uses logical
    // sizes like "small" or expresses the font-size as a percentage of the
    // user's default font setting.

    // With the smart minimum, we never want to get smaller than the minimum
    // font size to keep fonts readable. However we always allow the page to set
    // an explicit pixel size that is smaller, since sites will mis-render
    // otherwise (e.g., http://www.gamespot.com with a 9px minimum).

    int min_size = settings->GetMinimumFontSize();
    int min_logical_size = settings->GetMinimumLogicalFontSize();

    // Apply the hard minimum first.
    if (specified_size < min_size) {
      specified_size = min_size;
    }

    // Now apply the "smart minimum". The font size must either be relative to
    // the user default or the original size must have been acceptable. In other
    // words, we only apply the smart minimum whenever we're positive doing so
    // won't disrupt the layout.
    if (specified_size < min_logical_size && !is_absolute_size) {
      specified_size = min_logical_size;
    }
  }
  // Also clamp to a reasonable maximum to prevent insane font sizes from
  // causing crashes on various platforms (I'm looking at you, Windows.)
  return std::min(kMaximumAllowedFontSize, specified_size * zoom_factor);
}

float FontSizeFunctions::FontSizeForKeyword(const Document* document,
                                            unsigned keyword,
                                            bool is_monospace) {
  DCHECK_GE(keyword, 1u);
  DCHECK_LE(keyword, 8u);
  const Settings* settings = document ? document->GetSettings() : nullptr;
  bool quirks_mode = document ? document->InQuirksMode() : false;

  int medium_size = 0;
  int row = RowFromMediumFontSizeInRange(settings, quirks_mode, is_monospace,
                                         medium_size);
  if (row >= 0) {
    int col = (keyword - 1);
    return quirks_mode ? kQuirksFontSizeTable[row][col]
                       : kStrictFontSizeTable[row][col];
  }

  // Value is outside the range of the table. Apply the scale factor instead.
  float min_logical_size =
      settings ? std::max(settings->GetMinimumLogicalFontSize(), 1) : 1;
  return std::max(kFontSizeFactors[keyword - 1] * medium_size,
                  min_logical_size);
}

int FontSizeFunctions::LegacyFontSize(const Document* document,
                                      int pixel_font_size,
                                      bool is_monospace) {
  const Settings* settings = document->GetSettings();
  if (!settings) {
    return 1;
  }

  bool quirks_mode = document->InQuirksMode();
  int medium_size = 0;
  int row = RowFromMediumFontSizeInRange(settings, quirks_mode, is_monospace,
                                         medium_size);
  if (row >= 0) {
    return FindNearestLegacyFontSize<int>(
        pixel_font_size,
        quirks_mode ? kQuirksFontSizeTable[row] : kStrictFontSizeTable[row], 1);
  }

  return FindNearestLegacyFontSize<float>(pixel_font_size, kFontSizeFactors,
                                          medium_size);
}

std::optional<float> FontSizeFunctions::FontAspectValue(
    const SimpleFontData* font_data,
    FontSizeAdjust::Metric metric,
    float computed_size) {
  if (!font_data || !computed_size) {
    return std::nullopt;
  }

  float aspect_value = AspectValue(*font_data, metric, computed_size);
  if (!aspect_value) {
    return std::nullopt;
  }
  return aspect_value;
}

std::optional<float> FontSizeFunctions::MetricsMultiplierAdjustedFontSize(
    const SimpleFontData* font_data,
    const FontDescription& font_description) {
  DCHECK(font_data);
  const float computed_size = font_description.ComputedSize();
  const FontSizeAdjust size_adjust = font_description.SizeAdjust();
  if (!computed_size ||
      size_adjust.Value() == FontSizeAdjust::kFontSizeAdjustNone) {
    return std::nullopt;
  }

  float aspect_value =
      AspectValue(*font_data, size_adjust.GetMetric(), computed_size);
  if (!aspect_value) {
    return std::nullopt;
  }
  return (size_adjust.Value() / aspect_value) * computed_size;
}

}  // namespace blink
```