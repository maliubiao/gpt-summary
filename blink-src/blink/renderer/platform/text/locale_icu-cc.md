Response:
Let's break down the thought process for analyzing the `locale_icu.cc` file.

1. **Understand the Goal:** The primary objective is to understand the file's functionality and its relevance to JavaScript, HTML, and CSS. We also need to identify potential user/programmer errors and explore logical reasoning aspects.

2. **Initial Skim and Keywords:** Quickly read through the code, looking for keywords and patterns. Things that jump out are:
    * `#include`:  This immediately tells us about dependencies, specifically ICU (`<unicode/...>`).
    * `namespace blink`:  Confirms this is within the Blink rendering engine.
    * `Locale`, `LocaleICU`:  These are the central classes, suggesting this file is about handling locale-specific information.
    * `DateFormat`, `TimeFormat`, `DecimalSymbol`: These hint at formatting functionalities.
    * `Initialize...`: These functions likely set up internal state.
    * `UErrorCode`:  Indicates interactions with the ICU library, which returns status codes.
    * `String`, `StringBuffer`, `StringBuilder`:  Blink's string manipulation classes.
    * `kFallback...`:  Suggests default values if locale data isn't available.

3. **Identify Core Functionality - What does `LocaleICU` *do*?** Focus on the public methods of the `LocaleICU` class. These are the entry points for using its functionality. We see methods like:
    * `Create`:  A static factory method to instantiate `LocaleICU`.
    * `DecimalSymbol`, `DecimalTextAttribute`:  Getting symbols and attributes for number formatting.
    * `InitializeLocaleData`, `InitializeShortDateFormat`, `InitializeDateTimeFormat`: Initialization routines.
    * `MonthLabels`, `WeekDayShortLabels`, `FirstDayOfWeek`, `IsRTL`:  Accessing locale-specific data.
    * `DateFormat`, `TimeFormat`, `DateTimeFormatWithSeconds`, etc.:  Getting date and time format strings.
    * `MonthFormat`, `ShortMonthFormat`: Getting specific month format strings.
    * `ShortMonthLabels`, `StandAloneMonthLabels`, `ShortStandAloneMonthLabels`, `TimeAMPMLabels`: Accessing various label sets.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Now, think about how these functionalities relate to the browser's rendering and scripting capabilities.
    * **JavaScript:**  JavaScript's `Intl` API directly uses the underlying locale data provided by libraries like ICU (which this code interacts with). So, the date/time/number formatting, month names, weekday names, etc., are all crucial for `Intl`.
    * **HTML:**  HTML itself doesn't directly interact with this low-level code. However, HTML elements can *display* the formatted output produced by JavaScript using this data (e.g., displaying a date). The `lang` attribute on HTML elements is the mechanism for specifying the locale.
    * **CSS:** CSS has some locale-aware features, primarily related to text direction (`direction: rtl;`). The `IsRTL()` function in this code directly supports this CSS property. Also, CSS might influence the *display* of formatted dates/numbers, although the *formatting itself* is handled at a lower level.

5. **Illustrative Examples:**  For each connection to JavaScript, HTML, and CSS, create concrete examples:
    * **JavaScript:** Show how `Intl.DateTimeFormat`, `Intl.NumberFormat`, and `Intl.getCanonicalLocales` would use the data provided by this code.
    * **HTML:** Demonstrate the use of the `lang` attribute and how it implicitly affects date/number formatting (though the formatting is usually done via JS).
    * **CSS:** Show how `direction: rtl;` relies on the `IsRTL()` functionality.

6. **Logical Reasoning (Assumptions and Outputs):**  Focus on methods that perform transformations or calculations based on input. The `GetFormatForSkeleton` method is a good example.
    * **Input:** A locale string and a format skeleton (e.g., "yyyyMMMM").
    * **Process:**  It uses ICU's `udatpg_getBestPattern` to find the best matching format for the given skeleton in the specified locale.
    * **Output:**  A formatted date/time pattern string (e.g., "MMMM yyyy" for "en-US"). Create a few examples with different locales and skeletons to illustrate the logic.

7. **Common Errors:** Think about what could go wrong when using locale information:
    * **Incorrect Locale String:** Providing an invalid or unsupported locale code.
    * **Assuming Consistent Formatting:**  Forgetting that formatting varies significantly between locales.
    * **Locale Data Missing:**  If the underlying ICU data for a specific locale is not available, this code has fallback mechanisms, but it's worth noting.

8. **Structure and Refine:** Organize the information logically. Start with a summary of the file's purpose, then detail the functionalities, connections to web technologies, examples, logical reasoning, and common errors. Use clear and concise language.

9. **Self-Correction/Review:** After drafting the analysis, review it to ensure accuracy and completeness. Are the explanations clear? Are the examples relevant?  Have all aspects of the prompt been addressed?  For example, initially, I might have focused too much on the internal workings of ICU. The prompt asks for connections to web technologies, so I need to bring that to the forefront. Also, double-check the assumptions and outputs of the logical reasoning examples.

By following this systematic approach, breaking down the code into smaller, manageable parts, and focusing on the connections to web technologies, we can effectively analyze the `locale_icu.cc` file and provide a comprehensive explanation.
这个文件 `blink/renderer/platform/text/locale_icu.cc` 是 Chromium Blink 引擎中负责处理**本地化 (localization)** 相关功能的源代码文件。它主要通过调用 **ICU (International Components for Unicode)** 库来实现对不同语言和文化习惯的支持。

以下是该文件的主要功能：

**1. 提供 `LocaleICU` 类，用于封装特定语言环境的信息：**

*   **创建 `Locale` 对象:** `Locale::Create(const String& locale)` 是一个静态工厂方法，它接收一个表示语言环境的字符串（例如 "en-US", "zh-CN"），并创建一个 `LocaleICU` 实例。
*   **存储语言环境标识符:** `locale_` 成员变量存储了传递给构造函数的语言环境字符串。
*   **缓存 ICU 资源:**  `number_format_`, `short_date_format_`, `medium_time_format_`, `short_time_format_` 等成员变量用于缓存从 ICU 获取的格式化器对象，避免重复创建和销毁，提高性能。
*   **管理初始化状态:** `did_create_decimal_format_`, `did_create_short_date_format_`, `did_create_time_format_` 等布尔变量用于跟踪各种格式化器是否已经被初始化。
*   **析构函数:** `~LocaleICU()` 负责释放通过 ICU 创建的资源，例如关闭格式化器对象。

**2. 提供获取本地化数据的接口：**

*   **数字格式化：**
    *   `DecimalSymbol(UNumberFormatSymbol symbol)`: 获取特定数字符号（例如小数点、千位分隔符）的本地化表示。
    *   `DecimalTextAttribute(UNumberFormatTextAttribute tag)`: 获取数字格式化文本属性（例如正数前缀、负数后缀）。
    *   `InitializeLocaleData()`: 初始化数字格式化器，并获取各种数字符号和属性。
*   **日期和时间格式化：**
    *   `InitializeShortDateFormat()`: 初始化短日期格式化器。
    *   `OpenDateFormat(UDateFormatStyle time_style, UDateFormatStyle date_style)`: 创建一个指定日期和时间样式的 ICU 日期格式化器。
    *   `OpenDateFormatForStandAloneMonthLabels(bool is_short)`: 创建用于获取独立月份名称的日期格式化器（用于日历标题等）。
    *   `GetDateFormatPattern(const UDateFormat* date_format)`: 从日期格式化器中提取格式化模式字符串。
    *   `CreateLabelVector(...)`:  一个辅助函数，用于从日期格式化器中提取各种标签（例如月份名称、星期几名称）。
    *   `MonthLabels()`, `WeekDayShortLabels()`:  获取完整月份名称和简短星期几名称的本地化列表。如果 ICU 没有提供，则使用 fallback 值。
    *   `FirstDayOfWeek()`: 获取本地化的一周的第一天。
    *   `InitializeDateTimeFormat()`: 初始化各种时间格式化器。
    *   `DateFormat()`, `TimeFormat()`, `ShortTimeFormat()`, `DateTimeFormatWithSeconds()`, `DateTimeFormatWithoutSeconds()`: 获取各种日期和时间格式的模式字符串。
    *   `MonthFormat()`, `ShortMonthFormat()`:  获取月份的格式模式字符串。
    *   `ShortMonthLabels()`, `StandAloneMonthLabels()`, `ShortStandAloneMonthLabels()`, `TimeAMPMLabels()`: 获取各种月份名称和 AM/PM 标签的本地化列表。
*   **其他本地化信息：**
    *   `IsRTL()`: 判断当前语言环境是否为从右到左的排版方向。

**3. 与 JavaScript, HTML, CSS 的关系：**

这个文件直接影响着 JavaScript `Intl` API 的实现，以及浏览器对 HTML 和 CSS 中本地化相关特性的支持。

*   **JavaScript (Intl API):**
    *   `Intl.DateTimeFormat`: JavaScript 的 `Intl.DateTimeFormat` 对象依赖于 `LocaleICU` 提供的日期和时间格式化模式以及标签（例如月份名称、AM/PM）。当你在 JavaScript 中创建一个 `Intl.DateTimeFormat` 对象并指定一个 locale 时，Blink 引擎会使用 `LocaleICU` 来获取该 locale 对应的 ICU 格式化器和数据。
        *   **假设输入:** JavaScript 代码 `new Intl.DateTimeFormat('zh-CN').format(new Date())`
        *   **输出:**  `LocaleICU` 会被用来获取 "zh-CN" 的日期格式，最终 `format()` 方法会输出符合中文习惯的日期字符串，例如 "2023/10/27"。
    *   `Intl.NumberFormat`: 类似地，`Intl.NumberFormat` 依赖于 `LocaleICU` 提供的数字符号和格式。
        *   **假设输入:** JavaScript 代码 `new Intl.NumberFormat('de-DE').format(1234.56)`
        *   **输出:** `LocaleICU` 会获取德语的数字格式，输出结果可能是 "1.234,56"。
    *   `Intl.getCanonicalLocales`:  虽然 `locale_icu.cc` 不直接实现这个方法，但它提供的 `Locale` 抽象和 `LocaleICU` 实现是 `Intl` API 的基础。

*   **HTML:**
    *   **`lang` 属性:** HTML 元素的 `lang` 属性用于指定内容的语言。浏览器会利用这个信息来选择合适的本地化资源。虽然 `locale_icu.cc` 不直接处理 HTML，但它提供的功能是浏览器理解和应用 `lang` 属性的基础。例如，浏览器可能根据 `lang` 属性的值来选择不同的字体或者调整文本的排版方向（RTL）。
        *   **假设输入:** HTML 代码 `<p lang="ar">مرحبا</p>`
        *   **输出:**  由于 `lang` 属性设置为 "ar" (阿拉伯语)，`LocaleICU` 的 `IsRTL()` 方法会返回 true，浏览器可能会使用从右到左的布局来渲染该段落。

*   **CSS:**
    *   **`direction` 属性:** CSS 的 `direction` 属性可以显式指定文本的排版方向。`LocaleICU` 的 `IsRTL()` 方法的返回值可能会影响浏览器对 `direction` 属性的默认处理，尤其是在 `direction` 属性设置为 `auto` 时。
        *   **假设输入:** CSS 代码 `body { direction: auto; }`，并且当前页面语言设置为阿拉伯语 (`lang="ar"`)。
        *   **输出:**  由于 `LocaleICU` 对 "ar" 返回 `true`，浏览器可能会自动将 `body` 元素的文本方向设置为 `rtl`。

**4. 逻辑推理举例：**

*   **假设输入:**  请求创建一个 locale 为 "fr-CA" (加拿大法语) 的 `LocaleICU` 对象，并调用 `MonthLabels()`。
*   **输出:**  `LocaleICU` 会使用 ICU 库加载加拿大法语的月份名称，返回一个包含 "janvier", "février", "mars", ..., "décembre" 的 `Vector<String>`。如果 ICU 中没有 "fr-CA" 的特定数据，可能会回退到更通用的 "fr" 数据或者使用 fallback 值。

*   **假设输入:**  调用 `DecimalSymbol(UNUM_DECIMAL_SEPARATOR_SYMBOL)` 对于 "en-US" 和 "de-DE" 两个 `LocaleICU` 对象。
*   **输出:**
    *   对于 "en-US"，会返回字符串 "." (英文的小数点)。
    *   对于 "de-DE"，会返回字符串 "," (德文的小数点)。

**5. 用户或编程常见的使用错误举例：**

*   **使用错误的 locale 字符串:**  传递一个 ICU 不支持的或者拼写错误的 locale 字符串给 `Locale::Create()`，例如 "en_US" (应该用连字符 "en-US") 或 "xyz"。这可能导致无法正确加载本地化数据，或者使用默认的 fallback 值。
    *   **错误示例:** `Locale::Create("en_US");`
    *   **结果:**  可能无法创建有效的 `LocaleICU` 对象，或者加载的本地化数据不符合预期。

*   **假设所有 locale 的日期格式都相同:**  开发者可能会错误地假设所有语言的日期格式都像 "yyyy-MM-dd" 这样。
    *   **错误示例 (JavaScript):**  手动拼接日期字符串，例如 `year + "-" + month + "-" + day;` 而不使用 `Intl.DateTimeFormat`。
    *   **结果:**  在某些 locale 中，日期分隔符、年份月份的顺序可能不同，导致显示错误。例如，在 "en-US" 中，常见的格式是 "MM/dd/yyyy"。

*   **忽略 RTL 语言:** 在设计用户界面时，没有考虑到从右到左的语言（例如阿拉伯语、希伯来语）。
    *   **错误示例 (CSS):**  硬编码元素的左边距和右边距，而没有使用逻辑属性（如 `margin-inline-start` 和 `margin-inline-end`）。
    *   **结果:**  在 RTL 语言环境下，界面元素的布局可能会错乱。

*   **过度依赖 fallback 值:**  虽然 `LocaleICU` 提供了 fallback 机制，但过度依赖 fallback 值意味着用户体验可能不佳，因为显示的内容可能不符合用户的语言习惯。开发者应该确保系统或浏览器配置了正确的本地化数据。

总而言之，`blink/renderer/platform/text/locale_icu.cc` 是 Blink 引擎中一个至关重要的文件，它通过 ICU 库为浏览器提供了强大的本地化支持，直接影响着 Web 内容的国际化和本地化体验。理解这个文件的功能有助于开发者更好地理解浏览器如何处理不同语言和文化习惯，并避免常见的本地化错误。

Prompt: 
```
这是目录为blink/renderer/platform/text/locale_icu.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2011,2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/text/locale_icu.h"

#include <unicode/udatpg.h>
#include <unicode/udisplaycontext.h>
#include <unicode/uloc.h>

#include <iterator>
#include <limits>
#include <memory>

#include "base/memory/ptr_util.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"
#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ui/base/ui_base_features.h"

namespace blink {

std::unique_ptr<Locale> Locale::Create(const String& locale) {
  return std::make_unique<LocaleICU>(locale.Utf8());
}

LocaleICU::LocaleICU(const std::string& locale)
    : locale_(locale),
      number_format_(nullptr),
      short_date_format_(nullptr),
      did_create_decimal_format_(false),
      did_create_short_date_format_(false),
      medium_time_format_(nullptr),
      short_time_format_(nullptr),
      did_create_time_format_(false) {}

LocaleICU::~LocaleICU() {
  unum_close(number_format_);
  udat_close(short_date_format_);
  udat_close(medium_time_format_);
  udat_close(short_time_format_);
}

String LocaleICU::DecimalSymbol(UNumberFormatSymbol symbol) {
  UErrorCode status = U_ZERO_ERROR;
  int32_t buffer_length =
      unum_getSymbol(number_format_, symbol, nullptr, 0, &status);
  DCHECK(U_SUCCESS(status) || status == U_BUFFER_OVERFLOW_ERROR);
  if (U_FAILURE(status) && status != U_BUFFER_OVERFLOW_ERROR)
    return String();
  StringBuffer<UChar> buffer(buffer_length);
  status = U_ZERO_ERROR;
  unum_getSymbol(number_format_, symbol, buffer.Characters(), buffer_length,
                 &status);
  if (U_FAILURE(status))
    return String();
  return String::Adopt(buffer);
}

String LocaleICU::DecimalTextAttribute(UNumberFormatTextAttribute tag) {
  UErrorCode status = U_ZERO_ERROR;
  int32_t buffer_length =
      unum_getTextAttribute(number_format_, tag, nullptr, 0, &status);
  DCHECK(U_SUCCESS(status) || status == U_BUFFER_OVERFLOW_ERROR);
  if (U_FAILURE(status) && status != U_BUFFER_OVERFLOW_ERROR)
    return String();
  StringBuffer<UChar> buffer(buffer_length);
  status = U_ZERO_ERROR;
  unum_getTextAttribute(number_format_, tag, buffer.Characters(), buffer_length,
                        &status);
  DCHECK(U_SUCCESS(status));
  if (U_FAILURE(status))
    return String();
  return String::Adopt(buffer);
}

void LocaleICU::InitializeLocaleData() {
  if (did_create_decimal_format_)
    return;
  did_create_decimal_format_ = true;
  UErrorCode status = U_ZERO_ERROR;
  number_format_ =
      unum_open(UNUM_DECIMAL, nullptr, 0, locale_.c_str(), nullptr, &status);
  if (!U_SUCCESS(status))
    return;

  Vector<String, kDecimalSymbolsSize> symbols;
  symbols.push_back(DecimalSymbol(UNUM_ZERO_DIGIT_SYMBOL));
  symbols.push_back(DecimalSymbol(UNUM_ONE_DIGIT_SYMBOL));
  symbols.push_back(DecimalSymbol(UNUM_TWO_DIGIT_SYMBOL));
  symbols.push_back(DecimalSymbol(UNUM_THREE_DIGIT_SYMBOL));
  symbols.push_back(DecimalSymbol(UNUM_FOUR_DIGIT_SYMBOL));
  symbols.push_back(DecimalSymbol(UNUM_FIVE_DIGIT_SYMBOL));
  symbols.push_back(DecimalSymbol(UNUM_SIX_DIGIT_SYMBOL));
  symbols.push_back(DecimalSymbol(UNUM_SEVEN_DIGIT_SYMBOL));
  symbols.push_back(DecimalSymbol(UNUM_EIGHT_DIGIT_SYMBOL));
  symbols.push_back(DecimalSymbol(UNUM_NINE_DIGIT_SYMBOL));
  symbols.push_back(DecimalSymbol(UNUM_DECIMAL_SEPARATOR_SYMBOL));
  symbols.push_back(DecimalSymbol(UNUM_GROUPING_SEPARATOR_SYMBOL));
  DCHECK_EQ(symbols.size(), kDecimalSymbolsSize);
  SetLocaleData(symbols, DecimalTextAttribute(UNUM_POSITIVE_PREFIX),
                DecimalTextAttribute(UNUM_POSITIVE_SUFFIX),
                DecimalTextAttribute(UNUM_NEGATIVE_PREFIX),
                DecimalTextAttribute(UNUM_NEGATIVE_SUFFIX));
}

bool LocaleICU::InitializeShortDateFormat() {
  if (did_create_short_date_format_)
    return short_date_format_;
  short_date_format_ = OpenDateFormat(UDAT_NONE, UDAT_SHORT);
  did_create_short_date_format_ = true;
  return short_date_format_;
}

UDateFormat* LocaleICU::OpenDateFormat(UDateFormatStyle time_style,
                                       UDateFormatStyle date_style) const {
  const UChar kGmtTimezone[3] = {'G', 'M', 'T'};
  UErrorCode status = U_ZERO_ERROR;
  return udat_open(time_style, date_style, locale_.c_str(), kGmtTimezone,
                   std::size(kGmtTimezone), nullptr, -1, &status);
}

// We cannot use udat_*Symbols API to get standalone month names to use in
// calendar headers for Russian and potentially other languages. Instead,
// we have to format dates with patterns "LLLL" or "LLL" and set the
// display context to 'standalone'. See
// http://bugs.icu-project.org/trac/ticket/11552
UDateFormat* LocaleICU::OpenDateFormatForStandAloneMonthLabels(
    bool is_short) const {
  const UChar kMonthPattern[4] = {'L', 'L', 'L', 'L'};
  UErrorCode status = U_ZERO_ERROR;
  UDateFormat* formatter =
      udat_open(UDAT_PATTERN, UDAT_PATTERN, locale_.c_str(), nullptr, -1,
                kMonthPattern, is_short ? 3 : 4, &status);
  udat_setContext(formatter, UDISPCTX_CAPITALIZATION_FOR_STANDALONE, &status);
  DCHECK(U_SUCCESS(status));
  return formatter;
}

static String GetDateFormatPattern(const UDateFormat* date_format) {
  if (!date_format)
    return g_empty_string;

  UErrorCode status = U_ZERO_ERROR;
  int32_t length = udat_toPattern(date_format, true, nullptr, 0, &status);
  if (status != U_BUFFER_OVERFLOW_ERROR || !length)
    return g_empty_string;
  StringBuffer<UChar> buffer(length);
  status = U_ZERO_ERROR;
  udat_toPattern(date_format, true, buffer.Characters(), length, &status);
  if (U_FAILURE(status))
    return g_empty_string;
  return String::Adopt(buffer);
}

Vector<String> LocaleICU::CreateLabelVector(const UDateFormat* date_format,
                                            UDateFormatSymbolType type,
                                            int32_t start_index,
                                            int32_t size) {
  if (!date_format) {
    return {};
  }
  if (udat_countSymbols(date_format, type) != start_index + size) {
    return {};
  }

  Vector<String> labels;
  labels.reserve(size);
  bool is_stand_alone_month = (type == UDAT_STANDALONE_MONTHS) ||
                              (type == UDAT_STANDALONE_SHORT_MONTHS);
  for (int32_t i = 0; i < size; ++i) {
    UErrorCode status = U_ZERO_ERROR;
    int32_t length;
    static const UDate kEpoch = U_MILLIS_PER_DAY * 15u;  // 1970-01-15
    static const UDate kMonth = U_MILLIS_PER_DAY * 30u;  // 30 days in ms
    if (is_stand_alone_month) {
      length = udat_format(date_format, kEpoch + i * kMonth, nullptr, 0,
                           nullptr, &status);
    } else {
      length = udat_getSymbols(date_format, type, start_index + i, nullptr, 0,
                               &status);
    }
    if (status != U_BUFFER_OVERFLOW_ERROR) {
      return {};
    }
    StringBuffer<UChar> buffer(length);
    status = U_ZERO_ERROR;
    if (is_stand_alone_month) {
      udat_format(date_format, kEpoch + i * kMonth, buffer.Characters(), length,
                  nullptr, &status);
    } else {
      udat_getSymbols(date_format, type, start_index + i, buffer.Characters(),
                      length, &status);
    }
    if (U_FAILURE(status)) {
      return {};
    }
    labels.push_back(String::Adopt(buffer));
  }
  return labels;
}

const Vector<String>& LocaleICU::MonthLabels() {
  if (month_labels_.empty()) {
    if (InitializeShortDateFormat()) {
      month_labels_ =
          CreateLabelVector(short_date_format_, UDAT_MONTHS, UCAL_JANUARY, 12);
    }
    if (month_labels_.empty()) {
      month_labels_.reserve(std::size(kFallbackMonthNames));
      base::ranges::copy(kFallbackMonthNames,
                         std::back_inserter(month_labels_));
    }
  }
  return month_labels_;
}

const Vector<String>& LocaleICU::WeekDayShortLabels() {
  if (week_day_short_labels_.empty()) {
    if (InitializeShortDateFormat()) {
      week_day_short_labels_ = CreateLabelVector(
          short_date_format_, UDAT_NARROW_WEEKDAYS, UCAL_SUNDAY, 7);
    }
    if (week_day_short_labels_.empty()) {
      week_day_short_labels_.reserve(std::size(kFallbackWeekdayShortNames));
      base::ranges::copy(kFallbackWeekdayShortNames,
                         std::back_inserter(week_day_short_labels_));
    }
  }
  return week_day_short_labels_;
}

unsigned LocaleICU::FirstDayOfWeek() {
  if (!first_day_of_week_.has_value()) {
    first_day_of_week_ =
        InitializeShortDateFormat()
            ? ucal_getAttribute(udat_getCalendar(short_date_format_),
                                UCAL_FIRST_DAY_OF_WEEK) -
                  UCAL_SUNDAY
            : 0;
  }
  return first_day_of_week_.value();
}

bool LocaleICU::IsRTL() {
  UErrorCode status = U_ZERO_ERROR;
  return uloc_getCharacterOrientation(locale_.c_str(), &status) ==
         ULOC_LAYOUT_RTL;
}

void LocaleICU::InitializeDateTimeFormat() {
  if (did_create_time_format_)
    return;

  // We assume ICU medium time pattern and short time pattern are compatible
  // with LDML, because ICU specific pattern character "V" doesn't appear
  // in both medium and short time pattern.
  medium_time_format_ = OpenDateFormat(UDAT_MEDIUM, UDAT_NONE);
  time_format_with_seconds_ = GetDateFormatPattern(medium_time_format_);

  short_time_format_ = OpenDateFormat(UDAT_SHORT, UDAT_NONE);
  time_format_without_seconds_ = GetDateFormatPattern(short_time_format_);

  UDateFormat* date_time_format_with_seconds =
      OpenDateFormat(UDAT_MEDIUM, UDAT_SHORT);
  date_time_format_with_seconds_ =
      GetDateFormatPattern(date_time_format_with_seconds);
  udat_close(date_time_format_with_seconds);

  UDateFormat* date_time_format_without_seconds =
      OpenDateFormat(UDAT_SHORT, UDAT_SHORT);
  date_time_format_without_seconds_ =
      GetDateFormatPattern(date_time_format_without_seconds);
  udat_close(date_time_format_without_seconds);

  time_ampm_labels_ =
      CreateLabelVector(medium_time_format_, UDAT_AM_PMS, UCAL_AM, 2);
  if (time_ampm_labels_.empty()) {
    time_ampm_labels_ = {"AM", "PM"};
  }

  did_create_time_format_ = true;
}

String LocaleICU::DateFormat() {
  if (!date_format_.IsNull())
    return date_format_;
  if (!InitializeShortDateFormat())
    return "yyyy-MM-dd";
  date_format_ = GetDateFormatPattern(short_date_format_);
  return date_format_;
}

static String GetFormatForSkeleton(const char* locale, const String& skeleton) {
  String format = "yyyy-MM";
  UErrorCode status = U_ZERO_ERROR;
  UDateTimePatternGenerator* pattern_generator = udatpg_open(locale, &status);
  if (!pattern_generator)
    return format;
  status = U_ZERO_ERROR;
  Vector<UChar> skeleton_characters;
  skeleton.AppendTo(skeleton_characters);
  int32_t length =
      udatpg_getBestPattern(pattern_generator, skeleton_characters.data(),
                            skeleton_characters.size(), nullptr, 0, &status);
  if (status == U_BUFFER_OVERFLOW_ERROR && length) {
    StringBuffer<UChar> buffer(length);
    status = U_ZERO_ERROR;
    udatpg_getBestPattern(pattern_generator, skeleton_characters.data(),
                          skeleton_characters.size(), buffer.Characters(),
                          length, &status);
    if (U_SUCCESS(status))
      format = String::Adopt(buffer);
  }
  udatpg_close(pattern_generator);
  return format;
}

String LocaleICU::MonthFormat() {
  if (!month_format_.IsNull())
    return month_format_;
  // Gets a format for "MMMM" because Windows API always provides formats for
  // "MMMM" in some locales.
  month_format_ = GetFormatForSkeleton(locale_.c_str(), "yyyyMMMM");
  return month_format_;
}

String LocaleICU::ShortMonthFormat() {
  if (!short_month_format_.IsNull())
    return short_month_format_;
  short_month_format_ = GetFormatForSkeleton(locale_.c_str(), "yyyyMMM");
  return short_month_format_;
}

String LocaleICU::TimeFormat() {
  InitializeDateTimeFormat();
  return time_format_with_seconds_;
}

String LocaleICU::ShortTimeFormat() {
  InitializeDateTimeFormat();
  return time_format_without_seconds_;
}

String LocaleICU::DateTimeFormatWithSeconds() {
  InitializeDateTimeFormat();
  return date_time_format_with_seconds_;
}

String LocaleICU::DateTimeFormatWithoutSeconds() {
  InitializeDateTimeFormat();
  return date_time_format_without_seconds_;
}

const Vector<String>& LocaleICU::ShortMonthLabels() {
  if (short_month_labels_.empty()) {
    if (InitializeShortDateFormat()) {
      short_month_labels_ = CreateLabelVector(
          short_date_format_, UDAT_SHORT_MONTHS, UCAL_JANUARY, 12);
    }
    if (short_month_labels_.empty()) {
      short_month_labels_.reserve(std::size(kFallbackMonthShortNames));
      base::ranges::copy(kFallbackMonthShortNames,
                         std::back_inserter(short_month_labels_));
    }
  }
  return short_month_labels_;
}

const Vector<String>& LocaleICU::StandAloneMonthLabels() {
  if (stand_alone_month_labels_.empty()) {
    UDateFormat* month_formatter =
        OpenDateFormatForStandAloneMonthLabels(false);
    if (month_formatter) {
      stand_alone_month_labels_ = CreateLabelVector(
          month_formatter, UDAT_STANDALONE_MONTHS, UCAL_JANUARY, 12);
      udat_close(month_formatter);
    }
    if (stand_alone_month_labels_.empty()) {
      stand_alone_month_labels_ = MonthLabels();
    }
  }
  return stand_alone_month_labels_;
}

const Vector<String>& LocaleICU::ShortStandAloneMonthLabels() {
  if (short_stand_alone_month_labels_.empty()) {
    UDateFormat* month_formatter = OpenDateFormatForStandAloneMonthLabels(true);
    if (month_formatter) {
      short_stand_alone_month_labels_ = CreateLabelVector(
          month_formatter, UDAT_STANDALONE_SHORT_MONTHS, UCAL_JANUARY, 12);
      udat_close(month_formatter);
    }
    if (short_stand_alone_month_labels_.empty()) {
      short_stand_alone_month_labels_ = ShortMonthLabels();
    }
  }
  return short_stand_alone_month_labels_;
}

const Vector<String>& LocaleICU::TimeAMPMLabels() {
  InitializeDateTimeFormat();
  return time_ampm_labels_;
}

}  // namespace blink

"""

```