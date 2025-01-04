Response:
Let's break down the thought process for analyzing this `platform_locale.cc` file.

1. **Understand the Core Purpose:** The filename and the initial includes (`platform_locale.h`) immediately suggest this file deals with localization. Specifically, it handles how text and date/time are formatted and interpreted based on the user's locale.

2. **Identify Key Classes and Data Structures:**  A quick scan reveals the `Locale` class as the central entity. We also see `DateTimeStringBuilder`, `DateComponents`, and mentions of `DateTimeFormat`. These suggest the file handles more than just simple text localization.

3. **Analyze the `Locale` Class:**  This is the heart of the file. I'd go through its public methods and try to infer their functionality:
    * `DefaultLocale()` and `ResetDefaultLocale()`:  Management of a global default locale.
    * `QueryString()`:  Retrieving localized strings based on resource IDs. The overloads suggest handling different numbers of parameters.
    * `ValidationMessageTooLongText()`, `ValidationMessageTooShortText()`: Specific localization for form validation messages. This ties into HTML form elements.
    * `WeekFormatInLDML()`:  Dealing with week formatting, likely for `<input type="week">`. The "LDML" keyword hints at a standard format.
    * `SetLocaleData()`:  This is crucial. It's where the actual locale-specific data (decimal symbols, prefixes, suffixes) is set.
    * `ConvertToLocalizedNumber()`, `ConvertFromLocalizedNumber()`:  Conversion between standard number representations and locale-specific ones.
    * `StripInvalidNumberCharacters()`:  Sanitizing input strings related to numbers.
    * `LocalizedDecimalSeparator()`: Getting the locale's decimal separator.
    * `UsesSingleCharNumberFiltering()`: An optimization related to number parsing.
    * `IsSignPrefix()`, `HasTwoSignChars()`, `HasSignNotAfterE()`: Checks for valid number signs.
    * `IsDigit()`, `IsDecimalSeparator()`, `HasDecimalSeparator()`:  Checks for characters related to numbers.
    * `FormatDateTime()`: The big one for date/time formatting, taking a `DateComponents` object and a format type.

4. **Analyze the `DateTimeStringBuilder` Class:** This appears to be a helper class for `FormatDateTime`. It takes a `Locale` and `DateComponents`, and uses a `DateTimeFormat` parser to build the localized date/time string. The `VisitField()` and `VisitLiteral()` methods suggest it's handling tokens from the parsed format string.

5. **Look for Connections to Web Technologies (JavaScript, HTML, CSS):**  As I analyze the methods, I'd ask:
    * **HTML:** The validation message functions clearly relate to HTML forms and input validation. The `WeekFormatInLDML()` points to `<input type="week">`.
    * **JavaScript:**  While this C++ code doesn't *directly* interact with JavaScript, it provides the underlying functionality that JavaScript in the browser would use. For example, JavaScript's `toLocaleDateString()`, `toLocaleTimeString()`, and number formatting methods rely on the browser's underlying locale support, which this code contributes to.
    * **CSS:**  Less direct, but consider things like the `::placeholder` pseudo-element, which might need localized text. The overall rendering of text (like right-to-left languages) is also influenced by locale, though this file doesn't directly handle CSS styling.

6. **Identify Potential Logic and Assumptions:**  Examine the implementation details, such as:
    * The handling of different date/time format patterns in `DateTimeStringBuilder::VisitField()`.
    * The logic in `ConvertToLocalizedNumber()` and `ConvertFromLocalizedNumber()` for handling positive/negative prefixes/suffixes and decimal separators.
    * The `DetectSignAndGetDigitRange()` function's logic for finding the numerical part of a localized number string.

7. **Consider User/Programming Errors:** Think about how incorrect usage of related APIs or misunderstandings of localization principles could lead to problems. Examples include:
    * Incorrectly setting or retrieving locale data.
    * Assuming a specific number format without considering the locale.
    * Not handling right-to-left languages properly.

8. **Structure the Explanation:**  Organize the findings logically:
    * Start with the file's overall purpose.
    * Detail the functionality of the key classes, particularly `Locale`.
    * Explain the relationships to JavaScript, HTML, and CSS with concrete examples.
    * Provide examples of logic and assumptions.
    * Illustrate common usage errors.

9. **Refine and Review:** Read through the explanation to ensure clarity, accuracy, and completeness. Check for any jargon that needs clarification.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just about translating strings."  **Correction:**  Realized it also handles number and date/time formatting, which are locale-specific.
* **Considering JavaScript:** Initially focused on direct calls. **Correction:** Shifted to understanding how this C++ code provides the *foundation* for JavaScript localization APIs.
* **Thinking about errors:**  Started with basic programming errors. **Correction:**  Expanded to include errors related to misunderstanding localization concepts.

By following this structured approach, I can systematically analyze the source code and generate a comprehensive explanation of its functionality and relevance.
这个文件 `blink/renderer/platform/text/platform_locale.cc` 是 Chromium Blink 渲染引擎中负责处理本地化（localization）相关功能的核心组件。它提供了一种抽象层，使得 Blink 的其他部分能够以与特定语言和文化习惯相适应的方式处理文本、数字、日期和时间。

以下是 `platform_locale.cc` 的主要功能：

**1. 提供本地化信息的访问接口 (Locale Class):**

* **默认 Locale 管理:**  `Locale::DefaultLocale()` 返回当前默认的 `Locale` 对象，并负责初始化。`Locale::ResetDefaultLocale()` 用于重置默认 Locale。
* **查询本地化字符串:** `QueryString()` 方法族允许根据资源 ID 获取本地化的字符串。这些字符串通常存储在资源文件中，并根据当前的 locale 进行选择。
* **数字格式化:**
    * `ConvertToLocalizedNumber()`: 将标准数字字符串转换为当前 locale 特定的格式，例如使用不同的千位分隔符和小数点分隔符。
    * `ConvertFromLocalizedNumber()`: 将 locale 特定的数字字符串转换为标准数字字符串。
    * `StripInvalidNumberCharacters()`:  从字符串中移除 locale 不接受的数字字符。
    * `LocalizedDecimalSeparator()`: 返回当前 locale 使用的小数点分隔符。
    * `UsesSingleCharNumberFiltering()`:  指示当前 locale 是否可以使用单字符过滤来优化数字输入。
* **日期和时间格式化:**
    * `FormatDateTime()`:  根据 `DateComponents` 对象和指定的格式类型（短格式或长格式）格式化日期和时间。
    * 提供访问特定格式模式的方法，如 `ShortTimeFormat()`, `TimeFormat()`, `DateFormat()`, `ShortMonthFormat()`, `MonthFormat()`, `DateTimeFormatWithoutSeconds()`, `DateTimeFormatWithSeconds()`，这些方法返回当前 locale 的日期和时间格式模式。
    * `WeekFormatInLDML()`:  获取当前 locale 的 week 格式的 LDML 模式。
* **表单验证消息本地化:** 提供 `ValidationMessageTooLongText()` 和 `ValidationMessageTooShortText()` 方法，用于生成本地化的表单验证错误消息。
* **数字符号设置:** `SetLocaleData()` 允许设置特定 locale 的数字符号（例如小数点、千位分隔符、正负号前缀/后缀）。
* **数字解析辅助函数:** 提供 `DetectSignAndGetDigitRange()`, `MatchedDecimalSymbolIndex()`, `IsSignPrefix()`, `HasTwoSignChars()`, `HasSignNotAfterE()`, `IsDigit()`, `IsDecimalSeparator()`, `HasDecimalSeparator()` 等辅助函数，用于解析和验证本地化数字字符串。

**2. 日期和时间格式化助手 (DateTimeStringBuilder Class):**

* `DateTimeStringBuilder` 是一个辅助类，用于根据 `Locale` 和 `DateComponents` 对象以及格式字符串构建本地化的日期和时间字符串。
* 它实现了 `DateTimeFormat::TokenHandler` 接口，用于处理日期时间格式字符串中的不同标记（例如年、月、日、小时、分钟）。
* `Build()` 方法解析格式字符串并驱动字符串构建过程。
* `ToString()` 方法返回最终的本地化日期时间字符串。

**与 JavaScript, HTML, CSS 的关系：**

`platform_locale.cc` 提供的功能是 Blink 引擎处理与用户语言环境相关的 Web 技术的基础。

* **JavaScript:**
    * **`Intl` API:** JavaScript 的 `Intl` API（例如 `Intl.DateTimeFormat`, `Intl.NumberFormat`）在底层会使用 Blink 提供的本地化能力。`platform_locale.cc` 中的代码实现了这些 API 所需的基础功能。
    * **例如：** 当你在 JavaScript 中使用 `new Intl.NumberFormat().format(1234.56)` 时，Blink 会根据用户的 locale 设置，调用 `platform_locale.cc` 中的相关函数（例如 `ConvertToLocalizedNumber`）来格式化数字，可能得到 "1,234.56" (英语) 或 "1.234,56" (德语) 这样的结果。
    * **例如：** `new Intl.DateTimeFormat().format(new Date())` 会使用 `platform_locale.cc` 中的 `FormatDateTime` 等函数来生成本地化的日期和时间字符串。

* **HTML:**
    * **表单元素:**  `<input type="number">`, `<input type="date">`, `<input type="time">`, `<input type="datetime-local">`, `<input type="week">`, `<input type="month">` 等表单元素在显示和解析用户输入时会利用 `platform_locale.cc` 的功能。
    * **例如：** 当用户在一个 `type="number"` 的输入框中输入数字时，浏览器会使用 `platform_locale.cc` 中的函数来验证输入的字符是否符合当前 locale 的数字格式。
    * **例如：** `<input type="date">`  会使用 `platform_locale.cc` 中的日期格式信息来显示日期选择器的格式，以及解析用户输入的日期字符串。`WeekFormatInLDML()` 就直接关联到 `<input type="week">` 元素的处理。
    * **表单验证:** `ValidationMessageTooLongText()` 和 `ValidationMessageTooShortText()`  生成的本地化消息会用于 `<input>` 元素的 `setCustomValidity()` 方法等场景，向用户展示易于理解的错误信息。

* **CSS:**
    * **虽然 `platform_locale.cc` 不直接处理 CSS 样式，但它影响着文本的渲染方式。** 例如，对于从右到左 (RTL) 的语言，Blink 会使用 locale 信息来决定文本的排列方向。
    * **CSS 中的一些属性，例如 `direction: rtl;`，会与 locale 信息结合使用，确保内容按照正确的方向显示。**

**逻辑推理示例：**

**假设输入:**

* `Locale` 对象为英文 (US) locale。
* 调用 `ConvertToLocalizedNumber("1234.56")`。

**输出:**

* `"1,234.56"`

**推理过程:**  对于英文 (US) locale，千位分隔符是逗号 (,)，小数点分隔符是句点 (.)。 `ConvertToLocalizedNumber` 函数会根据这些 locale 设置来格式化数字字符串。

**用户或编程常见的使用错误示例：**

1. **假设开发者直接硬编码数字格式字符串：**
   ```cpp
   // 错误的做法
   String formatted_number = String::Format("%d.%02d", integer_part, fractional_part);
   ```
   这样做会忽略用户的 locale 设置，在某些 locale 中可能会显示错误的数字格式（例如，使用逗号作为小数点）。正确的做法是使用 `Locale` 对象的 `ConvertToLocalizedNumber`。

2. **假设开发者在 JavaScript 中手动拼接本地化日期字符串：**
   ```javascript
   // 错误的做法
   const date = new Date();
   const formattedDate = date.getFullYear() + '年' + (date.getMonth() + 1) + '月' + date.getDate() + '日';
   ```
   这种方式没有考虑到不同 locale 的日期格式顺序和分隔符。应该使用 `Intl.DateTimeFormat` 来根据用户的 locale 正确格式化日期。

3. **未能正确处理 RTL 语言：**  开发者可能在布局时没有考虑到 RTL 语言的文本方向，导致界面在 RTL 语言环境下显示错乱。Blink 的 locale 信息会影响文本方向，但开发者需要在 CSS 中使用逻辑属性（例如 `margin-inline-start`）来更好地支持 RTL 布局。

4. **错误地假设所有 locale 都使用相同的数字符号：**  开发者可能会错误地假设所有 locale 都使用句点作为小数点。例如，在处理用户输入的数字时，如果直接使用 `parseFloat` 解析一个包含逗号作为小数点的字符串，可能会得到错误的结果。应该使用 `Locale` 对象的 `ConvertFromLocalizedNumber` 来进行转换。

总而言之，`platform_locale.cc` 是 Blink 引擎中实现本地化功能的基础设施，它使得 Web 内容能够根据用户的语言和文化习惯进行呈现和交互，对于构建国际化的 Web 应用至关重要。开发者应该利用 Blink 提供的本地化 API 和工具，而不是尝试手动处理本地化逻辑，以避免常见的错误并确保良好的用户体验。

Prompt: 
```
这是目录为blink/renderer/platform/text/platform_locale.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/platform/text/platform_locale.h"

#include <memory>

#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/platform/text/date_time_format.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"

namespace blink {

namespace {
Locale* g_default_locale;
}

class DateTimeStringBuilder : private DateTimeFormat::TokenHandler {
 public:
  // The argument objects must be alive until this object dies.
  DateTimeStringBuilder(Locale&, const DateComponents&);
  DateTimeStringBuilder(const DateTimeStringBuilder&) = delete;
  DateTimeStringBuilder& operator=(const DateTimeStringBuilder&) = delete;

  bool Build(const String&);
  String ToString();

 private:
  // DateTimeFormat::TokenHandler functions.
  void VisitField(DateTimeFormat::FieldType, int) final;
  void VisitLiteral(const String&) final;

  String ZeroPadString(const String&, size_t width);
  void AppendNumber(int number, size_t width);

  StringBuilder builder_;
  Locale& localizer_;
  const DateComponents& date_;
};

DateTimeStringBuilder::DateTimeStringBuilder(Locale& localizer,
                                             const DateComponents& date)
    : localizer_(localizer), date_(date) {}

bool DateTimeStringBuilder::Build(const String& format_string) {
  builder_.ReserveCapacity(format_string.length());
  return DateTimeFormat::Parse(format_string, *this);
}

String DateTimeStringBuilder::ZeroPadString(const String& string,
                                            size_t pad_width) {
  if (string.length() >= pad_width)
    return string;
  wtf_size_t width = static_cast<wtf_size_t>(pad_width);
  StringBuilder zero_padded_string_builder;
  zero_padded_string_builder.ReserveCapacity(width);
  for (wtf_size_t i = string.length(); i < width; ++i)
    zero_padded_string_builder.Append('0');
  zero_padded_string_builder.Append(string);
  return zero_padded_string_builder.ToString();
}

void DateTimeStringBuilder::AppendNumber(int number, size_t width) {
  String zero_padded_number_string =
      ZeroPadString(String::Number(number), width);
  builder_.Append(
      localizer_.ConvertToLocalizedNumber(zero_padded_number_string));
}

void DateTimeStringBuilder::VisitField(DateTimeFormat::FieldType field_type,
                                       int number_of_pattern_characters) {
  switch (field_type) {
    case DateTimeFormat::kFieldTypeYear:
      // Always use padding width of 4 so it matches DateTimeEditElement.
      AppendNumber(date_.FullYear(), 4);
      return;
    case DateTimeFormat::kFieldTypeMonth:
      if (number_of_pattern_characters == 3) {
        builder_.Append(localizer_.ShortMonthLabels()[date_.Month()]);
      } else if (number_of_pattern_characters == 4) {
        builder_.Append(localizer_.MonthLabels()[date_.Month()]);
      } else {
        // Always use padding width of 2 so it matches DateTimeEditElement.
        AppendNumber(date_.Month() + 1, 2);
      }
      return;
    case DateTimeFormat::kFieldTypeMonthStandAlone:
      if (number_of_pattern_characters == 3) {
        builder_.Append(localizer_.ShortStandAloneMonthLabels()[date_.Month()]);
      } else if (number_of_pattern_characters == 4) {
        builder_.Append(localizer_.StandAloneMonthLabels()[date_.Month()]);
      } else {
        // Always use padding width of 2 so it matches DateTimeEditElement.
        AppendNumber(date_.Month() + 1, 2);
      }
      return;
    case DateTimeFormat::kFieldTypeDayOfMonth:
      // Always use padding width of 2 so it matches DateTimeEditElement.
      AppendNumber(date_.MonthDay(), 2);
      return;
    case DateTimeFormat::kFieldTypeWeekOfYear:
      // Always use padding width of 2 so it matches DateTimeEditElement.
      AppendNumber(date_.Week(), 2);
      return;
    case DateTimeFormat::kFieldTypePeriod:
      builder_.Append(
          localizer_.TimeAMPMLabels()[(date_.Hour() >= 12 ? 1 : 0)]);
      return;
    case DateTimeFormat::kFieldTypeHour12: {
      int hour12 = date_.Hour() % 12;
      if (!hour12)
        hour12 = 12;
      AppendNumber(hour12, number_of_pattern_characters);
      return;
    }
    case DateTimeFormat::kFieldTypeHour23:
      AppendNumber(date_.Hour(), number_of_pattern_characters);
      return;
    case DateTimeFormat::kFieldTypeHour11:
      AppendNumber(date_.Hour() % 12, number_of_pattern_characters);
      return;
    case DateTimeFormat::kFieldTypeHour24: {
      int hour24 = date_.Hour();
      if (!hour24)
        hour24 = 24;
      AppendNumber(hour24, number_of_pattern_characters);
      return;
    }
    case DateTimeFormat::kFieldTypeMinute:
      AppendNumber(date_.Minute(), number_of_pattern_characters);
      return;
    case DateTimeFormat::kFieldTypeSecond:
      if (!date_.Millisecond()) {
        AppendNumber(date_.Second(), number_of_pattern_characters);
      } else {
        double second = date_.Second() + date_.Millisecond() / 1000.0;
        String zero_padded_second_string = ZeroPadString(
            String::Format("%.03f", second), number_of_pattern_characters + 4);
        builder_.Append(
            localizer_.ConvertToLocalizedNumber(zero_padded_second_string));
      }
      return;
    default:
      return;
  }
}

void DateTimeStringBuilder::VisitLiteral(const String& text) {
  DCHECK(text.length());
  builder_.Append(text);
}

String DateTimeStringBuilder::ToString() {
  return builder_.ToString();
}

Locale& Locale::DefaultLocale() {
  DCHECK(IsMainThread());
  if (!g_default_locale)
    g_default_locale = Locale::Create(DefaultLanguage()).release();
  return *g_default_locale;
}

void Locale::ResetDefaultLocale() {
  // This is safe because no one owns a Locale object returned by
  // DefaultLocale().
  delete g_default_locale;
  g_default_locale = nullptr;
}

Locale::~Locale() = default;

String Locale::QueryString(int resource_id) {
  // FIXME: Returns a string localized for this locale.
  return Platform::Current()->QueryLocalizedString(resource_id);
}

String Locale::QueryString(int resource_id, const String& parameter) {
  // FIXME: Returns a string localized for this locale.
  return Platform::Current()->QueryLocalizedString(resource_id, parameter);
}

String Locale::QueryString(int resource_id,
                           const String& parameter1,
                           const String& parameter2) {
  // FIXME: Returns a string localized for this locale.
  return Platform::Current()->QueryLocalizedString(resource_id, parameter1,
                                                   parameter2);
}

String Locale::ValidationMessageTooLongText(unsigned value_length,
                                            int max_length) {
  return QueryString(IDS_FORM_VALIDATION_TOO_LONG,
                     ConvertToLocalizedNumber(String::Number(value_length)),
                     ConvertToLocalizedNumber(String::Number(max_length)));
}

String Locale::ValidationMessageTooShortText(unsigned value_length,
                                             int min_length) {
  if (value_length == 1) {
    return QueryString(IDS_FORM_VALIDATION_TOO_SHORT,
                       ConvertToLocalizedNumber(String::Number(value_length)),
                       ConvertToLocalizedNumber(String::Number(min_length)));
  }

  return QueryString(IDS_FORM_VALIDATION_TOO_SHORT_PLURAL,
                     ConvertToLocalizedNumber(String::Number(value_length)),
                     ConvertToLocalizedNumber(String::Number(min_length)));
}

String Locale::WeekFormatInLDML() {
  String templ = QueryString(IDS_FORM_INPUT_WEEK_TEMPLATE);
  // Converts a string like "Week $2, $1" to an LDML date format pattern like
  // "'Week 'ww', 'yyyy".
  StringBuilder builder;
  unsigned literal_start = 0;
  unsigned length = templ.length();
  for (unsigned i = 0; i + 1 < length; ++i) {
    if (templ[i] == '$' && (templ[i + 1] == '1' || templ[i + 1] == '2')) {
      if (literal_start < i)
        DateTimeFormat::QuoteAndappend(
            templ.Substring(literal_start, i - literal_start), builder);
      builder.Append(templ[++i] == '1' ? "yyyy" : "ww");
      literal_start = i + 1;
    }
  }
  if (literal_start < length)
    DateTimeFormat::QuoteAndappend(
        templ.Substring(literal_start, length - literal_start), builder);
  return builder.ToString();
}

void Locale::SetLocaleData(const Vector<String, kDecimalSymbolsSize>& symbols,
                           const String& positive_prefix,
                           const String& positive_suffix,
                           const String& negative_prefix,
                           const String& negative_suffix) {
  for (wtf_size_t i = 0; i < symbols.size(); ++i) {
    DCHECK(!symbols[i].empty());
    decimal_symbols_[i] = symbols[i];
  }
  positive_prefix_ = positive_prefix;
  positive_suffix_ = positive_suffix;
  negative_prefix_ = negative_prefix;
  negative_suffix_ = negative_suffix;
  DCHECK(!positive_prefix_.empty() || !positive_suffix_.empty() ||
         !negative_prefix_.empty() || !negative_suffix_.empty());
  has_locale_data_ = true;

  StringBuilder builder;
  for (size_t i = 0; i < kDecimalSymbolsSize; ++i) {
    // We don't accept group separators.
    if (i != kGroupSeparatorIndex)
      builder.Append(decimal_symbols_[i]);
  }
  builder.Append(positive_prefix_);
  builder.Append(positive_suffix_);
  builder.Append(negative_prefix_);
  builder.Append(negative_suffix_);
  acceptable_number_characters_ = builder.ToString();

  // Check if we can use single character filtering. We can if all symbols are
  // 1 character and there's no suffix. Since plus sign is optional, allow
  // zero length positive prefix.
  uses_single_char_number_filtering_ = false;
  if (decimal_symbols_[kDecimalSeparatorIndex].length() == 1 &&
      positive_prefix_.length() <= 1 && negative_prefix_.length() == 1 &&
      positive_suffix_.length() == 0 && negative_suffix_.length() == 0 &&
      !IsRTL()) {
    uses_single_char_number_filtering_ = true;
    for (wtf_size_t i = 0; i <= 9; ++i) {
      if (decimal_symbols_[i].length() != 1) {
        uses_single_char_number_filtering_ = false;
        break;
      }
    }
  }
}

String Locale::ConvertToLocalizedNumber(const String& input) {
  InitializeLocaleData();
  if (!has_locale_data_ || input.empty())
    return input;

  StringBuilder builder;
  builder.ReserveCapacity(input.length());

  const bool is_negative = input[0] == '-';
  builder.Append(is_negative ? negative_prefix_ : positive_prefix_);

  for (unsigned i = is_negative ? 1 : 0; i < input.length(); ++i) {
    const UChar c = input[i];
    CHECK(c == '.' || (c >= '0' && c <= '9'));
    builder.Append(
        decimal_symbols_[c == '.' ? kDecimalSeparatorIndex : (c - '0')]);
  }

  builder.Append(is_negative ? negative_suffix_ : positive_suffix_);

  return builder.ToString();
}

static bool Matches(const String& text, unsigned position, const String& part) {
  if (part.empty())
    return true;
  if (position + part.length() > text.length())
    return false;
  for (unsigned i = 0; i < part.length(); ++i) {
    if (text[position + i] != part[i])
      return false;
  }
  return true;
}

bool Locale::DetectSignAndGetDigitRange(const String& input,
                                        bool& is_negative,
                                        unsigned& start_index,
                                        unsigned& end_index) {
  DCHECK_EQ(input.Find(IsASCIISpace), WTF::kNotFound);
  start_index = 0;
  end_index = input.length();
  const auto adjust_for_affixes = [&](const String& prefix,
                                      const String& suffix) {
    if (!input.StartsWith(prefix) || !input.EndsWith(suffix)) {
      return false;
    }
    start_index = prefix.length();
    end_index -= suffix.length();
    return true;
  };

  const bool negative_empty =
      negative_prefix_.empty() && negative_suffix_.empty();
  if (!negative_empty &&
      // For some locales the negative prefix and/or suffix are preceded or
      // followed by whitespace. Exclude that for the purposes of this search
      // since the input string has already been stripped of whitespace.
      adjust_for_affixes(negative_prefix_.StripWhiteSpace(),
                         negative_suffix_.StripWhiteSpace())) {
    is_negative = true;
    return true;
  }

  // Note: Positive prefix and suffix may be empty, in which case this will
  // always succeed.
  if (adjust_for_affixes(positive_prefix_, positive_suffix_)) {
    is_negative = false;
    return true;
  }

  is_negative = negative_empty;
  return is_negative;
}

unsigned Locale::MatchedDecimalSymbolIndex(const String& input,
                                           unsigned& position) {
  for (unsigned symbol_index = 0; symbol_index < kDecimalSymbolsSize;
       ++symbol_index) {
    if (decimal_symbols_[symbol_index].length() &&
        Matches(input, position, decimal_symbols_[symbol_index])) {
      position += decimal_symbols_[symbol_index].length();
      return symbol_index;
    }
  }
  return kDecimalSymbolsSize;
}

String Locale::ConvertFromLocalizedNumber(const String& localized) {
  InitializeLocaleData();
  String input = localized.RemoveCharacters(IsASCIISpace);
  if (!has_locale_data_ || input.empty())
    return input;

  bool is_negative;
  unsigned start_index;
  unsigned end_index;
  if (!DetectSignAndGetDigitRange(input, is_negative, start_index, end_index))
    return input;

  // Ignore leading '+', but will reject '+'-only string later.
  if (!is_negative && end_index - start_index >= 2 && input[start_index] == '+')
    ++start_index;

  StringBuilder builder;
  builder.ReserveCapacity(input.length());
  if (is_negative)
    builder.Append('-');
  unsigned num_decimal_separators = 0;
  for (unsigned i = start_index; i < end_index;) {
    unsigned symbol_index = MatchedDecimalSymbolIndex(input, i);
    if (symbol_index >= kDecimalSymbolsSize)
      return input;
    if (symbol_index == kDecimalSeparatorIndex) {
      num_decimal_separators++;
      builder.Append('.');
    } else if (symbol_index == kGroupSeparatorIndex) {
      return input;
    } else {
      builder.Append(static_cast<UChar>('0' + symbol_index));
    }
  }
  String converted = builder.ToString();
  // Ignore trailing '.', but will reject '.'-only string later.
  if (converted.length() >= 2 && converted[converted.length() - 1] == '.') {
    // Leave it if there are two decimal separators since that's invalid.
    if (num_decimal_separators < 2)
      converted = converted.Left(converted.length() - 1);
  }
  return converted;
}

String Locale::StripInvalidNumberCharacters(const String& input,
                                            const String& standard_chars) {
  InitializeLocaleData();
  StringBuilder builder;
  builder.ReserveCapacity(input.length());
  for (unsigned i = 0; i < input.length(); ++i) {
    UChar ch = input[i];
    if (standard_chars.find(ch) != kNotFound)
      builder.Append(ch);
    else if (acceptable_number_characters_.find(ch) != kNotFound)
      builder.Append(ch);
  }
  return builder.ToString();
}

String Locale::LocalizedDecimalSeparator() {
  InitializeLocaleData();
  return decimal_symbols_[kDecimalSeparatorIndex];
}

bool Locale::UsesSingleCharNumberFiltering() {
  return uses_single_char_number_filtering_;
}

static bool IsE(UChar ch) {
  return ch == 'e' || ch == 'E';
}

bool Locale::IsSignPrefix(UChar ch) {
  if (ch == '+' || ch == '-')
    return true;
  if (negative_prefix_.length() == 1 && ch == negative_prefix_[0])
    return true;
  if (positive_prefix_.length() == 1 && ch == positive_prefix_[0])
    return true;

  return false;
}

bool Locale::HasTwoSignChars(const String& str) {
  // Unretained is safe because callback executes synchronously in Find().
  auto pos = str.Find(
      WTF::BindRepeating(&Locale::IsSignPrefix, WTF::Unretained(this)));
  if (pos == kNotFound)
    return false;
  // Unretained is safe because callback executes synchronously in Find().
  return str.Find(
             WTF::BindRepeating(&Locale::IsSignPrefix, WTF::Unretained(this)),
             pos + 1) != kNotFound;
}

bool Locale::HasSignNotAfterE(const String& str) {
  // Unretained is safe because callback executes synchronously in Find().
  auto pos = str.Find(
      WTF::BindRepeating(&Locale::IsSignPrefix, WTF::Unretained(this)));
  if (pos == kNotFound)
    return false;
  return pos == 0 || !IsE(str[pos - 1]);
}

bool Locale::IsDigit(UChar ch) {
  // Always allow 0 - 9.
  if (ch >= '0' && ch <= '9')
    return true;
  // Check each digit otherwise
  String ch_str(base::span_from_ref(ch));
  return (ch_str == decimal_symbols_[0] || ch_str == decimal_symbols_[1] ||
          ch_str == decimal_symbols_[2] || ch_str == decimal_symbols_[3] ||
          ch_str == decimal_symbols_[4] || ch_str == decimal_symbols_[5] ||
          ch_str == decimal_symbols_[6] || ch_str == decimal_symbols_[7] ||
          ch_str == decimal_symbols_[8] || ch_str == decimal_symbols_[9]);
}

// Is the character a decimal separator?
bool Locale::IsDecimalSeparator(UChar ch) {
  if (ch == '.')
    return true;
  return LocalizedDecimalSeparator() == String(base::span_from_ref(ch));
}

// Is there a decimal separator in a string?
bool Locale::HasDecimalSeparator(const String& str) {
  // Unretained is safe because callback executes synchronously in Find().
  return str.Find(WTF::BindRepeating(&Locale::IsDecimalSeparator,
                                     WTF::Unretained(this))) != kNotFound;
}

String Locale::FormatDateTime(const DateComponents& date,
                              FormatType format_type) {
  if (date.GetType() == DateComponents::kInvalid)
    return String();

  DateTimeStringBuilder builder(*this, date);
  switch (date.GetType()) {
    case DateComponents::kTime:
      builder.Build(format_type == kFormatTypeShort ? ShortTimeFormat()
                                                    : TimeFormat());
      break;
    case DateComponents::kDate:
      builder.Build(DateFormat());
      break;
    case DateComponents::kMonth:
      builder.Build(format_type == kFormatTypeShort ? ShortMonthFormat()
                                                    : MonthFormat());
      break;
    case DateComponents::kWeek:
      builder.Build(WeekFormatInLDML());
      break;
    case DateComponents::kDateTimeLocal:
      builder.Build(format_type == kFormatTypeShort
                        ? DateTimeFormatWithoutSeconds()
                        : DateTimeFormatWithSeconds());
      break;
    case DateComponents::kInvalid:
      NOTREACHED();
  }
  return builder.ToString();
}

}  // namespace blink

"""

```