Response:
Let's break down the request and the thought process to analyze the `locale_win.cc` file.

**1. Understanding the Core Request:**

The request asks for a breakdown of the file's functionality, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning (input/output), and common user/programming errors related to it.

**2. Initial Analysis of the File Path and Content:**

* **File Path:** `blink/renderer/platform/text/locale_win.cc` strongly suggests this file deals with localization (locale) specifically on the Windows platform within the Blink rendering engine. The `text` subdirectory further hints at its focus on text-related aspects of localization.
* **Copyright and License:** Standard boilerplate, indicating Google's ownership and the BSD license. Not directly functional but important for legal context.
* **Includes:**  The included headers provide crucial clues:
    * `locale_win.h`:  Its own header file, suggesting it defines a class or related functions.
    * Standard C++ headers (`iterator`, `limits`, `memory`).
    * `base/`: Likely utility functions from the Chromium base library (memory management, string manipulation).
    * `platform/language.h`:  Deals with language identification.
    * `platform/text/date_components.h`, `date_time_format.h`: Focus on date and time formatting.
    * `platform/web_test_support.h`:  Used for web testing, implying some conditional behavior.
    * `wtf/`:  Web Template Framework, Blink's internal utility library (strings, data structures).
    * `ui/base/ui_base_features.h`:  Potentially related to UI-specific localization settings.

**3. Identifying Key Functionality - Step-by-Step Reading and Interpretation:**

I would now go through the code section by section, trying to understand the purpose of each function and data member.

* **`ExtractLanguageCode`:**  Simple string manipulation to get the language part of a locale string (e.g., "en-US" -> "en").
* **`LCIDFromLocaleInternal` and `LCIDFromLocale`:** These are crucial. They deal with converting locale strings (like "en-US") into Windows Locale Identifiers (LCIDs), which are numerical representations used by the Windows API. The logic involves handling default locales and fallback mechanisms. The `LOCALE_USER_DEFAULT` and `LOCALE_NAME_MAX_LENGTH` constants are Windows-specific.
* **`Locale::Create`:** This static method seems to be the entry point for creating `Locale` objects. It calls `LCIDFromLocale` and then `LocaleWin::Create`. The `WebTestSupport::IsRunningWebTest()` check indicates a special handling for testing environments.
* **`LocaleWin::LocaleWin` (constructor):** Initializes the `LocaleWin` object with the LCID and a flag for default locale settings. It retrieves the first day of the week from the Windows locale settings.
* **`LocaleWin::Create`:**  A simple factory method using `base::WrapUnique` for memory management.
* **`LocaleWin::~LocaleWin` (destructor):** Empty, indicating no specific cleanup is needed.
* **`LocaleWin::GetLocaleInfoString` and `GetLocaleInfo(LCTYPE type, DWORD& result)`:** These are wrappers around the Windows API `GetLocaleInfo`, used to retrieve various locale-specific information (names of months, days, date/time formats, etc.). The `LOCALE_NOUSEROVERRIDE` flag is important for honoring or ignoring user-defined settings.
* **Date/Time Formatting (`CountContinuousLetters`, `CommitLiteralToken`, `ConvertWindowsDateTimeFormat`):** This section is dedicated to converting Windows date/time format strings into the LDML format used by JavaScript's `Intl` API. This is a significant part of the file's purpose. The comments and links to MSDN and LDML documentation are helpful here.
* **Retrieving Locale-Specific Labels (`MonthLabels`, `WeekDayShortLabels`, `ShortMonthLabels`, `StandAloneMonthLabels`, `ShortStandAloneMonthLabels`, `TimeAMPMLabels`):** These functions use `GetLocaleInfoString` with specific `LCTYPE` constants to fetch the localized names of months, days, and AM/PM indicators. Fallback mechanisms are in place if the Windows API doesn't provide the requested information.
* **`FirstDayOfWeek`, `IsRTL`:**  Get the first day of the week and determine if the locale is right-to-left.
* **Date/Time Format Accessors (`DateFormat`, `MonthFormat`, `ShortMonthFormat`, `TimeFormat`, `ShortTimeFormat`, `DateTimeFormatWithSeconds`, `DateTimeFormatWithoutSeconds`):** These functions retrieve and potentially convert the date and time format strings using `GetLocaleInfoString` and `ConvertWindowsDateTimeFormat`. They often cache the results to avoid repeated calls to the Windows API.
* **`InitializeLocaleData`:** This is responsible for initializing number formatting data (decimal separator, group separator, negative sign format). It considers digit substitution settings.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now, the crucial part is to link the C++ code to the user-facing web technologies:

* **JavaScript `Intl` API:** The converted date and time formats are directly used by JavaScript's `Intl.DateTimeFormat` object. The fetched month names, day names, and AM/PM labels are also used by `Intl`.
* **HTML `<input type="date">`, `<input type="time">`, `<input type="datetime-local">`:** These HTML elements rely on the browser's underlying locale settings for displaying and parsing date and time values. The data fetched and processed by `locale_win.cc` directly influences how these elements behave.
* **CSS `::marker` pseudo-element:** While less direct, the `IsRTL()` function could indirectly influence the default directionality of list markers. More broadly, the overall locale can impact default font selection and text rendering.

**5. Logical Reasoning (Input/Output Examples):**

For functions like `LCIDFromLocale` and `ConvertWindowsDateTimeFormat`, providing example inputs and their expected outputs clarifies their behavior.

**6. Identifying Potential User/Programming Errors:**

This involves thinking about how developers or the system might misconfigure things or make incorrect assumptions.

* **Incorrect Locale Strings:** Providing an invalid or unsupported locale string can lead to unexpected behavior or fallback to default settings.
* **Assuming Consistent Formatting:** Developers might assume date/time formats are consistent across all locales, which is incorrect.
* **Ignoring User Overrides:** The `defaults_for_locale` flag highlights the potential difference between system defaults and user-customized settings.

**7. Structuring the Answer:**

Finally, organize the gathered information into a clear and structured answer, covering each aspect of the request: functionality, relation to web technologies, logical reasoning examples, and common errors. Use clear headings and bullet points for readability. Emphasize the key roles of the file.
这个文件 `blink/renderer/platform/text/locale_win.cc` 是 Chromium Blink 引擎中处理与 Windows 操作系统相关的本地化 (localization) 功能的源代码文件。它主要负责提供在 Windows 平台上获取和格式化文本所需的特定于语言环境 (locale) 的信息。

以下是它的主要功能：

**1. 获取 Windows 本地化信息：**

* **从 locale 字符串获取 LCID (Locale Identifier)：**  通过 `LCIDFromLocale` 函数将诸如 "en-US" 或 "zh-CN" 这样的 locale 字符串转换为 Windows 系统使用的 LCID。LCID 是一个唯一的数字标识符，代表特定的语言和文化惯例。
* **使用 Windows API 获取本地化设置：**  通过调用 Windows API 函数 `GetLocaleInfo`，获取各种特定于 locale 的信息，例如：
    * 月份和星期几的名称（全称和简称）
    * 日期和时间的格式
    * AM/PM 字符串
    * 数字格式（小数点分隔符、千位分隔符等）
    * 一周的第一天

**2. 格式化日期和时间：**

* **转换 Windows 日期/时间格式为 LDML 格式：**  `ConvertWindowsDateTimeFormat` 函数将 Windows 系统使用的日期和时间格式字符串（例如 "yyyy/MM/dd"）转换为 LDML (Locale Data Markup Language) 格式，这是 Unicode 联盟定义的用于描述本地化数据的标准格式，JavaScript 的 `Intl` API 使用的就是 LDML 格式。

**3. 提供本地化数据给 Blink 引擎的其他部分：**

* **`LocaleWin` 类:**  该类封装了从 Windows 系统获取到的本地化信息，并提供了访问这些信息的接口。Blink 引擎的其他部分可以通过 `LocaleWin` 对象来获取特定 locale 的日期、时间、数字等格式信息。

**它与 JavaScript, HTML, CSS 的功能关系：**

这个文件直接影响着 JavaScript 中 `Intl` 对象的行为，以及 HTML 中与本地化相关的特性。

**JavaScript:**

* **`Intl.DateTimeFormat`:**  `locale_win.cc` 获取到的日期和时间格式（例如，短日期格式、长日期格式、带秒的时间格式等）会被用于初始化 JavaScript 的 `Intl.DateTimeFormat` 对象。当你在 JavaScript 中创建一个 `Intl.DateTimeFormat` 对象并指定一个 locale 时，Blink 引擎会使用 `locale_win.cc` 提供的数据来格式化日期和时间。

   **举例说明:**

   ```javascript
   // 假设用户的 Windows 系统 locale 设置为中文（中国大陆）
   const dateFormatter = new Intl.DateTimeFormat('zh-CN');
   const date = new Date();
   const formattedDate = dateFormatter.format(date);
   console.log(formattedDate); // 输出类似于 "2023/10/27" 的中文日期格式，具体的格式由 locale_win.cc 提供的数据决定。

   const timeFormatter = new Intl.DateTimeFormat('zh-CN', { timeStyle: 'short' });
   const formattedTime = timeFormatter.format(date);
   console.log(formattedTime); // 输出类似于 "下午2:30" 的中文时间格式。
   ```

* **`Intl.NumberFormat`:**  `locale_win.cc` 获取到的数字格式信息（例如，小数点分隔符、千位分隔符、负号格式等）会被用于初始化 JavaScript 的 `Intl.NumberFormat` 对象。

   **举例说明:**

   ```javascript
   // 假设用户的 Windows 系统 locale 设置为德语
   const numberFormatter = new Intl.NumberFormat('de-DE');
   const number = 12345.67;
   const formattedNumber = numberFormatter.format(number);
   console.log(formattedNumber); // 输出 "12.345,67"，德语使用逗号作为小数点分隔符，点号作为千位分隔符。
   ```

* **`Intl.getCanonicalLocales` 等其他 `Intl` API:**  `locale_win.cc` 也在底层支持着其他 `Intl` API 的功能，例如验证 locale 字符串的有效性等。

**HTML:**

* **`<input type="date">`, `<input type="time">`, `<input type="datetime-local">`:**  这些 HTML5 表单控件在渲染时会根据用户的系统 locale 设置来显示日期和时间的选择器，以及默认的日期和时间格式。`locale_win.cc` 提供的本地化信息会影响这些控件的默认行为和用户界面。

   **举例说明:**

   如果用户的 Windows 系统 locale 设置为中文，那么 `<input type="date">` 控件可能会默认显示一个日历，其中月份和星期几的名称是中文的，并且日期格式可能是 "YYYY/MM/DD"。

**CSS:**

* **`::marker` 伪元素 (间接关系):**  虽然不是直接相关，但 `locale_win.cc` 中 `IsRTL()` 函数判断 locale 是否为从右到左 (Right-to-Left) 的语言，这可能会间接影响 CSS 中列表项标记 (`::marker`) 的默认方向。

**逻辑推理的举例说明：**

**假设输入:**  一个 locale 字符串 "fr-CA" (法语 - 加拿大)。

**`LCIDFromLocale` 的输出:**  `locale_win.cc` 会尝试将 "fr-CA" 映射到对应的 Windows LCID。通过 Windows API 或内部的映射表，它可能会返回一个特定的 LCID 值，例如 `0x0c0c`。

**`ConvertWindowsDateTimeFormat` 的输入:**  从 Windows 系统获取到的法语（加拿大）的短日期格式字符串，例如 "yyyy-MM-dd"。

**`ConvertWindowsDateTimeFormat` 的输出:**  将其转换为 LDML 格式，例如 "yyyy-MM-dd"。对于简单的格式，转换可能只是简单地复制。对于更复杂的 Windows 格式，则需要进行转换。例如，Windows 中的 "ddd" (缩写的星期几名称) 会被转换为 LDML 的 "EEE"。

**用户或编程常见的使用错误：**

1. **假设所有 locale 的日期格式都相同：**  开发者可能会错误地假设所有用户的日期格式都是 "YYYY-MM-DD"，然后编写硬编码的日期解析逻辑，导致在其他 locale 下解析失败。

   **举例:**  如果用户在法语环境下，日期格式可能是 "jj/MM/aaaa"，你的代码如果只处理 "YYYY-MM-DD" 就会出错。

2. **忽略用户的 locale 设置：**  一些开发者可能会忽略用户的 locale 设置，而强制使用特定的日期或数字格式，这会降低用户体验，特别是对于国际化的应用。

   **举例:**  在一个面向全球用户的网站上，如果总是以美国英语的日期格式显示日期，那么对于欧洲或其他地区的用户来说可能会感到困惑。

3. **错误地解析或格式化数字：**  不同 locale 使用不同的数字格式，例如小数点和千位分隔符。如果开发者没有使用 `Intl.NumberFormat` 或类似的本地化工具，而是自己编写解析或格式化逻辑，很容易出错。

   **举例:**  在英语中，一百万通常写成 "1,000,000.00"，而在德语中可能是 "1.000.000,00"。如果你的代码假设小数点总是点号，千位分隔符总是逗号，那么在德语环境下就会解析错误。

4. **在服务器端进行不正确的本地化处理：**  如果服务器端没有正确地配置 locale 或使用合适的本地化库，可能会返回与用户期望的 locale 不符的数据格式。

   **举例:**  一个服务器端程序可能使用了默认的英文 locale 来格式化日期，然后将其发送到用户的浏览器，即使用户的浏览器设置了中文 locale，用户看到的仍然是英文格式的日期。

总之，`blink/renderer/platform/text/locale_win.cc` 是 Blink 引擎中至关重要的一个文件，它连接了 Windows 系统的本地化设置和 Blink 引擎的文本处理能力，直接影响着 Web 页面中与本地化相关的各种功能，特别是 JavaScript 的 `Intl` API 和 HTML 的本地化特性。理解其功能有助于开发者更好地处理 Web 应用的国际化和本地化问题，避免常见的错误。

Prompt: 
```
这是目录为blink/renderer/platform/text/locale_win.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/text/locale_win.h"

#include <iterator>
#include <limits>
#include <memory>

#include "base/memory/ptr_util.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_util.h"
#include "third_party/blink/renderer/platform/language.h"
#include "third_party/blink/renderer/platform/text/date_components.h"
#include "third_party/blink/renderer/platform/text/date_time_format.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"
#include "ui/base/ui_base_features.h"

namespace blink {

static String ExtractLanguageCode(const String& locale) {
  wtf_size_t dash_position = locale.find('-');
  if (dash_position == kNotFound)
    return locale;
  return locale.Left(dash_position);
}

static LCID LCIDFromLocaleInternal(LCID user_default_lcid,
                                   const String& user_default_language_code,
                                   const String& locale) {
  String locale_language_code = ExtractLanguageCode(locale);
  if (DeprecatedEqualIgnoringCase(locale_language_code,
                                  user_default_language_code))
    return user_default_lcid;
  if (locale.length() >= LOCALE_NAME_MAX_LENGTH)
    return 0;
  UChar buffer[LOCALE_NAME_MAX_LENGTH];
  auto buffer_slice = base::span(buffer).first(locale.length());
  if (locale.Is8Bit())
    StringImpl::CopyChars(buffer_slice, locale.Span8());
  else
    StringImpl::CopyChars(buffer_slice, locale.Span16());
  buffer[locale.length()] = '\0';
  return ::LocaleNameToLCID(base::as_writable_wcstr(buffer), 0);
}

static LCID LCIDFromLocale(const String& locale, bool defaults_for_locale) {
  // According to MSDN, 9 is enough for LOCALE_SISO639LANGNAME.
  const size_t kLanguageCodeBufferSize = 9;
  WCHAR lowercase_language_code[kLanguageCodeBufferSize];
  ::GetLocaleInfo(LOCALE_USER_DEFAULT,
                  LOCALE_SISO639LANGNAME |
                      (defaults_for_locale ? LOCALE_NOUSEROVERRIDE : 0),
                  lowercase_language_code, kLanguageCodeBufferSize);
  String user_default_language_code =
      String(base::as_u16cstr(lowercase_language_code));

  LCID lcid = LCIDFromLocaleInternal(LOCALE_USER_DEFAULT,
                                     user_default_language_code, locale);
  if (!lcid)
    lcid = LCIDFromLocaleInternal(
        LOCALE_USER_DEFAULT, user_default_language_code, DefaultLanguage());
  return lcid;
}

std::unique_ptr<Locale> Locale::Create(const String& locale) {
  // Whether the default settings for the locale should be used, ignoring user
  // overrides.
  bool defaults_for_locale = WebTestSupport::IsRunningWebTest();
  return LocaleWin::Create(LCIDFromLocale(locale, defaults_for_locale),
                           defaults_for_locale);
}

inline LocaleWin::LocaleWin(LCID lcid, bool defaults_for_locale)
    : lcid_(lcid),
      did_initialize_number_data_(false),
      defaults_for_locale_(defaults_for_locale) {
  DWORD value = 0;
  GetLocaleInfo(LOCALE_IFIRSTDAYOFWEEK |
                    (defaults_for_locale ? LOCALE_NOUSEROVERRIDE : 0),
                value);
  // 0:Monday, ..., 6:Sunday.
  // We need 1 for Monday, 0 for Sunday.
  first_day_of_week_ = (value + 1) % 7;
}

std::unique_ptr<LocaleWin> LocaleWin::Create(LCID lcid,
                                             bool defaults_for_locale) {
  return base::WrapUnique(new LocaleWin(lcid, defaults_for_locale));
}

LocaleWin::~LocaleWin() {}

String LocaleWin::GetLocaleInfoString(LCTYPE type) {
  int buffer_size_with_nul = ::GetLocaleInfo(
      lcid_, type | (defaults_for_locale_ ? LOCALE_NOUSEROVERRIDE : 0), 0, 0);
  if (buffer_size_with_nul <= 0)
    return String();
  StringBuffer<UChar> buffer(buffer_size_with_nul);
  ::GetLocaleInfo(
      lcid_, type | (defaults_for_locale_ ? LOCALE_NOUSEROVERRIDE : 0),
      base::as_writable_wcstr(buffer.Characters()), buffer_size_with_nul);
  buffer.Shrink(buffer_size_with_nul - 1);
  return String::Adopt(buffer);
}

void LocaleWin::GetLocaleInfo(LCTYPE type, DWORD& result) {
  ::GetLocaleInfo(lcid_, type | LOCALE_RETURN_NUMBER,
                  reinterpret_cast<LPWSTR>(&result),
                  sizeof(DWORD) / sizeof(TCHAR));
}

// -------------------------------- Tokenized date format

static unsigned CountContinuousLetters(const String& format, unsigned index) {
  unsigned count = 1;
  UChar reference = format[index];
  while (index + 1 < format.length()) {
    if (format[++index] != reference)
      break;
    ++count;
  }
  return count;
}

static void CommitLiteralToken(StringBuilder& literal_buffer,
                               StringBuilder& converted) {
  if (literal_buffer.length() <= 0)
    return;
  DateTimeFormat::QuoteAndappend(literal_buffer.ToString(), converted);
  literal_buffer.Clear();
}

// This function converts Windows date/time pattern format [1][2] into LDML date
// format pattern [3].
//
// i.e.
//   We set h, H, m, s, d, dd, M, or y as is. They have same meaning in both of
//   Windows and LDML.
//   We need to convert the following patterns:
//     t -> a
//     tt -> a
//     ddd -> EEE
//     dddd -> EEEE
//     g -> G
//     gg -> ignore
//
// [1] http://msdn.microsoft.com/en-us/library/dd317787(v=vs.85).aspx
// [2] http://msdn.microsoft.com/en-us/library/dd318148(v=vs.85).aspx
// [3] LDML http://unicode.org/reports/tr35/tr35-6.html#Date_Format_Patterns
static String ConvertWindowsDateTimeFormat(const String& format) {
  StringBuilder converted;
  StringBuilder literal_buffer;
  bool in_quote = false;
  bool last_quote_can_be_literal = false;
  for (unsigned i = 0; i < format.length(); ++i) {
    UChar ch = format[i];
    if (in_quote) {
      if (ch == '\'') {
        in_quote = false;
        DCHECK(i);
        if (last_quote_can_be_literal && format[i - 1] == '\'') {
          literal_buffer.Append('\'');
          last_quote_can_be_literal = false;
        } else {
          last_quote_can_be_literal = true;
        }
      } else {
        literal_buffer.Append(ch);
      }
      continue;
    }

    if (ch == '\'') {
      in_quote = true;
      if (last_quote_can_be_literal && i > 0 && format[i - 1] == '\'') {
        literal_buffer.Append(ch);
        last_quote_can_be_literal = false;
      } else {
        last_quote_can_be_literal = true;
      }
    } else if (IsASCIIAlpha(ch)) {
      CommitLiteralToken(literal_buffer, converted);
      unsigned symbol_start = i;
      unsigned count = CountContinuousLetters(format, i);
      i += count - 1;
      if (ch == 'h' || ch == 'H' || ch == 'm' || ch == 's' || ch == 'M' ||
          ch == 'y') {
        converted.Append(format, symbol_start, count);
      } else if (ch == 'd') {
        if (count <= 2)
          converted.Append(format, symbol_start, count);
        else if (count == 3)
          converted.Append("EEE");
        else
          converted.Append("EEEE");
      } else if (ch == 'g') {
        if (count == 1) {
          converted.Append('G');
        } else {
          // gg means imperial era in Windows.
          // Just ignore it.
        }
      } else if (ch == 't') {
        converted.Append('a');
      } else {
        literal_buffer.Append(format, symbol_start, count);
      }
    } else {
      literal_buffer.Append(ch);
    }
  }
  CommitLiteralToken(literal_buffer, converted);
  return converted.ToString();
}

const Vector<String>& LocaleWin::MonthLabels() {
  if (month_labels_.empty()) {
    static constexpr LCTYPE kTypes[12] = {
        LOCALE_SMONTHNAME1,  LOCALE_SMONTHNAME2,  LOCALE_SMONTHNAME3,
        LOCALE_SMONTHNAME4,  LOCALE_SMONTHNAME5,  LOCALE_SMONTHNAME6,
        LOCALE_SMONTHNAME7,  LOCALE_SMONTHNAME8,  LOCALE_SMONTHNAME9,
        LOCALE_SMONTHNAME10, LOCALE_SMONTHNAME11, LOCALE_SMONTHNAME12,
    };
    month_labels_.reserve(std::size(kTypes));
    for (unsigned i = 0; i < std::size(kTypes); ++i) {
      month_labels_.push_back(GetLocaleInfoString(kTypes[i]));
      if (month_labels_.back().empty()) {
        month_labels_.Shrink(0);
        base::ranges::copy(kFallbackMonthNames,
                           std::back_inserter(month_labels_));
        break;
      }
    }
  }
  return month_labels_;
}

const Vector<String>& LocaleWin::WeekDayShortLabels() {
  if (week_day_short_labels_.empty()) {
    static constexpr LCTYPE kTypes[7] = {
        // Numbered 1 (Monday) - 7 (Sunday), so do 7, then 1-6
        LOCALE_SSHORTESTDAYNAME7, LOCALE_SSHORTESTDAYNAME1,
        LOCALE_SSHORTESTDAYNAME2, LOCALE_SSHORTESTDAYNAME3,
        LOCALE_SSHORTESTDAYNAME4, LOCALE_SSHORTESTDAYNAME5,
        LOCALE_SSHORTESTDAYNAME6};
    week_day_short_labels_.reserve(std::size(kTypes));
    for (unsigned i = 0; i < std::size(kTypes); ++i) {
      week_day_short_labels_.push_back(GetLocaleInfoString(kTypes[i]));
      if (week_day_short_labels_.back().empty()) {
        week_day_short_labels_.Shrink(0);
        base::ranges::copy(kFallbackWeekdayShortNames,
                           std::back_inserter(week_day_short_labels_));
        break;
      }
    }
  }
  return week_day_short_labels_;
}

unsigned LocaleWin::FirstDayOfWeek() {
  return first_day_of_week_;
}

bool LocaleWin::IsRTL() {
  WTF::unicode::CharDirection dir =
      WTF::unicode::Direction(MonthLabels()[0][0]);
  return dir == WTF::unicode::kRightToLeft ||
         dir == WTF::unicode::kRightToLeftArabic;
}

String LocaleWin::DateFormat() {
  if (date_format_.IsNull())
    date_format_ =
        ConvertWindowsDateTimeFormat(GetLocaleInfoString(LOCALE_SSHORTDATE));
  return date_format_;
}

String LocaleWin::DateFormat(const String& windows_format) {
  return ConvertWindowsDateTimeFormat(windows_format);
}

String LocaleWin::MonthFormat() {
  if (month_format_.IsNull())
    month_format_ =
        ConvertWindowsDateTimeFormat(GetLocaleInfoString(LOCALE_SYEARMONTH));
  return month_format_;
}

String LocaleWin::ShortMonthFormat() {
  if (short_month_format_.IsNull())
    short_month_format_ =
        ConvertWindowsDateTimeFormat(GetLocaleInfoString(LOCALE_SYEARMONTH))
            .Replace("MMMM", "MMM");
  return short_month_format_;
}

String LocaleWin::TimeFormat() {
  if (time_format_with_seconds_.IsNull())
    time_format_with_seconds_ =
        ConvertWindowsDateTimeFormat(GetLocaleInfoString(LOCALE_STIMEFORMAT));
  return time_format_with_seconds_;
}

String LocaleWin::ShortTimeFormat() {
  if (!time_format_without_seconds_.IsNull())
    return time_format_without_seconds_;
  String format = GetLocaleInfoString(LOCALE_SSHORTTIME);
  // Vista or older Windows doesn't support LOCALE_SSHORTTIME.
  if (format.empty()) {
    format = GetLocaleInfoString(LOCALE_STIMEFORMAT);
    StringBuilder builder;
    builder.Append(GetLocaleInfoString(LOCALE_STIME));
    builder.Append("ss");
    wtf_size_t pos = format.ReverseFind(builder.ToString());
    if (pos != kNotFound)
      format.Remove(pos, builder.length());
  }
  time_format_without_seconds_ = ConvertWindowsDateTimeFormat(format);
  return time_format_without_seconds_;
}

String LocaleWin::DateTimeFormatWithSeconds() {
  if (!date_time_format_with_seconds_.IsNull())
    return date_time_format_with_seconds_;
  StringBuilder builder;
  builder.Append(DateFormat());
  builder.Append(' ');
  builder.Append(TimeFormat());
  date_time_format_with_seconds_ = builder.ToString();
  return date_time_format_with_seconds_;
}

String LocaleWin::DateTimeFormatWithoutSeconds() {
  if (!date_time_format_without_seconds_.IsNull())
    return date_time_format_without_seconds_;
  StringBuilder builder;
  builder.Append(DateFormat());
  builder.Append(' ');
  builder.Append(ShortTimeFormat());
  date_time_format_without_seconds_ = builder.ToString();
  return date_time_format_without_seconds_;
}

const Vector<String>& LocaleWin::ShortMonthLabels() {
  if (short_month_labels_.empty()) {
    static constexpr LCTYPE kTypes[12] = {
        LOCALE_SABBREVMONTHNAME1,  LOCALE_SABBREVMONTHNAME2,
        LOCALE_SABBREVMONTHNAME3,  LOCALE_SABBREVMONTHNAME4,
        LOCALE_SABBREVMONTHNAME5,  LOCALE_SABBREVMONTHNAME6,
        LOCALE_SABBREVMONTHNAME7,  LOCALE_SABBREVMONTHNAME8,
        LOCALE_SABBREVMONTHNAME9,  LOCALE_SABBREVMONTHNAME10,
        LOCALE_SABBREVMONTHNAME11, LOCALE_SABBREVMONTHNAME12,
    };
    short_month_labels_.reserve(std::size(kTypes));
    for (unsigned i = 0; i < std::size(kTypes); ++i) {
      short_month_labels_.push_back(GetLocaleInfoString(kTypes[i]));
      if (short_month_labels_.back().empty()) {
        short_month_labels_.Shrink(0);
        base::ranges::copy(kFallbackMonthShortNames,
                           std::back_inserter(short_month_labels_));
        break;
      }
    }
  }
  return short_month_labels_;
}

const Vector<String>& LocaleWin::StandAloneMonthLabels() {
  // Windows doesn't provide a way to get stand-alone month labels.
  return MonthLabels();
}

const Vector<String>& LocaleWin::ShortStandAloneMonthLabels() {
  // Windows doesn't provide a way to get stand-alone month labels.
  return ShortMonthLabels();
}

const Vector<String>& LocaleWin::TimeAMPMLabels() {
  if (time_ampm_labels_.empty()) {
    time_ampm_labels_.push_back(GetLocaleInfoString(LOCALE_S1159));
    time_ampm_labels_.push_back(GetLocaleInfoString(LOCALE_S2359));
  }
  return time_ampm_labels_;
}

void LocaleWin::InitializeLocaleData() {
  if (did_initialize_number_data_)
    return;

  Vector<String, kDecimalSymbolsSize> symbols;
  enum DigitSubstitution {
    kDigitSubstitutionContext = 0,
    kDigitSubstitution0to9 = 1,
    kDigitSubstitutionNative = 2,
  };
  DWORD digit_substitution = kDigitSubstitution0to9;
  GetLocaleInfo(LOCALE_IDIGITSUBSTITUTION, digit_substitution);
  if (digit_substitution == kDigitSubstitution0to9) {
    symbols.push_back("0");
    symbols.push_back("1");
    symbols.push_back("2");
    symbols.push_back("3");
    symbols.push_back("4");
    symbols.push_back("5");
    symbols.push_back("6");
    symbols.push_back("7");
    symbols.push_back("8");
    symbols.push_back("9");
  } else {
    String digits = GetLocaleInfoString(LOCALE_SNATIVEDIGITS);
    DCHECK_GE(digits.length(), 10u);
    for (unsigned i = 0; i < 10; ++i)
      symbols.push_back(digits.Substring(i, 1));
  }
  DCHECK(symbols.size() == kDecimalSeparatorIndex);
  symbols.push_back(GetLocaleInfoString(LOCALE_SDECIMAL));
  DCHECK(symbols.size() == kGroupSeparatorIndex);
  symbols.push_back(GetLocaleInfoString(LOCALE_STHOUSAND));
  DCHECK(symbols.size() == kDecimalSymbolsSize);

  String negative_sign = GetLocaleInfoString(LOCALE_SNEGATIVESIGN);
  enum NegativeFormat {
    kNegativeFormatParenthesis = 0,
    kNegativeFormatSignPrefix = 1,
    kNegativeFormatSignSpacePrefix = 2,
    kNegativeFormatSignSuffix = 3,
    kNegativeFormatSpaceSignSuffix = 4,
  };
  DWORD negative_format = kNegativeFormatSignPrefix;
  GetLocaleInfo(LOCALE_INEGNUMBER, negative_format);
  String negative_prefix = g_empty_string;
  String negative_suffix = g_empty_string;
  switch (negative_format) {
    case kNegativeFormatParenthesis:
      negative_prefix = "(";
      negative_suffix = ")";
      break;
    case kNegativeFormatSignSpacePrefix:
      negative_prefix = negative_sign + " ";
      break;
    case kNegativeFormatSignSuffix:
      negative_suffix = negative_sign;
      break;
    case kNegativeFormatSpaceSignSuffix:
      negative_suffix = " " + negative_sign;
      break;
    case kNegativeFormatSignPrefix:  // Fall through.
    default:
      negative_prefix = negative_sign;
      break;
  }
  did_initialize_number_data_ = true;
  SetLocaleData(symbols, g_empty_string, g_empty_string, negative_prefix,
                negative_suffix);
}
}

"""

```