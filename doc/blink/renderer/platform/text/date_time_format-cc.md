Response:
Let's break down the thought process for analyzing this C++ code file.

**1. Understanding the Request:**

The core request is to understand the functionality of the `date_time_format.cc` file in the Blink rendering engine. Specifically, I need to:

* Describe its core purpose.
* Explain its relationship (if any) to JavaScript, HTML, and CSS, providing examples.
* Demonstrate its logic with hypothetical inputs and outputs.
* Identify common user/programming errors related to its use.

**2. Initial Code Scan and Keyword Spotting:**

I start by quickly scanning the code for key terms and patterns. Things that jump out are:

* `DateTimeFormat`: This is the central class/namespace, suggesting date and time formatting.
* `Parse`: A function named "Parse" strongly indicates the file is involved in analyzing and interpreting date/time format strings.
* `TokenHandler`: This suggests the parsing process breaks down the format string into smaller units (tokens).
* `FieldType`:  This indicates different components of a date/time format (year, month, day, hour, minute, etc.).
* `kLowerCaseToFieldTypeMap`, `kUpperCaseToFieldTypeMap`: These are lookup tables mapping characters to specific `FieldType` values. This is a strong clue about how the parsing works.
* `'`:  The presence of single quotes and their special handling in the `Parse` function is significant. It suggests quotes are used to denote literal parts of the format string.
* `StringBuilder`:  This is a common pattern for efficient string concatenation, likely used to build up the formatted date/time string.
* `VisitLiteral`, `VisitField`: These methods within the `TokenHandler` suggest a callback mechanism where the parser informs another component about the identified literals and fields.
* `QuoteAndappend`: This function seems to handle escaping special characters (like single quotes) when embedding literals in a format string.

**3. Deducing Core Functionality:**

Based on the above observations, the primary function of this code is to **parse date and time format strings**. It takes a string representing a date/time pattern and breaks it down into its constituent parts (literals and date/time fields).

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now I need to bridge the gap between this low-level C++ code and the higher-level web technologies.

* **JavaScript:**  JavaScript has the `Intl.DateTimeFormat` object. This C++ code is *likely* part of the underlying implementation of that JavaScript API within the Blink engine. When JavaScript code uses `Intl.DateTimeFormat` to format or parse dates, this C++ code is involved in processing the format patterns provided to it.

    * *Example:*  I need a clear JavaScript example showing how the format string passed to `Intl.DateTimeFormat` relates to the C++ code.

* **HTML:** HTML itself doesn't directly interact with this code. However, the *results* of date/time formatting (done by this code) are often displayed in HTML.

    * *Example:* A website might use JavaScript with `Intl.DateTimeFormat` to display the current date, and that formatted date would then be inserted into an HTML element.

* **CSS:**  CSS is even more indirect. CSS styles the *appearance* of the formatted date/time, but doesn't influence the formatting process itself.

    * *Example:* CSS can change the font, color, and size of the date displayed in the HTML, but it doesn't change *how* the date is formatted (e.g., the order of month, day, year).

**5. Illustrative Input/Output for `Parse`:**

To demonstrate the `Parse` function's logic, I need to come up with some example format strings and predict how the parser would break them down. I should cover different cases:

* Simple formats (e.g., "yyyy-MM-dd").
* Formats with literals (e.g., "Month: MMMM, Year: yyyy").
* Formats with escaped quotes (e.g., "The date is 'today'").

For each input, I need to describe the output in terms of the `VisitLiteral` and `VisitField` calls on the `TokenHandler`.

**6. Identifying Common Errors:**

Consider how a developer might misuse this functionality (even indirectly through the JavaScript API).

* **Incorrect format strings:**  Using invalid characters or combinations of characters. The `Parse` function explicitly returns `false` in such cases.
* **Mismatched quotes:**  Forgetting to close quotes or having unbalanced quotes in the format string.
* **Locale issues (though the C++ code doesn't directly handle locales, it's a related concept in date/time formatting):** While this specific C++ file doesn't manage locales, the *context* is date/time formatting, where locale is crucial. So, mentioning locale-related errors in the higher-level usage is relevant.

**7. Explaining `QuoteAndappend`:**

This function needs its own explanation. It's about safely embedding literal strings that might contain special characters (like single quotes) within a larger format string. I need to show how it escapes single quotes.

**8. Structuring the Answer:**

Finally, I need to organize the information clearly, using headings and bullet points to make it easy to read and understand. I'll address each part of the original request in a structured way.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this code directly formats dates.
* **Correction:**  The name "Parse" and the `TokenHandler` suggest it's more about *interpreting* the format string, not performing the actual formatting. The formatting logic likely resides elsewhere.
* **Initial thought:** How closely tied is this to the JavaScript API?
* **Refinement:**  While not a one-to-one mapping, it's highly probable this code is part of the underlying machinery for `Intl.DateTimeFormat`. Phrasing needs to reflect this likelihood without making definitive claims about the exact internal structure.
* **Considering edge cases:** What happens with empty format strings? What if the format string contains only literals? These are good to think about to ensure the explanation is comprehensive.

By following this structured thought process, analyzing the code's components, and connecting it to the broader context of web development, I can generate a thorough and accurate explanation of the `date_time_format.cc` file's functionality.
这个C++源代码文件 `date_time_format.cc`，位于 Chromium Blink 引擎中，其主要功能是**解析日期和时间格式字符串**。  它并不直接进行日期和时间的格式化操作，而是负责理解和分解用户提供的格式模式，将其转换成引擎可以理解的内部表示。

以下是对其功能的详细列举和与 Web 技术关系的说明：

**1. 功能：解析日期和时间格式字符串**

* **将格式字符串分解为标记 (Tokens):**  该文件定义了一个 `DateTimeFormat::Parse` 函数，该函数接收一个日期和时间格式的字符串作为输入，并将其分解成不同的组成部分，称为标记 (tokens)。这些标记可以是：
    * **字面量 (Literals):**  格式字符串中需要按原样输出的文本，例如分隔符（如 "-"、"/"）、空格或其他字符。
    * **字段 (Fields):**  代表日期或时间的特定组成部分，例如年、月、日、小时、分钟、秒、时区等。这些字段由特定的字母表示（大小写敏感），例如 'y' 代表年，'M' 代表月，'d' 代表日。

* **识别字段类型 (Field Types):**  通过预定义的映射表 `kLowerCaseToFieldTypeMap` 和 `kUpperCaseToFieldTypeMap`，根据格式字符串中的字符（如 'y', 'M', 'h', 'H' 等），确定其对应的日期或时间字段类型。例如，'y' 被映射到 `DateTimeFormat::kFieldTypeYear`，'M' 被映射到 `DateTimeFormat::kFieldTypeMonth`。

* **处理转义字符:**  支持使用单引号 `'` 来转义字面量字符。例如，`'年'yyyy'月'MM'日'` 中的 `'年'`、`'月'` 和 `'日'` 将被视为字面量，而 `yyyy` 和 `MM` 将被视为字段。

* **提供回调机制:**  `DateTimeFormat::Parse` 函数接受一个 `TokenHandler` 接口的实例作为参数。在解析过程中，当识别到字面量或字段时，会调用 `TokenHandler` 接口的相应方法 (`VisitLiteral` 和 `VisitField`)，并将解析到的内容传递给它。这允许调用者自定义如何处理解析出的标记。

**2. 与 JavaScript, HTML, CSS 的关系**

此文件是 Blink 渲染引擎的底层实现，与 JavaScript 的 `Intl.DateTimeFormat` API 密切相关。

* **JavaScript (Intl.DateTimeFormat):**
    * `Intl.DateTimeFormat` 是 JavaScript 中用于格式化和解析日期和时间的国际化 API。当你在 JavaScript 中创建一个 `Intl.DateTimeFormat` 对象并提供一个格式模式 (pattern) 时，Blink 引擎很可能会使用 `date_time_format.cc` 中的逻辑来解析这个模式字符串。
    * **例子:**
        ```javascript
        const formatter = new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: 'long', day: 'numeric' });
        const date = new Date();
        const formattedDate = formatter.format(date); // "2023年10月27日"
        ```
        在这个例子中，`{ year: 'numeric', month: 'long', day: 'numeric' }`  或者更底层的格式字符串（例如 "yyyy年MMMM日"）会被传递到 Blink 引擎，然后 `date_time_format.cc` 中的 `Parse` 函数会解析这个格式字符串，识别出 "yyyy" 对应年份，"MMMM" 对应月份的完整名称等等。

* **HTML:**
    * HTML 本身不直接与 `date_time_format.cc` 交互。但是，通过 JavaScript 使用 `Intl.DateTimeFormat` 格式化后的日期和时间字符串最终会被插入到 HTML 元素中进行显示。
    * **例子:**
        ```html
        <div id="date"></div>
        <script>
          const dateElement = document.getElementById('date');
          const formatter = new Intl.DateTimeFormat('en-US', { dateStyle: 'full' });
          const date = new Date();
          dateElement.textContent = formatter.format(date); // 例如: "Friday, October 27, 2023"
        </script>
        ```
        在这个例子中，`Intl.DateTimeFormat` 的格式化操作依赖于 Blink 引擎对格式字符串的解析，而 `date_time_format.cc` 就参与了这个解析过程。

* **CSS:**
    * CSS 负责控制 HTML 元素的外观样式，包括日期和时间字符串的显示样式（例如字体、颜色、大小等）。但 CSS 不影响日期和时间是如何格式化的。  `date_time_format.cc` 的功能发生在格式化逻辑层面，与 CSS 无直接关系。

**3. 逻辑推理 (假设输入与输出)**

假设我们有以下格式字符串作为输入，并使用一个简单的 `TokenHandler` 来记录解析结果：

**假设输入:**  `"yyyy-MM-dd 'at' HH:mm:ss"`

**预期输出 (通过 TokenHandler 的调用):**

1. `VisitField(DateTimeFormat::kFieldTypeYear, 4)`  // 识别到 "yyyy"
2. `VisitLiteral("-")`                     // 识别到 "-"
3. `VisitField(DateTimeFormat::kFieldTypeMonth, 2)` // 识别到 "MM"
4. `VisitLiteral("-")`                     // 识别到 "-"
5. `VisitField(DateTimeFormat::kFieldTypeDayOfMonth, 2)` // 识别到 "dd"
6. `VisitLiteral(" at ")`                  // 识别到 " 'at' "，单引号被移除
7. `VisitField(DateTimeFormat::kFieldTypeHour23, 2)` // 识别到 "HH" (假设使用大写 H 表示 24 小时制)
8. `VisitLiteral(":")`                     // 识别到 ":"
9. `VisitField(DateTimeFormat::kFieldTypeMinute, 2)` // 识别到 "mm"
10. `VisitLiteral(":")`                    // 识别到 ":"
11. `VisitField(DateTimeFormat::kFieldTypeSecond, 2)` // 识别到 "ss"

**假设输入:**  `"MM/dd/yy"`

**预期输出:**

1. `VisitField(DateTimeFormat::kFieldTypeMonth, 2)`
2. `VisitLiteral("/")`
3. `VisitField(DateTimeFormat::kFieldTypeDayOfMonth, 2)`
4. `VisitLiteral("/")`
5. `VisitField(DateTimeFormat::kFieldTypeYear, 2)`

**假设输入 (包含转义):** `"It's the 'yyyy' year."`

**预期输出:**

1. `VisitLiteral("It's the ")`
2. `VisitLiteral("y")`  // 注意：单引号内的单个字符被视为字面量
3. `VisitLiteral("y")`
4. `VisitLiteral("y")`
5. `VisitLiteral("y")`
6. `VisitLiteral(" year.")`

**假设输入 (嵌套引号):** `"The date is ''today''."`

**预期输出:**

1. `VisitLiteral("The date is 'today'.")`  // 双单引号被解析为单个单引号字面量

**4. 用户或编程常见的使用错误**

虽然这个 C++ 文件本身是底层实现，用户或开发者在使用 JavaScript 的 `Intl.DateTimeFormat` 时可能会遇到以下与格式字符串相关的错误，这些错误最终可能与 `date_time_format.cc` 的解析逻辑相关：

* **使用无效的字段字符:**  例如，在格式字符串中使用了 `DateTimeFormat` 不支持的字符。`Parse` 函数会返回 `false` 表示解析失败。
    * **例子 (JavaScript):**
        ```javascript
        try {
          const formatter = new Intl.DateTimeFormat('en-US', { format: 'yyyymmdd' }); // 'm' 应该是 'M'
        } catch (error) {
          console.error(error); // 可能会抛出 RangeError 或类似错误，因为 'm' 不是有效的月份字段
        }
        ```

* **大小写错误:**  日期和时间字段的字符是大小写敏感的。例如，`MM` 代表月份，而 `mm` 代表分钟。混淆大小写会导致解析错误或得到意外的格式。
    * **例子 (JavaScript):**
        ```javascript
        const formatter1 = new Intl.DateTimeFormat('en-US', { format: 'dd-mm-yyyy' }); // 错误：mm 是分钟
        const formatter2 = new Intl.DateTimeFormat('en-US', { format: 'dd-MM-yyyy' }); // 正确：MM 是月份
        ```

* **未闭合的引号:**  如果在格式字符串中使用了单引号来表示字面量，但忘记闭合引号，会导致解析错误。
    * **例子 (JavaScript，虽然 `Intl.DateTimeFormat` 通常不直接使用引号，但可以体现在自定义格式中):**
        ```javascript
        // 假设底层实现允许这种自定义格式
        // const formatter = new Intl.DateTimeFormat('en-US', { format: 'The year is 'yyyy }); // 错误：引号未闭合
        ```

* **混淆字段数量:**  某些字段的长度决定了输出的格式（例如，`yy` 表示两位年份，`yyyy` 表示四位年份）。错误地使用字段数量会导致格式不符合预期。
    * **例子 (JavaScript):**
        ```javascript
        const formatter1 = new Intl.DateTimeFormat('en-US', { year: '2-digit' }); // 输出两位年份
        const formatter2 = new Intl.DateTimeFormat('en-US', { year: 'numeric' }); // 输出完整年份
        ```

* **不理解转义规则:**  没有正确理解如何使用单引号来转义字面量字符，可能导致输出结果与预期不符。

总之，`blink/renderer/platform/text/date_time_format.cc` 文件是 Chromium Blink 引擎中负责解析日期和时间格式字符串的关键组件，它为 JavaScript 的 `Intl.DateTimeFormat` API 提供了底层的支持，使得浏览器能够理解和处理各种日期和时间格式。理解其功能有助于我们更好地理解和使用 Web 平台的日期和时间处理能力。

### 提示词
```
这是目录为blink/renderer/platform/text/date_time_format.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/text/date_time_format.h"

#include "base/notreached.h"
#include "third_party/blink/renderer/platform/wtf/text/ascii_ctype.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

static const DateTimeFormat::FieldType kLowerCaseToFieldTypeMap[26] = {
    DateTimeFormat::kFieldTypePeriod,                   // a
    DateTimeFormat::kFieldTypePeriodAmPmNoonMidnight,   // b
    DateTimeFormat::kFieldTypeLocalDayOfWeekStandAlon,  // c
    DateTimeFormat::kFieldTypeDayOfMonth,               // d
    DateTimeFormat::kFieldTypeLocalDayOfWeek,           // e
    DateTimeFormat::kFieldTypeInvalid,                  // f
    DateTimeFormat::kFieldTypeModifiedJulianDay,        // g
    DateTimeFormat::kFieldTypeHour12,                   // h
    DateTimeFormat::kFieldTypeInvalid,                  // i
    DateTimeFormat::kFieldTypeInvalid,                  // j
    DateTimeFormat::kFieldTypeHour24,                   // k
    DateTimeFormat::kFieldTypeInvalid,                  // l
    DateTimeFormat::kFieldTypeMinute,                   // m
    DateTimeFormat::kFieldTypeInvalid,                  // n
    DateTimeFormat::kFieldTypeInvalid,                  // o
    DateTimeFormat::kFieldTypeInvalid,                  // p
    DateTimeFormat::kFieldTypeQuaterStandAlone,         // q
    DateTimeFormat::kFieldTypeYearRelatedGregorian,     // r
    DateTimeFormat::kFieldTypeSecond,                   // s
    DateTimeFormat::kFieldTypeInvalid,                  // t
    DateTimeFormat::kFieldTypeExtendedYear,             // u
    DateTimeFormat::kFieldTypeNonLocationZone,          // v
    DateTimeFormat::kFieldTypeWeekOfYear,               // w
    DateTimeFormat::kFieldTypeZoneIso8601,              // x
    DateTimeFormat::kFieldTypeYear,                     // y
    DateTimeFormat::kFieldTypeZone,                     // z
};

static const DateTimeFormat::FieldType kUpperCaseToFieldTypeMap[26] = {
    DateTimeFormat::kFieldTypeMillisecondsInDay,  // A
    DateTimeFormat::kFieldTypePeriodFlexible,     // B
    DateTimeFormat::kFieldTypeInvalid,            // C
    DateTimeFormat::kFieldTypeDayOfYear,          // D
    DateTimeFormat::kFieldTypeDayOfWeek,          // E
    DateTimeFormat::kFieldTypeDayOfWeekInMonth,   // F
    DateTimeFormat::kFieldTypeEra,                // G
    DateTimeFormat::kFieldTypeHour23,             // H
    DateTimeFormat::kFieldTypeInvalid,            // I
    DateTimeFormat::kFieldTypeInvalid,            // J
    DateTimeFormat::kFieldTypeHour11,             // K
    DateTimeFormat::kFieldTypeMonthStandAlone,    // L
    DateTimeFormat::kFieldTypeMonth,              // M
    DateTimeFormat::kFieldTypeInvalid,            // N
    DateTimeFormat::kFieldTypeZoneLocalized,      // O
    DateTimeFormat::kFieldTypeInvalid,            // P
    DateTimeFormat::kFieldTypeQuater,             // Q
    DateTimeFormat::kFieldTypeInvalid,            // R
    DateTimeFormat::kFieldTypeFractionalSecond,   // S
    DateTimeFormat::kFieldTypeInvalid,            // T
    DateTimeFormat::kFieldTypeYearCyclicName,     // U
    DateTimeFormat::kFieldTypeZoneId,             // V
    DateTimeFormat::kFieldTypeWeekOfMonth,        // W
    DateTimeFormat::kFieldTypeZoneIso8601Z,       // X
    DateTimeFormat::kFieldTypeYearOfWeekOfYear,   // Y
    DateTimeFormat::kFieldTypeRFC822Zone,         // Z
};

static DateTimeFormat::FieldType MapCharacterToFieldType(const UChar ch) {
  if (IsASCIIUpper(ch))
    return kUpperCaseToFieldTypeMap[ch - 'A'];

  if (IsASCIILower(ch))
    return kLowerCaseToFieldTypeMap[ch - 'a'];

  return DateTimeFormat::kFieldTypeLiteral;
}

bool DateTimeFormat::Parse(const String& source, TokenHandler& token_handler) {
  enum State {
    kStateInQuote,
    kStateInQuoteQuote,
    kStateLiteral,
    kStateQuote,
    kStateSymbol,
  } state = kStateLiteral;

  FieldType field_type = kFieldTypeLiteral;
  StringBuilder literal_buffer;
  int field_counter = 0;

  for (unsigned index = 0; index < source.length(); ++index) {
    const UChar ch = source[index];
    switch (state) {
      case kStateInQuote:
        if (ch == '\'') {
          state = kStateInQuoteQuote;
          break;
        }

        literal_buffer.Append(ch);
        break;

      case kStateInQuoteQuote:
        if (ch == '\'') {
          literal_buffer.Append('\'');
          state = kStateInQuote;
          break;
        }

        field_type = MapCharacterToFieldType(ch);
        if (field_type == kFieldTypeInvalid)
          return false;

        if (field_type == kFieldTypeLiteral) {
          literal_buffer.Append(ch);
          state = kStateLiteral;
          break;
        }

        if (literal_buffer.length()) {
          token_handler.VisitLiteral(literal_buffer.ToString());
          literal_buffer.Clear();
        }

        field_counter = 1;
        state = kStateSymbol;
        break;

      case kStateLiteral:
        if (ch == '\'') {
          state = kStateQuote;
          break;
        }

        field_type = MapCharacterToFieldType(ch);
        if (field_type == kFieldTypeInvalid)
          return false;

        if (field_type == kFieldTypeLiteral) {
          literal_buffer.Append(ch);
          break;
        }

        if (literal_buffer.length()) {
          token_handler.VisitLiteral(literal_buffer.ToString());
          literal_buffer.Clear();
        }

        field_counter = 1;
        state = kStateSymbol;
        break;

      case kStateQuote:
        literal_buffer.Append(ch);
        state = ch == '\'' ? kStateLiteral : kStateInQuote;
        break;

      case kStateSymbol: {
        DCHECK_NE(field_type, kFieldTypeInvalid);
        DCHECK_NE(field_type, kFieldTypeLiteral);
        DCHECK(literal_buffer.empty());

        FieldType field_type2 = MapCharacterToFieldType(ch);
        if (field_type2 == kFieldTypeInvalid)
          return false;

        if (field_type == field_type2) {
          ++field_counter;
          break;
        }

        token_handler.VisitField(field_type, field_counter);

        if (field_type2 == kFieldTypeLiteral) {
          if (ch == '\'') {
            state = kStateQuote;
          } else {
            literal_buffer.Append(ch);
            state = kStateLiteral;
          }
          break;
        }

        field_counter = 1;
        field_type = field_type2;
        break;
      }
    }
  }

  DCHECK_NE(field_type, kFieldTypeInvalid);

  switch (state) {
    case kStateLiteral:
    case kStateInQuoteQuote:
      if (literal_buffer.length())
        token_handler.VisitLiteral(literal_buffer.ToString());
      return true;

    case kStateQuote:
    case kStateInQuote:
      if (literal_buffer.length())
        token_handler.VisitLiteral(literal_buffer.ToString());
      return false;

    case kStateSymbol:
      DCHECK_NE(field_type, kFieldTypeLiteral);
      DCHECK(!literal_buffer.length());
      token_handler.VisitField(field_type, field_counter);
      return true;
  }

  NOTREACHED();
}

static bool IsASCIIAlphabetOrQuote(UChar ch) {
  return IsASCIIAlpha(ch) || ch == '\'';
}

void DateTimeFormat::QuoteAndappend(const String& literal,
                                    StringBuilder& buffer) {
  if (literal.length() <= 0)
    return;

  if (literal.Find(IsASCIIAlphabetOrQuote) == kNotFound) {
    buffer.Append(literal);
    return;
  }

  if (literal.find('\'') == kNotFound) {
    buffer.Append('\'');
    buffer.Append(literal);
    buffer.Append('\'');
    return;
  }

  for (unsigned i = 0; i < literal.length(); ++i) {
    if (literal[i] == '\'') {
      buffer.Append("''");
    } else {
      String escaped = literal.Substring(i);
      escaped.Replace("'", "''");
      buffer.Append('\'');
      buffer.Append(escaped);
      buffer.Append('\'');
      return;
    }
  }
}

}  // namespace blink
```