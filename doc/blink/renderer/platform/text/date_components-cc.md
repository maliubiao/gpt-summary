Response:
Let's break down the thought process to analyze the `date_components.cc` file.

1. **Understand the Core Purpose:** The file name `date_components.cc` and the namespace `blink` (which suggests it's part of the Blink rendering engine, specifically for handling web platform features) immediately point towards handling date and time related information. The presence of copyright information from Google reinforces its integration within a larger project.

2. **Identify Key Data Structures (Implicit):**  Although there isn't a prominent `struct` or `class` definition visible in the provided snippet (we only see the namespace and function implementations),  the functions themselves heavily imply the existence of a `DateComponents` class (or struct). This class likely holds members like `year_`, `month_`, `month_day_`, `hour_`, `minute_`, `second_`, `millisecond_`, `week_`, and `type_`. The functions operate on these implicit members.

3. **Analyze the Included Headers:**
    * `<limits.h>`: Standard C library for numerical limits (e.g., `INT_MAX`). This suggests the code performs numerical calculations and needs to be aware of potential overflows.
    * `"base/notreached.h"`:  Likely a Chromium-specific header for marking code paths that should never be executed. This indicates a focus on correctness and handling unexpected states.
    * `"third_party/blink/renderer/platform/wtf/date_math.h"`:  This is a strong indicator of date and time calculations. The "wtf" likely stands for "Web Template Framework," a Blink-specific utility library.
    * `"third_party/blink/renderer/platform/wtf/math_extras.h"`: Suggests more general mathematical utility functions are being used.
    * `"third_party/blink/renderer/platform/wtf/text/ascii_ctype.h"`:  Indicates character type checking, specifically for ASCII digits. This points towards parsing or validation of string inputs.
    * `"third_party/blink/renderer/platform/wtf/text/wtf_string.h"`:  Implies the code works with Blink's string class, likely for input and output of date/time representations.

4. **Categorize Function Functionality:**  Go through the provided functions and group them by their apparent purpose:
    * **Constants:**  `kMinimumWeekNumber`, `kMaximumWeekNumber`, `kMaximumMonthInMaximumYear`, etc. These define the valid ranges and boundary conditions for date/time values.
    * **Helper Functions:** `MaxDayOfMonth`, `DayOfWeek`, `CountDigits`, `ToInt`, `WithinHTMLDateLimits`, `PositiveFmod`, `OffsetTo1stWeekStart`. These are internal utility functions used by the main parsing and setting logic.
    * **Parsing Functions:** `ParseYear`, `ParseMonth`, `ParseDate`, `ParseWeek`, `ParseTime`, `ParseDateTimeLocal`. These functions take string inputs and attempt to extract date/time components. They adhere to a specific format (likely ISO 8601 or a subset).
    * **Setting Functions (from Milliseconds/Epoch):** `SetMillisecondsSinceEpochForDateInternal`, `SetMillisecondsSinceEpochForDate`, `SetMillisecondsSinceEpochForDateTimeLocal`, `SetMillisecondsSinceEpochForMonth`, `SetMillisecondsSinceMidnight`, `SetMillisecondsSinceEpochForWeek`, `SetMonthsSinceEpoch`, `SetWeek`. These functions allow setting the date/time components based on different time representations (milliseconds since the epoch, months since the epoch, etc.).
    * **Getting Functions (to Milliseconds/Epoch):** `MillisecondsSinceEpochForTime`, `MillisecondsSinceEpoch`, `MonthsSinceEpoch`. These functions convert the internal date/time components back into numerical representations.
    * **Formatting Functions (to String):** `ToStringForTime`, `ToString`. These functions format the internal date/time components into string representations.

5. **Analyze Interactions with Web Technologies (JavaScript, HTML, CSS):**

    * **HTML:**  The function names and the presence of constants related to HTML5 specifications strongly suggest a connection to HTML input types like `<input type="date">`, `<input type="time">`, `<input type="datetime-local">`, `<input type="month">`, and `<input type="week">`. The parsing functions directly handle the string formats that these input types produce.
    * **JavaScript:** The functions that convert to and from milliseconds since the epoch are crucial for interoperability with JavaScript's `Date` object, which internally represents dates and times in this way. When JavaScript interacts with the DOM and gets values from date/time input fields, or sets values for them, this C++ code is involved in the underlying parsing and formatting.
    * **CSS:** While direct interaction with CSS is less obvious, CSS might indirectly be involved. For example, the styling of date/time input fields can depend on the browser's interpretation of the validity of the date/time value. If the parsing logic in `date_components.cc` determines a value is invalid, this might influence how the browser renders the input field (e.g., showing an error indicator).

6. **Consider Logic and Examples:**

    * **Parsing:**  Think about how the parsing functions work step-by-step. For example, `ParseDate` relies on `ParseMonth`, which in turn relies on `ParseYear`. This hierarchical structure is common in parsing. Create simple input/output examples to illustrate the parsing logic.
    * **Setting/Getting (Milliseconds):** Understand the epoch (January 1, 1970, UTC) and how milliseconds are used to represent points in time. Give examples of how setting milliseconds translates to specific dates and times, and vice-versa.
    * **Week Calculation:** The logic for calculating the week number is more complex. Focus on the `OffsetTo1stWeekStart` function and how it determines the start of the ISO week.

7. **Identify Potential User/Programming Errors:**

    * **Invalid Input Format:** The strict parsing functions are prone to errors if the input string doesn't conform to the expected format.
    * **Out-of-Range Values:**  The code includes checks for minimum and maximum years, months, days, etc. Providing values outside these ranges will lead to errors.
    * **Leap Year Issues:**  The `MaxDayOfMonth` function correctly handles leap years, but errors could arise if developers assume a fixed number of days in February.
    * **Time Zone Issues (Implicit):**  While not explicitly handled in this snippet, it's important to note that `date_components.cc` seems to deal with local date and time (`DateTimeLocal`). Not understanding the distinction between local and UTC time can lead to errors.

8. **Refine and Organize:**  Structure the analysis logically, starting with the basic functionality and gradually moving towards more complex interactions and potential errors. Use clear headings and examples to make the explanation easy to understand.
这个文件 `blink/renderer/platform/text/date_components.cc` 是 Chromium Blink 渲染引擎的一部分，主要负责处理日期和时间相关的组件和操作。它的核心功能是**解析、验证和表示各种日期和时间格式，以便在渲染引擎中使用。**

以下是它的功能列表，以及与 JavaScript, HTML, CSS 的关系说明、逻辑推理示例和常见使用错误：

**主要功能:**

1. **日期和时间组件的解析 (Parsing):**
   - 能够解析符合特定格式 (例如 ISO 8601) 的日期和时间字符串。
   - 支持解析年、月、日、周、时、分、秒、毫秒等不同的日期和时间组成部分。
   - 提供了 `ParseYear`, `ParseMonth`, `ParseDate`, `ParseWeek`, `ParseTime`, `ParseDateTimeLocal` 等函数来实现不同粒度的解析。

2. **日期和时间组件的验证 (Validation):**
   - 验证解析出的日期和时间组件是否在允许的范围内 (例如，月份在 1-12 之间，日期在当月有效范围内)。
   - 检查年份是否在允许的最小和最大年份之间。
   - 提供了 `WithinHTMLDateLimits` 等函数来执行范围检查。

3. **日期和时间组件的表示 (Representation):**
   - 使用内部的数据结构 (很可能是一个 `DateComponents` 类，尽管代码片段中没有完整定义) 来存储解析后的日期和时间组件。
   - 能够将内部表示的日期和时间转换回字符串格式，例如通过 `ToString` 和 `ToStringForTime` 函数。

4. **日期和时间值的计算 (Calculation):**
   - 提供了计算星期几的功能 (`WeekDay`)。
   - 能够计算给定年份的最大周数 (`MaxWeekNumberInYear`).
   - 实现了从毫秒数 (自 Epoch) 到日期和时间组件的转换 (`SetMillisecondsSinceEpochForDateInternal`, `SetMillisecondsSinceEpochForDateTimeLocal` 等)。
   - 实现了从日期和时间组件到毫秒数的转换 (`MillisecondsSinceEpoch`, `MillisecondsSinceEpochForTime`)。
   - 提供了处理月份的计算 (`MonthsSinceEpoch`, `SetMonthsSinceEpoch`).
   - 实现了基于 ISO 8601 周号设置日期的功能 (`SetMillisecondsSinceEpochForWeek`, `SetWeek`).

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**
    - **交互:** 当 JavaScript 代码操作 HTML 中与日期和时间相关的元素 (如 `<input type="date">`, `<input type="time">`, `<input type="datetime-local">`, `<input type="month">`, `<input type="week">`) 时，Blink 引擎会使用 `date_components.cc` 中的代码来解析和处理用户输入或 JavaScript 设置的值。
    - **类型转换:** JavaScript 的 `Date` 对象内部使用自 Epoch (1970 年 1 月 1 日 UTC) 以来的毫秒数来表示日期和时间。`date_components.cc` 中的函数负责在 JavaScript 的 `Date` 对象和 Blink 内部的日期时间表示之间进行转换。例如，当 JavaScript 获取 HTML 输入元素的值时，`date_components.cc` 会解析字符串并可能将其转换为毫秒数传递给 JavaScript。反之，当 JavaScript 设置输入元素的值时，可能需要将毫秒数转换回字符串。
    - **举例:**
        ```html
        <input type="date" id="myDate">
        <script>
          const dateInput = document.getElementById('myDate');
          dateInput.value = '2023-10-27'; // JavaScript 设置值
          console.log(dateInput.value); // JavaScript 获取值
        </script>
        ```
        在这个例子中，当 JavaScript 设置 `dateInput.value` 时，Blink 会调用 `date_components.cc` 中的解析函数来验证 '2023-10-27' 是否为有效的日期格式。当 JavaScript 获取 `dateInput.value` 时，Blink 可能会使用 `date_components.cc` 中的格式化函数将内部表示转换回字符串。

* **HTML:**
    - **表单输入类型:**  HTML5 引入了多种日期和时间相关的输入类型，例如 `date`, `time`, `datetime-local`, `month`, `week`。`date_components.cc` 中的代码直接服务于这些输入类型的解析和验证。
    - **约束验证:** HTML 输入元素可以设置 `min` 和 `max` 属性来约束允许的日期和时间范围。`date_components.cc` 中的验证逻辑会考虑这些约束。
    - **举例:**
        ```html
        <input type="date" min="2023-01-01" max="2023-12-31">
        ```
        当用户在这个输入框中输入日期时，`date_components.cc` 会检查输入的日期是否在 2023-01-01 和 2023-12-31 之间。

* **CSS:**
    - **间接影响:** 虽然 `date_components.cc` 本身不直接处理 CSS，但 CSS 可以用于样式化日期和时间输入元素。浏览器如何呈现这些元素，包括错误状态 (例如，当输入无效日期时)，可能部分受到 `date_components.cc` 中验证结果的影响。
    - **选择器 (Indirectly):** 某些 CSS 选择器可能基于输入元素的有效性状态进行样式化，而输入元素的有效性又是由 Blink 的验证逻辑 (包括 `date_components.cc`) 决定的。

**逻辑推理示例:**

**假设输入:** 一个字符串 "2024-03-15" 作为 `<input type="date">` 元素的值。

**逻辑推理过程:**

1. **Blink 接收输入字符串:** 当用户在日期输入框中输入 "2024-03-15" 后，这个字符串会被传递给 Blink 引擎。
2. **调用解析函数:** Blink 会调用 `DateComponents::ParseDate` 函数来解析这个字符串。
3. **年份解析:** `ParseDate` 内部会先调用 `ParseYear`，提取 "2024"，并验证其是否在允许的年份范围内。
4. **月份解析:** 接着解析 "-" 字符，然后调用 `ToInt` 解析 "03" 为月份，并减 1 得到内部表示的月份 2 (0-based)。会检查月份是否在 0-11 之间，并调用 `WithinHTMLDateLimits` 检查年份和月份的组合是否有效。
5. **日期解析:** 再次解析 "-" 字符，然后调用 `ToInt` 解析 "15" 为日期。
6. **日期有效性检查:** 调用 `MaxDayOfMonth(2024, 2)` 计算 2024 年 3 月的最大天数 (31)，并检查 15 是否在这个范围内。由于 2024 是闰年，2 月有 29 天，所以 3 月最大天数为 31。还会调用 `WithinHTMLDateLimits` 检查年份、月份和日期的组合是否有效。
7. **内部表示:** 如果所有解析和验证都通过，日期组件会被存储在 `DateComponents` 对象的相应成员变量中 (`year_ = 2024`, `month_ = 2`, `month_day_ = 15`, `type_ = kDate`).

**假设输出:** 如果解析成功，`ParseDate` 函数返回 `true`，并且 `end` 参数会指示解析结束的位置。

**常见使用错误示例:**

* **用户错误 (HTML 表单):**
    - **输入无效日期格式:** 用户在 `<input type="date">` 中输入 "2023/10/27" (使用了斜杠而不是连字符)，这不符合 ISO 8601 格式，`ParseDate` 会返回 `false`，导致表单验证失败。
    - **输入超出范围的日期:** 用户在 `<input type="date" min="2023-01-01" max="2023-12-31">` 中输入 "2024-01-01"，`WithinHTMLDateLimits` 会检测到日期超出允许范围，导致验证失败。
    - **输入无效的月份或日期:** 用户输入 "2023-13-01" 或 "2023-02-30"，这些月份或日期在逻辑上不存在，会被相应的验证逻辑捕获。

* **编程错误 (JavaScript):**
    - **错误地格式化日期字符串传递给 HTML 输入元素:**  JavaScript 代码尝试设置 `<input type="date">` 的值为一个不符合 "YYYY-MM-DD" 格式的字符串，例如 `"October 27, 2023"`，Blink 的解析器无法识别，导致设置失败或行为不符合预期。
    - **假设所有月份都有 30 天:**  开发者在 JavaScript 中手动处理日期逻辑时，如果错误地假设所有月份都有 30 天，可能会导致与 `date_components.cc` 中精确的日期计算不一致，尤其是在跨月或处理闰年时。

总而言之，`blink/renderer/platform/text/date_components.cc` 是 Blink 引擎中处理日期和时间的核心模块，它确保了浏览器能够正确地理解和操作与日期和时间相关的数据，并与 JavaScript 和 HTML 的相关特性紧密配合。

### 提示词
```
这是目录为blink/renderer/platform/text/date_components.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/text/date_components.h"

#include <limits.h>
#include "base/notreached.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/ascii_ctype.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

// HTML5 specification defines minimum week of year is one.
const int DateComponents::kMinimumWeekNumber = 1;

// HTML5 specification defines maximum week of year is 53.
const int DateComponents::kMaximumWeekNumber = 53;

// This is September, since months are 0 based.
static const int kMaximumMonthInMaximumYear = 8;
static const int kMaximumDayInMaximumMonth = 13;
static const int kMaximumWeekInMaximumYear = 37;  // The week of 275760-09-13

static const int kDaysInMonth[12] = {31, 28, 31, 30, 31, 30,
                                     31, 31, 30, 31, 30, 31};

// 'month' is 0-based.
static int MaxDayOfMonth(int year, int month) {
  if (month != 1)  // February?
    return kDaysInMonth[month];
  return IsLeapYear(year) ? 29 : 28;
}

// 'month' is 0-based.
static int DayOfWeek(int year, int month, int day) {
  int shifted_month = month + 2;
  // 2:January, 3:Feburuary, 4:March, ...

  // Zeller's congruence
  if (shifted_month <= 3) {
    shifted_month += 12;
    year--;
  }
  // 4:March, ..., 14:January, 15:February

  int high_year = year / 100;
  int low_year = year % 100;
  // We add 6 to make the result Sunday-origin.
  int result = (day + 13 * shifted_month / 5 + low_year + low_year / 4 +
                high_year / 4 + 5 * high_year + 6) %
               7;
  return result;
}

int DateComponents::WeekDay() const {
  return DayOfWeek(year_, month_, month_day_);
}

int DateComponents::MaxWeekNumberInYear() const {
  int day = DayOfWeek(year_, 0, 1);  // January 1.
  return day == kThursday || (day == kWednesday && IsLeapYear(year_))
             ? kMaximumWeekNumber
             : kMaximumWeekNumber - 1;
}

static unsigned CountDigits(const String& src, unsigned start) {
  unsigned index = start;
  for (; index < src.length(); ++index) {
    if (!IsASCIIDigit(src[index]))
      break;
  }
  return index - start;
}

// Very strict integer parser. Do not allow leading or trailing whitespace
// unlike charactersToIntStrict().
static bool ToInt(const String& src,
                  unsigned parse_start,
                  unsigned parse_length,
                  int& out) {
  if (parse_start + parse_length > src.length() || !parse_length)
    return false;
  int value = 0;
  unsigned current = parse_start;
  unsigned end = current + parse_length;

  // We don't need to handle negative numbers for ISO 8601.
  for (; current < end; ++current) {
    if (!IsASCIIDigit(src[current]))
      return false;
    int digit = src[current] - '0';
    if (value > (INT_MAX - digit) / 10)  // Check for overflow.
      return false;
    value = value * 10 + digit;
  }
  out = value;
  return true;
}

bool DateComponents::ParseYear(const String& src,
                               unsigned start,
                               unsigned& end) {
  unsigned digits_length = CountDigits(src, start);
  // Needs at least 4 digits according to the standard.
  if (digits_length < 4)
    return false;
  int year;
  if (!ToInt(src, start, digits_length, year))
    return false;
  if (year < MinimumYear() || year > MaximumYear())
    return false;
  year_ = year;
  end = start + digits_length;
  return true;
}

static bool WithinHTMLDateLimits(int year, int month) {
  if (year < DateComponents::MinimumYear())
    return false;
  if (year < DateComponents::MaximumYear())
    return true;
  return month <= kMaximumMonthInMaximumYear;
}

static bool WithinHTMLDateLimits(int year, int month, int month_day) {
  if (year < DateComponents::MinimumYear())
    return false;
  if (year < DateComponents::MaximumYear())
    return true;
  if (month < kMaximumMonthInMaximumYear)
    return true;
  return month_day <= kMaximumDayInMaximumMonth;
}

static bool WithinHTMLDateLimits(int year,
                                 int month,
                                 int month_day,
                                 int hour,
                                 int minute,
                                 int second,
                                 int millisecond) {
  if (year < DateComponents::MinimumYear())
    return false;
  if (year < DateComponents::MaximumYear())
    return true;
  if (month < kMaximumMonthInMaximumYear)
    return true;
  if (month_day < kMaximumDayInMaximumMonth)
    return true;
  if (month_day > kMaximumDayInMaximumMonth)
    return false;
  // (year, month, monthDay) =
  // (MaximumYear, kMaximumMonthInMaximumYear, kMaximumDayInMaximumMonth)
  return !hour && !minute && !second && !millisecond;
}

bool DateComponents::ParseMonth(const String& src,
                                unsigned start,
                                unsigned& end) {
  unsigned index;
  if (!ParseYear(src, start, index))
    return false;
  if (index >= src.length() || src[index] != '-')
    return false;
  ++index;

  int month;
  if (!ToInt(src, index, 2, month) || month < 1 || month > 12)
    return false;
  --month;
  if (!WithinHTMLDateLimits(year_, month))
    return false;
  month_ = month;
  end = index + 2;
  type_ = kMonth;
  return true;
}

bool DateComponents::ParseDate(const String& src,
                               unsigned start,
                               unsigned& end) {
  unsigned index;
  if (!ParseMonth(src, start, index))
    return false;
  // '-' and 2-digits are needed.
  if (index + 2 >= src.length())
    return false;
  if (src[index] != '-')
    return false;
  ++index;

  int day;
  if (!ToInt(src, index, 2, day) || day < 1 ||
      day > MaxDayOfMonth(year_, month_))
    return false;
  if (!WithinHTMLDateLimits(year_, month_, day))
    return false;
  month_day_ = day;
  end = index + 2;
  type_ = kDate;
  return true;
}

bool DateComponents::ParseWeek(const String& src,
                               unsigned start,
                               unsigned& end) {
  unsigned index;
  if (!ParseYear(src, start, index))
    return false;

  // 4 characters ('-' 'W' digit digit) are needed.
  if (index + 3 >= src.length())
    return false;
  if (src[index] != '-')
    return false;
  ++index;
  if (src[index] != 'W')
    return false;
  ++index;

  int week;
  if (!ToInt(src, index, 2, week) || week < kMinimumWeekNumber ||
      week > MaxWeekNumberInYear())
    return false;
  if (year_ == MaximumYear() && week > kMaximumWeekInMaximumYear)
    return false;
  week_ = week;
  end = index + 2;
  type_ = kWeek;
  return true;
}

bool DateComponents::ParseTime(const String& src,
                               unsigned start,
                               unsigned& end) {
  int hour;
  if (!ToInt(src, start, 2, hour) || hour < 0 || hour > 23)
    return false;
  unsigned index = start + 2;
  if (index >= src.length())
    return false;
  if (src[index] != ':')
    return false;
  ++index;

  int minute;
  if (!ToInt(src, index, 2, minute) || minute < 0 || minute > 59)
    return false;
  index += 2;

  int second = 0;
  int millisecond = 0;
  // Optional second part.
  // Do not return with false because the part is optional.
  if (index + 2 < src.length() && src[index] == ':') {
    if (ToInt(src, index + 1, 2, second) && second >= 0 && second <= 59) {
      index += 3;

      // Optional fractional second part.
      if (index < src.length() && src[index] == '.') {
        unsigned digits_length = CountDigits(src, index + 1);
        if (digits_length > 0) {
          ++index;
          bool ok;
          if (digits_length == 1) {
            ok = ToInt(src, index, 1, millisecond);
            millisecond *= 100;
          } else if (digits_length == 2) {
            ok = ToInt(src, index, 2, millisecond);
            millisecond *= 10;
          } else if (digits_length == 3) {
            ok = ToInt(src, index, 3, millisecond);
          } else {  // digits_length >= 4
            return false;
          }
          DCHECK(ok);
          index += digits_length;
        }
      }
    }
  }
  hour_ = hour;
  minute_ = minute;
  second_ = second;
  millisecond_ = millisecond;
  end = index;
  type_ = kTime;
  return true;
}

bool DateComponents::ParseDateTimeLocal(const String& src,
                                        unsigned start,
                                        unsigned& end) {
  unsigned index;
  if (!ParseDate(src, start, index))
    return false;
  if (index >= src.length())
    return false;
  if (src[index] != 'T' && src[index] != ' ')
    return false;
  ++index;
  if (!ParseTime(src, index, end))
    return false;
  if (!WithinHTMLDateLimits(year_, month_, month_day_, hour_, minute_, second_,
                            millisecond_))
    return false;
  type_ = kDateTimeLocal;
  return true;
}

static inline double PositiveFmod(double value, double divider) {
  double remainder = fmod(value, divider);
  return remainder < 0 ? remainder + divider : remainder;
}

void DateComponents::SetMillisecondsSinceMidnightInternal(double ms_in_day) {
  DCHECK_GE(ms_in_day, 0);
  DCHECK_LT(ms_in_day, kMsPerDay);
  millisecond_ = static_cast<int>(fmod(ms_in_day, kMsPerSecond));
  double value = std::floor(ms_in_day / kMsPerSecond);
  second_ = static_cast<int>(fmod(value, kSecondsPerMinute));
  value = std::floor(value / kSecondsPerMinute);
  minute_ = static_cast<int>(fmod(value, kMinutesPerHour));
  hour_ = static_cast<int>(value / kMinutesPerHour);
}

bool DateComponents::SetMillisecondsSinceEpochForDateInternal(double ms) {
  year_ = MsToYear(ms);
  int year_day = DayInYear(ms, year_);
  month_ = MonthFromDayInYear(year_day, IsLeapYear(year_));
  month_day_ = DayInMonthFromDayInYear(year_day, IsLeapYear(year_));
  return true;
}

bool DateComponents::SetMillisecondsSinceEpochForDate(double ms) {
  type_ = kInvalid;
  if (!std::isfinite(ms))
    return false;
  if (!SetMillisecondsSinceEpochForDateInternal(round(ms)))
    return false;
  if (!WithinHTMLDateLimits(year_, month_, month_day_))
    return false;
  type_ = kDate;
  return true;
}

bool DateComponents::SetMillisecondsSinceEpochForDateTimeLocal(double ms) {
  type_ = kInvalid;
  if (!std::isfinite(ms))
    return false;
  ms = round(ms);
  SetMillisecondsSinceMidnightInternal(PositiveFmod(ms, kMsPerDay));
  if (!SetMillisecondsSinceEpochForDateInternal(ms))
    return false;
  if (!WithinHTMLDateLimits(year_, month_, month_day_, hour_, minute_, second_,
                            millisecond_))
    return false;
  type_ = kDateTimeLocal;
  return true;
}

bool DateComponents::SetMillisecondsSinceEpochForMonth(double ms) {
  type_ = kInvalid;
  if (!std::isfinite(ms))
    return false;
  if (!SetMillisecondsSinceEpochForDateInternal(round(ms)))
    return false;
  if (!WithinHTMLDateLimits(year_, month_))
    return false;
  type_ = kMonth;
  return true;
}

bool DateComponents::SetMillisecondsSinceMidnight(double ms) {
  type_ = kInvalid;
  if (!std::isfinite(ms))
    return false;
  SetMillisecondsSinceMidnightInternal(PositiveFmod(round(ms), kMsPerDay));
  type_ = kTime;
  return true;
}

bool DateComponents::SetMonthsSinceEpoch(double months) {
  if (!std::isfinite(months))
    return false;
  months = round(months);
  double double_month = PositiveFmod(months, 12);
  double double_year = 1970 + (months - double_month) / 12;
  if (double_year < MinimumYear() || MaximumYear() < double_year)
    return false;
  int year = static_cast<int>(double_year);
  int month = static_cast<int>(double_month);
  if (!WithinHTMLDateLimits(year, month))
    return false;
  year_ = year;
  month_ = month;
  type_ = kMonth;
  return true;
}

// Offset from January 1st to Monday of the ISO 8601's first week.
//   ex. If January 1st is Friday, such Monday is 3 days later. Returns 3.
static int OffsetTo1stWeekStart(int year) {
  int offset_to1st_week_start = 1 - DayOfWeek(year, 0, 1);
  if (offset_to1st_week_start <= -4)
    offset_to1st_week_start += 7;
  return offset_to1st_week_start;
}

bool DateComponents::SetMillisecondsSinceEpochForWeek(double ms) {
  type_ = kInvalid;
  if (!std::isfinite(ms))
    return false;
  ms = round(ms);

  year_ = MsToYear(ms);
  if (year_ < MinimumYear() || year_ > MaximumYear())
    return false;

  int year_day = DayInYear(ms, year_);
  int offset = OffsetTo1stWeekStart(year_);
  if (year_day < offset) {
    // The day belongs to the last week of the previous year.
    year_--;
    if (year_ <= MinimumYear())
      return false;
    week_ = MaxWeekNumberInYear();
  } else {
    week_ = ((year_day - offset) / 7) + 1;
    if (week_ > MaxWeekNumberInYear()) {
      year_++;
      week_ = 1;
    }
    if (year_ > MaximumYear() ||
        (year_ == MaximumYear() && week_ > kMaximumWeekInMaximumYear))
      return false;
  }
  type_ = kWeek;
  return true;
}

bool DateComponents::SetWeek(int year, int week_number) {
  type_ = kInvalid;
  if (year < MinimumYear() || year > MaximumYear())
    return false;
  year_ = year;
  if (week_number < 1 || week_number > MaxWeekNumberInYear())
    return false;
  week_ = week_number;
  type_ = kWeek;
  return true;
}

double DateComponents::MillisecondsSinceEpochForTime() const {
  DCHECK(type_ == kTime || type_ == kDateTimeLocal);
  return ((hour_ * kMinutesPerHour + minute_) * kSecondsPerMinute + second_) *
             kMsPerSecond +
         millisecond_;
}

double DateComponents::MillisecondsSinceEpoch() const {
  switch (type_) {
    case kDate:
      return DateToDaysFrom1970(year_, month_, month_day_) * kMsPerDay;
    case kDateTimeLocal:
      return DateToDaysFrom1970(year_, month_, month_day_) * kMsPerDay +
             MillisecondsSinceEpochForTime();
    case kMonth:
      return DateToDaysFrom1970(year_, month_, 1) * kMsPerDay;
    case kTime:
      return MillisecondsSinceEpochForTime();
    case kWeek:
      return (DateToDaysFrom1970(year_, 0, 1) + OffsetTo1stWeekStart(year_) +
              (week_ - 1) * 7) *
             kMsPerDay;
    case kInvalid:
      break;
  }
  NOTREACHED();
}

double DateComponents::MonthsSinceEpoch() const {
  DCHECK_EQ(type_, kMonth);
  return (year_ - 1970) * 12 + month_;
}

String DateComponents::ToStringForTime(SecondFormat format) const {
  DCHECK(type_ == kDateTimeLocal || type_ == kTime);
  SecondFormat effective_format = format;
  if (millisecond_)
    effective_format = SecondFormat::kMillisecond;
  else if (format == SecondFormat::kNone && second_)
    effective_format = SecondFormat::kSecond;

  switch (effective_format) {
    case SecondFormat::kNone:
      return String::Format("%02d:%02d", hour_, minute_);
    case SecondFormat::kSecond:
      return String::Format("%02d:%02d:%02d", hour_, minute_, second_);
    case SecondFormat::kMillisecond:
      return String::Format("%02d:%02d:%02d.%03d", hour_, minute_, second_,
                            millisecond_);
    default:
      NOTREACHED();
  }
}

String DateComponents::ToString(SecondFormat format) const {
  switch (type_) {
    case kDate:
      return String::Format("%04d-%02d-%02d", year_, month_ + 1, month_day_);
    case kDateTimeLocal:
      return String::Format("%04d-%02d-%02dT", year_, month_ + 1, month_day_) +
             ToStringForTime(format);
    case kMonth:
      return String::Format("%04d-%02d", year_, month_ + 1);
    case kTime:
      return ToStringForTime(format);
    case kWeek:
      return String::Format("%04d-W%02d", year_, week_);
    case kInvalid:
      break;
  }
  NOTREACHED();
}

}  // namespace blink
```