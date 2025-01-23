Response:
Let's break down the thought process for analyzing this V8 C++ code snippet.

1. **Initial Scan and Goal Identification:**

   - The first line, `// Copyright 2021 the V8 project authors. All rights reserved.`, immediately tells us this is V8 source code.
   - The `#include "src/temporal/temporal-parser.h"` is a crucial hint. The filename `temporal-parser.cc` combined with the include of a header file with a similar name strongly suggests this code is responsible for *parsing* temporal strings. "Temporal" likely relates to date and time concepts.

2. **High-Level Structure and Organization:**

   - The `namespace v8::internal { namespace { ... } }` structure is standard V8 for internal, non-exported code. This confirms it's an implementation detail.
   - The functions are primarily `Scan...` and some helper functions. This "Scan" prefix is a common pattern for parser components, suggesting a stateful or incremental parsing approach.

3. **Helper Function Analysis:**

   - Functions like `IsTZLeadingChar`, `IsTZChar`, `IsDecimalSeparator`, etc., clearly define character sets used in temporal string formats. This points to the code understanding different parts of a date/time string.
   - `CanonicalSign` shows handling of different minus sign representations.
   - `ToInt` converts a digit character to an integer.
   - The template functions `HasTwoDigits`, `ScanTwoDigitsExpectValue`, `ScanTwoDigitsExpectRange`, and `ScanTwoDigitsExpectZeroOrRange` are utility functions for simplifying the parsing of two-digit numbers with specific constraints. This is very common in date/time formats (months, days, hours, minutes, seconds).

4. **`Scan...` Function Pattern Recognition:**

   - The comments before the `ScanHour` function are key:
     - "The TemporalParser use two types of internal routine: Scan routines..."
     - The function signature `template <typename Char> int32_t Scan$ProductionName(base::Vector<Char> str, int32_t s, R* out)` is explicitly defined.
     - The return value is the length of the matched text or 0.
   - This confirms the hypothesis of a parsing mechanism. The `$ProductionName` placeholder suggests these functions correspond to grammar rules for temporal strings.

5. **Macro Usage (`SCAN_FORWARD`, `SCAN_EITHER_FORWARD`):**

   - These macros simplify the creation of `Scan` functions where one production directly calls another or where it chooses between two. This further reinforces the idea of a grammar-driven parser.

6. **Mapping to Temporal Concepts:**

   - Seeing `ScanHour`, `ScanMinuteSecond`, `ScanDateYear`, `ScanDateMonth`, `ScanDateDay`, `ScanTimeZoneUTCOffset`, etc., solidifies the code's purpose: parsing various components of date and time information.

7. **`ParsedISO8601Result` (Implicit):**

   -  The `R* out` or `ParsedISO8601Result* r` parameters in the `Scan` functions suggest a data structure where the parsed components are stored. The field names within the functions (e.g., `r->time_hour`, `r->date_year`) provide strong clues about the structure of this result object. It's likely designed to hold the individual pieces of a parsed ISO 8601 date/time string.

8. **ISO 8601 Focus:**

   - Many of the production names and the structure of the parsing functions closely align with the ISO 8601 standard for date and time representation. For example, `DateYear - DateMonth - DateDay` is a typical ISO 8601 date format.

9. **Considering Potential .tq Extension:**

   - The prompt mentions the `.tq` extension and Torque. Knowing that Torque is V8's domain-specific language for implementing built-in JavaScript features, the question is a bit of a distractor in this *specific* code. This code is clearly C++. However, it's important to note that *some* parsing logic within V8 might *involve* Torque for parts related to JavaScript API calls or built-in object creation. In this isolated snippet, there's no indication of Torque.

10. **JavaScript Relationship (Hypothesizing):**

    - Since it's a *parser* for temporal strings, it's very likely used when JavaScript code interacts with the `Temporal` API. This leads to the thought of examples like `Temporal.PlainDate.from()`, `Temporal.ZonedDateTime.from()`, etc., where the input string needs to be parsed.

11. **Code Logic Inference and Examples:**

    - By looking at the `ScanTwoDigitsExpectRange` calls within `ScanHour`, `ScanMinuteSecond`, etc., you can infer the allowed ranges for these components. This allows creating example inputs and the expected parsed outputs.

12. **Common Programming Errors:**

    - The parser is designed to handle specific formats. Common errors would be providing strings that deviate from those formats (e.g., invalid month numbers, wrong separators, missing components).

13. **Summarization:**

    - Finally, synthesize the observations into a concise summary of the code's functionality: parsing ISO 8601-like temporal strings into a structured representation for use within V8's `Temporal` API.

**Self-Correction/Refinement during the Thought Process:**

- **Initial thought:** "Is this a complete parser?"  No, it's a *part* of a parser. It focuses on the scanning and recognition of individual components. Higher-level logic would orchestrate these `Scan` functions.
- **Consideration of error handling:**  While the `Scan` functions return 0 on failure, the provided snippet doesn't show explicit error reporting or recovery mechanisms. This would likely exist at a higher level.
- **Re-evaluating the Torque question:** While this specific file is C++, acknowledge the possibility that other parts of the `Temporal` implementation might involve Torque. Don't make definitive statements beyond what the code shows.
好的，这是对 `v8/src/temporal/temporal-parser.cc` 代码片段的分析：

**功能归纳:**

这段 C++ 代码是 V8 JavaScript 引擎中用于解析符合 ISO 8601 扩展的日期和时间字符串的解析器的一部分。它定义了一系列 `Scan...` 函数，每个函数负责识别和提取日期时间字符串中的特定组成部分，例如年份、月份、日期、小时、分钟、秒、毫秒、时区偏移等等。

**详细功能分解:**

1. **定义字符类型判断函数:**
   - 代码开头定义了一系列 `inline constexpr bool Is...` 形式的函数，用于判断字符是否属于特定的字符集，例如 `IsTZLeadingChar` (时区名称的首字符), `IsDecimalSeparator` (小数点分隔符) 等。这些函数对应了 Temporal 规范中定义的词法单元。

2. **定义辅助解析函数:**
   - `ToInt`: 将字符转换为整数。
   - `HasTwoDigits`, `ScanTwoDigitsExpectValue`, `ScanTwoDigitsExpectRange`, `ScanTwoDigitsExpectZeroOrRange`: 这些模板函数简化了两位数字的扫描和验证，例如月份、日期、小时等。

3. **定义 `Scan...` 解析函数:**
   - 这部分是代码的核心。每个 `Scan...` 函数都尝试从给定的字符串的指定位置开始匹配一个特定的语法产生式 (production)。
   - 函数命名遵循 `Scan` + 产生式名称的模式，例如 `ScanHour`, `ScanMinuteSecond`, `ScanDate`, `ScanTimeZoneUTCOffset` 等。
   - 函数接收字符串 (`str`)、起始位置 (`s`) 和一个用于存储解析结果的结构体指针 (`out` 或 `r`) 作为参数。
   - 如果匹配成功，函数返回匹配的字符长度；否则返回 0。
   - 使用了宏 `SCAN_FORWARD` 和 `SCAN_EITHER_FORWARD` 来简化一些简单的产生式的定义。

4. **解析 ISO 8601 的各个组成部分:**
   - 代码涵盖了 ISO 8601 中日期、时间、时区偏移、时区名称、日历等多个组成部分的解析。
   - 例如：
     - `ScanHour` 解析小时。
     - `ScanDate` 解析日期 (年-月-日 或 年月日)。
     - `ScanTimeSpec` 解析时间 (时:分:秒.毫秒 或 时分秒毫秒)。
     - `ScanTimeZoneUTCOffset` 解析 UTC 偏移 (+/-HH:MM 或 Z)。
     - `ScanTimeZoneIANAName` 解析 IANA 时区名称 (例如 "America/New_York")。

5. **结构体 `ParsedISO8601Result` (推断):**
   - 虽然代码中没有显式定义 `ParsedISO8601Result` 结构体，但从 `Scan` 函数的使用方式可以看出，这个结构体用于存储解析出的日期和时间组件。它可能包含类似 `date_year`, `date_month`, `time_hour`, `time_minute`, `tzuo_sign` (时区偏移符号) 等字段。

**关于 .tq 扩展和 JavaScript 关系:**

- **`.tq` 扩展:**  如果 `v8/src/temporal/temporal-parser.cc` 以 `.tq` 结尾，那么它确实是 V8 的 Torque 源代码。 Torque 是一种用于实现 V8 内置功能的领域特定语言。 然而，根据您提供的代码片段，该文件名为 `.cc`，所以它是标准的 C++ 源代码。
- **JavaScript 关系:**  `v8/src/temporal/temporal-parser.cc` 与 JavaScript 的 `Temporal` API (实验性的日期和时间 API) 有着直接的关系。 当 JavaScript 代码中使用 `Temporal` API 解析日期和时间字符串时，V8 引擎会调用这里的 C++ 代码来进行底层的解析工作。

**JavaScript 示例:**

```javascript
const temporal = require('@js-temporal/polyfill'); // 或者使用浏览器内置的 Temporal

// 解析一个 ISO 8601 格式的日期时间字符串
const plainDateTime = temporal.PlainDateTime.from('2023-10-27T10:30:00');
console.log(plainDateTime.year);   // 输出: 2023
console.log(plainDateTime.month);  // 输出: 10
console.log(plainDateTime.day);    // 输出: 27
console.log(plainDateTime.hour);   // 输出: 10
console.log(plainDateTime.minute); // 输出: 30
console.log(plainDateTime.second); // 输出: 0

// 解析带时区偏移的日期时间字符串
const zonedDateTime = temporal.ZonedDateTime.from('2023-10-27T10:30:00-05:00[America/New_York]');
console.log(zonedDateTime.timeZone.id); // 输出: America/New_York

// 解析只包含日期的字符串
const plainDate = temporal.PlainDate.from('2023-11-15');
console.log(plainDate.month); // 输出: 11
```

当 `Temporal.PlainDateTime.from()`, `Temporal.ZonedDateTime.from()`, `Temporal.PlainDate.from()` 等方法被调用时，V8 内部会使用 `temporal-parser.cc` 中的代码来分析输入的字符串，提取年、月、日、时、分、秒、时区等信息，并创建相应的 `Temporal` 对象。

**代码逻辑推理和假设输入/输出:**

假设输入字符串为 `"2023-11-15T14:05:30.123Z"`

1. **`ScanDate`:** 会匹配 `"2023-11-15"`，并提取 `date_year = 2023`, `date_month = 11`, `date_day = 15`。
2. **`ScanTimeSpecSeparator`:** 会匹配 `"T"`。
3. **`ScanTimeSpec`:** 会匹配 `"14:05:30.123"`，并提取 `time_hour = 14`, `time_minute = 5`, `time_second = 30`, `time_nanosecond = 123000000` (假设 `ScanFractionalPart` 会进行单位转换)。
4. **`ScanTimeZone`:** 会匹配 `"Z"`，并设置 `utc_designator = true`。

**假设输入:** `"20240101"`
**预期输出:**
- `ScanDateFourDigitYear` 匹配 `"2024"`, `date_year = 2024`
- 紧接着 `ScanDateMonth` 匹配 `"01"`, `date_month = 1`
- 紧接着 `ScanDateDay` 匹配 `"01"`, `date_day = 1`
- `ScanDate` 返回匹配长度 8

**用户常见的编程错误:**

1. **日期格式不正确:**
   ```javascript
   // 错误：月份和日期顺序错误
   // Temporal.PlainDate.from('2023/27/10'); // 这将导致解析错误
   ```
   `temporal-parser.cc` 中的代码会期望特定的分隔符 (`-`) 和顺序 (年-月-日)。

2. **时间格式不正确:**
   ```javascript
   // 错误：缺少秒
   // Temporal.PlainTime.from('10:30'); // 这可能被认为是合法的，取决于具体的方法和默认值
   // 错误：使用了不合法的分隔符
   // Temporal.PlainTime.from('10-30-00'); // 这将导致解析错误
   ```
   代码期望使用 `:` 分隔小时、分钟和秒。

3. **时区格式不正确:**
   ```javascript
   // 错误：时区偏移格式错误
   // Temporal.ZonedDateTime.from('2023-10-27T10:30:00+05'); // 缺少分钟部分
   // 错误：IANA 时区名称拼写错误
   // Temporal.ZonedDateTime.from('2023-10-27T10:30:00[America/NewYork]'); // 缺少下划线
   ```
   `ScanTimeZoneUTCOffset` 和 `ScanTimeZoneIANAName` 会严格按照定义的格式进行匹配。

4. **使用了不存在的日期:**
   ```javascript
   // 错误：2月份没有 30 号
   // Temporal.PlainDate.from('2023-02-30'); // 这将导致 RangeError
   ```
   虽然解析器可能能够提取年、月、日，但在后续的验证阶段会检查日期的有效性。

**总结:**

`v8/src/temporal/temporal-parser.cc` (第一部分) 的主要功能是定义了一组底层的 C++ 函数，用于扫描和解析符合特定规则的日期和时间字符串的各个组成部分。这些函数是 V8 引擎实现 `Temporal` API 的关键部分，使得 JavaScript 能够理解和操作日期和时间数据。它通过一系列的 `Scan...` 函数，按照预定义的语法规则，从字符串中提取出年、月、日、时、分、秒、时区等信息。

### 提示词
```
这是目录为v8/src/temporal/temporal-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/temporal/temporal-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/temporal/temporal-parser.h"

#include <optional>

#include "src/base/bounds.h"
#include "src/objects/string-inl.h"
#include "src/strings/char-predicates-inl.h"

namespace v8::internal {

namespace {

// Temporal #prod-TZLeadingChar
inline constexpr bool IsTZLeadingChar(base::uc32 c) {
  return base::IsInRange(AsciiAlphaToLower(c), 'a', 'z') || c == '.' ||
         c == '_';
}

// Temporal #prod-TZChar
inline constexpr bool IsTZChar(base::uc32 c) {
  return IsTZLeadingChar(c) || c == '-';
}

// Temporal #prod-DecimalSeparator
inline constexpr bool IsDecimalSeparator(base::uc32 c) {
  return c == '.' || c == ',';
}

// Temporal #prod-DateTimeSeparator
inline constexpr bool IsDateTimeSeparator(base::uc32 c) {
  return c == ' ' || AsciiAlphaToLower(c) == 't';
}

// Temporal #prod-ASCIISign
inline constexpr bool IsAsciiSign(base::uc32 c) { return c == '-' || c == '+'; }

// Temporal #prod-Sign
inline constexpr bool IsSign(base::uc32 c) {
  return c == 0x2212 || IsAsciiSign(c);
}

// Temporal #prod-TimeZoneUTCOffsetSign
inline constexpr bool IsTimeZoneUTCOffsetSign(base::uc32 c) {
  return IsSign(c);
}

inline constexpr base::uc32 CanonicalSign(base::uc32 c) {
  return c == 0x2212 ? '-' : c;
}

inline constexpr int32_t ToInt(base::uc32 c) { return c - '0'; }

// A helper template to make the scanning of production w/ two digits simpler.
template <typename Char>
bool HasTwoDigits(base::Vector<Char> str, int32_t s, int32_t* out) {
  if (str.length() >= (s + 2) && IsDecimalDigit(str[s]) &&
      IsDecimalDigit(str[s + 1])) {
    *out = ToInt(str[s]) * 10 + ToInt(str[s + 1]);
    return true;
  }
  return false;
}

// A helper template to make the scanning of production w/ a single two digits
// value simpler.
template <typename Char>
int32_t ScanTwoDigitsExpectValue(base::Vector<Char> str, int32_t s,
                                 int32_t expected, int32_t* out) {
  return HasTwoDigits<Char>(str, s, out) && (*out == expected) ? 2 : 0;
}

// A helper template to make the scanning of production w/ two digits value in a
// range simpler.
template <typename Char>
int32_t ScanTwoDigitsExpectRange(base::Vector<Char> str, int32_t s, int32_t min,
                                 int32_t max, int32_t* out) {
  return HasTwoDigits<Char>(str, s, out) && base::IsInRange(*out, min, max) ? 2
                                                                            : 0;
}

// A helper template to make the scanning of production w/ two digits value as 0
// or in a range simpler.
template <typename Char>
int32_t ScanTwoDigitsExpectZeroOrRange(base::Vector<Char> str, int32_t s,
                                       int32_t min, int32_t max, int32_t* out) {
  return HasTwoDigits<Char>(str, s, out) &&
                 (*out == 0 || base::IsInRange(*out, min, max))
             ? 2
             : 0;
}

/**
 * The TemporalParser use two types of internal routine:
 * - Scan routines: Follow the function signature below:
 *   template <typename Char> int32_t Scan$ProductionName(
 *   base::Vector<Char> str, int32_t s, R* out)
 *
 *   These routine scan the next item from position s in str and store the
 *   parsed result into out if the expected string is successfully scanned.
 *   It return the length of matched text from s or 0 to indicate no
 *   expected item matched.
 *
 * - Satisfy routines: Follow the function sigature below:
 *   template <typename Char>
 *   bool Satisfy$ProductionName(base::Vector<Char> str, R* r);
 *   It scan from the beginning of the str by calling Scan routines to put
 *   parsed result into r and return true if the entire str satisfy the
 *   production. It internally use Scan routines.
 *
 * TODO(ftang) investigate refactoring to class before shipping
 * Reference to RegExpParserImpl by encapsulating the cursor position and
 * only manipulating the current character and position with Next(),
 * Advance(), current(), etc
 */

// For Hour Production
// Hour:
//   [0 1] Digit
//   2 [0 1 2 3]
template <typename Char>
int32_t ScanHour(base::Vector<Char> str, int32_t s, int32_t* out) {
  return ScanTwoDigitsExpectRange<Char>(str, s, 0, 23, out);
}

// UnpaddedHour :
//   DecimalDigit
//   1 DecimalDigit
//   20
//   21
//   22
//   23
template <typename Char>
int32_t ScanUnpaddedHour(base::Vector<Char> str, int32_t s) {
  int32_t dummy;
  int32_t len = ScanTwoDigitsExpectRange<Char>(str, s, 10, 23, &dummy);
  if (len > 0) return len;
  if (str.length() >= (s + 1) && IsDecimalDigit(str[s])) return 1;
  return 0;
}

// MinuteSecond:
//   [0 1 2 3 4 5] Digit
template <typename Char>
int32_t ScanMinuteSecond(base::Vector<Char> str, int32_t s, int32_t* out) {
  return ScanTwoDigitsExpectRange<Char>(str, s, 0, 59, out);
}

// For the forward production in the grammar such as
// ProductionB:
//   ProductionT
#define SCAN_FORWARD(B, T, R)                                \
  template <typename Char>                                   \
  int32_t Scan##B(base::Vector<Char> str, int32_t s, R* r) { \
    return Scan##T(str, s, r);                               \
  }

// Same as above but store the result into a particular field in R

// For the forward production in the grammar such as
// ProductionB:
//   ProductionT1
//   ProductionT2
#define SCAN_EITHER_FORWARD(B, T1, T2, R)                    \
  template <typename Char>                                   \
  int32_t Scan##B(base::Vector<Char> str, int32_t s, R* r) { \
    int32_t len;                                             \
    if ((len = Scan##T1(str, s, r)) > 0) return len;         \
    return Scan##T2(str, s, r);                              \
  }

// TimeHour: Hour
SCAN_FORWARD(TimeHour, Hour, int32_t)

// TimeMinute: MinuteSecond
SCAN_FORWARD(TimeMinute, MinuteSecond, int32_t)

// TimeSecond:
//   MinuteSecond
//   60
template <typename Char>
int32_t ScanTimeSecond(base::Vector<Char> str, int32_t s, int32_t* out) {
  return ScanTwoDigitsExpectRange<Char>(str, s, 0, 60, out);
}

constexpr int kPowerOfTen[] = {1,      10,      100,      1000,     10000,
                               100000, 1000000, 10000000, 100000000};

// FractionalPart : Digit{1,9}
template <typename Char>
int32_t ScanFractionalPart(base::Vector<Char> str, int32_t s, int32_t* out) {
  int32_t cur = s;
  if ((str.length() < (cur + 1)) || !IsDecimalDigit(str[cur])) return 0;
  *out = ToInt(str[cur++]);
  while ((cur < str.length()) && ((cur - s) < 9) && IsDecimalDigit(str[cur])) {
    *out = 10 * (*out) + ToInt(str[cur++]);
  }
  *out *= kPowerOfTen[9 - (cur - s)];
  return cur - s;
}

// TimeFraction: FractionalPart
SCAN_FORWARD(TimeFractionalPart, FractionalPart, int32_t)

// Fraction: DecimalSeparator FractionalPart
// DecimalSeparator: one of , .
template <typename Char>
int32_t ScanFraction(base::Vector<Char> str, int32_t s, int32_t* out) {
  if ((str.length() < (s + 2)) || (!IsDecimalSeparator(str[s]))) return 0;
  int32_t len;
  if ((len = ScanFractionalPart(str, s + 1, out)) == 0) return 0;
  return len + 1;
}

// TimeFraction: DecimalSeparator TimeFractionalPart
// DecimalSeparator: one of , .
template <typename Char>
int32_t ScanTimeFraction(base::Vector<Char> str, int32_t s, int32_t* out) {
  if ((str.length() < (s + 2)) || (!IsDecimalSeparator(str[s]))) return 0;
  int32_t len;
  if ((len = ScanTimeFractionalPart(str, s + 1, out)) == 0) return 0;
  return len + 1;
}

template <typename Char>
int32_t ScanTimeFraction(base::Vector<Char> str, int32_t s,
                         ParsedISO8601Result* r) {
  return ScanTimeFraction(str, s, &(r->time_nanosecond));
}

// TimeSpec:
//  TimeHour
//  TimeHour : TimeMinute
//  TimeHour : TimeMinute : TimeSecond [TimeFraction]
//  TimeHour TimeMinute
//  TimeHour TimeMinute TimeSecond [TimeFraction]
template <typename Char>
int32_t ScanTimeSpec(base::Vector<Char> str, int32_t s,
                     ParsedISO8601Result* r) {
  int32_t time_hour, time_minute, time_second;
  int32_t len;
  int32_t cur = s;
  if ((len = ScanTimeHour(str, cur, &time_hour)) == 0) return 0;
  cur += len;
  if ((cur + 1) > str.length()) {
    // TimeHour
    r->time_hour = time_hour;
    return cur - s;
  }
  if (str[cur] == ':') {
    cur++;
    if ((len = ScanTimeMinute(str, cur, &time_minute)) == 0) return 0;
    cur += len;
    if ((cur + 1) > str.length() || (str[cur] != ':')) {
      // TimeHour : TimeMinute
      r->time_hour = time_hour;
      r->time_minute = time_minute;
      return cur - s;
    }
    cur++;
    if ((len = ScanTimeSecond(str, cur, &time_second)) == 0) return 0;
  } else {
    if ((len = ScanTimeMinute(str, cur, &time_minute)) == 0) {
      // TimeHour
      r->time_hour = time_hour;
      return cur - s;
    }
    cur += len;
    if ((len = ScanTimeSecond(str, cur, &time_second)) == 0) {
      // TimeHour TimeMinute
      r->time_hour = time_hour;
      r->time_minute = time_minute;
      return cur - s;
    }
  }
  cur += len;
  len = ScanTimeFraction(str, cur, r);
  r->time_hour = time_hour;
  r->time_minute = time_minute;
  r->time_second = time_second;
  cur += len;
  return cur - s;
}

// TimeSpecSeparator: DateTimeSeparator TimeSpec
// DateTimeSeparator: SPACE, 't', or 'T'
template <typename Char>
int32_t ScanTimeSpecSeparator(base::Vector<Char> str, int32_t s,
                              ParsedISO8601Result* r) {
  if (!(((s + 1) < str.length()) && IsDateTimeSeparator(str[s]))) return 0;
  int32_t len = ScanTimeSpec(str, s + 1, r);
  return (len == 0) ? 0 : len + 1;
}

// DateExtendedYear: Sign Digit Digit Digit Digit Digit Digit
template <typename Char>
int32_t ScanDateExtendedYear(base::Vector<Char> str, int32_t s, int32_t* out) {
  if (str.length() < (s + 7)) return 0;
  if (IsSign(str[s]) && IsDecimalDigit(str[s + 1]) &&
      IsDecimalDigit(str[s + 2]) && IsDecimalDigit(str[s + 3]) &&
      IsDecimalDigit(str[s + 4]) && IsDecimalDigit(str[s + 5]) &&
      IsDecimalDigit(str[s + 6])) {
    int32_t sign = (CanonicalSign(str[s]) == '-') ? -1 : 1;
    *out = sign * (ToInt(str[s + 1]) * 100000 + ToInt(str[s + 2]) * 10000 +
                   ToInt(str[s + 3]) * 1000 + ToInt(str[s + 4]) * 100 +
                   ToInt(str[s + 5]) * 10 + ToInt(str[s + 6]));
    // In the end of #sec-temporal-iso8601grammar
    // It is a Syntax Error if DateExtendedYear is "-000000" or "−000000"
    // (U+2212 MINUS SIGN followed by 000000).
    if (sign == -1 && *out == 0) return 0;
    return 7;
  }
  return 0;
}

// DateFourDigitYear: Digit Digit Digit Digit
template <typename Char>
int32_t ScanDateFourDigitYear(base::Vector<Char> str, int32_t s, int32_t* out) {
  if (str.length() < (s + 4)) return 0;
  if (IsDecimalDigit(str[s]) && IsDecimalDigit(str[s + 1]) &&
      IsDecimalDigit(str[s + 2]) && IsDecimalDigit(str[s + 3])) {
    *out = ToInt(str[s]) * 1000 + ToInt(str[s + 1]) * 100 +
           ToInt(str[s + 2]) * 10 + ToInt(str[s + 3]);
    return 4;
  }
  return 0;
}

// DateYear:
//   DateFourDigitYear
//   DateExtendedYear
// The lookahead is at most 1 char.
SCAN_EITHER_FORWARD(DateYear, DateFourDigitYear, DateExtendedYear, int32_t)

// DateMonth:
//   0 NonzeroDigit
//   10
//   11
//   12
template <typename Char>
int32_t ScanDateMonth(base::Vector<Char> str, int32_t s, int32_t* out) {
  return ScanTwoDigitsExpectRange<Char>(str, s, 1, 12, out);
}

// DateDay:
//   0 NonzeroDigit
//   1 Digit
//   2 Digit
//   30
//   31
template <typename Char>
int32_t ScanDateDay(base::Vector<Char> str, int32_t s, int32_t* out) {
  return ScanTwoDigitsExpectRange<Char>(str, s, 1, 31, out);
}

// Date:
//   DateYear - DateMonth - DateDay
//   DateYear DateMonth DateDay
template <typename Char>
int32_t ScanDate(base::Vector<Char> str, int32_t s, ParsedISO8601Result* r) {
  int32_t date_year, date_month, date_day;
  int32_t cur = s;
  int32_t len;
  if ((len = ScanDateYear(str, cur, &date_year)) == 0) return 0;
  if (((cur += len) + 1) > str.length()) return 0;
  if (str[cur] == '-') {
    cur++;
    if ((len = ScanDateMonth(str, cur, &date_month)) == 0) return 0;
    cur += len;
    if (((cur + 1) > str.length()) || (str[cur++] != '-')) return 0;
  } else {
    if ((len = ScanDateMonth(str, cur, &date_month)) == 0) return 0;
    cur += len;
  }
  if ((len = ScanDateDay(str, cur, &date_day)) == 0) return 0;
  r->date_year = date_year;
  r->date_month = date_month;
  r->date_day = date_day;
  return cur + len - s;
}

// DateMonthWithThirtyOneDays : one of
//    01 03 05 07 08 10 12
template <typename Char>
int32_t ScanDateMonthWithThirtyOneDays(base::Vector<Char> str, int32_t s) {
  int32_t value;
  if (!HasTwoDigits(str, s, &value)) return false;
  return value == 1 || value == 3 || value == 5 || value == 7 || value == 8 ||
         value == 10 || value == 12;
}

// TimeZoneUTCOffsetHour: Hour
SCAN_FORWARD(TimeZoneUTCOffsetHour, Hour, int32_t)

// TimeZoneUTCOffsetMinute
SCAN_FORWARD(TimeZoneUTCOffsetMinute, MinuteSecond, int32_t)

// TimeZoneUTCOffsetSecond
SCAN_FORWARD(TimeZoneUTCOffsetSecond, MinuteSecond, int32_t)

// TimeZoneUTCOffsetFractionalPart: FractionalPart
// See PR1796
SCAN_FORWARD(TimeZoneUTCOffsetFractionalPart, FractionalPart, int32_t)

// TimeZoneUTCOffsetFraction: DecimalSeparator TimeZoneUTCOffsetFractionalPart
// See PR1796
template <typename Char>
int32_t ScanTimeZoneUTCOffsetFraction(base::Vector<Char> str, int32_t s,
                                      int32_t* out) {
  if ((str.length() < (s + 2)) || (!IsDecimalSeparator(str[s]))) return 0;
  int32_t len;
  if ((len = ScanTimeZoneUTCOffsetFractionalPart(str, s + 1, out)) > 0) {
    return len + 1;
  }
  return 0;
}

// TimeZoneNumericUTCOffset:
//   TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour
//   TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour : TimeZoneUTCOffsetMinute
//   TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour TimeZoneUTCOffsetMinute
//   TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour : TimeZoneUTCOffsetMinute :
//   TimeZoneUTCOffsetSecond [TimeZoneUTCOffsetFraction] TimeZoneUTCOffsetSign
//   TimeZoneUTCOffsetHour TimeZoneUTCOffsetMinute TimeZoneUTCOffsetSecond
//   [TimeZoneUTCOffsetFraction]

template <typename Char>
int32_t ScanTimeZoneNumericUTCOffset(base::Vector<Char> str, int32_t s,
                                     ParsedISO8601Result* r) {
  int32_t len, hour, minute, second, nanosecond;
  int32_t cur = s;
  if ((str.length() < (cur + 1)) || (!IsTimeZoneUTCOffsetSign(str[cur]))) {
    return 0;
  }
  int32_t sign = (CanonicalSign(str[cur++]) == '-') ? -1 : 1;
  if ((len = ScanTimeZoneUTCOffsetHour(str, cur, &hour)) == 0) return 0;
  cur += len;
  if ((cur + 1) > str.length()) {
    //   TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour
    r->tzuo_sign = sign;
    r->tzuo_hour = hour;
    r->offset_string_start = s;
    r->offset_string_length = cur - s;
    return cur - s;
  }
  if (str[cur] == ':') {
    cur++;
    if ((len = ScanTimeZoneUTCOffsetMinute(str, cur, &minute)) == 0) return 0;
    cur += len;
    if ((cur + 1) > str.length() || str[cur] != ':') {
      //   TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour : TimeZoneUTCOffsetMinute
      r->tzuo_sign = sign;
      r->tzuo_hour = hour;
      r->tzuo_minute = minute;
      r->offset_string_start = s;
      r->offset_string_length = cur - s;
      return cur - s;
    }
    cur++;
    if ((len = ScanTimeZoneUTCOffsetSecond(str, cur, &second)) == 0) return 0;
  } else {
    if ((len = ScanTimeZoneUTCOffsetMinute(str, cur, &minute)) == 0) {
      //   TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour
      r->tzuo_sign = sign;
      r->tzuo_hour = hour;
      r->offset_string_start = s;
      r->offset_string_length = cur - s;
      return cur - s;
    }
    cur += len;
    if ((len = ScanTimeZoneUTCOffsetSecond(str, cur, &second)) == 0) {
      //   TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour TimeZoneUTCOffsetMinute
      r->tzuo_sign = sign;
      r->tzuo_hour = hour;
      r->tzuo_minute = minute;
      r->offset_string_start = s;
      r->offset_string_length = cur - s;
      return cur - s;
    }
  }
  cur += len;
  len = ScanTimeZoneUTCOffsetFraction(str, cur, &nanosecond);
  r->tzuo_sign = sign;
  r->tzuo_hour = hour;
  r->tzuo_minute = minute;
  r->tzuo_second = second;
  if (len > 0) r->tzuo_nanosecond = nanosecond;
  r->offset_string_start = s;
  r->offset_string_length = cur + len - s;
  cur += len;
  return cur - s;
}

// TimeZoneUTCOffset:
//   TimeZoneNumericUTCOffset
//   UTCDesignator
template <typename Char>
int32_t ScanTimeZoneUTCOffset(base::Vector<Char> str, int32_t s,
                              ParsedISO8601Result* r) {
  if (str.length() < (s + 1)) return 0;
  if (AsciiAlphaToLower(str[s]) == 'z') {
    // UTCDesignator
    r->utc_designator = true;
    return 1;
  }
  // TimeZoneNumericUTCOffset
  return ScanTimeZoneNumericUTCOffset(str, s, r);
}

// TimeZoneIANANameComponent :
//   TZLeadingChar TZChar{0,13} but not one of . or ..
template <typename Char>
int32_t ScanTimeZoneIANANameComponent(base::Vector<Char> str, int32_t s) {
  int32_t cur = s;
  if (str.length() < (cur + 1) || !IsTZLeadingChar(str[cur++])) return 0;
  while (((cur) < str.length()) && ((cur - s) < 14) && IsTZChar(str[cur])) {
    cur++;
  }
  if ((cur - s) == 1 && str[s] == '.') return 0;
  if ((cur - s) == 2 && str[s] == '.' && str[s + 1] == '.') return 0;
  return cur - s;
}
// TimeZoneIANALegacyName :
//   Etc/GMT0
//   GMT0
//   GMT-0
//   GMT+0
//   EST5EDT
//   CST6CDT
//   MST7MDT
//   PST8PDT

template <typename Char>
int32_t ScanTimeZoneIANALegacyName(base::Vector<Char> str, int32_t s) {
  int32_t cur = s;
  {
    constexpr int32_t len = 4;
    if (str.length() < cur + len) return 0;
    if (CompareCharsEqual(str.begin() + cur, "GMT0", len)) return len;
  }

  {
    constexpr int32_t len = 5;
    if (str.length() < cur + len) return 0;
    if (CompareCharsEqual(str.begin() + cur, "GMT+0", len) ||
        CompareCharsEqual(str.begin() + cur, "GMT-0", len)) {
      return len;
    }
  }

  {
    constexpr int32_t len = 7;
    if (str.length() < cur + len) return 0;
    if (CompareCharsEqual(str.begin() + cur, "EST5EDT", len) ||
        CompareCharsEqual(str.begin() + cur, "CST6CDT", len) ||
        CompareCharsEqual(str.begin() + cur, "MST7MDT", len) ||
        CompareCharsEqual(str.begin() + cur, "PST8PDT", len)) {
      return len;
    }
  }

  {
    constexpr int32_t len = 8;
    if (str.length() < cur + len) return 0;
    if (CompareCharsEqual(str.begin() + cur, "Etc/GMT0", len)) return len;
  }

  return 0;
}

// Etc/GMT ASCIISign UnpaddedHour
template <typename Char>
int32_t ScanEtcGMTASCIISignUnpaddedHour(base::Vector<Char> str, int32_t s) {
  if ((s + 9) > str.length()) return 0;
  int32_t cur = s;
  int32_t len = arraysize("Etc/GMT") - 1;
  if (!CompareCharsEqual(str.begin() + cur, "Etc/GMT", len)) return 0;
  cur += len;
  Char sign = str[cur++];
  if (!IsAsciiSign(sign)) return 0;
  len = ScanUnpaddedHour(str, cur);
  if (len == 0) return 0;
  cur += len;
  return cur - s;
}

// TimeZoneIANANameTail :
//   TimeZoneIANANameComponent
//   TimeZoneIANANameComponent / TimeZoneIANANameTail
// TimeZoneIANAName :
//   Etc/GMT ASCIISign UnpaddedHour
//   TimeZoneIANANameTail
//   TimeZoneIANALegacyName
// The spec text use tail recusion with TimeZoneIANANameComponent and
// TimeZoneIANANameTail. In our implementation, we use an iteration loop
// instead.
template <typename Char>
int32_t ScanTimeZoneIANAName(base::Vector<Char> str, int32_t s) {
  int32_t len;
  if ((len = ScanEtcGMTASCIISignUnpaddedHour(str, s)) > 0 ||
      (len = ScanTimeZoneIANALegacyName(str, s)) > 0) {
    return len;
  }
  int32_t cur = s;
  if ((len = ScanTimeZoneIANANameComponent(str, cur)) == 0) return 0;
  cur += len;
  while ((str.length() > (cur + 1)) && (str[cur] == '/')) {
    cur++;
    if ((len = ScanTimeZoneIANANameComponent(str, cur)) == 0) {
      return 0;
    }
    // TimeZoneIANANameComponent / TimeZoneIANAName
    cur += len;
  }
  return cur - s;
}

// TimeZoneUTCOffsetName
//   Sign Hour
//   Sign Hour : MinuteSecond
//   Sign Hour MinuteSecond
//   Sign Hour : MinuteSecond : MinuteSecond [Fraction]
//   Sign Hour MinuteSecond MinuteSecond [Fraction]
//
template <typename Char>
int32_t ScanTimeZoneUTCOffsetName(base::Vector<Char> str, int32_t s) {
  int32_t cur = s;
  int32_t len;
  if ((str.length() < (s + 3)) || !IsSign(str[cur++])) return 0;
  int32_t hour, minute, second, fraction;
  if ((len = ScanHour(str, cur, &hour)) == 0) return 0;
  cur += len;
  if ((cur + 1) > str.length()) {
    // Sign Hour
    return cur - s;
  }
  if (str[cur] == ':') {
    // Sign Hour :
    cur++;
    if ((len = ScanMinuteSecond(str, cur, &minute)) == 0) return 0;
    cur += len;
    if ((cur + 1) > str.length() || (str[cur] != ':')) {
      // Sign Hour : MinuteSecond
      return cur - s;
    }
    cur++;
    // Sign Hour : MinuteSecond :
    if ((len = ScanMinuteSecond(str, cur, &second)) == 0) return 0;
    cur += len;
    len = ScanFraction(str, cur, &fraction);
    return cur + len - s;
  } else {
    if ((len = ScanMinuteSecond(str, cur, &minute)) == 0) {
      // Sign Hour
      return cur - s;
    }
    cur += len;
    if ((len = ScanMinuteSecond(str, cur, &second)) == 0) {
      // Sign Hour MinuteSecond
      return cur - s;
    }
    cur += len;
    len = ScanFraction(str, cur, &fraction);
    //  Sign Hour MinuteSecond MinuteSecond [Fraction]
    cur += len;
    return cur - s;
  }
}

// TimeZoneBracketedName
//   TimeZoneIANAName
//   "Etc/GMT" ASCIISign Hour
//   TimeZoneUTCOffsetName
// Since "Etc/GMT" also fit TimeZoneIANAName so we need to try
// "Etc/GMT" ASCIISign Hour first.
template <typename Char>
int32_t ScanEtcGMTAsciiSignHour(base::Vector<Char> str, int32_t s) {
  if ((s + 10) > str.length()) return 0;
  int32_t cur = s;
  if ((str[cur++] != 'E') || (str[cur++] != 't') || (str[cur++] != 'c') ||
      (str[cur++] != '/') || (str[cur++] != 'G') || (str[cur++] != 'M') ||
      (str[cur++] != 'T')) {
    return 0;
  }
  Char sign = str[cur++];
  if (!IsAsciiSign(sign)) return 0;
  int32_t hour;
  int32_t len = ScanHour(str, cur, &hour);
  if (len == 0) return 0;
  //   "Etc/GMT" ASCIISign Hour
  return 10;
}

template <typename Char>
int32_t ScanTimeZoneIdentifier(base::Vector<Char> str, int32_t s,
                               ParsedISO8601Result* r);
// TimeZoneBracketedAnnotation :
// [ TimeZoneIdentifier ]
template <typename Char>
int32_t ScanTimeZoneBracketedAnnotation(base::Vector<Char> str, int32_t s,
                                        ParsedISO8601Result* r) {
  if ((str.length() < (s + 3)) || (str[s] != '[')) return 0;
  int32_t cur = s + 1;
  int32_t len = ScanTimeZoneIdentifier(str, cur, r);
  cur += len;
  if (len == 0 || str.length() < (cur + 1) || (str[cur] != ']')) {
    // Only ScanTimeZoneBracketedAnnotation know the post condition of
    // TimeZoneIdentifier is not matched so we need to reset here.
    r->tzi_name_start = 0;
    r->tzi_name_length = 0;
    return 0;
  }
  cur++;
  return cur - s;
}

// TimeZoneOffsetRequired:
//   TimeZoneUTCOffset [TimeZoneBracketedAnnotation]
template <typename Char>
int32_t ScanTimeZoneOffsetRequired(base::Vector<Char> str, int32_t s,
                                   ParsedISO8601Result* r) {
  int32_t cur = s;
  cur += ScanTimeZoneUTCOffset(str, cur, r);
  if (cur == s) return 0;
  cur += ScanTimeZoneBracketedAnnotation(str, cur, r);
  return cur - s;
}

//   TimeZoneNameRequired:
//   [TimeZoneUTCOffset] TimeZoneBracketedAnnotation
template <typename Char>
int32_t ScanTimeZoneNameRequired(base::Vector<Char> str, int32_t s,
                                 ParsedISO8601Result* r) {
  int32_t cur = s;
  cur += ScanTimeZoneUTCOffset(str, cur, r);
  int32_t len = ScanTimeZoneBracketedAnnotation(str, cur, r);
  if (len == 0) return 0;
  cur += len;
  return cur - s;
}

// TimeZone:
//   TimeZoneUTCOffset [TimeZoneBracketedAnnotation]
//   TimeZoneBracketedAnnotation
template <typename Char>
int32_t ScanTimeZone(base::Vector<Char> str, int32_t s,
                     ParsedISO8601Result* r) {
  int32_t cur = s;
  int32_t len;
  // TimeZoneUTCOffset [TimeZoneBracketedAnnotation]
  if ((len = ScanTimeZoneUTCOffset(str, cur, r)) > 0) {
    cur += len;
    // [TimeZoneBracketedAnnotation]
    len = ScanTimeZoneBracketedAnnotation(str, cur, r);
    cur += len;
    return cur - s;
  }
  // TimeZoneBracketedAnnotation
  return ScanTimeZoneBracketedAnnotation(str, cur, r);
}

// ValidMonthDay :
//   DateMonth [-] 0 NonZeroDigit
//   DateMonth [-] 1 DecimalDigit
//   DateMonth [-] 2 DecimalDigit
//   DateMonth [-] 30 but not one of 0230 or 02-30
//   DateMonthWithThirtyOneDays [-] 31
template <typename Char>
int32_t ScanValidMonthDay(base::Vector<Char> str, int32_t s) {
  int32_t len;
  int32_t cur = s;
  int32_t date_month;
  if ((len = ScanDateMonth(str, cur, &date_month)) > 0) {
    cur += len;
    if (str.length() >= (cur + 1)) {
      if (str[cur] == '-') cur++;
      int32_t day_of_month;
      if ((len = ScanTwoDigitsExpectRange(str, cur, 1, 30, &day_of_month)) >
          0) {
        cur += len;
        // 0 NonZeroDigit
        // 1 DecimalDigit
        // 2 DecimalDigit
        // 30 but not one of 0230 or 02-30
        if (date_month != 2 || day_of_month != 30) {
          return cur - s;
        }
      }
    }
  }
  // Reset cur
  cur = s;
  //   DateMonthWithThirtyOneDays [-] 31
  if ((len = ScanDateMonthWithThirtyOneDays(str, cur)) > 0) {
    cur += len;
    if (str.length() >= (cur + 1)) {
      if (str[cur] == '-') cur++;
      int32_t dummy;
      if ((len = ScanTwoDigitsExpectValue(str, cur, 31, &dummy)) > 0) {
        cur += len;
        return cur - s;
      }
    }
  }
  return 0;
}

template <typename Char>
int32_t ScanDateSpecYearMonth(base::Vector<Char> str, int32_t s,
                              ParsedISO8601Result* r);

// TimeSpecWithOptionalTimeZoneNotAmbiguous :
//   TimeSpec [TimeZone] but not one of ValidMonthDay or DateSpecYearMonth
template <typename Char>
int32_t ScanTimeSpecWithOptionalTimeZoneNotAmbiguous(base::Vector<Char> str,
                                                     int32_t s,
                                                     ParsedISO8601Result* r) {
  int32_t cur = s;
  int32_t len;
  if ((len = ScanTimeSpec(str, cur, r)) == 0) return 0;
  cur += len;
  // [TimeZone]
  len = ScanTimeZone(str, cur, r);
  cur += len;
  len = cur - s;
  // If it match ValidMonthDay, consider invalid.
  if (ScanValidMonthDay(str, s) == len) return 0;
  // If it match DateSpecYearMonth, consider invalid.
  ParsedISO8601Result tmp;
  if (ScanDateSpecYearMonth(str, s, &tmp) == len) return 0;
  return len;
}

// CalendarNameComponent:
//   CalChar {3,8}
template <typename Char>
int32_t ScanCalendarNameComponent(base::Vector<Char> str, int32_t s) {
  int32_t cur = s;
  while ((cur < str.length()) && IsAlphaNumeric(str[cur])) cur++;
  if ((cur - s) < 3 || (cur - s) > 8) return 0;
  return cur - s;
}

// CalendarNameTail :
//   CalendarNameComponent
//   CalendarNameComponent - CalendarNameTail
// CalendarName :
//   CalendarNameTail
// The spec text use tail recusion with CalendarNameComponent and
// CalendarNameTail. In our implementation, we use an iteration loop instead.
template <typename Char>
int32_t ScanCalendarName(base::Vector<Char> str, int32_t s,
                         ParsedISO8601Result* r) {
  int32_t cur = s;
  int32_t len;
  if ((len = ScanCalendarNameComponent(str, cur)) == 0) return 0;
  cur += len;
  while ((str.length() > (cur + 1)) && (str[cur++] == '-')) {
    if ((len = ScanCalendarNameComponent(str, cur)) == 0) return 0;
    // CalendarNameComponent - CalendarName
    cur += len;
  }
  r->calendar_name_start = s;
  r->calendar_name_length = cur - s;
  return cur - s;
}

// Calendar: '[u-ca=' CalendarName ']'
template <typename Char>
int32_t ScanCalendar(base::Vector<Char> str, int32_t s,
                     ParsedISO8601Result* r) {
  if (str.length() < (s + 7)) return 0;
  int32_t cur = s;
  // "[u-ca="
  if ((str[cur++] != '[') || (str[cur++] != 'u') || (str[cur++] != '-') ||
      (str[cur++] != 'c') || (str[cur++] != 'a') || (str[cur++] != '=')) {
    return 0;
  }
  int32_t len = ScanCalendarName(str, cur, r);
  if (len == 0) return 0;
  if ((str.length() < (cur + len + 1)) || (str[cur + len] != ']')) {
    // Only ScanCalendar know the post condition of CalendarName is not met and
    // need to reset here.
    r->calendar_name_start = 0;
    r->calendar_name_length = 0;
    return 0;
  }
  return 6 + len + 1;
}

// CalendarTime_L1:
//  TimeDesignator TimeSpec [TimeZone] [Calendar]
template <typename Char>
int32_t ScanCalendarTime_L1(base::Vector<Char> str, int32_t s,
                            ParsedISO8601Result* r) {
  int32_t cur = s;
  if (str.length() < (s + 1)) return 0;
  // TimeDesignator
  if (AsciiAlphaToLower(str[cur++]) != 't') return 0;
  int32_t len = ScanTimeSpec(str, cur, r);
  if (len == 0) return 0;
  cur += len;
  // [TimeZone]
  cur += ScanTimeZone(str, cur, r);
  // [Calendar]
  cur += ScanCalendar(str, cur, r);
  return cur - s;
}

// CalendarTime_L2 :
//  TimeSpecWithOptionalTimeZoneNotAmbiguous [Calendar]
template <typename Char>
int32_t ScanCalendarTime_L2(base::Vector<Char> str, int32_t s,
                            ParsedISO8601Result* r) {
  int32_t cur = s;
  int32_t len = ScanTimeSpecWithOptionalTimeZoneNotAmbiguous(str, cur, r);
  if (len == 0) return 0;
  cur += len;
  // [Calendar]
  cur += ScanCalendar(str, cur, r);
  return cur - s;
}

// DateTime: Date [TimeSpecSeparator][TimeZone]
template <typename Char>
int32_t ScanDateTime(base::Vector<Char> str, int32_t s,
                     ParsedISO8601Result* r) {
  int32_t cur = s;
  int32_t len = ScanDate(str, cur, r);
  if (len == 0) return 0;
  cur += len;
  cur += ScanTimeSpecSeparator(str, cur, r);
  cur += ScanTimeZone(str, cur, r);
  return cur - s;
}

// DateSpecYearMonth: DateYear ['-'] DateMonth
template <typename Char>
int32_t ScanDateSpecYearMonth(base::Vector<Char> str, int32_t s,
                              ParsedISO8601Result* r) {
  int32_t date_year, date_month;
  int32_t cur = s;
  int32_t len = ScanDateYear(str, cur, &date_year);
  if (len == 0) return 0;
  cur += len;
  if (str.length() < (cur + 1)) return 0;
  if (str[cur] == '-') cur++;
  len = ScanDateMonth(str, cur, &date_month);
  if (len == 0) return 0;
  r->date_year = date_year;
  r->date_month = date_month;
  cur += len;
  return cur - s;
}

// DateSpecMonthDay:
//   [TwoDash] DateMonth [-] DateDay
template <typename Char>
int32_t ScanDateSpecMonthDay(base::Vector<Char> str, int32_t s,
                             ParsedISO8601Result* r) {
  if (str.length() < (s + 4)) return 0;
  int32_t cur = s;
  if (str[cur] == '-') {
    // The first two dash are optional together
    if (str[++cur] != '-') return 0;
    // TwoDash
    cur++;
  }
  int32_t date_month, date_day;
  int32_t len = ScanDateMonth(str, cur, &date_month);
  if (len == 0) return 0;
  cur += len;
  if (str.length() < (cur + 1)) return 0;
  // '-'
  if (str[cur] == '-') cur++;
  len = ScanDateDay(str, cur, &date_day);
  if (len == 0) return 0;
  r->date_month = date_month;
  r->date_day = date_day;
  cur += len;
  return cur - s;
}

// TimeZoneIdentifier :
//   TimeZoneIANAName
//   TimeZoneUTCOffsetName
template <typename Char>
int32_t ScanTimeZoneIdentifier(base::Vector<Char> str, int32_t s,
                               ParsedISO8601Result* r) {
  int32_t len;
  int32_t cur = s;
  if ((len = ScanTimeZoneIANAName(str, cur)) > 0 ||
      (len = ScanTimeZoneUTCOffsetName(str, cur)) > 0) {
    cur += len;
    r->tzi_name_start = s;
    r->tzi_name_length = len;
    return cur - s;
  }
  return 0;
}

// CalendarDateTime: DateTime [Calendar]
template <typename Char>
int32_t ScanCalendarDateTime(base::Vector<Char> str, int32_t s,
                             ParsedISO8601Result* r) {
  int32_t len = ScanDateTime(str, s, r);
  if (len == 0) return 0;
  return len + ScanCalendar(str, len, r);
}

// CalendarDateTimeTimeRequired: Date TimeSpecSeparator [TimeZone] [Calendar]
template <typename Char>
int32_t ScanCalendarDateTimeTimeRequired(base::Vector<Char> str, int32_t s,
                                         ParsedISO8601Result* r) {
  int32_t cur = s;
  int32_t len = ScanDate(str, cur, r);
  if (len == 0) return 0;
  cur += len;
  len = ScanTimeSpecSeparator(str, cur, r);
  if (len == 0) return 0;
  cur += len;
  // [TimeZone]
  cur += ScanTimeZone(str, cur, r);
  // [Calendar]
  cur += ScanCalendar(str, cur, r);
  return cur - s;
}

// TemporalZonedDateTimeString:
//   Date [TimeSpecSeparator] TimeZoneNameRequired [Calendar]
template <typename Char>
int32_t ScanTemporalZonedDateTimeString(base::Vector<Char> str, int32_t s,
```