Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Scan and High-Level Understanding:**

* **File Name:** `temporal-parser-unittest.cc`. The "unittest" part is a huge clue. This file *tests* something related to parsing temporal data.
* **Includes:**  `temporal-parser.h` is the core component being tested. The other includes (`execution/isolate.h`, `heap/factory-inl.h`, `test/unittests/test-utils.h`) are typical for V8 unit tests, providing necessary infrastructure.
* **Namespace:** `v8::internal`. This confirms it's internal V8 code, not part of the public API.
* **Comments:** The initial comments explicitly state the purpose: testing `TemporalParser` for ISO 8601 parsing, referencing the relevant specification section. This is the most important piece of information.
* **Key Data Structures/Constants:** `ParsedISO8601Result`, `ParsedISO8601Duration`, `kUndefined`. These suggest the parser outputs structured data representing parsed dates, times, and durations. `kUndefined` likely handles optional or missing fields.
* **Helper Functions:**  `CheckCalendar`, `CheckDate`, `CheckTime`, `CheckTimeZoneNumericUTCOffset`, `CheckDuration`. These functions clearly indicate the different aspects of temporal data being parsed and validated. The names are self-explanatory.
* **Macros:** `IMPL_VERIFY_PARSE_TEMPORAL_*_STRING_SUCCESS`. These macros are used to generate test helper functions. The `SUCCESS` suffix suggests they are for testing successful parsing scenarios. The different macro names indicate the different types of temporal strings being parsed (Date, DateTime, ZonedDateTime).

**2. Inferring Functionality Based on Code Structure:**

* **Parsing ISO 8601:**  The initial comment is the strongest indicator. The presence of functions like `TemporalParser::ParseTemporal...String` further confirms this. ISO 8601 is the standard for date and time representation.
* **Unit Testing:** The "unittest" suffix and the `TEST_F` macro clearly identify this as a unit test file. The structure of the tests involves setting up inputs and then *asserting* that the parser produces the expected outputs.
* **Testing Success Scenarios:** The macros with "Success" in their names and the `CHECK` statements within them indicate the primary focus of this part of the code is to verify correct parsing of valid ISO 8601 strings.
* **Testing Different Temporal Components:** The existence of separate check functions and `ParseTemporal` functions for dates, times, timezones, and durations implies the parser can handle these components individually or in combination.
* **Handling Optional Parts:** The `kUndefined` constant suggests the parser can deal with optional components within the ISO 8601 strings.

**3. Connecting to JavaScript (as requested):**

* **`Temporal` API:**  Knowing this is V8 code and related to temporal parsing, the obvious connection is the JavaScript `Temporal` API. This is a relatively new API designed to address shortcomings in JavaScript's built-in `Date` object.
* **JavaScript Examples:**  Based on the C++ code's focus on ISO 8601,  JavaScript `Temporal` API examples would involve creating `Temporal.PlainDate`, `Temporal.PlainTime`, `Temporal.ZonedDateTime`, and `Temporal.Duration` objects by parsing ISO 8601 strings.

**4. Code Logic Inference (Hypothetical Inputs and Outputs):**

* Focus on the `VerifyParseTemporal...StringSuccess` functions and the corresponding `Check...` functions. These provide clear examples of inputs and expected outputs. For instance, `VerifyParseTemporalDateStringSuccess("2023-10-27", 2023, 10, 27, "")` demonstrates the input string "2023-10-27" and the expected parsed year, month, and day.

**5. Identifying Potential User Errors:**

* **Invalid ISO 8601 formats:**  The code tests *successful* parsing. However, the structure suggests that if the input string doesn't conform to the ISO 8601 grammar, the parsing would fail. This is a common user error when working with date and time strings.

**6. Answering the Specific Questions:**

* **Functionality:**  Parse ISO 8601 date, time, and duration strings.
* **.tq extension:** No, it doesn't end in `.tq`, so it's C++, not Torque.
* **Relation to JavaScript:**  It's part of the V8 engine, which executes JavaScript. It likely underpins the `Temporal` API's parsing of date/time strings.
* **JavaScript Examples:** Provide examples of using `Temporal` to parse similar strings.
* **Code Logic Inference:** Provide input/output examples based on the existing test cases.
* **User Errors:**  Focus on incorrect ISO 8601 formatting.
* **Summary:** Synthesize the key functionalities into a concise summary.

**Self-Correction/Refinement during the Process:**

* Initially, I might focus too much on the low-level C++ details. It's crucial to step back and remember the *purpose* of the code (unit testing) and the library it's testing (`TemporalParser`).
*  The macros might seem complex at first. Recognizing they are just generating repetitive test functions simplifies understanding.
* Connecting to JavaScript requires knowledge of the `Temporal` API. If unfamiliar, a quick search would be necessary.

By following these steps, combining code analysis with domain knowledge (ISO 8601, unit testing, JavaScript `Temporal`), we can effectively understand and summarize the functionality of the provided code snippet.
好的，让我们来分析一下 `v8/test/unittests/temporal/temporal-parser-unittest.cc` 这个 V8 源代码文件的功能。

**功能归纳:**

这个 C++ 文件是 V8 JavaScript 引擎中 `TemporalParser` 类的单元测试。它的主要功能是测试 `TemporalParser` 类是否能够正确地解析符合 ISO 8601 标准的日期、时间和持续时间字符串。

**详细功能分解:**

1. **测试 ISO 8601 解析:**
   - 该文件专门用于测试 `TemporalParser` 对 ISO 8601 格式字符串的解析能力，涵盖日期、时间、带时区的日期时间以及持续时间等。
   - 它通过定义一系列的测试用例，每个用例都包含一个待解析的 ISO 8601 字符串，以及期望的解析结果。

2. **辅助检查函数:**
   - 文件中定义了一系列 `Check...` 函数（例如 `CheckCalendar`, `CheckDate`, `CheckTime`, `CheckTimeZoneNumericUTCOffset`, `CheckDuration`）。
   - 这些函数用于比较 `TemporalParser` 的解析结果与预期的结果是否一致，从而判断解析是否正确。

3. **测试宏定义:**
   - 定义了多个宏，例如 `IMPL_VERIFY_PARSE_TEMPORAL_DATE_STRING_SUCCESS`, `IMPL_VERIFY_PARSE_TEMPORAL_DATE_TIME_STRING_SUCCESS`, `IMPL_VERIFY_PARSE_TEMPORAL_ZONED_DATE_TIME_STRING_SUCCESS`。
   - 这些宏用于简化编写测试用例的过程，针对不同类型的 Temporal 对象（例如，仅日期，日期和时间，带时区的日期时间），自动生成测试函数。这些宏接收 ISO 字符串、期望的日期/时间组件以及日历信息等参数。

4. **`TemporalParserTest` 类:**
   - 定义了一个名为 `TemporalParserTest` 的测试类，继承自 `TestWithIsolate`，这是 V8 单元测试的基类。
   - 在这个类中，实例化了各种具体的测试用例，调用 `TemporalParser` 的解析方法，并使用 `Check...` 函数进行断言，验证解析结果的正确性。

5. **测试成功场景:**
   - 重点测试了各种符合 ISO 8601 标准的字符串，验证 `TemporalParser` 在这些情况下的正确解析。例如，测试不同的日期格式、时间格式、时区表示等。

6. **测试失败场景 (在后续部分):**
   - 从代码结构来看，虽然这里没有直接的失败测试用例，但后续的部分（第 2/3/4 部分）很可能会包含使用 `VERIFY_PARSE_FAIL` 宏定义的测试用例，用于验证 `TemporalParser` 在遇到不符合 ISO 8601 标准的字符串时能够正确地报告错误或返回失败。

**关于 .tq 结尾:**

文件中提到 "如果 `v8/test/unittests/temporal/temporal-parser-unittest.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码"。  **当前的这个文件并没有以 `.tq` 结尾，所以它是一个 C++ 源代码文件，而不是 Torque 文件。** Torque 是 V8 用来生成高效 JavaScript 内置函数的领域特定语言。

**与 JavaScript 的关系及示例:**

`TemporalParser` 是 V8 引擎内部用于解析日期和时间字符串的组件，它直接支持 JavaScript 中新的 `Temporal` API。 `Temporal` API 旨在替代旧的 `Date` 对象，提供更现代化、更易用的日期和时间处理方式。

**JavaScript 示例:**

假设 `TemporalParser` 能够正确解析 ISO 8601 格式的日期字符串，例如 "2023-10-27"。在 JavaScript 中，你可以使用 `Temporal.PlainDate.from()` 方法来解析这个字符串：

```javascript
const temporal = globalThis.Temporal; // 获取 Temporal API

if (temporal) {
  const plainDate = temporal.PlainDate.from("2023-10-27");
  console.log(plainDate.year);   // 输出: 2023
  console.log(plainDate.month);  // 输出: 10
  console.log(plainDate.day);    // 输出: 27
} else {
  console.log("Temporal API is not supported in this environment.");
}
```

同样，对于带时间的字符串：

```javascript
if (temporal) {
  const plainDateTime = temporal.PlainDateTime.from("2023-10-27T10:30:00");
  console.log(plainDateTime.hour);   // 输出: 10
  console.log(plainDateTime.minute); // 输出: 30
}
```

对于带时区的字符串：

```javascript
if (temporal) {
  const zonedDateTime = temporal.ZonedDateTime.from("2023-10-27T10:30:00+08:00[Asia/Shanghai]");
  console.log(zonedDateTime.timeZone.id); // 输出: Asia/Shanghai
}
```

对于持续时间字符串：

```javascript
if (temporal) {
  const duration = temporal.Duration.from("P1Y2M3DT4H5M6S");
  console.log(duration.years);   // 输出: 1
  console.log(duration.months);  // 输出: 2
}
```

**代码逻辑推理 (假设输入与输出):**

假设我们有以下测试用例（与代码中的宏定义类似）：

**假设输入:**  ISO 8601 日期字符串 `"2024-03-15"`

**`TemporalParser::ParseTemporalDateString()` 函数的预期输出 (ParsedISO8601Result):**

```
ParsedISO8601Result {
  date_year: 2024,
  date_month: 3,
  date_day: 15,
  calendar_name_start: kUndefined,
  calendar_name_length: 0,
  // 其他字段的默认或未定义值
}
```

`CheckDate()` 函数会验证 `actual.date_year` 是否等于 2024，`actual.date_month` 是否等于 3，`actual.date_day` 是否等于 15。

**涉及用户常见的编程错误 (如果 `TemporalParser` 没有正确实现):**

1. **解析格式错误的字符串:**  如果用户传递了一个不符合 ISO 8601 标准的字符串，例如 `"2024/03/15"` 或 `"March 15, 2024"`，`TemporalParser` 应该能够识别并拒绝这些格式。如果解析器实现不正确，可能会错误地解析这些字符串，导致数据错误。

   ```javascript
   // 错误的日期格式
   try {
     temporal.PlainDate.from("2024/03/15"); // 应该抛出错误
   } catch (e) {
     console.error("Error parsing date:", e);
   }
   ```

2. **时区处理错误:**  在处理带时区的日期时间时，如果 `TemporalParser` 没有正确解析时区信息，可能会导致时间转换错误。

   ```javascript
   // 假设解析器错误地处理了时区
   const zonedDateTime = temporal.ZonedDateTime.from("2023-10-27T10:30:00+08:00[Asia/Shanghai]");
   // 如果时区解析错误，可能会得到错误的时间
   ```

3. **日期范围错误:**  如果用户提供了超出有效日期范围的值（例如，2023-02-30），`TemporalParser` 应该能够检测到这些错误。

   ```javascript
   try {
     temporal.PlainDate.from("2023-02-30"); // 应该抛出错误
   } catch (e) {
     console.error("Error parsing date:", e);
   }
   ```

**第 1 部分功能归纳:**

总而言之，`v8/test/unittests/temporal/temporal-parser-unittest.cc` 的第 1 部分主要定义了用于测试 `TemporalParser` 成功解析各种符合 ISO 8601 标准的日期、时间和持续时间字符串的基础结构和辅助函数。它通过宏定义简化了编写测试用例的过程，并提供了一些用于断言解析结果正确性的 `Check...` 函数。这部分代码专注于验证在输入有效 ISO 字符串时，解析器是否能产生预期的结果。

### 提示词
```
这是目录为v8/test/unittests/temporal/temporal-parser-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/temporal/temporal-parser-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/temporal/temporal-parser.h"

#include <optional>

#include "src/execution/isolate.h"
#include "src/heap/factory-inl.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {

// This file test the TemporalParser to parse ISO 8601 according to
// #sec-temporal-iso8601grammar

// For int32_t fields in ParsedISO8601Result, kMinInt31 denote 'undefined'
// value.
const int32_t kUndefined = kMinInt31;

void CheckCalendar(Isolate* isolate, Handle<String> iso_string,
                   int32_t calendar_start, int32_t calendar_length,
                   const std::string& expected_calendar) {
  DirectHandle<String> actual_calendar = isolate->factory()->NewSubString(
      iso_string, calendar_start, calendar_start + calendar_length);
  CHECK(expected_calendar == actual_calendar->ToCString().get());
}

void CheckDate(const ParsedISO8601Result& actual, int32_t date_year,
               int32_t date_month, int32_t date_day) {
  CHECK_EQ(date_year, actual.date_year);
  CHECK_EQ(date_month, actual.date_month);
  CHECK_EQ(date_day, actual.date_day);
}

void CheckTime(const ParsedISO8601Result& actual, int32_t time_hour,
               int32_t time_minute, int32_t time_second,
               int32_t time_nanosecond) {
  CHECK_EQ(time_hour, actual.time_hour);
  CHECK_EQ(time_minute, actual.time_minute);
  CHECK_EQ(time_second, actual.time_second);
  CHECK_EQ(time_nanosecond, actual.time_nanosecond);
}

void CheckTimeZoneNumericUTCOffset(const ParsedISO8601Result& actual,
                                   int32_t tzuo_sign, int32_t tzuo_hour,
                                   int32_t tzuo_minute, int32_t tzuo_second,
                                   int32_t tzuo_nanosecond) {
  CHECK_EQ(tzuo_sign, actual.tzuo_sign);
  CHECK_EQ(tzuo_hour, actual.tzuo_hour);
  CHECK_EQ(tzuo_minute, actual.tzuo_minute);
  CHECK_EQ(tzuo_second, actual.tzuo_second);
  CHECK_EQ(tzuo_nanosecond, actual.tzuo_nanosecond);
}

void CheckDuration(const ParsedISO8601Duration& actual, int64_t sign,
                   int64_t years, int64_t months, int64_t weeks, int64_t days,
                   int64_t whole_hours, int64_t hours_fraction,
                   int64_t whole_minutes, int64_t minutes_fraction,
                   int64_t whole_seconds, int64_t seconds_fraction) {
  CHECK_EQ(sign, actual.sign);
  CHECK_EQ(years, actual.years);
  CHECK_EQ(months, actual.months);
  CHECK_EQ(weeks, actual.weeks);
  CHECK_EQ(days, actual.days);
  CHECK_EQ(whole_hours, actual.whole_hours);
  CHECK_EQ(hours_fraction, actual.hours_fraction);
  CHECK_EQ(whole_minutes, actual.whole_minutes);
  CHECK_EQ(minutes_fraction, actual.minutes_fraction);
  CHECK_EQ(whole_seconds, actual.whole_seconds);
  CHECK_EQ(seconds_fraction, actual.seconds_fraction);
}

char commatoperiod(char in) { return (in == ',') ? '.' : in; }

char asciitolower(char in) {
  return (in <= 'Z' && in >= 'A') ? (in - ('Z' - 'z')) : in;
}

#define IMPL_VERIFY_PARSE_TEMPORAL_DATE_STRING_SUCCESS(R)             \
  void VerifyParseTemporal##R##StringSuccess(                         \
      const char* str, int32_t date_year, int32_t date_month,         \
      int32_t date_day, const char* calendar_name) {                  \
    Handle<String> input = MakeString(str);                           \
    std::optional<ParsedISO8601Result> result =                       \
        TemporalParser::ParseTemporal##R##String(i_isolate(), input); \
    CHECK(result.has_value());                                        \
    ParsedISO8601Result actual = *result;                             \
    CheckDate(actual, date_year, date_month, date_day);               \
    CheckCalendar(i_isolate(), input, actual.calendar_name_start,     \
                  actual.calendar_name_length, calendar_name);        \
  }

#define IMPL_VERIFY_PARSE_TEMPORAL_DATE_TIME_STRING_SUCCESS(R)               \
  void VerifyParseTemporal##R##StringSuccess(                                \
      const char* str, int32_t date_year, int32_t date_month,                \
      int32_t date_day, int32_t time_hour, int32_t time_minute,              \
      int32_t time_second, int32_t time_nanosecond,                          \
      const char* calendar_name) {                                           \
    Handle<String> input = MakeString(str);                                  \
    std::optional<ParsedISO8601Result> result =                              \
        TemporalParser::ParseTemporal##R##String(i_isolate(), input);        \
    CHECK(result.has_value());                                               \
    ParsedISO8601Result actual = *result;                                    \
    CheckDate(actual, date_year, date_month, date_day);                      \
    CheckCalendar(i_isolate(), input, actual.calendar_name_start,            \
                  actual.calendar_name_length, calendar_name);               \
    CheckTime(actual, time_hour, time_minute, time_second, time_nanosecond); \
  }

#define IMPL_VERIFY_PARSE_TEMPORAL_ZONED_DATE_TIME_STRING_SUCCESS(R)           \
  void VerifyParseTemporal##R##StringSuccess(                                  \
      const char* str, int32_t date_year, int32_t date_month,                  \
      int32_t date_day, int32_t time_hour, int32_t time_minute,                \
      int32_t time_second, int32_t time_nanosecond, const char* calendar_name, \
      int32_t tzuo_sign, int32_t tzuo_hour, int32_t tzuo_minute,               \
      int32_t tzuo_second, int32_t tzuo_nanosecond, bool utc_designator,       \
      const char* tzi_name) {                                                  \
    Handle<String> input = MakeString(str);                                    \
    std::optional<ParsedISO8601Result> result =                                \
        TemporalParser::ParseTemporal##R##String(i_isolate(), input);          \
    CHECK(result.has_value());                                                 \
    ParsedISO8601Result actual = *result;                                      \
    CheckDate(actual, date_year, date_month, date_day);                        \
    CheckCalendar(i_isolate(), input, actual.calendar_name_start,              \
                  actual.calendar_name_length, calendar_name);                 \
    CheckTime(actual, time_hour, time_minute, time_second, time_nanosecond);   \
    CHECK_EQ(utc_designator, actual.utc_designator);                           \
    std::string actual_tzi_name(str + actual.tzi_name_start,                   \
                                actual.tzi_name_length);                       \
    CHECK(actual_tzi_name == tzi_name);                                        \
    if (!utc_designator) {                                                     \
      CheckTimeZoneNumericUTCOffset(actual, tzuo_sign, tzuo_hour, tzuo_minute, \
                                    tzuo_second, tzuo_nanosecond);             \
    }                                                                          \
  }

class TemporalParserTest : public TestWithIsolate {
 protected:
  IMPL_VERIFY_PARSE_TEMPORAL_DATE_STRING_SUCCESS(YearMonth)
  IMPL_VERIFY_PARSE_TEMPORAL_DATE_STRING_SUCCESS(MonthDay)
  IMPL_VERIFY_PARSE_TEMPORAL_DATE_TIME_STRING_SUCCESS(DateTime)
  IMPL_VERIFY_PARSE_TEMPORAL_ZONED_DATE_TIME_STRING_SUCCESS(ZonedDateTime)

  void VerifyParseTemporalInstantStringSuccess(
      const char* str, bool utc_designator, int32_t tzuo_sign,
      int32_t tzuo_hour, int32_t tzuo_minute, int32_t tzuo_second,
      int32_t tzuo_nanosecond) {
    Handle<String> input = MakeString(str);
    std::optional<ParsedISO8601Result> result =
        TemporalParser::ParseTemporalInstantString(i_isolate(), input);
    CHECK(result.has_value());
    ParsedISO8601Result actual = *result;
    CHECK_EQ(utc_designator, actual.utc_designator);
    if (!utc_designator) {
      CheckTimeZoneNumericUTCOffset(actual, tzuo_sign, tzuo_hour, tzuo_minute,
                                    tzuo_second, tzuo_nanosecond);
    }
  }

  void VerifyParseCalendarNameSuccess(const char* str) {
    Handle<String> input = MakeString(str);
    std::optional<ParsedISO8601Result> result =
        TemporalParser::ParseCalendarName(i_isolate(), input);
    CHECK(result.has_value());
    ParsedISO8601Result actual = *result;
    // For ParseCalendarName, we just validate the input fully match
    // CalendarName, therefore, the test pass if the start is 0 and
    // the calendar_name_length is the same as the length of the input.
    CHECK_EQ(actual.calendar_name_start, 0);
    CHECK_EQ(actual.calendar_name_length, input->length());
  }

  void VerifyParseTimeZoneIdentifierSuccess(const char* str) {
    Handle<String> input = MakeString(str);
    std::optional<ParsedISO8601Result> result =
        TemporalParser::ParseTimeZoneIdentifier(i_isolate(), input);
    CHECK(result.has_value());
    ParsedISO8601Result actual = *result;
    // For ParseTimeZoneIdentifier, we just validate the input fully match
    // TimeZoneIdentifier, therefore, the test pass if the start is 0 and
    // the tzi_name_length is the same as the length of the input.
    CHECK_EQ(actual.tzi_name_start, 0);
    CHECK_EQ(actual.tzi_name_length, input->length());
  }

  void VerifyParseTemporalTimeStringSuccess(const char* str, int32_t time_hour,
                                            int32_t time_minute,
                                            int32_t time_second,
                                            int32_t time_nanosecond,
                                            const char* calendar_name) {
    Handle<String> input = MakeString(str);
    ParsedISO8601Result actual =
        *TemporalParser::ParseTemporalTimeString(i_isolate(), input);
    CheckTime(actual, time_hour, time_minute, time_second, time_nanosecond);
    CheckCalendar(i_isolate(), input, actual.calendar_name_start,
                  actual.calendar_name_length, calendar_name);
  }

  void VerifyTemporalTimeStringTimeUndefined(const char* str) {
    VerifyParseTemporalTimeStringSuccess(str, kUndefined, kUndefined,
                                         kUndefined, kUndefined, "");
  }

  void VerifyParseDurationSuccess(const char* str, int64_t sign, int64_t years,
                                  int64_t months, int64_t weeks, int64_t days,
                                  int64_t whole_hours, int64_t hours_fraction,
                                  int64_t whole_minutes,
                                  int64_t minutes_fraction,
                                  int64_t whole_seconds,
                                  int64_t seconds_fraction) {
    Handle<String> input = MakeString(str);
    std::optional<ParsedISO8601Duration> result =
        TemporalParser::ParseTemporalDurationString(i_isolate(), input);
    CHECK(result.has_value());
    CheckDuration(*result, sign, years, months, weeks, days, whole_hours,
                  hours_fraction, whole_minutes, minutes_fraction,
                  whole_seconds, seconds_fraction);
  }

  void VerifyParseDurationSuccess(const char* str,
                                  const ParsedISO8601Duration& expected) {
    VerifyParseDurationSuccess(
        str, expected.sign, expected.years, expected.months, expected.weeks,
        expected.days, expected.whole_hours, expected.hours_fraction,
        expected.whole_minutes, expected.minutes_fraction,
        expected.whole_seconds, expected.seconds_fraction);
  }

  void VerifyParseDurationWithPositiveSign(const char* str) {
    Handle<String> input = MakeString(str);
    std::optional<ParsedISO8601Duration> result =
        TemporalParser::ParseTemporalDurationString(i_isolate(), input);
    CHECK(result.has_value());
    ParsedISO8601Duration expected = *result;
    std::string with_sign("+");
    with_sign += str;
    VerifyParseDurationSuccess(with_sign.c_str(), expected);
  }

  void VerifyParseDurationWithMinusSign(const char* str) {
    std::string with_sign("-");
    with_sign += str;
    Handle<String> input = MakeString(with_sign.c_str());
    std::optional<ParsedISO8601Duration> result =
        TemporalParser::ParseTemporalDurationString(i_isolate(), input);
    CHECK(result.has_value());
    ParsedISO8601Duration expected = *result;
    with_sign = "\u2212";
    with_sign += str;
    VerifyParseDurationSuccess(with_sign.c_str(), expected);
  }

  void VerifyParseDurationWithLowerCase(const char* str) {
    Handle<String> input = MakeString(str);
    std::optional<ParsedISO8601Duration> result =
        TemporalParser::ParseTemporalDurationString(i_isolate(), input);
    CHECK(result.has_value());
    ParsedISO8601Duration expected = *result;
    std::string lower(str);
    std::transform(lower.begin(), lower.end(), lower.begin(), asciitolower);
    VerifyParseDurationSuccess(lower.c_str(), expected);
  }

  void VerifyParseDurationWithComma(const char* str) {
    std::string period(str);
    std::transform(period.begin(), period.end(), period.begin(), commatoperiod);
    Handle<String> input = MakeString(str);
    std::optional<ParsedISO8601Duration> result =
        TemporalParser::ParseTemporalDurationString(i_isolate(), input);
    CHECK(result.has_value());
    ParsedISO8601Duration expected = *result;
    VerifyParseDurationSuccess(str, expected);
  }

  void VerifyParseTimeZoneNumericUTCOffsetSuccess(
      const char* str, int32_t tzuo_sign, int32_t tzuo_hour,
      int32_t tzuo_minute, int32_t tzuo_second, int32_t tzuo_nanosecond) {
    Handle<String> input = MakeString(str);
    std::optional<ParsedISO8601Result> result =
        TemporalParser::ParseTimeZoneNumericUTCOffset(i_isolate(), input);
    CHECK(result.has_value());
    CheckTimeZoneNumericUTCOffset(*result, tzuo_sign, tzuo_hour, tzuo_minute,
                                  tzuo_second, tzuo_nanosecond);
  }
};

#define VERIFY_PARSE_FAIL(R, str)                                     \
  do {                                                                \
    Handle<String> input = MakeString(str);                           \
    CHECK(!TemporalParser::Parse##R(i_isolate(), input).has_value()); \
  } while (false)

#define VERIFY_PARSE_FAIL_ON_DATE(R)                            \
  do {                                                          \
    VERIFY_PARSE_FAIL(R, "");                                   \
    /* sign only go with DateExtendedYear */                    \
    VERIFY_PARSE_FAIL(R, "+2021-03-04");                        \
    VERIFY_PARSE_FAIL(R, "-2021-03-04");                        \
    /* 1, 2, 3, 5 digits are not year */                        \
    VERIFY_PARSE_FAIL(R, "921-03-04");                          \
    VERIFY_PARSE_FAIL(R, "-821-03-04");                         \
    VERIFY_PARSE_FAIL(R, "9210304");                            \
    VERIFY_PARSE_FAIL(R, "-8210304");                           \
    VERIFY_PARSE_FAIL(R, "21-03-04");                           \
    VERIFY_PARSE_FAIL(R, "-31-03-04");                          \
    VERIFY_PARSE_FAIL(R, "\u221231-03-04");                     \
    VERIFY_PARSE_FAIL(R, "-310304");                            \
    VERIFY_PARSE_FAIL(R, "1-03-04");                            \
    VERIFY_PARSE_FAIL(R, "-3-03-04");                           \
    VERIFY_PARSE_FAIL(R, "10304");                              \
    VERIFY_PARSE_FAIL(R, "-30304");                             \
    VERIFY_PARSE_FAIL(R, "12921-03-04");                        \
    VERIFY_PARSE_FAIL(R, "-32821-03-04");                       \
    VERIFY_PARSE_FAIL(R, "129210304");                          \
    VERIFY_PARSE_FAIL(R, "-328210304");                         \
    VERIFY_PARSE_FAIL(R, "123456-03-04");                       \
    VERIFY_PARSE_FAIL(R, "1234560304");                         \
                                                                \
    /* 7 digits year */                                         \
    VERIFY_PARSE_FAIL(R, "0002021-09-03");                      \
    VERIFY_PARSE_FAIL(R, "-0002021-09-03");                     \
                                                                \
    /* It is a Syntax Error if DateExtendedYear is "-000000" */ \
    VERIFY_PARSE_FAIL(R, "-000000-09-03");                      \
    VERIFY_PARSE_FAIL(R, "\u2212000000-09-03");                 \
                                                                \
    /* single digit month */                                    \
    VERIFY_PARSE_FAIL(R, "1900-9-03");                          \
    VERIFY_PARSE_FAIL(R, "1900903");                            \
    /* out of range month */                                    \
    VERIFY_PARSE_FAIL(R, "1900-13-03");                         \
    VERIFY_PARSE_FAIL(R, "19001401");                           \
    /* single digit day */                                      \
    VERIFY_PARSE_FAIL(R, "1900-12-3");                          \
    VERIFY_PARSE_FAIL(R, "1900121");                            \
    /* Out of range day */                                      \
    VERIFY_PARSE_FAIL(R, "1900-12-32");                         \
    VERIFY_PARSE_FAIL(R, "19001232");                           \
    VERIFY_PARSE_FAIL(R, "1900-12-00");                         \
    VERIFY_PARSE_FAIL(R, "19001200");                           \
                                                                \
    /* Legal Date with other illegal stuff */                   \
    /* only with DateTimeSeparator */                           \
    VERIFY_PARSE_FAIL(R, "1900-12-31 ");                        \
    VERIFY_PARSE_FAIL(R, "19001231T");                          \
    VERIFY_PARSE_FAIL(R, "1900-12-31t");                        \
    VERIFY_PARSE_FAIL(R, "19001231 ");                          \
                                                                \
    /* Single digit hour */                                     \
    VERIFY_PARSE_FAIL(R, "1900-12-31 1");                       \
    VERIFY_PARSE_FAIL(R, "19001231T2");                         \
                                                                \
    /* Out of range hour */                                     \
    VERIFY_PARSE_FAIL(R, "1900-12-31t24");                      \
    VERIFY_PARSE_FAIL(R, "19001231 -1");                        \
                                                                \
    /* Single digit minute */                                   \
    VERIFY_PARSE_FAIL(R, "1900-12-31 03:1");                    \
    VERIFY_PARSE_FAIL(R, "19001231T024");                       \
                                                                \
    /* Out of range minute */                                   \
    VERIFY_PARSE_FAIL(R, "1900-12-31t04:61");                   \
    VERIFY_PARSE_FAIL(R, "19001231 23:70");                     \
                                                                \
    /* Single digit second */                                   \
    VERIFY_PARSE_FAIL(R, "1900-12-31 03:22:9");                 \
    VERIFY_PARSE_FAIL(R, "19001231T02494");                     \
                                                                \
    /* Out of range second */                                   \
    VERIFY_PARSE_FAIL(R, "1900-12-31t04:23:61");                \
    VERIFY_PARSE_FAIL(R, "19001231 23:12:80");                  \
                                                                \
    /* DecimalSeparator without TimeFractionalPart */           \
    VERIFY_PARSE_FAIL(R, "1900-12-31 03:22:09,");               \
    VERIFY_PARSE_FAIL(R, "19001231T024904.");                   \
                                                                \
    /* TimeFractionalPart too long */                           \
    VERIFY_PARSE_FAIL(R, "1900-12-31 03:22:09,9876543219");     \
    VERIFY_PARSE_FAIL(R, "19001231T024904.1234567890");         \
                                                                \
    /* Legal Date with illegal TimeZoneUTCOffset */             \
    VERIFY_PARSE_FAIL(R, "1900-12-31+1");                       \
    VERIFY_PARSE_FAIL(R, "1900-12-31+12:2");                    \
    VERIFY_PARSE_FAIL(R, "1900-12-31+122");                     \
    VERIFY_PARSE_FAIL(R, "1900-12-31+12:23:3");                 \
    VERIFY_PARSE_FAIL(R, "1900-12-31+12233");                   \
    VERIFY_PARSE_FAIL(R, "1900-12-31+12:23:45.");               \
    VERIFY_PARSE_FAIL(R, "1900-12-31+122345,");                 \
    VERIFY_PARSE_FAIL(R, "1900-12-31+12:23:45.1234567890");     \
    VERIFY_PARSE_FAIL(R, "1900-12-31+122345,0987654321");       \
    /* Legal Date with illegal [TimeZoneIANAName] */            \
    VERIFY_PARSE_FAIL(R, "1900-12-31[.]");                      \
    VERIFY_PARSE_FAIL(R, "1900-12-31[..]");                     \
    VERIFY_PARSE_FAIL(R, "1900-12-31[abc/.]");                  \
    VERIFY_PARSE_FAIL(R, "1900-12-31[abc/..]");                 \
    VERIFY_PARSE_FAIL(R, "1900-12-31[abcdefghijklmno]");        \
    VERIFY_PARSE_FAIL(R, "1900-12-31[abcdefghijklmn/-abcde]");  \
    VERIFY_PARSE_FAIL(R, "1900-12-31[-bcdefghijklmn/abcde]");   \
    VERIFY_PARSE_FAIL(R, "1900-12-31[abcdefghi//abde]");        \
    /* Legal Date with illegal [Etc/GMT ASCIISign Hour] */      \
    VERIFY_PARSE_FAIL(R, "1900-12-31[ETC/GMT+10]");             \
    /* Wrong case for Etc */                                    \
    VERIFY_PARSE_FAIL(R, "1900-12-31[etc/GMT-10]");             \
    /* Wrong case for GMT */                                    \
    VERIFY_PARSE_FAIL(R, "1900-12-31[Etc/gmt+00]");             \
    VERIFY_PARSE_FAIL(R, "1900-12-31[Etc/gmt-00]");             \
    VERIFY_PARSE_FAIL(R, "1900-12-31[Etc/gMt+00]");             \
    VERIFY_PARSE_FAIL(R, "1900-12-31[Etc/gmT-00]");             \
    /* not ASCII sign */                                        \
    VERIFY_PARSE_FAIL(R, "1900-12-31[Etc/GMT\u221200]");        \
    /* Out of range */                                          \
    VERIFY_PARSE_FAIL(R, "1900-12-31[Etc/GMT+24]");             \
    VERIFY_PARSE_FAIL(R, "1900-12-31[Etc/GMT-24]");             \
    /* leading 0 Hour */                                        \
    VERIFY_PARSE_FAIL(R, "1900-12-31[Etc/GMT+02]");             \
    VERIFY_PARSE_FAIL(R, "1900-12-31[Etc/GMT-00]");             \
    VERIFY_PARSE_FAIL(R, "2021-11-09Z[Etc/GMT+01]");            \
    /* Three digit hour */                                      \
    VERIFY_PARSE_FAIL(R, "1900-12-31[Etc/GMT+201]");            \
    VERIFY_PARSE_FAIL(R, "1900-12-31[Etc/GMT-000]");            \
    /* With minute */                                           \
    VERIFY_PARSE_FAIL(R, "1900-12-31[Etc/GMT+05:30]");          \
    VERIFY_PARSE_FAIL(R, "1900-12-31[Etc/GMT+0530]");           \
    /* Legal Date with illegal [TimeZoneUTCOffsetName] */       \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+]");                      \
    VERIFY_PARSE_FAIL(R, "1900-12-31[-]");                      \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+0]");                     \
    VERIFY_PARSE_FAIL(R, "1900-12-31[-1]");                     \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+01:]");                   \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+24]");                    \
    VERIFY_PARSE_FAIL(R, "1900-12-31[-25]");                    \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+01:2]");                  \
    VERIFY_PARSE_FAIL(R, "1900-12-31[-012]");                   \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+01:60]");                 \
    VERIFY_PARSE_FAIL(R, "1900-12-31[-23:60]");                 \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+2360]");                  \
    VERIFY_PARSE_FAIL(R, "1900-12-31[\u22121260]");             \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+01:23:]");                \
    VERIFY_PARSE_FAIL(R, "1900-12-31[-01234]");                 \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+01:23:4]");               \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+01:23:61]");              \
    VERIFY_PARSE_FAIL(R, "1900-12-31[-012372]");                \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+01:23:45.]");             \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+01:23:45,]");             \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+01:23:45.1234567890]");   \
    VERIFY_PARSE_FAIL(R, "1900-12-31[-01:23:45,0000000000]");   \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+01:23:4a]");              \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+01:b3:40]");              \
    VERIFY_PARSE_FAIL(R, "1900-12-31[+abcdefg]");               \
    /* Legal Date with illegal [CalendarName] */                \
    VERIFY_PARSE_FAIL(R, "1900-12-31[u-ca=]");                  \
    VERIFY_PARSE_FAIL(R, "1900-12-31[u-ca=123456789]");         \
    VERIFY_PARSE_FAIL(R, "1900-12-31[u-ca=a]");                 \
    VERIFY_PARSE_FAIL(R, "1900-12-31[u-ca=ab]");                \
    VERIFY_PARSE_FAIL(R, "1900-12-31[u-ca=abcdefghi]");         \
    VERIFY_PARSE_FAIL(R, "1900-12-31[u-ca=a-abcdefgh]");        \
    VERIFY_PARSE_FAIL(R, "1900-12-31[u-ca=ab-abcdefgh]");       \
    VERIFY_PARSE_FAIL(R, "1900-12-31[u-ca=abc-abcdefghi]");     \
    VERIFY_PARSE_FAIL(R, "1900-12-31[u-ca=abc-def-ghijklmno]"); \
  } while (false)

TEST_F(TemporalParserTest, TemporalTimeStringSuccess) {
  // DateTime: Date TimeSpecSeparator_opt TimeZone_opt
  // Date TimeSpecSeparator
  // Differeent DateTimeSeparator: <S> T or t
  VerifyParseTemporalTimeStringSuccess("2021-11-09T01", 1, kUndefined,
                                       kUndefined, kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-12-07t23", 23, kUndefined,
                                       kUndefined, kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-09-31 02", 2, kUndefined,
                                       kUndefined, kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09T0304", 3, 4, kUndefined,
                                       kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-12-07t05:16", 5, 16, kUndefined,
                                       kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-09-31 01:03:04", 1, 3, 4,
                                       kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-09-31 22:59:60", 22, 59, 60,
                                       kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-09-31 215907", 21, 59, 7,
                                       kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-09-31 20:49:37.987654321", 20, 49,
                                       37, 987654321, "");
  VerifyParseTemporalTimeStringSuccess("1964-07-10 19:51:42,123", 19, 51, 42,
                                       123000000, "");
  VerifyParseTemporalTimeStringSuccess("1964-07-10 13:03:60,12345", 13, 3, 60,
                                       123450000, "");
  VerifyParseTemporalTimeStringSuccess("1964-07-10 01:03:04,123456789", 1, 3, 4,
                                       123456789, "");
  VerifyParseTemporalTimeStringSuccess("19640710 09:18:27,12345678", 9, 18, 27,
                                       123456780, "");

  VerifyParseTemporalTimeStringSuccess("2021-11-09T03+11", 3, kUndefined,
                                       kUndefined, kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09t04:55-12:03", 4, 55,
                                       kUndefined, kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09t06:22:01.987654321-12:03", 6,
                                       22, 1, 987654321, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09t073344,98765432-12:03", 7,
                                       33, 44, 987654320, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09t07:33:44,98765432-1203", 7,
                                       33, 44, 987654320, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09 075317,9876543-1203", 7, 53,
                                       17, 987654300, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09T12-13:03:04", 12, kUndefined,
                                       kUndefined, kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09t1122-120304", 11, 22,
                                       kUndefined, kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09 223344-12:03:04.987654321",
                                       22, 33, 44, kUndefined, "");
  VerifyParseTemporalTimeStringSuccess(
      "2021-11-09 234512.9876-12:03:04.987654321", 23, 45, 12, 987600000, "");

  VerifyParseTemporalTimeStringSuccess(
      "2021-11-09T223344.987654321-120304.123456789", 22, 33, 44, 987654321,
      "");
  VerifyParseTemporalTimeStringSuccess(
      "19670316T223344.987654321-120304.123456789", 22, 33, 44, 987654321, "");

  VerifyParseTemporalTimeStringSuccess("2021-11-09T11z", 11, kUndefined,
                                       kUndefined, kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09t12Z", 12, kUndefined,
                                       kUndefined, kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09 01:23Z", 1, 23, kUndefined,
                                       kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09 01:23:45Z", 1, 23, 45,
                                       kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09 01:23:45.678912345Z", 1, 23,
                                       45, 678912345, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09 01:23:45,567891234Z", 1, 23,
                                       45, 567891234, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09 0123Z", 1, 23, kUndefined,
                                       kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09 012345Z", 1, 23, 45,
                                       kUndefined, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09t012345.678912345Z", 1, 23,
                                       45, 678912345, "");
  VerifyParseTemporalTimeStringSuccess("2021-11-09 012345,891234Z", 1, 23, 45,
                                       891234000, "");
  VerifyParseTemporalTimeStringSuccess("20211109T012345,891234567Z", 1, 23, 45,
                                       891234567, "");

  VerifyParseTemporalTimeStringSuccess(
      "2021-11-09 23:45:56.891234567Z[Etc/GMT+23]", 23, 45, 56, 891234567, "");
  // TimeZoneIANAName
  VerifyParseTemporalTimeStringSuccess("2021-11-09T12z[.BCDEFGHIJKLMN]", 12,
                                       kUndefined, kUndefined, kUndefined, "");
  VerifyParseTemporalTimeStringSuccess(
      "2021-11-09T23:45Z[ABCDEFGHIJKLMN/_bcde-ghij_lmn/.peqrstuv]", 23, 45,
      kUndefined, kUndefined, "");
  VerifyParseTemporalTimeStringSuccess(
      "2021-11-09t234534.234+1234[aBcDEfGHiJ.L_N/ABC...G_..KLMN]", 23, 45, 34,
      234000000, "");
  VerifyParseTemporalTimeStringSuccess(
      "2021-11-09 "
      "123456.789123456-012345.789123456[aBcDEfGHiJ.L_N/ABCbcdGfIJKLMN]",
      12, 34, 56, 789123456, "");

  VerifyParseTemporalTimeStringSuccess("2021-11-09 01:23:45.678912345Z", 1, 23,
                                       45, 678912345, "");

  VerifyParseTemporalTimeStringSuccess("2021-03-11T01[u-ca=iso8601]", 1,
                                       kUndefined, kUndefined, kUndefined,
                                       "iso8601");
  VerifyParseTemporalTimeStringSuccess(
      "2021-03-11 02:34[u-ca=abcdefgh-wxyzefg]", 2, 34, kUndefined, kUndefined,
      "abcdefgh-wxyzefg");

  VerifyParseTemporalTimeStringSuccess(
      "2021-11-03 "
      "123456.789-012345.789123456[aBcDEfGHiJ.L_N/"
      "ABCbcdGfIJKLMN][u-ca=abc]",
      12, 34, 56, 789000000, "abc");

  VerifyParseTemporalTimeStringSuccess(
      "2021-03-11T23[+12:34:56,789123456][u-ca=abcdefgh-wxyzefg]", 23,
      kUndefined, kUndefined, kUndefined, "abcdefgh-wxyzefg");
  VerifyParseTemporalTimeStringSuccess(
      "20210311T22:11[\u221200:34:56.789123456][u-ca=abcdefgh-"
      "wxyzefg-ijklmnop]",
      22, 11, kUndefined, kUndefined, "abcdefgh-wxyzefg-ijklmnop");
  VerifyParseTemporalTimeStringSuccess("2021-11-03T23:45:12.345[u-ca=abc]", 23,
                                       45, 12, 345000000, "abc");
  VerifyParseTemporalTimeStringSuccess("2021-11-03 234527[u-ca=iso-8601]", 23,
                                       45, 27, kUndefined, "iso-8601");

  VerifyParseTemporalTimeStringSuccess("2021-11-03t12[u-ca=123456-789]", 12,
                                       kUndefined, kUndefined, kUndefined,
                                       "123456-789");
}

TEST_F(TemporalParse
```