Response: The user wants a summary of the C++ source code file `v8/test/unittests/temporal/temporal-parser-unittest.cc`.
This file seems to be a unit test for a parser related to temporal data, likely adhering to the ISO 8601 standard.

The key functionalities I need to extract are:
1. What the code is testing.
2. What kind of inputs it uses.
3. What kind of checks it performs.
4. If there's any relation to JavaScript, provide an example.

Based on the `#include "src/temporal/temporal-parser.h"` and the comment `// This file test the TemporalParser to parse ISO 8601 according to #sec-temporal-iso8601grammar`, it's clear that this file tests the `TemporalParser` class for its ability to parse ISO 8601 formatted strings related to temporal data.

The presence of `CheckDate`, `CheckTime`, `CheckTimeZoneNumericUTCOffset`, and `CheckDuration` functions suggests the tests verify the correct parsing of different components of temporal strings.

The macros like `IMPL_VERIFY_PARSE_TEMPORAL_DATE_STRING_SUCCESS`, `IMPL_VERIFY_PARSE_TEMPORAL_DATE_TIME_STRING_SUCCESS`, and `IMPL_VERIFY_PARSE_TEMPORAL_ZONED_DATE_TIME_STRING_SUCCESS` indicate the file tests the successful parsing of different temporal types (date, date-time, zoned date-time).

The `TemporalParserTest` class uses these helper functions to run various test cases. The `TEST_F` macros define individual test methods like `TemporalTimeStringSuccess`, `TemporalTimeStringIllegal`, `TemporalDateTimeStringSuccess`, etc., which test both successful and unsuccessful parsing scenarios.

The connection to JavaScript likely lies in the `Temporal` API, a relatively new addition to JavaScript for handling dates and times more effectively than the built-in `Date` object. The V8 JavaScript engine implements this API, and this test file is part of V8's test suite, verifying the correctness of the ISO 8601 parsing functionality within the `Temporal` API.

For the JavaScript example, I can demonstrate how the `Temporal.PlainDate.from()` method (or similar methods for other temporal types) uses ISO 8601 strings as input.
这个C++源代码文件 (`v8/test/unittests/temporal/temporal-parser-unittest.cc`) 是V8 JavaScript引擎的一部分，专门用于测试 `TemporalParser` 类的功能。 `TemporalParser` 的主要职责是根据 ISO 8601 标准解析表示日期、时间和时区的字符串。

具体来说，这个文件的功能可以归纳为：

1. **测试 ISO 8601 格式的日期和时间字符串的解析**:  它包含了大量的测试用例，用于验证 `TemporalParser` 是否能正确地将符合 ISO 8601 规范的不同格式的字符串解析成内部表示。这些格式包括：
    * 仅包含日期的字符串 (例如 "2021-11-03", "20211103")
    * 包含日期和时间的字符串 (例如 "2021-11-09T01:02:03")
    * 包含日期、时间和时区的字符串 (例如 "2021-11-09T01:02:03Z", "2021-11-09T01:02:03+08:00", "2021-11-09T01:02:03[Asia/Shanghai]")
    * 包含年份和月份的字符串 (例如 "2021-11")
    * 包含月份和日期的字符串 (例如 "11-03")
    * 包含 UTC 偏移量的字符串 (例如 "+08:00", "-05:30")
    * 包含日历名称的字符串 (例如 "[u-ca=iso8601]")

2. **验证解析结果的正确性**:  文件中定义了多个 `Check...` 函数 (例如 `CheckDate`, `CheckTime`, `CheckTimeZoneNumericUTCOffset`)，用于比较 `TemporalParser` 的解析结果与预期值是否一致。这些检查覆盖了年、月、日、时、分、秒、纳秒以及时区偏移等各个组成部分。

3. **测试成功的解析场景**:  通过 `VerifyParseTemporal...StringSuccess` 宏和相关的函数，测试 `TemporalParser` 在接收到合法的 ISO 8601 字符串时能否成功解析并得到预期的结果。

4. **测试失败的解析场景**:  通过 `VERIFY_PARSE_FAIL` 宏，测试 `TemporalParser` 在接收到非法的 ISO 8601 字符串时能否正确地识别并返回解析失败。这有助于确保解析器的鲁棒性。

5. **涉及 JavaScript 的 `Temporal` API**:  `TemporalParser` 是 V8 引擎实现 JavaScript 中新的 `Temporal` API 的关键组成部分。`Temporal` API 旨在提供更现代、更易用的日期和时间处理方式，替代旧的 `Date` 对象。  这个单元测试文件确保了 V8 的 `Temporal` API 在处理符合 ISO 8601 标准的日期和时间字符串时能够正常工作。

**与 JavaScript 功能的关系及示例**

这个 C++ 文件测试的 `TemporalParser` 功能直接对应于 JavaScript 中 `Temporal` API 中各种 `from()` 方法或者直接创建 `Temporal` 对象时对 ISO 8601 字符串的解析。

**JavaScript 示例:**

```javascript
// 使用 Temporal.PlainDate.from() 解析 ISO 8601 日期字符串
const plainDate = Temporal.PlainDate.from("2023-10-27");
console.log(plainDate.year); // 输出: 2023
console.log(plainDate.month); // 输出: 10
console.log(plainDate.day);   // 输出: 27

// 使用 Temporal.ZonedDateTime.from() 解析带时区的 ISO 8601 日期时间字符串
const zonedDateTime = Temporal.ZonedDateTime.from("2023-10-27T10:30:00+08:00[Asia/Shanghai]");
console.log(zonedDateTime.year);       // 输出: 2023
console.log(zonedDateTime.month);      // 输出: 10
console.log(zonedDateTime.day);         // 输出: 27
console.log(zonedDateTime.hour);        // 输出: 10
console.log(zonedDateTime.minute);      // 输出: 30
console.log(zonedDateTime.timeZoneId);  // 输出: Asia/Shanghai

// 尝试解析非法的 ISO 8601 字符串会抛出 RangeError 或 TypeError
try {
  Temporal.PlainDate.from("2023-13-01"); // 月份超出范围
} catch (e) {
  console.error(e); // 输出 RangeError
}
```

在 V8 引擎的内部实现中，当 JavaScript 代码调用 `Temporal.PlainDate.from("2023-10-27")` 时，V8 会调用 `TemporalParser` 来解析 "2023-10-27" 这个字符串。 这个 C++ 测试文件中的用例，例如 `VerifyParseTemporalDateStringSuccess("2021-11-03", 2021, 11, 03, "")`，就是为了确保这个解析过程在 V8 内部能够正确进行。

总而言之，这个 C++ 文件是 V8 引擎中用于保证 `Temporal` API 能够正确解析 ISO 8601 格式日期和时间字符串的关键测试组件。

### 提示词
```
这是目录为v8/test/unittests/temporal/temporal-parser-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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

TEST_F(TemporalParserTest, TemporalTimeStringIllegal) {
  VERIFY_PARSE_FAIL_ON_DATE(TemporalTimeString);
  VERIFY_PARSE_FAIL(TemporalTimeString, "");

  VERIFY_PARSE_FAIL(TemporalTimeString,
                    "2021-03-11t03:45.67[u-ca=abcdefgh-wxyzefg-ijklmnop]");
  // Single digit Hour
  VERIFY_PARSE_FAIL(TemporalTimeString, "0");
  VERIFY_PARSE_FAIL(TemporalTimeString, "9");
  // out of range Hour
  VERIFY_PARSE_FAIL(TemporalTimeString, "99");
  VERIFY_PARSE_FAIL(TemporalTimeString, "24");
  // Single digit Hour or TimeMinute
  VERIFY_PARSE_FAIL(TemporalTimeString, "000");
  VERIFY_PARSE_FAIL(TemporalTimeString, "111");
  VERIFY_PARSE_FAIL(TemporalTimeString, "00:0");
  VERIFY_PARSE_FAIL(TemporalTimeString, "11:1");
  VERIFY_PARSE_FAIL(TemporalTimeString, "0:00");
  VERIFY_PARSE_FAIL(TemporalTimeString, "1:11");
  // out of range Hour TimeMinute
  VERIFY_PARSE_FAIL(TemporalTimeString, "2400");
  VERIFY_PARSE_FAIL(TemporalTimeString, "24:00");
  VERIFY_PARSE_FAIL(TemporalTimeString, "23:60");
  // out of range Hour TimeMinute or TimeSecond
  VERIFY_PARSE_FAIL(TemporalTimeString, "24:00:01");
  VERIFY_PARSE_FAIL(TemporalTimeString, "23:60:01");
  VERIFY_PARSE_FAIL(TemporalTimeString, "23:59:61");

  // Single digit Hour, TimeMinute or TimeSecond
  VERIFY_PARSE_FAIL(TemporalTimeString, "00000");
  VERIFY_PARSE_FAIL(TemporalTimeString, "22222");
  VERIFY_PARSE_FAIL(TemporalTimeString, "00:00:0");
  VERIFY_PARSE_FAIL(TemporalTimeString, "22:2:22");
  VERIFY_PARSE_FAIL(TemporalTimeString, "3:33:33");
  VERIFY_PARSE_FAIL(TemporalTimeString, "444:444");
  VERIFY_PARSE_FAIL(TemporalTimeString, "44444.567");
  VERIFY_PARSE_FAIL(TemporalTimeString, "44444,567");

  // wrong separator
  VERIFY_PARSE_FAIL(TemporalTimeString, "12:34:56 5678");

  // out of range Hour TimeMinute, TimeSecond or TimeFraction
  VERIFY_PARSE_FAIL(TemporalTimeString, "12:34:56.1234567890");
  VERIFY_PARSE_FAIL(TemporalTimeString, "24:01:02.123456789");
  VERIFY_PARSE_FAIL(TemporalTimeString, "23:60:02.123456789");
  VERIFY_PARSE_FAIL(TemporalTimeString, "23:59:61.123456789");
  VERIFY_PARSE_FAIL(TemporalTimeString, "23:33:44.0000000000");

  VERIFY_PARSE_FAIL(TemporalTimeString, "1900-12-31[Etc/GMT+2]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "1900-12-31[Etc/GMT-0]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "1900-12-31[Etc/GMT-0]");

  // Date TimeZone
  // DateExtendedYear
  VERIFY_PARSE_FAIL(TemporalTimeString, "+002021-11-03");
  VERIFY_PARSE_FAIL(TemporalTimeString, "+000001-11-03");
  VERIFY_PARSE_FAIL(TemporalTimeString, "+0020211103");
  VERIFY_PARSE_FAIL(TemporalTimeString, "+0000011231");
  VERIFY_PARSE_FAIL(TemporalTimeString, "+0000000101");
  VERIFY_PARSE_FAIL(TemporalTimeString, "+0000000101");
  VERIFY_PARSE_FAIL(TemporalTimeString, "+654321-11-03");
  VERIFY_PARSE_FAIL(TemporalTimeString, "+999999-12-31");
  VERIFY_PARSE_FAIL(TemporalTimeString, "-654321-11-03");
  VERIFY_PARSE_FAIL(TemporalTimeString, "-999999-12-31");
  VERIFY_PARSE_FAIL(TemporalTimeString, "\u2212999999-12-31");
  VERIFY_PARSE_FAIL(TemporalTimeString, "+6543211103");
  VERIFY_PARSE_FAIL(TemporalTimeString, "+9999991231");
  VERIFY_PARSE_FAIL(TemporalTimeString, "-6543211103");
  VERIFY_PARSE_FAIL(TemporalTimeString, "-9999991231");
  VERIFY_PARSE_FAIL(TemporalTimeString, "\u22129999991231");

  // Date TimeZone
  // Date TimeZoneOffsetRequired
  // Date TimeZoneUTCOffset TimeZoneBracketedAnnotation_opt
  // Date TimeZoneNumericUTCOffset
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09+11");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09-12:03");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09-1203");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09-12:03:04");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09-120304");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09-12:03:04,987654321");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09-120304.987654321");

  // Date UTCDesignator
  // Date UTCDesignator
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09z");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09Z");

  // Date TimeZoneNameRequired
  // Date TimeZoneBracketedAnnotation
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09[Etc/GMT+01]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09[Etc/GMT-23]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09[Etc/GMT+23]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09[Etc/GMT-00]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09[Etc/GMT+01]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09[Etc/GMT-23]");

  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09[ABCDEFGHIJKLMN]");
  VERIFY_PARSE_FAIL(TemporalTimeString,
                    "2021-11-09[ABCDEFGHIJKLMN/abcdefghijklmn/opeqrstuv]");
  VERIFY_PARSE_FAIL(TemporalTimeString,
                    "2021-11-09[aBcDEfGHiJ.L_N/ABC...G_..KLMN]");
  VERIFY_PARSE_FAIL(TemporalTimeString,
                    "2021-11-09[aBcDE-GHiJ.L_N/ABCbcdG-IJKLMN]");
  // TimeZoneUTCOffsetName
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09[+12]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09[+12:34]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09[+12:34:56]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09[+12:34:56,789123456]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09[+12:34:56.789123456]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-09[\u221200:34:56.789123456]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-03-11[u-ca=iso8601]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-03-11[u-ca=abcdefgh-wxyzefg]");
  VERIFY_PARSE_FAIL(TemporalTimeString,
                    "2021-03-11[u-ca=abcdefgh-wxyzefg-ijklmnop]");

  VERIFY_PARSE_FAIL(TemporalTimeString,
                    "2021-03-11[+12:34:56,789123456][u-ca=abcdefgh-wxyzefg]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-03[u-ca=abc]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-03[u-ca=iso-8601]");
  VERIFY_PARSE_FAIL(TemporalTimeString, "2021-11-03[u-ca=123456-789]");
}

#define IMPL_DATE_TIME_STRING_SUCCESS(R)                                       \
  do {                                                                         \
    /* CalendarDateTime : DateTime Calendaropt */                              \
    /* DateTime */                                                             \
    /* DateYear - DateMonth - DateDay */                                       \
    VerifyParse##R##Success("2021-11-03", 2021, 11, 03, kUndefined,            \
                            kUndefined, kUndefined, kUndefined, "");           \
    /* DateYear DateMonth DateDay */                                           \
    VerifyParse##R##Success("20211103", 2021, 11, 03, kUndefined, kUndefined,  \
                            kUndefined, kUndefined, "");                       \
    /* DateExtendedYear */                                                     \
    VerifyParse##R##Success("+002021-11-03", 2021, 11, 03, kUndefined,         \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("+000001-11-03", 1, 11, 03, kUndefined,            \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("+0020211103", 2021, 11, 03, kUndefined,           \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("+0000011231", 1, 12, 31, kUndefined, kUndefined,  \
                            kUndefined, kUndefined, "");                       \
    VerifyParse##R##Success("+0000000101", 0, 1, 1, kUndefined, kUndefined,    \
                            kUndefined, kUndefined, "");                       \
    VerifyParse##R##Success("+0000000101", 0, 1, 1, kUndefined, kUndefined,    \
                            kUndefined, kUndefined, "");                       \
    VerifyParse##R##Success("+654321-11-03", 654321, 11, 3, kUndefined,        \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("+999999-12-31", 999999, 12, 31, kUndefined,       \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("-654321-11-03", -654321, 11, 3, kUndefined,       \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("-999999-12-31", -999999, 12, 31, kUndefined,      \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("\u2212999999-12-31", -999999, 12, 31, kUndefined, \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("+6543211103", 654321, 11, 3, kUndefined,          \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("+9999991231", 999999, 12, 31, kUndefined,         \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("-6543211103", -654321, 11, 3, kUndefined,         \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("-9999991231", -999999, 12, 31, kUndefined,        \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("\u22129999991231", -999999, 12, 31, kUndefined,   \
                            kUndefined, kUndefined, kUndefined, "");           \
                                                                               \
    /* DateTime: Date TimeSpecSeparator_opt TimeZone_opt */                    \
    /* Date TimeSpecSeparator */                                               \
    /* Differeent DateTimeSeparator: <S> T or t */                             \
    VerifyParse##R##Success("2021-11-09T01", 2021, 11, 9, 1, kUndefined,       \
                            kUndefined, kUndefined, "");                       \
    VerifyParse##R##Success("2021-12-07t01", 2021, 12, 7, 1, kUndefined,       \
                            kUndefined, kUndefined, "");                       \
    VerifyParse##R##Success("2021-09-31 01", 2021, 9, 31, 1, kUndefined,       \
                            kUndefined, kUndefined, "");                       \
    VerifyParse##R##Success("2021-11-09T0102", 2021, 11, 9, 1, 2, kUndefined,  \
                            kUndefined, "");                                   \
    VerifyParse##R##Success("2021-12-07t01:02", 2021, 12, 7, 1, 2, kUndefined, \
                            kUndefined, "");                                   \
    VerifyParse##R##Success("2021-09-31 01:03:04", 2021, 9, 31, 1, 3, 4,       \
                            kUndefined, "");                                   \
    VerifyParse##R##Success("2021-09-31 01:03:60", 2021, 9, 31, 1, 3, 60,      \
                            kUndefined, "");                                   \
    VerifyParse##R##Success("2021-09-31 010304", 2021, 9, 31, 1, 3, 4,         \
                            kUndefined, "");                                   \
    VerifyParse##R##Success("2021-09-31 01:03:04.987654321", 2021, 9, 31, 1,   \
                            3, 4, 987654321, "");                              \
    VerifyParse##R##Success("1964-07-10 01:03:04,1", 1964, 7, 10, 1, 3, 4,     \
                            100000000, "");                                    \
    VerifyParse##R##Success("1964-07-10 01:03:60,1", 1964, 7, 10, 1, 3, 60,    \
                            100000000, "");                                    \
    VerifyParse##R##Success("1964-07-10 01:03:04,123456789", 1964, 7, 10, 1,   \
                            3, 4, 123456789, "");                              \
    VerifyParse##R##Success("19640710 01:03:04,123456789", 1964, 7, 10, 1, 3,  \
                            4, 123456789, "");                                 \
    /* Date TimeZone */                                                        \
    /* Date TimeZoneOffsetRequired */                                          \
    /* Date TimeZoneUTCOffset TimeZoneBracketedAnnotation_opt */               \
    /* Date TimeZoneNumericUTCOffset */                                        \
    VerifyParse##R##Success("2021-11-09+11", 2021, 11, 9, kUndefined,          \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09-12:03", 2021, 11, 9, kUndefined,       \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09-1203", 2021, 11, 9, kUndefined,        \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09-12:03:04", 2021, 11, 9, kUndefined,    \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09-120304", 2021, 11, 9, kUndefined,      \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09-12:03:04,987654321", 2021, 11, 9,      \
                            kUndefined, kUndefined, kUndefined, kUndefined,    \
                            "");                                               \
    VerifyParse##R##Success("2021-11-09-120304.123456789", 2021, 11, 9,        \
                            kUndefined, kUndefined, kUndefined, kUndefined,    \
                            "");                                               \
    VerifyParse##R##Success("2021-11-09T03+11", 2021, 11, 9, 3, kUndefined,    \
                            kUndefined, kUndefined, "");                       \
    VerifyParse##R##Success("2021-11-09t04:55-12:03", 2021, 11, 9, 4, 55,      \
                            kUndefined, kUndefined, "");                       \
    VerifyParse##R##Success("2021-11-09t06:22:01.987654321", 2021, 11, 9, 6,   \
                            22, 1, 987654321, "");                             \
    VerifyParse##R##Success("2021-11-09t062202,987654321", 2021, 11, 9, 6, 22, \
                            2, 987654321, "");                                 \
    VerifyParse##R##Success("2021-11-09t06:22:03.987654321-1203", 2021, 11, 9, \
                            6, 22, 3, 987654321, "");                          \
    VerifyParse##R##Success("2021-11-09 062204.987654321-1203", 2021, 11, 9,   \
                            6, 22, 4, 987654321, "");                          \
                                                                               \
    VerifyParse##R##Success("2021-11-09T12-12:03:04", 2021, 11, 9, 12,         \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09t1122-120304", 2021, 11, 9, 11, 22,     \
                            kUndefined, kUndefined, "");                       \
    VerifyParse##R##Success("2021-11-09 223344-12:03:04,987654321", 2021, 11,  \
                            9, 22, 33, 44, kUndefined, "");                    \
    VerifyParse##R##Success("2021-11-09T223344.987654321-120304.123456789",    \
                            2021, 11, 9, 22, 33, 44, 987654321, "");           \
    VerifyParse##R##Success("19670316T223344.987654321-120304.123456789",      \
                            1967, 3, 16, 22, 33, 44, 987654321, "");           \
    /* Date UTCDesignator */                                                   \
    VerifyParse##R##Success("2021-11-09z", 2021, 11, 9, kUndefined,            \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09Z", 2021, 11, 9, kUndefined,            \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09T11z", 2021, 11, 9, 11, kUndefined,     \
                            kUndefined, kUndefined, "");                       \
    VerifyParse##R##Success("2021-11-09t12Z", 2021, 11, 9, 12, kUndefined,     \
                            kUndefined, kUndefined, "");                       \
    VerifyParse##R##Success("2021-11-09 01:23Z", 2021, 11, 9, 1, 23,           \
                            kUndefined, kUndefined, "");                       \
    VerifyParse##R##Success("2021-11-09 01:23:45Z", 2021, 11, 9, 1, 23, 45,    \
                            kUndefined, "");                                   \
    VerifyParse##R##Success("2021-11-09 01:23:45.678912345Z", 2021, 11, 9, 1,  \
                            23, 45, 678912345, "");                            \
    VerifyParse##R##Success("2021-11-09 01:23:45,567891234Z", 2021, 11, 9, 1,  \
                            23, 45, 567891234, "");                            \
    VerifyParse##R##Success("2021-11-09 0123Z", 2021, 11, 9, 1, 23,            \
                            kUndefined, kUndefined, "");                       \
    VerifyParse##R##Success("2021-11-09 012345Z", 2021, 11, 9, 1, 23, 45,      \
                            kUndefined, "");                                   \
    VerifyParse##R##Success("2021-11-09t012345.678912345Z", 2021, 11, 9, 1,    \
                            23, 45, 678912345, "");                            \
    VerifyParse##R##Success("2021-11-09 012345,891234567Z", 2021, 11, 9, 1,    \
                            23, 45, 891234567, "");                            \
    VerifyParse##R##Success("20211109T012345,891234567Z", 2021, 11, 9, 1, 23,  \
                            45, 891234567, "");                                \
    /* Date TimeZoneNameRequired */                                            \
    /* Date TimeZoneBracketedAnnotation */                                     \
    VerifyParse##R##Success("2021-11-09[Etc/GMT+1]", 2021, 11, 9, kUndefined,  \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09[Etc/GMT-23]", 2021, 11, 9, kUndefined, \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09[Etc/GMT+23]", 2021, 11, 9, kUndefined, \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09[Etc/GMT-0]", 2021, 11, 9, kUndefined,  \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09Z[Etc/GMT+1]", 2021, 11, 9, kUndefined, \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09z[Etc/GMT-23]", 2021, 11, 9,            \
                            kUndefined, kUndefined, kUndefined, kUndefined,    \
                            "");                                               \
    VerifyParse##R##Success("2021-11-09 23:45:56.891234567Z[Etc/GMT+23]",      \
                            2021, 11, 9, 23, 45, 56, 891234567, "");           \
    /* TimeZoneIANAName */                                                     \
    VerifyParse##R##Success("2021-11-09[ABCDEFGHIJKLMN]", 2021, 11, 9,         \
                            kUndefined, kUndefined, kUndefined, kUndefined,    \
                            "");                                               \
    VerifyParse##R##Success(                                                   \
        "2021-11-09[ABCDEFGHIJKLMN/abcdefghijklmn/opeqrstuv]", 2021, 11, 9,    \
        kUndefined, kUndefined, kUndefined, kUndefined, "");                   \
    VerifyParse##R##Success("2021-11-09[aBcDEfGHiJ.L_N/ABC...G_..KLMN]", 2021, \
                            11, 9, kUndefined, kUndefined, kUndefined,         \
                            kUndefined, "");                                   \
    VerifyParse##R##Success("2021-11-09[aBcDE-GHiJ.L_N/ABCbcdG-IJKLMN]", 2021, \
                            11, 9, kUndefined, kUndefined, kUndefined,         \
                            kUndefined, "");                                   \
    VerifyParse##R##Success("2021-11-09T12z[.BCDEFGHIJKLMN]", 2021, 11, 9, 12, \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success(                                                   \
        "2021-11-09T23:45Z[ABCDEFGHIJKLMN/_bcde-ghij_lmn/.peqrstuv]", 2021,    \
        11, 9, 23, 45, kUndefined, kUndefined, "");                            \
    VerifyParse##R##Success(                                                   \
        "2021-11-09t234534.234+1234[aBcDEfGHiJ.L_N/ABC...G_..KLMN]", 2021, 11, \
        9, 23, 45, 34, 234000000, "");                                         \
    VerifyParse##R##Success(                                                   \
                                                                               \
        "2021-11-09 "                                                          \
        "123456.789123456-012345.789123456[aBcDEfGHiJ.L_N/ABCbcdGfIJKLMN]",    \
        2021, 11, 9, 12, 34, 56, 789123456, "");                               \
    /* TimeZoneUTCOffsetName */                                                \
    VerifyParse##R##Success("2021-11-09[+12]", 2021, 11, 9, kUndefined,        \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09[+12:34]", 2021, 11, 9, kUndefined,     \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09[-12:34:56]", 2021, 11, 9, kUndefined,  \
                            kUndefined, kUndefined, kUndefined, "");           \
    VerifyParse##R##Success("2021-11-09[+12:34:56,789123456]", 2021, 11, 9,    \
                            kUndefined, kUndefined, kUndefined, kUndefined,    \
                            "");                                               \
    VerifyParse##R##Success("2021-11-09[+12:34:56.789123456]", 2021, 11, 9,    \
                            kUndefined, kUndefined, kUndefined, kUndefined,    \
                            "");                                               \
    VerifyParse##R##Success("2021-11-09[\u221200:34:56.789123456]", 2021, 11,  \
                            9, kUndefined, kUndefined, kUndefined, kUndefined, \
                            "");                                               \
                                                                               \
    /* Date TimeSpecSeparator TimeZone */                                      \
    /* DateTime Calendaropt */                                                 \
    VerifyParse##R##Success("2021-11-03[u-ca=abc]", 2021, 11, 03, kUndefined,  \
                            kUndefined, kUndefined, kUndefined, "abc");        \
    VerifyParse##R##Success("2021-11-03[u-ca=iso-8601]", 2021, 11, 03,         \
                            kUndefined, kUndefined, kUndefined, kUndefined,    \
                            "iso-8601");                                       \
    VerifyParse##R##Success("2021-11-03[u-ca=123456-789]", 2021, 11, 03,       \
                            kUndefined, kUndefined, kUndefined, kUndefined,    \
                            "123456-789");                                     \
    VerifyParse##R##Success("2021-03-11[u-ca=abcdefgh-wxyzefg]", 2021, 3, 11,  \
                            kUndefined, kUndefined, kUndefined, kUndefined,    \
                            "abcdefgh-wxyzefg");                               \
    VerifyParse##R##Success("2021-03-11[u-ca=abcdefgh-wxyzefg-ijklmnop]",      \
                            2021, 3, 11, kUndefined, kUndefined, kUndefined,   \
                            kUndefined, "abcdefgh-wxyzefg-ijklmnop");          \
                                                                               \
    VerifyParse##R##Success(                                                   \
                                                                               \
        "2021-11-03 "                                                          \
        "123456.789123456-012345.789123456[aBcDEfGHiJ.L_N/"                    \
        "ABCbcdGfIJKLMN][u-ca=abc]",                                           \
        2021, 11, 03, 12, 34, 56, 789123456, "abc");                           \
    VerifyParse##R##Success(                                                   \
        "2021-03-11[+12:34:56,789123456][u-ca=abcdefgh-wxyzefg]", 2021, 3, 11, \
        kUndefined, kUndefined, kUndefined, kUndefined, "abcdefgh-wxyzefg");   \
    VerifyParse##R##Success(                                                   \
        "20210311[\u221200:34:56.789123456][u-ca="                             \
        "abcdefgh-wxyzefg-ijklmnop]",                                          \
        2021, 3, 11, kUndefined, kUndefined, kUndefined, kUndefined,           \
        "abcdefgh-wxyzefg-ijklmnop");                                          \
    VerifyParse##R##Success("2021-11-09 01:23:45.678912345Z", 2021, 11, 9, 1,  \
                            23, 45, 678912345, "");                            \
  } while (false)

TEST_F(TemporalParserTest, TemporalDateTimeStringSuccess) {
  IMPL_DATE_TIME_STRING_SUCCESS(TemporalDateTimeString);
}

TEST_F(TemporalParserTest, TemporalDateTimeStringIllegal) {
  VERIFY_PARSE_FAIL_ON_DATE(TemporalDateTimeString);
  VERIFY_PARSE_FAIL(TemporalDateTimeString, "+20210304");
  VERIFY_PARSE_FAIL(TemporalDateTimeString, "-20210304");
  VERIFY_PARSE_FAIL(TemporalDateTimeString, "\u221220210304");
  VERIFY_PARSE_FAIL(TemporalDateTimeString, "210304");
  // It is a Syntax Error if DateExtendedYear is "-000000"
  VERIFY_PARSE_FAIL(TemporalDateTimeString, "-0000000304");
  VERIFY_PARSE_FAIL(TemporalDateTimeString, "\u22120000000304");
}

TEST_F(TemporalParserTest, TemporalYearMonthStringSuccess) {
  // TemporalYearMonthString :
  //   DateSpecYearMonth
  //   DateTime

  // DateSpecYearMonth:
  //   DateYear -opt DateMonth
  VerifyParseTemporalYearMonthStringSuccess("2021-11", 2021, 11, kUndefined,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("202111", 2021, 11, kUndefined, "");
  VerifyParseTemporalYearMonthStringSuccess("+002021-11", 2021, 11, kUndefined,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("-002021-02", -2021, 02, kUndefined,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("-98765412", -987654, 12,
                                            kUndefined, "");

  // DateTime:
  // DateYear - DateMonth - DateDay
  VerifyParseTemporalYearMonthStringSuccess("2021-11-03", 2021, 11, 03, "");
  // DateYear DateMonth DateDay
  VerifyParseTemporalYearMonthStringSuccess("20211103", 2021, 11, 03, "");
  // DateExtendedYear
  VerifyParseTemporalYearMonthStringSuccess("+002021-11-03", 2021, 11, 03, "");
  VerifyParseTemporalYearMonthStringSuccess("+000001-11-03", 1, 11, 03, "");
  VerifyParseTemporalYearMonthStringSuccess("+0020211103", 2021, 11, 03, "");
  VerifyParseTemporalYearMonthStringSuccess("+0000011231", 1, 12, 31, "");
  VerifyParseTemporalYearMonthStringSuccess("+0000000101", 0, 1, 1, "");
  VerifyParseTemporalYearMonthStringSuccess("+0000000101", 0, 1, 1, "");
  VerifyParseTemporalYearMonthStringSuccess("+654321-11-03", 654321, 11, 3, "");
  VerifyParseTemporalYearMonthStringSuccess("+999999-12-31", 999999, 12, 31,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("-654321-11-03", -654321, 11, 3,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("-999999-12-31", -999999, 12, 31,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("\u2212999999-12-31", -999999, 12,
                                            31, "");
  VerifyParseTemporalYearMonthStringSuccess("+6543211103", 654321, 11, 3, "");
  VerifyParseTemporalYearMonthStringSuccess("+9999991231", 999999, 12, 31, "");
  VerifyParseTemporalYearMonthStringSuccess("-6543211103", -654321, 11, 3, "");
  VerifyParseTemporalYearMonthStringSuccess("-9999991231", -999999, 12, 31, "");
  VerifyParseTemporalYearMonthStringSuccess("\u22129999991231", -999999, 12, 31,
                                            "");

  // DateTime: Date TimeSpecSeparator_opt TimeZone_opt
  // Date TimeSpecSeparator
  // Differeent DateTimeSeparator: <S> T or t
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09T01", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-12-07t01", 2021, 12, 7, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-09-31 01", 2021, 9, 31, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09T0102", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-12-07t01:02", 2021, 12, 7,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("2021-09-31 01:03:04", 2021, 9, 31,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("2021-09-31 01:03:60", 2021, 9, 31,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("2021-09-31 010304", 2021, 9, 31,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("2021-09-31 01:03:04.987654321",
                                            2021, 9, 31, "");
  VerifyParseTemporalYearMonthStringSuccess("1964-07-10 01:03:04,1", 1964, 7,
                                            10, "");
  VerifyParseTemporalYearMonthStringSuccess("1964-07-10 01:03:60,1", 1964, 7,
                                            10, "");
  VerifyParseTemporalYearMonthStringSuccess("1964-07-10 01:03:04,123456789",
                                            1964, 7, 10, "");
  VerifyParseTemporalYearMonthStringSuccess("19640710 01:03:04,123456789", 1964,
                                            7, 10, "");
  // Date TimeZone
  // Date TimeZoneOffsetRequired
  // Date TimeZoneUTCOffset TimeZoneBracketedAnnotation_opt
  // Date TimeZoneNumericUTCOffset
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09+11", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09-12:03", 2021, 11, 9,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09-1203", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09-12:03:04", 2021, 11, 9,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09-120304", 2021, 11, 9,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09-12:03:04,987654321",
                                            2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09-120304.123456789", 2021,
                                            11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09T03+11", 2021, 11, 9,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09t04:55-12:03", 2021, 11,
                                            9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09t06:22:01.987654321",
                                            2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09t062202,987654321", 2021,
                                            11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess(
      "2021-11-09t06:22:03.987654321-1203", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09 062204.987654321-1203",
                                            2021, 11, 9, "");

  VerifyParseTemporalYearMonthStringSuccess("2021-11-09T12-12:03:04", 2021, 11,
                                            9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09t1122-120304", 2021, 11,
                                            9, "");
  VerifyParseTemporalYearMonthStringSuccess(
      "2021-11-09 223344-12:03:04,987654321", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess(
      "2021-11-09T223344.987654321-120304.123456789", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess(
      "19670316T223344.987654321-120304.123456789", 1967, 3, 16, "");
  // Date UTCDesignator
  // Date UTCDesignator
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09z", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09Z", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09T11z", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09t12Z", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09 01:23Z", 2021, 11, 9,
                                            "");
  Verify
```