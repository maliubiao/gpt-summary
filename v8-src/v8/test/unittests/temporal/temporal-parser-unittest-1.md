Response: The user has provided the second part of a C++ source code file that defines unit tests for parsing temporal data types. The goal is to understand the functionality of this specific part and relate it to JavaScript if possible.

**Plan:**

1. **Identify the major test categories:** Look for `TEST_F` macros to understand which parsing functions are being tested in this part.
2. **Analyze individual tests within each category:** Examine the `VerifyParse...Success` and `VERIFY_PARSE_FAIL` macros to understand what valid and invalid inputs are being tested.
3. **Infer the functionality being tested:** Based on the input strings and expected outputs, determine the specific parsing rules being validated.
4. **Relate to JavaScript:** If the tested functionality has equivalents in JavaScript's `Temporal` API, provide illustrative examples.
这是v8 JavaScript引擎中关于 `Temporal` API 中字符串解析功能的单元测试的第二部分。延续第一部分，这部分主要测试了以下 `Temporal` 对象的字符串解析：

* **`TemporalYearMonthString` (年-月字符串):**  测试成功和失败的年-月格式字符串解析。
* **`TemporalMonthDayString` (月-日字符串):** 测试成功和失败的月-日格式字符串解析，包括各种日期和时间组合，以及时区信息的解析。
* **`TemporalInstantString` (瞬时字符串):** 测试成功和失败的瞬时时间格式字符串解析，重点在于 UTC 偏移量的解析。
* **`TemporalZonedDateTimeString` (带时区的时间字符串):** 测试成功和失败的带有时区信息的时间日期字符串解析。
* **`TemporalDurationString` (持续时间字符串):** 测试各种有效和无效的持续时间字符串格式，包括正负号、不同单位、小数部分等。
* **`TimeZoneNumericUTCOffset` (数字 UTC 偏移量):**  测试各种有效和无效的数字 UTC 偏移量格式解析。
* **`TimeZoneIdentifier` (时区标识符):** 测试各种有效的时区标识符 (例如 "Etc/GMT+1", "Asia/Taipei", "+08:00") 的解析。
* **`CalendarName` (日历名称):** 测试有效的日历名称 (例如 "chinese", "roc") 的解析。

**与 JavaScript 功能的关系和示例:**

这个 C++ 文件中的测试代码直接对应于 JavaScript `Temporal` API 中各种对象的 `from()` 方法的字符串解析功能。`Temporal` API 旨在提供更现代和易用的日期和时间处理方式。

**JavaScript 示例:**

* **`TemporalYearMonthString`:**

```javascript
const yearMonth1 = Temporal.YearMonth.from('2021-11');
console.log(yearMonth1.year); // 输出: 2021
console.log(yearMonth1.month); // 输出: 11

const yearMonth2 = Temporal.YearMonth.from('202111');
console.log(yearMonth2.year); // 输出: 2021
console.log(yearMonth2.month); // 输出: 11

// 对应 C++ 中失败的测试
try {
  Temporal.YearMonth.from('+2021-12');
} catch (e) {
  console.error(e); // 抛出 RangeError 或 TypeError
}
```

* **`TemporalMonthDayString`:**

```javascript
const monthDay1 = Temporal.PlainMonthDay.from('--11-03');
console.log(monthDay1.month); // 输出: 11
console.log(monthDay1.day);   // 输出: 3

const monthDay2 = Temporal.PlainMonthDay.from('2021-11-03');
console.log(monthDay2.month); // 输出: 11
console.log(monthDay2.day);   // 输出: 3

// 对应 C++ 中失败的测试
try {
  Temporal.PlainMonthDay.from('--13-23');
} catch (e) {
  console.error(e); // 抛出 RangeError 或 TypeError
}
```

* **`TemporalInstantString`:**

```javascript
const instant1 = Temporal.Instant.from('2021-11-09Z');
console.log(instant1.epochNanoseconds); // 输出一个大的数字，表示自 Unix 纪元以来的纳秒数

const instant2 = Temporal.Instant.from('2021-11-09T12:34:56.987654321Z');
console.log(instant2.epochNanoseconds);

const instant3 = Temporal.Instant.from('20211109+00'); // UTC 偏移量
console.log(instant3.epochNanoseconds);

// 对应 C++ 中失败的测试
try {
  Temporal.Instant.from('202111090');
} catch (e) {
  console.error(e); // 抛出 RangeError 或 TypeError
}
```

* **`TemporalZonedDateTimeString`:**

```javascript
const zonedDateTime1 = Temporal.ZonedDateTime.from('2021-11-03T02:03:04.56789Z[Asia/Taipei]');
console.log(zonedDateTime1.timeZone.id); // 输出: Asia/Taipei
console.log(zonedDateTime1.nanosecond); // 输出: 567890000

// 对应 C++ 中失败的测试
try {
  Temporal.ZonedDateTime.from('20210304');
} catch (e) {
  console.error(e); // 抛出 RangeError 或 TypeError
}
```

* **`TemporalDurationString`:**

```javascript
const duration1 = Temporal.Duration.from('PT0S');
console.log(duration1.total('seconds')); // 输出: 0

const duration2 = Temporal.Duration.from('P1Y2M3W4DT5.6H7.8M9.1S');
console.log(duration2.years);     // 输出: 1
console.log(duration2.months);    // 输出: 2
console.log(duration2.weeks);     // 输出: 3
console.log(duration2.days);      // 输出: 4
console.log(duration2.hours);     // 输出: 5
console.log(duration2.minutes);   // 输出: 7
console.log(duration2.seconds);   // 输出: 9
console.log(duration2.milliseconds);// 输出: 100

// 对应 C++ 中失败的测试
try {
  Temporal.Duration.from('1Y');
} catch (e) {
  console.error(e); // 抛出 RangeError 或 TypeError
}
```

总之，这部分 C++ 单元测试代码旨在全面验证 v8 JavaScript 引擎在解析各种 `Temporal` API 相关字符串时的正确性，确保引擎能够按照规范成功解析有效的字符串，并正确地拒绝无效的字符串。这对于确保 JavaScript 中 `Temporal` API 的可靠性和一致性至关重要。

Prompt: 
```
这是目录为v8/test/unittests/temporal/temporal-parser-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
ParseTemporalYearMonthStringSuccess("2021-11-09 01:23:45Z", 2021, 11, 9,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09 01:23:45.678912345Z",
                                            2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09 01:23:45,567891234Z",
                                            2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09 0123Z", 2021, 11, 9,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09 012345Z", 2021, 11, 9,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09t012345.678912345Z",
                                            2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09 012345,891234567Z",
                                            2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("20211109T012345,891234567Z", 2021,
                                            11, 9, "");
  // Date TimeZoneNameRequired
  // Date TimeZoneBracketedAnnotation
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09[Etc/GMT+1]", 2021, 11,
                                            9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09[Etc/GMT-23]", 2021, 11,
                                            9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09[Etc/GMT+23]", 2021, 11,
                                            9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09[Etc/GMT-0]", 2021, 11,
                                            9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09Z[Etc/GMT+1]", 2021, 11,
                                            9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09z[Etc/GMT-23]", 2021, 11,
                                            9, "");
  VerifyParseTemporalYearMonthStringSuccess(
      "2021-11-09 23:45:56.891234567Z[Etc/GMT+23]", 2021, 11, 9, "");
  // TimeZoneIANAName
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09[ABCDEFGHIJKLMN]", 2021,
                                            11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess(
      "2021-11-09[ABCDEFGHIJKLMN/abcdefghijklmn/opeqrstuv]", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess(
      "2021-11-09[aBcDEfGHiJ.L_N/ABC...G_..KLMN]", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess(
      "2021-11-09[aBcDE-GHiJ.L_N/ABCbcdG-IJKLMN]", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09T12z[.BCDEFGHIJKLMN]",
                                            2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess(
      "2021-11-09T23:45Z[ABCDEFGHIJKLMN/_bcde-ghij_lmn/.peqrstuv]", 2021, 11, 9,
      "");
  VerifyParseTemporalYearMonthStringSuccess(
      "2021-11-09t234534.234+1234[aBcDEfGHiJ.L_N/ABC...G_..KLMN]", 2021, 11, 9,
      "");
  VerifyParseTemporalYearMonthStringSuccess(
      "2021-11-09 "
      "123456.789123456-012345.789123456[aBcDEfGHiJ.L_N/ABCbcdGfIJKLMN]",
      2021, 11, 9, "");
  // TimeZoneUTCOffsetName
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09[+12]", 2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09[+12:34]", 2021, 11, 9,
                                            "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09[-12:34:56]", 2021, 11,
                                            9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09[+12:34:56,789123456]",
                                            2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess("2021-11-09[+12:34:56.789123456]",
                                            2021, 11, 9, "");
  VerifyParseTemporalYearMonthStringSuccess(
      "2021-11-09[\u221200:34:56.789123456]", 2021, 11, 9, "");
}

TEST_F(TemporalParserTest, TemporalYearMonthStringIllegal) {
  VERIFY_PARSE_FAIL_ON_DATE(TemporalYearMonthString);
  // DateYear -opt DateMonth
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "+2021-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "-2021-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "2021\u221212");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u22122021-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "2021-00");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "2021-13");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "202100");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "202113");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "+98765-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "-12345-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u221212345-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "+9876-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "-1234-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u22121234-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "+987-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "-123-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u2212123-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "+98-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "-12-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u221212-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "+9-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "-1-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u22121-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "+9876512");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "-1234512");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u22121234512");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "+987612");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "-123412");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u2212123412");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "+98712");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u221212312");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "+9812");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "-1212");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u22121212");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "+912");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "-112");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u2212112");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "+12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "-12");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u221212");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "+1");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "-1");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u22121");
  // It is a Syntax Error if DateExtendedYear is "-000000"
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "-000000");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u2212000000");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "-00000001");
  VERIFY_PARSE_FAIL(TemporalYearMonthString, "\u221200000001");
}

TEST_F(TemporalParserTest, TemporalMonthDayStringSuccess) {
  // TemporalMonthDayString :
  //   DateSpecMonthDay
  //   DateTime

  // DateSpecMonthDay:
  //   TwoDashesopt DateMonth -opt DateDay
  VerifyParseTemporalMonthDayStringSuccess("--11-03", kUndefined, 11, 3, "");
  VerifyParseTemporalMonthDayStringSuccess("--1231", kUndefined, 12, 31, "");
  VerifyParseTemporalMonthDayStringSuccess("11-03", kUndefined, 11, 3, "");
  VerifyParseTemporalMonthDayStringSuccess("0131", kUndefined, 1, 31, "");

  // DateTime:
  // DateYear - DateMonth - DateDay
  VerifyParseTemporalMonthDayStringSuccess("2021-11-03", 2021, 11, 03, "");
  // DateYear DateMonth DateDay
  VerifyParseTemporalMonthDayStringSuccess("20211103", 2021, 11, 03, "");
  // DateExtendedYear
  VerifyParseTemporalMonthDayStringSuccess("+002021-11-03", 2021, 11, 03, "");
  VerifyParseTemporalMonthDayStringSuccess("+000001-11-03", 1, 11, 03, "");
  VerifyParseTemporalMonthDayStringSuccess("+0020211103", 2021, 11, 03, "");
  VerifyParseTemporalMonthDayStringSuccess("+0000011231", 1, 12, 31, "");
  VerifyParseTemporalMonthDayStringSuccess("+0000000101", 0, 1, 1, "");
  VerifyParseTemporalMonthDayStringSuccess("+0000000101", 0, 1, 1, "");
  VerifyParseTemporalMonthDayStringSuccess("+654321-11-03", 654321, 11, 3, "");
  VerifyParseTemporalMonthDayStringSuccess("+999999-12-31", 999999, 12, 31, "");
  VerifyParseTemporalMonthDayStringSuccess("-654321-11-03", -654321, 11, 3, "");
  VerifyParseTemporalMonthDayStringSuccess("-999999-12-31", -999999, 12, 31,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("\u2212999999-12-31", -999999, 12,
                                           31, "");
  VerifyParseTemporalMonthDayStringSuccess("+6543211103", 654321, 11, 3, "");
  VerifyParseTemporalMonthDayStringSuccess("+9999991231", 999999, 12, 31, "");
  VerifyParseTemporalMonthDayStringSuccess("-6543211103", -654321, 11, 3, "");
  VerifyParseTemporalMonthDayStringSuccess("-9999991231", -999999, 12, 31, "");
  VerifyParseTemporalMonthDayStringSuccess("\u22129999991231", -999999, 12, 31,
                                           "");

  // DateTime: Date TimeSpecSeparator_opt TimeZone_opt
  // Date TimeSpecSeparator
  // Differeent DateTimeSeparator: <S> T or t
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09T01", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-12-07t01", 2021, 12, 7, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-09-31 01", 2021, 9, 31, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09T0102", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-12-07t01:02", 2021, 12, 7, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-09-31 01:03:04", 2021, 9, 31,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("2021-09-31 01:03:60", 2021, 9, 31,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("2021-09-31 010304", 2021, 9, 31,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("2021-09-31 01:03:04.987654321",
                                           2021, 9, 31, "");
  VerifyParseTemporalMonthDayStringSuccess("1964-07-10 01:03:04,1", 1964, 7, 10,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("1964-07-10 01:03:60,1", 1964, 7, 10,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("1964-07-10 01:03:04,123456789",
                                           1964, 7, 10, "");
  VerifyParseTemporalMonthDayStringSuccess("19640710 01:03:04,123456789", 1964,
                                           7, 10, "");
  // Date TimeZone
  // Date TimeZoneOffsetRequired
  // Date TimeZoneUTCOffset TimeZoneBracketedAnnotation_opt
  // Date TimeZoneNumericUTCOffset
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09+11", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09-12:03", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09-1203", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09-12:03:04", 2021, 11, 9,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09-120304", 2021, 11, 9,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09-12:03:04,987654321",
                                           2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09-120304.123456789", 2021,
                                           11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09T03+11", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09t04:55-12:03", 2021, 11,
                                           9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09t06:22:01.987654321",
                                           2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09t062202,987654321", 2021,
                                           11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09t06:22:03.987654321-1203",
                                           2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09 062204.987654321-1203",
                                           2021, 11, 9, "");

  VerifyParseTemporalMonthDayStringSuccess("2021-11-09T12-12:03:04", 2021, 11,
                                           9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09t1122-120304", 2021, 11,
                                           9, "");
  VerifyParseTemporalMonthDayStringSuccess(
      "2021-11-09 223344-12:03:04,987654321", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess(
      "2021-11-09T223344.987654321-120304.123456789", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess(
      "19670316T223344.987654321-120304.123456789", 1967, 3, 16, "");
  // Date UTCDesignator
  // Date UTCDesignator
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09z", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09Z", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09T11z", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09t12Z", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09 01:23Z", 2021, 11, 9,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09 01:23:45Z", 2021, 11, 9,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09 01:23:45.678912345Z",
                                           2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09 01:23:45,567891234Z",
                                           2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09 0123Z", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09 012345Z", 2021, 11, 9,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09t012345.678912345Z", 2021,
                                           11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09 012345,891234567Z", 2021,
                                           11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("20211109T012345,891234567Z", 2021,
                                           11, 9, "");
  // Date TimeZoneNameRequired
  // Date TimeZoneBracketedAnnotation
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09[Etc/GMT+1]", 2021, 11, 9,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09[Etc/GMT-23]", 2021, 11,
                                           9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09[Etc/GMT+23]", 2021, 11,
                                           9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09[Etc/GMT-0]", 2021, 11, 9,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09Z[Etc/GMT+1]", 2021, 11,
                                           9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09z[Etc/GMT-23]", 2021, 11,
                                           9, "");
  VerifyParseTemporalMonthDayStringSuccess(
      "2021-11-09 23:45:56.891234567Z[Etc/GMT+23]", 2021, 11, 9, "");
  // TimeZoneIANAName
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09[ABCDEFGHIJKLMN]", 2021,
                                           11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess(
      "2021-11-09[ABCDEFGHIJKLMN/abcdefghijklmn/opeqrstuv]", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess(
      "2021-11-09[aBcDEfGHiJ.L_N/ABC...G_..KLMN]", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess(
      "2021-11-09[aBcDE-GHiJ.L_N/ABCbcdG-IJKLMN]", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09T12z[.BCDEFGHIJKLMN]",
                                           2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess(
      "2021-11-09T23:45Z[ABCDEFGHIJKLMN/_bcde-ghij_lmn/.peqrstuv]", 2021, 11, 9,
      "");
  VerifyParseTemporalMonthDayStringSuccess(
      "2021-11-09t234534.234+1234[aBcDEfGHiJ.L_N/ABC...G_..KLMN]", 2021, 11, 9,
      "");
  VerifyParseTemporalMonthDayStringSuccess(
      "2021-11-09 "
      "123456.789123456-012345.789123456[aBcDEfGHiJ.L_N/ABCbcdGfIJKLMN]",
      2021, 11, 9, "");
  // TimeZoneUTCOffsetName
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09[+12]", 2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09[+12:34]", 2021, 11, 9,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09[-12:34:56]", 2021, 11, 9,
                                           "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09[+12:34:56,789123456]",
                                           2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess("2021-11-09[+12:34:56.789123456]",
                                           2021, 11, 9, "");
  VerifyParseTemporalMonthDayStringSuccess(
      "2021-11-09[\u221200:34:56.789123456]", 2021, 11, 9, "");
}

TEST_F(TemporalParserTest, TemporalMonthDayStringIllegal) {
  VERIFY_PARSE_FAIL_ON_DATE(TemporalMonthDayString);
  // TwoDashesopt DateMonth -opt DateDay
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "--13-23");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "--12-32");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "--12-00");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "--00-02");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "00-02");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "10-00");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "0002");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "1000");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "-12-23");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "-1223");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "--1-23");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "--12-2");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "--122");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "--12-");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "-12-");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "--12");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "-12");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "-1");
  VERIFY_PARSE_FAIL(TemporalMonthDayString, "-1-2");
}

TEST_F(TemporalParserTest, TemporalInstantStringSuccess) {
  // Date TimeZoneOffsetRequired
  VerifyParseTemporalInstantStringSuccess("2021-11-09z", true, kUndefined,
                                          kUndefined, kUndefined, kUndefined,
                                          kUndefined);
  VerifyParseTemporalInstantStringSuccess("+002021-11-09z", true, kUndefined,
                                          kUndefined, kUndefined, kUndefined,
                                          kUndefined);
  VerifyParseTemporalInstantStringSuccess("-002021-11-09z", true, kUndefined,
                                          kUndefined, kUndefined, kUndefined,
                                          kUndefined);
  VerifyParseTemporalInstantStringSuccess("2021-11-09+00", false, 1, 0,
                                          kUndefined, kUndefined, kUndefined);
  VerifyParseTemporalInstantStringSuccess("20211109+00", false, 1, 0,
                                          kUndefined, kUndefined, kUndefined);
  VerifyParseTemporalInstantStringSuccess("20211109-23", false, -1, 23,
                                          kUndefined, kUndefined, kUndefined);
  VerifyParseTemporalInstantStringSuccess("20211109+0059", false, 1, 0, 59,
                                          kUndefined, kUndefined);
  VerifyParseTemporalInstantStringSuccess("20211109-23:59", false, -1, 23, 59,
                                          kUndefined, kUndefined);
  VerifyParseTemporalInstantStringSuccess("20211109+005921", false, 1, 0, 59,
                                          21, kUndefined);
  VerifyParseTemporalInstantStringSuccess("20211109-23:00:34", false, -1, 23, 0,
                                          34, kUndefined);
  VerifyParseTemporalInstantStringSuccess("20211109+00:59:21.000000001", false,
                                          1, 0, 59, 21, 1);
  VerifyParseTemporalInstantStringSuccess("20211109-230034.9", false, -1, 23, 0,
                                          34, 900000000);
  VerifyParseTemporalInstantStringSuccess("20211109-230035,89", false, -1, 23,
                                          0, 35, 890000000);

  // Date DateTimeSeparator TimeSpec TimeZoneOffsetRequired
  VerifyParseTemporalInstantStringSuccess("2021-11-09T12:34:56.987654321z",
                                          true, kUndefined, kUndefined,
                                          kUndefined, kUndefined, kUndefined);
  VerifyParseTemporalInstantStringSuccess("2021-11-09 12:34:56.987654321z",
                                          true, kUndefined, kUndefined,
                                          kUndefined, kUndefined, kUndefined);
  VerifyParseTemporalInstantStringSuccess("0001-11-09t12:34:56.987654321z",
                                          true, kUndefined, kUndefined,
                                          kUndefined, kUndefined, kUndefined);
  VerifyParseTemporalInstantStringSuccess("2021-11-09T12+00", false, 1, 0,
                                          kUndefined, kUndefined, kUndefined);
  VerifyParseTemporalInstantStringSuccess("20211109t23+00", false, 1, 0,
                                          kUndefined, kUndefined, kUndefined);
  VerifyParseTemporalInstantStringSuccess("20211109 10-23", false, -1, 23,
                                          kUndefined, kUndefined, kUndefined);
  VerifyParseTemporalInstantStringSuccess("20211109T00:34+0059", false, 1, 0,
                                          59, kUndefined, kUndefined);
  VerifyParseTemporalInstantStringSuccess("20211109t0233-23:59", false, -1, 23,
                                          59, kUndefined, kUndefined);
  VerifyParseTemporalInstantStringSuccess("20211109 091234+005921", false, 1, 0,
                                          59, 21, kUndefined);
  VerifyParseTemporalInstantStringSuccess("20211109T123456.789123456-23:00:34",
                                          false, -1, 23, 0, 34, kUndefined);
  VerifyParseTemporalInstantStringSuccess(
      "20211109t12:34:56.987654321+00:59:21.000000001", false, 1, 0, 59, 21, 1);
  VerifyParseTemporalInstantStringSuccess("20211109 235960,999999999-230034.9",
                                          false, -1, 23, 0, 34, 900000000);
  VerifyParseTemporalInstantStringSuccess("20211109T000000.000000000-230035,89",
                                          false, -1, 23, 0, 35, 890000000);
}

TEST_F(TemporalParserTest, TemporalInstantStringIllegal) {
  VERIFY_PARSE_FAIL_ON_DATE(TemporalInstantString);

  // Without TimeZoneUTCOffsetSign
  VERIFY_PARSE_FAIL(TemporalInstantString, "202111090");
  VERIFY_PARSE_FAIL(TemporalInstantString, "202111099");
  VERIFY_PARSE_FAIL(TemporalInstantString, "2021110900");
  VERIFY_PARSE_FAIL(TemporalInstantString, "2021110901");
  VERIFY_PARSE_FAIL(TemporalInstantString, "2021110923");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109ff");

  // Wrong TimeZoneUTCOffsetHour
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+24");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-24");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109\u221224");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+ab");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-2a");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109\u22122Z");
  // Single digit is not TimeZoneUTCOffsetHour
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+0");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+2");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-1");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109\u22123");

  // Extra
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+23 ");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109 -22");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+23:");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-22:");

  // Wrong TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour : TimeZoneUTCOffsetMinute
  // single digit TimeZoneUTCOffsetMinute
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+01:0");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+21:5");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-20:4");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109\u221219:3");
  // TimeZoneUTCOffsetMinute out of range
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+01:60");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+21:5a");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-20:4f");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109\u221219:a0");

  // Wrong TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour TimeZoneUTCOffsetMinute
  // single digit TimeZoneUTCOffsetMinute
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+010");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+215");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-204");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109\u2212193");
  // TimeZoneUTCOffsetMinute out of range
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+0160");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+215a");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-204f");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109\u221219a0");

  // TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour : TimeZoneUTCOffsetMinute :
  // TimeZoneUTCOffsetSecond TimeZoneUTCOffsetFractionopt with : here but not
  // there
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+01:0059");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+1534:33");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-07:34:339");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-07:34:.9");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-07:34:,9");
  // fraction too long
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-07:34:01.9876543219");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+07:34:01,9876543219");
  // fraction in hour or minute
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+01.0:00:59");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+01:00.1:59");

  // Wrong TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour TimeZoneUTCOffsetMinute
  // TimeZoneUTCOffsetSecond TimeZoneUTCOffsetFractionopt
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+0100.159");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+01.15009");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-0100,159");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-01,15009");
  // fraction too long
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109-073401.0000000000");
  VERIFY_PARSE_FAIL(TemporalInstantString, "20211109+073401,9876543219");
  // It is a Syntax Error if DateExtendedYear is "-000000"
  VERIFY_PARSE_FAIL(TemporalInstantString, "-0000001109+073401,9876543219");
  VERIFY_PARSE_FAIL(TemporalInstantString,
                    "\u22120000001109+073401,9876543219");
}

#define IMPL_ZONED_DATE_TIME_STRING_SUCCESS(R)                               \
  do {                                                                       \
    VerifyParse##R##Success("2021-11-03T02:03:04.56789z[Asia/Taipei]", 2021, \
                            11, 03, 2, 3, 4, 567890000, "", kUndefined,      \
                            kUndefined, kUndefined, kUndefined, kUndefined,  \
                            true, "Asia/Taipei");                            \
    VerifyParse##R##Success(                                                 \
        "1911-10-10[Asia/Shanghai][u-ca=roc]", 1911, 10, 10, kUndefined,     \
        kUndefined, kUndefined, kUndefined, "roc", kUndefined, kUndefined,   \
        kUndefined, kUndefined, kUndefined, false, "Asia/Shanghai");         \
    VerifyParse##R##Success(                                                 \
                                                                             \
        "+123456-12-31 "                                                     \
        "05:06:07+12:34:56.78901234[Europe/San_Marino][u-ca=hebrew]",        \
        123456, 12, 31, 5, 6, 7, kUndefined, "hebrew", 1, 12, 34, 56,        \
        789012340, false, "Europe/San_Marino");                              \
  } while (false)

TEST_F(TemporalParserTest, TemporalZonedDateTimeStringSuccess) {
  IMPL_ZONED_DATE_TIME_STRING_SUCCESS(TemporalZonedDateTimeString);
}

#define VERIFY_PARSE_FAIL_ON_ZONED_DATE_TIME(R)                            \
  do {                                                                     \
    VERIFY_PARSE_FAIL_ON_DATE(R);                                          \
    VERIFY_PARSE_FAIL(R, "+20210304");                                     \
    VERIFY_PARSE_FAIL(R, "-20210304");                                     \
    VERIFY_PARSE_FAIL(R, "\u221220210304");                                \
    VERIFY_PARSE_FAIL(R, "210304");                                        \
    VERIFY_PARSE_FAIL(R, "2021-03-04");                                    \
    VERIFY_PARSE_FAIL(R, "2021-03-04T23:59:20.1234");                      \
    VERIFY_PARSE_FAIL(R, "2021-03-04T23:59:20.1234z");                     \
    VERIFY_PARSE_FAIL(R, "2021-03-04[u-ca=roc]");                          \
    VERIFY_PARSE_FAIL(R, "2021-03-04T23:59:20.1234[u-ca=roc]");            \
    VERIFY_PARSE_FAIL(R, "2021-03-04T23:59:20.1234z[u-ca=roc]");           \
    VERIFY_PARSE_FAIL(R, "2021-03-04[]");                                  \
    VERIFY_PARSE_FAIL(R, "2021-03-04T23:59:20.1234[]");                    \
    VERIFY_PARSE_FAIL(R, "2021-03-04T23:59:20.1234z[]");                   \
    VERIFY_PARSE_FAIL(R, "2021-03-04[etc/gmt+00]");                        \
    VERIFY_PARSE_FAIL(R, "2021-03-04T23:59:20.1234[ETC/GMT+00]");          \
    VERIFY_PARSE_FAIL(R, "2021-03-04T23:59:20.1234z[Etc/GMT+24]");         \
    VERIFY_PARSE_FAIL(R, "2021-03-04[Etc/GMT+00:00]");                     \
    VERIFY_PARSE_FAIL(R, "2021-03-04[Etc/GMT\u221200]");                   \
    VERIFY_PARSE_FAIL(R, "2021-03-04T23:59:20.1234[.]");                   \
    VERIFY_PARSE_FAIL(R, "2021-03-04T23:59:20.1234z[..]");                 \
    VERIFY_PARSE_FAIL(R, "2021-03-04T23:59:20.1234[ABCD/.]");              \
    VERIFY_PARSE_FAIL(R, "2021-03-04T23:59:20.1234z[EFGH/..]");            \
    VERIFY_PARSE_FAIL(R, "2021-03-04T23:59:20.1234[abcdefghijklmno]");     \
    VERIFY_PARSE_FAIL(R, "2021-03-04 23:59:20.1234[abc/abcdefghijklmno]"); \
    VERIFY_PARSE_FAIL(R, "2021-03-04t23:59:20.1234[+1]");                  \
    VERIFY_PARSE_FAIL(R, "2021-03-04t23:59:20.1234[+123]");                \
    VERIFY_PARSE_FAIL(R, "2021-03-04t23:59:20.1234[+12345]");              \
    VERIFY_PARSE_FAIL(R, "2021-03-04t23:59:20.1234[-1]");                  \
    VERIFY_PARSE_FAIL(R, "2021-03-04t23:59:20.1234[-123]");                \
    VERIFY_PARSE_FAIL(R, "2021-03-04t23:59:20.1234[-12345]");              \
    VERIFY_PARSE_FAIL(R, "2021-03-04t23:59:20.1234[+12:3456]");            \
    VERIFY_PARSE_FAIL(R, "2021-03-04t23:59:20.1234[+1234:56]");            \
    VERIFY_PARSE_FAIL(R, "2021-03-04t23:59:20.1234[+123456.9876543210]");  \
    VERIFY_PARSE_FAIL(R, "2021-03-04t23:59:20.1234[+123456.]");            \
    VERIFY_PARSE_FAIL(R, "2021-03-04t23:59:20.1234[+123456,]");            \
    VERIFY_PARSE_FAIL(R, "-000000-03-04t23:59:20.1234[+123456,]");         \
    VERIFY_PARSE_FAIL(R, "\u2212000000-03-04t23:59:20.1234[+123456,]");    \
  } while (false)

TEST_F(TemporalParserTest, TemporalZonedDateTimeStringIllegal) {
  VERIFY_PARSE_FAIL_ON_ZONED_DATE_TIME(TemporalZonedDateTimeString);
}

constexpr int64_t empty = ParsedISO8601Duration::kEmpty;

// Test basic cases.
TEST_F(TemporalParserTest, TemporalDurationStringBasic) {
  VerifyParseDurationSuccess("PT0S", 1, empty, empty, empty, empty, empty,
                             empty, empty, empty, 0, empty);
  VerifyParseDurationSuccess("-PT0S", -1, empty, empty, empty, empty, empty,
                             empty, empty, empty, 0, empty);
  VerifyParseDurationSuccess("P1Y", 1, 1, empty, empty, empty, empty, empty,
                             empty, empty, empty, empty);
  VerifyParseDurationSuccess("P2M", 1, empty, 2, empty, empty, empty, empty,
                             empty, empty, empty, empty);
  VerifyParseDurationSuccess("P3W", 1, empty, empty, 3, empty, empty, empty,
                             empty, empty, empty, empty);
  VerifyParseDurationSuccess("P4D", 1, empty, empty, empty, 4, empty, empty,
                             empty, empty, empty, empty);
  VerifyParseDurationSuccess("PT5H", 1, empty, empty, empty, empty, 5, empty,
                             empty, empty, empty, empty);
  VerifyParseDurationSuccess("PT1.987654321H", 1, empty, empty, empty, empty, 1,
                             987654321, empty, empty, empty, empty);
  VerifyParseDurationSuccess("PT2.9H", 1, empty, empty, empty, empty, 2,
                             900000000, empty, empty, empty, empty);
  VerifyParseDurationSuccess("PT6M", 1, empty, empty, empty, empty, empty,
                             empty, 6, empty, empty, empty);
  VerifyParseDurationSuccess("PT2.234567891M", 1, empty, empty, empty, empty,
                             empty, empty, 2, 234567891, empty, empty);
  VerifyParseDurationSuccess("PT3.23M", 1, empty, empty, empty, empty, empty,
                             empty, 3, 230000000, empty, empty);
  VerifyParseDurationSuccess("PT7S", 1, empty, empty, empty, empty, empty,
                             empty, empty, empty, 7, empty);
  VerifyParseDurationSuccess("PT3.345678912S", 1, empty, empty, empty, empty,
                             empty, empty, empty, empty, 3, 345678912);
  VerifyParseDurationSuccess("PT4.345S", 1, empty, empty, empty, empty, empty,
                             empty, empty, empty, 4, 345000000);

  VerifyParseDurationSuccess("P1Y2M3W4DT5.6H7.8M9.1S", 1, 1, 2, 3, 4, 5,
                             600000000, 7, 800000000, 9, 100000000);
  VerifyParseDurationSuccess("-P9Y8M7W6DT5.4H3.2M1.9S", -1, 9, 8, 7, 6, 5,
                             400000000, 3, 200000000, 1, 900000000);

  VerifyParseDurationSuccess("P0Y0M0W0DT0.0H0.0M0.0S", 1, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0);
  VerifyParseDurationSuccess("-P0Y0M0W0DT0.0H0.0M0.0S", -1, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0);
}

// Test duration with ascii minus sign parsed correctly.
TEST_F(TemporalParserTest, TemporalDurationStringNegative) {
  VerifyParseDurationSuccess("-P1Y", -1, 1, empty, empty, empty, empty, empty,
                             empty, empty, empty, empty);
  VerifyParseDurationSuccess("-P2M", -1, empty, 2, empty, empty, empty, empty,
                             empty, empty, empty, empty);
  VerifyParseDurationSuccess("-P3W", -1, empty, empty, 3, empty, empty, empty,
                             empty, empty, empty, empty);
  VerifyParseDurationSuccess("-P4D", -1, empty, empty, empty, 4, empty, empty,
                             empty, empty, empty, empty);
  VerifyParseDurationSuccess("-PT5H", -1, empty, empty, empty, empty, 5, empty,
                             empty, empty, empty, empty);
  VerifyParseDurationSuccess("-PT4.123H", -1, empty, empty, empty, empty, 4,
                             123000000, empty, empty, empty, empty);
  VerifyParseDurationSuccess("-PT3.123456H", -1, empty, empty, empty, empty, 3,
                             123456000, empty, empty, empty, empty);
  VerifyParseDurationSuccess("-PT6M", -1, empty, empty, empty, empty, empty,
                             empty, 6, empty, empty, empty);
  VerifyParseDurationSuccess("-PT5.2M", -1, empty, empty, empty, empty, empty,
                             empty, 5, 200000000, empty, empty);
  VerifyParseDurationSuccess("-PT4.3456M", -1, empty, empty, empty, empty,
                             empty, empty, 4, 345600000, empty, empty);
  VerifyParseDurationSuccess("-PT7S", -1, empty, empty, empty, empty, empty,
                             empty, empty, empty, 7, empty);
  VerifyParseDurationSuccess("-PT6.987S", -1, empty, empty, empty, empty, empty,
                             empty, empty, empty, 6, 987000000);
}

// Test duration with + sign parsed the same as without + sign.
TEST_F(TemporalParserTest, TemporalDurationStringPlus) {
  // Check + Sign
  VerifyParseDurationWithPositiveSign("P1Y");
  VerifyParseDurationWithPositiveSign("P2M");
  VerifyParseDurationWithPositiveSign("P3W");
  VerifyParseDurationWithPositiveSign("P4D");
  VerifyParseDurationWithPositiveSign("PT5H");
  VerifyParseDurationWithPositiveSign("PT1.987654321H");
  VerifyParseDurationWithPositiveSign("PT2.9H");
  VerifyParseDurationWithPositiveSign("PT6M");
  VerifyParseDurationWithPositiveSign("PT2.234567891M");
  VerifyParseDurationWithPositiveSign("PT3.23M");
  VerifyParseDurationWithPositiveSign("PT7S");
  VerifyParseDurationWithPositiveSign("PT3.345678912S");
}

// Test duration with Unicode U+2212 minus sign parsed the same as ascii - sign.
TEST_F(TemporalParserTest, TemporalDurationStringMinus) {
  // Check + Sign
  VerifyParseDurationWithMinusSign("P1Y");
  VerifyParseDurationWithMinusSign("P2M");
  VerifyParseDurationWithMinusSign("P3W");
  VerifyParseDurationWithMinusSign("P4D");
  VerifyParseDurationWithMinusSign("PT5H");
  VerifyParseDurationWithMinusSign("PT1.987654321H");
  VerifyParseDurationWithMinusSign("PT2.9H");
  VerifyParseDurationWithMinusSign("PT6M");
  VerifyParseDurationWithMinusSign("PT2.234567891M");
  VerifyParseDurationWithMinusSign("PT3.23M");
  VerifyParseDurationWithMinusSign("PT7S");
  VerifyParseDurationWithMinusSign("PT3.345678912S");
}

// Test duration in lower case mark parsed the same as with upper case mark.
TEST_F(TemporalParserTest, TemporalDurationStringLowerCase) {
  // Check + Sign
  VerifyParseDurationWithLowerCase("P1Y");
  VerifyParseDurationWithLowerCase("P2M");
  VerifyParseDurationWithLowerCase("P3W");
  VerifyParseDurationWithLowerCase("P4D");
  VerifyParseDurationWithLowerCase("PT5H");
  VerifyParseDurationWithLowerCase("PT1.987654321H");
  VerifyParseDurationWithLowerCase("PT2.9H");
  VerifyParseDurationWithLowerCase("PT6M");
  VerifyParseDurationWithLowerCase("PT2.234567891M");
  VerifyParseDurationWithLowerCase("PT3.23M");
  VerifyParseDurationWithLowerCase("PT7S");
  VerifyParseDurationWithLowerCase("PT3.345678912S");
}

TEST_F(TemporalParserTest, TemporalDurationStringComma) {
  VerifyParseDurationWithComma("PT1,987654321H");
  VerifyParseDurationWithComma("PT2,9H");
  VerifyParseDurationWithComma("PT2,234567891M");
  VerifyParseDurationWithComma("PT3,23M");
  VerifyParseDurationWithComma("PT3,345678912S");
}

TEST_F(TemporalParserTest, TemporalDurationStringLongDigits) {
  VerifyParseDurationSuccess("P8999999999999999999Y", 1, 8999999999999999999,
                             empty, empty, empty, empty, empty, empty, empty,
                             empty, empty);
  VerifyParseDurationSuccess("P8999999999999999998M", 1, empty,
                             8999999999999999998, empty, empty, empty, empty,
                             empty, empty, empty, empty);
  VerifyParseDurationSuccess("P8999999999999999997W", 1, empty, empty,
                             8999999999999999997, empty, empty, empty, empty,
                             empty, empty, empty);
  VerifyParseDurationSuccess("P8999999999999999996D", 1, empty, empty, empty,
                             8999999999999999996, empty, empty, empty, empty,
                             empty, empty);
  VerifyParseDurationSuccess("PT8999999999999999995H", 1, empty, empty, empty,
                             empty, 8999999999999999995, empty, empty, empty,
                             empty, empty);
  VerifyParseDurationSuccess("PT8999999999999999994M", 1, empty, empty, empty,
                             empty, empty, empty, 8999999999999999994, empty,
                             empty, empty);
  VerifyParseDurationSuccess("PT8999999999999999993S", 1, empty, empty, empty,
                             empty, empty, empty, empty, empty,
                             8999999999999999993, empty);

  VerifyParseDurationSuccess("PT0.999999999H", 1, empty, empty, empty, empty, 0,
                             999999999, empty, empty, empty, empty);
  VerifyParseDurationSuccess("PT0.999999999M", 1, empty, empty, empty, empty,
                             empty, empty, 0, 999999999, empty, empty);
  VerifyParseDurationSuccess("PT0.999999999S", 1, empty, empty, empty, empty,
                             empty, empty, empty, empty, 0, 999999999);

  VerifyParseDurationSuccess("-P8999999999999999999Y", -1, 8999999999999999999,
                             empty, empty, empty, empty, empty, empty, empty,
                             empty, empty);
  VerifyParseDurationSuccess("-P8999999999999999998M", -1, empty,
                             8999999999999999998, empty, empty, empty, empty,
                             empty, empty, empty, empty);
  VerifyParseDurationSuccess("-P8999999999999999997W", -1, empty, empty,
                             8999999999999999997, empty, empty, empty, empty,
                             empty, empty, empty);
  VerifyParseDurationSuccess("-P8999999999999999996D", -1, empty, empty, empty,
                             8999999999999999996, empty, empty, empty, empty,
                             empty, empty);
  VerifyParseDurationSuccess("-PT8999999999999999995H", -1, empty, empty, empty,
                             empty, 8999999999999999995, empty, empty, empty,
                             empty, empty);
  VerifyParseDurationSuccess("-PT8999999999999999995H", -1, empty, empty, empty,
                             empty, 8999999999999999995, empty, empty, empty,
                             empty, empty);
  VerifyParseDurationSuccess("-PT8999999999999999994M", -1, empty, empty, empty,
                             empty, empty, empty, 8999999999999999994, empty,
                             empty, empty);
  VerifyParseDurationSuccess("-PT8999999999999999993S", -1, empty, empty, empty,
                             empty, empty, empty, empty, empty,
                             8999999999999999993, empty);

  VerifyParseDurationSuccess("-PT0.999999999H", -1, empty, empty, empty, empty,
                             0, 999999999, empty, empty, empty, empty);
  VerifyParseDurationSuccess("-PT0.999999999M", -1, empty, empty, empty, empty,
                             empty, empty, 0, 999999999, empty, empty);
  VerifyParseDurationSuccess("-PT0.999999999S", -1, empty, empty, empty, empty,
                             empty, empty, empty, empty, 0, 999999999);
}

TEST_F(TemporalParserTest, TemporalDurationStringNotSatisfy) {
  VERIFY_PARSE_FAIL(TemporalDurationString, "");

  // Missing P
  VERIFY_PARSE_FAIL(TemporalDurationString, "1Y");
  VERIFY_PARSE_FAIL(TemporalDurationString, "1M");
  VERIFY_PARSE_FAIL(TemporalDurationString, "+1W");
  VERIFY_PARSE_FAIL(TemporalDurationString, "-1D");

  // fraction with years, months, weeks or days
  VERIFY_PARSE_FAIL(TemporalDurationString, "P1.1Y");
  VERIFY_PARSE_FAIL(TemporalDurationString, "P2.2M");
  VERIFY_PARSE_FAIL(TemporalDurationString, "P3.3W");
  VERIFY_PARSE_FAIL(TemporalDurationString, "P4.4D");

  // Time without T
  VERIFY_PARSE_FAIL(TemporalDurationString, "P1H");
  VERIFY_PARSE_FAIL(TemporalDurationString, "P1S");

  // Sign after P
  VERIFY_PARSE_FAIL(TemporalDurationString, "P+1Y");
  VERIFY_PARSE_FAIL(TemporalDurationString, "P-2M");
  VERIFY_PARSE_FAIL(TemporalDurationString, "P\u22123W");
  VERIFY_PARSE_FAIL(TemporalDurationString, "P+4D");
  VERIFY_PARSE_FAIL(TemporalDurationString, "PT-4H");
  VERIFY_PARSE_FAIL(TemporalDurationString, "PT+5M");

  // with :
  VERIFY_PARSE_FAIL(TemporalDurationString, "PT01:22");

  // more than 9 digits in fraction
  VERIFY_PARSE_FAIL(TemporalDurationString, "PT1.9876543219H");
  VERIFY_PARSE_FAIL(TemporalDurationString, "PT0.9876543219M");
  VERIFY_PARSE_FAIL(TemporalDurationString, "PT2.9876543219S");

  // out of order
  VERIFY_PARSE_FAIL(TemporalDurationString, "P2M1Y");
  VERIFY_PARSE_FAIL(TemporalDurationString, "P3W4M");
  VERIFY_PARSE_FAIL(TemporalDurationString, "P5D6W");
  VERIFY_PARSE_FAIL(TemporalDurationString, "PT1H6Y");
  VERIFY_PARSE_FAIL(TemporalDurationString, "PT1M6W");
  VERIFY_PARSE_FAIL(TemporalDurationString, "PT1S6D");

  // Extra in the end
  VERIFY_PARSE_FAIL(TemporalDurationString, "P1Y ");
  VERIFY_PARSE_FAIL(TemporalDurationString, "P1Yp");
  VERIFY_PARSE_FAIL(TemporalDurationString, "P2M:");

  // Extra in the beginning
  VERIFY_PARSE_FAIL(TemporalDurationString, "pP1Y");
  VERIFY_PARSE_FAIL(TemporalDurationString, " P1Y");
  VERIFY_PARSE_FAIL(TemporalDurationString, ".P2M");

  // Fraction without digit
  VERIFY_PARSE_FAIL(TemporalDurationString, "PT.1H");
  VERIFY_PARSE_FAIL(TemporalDurationString, "PT.2M");
  VERIFY_PARSE_FAIL(TemporalDurationString, "PT.3S");

  // without date nor time
  VERIFY_PARSE_FAIL(TemporalDurationString, "P");
  VERIFY_PARSE_FAIL(TemporalDurationString, "PT");
}

TEST_F(TemporalParserTest, TimeZoneNumericUTCOffsetBasic) {
  // TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour
  VerifyParseTimeZoneNumericUTCOffsetSuccess("+00", 1, 0, kUndefined,
                                             kUndefined, kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("+23", 1, 23, kUndefined,
                                             kUndefined, kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("-23", -1, 23, kUndefined,
                                             kUndefined, kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("\u221223", -1, 23, kUndefined,
                                             kUndefined, kUndefined);

  // TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour : TimeZoneUTCOffsetMinute
  VerifyParseTimeZoneNumericUTCOffsetSuccess("+01:00", 1, 1, 0, kUndefined,
                                             kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("+21:59", 1, 21, 59, kUndefined,
                                             kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("-20:48", -1, 20, 48, kUndefined,
                                             kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("\u221219:33", -1, 19, 33,
                                             kUndefined, kUndefined);

  // TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour TimeZoneUTCOffsetMinute
  VerifyParseTimeZoneNumericUTCOffsetSuccess("+0100", 1, 1, 0, kUndefined,
                                             kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("+2159", 1, 21, 59, kUndefined,
                                             kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("-2048", -1, 20, 48, kUndefined,
                                             kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("\u22121933", -1, 19, 33,
                                             kUndefined, kUndefined);

  // TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour : TimeZoneUTCOffsetMinute :
  // TimeZoneUTCOffsetSecond TimeZoneUTCOffsetFractionopt
  VerifyParseTimeZoneNumericUTCOffsetSuccess("+01:00:59", 1, 1, 0, 59,
                                             kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("+15:34:33", 1, 15, 34, 33,
                                             kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("-09:59:00", -1, 9, 59, 00,
                                             kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("\u221218:53:22", -1, 18, 53, 22,
                                             kUndefined);

  VerifyParseTimeZoneNumericUTCOffsetSuccess("+01:00:59.987654321", 1, 1, 0, 59,
                                             987654321);
  // ',' as DecimalSeparator
  VerifyParseTimeZoneNumericUTCOffsetSuccess("+01:00:59,123456789", 1, 1, 0, 59,
                                             123456789);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("-09:59:00.9", -1, 9, 59, 00,
                                             900000000);
  // ',' as DecimalSeparator
  VerifyParseTimeZoneNumericUTCOffsetSuccess("-09:59:00,000000001", -1, 9, 59,
                                             00, 1);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("-09:59:00.000000001", -1, 9, 59,
                                             00, 1);

  // TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour TimeZoneUTCOffsetMinute
  // TimeZoneUTCOffsetSecond TimeZoneUTCOffsetFractionopt
  VerifyParseTimeZoneNumericUTCOffsetSuccess("+010059", 1, 1, 0, 59,
                                             kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("+153433", 1, 15, 34, 33,
                                             kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("-095900", -1, 9, 59, 00,
                                             kUndefined);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("\u2212185322", -1, 18, 53, 22,
                                             kUndefined);

  VerifyParseTimeZoneNumericUTCOffsetSuccess("+010059.987654321", 1, 1, 0, 59,
                                             987654321);
  // ',' as DecimalSeparator
  VerifyParseTimeZoneNumericUTCOffsetSuccess("+010059,123456789", 1, 1, 0, 59,
                                             123456789);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("-095900.9", -1, 9, 59, 00,
                                             900000000);
  // ',' as DecimalSeparator
  VerifyParseTimeZoneNumericUTCOffsetSuccess("-095900,000000001", -1, 9, 59, 00,
                                             1);
  VerifyParseTimeZoneNumericUTCOffsetSuccess("-095900.000000001", -1, 9, 59, 00,
                                             1);
}

TEST_F(TemporalParserTest, TimeZoneNumericUTCOffsetIllegal) {
  // Without TimeZoneUTCOffsetSign
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "0");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "9");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "00");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "01");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "23");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "ff");

  // Wrong TimeZoneUTCOffsetHour
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+24");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-24");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "\u221224");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+ab");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-2a");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "\u22122Z");
  // Single digit is not TimeZoneUTCOffsetHour
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+0");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+2");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-1");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "\u22123");

  // Extra
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+23 ");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, " -22");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+23:");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-22:");

  // Wrong TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour : TimeZoneUTCOffsetMinute
  // single digit TimeZoneUTCOffsetMinute
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+01:0");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+21:5");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-20:4");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "\u221219:3");
  // TimeZoneUTCOffsetMinute out of range
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+01:60");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+21:5a");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-20:4f");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "\u221219:a0");

  // Wrong TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour TimeZoneUTCOffsetMinute
  // single digit TimeZoneUTCOffsetMinute
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+010");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+215");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-204");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "\u2212193");
  // TimeZoneUTCOffsetMinute out of range
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+0160");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+215a");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-204f");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "\u221219a0");

  // TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour : TimeZoneUTCOffsetMinute :
  // TimeZoneUTCOffsetSecond TimeZoneUTCOffsetFractionopt with : here but not
  // there
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+01:0059");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+1534:33");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-07:34:339");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-07:34:.9");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-07:34:,9");
  // fraction too long
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-07:34:01.9876543219");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+07:34:01,9876543219");
  // fraction in hour or minute
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+01.0:00:59");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+01:00.1:59");

  // Wrong TimeZoneUTCOffsetSign TimeZoneUTCOffsetHour TimeZoneUTCOffsetMinute
  // TimeZoneUTCOffsetSecond TimeZoneUTCOffsetFractionopt
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+0100.159");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+01.15009");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-0100,159");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-01,15009");
  // fraction too long
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "-073401.0000000000");
  VERIFY_PARSE_FAIL(TimeZoneNumericUTCOffset, "+073401,9876543219");
}

TEST_F(TemporalParserTest, TimeZoneIdentifierSucccess) {
  // TimeZoneIANAName:
  //  Etc/GMT ASCIISign UnpaddedHour:
  VerifyParseTimeZoneIdentifierSuccess("Etc/GMT+0");
  VerifyParseTimeZoneIdentifierSuccess("Etc/GMT+1");
  VerifyParseTimeZoneIdentifierSuccess("Etc/GMT+11");
  VerifyParseTimeZoneIdentifierSuccess("Etc/GMT+23");
  //  TimeZoneIANANameTail
  VerifyParseTimeZoneIdentifierSuccess("_");
  VerifyParseTimeZoneIdentifierSuccess("_/_");
  VerifyParseTimeZoneIdentifierSuccess("a.");
  VerifyParseTimeZoneIdentifierSuccess("a..");
  VerifyParseTimeZoneIdentifierSuccess("a_");
  VerifyParseTimeZoneIdentifierSuccess("a-");
  VerifyParseTimeZoneIdentifierSuccess("a-b");
  VerifyParseTimeZoneIdentifierSuccess("a-b/c");
  VerifyParseTimeZoneIdentifierSuccess("abcdefghijklmn");
  VerifyParseTimeZoneIdentifierSuccess("abcdefghijklmn/ABCDEFGHIJKLMN");

  //  TimeZoneIANALegacyName
  VerifyParseTimeZoneIdentifierSuccess("Etc/GMT0");
  VerifyParseTimeZoneIdentifierSuccess("GMT0");
  VerifyParseTimeZoneIdentifierSuccess("GMT-0");
  VerifyParseTimeZoneIdentifierSuccess("GMT+0");
  VerifyParseTimeZoneIdentifierSuccess("EST5EDT");
  VerifyParseTimeZoneIdentifierSuccess("CST6CDT");
  VerifyParseTimeZoneIdentifierSuccess("MST7MDT");
  VerifyParseTimeZoneIdentifierSuccess("PST8PDT");

  // TimeZoneUTCOffsetName
  //  Sign Hour
  VerifyParseTimeZoneIdentifierSuccess("+00");
  VerifyParseTimeZoneIdentifierSuccess("+23");
  VerifyParseTimeZoneIdentifierSuccess("-00");
  VerifyParseTimeZoneIdentifierSuccess("-23");
  VerifyParseTimeZoneIdentifierSuccess("\u221200");
  VerifyParseTimeZoneIdentifierSuccess("\u221223");
  //  Sign Hour : MinuteSecond
  VerifyParseTimeZoneIdentifierSuccess("+00:00");
  VerifyParseTimeZoneIdentifierSuccess("+23:59");
  VerifyParseTimeZoneIdentifierSuccess("-00:00");
  VerifyParseTimeZoneIdentifierSuccess("-23:59");
  VerifyParseTimeZoneIdentifierSuccess("\u221200:00");
  VerifyParseTimeZoneIdentifierSuccess("\u221223:59");
  //  Sign Hour MinuteSecond
  VerifyParseTimeZoneIdentifierSuccess("+0000");
  VerifyParseTimeZoneIdentifierSuccess("+2359");
  VerifyParseTimeZoneIdentifierSuccess("-0000");
  VerifyParseTimeZoneIdentifierSuccess("-2359");
  VerifyParseTimeZoneIdentifierSuccess("\u22120000");
  VerifyParseTimeZoneIdentifierSuccess("\u22122359");

  //  Sign Hour : MinuteSecond : MinuteSecond Fractionopt
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00");
  VerifyParseTimeZoneIdentifierSuccess("+23:59:59");
  VerifyParseTimeZoneIdentifierSuccess("-00:00:00");
  VerifyParseTimeZoneIdentifierSuccess("-23:59:59");
  VerifyParseTimeZoneIdentifierSuccess("\u221200:00:00");
  VerifyParseTimeZoneIdentifierSuccess("\u221223:59:59");

  VerifyParseTimeZoneIdentifierSuccess("+00:00:00.0");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00,0");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00.10");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00,01");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00.012");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00,010");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00.0123");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00,0120");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00.01234");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00,01230");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00.012345");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00,012340");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00.0123450");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00,0123456");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00,01234567");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00.01234560");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00,012345678");
  VerifyParseTimeZoneIdentifierSuccess("+00:00:00.012345680");

  //  Sign Hour MinuteSecond MinuteSecond Fractionopt
  VerifyParseTimeZoneIdentifierSuccess("+000000");
  VerifyParseTimeZoneIdentifierSuccess("+235959");
  VerifyParseTimeZoneIdentifierSuccess("-000000");
  VerifyParseTimeZoneIdentifierSuccess("-235959");
  VerifyParseTimeZoneIdentifierSuccess("\u2212000000");
  VerifyParseTimeZoneIdentifierSuccess("\u2212235959");

  VerifyParseTimeZoneIdentifierSuccess("-000000.0");
  VerifyParseTimeZoneIdentifierSuccess("-000000,0");
  VerifyParseTimeZoneIdentifierSuccess("-000000.10");
  VerifyParseTimeZoneIdentifierSuccess("-000000,01");
  VerifyParseTimeZoneIdentifierSuccess("-000000.012");
  VerifyParseTimeZoneIdentifierSuccess("-000000,010");
  VerifyParseTimeZoneIdentifierSuccess("-000000.0123");
  VerifyParseTimeZoneIdentifierSuccess("-000000,0120");
  VerifyParseTimeZoneIdentifierSuccess("-000000.01234");
  VerifyParseTimeZoneIdentifierSuccess("-000000,01230");
  VerifyParseTimeZoneIdentifierSuccess("-000000.012345");
  VerifyParseTimeZoneIdentifierSuccess("-000000,012340");
  VerifyParseTimeZoneIdentifierSuccess("-000000.0123450");
  VerifyParseTimeZoneIdentifierSuccess("-000000,0123456");
  VerifyParseTimeZoneIdentifierSuccess("-000000,01234567");
  VerifyParseTimeZoneIdentifierSuccess("-000000.01234560");
  VerifyParseTimeZoneIdentifierSuccess("-000000,012345678");
  VerifyParseTimeZoneIdentifierSuccess("-000000.012345680");
}
TEST_F(TemporalParserTest, TimeZoneIdentifierIllegal) {
  //  Etc/GMT ASCIISign Hour:
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "[Etc/GMT+1]");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "Etc/GMT+01");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "Etc/GMT+24");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, ".");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "..");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "A/..");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "A/.");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-ab");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "abcdefghijklmno");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "abcdefghijklmno/ABCDEFGHIJKLMN");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "abcdefghijklmn/ABCDEFGHIJKLMNO");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "1");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "a1");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "Etc/GMT1");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "GMT1");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "GMT+1");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "GMT-1");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "EDT5EST");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "CDT6CST");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "MDT7MST");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "PDT8PST");

  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+2");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+24");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-24");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u221224");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+0:60");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+00:5");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+00:60");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-00:60");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u221200:60");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+24:59");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-24:59");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u221224:59");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+0060");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+00590");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-0060");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u22120060");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+2459");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-2459");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u22122459");

  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+00:0000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+0000:00");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+23:0000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+2300:00");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+00:5900");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+0059:00");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+00:0059");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+0000:59");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-00:0000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-0000:00");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-23:0000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-2300:00");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-00:5900");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-0059:00");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-00:0059");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-0000:59");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u221200:0000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u22120000:00");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u221223:0000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u22122300:00");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u221200:5900");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u22120059:00");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u221200:0059");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u22120000:59");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-00059");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-0:0059");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-00:059");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-000:59");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-0005:9");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-0000000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-00000000");

  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+240000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+006000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+000060");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-240000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-006000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-000060");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u2212240000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u2212006000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u2212000060");

  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+00:00:00.0000000000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-00:00:00.0000000000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u221200:00:00.0000000000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "+000000.0000000000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "-000000.0000000000");
  VERIFY_PARSE_FAIL(TimeZoneIdentifier, "\u2212000000.0000000000");
}

TEST_F(TemporalParserTest, CalendarNameSuccess) {
  // CalendarName
  VerifyParseCalendarNameSuccess("chinese");
  VerifyParseCalendarNameSuccess("roc");
  VerifyParseCalendarNameSuccess("indian");
  VerifyParseCalendarNameSuccess("persian");
  VerifyParseCalendarNameSuccess("abcd-efghi");
  VerifyParseCalendarNameSuccess("abcd-efghi");
  VerifyParseCalendarNameSuccess("a2345678-b2345678-c2345678-d7654321");
}

TEST_F(TemporalParserTest, CalendarNameIllegal) {
  VERIFY_PARSE_FAIL(CalendarName, "20210304[u-ca=]");
  VERIFY_PARSE_FAIL(CalendarName, "20210304[u-ca=a]");
  VERIFY_PARSE_FAIL(CalendarName, "20210304[u-ca=ab]");
  VERIFY_PARSE_FAIL(CalendarName, "20210304[u-ca=abcdef-ab]");
  VERIFY_PARSE_FAIL(CalendarName, "20210304[u-ca=abcdefghijkl]");
  // It is a Syntax Error if DateExtendedYear is "-000000"
  VERIFY_PARSE_FAIL(CalendarName, "-0000000304[u-ca=abcdef-ab]");
  VERIFY_PARSE_FAIL(CalendarName, "\u22120000000304[u-ca=abcdef-ab]");
  // TemporalInstantString
  VERIFY_PARSE_FAIL(CalendarName, "2021-11-08z[ABCD]");
  // CalendarDateTime
  VERIFY_PARSE_FAIL(CalendarName, "2021-11-08[u-ca=chinese]");
  VERIFY_PARSE_FAIL(CalendarName, "2021-11-08[ABCDEFG][u-ca=chinese]");
  VERIFY_PARSE_FAIL(CalendarName, "2021-11-08[ABCDEFG/hijklmn][u-ca=roc]");
  // Time
  VERIFY_PARSE_FAIL(CalendarName, "23:45:59");
  // DateSpecYearMonth
  VERIFY_PARSE_FAIL(CalendarName, "2021-12");
  // DateSpecMonthDay
  VERIFY_PARSE_FAIL(CalendarName, "--12-31");
  VERIFY_PARSE_FAIL(CalendarName, "12-31");
  VERIFY_PARSE_FAIL(CalendarName, "--1231");
}

}  // namespace internal
}  // namespace v8

"""


```