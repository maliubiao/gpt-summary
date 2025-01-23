Response:
Let's break down the thought process for answering this request.

**1. Understanding the Core Request:**

The request asks for an analysis of a C++ source code snippet (`v8/test/unittests/temporal/temporal-parser-unittest.cc`). Specifically, it wants to know its functionality, relationship to JavaScript (if any), illustrative JavaScript examples, code logic reasoning with input/output, common programming errors it might relate to, and a concise summary. The context is that this is part 3 of 4.

**2. Initial Scan and Identification of Key Patterns:**

The code snippet is clearly a series of unit tests. The naming conventions are very telling:

* `ParseTemporalYearMonthStringSuccess`, `VerifyParseTemporalYearMonthStringSuccess`: These functions are testing successful parsing of year-month strings.
* `ParseTemporalYearMonthStringIllegal`, `VERIFY_PARSE_FAIL`:  These are testing scenarios where parsing should fail.
*  The structure `TEST_F(TemporalParserTest, ...)` is a standard Google Test framework pattern for defining test cases within a test fixture.

The presence of strings like `"2021-11-09"`, `"20211109T012345Z"`, `"[Etc/GMT+1]"`, `"+12:34"` strongly suggests that this code is related to parsing date and time strings in various formats. The "Temporal" prefix further reinforces this, hinting at the ECMAScript Temporal API.

**3. Connecting to JavaScript:**

The "Temporal" keyword is a huge clue. The ECMAScript Temporal API is designed to address the shortcomings of JavaScript's built-in `Date` object. Therefore, a direct relationship exists. The C++ code is testing the parsing logic for string representations of Temporal objects.

**4. Illustrative JavaScript Examples:**

Given the connection to the Temporal API, the next step is to think about how a JavaScript developer would use the Temporal API and how the C++ code's tests relate to that usage. The tests are parsing strings to create Temporal objects. So, the JavaScript examples should demonstrate how to create these objects from strings using the `Temporal` API.

* `Temporal.PlainDate.from()`: This is the most direct equivalent of the parsing being tested for date-only strings.
* `Temporal.ZonedDateTime.from()`: This aligns with the tests involving time zones.
*  Highlighting the potential for errors in the input string format in JavaScript mirrors the "Illegal" tests in the C++ code.

**5. Code Logic Reasoning (Hypothetical):**

Since the actual parsing logic isn't provided *in this snippet*, the reasoning needs to be based on the *test cases*. The tests define the expected input and output.

* **Assumption:**  The parsing function takes a string as input.
* **Successful Parsing:** The tests show successful parsing leads to extracted year, month, and day components (and sometimes time and time zone).
* **Failed Parsing:** The tests for "Illegal" strings highlight various format errors that should cause the parsing to fail. These errors involve incorrect separators, out-of-range values, and invalid time zone formats.

**6. Common Programming Errors:**

The "Illegal" tests directly point to common programming errors users might make when working with date/time strings:

* Incorrect formats (missing separators, wrong order of components).
* Invalid values (out-of-range months, days).
* Incorrect time zone specifiers.
* Typos and syntax errors in the string representation.

Providing specific examples of these errors in JavaScript makes the connection clear.

**7. Functionality Summary (Part 3):**

The core function of this specific part of the file is to test the parsing of various string formats into Temporal date and time objects. It specifically covers:

* `TemporalYearMonthString`: Strings representing a year and month.
* `TemporalMonthDayString`: Strings representing a month and day (with optional year).
* `TemporalInstantString`: Strings representing an instant in time (with timezone offset).
* `TemporalZonedDateTimeString`: Strings representing a date and time with a specific time zone.

The tests include both successful parsing scenarios and scenarios where parsing should fail due to invalid input.

**8. Iterative Refinement (Self-Correction):**

During the process, some self-correction might be needed:

* **Initial thought:** Focus only on the date components. *Correction:* Notice the time and time zone components in many of the strings, indicating the tests are more comprehensive.
* **Initial thought:**  Assume a very specific parsing function. *Correction:* Realize the tests are verifying a more general parsing mechanism that handles multiple formats.
* **Initial thought:**  Only consider simple date formats. *Correction:* Recognize the complexity introduced by time zones and the various ways they can be represented.

By following this structured thought process, combining observation of the code patterns with knowledge of the related concepts (Temporal API, unit testing), a comprehensive and accurate answer can be constructed.
这是对 v8 源代码文件 `v8/test/unittests/temporal/temporal-parser-unittest.cc` 的第三部分分析。根据你提供的信息，我们可以推断出以下几点：

**1. 功能概括 (基于提供的代码片段):**

这部分代码的主要功能是**测试 Temporal API 中日期和时间字符串的解析功能是否正确**。它通过一系列的单元测试用例，验证了 `TemporalParser` 类能否成功地将各种符合 ISO 8601 标准的日期、年月、月日、瞬时时间和带时区的日期时间字符串解析为对应的 Temporal 对象。同时，它也测试了在解析非法格式字符串时是否会正确地失败。

具体来说，这部分测试覆盖了以下几种类型的 Temporal 字符串：

* **TemporalYearMonthString**:  测试年月字符串的解析，例如 "2021-11"。
* **TemporalMonthDayString**: 测试月日字符串的解析，例如 "--11-03" 或 "2021-11-03"。
* **TemporalInstantString**: 测试瞬时时间字符串的解析，例如 "2021-11-09Z" 或 "2021-11-09+00"。
* **TemporalZonedDateTimeString**: 测试带时区的日期时间字符串的解析，例如 "2021-11-03T02:03:04.56789z[Asia/Taipei]"。

**2. 关于文件扩展名和 Torque:**

如果 `v8/test/unittests/temporal/temporal-parser-unittest.cc` 以 `.tq` 结尾，那么它确实是一个 v8 Torque 源代码文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。然而，根据你提供的文件名，它以 `.cc` 结尾，表明这是一个 **C++** 源代码文件。因此，**它不是 Torque 源代码**。

**3. 与 JavaScript 的关系:**

V8 是 Chrome 浏览器和 Node.js 的 JavaScript 引擎。Temporal API 是一个提议中的新的 JavaScript API，旨在改进 JavaScript 中处理日期和时间的方式，以解决 `Date` 对象的许多问题。

因此，`v8/test/unittests/temporal/temporal-parser-unittest.cc` 中测试的解析功能直接与 **JavaScript 的 Temporal API** 相关。V8 引擎需要能够解析符合 Temporal API 规范的日期和时间字符串，才能在 JavaScript 代码中使用 Temporal 对象。

**JavaScript 示例:**

在 JavaScript 中，我们可以使用 `Temporal` API 的相关方法来解析字符串，这与 C++ 单元测试中验证的功能相对应。

```javascript
// 解析年月字符串
const yearMonth = Temporal.PlainYearMonth.from("2021-11");
console.log(yearMonth.year); // 输出 2021
console.log(yearMonth.month); // 输出 11

// 解析月日字符串
const monthDay = Temporal.PlainMonthDay.from("--11-03");
console.log(monthDay.month); // 输出 11
console.log(monthDay.day);   // 输出 3

// 解析带时区的日期时间字符串
const zonedDateTime = Temporal.ZonedDateTime.from("2021-11-03T02:03:04.56789z[Asia/Taipei]");
console.log(zonedDateTime.year); // 输出 2021
console.log(zonedDateTime.month); // 输出 11
console.log(zonedDateTime.day);   // 输出 3
console.log(zonedDateTime.timeZoneId); // 输出 Asia/Taipei

// 尝试解析非法字符串 (会抛出 RangeError 或 TypeError)
try {
  Temporal.PlainDate.from("2021-13-01");
} catch (e) {
  console.error("解析失败:", e);
}
```

**4. 代码逻辑推理 (假设输入与输出):**

让我们以 `VerifyParseTemporalYearMonthStringSuccess("2021-11-09 01:23:45Z", 2021, 11, 9, "");` 为例进行推理：

* **假设输入:** 字符串 "2021-11-09 01:23:45Z"
* **解析器行为:** `TemporalParser` 中的相关函数会解析该字符串，提取年、月、日等信息。
* **预期输出:**  成功解析，并提取出以下值：
    * 年份: 2021
    * 月份: 11
    * 日期: 9
    * 其他时间相关信息（在这个特定的 `VerifyParseTemporalYearMonthStringSuccess` 函数中，可能只关注日期部分，时间部分被忽略或验证为空字符串 ""）。

对于 `VERIFY_PARSE_FAIL(TemporalYearMonthString, "2021-00");`：

* **假设输入:** 字符串 "2021-00"
* **解析器行为:** `TemporalParser` 会尝试解析，但由于月份 "00" 无效。
* **预期输出:** 解析失败，并可能抛出异常或返回特定的错误代码，`VERIFY_PARSE_FAIL` 宏会检查是否发生了预期的解析失败。

**5. 涉及用户常见的编程错误:**

这些测试用例中 "TemporalYearMonthStringIllegal"、"TemporalMonthDayStringIllegal" 和 "TemporalInstantStringIllegal" 部分的测试直接反映了用户在编写处理日期时间字符串时容易犯的错误，例如：

* **日期格式错误:**
    * 使用错误的日期分隔符（例如，使用空格而不是连字符）。
    * 年、月、日的顺序错误。
    * 缺少必要的组成部分。
* **数值超出范围:**
    * 月份超出 1-12 的范围 (例如 "2021-13")。
    * 日期超出当月有效范围 (例如 "2021-11-31"，但11月只有30天)。
* **时间格式错误:**
    * 小时、分钟、秒的格式不正确。
    * 毫秒、微秒、纳秒的表示不正确。
* **时区格式错误:**
    * 时区偏移量格式错误 (例如 "+123" 而不是 "+12:00")。
    * 时区名称拼写错误或不符合 IANA 时区数据库规范。
* **使用不合法的字符:**
    * 在日期或时间部分使用非数字字符。

**JavaScript 示例 (常见错误):**

```javascript
// 错误的日期格式
try {
  Temporal.PlainDate.from("2021/11/03"); // 应该使用 "-"
} catch (e) {
  console.error("错误:", e);
}

// 月份超出范围
try {
  Temporal.PlainDate.from("2021-13-01");
} catch (e) {
  console.error("错误:", e);
}

// 时区偏移量格式错误
try {
  Temporal.Instant.from("2023-10-27T10:00:00+08"); // 应该是 +08:00
} catch (e) {
  console.error("错误:", e);
}
```

**总结 (第 3 部分的功能):**

这部分 `v8/test/unittests/temporal/temporal-parser-unittest.cc` 文件的主要功能是 **全面测试 V8 引擎中 Temporal API 相关日期和时间字符串解析器的正确性和健壮性**。它通过大量的成功和失败的测试用例，确保引擎能够按照 Temporal API 的规范准确地解析各种格式的日期时间字符串，并有效地处理非法的输入，从而保证 JavaScript 代码中 Temporal API 的正常运行。 这部分测试覆盖了年月、月日、瞬时时间和带时区的日期时间字符串的解析。

### 提示词
```
这是目录为v8/test/unittests/temporal/temporal-parser-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/temporal/temporal-parser-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```