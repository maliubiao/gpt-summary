Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger V8 test file. The snippet focuses on testing the parsing of `TemporalTimeString`, `TemporalDateTimeString`, and `TemporalYearMonthString`.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The code uses `VERIFY_PARSE_FAIL` and `VerifyParse...Success` macros. This immediately suggests that the primary function is to test the parsing logic for different temporal string formats. The "Fail" tests check for invalid inputs, while the "Success" tests verify correct parsing for valid inputs.

2. **Focus on `TemporalTimeStringIllegal` Test:** This section explicitly tests various invalid `TemporalTimeString` formats. It checks for:
    * Empty strings
    * Incorrect date components when parsing a time string
    * Single-digit hour, minute, or second
    * Out-of-range hour, minute, or second values
    * Incorrect separators (like spaces instead of colons)
    * Excessive precision in fractional seconds
    * Incorrect placement of timezone information in the context of time-only strings
    * Incorrect formatting of extended years, timezone offsets, UTC designators, and timezone names.
    * Incorrect calendar annotation format.

3. **Analyze `IMPL_DATE_TIME_STRING_SUCCESS` Macro:** This macro appears to define a set of successful parsing tests that are used by `TemporalDateTimeStringSuccess`. It covers a wide range of valid `TemporalDateTimeString` formats including:
    * Basic date formats (YYYY-MM-DD, YYYYMMDD)
    * Extended year formats (+/-YYYYYY-MM-DD, +/-YYYYYYMMDD)
    * Date and time combined with different separators ('T', 't', space)
    * Time with fractional seconds (using '.' or ',')
    * Timezone offsets (+/-HH:MM, +/-HHMM, +/-HH:MM:SS, +/-HHMMSS, with fractional seconds)
    * UTC designator ('Z' or 'z')
    * Timezone names in brackets (e.g., "[Etc/GMT+1]")
    * Calendar annotations (e.g., "[u-ca=iso8601]")

4. **Examine `TemporalDateTimeStringIllegal` Test:** This section focuses on specific illegal `TemporalDateTimeString` formats, mainly:
    * Missing separators in basic date formats when they should be present according to the full datetime grammar.
    * Incorrect or incomplete extended year formats.

5. **Analyze `TemporalYearMonthStringSuccess` Test:** This section tests the successful parsing of `TemporalYearMonthString`. It covers formats that are either:
    * Year and month only (YYYY-MM, YYYYMM, with extended years)
    * Full date and time strings (which are also valid `TemporalYearMonthString` according to the grammar referenced in the code). This reuses many of the valid `TemporalDateTimeString` formats.

6. **Infer the Overall Function:**  The code systematically tests if the Temporal parser correctly identifies valid and invalid strings representing dates, times, and date-times according to the specified grammar. This is crucial for ensuring the correctness of the Temporal API in JavaScript.

7. **Consider the ".tq" Question:**  The prompt mentions ".tq" files are Torque. This is important context for understanding where the parsing logic *might* be implemented (though this particular file is C++ *testing* the parser, not the parser itself).

8. **Connect to JavaScript (if applicable):** The Temporal API is a JavaScript API for working with dates and times. The tests are verifying the underlying C++ implementation that supports this API. Therefore, examples in JavaScript demonstrating the same concepts are relevant.

9. **Think about Code Logic and Assumptions:** The tests implicitly define the expected input and output of the parser. For example, `VerifyParseTemporalTimeStringSuccess("01:02:03.456", ...)` assumes that the input string "01:02:03.456" should be parsed into specific hour, minute, second, and fraction components.

10. **Consider Common Programming Errors:**  The "Illegal" tests directly point to common errors users might make when constructing temporal strings. Examples include incorrect separators, out-of-range values, and missing components.

11. **Address the "歸納一下它的功能" (Summarize its function) instruction:** This requires a concise description of the test file's purpose.

12. **Structure the Output:**  Organize the findings into the requested categories: functionality, relation to Torque, JavaScript examples, input/output assumptions, common errors, and a final summary.

By following these steps, it's possible to generate a comprehensive and accurate description of the provided code snippet.
这是第2部分，主要集中在测试 `TemporalTimeString`， `TemporalDateTimeString` 和 `TemporalYearMonthString` 这三种时间字符串的解析功能，并验证解析器能否正确识别合法的和非法的字符串格式。

**归纳一下它的功能:**

这部分代码主要功能是测试 V8 的 Temporal API 中时间字符串的解析器 (`TemporalParser`)。它通过一系列的单元测试用例，验证了解析器对于不同格式的 `TemporalTimeString`、`TemporalDateTimeString` 和 `TemporalYearMonthString` 是否能够正确地识别和解析，以及是否能够正确地拒绝非法的字符串格式。

具体来说，这部分代码做了以下几点：

1. **测试非法 `TemporalTimeString`:**  `TemporalTimeStringIllegal` 测试用例涵盖了各种不符合 `TemporalTimeString` 规范的字符串，例如：
    * 空字符串
    * 只有部分时间信息
    * 超出范围的小时、分钟、秒
    * 错误的分隔符
    * 包含日期信息 (因为这是 `TemporalTimeString`，应该只包含时间)
    * 错误的 TimeZone 和 Calendar 注释格式。

2. **测试合法 `TemporalDateTimeString`:** `TemporalDateTimeStringSuccess` 测试用例使用 `IMPL_DATE_TIME_STRING_SUCCESS` 宏定义了一系列合法的 `TemporalDateTimeString` 格式，并验证解析器能否正确提取出年、月、日、时、分、秒以及纳秒等信息。它涵盖了各种可能的日期和时间组合，包括：
    * 基本日期格式 (YYYY-MM-DD, YYYYMMDD)
    * 扩展年份格式 (+/-YYYYYY-MM-DD, +/-YYYYYYMMDD)
    * 日期和时间的不同分隔符 (T, t, 空格)
    * 包含或不包含秒和纳秒的时间
    * 包含时区偏移量 (+/-HH:MM, +/-HHMM, +/-HH:MM:SS, +/-HHMMSS)
    * 使用 'Z' 或 'z' 表示 UTC 时间
    * 包含时区名称 ([Etc/GMT+1])
    * 包含日历注释 ([u-ca=iso8601])。

3. **测试非法 `TemporalDateTimeString`:** `TemporalDateTimeStringIllegal` 测试用例测试了一些被认为是错误的 `TemporalDateTimeString` 格式，例如缺少分隔符的日期格式。

4. **测试合法 `TemporalYearMonthString`:** `TemporalYearMonthStringSuccess` 测试用例验证了解析器能否正确解析 `TemporalYearMonthString`，它既可以接受只包含年月的格式 (YYYY-MM, YYYYMM)，也可以接受完整的日期时间格式（因为根据规范，日期时间也是合法的 YearMonth 字符串）。这部分大量复用了 `TemporalDateTimeStringSuccess` 中的合法日期时间格式。

总而言之，这部分代码是 Temporal API 解析器健壮性的重要保证，通过大量的正反面测试用例，确保解析器能够准确地处理各种符合和不符合规范的时间字符串，为 JavaScript 中使用 Temporal API 提供了可靠的基础。

如果 `v8/test/unittests/temporal/temporal-parser-unittest.cc` 以 `.tq` 结尾，那它将是使用 V8 的 Torque 语言编写的源代码。 Torque 是一种用于定义 V8 内部实现的领域特定语言，通常用于实现内置函数和运行时代码。 然而，这个文件以 `.cc` 结尾，表明它是 C++ 源代码，用于进行单元测试。

由于这段代码的功能是测试与 JavaScript 的 Temporal API 相关的字符串解析，我们可以用 JavaScript 举例说明一些它测试的场景。

**JavaScript 示例:**

```javascript
// 对应 TemporalTimeStringIllegal 中的一些失败情况
try {
  Temporal.PlainTime.from('24:00:00'); // 超过小时范围
} catch (e) {
  console.log(e); // RangeError
}

try {
  Temporal.PlainTime.from('12:60:00'); // 超过分钟范围
} catch (e) {
  console.log(e); // RangeError
}

try {
  Temporal.PlainTime.from('12:34:61'); // 超过秒范围
} catch (e) {
  console.log(e); // RangeError
}

// 对应 TemporalDateTimeStringSuccess 中的一些成功情况
const dt1 = Temporal.PlainDateTime.from('2021-11-03');
console.log(dt1.year, dt1.month, dt1.day); // 2021 11 3

const dt2 = Temporal.PlainDateTime.from('20211109T0102');
console.log(dt2.year, dt2.month, dt2.day, dt2.hour, dt2.minute); // 2021 11 9 1 2

const dt3 = Temporal.PlainDateTime.from('2021-11-09T12-12:03:04');
console.log(dt3.year, dt3.month, dt3.day, dt3.hour); // 2021 11 9 12 // 注意这里时区信息会被处理，但 PlainDateTime 不带时区

const dt4 = Temporal.PlainDateTime.from('2021-11-09[Etc/GMT+1]'); // Temporal.PlainDateTime 不直接支持时区名称
console.log(dt4.year, dt4.month, dt4.day); // 2021 11 9

// 对应 TemporalYearMonthStringSuccess 中的一些成功情况
const ym1 = Temporal.YearMonth.from('2021-11');
console.log(ym1.year, ym1.month); // 2021 11

const ym2 = Temporal.YearMonth.from('20211103');
console.log(ym2.year, ym2.month, ym2.day); // 2021 11 undefined (Temporal.YearMonth 不包含 day)

const ym3 = Temporal.YearMonth.from('2021-11-09T01');
console.log(ym3.year, ym3.month, ym3.day); // 2021 11 undefined
```

**代码逻辑推理的假设输入与输出:**

以 `VerifyParseTemporalTimeStringSuccess("01:02:03.456", ...)` 为例：

* **假设输入:** 字符串 `"01:02:03.456"`
* **预期输出:**  解析器能够识别出：
    * 小时 (Hour): 1
    * 分钟 (Minute): 2
    * 秒 (Second): 3
    * 纳秒 (Fraction): 456000000 (会将小数部分转换为纳秒)

以 `VERIFY_PARSE_FAIL(TemporalTimeString, "24:00:00");` 为例：

* **假设输入:** 字符串 `"24:00:00"`
* **预期输出:** 解析器判断该字符串不符合 `TemporalTimeString` 的规范，解析失败。

**涉及用户常见的编程错误:**

1. **日期和时间组件超出范围:**  例如，月份输入 13，小时输入 24，分钟或秒输入 60 或更大。
   ```javascript
   // 错误示例
   try {
     Temporal.PlainDate.from('2023-13-01');
   } catch (e) {
     console.error(e); // RangeError
   }

   try {
     Temporal.PlainTime.from('24:00:00');
   } catch (e) {
     console.error(e); // RangeError
   }
   ```

2. **使用错误的分隔符:** 例如，日期中使用斜杠 `/` 而不是连字符 `-`。
   ```javascript
   // 错误示例
   try {
     Temporal.PlainDate.from('2023/11/01');
   } catch (e) {
     console.error(e); // RangeError 或 SyntaxError，取决于具体实现
   }
   ```

3. **在只需要时间的情况下包含了日期信息:**  `TemporalTimeString` 应该只包含时间部分。
   ```javascript
   // 错误示例
   try {
     Temporal.PlainTime.from('2023-11-01T10:00:00');
   } catch (e) {
     console.error(e); // RangeError 或 SyntaxError
   }
   ```

4. **错误的日期时间格式组合:** 例如，日期和时间之间缺少分隔符 `T`。
   ```javascript
   // 错误示例
   try {
     Temporal.PlainDateTime.from('2023-11-01 10:00:00'); // 假设 ' ' 不是有效分隔符
   } catch (e) {
     console.error(e); // RangeError 或 SyntaxError
   }
   ```

这些测试用例帮助开发者确保 Temporal API 的解析器能够有效地捕获这些常见的用户输入错误，并给出相应的错误提示。

### 提示词
```
这是目录为v8/test/unittests/temporal/temporal-parser-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/temporal/temporal-parser-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
rTest, TemporalTimeStringIllegal) {
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