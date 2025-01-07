Response:
Let's break down the thought process for analyzing this C++ unit test file.

1. **Understand the Goal:** The first step is to recognize this is a *unit test* file. Unit tests are designed to verify the behavior of small, isolated pieces of code. The filename `temporal-parser-unittest.cc` strongly suggests this file tests a *parser* specifically for *temporal* data.

2. **Identify the Core Functionality Under Test:** Look for the main subject of the tests. The consistent use of `VerifyParse...Success` and `VERIFY_PARSE_FAIL` macros, coupled with names like `TemporalDurationString`, `TimeZoneNumericUTCOffset`, and `CalendarName`, points to testing the parsing of different temporal string formats.

3. **Categorize the Tested Formats:**  Group the test cases by the type of temporal data being parsed:
    * **Durations:** Strings representing periods of time (e.g., "P1Y2M", "PT3H").
    * **Time Zones:**  Both numeric UTC offsets (e.g., "+05:00") and IANA time zone identifiers (e.g., "America/New_York").
    * **Calendar Names:** Identifiers for different calendar systems (e.g., "gregory", "chinese").

4. **Analyze Success Cases:** Examine the `VerifyParse...Success` calls. These calls take a test string as input and compare the parsed components against expected values. This provides concrete examples of valid input formats and their corresponding parsed outputs. Notice the pattern of extracting years, months, days, hours, minutes, seconds, and fractional seconds for durations. For time zones, the sign, hour, minute, second, and fractional second of the offset are extracted. For calendar names, the successful parsing of valid identifiers is tested.

5. **Analyze Failure Cases:** Look at the `VERIFY_PARSE_FAIL` calls. These calls assert that certain input strings should *not* be successfully parsed. This reveals the parser's constraints and expected error conditions. For example, the duration tests show that "1Y" (missing "P"), "P1.1Y" (fractional years), and "P1H" (time without "T") are invalid. Time zone failures highlight incorrect formatting, out-of-range values, and missing components. Calendar name failures showcase invalid characters or patterns.

6. **Infer Potential Code Structure (Without Seeing the Actual Parser Code):**  Based on the test cases, you can infer the general logic of the parser:
    * It likely uses regular expressions or character-by-character analysis to match the expected formats.
    * It needs to handle optional components (e.g., fractional seconds).
    * It has validation logic to ensure values are within valid ranges (e.g., hours 0-23, minutes 0-59).
    * It needs to distinguish between different temporal types (duration, time zone, calendar).

7. **Connect to JavaScript (Based on the Prompt's Clue):** The prompt mentions a possible connection to JavaScript. Knowing that JavaScript has a `Temporal` API, it's highly probable this C++ code is part of the underlying implementation for that API. The test cases mirror the string formats defined in the Temporal specification. This makes it possible to provide JavaScript examples of how these parsed strings would be used.

8. **Identify Potential User Errors:**  The failure cases directly translate to common mistakes users might make when providing temporal strings. For instance, forgetting the "P" in a duration string or using an invalid time zone format.

9. **Address Specific Instructions from the Prompt:** Go back through the prompt and ensure all parts are covered:
    * List the functions:  Done (parsing temporal strings).
    * Check for `.tq`: Not applicable.
    * JavaScript examples: Provided.
    * Code logic inference:  Provided (with assumptions on input/output).
    * Common programming errors:  Provided.
    * Summarize the functionality (for Part 4): Focus on the testing aspect and the verification of the parser's correctness.

10. **Refine and Organize:** Structure the analysis logically, using headings and bullet points to make it clear and easy to understand. Ensure the language is precise and avoids jargon where possible.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe it's testing some low-level string manipulation.
* **Correction:** The focus on *temporal* data and the specific formats points to a higher-level parser.

* **Initial thought:**  The success cases are just examples.
* **Refinement:**  The success cases are *assertions* about the parser's behavior. They define the expected output for valid inputs.

* **Initial thought:** The failure cases are random.
* **Refinement:** The failure cases are systematically testing edge cases and invalid formats to ensure the parser handles errors correctly.

By following this thought process, which involves understanding the context, identifying patterns, and relating the code to its purpose, we can effectively analyze and explain the functionality of the given unit test file.
好的，这是对 `v8/test/unittests/temporal/temporal-parser-unittest.cc` 文件功能的归纳总结，基于你提供的代码片段：

**功能归纳 (第 4 部分):**

这个 C++ 源代码文件 `v8/test/unittests/temporal/temporal-parser-unittest.cc` 是 V8 JavaScript 引擎中用于测试 Temporal API 中日期、时间和时区等字符串解析功能的单元测试文件。

**具体功能点：**

1. **测试 Duration 字符串解析 (TemporalDurationString):**
   - 验证各种格式的 Duration 字符串是否能被正确解析，包括包含年、月、周、天、小时、分钟和秒的组合。
   - 测试正负 Duration 的解析。
   - 测试使用 `+` 和 Unicode 减号 (`\u2212`) 表示正负号的情况。
   - 测试 Duration 标识符使用小写字母的情况。
   - 测试 Duration 中使用逗号作为小数分隔符的情况。
   - 测试 Duration 中包含大数字的情况。
   - 验证各种无效的 Duration 字符串是否能被正确识别并解析失败。

2. **测试 Numeric UTC Offset 解析 (TimeZoneNumericUTCOffsetBasic, TimeZoneNumericUTCOffsetIllegal):**
   - 验证各种格式的数字型 UTC 时区偏移字符串是否能被正确解析，包括：
     - `+HH`, `-HH`, `\u2212HH`
     - `+HH:MM`, `-HH:MM`, `\u2212HH:MM`
     - `+HHMM`, `-HHMM`, `\u2212HHMM`
     - `+HH:MM:SS`, `-HH:MM:SS`, `\u2212HH:MM:SS` (带或不带小数秒)
     - `+HHMMSS`, `-HHMMSS`, `\u2212HHMMSS` (带或不带小数秒)
   - 验证各种无效的数字型 UTC 时区偏移字符串是否能被正确识别并解析失败。

3. **测试 Time Zone Identifier 解析 (TimeZoneIdentifierSucccess, TimeZoneIdentifierIllegal):**
   - 验证各种格式的时区标识符字符串是否能被正确解析，包括：
     - IANA 时区名称 (例如: `Etc/GMT+0`, `America/New_York`)
     - 传统时区缩写 (例如: `EST5EDT`)
     - 数字型 UTC 偏移量格式 (例如: `+00:00:00`)
   - 验证各种无效的时区标识符字符串是否能被正确识别并解析失败。

4. **测试 Calendar Name 解析 (CalendarNameSuccess, CalendarNameIllegal):**
   - 验证有效的日历名称字符串 (例如: `chinese`, `roc`) 是否能被正确解析。
   - 验证各种无效的日历名称字符串是否能被正确识别并解析失败。

**关于文件类型的说明：**

你提到如果文件以 `.tq` 结尾，则它是 Torque 源代码。由于 `v8/test/unittests/temporal/temporal-parser-unittest.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。

**与 JavaScript 的关系：**

这个 C++ 文件中测试的解析功能是为 JavaScript 的 **Temporal API** 服务的。Temporal API 旨在改进 JavaScript 中日期和时间处理的方式。JavaScript 代码会调用 Temporal API 中的方法，这些方法在底层会依赖 C++ 代码（包括这里的解析器）来处理日期、时间和时区字符串。

**JavaScript 示例：**

```javascript
const durationString = 'P1Y2M3DT4H5M6S';
const duration = Temporal.Duration.from(durationString);
console.log(duration.years); // 输出 1
console.log(duration.months); // 输出 2
console.log(duration.days);   // 输出 3
console.log(duration.hours);  // 输出 4
console.log(duration.minutes); // 输出 5
console.log(duration.seconds); // 输出 6

const timeZoneString = '+08:00';
const timeZone = Temporal.TimeZone.from(timeZoneString);
console.log(timeZone.id); // 输出 "+08:00"

const calendarString = 'chinese';
const plainDate = new Temporal.PlainDate(2024, 1, 1, calendarString);
console.log(plainDate.calendar.id); // 输出 "chinese"
```

在这个例子中，`Temporal.Duration.from()`, `Temporal.TimeZone.from()`, 和 `Temporal.PlainDate` 构造函数在内部会使用到 C++ 的解析逻辑来处理传入的字符串。

**代码逻辑推理和假设输入/输出：**

以 `VerifyParseDurationSuccess("PT1H30M", 1, empty, empty, empty, empty, 1, empty, 30, empty, empty, empty);` 为例：

* **假设输入:** 字符串 `"PT1H30M"`
* **预期输出:**  解析器应该成功解析该字符串，并将以下组件提取出来：
    * `sign`: `1` (正数)
    * `hours`: `1`
    * `minutes`: `30`
    * 其他组件为空 (`empty`)

对于 `VERIFY_PARSE_FAIL(TemporalDurationString, "P1H");`：

* **假设输入:** 字符串 `"P1H"`
* **预期输出:** 解析器应该识别出该字符串格式不正确（缺少 "T" 分隔日期和时间部分），并解析失败。

**用户常见的编程错误：**

1. **Duration 字符串格式错误：**
   ```javascript
   // 忘记 'P'
   const wrongDuration = Temporal.Duration.from('1Y'); // 抛出 RangeError 或类似错误
   ```

2. **时区偏移量格式错误：**
   ```javascript
   // 缺少冒号
   const wrongTimeZone = Temporal.TimeZone.from('+0800'); // 可能会被解析为其他内容或抛出错误
   ```

3. **日历名称拼写错误或使用无效名称：**
   ```javascript
   const wrongCalendarDate = new Temporal.PlainDate(2024, 1, 1, 'chines'); // 可能不会报错，但会使用默认日历
   ```

**总结：**

`v8/test/unittests/temporal/temporal-parser-unittest.cc` 这个文件通过大量的单元测试用例，详尽地验证了 V8 JavaScript 引擎中 Temporal API 相关的字符串解析器的正确性和健壮性。它确保了各种合法的日期、时间和时区字符串能够被准确地解析，并且能够正确地识别并拒绝非法的字符串格式，从而为 JavaScript 开发者使用 Temporal API 提供了可靠的基础。

Prompt: 
```
这是目录为v8/test/unittests/temporal/temporal-parser-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/temporal/temporal-parser-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
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