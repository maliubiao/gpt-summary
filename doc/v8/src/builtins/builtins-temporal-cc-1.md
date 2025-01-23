Response:
Let's break down the thought process for analyzing this V8 source code snippet.

**1. Initial Scan and Keyword Recognition:**

The first step is to quickly scan the code and identify recurring keywords and patterns. I see:

* `METHOD1`, `TEMPORAL_METHOD1`, `TEMPORAL_METHOD2`, `TEMPORAL_PROTOTYPE_METHOD`, `TEMPORAL_VALUE_OF`, `TEMPORAL_GET`, `TEMPORAL_GET_NUMBER_AFTER_DIVID`, `TEMPORAL_GET_BIGINT_AFTER_DIVID`: These suggest macros or helper functions for defining methods on Temporal objects. The numbers likely indicate the number of arguments. "PROTOTYPE" strongly hints at JavaScript's prototype inheritance.
* `BUILTIN`: This signifies actual C++ function implementations within V8 that are exposed to JavaScript.
* `CHECK_RECEIVER`: This is a safety check, ensuring the `this` value is of the expected type (e.g., `JSTemporalCalendar`).
* `RETURN_RESULT_OR_FAILURE`:  Indicates functions that can potentially fail, likely related to error handling in JavaScript.
* `HandleScope scope(isolate)`:  Standard V8 idiom for managing memory and resources within a function.
* `JSTemporalInstant`, `JSTemporalCalendar`, `JSTemporalTimeZone`: These look like C++ classes representing the JavaScript Temporal API objects.
* `ToString`, `toJSON`: Standard JavaScript methods.
* `Add`, `Subtract`, `Compare`, `Round`, `Since`, `Until`:  Common date/time operations.
* Specific method names like `fromEpochSeconds`, `dateAdd`, `getInstantFor`, etc.:  These clearly relate to the functionality of the Temporal API.
* `#sec-temporal.*`: These comments refer to specific sections in the ECMAScript specification for the Temporal API.
* `V8_INTL_SUPPORT`: Conditional compilation based on internationalization support.

**2. Identifying Core Functionality Areas:**

Based on the method names and class prefixes, it's clear the code is focused on three main Temporal API objects:

* `Instant`: Representing a specific moment in time.
* `Calendar`: Representing a calendar system (e.g., Gregorian).
* `TimeZone`: Representing a time zone.

**3. Mapping C++ Methods to JavaScript Equivalents (Conceptual):**

At this stage, I start mentally linking the C++ methods to their corresponding JavaScript counterparts. For example:

* `TEMPORAL_METHOD1(Instant, FromEpochSeconds)` likely corresponds to `Temporal.Instant.fromEpochSeconds()`.
* `TEMPORAL_PROTOTYPE_METHOD1(Instant, Add, add)` likely corresponds to `Temporal.Instant.prototype.add()`.
* `BUILTIN(TemporalCalendarPrototypeToString)` corresponds to `Temporal.Calendar.prototype.toString`.

**4. Analyzing `BUILTIN` Functions in Detail:**

The `BUILTIN` functions are where the core logic resides. I pay close attention to what they are doing:

* `TemporalCalendarPrototypeId`, `TemporalCalendarPrototypeToJSON`, `TemporalCalendarPrototypeToString`: These are standard methods for getting a string representation of a `Temporal.Calendar` object. They confirm that the `id` property and `toString()` method return some identifier of the calendar.
* `TemporalCalendarFrom`: This looks like the implementation of `Temporal.Calendar.from()`, which is used to create a `Temporal.Calendar` from various inputs.
* Similar analysis for `TemporalTimeZonePrototypeId`, `TemporalTimeZonePrototypeToJSON`, `TemporalTimeZonePrototypeToString`, and `TemporalTimeZoneFrom`.

**5. Inferring Data Flow and Transformations:**

The `TEMPORAL_GET_*` macros provide clues about how data is accessed and potentially transformed. For instance:

* `TEMPORAL_GET_NUMBER_AFTER_DIVID(Instant, EpochSeconds, nanoseconds, 1000000000, epochSeconds)` suggests that `EpochSeconds` is derived by dividing the `nanoseconds` value by 1,000,000,000. This confirms the relationship between different units of time.

**6. Considering the Macros:**

Although the macro definitions aren't provided in this snippet, their names are quite informative. They abstract away common patterns for defining methods, handling arguments, and performing checks. Knowing they exist helps understand the structure of the code even without the full macro definitions.

**7. Addressing the Specific Questions in the Prompt:**

Now I can specifically answer the questions based on the information gathered:

* **Functionality:** List the categories of functions (creation, comparison, arithmetic, conversion, etc.) for `Instant`, `Calendar`, and `TimeZone`.
* **.tq extension:** Explain that this file is `.cc` and therefore C++, not Torque.
* **JavaScript Relation:** Provide concrete JavaScript examples that utilize the methods listed in the C++ code.
* **Logic and Examples:**  Give examples of how the conversion methods work (e.g., `fromEpochSeconds`) and how arithmetic operations (e.g., `add`, `subtract`) might behave.
* **Common Errors:** Think about typical user mistakes when working with dates, times, and time zones, and relate them to the functions provided.
* **Summary:**  Condense the findings into a concise overview of the file's purpose.

**8. Refinement and Organization:**

Finally, I organize the information logically, using clear headings and bullet points to present the findings in an understandable manner. I ensure the JavaScript examples are correct and illustrate the C++ functionality.

This systematic approach of scanning, identifying patterns, mapping to JavaScript concepts, analyzing specific functions, and then addressing the prompt's questions leads to a comprehensive understanding of the provided V8 source code snippet.
这是目录为 `v8/src/builtins/builtins-temporal.cc` 的一个 V8 源代码片段，它主要负责实现 ECMAScript Temporal API 的内置函数。由于文件名以 `.cc` 结尾，它是一个 **C++** 源代码文件，而不是 Torque (`.tq`) 文件。

**功能归纳：**

这个文件主要定义了 `Temporal` API 中 `Instant`, `Calendar`, 和 `TimeZone` 这几个核心类的内置方法（built-in functions）。这些方法是 JavaScript 代码直接调用的底层实现。

**按类别的功能列举：**

**1. `Temporal.Instant` 类的方法：**

* **创建 `Instant` 对象：**
    * `FromEpochSeconds`: 从 Unix 纪元（1970-01-01T00:00:00Z）以来的秒数创建 `Instant` 对象。
    * `FromEpochMilliseconds`: 从 Unix 纪元以来的毫秒数创建 `Instant` 对象。
    * `FromEpochMicroseconds`: 从 Unix 纪元以来的微秒数创建 `Instant` 对象。
    * `FromEpochNanoseconds`: 从 Unix 纪元以来的纳秒数创建 `Instant` 对象。
    * `From`: 从一个表示 `Instant` 的字符串或其他对象创建 `Instant` 对象。
* **比较 `Instant` 对象：**
    * `Compare`: 比较两个 `Instant` 对象的时间顺序。
    * `Equals`: 检查两个 `Instant` 对象是否表示同一时间点。
* **获取 `Instant` 的属性：**
    * `EpochNanoseconds`: 获取 `Instant` 对象自 Unix 纪元以来的纳秒数。
    * `EpochSeconds`: 获取 `Instant` 对象自 Unix 纪元以来的秒数（向下取整）。
    * `EpochMilliseconds`: 获取 `Instant` 对象自 Unix 纪元以来的毫秒数（向下取整）。
    * `EpochMicroseconds`: 获取 `Instant` 对象自 Unix 纪元以来的微秒数（BigInt）。
* **对 `Instant` 进行运算：**
    * `Add`: 给 `Instant` 对象增加一段时间。
    * `Round`: 将 `Instant` 对象四舍五入到最近的时间单位。
    * `Since`: 计算从另一个 `Instant` 到当前 `Instant` 的持续时间。
    * `Subtract`: 从 `Instant` 对象减去一段时间。
    * `Until`: 计算从当前 `Instant` 到另一个 `Instant` 的持续时间。
* **将 `Instant` 转换为其他表示形式：**
    * `ToJSON`: 将 `Instant` 对象转换为 JSON 字符串表示。
    * `ToLocaleString`: 将 `Instant` 对象转换为本地化字符串表示。
    * `ToString`: 将 `Instant` 对象转换为 ISO 8601 格式的字符串表示。
    * `ToZonedDateTime`: 将 `Instant` 对象转换为带有时区的 `ZonedDateTime` 对象。
    * `ToZonedDateTimeISO`: 将 `Instant` 对象转换为使用 ISO 日历的带有时区的 `ZonedDateTime` 对象。

**2. `Temporal.Calendar` 类的方法：**

* **构造函数：** `TEMPORAL_CONSTRUCTOR1(Calendar)` 表示 `Temporal.Calendar` 构造函数的实现。
* **获取 `Calendar` 的属性：**
    * `id` (通过 `TemporalCalendarPrototypeId` 实现): 获取 `Calendar` 对象的标识符（例如，'iso8601'）。
* **转换为字符串表示：**
    * `toJSON` (通过 `TemporalCalendarPrototypeToJSON` 实现): 返回 `Calendar` 的标识符。
    * `toString` (通过 `TemporalCalendarPrototypeToString` 实现): 返回 `Calendar` 的标识符。
* **日期计算相关：**
    * `DateAdd`: 在指定日期上增加一段时间。
    * `DateFromFields`: 从给定的字段（年、月、日等）创建 `PlainDate` 对象。
    * `DateUntil`: 计算两个日期之间的持续时间。
    * `Day`: 获取日期中的日。
    * `DaysInMonth`: 获取月份中的天数。
    * `DaysInWeek`: 获取一周中的天数（通常为 7）。
    * `DaysInYear`: 获取年份中的天数。
    * `DayOfWeek`: 获取日期是星期几。
    * `DayOfYear`: 获取日期是年份中的第几天。
    * `InLeapYear`: 判断年份是否为闰年。
    * `MergeFields`: 合并两个字段对象。
    * `Month`: 获取日期中的月份。
    * `MonthCode`: 获取日期的月份代码（例如，'M01', 'M12'）。
    * `MonthDayFromFields`: 从给定的月份和日期字段创建 `PlainMonthDay` 对象。
    * `MonthsInYear`: 获取年份中的月份数。
    * `Year`: 获取日期中的年份。
    * `YearMonthFromFields`: 从给定的年份和月份字段创建 `PlainYearMonth` 对象。
    * `WeekOfYear`: 获取日期是年份中的第几周。
* **`from` 方法：** `TemporalCalendarFrom` 实现 `Temporal.Calendar.from()` 方法，用于从字符串或其他对象创建 `Calendar` 对象。
* **国际化支持 (V8_INTL_SUPPORT):**
    * `Era`: 获取日期的纪元（例如，'BC', 'AD'）。
    * `EraYear`: 获取日期在纪元中的年份。

**3. `Temporal.TimeZone` 类的方法：**

* **构造函数：** `TEMPORAL_CONSTRUCTOR1(TimeZone)` 表示 `Temporal.TimeZone` 构造函数的实现。
* **获取 `TimeZone` 的属性：**
    * `id` (通过 `TemporalTimeZonePrototypeId` 实现): 获取 `TimeZone` 对象的标识符（例如，'UTC', 'America/New_York'）。
* **转换为字符串表示：**
    * `toJSON` (通过 `TemporalTimeZonePrototypeToJSON` 实现): 返回 `TimeZone` 的标识符。
    * `toString` (通过 `TemporalTimeZonePrototypeToString` 实现): 返回 `TimeZone` 的标识符。
* **时区转换相关：**
    * `GetInstantFor`: 获取特定日期时间在该时区对应的 `Instant`。
    * `GetNextTransition`: 获取该时区的下一个夏令时转换点。
    * `GetOffsetNanosecondsFor`: 获取特定 `Instant` 在该时区的偏移量（纳秒）。
    * `GetOffsetStringFor`: 获取特定 `Instant` 在该时区的偏移量字符串（例如，'+08:00'）。
    * `GetPlainDateTimeFor`: 获取特定 `Instant` 在该时区的 `PlainDateTime`。
    * `GetPossibleInstantsFor`: 获取特定本地日期时间在该时区可能对应的 `Instant` 列表（处理时区歧义）。
    * `GetPreviousTransition`: 获取该时区的上一个夏令时转换点。
* **`from` 方法：** `TemporalTimeZoneFrom` 实现 `Temporal.TimeZone.from()` 方法，用于从字符串或其他对象创建 `TimeZone` 对象。

**与 JavaScript 功能的关系及示例：**

是的，这个 C++ 文件中的方法直接对应了 JavaScript 中 `Temporal` API 的功能。以下是一些 JavaScript 示例：

```javascript
// Temporal.Instant
const now = Temporal.Instant.now();
const later = now.add({ hours: 1 });
console.log(later.toString()); // 输出 ISO 8601 格式的时间戳
console.log(now.epochSeconds); // 获取自 Unix 纪元以来的秒数

// Temporal.Calendar
const calendar = new Temporal.Calendar('iso8601');
const date = new Temporal.PlainDate(2023, 10, 26, calendar);
console.log(calendar.dayOfWeek(date)); // 输出星期几 (0-6)

// Temporal.TimeZone
const utc = new Temporal.TimeZone('UTC');
const losAngeles = new Temporal.TimeZone('America/Los_Angeles');
const instant = Temporal.Instant.fromEpochSeconds(1677676800); // 某个时间戳
console.log(utc.getOffsetStringFor(instant));      // 输出 UTC 偏移量 '+00:00'
console.log(losAngeles.getOffsetStringFor(instant)); // 输出洛杉矶偏移量，例如 '-08:00' 或 '-07:00'
```

**代码逻辑推理及假设输入输出：**

以 `TEMPORAL_METHOD1(Instant, FromEpochSeconds)` 为例：

* **假设输入：** 一个表示 Unix 纪元以来秒数的数值，例如 `1677676800`。
* **逻辑推理：**  这个 C++ 函数会接收这个数值，并创建一个内部的 `JSTemporalInstant` 对象，将该秒数存储为内部表示，通常是纳秒。它可能需要进行一些内部转换和验证。
* **输出：** 一个新的 `Temporal.Instant` 对象的 JavaScript 表示，该对象代表了 `2023-03-01T00:00:00Z`。

以 `TEMPORAL_PROTOTYPE_METHOD2(Instant, Compare)` 为例：

* **假设输入：** 两个 `Temporal.Instant` 对象，例如 `instant1` 代表 `2023-10-26T10:00:00Z`，`instant2` 代表 `2023-10-26T11:00:00Z`。
* **逻辑推理：** C++ 函数会接收这两个 `JSTemporalInstant` 对象，比较它们内部存储的纳秒值。
* **输出：**  返回一个数字：
    *  负数：如果 `instant1` 早于 `instant2`。
    *  正数：如果 `instant1` 晚于 `instant2`。
    *  零：如果 `instant1` 和 `instant2` 代表同一时间点。

**涉及用户常见的编程错误：**

* **时区处理错误：** 用户可能在进行日期时间计算时没有考虑到时区，导致在不同时区下得到错误的结果。例如，直接使用 `Date` 对象进行跨时区操作容易出错，而 `Temporal` API 提供了更明确的时区处理方式。
    ```javascript
    // 错误示例 (使用 Date)
    const date = new Date('2023-10-27T00:00:00'); // 假设用户期望的是本地时间
    console.log(date.toISOString()); // 输出的可能是 UTC 时间，与用户预期不符

    // 正确示例 (使用 Temporal)
    const plainDateTime = new Temporal.PlainDateTime(2023, 10, 27, 0, 0, 0);
    const timeZone = new Temporal.TimeZone('America/New_York');
    const zonedDateTime = plainDateTime.toZonedDateTime(timeZone);
    console.log(zonedDateTime.toString());
    ```
* **纪元时间单位混淆：** 用户可能混淆 `fromEpochSeconds`, `fromEpochMilliseconds`, `fromEpochNanoseconds` 等方法，使用了错误的单位，导致创建了错误的时间点。
    ```javascript
    // 错误示例
    const wrongInstant = Temporal.Instant.fromEpochSeconds(1677676800000); // 错误地将毫秒作为秒传入
    const correctInstant = Temporal.Instant.fromEpochMilliseconds(1677676800000);

    console.log(wrongInstant.toString()); // 输出与预期不符的时间
    console.log(correctInstant.toString()); // 输出正确的时间
    ```
* **假设 `Calendar` 是全局唯一的：** 用户可能错误地认为 `Temporal.Calendar` 是一个全局单例，而实际上需要为不同的日历系统创建不同的 `Calendar` 对象。
    ```javascript
    // 错误理解
    // 实际上应该根据需要创建不同的 Calendar 实例
    const isoCalendar = new Temporal.Calendar('iso8601');
    const japaneseCalendar = new Temporal.Calendar('japanese');
    ```

**功能归纳（针对第 2 部分）：**

这部分代码主要实现了 `Temporal` API 中 `Instant`、`Calendar` 和 `TimeZone` 这三个核心类的内置方法。它涵盖了创建对象、比较、获取属性、进行算术运算、以及转换为不同表示形式等功能。对于 `Calendar` 和 `TimeZone`，还包括了从字符串创建对象以及获取标识符的方法。代码中还包含了对国际化功能的支持（通过 `V8_INTL_SUPPORT` 宏控制）。总而言之，这个文件是 V8 引擎中 `Temporal` API 的核心实现部分，负责提供 JavaScript 可以调用的底层功能。

### 提示词
```
这是目录为v8/src/builtins/builtins-temporal.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-temporal.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ETHOD1(Instant, FromEpochSeconds)
TEMPORAL_METHOD1(Instant, FromEpochMilliseconds)
TEMPORAL_METHOD1(Instant, FromEpochMicroseconds)
TEMPORAL_METHOD1(Instant, FromEpochNanoseconds)
TEMPORAL_METHOD1(Instant, From)
TEMPORAL_METHOD2(Instant, Compare)
TEMPORAL_PROTOTYPE_METHOD1(Instant, Equals, equals)
TEMPORAL_VALUE_OF(Instant)
TEMPORAL_GET(Instant, EpochNanoseconds, nanoseconds)
TEMPORAL_GET_NUMBER_AFTER_DIVID(Instant, EpochSeconds, nanoseconds, 1000000000,
                                epochSeconds)
TEMPORAL_GET_NUMBER_AFTER_DIVID(Instant, EpochMilliseconds, nanoseconds,
                                1000000, epochMilliseconds)
TEMPORAL_GET_BIGINT_AFTER_DIVID(Instant, EpochMicroseconds, nanoseconds, 1000,
                                epochMicroseconds)
TEMPORAL_PROTOTYPE_METHOD1(Instant, Add, add)
TEMPORAL_PROTOTYPE_METHOD1(Instant, Round, round)
TEMPORAL_PROTOTYPE_METHOD2(Instant, Since, since)
TEMPORAL_PROTOTYPE_METHOD1(Instant, Subtract, subtract)
TEMPORAL_PROTOTYPE_METHOD0(Instant, ToJSON, toJSON)
TEMPORAL_PROTOTYPE_METHOD2(Instant, ToLocaleString, toLocaleString)
TEMPORAL_PROTOTYPE_METHOD1(Instant, ToString, toString)
TEMPORAL_PROTOTYPE_METHOD1(Instant, ToZonedDateTime, toZonedDateTime)
TEMPORAL_PROTOTYPE_METHOD1(Instant, ToZonedDateTimeISO, toZonedDateTimeISO)
TEMPORAL_PROTOTYPE_METHOD2(Instant, Until, until)

// Calendar
TEMPORAL_CONSTRUCTOR1(Calendar)

// #sec-get-temporal.calendar.prototype.id
BUILTIN(TemporalCalendarPrototypeId) {
  HandleScope scope(isolate);
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  CHECK_RECEIVER(JSTemporalCalendar, calendar,
                 "Temporal.Calendar.prototype.id");
  // 3. Return ? ToString(calendar).
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToString(isolate, calendar));
}

// #sec-temporal.calendar.prototype.tojson
BUILTIN(TemporalCalendarPrototypeToJSON) {
  HandleScope scope(isolate);
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  CHECK_RECEIVER(JSTemporalCalendar, calendar,
                 "Temporal.Calendar.prototype.toJSON");
  // 3. Return ? ToString(calendar).
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToString(isolate, calendar));
}

// #sec-temporal.calendar.prototype.tostring
BUILTIN(TemporalCalendarPrototypeToString) {
  HandleScope scope(isolate);
  const char* method_name = "Temporal.Calendar.prototype.toString";
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  CHECK_RECEIVER(JSTemporalCalendar, calendar, method_name);
  // 3. Return calendar.[[Identifier]].
  RETURN_RESULT_OR_FAILURE(
      isolate, JSTemporalCalendar::ToString(isolate, calendar, method_name));
}

TEMPORAL_PROTOTYPE_METHOD3(Calendar, DateAdd, dateAdd)
TEMPORAL_PROTOTYPE_METHOD2(Calendar, DateFromFields, dateFromFields)
TEMPORAL_PROTOTYPE_METHOD3(Calendar, DateUntil, dateUntil)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, Day, day)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, DaysInMonth, daysInMonth)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, DaysInWeek, daysInWeek)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, DaysInYear, daysInYear)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, DayOfWeek, dayOfWeek)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, DayOfYear, dayOfYear)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, InLeapYear, inLeapYear)
TEMPORAL_PROTOTYPE_METHOD2(Calendar, MergeFields, mergeFields)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, Month, month)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, MonthCode, monthCode)
TEMPORAL_PROTOTYPE_METHOD2(Calendar, MonthDayFromFields, monthDayFromFields)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, MonthsInYear, monthsInYear)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, Year, year)
TEMPORAL_PROTOTYPE_METHOD2(Calendar, YearMonthFromFields, yearMonthFromFields)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, WeekOfYear, weekOfYear)
// #sec-temporal.calendar.from
BUILTIN(TemporalCalendarFrom) {
  HandleScope scope(isolate);
  RETURN_RESULT_OR_FAILURE(isolate, temporal::ToTemporalCalendar(
                                        isolate, args.atOrUndefined(isolate, 1),
                                        "Temporal.Calendar.from"));
}

// TimeZone
TEMPORAL_CONSTRUCTOR1(TimeZone)
TEMPORAL_PROTOTYPE_METHOD2(TimeZone, GetInstantFor, getInstantFor)
TEMPORAL_PROTOTYPE_METHOD1(TimeZone, GetNextTransition, getNextTransition)
TEMPORAL_PROTOTYPE_METHOD1(TimeZone, GetOffsetNanosecondsFor,
                           getOffsetNanosecondsFor)
TEMPORAL_PROTOTYPE_METHOD1(TimeZone, GetOffsetStringFor, getOffsetStringFor)
TEMPORAL_PROTOTYPE_METHOD2(TimeZone, GetPlainDateTimeFor, getPlainDateTimeFor)
TEMPORAL_PROTOTYPE_METHOD1(TimeZone, GetPossibleInstantsFor,
                           getPossibleInstantFor)
TEMPORAL_PROTOTYPE_METHOD1(TimeZone, GetPreviousTransition,
                           getPreviousTransition)

// #sec-get-temporal.timezone.prototype.id
BUILTIN(TemporalTimeZonePrototypeId) {
  HandleScope scope(isolate);
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  CHECK_RECEIVER(JSTemporalTimeZone, time_zone,
                 "Temporal.TimeZone.prototype.id");
  // 3. Return ? ToString(timeZone).
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToString(isolate, time_zone));
}

// #sec-temporal.timezone.prototype.tojson
BUILTIN(TemporalTimeZonePrototypeToJSON) {
  HandleScope scope(isolate);
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  CHECK_RECEIVER(JSTemporalTimeZone, time_zone,
                 "Temporal.TimeZone.prototype.toJSON");
  // 3. Return ? ToString(timeZone).
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToString(isolate, time_zone));
}

// #sec-temporal.timezone.prototype.tostring
BUILTIN(TemporalTimeZonePrototypeToString) {
  HandleScope scope(isolate);
  const char* method_name = "Temporal.TimeZone.prototype.toString";
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  CHECK_RECEIVER(JSTemporalTimeZone, time_zone, method_name);
  // 3. Return timeZone.[[Identifier]].
  RETURN_RESULT_OR_FAILURE(
      isolate, JSTemporalTimeZone::ToString(isolate, time_zone, method_name));
}

// #sec-temporal.timezone.from
BUILTIN(TemporalTimeZoneFrom) {
  HandleScope scope(isolate);
  RETURN_RESULT_OR_FAILURE(isolate, temporal::ToTemporalTimeZone(
                                        isolate, args.atOrUndefined(isolate, 1),
                                        "Temporal.TimeZone.from"));
}

#ifdef V8_INTL_SUPPORT
// Temporal.Calendar.prototype.era/eraYear
TEMPORAL_PROTOTYPE_METHOD1(Calendar, Era, era)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, EraYear, eraYEar)
// get Temporal.*.prototype.era/eraYear
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDate, Era, era)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDate, EraYear, eraYear)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDateTime, Era, era)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDateTime, EraYear, eraYear)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainYearMonth, Era, era)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainYearMonth, EraYear, eraYear)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(Era)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(EraYear)
#endif  // V8_INTL_SUPPORT
}  // namespace internal
}  // namespace v8
```