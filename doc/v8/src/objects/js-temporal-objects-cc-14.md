Response:
The user wants to understand the functionality of the given C++ code snippet from `v8/src/objects/js-temporal-objects.cc`. They have also provided some specific constraints and questions about the code. I need to analyze the code, address each of the user's points, and summarize the overall functionality.

Here's a breakdown of the thought process:

1. **Identify the file and language:** The user explicitly states the file is `v8/src/objects/js-temporal-objects.cc`. The `.cc` extension indicates it's C++ code. The prompt also mentions `.tq`, which relates to Torque, another language used in V8. I need to note that the provided code is C++, not Torque.

2. **Determine the primary purpose:** The file name suggests it deals with JavaScript Temporal API objects. This is confirmed by the function names and the overall structure of the code, which implements methods of `JSTemporalCalendar` and `JSTemporalTimeZone`.

3. **Analyze individual functions:** I'll go through each function to understand its specific role. Key things to look for are:
    * Function name (e.g., `Difference`, `Day`, `MonthCode`, `GetInstantFor`).
    * Arguments and return types.
    * Internal V8 functions being called (e.g., `ToTemporalDate`, `CreateTemporalDuration`, `GetOptionsObject`).
    * Logic within the function (e.g., conditional checks, calculations).
    * Error handling (e.g., `THROW_NEW_ERROR`).

4. **Address specific user questions:**
    * **Functionality listing:**  Based on the analysis of individual functions, create a bulleted list summarizing their actions.
    * **Torque check:** Explicitly state that the file is C++, not Torque, based on the `.cc` extension.
    * **Relationship to JavaScript:**  For functions that directly correspond to JavaScript Temporal API methods, provide illustrative JavaScript examples. This will require understanding the purpose of the C++ code in the context of the JavaScript API.
    * **Code logic inference:** Choose a function with clear logic (like `Difference`) and demonstrate the flow with a hypothetical input and output.
    * **Common programming errors:** Identify potential errors a JavaScript developer might make when using the corresponding Temporal API methods. Think about type errors, invalid arguments, etc.
    * **Overall functionality summary:**  Based on the individual function analysis, provide a concise summary of the file's purpose.
    * **Part number:** Note that this is part 15 of 25.

5. **Structure the response:** Organize the information clearly with headings and bullet points for readability. Address each of the user's requests explicitly.

**Pre-computation and Pre-analysis (Internal Thought Process During Analysis):**

* **`Difference`:**  This function calculates the difference between two temporal dates in a specified unit. It involves converting JavaScript objects to internal `JSTemporalPlainDate` representations, getting options, and calling a core `DifferenceISODate` function.
* **`Day`, `MonthCode`, `Month`:** These functions extract specific components (day, month code, month) from a temporal date-like object. They handle different input types (`PlainDate`, `PlainDateTime`, `PlainMonthDay`, `PlainYearMonth`).
* **`MonthDayFromFields`, `YearMonthFromFields`:** These functions create `Temporal.PlainMonthDay` and `Temporal.PlainYearMonth` objects from a fields object, using the calendar's rules.
* **`Era`, `EraYear`:**  These functions deal with era and era year, and the provided code specifically handles the ISO 8601 calendar where these concepts are often undefined. The `#ifdef V8_INTL_SUPPORT` indicates that these are related to internationalization and other calendar systems.
* **`WeekOfYear`:** This function calculates the week of the year for a given date.
* **`ToString`:** This function returns the calendar's identifier (likely "iso8601" in most cases here).
* **`JSTemporalTimeZone::Now`:** Gets the system's current time zone.
* **`JSTemporalTimeZone::Constructor`:** Creates a `Temporal.TimeZone` object, handling both IANA time zone names and UTC offset strings.
* **`JSTemporalTimeZone::GetInstantFor`:** Converts a `Temporal.PlainDateTime` to a `Temporal.Instant` for a given time zone, handling disambiguation.
* **`JSTemporalTimeZone::GetPlainDateTimeFor`:**  Converts a `Temporal.Instant` to a `Temporal.PlainDateTime` in a specific time zone and calendar.
* **`JSTemporalTimeZone::GetNextTransition`, `GetPreviousTransition`:** These functions find the next or previous time zone transition (like daylight saving time changes). They are only relevant for IANA time zones, not fixed offset time zones.
* **`JSTemporalTimeZone::GetPossibleInstantsFor`:**  Given a `Temporal.PlainDateTime` and a time zone, this function returns an array of possible `Temporal.Instant` values. This is important for handling ambiguous local times around DST transitions.
* **`JSTemporalTimeZone::GetOffsetNanosecondsFor`:** Gets the UTC offset in nanoseconds for a given `Temporal.Instant` in a time zone.
* **`JSTemporalTimeZone::GetOffsetStringFor`:**  Gets the UTC offset as a string for a given `Temporal.Instant`.

By following this detailed analysis, I can construct a comprehensive and accurate response to the user's request.
好的，让我们来分析一下 `v8/src/objects/js-temporal-objects.cc` 这个 V8 源代码文件的功能。

**文件功能归纳：**

这个 C++ 文件 `v8/src/objects/js-temporal-objects.cc` 实现了 **ECMAScript Temporal API** 中 `Temporal.Calendar` 和 `Temporal.TimeZone` 两个核心类的部分功能。它包含了这些类的方法的 C++ 实现，这些方法用于处理日期、月份、年份的计算，以及时区的转换和查询。

**详细功能列举：**

* **`JSTemporalCalendar::Difference`**: 计算两个 `Temporal.PlainDate` 之间的差异，返回一个 `Temporal.Duration` 对象。可以指定最大的时间单位（例如，年、月、日）。
* **`JSTemporalCalendar::Day`**:  获取一个 Temporal 对象（`PlainDate`, `PlainDateTime`, 或 `PlainMonthDay`）的日期（day）。
* **`JSTemporalCalendar::MonthCode`**: 获取一个 Temporal 对象的月份代码（例如 "M01", "M12"）。
* **`JSTemporalCalendar::Month`**: 获取一个 Temporal 对象的月份。
* **`JSTemporalCalendar::MonthDayFromFields`**:  根据提供的字段创建一个 `Temporal.PlainMonthDay` 对象。
* **`JSTemporalCalendar::YearMonthFromFields`**: 根据提供的字段创建一个 `Temporal.PlainYearMonth` 对象。
* **`JSTemporalCalendar::Era` (在 `V8_INTL_SUPPORT` 宏定义下)**: 获取一个 Temporal 对象的纪元（era）。对于 ISO 8601 日历，通常返回 `undefined`。
* **`JSTemporalCalendar::EraYear` (在 `V8_INTL_SUPPORT` 宏定义下)**: 获取一个 Temporal 对象的纪元年（era year）。对于 ISO 8601 日历，通常返回 `undefined`。
* **`JSTemporalCalendar::WeekOfYear`**: 获取一个 `Temporal.PlainDate` 是一年中的第几周。
* **`JSTemporalCalendar::ToString`**: 返回 `Temporal.Calendar` 对象的标识符，通常是 "iso8601"。
* **`JSTemporalTimeZone::Now`**: 获取系统的当前时区。
* **`JSTemporalTimeZone::Constructor`**: `Temporal.TimeZone` 的构造函数，接受时区标识符（IANA 时区名或 UTC 偏移字符串）。
* **`JSTemporalTimeZone::GetInstantFor`**:  将一个 `Temporal.PlainDateTime` 对象转换为该时区下的 `Temporal.Instant` 对象。
* **`JSTemporalTimeZone::GetPlainDateTimeFor`**: 将一个 `Temporal.Instant` 对象转换为该时区和日历下的 `Temporal.PlainDateTime` 对象。
* **`JSTemporalTimeZone::GetNextTransition`**: 获取给定时间点之后该时区的下一个时区转换点（例如，夏令时开始）。
* **`JSTemporalTimeZone::GetPreviousTransition`**: 获取给定时间点之前该时区的上一个时区转换点。
* **`JSTemporalTimeZone::GetPossibleInstantsFor`**:  对于给定的 `Temporal.PlainDateTime`，返回该时区下所有可能的 `Temporal.Instant` 对象（用于处理时区转换时的歧义时间）。
* **`JSTemporalTimeZone::GetOffsetNanosecondsFor`**: 获取给定 `Temporal.Instant` 在该时区的 UTC 偏移量（纳秒）。
* **`JSTemporalTimeZone::GetOffsetStringFor`**: 获取给定 `Temporal.Instant` 在该时区的 UTC 偏移字符串（例如 "+08:00"）。

**关于 Torque 源代码：**

你提到如果 `v8/src/objects/js-temporal-objects.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。这是一个正确的判断。但是，由于该文件以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**。V8 使用 Torque 语言来定义一些内置的 JavaScript 函数和对象，但并非所有的 V8 源代码都是 Torque 编写的。

**与 JavaScript 功能的关系及示例：**

这些 C++ 代码直接实现了 JavaScript 中 `Temporal.Calendar` 和 `Temporal.TimeZone` 对象的方法。下面是一些 JavaScript 示例，展示了这些 C++ 代码在运行时所提供的功能：

```javascript
// Temporal.Calendar.prototype.difference
const date1 = new Temporal.PlainDate(2023, 10, 26);
const date2 = new Temporal.PlainDate(2023, 11, 15);
const duration = date1.difference(date2);
console.log(duration.days); // 输出 20

// Temporal.Calendar.prototype.day
const date = new Temporal.PlainDate(2023, 10, 26);
console.log(date.day); // 输出 26

// Temporal.Calendar.prototype.monthCode
console.log(date.monthCode); // 输出 "M10"

// Temporal.Calendar.prototype.month
console.log(date.month); // 输出 10

// Temporal.TimeZone.now
const timeZone = Temporal.Now.timeZone();
console.log(timeZone.id); // 输出例如 "Asia/Shanghai"

// Temporal.TimeZone 构造函数
const utcTimeZone = new Temporal.TimeZone('UTC');
console.log(utcTimeZone.id); // 输出 "UTC"

const shanghaiTimeZone = new Temporal.TimeZone('Asia/Shanghai');
console.log(shanghaiTimeZone.id); // 输出 "Asia/Shanghai"

// Temporal.TimeZone.prototype.getInstantFor
const dateTime = new Temporal.PlainDateTime(2023, 10, 26, 10, 30, 0);
const instant = shanghaiTimeZone.getInstantFor(dateTime);
console.log(instant.toString()); // 输出例如 "2023-10-26T02:30:00Z"

// Temporal.TimeZone.prototype.getPlainDateTimeFor
const plainDateTime = shanghaiTimeZone.getPlainDateTimeFor(instant);
console.log(plainDateTime.toString()); // 输出 "2023-10-26T10:30:00"

// Temporal.TimeZone.prototype.getOffsetStringFor
console.log(shanghaiTimeZone.getOffsetStringFor(instant)); // 输出 "+08:00"
```

**代码逻辑推理示例：**

**假设输入：**

* `one_obj` 代表 `Temporal.PlainDate(2023, 10, 10)`
* `two_obj` 代表 `Temporal.PlainDate(2023, 10, 15)`
* `options_obj` 是 `undefined`

**方法调用：** `JSTemporalCalendar::Difference(isolate, calendar, one_obj, two_obj, options_obj)`

**推理过程：**

1. `ToTemporalDate` 会将 `one_obj` 和 `two_obj` 转换为内部的 `JSTemporalPlainDate` 对象 `one` 和 `two`，分别包含 `iso_year=2023`, `iso_month=10`, `iso_day=10` 和 `iso_year=2023`, `iso_month=10`, `iso_day=15`。
2. `GetOptionsObject` 因为 `options_obj` 是 `undefined`，会创建一个空的对象作为 `options`。
3. `GetTemporalUnit` 会从 `options` 中查找 "largestUnit"，因为不存在，且默认值为 "auto"，所以 `largest_unit` 初始化为 `Unit::kAuto`。
4. 紧接着，如果 `largest_unit` 是 `Unit::kAuto`，则将其设置为 `Unit::kDay`。
5. `DifferenceISODate` 函数会被调用，传入两个日期和最大的单位 `Unit::kDay`。该函数会计算两个 ISO 日期之间的差异，返回一个 `DateDurationRecord`，其中 `days` 可能为 5，其他字段为 0。
6. `CreateTemporalDuration` 会使用 `DateDurationRecord` 中的值创建一个 `Temporal.Duration` 对象，表示 5 天的持续时间。

**输出：**  一个表示 5 天的 `Temporal.Duration` 对象。

**用户常见的编程错误示例：**

* **类型错误：**  传递了错误的类型给 Temporal API 的方法。
  ```javascript
  const date = new Temporal.PlainDate(2023, 10, 26);
  try {
    date.difference("not a Temporal.PlainDate"); // 错误：参数类型不匹配
  } catch (e) {
    console.error(e); // 输出 TypeError
  }
  ```
* **无效的参数值：** 提供了超出范围或无效的日期/时间值。
  ```javascript
  try {
    const invalidDate = new Temporal.PlainDate(2023, 13, 1); // 错误：月份超出范围
  } catch (e) {
    console.error(e); // 输出 RangeError
  }
  ```
* **时区名称错误：**  使用了不存在或拼写错误的 IANA 时区名称。
  ```javascript
  try {
    const invalidTimeZone = new Temporal.TimeZone("Invalid/TimeZone");
  } catch (e) {
    console.error(e); // 输出 RangeError
  }
  ```
* **混淆本地时间和 UTC 时间：** 在需要特定时区的时间时，错误地使用了本地时间，或者反之。

**总结 (第 15 部分，共 25 部分)：**

作为 V8 引擎中实现 ECMAScript Temporal API 的一部分，`v8/src/objects/js-temporal-objects.cc` 的这段代码主要负责 `Temporal.Calendar` 和 `Temporal.TimeZone` 对象的关键日期和时间计算、时区转换以及属性获取等核心功能。它通过 C++ 代码高效地实现了这些复杂的逻辑，为 JavaScript 开发者提供了强大的日期和时间处理能力。这部分代码是 Temporal API 实现的重要组成部分。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第15部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
j, method_name));
  // 5. Set two to ? ToTemporalDate(two).
  Handle<JSTemporalPlainDate> two;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, two,
                             ToTemporalDate(isolate, two_obj, method_name));
  // 6. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 7. Let largestUnit be ? GetTemporalUnit(options, "largestUnit", date,
  // "auto").
  Unit largest_unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, largest_unit,
      GetTemporalUnit(isolate, options, "largestUnit", UnitGroup::kDate,
                      Unit::kAuto, false, method_name),
      Handle<JSTemporalDuration>());
  // 8. If largestUnit is "auto", set largestUnit to "day".
  if (largest_unit == Unit::kAuto) largest_unit = Unit::kDay;

  // 9. Let result be ! DifferenceISODate(one.[[ISOYear]], one.[[ISOMonth]],
  // one.[[ISODay]], two.[[ISOYear]], two.[[ISOMonth]], two.[[ISODay]],
  // largestUnit).
  DateDurationRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      DifferenceISODate(isolate,
                        {one->iso_year(), one->iso_month(), one->iso_day()},
                        {two->iso_year(), two->iso_month(), two->iso_day()},
                        largest_unit, method_name),
      Handle<JSTemporalDuration>());

  // 10. Return ! CreateTemporalDuration(result.[[Years]], result.[[Months]],
  // result.[[Weeks]], result.[[Days]], 0, 0, 0, 0, 0, 0).
  return CreateTemporalDuration(isolate, {result.years,
                                          result.months,
                                          result.weeks,
                                          {result.days, 0, 0, 0, 0, 0, 0}})
      .ToHandleChecked();
}

// #sec-temporal.calendar.prototype.day
MaybeHandle<Smi> JSTemporalCalendar::Day(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]] or [[InitializedTemporalMonthDay]]
  // internal slot, then
  if (!(IsJSTemporalPlainDate(*temporal_date_like) ||
        IsJSTemporalPlainDateTime(*temporal_date_like) ||
        IsJSTemporalPlainMonthDay(*temporal_date_like))) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.day"));
  }

  // 5. Let day be ! ISODay(temporalDateLike).
  int32_t day;
  if (IsJSTemporalPlainDate(*temporal_date_like)) {
    day = Cast<JSTemporalPlainDate>(temporal_date_like)->iso_day();
  } else if (IsJSTemporalPlainDateTime(*temporal_date_like)) {
    day = Cast<JSTemporalPlainDateTime>(temporal_date_like)->iso_day();
  } else {
    DCHECK(IsJSTemporalPlainMonthDay(*temporal_date_like));
    day = Cast<JSTemporalPlainMonthDay>(temporal_date_like)->iso_day();
  }

  // 6. Return 𝔽(day).
  return handle(Smi::FromInt(day), isolate);
}

// #sec-temporal.calendar.prototype.monthcode
MaybeHandle<String> JSTemporalCalendar::MonthCode(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]], [[InitializedTemporalDateTime]],
  // [[InitializedTemporalMonthDay]], or
  // [[InitializedTemporalYearMonth]] internal slot, then
  if (!(IsPlainDatePlainDateTimeOrPlainYearMonth(temporal_date_like) ||
        IsJSTemporalPlainMonthDay(*temporal_date_like))) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.monthCode"));
  }

  // 5. Return ! ISOMonthCode(temporalDateLike).
  int32_t month;
  if (IsJSTemporalPlainDate(*temporal_date_like)) {
    month = Cast<JSTemporalPlainDate>(temporal_date_like)->iso_month();
  } else if (IsJSTemporalPlainDateTime(*temporal_date_like)) {
    month = Cast<JSTemporalPlainDateTime>(temporal_date_like)->iso_month();
  } else if (IsJSTemporalPlainMonthDay(*temporal_date_like)) {
    month = Cast<JSTemporalPlainMonthDay>(temporal_date_like)->iso_month();
  } else {
    DCHECK(IsJSTemporalPlainYearMonth(*temporal_date_like));
    month = Cast<JSTemporalPlainYearMonth>(temporal_date_like)->iso_month();
  }
  IncrementalStringBuilder builder(isolate);
  builder.AppendCharacter('M');
  if (month < 10) {
    builder.AppendCharacter('0');
  }
  builder.AppendInt(month);

  return indirect_handle(builder.Finish(), isolate);
}

// #sec-temporal.calendar.prototype.month
MaybeHandle<Smi> JSTemporalCalendar::Month(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 4. If Type(temporalDateLike) is Object and temporalDateLike has an
  // [[InitializedTemporalMonthDay]] internal slot, then
  if (IsJSTemporalPlainMonthDay(*temporal_date_like)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  // 5. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]], [[InitializedTemporalDateTime]],
  // or [[InitializedTemporalYearMonth]]
  // internal slot, then
  if (!IsPlainDatePlainDateTimeOrPlainYearMonth(temporal_date_like)) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.month"));
  }

  // 6. Return ! ISOMonth(temporalDateLike).
  int32_t month;
  if (IsJSTemporalPlainDate(*temporal_date_like)) {
    month = Cast<JSTemporalPlainDate>(temporal_date_like)->iso_month();
  } else if (IsJSTemporalPlainDateTime(*temporal_date_like)) {
    month = Cast<JSTemporalPlainDateTime>(temporal_date_like)->iso_month();
  } else {
    DCHECK(IsJSTemporalPlainYearMonth(*temporal_date_like));
    month = Cast<JSTemporalPlainYearMonth>(temporal_date_like)->iso_month();
  }

  // 7. Return 𝔽(month).
  return handle(Smi::FromInt(month), isolate);
}

// #sec-temporal.calendar.prototype.monthdayfromfields
MaybeHandle<JSTemporalPlainMonthDay> JSTemporalCalendar::MonthDayFromFields(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> fields_obj, Handle<Object> options_obj) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  const char* method_name = "Temporal.Calendar.prototype.monthDayFromFields";
  // 4. If Type(fields) is not Object, throw a TypeError exception.
  if (!IsJSReceiver(*fields_obj)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kCalledOnNonObject,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }
  Handle<JSReceiver> fields = Cast<JSReceiver>(fields_obj);
  // 5. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 6. Let result be ? ISOMonthDayFromFields(fields, options).
  if (calendar->calendar_index() == 0) {
    DateRecord result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        ISOMonthDayFromFields(isolate, fields, options, method_name),
        Handle<JSTemporalPlainMonthDay>());
    // 7. Return ? CreateTemporalMonthDay(result.[[Month]], result.[[Day]],
    // calendar, result.[[ReferenceISOYear]]).
    return CreateTemporalMonthDay(isolate, result.month, result.day, calendar,
                                  result.year);
  }
  // TODO(ftang) add intl code inside #ifdef V8_INTL_SUPPORT
  UNREACHABLE();
}

// #sec-temporal.calendar.prototype.yearmonthfromfields
MaybeHandle<JSTemporalPlainYearMonth> JSTemporalCalendar::YearMonthFromFields(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> fields_obj, Handle<Object> options_obj) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  const char* method_name = "Temporal.Calendar.prototype.yearMonthFromFields";
  // 4. If Type(fields) is not Object, throw a TypeError exception.
  if (!IsJSReceiver(*fields_obj)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kCalledOnNonObject,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }
  Handle<JSReceiver> fields = Cast<JSReceiver>(fields_obj);
  // 5. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 6. Let result be ? ISOYearMonthFromFields(fields, options).
  if (calendar->calendar_index() == 0) {
    DateRecord result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        ISOYearMonthFromFields(isolate, fields, options, method_name),
        Handle<JSTemporalPlainYearMonth>());
    // 7. Return ? CreateTemporalYearMonth(result.[[Year]], result.[[Month]],
    // calendar, result.[[ReferenceISODay]]).
    return CreateTemporalYearMonth(isolate, result.year, result.month, calendar,
                                   result.day);
  }
  // TODO(ftang) add intl code inside #ifdef V8_INTL_SUPPORT
  UNREACHABLE();
}

#ifdef V8_INTL_SUPPORT
// #sup-temporal.calendar.prototype.era
MaybeHandle<Object> JSTemporalCalendar::Era(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]], [[InitializedTemporalDateTime]],
  // or [[InitializedTemporalYearMonth]]
  // internal slot, then
  if (!IsPlainDatePlainDateTimeOrPlainYearMonth(temporal_date_like)) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.era"));
  }
  // 4. If calendar.[[Identifier]] is "iso8601", then
  if (calendar->calendar_index() == 0) {
    // a. Return undefined.
    return isolate->factory()->undefined_value();
  }
  UNIMPLEMENTED();
  // TODO(ftang) implement other calendars
  // 5. Return ! CalendarDateEra(calendar.[[Identifier]], temporalDateLike).
}

// #sup-temporal.calendar.prototype.erayear
MaybeHandle<Object> JSTemporalCalendar::EraYear(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]], [[InitializedTemporalDateTime]],
  // or [[InitializedTemporalYearMonth]]
  // internal slot, then
  if (!IsPlainDatePlainDateTimeOrPlainYearMonth(temporal_date_like)) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.eraYear"));
  }
  // 4. If calendar.[[Identifier]] is "iso8601", then
  if (calendar->calendar_index() == 0) {
    // a. Return undefined.
    return isolate->factory()->undefined_value();
  }
  UNIMPLEMENTED();
  // TODO(ftang) implement other calendars
  // 5. Let eraYear be ! CalendarDateEraYear(calendar.[[Identifier]],
  // temporalDateLike).
  // 6. If eraYear is undefined, then
  // a. Return undefined.
  // 7. Return 𝔽(eraYear).
}

#endif  // V8_INTL_SUPPORT

// #sec-temporal.calendar.prototype.weekofyear
MaybeHandle<Smi> JSTemporalCalendar::WeekOfYear(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. Let temporalDate be ? ToTemporalDate(temporalDateLike).
  Handle<JSTemporalPlainDate> temporal_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date,
      ToTemporalDate(isolate, temporal_date_like,
                     "Temporal.Calendar.prototype.weekOfYear"));
  // a. Let value be ! ToISOWeekOfYear(temporalDate.[[ISOYear]],
  // temporalDate.[[ISOMonth]], temporalDate.[[ISODay]]).
  int32_t value = ToISOWeekOfYear(
      isolate, {temporal_date->iso_year(), temporal_date->iso_month(),
                temporal_date->iso_day()});
  return handle(Smi::FromInt(value), isolate);
}

// #sec-temporal.calendar.prototype.tostring
MaybeHandle<String> JSTemporalCalendar::ToString(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    const char* method_name) {
  return CalendarIdentifier(isolate, calendar->calendar_index());
}

// #sec-temporal.now.timezone
MaybeHandle<JSTemporalTimeZone> JSTemporalTimeZone::Now(Isolate* isolate) {
  return SystemTimeZone(isolate);
}

// #sec-temporal.timezone
MaybeHandle<JSTemporalTimeZone> JSTemporalTimeZone::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> identifier_obj) {
  // 1. If NewTarget is undefined, then
  if (IsUndefined(*new_target, isolate)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kConstructorNotFunction,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     "Temporal.TimeZone")));
  }
  // 2. Set identifier to ? ToString(identifier).
  Handle<String> identifier;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, identifier,
                             Object::ToString(isolate, identifier_obj));
  Handle<String> canonical;
  // 3. If identifier satisfies the syntax of a TimeZoneNumericUTCOffset
  // (see 13.33), then
  if (IsValidTimeZoneNumericUTCOffsetString(isolate, identifier)) {
    // a. Let offsetNanoseconds be ? ParseTimeZoneOffsetString(identifier).
    int64_t offset_nanoseconds;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, offset_nanoseconds,
        ParseTimeZoneOffsetString(isolate, identifier),
        Handle<JSTemporalTimeZone>());

    // b. Let canonical be ! FormatTimeZoneOffsetString(offsetNanoseconds).
    canonical = FormatTimeZoneOffsetString(isolate, offset_nanoseconds);
  } else {
    // 4. Else,
    // a. If ! IsValidTimeZoneName(identifier) is false, then
    if (!IsValidTimeZoneName(isolate, identifier)) {
      // i. Throw a RangeError exception.
      THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidTimeZone,
                                             identifier));
    }
    // b. Let canonical be ! CanonicalizeTimeZoneName(identifier).
    canonical = CanonicalizeTimeZoneName(isolate, identifier);
  }
  // 5. Return ? CreateTemporalTimeZone(canonical, NewTarget).
  return CreateTemporalTimeZone(isolate, target, new_target, canonical);
}

namespace {

MaybeHandle<JSTemporalPlainDateTime> ToTemporalDateTime(
    Isolate* isolate, Handle<Object> item_obj, Handle<Object> options,
    const char* method_name);

MaybeHandle<JSTemporalPlainDateTime> ToTemporalDateTime(
    Isolate* isolate, Handle<Object> item_obj, const char* method_name) {
  // 1. If options is not present, set options to undefined.
  return ToTemporalDateTime(isolate, item_obj,
                            isolate->factory()->undefined_value(), method_name);
}

}  // namespace

// #sec-temporal.timezone.prototype.getinstantfor
MaybeHandle<JSTemporalInstant> JSTemporalTimeZone::GetInstantFor(
    Isolate* isolate, Handle<JSTemporalTimeZone> time_zone,
    Handle<Object> date_time_obj, Handle<Object> options_obj) {
  const char* method_name = "Temporal.TimeZone.prototype.getInstantFor";
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  // 3. Set dateTime to ? ToTemporalDateTime(dateTime).
  Handle<JSTemporalPlainDateTime> date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time,
      ToTemporalDateTime(isolate, date_time_obj, method_name));

  // 4. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 5. Let disambiguation be ? ToTemporalDisambiguation(options).
  Disambiguation disambiguation;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, disambiguation,
      ToTemporalDisambiguation(isolate, options, method_name),
      Handle<JSTemporalInstant>());

  // 6. Return ? BuiltinTimeZoneGetInstantFor(timeZone, dateTime,
  // disambiguation).
  return BuiltinTimeZoneGetInstantFor(isolate, time_zone, date_time,
                                      disambiguation, method_name);
}

namespace {

#ifdef V8_INTL_SUPPORT
Handle<Object> GetIANATimeZoneTransition(Isolate* isolate,
                                         Handle<BigInt> nanoseconds,
                                         int32_t time_zone_index,
                                         Intl::Transition transition) {
  if (time_zone_index == JSTemporalTimeZone::kUTCTimeZoneIndex) {
    return isolate->factory()->null_value();
  }
  return Intl::GetTimeZoneOffsetTransitionNanoseconds(isolate, time_zone_index,
                                                      nanoseconds, transition);
}
// #sec-temporal-getianatimezonenexttransition
Handle<Object> GetIANATimeZoneNextTransition(Isolate* isolate,
                                             Handle<BigInt> nanoseconds,
                                             int32_t time_zone_index) {
  return GetIANATimeZoneTransition(isolate, nanoseconds, time_zone_index,
                                   Intl::Transition::kNext);
}
// #sec-temporal-getianatimezoneprevioustransition
Handle<Object> GetIANATimeZonePreviousTransition(Isolate* isolate,
                                                 Handle<BigInt> nanoseconds,
                                                 int32_t time_zone_index) {
  return GetIANATimeZoneTransition(isolate, nanoseconds, time_zone_index,
                                   Intl::Transition::kPrevious);
}

Handle<Object> GetIANATimeZoneOffsetNanoseconds(Isolate* isolate,
                                                Handle<BigInt> nanoseconds,
                                                int32_t time_zone_index) {
  if (time_zone_index == JSTemporalTimeZone::kUTCTimeZoneIndex) {
    return handle(Smi::zero(), isolate);
  }

  return isolate->factory()->NewNumberFromInt64(
      Intl::GetTimeZoneOffsetNanoseconds(isolate, time_zone_index,
                                         nanoseconds));
}
#else   // V8_INTL_SUPPORT
// #sec-temporal-getianatimezonenexttransition
Handle<Object> GetIANATimeZoneNextTransition(Isolate* isolate, Handle<BigInt>,
                                             int32_t) {
  return isolate->factory()->null_value();
}
// #sec-temporal-getianatimezoneprevioustransition
Handle<Object> GetIANATimeZonePreviousTransition(Isolate* isolate,
                                                 Handle<BigInt>, int32_t) {
  return isolate->factory()->null_value();
}
Handle<Object> GetIANATimeZoneOffsetNanoseconds(Isolate* isolate,
                                                Handle<BigInt>,
                                                int32_t time_zone_index) {
  DCHECK_EQ(time_zone_index, JSTemporalTimeZone::kUTCTimeZoneIndex);
  return handle(Smi::zero(), isolate);
}
#endif  // V8_INTL_SUPPORT

}  // namespace

// #sec-temporal.timezone.prototype.getplaindatetimefor
MaybeHandle<JSTemporalPlainDateTime> JSTemporalTimeZone::GetPlainDateTimeFor(
    Isolate* isolate, Handle<JSTemporalTimeZone> time_zone,
    Handle<Object> instant_obj, Handle<Object> calendar_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.TimeZone.prototype.getPlainDateTimeFor";
  // 1. 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  // 3. Set instant to ? ToTemporalInstant(instant).
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant, ToTemporalInstant(isolate, instant_obj, method_name));
  // 4. Let calendar be ? ToTemporalCalendarWithISODefault(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ToTemporalCalendarWithISODefault(isolate, calendar_like, method_name));

  // 5. Return ? BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant,
  // calendar).
  return temporal::BuiltinTimeZoneGetPlainDateTimeFor(
      isolate, time_zone, instant, calendar, method_name);
}

// template for shared code of Temporal.TimeZone.prototype.getNextTransition and
// Temporal.TimeZone.prototype.getPreviousTransition
template <Handle<Object> (*iana_func)(Isolate*, Handle<BigInt>, int32_t)>
MaybeHandle<Object> GetTransition(Isolate* isolate,
                                  DirectHandle<JSTemporalTimeZone> time_zone,
                                  Handle<Object> starting_point_obj,
                                  const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  // 3. Set startingPoint to ? ToTemporalInstant(startingPoint).
  Handle<JSTemporalInstant> starting_point;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, starting_point,
      ToTemporalInstant(isolate, starting_point_obj, method_name));
  // 4. If timeZone.[[OffsetNanoseconds]] is not undefined, return null.
  if (time_zone->is_offset()) {
    return isolate->factory()->null_value();
  }
  // 5. Let transition be ?
  // GetIANATimeZoneNextTransition(startingPoint.[[Nanoseconds]],
  // timeZone.[[Identifier]]).
  Handle<Object> transition_obj =
      iana_func(isolate, handle(starting_point->nanoseconds(), isolate),
                time_zone->time_zone_index());
  // 6. If transition is null, return null.
  if (IsNull(*transition_obj)) {
    return isolate->factory()->null_value();
  }
  DCHECK(IsBigInt(*transition_obj));
  DirectHandle<BigInt> transition = Cast<BigInt>(transition_obj);
  // 7. Return ! CreateTemporalInstant(transition).
  return temporal::CreateTemporalInstant(isolate, transition).ToHandleChecked();
}

// #sec-temporal.timezone.prototype.getnexttransition
MaybeHandle<Object> JSTemporalTimeZone::GetNextTransition(
    Isolate* isolate, DirectHandle<JSTemporalTimeZone> time_zone,
    Handle<Object> starting_point_obj) {
  return GetTransition<GetIANATimeZoneNextTransition>(
      isolate, time_zone, starting_point_obj,
      "Temporal.TimeZone.prototype.getNextTransition");
}
// #sec-temporal.timezone.prototype.getprevioustransition
MaybeHandle<Object> JSTemporalTimeZone::GetPreviousTransition(
    Isolate* isolate, DirectHandle<JSTemporalTimeZone> time_zone,
    Handle<Object> starting_point_obj) {
  return GetTransition<GetIANATimeZonePreviousTransition>(
      isolate, time_zone, starting_point_obj,
      "Temporal.TimeZone.prototype.getPreviousTransition");
}

// #sec-temporal.timezone.prototype.getpossibleinstantsfor
// #sec-temporal-getianatimezoneepochvalue
MaybeHandle<JSArray> GetIANATimeZoneEpochValueAsArrayOfInstantForUTC(
    Isolate* isolate, const DateTimeRecord& date_time) {
  Factory* factory = isolate->factory();
  // 6. Let possibleInstants be a new empty List.
  DirectHandle<BigInt> epoch_nanoseconds =
      GetEpochFromISOParts(isolate, date_time);
  DirectHandle<FixedArray> fixed_array = factory->NewFixedArray(1);
  // 7. For each value epochNanoseconds in possibleEpochNanoseconds, do
  // a. If ! IsValidEpochNanoseconds(epochNanoseconds) is false, throw a
  // RangeError exception.
  if (!IsValidEpochNanoseconds(isolate, epoch_nanoseconds)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // b. Let instant be ! CreateTemporalInstant(epochNanoseconds).
  DirectHandle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(isolate, epoch_nanoseconds)
          .ToHandleChecked();
  // c. Append instant to possibleInstants.
  fixed_array->set(0, *instant);
  // 8. Return ! CreateArrayFromList(possibleInstants).
  return factory->NewJSArrayWithElements(fixed_array);
}

#ifdef V8_INTL_SUPPORT
MaybeHandle<JSArray> GetIANATimeZoneEpochValueAsArrayOfInstant(
    Isolate* isolate, int32_t time_zone_index,
    const DateTimeRecord& date_time) {
  Factory* factory = isolate->factory();
  if (time_zone_index == JSTemporalTimeZone::kUTCTimeZoneIndex) {
    return GetIANATimeZoneEpochValueAsArrayOfInstantForUTC(isolate, date_time);
  }

  // For TimeZone other than UTC, call ICU indirectly from Intl
  Handle<BigInt> nanoseconds_in_local_time =
      GetEpochFromISOParts(isolate, date_time);

  std::vector<Handle<BigInt>> possible_offset =
      Intl::GetTimeZonePossibleOffsetNanoseconds(isolate, time_zone_index,
                                                 nanoseconds_in_local_time);

  int32_t array_length = static_cast<int32_t>(possible_offset.size());
  DirectHandle<FixedArray> fixed_array = factory->NewFixedArray(array_length);

  for (int32_t i = 0; i < array_length; i++) {
    DirectHandle<BigInt> epoch_nanoseconds =
        BigInt::Subtract(isolate, nanoseconds_in_local_time, possible_offset[i])
            .ToHandleChecked();
    // a. If ! IsValidEpochNanoseconds(epochNanoseconds) is false, throw a
    // RangeError exception.
    if (!IsValidEpochNanoseconds(isolate, epoch_nanoseconds)) {
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
    }
    // b. Let instant be ! CreateTemporalInstant(epochNanoseconds).
    Handle<JSTemporalInstant> instant =
        temporal::CreateTemporalInstant(isolate, epoch_nanoseconds)
            .ToHandleChecked();
    // b. Append instant to possibleInstants.
    fixed_array->set(i, *(instant));
  }

  // 8. Return ! CreateArrayFromList(possibleInstants).
  return factory->NewJSArrayWithElements(fixed_array);
}

#else   //  V8_INTL_SUPPORT

MaybeHandle<JSArray> GetIANATimeZoneEpochValueAsArrayOfInstant(
    Isolate* isolate, int32_t time_zone_index,
    const DateTimeRecord& date_time) {
  DCHECK_EQ(time_zone_index, JSTemporalTimeZone::kUTCTimeZoneIndex);
  return GetIANATimeZoneEpochValueAsArrayOfInstantForUTC(isolate, date_time);
}
#endif  // V8_INTL_SUPPORT

// #sec-temporal.timezone.prototype.getpossibleinstantsfor
MaybeHandle<JSArray> JSTemporalTimeZone::GetPossibleInstantsFor(
    Isolate* isolate, DirectHandle<JSTemporalTimeZone> time_zone,
    Handle<Object> date_time_obj) {
  Factory* factory = isolate->factory();
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimezone]]).
  // 3. Set dateTime to ? ToTemporalDateTime(dateTime).
  Handle<JSTemporalPlainDateTime> date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time,
      ToTemporalDateTime(isolate, date_time_obj,
                         "Temporal.TimeZone.prototype.getPossibleInstantsFor"));
  DateTimeRecord date_time_record = {
      {date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
      {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
       date_time->iso_millisecond(), date_time->iso_microsecond(),
       date_time->iso_nanosecond()}};
  // 4. If timeZone.[[OffsetNanoseconds]] is not undefined, then
  if (time_zone->is_offset()) {
    // a. Let epochNanoseconds be ! GetEpochFromISOParts(dateTime.[[ISOYear]],
    // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
    // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
    // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
    // dateTime.[[ISONanosecond]]).
    Handle<BigInt> epoch_nanoseconds =
        GetEpochFromISOParts(isolate, date_time_record);
    // b. Let possibleEpochNanoseconds be « epochNanoseconds -
    // ℤ(timeZone.[[OffsetNanoseconds]]) ».
    epoch_nanoseconds =
        BigInt::Subtract(
            isolate, epoch_nanoseconds,
            BigInt::FromInt64(isolate, time_zone->offset_nanoseconds()))
            .ToHandleChecked();

    // The following is the step 7 and 8 for the case of step 4 under the if
    // block.

    // a. If ! IsValidEpochNanoseconds(epochNanoseconds) is false, throw a
    // RangeError exception.
    if (!IsValidEpochNanoseconds(isolate, epoch_nanoseconds)) {
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
    }

    // b. Let instant be ! CreateTemporalInstant(epochNanoseconds).

    DirectHandle<JSTemporalInstant> instant =
        temporal::CreateTemporalInstant(isolate, epoch_nanoseconds)
            .ToHandleChecked();
    // c. Return ! CreateArrayFromList(« instant »).
    DirectHandle<FixedArray> fixed_array = factory->NewFixedArray(1);
    fixed_array->set(0, *instant);
    return factory->NewJSArrayWithElements(fixed_array);
  }

  // 5. Let possibleEpochNanoseconds be ?
  // GetIANATimeZoneEpochValue(timeZone.[[Identifier]], dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]]).

  // ... Step 5-8 put into GetIANATimeZoneEpochValueAsArrayOfInstant
  // 8. Return ! CreateArrayFromList(possibleInstants).
  return GetIANATimeZoneEpochValueAsArrayOfInstant(
      isolate, time_zone->time_zone_index(), date_time_record);
}

// #sec-temporal.timezone.prototype.getoffsetnanosecondsfor
MaybeHandle<Object> JSTemporalTimeZone::GetOffsetNanosecondsFor(
    Isolate* isolate, DirectHandle<JSTemporalTimeZone> time_zone,
    Handle<Object> instant_obj) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  // 3. Set instant to ? ToTemporalInstant(instant).
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      ToTemporalInstant(isolate, instant_obj,
                        "Temporal.TimeZone.prototype.getOffsetNanosecondsFor"));
  // 4. If timeZone.[[OffsetNanoseconds]] is not undefined, return
  // timeZone.[[OffsetNanoseconds]].
  if (time_zone->is_offset()) {
    return isolate->factory()->NewNumberFromInt64(
        time_zone->offset_nanoseconds());
  }
  // 5. Return ! GetIANATimeZoneOffsetNanoseconds(instant.[[Nanoseconds]],
  // timeZone.[[Identifier]]).
  return GetIANATimeZoneOffsetNanoseconds(
      isolate, handle(instant->nanoseconds(), isolate),
      time_zone->time_zone_index());
}

// #sec-temporal.timezone.prototype.getoffsetstringfor
MaybeHandle<String> JSTemporalTimeZone::GetOffsetStringFor(
    Isolate* isolate, Handle<JSTemporalTimeZone> time_zone,
    Handle<Object> instant_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.TimeZone.prototype.getOffsetStringFor";
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  // 3. Set instant to ? ToTemporalInstant(instant).
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant, ToTemporalInstant(isolate, instant_obj, method_name));
  // 4. Return ? BuiltinTimeZoneGetOffsetStringFor(timeZone, instant).
  return BuiltinTimeZoneGetOffsetStringFor(isolate, time_zone, instant,
```