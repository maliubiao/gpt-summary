Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/js-temporal-objects.cc`. The summary should also consider:

1. **Torque source:** Whether the file would be a Torque file if it ended in `.tq`.
2. **JavaScript relationship:**  Illustrate any connection to JavaScript features with examples.
3. **Code logic reasoning:** Provide input/output examples for specific code sections.
4. **Common programming errors:**  Point out typical mistakes related to the code.
5. **Overall function:**  A concise description of the code's role as part 18/25.

**Mental Sandbox:**

*   **Identify key classes/functions:** The code heavily uses `JSTemporalPlainDateTime` and related concepts like `JSTemporalPlainDate`, `JSTemporalPlainTime`, `JSTemporalDuration`, and `JSTemporalPlainMonthDay`. The methods suggest operations on date and time values.
*   **Analyze function names:**  Names like `WithPlainDate`, `ToJSON`, `ToLocaleString`, `ToString`, `Round`, `Add`, `Subtract`, `Until`, `Since`, `GetISOFields`, `ToPlainDate`, `ToPlainTime`, `Now`, `NowISO`, and the `Constructor` for `JSTemporalPlainMonthDay` clearly indicate the functionalities implemented.
*   **Check for Torque implications:** The prompt mentions `.tq`. I need to explain that if this were Torque, it would be defining the *implementation* logic of these temporal objects at a lower level.
*   **JavaScript connection:** The code manipulates JavaScript `Object`s and `String`s. The methods correspond to methods available on `Temporal.PlainDateTime` and related objects in JavaScript. I'll need to create examples showcasing these.
*   **Logic and I/O:**  For functions like `WithPlainDate` or `RoundISODateTime`, I can devise simple scenarios with input `JSTemporalPlainDateTime` and expected output.
*   **Common errors:**  Think about typical mistakes when working with dates and times, like providing invalid date components or incorrect formatting. The code also includes error handling for invalid arguments.
*   **Part 18 of 25:** This suggests this file likely handles a specific set of functionalities within the broader Temporal API implementation in V8. I need to infer the scope of these functionalities.

**Constraint Checklist & Confidence Score:**

*   List functionalities: Yes
*   Torque info: Yes
*   JavaScript examples: Yes
*   Code logic I/O: Yes
*   Common errors: Yes
*   Summarize function (part 18/25): Yes

Confidence Score: 5/5  I have a good understanding of how to address each point.

**Strategizing complete.** I will now generate the response based on the analysis above.
这个 `v8/src/objects/js-temporal-objects.cc` 文件的功能是 **实现 JavaScript Temporal API 中的 `Temporal.PlainDateTime` 对象及其相关操作**。

**功能列举:**

这个文件包含了 `JSTemporalPlainDateTime` 类及其原型方法的 C++ 实现，主要功能包括：

*   **创建 `Temporal.PlainDateTime` 对象:**  通过 `temporal::CreateTemporalDateTime` 函数创建新的 `JSTemporalPlainDateTime` 实例。
*   **获取和设置日期部分:**
    *   `WithPlainDate`:  创建一个新的 `JSTemporalPlainDateTime` 对象，其时间部分与原对象相同，日期部分来自传入的 `Temporal.PlainDate` 对象。
*   **格式化输出:**
    *   `ToString`:  将 `Temporal.PlainDateTime` 对象格式化为字符串，支持不同的精度和日历显示选项。
    *   `ToJSON`:  将 `Temporal.PlainDateTime` 对象转换为 JSON 字符串表示。
    *   `ToLocaleString`:  根据指定的区域设置和选项，将 `Temporal.PlainDateTime` 对象格式化为本地化字符串。
*   **舍入操作:**
    *   `Round`:  将 `Temporal.PlainDateTime` 对象舍入到指定的最接近的单位。
*   **算术运算:**
    *   `Add`:  向 `Temporal.PlainDateTime` 对象添加一个 `Temporal.Duration`。
    *   `Subtract`:  从 `Temporal.PlainDateTime` 对象减去一个 `Temporal.Duration`。
*   **比较操作:**
    *   `Until`:  计算当前 `Temporal.PlainDateTime` 对象到另一个 `Temporal.PlainDateTime` 对象之间的时间间隔（返回 `Temporal.Duration`）。
    *   `Since`:  计算另一个 `Temporal.PlainDateTime` 对象到当前 `Temporal.PlainDateTime` 对象之间的时间间隔（返回 `Temporal.Duration`）。
*   **获取字段:**
    *   `GetISOFields`:  返回一个包含 `Temporal.PlainDateTime` 对象的 ISO 年、月、日、时、分、秒、毫秒、微秒、纳秒和日历信息的对象。
*   **转换为其他 Temporal 类型:**
    *   `ToPlainDate`:  提取 `Temporal.PlainDateTime` 对象的日期部分，返回一个新的 `Temporal.PlainDate` 对象。
    *   `ToPlainTime`:  提取 `Temporal.PlainDateTime` 对象的时间部分，返回一个新的 `Temporal.PlainTime` 对象。
*   **静态方法:**
    *   `Now`:  根据系统时钟和指定的时区和日历创建一个表示当前时刻的 `Temporal.PlainDateTime` 对象。
    *   `NowISO`:  根据系统时钟和指定的时区创建一个使用 ISO 8601 日历的表示当前时刻的 `Temporal.PlainDateTime` 对象。
*   **`Temporal.PlainMonthDay` 的构造函数:**  实现了 `Temporal.PlainMonthDay` 对象的创建逻辑。

**关于 Torque 源代码:**

如果 `v8/src/objects/js-temporal-objects.cc` 以 `.tq` 结尾，那么它会是一个 **V8 Torque 源代码**。 Torque 是一种用于编写 V8 内部函数的领域特定语言，它允许以更类型安全和更容易理解的方式来定义运行时代码。  在这种情况下，`.tq` 文件会包含 `JSTemporalPlainDateTime` 及其方法的 **更底层实现细节**，例如对象布局、属性访问和类型检查等。  当前的 `.cc` 文件包含了用 C++ 编写的实现逻辑。

**与 JavaScript 的关系及示例:**

`v8/src/objects/js-temporal-objects.cc` 中定义的 C++ 类和方法直接对应于 JavaScript 中 `Temporal.PlainDateTime` 对象及其原型方法的功能。

```javascript
// 创建 Temporal.PlainDateTime 对象
const dateTime = new Temporal.PlainDateTime(2023, 10, 27, 10, 30, 0);
console.log(dateTime.toString()); // 输出: 2023-10-27T10:30:00

// 使用 withPlainDate 方法
const newDate = new Temporal.PlainDate(2024, 1, 1);
const newDateTime = dateTime.withPlainDate(newDate);
console.log(newDateTime.toString()); // 输出: 2024-01-01T10:30:00

// 使用 toLocaleString 方法
console.log(dateTime.toLocaleString('zh-CN')); // 输出类似: 2023/10/27 上午10:30:00

// 使用 add 方法
const duration = new Temporal.Duration(0, 0, 0, 1); // 增加一天
const futureDateTime = dateTime.add(duration);
console.log(futureDateTime.toString()); // 输出: 2023-10-28T10:30:00

// 使用 until 方法
const anotherDateTime = new Temporal.PlainDateTime(2023, 10, 28, 12, 0, 0);
const timeUntil = dateTime.until(anotherDateTime);
console.log(timeUntil.toString()); // 输出类似: PT26H30M
```

**代码逻辑推理 (以 `WithPlainDate` 为例):**

**假设输入:**

*   `date_time`: 一个 `JSTemporalPlainDateTime` 对象，表示 2023-10-27T10:30:00。
*   `temporal_date_like`: 一个可以转换为 `JSTemporalPlainDate` 的 JavaScript 对象，例如 `new Temporal.PlainDate(2024, 1, 1)`。

**输出:**

一个新的 `JSTemporalPlainDateTime` 对象，表示 2024-01-01T10:30:00。

**代码逻辑:**

1. `ToTemporalDate` 将 `temporal_date_like` 转换为 `JSTemporalPlainDate` 对象。
2. `ConsolidateCalendars` 检查 `date_time` 和 `plain_date` 的日历是否兼容。
3. `temporal::CreateTemporalDateTime` 使用 `plain_date` 的年、月、日和 `date_time` 的时、分、秒等信息创建一个新的 `JSTemporalPlainDateTime` 对象。

**用户常见的编程错误:**

*   **提供无效的日期或时间组成部分:**  例如，尝试创建一个月份为 13 的 `Temporal.PlainDateTime` 对象。 这会在 C++ 代码的参数校验阶段抛出 `NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR()`。

    ```javascript
    // 错误示例：月份超出范围
    try {
      const invalidDateTime = new Temporal.PlainDateTime(2023, 13, 1);
    } catch (e) {
      console.error(e); // 输出 Temporal.InvalidArgRange
    }
    ```

*   **在需要 `Temporal.PlainDate` 类型的地方传递了其他类型的对象给 `withPlainDate`:** 这会导致 `ToTemporalDate` 函数抛出异常。

    ```javascript
    const dateTime = new Temporal.PlainDateTime(2023, 10, 27, 10, 30, 0);
    try {
      dateTime.withPlainDate("not a date"); // 错误：传递了字符串
    } catch (e) {
      console.error(e); // 可能输出 TypeError 或 RangeError
    }
    ```

*   **在 `Until` 或 `Since` 方法中比较具有不同日历的 `Temporal.PlainDateTime` 对象:** 代码中会调用 `CalendarEqualsBool` 进行检查，如果不相等则抛出 `NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR()`。

    ```javascript
    const date1 = new Temporal.PlainDateTime(2023, 10, 27, 10, 30, 0);
    const date2 = new Temporal.PlainDateTime(2023, 10, 28, 12, 0, 0, 'iso8601'); // 假设可以指定日历

    // 假设 date2 使用了非 iso8601 日历
    // try {
    //   date1.until(date2); // 会抛出 RangeError
    // } catch (e) {
    //   console.error(e);
    // }
    ```

**第 18 部分，共 25 部分的功能归纳:**

作为 25 个部分中的第 18 部分，`v8/src/objects/js-temporal-objects.cc` 主要负责 **`Temporal.PlainDateTime` 对象的具体实现**。它涵盖了创建、访问、修改、格式化和比较 `Temporal.PlainDateTime` 实例的核心逻辑。  考虑到这是实现 Temporal API 的一部分，之前的章节可能处理了基础的 Temporal 类型定义和辅助函数，而后续章节可能会涉及其他 Temporal 类型（如 `Temporal.PlainDate`, `Temporal.PlainTime`, `Temporal.ZonedDateTime` 等）的实现或更高级的功能。  这个文件专注于 `Temporal.PlainDateTime` 这个核心的日期和时间组合类型。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第18部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
ception.
  THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
}

}  // namespace

// #sec-temporal.plaindatetime.prototype.withplaindate
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::WithPlainDate(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> temporal_date_like) {
  // 1. Let temporalDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. Let plainDate be ? ToTemporalDate(plainDateLike).
  Handle<JSTemporalPlainDate> plain_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, plain_date,
      ToTemporalDate(isolate, temporal_date_like,
                     "Temporal.PlainDateTime.prototype.withPlainDate"));
  // 4. Let calendar be ? ConsolidateCalendars(temporalDateTime.[[Calendar]],
  // plainDate.[[Calendar]]).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ConsolidateCalendars(isolate, handle(date_time->calendar(), isolate),
                           handle(plain_date->calendar(), isolate)));
  // 5. Return ? CreateTemporalDateTime(plainDate.[[ISOYear]],
  // plainDate.[[ISOMonth]], plainDate.[[ISODay]], temporalDateTime.[[ISOHour]],
  // temporalDateTime.[[ISOMinute]], temporalDateTime.[[ISOSecond]],
  // temporalDateTime.[[ISOMillisecond]], temporalDateTime.[[ISOMicrosecond]],
  // temporalDateTime.[[ISONanosecond]], calendar).
  return temporal::CreateTemporalDateTime(
      isolate,
      {{plain_date->iso_year(), plain_date->iso_month(), plain_date->iso_day()},
       {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
        date_time->iso_millisecond(), date_time->iso_microsecond(),
        date_time->iso_nanosecond()}},
      calendar);
}

namespace {
MaybeHandle<String> TemporalDateTimeToString(Isolate* isolate,
                                             const DateTimeRecord& date_time,
                                             Handle<JSReceiver> calendar,
                                             Precision precision,
                                             ShowCalendar show_calendar) {
  IncrementalStringBuilder builder(isolate);
  // 1. Assert: isoYear, isoMonth, isoDay, hour, minute, second, millisecond,
  // microsecond, and nanosecond are integers.
  // 2. Let year be ! PadISOYear(isoYear).
  PadISOYear(&builder, date_time.date.year);

  // 3. Let month be ToZeroPaddedDecimalString(isoMonth, 2).
  builder.AppendCharacter('-');
  ToZeroPaddedDecimalString(&builder, date_time.date.month, 2);

  // 4. Let day be ToZeroPaddedDecimalString(isoDay, 2).
  builder.AppendCharacter('-');
  ToZeroPaddedDecimalString(&builder, date_time.date.day, 2);
  // 5. Let hour be ToZeroPaddedDecimalString(hour, 2).
  builder.AppendCharacter('T');
  ToZeroPaddedDecimalString(&builder, date_time.time.hour, 2);

  // 6. Let minute be ToZeroPaddedDecimalString(minute, 2).
  builder.AppendCharacter(':');
  ToZeroPaddedDecimalString(&builder, date_time.time.minute, 2);

  // 7. Let seconds be ! FormatSecondsStringPart(second, millisecond,
  // microsecond, nanosecond, precision).
  FormatSecondsStringPart(
      &builder, date_time.time.second, date_time.time.millisecond,
      date_time.time.microsecond, date_time.time.nanosecond, precision);
  // 8. Let calendarString be ? MaybeFormatCalendarAnnotation(calendar,
  // showCalendar).
  Handle<String> calendar_string;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar_string,
      MaybeFormatCalendarAnnotation(isolate, calendar, show_calendar));

  // 9. Return the string-concatenation of year, the code unit 0x002D
  // (HYPHEN-MINUS), month, the code unit 0x002D (HYPHEN-MINUS), day, 0x0054
  // (LATIN CAPITAL LETTER T), hour, the code unit 0x003A (COLON), minute,
  builder.AppendString(calendar_string);
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}
}  // namespace

// #sec-temporal.plaindatetime.prototype.tojson
MaybeHandle<String> JSTemporalPlainDateTime::ToJSON(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time) {
  return TemporalDateTimeToString(
      isolate,
      {{date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
       {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
        date_time->iso_millisecond(), date_time->iso_microsecond(),
        date_time->iso_nanosecond()}},
      Handle<JSReceiver>(date_time->calendar(), isolate), Precision::kAuto,
      ShowCalendar::kAuto);
}

// #sec-temporal.plaindatetime.prototype.tolocalestring
MaybeHandle<String> JSTemporalPlainDateTime::ToLocaleString(
    Isolate* isolate, Handle<JSTemporalPlainDateTime> date_time,
    Handle<Object> locales, Handle<Object> options) {
#ifdef V8_INTL_SUPPORT
  return JSDateTimeFormat::TemporalToLocaleString(
      isolate, date_time, locales, options,
      "Temporal.PlainDateTime.prototype.toLocaleString");
#else   //  V8_INTL_SUPPORT
  return TemporalDateTimeToString(
      isolate,
      {{date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
       {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
        date_time->iso_millisecond(), date_time->iso_microsecond(),
        date_time->iso_nanosecond()}},
      Handle<JSReceiver>(date_time->calendar(), isolate), Precision::kAuto,
      ShowCalendar::kAuto);
#endif  // V8_INTL_SUPPORT
}

namespace {

constexpr double kNsPerDay = 8.64e13;

DateTimeRecord RoundTime(
    Isolate* isolate, const TimeRecord& time, double increment, Unit unit,
    RoundingMode rounding_mode,
    // 3.a a. If dayLengthNs is not present, set dayLengthNs to nsPerDay.
    double day_length_ns = kNsPerDay);

// #sec-temporal-roundisodatetime
DateTimeRecord RoundISODateTime(
    Isolate* isolate, const DateTimeRecord& date_time, double increment,
    Unit unit, RoundingMode rounding_mode,
    // 3. If dayLength is not present, set dayLength to nsPerDay.
    double day_length_ns = kNsPerDay) {
  // 1. Assert: year, month, day, hour, minute, second, millisecond,
  // microsecond, and nanosecond are integers.
  TEMPORAL_ENTER_FUNC();
  // 2. Assert: ISODateTimeWithinLimits(year, month, day, hour, minute, second,
  // millisecond, microsecond, nanosecond) is true.
  DCHECK(ISODateTimeWithinLimits(isolate, date_time));

  // 4. Let roundedTime be ! RoundTime(hour, minute, second, millisecond,
  // microsecond, nanosecond, increment, unit, roundingMode, dayLength).
  DateTimeRecord rounded_time = RoundTime(isolate, date_time.time, increment,
                                          unit, rounding_mode, day_length_ns);
  // 5. Let balanceResult be ! BalanceISODate(year, month, day +
  // roundedTime.[[Days]]).
  rounded_time.date.year = date_time.date.year;
  rounded_time.date.month = date_time.date.month;
  rounded_time.date.day += date_time.date.day;
  DateRecord balance_result = BalanceISODate(isolate, rounded_time.date);

  // 6. Return the Record { [[Year]]: balanceResult.[[Year]], [[Month]]:
  // balanceResult.[[Month]], [[Day]]: balanceResult.[[Day]], [[Hour]]:
  // roundedTime.[[Hour]], [[Minute]]: roundedTime.[[Minute]], [[Second]]:
  // roundedTime.[[Second]], [[Millisecond]]: roundedTime.[[Millisecond]],
  // [[Microsecond]]: roundedTime.[[Microsecond]], [[Nanosecond]]:
  // roundedTime.[[Nanosecond]] }.
  return {balance_result, rounded_time.time};
}

}  // namespace

// #sec-temporal.plaindatetime.prototype.tostring
MaybeHandle<String> JSTemporalPlainDateTime::ToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainDateTime.prototype.toString";
  // 1. Let dateTime be the this value.
  // 2. Perform ? RequireInternalSlot(dateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 4. Let precision be ? ToSecondsStringPrecision(options).
  StringPrecision precision;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, precision,
      ToSecondsStringPrecision(isolate, options, method_name),
      Handle<String>());

  // 5. Let roundingMode be ? ToTemporalRoundingMode(options, "trunc").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, options, RoundingMode::kTrunc,
                             method_name),
      Handle<String>());

  // 6. Let showCalendar be ? ToShowCalendarOption(options).
  ShowCalendar show_calendar;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, show_calendar,
      ToShowCalendarOption(isolate, options, method_name), Handle<String>());

  // 7. Let result be ! RoundISODateTime(dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]], precision.[[Increment]], precision.[[Unit]],
  // roundingMode).
  DateTimeRecord result = RoundISODateTime(
      isolate,
      {{date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
       {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
        date_time->iso_millisecond(), date_time->iso_microsecond(),
        date_time->iso_nanosecond()}},
      precision.increment, precision.unit, rounding_mode);
  // 8. Return ? TemporalDateTimeToString(result.[[Year]], result.[[Month]],
  // result.[[Day]], result.[[Hour]], result.[[Minute]], result.[[Second]],
  // result.[[Millisecond]], result.[[Microsecond]], result.[[Nanosecond]],
  // dateTime.[[Calendar]], precision.[[Precision]], showCalendar).
  return TemporalDateTimeToString(isolate, result,
                                  handle(date_time->calendar(), isolate),
                                  precision.precision, show_calendar);
}

// #sec-temporal.now.plaindatetime
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::Now(
    Isolate* isolate, Handle<Object> calendar_like,
    Handle<Object> temporal_time_zone_like) {
  const char* method_name = "Temporal.Now.plainDateTime";
  // 1. Return ? SystemDateTime(temporalTimeZoneLike, calendarLike).
  return SystemDateTime(isolate, temporal_time_zone_like, calendar_like,
                        method_name);
}

// #sec-temporal.now.plaindatetimeiso
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::NowISO(
    Isolate* isolate, Handle<Object> temporal_time_zone_like) {
  const char* method_name = "Temporal.Now.plainDateTimeISO";
  // 1. Let calendar be ! GetISO8601Calendar().
  Handle<JSReceiver> calendar = temporal::GetISO8601Calendar(isolate);
  // 2. Return ? SystemDateTime(temporalTimeZoneLike, calendar).
  return SystemDateTime(isolate, temporal_time_zone_like, calendar,
                        method_name);
}

namespace {

// #sec-temporal-totemporaldatetimeroundingincrement
Maybe<double> ToTemporalDateTimeRoundingIncrement(
    Isolate* isolate, Handle<JSReceiver> normalized_option,
    Unit smallest_unit) {
  Maximum maximum;
  // 1. If smallestUnit is "day", then
  if (smallest_unit == Unit::kDay) {
    // a. Let maximum be 1.
    maximum.value = 1;
    maximum.defined = true;
    // 2. Else,
  } else {
    // a. Let maximum be !
    // MaximumTemporalDurationRoundingIncrement(smallestUnit).
    maximum = MaximumTemporalDurationRoundingIncrement(smallest_unit);
    // b. Assert: maximum is not undefined.
    DCHECK(maximum.defined);
  }
  // 3. Return ? ToTemporalRoundingIncrement(normalizedOptions, maximum, false).
  return ToTemporalRoundingIncrement(isolate, normalized_option, maximum.value,
                                     maximum.defined, false);
}

}  // namespace

// #sec-temporal.plaindatetime.prototype.round
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::Round(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> round_to_obj) {
  const char* method_name = "Temporal.PlainDateTime.prototype.round";
  Factory* factory = isolate->factory();
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(dateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. If roundTo is undefined, then
  if (IsUndefined(*round_to_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }

  Handle<JSReceiver> round_to;
  // 4. If Type(roundTo) is String, then
  if (IsString(*round_to_obj)) {
    // a. Let paramString be roundTo.
    Handle<String> param_string = Cast<String>(round_to_obj);
    // b. Set roundTo to ! OrdinaryObjectCreate(null).
    round_to = factory->NewJSObjectWithNullProto();
    // c. Perform ! CreateDataPropertyOrThrow(roundTo, "smallestUnit",
    // paramString).
    CHECK(JSReceiver::CreateDataProperty(isolate, round_to,
                                         factory->smallestUnit_string(),
                                         param_string, Just(kThrowOnError))
              .FromJust());
    // 5. Else
  } else {
    // a. Set roundTo to ? GetOptionsObject(roundTo).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, round_to,
        GetOptionsObject(isolate, round_to_obj, method_name));
  }

  // 6. Let smallestUnit be ? GetTemporalUnit(roundTo, "smallestUnit", time,
  // required).
  Unit smallest_unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, smallest_unit,
      GetTemporalUnit(isolate, round_to, "smallestUnit", UnitGroup::kTime,
                      Unit::kDay, true, method_name),
      Handle<JSTemporalPlainDateTime>());

  // 7. Let roundingMode be ? ToTemporalRoundingMode(roundTo, "halfExpand").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, round_to, RoundingMode::kHalfExpand,
                             method_name),
      Handle<JSTemporalPlainDateTime>());

  // 8. Let roundingIncrement be ? ToTemporalDateTimeRoundingIncrement(roundTo,
  // smallestUnit).
  double rounding_increment;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_increment,
      ToTemporalDateTimeRoundingIncrement(isolate, round_to, smallest_unit),
      Handle<JSTemporalPlainDateTime>());

  // 9. Let result be ! RoundISODateTime(dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]], roundingIncrement, smallestUnit, roundingMode).
  DateTimeRecord result = RoundISODateTime(
      isolate,
      {{date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
       {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
        date_time->iso_millisecond(), date_time->iso_microsecond(),
        date_time->iso_nanosecond()}},
      rounding_increment, smallest_unit, rounding_mode);

  // 10. Return ? CreateTemporalDateTime(result.[[Year]], result.[[Month]],
  // result.[[Day]], result.[[Hour]], result.[[Minute]], result.[[Second]],
  // result.[[Millisecond]], result.[[Microsecond]], result.[[Nanosecond]],
  // dateTime.[[Calendar]]).
  return temporal::CreateTemporalDateTime(
      isolate, result, handle(date_time->calendar(), isolate));
}

namespace {

MaybeHandle<JSTemporalPlainDateTime>
AddDurationToOrSubtractDurationFromPlainDateTime(
    Isolate* isolate, Arithmetic operation,
    DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> temporal_duration_like, Handle<Object> options_obj,
    const char* method_name) {
  // 1. If operation is subtract, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == Arithmetic::kSubtract ? -1.0 : 1.0;
  // 2. Let duration be ? ToTemporalDurationRecord(temporalDurationLike).
  DurationRecord duration;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, duration,
      temporal::ToTemporalDurationRecord(isolate, temporal_duration_like,
                                         method_name),
      Handle<JSTemporalPlainDateTime>());

  TimeDurationRecord& time_duration = duration.time_duration;

  // 3. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 4. Let result be ? AddDateTime(dateTime.[[ISOYear]], dateTime.[[ISOMonth]],
  // dateTime.[[ISODay]], dateTime.[[ISOHour]], dateTime.[[ISOMinute]],
  // dateTime.[[ISOSecond]], dateTime.[[ISOMillisecond]],
  // dateTime.[[ISOMicrosecond]], dateTime.[[ISONanosecond]],
  // dateTime.[[Calendar]], duration.[[Years]], duration.[[Months]],
  // duration.[[Weeks]], duration.[[Days]], duration.[[Hours]],
  // duration.[[Minutes]], duration.[[Seconds]], duration.[[Milliseconds]],
  // duration.[[Microseconds]], duration.[[Nanoseconds]], options).
  DateTimeRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      AddDateTime(isolate,
                  {{date_time->iso_year(), date_time->iso_month(),
                    date_time->iso_day()},
                   {date_time->iso_hour(), date_time->iso_minute(),
                    date_time->iso_second(), date_time->iso_millisecond(),
                    date_time->iso_microsecond(), date_time->iso_nanosecond()}},
                  handle(date_time->calendar(), isolate),
                  {sign * duration.years,
                   sign * duration.months,
                   sign * duration.weeks,
                   {sign * time_duration.days, sign * time_duration.hours,
                    sign * time_duration.minutes, sign * time_duration.seconds,
                    sign * time_duration.milliseconds,
                    sign * time_duration.microseconds,
                    sign * time_duration.nanoseconds}},
                  options),
      Handle<JSTemporalPlainDateTime>());

  // 5. Assert: ! IsValidISODate(result.[[Year]], result.[[Month]],
  // result.[[Day]]) is true.
  DCHECK(IsValidISODate(isolate, result.date));
  // 6. Assert: ! IsValidTime(result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]]) is true.
  DCHECK(IsValidTime(isolate, result.time));
  // 7. Return ? CreateTemporalDateTime(result.[[Year]], result.[[Month]],
  // result.[[Day]], result.[[Hour]], result.[[Minute]], result.[[Second]],
  // result.[[Millisecond]], result.[[Microsecond]], result.[[Nanosecond]],
  // dateTime.[[Calendar]]).
  return temporal::CreateTemporalDateTime(
      isolate, result, handle(date_time->calendar(), isolate));
}

}  // namespace

// #sec-temporal.plaindatetime.prototype.add
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::Add(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> temporal_duration_like, Handle<Object> options) {
  return AddDurationToOrSubtractDurationFromPlainDateTime(
      isolate, Arithmetic::kAdd, date_time, temporal_duration_like, options,
      "Temporal.PlainDateTime.prototype.add");
}

// #sec-temporal.plaindatetime.prototype.subtract
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::Subtract(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> temporal_duration_like, Handle<Object> options) {
  return AddDurationToOrSubtractDurationFromPlainDateTime(
      isolate, Arithmetic::kSubtract, date_time, temporal_duration_like,
      options, "Temporal.PlainDateTime.prototype.subtract");
}

namespace {

// #sec-temporal-differencetemporalplaindatetime
MaybeHandle<JSTemporalDuration> DifferenceTemporalPlainDateTime(
    Isolate* isolate, TimePreposition operation,
    DirectHandle<JSTemporalPlainDateTime> date_time, Handle<Object> other_obj,
    Handle<Object> options, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. If operation is since, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == TimePreposition::kSince ? -1 : 1;
  // 2. Set other to ? ToTemporalDateTime(other).
  Handle<JSTemporalPlainDateTime> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other, ToTemporalDateTime(isolate, other_obj, method_name));
  // 3. If ? CalendarEquals(dateTime.[[Calendar]], other.[[Calendar]]) is false,
  // throw a RangeError exception.
  bool calendar_equals;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar_equals,
      CalendarEqualsBool(isolate, handle(date_time->calendar(), isolate),
                         handle(other->calendar(), isolate)),
      Handle<JSTemporalDuration>());
  if (!calendar_equals) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 4. Let settings be ? GetDifferenceSettings(operation, options, datetime, «
  // », "nanosecond", "day").
  DifferenceSettings settings;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, settings,
      GetDifferenceSettings(isolate, operation, options, UnitGroup::kDateTime,
                            DisallowedUnitsInDifferenceSettings::kNone,
                            Unit::kNanosecond, Unit::kDay, method_name),
      Handle<JSTemporalDuration>());
  // 5. Let diff be ? DifferenceISODateTime(dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]], other.[[ISOYear]], other.[[ISOMonth]],
  // other.[[ISODay]], other.[[ISOHour]], other.[[ISOMinute]],
  // other.[[ISOSecond]], other.[[ISOMillisecond]], other.[[ISOMicrosecond]],
  // other.[[ISONanosecond]], dateTime.[[Calendar]], settings.[[LargestUnit]],
  // settings.[[Options]]).
  DurationRecord diff;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, diff,
      DifferenceISODateTime(
          isolate,
          {{date_time->iso_year(), date_time->iso_month(),
            date_time->iso_day()},
           {date_time->iso_hour(), date_time->iso_minute(),
            date_time->iso_second(), date_time->iso_millisecond(),
            date_time->iso_microsecond(), date_time->iso_nanosecond()}},
          {{other->iso_year(), other->iso_month(), other->iso_day()},
           {other->iso_hour(), other->iso_minute(), other->iso_second(),
            other->iso_millisecond(), other->iso_microsecond(),
            other->iso_nanosecond()}},
          handle(date_time->calendar(), isolate), settings.largest_unit,
          settings.options, method_name),
      Handle<JSTemporalDuration>());
  // 6. Let relativeTo be ! CreateTemporalDate(dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[Calendar]]).
  Handle<JSTemporalPlainDate> relative_to;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, relative_to,
      CreateTemporalDate(
          isolate,
          {date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
          handle(date_time->calendar(), isolate)),
      Handle<JSTemporalDuration>());
  // 7. Let roundResult be (? RoundDuration(diff.[[Years]], diff.[[Months]],
  // diff.[[Weeks]], diff.[[Days]], diff.[[Hours]], diff.[[Minutes]],
  // diff.[[Seconds]], diff.[[Milliseconds]], diff.[[Microseconds]],
  // diff.[[Nanoseconds]], settings.[[RoundingIncrement]],
  // settings.[[SmallestUnit]], settings.[[RoundingMode]],
  // relativeTo)).[[DurationRecord]].
  DurationRecordWithRemainder round_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, round_result,
      RoundDuration(isolate, diff, settings.rounding_increment,
                    settings.smallest_unit, settings.rounding_mode, relative_to,
                    method_name),
      Handle<JSTemporalDuration>());
  // 8. Let result be ? BalanceDuration(roundResult.[[Days]],
  // roundResult.[[Hours]], roundResult.[[Minutes]], roundResult.[[Seconds]],
  // roundResult.[[Milliseconds]], roundResult.[[Microseconds]],
  // roundResult.[[Nanoseconds]], settings.[[LargestUnit]]).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, round_result.record.time_duration,
      BalanceDuration(isolate, settings.largest_unit,
                      round_result.record.time_duration, method_name),
      Handle<JSTemporalDuration>());
  // 9. Return ! CreateTemporalDuration(sign × roundResult.[[Years]], sign ×
  // roundResult.[[Months]], sign × roundResult.[[Weeks]], sign ×
  // result.[[Days]], sign × result.[[Hours]], sign × result.[[Minutes]], sign ×
  // result.[[Seconds]], sign × result.[[Milliseconds]], sign ×
  // result.[[Microseconds]], sign × result.[[Nanoseconds]]).
  return CreateTemporalDuration(
             isolate, {sign * round_result.record.years,
                       sign * round_result.record.months,
                       sign * round_result.record.weeks,
                       {sign * round_result.record.time_duration.days,
                        sign * round_result.record.time_duration.hours,
                        sign * round_result.record.time_duration.minutes,
                        sign * round_result.record.time_duration.seconds,
                        sign * round_result.record.time_duration.milliseconds,
                        sign * round_result.record.time_duration.microseconds,
                        sign * round_result.record.time_duration.nanoseconds}})
      .ToHandleChecked();
}

}  // namespace

// #sec-temporal.plaindatetime.prototype.until
MaybeHandle<JSTemporalDuration> JSTemporalPlainDateTime::Until(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalPlainDateTime(
      isolate, TimePreposition::kUntil, handle, other, options,
      "Temporal.PlainDateTime.prototype.until");
}

// #sec-temporal.plaindatetime.prototype.since
MaybeHandle<JSTemporalDuration> JSTemporalPlainDateTime::Since(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalPlainDateTime(
      isolate, TimePreposition::kSince, handle, other, options,
      "Temporal.PlainDateTime.prototype.since");
}

// #sec-temporal.plaindatetime.prototype.getisofields
MaybeHandle<JSReceiver> JSTemporalPlainDateTime::GetISOFields(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time) {
  Factory* factory = isolate->factory();
  // 1. Let dateTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. Let fields be ! OrdinaryObjectCreate(%Object.prototype%).
  Handle<JSObject> fields =
      isolate->factory()->NewJSObject(isolate->object_function());
  // 4. Perform ! CreateDataPropertyOrThrow(fields, "calendar",
  // temporalTime.[[Calendar]]).
  CHECK(JSReceiver::CreateDataProperty(
            isolate, fields, factory->calendar_string(),
            Handle<JSReceiver>(date_time->calendar(), isolate),
            Just(kThrowOnError))
            .FromJust());
  // 5. Perform ! CreateDataPropertyOrThrow(fields, "isoDay",
  // 𝔽(dateTime.[[ISODay]])).
  // 6. Perform ! CreateDataPropertyOrThrow(fields, "isoHour",
  // 𝔽(temporalTime.[[ISOHour]])).
  // 7. Perform ! CreateDataPropertyOrThrow(fields, "isoMicrosecond",
  // 𝔽(temporalTime.[[ISOMicrosecond]])).
  // 8. Perform ! CreateDataPropertyOrThrow(fields, "isoMillisecond",
  // 𝔽(temporalTime.[[ISOMillisecond]])).
  // 9. Perform ! CreateDataPropertyOrThrow(fields, "isoMinute",
  // 𝔽(temporalTime.[[ISOMinute]])).
  // 10. Perform ! CreateDataPropertyOrThrow(fields, "isoMonth",
  // 𝔽(temporalTime.[[ISOMonth]])).
  // 11. Perform ! CreateDataPropertyOrThrow(fields, "isoNanosecond",
  // 𝔽(temporalTime.[[ISONanosecond]])).
  // 12. Perform ! CreateDataPropertyOrThrow(fields, "isoSecond",
  // 𝔽(temporalTime.[[ISOSecond]])).
  // 13. Perform ! CreateDataPropertyOrThrow(fields, "isoYear",
  // 𝔽(temporalTime.[[ISOYear]])).
  DEFINE_INT_FIELD(fields, isoDay, iso_day, date_time)
  DEFINE_INT_FIELD(fields, isoHour, iso_hour, date_time)
  DEFINE_INT_FIELD(fields, isoMicrosecond, iso_microsecond, date_time)
  DEFINE_INT_FIELD(fields, isoMillisecond, iso_millisecond, date_time)
  DEFINE_INT_FIELD(fields, isoMinute, iso_minute, date_time)
  DEFINE_INT_FIELD(fields, isoMonth, iso_month, date_time)
  DEFINE_INT_FIELD(fields, isoNanosecond, iso_nanosecond, date_time)
  DEFINE_INT_FIELD(fields, isoSecond, iso_second, date_time)
  DEFINE_INT_FIELD(fields, isoYear, iso_year, date_time)
  // 14. Return fields.
  return fields;
}

// #sec-temporal.plaindatetime.prototype.toplaindate
MaybeHandle<JSTemporalPlainDate> JSTemporalPlainDateTime::ToPlainDate(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time) {
  // 1. Let dateTime be the this value.
  // 2. Perform ? RequireInternalSlot(dateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. Return ? CreateTemporalDate(dateTime.[[ISOYear]], dateTime.[[ISOMonth]],
  // dateTime.[[ISODay]], dateTime.[[Calendar]]).
  return CreateTemporalDate(
      isolate,
      {date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
      Handle<JSReceiver>(date_time->calendar(), isolate));
}

// #sec-temporal.plaindatetime.prototype.toplaintime
MaybeHandle<JSTemporalPlainTime> JSTemporalPlainDateTime::ToPlainTime(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time) {
  // 1. Let dateTime be the this value.
  // 2. Perform ? RequireInternalSlot(dateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. Return ? CreateTemporalTime(dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]]).
  return CreateTemporalTime(
      isolate, {date_time->iso_hour(), date_time->iso_minute(),
                date_time->iso_second(), date_time->iso_millisecond(),
                date_time->iso_microsecond(), date_time->iso_nanosecond()});
}

// #sec-temporal.plainmonthday
MaybeHandle<JSTemporalPlainMonthDay> JSTemporalPlainMonthDay::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> iso_month_obj, Handle<Object> iso_day_obj,
    Handle<Object> calendar_like, Handle<Object> reference_iso_year_obj) {
  const char* method_name = "Temporal.PlainMonthDay";
  // 1. If NewTarget is undefined, throw a TypeError exception.
  if (IsUndefined(*new_target)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }

  // 3. Let m be ? ToIntegerThrowOnInfinity(isoMonth).
  TO_INT_THROW_ON_INFTY(iso_month, JSTemporalPlainMonthDay);
  // 5. Let d be ? ToIntegerThrowOnInfinity(isoDay).
  TO_INT_THROW_ON_INFTY(iso_day, JSTemporalPlainMonthDay);
  // 7. Let calendar be ? ToTemporalCalendarWithISODefault(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ToTemporalCalendarWithISODefault(isolate, calendar_like, method_name));

  // 2. If referenceISOYear is undefined, then
  // a. Set referenceISOYear to 1972𝔽.
  // ...
  // 8. Let ref be ? ToIntegerThrowOnInfinity(referenceISOYear).
  int32_t ref = 1972;
  if (!IsUndefined(*reference_iso_year_obj)) {
    TO_INT_THROW_ON_INFTY(reference_iso_year, JSTemporalPlainMonthDay);
    ref = reference_iso_year;
  }

  // 10. Return ? CreateTemporalMonthDay(y, m, calendar, ref, NewTarget).
  return CreateTemporalMonthDay(isolate, target, new_target, iso_month, iso_day,
                                calendar, ref);
}

namespace {

// #sec-temporal-parsetemporalmonthdaystring
Maybe<DateRecordWithCalendar> ParseTemporalMonthDayString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: Type(isoString) is String.
  // 2. If isoString does not satisfy the syntax of a TemporalMonthDayString
  // (see 13.33), then
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalMonthDayString(isolate, iso_string);
  if (!parsed.has_value()) {
    // a. Throw a *RangeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateRecordWithCalendar>());
  }
  // 3. If isoString contains a UTCDesignator, then
  if (parsed->utc_designator) {
    // a. Throw a *R
```