Response:
The user wants to understand the functionality of the `v8/src/objects/js-temporal-objects.cc` file, specifically part 6 out of 25.

Here's a plan to address the request:

1. **Identify the main functionalities** present in the provided code snippet. These seem to revolve around parsing and manipulating temporal-related strings (dates, times, timezones, durations, calendars) according to ISO 8601 standards.
2. **Check if it's a Torque file**:  The filename ends with `.cc`, so it's C++, not Torque.
3. **Illustrate with JavaScript examples**:  Provide JavaScript examples that correspond to the C++ functions, especially those that parse or format temporal data.
4. **Provide code logic reasoning**:  Select a function (like `ParseISODurationString`) and explain its input, the steps it performs, and the expected output.
5. **Highlight common programming errors**: Based on the functionality, point out common mistakes users might make when working with temporal data in JavaScript.
6. **Summarize the functionality of this part**: Concisely describe the role of this code within the larger context of temporal object handling in V8.
这是一个V8源代码文件，路径为 `v8/src/objects/js-temporal-objects.cc`，属于第6部分，共25部分。根据提供的代码片段，这个文件的主要功能是处理和解析与 JavaScript Temporal API 相关的字符串，包括日期、时间、时区和持续时间。

**功能归纳:**

这个代码片段的主要功能是实现 Temporal API 中用于解析各种 ISO 8601 格式字符串的底层逻辑，包括：

* **解析 ISO 8601 格式的持续时间字符串 (`ParseISODurationString`)**:  将字符串解析为年、月、周、日、小时、分钟、秒、毫秒、微秒和纳秒的 DurationRecord。
* **解析时区字符串 (`ParseTemporalTimeZoneString`)**:  解析时区标识符或带有时区信息的日期时间字符串，返回一个包含时区信息的记录。
* **解析时区偏移字符串 (`ParseTimeZoneOffsetString`)**:  解析形如 "+/-HH:MM" 或 "+/-HH:MM:SS" 的时区偏移字符串，并将其转换为纳秒级的整数偏移量。
* **验证时区偏移字符串的有效性 (`IsValidTimeZoneNumericUTCOffsetString`)**:  检查给定的字符串是否符合时区偏移的语法。
* **解析日历字符串 (`ParseTemporalCalendarString`)**:  从日期时间字符串中提取日历信息，如果不存在则默认为 "iso8601"。
* **比较日历是否相等 (`CalendarEqualsBool`, `CalendarEquals`)**:  比较两个日历对象是否相等。
* **获取日历字段 (`CalendarFields`)**:  获取日历对象支持的字段列表。
* **日历的日期加法 (`CalendarDateAdd`)**:  调用日历对象的 `dateAdd` 方法进行日期加法运算。
* **日历的日期差值计算 (`CalendarDateUntil`)**: 调用日历对象的 `dateUntil` 方法计算两个日期之间的差值。
* **默认合并字段 (`DefaultMergeFields`)**:  将两个包含字段的对象合并，处理 "month" 和 "monthCode" 字段的特殊情况。
* **获取指定时刻的时区偏移量 (`GetOffsetNanosecondsFor`)**:  调用时区对象的 `getOffsetNanosecondsFor` 方法获取指定 Instant 的时区偏移量（纳秒）。
* **转换为正整数 (`ToPositiveInteger`)**:  将参数转换为正整数，如果不是正整数则抛出 RangeError。
* **调用日历方法 (`InvokeCalendarMethod`)**:  封装了调用日历对象特定方法的逻辑。
* **一系列访问日历属性的抽象操作 (`CalendarYear`, `CalendarMonth`, `CalendarDay`, `CalendarMonthCode`, `CalendarEraYear`, `CalendarEra`, `DayOfWeek`, `DayOfYear`, `WeekOfYear`, `DaysInWeek`, `DaysInMonth`, `DaysInYear`, `MonthsInYear`, `InLeapYear`)**:  这些函数用于调用日历对象上对应的方法来获取年份、月份、日期等信息。
* **获取 ISO 8601 日历实例 (`GetISO8601Calendar`)**:  返回一个表示 ISO 8601 日历的 `JSTemporalCalendar` 对象。
* **判断是否为 UTC 时区 (`IsUTC`)**:  检查给定的时区字符串是否表示 UTC。
* **判断是否为内置日历 (`IsBuiltinCalendar`)**:  检查给定的日历标识符是否是 V8 内置支持的日历。
* **获取日历标识符 (`CalendarIdentifier`)**: 根据索引获取日历标识符。
* **获取日历索引 (`CalendarIndex`)**: 根据日历标识符获取其索引。
* **验证时区名称 (`IsValidTimeZoneName`)**: 验证给定的时区名称是否有效 (依赖 Intl 支持)。
* **规范化时区名称 (`CanonicalizeTimeZoneName`)**: 将时区名称规范化 (依赖 Intl 支持)。

**关于文件类型:**

`v8/src/objects/js-temporal-objects.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 Torque 文件。Torque 文件的扩展名是 `.tq`。

**与 Javascript 的关系及举例:**

这些 C++ 代码为 JavaScript 的 Temporal API 提供了底层的实现。Temporal API 允许开发者在 JavaScript 中以更现代的方式处理日期和时间。

例如，`ParseISODurationString` 函数对应于 JavaScript 中 `Temporal.Duration.from()` 方法解析 ISO 8601 持续时间字符串的功能：

```javascript
// JavaScript 示例
const duration = Temporal.Duration.from('P1Y2M3W4DT5H6M7.123S');
console.log(duration.years);   // 输出 1
console.log(duration.months);  // 输出 2
console.log(duration.weeks);   // 输出 3
console.log(duration.days);    // 输出 4
console.log(duration.hours);   // 输出 5
console.log(duration.minutes); // 输出 6
console.log(duration.seconds); // 输出 7
console.log(duration.milliseconds); // 输出 123
```

`ParseTemporalTimeZoneString` 与 `Temporal.TimeZone` 的构造函数或 `Temporal.ZonedDateTime.from()` 方法处理时区字符串有关：

```javascript
// JavaScript 示例
const timeZone = new Temporal.TimeZone('America/New_York');
console.log(timeZone.id); // 输出 "America/New_York"

const zonedDateTime = Temporal.ZonedDateTime.from('2023-10-27T10:00:00-04:00[America/New_York]');
console.log(zonedDateTime.timeZone.id); // 输出 "America/New_York"
```

`ParseTimeZoneOffsetString` 对应于解析时区偏移量的场景，虽然用户可能不会直接调用一个专门解析偏移量的 JavaScript API，但当解析带偏移量的日期时间字符串时，底层会用到类似的功能：

```javascript
// JavaScript 示例
const instant = Temporal.Instant.from('2023-10-27T14:00:00Z');
const zonedDateTime = instant.toZonedDateTimeISO('America/New_York');
console.log(zonedDateTime.offsetNanoseconds); // 输出相对于 UTC 的偏移量（纳秒）
```

`ParseTemporalCalendarString` 与在 Temporal API 中使用日历的场景相关：

```javascript
// JavaScript 示例
const plainDate = Temporal.PlainDate.from('2023-10-27', { calendar: 'iso8601' });
console.log(plainDate.calendar.id); // 输出 "iso8601"

const plainDateWithCustomCalendar = Temporal.PlainDate.from('2023-10-27[islamicc]', { disambiguation: 'compatible' });
console.log(plainDateWithCustomCalendar.calendar.id); // 输出 "islamicc"
```

**代码逻辑推理 (以 `ParseISODurationString` 为例):**

**假设输入:**  `iso_duration_string` 为字符串 `"P1YT2H"`

**执行步骤:**

1. **解析字符串:**  `TemporalParser::ParseDuration` 函数会解析字符串，提取出年 (1) 和小时 (2)。
2. **计算数值:**
   - `years_mv` 将为 1。
   - `hours_mv` 将为 2。
   - 其他时间单位的 `_mv` 变量将为 0。
3. **创建 DurationRecord:** `CreateDurationRecord` 函数会被调用，传入计算出的年、月、周等值。

**预期输出:**  一个 `DurationRecord` 对象，其字段如下：
```
{
  years: 1,
  months: 0,
  weeks: 0,
  days: 0,
  hours: 2,
  minutes: 0,
  seconds: 0,
  milliseconds: 0,
  microseconds: 0,
  nanoseconds: 0
}
```

**用户常见的编程错误:**

* **在 JavaScript 中使用错误的 ISO 8601 格式字符串:** 例如，日期和时间部分没有用 "T" 分隔，或者持续时间字符串的格式不正确（例如，缺少 "P"）。
  ```javascript
  // 错误示例
  // Temporal.PlainDate.from('2023-10-27 10:00:00'); // 错误：缺少 "T" 分隔符
  // Temporal.Duration.from('1Y'); // 错误：缺少 "P" 前缀
  ```
* **时区字符串不符合规范:**  使用了无效的时区名称或格式。
  ```javascript
  // 错误示例
  // new Temporal.TimeZone('InvalidTimeZone'); // 可能会抛出 RangeError
  ```
* **对 Temporal API 的理解不足:**  例如，混淆了 `PlainDate` 和 `ZonedDateTime`，导致在需要时区信息时使用了 `PlainDate`。
* **在需要数字时传递了字符串:**  虽然 Temporal API 内部会进行类型转换，但在某些底层操作中，如果传递了非预期的类型可能会导致错误。

总结来说，`v8/src/objects/js-temporal-objects.cc` 的这个部分是 V8 引擎中实现 JavaScript Temporal API 的关键组成部分，负责解析和处理各种与时间和日期相关的字符串，确保 JavaScript 代码能够正确地理解和操作这些数据。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
nds)
    // from 1.
    //
    // b. Let fSecondsScale be the length of fSecondsDigits.
    //
    // c. Let millisecondsMV be ! ToIntegerOrInfinity(fSecondsDigits) /
    // 10^fSecondsScale × 1000.
    DCHECK_LE(IfEmptyReturnZero(parsed->seconds_fraction), 1e9);
    nanoseconds_mv = std::round(IfEmptyReturnZero(parsed->seconds_fraction));
    // 15. Else,
  } else {
    // a. Let millisecondsMV be remainder(secondsMV, 1) × 1000.
    nanoseconds_mv = std::round((seconds_mv - std::floor(seconds_mv)) * 1e9);
  }
  milliseconds_mv = std::floor(nanoseconds_mv / 1000000);
  // 16. Let microsecondsMV be remainder(millisecondsMV, 1) × 1000.
  microseconds_mv = std::floor(nanoseconds_mv / 1000) -
                    std::floor(nanoseconds_mv / 1000000) * 1000;
  // 17. Let nanosecondsMV be remainder(microsecondsMV, 1) × 1000.
  nanoseconds_mv -= std::floor(nanoseconds_mv / 1000) * 1000;

  // 18. If sign contains the code point 0x002D (HYPHEN-MINUS) or 0x2212 (MINUS
  // SIGN), then a. Let factor be −1.
  // 19. Else,
  // a. Let factor be 1.
  double factor = parsed->sign;

  // 20. Return ? CreateDurationRecord(yearsMV × factor, monthsMV × factor,
  // weeksMV × factor, daysMV × factor, hoursMV × factor, floor(minutesMV) ×
  // factor, floor(secondsMV) × factor, floor(millisecondsMV) × factor,
  // floor(microsecondsMV) × factor, floor(nanosecondsMV) × factor).

  return CreateDurationRecord(
      isolate,
      {years_mv * factor,
       months_mv * factor,
       weeks_mv * factor,
       {days_mv * factor, hours_mv * factor, std::floor(minutes_mv) * factor,
        std::floor(seconds_mv) * factor, milliseconds_mv * factor,
        microseconds_mv * factor, nanoseconds_mv * factor}});
}

// #sec-temporal-parsetemporaltimezonestring
Maybe<TimeZoneRecord> ParseTemporalTimeZoneString(
    Isolate* isolate, Handle<String> time_zone_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Let parseResult be ParseText(StringToCodePoints(timeZoneString),
  // TimeZoneIdentifier).
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTimeZoneIdentifier(isolate, time_zone_string);
  // 2. If parseResult is a Parse Node, then
  if (parsed.has_value()) {
    // a. Return the Record { [[Z]]: false, [[OffsetString]]: undefined,
    // [[Name]]: timeZoneString }.
    return Just(TimeZoneRecord(
        {false, isolate->factory()->undefined_value(), time_zone_string}));
  }

  // 3. Let result be ? ParseISODateTime(timeZoneString).
  DateTimeRecordWithCalendar result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseISODateTime(isolate, time_zone_string),
      Nothing<TimeZoneRecord>());

  // 4. Let timeZoneResult be result.[[TimeZone]].
  // 5. If timeZoneResult.[[Z]] is false, timeZoneResult.[[OffsetString]] is
  // undefined, and timeZoneResult.[[Name]] is undefined, throw a RangeError
  // exception.
  if (!result.time_zone.z && IsUndefined(*result.time_zone.offset_string) &&
      IsUndefined(*result.time_zone.name)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<TimeZoneRecord>());
  }
  // 6. Return timeZoneResult.
  return Just(result.time_zone);
}

Maybe<int64_t> ParseTimeZoneOffsetString(Isolate* isolate,
                                         Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: Type(offsetString) is String.
  // 2. If offsetString does not satisfy the syntax of a
  // TimeZoneNumericUTCOffset (see 13.33), then
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTimeZoneNumericUTCOffset(isolate, iso_string);
  if (!parsed.has_value()) {
    /* a. Throw a RangeError exception. */
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(), Nothing<int64_t>());
  }
  // 3. Let sign, hours, minutes, seconds, and fraction be the parts of
  // offsetString produced respectively by the TimeZoneUTCOffsetSign,
  // TimeZoneUTCOffsetHour, TimeZoneUTCOffsetMinute, TimeZoneUTCOffsetSecond,
  // and TimeZoneUTCOffsetFraction productions, or undefined if not present.
  // 4. If either hours or sign are undefined, throw a RangeError exception.
  if (parsed->tzuo_hour_is_undefined() || parsed->tzuo_sign_is_undefined()) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(), Nothing<int64_t>());
  }
  // 5. If sign is the code unit 0x002D (HYPHEN-MINUS) or 0x2212 (MINUS SIGN),
  // then a. Set sign to −1.
  // 6. Else,
  // a. Set sign to 1.
  int64_t sign = parsed->tzuo_sign;

  // 7. Set hours to ! ToIntegerOrInfinity(hours).
  int64_t hours = parsed->tzuo_hour;
  // 8. Set minutes to ! ToIntegerOrInfinity(minutes).
  int64_t minutes =
      parsed->tzuo_minute_is_undefined() ? 0 : parsed->tzuo_minute;
  // 9. Set seconds to ! ToIntegerOrInfinity(seconds).
  int64_t seconds =
      parsed->tzuo_second_is_undefined() ? 0 : parsed->tzuo_second;
  // 10. If fraction is not undefined, then
  int64_t nanoseconds;
  if (!parsed->tzuo_nanosecond_is_undefined()) {
    // a. Set fraction to the string-concatenation of the previous value of
    // fraction and the string "000000000".
    // b. Let nanoseconds be the String value equal to the substring of fraction
    // consisting of the code units with indices 0 (inclusive) through 9
    // (exclusive). c. Set nanoseconds to ! ToIntegerOrInfinity(nanoseconds).
    nanoseconds = parsed->tzuo_nanosecond;
    // 11. Else,
  } else {
    // a. Let nanoseconds be 0.
    nanoseconds = 0;
  }
  // 12. Return sign × (((hours × 60 + minutes) × 60 + seconds) × 10^9 +
  // nanoseconds).
  return Just(sign * (((hours * 60 + minutes) * 60 + seconds) * 1000000000 +
                      nanoseconds));
}

bool IsValidTimeZoneNumericUTCOffsetString(Isolate* isolate,
                                           Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTimeZoneNumericUTCOffset(isolate, iso_string);
  return parsed.has_value();
}

// #sec-temporal-parsetemporalcalendarstring
MaybeHandle<String> ParseTemporalCalendarString(Isolate* isolate,
                                                Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Let parseResult be Completion(ParseISODateTime(isoString)).
  Maybe<DateTimeRecordWithCalendar> parse_result =
      ParseISODateTime(isolate, iso_string);
  // 2. If parseResult is a normal completion, then
  if (parse_result.IsJust()) {
    // a. Let calendar be parseResult.[[Value]].[[Calendar]].
    Handle<Object> calendar = parse_result.FromJust().calendar;
    // b. If calendar is undefined, return "iso8601".
    if (IsUndefined(*calendar)) {
      return isolate->factory()->iso8601_string();
      // c. Else, return calendar.
    } else {
      CHECK(IsString(*calendar));
      return Cast<String>(calendar);
    }
    // 3. Else,
  } else {
    DCHECK(isolate->has_exception());
    isolate->clear_exception();
    // a. Set parseResult to ParseText(StringToCodePoints(isoString),
    // CalendarName).
    std::optional<ParsedISO8601Result> parsed =
        TemporalParser::ParseCalendarName(isolate, iso_string);
    // b. If parseResult is a List of errors, throw a RangeError exception.
    if (!parsed.has_value()) {
      THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidCalendar,
                                             iso_string));
    }
    // c. Else, return isoString.
    return iso_string;
  }
}

// #sec-temporal-calendarequals
Maybe<bool> CalendarEqualsBool(Isolate* isolate, Handle<JSReceiver> one,
                               Handle<JSReceiver> two) {
  // 1. If one and two are the same Object value, return true.
  if (one.is_identical_to(two)) {
    return Just(true);
  }
  // 2. Let calendarOne be ? ToString(one).
  Handle<String> calendar_one;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar_one, Object::ToString(isolate, one), Nothing<bool>());
  // 3. Let calendarTwo be ? ToString(two).
  Handle<String> calendar_two;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar_two, Object::ToString(isolate, two), Nothing<bool>());
  // 4. If calendarOne is calendarTwo, return true.
  if (String::Equals(isolate, calendar_one, calendar_two)) {
    return Just(true);
  }
  // 5. Return false.
  return Just(false);
}
MaybeHandle<Oddball> CalendarEquals(Isolate* isolate, Handle<JSReceiver> one,
                                    Handle<JSReceiver> two) {
  bool result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, result,
                                         CalendarEqualsBool(isolate, one, two),
                                         Handle<Oddball>());
  return isolate->factory()->ToBoolean(result);
}

// #sec-temporal-calendarfields
MaybeHandle<FixedArray> CalendarFields(Isolate* isolate,
                                       Handle<JSReceiver> calendar,
                                       DirectHandle<FixedArray> field_names) {
  // 1. Let fields be ? GetMethod(calendar, "fields").
  Handle<Object> fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      Object::GetMethod(isolate, calendar,
                        isolate->factory()->fields_string()));
  // 2. Let fieldsArray be ! CreateArrayFromList(fieldNames).
  Handle<Object> fields_array =
      isolate->factory()->NewJSArrayWithElements(field_names);
  // 3. If fields is not undefined, then
  if (!IsUndefined(*fields)) {
    // a. Set fieldsArray to ? Call(fields, calendar, « fieldsArray »).
    Handle<Object> argv[] = {fields_array};
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, fields_array,
        Execution::Call(isolate, fields, calendar, 1, argv));
  }
  // 4. Return ? IterableToListOfType(fieldsArray, « String »).
  Handle<Object> argv[] = {fields_array};
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields_array,
      Execution::CallBuiltin(isolate,
                             isolate->string_fixed_array_from_iterable(),
                             fields_array, 1, argv));
  DCHECK(IsFixedArray(*fields_array));
  return Cast<FixedArray>(fields_array);
}

MaybeHandle<JSTemporalPlainDate> CalendarDateAdd(Isolate* isolate,
                                                 Handle<JSReceiver> calendar,
                                                 Handle<Object> date,
                                                 Handle<Object> duration) {
  // 2. If options is not present, set options to undefined.
  return CalendarDateAdd(isolate, calendar, date, duration,
                         isolate->factory()->undefined_value());
}

MaybeHandle<JSTemporalPlainDate> CalendarDateAdd(Isolate* isolate,
                                                 Handle<JSReceiver> calendar,
                                                 Handle<Object> date,
                                                 Handle<Object> duration,
                                                 Handle<Object> options) {
  Handle<Object> date_add;
  // 4. If dateAdd is not present, set dateAdd to ? GetMethod(calendar,
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_add,
      Object::GetMethod(isolate, calendar,
                        isolate->factory()->dateAdd_string()));
  return CalendarDateAdd(isolate, calendar, date, duration, options, date_add);
}

MaybeHandle<JSTemporalPlainDate> CalendarDateAdd(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<Object> date,
    Handle<Object> duration, Handle<Object> options, Handle<Object> date_add) {
  // 1. Assert: Type(options) is Object or Undefined.
  DCHECK(IsJSReceiver(*options) || IsUndefined(*options));

  // 3. Let addedDate be ? Call(dateAdd, calendar, « date, duration, options »).
  Handle<Object> argv[] = {date, duration, options};
  Handle<Object> added_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, added_date,
      Execution::Call(isolate, date_add, calendar, arraysize(argv), argv));
  // 4. Perform ? RequireInternalSlot(addedDate, [[InitializedTemporalDate]]).
  if (!IsJSTemporalPlainDate(*added_date)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  // 5. Return addedDate.
  return Cast<JSTemporalPlainDate>(added_date);
}

MaybeHandle<JSTemporalDuration> CalendarDateUntil(Isolate* isolate,
                                                  Handle<JSReceiver> calendar,
                                                  Handle<Object> one,
                                                  Handle<Object> two,
                                                  Handle<Object> options) {
  return CalendarDateUntil(isolate, calendar, one, two, options,
                           isolate->factory()->undefined_value());
}

MaybeHandle<JSTemporalDuration> CalendarDateUntil(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<Object> one,
    Handle<Object> two, Handle<Object> options, Handle<Object> date_until) {
  // 1. Assert: Type(calendar) is Object.
  // 2. If dateUntil is not present, set dateUntil to ? GetMethod(calendar,
  // "dateUntil").
  if (IsUndefined(*date_until)) {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, date_until,
        Object::GetMethod(isolate, calendar,
                          isolate->factory()->dateUntil_string()));
  }
  // 3. Let duration be ? Call(dateUntil, calendar, « one, two, options »).
  Handle<Object> argv[] = {one, two, options};
  Handle<Object> duration;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, duration,
      Execution::Call(isolate, date_until, calendar, arraysize(argv), argv));
  // 4. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  if (!IsJSTemporalDuration(*duration)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  // 5. Return duration.
  return Cast<JSTemporalDuration>(duration);
}

// #sec-temporal-defaultmergefields
MaybeHandle<JSReceiver> DefaultMergeFields(
    Isolate* isolate, Handle<JSReceiver> fields,
    Handle<JSReceiver> additional_fields) {
  Factory* factory = isolate->factory();
  // 1. Let merged be ! OrdinaryObjectCreate(%Object.prototype%).
  Handle<JSObject> merged =
      isolate->factory()->NewJSObject(isolate->object_function());

  // 2. Let originalKeys be ? EnumerableOwnPropertyNames(fields, key).
  Handle<FixedArray> original_keys;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, original_keys,
      KeyAccumulator::GetKeys(isolate, fields, KeyCollectionMode::kOwnOnly,
                              ENUMERABLE_STRINGS,
                              GetKeysConversion::kConvertToString));
  // 3. For each element nextKey of originalKeys, do
  for (int i = 0; i < original_keys->length(); i++) {
    // a. If nextKey is not "month" or "monthCode", then
    Handle<Object> next_key(original_keys->get(i), isolate);
    DCHECK(IsString(*next_key));
    Handle<String> next_key_string = Cast<String>(next_key);
    if (!(String::Equals(isolate, factory->month_string(), next_key_string) ||
          String::Equals(isolate, factory->monthCode_string(),
                         next_key_string))) {
      // i. Let propValue be ? Get(fields, nextKey).
      Handle<Object> prop_value;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, prop_value,
          Object::GetPropertyOrElement(isolate, fields, next_key_string));
      // ii. If propValue is not undefined, then
      if (!IsUndefined(*prop_value)) {
        // 1. Perform ! CreateDataPropertyOrThrow(merged, nextKey,
        // propValue).
        CHECK(JSReceiver::CreateDataProperty(isolate, merged, next_key_string,
                                             prop_value, Just(kDontThrow))
                  .FromJust());
      }
    }
  }
  // 4. Let newKeys be ? EnumerableOwnPropertyNames(additionalFields, key).
  Handle<FixedArray> new_keys;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, new_keys,
      KeyAccumulator::GetKeys(isolate, additional_fields,
                              KeyCollectionMode::kOwnOnly, ENUMERABLE_STRINGS,
                              GetKeysConversion::kConvertToString));
  bool new_keys_has_month_or_month_code = false;
  // 5. For each element nextKey of newKeys, do
  for (int i = 0; i < new_keys->length(); i++) {
    Handle<Object> next_key(new_keys->get(i), isolate);
    DCHECK(IsString(*next_key));
    Handle<String> next_key_string = Cast<String>(next_key);
    // a. Let propValue be ? Get(additionalFields, nextKey).
    Handle<Object> prop_value;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, prop_value,
        Object::GetPropertyOrElement(isolate, additional_fields,
                                     next_key_string));
    // b. If propValue is not undefined, then
    if (!IsUndefined(*prop_value)) {
      // 1. Perform ! CreateDataPropertyOrThrow(merged, nextKey, propValue).
      CHECK(JSReceiver::CreateDataProperty(isolate, merged, next_key_string,
                                           prop_value, Just(kDontThrow))
                .FromJust());
    }
    new_keys_has_month_or_month_code |=
        String::Equals(isolate, factory->month_string(), next_key_string) ||
        String::Equals(isolate, factory->monthCode_string(), next_key_string);
  }
  // 6. If newKeys does not contain either "month" or "monthCode", then
  if (!new_keys_has_month_or_month_code) {
    // a. Let month be ? Get(fields, "month").
    Handle<Object> month;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, month,
        JSReceiver::GetProperty(isolate, fields, factory->month_string()));
    // b. If month is not undefined, then
    if (!IsUndefined(*month)) {
      // i. Perform ! CreateDataPropertyOrThrow(merged, "month", month).
      CHECK(JSReceiver::CreateDataProperty(isolate, merged,
                                           factory->month_string(), month,
                                           Just(kDontThrow))
                .FromJust());
    }
    // c. Let monthCode be ? Get(fields, "monthCode").
    Handle<Object> month_code;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, month_code,
        JSReceiver::GetProperty(isolate, fields, factory->monthCode_string()));
    // d. If monthCode is not undefined, then
    if (!IsUndefined(*month_code)) {
      // i. Perform ! CreateDataPropertyOrThrow(merged, "monthCode", monthCode).
      CHECK(JSReceiver::CreateDataProperty(isolate, merged,
                                           factory->monthCode_string(),
                                           month_code, Just(kDontThrow))
                .FromJust());
    }
  }
  // 7. Return merged.
  return merged;
}

// #sec-temporal-getoffsetnanosecondsfor
Maybe<int64_t> GetOffsetNanosecondsFor(Isolate* isolate,
                                       Handle<JSReceiver> time_zone_obj,
                                       Handle<Object> instant,
                                       const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let getOffsetNanosecondsFor be ? GetMethod(timeZone,
  // "getOffsetNanosecondsFor").
  Handle<Object> get_offset_nanoseconds_for;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, get_offset_nanoseconds_for,
      Object::GetMethod(isolate, time_zone_obj,
                        isolate->factory()->getOffsetNanosecondsFor_string()),
      Nothing<int64_t>());
  if (!IsCallable(*get_offset_nanoseconds_for)) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewTypeError(MessageTemplate::kCalledNonCallable,
                     isolate->factory()->getOffsetNanosecondsFor_string()),
        Nothing<int64_t>());
  }
  Handle<Object> offset_nanoseconds_obj;
  // 3. Let offsetNanoseconds be ? Call(getOffsetNanosecondsFor, timeZone, «
  // instant »).
  Handle<Object> argv[] = {instant};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_nanoseconds_obj,
      Execution::Call(isolate, get_offset_nanoseconds_for, time_zone_obj, 1,
                      argv),
      Nothing<int64_t>());

  // 4. If Type(offsetNanoseconds) is not Number, throw a TypeError exception.
  if (!IsNumber(*offset_nanoseconds_obj)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<int64_t>());
  }

  // 5. If ! IsIntegralNumber(offsetNanoseconds) is false, throw a RangeError
  // exception.
  if (!IsIntegralNumber(isolate, offset_nanoseconds_obj)) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(), Nothing<int64_t>());
  }
  double offset_nanoseconds =
      Object::NumberValue(Cast<Number>(*offset_nanoseconds_obj));

  // 6. Set offsetNanoseconds to ℝ(offsetNanoseconds).
  int64_t offset_nanoseconds_int = static_cast<int64_t>(offset_nanoseconds);
  // 7. If abs(offsetNanoseconds) >= 86400 × 10^9, throw a RangeError exception.
  if (std::abs(offset_nanoseconds_int) >= 86400e9) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(), Nothing<int64_t>());
  }
  // 8. Return offsetNanoseconds.
  return Just(offset_nanoseconds_int);
}

// #sec-temporal-topositiveinteger
MaybeHandle<Number> ToPositiveInteger(Isolate* isolate,
                                      Handle<Object> argument) {
  TEMPORAL_ENTER_FUNC();

  // 1. Let integer be ? ToInteger(argument).
  Handle<Number> integer;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, integer,
                             ToIntegerThrowOnInfinity(isolate, argument));
  // 2. If integer ≤ 0, then
  if (NumberToInt32(*integer) <= 0) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  return integer;
}

}  // namespace

namespace temporal {
MaybeHandle<Object> InvokeCalendarMethod(Isolate* isolate,
                                         Handle<JSReceiver> calendar,
                                         Handle<String> name,
                                         Handle<JSReceiver> date_like) {
  Handle<Object> result;
  /* 1. Assert: Type(calendar) is Object. */
  DCHECK(calendar->TaggedImpl::IsObject());
  /* 2. Let result be ? Invoke(calendar, #name, « dateLike »). */
  Handle<Object> function;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, function,
                             Object::GetProperty(isolate, calendar, name));
  if (!IsCallable(*function)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kCalledNonCallable, name));
  }
  Handle<Object> argv[] = {date_like};
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result,
      Execution::Call(isolate, function, calendar, arraysize(argv), argv));
  return result;
}

#define CALENDAR_ABSTRACT_OPERATION_INT_ACTION(Name, name, Action)             \
  MaybeHandle<Smi> Calendar##Name(Isolate* isolate,                            \
                                  Handle<JSReceiver> calendar,                 \
                                  Handle<JSReceiver> date_like) {              \
    /* 1. Assert: Type(calendar) is Object.   */                               \
    /* 2. Let result be ? Invoke(calendar, property, « dateLike »). */       \
    Handle<Object> result;                                                     \
    ASSIGN_RETURN_ON_EXCEPTION(                                                \
        isolate, result,                                                       \
        InvokeCalendarMethod(isolate, calendar,                                \
                             isolate->factory()->name##_string(), date_like)); \
    /* 3. If result is undefined, throw a RangeError exception. */             \
    if (IsUndefined(*result)) {                                                \
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());        \
    }                                                                          \
    /* 4. Return ? Action(result). */                                          \
    ASSIGN_RETURN_ON_EXCEPTION(isolate, result, Action(isolate, result));      \
    return handle(Smi::FromInt(Object::NumberValue(Cast<Number>(*result))),    \
                  isolate);                                                    \
  }

#define CALENDAR_ABSTRACT_OPERATION(Name, property)                      \
  MaybeHandle<Object> Calendar##Name(Isolate* isolate,                   \
                                     Handle<JSReceiver> calendar,        \
                                     Handle<JSReceiver> date_like) {     \
    return InvokeCalendarMethod(isolate, calendar,                       \
                                isolate->factory()->property##_string(), \
                                date_like);                              \
  }

// #sec-temporal-calendaryear
CALENDAR_ABSTRACT_OPERATION_INT_ACTION(Year, year, ToIntegerThrowOnInfinity)
// #sec-temporal-calendarmonth
CALENDAR_ABSTRACT_OPERATION_INT_ACTION(Month, month, ToPositiveInteger)
// #sec-temporal-calendarday
CALENDAR_ABSTRACT_OPERATION_INT_ACTION(Day, day, ToPositiveInteger)
// #sec-temporal-calendarmonthcode
MaybeHandle<Object> CalendarMonthCode(Isolate* isolate,
                                      Handle<JSReceiver> calendar,
                                      Handle<JSReceiver> date_like) {
  // 1. Assert: Type(calendar) is Object.
  // 2. Let result be ? Invoke(calendar, monthCode , « dateLike »).
  Handle<Object> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result,
      InvokeCalendarMethod(isolate, calendar,
                           isolate->factory()->monthCode_string(), date_like));
  /* 3. If result is undefined, throw a RangeError exception. */
  if (IsUndefined(*result)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 4. Return ? ToString(result).
  return Object::ToString(isolate, result);
}

#ifdef V8_INTL_SUPPORT
// #sec-temporal-calendarerayear
MaybeHandle<Object> CalendarEraYear(Isolate* isolate,
                                    Handle<JSReceiver> calendar,
                                    Handle<JSReceiver> date_like) {
  // 1. Assert: Type(calendar) is Object.
  // 2. Let result be ? Invoke(calendar, eraYear , « dateLike »).
  Handle<Object> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result,
      InvokeCalendarMethod(isolate, calendar,
                           isolate->factory()->eraYear_string(), date_like));
  // 3. If result is not undefined, set result to ? ToIntegerOrInfinity(result).
  if (!IsUndefined(*result)) {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, result,
                               ToIntegerThrowOnInfinity(isolate, result));
  }
  // 4. Return result.
  return result;
}

// #sec-temporal-calendarera
MaybeHandle<Object> CalendarEra(Isolate* isolate, Handle<JSReceiver> calendar,
                                Handle<JSReceiver> date_like) {
  // 1. Assert: Type(calendar) is Object.
  // 2. Let result be ? Invoke(calendar, era , « dateLike »).
  Handle<Object> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result,
      InvokeCalendarMethod(isolate, calendar, isolate->factory()->era_string(),
                           date_like));
  // 3. If result is not undefined, set result to ? ToString(result).
  if (!IsUndefined(*result)) {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, result,
                               Object::ToString(isolate, result));
  }
  // 4. Return result.
  return result;
}

#endif  //  V8_INTL_SUPPORT

// #sec-temporal-calendardayofweek
CALENDAR_ABSTRACT_OPERATION(DayOfWeek, dayOfWeek)
// #sec-temporal-calendardayofyear
CALENDAR_ABSTRACT_OPERATION(DayOfYear, dayOfYear)
// #sec-temporal-calendarweekofyear
CALENDAR_ABSTRACT_OPERATION(WeekOfYear, weekOfYear)
// #sec-temporal-calendardaysinweek
CALENDAR_ABSTRACT_OPERATION(DaysInWeek, daysInWeek)
// #sec-temporal-calendardaysinmonth
CALENDAR_ABSTRACT_OPERATION(DaysInMonth, daysInMonth)
// #sec-temporal-calendardaysinyear
CALENDAR_ABSTRACT_OPERATION(DaysInYear, daysInYear)
// #sec-temporal-calendarmonthsinyear
CALENDAR_ABSTRACT_OPERATION(MonthsInYear, monthsInYear)
// #sec-temporal-calendarinleapyear
CALENDAR_ABSTRACT_OPERATION(InLeapYear, inLeapYear)

// #sec-temporal-getiso8601calendar
Handle<JSTemporalCalendar> GetISO8601Calendar(Isolate* isolate) {
  return CreateTemporalCalendar(isolate, isolate->factory()->iso8601_string())
      .ToHandleChecked();
}

}  // namespace temporal

namespace {

bool IsUTC(Isolate* isolate, Handle<String> time_zone) {
  // 1. Assert: Type(timeZone) is String.
  // 2. Let tzText be ! StringToCodePoints(timeZone).
  // 3. Let tzUpperText be the result of toUppercase(tzText), according to the
  // Unicode Default Case Conversion algorithm.
  // 4. Let tzUpper be ! CodePointsToString(tzUpperText).
  // 5. If tzUpper and "UTC" are the same sequence of code points, return true.
  // 6. Return false.
  if (time_zone->length() != 3) return false;
  time_zone = String::Flatten(isolate, time_zone);
  DisallowGarbageCollection no_gc;
  const String::FlatContent& flat = time_zone->GetFlatContent(no_gc);
  return (flat.Get(0) == u'U' || flat.Get(0) == u'u') &&
         (flat.Get(1) == u'T' || flat.Get(1) == u't') &&
         (flat.Get(2) == u'C' || flat.Get(2) == u'c');
}

#ifdef V8_INTL_SUPPORT
class CalendarMap final {
 public:
  CalendarMap() {
    icu::Locale locale("und");
    UErrorCode status = U_ZERO_ERROR;
    std::unique_ptr<icu::StringEnumeration> enumeration(
        icu::Calendar::getKeywordValuesForLocale("ca", locale, false, status));
    calendar_ids.push_back("iso8601");
    calendar_id_indices.insert({"iso8601", 0});
    int32_t i = 1;
    for (const char* item = enumeration->next(nullptr, status);
         U_SUCCESS(status) && item != nullptr;
         item = enumeration->next(nullptr, status)) {
      if (strcmp(item, "iso8601") != 0) {
        const char* type = uloc_toUnicodeLocaleType("ca", item);
        calendar_ids.push_back(type);
        calendar_id_indices.insert({type, i++});
      }
    }
  }
  bool Contains(const std::string& id) const {
    return calendar_id_indices.find(id) != calendar_id_indices.end();
  }

  std::string Id(int32_t index) const {
    DCHECK_LT(index, calendar_ids.size());
    return calendar_ids[index];
  }

  int32_t Index(const char* id) const {
    return calendar_id_indices.find(id)->second;
  }

 private:
  std::map<std::string, int32_t> calendar_id_indices;
  std::vector<std::string> calendar_ids;
};

DEFINE_LAZY_LEAKY_OBJECT_GETTER(CalendarMap, GetCalendarMap)

bool IsBuiltinCalendar(Isolate* isolate, Handle<String> id) {
  // 1. Let calendars be AvailableCalendars().
  // 2. If calendars contains the ASCII-lowercase of id, return true.
  // 3. Return false.
  id = Intl::ConvertToLower(isolate, String::Flatten(isolate, id))
           .ToHandleChecked();
  return GetCalendarMap()->Contains(id->ToCString().get());
}

Handle<String> CalendarIdentifier(Isolate* isolate, int32_t index) {
  return isolate->factory()->NewStringFromAsciiChecked(
      GetCalendarMap()->Id(index).c_str());
}

int32_t CalendarIndex(Isolate* isolate, Handle<String> id) {
  id = Intl::ConvertToLower(isolate, String::Flatten(isolate, id))
           .ToHandleChecked();
  return GetCalendarMap()->Index(id->ToCString().get());
}

bool IsValidTimeZoneName(Isolate* isolate, DirectHandle<String> time_zone) {
  return Intl::IsValidTimeZoneName(isolate, time_zone);
}

Handle<String> CanonicalizeTimeZoneName(Isolate* isolate,
                                        DirectHandle<String> identifier) {
  return Intl::CanonicalizeTimeZoneName(isolate, identifier).ToHandleChecked();
}

#else   // V8_INTL_SUPPORT
Handle<String> CalendarIdentifier(Isolate* isolate, int32_t index) {
  DCHECK_EQ(index, 0);
  return isolate->factory()->iso8601_string();
}

// #sec-temporal-isbuiltincalendar
bool IsBuiltinCalendar(Isolate* isolate, Handle<String> id) {
  // Note: For build without intl support, the only item in AvailableCalendars()
  // is "iso8601".
  // 1. Let calendars be AvailableCalendars().
  // 2. If calendars contains the ASCII-lowercase of id, return true.
  // 3. Return false.

  // Fast path
  if (isolate->factory()->iso8601_string()->Equals(*id)) return true;
  if (id->length() != 7) return false;
  id = String::Flatten(isolate, id);

  DisallowGarbageCollection no_gc;
  const String::FlatContent& flat = id->GetFlatContent(no_gc);
  // Return true if id is case insensitive equals to "iso8601".
  return AsciiAlphaToLower(flat.Get(0)) == 'i' &&
         AsciiAlphaToLower(flat.Get(1)) == 's' &&
         AsciiAlphaToLower(flat.Get(2)) == 'o' && flat.Get(3) == '8' &&
         flat.Get(4) == '6' && flat.Get(5) == '0' && flat.Get(6) == '1';
}

int32_t CalendarIndex(Isolate* isolate, Handle<String> id) { return 0; }
// #sec-isvalidtimezonename
bool IsValidTimeZoneName(Isolate* isolate, DirectHandle<String> time_zone) {
  return IsUTC(isolate, indirect_handle(time
```