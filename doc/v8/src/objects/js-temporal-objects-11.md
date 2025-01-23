Response: My goal is to analyze the provided C++ code snippet and summarize its functionality, relating it to JavaScript concepts if applicable. Here's my thinking process:

1. **Identify the Core Object:** The code heavily features `JSTemporalZonedDateTime`. This immediately tells me the file is about the `Temporal.ZonedDateTime` object in JavaScript's Temporal API.

2. **Scan for Key Methods:** I'll look for function names that correspond to known `Temporal.ZonedDateTime` methods in JavaScript. This includes:
    * `From`: Static methods like `from` for parsing.
    * `With`: Methods for creating new `ZonedDateTime` instances with modified properties (e.g., `withCalendar`, `withPlainDate`, `withPlainTime`, `withTimeZone`).
    * `To`: Methods for converting `ZonedDateTime` to other Temporal types (e.g., `toPlainYearMonth`, `toPlainMonthDay`, `toJSON`, `toLocaleString`, `toString`, `toPlainDate`, `toPlainTime`, `toPlainDateTime`, `toInstant`).
    * `Now`: Static methods like `now` and `nowISO`.
    * `Round`: The `round` method for rounding.
    * `Add`/`Subtract`: Methods for adding and subtracting durations.
    * `Until`/`Since`: Methods for calculating the duration between two `ZonedDateTime` instances.
    * `GetOffsetNanoseconds`: Getting the offset.
    * `StartOfDay`: Getting the start of the day.

3. **Analyze Individual Methods (Mental Walkthrough):** For each identified method, I'll briefly read through the code, paying attention to:
    * **Input Parameters:** What kind of data does the method take?  This helps understand its purpose.
    * **Core Logic:** What are the main operations performed?  Look for calls to other functions within the same file or external functions related to Temporal.
    * **Output:** What does the method return? This will usually be a new `JSTemporalZonedDateTime` or another Temporal object.
    * **Error Handling:**  Are there checks for invalid input or potential errors?  `MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE` and `ASSIGN_RETURN_ON_EXCEPTION` are key here.

4. **Relate to JavaScript (Examples):**  For the more prominent methods, I'll try to create simple JavaScript examples to illustrate how the C++ code corresponds to user-facing functionality. This reinforces the connection between the V8 implementation and the JavaScript API.

5. **Identify Common Patterns and Helper Functions:** Notice recurring patterns, like getting the `TimeZone` and `Calendar`, creating `TemporalInstant` objects, and calling functions like `InterpretTemporalDateTimeFields`, `ParseTimeZoneOffsetString`, `CreateTemporalZonedDateTime`, etc. These are likely helper functions that encapsulate common logic.

6. **Consider the "Part X of Y" Context:** The prompt states this is part 12 of 13. This suggests this file likely deals with the core functionality of `Temporal.ZonedDateTime`, with other parts potentially handling related objects or edge cases.

7. **Synthesize the Summary:**  Based on the above analysis, I'll formulate a concise summary that covers the following:
    * **Overall Purpose:**  Clearly state that the file implements the `Temporal.ZonedDateTime` object in V8.
    * **Key Functionality Areas:** Group related methods and describe the main operations supported (creation, manipulation, conversion, comparison, etc.).
    * **Relationship to JavaScript:**  Highlight how the C++ code enables the JavaScript `Temporal.ZonedDateTime` API.
    * **Mention of Helper Functions:** Briefly note the presence of internal helper functions.
    * **Acknowledge the "Part X of Y" context:**  Reinforce that this is a key part of the `Temporal` implementation.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the `ZonedDateTime` methods.
* **Correction:** Realize that `JSTemporalInstant` methods (like the static `Now` and `Compare`) are also present, indicating some related functionality. Include these in the summary.
* **Initial thought:**  List every single method individually in the summary.
* **Refinement:** Group methods by their purpose (e.g., "creation and parsing," "modification," "conversion") for better readability and conciseness.
* **Initial thought:**  Provide very technical C++ details in the explanation.
* **Refinement:** Focus on the *functional* aspects and how they relate to JavaScript, avoiding overly specific C++ implementation details unless they are crucial for understanding the functionality. Use the JavaScript examples to bridge the gap.

By following this structured process, I can effectively analyze the C++ code and generate a comprehensive and informative summary that addresses the prompt's requirements.
这个C++源代码文件 `v8/src/objects/js-temporal-objects.cc` 的第 12 部分，主要负责实现 **ECMAScript Temporal API** 中的 `Temporal.ZonedDateTime` 对象的各种方法。

**功能归纳：**

该部分代码实现了 `Temporal.ZonedDateTime` 对象的以下核心功能：

* **创建和解析 `Temporal.ZonedDateTime` 对象:**
    * `From`:  允许从各种输入（包括带有偏移量的字符串）创建 `Temporal.ZonedDateTime` 对象。这包括解析日期、时间、时区偏移量等信息。
* **修改 `Temporal.ZonedDateTime` 对象的属性:**
    * `WithCalendar`: 创建一个新的 `Temporal.ZonedDateTime` 对象，只修改日历。
    * `WithPlainDate`: 创建一个新的 `Temporal.ZonedDateTime` 对象，用一个 `Temporal.PlainDate` 对象替换日期部分。
    * `WithPlainTime`: 创建一个新的 `Temporal.ZonedDateTime` 对象，用一个 `Temporal.PlainTime` 对象替换时间部分。
    * `WithTimeZone`: 创建一个新的 `Temporal.ZonedDateTime` 对象，只修改时区。
* **将 `Temporal.ZonedDateTime` 对象转换为其他 Temporal 类型:**
    * `ToPlainYearMonth`:  转换为 `Temporal.PlainYearMonth` 对象。
    * `ToPlainMonthDay`: 转换为 `Temporal.PlainMonthDay` 对象。
    * `ToJSON`: 转换为 ISO 格式的 JSON 字符串。
    * `ToLocaleString`:  根据本地化设置格式化日期和时间。
    * `ToString`:  转换为字符串表示形式，允许自定义精度、日历显示、时区显示和偏移量显示。
    * `ToPlainDate`: 转换为 `Temporal.PlainDate` 对象。
    * `ToPlainTime`: 转换为 `Temporal.PlainTime` 对象。
    * `ToPlainDateTime`: 转换为 `Temporal.PlainDateTime` 对象。
    * `ToInstant`: 转换为 `Temporal.Instant` 对象。
* **获取 `Temporal.ZonedDateTime` 对象的属性:**
    * `OffsetNanoseconds`: 获取时区偏移量的纳秒表示。
    * `Offset`: 获取时区偏移量的字符串表示。
    * `GetISOFields`: 获取对象的 ISO 字段（年、月、日、时、分、秒、毫秒、微秒、纳秒、偏移量、时区和日历）。
* **执行与 `Temporal.ZonedDateTime` 相关的操作:**
    * `Now`: 获取当前时区的当前 `Temporal.ZonedDateTime` 对象。
    * `NowISO`: 获取 UTC 时区的当前 `Temporal.ZonedDateTime` 对象。
    * `Round`:  将 `Temporal.ZonedDateTime` 对象四舍五入到指定的精度。
    * `Add`:  向 `Temporal.ZonedDateTime` 对象添加一个 `Temporal.Duration`。
    * `Subtract`: 从 `Temporal.ZonedDateTime` 对象减去一个 `Temporal.Duration`。
    * `Until`: 计算两个 `Temporal.ZonedDateTime` 对象之间的时间差，返回一个 `Temporal.Duration` 对象（从第一个时间到第二个时间）。
    * `Since`: 计算两个 `Temporal.ZonedDateTime` 对象之间的时间差，返回一个 `Temporal.Duration` 对象（从第二个时间到第一个时间）。
    * `StartOfDay`: 获取 `Temporal.ZonedDateTime` 对象所在日期的开始时间。

**与 JavaScript 的关系及示例：**

该 C++ 文件是 V8 引擎的一部分，负责在底层实现 JavaScript 的 `Temporal.ZonedDateTime` 对象的功能。  JavaScript 代码通过 V8 引擎调用这些 C++ 函数来实现其 Temporal API 的行为。

以下是一些 JavaScript 示例，展示了该文件中实现的 C++ 功能：

```javascript
// 创建 Temporal.ZonedDateTime 对象
const zonedDateTime1 = Temporal.ZonedDateTime.from('2023-10-27T10:30:00+08:00[Asia/Shanghai]');
const zonedDateTime2 = Temporal.ZonedDateTime.from({
  year: 2023,
  month: 10,
  day: 27,
  hour: 10,
  minute: 30,
  timeZone: 'Asia/Shanghai'
});

// 修改属性
const sameTimeUTC = zonedDateTime1.withTimeZone('UTC');
const nextDaySameTime = zonedDateTime1.withPlainDate(zonedDateTime1.toPlainDate().add({ days: 1 }));

// 转换为其他 Temporal 类型
const plainDate = zonedDateTime1.toPlainDate();
const plainTime = zonedDateTime1.toPlainTime();
const isoString = zonedDateTime1.toString();

// 获取属性
const offsetNanoseconds = zonedDateTime1.offsetNanoseconds;
const offsetString = zonedDateTime1.offset;

// 执行操作
const nowShanghai = Temporal.Now.zonedDateTime('Asia/Shanghai');
const roundedTime = zonedDateTime1.round({ minutes: 15 });
const futureTime = zonedDateTime1.add({ hours: 2 });
const durationUntilFuture = zonedDateTime1.until(futureTime);
const startOfToday = zonedDateTime1.startOfDay();
```

**第 12 部分的意义：**

作为 13 个部分中的第 12 部分，这表明该文件几乎涵盖了 `Temporal.ZonedDateTime` 的所有核心功能。剩下的第 13 部分可能处理一些更边缘的情况、测试或与其他 Temporal 类型的交互。

总而言之，`js-temporal-objects.cc` 的第 12 部分是 V8 引擎中实现 `Temporal.ZonedDateTime` 核心逻辑的关键组成部分，它通过 C++ 代码赋予了 JavaScript 中 `Temporal.ZonedDateTime` 对象各种强大的日期和时间操作能力。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第12部分，共13部分，请归纳一下它的功能
```

### 源代码
```
eTimeResult be ? InterpretTemporalDateTimeFields(calendar,
  // fields, options).
  temporal::DateTimeRecord date_time_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, date_time_result,
      InterpretTemporalDateTimeFields(isolate, calendar, fields, options,
                                      method_name),
      Handle<JSTemporalZonedDateTime>());

  // 20. Let offsetNanoseconds be ? ParseTimeZoneOffsetString(offsetString).
  int64_t offset_nanoseconds;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_nanoseconds,
      ParseTimeZoneOffsetString(isolate, Cast<String>(offset_string)),
      Handle<JSTemporalZonedDateTime>());

  // 21. Let epochNanoseconds be ?
  // InterpretISODateTimeOffset(dateTimeResult.[[Year]],
  // dateTimeResult.[[Month]], dateTimeResult.[[Day]], dateTimeResult.[[Hour]],
  // dateTimeResult.[[Minute]], dateTimeResult.[[Second]],
  // dateTimeResult.[[Millisecond]], dateTimeResult.[[Microsecond]],
  // dateTimeResult.[[Nanosecond]], option, offsetNanoseconds, timeZone,
  // disambiguation, offset, match exactly).
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      InterpretISODateTimeOffset(
          isolate, {date_time_result.date, date_time_result.time},
          OffsetBehaviour::kOption, offset_nanoseconds, time_zone,
          disambiguation, offset, MatchBehaviour::kMatchExactly, method_name));

  // 27. Return ? CreateTemporalZonedDateTime(epochNanoseconds, timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(isolate, epoch_nanoseconds, time_zone,
                                     calendar);
}

// #sec-temporal.zoneddatetime.prototype.withcalendar
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::WithCalendar(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> calendar_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.withCalendar";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let calendar be ? ToTemporalCalendar(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      temporal::ToTemporalCalendar(isolate, calendar_like, method_name));

  // 4. Return ? CreateTemporalZonedDateTime(zonedDateTime.[[Nanoseconds]],
  // zonedDateTime.[[TimeZone]], calendar).
  DirectHandle<BigInt> nanoseconds(zoned_date_time->nanoseconds(), isolate);
  DirectHandle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  return CreateTemporalZonedDateTime(isolate, nanoseconds, time_zone, calendar);
}

// #sec-temporal.zoneddatetime.prototype.withplaindate
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::WithPlainDate(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> plain_date_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.withPlainDate";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let plainDate be ? ToTemporalDate(plainDateLike).
  Handle<JSTemporalPlainDate> plain_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, plain_date,
      ToTemporalDate(isolate, plain_date_like, method_name));

  // 4. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 5. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();

  // 6. Let plainDateTime be ?
  // temporal::BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant,
  // zonedDateTime.[[Calendar]]).
  Handle<JSTemporalPlainDateTime> plain_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, plain_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(
          isolate, time_zone, instant,
          handle(zoned_date_time->calendar(), isolate), method_name));
  // 7. Let calendar be ? ConsolidateCalendars(zonedDateTime.[[Calendar]],
  // plainDate.[[Calendar]]).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ConsolidateCalendars(isolate,
                           handle(zoned_date_time->calendar(), isolate),
                           handle(plain_date->calendar(), isolate)));

  // 8. Let resultPlainDateTime be ?
  // CreateTemporalDateTime(plainDate.[[ISOYear]], plainDate.[[ISOMonth]],
  // plainDate.[[ISODay]], plainDateTime.[[ISOHour]],
  // plainDateTime.[[ISOMinute]], plainDateTime.[[ISOSecond]],
  // plainDateTime.[[ISOMillisecond]], plainDateTime.[[ISOMicrosecond]],
  // plainDateTime.[[ISONanosecond]], calendar).
  Handle<JSTemporalPlainDateTime> result_plain_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result_plain_date_time,
      temporal::CreateTemporalDateTime(
          isolate,
          {{plain_date->iso_year(), plain_date->iso_month(),
            plain_date->iso_day()},
           {plain_date_time->iso_hour(), plain_date_time->iso_minute(),
            plain_date_time->iso_second(), plain_date_time->iso_millisecond(),
            plain_date_time->iso_microsecond(),
            plain_date_time->iso_nanosecond()}},
          calendar));
  // 9. Set instant to ? BuiltinTimeZoneGetInstantFor(timeZone,
  // resultPlainDateTime, "compatible").
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, result_plain_date_time,
                                   Disambiguation::kCompatible, method_name));
  // 10. Return ? CreateTemporalZonedDateTime(instant.[[Nanoseconds]], timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(
      isolate, handle(instant->nanoseconds(), isolate), time_zone, calendar);
}

// #sec-temporal.zoneddatetime.prototype.withplaintime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::WithPlainTime(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> plain_time_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.withPlainTime";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. If plainTimeLike is undefined, then
  Handle<JSTemporalPlainTime> plain_time;
  if (IsUndefined(*plain_time_like)) {
    // a. Let plainTime be ? CreateTemporalTime(0, 0, 0, 0, 0, 0).
    ASSIGN_RETURN_ON_EXCEPTION(isolate, plain_time,
                               CreateTemporalTime(isolate, {0, 0, 0, 0, 0, 0}));
    // 4. Else,
  } else {
    // a. Let plainTime be ? ToTemporalTime(plainTimeLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, plain_time,
        temporal::ToTemporalTime(isolate, plain_time_like, method_name));
  }
  // 5. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 6. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();
  // 7. Let calendar be zonedDateTime.[[Calendar]].
  DirectHandle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);
  // 8. Let plainDateTime be ?
  // temporal::BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant, calendar).
  Handle<JSTemporalPlainDateTime> plain_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, plain_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   calendar, method_name));
  // 9. Let resultPlainDateTime be ?
  // CreateTemporalDateTime(plainDateTime.[[ISOYear]],
  // plainDateTime.[[ISOMonth]], plainDateTime.[[ISODay]],
  // plainTime.[[ISOHour]], plainTime.[[ISOMinute]], plainTime.[[ISOSecond]],
  // plainTime.[[ISOMillisecond]], plainTime.[[ISOMicrosecond]],
  // plainTime.[[ISONanosecond]], calendar).
  Handle<JSTemporalPlainDateTime> result_plain_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result_plain_date_time,
      temporal::CreateTemporalDateTime(
          isolate,
          {{plain_date_time->iso_year(), plain_date_time->iso_month(),
            plain_date_time->iso_day()},
           {plain_time->iso_hour(), plain_time->iso_minute(),
            plain_time->iso_second(), plain_time->iso_millisecond(),
            plain_time->iso_microsecond(), plain_time->iso_nanosecond()}},
          calendar));
  // 10. Let instant be ? BuiltinTimeZoneGetInstantFor(timeZone,
  // resultPlainDateTime, "compatible").
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, result_plain_date_time,
                                   Disambiguation::kCompatible, method_name));
  // 11. Return ? CreateTemporalZonedDateTime(instant.[[Nanoseconds]], timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(
      isolate, handle(instant->nanoseconds(), isolate), time_zone, calendar);
}

// #sec-temporal.zoneddatetime.prototype.withtimezone
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::WithTimeZone(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> time_zone_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.withTimeZone";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let timeZone be ? ToTemporalTimeZone(timeZoneLike).
  Handle<JSReceiver> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      temporal::ToTemporalTimeZone(isolate, time_zone_like, method_name));

  // 4. Return ? CreateTemporalZonedDateTime(zonedDateTime.[[Nanoseconds]],
  // timeZone, zonedDateTime.[[Calendar]]).
  DirectHandle<BigInt> nanoseconds(zoned_date_time->nanoseconds(), isolate);
  DirectHandle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);
  return CreateTemporalZonedDateTime(isolate, nanoseconds, time_zone, calendar);
}

// Common code shared by ZonedDateTime.prototype.toPlainYearMonth and
// toPlainMonthDay
template <typename T,
          MaybeHandle<T> (*from_fields_func)(
              Isolate*, Handle<JSReceiver>, Handle<JSReceiver>, Handle<Object>)>
MaybeHandle<T> ZonedDateTimeToPlainYearMonthOrMonthDay(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    DirectHandle<String> field_name_1, DirectHandle<String> field_name_2,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  Factory* factory = isolate->factory();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 4. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();
  // 5. Let calendar be zonedDateTime.[[Calendar]].
  Handle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);
  // 6. Let temporalDateTime be ?
  // temporal::BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant, calendar).
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   calendar, method_name));
  // 7. Let fieldNames be ? CalendarFields(calendar, « field_name_1,
  // field_name_2 »).
  Handle<FixedArray> field_names = factory->NewFixedArray(2);
  field_names->set(0, *field_name_1);
  field_names->set(1, *field_name_2);
  ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                             CalendarFields(isolate, calendar, field_names));
  // 8. Let fields be ? PrepareTemporalFields(temporalDateTime, fieldNames, «»).
  Handle<JSReceiver> fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      PrepareTemporalFields(isolate, temporal_date_time, field_names,
                            RequiredFields::kNone));
  // 9. Return ? XxxFromFields(calendar, fields).
  return from_fields_func(isolate, calendar, fields,
                          factory->undefined_value());
}

// #sec-temporal.zoneddatetime.prototype.toplainyearmonth
MaybeHandle<JSTemporalPlainYearMonth> JSTemporalZonedDateTime::ToPlainYearMonth(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  return ZonedDateTimeToPlainYearMonthOrMonthDay<JSTemporalPlainYearMonth,
                                                 YearMonthFromFields>(
      isolate, zoned_date_time, isolate->factory()->monthCode_string(),
      isolate->factory()->year_string(),
      "Temporal.ZonedDateTime.prototype.toPlainYearMonth");
}

// #sec-temporal.zoneddatetime.prototype.toplainmonthday
MaybeHandle<JSTemporalPlainMonthDay> JSTemporalZonedDateTime::ToPlainMonthDay(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  return ZonedDateTimeToPlainYearMonthOrMonthDay<JSTemporalPlainMonthDay,
                                                 MonthDayFromFields>(
      isolate, zoned_date_time, isolate->factory()->day_string(),
      isolate->factory()->monthCode_string(),
      "Temporal.ZonedDateTime.prototype.toPlainMonthDay");
}

namespace {

// #sec-temporal-temporalzoneddatetimetostring
MaybeHandle<String> TemporalZonedDateTimeToString(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Precision precision, ShowCalendar show_calendar,
    ShowTimeZone show_time_zone, ShowOffset show_offset, double increment,
    Unit unit, RoundingMode rounding_mode, const char* method_name) {
  // 4. Let ns be ! RoundTemporalInstant(zonedDateTime.[[Nanoseconds]],
  // increment, unit, roundingMode).
  DirectHandle<BigInt> ns = RoundTemporalInstant(
      isolate, handle(zoned_date_time->nanoseconds(), isolate), increment, unit,
      rounding_mode);

  // 5. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 6. Let instant be ! CreateTemporalInstant(ns).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(isolate, ns).ToHandleChecked();

  // 7. Let isoCalendar be ! GetISO8601Calendar().
  Handle<JSTemporalCalendar> iso_calendar =
      temporal::GetISO8601Calendar(isolate);

  // 8. Let temporalDateTime be ?
  // BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant,
  // isoCalendar).
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   iso_calendar, method_name));
  // 9. Let dateTimeString be ?
  // TemporalDateTimeToString(temporalDateTime.[[ISOYear]],
  // temporalDateTime.[[ISOMonth]], temporalDateTime.[[ISODay]],
  // temporalDateTime.[[ISOHour]], temporalDateTime.[[ISOMinute]],
  // temporalDateTime.[[ISOSecond]], temporalDateTime.[[ISOMillisecond]],
  // temporalDateTime.[[ISOMicrosecond]], temporalDateTime.[[ISONanosecond]],
  // isoCalendar, precision, "never").
  Handle<String> date_time_string;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time_string,
      TemporalDateTimeToString(
          isolate,
          {{temporal_date_time->iso_year(), temporal_date_time->iso_month(),
            temporal_date_time->iso_day()},
           {temporal_date_time->iso_hour(), temporal_date_time->iso_minute(),
            temporal_date_time->iso_second(),
            temporal_date_time->iso_millisecond(),
            temporal_date_time->iso_microsecond(),
            temporal_date_time->iso_nanosecond()}},
          iso_calendar, precision, ShowCalendar::kNever));

  IncrementalStringBuilder builder(isolate);
  builder.AppendString(date_time_string);

  // 10. If showOffset is "never", then
  if (show_offset == ShowOffset::kNever) {
    // a. Let offsetString be the empty String.
    // 11. Else,
  } else {
    // a. Let offsetNs be ? GetOffsetNanosecondsFor(timeZone, instant).
    int64_t offset_ns;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, offset_ns,
        GetOffsetNanosecondsFor(isolate, time_zone, instant, method_name),
        Handle<String>());
    // b. Let offsetString be ! FormatISOTimeZoneOffsetString(offsetNs).
    builder.AppendString(FormatISOTimeZoneOffsetString(isolate, offset_ns));
  }

  // 12. If showTimeZone is "never", then
  if (show_time_zone == ShowTimeZone::kNever) {
    // a. Let timeZoneString be the empty String.
    // 13. Else,
  } else {
    // a. Let timeZoneID be ? ToString(timeZone).
    Handle<String> time_zone_id;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, time_zone_id,
                               Object::ToString(isolate, time_zone));
    // b. Let timeZoneString be the string-concatenation of the code unit 0x005B
    // (LEFT SQUARE BRACKET), timeZoneID, and the code unit 0x005D (RIGHT SQUARE
    // BRACKET).
    builder.AppendCStringLiteral("[");
    builder.AppendString(time_zone_id);
    builder.AppendCStringLiteral("]");
  }
  // 14. Let calendarString be ?
  // MaybeFormatCalendarAnnotation(zonedDateTime.[[Calendar]], showCalendar).
  Handle<String> calendar_string;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar_string,
      MaybeFormatCalendarAnnotation(
          isolate, handle(zoned_date_time->calendar(), isolate),
          show_calendar));

  // 15. Return the string-concatenation of dateTimeString, offsetString,
  // timeZoneString, and calendarString.
  builder.AppendString(calendar_string);
  return indirect_handle(builder.Finish(), isolate);
}

// #sec-temporal-temporalzoneddatetimetostring
MaybeHandle<String> TemporalZonedDateTimeToString(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Precision precision, ShowCalendar show_calendar,
    ShowTimeZone show_time_zone, ShowOffset show_offset,
    const char* method_name) {
  // 1. Assert: Type(zonedDateTime) is Object and zonedDateTime has an
  // [[InitializedTemporalZonedDateTime]] internal slot.
  // 2. If increment is not present, set it to 1.
  // 3. If unit is not present, set it to "nanosecond".
  // 4. If roundingMode is not present, set it to "trunc".
  return TemporalZonedDateTimeToString(
      isolate, zoned_date_time, precision, show_calendar, show_time_zone,
      show_offset, 1, Unit::kNanosecond, RoundingMode::kTrunc, method_name);
}

}  // namespace
// #sec-temporal.zoneddatetime.prototype.tojson
MaybeHandle<String> JSTemporalZonedDateTime::ToJSON(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Return ? TemporalZonedDateTimeToString(zonedDateTime, "auto", "auto",
  // "auto", "auto").
  return TemporalZonedDateTimeToString(
      isolate, zoned_date_time, Precision::kAuto, ShowCalendar::kAuto,
      ShowTimeZone::kAuto, ShowOffset::kAuto,
      "Temporal.ZonedDateTime.prototype.toJSON");
}

// #sec-temporal.zoneddatetime.prototype.tolocalestring
MaybeHandle<String> JSTemporalZonedDateTime::ToLocaleString(
    Isolate* isolate, Handle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> locales, Handle<Object> options) {
  const char* method_name = "Temporal.ZonedDateTime.prototype.toLocaleString";
#ifdef V8_INTL_SUPPORT
  return JSDateTimeFormat::TemporalToLocaleString(
      isolate, zoned_date_time, locales, options, method_name);
#else   //  V8_INTL_SUPPORT
  return TemporalZonedDateTimeToString(
      isolate, zoned_date_time, Precision::kAuto, ShowCalendar::kAuto,
      ShowTimeZone::kAuto, ShowOffset::kAuto, method_name);
#endif  //  V8_INTL_SUPPORT
}

// #sec-temporal.zoneddatetime.prototype.tostring
MaybeHandle<String> JSTemporalZonedDateTime::ToString(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> options_obj) {
  const char* method_name = "Temporal.ZonedDateTime.prototype.toString";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
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

  // 7. Let showTimeZone be ? ToShowTimeZoneNameOption(options).
  ShowTimeZone show_time_zone;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, show_time_zone,
      ToShowTimeZoneNameOption(isolate, options, method_name),
      Handle<String>());

  // 8. Let showOffset be ? ToShowOffsetOption(options).
  ShowOffset show_offset;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, show_offset, ToShowOffsetOption(isolate, options, method_name),
      Handle<String>());

  // 9. Return ? TemporalZonedDateTimeToString(zonedDateTime,
  // precision.[[Precision]], showCalendar, showTimeZone, showOffset,
  // precision.[[Increment]], precision.[[Unit]], roundingMode).
  return TemporalZonedDateTimeToString(
      isolate, zoned_date_time, precision.precision, show_calendar,
      show_time_zone, show_offset, precision.increment, precision.unit,
      rounding_mode, method_name);
}

// #sec-temporal.now.zoneddatetime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::Now(
    Isolate* isolate, Handle<Object> calendar_like,
    Handle<Object> temporal_time_zone_like) {
  const char* method_name = "Temporal.Now.zonedDateTime";
  // 1. Return ? SystemZonedDateTime(temporalTimeZoneLike, calendarLike).
  return SystemZonedDateTime(isolate, temporal_time_zone_like, calendar_like,
                             method_name);
}

// #sec-temporal.now.zoneddatetimeiso
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::NowISO(
    Isolate* isolate, Handle<Object> temporal_time_zone_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.Now.zonedDateTimeISO";
  // 1. Let calendar be ! GetISO8601Calendar().
  Handle<JSReceiver> calendar = temporal::GetISO8601Calendar(isolate);
  // 2. Return ? SystemZonedDateTime(temporalTimeZoneLike, calendar).
  return SystemZonedDateTime(isolate, temporal_time_zone_like, calendar,
                             method_name);
}

// #sec-temporal.zoneddatetime.prototype.round
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::Round(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> round_to_obj) {
  const char* method_name = "Temporal.ZonedDateTime.prototype.round";
  Factory* factory = isolate->factory();
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
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
  // required, « "day" »).
  Unit smallest_unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, smallest_unit,
      GetTemporalUnit(isolate, round_to, "smallestUnit", UnitGroup::kTime,
                      Unit::kDay, true, method_name, Unit::kDay),
      Handle<JSTemporalZonedDateTime>());

  // 7. Let roundingMode be ? ToTemporalRoundingMode(roundTo, "halfExpand").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, round_to, RoundingMode::kHalfExpand,
                             method_name),
      Handle<JSTemporalZonedDateTime>());

  // 8. Let roundingIncrement be ? ToTemporalDateTimeRoundingIncrement(roundTo,
  // smallestUnit).
  double rounding_increment;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_increment,
      ToTemporalDateTimeRoundingIncrement(isolate, round_to, smallest_unit),
      Handle<JSTemporalZonedDateTime>());

  // 9. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 10. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();
  // 11. Let calendar be zonedDateTime.[[Calendar]].
  Handle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);
  // 12. Let temporalDateTime be ? BuiltinTimeZoneGetPlainDateTimeFor(timeZone,
  // instant, calendar).
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   calendar, method_name));
  // 13. Let isoCalendar be ! GetISO8601Calendar().
  DirectHandle<JSReceiver> iso_calendar = temporal::GetISO8601Calendar(isolate);

  // 14. Let dtStart be ? CreateTemporalDateTime(temporalDateTime.[[ISOYear]],
  // temporalDateTime.[[ISOMonth]], temporalDateTime.[[ISODay]], 0, 0, 0, 0, 0,
  // 0, isoCalendar).
  Handle<JSTemporalPlainDateTime> dt_start;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, dt_start,
      temporal::CreateTemporalDateTime(
          isolate,
          {{temporal_date_time->iso_year(), temporal_date_time->iso_month(),
            temporal_date_time->iso_day()},
           {0, 0, 0, 0, 0, 0}},
          iso_calendar));
  // 15. Let instantStart be ? BuiltinTimeZoneGetInstantFor(timeZone, dtStart,
  // "compatible").
  Handle<JSTemporalInstant> instant_start;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant_start,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, dt_start,
                                   Disambiguation::kCompatible, method_name));
  // 16. Let startNs be instantStart.[[Nanoseconds]].
  Handle<BigInt> start_ns(instant_start->nanoseconds(), isolate);
  // 17. Let endNs be ? AddZonedDateTime(startNs, timeZone, calendar, 0, 0, 0,
  // 1, 0, 0, 0, 0, 0, 0).
  Handle<BigInt> end_ns;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, end_ns,
      AddZonedDateTime(isolate, start_ns, time_zone, calendar,
                       {0, 0, 0, {1, 0, 0, 0, 0, 0, 0}}, method_name));
  // 18. Let dayLengthNs be ℝ(endNs - startNs).
  DirectHandle<BigInt> day_length_ns =
      BigInt::Subtract(isolate, end_ns, start_ns).ToHandleChecked();
  // 19. If dayLengthNs ≤ 0, then
  if (day_length_ns->IsNegative() || !day_length_ns->ToBoolean()) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 20. Let roundResult be ! RoundISODateTime(temporalDateTime.[[ISOYear]],
  // temporalDateTime.[[ISOMonth]], temporalDateTime.[[ISODay]],
  // temporalDateTime.[[ISOHour]], temporalDateTime.[[ISOMinute]],
  // temporalDateTime.[[ISOSecond]], temporalDateTime.[[ISOMillisecond]],
  // temporalDateTime.[[ISOMicrosecond]], temporalDateTime.[[ISONanosecond]],
  // roundingIncrement, smallestUnit, roundingMode, dayLengthNs).
  DateTimeRecord round_result = RoundISODateTime(
      isolate,
      {{temporal_date_time->iso_year(), temporal_date_time->iso_month(),
        temporal_date_time->iso_day()},
       {temporal_date_time->iso_hour(), temporal_date_time->iso_minute(),
        temporal_date_time->iso_second(), temporal_date_time->iso_millisecond(),
        temporal_date_time->iso_microsecond(),
        temporal_date_time->iso_nanosecond()}},
      rounding_increment, smallest_unit, rounding_mode,
      Object::NumberValue(*BigInt::ToNumber(isolate, day_length_ns)));
  // 21. Let offsetNanoseconds be ? GetOffsetNanosecondsFor(timeZone, instant).
  int64_t offset_nanoseconds;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_nanoseconds,
      GetOffsetNanosecondsFor(isolate, time_zone, instant, method_name),
      Handle<JSTemporalZonedDateTime>());
  // 22. Let epochNanoseconds be ?
  // InterpretISODateTimeOffset(roundResult.[[Year]], roundResult.[[Month]],
  // roundResult.[[Day]], roundResult.[[Hour]], roundResult.[[Minute]],
  // roundResult.[[Second]], roundResult.[[Millisecond]],
  // roundResult.[[Microsecond]], roundResult.[[Nanosecond]], option,
  // offsetNanoseconds, timeZone, "compatible", "prefer", match exactly).
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      InterpretISODateTimeOffset(
          isolate, round_result, OffsetBehaviour::kOption, offset_nanoseconds,
          time_zone, Disambiguation::kCompatible, Offset::kPrefer,
          MatchBehaviour::kMatchExactly, method_name));

  // 23. Return ! CreateTemporalZonedDateTime(epochNanoseconds, timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(isolate, epoch_nanoseconds, time_zone,
                                     calendar)
      .ToHandleChecked();
}

namespace {

// #sec-temporal-adddurationtoOrsubtractdurationfromzoneddatetime
MaybeHandle<JSTemporalZonedDateTime>
AddDurationToOrSubtractDurationFromZonedDateTime(
    Isolate* isolate, Arithmetic operation,
    DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> temporal_duration_like, Handle<Object> options_obj,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. If operation is subtract, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == Arithmetic::kSubtract ? -1.0 : 1.0;
  // 2. Let duration be ? ToTemporalDurationRecord(temporalDurationLike).
  DurationRecord duration;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, duration,
      temporal::ToTemporalDurationRecord(isolate, temporal_duration_like,
                                         method_name),
      Handle<JSTemporalZonedDateTime>());

  TimeDurationRecord& time_duration = duration.time_duration;

  // 3. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 4. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 5. Let calendar be zonedDateTime.[[Calendar]].
  Handle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);
  // 6. Let epochNanoseconds be ?
  // AddZonedDateTime(zonedDateTime.[[Nanoseconds]], timeZone, calendar,
  // sign x duration.[[Years]], sign x duration.[[Months]], sign x
  // duration.[[Weeks]], sign x duration.[[Days]], sign x duration.[[Hours]],
  // sign x duration.[[Minutes]], sign x duration.[[Seconds]], sign x
  // duration.[[Milliseconds]], sign x duration.[[Microseconds]], sign x
  // duration.[[Nanoseconds]], options).
  Handle<BigInt> nanoseconds(zoned_date_time->nanoseconds(), isolate);
  duration.years *= sign;
  duration.months *= sign;
  duration.weeks *= sign;
  time_duration.days *= sign;
  time_duration.hours *= sign;
  time_duration.minutes *= sign;
  time_duration.seconds *= sign;
  time_duration.milliseconds *= sign;
  time_duration.microseconds *= sign;
  time_duration.nanoseconds *= sign;
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      AddZonedDateTime(isolate, nanoseconds, time_zone, calendar, duration,
                       options, method_name));

  // 7. Return ? CreateTemporalZonedDateTime(epochNanoseconds, timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(isolate, epoch_nanoseconds, time_zone,
                                     calendar);
}

}  // namespace

// #sec-temporal.zoneddatetime.prototype.add
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::Add(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> temporal_duration_like, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return AddDurationToOrSubtractDurationFromZonedDateTime(
      isolate, Arithmetic::kAdd, zoned_date_time, temporal_duration_like,
      options, "Temporal.ZonedDateTime.prototype.add");
}
// #sec-temporal.zoneddatetime.prototype.subtract
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::Subtract(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> temporal_duration_like, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return AddDurationToOrSubtractDurationFromZonedDateTime(
      isolate, Arithmetic::kSubtract, zoned_date_time, temporal_duration_like,
      options, "Temporal.ZonedDateTime.prototype.subtract");
}

namespace {

// #sec-temporal-differencetemporalzoneddatetime
MaybeHandle<JSTemporalDuration> DifferenceTemporalZonedDateTime(
    Isolate* isolate, TimePreposition operation,
    Handle<JSTemporalZonedDateTime> zoned_date_time, Handle<Object> other_obj,
    Handle<Object> options, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. If operation is since, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == TimePreposition::kSince ? -1 : 1;
  // 2. Set other to ? ToTemporalZonedDateTime(other).
  Handle<JSTemporalZonedDateTime> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other, ToTemporalZonedDateTime(isolate, other_obj, method_name));
  // 3. If ? CalendarEquals(zonedDateTime.[[Calendar]], other.[[Calendar]]) is
  // false, then
  bool calendar_equals;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar_equals,
      CalendarEqualsBool(isolate, handle(zoned_date_time->calendar(), isolate),
                         handle(other->calendar(), isolate)),
      Handle<JSTemporalDuration>());
  if (!calendar_equals) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 4. Let settings be ? GetDifferenceSettings(operation, options, datetime, «
  // », "nanosecond", "hour").
  DifferenceSettings settings;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, settings,
      GetDifferenceSettings(isolate, operation, options, UnitGroup::kDateTime,
                            DisallowedUnitsInDifferenceSettings::kNone,
                            Unit::kNanosecond, Unit::kHour, method_name),
      Handle<JSTemporalDuration>());

  // 5. If settings.[[LargestUnit]] is not one of "year", "month", "week", or
  // "day", then
  if (settings.largest_unit != Unit::kYear &&
      settings.largest_unit != Unit::kMonth &&
      settings.largest_unit != Unit::kWeek &&
      settings.largest_unit != Unit::kDay) {
    // 1. Let result be ! DifferenceInstant(zonedDateTime.[[Nanoseconds]],
    // other.[[Nanoseconds]], settings.[[RoundingIncrement]],
    // settings.[[SmallestUnit]], settings.[[LargestUnit]],
    // settings.[[RoundingMode]]).
    TimeDurationRecord balance_result = DifferenceInstant(
        isolate, handle(zoned_date_time->nanoseconds(), isolate),
        handle(other->nanoseconds(), isolate), settings.rounding_increment,
        settings.smallest_unit, settings.largest_unit, settings.rounding_mode,
        method_name);
    // d. Return ! CreateTemporalDuration(0, 0, 0, 0, sign ×
    // balanceResult.[[Hours]], sign × balanceResult.[[Minutes]], sign ×
    // balanceResult.[[Seconds]], sign × balanceResult.[[Milliseconds]], sign ×
    // balanceResult.[[Microseconds]], sign × balanceResult.[[Nanoseconds]]).
    return CreateTemporalDuration(
               isolate,
               {0,
                0,
                0,
                {0, sign * balance_result.hours, sign * balance_result.minutes,
                 sign * balance_result.seconds,
                 sign * balance_result.milliseconds,
                 sign * balance_result.microseconds,
                 sign * balance_result.nanoseconds}})
        .ToHandleChecked();
  }
  // 6. If ? TimeZoneEquals(zonedDateTime.[[TimeZone]], other.[[TimeZone]]) is
  // false, then
  bool equals;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, equals,
      TimeZoneEquals(isolate, handle(zoned_date_time->time_zone(), isolate),
                     handle(other->time_zone(), isolate)),
      Handle<JSTemporalDuration>());
  if (!equals) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 7. Let untilOptions be ? MergeLargestUnitOption(settings.[[Options]],
  // settings.[[LargestUnit]]).
  Handle<JSReceiver> until_options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, until_options,
      MergeLargestUnitOption(isolate, settings.options, settings.largest_unit));
  // 8. Let difference be ?
  // DifferenceZonedDateTime(zonedDateTime.[[Nanoseconds]],
  // other.[[Nanoseconds]], zonedDateTime.[[TimeZone]],
  // zonedDateTime.[[Calendar]], settings.[[LargestUnit]], untilOptions).
  DurationRecord difference;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, difference,
      DifferenceZonedDateTime(
          isolate, handle(zoned_date_time->nanoseconds(), isolate),
          handle(other->nanoseconds(), isolate),
          handle(zoned_date_time->time_zone(), isolate),
          handle(zoned_date_time->calendar(), isolate), settings.largest_unit,
          until_options, method_name),
      Handle<JSTemporalDuration>());

  // 9. Let roundResult be (? RoundDuration(difference.[[Years]],
  // difference.[[Months]], difference.[[Weeks]], difference.[[Days]],
  // difference.[[Hours]], difference.[[Minutes]], difference.[[Seconds]],
  // difference.[[Milliseconds]], difference.[[Microseconds]],
  // difference.[[Nanoseconds]], settings.[[RoundingIncrement]],
  // settings.[[SmallestUnit]], settings.[[RoundingMode]],
  // zonedDateTime)).[[DurationRecord]].
  DurationRecordWithRemainder round_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, round_result,
      RoundDuration(isolate, difference, settings.rounding_increment,
                    settings.smallest_unit, settings.rounding_mode,
                    zoned_date_time, method_name),
      Handle<JSTemporalDuration>());
  // 10. Let result be ? AdjustRoundedDurationDays(roundResult.[[Years]],
  // roundResult.[[Months]], roundResult.[[Weeks]], roundResult.[[Days]],
  // roundResult.[[Hours]], roundResult.[[Minutes]], roundResult.[[Seconds]],
  // roundResult.[[Milliseconds]], roundResult.[[Microseconds]],
  // roundResult.[[Nanoseconds]], settings.[[RoundingIncrement]],
  // settings.[[SmallestUnit]], settings.[[RoundingMode]], zonedDateTime).
  DurationRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      AdjustRoundedDurationDays(isolate, round_result.record,
                                settings.rounding_increment,
                                settings.smallest_unit, settings.rounding_mode,
                                zoned_date_time, method_name),
      Handle<JSTemporalDuration>());

  // 11. Return ! CreateTemporalDuration(sign × result.[[Years]], sign ×
  // result.[[Months]], sign × result.[[Weeks]], sign × result.[[Days]], sign ×
  // result.[[Hours]], sign × result.[[Minutes]], sign × result.[[Seconds]],
  // sign × result.[[Milliseconds]], sign × result.[[Microseconds]], sign ×
  // result.[[Nanoseconds]]).
  return CreateTemporalDuration(isolate,
                                {sign * result.years,
                                 sign * result.months,
                                 sign * result.weeks,
                                 {sign * result.time_duration.days,
                                  sign * result.time_duration.hours,
                                  sign * result.time_duration.minutes,
                                  sign * result.time_duration.seconds,
                                  sign * result.time_duration.milliseconds,
                                  sign * result.time_duration.microseconds,
                                  sign * result.time_duration.nanoseconds}})
      .ToHandleChecked();
}

}  // namespace

// #sec-temporal.zoneddatetime.prototype.until
MaybeHandle<JSTemporalDuration> JSTemporalZonedDateTime::Until(
    Isolate* isolate, Handle<JSTemporalZonedDateTime> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalZonedDateTime(
      isolate, TimePreposition::kUntil, handle, other, options,
      "Temporal.ZonedDateTime.prototype.until");
}

// #sec-temporal.zoneddatetime.prototype.since
MaybeHandle<JSTemporalDuration> JSTemporalZonedDateTime::Since(
    Isolate* isolate, Handle<JSTemporalZonedDateTime> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalZonedDateTime(
      isolate, TimePreposition::kSince, handle, other, options,
      "Temporal.ZonedDateTime.prototype.since");
}

// #sec-temporal.zoneddatetime.prototype.getisofields
MaybeHandle<JSReceiver> JSTemporalZonedDateTime::GetISOFields(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.getISOFields";
  Factory* factory = isolate->factory();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let fields be ! OrdinaryObjectCreate(%Object.prototype%).
  Handle<JSObject> fields =
      isolate->factory()->NewJSObject(isolate->object_function());
  // 4. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone =
      Handle<JSReceiver>(zoned_date_time->time_zone(), isolate);
  // 5. Let instant be ? CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate)));

  // 6. Let calendar be zonedDateTime.[[Calendar]].
  Handle<JSReceiver> calendar =
      Handle<JSReceiver>(zoned_date_time->calendar(), isolate);
  // 7. Let dateTime be ? BuiltinTimeZoneGetPlainDateTimeFor(timeZone,
  // instant, calendar).
  Handle<JSTemporalPlainDateTime> date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   calendar, method_name));
  // 8. Let offset be ? BuiltinTimeZoneGetOffsetStringFor(timeZone, instant).
  Handle<String> offset;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, offset,
                             BuiltinTimeZoneGetOffsetStringFor(
                                 isolate, time_zone, instant, method_name));

#define DEFINE_STRING_FIELD(obj, str, field)                                  \
  CHECK(JSReceiver::CreateDataProperty(isolate, obj, factory->str##_string(), \
                                       field, Just(kThrowOnError))            \
            .FromJust());

  // 9. Perform ! CreateDataPropertyOrThrow(fields, "calendar", calendar).
  // 10. Perform ! CreateDataPropertyOrThrow(fields, "isoDay",
  // 𝔽(dateTime.[[ISODay]])).
  // 11. Perform ! CreateDataPropertyOrThrow(fields, "isoHour",
  // 𝔽(temporalTime.[[ISOHour]])).
  // 12. Perform ! CreateDataPropertyOrThrow(fields, "isoMicrosecond",
  // 𝔽(temporalTime.[[ISOMicrosecond]])).
  // 13. Perform ! CreateDataPropertyOrThrow(fields, "isoMillisecond",
  // 𝔽(temporalTime.[[ISOMillisecond]])).
  // 14. Perform ! CreateDataPropertyOrThrow(fields, "isoMinute",
  // 𝔽(temporalTime.[[ISOMinute]])).
  // 15. Perform ! CreateDataPropertyOrThrow(fields, "isoMonth",
  // 𝔽(temporalTime.[[ISOMonth]])).
  // 16. Perform ! CreateDataPropertyOrThrow(fields, "isoNanosecond",
  // 𝔽(temporalTime.[[ISONanosecond]])).
  // 17. Perform ! CreateDataPropertyOrThrow(fields, "isoSecond",
  // 𝔽(temporalTime.[[ISOSecond]])).
  // 18. Perform ! CreateDataPropertyOrThrow(fields, "isoYear",
  // 𝔽(temporalTime.[[ISOYear]])).
  // 19. Perform ! CreateDataPropertyOrThrow(fields, "offset", offset).
  // 20. Perform ! CreateDataPropertyOrThrow(fields, "timeZone", timeZone).
  DEFINE_STRING_FIELD(fields, calendar, calendar)
  DEFINE_INT_FIELD(fields, isoDay, iso_day, date_time)
  DEFINE_INT_FIELD(fields, isoHour, iso_hour, date_time)
  DEFINE_INT_FIELD(fields, isoMicrosecond, iso_microsecond, date_time)
  DEFINE_INT_FIELD(fields, isoMillisecond, iso_millisecond, date_time)
  DEFINE_INT_FIELD(fields, isoMinute, iso_minute, date_time)
  DEFINE_INT_FIELD(fields, isoMonth, iso_month, date_time)
  DEFINE_INT_FIELD(fields, isoNanosecond, iso_nanosecond, date_time)
  DEFINE_INT_FIELD(fields, isoSecond, iso_second, date_time)
  DEFINE_INT_FIELD(fields, isoYear, iso_year, date_time)
  DEFINE_STRING_FIELD(fields, offset, offset)
  DEFINE_STRING_FIELD(fields, timeZone, time_zone)
  // 21. Return fields.
  return fields;
}

// #sec-temporal.now.instant
MaybeHandle<JSTemporalInstant> JSTemporalInstant::Now(Isolate* isolate) {
  TEMPORAL_ENTER_FUNC();
  return SystemInstant(isolate);
}

// #sec-get-temporal.zoneddatetime.prototype.offsetnanoseconds
MaybeHandle<Object> JSTemporalZonedDateTime::OffsetNanoseconds(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 4. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();
  // 5. Return 𝔽(? GetOffsetNanosecondsFor(timeZone, instant)).
  int64_t result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      GetOffsetNanosecondsFor(
          isolate, time_zone, instant,
          "Temporal.ZonedDateTime.prototype.offsetNanoseconds"),
      Handle<Object>());
  return isolate->factory()->NewNumberFromInt64(result);
}

// #sec-get-temporal.zoneddatetime.prototype.offset
MaybeHandle<String> JSTemporalZonedDateTime::Offset(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();
  // 4. Return ? BuiltinTimeZoneGetOffsetStringFor(zonedDateTime.[[TimeZone]],
  // instant).
  return BuiltinTimeZoneGetOffsetStringFor(
      isolate, handle(zoned_date_time->time_zone(), isolate), instant,
      "Temporal.ZonedDateTime.prototype.offset");
}

// #sec-temporal.zoneddatetime.prototype.startofday
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::StartOfDay(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.startOfDay";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 4. Let calendar be zonedDateTime.[[Calendar]].
  DirectHandle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);
  // 5. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();
  // 6. Let temporalDateTime be ?
  // BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant, calendar).
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   calendar, method_name));
  // 7. Let startDateTime be ?
  // CreateTemporalDateTime(temporalDateTime.[[ISOYear]],
  // temporalDateTime.[[ISOMonth]], temporalDateTime.[[ISODay]], 0, 0, 0, 0, 0,
  // 0, calendar).
  Handle<JSTemporalPlainDateTime> start_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, start_date_time,
      temporal::CreateTemporalDateTime(
          isolate,
          {{temporal_date_time->iso_year(), temporal_date_time->iso_month(),
            temporal_date_time->iso_day()},
           {0, 0, 0, 0, 0, 0}},
          calendar));
  // 8. Let startInstant be ? BuiltinTimeZoneGetInstantFor(timeZone,
  // startDateTime, "compatible").
  Handle<JSTemporalInstant> start_instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, start_instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, start_date_time,
                                   Disambiguation::kCompatible, method_name));
  // 9. Return ? CreateTemporalZonedDateTime(startInstant.[[Nanoseconds]],
  // timeZone, calendar).
  return CreateTemporalZonedDateTime(
      isolate, handle(start_instant->nanoseconds(), isolate), time_zone,
      calendar);
}

// #sec-temporal.zoneddatetime.prototype.toinstant
MaybeHandle<JSTemporalInstant> JSTemporalZonedDateTime::ToInstant(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Return ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  return temporal::CreateTemporalInstant(
             isolate, handle(zoned_date_time->nanoseconds(), isolate))
      .ToHandleChecked();
}

namespace {

// Function implment shared steps of toplaindate, toplaintime, toplaindatetime
MaybeHandle<JSTemporalPlainDateTime> ZonedDateTimeToPlainDateTime(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 4. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();
  // 5. 5. Return ? BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant,
  // zonedDateTime.[[Calendar]]).
  return temporal::BuiltinTimeZoneGetPlainDateTimeFor(
      isolate, time_zone, instant, handle(zoned_date_time->calendar(), isolate),
      method_name);
}

}  // namespace

// #sec-temporal.zoneddatetime.prototype.toplaindate
MaybeHandle<JSTemporalPlainDate> JSTemporalZonedDateTime::ToPlainDate(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  // Step 1-6 are the same as toplaindatetime
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      ZonedDateTimeToPlainDateTime(
          isolate, zoned_date_time,
          "Temporal.ZonedDateTime.prototype.toPlainDate"));
  // 7. Return ? CreateTemporalDate(temporalDateTime.[[ISOYear]],
  // temporalDateTime.[[ISOMonth]], temporalDateTime.[[ISODay]], calendar).
  return CreateTemporalDate(
      isolate,
      {temporal_date_time->iso_year(), temporal_date_time->iso_month(),
       temporal_date_time->iso_day()},
      handle(zoned_date_time->calendar(), isolate));
}

// #sec-temporal.zoneddatetime.prototype.toplaintime
MaybeHandle<JSTemporalPlainTime> JSTemporalZonedDateTime::ToPlainTime(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  // Step 1-6 are the same as toplaindatetime
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      ZonedDateTimeToPlainDateTime(
          isolate, zoned_date_time,
          "Temporal.ZonedDateTime.prototype.toPlainTime"));
  // 7. Return ?  CreateTemporalTime(temporalDateTime.[[ISOHour]],
  // temporalDateTime.[[ISOMinute]], temporalDateTime.[[ISOSecond]],
  // temporalDateTime.[[ISOMillisecond]], temporalDateTime.[[ISOMicrosecond]],
  // temporalDateTime.[[ISONanosecond]]).
  return CreateTemporalTime(
      isolate,
      {temporal_date_time->iso_hour(), temporal_date_time->iso_minute(),
       temporal_date_time->iso_second(), temporal_date_time->iso_millisecond(),
       temporal_date_time->iso_microsecond(),
       temporal_date_time->iso_nanosecond()});
}

// #sec-temporal.zoneddatetime.prototype.toplaindatetime
MaybeHandle<JSTemporalPlainDateTime> JSTemporalZonedDateTime::ToPlainDateTime(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  return ZonedDateTimeToPlainDateTime(
      isolate, zoned_date_time,
      "Temporal.ZonedDateTime.prototype.toPlainDateTime");
}

// #sec-temporal.instant
MaybeHandle<JSTemporalInstant> JSTemporalInstant::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> epoch_nanoseconds_obj) {
  TEMPORAL_ENTER_FUNC();
  // 1. If NewTarget is undefined, then
  if (IsUndefined(*new_target)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     "Temporal.Instant")));
  }
  // 2. Let epochNanoseconds be ? ToBigInt(epochNanoseconds).
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      BigInt::FromObject(isolate, epoch_nanoseconds_obj));
  // 3. If ! IsValidEpochNanoseconds(epochNanoseconds) is false, throw a
  // RangeError exception.
  if (!IsValidEpochNanoseconds(isolate, epoch_nanoseconds)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 4. Return ? CreateTemporalInstant(epochNanoseconds, NewTarget).
  return temporal::CreateTemporalInstant(isolate, target, new_target,
                                         epoch_nanoseconds);
}

namespace {

// The logic in Temporal.Instant.fromEpochSeconds and fromEpochMilliseconds,
// are the same except a scaling factor, code all of them into the follow
// function.
MaybeHandle<JSTemporalInstant> ScaleNumberToNanosecondsVerifyAndMake(
    Isolate* isolate, Handle<BigInt> bigint, uint32_t scale) {
  TEMPORAL_ENTER_FUNC();
  DCHECK(scale == 1 || scale == 1000 || scale == 1000000 ||
         scale == 1000000000);
  // 2. Let epochNanoseconds be epochXseconds × scaleℤ.
  Handle<BigInt> epoch_nanoseconds;
  if (scale == 1) {
    epoch_nanoseconds = bigint;
  } else {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, epoch_nanoseconds,
        BigInt::Multiply(isolate, BigInt::FromUint64(isolate, scale), bigint));
  }
  // 3. If ! IsValidEpochNanoseconds(epochNanoseconds) is false, throw a
  // RangeError exception.
  if (!IsValidEpochNanoseconds(isolate, epoch_nanoseconds)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  return temporal::CreateTemporalInstant(isolate, epoch_nanoseconds);
}

MaybeHandle<JSTemporalInstant> ScaleNumberToNanosecondsVerifyAndMake(
    Isolate* isolate, Handle<Object> epoch_Xseconds, uint32_t scale) {
  TEMPORAL_ENTER_FUNC();
  // 1. Set epochXseconds to ? ToNumber(epochXseconds).
  ASSIGN_RETURN_ON_EXCEPTION(isolate, epoch_Xseconds,
                             Object::ToNumber(isolate, epoch_Xseconds));
  // 2. Set epochMilliseconds to ? NumberToBigInt(epochMilliseconds).
  Handle<BigInt> bigint;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, bigint,
                             BigInt::FromNumber(isolate, epoch_Xseconds));
  return ScaleNumberToNanosecondsVerifyAndMake(isolate, bigint, scale);
}

MaybeHandle<JSTemporalInstant> ScaleToNanosecondsVerifyAndMake(
    Isolate* isolate, Handle<Object> epoch_Xseconds, uint32_t scale) {
  TEMPORAL_ENTER_FUNC();
  // 1. Set epochMicroseconds to ? ToBigInt(epochMicroseconds).
  Handle<BigInt> bigint;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, bigint,
                             BigInt::FromObject(isolate, epoch_Xseconds));
  return ScaleNumberToNanosecondsVerifyAndMake(isolate, bigint, scale);
}

}  // namespace

// #sec-temporal.instant.fromepochseconds
MaybeHandle<JSTemporalInstant> JSTemporalInstant::FromEpochSeconds(
    Isolate* isolate, Handle<Object> epoch_seconds) {
  TEMPORAL_ENTER_FUNC();
  return ScaleNumberToNanosecondsVerifyAndMake(isolate, epoch_seconds,
                                               1000000000);
}

// #sec-temporal.instant.fromepochmilliseconds
MaybeHandle<JSTemporalInstant> JSTemporalInstant::FromEpochMilliseconds(
    Isolate* isolate, Handle<Object> epoch_milliseconds) {
  TEMPORAL_ENTER_FUNC();
  return ScaleNumberToNanosecondsVerifyAndMake(isolate, epoch_milliseconds,
                                               1000000);
}

// #sec-temporal.instant.fromepochmicroseconds
MaybeHandle<JSTemporalInstant> JSTemporalInstant::FromEpochMicroseconds(
    Isolate* isolate, Handle<Object> epoch_microseconds) {
  TEMPORAL_ENTER_FUNC();
  return ScaleToNanosecondsVerifyAndMake(isolate, epoch_microseconds, 1000);
}

// #sec-temporal.instant.fromepochnanoeconds
MaybeHandle<JSTemporalInstant> JSTemporalInstant::FromEpochNanoseconds(
    Isolate* isolate, Handle<Object> epoch_nanoseconds) {
  TEMPORAL_ENTER_FUNC();
  return ScaleToNanosecondsVerifyAndMake(isolate, epoch_nanoseconds, 1);
}

// #sec-temporal.instant.compare
MaybeHandle<Smi> JSTemporalInstant::Compare(Isolate* isolate,
                                            Handle<Object> one_obj,
                                            Handle<Object> two_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.Instant.compare";
  // 1. Set one to ? ToTemporalInstant(one).
  Handle<JSTemporalInstant> one;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, one,
                             ToTemporalInstant(isolate, one_obj, method_name));
  // 2. Set two to ? ToTemporalInstant(two).
  Handle<JSTemporalInstant> two;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, two,
                             ToTemporalInstant(isolate, two_obj, method_name));
  // 3. Return 𝔽(! CompareEpochNanoseconds(one.[[Nanoseconds]],
  // two.[[Nanoseconds]])).
  return CompareEpochNanoseconds(isolate, handle(one->nanoseconds(), isolate),
                                 handle(two->nanoseconds(), isolate));
}

// #sec-temporal.instant.prototype.equals
MaybeHandle<Oddball> JSTemporalInstant::Equals(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> other_obj) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let instant be the this value.
  // 2. Perform ? RequireInternalSlot(instant, [[InitializedTemporalInstant]]).
  // 3. Set other to ? ToTemporalInstant(other).
  Handle<JSTemporalInstant> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other,
      ToTemporalInstant(isolate, other_obj,
                        "Temporal.Instant.prototype.equals"));
  // 4. If instant.[[Nanoseconds]] ≠ other.[[Nanoseconds]], return false.
  // 5. Return true.
  return isolate->factory()->ToBoolean(
      BigInt::EqualToBigInt(handle->nanoseconds(), other->nanoseconds()));
}

namespace {

// #sec-temporal-totemporalroundingincrement
Maybe<double> ToTemporalRoundingIncrement(Isolate* isolate,
                                          Handle<JSReceiver> normalized_options,
                                          double dividend,
                                          bool dividend_is_defined,
                                          bool inclusive) {
  double maximum;
  // 1. If dividend is undefined, then
  if (!dividend_is_defined) {
    // a. Let maximum be +∞.
    maximum = std::numeric_limits<double>::infinity();
    // 2. Else if inclusive is true, then
  } else if (inclusive) {
    // a. Let maximum be 𝔽(dividend).
    maximum = dividend;
    // 3. Else if dividend is more than 1, then
  } else if (dividend > 1) {
    // a. Let maximum be 𝔽(dividend-1).
    maximum = dividend - 1;
    // 4. Else,
  } else {
    // a. Let maximum be 1.
    maximum = 1;
  }
  // 5. Let increment be ? GetOption(normalizedOptions, "roundingIncrement", «
  // Number », empty, 1).
  double increment;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, increment,
      GetNumberOptionAsDouble(isolate, normalized_options,
                              isolate->factory()->roundingIncrement_string(),
                              1),
      Nothing<double>());

  // 6. If increment < 1 or increment > maximum, throw a RangeError exception.
  if (increment < 1 || increment > maximum) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(), Nothing<double>());
  }
  // 7. Set increment to floor(ℝ(increment)).
  increment = std::floor(increment);

  // 8. If dividend is not undefined and dividend modulo increment is not zero,
  // then
  if ((dividend_is_defined) && (std::fmod(dividend, increment) != 0)) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(), Nothing<double>());
  }
  // 9. Return increment.
  return Just(increment);
}

// #sec-temporal-roundtemporalinstant
Handle<BigInt> RoundTemporalInstant(Isolate* isolate, Handle<BigInt> ns,
                                    double increment, Unit unit,
                                    RoundingMode rounding_mode) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: Type(ns) is BigInt.
  double increment_ns;
  switch (unit) {
    // 2. If unit is "hour", then
    case Unit::kHour:
      // a. Let incrementNs be increment × 3.6 × 10^12.
      increment_ns = increment * 3.6e12;
      break;
    // 3. Else if unit is "minute", then
    case Unit::kMinute:
      // a. Let incrementNs be increment × 6 × 10^10.
      increment_ns = increment * 6e10;
      break;
    // 4. Else if unit is "second", then
    case Unit::kSecond:
      // a. Let incrementNs be increment × 10^9.
      increment_ns = increment * 1e9;
      break;
    // 5. Else if unit is "millisecond", then
    case Unit::kMillisecond:
      // a. Let incrementNs be increment × 10^6.
      increment_ns = increment * 1e6;
      break;
    // 6. Else if unit is "microsecond", then
    case Unit::kMicrosecond:
      // a. Let incrementNs be increment × 10^3.
      increment_ns = increment * 1e3;
      break;
    // 7. Else,
    // a. Assert: unit is "nanosecond".
    case Unit::kNanosecond:
      // b. Let incrementNs be increment.
      increment_ns = increment;
      break;
    default:
      UNREACHABLE();
  }
  // 8. Return ! RoundNumberToIncrementAsIfPositive(ℝ(ns), incrementNs,
  // roundingMode).
  return RoundNumberToIncrementAsIfPositive(isol
```