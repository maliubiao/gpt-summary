Response: The user wants a summary of the C++ source code file `v8/src/objects/js-temporal-objects.cc`. This is the 13th part of a 13-part file, which suggests it's the final part and might contain utility functions or implementations of methods related to the JavaScript `Temporal` API.

Based on the code snippets provided, I can see implementations for:

- `Temporal.Instant.prototype.round()`
- `Temporal.Instant.from()`
- `Temporal.Instant.prototype.toZonedDateTime()`
- `Temporal.Instant.prototype.toJSON()`
- `Temporal.Instant.prototype.toLocaleString()`
- `Temporal.Instant.prototype.toString()`
- `Temporal.Instant.prototype.toZonedDateTimeISO()`
- `Temporal.Instant.prototype.add()`
- `Temporal.Instant.prototype.subtract()`
- `Temporal.Instant.prototype.until()`
- `Temporal.Instant.prototype.since()`

It also includes helper functions like:

- `TemporalInstantToString()`
- `AddDurationToOrSubtractDurationFromInstant()`
- `NegateTemporalRoundingMode()`
- `GetDifferenceSettings()`
- `DifferenceInstant()`
- `DifferenceTemporalInstant()`
- `IsInvalidTemporalCalendarField()`
- `GetBuiltinCalendar()`
- `BuiltinTimeZoneGetInstantForCompatible()`

Considering this is the last part of the file, it likely focuses on implementing methods related to the `Temporal.Instant` object in JavaScript and some utility functions used by the `Temporal` API.

**Summary Plan:**

1. State that the file implements methods of the `Temporal.Instant` object.
2. List the main methods implemented.
3. Describe the purpose of each main method and relate it to its JavaScript counterpart.
4. Mention the presence of helper functions and their general purpose.
5. Provide a JavaScript example demonstrating one of the implemented methods.
这个C++源代码文件（`v8/src/objects/js-temporal-objects.cc`）是V8 JavaScript引擎中关于 `Temporal` API 的一部分，具体来说，**它实现了 `Temporal.Instant` 对象的一些核心功能**。 由于这是第 13 部分，也是最后一部分，它很可能包含了 `Temporal.Instant` 对象大部分的方法的具体实现以及一些辅助函数。

以下是该文件主要功能的归纳：

1. **`Temporal.Instant.prototype.round(roundTo)`:**  实现了 `Temporal.Instant` 对象的 `round` 方法，用于将时间瞬间四舍五入到指定的精度。它可以接收一个字符串（如 "hour", "minute"）或者一个包含 `smallestUnit` 和可选的 `roundingMode` 和 `roundingIncrement` 属性的对象作为参数。

2. **`Temporal.Instant.from(item)`:** 实现了 `Temporal.Instant` 对象的 `from` 静态方法，用于从其他类型的值（包括另一个 `Temporal.Instant` 对象或可以转换为 `Temporal.Instant` 的值）创建一个新的 `Temporal.Instant` 对象。

3. **`Temporal.Instant.prototype.toZonedDateTime(temporalTimeZoneLike)`:** 实现了 `Temporal.Instant` 对象的 `toZonedDateTime` 方法，将一个绝对的时间瞬间转换为带时区的日期时间 `Temporal.ZonedDateTime`。它需要一个包含 `timeZone` 和 `calendar` 属性的对象作为参数。

4. **`Temporal.Instant.prototype.toJSON()`:** 实现了 `Temporal.Instant` 对象的 `toJSON` 方法，返回 `Temporal.Instant` 的 ISO 8601 格式的字符串表示，始终使用 UTC 时区并省略日历信息。

5. **`Temporal.Instant.prototype.toLocaleString(locales, options)`:** 实现了 `Temporal.Instant` 对象的 `toLocaleString` 方法，根据指定的区域设置将 `Temporal.Instant` 格式化为本地化的字符串表示。这部分代码依赖于 V8 的国际化支持（`V8_INTL_SUPPORT`）。

6. **`Temporal.Instant.prototype.toString(options)`:** 实现了 `Temporal.Instant` 对象的 `toString` 方法，返回 `Temporal.Instant` 的字符串表示，可以自定义时区和精度。

7. **`Temporal.Instant.prototype.toZonedDateTimeISO(temporalTimeZoneLike)`:** 实现了 `Temporal.Instant` 对象的 `toZonedDateTimeISO` 方法，类似于 `toZonedDateTime`，但强制使用 ISO 8601 日历。

8. **`Temporal.Instant.prototype.add(temporalDurationLike)`:** 实现了 `Temporal.Instant` 对象的 `add` 方法，将一个 `Temporal.Duration` 对象添加到 `Temporal.Instant` 对象上，返回一个新的 `Temporal.Instant` 对象。

9. **`Temporal.Instant.prototype.subtract(temporalDurationLike)`:** 实现了 `Temporal.Instant` 对象的 `subtract` 方法，从 `Temporal.Instant` 对象中减去一个 `Temporal.Duration` 对象，返回一个新的 `Temporal.Instant` 对象。

10. **`Temporal.Instant.prototype.until(other, options)`:** 实现了 `Temporal.Instant` 对象的 `until` 方法，计算当前 `Temporal.Instant` 到另一个 `Temporal.Instant` 之间的时间差，并以 `Temporal.Duration` 对象的形式返回。

11. **`Temporal.Instant.prototype.since(other, options)`:** 实现了 `Temporal.Instant` 对象的 `since` 方法，计算另一个 `Temporal.Instant` 到当前 `Temporal.Instant` 之间的时间差，并以 `Temporal.Duration` 对象的形式返回。

此外，该文件还包含一些辅助函数，用于处理 `Temporal.Instant` 的各种操作，例如：

*   **`TemporalInstantToString`:** 将 `Temporal.Instant` 格式化为字符串。
*   **`AddDurationToOrSubtractDurationFromInstant`:**  用于 `add` 和 `subtract` 方法的内部逻辑。
*   **`NegateTemporalRoundingMode`:**  用于取反舍入模式。
*   **`GetDifferenceSettings`:**  用于获取计算时间差的配置项。
*   **`DifferenceInstant`:** 计算两个 `Temporal.Instant` 之间的原始时间差（以纳秒为单位）。
*   **`DifferenceTemporalInstant`:**  计算两个 `Temporal.Instant` 之间的 `Temporal.Duration` 差值。
*   **`IsInvalidTemporalCalendarField`:**  用于校验日历字段的有效性。
*   **`GetBuiltinCalendar`:**  获取内置日历对象。
*   **`BuiltinTimeZoneGetInstantForCompatible`:**  用于在给定时区和日期时间下获取对应的 `Temporal.Instant`。

**与 JavaScript 的关系及示例：**

这个 C++ 文件直接实现了 JavaScript 中 `Temporal.Instant` 对象的方法。  例如，`JSTemporalInstant::Round` 函数对应于 JavaScript 中的 `Temporal.Instant.prototype.round()` 方法。

**JavaScript 示例：**

```javascript
const now = Temporal.Instant.now();
console.log(now.toString()); // 输出当前时间的 ISO 8601 格式字符串

const roundedToHour = now.round('hour');
console.log(roundedToHour.toString()); // 输出四舍五入到小时的时间瞬间

const later = now.add({ hours: 2, minutes: 30 });
console.log(later.toString()); // 输出加上 2 小时 30 分钟后的时间瞬间

const anotherInstant = Temporal.Instant.from('2023-10-27T10:00:00Z');
const duration = now.until(anotherInstant);
console.log(duration.toString()); // 输出从 now 到 anotherInstant 的时间差
```

总而言之，这个 C++ 文件是 V8 引擎中实现 `Temporal.Instant` 对象核心功能的关键部分，它将 JavaScript 中对 `Temporal.Instant` 的操作转化为底层的 C++ 代码执行。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第13部分，共13部分，请归纳一下它的功能
```

### 源代码
```
ate, ns, increment_ns,
                                            rounding_mode);
}

}  // namespace

// #sec-temporal.instant.prototype.round
MaybeHandle<JSTemporalInstant> JSTemporalInstant::Round(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> round_to_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.Instant.prototype.round";
  Factory* factory = isolate->factory();
  // 1. Let instant be the this value.
  // 2. Perform ? RequireInternalSlot(instant, [[InitializedTemporalInstant]]).
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
                      Unit::kNotPresent, true, method_name),
      Handle<JSTemporalInstant>());

  // 7. Let roundingMode be ? ToTemporalRoundingMode(roundTo, "halfExpand").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, round_to, RoundingMode::kHalfExpand,
                             method_name),
      Handle<JSTemporalInstant>());
  double maximum;
  switch (smallest_unit) {
    // 8. If smallestUnit is "hour", then
    case Unit::kHour:
      // a. Let maximum be 24.
      maximum = 24;
      break;
    // 9. Else if smallestUnit is "minute", then
    case Unit::kMinute:
      // a. Let maximum be 1440.
      maximum = 1440;
      break;
    // 10. Else if smallestUnit is "second", then
    case Unit::kSecond:
      // a. Let maximum be 86400.
      maximum = 86400;
      break;
    // 11. Else if smallestUnit is "millisecond", then
    case Unit::kMillisecond:
      // a. Let maximum be 8.64 × 10^7.
      maximum = 8.64e7;
      break;
    // 12. Else if smallestUnit is "microsecond", then
    case Unit::kMicrosecond:
      // a. Let maximum be 8.64 × 10^10.
      maximum = 8.64e10;
      break;
    // 13. Else,
    case Unit::kNanosecond:
      // b. Let maximum be nsPerDay.
      maximum = kNsPerDay;
      break;
      // a. Assert: smallestUnit is "nanosecond".
    default:
      UNREACHABLE();
  }
  // 14. Let roundingIncrement be ? ToTemporalRoundingIncrement(roundTo,
  // maximum, true).
  double rounding_increment;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_increment,
      ToTemporalRoundingIncrement(isolate, round_to, maximum, true, true),
      Handle<JSTemporalInstant>());
  // 15. Let roundedNs be ! RoundTemporalInstant(instant.[[Nanoseconds]],
  // roundingIncrement, smallestUnit, roundingMode).
  DirectHandle<BigInt> rounded_ns = RoundTemporalInstant(
      isolate, Handle<BigInt>(handle->nanoseconds(), isolate),
      rounding_increment, smallest_unit, rounding_mode);
  // 16. Return ! CreateTemporalInstant(roundedNs).
  return temporal::CreateTemporalInstant(isolate, rounded_ns).ToHandleChecked();
}

// #sec-temporal.instant.from
MaybeHandle<JSTemporalInstant> JSTemporalInstant::From(Isolate* isolate,
                                                       Handle<Object> item) {
  TEMPORAL_ENTER_FUNC();
  //  1. If Type(item) is Object and item has an [[InitializedTemporalInstant]]
  //  internal slot, then
  if (IsJSTemporalInstant(*item)) {
    // a. Return ? CreateTemporalInstant(item.[[Nanoseconds]]).
    return temporal::CreateTemporalInstant(
        isolate,
        handle(Cast<JSTemporalInstant>(*item)->nanoseconds(), isolate));
  }
  // 2. Return ? ToTemporalInstant(item).
  return ToTemporalInstant(isolate, item, "Temporal.Instant.from");
}

// #sec-temporal.instant.prototype.tozoneddatetime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalInstant::ToZonedDateTime(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> item_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.Instant.prototype.toZonedDateTime";
  Factory* factory = isolate->factory();
  // 1. Let instant be the this value.
  // 2. Perform ? RequireInternalSlot(instant, [[InitializedTemporalInstant]]).
  // 3. If Type(item) is not Object, then
  if (!IsJSReceiver(*item_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
  // 4. Let calendarLike be ? Get(item, "calendar").
  Handle<Object> calendar_like;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar_like,
      JSReceiver::GetProperty(isolate, item, factory->calendar_string()));
  // 5. If calendarLike is undefined, then
  if (IsUndefined(*calendar_like)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  // 6. Let calendar be ? ToTemporalCalendar(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      temporal::ToTemporalCalendar(isolate, calendar_like, method_name));

  // 7. Let temporalTimeZoneLike be ? Get(item, "timeZone").
  Handle<Object> temporal_time_zone_like;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_time_zone_like,
      JSReceiver::GetProperty(isolate, item, factory->timeZone_string()));
  // 8. If temporalTimeZoneLike is undefined, then
  if (IsUndefined(*calendar_like)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  // 9. Let timeZone be ? ToTemporalTimeZone(temporalTimeZoneLike).
  Handle<JSReceiver> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      temporal::ToTemporalTimeZone(isolate, temporal_time_zone_like,
                                   method_name));
  // 10. Return ? CreateTemporalZonedDateTime(instant.[[Nanoseconds]], timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(
      isolate, Handle<BigInt>(handle->nanoseconds(), isolate), time_zone,
      calendar);
}

namespace {

// #sec-temporal-temporalinstanttostring
MaybeHandle<String> TemporalInstantToString(Isolate* isolate,
                                            Handle<JSTemporalInstant> instant,
                                            Handle<Object> time_zone_obj,
                                            Precision precision,
                                            const char* method_name) {
  IncrementalStringBuilder builder(isolate);
  // 1. Assert: Type(instant) is Object.
  // 2. Assert: instant has an [[InitializedTemporalInstant]] internal slot.
  // 3. Let outputTimeZone be timeZone.
  Handle<JSReceiver> output_time_zone;

  // 4. If outputTimeZone is undefined, then
  if (IsUndefined(*time_zone_obj)) {
    // a. Set outputTimeZone to ! CreateTemporalTimeZone("UTC").
    output_time_zone = CreateTemporalTimeZoneUTC(isolate);
  } else {
    DCHECK(IsJSReceiver(*time_zone_obj));
    output_time_zone = Cast<JSReceiver>(time_zone_obj);
  }

  // 5. Let isoCalendar be ! GetISO8601Calendar().
  Handle<JSTemporalCalendar> iso_calendar =
      temporal::GetISO8601Calendar(isolate);
  // 6. Let dateTime be ?
  // BuiltinTimeZoneGetPlainDateTimeFor(outputTimeZone, instant,
  // isoCalendar).
  Handle<JSTemporalPlainDateTime> date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(
          isolate, output_time_zone, instant, iso_calendar, method_name));
  // 7. Let dateTimeString be ? TemporalDateTimeToString(dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]], undefined, precision, "never").

  Handle<String> date_time_string;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time_string,
      TemporalDateTimeToString(
          isolate,
          {{date_time->iso_year(), date_time->iso_month(),
            date_time->iso_day()},
           {date_time->iso_hour(), date_time->iso_minute(),
            date_time->iso_second(), date_time->iso_millisecond(),
            date_time->iso_microsecond(), date_time->iso_nanosecond()}},
          iso_calendar,  // Unimportant due to ShowCalendar::kNever
          precision, ShowCalendar::kNever));
  builder.AppendString(date_time_string);

  // 8. If timeZone is undefined, then
  if (IsUndefined(*time_zone_obj)) {
    // a. Let timeZoneString be "Z".
    builder.AppendCharacter('Z');
  } else {
    // 9. Else,
    DCHECK(IsJSReceiver(*time_zone_obj));
    Handle<JSReceiver> time_zone = Cast<JSReceiver>(time_zone_obj);

    // a. Let offsetNs be ? GetOffsetNanosecondsFor(timeZone, instant).
    int64_t offset_ns;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, offset_ns,
        GetOffsetNanosecondsFor(isolate, time_zone, instant, method_name),
        Handle<String>());
    // b. Let timeZoneString be ! FormatISOTimeZoneOffsetString(offsetNs).
    DirectHandle<String> time_zone_string =
        FormatISOTimeZoneOffsetString(isolate, offset_ns);
    builder.AppendString(time_zone_string);
  }

  // 10. Return the string-concatenation of dateTimeString and timeZoneString.
  return indirect_handle(builder.Finish(), isolate);
}

}  // namespace

// #sec-temporal.instant.prototype.tojson
MaybeHandle<String> JSTemporalInstant::ToJSON(
    Isolate* isolate, Handle<JSTemporalInstant> instant) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let instant be the this value.
  // 2. Perform ? RequireInternalSlot(instant, [[InitializedTemporalInstant]]).
  // 3. Return ? TemporalInstantToString(instant, undefined, "auto").
  return TemporalInstantToString(
      isolate, instant, isolate->factory()->undefined_value(), Precision::kAuto,
      "Temporal.Instant.prototype.toJSON");
}

// #sec-temporal.instant.prototype.tolocalestring
MaybeHandle<String> JSTemporalInstant::ToLocaleString(
    Isolate* isolate, Handle<JSTemporalInstant> instant, Handle<Object> locales,
    Handle<Object> options) {
  const char* method_name = "Temporal.Instant.prototype.toLocaleString";
#ifdef V8_INTL_SUPPORT
  return JSDateTimeFormat::TemporalToLocaleString(isolate, instant, locales,
                                                  options, method_name);
#else   //  V8_INTL_SUPPORT
  return TemporalInstantToString(isolate, instant,
                                 isolate->factory()->undefined_value(),
                                 Precision::kAuto, method_name);
#endif  //  V8_INTL_SUPPORT
}

// #sec-temporal.instant.prototype.tostring
MaybeHandle<String> JSTemporalInstant::ToString(
    Isolate* isolate, DirectHandle<JSTemporalInstant> instant,
    Handle<Object> options_obj) {
  Factory* factory = isolate->factory();
  const char* method_name = "Temporal.Instant.prototype.toString";
  // 1. Let instant be the this value.
  // 2. Perform ? RequireInternalSlot(instant, [[InitializedTemporalInstant]]).
  // 3. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 4. Let timeZone be ? Get(options, "timeZone").
  Handle<Object> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      JSReceiver::GetProperty(isolate, options, factory->timeZone_string()));

  // 5. If timeZone is not undefined, then
  if (!IsUndefined(*time_zone)) {
    // a. Set timeZone to ? ToTemporalTimeZone(timeZone).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone,
        temporal::ToTemporalTimeZone(isolate, time_zone, method_name));
  }
  // 6. Let precision be ? ToSecondsStringPrecision(options).
  StringPrecision precision;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, precision,
      ToSecondsStringPrecision(isolate, options, method_name),
      Handle<String>());
  // 7. Let roundingMode be ? ToTemporalRoundingMode(options, "trunc").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, options, RoundingMode::kTrunc,
                             method_name),
      Handle<String>());
  // 8. Let roundedNs be ! RoundTemporalInstant(instant.[[Nanoseconds]],
  // precision.[[Increment]], precision.[[Unit]], roundingMode).
  DirectHandle<BigInt> rounded_ns =
      RoundTemporalInstant(isolate, handle(instant->nanoseconds(), isolate),
                           precision.increment, precision.unit, rounding_mode);

  // 9. Let roundedInstant be ! CreateTemporalInstant(roundedNs).
  Handle<JSTemporalInstant> rounded_instant =
      temporal::CreateTemporalInstant(isolate, rounded_ns).ToHandleChecked();

  // 10. Return ? TemporalInstantToString(roundedInstant, timeZone,
  // precision.[[Precision]]).
  return TemporalInstantToString(isolate, rounded_instant, time_zone,
                                 precision.precision,
                                 "Temporal.Instant.prototype.toString");
}

// #sec-temporal.instant.prototype.tozoneddatetimeiso
MaybeHandle<JSTemporalZonedDateTime> JSTemporalInstant::ToZonedDateTimeISO(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> item_obj) {
  TEMPORAL_ENTER_FUNC();
  Factory* factory = isolate->factory();
  // 1. Let instant be the this value.
  // 2. Perform ? RequireInternalSlot(instant, [[InitializedTemporalInstant]]).
  // 3. If Type(item) is Object, then
  if (IsJSReceiver(*item_obj)) {
    Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
    // a. Let timeZoneProperty be ? Get(item, "timeZone").
    Handle<Object> time_zone_property;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone_property,
        JSReceiver::GetProperty(isolate, item, factory->timeZone_string()));
    // b. If timeZoneProperty is not undefined, then
    if (!IsUndefined(*time_zone_property)) {
      // i. Set item to timeZoneProperty.
      item_obj = time_zone_property;
    }
  }
  // 4. Let timeZone be ? ToTemporalTimeZone(item).
  Handle<JSReceiver> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      temporal::ToTemporalTimeZone(
          isolate, item_obj, "Temporal.Instant.prototype.toZonedDateTimeISO"));
  // 5. Let calendar be ! GetISO8601Calendar().
  DirectHandle<JSTemporalCalendar> calendar =
      temporal::GetISO8601Calendar(isolate);
  // 6. Return ? CreateTemporalZonedDateTime(instant.[[Nanoseconds]], timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(
      isolate, Handle<BigInt>(handle->nanoseconds(), isolate), time_zone,
      calendar);
}

namespace {

// #sec-temporal-adddurationtoorsubtractdurationfrominstant
MaybeHandle<JSTemporalInstant> AddDurationToOrSubtractDurationFromInstant(
    Isolate* isolate, Arithmetic operation,
    DirectHandle<JSTemporalInstant> handle,
    Handle<Object> temporal_duration_like, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. If operation is subtract, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == Arithmetic::kSubtract ? -1.0 : 1.0;

  // See https://github.com/tc39/proposal-temporal/pull/2253
  // 2. Let duration be ? ToTemporalDurationRecord(temporalDurationLike).
  DurationRecord duration;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, duration,
      temporal::ToTemporalDurationRecord(isolate, temporal_duration_like,
                                         method_name),
      Handle<JSTemporalInstant>());

  TimeDurationRecord& time_duration = duration.time_duration;
  if (time_duration.days != 0 || duration.months != 0 || duration.weeks != 0 ||
      duration.years != 0) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Handle<JSTemporalInstant>());
  }

  // 3. Let ns be ? AddInstant(instant.[[EpochNanoseconds]], sign x
  // duration.[[Hours]], sign x duration.[[Minutes]], sign x
  // duration.[[Seconds]], sign x duration.[[Milliseconds]], sign x
  // duration.[[Microseconds]], sign x duration.[[Nanoseconds]]).
  Handle<BigInt> ns;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, ns,
      AddInstant(
          isolate, Handle<BigInt>(handle->nanoseconds(), isolate),
          {0, sign * time_duration.hours, sign * time_duration.minutes,
           sign * time_duration.seconds, sign * time_duration.milliseconds,
           sign * time_duration.microseconds,
           sign * time_duration.nanoseconds}));
  // 4. Return ! CreateTemporalInstant(ns).
  return temporal::CreateTemporalInstant(isolate, ns);
}

// #sec-temporal-negatetemporalroundingmode
RoundingMode NegateTemporalRoundingMode(RoundingMode rounding_mode) {
  switch (rounding_mode) {
    // 1. If roundingMode is "ceil", return "floor".
    case RoundingMode::kCeil:
      return RoundingMode::kFloor;
    // 2. If roundingMode is "floor", return "ceil".
    case RoundingMode::kFloor:
      return RoundingMode::kCeil;
    // 3. If roundingMode is "halfCeil", return "halfFloor".
    case RoundingMode::kHalfCeil:
      return RoundingMode::kHalfFloor;
    // 4. If roundingMode is "halfFloor", return "halfCeil".
    case RoundingMode::kHalfFloor:
      return RoundingMode::kHalfCeil;
    // 5. Return roundingMode.
    default:
      return rounding_mode;
  }
}

// #sec-temporal-getdifferencesettings
Maybe<DifferenceSettings> GetDifferenceSettings(
    Isolate* isolate, TimePreposition operation, Handle<Object> options,
    UnitGroup unit_group, DisallowedUnitsInDifferenceSettings disallowed_units,
    Unit fallback_smallest_unit, Unit smallest_largest_default_unit,
    const char* method_name) {
  DifferenceSettings record;
  // 1. Set options to ? GetOptionsObject(options).
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record.options, GetOptionsObject(isolate, options, method_name),
      Nothing<DifferenceSettings>());
  // 2. Let smallestUnit be ? GetTemporalUnit(options, "smallestUnit",
  // unitGroup, fallbackSmallestUnit).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record.smallest_unit,
      GetTemporalUnit(isolate, record.options, "smallestUnit", unit_group,
                      fallback_smallest_unit,
                      fallback_smallest_unit == Unit::kNotPresent, method_name),
      Nothing<DifferenceSettings>());
  // 3. If disallowedUnits contains smallestUnit, throw a RangeError exception.
  if (disallowed_units == DisallowedUnitsInDifferenceSettings::kWeekAndDay) {
    if (record.smallest_unit == Unit::kWeek) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kInvalidUnit,
                        isolate->factory()->smallestUnit_string(),
                        isolate->factory()->week_string()),
          Nothing<DifferenceSettings>());
    }
    if (record.smallest_unit == Unit::kDay) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kInvalidUnit,
                        isolate->factory()->smallestUnit_string(),
                        isolate->factory()->day_string()),
          Nothing<DifferenceSettings>());
    }
  }
  // 4. Let defaultLargestUnit be !
  // LargerOfTwoTemporalUnits(smallestLargestDefaultUnit, smallestUnit).
  Unit default_largest_unit = LargerOfTwoTemporalUnits(
      smallest_largest_default_unit, record.smallest_unit);
  // 5. Let largestUnit be ? GetTemporalUnit(options, "largestUnit", unitGroup,
  // "auto").
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record.largest_unit,
      GetTemporalUnit(isolate, record.options, "largestUnit", unit_group,
                      Unit::kAuto, false, method_name),
      Nothing<DifferenceSettings>());
  // 6. If disallowedUnits contains largestUnit, throw a RangeError exception.
  if (disallowed_units == DisallowedUnitsInDifferenceSettings::kWeekAndDay) {
    if (record.largest_unit == Unit::kWeek) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kInvalidUnit,
                        isolate->factory()->largestUnit_string(),
                        isolate->factory()->week_string()),
          Nothing<DifferenceSettings>());
    }
    if (record.largest_unit == Unit::kDay) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kInvalidUnit,
                        isolate->factory()->largestUnit_string(),
                        isolate->factory()->day_string()),
          Nothing<DifferenceSettings>());
    }
  }
  // 7. If largestUnit is "auto", set largestUnit to defaultLargestUnit.
  if (record.largest_unit == Unit::kAuto) {
    record.largest_unit = default_largest_unit;
  }
  // 8. If LargerOfTwoTemporalUnits(largestUnit, smallestUnit) is not
  // largestUnit, throw a RangeError exception.
  if (LargerOfTwoTemporalUnits(record.largest_unit, record.smallest_unit) !=
      record.largest_unit) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kInvalidArgumentForTemporal,
                      isolate->factory()->largestUnit_string()),
        Nothing<DifferenceSettings>());
  }
  // 9. Let roundingMode be ? ToTemporalRoundingMode(options, "trunc").
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record.rounding_mode,
      ToTemporalRoundingMode(isolate, record.options, RoundingMode::kTrunc,
                             method_name),
      Nothing<DifferenceSettings>());
  // 10. If operation is since, then
  if (operation == TimePreposition::kSince) {
    // a. Set roundingMode to ! NegateTemporalRoundingMode(roundingMode).
    record.rounding_mode = NegateTemporalRoundingMode(record.rounding_mode);
  }
  // 11. Let maximum be !
  // MaximumTemporalDurationRoundingIncrement(smallestUnit).
  Maximum maximum =
      MaximumTemporalDurationRoundingIncrement(record.smallest_unit);
  // 12. Let roundingIncrement be ? ToTemporalRoundingIncrement(options,
  // maximum, false).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record.rounding_increment,
      ToTemporalRoundingIncrement(isolate, record.options, maximum.value,
                                  maximum.defined, false),
      Nothing<DifferenceSettings>());
  // 13. Return the Record { [[SmallestUnit]]: smallestUnit, [[LargestUnit]]:
  // largestUnit, [[RoundingMode]]: roundingMode, [[RoundingIncrement]]:
  // roundingIncrement, [[Options]]: options }.
  return Just(record);
}

// #sec-temporal-differenceinstant
TimeDurationRecord DifferenceInstant(Isolate* isolate, Handle<BigInt> ns1,
                                     Handle<BigInt> ns2,
                                     double rounding_increment,
                                     Unit smallest_unit, Unit largest_unit,
                                     RoundingMode rounding_mode,
                                     const char* method_name) {
  // 1. Assert: Type(ns1) is BigInt.
  // 2. Assert: Type(ns2) is BigInt.
  // 3. Assert: The following step cannot fail due to overflow in the Number
  // domain because abs(ns2 - ns1) <= 2 x nsMaxInstant.

  // 4. Let roundResult be ! RoundDuration(0, 0, 0, 0, 0, 0, 0, 0, 0, ns2 - ns1,
  // roundingIncrement, smallestUnit, roundingMode).[[DurationRecord]].
  Handle<BigInt> diff = BigInt::Subtract(isolate, ns2, ns1).ToHandleChecked();
  // Note: Since diff could be very big and over the precision of double can
  // hold, break diff into diff_hours and diff_nanoseconds before pass into
  // RoundDuration.
  DirectHandle<BigInt> nanoseconds_in_a_hour =
      BigInt::FromUint64(isolate, 3600000000000);
  double diff_hours = Object::NumberValue(*BigInt::ToNumber(
      isolate,
      BigInt::Divide(isolate, diff, nanoseconds_in_a_hour).ToHandleChecked()));
  double diff_nanoseconds = Object::NumberValue(*BigInt::ToNumber(
      isolate, BigInt::Remainder(isolate, diff, nanoseconds_in_a_hour)
                   .ToHandleChecked()));
  DurationRecordWithRemainder round_record =
      RoundDuration(
          isolate, {0, 0, 0, {0, diff_hours, 0, 0, 0, 0, diff_nanoseconds}},
          rounding_increment, smallest_unit, rounding_mode, method_name)
          .ToChecked();
  // 5. Assert: roundResult.[[Days]] is 0.
  DCHECK_EQ(0, round_record.record.time_duration.days);
  // 6. Return ! BalanceDuration(0, roundResult.[[Hours]],
  // roundResult.[[Minutes]], roundResult.[[Seconds]],
  // roundResult.[[Milliseconds]], roundResult.[[Microseconds]],
  // roundResult.[[Nanoseconds]], largestUnit).
  return BalanceDuration(isolate, largest_unit,
                         isolate->factory()->undefined_value(),
                         round_record.record.time_duration, method_name)
      .ToChecked();
}

// #sec-temporal-differencetemporalinstant
MaybeHandle<JSTemporalDuration> DifferenceTemporalInstant(
    Isolate* isolate, TimePreposition operation,
    DirectHandle<JSTemporalInstant> instant, Handle<Object> other_obj,
    Handle<Object> options, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. If operation is since, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == TimePreposition::kSince ? -1 : 1;
  // 2. Set other to ? ToTemporalInstant(other).
  Handle<JSTemporalInstant> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other, ToTemporalInstant(isolate, other_obj, method_name));
  // 3. Let settings be ? GetDifferenceSettings(operation, options, time, « »,
  // "nanosecond", "second").
  DifferenceSettings settings;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, settings,
      GetDifferenceSettings(isolate, operation, options, UnitGroup::kTime,
                            DisallowedUnitsInDifferenceSettings::kNone,
                            Unit::kNanosecond, Unit::kSecond, method_name),
      Handle<JSTemporalDuration>());
  // 4. Let result be ! DifferenceInstant(instant.[[Nanoseconds]],
  // other.[[Nanoseconds]], settings.[[RoundingIncrement]],
  // settings.[[SmallestUnit]], settings.[[LargestUnit]],
  // settings.[[RoundingMode]]).
  TimeDurationRecord result = DifferenceInstant(
      isolate, handle(instant->nanoseconds(), isolate),
      handle(other->nanoseconds(), isolate), settings.rounding_increment,
      settings.smallest_unit, settings.largest_unit, settings.rounding_mode,
      method_name);
  // 5. Return ! CreateTemporalDuration(0, 0, 0, 0, sign × result.[[Hours]],
  // sign × result.[[Minutes]], sign × result.[[Seconds]], sign ×
  // result.[[Milliseconds]], sign × result.[[Microseconds]], sign ×
  // result.[[Nanoseconds]]).
  return CreateTemporalDuration(
             isolate, {0,
                       0,
                       0,
                       {0, sign * result.hours, sign * result.minutes,
                        sign * result.seconds, sign * result.milliseconds,
                        sign * result.microseconds, sign * result.nanoseconds}})
      .ToHandleChecked();
}
}  // namespace

// #sec-temporal.instant.prototype.add
MaybeHandle<JSTemporalInstant> JSTemporalInstant::Add(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> temporal_duration_like) {
  TEMPORAL_ENTER_FUNC();
  return AddDurationToOrSubtractDurationFromInstant(
      isolate, Arithmetic::kAdd, handle, temporal_duration_like,
      "Temporal.Instant.prototype.add");
}

// #sec-temporal.instant.prototype.subtract
MaybeHandle<JSTemporalInstant> JSTemporalInstant::Subtract(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> temporal_duration_like) {
  TEMPORAL_ENTER_FUNC();
  return AddDurationToOrSubtractDurationFromInstant(
      isolate, Arithmetic::kSubtract, handle, temporal_duration_like,
      "Temporal.Instant.prototype.subtract");
}

// #sec-temporal.instant.prototype.until
MaybeHandle<JSTemporalDuration> JSTemporalInstant::Until(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalInstant(isolate, TimePreposition::kUntil, handle,
                                   other, options,
                                   "Temporal.Instant.prototype.until");
}

// #sec-temporal.instant.prototype.since
MaybeHandle<JSTemporalDuration> JSTemporalInstant::Since(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalInstant(isolate, TimePreposition::kSince, handle,
                                   other, options,
                                   "Temporal.Instant.prototype.since");
}
namespace temporal {

// Step iii and iv of #sec-temporal.calendar.prototype.fields
MaybeHandle<Oddball> IsInvalidTemporalCalendarField(
    Isolate* isolate, Handle<String> next_value,
    DirectHandle<FixedArray> fields_name) {
  Factory* factory = isolate->factory();
  // iii. iii. If fieldNames contains nextValue, then
  for (int i = 0; i < fields_name->length(); i++) {
    Tagged<Object> item = fields_name->get(i);
    DCHECK(IsString(item));
    if (String::Equals(isolate, next_value,
                       handle(Cast<String>(item), isolate))) {
      return isolate->factory()->true_value();
    }
  }
  // iv. If nextValue is not one of "year", "month", "monthCode", "day", "hour",
  // "minute", "second", "millisecond", "microsecond", "nanosecond", then
  if (!(String::Equals(isolate, next_value, factory->year_string()) ||
        String::Equals(isolate, next_value, factory->month_string()) ||
        String::Equals(isolate, next_value, factory->monthCode_string()) ||
        String::Equals(isolate, next_value, factory->day_string()) ||
        String::Equals(isolate, next_value, factory->hour_string()) ||
        String::Equals(isolate, next_value, factory->minute_string()) ||
        String::Equals(isolate, next_value, factory->second_string()) ||
        String::Equals(isolate, next_value, factory->millisecond_string()) ||
        String::Equals(isolate, next_value, factory->microsecond_string()) ||
        String::Equals(isolate, next_value, factory->nanosecond_string()))) {
    return isolate->factory()->true_value();
  }
  return isolate->factory()->false_value();
}

// #sec-temporal-getbuiltincalendar
MaybeHandle<JSTemporalCalendar> GetBuiltinCalendar(Isolate* isolate,
                                                   Handle<String> id) {
  return JSTemporalCalendar::Constructor(isolate, CONSTRUCTOR(calendar),
                                         CONSTRUCTOR(calendar), id);
}

// A simple conviention function to avoid the need to unnecessarily exposing
// the definiation of enum Disambiguation.
MaybeHandle<JSTemporalInstant> BuiltinTimeZoneGetInstantForCompatible(
    Isolate* isolate, Handle<JSReceiver> time_zone,
    Handle<JSTemporalPlainDateTime> date_time, const char* method_name) {
  return BuiltinTimeZoneGetInstantFor(isolate, time_zone, date_time,
                                      Disambiguation::kCompatible, method_name);
}

}  // namespace temporal
}  // namespace v8::internal
```