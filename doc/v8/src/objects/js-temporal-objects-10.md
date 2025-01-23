Response: The user wants a summary of the C++ source code file `v8/src/objects/js-temporal-objects.cc`, specifically the functionality implemented in part 11 of 13. The summary should also highlight the relationship with JavaScript, providing examples.

Here's a breakdown of the code and how to summarize it:

1. **Identify the primary object:** The file name and surrounding code context suggest this part focuses on the `JSTemporalPlainTime` and `JSTemporalZonedDateTime` JavaScript objects, specifically their prototype methods.

2. **Analyze `JSTemporalPlainTime` methods:**
   - `ToPlainDateTime`:  Combines a `Temporal.PlainTime` with a `Temporal.PlainDate` to create a `Temporal.PlainDateTime`.
   - `Add`, `Subtract`:  Add or subtract a `Temporal.Duration` from a `Temporal.PlainTime`.
   - `Until`, `Since`:  Calculate the difference between two `Temporal.PlainTime` objects as a `Temporal.Duration`.
   - `GetISOFields`: Returns an object with the ISO components of the `Temporal.PlainTime`.
   - `ToJSON`:  Serializes the `Temporal.PlainTime` to a JSON string.
   - `ToLocaleString`: Formats the `Temporal.PlainTime` according to locale-specific conventions.
   - `ToString`:  Converts the `Temporal.PlainTime` to a string, allowing for rounding and precision options.

3. **Analyze helper functions for `JSTemporalPlainTime`:**
   -  The code includes functions for rounding time components (`RoundTime`, `RoundNumberToIncrement`, `RoundNumberToIncrementAsIfPositive`), managing rounding modes (`GetUnsignedRoundingMode`, `ApplyUnsignedRoundingMode`), and determining string precision (`ToSecondsStringPrecision`).

4. **Analyze `JSTemporalZonedDateTime` methods:**
   - `Constructor`:  Creates a new `Temporal.ZonedDateTime` object.
   - `HoursInDay`:  Calculates the number of hours in the day for a given `Temporal.ZonedDateTime`, accounting for possible DST transitions.
   - `From`: Creates a `Temporal.ZonedDateTime` from various input types.
   - `Compare`: Compares two `Temporal.ZonedDateTime` objects based on their epoch nanoseconds.
   - `Equals`:  Checks if two `Temporal.ZonedDateTime` objects are equal.
   - `With`: Creates a new `Temporal.ZonedDateTime` by modifying specific components of an existing one.

5. **Analyze helper functions for `JSTemporalZonedDateTime`:**
   - `ToTemporalZonedDateTime`:  Converts various input types to a `Temporal.ZonedDateTime`.
   - `TimeZoneEquals`: Checks if two time zone objects are equivalent.
   - `InterpretISODateTimeOffset`: A core function to interpret ISO date/time components along with an offset, taking into account time zones and disambiguation rules.

6. **Identify connections to JavaScript:** The function names directly correspond to methods available on the `Temporal.PlainTime` and `Temporal.ZonedDateTime` objects in JavaScript. The parameters and return types align with the JavaScript API.

7. **Formulate the summary:** Combine the analysis points into a concise description of the file's functionality, emphasizing the implementation of the prototype methods and related helper functions for the two Temporal objects. Use JavaScript examples to illustrate how these C++ functions are used in the JavaScript API.

8. **Address the "part 11 of 13" aspect:** Acknowledge that this is a specific part of a larger implementation and that it builds upon concepts likely defined in earlier parts.
这个C++源代码文件（`v8/src/objects/js-temporal-objects.cc`）是V8 JavaScript引擎中用于实现ECMAScript Temporal API的一部分，**主要负责实现 `Temporal.PlainTime` 和 `Temporal.ZonedDateTime` 两个JavaScript对象的原型方法以及相关的辅助功能**。 作为第11部分，它很可能延续了之前部分定义的基础结构和辅助函数，专注于实现这两个对象更复杂的操作。

具体来说，这部分代码实现了以下`Temporal.PlainTime` 的原型方法：

* **`toPlainDateTime`**:  将 `Temporal.PlainTime` 对象与另一个表示日期的对象组合成一个新的 `Temporal.PlainDateTime` 对象。
* **`add`**:  向 `Temporal.PlainTime` 对象添加一个 `Temporal.Duration` 对象。
* **`subtract`**:  从 `Temporal.PlainTime` 对象减去一个 `Temporal.Duration` 对象。
* **`until`**:  计算当前 `Temporal.PlainTime` 对象到另一个 `Temporal.PlainTime` 对象之间的时间差，返回一个 `Temporal.Duration` 对象。
* **`since`**:  计算另一个 `Temporal.PlainTime` 对象到当前 `Temporal.PlainTime` 对象之间的时间差，返回一个 `Temporal.Duration` 对象。
* **`getISOFields`**:  返回一个包含当前 `Temporal.PlainTime` 对象的 ISO 属性（`isoHour`, `isoMinute`, `isoSecond` 等）的对象。
* **`toJSON`**:  将 `Temporal.PlainTime` 对象转换为 JSON 字符串表示。
* **`toLocaleString`**:  根据指定的区域设置将 `Temporal.PlainTime` 对象格式化为本地化字符串。
* **`toString`**:  将 `Temporal.PlainTime` 对象转换为字符串表示，可以控制精度。

此外，这部分代码还实现了 `Temporal.ZonedDateTime` 的以下功能：

* **构造函数 (`Constructor`)**: 用于创建 `Temporal.ZonedDateTime` 对象。
* **`hoursInDay`**:  返回 `Temporal.ZonedDateTime` 所在日期的小时数，考虑到可能的夏令时调整。
* **`from`**:  一个静态方法，尝试从各种输入类型创建一个 `Temporal.ZonedDateTime` 对象。
* **`compare`**:  一个静态方法，比较两个 `Temporal.ZonedDateTime` 对象，返回一个表示大小关系的数字。
* **`equals`**:  判断当前 `Temporal.ZonedDateTime` 对象是否与另一个对象相等。
* **`with`**:  创建一个新的 `Temporal.ZonedDateTime` 对象，该对象是当前对象的副本，但某些属性已被修改。

**与 JavaScript 功能的关系及示例:**

这些 C++ 代码直接对应了 JavaScript 中 `Temporal.PlainTime` 和 `Temporal.ZonedDateTime` 对象的方法。V8 引擎负责执行 JavaScript 代码，当调用这些 Temporal API 的方法时，最终会调用到这些 C++ 代码进行实际的操作。

**`Temporal.PlainTime` 示例:**

```javascript
const plainTime = new Temporal.PlainTime(10, 30, 0);
const duration = new Temporal.Duration(1, 30, 0);
const laterTime = plainTime.add(duration);
console.log(laterTime.toString()); // 输出类似 "12:00:00"

const anotherTime = new Temporal.PlainTime(11, 0, 0);
const difference = plainTime.until(anotherTime);
console.log(difference.toString()); // 输出类似 "PT0H30M"

const isoFields = plainTime.getISOFields();
console.log(isoFields); // 输出类似 { calendar: 'iso8601', isoHour: 10, isoMicrosecond: 0, isoMillisecond: 0, isoMinute: 30, isoNanosecond: 0, isoSecond: 0 }
```

在 JavaScript 中调用 `plainTime.add(duration)` 时，V8 引擎会执行 `JSTemporalPlainTime::Add` 这个 C++ 函数，该函数会调用 `AddTime` 等辅助函数来完成时间的加法运算。

**`Temporal.ZonedDateTime` 示例:**

```javascript
const zonedDateTime = new Temporal.ZonedDateTime(BigInt(1678886400000000000), 'UTC');
const laterZonedDateTime = zonedDateTime.with({ hour: 12 });
console.log(laterZonedDateTime.toString()); // 输出类似 "2023-03-15T00:00:00+00:00[UTC]" (假设原始时间是 2023-03-15T00:00:00Z)

const anotherZonedDateTime = Temporal.ZonedDateTime.from('2023-03-15T10:00:00+08:00[Asia/Shanghai]');
const comparisonResult = zonedDateTime.compare(anotherZonedDateTime);
console.log(comparisonResult); // 输出 -1 或 1，取决于时间先后顺序

const hours = zonedDateTime.hoursInDay;
console.log(hours); // 输出 24
```

在 JavaScript 中调用 `zonedDateTime.hoursInDay` 时，V8 引擎会执行 `JSTemporalZonedDateTime::HoursInDay` 这个 C++ 函数，该函数会根据时区信息计算当天的实际小时数。

**总结:**

作为 Temporal API 实现的第11部分，这个 C++ 文件深入实现了 `Temporal.PlainTime` 和 `Temporal.ZonedDateTime` 的核心原型方法，包括时间运算、比较、格式化、属性获取以及对象创建和修改等功能。 这些 C++ 代码是 V8 引擎执行相应 JavaScript 代码的底层实现，保证了 Temporal API 在 JavaScript 中的正确运行。 这部分代码依赖于之前部分定义的 Temporal API 的基础结构和辅助工具函数，并为后续部分构建更高级的功能奠定了基础。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第11部分，共13部分，请归纳一下它的功能
```

### 源代码
```
t<JSTemporalPlainTime>(item_obj);
    return CreateTemporalTime(
        isolate, {item->iso_hour(), item->iso_minute(), item->iso_second(),
                  item->iso_millisecond(), item->iso_microsecond(),
                  item->iso_nanosecond()});
  }
  // 4. Return ? ToTemporalTime(item, overflow).
  return temporal::ToTemporalTime(isolate, item_obj, method_name, overflow);
}

// #sec-temporal.plaintime.prototype.toplaindatetime
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainTime::ToPlainDateTime(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> temporal_date_like) {
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalTime,
  // [[InitializedTemporalTime]]).
  // 3. Set temporalDate to ? ToTemporalDate(temporalDate).
  Handle<JSTemporalPlainDate> temporal_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date,
      ToTemporalDate(isolate, temporal_date_like,
                     "Temporal.PlainTime.prototype.toPlainDateTime"));
  // 4. Return ? CreateTemporalDateTime(temporalDate.[[ISOYear]],
  // temporalDate.[[ISOMonth]], temporalDate.[[ISODay]],
  // temporalTime.[[ISOHour]], temporalTime.[[ISOMinute]],
  // temporalTime.[[ISOSecond]], temporalTime.[[ISOMillisecond]],
  // temporalTime.[[ISOMicrosecond]], temporalTime.[[ISONanosecond]],
  // temporalDate.[[Calendar]]).
  return temporal::CreateTemporalDateTime(
      isolate,
      {{temporal_date->iso_year(), temporal_date->iso_month(),
        temporal_date->iso_day()},
       {temporal_time->iso_hour(), temporal_time->iso_minute(),
        temporal_time->iso_second(), temporal_time->iso_millisecond(),
        temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()}},
      handle(temporal_date->calendar(), isolate));
}

namespace {

// #sec-temporal-adddurationtoorsubtractdurationfromplaintime
MaybeHandle<JSTemporalPlainTime> AddDurationToOrSubtractDurationFromPlainTime(
    Isolate* isolate, Arithmetic operation,
    DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> temporal_duration_like, const char* method_name) {
  // 1. If operation is subtract, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == Arithmetic::kSubtract ? -1.0 : 1.0;
  // 2. Let duration be ? ToTemporalDurationRecord(temporalDurationLike).
  DurationRecord duration;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, duration,
      temporal::ToTemporalDurationRecord(isolate, temporal_duration_like,
                                         method_name),
      Handle<JSTemporalPlainTime>());
  TimeDurationRecord& time_duration = duration.time_duration;

  // 3. Let result be ! AddTime(temporalTime.[[ISOHour]],
  // temporalTime.[[ISOMinute]], temporalTime.[[ISOSecond]],
  // temporalTime.[[ISOMillisecond]], temporalTime.[[ISOMicrosecond]],
  // temporalTime.[[ISONanosecond]], sign x duration.[[Hours]], sign x
  // duration.[[Minutes]], sign x duration.[[Seconds]], sign x
  // duration.[[Milliseconds]], sign x duration.[[Microseconds]], sign x
  // duration.[[Nanoseconds]]).
  DateTimeRecord result = AddTime(
      isolate,
      {temporal_time->iso_hour(), temporal_time->iso_minute(),
       temporal_time->iso_second(), temporal_time->iso_millisecond(),
       temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()},
      {0, sign * time_duration.hours, sign * time_duration.minutes,
       sign * time_duration.seconds, sign * time_duration.milliseconds,
       sign * time_duration.microseconds, sign * time_duration.nanoseconds});
  // 4. Assert: ! IsValidTime(result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]]) is true.
  DCHECK(IsValidTime(isolate, result.time));
  // 5. Return ? CreateTemporalTime(result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]]).
  return CreateTemporalTime(isolate, result.time);
}

}  // namespace

// #sec-temporal.plaintime.prototype.add
MaybeHandle<JSTemporalPlainTime> JSTemporalPlainTime::Add(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> temporal_duration_like) {
  return AddDurationToOrSubtractDurationFromPlainTime(
      isolate, Arithmetic::kAdd, temporal_time, temporal_duration_like,
      "Temporal.PlainTime.prototype.add");
}

// #sec-temporal.plaintime.prototype.subtract
MaybeHandle<JSTemporalPlainTime> JSTemporalPlainTime::Subtract(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> temporal_duration_like) {
  return AddDurationToOrSubtractDurationFromPlainTime(
      isolate, Arithmetic::kSubtract, temporal_time, temporal_duration_like,
      "Temporal.PlainTime.prototype.subtract");
}

namespace {
// #sec-temporal-differencetemporalplantime
MaybeHandle<JSTemporalDuration> DifferenceTemporalPlainTime(
    Isolate* isolate, TimePreposition operation,
    DirectHandle<JSTemporalPlainTime> temporal_time, Handle<Object> other_obj,
    Handle<Object> options, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. If operation is since, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == TimePreposition::kSince ? -1 : 1;
  // 2. Set other to ? ToTemporalDate(other).
  Handle<JSTemporalPlainTime> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other,
      temporal::ToTemporalTime(isolate, other_obj, method_name));

  // 3. Let settings be ? GetDifferenceSettings(operation, options, time, « »,
  // "nanosecond", "hour").
  DifferenceSettings settings;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, settings,
      GetDifferenceSettings(isolate, operation, options, UnitGroup::kTime,
                            DisallowedUnitsInDifferenceSettings::kNone,
                            Unit::kNanosecond, Unit::kHour, method_name),
      Handle<JSTemporalDuration>());
  // 4. Let result be ! DifferenceTime(temporalTime.[[ISOHour]],
  // temporalTime.[[ISOMinute]], temporalTime.[[ISOSecond]],
  // temporalTime.[[ISOMillisecond]], temporalTime.[[ISOMicrosecond]],
  // temporalTime.[[ISONanosecond]], other.[[ISOHour]], other.[[ISOMinute]],
  // other.[[ISOSecond]], other.[[ISOMillisecond]], other.[[ISOMicrosecond]],
  // other.[[ISONanosecond]]).
  DurationRecordWithRemainder result;
  result.record.time_duration =
      DifferenceTime(
          isolate,
          {temporal_time->iso_hour(), temporal_time->iso_minute(),
           temporal_time->iso_second(), temporal_time->iso_millisecond(),
           temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()},
          {other->iso_hour(), other->iso_minute(), other->iso_second(),
           other->iso_millisecond(), other->iso_microsecond(),
           other->iso_nanosecond()})
          .ToChecked();
  // 5. Set result to (! RoundDuration(0, 0, 0, 0, result.[[Hours]],
  // result.[[Minutes]], result.[[Seconds]], result.[[Milliseconds]],
  // result.[[Microseconds]], result.[[Nanoseconds]],
  // settings.[[RoundingIncrement]], settings.[[SmallestUnit]],
  // settings.[[RoundingMode]])).[[DurationRecord]].
  result.record.years = result.record.months = result.record.weeks =
      result.record.time_duration.days = 0;
  result =
      RoundDuration(isolate, result.record, settings.rounding_increment,
                    settings.smallest_unit, settings.rounding_mode, method_name)
          .ToChecked();
  // 6. Set result to ! BalanceDuration(0, result.[[Hours]], result.[[Minutes]],
  // result.[[Seconds]], result.[[Milliseconds]], result.[[Microseconds]],
  // result.[[Nanoseconds]], settings.[[LargestUnit]]).
  result.record.time_duration.days = 0;
  result.record.time_duration =
      BalanceDuration(isolate, settings.largest_unit,
                      result.record.time_duration, method_name)
          .ToChecked();

  // 7. Return ! CreateTemporalDuration(0, 0, 0, 0, sign × result.[[Hours]],
  // sign × result.[[Minutes]], sign × result.[[Seconds]], sign ×
  // result.[[Milliseconds]], sign × result.[[Microseconds]], sign ×
  // result.[[Nanoseconds]]).
  result.record.years = result.record.months = result.record.weeks =
      result.record.time_duration.days = 0;
  result.record.time_duration.hours *= sign;
  result.record.time_duration.minutes *= sign;
  result.record.time_duration.seconds *= sign;
  result.record.time_duration.milliseconds *= sign;
  result.record.time_duration.microseconds *= sign;
  result.record.time_duration.nanoseconds *= sign;
  return CreateTemporalDuration(isolate, result.record).ToHandleChecked();
}

}  // namespace

// #sec-temporal.plaintime.prototype.until
MaybeHandle<JSTemporalDuration> JSTemporalPlainTime::Until(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalPlainTime(isolate, TimePreposition::kUntil, handle,
                                     other, options,
                                     "Temporal.PlainTime.prototype.until");
}

// #sec-temporal.plaintime.prototype.since
MaybeHandle<JSTemporalDuration> JSTemporalPlainTime::Since(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalPlainTime(isolate, TimePreposition::kSince, handle,
                                     other, options,
                                     "Temporal.PlainTime.prototype.since");
}

// #sec-temporal.plaintime.prototype.getisofields
MaybeHandle<JSReceiver> JSTemporalPlainTime::GetISOFields(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time) {
  Factory* factory = isolate->factory();
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalTime,
  // [[InitializedTemporalTime]]).
  // 3. Let fields be ! OrdinaryObjectCreate(%Object.prototype%).
  Handle<JSObject> fields =
      isolate->factory()->NewJSObject(isolate->object_function());
  // 4. Perform ! CreateDataPropertyOrThrow(fields, "calendar",
  // temporalTime.[[Calendar]]).
  Handle<JSTemporalCalendar> iso8601_calendar =
      temporal::GetISO8601Calendar(isolate);
  CHECK(JSReceiver::CreateDataProperty(isolate, fields,
                                       factory->calendar_string(),
                                       iso8601_calendar, Just(kThrowOnError))
            .FromJust());

  // 5. Perform ! CreateDataPropertyOrThrow(fields, "isoHour",
  // 𝔽(temporalTime.[[ISOHour]])).
  // 6. Perform ! CreateDataPropertyOrThrow(fields, "isoMicrosecond",
  // 𝔽(temporalTime.[[ISOMicrosecond]])).
  // 7. Perform ! CreateDataPropertyOrThrow(fields, "isoMillisecond",
  // 𝔽(temporalTime.[[ISOMillisecond]])).
  // 8. Perform ! CreateDataPropertyOrThrow(fields, "isoMinute",
  // 𝔽(temporalTime.[[ISOMinute]])).
  // 9. Perform ! CreateDataPropertyOrThrow(fields, "isoNanosecond",
  // 𝔽(temporalTime.[[ISONanosecond]])).
  // 10. Perform ! CreateDataPropertyOrThrow(fields, "isoSecond",
  // 𝔽(temporalTime.[[ISOSecond]])).
  DEFINE_INT_FIELD(fields, isoHour, iso_hour, temporal_time)
  DEFINE_INT_FIELD(fields, isoMicrosecond, iso_microsecond, temporal_time)
  DEFINE_INT_FIELD(fields, isoMillisecond, iso_millisecond, temporal_time)
  DEFINE_INT_FIELD(fields, isoMinute, iso_minute, temporal_time)
  DEFINE_INT_FIELD(fields, isoNanosecond, iso_nanosecond, temporal_time)
  DEFINE_INT_FIELD(fields, isoSecond, iso_second, temporal_time)
  // 11. Return fields.
  return fields;
}

// #sec-temporal.plaintime.prototype.tojson
MaybeHandle<String> JSTemporalPlainTime::ToJSON(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time) {
  return TemporalTimeToString(isolate, temporal_time, Precision::kAuto);
}

// #sup-temporal.plaintime.prototype.tolocalestring
MaybeHandle<String> JSTemporalPlainTime::ToLocaleString(
    Isolate* isolate, Handle<JSTemporalPlainTime> temporal_time,
    Handle<Object> locales, Handle<Object> options) {
#ifdef V8_INTL_SUPPORT
  return JSDateTimeFormat::TemporalToLocaleString(
      isolate, temporal_time, locales, options,
      "Temporal.PlainTime.prototype.toLocaleString");
#else   //  V8_INTL_SUPPORT
  return TemporalTimeToString(isolate, temporal_time, Precision::kAuto);
#endif  //  V8_INTL_SUPPORT
}

namespace {

// #sec-temporal-getunsignedroundingmode
UnsignedRoundingMode GetUnsignedRoundingMode(RoundingMode rounding_mode,
                                             bool is_negative) {
  // 1. If isNegative is true, return the specification type in the third column
  // of Table 14 where the first column is roundingMode and the second column is
  // "negative".
  if (is_negative) {
    switch (rounding_mode) {
      case RoundingMode::kCeil:
        return UnsignedRoundingMode::kZero;
      case RoundingMode::kFloor:
        return UnsignedRoundingMode::kInfinity;
      case RoundingMode::kExpand:
        return UnsignedRoundingMode::kInfinity;
      case RoundingMode::kTrunc:
        return UnsignedRoundingMode::kZero;
      case RoundingMode::kHalfCeil:
        return UnsignedRoundingMode::kHalfZero;
      case RoundingMode::kHalfFloor:
        return UnsignedRoundingMode::kHalfInfinity;
      case RoundingMode::kHalfExpand:
        return UnsignedRoundingMode::kHalfInfinity;
      case RoundingMode::kHalfTrunc:
        return UnsignedRoundingMode::kHalfZero;
      case RoundingMode::kHalfEven:
        return UnsignedRoundingMode::kHalfEven;
    }
  }
  // 2. Else, return the specification type in the third column of Table 14
  // where the first column is roundingMode and the second column is "positive".
  switch (rounding_mode) {
    case RoundingMode::kCeil:
      return UnsignedRoundingMode::kInfinity;
    case RoundingMode::kFloor:
      return UnsignedRoundingMode::kZero;
    case RoundingMode::kExpand:
      return UnsignedRoundingMode::kInfinity;
    case RoundingMode::kTrunc:
      return UnsignedRoundingMode::kZero;
    case RoundingMode::kHalfCeil:
      return UnsignedRoundingMode::kHalfInfinity;
    case RoundingMode::kHalfFloor:
      return UnsignedRoundingMode::kHalfZero;
    case RoundingMode::kHalfExpand:
      return UnsignedRoundingMode::kHalfInfinity;
    case RoundingMode::kHalfTrunc:
      return UnsignedRoundingMode::kHalfZero;
    case RoundingMode::kHalfEven:
      return UnsignedRoundingMode::kHalfEven;
  }
}

// #sec-temporal-applyunsignedroundingmode
double ApplyUnsignedRoundingMode(double x, double r1, double r2,
                                 UnsignedRoundingMode unsigned_rounding_mode) {
  // 1. If x is equal to r1, return r1.
  if (x == r1) return r1;
  // 2. Assert: r1 < x < r2.
  DCHECK_LT(r1, x);
  DCHECK_LT(x, r2);
  // 3. Assert: unsignedRoundingMode is not undefined.
  // 4. If unsignedRoundingMode is zero, return r1.
  if (unsigned_rounding_mode == UnsignedRoundingMode::kZero) return r1;
  // 5. If unsignedRoundingMode is infinity, return r2.
  if (unsigned_rounding_mode == UnsignedRoundingMode::kInfinity) return r2;
  // 6. Let d1 be x – r1.
  double d1 = x - r1;
  // 7. Let d2 be r2 – x.
  double d2 = r2 - x;
  // 8. If d1 < d2, return r1.
  if (d1 < d2) return r1;
  // 9. If d2 < d1, return r2.
  if (d2 < d1) return r2;
  // 10. Assert: d1 is equal to d2.
  DCHECK_EQ(d1, d2);
  // 11. If unsignedRoundingMode is half-zero, return r1.
  if (unsigned_rounding_mode == UnsignedRoundingMode::kHalfZero) return r1;
  // 12. If unsignedRoundingMode is half-infinity, return r2.
  if (unsigned_rounding_mode == UnsignedRoundingMode::kHalfInfinity) return r2;
  // 13. Assert: unsignedRoundingMode is half-even.
  DCHECK_EQ(unsigned_rounding_mode, UnsignedRoundingMode::kHalfEven);
  // 14. Let cardinality be (r1 / (r2 – r1)) modulo 2.
  int64_t cardinality = static_cast<int64_t>(r1) % 2;
  // 15. If cardinality is 0, return r1.
  if (cardinality == 0) return r1;
  // 16. Return r2.
  return r2;
}

// #sec-temporal-applyunsignedroundingmode
Handle<BigInt> ApplyUnsignedRoundingMode(
    Isolate* isolate, Handle<BigInt> num, Handle<BigInt> increment,
    Handle<BigInt> r1, Handle<BigInt> r2,
    UnsignedRoundingMode unsigned_rounding_mode) {
  // 1. If x is equal to r1, return r1.
  Handle<BigInt> rr1 =
      BigInt::Multiply(isolate, increment, r1).ToHandleChecked();
  Handle<BigInt> rr2 =
      BigInt::Multiply(isolate, increment, r2).ToHandleChecked();
  if (BigInt::EqualToBigInt(*num, *rr1)) return r1;
  // 2. Assert: r1 < x < r2.
  DCHECK_EQ(BigInt::CompareToBigInt(rr1, num), ComparisonResult::kLessThan);
  DCHECK_EQ(BigInt::CompareToBigInt(num, rr2), ComparisonResult::kLessThan);
  // 3. Assert: unsignedRoundingMode is not undefined.
  // 4. If unsignedRoundingMode is zero, return r1.
  if (unsigned_rounding_mode == UnsignedRoundingMode::kZero) return r1;
  // 5. If unsignedRoundingMode is infinity, return r2.
  if (unsigned_rounding_mode == UnsignedRoundingMode::kInfinity) return r2;
  // 6. Let d1 be x – r1.
  DirectHandle<BigInt> dd1 =
      BigInt::Subtract(isolate, num, rr1).ToHandleChecked();
  // 7. Let d2 be r2 – x.
  DirectHandle<BigInt> dd2 =
      BigInt::Subtract(isolate, rr2, num).ToHandleChecked();
  // 8. If d1 < d2, return r1.
  if (BigInt::CompareToBigInt(dd1, dd2) == ComparisonResult::kLessThan) {
    return r1;
  }
  // 9. If d2 < d1, return r2.
  if (BigInt::CompareToBigInt(dd2, dd1) == ComparisonResult::kLessThan) {
    return r2;
  }
  // 10. Assert: d1 is equal to d2.
  DCHECK_EQ(BigInt::CompareToBigInt(dd1, dd2), ComparisonResult::kEqual);
  // 11. If unsignedRoundingMode is half-zero, return r1.
  if (unsigned_rounding_mode == UnsignedRoundingMode::kHalfZero) return r1;
  // 12. If unsignedRoundingMode is half-infinity, return r2.
  if (unsigned_rounding_mode == UnsignedRoundingMode::kHalfInfinity) return r2;
  // 13. Assert: unsignedRoundingMode is half-even.
  DCHECK_EQ(unsigned_rounding_mode, UnsignedRoundingMode::kHalfEven);
  // 14. Let cardinality be (r1 / (r2 – r1)) modulo 2.
  DirectHandle<BigInt> cardinality =
      BigInt::Remainder(isolate, r1, BigInt::FromInt64(isolate, 2))
          .ToHandleChecked();
  // 15. If cardinality is 0, return r1.
  if (!cardinality->ToBoolean()) return r1;
  // 16. Return r2.
  return r2;
}

// #sec-temporal-roundnumbertoincrement
// For the case that x is double.
double RoundNumberToIncrement(Isolate* isolate, double x, double increment,
                              RoundingMode rounding_mode) {
  TEMPORAL_ENTER_FUNC();

  // 1. Let quotient be x / increment.
  double quotient = x / increment;
  bool is_negative;
  // 2. If quotient < 0, then
  if (quotient < 0) {
    // a. Let isNegative be true.
    is_negative = true;
    // b. Set quotient to -quotient.
    quotient = -quotient;
    // 3. Else,
  } else {
    // a. Let isNegative be false.
    is_negative = false;
  }
  // 4. Let unsignedRoundingMode be GetUnsignedRoundingMode(roundingMode,
  // isNegative).
  UnsignedRoundingMode unsigned_rounding_mode =
      GetUnsignedRoundingMode(rounding_mode, is_negative);

  // 5. Let r1 be the largest integer such that r1 ≤ quotient.
  double r1 = std::floor(quotient);
  // 6. Let r2 be the smallest integer such that r2 > quotient.
  double r2 = std::floor(quotient + 1);
  // 7. Let rounded be ApplyUnsignedRoundingMode(quotient, r1, r2,
  // unsignedRoundingMode).
  double rounded =
      ApplyUnsignedRoundingMode(quotient, r1, r2, unsigned_rounding_mode);
  // 8. If isNegative is true, set rounded to -rounded.
  if (is_negative) {
    rounded = -rounded;
  }
  // 9. Return rounded × increment.
  return rounded * increment;
}

// #sec-temporal-roundnumbertoincrementasifpositive
Handle<BigInt> RoundNumberToIncrementAsIfPositive(Isolate* isolate,
                                                  Handle<BigInt> x,
                                                  double increment,
                                                  RoundingMode rounding_mode) {
  TEMPORAL_ENTER_FUNC();

  // 1. Let quotient be x / increment.
  // 2. Let unsignedRoundingMode be GetUnsignedRoundingMode(roundingMode,
  // false).
  UnsignedRoundingMode unsigned_rounding_mode =
      GetUnsignedRoundingMode(rounding_mode, false);

  Handle<BigInt> increment_bigint =
      BigInt::FromNumber(isolate, isolate->factory()->NewNumber(increment))
          .ToHandleChecked();
  // 3. Let r1 be the largest integer such that r1 ≤ quotient.
  Handle<BigInt> r1 =
      BigInt::Divide(isolate, x, increment_bigint).ToHandleChecked();

  // Adjust for negative quotient.
  if (r1->IsNegative() && BigInt::Remainder(isolate, x, increment_bigint)
                              .ToHandleChecked()
                              ->ToBoolean()) {
    r1 = BigInt::Decrement(isolate, r1).ToHandleChecked();
  }

  // 4. Let r2 be the smallest integer such that r2 > quotient.
  Handle<BigInt> r2 = BigInt::Increment(isolate, r1).ToHandleChecked();
  // 5. Let rounded be ApplyUnsignedRoundingMode(quotient, r1, r2,
  // unsignedRoundingMode).
  Handle<BigInt> rounded = ApplyUnsignedRoundingMode(
      isolate, x, increment_bigint, r1, r2, unsigned_rounding_mode);
  // 6. Return rounded × increment.
  Handle<BigInt> result =
      BigInt::Multiply(isolate, rounded, increment_bigint).ToHandleChecked();
  return result;
}

DateTimeRecord RoundTime(Isolate* isolate, const TimeRecord& time,
                         double increment, Unit unit,
                         RoundingMode rounding_mode, double day_length_ns) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: hour, minute, second, millisecond, microsecond, nanosecond, and
  // increment are integers.
  // 2. Let fractionalSecond be nanosecond × 10^−9 + microsecond × 10^−6 +
  // millisecond × 10−3 + second.
  double fractional_second =
      static_cast<double>(time.nanosecond) / 100000000.0 +
      static_cast<double>(time.microsecond) / 1000000.0 +
      static_cast<double>(time.millisecond) / 1000.0 +
      static_cast<double>(time.second);
  double quantity;
  switch (unit) {
    // 3. If unit is "day", then
    case Unit::kDay:
      // a. If dayLengthNs is not present, set it to 8.64 × 10^13.
      // b. Let quantity be (((((hour × 60 + minute) × 60 + second) × 1000 +
      // millisecond) × 1000 + microsecond) × 1000 + nanosecond) / dayLengthNs.
      quantity =
          (((((time.hour * 60.0 + time.minute) * 60.0 + time.second) * 1000.0 +
             time.millisecond) *
                1000.0 +
            time.microsecond) *
               1000.0 +
           time.nanosecond) /
          day_length_ns;
      break;
    // 4. Else if unit is "hour", then
    case Unit::kHour:
      // a. Let quantity be (fractionalSecond / 60 + minute) / 60 + hour.
      quantity = (fractional_second / 60.0 + time.minute) / 60.0 + time.hour;
      break;
    // 5. Else if unit is "minute", then
    case Unit::kMinute:
      // a. Let quantity be fractionalSecond / 60 + minute.
      quantity = fractional_second / 60.0 + time.minute;
      break;
    // 6. Else if unit is "second", then
    case Unit::kSecond:
      // a. Let quantity be fractionalSecond.
      quantity = fractional_second;
      break;
    // 7. Else if unit is "millisecond", then
    case Unit::kMillisecond:
      // a. Let quantity be nanosecond × 10^−6 + microsecond × 10^−3 +
      // millisecond.
      quantity = time.nanosecond / 1000000.0 + time.microsecond / 1000.0 +
                 time.millisecond;
      break;
    // 8. Else if unit is "microsecond", then
    case Unit::kMicrosecond:
      // a. Let quantity be nanosecond × 10^−3 + microsecond.
      quantity = time.nanosecond / 1000.0 + time.microsecond;
      break;
    // 9. Else,
    default:
      // a. Assert: unit is "nanosecond".
      DCHECK_EQ(unit, Unit::kNanosecond);
      // b. Let quantity be nanosecond.
      quantity = time.nanosecond;
      break;
  }
  // 10. Let result be ! RoundNumberToIncrement(quantity, increment,
  // roundingMode).
  int32_t result =
      RoundNumberToIncrement(isolate, quantity, increment, rounding_mode);

  switch (unit) {
    // 11. If unit is "day", then
    case Unit::kDay:
      // a. Return the Record { [[Days]]: result, [[Hour]]: 0, [[Minute]]: 0,
      // [[Second]]: 0, [[Millisecond]]: 0, [[Microsecond]]: 0, [[Nanosecond]]:
      // 0 }.
      return {{0, 0, result}, {0, 0, 0, 0, 0, 0}};
    // 12. If unit is "hour", then
    case Unit::kHour:
      // a. Return ! BalanceTime(result, 0, 0, 0, 0, 0).
      return BalanceTime({static_cast<double>(result), 0, 0, 0, 0, 0});
    // 13. If unit is "minute", then
    case Unit::kMinute:
      // a. Return ! BalanceTime(hour, result, 0, 0, 0, 0).
      return BalanceTime({static_cast<double>(time.hour),
                          static_cast<double>(result), 0, 0, 0, 0});
    // 14. If unit is "second", then
    case Unit::kSecond:
      // a. Return ! BalanceTime(hour, minute, result, 0, 0, 0).
      return BalanceTime({static_cast<double>(time.hour),
                          static_cast<double>(time.minute),
                          static_cast<double>(result), 0, 0, 0});
    // 15. If unit is "millisecond", then
    case Unit::kMillisecond:
      // a. Return ! BalanceTime(hour, minute, second, result, 0, 0).
      return BalanceTime({static_cast<double>(time.hour),
                          static_cast<double>(time.minute),
                          static_cast<double>(time.second),
                          static_cast<double>(result), 0, 0});
    // 16. If unit is "microsecond", then
    case Unit::kMicrosecond:
      // a. Return ! BalanceTime(hour, minute, second, millisecond, result, 0).
      return BalanceTime({static_cast<double>(time.hour),
                          static_cast<double>(time.minute),
                          static_cast<double>(time.second),
                          static_cast<double>(time.millisecond),
                          static_cast<double>(result), 0});
    default:
      // 17. Assert: unit is "nanosecond".
      DCHECK_EQ(unit, Unit::kNanosecond);
      // 18. Return ! BalanceTime(hour, minute, second, millisecond,
      // microsecond, result).
      return BalanceTime(
          {static_cast<double>(time.hour), static_cast<double>(time.minute),
           static_cast<double>(time.second),
           static_cast<double>(time.millisecond),
           static_cast<double>(time.microsecond), static_cast<double>(result)});
  }
}

// #sec-temporal-tosecondsstringprecision
Maybe<StringPrecision> ToSecondsStringPrecision(
    Isolate* isolate, Handle<JSReceiver> normalized_options,
    const char* method_name) {
  // 1. Let smallestUnit be ? GetTemporalUnit(normalizedOptions, "smallestUnit",
  // time, undefined).
  Unit smallest_unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, smallest_unit,
      GetTemporalUnit(isolate, normalized_options, "smallestUnit",
                      UnitGroup::kTime, Unit::kNotPresent, false, method_name),
      Nothing<StringPrecision>());

  switch (smallest_unit) {
    // 2. If smallestUnit is "hour", throw a RangeError exception.
    case Unit::kHour:
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kPropertyValueOutOfRange,
                        isolate->factory()->smallestUnit_string()),
          Nothing<StringPrecision>());
    // 2. If smallestUnit is "minute", then
    case Unit::kMinute:
      // a. Return the new Record { [[Precision]]: "minute", [[Unit]]: "minute",
      // [[Increment]]: 1 }.
      return Just(StringPrecision({Precision::kMinute, Unit::kMinute, 1}));
    // 3. If smallestUnit is "second", then
    case Unit::kSecond:
      // a. Return the new Record { [[Precision]]: 0, [[Unit]]: "second",
      // [[Increment]]: 1 }.
      return Just(StringPrecision({Precision::k0, Unit::kSecond, 1}));
    // 4. If smallestUnit is "millisecond", then
    case Unit::kMillisecond:
      // a. Return the new Record { [[Precision]]: 3, [[Unit]]: "millisecond",
      // [[Increment]]: 1 }.
      return Just(StringPrecision({Precision::k3, Unit::kMillisecond, 1}));
    // 5. If smallestUnit is "microsecond", then
    case Unit::kMicrosecond:
      // a. Return the new Record { [[Precision]]: 6, [[Unit]]: "microsecond",
      // [[Increment]]: 1 }.
      return Just(StringPrecision({Precision::k6, Unit::kMicrosecond, 1}));
    // 6. If smallestUnit is "nanosecond", then
    case Unit::kNanosecond:
      // a. Return the new Record { [[Precision]]: 9, [[Unit]]: "nanosecond",
      // [[Increment]]: 1 }.
      return Just(StringPrecision({Precision::k9, Unit::kNanosecond, 1}));
    default:
      break;
  }
  Factory* factory = isolate->factory();
  // 8. Assert: smallestUnit is undefined.
  DCHECK(smallest_unit == Unit::kNotPresent);
  // 9. Let fractionalDigitsVal be ? Get(normalizedOptions,
  // "fractionalSecondDigits").
  Handle<Object> fractional_digits_val;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, fractional_digits_val,
      JSReceiver::GetProperty(isolate, normalized_options,
                              factory->fractionalSecondDigits_string()),
      Nothing<StringPrecision>());

  // 10. If Type(fractionalDigitsVal) is not Number, then
  if (!IsNumber(*fractional_digits_val)) {
    // a. If fractionalDigitsVal is not undefined, then
    if (!IsUndefined(*fractional_digits_val)) {
      // i. If ? ToString(fractionalDigitsVal) is not "auto", throw a RangeError
      // exception.
      Handle<String> string;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, string, Object::ToString(isolate, fractional_digits_val),
          Nothing<StringPrecision>());
      if (!String::Equals(isolate, string, factory->auto_string())) {
        THROW_NEW_ERROR_RETURN_VALUE(
            isolate,
            NewRangeError(MessageTemplate::kPropertyValueOutOfRange,
                          factory->fractionalSecondDigits_string()),
            Nothing<StringPrecision>());
      }
    }
    // b. Return the Record { [[Precision]]: "auto", [[Unit]]: "nanosecond",
    // [[Increment]]: 1 }.
    return Just(StringPrecision({Precision::kAuto, Unit::kNanosecond, 1}));
  }
  // 11. If fractionalDigitsVal is NaN, +∞𝔽, or -∞𝔽, throw a RangeError
  // exception.
  if (IsNaN(*fractional_digits_val) ||
      std::isinf(Object::NumberValue(Cast<Number>(*fractional_digits_val)))) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kPropertyValueOutOfRange,
                      factory->fractionalSecondDigits_string()),
        Nothing<StringPrecision>());
  }
  // 12. Let fractionalDigitCount be RoundTowardsZero(ℝ(fractionalDigitsVal)).
  int64_t fractional_digit_count = RoundTowardsZero(
      Object::NumberValue(Cast<Number>(*fractional_digits_val)));
  // 13. If fractionalDigitCount < 0 or fractionalDigitCount > 9, throw a
  // RangeError exception.
  if (fractional_digit_count < 0 || fractional_digit_count > 9) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kPropertyValueOutOfRange,
                      factory->fractionalSecondDigits_string()),
        Nothing<StringPrecision>());
  }
  // 14. If fractionalDigitCount is 0, then
  switch (fractional_digit_count) {
    case 0:
      // a. Return the Record { [[Precision]]: 0, [[Unit]]: "second",
      // [[Increment]]: 1 }.
      return Just(StringPrecision({Precision::k0, Unit::kSecond, 1}));
    // 15. If fractionalDigitCount is 1, 2, or 3, then
    // a. Return the Record { [[Precision]]: fractionalDigitCount, [[Unit]]:
    // "millisecond", [[Increment]]: 10^(3 - fractionalDigitCount) }.
    case 1:
      return Just(StringPrecision({Precision::k1, Unit::kMillisecond, 100}));
    case 2:
      return Just(StringPrecision({Precision::k2, Unit::kMillisecond, 10}));
    case 3:
      return Just(StringPrecision({Precision::k3, Unit::kMillisecond, 1}));
    // 16. If fractionalDigitCount is 4, 5, or 6, then
    // a. Return the Record { [[Precision]]: fractionalDigitCount, [[Unit]]:
    // "microsecond", [[Increment]]: 10^(6 - fractionalDigitCount) }.
    case 4:
      return Just(StringPrecision({Precision::k4, Unit::kMicrosecond, 100}));
    case 5:
      return Just(StringPrecision({Precision::k5, Unit::kMicrosecond, 10}));
    case 6:
      return Just(StringPrecision({Precision::k6, Unit::kMicrosecond, 1}));
    // 17. Assert: fractionalDigitCount is 7, 8, or 9.
    // 18. Return the Record { [[Precision]]: fractionalDigitCount, [[Unit]]:
    // "nanosecond", [[Increment]]: 109 - fractionalDigitCount }.
    case 7:
      return Just(StringPrecision({Precision::k7, Unit::kNanosecond, 100}));
    case 8:
      return Just(StringPrecision({Precision::k8, Unit::kNanosecond, 10}));
    case 9:
      return Just(StringPrecision({Precision::k9, Unit::kNanosecond, 1}));
    default:
      UNREACHABLE();
  }
}

// #sec-temporal-compareepochnanoseconds
MaybeHandle<Smi> CompareEpochNanoseconds(Isolate* isolate,
                                         DirectHandle<BigInt> one,
                                         DirectHandle<BigInt> two) {
  TEMPORAL_ENTER_FUNC();

  // 1. If epochNanosecondsOne > epochNanosecondsTwo, return 1.
  // 2. If epochNanosecondsOne < epochNanosecondsTwo, return -1.
  // 3. Return 0.
  return handle(
      Smi::FromInt(CompareResultToSign(BigInt::CompareToBigInt(one, two))),
      isolate);
}

}  // namespace

// #sec-temporal.plaintime.prototype.tostring
MaybeHandle<String> JSTemporalPlainTime::ToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainTime.prototype.toString";
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalTime,
  // [[InitializedTemporalTime]]).
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

  // 6. Let roundResult be ! RoundTime(temporalTime.[[ISOHour]],
  // temporalTime.[[ISOMinute]], temporalTime.[[ISOSecond]],
  // temporalTime.[[ISOMillisecond]], temporalTime.[[ISOMicrosecond]],
  // temporalTime.[[ISONanosecond]], precision.[[Increment]],
  // precision.[[Unit]], roundingMode).

  DateTimeRecord round_result = RoundTime(
      isolate,
      {temporal_time->iso_hour(), temporal_time->iso_minute(),
       temporal_time->iso_second(), temporal_time->iso_millisecond(),
       temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()},
      precision.increment, precision.unit, rounding_mode);
  // 7. Return ! TemporalTimeToString(roundResult.[[Hour]],
  // roundResult.[[Minute]], roundResult.[[Second]],
  // roundResult.[[Millisecond]], roundResult.[[Microsecond]],
  // roundResult.[[Nanosecond]], precision.[[Precision]]).
  return TemporalTimeToString(isolate, round_result.time, precision.precision);
}

// #sec-temporal.zoneddatetime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> epoch_nanoseconds_obj, Handle<Object> time_zone_like,
    Handle<Object> calendar_like) {
  const char* method_name = "Temporal.ZonedDateTime";
  // 1. If NewTarget is undefined, then
  if (IsUndefined(*new_target)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }
  // 2. Set epochNanoseconds to ? ToBigInt(epochNanoseconds).
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      BigInt::FromObject(isolate, epoch_nanoseconds_obj));
  // 3. If ! IsValidEpochNanoseconds(epochNanoseconds) is false, throw a
  // RangeError exception.
  if (!IsValidEpochNanoseconds(isolate, epoch_nanoseconds)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }

  // 4. Let timeZone be ? ToTemporalTimeZone(timeZoneLike).
  Handle<JSReceiver> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      temporal::ToTemporalTimeZone(isolate, time_zone_like, method_name));

  // 5. Let calendar be ? ToTemporalCalendarWithISODefault(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ToTemporalCalendarWithISODefault(isolate, calendar_like, method_name));

  // 6. Return ? CreateTemporalZonedDateTime(epochNanoseconds, timeZone,
  // calendar, NewTarget).
  return CreateTemporalZonedDateTime(isolate, target, new_target,
                                     epoch_nanoseconds, time_zone, calendar);
}

// #sec-get-temporal.zoneddatetime.prototype.hoursinday
MaybeHandle<Object> JSTemporalZonedDateTime::HoursInDay(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.hoursInDay";
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

  // 5. Let isoCalendar be ! GetISO8601Calendar().
  DirectHandle<JSReceiver> iso_calendar = temporal::GetISO8601Calendar(isolate);

  // 6. Let temporalDateTime be ? BuiltinTimeZoneGetPlainDateTimeFor(timeZone,
  // instant, isoCalendar).
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   iso_calendar, method_name));
  // 7. Let year be temporalDateTime.[[ISOYear]].
  // 8. Let month be temporalDateTime.[[ISOMonth]].
  // 9. Let day be temporalDateTime.[[ISODay]].
  // 10. Let today be ? CreateTemporalDateTime(year, month, day, 0, 0, 0, 0, 0,
  // 0, isoCalendar).
  Handle<JSTemporalPlainDateTime> today;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, today,
      temporal::CreateTemporalDateTime(
          isolate,
          {{temporal_date_time->iso_year(), temporal_date_time->iso_month(),
            temporal_date_time->iso_day()},
           {0, 0, 0, 0, 0, 0}},
          iso_calendar));
  // 11. Let tomorrowFields be BalanceISODate(year, month, day + 1).
  DateRecord tomorrow_fields = BalanceISODate(
      isolate, {temporal_date_time->iso_year(), temporal_date_time->iso_month(),
                temporal_date_time->iso_day() + 1});

  // 12. Let tomorrow be ? CreateTemporalDateTime(tomorrowFields.[[Year]],
  // tomorrowFields.[[Month]], tomorrowFields.[[Day]], 0, 0, 0, 0, 0, 0,
  // isoCalendar).
  Handle<JSTemporalPlainDateTime> tomorrow;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, tomorrow,
      temporal::CreateTemporalDateTime(
          isolate, {tomorrow_fields, {0, 0, 0, 0, 0, 0}}, iso_calendar));
  // 13. Let todayInstant be ? BuiltinTimeZoneGetInstantFor(timeZone, today,
  // "compatible").
  Handle<JSTemporalInstant> today_instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, today_instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, today,
                                   Disambiguation::kCompatible, method_name));
  // 14. Let tomorrowInstant be ? BuiltinTimeZoneGetInstantFor(timeZone,
  // tomorrow, "compatible").
  Handle<JSTemporalInstant> tomorrow_instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, tomorrow_instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, tomorrow,
                                   Disambiguation::kCompatible, method_name));
  // 15. Let diffNs be tomorrowInstant.[[Nanoseconds]] −
  // todayInstant.[[Nanoseconds]].
  Handle<BigInt> diff_ns =
      BigInt::Subtract(isolate,
                       handle(tomorrow_instant->nanoseconds(), isolate),
                       handle(today_instant->nanoseconds(), isolate))
          .ToHandleChecked();
  // 16. Return 𝔽(diffNs / (3.6 × 10^12)).
  //
  // Note: The result of the division may be non integer for TimeZone which
  // change fractional hours. Perform this division in two steps:
  // First convert it to seconds in BigInt, then perform floating point
  // division (seconds / 3600) to convert to hours.
  int64_t diff_seconds =
      BigInt::Divide(isolate, diff_ns, BigInt::FromUint64(isolate, 1000000000))
          .ToHandleChecked()
          ->AsInt64();
  double hours_in_that_day = static_cast<double>(diff_seconds) / 3600.0;
  return isolate->factory()->NewNumber(hours_in_that_day);
}

namespace {

// #sec-temporal-totemporalzoneddatetime
MaybeHandle<JSTemporalZonedDateTime> ToTemporalZonedDateTime(
    Isolate* isolate, Handle<Object> item_obj, Handle<Object> options,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 2. Assert: Type(options) is Object or Undefined.
  DCHECK(IsUndefined(*options) || IsJSReceiver(*options));
  // 3. Let offsetBehaviour be option.
  OffsetBehaviour offset_behaviour = OffsetBehaviour::kOption;
  // 4. Let matchBehaviour be match exactly.
  MatchBehaviour match_behaviour = MatchBehaviour::kMatchExactly;

  Handle<Object> offset_string;
  Handle<JSReceiver> time_zone;
  Handle<JSReceiver> calendar;

  temporal::DateTimeRecord result;

  // 5. If Type(item) is Object, then
  if (IsJSReceiver(*item_obj)) {
    Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
    // a. If item has an [[InitializedTemporalZonedDateTime]] internal slot,
    // then
    if (IsJSTemporalZonedDateTime(*item_obj)) {
      // i. Return item.
      return Cast<JSTemporalZonedDateTime>(item_obj);
    }
    // b. Let calendar be ? GetTemporalCalendarWithISODefault(item).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        GetTemporalCalendarWithISODefault(isolate, item, method_name));
    // c. Let fieldNames be ? CalendarFields(calendar, « "day", "hour",
    // "microsecond", "millisecond", "minute", "month", "monthCode",
    // "nanosecond", "second", "year" »).
    Handle<FixedArray> field_names = All10UnitsInFixedArray(isolate);
    ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                               CalendarFields(isolate, calendar, field_names));

    // d. Append "timeZone" to fieldNames.
    int32_t field_length = field_names->length();
    field_names = FixedArray::SetAndGrow(isolate, field_names, field_length++,
                                         factory->timeZone_string());

    // e. Append "offset" to fieldNames.
    field_names = FixedArray::SetAndGrow(isolate, field_names, field_length++,
                                         factory->offset_string());
    field_names->RightTrim(isolate, field_length);

    // f. Let fields be ? PrepareTemporalFields(item, fieldNames, « "timeZone"
    // »).
    Handle<JSReceiver> fields;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, fields,
        PrepareTemporalFields(isolate, item, field_names,
                              RequiredFields::kTimeZone));

    // g. Let timeZone be ? Get(fields, "timeZone").
    Handle<Object> time_zone_obj;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone_obj,
        JSReceiver::GetProperty(isolate, fields, factory->timeZone_string()));

    // h. Set timeZone to ? ToTemporalTimeZone(timeZone).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone,
        temporal::ToTemporalTimeZone(isolate, time_zone_obj, method_name));
    // i. Let offsetString be ? Get(fields, "offset").
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, offset_string,
        JSReceiver::GetProperty(isolate, fields, factory->offset_string()));

    // j. If offsetString is undefined, then
    if (IsUndefined(*offset_string)) {
      // i. Set offsetBehaviour to wall.
      offset_behaviour = OffsetBehaviour::kWall;
      // k. Else,
    } else {
      // i. Set offsetString to ? ToString(offsetString).
      ASSIGN_RETURN_ON_EXCEPTION(isolate, offset_string,
                                 Object::ToString(isolate, offset_string));
    }

    // l. Let result be ? InterpretTemporalDateTimeFields(calendar, fields,
    // options).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        InterpretTemporalDateTimeFields(isolate, calendar, fields, options,
                                        method_name),
        Handle<JSTemporalZonedDateTime>());
    // 5. Else,
  } else {
    // a. Perform ? ToTemporalOverflow(options).
    MAYBE_RETURN_ON_EXCEPTION_VALUE(
        isolate, ToTemporalOverflow(isolate, options, method_name),
        Handle<JSTemporalZonedDateTime>());
    // b. Let string be ? ToString(item).
    Handle<String> string;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, string,
                               Object::ToString(isolate, item_obj));
    // c. Let result be ? ParseTemporalZonedDateTimeString(string).
    DateTimeRecordWithCalendar parsed_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, parsed_result,
        ParseTemporalZonedDateTimeString(isolate, string),
        Handle<JSTemporalZonedDateTime>());
    result = {parsed_result.date, parsed_result.time};

    // d. Let timeZoneName be result.[[TimeZone]].[[Name]].
    // e. Assert: timeZoneName is not undefined.
    DCHECK(!IsUndefined(*parsed_result.time_zone.name));
    Handle<String> time_zone_name = Cast<String>(parsed_result.time_zone.name);

    // f. If ParseText(StringToCodePoints(timeZoneName),
    // TimeZoneNumericUTCOffset) is a List of errors, then
    std::optional<ParsedISO8601Result> parsed =
        TemporalParser::ParseTimeZoneNumericUTCOffset(isolate, time_zone_name);
    if (!parsed.has_value()) {
      // i. If ! IsValidTimeZoneName(timeZoneName) is false, throw a RangeError
      // exception.
      if (!IsValidTimeZoneName(isolate, time_zone_name)) {
        THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                     NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                     Handle<JSTemporalZonedDateTime>());
      }
      // ii. Set timeZoneName to ! CanonicalizeTimeZoneName(timeZoneName).
      time_zone_name = CanonicalizeTimeZoneName(isolate, time_zone_name);
    }
    // g. Let offsetString be result.[[TimeZone]].[[OffsetString]].
    offset_string = parsed_result.time_zone.offset_string;

    // h. If result.[[TimeZone]].[[Z]] is true, then
    if (parsed_result.time_zone.z) {
      // i. Set offsetBehaviour to exact.
      offset_behaviour = OffsetBehaviour::kExact;
      // i. Else if offsetString is undefined, then
    } else if (IsUndefined(*offset_string)) {
      // i. Set offsetBehaviour to wall.
      offset_behaviour = OffsetBehaviour::kWall;
    }
    // j. Let timeZone be ! CreateTemporalTimeZone(timeZoneName).
    time_zone = temporal::CreateTemporalTimeZone(isolate, time_zone_name)
                    .ToHandleChecked();
    // k. Let calendar be ?
    // ToTemporalCalendarWithISODefault(result.[[Calendar]]).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        ToTemporalCalendarWithISODefault(isolate, parsed_result.calendar,
                                         method_name));
    // j. Set matchBehaviour to match minutes.
    match_behaviour = MatchBehaviour::kMatchMinutes;
  }
  // 7. Let offsetNanoseconds be 0.
  int64_t offset_nanoseconds = 0;

  // 6. If offsetBehaviour is option, then
  if (offset_behaviour == OffsetBehaviour::kOption) {
    // a. Set offsetNanoseconds to ? ParseTimeZoneOffsetString(offsetString).
    DCHECK(IsString(*offset_string));
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, offset_nanoseconds,
        ParseTimeZoneOffsetString(isolate, Cast<String>(offset_string)),
        Handle<JSTemporalZonedDateTime>());
  }

  // 7. Let disambiguation be ? ToTemporalDisambiguation(options).
  Disambiguation disambiguation;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, disambiguation,
      ToTemporalDisambiguation(isolate, options, method_name),
      Handle<JSTemporalZonedDateTime>());

  // 8. Let offset be ? ToTemporalOffset(options, "reject").
  enum Offset offset;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset,
      ToTemporalOffset(isolate, options, Offset::kReject, method_name),
      Handle<JSTemporalZonedDateTime>());

  // 9. Let epochNanoseconds be ? InterpretISODateTimeOffset(result.[[Year]],
  // result.[[Month]], result.[[Day]], result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]], offsetBehaviour, offsetNanoseconds, timeZone,
  // disambiguation, offset, matchBehaviour).
  //
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      InterpretISODateTimeOffset(isolate, result, offset_behaviour,
                                 offset_nanoseconds, time_zone, disambiguation,
                                 offset, match_behaviour, method_name));

  // 8. Return ? CreateTemporalZonedDateTime(epochNanoseconds, timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(isolate, epoch_nanoseconds, time_zone,
                                     calendar);
}

MaybeHandle<JSTemporalZonedDateTime> ToTemporalZonedDateTime(
    Isolate* isolate, Handle<Object> item_obj, const char* method_name) {
  // 1. If options is not present, set options to undefined.
  return ToTemporalZonedDateTime(
      isolate, item_obj, isolate->factory()->undefined_value(), method_name);
}

}  // namespace

// #sec-temporal.zoneddatetime.from
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::From(
    Isolate* isolate, Handle<Object> item, Handle<Object> options_obj) {
  const char* method_name = "Temporal.ZonedDateTime.from";
  // 1. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 2. If Type(item) is Object and item has an
  // [[InitializedTemporalZonedDateTime]] internal slot, then
  if (IsJSTemporalZonedDateTime(*item)) {
    // a. Perform ? ToTemporalOverflow(options).
    MAYBE_RETURN_ON_EXCEPTION_VALUE(
        isolate, ToTemporalOverflow(isolate, options, method_name),
        Handle<JSTemporalZonedDateTime>());

    // b. Perform ? ToTemporalDisambiguation(options).
    {
      Disambiguation disambiguation;
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, disambiguation,
          ToTemporalDisambiguation(isolate, options, method_name),
          Handle<JSTemporalZonedDateTime>());
      USE(disambiguation);
    }

    // c. Perform ? ToTemporalOffset(options, "reject").
    {
      enum Offset offset;
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, offset,
          ToTemporalOffset(isolate, options, Offset::kReject, method_name),
          Handle<JSTemporalZonedDateTime>());
      USE(offset);
    }

    // d. Return ? CreateTemporalZonedDateTime(item.[[Nanoseconds]],
    // item.[[TimeZone]], item.[[Calendar]]).
    auto zoned_date_time = Cast<JSTemporalZonedDateTime>(item);
    return CreateTemporalZonedDateTime(
        isolate, handle(zoned_date_time->nanoseconds(), isolate),
        handle(zoned_date_time->time_zone(), isolate),
        handle(zoned_date_time->calendar(), isolate));
  }
  // 3. Return ? ToTemporalZonedDateTime(item, options).
  return ToTemporalZonedDateTime(isolate, item, options, method_name);
}

// #sec-temporal.zoneddatetime.compare
MaybeHandle<Smi> JSTemporalZonedDateTime::Compare(Isolate* isolate,
                                                  Handle<Object> one_obj,
                                                  Handle<Object> two_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.compare";
  // 1. Set one to ? ToTemporalZonedDateTime(one).
  Handle<JSTemporalZonedDateTime> one;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, one, ToTemporalZonedDateTime(isolate, one_obj, method_name));
  // 2. Set two to ? ToTemporalZonedDateTime(two).
  Handle<JSTemporalZonedDateTime> two;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, two, ToTemporalZonedDateTime(isolate, two_obj, method_name));
  // 3. Return 𝔽(! CompareEpochNanoseconds(one.[[Nanoseconds]],
  // two.[[Nanoseconds]])).
  return CompareEpochNanoseconds(isolate, handle(one->nanoseconds(), isolate),
                                 handle(two->nanoseconds(), isolate));
}

namespace {

// #sec-temporal-timezoneequals
Maybe<bool> TimeZoneEquals(Isolate* isolate, Handle<JSReceiver> one,
                           Handle<JSReceiver> two) {
  // 1. If one and two are the same Object value, return true.
  if (one.is_identical_to(two)) {
    return Just(true);
  }

  // 2. Let timeZoneOne be ? ToString(one).
  Handle<String> time_zone_one;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, time_zone_one, Object::ToString(isolate, one), Nothing<bool>());
  // 3. Let timeZoneTwo be ? ToString(two).
  Handle<String> time_zone_two;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, time_zone_two, Object::ToString(isolate, two), Nothing<bool>());
  // 4. If timeZoneOne is timeZoneTwo, return true.
  if (String::Equals(isolate, time_zone_one, time_zone_two)) {
    return Just(true);
  }
  // 5. Return false.
  return Just(false);
}

}  // namespace

// #sec-temporal.zoneddatetime.prototype.equals
MaybeHandle<Oddball> JSTemporalZonedDateTime::Equals(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> other_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.equals";
  Factory* factory = isolate->factory();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Set other to ? ToTemporalZonedDateTime(other).
  Handle<JSTemporalZonedDateTime> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other, ToTemporalZonedDateTime(isolate, other_obj, method_name));
  // 4. If zonedDateTime.[[Nanoseconds]] ≠ other.[[Nanoseconds]], return false.
  if (!BigInt::EqualToBigInt(zoned_date_time->nanoseconds(),
                             other->nanoseconds())) {
    return factory->false_value();
  }
  // 5. If ? TimeZoneEquals(zonedDateTime.[[TimeZone]], other.[[TimeZone]]) is
  // false, return false.
  bool equals;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, equals,
      TimeZoneEquals(isolate, handle(zoned_date_time->time_zone(), isolate),
                     handle(other->time_zone(), isolate)),
      Handle<Oddball>());
  if (!equals) {
    return factory->false_value();
  }
  // 6. Return ? CalendarEquals(zonedDateTime.[[Calendar]], other.[[Calendar]]).
  return CalendarEquals(isolate, handle(zoned_date_time->calendar(), isolate),
                        handle(other->calendar(), isolate));
}

namespace {

// #sec-temporal-interpretisodatetimeoffset
MaybeHandle<BigInt> InterpretISODateTimeOffset(
    Isolate* isolate, const DateTimeRecord& data,
    OffsetBehaviour offset_behaviour, int64_t offset_nanoseconds,
    Handle<JSReceiver> time_zone, Disambiguation disambiguation,
    Offset offset_option, MatchBehaviour match_behaviour,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: offsetNanoseconds is an integer or undefined.
  // 2. Let calendar be ! GetISO8601Calendar().
  DirectHandle<JSReceiver> calendar = temporal::GetISO8601Calendar(isolate);

  // 3. Let dateTime be ? CreateTemporalDateTime(year, month, day, hour, minute,
  // second, millisecond, microsecond, nanosecond, calendar).
  Handle<JSTemporalPlainDateTime> date_time;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, date_time,
                             temporal::CreateTemporalDateTime(
                                 isolate, {data.date, data.time}, calendar));

  // 4. If offsetBehaviour is wall, or offsetOption is "ignore", then
  if (offset_behaviour == OffsetBehaviour::kWall ||
      offset_option == Offset::kIgnore) {
    // a. Let instant be ? BuiltinTimeZoneGetInstantFor(timeZone, dateTime,
    // disambiguation).
    Handle<JSTemporalInstant> instant;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, instant,
        BuiltinTimeZoneGetInstantFor(isolate, time_zone, date_time,
                                     disambiguation, method_name));
    // b. Return instant.[[Nanoseconds]].
    return handle(instant->nanoseconds(), isolate);
  }
  // 5. If offsetBehaviour is exact, or offsetOption is "use", then
  if (offset_behaviour == OffsetBehaviour::kExact ||
      offset_option == Offset::kUse) {
    // a. Let epochNanoseconds be ? GetEpochFromISOParts(year, month, day, hour,
    // minute, second, millisecond, microsecond, nanosecond).
    Handle<BigInt> epoch_nanoseconds =
        GetEpochFromISOParts(isolate, {data.date, data.time});

    // b. Set epochNanoseconds to epochNanoseconds - ℤ(offsetNanoseconds).
    epoch_nanoseconds =
        BigInt::Subtract(isolate, epoch_nanoseconds,
                         BigInt::FromInt64(isolate, offset_nanoseconds))
            .ToHandleChecked();
    // c. If ! IsValidEpochNanoseconds(epochNanoseconds) is false, throw a
    // RangeError exception.
    if (!IsValidEpochNanoseconds(isolate, epoch_nanoseconds)) {
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
    }
    // d. Return epochNanoseconds.
    return epoch_nanoseconds;
  }
  // 6. Assert: offsetBehaviour is option.
  DCHECK_EQ(offset_behaviour, OffsetBehaviour::kOption);
  // 7. Assert: offsetOption is "prefer" or "reject".
  DCHECK(offset_option == Offset::kPrefer || offset_option == Offset::kReject);
  // 8. Let possibleInstants be ? GetPossibleInstantsFor(timeZone, dateTime).
  Handle<FixedArray> possible_instants;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, possible_instants,
      GetPossibleInstantsFor(isolate, time_zone, date_time));

  // 9. For each element candidate of possibleInstants, do
  for (int i = 0; i < possible_instants->length(); i++) {
    DCHECK(IsJSTemporalInstant(possible_instants->get(i)));
    Handle<JSTemporalInstant> candidate(
        Cast<JSTemporalInstant>(possible_instants->get(i)), isolate);
    // a. Let candidateNanoseconds be ? GetOffsetNanosecondsFor(timeZone,
    // candidate).
    int64_t candidate_nanoseconds;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, candidate_nanoseconds,
        GetOffsetNanosecondsFor(isolate, time_zone, candidate, method_name),
        Handle<BigInt>());
    // b. If candidateNanoseconds = offsetNanoseconds, then
    if (candidate_nanoseconds == offset_nanoseconds) {
      // i. Return candidate.[[Nanoseconds]].
      return Handle<BigInt>(candidate->nanoseconds(), isolate);
    }
    // c. If matchBehaviour is match minutes, then
    if (match_behaviour == MatchBehaviour::kMatchMinutes) {
      // i. Let roundedCandidateNanoseconds be !
      // RoundNumberToIncrement(candidateNanoseconds, 60 × 10^9, "halfExpand").
      double rounded_candidate_nanoseconds = RoundNumberToIncrement(
          isolate, candidate_nanoseconds, 6e10, RoundingMode::kHalfExpand);
      // ii. If roundedCandidateNanoseconds = offsetNanoseconds, then
      if (rounded_candidate_nanoseconds == offset_nanoseconds) {
        // 1. Return candidate.[[Nanoseconds]].
        return Handle<BigInt>(candidate->nanoseconds(), isolate);
      }
    }
  }
  // 10. If offsetOption is "reject", throw a RangeError exception.
  if (offset_option == Offset::kReject) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 11. Let instant be ? DisambiguatePossibleInstants(possibleInstants,
  // timeZone, dateTime, disambiguation).
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      DisambiguatePossibleInstants(isolate, possible_instants, time_zone,
                                   date_time, disambiguation, method_name));
  // 12. Return instant.[[Nanoseconds]].
  return Handle<BigInt>(instant->nanoseconds(), isolate);
}

}  // namespace

// #sec-temporal.zoneddatetime.prototype.with
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::With(
    Isolate* isolate, Handle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> temporal_zoned_date_time_like_obj,
    Handle<Object> options_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.with";
  Factory* factory = isolate->factory();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. If Type(temporalZonedDateTimeLike) is not Object, then
  if (!IsJSReceiver(*temporal_zoned_date_time_like_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  Handle<JSReceiver> temporal_zoned_date_time_like =
      Cast<JSReceiver>(temporal_zoned_date_time_like_obj);
  // 4. Perform ? RejectObjectWithCalendarOrTimeZone(temporalZonedDateTimeLike).
  MAYBE_RETURN(RejectObjectWithCalendarOrTimeZone(
                   isolate, temporal_zoned_date_time_like),
               Handle<JSTemporalZonedDateTime>());

  // 5. Let calendar be zonedDateTime.[[Calendar]].
  Handle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);

  // 6. Let fieldNames be ? CalendarFields(calendar, « "day", "hour",
  // "microsecond", "millisecond", "minute", "month", "monthCode", "nanosecond",
  // "second", "year" »).
  Handle<FixedArray> field_names;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, field_names,
      CalendarFields(isolate, calendar, All10UnitsInFixedArray(isolate)));

  // 7. Append "offset" to fieldNames.
  int32_t field_length = field_names->length();
  field_names = FixedArray::SetAndGrow(isolate, field_names, field_length++,
                                       factory->offset_string());
  field_names->RightTrim(isolate, field_length);

  // 8. Let partialZonedDateTime be ?
  // PreparePartialTemporalFields(temporalZonedDateTimeLike, fieldNames).
  Handle<JSReceiver> partial_zoned_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, partial_zoned_date_time,
      PreparePartialTemporalFields(isolate, temporal_zoned_date_time_like,
                                   field_names));
  // 9. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 10. Let disambiguation be ? ToTemporalDisambiguation(options).
  Disambiguation disambiguation;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, disambiguation,
      ToTemporalDisambiguation(isolate, options, method_name),
      Handle<JSTemporalZonedDateTime>());

  // 11. Let offset be ? ToTemporalOffset(options, "prefer").
  enum Offset offset;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset,
      ToTemporalOffset(isolate, options, Offset::kPrefer, method_name),
      Handle<JSTemporalZonedDateTime>());

  // 12. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);

  // 13. Append "timeZone" to fieldNames.
  field_length = field_names->length();
  field_names = FixedArray::SetAndGrow(isolate, field_names, field_length++,
                                       factory->timeZone_string());
  field_names->RightTrim(isolate, field_length);

  // 14. Let fields be ? PrepareTemporalFields(zonedDateTime, fieldNames, «
  // "timeZone", "offset"»).
  Handle<JSReceiver> fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      PrepareTemporalFields(isolate, zoned_date_time, field_names,
                            RequiredFields::kTimeZoneAndOffset));
  // 15. Set fields to ? CalendarMergeFields(calendar, fields,
  // partialZonedDateTime).
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      CalendarMergeFields(isolate, calendar, fields, partial_zoned_date_time));

  // 16. Set fields to ? PrepareTemporalFields(fields, fieldNames, « "timeZone"
  // , "offset"»).
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      PrepareTemporalFields(isolate, fields, field_names,
                            RequiredFields::kTimeZoneAndOffset));

  // 17. Let offsetString be ? Get(fields, "offset").
  Handle<Object> offset_string;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, offset_string,
      JSReceiver::GetProperty(isolate, fields, factory->offset_string()));

  // 18. Assert: Type(offsetString) is String.
  DCHECK(IsString(*offset_string));

  // 19. Let dat
```