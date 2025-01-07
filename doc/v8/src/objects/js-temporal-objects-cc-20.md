Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/js-temporal-objects.cc`. I need to:

1. **Identify the core purpose:**  The code deals with `JSTemporalPlainTime` objects, which are part of the Temporal API for date and time manipulation in JavaScript.
2. **Analyze individual functions:**  Each function seems to implement a specific operation on `JSTemporalPlainTime` objects. I'll list these operations.
3. **Check for Torque:**  The file extension is `.cc`, not `.tq`, so it's not a Torque source file.
4. **Connect to JavaScript:**  For functions related to JavaScript functionality, I need to provide illustrative JavaScript examples.
5. **Infer logic and provide examples:**  For functions with clear logic (like adding or subtracting time), I'll create hypothetical inputs and outputs.
6. **Highlight common errors:**  I need to think about typical mistakes users might make when using these functionalities in JavaScript.
7. **Synthesize a summary:**  Finally, I'll combine the individual function descriptions into a concise overall summary, keeping in mind this is part 21 of 25.

**Function Breakdown and Planning:**

*   **`ToTemporalTime`:** Converts an object to a `JSTemporalPlainTime`. JavaScript example: `Temporal.PlainTime.from(...)`.
*   **`ToPlainDateTime`:** Combines a `JSTemporalPlainTime` with a date to create a `JSTemporalPlainDateTime`. JavaScript example: `plainTime.toPlainDateTime(plainDate)`.
*   **`AddDurationToOrSubtractDurationFromPlainTime`:**  A helper for adding or subtracting durations.
*   **`Add`:** Adds a duration to a `JSTemporalPlainTime`. JavaScript example: `plainTime.add(duration)`.
*   **`Subtract`:** Subtracts a duration from a `JSTemporalPlainTime`. JavaScript example: `plainTime.subtract(duration)`.
*   **`DifferenceTemporalPlainTime`:** A helper for calculating the difference between two times.
*   **`Until`:** Calculates the duration until another `JSTemporalPlainTime`. JavaScript example: `plainTime.until(otherPlainTime)`.
*   **`Since`:** Calculates the duration since another `JSTemporalPlainTime`. JavaScript example: `plainTime.since(otherPlainTime)`.
*   **`GetISOFields`:** Returns the ISO components of a `JSTemporalPlainTime`. JavaScript example: `plainTime.getISOFields()`.
*   **`ToJSON`:** Converts a `JSTemporalPlainTime` to a JSON string. JavaScript example: `JSON.stringify(plainTime)`.
*   **`ToLocaleString`:** Converts a `JSTemporalPlainTime` to a locale-specific string. JavaScript example: `plainTime.toLocaleString()`.
*   **`GetUnsignedRoundingMode`:** Determines the rounding mode based on whether a value is negative.
*   **`ApplyUnsignedRoundingMode`:** Applies a specific unsigned rounding mode.
*   **`RoundNumberToIncrement`:** Rounds a number to a specific increment.
*   **`RoundNumberToIncrementAsIfPositive`:** Rounds a BigInt to a specific increment, treating it as positive.
*   **`RoundTime`:** Rounds the components of a time to a specific unit and increment.
*   **`ToSecondsStringPrecision`:** Determines the precision for string representation based on options.

Now I can generate the response with these points in mind.
这是 `v8/src/objects/js-temporal-objects.cc` 源代码文件的第 21 部分，主要负责实现 `Temporal.PlainTime` 对象的一些核心功能。以下是其功能的详细列举：

**主要功能：**

该文件主要实现了 `Temporal.PlainTime` 原型对象上的方法，允许进行各种时间相关的操作，例如：

*   **创建 `Temporal.PlainTime` 对象：**
    *   `ToTemporalTime`:  将传入的 JavaScript 对象转换为 `Temporal.PlainTime` 对象。它可以接受一个已经存在的 `Temporal.PlainTime` 对象（直接返回），也可以接受包含时间属性（hour, minute, second 等）的对象，并根据 `overflow` 选项处理超出范围的值。

*   **与其他 Temporal 类型的转换：**
    *   `ToPlainDateTime`: 将 `Temporal.PlainTime` 对象与一个 `Temporal.PlainDate` 或类似的对象结合，创建一个新的 `Temporal.PlainDateTime` 对象。

*   **时间的加减运算：**
    *   `Add`:  将一个 `Temporal.Duration` 对象添加到 `Temporal.PlainTime` 对象上，返回一个新的 `Temporal.PlainTime` 对象。
    *   `Subtract`: 从 `Temporal.PlainTime` 对象中减去一个 `Temporal.Duration` 对象，返回一个新的 `Temporal.PlainTime` 对象。
    *   `AddDurationToOrSubtractDurationFromPlainTime`:  `Add` 和 `Subtract` 方法的内部共享逻辑，根据 `operation` 参数决定是加法还是减法。

*   **时间差计算：**
    *   `Until`: 计算当前 `Temporal.PlainTime` 对象到另一个 `Temporal.PlainTime` 对象之间的时间差，返回一个 `Temporal.Duration` 对象。
    *   `Since`: 计算另一个 `Temporal.PlainTime` 对象到当前 `Temporal.PlainTime` 对象之间的时间差，返回一个 `Temporal.Duration` 对象。
    *   `DifferenceTemporalPlainTime`:  `Until` 和 `Since` 方法的内部共享逻辑，根据 `operation` 参数决定时间差的方向。

*   **获取时间组成部分：**
    *   `GetISOFields`:  返回一个包含 `Temporal.PlainTime` 对象的 ISO 年、月、日、小时、分钟、秒、毫秒、微秒和纳秒等属性的对象。

*   **字符串表示：**
    *   `ToJSON`: 将 `Temporal.PlainTime` 对象转换为符合 JSON 格式的字符串表示。
    *   `ToLocaleString`:  将 `Temporal.PlainTime` 对象转换为本地化格式的字符串表示（依赖于 Intl 支持）。

*   **时间的舍入：**
    *   `RoundTime`:  将时间舍入到指定的单位和增量。
    *   `RoundNumberToIncrement`:  将一个数字舍入到指定的增量。
    *   `RoundNumberToIncrementAsIfPositive`:  将一个 `BigInt` 舍入到指定的增量，将其视为正数。
    *   `GetUnsignedRoundingMode`: 根据舍入模式和数值的正负性获取无符号舍入模式。
    *   `ApplyUnsignedRoundingMode`:  应用无符号舍入模式。

*   **获取字符串表示精度：**
    *   `ToSecondsStringPrecision`:  根据提供的选项确定时间字符串表示的精度。

**关于文件类型：**

`v8/src/objects/js-temporal-objects.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 v8 Torque 源代码。

**与 JavaScript 功能的关系及示例：**

这些 C++ 代码实现了 JavaScript 中 `Temporal.PlainTime` 对象的方法。以下是一些 JavaScript 示例：

```javascript
const plainTime = Temporal.PlainTime.from('10:30:00.123456789');
const plainDate = Temporal.PlainDate.from('2023-10-27');
const duration = new Temporal.Duration(0, 0, 0, 0, 1, 30, 0, 0, 0);
const otherPlainTime = Temporal.PlainTime.from('11:00:00');

// 创建 Temporal.PlainTime
const time1 = Temporal.PlainTime.from({ hour: 10, minute: 15 });
console.log(time1.toString()); // 输出: 10:15:00

// 转换为 Temporal.PlainDateTime
const plainDateTime = plainTime.toPlainDateTime(plainDate);
console.log(plainDateTime.toString()); // 输出类似于: 2023-10-27T10:30:00.123456789

// 时间加法
const addedTime = plainTime.add(duration);
console.log(addedTime.toString()); // 输出: 12:00:00.123456789

// 时间减法
const subtractedTime = plainTime.subtract(duration);
console.log(subtractedTime.toString()); // 输出: 09:00:00.123456789

// 计算时间差
const untilDuration = plainTime.until(otherPlainTime);
console.log(untilDuration.toString()); // 输出: PT0H29M59.876543211S

const sinceDuration = plainTime.since(otherPlainTime);
console.log(sinceDuration.toString()); // 输出: PT-0H29M59.876543211S

// 获取 ISO 字段
const isoFields = plainTime.getISOFields();
console.log(isoFields); // 输出类似于: { calendar: 'iso8601', isoHour: 10, isoMinute: 30, ... }

// 转换为 JSON 字符串
const jsonString = JSON.stringify(plainTime);
console.log(jsonString); // 输出: "10:30:00.123456789"

// 转换为本地化字符串
console.log(plainTime.toLocaleString('zh-CN')); // 输出本地化的时间字符串 (取决于环境)
```

**代码逻辑推理示例：**

**假设输入：**

*   `temporal_time`: 一个 `Temporal.PlainTime` 对象，表示 `10:15:30.500`
*   `temporal_duration_like`: 一个 JavaScript 对象，表示 duration `{ hours: 1, minutes: -10 }`

**调用的方法：** `JSTemporalPlainTime::Add(isolate, temporal_time, temporal_duration_like)`

**代码逻辑推理：**

1. `AddDurationToOrSubtractDurationFromPlainTime` 函数被调用，`operation` 为 `Arithmetic::kAdd`。
2. `sign` 被设置为 `1.0`。
3. `ToTemporalDurationRecord` 将 `temporal_duration_like` 转换为 `DurationRecord`，其中 `time_duration.hours` 为 `1`，`time_duration.minutes` 为 `-10`。
4. `AddTime` 函数被调用，将时间组成部分相加：
    *   `hour`: 10 + 1 = 11
    *   `minute`: 15 + (-10) = 5
    *   `second`: 30
    *   `millisecond`: 500
5. `CreateTemporalTime` 使用计算后的时间组成部分创建一个新的 `Temporal.PlainTime` 对象。

**输出：**

一个新的 `Temporal.PlainTime` 对象，表示 `11:05:30.500`。

**用户常见的编程错误示例：**

*   **向 `ToPlainDateTime` 传递不正确的日期类型：**

    ```javascript
    const plainTime = Temporal.PlainTime.from('10:00:00');
    const notADate = "this is not a date";
    // 错误：会抛出 TypeError，因为 notADate 不能转换为 Temporal.PlainDate
    const plainDateTime = plainTime.toPlainDateTime(notADate);
    ```

*   **对 `Add` 或 `Subtract` 传递不正确的 Duration 类型：**

    ```javascript
    const plainTime = Temporal.PlainTime.from('10:00:00');
    const notADuration = { hours: 1 }; // 缺少必要的 Duration 属性
    // 错误：可能会抛出 TypeError，因为 notADuration 不能被正确解析为 Temporal.Duration
    const newTime = plainTime.add(notADuration);
    ```

*   **在时间差计算中假设固定的单位大小：**

    ```javascript
    const time1 = Temporal.PlainTime.from('00:00:00');
    const time2 = Temporal.PlainTime.from('01:30:00');
    const duration = time1.until(time2);
    // 错误：直接访问 duration.minutes 可能会导致误解，
    // 应该使用 toRounded() 或其他方法来获取特定单位的差值
    console.log(duration.minutes); // 这可能不是你期望的 90
    ```

**归纳其功能 (第 21 部分，共 25 部分)：**

作为 `Temporal.PlainTime` 实现的一部分，第 21 部分主要集中在 **`Temporal.PlainTime` 对象的各种操作和转换**。它定义了如何创建、加减、计算时间差、获取组成部分以及将其转换为其他 Temporal 类型和字符串表示的方法。这部分代码是 `Temporal.PlainTime` 核心功能的关键组成部分，使得 JavaScript 开发者能够方便地操作和处理时间值。考虑到这是 25 部分中的第 21 部分，可以推断出前面的部分可能涉及对象的创建和基础属性，而后面的部分可能涉及更高级的功能或与其他 Temporal 类型的交互。

Prompt: 
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第21部分，共25部分，请归纳一下它的功能

"""
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
      return Just(
"""


```