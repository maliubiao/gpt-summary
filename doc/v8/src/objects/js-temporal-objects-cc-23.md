Response:
The user wants a summary of the provided V8 source code snippet.
The code is part of `v8/src/objects/js-temporal-objects.cc`.
This file likely contains the implementation of the ECMAScript Temporal API within V8.
The snippet includes functions related to `JSTemporalZonedDateTime` and `JSTemporalInstant`.

Let's break down the functionality based on the provided code:

- **`AddDurationToOrSubtractDurationFromZonedDateTime`**: This function seems to handle adding or subtracting a duration from a `JSTemporalZonedDateTime`.
- **`JSTemporalZonedDateTime::Add` and `JSTemporalZonedDateTime::Subtract`**: These are likely the public methods on the `JSTemporalZonedDateTime` prototype for adding and subtracting durations, respectively. They call the internal function mentioned above.
- **`DifferenceTemporalZonedDateTime`**: This function calculates the difference between two `JSTemporalZonedDateTime` objects, returning a `JSTemporalDuration`.
- **`JSTemporalZonedDateTime::Until` and `JSTemporalZonedDateTime::Since`**: These are the public methods to calculate the duration until or since another `JSTemporalZonedDateTime`. They call the `DifferenceTemporalZonedDateTime` function.
- **`JSTemporalZonedDateTime::GetISOFields`**: This method extracts the ISO-related date and time components, along with the offset and calendar, from a `JSTemporalZonedDateTime`.
- **`JSTemporalInstant::Now`**: This method returns the current system time as a `JSTemporalInstant`.
- **`JSTemporalZonedDateTime::OffsetNanoseconds` and `JSTemporalZonedDateTime::Offset`**: These methods retrieve the offset of a `JSTemporalZonedDateTime` in nanoseconds and as a string, respectively.
- **`JSTemporalZonedDateTime::StartOfDay`**: This method returns a new `JSTemporalZonedDateTime` representing the start of the day for the given object.
- **`JSTemporalZonedDateTime::ToInstant`**: This method converts a `JSTemporalZonedDateTime` to a `JSTemporalInstant`.
- **`ZonedDateTimeToPlainDateTime`**:  An internal helper function to get the `JSTemporalPlainDateTime` representation of a `JSTemporalZonedDateTime`.
- **`JSTemporalZonedDateTime::ToPlainDate`, `JSTemporalZonedDateTime::ToPlainTime`, `JSTemporalZonedDateTime::ToPlainDateTime`**: These methods convert a `JSTemporalZonedDateTime` to its `JSTemporalPlainDate`, `JSTemporalPlainTime`, or `JSTemporalPlainDateTime` components, respectively.
- **`JSTemporalInstant::Constructor`**: The constructor for `JSTemporalInstant`.
- **`ScaleNumberToNanosecondsVerifyAndMake` and `ScaleToNanosecondsVerifyAndMake`**: Internal helper functions to create `JSTemporalInstant` from epoch seconds, milliseconds, or microseconds.
- **`JSTemporalInstant::FromEpochSeconds`, `JSTemporalInstant::FromEpochMilliseconds`, `JSTemporalInstant::FromEpochMicroseconds`, `JSTemporalInstant::FromEpochNanoseconds`**: Static methods to create `JSTemporalInstant` from a specific epoch value.
- **`JSTemporalInstant::Compare`**: Compares two `JSTemporalInstant` objects.
- **`JSTemporalInstant::Equals`**: Checks if two `JSTemporalInstant` objects are equal.
- **`ToTemporalRoundingIncrement`**:  A helper function to validate and get the rounding increment from options.
- **`RoundTemporalInstant`**:  Rounds a `JSTemporalInstant` to a specific increment.

Now, let's address the user's specific points:

- **File extension:** The code is in `.cc`, so it's C++ source code, not Torque.
- **Relationship to JavaScript:** The code implements the functionality of the Temporal API, which is directly accessible in JavaScript.
- **Code logic and examples:** We can create examples for adding, subtracting, finding differences, and conversions.
- **Common programming errors:**  Using incorrect units or not handling time zones properly are common errors.
- **Overall functionality:**  The snippet focuses on the core arithmetic and conversion operations for `ZonedDateTime` and `Instant` objects in the Temporal API.

Based on the context provided ("This is part 24 of 25"), this file likely covers a significant portion of the `ZonedDateTime` and `Instant` functionality within the V8 implementation of the Temporal API.
这是 V8 源代码文件 `v8/src/objects/js-temporal-objects.cc` 的一个代码片段，它主要负责实现 **ECMAScript Temporal API** 中 `Temporal.ZonedDateTime` 和 `Temporal.Instant` 对象的部分功能。

**主要功能概括:**

这个代码片段主要实现了以下与 `Temporal.ZonedDateTime` 和 `Temporal.Instant` 相关的操作：

* **`Temporal.ZonedDateTime` 的算术运算:**
    * **`add()` 和 `subtract()`:**  向 `Temporal.ZonedDateTime` 对象添加或减去一个 `Temporal.Duration` 对象。
    * **内部函数 `AddDurationToOrSubtractDurationFromZonedDateTime`:**  负责 `add()` 和 `subtract()` 的核心逻辑，根据加法或减法的操作符进行不同的处理。
* **`Temporal.ZonedDateTime` 的比较和差异计算:**
    * **`until()` 和 `since()`:** 计算两个 `Temporal.ZonedDateTime` 之间的时间差，返回一个 `Temporal.Duration` 对象。
    * **内部函数 `DifferenceTemporalZonedDateTime`:** 负责 `until()` 和 `since()` 的核心逻辑，处理不同单位的差异计算。
* **`Temporal.ZonedDateTime` 的属性获取和转换:**
    * **`getISOFields()`:** 获取 `Temporal.ZonedDateTime` 对象的 ISO 年、月、日、时、分、秒、毫秒、微秒、纳秒以及时区偏移量和日历。
    * **`offsetNanoseconds` 和 `offset` (getter):** 获取 `Temporal.ZonedDateTime` 的时区偏移量，分别以纳秒和字符串形式返回。
    * **`startOfDay()`:** 返回一个新的 `Temporal.ZonedDateTime` 对象，表示当前 `Temporal.ZonedDateTime` 所在日期的开始时间（午夜）。
    * **`toInstant()`:** 将 `Temporal.ZonedDateTime` 转换为 `Temporal.Instant` 对象。
    * **`toPlainDate()`、`toPlainTime()`、`toPlainDateTime()`:** 将 `Temporal.ZonedDateTime` 转换为 `Temporal.PlainDate`、`Temporal.PlainTime` 或 `Temporal.PlainDateTime` 对象。
    * **内部函数 `ZonedDateTimeToPlainDateTime`:**  为 `toPlainDate`、`toPlainTime` 和 `toPlainDateTime` 提供共享的转换逻辑。
* **`Temporal.Instant` 的创建和操作:**
    * **构造函数:** 创建 `Temporal.Instant` 对象，需要传入一个表示纪元纳秒的 BigInt 值。
    * **`now()` (静态方法):** 获取当前系统时间的 `Temporal.Instant` 对象。
    * **`fromEpochSeconds()`、`fromEpochMilliseconds()`、`fromEpochMicroseconds()`、`fromEpochNanoseconds()` (静态方法):** 从自 Unix 纪元开始的秒、毫秒、微秒或纳秒数创建 `Temporal.Instant` 对象。
    * **`compare()` (静态方法):** 比较两个 `Temporal.Instant` 对象的时间先后顺序。
    * **`equals()`:** 判断两个 `Temporal.Instant` 对象是否表示同一时间点。
* **内部辅助函数:**
    * **`ToTemporalRoundingIncrement`:**  用于将传入的选项转换为有效的舍入增量。
    * **`RoundTemporalInstant`:**  根据指定的舍入模式和单位，对 `Temporal.Instant` 进行舍入操作。

**关于文件类型:**

根据您的描述，`v8/src/objects/js-temporal-objects.cc` 以 `.cc` 结尾，这意味着它是一个 **C++ 源代码文件**。如果它以 `.tq` 结尾，那它才是 V8 Torque 源代码。

**与 JavaScript 的关系及示例:**

这个 C++ 代码文件实现了 JavaScript 中 `Temporal.ZonedDateTime` 和 `Temporal.Instant` 对象的功能。JavaScript 代码可以直接调用这些功能。

**示例 (JavaScript):**

```javascript
// 创建一个 Temporal.ZonedDateTime 对象
const zonedDateTime = Temporal.ZonedDateTime.from('2023-10-27T10:30:00+08:00[Asia/Shanghai]');

// 添加 2 天
const futureZonedDateTime = zonedDateTime.add({ days: 2 });
console.log(futureZonedDateTime.toString()); // 输出添加两天后的 ZonedDateTime

// 减去 1 小时
const pastZonedDateTime = zonedDateTime.subtract({ hours: 1 });
console.log(pastZonedDateTime.toString()); // 输出减去一小时后的 ZonedDateTime

// 计算到另一个 ZonedDateTime 的时间差
const anotherZonedDateTime = Temporal.ZonedDateTime.from('2023-10-28T12:00:00+08:00[Asia/Shanghai]');
const durationUntil = zonedDateTime.until(anotherZonedDateTime);
console.log(durationUntil.toString()); // 输出时间差

// 获取 ISO 字段
const isoFields = zonedDateTime.getISOFields();
console.log(isoFields);

// 转换为 Instant
const instant = zonedDateTime.toInstant();
console.log(instant.toString());

// 获取当前 Instant
const nowInstant = Temporal.Instant.now();
console.log(nowInstant.toString());

// 从纪元毫秒创建 Instant
const instantFromEpoch = Temporal.Instant.fromEpochMilliseconds(1677777777000);
console.log(instantFromEpoch.toString());

// 比较两个 Instant
const instant1 = Temporal.Instant.fromEpochSeconds(100);
const instant2 = Temporal.Instant.fromEpochSeconds(200);
console.log(Temporal.Instant.compare(instant1, instant2)); // 输出 -1 (instant1 在 instant2 之前)
```

**代码逻辑推理与假设输入输出:**

**示例 1: `AddDurationToOrSubtractDurationFromZonedDateTime` (假设是加法)**

**假设输入:**

* `zoned_date_time`: 一个表示 `2023-10-27T10:30:00+08:00[Asia/Shanghai]` 的 `JSTemporalZonedDateTime` 对象。
* `temporal_duration_like`: 一个表示 `{ days: 2, hours: 1 }` 的 JavaScript 对象。
* `options`:  `undefined`。
* `method_name`: `"Temporal.ZonedDateTime.prototype.add"`。

**推断的输出:**

一个新的 `JSTemporalZonedDateTime` 对象，表示 `2023-10-29T11:30:00+08:00[Asia/Shanghai]` (日期增加两天，小时增加一小时)。由于时区是 `Asia/Shanghai`，V8 会处理夏令时等复杂情况，确保时间点的正确性。

**示例 2: `DifferenceTemporalZonedDateTime` (假设是 `until`)**

**假设输入:**

* `operation`: `TimePreposition::kUntil`。
* `zoned_date_time`: 一个表示 `2023-10-27T10:30:00+08:00[Asia/Shanghai]` 的 `JSTemporalZonedDateTime` 对象。
* `other_obj`: 一个表示 `2023-10-28T12:00:00+08:00[Asia/Shanghai]` 的 `JSTemporalZonedDateTime` 对象。
* `options`: `undefined`。
* `method_name`: `"Temporal.ZonedDateTime.prototype.until"`。

**推断的输出:**

一个 `JSTemporalDuration` 对象，表示 `{ days: 1, hours: 1, minutes: 30 }` (从 `zoned_date_time` 到 `other_obj` 的时间差)。

**用户常见的编程错误:**

* **时区混淆:**  在不同的时区之间进行计算时，没有明确指定时区或错误地假设时区。例如，在没有考虑时区的情况下，简单地将一个日期时间对象的时区信息替换为另一个时区。
    ```javascript
    // 错误示例：假设两个日期时间在同一时间点
    const zdt1 = Temporal.ZonedDateTime.from('2023-10-27T10:00:00+08:00[Asia/Shanghai]');
    const zdt2 = Temporal.ZonedDateTime.from(zdt1.toString().replace('+08:00[Asia/Shanghai]', '-05:00[America/New_York]'));
    console.log(zdt1.toInstant().toString() === zdt2.toInstant().toString()); // 结果可能是 false，因为时间点不同
    ```
* **单位错误:** 在进行时间加减或比较时，使用了不合适的单位，导致计算结果不符合预期。例如，尝试用月份来精确计算跨越年份的时间差，而不考虑每个月的天数不同。
    ```javascript
    const zdtStart = Temporal.ZonedDateTime.from('2023-01-31T10:00:00+08:00[Asia/Shanghai]');
    const zdtEnd = Temporal.ZonedDateTime.from('2023-03-01T10:00:00+08:00[Asia/Shanghai]');
    const duration = zdtStart.until(zdtEnd, { largestUnit: 'month' });
    console.log(duration.months); // 可能不是期望的 2，因为计算方式会考虑实际经过的时间
    ```
* **舍入错误:** 在需要进行时间精度控制时，没有正确使用舍入选项，导致结果不准确。
    ```javascript
    const instant = Temporal.Instant.fromEpochSeconds(100.5);
    // 没有指定舍入模式，默认的舍入行为可能不是期望的
    // 需要使用 roundTo 方法并指定 roundingIncrement 和 roundingMode
    ```

**第 24 部分，共 25 部分的功能归纳:**

作为 25 个部分中的第 24 部分，这个代码片段几乎涵盖了 `Temporal.ZonedDateTime` 和 `Temporal.Instant` 对象的核心功能，包括创建、算术运算、比较、属性获取、以及与其他 Temporal 类型之间的转换。考虑到这是倒数第二部分，可以推测最后一部分可能包含一些不太常用的功能、内部辅助函数或者与其他 Temporal 类型的集成。总体而言，这个文件在 V8 的 Temporal API 实现中扮演着至关重要的角色，负责处理带有时区信息的日期时间和瞬时时间的各种操作。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第24部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
on.[[Years]], sign x duration.[[Months]], sign x
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