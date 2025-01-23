Response: The user wants a summary of the C++ code in `v8/src/objects/js-temporal-objects.cc`, specifically part 6 of 13. I need to understand the functionality implemented in this section and identify any connections to JavaScript's Temporal API. If a connection exists, I should provide a JavaScript example.

Based on the provided code snippets, this section seems to focus on the implementation of the `Temporal.Duration` object's methods, particularly those involving calculations, rounding, and comparisons with relative temporal objects (like `Temporal.PlainDate` and `Temporal.ZonedDateTime`).

Here's a breakdown of the key methods and their potential JavaScript equivalents:

- **`Total`**: Calculates the total value of the duration in a specific unit. This likely corresponds to `Temporal.Duration.prototype.total()`.
- **`ToPartialDuration`**:  Extracts duration components from a given object. This seems like an internal helper function used by other methods.
- **`With`**: Creates a new `Temporal.Duration` with some components replaced. This corresponds to `Temporal.Duration.prototype.with()`.
- **`Sign`**: Returns the sign of the duration. This corresponds to `Temporal.Duration.prototype.sign`.
- **`Blank`**: Checks if the duration is zero for all components. This corresponds to `Temporal.Duration.prototype.blank`.
- **`CreateNegatedDurationRecord` and `CreateNegatedTemporalDuration`**:  Creates a negated duration. This corresponds to `Temporal.Duration.prototype.negated()`.
- **`Abs`**: Creates the absolute value of the duration. This corresponds to `Temporal.Duration.prototype.abs()`.
- **`ToRelativeTemporalObject`**:  Converts an object to a relative temporal object. This seems like an internal helper function.
- **`DefaultTemporalLargestUnit`**: Determines the largest unit present in a duration. Likely an internal helper.
- **`DifferenceZonedDateTime`**: Calculates the difference between two `Temporal.ZonedDateTime` instances as a `Temporal.Duration`. This is likely an internal helper for operations involving `Temporal.ZonedDateTime`.
- **`AddDuration`**: Adds two durations together, potentially with a relative context. This seems related to `Temporal.Duration.prototype.add()`.
- **`AddDurationToOrSubtractDurationFromDuration`**: A helper function for adding or subtracting durations.
- **`Add`**: Adds another duration to the current duration. This corresponds to `Temporal.Duration.prototype.add()`.
- **`Subtract`**: Subtracts another duration from the current duration. This corresponds to `Temporal.Duration.prototype.subtract()`.
- **`ToJSON`**: Converts the duration to a JSON string. This corresponds to `Temporal.Duration.prototype.toJSON()`.
- **`ToLocaleString`**: Converts the duration to a locale-specific string. This corresponds to `Temporal.Duration.prototype.toLocaleString()`.
- **`MoveRelativeZonedDateTime`**: Moves a `Temporal.ZonedDateTime` by a given date duration. An internal helper.
- **`DaysUntil`**: Calculates the number of days between two `Temporal.PlainDate` instances. An internal helper.
- **`MoveRelativeDate`**: Moves a `Temporal.PlainDate` by a given duration. An internal helper.
- **`RoundDuration`**: Rounds a duration to a specific unit. This likely corresponds to `Temporal.Duration.prototype.round()`.

I will now synthesize this information into a concise summary and provide JavaScript examples where applicable.
这个C++源代码文件 `v8/src/objects/js-temporal-objects.cc` 的第6部分，主要负责实现 `Temporal.Duration` 对象的一些核心方法，这些方法涉及到**对 Duration 对象进行各种计算和操作**，并且在某些情况下需要考虑相对的 Temporal 对象（如 `Temporal.PlainDate` 或 `Temporal.ZonedDateTime`）。

以下是该部分代码的主要功能归纳：

1. **`Total` 方法的实现**: 计算 `Temporal.Duration` 对象在指定单位下的总值。例如，将一个包含年、月、日的 Duration 转换为总共多少天。

2. **`ToPartialDuration` 函数**:  将一个类似 Duration 的对象转换为标准的 Duration 记录，用于提取 Duration 的各个组成部分。

3. **`With` 方法的实现**:  创建一个新的 `Temporal.Duration` 对象，其部分属性值被传入的对象覆盖。

4. **`Sign` 属性的实现**: 返回 `Temporal.Duration` 对象的符号（正数返回 1，负数返回 -1，零返回 0）。

5. **`Blank` 属性的实现**:  判断 `Temporal.Duration` 对象是否为空（所有组成部分都为零）。

6. **`Negated` 方法的实现**: 创建一个新的 `Temporal.Duration` 对象，其所有组成部分的符号与原对象相反。

7. **`Abs` 方法的实现**: 创建一个新的 `Temporal.Duration` 对象，其所有组成部分都是原对象对应部分的绝对值。

8. **`ToRelativeTemporalObject` 函数**: 将一个对象转换为可以作为相对参考的 Temporal 对象 (`Temporal.PlainDate` 或 `Temporal.ZonedDateTime`)。

9. **`DefaultTemporalLargestUnit` 函数**:  确定 `Temporal.Duration` 对象中存在的最大时间单位（例如，如果年不为零，则返回 "year"）。

10. **`DifferenceZonedDateTime` 函数**: 计算两个 `Temporal.ZonedDateTime` 之间的差值，返回一个 `Temporal.Duration` 对象。

11. **`AddDuration` 函数**:  将两个 Duration 对象相加，可以指定一个相对的 Temporal 对象作为上下文，用于处理日期单位的加法。

12. **`AddDurationToOrSubtractDurationFromDuration` 函数**:  作为 `Add` 和 `Subtract` 方法的通用实现，处理 Duration 的加法和减法操作。

13. **`Add` 方法的实现**:  将另一个 Duration 对象加到当前 Duration 对象上。

14. **`Subtract` 方法的实现**:  从当前 Duration 对象中减去另一个 Duration 对象。

15. **`ToJSON` 方法的实现**:  将 `Temporal.Duration` 对象转换为 JSON 字符串表示。

16. **`ToLocaleString` 方法的实现**:  将 `Temporal.Duration` 对象转换为本地化字符串表示。

17. **`MoveRelativeZonedDateTime` 函数**:  将一个 `Temporal.ZonedDateTime` 对象按照给定的日期 Duration 移动。

18. **`DaysUntil` 函数**:  计算两个 `Temporal.PlainDate` 之间相差的天数。

19. **`MoveRelativeDate` 函数**:  将一个 `Temporal.PlainDate` 对象按照给定的 Duration 移动。

20. **`RoundDuration` 函数**:  将 `Temporal.Duration` 对象按照指定的单位和舍入模式进行舍入。

**与 Javascript 功能的关系及示例:**

这个 C++ 文件是 V8 引擎的一部分，V8 引擎是 Chrome 和 Node.js 的 JavaScript 引擎。因此，这个文件中的 C++ 代码直接实现了 JavaScript 中 `Temporal` API 的 `Temporal.Duration` 对象的功能。

以下是一些与文件中 C++ 代码对应的 JavaScript 示例：

**1. `Total` 方法:**

```javascript
const duration = new Temporal.Duration(1, 2, 0, 10, 5, 30, 0, 0, 0);
const totalDays = duration.total('days');
console.log(totalDays); // 输出该 Duration 换算成总共有多少天，会考虑月份的长度
```

**2. `With` 方法:**

```javascript
const duration = new Temporal.Duration(1, 2, 0, 10);
const newDuration = duration.with({ months: 5, days: 15 });
console.log(newDuration.toString()); // 输出 P1Y5M15D
```

**3. `Sign` 属性:**

```javascript
const positiveDuration = new Temporal.Duration(1, 0, 0, 0);
const negativeDuration = new Temporal.Duration(-1, 0, 0, 0);
const zeroDuration = new Temporal.Duration(0, 0, 0, 0);

console.log(positiveDuration.sign); // 输出 1
console.log(negativeDuration.sign); // 输出 -1
console.log(zeroDuration.sign);     // 输出 0
```

**4. `Blank` 属性:**

```javascript
const blankDuration = new Temporal.Duration(0, 0, 0, 0);
const nonBlankDuration = new Temporal.Duration(1, 0, 0, 0);

console.log(blankDuration.blank);    // 输出 true
console.log(nonBlankDuration.blank); // 输出 false
```

**5. `Negated` 方法:**

```javascript
const duration = new Temporal.Duration(1, -2, 3, -4);
const negatedDuration = duration.negated();
console.log(negatedDuration.toString()); // 输出 P-1Y2M-3DT4H
```

**6. `Abs` 方法:**

```javascript
const duration = new Temporal.Duration(1, -2, 3, -4);
const absoluteDuration = duration.abs();
console.log(absoluteDuration.toString()); // 输出 P1Y2M3DT4H
```

**7. `Add` 方法:**

```javascript
const duration1 = new Temporal.Duration(1, 0, 0, 5);
const duration2 = new Temporal.Duration(0, 2, 0, 3);
const result = duration1.add(duration2);
console.log(result.toString()); // 输出 P1Y2M8D
```

**8. `Subtract` 方法:**

```javascript
const duration1 = new Temporal.Duration(1, 2, 0, 10);
const duration2 = new Temporal.Duration(0, 1, 0, 5);
const result = duration1.subtract(duration2);
console.log(result.toString()); // 输出 P1M5D
```

**9. `ToJSON` 方法:**

```javascript
const duration = new Temporal.Duration(1, 2, 0, 10, 5, 30);
const jsonString = duration.toJSON();
console.log(jsonString); // 输出 "P1Y2M10DT5H30M"
```

**10. `ToLocaleString` 方法:**

```javascript
const duration = new Temporal.Duration(1, 2, 0, 10, 5, 30);
const localeString = duration.toLocaleString('zh-CN');
console.log(localeString); // 输出符合中文本地化习惯的 Duration 字符串 (具体输出可能因实现而异)
```

总而言之，这个 C++ 代码文件是 `Temporal.Duration` 对象在 V8 引擎中的底层实现，它定义了 Duration 对象的各种行为和计算逻辑，这些逻辑直接被 JavaScript 中的 `Temporal.Duration` API 调用。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第6部分，共13部分，请归纳一下它的功能
```

### 源代码
```
>months()),
                                 Object::NumberValue(duration->weeks()),
                                 Object::NumberValue(duration->days())},
                                largest_unit, relative_to, method_name),
      Handle<JSTemporalDuration>());
  // 22. Let roundResult be (? RoundDuration(unbalanceResult.[[Years]],
  // unbalanceResult.[[Months]], unbalanceResult.[[Weeks]],
  // unbalanceResult.[[Days]], duration.[[Hours]], duration.[[Minutes]],
  // duration.[[Seconds]], duration.[[Milliseconds]], duration.[[Microseconds]],
  // duration.[[Nanoseconds]], roundingIncrement, smallestUnit, roundingMode,
  // relativeTo)).[[DurationRecord]].
  DurationRecordWithRemainder round_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, round_result,
      RoundDuration(
          isolate,
          {unbalance_result.years,
           unbalance_result.months,
           unbalance_result.weeks,
           {unbalance_result.days, Object::NumberValue(duration->hours()),
            Object::NumberValue(duration->minutes()),
            Object::NumberValue(duration->seconds()),
            Object::NumberValue(duration->milliseconds()),
            Object::NumberValue(duration->microseconds()),
            Object::NumberValue(duration->nanoseconds())}},
          rounding_increment, smallest_unit, rounding_mode, relative_to,
          method_name),
      Handle<JSTemporalDuration>());

  // 23. Let adjustResult be ? AdjustRoundedDurationDays(roundResult.[[Years]],
  // roundResult.[[Months]], roundResult.[[Weeks]], roundResult.[[Days]],
  // roundResult.[[Hours]], roundResult.[[Minutes]], roundResult.[[Seconds]],
  // roundResult.[[Milliseconds]], roundResult.[[Microseconds]],
  // roundResult.[[Nanoseconds]], roundingIncrement, smallestUnit, roundingMode,
  // relativeTo).
  DurationRecord adjust_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, adjust_result,
      AdjustRoundedDurationDays(isolate, round_result.record,
                                rounding_increment, smallest_unit,
                                rounding_mode, relative_to, method_name),
      Handle<JSTemporalDuration>());
  // 24. Let balanceResult be ? BalanceDurationRelative(adjustResult.[[Years]],
  // adjustResult.[[Months]], adjustResult.[[Weeks]], adjustResult.[[Days]],
  // largestUnit, relativeTo).
  DateDurationRecord balance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, balance_result,
      BalanceDurationRelative(
          isolate,
          {adjust_result.years, adjust_result.months, adjust_result.weeks,
           adjust_result.time_duration.days},
          largest_unit, relative_to, method_name),
      Handle<JSTemporalDuration>());
  // 25. If Type(relativeTo) is Object and relativeTo has an
  // [[InitializedTemporalZonedDateTime]] internal slot, then
  if (IsJSTemporalZonedDateTime(*relative_to)) {
    // a. Set relativeTo to ? MoveRelativeZonedDateTime(relativeTo,
    // balanceResult.[[Years]], balanceResult.[[Months]],
    // balanceResult.[[Weeks]], 0).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, relative_to,
        MoveRelativeZonedDateTime(isolate,
                                  Cast<JSTemporalZonedDateTime>(relative_to),
                                  {balance_result.years, balance_result.months,
                                   balance_result.weeks, 0},
                                  method_name));
  }
  // 26. Let result be ? BalanceDuration(balanceResult.[[Days]],
  // adjustResult.[[Hours]], adjustResult.[[Minutes]], adjustResult.[[Seconds]],
  // adjustResult.[[Milliseconds]], adjustResult.[[Microseconds]],
  // adjustResult.[[Nanoseconds]], largestUnit, relativeTo).
  TimeDurationRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      BalanceDuration(isolate, largest_unit, relative_to,
                      {balance_result.days, adjust_result.time_duration.hours,
                       adjust_result.time_duration.minutes,
                       adjust_result.time_duration.seconds,
                       adjust_result.time_duration.milliseconds,
                       adjust_result.time_duration.microseconds,
                       adjust_result.time_duration.nanoseconds},
                      method_name),
      Handle<JSTemporalDuration>());
  // 27. Return ! CreateTemporalDuration(balanceResult.[[Years]],
  // balanceResult.[[Months]], balanceResult.[[Weeks]], result.[[Days]],
  // result.[[Hours]], result.[[Minutes]], result.[[Seconds]],
  // result.[[Milliseconds]], result.[[Microseconds]], result.[[Nanoseconds]]).
  return CreateTemporalDuration(isolate,
                                {balance_result.years, balance_result.months,
                                 balance_result.weeks, result})
      .ToHandleChecked();
}

// #sec-temporal.duration.prototype.total
MaybeHandle<Object> JSTemporalDuration::Total(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration,
    Handle<Object> total_of_obj) {
  const char* method_name = "Temporal.Duration.prototype.total";
  Factory* factory = isolate->factory();
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. If totalOf is undefined, throw a TypeError exception.
  if (IsUndefined(*total_of_obj, isolate)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }

  Handle<JSReceiver> total_of;
  // 4. If Type(totalOf) is String, then
  if (IsString(*total_of_obj)) {
    // a. Let paramString be totalOf.
    Handle<String> param_string = Cast<String>(total_of_obj);
    // b. Set totalOf to ! OrdinaryObjectCreate(null).
    total_of = factory->NewJSObjectWithNullProto();
    // c. Perform ! CreateDataPropertyOrThrow(total_of, "unit", paramString).
    CHECK(JSReceiver::CreateDataProperty(isolate, total_of,
                                         factory->unit_string(), param_string,
                                         Just(kThrowOnError))
              .FromJust());
  } else {
    // 5. Set totalOf to ? GetOptionsObject(totalOf).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, total_of,
        GetOptionsObject(isolate, total_of_obj, method_name));
  }

  // 6. Let relativeTo be ? ToRelativeTemporalObject(totalOf).
  Handle<Object> relative_to;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, relative_to,
      ToRelativeTemporalObject(isolate, total_of, method_name));
  // 7. Let unit be ? GetTemporalUnit(totalOf, "unit", datetime, required).
  Unit unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, unit,
      GetTemporalUnit(isolate, total_of, "unit", UnitGroup::kDateTime,
                      Unit::kNotPresent, true, method_name),
      Handle<Object>());
  // 8. Let unbalanceResult be ? UnbalanceDurationRelative(duration.[[Years]],
  // duration.[[Months]], duration.[[Weeks]], duration.[[Days]], unit,
  // relativeTo).
  DateDurationRecord unbalance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, unbalance_result,
      UnbalanceDurationRelative(isolate,
                                {Object::NumberValue(duration->years()),
                                 Object::NumberValue(duration->months()),
                                 Object::NumberValue(duration->weeks()),
                                 Object::NumberValue(duration->days())},
                                unit, relative_to, method_name),
      Handle<Object>());

  // 9. Let intermediate be undefined.
  Handle<Object> intermediate = factory->undefined_value();

  // 8. If relativeTo has an [[InitializedTemporalZonedDateTime]] internal slot,
  // then
  if (IsJSTemporalZonedDateTime(*relative_to)) {
    // a. Set intermediate to ? MoveRelativeZonedDateTime(relativeTo,
    // unbalanceResult.[[Years]], unbalanceResult.[[Months]],
    // unbalanceResult.[[Weeks]], 0).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, intermediate,
        MoveRelativeZonedDateTime(
            isolate, Cast<JSTemporalZonedDateTime>(relative_to),
            {unbalance_result.years, unbalance_result.months,
             unbalance_result.weeks, 0},
            method_name));
  }

  // 11. Let balanceResult be ?
  // BalancePossiblyInfiniteDuration(unbalanceResult.[[Days]],
  // duration.[[Hours]], duration.[[Minutes]], duration.[[Seconds]],
  // duration.[[Milliseconds]], duration.[[Microseconds]],
  // duration.[[Nanoseconds]], unit, intermediate).
  BalancePossiblyInfiniteDurationResult balance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, balance_result,
      BalancePossiblyInfiniteDuration(
          isolate, unit, intermediate,
          {unbalance_result.days, Object::NumberValue(duration->hours()),
           Object::NumberValue(duration->minutes()),
           Object::NumberValue(duration->seconds()),
           Object::NumberValue(duration->milliseconds()),
           Object::NumberValue(duration->microseconds()),
           Object::NumberValue(duration->nanoseconds())},
          method_name),
      Handle<Object>());
  // 12. If balanceResult is positive overflow, return +∞𝔽.
  if (balance_result.overflow == BalanceOverflow::kPositive) {
    return factory->infinity_value();
  }
  // 13. If balanceResult is negative overflow, return -∞𝔽.
  if (balance_result.overflow == BalanceOverflow::kNegative) {
    return factory->minus_infinity_value();
  }
  // 14. Assert: balanceResult is a Time Duration Record.
  DCHECK_EQ(balance_result.overflow, BalanceOverflow::kNone);
  // 15. Let roundRecord be ? RoundDuration(unbalanceResult.[[Years]],
  // unbalanceResult.[[Months]], unbalanceResult.[[Weeks]],
  // balanceResult.[[Days]], balanceResult.[[Hours]], balanceResult.[[Minutes]],
  // balanceResult.[[Seconds]], balanceResult.[[Milliseconds]],
  // balanceResult.[[Microseconds]], balanceResult.[[Nanoseconds]], 1, unit,
  // "trunc", relativeTo).
  DurationRecordWithRemainder round_record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, round_record,
      RoundDuration(isolate,
                    {unbalance_result.years, unbalance_result.months,
                     unbalance_result.weeks, balance_result.value},
                    1, unit, RoundingMode::kTrunc, relative_to, method_name),
      Handle<Object>());
  // 16. Let roundResult be roundRecord.[[DurationRecord]].
  DurationRecord& round_result = round_record.record;

  double whole;
  switch (unit) {
    // 17. If unit is "year", then
    case Unit::kYear:
      // a. Let whole be roundResult.[[Years]].
      whole = round_result.years;
      break;
    // 18. If unit is "month", then
    case Unit::kMonth:
      // a. Let whole be roundResult.[[Months]].
      whole = round_result.months;
      break;
    // 19. If unit is "week", then
    case Unit::kWeek:
      // a. Let whole be roundResult.[[Weeks]].
      whole = round_result.weeks;
      break;
    // 20. If unit is "day", then
    case Unit::kDay:
      // a. Let whole be roundResult.[[Days]].
      whole = round_result.time_duration.days;
      break;
    // 21. If unit is "hour", then
    case Unit::kHour:
      // a. Let whole be roundResult.[[Hours]].
      whole = round_result.time_duration.hours;
      break;
    // 22. If unit is "minute", then
    case Unit::kMinute:
      // a. Let whole be roundResult.[[Minutes]].
      whole = round_result.time_duration.minutes;
      break;
    // 23. If unit is "second", then
    case Unit::kSecond:
      // a. Let whole be roundResult.[[Seconds]].
      whole = round_result.time_duration.seconds;
      break;
    // 24. If unit is "millisecond", then
    case Unit::kMillisecond:
      // a. Let whole be roundResult.[[Milliseconds]].
      whole = round_result.time_duration.milliseconds;
      break;
    // 25. If unit is "microsecond", then
    case Unit::kMicrosecond:
      // a. Let whole be roundResult.[[Microseconds]].
      whole = round_result.time_duration.microseconds;
      break;
    // 26. If unit is "naoosecond", then
    case Unit::kNanosecond:
      // a. Let whole be roundResult.[[Nanoseconds]].
      whole = round_result.time_duration.nanoseconds;
      break;
    default:
      UNREACHABLE();
  }
  // 27. Return 𝔽(whole + roundRecord.[[Remainder]]).
  return factory->NewNumber(whole + round_record.remainder);
}

namespace temporal {
// #sec-temporal-topartialduration
Maybe<DurationRecord> ToPartialDuration(
    Isolate* isolate, Handle<Object> temporal_duration_like_obj,
    const DurationRecord& input) {
  // 1. If Type(temporalDurationLike) is not Object, then
  if (!IsJSReceiver(*temporal_duration_like_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<DurationRecord>());
  }
  Handle<JSReceiver> temporal_duration_like =
      Cast<JSReceiver>(temporal_duration_like_obj);

  // 2. Let result be a new partial Duration Record with each field set to
  // undefined.
  DurationRecord result = input;

  // 3. Let any be false.
  bool any = false;

  // Table 8: Duration Record Fields
  // #table-temporal-duration-record-fields
  // 4. For each row of Table 8, except the header row, in table order, do
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, any,
      IterateDurationRecordFieldsTable(
          isolate, temporal_duration_like,
          [](Isolate* isolate, Handle<JSReceiver> temporal_duration_like,
             Handle<String> prop, double* field) -> Maybe<bool> {
            bool not_undefined = false;
            // a. Let prop be the Property value of the current row.
            Handle<Object> val;
            // b. Let val be ? Get(temporalDurationLike, prop).
            ASSIGN_RETURN_ON_EXCEPTION_VALUE(
                isolate, val,
                JSReceiver::GetProperty(isolate, temporal_duration_like, prop),
                Nothing<bool>());
            // c. If val is not undefined, then
            if (!IsUndefined(*val)) {
              // i. Set any to true.
              not_undefined = true;
              // ii. Let val be 𝔽(? ToIntegerWithoutRounding(val)).
              // iii. Set result's field whose name is the Field Name value of
              // the current row to val.
              MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
                  isolate, *field, ToIntegerWithoutRounding(isolate, val),
                  Nothing<bool>());
            }
            return Just(not_undefined);
          },
          &result),
      Nothing<DurationRecord>());

  // 5. If any is false, then
  if (!any) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<DurationRecord>());
  }
  // 6. Return result.
  return Just(result);
}

}  // namespace temporal

// #sec-temporal.duration.prototype.with
MaybeHandle<JSTemporalDuration> JSTemporalDuration::With(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration,
    Handle<Object> temporal_duration_like) {
  DurationRecord partial;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, partial,
      temporal::ToPartialDuration(
          isolate, temporal_duration_like,
          {Object::NumberValue(duration->years()),
           Object::NumberValue(duration->months()),
           Object::NumberValue(duration->weeks()),
           {Object::NumberValue(duration->days()),
            Object::NumberValue(duration->hours()),
            Object::NumberValue(duration->minutes()),
            Object::NumberValue(duration->seconds()),
            Object::NumberValue(duration->milliseconds()),
            Object::NumberValue(duration->microseconds()),
            Object::NumberValue(duration->nanoseconds())}}),
      Handle<JSTemporalDuration>());

  // 24. Return ? CreateTemporalDuration(years, months, weeks, days, hours,
  // minutes, seconds, milliseconds, microseconds, nanoseconds).
  return CreateTemporalDuration(isolate, partial);
}

// #sec-get-temporal.duration.prototype.sign
MaybeHandle<Smi> JSTemporalDuration::Sign(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. Return ! DurationSign(duration.[[Years]], duration.[[Months]],
  // duration.[[Weeks]], duration.[[Days]], duration.[[Hours]],
  // duration.[[Minutes]], duration.[[Seconds]], duration.[[Milliseconds]],
  // duration.[[Microseconds]], duration.[[Nanoseconds]]).
  return handle(Smi::FromInt(DurationRecord::Sign(
                    {Object::NumberValue(duration->years()),
                     Object::NumberValue(duration->months()),
                     Object::NumberValue(duration->weeks()),
                     {Object::NumberValue(duration->days()),
                      Object::NumberValue(duration->hours()),
                      Object::NumberValue(duration->minutes()),
                      Object::NumberValue(duration->seconds()),
                      Object::NumberValue(duration->milliseconds()),
                      Object::NumberValue(duration->microseconds()),
                      Object::NumberValue(duration->nanoseconds())}})),
                isolate);
}

// #sec-get-temporal.duration.prototype.blank
MaybeHandle<Oddball> JSTemporalDuration::Blank(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. Let sign be ! DurationSign(duration.[[Years]], duration.[[Months]],
  // duration.[[Weeks]], duration.[[Days]], duration.[[Hours]],
  // duration.[[Minutes]], duration.[[Seconds]], duration.[[Milliseconds]],
  // duration.[[Microseconds]], duration.[[Nanoseconds]]).
  // 4. If sign = 0, return true.
  // 5. Return false.
  int32_t sign =
      DurationRecord::Sign({Object::NumberValue(duration->years()),
                            Object::NumberValue(duration->months()),
                            Object::NumberValue(duration->weeks()),
                            {Object::NumberValue(duration->days()),
                             Object::NumberValue(duration->hours()),
                             Object::NumberValue(duration->minutes()),
                             Object::NumberValue(duration->seconds()),
                             Object::NumberValue(duration->milliseconds()),
                             Object::NumberValue(duration->microseconds()),
                             Object::NumberValue(duration->nanoseconds())}});
  return isolate->factory()->ToBoolean(sign == 0);
}

namespace {
// #sec-temporal-createnegateddurationrecord
// see https://github.com/tc39/proposal-temporal/pull/2281
Maybe<DurationRecord> CreateNegatedDurationRecord(
    Isolate* isolate, const DurationRecord& duration) {
  return CreateDurationRecord(
      isolate,
      {-duration.years,
       -duration.months,
       -duration.weeks,
       {-duration.time_duration.days, -duration.time_duration.hours,
        -duration.time_duration.minutes, -duration.time_duration.seconds,
        -duration.time_duration.milliseconds,
        -duration.time_duration.microseconds,
        -duration.time_duration.nanoseconds}});
}

// #sec-temporal-createnegatedtemporalduration
MaybeHandle<JSTemporalDuration> CreateNegatedTemporalDuration(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: Type(duration) is Object.
  // 2. Assert: duration has an [[InitializedTemporalDuration]] internal slot.
  // 3. Return ! CreateTemporalDuration(−duration.[[Years]],
  // −duration.[[Months]], −duration.[[Weeks]], −duration.[[Days]],
  // −duration.[[Hours]], −duration.[[Minutes]], −duration.[[Seconds]],
  // −duration.[[Milliseconds]], −duration.[[Microseconds]],
  // −duration.[[Nanoseconds]]).
  return CreateTemporalDuration(
             isolate, {-Object::NumberValue(duration->years()),
                       -Object::NumberValue(duration->months()),
                       -Object::NumberValue(duration->weeks()),
                       {-Object::NumberValue(duration->days()),
                        -Object::NumberValue(duration->hours()),
                        -Object::NumberValue(duration->minutes()),
                        -Object::NumberValue(duration->seconds()),
                        -Object::NumberValue(duration->milliseconds()),
                        -Object::NumberValue(duration->microseconds()),
                        -Object::NumberValue(duration->nanoseconds())}})
      .ToHandleChecked();
}

}  // namespace

// #sec-temporal.duration.prototype.negated
MaybeHandle<JSTemporalDuration> JSTemporalDuration::Negated(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  // Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).

  // 3. Return ! CreateNegatedTemporalDuration(duration).
  return CreateNegatedTemporalDuration(isolate, duration).ToHandleChecked();
}

// #sec-temporal.duration.prototype.abs
MaybeHandle<JSTemporalDuration> JSTemporalDuration::Abs(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. Return ? CreateTemporalDuration(abs(duration.[[Years]]),
  // abs(duration.[[Months]]), abs(duration.[[Weeks]]), abs(duration.[[Days]]),
  // abs(duration.[[Hours]]), abs(duration.[[Minutes]]),
  // abs(duration.[[Seconds]]), abs(duration.[[Milliseconds]]),
  // abs(duration.[[Microseconds]]), abs(duration.[[Nanoseconds]])).
  return CreateTemporalDuration(
      isolate, {std::abs(Object::NumberValue(duration->years())),
                std::abs(Object::NumberValue(duration->months())),
                std::abs(Object::NumberValue(duration->weeks())),
                {std::abs(Object::NumberValue(duration->days())),
                 std::abs(Object::NumberValue(duration->hours())),
                 std::abs(Object::NumberValue(duration->minutes())),
                 std::abs(Object::NumberValue(duration->seconds())),
                 std::abs(Object::NumberValue(duration->milliseconds())),
                 std::abs(Object::NumberValue(duration->microseconds())),
                 std::abs(Object::NumberValue(duration->nanoseconds()))}});
}

namespace {

// #sec-temporal-interpretisodatetimeoffset
MaybeHandle<BigInt> InterpretISODateTimeOffset(
    Isolate* isolate, const DateTimeRecord& data,
    OffsetBehaviour offset_behaviour, int64_t offset_nanoseconds,
    Handle<JSReceiver> time_zone, Disambiguation disambiguation,
    Offset offset_option, MatchBehaviour match_behaviour,
    const char* method_name);

// #sec-temporal-interprettemporaldatetimefields
Maybe<temporal::DateTimeRecord> InterpretTemporalDateTimeFields(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<JSReceiver> fields,
    Handle<Object> options, const char* method_name);

// #sec-temporal-torelativetemporalobject
MaybeHandle<Object> ToRelativeTemporalObject(Isolate* isolate,
                                             Handle<JSReceiver> options,
                                             const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 1. Assert: Type(options) is Object.
  // 2. Let value be ? Get(options, "relativeTo").
  Handle<Object> value_obj;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, value_obj,
      JSReceiver::GetProperty(isolate, options, factory->relativeTo_string()));
  // 3. If value is undefined, then
  if (IsUndefined(*value_obj)) {
    // a. Return value.
    return value_obj;
  }
  // 4. Let offsetBehaviour be option.
  OffsetBehaviour offset_behaviour = OffsetBehaviour::kOption;

  // 5. Let matchBehaviour be match exactly.
  MatchBehaviour match_behaviour = MatchBehaviour::kMatchExactly;

  Handle<Object> time_zone_obj = factory->undefined_value();
  Handle<Object> offset_string_obj;
  temporal::DateTimeRecord result;
  Handle<JSReceiver> calendar;
  // 6. If Type(value) is Object, then
  if (IsJSReceiver(*value_obj)) {
    Handle<JSReceiver> value = Cast<JSReceiver>(value_obj);
    // a. If value has either an [[InitializedTemporalDate]] or
    // [[InitializedTemporalZonedDateTime]] internal slot, then
    if (IsJSTemporalPlainDate(*value) || IsJSTemporalZonedDateTime(*value)) {
      // i. Return value.
      return value;
    }
    // b. If value has an [[InitializedTemporalDateTime]] internal slot, then
    if (IsJSTemporalPlainDateTime(*value)) {
      auto date_time_value = Cast<JSTemporalPlainDateTime>(value);
      // i. Return ? CreateTemporalDateTime(value.[[ISOYear]],
      // value.[[ISOMonth]], value.[[ISODay]],
      // value.[[Calendar]]).
      return CreateTemporalDate(
          isolate,
          {date_time_value->iso_year(), date_time_value->iso_month(),
           date_time_value->iso_day()},
          handle(date_time_value->calendar(), isolate));
    }
    // c. Let calendar be ? GetTemporalCalendarWithISODefault(value).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        GetTemporalCalendarWithISODefault(isolate, value, method_name));
    // d. Let fieldNames be ? CalendarFields(calendar, «  "day", "hour",
    // "microsecond", "millisecond", "minute", "month", "monthCode",
    // "nanosecond", "second", "year" »).
    Handle<FixedArray> field_names = All10UnitsInFixedArray(isolate);
    ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                               CalendarFields(isolate, calendar, field_names));
    // e. Let fields be ? PrepareTemporalFields(value, fieldNames, «»).
    Handle<JSReceiver> fields;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, fields,
        PrepareTemporalFields(isolate, value, field_names,
                              RequiredFields::kNone));
    // f. Let dateOptions be ! OrdinaryObjectCreate(null).
    Handle<JSObject> date_options = factory->NewJSObjectWithNullProto();
    // g. Perform ! CreateDataPropertyOrThrow(dateOptions, "overflow",
    // "constrain").
    CHECK(JSReceiver::CreateDataProperty(
              isolate, date_options, factory->overflow_string(),
              factory->constrain_string(), Just(kThrowOnError))
              .FromJust());
    // h. Let result be ? InterpretTemporalDateTimeFields(calendar, fields,
    // dateOptions).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        InterpretTemporalDateTimeFields(isolate, calendar, fields, date_options,
                                        method_name),
        Handle<Object>());
    // i. Let offsetString be ? Get(value, "offset").
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, offset_string_obj,
        JSReceiver::GetProperty(isolate, value, factory->offset_string()));
    // j. Let timeZone be ? Get(value, "timeZone").
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone_obj,
        JSReceiver::GetProperty(isolate, value, factory->timeZone_string()));
    // k. If timeZone is not undefined, then
    if (!IsUndefined(*time_zone_obj)) {
      // i. Set timeZone to ? ToTemporalTimeZone(timeZone).
      Handle<JSReceiver> time_zone;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, time_zone,
          temporal::ToTemporalTimeZone(isolate, time_zone_obj, method_name));
      time_zone_obj = time_zone;
    }

    // l. If offsetString is undefined, then
    if (IsUndefined(*offset_string_obj)) {
      // i. Set offsetBehaviour to wall.
      offset_behaviour = OffsetBehaviour::kWall;
    }
    // 6. Else,
  } else {
    // a. Let string be ? ToString(value).
    Handle<String> string;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, string,
                               Object::ToString(isolate, value_obj));
    DateTimeRecordWithCalendar parsed_result;
    // b. Let result be ? ParseTemporalRelativeToString(string).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, parsed_result, ParseTemporalRelativeToString(isolate, string),
        Handle<Object>());
    result = {parsed_result.date, parsed_result.time};
    // c. Let calendar be ?
    // ToTemporalCalendarWithISODefault(result.[[Calendar]]).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        ToTemporalCalendarWithISODefault(isolate, parsed_result.calendar,
                                         method_name));

    // d. Let offsetString be result.[[TimeZone]].[[OffsetString]].
    offset_string_obj = parsed_result.time_zone.offset_string;

    // e. Let timeZoneName be result.[[TimeZone]].[[Name]].
    Handle<Object> time_zone_name_obj = parsed_result.time_zone.name;

    // f. If timeZoneName is undefined, then
    if (IsUndefined(*time_zone_name_obj)) {
      // i. Let timeZone be undefined.
      time_zone_obj = factory->undefined_value();
      // g. Else,
    } else {
      // i. If ParseText(StringToCodePoints(timeZoneName),
      // TimeZoneNumericUTCOffset) is a List of errors, then
      DCHECK(IsString(*time_zone_name_obj));
      Handle<String> time_zone_name = Cast<String>(time_zone_name_obj);
      std::optional<ParsedISO8601Result> parsed =
          TemporalParser::ParseTimeZoneNumericUTCOffset(isolate,
                                                        time_zone_name);
      if (!parsed.has_value()) {
        // 1. If ! IsValidTimeZoneName(timeZoneName) is false, throw a
        // RangeError exception.
        if (!IsValidTimeZoneName(isolate, time_zone_name)) {
          THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                       NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                       Handle<Object>());
        }
        // 2. Set timeZoneName to ! CanonicalizeTimeZoneName(timeZoneName).
        time_zone_name = CanonicalizeTimeZoneName(isolate, time_zone_name);
      }
      // ii. Let timeZone be ! CreateTemporalTimeZone(timeZoneName).
      Handle<JSTemporalTimeZone> time_zone =
          temporal::CreateTemporalTimeZone(isolate, time_zone_name)
              .ToHandleChecked();
      time_zone_obj = time_zone;

      // iii. If result.[[TimeZone]].[[Z]] is true, then
      if (parsed_result.time_zone.z) {
        // 1. Set offsetBehaviour to exact.
        offset_behaviour = OffsetBehaviour::kExact;
        // iv. Else if offsetString is undefined, then
      } else if (IsUndefined(*offset_string_obj)) {
        // 1. Set offsetBehaviour to wall.
        offset_behaviour = OffsetBehaviour::kWall;
      }
      // v. Set matchBehaviour to match minutes.
      match_behaviour = MatchBehaviour::kMatchMinutes;
    }
  }
  // 8. If timeZone is undefined, then
  if (IsUndefined(*time_zone_obj)) {
    // a. Return ? CreateTemporalDate(result.[[Year]], result.[[Month]],
    // result.[[Day]], calendar).
    return CreateTemporalDate(isolate, result.date, calendar);
  }
  DCHECK(IsJSReceiver(*time_zone_obj));
  Handle<JSReceiver> time_zone = Cast<JSReceiver>(time_zone_obj);
  // 9. If offsetBehaviour is option, then
  int64_t offset_ns = 0;
  if (offset_behaviour == OffsetBehaviour::kOption) {
    // a. Set offsetString to ? ToString(offsetString).
    Handle<String> offset_string;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, offset_string,
                               Object::ToString(isolate, offset_string_obj));
    // b. Let offsetNs be ? ParseTimeZoneOffsetString(offset_string).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, offset_ns, ParseTimeZoneOffsetString(isolate, offset_string),
        Handle<Object>());
    // 10. Else,
  } else {
    // a. Let offsetNs be 0.
    offset_ns = 0;
  }
  // 11. Let epochNanoseconds be ? InterpretISODateTimeOffset(result.[[Year]],
  // result.[[Month]], result.[[Day]], result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]], offsetBehaviour, offsetNs, timeZone, "compatible",
  // "reject", matchBehaviour).
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      InterpretISODateTimeOffset(isolate, result, offset_behaviour, offset_ns,
                                 time_zone, Disambiguation::kCompatible,
                                 Offset::kReject, match_behaviour,
                                 method_name));

  // 12. Return ? CreateTemporalZonedDateTime(epochNanoseconds, timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(isolate, epoch_nanoseconds, time_zone,
                                     calendar);
}

// #sec-temporal-defaulttemporallargestunit
Unit DefaultTemporalLargestUnit(const DurationRecord& dur) {
  // 1. If years is not zero, return "year".
  if (dur.years != 0) return Unit::kYear;
  // 2. If months is not zero, return "month".
  if (dur.months != 0) return Unit::kMonth;
  // 3. If weeks is not zero, return "week".
  if (dur.weeks != 0) return Unit::kWeek;
  // 4. If days is not zero, return "day".
  if (dur.time_duration.days != 0) return Unit::kDay;
  // 5dur.. If hours is not zero, return "hour".
  if (dur.time_duration.hours != 0) return Unit::kHour;
  // 6. If minutes is not zero, return "minute".
  if (dur.time_duration.minutes != 0) return Unit::kMinute;
  // 7. If seconds is not zero, return "second".
  if (dur.time_duration.seconds != 0) return Unit::kSecond;
  // 8. If milliseconds is not zero, return "millisecond".
  if (dur.time_duration.milliseconds != 0) return Unit::kMillisecond;
  // 9. If microseconds is not zero, return "microsecond".
  if (dur.time_duration.microseconds != 0) return Unit::kMicrosecond;
  // 10. Return "nanosecond".
  return Unit::kNanosecond;
}

// #sec-temporal-differencezoneddatetime
Maybe<DurationRecord> DifferenceZonedDateTime(
    Isolate* isolate, Handle<BigInt> ns1, Handle<BigInt> ns2,
    Handle<JSReceiver> time_zone, Handle<JSReceiver> calendar,
    Unit largest_unit, Handle<JSReceiver> options, const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 1. If ns1 is ns2, then
  if (BigInt::CompareToBigInt(ns1, ns2) == ComparisonResult::kEqual) {
    // a. Return ! CreateDurationRecord(0, 0, 0, 0, 0, 0, 0, 0, 0, 0).
    return Just(CreateDurationRecord(isolate, {0, 0, 0, {0, 0, 0, 0, 0, 0, 0}})
                    .ToChecked());
  }
  // 2. Let startInstant be ! CreateTemporalInstant(ns1).
  Handle<JSTemporalInstant> start_instant =
      temporal::CreateTemporalInstant(isolate, ns1).ToHandleChecked();
  // 3. Let startDateTime be ?
  // temporal::BuiltinTimeZoneGetPlainDateTimeFor(timeZone, startInstant,
  // calendar).
  Handle<JSTemporalPlainDateTime> start_date_time;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, start_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(
          isolate, time_zone, start_instant, calendar, method_name),
      Nothing<DurationRecord>());
  // 4. Let endInstant be ! CreateTemporalInstant(ns2).
  Handle<JSTemporalInstant> end_instant =
      temporal::CreateTemporalInstant(isolate, ns2).ToHandleChecked();
  // 5. Let endDateTime be ?
  // temporal::BuiltinTimeZoneGetPlainDateTimeFor(timeZone, endInstant,
  // calendar).
  Handle<JSTemporalPlainDateTime> end_date_time;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, end_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(
          isolate, time_zone, end_instant, calendar, method_name),
      Nothing<DurationRecord>());
  // 6. Let dateDifference be ? DifferenceISODateTime(startDateTime.[[ISOYear]],
  // startDateTime.[[ISOMonth]], startDateTime.[[ISODay]],
  // startDateTime.[[ISOHour]], startDateTime.[[ISOMinute]],
  // startDateTime.[[ISOSecond]], startDateTime.[[ISOMillisecond]],
  // startDateTime.[[ISOMicrosecond]], startDateTime.[[ISONanosecond]],
  // endDateTime.[[ISOYear]], endDateTime.[[ISOMonth]], endDateTime.[[ISODay]],
  // endDateTime.[[ISOHour]], endDateTime.[[ISOMinute]],
  // endDateTime.[[ISOSecond]], endDateTime.[[ISOMillisecond]],
  // endDateTime.[[ISOMicrosecond]], endDateTime.[[ISONanosecond]], calendar,
  // largestUnit, options).
  DurationRecord date_difference;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, date_difference,
      DifferenceISODateTime(
          isolate,
          {{start_date_time->iso_year(), start_date_time->iso_month(),
            start_date_time->iso_day()},
           {start_date_time->iso_hour(), start_date_time->iso_minute(),
            start_date_time->iso_second(), start_date_time->iso_millisecond(),
            start_date_time->iso_microsecond(),
            start_date_time->iso_nanosecond()}},
          {{end_date_time->iso_year(), end_date_time->iso_month(),
            end_date_time->iso_day()},
           {end_date_time->iso_hour(), end_date_time->iso_minute(),
            end_date_time->iso_second(), end_date_time->iso_millisecond(),
            end_date_time->iso_microsecond(), end_date_time->iso_nanosecond()}},
          calendar, largest_unit, options, method_name),
      Nothing<DurationRecord>());

  // 7. Let intermediateNs be ? AddZonedDateTime(ns1, timeZone, calendar,
  // dateDifference.[[Years]], dateDifference.[[Months]],
  // dateDifference.[[Weeks]], 0, 0, 0, 0, 0, 0, 0).
  Handle<BigInt> intermediate_ns;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, intermediate_ns,
      AddZonedDateTime(isolate, ns1, time_zone, calendar,
                       {date_difference.years,
                        date_difference.months,
                        date_difference.weeks,
                        {0, 0, 0, 0, 0, 0, 0}},
                       method_name),
      Nothing<DurationRecord>());
  // 8. Let timeRemainderNs be ns2 − intermediateNs.
  Handle<BigInt> time_remainder_ns =
      BigInt::Subtract(isolate, ns2, intermediate_ns).ToHandleChecked();

  // 9. Let intermediate be ? CreateTemporalZonedDateTime(intermediateNs,
  // timeZone, calendar).
  Handle<JSTemporalZonedDateTime> intermediate =
      CreateTemporalZonedDateTime(isolate, intermediate_ns, time_zone, calendar)
          .ToHandleChecked();

  // 10. Let result be ? NanosecondsToDays(ℝ(timeRemainderNs), intermediate).
  NanosecondsToDaysResult result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      NanosecondsToDays(isolate, time_remainder_ns, intermediate, method_name),
      Nothing<DurationRecord>());

  // 11. Let timeDifference be ! BalanceDuration(0, 0, 0, 0, 0, 0,
  // result.[[Nanoseconds]], "hour").
  TimeDurationRecord time_difference =
      BalanceDuration(isolate, Unit::kHour,
                      {0, 0, 0, 0, 0, 0, result.nanoseconds}, method_name)
          .ToChecked();

  // 12. Return ! CreateDurationRecord(dateDifference.[[Years]],
  // dateDifference.[[Months]], dateDifference.[[Weeks]], result.[[Days]],
  // timeDifference.[[Hours]], timeDifference.[[Minutes]],
  // timeDifference.[[Seconds]], timeDifference.[[Milliseconds]],
  // timeDifference.[[Microseconds]], timeDifference.[[Nanoseconds]]).
  time_difference.days = result.days;
  return Just(CreateDurationRecord(
                  isolate, {date_difference.years, date_difference.months,
                            date_difference.weeks, time_difference})
                  .ToChecked());
}

Maybe<DurationRecord> AddDuration(Isolate* isolate, const DurationRecord& dur1,
                                  const DurationRecord& dur2,
                                  Handle<Object> relative_to_obj,
                                  const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  DurationRecord result;
  // 1. Let largestUnit1 be ! DefaultTemporalLargestUnit(y1, mon1, w1, d1, h1,
  // min1, s1, ms1, mus1).
  Unit largest_unit1 = DefaultTemporalLargestUnit(dur1);
  // 2. Let largestUnit2 be ! DefaultTemporalLargestUnit(y2, mon2, w2, d2, h2,
  // min2, s2, ms2, mus2).
  Unit largest_unit2 = DefaultTemporalLargestUnit(dur2);
  // 3. Let largestUnit be ! LargerOfTwoTemporalUnits(largestUnit1,
  // largestUnit2).
  Unit largest_unit = LargerOfTwoTemporalUnits(largest_unit1, largest_unit2);

  // 5. If relativeTo is undefined, then
  if (IsUndefined(*relative_to_obj)) {
    // a. If largestUnit is one of "year", "month", or "week", then
    if (largest_unit == Unit::kYear || largest_unit == Unit::kMonth ||
        largest_unit == Unit::kWeek) {
      // i. Throw a RangeError exception.
      THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                   NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                   Nothing<DurationRecord>());
    }
    // b. Let result be ? BalanceDuration(d1 + d2, h1 + h2, min1 + min2, s1 +
    // s2, ms1 + ms2, mus1 + mus2, ns1 + ns2, largestUnit).
    // Note: We call a special version of BalanceDuration which add two duration
    // internally to avoid overflow the double.
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result.time_duration,
        BalanceDuration(isolate, largest_unit, dur1.time_duration,
                        dur2.time_duration, method_name),
        Nothing<DurationRecord>());

    // c. Return ! CreateDurationRecord(0, 0, 0, result.[[Days]],
    // result.[[Hours]], result.[[Minutes]], result.[[Seconds]],
    // result.[[Milliseconds]], result.[[Microseconds]],
    // result.[[Nanoseconds]]).
    return Just(CreateDurationRecord(isolate, {0, 0, 0, result.time_duration})
                    .ToChecked());
    // 5. If relativeTo has an [[InitializedTemporalDate]] internal slot, then
  } else if (IsJSTemporalPlainDate(*relative_to_obj)) {
    // a. Let calendar be relativeTo.[[Calendar]].
    Handle<JSTemporalPlainDate> relative_to =
        Cast<JSTemporalPlainDate>(relative_to_obj);
    Handle<JSReceiver> calendar(relative_to->calendar(), isolate);
    // b. Let dateDuration1 be ? CreateTemporalDuration(y1, mon1, w1, d1, 0, 0,
    // 0, 0, 0, 0).
    Handle<JSTemporalDuration> date_duration1;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, date_duration1,
        CreateTemporalDuration(isolate,
                               {dur1.years,
                                dur1.months,
                                dur1.weeks,
                                {dur1.time_duration.days, 0, 0, 0, 0, 0, 0}}),
        Nothing<DurationRecord>());
    // c. Let dateDuration2 be ? CreateTemporalDuration(y2, mon2, w2, d2, 0, 0,
    // 0, 0, 0, 0).
    Handle<JSTemporalDuration> date_duration2;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, date_duration2,
        CreateTemporalDuration(isolate,
                               {dur2.years,
                                dur2.months,
                                dur2.weeks,
                                {dur2.time_duration.days, 0, 0, 0, 0, 0, 0}}),
        Nothing<DurationRecord>());
    // d. Let dateAdd be ? GetMethod(calendar, "dateAdd").
    Handle<Object> date_add;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, date_add,
        Object::GetMethod(isolate, calendar, factory->dateAdd_string()),
        Nothing<DurationRecord>());
    // e. Let intermediate be ? CalendarDateAdd(calendar, relativeTo,
    // dateDuration1, undefined, dateAdd).
    Handle<JSTemporalPlainDate> intermediate;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, intermediate,
        CalendarDateAdd(isolate, calendar, relative_to, date_duration1,
                        factory->undefined_value(), date_add),
        Nothing<DurationRecord>());
    // f. Let end be ? CalendarDateAdd(calendar, intermediate, dateDuration2,
    // undefined, dateAdd).
    Handle<JSTemporalPlainDate> end;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, end,
        CalendarDateAdd(isolate, calendar, intermediate, date_duration2,
                        factory->undefined_value(), date_add),
        Nothing<DurationRecord>());
    // g. Let dateLargestUnit be ! LargerOfTwoTemporalUnits("day", largestUnit).
    Unit date_largest_unit = LargerOfTwoTemporalUnits(Unit::kDay, largest_unit);
    // h. Let differenceOptions be ! OrdinaryObjectCreate(null).
    Handle<JSObject> difference_options = factory->NewJSObjectWithNullProto();
    // i. Perform ! CreateDataPropertyOrThrow(differenceOptions, "largestUnit",
    // dateLargestUnit).
    CHECK(JSReceiver::CreateDataProperty(
              isolate, difference_options, factory->largestUnit_string(),
              UnitToString(isolate, date_largest_unit), Just(kThrowOnError))
              .FromJust());

    // j. Let dateDifference be ? CalendarDateUntil(calendar, relativeTo, end,
    // differenceOptions).
    Handle<JSTemporalDuration> date_difference;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, date_difference,
        CalendarDateUntil(isolate, calendar, relative_to, end,
                          difference_options),
        Nothing<DurationRecord>());
    // n. Let result be ? BalanceDuration(dateDifference.[[Days]], h1 + h2, min1
    // + min2, s1 + s2, ms1 + ms2, mus1 + mus2, ns1 + ns2, largestUnit).
    // Note: We call a special version of BalanceDuration which add two duration
    // internally to avoid overflow the double.
    TimeDurationRecord time_dur1 = dur1.time_duration;
    time_dur1.days = Object::NumberValue(date_difference->days());
    TimeDurationRecord time_dur2 = dur2.time_duration;
    time_dur2.days = 0;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result.time_duration,
        BalanceDuration(isolate, largest_unit, time_dur1, time_dur2,
                        method_name),
        Nothing<DurationRecord>());
    // l. Return ! CreateDurationRecord(dateDifference.[[Years]],
    // dateDifference.[[Months]], dateDifference.[[Weeks]], result.[[Days]],
    // result.[[Hours]], result.[[Minutes]], result.[[Seconds]],
    // result.[[Milliseconds]], result.[[Microseconds]],
    // result.[[Nanoseconds]]).
    return Just(CreateDurationRecord(
                    isolate, {Object::NumberValue(date_difference->years()),
                              Object::NumberValue(date_difference->months()),
                              Object::NumberValue(date_difference->weeks()),
                              result.time_duration})
                    .ToChecked());
  }
  // 6. Assert: relativeTo has an [[InitializedTemporalZonedDateTime]]
  // internal slot.
  DCHECK(IsJSTemporalZonedDateTime(*relative_to_obj));
  auto relative_to = Cast<JSTemporalZonedDateTime>(relative_to_obj);
  // 7. Let timeZone be relativeTo.[[TimeZone]].
  Handle<JSReceiver> time_zone(relative_to->time_zone(), isolate);
  // 8. Let calendar be relativeTo.[[Calendar]].
  Handle<JSReceiver> calendar(relative_to->calendar(), isolate);
  // 9. Let intermediateNs be ? AddZonedDateTime(relativeTo.[[Nanoseconds]],
  // timeZone, calendar, y1, mon1, w1, d1, h1, min1, s1, ms1, mus1, ns1).
  Handle<BigInt> intermediate_ns;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, intermediate_ns,
      AddZonedDateTime(isolate, handle(relative_to->nanoseconds(), isolate),
                       time_zone, calendar, dur1, method_name),
      Nothing<DurationRecord>());
  // 10. Let endNs be ? AddZonedDateTime(intermediateNs, timeZone, calendar,
  // y2, mon2, w2, d2, h2, min2, s2, ms2, mus2, ns2).
  Handle<BigInt> end_ns;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, end_ns,
      AddZonedDateTime(isolate, intermediate_ns, time_zone, calendar, dur2,
                       method_name),
      Nothing<DurationRecord>());
  // 11. If largestUnit is not one of "year", "month", "week", or "day", then
  if (!(largest_unit == Unit::kYear || largest_unit == Unit::kMonth ||
        largest_unit == Unit::kWeek || largest_unit == Unit::kDay)) {
    // a. Let result be ! DifferenceInstant(relativeTo.[[Nanoseconds]], endNs,
    // 1, *"nanosecond"*, largestUnit, *"halfExpand"*).
    result.time_duration =
        DifferenceInstant(isolate, handle(relative_to->nanoseconds(), isolate),
                          end_ns, 1, Unit::kNanosecond, largest_unit,
                          RoundingMode::kHalfExpand, method_name);
    // b. Return ! CreateDurationRecord(0, 0, 0, 0, result.[[Hours]],
    // result.[[Minutes]], result.[[Seconds]], result.[[Milliseconds]],
    // result.[[Microseconds]], result.[[Nanoseconds]]).
    result.time_duration.days = 0;
    return Just(CreateDurationRecord(isolate, {0, 0, 0, result.time_duration})
                    .ToChecked());
  }
  // 12. Return ? DifferenceZonedDateTime(relativeTo.[[Nanoseconds]], endNs,
  // timeZone, calendar, largestUnit, OrdinaryObjectCreate(null)).
  return DifferenceZonedDateTime(
      isolate, handle(relative_to->nanoseconds(), isolate), end_ns, time_zone,
      calendar, largest_unit, factory->NewJSObjectWithNullProto(), method_name);
}

MaybeHandle<JSTemporalDuration> AddDurationToOrSubtractDurationFromDuration(
    Isolate* isolate, Arithmetic operation,
    DirectHandle<JSTemporalDuration> duration, Handle<Object> other_obj,
    Handle<Object> options_obj, const char* method_name) {
  // 1. If operation is subtract, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == Arithmetic::kSubtract ? -1.0 : 1.0;

  // 2. Set other to ? ToTemporalDurationRecord(other).
  DurationRecord other;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, other,
      temporal::ToTemporalDurationRecord(isolate, other_obj, method_name),
      Handle<JSTemporalDuration>());

  // 3. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 4. Let relativeTo be ? ToRelativeTemporalObject(options).
  Handle<Object> relative_to;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, relative_to,
      ToRelativeTemporalObject(isolate, options, method_name));

  // 5. Let result be ? AddDuration(duration.[[Years]], duration.[[Months]],
  // duration.[[Weeks]], duration.[[Days]], duration.[[Hours]],
  // duration.[[Minutes]], duration.[[Seconds]], duration.[[Milliseconds]],
  // duration.[[Microseconds]], duration.[[Nanoseconds]], sign ×
  // other.[[Years]], sign × other.[[Months]], sign × other.[[Weeks]], sign ×
  // other.[[Days]], sign × other.[[Hours]], sign × other.[[Minutes]], sign ×
  // other.[[Seconds]], sign × other.[[Milliseconds]], sign ×
  // other.[[Microseconds]], sign × other.[[Nanoseconds]], relativeTo).
  DurationRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      AddDuration(
          isolate,
          {Object::NumberValue(duration->years()),
           Object::NumberValue(duration->months()),
           Object::NumberValue(duration->weeks()),
           {Object::NumberValue(duration->days()),
            Object::NumberValue(duration->hours()),
            Object::NumberValue(duration->minutes()),
            Object::NumberValue(duration->seconds()),
            Object::NumberValue(duration->milliseconds()),
            Object::NumberValue(duration->microseconds()),
            Object::NumberValue(duration->nanoseconds())}},
          {sign * other.years,
           sign * other.months,
           sign * other.weeks,
           {sign * other.time_duration.days, sign * other.time_duration.hours,
            sign * other.time_duration.minutes,
            sign * other.time_duration.seconds,
            sign * other.time_duration.milliseconds,
            sign * other.time_duration.microseconds,
            sign * other.time_duration.nanoseconds}},
          relative_to, method_name),
      Handle<JSTemporalDuration>());

  // 6. Return ! CreateTemporalDuration(result.[[Years]], result.[[Months]],
  // result.[[Weeks]], result.[[Days]], result.[[Hours]], result.[[Minutes]],
  // result.[[Seconds]], result.[[Milliseconds]], result.[[Microseconds]],
  // result.[[Nanoseconds]]).
  return CreateTemporalDuration(isolate, result).ToHandleChecked();
}

}  // namespace

// #sec-temporal.duration.prototype.add
MaybeHandle<JSTemporalDuration> JSTemporalDuration::Add(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration,
    Handle<Object> other, Handle<Object> options) {
  return AddDurationToOrSubtractDurationFromDuration(
      isolate, Arithmetic::kAdd, duration, other, options,
      "Temporal.Duration.prototype.add");
}

// #sec-temporal.duration.prototype.subtract
MaybeHandle<JSTemporalDuration> JSTemporalDuration::Subtract(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration,
    Handle<Object> other, Handle<Object> options) {
  return AddDurationToOrSubtractDurationFromDuration(
      isolate, Arithmetic::kSubtract, duration, other, options,
      "Temporal.Duration.prototype.subtract");
}

// #sec-temporal.duration.prototype.tojson
MaybeHandle<String> JSTemporalDuration::ToJSON(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. Return ! TemporalDurationToString(duration.[[Years]],
  // duration.[[Months]], duration.[[Weeks]], duration.[[Days]],
  // duration.[[Hours]], duration.[[Minutes]], duration.[[Seconds]],
  // duration.[[Milliseconds]], duration.[[Microseconds]],
  // duration.[[Nanoseconds]], "auto").
  DurationRecord dur = {Object::NumberValue(duration->years()),
                        Object::NumberValue(duration->months()),
                        Object::NumberValue(duration->weeks()),
                        {Object::NumberValue(duration->days()),
                         Object::NumberValue(duration->hours()),
                         Object::NumberValue(duration->minutes()),
                         Object::NumberValue(duration->seconds()),
                         Object::NumberValue(duration->milliseconds()),
                         Object::NumberValue(duration->microseconds()),
                         Object::NumberValue(duration->nanoseconds())}};
  return TemporalDurationToString(isolate, dur, Precision::kAuto);
}

// #sec-temporal.duration.prototype.tolocalestring
MaybeHandle<String> JSTemporalDuration::ToLocaleString(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration,
    DirectHandle<Object> locales, DirectHandle<Object> options) {
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. Return ! TemporalDurationToString(duration.[[Years]],
  // duration.[[Months]], duration.[[Weeks]], duration.[[Days]],
  // duration.[[Hours]], duration.[[Minutes]], duration.[[Seconds]],
  // duration.[[Milliseconds]], duration.[[Microseconds]],
  // duration.[[Nanoseconds]], "auto").
  DurationRecord dur = {Object::NumberValue(duration->years()),
                        Object::NumberValue(duration->months()),
                        Object::NumberValue(duration->weeks()),
                        {Object::NumberValue(duration->days()),
                         Object::NumberValue(duration->hours()),
                         Object::NumberValue(duration->minutes()),
                         Object::NumberValue(duration->seconds()),
                         Object::NumberValue(duration->milliseconds()),
                         Object::NumberValue(duration->microseconds()),
                         Object::NumberValue(duration->nanoseconds())}};

  // TODO(ftang) Implement #sup-temporal.duration.prototype.tolocalestring
  return TemporalDurationToString(isolate, dur, Precision::kAuto);
}

namespace {
// #sec-temporal-moverelativezoneddatetime
MaybeHandle<JSTemporalZonedDateTime> MoveRelativeZonedDateTime(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    const DateDurationRecord& duration, const char* method_name) {
  // 1. Let intermediateNs be ? AddZonedDateTime(zonedDateTime.[[Nanoseconds]],
  // zonedDateTime.[[TimeZone]], zonedDateTime.[[Calendar]], years, months,
  // weeks, days, 0, 0, 0, 0, 0, 0).
  Handle<BigInt> intermediate_ns;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, intermediate_ns,
      AddZonedDateTime(isolate, handle(zoned_date_time->nanoseconds(), isolate),
                       handle(zoned_date_time->time_zone(), isolate),
                       handle(zoned_date_time->calendar(), isolate),
                       {duration.years,
                        duration.months,
                        duration.weeks,
                        {duration.days, 0, 0, 0, 0, 0, 0}},
                       method_name));
  // 2. Return ! CreateTemporalZonedDateTime(intermediateNs,
  // zonedDateTime.[[TimeZone]], zonedDateTime.[[Calendar]]).
  return CreateTemporalZonedDateTime(
             isolate, intermediate_ns,
             handle(zoned_date_time->time_zone(), isolate),
             handle(zoned_date_time->calendar(), isolate))
      .ToHandleChecked();
}

// #sec-temporal-daysuntil
double DaysUntil(Isolate* isolate, DirectHandle<JSTemporalPlainDate> earlier,
                 DirectHandle<JSTemporalPlainDate> later,
                 const char* method_name) {
  // 1. Let epochDays1 be MakeDay(𝔽(earlier.[[ISOYear]]), 𝔽(earlier.[[ISOMonth]]
  // - 1), 𝔽(earlier.[[ISODay]])).
  double epoch_days1 = MakeDay(earlier->iso_year(), earlier->iso_month() - 1,
                               earlier->iso_day());
  // 2. Assert: epochDays1 is finite.
  // 3. Let epochDays2 be MakeDay(𝔽(later.[[ISOYear]]), 𝔽(later.[[ISOMonth]] -
  // 1), 𝔽(later.[[ISODay]])).
  double epoch_days2 =
      MakeDay(later->iso_year(), later->iso_month() - 1, later->iso_day());
  // 4. Assert: epochDays2 is finite.
  // 5. Return ℝ(epochDays2) - ℝ(epochDays1).
  return epoch_days2 - epoch_days1;
}

// #sec-temporal-moverelativedate
Maybe<MoveRelativeDateResult> MoveRelativeDate(
    Isolate* isolate, Handle<JSReceiver> calendar,
    Handle<JSTemporalPlainDate> relative_to,
    Handle<JSTemporalDuration> duration, const char* method_name) {
  // 1. Let newDate be ? CalendarDateAdd(calendar, relativeTo, duration).
  Handle<JSTemporalPlainDate> new_date;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, new_date,
      CalendarDateAdd(isolate, calendar, relative_to, duration),
      Nothing<MoveRelativeDateResult>());
  // 2. Let days be DaysUntil(relativeTo, newDate).
  double days = DaysUntil(isolate, relative_to, new_date, method_name);
  // 3. Return the Record { [[RelativeTo]]: newDate, [[Days]]: days }.
  return Just(MoveRelativeDateResult({new_date, days}));
}

// #sec-temporal-roundduration
Maybe<DurationRecordWithRemainder> RoundDuration(Isolate* isolate,
                                                 const DurationRecord& duration,
                                                 double increment, Unit unit,
                                                 RoundingMode rounding_mode,
                                                 Handle<Object> relative_to,
                                                 const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // optional argument relativeTo (undefined, a Temporal.PlainDate, or a
  // Temporal.ZonedDateTime)
  DCHECK(IsUndefined(*relative_to) || IsJSTemporalPlainDate(*relative_to) ||
         IsJSTemporalZonedDateTime(*relative_to));

  Factory* factory = isolate->factory();
  DurationRecordWithRemainder result;
  result.record = duration;
  // 2. If unit is "year", "month", or "week", and relativeTo is undefined, then
  if ((unit == Unit::kYear || unit == Unit::kMonth || unit == Unit::kWeek) &&
      IsUndefined(*relative_to)) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DurationRecordWithRemainder>());
  }

  // 3. Let zonedRelativeTo be undefined.
  Handle<Object> zoned_relative_to = isolate->factory()->undefined_value();

  Handle<JSReceiver> calendar;
  // 5. If relativeTo is not undefined, then
  if (!IsUndefined(*relative_to)) {
    // a. If relativeTo has an [[InitializedTemporalZonedDateTime]] internal
    // slot, then
    if (IsJSTemporalZonedDateTime(*relative_to)) {
      // i. Set zonedRelativeTo to relativeTo.
      zoned_relative_to = relative_to;
      // ii. Set relativeTo to ? ToTemporalDate(relativeTo).
      Handle<JSTemporalPlainDate> date;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, date, ToTemporalDate(isolate, relative_to, method_name),
          Nothing<DurationRecordWithRemainder>());
      relative_to = date;
      // b. Else,
    } else {
      // i. Assert: relativeTo has an [[InitializedTemporalDate]] internal
      // slot.
      DCHECK(IsJSTemporalPlainDate(*relative_to));
    }
    // c. Let calendar be relativeTo.[[Calendar]].
    calendar = Handle<JSReceiver>(
        Cast<JSTemporalPlainDate>(relative_to)->calendar(), isolate);
    // 5. Else,
  } else {
    // a. NOTE: calendar will not be used below.
  }
  double fractional_seconds = 0;
  // 6. If unit is one of "year", "month", "week", or "day", then
  if (unit == Unit::kYear || unit == Unit::kMonth || unit == Unit::kWeek ||
      unit == Unit::kDay) {
    // a. Let nanoseconds be ! TotalDurationNanoseconds(0, hours, minutes,
    // seconds, milliseconds, microseconds, nanoseconds, 0).
    TimeDurationRecord time_duration = duration.time_duration;
    time_duration.days = 0;
    Handle<BigInt> nanoseconds =
        TotalDurationNanoseconds(isolate, time_duration, 0);

    // b. Let intermediate be undefined.
    Handle<Object> intermediate = isolate->factory()->undefined_value();

    // c. If zonedRelativeTo is not undefined, then
    if (!IsUndefined(*zoned_relative_to)) {
      DCHECK(IsJSTemporalZonedDateTime(*zoned_relative_to));
      // i. Let intermediate be ? MoveRelativeZonedDateTime(zonedRelativeTo,
      // years, months, weeks, days).
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, intermediate,
          MoveRelativeZonedDateTime(
              isolate, Cast<JSTemporalZonedDateTime>(zoned_relative_to),
              {duration.years, duration.months, duration.weeks,
               duration.time_duration.days},
              method_name),
          Nothing<DurationRecordWithRemainder>());
    }

    // d. Let result be ? NanosecondsToDays(nanoseconds, intermediate).
    NanosecondsToDaysResult to_days_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, to_days_result,
        NanosecondsToDays(isolate, nanoseconds, intermediate, method_name),
        Nothing<DurationRecordWithRemainder>());

    // e. Set days to days + result.[[Days]] + result.[[Nanoseconds]] /
    // result.[[DayLength]].
    result.record.time_duration.days +=
        to_days_result.days +
        // https://github.com/tc39/proposal-temporal/issues/2366
        std::round(to_days_result.nanoseconds / to_days_result.day_length);

    // f. Set hours, minutes, seconds, milliseconds, microseconds, and
    // nanoseconds to 0.
    result.record.time_duration.hours = result.record.time_duration.minutes =
        result.record.time_duration.seconds =
            result.record.time_duration.milliseconds =
                result.record.time_duration.microseconds =
                    result.record.time_duration.nanoseconds = 0;

    // 7. Else,
  } else {
    // a. Let fractionalSeconds be nanoseconds × 10^−9 + microseconds × 10^−6 +
    // milliseconds × 10^−3 + seconds.
    fractional_seconds = result.record.time_duration.nanoseconds * 1e-9 +
                         result.record.time_duration.microseconds * 1e-6 +
                         result.record.time_duration.milliseconds * 1e-3 +
                         result.record.time_duration.seconds;
  }
  // 8. Let remainder be undefined.
  result.remainder = -1;  // use -1 for undefined now.

  switch (unit) {
    // 9. If unit is "year", then
    case Unit::kYear: {
      // a. Let yearsDuration be ! CreateTemporalDuration(years, 0, 0, 0, 0, 0,
      // 0, 0, 0, 0).
      Handle<JSTemporalDuration> years_duration =
          CreateTemporalDuration(isolate,
                                 {duration.years, 0, 0, {0, 0, 0, 0, 0, 0, 0}})
              .ToHandleChecked();

      // b. Let dateAdd be ? GetMethod(calendar, "dateAdd").
      Handle<Object> date_add;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, date_add,
          Object::GetMethod(isolate, calendar, factory->dateAdd_string()),
          Nothing<DurationRecordWithRemainder>());

      // c. Let yearsLater be ? CalendarDateAdd(calendar, relativeTo,
      // yearsDuration, undefined, dateAdd).
      Handle<JSTemporalPlainDate> years_later;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, years_later,
          CalendarDateAdd(isolate, calendar, relative_to, years_duration,
                          isolate->factory()->undefined_value(), date_add),
          Nothing<DurationRecordWithRemainder>());

      // d. Let yearsMonthsWeeks be ! CreateTemporalDuration(years, months,
      // weeks, 0, 0, 0, 0, 0, 0, 0).
      Handle<JSTemporalDuration> years_months_weeks =
          CreateTemporalDuration(isolate, {duration.years,
                                           duration.months,
                                           duration.weeks,
                                           {0, 0, 0, 0, 0, 0, 0}})
              .ToHandleChecked();

      // e. Let yearsMonthsWeeksLater be ? CalendarDateAdd(calendar, relativeTo,
      // yearsMonthsWeeks, undefined, dateAdd).
      Handle<JSTemporalPlainDate> years_months_weeks_later;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, years_months_weeks_later,
          CalendarDateAdd
```