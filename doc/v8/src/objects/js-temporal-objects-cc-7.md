Response:
Let's break down the thought process for analyzing this code snippet.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick skim to identify recurring keywords and patterns. I see:

* `MaybeHandle`, `Handle`, `Isolate*`: These are common V8 types, suggesting interaction with the V8 heap and garbage collection.
* `BigInt`: Indicates handling of large integers, likely for nanosecond precision.
* `DurationRecord`, `TimeDurationRecord`:  These are custom structs for representing time durations.
* `JSTemporal...`:  These names strongly suggest the code is related to the ECMAScript Temporal API. Knowing this provides a significant context boost.
* Function names like `AddZonedDateTime`, `NanosecondsToDays`, `DifferenceISODateTime`, `AddInstant`, `IsValidEpochNanoseconds`, `GetEpochFromISOParts`, `DurationRecord::Sign`, `IsValidDuration`, `IsISOLeapYear`, `ISODaysInMonth`, `ISODaysInYear`: These names are self-descriptive and give clues about the functionality.
* Comments like `#sec-temporal-...`: These are references to specific sections of the ECMAScript specification, confirming the Temporal API connection.

**2. High-Level Purpose Identification:**

Based on the keywords and function names, it's clear that this code deals with manipulating and calculating Temporal-related values, specifically:

* **Durations:** Representing periods of time with different units.
* **Instants:** Representing a specific point in time.
* **Zoned Date-Times:** Representing a date and time in a specific time zone.
* **Calendars:**  Abstracting calendar systems.

**3. Function-by-Function Analysis (Key Functions):**

Now, I focus on the core functions to understand their specific roles:

* **`BalancePossiblyInfiniteDuration`:** This looks like it handles durations that might be infinite due to overflow, which is crucial for robust time calculations.
* **`AddZonedDateTime`:**  This is a key function for adding a duration to a zoned date-time. The logic involves converting to an instant, adding date components, then adding time components.
* **`NanosecondsToDays`:** This function converts a nanosecond duration to days, potentially considering a relative time zone to account for DST changes. The complexity suggests it handles edge cases and DST transitions.
* **`DifferenceISODateTime`:** Calculates the difference between two date-times, respecting calendar rules and handling different units.
* **`AddInstant`:**  Performs basic addition of a time duration to an instant (represented by nanoseconds since the epoch).
* **`IsValidEpochNanoseconds`:**  Validates if a BigInt representing nanoseconds since the epoch falls within the acceptable range.
* **`GetEpochFromISOParts`:** Converts ISO date and time components into nanoseconds since the epoch.
* **`DurationRecord::Sign`:** Determines the sign of a duration.
* **`IsValidDuration`:**  Checks if a `DurationRecord` represents a valid duration (finite values, consistent sign, within reasonable bounds).
* **`IsISOLeapYear`, `ISODaysInMonth`, `ISODaysInYear`:** These are standard ISO calendar calculations.

**4. Identifying JavaScript Connections:**

Because of the `JSTemporal...` types and the specification references, I immediately know this code is directly related to the JavaScript Temporal API. I then think of concrete JavaScript examples that would exercise these functions. For example, `AddZonedDateTime` directly corresponds to methods like `Temporal.ZonedDateTime.prototype.add()`.

**5. Inferring Logic and Potential Errors:**

As I analyze the code, I try to reason about the logic:

* **Overflow Handling:** The checks for `std::isinf` in `BalancePossiblyInfiniteDuration` and the range checks in `IsValidEpochNanoseconds` indicate awareness of potential overflow issues with time calculations.
* **Time Zones and DST:** The complexity of `NanosecondsToDays` and `AddZonedDateTime` (involving `BuiltinTimeZoneGetPlainDateTimeFor` and `BuiltinTimeZoneGetInstantFor`) strongly suggests handling of time zones and daylight saving time.
* **Calendar Integration:** The frequent passing of `calendar` handles indicates that the code is designed to work with different calendar systems beyond the ISO calendar.

Based on this understanding, I can anticipate common programming errors:

* **Incorrect unit usage:**  Adding years when you meant days, for example.
* **Ignoring time zones:** Performing calculations without considering time zone effects, leading to incorrect results around DST transitions.
* **Overflow:**  Calculations that result in values outside the representable range for `BigInt`.

**6. Structure and Organization:**

I notice the code is organized into functions that perform specific operations related to Temporal objects. The use of `MaybeHandle` and error checking with `ASSIGN_RETURN_ON_EXCEPTION` is characteristic of V8's error handling mechanisms.

**7. Torque Consideration (Even Though Not Applicable Here):**

The prompt mentions `.tq` files. Even though this file is `.cc`, I acknowledge that if it *were* a `.tq` file, it would be a Torque source, a domain-specific language used for implementing JavaScript built-ins in V8 with better type safety.

**8. Synthesizing the Summary:**

Finally, I combine all the information gathered to create a concise summary that covers the main functionalities, JavaScript connections, potential errors, and the overall purpose of the code. I also pay attention to the "part X of 25" instruction and acknowledge the limited context.

**Self-Correction/Refinement During the Process:**

* Initially, I might just see "BigInt" and think it's just about large numbers. However, the context of `epoch_nanoseconds` quickly clarifies that these are for representing very precise points in time.
* Seeing the `CalendarDateAdd` and `CalendarDateUntil` functions makes it clear that calendar abstractions are a key feature, not just simple date/time arithmetic.
* The repeated use of `TEMPORAL_ENTER_FUNC()` is a V8-specific macro, and while not crucial for understanding the *functionality*, it's worth noting as a V8 implementation detail.

By following these steps, I can systematically analyze the code snippet and arrive at a comprehensive understanding of its purpose and features.
好的，让我们来分析一下 `v8/src/objects/js-temporal-objects.cc` 这个 V8 源代码文件的功能。

**功能归纳:**

这个 C++ 文件是 V8 引擎中实现 ECMAScript Temporal API 相关对象的核心部分。它包含了处理日期、时间和时区的各种底层操作，例如：

* **时间单位的平衡和创建:**  `BalancePossiblyInfiniteDuration` 函数用于处理可能无限大的时间间隔，并将其转换为标准的 `TimeDurationRecord`。
* **带时区日期时间的加法:** `AddZonedDateTime` 函数实现了带时区日期时间对象的加法操作，它会考虑时区和日历的影响。
* **纳秒到天的转换:** `NanosecondsToDays` 函数将纳秒数转换为天数，这个过程会考虑相对的带时区日期时间，以处理夏令时等时区变化。
* **日期时间差的计算:** `DifferenceISODateTime` 函数计算两个 ISO 日期时间之间的差值，可以指定最大的时间单位。
* **Instant (瞬间) 对象的加法:** `AddInstant` 函数将一个时间间隔加到一个表示瞬间的纳秒值上。
* **Epoch 纳秒的有效性检查:** `IsValidEpochNanoseconds` 函数验证给定的纳秒值是否在允许的 Epoch 时间范围内。
* **从 ISO 部件获取 Epoch:** `GetEpochFromISOParts` 函数将 ISO 年、月、日、时、分、秒等信息转换为自 Epoch 以来的纳秒数。
* **Duration (持续时间) 的符号和有效性检查:** `DurationRecord::Sign` 函数获取持续时间的符号，`IsValidDuration` 函数检查一个 `DurationRecord` 是否有效（例如，各个字段的符号一致，数值在合理范围内）。
* **ISO 日历相关的辅助函数:**  `IsISOLeapYear`, `ISODaysInMonth`, `ISODaysInYear` 等函数用于执行 ISO 日历相关的计算，如判断是否为闰年，获取某个月的天数等。

**是否为 Torque 源代码:**

根据您提供的信息，`v8/src/objects/js-temporal-objects.cc` 以 `.cc` 结尾，这意味着它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 源代码文件以 `.tq` 结尾）。

**与 JavaScript 的关系和示例:**

这个文件中的 C++ 代码是 JavaScript 中 `Temporal` API 的底层实现。`Temporal` API 提供了现代的日期和时间处理方式，旨在替代 `Date` 对象的一些缺陷。

**JavaScript 示例:**

```javascript
const now = Temporal.Now.zonedDateTimeISO();
const duration = new Temporal.Duration(1, 2, 0, 5, 10, 30, 0, 0, 0); // 1年2个月5天10小时30分钟

// 使用 add 方法 (对应 C++ 中的 AddZonedDateTime)
const future = now.add(duration);
console.log(future.toString());

// 计算两个日期时间的差值 (对应 C++ 中的 DifferenceISODateTime)
const later = now.add({ days: 10 });
const difference = now.until(later, { unit: 'day' });
console.log(difference); // 输出类似 { days: 10 }

// 创建一个 Duration 对象 (涉及到 C++ 中 DurationRecord 的创建)
const anotherDuration = new Temporal.Duration(0, 0, 0, 1); // 1天

// 将持续时间添加到 Instant (对应 C++ 中的 AddInstant)
const instantNow = Temporal.Now.instant();
const instantLater = instantNow.add(anotherDuration);
console.log(instantLater.toString());
```

**代码逻辑推理和假设输入/输出:**

让我们看一个 `BalancePossiblyInfiniteDuration` 函数相关的代码片段：

```c++
rs_value = Object::NumberValue(*BigInt::ToNumber(isolate, hours));
  double minutes_value =
      Object::NumberValue(*BigInt::ToNumber(isolate, minutes));
  double seconds_value =
      Object::NumberValue(*BigInt::ToNumber(isolate, seconds));
  double milliseconds_value =
      Object::NumberValue(*BigInt::ToNumber(isolate, milliseconds));
  double microseconds_value =
      Object::NumberValue(*BigInt::ToNumber(isolate, microseconds));
  double nanoseconds_value =
      Object::NumberValue(*BigInt::ToNumber(isolate, nanoseconds));
  if (std::isinf(days) || std::isinf(hours_value) ||
      std::isinf(minutes_value) || std::isinf(seconds_value) ||
      std::isinf(milliseconds_value) || std::isinf(microseconds_value) ||
      std::isinf(nanoseconds_value)) {
    return Just(BalancePossiblyInfiniteDurationResult(
        {{0, 0, 0, 0, 0, 0, 0},
         sign == 1 ? BalanceOverflow::kPositive : BalanceOverflow::kNegative}));
  }
```

**假设输入:**

假设我们有一个表示时间间隔的对象，其 `hours` 字段的值非常大，以至于转换为 `double` 后变成了 `std::isinf()` 返回 `true` 的正无穷。 其他字段的值可以是任意有限数字。 假设 `sign` 为 `1`。

**预期输出:**

由于 `hours_value` 是无穷大，`if` 条件成立。 函数会返回一个 `BalancePossiblyInfiniteDurationResult`，其中 `TimeDurationRecord` 的所有字段都为 0，而 `BalanceOverflow` 为 `kPositive`。 这表示时间间隔是无限大，并且是正向的。

**用户常见的编程错误:**

使用 `Temporal` API 时，用户可能会犯以下错误：

* **单位混淆:**  例如，在应该使用 `days` 的地方使用了 `hours`，导致时间计算错误。
    ```javascript
    // 错误地认为这表示 24 小时后
    const wrongDuration = new Temporal.Duration({ hours: 24 });
    ```
* **忽略时区:**  在处理需要考虑时区的日期时间时，没有正确使用 `ZonedDateTime` 对象，或者在不同时区之间进行比较或计算时没有进行适当的转换。
    ```javascript
    const parisTime = Temporal.ZonedDateTime.from('2023-10-27T10:00:00[Europe/Paris]');
    const newYorkTime = Temporal.ZonedDateTime.from('2023-10-27T10:00:00[America/New_York]');

    // 直接比较，没有考虑时差
    console.log(parisTime === newYorkTime); // false，但它们代表不同的时刻

    // 应该转换为相同的时区或使用 instant 进行比较
    console.log(parisTime.toInstant().equals(newYorkTime.toInstant())); // false
    ```
* **对 `PlainDate` 或 `PlainTime` 对象执行需要时区的操作:** `PlainDate` 和 `PlainTime` 不包含时区信息，对其执行需要时区的操作（如与 `Instant` 比较）可能会导致错误或不明确的结果。
* **超出 `BigInt` 的范围:** 虽然 `Temporal` 内部使用 `BigInt` 来处理纳秒，但如果用户在其他计算中生成了超出 `BigInt` 表示范围的数值，可能会导致错误。

**总结第 8 部分的功能:**

作为第 8 部分，这段代码主要关注以下几个核心的 Temporal API 功能的底层实现：

* **处理可能无限大的时间间隔。**
* **带时区日期时间的加法运算，这是 `Temporal.ZonedDateTime.prototype.add()` 方法的基础。**
* **纳秒到天的转换，这在某些时间单位的换算中是必要的。**

理解这些底层 C++ 代码有助于深入了解 `Temporal` API 的工作原理以及 V8 引擎是如何高效地处理日期和时间操作的。

Prompt: 
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共25部分，请归纳一下它的功能

"""
rs_value = Object::NumberValue(*BigInt::ToNumber(isolate, hours));
  double minutes_value =
      Object::NumberValue(*BigInt::ToNumber(isolate, minutes));
  double seconds_value =
      Object::NumberValue(*BigInt::ToNumber(isolate, seconds));
  double milliseconds_value =
      Object::NumberValue(*BigInt::ToNumber(isolate, milliseconds));
  double microseconds_value =
      Object::NumberValue(*BigInt::ToNumber(isolate, microseconds));
  double nanoseconds_value =
      Object::NumberValue(*BigInt::ToNumber(isolate, nanoseconds));
  if (std::isinf(days) || std::isinf(hours_value) ||
      std::isinf(minutes_value) || std::isinf(seconds_value) ||
      std::isinf(milliseconds_value) || std::isinf(microseconds_value) ||
      std::isinf(nanoseconds_value)) {
    return Just(BalancePossiblyInfiniteDurationResult(
        {{0, 0, 0, 0, 0, 0, 0},
         sign == 1 ? BalanceOverflow::kPositive : BalanceOverflow::kNegative}));
  }

  // 16. Return ? CreateTimeDurationRecord(days, hours × sign, minutes × sign,
  // seconds × sign, milliseconds × sign, microseconds × sign, nanoseconds ×
  // sign).
  TimeDurationRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      TimeDurationRecord::Create(
          isolate, days, hours_value * sign, minutes_value * sign,
          seconds_value * sign, milliseconds_value * sign,
          microseconds_value * sign, nanoseconds_value * sign),
      Nothing<BalancePossiblyInfiniteDurationResult>());
  return Just(
      BalancePossiblyInfiniteDurationResult({result, BalanceOverflow::kNone}));
}

// #sec-temporal-addzoneddatetime
MaybeHandle<BigInt> AddZonedDateTime(Isolate* isolate,
                                     Handle<BigInt> epoch_nanoseconds,
                                     Handle<JSReceiver> time_zone,
                                     Handle<JSReceiver> calendar,
                                     const DurationRecord& duration,
                                     const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 1. If options is not present, set options to undefined.
  return AddZonedDateTime(isolate, epoch_nanoseconds, time_zone, calendar,
                          duration, isolate->factory()->undefined_value(),
                          method_name);
}

// #sec-temporal-addzoneddatetime
MaybeHandle<BigInt> AddZonedDateTime(Isolate* isolate,
                                     Handle<BigInt> epoch_nanoseconds,
                                     Handle<JSReceiver> time_zone,
                                     Handle<JSReceiver> calendar,
                                     const DurationRecord& duration,
                                     Handle<Object> options,
                                     const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  TimeDurationRecord time_duration = duration.time_duration;
  // 2. If all of years, months, weeks, and days are 0, then
  if (duration.years == 0 && duration.months == 0 && duration.weeks == 0 &&
      time_duration.days == 0) {
    // a. Return ? AddInstant(epochNanoseconds, hours, minutes, seconds,
    // milliseconds, microseconds, nanoseconds).
    return AddInstant(isolate, epoch_nanoseconds, time_duration);
  }
  // 3. Let instant be ! CreateTemporalInstant(epochNanoseconds).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(isolate, epoch_nanoseconds)
          .ToHandleChecked();

  // 4. Let temporalDateTime be ?
  // BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant, calendar).
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   calendar, method_name));
  // 5. Let datePart be ? CreateTemporalDate(temporalDateTime.[[ISOYear]],
  // temporalDateTime.[[ISOMonth]], temporalDateTime.[[ISODay]], calendar).
  Handle<JSTemporalPlainDate> date_part;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_part,
      CreateTemporalDate(
          isolate,
          {temporal_date_time->iso_year(), temporal_date_time->iso_month(),
           temporal_date_time->iso_day()},
          calendar));
  // 6. Let dateDuration be ? CreateTemporalDuration(years, months, weeks, days,
  // 0, 0, 0, 0, 0, 0).
  Handle<JSTemporalDuration> date_duration;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_duration,
      CreateTemporalDuration(isolate,
                             {duration.years,
                              duration.months,
                              duration.weeks,
                              {time_duration.days, 0, 0, 0, 0, 0, 0}}));
  // 7. Let addedDate be ? CalendarDateAdd(calendar, datePart, dateDuration,
  // options).
  Handle<JSTemporalPlainDate> added_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, added_date,
      CalendarDateAdd(isolate, calendar, date_part, date_duration, options));
  // 8. Let intermediateDateTime be ?
  // CreateTemporalDateTime(addedDate.[[ISOYear]], addedDate.[[ISOMonth]],
  // addedDate.[[ISODay]], temporalDateTime.[[ISOHour]],
  // temporalDateTime.[[ISOMinute]], temporalDateTime.[[ISOSecond]],
  // temporalDateTime.[[ISOMillisecond]], temporalDateTime.[[ISOMicrosecond]],
  // temporalDateTime.[[ISONanosecond]], calendar).
  Handle<JSTemporalPlainDateTime> intermediate_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, intermediate_date_time,
      temporal::CreateTemporalDateTime(
          isolate,
          {{added_date->iso_year(), added_date->iso_month(),
            added_date->iso_day()},
           {temporal_date_time->iso_hour(), temporal_date_time->iso_minute(),
            temporal_date_time->iso_second(),
            temporal_date_time->iso_millisecond(),
            temporal_date_time->iso_microsecond(),
            temporal_date_time->iso_nanosecond()}},
          calendar));
  // 9. Let intermediateInstant be ? BuiltinTimeZoneGetInstantFor(timeZone,
  // intermediateDateTime, "compatible").
  Handle<JSTemporalInstant> intermediate_instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, intermediate_instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, intermediate_date_time,
                                   Disambiguation::kCompatible, method_name));
  // 10. Return ? AddInstant(intermediateInstant.[[Nanoseconds]], hours,
  // minutes, seconds, milliseconds, microseconds, nanoseconds).
  time_duration.days = 0;
  return AddInstant(isolate,
                    handle(intermediate_instant->nanoseconds(), isolate),
                    time_duration);
}

Maybe<NanosecondsToDaysResult> NanosecondsToDays(Isolate* isolate,
                                                 Handle<BigInt> nanoseconds,
                                                 Handle<Object> relative_to_obj,
                                                 const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let dayLengthNs be nsPerDay.
  constexpr int64_t kDayLengthNs = 86400000000000LLU;
  Handle<BigInt> day_length_ns = BigInt::FromInt64(isolate, kDayLengthNs);
  double sign;
  switch (BigInt::CompareToNumber(nanoseconds, handle(Smi::zero(), isolate))) {
    // 2. If nanoseconds = 0, then
    case ComparisonResult::kEqual:
      // a. Return the Record { [[Days]]: 0, [[Nanoseconds]]: 0, [[DayLength]]:
      // dayLengthNs }.
      return Just(NanosecondsToDaysResult({0, 0, kDayLengthNs}));
    // 3. If nanoseconds < 0, let sign be -1; else, let sign be 1.
    case ComparisonResult::kLessThan:
      sign = -1;
      break;
    case ComparisonResult::kGreaterThan:
      sign = 1;
      break;
    default:
      UNREACHABLE();
  }

  // 4. If Type(relativeTo) is not Object or relativeTo does not have an
  // [[InitializedTemporalZonedDateTime]] internal slot, then
  if (!IsJSTemporalZonedDateTime(*relative_to_obj)) {
    // a. Return the Record { [[Days]]: RoundTowardsZero(nanoseconds /
    // dayLengthNs), [[Nanoseconds]]: (abs(nanoseconds) modulo dayLengthNs) ×
    // sign, [[DayLength]]: dayLengthNs }.
    if (sign == -1) {
      nanoseconds = BigInt::UnaryMinus(isolate, nanoseconds);
    }
    Handle<BigInt> days_bigint;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, days_bigint,
        BigInt::Divide(isolate, nanoseconds, day_length_ns),
        Nothing<NanosecondsToDaysResult>());
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, nanoseconds,
        BigInt::Remainder(isolate, nanoseconds, day_length_ns),
        Nothing<NanosecondsToDaysResult>());
    if (sign == -1) {
      days_bigint = BigInt::UnaryMinus(isolate, days_bigint);
      nanoseconds = BigInt::UnaryMinus(isolate, nanoseconds);
    }
    return Just(NanosecondsToDaysResult(
        {Object::NumberValue(*BigInt::ToNumber(isolate, days_bigint)),
         Object::NumberValue(*BigInt::ToNumber(isolate, nanoseconds)),
         kDayLengthNs}));
  }
  auto relative_to = Cast<JSTemporalZonedDateTime>(relative_to_obj);
  // 5. Let startNs be ℝ(relativeTo.[[Nanoseconds]]).
  Handle<BigInt> start_ns = handle(relative_to->nanoseconds(), isolate);
  // 6. Let startInstant be ! CreateTemporalInstant(ℤ(sartNs)).
  Handle<JSTemporalInstant> start_instant =
      temporal::CreateTemporalInstant(
          isolate, handle(relative_to->nanoseconds(), isolate))
          .ToHandleChecked();

  // 7. Let startDateTime be ?
  // BuiltinTimeZoneGetPlainDateTimeFor(relativeTo.[[TimeZone]],
  // startInstant, relativeTo.[[Calendar]]).
  Handle<JSReceiver> time_zone =
      Handle<JSReceiver>(relative_to->time_zone(), isolate);
  Handle<JSReceiver> calendar =
      Handle<JSReceiver>(relative_to->calendar(), isolate);
  Handle<JSTemporalPlainDateTime> start_date_time;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, start_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(
          isolate, time_zone, start_instant, calendar, method_name),
      Nothing<NanosecondsToDaysResult>());

  // 8. Let endNs be startNs + nanoseconds.
  Handle<BigInt> end_ns;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, end_ns,
                                   BigInt::Add(isolate, start_ns, nanoseconds),
                                   Nothing<NanosecondsToDaysResult>());

  // 9. If ! IsValidEpochNanoseconds(ℤ(endNs)) is false, throw a RangeError
  // exception.
  if (!IsValidEpochNanoseconds(isolate, end_ns)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<NanosecondsToDaysResult>());
  }

  // 10. Let endInstant be ! CreateTemporalInstant(ℤ(endNs)).
  Handle<JSTemporalInstant> end_instant =
      temporal::CreateTemporalInstant(isolate, end_ns).ToHandleChecked();
  // 11. Let endDateTime be ?
  // BuiltinTimeZoneGetPlainDateTimeFor(relativeTo.[[TimeZone]],
  // endInstant, relativeTo.[[Calendar]]).
  Handle<JSTemporalPlainDateTime> end_date_time;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, end_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(
          isolate, time_zone, end_instant, calendar, method_name),
      Nothing<NanosecondsToDaysResult>());

  // 12. Let dateDifference be ?
  // DifferenceISODateTime(startDateTime.[[ISOYear]],
  // startDateTime.[[ISOMonth]], startDateTime.[[ISODay]],
  // startDateTime.[[ISOHour]], startDateTime.[[ISOMinute]],
  // startDateTime.[[ISOSecond]], startDateTime.[[ISOMillisecond]],
  // startDateTime.[[ISOMicrosecond]], startDateTime.[[ISONanosecond]],
  // endDateTime.[[ISOYear]], endDateTime.[[ISOMonth]], endDateTime.[[ISODay]],
  // endDateTime.[[ISOHour]], endDateTime.[[ISOMinute]],
  // endDateTime.[[ISOSecond]], endDateTime.[[ISOMillisecond]],
  // endDateTime.[[ISOMicrosecond]], endDateTime.[[ISONanosecond]],
  // relativeTo.[[Calendar]], "day", OrdinaryObjectCreate(null)).
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
          calendar, Unit::kDay, isolate->factory()->NewJSObjectWithNullProto(),
          method_name),
      Nothing<NanosecondsToDaysResult>());

  // 13. Let days be dateDifference.[[Days]].
  double days = date_difference.time_duration.days;

  // 14. Let intermediateNs be ℝ(? AddZonedDateTime(ℤ(startNs),
  // relativeTo.[[TimeZone]], relativeTo.[[Calendar]], 0, 0, 0, days, 0, 0, 0,
  // 0, 0, 0)).
  Handle<BigInt> intermediate_ns;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, intermediate_ns,
      AddZonedDateTime(isolate, start_ns, time_zone, calendar,
                       {0, 0, 0, {days, 0, 0, 0, 0, 0, 0}}, method_name),
      Nothing<NanosecondsToDaysResult>());

  // 15. If sign is 1, then
  if (sign == 1) {
    // a. Repeat, while days > 0 and intermediateNs > endNs,
    while (days > 0 && BigInt::CompareToBigInt(intermediate_ns, end_ns) ==
                           ComparisonResult::kGreaterThan) {
      // i. Set days to days − 1.
      days -= 1;
      // ii. Set intermediateNs to ℝ(? AddZonedDateTime(ℤ(startNs),
      // relativeTo.[[TimeZone]], relativeTo.[[Calendar]], 0, 0, 0, days, 0, 0,
      // 0, 0, 0, 0)).
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, intermediate_ns,
          AddZonedDateTime(isolate, start_ns, time_zone, calendar,
                           {0, 0, 0, {days, 0, 0, 0, 0, 0, 0}}, method_name),
          Nothing<NanosecondsToDaysResult>());
    }
  }

  // 16. Set nanoseconds to endNs − intermediateNs.
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, nanoseconds, BigInt::Subtract(isolate, end_ns, intermediate_ns),
      Nothing<NanosecondsToDaysResult>());

  // 17. Let done be false.
  bool done = false;

  // 18. Repeat, while done is false,
  while (!done) {
    // a. Let oneDayFartherNs be ℝ(? AddZonedDateTime(ℤ(intermediateNs),
    // relativeTo.[[TimeZone]], relativeTo.[[Calendar]], 0, 0, 0, sign, 0, 0, 0,
    // 0, 0, 0)).
    Handle<BigInt> one_day_farther_ns;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, one_day_farther_ns,
        AddZonedDateTime(isolate, intermediate_ns, time_zone, calendar,
                         {0, 0, 0, {sign, 0, 0, 0, 0, 0, 0}}, method_name),
        Nothing<NanosecondsToDaysResult>());

    // b. Set dayLengthNs to oneDayFartherNs − intermediateNs.
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, day_length_ns,
        BigInt::Subtract(isolate, one_day_farther_ns, intermediate_ns),
        Nothing<NanosecondsToDaysResult>());

    // c. If (nanoseconds − dayLengthNs) × sign ≥ 0, then
    if (sign * CompareResultToSign(
                   BigInt::CompareToBigInt(nanoseconds, day_length_ns)) >=
        0) {
      // i. Set nanoseconds to nanoseconds − dayLengthNs.
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, nanoseconds,
          BigInt::Subtract(isolate, nanoseconds, day_length_ns),
          Nothing<NanosecondsToDaysResult>());

      // ii. Set intermediateNs to oneDayFartherNs.
      intermediate_ns = one_day_farther_ns;

      // iii. Set days to days + sign.
      days += sign;
      // d. Else,
    } else {
      // i. Set done to true.
      done = true;
    }
  }

  // 20. Return the new Record { [[Days]]: days, [[Nanoseconds]]: nanoseconds,
  // [[DayLength]]: abs(dayLengthNs) }.
  NanosecondsToDaysResult result(
      {days, Object::NumberValue(*BigInt::ToNumber(isolate, nanoseconds)),
       std::abs(day_length_ns->AsInt64())});
  return Just(result);
}

// #sec-temporal-differenceisodatetime
Maybe<DurationRecord> DifferenceISODateTime(
    Isolate* isolate, const DateTimeRecord& date_time1,
    const DateTimeRecord& date_time2, Handle<JSReceiver> calendar,
    Unit largest_unit, Handle<JSReceiver> options, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: ISODateTimeWithinLimits(y1, mon1, d1, h1, min1, s1, ms1, mus1,
  // ns1) is true.
  DCHECK(ISODateTimeWithinLimits(isolate, date_time1));
  // 2. Assert: ISODateTimeWithinLimits(y2, mon2, d2, h2, min2, s2, ms2, mus2,
  // ns2) is true.
  DCHECK(ISODateTimeWithinLimits(isolate, date_time2));
  // 3. Let timeDifference be ! DifferenceTime(h1, min1, s1, ms1, mus1, ns1, h2,
  // min2, s2, ms2, mus2, ns2).
  TimeDurationRecord time_difference =
      DifferenceTime(isolate, date_time1.time, date_time2.time).ToChecked();

  // 4. Let timeSign be ! DurationSign(0, 0, 0, 0, timeDifference.[[Hours]],
  // timeDifference.[[Minutes]], timeDifference.[[Seconds]],
  // timeDifference.[[Milliseconds]], timeDifference.[[Microseconds]],
  // timeDifference.[[Nanoseconds]]).
  time_difference.days = 0;
  double time_sign = DurationRecord::Sign({0, 0, 0, time_difference});

  // 5. Let dateSign be ! CompareISODate(y2, mon2, d2, y1, mon1, d1).
  double date_sign = CompareISODate(date_time2.date, date_time1.date);

  // 6. Let adjustedDate be CreateISODateRecordWithCalendar(y1, mon1, d1).
  DateRecord adjusted_date = date_time1.date;
  CHECK(IsValidISODate(isolate, adjusted_date));

  // 7. If timeSign is -dateSign, then
  if (time_sign == -date_sign) {
    adjusted_date.day -= time_sign;
    // a. Set adjustedDate to BalanceISODate(adjustedDate.[[Year]],
    // adjustedDate.[[Month]], adjustedDate.[[Day]] - timeSign).
    adjusted_date = BalanceISODate(isolate, adjusted_date);
    // b. Set timeDifference to ! BalanceDuration(-timeSign,
    // timeDifference.[[Hours]], timeDifference.[[Minutes]],
    // timeDifference.[[Seconds]], timeDifference.[[Milliseconds]],
    // timeDifference.[[Microseconds]], timeDifference.[[Nanoseconds]],
    // largestUnit).
    time_difference.days = -time_sign;
    time_difference =
        BalanceDuration(isolate, largest_unit, time_difference, method_name)
            .ToChecked();
  }

  // 8. Let date1 be ! CreateTemporalDate(adjustedDate.[[Year]],
  // adjustedDate.[[Month]], adjustedDate.[[Day]], calendar).
  Handle<JSTemporalPlainDate> date1 =
      CreateTemporalDate(isolate, adjusted_date, calendar).ToHandleChecked();

  // 9. Let date2 be ! CreateTemporalDate(y2, mon2, d2, calendar).
  Handle<JSTemporalPlainDate> date2 =
      CreateTemporalDate(isolate, date_time2.date, calendar).ToHandleChecked();
  // 10. Let dateLargestUnit be ! LargerOfTwoTemporalUnits("day", largestUnit).
  Unit date_largest_unit = LargerOfTwoTemporalUnits(Unit::kDay, largest_unit);

  // 11. Let untilOptions be ? MergeLargestUnitOption(options, dateLargestUnit).
  Handle<JSReceiver> until_options;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, until_options,
      MergeLargestUnitOption(isolate, options, date_largest_unit),
      Nothing<DurationRecord>());
  // 12. Let dateDifference be ? CalendarDateUntil(calendar, date1, date2,
  // untilOptions).
  Handle<JSTemporalDuration> date_difference;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, date_difference,
      CalendarDateUntil(isolate, calendar, date1, date2, until_options),
      Nothing<DurationRecord>());
  // 13. Let balanceResult be ? BalanceDuration(dateDifference.[[Days]],
  // timeDifference.[[Hours]], timeDifference.[[Minutes]],
  // timeDifference.[[Seconds]], timeDifference.[[Milliseconds]],
  // timeDifference.[[Microseconds]], timeDifference.[[Nanoseconds]],
  // largestUnit).

  time_difference.days = Object::NumberValue(date_difference->days());
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, time_difference,
      BalanceDuration(isolate, largest_unit, time_difference, method_name),
      Nothing<DurationRecord>());

  // 14. Return ! CreateDurationRecord(dateDifference.[[Years]],
  // dateDifference.[[Months]], dateDifference.[[Weeks]],
  // balanceResult.[[Days]], balanceResult.[[Hours]], balanceResult.[[Minutes]],
  // balanceResult.[[Seconds]], balanceResult.[[Milliseconds]],
  // balanceResult.[[Microseconds]], balanceResult.[[Nanoseconds]]).

  return Just(CreateDurationRecord(
                  isolate, {Object::NumberValue(date_difference->years()),
                            Object::NumberValue(date_difference->months()),
                            Object::NumberValue(date_difference->weeks()),
                            time_difference})
                  .ToChecked());
}

// #sec-temporal-addinstant
MaybeHandle<BigInt> AddInstant(Isolate* isolate,
                               Handle<BigInt> epoch_nanoseconds,
                               const TimeDurationRecord& addend) {
  TEMPORAL_ENTER_FUNC();
  Factory* factory = isolate->factory();

  // 1. Assert: hours, minutes, seconds, milliseconds, microseconds, and
  // nanoseconds are integer Number values.
  // 2. Let result be epochNanoseconds + ℤ(nanoseconds) +
  // ℤ(microseconds) × 1000ℤ + ℤ(milliseconds) × 10^6ℤ + ℤ(seconds) × 10^9ℤ +
  // ℤ(minutes) × 60ℤ × 10^9ℤ + ℤ(hours) × 3600ℤ × 10^9ℤ.

  // epochNanoseconds + ℤ(nanoseconds)
  Handle<BigInt> result =
      BigInt::Add(
          isolate, epoch_nanoseconds,
          BigInt::FromNumber(isolate, factory->NewNumber(addend.nanoseconds))
              .ToHandleChecked())
          .ToHandleChecked();

  // + ℤ(microseconds) × 1000ℤ
  Handle<BigInt> temp =
      BigInt::Multiply(
          isolate,
          BigInt::FromNumber(isolate, factory->NewNumber(addend.microseconds))
              .ToHandleChecked(),
          BigInt::FromInt64(isolate, 1000))
          .ToHandleChecked();
  result = BigInt::Add(isolate, result, temp).ToHandleChecked();

  // + ℤ(milliseconds) × 10^6ℤ
  temp = BigInt::Multiply(isolate,
                          BigInt::FromNumber(
                              isolate, factory->NewNumber(addend.milliseconds))
                              .ToHandleChecked(),
                          BigInt::FromInt64(isolate, 1000000))
             .ToHandleChecked();
  result = BigInt::Add(isolate, result, temp).ToHandleChecked();

  // + ℤ(seconds) × 10^9ℤ
  temp = BigInt::Multiply(
             isolate,
             BigInt::FromNumber(isolate, factory->NewNumber(addend.seconds))
                 .ToHandleChecked(),
             BigInt::FromInt64(isolate, 1000000000))
             .ToHandleChecked();
  result = BigInt::Add(isolate, result, temp).ToHandleChecked();

  // + ℤ(minutes) × 60ℤ × 10^9ℤ.
  temp = BigInt::Multiply(
             isolate,
             BigInt::FromNumber(isolate, factory->NewNumber(addend.minutes))
                 .ToHandleChecked(),
             BigInt::FromInt64(isolate, 60000000000))
             .ToHandleChecked();
  result = BigInt::Add(isolate, result, temp).ToHandleChecked();

  // + ℤ(hours) × 3600ℤ × 10^9ℤ.
  temp = BigInt::Multiply(
             isolate,
             BigInt::FromNumber(isolate, factory->NewNumber(addend.hours))
                 .ToHandleChecked(),
             BigInt::FromInt64(isolate, 3600000000000))
             .ToHandleChecked();
  result = BigInt::Add(isolate, result, temp).ToHandleChecked();

  // 3. If ! IsValidEpochNanoseconds(result) is false, throw a RangeError
  // exception.
  if (!IsValidEpochNanoseconds(isolate, result)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 4. Return result.
  return result;
}

// #sec-temporal-isvalidepochnanoseconds
bool IsValidEpochNanoseconds(Isolate* isolate,
                             DirectHandle<BigInt> epoch_nanoseconds) {
  TEMPORAL_ENTER_FUNC();
  // nsMinInstant = -nsMaxInstant = -8.64 × 10^21
  constexpr double kNsMinInstant = -8.64e21;
  // nsMaxInstant = 10^8 × nsPerDay = 8.64 × 1021
  constexpr double kNsMaxInstant = 8.64e21;

  // 1. Assert: Type(epochNanoseconds) is BigInt.
  // 2. If ℝ(epochNanoseconds) < nsMinInstant or ℝ(epochNanoseconds) >
  // nsMaxInstant, then
  if (BigInt::CompareToNumber(epoch_nanoseconds,
                              isolate->factory()->NewNumber(kNsMinInstant)) ==
          ComparisonResult::kLessThan ||
      BigInt::CompareToNumber(epoch_nanoseconds,
                              isolate->factory()->NewNumber(kNsMaxInstant)) ==
          ComparisonResult::kGreaterThan) {
    // a. Return false.
    return false;
  }
  return true;
}

Handle<BigInt> GetEpochFromISOParts(Isolate* isolate,
                                    const DateTimeRecord& date_time) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: year, month, day, hour, minute, second, millisecond,
  // microsecond, and nanosecond are integers.
  // 2. Assert: ! IsValidISODate(year, month, day) is true.
  DCHECK(IsValidISODate(isolate, date_time.date));
  // 3. Assert: ! IsValidTime(hour, minute, second, millisecond, microsecond,
  // nanosecond) is true.
  DCHECK(IsValidTime(isolate, date_time.time));
  // 4. Let date be ! MakeDay(𝔽(year), 𝔽(month − 1), 𝔽(day)).
  double date = MakeDay(date_time.date.year, date_time.date.month - 1,
                        date_time.date.day);
  // 5. Let time be ! MakeTime(𝔽(hour), 𝔽(minute), 𝔽(second), 𝔽(millisecond)).
  double time = MakeTime(date_time.time.hour, date_time.time.minute,
                         date_time.time.second, date_time.time.millisecond);
  // 6. Let ms be ! MakeDate(date, time).
  double ms = MakeDate(date, time);
  // 7. Assert: ms is finite.
  // 8. Return ℝ(ms) × 10^6 + microsecond × 10^3 + nanosecond.
  return BigInt::Add(
             isolate,
             BigInt::Add(
                 isolate,
                 BigInt::Multiply(
                     isolate,
                     BigInt::FromNumber(isolate,
                                        isolate->factory()->NewNumber(ms))
                         .ToHandleChecked(),
                     BigInt::FromInt64(isolate, 1000000))
                     .ToHandleChecked(),
                 BigInt::Multiply(
                     isolate,
                     BigInt::FromInt64(isolate, date_time.time.microsecond),
                     BigInt::FromInt64(isolate, 1000))
                     .ToHandleChecked())
                 .ToHandleChecked(),
             BigInt::FromInt64(isolate, date_time.time.nanosecond))
      .ToHandleChecked();
}

}  // namespace

namespace temporal {

// #sec-temporal-durationsign
int32_t DurationRecord::Sign(const DurationRecord& dur) {
  TEMPORAL_ENTER_FUNC();

  // 1. For each value v of « years, months, weeks, days, hours, minutes,
  // seconds, milliseconds, microseconds, nanoseconds », do a. If v < 0, return
  // −1. b. If v > 0, return 1.
  // 2. Return 0.
  if (dur.years < 0) return -1;
  if (dur.years > 0) return 1;
  if (dur.months < 0) return -1;
  if (dur.months > 0) return 1;
  if (dur.weeks < 0) return -1;
  if (dur.weeks > 0) return 1;
  const TimeDurationRecord& time = dur.time_duration;
  if (time.days < 0) return -1;
  if (time.days > 0) return 1;
  if (time.hours < 0) return -1;
  if (time.hours > 0) return 1;
  if (time.minutes < 0) return -1;
  if (time.minutes > 0) return 1;
  if (time.seconds < 0) return -1;
  if (time.seconds > 0) return 1;
  if (time.milliseconds < 0) return -1;
  if (time.milliseconds > 0) return 1;
  if (time.microseconds < 0) return -1;
  if (time.microseconds > 0) return 1;
  if (time.nanoseconds < 0) return -1;
  if (time.nanoseconds > 0) return 1;
  return 0;
}

// #sec-temporal-isvalidduration
bool IsValidDuration(Isolate* isolate, const DurationRecord& dur) {
  TEMPORAL_ENTER_FUNC();

  // 1. Let sign be ! DurationSign(years, months, weeks, days, hours, minutes,
  // seconds, milliseconds, microseconds, nanoseconds).
  int32_t sign = DurationRecord::Sign(dur);
  // 2. For each value v of « years, months, weeks, days, hours, minutes,
  // seconds, milliseconds, microseconds, nanoseconds », do a. If v is not
  // finite, return false. b. If v < 0 and sign > 0, return false. c. If v > 0
  // and sign < 0, return false.
  // 3. Return true.
  const TimeDurationRecord& time = dur.time_duration;

  if (!(std::isfinite(dur.years) && std::isfinite(dur.months) &&
        std::isfinite(dur.weeks) && std::isfinite(time.days) &&
        std::isfinite(time.hours) && std::isfinite(time.minutes) &&
        std::isfinite(time.seconds) && std::isfinite(time.milliseconds) &&
        std::isfinite(time.microseconds) && std::isfinite(time.nanoseconds))) {
    return false;
  }
  if ((sign > 0 && (dur.years < 0 || dur.months < 0 || dur.weeks < 0 ||
                    time.days < 0 || time.hours < 0 || time.minutes < 0 ||
                    time.seconds < 0 || time.milliseconds < 0 ||
                    time.microseconds < 0 || time.nanoseconds < 0)) ||
      (sign < 0 && (dur.years > 0 || dur.months > 0 || dur.weeks > 0 ||
                    time.days > 0 || time.hours > 0 || time.minutes > 0 ||
                    time.seconds > 0 || time.milliseconds > 0 ||
                    time.microseconds > 0 || time.nanoseconds > 0))) {
    return false;
  }
  static const double kPower32Of2 = static_cast<double>(int64_t(1) << 32);
  static const int64_t kPower53Of2 = int64_t(1) << 53;
  // 3. If abs(years) ≥ 2**32, return false.
  if (std::abs(dur.years) >= kPower32Of2) {
    return false;
  }
  // 4. If abs(months) ≥ 2**32, return false.
  if (std::abs(dur.months) >= kPower32Of2) {
    return false;
  }
  // 5. If abs(weeks) ≥ 2**32, return false.
  if (std::abs(dur.weeks) >= kPower32Of2) {
    return false;
  }
  // 6. Let normalizedSeconds be days × 86,400 + hours × 3600 + minutes × 60 +
  // seconds + ℝ(𝔽(milliseconds)) × 10**-3 + ℝ(𝔽(microseconds)) × 10**-6 +
  // ℝ(𝔽(nanoseconds)) × 10**-9.
  // 7. NOTE: The above step cannot be implemented directly using floating-point
  // arithmetic. Multiplying by 10**-3, 10**-6, and 10**-9 respectively may be
  // imprecise when milliseconds, microseconds, or nanoseconds is an unsafe
  // integer. This multiplication can be implemented in C++ with an
  // implementation of std::remquo() with sufficient bits in the quotient.
  // String manipulation will also give an exact result, since the
  // multiplication is by a power of 10.
  // 8. If abs(normalizedSeconds) ≥ 2**53, return false.

  int64_t allowed = kPower53Of2;
  double in_seconds = std::abs(time.days * 86400.0 + time.hours * 3600.0 +
                               time.minutes * 60.0 + time.seconds);

  if (in_seconds >= allowed) {
    return false;
  }
  allowed -= in_seconds;

  // Check the part > 1 seconds.
  in_seconds = std::floor(std::abs(time.milliseconds / 1e3)) +
               std::floor(std::abs(time.microseconds / 1e6)) +
               std::floor(std::abs(time.nanoseconds / 1e9));
  if (in_seconds >= allowed) {
    return false;
  }
  allowed -= in_seconds;

  // Sum of the three remainings will surely < 3
  if (allowed > 3) {
    return true;
  }

  allowed *= 1000000000;  // convert to ns
  int64_t remainders = std::abs(fmod(time.milliseconds, 1e3)) * 1000000 +
                       std::abs(fmod(time.microseconds, 1e6)) * 1000 +
                       std::abs(fmod(time.nanoseconds, 1e9));
  if (remainders >= allowed) {
    return false;
  }
  return true;
}

}  // namespace temporal

namespace {

// #sec-temporal-isisoleapyear
bool IsISOLeapYear(Isolate* isolate, int32_t year) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: year is an integer.
  // 2. If year modulo 4 ≠ 0, return false.
  // 3. If year modulo 400 = 0, return true.
  // 4. If year modulo 100 = 0, return false.
  // 5. Return true.
  return isolate->date_cache()->IsLeap(year);
}

// #sec-temporal-isodaysinmonth
int32_t ISODaysInMonth(Isolate* isolate, int32_t year, int32_t month) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: year is an integer.
  // 2. Assert: month is an integer, month ≥ 1, and month ≤ 12.
  DCHECK_GE(month, 1);
  DCHECK_LE(month, 12);
  // 3. If month is 1, 3, 5, 7, 8, 10, or 12, return 31.
  if (month % 2 == ((month < 8) ? 1 : 0)) return 31;
  // 4. If month is 4, 6, 9, or 11, return 30.
  DCHECK(month == 2 || month == 4 || month == 6 || month == 9 || month == 11);
  if (month != 2) return 30;
  // 5. If ! IsISOLeapYear(year) is true, return 29.
  return IsISOLeapYear(isolate, year) ? 29 : 28;
  // 6. Return 28.
}

// #sec-temporal-isodaysinyear
int32_t ISODaysInYear(Isolate* isolate, int32_t year) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: year is an integer.
  // 2. If ! IsISOLeapYear(year) is true, then
  // a. Return 366.
  // 3. Return 365.
  return IsISOLeapYear(isolate, year)
"""


```