Response: The user wants me to summarize the functionality of a C++ source code file related to JavaScript's Temporal API. This is part 5 of 13, which suggests a larger scope. I need to identify the core purpose of the code snippets provided and how they relate to date and time manipulation in JavaScript.

Here's a breakdown of the code:

1. **Validation Functions:** `IsValidTime`, `IsValidISODate` - These functions check if given time and date components form valid calendar dates and times.
2. **Comparison Functions:** `CompareISODate`, `CompareISODateTime` - These functions compare two dates or date-times and return -1, 0, or 1.
3. **Normalization/Balancing Functions:** `BalanceISOYearMonth`, `BalanceTime` - These functions take potentially out-of-range time or year-month components and normalize them (e.g., 61 minutes becomes 1 hour and 1 minute).
4. **Difference Function:** `DifferenceTime` -  Calculates the difference between two times.
5. **Addition Function:** `AddTime` - Adds a time duration to a given time.
6. **Total Duration in Nanoseconds:** `TotalDurationNanoseconds` - Converts a time duration into its equivalent in nanoseconds as a `BigInt`.
7. **ISOMonthDayFromFields:** `ISOMonthDayFromFields` -  Handles the creation of a date record from a JavaScript object potentially containing `month`, `monthCode`, and `year`.
8. **JSTemporalDuration Constructor:**  The constructor for `JSTemporalDuration`, taking individual date/time components as arguments.
9. **Helper Functions for Duration Operations:** Several functions starting with `ToRelativeTemporalObject`, `DefaultTemporalLargestUnit`, etc., suggest implementation details for more complex duration calculations like rounding, adding, and comparing.
10. **AdjustRoundedDurationDays:** `AdjustRoundedDurationDays` -  A function that adjusts a duration involving days, potentially considering timezones.
11. **CalculateOffsetShift:** `CalculateOffsetShift` - Calculates the offset difference in nanoseconds between two points in time, likely used in timezone calculations.
12. **MoveRelativeDate:** `MoveRelativeDate` -  A function to move a date by a duration, considering the calendar.
13. **UnbalanceDurationRelative:** `UnbalanceDurationRelative` -  Converts a duration to a representation with a specific largest unit, useful for calculations involving different units.
14. **BalanceDurationRelative:** `BalanceDurationRelative` -  Balances a date duration relative to a specific point in time.
15. **JSTemporalDuration::Compare:**  The C++ implementation of comparing two `JSTemporalDuration` objects.
16. **JSTemporalDuration::From:**  Creates a `JSTemporalDuration` from various input types.
17. **Helper Functions for Rounding:**  `MaximumTemporalDurationRoundingIncrement`, `ToTemporalRoundingIncrement` are related to the rounding of durations.
18. **MoveRelativeZonedDateTime:** `MoveRelativeZonedDateTime` - Moves a zoned date-time by a duration.
19. **RoundDuration:** `RoundDuration` - Implements the rounding of a duration to a specific unit.
20. **JSTemporalDuration::Round:** The C++ implementation for rounding a `JSTemporalDuration`.

**Overall Functionality:** This part of the `js-temporal-objects.cc` file seems to contain core logic for validating, comparing, and performing basic arithmetic operations (addition, subtraction implicitly through difference) on date and time components. It also includes more complex logic for handling durations, particularly when dealing with different units and timezones.

**Relationship to JavaScript:**  These C++ functions are the underlying implementation for the JavaScript `Temporal` API. They provide the low-level mechanics for the date and time manipulations that JavaScript developers interact with.
这个C++源代码文件（`v8/src/objects/js-temporal-objects.cc` 的第5部分）主要实现了 **Temporal API 中与基本日期和时间操作相关的核心功能**。 它定义了一些用于验证、比较、平衡（规范化）以及计算日期和时间的 C++ 函数。这些函数是 JavaScript 中 `Temporal` 对象（如 `Temporal.PlainDate`, `Temporal.PlainTime`, `Temporal.Duration` 等）行为的基础。

**具体功能归纳如下：**

1. **日期和时间的有效性检查:**
    *   `IsValidTime`:  验证小时、分钟、秒、毫秒、微秒和纳秒是否在有效范围内。
    *   `IsValidISODate`: 验证年、月、日是否构成一个有效的 ISO 日期。

2. **日期和时间的比较:**
    *   `CompareISODate`: 比较两个 ISO 日期的大小。
    *   `CompareISODateTime`: 比较两个 ISO 日期时间的大小。

3. **日期和时间的规范化 (Balancing):**
    *   `BalanceISOYearMonth`:  将可能超出范围的月份值调整到正常范围，并相应地调整年份。例如，月份为 13 会被调整为下一年的一月份。
    *   `BalanceTime`:  将可能超出范围的时间分量（如超过 60 的秒）调整到正常范围，并相应地调整更大的时间分量（如分钟和小时）。

4. **时间差的计算:**
    *   `DifferenceTime`: 计算两个 `TimeRecord` 之间的时间差，返回一个 `TimeDurationRecord`。

5. **时间的加法:**
    *   `AddTime`: 将一个 `TimeDurationRecord` 加到一个 `TimeRecord` 上，并返回规范化后的 `DateTimeRecord`。

6. **持续时间转换为纳秒:**
    *   `TotalDurationNanoseconds`: 将一个 `TimeDurationRecord` 的总持续时间转换为纳秒 `BigInt`。这个函数在处理精度要求高的场景非常重要。

7. **从字段创建 ISO 月日:**
    *   `ISOMonthDayFromFields`:  从一个包含 "day", "month", "monthCode", "year" 字段的 JavaScript 对象中提取并规范化 ISO 的月和日信息。

8. **`Temporal.Duration` 构造函数实现:**
    *   实现了 `Temporal.Duration` 类的构造函数，负责将传入的年、月、周、日、时、分、秒、毫秒、微秒和纳秒参数转换为内部表示。

9. **`Temporal.Duration` 操作的辅助函数:**
    *   定义了一系列辅助函数，用于实现 `Temporal.Duration` 的更复杂的操作，例如：
        *   `ToRelativeTemporalObject`: 将一个对象转换为相对的 Temporal 对象。
        *   `DefaultTemporalLargestUnit`: 确定 Duration 的默认最大单位。
        *   `RoundTemporalInstant`:  对一个时间戳进行舍入。
        *   `DifferenceInstant`: 计算两个时间戳的差值。
        *   `DifferenceZonedDateTime`: 计算两个带时区日期时间的差值。
        *   `AddDuration`: 将两个 Duration 相加。
        *   `AdjustRoundedDurationDays`: 调整舍入后的 Duration 的天数部分。
        *   `CalculateOffsetShift`: 计算时区偏移量的变化。
        *   `MoveRelativeDate`:  根据 Duration 移动一个相对的日期。
        *   `UnbalanceDurationRelative`: 将 Duration 转换为以指定最大单位表示的形式。
        *   `BalanceDurationRelative`: 平衡相对于特定日期的 Duration。
        *   `MaximumTemporalDurationRoundingIncrement`, `ToTemporalRoundingIncrement`:  用于 Duration 舍入的辅助函数。
        *   `MoveRelativeZonedDateTime`: 根据 Duration 移动一个带时区的日期时间。
        *   `RoundDuration`: 对 Duration 进行舍入。

10. **`Temporal.Duration.compare` 的实现:**
    *   `JSTemporalDuration::Compare`: 实现了比较两个 `Temporal.Duration` 对象的方法。

11. **`Temporal.Duration.from` 的实现:**
    *   `JSTemporalDuration::From`:  实现了从不同类型的值创建 `Temporal.Duration` 对象的方法。

12. **`Temporal.Duration.prototype.round` 的实现:**
    *   `JSTemporalDuration::Round`: 实现了 `Temporal.Duration` 对象的 `round` 方法，用于将 Duration 舍入到指定的单位。

**与 JavaScript 功能的关系及示例:**

这些 C++ 代码直接支持了 JavaScript 中 `Temporal` API 的使用。例如，`IsValidISODate` 对应于你可能在 JavaScript 中执行的日期有效性检查，而 `BalanceTime` 则在内部处理了时间分量的溢出。

**JavaScript 示例:**

```javascript
// 假设 JavaScript 引擎内部使用了这些 C++ 函数

// 有效性检查
const isValidDate = (year, month, day) => {
  // 引擎内部可能调用 IsValidISODate
  try {
    Temporal.PlainDate.from({ year, month, day });
    return true;
  } catch (e) {
    return false;
  }
};
console.log(isValidDate(2023, 10, 27)); // true
console.log(isValidDate(2023, 13, 1));  // false

// 比较日期
const compareDates = (date1, date2) => {
  // 引擎内部可能调用 CompareISODate
  if (date1.equals(date2)) return 0;
  if (date1 < date2) return -1;
  return 1;
};
const date1 = Temporal.PlainDate.from('2023-10-26');
const date2 = Temporal.PlainDate.from('2023-10-27');
console.log(compareDates(date1, date2)); // -1

// 平衡时间
const balanceTime = (hour, minute, second) => {
  // 引擎内部可能调用 BalanceTime
  const time = Temporal.PlainTime.from({ hour, minute, second });
  return {
    hour: time.hour,
    minute: time.minute,
    second: time.second,
  };
};
console.log(balanceTime(10, 70, 5)); // { hour: 11, minute: 10, second: 5 }

// 计算时间差
const diff = Temporal.PlainTime.from('10:00:00').until(Temporal.PlainTime.from('11:30:15'));
console.log(diff); // PT1H30M15S (引擎内部可能使用 DifferenceTime 等函数)

// Duration 的创建和比较
const duration1 = new Temporal.Duration(1, 2, 0, 5); // 1年 2月 5天
const duration2 = new Temporal.Duration(1, 1, 0, 7);
console.log(duration1.compare(duration2)); // 1 (引擎内部使用 JSTemporalDuration::Compare)

// Duration 的舍入
const durationToRound = new Temporal.Duration(0, 0, 0, 0, 1, 30, 45); // 1小时 30分 45秒
const roundedDuration = durationToRound.round({ smallestUnit: 'hour' });
console.log(roundedDuration); // PT2H (引擎内部使用 JSTemporalDuration::Round)
```

总而言之，这个 C++ 文件是 V8 引擎中 `Temporal` API 的核心实现部分，它提供了处理日期、时间和持续时间的基本构建块，确保了 JavaScript 中 `Temporal` 对象的正确行为和计算。

Prompt: 
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共13部分，请归纳一下它的功能

"""
 ? 366 : 365;
}

bool IsValidTime(Isolate* isolate, const TimeRecord& time) {
  TEMPORAL_ENTER_FUNC();

  // 2. If hour < 0 or hour > 23, then
  // a. Return false.
  if (time.hour < 0 || time.hour > 23) return false;
  // 3. If minute < 0 or minute > 59, then
  // a. Return false.
  if (time.minute < 0 || time.minute > 59) return false;
  // 4. If second < 0 or second > 59, then
  // a. Return false.
  if (time.second < 0 || time.second > 59) return false;
  // 5. If millisecond < 0 or millisecond > 999, then
  // a. Return false.
  if (time.millisecond < 0 || time.millisecond > 999) return false;
  // 6. If microsecond < 0 or microsecond > 999, then
  // a. Return false.
  if (time.microsecond < 0 || time.microsecond > 999) return false;
  // 7. If nanosecond < 0 or nanosecond > 999, then
  // a. Return false.
  if (time.nanosecond < 0 || time.nanosecond > 999) return false;
  // 8. Return true.
  return true;
}

// #sec-temporal-isvalidisodate
bool IsValidISODate(Isolate* isolate, const DateRecord& date) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: year, month, and day are integers.
  // 2. If month < 1 or month > 12, then
  // a. Return false.
  if (date.month < 1 || date.month > 12) return false;
  // 3. Let daysInMonth be ! ISODaysInMonth(year, month).
  // 4. If day < 1 or day > daysInMonth, then
  // a. Return false.
  if (date.day < 1 ||
      date.day > ISODaysInMonth(isolate, date.year, date.month)) {
    return false;
  }
  // 5. Return true.
  return true;
}

// #sec-temporal-compareisodate
int32_t CompareISODate(const DateRecord& one, const DateRecord& two) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: y1, m1, d1, y2, m2, and d2 are integers.
  // 2. If y1 > y2, return 1.
  if (one.year > two.year) return 1;
  // 3. If y1 < y2, return -1.
  if (one.year < two.year) return -1;
  // 4. If m1 > m2, return 1.
  if (one.month > two.month) return 1;
  // 5. If m1 < m2, return -1.
  if (one.month < two.month) return -1;
  // 6. If d1 > d2, return 1.
  if (one.day > two.day) return 1;
  // 7. If d1 < d2, return -1.
  if (one.day < two.day) return -1;
  // 8. Return 0.
  return 0;
}

int32_t CompareTemporalTime(const TimeRecord& time1, const TimeRecord& time2);

// #sec-temporal-compareisodatetime
int32_t CompareISODateTime(const DateTimeRecord& one,
                           const DateTimeRecord& two) {
  // 2. Let dateResult be ! CompareISODate(y1, mon1, d1, y2, mon2, d2).
  int32_t date_result = CompareISODate(one.date, two.date);
  // 3. If dateResult is not 0, then
  if (date_result != 0) {
    // a. Return dateResult.
    return date_result;
  }
  // 4. Return ! CompareTemporalTime(h1, min1, s1, ms1, mus1, ns1, h2, min2, s2,
  // ms2, mus2, ns2).
  return CompareTemporalTime(one.time, two.time);
}

inline int32_t floor_divid(int32_t a, int32_t b) {
  return (((a) / (b)) + ((((a) < 0) && (((a) % (b)) != 0)) ? -1 : 0));
}
// #sec-temporal-balanceisoyearmonth
void BalanceISOYearMonth(Isolate* isolate, int32_t* year, int32_t* month) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: year and month are integers.
  // 2. Set year to year + floor((month - 1) / 12).
  *year += floor_divid((*month - 1), 12);
  // 3. Set month to (month − 1) modulo 12 + 1.
  *month = static_cast<int32_t>(modulo(*month - 1, 12)) + 1;

  // 4. Return the new Record { [[Year]]: year, [[Month]]: month }.
}
// #sec-temporal-balancetime
DateTimeRecord BalanceTime(const UnbalancedTimeRecord& input) {
  TEMPORAL_ENTER_FUNC();
  UnbalancedTimeRecord time(input);
  TimeRecord result;

  // 1. Assert: hour, minute, second, millisecond, microsecond, and nanosecond
  // are integers.
  // 2. Set microsecond to microsecond + floor(nanosecond / 1000).
  time.microsecond += std::floor(time.nanosecond / 1000.0);
  // 3. Set nanosecond to nanosecond modulo 1000.
  result.nanosecond = modulo(time.nanosecond, 1000);
  // 4. Set millisecond to millisecond + floor(microsecond / 1000).
  time.millisecond += std::floor(time.microsecond / 1000.0);
  // 5. Set microsecond to microsecond modulo 1000.
  result.microsecond = modulo(time.microsecond, 1000);
  // 6. Set second to second + floor(millisecond / 1000).
  time.second += std::floor(time.millisecond / 1000.0);
  // 7. Set millisecond to millisecond modulo 1000.
  result.millisecond = modulo(time.millisecond, 1000);
  // 8. Set minute to minute + floor(second / 60).
  time.minute += std::floor(time.second / 60.0);
  // 9. Set second to second modulo 60.
  result.second = modulo(time.second, 60);
  // 10. Set hour to hour + floor(minute / 60).
  time.hour += std::floor(time.minute / 60.0);
  // 11. Set minute to minute modulo 60.
  result.minute = modulo(time.minute, 60);
  // 12. Let days be floor(hour / 24).
  int32_t days = std::floor(time.hour / 24.0);
  // 13. Set hour to hour modulo 24.
  result.hour = modulo(time.hour, 24);
  // 14. Return the new Record { [[Days]]: days, [[Hour]]: hour, [[Minute]]:
  // minute, [[Second]]: second, [[Millisecond]]: millisecond, [[Microsecond]]:
  // microsecond, [[Nanosecond]]: nanosecond }.
  return {{0, 0, days}, result};
}

// #sec-temporal-differencetime
Maybe<TimeDurationRecord> DifferenceTime(Isolate* isolate,
                                         const TimeRecord& time1,
                                         const TimeRecord& time2) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: h1, min1, s1, ms1, mus1, ns1, h2, min2, s2, ms2, mus2, and ns2
  // are integers.
  TimeDurationRecord dur;
  // 2. Let hours be h2 − h1.
  dur.hours = time2.hour - time1.hour;
  // 3. Let minutes be min2 − min1.
  dur.minutes = time2.minute - time1.minute;
  // 4. Let seconds be s2 − s1.
  dur.seconds = time2.second - time1.second;
  // 5. Let milliseconds be ms2 − ms1.
  dur.milliseconds = time2.millisecond - time1.millisecond;
  // 6. Let microseconds be mus2 − mus1.
  dur.microseconds = time2.microsecond - time1.microsecond;
  // 7. Let nanoseconds be ns2 − ns1.
  dur.nanoseconds = time2.nanosecond - time1.nanosecond;
  // 8. Let sign be ! DurationSign(0, 0, 0, 0, hours, minutes, seconds,
  // milliseconds, microseconds, nanoseconds).
  double sign = DurationRecord::Sign(
      {0,
       0,
       0,
       {0, dur.hours, dur.minutes, dur.seconds, dur.milliseconds,
        dur.microseconds, dur.nanoseconds}});

  // 9. Let bt be ! BalanceTime(hours × sign, minutes × sign, seconds × sign,
  // milliseconds × sign, microseconds × sign, nanoseconds × sign).
  DateTimeRecord bt =
      BalanceTime({dur.hours * sign, dur.minutes * sign, dur.seconds * sign,
                   dur.milliseconds * sign, dur.microseconds * sign,
                   dur.nanoseconds * sign});

  // 9. Return ! CreateTimeDurationRecord(bt.[[Days]] × sign, bt.[[Hour]] ×
  // sign, bt.[[Minute]] × sign, bt.[[Second]] × sign, bt.[[Millisecond]] ×
  // sign, bt.[[Microsecond]] × sign, bt.[[Nanosecond]] × sign).
  return TimeDurationRecord::Create(
      isolate, bt.date.day * sign, bt.time.hour * sign, bt.time.minute * sign,
      bt.time.second * sign, bt.time.millisecond * sign,
      bt.time.microsecond * sign, bt.time.nanosecond * sign);
}

// #sec-temporal-addtime
DateTimeRecord AddTime(Isolate* isolate, const TimeRecord& time,
                       const TimeDurationRecord& addend) {
  TEMPORAL_ENTER_FUNC();

  DCHECK_EQ(addend.days, 0);
  // 1. Assert: hour, minute, second, millisecond, microsecond, nanosecond,
  // hours, minutes, seconds, milliseconds, microseconds, and nanoseconds are
  // integers.
  // 2. Let hour be hour + hours.
  return BalanceTime({time.hour + addend.hours,
                      // 3. Let minute be minute + minutes.
                      time.minute + addend.minutes,
                      // 4. Let second be second + seconds.
                      time.second + addend.seconds,
                      // 5. Let millisecond be millisecond + milliseconds.
                      time.millisecond + addend.milliseconds,
                      // 6. Let microsecond be microsecond + microseconds.
                      time.microsecond + addend.microseconds,
                      // 7. Let nanosecond be nanosecond + nanoseconds.
                      time.nanosecond + addend.nanoseconds});
  // 8. Return ! BalanceTime(hour, minute, second, millisecond, microsecond,
  // nanosecond).
}

// #sec-temporal-totaldurationnanoseconds
Handle<BigInt> TotalDurationNanoseconds(Isolate* isolate,
                                        const TimeDurationRecord& value,
                                        double offset_shift) {
  TEMPORAL_ENTER_FUNC();

  TimeDurationRecord duration(value);

  Handle<BigInt> nanoseconds =
      BigInt::FromNumber(isolate,
                         isolate->factory()->NewNumber(value.nanoseconds))
          .ToHandleChecked();

  // 1. Assert: offsetShift is an integer.
  // 2. Set nanoseconds to ℝ(nanoseconds).
  // 3. If days ≠ 0, then
  if (duration.days != 0) {
    // a. Set nanoseconds to nanoseconds − offsetShift.
    nanoseconds = BigInt::Subtract(
                      isolate, nanoseconds,
                      BigInt::FromNumber(
                          isolate, isolate->factory()->NewNumber(offset_shift))
                          .ToHandleChecked())
                      .ToHandleChecked();
  }

  Handle<BigInt> thousand = BigInt::FromInt64(isolate, 1000);
  Handle<BigInt> sixty = BigInt::FromInt64(isolate, 60);
  Handle<BigInt> twentyfour = BigInt::FromInt64(isolate, 24);
  // 4. Set hours to ℝ(hours) + ℝ(days) × 24.

  Handle<BigInt> x =
      BigInt::FromNumber(isolate, isolate->factory()->NewNumber(value.days))
          .ToHandleChecked();
  x = BigInt::Multiply(isolate, twentyfour, x).ToHandleChecked();
  x = BigInt::Add(isolate, x,
                  BigInt::FromNumber(isolate,
                                     isolate->factory()->NewNumber(value.hours))
                      .ToHandleChecked())
          .ToHandleChecked();

  // 5. Set minutes to ℝ(minutes) + hours × 60.
  x = BigInt::Multiply(isolate, sixty, x).ToHandleChecked();
  x = BigInt::Add(isolate, x,
                  BigInt::FromNumber(
                      isolate, isolate->factory()->NewNumber(value.minutes))
                      .ToHandleChecked())
          .ToHandleChecked();
  // 6. Set seconds to ℝ(seconds) + minutes × 60.
  x = BigInt::Multiply(isolate, sixty, x).ToHandleChecked();
  x = BigInt::Add(isolate, x,
                  BigInt::FromNumber(
                      isolate, isolate->factory()->NewNumber(value.seconds))
                      .ToHandleChecked())
          .ToHandleChecked();
  // 7. Set milliseconds to ℝ(milliseconds) + seconds × 1000.
  x = BigInt::Multiply(isolate, thousand, x).ToHandleChecked();
  x = BigInt::Add(isolate, x,
                  BigInt::FromNumber(isolate, isolate->factory()->NewNumber(
                                                  value.milliseconds))
                      .ToHandleChecked())
          .ToHandleChecked();
  // 8. Set microseconds to ℝ(microseconds) + milliseconds × 1000.
  x = BigInt::Multiply(isolate, thousand, x).ToHandleChecked();
  x = BigInt::Add(isolate, x,
                  BigInt::FromNumber(isolate, isolate->factory()->NewNumber(
                                                  value.microseconds))
                      .ToHandleChecked())
          .ToHandleChecked();
  // 9. Return nanoseconds + microseconds × 1000.
  x = BigInt::Multiply(isolate, thousand, x).ToHandleChecked();
  x = BigInt::Add(isolate, x, nanoseconds).ToHandleChecked();
  return x;
}

Maybe<DateRecord> RegulateISODate(Isolate* isolate, ShowOverflow overflow,
                                  const DateRecord& date);
Maybe<int32_t> ResolveISOMonth(Isolate* isolate, Handle<JSReceiver> fields);

// #sec-temporal-isomonthdayfromfields
Maybe<DateRecord> ISOMonthDayFromFields(Isolate* isolate,
                                        Handle<JSReceiver> fields,
                                        Handle<JSReceiver> options,
                                        const char* method_name) {
  Factory* factory = isolate->factory();
  // 1. Assert: Type(fields) is Object.
  // 2. Set fields to ? PrepareTemporalFields(fields, « "day", "month",
  // "monthCode", "year" », «"day"»).
  DirectHandle<FixedArray> field_names =
      DayMonthMonthCodeYearInFixedArray(isolate);
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, fields,
      PrepareTemporalFields(isolate, fields, field_names, RequiredFields::kDay),
      Nothing<DateRecord>());
  // 3. Let overflow be ? ToTemporalOverflow(options).
  ShowOverflow overflow;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, overflow, ToTemporalOverflow(isolate, options, method_name),
      Nothing<DateRecord>());
  // 4. Let month be ! Get(fields, "month").
  DirectHandle<Object> month_obj =
      JSReceiver::GetProperty(isolate, fields, factory->month_string())
          .ToHandleChecked();
  // 5. Let monthCode be ! Get(fields, "monthCode").
  DirectHandle<Object> month_code_obj =
      JSReceiver::GetProperty(isolate, fields, factory->monthCode_string())
          .ToHandleChecked();
  // 6. Let year be ! Get(fields, "year").
  DirectHandle<Object> year_obj =
      JSReceiver::GetProperty(isolate, fields, factory->year_string())
          .ToHandleChecked();
  // 7. If month is not undefined, and monthCode and year are both undefined,
  // then
  if (!IsUndefined(*month_obj, isolate) &&
      IsUndefined(*month_code_obj, isolate) &&
      IsUndefined(*year_obj, isolate)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<DateRecord>());
  }
  // 8. Set month to ? ResolveISOMonth(fields).
  DateRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, result.month,
                                         ResolveISOMonth(isolate, fields),
                                         Nothing<DateRecord>());

  // 9. Let day be ! Get(fields, "day").
  DirectHandle<Object> day_obj =
      JSReceiver::GetProperty(isolate, fields, factory->day_string())
          .ToHandleChecked();
  // 10. Assert: Type(day) is Number.
  // Note: "day" in fields is always converted by
  // ToIntegerThrowOnInfinity inside the PrepareTemporalFields above.
  // Therefore the day_obj is always an integer.
  result.day = FastD2I(floor(Object::NumberValue(Cast<Number>(*day_obj))));
  // 11. Let referenceISOYear be 1972 (the first leap year after the Unix
  // epoch).
  int32_t reference_iso_year = 1972;
  // 12. If monthCode is undefined, then
  if (IsUndefined(*month_code_obj, isolate)) {
    result.year = FastD2I(floor(Object::NumberValue(Cast<Number>(*year_obj))));
    // a. Let result be ? RegulateISODate(year, month, day, overflow).
  } else {
    // 13. Else,
    // a. Let result be ? RegulateISODate(referenceISOYear, month, day,
    // overflow).
    result.year = reference_iso_year;
  }
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, RegulateISODate(isolate, overflow, result),
      Nothing<DateRecord>());
  // 14. Return the new Record { [[Month]]: result.[[Month]], [[Day]]:
  // result.[[Day]], [[ReferenceISOYear]]: referenceISOYear }.
  result.year = reference_iso_year;
  return Just(result);
}

}  // namespace

// #sec-temporal.duration
MaybeHandle<JSTemporalDuration> JSTemporalDuration::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> years, Handle<Object> months, Handle<Object> weeks,
    Handle<Object> days, Handle<Object> hours, Handle<Object> minutes,
    Handle<Object> seconds, Handle<Object> milliseconds,
    Handle<Object> microseconds, Handle<Object> nanoseconds) {
  const char* method_name = "Temporal.Duration";
  // 1. If NewTarget is undefined, then
  if (IsUndefined(*new_target)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }
  // 2. Let y be ? ToIntegerWithoutRounding(years).
  double y;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, y, ToIntegerWithoutRounding(isolate, years),
      Handle<JSTemporalDuration>());

  // 3. Let mo be ? ToIntegerWithoutRounding(months).
  double mo;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, mo, ToIntegerWithoutRounding(isolate, months),
      Handle<JSTemporalDuration>());

  // 4. Let w be ? ToIntegerWithoutRounding(weeks).
  double w;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, w, ToIntegerWithoutRounding(isolate, weeks),
      Handle<JSTemporalDuration>());

  // 5. Let d be ? ToIntegerWithoutRounding(days).
  double d;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, d, ToIntegerWithoutRounding(isolate, days),
      Handle<JSTemporalDuration>());

  // 6. Let h be ? ToIntegerWithoutRounding(hours).
  double h;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, h, ToIntegerWithoutRounding(isolate, hours),
      Handle<JSTemporalDuration>());

  // 7. Let m be ? ToIntegerWithoutRounding(minutes).
  double m;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, m, ToIntegerWithoutRounding(isolate, minutes),
      Handle<JSTemporalDuration>());

  // 8. Let s be ? ToIntegerWithoutRounding(seconds).
  double s;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, s, ToIntegerWithoutRounding(isolate, seconds),
      Handle<JSTemporalDuration>());

  // 9. Let ms be ? ToIntegerWithoutRounding(milliseconds).
  double ms;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, ms, ToIntegerWithoutRounding(isolate, milliseconds),
      Handle<JSTemporalDuration>());

  // 10. Let mis be ? ToIntegerWithoutRounding(microseconds).
  double mis;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, mis, ToIntegerWithoutRounding(isolate, microseconds),
      Handle<JSTemporalDuration>());

  // 11. Let ns be ? ToIntegerWithoutRounding(nanoseconds).
  double ns;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, ns, ToIntegerWithoutRounding(isolate, nanoseconds),
      Handle<JSTemporalDuration>());

  // 12. Return ? CreateTemporalDuration(y, mo, w, d, h, m, s, ms, mis, ns,
  // NewTarget).
  return CreateTemporalDuration(isolate, target, new_target,
                                {y, mo, w, {d, h, m, s, ms, mis, ns}});
}

namespace {

// #sec-temporal-torelativetemporalobject
MaybeHandle<Object> ToRelativeTemporalObject(Isolate* isolate,
                                             Handle<JSReceiver> options,
                                             const char* method_name);

// #sec-temporal-defaulttemporallargestunit
Unit DefaultTemporalLargestUnit(const DurationRecord& dur);

// #sec-temporal-roundtemporalinstant
Handle<BigInt> RoundTemporalInstant(Isolate* isolate, Handle<BigInt> ns,
                                    double increment, Unit unit,
                                    RoundingMode rounding_mode);

// #sec-temporal-differenceinstant
TimeDurationRecord DifferenceInstant(Isolate* isolate, Handle<BigInt> ns1,
                                     Handle<BigInt> ns2,
                                     double rounding_increment,
                                     Unit smallest_unit, Unit largest_unit,
                                     RoundingMode rounding_mode,
                                     const char* method_name);

// #sec-temporal-differencezoneddatetime
Maybe<DurationRecord> DifferenceZonedDateTime(
    Isolate* isolate, Handle<BigInt> ns1, Handle<BigInt> ns2,
    Handle<JSReceiver> time_zone, Handle<JSReceiver> calendar,
    Unit largest_unit, Handle<JSReceiver> options, const char* method_name);

// #sec-temporal-addduration
Maybe<DurationRecord> AddDuration(Isolate* isolate, const DurationRecord& dur1,
                                  const DurationRecord& dur2,
                                  Handle<Object> relative_to_obj,
                                  const char* method_name);

// #sec-temporal-adjustroundeddurationdays
Maybe<DurationRecord> AdjustRoundedDurationDays(Isolate* isolate,
                                                const DurationRecord& duration,
                                                double increment, Unit unit,
                                                RoundingMode rounding_mode,
                                                Handle<Object> relative_to_obj,
                                                const char* method_name) {
  // 1. If Type(relativeTo) is not Object; or relativeTo does not have an
  // [[InitializedTemporalZonedDateTime]] internal slot; or unit is one of
  // "year", "month", "week", or "day"; or unit is "nanosecond" and increment is
  // 1, then
  if (!IsJSTemporalZonedDateTime(*relative_to_obj) ||
      (unit == Unit::kYear || unit == Unit::kMonth || unit == Unit::kWeek ||
       unit == Unit::kDay) ||
      (unit == Unit::kNanosecond && increment == 1)) {
    // a. Return ! CreateDurationRecord(years, months, weeks, days, hours,
    // minutes, seconds, milliseconds, microseconds, nanoseconds).
    return Just(CreateDurationRecord(isolate, duration).ToChecked());
  }
  Handle<JSTemporalZonedDateTime> relative_to =
      Cast<JSTemporalZonedDateTime>(relative_to_obj);
  // 2. Let timeRemainderNs be ! TotalDurationNanoseconds(0, hours, minutes,
  // seconds, milliseconds, microseconds, nanoseconds, 0).
  Handle<BigInt> time_remainder_ns = TotalDurationNanoseconds(
      isolate,
      {0, duration.time_duration.hours, duration.time_duration.minutes,
       duration.time_duration.seconds, duration.time_duration.milliseconds,
       duration.time_duration.microseconds, duration.time_duration.nanoseconds},
      0);

  ComparisonResult compare =
      BigInt::CompareToNumber(time_remainder_ns, handle(Smi::zero(), isolate));
  double direction;
  // 3. If timeRemainderNs = 0, let direction be 0.
  if (compare == ComparisonResult::kEqual) {
    direction = 0;
    // 4. Else if timeRemainderNs < 0, let direction be -1.
  } else if (compare == ComparisonResult::kLessThan) {
    direction = -1;
    // 5. Else, let direction be 1.
  } else {
    direction = 1;
  }

  // 6. Let dayStart be ? AddZonedDateTime(relativeTo.[[Nanoseconds]],
  // relativeTo.[[TimeZone]], relativeTo.[[Calendar]], years, months, weeks,
  // days, 0, 0, 0, 0, 0, 0).
  Handle<BigInt> day_start;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, day_start,
      AddZonedDateTime(isolate, handle(relative_to->nanoseconds(), isolate),
                       handle(relative_to->time_zone(), isolate),
                       handle(relative_to->calendar(), isolate),
                       {duration.years,
                        duration.months,
                        duration.weeks,
                        {duration.time_duration.days, 0, 0, 0, 0, 0, 0}},
                       method_name),
      Nothing<DurationRecord>());
  // 7. Let dayEnd be ? AddZonedDateTime(dayStart, relativeTo.[[TimeZone]],
  // relativeTo.[[Calendar]], 0, 0, 0, direction, 0, 0, 0, 0, 0, 0).
  Handle<BigInt> day_end;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, day_end,
      AddZonedDateTime(isolate, day_start,
                       handle(relative_to->time_zone(), isolate),
                       handle(relative_to->calendar(), isolate),
                       {0, 0, 0, {direction, 0, 0, 0, 0, 0, 0}}, method_name),
      Nothing<DurationRecord>());
  // 8. Let dayLengthNs be ℝ(dayEnd - dayStart).
  Handle<BigInt> day_length_ns =
      BigInt::Subtract(isolate, day_end, day_start).ToHandleChecked();
  // 9. If (timeRemainderNs - dayLengthNs) × direction < 0, then
  Handle<BigInt> time_remainder_ns_minus_day_length_ns =
      BigInt::Subtract(isolate, time_remainder_ns, day_length_ns)
          .ToHandleChecked();

  if (time_remainder_ns_minus_day_length_ns->AsInt64() * direction < 0) {
    // a. Return ! CreateDurationRecord(years, months, weeks, days, hours,
    // minutes, seconds, milliseconds, microseconds, nanoseconds).
    return Just(CreateDurationRecord(isolate, duration).ToChecked());
  }
  // 10. Set timeRemainderNs to ! RoundTemporalInstant(ℤ(timeRemainderNs -
  // dayLengthNs), increment, unit, roundingMode).
  time_remainder_ns =
      RoundTemporalInstant(isolate, time_remainder_ns_minus_day_length_ns,
                           increment, unit, rounding_mode);
  // 11. Let adjustedDateDuration be ? AddDuration(years, months, weeks, days,
  // 0, 0, 0, 0, 0, 0, 0, 0, 0, direction, 0, 0, 0, 0, 0, 0, relativeTo).
  DurationRecord adjusted_date_duration;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, adjusted_date_duration,
      AddDuration(isolate,
                  {duration.years,
                   duration.months,
                   duration.weeks,
                   {duration.time_duration.days, 0, 0, 0, 0, 0, 0}},
                  {0, 0, 0, {direction, 0, 0, 0, 0, 0, 0}}, relative_to,
                  method_name),
      Nothing<DurationRecord>());
  // 12. Let adjustedTimeDuration be ? BalanceDuration(0, 0, 0, 0, 0, 0,
  // timeRemainderNs, "hour").
  TimeDurationRecord adjusted_time_duration;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, adjusted_time_duration,
      BalanceDuration(isolate, Unit::kHour, time_remainder_ns, method_name),
      Nothing<DurationRecord>());
  // 13. Return ! CreateDurationRecord(adjustedDateDuration.[[Years]],
  // adjustedDateDuration.[[Months]], adjustedDateDuration.[[Weeks]],
  // adjustedDateDuration.[[Days]], adjustedTimeDuration.[[Hours]],
  // adjustedTimeDuration.[[Minutes]], adjustedTimeDuration.[[Seconds]],
  // adjustedTimeDuration.[[Milliseconds]],
  // adjustedTimeDuration.[[Microseconds]],
  // adjustedTimeDuration.[[Nanoseconds]]).
  adjusted_time_duration.days = adjusted_date_duration.time_duration.days;
  return Just(
      CreateDurationRecord(
          isolate, {adjusted_date_duration.years, adjusted_date_duration.months,
                    adjusted_date_duration.weeks, adjusted_time_duration})
          .ToChecked());
}

// #sec-temporal-calculateoffsetshift
Maybe<int64_t> CalculateOffsetShift(Isolate* isolate,
                                    Handle<Object> relative_to_obj,
                                    const DateDurationRecord& dur,
                                    const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 1. If Type(relativeTo) is not Object or relativeTo does not have an
  // [[InitializedTemporalZonedDateTime]] internal slot, return 0.
  if (!IsJSTemporalZonedDateTime(*relative_to_obj)) {
    return Just(static_cast<int64_t>(0));
  }
  auto relative_to = Cast<JSTemporalZonedDateTime>(relative_to_obj);
  // 2. Let instant be ! CreateTemporalInstant(relativeTo.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(relative_to->nanoseconds(), isolate))
          .ToHandleChecked();
  // 3. Let offsetBefore be ? GetOffsetNanosecondsFor(relativeTo.[[TimeZone]],
  // instant).
  int64_t offset_before;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_before,
      GetOffsetNanosecondsFor(isolate,
                              handle(relative_to->time_zone(), isolate),
                              instant, method_name),
      Nothing<int64_t>());
  // 4. Let after be ? AddZonedDateTime(relativeTo.[[Nanoseconds]],
  // relativeTo.[[TimeZone]], relativeTo.[[Calendar]], y, mon, w, d, 0, 0, 0, 0,
  // 0, 0).
  Handle<BigInt> after;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, after,
      AddZonedDateTime(
          isolate, handle(relative_to->nanoseconds(), isolate),
          handle(relative_to->time_zone(), isolate),
          handle(relative_to->calendar(), isolate),
          {dur.years, dur.months, dur.weeks, {dur.days, 0, 0, 0, 0, 0, 0}},
          method_name),
      Nothing<int64_t>());
  // 5. Let instantAfter be ! CreateTemporalInstant(after).
  Handle<JSTemporalInstant> instant_after =
      temporal::CreateTemporalInstant(isolate, after).ToHandleChecked();
  // 6. Let offsetAfter be ? GetOffsetNanosecondsFor(relativeTo.[[TimeZone]],
  // instantAfter).
  int64_t offset_after;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_after,
      GetOffsetNanosecondsFor(isolate,
                              handle(relative_to->time_zone(), isolate),
                              instant_after, method_name),
      Nothing<int64_t>());
  // 7. Return offsetAfter − offsetBefore
  return Just(offset_after - offset_before);
}

// #sec-temporal-moverelativedate
struct MoveRelativeDateResult {
  Handle<JSTemporalPlainDate> relative_to;
  double days;
};
Maybe<MoveRelativeDateResult> MoveRelativeDate(
    Isolate* isolate, Handle<JSReceiver> calendar,
    Handle<JSTemporalPlainDate> relative_to,
    Handle<JSTemporalDuration> duration, const char* method_name);

// #sec-temporal-unbalancedurationrelative
Maybe<DateDurationRecord> UnbalanceDurationRelative(
    Isolate* isolate, const DateDurationRecord& dur, Unit largest_unit,
    Handle<Object> relative_to_obj, const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 1. If largestUnit is "year", or years, months, weeks, and days are all 0,
  // then
  if (largest_unit == Unit::kYear ||
      (dur.years == 0 && dur.months == 0 && dur.weeks == 0 && dur.days == 0)) {
    // a. Return ! CreateDateDurationRecord(years, months, weeks, days).
    return Just(DateDurationRecord::Create(isolate, dur.years, dur.months,
                                           dur.weeks, dur.days)
                    .ToChecked());
  }
  // 2. Let sign be ! DurationSign(years, months, weeks, days, 0, 0, 0, 0, 0,
  // 0).
  double sign = DurationRecord::Sign(
      {dur.years, dur.months, dur.weeks, {dur.days, 0, 0, 0, 0, 0, 0}});
  // 3. Assert: sign ≠ 0.
  DCHECK_NE(sign, 0);
  // 4. Let oneYear be ! CreateTemporalDuration(sign, 0, 0, 0, 0, 0, 0, 0, 0,
  // 0).
  Handle<JSTemporalDuration> one_year =
      CreateTemporalDuration(isolate, {sign, 0, 0, {0, 0, 0, 0, 0, 0, 0}})
          .ToHandleChecked();
  // 5. Let oneMonth be ! CreateTemporalDuration(0, sign, 0, 0, 0, 0, 0, 0, 0,
  // 0).
  Handle<JSTemporalDuration> one_month =
      CreateTemporalDuration(isolate, {0, sign, 0, {0, 0, 0, 0, 0, 0, 0}})
          .ToHandleChecked();
  // 6. Let oneWeek be ! CreateTemporalDuration(0, 0, sign, 0, 0, 0, 0, 0, 0,
  // 0).
  Handle<JSTemporalDuration> one_week =
      CreateTemporalDuration(isolate, {0, 0, sign, {0, 0, 0, 0, 0, 0, 0}})
          .ToHandleChecked();
  // 7. If relativeTo is not undefined, then
  Handle<JSTemporalPlainDate> relative_to;
  Handle<JSReceiver> calendar;
  if (!IsUndefined(*relative_to_obj)) {
    // a. Set relativeTo to ? ToTemporalDate(relativeTo).
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, relative_to,
        ToTemporalDate(isolate, relative_to_obj, method_name),
        Nothing<DateDurationRecord>());
    // b. Let calendar be relativeTo.[[Calendar]].
    calendar = handle(relative_to->calendar(), isolate);
    // 8. Else,
  } else {
    // a. Let calendar be undefined.
  }
  DateDurationRecord result = dur;
  // 9. If largestUnit is "month", then
  if (largest_unit == Unit::kMonth) {
    // a. If calendar is undefined, then
    if (calendar.is_null()) {
      // i. Throw a RangeError exception.
      THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                   NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                   Nothing<DateDurationRecord>());
    }
    // b. Let dateAdd be ? GetMethod(calendar, "dateAdd").
    Handle<Object> date_add;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, date_add,
        Object::GetMethod(isolate, calendar, factory->dateAdd_string()),
        Nothing<DateDurationRecord>());
    // c. Let dateUntil be ? GetMethod(calendar, "dateUntil").
    Handle<Object> date_until;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, date_until,
        Object::GetMethod(isolate, calendar, factory->dateUntil_string()),
        Nothing<DateDurationRecord>());
    // d. Repeat, while years ≠ 0,
    while (result.years != 0) {
      // i. Let newRelativeTo be ? CalendarDateAdd(calendar, relativeTo,
      // oneYear, undefined, dateAdd).
      Handle<JSTemporalPlainDate> new_relative_to;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, new_relative_to,
          CalendarDateAdd(isolate, calendar, relative_to, one_year,
                          factory->undefined_value(), date_add),
          Nothing<DateDurationRecord>());
      // ii. Let untilOptions be ! OrdinaryObjectCreate(null).
      Handle<JSObject> until_options = factory->NewJSObjectWithNullProto();
      // iii. Perform ! CreateDataPropertyOrThrow(untilOptions, "largestUnit",
      // "month").
      CHECK(JSReceiver::CreateDataProperty(
                isolate, until_options, factory->largestUnit_string(),
                factory->month_string(), Just(kThrowOnError))
                .FromJust());
      // iv. Let untilResult be ? CalendarDateUntil(calendar, relativeTo,
      // newRelativeTo, untilOptions, dateUntil).
      Handle<JSTemporalDuration> until_result;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, until_result,
          CalendarDateUntil(isolate, calendar, relative_to, new_relative_to,
                            until_options, date_until),
          Nothing<DateDurationRecord>());
      // v. Let oneYearMonths be untilResult.[[Months]].
      double one_year_months = Object::NumberValue(until_result->months());
      // vi. Set relativeTo to newRelativeTo.
      relative_to = new_relative_to;
      // vii. Set years to years − sign.
      result.years -= sign;
      // viii. Set months to months + oneYearMonths.
      result.months += one_year_months;
    }
    // 10. Else if largestUnit is "week", then
  } else if (largest_unit == Unit::kWeek) {
    // a. If calendar is undefined, then
    if (calendar.is_null()) {
      // i. Throw a RangeError exception.
      THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                   NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                   Nothing<DateDurationRecord>());
    }
    // b. Repeat, while years ≠ 0,
    while (result.years != 0) {
      // i. Let moveResult be ? MoveRelativeDate(calendar, relativeTo, oneYear).
      MoveRelativeDateResult move_result;
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar, relative_to, one_year,
                           method_name),
          Nothing<DateDurationRecord>());
      // ii. Set relativeTo to moveResult.[[RelativeTo]].
      relative_to = move_result.relative_to;
      // iii. Set days to days + moveResult.[[Days]].
      result.days += move_result.days;
      // iv. Set years to years - sign.
      result.years -= sign;
    }
    // c. Repeat, while months ≠ 0,
    while (result.months != 0) {
      // i. Let moveResult be ? MoveRelativeDate(calendar, relativeTo,
      // oneMonth).
      MoveRelativeDateResult move_result;
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar, relative_to, one_month,
                           method_name),
          Nothing<DateDurationRecord>());
      // ii. Set relativeTo to moveResult.[[RelativeTo]].
      relative_to = move_result.relative_to;
      // iii. Set days to days + moveResult.[[Days]].
      result.days += move_result.days;
      // iv. Set months to months - sign.
      result.months -= sign;
    }
    // 11. Else,
  } else {
    // a. If any of years, months, and weeks are not zero, then
    if ((result.years != 0) || (result.months != 0) || (result.weeks != 0)) {
      // i. If calendar is undefined, then
      if (calendar.is_null()) {
        // i. Throw a RangeError exception.
        THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                     NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                     Nothing<DateDurationRecord>());
      }
      // b. Repeat, while years ≠ 0,
      while (result.years != 0) {
        // i. Let moveResult be ? MoveRelativeDate(calendar, relativeTo,
        // oneYear).
        MoveRelativeDateResult move_result;
        MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, move_result,
            MoveRelativeDate(isolate, calendar, relative_to, one_year,
                             method_name),
            Nothing<DateDurationRecord>());
        // ii. Set relativeTo to moveResult.[[RelativeTo]].
        relative_to = move_result.relative_to;
        // iii. Set days to days + moveResult.[[Days]].
        result.days += move_result.days;
        // iv. Set years to years - sign.
        result.years -= sign;
      }
      // c. Repeat, while months ≠ 0,
      while (result.months != 0) {
        // i. Let moveResult be ? MoveRelativeDate(calendar, relativeTo,
        // oneMonth).
        MoveRelativeDateResult move_result;
        MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, move_result,
            MoveRelativeDate(isolate, calendar, relative_to, one_month,
                             method_name),
            Nothing<DateDurationRecord>());
        // ii. Set relativeTo to moveResult.[[RelativeTo]].
        relative_to = move_result.relative_to;
        // iii. Set days to days + moveResult.[[Days]].
        result.days += move_result.days;
        // iv. Set months to years - sign.
        result.months -= sign;
      }
      // d. Repeat, while weeks ≠ 0,
      while (result.weeks != 0) {
        // i. Let moveResult be ? MoveRelativeDate(calendar, relativeTo,
        // oneWeek).
        MoveRelativeDateResult move_result;
        MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, move_result,
            MoveRelativeDate(isolate, calendar, relative_to, one_week,
                             method_name),
            Nothing<DateDurationRecord>());
        // ii. Set relativeTo to moveResult.[[RelativeTo]].
        relative_to = move_result.relative_to;
        // iii. Set days to days + moveResult.[[Days]].
        result.days += move_result.days;
        // iv. Set weeks to years - sign.
        result.weeks -= sign;
      }
    }
  }
  // 12. Return ? CreateDateDurationRecord(years, months, weeks, days).
  return DateDurationRecord::Create(isolate, result.years, result.months,
                                    result.weeks, result.days);
}

// #sec-temporal-balancedurationrelative
Maybe<DateDurationRecord> BalanceDurationRelative(
    Isolate* isolate, const DateDurationRecord& dur, Unit largest_unit,
    Handle<Object> relative_to_obj, const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 1. If largestUnit is not one of "year", "month", or "week", or years,
  // months, weeks, and days are all 0, then

  if ((largest_unit != Unit::kYear && largest_unit != Unit::kMonth &&
       largest_unit != Unit::kWeek) ||
      (dur.years == 0 && dur.months == 0 && dur.weeks == 0 && dur.days == 0)) {
    // a. Return ! CreateDateDurationRecord(years, months, weeks, days).
    return Just(DateDurationRecord::Create(isolate, dur.years, dur.months,
                                           dur.weeks, dur.days)
                    .ToChecked());
  }
  // 2. If relativeTo is undefined, then
  if (IsUndefined(*relative_to_obj)) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateDurationRecord>());
  }

  // 3. Let sign be ! DurationSign(years, months, weeks, days, 0, 0, 0, 0, 0,
  // 0).
  double sign = DurationRecord::Sign(
      {dur.years, dur.months, dur.weeks, {dur.days, 0, 0, 0, 0, 0, 0}});
  // 4. Assert: sign ≠ 0.
  DCHECK_NE(sign, 0);
  // 5. Let oneYear be ! CreateTemporalDuration(sign, 0, 0, 0, 0, 0, 0, 0, 0,
  // 0).
  Handle<JSTemporalDuration> one_year =
      CreateTemporalDuration(isolate, {sign, 0, 0, {0, 0, 0, 0, 0, 0, 0}})
          .ToHandleChecked();
  // 6. Let oneMonth be ! CreateTemporalDuration(0, sign, 0, 0, 0, 0, 0, 0, 0,
  // 0).
  Handle<JSTemporalDuration> one_month =
      CreateTemporalDuration(isolate, {0, sign, 0, {0, 0, 0, 0, 0, 0, 0}})
          .ToHandleChecked();
  // 7. Let oneWeek be ! CreateTemporalDuration(0, 0, sign, 0, 0, 0, 0, 0, 0,
  // 0).
  Handle<JSTemporalDuration> one_week =
      CreateTemporalDuration(isolate, {0, 0, sign, {0, 0, 0, 0, 0, 0, 0}})
          .ToHandleChecked();
  // 8. Set relativeTo to ? ToTemporalDate(relativeTo).
  Handle<JSTemporalPlainDate> relative_to;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, relative_to,
      ToTemporalDate(isolate, relative_to_obj, method_name),
      Nothing<DateDurationRecord>());
  // 9. Let calendar be relativeTo.[[Calendar]].
  Handle<JSReceiver> calendar(relative_to->calendar(), isolate);

  DateDurationRecord result = dur;
  // 10.  If largestUnit is "year", then
  if (largest_unit == Unit::kYear) {
    // a. Let moveResult be ? MoveRelativeDate(calendar, relativeTo, oneYear).
    MoveRelativeDateResult move_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, move_result,
        MoveRelativeDate(isolate, calendar, relative_to, one_year, method_name),
        Nothing<DateDurationRecord>());
    // b. Let newRelativeTo be moveResult.[[RelativeTo]].
    Handle<JSTemporalPlainDate> new_relative_to = move_result.relative_to;
    // c. Let oneYearDays be moveResult.[[Days]].
    double one_year_days = move_result.days;
    // d. Repeat, while abs(days) ≥ abs(oneYearDays),
    while (std::abs(result.days) >= std::abs(one_year_days)) {
      // i. Set days to days - oneYearDays.
      result.days -= one_year_days;
      // ii. Set years to years + sign.
      result.years += sign;
      // iii. Set relativeTo to newRelativeTo.
      relative_to = new_relative_to;
      // iv. Set moveResult to ? MoveRelativeDate(calendar, relativeTo,
      // oneYear).
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar, relative_to, one_year,
                           method_name),
          Nothing<DateDurationRecord>());

      // iv. Set newRelativeTo to moveResult.[[RelativeTo]].
      new_relative_to = move_result.relative_to;
      // v. Set oneYearDays to moveResult.[[Days]].
      one_year_days = move_result.days;
    }
    // e. Set moveResult to ? MoveRelativeDate(calendar, relativeTo, oneMonth).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, move_result,
        MoveRelativeDate(isolate, calendar, relative_to, one_month,
                         method_name),
        Nothing<DateDurationRecord>());
    // f. Set newRelativeTo to moveResult.[[RelativeTo]].
    new_relative_to = move_result.relative_to;
    // g. Let oneMonthDays be moveResult.[[Days]].
    double one_month_days = move_result.days;
    // h. Repeat, while abs(days) ≥ abs(oneMonthDays),
    while (std::abs(result.days) >= std::abs(one_month_days)) {
      // i. Set days to days - oneMonthDays.
      result.days -= one_month_days;
      // ii. Set months to months + sign.
      result.months += sign;
      // iii. Set relativeTo to newRelativeTo.
      relative_to = new_relative_to;
      // iv. Set moveResult to ? MoveRelativeDate(calendar, relativeTo,
      // oneMonth).
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar, relative_to, one_month,
                           method_name),
          Nothing<DateDurationRecord>());
      // iv. Set newRrelativeTo to moveResult.[[RelativeTo]].
      new_relative_to = move_result.relative_to;
      // v. Set oneMonthDays to moveResult.[[Days]].
      one_month_days = move_result.days;
    }
    // i. Let dateAdd be ? GetMethod(calendar, "dateAdd").
    Handle<Object> date_add;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, date_add,
        Object::GetMethod(isolate, calendar, factory->dateAdd_string()),
        Nothing<DateDurationRecord>());
    // j. Set newRelativeTo be ? CalendarDateAdd(calendar, relativeTo, oneYear,
    // undefined, dateAdd).
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, new_relative_to,
        CalendarDateAdd(isolate, calendar, relative_to, one_year,
                        factory->undefined_value(), date_add),
        Nothing<DateDurationRecord>());
    // k. Let dateUntil be ? GetMethod(calendar, "dateUntil").
    Handle<Object> date_until;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, date_until,
        Object::GetMethod(isolate, calendar, factory->dateUntil_string()),
        Nothing<DateDurationRecord>());
    // l. Let untilOptions be OrdinaryObjectCreate(null).
    Handle<JSObject> until_options = factory->NewJSObjectWithNullProto();
    // m. Perform ! CreateDataPropertyOrThrow(untilOptions, "largestUnit",
    // "month").
    CHECK(JSReceiver::CreateDataProperty(
              isolate, until_options, factory->largestUnit_string(),
              factory->month_string(), Just(kThrowOnError))
              .FromJust());
    // n. Let untilResult be ? CalendarDateUntil(calendar, relativeTo,
    // newRelativeTo, untilOptions, dateUntil).
    Handle<JSTemporalDuration> until_result;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, until_result,
        CalendarDateUntil(isolate, calendar, relative_to, new_relative_to,
                          until_options, date_until),
        Nothing<DateDurationRecord>());
    // o. Let oneYearMonths be untilResult.[[Months]].
    double one_year_months = Object::NumberValue(until_result->months());
    // p. Repeat, while abs(months) ≥ abs(oneYearMonths),
    while (std::abs(result.months) >= std::abs(one_year_months)) {
      // i. Set months to months - oneYearMonths.
      result.months -= one_year_months;
      // ii. Set years to years + sign.
      result.years += sign;
      // iii. Set relativeTo to newRelativeTo.
      relative_to = new_relative_to;
      // iv. Set newRelativeTo to ? CalendarDateAdd(calendar, relativeTo,
      // oneYear, undefined, dateAdd).
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, new_relative_to,
          CalendarDateAdd(isolate, calendar, relative_to, one_year,
                          factory->undefined_value(), date_add),
          Nothing<DateDurationRecord>());
      // v. Set untilOptions to OrdinaryObjectCreate(null).
      until_options = factory->NewJSObjectWithNullProto();
      // vi. Perform ! CreateDataPropertyOrThrow(untilOptions, "largestUnit",
      // "month").
      CHECK(JSReceiver::CreateDataProperty(
                isolate, until_options, factory->largestUnit_string(),
                factory->month_string(), Just(kThrowOnError))
                .FromJust());
      // vii. Set untilResult to ? CalendarDateUntil(calendar, relativeTo,
      // newRelativeTo, untilOptions, dateUntil).
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, until_result,
          CalendarDateUntil(isolate, calendar, relative_to, new_relative_to,
                            until_options, date_until),
          Nothing<DateDurationRecord>());
      // viii. Set oneYearMonths to untilResult.[[Months]].
      one_year_months = Object::NumberValue(until_result->months());
    }
    // 11. Else if largestUnit is "month", then
  } else if (largest_unit == Unit::kMonth) {
    // a. Let moveResult be ? MoveRelativeDate(calendar, relativeTo, oneMonth).
    MoveRelativeDateResult move_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, move_result,
        MoveRelativeDate(isolate, calendar, relative_to, one_month,
                         method_name),
        Nothing<DateDurationRecord>());
    // b. Let newRelativeTo be moveResult.[[RelativeTo]].
    Handle<JSTemporalPlainDate> new_relative_to = move_result.relative_to;
    // c. Let oneMonthDays be moveResult.[[Days]].
    double one_month_days = move_result.days;
    // d. Repeat, while abs(days) ≥ abs(oneMonthDays),
    while (std::abs(result.days) >= std::abs(one_month_days)) {
      // i. Set days to days - oneMonthDays.
      result.days -= one_month_days;
      // ii. Set months to months + sign.
      result.months += sign;
      // iii. Set relativeTo to newRelativeTo.
      relative_to = new_relative_to;
      // iv. Set moveResult to ? MoveRelativeDate(calendar, relativeTo,
      // oneMonth).
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar, relative_to, one_month,
                           method_name),
          Nothing<DateDurationRecord>());
      // v. Set newRelativeTo to moveResult.[[RelativeTo]].
      new_relative_to = move_result.relative_to;
      // vi. Set oneMonthDays to moveResult.[[Days]].
      one_month_days = move_result.days;
    }
    // 12. Else
  } else {
    // a. Assert: largestUnit is "week".
    DCHECK_EQ(largest_unit, Unit::kWeek);
    // b. Let moveResult be ? MoveRelativeDate(calendar, relativeTo, oneWeek).
    MoveRelativeDateResult move_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, move_result,
        MoveRelativeDate(isolate, calendar, relative_to, one_week, method_name),
        Nothing<DateDurationRecord>());
    // c. Let newRelativeTo be moveResult.[[RelativeTo]].
    Handle<JSTemporalPlainDate> new_relative_to = move_result.relative_to;
    // d. Let oneWeekDays be moveResult.[[Days]].
    double one_week_days = move_result.days;
    // e. Repeat, while abs(days) ≥ abs(oneWeekDays),
    while (std::abs(result.days) >= std::abs(one_week_days)) {
      // i. Set days to days - oneWeekDays.
      result.days -= one_week_days;
      // ii. Set weeks to weeks + sign.
      result.weeks += sign;
      // iii. Set relativeTo to newRelativeTo.
      relative_to = new_relative_to;
      // v. Set moveResult to ? MoveRelativeDate(calendar, relativeTo,
      // oneWeek).
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar, relative_to, one_week,
                           method_name),
          Nothing<DateDurationRecord>());
      // v. Set newRelativeTo to moveResult.[[RelativeTo]].
      new_relative_to = move_result.relative_to;
      // vi. Set oneWeekDays to moveResult.[[Days]].
      one_week_days = move_result.days;
    }
  }
  // 12. Return ? CreateDateDurationRecord(years, months, weeks, days).
  return DateDurationRecord::Create(isolate, result.years, result.months,
                                    result.weeks, result.days);
}

}  // namespace

// #sec-temporal.duration.compare
MaybeHandle<Smi> JSTemporalDuration::Compare(Isolate* isolate,
                                             Handle<Object> one_obj,
                                             Handle<Object> two_obj,
                                             Handle<Object> options_obj) {
  const char* method_name = "Temporal.Duration.compare";
  // 1. Set one to ? ToTemporalDuration(one).
  Handle<JSTemporalDuration> one;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, one,
      temporal::ToTemporalDuration(isolate, one_obj, method_name));
  // 2. Set two to ? ToTemporalDuration(two).
  Handle<JSTemporalDuration> two;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, two,
      temporal::ToTemporalDuration(isolate, two_obj, method_name));
  // 3. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 4. Let relativeTo be ? ToRelativeTemporalObject(options).
  Handle<Object> relative_to;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, relative_to,
      ToRelativeTemporalObject(isolate, options, method_name));
  // 5. LetCalculateOffsetShift shift1 be ? CalculateOffsetShift(relativeTo,
  // one.[[Years]], one.[[Months]], one.[[Weeks]], one.[[Days]]).
  int64_t shift1;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, shift1,
      CalculateOffsetShift(
          isolate, relative_to,
          {Object::NumberValue(one->years()),
           Object::NumberValue(one->months()),
           Object::NumberValue(one->weeks()), Object::NumberValue(one->days())},
          method_name),
      Handle<Smi>());
  // 6. Let shift2 be ? CalculateOffsetShift(relativeTo, two.[[Years]],
  // two.[[Months]], two.[[Weeks]], two.[[Days]]).
  int64_t shift2;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, shift2,
      CalculateOffsetShift(
          isolate, relative_to,
          {Object::NumberValue(two->years()),
           Object::NumberValue(two->months()),
           Object::NumberValue(two->weeks()), Object::NumberValue(two->days())},
          method_name),
      Handle<Smi>());
  // 7. If any of one.[[Years]], two.[[Years]], one.[[Months]], two.[[Months]],
  // one.[[Weeks]], or two.[[Weeks]] are not 0, then
  double days1, days2;
  if (Object::NumberValue(one->years()) != 0 ||
      Object::NumberValue(two->years()) != 0 ||
      Object::NumberValue(one->months()) != 0 ||
      Object::NumberValue(two->months()) != 0 ||
      Object::NumberValue(one->weeks()) != 0 ||
      Object::NumberValue(two->weeks()) != 0) {
    // a. Let unbalanceResult1 be ? UnbalanceDurationRelative(one.[[Years]],
    // one.[[Months]], one.[[Weeks]], one.[[Days]], "day", relativeTo).
    DateDurationRecord unbalance_result1;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, unbalance_result1,
        UnbalanceDurationRelative(isolate,
                                  {Object::NumberValue(one->years()),
                                   Object::NumberValue(one->months()),
                                   Object::NumberValue(one->weeks()),
                                   Object::NumberValue(one->days())},
                                  Unit::kDay, relative_to, method_name),
        Handle<Smi>());
    // b. Let unbalanceResult2 be ? UnbalanceDurationRelative(two.[[Years]],
    // two.[[Months]], two.[[Weeks]], two.[[Days]], "day", relativeTo).
    DateDurationRecord unbalance_result2;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, unbalance_result2,
        UnbalanceDurationRelative(isolate,
                                  {Object::NumberValue(two->years()),
                                   Object::NumberValue(two->months()),
                                   Object::NumberValue(two->weeks()),
                                   Object::NumberValue(two->days())},
                                  Unit::kDay, relative_to, method_name),
        Handle<Smi>());
    // c. Let days1 be unbalanceResult1.[[Days]].
    days1 = unbalance_result1.days;
    // d. Let days2 be unbalanceResult2.[[Days]].
    days2 = unbalance_result2.days;
    // 8. Else,
  } else {
    // a. Let days1 be one.[[Days]].
    days1 = Object::NumberValue(one->days());
    // b. Let days2 be two.[[Days]].
    days2 = Object::NumberValue(two->days());
  }
  // 9. Let ns1 be ! TotalDurationNanoseconds(days1, one.[[Hours]],
  // one.[[Minutes]], one.[[Seconds]], one.[[Milliseconds]],
  // one.[[Microseconds]], one.[[Nanoseconds]], shift1).
  DirectHandle<BigInt> ns1 = TotalDurationNanoseconds(
      isolate,
      {days1, Object::NumberValue(one->hours()),
       Object::NumberValue(one->minutes()), Object::NumberValue(one->seconds()),
       Object::NumberValue(one->milliseconds()),
       Object::NumberValue(one->microseconds()),
       Object::NumberValue(one->nanoseconds())},
      shift1);
  // 10. Let ns2 be ! TotalDurationNanoseconds(days2, two.[[Hours]],
  // two.[[Minutes]], two.[[Seconds]], two.[[Milliseconds]],
  // two.[[Microseconds]], two.[[Nanoseconds]], shift2).
  DirectHandle<BigInt> ns2 = TotalDurationNanoseconds(
      isolate,
      {days2, Object::NumberValue(two->hours()),
       Object::NumberValue(two->minutes()), Object::NumberValue(two->seconds()),
       Object::NumberValue(two->milliseconds()),
       Object::NumberValue(two->microseconds()),
       Object::NumberValue(two->nanoseconds())},
      shift2);
  switch (BigInt::CompareToBigInt(ns1, ns2)) {
    // 11. If ns1 > ns2, return 1𝔽.
    case ComparisonResult::kGreaterThan:
      return handle(Smi::FromInt(1), isolate);
    // 12. If ns1 < ns2, return -1𝔽.
    case ComparisonResult::kLessThan:
      return handle(Smi::FromInt(-1), isolate);
    // 13. Return +0𝔽.
    default:
      return handle(Smi::FromInt(0), isolate);
  }
}

// #sec-temporal.duration.from
MaybeHandle<JSTemporalDuration> JSTemporalDuration::From(Isolate* isolate,
                                                         Handle<Object> item) {
  //  1. If Type(item) is Object and item has an [[InitializedTemporalDuration]]
  //  internal slot, then
  if (IsJSTemporalDuration(*item)) {
    // a. Return ? CreateTemporalDuration(item.[[Years]], item.[[Months]],
    // item.[[Weeks]], item.[[Days]], item.[[Hours]], item.[[Minutes]],
    // item.[[Seconds]], item.[[Milliseconds]], item.[[Microseconds]],
    // item.[[Nanoseconds]]).
    auto duration = Cast<JSTemporalDuration>(item);
    return CreateTemporalDuration(
        isolate, {Object::NumberValue(duration->years()),
                  Object::NumberValue(duration->months()),
                  Object::NumberValue(duration->weeks()),
                  {Object::NumberValue(duration->days()),
                   Object::NumberValue(duration->hours()),
                   Object::NumberValue(duration->minutes()),
                   Object::NumberValue(duration->seconds()),
                   Object::NumberValue(duration->milliseconds()),
                   Object::NumberValue(duration->microseconds()),
                   Object::NumberValue(duration->nanoseconds())}});
  }
  // 2. Return ? ToTemporalDuration(item).
  return temporal::ToTemporalDuration(isolate, item, "Temporal.Duration.from");
}

namespace {
// #sec-temporal-maximumtemporaldurationroundingincrement
struct Maximum {
  bool defined;
  double value;
};
Maximum MaximumTemporalDurationRoundingIncrement(Unit unit);
// #sec-temporal-totemporalroundingincrement
Maybe<double> ToTemporalRoundingIncrement(Isolate* isolate,
                                          Handle<JSReceiver> normalized_options,
                                          double dividend,
                                          bool dividend_is_defined,
                                          bool inclusive);

// #sec-temporal-moverelativezoneddatetime
MaybeHandle<JSTemporalZonedDateTime> MoveRelativeZonedDateTime(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    const DateDurationRecord& duration, const char* method_name);

// #sec-temporal-roundduration
Maybe<DurationRecordWithRemainder> RoundDuration(Isolate* isolate,
                                                 const DurationRecord& duration,
                                                 double increment, Unit unit,
                                                 RoundingMode rounding_mode,
                                                 Handle<Object> relative_to,
                                                 const char* method_name);
}  // namespace

// #sec-temporal.duration.prototype.round
MaybeHandle<JSTemporalDuration> JSTemporalDuration::Round(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration,
    Handle<Object> round_to_obj) {
  const char* method_name = "Temporal.Duration.prototype.round";
  Factory* factory = isolate->factory();
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
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
    // c. Perform ! CreateDataPropertyOrThrow(roundTo, "_smallestUnit_",
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
  // 6. Let smallestUnitPresent be true.
  bool smallest_unit_present = true;
  // 7. Let largestUnitPresent be true.
  bool largest_unit_present = true;
  // 8. Let smallestUnit be ? GetTemporalUnit(roundTo, "smallestUnit", datetime,
  // undefined).
  Unit smallest_unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, smallest_unit,
      GetTemporalUnit(isolate, round_to, "smallestUnit", UnitGroup::kDateTime,
                      Unit::kNotPresent, false, method_name),
      Handle<JSTemporalDuration>());
  // 9. If smallestUnit is undefined, then
  if (smallest_unit == Unit::kNotPresent) {
    // a. Set smallestUnitPresent to false.
    smallest_unit_present = false;
    // b. Set smallestUnit to "nanosecond".
    smallest_unit = Unit::kNanosecond;
  }
  // 10. Let defaultLargestUnit be !
  // DefaultTemporalLargestUnit(duration.[[Years]], duration.[[Months]],
  // duration.[[Weeks]], duration.[[Days]], duration.[[Hours]],
  // duration.[[Minutes]], duration.[[Seconds]], duration.[[Milliseconds]],
  // duration.[[Microseconds]]).
  Unit default_largest_unit = DefaultTemporalLargestUnit(
      {Object::NumberValue(duration->years()),
       Object::NumberValue(duration->months()),
       Object::NumberValue(duration->weeks()),
       {Object::NumberValue(duration->days()),
        Object::NumberValue(duration->hours()),
        Object::NumberValue(duration->minutes()),
        Object::NumberValue(duration->seconds()),
        Object::NumberValue(duration->milliseconds()),
        Object::NumberValue(duration->microseconds()),
        Object::NumberValue(duration->nanoseconds())}});

  // 11. Set defaultLargestUnit to !
  // LargerOfTwoTemporalUnits(defaultLargestUnit, smallestUnit).
  default_largest_unit =
      LargerOfTwoTemporalUnits(default_largest_unit, smallest_unit);
  // 12. Let largestUnit be ? GetTemporalUnit(roundTo, "largestUnit", datetime,
  // undefined, « "auto" »).
  Unit largest_unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, largest_unit,
      GetTemporalUnit(isolate, round_to, "largestUnit", UnitGroup::kDateTime,
                      Unit::kNotPresent, false, method_name, Unit::kAuto),
      Handle<JSTemporalDuration>());
  // 13. If largestUnit is undefined, then
  if (largest_unit == Unit::kNotPresent) {
    // a. Set largestUnitPresent to false.
    largest_unit_present = false;
    // b. Set largestUnit to defaultLargestUnit.
    largest_unit = default_largest_unit;
    // 14. Else if largestUnit is "auto", then
  } else if (largest_unit == Unit::kAuto) {
    // a. Set largestUnit to defaultLargestUnit.
    largest_unit = default_largest_unit;
  }
  // 15. If smallestUnitPresent is false and largestUnitPresent is false, then
  if (!smallest_unit_present && !largest_unit_present) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 16. If LargerOfTwoTemporalUnits(largestUnit, smallestUnit) is not
  // largestUnit, throw a RangeError exception.
  if (LargerOfTwoTemporalUnits(largest_unit, smallest_unit) != largest_unit) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 17. Let roundingMode be ? ToTemporalRoundingMode(roundTo, "halfExpand").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, round_to, RoundingMode::kHalfExpand,
                             method_name),
      Handle<JSTemporalDuration>());
  // 18. Let maximum be !
  // MaximumTemporalDurationRoundingIncrement(smallestUnit).
  Maximum maximum = MaximumTemporalDurationRoundingIncrement(smallest_unit);

  // 19. Let roundingIncrement be ? ToTemporalRoundingIncrement(roundTo,
  // maximum, false).
  double rounding_increment;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_increment,
      ToTemporalRoundingIncrement(isolate, round_to, maximum.value,
                                  maximum.defined, false),
      Handle<JSTemporalDuration>());
  // 20. Let relativeTo be ? ToRelativeTemporalObject(roundTo).
  Handle<Object> relative_to;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, relative_to,
      ToRelativeTemporalObject(isolate, round_to, method_name));
  // 21. Let unbalanceResult be ? UnbalanceDurationRelative(duration.[[Years]],
  // duration.[[Months]], duration.[[Weeks]], duration.[[Days]], largestUnit,
  // relativeTo).
  DateDurationRecord unbalance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, unbalance_result,
      UnbalanceDurationRelative(isolate,
                                {Object::NumberValue(duration->years()),
                                 Object::NumberValue(duration-
"""


```