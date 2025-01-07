Response:
The user wants me to analyze a C++ source code file (`v8/src/objects/js-temporal-objects.cc`) from the V8 JavaScript engine. I need to describe its functionality, check if it were a Torque file (by looking at the extension), explain its relation to JavaScript with examples, provide logic reasoning with input/output examples, illustrate common programming errors, and summarize its functionality as part 9 of 25.

Here's a plan:
1. **File Extension Check:** Verify if the provided filename ends with `.tq`.
2. **Functionality Description:** Analyze the functions in the code snippet and describe their purpose. Focus on functions related to date and time manipulation like `IsValidTime`, `IsValidISODate`, `CompareISODate`, `BalanceTime`, `DifferenceTime`, `AddTime`, `TotalDurationNanoseconds`, `ISOMonthDayFromFields`, `BalanceISOYearMonth`, `CompareISODateTime`.
3. **JavaScript Relationship:** Identify how these C++ functions relate to JavaScript's `Temporal` API. Provide JavaScript examples that might internally use these functions.
4. **Logic Reasoning:** Select a function with clear logic (e.g., `IsValidTime`, `CompareISODate`) and demonstrate its behavior with example inputs and outputs.
5. **Common Programming Errors:** Based on the function functionalities, suggest common mistakes a programmer might make when working with dates and times in JavaScript (specifically related to the `Temporal` API if possible).
6. **Summary:** Provide a concise summary of the file's role within V8, considering it's the 9th of 25 parts. It likely handles core logic for the `Temporal` API.
这是一个V8源代码文件，其主要功能是实现与 JavaScript `Temporal` API 相关的底层逻辑。

**文件类型判断:**

`v8/src/objects/js-temporal-objects.cc` 的文件扩展名是 `.cc`，这表明它是一个 **C++** 源代码文件，而不是 Torque 源代码文件。如果它是 Torque 源代码，它的扩展名将会是 `.tq`。

**功能列举:**

该文件包含了一系列用于处理日期、时间和持续时间的函数。主要功能可以归纳为：

* **验证日期和时间:**
    * `IsValidTime`: 检查给定的时间记录（小时、分钟、秒、毫秒、微秒、纳秒）是否有效。
    * `IsValidISODate`: 检查给定的 ISO 日期记录（年、月、日）是否有效。
* **比较日期和时间:**
    * `CompareISODate`: 比较两个 ISO 日期记录。
    * `CompareISODateTime`: 比较两个 ISO 日期时间记录。
    * `CompareTemporalTime`: (虽然代码中未完整给出，但函数名暗示了比较时间的功能)
* **调整和平衡日期和时间:**
    * `BalanceISOYearMonth`: 调整年份和月份，确保月份在 1-12 之间。
    * `BalanceTime`: 平衡时间记录，将纳秒、微秒、毫秒、秒、分钟的溢出部分向上进位到更高级别的单位，并将小时溢出部分转换为天数。
* **计算日期和时间的差值:**
    * `DifferenceTime`: 计算两个时间记录之间的差值，返回一个时间差记录。
* **添加日期和时间:**
    * `AddTime`: 将一个时间差添加到给定的时间记录。
* **计算持续时间的总纳秒数:**
    * `TotalDurationNanoseconds`: 将一个时间持续时间记录转换为总的纳秒数。
* **从字段创建 ISO 月份和日期:**
    * `ISOMonthDayFromFields`: 从包含日期字段的对象中解析并创建 ISO 月份和日期。
* **调节 ISO 日期:**
    * `RegulateISODate`: (代码片段中未完整给出，但函数名暗示了根据溢出策略调节日期的功能)
* **解析 ISO 月份:**
    * `ResolveISOMonth`: (代码片段中未完整给出，但函数名暗示了解析 ISO 月份的功能)
* **`Temporal.Duration` 构造函数:** 实现了 `Temporal.Duration` 对象的构造过程。
* **与相对时间对象的操作:**
    * `ToRelativeTemporalObject`: (代码片段中未完整给出，但函数名暗示了转换为相对时间对象的功能)
    * `DefaultTemporalLargestUnit`: (代码片段中未完整给出，但函数名暗示了获取默认最大时间单位的功能)
    * `RoundTemporalInstant`: 对时间戳进行舍入操作。
    * `DifferenceInstant`: 计算两个时间戳之间的差值。
    * `DifferenceZonedDateTime`: 计算两个带时区日期时间之间的差值。
    * `AddDuration`: 将一个持续时间添加到另一个持续时间。
    * `AdjustRoundedDurationDays`: 调整舍入后的持续时间天数。
    * `CalculateOffsetShift`: 计算时区偏移量的变化。
    * `MoveRelativeDate`: 移动相对日期。
    * `UnbalanceDurationRelative`: 相对于某个日期解构持续时间。

**与 JavaScript 的关系 (以 `Temporal` API 为例):**

这些 C++ 函数为 JavaScript 的 `Temporal` API 提供了底层的实现。`Temporal` API 旨在为 JavaScript 提供现代化的日期和时间处理能力。

例如，`IsValidTime` 函数可能在 JavaScript 中创建 `Temporal.PlainTime` 实例时进行验证：

```javascript
// 这段 JavaScript 代码在 V8 引擎内部可能会调用 IsValidTime 类似的 C++ 函数
try {
  const time = new Temporal.PlainTime(25, 30, 15); // 小时超出范围
} catch (e) {
  console.error(e); // 输出 RangeError
}

try {
  const time = new Temporal.PlainTime(10, 70, 15); // 分钟超出范围
} catch (e) {
  console.error(e); // 输出 RangeError
}

const validTime = new Temporal.PlainTime(10, 30, 15);
```

`CompareISODate` 函数可能在 `Temporal.PlainDate` 实例的比较操作中使用：

```javascript
const date1 = new Temporal.PlainDate(2023, 10, 26);
const date2 = new Temporal.PlainDate(2023, 11, 15);

if (date1 < date2) { // JavaScript 引擎内部可能会调用 CompareISODate 类似的 C++ 函数
  console.log("date1 在 date2 之前");
}
```

`BalanceTime` 函数在进行时间单位的加减运算时非常重要，确保结果的各个时间单位都在有效范围内：

```javascript
const time = new Temporal.PlainTime(10, 30, 50, 500, 500, 500);
const duration = new Temporal.Duration(0, 0, 0, 0, 0, 0, 10, 600, 600, 600);
const newTime = time.add(duration); // JavaScript 引擎内部可能会调用 BalanceTime 类似的 C++ 函数
console.log(newTime.toString()); // 输出例如 10:31:01.101601
```

**代码逻辑推理 (以 `IsValidTime` 为例):**

**假设输入:**

```c++
Isolate* isolate = nullptr; // 假设已获取 Isolate 实例
TimeRecord valid_time = {10, 30, 15, 500, 500, 500};
TimeRecord invalid_time_hour = {25, 30, 15, 500, 500, 500};
TimeRecord invalid_time_minute = {10, 70, 15, 500, 500, 500};
```

**输出:**

```
IsValidTime(isolate, valid_time) -> true
IsValidTime(isolate, invalid_time_hour) -> false
IsValidTime(isolate, invalid_time_minute) -> false
```

**代码逻辑推理 (以 `CompareISODate` 为例):**

**假设输入:**

```c++
DateRecord date1_earlier = {2023, 10, 26};
DateRecord date2_later = {2023, 11, 15};
DateRecord date3_same = {2023, 10, 26};
```

**输出:**

```
CompareISODate(date1_earlier, date2_later) -> -1
CompareISODate(date2_later, date1_earlier) -> 1
CompareISODate(date1_earlier, date3_same) -> 0
```

**用户常见的编程错误 (与 `Temporal` API 相关):**

1. **日期或时间组件超出范围:** 尝试创建超出有效范围的 `Temporal.PlainDate` 或 `Temporal.PlainTime` 实例。

   ```javascript
   // 错误：月份超出范围
   // const invalidDate = new Temporal.PlainDate(2023, 13, 15);
   // 错误：小时超出范围
   // const invalidTime = new Temporal.PlainTime(24, 30, 0);
   ```

2. **假设月份的天数不变:**  在进行日期计算时，没有考虑到不同月份天数不同以及闰年的影响。`Temporal` API 提供了正确处理这些情况的方法。

   ```javascript
   // 错误的做法：直接增加天数，没有考虑月份变化
   // let date = new Temporal.PlainDate(2023, 1, 30);
   // date = date.add({ days: 2 }); // 期望是 2 月 1 日，但简单加 2 可能会出错

   // 正确的做法：使用 Temporal API 的方法
   let date = new Temporal.PlainDate(2023, 1, 30);
   date = date.add({ days: 2 });
   console.log(date.toString()); // 输出 2023-02-01
   ```

3. **时区处理不当:**  在需要考虑时区的场景下，错误地使用了 `Temporal.PlainDate` 或 `Temporal.PlainTime` 而不是 `Temporal.ZonedDateTime`。

   ```javascript
   // 错误的做法：没有考虑时区
   // const meetingTime = new Temporal.PlainDateTime(2023, 11, 16, 10, 0, 0);
   // 不同时区的人看到的时间会不同

   // 正确的做法：使用带时区的日期时间
   const timeZone = Temporal.TimeZone.from('America/New_York');
   const meetingTime = new Temporal.ZonedDateTime(Temporal.Instant.fromEpochSeconds(1700142000), timeZone);
   console.log(meetingTime.toString());
   ```

**功能归纳 (作为第 9 部分):**

作为 V8 引擎中处理 `Temporal` API 的第 9 部分，这个文件主要负责实现 `Temporal` API 中**基础的日期和时间操作**。它提供了用于验证、比较、调整和计算日期和时间的核心 C++ 函数。这些底层函数为 JavaScript 中 `Temporal` 对象的创建和操作提供了坚实的基础。考虑到这是一个较大的功能模块的一部分，可以推测之前的模块可能处理了 `Temporal` API 的类型定义、属性访问等，而后续的模块可能会涉及更复杂的时区处理、格式化、解析等功能。 该文件专注于提供构建更高级日期时间功能的构建块。

Prompt: 
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共25部分，请归纳一下它的功能

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
      // ii
"""


```