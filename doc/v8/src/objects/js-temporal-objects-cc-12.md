Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/objects/js-temporal-objects.cc`. This is part 13 of 25, suggesting it's a section within a larger file. I need to analyze the code and provide:

1. **Functionality:** A summary of what the code does.
2. **Torque Source:** Check if the filename ends with `.tq`.
3. **JavaScript Relation:** If the code relates to JavaScript features, provide a JavaScript example.
4. **Code Logic Inference:** Identify any logic within the code and give example inputs and outputs.
5. **Common Programming Errors:**  Point out potential user errors related to the functionality.
6. **Part Summary:**  A concise overview of this specific section's role within the larger file.

Let's break down the code snippet:

- It seems to be implementing rounding logic for `Temporal.Duration` objects.
- There's a `RoundDuration` function that takes a `DurationRecord`, increment, unit, and rounding mode.
- The code handles different time units (year, month, week, day, hour, minute, second, millisecond, microsecond, nanosecond) separately.
- It uses functions like `CalendarDateAdd`, `CalendarDateUntil`, `MoveRelativeDate`, `DaysUntil`, and `RoundNumberToIncrement`. These suggest interactions with calendar calculations and date manipulation.
- The `ToString` method for `JSTemporalDuration` calls `RoundDuration`.
- There's also code related to `JSTemporalCalendar` constructor and helper functions like `ToISODayOfYear`, `ToISODayOfWeek`, `RegulateISODate`, `RegulateISOYearMonth`, `ResolveISOMonth`, and `ISODateFromFields`.

**High-level plan:**

1. Summarize the main functionality related to rounding durations and calendar operations.
2. Confirm that the file isn't a Torque file.
3. Provide JavaScript examples demonstrating `Temporal.Duration.round()` and related calendar operations.
4. Create a simple example of rounding a duration to a specific unit.
5. Explain common errors like providing invalid rounding units or increments.
6. Summarize this part as dealing with the core logic for rounding `Temporal.Duration` values and some basic `Temporal.Calendar` functionality.
好的，让我们来分析一下这段 v8 源代码 `v8/src/objects/js-temporal-objects.cc` 的功能。

**功能归纳:**

这段代码主要实现了 `Temporal.Duration` 对象的舍入 (rounding) 功能，以及一部分 `Temporal.Calendar` 相关的辅助功能。更具体地说：

1. **`RoundDuration` 函数:** 这是核心功能，它接收一个 `DurationRecord`（表示一个时间段），一个增量值 `increment`，一个时间单位 `unit`，一个舍入模式 `rounding_mode`，以及一个可选的相对日期 `relative_to`。它的作用是根据指定的单位、增量和舍入模式，对给定的时间段进行舍入。它能处理各种时间单位，包括年、月、周、日、小时、分钟、秒、毫秒、微秒和纳秒。

2. **`JSTemporalDuration::ToString` 函数:** 这个函数负责将 `Temporal.Duration` 对象转换为字符串表示形式。它内部调用了 `RoundDuration` 函数，并使用 `ToSecondsStringPrecision` 来确定精度。

3. **`JSTemporalCalendar::Constructor` 函数:** 这是 `Temporal.Calendar` 对象的构造函数，它负责创建 `Temporal.Calendar` 实例并验证传入的日历标识符是否是内置的。

4. **辅助函数:**  代码中还包含了一些辅助函数，用于处理日期和时间计算，例如：
    - `ToISODayOfYear`: 计算给定日期是一年中的第几天。
    - `ToISODayOfWeek`: 计算给定日期是星期几。
    - `RegulateISODate`: 根据指定的溢出行为（`constrain` 或 `reject`）调整 ISO 日期。
    - `RegulateISOYearMonth`: 根据指定的溢出行为调整 ISO 年月。
    - `ResolveISOMonth`: 解析包含月份信息的字段，可以处理数字月份或月份代码（如 "M01"）。

**关于文件类型:**

`v8/src/objects/js-temporal-objects.cc` 以 `.cc` 结尾，因此它是一个 **v8 C++ 源代码文件**，而不是 v8 Torque 源代码文件。

**与 JavaScript 的关系及示例:**

这段代码与 JavaScript 的 `Temporal` API 中的 `Temporal.Duration` 和 `Temporal.Calendar` 对象的功能直接相关。

**JavaScript 示例 (舍入 Duration):**

```javascript
const duration = new Temporal.Duration(1, 6, 2, 10, 5, 30, 45, 500, 600, 700);

// 将 duration 舍入到最接近的月
const roundedToMonth = duration.round({ smallestUnit: 'month' });
console.log(roundedToMonth.toString()); // 可能输出 PT1Y7M

// 将 duration 舍入到最接近的周，以 2 周为增量，向上舍入
const roundedToWeek = duration.round({ smallestUnit: 'week', roundingIncrement: 2, roundingMode: 'ceil' });
console.log(roundedToWeek.toString()); // 可能输出 PT2W

// 需要一个相对日期才能进行某些基于日历的舍入
const now = Temporal.Now.plainDateISO();
const roundedToYear = duration.round({ smallestUnit: 'year', relativeTo: now });
console.log(roundedToYear.toString()); // 可能输出 PT2Y
```

**代码逻辑推理 (以 `RoundDuration` 中 unit 为 "year" 的情况为例):**

**假设输入:**

- `duration`:  `{ years: 1, months: 6, weeks: 0, days: 10, hours: 0, minutes: 0, seconds: 0, milliseconds: 0, microseconds: 0, nanoseconds: 0 }`
- `increment`: `1`
- `unit`: `"year"`
- `rounding_mode`: `"nearest"` (假设)
- `relative_to`: 一个 `Temporal.PlainDate` 对象，例如 `2023-10-26`

**推理过程 (部分):**

1. 代码首先创建一个包含年和月的 `Temporal.Duration` 对象 `yearsMonths`。
2. 它使用 `CalendarDateAdd` 将 `yearsMonths` 添加到 `relative_to`，得到 `yearsMonthsLater`。
3. 类似地，它创建包含年、月和周的 `Temporal.Duration` 对象 `yearsMonthsWeeks`，并添加到 `relative_to` 得到 `yearsMonthsWeeksLater`。
4. `DaysUntil` 计算 `yearsMonthsLater` 和 `yearsMonthsWeeksLater` 之间的天数差 `months_weeks_in_days`。
5. 将 `relative_to` 更新为 `yearsMonthsLater`。
6. 将 `months_weeks_in_days` 加到 `result.record.time_duration.days` 上。
7. 创建一个包含这些天数的 `Temporal.Duration` 对象 `days_duration`。
8. 使用 `CalendarDateAdd` 将 `days_duration` 添加到 `relative_to`，得到 `days_later`。
9. 创建一个选项对象 `until_options`，指定 `largestUnit` 为 "year"。
10. 使用 `CalendarDateUntil` 计算从 `relative_to` 到 `days_later` 经过的年数 `yearsPassed`。
11. 将 `yearsPassed` 加到 `result.record.years` 上。
12. ...（后续步骤会计算剩余的天数，并根据舍入模式调整年份）

**假设输出:**

最终的 `result` 可能会是：

- `result.record`: `{ years: 2, months: 0, weeks: 0, days: 0, hours: 0, minutes: 0, seconds: 0, milliseconds: 0, microseconds: 0, nanoseconds: 0 }` (取决于具体的日期和舍入模式)
- `result.remainder`: 一个表示剩余部分的数值。

**用户常见的编程错误:**

1. **在需要 `relativeTo` 时未提供:** 对于像 "year" 或 "month" 这样的较大单位进行舍入时，通常需要提供一个 `relativeTo` 日期，因为这些单位的长度是可变的。如果未提供，JavaScript 代码会抛出错误。

   ```javascript
   const duration = new Temporal.Duration(1, 0, 0, 0);
   // 错误: Rounding to 'year' requires a relativeTo
   // duration.round({ smallestUnit: 'year' });

   const now = Temporal.Now.plainDateISO();
   const rounded = duration.round({ smallestUnit: 'year', relativeTo: now });
   ```

2. **提供无效的 `roundingIncrement`:**  `roundingIncrement` 必须是正数。

   ```javascript
   const duration = new Temporal.Duration(0, 0, 1, 0);
   // 错误: roundingIncrement 必须是正数
   // duration.round({ smallestUnit: 'week', roundingIncrement: 0 });
   ```

3. **提供无效的 `smallestUnit`:**  `smallestUnit` 必须是 `Temporal.Duration` 支持的有效单位字符串。

   ```javascript
   const duration = new Temporal.Duration(1, 0, 0, 0);
   // 错误: 'invalid-unit' 不是有效的 smallestUnit
   // duration.round({ smallestUnit: 'invalid-unit' });
   ```

**第 13 部分的功能归纳:**

作为 25 个部分中的第 13 部分，这段代码主要集中在 `Temporal.Duration` 对象的**核心舍入逻辑**的实现上。它处理了根据不同时间单位、增量和舍入模式调整时间段的过程，并且初步涉及了 `Temporal.Calendar` 对象的基本构造和一些日期计算辅助功能。可以认为这是 `Temporal.Duration` 对象关键功能的实现部分。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第13部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
(isolate, calendar, relative_to, years_months_weeks,
                          isolate->factory()->undefined_value(), date_add),
          Nothing<DurationRecordWithRemainder>());

      // f. Let monthsWeeksInDays be DaysUntil(yearsLater,
      // yearsMonthsWeeksLater).
      double months_weeks_in_days = DaysUntil(
          isolate, years_later, years_months_weeks_later, method_name);

      // g. Set relativeTo to yearsLater.
      relative_to = years_later;

      // h. Let days be days + monthsWeeksInDays.
      result.record.time_duration.days += months_weeks_in_days;

      // i. Let daysDuration be ? CreateTemporalDuration(0, 0, 0, days, 0, 0, 0,
      // 0, 0, 0).
      Handle<JSTemporalDuration> days_duration;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, days_duration,
          CreateTemporalDuration(
              isolate,
              {0, 0, 0, {result.record.time_duration.days, 0, 0, 0, 0, 0, 0}}),
          Nothing<DurationRecordWithRemainder>());

      // j. Let daysLater be ? CalendarDateAdd(calendar, relativeTo,
      // daysDuration, undefined, dateAdd).
      Handle<JSTemporalPlainDate> days_later;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, days_later,
          CalendarDateAdd(isolate, calendar, relative_to, days_duration,
                          isolate->factory()->undefined_value(), date_add),
          Nothing<DurationRecordWithRemainder>());

      // k. Let untilOptions be OrdinaryObjectCreate(null).
      Handle<JSObject> until_options = factory->NewJSObjectWithNullProto();

      // l. Perform ! CreateDataPropertyOrThrow(untilOptions, "largestUnit",
      // "year").
      CHECK(JSReceiver::CreateDataProperty(
                isolate, until_options, factory->largestUnit_string(),
                factory->year_string(), Just(kThrowOnError))
                .FromJust());

      // m. Let timePassed be ? CalendarDateUntil(calendar, relativeTo,
      // daysLater, untilOptions).
      Handle<JSTemporalDuration> time_passed;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, time_passed,
          CalendarDateUntil(isolate, calendar, relative_to, days_later,
                            until_options),
          Nothing<DurationRecordWithRemainder>());

      // n. Let yearsPassed be timePassed.[[Years]].
      double years_passed = Object::NumberValue(time_passed->years());

      // o. Set years to years + yearsPassed.
      result.record.years += years_passed;

      // p. Let oldRelativeTo be relativeTo.
      Handle<Object> old_relative_to = relative_to;

      // q. Let yearsDuration be ? CreateTemporalDuration(yearsPassed, 0, 0, 0,
      // 0, 0, 0, 0, 0, 0).
      years_duration = CreateTemporalDuration(
                           isolate, {years_passed, 0, 0, {0, 0, 0, 0, 0, 0, 0}})
                           .ToHandleChecked();

      // r. Set relativeTo to ? CalendarDateAdd(calendar, relativeTo,
      // yearsDuration, undefined, dateAdd).
      Handle<JSTemporalPlainDate> years_added;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, years_added,
          CalendarDateAdd(isolate, calendar, relative_to, years_duration,
                          isolate->factory()->undefined_value(), date_add),
          Nothing<DurationRecordWithRemainder>());
      relative_to = years_added;

      // s. Let daysPassed be DaysUntil(oldRelativeTo, relativeTo).
      DCHECK(IsJSTemporalPlainDate(*old_relative_to));
      DCHECK(IsJSTemporalPlainDate(*relative_to));
      double days_passed =
          DaysUntil(isolate, Cast<JSTemporalPlainDate>(old_relative_to),
                    Cast<JSTemporalPlainDate>(relative_to), method_name);

      // t. Set days to days - daysPassed.
      result.record.time_duration.days -= days_passed;

      // u. If days < 0, let sign be -1; else, let sign be 1.
      double sign = result.record.time_duration.days < 0 ? -1 : 1;

      // v. Let oneYear be ! CreateTemporalDuration(sign, 0, 0, 0, 0, 0, 0, 0,
      // 0, 0).
      Handle<JSTemporalDuration> one_year =
          CreateTemporalDuration(isolate, {sign, 0, 0, {0, 0, 0, 0, 0, 0, 0}})
              .ToHandleChecked();

      // w. Let moveResult be ? MoveRelativeDate(calendar, relativeTo, oneYear).
      MoveRelativeDateResult move_result;
      DCHECK(IsJSTemporalPlainDate(*relative_to));
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar,
                           Cast<JSTemporalPlainDate>(relative_to), one_year,
                           method_name),
          Nothing<DurationRecordWithRemainder>());

      // x. Let oneYearDays be moveResult.[[Days]].
      double one_year_days = move_result.days;
      // y. Let fractionalYears be years + days / abs(oneYearDays).
      double fractional_years =
          result.record.years +
          result.record.time_duration.days / std::abs(one_year_days);
      // z. Set years to RoundNumberToIncrement(fractionalYears, increment,
      // roundingMode).
      result.record.years = RoundNumberToIncrement(isolate, fractional_years,
                                                   increment, rounding_mode);
      // aa. Set remainder to fractionalYears - years.
      result.remainder = fractional_years - result.record.years;
      // ab. Set months, weeks, and days to 0.
      result.record.months = result.record.weeks =
          result.record.time_duration.days = 0;
    } break;
    // 10. Else if unit is "month", then
    case Unit::kMonth: {
      // a. Let yearsMonths be ! CreateTemporalDuration(years, months, 0, 0, 0,
      // 0, 0, 0, 0, 0).
      Handle<JSTemporalDuration> years_months =
          CreateTemporalDuration(
              isolate,
              {duration.years, duration.months, 0, {0, 0, 0, 0, 0, 0, 0}})
              .ToHandleChecked();

      // b. Let dateAdd be ? GetMethod(calendar, "dateAdd").
      Handle<Object> date_add;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, date_add,
          Object::GetMethod(isolate, calendar, factory->dateAdd_string()),
          Nothing<DurationRecordWithRemainder>());

      // c. Let yearsMonthsLater be ? CalendarDateAdd(calendar, relativeTo,
      // yearsMonths, undefined, dateAdd).
      Handle<JSTemporalPlainDate> years_months_later;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, years_months_later,
          CalendarDateAdd(isolate, calendar, relative_to, years_months,
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
          CalendarDateAdd(isolate, calendar, relative_to, years_months_weeks,
                          isolate->factory()->undefined_value(), date_add),
          Nothing<DurationRecordWithRemainder>());

      // f. Let weeksInDays be DaysUntil(yearsMonthsLater,
      // yearsMonthsWeeksLater).
      double weeks_in_days = DaysUntil(isolate, years_months_later,
                                       years_months_weeks_later, method_name);

      // g. Set relativeTo to yearsMonthsLater.
      relative_to = years_months_later;

      // h. Let days be days + weeksInDays.
      result.record.time_duration.days += weeks_in_days;

      // i. If days < 0, let sign be -1; else, let sign be 1.
      double sign = result.record.time_duration.days < 0 ? -1 : 1;

      // j. Let oneMonth be ! CreateTemporalDuration(0, sign, 0, 0, 0, 0, 0, 0,
      // 0, 0).
      Handle<JSTemporalDuration> one_month =
          CreateTemporalDuration(isolate, {0, sign, 0, {0, 0, 0, 0, 0, 0, 0}})
              .ToHandleChecked();

      // k. Let moveResult be ? MoveRelativeDate(calendar, relativeTo,
      // oneMonth).
      MoveRelativeDateResult move_result;
      DCHECK(IsJSTemporalPlainDate(*relative_to));
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar,
                           Cast<JSTemporalPlainDate>(relative_to), one_month,
                           method_name),
          Nothing<DurationRecordWithRemainder>());

      // l. Set relativeTo to moveResult.[[RelativeTo]].
      relative_to = move_result.relative_to;

      // m. Let oneMonthDays be moveResult.[[Days]].
      double one_month_days = move_result.days;

      // n. Repeat, while abs(days) ≥ abs(oneMonthDays),
      while (std::abs(result.record.time_duration.days) >=
             std::abs(one_month_days)) {
        // i. Set months to months + sign.
        result.record.months += sign;
        // ii. Set days to days - oneMonthDays.
        result.record.time_duration.days -= one_month_days;
        // iii. Set moveResult to ? MoveRelativeDate(calendar, relativeTo,
        // oneMonth).
        DCHECK(IsJSTemporalPlainDate(*relative_to));
        MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, move_result,
            MoveRelativeDate(isolate, calendar,
                             Cast<JSTemporalPlainDate>(relative_to), one_month,
                             method_name),
            Nothing<DurationRecordWithRemainder>());
        // iv. Set relativeTo to moveResult.[[RelativeTo]].
        relative_to = move_result.relative_to;
        // v. Set oneMonthDays to moveResult.[[Days]].
        one_month_days = move_result.days;
      }
      // o. Let fractionalMonths be months + days / abs(oneMonthDays).
      double fractional_months =
          result.record.months +
          result.record.time_duration.days / std::abs(one_month_days);
      // p. Set months to RoundNumberToIncrement(fractionalMonths, increment,
      // roundingMode).
      result.record.months = RoundNumberToIncrement(isolate, fractional_months,
                                                    increment, rounding_mode);
      // q. Set remainder to fractionalMonths - months.
      result.remainder = fractional_months - result.record.months;
      // r. Set weeks and days to 0.
      result.record.weeks = result.record.time_duration.days = 0;
    } break;
    // 11. Else if unit is "week", then
    case Unit::kWeek: {
      // a. If days < 0, let sign be -1; else, let sign be 1.
      double sign = result.record.time_duration.days < 0 ? -1 : 1;
      // b. Let oneWeek be ! CreateTemporalDuration(0, 0, sign, 0, 0, 0, 0, 0,
      // 0, 0).
      Handle<JSTemporalDuration> one_week =
          CreateTemporalDuration(isolate, {0, 0, sign, {0, 0, 0, 0, 0, 0, 0}})
              .ToHandleChecked();

      // c. Let moveResult be ? MoveRelativeDate(calendar, relativeTo, oneWeek).
      MoveRelativeDateResult move_result;
      DCHECK(IsJSTemporalPlainDate(*relative_to));
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar,
                           Cast<JSTemporalPlainDate>(relative_to), one_week,
                           method_name),
          Nothing<DurationRecordWithRemainder>());

      // d. Set relativeTo to moveResult.[[RelativeTo]].
      relative_to = move_result.relative_to;

      // e. Let oneWeekDays be moveResult.[[Days]].
      double one_week_days = move_result.days;

      // f. Repeat, while abs(days) ≥ abs(oneWeekDays),
      while (std::abs(result.record.time_duration.days) >=
             std::abs(one_week_days)) {
        // i. Set weeks to weeks + sign.
        result.record.weeks += sign;
        // ii. Set days to days - oneWeekDays.
        result.record.time_duration.days -= one_week_days;
        // iii. Set moveResult to ? MoveRelativeDate(calendar, relativeTo,
        // oneWeek).
        DCHECK(IsJSTemporalPlainDate(*relative_to));
        MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, move_result,
            MoveRelativeDate(isolate, calendar,
                             Cast<JSTemporalPlainDate>(relative_to), one_week,
                             method_name),
            Nothing<DurationRecordWithRemainder>());
        // iv. Set relativeTo to moveResult.[[RelativeTo]].
        relative_to = move_result.relative_to;
        // v. Set oneWeekDays to moveResult.[[Days]].
        one_week_days = move_result.days;
      }

      // g. Let fractionalWeeks be weeks + days / abs(oneWeekDays).
      double fractional_weeks =
          result.record.weeks +
          result.record.time_duration.days / std::abs(one_week_days);
      // h. Set weeks to RoundNumberToIncrement(fractionalWeeks, increment,
      // roundingMode).
      result.record.weeks = RoundNumberToIncrement(isolate, fractional_weeks,
                                                   increment, rounding_mode);
      // i. Set remainder to fractionalWeeks - weeks.
      result.remainder = fractional_weeks - result.record.weeks;
      // j. Set days to 0.
      result.record.time_duration.days = 0;
    } break;
    // 12. Else if unit is "day", then
    case Unit::kDay: {
      // a. Let fractionalDays be days.
      double fractional_days = result.record.time_duration.days;

      // b. Set days to ! RoundNumberToIncrement(days, increment, roundingMode).
      result.record.time_duration.days = RoundNumberToIncrement(
          isolate, result.record.time_duration.days, increment, rounding_mode);

      // c. Set remainder to fractionalDays - days.
      result.remainder = fractional_days - result.record.time_duration.days;
    } break;
    // 13. Else if unit is "hour", then
    case Unit::kHour: {
      // a. Let fractionalHours be (fractionalSeconds / 60 + minutes) / 60 +
      // hours.
      double fractional_hours =
          (fractional_seconds / 60.0 + duration.time_duration.minutes) / 60.0 +
          duration.time_duration.hours;

      // b. Set hours to ! RoundNumberToIncrement(fractionalHours, increment,
      // roundingMode).
      result.record.time_duration.hours = RoundNumberToIncrement(
          isolate, fractional_hours, increment, rounding_mode);

      // c. Set remainder to fractionalHours - hours.
      result.remainder = fractional_hours - result.record.time_duration.hours;

      // d. Set minutes, seconds, milliseconds, microseconds, and nanoseconds to
      // 0.
      result.record.time_duration.minutes =
          result.record.time_duration.seconds =
              result.record.time_duration.milliseconds =
                  result.record.time_duration.microseconds =
                      result.record.time_duration.nanoseconds = 0;
    } break;
    // 14. Else if unit is "minute", then
    case Unit::kMinute: {
      // a. Let fractionalMinutes be fractionalSeconds / 60 + minutes.
      double fractional_minutes =
          fractional_seconds / 60.0 + duration.time_duration.minutes;

      // b. Set minutes to ! RoundNumberToIncrement(fractionalMinutes,
      // increment, roundingMode).
      result.record.time_duration.minutes = RoundNumberToIncrement(
          isolate, fractional_minutes, increment, rounding_mode);

      // c. Set remainder to fractionalMinutes - minutes.
      result.remainder =
          fractional_minutes - result.record.time_duration.minutes;

      // d. Set seconds, milliseconds, microseconds, and nanoseconds to 0.
      result.record.time_duration.seconds =
          result.record.time_duration.milliseconds =
              result.record.time_duration.microseconds =
                  result.record.time_duration.nanoseconds = 0;
    } break;
    // 15. Else if unit is "second", then
    case Unit::kSecond: {
      // a. Set seconds to ! RoundNumberToIncrement(fractionalSeconds,
      // increment, roundingMode).
      result.record.time_duration.seconds = RoundNumberToIncrement(
          isolate, fractional_seconds, increment, rounding_mode);

      // b. Set remainder to fractionalSeconds - seconds.
      result.remainder =
          fractional_seconds - result.record.time_duration.seconds;

      // c. Set milliseconds, microseconds, and nanoseconds to 0.
      result.record.time_duration.milliseconds =
          result.record.time_duration.microseconds =
              result.record.time_duration.nanoseconds = 0;
    } break;
    // 16. Else if unit is "millisecond", then
    case Unit::kMillisecond: {
      // a. Let fractionalMilliseconds be nanoseconds × 10^−6 + microseconds ×
      // 10^−3 + milliseconds.
      double fractional_milliseconds =
          duration.time_duration.nanoseconds * 1e-6 +
          duration.time_duration.microseconds * 1e-3 +
          duration.time_duration.milliseconds;

      // b. Set milliseconds to ! RoundNumberToIncrement(fractionalMilliseconds,
      // increment, roundingMode).
      result.record.time_duration.milliseconds = RoundNumberToIncrement(
          isolate, fractional_milliseconds, increment, rounding_mode);

      // c. Set remainder to fractionalMilliseconds - milliseconds.
      result.remainder =
          fractional_milliseconds - result.record.time_duration.milliseconds;

      // d. Set microseconds and nanoseconds to 0.
      result.record.time_duration.microseconds =
          result.record.time_duration.nanoseconds = 0;
    } break;
    // 17. Else if unit is "microsecond", then
    case Unit::kMicrosecond: {
      // a. Let fractionalMicroseconds be nanoseconds × 10−3 + microseconds.
      double fractional_microseconds =
          duration.time_duration.nanoseconds * 1e-3 +
          duration.time_duration.microseconds;

      // b. Set microseconds to ! RoundNumberToIncrement(fractionalMicroseconds,
      // increment, roundingMode).
      result.record.time_duration.microseconds = RoundNumberToIncrement(
          isolate, fractional_microseconds, increment, rounding_mode);

      // c. Set remainder to fractionalMicroseconds - microseconds.
      result.remainder =
          fractional_microseconds - result.record.time_duration.microseconds;

      // d. Set nanoseconds to 0.
      result.record.time_duration.nanoseconds = 0;
    } break;
    // 18. Else,
    default: {
      // a. Assert: unit is "nanosecond".
      DCHECK_EQ(unit, Unit::kNanosecond);
      // b. Set remainder to nanoseconds.
      result.remainder = result.record.time_duration.nanoseconds;

      // c. Set nanoseconds to ! RoundNumberToIncrement(nanoseconds, increment,
      // roundingMode).
      result.record.time_duration.nanoseconds = RoundNumberToIncrement(
          isolate, result.record.time_duration.nanoseconds, increment,
          rounding_mode);

      // d. Set remainder to remainder − nanoseconds.
      result.remainder -= result.record.time_duration.nanoseconds;
    } break;
  }
  // 19. Let duration be ? CreateDurationRecord(years, months, weeks, days,
  // hours, minutes, seconds, milliseconds, microseconds, nanoseconds).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result.record, CreateDurationRecord(isolate, result.record),
      Nothing<DurationRecordWithRemainder>());

  return Just(result);
}

Maybe<DurationRecordWithRemainder> RoundDuration(Isolate* isolate,
                                                 const DurationRecord& duration,
                                                 double increment, Unit unit,
                                                 RoundingMode rounding_mode,
                                                 const char* method_name) {
  // 1. If relativeTo is not present, set relativeTo to undefined.
  return RoundDuration(isolate, duration, increment, unit, rounding_mode,
                       isolate->factory()->undefined_value(), method_name);
}

// #sec-temporal-tosecondsstringprecision
struct StringPrecision {
  Precision precision;
  Unit unit;
  double increment;
};

// #sec-temporal-tosecondsstringprecision
Maybe<StringPrecision> ToSecondsStringPrecision(
    Isolate* isolate, Handle<JSReceiver> normalized_options,
    const char* method_name);

}  // namespace

// #sec-temporal.duration.prototype.tostring
MaybeHandle<String> JSTemporalDuration::ToString(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration,
    Handle<Object> options_obj) {
  const char* method_name = "Temporal.Duration.prototype.toString";
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

  // 5. If precision.[[Unit]] is "minute", throw a RangeError exception.
  if (precision.unit == Unit::kMinute) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 6. Let roundingMode be ? ToTemporalRoundingMode(options, "trunc").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, options, RoundingMode::kTrunc,
                             method_name),
      Handle<String>());

  // 7. Let result be ? RoundDuration(duration.[[Years]], duration.[[Months]],
  // duration.[[Weeks]], duration.[[Days]], duration.[[Hours]],
  // duration.[[Minutes]], duration.[[Seconds]], duration.[[Milliseconds]],
  // duration.[[Microseconds]], duration.[[Nanoseconds]],
  // precision.[[Increment]], precision.[[Unit]], roundingMode).
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
  DurationRecordWithRemainder result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      RoundDuration(isolate, dur, precision.increment, precision.unit,
                    rounding_mode, method_name),
      Handle<String>());

  // 8. Return ! TemporalDurationToString(result.[[Years]], result.[[Months]],
  // result.[[Weeks]], result.[[Days]], result.[[Hours]], result.[[Minutes]],
  // result.[[Seconds]], result.[[Milliseconds]], result.[[Microseconds]],
  // result.[[Nanoseconds]], precision.[[Precision]]).

  return TemporalDurationToString(isolate, result.record, precision.precision);
}

// #sec-temporal.calendar
MaybeHandle<JSTemporalCalendar> JSTemporalCalendar::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> identifier_obj) {
  // 1. If NewTarget is undefined, then
  if (IsUndefined(*new_target, isolate)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kConstructorNotFunction,
                                 isolate->factory()->NewStringFromStaticChars(
                                     "Temporal.Calendar")));
  }
  // 2. Set identifier to ? ToString(identifier).
  Handle<String> identifier;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, identifier,
                             Object::ToString(isolate, identifier_obj));
  // 3. If ! IsBuiltinCalendar(id) is false, then
  if (!IsBuiltinCalendar(isolate, identifier)) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(
        isolate, NewRangeError(MessageTemplate::kInvalidCalendar, identifier));
  }
  return CreateTemporalCalendar(isolate, target, new_target, identifier);
}

namespace {

// #sec-temporal-toisodayofyear
int32_t ToISODayOfYear(Isolate* isolate, const DateRecord& date) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: IsValidISODate(year, month, day) is *true*.
  DCHECK(IsValidISODate(isolate, date));
  // 2. Let _epochDays_ be MakeDay(𝔽(year), 𝔽(month - 1), 𝔽(day)).
  // 3. Assert: _epochDays_ is finite.
  // 4. Return ℝ(DayWithinYear(MakeDate(_epochDays_, *+0*<sub>𝔽</sub>))) + 1.
  // Note: In ISO 8601, Jan: month=1, Dec: month=12,
  // In DateCache API, Jan: month=0, Dec: month=11 so we need to - 1 for month.
  return date.day +
         isolate->date_cache()->DaysFromYearMonth(date.year, date.month - 1) -
         isolate->date_cache()->DaysFromYearMonth(date.year, 0);
}

bool IsPlainDatePlainDateTimeOrPlainYearMonth(
    DirectHandle<Object> temporal_date_like) {
  return IsJSTemporalPlainDate(*temporal_date_like) ||
         IsJSTemporalPlainDateTime(*temporal_date_like) ||
         IsJSTemporalPlainYearMonth(*temporal_date_like);
}

// #sec-temporal-toisodayofweek
int32_t ToISODayOfWeek(Isolate* isolate, const DateRecord& date) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: IsValidISODate(year, month, day) is *true*.
  DCHECK(IsValidISODate(isolate, date));
  // 2. Let _epochDays_ be MakeDay(𝔽(year), 𝔽(month - 1), 𝔽(day)).
  // Note: "- 1" after "date.day" came from the MakeyDay AO in
  // "9. Return Day(t) + dt - 1𝔽."
  int32_t epoch_days =
      isolate->date_cache()->DaysFromYearMonth(date.year, date.month - 1) +
      date.day - 1;
  // 3. Assert: _epochDays_ is finite.
  // 4. Let _dayOfWeek_ be WeekDay(MakeDate(_epochDays_, *+0*<sub>𝔽</sub>)).
  int32_t weekday = isolate->date_cache()->Weekday(epoch_days);
  // 5. If _dayOfWeek_ = *+0*<sub>𝔽</sub>, return 7.

  // Note: In ISO 8601, Jan: month=1, Dec: month=12.
  // In DateCache API, Jan: month=0, Dec: month=11 so we need to - 1 for month.
  // Weekday() expect "the number of days since the epoch" as input and the
  // value of day is 1-based so we need to minus 1 to calculate "the number of
  // days" because the number of days on the epoch (1970/1/1) should be 0,
  // not 1
  // Note: In ISO 8601, Sun: weekday=7 Mon: weekday=1
  // In DateCache API, Sun: weekday=0 Mon: weekday=1
  // 6. Return ℝ(_dayOfWeek_).
  return weekday == 0 ? 7 : weekday;
}

// #sec-temporal-regulateisodate
Maybe<DateRecord> RegulateISODate(Isolate* isolate, ShowOverflow overflow,
                                  const DateRecord& date) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: year, month, and day are integers.
  // 2. Assert: overflow is either "constrain" or "reject".
  switch (overflow) {
    // 3. If overflow is "reject", then
    case ShowOverflow::kReject:
      // a. If ! IsValidISODate(year, month, day) is false, throw a RangeError
      // exception.
      if (!IsValidISODate(isolate, date)) {
        THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                     NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                     Nothing<DateRecord>());
      }
      // b. Return the Record { [[Year]]: year, [[Month]]: month, [[Day]]: day
      // }.
      return Just(date);
    // 4. If overflow is "constrain", then
    case ShowOverflow::kConstrain:
      DateRecord result(date);
      // a. Set month to ! ConstrainToRange(month, 1, 12).
      result.month = std::max(std::min(result.month, 12), 1);
      // b. Set day to ! ConstrainToRange(day, 1, ! ISODaysInMonth(year,
      // month)).
      result.day =
          std::max(std::min(result.day,
                            ISODaysInMonth(isolate, result.year, result.month)),
                   1);
      // c. Return the Record { [[Year]]: year, [[Month]]: month, [[Day]]: day
      // }.
      return Just(result);
  }
}

// #sec-temporal-regulateisoyearmonth
Maybe<int32_t> RegulateISOYearMonth(Isolate* isolate, ShowOverflow overflow,
                                    int32_t month) {
  // 1. Assert: year and month are integers.
  // 2. Assert: overflow is either "constrain" or "reject".
  switch (overflow) {
    // 3. If overflow is "constrain", then
    case ShowOverflow::kConstrain:
      // a. Return ! ConstrainISOYearMonth(year, month).
      return Just(std::max(std::min(month, 12), 1));
    // 4. If overflow is "reject", then
    case ShowOverflow::kReject:
      // a. If ! IsValidISOMonth(month) is false, throw a RangeError exception.
      if (month < 1 || 12 < month) {
        THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                     NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                     Nothing<int32_t>());
      }
      // b. Return the new Record { [[Year]]: year, [[Month]]: month }.
      return Just(month);
    default:
      UNREACHABLE();
  }
}

// #sec-temporal-resolveisomonth
Maybe<int32_t> ResolveISOMonth(Isolate* isolate, Handle<JSReceiver> fields) {
  Factory* factory = isolate->factory();
  // 1. Let month be ! Get(fields, "month").
  DirectHandle<Object> month_obj =
      JSReceiver::GetProperty(isolate, fields, factory->month_string())
          .ToHandleChecked();
  // 2. Let monthCode be ! Get(fields, "monthCode").
  Handle<Object> month_code_obj =
      JSReceiver::GetProperty(isolate, fields, factory->monthCode_string())
          .ToHandleChecked();
  // 3. If monthCode is undefined, then
  if (IsUndefined(*month_code_obj, isolate)) {
    // a. If month is undefined, throw a TypeError exception.
    if (IsUndefined(*month_obj, isolate)) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(), Nothing<int32_t>());
    }
    // b. Return month.
    // Note: In Temporal spec, "month" in fields is always converted by
    // ToPositiveInteger inside PrepareTemporalFields before calling
    // ResolveISOMonth. Therefore the month_obj is always a positive integer.
    DCHECK(IsSmi(*month_obj) || IsHeapNumber(*month_obj));
    return Just(FastD2I(Object::NumberValue(Cast<Number>(*month_obj))));
  }
  // 4. Assert: Type(monthCode) is String.
  DCHECK(IsString(*month_code_obj));
  Handle<String> month_code;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, month_code,
                                   Object::ToString(isolate, month_code_obj),
                                   Nothing<int32_t>());
  // 5. Let monthLength be the length of monthCode.
  // 6. If monthLength is not 3, throw a RangeError exception.
  if (month_code->length() != 3) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kPropertyValueOutOfRange,
                      factory->monthCode_string()),
        Nothing<int32_t>());
  }
  // 7. Let numberPart be the substring of monthCode from 1.
  // 8. Set numberPart to ! ToIntegerOrInfinity(numberPart).
  // 9. If numberPart < 1 or numberPart > 12, throw a RangeError exception.
  uint16_t m0 = month_code->Get(0);
  uint16_t m1 = month_code->Get(1);
  uint16_t m2 = month_code->Get(2);
  if (!((m0 == 'M') && ((m1 == '0' && '1' <= m2 && m2 <= '9') ||
                        (m1 == '1' && '0' <= m2 && m2 <= '2')))) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kPropertyValueOutOfRange,
                      factory->monthCode_string()),
        Nothing<int32_t>());
  }
  int32_t number_part =
      10 * static_cast<int32_t>(m1 - '0') + static_cast<int32_t>(m2 - '0');
  // 10. If month is not undefined, and month ≠ numberPart, then
  // 11. If ! SameValueNonNumeric(monthCode, ! BuildISOMonthCode(numberPart)) is
  // false, then a. Throw a RangeError exception.
  // Note: In Temporal spec, "month" in fields is always converted by
  // ToPositiveInteger inside PrepareTemporalFields before calling
  // ResolveISOMonth. Therefore the month_obj is always a positive integer.
  if (!IsUndefined(*month_obj) &&
      FastD2I(Object::NumberValue(Cast<Number>(*month_obj))) != number_part) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kPropertyValueOutOfRange,
                      factory->month_string()),
        Nothing<int32_t>());
  }

  // 12. Return numberPart.
  return Just(number_part);
}

// #sec-temporal-isodatefromfields
Maybe<DateRecord> ISODateFromFields(Isolate* isolate, Handle<JSReceiver> fields,
                                    Handle<JSReceiver> options,
```