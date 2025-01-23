Response: The user wants to understand the functionality of the C++ code in `v8/src/objects/js-temporal-objects.cc`, specifically part 7 of 13. I need to:

1. **Summarize the C++ code's purpose**: Focus on the functions and logic within this specific part of the file.
2. **Relate it to JavaScript**: Explain how the C++ code connects to JavaScript functionality, particularly within the Temporal API.
3. **Provide JavaScript examples**: Illustrate the connection with concrete JavaScript code snippets.

Based on the provided code snippet, it seems to be implementing parts of the Temporal API related to:

- **Rounding durations**: The `RoundDuration` function and its helper `RoundNumberToIncrement`.
- **Formatting durations to strings**: The `ToString` method of `JSTemporalDuration` and the `ToSecondsStringPrecision` function.
- **Calendar operations**: The `JSTemporalCalendar` constructor and several methods like `DateAdd`, `DaysInYear`, `DaysInMonth`, `Year`, `DayOfYear`, `DayOfWeek`, `MonthsInYear`, `InLeapYear`, `DaysInWeek`, `DateFromFields`, `MergeFields`, and `DateUntil`.
- **Date calculations**: Helper functions like `ToISODayOfYear`, `ToISODayOfWeek`, `RegulateISODate`, `RegulateISOYearMonth`, `ResolveISOMonth`, `ISODateFromFields`, `AddISODate`, `DifferenceISODate`, `ISOYearMonthFromFields`, and `ToISOWeekOfYear`.

The code appears to handle calculations and manipulations related to dates and durations, adhering to the ISO 8601 calendar in this specific section. It interacts with JavaScript through the V8 engine's internal representation of JavaScript objects (like `JSTemporalDuration` and `JSTemporalPlainDate`).
Based on the provided C++ code snippet from `v8/src/objects/js-temporal-objects.cc`, specifically part 7 of 13, this section focuses on implementing several functionalities related to the **Temporal API's `Temporal.Duration` and `Temporal.Calendar` objects**.

Here's a breakdown of the key functionalities:

**1. Rounding Temporal Durations:**

- The code defines the `RoundDuration` function. This function takes a `DurationRecord` (representing years, months, weeks, days, hours, etc.), an `increment`, a `unit` to round to, a `roundingMode`, and optionally a `relativeTo` date.
- It implements the logic to round the duration to the specified unit and increment, considering the rounding mode. This involves potentially moving forward or backward in time using calendar operations when rounding to larger units like years or months.
- Helper functions like `RoundNumberToIncrement` are used for the actual rounding of numerical values.

**2. Formatting Temporal Durations to Strings:**

- The `JSTemporalDuration::ToString` method is defined. This method takes options to control the precision of the output string.
- It uses `ToSecondsStringPrecision` to determine the desired precision based on the options.
- It then calls `RoundDuration` to round the duration to the specified precision before formatting it into a string using `TemporalDurationToString`.

**3. Implementing `Temporal.Calendar` Functionality (for ISO 8601 calendar):**

- The `JSTemporalCalendar::Constructor` enforces that the calendar identifier is valid (in this case, likely "iso8601").
- Several methods of the `Temporal.Calendar.prototype` are implemented:
    - `DateAdd`: Adds a duration to a date, taking into account calendar rules and overflow behavior. It utilizes the `AddISODate` helper function for ISO calendar calculations.
    - `DaysInYear`: Returns the number of days in the year of a given date. It uses the `ISODaysInYear` helper.
    - `DaysInMonth`: Returns the number of days in the month of a given date. It uses the `ISODaysInMonth` helper.
    - `Year`: Returns the year of a given date.
    - `DayOfYear`: Returns the day of the year for a given date. It uses the `ToISODayOfYear` helper.
    - `DayOfWeek`: Returns the day of the week for a given date (ISO 8601 convention: Monday is 1, Sunday is 7). It uses the `ToISODayOfWeek` helper.
    - `MonthsInYear`: Returns the number of months in a year (always 12 for ISO 8601).
    - `InLeapYear`: Determines if the year of a given date is a leap year. It uses the `IsISOLeapYear` helper.
    - `DaysInWeek`: Returns the number of days in a week (always 7).
    - `DateFromFields`: Creates a `Temporal.PlainDate` from a fields object, using `ISODateFromFields` to handle ISO calendar specifics.
    - `MergeFields`: Merges two sets of fields for a date, using `DefaultMergeFields` for the ISO calendar.
    - `DateUntil`: Calculates the duration between two dates, using the `DifferenceISODate` helper for ISO calendar calculations.

**4. Helper Functions for Date Calculations (ISO 8601 specific):**

- A set of helper functions are defined to perform date-related calculations according to the ISO 8601 calendar:
    - `ToISODayOfYear`: Calculates the day number within the year for a given ISO date.
    - `ToISODayOfWeek`: Calculates the day of the week (1-7) for a given ISO date.
    - `RegulateISODate`: Ensures the validity of an ISO date, either by constraining values or throwing an error.
    - `RegulateISOYearMonth`: Ensures the validity of an ISO year and month.
    - `ResolveISOMonth`: Resolves the month from either a "month" number or a "monthCode" string.
    - `ISODateFromFields`: Creates a `DateRecord` from a fields object, validating the ISO date components.
    - `AddISODate`: Adds years, months, weeks, and days to an ISO date, handling overflow.
    - `DifferenceISODate`: Calculates the difference between two ISO dates in terms of years, months, weeks, and days.
    - `ISOYearMonthFromFields`: Creates a `DateRecord` (representing a year-month) from a fields object.
    - `ToISOWeekOfYear`: Calculates the ISO week number of the year for a given date.

**Relationship to JavaScript and Examples:**

This C++ code directly implements the core logic for several JavaScript functionalities within the Temporal API. When you use these Temporal API methods in your JavaScript code, the V8 engine executes the corresponding C++ code in this file.

Here are some JavaScript examples illustrating the connection:

```javascript
// Temporal.Duration.prototype.toString()
const duration = new Temporal.Duration(1, 2, 0, 5);
console.log(duration.toString()); //  "P1Y2M5D"
console.log(duration.toString({ smallestUnit: 'month' })); // "P1Y2M"

// Temporal.Calendar.prototype.dateAdd()
const calendar = new Temporal.Calendar('iso8601');
const date = new Temporal.PlainDate(2023, 10, 26);
const durationToAdd = new Temporal.Duration(0, 1, 0, 10);
const newDate = calendar.dateAdd(date, durationToAdd);
console.log(newDate.toString()); // "2023-12-05"

// Temporal.Calendar.prototype.daysInYear()
const dateForDaysInYear = new Temporal.PlainDate(2024, 1, 1); // Leap year
console.log(calendar.daysInYear(dateForDaysInYear)); // 366

// Temporal.Calendar.prototype.dayOfYear()
const aDate = new Temporal.PlainDate(2023, 5, 15);
console.log(calendar.dayOfYear(aDate)); // 135

// Temporal.Calendar.prototype.dateUntil()
const startDate = new Temporal.PlainDate(2023, 1, 15);
const endDate = new Temporal.PlainDate(2023, 3, 20);
const difference = calendar.dateUntil(startDate, endDate);
console.log(difference.toString()); // "P2M5D"
```

In these examples, when JavaScript code calls methods like `toString()` on a `Temporal.Duration` or `dateAdd()` on a `Temporal.Calendar`, the V8 engine internally invokes the corresponding C++ functions defined in this part of `js-temporal-objects.cc` to perform the underlying calculations and operations. The helper functions in C++ ensure the logic adheres to the specifications of the Temporal API, especially regarding the ISO 8601 calendar.

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第7部分，共13部分，请归纳一下它的功能
```

### 源代码
```
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
                                    const char* method_name) {
  Factory* factory = isolate->factory();

  // 1. Assert: Type(fields) is Object.
  // 2. Set fields to ? PrepareTemporalFields(fields, « "day", "month",
  // "monthCode", "year" », «"year", "day"»).
  DirectHandle<FixedArray> field_names =
      DayMonthMonthCodeYearInFixedArray(isolate);
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, fields,
      PrepareTemporalFields(isolate, fields, field_names,
                            RequiredFields::kYearAndDay),
      Nothing<DateRecord>());
  // 3. Let overflow be ? ToTemporalOverflow(options).
  ShowOverflow overflow;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, overflow, ToTemporalOverflow(isolate, options, method_name),
      Nothing<DateRecord>());

  // 4. Let year be ! Get(fields, "year").
  DirectHandle<Object> year_obj =
      JSReceiver::GetProperty(isolate, fields, factory->year_string())
          .ToHandleChecked();
  // 5. Assert: Type(year) is Number.
  // Note: "year" in fields is always converted by
  // ToIntegerThrowOnInfinity inside the PrepareTemporalFields above.
  // Therefore the year_obj is always an integer.
  DCHECK(IsSmi(*year_obj) || IsHeapNumber(*year_obj));

  // 6. Let month be ? ResolveISOMonth(fields).
  int32_t month;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, month, ResolveISOMonth(isolate, fields), Nothing<DateRecord>());

  // 7. Let day be ! Get(fields, "day").
  DirectHandle<Object> day_obj =
      JSReceiver::GetProperty(isolate, fields, factory->day_string())
          .ToHandleChecked();
  // 8. Assert: Type(day) is Number.
  // Note: "day" in fields is always converted by
  // ToIntegerThrowOnInfinity inside the PrepareTemporalFields above.
  // Therefore the day_obj is always an integer.
  DCHECK(IsSmi(*day_obj) || IsHeapNumber(*day_obj));
  // 9. Return ? RegulateISODate(year, month, day, overflow).
  return RegulateISODate(
      isolate, overflow,
      {FastD2I(Object::NumberValue(Cast<Number>(*year_obj))), month,
       FastD2I(Object::NumberValue(Cast<Number>(*day_obj)))});
}

// #sec-temporal-addisodate
Maybe<DateRecord> AddISODate(Isolate* isolate, const DateRecord& date,
                             const DateDurationRecord& duration,
                             ShowOverflow overflow) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: year, month, day, years, months, weeks, and days are integers.
  // 2. Assert: overflow is either "constrain" or "reject".
  DCHECK(overflow == ShowOverflow::kConstrain ||
         overflow == ShowOverflow::kReject);
  // 3. Let intermediate be ! BalanceISOYearMonth(year + years, month + months).
  DateRecord intermediate = date;
  intermediate.year += static_cast<int32_t>(duration.years);
  intermediate.month += static_cast<int32_t>(duration.months);
  BalanceISOYearMonth(isolate, &intermediate.year, &intermediate.month);
  // 4. Let intermediate be ? RegulateISODate(intermediate.[[Year]],
  // intermediate.[[Month]], day, overflow).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, intermediate, RegulateISODate(isolate, overflow, intermediate),
      Nothing<DateRecord>());

  // 5. Set days to days + 7 × weeks.
  // 6. Let d be intermediate.[[Day]] + days.
  intermediate.day += duration.days + 7 * duration.weeks;
  // 7. Return BalanceISODate(intermediate.[[Year]], intermediate.[[Month]], d).
  return Just(BalanceISODate(isolate, intermediate));
}

// #sec-temporal-differenceisodate
Maybe<DateDurationRecord> DifferenceISODate(Isolate* isolate,
                                            const DateRecord& date1,
                                            const DateRecord& date2,
                                            Unit largest_unit,
                                            const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: largestUnit is one of "year", "month", "week", or "day".
  DCHECK(largest_unit == Unit::kYear || largest_unit == Unit::kMonth ||
         largest_unit == Unit::kWeek || largest_unit == Unit::kDay);
  // 2. If largestUnit is "year" or "month", then
  switch (largest_unit) {
    case Unit::kYear:
    case Unit::kMonth: {
      // a. Let sign be -(! CompareISODate(y1, m1, d1, y2, m2, d2)).
      int32_t sign = -CompareISODate(date1, date2);
      // b. If sign is 0, return ! CreateDateDurationRecord(0, 0, 0, 0).
      if (sign == 0) {
        return DateDurationRecord::Create(isolate, 0, 0, 0, 0);
      }

      // c. Let start be the new Record { [[Year]]: y1, [[Month]]: m1, [[Day]]:
      // d1
      // }.
      DateRecord start = date1;
      // d. Let end be the new Record { [[Year]]: y2, [[Month]]: m2, [[Day]]:
      // d2 }.
      DateRecord end = date2;
      // e. Let years be end.[[Year]] − start.[[Year]].
      double years = end.year - start.year;
      // f. Let mid be ! AddISODate(y1, m1, d1, years, 0, 0, 0, "constrain").
      DateRecord mid;
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, mid,
          AddISODate(isolate, date1, {years, 0, 0, 0},
                     ShowOverflow::kConstrain),
          Nothing<DateDurationRecord>());

      // g. Let midSign be -(! CompareISODate(mid.[[Year]], mid.[[Month]],
      // mid.[[Day]], y2, m2, d2)).
      int32_t mid_sign = -CompareISODate(mid, date2);

      // h. If midSign is 0, then
      if (mid_sign == 0) {
        // i. If largestUnit is "year", return ! CreateDateDurationRecord(years,
        // 0, 0, 0).
        if (largest_unit == Unit::kYear) {
          return DateDurationRecord::Create(isolate, years, 0, 0, 0);
        }
        // ii. Return ! CreateDateDurationRecord(0, years × 12, 0, 0).
        return DateDurationRecord::Create(isolate, 0, years * 12, 0, 0);
      }
      // i. Let months be end.[[Month]] − start.[[Month]].
      double months = end.month - start.month;
      // j. If midSign is not equal to sign, then
      if (mid_sign != sign) {
        // i. Set years to years - sign.
        years -= sign;
        // ii. Set months to months + sign × 12.
        months += sign * 12;
      }
      // k. Set mid be ! AddISODate(y1, m1, d1, years, months, 0, 0,
      // "constrain").
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, mid,
          AddISODate(isolate, date1, {years, months, 0, 0},
                     ShowOverflow::kConstrain),
          Nothing<DateDurationRecord>());
      // l. Let midSign be -(! CompareISODate(mid.[[Year]], mid.[[Month]],
      // mid.[[Day]], y2, m2, d2)).
      mid_sign = -CompareISODate(mid, date2);
      // m. If midSign is 0, then
      if (mid_sign == 0) {
        // 1. i. If largestUnit is "year", return !
        // CreateDateDurationRecord(years, months, 0, 0).
        if (largest_unit == Unit::kYear) {
          return DateDurationRecord::Create(isolate, years, months, 0, 0);
        }
        // ii. Return ! CreateDateDurationRecord(0, months + years × 12, 0, 0).
        return DateDurationRecord::Create(isolate, 0, months + years * 12, 0,
                                          0);
      }
      // n. If midSign is not equal to sign, then
      if (mid_sign != sign) {
        // i. Set months to months - sign.
        months -= sign;
        // ii. If months is equal to -sign, then
        if (months == -sign) {
          // 1. Set years to years - sign.
          years -= sign;
          // 2. Set months to 11 × sign.
          months = 11 * sign;
        }
        // iii. Set mid be ! AddISODate(y1, m1, d1, years, months, 0, 0,
        // "constrain").
        MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, mid,
            AddISODate(isolate, date1, {years, months, 0, 0},
                       ShowOverflow::kConstrain),
            Nothing<DateDurationRecord>());
        // iv. Let midSign be -(! CompareISODate(mid.[[Year]], mid.[[Month]],
        // mid.[[Day]], y2, m2, d2)).
        mid_sign = -CompareISODate(mid, date2);
      }
      // o. Let days be 0.
      double days = 0;
      // p. If mid.[[Month]] = end.[[Month]], then
      if (mid.month == end.month) {
        // i. Assert: mid.[[Year]] = end.[[Year]].
        DCHECK_EQ(mid.year, end.year);
        // ii. Set days to end.[[Day]] - mid.[[Day]].
        days = end.day - mid.day;
      } else if (sign < 0) {
        // q. Else if sign < 0, set days to -mid.[[Day]] - (!
        // ISODaysInMonth(end.[[Year]], end.[[Month]]) - end.[[Day]]).
        days =
            -mid.day - (ISODaysInMonth(isolate, end.year, end.month) - end.day);
      } else {
        // r. Else, set days to end.[[Day]] + (! ISODaysInMonth(mid.[[Year]],
        // mid.[[Month]]) - mid.[[Day]]).
        days =
            end.day + (ISODaysInMonth(isolate, mid.year, mid.month) - mid.day);
      }
      // s. If largestUnit is "month", then
      if (largest_unit == Unit::kMonth) {
        // i. Set months to months + years × 12.
        months += years * 12;
        // ii. Set years to 0.
        years = 0;
      }
      // t. Return ! CreateDateDurationRecord(years, months, 0, days).
      return DateDurationRecord::Create(isolate, years, months, 0, days);
    }
      // 3. If largestUnit is "day" or "week", then
    case Unit::kDay:
    case Unit::kWeek: {
      DateRecord smaller, greater;
      // a. If ! CompareISODate(y1, m1, d1, y2, m2, d2) < 0, then
      int32_t sign;
      if (CompareISODate(date1, date2) < 0) {
        // i. Let smaller be the Record { [[Year]]: y1, [[Month]]: m1, [[Day]]:
        // d1
        // }.
        smaller = date1;
        // ii. Let greater be the Record { [[Year]]: y2, [[Month]]: m2, [[Day]]:
        // d2
        // }.
        greater = date2;
        // iii. Let sign be 1.
        sign = 1;
      } else {
        // b. Else,
        // i. Let smaller be the new Record { [[Year]]: y2, [[Month]]: m2,
        // [[Day]]: d2 }.
        smaller = date2;
        // ii. Let greater be the new Record { [[Year]]: y1, [[Month]]: m1,
        // [[Day]]: d1 }.
        greater = date1;
        // iii. Let sign be −1.
        sign = -1;
      }
      // c. Let days be ! ToISODayOfYear(greater.[[Year]], greater.[[Month]],
      // greater.[[Day]]) − ! ToISODayOfYear(smaller.[[Year]],
      // smaller.[[Month]], smaller.[[Day]]).
      int32_t days =
          ToISODayOfYear(isolate, greater) - ToISODayOfYear(isolate, smaller);
      // d. Let year be smaller.[[Year]].
      // e. Repeat, while year < greater.[[Year]],
      for (int32_t year = smaller.year; year < greater.year; year++) {
        // i. Set days to days + ! ISODaysInYear(year).
        // ii. Set year to year + 1.
        days += ISODaysInYear(isolate, year);
      }
      // f. Let weeks be 0.
      int32_t weeks = 0;
      // g. If largestUnit is "week", then
      if (largest_unit == Unit::kWeek) {
        // i. Set weeks to floor(days / 7).
        weeks = days / 7;
        // ii. Set days to days mod 7.
        days = days % 7;
      }
      // h. Return ! CreateDateDurationRecord(0, 0, weeks × sign, days × sign).
      return DateDurationRecord::Create(isolate, 0, 0, weeks * sign,
                                        days * sign);
    }
    default:
      UNREACHABLE();
  }
}

// #sec-temporal-isoyearmonthfromfields
Maybe<DateRecord> ISOYearMonthFromFields(Isolate* isolate,
                                         Handle<JSReceiver> fields,
                                         Handle<JSReceiver> options,
                                         const char* method_name) {
  Factory* factory = isolate->factory();
  // 1. Assert: Type(fields) is Object.
  // 2. Set fields to ? PrepareTemporalFields(fields, « "month", "monthCode",
  // "year" », «»).
  DirectHandle<FixedArray> field_names = factory->NewFixedArray(3);
  field_names->set(0, ReadOnlyRoots(isolate).month_string());
  field_names->set(1, ReadOnlyRoots(isolate).monthCode_string());
  field_names->set(2, ReadOnlyRoots(isolate).year_string());
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, fields,
      PrepareTemporalFields(isolate, fields, field_names,
                            RequiredFields::kNone),
      Nothing<DateRecord>());
  // 3. Let overflow be ? ToTemporalOverflow(options).
  ShowOverflow overflow;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, overflow, ToTemporalOverflow(isolate, options, method_name),
      Nothing<DateRecord>());

  // 4. Let year be ! Get(fields, "year").
  DirectHandle<Object> year_obj =
      JSReceiver::GetProperty(isolate, fields, factory->year_string())
          .ToHandleChecked();
  // 5. If year is undefined, throw a TypeError exception.
  if (IsUndefined(*year_obj, isolate)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<DateRecord>());
  }
  DateRecord result;
  result.year = FastD2I(floor(Object::NumberValue(Cast<Number>(*year_obj))));
  // 6. Let month be ? ResolveISOMonth(fields).
  int32_t month;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, month, ResolveISOMonth(isolate, fields), Nothing<DateRecord>());
  // 7. Let result be ? RegulateISOYearMonth(year, month, overflow).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result.month, RegulateISOYearMonth(isolate, overflow, month),
      Nothing<DateRecord>());
  // 8. Return the new Record { [[Year]]: result.[[Year]], [[Month]]:
  // result.[[Month]], [[ReferenceISODay]]: 1 }.
  result.day = 1;
  return Just(result);
}
// #sec-temporal-toisoweekofyear
int32_t ToISOWeekOfYear(Isolate* isolate, const DateRecord& date) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: IsValidISODate(year, month, day) is *true*.
  DCHECK(IsValidISODate(isolate, date));

  // 2. Let wednesday be 3.
  constexpr int32_t kWednesday = 3;
  // 3. Let thursday_ be 4.
  constexpr int32_t kThursday = 4;
  // 4. Let friday be 5.
  constexpr int32_t kFriday = 5;
  // 5. Let saturday be 6.
  constexpr int32_t kSaturday = 6;
  // 6. Let daysInWeek be 7.
  constexpr int32_t kDaysInWeek = 7;
  // 7. Let maxWeekNumber be 53.
  constexpr int32_t kMaxWeekNumber = 53;
  // 8. Let dayOfYear be ToISODayOfYear(year, month, day).
  int32_t day_of_year = ToISODayOfYear(isolate, date);
  // 9. Let dayOfWeek be ToISODayOfWeek(year, month, day).
  int32_t day_of_week = ToISODayOfWeek(isolate, date);
  // 10. Let week be floor((dayOfYear + daysInWeek - dayOfWeek + wednesday ) /
  // daysInWeek).
  int32_t week =
      (day_of_year + kDaysInWeek - day_of_week + kWednesday) / kDaysInWeek;
  // 11. If week < 1, then
  if (week < 1) {
    // a. NOTE: This is the last week of the previous year.
    // b. Let dayOfJan1st be ToISODayOfWeek(year, 1, 1).
    int32_t day_of_jan_1st = ToISODayOfWeek(isolate, {date.year, 1, 1});
    // c. If dayOfJan1st is friday, then
    if (day_of_jan_1st == kFriday) {
      // a. Return maxWeekNumber.
      return kMaxWeekNumber;
    }
    // d. If dayOfJan1st is saturday, and InLeapYear(TimeFromYear(𝔽(year - 1)))
    // is *1*<sub>𝔽</sub>, then
    if (day_of_jan_1st == kSaturday && IsISOLeapYear(isolate, date.year - 1)) {
      // i. Return maxWeekNumber.
      return kMaxWeekNumber;
    }
    // e. Return maxWeekNumber - 1.
    return kMaxWeekNumber - 1;
  }
  // 12. If week is maxWeekNumber, then
  if (week == kMaxWeekNumber) {
    // a. Let daysInYear be DaysInYear(𝔽(year)).
    int32_t days_in_year = ISODaysInYear(isolate, date.year);
    // b. Let daysLaterInYear be daysInYear - dayOfYear.
    int32_t days_later_in_year = days_in_year - day_of_year;
    // c. Let daysAfterThursday be thursday - dayOfWeek.
    int32_t days_after_thursday = kThursday - day_of_week;
    // d. If daysLaterInYear &lt; daysAfterThursday, then
    if (days_later_in_year < days_after_thursday) {
      // 1. Return 1.
      return 1;
    }
  }
  // 13. Return week.
  return week;
}

}  // namespace

// #sec-temporal.calendar.prototype.dateadd
MaybeHandle<JSTemporalPlainDate> JSTemporalCalendar::DateAdd(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> date_obj, Handle<Object> duration_obj,
    Handle<Object> options_obj) {
  const char* method_name = "Temporal.Calendar.prototype.dateAdd";
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. Set date to ? ToTemporalDate(date).
  Handle<JSTemporalPlainDate> date;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, date,
                             ToTemporalDate(isolate, date_obj, method_name));

  // 5. Set duration to ? ToTemporalDuration(duration).
  Handle<JSTemporalDuration> duration;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, duration,
      temporal::ToTemporalDuration(isolate, duration_obj, method_name));

  // 6. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 7. Let overflow be ? ToTemporalOverflow(options).
  ShowOverflow overflow;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, overflow, ToTemporalOverflow(isolate, options, method_name),
      Handle<JSTemporalPlainDate>());

  // 8. Let balanceResult be ? BalanceDuration(duration.[[Days]],
  // duration.[[Hours]], duration.[[Minutes]], duration.[[Seconds]],
  // duration.[[Milliseconds]], duration.[[Microseconds]],
  // duration.[[Nanoseconds]], "day").
  TimeDurationRecord balance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, balance_result,
      BalanceDuration(isolate, Unit::kDay,
                      {Object::NumberValue(duration->days()),
                       Object::NumberValue(duration->hours()),
                       Object::NumberValue(duration->minutes()),
                       Object::NumberValue(duration->seconds()),
                       Object::NumberValue(duration->milliseconds()),
                       Object::NumberValue(duration->microseconds()),
                       Object::NumberValue(duration->nanoseconds())},
                      method_name),
      Handle<JSTemporalPlainDate>());

  DateRecord result;
  // If calendar.[[Identifier]] is "iso8601", then
  if (calendar->calendar_index() == 0) {
    // 9. Let result be ? AddISODate(date.[[ISOYear]], date.[[ISOMonth]],
    // date.[[ISODay]], duration.[[Years]], duration.[[Months]],
    // duration.[[Weeks]], balanceResult.[[Days]], overflow).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        AddISODate(
            isolate, {date->iso_year(), date->iso_month(), date->iso_day()},
            {Object::NumberValue(duration->years()),
             Object::NumberValue(duration->months()),
             Object::NumberValue(duration->weeks()), balance_result.days},
            overflow),
        Handle<JSTemporalPlainDate>());
  } else {
#ifdef V8_INTL_SUPPORT
    // TODO(ftang) add code for other calendar.
    UNIMPLEMENTED();
#else   // V8_INTL_SUPPORT
    UNREACHABLE();
#endif  // V8_INTL_SUPPORT
  }
  // 10. Return ? CreateTemporalDate(result.[[Year]], result.[[Month]],
  // result.[[Day]], calendar).
  return CreateTemporalDate(isolate, result, calendar);
}

// #sec-temporal.calendar.prototype.daysinyear
MaybeHandle<Smi> JSTemporalCalendar::DaysInYear(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]], [[InitializedTemporalDateTime]] or
  // [[InitializedTemporalYearMonth]] internal slot, then
  if (!IsPlainDatePlainDateTimeOrPlainYearMonth(temporal_date_like)) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.daysInYear"));
  }

  // a. Let daysInYear be ! ISODaysInYear(temporalDateLike.[[ISOYear]]).
  int32_t year;
  if (IsJSTemporalPlainDate(*temporal_date_like)) {
    year = Cast<JSTemporalPlainDate>(temporal_date_like)->iso_year();
  } else if (IsJSTemporalPlainDateTime(*temporal_date_like)) {
    year = Cast<JSTemporalPlainDateTime>(temporal_date_like)->iso_year();
  } else {
    DCHECK(IsJSTemporalPlainYearMonth(*temporal_date_like));
    year = Cast<JSTemporalPlainYearMonth>(temporal_date_like)->iso_year();
  }
  int32_t days_in_year = ISODaysInYear(isolate, year);
  // 6. Return 𝔽(daysInYear).
  return handle(Smi::FromInt(days_in_year), isolate);
}

// #sec-temporal.calendar.prototype.daysinmonth
MaybeHandle<Smi> JSTemporalCalendar::DaysInMonth(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1 Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]], [[InitializedTemporalDateTime]] or
  // [[InitializedTemporalYearMonth]] internal slot, then
  if (!IsPlainDatePlainDateTimeOrPlainYearMonth(temporal_date_like)) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.daysInMonth"));
  }

  // 5. Return 𝔽(! ISODaysInMonth(temporalDateLike.[[ISOYear]],
  // temporalDateLike.[[ISOMonth]])).
  int32_t year;
  int32_t month;
  if (IsJSTemporalPlainDate(*temporal_date_like)) {
    year = Cast<JSTemporalPlainDate>(temporal_date_like)->iso_year();
    month = Cast<JSTemporalPlainDate>(temporal_date_like)->iso_month();
  } else if (IsJSTemporalPlainDateTime(*temporal_date_like)) {
    year = Cast<JSTemporalPlainDateTime>(temporal_date_like)->iso_year();
    month = Cast<JSTemporalPlainDateTime>(temporal_date_like)->iso_month();
  } else {
    DCHECK(IsJSTemporalPlainYearMonth(*temporal_date_like));
    year = Cast<JSTemporalPlainYearMonth>(temporal_date_like)->iso_year();
    month = Cast<JSTemporalPlainYearMonth>(temporal_date_like)->iso_month();
  }
  return handle(Smi::FromInt(ISODaysInMonth(isolate, year, month)), isolate);
}

// #sec-temporal.calendar.prototype.year
MaybeHandle<Smi> JSTemporalCalendar::Year(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]], [[InitializedTemporalDateTime]],
  // or [[InitializedTemporalYearMonth]]
  // internal slot, then
  if (!IsPlainDatePlainDateTimeOrPlainYearMonth(temporal_date_like)) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.year"));
  }

  // a. Let year be ! ISOYear(temporalDateLike).
  int32_t year;
  if (IsJSTemporalPlainDate(*temporal_date_like)) {
    year = Cast<JSTemporalPlainDate>(temporal_date_like)->iso_year();
  } else if (IsJSTemporalPlainDateTime(*temporal_date_like)) {
    year = Cast<JSTemporalPlainDateTime>(temporal_date_like)->iso_year();
  } else {
    DCHECK(IsJSTemporalPlainYearMonth(*temporal_date_like));
    year = Cast<JSTemporalPlainYearMonth>(temporal_date_like)->iso_year();
  }

  // 6. Return 𝔽(year).
  return handle(Smi::FromInt(year), isolate);
}

// #sec-temporal.calendar.prototype.dayofyear
MaybeHandle<Smi> JSTemporalCalendar::DayOfYear(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. Let temporalDate be ? ToTemporalDate(temporalDateLike).
  Handle<JSTemporalPlainDate> temporal_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date,
      ToTemporalDate(isolate, temporal_date_like,
                     "Temporal.Calendar.prototype.dayOfYear"));
  // a. Let value be ! ToISODayOfYear(temporalDate.[[ISOYear]],
  // temporalDate.[[ISOMonth]], temporalDate.[[ISODay]]).
  int32_t value = ToISODayOfYear(
      isolate, {temporal_date->iso_year(), temporal_date->iso_month(),
                temporal_date->iso_day()});
  return handle(Smi::FromInt(value), isolate);
}

// #sec-temporal.calendar.prototype.dayofweek
MaybeHandle<Smi> JSTemporalCalendar::DayOfWeek(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. Let temporalDate be ? ToTemporalDate(temporalDateLike).
  Handle<JSTemporalPlainDate> temporal_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date,
      ToTemporalDate(isolate, temporal_date_like,
                     "Temporal.Calendar.prototype.dayOfWeek"));
  // a. Let value be ! ToISODayOfWeek(temporalDate.[[ISOYear]],
  // temporalDate.[[ISOMonth]], temporalDate.[[ISODay]]).
  int32_t value = ToISODayOfWeek(
      isolate, {temporal_date->iso_year(), temporal_date->iso_month(),
                temporal_date->iso_day()});
  return handle(Smi::FromInt(value), isolate);
}

// #sec-temporal.calendar.prototype.monthsinyear
MaybeHandle<Smi> JSTemporalCalendar::MonthsInYear(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]], [[InitializedTemporalDateTime]], or
  // [[InitializedTemporalYearMonth]] internal slot, then
  if (!IsPlainDatePlainDateTimeOrPlainYearMonth(temporal_date_like)) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.monthsInYear"));
  }

  // a. a. Let monthsInYear be 12.
  int32_t months_in_year = 12;
  // 6. Return 𝔽(monthsInYear).
  return handle(Smi::FromInt(months_in_year), isolate);
}

// #sec-temporal.calendar.prototype.inleapyear
MaybeHandle<Oddball> JSTemporalCalendar::InLeapYear(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]], [[InitializedTemporalDateTime]], or
  // [[InitializedTemporalYearMonth]] internal slot, then
  if (!IsPlainDatePlainDateTimeOrPlainYearMonth(temporal_date_like)) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.inLeapYear"));
  }

  // a. Let inLeapYear be ! IsISOLeapYear(temporalDateLike.[[ISOYear]]).
  int32_t year;
  if (IsJSTemporalPlainDate(*temporal_date_like)) {
    year = Cast<JSTemporalPlainDate>(temporal_date_like)->iso_year();
  } else if (IsJSTemporalPlainDateTime(*temporal_date_like)) {
    year = Cast<JSTemporalPlainDateTime>(temporal_date_like)->iso_year();
  } else {
    DCHECK(IsJSTemporalPlainYearMonth(*temporal_date_like));
    year = Cast<JSTemporalPlainYearMonth>(temporal_date_like)->iso_year();
  }
  return isolate->factory()->ToBoolean(IsISOLeapYear(isolate, year));
}

// #sec-temporal.calendar.prototype.daysinweek
MaybeHandle<Smi> JSTemporalCalendar::DaysInWeek(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. Perform ? ToTemporalDate(temporalDateLike).
  Handle<JSTemporalPlainDate> date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date,
      ToTemporalDate(isolate, temporal_date_like,
                     "Temporal.Calendar.prototype.daysInWeek"));
  // 5. Return 7𝔽.
  return handle(Smi::FromInt(7), isolate);
}

// #sec-temporal.calendar.prototype.datefromfields
MaybeHandle<JSTemporalPlainDate> JSTemporalCalendar::DateFromFields(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> fields_obj, Handle<Object> options_obj) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. If Type(fields) is not Object, throw a TypeError exception.
  const char* method_name = "Temporal.Calendar.prototype.dateFromFields";
  if (!IsJSReceiver(*fields_obj)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kCalledOnNonObject,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }
  Handle<JSReceiver> fields = Cast<JSReceiver>(fields_obj);

  // 5. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  if (calendar->calendar_index() == 0) {
    // 6. Let result be ? ISODateFromFields(fields, options).
    DateRecord result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        ISODateFromFields(isolate, fields, options, method_name),
        Handle<JSTemporalPlainDate>());
    // 7. Return ? CreateTemporalDate(result.[[Year]], result.[[Month]],
    // result.[[Day]], calendar).
    return CreateTemporalDate(isolate, result, calendar);
  }
  // TODO(ftang) add intl implementation inside #ifdef V8_INTL_SUPPORT
  UNREACHABLE();
}

// #sec-temporal.calendar.prototype.mergefields
MaybeHandle<JSReceiver> JSTemporalCalendar::MergeFields(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> fields_obj, Handle<Object> additional_fields_obj) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. Set fields to ? ToObject(fields).
  Handle<JSReceiver> fields;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, fields,
                             Object::ToObject(isolate, fields_obj));

  // 5. Set additionalFields to ? ToObject(additionalFields).
  Handle<JSReceiver> additional_fields;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, additional_fields,
                             Object::ToObject(isolate, additional_fields_obj));
  // 5. If calendar.[[Identifier]] is "iso8601", then
  if (calendar->calendar_index() == 0) {
    // a. Return ? DefaultMergeFields(fields, additionalFields).
    return DefaultMergeFields(isolate, fields, additional_fields);
  }
#ifdef V8_INTL_SUPPORT
  // TODO(ftang) add Intl code.
#endif  // V8_INTL_SUPPORT
  UNREACHABLE();
}

// #sec-temporal.calendar.prototype.dateuntil
MaybeHandle<JSTemporalDuration> JSTemporalCalendar::DateUntil(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> one_obj, Handle<Object> two_obj,
    Handle<Object> options_obj) {
  const char* method_name = "Temporal.Calendar.prototype.dateUntil";
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. Set one to ? ToTemporalDate(one).
  Handle<JSTemporalPlainDate> one;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, one,
                             ToTemporalDate(isolate, one_ob
```