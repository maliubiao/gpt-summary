Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/objects/js-temporal-objects.cc`.
The code seems to implement parts of the ECMAScript Temporal API, specifically related to date calculations and manipulations within the ISO 8601 calendar.

Here's a breakdown of the thought process to analyze the code:

1. **Identify the file and its potential role:** The file path `v8/src/objects/js-temporal-objects.cc` suggests this code defines the behavior of JavaScript Temporal objects within the V8 engine. The `.cc` extension confirms it's C++ source code.

2. **Check for Torque:** The prompt asks about `.tq` files. This file is `.cc`, so it's not Torque. This means the logic is implemented directly in C++.

3. **Look for JavaScript relationships:** The presence of functions like `ToTemporalDate`, `CreateTemporalDate`, and method names like `Temporal.Calendar.prototype.dateAdd` strongly indicates a connection to the JavaScript Temporal API. The code directly implements the underlying logic for these JavaScript features.

4. **Analyze individual functions:** Go through each function in the snippet and try to understand its purpose based on its name and the operations it performs.

    * **`ISODateFromFields`:** This function seems to take an object containing date fields (year, month, day) and options, and then constructs a valid ISO date record. It uses helper functions like `PrepareTemporalFields`, `ToTemporalOverflow`, and `RegulateISODate`.

    * **`AddISODate`:** This function adds a date duration to a given date. It handles balancing of months and years and uses `RegulateISODate` to ensure the resulting date is valid.

    * **`DifferenceISODate`:**  This function calculates the difference between two dates in terms of years, months, weeks, or days. It uses `CompareISODate` to compare dates and `AddISODate` for intermediate calculations. The logic varies depending on the `largest_unit` specified.

    * **`ISOYearMonthFromFields`:** This function seems similar to `ISODateFromFields` but focuses on year and month, potentially used for `Temporal.PlainYearMonth`.

    * **`ToISOWeekOfYear`:**  This function calculates the ISO week number for a given date. It involves calculations based on the day of the year and the day of the week.

    * **`JSTemporalCalendar::DateAdd`:** This is a method on the `JSTemporalCalendar` class and implements the `dateAdd` functionality of the `Temporal.Calendar` prototype. It calls `AddISODate` internally for the ISO calendar.

    * **`JSTemporalCalendar::DaysInYear`:**  This method returns the number of days in the year for a given date.

    * **`JSTemporalCalendar::DaysInMonth`:** This method returns the number of days in the month for a given date.

    * **`JSTemporalCalendar::Year`:** This method extracts the year from a Temporal object.

    * **`JSTemporalCalendar::DayOfYear`:** This method returns the day of the year for a given date.

    * **`JSTemporalCalendar::DayOfWeek`:** This method returns the day of the week for a given date.

    * **`JSTemporalCalendar::MonthsInYear`:** This method returns the number of months in a year (always 12 for ISO).

    * **`JSTemporalCalendar::InLeapYear`:** This method checks if a given date falls within a leap year.

    * **`JSTemporalCalendar::DaysInWeek`:** This method returns the number of days in a week (always 7).

    * **`JSTemporalCalendar::DateFromFields`:**  This method on `JSTemporalCalendar` is a wrapper around `ISODateFromFields`.

    * **`JSTemporalCalendar::MergeFields`:** This method merges fields from two objects.

    * **`JSTemporalCalendar::DateUntil`:** This method calculates the duration between two dates.

5. **Identify common patterns and helper functions:** Notice the repeated use of functions like `PrepareTemporalFields`, `ToTemporalOverflow`, `RegulateISODate`, `BalanceISOYearMonth`, `CompareISODate`, `ToISODayOfYear`, `ToISODayOfWeek`, and `ISODaysInMonth`. These are likely utility functions for handling date calculations and validation.

6. **Infer functionality and purpose:** Based on the function names and the operations they perform, deduce the overall functionality of the code. It's responsible for implementing core date manipulation logic for the Temporal API in V8.

7. **Construct JavaScript examples:**  For functions related to JavaScript, create simple JavaScript code snippets that demonstrate their usage and how they relate to the C++ code.

8. **Consider code logic and assumptions:** For functions with more complex logic like `DifferenceISODate`, try to reason about potential inputs and outputs to understand the flow.

9. **Think about potential user errors:** Consider common mistakes developers might make when working with dates and how the code might handle or prevent those errors.

10. **Summarize the functionality:**  Combine the understanding of individual functions and the overall purpose to create a concise summary of the code's role. Emphasize its connection to the JavaScript Temporal API and its responsibility for date calculations within the ISO 8601 calendar.

By following these steps, we can effectively analyze the provided C++ code snippet and provide a comprehensive explanation of its functionality.```c++
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
    month = Cast<JSTemporalPlainYear
Prompt: 
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第14部分，共25部分，请归纳一下它的功能

"""
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
"""


```