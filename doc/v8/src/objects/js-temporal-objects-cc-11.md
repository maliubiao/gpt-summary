Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/objects/js-temporal-objects.cc`. They have several specific questions about its nature and purpose, including:

1. **General functionality:** What does this code do?
2. **Torque source:** If the filename ended in `.tq`, it would be a Torque file. This is not the case here.
3. **JavaScript relationship:** If it's related to JavaScript, show an example.
4. **Code logic:**  Provide input and output examples for the logic.
5. **Common errors:**  Point out potential programmer mistakes.
6. **Summary:**  Provide a concise overview of the code's function.

Let's break down the code snippet to answer these questions.

**Code Analysis:**

The code defines several functions related to the `Temporal` API in JavaScript, specifically focusing on:

* **`DefaultTemporalLargestUnit`:** Determines the largest non-zero unit in a `DurationRecord`.
* **`DifferenceZonedDateTime`:** Calculates the difference between two `ZonedDateTime` instances, returning a `DurationRecord`. This involves converting to instants, getting plain date-times, calculating date differences, adjusting for time zones, and balancing the duration.
* **`AddDuration`:** Adds two `DurationRecord` instances, optionally with a `relative_to` object (either `PlainDate` or `ZonedDateTime`) for calendar-aware addition.
* **`AddDurationToOrSubtractDurationFromDuration`:**  A helper function to add or subtract durations, handling the sign.
* **`JSTemporalDuration::Add` and `JSTemporalDuration::Subtract`:**  Implement the `add` and `subtract` methods on `Temporal.Duration.prototype`.
* **`JSTemporalDuration::ToJSON` and `JSTemporalDuration::ToLocaleString`:** Implement methods to serialize the duration to JSON and a locale-specific string.
* **`MoveRelativeZonedDateTime`:**  Moves a `ZonedDateTime` by a given date duration.
* **`DaysUntil`:** Calculates the number of days between two `PlainDate` instances.
* **`MoveRelativeDate`:**  Moves a `PlainDate` by a duration, returning the new date and the number of days moved.
* **`RoundDuration`:** Rounds a duration to a specified unit, considering a relative date or zoned date-time if necessary.

**Answering the User's Questions:**

1. **Functionality:** The code implements core logic for the JavaScript `Temporal.Duration` object, including calculating differences between zoned date-times, adding and subtracting durations (with and without relative context), and rounding durations.

2. **Torque Source:** The prompt correctly identifies that the file does not end in `.tq`, so it's **not** a Torque source file. It's standard C++ code within the V8 project.

3. **JavaScript Relationship:**  The code directly implements functionality exposed in the JavaScript `Temporal` API.

4. **Code Logic (with examples):**

   * **`DefaultTemporalLargestUnit`:**
     * **Input:** `DurationRecord{ years: 1, months: 0, weeks: 0, days: 0, hours: 0, minutes: 0, seconds: 0, milliseconds: 0, microseconds: 0, nanoseconds: 0 }`
     * **Output:** `Unit::kYear`
     * **Input:** `DurationRecord{ years: 0, months: 0, weeks: 0, days: 0, hours: 0, minutes: 30, seconds: 0, milliseconds: 0, microseconds: 0, nanoseconds: 0 }`
     * **Output:** `Unit::kMinute`

   * **`DifferenceZonedDateTime`:**
     * **Assumption:** We have two `Temporal.ZonedDateTime` instances in JavaScript.
     * **JavaScript Input (Conceptual):**
       ```javascript
       const zdt1 = Temporal.ZonedDateTime.from('2024-03-15T10:00:00-08:00[America/Los_Angeles]');
       const zdt2 = Temporal.ZonedDateTime.from('2024-03-16T12:30:00-07:00[America/Los_Angeles]');
       ```
     * **C++ Input (Hypothetical):**  This would involve the internal representation of `zdt1` and `zdt2` as `BigInt` nanoseconds and timezone/calendar objects.
     * **Output (Conceptual `DurationRecord`):**  Likely something like `{ days: 1, hours: 2, minutes: 30, ... }`  The exact output depends on the `largestUnit` and options passed.

   * **`AddDuration` (without `relative_to`):**
     * **Input `dur1`:** `{ years: 0, months: 0, weeks: 0, days: 1, hours: 2, minutes: 0, seconds: 0, milliseconds: 0, microseconds: 0, nanoseconds: 0 }`
     * **Input `dur2`:** `{ years: 0, months: 0, weeks: 0, days: 0, hours: 3, minutes: 30, seconds: 0, milliseconds: 0, microseconds: 0, nanoseconds: 0 }`
     * **Output:** `{ years: 0, months: 0, weeks: 0, days: 1, hours: 5, minutes: 30, seconds: 0, milliseconds: 0, microseconds: 0, nanoseconds: 0 }`

   * **`AddDuration` (with `relative_to` as `PlainDate`):**
     * **Input `dur1`:** `{ years: 1, months: 0, weeks: 0, days: 0, ... }`
     * **Input `dur2`:** `{ years: 0, months: 1, weeks: 0, days: 0, ... }`
     * **Input `relative_to` (Conceptual):** `Temporal.PlainDate.from('2023-01-15')`
     * **Output:** The function will use the calendar's `dateAdd` method to handle year and month arithmetic, so the result depends on the calendar's rules.

5. **Common Programming Errors:**

   * **Using `AddDuration` with year/month/week units without a `relative_to`:**  The code explicitly throws a `RangeError` in this scenario because adding years or months without a context (a specific date) is ambiguous (e.g., adding one month to January 31st).
     * **JavaScript Example:**
       ```javascript
       const dur1 = new Temporal.Duration(1, 0, 0);
       const dur2 = new Temporal.Duration(0, 1, 0);
       // This will throw an error:
       dur1.add(dur2);
       ```
     * **Correct Usage:**
       ```javascript
       const dur1 = new Temporal.Duration(1, 0, 0);
       const dur2 = new Temporal.Duration(0, 1, 0);
       const date = Temporal.PlainDate.from('2023-01-15');
       dur1.add(dur2, { relativeTo: date });
       ```

   * **Assuming consistent day lengths in `DifferenceZonedDateTime`:** The code needs to account for daylight saving time changes and varying day lengths when calculating differences across time zones. Failing to use the correct time zone information will lead to incorrect duration calculations.

6. **Summary of Functionality:** This code snippet is a part of the V8 JavaScript engine that implements the core arithmetic and difference calculations for `Temporal.Duration` objects. It handles adding, subtracting, and comparing durations, taking into account calendar systems and time zones when necessary, especially for operations involving larger units like years, months, and weeks. It ensures that these operations are context-aware to avoid ambiguity.

This detailed breakdown should provide a good understanding of the functionality of the given code.
This section of the V8 source code (`v8/src/objects/js-temporal-objects.cc`) focuses on implementing core functionalities for the JavaScript `Temporal` API, specifically related to the `Temporal.Duration` object and calculations involving `Temporal.ZonedDateTime`.

Here's a breakdown of its functions:

**Key Functionalities:**

* **`DefaultTemporalLargestUnit(DurationRecord dur)`:** Determines the largest non-zero unit present in a `DurationRecord` (e.g., if a duration has years and days, the largest unit is "year"). This is used internally to determine the appropriate unit for balancing durations.
* **`DifferenceZonedDateTime(Isolate*, Handle<BigInt> ns1, Handle<BigInt> ns2, Handle<JSReceiver> time_zone, Handle<JSReceiver> calendar, Unit largest_unit, Handle<JSReceiver> options, const char* method_name)`:** Calculates the difference between two `Temporal.ZonedDateTime` instances represented by their nanosecond values (`ns1`, `ns2`). It takes into account the time zone and calendar, and the desired largest unit for the resulting duration. The process involves:
    * Converting nanoseconds to `Temporal.Instant` objects.
    * Getting the corresponding `Temporal.PlainDateTime` for each instant in the given time zone and calendar.
    * Calculating the date difference using `DifferenceISODateTime`.
    * Adding the date difference back to the start time to get an intermediate point.
    * Calculating the remaining time difference in nanoseconds.
    * Converting the remaining nanoseconds to days using `NanosecondsToDays`.
    * Balancing the time difference to get hours, minutes, seconds, etc.
    * Combining the date difference and time difference into the final `DurationRecord`.
* **`AddDuration(Isolate*, const DurationRecord& dur1, const DurationRecord& dur2, Handle<Object> relative_to_obj, const char* method_name)`:** Adds two `DurationRecord` objects. It handles cases with and without a `relative_to` object:
    * **Without `relative_to`:** If the largest unit is year, month, or week, it throws an error because the addition is ambiguous without a reference point. Otherwise, it simply adds the corresponding time components and balances the result.
    * **With `relative_to` (as `Temporal.PlainDate`):** It uses the calendar's `dateAdd` method to add the date components of the durations to the `relative_to` date. Then, it calculates the difference between the initial and final dates. The time components of the durations are added separately and balanced.
    * **With `relative_to` (as `Temporal.ZonedDateTime`):** It adds the durations to the `relative_to` zoned date-time using `AddZonedDateTime`. If the largest unit is smaller than "day", it calculates the difference in nanoseconds. Otherwise, it uses `DifferenceZonedDateTime` to calculate the difference.
* **`AddDurationToOrSubtractDurationFromDuration(Isolate*, Arithmetic operation, DirectHandle<JSTemporalDuration> duration, Handle<Object> other_obj, Handle<Object> options_obj, const char* method_name)`:** A helper function for implementing both `add` and `subtract` on `Temporal.Duration` objects. It handles the sign based on the `operation`. It converts the `other_obj` to a `DurationRecord`, gets the `relative_to` object from options, and then calls `AddDuration`.
* **`JSTemporalDuration::Add(...)` and `JSTemporalDuration::Subtract(...)`:** Implement the `add` and `subtract` methods on the `Temporal.Duration.prototype` in JavaScript, calling `AddDurationToOrSubtractDurationFromDuration`.
* **`JSTemporalDuration::ToJSON(...)`:**  Implements the `toJSON` method for `Temporal.Duration`, returning the ISO 8601 string representation of the duration.
* **`JSTemporalDuration::ToLocaleString(...)`:** Implements the `toLocaleString` method (currently returns the same as `toJSON`).
* **`MoveRelativeZonedDateTime(...)`:** Moves a `Temporal.ZonedDateTime` by a given date duration (years, months, weeks, days).
* **`DaysUntil(...)`:** Calculates the number of days between two `Temporal.PlainDate` objects.
* **`MoveRelativeDate(...)`:** Moves a `Temporal.PlainDate` by a `Temporal.Duration` using the calendar's `dateAdd` method and calculates the number of days moved.
* **`RoundDuration(...)`:** Rounds a `DurationRecord` to a specified unit. It handles different units and the presence of a `relative_to` object for calendar-aware rounding.

**If `v8/src/objects/js-temporal-objects.cc` ended with `.tq`:**

It would be a **v8 Torque source code** file. Torque is a domain-specific language used within V8 for writing performance-critical runtime functions. It provides a way to write code that is more tightly integrated with V8's internal data structures and avoids some of the overhead of the standard C++ compiler.

**Relationship with JavaScript:**

This code directly implements functionalities exposed in the JavaScript `Temporal` API. Here are some examples:

```javascript
// JavaScript examples demonstrating the C++ code's functionality

// 1. Temporal.Duration.prototype.add
const duration1 = new Temporal.Duration(1, 2, 0, 5); // 1 year, 2 months, 5 days
const duration2 = new Temporal.Duration(0, 1, 1, 2); // 1 month, 1 week, 2 days
const relativeToDate = Temporal.PlainDate.from('2023-01-15');
const sum = duration1.add(duration2, { relativeTo: relativeToDate });
console.log(sum.toString()); // Output will vary based on calendar rules

const duration3 = new Temporal.Duration(5, 0, 0);
// const invalidSum = duration1.add(duration3); // This would throw an error in JavaScript

// 2. Temporal.Duration.prototype.subtract
const difference = duration1.subtract(duration2, { relativeTo: relativeToDate });
console.log(difference.toString());

// 3. Temporal.Duration.prototype.toJSON
const jsonRepresentation = duration1.toJSON();
console.log(jsonRepresentation); // Output: "P1Y2M5D"

// 4. Calculating the difference between two ZonedDateTimes
const zdt1 = Temporal.ZonedDateTime.from('2023-10-26T10:00:00-08:00[America/Los_Angeles]');
const zdt2 = Temporal.ZonedDateTime.from('2023-10-27T12:30:00-07:00[America/Los_Angeles]');
const diff = zdt1.since(zdt2); // Internally uses DifferenceZonedDateTime
console.log(diff.toString());
```

**Code Logic Reasoning (Hypothetical):**

**Scenario:** Calculating the difference between two `ZonedDateTime` instances where the difference spans across a daylight saving time transition.

**Assumed Input:**

* `ns1`: Nanosecond representation of `2023-03-11T01:00:00-08:00[America/Los_Angeles]` (before DST)
* `ns2`: Nanosecond representation of `2023-03-12T01:00:00-07:00[America/Los_Angeles]` (after DST)
* `time_zone`:  Object representing the "America/Los_Angeles" time zone.
* `calendar`:  Object representing the default ISO 8601 calendar.
* `largest_unit`: "day"

**Expected Output:**

A `DurationRecord` representing a difference of 1 day. The key here is that even though the clock time is the same (1:00 AM), there are 25 hours between these two instants due to the DST transition. The `DifferenceZonedDateTime` function would correctly handle this by:

1. Converting `ns1` and `ns2` to `Temporal.Instant`.
2. Getting the `PlainDateTime` for each instant.
3. Calculating the date difference (which would be 1 day).
4. Calculating the remaining time difference, which would account for the hour gained due to DST.
5. Combining these to produce a duration of 1 day.

**User Common Programming Errors:**

* **Adding or subtracting durations with year/month/week units without a `relativeTo`:**  This is a common mistake because the result is ambiguous. For example, adding one month to January 31st is not clearly defined without knowing the target date's context.
    ```javascript
    const dur1 = new Temporal.Duration(1, 0, 0);
    const dur2 = new Temporal.Duration(0, 1, 0);
    // Error: Cannot add/subtract year/month/week without relativeTo
    // const sum = dur1.add(dur2);
    ```
* **Incorrectly assuming consistent day lengths when calculating differences across time zones:** When working with `ZonedDateTime`, the duration between two points might not be what you intuitively expect based on clock times due to DST or other time zone rule changes. Relying solely on the difference in clock hours can be misleading.
* **Forgetting to specify a `relativeTo` when rounding durations involving year, month, or week:** Similar to addition/subtraction, rounding these larger units requires context.

**归纳一下它的功能 (Summary of its Functionality):**

This part of the V8 source code implements the core logic for the JavaScript `Temporal.Duration` object and related `Temporal.ZonedDateTime` calculations. It provides the functionality to:

* Determine the largest unit in a duration.
* Calculate the difference between two zoned date-time instances, considering time zones and calendar rules.
* Add and subtract durations, both with simple time unit additions and with calendar-aware calculations using a relative date or zoned date-time.
* Implement the `add`, `subtract`, `toJSON`, and `toLocaleString` methods for `Temporal.Duration`.
* Move a zoned date-time by a duration.
* Calculate the number of days between two plain dates.
* Round durations to specific units, potentially using a relative date or zoned date-time for context.

Essentially, it's a crucial piece of the V8 engine that makes the `Temporal.Duration` object functional and accurate according to the ECMAScript Temporal specification.

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第12部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
rs != 0) return Unit::kYear;
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