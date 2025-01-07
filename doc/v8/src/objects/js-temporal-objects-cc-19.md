Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/js-temporal-objects.cc`. I need to identify the key operations and data structures involved.

Here's a breakdown of the code's content:

1. **`AddDurationToOrSubtractDurationFromPlainYearMonth`**:  This function handles adding or subtracting durations from `JSTemporalPlainYearMonth` objects. It involves calendar operations and duration calculations.
2. **`JSTemporalPlainYearMonth::Add` and `JSTemporalPlainYearMonth::Subtract`**: These are methods on `JSTemporalPlainYearMonth` that call the above function for addition and subtraction respectively.
3. **`DifferenceTemporalPlainYearMonth`**: This function calculates the difference between two `JSTemporalPlainYearMonth` objects, resulting in a `JSTemporalDuration`. It also handles rounding.
4. **`JSTemporalPlainYearMonth::Until` and `JSTemporalPlainYearMonth::Since`**: These methods on `JSTemporalPlainYearMonth` use the `DifferenceTemporalPlainYearMonth` function to find the duration until or since another `JSTemporalPlainYearMonth`.
5. **`JSTemporalPlainYearMonth::With`**: This method allows modification of a `JSTemporalPlainYearMonth` object with new values.
6. **`JSTemporalPlainYearMonth::ToPlainDate`**: This method converts a `JSTemporalPlainYearMonth` to a `JSTemporalPlainDate`, requiring a 'day' value.
7. **`JSTemporalPlainYearMonth::GetISOFields`**: This method extracts the ISO year, month, and day components of a `JSTemporalPlainYearMonth`.
8. **`JSTemporalPlainYearMonth::ToJSON`**:  This method likely converts the `JSTemporalPlainYearMonth` to a JSON string representation.
9. **`JSTemporalPlainYearMonth::ToString`**:  This method converts the `JSTemporalPlainYearMonth` to a string representation, potentially with formatting options.
10. **`JSTemporalPlainYearMonth::ToLocaleString`**: This method converts the `JSTemporalPlainYearMonth` to a locale-sensitive string representation.
11. **`JSTemporalPlainTime::Constructor`**: This is the constructor for `JSTemporalPlainTime` objects.
12. **`JSTemporalPlainTime::ToZonedDateTime`**: This method converts a `JSTemporalPlainTime` to a `JSTemporalZonedDateTime`, requiring date and timezone information.
13. **`CompareTemporalTime`**: This is a helper function to compare two `TimeRecord` structures.
14. **`JSTemporalPlainTime::Compare`**: This method compares two `JSTemporalPlainTime` objects.
15. **`JSTemporalPlainTime::Equals`**: This method checks if two `JSTemporalPlainTime` objects are equal.
16. **`MaximumTemporalDurationRoundingIncrement`**: This helper function determines the maximum valid rounding increment for a given time unit.
17. **`JSTemporalPlainTime::Round`**: This method rounds a `JSTemporalPlainTime` to a specified unit.
18. **`JSTemporalPlainTime::With`**: This method allows modification of a `JSTemporalPlainTime` object.
19. **`JSTemporalPlainTime::NowISO`**: This method gets the current time in the ISO calendar system.
20. **`JSTemporalPlainTime::From`**: This method creates a `JSTemporalPlainTime` from various input types.

The code heavily interacts with the `Temporal` API in JavaScript, specifically dealing with `PlainYearMonth` and `PlainTime` objects. It performs calendar calculations, duration arithmetic, comparisons, and conversions.

Given the prompt's constraints, I need to:

*   List the functionalities.
*   Confirm it's C++ source (it is).
*   Provide JavaScript examples if related to JavaScript functionality.
*   Give example inputs and outputs for code logic.
*   Illustrate common programming errors.
*   Summarize the overall functionality as part 20/25.
This C++ source code file, `v8/src/objects/js-temporal-objects.cc`, is part of the V8 JavaScript engine and implements the functionality for several `Temporal` API objects in JavaScript. Here's a breakdown of its functions:

**Core Functionalities Implemented:**

1. **`AddDurationToOrSubtractDurationFromPlainYearMonth`**: This function is a core logic block for adding or subtracting a `Temporal.Duration` from a `Temporal.PlainYearMonth`. It handles calendar adjustments and potential errors.

2. **`JSTemporalPlainYearMonth::Add` and `JSTemporalPlainYearMonth::Subtract`**: These methods implement the `add()` and `subtract()` functionality of the `Temporal.PlainYearMonth.prototype`. They take a `Temporal.Duration`-like object and options as input and return a new `Temporal.PlainYearMonth`.

3. **`DifferenceTemporalPlainYearMonth`**: This function calculates the difference between two `Temporal.PlainYearMonth` objects, resulting in a `Temporal.Duration`. It considers options like the largest and smallest units for the difference.

4. **`JSTemporalPlainYearMonth::Until` and `JSTemporalPlainYearMonth::Since`**: These methods implement the `until()` and `since()` functionality of the `Temporal.PlainYearMonth.prototype`. They use `DifferenceTemporalPlainYearMonth` to calculate the duration between two year-month values.

5. **`JSTemporalPlainYearMonth::With`**: This method implements the `with()` functionality of `Temporal.PlainYearMonth.prototype`, allowing you to create a new `Temporal.PlainYearMonth` object by changing specific fields (year, month).

6. **`JSTemporalPlainYearMonth::ToPlainDate`**: This method implements the `toPlainDate()` functionality of `Temporal.PlainYearMonth.prototype`. It combines the year and month with a provided day to create a `Temporal.PlainDate`.

7. **`JSTemporalPlainYearMonth::GetISOFields`**: This method implements `getISOFields()`, returning an object with the ISO year, month, and day of the `Temporal.PlainYearMonth`.

8. **`JSTemporalPlainYearMonth::ToJSON`**: This method implements the `toJSON()` functionality, converting the `Temporal.PlainYearMonth` to its canonical string representation.

9. **`JSTemporalPlainYearMonth::ToString`**: This method implements the `toString()` functionality, allowing for customization of the string representation through options.

10. **`JSTemporalPlainYearMonth::ToLocaleString`**: This method implements `toLocaleString()`, providing a localized string representation of the `Temporal.PlainYearMonth`.

11. **`JSTemporalPlainTime::Constructor`**: This function is the constructor for `Temporal.PlainTime` objects, handling the creation of new instances.

12. **`JSTemporalPlainTime::ToZonedDateTime`**: This method implements `toZonedDateTime()`, converting a `Temporal.PlainTime` to a `Temporal.ZonedDateTime` by combining it with a `Temporal.PlainDate` and a `Temporal.TimeZone`.

13. **`CompareTemporalTime`**:  A helper function to compare two times based on their hour, minute, second, and fractional second components.

14. **`JSTemporalPlainTime::Compare`**: This method implements the static `compare()` method of `Temporal.PlainTime`, allowing comparison of two `Temporal.PlainTime` objects.

15. **`JSTemporalPlainTime::Equals`**: This method implements the `equals()` functionality of `Temporal.PlainTime.prototype`, checking if two `Temporal.PlainTime` objects represent the same time.

16. **`MaximumTemporalDurationRoundingIncrement`**: A utility function that determines the maximum valid rounding increment for a given time unit (e.g., you can't round hours to the nearest 30 hours).

17. **`JSTemporalPlainTime::Round`**: This method implements the `round()` functionality of `Temporal.PlainTime.prototype`, allowing you to round the time to a specified unit.

18. **`JSTemporalPlainTime::With`**: This method implements the `with()` functionality of `Temporal.PlainTime.prototype`, allowing you to create a new `Temporal.PlainTime` by changing specific time components.

19. **`JSTemporalPlainTime::NowISO`**: This method implements the static `now.plainTimeISO()` method, returning the current time in the ISO 8601 calendar system for a given timezone.

20. **`JSTemporalPlainTime::From`**: This method implements the static `from()` method of `Temporal.PlainTime`, creating a `Temporal.PlainTime` object from various input types.

**Is it Torque?**

The code provided is **C++**, not Torque. If the filename ended in `.tq`, it would indicate a Torque source file.

**Relationship to JavaScript Functionality (with Examples):**

Yes, this code directly implements the functionality of the `Temporal` API in JavaScript. Here are some JavaScript examples demonstrating the C++ code's effects:

```javascript
// Temporal.PlainYearMonth.prototype.add
const yearMonth = Temporal.PlainYearMonth.from('2023-10');
const duration = Temporal.Duration.from({ months: 2 });
const futureYearMonth = yearMonth.add(duration);
console.log(futureYearMonth.toString()); // Output: 2023-12

// Temporal.PlainYearMonth.prototype.subtract
const pastYearMonth = yearMonth.subtract(duration);
console.log(pastYearMonth.toString());  // Output: 2023-08

// Temporal.PlainYearMonth.prototype.until
const anotherYearMonth = Temporal.PlainYearMonth.from('2024-01');
const timeUntil = yearMonth.until(anotherYearMonth);
console.log(timeUntil.toString()); // Output: P3M

// Temporal.PlainYearMonth.prototype.since
const timeSince = yearMonth.since(pastYearMonth);
console.log(timeSince.toString()); // Output: P2M

// Temporal.PlainYearMonth.prototype.with
const updatedYearMonth = yearMonth.with({ month: 11 });
console.log(updatedYearMonth.toString()); // Output: 2023-11

// Temporal.PlainYearMonth.prototype.toPlainDate
const date = yearMonth.toPlainDate({ day: 15 });
console.log(date.toString()); // Output: 2023-10-15

// Temporal.PlainTime.prototype.toZonedDateTime
const time = new Temporal.PlainTime(10, 30, 0);
const dateForTime = Temporal.PlainDate.from('2023-10-27');
const timeZone = Temporal.TimeZone.from('America/Los_Angeles');
const zonedDateTime = time.toZonedDateTime({ plainDate: dateForTime, timeZone: timeZone });
console.log(zonedDateTime.toString());

// Temporal.PlainTime.compare
const time1 = new Temporal.PlainTime(10, 0, 0);
const time2 = new Temporal.PlainTime(11, 0, 0);
console.log(Temporal.PlainTime.compare(time1, time2)); // Output: -1

// Temporal.PlainTime.prototype.equals
const anotherTime = new Temporal.PlainTime(10, 30, 0);
console.log(time.equals(anotherTime)); // Output: true

// Temporal.PlainTime.prototype.round
const timeToRound = new Temporal.PlainTime(10, 30, 45);
const roundedTime = timeToRound.round({ smallestUnit: 'minute' });
console.log(roundedTime.toString()); // Output: 10:31:00

// Temporal.PlainTime.prototype.with
const newTime = time.with({ hour: 11 });
console.log(newTime.toString()); // Output: 11:30:00

// Temporal.Now.plainTimeISO
const nowTime = Temporal.Now.plainTimeISO('UTC');
console.log(nowTime.toString());

// Temporal.PlainTime.from
const timeFromString = Temporal.PlainTime.from('14:15:30');
console.log(timeFromString.toString());
```

**Code Logic Inference (with Example):**

Let's take the `AddDurationToOrSubtractDurationFromPlainYearMonth` function.

**Hypothetical Input:**

*   `year_month`: A `Temporal.PlainYearMonth` representing '2023-08'.
*   `temporal_duration_like`: A `Temporal.Duration` representing `{ months: 3 }`.
*   `Arithmetic::kAdd`:  Specifies addition.
*   `options`: An empty object `{}`.

**Expected Output:**

A new `Temporal.PlainYearMonth` representing '2023-11'.

**Reasoning:** The function would add 3 months to August 2023, resulting in November 2023. The underlying calendar logic handles the month rollover correctly.

**Common Programming Errors (related to this code):**

1. **Incorrect Duration Units:**  Providing a duration with incompatible units when adding or subtracting from a `PlainYearMonth`. For instance, trying to add days to a `PlainYearMonth` without considering the varying number of days in a month.

    ```javascript
    const yearMonth = Temporal.PlainYearMonth.from('2023-02');
    const duration = Temporal.Duration.from({ days: 30 });
    // This might lead to unexpected results or errors depending on the calendar
    const result = yearMonth.add(duration);
    ```

2. **Missing Required Fields for `toPlainDate`:** Not providing the `day` property when calling `toPlainDate()`.

    ```javascript
    const yearMonth = Temporal.PlainYearMonth.from('2023-10');
    // This will throw an error because 'day' is missing
    const date = yearMonth.toPlainDate({});
    ```

3. **Providing Invalid Time Zone or Date for `toZonedDateTime`:** When converting a `PlainTime` to a `ZonedDateTime`, the provided `plainDate` and `timeZone` must be valid.

    ```javascript
    const time = new Temporal.PlainTime(12, 0, 0);
    const invalidTimeZone = 'Invalid/TimeZone';
    // This will likely throw an error
    const zonedDateTime = time.toZonedDateTime({
      plainDate: Temporal.PlainDate.from('2023-10-27'),
      timeZone: invalidTimeZone
    });
    ```

4. **Incorrect Rounding Units:**  Trying to round to units that are not valid for `PlainTime` (e.g., rounding to 'month').

    ```javascript
    const time = new Temporal.PlainTime(10, 30, 0);
    // This will throw an error as 'month' is not a valid unit for PlainTime rounding
    const roundedTime = time.round({ smallestUnit: 'month' });
    ```

**归纳一下它的功能 (Summary of its Functionality):**

This section of the V8 source code (`v8/src/objects/js-temporal-objects.cc`) is responsible for implementing the core logic and behavior of the `Temporal.PlainYearMonth` and `Temporal.PlainTime` objects in JavaScript. It handles operations like:

*   Creating, manipulating (adding, subtracting), and comparing `PlainYearMonth` values.
*   Converting `PlainYearMonth` to other `Temporal` types like `PlainDate`.
*   Extracting ISO fields from `PlainYearMonth`.
*   Formatting `PlainYearMonth` for string and JSON representations.
*   Creating, manipulating (rounding, using `with`), and comparing `PlainTime` values.
*   Converting `PlainTime` to `ZonedDateTime`.
*   Getting the current `PlainTime`.

Essentially, this code provides the foundational C++ implementations that make the `Temporal.PlainYearMonth` and `Temporal.PlainTime` objects usable and functional within the V8 JavaScript engine. As the 20th part of a 25-part series, it focuses on these specific `Temporal` types, likely building upon or being followed by implementations for other `Temporal` objects.

Prompt: 
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第20部分，共25部分，请归纳一下它的功能

"""
nError))
            .FromJust());

  // 12. Let date be ? CalendarDateFromFields(calendar, fields).
  Handle<JSTemporalPlainDate> date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date,
      FromFields<JSTemporalPlainDate>(
          isolate, calendar, fields, isolate->factory()->undefined_value(),
          isolate->factory()->dateFromFields_string(),
          JS_TEMPORAL_PLAIN_DATE_TYPE));

  // 13. Let durationToAdd be ! CreateTemporalDuration(duration.[[Years]],
  // duration.[[Months]], duration.[[Weeks]], balanceResult.[[Days]], 0, 0, 0,
  // 0, 0, 0).
  Handle<JSTemporalDuration> duration_to_add =
      CreateTemporalDuration(isolate, {duration.years,
                                       duration.months,
                                       duration.weeks,
                                       {balance_result.days, 0, 0, 0, 0, 0, 0}})
          .ToHandleChecked();
  // 14. Let optionsCopy be OrdinaryObjectCreate(null).
  Handle<JSReceiver> options_copy =
      isolate->factory()->NewJSObjectWithNullProto();

  // 15. Let entries be ? EnumerableOwnPropertyNames(options, key+value).
  // 16. For each element nextEntry of entries, do
  // a. Perform ! CreateDataPropertyOrThrow(optionsCopy, nextEntry[0],
  // nextEntry[1]).
  bool set;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, set,
      JSReceiver::SetOrCopyDataProperties(
          isolate, options_copy, options,
          PropertiesEnumerationMode::kEnumerationOrder, {}, false),
      Handle<JSTemporalPlainYearMonth>());

  // 17. Let addedDate be ? CalendarDateAdd(calendar, date, durationToAdd,
  // options).
  Handle<JSTemporalPlainDate> added_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, added_date,
      CalendarDateAdd(isolate, calendar, date, duration_to_add, options));
  // 18. Let addedDateFields be ? PrepareTemporalFields(addedDate, fieldNames,
  // «»).
  Handle<JSReceiver> added_date_fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, added_date_fields,
      PrepareTemporalFields(isolate, added_date, field_names,
                            RequiredFields::kNone));
  // 19. Return ? CalendarYearMonthFromFields(calendar, addedDateFields,
  // optionsCopy).
  return FromFields<JSTemporalPlainYearMonth>(
      isolate, calendar, added_date_fields, options_copy,
      isolate->factory()->yearMonthFromFields_string(),
      JS_TEMPORAL_PLAIN_YEAR_MONTH_TYPE);
}

}  // namespace

// #sec-temporal.plainyearmonth.prototype.add
MaybeHandle<JSTemporalPlainYearMonth> JSTemporalPlainYearMonth::Add(
    Isolate* isolate, Handle<JSTemporalPlainYearMonth> year_month,
    Handle<Object> temporal_duration_like, Handle<Object> options) {
  return AddDurationToOrSubtractDurationFromPlainYearMonth(
      isolate, Arithmetic::kAdd, year_month, temporal_duration_like, options,
      "Temporal.PlainYearMonth.prototype.add");
}

// #sec-temporal.plainyearmonth.prototype.subtract
MaybeHandle<JSTemporalPlainYearMonth> JSTemporalPlainYearMonth::Subtract(
    Isolate* isolate, Handle<JSTemporalPlainYearMonth> year_month,
    Handle<Object> temporal_duration_like, Handle<Object> options) {
  return AddDurationToOrSubtractDurationFromPlainYearMonth(
      isolate, Arithmetic::kSubtract, year_month, temporal_duration_like,
      options, "Temporal.PlainYearMonth.prototype.subtract");
}

namespace {
// #sec-temporal-differencetemporalplandyearmonth
MaybeHandle<JSTemporalDuration> DifferenceTemporalPlainYearMonth(
    Isolate* isolate, TimePreposition operation,
    Handle<JSTemporalPlainYearMonth> year_month, Handle<Object> other_obj,
    Handle<Object> options, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. If operation is since, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == TimePreposition::kSince ? -1 : 1;
  // 2. Set other to ? ToTemporalDateTime(other).
  Handle<JSTemporalPlainYearMonth> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other, ToTemporalYearMonth(isolate, other_obj, method_name));
  // 3. Let calendar be yearMonth.[[Calendar]].
  Handle<JSReceiver> calendar(year_month->calendar(), isolate);

  // 4. If ? CalendarEquals(calendar, other.[[Calendar]]) is false, throw a
  // RangeError exception.
  bool calendar_equals;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar_equals,
      CalendarEqualsBool(isolate, calendar, handle(other->calendar(), isolate)),
      Handle<JSTemporalDuration>());
  if (!calendar_equals) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }

  // 5. Let settings be ? GetDifferenceSettings(operation, options, date, «
  // "week", "day" », "month", "year").
  DifferenceSettings settings;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, settings,
      GetDifferenceSettings(isolate, operation, options, UnitGroup::kDate,
                            DisallowedUnitsInDifferenceSettings::kWeekAndDay,
                            Unit::kMonth, Unit::kYear, method_name),
      Handle<JSTemporalDuration>());
  // 6. Let fieldNames be ? CalendarFields(calendar, « "monthCode", "year" »).
  Factory* factory = isolate->factory();
  Handle<FixedArray> field_names = MonthCodeYearInFixedArray(isolate);
  ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                             CalendarFields(isolate, calendar, field_names));

  // 7. Let otherFields be ? PrepareTemporalFields(other, fieldNames, «»).
  Handle<JSReceiver> other_fields;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, other_fields,
                             PrepareTemporalFields(isolate, other, field_names,
                                                   RequiredFields::kNone));
  // 8. Perform ! CreateDataPropertyOrThrow(otherFields, "day", 1𝔽).
  Handle<Object> one = handle(Smi::FromInt(1), isolate);
  CHECK(JSReceiver::CreateDataProperty(isolate, other_fields,
                                       factory->day_string(), one,
                                       Just(kThrowOnError))
            .FromJust());
  // 9. Let otherDate be ? CalendarDateFromFields(calendar, otherFields).
  //  DateFromFields(Isolate* isolate,
  Handle<JSTemporalPlainDate> other_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other_date,
      DateFromFields(isolate, calendar, other_fields,
                     isolate->factory()->undefined_value()));
  // 10. Let thisFields be ? PrepareTemporalFields(yearMonth, fieldNames, «»).
  Handle<JSReceiver> this_fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, this_fields,
      PrepareTemporalFields(isolate, year_month, field_names,
                            RequiredFields::kNone));
  // 11. Perform ! CreateDataPropertyOrThrow(thisFields, "day", 1𝔽).
  CHECK(JSReceiver::CreateDataProperty(isolate, this_fields,
                                       factory->day_string(), one,
                                       Just(kThrowOnError))
            .FromJust());
  // 12. Let thisDate be ? CalendarDateFromFields(calendar, thisFields).
  Handle<JSTemporalPlainDate> this_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, this_date,
      DateFromFields(isolate, calendar, this_fields,
                     isolate->factory()->undefined_value()));
  // 13. Let untilOptions be ? MergeLargestUnitOption(settings.[[Options]],
  // settings.[[LargestUnit]]).
  Handle<JSReceiver> until_options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, until_options,
      MergeLargestUnitOption(isolate, settings.options, settings.largest_unit));
  // 14. Let result be ? CalendarDateUntil(calendar, thisDate, otherDate,
  // untilOptions).
  Handle<JSTemporalDuration> result;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, result,
                             CalendarDateUntil(isolate, calendar, this_date,
                                               other_date, until_options));

  // 15. If settings.[[SmallestUnit]] is not "month" or
  // settings.[[RoundingIncrement]] ≠ 1, then
  if (settings.smallest_unit != Unit::kMonth ||
      settings.rounding_increment != 1) {
    // a. Set result to (? RoundDuration(result.[[Years]], result.[[Months]], 0,
    // 0, 0, 0, 0, 0, 0, 0, settings.[[RoundingIncrement]],
    // settings.[[SmallestUnit]], settings.[[RoundingMode]],
    // thisDate)).[[DurationRecord]].
    DurationRecordWithRemainder round_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, round_result,
        RoundDuration(isolate,
                      {Object::NumberValue(result->years()),
                       Object::NumberValue(result->months()),
                       0,
                       {0, 0, 0, 0, 0, 0, 0}},
                      settings.rounding_increment, settings.smallest_unit,
                      settings.rounding_mode, this_date, method_name),
        Handle<JSTemporalDuration>());
    // 16. Return ! CreateTemporalDuration(sign × result.[[Years]], sign ×
    // result.[[Months]], 0, 0, 0, 0, 0, 0, 0, 0).
    return CreateTemporalDuration(isolate, {round_result.record.years * sign,
                                            round_result.record.months * sign,
                                            0,
                                            {0, 0, 0, 0, 0, 0, 0}})
        .ToHandleChecked();
  }
  // 16. Return ! CreateTemporalDuration(sign × result.[[Years]], sign ×
  // result.[[Months]], 0, 0, 0, 0, 0, 0, 0, 0).
  return CreateTemporalDuration(isolate,
                                {Object::NumberValue(result->years()) * sign,
                                 Object::NumberValue(result->months()) * sign,
                                 0,
                                 {0, 0, 0, 0, 0, 0, 0}})
      .ToHandleChecked();
}

}  // namespace

// #sec-temporal.plainyearmonth.prototype.until
MaybeHandle<JSTemporalDuration> JSTemporalPlainYearMonth::Until(
    Isolate* isolate, Handle<JSTemporalPlainYearMonth> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalPlainYearMonth(
      isolate, TimePreposition::kUntil, handle, other, options,
      "Temporal.PlainYearMonth.prototype.until");
}

// #sec-temporal.plainyearmonth.prototype.since
MaybeHandle<JSTemporalDuration> JSTemporalPlainYearMonth::Since(
    Isolate* isolate, Handle<JSTemporalPlainYearMonth> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalPlainYearMonth(
      isolate, TimePreposition::kSince, handle, other, options,
      "Temporal.PlainYearMonth.prototype.since");
}

// #sec-temporal.plainyearmonth.prototype.with
MaybeHandle<JSTemporalPlainYearMonth> JSTemporalPlainYearMonth::With(
    Isolate* isolate, Handle<JSTemporalPlainYearMonth> temporal_year_month,
    Handle<Object> temporal_year_month_like_obj, Handle<Object> options_obj) {
  // 6. Let fieldNames be ? CalendarFields(calendar, « "month", "monthCode",
  // "year" »).
  Handle<FixedArray> field_names = MonthMonthCodeYearInFixedArray(isolate);
  return PlainDateOrYearMonthOrMonthDayWith<JSTemporalPlainYearMonth,
                                            YearMonthFromFields>(
      isolate, temporal_year_month, temporal_year_month_like_obj, options_obj,
      field_names, "Temporal.PlainYearMonth.prototype.with");
}

// #sec-temporal.plainyearmonth.prototype.toplaindate
MaybeHandle<JSTemporalPlainDate> JSTemporalPlainYearMonth::ToPlainDate(
    Isolate* isolate, Handle<JSTemporalPlainYearMonth> year_month,
    Handle<Object> item_obj) {
  Factory* factory = isolate->factory();
  // 5. Let receiverFieldNames be ? CalendarFields(calendar, « "monthCode",
  // "year" »).
  // 7. Let inputFieldNames be ? CalendarFields(calendar, « "day" »).
  return PlainMonthDayOrYearMonthToPlainDate<JSTemporalPlainYearMonth>(
      isolate, year_month, item_obj, factory->monthCode_string(),
      factory->year_string(), factory->day_string());
}

// #sec-temporal.plainyearmonth.prototype.getisofields
MaybeHandle<JSReceiver> JSTemporalPlainYearMonth::GetISOFields(
    Isolate* isolate, DirectHandle<JSTemporalPlainYearMonth> year_month) {
  Factory* factory = isolate->factory();
  // 1. Let yearMonth be the this value.
  // 2. Perform ? RequireInternalSlot(yearMonth,
  // [[InitializedTemporalYearMonth]]).
  // 3. Let fields be ! OrdinaryObjectCreate(%Object.prototype%).
  Handle<JSObject> fields =
      isolate->factory()->NewJSObject(isolate->object_function());
  // 4. Perform ! CreateDataPropertyOrThrow(fields, "calendar",
  // yearMonth.[[Calendar]]).
  CHECK(JSReceiver::CreateDataProperty(
            isolate, fields, factory->calendar_string(),
            Handle<JSReceiver>(year_month->calendar(), isolate),
            Just(kThrowOnError))
            .FromJust());
  // 5. Perform ! CreateDataPropertyOrThrow(fields, "isoDay",
  // 𝔽(yearMonth.[[ISODay]])).
  // 6. Perform ! CreateDataPropertyOrThrow(fields, "isoMonth",
  // 𝔽(yearMonth.[[ISOMonth]])).
  // 7. Perform ! CreateDataPropertyOrThrow(fields, "isoYear",
  // 𝔽(yearMonth.[[ISOYear]])).
  DEFINE_INT_FIELD(fields, isoDay, iso_day, year_month)
  DEFINE_INT_FIELD(fields, isoMonth, iso_month, year_month)
  DEFINE_INT_FIELD(fields, isoYear, iso_year, year_month)
  // 8. Return fields.
  return fields;
}

// #sec-temporal.plainyearmonth.prototype.tojson
MaybeHandle<String> JSTemporalPlainYearMonth::ToJSON(
    Isolate* isolate, DirectHandle<JSTemporalPlainYearMonth> year_month) {
  return TemporalYearMonthToString(isolate, year_month, ShowCalendar::kAuto);
}

// #sec-temporal.plainyearmonth.prototype.tostring
MaybeHandle<String> JSTemporalPlainYearMonth::ToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainYearMonth> year_month,
    Handle<Object> options) {
  return TemporalToString<JSTemporalPlainYearMonth, TemporalYearMonthToString>(
      isolate, year_month, options,
      "Temporal.PlainYearMonth.prototype.toString");
}

// #sec-temporal.plainyearmonth.prototype.tolocalestring
MaybeHandle<String> JSTemporalPlainYearMonth::ToLocaleString(
    Isolate* isolate, Handle<JSTemporalPlainYearMonth> year_month,
    Handle<Object> locales, Handle<Object> options) {
#ifdef V8_INTL_SUPPORT
  return JSDateTimeFormat::TemporalToLocaleString(
      isolate, year_month, locales, options,
      "Temporal.PlainYearMonth.prototype.toLocaleString");
#else   //  V8_INTL_SUPPORT
  return TemporalYearMonthToString(isolate, year_month, ShowCalendar::kAuto);
#endif  //  V8_INTL_SUPPORT
}

// #sec-temporal-plaintime-constructor
MaybeHandle<JSTemporalPlainTime> JSTemporalPlainTime::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> hour_obj, Handle<Object> minute_obj,
    Handle<Object> second_obj, Handle<Object> millisecond_obj,
    Handle<Object> microsecond_obj, Handle<Object> nanosecond_obj) {
  const char* method_name = "Temporal.PlainTime";
  // 1. If NewTarget is undefined, then
  // a. Throw a TypeError exception.
  if (IsUndefined(*new_target)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }

  TO_INT_THROW_ON_INFTY(hour, JSTemporalPlainTime);
  TO_INT_THROW_ON_INFTY(minute, JSTemporalPlainTime);
  TO_INT_THROW_ON_INFTY(second, JSTemporalPlainTime);
  TO_INT_THROW_ON_INFTY(millisecond, JSTemporalPlainTime);
  TO_INT_THROW_ON_INFTY(microsecond, JSTemporalPlainTime);
  TO_INT_THROW_ON_INFTY(nanosecond, JSTemporalPlainTime);

  // 14. Return ? CreateTemporalTime(hour, minute, second, millisecond,
  // microsecond, nanosecond, NewTarget).
  return CreateTemporalTime(
      isolate, target, new_target,
      {hour, minute, second, millisecond, microsecond, nanosecond});
}

// #sec-temporal.plaintime.prototype.tozoneddatetime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalPlainTime::ToZonedDateTime(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> item_obj) {
  const char* method_name = "Temporal.PlainTime.prototype.toZonedDateTime";
  Factory* factory = isolate->factory();
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalTime,
  // [[InitializedTemporalTime]]).
  // 3. If Type(item) is not Object, then
  if (!IsJSReceiver(*item_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
  // 4. Let temporalDateLike be ? Get(item, "plainDate").
  Handle<Object> temporal_date_like;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_like,
      JSReceiver::GetProperty(isolate, item, factory->plainDate_string()));
  // 5. If temporalDateLike is undefined, then
  if (IsUndefined(*temporal_date_like)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  // 6. Let temporalDate be ? ToTemporalDate(temporalDateLike).
  Handle<JSTemporalPlainDate> temporal_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date,
      ToTemporalDate(isolate, temporal_date_like, method_name));
  // 7. Let temporalTimeZoneLike be ? Get(item, "timeZone").
  Handle<Object> temporal_time_zone_like;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_time_zone_like,
      JSReceiver::GetProperty(isolate, item, factory->timeZone_string()));
  // 8. If temporalTimeZoneLike is undefined, then
  if (IsUndefined(*temporal_time_zone_like)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  // 9. Let timeZone be ? ToTemporalTimeZone(temporalTimeZoneLike).
  Handle<JSReceiver> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      temporal::ToTemporalTimeZone(isolate, temporal_time_zone_like,
                                   method_name));
  // 10. Let temporalDateTime be ?
  // CreateTemporalDateTime(temporalDate.[[ISOYear]], temporalDate.[[ISOMonth]],
  // temporalDate.[[ISODay]], temporalTime.[[ISOHour]],
  // temporalTime.[[ISOMinute]], temporalTime.[[ISOSecond]],
  // temporalTime.[[ISOMillisecond]], temporalTime.[[ISOMicrosecond]],
  // temporalTime.[[ISONanosecond]], temporalDate.[[Calendar]]).
  DirectHandle<JSReceiver> calendar(temporal_date->calendar(), isolate);
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::CreateTemporalDateTime(
          isolate,
          {{temporal_date->iso_year(), temporal_date->iso_month(),
            temporal_date->iso_day()},
           {temporal_time->iso_hour(), temporal_time->iso_minute(),
            temporal_time->iso_second(), temporal_time->iso_millisecond(),
            temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()}},
          calendar));
  // 11. Let instant be ? BuiltinTimeZoneGetInstantFor(timeZone,
  // temporalDateTime, "compatible").
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, temporal_date_time,
                                   Disambiguation::kCompatible, method_name));
  // 12. Return ? CreateTemporalZonedDateTime(instant.[[Nanoseconds]], timeZone,
  // temporalDate.[[Calendar]]).
  return CreateTemporalZonedDateTime(
      isolate, handle(instant->nanoseconds(), isolate), time_zone, calendar);
}

namespace {
// #sec-temporal-comparetemporaltime
int32_t CompareTemporalTime(const TimeRecord& time1, const TimeRecord& time2) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: h1, min1, s1, ms1, mus1, ns1, h2, min2, s2, ms2, mus2, and ns2
  // are integers.
  // 2. If h1 > h2, return 1.
  if (time1.hour > time2.hour) return 1;
  // 3. If h1 < h2, return -1.
  if (time1.hour < time2.hour) return -1;
  // 4. If min1 > min2, return 1.
  if (time1.minute > time2.minute) return 1;
  // 5. If min1 < min2, return -1.
  if (time1.minute < time2.minute) return -1;
  // 6. If s1 > s2, return 1.
  if (time1.second > time2.second) return 1;
  // 7. If s1 < s2, return -1.
  if (time1.second < time2.second) return -1;
  // 8. If ms1 > ms2, return 1.
  if (time1.millisecond > time2.millisecond) return 1;
  // 9. If ms1 < ms2, return -1.
  if (time1.millisecond < time2.millisecond) return -1;
  // 10. If mus1 > mus2, return 1.
  if (time1.microsecond > time2.microsecond) return 1;
  // 11. If mus1 < mus2, return -1.
  if (time1.microsecond < time2.microsecond) return -1;
  // 12. If ns1 > ns2, return 1.
  if (time1.nanosecond > time2.nanosecond) return 1;
  // 13. If ns1 < ns2, return -1.
  if (time1.nanosecond < time2.nanosecond) return -1;
  // 14. Return 0.
  return 0;
}
}  // namespace

// #sec-temporal.plaintime.compare
MaybeHandle<Smi> JSTemporalPlainTime::Compare(Isolate* isolate,
                                              Handle<Object> one_obj,
                                              Handle<Object> two_obj) {
  const char* method_name = "Temporal.PainTime.compare";
  // 1. Set one to ? ToTemporalTime(one).
  Handle<JSTemporalPlainTime> one;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, one, temporal::ToTemporalTime(isolate, one_obj, method_name));
  // 2. Set two to ? ToTemporalTime(two).
  Handle<JSTemporalPlainTime> two;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, two, temporal::ToTemporalTime(isolate, two_obj, method_name));
  // 3. Return 𝔽(! CompareTemporalTime(one.[[ISOHour]], one.[[ISOMinute]],
  // one.[[ISOSecond]], one.[[ISOMillisecond]], one.[[ISOMicrosecond]],
  // one.[[ISONanosecond]], two.[[ISOHour]], two.[[ISOMinute]],
  // two.[[ISOSecond]], two.[[ISOMillisecond]], two.[[ISOMicrosecond]],
  // two.[[ISONanosecond]])).
  return handle(Smi::FromInt(CompareTemporalTime(
                    {one->iso_hour(), one->iso_minute(), one->iso_second(),
                     one->iso_millisecond(), one->iso_microsecond(),
                     one->iso_nanosecond()},
                    {two->iso_hour(), two->iso_minute(), two->iso_second(),
                     two->iso_millisecond(), two->iso_microsecond(),
                     two->iso_nanosecond()})),
                isolate);
}

// #sec-temporal.plaintime.prototype.equals
MaybeHandle<Oddball> JSTemporalPlainTime::Equals(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> other_obj) {
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalTime,
  // [[InitializedTemporalTime]]).
  // 3. Set other to ? ToTemporalTime(other).
  Handle<JSTemporalPlainTime> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other,
      temporal::ToTemporalTime(isolate, other_obj,
                               "Temporal.PlainTime.prototype.equals"));
  // 4. If temporalTime.[[ISOHour]] ≠ other.[[ISOHour]], return false.
  if (temporal_time->iso_hour() != other->iso_hour())
    return isolate->factory()->false_value();
  // 5. If temporalTime.[[ISOMinute]] ≠ other.[[ISOMinute]], return false.
  if (temporal_time->iso_minute() != other->iso_minute())
    return isolate->factory()->false_value();
  // 6. If temporalTime.[[ISOSecond]] ≠ other.[[ISOSecond]], return false.
  if (temporal_time->iso_second() != other->iso_second())
    return isolate->factory()->false_value();
  // 7. If temporalTime.[[ISOMillisecond]] ≠ other.[[ISOMillisecond]], return
  // false.
  if (temporal_time->iso_millisecond() != other->iso_millisecond())
    return isolate->factory()->false_value();
  // 8. If temporalTime.[[ISOMicrosecond]] ≠ other.[[ISOMicrosecond]], return
  // false.
  if (temporal_time->iso_microsecond() != other->iso_microsecond())
    return isolate->factory()->false_value();
  // 9. If temporalTime.[[ISONanosecond]] ≠ other.[[ISONanosecond]], return
  // false.
  if (temporal_time->iso_nanosecond() != other->iso_nanosecond())
    return isolate->factory()->false_value();
  // 10. Return true.
  return isolate->factory()->true_value();
}

namespace {

// #sec-temporal-maximumtemporaldurationroundingincrement
Maximum MaximumTemporalDurationRoundingIncrement(Unit unit) {
  switch (unit) {
    // 1. If unit is "year", "month", "week", or "day", then
    case Unit::kYear:
    case Unit::kMonth:
    case Unit::kWeek:
    case Unit::kDay:
      // a. Return undefined.
      return {false, 0};
    // 2. If unit is "hour", then
    case Unit::kHour:
      // a. Return 24.
      return {true, 24};
    // 3. If unit is "minute" or "second", then
    case Unit::kMinute:
    case Unit::kSecond:
      // a. Return 60.
      return {true, 60};
    // 4. Assert: unit is one of "millisecond", "microsecond", or "nanosecond".
    case Unit::kMillisecond:
    case Unit::kMicrosecond:
    case Unit::kNanosecond:
      // 5. Return 1000.
      return {true, 1000};
    default:
      UNREACHABLE();
  }
}

}  // namespace

// #sec-temporal.plaintime.prototype.round
MaybeHandle<JSTemporalPlainTime> JSTemporalPlainTime::Round(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> round_to_obj) {
  const char* method_name = "Temporal.PlainTime.prototype.round";
  Factory* factory = isolate->factory();
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalTime,
  // [[InitializedTemporalTime]]).
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
    // c. Perform ! CreateDataPropertyOrThrow(roundTo, "smallestUnit",
    // paramString).
    CHECK(JSReceiver::CreateDataProperty(isolate, round_to,
                                         factory->smallestUnit_string(),
                                         param_string, Just(kThrowOnError))
              .FromJust());
  } else {
    // 5. Set roundTo to ? GetOptionsObject(roundTo).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, round_to,
        GetOptionsObject(isolate, round_to_obj, method_name));
  }

  // 6. Let smallestUnit be ? GetTemporalUnit(roundTo, "smallestUnit", time,
  // required).
  Unit smallest_unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, smallest_unit,
      GetTemporalUnit(isolate, round_to, "smallestUnit", UnitGroup::kTime,
                      Unit::kNotPresent, true, method_name),
      Handle<JSTemporalPlainTime>());

  // 7. Let roundingMode be ? ToTemporalRoundingMode(roundTo, "halfExpand").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, round_to, RoundingMode::kHalfExpand,
                             method_name),
      Handle<JSTemporalPlainTime>());

  // 8. Let maximum be ! MaximumTemporalDurationRoundingIncrement(smallestUnit).
  Maximum maximum = MaximumTemporalDurationRoundingIncrement(smallest_unit);

  // 9. Let roundingIncrement be ? ToTemporalRoundingIncrement(roundTo,
  // maximum, false).
  double rounding_increment;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_increment,
      ToTemporalRoundingIncrement(isolate, round_to, maximum.value,
                                  maximum.defined, false),
      Handle<JSTemporalPlainTime>());

  // 12. Let result be ! RoundTime(temporalTime.[[ISOHour]],
  // temporalTime.[[ISOMinute]], temporalTime.[[ISOSecond]],
  // temporalTime.[[ISOMillisecond]], temporalTime.[[ISOMicrosecond]],
  // temporalTime.[[ISONanosecond]], roundingIncrement, smallestUnit,
  // roundingMode).
  DateTimeRecord result = RoundTime(
      isolate,
      {temporal_time->iso_hour(), temporal_time->iso_minute(),
       temporal_time->iso_second(), temporal_time->iso_millisecond(),
       temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()},
      rounding_increment, smallest_unit, rounding_mode);
  // 13. Return ? CreateTemporalTime(result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]]).
  return CreateTemporalTime(isolate, result.time);
}

// #sec-temporal.plaintime.prototype.with
MaybeHandle<JSTemporalPlainTime> JSTemporalPlainTime::With(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> temporal_time_like_obj, Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainTime.prototype.with";
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalTime,
  // [[InitializedTemporalTime]]).
  // 3. If Type(temporalTimeLike) is not Object, then
  if (!IsJSReceiver(*temporal_time_like_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  Handle<JSReceiver> temporal_time_like =
      Cast<JSReceiver>(temporal_time_like_obj);
  // 4. Perform ? RejectObjectWithCalendarOrTimeZone(temporalTimeLike).
  MAYBE_RETURN(RejectObjectWithCalendarOrTimeZone(isolate, temporal_time_like),
               Handle<JSTemporalPlainTime>());
  // 5. Let partialTime be ? ToPartialTime(temporalTimeLike).
  TimeRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      ToPartialTime(
          isolate, temporal_time_like,
          {temporal_time->iso_hour(), temporal_time->iso_minute(),
           temporal_time->iso_second(), temporal_time->iso_millisecond(),
           temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()},
          method_name),
      Handle<JSTemporalPlainTime>());

  // 6. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 7. Let overflow be ? ToTemporalOverflow(options).
  ShowOverflow overflow;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, overflow, ToTemporalOverflow(isolate, options, method_name),
      Handle<JSTemporalPlainTime>());

  // 20. Let result be ? RegulateTime(hour, minute, second, millisecond,
  // microsecond, nanosecond, overflow).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, temporal::RegulateTime(isolate, result, overflow),
      Handle<JSTemporalPlainTime>());
  // 25. Return ? CreateTemporalTime(result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]]).
  return CreateTemporalTime(isolate, result);
}

// #sec-temporal.now.plaintimeiso
MaybeHandle<JSTemporalPlainTime> JSTemporalPlainTime::NowISO(
    Isolate* isolate, Handle<Object> temporal_time_zone_like) {
  const char* method_name = "Temporal.Now.plainTimeISO";
  // 1. Let calendar be ! GetISO8601Calendar().
  Handle<JSReceiver> calendar = temporal::GetISO8601Calendar(isolate);
  // 2. Let dateTime be ? SystemDateTime(temporalTimeZoneLike, calendar).
  Handle<JSTemporalPlainDateTime> date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time,
      SystemDateTime(isolate, temporal_time_zone_like, calendar, method_name));
  // 3. Return ! CreateTemporalTime(dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]]).
  return CreateTemporalTime(
             isolate,
             {date_time->iso_hour(), date_time->iso_minute(),
              date_time->iso_second(), date_time->iso_millisecond(),
              date_time->iso_microsecond(), date_time->iso_nanosecond()})
      .ToHandleChecked();
}

// #sec-temporal.plaintime.from
MaybeHandle<JSTemporalPlainTime> JSTemporalPlainTime::From(
    Isolate* isolate, Handle<Object> item_obj, Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainTime.from";
  // 1. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 2. Let overflow be ? ToTemporalOverflow(options).
  ShowOverflow overflow;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, overflow, ToTemporalOverflow(isolate, options, method_name),
      Handle<JSTemporalPlainTime>());
  // 3. If Type(item) is Object and item has an [[InitializedTemporalTime]]
  // internal slot, then
  if (IsJSTemporalPlainTime(*item_obj)) {
    // a. Return ? CreateTemporalTime(item.[[ISOHour]], item.[[ISOMinute]],
    // item.[[ISOSecond]], item.[[ISOMillisecond]], item.[[ISOMicrosecond]],
    // item.[[ISONanosecond]]).
    auto item = Cas
"""


```