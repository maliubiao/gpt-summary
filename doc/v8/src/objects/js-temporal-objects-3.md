Response: The user wants a summary of the C++ source code file `v8/src/objects/js-temporal-objects.cc`, specifically part 4 of 13. The summary should focus on the functionalities implemented in this part and highlight any relationship with Javascript features, providing Javascript examples if applicable.

Based on the code snippets provided, this part of the file seems to implement helper functions and algorithms related to the **Temporal API** in Javascript. These functions deal with:

1. **Time and Date Record Manipulation**:  Functions to convert Javascript objects to internal time and date records (`ToTemporalTimeRecordOrPartialTime`, `ToPartialTime`, `ToTemporalTimeRecord`).
2. **Temporal Units**:  Functions to get and manage temporal units like "year", "month", "day", "hour", etc. (`GetTemporalUnit`, `MergeLargestUnitOption`, `LargerOfTwoTemporalUnits`, `UnitToString`).
3. **Date and Time Calculations**: Functions for balancing date and time components (`BalanceISODate`, `AddDateTime`).
4. **Duration Handling**: Functions for balancing and manipulating durations (`BalanceDuration`, `BalancePossiblyInfiniteDuration`).
5. **ZonedDateTime Arithmetic**: Functions for adding durations to ZonedDateTime values (`AddZonedDateTime`).
6. **Nanosecond to Days Conversion**: Functions to convert nanoseconds to days, considering time zones (`NanosecondsToDays`).
7. **Difference between DateTimes**: Functions to calculate the difference between two DateTimes (`DifferenceISODateTime`).
8. **Instant Arithmetic**: Functions for adding durations to Instant values (`AddInstant`).
9. **Epoch Nanosecond Validation**: Functions to check if a given nanosecond value is a valid epoch nanosecond (`IsValidEpochNanoseconds`).
10. **Getting Epoch from ISO Parts**:  Functions to convert ISO date and time components to epoch nanoseconds (`GetEpochFromISOParts`).
11. **Duration Sign and Validity**: Functions to determine the sign of a duration and check if a duration is valid (`DurationRecord::Sign`, `IsValidDuration`).
12. **ISO Date Calculations**: Helper functions for ISO calendar calculations like checking for leap years and getting days in a month/year (`IsISOLeapYear`, `ISODaysInMonth`, `ISODaysInYear`).

The file heavily relies on internal representations of dates, times, and durations and performs operations according to the Temporal API specifications. The relationship with Javascript is that these C++ functions are the underlying implementation for the Javascript `Temporal` objects and their methods.
This part of the `js-temporal-objects.cc` file in V8 seems to focus on implementing **core functionalities for handling and manipulating temporal values**, which are central to the Javascript `Temporal` API.

Here's a breakdown of its key functions:

*   **`ToTemporalTimeRecordOrPartialTime`, `ToPartialTime`, `ToTemporalTimeRecord`**: These functions are responsible for converting Javascript objects (that are expected to represent a time) into an internal `TimeRecord` structure. They extract hour, minute, second, millisecond, microsecond, and nanosecond properties from the Javascript object. `ToPartialTime` allows for undefined properties, while `ToTemporalTimeRecord` requires all time components to be present or throws an error.

    **Javascript Example:**

    ```javascript
    // Assuming the C++ code is used internally by the Temporal API

    const timeLike = { hour: 10, minute: 30, second: 0 };
    // Internally, V8 would use functions like ToPartialTime to convert
    // timeLike into a TimeRecord

    const fullTime = { hour: 10, minute: 30, second: 0, millisecond: 500, microsecond: 100, nanosecond: 1 };
    // Internally, V8 would use functions like ToTemporalTimeRecord for fullTime
    ```

*   **`GetTemporalUnit`**: This function retrieves a temporal unit (like "year", "month", "day", "hour", etc.) from a Javascript options object. It handles singular and plural forms and ensures the provided unit is valid for the given context (e.g., date units vs. time units).

    **Javascript Example:**

    ```javascript
    // Assuming the C++ code is used internally by the Temporal API

    const options1 = { largestUnit: 'day' };
    // Internally, V8 would use GetTemporalUnit to extract 'day'

    const options2 = { smallestUnit: 'minutes' };
    // Internally, V8 would use GetTemporalUnit to extract 'minute'
    ```

*   **`MergeLargestUnitOption`**: This function creates a new options object by merging the original options with a specific "largestUnit" property.

*   **`ToIntegerThrowOnInfinity`**: This utility function converts a Javascript value to an integer, throwing an error if the value is infinity or negative infinity.

*   **`LargerOfTwoTemporalUnits`**:  Compares two temporal units and returns the larger one (e.g., "month" is larger than "day").

*   **`UnitToString`**: Converts an internal `Unit` enum value back to its string representation (e.g., `Unit::kMonth` to "month").

*   **`CreateISODateRecord`, `BalanceISODate`**: These functions deal with creating and balancing ISO date components (year, month, day) to ensure they represent a valid date.

*   **`AddDateTime`**: This function adds a duration to a given date and time. It handles the complexities of adding time components and date components separately, potentially involving calendar calculations.

    **Javascript Example:**

    ```javascript
    // Assuming the C++ code is used internally by the Temporal API

    const plainDateTime = Temporal.PlainDateTime.from({ year: 2023, month: 10, day: 26, hour: 10, minute: 0 });
    const duration = Temporal.Duration.from({ hours: 2 });
    // Internally, V8 would use AddDateTime to perform the addition
    const laterDateTime = plainDateTime.add(duration);
    ```

*   **`BalanceDuration`**:  A set of overloaded functions that balance the components of a duration (e.g., converting 60 seconds into 1 minute). They can take various forms of input, including relative-to information for context-sensitive balancing.

    **Javascript Example:**

    ```javascript
    // Assuming the C++ code is used internally by the Temporal API

    const duration1 = Temporal.Duration.from({ seconds: 90 });
    // Internally, V8's BalanceDuration would likely be used to normalize this
    // to something like { minutes: 1, seconds: 30 }

    const duration2 = Temporal.Duration.from({ days: 1, hours: 25 });
    // Internally, BalanceDuration would be used to normalize this
    // to something like { days: 2, hours: 1 }
    ```

*   **`BalancePossiblyInfiniteDuration`**:  Similar to `BalanceDuration`, but handles potentially infinite durations (though it will throw errors in such cases within this part of the code).

*   **`AddZonedDateTime`**: This function adds a duration to a `Temporal.ZonedDateTime`. It considers the time zone and calendar when performing the addition, which can involve handling daylight saving time transitions.

    **Javascript Example:**

    ```javascript
    // Assuming the C++ code is used internally by the Temporal API

    const timeZone = Temporal.TimeZone.from('America/Los_Angeles');
    const zonedDateTime = Temporal.ZonedDateTime.from('2023-10-26T10:00:00-07:00[America/Los_Angeles]');
    const duration = Temporal.Duration.from({ days: 1 });
    // Internally, V8 would use AddZonedDateTime to add the duration,
    // potentially adjusting for DST changes
    const laterZonedDateTime = zonedDateTime.add(duration);
    ```

*   **`NanosecondsToDays`**: Converts a duration in nanoseconds to days, potentially considering a relative `ZonedDateTime` to account for varying day lengths due to time zone changes.

*   **`DifferenceISODateTime`**: Calculates the difference between two date-time values, returning a `DurationRecord`. It considers the calendar and allows specifying the largest unit for the difference.

    **Javascript Example:**

    ```javascript
    // Assuming the C++ code is used internally by the Temporal API

    const dateTime1 = Temporal.PlainDateTime.from('2023-10-25T10:00:00');
    const dateTime2 = Temporal.PlainDateTime.from('2023-10-26T12:30:00');
    // Internally, V8 would use DifferenceISODateTime to calculate the difference
    const difference = dateTime1.until(dateTime2);
    ```

*   **`AddInstant`**: Adds a time duration (hours, minutes, seconds, milliseconds, microseconds, nanoseconds) to a point in time represented by epoch nanoseconds.

    **Javascript Example:**

    ```javascript
    // Assuming the C++ code is used internally by the Temporal API

    const instant = Temporal.Instant.fromEpochNanoseconds(1666780800000000000n); // Example epoch nanoseconds
    const duration = Temporal.Duration.from({ hours: 1 });
    // Internally, V8 would use AddInstant to add the duration
    const laterInstant = instant.add(duration);
    ```

*   **`IsValidEpochNanoseconds`**: Checks if a given `BigInt` value represents a valid number of nanoseconds since the epoch (within the supported range).

*   **`GetEpochFromISOParts`**: Converts ISO date and time components into the equivalent number of nanoseconds since the epoch.

*   **`DurationRecord::Sign`**: Determines the sign of a duration (positive, negative, or zero) based on its components.

*   **`IsValidDuration`**: Checks if a `DurationRecord` represents a valid duration (e.g., no mixed signs for components, within reasonable limits).

*   **`IsISOLeapYear`, `ISODaysInMonth`, `ISODaysInYear`**: These are utility functions for performing calculations related to the ISO calendar, such as determining if a year is a leap year and how many days are in a specific month or year.

In essence, this part of the file lays the groundwork for the core arithmetic and manipulation operations that the Javascript `Temporal` API exposes to developers. It handles the low-level details of working with dates, times, and durations in a consistent and correct manner, taking into account calendar systems and time zones where necessary.

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共13部分，请归纳一下它的功能
```

### 源代码
```
_zone, isolate));
}
// #sec-canonicalizetimezonename
Handle<String> CanonicalizeTimeZoneName(Isolate* isolate,
                                        DirectHandle<String> identifier) {
  return isolate->factory()->UTC_string();
}
#endif  // V8_INTL_SUPPORT

// Common routine shared by ToTemporalTimeRecord and ToPartialTime
// #sec-temporal-topartialtime
// #sec-temporal-totemporaltimerecord
Maybe<TimeRecord> ToTemporalTimeRecordOrPartialTime(
    Isolate* isolate, Handle<JSReceiver> temporal_time_like,
    const TimeRecord& time, bool skip_undefined, const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  TimeRecord result(time);
  Factory* factory = isolate->factory();
  // 1. Assert: Type(temporalTimeLike) is Object.
  // 2. Let result be the new Record { [[Hour]]: undefined, [[Minute]]:
  // undefined, [[Second]]: undefined, [[Millisecond]]: undefined,
  // [[Microsecond]]: undefined, [[Nanosecond]]: undefined }.
  // See https://github.com/tc39/proposal-temporal/pull/1862
  // 3. Let _any_ be *false*.
  bool any = false;
  // 4. For each row of Table 4, except the header row, in table order, do
  std::array<std::pair<Handle<String>, int32_t*>, 6> table4 = {
      {{factory->hour_string(), &result.hour},
       {factory->microsecond_string(), &result.microsecond},
       {factory->millisecond_string(), &result.millisecond},
       {factory->minute_string(), &result.minute},
       {factory->nanosecond_string(), &result.nanosecond},
       {factory->second_string(), &result.second}}};
  for (const auto& row : table4) {
    Handle<Object> value;
    // a. Let property be the Property value of the current row.
    // b. Let value be ? Get(temporalTimeLike, property).
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, value,
        JSReceiver::GetProperty(isolate, temporal_time_like, row.first),
        Nothing<TimeRecord>());
    // c. If value is not undefined, then
    if (!IsUndefined(*value)) {
      // i. Set _any_ to *true*.
      any = true;
      // If it is inside ToPartialTime, we only continue if it is not undefined.
    } else if (skip_undefined) {
      continue;
    }
    // d. / ii. Set value to ? ToIntegerThrowOnOInfinity(value).
    Handle<Number> value_number;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, value_number,
                                     ToIntegerThrowOnInfinity(isolate, value),
                                     Nothing<TimeRecord>());
    // e. / iii. Set result's internal slot whose name is the Internal Slot
    // value of the current row to value.
    *(row.second) = Object::NumberValue(*value_number);
  }

  // 5. If _any_ is *false*, then
  if (!any) {
    // a. Throw a *TypeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<TimeRecord>());
  }
  // 4. Return result.
  return Just(result);
}

// #sec-temporal-topartialtime
Maybe<TimeRecord> ToPartialTime(Isolate* isolate,
                                Handle<JSReceiver> temporal_time_like,
                                const TimeRecord& time,
                                const char* method_name) {
  return ToTemporalTimeRecordOrPartialTime(isolate, temporal_time_like, time,
                                           true, method_name);
}

// #sec-temporal-totemporaltimerecord
Maybe<TimeRecord> ToTemporalTimeRecord(Isolate* isolate,
                                       Handle<JSReceiver> temporal_time_like,
                                       const char* method_name) {
  return ToTemporalTimeRecordOrPartialTime(
      isolate, temporal_time_like,
      {kMinInt31, kMinInt31, kMinInt31, kMinInt31, kMinInt31, kMinInt31}, false,
      method_name);
}

// #sec-temporal-gettemporalunit
// In the spec text, the extraValues is defined as an optional argument of
// "a List of ECMAScript language values". Most of the caller does not pass in
// value for extraValues, which is represented by the default Unit::kNotPresent.
// For the three places in the spec text calling GetTemporalUnit with
// an extraValues argument:
// << "day" >> is passed in as in the algorithm of
//   Temporal.PlainDateTime.prototype.round() and
//   Temporal.ZonedDateTime.prototype.round();
// << "auto" >> is passed in as in the algorithm of
// Temporal.Duration.prototype.round().
// Therefore we can simply use a Unit of three possible value, the default
// Unit::kNotPresent, Unit::kDay, and Unit::kAuto to cover all the possible
// value for extraValues.
Maybe<Unit> GetTemporalUnit(Isolate* isolate,
                            Handle<JSReceiver> normalized_options,
                            const char* key, UnitGroup unit_group,
                            Unit default_value, bool default_is_required,
                            const char* method_name,
                            Unit extra_values = Unit::kNotPresent) {
  std::vector<const char*> str_values;
  std::vector<Unit> enum_values;
  switch (unit_group) {
    case UnitGroup::kDate:
      if (default_value == Unit::kAuto || extra_values == Unit::kAuto) {
        str_values = {"year",  "month",  "week",  "day", "auto",
                      "years", "months", "weeks", "days"};
        enum_values = {Unit::kYear,  Unit::kMonth, Unit::kWeek,
                       Unit::kDay,   Unit::kAuto,  Unit::kYear,
                       Unit::kMonth, Unit::kWeek,  Unit::kDay};
      } else {
        DCHECK(default_value == Unit::kNotPresent ||
               default_value == Unit::kYear || default_value == Unit::kMonth ||
               default_value == Unit::kWeek || default_value == Unit::kDay);
        str_values = {"year",  "month",  "week",  "day",
                      "years", "months", "weeks", "days"};
        enum_values = {Unit::kYear, Unit::kMonth, Unit::kWeek, Unit::kDay,
                       Unit::kYear, Unit::kMonth, Unit::kWeek, Unit::kDay};
      }
      break;
    case UnitGroup::kTime:
      if (default_value == Unit::kAuto || extra_values == Unit::kAuto) {
        str_values = {"hour",        "minute",       "second",
                      "millisecond", "microsecond",  "nanosecond",
                      "auto",        "hours",        "minutes",
                      "seconds",     "milliseconds", "microseconds",
                      "nanoseconds"};
        enum_values = {
            Unit::kHour,        Unit::kMinute,      Unit::kSecond,
            Unit::kMillisecond, Unit::kMicrosecond, Unit::kNanosecond,
            Unit::kAuto,        Unit::kHour,        Unit::kMinute,
            Unit::kSecond,      Unit::kMillisecond, Unit::kMicrosecond,
            Unit::kNanosecond};
      } else if (default_value == Unit::kDay || extra_values == Unit::kDay) {
        str_values = {"hour",        "minute",       "second",
                      "millisecond", "microsecond",  "nanosecond",
                      "day",         "hours",        "minutes",
                      "seconds",     "milliseconds", "microseconds",
                      "nanoseconds", "days"};
        enum_values = {
            Unit::kHour,        Unit::kMinute,      Unit::kSecond,
            Unit::kMillisecond, Unit::kMicrosecond, Unit::kNanosecond,
            Unit::kDay,         Unit::kHour,        Unit::kMinute,
            Unit::kSecond,      Unit::kMillisecond, Unit::kMicrosecond,
            Unit::kNanosecond,  Unit::kDay};
      } else {
        DCHECK(default_value == Unit::kNotPresent ||
               default_value == Unit::kHour || default_value == Unit::kMinute ||
               default_value == Unit::kSecond ||
               default_value == Unit::kMillisecond ||
               default_value == Unit::kMicrosecond ||
               default_value == Unit::kNanosecond);
        str_values = {"hour",         "minute",       "second",
                      "millisecond",  "microsecond",  "nanosecond",
                      "hours",        "minutes",      "seconds",
                      "milliseconds", "microseconds", "nanoseconds"};
        enum_values = {
            Unit::kHour,        Unit::kMinute,      Unit::kSecond,
            Unit::kMillisecond, Unit::kMicrosecond, Unit::kNanosecond,
            Unit::kHour,        Unit::kMinute,      Unit::kSecond,
            Unit::kMillisecond, Unit::kMicrosecond, Unit::kNanosecond};
      }
      break;
    case UnitGroup::kDateTime:
      if (default_value == Unit::kAuto || extra_values == Unit::kAuto) {
        str_values = {"year",         "month",        "week",
                      "day",          "hour",         "minute",
                      "second",       "millisecond",  "microsecond",
                      "nanosecond",   "auto",         "years",
                      "months",       "weeks",        "days",
                      "hours",        "minutes",      "seconds",
                      "milliseconds", "microseconds", "nanoseconds"};
        enum_values = {
            Unit::kYear,        Unit::kMonth,       Unit::kWeek,
            Unit::kDay,         Unit::kHour,        Unit::kMinute,
            Unit::kSecond,      Unit::kMillisecond, Unit::kMicrosecond,
            Unit::kNanosecond,  Unit::kAuto,        Unit::kYear,
            Unit::kMonth,       Unit::kWeek,        Unit::kDay,
            Unit::kHour,        Unit::kMinute,      Unit::kSecond,
            Unit::kMillisecond, Unit::kMicrosecond, Unit::kNanosecond};
      } else {
        str_values = {
            "year",        "month",        "week",         "day",
            "hour",        "minute",       "second",       "millisecond",
            "microsecond", "nanosecond",   "years",        "months",
            "weeks",       "days",         "hours",        "minutes",
            "seconds",     "milliseconds", "microseconds", "nanoseconds"};
        enum_values = {
            Unit::kYear,        Unit::kMonth,       Unit::kWeek,
            Unit::kDay,         Unit::kHour,        Unit::kMinute,
            Unit::kSecond,      Unit::kMillisecond, Unit::kMicrosecond,
            Unit::kNanosecond,  Unit::kYear,        Unit::kMonth,
            Unit::kWeek,        Unit::kDay,         Unit::kHour,
            Unit::kMinute,      Unit::kSecond,      Unit::kMillisecond,
            Unit::kMicrosecond, Unit::kNanosecond};
      }
      break;
  }

  // 4. If default is required, then
  if (default_is_required) default_value = Unit::kNotPresent;
  // a. Let defaultValue be undefined.
  // 5. Else,
  // a. Let defaultValue be default.
  // b. If defaultValue is not undefined and singularNames does not contain
  // defaultValue, then i. Append defaultValue to singularNames.

  // 9. Let value be ? GetOption(normalizedOptions, key, "string",
  // allowedValues, defaultValue).
  Unit value;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, value,
      GetStringOption<Unit>(isolate, normalized_options, key, method_name,
                            str_values, enum_values, default_value),
      Nothing<Unit>());

  // 10. If value is undefined and default is required, throw a RangeError
  // exception.
  if (default_is_required && value == Unit::kNotPresent) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(
            MessageTemplate::kValueOutOfRange,
            isolate->factory()->undefined_value(),
            isolate->factory()->NewStringFromAsciiChecked(method_name),
            isolate->factory()->NewStringFromAsciiChecked(key)),
        Nothing<Unit>());
  }
  // 12. Return value.
  return Just(value);
}

// #sec-temporal-mergelargestunitoption
MaybeHandle<JSReceiver> MergeLargestUnitOption(Isolate* isolate,
                                               Handle<JSReceiver> options,
                                               Unit largest_unit) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let merged be OrdinaryObjectCreate(null).
  Handle<JSReceiver> merged = isolate->factory()->NewJSObjectWithNullProto();
  // 2. Let keys be ? EnumerableOwnPropertyNames(options, key).
  // 3. For each element nextKey of keys, do
  // a. Let propValue be ? Get(options, nextKey).
  // b. Perform ! CreateDataPropertyOrThrow(merged, nextKey, propValue).
  JSReceiver::SetOrCopyDataProperties(
      isolate, merged, options, PropertiesEnumerationMode::kEnumerationOrder,
      {}, false)
      .Check();

  // 4. Perform ! CreateDataPropertyOrThrow(merged, "largestUnit", largestUnit).
  CHECK(JSReceiver::CreateDataProperty(
            isolate, merged, isolate->factory()->largestUnit_string(),
            UnitToString(isolate, largest_unit), Just(kThrowOnError))
            .FromJust());
  // 5. Return merged.
  return merged;
}

// #sec-temporal-tointegerthrowoninfinity
MaybeHandle<Number> ToIntegerThrowOnInfinity(Isolate* isolate,
                                             Handle<Object> argument) {
  TEMPORAL_ENTER_FUNC();

  // 1. Let integer be ? ToIntegerOrInfinity(argument).
  Handle<Number> integer;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, integer,
                             Object::ToInteger(isolate, argument));
  // 2. If integer is +∞ or -∞, throw a RangeError exception.
  if (!std::isfinite(Object::NumberValue(*integer))) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  return integer;
}

// #sec-temporal-largeroftwotemporalunits
Unit LargerOfTwoTemporalUnits(Unit u1, Unit u2) {
  // 1. If either u1 or u2 is "year", return "year".
  if (u1 == Unit::kYear || u2 == Unit::kYear) return Unit::kYear;
  // 2. If either u1 or u2 is "month", return "month".
  if (u1 == Unit::kMonth || u2 == Unit::kMonth) return Unit::kMonth;
  // 3. If either u1 or u2 is "week", return "week".
  if (u1 == Unit::kWeek || u2 == Unit::kWeek) return Unit::kWeek;
  // 4. If either u1 or u2 is "day", return "day".
  if (u1 == Unit::kDay || u2 == Unit::kDay) return Unit::kDay;
  // 5. If either u1 or u2 is "hour", return "hour".
  if (u1 == Unit::kHour || u2 == Unit::kHour) return Unit::kHour;
  // 6. If either u1 or u2 is "minute", return "minute".
  if (u1 == Unit::kMinute || u2 == Unit::kMinute) return Unit::kMinute;
  // 7. If either u1 or u2 is "second", return "second".
  if (u1 == Unit::kSecond || u2 == Unit::kSecond) return Unit::kSecond;
  // 8. If either u1 or u2 is "millisecond", return "millisecond".
  if (u1 == Unit::kMillisecond || u2 == Unit::kMillisecond)
    return Unit::kMillisecond;
  // 9. If either u1 or u2 is "microsecond", return "microsecond".
  if (u1 == Unit::kMicrosecond || u2 == Unit::kMicrosecond)
    return Unit::kMicrosecond;
  // 10. Return "nanosecond".
  return Unit::kNanosecond;
}

Handle<String> UnitToString(Isolate* isolate, Unit unit) {
  switch (unit) {
    case Unit::kYear:
      return ReadOnlyRoots(isolate).year_string_handle();
    case Unit::kMonth:
      return ReadOnlyRoots(isolate).month_string_handle();
    case Unit::kWeek:
      return ReadOnlyRoots(isolate).week_string_handle();
    case Unit::kDay:
      return ReadOnlyRoots(isolate).day_string_handle();
    case Unit::kHour:
      return ReadOnlyRoots(isolate).hour_string_handle();
    case Unit::kMinute:
      return ReadOnlyRoots(isolate).minute_string_handle();
    case Unit::kSecond:
      return ReadOnlyRoots(isolate).second_string_handle();
    case Unit::kMillisecond:
      return ReadOnlyRoots(isolate).millisecond_string_handle();
    case Unit::kMicrosecond:
      return ReadOnlyRoots(isolate).microsecond_string_handle();
    case Unit::kNanosecond:
      return ReadOnlyRoots(isolate).nanosecond_string_handle();
    case Unit::kNotPresent:
    case Unit::kAuto:
      UNREACHABLE();
  }
}

// #sec-temporal-create-iso-date-record
DateRecord CreateISODateRecord(Isolate* isolate, const DateRecord& date) {
  // 1. Assert: IsValidISODate(year, month, day) is true.
  DCHECK(IsValidISODate(isolate, date));
  // 2. Return the Record { [[Year]]: year, [[Month]]: month, [[Day]]: day }.
  return date;
}

// #sec-temporal-balanceisodate
DateRecord BalanceISODate(Isolate* isolate, const DateRecord& date) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let epochDays be MakeDay(𝔽(year), 𝔽(month - 1), 𝔽(day)).
  double epoch_days = MakeDay(date.year, date.month - 1, date.day);
  // 2. Assert: epochDays is finite.
  DCHECK(std::isfinite(epoch_days));
  // 3. Let ms be MakeDate(epochDays, +0𝔽).
  double ms = MakeDate(epoch_days, 0);
  // 4. Return CreateISODateRecordWithCalendar(ℝ(YearFromTime(ms)),
  // ℝ(MonthFromTime(ms)) + 1, ℝ(DateFromTime(ms))).
  int year = 0;
  int month = 0;
  int day = 0;
  int wday = 0;
  int hour = 0;
  int minute = 0;
  int second = 0;
  int millisecond = 0;

  DCHECK(std::isfinite(ms));
  DCHECK_LT(ms, static_cast<double>(std::numeric_limits<int64_t>::max()));
  DCHECK_GT(ms, static_cast<double>(std::numeric_limits<int64_t>::min()));
  isolate->date_cache()->BreakDownTime(ms, &year, &month, &day, &wday, &hour,
                                       &minute, &second, &millisecond);

  return CreateISODateRecord(isolate, {year, month + 1, day});
}

// #sec-temporal-adddatetime
Maybe<DateTimeRecord> AddDateTime(Isolate* isolate,
                                  const DateTimeRecord& date_time,
                                  Handle<JSReceiver> calendar,
                                  const DurationRecord& dur,
                                  Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: ISODateTimeWithinLimits(year, month, day, hour, minute, second,
  // millisecond, microsecond, nanosecond) is true.
  DCHECK(ISODateTimeWithinLimits(isolate, date_time));
  // 2. Let timeResult be ! AddTime(hour, minute, second, millisecond,
  // microsecond, nanosecond, hours, minutes, seconds, milliseconds,
  // microseconds, nanoseconds).
  const TimeDurationRecord& time = dur.time_duration;
  DateTimeRecord time_result =
      AddTime(isolate, date_time.time,
              {0, time.hours, time.minutes, time.seconds, time.milliseconds,
               time.microseconds, time.nanoseconds});

  // 3. Let datePart be ? CreateTemporalDate(year, month, day, calendar).
  Handle<JSTemporalPlainDate> date_part;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, date_part, CreateTemporalDate(isolate, date_time.date, calendar),
      Nothing<DateTimeRecord>());
  // 4. Let dateDuration be ? CreateTemporalDuration(years, months, weeks, days
  // + timeResult.[[Days]], 0, 0, 0, 0, 0, 0).
  Handle<JSTemporalDuration> date_duration;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, date_duration,
      CreateTemporalDuration(
          isolate,
          {dur.years,
           dur.months,
           dur.weeks,
           {dur.time_duration.days + time_result.date.day, 0, 0, 0, 0, 0, 0}}),
      Nothing<DateTimeRecord>());
  // 5. Let addedDate be ? CalendarDateAdd(calendar, datePart, dateDuration,
  // options).
  Handle<JSTemporalPlainDate> added_date;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, added_date,
      CalendarDateAdd(isolate, calendar, date_part, date_duration, options),
      Nothing<DateTimeRecord>());
  // 6. Return the new Record { [[Year]]: addedDate.[[ISOYear]], [[Month]]:
  // addedDate.[[ISOMonth]], [[Day]]: addedDate.[[ISODay]], [[Hour]]:
  // timeResult.[[Hour]], [[Minute]]: timeResult.[[Minute]], [[Second]]:
  // timeResult.[[Second]], [[Millisecond]]: timeResult.[[Millisecond]],
  // [[Microsecond]]: timeResult.[[Microsecond]], [[Nanosecond]]:
  // timeResult.[[Nanosecond]], }.
  time_result.date = {added_date->iso_year(), added_date->iso_month(),
                      added_date->iso_day()};
  return Just(time_result);
}

// #sec-temporal-balanceduration
Maybe<TimeDurationRecord> BalanceDuration(Isolate* isolate, Unit largest_unit,
                                          const TimeDurationRecord& duration,
                                          const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 1. If relativeTo is not present, set relativeTo to undefined.
  return BalanceDuration(isolate, largest_unit,
                         isolate->factory()->undefined_value(), duration,
                         method_name);
}

Maybe<TimeDurationRecord> BalanceDuration(Isolate* isolate, Unit largest_unit,
                                          Handle<BigInt> nanoseconds,
                                          const char* method_name) {
  // 1. Let balanceResult be ? BalancePossiblyInfiniteDuration(days, hours,
  // minutes, seconds, milliseconds, microseconds, nanoseconds, largestUnit,
  // relativeTo).
  BalancePossiblyInfiniteDurationResult balance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, balance_result,
      BalancePossiblyInfiniteDuration(isolate, largest_unit, 0, nanoseconds,
                                      method_name),
      Nothing<TimeDurationRecord>());

  // 2. If balanceResult is positive overflow or negative overflow, then
  if (balance_result.overflow != BalanceOverflow::kNone) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<TimeDurationRecord>());
    // 3. Else,
  } else {
    // a. Return balanceResult.
    return Just(balance_result.value);
  }
}

Maybe<TimeDurationRecord> BalanceDuration(Isolate* isolate, Unit largest_unit,
                                          const TimeDurationRecord& dur1,
                                          const TimeDurationRecord& dur2,
                                          const char* method_name) {
  // Add the two TimeDurationRecord as BigInt in nanoseconds.
  Handle<BigInt> nanoseconds =
      BigInt::Add(isolate, TotalDurationNanoseconds(isolate, dur1, 0),
                  TotalDurationNanoseconds(isolate, dur2, 0))
          .ToHandleChecked();
  return BalanceDuration(isolate, largest_unit, nanoseconds, method_name);
}

// #sec-temporal-balanceduration
Maybe<TimeDurationRecord> BalanceDuration(Isolate* isolate, Unit largest_unit,
                                          Handle<Object> relative_to_obj,
                                          const TimeDurationRecord& value,
                                          const char* method_name) {
  // 1. Let balanceResult be ? BalancePossiblyInfiniteDuration(days, hours,
  // minutes, seconds, milliseconds, microseconds, nanoseconds, largestUnit,
  // relativeTo).
  BalancePossiblyInfiniteDurationResult balance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, balance_result,
      BalancePossiblyInfiniteDuration(isolate, largest_unit, relative_to_obj,
                                      value, method_name),
      Nothing<TimeDurationRecord>());

  // 2. If balanceResult is positive overflow or negative overflow, then
  if (balance_result.overflow != BalanceOverflow::kNone) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<TimeDurationRecord>());
    // 3. Else,
  } else {
    // a. Return balanceResult.
    return Just(balance_result.value);
  }
}

// sec-temporal-balancepossiblyinfiniteduration
Maybe<BalancePossiblyInfiniteDurationResult> BalancePossiblyInfiniteDuration(
    Isolate* isolate, Unit largest_unit, Handle<Object> relative_to_obj,
    const TimeDurationRecord& value, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  TimeDurationRecord duration = value;
  Handle<BigInt> nanoseconds;

  // 2. If Type(relativeTo) is Object and relativeTo has an
  // [[InitializedTemporalZonedDateTime]] internal slot, then
  if (IsJSTemporalZonedDateTime(*relative_to_obj)) {
    auto relative_to = Cast<JSTemporalZonedDateTime>(relative_to_obj);
    // a. Let endNs be ? AddZonedDateTime(relativeTo.[[Nanoseconds]],
    // relativeTo.[[TimeZone]], relativeTo.[[Calendar]], 0, 0, 0, days, hours,
    // minutes, seconds, milliseconds, microseconds, nanoseconds).
    Handle<BigInt> end_ns;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, end_ns,
        AddZonedDateTime(isolate, handle(relative_to->nanoseconds(), isolate),
                         handle(relative_to->time_zone(), isolate),
                         handle(relative_to->calendar(), isolate),
                         {0, 0, 0, duration}, method_name),
        Nothing<BalancePossiblyInfiniteDurationResult>());
    // b. Set nanoseconds to endNs − relativeTo.[[Nanoseconds]].
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, nanoseconds,
        BigInt::Subtract(isolate, end_ns,
                         handle(relative_to->nanoseconds(), isolate)),
        Nothing<BalancePossiblyInfiniteDurationResult>());
    // 3. Else,
  } else {
    // a. Set nanoseconds to ℤ(! TotalDurationNanoseconds(days, hours, minutes,
    // seconds, milliseconds, microseconds, nanoseconds, 0)).
    nanoseconds = TotalDurationNanoseconds(isolate, duration, 0);
  }

  // Call the BigInt version for the same process after step 4
  // The only value need to pass in is nanoseconds and days because
  // 1) step 4 and 5 use nanoseconds and days only, and
  // 2) step 6 is "Set hours, minutes, seconds, milliseconds, and microseconds
  // to 0."
  return BalancePossiblyInfiniteDuration(isolate, largest_unit, relative_to_obj,
                                         duration.days, nanoseconds,
                                         method_name);
}

// The special case of BalancePossiblyInfiniteDuration while the nanosecond is a
// large value and days contains non-zero values but the rest are 0.
// This version has no relative_to.
Maybe<BalancePossiblyInfiniteDurationResult> BalancePossiblyInfiniteDuration(
    Isolate* isolate, Unit largest_unit, Handle<Object> relative_to_obj,
    double days, Handle<BigInt> nanoseconds, const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 4. If largestUnit is one of "year", "month", "week", or "day", then
  if (largest_unit == Unit::kYear || largest_unit == Unit::kMonth ||
      largest_unit == Unit::kWeek || largest_unit == Unit::kDay) {
    // a. Let result be ? NanosecondsToDays(nanoseconds, relativeTo).
    NanosecondsToDaysResult result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        NanosecondsToDays(isolate, nanoseconds, relative_to_obj, method_name),
        Nothing<BalancePossiblyInfiniteDurationResult>());
    // b. Set days to result.[[Days]].
    days = result.days;
    // c. Set nanoseconds to result.[[Nanoseconds]].
    nanoseconds = BigInt::FromInt64(isolate, result.nanoseconds);
    // 5. Else,
  } else {
    // a. Set days to 0.
    days = 0;
  }
  // 6. Set hours, minutes, seconds, milliseconds, and microseconds to 0.
  DirectHandle<BigInt> thousand = BigInt::FromInt64(isolate, 1000);
  DirectHandle<BigInt> sixty = BigInt::FromInt64(isolate, 60);
  Handle<BigInt> zero = BigInt::FromInt64(isolate, 0);
  DirectHandle<BigInt> hours = zero;
  Handle<BigInt> minutes = zero;
  Handle<BigInt> seconds = zero;
  Handle<BigInt> milliseconds = zero;
  Handle<BigInt> microseconds = zero;

  // 7. If nanoseconds < 0, let sign be −1; else, let sign be 1.
  // 8. Set nanoseconds to abs(nanoseconds).
  int32_t sign = 1;
  if (nanoseconds->IsNegative()) {
    sign = -1;
    nanoseconds = BigInt::UnaryMinus(isolate, nanoseconds);
  }

  // 9 If largestUnit is "year", "month", "week", "day", or "hour", then
  switch (largest_unit) {
    case Unit::kYear:
    case Unit::kMonth:
    case Unit::kWeek:
    case Unit::kDay:
    case Unit::kHour:
      // a. Set microseconds to floor(nanoseconds / 1000).
      microseconds =
          BigInt::Divide(isolate, nanoseconds, thousand).ToHandleChecked();
      // b. Set nanoseconds to nanoseconds modulo 1000.
      nanoseconds =
          BigInt::Remainder(isolate, nanoseconds, thousand).ToHandleChecked();
      // c. Set milliseconds to floor(microseconds / 1000).
      milliseconds =
          BigInt::Divide(isolate, microseconds, thousand).ToHandleChecked();
      // d. Set microseconds to microseconds modulo 1000.
      microseconds =
          BigInt::Remainder(isolate, microseconds, thousand).ToHandleChecked();
      // e. Set seconds to floor(milliseconds / 1000).
      seconds =
          BigInt::Divide(isolate, milliseconds, thousand).ToHandleChecked();
      // f. Set milliseconds to milliseconds modulo 1000.
      milliseconds =
          BigInt::Remainder(isolate, milliseconds, thousand).ToHandleChecked();
      // g. Set minutes to floor(seconds, 60).
      minutes = BigInt::Divide(isolate, seconds, sixty).ToHandleChecked();
      // h. Set seconds to seconds modulo 60.
      seconds = BigInt::Remainder(isolate, seconds, sixty).ToHandleChecked();
      // i. Set hours to floor(minutes / 60).
      hours = BigInt::Divide(isolate, minutes, sixty).ToHandleChecked();
      // j. Set minutes to minutes modulo 60.
      minutes = BigInt::Remainder(isolate, minutes, sixty).ToHandleChecked();
      break;
    // 10. Else if largestUnit is "minute", then
    case Unit::kMinute:
      // a. Set microseconds to floor(nanoseconds / 1000).
      microseconds =
          BigInt::Divide(isolate, nanoseconds, thousand).ToHandleChecked();
      // b. Set nanoseconds to nanoseconds modulo 1000.
      nanoseconds =
          BigInt::Remainder(isolate, nanoseconds, thousand).ToHandleChecked();
      // c. Set milliseconds to floor(microseconds / 1000).
      milliseconds =
          BigInt::Divide(isolate, microseconds, thousand).ToHandleChecked();
      // d. Set microseconds to microseconds modulo 1000.
      microseconds =
          BigInt::Remainder(isolate, microseconds, thousand).ToHandleChecked();
      // e. Set seconds to floor(milliseconds / 1000).
      seconds =
          BigInt::Divide(isolate, milliseconds, thousand).ToHandleChecked();
      // f. Set milliseconds to milliseconds modulo 1000.
      milliseconds =
          BigInt::Remainder(isolate, milliseconds, thousand).ToHandleChecked();
      // g. Set minutes to floor(seconds / 60).
      minutes = BigInt::Divide(isolate, seconds, sixty).ToHandleChecked();
      // h. Set seconds to seconds modulo 60.
      seconds = BigInt::Remainder(isolate, seconds, sixty).ToHandleChecked();
      break;
    // 11. Else if largestUnit is "second", then
    case Unit::kSecond:
      // a. Set microseconds to floor(nanoseconds / 1000).
      microseconds =
          BigInt::Divide(isolate, nanoseconds, thousand).ToHandleChecked();
      // b. Set nanoseconds to nanoseconds modulo 1000.
      nanoseconds =
          BigInt::Remainder(isolate, nanoseconds, thousand).ToHandleChecked();
      // c. Set milliseconds to floor(microseconds / 1000).
      milliseconds =
          BigInt::Divide(isolate, microseconds, thousand).ToHandleChecked();
      // d. Set microseconds to microseconds modulo 1000.
      microseconds =
          BigInt::Remainder(isolate, microseconds, thousand).ToHandleChecked();
      // e. Set seconds to floor(milliseconds / 1000).
      seconds =
          BigInt::Divide(isolate, milliseconds, thousand).ToHandleChecked();
      // f. Set milliseconds to milliseconds modulo 1000.
      milliseconds =
          BigInt::Remainder(isolate, milliseconds, thousand).ToHandleChecked();
      break;
    // 12. Else if largestUnit is "millisecond", then
    case Unit::kMillisecond:
      // a. Set microseconds to floor(nanoseconds / 1000).
      microseconds =
          BigInt::Divide(isolate, nanoseconds, thousand).ToHandleChecked();
      // b. Set nanoseconds to nanoseconds modulo 1000.
      nanoseconds =
          BigInt::Remainder(isolate, nanoseconds, thousand).ToHandleChecked();
      // c. Set milliseconds to floor(microseconds / 1000).
      milliseconds =
          BigInt::Divide(isolate, microseconds, thousand).ToHandleChecked();
      // d. Set microseconds to microseconds modulo 1000.
      microseconds =
          BigInt::Remainder(isolate, microseconds, thousand).ToHandleChecked();
      break;
    // 13. Else if largestUnit is "microsecond", then
    case Unit::kMicrosecond:
      // a. Set microseconds to floor(nanoseconds / 1000).
      microseconds =
          BigInt::Divide(isolate, nanoseconds, thousand).ToHandleChecked();
      // b. Set nanoseconds to nanoseconds modulo 1000.
      nanoseconds =
          BigInt::Remainder(isolate, nanoseconds, thousand).ToHandleChecked();
      break;
    // 14. Else,
    case Unit::kNanosecond:
      // a. Assert: largestUnit is "nanosecond".
      break;
    case Unit::kAuto:
    case Unit::kNotPresent:
      UNREACHABLE();
  }
  // 15. For each value v of « days, hours, minutes, seconds, milliseconds,
  // microseconds, nanoseconds », do a. If 𝔽(v) is not finite, then i. If sign
  // = 1, then
  // 1. Return positive overflow.
  // ii. Else if sign = -1, then
  // 1. Return negative overflow.
  double hours_value = Object::NumberValue(*BigInt::ToNumber(isolate, hours));
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
```