Response: The user wants me to summarize the functionality of the C++ code provided. This is the second part of a 13-part file, so the functionality might be related to the previous part.

The code defines several functions related to the `Temporal` proposal for JavaScript, which aims to improve date and time handling.

Based on the function names and their implementations, I can identify the following functionalities:

1. **String formatting for Temporal.Time:** Functions like `FormatSecondsStringPart` and `TemporalTimeToString` handle converting `Temporal.Time` objects into string representations with different levels of precision.
2. **Conversion from `Temporal.Instant` to `Temporal.PlainDateTime`:** The `BuiltinTimeZoneGetPlainDateTimeFor` function is responsible for converting an instant in time to a date and time in a specific timezone and calendar.
3. **Handling ambiguous date/time lookups:**  The `GetPossibleInstantsFor` and `DisambiguatePossibleInstants` functions deal with scenarios where a given date and time might correspond to multiple instants (due to DST transitions, for example) and provide mechanisms to choose the correct instant based on disambiguation strategies ("earlier", "later", "compatible", "reject").
4. **Retrieving Calendar information:**  The `GetTemporalCalendarWithISODefault` function helps in extracting the `Temporal.Calendar` object from various Temporal types or using the ISO 8601 calendar as a default.
5. **Preparing Temporal fields:** The `PrepareTemporalFields` and `PreparePartialTemporalFields` functions are used to extract and validate fields from JavaScript objects to create Temporal objects. They handle default values and type conversions.
6. **Creating Temporal objects from fields:** The `DateFromFields`, `YearMonthFromFields`, and `MonthDayFromFields` functions delegate to the calendar's methods to construct corresponding Temporal objects.
7. **Handling overflow and offset options:** Functions like `ToTemporalOverflow`, `ToTemporalOffset`, and `ToTemporalDisambiguation` process options objects to determine how to handle out-of-range values and time zone offsets.
8. **Conversion to `Temporal.Instant`:** The `ToTemporalInstant` function converts various types (including other Temporal objects and strings) to a `Temporal.Instant`.
9. **Conversion to `Temporal.Calendar`:** The `ToTemporalCalendar` function ensures that an input is a valid `Temporal.Calendar` object.
10. **Conversion to `Temporal.Date`:** The `ToTemporalDate` function converts various types to a `Temporal.PlainDate`.
11. **Integer validation:** The `IsIntegralNumber` function checks if a given JavaScript value is an integer.
12. **Safe integer conversion:** The `ToIntegerWithoutRounding` function converts a JavaScript value to an integer and throws an error if it's not a valid integer.
13. **Time regulation:** The `RegulateTime` function adjusts time components based on the provided overflow behavior ("constrain" or "reject").
14. **Conversion to `Temporal.Time`:** The `ToTemporalTime` function converts various types to a `Temporal.PlainTime`.
15. **Conversion to `Temporal.Duration` (Record):** The `ToTemporalDurationRecord` function converts an object or string to a `DurationRecord`, which is likely an internal representation of a `Temporal.Duration`.
16. **Conversion to `Temporal.Duration`:** The `ToTemporalDuration` function converts various types to a `Temporal.Duration`.
17. **Conversion to `Temporal.TimeZone`:** The `ToTemporalTimeZone` function ensures that an input is a valid `Temporal.TimeZone` object.
18. **Retrieving system date/time and zoned date/time:** The `SystemDateTime` and `SystemZonedDateTime` functions get the current date and time in the system's timezone.
19. **Comparing Temporal values:** The `CompareResultToSign` function converts a comparison result enum to an integer.
20. **Formatting TimeZone offsets:** The `FormatTimeZoneOffsetString` function converts nanosecond offsets into human-readable offset strings like "+HH:MM" or "-HH:MM:SS.mmm".

Now, let's provide some JavaScript examples related to these functionalities.
This part of the C++ code for `v8/src/objects/js-temporal-objects.cc` focuses on implementing core functionalities for the **Temporal API** in JavaScript, specifically related to **time zones, conversions between Temporal types, and parsing/formatting**.

Here's a breakdown of its functions:

**1. String Representation of `Temporal.Time`:**

*   **`FormatSecondsStringPart`**:  Formats the seconds, milliseconds, microseconds, and nanoseconds part of a time string based on the desired precision.
*   **`TemporalTimeToString`**: Converts a `TimeRecord` (internal representation of time) or a `JSTemporalPlainTime` object into a string representation according to the specified precision.

**JavaScript Example:**

```javascript
const time = new Temporal.PlainTime(10, 30, 45, 123, 456, 789);

console.log(time.toString()); // Output: 10:30:45.123456789
console.log(time.toString({ smallestUnit: 'millisecond' })); // Output: 10:30:45.123
```

**2. Conversion from `Temporal.Instant` to `Temporal.PlainDateTime` with Time Zones:**

*   **`BuiltinTimeZoneGetPlainDateTimeFor`**:  This crucial function takes a `Temporal.Instant` (a point in time), a `Temporal.TimeZone`, and a `Temporal.Calendar` and calculates the corresponding `Temporal.PlainDateTime` in that specific time zone and calendar. It handles the complexities of time zone offsets.

**JavaScript Example:**

```javascript
const instant = Temporal.Instant.fromEpochSeconds(1678886400); // Some instant
const timeZone = Temporal.TimeZone.from('America/Los_Angeles');
const calendar = Temporal.Calendar.from('iso8601');

const dateTime = timeZone.getPlainDateTimeFor(instant, calendar);
console.log(dateTime.toString()); // Output will be the date and time in Los Angeles at the given instant.
```

**3. Handling Ambiguous Date/Time Lookups (Time Zone Disambiguation):**

*   **`GetPossibleInstantsFor`**:  When converting a `Temporal.PlainDateTime` to an `Temporal.Instant`, there might be multiple possible instants due to Daylight Saving Time (DST) transitions. This function asks the time zone object for the potential instants.
*   **`DisambiguatePossibleInstants`**: Takes the list of possible instants and a disambiguation strategy ("earlier", "later", "compatible", "reject") to determine the correct `Temporal.Instant`.

**JavaScript Example:**

```javascript
const timeZone = Temporal.TimeZone.from('America/New_York');
const dateTime = new Temporal.PlainDateTime(2023, 3, 12, 2, 30); // Time during DST transition

// Trying to get an instant without disambiguation might be ambiguous
// You'd typically use the 'disambiguation' option in a method like 'toZonedDateTime'

const possibleInstants = timeZone.getPossibleInstantsFor(dateTime);
console.log(possibleInstants.length); // Output: 2 (due to the DST gap)

const instantEarlier = timeZone.getInstantFor(dateTime, { disambiguation: 'earlier' });
const instantLater = timeZone.getInstantFor(dateTime, { disambiguation: 'later' });

console.log(instantEarlier.epochSeconds);
console.log(instantLater.epochSeconds); // These will be different
```

**4. Working with `Temporal.Calendar`:**

*   **`GetTemporalCalendarWithISODefault`**:  Retrieves the `Temporal.Calendar` object from a Temporal object or uses the ISO 8601 calendar if no calendar is specified.

**JavaScript Example:**

```javascript
const date = new Temporal.PlainDate(2023, 3, 15);
const calendar = Temporal.Calendar.from('iso8601');
const zonedDateTime = Temporal.ZonedDateTime.from('2023-03-15T10:00:00-08:00[America/Los_Angeles]');

console.log(Temporal.Calendar.getTemporalCalendarWithISODefault(date).id); // Output: iso8601
console.log(Temporal.Calendar.getTemporalCalendarWithISODefault(zonedDateTime).id); // Output: iso8601
```

**5. Preparing and Creating Temporal Objects from Fields:**

*   **`PrepareTemporalFieldsOrPartial`**, **`PrepareTemporalFields`**, **`PreparePartialTemporalFields`**: These functions handle extracting and validating properties (year, month, day, hour, etc.) from JavaScript objects to create Temporal objects. They deal with default values and required fields.
*   **`FromFields`**, **`DateFromFields`**, **`YearMonthFromFields`**, **`MonthDayFromFields`**: These functions are used to create specific Temporal types (`PlainDate`, `PlainYearMonth`, `PlainMonthDay`) by calling corresponding methods on the `Temporal.Calendar` object.

**JavaScript Example:**

```javascript
const calendar = new Temporal.Calendar('iso8601');
const fields = { year: 2023, month: 3, day: 15 };
const date = calendar.dateFromFields(fields);
console.log(date.toString()); // Output: 2023-03-15

const partialFields = { monthCode: 'M03', day: 15 };
const monthDay = calendar.monthDayFromFields(partialFields);
console.log(monthDay.toString()); // Output: 03-15
```

**6. Handling Options Objects (`overflow`, `offset`, `disambiguation`):**

*   **`ToTemporalOverflow`**, **`ToTemporalOffset`**, **`ToTemporalDisambiguation`**: These helper functions extract and validate specific options from option objects used in various Temporal methods. They define how to handle out-of-range values, time zone offsets, and ambiguous time zone conversions.

**JavaScript Example:**

```javascript
const time = new Temporal.PlainTime(25, 0, 0); // Invalid hour
try {
  time.toPlainTime({ overflow: 'reject' }); // This will throw an error
} catch (e) {
  console.error(e);
}

const constrainedTime = time.toPlainTime({ overflow: 'constrain' });
console.log(constrainedTime.toString()); // Output: 23:59:59.999999999 (or similar, depending on implementation details)
```

**7. Conversion to `Temporal.Instant`:**

*   **`ToTemporalInstant`**: Converts various JavaScript values (including other Temporal objects and strings) into a `Temporal.Instant`.

**JavaScript Example:**

```javascript
const instantFromString = Temporal.Instant.from('2023-03-15T10:00:00Z');
const zonedDateTime = Temporal.ZonedDateTime.from('2023-03-15T10:00:00-08:00[America/Los_Angeles]');
const instantFromZonedDateTime = Temporal.Instant.from(zonedDateTime);

console.log(instantFromString.epochSeconds);
console.log(instantFromZonedDateTime.epochSeconds); // Should be the same epoch seconds
```

**8. Conversion to `Temporal.Calendar`:**

*   **`ToTemporalCalendar`**: Ensures that a given JavaScript value is a valid `Temporal.Calendar` object. It can handle calendar identifiers (like "iso8601") or existing `Temporal.Calendar` instances.

**JavaScript Example:**

```javascript
const calendarISO = Temporal.Calendar.from('iso8601');
const calendarJapanese = Temporal.Calendar.from('japanese');

console.log(Temporal.Calendar.from('iso8601').id); // Output: iso8601
console.log(Temporal.Calendar.from(calendarJapanese).id); // Output: japanese
```

**9. Conversion to `Temporal.PlainDate`:**

*   **`ToTemporalDate`**: Converts various JavaScript values (including other Temporal objects, strings) to a `Temporal.PlainDate`. It respects the `overflow` option.

**JavaScript Example:**

```javascript
const dateFromString = Temporal.PlainDate.from('2023-03-15');
const dateTime = Temporal.PlainDateTime.from('2023-03-15T10:00:00');
const dateFromDateTime = Temporal.PlainDate.from(dateTime);

console.log(dateFromString.toString());
console.log(dateFromDateTime.toString());
```

**10. Integer Validation and Conversion:**

*   **`IsIntegralNumber`**: Checks if a JavaScript value is an integer.
*   **`ToIntegerWithoutRounding`**: Converts a JavaScript value to an integer, throwing an error if it's not a valid integer.

**JavaScript Example (Internal Use, less direct JS API):**

These are used internally by the Temporal implementation to ensure correct type handling. You'd see their effects indirectly through the behavior of Temporal methods.

**11. Time Regulation:**

*   **`RegulateTime`**: Ensures that the components of a time (hour, minute, second, etc.) are within valid ranges, applying either "constrain" (clamp values) or "reject" (throw error) behavior.

**JavaScript Example (Indirect):**

```javascript
const time = new Temporal.PlainTime(10, 70, 0); // Invalid minutes
const constrainedTime = time.toPlainTime({ overflow: 'constrain' });
console.log(constrainedTime.toString()); // Output: 10:59:59.999... (or similar)

try {
  time.toPlainTime({ overflow: 'reject' }); // Throws an error
} catch (e) {
  console.error(e);
}
```

**12. Conversion to `Temporal.PlainTime`:**

*   **`ToTemporalTime`**: Converts various JavaScript values to a `Temporal.PlainTime`.

**JavaScript Example:**

```javascript
const timeFromString = Temporal.PlainTime.from('10:30:00');
const dateTime = Temporal.PlainDateTime.from('2023-03-15T10:30:00');
const timeFromDateTime = Temporal.PlainTime.from(dateTime);

console.log(timeFromString.toString());
console.log(timeFromDateTime.toString());
```

**13. Conversion to `Temporal.Duration` (Record and Object):**

*   **`ToTemporalDurationRecord`**: Converts a JavaScript value to an internal `DurationRecord` representation.
*   **`ToTemporalDuration`**: Converts a JavaScript value to a `Temporal.Duration` object.

**JavaScript Example:**

```javascript
const durationFromString = Temporal.Duration.from('P1Y2M3DT4H5M6S');
const durationFromObject = Temporal.Duration.from({ years: 1, months: 2, days: 3 });

console.log(durationFromString.toString());
console.log(durationFromObject.toString());
```

**14. Conversion to `Temporal.TimeZone`:**

*   **`ToTemporalTimeZone`**: Ensures that a given JavaScript value is a valid `Temporal.TimeZone` object, handling IANA time zone names, UTC, and offset strings.

**JavaScript Example:**

```javascript
const timeZoneLosAngeles = Temporal.TimeZone.from('America/Los_Angeles');
const timeZoneUTC = Temporal.TimeZone.from('UTC');
const timeZoneOffset = Temporal.TimeZone.from('-08:00');

console.log(timeZoneLosAngeles.id);
console.log(timeZoneUTC.id);
console.log(timeZoneOffset.id);
```

**15. Getting System Date/Time and Zoned Date/Time:**

*   **`SystemDateTime`**: Returns the current date and time in the system's time zone and a specified calendar.
*   **`SystemZonedDateTime`**: Returns the current date and time as a `Temporal.ZonedDateTime` in the system's time zone and a specified calendar.

**JavaScript Example:**

```javascript
const nowDateTime = Temporal.Now.plainDateTimeISO();
const nowZonedDateTime = Temporal.Now.zonedDateTimeISO();

console.log(nowDateTime.toString());
console.log(nowZonedDateTime.toString());
```

**16. Formatting Time Zone Offsets:**

*   **`FormatTimeZoneOffsetString`**: Converts a numeric time zone offset (in nanoseconds) into a string representation like "+HH:MM" or "-HH:MM:SS.milliseconds".

**JavaScript Example (Internal Use):**

This is used internally by the Temporal implementation to format time zone offsets for display or serialization. You'd see its effects in the output of methods like `zonedDateTime.toString()`.

In summary, this section of the C++ code is crucial for implementing the core logic of the Temporal API in V8, handling conversions, time zone calculations, and string formatting, bringing the power of precise date and time manipulation to JavaScript.

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共13部分，请归纳一下它的功能
```

### 源代码
```
fraction %= divisor;
      divisor /= 10;
    }
  }
  // 7. Return the string-concatenation of secondsString, the code unit 0x002E
  // (FULL STOP), and fraction.
}

// #sec-temporal-temporaltimetostring
Handle<String> TemporalTimeToString(Isolate* isolate, const TimeRecord& time,
                                    Precision precision) {
  // 1. Assert: hour, minute, second, millisecond, microsecond and nanosecond
  // are integers.
  IncrementalStringBuilder builder(isolate);
  // 2. Let hour be ToZeroPaddedDecimalString(hour, 2).
  ToZeroPaddedDecimalString(&builder, time.hour, 2);
  builder.AppendCharacter(':');
  // 3. Let minute be ToZeroPaddedDecimalString(minute, 2).
  ToZeroPaddedDecimalString(&builder, time.minute, 2);
  // 4. Let seconds be ! FormatSecondsStringPart(second, millisecond,
  // microsecond, nanosecond, precision).
  FormatSecondsStringPart(&builder, time.second, time.millisecond,
                          time.microsecond, time.nanosecond, precision);
  // 5. Return the string-concatenation of hour, the code unit 0x003A (COLON),
  // minute, and seconds.
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

Handle<String> TemporalTimeToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Precision precision) {
  return TemporalTimeToString(
      isolate,
      {temporal_time->iso_hour(), temporal_time->iso_minute(),
       temporal_time->iso_second(), temporal_time->iso_millisecond(),
       temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()},
      precision);
}

}  // namespace

namespace temporal {
MaybeHandle<JSTemporalPlainDateTime> BuiltinTimeZoneGetPlainDateTimeFor(
    Isolate* isolate, Handle<JSReceiver> time_zone,
    Handle<JSTemporalInstant> instant, DirectHandle<JSReceiver> calendar,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let offsetNanoseconds be ? GetOffsetNanosecondsFor(timeZone, instant).
  int64_t offset_nanoseconds;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_nanoseconds,
      GetOffsetNanosecondsFor(isolate, time_zone, instant, method_name),
      Handle<JSTemporalPlainDateTime>());
  // 2. Let result be ! GetISOPartsFromEpoch(instant.[[Nanoseconds]]).
  DateTimeRecord result =
      GetISOPartsFromEpoch(isolate, handle(instant->nanoseconds(), isolate));

  // 3. Set result to ! BalanceISODateTime(result.[[Year]], result.[[Month]],
  // result.[[Day]], result.[[Hour]], result.[[Minute]], result.[[Second]],
  // result.[[Millisecond]], result.[[Microsecond]], result.[[Nanosecond]] +
  // offsetNanoseconds).

  // Note: Since offsetNanoseconds is bounded 86400x 10^9, the
  // result of result.[[Nanosecond]] + offsetNanoseconds may overflow int32_t
  // Therefore we distribute the sum to other fields below to make sure it won't
  // overflow each of the int32_t fields. But it will leave each field to be
  // balanced by BalanceISODateTime
  result.time.nanosecond += offset_nanoseconds % 1000;
  result.time.microsecond += (offset_nanoseconds / 1000) % 1000;
  result.time.millisecond += (offset_nanoseconds / 1000000L) % 1000;
  result.time.second += (offset_nanoseconds / 1000000000L) % 60;
  result.time.minute += (offset_nanoseconds / 60000000000L) % 60;
  result.time.hour += (offset_nanoseconds / 3600000000000L) % 24;
  result.date.day += (offset_nanoseconds / 86400000000000L);

  result = BalanceISODateTime(isolate, result);
  // 4. Return ? CreateTemporalDateTime(result.[[Year]], result.[[Month]],
  // result.[[Day]], result.[[Hour]], result.[[Minute]], result.[[Second]],
  // result.[[Millisecond]], result.[[Microsecond]], result.[[Nanosecond]],
  // calendar).
  return temporal::CreateTemporalDateTime(isolate, result, calendar);
}

}  // namespace temporal

namespace {
// #sec-temporal-getpossibleinstantsfor
MaybeHandle<FixedArray> GetPossibleInstantsFor(Isolate* isolate,
                                               Handle<JSReceiver> time_zone,
                                               Handle<Object> date_time) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let possibleInstants be ? Invoke(timeZone, "getPossibleInstantsFor", «
  // dateTime »).
  Handle<Object> function;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, function,
      Object::GetProperty(isolate, time_zone,
                          isolate->factory()->getPossibleInstantsFor_string()));
  if (!IsCallable(*function)) {
    THROW_NEW_ERROR(
        isolate,
        NewTypeError(MessageTemplate::kCalledNonCallable,
                     isolate->factory()->getPossibleInstantsFor_string()));
  }
  Handle<Object> possible_instants;
  {
    Handle<Object> argv[] = {date_time};
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, possible_instants,
        Execution::Call(isolate, function, time_zone, arraysize(argv), argv));
  }

  // Step 4-6 of GetPossibleInstantsFor is implemented inside
  // temporal_instant_fixed_array_from_iterable.
  {
    Handle<Object> argv[] = {possible_instants};
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, possible_instants,
        Execution::CallBuiltin(
            isolate, isolate->temporal_instant_fixed_array_from_iterable(),
            possible_instants, arraysize(argv), argv));
  }
  DCHECK(IsFixedArray(*possible_instants));
  // 7. Return list.
  return Cast<FixedArray>(possible_instants);
}

// #sec-temporal-disambiguatepossibleinstants
MaybeHandle<JSTemporalInstant> DisambiguatePossibleInstants(
    Isolate* isolate, Handle<FixedArray> possible_instants,
    Handle<JSReceiver> time_zone, Handle<Object> date_time_obj,
    Disambiguation disambiguation, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: dateTime has an [[InitializedTemporalDateTime]] internal slot.
  DCHECK(IsJSTemporalPlainDateTime(*date_time_obj));
  auto date_time = Cast<JSTemporalPlainDateTime>(date_time_obj);

  // 2. Let n be possibleInstants's length.
  int32_t n = possible_instants->length();

  // 3. If n = 1, then
  if (n == 1) {
    // a. Return possibleInstants[0].
    Handle<Object> ret_obj(possible_instants->get(0), isolate);
    DCHECK(IsJSTemporalInstant(*ret_obj));
    return Cast<JSTemporalInstant>(ret_obj);
  }
  // 4. If n ≠ 0, then
  if (n != 0) {
    // a. If disambiguation is "earlier" or "compatible", then
    if (disambiguation == Disambiguation::kEarlier ||
        disambiguation == Disambiguation::kCompatible) {
      // i. Return possibleInstants[0].
      Handle<Object> ret_obj(possible_instants->get(0), isolate);
      DCHECK(IsJSTemporalInstant(*ret_obj));
      return Cast<JSTemporalInstant>(ret_obj);
    }
    // b. If disambiguation is "later", then
    if (disambiguation == Disambiguation::kLater) {
      // i. Return possibleInstants[n − 1].
      Handle<Object> ret_obj(possible_instants->get(n - 1), isolate);
      DCHECK(IsJSTemporalInstant(*ret_obj));
      return Cast<JSTemporalInstant>(ret_obj);
    }
    // c. Assert: disambiguation is "reject".
    DCHECK_EQ(disambiguation, Disambiguation::kReject);
    // d. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 5. Assert: n = 0.
  DCHECK_EQ(n, 0);
  // 6. If disambiguation is "reject", then
  if (disambiguation == Disambiguation::kReject) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 7. Let epochNanoseconds be ! GetEpochFromISOParts(dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]]).
  Handle<BigInt> epoch_nanoseconds = GetEpochFromISOParts(
      isolate,
      {{date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
       {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
        date_time->iso_millisecond(), date_time->iso_microsecond(),
        date_time->iso_nanosecond()}});

  // 8. Let dayBeforeNs be epochNanoseconds - ℤ(nsPerDay).
  Handle<BigInt> one_day_in_ns = BigInt::FromUint64(isolate, 86400000000000ULL);
  DirectHandle<BigInt> day_before_ns =
      BigInt::Subtract(isolate, epoch_nanoseconds, one_day_in_ns)
          .ToHandleChecked();
  // 9. If ! IsValidEpochNanoseconds(dayBeforeNs) is false, throw a RangeError
  // exception.
  if (!IsValidEpochNanoseconds(isolate, day_before_ns)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 10. Let dayBefore be ! CreateTemporalInstant(dayBeforeNs).
  Handle<JSTemporalInstant> day_before =
      temporal::CreateTemporalInstant(isolate, day_before_ns).ToHandleChecked();
  // 11. Let dayAfterNs be epochNanoseconds + ℤ(nsPerDay).
  DirectHandle<BigInt> day_after_ns =
      BigInt::Add(isolate, epoch_nanoseconds, one_day_in_ns).ToHandleChecked();
  // 12. If ! IsValidEpochNanoseconds(dayAfterNs) is false, throw a RangeError
  // exception.
  if (!IsValidEpochNanoseconds(isolate, day_after_ns)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 13. Let dayAfter be ! CreateTemporalInstant(dayAfterNs).
  Handle<JSTemporalInstant> day_after =
      temporal::CreateTemporalInstant(isolate, day_after_ns).ToHandleChecked();
  // 10. Let offsetBefore be ? GetOffsetNanosecondsFor(timeZone, dayBefore).
  int64_t offset_before;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_before,
      GetOffsetNanosecondsFor(isolate, time_zone, day_before, method_name),
      Handle<JSTemporalInstant>());
  // 11. Let offsetAfter be ? GetOffsetNanosecondsFor(timeZone, dayAfter).
  int64_t offset_after;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_after,
      GetOffsetNanosecondsFor(isolate, time_zone, day_after, method_name),
      Handle<JSTemporalInstant>());

  // 12. Let nanoseconds be offsetAfter − offsetBefore.
  double nanoseconds = offset_after - offset_before;

  // 13. If disambiguation is "earlier", then
  if (disambiguation == Disambiguation::kEarlier) {
    // a. Let earlier be ? AddDateTime(dateTime.[[ISOYear]],
    // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
    // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
    // dateTime.[[ISOMillisecond]],
    // dateTime.[[ISOMicrosecond]], dateTime.[[ISONanosecond]],
    // dateTime.[[Calendar]], 0, 0, 0, 0, 0, 0, 0, 0, 0, −nanoseconds,
    // undefined).
    DateTimeRecord earlier;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, earlier,
        AddDateTime(
            isolate,
            {{date_time->iso_year(), date_time->iso_month(),
              date_time->iso_day()},
             {date_time->iso_hour(), date_time->iso_minute(),
              date_time->iso_second(), date_time->iso_millisecond(),
              date_time->iso_microsecond(), date_time->iso_nanosecond()}},
            handle(date_time->calendar(), isolate),
            {0, 0, 0, {0, 0, 0, 0, 0, 0, -nanoseconds}},
            isolate->factory()->undefined_value()),
        Handle<JSTemporalInstant>());
    // See https://github.com/tc39/proposal-temporal/issues/1816
    // b. Let earlierDateTime be ? CreateTemporalDateTime(earlier.[[Year]],
    // earlier.[[Month]], earlier.[[Day]], earlier.[[Hour]], earlier.[[Minute]],
    // earlier.[[Second]], earlier.[[Millisecond]], earlier.[[Microsecond]],
    // earlier.[[Nanosecond]], dateTime.[[Calendar]]).
    Handle<JSTemporalPlainDateTime> earlier_date_time;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, earlier_date_time,
        temporal::CreateTemporalDateTime(
            isolate, earlier, handle(date_time->calendar(), isolate)));

    // c. Set possibleInstants to ? GetPossibleInstantsFor(timeZone,
    // earlierDateTime).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, possible_instants,
        GetPossibleInstantsFor(isolate, time_zone, earlier_date_time));

    // d. If possibleInstants is empty, throw a RangeError exception.
    if (possible_instants->length() == 0) {
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
    }
    // e. Return possibleInstants[0].
    Handle<Object> ret_obj(possible_instants->get(0), isolate);
    DCHECK(IsJSTemporalInstant(*ret_obj));
    return Cast<JSTemporalInstant>(ret_obj);
  }
  // 14. Assert: disambiguation is "compatible" or "later".
  DCHECK(disambiguation == Disambiguation::kCompatible ||
         disambiguation == Disambiguation::kLater);
  // 15. Let later be ? AddDateTime(dateTime.[[ISOYear]], dateTime.[[ISOMonth]],
  // dateTime.[[ISODay]], dateTime.[[ISOHour]], dateTime.[[ISOMinute]],
  // dateTime.[[ISOSecond]], dateTime.[[ISOMillisecond]],
  // dateTime.[[ISOMicrosecond]], dateTime.[[ISONanosecond]],
  // dateTime.[[Calendar]], 0, 0, 0, 0, 0, 0, 0, 0, 0, nanoseconds, undefined).
  DateTimeRecord later;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, later,
      AddDateTime(isolate,
                  {{date_time->iso_year(), date_time->iso_month(),
                    date_time->iso_day()},
                   {date_time->iso_hour(), date_time->iso_minute(),
                    date_time->iso_second(), date_time->iso_millisecond(),
                    date_time->iso_microsecond(), date_time->iso_nanosecond()}},
                  handle(date_time->calendar(), isolate),
                  {0, 0, 0, {0, 0, 0, 0, 0, 0, nanoseconds}},
                  isolate->factory()->undefined_value()),
      Handle<JSTemporalInstant>());

  // See https://github.com/tc39/proposal-temporal/issues/1816
  // 16. Let laterDateTime be ? CreateTemporalDateTime(later.[[Year]],
  // later.[[Month]], later.[[Day]], later.[[Hour]], later.[[Minute]],
  // later.[[Second]], later.[[Millisecond]], later.[[Microsecond]],
  // later.[[Nanosecond]], dateTime.[[Calendar]]).

  Handle<JSTemporalPlainDateTime> later_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, later_date_time,
      temporal::CreateTemporalDateTime(isolate, later,
                                       handle(date_time->calendar(), isolate)));
  // 17. Set possibleInstants to ? GetPossibleInstantsFor(timeZone,
  // laterDateTime).
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, possible_instants,
      GetPossibleInstantsFor(isolate, time_zone, later_date_time));
  // 18. Set n to possibleInstants's length.
  n = possible_instants->length();
  // 19. If n = 0, throw a RangeError exception.
  if (n == 0) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 20. Return possibleInstants[n − 1].
  Handle<Object> ret_obj(possible_instants->get(n - 1), isolate);
  DCHECK(IsJSTemporalInstant(*ret_obj));
  return Cast<JSTemporalInstant>(ret_obj);
}

// #sec-temporal-gettemporalcalendarwithisodefault
MaybeHandle<JSReceiver> GetTemporalCalendarWithISODefault(
    Isolate* isolate, Handle<JSReceiver> item, const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 1. If item has an [[InitializedTemporalDate]],
  // [[InitializedTemporalDateTime]], [[InitializedTemporalMonthDay]],
  // [[InitializedTemporalTime]], [[InitializedTemporalYearMonth]], or
  // [[InitializedTemporalZonedDateTime]] internal slot, then a. Return
  // item.[[Calendar]].
  if (IsJSTemporalPlainDate(*item)) {
    return handle(Cast<JSTemporalPlainDate>(item)->calendar(), isolate);
  }
  if (IsJSTemporalPlainDateTime(*item)) {
    return handle(Cast<JSTemporalPlainDateTime>(item)->calendar(), isolate);
  }
  if (IsJSTemporalPlainMonthDay(*item)) {
    return handle(Cast<JSTemporalPlainMonthDay>(item)->calendar(), isolate);
  }
  if (IsJSTemporalPlainTime(*item)) {
    return handle(Cast<JSTemporalPlainTime>(item)->calendar(), isolate);
  }
  if (IsJSTemporalPlainYearMonth(*item)) {
    return handle(Cast<JSTemporalPlainYearMonth>(item)->calendar(), isolate);
  }
  if (IsJSTemporalZonedDateTime(*item)) {
    return handle(Cast<JSTemporalZonedDateTime>(item)->calendar(), isolate);
  }

  // 2. Let calendar be ? Get(item, "calendar").
  Handle<Object> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      JSReceiver::GetProperty(isolate, item, factory->calendar_string()));
  // 3. Return ? ToTemporalCalendarWithISODefault(calendar).
  return ToTemporalCalendarWithISODefault(isolate, calendar, method_name);
}

enum class RequiredFields {
  kNone,
  kTimeZone,
  kTimeZoneAndOffset,
  kDay,
  kYearAndDay
};

// The common part of PrepareTemporalFields and PreparePartialTemporalFields
// #sec-temporal-preparetemporalfields
// #sec-temporal-preparepartialtemporalfields
V8_WARN_UNUSED_RESULT MaybeHandle<JSReceiver> PrepareTemporalFieldsOrPartial(
    Isolate* isolate, Handle<JSReceiver> fields,
    DirectHandle<FixedArray> field_names, RequiredFields required,
    bool partial) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 1. Let result be OrdinaryObjectCreate(null).
  Handle<JSReceiver> result = isolate->factory()->NewJSObjectWithNullProto();
  // 2. Let any be false.
  bool any = false;
  // 3. For each value property of fieldNames, do
  int length = field_names->length();
  for (int i = 0; i < length; i++) {
    Handle<Object> property_obj(field_names->get(i), isolate);
    Handle<String> property = Cast<String>(property_obj);
    // a. Let value be ? Get(fields, property).
    Handle<Object> value;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, value, JSReceiver::GetProperty(isolate, fields, property));

    // b. If value is undefined, then
    if (IsUndefined(*value)) {
      // This part is only for PrepareTemporalFields
      // Skip for the case of PreparePartialTemporalFields.
      if (partial) continue;

      // i. If requiredFields contains property, then
      if (((required == RequiredFields::kDay ||
            required == RequiredFields::kYearAndDay) &&
           String::Equals(isolate, property, factory->day_string())) ||
          ((required == RequiredFields::kTimeZone ||
            required == RequiredFields::kTimeZoneAndOffset) &&
           String::Equals(isolate, property, factory->timeZone_string())) ||
          (required == RequiredFields::kTimeZoneAndOffset &&
           String::Equals(isolate, property, factory->offset_string())) ||
          (required == RequiredFields::kYearAndDay &&
           String::Equals(isolate, property, factory->year_string()))) {
        // 1. Throw a TypeError exception.
        THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
      }
      // ii. Else,
      // 1. If property is in the Property column of Table 13, then
      // a. Set value to the corresponding Default value of the same row.
      if (String::Equals(isolate, property, factory->hour_string()) ||
          String::Equals(isolate, property, factory->minute_string()) ||
          String::Equals(isolate, property, factory->second_string()) ||
          String::Equals(isolate, property, factory->millisecond_string()) ||
          String::Equals(isolate, property, factory->microsecond_string()) ||
          String::Equals(isolate, property, factory->nanosecond_string())) {
        value = Handle<Object>(Smi::zero(), isolate);
      }
    } else {
      // For both PrepareTemporalFields and PreparePartialTemporalFields
      any = partial;
      // c. Else,
      // i. If property is in the Property column of Table 13 and there is a
      // Conversion value in the same row, then
      // 1. Let Conversion represent the abstract operation named by the
      // Conversion value of the same row.
      // 2. Set value to ? Conversion(value).
      if (String::Equals(isolate, property, factory->month_string()) ||
          String::Equals(isolate, property, factory->day_string())) {
        ASSIGN_RETURN_ON_EXCEPTION(isolate, value,
                                   ToPositiveInteger(isolate, value));
      } else if (String::Equals(isolate, property, factory->year_string()) ||
                 String::Equals(isolate, property, factory->hour_string()) ||
                 String::Equals(isolate, property, factory->minute_string()) ||
                 String::Equals(isolate, property, factory->second_string()) ||
                 String::Equals(isolate, property,
                                factory->millisecond_string()) ||
                 String::Equals(isolate, property,
                                factory->microsecond_string()) ||
                 String::Equals(isolate, property,
                                factory->nanosecond_string()) ||
                 String::Equals(isolate, property, factory->eraYear_string())) {
        ASSIGN_RETURN_ON_EXCEPTION(isolate, value,
                                   ToIntegerThrowOnInfinity(isolate, value));
      } else if (String::Equals(isolate, property,
                                factory->monthCode_string()) ||
                 String::Equals(isolate, property, factory->offset_string()) ||
                 String::Equals(isolate, property, factory->era_string())) {
        ASSIGN_RETURN_ON_EXCEPTION(isolate, value,
                                   Object::ToString(isolate, value));
      }
    }

    // d. Perform ! CreateDataPropertyOrThrow(result, property, value).
    CHECK(JSReceiver::CreateDataProperty(isolate, result, property, value,
                                         Just(kThrowOnError))
              .FromJust());
  }

  // Only for PreparePartialTemporalFields
  if (partial) {
    // 5. If any is false, then
    if (!any) {
      // a. Throw a TypeError exception.
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
    }
  }
  // 4. Return result.
  return result;
}

// #sec-temporal-preparetemporalfields
V8_WARN_UNUSED_RESULT MaybeHandle<JSReceiver> PrepareTemporalFields(
    Isolate* isolate, Handle<JSReceiver> fields,
    DirectHandle<FixedArray> field_names, RequiredFields required) {
  TEMPORAL_ENTER_FUNC();

  return PrepareTemporalFieldsOrPartial(isolate, fields, field_names, required,
                                        false);
}

// #sec-temporal-preparepartialtemporalfields
V8_WARN_UNUSED_RESULT MaybeHandle<JSReceiver> PreparePartialTemporalFields(
    Isolate* isolate, Handle<JSReceiver> fields,
    DirectHandle<FixedArray> field_names) {
  TEMPORAL_ENTER_FUNC();

  return PrepareTemporalFieldsOrPartial(isolate, fields, field_names,
                                        RequiredFields::kNone, true);
}

// Template for DateFromFields, YearMonthFromFields, and MonthDayFromFields
template <typename T>
MaybeHandle<T> FromFields(Isolate* isolate, Handle<JSReceiver> calendar,
                          Handle<JSReceiver> fields, Handle<Object> options,
                          Handle<String> property, InstanceType type) {
  Handle<Object> function;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, function,
                             Object::GetProperty(isolate, calendar, property));
  if (!IsCallable(*function)) {
    THROW_NEW_ERROR(
        isolate, NewTypeError(MessageTemplate::kCalledNonCallable, property));
  }
  Handle<Object> argv[] = {fields, options};
  Handle<Object> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result, Execution::Call(isolate, function, calendar, 2, argv));
  if ((!IsHeapObject(*result)) ||
      Cast<HeapObject>(*result)->map()->instance_type() != type) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  return Cast<T>(result);
}

// #sec-temporal-datefromfields
MaybeHandle<JSTemporalPlainDate> DateFromFields(Isolate* isolate,
                                                Handle<JSReceiver> calendar,
                                                Handle<JSReceiver> fields,
                                                Handle<Object> options) {
  return FromFields<JSTemporalPlainDate>(
      isolate, calendar, fields, options,
      isolate->factory()->dateFromFields_string(), JS_TEMPORAL_PLAIN_DATE_TYPE);
}

// #sec-temporal-yearmonthfromfields
MaybeHandle<JSTemporalPlainYearMonth> YearMonthFromFields(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<JSReceiver> fields,
    Handle<Object> options) {
  return FromFields<JSTemporalPlainYearMonth>(
      isolate, calendar, fields, options,
      isolate->factory()->yearMonthFromFields_string(),
      JS_TEMPORAL_PLAIN_YEAR_MONTH_TYPE);
}
MaybeHandle<JSTemporalPlainYearMonth> YearMonthFromFields(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<JSReceiver> fields) {
  // 1. If options is not present, set options to undefined.
  return YearMonthFromFields(isolate, calendar, fields,
                             isolate->factory()->undefined_value());
}

// #sec-temporal-monthdayfromfields
MaybeHandle<JSTemporalPlainMonthDay> MonthDayFromFields(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<JSReceiver> fields,
    Handle<Object> options) {
  return FromFields<JSTemporalPlainMonthDay>(
      isolate, calendar, fields, options,
      isolate->factory()->monthDayFromFields_string(),
      JS_TEMPORAL_PLAIN_MONTH_DAY_TYPE);
}
MaybeHandle<JSTemporalPlainMonthDay> MonthDayFromFields(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<JSReceiver> fields) {
  // 1. If options is not present, set options to undefined.
  return MonthDayFromFields(isolate, calendar, fields,
                            isolate->factory()->undefined_value());
}

// #sec-temporal-totemporaloverflow
Maybe<ShowOverflow> ToTemporalOverflow(Isolate* isolate, Handle<Object> options,
                                       const char* method_name) {
  // 1. If options is undefined, return "constrain".
  if (IsUndefined(*options)) return Just(ShowOverflow::kConstrain);
  DCHECK(IsJSReceiver(*options));
  // 2. Return ? GetOption(options, "overflow", « String », « "constrain",
  // "reject" », "constrain").
  return GetStringOption<ShowOverflow>(
      isolate, Cast<JSReceiver>(options), "overflow", method_name,
      {"constrain", "reject"},
      {ShowOverflow::kConstrain, ShowOverflow::kReject},
      ShowOverflow::kConstrain);
}

// #sec-temporal-totemporaloffset
Maybe<Offset> ToTemporalOffset(Isolate* isolate, Handle<Object> options,
                               Offset fallback, const char* method_name) {
  // 1. If options is undefined, return fallback.
  if (IsUndefined(*options)) return Just(fallback);
  DCHECK(IsJSReceiver(*options));

  // 2. Return ? GetOption(options, "offset", « String », « "prefer", "use",
  // "ignore", "reject" », fallback).
  return GetStringOption<Offset>(
      isolate, Cast<JSReceiver>(options), "offset", method_name,
      {"prefer", "use", "ignore", "reject"},
      {Offset::kPrefer, Offset::kUse, Offset::kIgnore, Offset::kReject},
      fallback);
}

// #sec-temporal-totemporaldisambiguation
Maybe<Disambiguation> ToTemporalDisambiguation(Isolate* isolate,
                                               Handle<Object> options,
                                               const char* method_name) {
  // 1. If options is undefined, return "compatible".
  if (IsUndefined(*options)) return Just(Disambiguation::kCompatible);
  DCHECK(IsJSReceiver(*options));
  // 2. Return ? GetOption(options, "disambiguation", « String », «
  // "compatible", "earlier", "later", "reject" », "compatible").
  return GetStringOption<Disambiguation>(
      isolate, Cast<JSReceiver>(options), "disambiguation", method_name,
      {"compatible", "earlier", "later", "reject"},
      {Disambiguation::kCompatible, Disambiguation::kEarlier,
       Disambiguation::kLater, Disambiguation::kReject},
      Disambiguation::kCompatible);
}

// #sec-temporal-builtintimezonegetinstantfor
MaybeHandle<JSTemporalInstant> BuiltinTimeZoneGetInstantFor(
    Isolate* isolate, Handle<JSReceiver> time_zone,
    Handle<JSTemporalPlainDateTime> date_time, Disambiguation disambiguation,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: dateTime has an [[InitializedTemporalDateTime]] internal slot.
  // 2. Let possibleInstants be ? GetPossibleInstantsFor(timeZone, dateTime).
  Handle<FixedArray> possible_instants;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, possible_instants,
      GetPossibleInstantsFor(isolate, time_zone, date_time));
  // 3. Return ? DisambiguatePossibleInstants(possibleInstants, timeZone,
  // dateTime, disambiguation).
  return DisambiguatePossibleInstants(isolate, possible_instants, time_zone,
                                      date_time, disambiguation, method_name);
}

// #sec-temporal-totemporalinstant
MaybeHandle<JSTemporalInstant> ToTemporalInstant(Isolate* isolate,
                                                 Handle<Object> item,
                                                 const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 1. If Type(item) is Object, then
  // a. If item has an [[InitializedTemporalInstant]] internal slot, then
  if (IsJSTemporalInstant(*item)) {
    // i. Return item.
    return Cast<JSTemporalInstant>(item);
  }
  // b. If item has an [[InitializedTemporalZonedDateTime]] internal slot, then
  if (IsJSTemporalZonedDateTime(*item)) {
    // i. Return ! CreateTemporalInstant(item.[[Nanoseconds]]).
    DirectHandle<BigInt> nanoseconds(
        Cast<JSTemporalZonedDateTime>(*item)->nanoseconds(), isolate);
    return temporal::CreateTemporalInstant(isolate, nanoseconds)
        .ToHandleChecked();
  }
  // 2. Let string be ? ToString(item).
  Handle<String> string;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, string, Object::ToString(isolate, item));

  // 3. Let epochNanoseconds be ? ParseTemporalInstant(string).
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, epoch_nanoseconds,
                             ParseTemporalInstant(isolate, string));

  // 4. Return ? CreateTemporalInstant(ℤ(epochNanoseconds)).
  return temporal::CreateTemporalInstant(isolate, epoch_nanoseconds);
}

}  // namespace

namespace temporal {
// #sec-temporal-totemporalcalendar
MaybeHandle<JSReceiver> ToTemporalCalendar(
    Isolate* isolate, Handle<Object> temporal_calendar_like,
    const char* method_name) {
  Factory* factory = isolate->factory();
  // 1.If Type(temporalCalendarLike) is Object, then
  if (IsJSReceiver(*temporal_calendar_like)) {
    // a. If temporalCalendarLike has an [[InitializedTemporalDate]],
    // [[InitializedTemporalDateTime]], [[InitializedTemporalMonthDay]],
    // [[InitializedTemporalTime]], [[InitializedTemporalYearMonth]], or
    // [[InitializedTemporalZonedDateTime]] internal slot, then i. Return
    // temporalCalendarLike.[[Calendar]].

#define EXTRACT_CALENDAR(T, obj)                                  \
  if (IsJSTemporal##T(*obj)) {                                    \
    return handle(Cast<JSTemporal##T>(obj)->calendar(), isolate); \
  }

    EXTRACT_CALENDAR(PlainDate, temporal_calendar_like)
    EXTRACT_CALENDAR(PlainDateTime, temporal_calendar_like)
    EXTRACT_CALENDAR(PlainMonthDay, temporal_calendar_like)
    EXTRACT_CALENDAR(PlainTime, temporal_calendar_like)
    EXTRACT_CALENDAR(PlainYearMonth, temporal_calendar_like)
    EXTRACT_CALENDAR(ZonedDateTime, temporal_calendar_like)

#undef EXTRACT_CALENDAR
    Handle<JSReceiver> obj = Cast<JSReceiver>(temporal_calendar_like);

    // b. If ? HasProperty(temporalCalendarLike, "calendar") is false, return
    // temporalCalendarLike.
    bool has;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, has,
        JSReceiver::HasProperty(isolate, obj, factory->calendar_string()),
        Handle<JSReceiver>());
    if (!has) {
      return obj;
    }
    // c.  Set temporalCalendarLike to ? Get(temporalCalendarLike, "calendar").
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_calendar_like,
        JSReceiver::GetProperty(isolate, obj, factory->calendar_string()));
    // d. If Type(temporalCalendarLike) is Object
    if (IsJSReceiver(*temporal_calendar_like)) {
      obj = Cast<JSReceiver>(temporal_calendar_like);
      // and ? HasProperty(temporalCalendarLike, "calendar") is false,
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, has,
          JSReceiver::HasProperty(isolate, obj, factory->calendar_string()),
          Handle<JSReceiver>());
      if (!has) {
        // return temporalCalendarLike.
        return obj;
      }
    }
  }

  // 2. Let identifier be ? ToString(temporalCalendarLike).
  Handle<String> identifier;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, identifier,
                             Object::ToString(isolate, temporal_calendar_like));
  // 3. Let identifier be ? ParseTemporalCalendarString(identifier).
  ASSIGN_RETURN_ON_EXCEPTION(isolate, identifier,
                             ParseTemporalCalendarString(isolate, identifier));
  // 4. If IsBuiltinCalendar(identifier) is false, throw a RangeError
  // exception.
  if (!IsBuiltinCalendar(isolate, identifier)) {
    THROW_NEW_ERROR(
        isolate, NewRangeError(MessageTemplate::kInvalidCalendar, identifier));
  }
  // 5. Return ? CreateTemporalCalendar(identifier).
  return CreateTemporalCalendar(isolate, identifier);
}

}  // namespace temporal

namespace {
// #sec-temporal-totemporalcalendarwithisodefault
MaybeHandle<JSReceiver> ToTemporalCalendarWithISODefault(
    Isolate* isolate, Handle<Object> temporal_calendar_like,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 1. If temporalCalendarLike is undefined, then
  if (IsUndefined(*temporal_calendar_like)) {
    // a. Return ? GetISO8601Calendar().
    return temporal::GetISO8601Calendar(isolate);
  }
  // 2. Return ? ToTemporalCalendar(temporalCalendarLike).
  return temporal::ToTemporalCalendar(isolate, temporal_calendar_like,
                                      method_name);
}

// Create «  "day", "hour", "microsecond", "millisecond", "minute", "month",
// "monthCode", "nanosecond", "second", "year" » in several AOs.
Handle<FixedArray> All10UnitsInFixedArray(Isolate* isolate) {
  Handle<FixedArray> field_names = isolate->factory()->NewFixedArray(10);
  field_names->set(0, ReadOnlyRoots(isolate).day_string());
  field_names->set(1, ReadOnlyRoots(isolate).hour_string());
  field_names->set(2, ReadOnlyRoots(isolate).microsecond_string());
  field_names->set(3, ReadOnlyRoots(isolate).millisecond_string());
  field_names->set(4, ReadOnlyRoots(isolate).minute_string());
  field_names->set(5, ReadOnlyRoots(isolate).month_string());
  field_names->set(6, ReadOnlyRoots(isolate).monthCode_string());
  field_names->set(7, ReadOnlyRoots(isolate).nanosecond_string());
  field_names->set(8, ReadOnlyRoots(isolate).second_string());
  field_names->set(9, ReadOnlyRoots(isolate).year_string());
  return field_names;
}

// Create « "day", "month", "monthCode", "year" » in several AOs.
Handle<FixedArray> DayMonthMonthCodeYearInFixedArray(Isolate* isolate) {
  Handle<FixedArray> field_names = isolate->factory()->NewFixedArray(4);
  field_names->set(0, ReadOnlyRoots(isolate).day_string());
  field_names->set(1, ReadOnlyRoots(isolate).month_string());
  field_names->set(2, ReadOnlyRoots(isolate).monthCode_string());
  field_names->set(3, ReadOnlyRoots(isolate).year_string());
  return field_names;
}

// Create « "month", "monthCode", "year" » in several AOs.
Handle<FixedArray> MonthMonthCodeYearInFixedArray(Isolate* isolate) {
  Handle<FixedArray> field_names = isolate->factory()->NewFixedArray(3);
  field_names->set(0, ReadOnlyRoots(isolate).month_string());
  field_names->set(1, ReadOnlyRoots(isolate).monthCode_string());
  field_names->set(2, ReadOnlyRoots(isolate).year_string());
  return field_names;
}

// Create « "monthCode", "year" » in several AOs.
Handle<FixedArray> MonthCodeYearInFixedArray(Isolate* isolate) {
  Handle<FixedArray> field_names = isolate->factory()->NewFixedArray(2);
  field_names->set(0, ReadOnlyRoots(isolate).monthCode_string());
  field_names->set(1, ReadOnlyRoots(isolate).year_string());
  return field_names;
}

// #sec-temporal-totemporaldate
MaybeHandle<JSTemporalPlainDate> ToTemporalDate(Isolate* isolate,
                                                Handle<Object> item_obj,
                                                Handle<Object> options,
                                                const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 2. Assert: Type(options) is Object or Undefined.
  DCHECK(IsJSReceiver(*options) || IsUndefined(*options));
  // 3. If Type(item) is Object, then
  if (IsJSReceiver(*item_obj)) {
    Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
    // a. If item has an [[InitializedTemporalDate]] internal slot, then
    // i. Return item.
    if (IsJSTemporalPlainDate(*item)) {
      return Cast<JSTemporalPlainDate>(item);
    }
    // b. If item has an [[InitializedTemporalZonedDateTime]] internal slot,
    // then
    if (IsJSTemporalZonedDateTime(*item)) {
      // i. Perform ? ToTemporalOverflow(options).
      MAYBE_RETURN_ON_EXCEPTION_VALUE(
          isolate, ToTemporalOverflow(isolate, options, method_name),
          Handle<JSTemporalPlainDate>());

      // ii. Let instant be ! CreateTemporalInstant(item.[[Nanoseconds]]).
      auto zoned_date_time = Cast<JSTemporalZonedDateTime>(item);
      Handle<JSTemporalInstant> instant =
          temporal::CreateTemporalInstant(
              isolate, handle(zoned_date_time->nanoseconds(), isolate))
              .ToHandleChecked();
      // iii. Let plainDateTime be ?
      // BuiltinTimeZoneGetPlainDateTimeFor(item.[[TimeZone]],
      // instant, item.[[Calendar]]).
      Handle<JSTemporalPlainDateTime> plain_date_time;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, plain_date_time,
          temporal::BuiltinTimeZoneGetPlainDateTimeFor(
              isolate,
              Handle<JSReceiver>(zoned_date_time->time_zone(), isolate),
              instant, Handle<JSReceiver>(zoned_date_time->calendar(), isolate),
              method_name));
      // iv. Return ! CreateTemporalDate(plainDateTime.[[ISOYear]],
      // plainDateTime.[[ISOMonth]], plainDateTime.[[ISODay]],
      // plainDateTime.[[Calendar]]).
      return CreateTemporalDate(
                 isolate,
                 {plain_date_time->iso_year(), plain_date_time->iso_month(),
                  plain_date_time->iso_day()},
                 handle(plain_date_time->calendar(), isolate))
          .ToHandleChecked();
    }

    // c. If item has an [[InitializedTemporalDateTime]] internal slot, then
    // item.[[ISODay]], item.[[Calendar]]).
    if (IsJSTemporalPlainDateTime(*item)) {
      // i. Perform ? ToTemporalOverflow(options).
      MAYBE_RETURN_ON_EXCEPTION_VALUE(
          isolate, ToTemporalOverflow(isolate, options, method_name),
          Handle<JSTemporalPlainDate>());
      // ii. Return ! CreateTemporalDate(item.[[ISOYear]], item.[[ISOMonth]],
      auto date_time = Cast<JSTemporalPlainDateTime>(item);
      return CreateTemporalDate(isolate,
                                {date_time->iso_year(), date_time->iso_month(),
                                 date_time->iso_day()},
                                handle(date_time->calendar(), isolate))
          .ToHandleChecked();
    }

    // d. Let calendar be ? GetTemporalCalendarWithISODefault(item).
    Handle<JSReceiver> calendar;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        GetTemporalCalendarWithISODefault(isolate, item, method_name));
    // e. Let fieldNames be ? CalendarFields(calendar, « "day", "month",
    // "monthCode", "year" »).
    Handle<FixedArray> field_names = DayMonthMonthCodeYearInFixedArray(isolate);
    ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                               CalendarFields(isolate, calendar, field_names));
    // f. Let fields be ? PrepareTemporalFields(item,
    // fieldNames, «»).
    Handle<JSReceiver> fields;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, fields,
                               PrepareTemporalFields(isolate, item, field_names,
                                                     RequiredFields::kNone));
    // g. Return ? DateFromFields(calendar, fields, options).
    return DateFromFields(isolate, calendar, fields, options);
  }
  // 4. Perform ? ToTemporalOverflow(options).
  MAYBE_RETURN_ON_EXCEPTION_VALUE(
      isolate, ToTemporalOverflow(isolate, options, method_name),
      Handle<JSTemporalPlainDate>());

  // 5. Let string be ? ToString(item).
  Handle<String> string;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, string,
                             Object::ToString(isolate, item_obj));
  // 6. Let result be ? ParseTemporalDateString(string).
  DateRecordWithCalendar result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseTemporalDateString(isolate, string),
      Handle<JSTemporalPlainDate>());

  // 7. Assert: ! IsValidISODate(result.[[Year]], result.[[Month]],
  // result.[[Day]]) is true.
  DCHECK(IsValidISODate(isolate, result.date));
  // 8. Let calendar be ? ToTemporalCalendarWithISODefault(result.[[Calendar]]).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ToTemporalCalendarWithISODefault(isolate, result.calendar, method_name));
  // 9. Return ? CreateTemporalDate(result.[[Year]], result.[[Month]],
  // result.[[Day]], calendar).
  return CreateTemporalDate(isolate, result.date, calendar);
}

MaybeHandle<JSTemporalPlainDate> ToTemporalDate(Isolate* isolate,
                                                Handle<Object> item_obj,
                                                const char* method_name) {
  // 1. If options is not present, set options to undefined.
  return ToTemporalDate(isolate, item_obj,
                        isolate->factory()->undefined_value(), method_name);
}

// #sec-isintegralnumber
bool IsIntegralNumber(Isolate* isolate, DirectHandle<Object> argument) {
  // 1. If Type(argument) is not Number, return false.
  if (!IsNumber(*argument)) return false;
  // 2. If argument is NaN, +∞𝔽, or -∞𝔽, return false.
  double number = Object::NumberValue(Cast<Number>(*argument));
  if (!std::isfinite(number)) return false;
  // 3. If floor(abs(ℝ(argument))) ≠ abs(ℝ(argument)), return false.
  if (std::floor(std::abs(number)) != std::abs(number)) return false;
  // 4. Return true.
  return true;
}

// #sec-temporal-tointegerwithoutrounding
Maybe<double> ToIntegerWithoutRounding(Isolate* isolate,
                                       Handle<Object> argument) {
  // 1. Let number be ? ToNumber(argument).
  Handle<Number> number;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, number, Object::ToNumber(isolate, argument), Nothing<double>());
  // 2. If number is NaN, +0𝔽, or −0𝔽 return 0.
  if (IsNaN(*number) || Object::NumberValue(*number) == 0) {
    return Just(static_cast<double>(0));
  }
  // 3. If IsIntegralNumber(number) is false, throw a RangeError exception.
  if (!IsIntegralNumber(isolate, number)) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(), Nothing<double>());
  }
  // 4. Return ℝ(number).
  return Just(Object::NumberValue(*number));
}

}  // namespace

namespace temporal {

// #sec-temporal-regulatetime
Maybe<TimeRecord> RegulateTime(Isolate* isolate, const TimeRecord& time,
                               ShowOverflow overflow) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: hour, minute, second, millisecond, microsecond and nanosecond
  // are integers.
  // 2. Assert: overflow is either "constrain" or "reject".
  switch (overflow) {
    case ShowOverflow::kConstrain: {
      TimeRecord result(time);
      // 3. If overflow is "constrain", then
      // a. Return ! ConstrainTime(hour, minute, second, millisecond,
      // microsecond, nanosecond).
      result.hour = std::max(std::min(result.hour, 23), 0);
      result.minute = std::max(std::min(result.minute, 59), 0);
      result.second = std::max(std::min(result.second, 59), 0);
      result.millisecond = std::max(std::min(result.millisecond, 999), 0);
      result.microsecond = std::max(std::min(result.microsecond, 999), 0);
      result.nanosecond = std::max(std::min(result.nanosecond, 999), 0);
      return Just(result);
    }
    case ShowOverflow::kReject:
      // 4. If overflow is "reject", then
      // a. If ! IsValidTime(hour, minute, second, millisecond, microsecond,
      // nanosecond) is false, throw a RangeError exception.
      if (!IsValidTime(isolate, time)) {
        THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                     NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                     Nothing<TimeRecord>());
      }
      // b. Return the new Record { [[Hour]]: hour, [[Minute]]: minute,
      // [[Second]]: second, [[Millisecond]]: millisecond, [[Microsecond]]:
      // microsecond, [[Nanosecond]]: nanosecond }.
      return Just(time);
  }
}

// #sec-temporal-totemporaltime
MaybeHandle<JSTemporalPlainTime> ToTemporalTime(
    Isolate* isolate, Handle<Object> item_obj, const char* method_name,
    ShowOverflow overflow = ShowOverflow::kConstrain) {
  Factory* factory = isolate->factory();
  TimeRecordWithCalendar result;
  // 2. Assert: overflow is either "constrain" or "reject".
  // 3. If Type(item) is Object, then
  if (IsJSReceiver(*item_obj)) {
    Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
    // a. If item has an [[InitializedTemporalTime]] internal slot, then
    // i. Return item.
    if (IsJSTemporalPlainTime(*item)) {
      return Cast<JSTemporalPlainTime>(item);
    }
    // b. If item has an [[InitializedTemporalZonedDateTime]] internal slot,
    // then
    if (IsJSTemporalZonedDateTime(*item)) {
      // i. Let instant be ! CreateTemporalInstant(item.[[Nanoseconds]]).
      auto zoned_date_time = Cast<JSTemporalZonedDateTime>(item);
      Handle<JSTemporalInstant> instant =
          CreateTemporalInstant(isolate,
                                handle(zoned_date_time->nanoseconds(), isolate))
              .ToHandleChecked();
      // ii. Set plainDateTime to ?
      // BuiltinTimeZoneGetPlainDateTimeFor(item.[[TimeZone]],
      // instant, item.[[Calendar]]).
      Handle<JSTemporalPlainDateTime> plain_date_time;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, plain_date_time,
          BuiltinTimeZoneGetPlainDateTimeFor(
              isolate,
              Handle<JSReceiver>(zoned_date_time->time_zone(), isolate),
              instant, Handle<JSReceiver>(zoned_date_time->calendar(), isolate),
              method_name));
      // iii. Return !
      // CreateTemporalTime(plainDateTime.[[ISOHour]],
      // plainDateTime.[[ISOMinute]], plainDateTime.[[ISOSecond]],
      // plainDateTime.[[ISOMillisecond]], plainDateTime.[[ISOMicrosecond]],
      // plainDateTime.[[ISONanosecond]]).
      return CreateTemporalTime(isolate, {plain_date_time->iso_hour(),
                                          plain_date_time->iso_minute(),
                                          plain_date_time->iso_second(),
                                          plain_date_time->iso_millisecond(),
                                          plain_date_time->iso_microsecond(),
                                          plain_date_time->iso_nanosecond()})
          .ToHandleChecked();
    }
    // c. If item has an [[InitializedTemporalDateTime]] internal slot, then
    if (IsJSTemporalPlainDateTime(*item)) {
      // i. Return ! CreateTemporalTime(item.[[ISOHour]], item.[[ISOMinute]],
      // item.[[ISOSecond]], item.[[ISOMillisecond]], item.[[ISOMicrosecond]],
      // item.[[ISONanosecond]]).
      auto date_time = Cast<JSTemporalPlainDateTime>(item);
      return CreateTemporalTime(
                 isolate,
                 {date_time->iso_hour(), date_time->iso_minute(),
                  date_time->iso_second(), date_time->iso_millisecond(),
                  date_time->iso_microsecond(), date_time->iso_nanosecond()})
          .ToHandleChecked();
    }
    // d. Let calendar be ? GetTemporalCalendarWithISODefault(item).
    Handle<JSReceiver> calendar;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        GetTemporalCalendarWithISODefault(isolate, item, method_name));
    // e. If ? ToString(calendar) is not "iso8601", then
    Handle<String> identifier;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, identifier,
                               Object::ToString(isolate, calendar));
    if (!String::Equals(isolate, factory->iso8601_string(), identifier)) {
      // i. Throw a RangeError exception.
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
    }
    // f. Let result be ? ToTemporalTimeRecord(item).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result.time, ToTemporalTimeRecord(isolate, item, method_name),
        Handle<JSTemporalPlainTime>());
    // g. Set result to ? RegulateTime(result.[[Hour]], result.[[Minute]],
    // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
    // result.[[Nanosecond]], overflow).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result.time, RegulateTime(isolate, result.time, overflow),
        Handle<JSTemporalPlainTime>());
  } else {
    // 4. Else,
    // a. Let string be ? ToString(item).
    Handle<String> string;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, string,
                               Object::ToString(isolate, item_obj));
    // b. Let result be ? ParseTemporalTimeString(string).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result, ParseTemporalTimeString(isolate, string),
        Handle<JSTemporalPlainTime>());
    // c. Assert: ! IsValidTime(result.[[Hour]], result.[[Minute]],
    // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
    // result.[[Nanosecond]]) is true.
    DCHECK(IsValidTime(isolate, result.time));
    // d. If result.[[Calendar]] is not one of undefined or "iso8601", then
    DCHECK(IsUndefined(*result.calendar) || IsString(*result.calendar));
    if (!IsUndefined(*result.calendar) &&
        !String::Equals(isolate, Cast<String>(result.calendar),
                        isolate->factory()->iso8601_string())) {
      // i. Throw a RangeError exception.
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
    }
  }
  // 5. Return ? CreateTemporalTime(result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]]).
  return CreateTemporalTime(isolate, result.time);
}

// Helper function to loop through Table 8 Duration Record Fields
// This function implement
// "For each row of Table 8, except the header row, in table order, do"
// loop. It is designed to be used to implement the common part of
// ToPartialDuration, ToTemporalDurationRecord
Maybe<bool> IterateDurationRecordFieldsTable(
    Isolate* isolate, Handle<JSReceiver> temporal_duration_like,
    Maybe<bool> (*RowFunction)(Isolate*,
                               Handle<JSReceiver> temporal_duration_like,
                               Handle<String>, double*),
    DurationRecord* record) {
  Factory* factory = isolate->factory();
  std::array<std::pair<Handle<String>, double*>, 10> table8 = {
      {{factory->days_string(), &record->time_duration.days},
       {factory->hours_string(), &record->time_duration.hours},
       {factory->microseconds_string(), &record->time_duration.microseconds},
       {factory->milliseconds_string(), &record->time_duration.milliseconds},
       {factory->minutes_string(), &record->time_duration.minutes},
       {factory->months_string(), &record->months},
       {factory->nanoseconds_string(), &record->time_duration.nanoseconds},
       {factory->seconds_string(), &record->time_duration.seconds},
       {factory->weeks_string(), &record->weeks},
       {factory->years_string(), &record->years}}};

  // x. Let any be false.
  bool any = false;
  // x+1. For each row of Table 8, except the header row, in table order, do
  for (const auto& row : table8) {
    bool result;
    // row.first is prop: the Property Name value of the current row
    // row.second is the address of result's field whose name is the Field Name
    // value of the current row
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        RowFunction(isolate, temporal_duration_like, row.first, row.second),
        Nothing<bool>());
    any |= result;
  }
  return Just(any);
}

// #sec-temporal-totemporaldurationrecord
Maybe<DurationRecord> ToTemporalDurationRecord(
    Isolate* isolate, Handle<Object> temporal_duration_like_obj,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 1. If Type(temporalDurationLike) is not Object, then
  if (!IsJSReceiver(*temporal_duration_like_obj)) {
    // a. Let string be ? ToString(temporalDurationLike).
    Handle<String> string;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, string, Object::ToString(isolate, temporal_duration_like_obj),
        Nothing<DurationRecord>());
    // b. Let result be ? ParseTemporalDurationString(string).
    return ParseTemporalDurationString(isolate, string);
  }
  Handle<JSReceiver> temporal_duration_like =
      Cast<JSReceiver>(temporal_duration_like_obj);
  // 2. If temporalDurationLike has an [[InitializedTemporalDuration]] internal
  // slot, then
  if (IsJSTemporalDuration(*temporal_duration_like)) {
    // a. Return ! CreateDurationRecord(temporalDurationLike.[[Years]],
    // temporalDurationLike.[[Months]], temporalDurationLike.[[Weeks]],
    // temporalDurationLike.[[Days]], temporalDurationLike.[[Hours]],
    // temporalDurationLike.[[Minutes]], temporalDurationLike.[[Seconds]],
    // temporalDurationLike.[[Milliseconds]],
    // temporalDurationLike.[[Microseconds]],
    // temporalDurationLike.[[Nanoseconds]]).
    auto duration = Cast<JSTemporalDuration>(temporal_duration_like);
    return DurationRecord::Create(isolate,
                                  Object::NumberValue(duration->years()),
                                  Object::NumberValue(duration->months()),
                                  Object::NumberValue(duration->weeks()),
                                  Object::NumberValue(duration->days()),
                                  Object::NumberValue(duration->hours()),
                                  Object::NumberValue(duration->minutes()),
                                  Object::NumberValue(duration->seconds()),
                                  Object::NumberValue(duration->milliseconds()),
                                  Object::NumberValue(duration->microseconds()),
                                  Object::NumberValue(duration->nanoseconds()));
  }
  // 3. Let result be a new Record with all the internal slots given in the
  // Internal Slot column in Table 8.
  DurationRecord result;
  // 4. Let any be false.
  bool any = false;

  // 5. For each row of Table 8, except the header row, in table order, do
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
            // c. If val is undefined, then
            if (IsUndefined(*val)) {
              // i. Set result's internal slot whose name is the Internal Slot
              // value of the current row to 0.
              *field = 0;
              // d. Else,
            } else {
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

  // 6. If any is false, then
  if (!any) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<DurationRecord>());
  }
  // 7. If ! IsValidDuration(result.[[Years]], result.[[Months]],
  // result.[[Weeks]] result.[[Days]], result.[[Hours]], result.[[Minutes]],
  // result.[[Seconds]], result.[[Milliseconds]], result.[[Microseconds]],
  // result.[[Nanoseconds]]) is false, then
  if (!IsValidDuration(isolate, result)) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DurationRecord>());
  }
  // 8. Return result.
  return Just(result);
}

// #sec-temporal-totemporalduration
MaybeHandle<JSTemporalDuration> ToTemporalDuration(Isolate* isolate,
                                                   Handle<Object> item,
                                                   const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  DurationRecord result;
  // 1. If Type(item) is Object and item has an [[InitializedTemporalDuration]]
  // internal slot, then
  if (IsJSTemporalDuration(*item)) {
    // a. Return item.
    return Cast<JSTemporalDuration>(item);
  }
  // 2. Let result be ? ToTemporalDurationRecord(item).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ToTemporalDurationRecord(isolate, item, method_name),
      Handle<JSTemporalDuration>());

  // 3. Return ? CreateTemporalDuration(result.[[Years]], result.[[Months]],
  // result.[[Weeks]], result.[[Days]], result.[[Hours]], result.[[Minutes]],
  // result.[[Seconds]], result.[[Milliseconds]], result.[[Microseconds]],
  // result.[[Nanoseconds]]).
  return CreateTemporalDuration(isolate, result);
}

// #sec-temporal-totemporaltimezone
MaybeHandle<JSReceiver> ToTemporalTimeZone(
    Isolate* isolate, Handle<Object> temporal_time_zone_like,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 1. If Type(temporalTimeZoneLike) is Object, then
  if (IsJSReceiver(*temporal_time_zone_like)) {
    // a. If temporalTimeZoneLike has an [[InitializedTemporalZonedDateTime]]
    // internal slot, then
    if (IsJSTemporalZonedDateTime(*temporal_time_zone_like)) {
      // i. Return temporalTimeZoneLike.[[TimeZone]].
      auto zoned_date_time =
          Cast<JSTemporalZonedDateTime>(temporal_time_zone_like);
      return handle(zoned_date_time->time_zone(), isolate);
    }
    Handle<JSReceiver> obj = Cast<JSReceiver>(temporal_time_zone_like);
    // b. If ? HasProperty(temporalTimeZoneLike, "timeZone") is false,
    bool has;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, has,
        JSReceiver::HasProperty(isolate, obj, factory->timeZone_string()),
        Handle<JSReceiver>());
    if (!has) {
      // return temporalTimeZoneLike.
      return obj;
    }
    // c. Set temporalTimeZoneLike to ?
    // Get(temporalTimeZoneLike, "timeZone").
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_time_zone_like,
        JSReceiver::GetProperty(isolate, obj, factory->timeZone_string()));
    // d. If Type(temporalTimeZoneLike)
    if (IsJSReceiver(*temporal_time_zone_like)) {
      // is Object and ? HasProperty(temporalTimeZoneLike, "timeZone") is false,
      obj = Cast<JSReceiver>(temporal_time_zone_like);
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, has,
          JSReceiver::HasProperty(isolate, obj, factory->timeZone_string()),
          Handle<JSReceiver>());
      if (!has) {
        // return temporalTimeZoneLike.
        return obj;
      }
    }
  }
  Handle<String> identifier;
  // 2. Let identifier be ? ToString(temporalTimeZoneLike).
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, identifier, Object::ToString(isolate, temporal_time_zone_like));

  // 3. Let parseResult be ? ParseTemporalTimeZoneString(identifier).
  TimeZoneRecord parse_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, parse_result, ParseTemporalTimeZoneString(isolate, identifier),
      Handle<JSReceiver>());

  // 4. If parseResult.[[Name]] is not undefined, then
  if (!IsUndefined(*parse_result.name)) {
    DCHECK(IsString(*parse_result.name));
    // a. Let name be parseResult.[[Name]].
    Handle<String> name = Cast<String>(parse_result.name);
    // b. If ParseText(StringToCodePoints(name, TimeZoneNumericUTCOffset)) is
    // a List of errors, then
    std::optional<ParsedISO8601Result> parsed_offset =
        TemporalParser::ParseTimeZoneNumericUTCOffset(isolate, name);
    if (!parsed_offset.has_value()) {
      // i. If ! IsValidTimeZoneName(name) is false, throw a RangeError
      // exception.
      if (!IsValidTimeZoneName(isolate, name)) {
        THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
      }
      // ii. Set name to ! CanonicalizeTimeZoneName(name).
      name = CanonicalizeTimeZoneName(isolate, name);
    }
    // c. Return ! CreateTemporalTimeZone(name).
    return temporal::CreateTemporalTimeZone(isolate, name);
  }
  // 5. If parseResult.[[Z]] is true, return ! CreateTemporalTimeZone("UTC").
  if (parse_result.z) {
    return CreateTemporalTimeZoneUTC(isolate);
  }
  // 6. Return ! CreateTemporalTimeZone(parseResult.[[OffsetString]]).
  DCHECK(IsString(*parse_result.offset_string));
  return temporal::CreateTemporalTimeZone(
      isolate, Cast<String>(parse_result.offset_string));
}

}  // namespace temporal

namespace {
// #sec-temporal-systemdatetime
MaybeHandle<JSTemporalPlainDateTime> SystemDateTime(
    Isolate* isolate, Handle<Object> temporal_time_zone_like,
    Handle<Object> calendar_like, const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Handle<JSReceiver> time_zone;
  // 1. 1. If temporalTimeZoneLike is undefined, then
  if (IsUndefined(*temporal_time_zone_like)) {
    // a. Let timeZone be ! SystemTimeZone().
    time_zone = SystemTimeZone(isolate);
  } else {
    // 2. Else,
    // a. Let timeZone be ? ToTemporalTimeZone(temporalTimeZoneLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone,
        temporal::ToTemporalTimeZone(isolate, temporal_time_zone_like,
                                     method_name));
  }
  Handle<JSReceiver> calendar;
  // 3. Let calendar be ? ToTemporalCalendar(calendarLike).
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      temporal::ToTemporalCalendar(isolate, calendar_like, method_name));
  // 4. Let instant be ! SystemInstant().
  Handle<JSTemporalInstant> instant = SystemInstant(isolate);
  // 5. Return ? BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant,
  // calendar).
  return temporal::BuiltinTimeZoneGetPlainDateTimeFor(
      isolate, time_zone, instant, calendar, method_name);
}

MaybeHandle<JSTemporalZonedDateTime> SystemZonedDateTime(
    Isolate* isolate, Handle<Object> temporal_time_zone_like,
    Handle<Object> calendar_like, const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Handle<JSReceiver> time_zone;
  // 1. 1. If temporalTimeZoneLike is undefined, then
  if (IsUndefined(*temporal_time_zone_like)) {
    // a. Let timeZone be ! SystemTimeZone().
    time_zone = SystemTimeZone(isolate);
  } else {
    // 2. Else,
    // a. Let timeZone be ? ToTemporalTimeZone(temporalTimeZoneLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone,
        temporal::ToTemporalTimeZone(isolate, temporal_time_zone_like,
                                     method_name));
  }
  Handle<JSReceiver> calendar;
  // 3. Let calendar be ? ToTemporalCalendar(calendarLike).
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      temporal::ToTemporalCalendar(isolate, calendar_like, method_name));
  // 4. Let ns be ! SystemUTCEpochNanoseconds().
  DirectHandle<BigInt> ns = SystemUTCEpochNanoseconds(isolate);
  // Return ? CreateTemporalZonedDateTime(ns, timeZone, calendar).
  return CreateTemporalZonedDateTime(isolate, ns, time_zone, calendar);
}

int CompareResultToSign(ComparisonResult r) {
  DCHECK_NE(r, ComparisonResult::kUndefined);
  return static_cast<int>(r);
}

// #sec-temporal-formattimezoneoffsetstring
Handle<String> FormatTimeZoneOffsetString(Isolate* isolate,
                                          int64_t offset_nanoseconds) {
  IncrementalStringBuilder builder(isolate);
  // 1. Assert: offsetNanoseconds is an integer.
  // 2. If offsetNanoseconds ≥ 0, let sign be "+"; otherwise, let sign be "-".
  builder.AppendCharacter((offset_nanoseconds >= 0) ? '+' : '-');
  // 3. Let offsetNanoseconds be abs(offsetNanoseconds).
  offset_nanoseconds = std::abs(offset_nanoseconds);
  // 4. Let nanoseconds be offsetNanoseconds modulo 10^9.
  int64_t nanoseconds = offset_nanoseconds % 1000000000;
  // 5. Let seconds be floor(offsetNanoseconds / 10^9) modulo 60.
  int32_t seconds = (offset_nanoseconds / 1000000000) % 60;
  // 6. Let minutes be floor(offsetNanoseconds / (6 × 10^10)) modulo 60.
  int32_t minutes = (offset_nanoseconds / 60000000000) % 60;
  // 7. Let hours be floor(offsetNanoseconds / (3.6 × 10^12)).
  int32_t hours = offset_nanoseconds / 3600000000000;
  // 8. Let h be ToZeroPaddedDecimalString(hours, 2).
  ToZeroPaddedDecimalString(&builder, hours, 2);

  // 9. Let m be ToZeroPaddedDecimalString(minutes, 2).
  builder.AppendCharacter(':');
  ToZeroPadde
```