Response:
The user wants a summary of the provided C++ code snippet from `v8/src/objects/js-temporal-objects.cc`. The instructions mention checking for `.tq` extension (it doesn't have it), relevance to JavaScript (it does), code logic (yes), and common programming errors (likely).

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:**  The code is clearly about creating and manipulating Temporal API objects in V8. Keywords like `CreateTemporalPlainDate`, `CreateTemporalZonedDateTime`, `CreateTemporalDuration`, etc., strongly suggest this.

2. **Categorize the Creation Functions:** Notice a pattern: functions named `CreateTemporal...`  These functions take various inputs and construct specific Temporal objects (Date, Time, DateTime, Duration, Instant, TimeZone, MonthDay, YearMonth, ZonedDateTime).

3. **Analyze the Input Parameters:** Observe that the creation functions typically take:
    * `Isolate* isolate`:  Essential for V8's memory management.
    * Target and New Target: Standard JavaScript constructor patterns.
    * Specific data fields (year, month, day, hours, minutes, seconds, nanoseconds, etc.).
    * `calendar`: Represents a calendar system.
    * `time_zone`:  Represents a time zone.

4. **Look for Validation:** The code includes checks using functions like `IsValidISODate`, `ISOYearMonthWithinLimits`, and `IsValidDuration`. This indicates that the code performs input validation.

5. **Identify Data Structures:** The code uses structs like `DateDurationRecord`, `TimeDurationRecord`, and `DurationRecord` to group related time components.

6. **Pinpoint Utility Functions:** Functions like `NormalizeMinusZero`, `BalanceISODateTime`, `RoundTowardsZero`, and `TemporalDurationToString` provide supporting logic for Temporal operations. `SystemInstant` and `SystemTimeZone` are about getting the current system time.

7. **Consider JavaScript Relevance:**  The Temporal API is a JavaScript standard. The C++ code is the underlying implementation. The creation functions directly correspond to how you would construct these objects in JavaScript.

8. **Think About Error Handling:** The use of `MaybeHandle` and `THROW_INVALID_RANGE` suggests that the C++ code handles potential errors during object creation. This ties into common programming errors in JavaScript when using the Temporal API.

9. **Code Logic Example (Mental Simulation):** Take `CreateTemporalPlainDate`. Imagine passing in invalid date components (e.g., month 13). The `IsValidISODate` check would catch this and throw an error. For valid inputs, the function creates the `JSTemporalPlainDate` object and sets its internal slots.

10. **Common Programming Errors (JavaScript Context):**  Consider mistakes users might make with the Temporal API, such as providing out-of-range values for date/time components or incorrect time zone strings.

11. **Structure the Summary:** Organize the findings into logical categories: Core Functionality, Creation of Temporal Objects, Input Validation, Data Structures, Utility Functions, JavaScript Relevance, Error Handling, and Potential User Errors.

12. **Refine and Elaborate:** Add details to each category. For instance, list the specific Temporal objects being created. Explain *why* validation is important. Give concrete JavaScript examples.

13. **Address the Specific Instructions:**
    * `.tq` check: Explicitly state it's not a Torque file.
    * JavaScript relation: Provide relevant JavaScript code examples.
    * Code logic:  Describe the input-output and the validation process.
    * Common errors:  Give JavaScript examples of incorrect usage.
    * Part of a larger series: Acknowledge this and provide a concise summary of the specific snippet.

By following these steps, a comprehensive and accurate summary of the code snippet can be generated. The focus is on understanding the *purpose* of the code and its relationship to the JavaScript Temporal API.
Based on the provided C++ code snippet from `v8/src/objects/js-temporal-objects.cc`, here's a summary of its functionality:

**归纳功能:**

This code snippet focuses on the **creation of various Temporal API objects** within the V8 JavaScript engine. It defines several C++ functions responsible for instantiating and initializing different Temporal objects like `PlainDate`, `PlainTime`, `PlainDateTime`, `Instant`, `TimeZone`, `Duration`, `PlainMonthDay`, `PlainYearMonth`, and `ZonedDateTime`.

**更详细的功能列表:**

1. **Temporal Object Creation:** It provides functions to create instances of various Temporal API objects. Each creation function typically takes the necessary components (like year, month, day, hour, minute, second, nanosecond, calendar, time zone) as input and constructs the corresponding Temporal object.

2. **Constructor Integration:** The code interacts with JavaScript constructors for these Temporal objects. It uses `ORDINARY_CREATE_FROM_CONSTRUCTOR` to create the base JavaScript object and then sets internal slots (like `[[ISOYear]]`, `[[ISOMonth]]`, `[[Nanoseconds]]`, `[[TimeZone]]`, `[[Calendar]]`) with the provided values.

3. **Input Validation:**  Many of the creation functions include validation steps to ensure the provided input values are valid according to the Temporal specification. Examples include:
   - `IsValidISODate`: Checks if the given year, month, and day form a valid ISO date.
   - `ISOYearMonthWithinLimits`: Checks if the year and month are within the allowed range.
   - `IsValidDuration`: Checks if the duration components (years, months, weeks, days, etc.) form a valid duration.
   - `IsValidEpochNanoseconds`: Checks if the provided nanoseconds since the epoch is valid.

4. **Normalization and Balancing:** Functions like `NormalizeMinusZero` and `BalanceISODateTime` are used to normalize and balance date and time components. For example, `BalanceISODateTime` handles cases where the time components overflow (e.g., more than 60 seconds) and adjusts the date components accordingly.

5. **String Conversion:** The code includes functions like `TemporalDurationToString` to convert `DurationRecord` objects into their string representation according to the Temporal specification.

6. **System Time and Time Zone Access:** Functions like `SystemInstant` and `SystemTimeZone` provide ways to access the current system time as an `Instant` and the system's default time zone.

7. **Internal Data Structures:** The code utilizes structures like `DateDurationRecord`, `TimeDurationRecord`, and `DurationRecord` to represent the components of a duration internally.

**如果 v8/src/objects/js-temporal-objects.cc 以 .tq 结尾:**

If the file ended with `.tq`, it would indicate that it's a **Torque source file**. Torque is a domain-specific language used within V8 to generate efficient C++ code for runtime functions. This particular file does not end in `.tq`, so it's standard C++.

**与 JavaScript 功能的关系及示例:**

This C++ code directly implements the core functionality of the JavaScript Temporal API. When you use the Temporal API in JavaScript, the underlying operations often call into these C++ functions.

**JavaScript 示例:**

```javascript
// Creating a Temporal.PlainDate
const plainDate = new Temporal.PlainDate(2023, 10, 27);

// Creating a Temporal.ZonedDateTime
const zonedDateTime = new Temporal.ZonedDateTime(
  BigInt(1677888000000000000), // Nanoseconds since the epoch
  'UTC'
);

// Creating a Temporal.Duration
const duration = new Temporal.Duration(1, 2, 0, 5); // 1 year, 2 months, 5 days
```

When these JavaScript code snippets are executed, V8 will call the corresponding C++ functions (like `CreateTemporalPlainDate`, `CreateTemporalZonedDateTime`, `CreateTemporalDuration`) defined in this file to create and initialize the respective Temporal objects.

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

- `iso_year`: 2024
- `iso_month`: 2
- `iso_day`: 29
- `calendar`: A valid `JSReceiver` representing a calendar (e.g., the ISO 8601 calendar).

**对应调用的 C++ 函数:**  Likely `CreateTemporalPlainDate`.

**输出:**

- A `MaybeHandle<JSTemporalPlainDate>` containing a pointer to a newly created `JSTemporalPlainDate` object.
- The internal slots of the `JSTemporalPlainDate` object would be set as follows:
  - `[[ISOYear]]`: 2024
  - `[[ISOMonth]]`: 2
  - `[[ISODay]]`: 29
  - `[[Calendar]]`:  Points to the provided calendar object.

**如果输入无效 (例如，`iso_month` 为 13):**

- The `IsValidISODate` check would fail.
- The function would throw a `RangeError` exception.
- The `MaybeHandle` would be empty (indicating failure).

**用户常见的编程错误及示例:**

1. **Providing invalid date or time components:**

   ```javascript
   // Error: Month 13 is invalid
   const invalidDate = new Temporal.PlainDate(2023, 13, 15);

   // Error: Day 31 in February is invalid (in a non-leap year)
   const anotherInvalidDate = new Temporal.PlainDate(2023, 2, 31);
   ```
   The C++ validation functions like `IsValidISODate` in this file are responsible for catching these errors and throwing appropriate exceptions.

2. **Using incorrect time zone identifiers:**

   ```javascript
   // Error: 'InvalidTimeZone' is not a valid IANA time zone name
   const invalidZone = new Temporal.ZonedDateTime(BigInt(0), 'InvalidTimeZone');
   ```
   While the provided code doesn't directly handle time zone parsing (it likely delegates to other parts of V8 or the underlying system), the concept of validating input applies here as well.

3. **Creating durations with inconsistent or invalid components:**

   ```javascript
   // Error: This might be considered an invalid duration depending on the specific rules
   const strangeDuration = new Temporal.Duration(1.5, 2.8, 0.1);
   ```
   The `IsValidDuration` function in the C++ code would check the validity of the duration components.

This code snippet is a fundamental part of the V8 implementation for the Temporal API, ensuring that Temporal objects are created correctly and that invalid input is handled appropriately, mirroring the expected behavior of the JavaScript API.

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
ct->set_calendar(*calendar);
  // 10. Set object.[[ISOYear]] to referenceISOYear.
  object->set_iso_year(reference_iso_year);
  // 11. Return object.
  return object;
}

MaybeHandle<JSTemporalPlainMonthDay> CreateTemporalMonthDay(
    Isolate* isolate, int32_t iso_month, int32_t iso_day,
    DirectHandle<JSReceiver> calendar, int32_t reference_iso_year) {
  return CreateTemporalMonthDay(isolate, CONSTRUCTOR(plain_month_day),
                                CONSTRUCTOR(plain_month_day), iso_month,
                                iso_day, calendar, reference_iso_year);
}

// #sec-temporal-createtemporalyearmonth
MaybeHandle<JSTemporalPlainYearMonth> CreateTemporalYearMonth(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    int32_t iso_year, int32_t iso_month, DirectHandle<JSReceiver> calendar,
    int32_t reference_iso_day) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: isoYear, isoMonth, and referenceISODay are integers.
  // 2. Assert: Type(calendar) is Object.
  // 3. If ! IsValidISODate(isoYear, isoMonth, referenceISODay) is false, throw
  // a RangeError exception.
  if (!IsValidISODate(isolate, {iso_year, iso_month, reference_iso_day})) {
    THROW_INVALID_RANGE(JSTemporalPlainYearMonth);
  }
  // 4. If ! ISOYearMonthWithinLimits(isoYear, isoMonth) is false, throw a
  // RangeError exception.
  if (!ISOYearMonthWithinLimits(iso_year, iso_month)) {
    THROW_INVALID_RANGE(JSTemporalPlainYearMonth);
  }
  // 5. If newTarget is not present, set it to %Temporal.PlainYearMonth%.
  // 6. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.PlainYearMonth.prototype%", « [[InitializedTemporalYearMonth]],
  // [[ISOYear]], [[ISOMonth]], [[ISODay]], [[Calendar]] »).
  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalPlainYearMonth)
  object->set_year_month_day(0);
  // 7. Set object.[[ISOYear]] to isoYear.
  object->set_iso_year(iso_year);
  // 8. Set object.[[ISOMonth]] to isoMonth.
  object->set_iso_month(iso_month);
  // 9. Set object.[[Calendar]] to calendar.
  object->set_calendar(*calendar);
  // 10. Set object.[[ISODay]] to referenceISODay.
  object->set_iso_day(reference_iso_day);
  // 11. Return object.
  return object;
}

MaybeHandle<JSTemporalPlainYearMonth> CreateTemporalYearMonth(
    Isolate* isolate, int32_t iso_year, int32_t iso_month,
    DirectHandle<JSReceiver> calendar, int32_t reference_iso_day) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalYearMonth(isolate, CONSTRUCTOR(plain_year_month),
                                 CONSTRUCTOR(plain_year_month), iso_year,
                                 iso_month, calendar, reference_iso_day);
}

// #sec-temporal-createtemporalzoneddatetime
MaybeHandle<JSTemporalZonedDateTime> CreateTemporalZonedDateTime(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    DirectHandle<BigInt> epoch_nanoseconds, DirectHandle<JSReceiver> time_zone,
    DirectHandle<JSReceiver> calendar) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: Type(epochNanoseconds) is BigInt.
  // 2. Assert: ! IsValidEpochNanoseconds(epochNanoseconds) is true.
  DCHECK(IsValidEpochNanoseconds(isolate, epoch_nanoseconds));
  // 3. Assert: Type(timeZone) is Object.
  // 4. Assert: Type(calendar) is Object.
  // 5. If newTarget is not present, set it to %Temporal.ZonedDateTime%.
  // 6. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.ZonedDateTime.prototype%", «
  // [[InitializedTemporalZonedDateTime]], [[Nanoseconds]], [[TimeZone]],
  // [[Calendar]] »).
  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalZonedDateTime)
  // 7. Set object.[[Nanoseconds]] to epochNanoseconds.
  object->set_nanoseconds(*epoch_nanoseconds);
  // 8. Set object.[[TimeZone]] to timeZone.
  object->set_time_zone(*time_zone);
  // 9. Set object.[[Calendar]] to calendar.
  object->set_calendar(*calendar);
  // 10. Return object.
  return object;
}

MaybeHandle<JSTemporalZonedDateTime> CreateTemporalZonedDateTime(
    Isolate* isolate, DirectHandle<BigInt> epoch_nanoseconds,
    DirectHandle<JSReceiver> time_zone, DirectHandle<JSReceiver> calendar) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalZonedDateTime(isolate, CONSTRUCTOR(zoned_date_time),
                                     CONSTRUCTOR(zoned_date_time),
                                     epoch_nanoseconds, time_zone, calendar);
}

inline double NormalizeMinusZero(double v) { return IsMinusZero(v) ? 0 : v; }

// #sec-temporal-createdatedurationrecord
Maybe<DateDurationRecord> DateDurationRecord::Create(
    Isolate* isolate, double years, double months, double weeks, double days) {
  // 1. If ! IsValidDuration(years, months, weeks, days, 0, 0, 0, 0, 0, 0) is
  // false, throw a RangeError exception.
  if (!IsValidDuration(isolate,
                       {years, months, weeks, {days, 0, 0, 0, 0, 0, 0}})) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateDurationRecord>());
  }
  // 2. Return the Record { [[Years]]: ℝ(𝔽(years)), [[Months]]: ℝ(𝔽(months)),
  // [[Weeks]]: ℝ(𝔽(weeks)), [[Days]]: ℝ(𝔽(days)) }.
  DateDurationRecord record = {years, months, weeks, days};
  return Just(record);
}

}  // namespace

namespace temporal {
// #sec-temporal-createtimedurationrecord
Maybe<TimeDurationRecord> TimeDurationRecord::Create(
    Isolate* isolate, double days, double hours, double minutes, double seconds,
    double milliseconds, double microseconds, double nanoseconds) {
  // 1. If ! IsValidDuration(0, 0, 0, days, hours, minutes, seconds,
  // milliseconds, microseconds, nanoseconds) is false, throw a RangeError
  // exception.
  TimeDurationRecord record = {days,         hours,        minutes,    seconds,
                               milliseconds, microseconds, nanoseconds};
  if (!IsValidDuration(isolate, {0, 0, 0, record})) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<TimeDurationRecord>());
  }
  // 2. Return the Record { [[Days]]: ℝ(𝔽(days)), [[Hours]]: ℝ(𝔽(hours)),
  // [[Minutes]]: ℝ(𝔽(minutes)), [[Seconds]]: ℝ(𝔽(seconds)), [[Milliseconds]]:
  // ℝ(𝔽(milliseconds)), [[Microseconds]]: ℝ(𝔽(microseconds)), [[Nanoseconds]]:
  // ℝ(𝔽(nanoseconds)) }.
  return Just(record);
}

// #sec-temporal-createdurationrecord
Maybe<DurationRecord> DurationRecord::Create(
    Isolate* isolate, double years, double months, double weeks, double days,
    double hours, double minutes, double seconds, double milliseconds,
    double microseconds, double nanoseconds) {
  // 1. If ! IsValidDuration(years, months, weeks, days, hours, minutes,
  // seconds, milliseconds, microseconds, nanoseconds) is false, throw a
  // RangeError exception.
  DurationRecord record = {
      years,
      months,
      weeks,
      {days, hours, minutes, seconds, milliseconds, microseconds, nanoseconds}};
  if (!IsValidDuration(isolate, record)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DurationRecord>());
  }
  // 2. Return the Record { [[Years]]: ℝ(𝔽(years)), [[Months]]: ℝ(𝔽(months)),
  // [[Weeks]]: ℝ(𝔽(weeks)), [[Days]]: ℝ(𝔽(days)), [[Hours]]: ℝ(𝔽(hours)),
  // [[Minutes]]: ℝ(𝔽(minutes)), [[Seconds]]: ℝ(𝔽(seconds)), [[Milliseconds]]:
  // ℝ(𝔽(milliseconds)), [[Microseconds]]: ℝ(𝔽(microseconds)), [[Nanoseconds]]:
  // ℝ(𝔽(nanoseconds)) }.
  return Just(record);
}
}  // namespace temporal

namespace {
// #sec-temporal-createtemporalduration
MaybeHandle<JSTemporalDuration> CreateTemporalDuration(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    const DurationRecord& duration) {
  TEMPORAL_ENTER_FUNC();
  Factory* factory = isolate->factory();
  // 1. If ! IsValidDuration(years, months, weeks, days, hours, minutes,
  // seconds, milliseconds, microseconds, nanoseconds) is false, throw a
  // RangeError exception.
  if (!IsValidDuration(isolate, duration)) {
    THROW_INVALID_RANGE(JSTemporalDuration);
  }

  // 2. If newTarget is not present, set it to %Temporal.Duration%.
  // 3. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.Duration.prototype%", « [[InitializedTemporalDuration]],
  // [[Years]], [[Months]], [[Weeks]], [[Days]], [[Hours]], [[Minutes]],
  // [[Seconds]], [[Milliseconds]], [[Microseconds]], [[Nanoseconds]] »).
  const TimeDurationRecord& time_duration = duration.time_duration;
  DirectHandle<Number> years =
      factory->NewNumber(NormalizeMinusZero(duration.years));
  DirectHandle<Number> months =
      factory->NewNumber(NormalizeMinusZero(duration.months));
  DirectHandle<Number> weeks =
      factory->NewNumber(NormalizeMinusZero(duration.weeks));
  DirectHandle<Number> days =
      factory->NewNumber(NormalizeMinusZero(time_duration.days));
  DirectHandle<Number> hours =
      factory->NewNumber(NormalizeMinusZero(time_duration.hours));
  DirectHandle<Number> minutes =
      factory->NewNumber(NormalizeMinusZero(time_duration.minutes));
  DirectHandle<Number> seconds =
      factory->NewNumber(NormalizeMinusZero(time_duration.seconds));
  DirectHandle<Number> milliseconds =
      factory->NewNumber(NormalizeMinusZero(time_duration.milliseconds));
  DirectHandle<Number> microseconds =
      factory->NewNumber(NormalizeMinusZero(time_duration.microseconds));
  DirectHandle<Number> nanoseconds =
      factory->NewNumber(NormalizeMinusZero(time_duration.nanoseconds));
  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalDuration)
  // 4. Set object.[[Years]] to ℝ(𝔽(years)).
  object->set_years(*years);
  // 5. Set object.[[Months]] to ℝ(𝔽(months)).
  object->set_months(*months);
  // 6. Set object.[[Weeks]] to ℝ(𝔽(weeks)).
  object->set_weeks(*weeks);
  // 7. Set object.[[Days]] to ℝ(𝔽(days)).
  object->set_days(*days);
  // 8. Set object.[[Hours]] to ℝ(𝔽(hours)).
  object->set_hours(*hours);
  // 9. Set object.[[Minutes]] to ℝ(𝔽(minutes)).
  object->set_minutes(*minutes);
  // 10. Set object.[[Seconds]] to ℝ(𝔽(seconds)).
  object->set_seconds(*seconds);
  // 11. Set object.[[Milliseconds]] to ℝ(𝔽(milliseconds)).
  object->set_milliseconds(*milliseconds);
  // 12. Set object.[[Microseconds]] to ℝ(𝔽(microseconds)).
  object->set_microseconds(*microseconds);
  // 13. Set object.[[Nanoseconds]] to ℝ(𝔽(nanoseconds)).
  object->set_nanoseconds(*nanoseconds);
  // 14. Return object.
  return object;
}

MaybeHandle<JSTemporalDuration> CreateTemporalDuration(
    Isolate* isolate, const DurationRecord& duration) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalDuration(isolate, CONSTRUCTOR(duration),
                                CONSTRUCTOR(duration), duration);
}

}  // namespace

namespace temporal {

// #sec-temporal-createtemporalinstant
MaybeHandle<JSTemporalInstant> CreateTemporalInstant(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    DirectHandle<BigInt> epoch_nanoseconds) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: Type(epochNanoseconds) is BigInt.
  // 2. Assert: ! IsValidEpochNanoseconds(epochNanoseconds) is true.
  DCHECK(IsValidEpochNanoseconds(isolate, epoch_nanoseconds));

  // 4. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.Instant.prototype%", « [[InitializedTemporalInstant]],
  // [[Nanoseconds]] »).
  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalInstant)
  // 5. Set object.[[Nanoseconds]] to ns.
  object->set_nanoseconds(*epoch_nanoseconds);
  return object;
}

MaybeHandle<JSTemporalInstant> CreateTemporalInstant(
    Isolate* isolate, DirectHandle<BigInt> epoch_nanoseconds) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalInstant(isolate, CONSTRUCTOR(instant),
                               CONSTRUCTOR(instant), epoch_nanoseconds);
}

}  // namespace temporal

namespace {

MaybeHandle<JSTemporalTimeZone> CreateTemporalTimeZoneFromIndex(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    int32_t index) {
  TEMPORAL_ENTER_FUNC();
  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalTimeZone)
  object->set_flags(0);
  object->set_details(0);

  object->set_is_offset(false);
  object->set_offset_milliseconds_or_time_zone_index(index);
  return object;
}

Handle<JSTemporalTimeZone> CreateTemporalTimeZoneUTC(
    Isolate* isolate, Handle<JSFunction> target,
    Handle<HeapObject> new_target) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalTimeZoneFromIndex(isolate, target, new_target, 0)
      .ToHandleChecked();
}

Handle<JSTemporalTimeZone> CreateTemporalTimeZoneUTC(Isolate* isolate) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalTimeZoneUTC(isolate, CONSTRUCTOR(time_zone),
                                   CONSTRUCTOR(time_zone));
}

bool IsUTC(Isolate* isolate, Handle<String> time_zone);

// #sec-temporal-createtemporaltimezone
MaybeHandle<JSTemporalTimeZone> CreateTemporalTimeZone(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<String> identifier) {
  TEMPORAL_ENTER_FUNC();

  // 1. If newTarget is not present, set it to %Temporal.TimeZone%.
  // 2. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.TimeZone.prototype%", « [[InitializedTemporalTimeZone]],
  // [[Identifier]], [[OffsetNanoseconds]] »).

  // 3. Let offsetNanosecondsResult be ParseTimeZoneOffsetString(identifier).
  Maybe<int64_t> maybe_offset_nanoseconds =
      ParseTimeZoneOffsetString(isolate, identifier);
  // 4. If offsetNanosecondsResult is an abrupt completion, then
  if (maybe_offset_nanoseconds.IsNothing()) {
    DCHECK(isolate->has_exception());
    isolate->clear_exception();
    // a. Assert: ! CanonicalizeTimeZoneName(identifier) is identifier.
    DCHECK(String::Equals(isolate, identifier,
                          CanonicalizeTimeZoneName(isolate, identifier)));

    // b. Set object.[[Identifier]] to identifier.
    // c. Set object.[[OffsetNanoseconds]] to undefined.
    if (IsUTC(isolate, identifier)) {
      return CreateTemporalTimeZoneUTC(isolate, target, new_target);
    }
#ifdef V8_INTL_SUPPORT
    int32_t time_zone_index = Intl::GetTimeZoneIndex(isolate, identifier);
    DCHECK_GE(time_zone_index, 0);
    return CreateTemporalTimeZoneFromIndex(isolate, target, new_target,
                                           time_zone_index);
#else
    UNREACHABLE();
#endif  // V8_INTL_SUPPORT
    // 5. Else,
  } else {
    // a. Set object.[[Identifier]] to !
    // FormatTimeZoneOffsetString(offsetNanosecondsResult.[[Value]]). b. Set
    // object.[[OffsetNanoseconds]] to offsetNanosecondsResult.[[Value]].
    ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                     JSTemporalTimeZone)
    object->set_flags(0);
    object->set_details(0);

    object->set_is_offset(true);
    object->set_offset_nanoseconds(maybe_offset_nanoseconds.FromJust());
    return object;
  }
  // 6. Return object.
}

MaybeHandle<JSTemporalTimeZone> CreateTemporalTimeZoneDefaultTarget(
    Isolate* isolate, Handle<String> identifier) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalTimeZone(isolate, CONSTRUCTOR(time_zone),
                                CONSTRUCTOR(time_zone), identifier);
}

}  // namespace

namespace temporal {
MaybeHandle<JSTemporalTimeZone> CreateTemporalTimeZone(
    Isolate* isolate, Handle<String> identifier) {
  return CreateTemporalTimeZoneDefaultTarget(isolate, identifier);
}
}  // namespace temporal

namespace {

// #sec-temporal-systeminstant
Handle<JSTemporalInstant> SystemInstant(Isolate* isolate) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let ns be ! SystemUTCEpochNanoseconds().
  DirectHandle<BigInt> ns = SystemUTCEpochNanoseconds(isolate);
  // 2. Return ? CreateTemporalInstant(ns).
  return temporal::CreateTemporalInstant(isolate, ns).ToHandleChecked();
}

// #sec-temporal-systemtimezone
Handle<JSTemporalTimeZone> SystemTimeZone(Isolate* isolate) {
  TEMPORAL_ENTER_FUNC();
  Handle<String> default_time_zone = DefaultTimeZone(isolate);
  return temporal::CreateTemporalTimeZone(isolate, default_time_zone)
      .ToHandleChecked();
}

DateTimeRecord GetISOPartsFromEpoch(Isolate* isolate,
                                    Handle<BigInt> epoch_nanoseconds) {
  TEMPORAL_ENTER_FUNC();
  DateTimeRecord result;
  // 1. Assert: ! IsValidEpochNanoseconds(ℤ(epochNanoseconds)) is true.
  DCHECK(IsValidEpochNanoseconds(isolate, epoch_nanoseconds));
  // 2. Let remainderNs be epochNanoseconds modulo 10^6.
  Handle<BigInt> million = BigInt::FromUint64(isolate, 1000000);
  Handle<BigInt> remainder_ns =
      BigInt::Remainder(isolate, epoch_nanoseconds, million).ToHandleChecked();
  // Need to do some remainder magic to negative remainder.
  if (remainder_ns->IsNegative()) {
    remainder_ns =
        BigInt::Add(isolate, remainder_ns, million).ToHandleChecked();
  }

  // 3. Let epochMilliseconds be (epochNanoseconds − remainderNs) / 10^6.
  int64_t epoch_milliseconds =
      BigInt::Divide(isolate,
                     BigInt::Subtract(isolate, epoch_nanoseconds, remainder_ns)
                         .ToHandleChecked(),
                     million)
          .ToHandleChecked()
          ->AsInt64();
  int year = 0;
  int month = 0;
  int day = 0;
  int wday = 0;
  int hour = 0;
  int min = 0;
  int sec = 0;
  int ms = 0;
  isolate->date_cache()->BreakDownTime(epoch_milliseconds, &year, &month, &day,
                                       &wday, &hour, &min, &sec, &ms);

  // 4. Let year be ! YearFromTime(epochMilliseconds).
  result.date.year = year;
  // 5. Let month be ! MonthFromTime(epochMilliseconds) + 1.
  result.date.month = month + 1;
  DCHECK_GE(result.date.month, 1);
  DCHECK_LE(result.date.month, 12);
  // 6. Let day be ! DateFromTime(epochMilliseconds).
  result.date.day = day;
  DCHECK_GE(result.date.day, 1);
  DCHECK_LE(result.date.day, 31);
  // 7. Let hour be ! HourFromTime(epochMilliseconds).
  result.time.hour = hour;
  DCHECK_GE(result.time.hour, 0);
  DCHECK_LE(result.time.hour, 23);
  // 8. Let minute be ! MinFromTime(epochMilliseconds).
  result.time.minute = min;
  DCHECK_GE(result.time.minute, 0);
  DCHECK_LE(result.time.minute, 59);
  // 9. Let second be ! SecFromTime(epochMilliseconds).
  result.time.second = sec;
  DCHECK_GE(result.time.second, 0);
  DCHECK_LE(result.time.second, 59);
  // 10. Let millisecond be ! msFromTime(epochMilliseconds).
  result.time.millisecond = ms;
  DCHECK_GE(result.time.millisecond, 0);
  DCHECK_LE(result.time.millisecond, 999);
  // 11. Let microsecond be floor(remainderNs / 1000) modulo 1000.
  int64_t remainder = remainder_ns->AsInt64();
  result.time.microsecond = (remainder / 1000) % 1000;
  DCHECK_GE(result.time.microsecond, 0);
  // 12. 12. Assert: microsecond < 1000.
  DCHECK_LE(result.time.microsecond, 999);
  // 13. Let nanosecond be remainderNs modulo 1000.
  result.time.nanosecond = remainder % 1000;
  DCHECK_GE(result.time.nanosecond, 0);
  DCHECK_LE(result.time.nanosecond, 999);
  // 14. Return the Record { [[Year]]: year, [[Month]]: month, [[Day]]: day,
  // [[Hour]]: hour, [[Minute]]: minute, [[Second]]: second, [[Millisecond]]:
  // millisecond, [[Microsecond]]: microsecond, [[Nanosecond]]: nanosecond }.
  return result;
}

// #sec-temporal-balanceisodatetime
DateTimeRecord BalanceISODateTime(Isolate* isolate,
                                  const DateTimeRecord& date_time) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: year, month, day, hour, minute, second, millisecond,
  // microsecond, and nanosecond are integers.
  // 2. Let balancedTime be ! BalanceTime(hour, minute, second, millisecond,
  // microsecond, nanosecond).
  DateTimeRecord balanced_time =
      BalanceTime({static_cast<double>(date_time.time.hour),
                   static_cast<double>(date_time.time.minute),
                   static_cast<double>(date_time.time.second),
                   static_cast<double>(date_time.time.millisecond),
                   static_cast<double>(date_time.time.microsecond),
                   static_cast<double>(date_time.time.nanosecond)});
  // 3. Let balancedDate be ! BalanceISODate(year, month, day +
  // balancedTime.[[Days]]).
  DateRecord added_date = date_time.date;
  added_date.day += balanced_time.date.day;
  DateRecord balanced_date = BalanceISODate(isolate, added_date);
  // 4. Return the Record { [[Year]]: balancedDate.[[Year]], [[Month]]:
  // balancedDate.[[Month]], [[Day]]: balancedDate.[[Day]], [[Hour]]:
  // balancedTime.[[Hour]], [[Minute]]: balancedTime.[[Minute]], [[Second]]:
  // balancedTime.[[Second]], [[Millisecond]]: balancedTime.[[Millisecond]],
  // [[Microsecond]]: balancedTime.[[Microsecond]], [[Nanosecond]]:
  // balancedTime.[[Nanosecond]] }.
  return {balanced_date, balanced_time.time};
}

// #sec-temporal-roundtowardszero
double RoundTowardsZero(double x) {
  // 1. Return the mathematical value that is the same sign as x and whose
  // magnitude is floor(abs(x)).
  if (x < 0) {
    return -std::floor(std::abs(x));
  } else {
    return std::floor(std::abs(x));
  }
}

// #sec-temporal-temporaldurationtostring
Handle<String> TemporalDurationToString(Isolate* isolate,
                                        const DurationRecord& duration,
                                        Precision precision) {
  IncrementalStringBuilder builder(isolate);
  DCHECK(precision != Precision::kMinute);
  // 1. Let sign be ! DurationSign(years, months, weeks, days, hours, minutes,
  // seconds, milliseconds, microseconds, nanoseconds).
  DurationRecord dur = duration;
  int32_t sign = DurationRecord::Sign(dur);
  // Note: for the operation below, to avoid microseconds .. seconds lost
  // precision while the resulting value may exceed the precision limit, we use
  // extra double xx_add to hold the additional temp value.
  // 2. Set microseconds to microseconds + RoundTowardsZero(nanoseconds / 1000).
  double microseconds_add =
      RoundTowardsZero(dur.time_duration.nanoseconds / 1000);
  // 3. Set nanoseconds to remainder(nanoseconds, 1000).
  dur.time_duration.nanoseconds =
      std::fmod(dur.time_duration.nanoseconds, 1000);
  // 4. Set milliseconds to milliseconds + RoundTowardsZero(microseconds /
  // 1000).
  double milliseconds_add = RoundTowardsZero(
      dur.time_duration.microseconds / 1000 + microseconds_add / 1000);
  // 5. Set microseconds to remainder(microseconds, 1000).
  dur.time_duration.microseconds =
      std::fmod(std::fmod(dur.time_duration.microseconds, 1000) +
                    std::fmod(microseconds_add, 1000),
                1000);
  // 6. Set seconds to seconds + RoundTowardsZero(milliseconds / 1000).
  double seconds_add = RoundTowardsZero(dur.time_duration.milliseconds / 1000 +
                                        milliseconds_add / 1000);
  // 7. Set milliseconds to remainder(milliseconds, 1000).
  dur.time_duration.milliseconds =
      std::fmod(std::fmod(dur.time_duration.milliseconds, 1000) +
                    std::fmod(milliseconds_add, 1000),
                1000);

  // 8. Let datePart be "".
  IncrementalStringBuilder date_part(isolate);
  // Number.MAX_VALUE.toString() is "1.7976931348623157e+308"
  // We add several more spaces to 320.
  base::ScopedVector<char> buf(320);

  // 9. If years is not 0, then
  if (dur.years != 0) {
    // a. Set datePart to the string concatenation of abs(years) formatted as a
    // decimal number and the code unit 0x0059 (LATIN CAPITAL LETTER Y).
    SNPrintF(buf, "%.0f", std::abs(dur.years));
    date_part.AppendCString(buf.data());
    date_part.AppendCharacter('Y');
  }
  // 10. If months is not 0, then
  if (dur.months != 0) {
    // a. Set datePart to the string concatenation of datePart,
    // abs(months) formatted as a decimal number, and the code unit
    // 0x004D (LATIN CAPITAL LETTER M).
    SNPrintF(buf, "%.0f", std::abs(dur.months));
    date_part.AppendCString(buf.data());
    date_part.AppendCharacter('M');
  }
  // 11. If weeks is not 0, then
  if (dur.weeks != 0) {
    // a. Set datePart to the string concatenation of datePart,
    // abs(weeks) formatted as a decimal number, and the code unit
    // 0x0057 (LATIN CAPITAL LETTER W).
    SNPrintF(buf, "%.0f", std::abs(dur.weeks));
    date_part.AppendCString(buf.data());
    date_part.AppendCharacter('W');
  }
  // 12. If days is not 0, then
  if (dur.time_duration.days != 0) {
    // a. Set datePart to the string concatenation of datePart,
    // abs(days) formatted as a decimal number, and the code unit 0x0044
    // (LATIN CAPITAL LETTER D).
    SNPrintF(buf, "%.0f", std::abs(dur.time_duration.days));
    date_part.AppendCString(buf.data());
    date_part.AppendCharacter('D');
  }
  // 13. Let timePart be "".
  IncrementalStringBuilder time_part(isolate);
  // 14. If hours is not 0, then
  if (dur.time_duration.hours != 0) {
    // a. Set timePart to the string concatenation of abs(hours) formatted as a
    // decimal number and the code unit 0x0048 (LATIN CAPITAL LETTER H).
    SNPrintF(buf, "%.0f", std::abs(dur.time_duration.hours));
    time_part.AppendCString(buf.data());
    time_part.AppendCharacter('H');
  }
  // 15. If minutes is not 0, then
  if (dur.time_duration.minutes != 0) {
    // a. Set timePart to the string concatenation of timePart,
    // abs(minutes) formatted as a decimal number, and the code unit
    // 0x004D (LATIN CAPITAL LETTER M).
    SNPrintF(buf, "%.0f", std::abs(dur.time_duration.minutes));
    time_part.AppendCString(buf.data());
    time_part.AppendCharacter('M');
  }
  IncrementalStringBuilder seconds_part(isolate);
  IncrementalStringBuilder decimal_part(isolate);
  // 16. If any of seconds, milliseconds, microseconds, and nanoseconds are not
  // 0; or years, months, weeks, days, hours, and minutes are all 0, or
  // precision is not "auto" then
  if ((dur.time_duration.seconds != 0 || seconds_add != 0 ||
       dur.time_duration.milliseconds != 0 ||
       dur.time_duration.microseconds != 0 ||
       dur.time_duration.nanoseconds != 0) ||
      (dur.years == 0 && dur.months == 0 && dur.weeks == 0 &&
       dur.time_duration.days == 0 && dur.time_duration.hours == 0 &&
       dur.time_duration.minutes == 0) ||
      precision != Precision::kAuto) {
    // a. Let fraction be abs(milliseconds) × 10^6 + abs(microseconds) × 10^3 +
    // abs(nanoseconds).
    int64_t fraction = std::abs(dur.time_duration.milliseconds) * 1e6 +
                       std::abs(dur.time_duration.microseconds) * 1e3 +
                       std::abs(dur.time_duration.nanoseconds);
    // b. Let decimalPart be fraction formatted as a nine-digit decimal number,
    // padded to the left with zeroes if necessary.
    int64_t divisor = 100000000;

    // c. If precision is "auto", then
    if (precision == Precision::kAuto) {
      // i. Set decimalPart to the longest possible substring of decimalPart
      // starting at position 0 and not ending with the code unit 0x0030 (DIGIT
      // ZERO).
      while (fraction > 0) {
        decimal_part.AppendInt(static_cast<int32_t>(fraction / divisor));
        fraction %= divisor;
        divisor /= 10;
      }
      // d. Else if precision = 0, then
    } else if (precision == Precision::k0) {
      // i. Set decimalPart to "".
      // e. Else,
    } else {
      // i. Set decimalPart to the substring of decimalPart from 0 to precision.
      int32_t precision_len = static_cast<int32_t>(precision);
      DCHECK_LE(0, precision_len);
      DCHECK_GE(9, precision_len);
      for (int32_t len = 0; len < precision_len; len++) {
        decimal_part.AppendInt(static_cast<int32_t>(fraction / divisor));
        fraction %= divisor;
        divisor /= 10;
      }
    }
    // f. Let secondsPart be abs(seconds) formatted as a decimal number.
    if (std::abs(seconds_add + dur.time_duration.seconds) < kMaxSafeInteger) {
      // Fast path: The seconds_add + dur.time_duration.seconds is in the range
      // the double could keep the precision.
      dur.time_duration.seconds += seconds_add;
      SNPrintF(buf, "%.0f", std::abs(dur.time_duration.seconds));
      seconds_part.AppendCString(buf.data());
    } else {
      // Slow path: The seconds_add + dur.time_duration.seconds is out of the
      // range which the double could keep the precision. Format by math via
      // BigInt.
      seconds_part.AppendString(
          BigInt::ToString(
              isolate,
              BigInt::Add(
                  isolate,
                  BigInt::FromNumber(isolate, isolate->factory()->NewNumber(
                                                  std::abs(seconds_add)))
                      .ToHandleChecked(),
                  BigInt::FromNumber(isolate,
                                     isolate->factory()->NewNumber(
                                         std::abs(dur.time_duration.seconds)))
                      .ToHandleChecked())
                  .ToHandleChecked())
              .ToHandleChecked());
    }

    // g. If decimalPart is not "", then
    if (decimal_part.Length() != 0) {
      // i. Set secondsPart to the string-concatenation of secondsPart, the code
      // unit 0x002E (FULL STOP), and decimalPart.
      seconds_part.AppendCharacter('.');
      seconds_part.AppendString(decimal_part.Finish().ToHandleChecked());
    }

    // h. Set timePart to the string concatenation of timePart, secondsPart, and
    // the code unit 0x0053 (LATIN CAPITAL LETTER S).
    time_part.AppendString(seconds_part.Finish().ToHandleChecked());
    time_part.AppendCharacter('S');
  }
  // 17. Let signPart be the code unit 0x002D (HYPHEN-MINUS) if sign < 0, and
  // otherwise the empty String.
  if (sign < 0) {
    builder.AppendCharacter('-');
  }

  // 18. Let result be the string concatenation of signPart, the code unit
  // 0x0050 (LATIN CAPITAL LETTER P) and datePart.
  builder.AppendCharacter('P');
  builder.AppendString(date_part.Finish().ToHandleChecked());

  // 19. If timePart is not "", then
  if (time_part.Length() > 0) {
    // a. Set result to the string concatenation of result, the code unit 0x0054
    // (LATIN CAPITAL LETTER T), and timePart.
    builder.AppendCharacter('T');
    builder.AppendString(time_part.Finish().ToHandleChecked());
  }
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

void ToZeroPaddedDecimalString(IncrementalStringBuilder* builder, int32_t n,
                               int32_t min_length);
// #sec-temporal-formatsecondsstringpart
void FormatSecondsStringPart(IncrementalStringBuilder* builder, int32_t second,
                             int32_t millisecond, int32_t microsecond,
                             int32_t nanosecond, Precision precision) {
  // 1. Assert: second, millisecond, microsecond and nanosecond are integers.
  // 2. If precision is "minute", return "".
  if (precision == Precision::kMinute) {
    return;
  }
  // 3. Let secondsString be the string-concatenation of the code unit 0x003A
  // (COLON) and second formatted as a two-digit decimal number, padded to the
  // left with zeroes if necessary.
  builder->AppendCharacter(':');
  ToZeroPaddedDecimalString(builder, second, 2);
  // 4. Let fraction be millisecond × 10^6 + microsecond × 10^3 + nanosecond.
  int64_t fraction = millisecond * 1000000 + microsecond * 1000 + nanosecond;
  int64_t divisor = 100000000;
  // 5. If precision is "auto", then
  if (precision == Precision::kAuto) {
    // a. If fraction is 0, return secondsString.
    if (fraction == 0) {
      return;
    }
    builder->AppendCharacter('.');
    // b. Set fraction to ToZeroPaddedDecimalString(fraction, 9).
    // c. Set fraction to the longest possible substring of fraction starting at
    // position 0 and not ending with the code unit 0x0030 (DIGIT ZERO).
    while (fraction > 0) {
      builder->AppendInt(static_cast<int32_t>(fraction / divisor));
      fraction %= divisor;
      divisor /= 10;
    }
    // 6. Else,
  } else {
    // a. If precision is 0, return secondsString.
    if (precision == Precision::k0) {
      return;
    }
    builder->AppendCharacter('.');
    // b. Set fraction to ToZeroPaddedDecimalString(fraction, 9).
    // c. Set fraction to the substring of fraction from 0 to precision.
    int32_t precision_len = static_cast<int32_t>(precision);
    DCHECK_LE(0, precision_len);
    DCHECK_GE(9, precision_len);
    for (int32_t len = 0; len < precision_len; len++) {
      builder->AppendInt(static_cast<int32_t>(fraction / divisor));
```