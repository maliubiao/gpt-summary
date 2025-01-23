Response:
Let's break down the thought process for analyzing the provided V8 C++ code snippet.

1. **Identify the Core Subject:** The filename `v8/src/objects/js-temporal-objects.cc` and the class names like `JSTemporalInstant` immediately tell us this code is related to the "Temporal" API in JavaScript and specifically deals with the `Instant` object.

2. **Scan for Key Methods:** Look for methods with names that correspond to common `Temporal.Instant` methods in JavaScript. We see:
    * `Round`
    * `From`
    * `ToZonedDateTime`
    * `ToJSON`
    * `ToLocaleString`
    * `ToString`
    * `ToZonedDateTimeISO`
    * `Add`
    * `Subtract`
    * `Until`
    * `Since`

3. **Analyze Individual Method Functionality:**  For each key method, read the code comments and the logic to understand what it does. Pay attention to:
    * **Input parameters:** What types of arguments does it take? Are there checks for specific types or internal slots?
    * **Internal steps:** What are the numbered steps? These directly correspond to the ECMAScript specification.
    * **Helper functions:** Are there calls to other functions (e.g., `GetTemporalUnit`, `ToTemporalRoundingMode`, `CreateTemporalInstant`, `GetOffsetNanosecondsFor`)? This indicates dependencies on other parts of the Temporal implementation.
    * **Error handling:** Does the code throw exceptions (`THROW_NEW_ERROR`)? Under what conditions?
    * **Return values:** What does the method return?  Is it a `MaybeHandle` which indicates potential failure?

4. **Infer Relationships to JavaScript:** Connect the C++ methods to their JavaScript counterparts. For example, `JSTemporalInstant::Round` directly implements `Temporal.Instant.prototype.round()`. Consider how the C++ code manipulates the internal representation of `Temporal.Instant` (likely nanoseconds since the epoch).

5. **Look for Code Logic and Potential Edge Cases:**
    * **Rounding:** The `Round` method has significant logic for handling different rounding units and modes. Think about how different inputs would affect the output.
    * **Time Zones:**  Methods like `ToZonedDateTime` and `ToString` involve time zone conversions. This is a complex area with potential for errors.
    * **Duration Arithmetic:** `Add` and `Subtract` operate on durations. Consider the constraints on the duration values (e.g., the comment about only allowing time units for `Instant` addition/subtraction).
    * **Difference Calculations:** `Until` and `Since` calculate the difference between two instants. Pay attention to the `DifferenceSettings` and how different options affect the result.

6. **Identify Potential User Errors:** Based on the code and its connection to JavaScript, think about common mistakes developers might make when using the `Temporal.Instant` API:
    * Incorrect types for arguments (e.g., passing a number where an object is expected).
    * Providing invalid rounding units or increments.
    * Not understanding the impact of time zones on conversions and string representations.
    * Trying to add or subtract durations with date components from an `Instant`.

7. **Synthesize and Organize:** Group the findings into logical categories: core functionality, interaction with JavaScript, code logic examples, potential errors, and the overall purpose of the file.

8. **Address Specific Instructions:**  Make sure to answer all parts of the prompt:
    * List the functions.
    * Confirm it's C++ (not Torque).
    * Provide JavaScript examples.
    * Give input/output examples for logic.
    * List common programming errors.
    * Summarize the overall purpose (as part 25/25).

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This file just handles basic `Instant` operations."  **Correction:**  Realized the rounding and time zone conversion logic is quite involved.
* **Considering Torque:** Double-checked the `.cc` extension to confirm it's not a Torque file.
* **JavaScript examples:** Initially thought of very simple examples, but then realized more illustrative examples showing different options and scenarios would be better.
* **Input/Output:**  Initially focused on just one example, but realized showing variations based on rounding or time zones would be more helpful.
* **Error examples:** Tried to think of errors beyond just type errors, considering the specific constraints of the Temporal API.
* **Summary (Part 25/25):**  Emphasized the "final part" aspect and the culmination of `Instant` functionality within the larger Temporal API.

By following this structured approach, analyzing the code, and considering the context of the Temporal API, we can arrive at a comprehensive understanding of the functionality of `v8/src/objects/js-temporal-objects.cc`.
This C++ source code file, `v8/src/objects/js-temporal-objects.cc`, is a core component of the V8 JavaScript engine's implementation of the ECMAScript Temporal API, specifically focusing on the `Temporal.Instant` object.

Here's a breakdown of its functionalities:

**Core Functionality: Implementation of `Temporal.Instant` Methods**

This file implements the native C++ logic for various methods available on the `Temporal.Instant` prototype in JavaScript. `Temporal.Instant` represents a specific moment in time, independent of any time zone or calendar. The key functionalities implemented here include:

* **`Round()`:**  Rounds a `Temporal.Instant` to a specific unit (e.g., seconds, minutes, hours). It handles different rounding modes (e.g., `halfExpand`, `ceil`, `floor`, `trunc`).
* **`From()`:** Creates a `Temporal.Instant` from various input types, including existing `Temporal.Instant` objects and other objects that can be converted to a `Temporal.Instant`.
* **`ToZonedDateTime()`:** Converts a `Temporal.Instant` to a `Temporal.ZonedDateTime` by combining it with a specific time zone and calendar.
* **`ToJSON()`:** Returns an ISO 8601 string representation of the `Temporal.Instant` in UTC.
* **`ToLocaleString()`:** Returns a language-sensitive representation of the `Temporal.Instant`. (Implementation might rely on `Intl` support).
* **`ToString()`:** Returns a string representation of the `Temporal.Instant`, allowing customization of precision and time zone.
* **`ToZonedDateTimeISO()`:** Similar to `ToZonedDateTime()`, but always uses the ISO 8601 calendar.
* **`Add()`:** Adds a `Temporal.Duration` to a `Temporal.Instant`, resulting in a new `Temporal.Instant`. Only time units (hours, minutes, seconds, milliseconds, microseconds, nanoseconds) in the duration are allowed.
* **`Subtract()`:** Subtracts a `Temporal.Duration` from a `Temporal.Instant`, resulting in a new `Temporal.Instant`. Only time units in the duration are allowed.
* **`Until()`:** Calculates the `Temporal.Duration` between two `Temporal.Instant` objects, expressing the difference in larger units (e.g., hours, minutes).
* **`Since()`:** Calculates the `Temporal.Duration` between two `Temporal.Instant` objects, similar to `Until()` but the duration represents how much time has passed since the other instant.

**Is it a Torque Source File?**

The filename ends with `.cc`, which is the standard extension for C++ source files in V8. If it ended with `.tq`, then it would be a Torque source file. Therefore, this is **not** a V8 Torque source file.

**Relationship to JavaScript and Examples**

This C++ code directly implements the behavior of the `Temporal.Instant` object in JavaScript. When you use `Temporal.Instant` methods in your JavaScript code, the V8 engine executes the corresponding C++ functions in this file.

Here are some JavaScript examples illustrating the functionalities:

```javascript
const now = Temporal.Instant.now();
console.log(now.toString()); // Output: e.g., 2023-10-27T10:00:00.123456789Z

// Rounding
const roundedToSeconds = now.round({ smallestUnit: 'second' });
console.log(roundedToSeconds.toString());

// Adding a duration
const later = now.add(Temporal.Duration.from({ hours: 1 }));
console.log(later.toString());

// Converting to ZonedDateTime
const parisTimeZone = Temporal.TimeZone.from('Europe/Paris');
const zonedDateTime = now.toZonedDateTime({ timeZone: parisTimeZone, calendar: 'iso8601' });
console.log(zonedDateTime.toString());

// Calculating the difference
const future = now.add(Temporal.Duration.from({ minutes: 30 }));
const difference = now.until(future);
console.log(difference.toString());
```

**Code Logic Inference: `Round()` Example**

Let's consider the `Round()` function.

**Hypothetical Input:**

* `instant`: A `Temporal.Instant` representing `2023-10-27T10:00:30.500000000Z` (internally stored as a BigInt representing nanoseconds since the epoch).
* `roundTo_obj`: A JavaScript object `{ smallestUnit: 'second', roundingMode: 'halfExpand' }`.

**Code Logic Flow:**

1. The code retrieves the `smallestUnit` ("second") and `roundingMode` ("halfExpand").
2. It calculates the `roundingIncrement` based on the `smallestUnit` (1 for seconds).
3. `RoundTemporalInstant` (another internal function) is called with the instant's nanoseconds, the rounding increment, the smallest unit, and the rounding mode.
4. `RoundTemporalInstant` performs the rounding logic. Since the fractional part of the second (500 milliseconds) is exactly half, and the rounding mode is 'halfExpand', it will round up.

**Hypothetical Output:**

A new `Temporal.Instant` representing `2023-10-27T10:00:31Z`.

**Common Programming Errors (Related to User Interaction)**

Users might encounter these errors when working with `Temporal.Instant`:

1. **Incorrect Type for `roundTo` in `round()`:** Passing a number or `null` directly instead of an object with `smallestUnit`.
   ```javascript
   const now = Temporal.Instant.now();
   // Error: TypeError: Invalid argument type
   const rounded = now.round('second');
   ```

2. **Invalid `smallestUnit` in `round()`:**  Providing a string that is not a valid Temporal unit.
   ```javascript
   const now = Temporal.Instant.now();
   // Error: RangeError: Invalid units specified for smallestUnit
   const rounded = now.round({ smallestUnit: 'fortnight' });
   ```

3. **Trying to add or subtract durations with date components:** `Temporal.Instant` only represents a point in time, so adding or subtracting things like months or years is not directly supported. This needs to be done via conversion to `Temporal.ZonedDateTime` or `Temporal.PlainDateTime`.
   ```javascript
   const now = Temporal.Instant.now();
   const duration = Temporal.Duration.from({ months: 1 });
   // Error: RangeError: day, week, month, or year units are not allowed when adding to or subtracting from an Instant
   const later = now.add(duration);
   ```

4. **Not understanding the impact of time zones:** When converting to a string or `ZonedDateTime`, the time zone plays a crucial role. Forgetting to specify a time zone or using the wrong one can lead to unexpected results.

**归纳一下它的功能 (Summary of its Functionality)**

As the 25th and final part related to `Temporal.Instant`, this file encapsulates the core, low-level C++ implementation of the `Temporal.Instant` object's behavior within the V8 JavaScript engine. It handles the fundamental operations of creating, manipulating (rounding, adding, subtracting), converting, and representing specific moments in time, forming a crucial building block for the Temporal API in JavaScript. It ensures the accurate and efficient execution of `Temporal.Instant` methods when JavaScript code utilizes them.

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第25部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
ate, ns, increment_ns,
                                            rounding_mode);
}

}  // namespace

// #sec-temporal.instant.prototype.round
MaybeHandle<JSTemporalInstant> JSTemporalInstant::Round(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> round_to_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.Instant.prototype.round";
  Factory* factory = isolate->factory();
  // 1. Let instant be the this value.
  // 2. Perform ? RequireInternalSlot(instant, [[InitializedTemporalInstant]]).
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
    // a. Set roundTo to ? GetOptionsObject(roundTo).
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
      Handle<JSTemporalInstant>());

  // 7. Let roundingMode be ? ToTemporalRoundingMode(roundTo, "halfExpand").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, round_to, RoundingMode::kHalfExpand,
                             method_name),
      Handle<JSTemporalInstant>());
  double maximum;
  switch (smallest_unit) {
    // 8. If smallestUnit is "hour", then
    case Unit::kHour:
      // a. Let maximum be 24.
      maximum = 24;
      break;
    // 9. Else if smallestUnit is "minute", then
    case Unit::kMinute:
      // a. Let maximum be 1440.
      maximum = 1440;
      break;
    // 10. Else if smallestUnit is "second", then
    case Unit::kSecond:
      // a. Let maximum be 86400.
      maximum = 86400;
      break;
    // 11. Else if smallestUnit is "millisecond", then
    case Unit::kMillisecond:
      // a. Let maximum be 8.64 × 10^7.
      maximum = 8.64e7;
      break;
    // 12. Else if smallestUnit is "microsecond", then
    case Unit::kMicrosecond:
      // a. Let maximum be 8.64 × 10^10.
      maximum = 8.64e10;
      break;
    // 13. Else,
    case Unit::kNanosecond:
      // b. Let maximum be nsPerDay.
      maximum = kNsPerDay;
      break;
      // a. Assert: smallestUnit is "nanosecond".
    default:
      UNREACHABLE();
  }
  // 14. Let roundingIncrement be ? ToTemporalRoundingIncrement(roundTo,
  // maximum, true).
  double rounding_increment;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_increment,
      ToTemporalRoundingIncrement(isolate, round_to, maximum, true, true),
      Handle<JSTemporalInstant>());
  // 15. Let roundedNs be ! RoundTemporalInstant(instant.[[Nanoseconds]],
  // roundingIncrement, smallestUnit, roundingMode).
  DirectHandle<BigInt> rounded_ns = RoundTemporalInstant(
      isolate, Handle<BigInt>(handle->nanoseconds(), isolate),
      rounding_increment, smallest_unit, rounding_mode);
  // 16. Return ! CreateTemporalInstant(roundedNs).
  return temporal::CreateTemporalInstant(isolate, rounded_ns).ToHandleChecked();
}

// #sec-temporal.instant.from
MaybeHandle<JSTemporalInstant> JSTemporalInstant::From(Isolate* isolate,
                                                       Handle<Object> item) {
  TEMPORAL_ENTER_FUNC();
  //  1. If Type(item) is Object and item has an [[InitializedTemporalInstant]]
  //  internal slot, then
  if (IsJSTemporalInstant(*item)) {
    // a. Return ? CreateTemporalInstant(item.[[Nanoseconds]]).
    return temporal::CreateTemporalInstant(
        isolate,
        handle(Cast<JSTemporalInstant>(*item)->nanoseconds(), isolate));
  }
  // 2. Return ? ToTemporalInstant(item).
  return ToTemporalInstant(isolate, item, "Temporal.Instant.from");
}

// #sec-temporal.instant.prototype.tozoneddatetime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalInstant::ToZonedDateTime(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> item_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.Instant.prototype.toZonedDateTime";
  Factory* factory = isolate->factory();
  // 1. Let instant be the this value.
  // 2. Perform ? RequireInternalSlot(instant, [[InitializedTemporalInstant]]).
  // 3. If Type(item) is not Object, then
  if (!IsJSReceiver(*item_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
  // 4. Let calendarLike be ? Get(item, "calendar").
  Handle<Object> calendar_like;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar_like,
      JSReceiver::GetProperty(isolate, item, factory->calendar_string()));
  // 5. If calendarLike is undefined, then
  if (IsUndefined(*calendar_like)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  // 6. Let calendar be ? ToTemporalCalendar(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      temporal::ToTemporalCalendar(isolate, calendar_like, method_name));

  // 7. Let temporalTimeZoneLike be ? Get(item, "timeZone").
  Handle<Object> temporal_time_zone_like;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_time_zone_like,
      JSReceiver::GetProperty(isolate, item, factory->timeZone_string()));
  // 8. If temporalTimeZoneLike is undefined, then
  if (IsUndefined(*calendar_like)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  // 9. Let timeZone be ? ToTemporalTimeZone(temporalTimeZoneLike).
  Handle<JSReceiver> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      temporal::ToTemporalTimeZone(isolate, temporal_time_zone_like,
                                   method_name));
  // 10. Return ? CreateTemporalZonedDateTime(instant.[[Nanoseconds]], timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(
      isolate, Handle<BigInt>(handle->nanoseconds(), isolate), time_zone,
      calendar);
}

namespace {

// #sec-temporal-temporalinstanttostring
MaybeHandle<String> TemporalInstantToString(Isolate* isolate,
                                            Handle<JSTemporalInstant> instant,
                                            Handle<Object> time_zone_obj,
                                            Precision precision,
                                            const char* method_name) {
  IncrementalStringBuilder builder(isolate);
  // 1. Assert: Type(instant) is Object.
  // 2. Assert: instant has an [[InitializedTemporalInstant]] internal slot.
  // 3. Let outputTimeZone be timeZone.
  Handle<JSReceiver> output_time_zone;

  // 4. If outputTimeZone is undefined, then
  if (IsUndefined(*time_zone_obj)) {
    // a. Set outputTimeZone to ! CreateTemporalTimeZone("UTC").
    output_time_zone = CreateTemporalTimeZoneUTC(isolate);
  } else {
    DCHECK(IsJSReceiver(*time_zone_obj));
    output_time_zone = Cast<JSReceiver>(time_zone_obj);
  }

  // 5. Let isoCalendar be ! GetISO8601Calendar().
  Handle<JSTemporalCalendar> iso_calendar =
      temporal::GetISO8601Calendar(isolate);
  // 6. Let dateTime be ?
  // BuiltinTimeZoneGetPlainDateTimeFor(outputTimeZone, instant,
  // isoCalendar).
  Handle<JSTemporalPlainDateTime> date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(
          isolate, output_time_zone, instant, iso_calendar, method_name));
  // 7. Let dateTimeString be ? TemporalDateTimeToString(dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]], undefined, precision, "never").

  Handle<String> date_time_string;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time_string,
      TemporalDateTimeToString(
          isolate,
          {{date_time->iso_year(), date_time->iso_month(),
            date_time->iso_day()},
           {date_time->iso_hour(), date_time->iso_minute(),
            date_time->iso_second(), date_time->iso_millisecond(),
            date_time->iso_microsecond(), date_time->iso_nanosecond()}},
          iso_calendar,  // Unimportant due to ShowCalendar::kNever
          precision, ShowCalendar::kNever));
  builder.AppendString(date_time_string);

  // 8. If timeZone is undefined, then
  if (IsUndefined(*time_zone_obj)) {
    // a. Let timeZoneString be "Z".
    builder.AppendCharacter('Z');
  } else {
    // 9. Else,
    DCHECK(IsJSReceiver(*time_zone_obj));
    Handle<JSReceiver> time_zone = Cast<JSReceiver>(time_zone_obj);

    // a. Let offsetNs be ? GetOffsetNanosecondsFor(timeZone, instant).
    int64_t offset_ns;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, offset_ns,
        GetOffsetNanosecondsFor(isolate, time_zone, instant, method_name),
        Handle<String>());
    // b. Let timeZoneString be ! FormatISOTimeZoneOffsetString(offsetNs).
    DirectHandle<String> time_zone_string =
        FormatISOTimeZoneOffsetString(isolate, offset_ns);
    builder.AppendString(time_zone_string);
  }

  // 10. Return the string-concatenation of dateTimeString and timeZoneString.
  return indirect_handle(builder.Finish(), isolate);
}

}  // namespace

// #sec-temporal.instant.prototype.tojson
MaybeHandle<String> JSTemporalInstant::ToJSON(
    Isolate* isolate, Handle<JSTemporalInstant> instant) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let instant be the this value.
  // 2. Perform ? RequireInternalSlot(instant, [[InitializedTemporalInstant]]).
  // 3. Return ? TemporalInstantToString(instant, undefined, "auto").
  return TemporalInstantToString(
      isolate, instant, isolate->factory()->undefined_value(), Precision::kAuto,
      "Temporal.Instant.prototype.toJSON");
}

// #sec-temporal.instant.prototype.tolocalestring
MaybeHandle<String> JSTemporalInstant::ToLocaleString(
    Isolate* isolate, Handle<JSTemporalInstant> instant, Handle<Object> locales,
    Handle<Object> options) {
  const char* method_name = "Temporal.Instant.prototype.toLocaleString";
#ifdef V8_INTL_SUPPORT
  return JSDateTimeFormat::TemporalToLocaleString(isolate, instant, locales,
                                                  options, method_name);
#else   //  V8_INTL_SUPPORT
  return TemporalInstantToString(isolate, instant,
                                 isolate->factory()->undefined_value(),
                                 Precision::kAuto, method_name);
#endif  //  V8_INTL_SUPPORT
}

// #sec-temporal.instant.prototype.tostring
MaybeHandle<String> JSTemporalInstant::ToString(
    Isolate* isolate, DirectHandle<JSTemporalInstant> instant,
    Handle<Object> options_obj) {
  Factory* factory = isolate->factory();
  const char* method_name = "Temporal.Instant.prototype.toString";
  // 1. Let instant be the this value.
  // 2. Perform ? RequireInternalSlot(instant, [[InitializedTemporalInstant]]).
  // 3. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 4. Let timeZone be ? Get(options, "timeZone").
  Handle<Object> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      JSReceiver::GetProperty(isolate, options, factory->timeZone_string()));

  // 5. If timeZone is not undefined, then
  if (!IsUndefined(*time_zone)) {
    // a. Set timeZone to ? ToTemporalTimeZone(timeZone).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone,
        temporal::ToTemporalTimeZone(isolate, time_zone, method_name));
  }
  // 6. Let precision be ? ToSecondsStringPrecision(options).
  StringPrecision precision;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, precision,
      ToSecondsStringPrecision(isolate, options, method_name),
      Handle<String>());
  // 7. Let roundingMode be ? ToTemporalRoundingMode(options, "trunc").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, options, RoundingMode::kTrunc,
                             method_name),
      Handle<String>());
  // 8. Let roundedNs be ! RoundTemporalInstant(instant.[[Nanoseconds]],
  // precision.[[Increment]], precision.[[Unit]], roundingMode).
  DirectHandle<BigInt> rounded_ns =
      RoundTemporalInstant(isolate, handle(instant->nanoseconds(), isolate),
                           precision.increment, precision.unit, rounding_mode);

  // 9. Let roundedInstant be ! CreateTemporalInstant(roundedNs).
  Handle<JSTemporalInstant> rounded_instant =
      temporal::CreateTemporalInstant(isolate, rounded_ns).ToHandleChecked();

  // 10. Return ? TemporalInstantToString(roundedInstant, timeZone,
  // precision.[[Precision]]).
  return TemporalInstantToString(isolate, rounded_instant, time_zone,
                                 precision.precision,
                                 "Temporal.Instant.prototype.toString");
}

// #sec-temporal.instant.prototype.tozoneddatetimeiso
MaybeHandle<JSTemporalZonedDateTime> JSTemporalInstant::ToZonedDateTimeISO(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> item_obj) {
  TEMPORAL_ENTER_FUNC();
  Factory* factory = isolate->factory();
  // 1. Let instant be the this value.
  // 2. Perform ? RequireInternalSlot(instant, [[InitializedTemporalInstant]]).
  // 3. If Type(item) is Object, then
  if (IsJSReceiver(*item_obj)) {
    Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
    // a. Let timeZoneProperty be ? Get(item, "timeZone").
    Handle<Object> time_zone_property;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone_property,
        JSReceiver::GetProperty(isolate, item, factory->timeZone_string()));
    // b. If timeZoneProperty is not undefined, then
    if (!IsUndefined(*time_zone_property)) {
      // i. Set item to timeZoneProperty.
      item_obj = time_zone_property;
    }
  }
  // 4. Let timeZone be ? ToTemporalTimeZone(item).
  Handle<JSReceiver> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      temporal::ToTemporalTimeZone(
          isolate, item_obj, "Temporal.Instant.prototype.toZonedDateTimeISO"));
  // 5. Let calendar be ! GetISO8601Calendar().
  DirectHandle<JSTemporalCalendar> calendar =
      temporal::GetISO8601Calendar(isolate);
  // 6. Return ? CreateTemporalZonedDateTime(instant.[[Nanoseconds]], timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(
      isolate, Handle<BigInt>(handle->nanoseconds(), isolate), time_zone,
      calendar);
}

namespace {

// #sec-temporal-adddurationtoorsubtractdurationfrominstant
MaybeHandle<JSTemporalInstant> AddDurationToOrSubtractDurationFromInstant(
    Isolate* isolate, Arithmetic operation,
    DirectHandle<JSTemporalInstant> handle,
    Handle<Object> temporal_duration_like, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. If operation is subtract, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == Arithmetic::kSubtract ? -1.0 : 1.0;

  // See https://github.com/tc39/proposal-temporal/pull/2253
  // 2. Let duration be ? ToTemporalDurationRecord(temporalDurationLike).
  DurationRecord duration;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, duration,
      temporal::ToTemporalDurationRecord(isolate, temporal_duration_like,
                                         method_name),
      Handle<JSTemporalInstant>());

  TimeDurationRecord& time_duration = duration.time_duration;
  if (time_duration.days != 0 || duration.months != 0 || duration.weeks != 0 ||
      duration.years != 0) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Handle<JSTemporalInstant>());
  }

  // 3. Let ns be ? AddInstant(instant.[[EpochNanoseconds]], sign x
  // duration.[[Hours]], sign x duration.[[Minutes]], sign x
  // duration.[[Seconds]], sign x duration.[[Milliseconds]], sign x
  // duration.[[Microseconds]], sign x duration.[[Nanoseconds]]).
  Handle<BigInt> ns;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, ns,
      AddInstant(
          isolate, Handle<BigInt>(handle->nanoseconds(), isolate),
          {0, sign * time_duration.hours, sign * time_duration.minutes,
           sign * time_duration.seconds, sign * time_duration.milliseconds,
           sign * time_duration.microseconds,
           sign * time_duration.nanoseconds}));
  // 4. Return ! CreateTemporalInstant(ns).
  return temporal::CreateTemporalInstant(isolate, ns);
}

// #sec-temporal-negatetemporalroundingmode
RoundingMode NegateTemporalRoundingMode(RoundingMode rounding_mode) {
  switch (rounding_mode) {
    // 1. If roundingMode is "ceil", return "floor".
    case RoundingMode::kCeil:
      return RoundingMode::kFloor;
    // 2. If roundingMode is "floor", return "ceil".
    case RoundingMode::kFloor:
      return RoundingMode::kCeil;
    // 3. If roundingMode is "halfCeil", return "halfFloor".
    case RoundingMode::kHalfCeil:
      return RoundingMode::kHalfFloor;
    // 4. If roundingMode is "halfFloor", return "halfCeil".
    case RoundingMode::kHalfFloor:
      return RoundingMode::kHalfCeil;
    // 5. Return roundingMode.
    default:
      return rounding_mode;
  }
}

// #sec-temporal-getdifferencesettings
Maybe<DifferenceSettings> GetDifferenceSettings(
    Isolate* isolate, TimePreposition operation, Handle<Object> options,
    UnitGroup unit_group, DisallowedUnitsInDifferenceSettings disallowed_units,
    Unit fallback_smallest_unit, Unit smallest_largest_default_unit,
    const char* method_name) {
  DifferenceSettings record;
  // 1. Set options to ? GetOptionsObject(options).
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record.options, GetOptionsObject(isolate, options, method_name),
      Nothing<DifferenceSettings>());
  // 2. Let smallestUnit be ? GetTemporalUnit(options, "smallestUnit",
  // unitGroup, fallbackSmallestUnit).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record.smallest_unit,
      GetTemporalUnit(isolate, record.options, "smallestUnit", unit_group,
                      fallback_smallest_unit,
                      fallback_smallest_unit == Unit::kNotPresent, method_name),
      Nothing<DifferenceSettings>());
  // 3. If disallowedUnits contains smallestUnit, throw a RangeError exception.
  if (disallowed_units == DisallowedUnitsInDifferenceSettings::kWeekAndDay) {
    if (record.smallest_unit == Unit::kWeek) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kInvalidUnit,
                        isolate->factory()->smallestUnit_string(),
                        isolate->factory()->week_string()),
          Nothing<DifferenceSettings>());
    }
    if (record.smallest_unit == Unit::kDay) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kInvalidUnit,
                        isolate->factory()->smallestUnit_string(),
                        isolate->factory()->day_string()),
          Nothing<DifferenceSettings>());
    }
  }
  // 4. Let defaultLargestUnit be !
  // LargerOfTwoTemporalUnits(smallestLargestDefaultUnit, smallestUnit).
  Unit default_largest_unit = LargerOfTwoTemporalUnits(
      smallest_largest_default_unit, record.smallest_unit);
  // 5. Let largestUnit be ? GetTemporalUnit(options, "largestUnit", unitGroup,
  // "auto").
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record.largest_unit,
      GetTemporalUnit(isolate, record.options, "largestUnit", unit_group,
                      Unit::kAuto, false, method_name),
      Nothing<DifferenceSettings>());
  // 6. If disallowedUnits contains largestUnit, throw a RangeError exception.
  if (disallowed_units == DisallowedUnitsInDifferenceSettings::kWeekAndDay) {
    if (record.largest_unit == Unit::kWeek) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kInvalidUnit,
                        isolate->factory()->largestUnit_string(),
                        isolate->factory()->week_string()),
          Nothing<DifferenceSettings>());
    }
    if (record.largest_unit == Unit::kDay) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kInvalidUnit,
                        isolate->factory()->largestUnit_string(),
                        isolate->factory()->day_string()),
          Nothing<DifferenceSettings>());
    }
  }
  // 7. If largestUnit is "auto", set largestUnit to defaultLargestUnit.
  if (record.largest_unit == Unit::kAuto) {
    record.largest_unit = default_largest_unit;
  }
  // 8. If LargerOfTwoTemporalUnits(largestUnit, smallestUnit) is not
  // largestUnit, throw a RangeError exception.
  if (LargerOfTwoTemporalUnits(record.largest_unit, record.smallest_unit) !=
      record.largest_unit) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kInvalidArgumentForTemporal,
                      isolate->factory()->largestUnit_string()),
        Nothing<DifferenceSettings>());
  }
  // 9. Let roundingMode be ? ToTemporalRoundingMode(options, "trunc").
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record.rounding_mode,
      ToTemporalRoundingMode(isolate, record.options, RoundingMode::kTrunc,
                             method_name),
      Nothing<DifferenceSettings>());
  // 10. If operation is since, then
  if (operation == TimePreposition::kSince) {
    // a. Set roundingMode to ! NegateTemporalRoundingMode(roundingMode).
    record.rounding_mode = NegateTemporalRoundingMode(record.rounding_mode);
  }
  // 11. Let maximum be !
  // MaximumTemporalDurationRoundingIncrement(smallestUnit).
  Maximum maximum =
      MaximumTemporalDurationRoundingIncrement(record.smallest_unit);
  // 12. Let roundingIncrement be ? ToTemporalRoundingIncrement(options,
  // maximum, false).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record.rounding_increment,
      ToTemporalRoundingIncrement(isolate, record.options, maximum.value,
                                  maximum.defined, false),
      Nothing<DifferenceSettings>());
  // 13. Return the Record { [[SmallestUnit]]: smallestUnit, [[LargestUnit]]:
  // largestUnit, [[RoundingMode]]: roundingMode, [[RoundingIncrement]]:
  // roundingIncrement, [[Options]]: options }.
  return Just(record);
}

// #sec-temporal-differenceinstant
TimeDurationRecord DifferenceInstant(Isolate* isolate, Handle<BigInt> ns1,
                                     Handle<BigInt> ns2,
                                     double rounding_increment,
                                     Unit smallest_unit, Unit largest_unit,
                                     RoundingMode rounding_mode,
                                     const char* method_name) {
  // 1. Assert: Type(ns1) is BigInt.
  // 2. Assert: Type(ns2) is BigInt.
  // 3. Assert: The following step cannot fail due to overflow in the Number
  // domain because abs(ns2 - ns1) <= 2 x nsMaxInstant.

  // 4. Let roundResult be ! RoundDuration(0, 0, 0, 0, 0, 0, 0, 0, 0, ns2 - ns1,
  // roundingIncrement, smallestUnit, roundingMode).[[DurationRecord]].
  Handle<BigInt> diff = BigInt::Subtract(isolate, ns2, ns1).ToHandleChecked();
  // Note: Since diff could be very big and over the precision of double can
  // hold, break diff into diff_hours and diff_nanoseconds before pass into
  // RoundDuration.
  DirectHandle<BigInt> nanoseconds_in_a_hour =
      BigInt::FromUint64(isolate, 3600000000000);
  double diff_hours = Object::NumberValue(*BigInt::ToNumber(
      isolate,
      BigInt::Divide(isolate, diff, nanoseconds_in_a_hour).ToHandleChecked()));
  double diff_nanoseconds = Object::NumberValue(*BigInt::ToNumber(
      isolate, BigInt::Remainder(isolate, diff, nanoseconds_in_a_hour)
                   .ToHandleChecked()));
  DurationRecordWithRemainder round_record =
      RoundDuration(
          isolate, {0, 0, 0, {0, diff_hours, 0, 0, 0, 0, diff_nanoseconds}},
          rounding_increment, smallest_unit, rounding_mode, method_name)
          .ToChecked();
  // 5. Assert: roundResult.[[Days]] is 0.
  DCHECK_EQ(0, round_record.record.time_duration.days);
  // 6. Return ! BalanceDuration(0, roundResult.[[Hours]],
  // roundResult.[[Minutes]], roundResult.[[Seconds]],
  // roundResult.[[Milliseconds]], roundResult.[[Microseconds]],
  // roundResult.[[Nanoseconds]], largestUnit).
  return BalanceDuration(isolate, largest_unit,
                         isolate->factory()->undefined_value(),
                         round_record.record.time_duration, method_name)
      .ToChecked();
}

// #sec-temporal-differencetemporalinstant
MaybeHandle<JSTemporalDuration> DifferenceTemporalInstant(
    Isolate* isolate, TimePreposition operation,
    DirectHandle<JSTemporalInstant> instant, Handle<Object> other_obj,
    Handle<Object> options, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. If operation is since, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == TimePreposition::kSince ? -1 : 1;
  // 2. Set other to ? ToTemporalInstant(other).
  Handle<JSTemporalInstant> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other, ToTemporalInstant(isolate, other_obj, method_name));
  // 3. Let settings be ? GetDifferenceSettings(operation, options, time, « »,
  // "nanosecond", "second").
  DifferenceSettings settings;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, settings,
      GetDifferenceSettings(isolate, operation, options, UnitGroup::kTime,
                            DisallowedUnitsInDifferenceSettings::kNone,
                            Unit::kNanosecond, Unit::kSecond, method_name),
      Handle<JSTemporalDuration>());
  // 4. Let result be ! DifferenceInstant(instant.[[Nanoseconds]],
  // other.[[Nanoseconds]], settings.[[RoundingIncrement]],
  // settings.[[SmallestUnit]], settings.[[LargestUnit]],
  // settings.[[RoundingMode]]).
  TimeDurationRecord result = DifferenceInstant(
      isolate, handle(instant->nanoseconds(), isolate),
      handle(other->nanoseconds(), isolate), settings.rounding_increment,
      settings.smallest_unit, settings.largest_unit, settings.rounding_mode,
      method_name);
  // 5. Return ! CreateTemporalDuration(0, 0, 0, 0, sign × result.[[Hours]],
  // sign × result.[[Minutes]], sign × result.[[Seconds]], sign ×
  // result.[[Milliseconds]], sign × result.[[Microseconds]], sign ×
  // result.[[Nanoseconds]]).
  return CreateTemporalDuration(
             isolate, {0,
                       0,
                       0,
                       {0, sign * result.hours, sign * result.minutes,
                        sign * result.seconds, sign * result.milliseconds,
                        sign * result.microseconds, sign * result.nanoseconds}})
      .ToHandleChecked();
}
}  // namespace

// #sec-temporal.instant.prototype.add
MaybeHandle<JSTemporalInstant> JSTemporalInstant::Add(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> temporal_duration_like) {
  TEMPORAL_ENTER_FUNC();
  return AddDurationToOrSubtractDurationFromInstant(
      isolate, Arithmetic::kAdd, handle, temporal_duration_like,
      "Temporal.Instant.prototype.add");
}

// #sec-temporal.instant.prototype.subtract
MaybeHandle<JSTemporalInstant> JSTemporalInstant::Subtract(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> temporal_duration_like) {
  TEMPORAL_ENTER_FUNC();
  return AddDurationToOrSubtractDurationFromInstant(
      isolate, Arithmetic::kSubtract, handle, temporal_duration_like,
      "Temporal.Instant.prototype.subtract");
}

// #sec-temporal.instant.prototype.until
MaybeHandle<JSTemporalDuration> JSTemporalInstant::Until(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalInstant(isolate, TimePreposition::kUntil, handle,
                                   other, options,
                                   "Temporal.Instant.prototype.until");
}

// #sec-temporal.instant.prototype.since
MaybeHandle<JSTemporalDuration> JSTemporalInstant::Since(
    Isolate* isolate, DirectHandle<JSTemporalInstant> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalInstant(isolate, TimePreposition::kSince, handle,
                                   other, options,
                                   "Temporal.Instant.prototype.since");
}
namespace temporal {

// Step iii and iv of #sec-temporal.calendar.prototype.fields
MaybeHandle<Oddball> IsInvalidTemporalCalendarField(
    Isolate* isolate, Handle<String> next_value,
    DirectHandle<FixedArray> fields_name) {
  Factory* factory = isolate->factory();
  // iii. iii. If fieldNames contains nextValue, then
  for (int i = 0; i < fields_name->length(); i++) {
    Tagged<Object> item = fields_name->get(i);
    DCHECK(IsString(item));
    if (String::Equals(isolate, next_value,
                       handle(Cast<String>(item), isolate))) {
      return isolate->factory()->true_value();
    }
  }
  // iv. If nextValue is not one of "year", "month", "monthCode", "day", "hour",
  // "minute", "second", "millisecond", "microsecond", "nanosecond", then
  if (!(String::Equals(isolate, next_value, factory->year_string()) ||
        String::Equals(isolate, next_value, factory->month_string()) ||
        String::Equals(isolate, next_value, factory->monthCode_string()) ||
        String::Equals(isolate, next_value, factory->day_string()) ||
        String::Equals(isolate, next_value, factory->hour_string()) ||
        String::Equals(isolate, next_value, factory->minute_string()) ||
        String::Equals(isolate, next_value, factory->second_string()) ||
        String::Equals(isolate, next_value, factory->millisecond_string()) ||
        String::Equals(isolate, next_value, factory->microsecond_string()) ||
        String::Equals(isolate, next_value, factory->nanosecond_string()))) {
    return isolate->factory()->true_value();
  }
  return isolate->factory()->false_value();
}

// #sec-temporal-getbuiltincalendar
MaybeHandle<JSTemporalCalendar> GetBuiltinCalendar(Isolate* isolate,
                                                   Handle<String> id) {
  return JSTemporalCalendar::Constructor(isolate, CONSTRUCTOR(calendar),
                                         CONSTRUCTOR(calendar), id);
}

// A simple conviention function to avoid the need to unnecessarily exposing
// the definiation of enum Disambiguation.
MaybeHandle<JSTemporalInstant> BuiltinTimeZoneGetInstantForCompatible(
    Isolate* isolate, Handle<JSReceiver> time_zone,
    Handle<JSTemporalPlainDateTime> date_time, const char* method_name) {
  return BuiltinTimeZoneGetInstantFor(isolate, time_zone, date_time,
                                      Disambiguation::kCompatible, method_name);
}

}  // namespace temporal
}  // namespace v8::internal
```