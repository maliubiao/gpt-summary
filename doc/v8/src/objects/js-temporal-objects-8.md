Response: The user wants a summary of the C++ source code file `v8/src/objects/js-temporal-objects.cc`. This is part 9 of 13, suggesting this file likely deals with a specific aspect of the Temporal API implementation in V8.

Based on the code snippets provided, I can identify the following key functionalities:

1. **`JSTemporalPlainDate` implementation:**
    - Handles creation of `Temporal.PlainDate` objects.
    - Implements methods like `from`, `GetISOFields`, `ToJSON`, `toString`, `toLocaleString`.
    - Includes logic for converting other types to `Temporal.PlainDate`.

2. **`JSTemporalPlainDateTime` implementation:**
    - Handles creation of `Temporal.PlainDateTime` objects.
    - Implements methods like `from`, `compare`, `equals`, `with`, `withPlainTime`, `withCalendar`, `toPlainYearMonth`, `toPlainMonthDay`, `toZonedDateTime`, `withPlainDate`, `toJSON`, `toLocaleString`, `round`, `add`, `subtract`, `until`, `since`, `GetISOFields`, `toPlainDate`, `toPlainTime`, `Now`, `NowISO`.
    - Includes logic for parsing and interpreting date-time strings.
    - Contains functions for rounding and arithmetic operations on `Temporal.PlainDateTime` objects.

3. **Helper functions and namespaces:**
    - `ToShowCalendarOption`:  Handles parsing the `calendarName` option.
    - `TemporalToString`:  Generic function for `toString` implementations.
    - `InterpretTemporalDateTimeFields`:  Handles interpreting fields to create a date-time record.
    - `ParseTemporalDateTimeString`: Parses ISO date-time strings.
    - `ConsolidateCalendars`:  Handles comparing and consolidating calendar objects.
    - `TemporalDateTimeToString`:  Formats a `Temporal.PlainDateTime` to a string.
    - `RoundISODateTime`:  Rounds an ISO date-time based on specified units.
    - `AddDurationToOrSubtractDurationFromPlainDateTime`: Handles adding or subtracting durations from a `Temporal.PlainDateTime`.
    - `DifferenceTemporalPlainDateTime`: Calculates the difference between two `Temporal.PlainDateTime` objects.
    - `ParseTemporalMonthDayString`: Parses ISO month-day strings.

4. **Relationship to JavaScript:**
    - The C++ code directly implements the functionality of the `Temporal.PlainDate` and `Temporal.PlainDateTime` JavaScript objects.
    - Methods defined in C++ correspond to methods available on these objects in JavaScript.
    - The code handles parsing and validation of input from JavaScript.

Considering this is part 9 of 13, it's likely this file focuses on the core implementations of `Temporal.PlainDate` and `Temporal.PlainDateTime`, along with essential related functionalities like parsing and formatting.

Now, let's construct the summary and JavaScript examples.
This C++ source code file (`v8/src/objects/js-temporal-objects.cc`) is part of the implementation of the **Temporal API** in V8, specifically focusing on the `Temporal.PlainDate` and `Temporal.PlainDateTime` objects.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Implementation of `Temporal.PlainDate`:** This section of the code provides the underlying C++ implementation for the JavaScript `Temporal.PlainDate` object. It includes:
    * **Constructor logic:** How `Temporal.PlainDate` instances are created.
    * **`from()` method:**  Creating a `Temporal.PlainDate` from various input types (including other `Temporal.PlainDate` objects).
    * **`getISOFields()` method:**  Retrieving the ISO year, month, and day components.
    * **`toJSON()` method:**  Converting the `Temporal.PlainDate` to a JSON string.
    * **`toString()` method:**  Formatting the `Temporal.PlainDate` into a human-readable string, with options for calendar display.
    * **`toLocaleString()` method:** Formatting the `Temporal.PlainDate` according to locale-specific conventions.

* **Implementation of `Temporal.PlainDateTime`:** This is a significant portion of the file, providing the C++ implementation for the JavaScript `Temporal.PlainDateTime` object. It includes:
    * **Constructor logic:** How `Temporal.PlainDateTime` instances are created.
    * **`from()` method:** Creating a `Temporal.PlainDateTime` from various input types (including other Temporal objects).
    * **`compare()` method:**  Comparing two `Temporal.PlainDateTime` instances.
    * **`equals()` method:** Checking if two `Temporal.PlainDateTime` instances are equal.
    * **`with()` method:** Creating a new `Temporal.PlainDateTime` by replacing some of its components.
    * **`withPlainTime()` method:** Creating a new `Temporal.PlainDateTime` with a different time component.
    * **`withCalendar()` method:** Creating a new `Temporal.PlainDateTime` with a different calendar.
    * **`toPlainYearMonth()` and `toPlainMonthDay()` methods:** Converting to `Temporal.PlainYearMonth` and `Temporal.PlainMonthDay` respectively.
    * **`toZonedDateTime()` method:** Converting to a `Temporal.ZonedDateTime`.
    * **`withPlainDate()` method:** Creating a new `Temporal.PlainDateTime` with a different date component.
    * **`toJSON()` method:** Converting the `Temporal.PlainDateTime` to a JSON string.
    * **`toLocaleString()` method:** Formatting the `Temporal.PlainDateTime` according to locale-specific conventions.
    * **`round()` method:** Rounding the `Temporal.PlainDateTime` to a specific granularity.
    * **`add()` and `subtract()` methods:** Adding or subtracting a `Temporal.Duration`.
    * **`until()` and `since()` methods:** Calculating the duration between two `Temporal.PlainDateTime` instances.
    * **`getISOFields()` method:** Retrieving the ISO date and time components.
    * **`toPlainDate()` and `toPlainTime()` methods:** Extracting the date and time components as `Temporal.PlainDate` and `Temporal.PlainTime` objects.
    * **`Now()` and `NowISO()` methods:**  Retrieving the current date and time in the specified time zone and calendar (or ISO 8601).

* **Helper Functions and Namespaces:** The file also contains various internal helper functions and namespaces to support the core implementations, such as:
    * Functions for parsing Temporal strings.
    * Functions for validating and regulating date and time components.
    * Functions for handling options and settings.
    * Functions for converting between different Temporal types.
    * Functions for performing arithmetic operations on Temporal objects.

**Relationship to JavaScript (with examples):**

This C++ code is the engine behind the `Temporal.PlainDate` and `Temporal.PlainDateTime` objects that JavaScript developers interact with. Every time you use these objects in JavaScript, the underlying C++ code in this file (and related files) is being executed.

**`Temporal.PlainDate` Examples:**

```javascript
// Creating a Temporal.PlainDate
const plainDate = new Temporal.PlainDate(2023, 10, 26);
console.log(plainDate.toString()); // Output: 2023-10-26

// Using the from() method
const anotherDate = Temporal.PlainDate.from('2023-10-27');
console.log(anotherDate.toString()); // Output: 2023-10-27

// Getting ISO fields
const isoFields = plainDate.getISOFields();
console.log(isoFields); // Output: { calendar: [Temporal.Calendar], isoDay: 26, isoMonth: 10, isoYear: 2023 }
```

**`Temporal.PlainDateTime` Examples:**

```javascript
// Creating a Temporal.PlainDateTime
const plainDateTime = new Temporal.PlainDateTime(2023, 10, 26, 10, 30, 0);
console.log(plainDateTime.toString()); // Output: 2023-10-26T10:30:00

// Using the from() method
const anotherDateTime = Temporal.PlainDateTime.from('2023-10-27T11:45:00');
console.log(anotherDateTime.toString()); // Output: 2023-10-27T11:45:00

// Comparing two PlainDateTime objects
const laterDateTime = new Temporal.PlainDateTime(2023, 10, 26, 12, 0, 0);
console.log(Temporal.PlainDateTime.compare(plainDateTime, laterDateTime)); // Output: -1 (plainDateTime is earlier)

// Adding a duration
const duration = new Temporal.Duration(0, 0, 0, 1); // 1 day
const futureDateTime = plainDateTime.add(duration);
console.log(futureDateTime.toString()); // Output: 2023-10-27T10:30:00

// Getting ISO fields
const dateTimeIsoFields = plainDateTime.getISOFields();
console.log(dateTimeIsoFields);
// Output: {
//   calendar: [Temporal.Calendar],
//   isoDay: 26,
//   isoHour: 10,
//   isoMicrosecond: 0,
//   isoMillisecond: 0,
//   isoMinute: 30,
//   isoMonth: 10,
//   isoNanosecond: 0,
//   isoSecond: 0,
//   isoYear: 2023
// }
```

**In summary, this specific part of the V8 source code is responsible for the core logic and functionality of the `Temporal.PlainDate` and `Temporal.PlainDateTime` JavaScript objects, enabling developers to work with dates and times without time zone information in a standardized and robust way.** The fact that it's part 9 of 13 suggests that the Temporal API implementation is divided into logical components across multiple files.

Prompt: 
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第9部分，共13部分，请归纳一下它的功能

"""
bject(isolate, options_obj, method_name));
  // 2. If Type(item) is Object and item has an [[InitializedTemporalDate]]
  // internal slot, then
  if (IsJSTemporalPlainDate(*item)) {
    // a. Perform ? ToTemporalOverflow(options).
    MAYBE_RETURN_ON_EXCEPTION_VALUE(
        isolate, ToTemporalOverflow(isolate, options, method_name),
        Handle<JSTemporalPlainDate>());
    // b. Return ? CreateTemporalDate(item.[[ISOYear]], item.[[ISOMonth]],
    // item.[[ISODay]], item.[[Calendar]]).
    auto date = Cast<JSTemporalPlainDate>(item);
    return CreateTemporalDate(
        isolate, {date->iso_year(), date->iso_month(), date->iso_day()},
        Handle<JSReceiver>(date->calendar(), isolate));
  }
  // 3. Return ? ToTemporalDate(item, options).
  return ToTemporalDate(isolate, item, options, method_name);
}

#define DEFINE_INT_FIELD(obj, str, field, item)                \
  CHECK(JSReceiver::CreateDataProperty(                        \
            isolate, obj, factory->str##_string(),             \
            Handle<Smi>(Smi::FromInt(item->field()), isolate), \
            Just(kThrowOnError))                               \
            .FromJust());

// #sec-temporal.plaindate.prototype.getisofields
MaybeHandle<JSReceiver> JSTemporalPlainDate::GetISOFields(
    Isolate* isolate, DirectHandle<JSTemporalPlainDate> temporal_date) {
  Factory* factory = isolate->factory();
  // 1. Let temporalDate be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDate,
  // [[InitializedTemporalDate]]).
  // 3. Let fields be ! OrdinaryObjectCreate(%Object.prototype%).
  Handle<JSObject> fields =
      isolate->factory()->NewJSObject(isolate->object_function());
  // 4. Perform ! CreateDataPropertyOrThrow(fields, "calendar",
  // temporalDate.[[Calendar]]).
  CHECK(JSReceiver::CreateDataProperty(
            isolate, fields, factory->calendar_string(),
            Handle<JSReceiver>(temporal_date->calendar(), isolate),
            Just(kThrowOnError))
            .FromJust());
  // 5. Perform ! CreateDataPropertyOrThrow(fields, "isoDay",
  // 𝔽(temporalDate.[[ISODay]])).
  // 6. Perform ! CreateDataPropertyOrThrow(fields, "isoMonth",
  // 𝔽(temporalDate.[[ISOMonth]])).
  // 7. Perform ! CreateDataPropertyOrThrow(fields, "isoYear",
  // 𝔽(temporalDate.[[ISOYear]])).
  DEFINE_INT_FIELD(fields, isoDay, iso_day, temporal_date)
  DEFINE_INT_FIELD(fields, isoMonth, iso_month, temporal_date)
  DEFINE_INT_FIELD(fields, isoYear, iso_year, temporal_date)
  // 8. Return fields.
  return fields;
}

// #sec-temporal.plaindate.prototype.tojson
MaybeHandle<String> JSTemporalPlainDate::ToJSON(
    Isolate* isolate, DirectHandle<JSTemporalPlainDate> temporal_date) {
  // 1. Let temporalDate be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDate,
  // [[InitializedTemporalDate]]).
  // 3. Return ? TemporalDateToString(temporalDate, "auto").
  return TemporalDateToString(isolate, temporal_date, ShowCalendar::kAuto);
}

namespace {

// #sec-temporal-toshowcalendaroption
Maybe<ShowCalendar> ToShowCalendarOption(Isolate* isolate,
                                         Handle<JSReceiver> options,
                                         const char* method_name) {
  // 1. Return ? GetOption(normalizedOptions, "calendarName", « String », «
  // "auto", "always", "never" », "auto").
  return GetStringOption<ShowCalendar>(
      isolate, options, "calendarName", method_name,
      {"auto", "always", "never"},
      {ShowCalendar::kAuto, ShowCalendar::kAlways, ShowCalendar::kNever},
      ShowCalendar::kAuto);
}

template <typename T,
          MaybeHandle<String> (*F)(Isolate*, DirectHandle<T>, ShowCalendar)>
MaybeHandle<String> TemporalToString(Isolate* isolate, DirectHandle<T> temporal,
                                     Handle<Object> options_obj,
                                     const char* method_name) {
  // 1. Let temporalDate be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDate,
  // [[InitializedTemporalDate]]).
  // 3. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 4. Let showCalendar be ? ToShowCalendarOption(options).
  ShowCalendar show_calendar;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, show_calendar,
      ToShowCalendarOption(isolate, options, method_name), Handle<String>());
  // 5. Return ? TemporalDateToString(temporalDate, showCalendar).
  return F(isolate, temporal, show_calendar);
}
}  // namespace

// #sec-temporal.plaindate.prototype.tostring
MaybeHandle<String> JSTemporalPlainDate::ToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainDate> temporal_date,
    Handle<Object> options) {
  return TemporalToString<JSTemporalPlainDate, TemporalDateToString>(
      isolate, temporal_date, options, "Temporal.PlainDate.prototype.toString");
}

// #sup-temporal.plaindate.prototype.tolocalestring
MaybeHandle<String> JSTemporalPlainDate::ToLocaleString(
    Isolate* isolate, Handle<JSTemporalPlainDate> temporal_date,
    Handle<Object> locales, Handle<Object> options) {
#ifdef V8_INTL_SUPPORT
  return JSDateTimeFormat::TemporalToLocaleString(
      isolate, temporal_date, locales, options,
      "Temporal.PlainDate.prototype.toLocaleString");
#else   //  V8_INTL_SUPPORT
  return TemporalDateToString(isolate, temporal_date, ShowCalendar::kAuto);
#endif  // V8_INTL_SUPPORT
}

// #sec-temporal-createtemporaldatetime
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> iso_year_obj, Handle<Object> iso_month_obj,
    Handle<Object> iso_day_obj, Handle<Object> hour_obj,
    Handle<Object> minute_obj, Handle<Object> second_obj,
    Handle<Object> millisecond_obj, Handle<Object> microsecond_obj,
    Handle<Object> nanosecond_obj, Handle<Object> calendar_like) {
  const char* method_name = "Temporal.PlainDateTime";
  // 1. If NewTarget is undefined, throw a TypeError exception.
  if (IsUndefined(*new_target)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }

  TO_INT_THROW_ON_INFTY(iso_year, JSTemporalPlainDateTime);
  TO_INT_THROW_ON_INFTY(iso_month, JSTemporalPlainDateTime);
  TO_INT_THROW_ON_INFTY(iso_day, JSTemporalPlainDateTime);
  TO_INT_THROW_ON_INFTY(hour, JSTemporalPlainDateTime);
  TO_INT_THROW_ON_INFTY(minute, JSTemporalPlainDateTime);
  TO_INT_THROW_ON_INFTY(second, JSTemporalPlainDateTime);
  TO_INT_THROW_ON_INFTY(millisecond, JSTemporalPlainDateTime);
  TO_INT_THROW_ON_INFTY(microsecond, JSTemporalPlainDateTime);
  TO_INT_THROW_ON_INFTY(nanosecond, JSTemporalPlainDateTime);

  // 20. Let calendar be ? ToTemporalCalendarWithISODefault(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ToTemporalCalendarWithISODefault(isolate, calendar_like, method_name));

  // 21. Return ? CreateTemporalDateTime(isoYear, isoMonth, isoDay, hour,
  // minute, second, millisecond, microsecond, nanosecond, calendar, NewTarget).
  return CreateTemporalDateTime(
      isolate, target, new_target,
      {{iso_year, iso_month, iso_day},
       {hour, minute, second, millisecond, microsecond, nanosecond}},
      calendar);
}

namespace {

// #sec-temporal-interprettemporaldatetimefields
Maybe<temporal::DateTimeRecord> InterpretTemporalDateTimeFields(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<JSReceiver> fields,
    Handle<Object> options, const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 1. Let timeResult be ? ToTemporalTimeRecord(fields).
  TimeRecord time_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, time_result, ToTemporalTimeRecord(isolate, fields, method_name),
      Nothing<temporal::DateTimeRecord>());

  // 2. Let temporalDate be ? DateFromFields(calendar, fields, options).
  Handle<JSTemporalPlainDate> temporal_date;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, temporal_date,
      DateFromFields(isolate, calendar, fields, options),
      Nothing<temporal::DateTimeRecord>());

  // 3. Let overflow be ? ToTemporalOverflow(options).
  ShowOverflow overflow;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, overflow, ToTemporalOverflow(isolate, options, method_name),
      Nothing<temporal::DateTimeRecord>());

  // 4. Let timeResult be ? RegulateTime(timeResult.[[Hour]],
  // timeResult.[[Minute]], timeResult.[[Second]], timeResult.[[Millisecond]],
  // timeResult.[[Microsecond]], timeResult.[[Nanosecond]], overflow).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, time_result,
      temporal::RegulateTime(isolate, time_result, overflow),
      Nothing<temporal::DateTimeRecord>());
  // 5. Return the new Record { [[Year]]: temporalDate.[[ISOYear]], [[Month]]:
  // temporalDate.[[ISOMonth]], [[Day]]: temporalDate.[[ISODay]], [[Hour]]:
  // timeResult.[[Hour]], [[Minute]]: timeResult.[[Minute]], [[Second]]:
  // timeResult.[[Second]], [[Millisecond]]: timeResult.[[Millisecond]],
  // [[Microsecond]]: timeResult.[[Microsecond]], [[Nanosecond]]:
  // timeResult.[[Nanosecond]] }.

  temporal::DateTimeRecord result = {
      {temporal_date->iso_year(), temporal_date->iso_month(),
       temporal_date->iso_day()},
      time_result};
  return Just(result);
}

// #sec-temporal-parsetemporaldatetimestring
Maybe<DateTimeRecordWithCalendar> ParseTemporalDateTimeString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: Type(isoString) is String.
  // 2. If isoString does not satisfy the syntax of a TemporalDateTimeString
  // (see 13.33), then
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalDateTimeString(isolate, iso_string);
  if (!parsed.has_value()) {
    // a. Throw a *RangeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateTimeRecordWithCalendar>());
  }

  // 3. If _isoString_ contains a |UTCDesignator|, then
  if (parsed->utc_designator) {
    // a. Throw a *RangeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateTimeRecordWithCalendar>());
  }

  // 3. Let result be ? ParseISODateTime(isoString).
  // 4. Return result.
  return ParseISODateTime(isolate, iso_string, *parsed);
}

// #sec-temporal-totemporaldatetime
MaybeHandle<JSTemporalPlainDateTime> ToTemporalDateTime(
    Isolate* isolate, Handle<Object> item_obj, Handle<Object> options,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 2. Assert: Type(options) is Object or Undefined.
  DCHECK(IsJSReceiver(*options) || IsUndefined(*options));

  Handle<JSReceiver> calendar;
  temporal::DateTimeRecord result;
  // 2. If Type(item) is Object, then
  if (IsJSReceiver(*item_obj)) {
    Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
    // a. If item has an [[InitializedTemporalDateTime]] internal slot, then
    // i. Return item.
    if (IsJSTemporalPlainDateTime(*item)) {
      return Cast<JSTemporalPlainDateTime>(item);
    }
    // b. If item has an [[InitializedTemporalZonedDateTime]] internal slot,
    // then
    if (IsJSTemporalZonedDateTime(*item)) {
      // i. Perform ? ToTemporalOverflow(options).
      MAYBE_RETURN_ON_EXCEPTION_VALUE(
          isolate, ToTemporalOverflow(isolate, options, method_name),
          Handle<JSTemporalPlainDateTime>());
      // ii. Let instant be ! CreateTemporalInstant(item.[[Nanoseconds]]).
      auto zoned_date_time = Cast<JSTemporalZonedDateTime>(item);
      Handle<JSTemporalInstant> instant =
          temporal::CreateTemporalInstant(
              isolate, handle(zoned_date_time->nanoseconds(), isolate))
              .ToHandleChecked();
      // iii. Return ?
      // temporal::BuiltinTimeZoneGetPlainDateTimeFor(item.[[TimeZone]],
      // instant, item.[[Calendar]]).
      return temporal::BuiltinTimeZoneGetPlainDateTimeFor(
          isolate, handle(zoned_date_time->time_zone(), isolate), instant,
          handle(zoned_date_time->calendar(), isolate), method_name);
    }
    // c. If item has an [[InitializedTemporalDate]] internal slot, then
    if (IsJSTemporalPlainDate(*item)) {
      // i. Perform ? ToTemporalOverflow(options).
      MAYBE_RETURN_ON_EXCEPTION_VALUE(
          isolate, ToTemporalOverflow(isolate, options, method_name),
          Handle<JSTemporalPlainDateTime>());
      // ii. Return ? CreateTemporalDateTime(item.[[ISOYear]],
      // item.[[ISOMonth]], item.[[ISODay]], 0, 0, 0, 0, 0, 0,
      // item.[[Calendar]]).
      auto date = Cast<JSTemporalPlainDate>(item);
      return temporal::CreateTemporalDateTime(
          isolate,
          {{date->iso_year(), date->iso_month(), date->iso_day()},
           {0, 0, 0, 0, 0, 0}},
          handle(date->calendar(), isolate));
    }
    // d. Let calendar be ? GetTemporalCalendarWithISODefault(item).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        GetTemporalCalendarWithISODefault(isolate, item, method_name));
    // e. Let fieldNames be ? CalendarFields(calendar, « "day", "hour",
    // "microsecond", "millisecond", "minute", "month", "monthCode",
    // "nanosecond", "second", "year" »).
    Handle<FixedArray> field_names = All10UnitsInFixedArray(isolate);
    ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                               CalendarFields(isolate, calendar, field_names));
    // f. Let fields be ? PrepareTemporalFields(item,
    // PrepareTemporalFields(item, fieldNames, «»).
    Handle<JSReceiver> fields;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, fields,
                               PrepareTemporalFields(isolate, item, field_names,
                                                     RequiredFields::kNone));
    // g. Let result be ?
    // InterpretTemporalDateTimeFields(calendar, fields, options).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        InterpretTemporalDateTimeFields(isolate, calendar, fields, options,
                                        method_name),
        Handle<JSTemporalPlainDateTime>());
  } else {
    // 3. Else,
    // a. Perform ? ToTemporalOverflow(options).
    MAYBE_RETURN_ON_EXCEPTION_VALUE(
        isolate, ToTemporalOverflow(isolate, options, method_name),
        Handle<JSTemporalPlainDateTime>());

    // b. Let string be ? ToString(item).
    Handle<String> string;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, string,
                               Object::ToString(isolate, item_obj));
    // c. Let result be ? ParseTemporalDateTimeString(string).
    DateTimeRecordWithCalendar parsed_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, parsed_result, ParseTemporalDateTimeString(isolate, string),
        Handle<JSTemporalPlainDateTime>());
    result = {parsed_result.date, parsed_result.time};
    // d. Assert: ! IsValidISODate(result.[[Year]], result.[[Month]],
    // result.[[Day]]) is true.
    DCHECK(IsValidISODate(isolate, result.date));
    // e. Assert: ! IsValidTime(result.[[Hour]],
    // result.[[Minute]], result.[[Second]], result.[[Millisecond]],
    // result.[[Microsecond]], result.[[Nanosecond]]) is true.
    DCHECK(IsValidTime(isolate, result.time));
    // f. Let calendar
    // be ? ToTemporalCalendarWithISODefault(result.[[Calendar]]).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        ToTemporalCalendarWithISODefault(isolate, parsed_result.calendar,
                                         method_name));
  }
  // 4. Return ? CreateTemporalDateTime(result.[[Year]], result.[[Month]],
  // result.[[Day]], result.[[Hour]], result.[[Minute]], result.[[Second]],
  // result.[[Millisecond]], result.[[Microsecond]], result.[[Nanosecond]],
  // calendar).
  return temporal::CreateTemporalDateTime(isolate, {result.date, result.time},
                                          calendar);
}

}  // namespace

// #sec-temporal.plaindatetime.from
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::From(
    Isolate* isolate, Handle<Object> item, Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainDateTime.from";
  // 1. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 2. If Type(item) is Object and item has an [[InitializedTemporalDateTime]]
  // internal slot, then
  if (IsJSTemporalPlainDateTime(*item)) {
    // a. Perform ? ToTemporalOverflow(options).
    MAYBE_RETURN_ON_EXCEPTION_VALUE(
        isolate, ToTemporalOverflow(isolate, options, method_name),
        Handle<JSTemporalPlainDateTime>());
    // b. Return ? CreateTemporalDateTime(item.[[ISYear]], item.[[ISOMonth]],
    // item.[[ISODay]], item.[[ISOHour]], item.[[ISOMinute]],
    // item.[[ISOSecond]], item.[[ISOMillisecond]], item.[[ISOMicrosecond]],
    // item.[[ISONanosecond]], item.[[Calendar]]).
    auto date_time = Cast<JSTemporalPlainDateTime>(item);
    return temporal::CreateTemporalDateTime(
        isolate,
        {{date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
         {date_time->iso_hour(), date_time->iso_minute(),
          date_time->iso_second(), date_time->iso_millisecond(),
          date_time->iso_microsecond(), date_time->iso_nanosecond()}},
        handle(date_time->calendar(), isolate));
  }
  // 3. Return ? ToTemporalDateTime(item, options).
  return ToTemporalDateTime(isolate, item, options, method_name);
}

// #sec-temporal.plaindatetime.compare
MaybeHandle<Smi> JSTemporalPlainDateTime::Compare(Isolate* isolate,
                                                  Handle<Object> one_obj,
                                                  Handle<Object> two_obj) {
  const char* method_name = "Temporal.PlainDateTime.compare";
  // 1. Set one to ? ToTemporalDateTime(one).
  Handle<JSTemporalPlainDateTime> one;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, one,
                             ToTemporalDateTime(isolate, one_obj, method_name));
  // 2. Set two to ? ToTemporalDateTime(two).
  Handle<JSTemporalPlainDateTime> two;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, two,
                             ToTemporalDateTime(isolate, two_obj, method_name));
  // 3. Return 𝔽(! CompareISODateTime(one.[[ISOYear]], one.[[ISOMonth]],
  // one.[[ISODay]], one.[[ISOHour]], one.[[ISOMinute]], one.[[ISOSecond]],
  // one.[[ISOMillisecond]], one.[[ISOMicrosecond]], one.[[ISONanosecond]],
  // two.[[ISOYear]], two.[[ISOMonth]], two.[[ISODay]], two.[[ISOHour]],
  // two.[[ISOMinute]], two.[[ISOSecond]], two.[[ISOMillisecond]],
  // two.[[ISOMicrosecond]], two.[[ISONanosecond]])).
  return Handle<Smi>(
      Smi::FromInt(CompareISODateTime(
          {
              {one->iso_year(), one->iso_month(), one->iso_day()},
              {one->iso_hour(), one->iso_minute(), one->iso_second(),
               one->iso_millisecond(), one->iso_microsecond(),
               one->iso_nanosecond()},
          },
          {
              {two->iso_year(), two->iso_month(), two->iso_day()},
              {two->iso_hour(), two->iso_minute(), two->iso_second(),
               two->iso_millisecond(), two->iso_microsecond(),
               two->iso_nanosecond()},
          })),
      isolate);
}

// #sec-temporal.plaindatetime.prototype.equals
MaybeHandle<Oddball> JSTemporalPlainDateTime::Equals(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> other_obj) {
  // 1. Let dateTime be the this value.
  // 2. Perform ? RequireInternalSlot(dateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. Set other to ? ToTemporalDateTime(other).
  Handle<JSTemporalPlainDateTime> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other,
      ToTemporalDateTime(isolate, other_obj,
                         "Temporal.PlainDateTime.prototype.equals"));
  // 4. Let result be ! CompareISODateTime(dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]], other.[[ISOYear]], other.[[ISOMonth]],
  // other.[[ISODay]], other.[[ISOHour]], other.[[ISOMinute]],
  // other.[[ISOSecond]], other.[[ISOMillisecond]], other.[[ISOMicrosecond]],
  // other.[[ISONanosecond]]).
  int32_t result = CompareISODateTime(
      {
          {date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
          {date_time->iso_hour(), date_time->iso_minute(),
           date_time->iso_second(), date_time->iso_millisecond(),
           date_time->iso_microsecond(), date_time->iso_nanosecond()},
      },
      {
          {other->iso_year(), other->iso_month(), other->iso_day()},
          {other->iso_hour(), other->iso_minute(), other->iso_second(),
           other->iso_millisecond(), other->iso_microsecond(),
           other->iso_nanosecond()},
      });
  // 5. If result is not 0, return false.
  if (result != 0) return isolate->factory()->false_value();
  // 6. Return ? CalendarEquals(dateTime.[[Calendar]], other.[[Calendar]]).
  return CalendarEquals(isolate, handle(date_time->calendar(), isolate),
                        handle(other->calendar(), isolate));
}

// #sec-temporal.plaindatetime.prototype.with
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::With(
    Isolate* isolate, Handle<JSTemporalPlainDateTime> date_time,
    Handle<Object> temporal_date_time_like_obj, Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainDateTime.prototype.with";
  // 1. Let dateTime be the this value.
  // 2. Perform ? RequireInternalSlot(dateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. If Type(temporalDateTimeLike) is not Object, then
  if (!IsJSReceiver(*temporal_date_time_like_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  Handle<JSReceiver> temporal_date_time_like =
      Cast<JSReceiver>(temporal_date_time_like_obj);
  // 4. Perform ? RejectObjectWithCalendarOrTimeZone(temporalTimeLike).
  MAYBE_RETURN(
      RejectObjectWithCalendarOrTimeZone(isolate, temporal_date_time_like),
      Handle<JSTemporalPlainDateTime>());
  // 5. Let calendar be dateTime.[[Calendar]].
  Handle<JSReceiver> calendar =
      Handle<JSReceiver>(date_time->calendar(), isolate);
  // 6. Let fieldNames be ? CalendarFields(calendar, « "day", "hour",
  // "microsecond", "millisecond", "minute", "month", "monthCode", "nanosecond",
  // "second", "year" »).
  Handle<FixedArray> field_names = All10UnitsInFixedArray(isolate);
  ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                             CalendarFields(isolate, calendar, field_names));

  // 7. Let partialDateTime be ?
  // PreparePartialTemporalFields(temporalDateTimeLike, fieldNames).
  Handle<JSReceiver> partial_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, partial_date_time,
      PreparePartialTemporalFields(isolate, temporal_date_time_like,
                                   field_names));

  // 8. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 9. Let fields be ? PrepareTemporalFields(dateTime, fieldNames, «»).
  Handle<JSReceiver> fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      PrepareTemporalFields(isolate, date_time, field_names,
                            RequiredFields::kNone));

  // 10. Set fields to ? CalendarMergeFields(calendar, fields, partialDateTime).
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      CalendarMergeFields(isolate, calendar, fields, partial_date_time));
  // 11. Set fields to ? PrepareTemporalFields(fields, fieldNames, «»).
  ASSIGN_RETURN_ON_EXCEPTION(isolate, fields,
                             PrepareTemporalFields(isolate, fields, field_names,
                                                   RequiredFields::kNone));
  // 12. Let result be ? InterpretTemporalDateTimeFields(calendar, fields,
  // options).
  temporal::DateTimeRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      InterpretTemporalDateTimeFields(isolate, calendar, fields, options,
                                      method_name),
      Handle<JSTemporalPlainDateTime>());
  // 13. Assert: ! IsValidISODate(result.[[Year]], result.[[Month]],
  // result.[[Day]]) is true.
  DCHECK(IsValidISODate(isolate, result.date));
  // 14. Assert: ! IsValidTime(result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]]) is true.
  DCHECK(IsValidTime(isolate, result.time));
  // 15. Return ? CreateTemporalDateTime(result.[[Year]], result.[[Month]],
  // result.[[Day]], result.[[Hour]], result.[[Minute]], result.[[Second]],
  // result.[[Millisecond]], result.[[Microsecond]], result.[[Nanosecond]],
  // calendar).
  return temporal::CreateTemporalDateTime(isolate, {result.date, result.time},
                                          calendar);
}

// #sec-temporal.plaindatetime.prototype.withplaintime
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::WithPlainTime(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> plain_time_like) {
  // 1. Let temporalDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. If plainTimeLike is undefined, then
  if (IsUndefined(*plain_time_like)) {
    // a. Return ? CreateTemporalDateTime(temporalDateTime.[[ISOYear]],
    // temporalDateTime.[[ISOMonth]], temporalDateTime.[[ISODay]], 0, 0, 0, 0,
    // 0, 0, temporalDateTime.[[Calendar]]).
    return temporal::CreateTemporalDateTime(
        isolate,
        {{date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
         {0, 0, 0, 0, 0, 0}},
        handle(date_time->calendar(), isolate));
  }
  Handle<JSTemporalPlainTime> plain_time;
  // 4. Let plainTime be ? ToTemporalTime(plainTimeLike).
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, plain_time,
      temporal::ToTemporalTime(
          isolate, plain_time_like,
          "Temporal.PlainDateTime.prototype.withPlainTime"));
  // 5. Return ? CreateTemporalDateTime(temporalDateTime.[[ISOYear]],
  // temporalDateTime.[[ISOMonth]], temporalDateTime.[[ISODay]],
  // plainTime.[[ISOHour]], plainTime.[[ISOMinute]], plainTime.[[ISOSecond]],
  // plainTime.[[ISOMillisecond]], plainTime.[[ISOMicrosecond]],
  // plainTime.[[ISONanosecond]], temporalDateTime.[[Calendar]]).
  return temporal::CreateTemporalDateTime(
      isolate,
      {{date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
       {plain_time->iso_hour(), plain_time->iso_minute(),
        plain_time->iso_second(), plain_time->iso_millisecond(),
        plain_time->iso_microsecond(), plain_time->iso_nanosecond()}},
      handle(date_time->calendar(), isolate));
}

// #sec-temporal.plaindatetime.prototype.withcalendar
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::WithCalendar(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> calendar_like) {
  // 1. Let temporalDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. Let calendar be ? ToTemporalCalendar(calendar).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      temporal::ToTemporalCalendar(
          isolate, calendar_like,
          "Temporal.PlainDateTime.prototype.withCalendar"));
  // 4. Return ? CreateTemporalDateTime(temporalDateTime.[[ISOYear]],
  // temporalDateTime.[[ISOMonth]], temporalDateTime.[[ISODay]],
  // temporalDateTime.[[ISOHour]], temporalDateTime.[[ISOMinute]],
  // temporalDateTime.[[ISOSecond]], temporalDateTime.[[ISOMillisecond]],
  // temporalDateTime.[[ISOMicrosecond]], temporalDateTime.[[ISONanosecond]],
  // calendar).
  return temporal::CreateTemporalDateTime(
      isolate,
      {{date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
       {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
        date_time->iso_millisecond(), date_time->iso_microsecond(),
        date_time->iso_nanosecond()}},
      calendar);
}

// #sec-temporal.plaindatetime.prototype.toplainyearmonth
MaybeHandle<JSTemporalPlainYearMonth> JSTemporalPlainDateTime::ToPlainYearMonth(
    Isolate* isolate, Handle<JSTemporalPlainDateTime> date_time) {
  return ToPlain<JSTemporalPlainDateTime, JSTemporalPlainYearMonth,
                 YearMonthFromFields>(isolate, date_time,
                                      isolate->factory()->monthCode_string(),
                                      isolate->factory()->year_string());
}

// #sec-temporal.plaindatetime.prototype.toplainmonthday
MaybeHandle<JSTemporalPlainMonthDay> JSTemporalPlainDateTime::ToPlainMonthDay(
    Isolate* isolate, Handle<JSTemporalPlainDateTime> date_time) {
  return ToPlain<JSTemporalPlainDateTime, JSTemporalPlainMonthDay,
                 MonthDayFromFields>(isolate, date_time,
                                     isolate->factory()->day_string(),
                                     isolate->factory()->monthCode_string());
}

// #sec-temporal.plaindatetime.prototype.tozoneddatetime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalPlainDateTime::ToZonedDateTime(
    Isolate* isolate, Handle<JSTemporalPlainDateTime> date_time,
    Handle<Object> temporal_time_zone_like, Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainDateTime.prototype.toZonedDateTime";
  // 1. Let dateTime be the this value.
  // 2. Perform ? RequireInternalSlot(dateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. Let timeZone be ? ToTemporalTimeZone(temporalTimeZoneLike).
  Handle<JSReceiver> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      temporal::ToTemporalTimeZone(isolate, temporal_time_zone_like,
                                   method_name));
  // 4. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 5. Let disambiguation be ? ToTemporalDisambiguation(options).
  Disambiguation disambiguation;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, disambiguation,
      ToTemporalDisambiguation(isolate, options, method_name),
      Handle<JSTemporalZonedDateTime>());

  // 6. Let instant be ? BuiltinTimeZoneGetInstantFor(timeZone, dateTime,
  // disambiguation).
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, date_time,
                                   disambiguation, method_name));

  // 7. Return ? CreateTemporalZonedDateTime(instant.[[Nanoseconds]],
  // timeZone, dateTime.[[Calendar]]).
  return CreateTemporalZonedDateTime(
      isolate, handle(instant->nanoseconds(), isolate), time_zone,
      Handle<JSReceiver>(date_time->calendar(), isolate));
}

namespace {

// #sec-temporal-consolidatecalendars
MaybeHandle<JSReceiver> ConsolidateCalendars(Isolate* isolate,
                                             Handle<JSReceiver> one,
                                             Handle<JSReceiver> two) {
  Factory* factory = isolate->factory();
  // 1. If one and two are the same Object value, return two.
  if (one.is_identical_to(two)) return two;

  // 2. Let calendarOne be ? ToString(one).
  Handle<String> calendar_one;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, calendar_one,
                             Object::ToString(isolate, one));
  // 3. Let calendarTwo be ? ToString(two).
  Handle<String> calendar_two;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, calendar_two,
                             Object::ToString(isolate, two));
  // 4. If calendarOne is calendarTwo, return two.
  if (String::Equals(isolate, calendar_one, calendar_two)) {
    return two;
  }
  // 5. If calendarOne is "iso8601", return two.
  if (String::Equals(isolate, calendar_one, factory->iso8601_string())) {
    return two;
  }
  // 6. If calendarTwo is "iso8601", return one.
  if (String::Equals(isolate, calendar_two, factory->iso8601_string())) {
    return one;
  }
  // 7. Throw a RangeError exception.
  THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
}

}  // namespace

// #sec-temporal.plaindatetime.prototype.withplaindate
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::WithPlainDate(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> temporal_date_like) {
  // 1. Let temporalDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. Let plainDate be ? ToTemporalDate(plainDateLike).
  Handle<JSTemporalPlainDate> plain_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, plain_date,
      ToTemporalDate(isolate, temporal_date_like,
                     "Temporal.PlainDateTime.prototype.withPlainDate"));
  // 4. Let calendar be ? ConsolidateCalendars(temporalDateTime.[[Calendar]],
  // plainDate.[[Calendar]]).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ConsolidateCalendars(isolate, handle(date_time->calendar(), isolate),
                           handle(plain_date->calendar(), isolate)));
  // 5. Return ? CreateTemporalDateTime(plainDate.[[ISOYear]],
  // plainDate.[[ISOMonth]], plainDate.[[ISODay]], temporalDateTime.[[ISOHour]],
  // temporalDateTime.[[ISOMinute]], temporalDateTime.[[ISOSecond]],
  // temporalDateTime.[[ISOMillisecond]], temporalDateTime.[[ISOMicrosecond]],
  // temporalDateTime.[[ISONanosecond]], calendar).
  return temporal::CreateTemporalDateTime(
      isolate,
      {{plain_date->iso_year(), plain_date->iso_month(), plain_date->iso_day()},
       {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
        date_time->iso_millisecond(), date_time->iso_microsecond(),
        date_time->iso_nanosecond()}},
      calendar);
}

namespace {
MaybeHandle<String> TemporalDateTimeToString(Isolate* isolate,
                                             const DateTimeRecord& date_time,
                                             Handle<JSReceiver> calendar,
                                             Precision precision,
                                             ShowCalendar show_calendar) {
  IncrementalStringBuilder builder(isolate);
  // 1. Assert: isoYear, isoMonth, isoDay, hour, minute, second, millisecond,
  // microsecond, and nanosecond are integers.
  // 2. Let year be ! PadISOYear(isoYear).
  PadISOYear(&builder, date_time.date.year);

  // 3. Let month be ToZeroPaddedDecimalString(isoMonth, 2).
  builder.AppendCharacter('-');
  ToZeroPaddedDecimalString(&builder, date_time.date.month, 2);

  // 4. Let day be ToZeroPaddedDecimalString(isoDay, 2).
  builder.AppendCharacter('-');
  ToZeroPaddedDecimalString(&builder, date_time.date.day, 2);
  // 5. Let hour be ToZeroPaddedDecimalString(hour, 2).
  builder.AppendCharacter('T');
  ToZeroPaddedDecimalString(&builder, date_time.time.hour, 2);

  // 6. Let minute be ToZeroPaddedDecimalString(minute, 2).
  builder.AppendCharacter(':');
  ToZeroPaddedDecimalString(&builder, date_time.time.minute, 2);

  // 7. Let seconds be ! FormatSecondsStringPart(second, millisecond,
  // microsecond, nanosecond, precision).
  FormatSecondsStringPart(
      &builder, date_time.time.second, date_time.time.millisecond,
      date_time.time.microsecond, date_time.time.nanosecond, precision);
  // 8. Let calendarString be ? MaybeFormatCalendarAnnotation(calendar,
  // showCalendar).
  Handle<String> calendar_string;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar_string,
      MaybeFormatCalendarAnnotation(isolate, calendar, show_calendar));

  // 9. Return the string-concatenation of year, the code unit 0x002D
  // (HYPHEN-MINUS), month, the code unit 0x002D (HYPHEN-MINUS), day, 0x0054
  // (LATIN CAPITAL LETTER T), hour, the code unit 0x003A (COLON), minute,
  builder.AppendString(calendar_string);
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}
}  // namespace

// #sec-temporal.plaindatetime.prototype.tojson
MaybeHandle<String> JSTemporalPlainDateTime::ToJSON(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time) {
  return TemporalDateTimeToString(
      isolate,
      {{date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
       {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
        date_time->iso_millisecond(), date_time->iso_microsecond(),
        date_time->iso_nanosecond()}},
      Handle<JSReceiver>(date_time->calendar(), isolate), Precision::kAuto,
      ShowCalendar::kAuto);
}

// #sec-temporal.plaindatetime.prototype.tolocalestring
MaybeHandle<String> JSTemporalPlainDateTime::ToLocaleString(
    Isolate* isolate, Handle<JSTemporalPlainDateTime> date_time,
    Handle<Object> locales, Handle<Object> options) {
#ifdef V8_INTL_SUPPORT
  return JSDateTimeFormat::TemporalToLocaleString(
      isolate, date_time, locales, options,
      "Temporal.PlainDateTime.prototype.toLocaleString");
#else   //  V8_INTL_SUPPORT
  return TemporalDateTimeToString(
      isolate,
      {{date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
       {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
        date_time->iso_millisecond(), date_time->iso_microsecond(),
        date_time->iso_nanosecond()}},
      Handle<JSReceiver>(date_time->calendar(), isolate), Precision::kAuto,
      ShowCalendar::kAuto);
#endif  // V8_INTL_SUPPORT
}

namespace {

constexpr double kNsPerDay = 8.64e13;

DateTimeRecord RoundTime(
    Isolate* isolate, const TimeRecord& time, double increment, Unit unit,
    RoundingMode rounding_mode,
    // 3.a a. If dayLengthNs is not present, set dayLengthNs to nsPerDay.
    double day_length_ns = kNsPerDay);

// #sec-temporal-roundisodatetime
DateTimeRecord RoundISODateTime(
    Isolate* isolate, const DateTimeRecord& date_time, double increment,
    Unit unit, RoundingMode rounding_mode,
    // 3. If dayLength is not present, set dayLength to nsPerDay.
    double day_length_ns = kNsPerDay) {
  // 1. Assert: year, month, day, hour, minute, second, millisecond,
  // microsecond, and nanosecond are integers.
  TEMPORAL_ENTER_FUNC();
  // 2. Assert: ISODateTimeWithinLimits(year, month, day, hour, minute, second,
  // millisecond, microsecond, nanosecond) is true.
  DCHECK(ISODateTimeWithinLimits(isolate, date_time));

  // 4. Let roundedTime be ! RoundTime(hour, minute, second, millisecond,
  // microsecond, nanosecond, increment, unit, roundingMode, dayLength).
  DateTimeRecord rounded_time = RoundTime(isolate, date_time.time, increment,
                                          unit, rounding_mode, day_length_ns);
  // 5. Let balanceResult be ! BalanceISODate(year, month, day +
  // roundedTime.[[Days]]).
  rounded_time.date.year = date_time.date.year;
  rounded_time.date.month = date_time.date.month;
  rounded_time.date.day += date_time.date.day;
  DateRecord balance_result = BalanceISODate(isolate, rounded_time.date);

  // 6. Return the Record { [[Year]]: balanceResult.[[Year]], [[Month]]:
  // balanceResult.[[Month]], [[Day]]: balanceResult.[[Day]], [[Hour]]:
  // roundedTime.[[Hour]], [[Minute]]: roundedTime.[[Minute]], [[Second]]:
  // roundedTime.[[Second]], [[Millisecond]]: roundedTime.[[Millisecond]],
  // [[Microsecond]]: roundedTime.[[Microsecond]], [[Nanosecond]]:
  // roundedTime.[[Nanosecond]] }.
  return {balance_result, rounded_time.time};
}

}  // namespace

// #sec-temporal.plaindatetime.prototype.tostring
MaybeHandle<String> JSTemporalPlainDateTime::ToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainDateTime.prototype.toString";
  // 1. Let dateTime be the this value.
  // 2. Perform ? RequireInternalSlot(dateTime,
  // [[InitializedTemporalDateTime]]).
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

  // 5. Let roundingMode be ? ToTemporalRoundingMode(options, "trunc").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, options, RoundingMode::kTrunc,
                             method_name),
      Handle<String>());

  // 6. Let showCalendar be ? ToShowCalendarOption(options).
  ShowCalendar show_calendar;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, show_calendar,
      ToShowCalendarOption(isolate, options, method_name), Handle<String>());

  // 7. Let result be ! RoundISODateTime(dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]], precision.[[Increment]], precision.[[Unit]],
  // roundingMode).
  DateTimeRecord result = RoundISODateTime(
      isolate,
      {{date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
       {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
        date_time->iso_millisecond(), date_time->iso_microsecond(),
        date_time->iso_nanosecond()}},
      precision.increment, precision.unit, rounding_mode);
  // 8. Return ? TemporalDateTimeToString(result.[[Year]], result.[[Month]],
  // result.[[Day]], result.[[Hour]], result.[[Minute]], result.[[Second]],
  // result.[[Millisecond]], result.[[Microsecond]], result.[[Nanosecond]],
  // dateTime.[[Calendar]], precision.[[Precision]], showCalendar).
  return TemporalDateTimeToString(isolate, result,
                                  handle(date_time->calendar(), isolate),
                                  precision.precision, show_calendar);
}

// #sec-temporal.now.plaindatetime
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::Now(
    Isolate* isolate, Handle<Object> calendar_like,
    Handle<Object> temporal_time_zone_like) {
  const char* method_name = "Temporal.Now.plainDateTime";
  // 1. Return ? SystemDateTime(temporalTimeZoneLike, calendarLike).
  return SystemDateTime(isolate, temporal_time_zone_like, calendar_like,
                        method_name);
}

// #sec-temporal.now.plaindatetimeiso
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::NowISO(
    Isolate* isolate, Handle<Object> temporal_time_zone_like) {
  const char* method_name = "Temporal.Now.plainDateTimeISO";
  // 1. Let calendar be ! GetISO8601Calendar().
  Handle<JSReceiver> calendar = temporal::GetISO8601Calendar(isolate);
  // 2. Return ? SystemDateTime(temporalTimeZoneLike, calendar).
  return SystemDateTime(isolate, temporal_time_zone_like, calendar,
                        method_name);
}

namespace {

// #sec-temporal-totemporaldatetimeroundingincrement
Maybe<double> ToTemporalDateTimeRoundingIncrement(
    Isolate* isolate, Handle<JSReceiver> normalized_option,
    Unit smallest_unit) {
  Maximum maximum;
  // 1. If smallestUnit is "day", then
  if (smallest_unit == Unit::kDay) {
    // a. Let maximum be 1.
    maximum.value = 1;
    maximum.defined = true;
    // 2. Else,
  } else {
    // a. Let maximum be !
    // MaximumTemporalDurationRoundingIncrement(smallestUnit).
    maximum = MaximumTemporalDurationRoundingIncrement(smallest_unit);
    // b. Assert: maximum is not undefined.
    DCHECK(maximum.defined);
  }
  // 3. Return ? ToTemporalRoundingIncrement(normalizedOptions, maximum, false).
  return ToTemporalRoundingIncrement(isolate, normalized_option, maximum.value,
                                     maximum.defined, false);
}

}  // namespace

// #sec-temporal.plaindatetime.prototype.round
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::Round(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> round_to_obj) {
  const char* method_name = "Temporal.PlainDateTime.prototype.round";
  Factory* factory = isolate->factory();
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(dateTime,
  // [[InitializedTemporalDateTime]]).
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
    // 5. Else
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
                      Unit::kDay, true, method_name),
      Handle<JSTemporalPlainDateTime>());

  // 7. Let roundingMode be ? ToTemporalRoundingMode(roundTo, "halfExpand").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, round_to, RoundingMode::kHalfExpand,
                             method_name),
      Handle<JSTemporalPlainDateTime>());

  // 8. Let roundingIncrement be ? ToTemporalDateTimeRoundingIncrement(roundTo,
  // smallestUnit).
  double rounding_increment;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_increment,
      ToTemporalDateTimeRoundingIncrement(isolate, round_to, smallest_unit),
      Handle<JSTemporalPlainDateTime>());

  // 9. Let result be ! RoundISODateTime(dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]], roundingIncrement, smallestUnit, roundingMode).
  DateTimeRecord result = RoundISODateTime(
      isolate,
      {{date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
       {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
        date_time->iso_millisecond(), date_time->iso_microsecond(),
        date_time->iso_nanosecond()}},
      rounding_increment, smallest_unit, rounding_mode);

  // 10. Return ? CreateTemporalDateTime(result.[[Year]], result.[[Month]],
  // result.[[Day]], result.[[Hour]], result.[[Minute]], result.[[Second]],
  // result.[[Millisecond]], result.[[Microsecond]], result.[[Nanosecond]],
  // dateTime.[[Calendar]]).
  return temporal::CreateTemporalDateTime(
      isolate, result, handle(date_time->calendar(), isolate));
}

namespace {

MaybeHandle<JSTemporalPlainDateTime>
AddDurationToOrSubtractDurationFromPlainDateTime(
    Isolate* isolate, Arithmetic operation,
    DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> temporal_duration_like, Handle<Object> options_obj,
    const char* method_name) {
  // 1. If operation is subtract, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == Arithmetic::kSubtract ? -1.0 : 1.0;
  // 2. Let duration be ? ToTemporalDurationRecord(temporalDurationLike).
  DurationRecord duration;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, duration,
      temporal::ToTemporalDurationRecord(isolate, temporal_duration_like,
                                         method_name),
      Handle<JSTemporalPlainDateTime>());

  TimeDurationRecord& time_duration = duration.time_duration;

  // 3. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 4. Let result be ? AddDateTime(dateTime.[[ISOYear]], dateTime.[[ISOMonth]],
  // dateTime.[[ISODay]], dateTime.[[ISOHour]], dateTime.[[ISOMinute]],
  // dateTime.[[ISOSecond]], dateTime.[[ISOMillisecond]],
  // dateTime.[[ISOMicrosecond]], dateTime.[[ISONanosecond]],
  // dateTime.[[Calendar]], duration.[[Years]], duration.[[Months]],
  // duration.[[Weeks]], duration.[[Days]], duration.[[Hours]],
  // duration.[[Minutes]], duration.[[Seconds]], duration.[[Milliseconds]],
  // duration.[[Microseconds]], duration.[[Nanoseconds]], options).
  DateTimeRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      AddDateTime(isolate,
                  {{date_time->iso_year(), date_time->iso_month(),
                    date_time->iso_day()},
                   {date_time->iso_hour(), date_time->iso_minute(),
                    date_time->iso_second(), date_time->iso_millisecond(),
                    date_time->iso_microsecond(), date_time->iso_nanosecond()}},
                  handle(date_time->calendar(), isolate),
                  {sign * duration.years,
                   sign * duration.months,
                   sign * duration.weeks,
                   {sign * time_duration.days, sign * time_duration.hours,
                    sign * time_duration.minutes, sign * time_duration.seconds,
                    sign * time_duration.milliseconds,
                    sign * time_duration.microseconds,
                    sign * time_duration.nanoseconds}},
                  options),
      Handle<JSTemporalPlainDateTime>());

  // 5. Assert: ! IsValidISODate(result.[[Year]], result.[[Month]],
  // result.[[Day]]) is true.
  DCHECK(IsValidISODate(isolate, result.date));
  // 6. Assert: ! IsValidTime(result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]]) is true.
  DCHECK(IsValidTime(isolate, result.time));
  // 7. Return ? CreateTemporalDateTime(result.[[Year]], result.[[Month]],
  // result.[[Day]], result.[[Hour]], result.[[Minute]], result.[[Second]],
  // result.[[Millisecond]], result.[[Microsecond]], result.[[Nanosecond]],
  // dateTime.[[Calendar]]).
  return temporal::CreateTemporalDateTime(
      isolate, result, handle(date_time->calendar(), isolate));
}

}  // namespace

// #sec-temporal.plaindatetime.prototype.add
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::Add(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> temporal_duration_like, Handle<Object> options) {
  return AddDurationToOrSubtractDurationFromPlainDateTime(
      isolate, Arithmetic::kAdd, date_time, temporal_duration_like, options,
      "Temporal.PlainDateTime.prototype.add");
}

// #sec-temporal.plaindatetime.prototype.subtract
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDateTime::Subtract(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time,
    Handle<Object> temporal_duration_like, Handle<Object> options) {
  return AddDurationToOrSubtractDurationFromPlainDateTime(
      isolate, Arithmetic::kSubtract, date_time, temporal_duration_like,
      options, "Temporal.PlainDateTime.prototype.subtract");
}

namespace {

// #sec-temporal-differencetemporalplaindatetime
MaybeHandle<JSTemporalDuration> DifferenceTemporalPlainDateTime(
    Isolate* isolate, TimePreposition operation,
    DirectHandle<JSTemporalPlainDateTime> date_time, Handle<Object> other_obj,
    Handle<Object> options, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. If operation is since, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == TimePreposition::kSince ? -1 : 1;
  // 2. Set other to ? ToTemporalDateTime(other).
  Handle<JSTemporalPlainDateTime> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other, ToTemporalDateTime(isolate, other_obj, method_name));
  // 3. If ? CalendarEquals(dateTime.[[Calendar]], other.[[Calendar]]) is false,
  // throw a RangeError exception.
  bool calendar_equals;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar_equals,
      CalendarEqualsBool(isolate, handle(date_time->calendar(), isolate),
                         handle(other->calendar(), isolate)),
      Handle<JSTemporalDuration>());
  if (!calendar_equals) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 4. Let settings be ? GetDifferenceSettings(operation, options, datetime, «
  // », "nanosecond", "day").
  DifferenceSettings settings;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, settings,
      GetDifferenceSettings(isolate, operation, options, UnitGroup::kDateTime,
                            DisallowedUnitsInDifferenceSettings::kNone,
                            Unit::kNanosecond, Unit::kDay, method_name),
      Handle<JSTemporalDuration>());
  // 5. Let diff be ? DifferenceISODateTime(dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]], other.[[ISOYear]], other.[[ISOMonth]],
  // other.[[ISODay]], other.[[ISOHour]], other.[[ISOMinute]],
  // other.[[ISOSecond]], other.[[ISOMillisecond]], other.[[ISOMicrosecond]],
  // other.[[ISONanosecond]], dateTime.[[Calendar]], settings.[[LargestUnit]],
  // settings.[[Options]]).
  DurationRecord diff;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, diff,
      DifferenceISODateTime(
          isolate,
          {{date_time->iso_year(), date_time->iso_month(),
            date_time->iso_day()},
           {date_time->iso_hour(), date_time->iso_minute(),
            date_time->iso_second(), date_time->iso_millisecond(),
            date_time->iso_microsecond(), date_time->iso_nanosecond()}},
          {{other->iso_year(), other->iso_month(), other->iso_day()},
           {other->iso_hour(), other->iso_minute(), other->iso_second(),
            other->iso_millisecond(), other->iso_microsecond(),
            other->iso_nanosecond()}},
          handle(date_time->calendar(), isolate), settings.largest_unit,
          settings.options, method_name),
      Handle<JSTemporalDuration>());
  // 6. Let relativeTo be ! CreateTemporalDate(dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[Calendar]]).
  Handle<JSTemporalPlainDate> relative_to;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, relative_to,
      CreateTemporalDate(
          isolate,
          {date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
          handle(date_time->calendar(), isolate)),
      Handle<JSTemporalDuration>());
  // 7. Let roundResult be (? RoundDuration(diff.[[Years]], diff.[[Months]],
  // diff.[[Weeks]], diff.[[Days]], diff.[[Hours]], diff.[[Minutes]],
  // diff.[[Seconds]], diff.[[Milliseconds]], diff.[[Microseconds]],
  // diff.[[Nanoseconds]], settings.[[RoundingIncrement]],
  // settings.[[SmallestUnit]], settings.[[RoundingMode]],
  // relativeTo)).[[DurationRecord]].
  DurationRecordWithRemainder round_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, round_result,
      RoundDuration(isolate, diff, settings.rounding_increment,
                    settings.smallest_unit, settings.rounding_mode, relative_to,
                    method_name),
      Handle<JSTemporalDuration>());
  // 8. Let result be ? BalanceDuration(roundResult.[[Days]],
  // roundResult.[[Hours]], roundResult.[[Minutes]], roundResult.[[Seconds]],
  // roundResult.[[Milliseconds]], roundResult.[[Microseconds]],
  // roundResult.[[Nanoseconds]], settings.[[LargestUnit]]).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, round_result.record.time_duration,
      BalanceDuration(isolate, settings.largest_unit,
                      round_result.record.time_duration, method_name),
      Handle<JSTemporalDuration>());
  // 9. Return ! CreateTemporalDuration(sign × roundResult.[[Years]], sign ×
  // roundResult.[[Months]], sign × roundResult.[[Weeks]], sign ×
  // result.[[Days]], sign × result.[[Hours]], sign × result.[[Minutes]], sign ×
  // result.[[Seconds]], sign × result.[[Milliseconds]], sign ×
  // result.[[Microseconds]], sign × result.[[Nanoseconds]]).
  return CreateTemporalDuration(
             isolate, {sign * round_result.record.years,
                       sign * round_result.record.months,
                       sign * round_result.record.weeks,
                       {sign * round_result.record.time_duration.days,
                        sign * round_result.record.time_duration.hours,
                        sign * round_result.record.time_duration.minutes,
                        sign * round_result.record.time_duration.seconds,
                        sign * round_result.record.time_duration.milliseconds,
                        sign * round_result.record.time_duration.microseconds,
                        sign * round_result.record.time_duration.nanoseconds}})
      .ToHandleChecked();
}

}  // namespace

// #sec-temporal.plaindatetime.prototype.until
MaybeHandle<JSTemporalDuration> JSTemporalPlainDateTime::Until(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalPlainDateTime(
      isolate, TimePreposition::kUntil, handle, other, options,
      "Temporal.PlainDateTime.prototype.until");
}

// #sec-temporal.plaindatetime.prototype.since
MaybeHandle<JSTemporalDuration> JSTemporalPlainDateTime::Since(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalPlainDateTime(
      isolate, TimePreposition::kSince, handle, other, options,
      "Temporal.PlainDateTime.prototype.since");
}

// #sec-temporal.plaindatetime.prototype.getisofields
MaybeHandle<JSReceiver> JSTemporalPlainDateTime::GetISOFields(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time) {
  Factory* factory = isolate->factory();
  // 1. Let dateTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. Let fields be ! OrdinaryObjectCreate(%Object.prototype%).
  Handle<JSObject> fields =
      isolate->factory()->NewJSObject(isolate->object_function());
  // 4. Perform ! CreateDataPropertyOrThrow(fields, "calendar",
  // temporalTime.[[Calendar]]).
  CHECK(JSReceiver::CreateDataProperty(
            isolate, fields, factory->calendar_string(),
            Handle<JSReceiver>(date_time->calendar(), isolate),
            Just(kThrowOnError))
            .FromJust());
  // 5. Perform ! CreateDataPropertyOrThrow(fields, "isoDay",
  // 𝔽(dateTime.[[ISODay]])).
  // 6. Perform ! CreateDataPropertyOrThrow(fields, "isoHour",
  // 𝔽(temporalTime.[[ISOHour]])).
  // 7. Perform ! CreateDataPropertyOrThrow(fields, "isoMicrosecond",
  // 𝔽(temporalTime.[[ISOMicrosecond]])).
  // 8. Perform ! CreateDataPropertyOrThrow(fields, "isoMillisecond",
  // 𝔽(temporalTime.[[ISOMillisecond]])).
  // 9. Perform ! CreateDataPropertyOrThrow(fields, "isoMinute",
  // 𝔽(temporalTime.[[ISOMinute]])).
  // 10. Perform ! CreateDataPropertyOrThrow(fields, "isoMonth",
  // 𝔽(temporalTime.[[ISOMonth]])).
  // 11. Perform ! CreateDataPropertyOrThrow(fields, "isoNanosecond",
  // 𝔽(temporalTime.[[ISONanosecond]])).
  // 12. Perform ! CreateDataPropertyOrThrow(fields, "isoSecond",
  // 𝔽(temporalTime.[[ISOSecond]])).
  // 13. Perform ! CreateDataPropertyOrThrow(fields, "isoYear",
  // 𝔽(temporalTime.[[ISOYear]])).
  DEFINE_INT_FIELD(fields, isoDay, iso_day, date_time)
  DEFINE_INT_FIELD(fields, isoHour, iso_hour, date_time)
  DEFINE_INT_FIELD(fields, isoMicrosecond, iso_microsecond, date_time)
  DEFINE_INT_FIELD(fields, isoMillisecond, iso_millisecond, date_time)
  DEFINE_INT_FIELD(fields, isoMinute, iso_minute, date_time)
  DEFINE_INT_FIELD(fields, isoMonth, iso_month, date_time)
  DEFINE_INT_FIELD(fields, isoNanosecond, iso_nanosecond, date_time)
  DEFINE_INT_FIELD(fields, isoSecond, iso_second, date_time)
  DEFINE_INT_FIELD(fields, isoYear, iso_year, date_time)
  // 14. Return fields.
  return fields;
}

// #sec-temporal.plaindatetime.prototype.toplaindate
MaybeHandle<JSTemporalPlainDate> JSTemporalPlainDateTime::ToPlainDate(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time) {
  // 1. Let dateTime be the this value.
  // 2. Perform ? RequireInternalSlot(dateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. Return ? CreateTemporalDate(dateTime.[[ISOYear]], dateTime.[[ISOMonth]],
  // dateTime.[[ISODay]], dateTime.[[Calendar]]).
  return CreateTemporalDate(
      isolate,
      {date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
      Handle<JSReceiver>(date_time->calendar(), isolate));
}

// #sec-temporal.plaindatetime.prototype.toplaintime
MaybeHandle<JSTemporalPlainTime> JSTemporalPlainDateTime::ToPlainTime(
    Isolate* isolate, DirectHandle<JSTemporalPlainDateTime> date_time) {
  // 1. Let dateTime be the this value.
  // 2. Perform ? RequireInternalSlot(dateTime,
  // [[InitializedTemporalDateTime]]).
  // 3. Return ? CreateTemporalTime(dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]]).
  return CreateTemporalTime(
      isolate, {date_time->iso_hour(), date_time->iso_minute(),
                date_time->iso_second(), date_time->iso_millisecond(),
                date_time->iso_microsecond(), date_time->iso_nanosecond()});
}

// #sec-temporal.plainmonthday
MaybeHandle<JSTemporalPlainMonthDay> JSTemporalPlainMonthDay::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> iso_month_obj, Handle<Object> iso_day_obj,
    Handle<Object> calendar_like, Handle<Object> reference_iso_year_obj) {
  const char* method_name = "Temporal.PlainMonthDay";
  // 1. If NewTarget is undefined, throw a TypeError exception.
  if (IsUndefined(*new_target)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }

  // 3. Let m be ? ToIntegerThrowOnInfinity(isoMonth).
  TO_INT_THROW_ON_INFTY(iso_month, JSTemporalPlainMonthDay);
  // 5. Let d be ? ToIntegerThrowOnInfinity(isoDay).
  TO_INT_THROW_ON_INFTY(iso_day, JSTemporalPlainMonthDay);
  // 7. Let calendar be ? ToTemporalCalendarWithISODefault(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ToTemporalCalendarWithISODefault(isolate, calendar_like, method_name));

  // 2. If referenceISOYear is undefined, then
  // a. Set referenceISOYear to 1972𝔽.
  // ...
  // 8. Let ref be ? ToIntegerThrowOnInfinity(referenceISOYear).
  int32_t ref = 1972;
  if (!IsUndefined(*reference_iso_year_obj)) {
    TO_INT_THROW_ON_INFTY(reference_iso_year, JSTemporalPlainMonthDay);
    ref = reference_iso_year;
  }

  // 10. Return ? CreateTemporalMonthDay(y, m, calendar, ref, NewTarget).
  return CreateTemporalMonthDay(isolate, target, new_target, iso_month, iso_day,
                                calendar, ref);
}

namespace {

// #sec-temporal-parsetemporalmonthdaystring
Maybe<DateRecordWithCalendar> ParseTemporalMonthDayString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: Type(isoString) is String.
  // 2. If isoString does not satisfy the syntax of a TemporalMonthDayString
  // (see 13.33), then
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalMonthDayString(isolate, iso_string);
  if (!parsed.has_value()) {
    // a. Throw a *RangeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateRecordWithCalendar>());
  }
  // 3. If isoString contains a UTCDesignator, then
  if (parsed->utc_designator) {
    // a. Throw a *R
"""


```