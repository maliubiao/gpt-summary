Response:
The user wants a summary of the provided C++ code snippet from `v8/src/objects/js-temporal-objects.cc`. I need to identify the functionalities implemented in this part of the file. The instructions also specify to check for `.tq` extension (not present), relate the code to JavaScript if possible, provide examples, discuss potential errors, and summarize the content as part 4 of 25.

Here's a breakdown of the code's functionality based on the function names and logic:

1. **Calendar Handling:**
   - `ToTemporalCalendar`: Converts a given object to a `TemporalCalendar` object. It handles string identifiers and existing `TemporalCalendar` objects.
   - `ToTemporalCalendarWithISODefault`: Similar to `ToTemporalCalendar` but defaults to the ISO 8601 calendar if the input is undefined.
   - `CreateTemporalCalendar`:  Creates a `TemporalCalendar` object.
   - `GetISO8601Calendar`: Retrieves the ISO 8601 calendar.

2. **Data Structures:**
   - `All10UnitsInFixedArray`, `DayMonthMonthCodeYearInFixedArray`, `MonthMonthCodeYearInFixedArray`, `MonthCodeYearInFixedArray`:  Create fixed arrays of strings representing different date/time units. These seem to be used for defining the expected fields when processing date/time objects.

3. **Date Handling:**
   - `ToTemporalDate`: Converts an object to a `TemporalDate` object. It handles different input types:
     - Existing `TemporalDate` objects.
     - `TemporalZonedDateTime` objects (converting them to a plain date based on the timezone and calendar).
     - `TemporalDateTime` objects (extracting the date part).
     - Objects with date fields, using `CalendarFields` and `DateFromFields`.
     - Date strings, parsing them with `ParseTemporalDateString`.
   - `CreateTemporalDate`: Creates a `TemporalDate` object.

4. **Type Checking and Conversion:**
   - `IsIntegralNumber`: Checks if a number is an integer.
   - `ToIntegerWithoutRounding`: Converts an object to an integer, throwing an error if it's not a valid integer.

5. **Time Handling:**
   - `RegulateTime`: Adjusts time components (hour, minute, etc.) based on an overflow setting ("constrain" or "reject").
   - `ToTemporalTime`: Converts an object to a `TemporalTime` object, similar to `ToTemporalDate` but for time.
   - `CreateTemporalTime`: Creates a `TemporalTime` object.
   - `ToTemporalTimeRecord`: Extracts time components from an object.
   - `ParseTemporalTimeString`: Parses a string to extract time components.
   - `IsValidTime`: Checks if the provided time components are valid.

6. **Duration Handling:**
   - `IterateDurationRecordFieldsTable`: A helper function to iterate over the fields of a duration record, used by `ToPartialDuration` and `ToTemporalDurationRecord`.
   - `ToTemporalDurationRecord`: Converts an object to a `DurationRecord`.
   - `ToTemporalDuration`: Converts an object to a `TemporalDuration` object.
   - `CreateTemporalDuration`: Creates a `TemporalDuration` object.
   - `ParseTemporalDurationString`: Parses a string to extract duration components.
   - `IsValidDuration`: Checks if the provided duration components are valid.

7. **Time Zone Handling:**
   - `ToTemporalTimeZone`: Converts an object to a `TemporalTimeZone` object.
   - `CreateTemporalTimeZone`: Creates a `TemporalTimeZone` object.
   - `CreateTemporalTimeZoneUTC`: Creates a `TemporalTimeZone` object for UTC.
   - `ParseTemporalTimeZoneString`: Parses a string to extract time zone information.
   - `IsValidTimeZoneName`: Checks if a time zone name is valid.
   - `CanonicalizeTimeZoneName`: Converts a time zone name to its canonical form.

8. **System Time:**
   - `SystemDateTime`: Gets the current date and time in a specified or system time zone and calendar.
   - `SystemZonedDateTime`: Gets the current date and time with time zone information.
   - `SystemTimeZone`: Gets the system's time zone.
   - `SystemInstant`: Gets the current instant in time.
   - `SystemUTCEpochNanoseconds`: Gets the current UTC epoch nanoseconds.

9. **Comparison:**
    - `CompareResultToSign`: Converts a comparison result to an integer sign.

10. **Formatting:**
    - `FormatTimeZoneOffsetString`: Formats a time zone offset in nanoseconds to a string like "+HH:MM" or "-HH:MM:SS".

Based on this analysis, I can now formulate the summary, examples, and error scenarios.
```cpp
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
    // Get(temporalTimeZoneLike
### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
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