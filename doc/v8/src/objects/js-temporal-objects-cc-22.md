Response:
The user wants a summary of the provided C++ code snippet for `v8/src/objects/js-temporal-objects.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core functionality:** The code primarily deals with `JSTemporalZonedDateTime` objects. This suggests functions related to creating, manipulating, and converting these objects.

2. **Scan for function names and their actions:**  Look for keywords like `Create`, `With`, `To`, `Add`, `Round`, `Now`. These verbs hint at the operations being performed.

3. **Group related functions:** Notice patterns like `WithCalendar`, `WithPlainDate`, `WithPlainTime`, `WithTimeZone`. These are all variations of modifying a `JSTemporalZonedDateTime`. Similarly, `ToPlainYearMonth`, `ToPlainMonthDay`, `ToString`, `ToJSON`, `ToLocaleString` are conversions to other types.

4. **Infer functionality from parameter names and internal slots:**  The code frequently accesses internal slots like `[[Nanoseconds]]`, `[[TimeZone]]`, `[[Calendar]]`. This confirms that the functions manipulate the internal state of `JSTemporalZonedDateTime` objects. Parameters like `calendar_like`, `plain_date_like`, `time_zone_like` indicate input types for object creation or modification.

5. **Connect to JavaScript concepts:** The names of the functions closely mirror the methods available on the `Temporal.ZonedDateTime` object in JavaScript. This allows for direct mapping and example generation. For instance, `WithCalendar` corresponds to the JavaScript `withCalendar()` method.

6. **Identify potential user errors:**  The `round` function's check for `undefined` input and the `AddZonedDateTime` function's handling of potential errors point to common mistakes users might make when using the Temporal API.

7. **Pay attention to conditional logic:** The `ToString` function uses options to control the output format, highlighting the flexibility of the API.

8. **Note external dependencies:** The mention of `V8_INTL_SUPPORT` in `ToLocaleString` indicates interaction with internationalization features.

9. **Address the '.tq' question:** The prompt explicitly asks about `.tq` files. Since the given file is `.cc`, the answer should clearly state that it's not a Torque file.

10. **Synthesize a summary:** Combine the identified functionalities into a concise overview, emphasizing the core purpose of the code.

11. **Organize the answer:** Structure the response with clear headings for each aspect (functionality, JavaScript examples, logic, errors, summary).

12. **Refine and clarify:** Review the generated answer for clarity, accuracy, and completeness. Ensure the JavaScript examples are relevant and easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on low-level C++ details.
* **Correction:** Shift focus to the high-level functionality and how it relates to the JavaScript API, as requested by the prompt.
* **Initial thought:** List every single function individually.
* **Correction:** Group functions by their purpose (creation, modification, conversion) for better readability and understanding.
* **Initial thought:** Provide very complex JavaScript examples.
* **Correction:** Simplify the JavaScript examples to illustrate the core concept without unnecessary complexity.
* **Initial thought:**  Miss the connection to potential user errors.
* **Correction:**  Review the code for error handling patterns and relate them to likely user mistakes.

By following these steps and refining the analysis along the way, a comprehensive and accurate answer can be generated.
```cpp
eTimeResult be ? InterpretTemporalDateTimeFields(calendar,
  // fields, options).
  temporal::DateTimeRecord date_time_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, date_time_result,
      InterpretTemporalDateTimeFields(isolate, calendar, fields, options,
                                      method_name),
      Handle<JSTemporalZonedDateTime>());

  // 20. Let offsetNanoseconds be ? ParseTimeZoneOffsetString(offsetString).
  int64_t offset_nanoseconds;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_nanoseconds,
      ParseTimeZoneOffsetString(isolate, Cast<String>(offset_string)),
      Handle<JSTemporalZonedDateTime>());

  // 21. Let epochNanoseconds be ?
  // InterpretISODateTimeOffset(dateTimeResult.[[Year]],
  // dateTimeResult.[[Month]], dateTimeResult.[[Day]], dateTimeResult.[[Hour]],
  // dateTimeResult.[[Minute]], dateTimeResult.[[Second]],
  // dateTimeResult.[[Millisecond]], dateTimeResult.[[Microsecond]],
  // dateTimeResult.[[Nanosecond]], option, offsetNanoseconds, timeZone,
  // disambiguation, offset, match exactly).
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      InterpretISODateTimeOffset(
          isolate, {date_time_result.date, date_time_result.time},
          OffsetBehaviour::kOption, offset_nanoseconds, time_zone,
          disambiguation, offset, MatchBehaviour::kMatchExactly, method_name));

  // 27. Return ? CreateTemporalZonedDateTime(epochNanoseconds, timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(isolate, epoch_nanoseconds, time_zone,
                                     calendar);
}

// #sec-temporal.zoneddatetime.prototype.withcalendar
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::WithCalendar(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> calendar_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.withCalendar";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let calendar be ? ToTemporalCalendar(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      temporal::ToTemporalCalendar(isolate, calendar_like, method_name));

  // 4. Return ? CreateTemporalZonedDateTime(zonedDateTime.[[Nanoseconds]],
  // zonedDateTime.[[TimeZone]], calendar).
  DirectHandle<BigInt> nanoseconds(zoned_date_time->nanoseconds(), isolate);
  DirectHandle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  return CreateTemporalZonedDateTime(isolate, nanoseconds, time_zone, calendar);
}

// #sec-temporal.zoneddatetime.prototype.withplaindate
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::WithPlainDate(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> plain_date_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.withPlainDate";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let plainDate be ? ToTemporalDate(plainDateLike).
  Handle<JSTemporalPlainDate> plain_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, plain_date,
      ToTemporalDate(isolate, plain_date_like, method_name));

  // 4. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 5. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();

  // 6. Let plainDateTime be ?
  // temporal::BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant,
  // zonedDateTime.[[Calendar]]).
  Handle<JSTemporalPlainDateTime> plain_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, plain_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(
          isolate, time_zone, instant,
          handle(zoned_date_time->calendar(), isolate), method_name));
  // 7. Let calendar be ? ConsolidateCalendars(zonedDateTime.[[Calendar]],
  // plainDate.[[Calendar]]).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ConsolidateCalendars(isolate,
                           handle(zoned_date_time->calendar(), isolate),
                           handle(plain_date->calendar(), isolate)));

  // 8. Let resultPlainDateTime be ?
  // CreateTemporalDateTime(plainDate.[[ISOYear]], plainDate.[[ISOMonth]],
  // plainDate.[[ISODay]], plainDateTime.[[ISOHour]],
  // plainDateTime.[[ISOMinute]], plainDateTime.[[ISOSecond]],
  // plainDateTime.[[ISOMillisecond]], plainDateTime.[[ISOMicrosecond]],
  // plainDateTime.[[ISONanosecond]], calendar).
  Handle<JSTemporalPlainDateTime> result_plain_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result_plain_date_time,
      temporal::CreateTemporalDateTime(
          isolate,
          {{plain_date->iso_year(), plain_date->iso_month(),
            plain_date->iso_day()},
           {plain_date_time->iso_hour(), plain_date_time->iso_minute(),
            plain_date_time->iso_second(), plain_date_time->iso_millisecond(),
            plain_date_time->iso_microsecond(),
            plain_date_time->iso_nanosecond()}},
          calendar));
  // 9. Set instant to ? BuiltinTimeZoneGetInstantFor(timeZone,
  // resultPlainDateTime, "compatible").
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, result_plain_date_time,
                                   Disambiguation::kCompatible, method_name));
  // 10. Return ? CreateTemporalZonedDateTime(instant.[[Nanoseconds]], timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(
      isolate, handle(instant->nanoseconds(), isolate), time_zone, calendar);
}

// #sec-temporal.zoneddatetime.prototype.withplaintime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::WithPlainTime(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> plain_time_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.withPlainTime";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. If plainTimeLike is undefined, then
  Handle<JSTemporalPlainTime> plain_time;
  if (IsUndefined(*plain_time_like)) {
    // a. Let plainTime be ? CreateTemporalTime(0, 0, 0, 0, 0, 0).
    ASSIGN_RETURN_ON_EXCEPTION(isolate, plain_time,
                               CreateTemporalTime(isolate, {0, 0, 0, 0, 0, 0}));
    // 4. Else,
  } else {
    // a. Let plainTime be ? ToTemporalTime(plainTimeLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, plain_time,
        temporal::ToTemporalTime(isolate, plain_time_like, method_name));
  }
  // 5. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 6. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();
  // 7. Let calendar be zonedDateTime.[[Calendar]].
  DirectHandle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);
  // 8. Let plainDateTime be ?
  // temporal::BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant, calendar).
  Handle<JSTemporalPlainDateTime> plain_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, plain_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   calendar, method_name));
  // 9. Let resultPlainDateTime be ?
  // CreateTemporalDateTime(plainDateTime.[[ISOYear]],
  // plainDateTime.[[ISOMonth]], plainDateTime.[[ISODay]],
  // plainTime.[[ISOHour]], plainTime.[[ISOMinute]], plainTime.[[ISOSecond]],
  // plainTime.[[ISOMillisecond]], plainTime.[[ISOMicrosecond]],
  // plainTime.[[ISONanosecond]], calendar).
  Handle<JSTemporalPlainDateTime> result_plain_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result_plain_date_time,
      temporal::CreateTemporalDateTime(
          isolate,
          {{plain_date_time->iso_year(), plain_date_time->iso_month(),
            plain_date_time->iso_day()},
           {plain_time->iso_hour(), plain_time->iso_minute(),
            plain_time->iso_second(), plain_time->iso_millisecond(),
            plain_time->iso_microsecond(),
            plain_time->iso_nanosecond()}},
          calendar));
  // 10. Let instant be ? BuiltinTimeZoneGetInstantFor(timeZone,
  // resultPlainDateTime, "compatible").
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, result_plain_date_time,
                                   Disambiguation::kCompatible, method_name));
  // 11. Return ? CreateTemporalZonedDateTime(instant.[[Nanoseconds]], timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(
      isolate, handle(instant->nanoseconds(), isolate), time_zone, calendar);
}

// #sec-temporal.zoneddatetime.prototype.withtimezone
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::WithTimeZone(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> time_zone_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.withTimeZone";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let timeZone be ? ToTemporalTimeZone(timeZoneLike).
  Handle<JSReceiver> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      temporal::ToTemporalTimeZone(isolate, time_zone_like, method_name));

  // 4. Return ? CreateTemporalZonedDateTime(zonedDateTime.[[Nanoseconds]],
  // timeZone, zonedDateTime.[[Calendar]]).
  DirectHandle<BigInt> nanoseconds(zoned_date_time->nanoseconds(), isolate);
  DirectHandle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);
  return CreateTemporalZonedDateTime(isolate, nanoseconds, time_zone, calendar);
}

// Common code shared by ZonedDateTime.prototype.toPlainYearMonth and
// toPlainMonthDay
template <typename T,
          MaybeHandle<T> (*from_fields_func)(
              Isolate*, Handle<JSReceiver>, Handle<JSReceiver>, Handle<Object>)>
MaybeHandle<T> ZonedDateTimeToPlainYearMonthOrMonthDay(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    DirectHandle<String> field_name_1, DirectHandle<String> field_name_2,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  Factory* factory = isolate->factory();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 4. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();
  // 5. Let calendar be zonedDateTime.[[Calendar]].
  Handle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);
  // 6. Let temporalDateTime be ?
  // temporal::BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant, calendar).
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   calendar, method_name));
  // 7. Let fieldNames be ? CalendarFields(calendar, « field_name_1,
  // field_name_2 »).
  Handle<FixedArray> field_names = factory->NewFixedArray(2);
  field_names->set(0, *field_name_1);
  field_names->set(1, *field_name_2);
  ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                             CalendarFields(isolate, calendar, field_names));
  // 8. Let fields be ? PrepareTemporalFields(temporalDateTime, fieldNames, «»).
  Handle<JSReceiver> fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      PrepareTemporalFields(isolate, temporal_date_time, field_names,
                            RequiredFields::kNone));
  // 9. Return ? XxxFromFields(calendar, fields).
  return from_fields_func(isolate, calendar, fields,
                          factory->undefined_value());
}

// #sec-temporal.zoneddatetime.prototype.toplainyearmonth
MaybeHandle<JSTemporalPlainYearMonth> JSTemporalZonedDateTime::ToPlainYearMonth(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  return ZonedDateTimeToPlainYearMonthOrMonthDay<JSTemporalPlainYearMonth,
                                                 YearMonthFromFields>(
      isolate, zoned_date_time, isolate->factory()->monthCode_string(),
      isolate->factory()->year_string(),
      "Temporal.ZonedDateTime.prototype.toPlainYearMonth");
}

// #sec-temporal.zoneddatetime.prototype.toplainmonthday
MaybeHandle<JSTemporalPlainMonthDay> JSTemporalZonedDateTime::ToPlainMonthDay(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  return ZonedDateTimeToPlainYearMonthOrMonthDay<JSTemporalPlainMonthDay,
                                                 MonthDayFromFields>(
      isolate, zoned_date_time, isolate->factory()->day_string(),
      isolate->factory()->monthCode_string(),
      "Temporal.ZonedDateTime.prototype.toPlainMonthDay");
}

namespace {

// #sec-temporal-temporalzoneddatetimetostring
MaybeHandle<String> TemporalZonedDateTimeToString(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Precision precision, ShowCalendar show_calendar,
    ShowTimeZone show_time_zone, ShowOffset show_offset, double increment,
    Unit unit, RoundingMode rounding_mode, const char* method_name) {
  // 4. Let ns be ! RoundTemporalInstant(zonedDateTime.[[Nanoseconds]],
  // increment, unit, roundingMode).
  DirectHandle<BigInt> ns = RoundTemporalInstant(
      isolate, handle(zoned_date_time->nanoseconds(), isolate), increment, unit,
      rounding_mode);

  // 5. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 6. Let instant be ! CreateTemporalInstant(ns).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(isolate, ns).ToHandleChecked();

  // 7. Let isoCalendar be ! GetISO8601Calendar().
  Handle<JSTemporalCalendar> iso_calendar =
      temporal::GetISO8601Calendar(isolate);

  // 8. Let temporalDateTime be ?
  // BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant,
  // isoCalendar).
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   iso_calendar, method_name));
  // 9. Let dateTimeString be ?
  // TemporalDateTimeToString(temporalDateTime.[[ISOYear]],
  // temporalDateTime.[[ISOMonth]], temporalDateTime.[[ISODay]],
  // temporalDateTime.[[ISOHour]], temporalDateTime.[[ISOMinute]],
  // temporalDateTime.[[ISOSecond]], temporalDateTime.[[ISOMillisecond]],
  // temporalDateTime.[[ISOMicrosecond]], temporalDateTime.[[ISONanosecond]],
  // isoCalendar, precision, "never").
  Handle<String> date_time_string;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time_string,
      TemporalDateTimeToString(
          isolate,
          {{temporal_date_time->iso_year(), temporal_date_time->iso_month(),
            temporal_date_time->iso_day()},
           {temporal_date_time->iso_hour(), temporal_date_time->iso_minute(),
            temporal_date_time->iso_second(),
            temporal_date_time->iso_millisecond(),
            temporal_date_time->iso_microsecond(),
            temporal_date_time->iso_nanosecond()}},
          iso_calendar, precision, ShowCalendar::kNever));

  IncrementalStringBuilder builder(isolate);
  builder.AppendString(date_time_string);

  // 10. If showOffset is "never", then
  if (show_offset == ShowOffset::kNever) {
    // a. Let offsetString be the empty String.
    // 11. Else,
  } else {
    // a. Let offsetNs be ? GetOffsetNanosecondsFor(timeZone, instant).
    int64_t offset_ns;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, offset_ns,
        GetOffsetNanosecondsFor(isolate, time_zone, instant, method_name),
        Handle<String>());
    // b. Let offsetString be ! FormatISOTimeZoneOffsetString(offsetNs).
    builder.AppendString(FormatISOTimeZoneOffsetString(isolate, offset_ns));
  }

  // 12. If showTimeZone is "never", then
  if (show_time_zone == ShowTimeZone::kNever) {
    // a. Let timeZoneString be the empty String.
    // 13. Else,
  } else {
    // a. Let timeZoneID be ? ToString(timeZone).
    Handle<String> time_zone_id;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, time_zone_id,
                               Object::ToString(isolate, time_zone));
    // b. Let timeZoneString be the string-concatenation of the code unit 0x005B
    // (LEFT SQUARE BRACKET), timeZoneID, and the code unit 0x005D (RIGHT SQUARE
    // BRACKET).
    builder.AppendCStringLiteral("[");
    builder.AppendString(time_zone_id);
    builder.AppendCStringLiteral("]");
  }
  // 14. Let calendarString be ?
  // MaybeFormatCalendarAnnotation(zonedDateTime.[[Calendar]], showCalendar).
  Handle<String> calendar_string;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar_string,
      MaybeFormatCalendarAnnotation(
          isolate, handle(zoned_date_time->calendar(), isolate),
          show_calendar));

  // 15. Return the string-concatenation of dateTimeString, offsetString,
  // timeZoneString, and calendarString.
  builder.AppendString(calendar_string);
  return indirect_handle(builder.Finish(), isolate);
}

// #sec-temporal-temporalzoneddatetimetostring
MaybeHandle<String> TemporalZonedDateTimeToString(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Precision precision, ShowCalendar show_calendar,
    ShowTimeZone show_time_zone, ShowOffset show_offset,
    const char* method_name) {
  // 1. Assert: Type(zonedDateTime) is Object and zonedDateTime has an
  // [[InitializedTemporalZonedDateTime]] internal slot.
  // 2. If increment is not present, set it to 1.
  // 3. If unit is not present, set it to "nanosecond".
  // 4. If roundingMode is not present, set it to "trunc".
  return TemporalZonedDateTimeToString(
      isolate, zoned_date_time, precision, show_calendar, show_time_zone,
      show_offset, 1, Unit::kNanosecond, RoundingMode::kTrunc, method_name);
}

}  // namespace
// #sec-temporal.zoneddatetime.prototype.tojson
MaybeHandle<String> JSTemporalZonedDateTime::ToJSON(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Return ? TemporalZonedDateTimeToString(zonedDateTime, "auto", "auto",
  // "auto", "auto").
  return TemporalZonedDateTimeToString(
      isolate, zoned_date_time, Precision::kAuto, ShowCalendar::kAuto,
      ShowTimeZone::kAuto, ShowOffset::kAuto,
      "Temporal.ZonedDateTime.prototype.toJSON");
}

// #sec-temporal.zoneddatetime.prototype.tolocalestring
MaybeHandle<String> JSTemporalZonedDateTime::ToLocaleString(
    Isolate* isolate, Handle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> locales, Handle<Object> options) {
  const char* method_name = "Temporal.ZonedDateTime.prototype.toLocaleString";
#ifdef V8_INTL_SUPPORT
  return JSDateTimeFormat::TemporalToLocaleString(
      isolate, zoned_date_time, locales, options, method_name);
#else   //  V8_INTL_SUPPORT
  return TemporalZonedDateTimeToString(
      isolate, zoned_date_time, Precision::kAuto, ShowCalendar::kAuto,
      ShowTimeZone::kAuto, ShowOffset::kAuto, method_name);
#endif  //  V8_INTL_SUPPORT
}

// #sec-temporal.zoneddatetime.prototype.tostring
MaybeHandle<String> JSTemporalZonedDateTime::ToString(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> options_obj) {
  const char* method_name = "Temporal.ZonedDateTime.prototype.toString";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
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

  // 7. Let showTimeZone be ? ToShowTimeZoneNameOption(options).
  ShowTimeZone show_time_zone;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, show_time_zone,
      ToShowTimeZoneNameOption(isolate, options, method_name),
      Handle<String>());

  // 8. Let showOffset be ? ToShowOffsetOption(options).
  ShowOffset show_offset;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, show_offset, ToShowOffsetOption(isolate, options, method_name),
      Handle<String>());

  // 9. Return ? TemporalZonedDateTimeToString(zonedDateTime,
  // precision.[[Precision]], showCalendar, showTimeZone, showOffset,
  // precision.[[Increment]], precision.[[Unit]], roundingMode).
  return TemporalZonedDateTimeToString(
      isolate, zoned_date_time, precision.precision, show_calendar,
      show_time_zone, show_offset, precision.increment, precision.unit,
      rounding_mode, method_name);
}

// #sec-temporal.now.zoneddatetime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::Now(
    Isolate* isolate, Handle<Object> calendar_like,
    Handle<Object> temporal_time_zone_like) {
  const char* method_name = "Temporal.Now.zonedDateTime";
  // 1. Return ? SystemZonedDateTime(temporalTimeZoneLike, calendarLike).
  return SystemZonedDateTime(isolate, temporal_time_zone_like, calendar_like,
                             method_name);
}

// #sec-temporal.now.zoneddatetimeiso
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::NowISO(
    Isolate* isolate, Handle<Object> temporal_time_zone_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.Now.zonedDateTimeISO";
  // 1. Let calendar be ! GetISO8601Calendar().
  Handle<JSReceiver> calendar = temporal::GetISO8601Calendar(isolate);
  // 2. Return ? SystemZonedDateTime(temporalTimeZoneLike, calendar).
  return SystemZonedDateTime(isolate, temporal_time_zone_like, calendar,
                             method_name);
}

// #sec-temporal.zoneddatetime.prototype.round
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::Round(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> round_to_obj) {
  const char* method_name = "Temporal.ZonedDateTime.prototype.round";
  Factory* factory = isolate->factory();
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
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
  // required, « "day" »).
  Unit smallest_unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, smallest_unit,
      GetTemporalUnit(isolate, round_to, "smallestUnit", UnitGroup::kTime,
                      Unit::kDay, true, method_name, Unit::kDay),
      Handle<JSTemporalZonedDateTime>());

  // 7. Let roundingMode be ? ToTemporalRoundingMode(roundTo, "halfExpand").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, round_to, RoundingMode::kHalfExpand,
                             method_name),
      Handle<JSTemporalZonedDateTime>());

  // 8. Let roundingIncrement be ? ToTemporalDateTimeRoundingIncrement(roundTo,
  // smallestUnit).
  double rounding_increment;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_increment,
      ToTemporalDateTimeRoundingIncrement(isolate, round_to, smallest_unit),
      Handle<JSTemporalZonedDateTime>());

  // 9. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 10. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();
  // 11. Let calendar be zonedDateTime.[[Calendar]].
  Handle
### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第23部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
eTimeResult be ? InterpretTemporalDateTimeFields(calendar,
  // fields, options).
  temporal::DateTimeRecord date_time_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, date_time_result,
      InterpretTemporalDateTimeFields(isolate, calendar, fields, options,
                                      method_name),
      Handle<JSTemporalZonedDateTime>());

  // 20. Let offsetNanoseconds be ? ParseTimeZoneOffsetString(offsetString).
  int64_t offset_nanoseconds;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_nanoseconds,
      ParseTimeZoneOffsetString(isolate, Cast<String>(offset_string)),
      Handle<JSTemporalZonedDateTime>());

  // 21. Let epochNanoseconds be ?
  // InterpretISODateTimeOffset(dateTimeResult.[[Year]],
  // dateTimeResult.[[Month]], dateTimeResult.[[Day]], dateTimeResult.[[Hour]],
  // dateTimeResult.[[Minute]], dateTimeResult.[[Second]],
  // dateTimeResult.[[Millisecond]], dateTimeResult.[[Microsecond]],
  // dateTimeResult.[[Nanosecond]], option, offsetNanoseconds, timeZone,
  // disambiguation, offset, match exactly).
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      InterpretISODateTimeOffset(
          isolate, {date_time_result.date, date_time_result.time},
          OffsetBehaviour::kOption, offset_nanoseconds, time_zone,
          disambiguation, offset, MatchBehaviour::kMatchExactly, method_name));

  // 27. Return ? CreateTemporalZonedDateTime(epochNanoseconds, timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(isolate, epoch_nanoseconds, time_zone,
                                     calendar);
}

// #sec-temporal.zoneddatetime.prototype.withcalendar
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::WithCalendar(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> calendar_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.withCalendar";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let calendar be ? ToTemporalCalendar(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      temporal::ToTemporalCalendar(isolate, calendar_like, method_name));

  // 4. Return ? CreateTemporalZonedDateTime(zonedDateTime.[[Nanoseconds]],
  // zonedDateTime.[[TimeZone]], calendar).
  DirectHandle<BigInt> nanoseconds(zoned_date_time->nanoseconds(), isolate);
  DirectHandle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  return CreateTemporalZonedDateTime(isolate, nanoseconds, time_zone, calendar);
}

// #sec-temporal.zoneddatetime.prototype.withplaindate
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::WithPlainDate(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> plain_date_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.withPlainDate";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let plainDate be ? ToTemporalDate(plainDateLike).
  Handle<JSTemporalPlainDate> plain_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, plain_date,
      ToTemporalDate(isolate, plain_date_like, method_name));

  // 4. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 5. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();

  // 6. Let plainDateTime be ?
  // temporal::BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant,
  // zonedDateTime.[[Calendar]]).
  Handle<JSTemporalPlainDateTime> plain_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, plain_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(
          isolate, time_zone, instant,
          handle(zoned_date_time->calendar(), isolate), method_name));
  // 7. Let calendar be ? ConsolidateCalendars(zonedDateTime.[[Calendar]],
  // plainDate.[[Calendar]]).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ConsolidateCalendars(isolate,
                           handle(zoned_date_time->calendar(), isolate),
                           handle(plain_date->calendar(), isolate)));

  // 8. Let resultPlainDateTime be ?
  // CreateTemporalDateTime(plainDate.[[ISOYear]], plainDate.[[ISOMonth]],
  // plainDate.[[ISODay]], plainDateTime.[[ISOHour]],
  // plainDateTime.[[ISOMinute]], plainDateTime.[[ISOSecond]],
  // plainDateTime.[[ISOMillisecond]], plainDateTime.[[ISOMicrosecond]],
  // plainDateTime.[[ISONanosecond]], calendar).
  Handle<JSTemporalPlainDateTime> result_plain_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result_plain_date_time,
      temporal::CreateTemporalDateTime(
          isolate,
          {{plain_date->iso_year(), plain_date->iso_month(),
            plain_date->iso_day()},
           {plain_date_time->iso_hour(), plain_date_time->iso_minute(),
            plain_date_time->iso_second(), plain_date_time->iso_millisecond(),
            plain_date_time->iso_microsecond(),
            plain_date_time->iso_nanosecond()}},
          calendar));
  // 9. Set instant to ? BuiltinTimeZoneGetInstantFor(timeZone,
  // resultPlainDateTime, "compatible").
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, result_plain_date_time,
                                   Disambiguation::kCompatible, method_name));
  // 10. Return ? CreateTemporalZonedDateTime(instant.[[Nanoseconds]], timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(
      isolate, handle(instant->nanoseconds(), isolate), time_zone, calendar);
}

// #sec-temporal.zoneddatetime.prototype.withplaintime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::WithPlainTime(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> plain_time_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.withPlainTime";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. If plainTimeLike is undefined, then
  Handle<JSTemporalPlainTime> plain_time;
  if (IsUndefined(*plain_time_like)) {
    // a. Let plainTime be ? CreateTemporalTime(0, 0, 0, 0, 0, 0).
    ASSIGN_RETURN_ON_EXCEPTION(isolate, plain_time,
                               CreateTemporalTime(isolate, {0, 0, 0, 0, 0, 0}));
    // 4. Else,
  } else {
    // a. Let plainTime be ? ToTemporalTime(plainTimeLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, plain_time,
        temporal::ToTemporalTime(isolate, plain_time_like, method_name));
  }
  // 5. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 6. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();
  // 7. Let calendar be zonedDateTime.[[Calendar]].
  DirectHandle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);
  // 8. Let plainDateTime be ?
  // temporal::BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant, calendar).
  Handle<JSTemporalPlainDateTime> plain_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, plain_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   calendar, method_name));
  // 9. Let resultPlainDateTime be ?
  // CreateTemporalDateTime(plainDateTime.[[ISOYear]],
  // plainDateTime.[[ISOMonth]], plainDateTime.[[ISODay]],
  // plainTime.[[ISOHour]], plainTime.[[ISOMinute]], plainTime.[[ISOSecond]],
  // plainTime.[[ISOMillisecond]], plainTime.[[ISOMicrosecond]],
  // plainTime.[[ISONanosecond]], calendar).
  Handle<JSTemporalPlainDateTime> result_plain_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result_plain_date_time,
      temporal::CreateTemporalDateTime(
          isolate,
          {{plain_date_time->iso_year(), plain_date_time->iso_month(),
            plain_date_time->iso_day()},
           {plain_time->iso_hour(), plain_time->iso_minute(),
            plain_time->iso_second(), plain_time->iso_millisecond(),
            plain_time->iso_microsecond(), plain_time->iso_nanosecond()}},
          calendar));
  // 10. Let instant be ? BuiltinTimeZoneGetInstantFor(timeZone,
  // resultPlainDateTime, "compatible").
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, result_plain_date_time,
                                   Disambiguation::kCompatible, method_name));
  // 11. Return ? CreateTemporalZonedDateTime(instant.[[Nanoseconds]], timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(
      isolate, handle(instant->nanoseconds(), isolate), time_zone, calendar);
}

// #sec-temporal.zoneddatetime.prototype.withtimezone
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::WithTimeZone(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> time_zone_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.withTimeZone";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let timeZone be ? ToTemporalTimeZone(timeZoneLike).
  Handle<JSReceiver> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      temporal::ToTemporalTimeZone(isolate, time_zone_like, method_name));

  // 4. Return ? CreateTemporalZonedDateTime(zonedDateTime.[[Nanoseconds]],
  // timeZone, zonedDateTime.[[Calendar]]).
  DirectHandle<BigInt> nanoseconds(zoned_date_time->nanoseconds(), isolate);
  DirectHandle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);
  return CreateTemporalZonedDateTime(isolate, nanoseconds, time_zone, calendar);
}

// Common code shared by ZonedDateTime.prototype.toPlainYearMonth and
// toPlainMonthDay
template <typename T,
          MaybeHandle<T> (*from_fields_func)(
              Isolate*, Handle<JSReceiver>, Handle<JSReceiver>, Handle<Object>)>
MaybeHandle<T> ZonedDateTimeToPlainYearMonthOrMonthDay(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    DirectHandle<String> field_name_1, DirectHandle<String> field_name_2,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  Factory* factory = isolate->factory();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 4. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();
  // 5. Let calendar be zonedDateTime.[[Calendar]].
  Handle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);
  // 6. Let temporalDateTime be ?
  // temporal::BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant, calendar).
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   calendar, method_name));
  // 7. Let fieldNames be ? CalendarFields(calendar, « field_name_1,
  // field_name_2 »).
  Handle<FixedArray> field_names = factory->NewFixedArray(2);
  field_names->set(0, *field_name_1);
  field_names->set(1, *field_name_2);
  ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                             CalendarFields(isolate, calendar, field_names));
  // 8. Let fields be ? PrepareTemporalFields(temporalDateTime, fieldNames, «»).
  Handle<JSReceiver> fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      PrepareTemporalFields(isolate, temporal_date_time, field_names,
                            RequiredFields::kNone));
  // 9. Return ? XxxFromFields(calendar, fields).
  return from_fields_func(isolate, calendar, fields,
                          factory->undefined_value());
}

// #sec-temporal.zoneddatetime.prototype.toplainyearmonth
MaybeHandle<JSTemporalPlainYearMonth> JSTemporalZonedDateTime::ToPlainYearMonth(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  return ZonedDateTimeToPlainYearMonthOrMonthDay<JSTemporalPlainYearMonth,
                                                 YearMonthFromFields>(
      isolate, zoned_date_time, isolate->factory()->monthCode_string(),
      isolate->factory()->year_string(),
      "Temporal.ZonedDateTime.prototype.toPlainYearMonth");
}

// #sec-temporal.zoneddatetime.prototype.toplainmonthday
MaybeHandle<JSTemporalPlainMonthDay> JSTemporalZonedDateTime::ToPlainMonthDay(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  return ZonedDateTimeToPlainYearMonthOrMonthDay<JSTemporalPlainMonthDay,
                                                 MonthDayFromFields>(
      isolate, zoned_date_time, isolate->factory()->day_string(),
      isolate->factory()->monthCode_string(),
      "Temporal.ZonedDateTime.prototype.toPlainMonthDay");
}

namespace {

// #sec-temporal-temporalzoneddatetimetostring
MaybeHandle<String> TemporalZonedDateTimeToString(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Precision precision, ShowCalendar show_calendar,
    ShowTimeZone show_time_zone, ShowOffset show_offset, double increment,
    Unit unit, RoundingMode rounding_mode, const char* method_name) {
  // 4. Let ns be ! RoundTemporalInstant(zonedDateTime.[[Nanoseconds]],
  // increment, unit, roundingMode).
  DirectHandle<BigInt> ns = RoundTemporalInstant(
      isolate, handle(zoned_date_time->nanoseconds(), isolate), increment, unit,
      rounding_mode);

  // 5. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 6. Let instant be ! CreateTemporalInstant(ns).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(isolate, ns).ToHandleChecked();

  // 7. Let isoCalendar be ! GetISO8601Calendar().
  Handle<JSTemporalCalendar> iso_calendar =
      temporal::GetISO8601Calendar(isolate);

  // 8. Let temporalDateTime be ?
  // BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant,
  // isoCalendar).
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   iso_calendar, method_name));
  // 9. Let dateTimeString be ?
  // TemporalDateTimeToString(temporalDateTime.[[ISOYear]],
  // temporalDateTime.[[ISOMonth]], temporalDateTime.[[ISODay]],
  // temporalDateTime.[[ISOHour]], temporalDateTime.[[ISOMinute]],
  // temporalDateTime.[[ISOSecond]], temporalDateTime.[[ISOMillisecond]],
  // temporalDateTime.[[ISOMicrosecond]], temporalDateTime.[[ISONanosecond]],
  // isoCalendar, precision, "never").
  Handle<String> date_time_string;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time_string,
      TemporalDateTimeToString(
          isolate,
          {{temporal_date_time->iso_year(), temporal_date_time->iso_month(),
            temporal_date_time->iso_day()},
           {temporal_date_time->iso_hour(), temporal_date_time->iso_minute(),
            temporal_date_time->iso_second(),
            temporal_date_time->iso_millisecond(),
            temporal_date_time->iso_microsecond(),
            temporal_date_time->iso_nanosecond()}},
          iso_calendar, precision, ShowCalendar::kNever));

  IncrementalStringBuilder builder(isolate);
  builder.AppendString(date_time_string);

  // 10. If showOffset is "never", then
  if (show_offset == ShowOffset::kNever) {
    // a. Let offsetString be the empty String.
    // 11. Else,
  } else {
    // a. Let offsetNs be ? GetOffsetNanosecondsFor(timeZone, instant).
    int64_t offset_ns;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, offset_ns,
        GetOffsetNanosecondsFor(isolate, time_zone, instant, method_name),
        Handle<String>());
    // b. Let offsetString be ! FormatISOTimeZoneOffsetString(offsetNs).
    builder.AppendString(FormatISOTimeZoneOffsetString(isolate, offset_ns));
  }

  // 12. If showTimeZone is "never", then
  if (show_time_zone == ShowTimeZone::kNever) {
    // a. Let timeZoneString be the empty String.
    // 13. Else,
  } else {
    // a. Let timeZoneID be ? ToString(timeZone).
    Handle<String> time_zone_id;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, time_zone_id,
                               Object::ToString(isolate, time_zone));
    // b. Let timeZoneString be the string-concatenation of the code unit 0x005B
    // (LEFT SQUARE BRACKET), timeZoneID, and the code unit 0x005D (RIGHT SQUARE
    // BRACKET).
    builder.AppendCStringLiteral("[");
    builder.AppendString(time_zone_id);
    builder.AppendCStringLiteral("]");
  }
  // 14. Let calendarString be ?
  // MaybeFormatCalendarAnnotation(zonedDateTime.[[Calendar]], showCalendar).
  Handle<String> calendar_string;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar_string,
      MaybeFormatCalendarAnnotation(
          isolate, handle(zoned_date_time->calendar(), isolate),
          show_calendar));

  // 15. Return the string-concatenation of dateTimeString, offsetString,
  // timeZoneString, and calendarString.
  builder.AppendString(calendar_string);
  return indirect_handle(builder.Finish(), isolate);
}

// #sec-temporal-temporalzoneddatetimetostring
MaybeHandle<String> TemporalZonedDateTimeToString(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Precision precision, ShowCalendar show_calendar,
    ShowTimeZone show_time_zone, ShowOffset show_offset,
    const char* method_name) {
  // 1. Assert: Type(zonedDateTime) is Object and zonedDateTime has an
  // [[InitializedTemporalZonedDateTime]] internal slot.
  // 2. If increment is not present, set it to 1.
  // 3. If unit is not present, set it to "nanosecond".
  // 4. If roundingMode is not present, set it to "trunc".
  return TemporalZonedDateTimeToString(
      isolate, zoned_date_time, precision, show_calendar, show_time_zone,
      show_offset, 1, Unit::kNanosecond, RoundingMode::kTrunc, method_name);
}

}  // namespace
// #sec-temporal.zoneddatetime.prototype.tojson
MaybeHandle<String> JSTemporalZonedDateTime::ToJSON(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Return ? TemporalZonedDateTimeToString(zonedDateTime, "auto", "auto",
  // "auto", "auto").
  return TemporalZonedDateTimeToString(
      isolate, zoned_date_time, Precision::kAuto, ShowCalendar::kAuto,
      ShowTimeZone::kAuto, ShowOffset::kAuto,
      "Temporal.ZonedDateTime.prototype.toJSON");
}

// #sec-temporal.zoneddatetime.prototype.tolocalestring
MaybeHandle<String> JSTemporalZonedDateTime::ToLocaleString(
    Isolate* isolate, Handle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> locales, Handle<Object> options) {
  const char* method_name = "Temporal.ZonedDateTime.prototype.toLocaleString";
#ifdef V8_INTL_SUPPORT
  return JSDateTimeFormat::TemporalToLocaleString(
      isolate, zoned_date_time, locales, options, method_name);
#else   //  V8_INTL_SUPPORT
  return TemporalZonedDateTimeToString(
      isolate, zoned_date_time, Precision::kAuto, ShowCalendar::kAuto,
      ShowTimeZone::kAuto, ShowOffset::kAuto, method_name);
#endif  //  V8_INTL_SUPPORT
}

// #sec-temporal.zoneddatetime.prototype.tostring
MaybeHandle<String> JSTemporalZonedDateTime::ToString(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> options_obj) {
  const char* method_name = "Temporal.ZonedDateTime.prototype.toString";
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
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

  // 7. Let showTimeZone be ? ToShowTimeZoneNameOption(options).
  ShowTimeZone show_time_zone;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, show_time_zone,
      ToShowTimeZoneNameOption(isolate, options, method_name),
      Handle<String>());

  // 8. Let showOffset be ? ToShowOffsetOption(options).
  ShowOffset show_offset;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, show_offset, ToShowOffsetOption(isolate, options, method_name),
      Handle<String>());

  // 9. Return ? TemporalZonedDateTimeToString(zonedDateTime,
  // precision.[[Precision]], showCalendar, showTimeZone, showOffset,
  // precision.[[Increment]], precision.[[Unit]], roundingMode).
  return TemporalZonedDateTimeToString(
      isolate, zoned_date_time, precision.precision, show_calendar,
      show_time_zone, show_offset, precision.increment, precision.unit,
      rounding_mode, method_name);
}

// #sec-temporal.now.zoneddatetime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::Now(
    Isolate* isolate, Handle<Object> calendar_like,
    Handle<Object> temporal_time_zone_like) {
  const char* method_name = "Temporal.Now.zonedDateTime";
  // 1. Return ? SystemZonedDateTime(temporalTimeZoneLike, calendarLike).
  return SystemZonedDateTime(isolate, temporal_time_zone_like, calendar_like,
                             method_name);
}

// #sec-temporal.now.zoneddatetimeiso
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::NowISO(
    Isolate* isolate, Handle<Object> temporal_time_zone_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.Now.zonedDateTimeISO";
  // 1. Let calendar be ! GetISO8601Calendar().
  Handle<JSReceiver> calendar = temporal::GetISO8601Calendar(isolate);
  // 2. Return ? SystemZonedDateTime(temporalTimeZoneLike, calendar).
  return SystemZonedDateTime(isolate, temporal_time_zone_like, calendar,
                             method_name);
}

// #sec-temporal.zoneddatetime.prototype.round
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::Round(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> round_to_obj) {
  const char* method_name = "Temporal.ZonedDateTime.prototype.round";
  Factory* factory = isolate->factory();
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
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
  // required, « "day" »).
  Unit smallest_unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, smallest_unit,
      GetTemporalUnit(isolate, round_to, "smallestUnit", UnitGroup::kTime,
                      Unit::kDay, true, method_name, Unit::kDay),
      Handle<JSTemporalZonedDateTime>());

  // 7. Let roundingMode be ? ToTemporalRoundingMode(roundTo, "halfExpand").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, round_to, RoundingMode::kHalfExpand,
                             method_name),
      Handle<JSTemporalZonedDateTime>());

  // 8. Let roundingIncrement be ? ToTemporalDateTimeRoundingIncrement(roundTo,
  // smallestUnit).
  double rounding_increment;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_increment,
      ToTemporalDateTimeRoundingIncrement(isolate, round_to, smallest_unit),
      Handle<JSTemporalZonedDateTime>());

  // 9. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 10. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  Handle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();
  // 11. Let calendar be zonedDateTime.[[Calendar]].
  Handle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);
  // 12. Let temporalDateTime be ? BuiltinTimeZoneGetPlainDateTimeFor(timeZone,
  // instant, calendar).
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   calendar, method_name));
  // 13. Let isoCalendar be ! GetISO8601Calendar().
  DirectHandle<JSReceiver> iso_calendar = temporal::GetISO8601Calendar(isolate);

  // 14. Let dtStart be ? CreateTemporalDateTime(temporalDateTime.[[ISOYear]],
  // temporalDateTime.[[ISOMonth]], temporalDateTime.[[ISODay]], 0, 0, 0, 0, 0,
  // 0, isoCalendar).
  Handle<JSTemporalPlainDateTime> dt_start;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, dt_start,
      temporal::CreateTemporalDateTime(
          isolate,
          {{temporal_date_time->iso_year(), temporal_date_time->iso_month(),
            temporal_date_time->iso_day()},
           {0, 0, 0, 0, 0, 0}},
          iso_calendar));
  // 15. Let instantStart be ? BuiltinTimeZoneGetInstantFor(timeZone, dtStart,
  // "compatible").
  Handle<JSTemporalInstant> instant_start;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant_start,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, dt_start,
                                   Disambiguation::kCompatible, method_name));
  // 16. Let startNs be instantStart.[[Nanoseconds]].
  Handle<BigInt> start_ns(instant_start->nanoseconds(), isolate);
  // 17. Let endNs be ? AddZonedDateTime(startNs, timeZone, calendar, 0, 0, 0,
  // 1, 0, 0, 0, 0, 0, 0).
  Handle<BigInt> end_ns;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, end_ns,
      AddZonedDateTime(isolate, start_ns, time_zone, calendar,
                       {0, 0, 0, {1, 0, 0, 0, 0, 0, 0}}, method_name));
  // 18. Let dayLengthNs be ℝ(endNs - startNs).
  DirectHandle<BigInt> day_length_ns =
      BigInt::Subtract(isolate, end_ns, start_ns).ToHandleChecked();
  // 19. If dayLengthNs ≤ 0, then
  if (day_length_ns->IsNegative() || !day_length_ns->ToBoolean()) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 20. Let roundResult be ! RoundISODateTime(temporalDateTime.[[ISOYear]],
  // temporalDateTime.[[ISOMonth]], temporalDateTime.[[ISODay]],
  // temporalDateTime.[[ISOHour]], temporalDateTime.[[ISOMinute]],
  // temporalDateTime.[[ISOSecond]], temporalDateTime.[[ISOMillisecond]],
  // temporalDateTime.[[ISOMicrosecond]], temporalDateTime.[[ISONanosecond]],
  // roundingIncrement, smallestUnit, roundingMode, dayLengthNs).
  DateTimeRecord round_result = RoundISODateTime(
      isolate,
      {{temporal_date_time->iso_year(), temporal_date_time->iso_month(),
        temporal_date_time->iso_day()},
       {temporal_date_time->iso_hour(), temporal_date_time->iso_minute(),
        temporal_date_time->iso_second(), temporal_date_time->iso_millisecond(),
        temporal_date_time->iso_microsecond(),
        temporal_date_time->iso_nanosecond()}},
      rounding_increment, smallest_unit, rounding_mode,
      Object::NumberValue(*BigInt::ToNumber(isolate, day_length_ns)));
  // 21. Let offsetNanoseconds be ? GetOffsetNanosecondsFor(timeZone, instant).
  int64_t offset_nanoseconds;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_nanoseconds,
      GetOffsetNanosecondsFor(isolate, time_zone, instant, method_name),
      Handle<JSTemporalZonedDateTime>());
  // 22. Let epochNanoseconds be ?
  // InterpretISODateTimeOffset(roundResult.[[Year]], roundResult.[[Month]],
  // roundResult.[[Day]], roundResult.[[Hour]], roundResult.[[Minute]],
  // roundResult.[[Second]], roundResult.[[Millisecond]],
  // roundResult.[[Microsecond]], roundResult.[[Nanosecond]], option,
  // offsetNanoseconds, timeZone, "compatible", "prefer", match exactly).
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      InterpretISODateTimeOffset(
          isolate, round_result, OffsetBehaviour::kOption, offset_nanoseconds,
          time_zone, Disambiguation::kCompatible, Offset::kPrefer,
          MatchBehaviour::kMatchExactly, method_name));

  // 23. Return ! CreateTemporalZonedDateTime(epochNanoseconds, timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(isolate, epoch_nanoseconds, time_zone,
                                     calendar)
      .ToHandleChecked();
}

namespace {

// #sec-temporal-adddurationtoOrsubtractdurationfromzoneddatetime
MaybeHandle<JSTemporalZonedDateTime>
AddDurationToOrSubtractDurationFromZonedDateTime(
    Isolate* isolate, Arithmetic operation,
    DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> temporal_duration_like, Handle<Object> options_obj,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. If operation is subtract, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == Arithmetic::kSubtract ? -1.0 : 1.0;
  // 2. Let duration be ? ToTemporalDurationRecord(temporalDurationLike).
  DurationRecord duration;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, duration,
      temporal::ToTemporalDurationRecord(isolate, temporal_duration_like,
                                         method_name),
      Handle<JSTemporalZonedDateTime>());

  TimeDurationRecord& time_duration = duration.time_duration;

  // 3. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 4. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);
  // 5. Let calendar be zonedDateTime.[[Calendar]].
  Handle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);
  // 6. Let epochNanoseconds be ?
  // AddZonedDateTime(zonedDateTime.[[Nanoseconds]], timeZone, calendar,
  // sign x durati
```