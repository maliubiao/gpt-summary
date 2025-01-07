Response:
The user has provided a snippet of C++ code from `v8/src/objects/js-temporal-objects.cc` and is asking for a summary of its functionality. The user also has some specific constraints and questions related to the nature of the code (Torque, Javascript relation) and potential errors.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core functionality:**  The code primarily deals with formatting and parsing of date and time strings, specifically in the context of the Temporal API (based on the function names and comments). Keywords like `FormatISO...`, `ParseISO...`, `ToZeroPaddedDecimalString`, and `PadISOYear` clearly indicate string manipulation for date/time representations.

2. **Check for Torque:** The prompt mentions `.tq` files. A quick scan reveals no obvious Torque syntax. The code uses standard C++ with V8-specific types like `Handle`, `Isolate`, `IncrementalStringBuilder`, etc. Therefore, it's not Torque.

3. **Identify Javascript relationship:** The "Temporal" prefix strongly suggests a connection to the Javascript Temporal API. The functions are likely implementations of internal operations used by the Javascript `Temporal` objects.

4. **Provide Javascript examples:**  To illustrate the Javascript connection, map the C++ functions to their corresponding Javascript functionality. For example, `FormatISOTimeString` is used when a `Temporal.PlainTime` object is converted to a string. Similarly, `ParseTemporalDateString` is used when parsing a date string into a `Temporal.PlainDate` object.

5. **Look for code logic and provide input/output examples:**  Analyze some of the core functions for their logic.
    * `FormatISOTimeString`: Takes hours, minutes, seconds, and nanoseconds and formats them into an ISO time string. Consider cases with and without fractional seconds.
    * `FormatISOTimeZoneOffsetString`: Takes nanosecond offset and formats it into a timezone offset string. Consider positive and negative offsets.
    * `ToZeroPaddedDecimalString`:  Simple padding. Show how it adds leading zeros.
    * `PadISOYear`: Handles different year ranges and signs. Illustrate with a normal year and a year outside the default range.

6. **Identify potential programming errors:** Consider common mistakes users might make when working with date and time strings, especially in relation to the parsing functions. Examples include:
    * Invalid ISO format strings.
    * Providing timezone information when parsing a plain time.
    * Incorrect date components.

7. **Summarize the functionality:**  Condense the observations into a concise summary, highlighting the main tasks performed by the code: formatting and parsing Temporal-related date and time strings according to ISO 8601.

8. **Address the "part X of Y" constraint:**  Acknowledge the part number and total parts. This demonstrates attention to detail.

9. **Review and refine:** Ensure the language is clear, examples are relevant, and the summary accurately reflects the code's purpose. Double-check that all parts of the prompt are addressed. For instance, explicitly state that the code is *not* Torque.

**(Self-Correction during thought process):** Initially, I might have just focused on individual function descriptions. However, realizing the prompt asks for the *overall* functionality, I shifted to a more thematic approach, grouping related functions and highlighting their common purpose within the Temporal API context. I also made sure to provide concrete examples instead of just abstract descriptions. The prompt about potential errors prompted me to think about the user's perspective when interacting with the Javascript API that this C++ code supports.
```cpp
dDecimalString(&builder, minutes, 2);

  // 10. Let s be ToZeroPaddedDecimalString(seconds, 2).
  // 11. If nanoseconds ≠ 0, then
  if (nanoseconds != 0) {
    // a. Let fraction be ToZeroPaddedDecimalString(nanoseconds, 9).
    // b. Set fraction to the longest possible substring of fraction starting at
    // position 0 and not ending with the code unit 0x0030 (DIGIT ZERO). c. Let
    // post be the string-concatenation of the code unit 0x003A (COLON), s, the
    // code unit 0x002E (FULL STOP), and fraction.
    builder.AppendCharacter(':');
    ToZeroPaddedDecimalString(&builder, seconds, 2);
    builder.AppendCharacter('.');
    int64_t divisor = 100000000;
    do {
      builder.AppendInt(static_cast<int>(nanoseconds / divisor));
      nanoseconds %= divisor;
      divisor /= 10;
    } while (nanoseconds > 0);
    // 11. Else if seconds ≠ 0, then
  } else if (seconds != 0) {
    // a. Let post be the string-concatenation of the code unit 0x003A (COLON)
    // and s.
    builder.AppendCharacter(':');
    ToZeroPaddedDecimalString(&builder, seconds, 2);
  }
  // 12. Return the string-concatenation of sign, h, the code unit 0x003A
  // (COLON), m, and post.
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

double RoundNumberToIncrement(Isolate* isolate, double x, double increment,
                              RoundingMode rounding_mode);

// #sec-temporal-formatisotimezoneoffsetstring
Handle<String> FormatISOTimeZoneOffsetString(Isolate* isolate,
                                             int64_t offset_nanoseconds) {
  IncrementalStringBuilder builder(isolate);
  // 1. Assert: offsetNanoseconds is an integer.
  // 2. Set offsetNanoseconds to ! RoundNumberToIncrement(offsetNanoseconds, 60
  // × 10^9, "halfExpand").
  offset_nanoseconds = RoundNumberToIncrement(
      isolate, offset_nanoseconds, 60000000000, RoundingMode::kHalfExpand);
  // 3. If offsetNanoseconds ≥ 0, let sign be "+"; otherwise, let sign be "-".
  builder.AppendCharacter((offset_nanoseconds >= 0) ? '+' : '-');
  // 4. Set offsetNanoseconds to abs(offsetNanoseconds).
  offset_nanoseconds = std::abs(offset_nanoseconds);
  // 5. Let minutes be offsetNanoseconds / (60 × 10^9) modulo 60.
  int32_t minutes = (offset_nanoseconds / 60000000000) % 60;
  // 6. Let hours be floor(offsetNanoseconds / (3600 × 10^9)).
  int32_t hours = offset_nanoseconds / 3600000000000;
  // 7. Let h be ToZeroPaddedDecimalString(hours, 2).
  ToZeroPaddedDecimalString(&builder, hours, 2);

  // 8. Let m be ToZeroPaddedDecimalString(minutes, 2).
  builder.AppendCharacter(':');
  ToZeroPaddedDecimalString(&builder, minutes, 2);
  // 9. Return the string-concatenation of sign, h, the code unit 0x003A
  // (COLON), and m.
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

int32_t DecimalLength(int32_t n) {
  int32_t i = 1;
  while (n >= 10) {
    n /= 10;
    i++;
  }
  return i;
}

// #sec-tozeropaddeddecimalstring
void ToZeroPaddedDecimalString(IncrementalStringBuilder* builder, int32_t n,
                               int32_t min_length) {
  for (int32_t pad = min_length - DecimalLength(n); pad > 0; pad--) {
    builder->AppendCharacter('0');
  }
  builder->AppendInt(n);
}

// #sec-temporal-padisoyear
void PadISOYear(IncrementalStringBuilder* builder, int32_t y) {
  // 1. Assert: y is an integer.
  // 2. If y ≥ 0 and y ≤ 9999, then
  if (y >= 0 && y <= 9999) {
    // a. Return ToZeroPaddedDecimalString(y, 4).
    ToZeroPaddedDecimalString(builder, y, 4);
    return;
  }
  // 3. If y > 0, let yearSign be "+"; otherwise, let yearSign be "-".
  if (y > 0) {
    builder->AppendCharacter('+');
  } else {
    builder->AppendCharacter('-');
  }
  // 4. Let year be ToZeroPaddedDecimalString(abs(y), 6).
  ToZeroPaddedDecimalString(builder, std::abs(y), 6);
  // 5. Return the string-concatenation of yearSign and year.
}

// #sec-temporal-formatcalendarannotation
Handle<String> FormatCalendarAnnotation(Isolate* isolate, Handle<String> id,
                                        ShowCalendar show_calendar) {
  // 1.Assert: showCalendar is "auto", "always", or "never".
  // 2. If showCalendar is "never", return the empty String.
  if (show_calendar == ShowCalendar::kNever) {
    return isolate->factory()->empty_string();
  }
  // 3. If showCalendar is "auto" and id is "iso8601", return the empty String.
  if (show_calendar == ShowCalendar::kAuto &&
      String::Equals(isolate, id, isolate->factory()->iso8601_string())) {
    return isolate->factory()->empty_string();
  }
  // 4. Return the string-concatenation of "[u-ca=", id, and "]".
  IncrementalStringBuilder builder(isolate);
  builder.AppendCStringLiteral("[u-ca=");
  builder.AppendString(id);
  builder.AppendCharacter(']');
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

// #sec-temporal-maybeformatcalendarannotation
MaybeHandle<String> MaybeFormatCalendarAnnotation(
    Isolate* isolate, Handle<JSReceiver> calendar_object,
    ShowCalendar show_calendar) {
  // 1. If showCalendar is "never", return the empty String.
  if (show_calendar == ShowCalendar::kNever) {
    return isolate->factory()->empty_string();
  }
  // 2. Let calendarID be ? ToString(calendarObject).
  Handle<String> calendar_id;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, calendar_id,
                             Object::ToString(isolate, calendar_object));
  // 3. Return FormatCalendarAnnotation(calendarID, showCalendar).
  return FormatCalendarAnnotation(isolate, calendar_id, show_calendar);
}

// #sec-temporal-temporaldatetostring
MaybeHandle<String> TemporalDateToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainDate> temporal_date,
    ShowCalendar show_calendar) {
  IncrementalStringBuilder builder(isolate);
  // 1. Assert: Type(temporalDate) is Object.
  // 2. Assert: temporalDate has an [[InitializedTemporalDate]] internal slot.
  // 3. Let year be ! PadISOYear(temporalDate.[[ISOYear]]).
  PadISOYear(&builder, temporal_date->iso_year());
  // 4. Let month be ToZeroPaddedDecimalString(temporalDate.[[ISOMonth]], 2).
  builder.AppendCharacter('-');
  ToZeroPaddedDecimalString(&builder, temporal_date->iso_month(), 2);
  // 5. Let day be ToZeroPaddedDecimalString(temporalDate.[[ISODay]], 2).
  builder.AppendCharacter('-');
  ToZeroPaddedDecimalString(&builder, temporal_date->iso_day(), 2);
  // 6. Let calendar be ?
  // MaybeFormatCalendarAnnotation(temporalDate.[[Calendar]], showCalendar).
  Handle<String> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      MaybeFormatCalendarAnnotation(
          isolate, handle(temporal_date->calendar(), isolate), show_calendar));

  // 7. Return the string-concatenation of year, the code unit 0x002D
  // (HYPHEN-MINUS), month, the code unit 0x002D (HYPHEN-MINUS), day, and
  // calendar.
  builder.AppendString(calendar);
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

// #sec-temporal-temporalmonthdaytostring
MaybeHandle<String> TemporalMonthDayToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainMonthDay> month_day,
    ShowCalendar show_calendar) {
  // 1. Assert: Type(monthDay) is Object.
  // 2. Assert: monthDay has an [[InitializedTemporalMonthDay]] internal slot.
  IncrementalStringBuilder builder(isolate);
  // 6. Let calendarID be ? ToString(monthDay.[[Calendar]]).
  Handle<String> calendar_id;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar_id,
      Object::ToString(isolate, handle(month_day->calendar(), isolate)));
  // 7. If showCalendar is "always" or if calendarID is not "iso8601", then
  if (show_calendar == ShowCalendar::kAlways ||
      !String::Equals(isolate, calendar_id,
                      isolate->factory()->iso8601_string())) {
    // a. Let year be ! PadISOYear(monthDay.[[ISOYear]]).
    PadISOYear(&builder, month_day->iso_year());
    // b. Set result to the string-concatenation of year, the code unit
    // 0x002D (HYPHEN-MINUS), and result.
    builder.AppendCharacter('-');
  }
  // 3. Let month be ToZeroPaddedDecimalString(monthDay.[[ISOMonth]], 2).
  ToZeroPaddedDecimalString(&builder, month_day->iso_month(), 2);
  // 5. Let result be the string-concatenation of month, the code unit 0x002D
  // (HYPHEN-MINUS), and day.
  builder.AppendCharacter('-');
  // 4. Let day be ToZeroPaddedDecimalString(monthDay.[[ISODay]], 2).
  ToZeroPaddedDecimalString(&builder, month_day->iso_day(), 2);
  // 8. Let calendarString be ! FormatCalendarAnnotation(calendarID,
  // showCalendar).
  DirectHandle<String> calendar_string =
      FormatCalendarAnnotation(isolate, calendar_id, show_calendar);
  // 9. Set result to the string-concatenation of result and calendarString.
  builder.AppendString(calendar_string);
  // 10. Return result.
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

// #sec-temporal-temporalyearmonthtostring
MaybeHandle<String> TemporalYearMonthToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainYearMonth> year_month,
    ShowCalendar show_calendar) {
  // 1. Assert: Type(yearMonth) is Object.
  // 2. Assert: yearMonth has an [[InitializedTemporalYearMonth]] internal slot.
  IncrementalStringBuilder builder(isolate);
  // 3. Let year be ! PadISOYear(yearMonth.[[ISOYear]]).
  PadISOYear(&builder, year_month->iso_year());
  // 4. Let month be ToZeroPaddedDecimalString(yearMonth.[[ISOMonth]], 2).
  // 5. Let result be the string-concatenation of year, the code unit 0x002D
  // (HYPHEN-MINUS), and month.
  builder.AppendCharacter('-');
  ToZeroPaddedDecimalString(&builder, year_month->iso_month(), 2);
  // 6. Let calendarID be ? ToString(yearMonth.[[Calendar]]).
  Handle<String> calendar_id;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar_id,
      Object::ToString(isolate, handle(year_month->calendar(), isolate)));
  // 7. If showCalendar is "always" or if *_calendarID_ is not *"iso8601", then
  if (show_calendar == ShowCalendar::kAlways ||
      !String::Equals(isolate, calendar_id,
                      isolate->factory()->iso8601_string())) {
    // a. Let day be ToZeroPaddedDecimalString(yearMonth.[[ISODay]], 2).
    // b. Set result to the string-concatenation of result, the code unit 0x002D
    // (HYPHEN-MINUS), and day.
    builder.AppendCharacter('-');
    ToZeroPaddedDecimalString(&builder, year_month->iso_day(), 2);
  }
  // 8. Let calendarString be ! FormatCalendarAnnotation(calendarID,
  // showCalendar).
  DirectHandle<String> calendar_string =
      FormatCalendarAnnotation(isolate, calendar_id, show_calendar);
  // 9. Set result to the string-concatenation of result and calendarString.
  builder.AppendString(calendar_string);
  // 10. Return result.
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

// #sec-temporal-builtintimezonegetoffsetstringfor
MaybeHandle<String> BuiltinTimeZoneGetOffsetStringFor(
    Isolate* isolate, Handle<JSReceiver> time_zone,
    Handle<JSTemporalInstant> instant, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let offsetNanoseconds be ? GetOffsetNanosecondsFor(timeZone, instant).
  int64_t offset_nanoseconds;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_nanoseconds,
      GetOffsetNanosecondsFor(isolate, time_zone, instant, method_name),
      Handle<String>());

  // 2. Return ! FormatTimeZoneOffsetString(offsetNanoseconds).
  return FormatTimeZoneOffsetString(isolate, offset_nanoseconds);
}

// #sec-temporal-parseisodatetime
Maybe<DateTimeRecordWithCalendar> ParseISODateTime(
    Isolate* isolate, Handle<String> iso_string,
    const ParsedISO8601Result& parsed);
// Note: We split ParseISODateTime to two function because the spec text
// repeates some parsing unnecessary. If a function is calling ParseISODateTime
// from a AO which already call ParseText() for TemporalDateTimeString,
// TemporalInstantString, TemporalMonthDayString, TemporalTimeString,
// TemporalYearMonthString, TemporalZonedDateTimeString. But for the usage in
// ParseTemporalTimeZoneString, we use the following version.
Maybe<DateTimeRecordWithCalendar> ParseISODateTime(Isolate* isolate,
                                                   Handle<String> iso_string) {
  // 2. For each nonterminal goal of « TemporalDateTimeString,
  // TemporalInstantString, TemporalMonthDayString, TemporalTimeString,
  // TemporalYearMonthString, TemporalZonedDateTimeString », do

  // a. If parseResult is not a Parse Node, set parseResult to
  // ParseText(StringToCodePoints(isoString), goal).
  std::optional<ParsedISO8601Result> parsed;
  if ((parsed =
           TemporalParser::ParseTemporalDateTimeString(isolate, iso_string))
          .has_value() ||
      (parsed = TemporalParser::ParseTemporalInstantString(isolate, iso_string))
          .has_value() ||
      (parsed =
           TemporalParser::ParseTemporalMonthDayString(isolate, iso_string))
          .has_value() ||
      (parsed = TemporalParser::ParseTemporalTimeString(isolate, iso_string))
          .has_value() ||
      (parsed =
           TemporalParser::ParseTemporalYearMonthString(isolate, iso_string))
          .has_value() ||
      (parsed = TemporalParser::ParseTemporalZonedDateTimeString(isolate,
                                                                 iso_string))
          .has_value()) {
    return ParseISODateTime(isolate, iso_string, *parsed);
  }

  // 3. If parseResult is not a Parse Node, throw a RangeError exception.
  THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                               Nothing<DateTimeRecordWithCalendar>());
}

Maybe<DateTimeRecordWithCalendar> ParseISODateTime(
    Isolate* isolate, Handle<String> iso_string,
    const ParsedISO8601Result& parsed) {
  TEMPORAL_ENTER_FUNC();

  DateTimeRecordWithCalendar result;
  // 6. Set yearMV to ! ToIntegerOrInfinity(year).
  result.date.year = parsed.date_year;
  // 7. If month is undefined, then
  if (parsed.date_month_is_undefined()) {
    // a. Set monthMV to 1.
    result.date.month = 1;
    // 8. Else,
  } else {
    // a. Set monthMV to ! ToIntegerOrInfinity(month).
    result.date.month = parsed.date_month;
  }

  // 9. If day is undefined, then
  if (parsed.date_day_is_undefined()) {
    // a. Set dayMV to 1.
    result.date.day = 1;
    // 10. Else,
  } else {
    // a. Set dayMV to ! ToIntegerOrInfinity(day).
    result.date.day = parsed.date_day;
  }
  // 11. Set hourMV to ! ToIntegerOrInfinity(hour).
  result.time.hour = parsed.time_hour_is_undefined() ? 0 : parsed.time_hour;
  // 12. Set minuteMV to ! ToIntegerOrInfinity(minute).
  result.time.minute =
      parsed.time_minute_is_undefined() ? 0 : parsed.time_minute;
  // 13. Set secondMV to ! ToIntegerOrInfinity(second).
  result.time.second =
      parsed.time_second_is_undefined() ? 0 : parsed.time_second;
  // 14. If secondMV is 60, then
  if (result.time.second == 60) {
    // a. Set secondMV to 59.
    result.time.second = 59;
  }
  // 15. If fSeconds is not empty, then
  if (!parsed.time_nanosecond_is_undefined()) {
    // a. Let fSecondsDigits be the substring of CodePointsToString(fSeconds)
    // from 1.
    //
    // b. Let fSecondsDigitsExtended be the string-concatenation of
    // fSecondsDigits and "000000000".
    //
    // c. Let millisecond be the substring of fSecondsDigitsExtended from 0 to
    // 3.
    //
    // d. Let microsecond be the substring of fSecondsDigitsExtended from 3 to
    // 6.
    //
    // e. Let nanosecond be the substring of fSecondsDigitsExtended from 6 to 9.
    //
    // f. Let millisecondMV be ! ToIntegerOrInfinity(millisecond).
    result.time.millisecond = parsed.time_nanosecond / 1000000;
    // g. Let microsecondMV be ! ToIntegerOrInfinity(microsecond).
    result.time.microsecond = (parsed.time_nanosecond / 1000) % 1000;
    // h. Let nanosecondMV be ! ToIntegerOrInfinity(nanosecond).
    result.time.nanosecond = (parsed.time_nanosecond % 1000);
    // 16. Else,
  } else {
    // a. Let millisecondMV be 0.
    result.time.millisecond = 0;
    // b. Let microsecondMV be 0.
    result.time.microsecond = 0;
    // c. Let nanosecondMV be 0.
    result.time.nanosecond = 0;
  }
  // 17. If ! IsValidISODate(yearMV, monthMV, dayMV) is false, throw a
  // RangeError exception.
  if (!IsValidISODate(isolate, result.date)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateTimeRecordWithCalendar>());
  }
  // 18. If ! IsValidTime(hourMV, minuteMV, secondMV, millisecondMV,
  // microsecondMV, nanosecond) is false, throw a RangeError exception.
  if (!IsValidTime(isolate, result.time)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateTimeRecordWithCalendar>());
  }

  // 19. Let timeZoneResult be the Record { [[Z]]: false, [[OffsetString]]:
  // undefined, [[Name]]: undefined }.
  result.time_zone = {false, isolate->factory()->undefined_value(),
                      isolate->factory()->undefined_value()};
  // 20. If parseResult contains a TimeZoneIdentifier Parse Node, then
  if (parsed.tzi_name_length != 0) {
    // a. Let name be the source text matched by the TimeZoneIdentifier Parse
    // Node contained within parseResult.
    //
    // b. Set timeZoneResult.[[Name]] to CodePointsToString(name).
    result.time_zone.name = isolate->factory()->NewSubString(
        iso_string, parsed.tzi_name_start,
        parsed.tzi_name_start + parsed.tzi_name_length);
  }
  // 21. If parseResult contains a UTCDesignator Parse Node, then
  if (parsed.utc_designator) {
    // a. Set timeZoneResult.[[Z]] to true.
    result.time_zone.z = true;
    // 22. Else,
  } else {
    // a. If parseResult contains a TimeZoneNumericUTCOffset Parse Node, then
    if (parsed.offset_string_length != 0) {
      // i. Let offset be the source text matched by the
      // TimeZoneNumericUTCOffset Parse Node contained within parseResult.
      // ii. Set timeZoneResult.[[OffsetString]] to CodePointsToString(offset).
      result.time_zone.offset_string = isolate->factory()->NewSubString(
          iso_string, parsed.offset_string_start,
          parsed.offset_string_start + parsed.offset_string_length);
    }
  }

  // 23. If calendar is empty, then
  if (parsed.calendar_name_length == 0) {
    // a. Let calendarVal be undefined.
    result.calendar = isolate->factory()->undefined_value();
    // 24. Else,
  } else {
    // a. Let calendarVal be CodePointsToString(calendar).
    result.calendar = isolate->factory()->NewSubString(
        iso_string, parsed.calendar_name_start,
        parsed.calendar_name_start + parsed.calendar_name_length);
  }
  // 24. Return the Record { [[Year]]: yearMV, [[Month]]: monthMV, [[Day]]:
  // dayMV, [[Hour]]: hourMV, [[Minute]]: minuteMV, [[Second]]: secondMV,
  // [[Millisecond]]: millisecondMV, [[Microsecond]]: microsecondMV,
  // [[Nanosecond]]: nanosecondMV, [[TimeZone]]: timeZoneResult,
  // [[Calendar]]: calendarVal, }.
  return Just(result);
}

// #sec-temporal-parsetemporaldatestring
Maybe<DateRecordWithCalendar> ParseTemporalDateString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let parts be ? ParseTemporalDateTimeString(isoString).
  // 2. Return the Record { [[Year]]: parts.[[Year]], [[Month]]:
  // parts.[[Month]], [[Day]]: parts.[[Day]], [[Calendar]]: parts.[[Calendar]]
  // }.
  DateTimeRecordWithCalendar record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record, ParseTemporalDateTimeString(isolate, iso_string),
      Nothing<DateRecordWithCalendar>());
  DateRecordWithCalendar result = {record.date, record.calendar};
  return Just(result);
}

// #sec-temporal-parsetemporaltimestring
Maybe<TimeRecordWithCalendar> ParseTemporalTimeString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: Type(isoString) is String.
  // 2. If isoString does not satisfy the syntax of a TemporalTimeString
  // (see 13.33), then
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalTimeString(isolate, iso_string);
  if (!parsed.has_value()) {
    // a. Throw a *RangeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<TimeRecordWithCalendar>());
  }

  // 3. If _isoString_ contains a |UTCDesignator|, then
  if (parsed->utc_designator) {
    // a. Throw a *RangeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<TimeRecordWithCalendar>());
  }

  // 3. Let result be ? ParseISODateTime(isoString).
  DateTimeRecordWithCalendar result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseISODateTime(isolate, iso_string, *parsed),
      Nothing<TimeRecordWithCalendar>());
  // 4. Return the Record { [[Hour]]: result.[[Hour]], [[Minute]]:
  // result.[[Minute]], [[Second]]: result.[[Second]], [[Millisecond]]:
  // result.[[Millisecond]], [[Microsecond]]: result.[[Microsecond]],
  // [[Nanosecond]]: result.[[Nanosecond]], [[Calendar]]: result.[[Calendar]] }.
  TimeRecordWithCalendar ret = {result.time, result.calendar};
  return Just(ret);
}

// #sec-temporal-parsetemporalinstantstring
Maybe<InstantRecord> ParseTemporalInstantString(Isolate* isolate,
                                                Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. If ParseText(StringToCodePoints(isoString), TemporalInstantString) is a
  // List of errors, throw a RangeError exception.
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalInstantString(isolate, iso_string);
  if (!parsed.has_value()) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<InstantRecord>());
  }

  // 2. Let result be ? ParseISODateTime(isoString).
  DateTimeRecordWithCalendar result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseISODateTime(isolate, iso_string, *parsed),
      Nothing<InstantRecord>());

  // 3. Let offsetString be result.[[TimeZone]].[[OffsetString]].
  Handle<Object> offset_string = result.time_zone.offset_string;

  // 4. If result.[[TimeZone]].[[Z]] is true, then
  if (result.time_zone.z) {
    // a. Set offsetString to "+00:00".
    offset_string = isolate->factory()->NewStringFromStaticChars("+00:00");
  }
  // 5. Assert: offsetString is not undefined.
  DCHECK(!IsUndefined(*offset_string));

  // 6. Return the new Record { [[Year]]: result.[[Year]],
  // [[Month]]: result.[[Month]], [[Day]]: result.[[Day]],
  // [[Hour]]: result.[[Hour]], [[Minute]]: result.[[Minute]],
  // [[Second]]: result.[[Second]],
  // [[Millisecond]]: result.[[Millisecond]],
  // [[Microsecond]]: result.[[Microsecond]],
  // [[Nanosecond]]: result.[[Nanosecond]],
  // [[TimeZoneOffsetString]]: offsetString }.
  InstantRecord record({result.date, result.time, offset_string});
  return Just(record);
}

// #sec-temporal-parsetemporalrelativetostring
Maybe<DateTimeRecordWithCalendar> ParseTemporalRelativeToString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. If ParseText(StringToCodePoints(isoString), TemporalDateTimeString) is a
  // List of errors, throw a RangeError exception.
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalDateTimeString(isolate, iso_string);
  if (!parsed.has_value()) {
    // a. Throw a *RangeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateTimeRecordWithCalendar>());
  }
  // 2. Returns ? ParseISODateTime(isoString).
  return ParseISODateTime(isolate, iso_string, *parsed);
}

// #sec-temporal-parsetemporalinstant
MaybeHandle<BigInt> ParseTemporalInstant(Isolate* isolate,
                                         Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: Type(isoString) is String.
  // 2. Let result be ? ParseTemporalInstantString(isoString).
  InstantRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseTemporalInstantString(isolate, iso_string),
      Handle<BigInt>());

  // 3. Let offsetString be result.[[TimeZoneOffsetString]].
  // 4. Assert: offsetString is not undefined.
  DCHECK(!IsUndefined(*result.offset_string));

  // 5. Let utc be ? GetEpoch
Prompt: 
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共25部分，请归纳一下它的功能

"""
dDecimalString(&builder, minutes, 2);

  // 10. Let s be ToZeroPaddedDecimalString(seconds, 2).
  // 11. If nanoseconds ≠ 0, then
  if (nanoseconds != 0) {
    // a. Let fraction be ToZeroPaddedDecimalString(nanoseconds, 9).
    // b. Set fraction to the longest possible substring of fraction starting at
    // position 0 and not ending with the code unit 0x0030 (DIGIT ZERO). c. Let
    // post be the string-concatenation of the code unit 0x003A (COLON), s, the
    // code unit 0x002E (FULL STOP), and fraction.
    builder.AppendCharacter(':');
    ToZeroPaddedDecimalString(&builder, seconds, 2);
    builder.AppendCharacter('.');
    int64_t divisor = 100000000;
    do {
      builder.AppendInt(static_cast<int>(nanoseconds / divisor));
      nanoseconds %= divisor;
      divisor /= 10;
    } while (nanoseconds > 0);
    // 11. Else if seconds ≠ 0, then
  } else if (seconds != 0) {
    // a. Let post be the string-concatenation of the code unit 0x003A (COLON)
    // and s.
    builder.AppendCharacter(':');
    ToZeroPaddedDecimalString(&builder, seconds, 2);
  }
  // 12. Return the string-concatenation of sign, h, the code unit 0x003A
  // (COLON), m, and post.
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

double RoundNumberToIncrement(Isolate* isolate, double x, double increment,
                              RoundingMode rounding_mode);

// #sec-temporal-formatisotimezoneoffsetstring
Handle<String> FormatISOTimeZoneOffsetString(Isolate* isolate,
                                             int64_t offset_nanoseconds) {
  IncrementalStringBuilder builder(isolate);
  // 1. Assert: offsetNanoseconds is an integer.
  // 2. Set offsetNanoseconds to ! RoundNumberToIncrement(offsetNanoseconds, 60
  // × 10^9, "halfExpand").
  offset_nanoseconds = RoundNumberToIncrement(
      isolate, offset_nanoseconds, 60000000000, RoundingMode::kHalfExpand);
  // 3. If offsetNanoseconds ≥ 0, let sign be "+"; otherwise, let sign be "-".
  builder.AppendCharacter((offset_nanoseconds >= 0) ? '+' : '-');
  // 4. Set offsetNanoseconds to abs(offsetNanoseconds).
  offset_nanoseconds = std::abs(offset_nanoseconds);
  // 5. Let minutes be offsetNanoseconds / (60 × 10^9) modulo 60.
  int32_t minutes = (offset_nanoseconds / 60000000000) % 60;
  // 6. Let hours be floor(offsetNanoseconds / (3600 × 10^9)).
  int32_t hours = offset_nanoseconds / 3600000000000;
  // 7. Let h be ToZeroPaddedDecimalString(hours, 2).
  ToZeroPaddedDecimalString(&builder, hours, 2);

  // 8. Let m be ToZeroPaddedDecimalString(minutes, 2).
  builder.AppendCharacter(':');
  ToZeroPaddedDecimalString(&builder, minutes, 2);
  // 9. Return the string-concatenation of sign, h, the code unit 0x003A
  // (COLON), and m.
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

int32_t DecimalLength(int32_t n) {
  int32_t i = 1;
  while (n >= 10) {
    n /= 10;
    i++;
  }
  return i;
}

// #sec-tozeropaddeddecimalstring
void ToZeroPaddedDecimalString(IncrementalStringBuilder* builder, int32_t n,
                               int32_t min_length) {
  for (int32_t pad = min_length - DecimalLength(n); pad > 0; pad--) {
    builder->AppendCharacter('0');
  }
  builder->AppendInt(n);
}

// #sec-temporal-padisoyear
void PadISOYear(IncrementalStringBuilder* builder, int32_t y) {
  // 1. Assert: y is an integer.
  // 2. If y ≥ 0 and y ≤ 9999, then
  if (y >= 0 && y <= 9999) {
    // a. Return ToZeroPaddedDecimalString(y, 4).
    ToZeroPaddedDecimalString(builder, y, 4);
    return;
  }
  // 3. If y > 0, let yearSign be "+"; otherwise, let yearSign be "-".
  if (y > 0) {
    builder->AppendCharacter('+');
  } else {
    builder->AppendCharacter('-');
  }
  // 4. Let year be ToZeroPaddedDecimalString(abs(y), 6).
  ToZeroPaddedDecimalString(builder, std::abs(y), 6);
  // 5. Return the string-concatenation of yearSign and year.
}

// #sec-temporal-formatcalendarannotation
Handle<String> FormatCalendarAnnotation(Isolate* isolate, Handle<String> id,
                                        ShowCalendar show_calendar) {
  // 1.Assert: showCalendar is "auto", "always", or "never".
  // 2. If showCalendar is "never", return the empty String.
  if (show_calendar == ShowCalendar::kNever) {
    return isolate->factory()->empty_string();
  }
  // 3. If showCalendar is "auto" and id is "iso8601", return the empty String.
  if (show_calendar == ShowCalendar::kAuto &&
      String::Equals(isolate, id, isolate->factory()->iso8601_string())) {
    return isolate->factory()->empty_string();
  }
  // 4. Return the string-concatenation of "[u-ca=", id, and "]".
  IncrementalStringBuilder builder(isolate);
  builder.AppendCStringLiteral("[u-ca=");
  builder.AppendString(id);
  builder.AppendCharacter(']');
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

// #sec-temporal-maybeformatcalendarannotation
MaybeHandle<String> MaybeFormatCalendarAnnotation(
    Isolate* isolate, Handle<JSReceiver> calendar_object,
    ShowCalendar show_calendar) {
  // 1. If showCalendar is "never", return the empty String.
  if (show_calendar == ShowCalendar::kNever) {
    return isolate->factory()->empty_string();
  }
  // 2. Let calendarID be ? ToString(calendarObject).
  Handle<String> calendar_id;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, calendar_id,
                             Object::ToString(isolate, calendar_object));
  // 3. Return FormatCalendarAnnotation(calendarID, showCalendar).
  return FormatCalendarAnnotation(isolate, calendar_id, show_calendar);
}

// #sec-temporal-temporaldatetostring
MaybeHandle<String> TemporalDateToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainDate> temporal_date,
    ShowCalendar show_calendar) {
  IncrementalStringBuilder builder(isolate);
  // 1. Assert: Type(temporalDate) is Object.
  // 2. Assert: temporalDate has an [[InitializedTemporalDate]] internal slot.
  // 3. Let year be ! PadISOYear(temporalDate.[[ISOYear]]).
  PadISOYear(&builder, temporal_date->iso_year());
  // 4. Let month be ToZeroPaddedDecimalString(temporalDate.[[ISOMonth]], 2).
  builder.AppendCharacter('-');
  ToZeroPaddedDecimalString(&builder, temporal_date->iso_month(), 2);
  // 5. Let day be ToZeroPaddedDecimalString(temporalDate.[[ISODay]], 2).
  builder.AppendCharacter('-');
  ToZeroPaddedDecimalString(&builder, temporal_date->iso_day(), 2);
  // 6. Let calendar be ?
  // MaybeFormatCalendarAnnotation(temporalDate.[[Calendar]], showCalendar).
  Handle<String> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      MaybeFormatCalendarAnnotation(
          isolate, handle(temporal_date->calendar(), isolate), show_calendar));

  // 7. Return the string-concatenation of year, the code unit 0x002D
  // (HYPHEN-MINUS), month, the code unit 0x002D (HYPHEN-MINUS), day, and
  // calendar.
  builder.AppendString(calendar);
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

// #sec-temporal-temporalmonthdaytostring
MaybeHandle<String> TemporalMonthDayToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainMonthDay> month_day,
    ShowCalendar show_calendar) {
  // 1. Assert: Type(monthDay) is Object.
  // 2. Assert: monthDay has an [[InitializedTemporalMonthDay]] internal slot.
  IncrementalStringBuilder builder(isolate);
  // 6. Let calendarID be ? ToString(monthDay.[[Calendar]]).
  Handle<String> calendar_id;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar_id,
      Object::ToString(isolate, handle(month_day->calendar(), isolate)));
  // 7. If showCalendar is "always" or if calendarID is not "iso8601", then
  if (show_calendar == ShowCalendar::kAlways ||
      !String::Equals(isolate, calendar_id,
                      isolate->factory()->iso8601_string())) {
    // a. Let year be ! PadISOYear(monthDay.[[ISOYear]]).
    PadISOYear(&builder, month_day->iso_year());
    // b. Set result to the string-concatenation of year, the code unit
    // 0x002D (HYPHEN-MINUS), and result.
    builder.AppendCharacter('-');
  }
  // 3. Let month be ToZeroPaddedDecimalString(monthDay.[[ISOMonth]], 2).
  ToZeroPaddedDecimalString(&builder, month_day->iso_month(), 2);
  // 5. Let result be the string-concatenation of month, the code unit 0x002D
  // (HYPHEN-MINUS), and day.
  builder.AppendCharacter('-');
  // 4. Let day be ToZeroPaddedDecimalString(monthDay.[[ISODay]], 2).
  ToZeroPaddedDecimalString(&builder, month_day->iso_day(), 2);
  // 8. Let calendarString be ! FormatCalendarAnnotation(calendarID,
  // showCalendar).
  DirectHandle<String> calendar_string =
      FormatCalendarAnnotation(isolate, calendar_id, show_calendar);
  // 9. Set result to the string-concatenation of result and calendarString.
  builder.AppendString(calendar_string);
  // 10. Return result.
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

// #sec-temporal-temporalyearmonthtostring
MaybeHandle<String> TemporalYearMonthToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainYearMonth> year_month,
    ShowCalendar show_calendar) {
  // 1. Assert: Type(yearMonth) is Object.
  // 2. Assert: yearMonth has an [[InitializedTemporalYearMonth]] internal slot.
  IncrementalStringBuilder builder(isolate);
  // 3. Let year be ! PadISOYear(yearMonth.[[ISOYear]]).
  PadISOYear(&builder, year_month->iso_year());
  // 4. Let month be ToZeroPaddedDecimalString(yearMonth.[[ISOMonth]], 2).
  // 5. Let result be the string-concatenation of year, the code unit 0x002D
  // (HYPHEN-MINUS), and month.
  builder.AppendCharacter('-');
  ToZeroPaddedDecimalString(&builder, year_month->iso_month(), 2);
  // 6. Let calendarID be ? ToString(yearMonth.[[Calendar]]).
  Handle<String> calendar_id;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar_id,
      Object::ToString(isolate, handle(year_month->calendar(), isolate)));
  // 7. If showCalendar is "always" or if *_calendarID_ is not *"iso8601", then
  if (show_calendar == ShowCalendar::kAlways ||
      !String::Equals(isolate, calendar_id,
                      isolate->factory()->iso8601_string())) {
    // a. Let day be ToZeroPaddedDecimalString(yearMonth.[[ISODay]], 2).
    // b. Set result to the string-concatenation of result, the code unit 0x002D
    // (HYPHEN-MINUS), and day.
    builder.AppendCharacter('-');
    ToZeroPaddedDecimalString(&builder, year_month->iso_day(), 2);
  }
  // 8. Let calendarString be ! FormatCalendarAnnotation(calendarID,
  // showCalendar).
  DirectHandle<String> calendar_string =
      FormatCalendarAnnotation(isolate, calendar_id, show_calendar);
  // 9. Set result to the string-concatenation of result and calendarString.
  builder.AppendString(calendar_string);
  // 10. Return result.
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

// #sec-temporal-builtintimezonegetoffsetstringfor
MaybeHandle<String> BuiltinTimeZoneGetOffsetStringFor(
    Isolate* isolate, Handle<JSReceiver> time_zone,
    Handle<JSTemporalInstant> instant, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let offsetNanoseconds be ? GetOffsetNanosecondsFor(timeZone, instant).
  int64_t offset_nanoseconds;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_nanoseconds,
      GetOffsetNanosecondsFor(isolate, time_zone, instant, method_name),
      Handle<String>());

  // 2. Return ! FormatTimeZoneOffsetString(offsetNanoseconds).
  return FormatTimeZoneOffsetString(isolate, offset_nanoseconds);
}

// #sec-temporal-parseisodatetime
Maybe<DateTimeRecordWithCalendar> ParseISODateTime(
    Isolate* isolate, Handle<String> iso_string,
    const ParsedISO8601Result& parsed);
// Note: We split ParseISODateTime to two function because the spec text
// repeates some parsing unnecessary. If a function is calling ParseISODateTime
// from a AO which already call ParseText() for TemporalDateTimeString,
// TemporalInstantString, TemporalMonthDayString, TemporalTimeString,
// TemporalYearMonthString, TemporalZonedDateTimeString. But for the usage in
// ParseTemporalTimeZoneString, we use the following version.
Maybe<DateTimeRecordWithCalendar> ParseISODateTime(Isolate* isolate,
                                                   Handle<String> iso_string) {
  // 2. For each nonterminal goal of « TemporalDateTimeString,
  // TemporalInstantString, TemporalMonthDayString, TemporalTimeString,
  // TemporalYearMonthString, TemporalZonedDateTimeString », do

  // a. If parseResult is not a Parse Node, set parseResult to
  // ParseText(StringToCodePoints(isoString), goal).
  std::optional<ParsedISO8601Result> parsed;
  if ((parsed =
           TemporalParser::ParseTemporalDateTimeString(isolate, iso_string))
          .has_value() ||
      (parsed = TemporalParser::ParseTemporalInstantString(isolate, iso_string))
          .has_value() ||
      (parsed =
           TemporalParser::ParseTemporalMonthDayString(isolate, iso_string))
          .has_value() ||
      (parsed = TemporalParser::ParseTemporalTimeString(isolate, iso_string))
          .has_value() ||
      (parsed =
           TemporalParser::ParseTemporalYearMonthString(isolate, iso_string))
          .has_value() ||
      (parsed = TemporalParser::ParseTemporalZonedDateTimeString(isolate,
                                                                 iso_string))
          .has_value()) {
    return ParseISODateTime(isolate, iso_string, *parsed);
  }

  // 3. If parseResult is not a Parse Node, throw a RangeError exception.
  THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                               Nothing<DateTimeRecordWithCalendar>());
}

Maybe<DateTimeRecordWithCalendar> ParseISODateTime(
    Isolate* isolate, Handle<String> iso_string,
    const ParsedISO8601Result& parsed) {
  TEMPORAL_ENTER_FUNC();

  DateTimeRecordWithCalendar result;
  // 6. Set yearMV to ! ToIntegerOrInfinity(year).
  result.date.year = parsed.date_year;
  // 7. If month is undefined, then
  if (parsed.date_month_is_undefined()) {
    // a. Set monthMV to 1.
    result.date.month = 1;
    // 8. Else,
  } else {
    // a. Set monthMV to ! ToIntegerOrInfinity(month).
    result.date.month = parsed.date_month;
  }

  // 9. If day is undefined, then
  if (parsed.date_day_is_undefined()) {
    // a. Set dayMV to 1.
    result.date.day = 1;
    // 10. Else,
  } else {
    // a. Set dayMV to ! ToIntegerOrInfinity(day).
    result.date.day = parsed.date_day;
  }
  // 11. Set hourMV to ! ToIntegerOrInfinity(hour).
  result.time.hour = parsed.time_hour_is_undefined() ? 0 : parsed.time_hour;
  // 12. Set minuteMV to ! ToIntegerOrInfinity(minute).
  result.time.minute =
      parsed.time_minute_is_undefined() ? 0 : parsed.time_minute;
  // 13. Set secondMV to ! ToIntegerOrInfinity(second).
  result.time.second =
      parsed.time_second_is_undefined() ? 0 : parsed.time_second;
  // 14. If secondMV is 60, then
  if (result.time.second == 60) {
    // a. Set secondMV to 59.
    result.time.second = 59;
  }
  // 15. If fSeconds is not empty, then
  if (!parsed.time_nanosecond_is_undefined()) {
    // a. Let fSecondsDigits be the substring of CodePointsToString(fSeconds)
    // from 1.
    //
    // b. Let fSecondsDigitsExtended be the string-concatenation of
    // fSecondsDigits and "000000000".
    //
    // c. Let millisecond be the substring of fSecondsDigitsExtended from 0 to
    // 3.
    //
    // d. Let microsecond be the substring of fSecondsDigitsExtended from 3 to
    // 6.
    //
    // e. Let nanosecond be the substring of fSecondsDigitsExtended from 6 to 9.
    //
    // f. Let millisecondMV be ! ToIntegerOrInfinity(millisecond).
    result.time.millisecond = parsed.time_nanosecond / 1000000;
    // g. Let microsecondMV be ! ToIntegerOrInfinity(microsecond).
    result.time.microsecond = (parsed.time_nanosecond / 1000) % 1000;
    // h. Let nanosecondMV be ! ToIntegerOrInfinity(nanosecond).
    result.time.nanosecond = (parsed.time_nanosecond % 1000);
    // 16. Else,
  } else {
    // a. Let millisecondMV be 0.
    result.time.millisecond = 0;
    // b. Let microsecondMV be 0.
    result.time.microsecond = 0;
    // c. Let nanosecondMV be 0.
    result.time.nanosecond = 0;
  }
  // 17. If ! IsValidISODate(yearMV, monthMV, dayMV) is false, throw a
  // RangeError exception.
  if (!IsValidISODate(isolate, result.date)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateTimeRecordWithCalendar>());
  }
  // 18. If ! IsValidTime(hourMV, minuteMV, secondMV, millisecondMV,
  // microsecondMV, nanosecond) is false, throw a RangeError exception.
  if (!IsValidTime(isolate, result.time)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateTimeRecordWithCalendar>());
  }

  // 19. Let timeZoneResult be the Record { [[Z]]: false, [[OffsetString]]:
  // undefined, [[Name]]: undefined }.
  result.time_zone = {false, isolate->factory()->undefined_value(),
                      isolate->factory()->undefined_value()};
  // 20. If parseResult contains a TimeZoneIdentifier Parse Node, then
  if (parsed.tzi_name_length != 0) {
    // a. Let name be the source text matched by the TimeZoneIdentifier Parse
    // Node contained within parseResult.
    //
    // b. Set timeZoneResult.[[Name]] to CodePointsToString(name).
    result.time_zone.name = isolate->factory()->NewSubString(
        iso_string, parsed.tzi_name_start,
        parsed.tzi_name_start + parsed.tzi_name_length);
  }
  // 21. If parseResult contains a UTCDesignator Parse Node, then
  if (parsed.utc_designator) {
    // a. Set timeZoneResult.[[Z]] to true.
    result.time_zone.z = true;
    // 22. Else,
  } else {
    // a. If parseResult contains a TimeZoneNumericUTCOffset Parse Node, then
    if (parsed.offset_string_length != 0) {
      // i. Let offset be the source text matched by the
      // TimeZoneNumericUTCOffset Parse Node contained within parseResult.
      // ii. Set timeZoneResult.[[OffsetString]] to CodePointsToString(offset).
      result.time_zone.offset_string = isolate->factory()->NewSubString(
          iso_string, parsed.offset_string_start,
          parsed.offset_string_start + parsed.offset_string_length);
    }
  }

  // 23. If calendar is empty, then
  if (parsed.calendar_name_length == 0) {
    // a. Let calendarVal be undefined.
    result.calendar = isolate->factory()->undefined_value();
    // 24. Else,
  } else {
    // a. Let calendarVal be CodePointsToString(calendar).
    result.calendar = isolate->factory()->NewSubString(
        iso_string, parsed.calendar_name_start,
        parsed.calendar_name_start + parsed.calendar_name_length);
  }
  // 24. Return the Record { [[Year]]: yearMV, [[Month]]: monthMV, [[Day]]:
  // dayMV, [[Hour]]: hourMV, [[Minute]]: minuteMV, [[Second]]: secondMV,
  // [[Millisecond]]: millisecondMV, [[Microsecond]]: microsecondMV,
  // [[Nanosecond]]: nanosecondMV, [[TimeZone]]: timeZoneResult,
  // [[Calendar]]: calendarVal, }.
  return Just(result);
}

// #sec-temporal-parsetemporaldatestring
Maybe<DateRecordWithCalendar> ParseTemporalDateString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let parts be ? ParseTemporalDateTimeString(isoString).
  // 2. Return the Record { [[Year]]: parts.[[Year]], [[Month]]:
  // parts.[[Month]], [[Day]]: parts.[[Day]], [[Calendar]]: parts.[[Calendar]]
  // }.
  DateTimeRecordWithCalendar record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record, ParseTemporalDateTimeString(isolate, iso_string),
      Nothing<DateRecordWithCalendar>());
  DateRecordWithCalendar result = {record.date, record.calendar};
  return Just(result);
}

// #sec-temporal-parsetemporaltimestring
Maybe<TimeRecordWithCalendar> ParseTemporalTimeString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: Type(isoString) is String.
  // 2. If isoString does not satisfy the syntax of a TemporalTimeString
  // (see 13.33), then
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalTimeString(isolate, iso_string);
  if (!parsed.has_value()) {
    // a. Throw a *RangeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<TimeRecordWithCalendar>());
  }

  // 3. If _isoString_ contains a |UTCDesignator|, then
  if (parsed->utc_designator) {
    // a. Throw a *RangeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<TimeRecordWithCalendar>());
  }

  // 3. Let result be ? ParseISODateTime(isoString).
  DateTimeRecordWithCalendar result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseISODateTime(isolate, iso_string, *parsed),
      Nothing<TimeRecordWithCalendar>());
  // 4. Return the Record { [[Hour]]: result.[[Hour]], [[Minute]]:
  // result.[[Minute]], [[Second]]: result.[[Second]], [[Millisecond]]:
  // result.[[Millisecond]], [[Microsecond]]: result.[[Microsecond]],
  // [[Nanosecond]]: result.[[Nanosecond]], [[Calendar]]: result.[[Calendar]] }.
  TimeRecordWithCalendar ret = {result.time, result.calendar};
  return Just(ret);
}

// #sec-temporal-parsetemporalinstantstring
Maybe<InstantRecord> ParseTemporalInstantString(Isolate* isolate,
                                                Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. If ParseText(StringToCodePoints(isoString), TemporalInstantString) is a
  // List of errors, throw a RangeError exception.
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalInstantString(isolate, iso_string);
  if (!parsed.has_value()) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<InstantRecord>());
  }

  // 2. Let result be ? ParseISODateTime(isoString).
  DateTimeRecordWithCalendar result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseISODateTime(isolate, iso_string, *parsed),
      Nothing<InstantRecord>());

  // 3. Let offsetString be result.[[TimeZone]].[[OffsetString]].
  Handle<Object> offset_string = result.time_zone.offset_string;

  // 4. If result.[[TimeZone]].[[Z]] is true, then
  if (result.time_zone.z) {
    // a. Set offsetString to "+00:00".
    offset_string = isolate->factory()->NewStringFromStaticChars("+00:00");
  }
  // 5. Assert: offsetString is not undefined.
  DCHECK(!IsUndefined(*offset_string));

  // 6. Return the new Record { [[Year]]: result.[[Year]],
  // [[Month]]: result.[[Month]], [[Day]]: result.[[Day]],
  // [[Hour]]: result.[[Hour]], [[Minute]]: result.[[Minute]],
  // [[Second]]: result.[[Second]],
  // [[Millisecond]]: result.[[Millisecond]],
  // [[Microsecond]]: result.[[Microsecond]],
  // [[Nanosecond]]: result.[[Nanosecond]],
  // [[TimeZoneOffsetString]]: offsetString }.
  InstantRecord record({result.date, result.time, offset_string});
  return Just(record);
}

// #sec-temporal-parsetemporalrelativetostring
Maybe<DateTimeRecordWithCalendar> ParseTemporalRelativeToString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. If ParseText(StringToCodePoints(isoString), TemporalDateTimeString) is a
  // List of errors, throw a RangeError exception.
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalDateTimeString(isolate, iso_string);
  if (!parsed.has_value()) {
    // a. Throw a *RangeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateTimeRecordWithCalendar>());
  }
  // 2. Returns ? ParseISODateTime(isoString).
  return ParseISODateTime(isolate, iso_string, *parsed);
}

// #sec-temporal-parsetemporalinstant
MaybeHandle<BigInt> ParseTemporalInstant(Isolate* isolate,
                                         Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: Type(isoString) is String.
  // 2. Let result be ? ParseTemporalInstantString(isoString).
  InstantRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseTemporalInstantString(isolate, iso_string),
      Handle<BigInt>());

  // 3. Let offsetString be result.[[TimeZoneOffsetString]].
  // 4. Assert: offsetString is not undefined.
  DCHECK(!IsUndefined(*result.offset_string));

  // 5. Let utc be ? GetEpochFromISOParts(result.[[Year]], result.[[Month]],
  // result.[[Day]], result.[[Hour]], result.[[Minute]], result.[[Second]],
  // result.[[Millisecond]], result.[[Microsecond]], result.[[Nanosecond]]).
  Handle<BigInt> utc =
      GetEpochFromISOParts(isolate, {result.date, result.time});

  // 6. Let offsetNanoseconds be ? ParseTimeZoneOffsetString(offsetString).
  int64_t offset_nanoseconds;
  DCHECK(IsString(*result.offset_string));
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_nanoseconds,
      ParseTimeZoneOffsetString(isolate, Cast<String>(result.offset_string)),
      Handle<BigInt>());

  // 7. Let result be utc - ℤ(offsetNanoseconds).
  Handle<BigInt> result_value =
      BigInt::Subtract(isolate, utc,
                       BigInt::FromInt64(isolate, offset_nanoseconds))
          .ToHandleChecked();
  // 8. If ! IsValidEpochNanoseconds(result) is false, then
  if (!IsValidEpochNanoseconds(isolate, result_value)) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 9. Return result.
  return result_value;
}

// #sec-temporal-parsetemporalzoneddatetimestring
Maybe<DateTimeRecordWithCalendar> ParseTemporalZonedDateTimeString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();
  // 1. If ParseText(StringToCodePoints(isoString), TemporalZonedDateTimeString)
  // is a List of errors, throw a RangeError exception.
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalZonedDateTimeString(isolate, iso_string);
  if (!parsed.has_value()) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateTimeRecordWithCalendar>());
  }

  // 2. Return ? ParseISODateTime(isoString).
  return ParseISODateTime(isolate, iso_string, *parsed);
}

// #sec-temporal-createdurationrecord
Maybe<DurationRecord> CreateDurationRecord(Isolate* isolate,
                                           const DurationRecord& duration) {
  //   1. If ! IsValidDuration(years, months, weeks, days, hours, minutes,
  //   seconds, milliseconds, microseconds, nanoseconds) is false, throw a
  //   RangeError exception.
  if (!IsValidDuration(isolate, duration)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DurationRecord>());
  }
  // 2. Return the Record { [[Years]]: ℝ(𝔽(years)), [[Months]]: ℝ(𝔽(months)),
  // [[Weeks]]: ℝ(𝔽(weeks)), [[Days]]: ℝ(𝔽(days)), [[Hours]]: ℝ(𝔽(hours)),
  // [[Minutes]]: ℝ(𝔽(minutes)), [[Seconds]]: ℝ(𝔽(seconds)), [[Milliseconds]]:
  // ℝ(𝔽(milliseconds)), [[Microseconds]]: ℝ(𝔽(microseconds)), [[Nanoseconds]]:
  // ℝ(𝔽(nanoseconds)) }.
  return Just(duration);
}

inline double IfEmptyReturnZero(double value) {
  return value == ParsedISO8601Duration::kEmpty ? 0 : value;
}

// #sec-temporal-parsetemporaldurationstring
Maybe<DurationRecord> ParseTemporalDurationString(Isolate* isolate,
                                                  Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();
  // In this funciton, we use 'double' as type for all mathematical values
  // because in
  // https://tc39.es/proposal-temporal/#sec-properties-of-temporal-duration-instances
  // they are "A float64-representable integer representing the number" in the
  // internal slots.
  // 1. Let duration be ParseText(StringToCodePoints(isoString),
  // TemporalDurationString).
  // 2. If duration is a List of errors, throw a RangeError exception.
  // 3. Let each of sign, years, months, weeks, days, hours, fHours, minutes,
  // fMinutes, seconds, and fSeconds be the source text matched by the
  // respective Sign, DurationYears, DurationMonths, DurationWeeks,
  // DurationDays, DurationWholeHours, DurationHoursFraction,
  // DurationWholeMinutes, DurationMinutesFraction, DurationWholeSeconds, and
  // DurationSecondsFraction Parse Node enclosed by duration, or an empty
  // sequence of code points if not present.
  std::optional<ParsedISO8601Duration> parsed =
      TemporalParser::ParseTemporalDurationString(isolate, iso_string);
  if (!parsed.has_value()) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DurationRecord>());
  }
  // 4. Let yearsMV be ! ToIntegerOrInfinity(CodePointsToString(years)).
  double years_mv = IfEmptyReturnZero(parsed->years);
  // 5. Let monthsMV be ! ToIntegerOrInfinity(CodePointsToString(months)).
  double months_mv = IfEmptyReturnZero(parsed->months);
  // 6. Let weeksMV be ! ToIntegerOrInfinity(CodePointsToString(weeks)).
  double weeks_mv = IfEmptyReturnZero(parsed->weeks);
  // 7. Let daysMV be ! ToIntegerOrInfinity(CodePointsToString(days)).
  double days_mv = IfEmptyReturnZero(parsed->days);
  // 8. Let hoursMV be ! ToIntegerOrInfinity(CodePointsToString(hours)).
  double hours_mv = IfEmptyReturnZero(parsed->whole_hours);
  // 9. If fHours is not empty, then
  double minutes_mv;
  if (parsed->hours_fraction != ParsedISO8601Duration::kEmpty) {
    // a. If any of minutes, fMinutes, seconds, fSeconds is not empty, throw a
    // RangeError exception.
    if (parsed->whole_minutes != ParsedISO8601Duration::kEmpty ||
        parsed->minutes_fraction != ParsedISO8601Duration::kEmpty ||
        parsed->whole_seconds != ParsedISO8601Duration::kEmpty ||
        parsed->seconds_fraction != ParsedISO8601Duration::kEmpty) {
      THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                   NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                   Nothing<DurationRecord>());
    }
    // b. Let fHoursDigits be the substring of CodePointsToString(fHours)
    // from 1.
    //
    // c. Let fHoursScale be the length of fHoursDigits.
    //
    // d. Let
    // minutesMV be ! ToIntegerOrInfinity(fHoursDigits) / 10^fHoursScale × 60.
    minutes_mv = IfEmptyReturnZero(parsed->hours_fraction) * 60.0 / 1e9;
    // 10. Else,
  } else {
    // a. Let minutesMV be ! ToIntegerOrInfinity(CodePointsToString(minutes)).
    minutes_mv = IfEmptyReturnZero(parsed->whole_minutes);
  }
  double seconds_mv;
  // 11. If fMinutes is not empty, then
  if (parsed->minutes_fraction != ParsedISO8601Duration::kEmpty) {
    // a. If any of seconds, fSeconds is not empty, throw a RangeError
    // exception.
    if (parsed->whole_seconds != ParsedISO8601Duration::kEmpty ||
        parsed->seconds_fraction != ParsedISO8601Duration::kEmpty) {
      THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                   NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                   Nothing<DurationRecord>());
    }
    // b. Let fMinutesDigits be the substring of CodePointsToString(fMinutes)
    // from 1.
    //
    // c. Let fMinutesScale be the length of fMinutesDigits.
    //
    // d. Let secondsMV be ! ToIntegerOrInfinity(fMinutesDigits) /
    // 10^fMinutesScale × 60.
    seconds_mv = IfEmptyReturnZero(parsed->minutes_fraction) * 60.0 / 1e9;
    // 12. Else if seconds is not empty, then
  } else if (parsed->whole_seconds != ParsedISO8601Duration::kEmpty) {
    // a. Let secondsMV be ! ToIntegerOrInfinity(CodePointsToString(seconds)).
    seconds_mv = parsed->whole_seconds;
    // 13. Else,
  } else {
    // a. Let secondsMV be remainder(minutesMV, 1) × 60.
    seconds_mv = (minutes_mv - std::floor(minutes_mv)) * 60.0;
  }
  double milliseconds_mv, microseconds_mv, nanoseconds_mv;
  // Note: In step 14-17, we calculate from nanoseconds_mv to miilliseconds_mv
  // in the reversee order of the spec text to avoid numerical errors would be
  // introduced by multiple division inside the remainder operations. If we
  // strickly follow the order by using double, the end result of nanoseconds_mv
  // will be wrong due to numerical errors.
  //
  // 14. If fSeconds is not empty, then
  if (parsed->seconds_fraction != ParsedISO8601Duration::kEmpty) {
    // a. Let fSecondsDigits be the substring of CodePointsToString(fSeco
"""


```