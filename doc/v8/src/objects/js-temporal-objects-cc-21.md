Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/objects/js-temporal-objects.cc`. I need to analyze the code and explain its purpose, relating it to JavaScript's Temporal API if applicable. I should also address the specific instructions about `.tq` files, JavaScript examples, code logic inference, common programming errors, and finally, provide a summary of the functionality for this specific part (part 22 of 25).

**Plan:**

1. **Identify Core Functionalities:**  Scan the code for function definitions and their roles within the Temporal API context. Look for patterns like object construction, comparison, formatting, and manipulation.
2. **Relate to JavaScript Temporal API:** For each identified functionality, connect it to the corresponding JavaScript `Temporal` object or method (e.g., `Temporal.PlainTime.prototype.toString`, `Temporal.ZonedDateTime`).
3. **Illustrate with JavaScript Examples:**  Provide simple JavaScript code snippets demonstrating how the C++ code is used indirectly when interacting with the Temporal API.
4. **Infer Code Logic:** For functions like `CompareEpochNanoseconds` and `InterpretISODateTimeOffset`, deduce the input and output based on their purpose and the surrounding code.
5. **Identify Potential Errors:** Based on the function names and logic (e.g., `ToTemporalZonedDateTime`, handling of offsets and time zones), pinpoint common mistakes users might make.
6. **Address `.tq` Files:** Explain the meaning of `.tq` and its relevance (or irrelevance in this case).
7. **Summarize Functionality:** Concisely describe the overall purpose of the provided code segment within the larger context of the `js-temporal-objects.cc` file.
```c++
StringPrecision({Precision::k9, Unit::kNanosecond, 1}));
    default:
      UNREACHABLE();
  }
}

// #sec-temporal-compareepochnanoseconds
MaybeHandle<Smi> CompareEpochNanoseconds(Isolate* isolate,
                                         DirectHandle<BigInt> one,
                                         DirectHandle<BigInt> two) {
  TEMPORAL_ENTER_FUNC();

  // 1. If epochNanosecondsOne > epochNanosecondsTwo, return 1.
  // 2. If epochNanosecondsOne < epochNanosecondsTwo, return -1.
  // 3. Return 0.
  return handle(
      Smi::FromInt(CompareResultToSign(BigInt::CompareToBigInt(one, two))),
      isolate);
}

}  // namespace

// #sec-temporal.plaintime.prototype.tostring
MaybeHandle<String> JSTemporalPlainTime::ToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainTime.prototype.toString";
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalTime,
  // [[InitializedTemporalTime]]).
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

  // 6. Let roundResult be ! RoundTime(temporalTime.[[ISOHour]],
  // temporalTime.[[ISOMinute]], temporalTime.[[ISOSecond]],
  // temporalTime.[[ISOMillisecond]], temporalTime.[[ISOMicrosecond]],
  // temporalTime.[[ISONanosecond]], precision.[[Increment]],
  // precision.[[Unit]], roundingMode).

  DateTimeRecord round_result = RoundTime(
      isolate,
      {temporal_time->iso_hour(), temporal_time->iso_minute(),
       temporal_time->iso_second(), temporal_time->iso_millisecond(),
       temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()},
      precision.increment, precision.unit, rounding_mode);
  // 7. Return ! TemporalTimeToString(roundResult.[[Hour]],
  // roundResult.[[Minute]], roundResult.[[Second]],
  // roundResult.[[Millisecond]], roundResult.[[Microsecond]],
  // roundResult.[[Nanosecond]], precision.[[Precision]]).
  return TemporalTimeToString(isolate, round_result.time, precision.precision);
}

// #sec-temporal.zoneddatetime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> epoch_nanoseconds_obj, Handle<Object> time_zone_like,
    Handle<Object> calendar_like) {
  const char* method_name = "Temporal.ZonedDateTime";
  // 1. If NewTarget is undefined, then
  if (IsUndefined(*new_target)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }
  // 2. Set epochNanoseconds to ? ToBigInt(epochNanoseconds).
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      BigInt::FromObject(isolate, epoch_nanoseconds_obj));
  // 3. If ! IsValidEpochNanoseconds(epochNanoseconds) is false, throw a
  // RangeError exception.
  if (!IsValidEpochNanoseconds(isolate, epoch_nanoseconds)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }

  // 4. Let timeZone be ? ToTemporalTimeZone(timeZoneLike).
  Handle<JSReceiver> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      temporal::ToTemporalTimeZone(isolate, time_zone_like, method_name));

  // 5. Let calendar be ? ToTemporalCalendarWithISODefault(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ToTemporalCalendarWithISODefault(isolate, calendar_like, method_name));

  // 6. Return ? CreateTemporalZonedDateTime(epochNanoseconds, timeZone,
  // calendar, NewTarget).
  return CreateTemporalZonedDateTime(isolate, target, new_target,
                                     epoch_nanoseconds, time_zone, calendar);
}

// #sec-get-temporal.zoneddatetime.prototype.hoursinday
MaybeHandle<Object> JSTemporalZonedDateTime::HoursInDay(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.hoursInDay";
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

  // 5. Let isoCalendar be ! GetISO8601Calendar().
  DirectHandle<JSReceiver> iso_calendar = temporal::GetISO8601Calendar(isolate);

  // 6. Let temporalDateTime be ? BuiltinTimeZoneGetPlainDateTimeFor(timeZone,
  // instant, isoCalendar).
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   iso_calendar, method_name));
  // 7. Let year be temporalDateTime.[[ISOYear]].
  // 8. Let month be temporalDateTime.[[ISOMonth]].
  // 9. Let day be temporalDateTime.[[ISODay]].
  // 10. Let today be ? CreateTemporalDateTime(year, month, day, 0, 0, 0, 0, 0,
  // 0, isoCalendar).
  Handle<JSTemporalPlainDateTime> today;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, today,
      temporal::CreateTemporalDateTime(
          isolate,
          {{temporal_date_time->iso_year(), temporal_date_time->iso_month(),
            temporal_date_time->iso_day()},
           {0, 0, 0, 0, 0, 0}},
          iso_calendar));
  // 11. Let tomorrowFields be BalanceISODate(year, month, day + 1).
  DateRecord tomorrow_fields = BalanceISODate(
      isolate, {temporal_date_time->iso_year(), temporal_date_time->iso_month(),
                temporal_date_time->iso_day() + 1});

  // 12. Let tomorrow be ? CreateTemporalDateTime(tomorrowFields.[[Year]],
  // tomorrowFields.[[Month]], tomorrowFields.[[Day]], 0, 0, 0, 0, 0, 0,
  // isoCalendar).
  Handle<JSTemporalPlainDateTime> tomorrow;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, tomorrow,
      temporal::CreateTemporalDateTime(
          isolate, {tomorrow_fields, {0, 0, 0, 0, 0, 0}}, iso_calendar));
  // 13. Let todayInstant be ? BuiltinTimeZoneGetInstantFor(timeZone, today,
  // "compatible").
  Handle<JSTemporalInstant> today_instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, today_instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, today,
                                   Disambiguation::kCompatible, method_name));
  // 14. Let tomorrowInstant be ? BuiltinTimeZoneGetInstantFor(timeZone,
  // tomorrow, "compatible").
  Handle<JSTemporalInstant> tomorrow_instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, tomorrow_instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, tomorrow,
                                   Disambiguation::kCompatible, method_name));
  // 15. Let diffNs be tomorrowInstant.[[Nanoseconds]] −
  // todayInstant.[[Nanoseconds]].
  Handle<BigInt> diff_ns =
      BigInt::Subtract(isolate,
                       handle(tomorrow_instant->nanoseconds(), isolate),
                       handle(today_instant->nanoseconds(), isolate))
          .ToHandleChecked();
  // 16. Return 𝔽(diffNs / (3.6 × 10^12)).
  //
  // Note: The result of the division may be non integer for TimeZone which
  // change fractional hours. Perform this division in two steps:
  // First convert it to seconds in BigInt, then perform floating point
  // division (seconds / 3600) to convert to hours.
  int64_t diff_seconds =
      BigInt::Divide(isolate, diff_ns, BigInt::FromUint64(isolate, 1000000000))
          .ToHandleChecked()
          ->AsInt64();
  double hours_in_that_day = static_cast<double>(diff_seconds) / 3600.0;
  return isolate->factory()->NewNumber(hours_in_that_day);
}

namespace {

// #sec-temporal-totemporalzoneddatetime
MaybeHandle<JSTemporalZonedDateTime> ToTemporalZonedDateTime(
    Isolate* isolate, Handle<Object> item_obj, Handle<Object> options,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 2. Assert: Type(options) is Object or Undefined.
  DCHECK(IsUndefined(*options) || IsJSReceiver(*options));
  // 3. Let offsetBehaviour be option.
  OffsetBehaviour offset_behaviour = OffsetBehaviour::kOption;
  // 4. Let matchBehaviour be match exactly.
  MatchBehaviour match_behaviour = MatchBehaviour::kMatchExactly;

  Handle<Object> offset_string;
  Handle<JSReceiver> time_zone;
  Handle<JSReceiver> calendar;

  temporal::DateTimeRecord result;

  // 5. If Type(item) is Object, then
  if (IsJSReceiver(*item_obj)) {
    Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
    // a. If item has an [[InitializedTemporalZonedDateTime]] internal slot,
    // then
    if (IsJSTemporalZonedDateTime(*item_obj)) {
      // i. Return item.
      return Cast<JSTemporalZonedDateTime>(item_obj);
    }
    // b. Let calendar be ? GetTemporalCalendarWithISODefault(item).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        GetTemporalCalendarWithISODefault(isolate, item, method_name));
    // c. Let fieldNames be ? CalendarFields(calendar, « "day", "hour",
    // "microsecond", "millisecond", "minute", "month", "monthCode",
    // "nanosecond", "second", "year" »).
    Handle<FixedArray> field_names = All10UnitsInFixedArray(isolate);
    ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                               CalendarFields(isolate, calendar, field_names));

    // d. Append "timeZone" to fieldNames.
    int32_t field_length = field_names->length();
    field_names = FixedArray::SetAndGrow(isolate, field_names, field_length++,
                                         factory->timeZone_string());

    // e. Append "offset" to fieldNames.
    field_names = FixedArray::SetAndGrow(isolate, field_names, field_length++,
                                         factory->offset_string());
    field_names->RightTrim(isolate, field_length);

    // f. Let fields be ? PrepareTemporalFields(item, fieldNames, « "timeZone"
    // »).
    Handle<JSReceiver> fields;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, fields,
        PrepareTemporalFields(isolate, item, field_names,
                              RequiredFields::kTimeZone));

    // g. Let timeZone be ? Get(fields, "timeZone").
    Handle<Object> time_zone_obj;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone_obj,
        JSReceiver::GetProperty(isolate, fields, factory->timeZone_string()));

    // h. Set timeZone to ? ToTemporalTimeZone(timeZone).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone,
        temporal::ToTemporalTimeZone(isolate, time_zone_obj, method_name));
    // i. Let offsetString be ? Get(fields, "offset").
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, offset_string,
        JSReceiver::GetProperty(isolate, fields, factory->offset_string()));

    // j. If offsetString is undefined, then
    if (IsUndefined(*offset_string)) {
      // i. Set offsetBehaviour to wall.
      offset_behaviour = OffsetBehaviour::kWall;
      // k. Else,
    } else {
      // i. Set offsetString to ? ToString(offsetString).
      ASSIGN_RETURN_ON_EXCEPTION(isolate, offset_string,
                                 Object::ToString(isolate, offset_string));
    }

    // l. Let result be ? InterpretTemporalDateTimeFields(calendar, fields,
    // options).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        InterpretTemporalDateTimeFields(isolate, calendar, fields, options,
                                        method_name),
        Handle<JSTemporalZonedDateTime>());
    // 5. Else,
  } else {
    // a. Perform ? ToTemporalOverflow(options).
    MAYBE_RETURN_ON_EXCEPTION_VALUE(
        isolate, ToTemporalOverflow(isolate, options, method_name),
        Handle<JSTemporalZonedDateTime>());
    // b. Let string be ? ToString(item).
    Handle<String> string;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, string,
                               Object::ToString(isolate, item_obj));
    // c. Let result be ? ParseTemporalZonedDateTimeString(string).
    DateTimeRecordWithCalendar parsed_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, parsed_result,
        ParseTemporalZonedDateTimeString(isolate, string),
        Handle<JSTemporalZonedDateTime>());
    result = {parsed_result.date, parsed_result.time};

    // d. Let timeZoneName be result.[[TimeZone]].[[Name]].
    // e. Assert: timeZoneName is not undefined.
    DCHECK(!IsUndefined(*parsed_result.time_zone.name));
    Handle<String> time_zone_name = Cast<String>(parsed_result.time_zone.name);

    // f. If ParseText(StringToCodePoints(timeZoneName),
    // TimeZoneNumericUTCOffset) is a List of errors, then
    std::optional<ParsedISO8601Result> parsed =
        TemporalParser::ParseTimeZoneNumericUTCOffset(isolate, time_zone_name);
    if (!parsed.has_value()) {
      // i. If ! IsValidTimeZoneName(timeZoneName) is false, throw a RangeError
      // exception.
      if (!IsValidTimeZoneName(isolate, time_zone_name)) {
        THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                     NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                     Handle<JSTemporalZonedDateTime>());
      }
      // ii. Set timeZoneName to ! CanonicalizeTimeZoneName(timeZoneName).
      time_zone_name = CanonicalizeTimeZoneName(isolate, time_zone_name);
    }
    // g. Let offsetString be result.[[TimeZone]].[[OffsetString]].
    offset_string = parsed_result.time_zone.offset_string;

    // h. If result.[[TimeZone]].[[Z]] is true, then
    if (parsed_result.time_zone.z) {
      // i. Set offsetBehaviour to exact.
      offset_behaviour = OffsetBehaviour::kExact;
      // i. Else if offsetString is undefined, then
    } else if (IsUndefined(*offset_string)) {
      // i. Set offsetBehaviour to wall.
      offset_behaviour = OffsetBehaviour::kWall;
    }
    // j. Let timeZone be ! CreateTemporalTimeZone(timeZoneName).
    time_zone = temporal::CreateTemporalTimeZone(isolate, time_zone_name)
                    .ToHandleChecked();
    // k. Let calendar be ?
    // ToTemporalCalendarWithISODefault(result.[[Calendar]]).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        ToTemporalCalendarWithISODefault(isolate, parsed_result.calendar,
                                         method_name));
    // j. Set matchBehaviour to match minutes.
    match_behaviour = MatchBehaviour::kMatchMinutes;
  }
  // 7. Let offsetNanoseconds be 0.
  int64_t offset_nanoseconds = 0;

  // 6. If offsetBehaviour is option, then
  if (offset_behaviour == OffsetBehaviour::kOption) {
    // a. Set offsetNanoseconds to ? ParseTimeZoneOffsetString(offsetString).
    DCHECK(IsString(*offset_string));
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, offset_nanoseconds,
        ParseTimeZoneOffsetString(isolate, Cast<String>(offset_string)),
        Handle<JSTemporalZonedDateTime>());
  }

  // 7. Let disambiguation be ? ToTemporalDisambiguation(options).
  Disambiguation disambiguation;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, disambiguation,
      ToTemporalDisambiguation(isolate, options, method_name),
      Handle<JSTemporalZonedDateTime>());

  // 8. Let offset be ? ToTemporalOffset(options, "reject").
  enum Offset offset;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset,
      ToTemporalOffset(isolate, options, Offset::kReject, method_name),
      Handle<JSTemporalZonedDateTime>());

  // 9. Let epochNanoseconds be ? InterpretISODateTimeOffset(result.[[Year]],
  // result.[[Month]], result.[[Day]], result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]], offsetBehaviour, offsetNanoseconds, timeZone,
  // disambiguation, offset, matchBehaviour).
  //
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      InterpretISODateTimeOffset(isolate, result, offset_behaviour,
                                 offset_nanoseconds, time_zone, disambiguation,
                                 offset, match_behaviour, method_name));

  // 8. Return ? CreateTemporalZonedDateTime(epochNanoseconds, timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(isolate, epoch_nanoseconds, time_zone,
                                     calendar);
}

MaybeHandle<JSTemporalZonedDateTime> ToTemporalZonedDateTime(
    Isolate* isolate, Handle<Object> item_obj, const char* method_name) {
  // 1. If options is not present, set options to undefined.
  return ToTemporalZonedDateTime(
      isolate, item_obj, isolate->factory()->undefined_value(), method_name);
}

}  // namespace

// #sec-temporal.zoneddatetime.from
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::From(
    Isolate* isolate, Handle<Object> item, Handle<Object> options_obj) {
  const char* method_name = "Temporal.ZonedDateTime.from";
  // 1. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 2. If Type(item) is Object and item has an
  // [[InitializedTemporalZonedDateTime]] internal slot, then
  if (IsJSTemporalZonedDateTime(*item)) {
    // a. Perform ? ToTemporalOverflow(options).
    MAYBE_RETURN_ON_EXCEPTION_VALUE(
        isolate, ToTemporalOverflow(isolate, options, method_name),
        Handle<JSTemporalZonedDateTime>());

    // b. Perform ? ToTemporalDisambiguation(options).
    {
      Disambiguation disambiguation;
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, disambiguation,
          ToTemporalDisambiguation(isolate, options, method_name),
          Handle<JSTemporalZonedDateTime>());
      USE(disambiguation);
    }

    // c. Perform ? ToTemporalOffset(options, "reject").
    {
      enum Offset offset;
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, offset,
          ToTemporalOffset(isolate, options, Offset::kReject, method_name),
          Handle<JSTemporalZonedDateTime>());
      USE(offset);
    }

    // d. Return ? CreateTemporalZonedDateTime(item.[[Nanoseconds]],
    // item.[[TimeZone]], item.[[Calendar]]).
    auto zoned_date_time = Cast<JSTemporalZonedDateTime>(item);
    return CreateTemporalZonedDateTime(
        isolate, handle(zoned_date_time->nanoseconds(), isolate),
        handle(zoned_date_time->time_zone(), isolate),
        handle(zoned_date_time->calendar(), isolate));
  }
  // 3. Return ? ToTemporalZonedDateTime(item, options).
  return ToTemporalZonedDateTime(isolate, item, options, method_name);
}

// #sec-temporal.zoneddatetime.compare
MaybeHandle<Smi> JSTemporalZonedDateTime::Compare(Isolate* isolate,
                                                  Handle<Object> one_obj,
                                                  Handle<Object> two_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.compare";
  // 1. Set one to ? ToTemporalZonedDateTime(one).
  Handle<JSTemporalZonedDateTime> one;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, one, ToTemporalZonedDateTime(isolate, one_obj, method_name));
  // 2. Set two to ? ToTemporalZonedDateTime(two).
  Handle<JSTemporalZonedDateTime> two;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, two, ToTemporalZonedDateTime(isolate, two_obj, method_name));
  // 3. Return 𝔽(! CompareEpochNanoseconds(one.[[Nanoseconds]],
  // two.[[Nanoseconds]])).
  return CompareEpochNanoseconds(isolate, handle(one->nanoseconds(), isolate),
                                 handle(two->nanoseconds(), isolate));
}

namespace {

// #sec-temporal-timezoneequals
Maybe<bool> TimeZoneEquals(Isolate* isolate, Handle<JSReceiver> one,
                           Handle<JSReceiver> two) {
  // 1. If one and two are the same Object value, return true.
  if (one.is_identical_to(two)) {
    return Just(true);
  }

  // 2. Let timeZoneOne be ? ToString(one).
  Handle<String> time_zone_one;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, time_zone_one, Object::ToString(isolate, one), Nothing<bool>());
  // 3. Let timeZoneTwo be ? ToString(two).
  Handle<String> time_zone_two;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, time_zone_two, Object::ToString(isolate, two), Nothing<bool>());
  // 4. If timeZoneOne is timeZoneTwo, return true.
  if (String::Equals(isolate, time_zone_one, time_zone_two)) {
    return Just(true);
  }
  // 5. Return false.
  return Just(false);
}

}  // namespace

// #sec-temporal.zoneddatetime.prototype.equals
MaybeHandle<Oddball> JSTemporalZonedDateTime::Equals(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> other_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.equals";
  Factory* factory = isolate->factory();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Set other to ? ToTemporalZonedDateTime(other).
  Handle<JSTemporalZonedDateTime> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other, ToTemporalZonedDateTime(isolate, other_obj, method_name));
  // 4. If zonedDateTime.[[Nanoseconds]] ≠ other.[[Nanoseconds]], return false.
  if (!BigInt::EqualToBigInt(zoned_date_time->nanoseconds(),
                             other->nanoseconds())) {
    return factory->false_value();
  }
  // 5. If ? TimeZoneEquals(zonedDateTime.[[TimeZone]], other.[[TimeZone]]) is
  // false, return false.
  bool equals;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, equals,
      TimeZoneEquals(isolate, handle(zoned_date_time->time_zone(), isolate),
                     handle(other->time_zone(), isolate)),
      Handle<Oddball>());
  if (!equals) {
    return factory->false_value();
  }
  // 6. Return ? CalendarEquals(zonedDateTime.[[Calendar]], other.[[Calendar]]).
  return CalendarEquals(isolate, handle(zoned_date_time->calendar(), isolate),
                        handle(other->calendar(), isolate));
}

namespace {

// #sec-temporal-interpretisodatetimeoffset
MaybeHandle<BigInt> InterpretISODateTimeOffset(
    Isolate* isolate, const DateTimeRecord& data,
    OffsetBehaviour offset_behaviour, int64_t offset_nanoseconds,
    Handle<JSReceiver> time_zone, Disambiguation disambiguation,
    Offset offset_option, MatchBehaviour match_behaviour,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: offsetNanoseconds is an integer or undefined.
  // 2. Let calendar be ! GetISO8601Calendar().
  DirectHandle<JSReceiver> calendar = temporal::GetISO8601Calendar(isolate);

  // 3. Let dateTime be ? CreateTemporalDateTime(year, month, day, hour, minute,
  // second, millisecond, microsecond, nanosecond, calendar).
  Handle<JSTemporalPlainDateTime> date_time;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, date_time,
                             temporal::CreateTemporalDateTime(
                                 isolate, {data.date, data.time}, calendar));

  // 4. If offsetBehaviour is wall, or offsetOption is "ignore", then
  if (offset_behaviour == OffsetBehaviour::kWall ||
      offset_option == Offset::kIgnore) {
    // a. Let instant be ? BuiltinTimeZoneGetInstantFor(timeZone, dateTime,
    // disambiguation).
    Handle<JSTemporalInstant> instant;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, instant,
        BuiltinTimeZoneGetInstantFor(isolate, time_zone, date_time,
                                     disambiguation, method_name));
    // b. Return instant.[[Nanoseconds]].
    return handle(instant->nanoseconds(), isolate);
  }
  // 5. If offsetBehaviour is exact, or offsetOption is "use", then
  if (offset_behaviour == OffsetBehaviour::kExact ||
      offset_option == Offset::kUse) {
    // a. Let epochNanoseconds be ? GetEpochFromISOParts(year, month, day, hour,
    // minute, second, millisecond, microsecond, nanosecond).
    Handle<BigInt> epoch_nanoseconds =
        GetEpochFromISOParts(isolate, {data.date, data.time});

    // b. Set epochNanoseconds to epochNanoseconds - ℤ(offsetNanoseconds).
    epoch_nanoseconds =
        BigInt::Subtract(isolate, epoch_nanoseconds,
                         BigInt::FromInt64(isolate, offset_nanoseconds))
            .ToHandleChecked();
    // c. If ! IsValidEpochNanoseconds(epochNanoseconds) is false, throw a
    // RangeError exception.
    if (!IsValidEpochNanoseconds(isolate, epoch_nanoseconds)) {
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
    }
    // d. Return epochNanoseconds.
    return epoch_nanoseconds;
  }
  // 6. Assert: offsetBehaviour is option.
  DCHECK_EQ(offset_behaviour, OffsetBehaviour::kOption);
  // 7. Assert: offsetOption is "prefer" or "reject".
  DCHECK(offset_option == Offset::kPrefer || offset_option == Offset::kReject);
  // 8. Let possibleInstants be ? GetPossibleInstantsFor(timeZone, dateTime).
  Handle<FixedArray> possible_instants;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, possible_instants,
      GetPossibleInstantsFor(isolate, time_zone, date_time));

  // 9. For each element candidate of possibleInstants, do
  for (int i = 0; i < possible_instants->length(); i++) {
    DCHECK(IsJSTemporalInstant(possible_instants->get(i)));
    Handle<JSTemporalInstant> candidate(
        Cast<JSTemporalInstant>(possible_instants->get(i)), isolate);
    // a. Let candidateNanoseconds be ? GetOffsetNanosecondsFor(timeZone,
    // candidate).
    int64_t candidate_nanoseconds;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, candidate_nanoseconds,
        GetOffsetNanosecondsFor(isolate, time_zone, candidate, method_name),
        Handle<BigInt>());
    // b. If candidateNanoseconds = offsetNanoseconds, then
    if (candidate_nanoseconds == offset_nanoseconds) {
      // i. Return candidate.[[Nanoseconds]].
      return Handle<BigInt>(candidate->nanoseconds(), isolate);
    }
    // c. If matchBehaviour is match minutes, then
    if (match_behaviour == MatchBehaviour::kMatchMinutes) {
      // i. Let roundedCandidateNanoseconds be !
      // RoundNumberToIncrement(candidateNanoseconds, 60 × 10^9, "halfExpand").
      double rounded_candidate_nanoseconds = RoundNumberToIncrement(
          isolate, candidate_nanoseconds, 6e10, RoundingMode::kHalfExpand);
      // ii. If roundedCandidateNanoseconds = offsetNanoseconds, then
      if (rounded_candidate_nanoseconds == offset_nanoseconds) {
        // 1. Return candidate.[[Nanoseconds]].
        return Handle<BigInt>(candidate->nanoseconds(), isolate);
      }
    }
  }
  // 10. If offsetOption is "reject", throw a RangeError exception.
  if (offset_option == Offset::kReject) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 11. Let instant be ? DisambiguatePossibleInstants(possibleInstants,
  // timeZone, dateTime, disambiguation).
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      Disamb
Prompt: 
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第22部分，共25部分，请归纳一下它的功能

"""
StringPrecision({Precision::k9, Unit::kNanosecond, 1}));
    default:
      UNREACHABLE();
  }
}

// #sec-temporal-compareepochnanoseconds
MaybeHandle<Smi> CompareEpochNanoseconds(Isolate* isolate,
                                         DirectHandle<BigInt> one,
                                         DirectHandle<BigInt> two) {
  TEMPORAL_ENTER_FUNC();

  // 1. If epochNanosecondsOne > epochNanosecondsTwo, return 1.
  // 2. If epochNanosecondsOne < epochNanosecondsTwo, return -1.
  // 3. Return 0.
  return handle(
      Smi::FromInt(CompareResultToSign(BigInt::CompareToBigInt(one, two))),
      isolate);
}

}  // namespace

// #sec-temporal.plaintime.prototype.tostring
MaybeHandle<String> JSTemporalPlainTime::ToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainTime.prototype.toString";
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalTime,
  // [[InitializedTemporalTime]]).
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

  // 6. Let roundResult be ! RoundTime(temporalTime.[[ISOHour]],
  // temporalTime.[[ISOMinute]], temporalTime.[[ISOSecond]],
  // temporalTime.[[ISOMillisecond]], temporalTime.[[ISOMicrosecond]],
  // temporalTime.[[ISONanosecond]], precision.[[Increment]],
  // precision.[[Unit]], roundingMode).

  DateTimeRecord round_result = RoundTime(
      isolate,
      {temporal_time->iso_hour(), temporal_time->iso_minute(),
       temporal_time->iso_second(), temporal_time->iso_millisecond(),
       temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()},
      precision.increment, precision.unit, rounding_mode);
  // 7. Return ! TemporalTimeToString(roundResult.[[Hour]],
  // roundResult.[[Minute]], roundResult.[[Second]],
  // roundResult.[[Millisecond]], roundResult.[[Microsecond]],
  // roundResult.[[Nanosecond]], precision.[[Precision]]).
  return TemporalTimeToString(isolate, round_result.time, precision.precision);
}

// #sec-temporal.zoneddatetime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> epoch_nanoseconds_obj, Handle<Object> time_zone_like,
    Handle<Object> calendar_like) {
  const char* method_name = "Temporal.ZonedDateTime";
  // 1. If NewTarget is undefined, then
  if (IsUndefined(*new_target)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }
  // 2. Set epochNanoseconds to ? ToBigInt(epochNanoseconds).
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      BigInt::FromObject(isolate, epoch_nanoseconds_obj));
  // 3. If ! IsValidEpochNanoseconds(epochNanoseconds) is false, throw a
  // RangeError exception.
  if (!IsValidEpochNanoseconds(isolate, epoch_nanoseconds)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }

  // 4. Let timeZone be ? ToTemporalTimeZone(timeZoneLike).
  Handle<JSReceiver> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      temporal::ToTemporalTimeZone(isolate, time_zone_like, method_name));

  // 5. Let calendar be ? ToTemporalCalendarWithISODefault(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ToTemporalCalendarWithISODefault(isolate, calendar_like, method_name));

  // 6. Return ? CreateTemporalZonedDateTime(epochNanoseconds, timeZone,
  // calendar, NewTarget).
  return CreateTemporalZonedDateTime(isolate, target, new_target,
                                     epoch_nanoseconds, time_zone, calendar);
}

// #sec-get-temporal.zoneddatetime.prototype.hoursinday
MaybeHandle<Object> JSTemporalZonedDateTime::HoursInDay(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.hoursInDay";
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

  // 5. Let isoCalendar be ! GetISO8601Calendar().
  DirectHandle<JSReceiver> iso_calendar = temporal::GetISO8601Calendar(isolate);

  // 6. Let temporalDateTime be ? BuiltinTimeZoneGetPlainDateTimeFor(timeZone,
  // instant, isoCalendar).
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(isolate, time_zone, instant,
                                                   iso_calendar, method_name));
  // 7. Let year be temporalDateTime.[[ISOYear]].
  // 8. Let month be temporalDateTime.[[ISOMonth]].
  // 9. Let day be temporalDateTime.[[ISODay]].
  // 10. Let today be ? CreateTemporalDateTime(year, month, day, 0, 0, 0, 0, 0,
  // 0, isoCalendar).
  Handle<JSTemporalPlainDateTime> today;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, today,
      temporal::CreateTemporalDateTime(
          isolate,
          {{temporal_date_time->iso_year(), temporal_date_time->iso_month(),
            temporal_date_time->iso_day()},
           {0, 0, 0, 0, 0, 0}},
          iso_calendar));
  // 11. Let tomorrowFields be BalanceISODate(year, month, day + 1).
  DateRecord tomorrow_fields = BalanceISODate(
      isolate, {temporal_date_time->iso_year(), temporal_date_time->iso_month(),
                temporal_date_time->iso_day() + 1});

  // 12. Let tomorrow be ? CreateTemporalDateTime(tomorrowFields.[[Year]],
  // tomorrowFields.[[Month]], tomorrowFields.[[Day]], 0, 0, 0, 0, 0, 0,
  // isoCalendar).
  Handle<JSTemporalPlainDateTime> tomorrow;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, tomorrow,
      temporal::CreateTemporalDateTime(
          isolate, {tomorrow_fields, {0, 0, 0, 0, 0, 0}}, iso_calendar));
  // 13. Let todayInstant be ? BuiltinTimeZoneGetInstantFor(timeZone, today,
  // "compatible").
  Handle<JSTemporalInstant> today_instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, today_instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, today,
                                   Disambiguation::kCompatible, method_name));
  // 14. Let tomorrowInstant be ? BuiltinTimeZoneGetInstantFor(timeZone,
  // tomorrow, "compatible").
  Handle<JSTemporalInstant> tomorrow_instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, tomorrow_instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, tomorrow,
                                   Disambiguation::kCompatible, method_name));
  // 15. Let diffNs be tomorrowInstant.[[Nanoseconds]] −
  // todayInstant.[[Nanoseconds]].
  Handle<BigInt> diff_ns =
      BigInt::Subtract(isolate,
                       handle(tomorrow_instant->nanoseconds(), isolate),
                       handle(today_instant->nanoseconds(), isolate))
          .ToHandleChecked();
  // 16. Return 𝔽(diffNs / (3.6 × 10^12)).
  //
  // Note: The result of the division may be non integer for TimeZone which
  // change fractional hours. Perform this division in two steps:
  // First convert it to seconds in BigInt, then perform floating point
  // division (seconds / 3600) to convert to hours.
  int64_t diff_seconds =
      BigInt::Divide(isolate, diff_ns, BigInt::FromUint64(isolate, 1000000000))
          .ToHandleChecked()
          ->AsInt64();
  double hours_in_that_day = static_cast<double>(diff_seconds) / 3600.0;
  return isolate->factory()->NewNumber(hours_in_that_day);
}

namespace {

// #sec-temporal-totemporalzoneddatetime
MaybeHandle<JSTemporalZonedDateTime> ToTemporalZonedDateTime(
    Isolate* isolate, Handle<Object> item_obj, Handle<Object> options,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 2. Assert: Type(options) is Object or Undefined.
  DCHECK(IsUndefined(*options) || IsJSReceiver(*options));
  // 3. Let offsetBehaviour be option.
  OffsetBehaviour offset_behaviour = OffsetBehaviour::kOption;
  // 4. Let matchBehaviour be match exactly.
  MatchBehaviour match_behaviour = MatchBehaviour::kMatchExactly;

  Handle<Object> offset_string;
  Handle<JSReceiver> time_zone;
  Handle<JSReceiver> calendar;

  temporal::DateTimeRecord result;

  // 5. If Type(item) is Object, then
  if (IsJSReceiver(*item_obj)) {
    Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
    // a. If item has an [[InitializedTemporalZonedDateTime]] internal slot,
    // then
    if (IsJSTemporalZonedDateTime(*item_obj)) {
      // i. Return item.
      return Cast<JSTemporalZonedDateTime>(item_obj);
    }
    // b. Let calendar be ? GetTemporalCalendarWithISODefault(item).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        GetTemporalCalendarWithISODefault(isolate, item, method_name));
    // c. Let fieldNames be ? CalendarFields(calendar, « "day", "hour",
    // "microsecond", "millisecond", "minute", "month", "monthCode",
    // "nanosecond", "second", "year" »).
    Handle<FixedArray> field_names = All10UnitsInFixedArray(isolate);
    ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                               CalendarFields(isolate, calendar, field_names));

    // d. Append "timeZone" to fieldNames.
    int32_t field_length = field_names->length();
    field_names = FixedArray::SetAndGrow(isolate, field_names, field_length++,
                                         factory->timeZone_string());

    // e. Append "offset" to fieldNames.
    field_names = FixedArray::SetAndGrow(isolate, field_names, field_length++,
                                         factory->offset_string());
    field_names->RightTrim(isolate, field_length);

    // f. Let fields be ? PrepareTemporalFields(item, fieldNames, « "timeZone"
    // »).
    Handle<JSReceiver> fields;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, fields,
        PrepareTemporalFields(isolate, item, field_names,
                              RequiredFields::kTimeZone));

    // g. Let timeZone be ? Get(fields, "timeZone").
    Handle<Object> time_zone_obj;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone_obj,
        JSReceiver::GetProperty(isolate, fields, factory->timeZone_string()));

    // h. Set timeZone to ? ToTemporalTimeZone(timeZone).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone,
        temporal::ToTemporalTimeZone(isolate, time_zone_obj, method_name));
    // i. Let offsetString be ? Get(fields, "offset").
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, offset_string,
        JSReceiver::GetProperty(isolate, fields, factory->offset_string()));

    // j. If offsetString is undefined, then
    if (IsUndefined(*offset_string)) {
      // i. Set offsetBehaviour to wall.
      offset_behaviour = OffsetBehaviour::kWall;
      // k. Else,
    } else {
      // i. Set offsetString to ? ToString(offsetString).
      ASSIGN_RETURN_ON_EXCEPTION(isolate, offset_string,
                                 Object::ToString(isolate, offset_string));
    }

    // l. Let result be ? InterpretTemporalDateTimeFields(calendar, fields,
    // options).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        InterpretTemporalDateTimeFields(isolate, calendar, fields, options,
                                        method_name),
        Handle<JSTemporalZonedDateTime>());
    // 5. Else,
  } else {
    // a. Perform ? ToTemporalOverflow(options).
    MAYBE_RETURN_ON_EXCEPTION_VALUE(
        isolate, ToTemporalOverflow(isolate, options, method_name),
        Handle<JSTemporalZonedDateTime>());
    // b. Let string be ? ToString(item).
    Handle<String> string;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, string,
                               Object::ToString(isolate, item_obj));
    // c. Let result be ? ParseTemporalZonedDateTimeString(string).
    DateTimeRecordWithCalendar parsed_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, parsed_result,
        ParseTemporalZonedDateTimeString(isolate, string),
        Handle<JSTemporalZonedDateTime>());
    result = {parsed_result.date, parsed_result.time};

    // d. Let timeZoneName be result.[[TimeZone]].[[Name]].
    // e. Assert: timeZoneName is not undefined.
    DCHECK(!IsUndefined(*parsed_result.time_zone.name));
    Handle<String> time_zone_name = Cast<String>(parsed_result.time_zone.name);

    // f. If ParseText(StringToCodePoints(timeZoneName),
    // TimeZoneNumericUTCOffset) is a List of errors, then
    std::optional<ParsedISO8601Result> parsed =
        TemporalParser::ParseTimeZoneNumericUTCOffset(isolate, time_zone_name);
    if (!parsed.has_value()) {
      // i. If ! IsValidTimeZoneName(timeZoneName) is false, throw a RangeError
      // exception.
      if (!IsValidTimeZoneName(isolate, time_zone_name)) {
        THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                     NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                     Handle<JSTemporalZonedDateTime>());
      }
      // ii. Set timeZoneName to ! CanonicalizeTimeZoneName(timeZoneName).
      time_zone_name = CanonicalizeTimeZoneName(isolate, time_zone_name);
    }
    // g. Let offsetString be result.[[TimeZone]].[[OffsetString]].
    offset_string = parsed_result.time_zone.offset_string;

    // h. If result.[[TimeZone]].[[Z]] is true, then
    if (parsed_result.time_zone.z) {
      // i. Set offsetBehaviour to exact.
      offset_behaviour = OffsetBehaviour::kExact;
      // i. Else if offsetString is undefined, then
    } else if (IsUndefined(*offset_string)) {
      // i. Set offsetBehaviour to wall.
      offset_behaviour = OffsetBehaviour::kWall;
    }
    // j. Let timeZone be ! CreateTemporalTimeZone(timeZoneName).
    time_zone = temporal::CreateTemporalTimeZone(isolate, time_zone_name)
                    .ToHandleChecked();
    // k. Let calendar be ?
    // ToTemporalCalendarWithISODefault(result.[[Calendar]]).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        ToTemporalCalendarWithISODefault(isolate, parsed_result.calendar,
                                         method_name));
    // j. Set matchBehaviour to match minutes.
    match_behaviour = MatchBehaviour::kMatchMinutes;
  }
  // 7. Let offsetNanoseconds be 0.
  int64_t offset_nanoseconds = 0;

  // 6. If offsetBehaviour is option, then
  if (offset_behaviour == OffsetBehaviour::kOption) {
    // a. Set offsetNanoseconds to ? ParseTimeZoneOffsetString(offsetString).
    DCHECK(IsString(*offset_string));
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, offset_nanoseconds,
        ParseTimeZoneOffsetString(isolate, Cast<String>(offset_string)),
        Handle<JSTemporalZonedDateTime>());
  }

  // 7. Let disambiguation be ? ToTemporalDisambiguation(options).
  Disambiguation disambiguation;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, disambiguation,
      ToTemporalDisambiguation(isolate, options, method_name),
      Handle<JSTemporalZonedDateTime>());

  // 8. Let offset be ? ToTemporalOffset(options, "reject").
  enum Offset offset;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset,
      ToTemporalOffset(isolate, options, Offset::kReject, method_name),
      Handle<JSTemporalZonedDateTime>());

  // 9. Let epochNanoseconds be ? InterpretISODateTimeOffset(result.[[Year]],
  // result.[[Month]], result.[[Day]], result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]], offsetBehaviour, offsetNanoseconds, timeZone,
  // disambiguation, offset, matchBehaviour).
  //
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      InterpretISODateTimeOffset(isolate, result, offset_behaviour,
                                 offset_nanoseconds, time_zone, disambiguation,
                                 offset, match_behaviour, method_name));

  // 8. Return ? CreateTemporalZonedDateTime(epochNanoseconds, timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(isolate, epoch_nanoseconds, time_zone,
                                     calendar);
}

MaybeHandle<JSTemporalZonedDateTime> ToTemporalZonedDateTime(
    Isolate* isolate, Handle<Object> item_obj, const char* method_name) {
  // 1. If options is not present, set options to undefined.
  return ToTemporalZonedDateTime(
      isolate, item_obj, isolate->factory()->undefined_value(), method_name);
}

}  // namespace

// #sec-temporal.zoneddatetime.from
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::From(
    Isolate* isolate, Handle<Object> item, Handle<Object> options_obj) {
  const char* method_name = "Temporal.ZonedDateTime.from";
  // 1. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 2. If Type(item) is Object and item has an
  // [[InitializedTemporalZonedDateTime]] internal slot, then
  if (IsJSTemporalZonedDateTime(*item)) {
    // a. Perform ? ToTemporalOverflow(options).
    MAYBE_RETURN_ON_EXCEPTION_VALUE(
        isolate, ToTemporalOverflow(isolate, options, method_name),
        Handle<JSTemporalZonedDateTime>());

    // b. Perform ? ToTemporalDisambiguation(options).
    {
      Disambiguation disambiguation;
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, disambiguation,
          ToTemporalDisambiguation(isolate, options, method_name),
          Handle<JSTemporalZonedDateTime>());
      USE(disambiguation);
    }

    // c. Perform ? ToTemporalOffset(options, "reject").
    {
      enum Offset offset;
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, offset,
          ToTemporalOffset(isolate, options, Offset::kReject, method_name),
          Handle<JSTemporalZonedDateTime>());
      USE(offset);
    }

    // d. Return ? CreateTemporalZonedDateTime(item.[[Nanoseconds]],
    // item.[[TimeZone]], item.[[Calendar]]).
    auto zoned_date_time = Cast<JSTemporalZonedDateTime>(item);
    return CreateTemporalZonedDateTime(
        isolate, handle(zoned_date_time->nanoseconds(), isolate),
        handle(zoned_date_time->time_zone(), isolate),
        handle(zoned_date_time->calendar(), isolate));
  }
  // 3. Return ? ToTemporalZonedDateTime(item, options).
  return ToTemporalZonedDateTime(isolate, item, options, method_name);
}

// #sec-temporal.zoneddatetime.compare
MaybeHandle<Smi> JSTemporalZonedDateTime::Compare(Isolate* isolate,
                                                  Handle<Object> one_obj,
                                                  Handle<Object> two_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.compare";
  // 1. Set one to ? ToTemporalZonedDateTime(one).
  Handle<JSTemporalZonedDateTime> one;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, one, ToTemporalZonedDateTime(isolate, one_obj, method_name));
  // 2. Set two to ? ToTemporalZonedDateTime(two).
  Handle<JSTemporalZonedDateTime> two;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, two, ToTemporalZonedDateTime(isolate, two_obj, method_name));
  // 3. Return 𝔽(! CompareEpochNanoseconds(one.[[Nanoseconds]],
  // two.[[Nanoseconds]])).
  return CompareEpochNanoseconds(isolate, handle(one->nanoseconds(), isolate),
                                 handle(two->nanoseconds(), isolate));
}

namespace {

// #sec-temporal-timezoneequals
Maybe<bool> TimeZoneEquals(Isolate* isolate, Handle<JSReceiver> one,
                           Handle<JSReceiver> two) {
  // 1. If one and two are the same Object value, return true.
  if (one.is_identical_to(two)) {
    return Just(true);
  }

  // 2. Let timeZoneOne be ? ToString(one).
  Handle<String> time_zone_one;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, time_zone_one, Object::ToString(isolate, one), Nothing<bool>());
  // 3. Let timeZoneTwo be ? ToString(two).
  Handle<String> time_zone_two;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, time_zone_two, Object::ToString(isolate, two), Nothing<bool>());
  // 4. If timeZoneOne is timeZoneTwo, return true.
  if (String::Equals(isolate, time_zone_one, time_zone_two)) {
    return Just(true);
  }
  // 5. Return false.
  return Just(false);
}

}  // namespace

// #sec-temporal.zoneddatetime.prototype.equals
MaybeHandle<Oddball> JSTemporalZonedDateTime::Equals(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> other_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.equals";
  Factory* factory = isolate->factory();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. Set other to ? ToTemporalZonedDateTime(other).
  Handle<JSTemporalZonedDateTime> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other, ToTemporalZonedDateTime(isolate, other_obj, method_name));
  // 4. If zonedDateTime.[[Nanoseconds]] ≠ other.[[Nanoseconds]], return false.
  if (!BigInt::EqualToBigInt(zoned_date_time->nanoseconds(),
                             other->nanoseconds())) {
    return factory->false_value();
  }
  // 5. If ? TimeZoneEquals(zonedDateTime.[[TimeZone]], other.[[TimeZone]]) is
  // false, return false.
  bool equals;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, equals,
      TimeZoneEquals(isolate, handle(zoned_date_time->time_zone(), isolate),
                     handle(other->time_zone(), isolate)),
      Handle<Oddball>());
  if (!equals) {
    return factory->false_value();
  }
  // 6. Return ? CalendarEquals(zonedDateTime.[[Calendar]], other.[[Calendar]]).
  return CalendarEquals(isolate, handle(zoned_date_time->calendar(), isolate),
                        handle(other->calendar(), isolate));
}

namespace {

// #sec-temporal-interpretisodatetimeoffset
MaybeHandle<BigInt> InterpretISODateTimeOffset(
    Isolate* isolate, const DateTimeRecord& data,
    OffsetBehaviour offset_behaviour, int64_t offset_nanoseconds,
    Handle<JSReceiver> time_zone, Disambiguation disambiguation,
    Offset offset_option, MatchBehaviour match_behaviour,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: offsetNanoseconds is an integer or undefined.
  // 2. Let calendar be ! GetISO8601Calendar().
  DirectHandle<JSReceiver> calendar = temporal::GetISO8601Calendar(isolate);

  // 3. Let dateTime be ? CreateTemporalDateTime(year, month, day, hour, minute,
  // second, millisecond, microsecond, nanosecond, calendar).
  Handle<JSTemporalPlainDateTime> date_time;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, date_time,
                             temporal::CreateTemporalDateTime(
                                 isolate, {data.date, data.time}, calendar));

  // 4. If offsetBehaviour is wall, or offsetOption is "ignore", then
  if (offset_behaviour == OffsetBehaviour::kWall ||
      offset_option == Offset::kIgnore) {
    // a. Let instant be ? BuiltinTimeZoneGetInstantFor(timeZone, dateTime,
    // disambiguation).
    Handle<JSTemporalInstant> instant;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, instant,
        BuiltinTimeZoneGetInstantFor(isolate, time_zone, date_time,
                                     disambiguation, method_name));
    // b. Return instant.[[Nanoseconds]].
    return handle(instant->nanoseconds(), isolate);
  }
  // 5. If offsetBehaviour is exact, or offsetOption is "use", then
  if (offset_behaviour == OffsetBehaviour::kExact ||
      offset_option == Offset::kUse) {
    // a. Let epochNanoseconds be ? GetEpochFromISOParts(year, month, day, hour,
    // minute, second, millisecond, microsecond, nanosecond).
    Handle<BigInt> epoch_nanoseconds =
        GetEpochFromISOParts(isolate, {data.date, data.time});

    // b. Set epochNanoseconds to epochNanoseconds - ℤ(offsetNanoseconds).
    epoch_nanoseconds =
        BigInt::Subtract(isolate, epoch_nanoseconds,
                         BigInt::FromInt64(isolate, offset_nanoseconds))
            .ToHandleChecked();
    // c. If ! IsValidEpochNanoseconds(epochNanoseconds) is false, throw a
    // RangeError exception.
    if (!IsValidEpochNanoseconds(isolate, epoch_nanoseconds)) {
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
    }
    // d. Return epochNanoseconds.
    return epoch_nanoseconds;
  }
  // 6. Assert: offsetBehaviour is option.
  DCHECK_EQ(offset_behaviour, OffsetBehaviour::kOption);
  // 7. Assert: offsetOption is "prefer" or "reject".
  DCHECK(offset_option == Offset::kPrefer || offset_option == Offset::kReject);
  // 8. Let possibleInstants be ? GetPossibleInstantsFor(timeZone, dateTime).
  Handle<FixedArray> possible_instants;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, possible_instants,
      GetPossibleInstantsFor(isolate, time_zone, date_time));

  // 9. For each element candidate of possibleInstants, do
  for (int i = 0; i < possible_instants->length(); i++) {
    DCHECK(IsJSTemporalInstant(possible_instants->get(i)));
    Handle<JSTemporalInstant> candidate(
        Cast<JSTemporalInstant>(possible_instants->get(i)), isolate);
    // a. Let candidateNanoseconds be ? GetOffsetNanosecondsFor(timeZone,
    // candidate).
    int64_t candidate_nanoseconds;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, candidate_nanoseconds,
        GetOffsetNanosecondsFor(isolate, time_zone, candidate, method_name),
        Handle<BigInt>());
    // b. If candidateNanoseconds = offsetNanoseconds, then
    if (candidate_nanoseconds == offset_nanoseconds) {
      // i. Return candidate.[[Nanoseconds]].
      return Handle<BigInt>(candidate->nanoseconds(), isolate);
    }
    // c. If matchBehaviour is match minutes, then
    if (match_behaviour == MatchBehaviour::kMatchMinutes) {
      // i. Let roundedCandidateNanoseconds be !
      // RoundNumberToIncrement(candidateNanoseconds, 60 × 10^9, "halfExpand").
      double rounded_candidate_nanoseconds = RoundNumberToIncrement(
          isolate, candidate_nanoseconds, 6e10, RoundingMode::kHalfExpand);
      // ii. If roundedCandidateNanoseconds = offsetNanoseconds, then
      if (rounded_candidate_nanoseconds == offset_nanoseconds) {
        // 1. Return candidate.[[Nanoseconds]].
        return Handle<BigInt>(candidate->nanoseconds(), isolate);
      }
    }
  }
  // 10. If offsetOption is "reject", throw a RangeError exception.
  if (offset_option == Offset::kReject) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 11. Let instant be ? DisambiguatePossibleInstants(possibleInstants,
  // timeZone, dateTime, disambiguation).
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      DisambiguatePossibleInstants(isolate, possible_instants, time_zone,
                                   date_time, disambiguation, method_name));
  // 12. Return instant.[[Nanoseconds]].
  return Handle<BigInt>(instant->nanoseconds(), isolate);
}

}  // namespace

// #sec-temporal.zoneddatetime.prototype.with
MaybeHandle<JSTemporalZonedDateTime> JSTemporalZonedDateTime::With(
    Isolate* isolate, Handle<JSTemporalZonedDateTime> zoned_date_time,
    Handle<Object> temporal_zoned_date_time_like_obj,
    Handle<Object> options_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.ZonedDateTime.prototype.with";
  Factory* factory = isolate->factory();
  // 1. Let zonedDateTime be the this value.
  // 2. Perform ? RequireInternalSlot(zonedDateTime,
  // [[InitializedTemporalZonedDateTime]]).
  // 3. If Type(temporalZonedDateTimeLike) is not Object, then
  if (!IsJSReceiver(*temporal_zoned_date_time_like_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  Handle<JSReceiver> temporal_zoned_date_time_like =
      Cast<JSReceiver>(temporal_zoned_date_time_like_obj);
  // 4. Perform ? RejectObjectWithCalendarOrTimeZone(temporalZonedDateTimeLike).
  MAYBE_RETURN(RejectObjectWithCalendarOrTimeZone(
                   isolate, temporal_zoned_date_time_like),
               Handle<JSTemporalZonedDateTime>());

  // 5. Let calendar be zonedDateTime.[[Calendar]].
  Handle<JSReceiver> calendar(zoned_date_time->calendar(), isolate);

  // 6. Let fieldNames be ? CalendarFields(calendar, « "day", "hour",
  // "microsecond", "millisecond", "minute", "month", "monthCode", "nanosecond",
  // "second", "year" »).
  Handle<FixedArray> field_names;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, field_names,
      CalendarFields(isolate, calendar, All10UnitsInFixedArray(isolate)));

  // 7. Append "offset" to fieldNames.
  int32_t field_length = field_names->length();
  field_names = FixedArray::SetAndGrow(isolate, field_names, field_length++,
                                       factory->offset_string());
  field_names->RightTrim(isolate, field_length);

  // 8. Let partialZonedDateTime be ?
  // PreparePartialTemporalFields(temporalZonedDateTimeLike, fieldNames).
  Handle<JSReceiver> partial_zoned_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, partial_zoned_date_time,
      PreparePartialTemporalFields(isolate, temporal_zoned_date_time_like,
                                   field_names));
  // 9. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 10. Let disambiguation be ? ToTemporalDisambiguation(options).
  Disambiguation disambiguation;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, disambiguation,
      ToTemporalDisambiguation(isolate, options, method_name),
      Handle<JSTemporalZonedDateTime>());

  // 11. Let offset be ? ToTemporalOffset(options, "prefer").
  enum Offset offset;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset,
      ToTemporalOffset(isolate, options, Offset::kPrefer, method_name),
      Handle<JSTemporalZonedDateTime>());

  // 12. Let timeZone be zonedDateTime.[[TimeZone]].
  Handle<JSReceiver> time_zone(zoned_date_time->time_zone(), isolate);

  // 13. Append "timeZone" to fieldNames.
  field_length = field_names->length();
  field_names = FixedArray::SetAndGrow(isolate, field_names, field_length++,
                                       factory->timeZone_string());
  field_names->RightTrim(isolate, field_length);

  // 14. Let fields be ? PrepareTemporalFields(zonedDateTime, fieldNames, «
  // "timeZone", "offset"»).
  Handle<JSReceiver> fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      PrepareTemporalFields(isolate, zoned_date_time, field_names,
                            RequiredFields::kTimeZoneAndOffset));
  // 15. Set fields to ? CalendarMergeFields(calendar, fields,
  // partialZonedDateTime).
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      CalendarMergeFields(isolate, calendar, fields, partial_zoned_date_time));

  // 16. Set fields to ? PrepareTemporalFields(fields, fieldNames, « "timeZone"
  // , "offset"»).
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      PrepareTemporalFields(isolate, fields, field_names,
                            RequiredFields::kTimeZoneAndOffset));

  // 17. Let offsetString be ? Get(fields, "offset").
  Handle<Object> offset_string;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, offset_string,
      JSReceiver::GetProperty(isolate, fields, factory->offset_string()));

  // 18. Assert: Type(offsetString) is String.
  DCHECK(IsString(*offset_string));

  // 19. Let dat
"""


```