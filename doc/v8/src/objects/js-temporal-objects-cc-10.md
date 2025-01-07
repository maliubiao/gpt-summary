Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/js-temporal-objects.cc`. The summary should include:

1. **General Functionality:** What does this code do?
2. **Torque Source:**  Check if the filename ends with `.tq`.
3. **JavaScript Relationship:** If related to JavaScript functionality, provide examples.
4. **Code Logic Inference:**  Explain the logic with hypothetical inputs and outputs.
5. **Common Programming Errors:** Give examples of user errors.
6. **Overall Functionality (for this part):** Summarize the specific functions in this excerpt, considering it's part 11 of 25.

Let's break down the code section by section:

*   **`JSTemporalDuration::Round` function:** This function seems to handle rounding operations on `Temporal.Duration` objects. It involves several steps like unbalancing, rounding, adjusting, and balancing the duration components. It interacts with `Temporal.ZonedDateTime` for relative calculations.
*   **`JSTemporalDuration::Total` function:** This function calculates the total value of a `Temporal.Duration` in a specific unit. It also handles relative calculations with `Temporal.ZonedDateTime`.
*   **`ToPartialDuration` function:** This utility function appears to extract duration components from a JavaScript object-like structure.
*   **`JSTemporalDuration::With` function:** This function likely creates a new `Temporal.Duration` by merging properties from an existing duration and a partial duration object.
*   **`JSTemporalDuration::Sign` function:** This function returns the sign of a `Temporal.Duration`.
*   **`JSTemporalDuration::Blank` function:** This function checks if a `Temporal.Duration` represents zero duration.
*   **`CreateNegatedDurationRecord` and `CreateNegatedTemporalDuration` functions:** These functions create negated versions of duration records and `Temporal.Duration` objects.
*   **`JSTemporalDuration::Negated` function:** This function returns a new `Temporal.Duration` with all components negated.
*   **`JSTemporalDuration::Abs` function:** This function returns a new `Temporal.Duration` with the absolute values of all components.
*   **`InterpretISODateTimeOffset`, `InterpretTemporalDateTimeFields`, and `ToRelativeTemporalObject` functions:** These utility functions seem related to parsing and interpreting date/time information, particularly when dealing with relative time calculations and time zones.
*   **`DefaultTemporalLargestUnit` function:** This function determines the largest non-zero unit in a duration.

Based on these observations, the primary focus of this code section is the implementation of various methods for the `Temporal.Duration` object in JavaScript, including rounding, calculating totals, creating new durations by merging or negating, checking the sign and "blankness" of a duration, and handling relative date/time calculations.
```cpp
// #sec-temporal.duration.prototype.round
MaybeHandle<JSTemporalDuration> JSTemporalDuration::Round(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration,
    Handle<Object> round_to_obj) {
  const char* method_name = "Temporal.Duration.prototype.round";
  Factory* factory = isolate->factory();
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. If roundTo is undefined, throw a TypeError exception.
  if (IsUndefined(*round_to_obj, isolate)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }

  Handle<JSReceiver> round_to;
  // 4. If Type(roundTo) is String, then
  if (IsString(*round_to_obj)) {
    // a. Let unitString be roundTo.
    Handle<String> unit_string = Cast<String>(round_to_obj);
    // b. Set roundTo to ! OrdinaryObjectCreate(null).
    round_to = factory->NewJSObjectWithNullProto();
    // c. Perform ! CreateDataPropertyOrThrow(roundTo, "smallestUnit",
    // unitString).
    CHECK(JSReceiver::CreateDataProperty(isolate, round_to,
                                         factory->smallestUnit_string(),
                                         unit_string, Just(kThrowOnError))
              .FromJust());
  } else {
    // 5. Set roundTo to ? GetOptionsObject(roundTo).
    ASSIGN_RETURN_ON_EXCEPTION(isolate, round_to,
                               GetOptionsObject(isolate, round_to_obj,
                                                method_name));
  }

  // 6. Let smallestUnit be ? GetTemporalUnit(roundTo, "smallestUnit", datetime,
  // undefined).
  Unit smallest_unit = Unit::kUndefined;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, smallest_unit,
      GetTemporalUnit(isolate, round_to, "smallestUnit", UnitGroup::kDateTime,
                      Unit::kUndefined, false, method_name),
      Handle<JSTemporalDuration>());
  // 7. Let roundingIncrement be ? GetNumberOption(roundTo, "roundingIncrement",
  // « 1 », undefined, positiveNumber).
  double rounding_increment;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_increment,
      GetNumberOption(isolate, round_to, factory->roundingIncrement_string(),
                      RoundingIncrementDefault(),
                      GetPositiveNumberOptionRange()),
      Handle<JSTemporalDuration>());
  // 8. Let roundingMode be ? GetOption(roundTo, "roundingMode", « "ceil",
  // "floor", "halfExpand", "halfEven", "trunc" » , "halfExpand").
  RoundingMode rounding_mode = RoundingMode::kHalfExpand;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      GetRoundingModeOption(isolate, round_to, method_name),
      Handle<JSTemporalDuration>());

  // 9. Let relativeTo be ? ToRelativeTemporalObject(roundTo).
  Handle<Object> relative_to;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, relative_to,
      ToRelativeTemporalObject(isolate, round_to, method_name));

  // 10. If smallestUnit is undefined, then
  if (smallest_unit == Unit::kUndefined) {
    // a. If relativeTo is undefined, then
    if (IsUndefined(*relative_to)) {
      // i. Throw a TypeError exception.
      THROW_NEW_ERROR(isolate, NEW_TYPE_ERROR(
                                    MessageTemplate::kTemporalMissingUnit));
    }
    // b. Let largestUnit be ? GetTemporalUnit(roundTo, "largestUnit", datetime,
    // undefined).
    Unit largest_unit = Unit::kUndefined;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, largest_unit,
        GetTemporalUnit(isolate, round_to, "largestUnit", UnitGroup::kDateTime,
                        Unit::kUndefined, false, method_name),
        Handle<JSTemporalDuration>());
    // c. If largestUnit is undefined, set largestUnit to "day".
    if (largest_unit == Unit::kUndefined) {
      largest_unit = Unit::kDay;
    }
    // d. If largestUnit is "year", set smallestUnit to "year".
    if (largest_unit == Unit::kYear) {
      smallest_unit = Unit::kYear;
    }
    // e. Else if largestUnit is "month", set smallestUnit to "month".
    else if (largest_unit == Unit::kMonth) {
      smallest_unit = Unit::kMonth;
    }
    // f. Else if largestUnit is "week", set smallestUnit to "week".
    else if (largest_unit == Unit::kWeek) {
      smallest_unit = Unit::kWeek;
    }
    // g. Else, set smallestUnit to "day".
    else {
      smallest_unit = Unit::kDay;
    }
  }
  // 11. If relativeTo is undefined, then
  if (IsUndefined(*relative_to)) {
    // a. Return ? RoundDuration(duration.[[Years]], duration.[[Months]],
    // duration.[[Weeks]], duration.[[Days]], duration.[[Hours]],
    // duration.[[Minutes]], duration.[[Seconds]], duration.[[Milliseconds]],
    // duration.[[Microseconds]], duration.[[Nanoseconds]], roundingIncrement,
    // smallestUnit, roundingMode).
    DurationRecordWithRemainder round_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, round_result,
        RoundDuration(
            isolate,
            {Object::NumberValue(duration->years()),
             Object::NumberValue(duration->months()),
             Object::NumberValue(duration->weeks()),
             {Object::NumberValue(duration->days()),
              Object::NumberValue(duration->hours()),
              Object::NumberValue(duration->minutes()),
              Object::NumberValue(duration->seconds()),
              Object::NumberValue(duration->milliseconds()),
              Object::NumberValue(duration->microseconds()),
              Object::NumberValue(duration->nanoseconds())}},
            rounding_increment, smallest_unit, rounding_mode, relative_to,
            method_name),
        Handle<JSTemporalDuration>());
    return CreateTemporalDuration(isolate, round_result.record);
  }

  // 12. Let largestUnit be ? GetTemporalUnit(roundTo, "largestUnit", datetime,
  // "auto").
  Unit largest_unit = Unit::kAuto;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, largest_unit,
      GetTemporalUnit(isolate, round_to, "largestUnit", UnitGroup::kDateTime,
                      Unit::kAuto, false, method_name),
      Handle<JSTemporalDuration>());

  // 13. If largestUnit is "auto", then
  if (largest_unit == Unit::kAuto) {
    // a. Let largestUnit be ! DefaultTemporalLargestUnit(duration).
    largest_unit = DefaultTemporalLargestUnit({
        Object::NumberValue(duration->years()),
        Object::NumberValue(duration->months()),
        Object::NumberValue(duration->weeks()),
        {Object::NumberValue(duration->days()),
         Object::NumberValue(duration->hours()),
         Object::NumberValue(duration->minutes()),
         Object::NumberValue(duration->seconds()),
         Object::NumberValue(duration->milliseconds()),
         Object::NumberValue(duration->microseconds()),
         Object::NumberValue(duration->nanoseconds())}});
  }

  // 14. If ! IsValidDurationUnit(largestUnit) is false, throw a RangeError
  // exception.
  if (!IsValidDurationUnit(largest_unit)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }

  // 15. If ! IsValidDurationUnit(smallestUnit) is false, throw a RangeError
  // exception.
  if (!IsValidDurationUnit(smallest_unit)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }

  // 16. If LargerOf(largestUnit, smallestUnit) is not largestUnit, throw a
  // RangeError exception.
  if (LargerOf(largest_unit, smallest_unit) != largest_unit) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }

  // 17. Let unbalanceResult be ? UnbalanceDurationRelative(duration.[[Years]],
  // duration.[[Months]], duration.[[Weeks]], duration.[[Days]], largestUnit,
  // relativeTo).
  DateDurationRecord unbalance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, unbalance_result,
      UnbalanceDurationRelative(isolate,
                                {Object::NumberValue(duration->years()),
                                 Object::NumberValue(duration->months()),
                                 Object::NumberValue(duration->weeks()),
                                 Object::NumberValue(duration->days())},
                                largest_unit, relative_to, method_name),
      Handle<JSTemporalDuration>());
  // 18. Let roundResult be ? RoundDuration(unbalanceResult.[[Years]],
  // unbalanceResult.[[Months]], unbalanceResult.[[Weeks]],
  // unbalanceResult.[[Days]], duration.[[Hours]], duration.[[Minutes]],
  // duration.[[Seconds]], duration.[[Milliseconds]], duration.[[Microseconds]],
  // duration.[[Nanoseconds]], roundingIncrement, smallestUnit, roundingMode,
  // relativeTo).[[DurationRecord]].
  DurationRecordWithRemainder round_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, round_result,
      RoundDuration(
          isolate,
          {unbalance_result.years,
           unbalance_result.months,
           unbalance_result.weeks,
           {unbalance_result.days, Object::NumberValue(duration->hours()),
            Object::NumberValue(duration->minutes()),
            Object::NumberValue(duration->seconds()),
            Object::NumberValue(duration->milliseconds()),
            Object::NumberValue(duration->microseconds()),
            Object::NumberValue(duration->nanoseconds())}},
          rounding_increment, smallest_unit, rounding_mode, relative_to,
          method_name),
      Handle<JSTemporalDuration>());

  // 19. Let adjustResult be ? AdjustRoundedDurationDays(roundResult.[[Years]],
  // roundResult.[[Months]], roundResult.[[Weeks]], roundResult.[[Days]],
  // roundResult.[[Hours]], roundResult.[[Minutes]], roundResult.[[Seconds]],
  // roundResult.[[Milliseconds]], roundResult.[[Microseconds]],
  // roundResult.[[Nanoseconds]], roundingIncrement, smallestUnit, roundingMode,
  // relativeTo).
  DurationRecord adjust_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, adjust_result,
      AdjustRoundedDurationDays(isolate, round_result.record,
                                rounding_increment, smallest_unit,
                                rounding_mode, relative_to, method_name),
      Handle<JSTemporalDuration>());
  // 20. Let balanceResult be ? BalanceDurationRelative(adjustResult.[[Years]],
  // adjustResult.[[Months]], adjustResult.[[Weeks]], adjustResult.[[Days]],
  // largestUnit, relativeTo).
  DateDurationRecord balance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, balance_result,
      BalanceDurationRelative(
          isolate,
          {adjust_result.years, adjust_result.months, adjust_result.weeks,
           adjust_result.time_duration.days},
          largest_unit, relative_to, method_name),
      Handle<JSTemporalDuration>());
  // 21. If Type(relativeTo) is Object and relativeTo has an
  // [[InitializedTemporalZonedDateTime]] internal slot, then
  if (IsJSTemporalZonedDateTime(*relative_to)) {
    // a. Set relativeTo to ? MoveRelativeZonedDateTime(relativeTo,
    // balanceResult.[[Years]], balanceResult.[[Months]],
    // balanceResult.[[Weeks]], 0).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, relative_to,
        MoveRelativeZonedDateTime(isolate,
                                  Cast<JSTemporalZonedDateTime>(relative_to),
                                  {balance_result.years, balance_result.months,
                                   balance_result.weeks, 0},
                                  method_name));
  }
  // 22. Let result be ? BalanceDuration(balanceResult.[[Days]],
  // adjustResult.[[Hours]], adjustResult.[[Minutes]], adjustResult.[[Seconds]],
  // adjustResult.[[Milliseconds]], adjustResult.[[Microseconds]],
  // adjustResult.[[Nanoseconds]], largestUnit, relativeTo).
  TimeDurationRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      BalanceDuration(isolate, largest_unit, relative_to,
                      {balance_result.days, adjust_result.time_duration.hours,
                       adjust_result.time_duration.minutes,
                       adjust_result.time_duration.seconds,
                       adjust_result.time_duration.milliseconds,
                       adjust_result.time_duration.microseconds,
                       adjust_result.time_duration.nanoseconds},
                      method_name),
      Handle<JSTemporalDuration>());
  // 23. Return ! CreateTemporalDuration(balanceResult.[[Years]],
  // balanceResult.[[Months]], balanceResult.[[Weeks]], result.[[Days]],
  // result.[[Hours]], result.[[Minutes]], result.[[Seconds]],
  // result.[[Milliseconds]], result.[[Microseconds]], result.[[Nanoseconds]]).
  return CreateTemporalDuration(isolate,
                                {balance_result.years, balance_result.months,
                                 balance_result.weeks, result})
      .ToHandleChecked();
}

// #sec-temporal.duration.prototype.total
MaybeHandle<Object> JSTemporalDuration::Total(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration,
    Handle<Object> total_of_obj) {
  const char* method_name = "Temporal.Duration.prototype.total";
  Factory* factory = isolate->factory();
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. If totalOf is undefined, throw a TypeError exception.
  if (IsUndefined(*total_of_obj, isolate)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }

  Handle<JSReceiver> total_of;
  // 4. If Type(totalOf) is String, then
  if (IsString(*total_of_obj)) {
    // a. Let paramString be totalOf.
    Handle<String> param_string = Cast<String>(total_of_obj);
    // b. Set totalOf to ! OrdinaryObjectCreate(null).
    total_of = factory->NewJSObjectWithNullProto();
    // c. Perform ! CreateDataPropertyOrThrow(total_of, "unit", paramString).
    CHECK(JSReceiver::CreateDataProperty(isolate, total_of,
                                         factory->unit_string(), param_string,
                                         Just(kThrowOnError))
              .FromJust());
  } else {
    // 5. Set totalOf to ? GetOptionsObject(totalOf).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, total_of,
        GetOptionsObject(isolate, total_of_obj, method_name));
  }

  // 6. Let relativeTo be ? ToRelativeTemporalObject(totalOf).
  Handle<Object> relative_to;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, relative_to,
      ToRelativeTemporalObject(isolate, total_of, method_name));
  // 7. Let unit be ? GetTemporalUnit(totalOf, "unit", datetime, required).
  Unit unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, unit,
      GetTemporalUnit(isolate, total_of, "unit", UnitGroup::kDateTime,
                      Unit::kNotPresent, true, method_name),
      Handle<Object>());
  // 8. Let unbalanceResult be ? UnbalanceDurationRelative(duration.[[Years]],
  // duration.[[Months]], duration.[[Weeks]], duration.[[Days]], unit,
  // relativeTo).
  DateDurationRecord unbalance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, unbalance_result,
      UnbalanceDurationRelative(isolate,
                                {Object::NumberValue(duration->years()),
                                 Object::NumberValue(duration->months()),
                                 Object::NumberValue(duration->weeks()),
                                 Object::NumberValue(duration->days())},
                                unit, relative_to, method_name),
      Handle<Object>());

  // 9. Let intermediate be undefined.
  Handle<Object> intermediate = factory->undefined_value();

  // 8. If relativeTo has an [[InitializedTemporalZonedDateTime]] internal slot,
  // then
  if (IsJSTemporalZonedDateTime(*relative_to)) {
    // a. Set intermediate to ? MoveRelativeZonedDateTime(relativeTo,
    // unbalanceResult.[[Years]], unbalanceResult.[[Months]],
    // unbalanceResult.[[Weeks]], 0).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, intermediate,
        MoveRelativeZonedDateTime(
            isolate, Cast<JSTemporalZonedDateTime>(relative_to),
            {unbalance_result.years, unbalance_result.months,
             unbalance_result.weeks, 0},
            method_name));
  }

  // 11. Let balanceResult be ?
  // BalancePossiblyInfiniteDuration(unbalanceResult.[[Days]],
  // duration.[[Hours]], duration.[[Minutes]], duration.[[Seconds]],
  // duration.[[Milliseconds]], duration.[[Microseconds]],
  // duration.[[Nanoseconds]], unit, intermediate).
  BalancePossiblyInfiniteDurationResult balance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, balance_result,
      BalancePossiblyInfiniteDuration(
          isolate, unit, intermediate,
          {unbalance_result.days, Object::NumberValue(duration->hours()),
           Object::NumberValue(duration->minutes()),
           Object::NumberValue(duration->seconds()),
           Object::NumberValue(duration->milliseconds()),
           Object::NumberValue(duration->microseconds()),
           Object::NumberValue(duration->nanoseconds())},
          method_name),
      Handle<Object>());
  // 12. If balanceResult is positive overflow, return +∞𝔽.
  if (balance_result.overflow == BalanceOverflow::kPositive) {
    return factory->infinity_value();
  }
  // 13. If balanceResult is negative overflow, return -∞𝔽.
  if (balance_result.overflow == BalanceOverflow::kNegative) {
    return factory->minus_infinity_value();
  }
  // 14. Assert: balanceResult is a Time Duration Record.
  DCHECK_EQ(balance_result.overflow, BalanceOverflow::kNone);
  // 15. Let roundRecord be ? RoundDuration(unbalanceResult.[[Years]],
  // unbalanceResult.[[Months]], unbalanceResult.[[Weeks]],
  // balanceResult.[[Days]], balanceResult.[[Hours]], balanceResult.[[Minutes]],
  // balanceResult.[[Seconds]], balanceResult.[[Milliseconds]],
  // balanceResult.[[Microseconds]], balanceResult.[[Nanoseconds]], 1, unit,
  // "trunc", relativeTo).
  DurationRecordWithRemainder round_record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, round_record,
      RoundDuration(isolate,
                    {unbalance_result.years, unbalance_result.months,
                     unbalance_result.weeks, balance_result.value},
                    1, unit, RoundingMode::kTrunc, relative_to, method_name),
      Handle<Object>());
  // 16. Let roundResult be roundRecord.[[DurationRecord]].
  DurationRecord& round_result = round_record.record;

  double whole;
  switch (unit) {
    // 17. If unit is "year", then
    case Unit::kYear:
      // a. Let whole be roundResult.[[Years]].
      whole = round_result.years;
      break;
    // 18. If unit is "month", then
    case Unit::kMonth:
      // a. Let whole be roundResult.[[Months]].
      whole = round_result.months;
      break;
    // 19. If unit is "week", then
    case Unit::kWeek:
      // a. Let whole be roundResult.[[Weeks]].
      whole = round_result.weeks;
      break;
    // 20. If unit is "day", then
    case Unit::kDay:
      // a. Let whole be roundResult.[[Days]].
      whole = round_result.time_duration.days;
      break;
    // 21. If unit is "hour", then
    case Unit::kHour:
      // a. Let whole be roundResult.[[Hours]].
      whole = round_result.time_duration.hours;
      break;
    // 22. If unit is "minute", then
    case Unit::kMinute:
      // a. Let whole be roundResult.[[Minutes]].
      whole = round_result.time_duration.minutes;
      break;
    // 23. If unit is "second", then
    case Unit::kSecond:
      // a. Let whole be roundResult.[[Seconds]].
      whole = round_result.time_duration.seconds;
      break;
    // 24. If unit is "millisecond", then
    case Unit::kMillisecond:
      // a. Let whole be roundResult.[[Milliseconds]].
      whole = round_result.time_duration.milliseconds;
      break;
    // 25. If unit is "microsecond", then
    case Unit::kMicrosecond:
      // a. Let whole be roundResult.[[Microseconds]].
      whole = round_result.time_duration.microseconds;
      break;
    // 26. If unit is "naoosecond", then
    case Unit::kNanosecond:
      // a. Let whole be roundResult.[[Nanoseconds]].
      whole = round_result.time_duration.nanoseconds;
      break;
    default:
      UNREACHABLE();
  }
  // 27. Return 𝔽(whole + roundRecord.[[Remainder]]).
  return factory->NewNumber(whole + round_record.remainder);
}

namespace temporal {
// #sec-temporal-topartialduration
Maybe<DurationRecord> ToPartialDuration(
    Isolate* isolate, Handle<Object> temporal_duration_like_obj,
    const DurationRecord& input) {
  // 1. If Type(temporalDurationLike) is not Object, then
  if (!IsJSReceiver(*temporal_duration_like_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<DurationRecord>());
  }
  Handle<JSReceiver> temporal_duration_like =
      Cast<JSReceiver>(temporal_duration_like_obj);

  // 2. Let result be a new partial Duration Record with each field set to
  // undefined.
  DurationRecord result = input;

  // 3. Let any be false.
  bool any = false;

  // Table 8: Duration Record Fields
  // #table-temporal-duration-record-fields
  // 4. For each row of Table 8, except the header row, in table order, do
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
            // c. If val is not undefined, then
            if (!IsUndefined(*val)) {
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

  // 5. If any is false, then
  if (!any) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<DurationRecord>());
  }
  // 6. Return result.
  return Just(result);
}

}  // namespace temporal

// #sec-temporal.duration.prototype.with
MaybeHandle<JSTemporalDuration> JSTemporalDuration::With(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration,
    Handle<Object> temporal_duration_like) {
  DurationRecord partial;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, partial,
      temporal::ToPartialDuration(
          isolate, temporal_duration_like,
          {Object::NumberValue(duration->years()),
           Object::NumberValue(duration->months()),
           Object::NumberValue(duration->weeks()),
           {Object::NumberValue(duration->days()),
            Object::NumberValue(duration->hours()),
            Object::NumberValue(duration->minutes()),
            Object::NumberValue(duration->seconds()),
            Object::NumberValue(duration->milliseconds()),
            Object::NumberValue(duration->microseconds()),
            Object::NumberValue(duration->nanoseconds())}}),
      Handle<JSTemporalDuration>());

  // 24. Return ? CreateTemporalDuration(years, months, weeks, days, hours,
  // minutes, seconds, milliseconds, microseconds, nanoseconds).
  return CreateTemporalDuration(isolate, partial);
}

// #sec-get-temporal.duration.prototype.sign
MaybeHandle<Smi> JSTemporalDuration::Sign(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. Return ! DurationSign(duration.[[Years]], duration.[[Months]],
  // duration.[[Weeks]], duration.[[Days]], duration.[[Hours]],
  // duration.[[Minutes]], duration.[[Seconds]], duration.[[Milliseconds]],
  // duration.[[Microseconds]], duration.[[Nanoseconds]]).
  return handle(Smi::FromInt(DurationRecord::Sign(
                    {Object::NumberValue(duration->years()),
                     Object::NumberValue(duration->months()),
                     Object::NumberValue(duration->weeks()),
                     {Object::NumberValue(duration->days()),
                      Object::NumberValue(duration->hours()),
                      Object::NumberValue(duration->minutes()),
                      Object::NumberValue(duration->seconds()),
                      Object::NumberValue(duration->milliseconds()),
                      Object::NumberValue(duration->microseconds()),
                      Object::NumberValue(duration->nanoseconds())}})),
                isolate);
}

// #sec-get-temporal.duration.prototype.blank
MaybeHandle<Oddball> JSTemporalDuration::Blank(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. Let sign be ! DurationSign(duration.[[Years]], duration.[[Months]],
  // duration.[[Weeks]], duration.[[Days]], duration.[[Hours]],
  // duration.[[Minutes]], duration.[[Seconds]], duration.[[Milliseconds]],
  // duration.[[Microseconds]], duration.[[Nanoseconds]]).
  // 4. If sign = 0, return true.
  // 5. Return false.
  int32_t sign =
      DurationRecord::Sign({Object::NumberValue(duration->years()),
                            Object::NumberValue(duration->months()),
                            Object::NumberValue(duration->weeks()),
                            {Object::NumberValue(duration->days()),
                             Object::NumberValue(duration->hours()),
                             Object::NumberValue(duration->minutes()),
                             Object::NumberValue(duration->seconds()),
                             Object::NumberValue(duration->milliseconds()),
                             Object::NumberValue(duration->microseconds()),
                             Object::NumberValue(duration->nanoseconds())}});
  return isolate->factory()->ToBoolean(sign == 0);
}

namespace {
// #sec-temporal-createnegateddurationrecord
// see https://github.com/tc39/proposal-temporal/pull/2281
Maybe<DurationRecord> CreateNegatedDurationRecord(
    Isolate* isolate, const DurationRecord& duration) {
  return CreateDurationRecord(
      isolate,
      {-duration.years,
       -duration.months,
       -duration.weeks,
       {-duration.time_duration.days, -duration.time_duration.hours,
        -duration.time_duration.minutes, -duration.time_duration.seconds,
        -duration.time_duration.milliseconds,
        -duration.time_duration.microseconds,
        -duration.time_duration.nanoseconds}});
}

// #sec-temporal-createnegatedtemporalduration
MaybeHandle<JSTemporalDuration> CreateNegatedTemporalDuration(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: Type(duration) is Object.
  // 2. Assert: duration has an [[InitializedTemporalDuration]] internal slot.
  // 3. Return ! CreateTemporalDuration(−duration.[[Years]],
  // −duration.[[Months]], −duration.[[Weeks]], −duration.[[Days]],
  // −duration.[[Hours]], −duration.[[Minutes]], −duration.[[Seconds]],
  // −duration.[[Milliseconds]], −duration.[[Microseconds]],
  // −duration.[[Nanoseconds]]).
  return CreateTemporalDuration(
             isolate, {-Object::NumberValue(duration->years()),
                       -Object::NumberValue(duration->months()),
                       -Object::NumberValue(duration->weeks()),
                       {-Object::NumberValue(duration->days()),
                        -Object::NumberValue(duration->hours()),
                        -Object::NumberValue(duration->minutes()),
                        -Object::NumberValue(duration->seconds()),
                        -Object::NumberValue(duration->milliseconds()),
                        -Object::NumberValue(duration->microseconds()),
                        -Object::NumberValue(duration->nanoseconds())}})
      .ToHandleChecked();
}

}  // namespace

// #sec-temporal.duration.prototype.negated
MaybeHandle<JSTemporalDuration> JSTemporalDuration::Negated(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  // Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).

  // 3. Return ! CreateNegatedTemporalDuration(duration).
  return CreateNegatedTemporalDuration(isolate, duration).ToHandleChecked();
}

// #sec-temporal.duration.prototype.abs
MaybeHandle<JSTemporalDuration> JSTemporalDuration::Abs(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  // 1. Let duration
Prompt: 
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第11部分，共25部分，请归纳一下它的功能

"""
>months()),
                                 Object::NumberValue(duration->weeks()),
                                 Object::NumberValue(duration->days())},
                                largest_unit, relative_to, method_name),
      Handle<JSTemporalDuration>());
  // 22. Let roundResult be (? RoundDuration(unbalanceResult.[[Years]],
  // unbalanceResult.[[Months]], unbalanceResult.[[Weeks]],
  // unbalanceResult.[[Days]], duration.[[Hours]], duration.[[Minutes]],
  // duration.[[Seconds]], duration.[[Milliseconds]], duration.[[Microseconds]],
  // duration.[[Nanoseconds]], roundingIncrement, smallestUnit, roundingMode,
  // relativeTo)).[[DurationRecord]].
  DurationRecordWithRemainder round_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, round_result,
      RoundDuration(
          isolate,
          {unbalance_result.years,
           unbalance_result.months,
           unbalance_result.weeks,
           {unbalance_result.days, Object::NumberValue(duration->hours()),
            Object::NumberValue(duration->minutes()),
            Object::NumberValue(duration->seconds()),
            Object::NumberValue(duration->milliseconds()),
            Object::NumberValue(duration->microseconds()),
            Object::NumberValue(duration->nanoseconds())}},
          rounding_increment, smallest_unit, rounding_mode, relative_to,
          method_name),
      Handle<JSTemporalDuration>());

  // 23. Let adjustResult be ? AdjustRoundedDurationDays(roundResult.[[Years]],
  // roundResult.[[Months]], roundResult.[[Weeks]], roundResult.[[Days]],
  // roundResult.[[Hours]], roundResult.[[Minutes]], roundResult.[[Seconds]],
  // roundResult.[[Milliseconds]], roundResult.[[Microseconds]],
  // roundResult.[[Nanoseconds]], roundingIncrement, smallestUnit, roundingMode,
  // relativeTo).
  DurationRecord adjust_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, adjust_result,
      AdjustRoundedDurationDays(isolate, round_result.record,
                                rounding_increment, smallest_unit,
                                rounding_mode, relative_to, method_name),
      Handle<JSTemporalDuration>());
  // 24. Let balanceResult be ? BalanceDurationRelative(adjustResult.[[Years]],
  // adjustResult.[[Months]], adjustResult.[[Weeks]], adjustResult.[[Days]],
  // largestUnit, relativeTo).
  DateDurationRecord balance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, balance_result,
      BalanceDurationRelative(
          isolate,
          {adjust_result.years, adjust_result.months, adjust_result.weeks,
           adjust_result.time_duration.days},
          largest_unit, relative_to, method_name),
      Handle<JSTemporalDuration>());
  // 25. If Type(relativeTo) is Object and relativeTo has an
  // [[InitializedTemporalZonedDateTime]] internal slot, then
  if (IsJSTemporalZonedDateTime(*relative_to)) {
    // a. Set relativeTo to ? MoveRelativeZonedDateTime(relativeTo,
    // balanceResult.[[Years]], balanceResult.[[Months]],
    // balanceResult.[[Weeks]], 0).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, relative_to,
        MoveRelativeZonedDateTime(isolate,
                                  Cast<JSTemporalZonedDateTime>(relative_to),
                                  {balance_result.years, balance_result.months,
                                   balance_result.weeks, 0},
                                  method_name));
  }
  // 26. Let result be ? BalanceDuration(balanceResult.[[Days]],
  // adjustResult.[[Hours]], adjustResult.[[Minutes]], adjustResult.[[Seconds]],
  // adjustResult.[[Milliseconds]], adjustResult.[[Microseconds]],
  // adjustResult.[[Nanoseconds]], largestUnit, relativeTo).
  TimeDurationRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      BalanceDuration(isolate, largest_unit, relative_to,
                      {balance_result.days, adjust_result.time_duration.hours,
                       adjust_result.time_duration.minutes,
                       adjust_result.time_duration.seconds,
                       adjust_result.time_duration.milliseconds,
                       adjust_result.time_duration.microseconds,
                       adjust_result.time_duration.nanoseconds},
                      method_name),
      Handle<JSTemporalDuration>());
  // 27. Return ! CreateTemporalDuration(balanceResult.[[Years]],
  // balanceResult.[[Months]], balanceResult.[[Weeks]], result.[[Days]],
  // result.[[Hours]], result.[[Minutes]], result.[[Seconds]],
  // result.[[Milliseconds]], result.[[Microseconds]], result.[[Nanoseconds]]).
  return CreateTemporalDuration(isolate,
                                {balance_result.years, balance_result.months,
                                 balance_result.weeks, result})
      .ToHandleChecked();
}

// #sec-temporal.duration.prototype.total
MaybeHandle<Object> JSTemporalDuration::Total(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration,
    Handle<Object> total_of_obj) {
  const char* method_name = "Temporal.Duration.prototype.total";
  Factory* factory = isolate->factory();
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. If totalOf is undefined, throw a TypeError exception.
  if (IsUndefined(*total_of_obj, isolate)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }

  Handle<JSReceiver> total_of;
  // 4. If Type(totalOf) is String, then
  if (IsString(*total_of_obj)) {
    // a. Let paramString be totalOf.
    Handle<String> param_string = Cast<String>(total_of_obj);
    // b. Set totalOf to ! OrdinaryObjectCreate(null).
    total_of = factory->NewJSObjectWithNullProto();
    // c. Perform ! CreateDataPropertyOrThrow(total_of, "unit", paramString).
    CHECK(JSReceiver::CreateDataProperty(isolate, total_of,
                                         factory->unit_string(), param_string,
                                         Just(kThrowOnError))
              .FromJust());
  } else {
    // 5. Set totalOf to ? GetOptionsObject(totalOf).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, total_of,
        GetOptionsObject(isolate, total_of_obj, method_name));
  }

  // 6. Let relativeTo be ? ToRelativeTemporalObject(totalOf).
  Handle<Object> relative_to;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, relative_to,
      ToRelativeTemporalObject(isolate, total_of, method_name));
  // 7. Let unit be ? GetTemporalUnit(totalOf, "unit", datetime, required).
  Unit unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, unit,
      GetTemporalUnit(isolate, total_of, "unit", UnitGroup::kDateTime,
                      Unit::kNotPresent, true, method_name),
      Handle<Object>());
  // 8. Let unbalanceResult be ? UnbalanceDurationRelative(duration.[[Years]],
  // duration.[[Months]], duration.[[Weeks]], duration.[[Days]], unit,
  // relativeTo).
  DateDurationRecord unbalance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, unbalance_result,
      UnbalanceDurationRelative(isolate,
                                {Object::NumberValue(duration->years()),
                                 Object::NumberValue(duration->months()),
                                 Object::NumberValue(duration->weeks()),
                                 Object::NumberValue(duration->days())},
                                unit, relative_to, method_name),
      Handle<Object>());

  // 9. Let intermediate be undefined.
  Handle<Object> intermediate = factory->undefined_value();

  // 8. If relativeTo has an [[InitializedTemporalZonedDateTime]] internal slot,
  // then
  if (IsJSTemporalZonedDateTime(*relative_to)) {
    // a. Set intermediate to ? MoveRelativeZonedDateTime(relativeTo,
    // unbalanceResult.[[Years]], unbalanceResult.[[Months]],
    // unbalanceResult.[[Weeks]], 0).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, intermediate,
        MoveRelativeZonedDateTime(
            isolate, Cast<JSTemporalZonedDateTime>(relative_to),
            {unbalance_result.years, unbalance_result.months,
             unbalance_result.weeks, 0},
            method_name));
  }

  // 11. Let balanceResult be ?
  // BalancePossiblyInfiniteDuration(unbalanceResult.[[Days]],
  // duration.[[Hours]], duration.[[Minutes]], duration.[[Seconds]],
  // duration.[[Milliseconds]], duration.[[Microseconds]],
  // duration.[[Nanoseconds]], unit, intermediate).
  BalancePossiblyInfiniteDurationResult balance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, balance_result,
      BalancePossiblyInfiniteDuration(
          isolate, unit, intermediate,
          {unbalance_result.days, Object::NumberValue(duration->hours()),
           Object::NumberValue(duration->minutes()),
           Object::NumberValue(duration->seconds()),
           Object::NumberValue(duration->milliseconds()),
           Object::NumberValue(duration->microseconds()),
           Object::NumberValue(duration->nanoseconds())},
          method_name),
      Handle<Object>());
  // 12. If balanceResult is positive overflow, return +∞𝔽.
  if (balance_result.overflow == BalanceOverflow::kPositive) {
    return factory->infinity_value();
  }
  // 13. If balanceResult is negative overflow, return -∞𝔽.
  if (balance_result.overflow == BalanceOverflow::kNegative) {
    return factory->minus_infinity_value();
  }
  // 14. Assert: balanceResult is a Time Duration Record.
  DCHECK_EQ(balance_result.overflow, BalanceOverflow::kNone);
  // 15. Let roundRecord be ? RoundDuration(unbalanceResult.[[Years]],
  // unbalanceResult.[[Months]], unbalanceResult.[[Weeks]],
  // balanceResult.[[Days]], balanceResult.[[Hours]], balanceResult.[[Minutes]],
  // balanceResult.[[Seconds]], balanceResult.[[Milliseconds]],
  // balanceResult.[[Microseconds]], balanceResult.[[Nanoseconds]], 1, unit,
  // "trunc", relativeTo).
  DurationRecordWithRemainder round_record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, round_record,
      RoundDuration(isolate,
                    {unbalance_result.years, unbalance_result.months,
                     unbalance_result.weeks, balance_result.value},
                    1, unit, RoundingMode::kTrunc, relative_to, method_name),
      Handle<Object>());
  // 16. Let roundResult be roundRecord.[[DurationRecord]].
  DurationRecord& round_result = round_record.record;

  double whole;
  switch (unit) {
    // 17. If unit is "year", then
    case Unit::kYear:
      // a. Let whole be roundResult.[[Years]].
      whole = round_result.years;
      break;
    // 18. If unit is "month", then
    case Unit::kMonth:
      // a. Let whole be roundResult.[[Months]].
      whole = round_result.months;
      break;
    // 19. If unit is "week", then
    case Unit::kWeek:
      // a. Let whole be roundResult.[[Weeks]].
      whole = round_result.weeks;
      break;
    // 20. If unit is "day", then
    case Unit::kDay:
      // a. Let whole be roundResult.[[Days]].
      whole = round_result.time_duration.days;
      break;
    // 21. If unit is "hour", then
    case Unit::kHour:
      // a. Let whole be roundResult.[[Hours]].
      whole = round_result.time_duration.hours;
      break;
    // 22. If unit is "minute", then
    case Unit::kMinute:
      // a. Let whole be roundResult.[[Minutes]].
      whole = round_result.time_duration.minutes;
      break;
    // 23. If unit is "second", then
    case Unit::kSecond:
      // a. Let whole be roundResult.[[Seconds]].
      whole = round_result.time_duration.seconds;
      break;
    // 24. If unit is "millisecond", then
    case Unit::kMillisecond:
      // a. Let whole be roundResult.[[Milliseconds]].
      whole = round_result.time_duration.milliseconds;
      break;
    // 25. If unit is "microsecond", then
    case Unit::kMicrosecond:
      // a. Let whole be roundResult.[[Microseconds]].
      whole = round_result.time_duration.microseconds;
      break;
    // 26. If unit is "naoosecond", then
    case Unit::kNanosecond:
      // a. Let whole be roundResult.[[Nanoseconds]].
      whole = round_result.time_duration.nanoseconds;
      break;
    default:
      UNREACHABLE();
  }
  // 27. Return 𝔽(whole + roundRecord.[[Remainder]]).
  return factory->NewNumber(whole + round_record.remainder);
}

namespace temporal {
// #sec-temporal-topartialduration
Maybe<DurationRecord> ToPartialDuration(
    Isolate* isolate, Handle<Object> temporal_duration_like_obj,
    const DurationRecord& input) {
  // 1. If Type(temporalDurationLike) is not Object, then
  if (!IsJSReceiver(*temporal_duration_like_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<DurationRecord>());
  }
  Handle<JSReceiver> temporal_duration_like =
      Cast<JSReceiver>(temporal_duration_like_obj);

  // 2. Let result be a new partial Duration Record with each field set to
  // undefined.
  DurationRecord result = input;

  // 3. Let any be false.
  bool any = false;

  // Table 8: Duration Record Fields
  // #table-temporal-duration-record-fields
  // 4. For each row of Table 8, except the header row, in table order, do
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
            // c. If val is not undefined, then
            if (!IsUndefined(*val)) {
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

  // 5. If any is false, then
  if (!any) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<DurationRecord>());
  }
  // 6. Return result.
  return Just(result);
}

}  // namespace temporal

// #sec-temporal.duration.prototype.with
MaybeHandle<JSTemporalDuration> JSTemporalDuration::With(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration,
    Handle<Object> temporal_duration_like) {
  DurationRecord partial;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, partial,
      temporal::ToPartialDuration(
          isolate, temporal_duration_like,
          {Object::NumberValue(duration->years()),
           Object::NumberValue(duration->months()),
           Object::NumberValue(duration->weeks()),
           {Object::NumberValue(duration->days()),
            Object::NumberValue(duration->hours()),
            Object::NumberValue(duration->minutes()),
            Object::NumberValue(duration->seconds()),
            Object::NumberValue(duration->milliseconds()),
            Object::NumberValue(duration->microseconds()),
            Object::NumberValue(duration->nanoseconds())}}),
      Handle<JSTemporalDuration>());

  // 24. Return ? CreateTemporalDuration(years, months, weeks, days, hours,
  // minutes, seconds, milliseconds, microseconds, nanoseconds).
  return CreateTemporalDuration(isolate, partial);
}

// #sec-get-temporal.duration.prototype.sign
MaybeHandle<Smi> JSTemporalDuration::Sign(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. Return ! DurationSign(duration.[[Years]], duration.[[Months]],
  // duration.[[Weeks]], duration.[[Days]], duration.[[Hours]],
  // duration.[[Minutes]], duration.[[Seconds]], duration.[[Milliseconds]],
  // duration.[[Microseconds]], duration.[[Nanoseconds]]).
  return handle(Smi::FromInt(DurationRecord::Sign(
                    {Object::NumberValue(duration->years()),
                     Object::NumberValue(duration->months()),
                     Object::NumberValue(duration->weeks()),
                     {Object::NumberValue(duration->days()),
                      Object::NumberValue(duration->hours()),
                      Object::NumberValue(duration->minutes()),
                      Object::NumberValue(duration->seconds()),
                      Object::NumberValue(duration->milliseconds()),
                      Object::NumberValue(duration->microseconds()),
                      Object::NumberValue(duration->nanoseconds())}})),
                isolate);
}

// #sec-get-temporal.duration.prototype.blank
MaybeHandle<Oddball> JSTemporalDuration::Blank(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. Let sign be ! DurationSign(duration.[[Years]], duration.[[Months]],
  // duration.[[Weeks]], duration.[[Days]], duration.[[Hours]],
  // duration.[[Minutes]], duration.[[Seconds]], duration.[[Milliseconds]],
  // duration.[[Microseconds]], duration.[[Nanoseconds]]).
  // 4. If sign = 0, return true.
  // 5. Return false.
  int32_t sign =
      DurationRecord::Sign({Object::NumberValue(duration->years()),
                            Object::NumberValue(duration->months()),
                            Object::NumberValue(duration->weeks()),
                            {Object::NumberValue(duration->days()),
                             Object::NumberValue(duration->hours()),
                             Object::NumberValue(duration->minutes()),
                             Object::NumberValue(duration->seconds()),
                             Object::NumberValue(duration->milliseconds()),
                             Object::NumberValue(duration->microseconds()),
                             Object::NumberValue(duration->nanoseconds())}});
  return isolate->factory()->ToBoolean(sign == 0);
}

namespace {
// #sec-temporal-createnegateddurationrecord
// see https://github.com/tc39/proposal-temporal/pull/2281
Maybe<DurationRecord> CreateNegatedDurationRecord(
    Isolate* isolate, const DurationRecord& duration) {
  return CreateDurationRecord(
      isolate,
      {-duration.years,
       -duration.months,
       -duration.weeks,
       {-duration.time_duration.days, -duration.time_duration.hours,
        -duration.time_duration.minutes, -duration.time_duration.seconds,
        -duration.time_duration.milliseconds,
        -duration.time_duration.microseconds,
        -duration.time_duration.nanoseconds}});
}

// #sec-temporal-createnegatedtemporalduration
MaybeHandle<JSTemporalDuration> CreateNegatedTemporalDuration(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: Type(duration) is Object.
  // 2. Assert: duration has an [[InitializedTemporalDuration]] internal slot.
  // 3. Return ! CreateTemporalDuration(−duration.[[Years]],
  // −duration.[[Months]], −duration.[[Weeks]], −duration.[[Days]],
  // −duration.[[Hours]], −duration.[[Minutes]], −duration.[[Seconds]],
  // −duration.[[Milliseconds]], −duration.[[Microseconds]],
  // −duration.[[Nanoseconds]]).
  return CreateTemporalDuration(
             isolate, {-Object::NumberValue(duration->years()),
                       -Object::NumberValue(duration->months()),
                       -Object::NumberValue(duration->weeks()),
                       {-Object::NumberValue(duration->days()),
                        -Object::NumberValue(duration->hours()),
                        -Object::NumberValue(duration->minutes()),
                        -Object::NumberValue(duration->seconds()),
                        -Object::NumberValue(duration->milliseconds()),
                        -Object::NumberValue(duration->microseconds()),
                        -Object::NumberValue(duration->nanoseconds())}})
      .ToHandleChecked();
}

}  // namespace

// #sec-temporal.duration.prototype.negated
MaybeHandle<JSTemporalDuration> JSTemporalDuration::Negated(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  // Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).

  // 3. Return ! CreateNegatedTemporalDuration(duration).
  return CreateNegatedTemporalDuration(isolate, duration).ToHandleChecked();
}

// #sec-temporal.duration.prototype.abs
MaybeHandle<JSTemporalDuration> JSTemporalDuration::Abs(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration) {
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. Return ? CreateTemporalDuration(abs(duration.[[Years]]),
  // abs(duration.[[Months]]), abs(duration.[[Weeks]]), abs(duration.[[Days]]),
  // abs(duration.[[Hours]]), abs(duration.[[Minutes]]),
  // abs(duration.[[Seconds]]), abs(duration.[[Milliseconds]]),
  // abs(duration.[[Microseconds]]), abs(duration.[[Nanoseconds]])).
  return CreateTemporalDuration(
      isolate, {std::abs(Object::NumberValue(duration->years())),
                std::abs(Object::NumberValue(duration->months())),
                std::abs(Object::NumberValue(duration->weeks())),
                {std::abs(Object::NumberValue(duration->days())),
                 std::abs(Object::NumberValue(duration->hours())),
                 std::abs(Object::NumberValue(duration->minutes())),
                 std::abs(Object::NumberValue(duration->seconds())),
                 std::abs(Object::NumberValue(duration->milliseconds())),
                 std::abs(Object::NumberValue(duration->microseconds())),
                 std::abs(Object::NumberValue(duration->nanoseconds()))}});
}

namespace {

// #sec-temporal-interpretisodatetimeoffset
MaybeHandle<BigInt> InterpretISODateTimeOffset(
    Isolate* isolate, const DateTimeRecord& data,
    OffsetBehaviour offset_behaviour, int64_t offset_nanoseconds,
    Handle<JSReceiver> time_zone, Disambiguation disambiguation,
    Offset offset_option, MatchBehaviour match_behaviour,
    const char* method_name);

// #sec-temporal-interprettemporaldatetimefields
Maybe<temporal::DateTimeRecord> InterpretTemporalDateTimeFields(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<JSReceiver> fields,
    Handle<Object> options, const char* method_name);

// #sec-temporal-torelativetemporalobject
MaybeHandle<Object> ToRelativeTemporalObject(Isolate* isolate,
                                             Handle<JSReceiver> options,
                                             const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 1. Assert: Type(options) is Object.
  // 2. Let value be ? Get(options, "relativeTo").
  Handle<Object> value_obj;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, value_obj,
      JSReceiver::GetProperty(isolate, options, factory->relativeTo_string()));
  // 3. If value is undefined, then
  if (IsUndefined(*value_obj)) {
    // a. Return value.
    return value_obj;
  }
  // 4. Let offsetBehaviour be option.
  OffsetBehaviour offset_behaviour = OffsetBehaviour::kOption;

  // 5. Let matchBehaviour be match exactly.
  MatchBehaviour match_behaviour = MatchBehaviour::kMatchExactly;

  Handle<Object> time_zone_obj = factory->undefined_value();
  Handle<Object> offset_string_obj;
  temporal::DateTimeRecord result;
  Handle<JSReceiver> calendar;
  // 6. If Type(value) is Object, then
  if (IsJSReceiver(*value_obj)) {
    Handle<JSReceiver> value = Cast<JSReceiver>(value_obj);
    // a. If value has either an [[InitializedTemporalDate]] or
    // [[InitializedTemporalZonedDateTime]] internal slot, then
    if (IsJSTemporalPlainDate(*value) || IsJSTemporalZonedDateTime(*value)) {
      // i. Return value.
      return value;
    }
    // b. If value has an [[InitializedTemporalDateTime]] internal slot, then
    if (IsJSTemporalPlainDateTime(*value)) {
      auto date_time_value = Cast<JSTemporalPlainDateTime>(value);
      // i. Return ? CreateTemporalDateTime(value.[[ISOYear]],
      // value.[[ISOMonth]], value.[[ISODay]],
      // value.[[Calendar]]).
      return CreateTemporalDate(
          isolate,
          {date_time_value->iso_year(), date_time_value->iso_month(),
           date_time_value->iso_day()},
          handle(date_time_value->calendar(), isolate));
    }
    // c. Let calendar be ? GetTemporalCalendarWithISODefault(value).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        GetTemporalCalendarWithISODefault(isolate, value, method_name));
    // d. Let fieldNames be ? CalendarFields(calendar, «  "day", "hour",
    // "microsecond", "millisecond", "minute", "month", "monthCode",
    // "nanosecond", "second", "year" »).
    Handle<FixedArray> field_names = All10UnitsInFixedArray(isolate);
    ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                               CalendarFields(isolate, calendar, field_names));
    // e. Let fields be ? PrepareTemporalFields(value, fieldNames, «»).
    Handle<JSReceiver> fields;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, fields,
        PrepareTemporalFields(isolate, value, field_names,
                              RequiredFields::kNone));
    // f. Let dateOptions be ! OrdinaryObjectCreate(null).
    Handle<JSObject> date_options = factory->NewJSObjectWithNullProto();
    // g. Perform ! CreateDataPropertyOrThrow(dateOptions, "overflow",
    // "constrain").
    CHECK(JSReceiver::CreateDataProperty(
              isolate, date_options, factory->overflow_string(),
              factory->constrain_string(), Just(kThrowOnError))
              .FromJust());
    // h. Let result be ? InterpretTemporalDateTimeFields(calendar, fields,
    // dateOptions).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        InterpretTemporalDateTimeFields(isolate, calendar, fields, date_options,
                                        method_name),
        Handle<Object>());
    // i. Let offsetString be ? Get(value, "offset").
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, offset_string_obj,
        JSReceiver::GetProperty(isolate, value, factory->offset_string()));
    // j. Let timeZone be ? Get(value, "timeZone").
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone_obj,
        JSReceiver::GetProperty(isolate, value, factory->timeZone_string()));
    // k. If timeZone is not undefined, then
    if (!IsUndefined(*time_zone_obj)) {
      // i. Set timeZone to ? ToTemporalTimeZone(timeZone).
      Handle<JSReceiver> time_zone;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, time_zone,
          temporal::ToTemporalTimeZone(isolate, time_zone_obj, method_name));
      time_zone_obj = time_zone;
    }

    // l. If offsetString is undefined, then
    if (IsUndefined(*offset_string_obj)) {
      // i. Set offsetBehaviour to wall.
      offset_behaviour = OffsetBehaviour::kWall;
    }
    // 6. Else,
  } else {
    // a. Let string be ? ToString(value).
    Handle<String> string;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, string,
                               Object::ToString(isolate, value_obj));
    DateTimeRecordWithCalendar parsed_result;
    // b. Let result be ? ParseTemporalRelativeToString(string).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, parsed_result, ParseTemporalRelativeToString(isolate, string),
        Handle<Object>());
    result = {parsed_result.date, parsed_result.time};
    // c. Let calendar be ?
    // ToTemporalCalendarWithISODefault(result.[[Calendar]]).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        ToTemporalCalendarWithISODefault(isolate, parsed_result.calendar,
                                         method_name));

    // d. Let offsetString be result.[[TimeZone]].[[OffsetString]].
    offset_string_obj = parsed_result.time_zone.offset_string;

    // e. Let timeZoneName be result.[[TimeZone]].[[Name]].
    Handle<Object> time_zone_name_obj = parsed_result.time_zone.name;

    // f. If timeZoneName is undefined, then
    if (IsUndefined(*time_zone_name_obj)) {
      // i. Let timeZone be undefined.
      time_zone_obj = factory->undefined_value();
      // g. Else,
    } else {
      // i. If ParseText(StringToCodePoints(timeZoneName),
      // TimeZoneNumericUTCOffset) is a List of errors, then
      DCHECK(IsString(*time_zone_name_obj));
      Handle<String> time_zone_name = Cast<String>(time_zone_name_obj);
      std::optional<ParsedISO8601Result> parsed =
          TemporalParser::ParseTimeZoneNumericUTCOffset(isolate,
                                                        time_zone_name);
      if (!parsed.has_value()) {
        // 1. If ! IsValidTimeZoneName(timeZoneName) is false, throw a
        // RangeError exception.
        if (!IsValidTimeZoneName(isolate, time_zone_name)) {
          THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                       NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                       Handle<Object>());
        }
        // 2. Set timeZoneName to ! CanonicalizeTimeZoneName(timeZoneName).
        time_zone_name = CanonicalizeTimeZoneName(isolate, time_zone_name);
      }
      // ii. Let timeZone be ! CreateTemporalTimeZone(timeZoneName).
      Handle<JSTemporalTimeZone> time_zone =
          temporal::CreateTemporalTimeZone(isolate, time_zone_name)
              .ToHandleChecked();
      time_zone_obj = time_zone;

      // iii. If result.[[TimeZone]].[[Z]] is true, then
      if (parsed_result.time_zone.z) {
        // 1. Set offsetBehaviour to exact.
        offset_behaviour = OffsetBehaviour::kExact;
        // iv. Else if offsetString is undefined, then
      } else if (IsUndefined(*offset_string_obj)) {
        // 1. Set offsetBehaviour to wall.
        offset_behaviour = OffsetBehaviour::kWall;
      }
      // v. Set matchBehaviour to match minutes.
      match_behaviour = MatchBehaviour::kMatchMinutes;
    }
  }
  // 8. If timeZone is undefined, then
  if (IsUndefined(*time_zone_obj)) {
    // a. Return ? CreateTemporalDate(result.[[Year]], result.[[Month]],
    // result.[[Day]], calendar).
    return CreateTemporalDate(isolate, result.date, calendar);
  }
  DCHECK(IsJSReceiver(*time_zone_obj));
  Handle<JSReceiver> time_zone = Cast<JSReceiver>(time_zone_obj);
  // 9. If offsetBehaviour is option, then
  int64_t offset_ns = 0;
  if (offset_behaviour == OffsetBehaviour::kOption) {
    // a. Set offsetString to ? ToString(offsetString).
    Handle<String> offset_string;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, offset_string,
                               Object::ToString(isolate, offset_string_obj));
    // b. Let offsetNs be ? ParseTimeZoneOffsetString(offset_string).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, offset_ns, ParseTimeZoneOffsetString(isolate, offset_string),
        Handle<Object>());
    // 10. Else,
  } else {
    // a. Let offsetNs be 0.
    offset_ns = 0;
  }
  // 11. Let epochNanoseconds be ? InterpretISODateTimeOffset(result.[[Year]],
  // result.[[Month]], result.[[Day]], result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]], offsetBehaviour, offsetNs, timeZone, "compatible",
  // "reject", matchBehaviour).
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, epoch_nanoseconds,
      InterpretISODateTimeOffset(isolate, result, offset_behaviour, offset_ns,
                                 time_zone, Disambiguation::kCompatible,
                                 Offset::kReject, match_behaviour,
                                 method_name));

  // 12. Return ? CreateTemporalZonedDateTime(epochNanoseconds, timeZone,
  // calendar).
  return CreateTemporalZonedDateTime(isolate, epoch_nanoseconds, time_zone,
                                     calendar);
}

// #sec-temporal-defaulttemporallargestunit
Unit DefaultTemporalLargestUnit(const DurationRecord& dur) {
  // 1. If years is not zero, return "year".
  if (dur.yea
"""


```