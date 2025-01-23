Response: The user wants a summary of the C++ source code file `v8/src/objects/js-temporal-objects.cc`.
This is the 8th part of a 13-part file, suggesting it's a large file dealing with JavaScript's Temporal API implementation in V8.

Here's a breakdown of how to approach this:

1. **Identify the primary purpose:** The filename suggests it's related to "Temporal" objects. The code confirms this by implementing functionalities for `Temporal.Calendar`, `Temporal.TimeZone`, and `Temporal.PlainDate`.

2. **Analyze the code blocks:**  Go through each function and identify the JavaScript API it's implementing. Look for keywords like "prototype", "constructor", and the specific Temporal object names.

3. **Group related functionalities:**  Organize the findings based on the Temporal object they belong to (Calendar, TimeZone, PlainDate).

4. **Describe the functionality of each group:**  Summarize what each group of functions does in terms of the Temporal API.

5. **Illustrate with JavaScript examples:** For each group, provide a concise JavaScript example that uses the corresponding Temporal API feature.

6. **Consider the "part 8 of 13" aspect:** Since it's a part of a larger file, acknowledge that this file likely handles a subset of the overall Temporal API implementation.

**Pre-computation/Analysis of the provided code:**

* **`JSTemporalCalendar`:**  This section implements methods of `Temporal.Calendar.prototype`, like `dateFromFields`, `yearMonthFromFields`, `day`, `month`, `monthCode`, `weekOfYear`, `toString`. It also includes stubs for `era` and `eraYear` (likely for non-ISO calendars).
* **`JSTemporalTimeZone`:** This section covers methods of `Temporal.TimeZone`, such as the constructor, `now`, `getInstantFor`, `getPlainDateTimeFor`, `getNextTransition`, `getPreviousTransition`, `getPossibleInstantsFor`, `getOffsetNanosecondsFor`, `getOffsetStringFor`, `toString`.
* **`JSTemporalPlainDate`:** This section deals with `Temporal.PlainDate` methods like the constructor, `compare`, `equals`, `withCalendar`, `toPlainYearMonth`, `toPlainMonthDay`, `toPlainDateTime`, `toZonedDateTime`, `add`, `subtract`, `until`, `since`, `now`, `nowISO`, and `from`. It also contains internal helper functions like `RejectObjectWithCalendarOrTimeZone`, `CalendarMergeFields`, and `PlainDateOrYearMonthOrMonthDayWith`.

Now, let's construct the summary based on this analysis.这个C++源代码文件 `v8/src/objects/js-temporal-objects.cc` 是V8引擎中实现 **JavaScript Temporal API** 的一部分，具体来说，这个第8部分主要负责实现以下几个核心的 **Temporal** 对象的功能：

1. **`Temporal.Calendar` 原型对象的方法:**  这个部分实现了 `Temporal.Calendar.prototype` 上的一些方法，用于处理日期和月份相关的计算和属性获取。
2. **`Temporal.TimeZone` 构造函数和原型对象的方法:**  这部分实现了 `Temporal.TimeZone` 构造函数以及其原型对象上的方法，用于处理时区相关的操作，例如获取特定时间的 Instant，获取特定 Instant 的 LocalDateTime 等。
3. **`Temporal.PlainDate` 构造函数和原型对象的方法:** 这部分实现了 `Temporal.PlainDate` 构造函数及其原型对象上的方法，用于处理不带时区的日期。

由于这是第8部分，可以推断出其他部分会实现 Temporal API 的其他对象，例如 `Temporal.PlainTime`, `Temporal.PlainDateTime`, `Temporal.Instant`, `Temporal.Duration` 等。

下面分别用 JavaScript 举例说明这些功能：

**1. `Temporal.Calendar` 的功能示例：**

这个文件中的代码实现了 `Temporal.Calendar` 的部分方法，例如 `day`, `month`, `monthCode` 等。

```javascript
const calendar = new Temporal.Calendar('iso8601');
const date = new Temporal.PlainDate(2023, 10, 26);

console.log(calendar.day(date)); // 获取日期中的日： 26
console.log(calendar.month(date)); // 获取日期中的月份： 10
console.log(calendar.monthCode(date)); // 获取日期中的月份代码： "M10"

const date1 = new Temporal.PlainDate(2023, 10, 26);
const date2 = new Temporal.PlainDate(2023, 11, 15);
const duration = calendar.dateUntil(date1, date2);
console.log(duration); // 计算两个日期之间的差值，结果是一个 Temporal.Duration 对象
```

**2. `Temporal.TimeZone` 的功能示例：**

这个文件实现了 `Temporal.TimeZone` 的构造和部分原型方法，例如 `now`, `getInstantFor`, `getPlainDateTimeFor` 等。

```javascript
const timeZone = new Temporal.TimeZone('America/Los_Angeles');
const now = Temporal.Now.instant();

console.log(timeZone.getPlainDateTimeFor(now)); // 获取当前 Instant 在洛杉矶时区的本地日期和时间

const dateTime = new Temporal.PlainDateTime(2023, 10, 26, 10, 30, 0);
const instant = timeZone.getInstantFor(dateTime);
console.log(instant); // 获取特定本地日期时间在洛杉矶时区对应的 Instant

const nextTransition = timeZone.getNextTransition(now);
console.log(nextTransition); // 获取洛杉矶时区在当前时间之后的下一个夏令时转换点
```

**3. `Temporal.PlainDate` 的功能示例：**

这个文件实现了 `Temporal.PlainDate` 的构造函数和一些原型方法，例如 `compare`, `equals`, `add`, `subtract` 等。

```javascript
const date1 = new Temporal.PlainDate(2023, 10, 26);
const date2 = new Temporal.PlainDate(2023, 11, 15);

console.log(Temporal.PlainDate.compare(date1, date2)); // 比较两个日期： -1 (date1 在 date2 之前)
console.log(date1.equals(date2)); // 检查两个日期是否相等： false

const duration = new Temporal.Duration(0, 1, 0); // 1个月
const futureDate = date1.add(duration);
console.log(futureDate.toString()); // "2023-11-26"

const pastDate = date2.subtract(duration);
console.log(pastDate.toString()); // "2023-10-15"

console.log(date1.until(date2)); // 计算 date1 到 date2 的持续时间
console.log(date2.since(date1)); // 计算 date2 自 date1 以来的持续时间

const today = Temporal.Now.plainDateISO();
console.log(today.toString()); // 获取今天的 ISO 格式日期 (不带时区)
```

**总结:**

总而言之，`v8/src/objects/js-temporal-objects.cc` 的第8部分专注于实现 JavaScript **Temporal API** 中 `Temporal.Calendar`, `Temporal.TimeZone`, 和 `Temporal.PlainDate` 这几个核心对象的关键功能。它处理了日历相关的计算、时区转换以及不带时区的日期操作，是 V8 引擎支持现代日期和时间处理的重要组成部分。 由于是多部分文件，可以预见其他部分会处理 Temporal API 的其他时间单位和组合，例如时间和带时区的日期时间等。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第8部分，共13部分，请归纳一下它的功能
```

### 源代码
```
j, method_name));
  // 5. Set two to ? ToTemporalDate(two).
  Handle<JSTemporalPlainDate> two;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, two,
                             ToTemporalDate(isolate, two_obj, method_name));
  // 6. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 7. Let largestUnit be ? GetTemporalUnit(options, "largestUnit", date,
  // "auto").
  Unit largest_unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, largest_unit,
      GetTemporalUnit(isolate, options, "largestUnit", UnitGroup::kDate,
                      Unit::kAuto, false, method_name),
      Handle<JSTemporalDuration>());
  // 8. If largestUnit is "auto", set largestUnit to "day".
  if (largest_unit == Unit::kAuto) largest_unit = Unit::kDay;

  // 9. Let result be ! DifferenceISODate(one.[[ISOYear]], one.[[ISOMonth]],
  // one.[[ISODay]], two.[[ISOYear]], two.[[ISOMonth]], two.[[ISODay]],
  // largestUnit).
  DateDurationRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      DifferenceISODate(isolate,
                        {one->iso_year(), one->iso_month(), one->iso_day()},
                        {two->iso_year(), two->iso_month(), two->iso_day()},
                        largest_unit, method_name),
      Handle<JSTemporalDuration>());

  // 10. Return ! CreateTemporalDuration(result.[[Years]], result.[[Months]],
  // result.[[Weeks]], result.[[Days]], 0, 0, 0, 0, 0, 0).
  return CreateTemporalDuration(isolate, {result.years,
                                          result.months,
                                          result.weeks,
                                          {result.days, 0, 0, 0, 0, 0, 0}})
      .ToHandleChecked();
}

// #sec-temporal.calendar.prototype.day
MaybeHandle<Smi> JSTemporalCalendar::Day(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]] or [[InitializedTemporalMonthDay]]
  // internal slot, then
  if (!(IsJSTemporalPlainDate(*temporal_date_like) ||
        IsJSTemporalPlainDateTime(*temporal_date_like) ||
        IsJSTemporalPlainMonthDay(*temporal_date_like))) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.day"));
  }

  // 5. Let day be ! ISODay(temporalDateLike).
  int32_t day;
  if (IsJSTemporalPlainDate(*temporal_date_like)) {
    day = Cast<JSTemporalPlainDate>(temporal_date_like)->iso_day();
  } else if (IsJSTemporalPlainDateTime(*temporal_date_like)) {
    day = Cast<JSTemporalPlainDateTime>(temporal_date_like)->iso_day();
  } else {
    DCHECK(IsJSTemporalPlainMonthDay(*temporal_date_like));
    day = Cast<JSTemporalPlainMonthDay>(temporal_date_like)->iso_day();
  }

  // 6. Return 𝔽(day).
  return handle(Smi::FromInt(day), isolate);
}

// #sec-temporal.calendar.prototype.monthcode
MaybeHandle<String> JSTemporalCalendar::MonthCode(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]], [[InitializedTemporalDateTime]],
  // [[InitializedTemporalMonthDay]], or
  // [[InitializedTemporalYearMonth]] internal slot, then
  if (!(IsPlainDatePlainDateTimeOrPlainYearMonth(temporal_date_like) ||
        IsJSTemporalPlainMonthDay(*temporal_date_like))) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.monthCode"));
  }

  // 5. Return ! ISOMonthCode(temporalDateLike).
  int32_t month;
  if (IsJSTemporalPlainDate(*temporal_date_like)) {
    month = Cast<JSTemporalPlainDate>(temporal_date_like)->iso_month();
  } else if (IsJSTemporalPlainDateTime(*temporal_date_like)) {
    month = Cast<JSTemporalPlainDateTime>(temporal_date_like)->iso_month();
  } else if (IsJSTemporalPlainMonthDay(*temporal_date_like)) {
    month = Cast<JSTemporalPlainMonthDay>(temporal_date_like)->iso_month();
  } else {
    DCHECK(IsJSTemporalPlainYearMonth(*temporal_date_like));
    month = Cast<JSTemporalPlainYearMonth>(temporal_date_like)->iso_month();
  }
  IncrementalStringBuilder builder(isolate);
  builder.AppendCharacter('M');
  if (month < 10) {
    builder.AppendCharacter('0');
  }
  builder.AppendInt(month);

  return indirect_handle(builder.Finish(), isolate);
}

// #sec-temporal.calendar.prototype.month
MaybeHandle<Smi> JSTemporalCalendar::Month(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 4. If Type(temporalDateLike) is Object and temporalDateLike has an
  // [[InitializedTemporalMonthDay]] internal slot, then
  if (IsJSTemporalPlainMonthDay(*temporal_date_like)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  // 5. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]], [[InitializedTemporalDateTime]],
  // or [[InitializedTemporalYearMonth]]
  // internal slot, then
  if (!IsPlainDatePlainDateTimeOrPlainYearMonth(temporal_date_like)) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.month"));
  }

  // 6. Return ! ISOMonth(temporalDateLike).
  int32_t month;
  if (IsJSTemporalPlainDate(*temporal_date_like)) {
    month = Cast<JSTemporalPlainDate>(temporal_date_like)->iso_month();
  } else if (IsJSTemporalPlainDateTime(*temporal_date_like)) {
    month = Cast<JSTemporalPlainDateTime>(temporal_date_like)->iso_month();
  } else {
    DCHECK(IsJSTemporalPlainYearMonth(*temporal_date_like));
    month = Cast<JSTemporalPlainYearMonth>(temporal_date_like)->iso_month();
  }

  // 7. Return 𝔽(month).
  return handle(Smi::FromInt(month), isolate);
}

// #sec-temporal.calendar.prototype.monthdayfromfields
MaybeHandle<JSTemporalPlainMonthDay> JSTemporalCalendar::MonthDayFromFields(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> fields_obj, Handle<Object> options_obj) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  const char* method_name = "Temporal.Calendar.prototype.monthDayFromFields";
  // 4. If Type(fields) is not Object, throw a TypeError exception.
  if (!IsJSReceiver(*fields_obj)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kCalledOnNonObject,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }
  Handle<JSReceiver> fields = Cast<JSReceiver>(fields_obj);
  // 5. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 6. Let result be ? ISOMonthDayFromFields(fields, options).
  if (calendar->calendar_index() == 0) {
    DateRecord result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        ISOMonthDayFromFields(isolate, fields, options, method_name),
        Handle<JSTemporalPlainMonthDay>());
    // 7. Return ? CreateTemporalMonthDay(result.[[Month]], result.[[Day]],
    // calendar, result.[[ReferenceISOYear]]).
    return CreateTemporalMonthDay(isolate, result.month, result.day, calendar,
                                  result.year);
  }
  // TODO(ftang) add intl code inside #ifdef V8_INTL_SUPPORT
  UNREACHABLE();
}

// #sec-temporal.calendar.prototype.yearmonthfromfields
MaybeHandle<JSTemporalPlainYearMonth> JSTemporalCalendar::YearMonthFromFields(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> fields_obj, Handle<Object> options_obj) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  const char* method_name = "Temporal.Calendar.prototype.yearMonthFromFields";
  // 4. If Type(fields) is not Object, throw a TypeError exception.
  if (!IsJSReceiver(*fields_obj)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kCalledOnNonObject,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }
  Handle<JSReceiver> fields = Cast<JSReceiver>(fields_obj);
  // 5. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 6. Let result be ? ISOYearMonthFromFields(fields, options).
  if (calendar->calendar_index() == 0) {
    DateRecord result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        ISOYearMonthFromFields(isolate, fields, options, method_name),
        Handle<JSTemporalPlainYearMonth>());
    // 7. Return ? CreateTemporalYearMonth(result.[[Year]], result.[[Month]],
    // calendar, result.[[ReferenceISODay]]).
    return CreateTemporalYearMonth(isolate, result.year, result.month, calendar,
                                   result.day);
  }
  // TODO(ftang) add intl code inside #ifdef V8_INTL_SUPPORT
  UNREACHABLE();
}

#ifdef V8_INTL_SUPPORT
// #sup-temporal.calendar.prototype.era
MaybeHandle<Object> JSTemporalCalendar::Era(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]], [[InitializedTemporalDateTime]],
  // or [[InitializedTemporalYearMonth]]
  // internal slot, then
  if (!IsPlainDatePlainDateTimeOrPlainYearMonth(temporal_date_like)) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.era"));
  }
  // 4. If calendar.[[Identifier]] is "iso8601", then
  if (calendar->calendar_index() == 0) {
    // a. Return undefined.
    return isolate->factory()->undefined_value();
  }
  UNIMPLEMENTED();
  // TODO(ftang) implement other calendars
  // 5. Return ! CalendarDateEra(calendar.[[Identifier]], temporalDateLike).
}

// #sup-temporal.calendar.prototype.erayear
MaybeHandle<Object> JSTemporalCalendar::EraYear(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. If Type(temporalDateLike) is not Object or temporalDateLike does not
  // have an [[InitializedTemporalDate]], [[InitializedTemporalDateTime]],
  // or [[InitializedTemporalYearMonth]]
  // internal slot, then
  if (!IsPlainDatePlainDateTimeOrPlainYearMonth(temporal_date_like)) {
    // a. Set temporalDateLike to ? ToTemporalDate(temporalDateLike).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_like,
        ToTemporalDate(isolate, temporal_date_like,
                       "Temporal.Calendar.prototype.eraYear"));
  }
  // 4. If calendar.[[Identifier]] is "iso8601", then
  if (calendar->calendar_index() == 0) {
    // a. Return undefined.
    return isolate->factory()->undefined_value();
  }
  UNIMPLEMENTED();
  // TODO(ftang) implement other calendars
  // 5. Let eraYear be ! CalendarDateEraYear(calendar.[[Identifier]],
  // temporalDateLike).
  // 6. If eraYear is undefined, then
  // a. Return undefined.
  // 7. Return 𝔽(eraYear).
}

#endif  // V8_INTL_SUPPORT

// #sec-temporal.calendar.prototype.weekofyear
MaybeHandle<Smi> JSTemporalCalendar::WeekOfYear(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    Handle<Object> temporal_date_like) {
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  // 3. Assert: calendar.[[Identifier]] is "iso8601".
  // 4. Let temporalDate be ? ToTemporalDate(temporalDateLike).
  Handle<JSTemporalPlainDate> temporal_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date,
      ToTemporalDate(isolate, temporal_date_like,
                     "Temporal.Calendar.prototype.weekOfYear"));
  // a. Let value be ! ToISOWeekOfYear(temporalDate.[[ISOYear]],
  // temporalDate.[[ISOMonth]], temporalDate.[[ISODay]]).
  int32_t value = ToISOWeekOfYear(
      isolate, {temporal_date->iso_year(), temporal_date->iso_month(),
                temporal_date->iso_day()});
  return handle(Smi::FromInt(value), isolate);
}

// #sec-temporal.calendar.prototype.tostring
MaybeHandle<String> JSTemporalCalendar::ToString(
    Isolate* isolate, DirectHandle<JSTemporalCalendar> calendar,
    const char* method_name) {
  return CalendarIdentifier(isolate, calendar->calendar_index());
}

// #sec-temporal.now.timezone
MaybeHandle<JSTemporalTimeZone> JSTemporalTimeZone::Now(Isolate* isolate) {
  return SystemTimeZone(isolate);
}

// #sec-temporal.timezone
MaybeHandle<JSTemporalTimeZone> JSTemporalTimeZone::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> identifier_obj) {
  // 1. If NewTarget is undefined, then
  if (IsUndefined(*new_target, isolate)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kConstructorNotFunction,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     "Temporal.TimeZone")));
  }
  // 2. Set identifier to ? ToString(identifier).
  Handle<String> identifier;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, identifier,
                             Object::ToString(isolate, identifier_obj));
  Handle<String> canonical;
  // 3. If identifier satisfies the syntax of a TimeZoneNumericUTCOffset
  // (see 13.33), then
  if (IsValidTimeZoneNumericUTCOffsetString(isolate, identifier)) {
    // a. Let offsetNanoseconds be ? ParseTimeZoneOffsetString(identifier).
    int64_t offset_nanoseconds;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, offset_nanoseconds,
        ParseTimeZoneOffsetString(isolate, identifier),
        Handle<JSTemporalTimeZone>());

    // b. Let canonical be ! FormatTimeZoneOffsetString(offsetNanoseconds).
    canonical = FormatTimeZoneOffsetString(isolate, offset_nanoseconds);
  } else {
    // 4. Else,
    // a. If ! IsValidTimeZoneName(identifier) is false, then
    if (!IsValidTimeZoneName(isolate, identifier)) {
      // i. Throw a RangeError exception.
      THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidTimeZone,
                                             identifier));
    }
    // b. Let canonical be ! CanonicalizeTimeZoneName(identifier).
    canonical = CanonicalizeTimeZoneName(isolate, identifier);
  }
  // 5. Return ? CreateTemporalTimeZone(canonical, NewTarget).
  return CreateTemporalTimeZone(isolate, target, new_target, canonical);
}

namespace {

MaybeHandle<JSTemporalPlainDateTime> ToTemporalDateTime(
    Isolate* isolate, Handle<Object> item_obj, Handle<Object> options,
    const char* method_name);

MaybeHandle<JSTemporalPlainDateTime> ToTemporalDateTime(
    Isolate* isolate, Handle<Object> item_obj, const char* method_name) {
  // 1. If options is not present, set options to undefined.
  return ToTemporalDateTime(isolate, item_obj,
                            isolate->factory()->undefined_value(), method_name);
}

}  // namespace

// #sec-temporal.timezone.prototype.getinstantfor
MaybeHandle<JSTemporalInstant> JSTemporalTimeZone::GetInstantFor(
    Isolate* isolate, Handle<JSTemporalTimeZone> time_zone,
    Handle<Object> date_time_obj, Handle<Object> options_obj) {
  const char* method_name = "Temporal.TimeZone.prototype.getInstantFor";
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  // 3. Set dateTime to ? ToTemporalDateTime(dateTime).
  Handle<JSTemporalPlainDateTime> date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time,
      ToTemporalDateTime(isolate, date_time_obj, method_name));

  // 4. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 5. Let disambiguation be ? ToTemporalDisambiguation(options).
  Disambiguation disambiguation;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, disambiguation,
      ToTemporalDisambiguation(isolate, options, method_name),
      Handle<JSTemporalInstant>());

  // 6. Return ? BuiltinTimeZoneGetInstantFor(timeZone, dateTime,
  // disambiguation).
  return BuiltinTimeZoneGetInstantFor(isolate, time_zone, date_time,
                                      disambiguation, method_name);
}

namespace {

#ifdef V8_INTL_SUPPORT
Handle<Object> GetIANATimeZoneTransition(Isolate* isolate,
                                         Handle<BigInt> nanoseconds,
                                         int32_t time_zone_index,
                                         Intl::Transition transition) {
  if (time_zone_index == JSTemporalTimeZone::kUTCTimeZoneIndex) {
    return isolate->factory()->null_value();
  }
  return Intl::GetTimeZoneOffsetTransitionNanoseconds(isolate, time_zone_index,
                                                      nanoseconds, transition);
}
// #sec-temporal-getianatimezonenexttransition
Handle<Object> GetIANATimeZoneNextTransition(Isolate* isolate,
                                             Handle<BigInt> nanoseconds,
                                             int32_t time_zone_index) {
  return GetIANATimeZoneTransition(isolate, nanoseconds, time_zone_index,
                                   Intl::Transition::kNext);
}
// #sec-temporal-getianatimezoneprevioustransition
Handle<Object> GetIANATimeZonePreviousTransition(Isolate* isolate,
                                                 Handle<BigInt> nanoseconds,
                                                 int32_t time_zone_index) {
  return GetIANATimeZoneTransition(isolate, nanoseconds, time_zone_index,
                                   Intl::Transition::kPrevious);
}

Handle<Object> GetIANATimeZoneOffsetNanoseconds(Isolate* isolate,
                                                Handle<BigInt> nanoseconds,
                                                int32_t time_zone_index) {
  if (time_zone_index == JSTemporalTimeZone::kUTCTimeZoneIndex) {
    return handle(Smi::zero(), isolate);
  }

  return isolate->factory()->NewNumberFromInt64(
      Intl::GetTimeZoneOffsetNanoseconds(isolate, time_zone_index,
                                         nanoseconds));
}
#else   // V8_INTL_SUPPORT
// #sec-temporal-getianatimezonenexttransition
Handle<Object> GetIANATimeZoneNextTransition(Isolate* isolate, Handle<BigInt>,
                                             int32_t) {
  return isolate->factory()->null_value();
}
// #sec-temporal-getianatimezoneprevioustransition
Handle<Object> GetIANATimeZonePreviousTransition(Isolate* isolate,
                                                 Handle<BigInt>, int32_t) {
  return isolate->factory()->null_value();
}
Handle<Object> GetIANATimeZoneOffsetNanoseconds(Isolate* isolate,
                                                Handle<BigInt>,
                                                int32_t time_zone_index) {
  DCHECK_EQ(time_zone_index, JSTemporalTimeZone::kUTCTimeZoneIndex);
  return handle(Smi::zero(), isolate);
}
#endif  // V8_INTL_SUPPORT

}  // namespace

// #sec-temporal.timezone.prototype.getplaindatetimefor
MaybeHandle<JSTemporalPlainDateTime> JSTemporalTimeZone::GetPlainDateTimeFor(
    Isolate* isolate, Handle<JSTemporalTimeZone> time_zone,
    Handle<Object> instant_obj, Handle<Object> calendar_like) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.TimeZone.prototype.getPlainDateTimeFor";
  // 1. 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  // 3. Set instant to ? ToTemporalInstant(instant).
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant, ToTemporalInstant(isolate, instant_obj, method_name));
  // 4. Let calendar be ? ToTemporalCalendarWithISODefault(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ToTemporalCalendarWithISODefault(isolate, calendar_like, method_name));

  // 5. Return ? BuiltinTimeZoneGetPlainDateTimeFor(timeZone, instant,
  // calendar).
  return temporal::BuiltinTimeZoneGetPlainDateTimeFor(
      isolate, time_zone, instant, calendar, method_name);
}

// template for shared code of Temporal.TimeZone.prototype.getNextTransition and
// Temporal.TimeZone.prototype.getPreviousTransition
template <Handle<Object> (*iana_func)(Isolate*, Handle<BigInt>, int32_t)>
MaybeHandle<Object> GetTransition(Isolate* isolate,
                                  DirectHandle<JSTemporalTimeZone> time_zone,
                                  Handle<Object> starting_point_obj,
                                  const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  // 3. Set startingPoint to ? ToTemporalInstant(startingPoint).
  Handle<JSTemporalInstant> starting_point;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, starting_point,
      ToTemporalInstant(isolate, starting_point_obj, method_name));
  // 4. If timeZone.[[OffsetNanoseconds]] is not undefined, return null.
  if (time_zone->is_offset()) {
    return isolate->factory()->null_value();
  }
  // 5. Let transition be ?
  // GetIANATimeZoneNextTransition(startingPoint.[[Nanoseconds]],
  // timeZone.[[Identifier]]).
  Handle<Object> transition_obj =
      iana_func(isolate, handle(starting_point->nanoseconds(), isolate),
                time_zone->time_zone_index());
  // 6. If transition is null, return null.
  if (IsNull(*transition_obj)) {
    return isolate->factory()->null_value();
  }
  DCHECK(IsBigInt(*transition_obj));
  DirectHandle<BigInt> transition = Cast<BigInt>(transition_obj);
  // 7. Return ! CreateTemporalInstant(transition).
  return temporal::CreateTemporalInstant(isolate, transition).ToHandleChecked();
}

// #sec-temporal.timezone.prototype.getnexttransition
MaybeHandle<Object> JSTemporalTimeZone::GetNextTransition(
    Isolate* isolate, DirectHandle<JSTemporalTimeZone> time_zone,
    Handle<Object> starting_point_obj) {
  return GetTransition<GetIANATimeZoneNextTransition>(
      isolate, time_zone, starting_point_obj,
      "Temporal.TimeZone.prototype.getNextTransition");
}
// #sec-temporal.timezone.prototype.getprevioustransition
MaybeHandle<Object> JSTemporalTimeZone::GetPreviousTransition(
    Isolate* isolate, DirectHandle<JSTemporalTimeZone> time_zone,
    Handle<Object> starting_point_obj) {
  return GetTransition<GetIANATimeZonePreviousTransition>(
      isolate, time_zone, starting_point_obj,
      "Temporal.TimeZone.prototype.getPreviousTransition");
}

// #sec-temporal.timezone.prototype.getpossibleinstantsfor
// #sec-temporal-getianatimezoneepochvalue
MaybeHandle<JSArray> GetIANATimeZoneEpochValueAsArrayOfInstantForUTC(
    Isolate* isolate, const DateTimeRecord& date_time) {
  Factory* factory = isolate->factory();
  // 6. Let possibleInstants be a new empty List.
  DirectHandle<BigInt> epoch_nanoseconds =
      GetEpochFromISOParts(isolate, date_time);
  DirectHandle<FixedArray> fixed_array = factory->NewFixedArray(1);
  // 7. For each value epochNanoseconds in possibleEpochNanoseconds, do
  // a. If ! IsValidEpochNanoseconds(epochNanoseconds) is false, throw a
  // RangeError exception.
  if (!IsValidEpochNanoseconds(isolate, epoch_nanoseconds)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // b. Let instant be ! CreateTemporalInstant(epochNanoseconds).
  DirectHandle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(isolate, epoch_nanoseconds)
          .ToHandleChecked();
  // c. Append instant to possibleInstants.
  fixed_array->set(0, *instant);
  // 8. Return ! CreateArrayFromList(possibleInstants).
  return factory->NewJSArrayWithElements(fixed_array);
}

#ifdef V8_INTL_SUPPORT
MaybeHandle<JSArray> GetIANATimeZoneEpochValueAsArrayOfInstant(
    Isolate* isolate, int32_t time_zone_index,
    const DateTimeRecord& date_time) {
  Factory* factory = isolate->factory();
  if (time_zone_index == JSTemporalTimeZone::kUTCTimeZoneIndex) {
    return GetIANATimeZoneEpochValueAsArrayOfInstantForUTC(isolate, date_time);
  }

  // For TimeZone other than UTC, call ICU indirectly from Intl
  Handle<BigInt> nanoseconds_in_local_time =
      GetEpochFromISOParts(isolate, date_time);

  std::vector<Handle<BigInt>> possible_offset =
      Intl::GetTimeZonePossibleOffsetNanoseconds(isolate, time_zone_index,
                                                 nanoseconds_in_local_time);

  int32_t array_length = static_cast<int32_t>(possible_offset.size());
  DirectHandle<FixedArray> fixed_array = factory->NewFixedArray(array_length);

  for (int32_t i = 0; i < array_length; i++) {
    DirectHandle<BigInt> epoch_nanoseconds =
        BigInt::Subtract(isolate, nanoseconds_in_local_time, possible_offset[i])
            .ToHandleChecked();
    // a. If ! IsValidEpochNanoseconds(epochNanoseconds) is false, throw a
    // RangeError exception.
    if (!IsValidEpochNanoseconds(isolate, epoch_nanoseconds)) {
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
    }
    // b. Let instant be ! CreateTemporalInstant(epochNanoseconds).
    Handle<JSTemporalInstant> instant =
        temporal::CreateTemporalInstant(isolate, epoch_nanoseconds)
            .ToHandleChecked();
    // b. Append instant to possibleInstants.
    fixed_array->set(i, *(instant));
  }

  // 8. Return ! CreateArrayFromList(possibleInstants).
  return factory->NewJSArrayWithElements(fixed_array);
}

#else   //  V8_INTL_SUPPORT

MaybeHandle<JSArray> GetIANATimeZoneEpochValueAsArrayOfInstant(
    Isolate* isolate, int32_t time_zone_index,
    const DateTimeRecord& date_time) {
  DCHECK_EQ(time_zone_index, JSTemporalTimeZone::kUTCTimeZoneIndex);
  return GetIANATimeZoneEpochValueAsArrayOfInstantForUTC(isolate, date_time);
}
#endif  // V8_INTL_SUPPORT

// #sec-temporal.timezone.prototype.getpossibleinstantsfor
MaybeHandle<JSArray> JSTemporalTimeZone::GetPossibleInstantsFor(
    Isolate* isolate, DirectHandle<JSTemporalTimeZone> time_zone,
    Handle<Object> date_time_obj) {
  Factory* factory = isolate->factory();
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimezone]]).
  // 3. Set dateTime to ? ToTemporalDateTime(dateTime).
  Handle<JSTemporalPlainDateTime> date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time,
      ToTemporalDateTime(isolate, date_time_obj,
                         "Temporal.TimeZone.prototype.getPossibleInstantsFor"));
  DateTimeRecord date_time_record = {
      {date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
      {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
       date_time->iso_millisecond(), date_time->iso_microsecond(),
       date_time->iso_nanosecond()}};
  // 4. If timeZone.[[OffsetNanoseconds]] is not undefined, then
  if (time_zone->is_offset()) {
    // a. Let epochNanoseconds be ! GetEpochFromISOParts(dateTime.[[ISOYear]],
    // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
    // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
    // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
    // dateTime.[[ISONanosecond]]).
    Handle<BigInt> epoch_nanoseconds =
        GetEpochFromISOParts(isolate, date_time_record);
    // b. Let possibleEpochNanoseconds be « epochNanoseconds -
    // ℤ(timeZone.[[OffsetNanoseconds]]) ».
    epoch_nanoseconds =
        BigInt::Subtract(
            isolate, epoch_nanoseconds,
            BigInt::FromInt64(isolate, time_zone->offset_nanoseconds()))
            .ToHandleChecked();

    // The following is the step 7 and 8 for the case of step 4 under the if
    // block.

    // a. If ! IsValidEpochNanoseconds(epochNanoseconds) is false, throw a
    // RangeError exception.
    if (!IsValidEpochNanoseconds(isolate, epoch_nanoseconds)) {
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
    }

    // b. Let instant be ! CreateTemporalInstant(epochNanoseconds).

    DirectHandle<JSTemporalInstant> instant =
        temporal::CreateTemporalInstant(isolate, epoch_nanoseconds)
            .ToHandleChecked();
    // c. Return ! CreateArrayFromList(« instant »).
    DirectHandle<FixedArray> fixed_array = factory->NewFixedArray(1);
    fixed_array->set(0, *instant);
    return factory->NewJSArrayWithElements(fixed_array);
  }

  // 5. Let possibleEpochNanoseconds be ?
  // GetIANATimeZoneEpochValue(timeZone.[[Identifier]], dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]]).

  // ... Step 5-8 put into GetIANATimeZoneEpochValueAsArrayOfInstant
  // 8. Return ! CreateArrayFromList(possibleInstants).
  return GetIANATimeZoneEpochValueAsArrayOfInstant(
      isolate, time_zone->time_zone_index(), date_time_record);
}

// #sec-temporal.timezone.prototype.getoffsetnanosecondsfor
MaybeHandle<Object> JSTemporalTimeZone::GetOffsetNanosecondsFor(
    Isolate* isolate, DirectHandle<JSTemporalTimeZone> time_zone,
    Handle<Object> instant_obj) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  // 3. Set instant to ? ToTemporalInstant(instant).
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      ToTemporalInstant(isolate, instant_obj,
                        "Temporal.TimeZone.prototype.getOffsetNanosecondsFor"));
  // 4. If timeZone.[[OffsetNanoseconds]] is not undefined, return
  // timeZone.[[OffsetNanoseconds]].
  if (time_zone->is_offset()) {
    return isolate->factory()->NewNumberFromInt64(
        time_zone->offset_nanoseconds());
  }
  // 5. Return ! GetIANATimeZoneOffsetNanoseconds(instant.[[Nanoseconds]],
  // timeZone.[[Identifier]]).
  return GetIANATimeZoneOffsetNanoseconds(
      isolate, handle(instant->nanoseconds(), isolate),
      time_zone->time_zone_index());
}

// #sec-temporal.timezone.prototype.getoffsetstringfor
MaybeHandle<String> JSTemporalTimeZone::GetOffsetStringFor(
    Isolate* isolate, Handle<JSTemporalTimeZone> time_zone,
    Handle<Object> instant_obj) {
  TEMPORAL_ENTER_FUNC();
  const char* method_name = "Temporal.TimeZone.prototype.getOffsetStringFor";
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  // 3. Set instant to ? ToTemporalInstant(instant).
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant, ToTemporalInstant(isolate, instant_obj, method_name));
  // 4. Return ? BuiltinTimeZoneGetOffsetStringFor(timeZone, instant).
  return BuiltinTimeZoneGetOffsetStringFor(isolate, time_zone, instant,
                                           method_name);
}

// #sec-temporal.timezone.prototype.tostring
MaybeHandle<Object> JSTemporalTimeZone::ToString(
    Isolate* isolate, DirectHandle<JSTemporalTimeZone> time_zone,
    const char* method_name) {
  return time_zone->id(isolate);
}

int32_t JSTemporalTimeZone::time_zone_index() const {
  DCHECK(is_offset() == false);
  return offset_milliseconds_or_time_zone_index();
}

int64_t JSTemporalTimeZone::offset_nanoseconds() const {
  TEMPORAL_ENTER_FUNC();
  DCHECK(is_offset());
  return static_cast<int64_t>(offset_milliseconds()) * 1000000 +
         static_cast<int64_t>(offset_sub_milliseconds());
}

void JSTemporalTimeZone::set_offset_nanoseconds(int64_t ns) {
  this->set_offset_milliseconds(static_cast<int32_t>(ns / 1000000));
  this->set_offset_sub_milliseconds(static_cast<int32_t>(ns % 1000000));
}

MaybeHandle<String> JSTemporalTimeZone::id(Isolate* isolate) const {
  if (is_offset()) {
    return FormatTimeZoneOffsetString(isolate, offset_nanoseconds());
  }
#ifdef V8_INTL_SUPPORT
  std::string id =
      Intl::TimeZoneIdFromIndex(offset_milliseconds_or_time_zone_index());
  return isolate->factory()->NewStringFromAsciiChecked(id.c_str());
#else   // V8_INTL_SUPPORT
  DCHECK_EQ(kUTCTimeZoneIndex, offset_milliseconds_or_time_zone_index());
  return isolate->factory()->UTC_string();
#endif  // V8_INTL_SUPPORT
}

MaybeHandle<JSTemporalPlainDate> JSTemporalPlainDate::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> iso_year_obj, Handle<Object> iso_month_obj,
    Handle<Object> iso_day_obj, Handle<Object> calendar_like) {
  const char* method_name = "Temporal.PlainDate";
  // 1. If NewTarget is undefined, throw a TypeError exception.
  if (IsUndefined(*new_target)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }
#define TO_INT_THROW_ON_INFTY(name, T)                                         \
  int32_t name;                                                                \
  {                                                                            \
    Handle<Object> number_##name;                                              \
    /* x. Let name be ? ToIntegerThrowOnInfinity(name). */                     \
    ASSIGN_RETURN_ON_EXCEPTION(isolate, number_##name,                         \
                               ToIntegerThrowOnInfinity(isolate, name##_obj)); \
    name = NumberToInt32(*number_##name);                                      \
  }

  TO_INT_THROW_ON_INFTY(iso_year, JSTemporalPlainDate);
  TO_INT_THROW_ON_INFTY(iso_month, JSTemporalPlainDate);
  TO_INT_THROW_ON_INFTY(iso_day, JSTemporalPlainDate);

  // 8. Let calendar be ? ToTemporalCalendarWithISODefault(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ToTemporalCalendarWithISODefault(isolate, calendar_like, method_name));

  // 9. Return ? CreateTemporalDate(y, m, d, calendar, NewTarget).
  return CreateTemporalDate(isolate, target, new_target,
                            {iso_year, iso_month, iso_day}, calendar);
}

// #sec-temporal.plaindate.compare
MaybeHandle<Smi> JSTemporalPlainDate::Compare(Isolate* isolate,
                                              Handle<Object> one_obj,
                                              Handle<Object> two_obj) {
  const char* method_name = "Temporal.PlainDate.compare";
  // 1. Set one to ? ToTemporalDate(one).
  Handle<JSTemporalPlainDate> one;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, one,
                             ToTemporalDate(isolate, one_obj, method_name));
  // 2. Set two to ? ToTemporalDate(two).
  Handle<JSTemporalPlainDate> two;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, two,
                             ToTemporalDate(isolate, two_obj, method_name));
  // 3. Return 𝔽(! CompareISODate(one.[[ISOYear]], one.[[ISOMonth]],
  // one.[[ISODay]], two.[[ISOYear]], two.[[ISOMonth]], two.[[ISODay]])).
  return Handle<Smi>(Smi::FromInt(CompareISODate(
                         {one->iso_year(), one->iso_month(), one->iso_day()},
                         {two->iso_year(), two->iso_month(), two->iso_day()})),
                     isolate);
}

// #sec-temporal.plaindate.prototype.equals
MaybeHandle<Oddball> JSTemporalPlainDate::Equals(
    Isolate* isolate, DirectHandle<JSTemporalPlainDate> temporal_date,
    Handle<Object> other_obj) {
  Factory* factory = isolate->factory();
  // 1. Let temporalDate be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDate,
  // [[InitializedTemporalDate]]).
  // 3. Set other to ? ToTemporalDate(other).
  Handle<JSTemporalPlainDate> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other,
      ToTemporalDate(isolate, other_obj,
                     "Temporal.PlainDate.prototype.equals"));
  // 4. If temporalDate.[[ISOYear]] ≠ other.[[ISOYear]], return false.
  if (temporal_date->iso_year() != other->iso_year()) {
    return factory->false_value();
  }
  // 5. If temporalDate.[[ISOMonth]] ≠ other.[[ISOMonth]], return false.
  if (temporal_date->iso_month() != other->iso_month()) {
    return factory->false_value();
  }
  // 6. If temporalDate.[[ISODay]] ≠ other.[[ISODay]], return false.
  if (temporal_date->iso_day() != other->iso_day()) {
    return factory->false_value();
  }
  // 7. Return ? CalendarEquals(temporalDate.[[Calendar]], other.[[Calendar]]).
  return CalendarEquals(isolate, handle(temporal_date->calendar(), isolate),
                        handle(other->calendar(), isolate));
}

// #sec-temporal.plaindate.prototype.withcalendar
MaybeHandle<JSTemporalPlainDate> JSTemporalPlainDate::WithCalendar(
    Isolate* isolate, DirectHandle<JSTemporalPlainDate> temporal_date,
    Handle<Object> calendar_like) {
  const char* method_name = "Temporal.PlainDate.prototype.withCalendar";
  // 1. Let temporalDate be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDate,
  // [[InitializedTemporalDate]]).
  // 3. Let calendar be ? ToTemporalCalendar(calendar).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      temporal::ToTemporalCalendar(isolate, calendar_like, method_name));
  // 4. Return ? CreateTemporalDate(temporalDate.[[ISOYear]],
  // temporalDate.[[ISOMonth]], temporalDate.[[ISODay]], calendar).
  return CreateTemporalDate(
      isolate,
      {temporal_date->iso_year(), temporal_date->iso_month(),
       temporal_date->iso_day()},
      calendar);
}

// Template for common code shared by
// Temporal.PlainDate(Timne)?.prototype.toPlain(YearMonth|MonthDay)
// #sec-temporal.plaindate.prototype.toplainmonthday
// #sec-temporal.plaindate.prototype.toplainyearmonth
// #sec-temporal.plaindatetime.prototype.toplainmonthday
// #sec-temporal.plaindatetime.prototype.toplainyearmonth
template <typename T, typename R,
          MaybeHandle<R> (*from_fields)(Isolate*, Handle<JSReceiver>,
                                        Handle<JSReceiver>, Handle<Object>)>
MaybeHandle<R> ToPlain(Isolate* isolate, Handle<T> t, DirectHandle<String> f1,
                       DirectHandle<String> f2) {
  Factory* factory = isolate->factory();
  // 1. Let temporalDate be the this value.
  // 2. Perform ? RequireInternalSlot(t, [[InitializedTemporalDate]]).
  // 3. Let calendar be t.[[Calendar]].
  Handle<JSReceiver> calendar(t->calendar(), isolate);
  // 4. Let fieldNames be ? CalendarFields(calendar, « f1 , f2 »).
  Handle<FixedArray> field_names = factory->NewFixedArray(2);
  field_names->set(0, *f1);
  field_names->set(1, *f2);
  ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                             CalendarFields(isolate, calendar, field_names));
  // 5. Let fields be ? PrepareTemporalFields(t, fieldNames, «»).
  Handle<JSReceiver> fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      PrepareTemporalFields(isolate, t, field_names, RequiredFields::kNone));
  // 6. Return ? FromFields(calendar, fields).
  return from_fields(isolate, calendar, fields,
                     isolate->factory()->undefined_value());
}

// #sec-temporal.plaindate.prototype.toplainyearmonth
MaybeHandle<JSTemporalPlainYearMonth> JSTemporalPlainDate::ToPlainYearMonth(
    Isolate* isolate, Handle<JSTemporalPlainDate> temporal_date) {
  return ToPlain<JSTemporalPlainDate, JSTemporalPlainYearMonth,
                 YearMonthFromFields>(isolate, temporal_date,
                                      isolate->factory()->monthCode_string(),
                                      isolate->factory()->year_string());
}

// #sec-temporal.plaindate.prototype.toplainmonthday
MaybeHandle<JSTemporalPlainMonthDay> JSTemporalPlainDate::ToPlainMonthDay(
    Isolate* isolate, Handle<JSTemporalPlainDate> temporal_date) {
  return ToPlain<JSTemporalPlainDate, JSTemporalPlainMonthDay,
                 MonthDayFromFields>(isolate, temporal_date,
                                     isolate->factory()->day_string(),
                                     isolate->factory()->monthCode_string());
}

// #sec-temporal.plaindate.prototype.toplaindatetime
MaybeHandle<JSTemporalPlainDateTime> JSTemporalPlainDate::ToPlainDateTime(
    Isolate* isolate, DirectHandle<JSTemporalPlainDate> temporal_date,
    Handle<Object> temporal_time_obj) {
  // 1. Let temporalDate be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDate,
  // [[InitializedTemporalDate]]).
  // 3. If temporalTime is undefined, then
  if (IsUndefined(*temporal_time_obj)) {
    // a. Return ? CreateTemporalDateTime(temporalDate.[[ISOYear]],
    // temporalDate.[[ISOMonth]], temporalDate.[[ISODay]], 0, 0, 0, 0, 0, 0,
    // temporalDate.[[Calendar]]).
    return temporal::CreateTemporalDateTime(
        isolate,
        {{temporal_date->iso_year(), temporal_date->iso_month(),
          temporal_date->iso_day()},
         {0, 0, 0, 0, 0, 0}},
        Handle<JSReceiver>(temporal_date->calendar(), isolate));
  }
  // 4. Set temporalTime to ? ToTemporalTime(temporalTime).
  Handle<JSTemporalPlainTime> temporal_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_time,
      temporal::ToTemporalTime(isolate, temporal_time_obj,
                               "Temporal.PlainDate.prototype.toPlainDateTime"));
  // 5. Return ? CreateTemporalDateTime(temporalDate.[[ISOYear]],
  // temporalDate.[[ISOMonth]], temporalDate.[[ISODay]],
  // temporalTime.[[ISOHour]], temporalTime.[[ISOMinute]],
  // temporalTime.[[ISOSecond]], temporalTime.[[ISOMillisecond]],
  // temporalTime.[[ISOMicrosecond]], temporalTime.[[ISONanosecond]],
  // temporalDate.[[Calendar]]).
  return temporal::CreateTemporalDateTime(
      isolate,
      {{temporal_date->iso_year(), temporal_date->iso_month(),
        temporal_date->iso_day()},
       {temporal_time->iso_hour(), temporal_time->iso_minute(),
        temporal_time->iso_second(), temporal_time->iso_millisecond(),
        temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()}},
      Handle<JSReceiver>(temporal_date->calendar(), isolate));
}

namespace {

// #sec-temporal-rejectobjectwithcalendarortimezone
Maybe<bool> RejectObjectWithCalendarOrTimeZone(Isolate* isolate,
                                               Handle<JSReceiver> object) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 1. Assert: Type(object) is Object.
  // 2. If object has an [[InitializedTemporalDate]],
  // [[InitializedTemporalDateTime]], [[InitializedTemporalMonthDay]],
  // [[InitializedTemporalTime]], [[InitializedTemporalYearMonth]], or
  // [[InitializedTemporalZonedDateTime]] internal slot, then
  if (IsJSTemporalPlainDate(*object) || IsJSTemporalPlainDateTime(*object) ||
      IsJSTemporalPlainMonthDay(*object) || IsJSTemporalPlainTime(*object) ||
      IsJSTemporalPlainYearMonth(*object) ||
      IsJSTemporalZonedDateTime(*object)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<bool>());
  }
  // 3. Let calendarProperty be ? Get(object, "calendar").
  Handle<Object> calendar_property;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar_property,
      JSReceiver::GetProperty(isolate, object, factory->calendar_string()),
      Nothing<bool>());
  // 4. If calendarProperty is not undefined, then
  if (!IsUndefined(*calendar_property)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<bool>());
  }
  // 5. Let timeZoneProperty be ? Get(object, "timeZone").
  Handle<Object> time_zone_property;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, time_zone_property,
      JSReceiver::GetProperty(isolate, object, factory->timeZone_string()),
      Nothing<bool>());
  // 6. If timeZoneProperty is not undefined, then
  if (!IsUndefined(*time_zone_property)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<bool>());
  }
  return Just(true);
}

// #sec-temporal-calendarmergefields
MaybeHandle<JSReceiver> CalendarMergeFields(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<JSReceiver> fields,
    Handle<JSReceiver> additional_fields) {
  // 1. Let mergeFields be ? GetMethod(calendar, "mergeFields").
  Handle<Object> merge_fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, merge_fields,
      Object::GetMethod(isolate, calendar,
                        isolate->factory()->mergeFields_string()));
  // 2. If mergeFields is undefined, then
  if (IsUndefined(*merge_fields)) {
    // a. Return ? DefaultMergeFields(fields, additionalFields).
    return DefaultMergeFields(isolate, fields, additional_fields);
  }
  // 3. Return ? Call(mergeFields, calendar, « fields, additionalFields »).
  Handle<Object> argv[] = {fields, additional_fields};
  Handle<Object> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result,
      Execution::Call(isolate, merge_fields, calendar, 2, argv));
  // 4. If Type(result) is not Object, throw a TypeError exception.
  if (!IsJSReceiver(*result)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  return Cast<JSReceiver>(result);
}

// Common code shared by Temporal.Plain(Date|YearMonth|MonthDay).prototype.with
template <typename T,
          MaybeHandle<T> (*from_fields_func)(
              Isolate*, Handle<JSReceiver>, Handle<JSReceiver>, Handle<Object>)>
MaybeHandle<T> PlainDateOrYearMonthOrMonthDayWith(
    Isolate* isolate, Handle<T> temporal, Handle<Object> temporal_like_obj,
    Handle<Object> options_obj, Handle<FixedArray> field_names,
    const char* method_name) {
  // 1. Let temporalDate be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDate,
  // [[InitializedTemporalXXX]]).
  // 3. If Type(temporalXXXLike) is not Object, then
  if (!IsJSReceiver(*temporal_like_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  Handle<JSReceiver> temporal_like = Cast<JSReceiver>(temporal_like_obj);
  // 4. Perform ? RejectObjectWithCalendarOrTimeZone(temporalXXXLike).
  MAYBE_RETURN(RejectObjectWithCalendarOrTimeZone(isolate, temporal_like),
               Handle<T>());

  // 5. Let calendar be temporalXXX.[[Calendar]].
  Handle<JSReceiver> calendar(temporal->calendar(), isolate);

  // 6. Let fieldNames be ? CalendarFields(calendar, fieldNames).
  ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                             CalendarFields(isolate, calendar, field_names));
  // 7. Let partialDate be ? PreparePartialTemporalFields(temporalXXXLike,
  // fieldNames).
  Handle<JSReceiver> partial_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, partial_date,
      PreparePartialTemporalFields(isolate, temporal_like, field_names));
  // 8. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 9. Let fields be ? PrepareTemporalFields(temporalXXX, fieldNames, «»).
  Handle<JSReceiver> fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      PrepareTemporalFields(isolate, temporal, field_names,
                            RequiredFields::kNone));
  // 10. Set fields to ? CalendarMergeFields(calendar, fields, partialDate).
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      CalendarMergeFields(isolate, calendar, fields, partial_date));
  // 11. Set fields to ? PrepareTemporalFields(fields, fieldNames, «»).
  ASSIGN_RETURN_ON_EXCEPTION(isolate, fields,
                             PrepareTemporalFields(isolate, fields, field_names,
                                                   RequiredFields::kNone));
  // 12. Return ? XxxFromFields(calendar, fields, options).
  return from_fields_func(isolate, calendar, fields, options);
}

}  // namespace

// #sec-temporal.plaindate.prototype.with
MaybeHandle<JSTemporalPlainDate> JSTemporalPlainDate::With(
    Isolate* isolate, Handle<JSTemporalPlainDate> temporal_date,
    Handle<Object> temporal_date_like_obj, Handle<Object> options_obj) {
  // 6. Let fieldNames be ? CalendarFields(calendar, « "day", "month",
  // "monthCode", "year" »).
  Handle<FixedArray> field_names = DayMonthMonthCodeYearInFixedArray(isolate);
  return PlainDateOrYearMonthOrMonthDayWith<JSTemporalPlainDate,
                                            DateFromFields>(
      isolate, temporal_date, temporal_date_like_obj, options_obj, field_names,
      "Temporal.PlainDate.prototype.with");
}

// #sec-temporal.plaindate.prototype.tozoneddatetime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalPlainDate::ToZonedDateTime(
    Isolate* isolate, DirectHandle<JSTemporalPlainDate> temporal_date,
    Handle<Object> item_obj) {
  const char* method_name = "Temporal.PlainDate.prototype.toZonedDateTime";
  Factory* factory = isolate->factory();
  // 1. Let temporalDate be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDate,
  // [[InitializedTemporalDate]]).
  // 3. If Type(item) is Object, then
  Handle<JSReceiver> time_zone;
  Handle<Object> temporal_time_obj;
  if (IsJSReceiver(*item_obj)) {
    Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
    // a. Let timeZoneLike be ? Get(item, "timeZone").
    Handle<Object> time_zone_like;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone_like,
        JSReceiver::GetProperty(isolate, item, factory->timeZone_string()));
    // b. If timeZoneLike is undefined, then
    if (IsUndefined(*time_zone_like)) {
      // i. Let timeZone be ? ToTemporalTimeZone(item).
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, time_zone,
          temporal::ToTemporalTimeZone(isolate, item, method_name));
      // ii. Let temporalTime be undefined.
      temporal_time_obj = factory->undefined_value();
      // c. Else,
    } else {
      // i. Let timeZone be ? ToTemporalTimeZone(timeZoneLike).
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, time_zone,
          temporal::ToTemporalTimeZone(isolate, time_zone_like, method_name));
      // ii. Let temporalTime be ? Get(item, "plainTime").
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, temporal_time_obj,
          JSReceiver::GetProperty(isolate, item, factory->plainTime_string()));
    }
    // 4. Else,
  } else {
    // a. Let timeZone be ? ToTemporalTimeZone(item).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, time_zone,
        temporal::ToTemporalTimeZone(isolate, item_obj, method_name));
    // b. Let temporalTime be undefined.
    temporal_time_obj = factory->undefined_value();
  }
  // 5. If temporalTime is undefined, then
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  DirectHandle<JSReceiver> calendar(temporal_date->calendar(), isolate);
  if (IsUndefined(*temporal_time_obj)) {
    // a. Let temporalDateTime be ?
    // CreateTemporalDateTime(temporalDate.[[ISOYear]],
    // temporalDate.[[ISOMonth]], temporalDate.[[ISODay]], 0, 0, 0, 0, 0, 0,
    // temporalDate.[[Calendar]]).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_time,
        temporal::CreateTemporalDateTime(
            isolate,
            {{temporal_date->iso_year(), temporal_date->iso_month(),
              temporal_date->iso_day()},
             {0, 0, 0, 0, 0, 0}},
            calendar));
    // 6. Else,
  } else {
    Handle<JSTemporalPlainTime> temporal_time;
    // a. Set temporalTime to ? ToTemporalTime(temporalTime).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_time,
        temporal::ToTemporalTime(isolate, temporal_time_obj, method_name));
    // b. Let temporalDateTime be ?
    // CreateTemporalDateTime(temporalDate.[[ISOYear]],
    // temporalDate.[[ISOMonth]], temporalDate.[[ISODay]],
    // temporalTime.[[ISOHour]], temporalTime.[[ISOMinute]],
    // temporalTime.[[ISOSecond]], temporalTime.[[ISOMillisecond]],
    // temporalTime.[[ISOMicrosecond]], temporalTime.[[ISONanosecond]],
    // temporalDate.[[Calendar]]).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_date_time,
        temporal::CreateTemporalDateTime(
            isolate,
            {{temporal_date->iso_year(), temporal_date->iso_month(),
              temporal_date->iso_day()},
             {temporal_time->iso_hour(), temporal_time->iso_minute(),
              temporal_time->iso_second(), temporal_time->iso_millisecond(),
              temporal_time->iso_microsecond(),
              temporal_time->iso_nanosecond()}},
            calendar));
  }
  // 7. Let instant be ? BuiltinTimeZoneGetInstantFor(timeZone,
  // temporalDateTime, "compatible").
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, temporal_date_time,
                                   Disambiguation::kCompatible, method_name));
  // 8. Return ? CreateTemporalZonedDateTime(instant.[[Nanoseconds]], timeZone,
  // temporalDate.[[Calendar]]).
  return CreateTemporalZonedDateTime(
      isolate, handle(instant->nanoseconds(), isolate), time_zone, calendar);
}

// #sec-temporal.plaindate.prototype.add
MaybeHandle<JSTemporalPlainDate> JSTemporalPlainDate::Add(
    Isolate* isolate, Handle<JSTemporalPlainDate> temporal_date,
    Handle<Object> temporal_duration_like, Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainDate.prototype.add";
  // 1. Let temporalDate be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDate,
  // [[InitializedTemporalDate]]).
  // 3. Let duration be ? ToTemporalDuration(temporalDurationLike).
  Handle<JSTemporalDuration> duration;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, duration,
                             temporal::ToTemporalDuration(
                                 isolate, temporal_duration_like, method_name));

  // 4. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 5. Return ? CalendarDateAdd(temporalDate.[[Calendar]], temporalDate,
  // duration, options).
  return CalendarDateAdd(isolate, handle(temporal_date->calendar(), isolate),
                         temporal_date, duration, options);
}

// #sec-temporal.plaindate.prototype.subtract
MaybeHandle<JSTemporalPlainDate> JSTemporalPlainDate::Subtract(
    Isolate* isolate, Handle<JSTemporalPlainDate> temporal_date,
    Handle<Object> temporal_duration_like, Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainDate.prototype.subtract";
  // 1. Let temporalDate be the this value.
  // 2. Perform ? RequireInternalSlot(temporalDate,
  // [[InitializedTemporalDate]]).
  // 3. Let duration be ? ToTemporalDuration(temporalDurationLike).
  Handle<JSTemporalDuration> duration;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, duration,
                             temporal::ToTemporalDuration(
                                 isolate, temporal_duration_like, method_name));

  // 4. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));

  // 5. Let negatedDuration be ! CreateNegatedTemporalDuration(duration).
  Handle<JSTemporalDuration> negated_duration =
      CreateNegatedTemporalDuration(isolate, duration).ToHandleChecked();

  // 6. Return ? CalendarDateAdd(temporalDate.[[Calendar]], temporalDate,
  // negatedDuration, options).
  return CalendarDateAdd(isolate, handle(temporal_date->calendar(), isolate),
                         temporal_date, negated_duration, options);
}

namespace {
// #sec-temporal-differencetemporalplandate
MaybeHandle<JSTemporalDuration> DifferenceTemporalPlainDate(
    Isolate* isolate, TimePreposition operation,
    Handle<JSTemporalPlainDate> temporal_date, Handle<Object> other_obj,
    Handle<Object> options, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. If operation is since, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == TimePreposition::kSince ? -1 : 1;
  // 2. Set other to ? ToTemporalDate(other).
  Handle<JSTemporalPlainDate> other;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, other,
                             ToTemporalDate(isolate, other_obj, method_name));
  // 3. If ? CalendarEquals(temporalDate.[[Calendar]], other.[[Calendar]]) is
  // false, throw a RangeError exception.
  bool calendar_equals;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar_equals,
      CalendarEqualsBool(isolate, handle(temporal_date->calendar(), isolate),
                         handle(other->calendar(), isolate)),
      Handle<JSTemporalDuration>());
  if (!calendar_equals) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }

  // 4. Let settings be ? GetDifferenceSettings(operation, options, date, « »,
  // "day", "day").
  DifferenceSettings settings;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, settings,
      GetDifferenceSettings(isolate, operation, options, UnitGroup::kDate,
                            DisallowedUnitsInDifferenceSettings::kNone,
                            Unit::kDay, Unit::kDay, method_name),
      Handle<JSTemporalDuration>());
  // 5. Let untilOptions be ? MergeLargestUnitOption(settings.[[Options]],
  // settings.[[LargestUnit]]).
  Handle<JSReceiver> until_options;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, until_options,
      MergeLargestUnitOption(isolate, settings.options, settings.largest_unit),
      Handle<JSTemporalDuration>());
  // 6. Let result be ? CalendarDateUntil(temporalDate.[[Calendar]],
  // temporalDate, other, untilOptions).
  Handle<JSTemporalDuration> result;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      CalendarDateUntil(isolate, handle(temporal_date->calendar(), isolate),
                        temporal_date, other, until_options),
      Handle<JSTemporalDuration>());
  // 7. If settings.[[SmallestUnit]] is not "day" or
  // settings.[[RoundingIncrement]] ≠ 1, then
  if (settings.smallest_unit != Unit::kDay ||
      settings.rounding_increment != 1) {
    // a. Set result to (? RoundDuration(result.[[Years]], result.[[Months]],
    // result.[[Weeks]], result.[[Days]], 0, 0, 0, 0, 0, 0,
    // settings.[[RoundingIncrement]], settings.[[SmallestUnit]],
    // settings.[[RoundingMode]], temporalDate)).[[DurationRecord]].
    DurationRecordWithRemainder round_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, round_result,
        RoundDuration(isolate,
                      {Object::NumberValue(result->years()),
                       Object::NumberValue(result->months()),
                       Object::NumberValue(result->weeks()),
                       {Object::NumberValue(result->days()), 0, 0, 0, 0, 0, 0}},
                      settings.rounding_increment, settings.smallest_unit,
                      settings.rounding_mode, temporal_date, method_name),
        Handle<JSTemporalDuration>());
    // 8. Return ! CreateTemporalDuration(sign × result.[[Years]], sign ×
    // result.[[Months]], sign × result.[[Weeks]], sign × result.[[Days]], 0, 0,
    // 0, 0, 0, 0).
    round_result.record.years *= sign;
    round_result.record.months *= sign;
    round_result.record.weeks *= sign;
    round_result.record.time_duration.days *= sign;
    round_result.record.time_duration.hours =
        round_result.record.time_duration.minutes =
            round_result.record.time_duration.seconds =
                round_result.record.time_duration.milliseconds =
                    round_result.record.time_duration.microseconds =
                        round_result.record.time_duration.nanoseconds = 0;
    return CreateTemporalDuration(isolate, round_result.record)
        .ToHandleChecked();
  }
  // 8. Return ! CreateTemporalDuration(sign × result.[[Years]], sign ×
  // result.[[Months]], sign × result.[[Weeks]], sign × result.[[Days]], 0, 0,
  // 0, 0, 0, 0).
  return CreateTemporalDuration(
             isolate,
             {sign * Object::NumberValue(result->years()),
              sign * Object::NumberValue(result->months()),
              sign * Object::NumberValue(result->weeks()),
              {sign * Object::NumberValue(result->days()), 0, 0, 0, 0, 0, 0}})
      .ToHandleChecked();
}

}  // namespace

// #sec-temporal.plaindate.prototype.until
MaybeHandle<JSTemporalDuration> JSTemporalPlainDate::Until(
    Isolate* isolate, Handle<JSTemporalPlainDate> handle, Handle<Object> other,
    Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalPlainDate(isolate, TimePreposition::kUntil, handle,
                                     other, options,
                                     "Temporal.PlainDate.prototype.until");
}

// #sec-temporal.plaindate.prototype.since
MaybeHandle<JSTemporalDuration> JSTemporalPlainDate::Since(
    Isolate* isolate, Handle<JSTemporalPlainDate> handle, Handle<Object> other,
    Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalPlainDate(isolate, TimePreposition::kSince, handle,
                                     other, options,
                                     "Temporal.PlainDate.prototype.since");
}

// #sec-temporal.now.plaindate
MaybeHandle<JSTemporalPlainDate> JSTemporalPlainDate::Now(
    Isolate* isolate, Handle<Object> calendar_like,
    Handle<Object> temporal_time_zone_like) {
  const char* method_name = "Temporal.Now.plainDate";
  // 1. Let dateTime be ? SystemDateTime(temporalTimeZoneLike, calendarLike).
  Handle<JSTemporalPlainDateTime> date_time;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, date_time,
                             SystemDateTime(isolate, temporal_time_zone_like,
                                            calendar_like, method_name));
  // 2. Return ! CreateTemporalDate(dateTime.[[ISOYear]], dateTime.[[ISOMonth]],
  // dateTime.[[ISODay]], dateTime.[[Calendar]]).
  return CreateTemporalDate(isolate,
                            {date_time->iso_year(), date_time->iso_month(),
                             date_time->iso_day()},
                            Handle<JSReceiver>(date_time->calendar(), isolate))
      .ToHandleChecked();
}

// #sec-temporal.now.plaindateiso
MaybeHandle<JSTemporalPlainDate> JSTemporalPlainDate::NowISO(
    Isolate* isolate, Handle<Object> temporal_time_zone_like) {
  const char* method_name = "Temporal.Now.plainDateISO";
  // 1. Let calendar be ! GetISO8601Calendar().
  Handle<JSReceiver> calendar = temporal::GetISO8601Calendar(isolate);
  // 2. Let dateTime be ? SystemDateTime(temporalTimeZoneLike, calendar).
  Handle<JSTemporalPlainDateTime> date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time,
      SystemDateTime(isolate, temporal_time_zone_like, calendar, method_name));
  // 3. Return ! CreateTemporalDate(dateTime.[[ISOYear]], dateTime.[[ISOMonth]],
  // dateTime.[[ISODay]], dateTime.[[Calendar]]).
  return CreateTemporalDate(isolate,
                            {date_time->iso_year(), date_time->iso_month(),
                             date_time->iso_day()},
                            Handle<JSReceiver>(date_time->calendar(), isolate))
      .ToHandleChecked();
}

// #sec-temporal.plaindate.from
MaybeHandle<JSTemporalPlainDate> JSTemporalPlainDate::From(
    Isolate* isolate, Handle<Object> item, Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainDate.from";
  // 1. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsO
```