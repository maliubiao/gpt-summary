Response: The user wants a summary of the C++ source code file `v8/src/objects/js-temporal-objects.cc`.
This is part 10 of 13. I need to focus on the functionalities implemented in this specific part of the file.

Based on the code snippets, this part seems to be heavily focused on the implementation of `Temporal.PlainMonthDay` and `Temporal.PlainYearMonth` objects, and starting to introduce `Temporal.PlainTime`.

Specifically, it includes functions for:
- Parsing strings to create `Temporal.PlainMonthDay` and `Temporal.PlainYearMonth` objects.
- Converting other Temporal objects or plain objects into `Temporal.PlainMonthDay` and `Temporal.PlainYearMonth` objects.
- Comparing `Temporal.PlainMonthDay` and `Temporal.PlainYearMonth` objects.
- Performing arithmetic operations (add, subtract) on `Temporal.PlainYearMonth` objects.
- Calculating the difference between two `Temporal.PlainYearMonth` objects.
- Creating new `Temporal.PlainMonthDay` and `Temporal.PlainYearMonth` objects by modifying existing ones (`with`).
- Converting `Temporal.PlainMonthDay` and `Temporal.PlainYearMonth` to `Temporal.PlainDate`.
- Getting the ISO fields of `Temporal.PlainMonthDay` and `Temporal.PlainYearMonth`.
- Converting `Temporal.PlainMonthDay` and `Temporal.PlainYearMonth` to JSON strings.
- Converting `Temporal.PlainMonthDay` and `Temporal.PlainYearMonth` to locale strings.
- Constructing `Temporal.PlainTime` objects.
- Converting `Temporal.PlainTime` to `TemporalZonedDateTime`.
- Comparing `Temporal.PlainTime` objects.
- Rounding `Temporal.PlainTime` objects.
- Creating new `Temporal.PlainTime` objects by modifying existing ones (`with`).
- Getting the current `Temporal.PlainTime`.
- Creating `Temporal.PlainTime` from various input types.

This file implements core functionalities for `Temporal.PlainMonthDay`, `Temporal.PlainYearMonth`, and the beginning of `Temporal.PlainTime`, enabling their creation, manipulation, and comparison. These functionalities directly relate to the Javascript `Temporal` API.
这个C++源代码文件 `v8/src/objects/js-temporal-objects.cc` 的第 10 部分主要负责实现以下 JavaScript `Temporal` API 中的对象的功能：

1. **`Temporal.PlainMonthDay`**:  定义了 `Temporal.PlainMonthDay` 对象的创建、转换、比较和修改等操作。
    *   **创建和转换**:  实现了从不同的类型（包括其他 Temporal 对象、普通对象和字符串）创建 `Temporal.PlainMonthDay` 对象的方法，如 `From` 和 `ToTemporalMonthDay`。
    *   **比较**: 实现了 `equals` 方法，用于比较两个 `Temporal.PlainMonthDay` 对象是否相等。
    *   **修改**: 实现了 `with` 方法，允许创建一个具有指定属性（月份、日期等）的新 `Temporal.PlainMonthDay` 对象。
    *   **转换为 `Temporal.PlainDate`**: 实现了 `toPlainDate` 方法，需要提供年份信息才能转换。
    *   **获取 ISO 字段**: 实现了 `getISOFields` 方法，返回包含 ISO 年、月、日和日历信息的对象。
    *   **字符串表示**: 实现了 `toJSON` 和 `toString` 方法，用于获取对象的字符串表示。
    *   **本地化字符串**: 实现了 `toLocaleString` 方法，用于获取本地化的字符串表示。

2. **`Temporal.PlainYearMonth`**: 定义了 `Temporal.PlainYearMonth` 对象的创建、转换、比较、算术运算和修改等操作。
    *   **构造函数**: 实现了 `Temporal.PlainYearMonth` 的构造函数。
    *   **创建和转换**: 实现了从不同的类型创建 `Temporal.PlainYearMonth` 对象的方法，如 `From` 和 `ToTemporalYearMonth`。
    *   **比较**: 实现了 `compare` 方法用于比较两个 `Temporal.PlainYearMonth` 的顺序，以及 `equals` 方法用于检查是否相等。
    *   **算术运算**: 实现了 `add` 和 `subtract` 方法，用于对 `Temporal.PlainYearMonth` 对象进行加减操作，可以传入 `Temporal.Duration` 对象。
    *   **计算差值**: 实现了 `until` 和 `since` 方法，用于计算两个 `Temporal.PlainYearMonth` 之间的差值，返回 `Temporal.Duration` 对象。
    *   **修改**: 实现了 `with` 方法，允许创建一个具有指定属性（年份、月份等）的新 `Temporal.PlainYearMonth` 对象。
    *   **转换为 `Temporal.PlainDate`**: 实现了 `toPlainDate` 方法，需要提供日期信息才能转换。
    *   **获取 ISO 字段**: 实现了 `getISOFields` 方法，返回包含 ISO 年、月、日和日历信息的对象。
    *   **字符串表示**: 实现了 `toJSON` 和 `toString` 方法，用于获取对象的字符串表示。
    *   **本地化字符串**: 实现了 `toLocaleString` 方法，用于获取本地化的字符串表示。

3. **`Temporal.PlainTime`**: 开始定义 `Temporal.PlainTime` 对象的相关功能。
    *   **构造函数**: 实现了 `Temporal.PlainTime` 的构造函数。
    *   **转换为 `Temporal.ZonedDateTime`**: 实现了 `toZonedDateTime` 方法，需要提供日期和时区信息。
    *   **比较**: 实现了 `compare` 方法，用于比较两个 `Temporal.PlainTime` 对象的顺序。
    *   **相等性判断**: 实现了 `equals` 方法，用于判断两个 `Temporal.PlainTime` 对象是否相等。
    *   **舍入**: 实现了 `round` 方法，用于将 `Temporal.PlainTime` 对象舍入到指定的时间单位。
    *   **修改**: 实现了 `with` 方法，允许创建一个具有指定属性（小时、分钟等）的新 `Temporal.PlainTime` 对象。
    *   **获取当前时间**: 实现了 `NowISO` 静态方法，根据提供的时区获取当前的 `Temporal.PlainTime`。
    *   **从不同类型创建**: 实现了 `From` 方法，用于从不同的类型创建 `Temporal.PlainTime` 对象.

**与 JavaScript 功能的关联和示例:**

这些 C++ 代码直接实现了 JavaScript 中 `Temporal` API 的功能。以下是用 JavaScript 举例说明其功能的示例：

**`Temporal.PlainMonthDay` 示例:**

```javascript
const monthDay1 = Temporal.PlainMonthDay.from("12-25");
const monthDay2 = new Temporal.PlainMonthDay(12, 25);

console.log(monthDay1.equals(monthDay2)); // true

const nextMonthDay = monthDay1.with({ month: 1 });
console.log(nextMonthDay.toString()); // 01-25

const dateFromMonthDay = monthDay1.toPlainDate({ year: 2023 });
console.log(dateFromMonthDay.toString()); // 2023-12-25
```

**`Temporal.PlainYearMonth` 示例:**

```javascript
const yearMonth1 = Temporal.PlainYearMonth.from("2023-10");
const yearMonth2 = new Temporal.PlainYearMonth(2023, 10);

console.log(yearMonth1.equals(yearMonth2)); // true
console.log(Temporal.PlainYearMonth.compare(yearMonth1, yearMonth2)); // 0

const nextYearMonth = yearMonth1.with({ year: 2024 });
console.log(nextYearMonth.toString()); // 2024-10

const nextMonth = yearMonth1.add({ months: 1 });
console.log(nextMonth.toString()); // 2023-11

const dateFromYearMonth = yearMonth1.toPlainDate({ day: 15 });
console.log(dateFromYearMonth.toString()); // 2023-10-15
```

**`Temporal.PlainTime` 示例:**

```javascript
const time1 = new Temporal.PlainTime(10, 30, 0);
const time2 = Temporal.PlainTime.from("10:30:00");

console.log(time1.equals(time2)); // true
console.log(Temporal.PlainTime.compare(time1, time2)); // 0

const laterTime = time1.with({ minute: 45 });
console.log(laterTime.toString()); // 10:45:00

const roundedTime = time1.round({ smallestUnit: 'hour' });
console.log(roundedTime.toString()); // 10:00:00

// 需要提供一个 Temporal.TimeZone 对象
// const zonedDateTime = time1.toZonedDateTime({ plainDate: "2023-10-27", timeZone: "UTC" });
// console.log(zonedDateTime.toString());
```

总而言之，这部分 C++ 代码是 V8 引擎中实现 `Temporal` API 中 `PlainMonthDay`, `PlainYearMonth` 和 `PlainTime` 对象核心功能的关键组成部分。它处理了对象的创建、转换、比较、算术运算、修改以及与其他 `Temporal` 类型的交互，使得 JavaScript 开发者能够在代码中使用这些强大的日期和时间抽象。

Prompt: 
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第10部分，共13部分，请归纳一下它的功能

"""
angeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateRecordWithCalendar>());
  }

  // 3. Let result be ? ParseISODateTime(isoString).
  DateTimeRecordWithCalendar result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseISODateTime(isolate, iso_string, *parsed),
      Nothing<DateRecordWithCalendar>());
  // 5. Let year be result.[[Year]].
  // 6. If no part of isoString is produced by the DateYear production, then
  // a. Set year to undefined.

  // 7. Return the Record { [[Year]]: year, [[Month]]: result.[[Month]],
  // [[Day]]: result.[[Day]], [[Calendar]]: result.[[Calendar]] }.
  DateRecordWithCalendar ret({result.date, result.calendar});
  return Just(ret);
}

// #sec-temporal-totemporalmonthday
MaybeHandle<JSTemporalPlainMonthDay> ToTemporalMonthDay(
    Isolate* isolate, Handle<Object> item_obj, Handle<Object> options,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 2. Assert: Type(options) is Object or Undefined.
  DCHECK(IsJSReceiver(*options) || IsUndefined(*options));

  // 3. Let referenceISOYear be 1972 (the first leap year after the Unix epoch).
  constexpr int32_t kReferenceIsoYear = 1972;
  // 4. If Type(item) is Object, then
  if (IsJSReceiver(*item_obj)) {
    Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
    // a. If item has an [[InitializedTemporalMonthDay]] internal slot, then
    // i. Return item.
    if (IsJSTemporalPlainMonthDay(*item_obj)) {
      return Cast<JSTemporalPlainMonthDay>(item_obj);
    }
    bool calendar_absent = false;
    // b. If item has an [[InitializedTemporalDate]],
    // [[InitializedTemporalDateTime]], [[InitializedTemporalTime]],
    // [[InitializedTemporalYearMonth]], or [[InitializedTemporalZonedDateTime]]
    // internal slot, then
    // i. Let calendar be item.[[Calendar]].
    // ii. Let calendarAbsent be false.
    Handle<JSReceiver> calendar;
    if (IsJSTemporalPlainDate(*item_obj)) {
      calendar =
          handle(Cast<JSTemporalPlainDate>(item_obj)->calendar(), isolate);
    } else if (IsJSTemporalPlainDateTime(*item_obj)) {
      calendar =
          handle(Cast<JSTemporalPlainDateTime>(item_obj)->calendar(), isolate);
    } else if (IsJSTemporalPlainTime(*item_obj)) {
      calendar =
          handle(Cast<JSTemporalPlainTime>(item_obj)->calendar(), isolate);
    } else if (IsJSTemporalPlainYearMonth(*item_obj)) {
      calendar =
          handle(Cast<JSTemporalPlainYearMonth>(item_obj)->calendar(), isolate);
    } else if (IsJSTemporalZonedDateTime(*item_obj)) {
      calendar =
          handle(Cast<JSTemporalZonedDateTime>(item_obj)->calendar(), isolate);
      // c. Else,
    } else {
      // i. Let calendar be ? Get(item, "calendar").
      Handle<Object> calendar_obj;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, calendar_obj,
          JSReceiver::GetProperty(isolate, item, factory->calendar_string()));
      // ii. If calendar is undefined, then
      if (IsUndefined(*calendar_obj)) {
        // 1. Let calendarAbsent be true.
        calendar_absent = true;
      }
      // iv. Set calendar to ? ToTemporalCalendarWithISODefault(calendar).
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, calendar,
          ToTemporalCalendarWithISODefault(isolate, calendar_obj, method_name));
    }
    // d. Let fieldNames be ? CalendarFields(calendar, « "day", "month",
    // "monthCode", "year" »).
    Handle<FixedArray> field_names = DayMonthMonthCodeYearInFixedArray(isolate);
    ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                               CalendarFields(isolate, calendar, field_names));
    // e. Let fields be ? PrepareTemporalFields(item, fieldNames, «»).
    Handle<JSReceiver> fields;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, fields,
                               PrepareTemporalFields(isolate, item, field_names,
                                                     RequiredFields::kNone));
    // f. Let month be ? Get(fields, "month").
    Handle<Object> month;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, month,
        JSReceiver::GetProperty(isolate, fields, factory->month_string()),
        Handle<JSTemporalPlainMonthDay>());
    // g. Let monthCode be ? Get(fields, "monthCode").
    Handle<Object> month_code;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, month_code,
        JSReceiver::GetProperty(isolate, fields, factory->monthCode_string()),
        Handle<JSTemporalPlainMonthDay>());
    // h. Let year be ? Get(fields, "year").
    Handle<Object> year;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, year,
        JSReceiver::GetProperty(isolate, fields, factory->year_string()),
        Handle<JSTemporalPlainMonthDay>());
    // i. If calendarAbsent is true, and month is not undefined, and monthCode
    // is undefined and year is undefined, then
    if (calendar_absent && !IsUndefined(*month) && IsUndefined(*month_code) &&
        IsUndefined(*year)) {
      // i. Perform ! CreateDataPropertyOrThrow(fields, "year",
      // 𝔽(referenceISOYear)).
      CHECK(JSReceiver::CreateDataProperty(
                isolate, fields, factory->year_string(),
                handle(Smi::FromInt(kReferenceIsoYear), isolate),
                Just(kThrowOnError))
                .FromJust());
    }
    // j. Return ? MonthDayFromFields(calendar, fields, options).
    return MonthDayFromFields(isolate, calendar, fields, options);
  }
  // 5. Perform ? ToTemporalOverflow(options).
  MAYBE_RETURN_ON_EXCEPTION_VALUE(
      isolate, ToTemporalOverflow(isolate, options, method_name),
      Handle<JSTemporalPlainMonthDay>());

  // 6. Let string be ? ToString(item).
  Handle<String> string;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, string,
                             Object::ToString(isolate, item_obj));

  // 7. Let result be ? ParseTemporalMonthDayString(string).
  DateRecordWithCalendar result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseTemporalMonthDayString(isolate, string),
      Handle<JSTemporalPlainMonthDay>());

  // 8. Let calendar be ? ToTemporalCalendarWithISODefault(result.[[Calendar]]).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ToTemporalCalendarWithISODefault(isolate, result.calendar, method_name));

  // 9. If result.[[Year]] is undefined, then
  // We use kMintInt31 to represent undefined
  if (result.date.year == kMinInt31) {
    // a. Return ? CreateTemporalMonthDay(result.[[Month]], result.[[Day]],
    // calendar, referenceISOYear).
    return CreateTemporalMonthDay(isolate, result.date.month, result.date.day,
                                  calendar, kReferenceIsoYear);
  }

  Handle<JSTemporalPlainMonthDay> created_result;
  // 10. Set result to ? CreateTemporalMonthDay(result.[[Month]],
  // result.[[Day]], calendar, referenceISOYear).
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, created_result,
      CreateTemporalMonthDay(isolate, result.date.month, result.date.day,
                             calendar, kReferenceIsoYear));
  // 11.  NOTE: The following operation is called without options, in order for
  // the calendar to store a canonical value in the [[ISOYear]] internal slot of
  // the result.
  // 12. Return ? CalendarMonthDayFromFields(calendar, result).
  return MonthDayFromFields(isolate, calendar, created_result);
}

MaybeHandle<JSTemporalPlainMonthDay> ToTemporalMonthDay(
    Isolate* isolate, Handle<Object> item_obj, const char* method_name) {
  // 1. If options is not present, set options to undefined.
  return ToTemporalMonthDay(isolate, item_obj,
                            isolate->factory()->undefined_value(), method_name);
}

}  // namespace

// #sec-temporal.plainmonthday.from
MaybeHandle<JSTemporalPlainMonthDay> JSTemporalPlainMonthDay::From(
    Isolate* isolate, Handle<Object> item, Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainMonthDay.from";
  // 1. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 2. If Type(item) is Object and item has an [[InitializedTemporalMonthDay]]
  // internal slot, then
  if (IsJSTemporalPlainMonthDay(*item)) {
    // a. Perform ? ToTemporalOverflow(options).
    MAYBE_RETURN_ON_EXCEPTION_VALUE(
        isolate, ToTemporalOverflow(isolate, options, method_name),
        Handle<JSTemporalPlainMonthDay>());
    // b. Return ? CreateTemporalMonthDay(item.[[ISOMonth]], item.[[ISODay]],
    // item.[[Calendar]], item.[[ISOYear]]).
    auto month_day = Cast<JSTemporalPlainMonthDay>(item);
    return CreateTemporalMonthDay(
        isolate, month_day->iso_month(), month_day->iso_day(),
        handle(month_day->calendar(), isolate), month_day->iso_year());
  }
  // 3. Return ? ToTemporalMonthDay(item, options).
  return ToTemporalMonthDay(isolate, item, options, method_name);
}

// #sec-temporal.plainyearmonth.prototype.equals
MaybeHandle<Oddball> JSTemporalPlainMonthDay::Equals(
    Isolate* isolate, DirectHandle<JSTemporalPlainMonthDay> month_day,
    Handle<Object> other_obj) {
  // 1. Let monthDay be the this value.
  // 2. Perform ? RequireInternalSlot(monthDay,
  // [[InitializedTemporalMonthDay]]).
  // 3. Set other to ? ToTemporalMonthDay(other).
  Handle<JSTemporalPlainMonthDay> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other,
      ToTemporalMonthDay(isolate, other_obj,
                         "Temporal.PlainMonthDay.prototype.equals"));
  // 4. If monthDay.[[ISOMonth]] ≠ other.[[ISOMonth]], return false.
  if (month_day->iso_month() != other->iso_month())
    return isolate->factory()->false_value();
  // 5. If monthDay.[[ISODay]] ≠ other.[[ISODay]], return false.
  if (month_day->iso_day() != other->iso_day())
    return isolate->factory()->false_value();
  // 6. If monthDay.[[ISOYear]] ≠ other.[[ISOYear]], return false.
  if (month_day->iso_year() != other->iso_year())
    return isolate->factory()->false_value();
  // 7. Return ? CalendarEquals(monthDay.[[Calendar]], other.[[Calendar]]).
  return CalendarEquals(isolate,
                        Handle<JSReceiver>(month_day->calendar(), isolate),
                        Handle<JSReceiver>(other->calendar(), isolate));
}

// #sec-temporal.plainmonthday.prototype.with
MaybeHandle<JSTemporalPlainMonthDay> JSTemporalPlainMonthDay::With(
    Isolate* isolate, Handle<JSTemporalPlainMonthDay> temporal_month_day,
    Handle<Object> temporal_month_day_like_obj, Handle<Object> options_obj) {
  // 6. Let fieldNames be ? CalendarFields(calendar, « "day", "month",
  // "monthCode", "year" »).
  Handle<FixedArray> field_names = DayMonthMonthCodeYearInFixedArray(isolate);
  return PlainDateOrYearMonthOrMonthDayWith<JSTemporalPlainMonthDay,
                                            MonthDayFromFields>(
      isolate, temporal_month_day, temporal_month_day_like_obj, options_obj,
      field_names, "Temporal.PlainMonthDay.prototype.with");
}

namespace {

// Common code shared by PlainMonthDay and PlainYearMonth.prototype.toPlainDate
template <typename T>
MaybeHandle<JSTemporalPlainDate> PlainMonthDayOrYearMonthToPlainDate(
    Isolate* isolate, Handle<T> temporal, Handle<Object> item_obj,
    DirectHandle<String> receiver_field_name_1,
    DirectHandle<String> receiver_field_name_2,
    DirectHandle<String> input_field_name) {
  Factory* factory = isolate->factory();
  // 1. Let monthDay be the this value.
  // 2. Perform ? RequireInternalSlot(monthDay,
  // [[InitializedTemporalXXX]]).
  // 3. If Type(item) is not Object, then
  if (!IsJSReceiver(*item_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
  // 4. Let calendar be Xxx.[[Calendar]].
  Handle<JSReceiver> calendar(temporal->calendar(), isolate);
  // 5. Let receiverFieldNames be ? CalendarFields(calendar, «
  // receiverFieldName1, receiverFieldName2 »).
  Handle<FixedArray> receiver_field_names = factory->NewFixedArray(2);
  receiver_field_names->set(0, *receiver_field_name_1);
  receiver_field_names->set(1, *receiver_field_name_2);
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, receiver_field_names,
      CalendarFields(isolate, calendar, receiver_field_names));
  // 6. Let fields be ? PrepareTemporalFields(temporal, receiverFieldNames, «»).
  Handle<JSReceiver> fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      PrepareTemporalFields(isolate, temporal, receiver_field_names,
                            RequiredFields::kNone));
  // 7. Let inputFieldNames be ? CalendarFields(calendar, « inputFieldName »).
  Handle<FixedArray> input_field_names = factory->NewFixedArray(1);
  input_field_names->set(0, *input_field_name);
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, input_field_names,
      CalendarFields(isolate, calendar, input_field_names));
  // 8. Let inputFields be ? PrepareTemporalFields(item, inputFieldNames, «»).
  Handle<JSReceiver> input_fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, input_fields,
      PrepareTemporalFields(isolate, item, input_field_names,
                            RequiredFields::kNone));
  // 9. Let mergedFields be ? CalendarMergeFields(calendar, fields,
  // inputFields).
  Handle<JSReceiver> merged_fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, merged_fields,
      CalendarMergeFields(isolate, calendar, fields, input_fields));
  // 10. Let mergedFieldNames be the List containing all the elements of
  // receiverFieldNames followed by all the elements of inputFieldNames, with
  // duplicate elements removed.
  Handle<FixedArray> merged_field_names = factory->NewFixedArray(
      receiver_field_names->length() + input_field_names->length());
  Handle<StringSet> added = StringSet::New(isolate);
  for (int i = 0; i < receiver_field_names->length(); i++) {
    Handle<Object> item(receiver_field_names->get(i), isolate);
    DCHECK(IsString(*item));
    auto string = Cast<String>(item);
    if (!added->Has(isolate, string)) {
      merged_field_names->set(added->NumberOfElements(), *item);
      added = StringSet::Add(isolate, added, string);
    }
  }
  for (int i = 0; i < input_field_names->length(); i++) {
    Handle<Object> item(input_field_names->get(i), isolate);
    DCHECK(IsString(*item));
    auto string = Cast<String>(item);
    if (!added->Has(isolate, string)) {
      merged_field_names->set(added->NumberOfElements(), *item);
      added = StringSet::Add(isolate, added, string);
    }
  }
  merged_field_names = FixedArray::RightTrimOrEmpty(isolate, merged_field_names,
                                                    added->NumberOfElements());

  // 11. Set mergedFields to ? PrepareTemporalFields(mergedFields,
  // mergedFieldNames, «»).
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, merged_fields,
      PrepareTemporalFields(isolate, merged_fields, merged_field_names,
                            RequiredFields::kNone));
  // 12. Let options be ! OrdinaryObjectCreate(null).
  Handle<JSObject> options = factory->NewJSObjectWithNullProto();
  // 13. Perform ! CreateDataPropertyOrThrow(options, "overflow", "reject").
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->overflow_string(),
            factory->reject_string(), Just(kThrowOnError))
            .FromJust());
  // 14. Return ? DateFromFields(calendar, mergedFields, options).
  return DateFromFields(isolate, calendar, merged_fields, options);
}

}  // namespace

// #sec-temporal.plainmonthday.prototype.toplaindate
MaybeHandle<JSTemporalPlainDate> JSTemporalPlainMonthDay::ToPlainDate(
    Isolate* isolate, Handle<JSTemporalPlainMonthDay> month_day,
    Handle<Object> item_obj) {
  Factory* factory = isolate->factory();
  // 5. Let receiverFieldNames be ? CalendarFields(calendar, « "day",
  // "monthCode" »).
  // 7. Let inputFieldNames be ? CalendarFields(calendar, « "year" »).
  return PlainMonthDayOrYearMonthToPlainDate<JSTemporalPlainMonthDay>(
      isolate, month_day, item_obj, factory->day_string(),
      factory->monthCode_string(), factory->year_string());
}

// #sec-temporal.plainmonthday.prototype.getisofields
MaybeHandle<JSReceiver> JSTemporalPlainMonthDay::GetISOFields(
    Isolate* isolate, DirectHandle<JSTemporalPlainMonthDay> month_day) {
  Factory* factory = isolate->factory();
  // 1. Let monthDay be the this value.
  // 2. Perform ? RequireInternalSlot(monthDay,
  // [[InitializedTemporalMonthDay]]).
  // 3. Let fields be ! OrdinaryObjectCreate(%Object.prototype%).
  Handle<JSObject> fields = factory->NewJSObject(isolate->object_function());
  // 4. Perform ! CreateDataPropertyOrThrow(fields, "calendar",
  // montyDay.[[Calendar]]).
  CHECK(JSReceiver::CreateDataProperty(
            isolate, fields, factory->calendar_string(),
            Handle<JSReceiver>(month_day->calendar(), isolate),
            Just(kThrowOnError))
            .FromJust());

  // 5. Perform ! CreateDataPropertyOrThrow(fields, "isoDay",
  // 𝔽(montyDay.[[ISODay]])).
  // 6. Perform ! CreateDataPropertyOrThrow(fields, "isoMonth",
  // 𝔽(montyDay.[[ISOMonth]])).
  // 7. Perform ! CreateDataPropertyOrThrow(fields, "isoYear",
  // 𝔽(montyDay.[[ISOYear]])).
  DEFINE_INT_FIELD(fields, isoDay, iso_day, month_day)
  DEFINE_INT_FIELD(fields, isoMonth, iso_month, month_day)
  DEFINE_INT_FIELD(fields, isoYear, iso_year, month_day)
  // 8. Return fields.
  return fields;
}

// #sec-temporal.plainmonthday.prototype.tojson
MaybeHandle<String> JSTemporalPlainMonthDay::ToJSON(
    Isolate* isolate, DirectHandle<JSTemporalPlainMonthDay> month_day) {
  return TemporalMonthDayToString(isolate, month_day, ShowCalendar::kAuto);
}

// #sec-temporal.plainmonthday.prototype.tostring
MaybeHandle<String> JSTemporalPlainMonthDay::ToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainMonthDay> month_day,
    Handle<Object> options) {
  return TemporalToString<JSTemporalPlainMonthDay, TemporalMonthDayToString>(
      isolate, month_day, options, "Temporal.PlainMonthDay.prototype.toString");
}

// #sec-temporal.plainmonthday.prototype.tolocalestring
MaybeHandle<String> JSTemporalPlainMonthDay::ToLocaleString(
    Isolate* isolate, Handle<JSTemporalPlainMonthDay> month_day,
    Handle<Object> locales, Handle<Object> options) {
#ifdef V8_INTL_SUPPORT
  return JSDateTimeFormat::TemporalToLocaleString(
      isolate, month_day, locales, options,
      "Temporal.PlainMonthDay.prototype.toLocaleString");
#else   //  V8_INTL_SUPPORT
  return TemporalMonthDayToString(isolate, month_day, ShowCalendar::kAuto);
#endif  //  V8_INTL_SUPPORT
}

MaybeHandle<JSTemporalPlainYearMonth> JSTemporalPlainYearMonth::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> iso_year_obj, Handle<Object> iso_month_obj,
    Handle<Object> calendar_like, Handle<Object> reference_iso_day_obj) {
  const char* method_name = "Temporal.PlainYearMonth";
  // 1. If NewTarget is undefined, throw a TypeError exception.
  if (IsUndefined(*new_target)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }
  // 7. Let calendar be ? ToTemporalCalendarWithISODefault(calendarLike).
  // 10. Return ? CreateTemporalYearMonth(y, m, calendar, ref, NewTarget).

  // 3. Let y be ? ToIntegerThrowOnInfinity(isoYear).
  TO_INT_THROW_ON_INFTY(iso_year, JSTemporalPlainYearMonth);
  // 5. Let m be ? ToIntegerThrowOnInfinity(isoMonth).
  TO_INT_THROW_ON_INFTY(iso_month, JSTemporalPlainYearMonth);
  // 7. Let calendar be ? ToTemporalCalendarWithISODefault(calendarLike).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ToTemporalCalendarWithISODefault(isolate, calendar_like, method_name));

  // 2. If referenceISODay is undefined, then
  // a. Set referenceISODay to 1𝔽.
  // ...
  // 8. Let ref be ? ToIntegerThrowOnInfinity(referenceISODay).
  int32_t ref = 1;
  if (!IsUndefined(*reference_iso_day_obj)) {
    TO_INT_THROW_ON_INFTY(reference_iso_day, JSTemporalPlainYearMonth);
    ref = reference_iso_day;
  }

  // 10. Return ? CreateTemporalYearMonth(y, m, calendar, ref, NewTarget).
  return CreateTemporalYearMonth(isolate, target, new_target, iso_year,
                                 iso_month, calendar, ref);
}

namespace {

// #sec-temporal-parsetemporalyearmonthstring
Maybe<DateRecordWithCalendar> ParseTemporalYearMonthString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: Type(isoString) is String.
  // 2. If isoString does not satisfy the syntax of a TemporalYearMonthString
  // (see 13.33), then
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalYearMonthString(isolate, iso_string);
  if (!parsed.has_value()) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateRecordWithCalendar>());
  }

  // 3. If _isoString_ contains a |UTCDesignator|, then
  if (parsed->utc_designator) {
    // a. Throw a *RangeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateRecordWithCalendar>());
  }

  // 3. Let result be ? ParseISODateTime(isoString).
  DateTimeRecordWithCalendar result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseISODateTime(isolate, iso_string, *parsed),
      Nothing<DateRecordWithCalendar>());

  // 4. Return the Record { [[Year]]: result.[[Year]], [[Month]]:
  // result.[[Month]], [[Day]]: result.[[Day]], [[Calendar]]:
  // result.[[Calendar]] }.
  DateRecordWithCalendar ret = {
      {result.date.year, result.date.month, result.date.day}, result.calendar};
  return Just(ret);
}

// #sec-temporal-totemporalyearmonth
MaybeHandle<JSTemporalPlainYearMonth> ToTemporalYearMonth(
    Isolate* isolate, Handle<Object> item_obj, Handle<Object> options,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 2. Assert: Type(options) is Object or Undefined.
  DCHECK(IsJSReceiver(*options) || IsUndefined(*options));
  // 3. If Type(item) is Object, then
  if (IsJSReceiver(*item_obj)) {
    Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
    // a. If item has an [[InitializedTemporalYearMonth]] internal slot, then
    // i. Return item.
    if (IsJSTemporalPlainYearMonth(*item_obj)) {
      return Cast<JSTemporalPlainYearMonth>(item_obj);
    }

    // b. Let calendar be ? GetTemporalCalendarWithISODefault(item).
    Handle<JSReceiver> calendar;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, calendar,
        GetTemporalCalendarWithISODefault(isolate, item, method_name));
    // c. Let fieldNames be ? CalendarFields(calendar, « "month", "monthCode",
    // "year" »).
    Handle<FixedArray> field_names = MonthMonthCodeYearInFixedArray(isolate);
    ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                               CalendarFields(isolate, calendar, field_names));
    // d. Let fields be ? PrepareTemporalFields(item, fieldNames, «»).
    Handle<JSReceiver> fields;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, fields,
                               PrepareTemporalFields(isolate, item, field_names,
                                                     RequiredFields::kNone));
    // e. Return ? YearMonthFromFields(calendar, fields, options).
    return YearMonthFromFields(isolate, calendar, fields, options);
  }
  // 4. Perform ? ToTemporalOverflow(options).
  MAYBE_RETURN_ON_EXCEPTION_VALUE(
      isolate, ToTemporalOverflow(isolate, options, method_name),
      Handle<JSTemporalPlainYearMonth>());
  // 5. Let string be ? ToString(item).
  Handle<String> string;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, string,
                             Object::ToString(isolate, item_obj));
  // 6. Let result be ? ParseTemporalYearMonthString(string).
  DateRecordWithCalendar result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseTemporalYearMonthString(isolate, string),
      Handle<JSTemporalPlainYearMonth>());
  // 7. Let calendar be ? ToTemporalCalendarWithISODefault(result.[[Calendar]]).
  Handle<JSReceiver> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      ToTemporalCalendarWithISODefault(isolate, result.calendar, method_name));
  // 8. Set result to ? CreateTemporalYearMonth(result.[[Year]],
  // result.[[Month]], calendar, result.[[Day]]).
  Handle<JSTemporalPlainYearMonth> created_result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, created_result,
      CreateTemporalYearMonth(isolate, result.date.year, result.date.month,
                              calendar, result.date.day));
  // 9. NOTE: The following operation is called without options, in order for
  // the calendar to store a canonical value in the [[ISODay]] internal slot of
  // the result.
  // 10. Return ? CalendarYearMonthFromFields(calendar, result).
  return YearMonthFromFields(isolate, calendar, created_result);
}

MaybeHandle<JSTemporalPlainYearMonth> ToTemporalYearMonth(
    Isolate* isolate, Handle<Object> item_obj, const char* method_name) {
  // 1. If options is not present, set options to undefined.
  return ToTemporalYearMonth(
      isolate, item_obj, isolate->factory()->undefined_value(), method_name);
}

}  // namespace

// #sec-temporal.plainyearmonth.from
MaybeHandle<JSTemporalPlainYearMonth> JSTemporalPlainYearMonth::From(
    Isolate* isolate, Handle<Object> item, Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainYearMonth.from";
  // 1. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 2. If Type(item) is Object and item has an [[InitializedTemporalYearMonth]]
  // internal slot, then
  if (IsJSTemporalPlainYearMonth(*item)) {
    // a. Perform ? ToTemporalOverflow(options).
    MAYBE_RETURN_ON_EXCEPTION_VALUE(
        isolate, ToTemporalOverflow(isolate, options, method_name),
        Handle<JSTemporalPlainYearMonth>());
    // b. Return ? CreateTemporalYearMonth(item.[[ISOYear]], item.[[ISOMonth]],
    // item.[[Calendar]], item.[[ISODay]]).
    auto year_month = Cast<JSTemporalPlainYearMonth>(item);
    return CreateTemporalYearMonth(
        isolate, year_month->iso_year(), year_month->iso_month(),
        handle(year_month->calendar(), isolate), year_month->iso_day());
  }
  // 3. Return ? ToTemporalYearMonth(item, options).
  return ToTemporalYearMonth(isolate, item, options, method_name);
}

// #sec-temporal.plainyearmonth.compare
MaybeHandle<Smi> JSTemporalPlainYearMonth::Compare(Isolate* isolate,
                                                   Handle<Object> one_obj,
                                                   Handle<Object> two_obj) {
  const char* method_name = "Temporal.PlainYearMonth.compare";
  // 1. Set one to ? ToTemporalYearMonth(one).
  Handle<JSTemporalPlainYearMonth> one;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, one, ToTemporalYearMonth(isolate, one_obj, method_name));
  // 2. Set two to ? ToTemporalYearMonth(two).
  Handle<JSTemporalPlainYearMonth> two;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, two, ToTemporalYearMonth(isolate, two_obj, method_name));
  // 3. Return 𝔽(! CompareISODate(one.[[ISOYear]], one.[[ISOMonth]],
  // one.[[ISODay]], two.[[ISOYear]], two.[[ISOMonth]], two.[[ISODay]])).
  return handle(Smi::FromInt(CompareISODate(
                    {one->iso_year(), one->iso_month(), one->iso_day()},
                    {two->iso_year(), two->iso_month(), two->iso_day()})),
                isolate);
}

// #sec-temporal.plainyearmonth.prototype.equals
MaybeHandle<Oddball> JSTemporalPlainYearMonth::Equals(
    Isolate* isolate, DirectHandle<JSTemporalPlainYearMonth> year_month,
    Handle<Object> other_obj) {
  // 1. Let yearMonth be the this value.
  // 2. Perform ? RequireInternalSlot(yearMonth,
  // [[InitializedTemporalYearMonth]]).
  // 3. Set other to ? ToTemporalYearMonth(other).
  Handle<JSTemporalPlainYearMonth> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other,
      ToTemporalYearMonth(isolate, other_obj,
                          "Temporal.PlainYearMonth.prototype.equals"));
  // 4. If yearMonth.[[ISOYear]] ≠ other.[[ISOYear]], return false.
  if (year_month->iso_year() != other->iso_year())
    return isolate->factory()->false_value();
  // 5. If yearMonth.[[ISOMonth]] ≠ other.[[ISOMonth]], return false.
  if (year_month->iso_month() != other->iso_month())
    return isolate->factory()->false_value();
  // 6. If yearMonth.[[ISODay]] ≠ other.[[ISODay]], return false.
  if (year_month->iso_day() != other->iso_day())
    return isolate->factory()->false_value();
  // 7. Return ? CalendarEquals(yearMonth.[[Calendar]], other.[[Calendar]]).
  return CalendarEquals(isolate,
                        Handle<JSReceiver>(year_month->calendar(), isolate),
                        Handle<JSReceiver>(other->calendar(), isolate));
}

namespace {

MaybeHandle<JSTemporalPlainYearMonth>
AddDurationToOrSubtractDurationFromPlainYearMonth(
    Isolate* isolate, Arithmetic operation,
    Handle<JSTemporalPlainYearMonth> year_month,
    Handle<Object> temporal_duration_like, Handle<Object> options_obj,
    const char* method_name) {
  // 1. Let duration be ? ToTemporalDurationRecord(temporalDurationLike).
  DurationRecord duration;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, duration,
      temporal::ToTemporalDurationRecord(isolate, temporal_duration_like,
                                         method_name),
      Handle<JSTemporalPlainYearMonth>());

  // 2. If operation is subtract, then
  if (operation == Arithmetic::kSubtract) {
    // a. Set duration to ! CreateNegatedDurationRecord(duration).
    duration = CreateNegatedDurationRecord(isolate, duration).ToChecked();
  }
  // 3. Let balanceResult be ? BalanceDuration(duration.[[Days]],
  // duration.[[Hours]], duration.[[Minutes]], duration.[[Seconds]],
  // duration.[[Milliseconds]], duration.[[Microseconds]],
  // duration.[[Nanoseconds]], "day").
  TimeDurationRecord balance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, balance_result,
      BalanceDuration(isolate, Unit::kDay, duration.time_duration, method_name),
      Handle<JSTemporalPlainYearMonth>());
  // 4. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 5. Let calendar be yearMonth.[[Calendar]].
  Handle<JSReceiver> calendar(year_month->calendar(), isolate);

  // 6. Let fieldNames be ? CalendarFields(calendar, « "monthCode", "year" »).
  Factory* factory = isolate->factory();
  Handle<FixedArray> field_names = MonthCodeYearInFixedArray(isolate);
  ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                             CalendarFields(isolate, calendar, field_names));

  // 7. Let fields be ? PrepareTemporalFields(yearMonth, fieldNames, «»).
  Handle<JSReceiver> fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      PrepareTemporalFields(isolate, year_month, field_names,
                            RequiredFields::kNone));

  // 8. Set sign to ! DurationSign(duration.[[Years]], duration.[[Months]],
  // duration.[[Weeks]], balanceResult.[[Days]], 0, 0, 0, 0, 0, 0).
  int32_t sign =
      DurationRecord::Sign({duration.years,
                            duration.months,
                            duration.weeks,
                            {balance_result.days, 0, 0, 0, 0, 0, 0}});

  // 9. If sign < 0, then
  Handle<Object> day;
  if (sign < 0) {
    // a. Let dayFromCalendar be ? CalendarDaysInMonth(calendar, yearMonth).
    Handle<Object> day_from_calendar;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, day_from_calendar,
        temporal::CalendarDaysInMonth(isolate, calendar, year_month));

    // b. Let day be ? ToPositiveInteger(dayFromCalendar).
    ASSIGN_RETURN_ON_EXCEPTION(isolate, day,
                               ToPositiveInteger(isolate, day_from_calendar));
    // 10. Else,
  } else {
    // a. Let day be 1.
    day = handle(Smi::FromInt(1), isolate);
  }
  // 11. Perform ! CreateDataPropertyOrThrow(fields, "day", day).
  CHECK(JSReceiver::CreateDataProperty(isolate, fields, factory->day_string(),
                                       day, Just(kThrowOnError))
            .FromJust());

  // 12. Let date be ? CalendarDateFromFields(calendar, fields).
  Handle<JSTemporalPlainDate> date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date,
      FromFields<JSTemporalPlainDate>(
          isolate, calendar, fields, isolate->factory()->undefined_value(),
          isolate->factory()->dateFromFields_string(),
          JS_TEMPORAL_PLAIN_DATE_TYPE));

  // 13. Let durationToAdd be ! CreateTemporalDuration(duration.[[Years]],
  // duration.[[Months]], duration.[[Weeks]], balanceResult.[[Days]], 0, 0, 0,
  // 0, 0, 0).
  Handle<JSTemporalDuration> duration_to_add =
      CreateTemporalDuration(isolate, {duration.years,
                                       duration.months,
                                       duration.weeks,
                                       {balance_result.days, 0, 0, 0, 0, 0, 0}})
          .ToHandleChecked();
  // 14. Let optionsCopy be OrdinaryObjectCreate(null).
  Handle<JSReceiver> options_copy =
      isolate->factory()->NewJSObjectWithNullProto();

  // 15. Let entries be ? EnumerableOwnPropertyNames(options, key+value).
  // 16. For each element nextEntry of entries, do
  // a. Perform ! CreateDataPropertyOrThrow(optionsCopy, nextEntry[0],
  // nextEntry[1]).
  bool set;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, set,
      JSReceiver::SetOrCopyDataProperties(
          isolate, options_copy, options,
          PropertiesEnumerationMode::kEnumerationOrder, {}, false),
      Handle<JSTemporalPlainYearMonth>());

  // 17. Let addedDate be ? CalendarDateAdd(calendar, date, durationToAdd,
  // options).
  Handle<JSTemporalPlainDate> added_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, added_date,
      CalendarDateAdd(isolate, calendar, date, duration_to_add, options));
  // 18. Let addedDateFields be ? PrepareTemporalFields(addedDate, fieldNames,
  // «»).
  Handle<JSReceiver> added_date_fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, added_date_fields,
      PrepareTemporalFields(isolate, added_date, field_names,
                            RequiredFields::kNone));
  // 19. Return ? CalendarYearMonthFromFields(calendar, addedDateFields,
  // optionsCopy).
  return FromFields<JSTemporalPlainYearMonth>(
      isolate, calendar, added_date_fields, options_copy,
      isolate->factory()->yearMonthFromFields_string(),
      JS_TEMPORAL_PLAIN_YEAR_MONTH_TYPE);
}

}  // namespace

// #sec-temporal.plainyearmonth.prototype.add
MaybeHandle<JSTemporalPlainYearMonth> JSTemporalPlainYearMonth::Add(
    Isolate* isolate, Handle<JSTemporalPlainYearMonth> year_month,
    Handle<Object> temporal_duration_like, Handle<Object> options) {
  return AddDurationToOrSubtractDurationFromPlainYearMonth(
      isolate, Arithmetic::kAdd, year_month, temporal_duration_like, options,
      "Temporal.PlainYearMonth.prototype.add");
}

// #sec-temporal.plainyearmonth.prototype.subtract
MaybeHandle<JSTemporalPlainYearMonth> JSTemporalPlainYearMonth::Subtract(
    Isolate* isolate, Handle<JSTemporalPlainYearMonth> year_month,
    Handle<Object> temporal_duration_like, Handle<Object> options) {
  return AddDurationToOrSubtractDurationFromPlainYearMonth(
      isolate, Arithmetic::kSubtract, year_month, temporal_duration_like,
      options, "Temporal.PlainYearMonth.prototype.subtract");
}

namespace {
// #sec-temporal-differencetemporalplandyearmonth
MaybeHandle<JSTemporalDuration> DifferenceTemporalPlainYearMonth(
    Isolate* isolate, TimePreposition operation,
    Handle<JSTemporalPlainYearMonth> year_month, Handle<Object> other_obj,
    Handle<Object> options, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. If operation is since, let sign be -1. Otherwise, let sign be 1.
  double sign = operation == TimePreposition::kSince ? -1 : 1;
  // 2. Set other to ? ToTemporalDateTime(other).
  Handle<JSTemporalPlainYearMonth> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other, ToTemporalYearMonth(isolate, other_obj, method_name));
  // 3. Let calendar be yearMonth.[[Calendar]].
  Handle<JSReceiver> calendar(year_month->calendar(), isolate);

  // 4. If ? CalendarEquals(calendar, other.[[Calendar]]) is false, throw a
  // RangeError exception.
  bool calendar_equals;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar_equals,
      CalendarEqualsBool(isolate, calendar, handle(other->calendar(), isolate)),
      Handle<JSTemporalDuration>());
  if (!calendar_equals) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }

  // 5. Let settings be ? GetDifferenceSettings(operation, options, date, «
  // "week", "day" », "month", "year").
  DifferenceSettings settings;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, settings,
      GetDifferenceSettings(isolate, operation, options, UnitGroup::kDate,
                            DisallowedUnitsInDifferenceSettings::kWeekAndDay,
                            Unit::kMonth, Unit::kYear, method_name),
      Handle<JSTemporalDuration>());
  // 6. Let fieldNames be ? CalendarFields(calendar, « "monthCode", "year" »).
  Factory* factory = isolate->factory();
  Handle<FixedArray> field_names = MonthCodeYearInFixedArray(isolate);
  ASSIGN_RETURN_ON_EXCEPTION(isolate, field_names,
                             CalendarFields(isolate, calendar, field_names));

  // 7. Let otherFields be ? PrepareTemporalFields(other, fieldNames, «»).
  Handle<JSReceiver> other_fields;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, other_fields,
                             PrepareTemporalFields(isolate, other, field_names,
                                                   RequiredFields::kNone));
  // 8. Perform ! CreateDataPropertyOrThrow(otherFields, "day", 1𝔽).
  Handle<Object> one = handle(Smi::FromInt(1), isolate);
  CHECK(JSReceiver::CreateDataProperty(isolate, other_fields,
                                       factory->day_string(), one,
                                       Just(kThrowOnError))
            .FromJust());
  // 9. Let otherDate be ? CalendarDateFromFields(calendar, otherFields).
  //  DateFromFields(Isolate* isolate,
  Handle<JSTemporalPlainDate> other_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other_date,
      DateFromFields(isolate, calendar, other_fields,
                     isolate->factory()->undefined_value()));
  // 10. Let thisFields be ? PrepareTemporalFields(yearMonth, fieldNames, «»).
  Handle<JSReceiver> this_fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, this_fields,
      PrepareTemporalFields(isolate, year_month, field_names,
                            RequiredFields::kNone));
  // 11. Perform ! CreateDataPropertyOrThrow(thisFields, "day", 1𝔽).
  CHECK(JSReceiver::CreateDataProperty(isolate, this_fields,
                                       factory->day_string(), one,
                                       Just(kThrowOnError))
            .FromJust());
  // 12. Let thisDate be ? CalendarDateFromFields(calendar, thisFields).
  Handle<JSTemporalPlainDate> this_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, this_date,
      DateFromFields(isolate, calendar, this_fields,
                     isolate->factory()->undefined_value()));
  // 13. Let untilOptions be ? MergeLargestUnitOption(settings.[[Options]],
  // settings.[[LargestUnit]]).
  Handle<JSReceiver> until_options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, until_options,
      MergeLargestUnitOption(isolate, settings.options, settings.largest_unit));
  // 14. Let result be ? CalendarDateUntil(calendar, thisDate, otherDate,
  // untilOptions).
  Handle<JSTemporalDuration> result;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, result,
                             CalendarDateUntil(isolate, calendar, this_date,
                                               other_date, until_options));

  // 15. If settings.[[SmallestUnit]] is not "month" or
  // settings.[[RoundingIncrement]] ≠ 1, then
  if (settings.smallest_unit != Unit::kMonth ||
      settings.rounding_increment != 1) {
    // a. Set result to (? RoundDuration(result.[[Years]], result.[[Months]], 0,
    // 0, 0, 0, 0, 0, 0, 0, settings.[[RoundingIncrement]],
    // settings.[[SmallestUnit]], settings.[[RoundingMode]],
    // thisDate)).[[DurationRecord]].
    DurationRecordWithRemainder round_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, round_result,
        RoundDuration(isolate,
                      {Object::NumberValue(result->years()),
                       Object::NumberValue(result->months()),
                       0,
                       {0, 0, 0, 0, 0, 0, 0}},
                      settings.rounding_increment, settings.smallest_unit,
                      settings.rounding_mode, this_date, method_name),
        Handle<JSTemporalDuration>());
    // 16. Return ! CreateTemporalDuration(sign × result.[[Years]], sign ×
    // result.[[Months]], 0, 0, 0, 0, 0, 0, 0, 0).
    return CreateTemporalDuration(isolate, {round_result.record.years * sign,
                                            round_result.record.months * sign,
                                            0,
                                            {0, 0, 0, 0, 0, 0, 0}})
        .ToHandleChecked();
  }
  // 16. Return ! CreateTemporalDuration(sign × result.[[Years]], sign ×
  // result.[[Months]], 0, 0, 0, 0, 0, 0, 0, 0).
  return CreateTemporalDuration(isolate,
                                {Object::NumberValue(result->years()) * sign,
                                 Object::NumberValue(result->months()) * sign,
                                 0,
                                 {0, 0, 0, 0, 0, 0, 0}})
      .ToHandleChecked();
}

}  // namespace

// #sec-temporal.plainyearmonth.prototype.until
MaybeHandle<JSTemporalDuration> JSTemporalPlainYearMonth::Until(
    Isolate* isolate, Handle<JSTemporalPlainYearMonth> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalPlainYearMonth(
      isolate, TimePreposition::kUntil, handle, other, options,
      "Temporal.PlainYearMonth.prototype.until");
}

// #sec-temporal.plainyearmonth.prototype.since
MaybeHandle<JSTemporalDuration> JSTemporalPlainYearMonth::Since(
    Isolate* isolate, Handle<JSTemporalPlainYearMonth> handle,
    Handle<Object> other, Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();
  return DifferenceTemporalPlainYearMonth(
      isolate, TimePreposition::kSince, handle, other, options,
      "Temporal.PlainYearMonth.prototype.since");
}

// #sec-temporal.plainyearmonth.prototype.with
MaybeHandle<JSTemporalPlainYearMonth> JSTemporalPlainYearMonth::With(
    Isolate* isolate, Handle<JSTemporalPlainYearMonth> temporal_year_month,
    Handle<Object> temporal_year_month_like_obj, Handle<Object> options_obj) {
  // 6. Let fieldNames be ? CalendarFields(calendar, « "month", "monthCode",
  // "year" »).
  Handle<FixedArray> field_names = MonthMonthCodeYearInFixedArray(isolate);
  return PlainDateOrYearMonthOrMonthDayWith<JSTemporalPlainYearMonth,
                                            YearMonthFromFields>(
      isolate, temporal_year_month, temporal_year_month_like_obj, options_obj,
      field_names, "Temporal.PlainYearMonth.prototype.with");
}

// #sec-temporal.plainyearmonth.prototype.toplaindate
MaybeHandle<JSTemporalPlainDate> JSTemporalPlainYearMonth::ToPlainDate(
    Isolate* isolate, Handle<JSTemporalPlainYearMonth> year_month,
    Handle<Object> item_obj) {
  Factory* factory = isolate->factory();
  // 5. Let receiverFieldNames be ? CalendarFields(calendar, « "monthCode",
  // "year" »).
  // 7. Let inputFieldNames be ? CalendarFields(calendar, « "day" »).
  return PlainMonthDayOrYearMonthToPlainDate<JSTemporalPlainYearMonth>(
      isolate, year_month, item_obj, factory->monthCode_string(),
      factory->year_string(), factory->day_string());
}

// #sec-temporal.plainyearmonth.prototype.getisofields
MaybeHandle<JSReceiver> JSTemporalPlainYearMonth::GetISOFields(
    Isolate* isolate, DirectHandle<JSTemporalPlainYearMonth> year_month) {
  Factory* factory = isolate->factory();
  // 1. Let yearMonth be the this value.
  // 2. Perform ? RequireInternalSlot(yearMonth,
  // [[InitializedTemporalYearMonth]]).
  // 3. Let fields be ! OrdinaryObjectCreate(%Object.prototype%).
  Handle<JSObject> fields =
      isolate->factory()->NewJSObject(isolate->object_function());
  // 4. Perform ! CreateDataPropertyOrThrow(fields, "calendar",
  // yearMonth.[[Calendar]]).
  CHECK(JSReceiver::CreateDataProperty(
            isolate, fields, factory->calendar_string(),
            Handle<JSReceiver>(year_month->calendar(), isolate),
            Just(kThrowOnError))
            .FromJust());
  // 5. Perform ! CreateDataPropertyOrThrow(fields, "isoDay",
  // 𝔽(yearMonth.[[ISODay]])).
  // 6. Perform ! CreateDataPropertyOrThrow(fields, "isoMonth",
  // 𝔽(yearMonth.[[ISOMonth]])).
  // 7. Perform ! CreateDataPropertyOrThrow(fields, "isoYear",
  // 𝔽(yearMonth.[[ISOYear]])).
  DEFINE_INT_FIELD(fields, isoDay, iso_day, year_month)
  DEFINE_INT_FIELD(fields, isoMonth, iso_month, year_month)
  DEFINE_INT_FIELD(fields, isoYear, iso_year, year_month)
  // 8. Return fields.
  return fields;
}

// #sec-temporal.plainyearmonth.prototype.tojson
MaybeHandle<String> JSTemporalPlainYearMonth::ToJSON(
    Isolate* isolate, DirectHandle<JSTemporalPlainYearMonth> year_month) {
  return TemporalYearMonthToString(isolate, year_month, ShowCalendar::kAuto);
}

// #sec-temporal.plainyearmonth.prototype.tostring
MaybeHandle<String> JSTemporalPlainYearMonth::ToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainYearMonth> year_month,
    Handle<Object> options) {
  return TemporalToString<JSTemporalPlainYearMonth, TemporalYearMonthToString>(
      isolate, year_month, options,
      "Temporal.PlainYearMonth.prototype.toString");
}

// #sec-temporal.plainyearmonth.prototype.tolocalestring
MaybeHandle<String> JSTemporalPlainYearMonth::ToLocaleString(
    Isolate* isolate, Handle<JSTemporalPlainYearMonth> year_month,
    Handle<Object> locales, Handle<Object> options) {
#ifdef V8_INTL_SUPPORT
  return JSDateTimeFormat::TemporalToLocaleString(
      isolate, year_month, locales, options,
      "Temporal.PlainYearMonth.prototype.toLocaleString");
#else   //  V8_INTL_SUPPORT
  return TemporalYearMonthToString(isolate, year_month, ShowCalendar::kAuto);
#endif  //  V8_INTL_SUPPORT
}

// #sec-temporal-plaintime-constructor
MaybeHandle<JSTemporalPlainTime> JSTemporalPlainTime::Constructor(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<Object> hour_obj, Handle<Object> minute_obj,
    Handle<Object> second_obj, Handle<Object> millisecond_obj,
    Handle<Object> microsecond_obj, Handle<Object> nanosecond_obj) {
  const char* method_name = "Temporal.PlainTime";
  // 1. If NewTarget is undefined, then
  // a. Throw a TypeError exception.
  if (IsUndefined(*new_target)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     method_name)));
  }

  TO_INT_THROW_ON_INFTY(hour, JSTemporalPlainTime);
  TO_INT_THROW_ON_INFTY(minute, JSTemporalPlainTime);
  TO_INT_THROW_ON_INFTY(second, JSTemporalPlainTime);
  TO_INT_THROW_ON_INFTY(millisecond, JSTemporalPlainTime);
  TO_INT_THROW_ON_INFTY(microsecond, JSTemporalPlainTime);
  TO_INT_THROW_ON_INFTY(nanosecond, JSTemporalPlainTime);

  // 14. Return ? CreateTemporalTime(hour, minute, second, millisecond,
  // microsecond, nanosecond, NewTarget).
  return CreateTemporalTime(
      isolate, target, new_target,
      {hour, minute, second, millisecond, microsecond, nanosecond});
}

// #sec-temporal.plaintime.prototype.tozoneddatetime
MaybeHandle<JSTemporalZonedDateTime> JSTemporalPlainTime::ToZonedDateTime(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> item_obj) {
  const char* method_name = "Temporal.PlainTime.prototype.toZonedDateTime";
  Factory* factory = isolate->factory();
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalTime,
  // [[InitializedTemporalTime]]).
  // 3. If Type(item) is not Object, then
  if (!IsJSReceiver(*item_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  Handle<JSReceiver> item = Cast<JSReceiver>(item_obj);
  // 4. Let temporalDateLike be ? Get(item, "plainDate").
  Handle<Object> temporal_date_like;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_like,
      JSReceiver::GetProperty(isolate, item, factory->plainDate_string()));
  // 5. If temporalDateLike is undefined, then
  if (IsUndefined(*temporal_date_like)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  // 6. Let temporalDate be ? ToTemporalDate(temporalDateLike).
  Handle<JSTemporalPlainDate> temporal_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date,
      ToTemporalDate(isolate, temporal_date_like, method_name));
  // 7. Let temporalTimeZoneLike be ? Get(item, "timeZone").
  Handle<Object> temporal_time_zone_like;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_time_zone_like,
      JSReceiver::GetProperty(isolate, item, factory->timeZone_string()));
  // 8. If temporalTimeZoneLike is undefined, then
  if (IsUndefined(*temporal_time_zone_like)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  // 9. Let timeZone be ? ToTemporalTimeZone(temporalTimeZoneLike).
  Handle<JSReceiver> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone,
      temporal::ToTemporalTimeZone(isolate, temporal_time_zone_like,
                                   method_name));
  // 10. Let temporalDateTime be ?
  // CreateTemporalDateTime(temporalDate.[[ISOYear]], temporalDate.[[ISOMonth]],
  // temporalDate.[[ISODay]], temporalTime.[[ISOHour]],
  // temporalTime.[[ISOMinute]], temporalTime.[[ISOSecond]],
  // temporalTime.[[ISOMillisecond]], temporalTime.[[ISOMicrosecond]],
  // temporalTime.[[ISONanosecond]], temporalDate.[[Calendar]]).
  DirectHandle<JSReceiver> calendar(temporal_date->calendar(), isolate);
  Handle<JSTemporalPlainDateTime> temporal_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, temporal_date_time,
      temporal::CreateTemporalDateTime(
          isolate,
          {{temporal_date->iso_year(), temporal_date->iso_month(),
            temporal_date->iso_day()},
           {temporal_time->iso_hour(), temporal_time->iso_minute(),
            temporal_time->iso_second(), temporal_time->iso_millisecond(),
            temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()}},
          calendar));
  // 11. Let instant be ? BuiltinTimeZoneGetInstantFor(timeZone,
  // temporalDateTime, "compatible").
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, instant,
      BuiltinTimeZoneGetInstantFor(isolate, time_zone, temporal_date_time,
                                   Disambiguation::kCompatible, method_name));
  // 12. Return ? CreateTemporalZonedDateTime(instant.[[Nanoseconds]], timeZone,
  // temporalDate.[[Calendar]]).
  return CreateTemporalZonedDateTime(
      isolate, handle(instant->nanoseconds(), isolate), time_zone, calendar);
}

namespace {
// #sec-temporal-comparetemporaltime
int32_t CompareTemporalTime(const TimeRecord& time1, const TimeRecord& time2) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: h1, min1, s1, ms1, mus1, ns1, h2, min2, s2, ms2, mus2, and ns2
  // are integers.
  // 2. If h1 > h2, return 1.
  if (time1.hour > time2.hour) return 1;
  // 3. If h1 < h2, return -1.
  if (time1.hour < time2.hour) return -1;
  // 4. If min1 > min2, return 1.
  if (time1.minute > time2.minute) return 1;
  // 5. If min1 < min2, return -1.
  if (time1.minute < time2.minute) return -1;
  // 6. If s1 > s2, return 1.
  if (time1.second > time2.second) return 1;
  // 7. If s1 < s2, return -1.
  if (time1.second < time2.second) return -1;
  // 8. If ms1 > ms2, return 1.
  if (time1.millisecond > time2.millisecond) return 1;
  // 9. If ms1 < ms2, return -1.
  if (time1.millisecond < time2.millisecond) return -1;
  // 10. If mus1 > mus2, return 1.
  if (time1.microsecond > time2.microsecond) return 1;
  // 11. If mus1 < mus2, return -1.
  if (time1.microsecond < time2.microsecond) return -1;
  // 12. If ns1 > ns2, return 1.
  if (time1.nanosecond > time2.nanosecond) return 1;
  // 13. If ns1 < ns2, return -1.
  if (time1.nanosecond < time2.nanosecond) return -1;
  // 14. Return 0.
  return 0;
}
}  // namespace

// #sec-temporal.plaintime.compare
MaybeHandle<Smi> JSTemporalPlainTime::Compare(Isolate* isolate,
                                              Handle<Object> one_obj,
                                              Handle<Object> two_obj) {
  const char* method_name = "Temporal.PainTime.compare";
  // 1. Set one to ? ToTemporalTime(one).
  Handle<JSTemporalPlainTime> one;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, one, temporal::ToTemporalTime(isolate, one_obj, method_name));
  // 2. Set two to ? ToTemporalTime(two).
  Handle<JSTemporalPlainTime> two;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, two, temporal::ToTemporalTime(isolate, two_obj, method_name));
  // 3. Return 𝔽(! CompareTemporalTime(one.[[ISOHour]], one.[[ISOMinute]],
  // one.[[ISOSecond]], one.[[ISOMillisecond]], one.[[ISOMicrosecond]],
  // one.[[ISONanosecond]], two.[[ISOHour]], two.[[ISOMinute]],
  // two.[[ISOSecond]], two.[[ISOMillisecond]], two.[[ISOMicrosecond]],
  // two.[[ISONanosecond]])).
  return handle(Smi::FromInt(CompareTemporalTime(
                    {one->iso_hour(), one->iso_minute(), one->iso_second(),
                     one->iso_millisecond(), one->iso_microsecond(),
                     one->iso_nanosecond()},
                    {two->iso_hour(), two->iso_minute(), two->iso_second(),
                     two->iso_millisecond(), two->iso_microsecond(),
                     two->iso_nanosecond()})),
                isolate);
}

// #sec-temporal.plaintime.prototype.equals
MaybeHandle<Oddball> JSTemporalPlainTime::Equals(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> other_obj) {
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalTime,
  // [[InitializedTemporalTime]]).
  // 3. Set other to ? ToTemporalTime(other).
  Handle<JSTemporalPlainTime> other;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, other,
      temporal::ToTemporalTime(isolate, other_obj,
                               "Temporal.PlainTime.prototype.equals"));
  // 4. If temporalTime.[[ISOHour]] ≠ other.[[ISOHour]], return false.
  if (temporal_time->iso_hour() != other->iso_hour())
    return isolate->factory()->false_value();
  // 5. If temporalTime.[[ISOMinute]] ≠ other.[[ISOMinute]], return false.
  if (temporal_time->iso_minute() != other->iso_minute())
    return isolate->factory()->false_value();
  // 6. If temporalTime.[[ISOSecond]] ≠ other.[[ISOSecond]], return false.
  if (temporal_time->iso_second() != other->iso_second())
    return isolate->factory()->false_value();
  // 7. If temporalTime.[[ISOMillisecond]] ≠ other.[[ISOMillisecond]], return
  // false.
  if (temporal_time->iso_millisecond() != other->iso_millisecond())
    return isolate->factory()->false_value();
  // 8. If temporalTime.[[ISOMicrosecond]] ≠ other.[[ISOMicrosecond]], return
  // false.
  if (temporal_time->iso_microsecond() != other->iso_microsecond())
    return isolate->factory()->false_value();
  // 9. If temporalTime.[[ISONanosecond]] ≠ other.[[ISONanosecond]], return
  // false.
  if (temporal_time->iso_nanosecond() != other->iso_nanosecond())
    return isolate->factory()->false_value();
  // 10. Return true.
  return isolate->factory()->true_value();
}

namespace {

// #sec-temporal-maximumtemporaldurationroundingincrement
Maximum MaximumTemporalDurationRoundingIncrement(Unit unit) {
  switch (unit) {
    // 1. If unit is "year", "month", "week", or "day", then
    case Unit::kYear:
    case Unit::kMonth:
    case Unit::kWeek:
    case Unit::kDay:
      // a. Return undefined.
      return {false, 0};
    // 2. If unit is "hour", then
    case Unit::kHour:
      // a. Return 24.
      return {true, 24};
    // 3. If unit is "minute" or "second", then
    case Unit::kMinute:
    case Unit::kSecond:
      // a. Return 60.
      return {true, 60};
    // 4. Assert: unit is one of "millisecond", "microsecond", or "nanosecond".
    case Unit::kMillisecond:
    case Unit::kMicrosecond:
    case Unit::kNanosecond:
      // 5. Return 1000.
      return {true, 1000};
    default:
      UNREACHABLE();
  }
}

}  // namespace

// #sec-temporal.plaintime.prototype.round
MaybeHandle<JSTemporalPlainTime> JSTemporalPlainTime::Round(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> round_to_obj) {
  const char* method_name = "Temporal.PlainTime.prototype.round";
  Factory* factory = isolate->factory();
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalTime,
  // [[InitializedTemporalTime]]).
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
    // 5. Set roundTo to ? GetOptionsObject(roundTo).
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
      Handle<JSTemporalPlainTime>());

  // 7. Let roundingMode be ? ToTemporalRoundingMode(roundTo, "halfExpand").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, round_to, RoundingMode::kHalfExpand,
                             method_name),
      Handle<JSTemporalPlainTime>());

  // 8. Let maximum be ! MaximumTemporalDurationRoundingIncrement(smallestUnit).
  Maximum maximum = MaximumTemporalDurationRoundingIncrement(smallest_unit);

  // 9. Let roundingIncrement be ? ToTemporalRoundingIncrement(roundTo,
  // maximum, false).
  double rounding_increment;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_increment,
      ToTemporalRoundingIncrement(isolate, round_to, maximum.value,
                                  maximum.defined, false),
      Handle<JSTemporalPlainTime>());

  // 12. Let result be ! RoundTime(temporalTime.[[ISOHour]],
  // temporalTime.[[ISOMinute]], temporalTime.[[ISOSecond]],
  // temporalTime.[[ISOMillisecond]], temporalTime.[[ISOMicrosecond]],
  // temporalTime.[[ISONanosecond]], roundingIncrement, smallestUnit,
  // roundingMode).
  DateTimeRecord result = RoundTime(
      isolate,
      {temporal_time->iso_hour(), temporal_time->iso_minute(),
       temporal_time->iso_second(), temporal_time->iso_millisecond(),
       temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()},
      rounding_increment, smallest_unit, rounding_mode);
  // 13. Return ? CreateTemporalTime(result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]]).
  return CreateTemporalTime(isolate, result.time);
}

// #sec-temporal.plaintime.prototype.with
MaybeHandle<JSTemporalPlainTime> JSTemporalPlainTime::With(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Handle<Object> temporal_time_like_obj, Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainTime.prototype.with";
  // 1. Let temporalTime be the this value.
  // 2. Perform ? RequireInternalSlot(temporalTime,
  // [[InitializedTemporalTime]]).
  // 3. If Type(temporalTimeLike) is not Object, then
  if (!IsJSReceiver(*temporal_time_like_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  Handle<JSReceiver> temporal_time_like =
      Cast<JSReceiver>(temporal_time_like_obj);
  // 4. Perform ? RejectObjectWithCalendarOrTimeZone(temporalTimeLike).
  MAYBE_RETURN(RejectObjectWithCalendarOrTimeZone(isolate, temporal_time_like),
               Handle<JSTemporalPlainTime>());
  // 5. Let partialTime be ? ToPartialTime(temporalTimeLike).
  TimeRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result,
      ToPartialTime(
          isolate, temporal_time_like,
          {temporal_time->iso_hour(), temporal_time->iso_minute(),
           temporal_time->iso_second(), temporal_time->iso_millisecond(),
           temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()},
          method_name),
      Handle<JSTemporalPlainTime>());

  // 6. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 7. Let overflow be ? ToTemporalOverflow(options).
  ShowOverflow overflow;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, overflow, ToTemporalOverflow(isolate, options, method_name),
      Handle<JSTemporalPlainTime>());

  // 20. Let result be ? RegulateTime(hour, minute, second, millisecond,
  // microsecond, nanosecond, overflow).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, temporal::RegulateTime(isolate, result, overflow),
      Handle<JSTemporalPlainTime>());
  // 25. Return ? CreateTemporalTime(result.[[Hour]], result.[[Minute]],
  // result.[[Second]], result.[[Millisecond]], result.[[Microsecond]],
  // result.[[Nanosecond]]).
  return CreateTemporalTime(isolate, result);
}

// #sec-temporal.now.plaintimeiso
MaybeHandle<JSTemporalPlainTime> JSTemporalPlainTime::NowISO(
    Isolate* isolate, Handle<Object> temporal_time_zone_like) {
  const char* method_name = "Temporal.Now.plainTimeISO";
  // 1. Let calendar be ! GetISO8601Calendar().
  Handle<JSReceiver> calendar = temporal::GetISO8601Calendar(isolate);
  // 2. Let dateTime be ? SystemDateTime(temporalTimeZoneLike, calendar).
  Handle<JSTemporalPlainDateTime> date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time,
      SystemDateTime(isolate, temporal_time_zone_like, calendar, method_name));
  // 3. Return ! CreateTemporalTime(dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]]).
  return CreateTemporalTime(
             isolate,
             {date_time->iso_hour(), date_time->iso_minute(),
              date_time->iso_second(), date_time->iso_millisecond(),
              date_time->iso_microsecond(), date_time->iso_nanosecond()})
      .ToHandleChecked();
}

// #sec-temporal.plaintime.from
MaybeHandle<JSTemporalPlainTime> JSTemporalPlainTime::From(
    Isolate* isolate, Handle<Object> item_obj, Handle<Object> options_obj) {
  const char* method_name = "Temporal.PlainTime.from";
  // 1. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 2. Let overflow be ? ToTemporalOverflow(options).
  ShowOverflow overflow;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, overflow, ToTemporalOverflow(isolate, options, method_name),
      Handle<JSTemporalPlainTime>());
  // 3. If Type(item) is Object and item has an [[InitializedTemporalTime]]
  // internal slot, then
  if (IsJSTemporalPlainTime(*item_obj)) {
    // a. Return ? CreateTemporalTime(item.[[ISOHour]], item.[[ISOMinute]],
    // item.[[ISOSecond]], item.[[ISOMillisecond]], item.[[ISOMicrosecond]],
    // item.[[ISONanosecond]]).
    auto item = Cas
"""


```