Response:
The user wants a summary of the provided C++ code, which is part of the V8 JavaScript engine. The code seems to implement the functionality for `Temporal.PlainDate` and `Temporal.PlainDateTime` objects in JavaScript.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core functionality:** The code heavily mentions `JSTemporalPlainDate` and `JSTemporalPlainDateTime`. These are clearly the central objects this file deals with. The "Temporal" prefix suggests this is related to the Temporal API for date and time manipulation in JavaScript.

2. **Analyze function names and arguments:**  Look for patterns in function names. Functions like `CreateTemporalDate`, `ToTemporalDate`, `GetISOFields`, `ToString`, `From`, `Compare`, `Equals`, `With`, `WithPlainTime`, `WithCalendar`, `ToPlainYearMonth`, `ToPlainMonthDay`, `ToZonedDateTime` strongly suggest the kinds of operations that can be performed on these Temporal objects. The arguments often involve `Isolate*`, which is standard in V8 C++ code, and `Handle<...>`, which represents managed pointers to V8 objects. Arguments like `options_obj` or `calendar_like` hint at configuration or related objects.

3. **Scan for keywords and concepts:**  Words like "ISO", "calendar", "overflow", "fields", "string", "JSON", "toLocaleString", and "compare" are significant. They point to specific aspects of date/time handling, such as ISO 8601 formatting, calendar systems, handling out-of-range values, accessing internal data, string representations, JSON serialization, localization, and comparison operations.

4. **Check for conditional compilation:** The `#ifdef V8_INTL_SUPPORT` block indicates that internationalization features are handled differently depending on the build configuration.

5. **Pay attention to helper functions and namespaces:** The code defines helper functions within an anonymous namespace and uses functions like `GetOptionsObject`, `ToTemporalOverflow`, `TemporalDateToString`, `CreateTemporalDateTime`, `ParseTemporalDateTimeString`, `CalendarFields`, `CalendarMergeFields`, `BuiltinTimeZoneGetInstantFor`, etc. These are building blocks for the main functionality.

6. **Infer from the structure and logic:** The code follows a pattern of input validation, conversion (e.g., `ToTemporalDate`), internal slot access, and object creation or manipulation. The presence of "MaybeHandle" suggests that operations can fail and return exceptions.

7. **Address the specific instructions:**
    * **Functionality Listing:**  Based on the analysis, list the key operations supported.
    * **Torque:**  Note that the file extension is `.cc`, so it's C++, not Torque.
    * **JavaScript Examples:**  For functions with clear JavaScript counterparts (like `from`, `equals`, `with`, `toString`), provide simple JavaScript examples.
    * **Code Logic Reasoning:** Select a representative function (like `ToTemporalDate`) and illustrate the input/output based on the logic (checking for existing Temporal objects, converting from other types).
    * **Common Programming Errors:** Think about typical mistakes when working with date/time, such as invalid date formats or incorrect option usage.
    * **Part of a larger system:** Acknowledge that this is one component of a larger Temporal implementation.

8. **Refine and organize:** Structure the summary logically, starting with the main purpose and then detailing specific aspects. Use clear and concise language. Emphasize the connection to the JavaScript Temporal API.

Self-Correction/Refinement during the process:

* **Initial thought:** Maybe this file just creates the objects. **Correction:** The presence of methods like `Compare`, `With`, and `ToString` indicates more complex logic beyond just object creation.
* **Misinterpretation:**  Initially, I might not have fully grasped the role of "options". **Correction:** Realizing that many functions take an `options` argument highlights the configurability of the Temporal API.
* **Overlooking details:** I might have missed the internationalization aspect. **Correction:**  The `#ifdef` block is a key detail and should be included.
* **Ambiguity:**  The initial summary might be too vague. **Correction:**  Providing JavaScript examples and specific function explanations makes the summary more concrete.

By following these steps, the generated summary accurately captures the functionality of the `js-temporal-objects.cc` file and addresses all the user's requirements.
这是一个 V8 引擎的源代码文件，主要负责实现 JavaScript 中 `Temporal.PlainDate` 和 `Temporal.PlainDateTime` 对象的底层功能。 这是 Temporal API 的一部分，旨在提供现代化的日期和时间处理能力。

**主要功能归纳:**

这个文件实现了 `Temporal.PlainDate` 和 `Temporal.PlainDateTime` 对象的创建、转换、比较以及各种操作方法。 具体来说，它包含了以下功能：

* **对象创建:**  定义了如何从不同的输入（例如，年、月、日，或者一个包含日期信息的对象）创建 `Temporal.PlainDate` 和 `Temporal.PlainDateTime` 对象。
* **类型转换:** 提供了将其他类型的值转换为 `Temporal.PlainDate` 和 `Temporal.PlainDateTime` 对象的方法，例如从一个包含日期信息的普通 JavaScript 对象或一个 ISO 格式的字符串。
* **属性访问:**  实现了获取 `Temporal.PlainDate` 和 `Temporal.PlainDateTime` 对象的 ISO 日期字段 (年、月、日) 的方法。
* **字符串表示:**  定义了将 `Temporal.PlainDate` 和 `Temporal.PlainDateTime` 对象转换为字符串的方法，包括默认格式和根据选项自定义格式（例如，是否显示日历信息）。同时也支持 `toJSON` 方法。
* **比较操作:**  实现了比较两个 `Temporal.PlainDate` 或 `Temporal.PlainDateTime` 对象的方法，用于判断它们的先后顺序。
* **相等性判断:**  提供了判断两个 `Temporal.PlainDate` 或 `Temporal.PlainDateTime` 对象是否相等的方法，包括比较日期和日历。
* **修改操作:** 实现了创建新的 `Temporal.PlainDate` 或 `Temporal.PlainDateTime` 对象，其部分属性被修改（例如，修改年份，或者只修改时间部分）。
* **与其他 Temporal 类型的转换:** 提供了将 `Temporal.PlainDateTime` 对象转换为 `Temporal.PlainYearMonth`, `Temporal.PlainMonthDay`, 和 `Temporal.ZonedDateTime` 对象的方法。
* **日历处理:** 涉及到与日历对象 (`Temporal.Calendar`) 的交互，包括获取日期字段、合并字段等。
* **本地化:** 提供了 `toLocaleString` 方法，用于根据本地化设置格式化日期和时间（需要 V8 的国际化支持）。

**关于 .tq 扩展名:**

`v8/src/objects/js-temporal-objects.cc` **不是**以 `.tq` 结尾，所以它是一个 **C++** 源代码文件，而不是 Torque 源代码文件。 Torque 是一种 V8 特有的领域特定语言，用于生成高效的 JavaScript 内置函数的 C++ 代码。  虽然这个文件是 C++，但它可能包含手动编写的或者由其他工具生成的 C++ 代码来实现 Temporal API 的功能。

**与 JavaScript 功能的关系及示例:**

这个 C++ 文件中的代码直接支撑着 JavaScript 中 `Temporal.PlainDate` 和 `Temporal.PlainDateTime` 对象的行为。  下面是一些 JavaScript 示例，展示了与这个 C++ 文件中功能相关的操作：

```javascript
// 创建 Temporal.PlainDate 对象
const date1 = new Temporal.PlainDate(2023, 10, 26);
const date2 = Temporal.PlainDate.from({ year: 2023, month: 10, day: 27 });
const date3 = Temporal.PlainDate.from('2023-10-28');

// 创建 Temporal.PlainDateTime 对象
const dateTime1 = new Temporal.PlainDateTime(2023, 10, 26, 10, 30, 0);
const dateTime2 = Temporal.PlainDateTime.from({ year: 2023, month: 10, day: 26, hour: 11, minute: 15 });
const dateTime3 = Temporal.PlainDateTime.from('2023-10-26T12:00:00');

// 获取 ISO 字段
console.log(date1.year); // 2023
console.log(date1.month); // 10
console.log(date1.day); // 26

// 转换为字符串
console.log(date1.toString()); // "2023-10-26"
console.log(dateTime1.toString()); // "2023-10-26T10:30:00"

// 比较
console.log(Temporal.PlainDate.compare(date1, date2)); // -1 (date1 在 date2 之前)

// 相等性判断
console.log(date1.equals(date2)); // false

// 修改日期
const newDate = date1.with({ day: 27 });
console.log(newDate.toString()); // "2023-10-27"

// 修改日期时间
const newDateTime = dateTime1.with({ hour: 11 });
console.log(newDateTime.toString()); // "2023-10-26T11:30:00"

// 转换为其他 Temporal 类型
const yearMonth = dateTime1.toPlainYearMonth();
console.log(yearMonth.toString()); // "2023-10"

// 使用 toLocaleString 进行本地化格式化
// (需要浏览器或 Node.js 支持 Intl)
// console.log(date1.toLocaleString());
```

**代码逻辑推理 (以 `ToTemporalDate` 函数为例):**

**假设输入:**

* `item_obj`:  一个 JavaScript 对象，例如 `{ year: 2024, month: 1, day: 15 }`
* `options`:  一个 JavaScript 对象，例如 `{ overflow: 'reject' }`
* `method_name`:  字符串 "Temporal.PlainDate.from"

**预期输出:**

一个 `Handle<JSTemporalPlainDate>`，表示 2024 年 1 月 15 日的 `Temporal.PlainDate` 对象。

**代码逻辑:**

1. `ToTemporalDate` 函数首先检查 `item_obj` 的类型。
2. 如果 `item_obj` 是一个 `JSTemporalPlainDate` 对象，并且提供了 `options`，则会根据 `options` 中的 `overflow` 属性进行溢出处理，并返回一个新的 `JSTemporalPlainDate` 对象（可能是原始对象的克隆）。
3. 如果 `item_obj` 不是 `JSTemporalPlainDate` 对象，则会尝试将其转换为 `Temporal.PlainDate`。这可能涉及到调用 `GetTemporalCalendarWithISODefault` 来获取日历信息，以及 `PrepareTemporalFields` 来提取日期字段。
4. 最后，使用提取到的日期字段和日历信息调用 `CreateTemporalDate` 来创建一个新的 `JSTemporalPlainDate` 对象。

**用户常见的编程错误:**

* **传递无效的日期格式字符串:** 例如，传递一个不符合 ISO 8601 格式的字符串给 `Temporal.PlainDate.from()` 或 `Temporal.PlainDateTime.from()`。

  ```javascript
  // 错误：日期格式不正确
  // const invalidDate = Temporal.PlainDate.from('2023/10/27');
  ```

* **提供的对象缺少必要的日期字段:** 当使用对象字面量创建 `Temporal.PlainDate` 或 `Temporal.PlainDateTime` 时，缺少 `year`、`month` 或 `day` 等必要的属性会导致错误。

  ```javascript
  // 错误：缺少 day 属性
  // const incompleteDate = Temporal.PlainDate.from({ year: 2023, month: 10 });
  ```

* **溢出错误:**  当提供的日期值超出范围，并且 `overflow` 选项设置为 `'reject'` 时，会抛出错误。

  ```javascript
  // 错误：月份超出范围，且 overflow 为 'reject' (默认值)
  // const invalidDate = Temporal.PlainDate.from({ year: 2023, month: 13, day: 1 });
  ```

* **混淆使用不同的 Temporal 类型:** 尝试将 `Temporal.PlainTime` 对象传递给期望 `Temporal.PlainDate` 或 `Temporal.PlainDateTime` 的函数。

**作为第 17 部分 (共 25 部分) 的功能归纳:**

作为 Temporal API 实现的一部分，这个文件专注于 `Temporal.PlainDate` 和 `Temporal.PlainDateTime` 对象的 **核心表示和基本操作**。它提供了创建、转换、比较和基本修改这些日期和日期时间对象的基础设施。  后续的部分可能会涉及更复杂的操作，例如时区处理、持续时间计算、以及与 `Temporal.Instant` 等其他 Temporal 类型的交互。  这个文件是构建完整 Temporal API 功能的重要组成部分。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第17部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  // 7. Throw a RangeError ex
```