Response:
Let's break down the thought process for analyzing this V8 source code snippet.

**1. Initial Understanding & Context:**

* **File Path:** `v8/src/objects/js-temporal-objects.cc` tells us this is C++ code within the V8 engine specifically dealing with JavaScript's Temporal API objects. The `.cc` extension confirms it's C++.
* **"Part 16 of 25":** This suggests we're looking at a specific section of a larger file, likely focusing on related functionality. It's important not to assume it's the *entire* implementation of these objects.
* **Keywords:** The presence of `JSTemporalTimeZone`, `JSTemporalPlainDate`, `CompareISODate`, `CalendarEquals`, `CreateTemporalDate`, etc., immediately points towards the implementation of the JavaScript `Temporal` API's `TimeZone` and `PlainDate` objects and related operations.

**2. Scanning for Key Functions and Structures:**

* I'll start by identifying the main classes and functions defined in this snippet. This helps create a high-level overview. I see:
    * `JSTemporalTimeZone` and its methods (`ToString`, `id`, `offset_nanoseconds`, etc.)
    * `JSTemporalPlainDate` and its static (`Constructor`, `Compare`, `Now`, `From`, `NowISO`) and instance (`Equals`, `WithCalendar`, `ToPlainYearMonth`, `ToPlainMonthDay`, `ToPlainDateTime`, `With`, `ToZonedDateTime`, `Add`, `Subtract`, `Until`, `Since`) methods.
    * Several helper functions within the anonymous namespace like `RejectObjectWithCalendarOrTimeZone`, `CalendarMergeFields`, and `PlainDateOrYearMonthOrMonthDayWith`.

**3. Analyzing Functionality of Each Class/Function Group:**

* **`JSTemporalTimeZone`:**  Seems to handle time zone representation. The `is_offset()` check suggests it can represent both named time zones (like "UTC") and offset time zones (like "+05:00"). The `#ifdef V8_INTL_SUPPORT` indicates Internationalization API interaction for named time zones.
* **`JSTemporalPlainDate`:** This is the core of this snippet. It provides functionalities for:
    * **Construction:** `Constructor`, `CreateTemporalDate` (likely a helper).
    * **Comparison:** `Compare`, `CompareISODate`, `Equals`.
    * **Modification:** `WithCalendar`, `With`.
    * **Conversion:** `ToPlainYearMonth`, `ToPlainMonthDay`, `ToPlainDateTime`, `ToZonedDateTime`.
    * **Arithmetic:** `Add`, `Subtract`, `Until`, `Since`.
    * **Static methods:** `Now` (with calendar), `NowISO` (ISO calendar), `From` (parsing).

**4. Identifying Relationships and Patterns:**

* **`ToTemporal...` functions:**  These are clearly used for type coercion (e.g., `ToTemporalDate`, `ToTemporalTimeZone`). They are likely crucial for ensuring input arguments are of the correct Temporal type.
* **`Calendar...` functions:**  Functions like `CalendarEquals`, `CalendarFields`, `CalendarDateAdd`, `CalendarDateUntil` suggest interaction with a separate "Calendar" abstraction, allowing for different calendar systems (not just Gregorian).
* **Helper functions in anonymous namespace:**  These encapsulate reusable logic, making the main methods cleaner. For example, `RejectObjectWithCalendarOrTimeZone` enforces constraints on input objects. `PlainDateOrYearMonthOrMonthDayWith` shows a template pattern for the `with` methods.

**5. Considering JavaScript Interaction and Examples:**

* The names of the methods strongly correlate with the methods available on `Temporal.PlainDate` and `Temporal.TimeZone` in JavaScript.
* I can now start constructing JavaScript examples that would trigger these C++ functions. For instance:
    * `new Temporal.PlainDate(2023, 10, 26)` would call the `Constructor`.
    * `date1.equals(date2)` would call the `Equals` method.
    * `Temporal.PlainDate.compare(date1, date2)` would call the static `Compare` method.

**6. Code Logic and Assumptions:**

* The `TO_INT_THROW_ON_INFTY` macro is a common V8 pattern for converting JavaScript numbers to C++ integers with error handling.
* The `CompareISODate` function likely performs a simple lexicographical comparison of year, month, and day.
* The `Calendar` abstraction is key to handling different calendar systems. The code interacts with it to perform calendar-specific operations.

**7. Common Programming Errors:**

* **Type errors:** Passing non-Temporal objects to methods expecting them.
* **Invalid date components:**  Providing out-of-range year, month, or day values in the constructor.
* **Mixing calendars:** Attempting to compare or perform arithmetic between dates with different calendars without proper conversion.
* **Incorrect `with` usage:**  Trying to set properties that are not valid for the given calendar or object type.

**8. Torque Consideration (if the file ended in `.tq`):**

* Since the file ends in `.cc`, it's C++. If it were `.tq`, I'd know it's Torque, a V8-specific language for generating optimized C++ code. The analysis would shift to understanding the Torque syntax and how it maps to the eventual C++ implementation.

**9. Synthesizing the Summary:**

* Finally, I'll organize my findings into a concise summary covering the key functionalities, JavaScript relevance, potential errors, and the overall purpose of this code snippet within the broader V8 and Temporal API context. The "Part 16 of 25" reinforces that this is a component of a larger system.

This detailed thought process involves: understanding the context, identifying key components, analyzing their functions, finding relationships, connecting to JavaScript, considering potential errors, and synthesizing the information into a clear summary. It's an iterative process, and I might jump back and forth between these steps as I discover more about the code.
好的，让我们来分析一下 `v8/src/objects/js-temporal-objects.cc` 这个 V8 源代码文件的功能。

**核心功能归纳：**

这个 C++ 文件主要负责实现 JavaScript `Temporal` API 中的 `Temporal.TimeZone` 和 `Temporal.PlainDate` 对象及其相关操作。它定义了这些对象的内部结构、构造过程以及各种原型方法（如比较、转换、算术运算等）。

**详细功能点：**

**1. `JSTemporalTimeZone` 类的实现：**

* **表示时区：**  `JSTemporalTimeZone` 类用于表示时区，既可以表示 UTC 偏移量（例如 "+08:00"），也可以表示 IANA 时区名称（例如 "America/Los_Angeles"）。
* **`ToString()` 和 `id()` 方法：**  用于获取时区的字符串表示形式。对于偏移量时区，会格式化成 "+/-HH:MM" 的形式。对于命名时区，会尝试从 ICU 库（如果 V8 编译时启用了国际化支持）获取 ID。
* **`offset_nanoseconds()` 和 `set_offset_nanoseconds()` 方法：** 用于获取和设置偏移量时区的纳秒偏移量。
* **`time_zone_index()` 方法：**  用于获取命名时区的索引。

**2. `JSTemporalPlainDate` 类的实现：**

* **表示日期：** `JSTemporalPlainDate` 类用于表示一个没有时区的日期，包含年、月、日和日历信息。
* **`Constructor()` 方法：**  作为 `Temporal.PlainDate` 构造函数的 C++ 实现，负责创建 `JSTemporalPlainDate` 对象。它会进行参数校验，并将传入的年、月、日转换为整数，并获取日历对象。
* **`Compare()` 方法：**  静态方法，用于比较两个 `Temporal.PlainDate` 对象的大小。它会先将传入的参数转换为 `Temporal.PlainDate` 对象，然后比较它们的年、月、日。
* **`Equals()` 方法：**  用于判断当前 `Temporal.PlainDate` 对象是否与另一个对象相等。它会比较年、月、日以及日历是否相同。
* **`WithCalendar()` 方法：**  创建一个新的 `Temporal.PlainDate` 对象，其日期与原对象相同，但日历被替换为新的日历。
* **`ToPlainYearMonth()` 和 `ToPlainMonthDay()` 方法：**  将 `Temporal.PlainDate` 对象转换为 `Temporal.PlainYearMonth` 和 `Temporal.PlainMonthDay` 对象。
* **`ToPlainDateTime()` 方法：**  将 `Temporal.PlainDate` 对象转换为 `Temporal.PlainDateTime` 对象，可以指定时间部分，默认为午夜。
* **`With()` 方法：**  创建一个新的 `Temporal.PlainDate` 对象，其部分属性（如年、月、日）被传入的对象覆盖。
* **`ToZonedDateTime()` 方法：**  将 `Temporal.PlainDate` 对象转换为 `Temporal.ZonedDateTime` 对象，需要提供时区信息。
* **`Add()` 和 `Subtract()` 方法：**  对 `Temporal.PlainDate` 对象进行加减操作，可以传入 `Temporal.Duration` 对象。这些操作会委托给日历对象的 `CalendarDateAdd` 方法。
* **`Until()` 和 `Since()` 方法：**  计算两个 `Temporal.PlainDate` 对象之间的时间差，返回一个 `Temporal.Duration` 对象。这些操作会委托给日历对象的 `CalendarDateUntil` 方法。
* **`Now()` 和 `NowISO()` 方法：**  静态方法，用于获取当前日期。`Now()` 方法使用指定的时区和日历，`NowISO()` 方法使用 ISO 8601 日历。
* **`From()` 方法：**  静态方法，用于从各种类型的输入（如对象、字符串）创建 `Temporal.PlainDate` 对象。

**3. 辅助函数：**

* **`RejectObjectWithCalendarOrTimeZone()`：**  检查一个对象是否不应该包含 `calendar` 或 `timeZone` 属性，用于确保某些操作的参数类型正确。
* **`CalendarMergeFields()`：**  用于合并来自不同来源的日期字段，如果日历对象提供了 `mergeFields` 方法则调用，否则使用默认的合并逻辑。
* **`PlainDateOrYearMonthOrMonthDayWith()`：**  一个模板函数，用于实现 `with` 方法的通用逻辑。
* **`DifferenceTemporalPlainDate()`：**  一个辅助函数，用于实现 `Until` 和 `Since` 方法的通用逻辑。

**如果 `v8/src/objects/js-temporal-objects.cc` 以 `.tq` 结尾：**

如果文件名是 `js-temporal-objects.tq`，那么它将是使用 **Torque** 编写的。Torque 是 V8 内部使用的一种领域特定语言，用于生成高效的 C++ 代码。Torque 代码更抽象，更易于阅读和维护，并且可以进行类型检查和生成优化的代码。

**与 JavaScript 功能的关系及示例：**

这个 C++ 文件中的代码直接对应于 JavaScript `Temporal` API 中 `Temporal.TimeZone` 和 `Temporal.PlainDate` 对象的行为。

```javascript
// Temporal.TimeZone 的使用
const utc = new Temporal.TimeZone('UTC');
const losAngeles = new Temporal.TimeZone('America/Los_Angeles');
const offset = new Temporal.TimeZone('+05:30');

console.log(utc.toString()); // "UTC"
console.log(losAngeles.id);   // "America/Los_Angeles"
console.log(offset.id);      // "+05:30"

// Temporal.PlainDate 的使用
const today = Temporal.PlainDate.today();
const specificDate = new Temporal.PlainDate(2023, 10, 26);
const anotherDate = Temporal.PlainDate.from('2023-10-27');

console.log(today.toString());
console.log(specificDate.year); // 2023
console.log(specificDate.month); // 10
console.log(specificDate.day);   // 26

console.log(specificDate.equals(anotherDate)); // false
console.log(Temporal.PlainDate.compare(specificDate, anotherDate)); // -1

const nextMonth = specificDate.with({ month: 11 });
console.log(nextMonth.toString()); // "2023-11-26"

const later = specificDate.add({ days: 5 });
console.log(later.toString()); // "2023-10-31"

const diff = specificDate.until(later);
console.log(diff.days); // 5
```

**代码逻辑推理（假设输入与输出）：**

假设我们有以下 JavaScript 代码：

```javascript
const date1 = new Temporal.PlainDate(2023, 10, 26);
const date2 = new Temporal.PlainDate(2023, 10, 27);

console.log(Temporal.PlainDate.compare(date1, date2));
```

* **输入：** `date1` 对应的 `JSTemporalPlainDate` 对象，其 `iso_year` 为 2023，`iso_month` 为 10，`iso_day` 为 26。`date2` 对应的 `JSTemporalPlainDate` 对象，其 `iso_year` 为 2023，`iso_month` 为 10，`iso_day` 为 27。
* **执行的 C++ 代码：** `JSTemporalPlainDate::Compare()` 方法会被调用。
* **C++ 代码逻辑：**
    1. `ToTemporalDate()` 会将 JavaScript 对象转换为 `JSTemporalPlainDate` 对象。
    2. `CompareISODate()` 函数会被调用，比较 `date1` 和 `date2` 的年、月、日。
    3. 由于 `date1` 的日 (26) 小于 `date2` 的日 (27)，`CompareISODate()` 返回 -1。
* **输出：** JavaScript 代码的 `console.log()` 将输出 `-1`。

**用户常见的编程错误：**

* **类型错误：**  向期望 `Temporal.PlainDate` 对象的方法传递了其他类型的对象。
  ```javascript
  const date = new Temporal.PlainDate(2023, 10, 26);
  try {
    date.equals("not a date"); // 错误：参数类型不匹配
  } catch (e) {
    console.error(e); // TypeError
  }
  ```
* **无效的日期组成部分：**  在创建 `Temporal.PlainDate` 对象时提供了无效的年、月、日。
  ```javascript
  try {
    const invalidDate = new Temporal.PlainDate(2023, 2, 30); // 错误：2023年2月没有30号
  } catch (e) {
    console.error(e); // RangeError
  }
  ```
* **混淆时区：**  在不需要时区的操作中使用了带时区的对象，或者在需要时区的操作中忘记提供时区信息。
* **不理解日历的概念：**  `Temporal.PlainDate` 关联着一个日历，如果与期望的日历不符，可能会导致意外的结果。

**归纳 `v8/src/objects/js-temporal-objects.cc` 的功能（第 16 部分，共 25 部分）：**

作为 `Temporal` API 实现的一部分，`v8/src/objects/js-temporal-objects.cc` 这个文件专门负责实现 `Temporal.TimeZone` 和 `Temporal.PlainDate` 这两个核心的日期和时间概念。它定义了这些对象在 V8 引擎中的内部表示和行为，包括创建、比较、转换以及基本的算术运算。作为 25 个部分中的第 16 部分，它很可能专注于 `Temporal` API 中与日期和时区处理相关的核心功能。其他部分可能涉及其他 `Temporal` 对象（如 `Temporal.DateTime`, `Temporal.Instant`, `Temporal.Duration` 等）的实现。

总而言之，这个文件是 V8 引擎中实现 JavaScript `Temporal` API 的关键组成部分，它将 JavaScript 中对日期和时区的抽象操作转化为高效的 C++ 代码实现。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第16部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
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