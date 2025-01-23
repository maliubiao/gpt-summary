Response:
Let's break down the thought process for analyzing this V8 source code snippet.

1. **Identify the Core File and its Purpose:** The prompt clearly states the file is `v8/src/objects/js-temporal-objects.cc`. The "objects" part strongly suggests this code deals with the internal representation and manipulation of JavaScript objects within V8. The "js-temporal-objects" part immediately points to the JavaScript Temporal API.

2. **Scan for Key Temporal API Concepts:**  Quickly read through the code, looking for familiar names from the Temporal API. Words like `PlainMonthDay`, `PlainYearMonth`, `PlainDate`, `Calendar`, `Duration`, `from`, `with`, `equals`, `toPlainDate`, `toISOString`, `toLocaleString`, `compare`, `add`, `subtract` stand out. These are the building blocks of the Temporal API.

3. **Infer Class-Specific Functionality:** Notice the code is organized into sections for `JSTemporalPlainMonthDay` and `JSTemporalPlainYearMonth`. This implies the file handles the specific logic for these two Temporal types.

4. **Analyze Individual Functions:**  For each function, try to understand its purpose based on its name and the operations it performs:
    * **`From`:**  Likely a static factory method for creating instances from various inputs. The code checks for existing instances and uses `ToTemporalMonthDay` or `ToTemporalYearMonth`.
    * **`Equals`:**  Implements the equality check between two Temporal objects. It compares the internal ISO values (year, month, day) and the calendar.
    * **`With`:**  Creates a new Temporal object by modifying specific fields. It uses `CalendarFields` and `PrepareTemporalFields` which are common patterns in Temporal for interacting with calendar systems.
    * **`ToPlainDate`:** Converts a `PlainMonthDay` or `PlainYearMonth` to a `PlainDate`, requiring a `year` to complete the date.
    * **`GetISOFields`:** Returns an object containing the internal ISO representation of the Temporal object.
    * **`ToJSON`:** Serializes the Temporal object to a JSON string.
    * **`ToString`:**  Converts the Temporal object to a human-readable string.
    * **`ToLocaleString`:**  Formats the Temporal object according to locale-specific conventions (using `JSDateTimeFormat` if internationalization support is enabled).
    * **Constructors:**  Handle the creation of new `PlainMonthDay` and `PlainYearMonth` objects, including input validation and calendar handling.
    * **`Compare`:**  Compares two `PlainYearMonth` objects.
    * **`Add` / `Subtract` (and the shared helper `AddDurationToOrSubtractDurationFromPlainYearMonth`):** Implement the arithmetic operations of adding or subtracting durations.

5. **Identify Common Patterns:**
    * **`ToTemporal...` functions:** These seem to be common internal functions responsible for converting various JavaScript values into the specific Temporal object type. They handle different input types (existing Temporal objects, strings, plain objects).
    * **Calendar Interaction:**  The code frequently interacts with a `Calendar` object using functions like `CalendarFields`, `CalendarEquals`, `CalendarMergeFields`, `CalendarDaysInMonth`, and `ToTemporalCalendarWithISODefault`. This highlights the importance of calendar systems in the Temporal API.
    * **Error Handling:**  Look for `THROW_NEW_ERROR` and `MAYBE_RETURN_ON_EXCEPTION` which indicate how V8 handles errors during Temporal operations.
    * **Internal Slots:** References to `[[InitializedTemporalMonthDay]]` etc., point to internal properties that distinguish Temporal objects.

6. **Relate to JavaScript Usage (if applicable):** For each function, try to imagine how it would be used in JavaScript. For example:
    * `PlainMonthDay.from("01-01")` would call the `From` method.
    * `monthDay1.equals(monthDay2)` would call the `Equals` method.
    * `yearMonth.toPlainDate({ year: 2024 })` would call the `ToPlainDate` method.

7. **Look for Potential User Errors:** Think about common mistakes developers might make when using the Temporal API. Examples include:
    * Providing invalid string formats to `from`.
    * Trying to add incompatible units (e.g., adding a year to a `PlainTime`). While this specific file doesn't cover `PlainTime`, the general principle applies.
    * Not handling potential exceptions.
    * Misunderstanding the role of the calendar.

8. **Address Specific Constraints:**  Ensure all parts of the prompt are covered:
    * **Function listing:** Done by analyzing individual functions.
    * **Torque check:**  Explicitly check for the `.tq` extension (which isn't the case here).
    * **JavaScript relationship and examples:** Provide concrete JavaScript examples where applicable.
    * **Code logic and examples:**  While full logic tracing is difficult, describe the general flow and provide simple input/output scenarios.
    * **Common errors:** List typical user mistakes.
    * **Part of a series:** Acknowledge the context (part 19 of 25) and infer that this file likely focuses on specific aspects of the Temporal API object implementation.

9. **Summarize the Functionality:** Combine the understanding of individual functions and patterns into a concise summary that captures the overall purpose of the file. Emphasize the core responsibilities related to `PlainMonthDay` and `PlainYearMonth`.

**Self-Correction/Refinement:**

* **Initial thought:**  "This just handles object creation."  **Correction:**  It handles much more than that – parsing, comparison, modification, formatting, etc.
* **Initial thought:** "The calendar is just a property." **Correction:** The calendar is a central concept, with specific functions dedicated to interacting with it.
* **Review the prompt again:** Make sure all constraints are addressed. For example, double-check if JavaScript examples are provided where relevant.

By following these steps, a comprehensive understanding of the V8 source code snippet can be achieved, even without being a V8 expert. The key is to leverage knowledge of the JavaScript Temporal API and common programming patterns.
好的，我们来分析一下 `v8/src/objects/js-temporal-objects.cc` 这个 V8 源代码文件的功能。

**核心功能归纳：**

从代码片段来看，`v8/src/objects/js-temporal-objects.cc` 文件主要负责实现 JavaScript Temporal API 中的 `Temporal.PlainMonthDay` 和 `Temporal.PlainYearMonth` 这两个核心对象的功能。它包含了这两个对象的创建、属性访问、比较、转换、格式化等操作的底层 C++ 实现。

**具体功能分解：**

1. **`Temporal.PlainMonthDay` 的实现：**
   - **创建:** 实现了 `PlainMonthDay` 对象的构造函数 (`JSTemporalPlainMonthDay::Constructor`)，以及从不同类型的值创建 `PlainMonthDay` 对象的方法 (`JSTemporalPlainMonthDay::From`，`ToTemporalMonthDay`)。
   - **属性访问:**  提供了获取 `PlainMonthDay` 对象内部 ISO 日期字段（年、月、日）和日历的方法 (`GetISOFields`)。
   - **比较:** 实现了判断两个 `PlainMonthDay` 对象是否相等的方法 (`Equals`)。
   - **修改:** 提供了创建一个新的 `PlainMonthDay` 对象，其部分属性被修改的方法 (`With`)。
   - **转换:** 提供了将 `PlainMonthDay` 对象转换为 `Temporal.PlainDate` 对象的方法 (`ToPlainDate`)。
   - **格式化:** 实现了将 `PlainMonthDay` 对象转换为字符串的方法 (`ToString`, `ToLocaleString`, `ToJSON`)。
   - **解析:** 实现了从字符串解析创建 `PlainMonthDay` 对象的方法 (`ParseTemporalMonthDayString`)。

2. **`Temporal.PlainYearMonth` 的实现：**
   - **创建:** 实现了 `PlainYearMonth` 对象的构造函数 (`JSTemporalPlainYearMonth::Constructor`)，以及从不同类型的值创建 `PlainYearMonth` 对象的方法 (`JSTemporalPlainYearMonth::From`，`ToTemporalYearMonth`)。
   - **比较:** 实现了判断两个 `PlainYearMonth` 对象是否相等的方法 (`Equals`) 和比较大小的方法 (`Compare`)。
   - **转换:** 提供了将 `PlainYearMonth` 对象转换为 `Temporal.PlainDate` 对象的方法 (`ToPlainDate`)。
   - **格式化:** 实现了将 `PlainYearMonth` 对象转换为字符串的方法。
   - **解析:** 实现了从字符串解析创建 `PlainYearMonth` 对象的方法 (`ParseTemporalYearMonthString`)。
   - **运算:** 实现了 `PlainYearMonth` 对象添加或减去 `Temporal.Duration` 的方法 (`AddDurationToOrSubtractDurationFromPlainYearMonth`)。

3. **内部辅助函数：**
   - 提供了用于解析 ISO 日期和时间字符串的辅助函数 (`ParseISODateTime`, `ParseTemporalMonthDayString`, `ParseTemporalYearMonthString`)。
   - 提供了用于将不同类型的值转换为 `Temporal.Calendar` 对象的辅助函数 (`ToTemporalCalendarWithISODefault`, `GetTemporalCalendarWithISODefault`)。
   - 提供了用于处理 Temporal 字段的辅助函数 (`PrepareTemporalFields`)。
   - 提供了用于处理溢出选项的辅助函数 (`ToTemporalOverflow`)。
   - 提供了用于从字段创建 `PlainMonthDay` 和 `PlainYearMonth` 对象的辅助函数 (`MonthDayFromFields`, `YearMonthFromFields`, `CreateTemporalMonthDay`, `CreateTemporalYearMonth`)。

**关于 .tq 结尾：**

如果 `v8/src/objects/js-temporal-objects.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque** 源代码文件。Torque 是一种 V8 内部使用的类型化的中间语言，用于生成高效的 C++ 代码。目前的 `.cc` 结尾表明它是直接用 C++ 编写的。

**与 JavaScript 功能的关系及示例：**

`v8/src/objects/js-temporal-objects.cc` 中实现的 C++ 代码直接支撑着 JavaScript 中 `Temporal.PlainMonthDay` 和 `Temporal.PlainYearMonth` 的功能。

**JavaScript 示例：**

```javascript
// Temporal.PlainMonthDay 的使用
const monthDay1 = Temporal.PlainMonthDay.from('01-15');
const monthDay2 = new Temporal.PlainMonthDay(3, 15); // 月份从 1 开始

console.log(monthDay1.monthCode); // 输出: M01
console.log(monthDay2.day);       // 输出: 15
console.log(monthDay1.equals(monthDay2)); // 输出: false (月份不同)

const monthDay3 = monthDay1.with({ month: 3 });
console.log(monthDay3.equals(monthDay2)); // 输出: true

const dateFromMonthDay = monthDay1.toPlainDate({ year: 2024 });
console.log(dateFromMonthDay.toString()); // 输出: 2024-01-15

// Temporal.PlainYearMonth 的使用
const yearMonth1 = Temporal.PlainYearMonth.from('2023-12');
const yearMonth2 = new Temporal.PlainYearMonth(2024, 1);

console.log(yearMonth1.year);  // 输出: 2023
console.log(yearMonth2.month); // 输出: 1
console.log(yearMonth1.equals(yearMonth2)); // 输出: false

const yearMonth3 = yearMonth1.with({ year: 2024 });
console.log(yearMonth3.equals(yearMonth2)); // 输出: false (月份不同)

const dateFromYearMonth = yearMonth1.toPlainDate({ day: 1 });
console.log(dateFromYearMonth.toString()); // 输出: 2023-12-01

console.log(Temporal.PlainYearMonth.compare(yearMonth1, yearMonth2)); // 输出: -1 (yearMonth1 在 yearMonth2 之前)
```

**代码逻辑推理与假设输入输出：**

**示例 1: `ToTemporalMonthDay` 函数**

**假设输入：**
- `item_obj`: JavaScript 字符串 `"12-25"`
- `options`:  `undefined`
- `method_name`: `"someMethod"`

**代码逻辑推理：**
1. `Type(item_obj)` 是字符串，所以会执行到第 6 步。
2. 调用 `Object::ToString` 将 `item_obj` 转换为字符串 `"12-25"`。
3. 调用 `ParseTemporalMonthDayString` 解析字符串，得到 `result`，其中 `result.date.month` 为 12，`result.date.day` 为 25，`result.calendar` 为 undefined (ISO 日历)。
4. 调用 `ToTemporalCalendarWithISODefault` 将 `result.calendar` (undefined) 转换为默认的 ISO 日历对象。
5. `result.date.year` 为 `kMinInt31` (表示未定义)。
6. 调用 `CreateTemporalMonthDay` 创建一个新的 `Temporal.PlainMonthDay` 对象，月份为 12，日为 25，日历为 ISO，年份为默认的 `kReferenceIsoYear` (1972)。

**预期输出：**  返回一个新的 `Temporal.PlainMonthDay` 对象，表示 12 月 25 日，年份为 1972，使用 ISO 日历。

**示例 2: `JSTemporalPlainMonthDay::Equals` 函数**

**假设输入：**
- `month_day`: 一个 `Temporal.PlainMonthDay` 对象，内部 ISO 月份为 1，ISO 日为 15，ISO 年份为 1972，日历为 ISO。
- `other_obj`: 一个 JavaScript 对象，可以被转换为 `Temporal.PlainMonthDay`，其内部 ISO 月份为 1，ISO 日为 15，ISO 年份为 1972，日历为 ISO。

**代码逻辑推理：**
1. `RequireInternalSlot` 检查 `month_day` 是否是 `Temporal.PlainMonthDay` 对象。
2. 调用 `ToTemporalMonthDay` 将 `other_obj` 转换为 `Temporal.PlainMonthDay` 对象。
3. 比较 `month_day` 和 `other` 的 `iso_month` (相等，都为 1)。
4. 比较 `month_day` 和 `other` 的 `iso_day` (相等，都为 15)。
5. 比较 `month_day` 和 `other` 的 `iso_year` (相等，都为 1972)。
6. 调用 `CalendarEquals` 比较两个对象的日历 (相等，都是 ISO 日历)。

**预期输出：** 返回 V8 的 `true` 值。

**用户常见的编程错误：**

1. **日期字符串格式错误：**  向 `Temporal.PlainMonthDay.from()` 或 `Temporal.PlainYearMonth.from()` 传递格式不正确的日期字符串，例如 `"2023/12/01"` 而不是 `"2023-12-01"`。

   ```javascript
   // 错误示例
   try {
     const invalidMonthDay = Temporal.PlainMonthDay.from("01/15");
   } catch (e) {
     console.error("错误：", e); // 可能抛出 RangeError
   }
   ```

2. **月份或日期超出范围：** 尝试创建月份大于 12 或日期超出当月天数的 `PlainMonthDay` 或 `PlainYearMonth` 对象。

   ```javascript
   // 错误示例
   try {
     const invalidMonthDay = new Temporal.PlainMonthDay(13, 15);
   } catch (e) {
     console.error("错误：", e); // 抛出 RangeError
   }
   ```

3. **在使用 `toPlainDate` 时缺少年份或日期：**  将 `PlainMonthDay` 转换为 `PlainDate` 时，必须提供年份；将 `PlainYearMonth` 转换为 `PlainDate` 时，必须提供日期。

   ```javascript
   const monthDay = Temporal.PlainMonthDay.from('12-25');
   try {
     const invalidDate = monthDay.toPlainDate({}); // 缺少 year
   } catch (e) {
     console.error("错误：", e); // 抛出 TypeError
   }
   ```

4. **混淆 `Temporal.PlainMonthDay` 和 `Temporal.PlainYearMonth` 的用途：**  错误地认为 `PlainMonthDay` 包含了年份信息，或者在需要月份和年份时使用了 `PlainMonthDay`。

5. **不理解日历对象的影响：**  忽略了 `Temporal.Calendar` 对象在日期计算和比较中的作用，导致在非 ISO 日历下出现意外的结果。

**作为第 19 部分，共 25 部分的功能归纳：**

考虑到这是系列文章的第 19 部分，并且主题是 V8 中 JavaScript Temporal 对象的实现，可以推断出：

- 前面的部分可能已经介绍了 Temporal API 的基础概念、其他核心对象（如 `Temporal.Instant`、`Temporal.ZonedDateTime`、`Temporal.PlainDate`、`Temporal.PlainTime`、`Temporal.Duration` 等）的实现。
- 这一部分专注于 `Temporal.PlainMonthDay` 和 `Temporal.PlainYearMonth` 这两个特定的、相对简单的日期组成部分对象的实现细节。
- 后面的部分可能会涉及更复杂的时间概念（如时区处理）、格式化选项、更高级的日期计算，以及与其他 Temporal 对象的交互。

总而言之，`v8/src/objects/js-temporal-objects.cc` 的这段代码是 V8 引擎中实现 JavaScript Temporal API 中 `Temporal.PlainMonthDay` 和 `Temporal.PlainYearMonth` 功能的关键部分，它负责对象的创建、属性访问、比较、转换和格式化等核心操作。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第19部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
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
                                       day, Just(kThrowO
```