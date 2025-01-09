Response:
Let's break down the thought process for analyzing the provided V8 source code snippet.

**1. Initial Understanding and Keyword Spotting:**

The first step is to recognize the context. The comment `// Copyright 2021 the V8 project authors.` immediately tells us this is part of the V8 JavaScript engine. The file path `v8/src/builtins/builtins-temporal.cc` points to built-in functions related to the "Temporal" API. The `#include` directives confirm this, especially the inclusion of `src/objects/js-temporal-objects-inl.h`.

Keywords like `BUILTIN`, `TemporalNow`, `TemporalConstructor`, `TemporalPrototypeMethod`, `TemporalGet`, etc., stand out. These are clearly macros used to define built-in JavaScript functions.

**2. Identifying the Core Functionality:**

The recurring pattern `Temporal` followed by a type name (like `PlainDate`, `PlainTime`, `ZonedDateTime`, `Duration`, `Instant`) strongly suggests that this file implements the core functionality of the JavaScript Temporal API within V8. The macros themselves hint at the operations supported for each Temporal type: construction, getting current time, prototype methods (like `add`, `subtract`, `with`, `equals`, etc.), and static methods (like `from`, `compare`).

**3. Analyzing the Macros:**

The macros are the key to understanding how the built-ins are defined. Let's look at a few examples:

* **`TEMPORAL_NOW0(T)`:** This macro defines a built-in function named `TemporalNowT` (where `T` is a Temporal type like `TimeZone`). It calls the static `Now()` method of the corresponding `JSTemporalT` class. This indicates functionality for getting the current time for various Temporal types.

* **`TEMPORAL_CONSTRUCTOR1(T)`:** This macro defines the constructor for a Temporal type. It calls the static `Constructor()` method of the `JSTemporalT` class.

* **`TEMPORAL_PROTOTYPE_METHOD1(T, METHOD, name)`:** This macro defines a prototype method. It checks if the `this` value is a `JSTemporalT` object and then calls the `METHOD` on that object, passing in arguments. This is how methods like `plainDate.add()` are implemented.

* **`TEMPORAL_GET(T, METHOD, field)`:** This macro defines a getter for a property. It retrieves the `field` from the `JSTemporalT` object. This corresponds to accessing properties like `plainDate.year`.

**4. Mapping to JavaScript Concepts:**

With the macro analysis, it's easier to connect the C++ code to JavaScript.

* `TemporalNow...`:  Corresponds to static methods like `Temporal.Now.plainDate()`.
* `Temporal...Constructor`: Corresponds to constructors like `new Temporal.PlainDate()`.
* `Temporal...Prototype...`: Corresponds to methods called on Temporal objects, like `plainDate.add()`.
* `Temporal.PlainDate.from()`: Implemented by the `TEMPORAL_METHOD2(PlainDate, From)` macro.

**5. Inferring Functionality from the Defined Built-ins:**

By listing the specific built-ins defined for each Temporal type, we can deduce the supported operations. For example, for `PlainDate`, we see:

* **Construction:** `TemporalPlainDateConstructor`
* **Static Methods:** `From`, `Compare`
* **Getters:** `Calendar`, `Year`, `Month`, `Day`, etc.
* **Prototype Methods:** `Add`, `Subtract`, `WithCalendar`, `With`, `Since`, `Until`, `ToPlainDateTime`, `ToZonedDateTime`, `Equals`, `ToJSON`, `toLocaleString`, `toString`.

This gives a comprehensive picture of what you can do with a `Temporal.PlainDate` object in JavaScript.

**6. Identifying Potential User Errors:**

The `TEMPORAL_VALUE_OF(T)` macro is interesting. It throws a `TypeError` indicating that `valueOf` shouldn't be used directly for comparison. This is a common JavaScript pitfall, and the Temporal API addresses it by providing explicit comparison methods like `equals`, `since`, and `until`. This helps identify a potential user error.

**7. Addressing Specific Questions:**

* **`.tq` extension:** The code uses `.cc`, so it's C++, not Torque. The comment explains what a `.tq` file would indicate.
* **JavaScript examples:** The understanding of the mapping between macros and JavaScript concepts makes it easy to create relevant examples.
* **Code Logic/Assumptions:**  The macros themselves represent the high-level logic. Assumptions can be made about the underlying `JSTemporal...` classes (defined in other files) handling the actual date/time calculations.
* **归纳功能 (Summarizing Functionality):** This involves synthesizing the information gathered from the previous steps into a concise description of the file's purpose.

**Self-Correction/Refinement:**

Initially, one might just list the macros. However, the key is to connect these macros to the actual JavaScript API they represent. Realizing that the pattern `Temporal` + Type name is crucial for organization. Also, paying attention to specific error handling, like the `valueOf` example, adds valuable insight. The process involves moving from the low-level C++ implementation details to the high-level JavaScript API usage.
好的，让我们来分析一下 `v8/src/builtins/builtins-temporal.cc` 这个 V8 源代码文件的功能。

**功能归纳：**

`v8/src/builtins/builtins-temporal.cc` 文件是 V8 JavaScript 引擎中实现 **Temporal API** 内建函数的核心部分。它定义了 JavaScript 中 `Temporal` 对象及其相关类的构造函数、静态方法和原型方法的具体实现。

**具体功能分解：**

1. **实现了 Temporal API 的各种类和方法:**
   - 这个文件包含了 `Temporal.Instant`, `Temporal.PlainDate`, `Temporal.PlainTime`, `Temporal.PlainDateTime`, `Temporal.PlainYearMonth`, `Temporal.PlainMonthDay`, `Temporal.ZonedDateTime`, `Temporal.Duration`, `Temporal.TimeZone` 等类的构造函数和相关方法。
   - 这些方法涵盖了创建、比较、算术运算（加减）、属性访问、格式化、时区转换等与日期和时间操作相关的功能。

2. **定义了获取当前时间的方法:**
   - 使用 `TEMPORAL_NOW0`, `TEMPORAL_NOW2`, `TEMPORAL_NOW_ISO1` 等宏定义了获取当前 `Instant`, `PlainDateTime`, `PlainDate`, `PlainTime`, `ZonedDateTime` 和 `TimeZone` 的方法（例如 `Temporal.Now.plainDate()`, `Temporal.Now.instant()` 等）。

3. **实现了构造函数:**
   - 使用 `TEMPORAL_CONSTRUCTOR1` 宏定义了 `Temporal.Instant` 的构造函数。
   - 对于其他需要更多参数的 Temporal 类，则直接定义了构造函数，例如 `TemporalPlainDateConstructor`, `TemporalPlainTimeConstructor` 等。

4. **实现了原型方法:**
   - 使用 `TEMPORAL_PROTOTYPE_METHOD0`, `TEMPORAL_PROTOTYPE_METHOD1`, `TEMPORAL_PROTOTYPE_METHOD2`, `TEMPORAL_PROTOTYPE_METHOD3` 等宏定义了各种 Temporal 对象的原型方法，例如 `plainDate.add()`, `plainTime.round()`, `zonedDateTime.withCalendar()` 等。

5. **实现了静态方法:**
   - 使用 `TEMPORAL_METHOD1`, `TEMPORAL_METHOD2` 等宏定义了 Temporal 类的静态方法，例如 `Temporal.PlainDate.from()`, `Temporal.PlainTime.compare()` 等。

6. **处理 `valueOf` 方法:**
   - 使用 `TEMPORAL_VALUE_OF` 宏定义了 `valueOf` 方法，并抛出一个 `TypeError`，提示用户不要直接使用 `valueOf` 进行比较，而是使用专门的比较方法（例如 `compare`）。

7. **实现属性访问器 (Getters):**
   - 使用 `TEMPORAL_GET_SMI`, `TEMPORAL_GET`, `TEMPORAL_GET_NUMBER_AFTER_DIVID`, `TEMPORAL_GET_BIGINT_AFTER_DIVID` 等宏定义了访问 Temporal 对象属性的方法，例如 `plainDate.year`, `plainTime.hour`, `zonedDateTime.epochSeconds` 等。

8. **与 Calendar 对象交互:**
   - 使用 `TEMPORAL_GET_BY_FORWARD_CALENDAR` 和 `TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD` 宏定义了与 `Temporal.Calendar` 对象交互的方法，例如获取年份、月份、星期几等，这些方法会委托给关联的 `Calendar` 对象进行处理。

9. **与 TimeZone 对象交互 (针对 ZonedDateTime):**
   - 使用 `TEMPORAL_ZONED_DATE_TIME_GET_PREPARE` 及相关的宏定义了 `ZonedDateTime` 对象获取年、月、日、时、分、秒等属性的方法，这些方法会考虑时区的影响。

**关于文件后缀 `.tq`:**

你说的很对。如果 `v8/src/builtins/builtins-temporal.cc` 的文件后缀是 `.tq`，那么它就表示这是一个 **V8 Torque** 源代码文件。Torque 是 V8 用来定义内建函数的一种领域特定语言，它比直接用 C++ 写内建函数更安全、更容易维护。

**与 JavaScript 功能的关系及示例:**

这个文件直接实现了 JavaScript 的 `Temporal` API。你在 JavaScript 中使用的 `Temporal` 对象和方法，其背后的 C++ 代码实现就位于这个文件中（或相关的 Torque 文件，如果存在）。

**JavaScript 示例：**

```javascript
// 获取当前日期
const today = Temporal.Now.plainDateISO();
console.log(today.toString()); // 例如：2023-10-27

// 创建一个特定的日期
const specificDate = new Temporal.PlainDate(2024, 1, 1);
console.log(specificDate.toString()); // 2024-01-01

// 日期加法
const futureDate = today.add({ days: 7 });
console.log(futureDate.toString());

// 比较两个日期
const isBefore = specificDate.since(today).sign === 1; // specificDate 在 today 之后
console.log(isBefore);

// 获取当前带时区的日期时间
const nowZoned = Temporal.Now.zonedDateTimeISO();
console.log(nowZoned.toString());

// 创建一个 Duration 对象
const duration = new Temporal.Duration(1, 2, 0, 5); // 1 年，2 个月，5 天
console.log(duration.toString());

// 对日期进行时区转换 (需要 TimeZone 对象)
const parisTimeZone = new Temporal.TimeZone("Europe/Paris");
const nowInParis = nowZoned.withTimeZone(parisTimeZone);
console.log(nowInParis.toString());
```

**代码逻辑推理及假设输入输出：**

假设我们有一个 `Temporal.PlainDate` 对象 `myDate`，其内部表示的 ISO 年、月、日分别是 2023, 10, 27。当我们调用 `myDate.day` 时，根据 `TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDate, Day, day)` 宏的定义，V8 内部会执行以下逻辑：

1. **检查接收者:** 确保 `myDate` 是一个 `JSTemporalPlainDate` 对象。
2. **调用 Calendar 的方法:** 调用与 `myDate` 关联的 `Calendar` 对象的 `Day` 方法，并将 `myDate` 作为参数传递。
3. **返回结果:** `Calendar` 对象的 `Day` 方法会根据其日历系统的规则计算出日期，并返回结果（在本例中很可能是 27）。

**假设输入：** `myDate` 是一个 `Temporal.PlainDate` 实例，ISO 年为 2023，ISO 月为 10，ISO 日为 27。

**输出：** 调用 `myDate.day` 会返回数字 `27`。

**用户常见的编程错误示例：**

1. **直接使用 `valueOf` 进行比较：**

   ```javascript
   const date1 = new Temporal.PlainDate(2023, 10, 27);
   const date2 = new Temporal.PlainDate(2023, 10, 27);

   // 错误的做法：直接比较 valueOf 的结果
   console.log(date1.valueOf() === date2.valueOf()); // 可能会得到 false，因为 valueOf 返回的是内部表示

   // 正确的做法：使用 equals 方法
   console.log(date1.equals(date2)); // true
   ```

2. **混淆 `PlainDate` 和 `ZonedDateTime`：**

   ```javascript
   const plainDate = new Temporal.PlainDate(2023, 10, 27);
   const zonedDateTime = Temporal.Now.zonedDateTimeISO();

   // 错误的做法：直接将 PlainDate 赋值给需要 ZonedDateTime 的地方
   // 可能会导致类型错误或逻辑错误

   // 正确的做法：根据需要进行转换
   const zonedFromPlain = plainDate.toZonedDateTime("UTC"); // 假设转换为 UTC 时区
   ```

3. **不理解 Duration 的单位：**

   ```javascript
   const duration = new Temporal.Duration(365, 0, 0, 0); // 假设表示 365 天
   const today = Temporal.Now.plainDateISO();
   const future = today.add(duration);
   console.log(future.toString()); // 结果可能不是精确的一年后，因为 Duration 的 years 单位是不精确的
   ```
   应该根据需要使用更精确的单位，或者考虑使用 `PlainDate.until()` 来计算日期之间的精确间隔。

**总结一下它的功能:**

总而言之，`v8/src/builtins/builtins-temporal.cc` 文件在 V8 引擎中扮演着至关重要的角色，它 **使用 C++ 实现了 JavaScript Temporal API 的核心功能**，让开发者能够在 JavaScript 中方便且精确地处理日期和时间相关的操作。它定义了各种 Temporal 类的行为，包括创建、计算、比较和格式化等，并处理了与时区和日历系统的交互。

Prompt: 
```
这是目录为v8/src/builtins/builtins-temporal.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-temporal.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-utils-inl.h"
#include "src/builtins/builtins.h"
#include "src/objects/bigint.h"
#include "src/objects/js-temporal-objects-inl.h"

namespace v8 {
namespace internal {

#define TO_BE_IMPLEMENTED(id)   \
  BUILTIN_NO_RCS(id) {          \
    HandleScope scope(isolate); \
    UNIMPLEMENTED();            \
  }

#define TEMPORAL_NOW0(T)                                            \
  BUILTIN(TemporalNow##T) {                                         \
    HandleScope scope(isolate);                                     \
    RETURN_RESULT_OR_FAILURE(isolate, JSTemporal##T::Now(isolate)); \
  }

#define TEMPORAL_NOW2(T)                                                     \
  BUILTIN(TemporalNow##T) {                                                  \
    HandleScope scope(isolate);                                              \
    RETURN_RESULT_OR_FAILURE(                                                \
        isolate, JSTemporal##T::Now(isolate, args.atOrUndefined(isolate, 1), \
                                    args.atOrUndefined(isolate, 2)));        \
  }

#define TEMPORAL_NOW_ISO1(T)                                             \
  BUILTIN(TemporalNow##T##ISO) {                                         \
    HandleScope scope(isolate);                                          \
    RETURN_RESULT_OR_FAILURE(                                            \
        isolate,                                                         \
        JSTemporal##T::NowISO(isolate, args.atOrUndefined(isolate, 1))); \
  }

#define TEMPORAL_CONSTRUCTOR1(T)                                              \
  BUILTIN(Temporal##T##Constructor) {                                         \
    HandleScope scope(isolate);                                               \
    RETURN_RESULT_OR_FAILURE(                                                 \
        isolate,                                                              \
        JSTemporal##T::Constructor(isolate, args.target(), args.new_target(), \
                                   args.atOrUndefined(isolate, 1)));          \
  }

#define TEMPORAL_PROTOTYPE_METHOD0(T, METHOD, name)                          \
  BUILTIN(Temporal##T##Prototype##METHOD) {                                  \
    HandleScope scope(isolate);                                              \
    CHECK_RECEIVER(JSTemporal##T, obj, "Temporal." #T ".prototype." #name);  \
    RETURN_RESULT_OR_FAILURE(isolate, JSTemporal##T ::METHOD(isolate, obj)); \
  }

#define TEMPORAL_PROTOTYPE_METHOD1(T, METHOD, name)                            \
  BUILTIN(Temporal##T##Prototype##METHOD) {                                    \
    HandleScope scope(isolate);                                                \
    CHECK_RECEIVER(JSTemporal##T, obj, "Temporal." #T ".prototype." #name);    \
    RETURN_RESULT_OR_FAILURE(                                                  \
        isolate,                                                               \
        JSTemporal##T ::METHOD(isolate, obj, args.atOrUndefined(isolate, 1))); \
  }

#define TEMPORAL_PROTOTYPE_METHOD2(T, METHOD, name)                          \
  BUILTIN(Temporal##T##Prototype##METHOD) {                                  \
    HandleScope scope(isolate);                                              \
    CHECK_RECEIVER(JSTemporal##T, obj, "Temporal." #T ".prototype." #name);  \
    RETURN_RESULT_OR_FAILURE(                                                \
        isolate,                                                             \
        JSTemporal##T ::METHOD(isolate, obj, args.atOrUndefined(isolate, 1), \
                               args.atOrUndefined(isolate, 2)));             \
  }

#define TEMPORAL_PROTOTYPE_METHOD3(T, METHOD, name)                          \
  BUILTIN(Temporal##T##Prototype##METHOD) {                                  \
    HandleScope scope(isolate);                                              \
    CHECK_RECEIVER(JSTemporal##T, obj, "Temporal." #T ".prototype." #name);  \
    RETURN_RESULT_OR_FAILURE(                                                \
        isolate,                                                             \
        JSTemporal##T ::METHOD(isolate, obj, args.atOrUndefined(isolate, 1), \
                               args.atOrUndefined(isolate, 2),               \
                               args.atOrUndefined(isolate, 3)));             \
  }

#define TEMPORAL_METHOD1(T, METHOD)                                       \
  BUILTIN(Temporal##T##METHOD) {                                          \
    HandleScope scope(isolate);                                           \
    RETURN_RESULT_OR_FAILURE(                                             \
        isolate,                                                          \
        JSTemporal##T ::METHOD(isolate, args.atOrUndefined(isolate, 1))); \
  }

#define TEMPORAL_METHOD2(T, METHOD)                                     \
  BUILTIN(Temporal##T##METHOD) {                                        \
    HandleScope scope(isolate);                                         \
    RETURN_RESULT_OR_FAILURE(                                           \
        isolate,                                                        \
        JSTemporal##T ::METHOD(isolate, args.atOrUndefined(isolate, 1), \
                               args.atOrUndefined(isolate, 2)));        \
  }

#define TEMPORAL_VALUE_OF(T)                                                 \
  BUILTIN(Temporal##T##PrototypeValueOf) {                                   \
    HandleScope scope(isolate);                                              \
    THROW_NEW_ERROR_RETURN_FAILURE(                                          \
        isolate, NewTypeError(MessageTemplate::kDoNotUse,                    \
                              isolate->factory()->NewStringFromAsciiChecked( \
                                  "Temporal." #T ".prototype.valueOf"),      \
                              isolate->factory()->NewStringFromAsciiChecked( \
                                  "use Temporal." #T                         \
                                  ".prototype.compare for comparison.")));   \
  }

#define TEMPORAL_GET_SMI(T, METHOD, field)                   \
  BUILTIN(Temporal##T##Prototype##METHOD) {                  \
    HandleScope scope(isolate);                              \
    CHECK_RECEIVER(JSTemporal##T, obj,                       \
                   "get Temporal." #T ".prototype." #field); \
    return Smi::FromInt(obj->field());                       \
  }

#define TEMPORAL_METHOD1(T, METHOD)                                       \
  BUILTIN(Temporal##T##METHOD) {                                          \
    HandleScope scope(isolate);                                           \
    RETURN_RESULT_OR_FAILURE(                                             \
        isolate,                                                          \
        JSTemporal##T ::METHOD(isolate, args.atOrUndefined(isolate, 1))); \
  }

#define TEMPORAL_METHOD2(T, METHOD)                                     \
  BUILTIN(Temporal##T##METHOD) {                                        \
    HandleScope scope(isolate);                                         \
    RETURN_RESULT_OR_FAILURE(                                           \
        isolate,                                                        \
        JSTemporal##T ::METHOD(isolate, args.atOrUndefined(isolate, 1), \
                               args.atOrUndefined(isolate, 2)));        \
  }

#define TEMPORAL_GET(T, METHOD, field)                                       \
  BUILTIN(Temporal##T##Prototype##METHOD) {                                  \
    HandleScope scope(isolate);                                              \
    CHECK_RECEIVER(JSTemporal##T, obj, "Temporal." #T ".prototype." #field); \
    return obj->field();                                                     \
  }

#define TEMPORAL_GET_NUMBER_AFTER_DIVID(T, M, field, scale, name)         \
  BUILTIN(Temporal##T##Prototype##M) {                                    \
    HandleScope scope(isolate);                                           \
    CHECK_RECEIVER(JSTemporal##T, handle,                                 \
                   "get Temporal." #T ".prototype." #name);               \
    Handle<BigInt> value;                                                 \
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(                                   \
        isolate, value,                                                   \
        BigInt::Divide(isolate, Handle<BigInt>(handle->field(), isolate), \
                       BigInt::FromUint64(isolate, scale)));              \
    DirectHandle<Object> number = BigInt::ToNumber(isolate, value);       \
    DCHECK(std::isfinite(Object::NumberValue(*number)));                  \
    return *number;                                                       \
  }

#define TEMPORAL_GET_BIGINT_AFTER_DIVID(T, M, field, scale, name)         \
  BUILTIN(Temporal##T##Prototype##M) {                                    \
    HandleScope scope(isolate);                                           \
    CHECK_RECEIVER(JSTemporal##T, handle,                                 \
                   "get Temporal." #T ".prototype." #name);               \
    RETURN_RESULT_OR_FAILURE(                                             \
        isolate,                                                          \
        BigInt::Divide(isolate, Handle<BigInt>(handle->field(), isolate), \
                       BigInt::FromUint64(isolate, scale)));              \
  }

#define TEMPORAL_GET_BY_FORWARD_CALENDAR(T, METHOD, name)                 \
  BUILTIN(Temporal##T##Prototype##METHOD) {                               \
    HandleScope scope(isolate);                                           \
    CHECK_RECEIVER(JSTemporal##T, temporal_date,                          \
                   "get Temporal." #T ".prototype." #name);               \
    RETURN_RESULT_OR_FAILURE(                                             \
        isolate, temporal::Calendar##METHOD(                              \
                     isolate, handle(temporal_date->calendar(), isolate), \
                     temporal_date));                                     \
  }

#define TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(T, METHOD, name)              \
  BUILTIN(Temporal##T##Prototype##METHOD) {                                  \
    HandleScope scope(isolate);                                              \
    /* 2. Perform ? RequireInternalSlot(temporalDate, */                     \
    /*    [[InitializedTemporal#T]]). */                                     \
    CHECK_RECEIVER(JSTemporal##T, date_like,                                 \
                   "get Temporal." #T ".prototype." #name);                  \
    /* 3. Let calendar be temporalDate.[[Calendar]]. */                      \
    Handle<JSReceiver> calendar = handle(date_like->calendar(), isolate);    \
    /* 2. Return ? Invoke(calendar, "name", « dateLike »).  */             \
    RETURN_RESULT_OR_FAILURE(                                                \
        isolate, temporal::InvokeCalendarMethod(                             \
                     isolate, calendar, isolate->factory()->name##_string(), \
                     date_like));                                            \
  }

// Now
TEMPORAL_NOW0(TimeZone)
TEMPORAL_NOW0(Instant)
TEMPORAL_NOW2(PlainDateTime)
TEMPORAL_NOW_ISO1(PlainDateTime)
TEMPORAL_NOW2(PlainDate)
TEMPORAL_NOW_ISO1(PlainDate)

// There is NO Temporal.now.plainTime
// See https://github.com/tc39/proposal-temporal/issues/1540
TEMPORAL_NOW_ISO1(PlainTime)
TEMPORAL_NOW2(ZonedDateTime)
TEMPORAL_NOW_ISO1(ZonedDateTime)

// PlainDate
BUILTIN(TemporalPlainDateConstructor) {
  HandleScope scope(isolate);
  RETURN_RESULT_OR_FAILURE(
      isolate, JSTemporalPlainDate::Constructor(
                   isolate, args.target(), args.new_target(),
                   args.atOrUndefined(isolate, 1),    // iso_year
                   args.atOrUndefined(isolate, 2),    // iso_month
                   args.atOrUndefined(isolate, 3),    // iso_day
                   args.atOrUndefined(isolate, 4)));  // calendar_like
}
TEMPORAL_METHOD2(PlainDate, From)
TEMPORAL_METHOD2(PlainDate, Compare)
TEMPORAL_GET(PlainDate, Calendar, calendar)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDate, Year, year)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDate, Month, month)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDate, MonthCode, monthCode)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDate, Day, day)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDate, DayOfWeek, dayOfWeek)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDate, DayOfYear, dayOfYear)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDate, WeekOfYear, weekOfYear)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDate, DaysInWeek, daysInWeek)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDate, DaysInMonth, daysInMonth)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDate, DaysInYear, daysInYear)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDate, MonthsInYear, monthsInYear)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDate, InLeapYear, inLeapYear)
TEMPORAL_PROTOTYPE_METHOD0(PlainDate, ToPlainYearMonth, toPlainYearMonth)
TEMPORAL_PROTOTYPE_METHOD0(PlainDate, ToPlainMonthDay, toPlainMonthDay)
TEMPORAL_PROTOTYPE_METHOD2(PlainDate, Add, add)
TEMPORAL_PROTOTYPE_METHOD2(PlainDate, Subtract, subtract)
TEMPORAL_PROTOTYPE_METHOD1(PlainDate, WithCalendar, withCalendar)
TEMPORAL_PROTOTYPE_METHOD2(PlainDate, With, with)
TEMPORAL_PROTOTYPE_METHOD0(PlainDate, GetISOFields, getISOFields)
TEMPORAL_PROTOTYPE_METHOD2(PlainDate, Since, since)
TEMPORAL_PROTOTYPE_METHOD2(PlainDate, Until, until)
TEMPORAL_PROTOTYPE_METHOD1(PlainDate, ToPlainDateTime, toPlainDateTime)
TEMPORAL_PROTOTYPE_METHOD1(PlainDate, ToZonedDateTime, toZonedDateTime)
TEMPORAL_PROTOTYPE_METHOD1(PlainDate, Equals, equals)
TEMPORAL_VALUE_OF(PlainDate)
TEMPORAL_PROTOTYPE_METHOD0(PlainDate, ToJSON, toJSON)
TEMPORAL_PROTOTYPE_METHOD2(PlainDate, ToLocaleString, toLocaleString)
TEMPORAL_PROTOTYPE_METHOD1(PlainDate, ToString, toString)

// PlainTime
BUILTIN(TemporalPlainTimeConstructor) {
  HandleScope scope(isolate);
  RETURN_RESULT_OR_FAILURE(isolate,
                           JSTemporalPlainTime::Constructor(
                               isolate, args.target(), args.new_target(),
                               args.atOrUndefined(isolate, 1),    // hour
                               args.atOrUndefined(isolate, 2),    // minute
                               args.atOrUndefined(isolate, 3),    // second
                               args.atOrUndefined(isolate, 4),    // millisecond
                               args.atOrUndefined(isolate, 5),    // microsecond
                               args.atOrUndefined(isolate, 6)));  // nanosecond
}
TEMPORAL_GET(PlainTime, Calendar, calendar)
TEMPORAL_GET_SMI(PlainTime, Hour, iso_hour)
TEMPORAL_GET_SMI(PlainTime, Minute, iso_minute)
TEMPORAL_GET_SMI(PlainTime, Second, iso_second)
TEMPORAL_GET_SMI(PlainTime, Millisecond, iso_millisecond)
TEMPORAL_GET_SMI(PlainTime, Microsecond, iso_microsecond)
TEMPORAL_GET_SMI(PlainTime, Nanosecond, iso_nanosecond)
TEMPORAL_METHOD2(PlainTime, From)
TEMPORAL_PROTOTYPE_METHOD1(PlainTime, ToZonedDateTime, toZonedDateTime)
TEMPORAL_METHOD2(PlainTime, Compare)
TEMPORAL_PROTOTYPE_METHOD1(PlainTime, Equals, equals)
TEMPORAL_PROTOTYPE_METHOD1(PlainTime, Add, add)
TEMPORAL_PROTOTYPE_METHOD1(PlainTime, Subtract, subtract)
TEMPORAL_PROTOTYPE_METHOD0(PlainTime, GetISOFields, getISOFields)
TEMPORAL_PROTOTYPE_METHOD1(PlainTime, Round, round)
TEMPORAL_PROTOTYPE_METHOD2(PlainTime, Since, since)
TEMPORAL_PROTOTYPE_METHOD1(PlainTime, ToPlainDateTime, toPlainDateTime)
TEMPORAL_PROTOTYPE_METHOD0(PlainTime, ToJSON, toJSON)
TEMPORAL_PROTOTYPE_METHOD2(PlainTime, ToLocaleString, toLocaleString)
TEMPORAL_PROTOTYPE_METHOD1(PlainTime, ToString, toString)
TEMPORAL_PROTOTYPE_METHOD2(PlainTime, Until, until)
TEMPORAL_PROTOTYPE_METHOD2(PlainTime, With, with)
TEMPORAL_VALUE_OF(PlainTime)

// PlainDateTime
BUILTIN(TemporalPlainDateTimeConstructor) {
  HandleScope scope(isolate);
  RETURN_RESULT_OR_FAILURE(
      isolate, JSTemporalPlainDateTime::Constructor(
                   isolate, args.target(), args.new_target(),
                   args.atOrUndefined(isolate, 1),     // iso_year
                   args.atOrUndefined(isolate, 2),     // iso_month
                   args.atOrUndefined(isolate, 3),     // iso_day
                   args.atOrUndefined(isolate, 4),     // hour
                   args.atOrUndefined(isolate, 5),     // minute
                   args.atOrUndefined(isolate, 6),     // second
                   args.atOrUndefined(isolate, 7),     // millisecond
                   args.atOrUndefined(isolate, 8),     // microsecond
                   args.atOrUndefined(isolate, 9),     // nanosecond
                   args.atOrUndefined(isolate, 10)));  // calendar_like
}
TEMPORAL_GET(PlainDateTime, Calendar, calendar)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDateTime, Year, year)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDateTime, Month, month)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDateTime, MonthCode, monthCode)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDateTime, Day, day)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDateTime, DayOfWeek, dayOfWeek)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDateTime, DayOfYear, dayOfYear)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDateTime, WeekOfYear, weekOfYear)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDateTime, DaysInWeek, daysInWeek)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDateTime, DaysInMonth, daysInMonth)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDateTime, DaysInYear, daysInYear)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDateTime, MonthsInYear,
                                       monthsInYear)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainDateTime, InLeapYear, inLeapYear)
TEMPORAL_PROTOTYPE_METHOD1(PlainDateTime, WithCalendar, withCalendar)
TEMPORAL_PROTOTYPE_METHOD1(PlainDateTime, WithPlainTime, withPlainTime)
TEMPORAL_GET_SMI(PlainDateTime, Hour, iso_hour)
TEMPORAL_GET_SMI(PlainDateTime, Minute, iso_minute)
TEMPORAL_GET_SMI(PlainDateTime, Second, iso_second)
TEMPORAL_GET_SMI(PlainDateTime, Millisecond, iso_millisecond)
TEMPORAL_GET_SMI(PlainDateTime, Microsecond, iso_microsecond)
TEMPORAL_GET_SMI(PlainDateTime, Nanosecond, iso_nanosecond)
TEMPORAL_METHOD2(PlainDateTime, From)
TEMPORAL_METHOD2(PlainDateTime, Compare)
TEMPORAL_PROTOTYPE_METHOD1(PlainDateTime, Equals, equals)
TEMPORAL_PROTOTYPE_METHOD0(PlainDateTime, ToPlainYearMonth, toPlainYearMonth)
TEMPORAL_PROTOTYPE_METHOD0(PlainDateTime, ToPlainMonthDay, toPlainMonthDay)
TEMPORAL_PROTOTYPE_METHOD2(PlainDateTime, ToZonedDateTime, toZonedDateTime)
TEMPORAL_PROTOTYPE_METHOD0(PlainDateTime, GetISOFields, getISOFields)
TEMPORAL_PROTOTYPE_METHOD1(PlainDateTime, WithPlainDate, withPlainDate)
TEMPORAL_PROTOTYPE_METHOD2(PlainDateTime, With, with)
TEMPORAL_PROTOTYPE_METHOD2(PlainDateTime, Add, add)
TEMPORAL_PROTOTYPE_METHOD1(PlainDateTime, Round, round)
TEMPORAL_PROTOTYPE_METHOD2(PlainDateTime, Since, since)
TEMPORAL_PROTOTYPE_METHOD2(PlainDateTime, Subtract, subtract)
TEMPORAL_PROTOTYPE_METHOD0(PlainDateTime, ToPlainDate, toPlainDate)
TEMPORAL_PROTOTYPE_METHOD0(PlainDateTime, ToPlainTime, toPlainTime)
TEMPORAL_PROTOTYPE_METHOD0(PlainDateTime, ToJSON, toJSON)
TEMPORAL_PROTOTYPE_METHOD2(PlainDateTime, ToLocaleString, toLocaleString)
TEMPORAL_PROTOTYPE_METHOD1(PlainDateTime, ToString, toString)
TEMPORAL_PROTOTYPE_METHOD2(PlainDateTime, Until, until)
TEMPORAL_VALUE_OF(PlainDateTime)

// PlainYearMonth
BUILTIN(TemporalPlainYearMonthConstructor) {
  HandleScope scope(isolate);
  RETURN_RESULT_OR_FAILURE(
      isolate, JSTemporalPlainYearMonth::Constructor(
                   isolate, args.target(), args.new_target(),
                   args.atOrUndefined(isolate, 1),    // iso_year
                   args.atOrUndefined(isolate, 2),    // iso_month
                   args.atOrUndefined(isolate, 3),    // calendar_like
                   args.atOrUndefined(isolate, 4)));  // reference_iso_day
}
TEMPORAL_GET(PlainYearMonth, Calendar, calendar)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainYearMonth, Year, year)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainYearMonth, Month, month)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainYearMonth, MonthCode, monthCode)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainYearMonth, DaysInYear, daysInYear)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainYearMonth, DaysInMonth, daysInMonth)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainYearMonth, MonthsInYear,
                                       monthsInYear)
TEMPORAL_GET_BY_INVOKE_CALENDAR_METHOD(PlainYearMonth, InLeapYear, inLeapYear)
TEMPORAL_METHOD2(PlainYearMonth, From)
TEMPORAL_METHOD2(PlainYearMonth, Compare)
TEMPORAL_PROTOTYPE_METHOD2(PlainYearMonth, Add, add)
TEMPORAL_PROTOTYPE_METHOD2(PlainYearMonth, Subtract, subtract)
TEMPORAL_PROTOTYPE_METHOD1(PlainYearMonth, Equals, equals)
TEMPORAL_PROTOTYPE_METHOD2(PlainYearMonth, With, with)
TEMPORAL_PROTOTYPE_METHOD1(PlainYearMonth, ToPlainDate, toPlainDate)
TEMPORAL_PROTOTYPE_METHOD0(PlainYearMonth, GetISOFields, getISOFields)
TEMPORAL_VALUE_OF(PlainYearMonth)
TEMPORAL_PROTOTYPE_METHOD2(PlainYearMonth, Since, since)
TEMPORAL_PROTOTYPE_METHOD2(PlainYearMonth, ToLocaleString, toLocaleString)
TEMPORAL_PROTOTYPE_METHOD0(PlainYearMonth, ToJSON, toJSON)
TEMPORAL_PROTOTYPE_METHOD1(PlainYearMonth, ToString, toString)
TEMPORAL_PROTOTYPE_METHOD2(PlainYearMonth, Until, until)

// PlainMonthDay
BUILTIN(TemporalPlainMonthDayConstructor) {
  HandleScope scope(isolate);
  RETURN_RESULT_OR_FAILURE(
      isolate, JSTemporalPlainMonthDay::Constructor(
                   isolate, args.target(), args.new_target(),
                   args.atOrUndefined(isolate, 1),    // iso_month
                   args.atOrUndefined(isolate, 2),    // iso_day
                   args.atOrUndefined(isolate, 3),    // calendar_like
                   args.atOrUndefined(isolate, 4)));  // reference_iso_year
}
TEMPORAL_GET(PlainMonthDay, Calendar, calendar)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainMonthDay, MonthCode, monthCode)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainMonthDay, Day, day)
TEMPORAL_METHOD2(PlainMonthDay, From)
TEMPORAL_PROTOTYPE_METHOD1(PlainMonthDay, Equals, equals)
TEMPORAL_PROTOTYPE_METHOD2(PlainMonthDay, With, with)
TEMPORAL_PROTOTYPE_METHOD1(PlainMonthDay, ToPlainDate, toPlainDate)
TEMPORAL_PROTOTYPE_METHOD0(PlainMonthDay, GetISOFields, getISOFields)
TEMPORAL_VALUE_OF(PlainMonthDay)
TEMPORAL_PROTOTYPE_METHOD0(PlainMonthDay, ToJSON, toJSON)
TEMPORAL_PROTOTYPE_METHOD2(PlainMonthDay, ToLocaleString, toLocaleString)
TEMPORAL_PROTOTYPE_METHOD1(PlainMonthDay, ToString, toString)

// ZonedDateTime

#define TEMPORAL_ZONED_DATE_TIME_GET_PREPARE(M)                               \
  HandleScope scope(isolate);                                                 \
  const char* method_name = "get Temporal.ZonedDateTime.prototype." #M;       \
  /* 1. Let zonedDateTime be the this value. */                               \
  /* 2. Perform ? RequireInternalSlot(zonedDateTime, */                       \
  /* [[InitializedTemporalZonedDateTime]]). */                                \
  CHECK_RECEIVER(JSTemporalZonedDateTime, zoned_date_time, method_name);      \
  /* 3. Let timeZone be zonedDateTime.[[TimeZone]]. */                        \
  Handle<JSReceiver> time_zone =                                              \
      handle(zoned_date_time->time_zone(), isolate);                          \
  /* 4. Let instant be ?                                   */                 \
  /* CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]). */                 \
  Handle<JSTemporalInstant> instant;                                          \
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(                                         \
      isolate, instant,                                                       \
      temporal::CreateTemporalInstant(                                        \
          isolate, Handle<BigInt>(zoned_date_time->nanoseconds(), isolate))); \
  /* 5. Let calendar be zonedDateTime.[[Calendar]]. */                        \
  Handle<JSReceiver> calendar = handle(zoned_date_time->calendar(), isolate); \
  /* 6. Let temporalDateTime be ?                 */                          \
  /* BuiltinTimeZoneGetPlainDateTimeFor(timeZone, */                          \
  /* instant, calendar). */                                                   \
  Handle<JSTemporalPlainDateTime> temporal_date_time;                         \
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(                                         \
      isolate, temporal_date_time,                                            \
      temporal::BuiltinTimeZoneGetPlainDateTimeFor(                           \
          isolate, time_zone, instant, calendar, method_name));

#define TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(M) \
  BUILTIN(TemporalZonedDateTimePrototype##M) {                            \
    TEMPORAL_ZONED_DATE_TIME_GET_PREPARE(M)                               \
    /* 7. Return ? Calendar##M(calendar, temporalDateTime). */            \
    RETURN_RESULT_OR_FAILURE(                                             \
        isolate,                                                          \
        temporal::Calendar##M(isolate, calendar, temporal_date_time));    \
  }

#define TEMPORAL_ZONED_DATE_TIME_GET_INT_BY_FORWARD_TIME_ZONE(M, field) \
  BUILTIN(TemporalZonedDateTimePrototype##M) {                          \
    TEMPORAL_ZONED_DATE_TIME_GET_PREPARE(M)                             \
    /* 7. Return 𝔽(temporalDateTime.[[ #field ]]). */                \
    return Smi::FromInt(temporal_date_time->field());                   \
  }

BUILTIN(TemporalZonedDateTimeConstructor) {
  HandleScope scope(isolate);
  RETURN_RESULT_OR_FAILURE(
      isolate, JSTemporalZonedDateTime::Constructor(
                   isolate, args.target(), args.new_target(),
                   args.atOrUndefined(isolate, 1),    // epoch_nanoseconds
                   args.atOrUndefined(isolate, 2),    // time_zone_like
                   args.atOrUndefined(isolate, 3)));  // calendar_like
}
TEMPORAL_METHOD2(ZonedDateTime, From)
TEMPORAL_METHOD2(ZonedDateTime, Compare)
TEMPORAL_GET(ZonedDateTime, Calendar, calendar)
TEMPORAL_GET(ZonedDateTime, TimeZone, time_zone)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(Year)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(Month)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(MonthCode)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(Day)
TEMPORAL_GET(ZonedDateTime, EpochNanoseconds, nanoseconds)
TEMPORAL_GET_NUMBER_AFTER_DIVID(ZonedDateTime, EpochSeconds, nanoseconds,
                                1000000000, epochSeconds)
TEMPORAL_GET_NUMBER_AFTER_DIVID(ZonedDateTime, EpochMilliseconds, nanoseconds,
                                1000000, epochMilliseconds)
TEMPORAL_GET_BIGINT_AFTER_DIVID(ZonedDateTime, EpochMicroseconds, nanoseconds,
                                1000, epochMicroseconds)
TEMPORAL_ZONED_DATE_TIME_GET_INT_BY_FORWARD_TIME_ZONE(Hour, iso_hour)
TEMPORAL_ZONED_DATE_TIME_GET_INT_BY_FORWARD_TIME_ZONE(Minute, iso_minute)
TEMPORAL_ZONED_DATE_TIME_GET_INT_BY_FORWARD_TIME_ZONE(Second, iso_second)
TEMPORAL_ZONED_DATE_TIME_GET_INT_BY_FORWARD_TIME_ZONE(Millisecond,
                                                      iso_millisecond)
TEMPORAL_ZONED_DATE_TIME_GET_INT_BY_FORWARD_TIME_ZONE(Microsecond,
                                                      iso_microsecond)
TEMPORAL_ZONED_DATE_TIME_GET_INT_BY_FORWARD_TIME_ZONE(Nanosecond,
                                                      iso_nanosecond)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(DayOfWeek)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(DayOfYear)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(WeekOfYear)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(DaysInWeek)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(DaysInMonth)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(DaysInYear)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(MonthsInYear)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(InLeapYear)
TEMPORAL_PROTOTYPE_METHOD1(ZonedDateTime, Equals, equals)
TEMPORAL_PROTOTYPE_METHOD0(ZonedDateTime, HoursInDay, hoursInDay)
TEMPORAL_PROTOTYPE_METHOD2(ZonedDateTime, With, with)
TEMPORAL_PROTOTYPE_METHOD1(ZonedDateTime, WithCalendar, withCalendar)
TEMPORAL_PROTOTYPE_METHOD1(ZonedDateTime, WithPlainDate, withPlainDate)
TEMPORAL_PROTOTYPE_METHOD1(ZonedDateTime, WithPlainTime, withPlainTime)
TEMPORAL_PROTOTYPE_METHOD1(ZonedDateTime, WithTimeZone, withTimeZone)
TEMPORAL_PROTOTYPE_METHOD0(ZonedDateTime, ToPlainYearMonth, toPlainYearMonth)
TEMPORAL_PROTOTYPE_METHOD0(ZonedDateTime, ToPlainMonthDay, toPlainMonthDay)
TEMPORAL_PROTOTYPE_METHOD1(ZonedDateTime, Round, round)
TEMPORAL_PROTOTYPE_METHOD2(ZonedDateTime, Add, add)
TEMPORAL_PROTOTYPE_METHOD2(ZonedDateTime, Subtract, subtract)
TEMPORAL_PROTOTYPE_METHOD0(ZonedDateTime, GetISOFields, getISOFields)
TEMPORAL_PROTOTYPE_METHOD0(ZonedDateTime, OffsetNanoseconds, offsetNanoseconds)
TEMPORAL_PROTOTYPE_METHOD0(ZonedDateTime, Offset, offset)
TEMPORAL_PROTOTYPE_METHOD2(ZonedDateTime, Since, since)
TEMPORAL_PROTOTYPE_METHOD0(ZonedDateTime, StartOfDay, startOfDay)
TEMPORAL_PROTOTYPE_METHOD0(ZonedDateTime, ToInstant, toInstant)
TEMPORAL_PROTOTYPE_METHOD0(ZonedDateTime, ToJSON, toJSON)
TEMPORAL_PROTOTYPE_METHOD0(ZonedDateTime, ToPlainDate, toPlainDate)
TEMPORAL_PROTOTYPE_METHOD0(ZonedDateTime, ToPlainTime, toPlainTime)
TEMPORAL_PROTOTYPE_METHOD0(ZonedDateTime, ToPlainDateTime, toPlainDateTime)
TEMPORAL_PROTOTYPE_METHOD2(ZonedDateTime, ToLocaleString, toLocaleString)
TEMPORAL_PROTOTYPE_METHOD1(ZonedDateTime, ToString, toString)
TEMPORAL_PROTOTYPE_METHOD2(ZonedDateTime, Until, until)
TEMPORAL_VALUE_OF(ZonedDateTime)

// Duration
BUILTIN(TemporalDurationConstructor) {
  HandleScope scope(isolate);
  RETURN_RESULT_OR_FAILURE(
      isolate, JSTemporalDuration::Constructor(
                   isolate, args.target(), args.new_target(),
                   args.atOrUndefined(isolate, 1),     // years
                   args.atOrUndefined(isolate, 2),     // months
                   args.atOrUndefined(isolate, 3),     // weeks
                   args.atOrUndefined(isolate, 4),     // days
                   args.atOrUndefined(isolate, 5),     // hours
                   args.atOrUndefined(isolate, 6),     // minutes
                   args.atOrUndefined(isolate, 7),     // seconds
                   args.atOrUndefined(isolate, 8),     // milliseconds
                   args.atOrUndefined(isolate, 9),     // microseconds
                   args.atOrUndefined(isolate, 10)));  // nanoseconds
}

BUILTIN(TemporalDurationCompare) {
  HandleScope scope(isolate);
  RETURN_RESULT_OR_FAILURE(isolate, JSTemporalDuration::Compare(
                                        isolate, args.atOrUndefined(isolate, 1),
                                        args.atOrUndefined(isolate, 2),
                                        args.atOrUndefined(isolate, 3)));
}
TEMPORAL_METHOD1(Duration, From)
TEMPORAL_GET(Duration, Years, years)
TEMPORAL_GET(Duration, Months, months)
TEMPORAL_GET(Duration, Weeks, weeks)
TEMPORAL_GET(Duration, Days, days)
TEMPORAL_GET(Duration, Hours, hours)
TEMPORAL_GET(Duration, Minutes, minutes)
TEMPORAL_GET(Duration, Seconds, seconds)
TEMPORAL_GET(Duration, Milliseconds, milliseconds)
TEMPORAL_GET(Duration, Microseconds, microseconds)
TEMPORAL_GET(Duration, Nanoseconds, nanoseconds)
TEMPORAL_PROTOTYPE_METHOD1(Duration, Round, round)
TEMPORAL_PROTOTYPE_METHOD1(Duration, Total, total)
TEMPORAL_PROTOTYPE_METHOD1(Duration, With, with)
TEMPORAL_PROTOTYPE_METHOD0(Duration, Sign, sign)
TEMPORAL_PROTOTYPE_METHOD0(Duration, Blank, blank)
TEMPORAL_PROTOTYPE_METHOD0(Duration, Negated, negated)
TEMPORAL_PROTOTYPE_METHOD0(Duration, Abs, abs)
TEMPORAL_PROTOTYPE_METHOD2(Duration, Add, add)
TEMPORAL_PROTOTYPE_METHOD2(Duration, Subtract, subtract)
TEMPORAL_VALUE_OF(Duration)
TEMPORAL_PROTOTYPE_METHOD0(Duration, ToJSON, toJSON)
TEMPORAL_PROTOTYPE_METHOD2(Duration, ToLocaleString, toLocaleString)
TEMPORAL_PROTOTYPE_METHOD1(Duration, ToString, toString)

// Instant
TEMPORAL_CONSTRUCTOR1(Instant)
TEMPORAL_M
"""


```