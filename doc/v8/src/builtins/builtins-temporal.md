Response: Let's break down the thought process for analyzing this C++ code and connecting it to JavaScript's Temporal API.

1. **Identify the Core Purpose:** The file name `builtins-temporal.cc` and the numerous macros starting with `TEMPORAL_` strongly suggest this file implements the built-in functions for the JavaScript `Temporal` API within the V8 JavaScript engine.

2. **Recognize the Macro Patterns:**  The code heavily uses C++ macros. This is a common technique in V8 to reduce boilerplate and generate similar function implementations. Observing the patterns in the macro names is key:
    * `TEMPORAL_NOW*`:  Likely related to creating `Temporal` objects representing the current time.
    * `TEMPORAL_CONSTRUCTOR*`:  Clearly about constructing `Temporal` objects.
    * `TEMPORAL_PROTOTYPE_METHOD*`: These are the methods attached to the prototype of each `Temporal` object type.
    * `TEMPORAL_METHOD*`:  Likely static methods on the `Temporal` classes themselves.
    * `TEMPORAL_GET*`:  Accessors for properties of `Temporal` objects.
    * `TEMPORAL_VALUE_OF`: Handles the `valueOf` method.

3. **Map Macros to Functionality:**  For each macro family, consider its probable JavaScript counterpart:
    * `TEMPORAL_NOW`:  Corresponds to `Temporal.Now.xxx()`.
    * `TEMPORAL_CONSTRUCTOR`: Corresponds to `new Temporal.Xxx()`.
    * `TEMPORAL_PROTOTYPE_METHOD`: Corresponds to methods like `date.add()`, `time.round()`, etc.
    * `TEMPORAL_METHOD`: Corresponds to static methods like `Temporal.PlainDate.from()`, `Temporal.Duration.compare()`.
    * `TEMPORAL_GET`: Corresponds to accessing properties like `date.year`, `time.hour`.
    * `TEMPORAL_VALUE_OF`: Handles the behavior of `valueOf` (which is explicitly disallowed for `Temporal` objects).

4. **Identify the `Temporal` Types:**  Scanning the macro usages reveals the various `Temporal` types being implemented: `PlainDate`, `PlainTime`, `PlainDateTime`, `PlainYearMonth`, `PlainMonthDay`, `ZonedDateTime`, `Duration`, `Instant`, `Calendar`, `TimeZone`. This list matches the core types in the JavaScript `Temporal` API.

5. **Connect C++ Structures to JavaScript Concepts:**
    * `JSTemporalXxx`:  These C++ classes (e.g., `JSTemporalPlainDate`) likely represent the internal representation of the corresponding JavaScript `Temporal` objects.
    * `isolate`:  Represents the V8 JavaScript execution environment.
    * `HandleScope`: Manages memory within the V8 engine.
    * `RETURN_RESULT_OR_FAILURE`: A macro for handling potential errors and returning values.
    * `CHECK_RECEIVER`:  Ensures the `this` value in a method call is the expected `Temporal` object type.

6. **Infer Function Implementations from Macros:**  By looking at the macro definitions and their usage, you can understand the general flow:
    * Most built-in functions take arguments (`args`).
    * They often perform checks (e.g., `CHECK_RECEIVER`).
    * They call methods on the internal `JSTemporalXxx` objects (e.g., `JSTemporalPlainDate::Constructor`, `JSTemporalPlainDate::Add`).
    * They handle potential failures.

7. **Formulate a Summary of Functionality:** Based on the identified types and the macro patterns, summarize the file's purpose: implementing the built-in functions for the JavaScript `Temporal` API in V8. Mention the core `Temporal` types covered.

8. **Construct JavaScript Examples:** For each major `Temporal` type, select a few representative built-in functions implemented in the C++ code and show how they are used in JavaScript. Choose examples that demonstrate constructors, static methods (`from`, `compare`), prototype methods (`add`, `round`), and property accessors (`year`, `hour`). This solidifies the connection between the C++ implementation and the JavaScript API.

9. **Explain the "Why":**  Explain *why* this C++ code is necessary. It's the underlying implementation that makes the JavaScript `Temporal` API work efficiently within the browser or Node.js environment. It handles the complex logic of date and time calculations, time zones, and calendar systems.

10. **Refine and Organize:** Review the summary and examples for clarity and accuracy. Organize the information logically, perhaps grouping examples by `Temporal` type. Ensure the JavaScript examples are correct and illustrate the corresponding C++ functionality.

Self-Correction/Refinement during the process:

* **Initial thought:**  Maybe this file only handles a *subset* of `Temporal`. **Correction:**  As you scan through, you see macros for almost all the core `Temporal` types, indicating comprehensive coverage.
* **Initial thought:**  The macros are just for convenience. **Refinement:** The macros are crucial for V8's code generation and efficiency, allowing similar code patterns to be expressed concisely.
* **Initial thought:** Just list the functions. **Refinement:**  It's more helpful to categorize them (constructors, prototype methods, etc.) and connect them explicitly to the JavaScript API elements they implement. The JavaScript examples are essential for making the connection clear.
这个 C++ 源代码文件 `builtins-temporal.cc` 是 **V8 JavaScript 引擎** 中用于实现 **ECMAScript Temporal API** 的内置函数（built-ins）。

**功能归纳：**

该文件定义了大量的 C++ 函数，这些函数直接对应于 JavaScript 中 `Temporal` API 的各种构造函数、静态方法和原型方法。  它负责以下核心功能：

1. **构造 `Temporal` 对象:**  实现了 `Temporal.PlainDate`, `Temporal.PlainTime`, `Temporal.PlainDateTime`, `Temporal.ZonedDateTime`, `Temporal.Duration`, `Temporal.Instant`, `Temporal.Calendar`, `Temporal.TimeZone` 等对象的构造过程。
2. **实现 `Temporal` 对象的静态方法:**  例如 `Temporal.PlainDate.from()`, `Temporal.PlainDate.compare()`, `Temporal.Instant.fromEpochSeconds()` 等。
3. **实现 `Temporal` 对象的原型方法:** 例如 `plainDate.add()`, `plainTime.round()`, `zonedDateTime.withTimeZone()`, `instant.toString()` 等。
4. **实现 `Temporal` 对象的属性访问器 (getters):** 例如 `plainDate.year`, `plainTime.hour`, `zonedDateTime.epochNanoseconds` 等。
5. **处理 `Temporal` 对象的特殊方法:** 例如 `valueOf` (在 `Temporal` 中被禁用并抛出错误)。
6. **与 `Intl` 集成:**  部分代码（带有 `V8_INTL_SUPPORT` 宏）涉及到与国际化相关的日历属性，例如 `era` 和 `eraYear`。
7. **实现 `Temporal.Now` 系列方法:** 用于获取当前时间相关的 `Temporal` 对象。
8. **调用底层的 `JSTemporal...` C++ 类:**  这些内置函数通常会调用在 `src/objects/js-temporal-objects-inl.h` 中定义的 `JSTemporal...` 类的方法，这些类包含了 `Temporal` 对象的内部状态和更底层的逻辑实现。

**与 JavaScript 的关系及示例：**

这个 C++ 文件是 JavaScript `Temporal` API 的底层实现。当你在 JavaScript 中使用 `Temporal` API 时，V8 引擎会执行这个文件中对应的 C++ 内置函数。

**以下是一些 JavaScript 示例，并对应到 `builtins-temporal.cc` 中的部分实现：**

**1. 构造函数：**

```javascript
// 对应 builtins-temporal.cc 中的 BUILTIN(TemporalPlainDateConstructor)
const plainDate = new Temporal.PlainDate(2023, 10, 27);

// 对应 builtins-temporal.cc 中的 BUILTIN(TemporalPlainTimeConstructor)
const plainTime = new Temporal.PlainTime(10, 30, 0);

// 对应 builtins-temporal.cc 中的 BUILTIN(TemporalPlainDateTimeConstructor)
const plainDateTime = new Temporal.PlainDateTime(2023, 10, 27, 10, 30, 0);
```

**2. 静态方法：**

```javascript
// 对应 builtins-temporal.cc 中的 TEMPORAL_METHOD2(PlainDate, From) 和 BUILTIN(TemporalPlainDateFrom)
const anotherDate = Temporal.PlainDate.from('2023-10-28');

// 对应 builtins-temporal.cc 中的 TEMPORAL_METHOD2(Duration, Compare) 和 BUILTIN(TemporalDurationCompare)
const duration1 = new Temporal.Duration(1, 0, 0);
const duration2 = new Temporal.Duration(0, 12, 0);
const comparisonResult = Temporal.Duration.compare(duration1, duration2);
```

**3. 原型方法：**

```javascript
const date = new Temporal.PlainDate(2023, 10, 27);

// 对应 builtins-temporal.cc 中的 TEMPORAL_PROTOTYPE_METHOD2(PlainDate, Add, add) 和 BUILTIN(TemporalPlainDatePrototypeAdd)
const futureDate = date.add({ days: 7 });

// 对应 builtins-temporal.cc 中的 TEMPORAL_PROTOTYPE_METHOD1(PlainTime, Round, round) 和 BUILTIN(TemporalPlainTimePrototypeRound)
const time = new Temporal.PlainTime(10, 30, 15);
const roundedTime = time.round({ smallestUnit: 'minute' });

// 对应 builtins-temporal.cc 中的 TEMPORAL_PROTOTYPE_METHOD0(PlainDate, ToJSON, toJSON) 和 BUILTIN(TemporalPlainDatePrototypeToJSON)
const jsonString = date.toJSON();
```

**4. 属性访问器 (getters):**

```javascript
const date = new Temporal.PlainDate(2023, 10, 27);

// 对应 builtins-temporal.cc 中的 TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDate, Year, year) 和 BUILTIN(TemporalPlainDatePrototypeYear)
const year = date.year;

// 对应 builtins-temporal.cc 中的 TEMPORAL_GET_SMI(PlainTime, Hour, iso_hour) 和 BUILTIN(TemporalPlainTimePrototypeHour)
const time = new Temporal.PlainTime(10, 30, 0);
const hour = time.hour;
```

**5. `Temporal.Now` 系列方法：**

```javascript
// 对应 builtins-temporal.cc 中的 TEMPORAL_NOW0(TimeZone) 和 BUILTIN(TemporalNowTimeZone)
const timeZone = Temporal.Now.timeZone();

// 对应 builtins-temporal.cc 中的 TEMPORAL_NOW2(PlainDateTime) 和 BUILTIN(TemporalNowPlainDateTime)
const nowDateTime = Temporal.Now.plainDateTime('iso8601');
```

**总结:**

`builtins-temporal.cc` 文件是 V8 引擎中 `Temporal` API 的核心实现部分，它将 JavaScript 中对 `Temporal` 对象的各种操作转化为底层的 C++ 代码执行，从而使 JavaScript 能够高效地处理日期、时间和时区相关的复杂逻辑。  该文件通过大量的宏定义来简化和组织代码，清晰地映射了 JavaScript `Temporal` API 的各种特性。

### 提示词
```
这是目录为v8/src/builtins/builtins-temporal.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
TEMPORAL_METHOD1(Instant, FromEpochSeconds)
TEMPORAL_METHOD1(Instant, FromEpochMilliseconds)
TEMPORAL_METHOD1(Instant, FromEpochMicroseconds)
TEMPORAL_METHOD1(Instant, FromEpochNanoseconds)
TEMPORAL_METHOD1(Instant, From)
TEMPORAL_METHOD2(Instant, Compare)
TEMPORAL_PROTOTYPE_METHOD1(Instant, Equals, equals)
TEMPORAL_VALUE_OF(Instant)
TEMPORAL_GET(Instant, EpochNanoseconds, nanoseconds)
TEMPORAL_GET_NUMBER_AFTER_DIVID(Instant, EpochSeconds, nanoseconds, 1000000000,
                                epochSeconds)
TEMPORAL_GET_NUMBER_AFTER_DIVID(Instant, EpochMilliseconds, nanoseconds,
                                1000000, epochMilliseconds)
TEMPORAL_GET_BIGINT_AFTER_DIVID(Instant, EpochMicroseconds, nanoseconds, 1000,
                                epochMicroseconds)
TEMPORAL_PROTOTYPE_METHOD1(Instant, Add, add)
TEMPORAL_PROTOTYPE_METHOD1(Instant, Round, round)
TEMPORAL_PROTOTYPE_METHOD2(Instant, Since, since)
TEMPORAL_PROTOTYPE_METHOD1(Instant, Subtract, subtract)
TEMPORAL_PROTOTYPE_METHOD0(Instant, ToJSON, toJSON)
TEMPORAL_PROTOTYPE_METHOD2(Instant, ToLocaleString, toLocaleString)
TEMPORAL_PROTOTYPE_METHOD1(Instant, ToString, toString)
TEMPORAL_PROTOTYPE_METHOD1(Instant, ToZonedDateTime, toZonedDateTime)
TEMPORAL_PROTOTYPE_METHOD1(Instant, ToZonedDateTimeISO, toZonedDateTimeISO)
TEMPORAL_PROTOTYPE_METHOD2(Instant, Until, until)

// Calendar
TEMPORAL_CONSTRUCTOR1(Calendar)

// #sec-get-temporal.calendar.prototype.id
BUILTIN(TemporalCalendarPrototypeId) {
  HandleScope scope(isolate);
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  CHECK_RECEIVER(JSTemporalCalendar, calendar,
                 "Temporal.Calendar.prototype.id");
  // 3. Return ? ToString(calendar).
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToString(isolate, calendar));
}

// #sec-temporal.calendar.prototype.tojson
BUILTIN(TemporalCalendarPrototypeToJSON) {
  HandleScope scope(isolate);
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  CHECK_RECEIVER(JSTemporalCalendar, calendar,
                 "Temporal.Calendar.prototype.toJSON");
  // 3. Return ? ToString(calendar).
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToString(isolate, calendar));
}

// #sec-temporal.calendar.prototype.tostring
BUILTIN(TemporalCalendarPrototypeToString) {
  HandleScope scope(isolate);
  const char* method_name = "Temporal.Calendar.prototype.toString";
  // 1. Let calendar be the this value.
  // 2. Perform ? RequireInternalSlot(calendar,
  // [[InitializedTemporalCalendar]]).
  CHECK_RECEIVER(JSTemporalCalendar, calendar, method_name);
  // 3. Return calendar.[[Identifier]].
  RETURN_RESULT_OR_FAILURE(
      isolate, JSTemporalCalendar::ToString(isolate, calendar, method_name));
}

TEMPORAL_PROTOTYPE_METHOD3(Calendar, DateAdd, dateAdd)
TEMPORAL_PROTOTYPE_METHOD2(Calendar, DateFromFields, dateFromFields)
TEMPORAL_PROTOTYPE_METHOD3(Calendar, DateUntil, dateUntil)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, Day, day)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, DaysInMonth, daysInMonth)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, DaysInWeek, daysInWeek)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, DaysInYear, daysInYear)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, DayOfWeek, dayOfWeek)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, DayOfYear, dayOfYear)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, InLeapYear, inLeapYear)
TEMPORAL_PROTOTYPE_METHOD2(Calendar, MergeFields, mergeFields)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, Month, month)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, MonthCode, monthCode)
TEMPORAL_PROTOTYPE_METHOD2(Calendar, MonthDayFromFields, monthDayFromFields)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, MonthsInYear, monthsInYear)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, Year, year)
TEMPORAL_PROTOTYPE_METHOD2(Calendar, YearMonthFromFields, yearMonthFromFields)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, WeekOfYear, weekOfYear)
// #sec-temporal.calendar.from
BUILTIN(TemporalCalendarFrom) {
  HandleScope scope(isolate);
  RETURN_RESULT_OR_FAILURE(isolate, temporal::ToTemporalCalendar(
                                        isolate, args.atOrUndefined(isolate, 1),
                                        "Temporal.Calendar.from"));
}

// TimeZone
TEMPORAL_CONSTRUCTOR1(TimeZone)
TEMPORAL_PROTOTYPE_METHOD2(TimeZone, GetInstantFor, getInstantFor)
TEMPORAL_PROTOTYPE_METHOD1(TimeZone, GetNextTransition, getNextTransition)
TEMPORAL_PROTOTYPE_METHOD1(TimeZone, GetOffsetNanosecondsFor,
                           getOffsetNanosecondsFor)
TEMPORAL_PROTOTYPE_METHOD1(TimeZone, GetOffsetStringFor, getOffsetStringFor)
TEMPORAL_PROTOTYPE_METHOD2(TimeZone, GetPlainDateTimeFor, getPlainDateTimeFor)
TEMPORAL_PROTOTYPE_METHOD1(TimeZone, GetPossibleInstantsFor,
                           getPossibleInstantFor)
TEMPORAL_PROTOTYPE_METHOD1(TimeZone, GetPreviousTransition,
                           getPreviousTransition)

// #sec-get-temporal.timezone.prototype.id
BUILTIN(TemporalTimeZonePrototypeId) {
  HandleScope scope(isolate);
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  CHECK_RECEIVER(JSTemporalTimeZone, time_zone,
                 "Temporal.TimeZone.prototype.id");
  // 3. Return ? ToString(timeZone).
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToString(isolate, time_zone));
}

// #sec-temporal.timezone.prototype.tojson
BUILTIN(TemporalTimeZonePrototypeToJSON) {
  HandleScope scope(isolate);
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  CHECK_RECEIVER(JSTemporalTimeZone, time_zone,
                 "Temporal.TimeZone.prototype.toJSON");
  // 3. Return ? ToString(timeZone).
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToString(isolate, time_zone));
}

// #sec-temporal.timezone.prototype.tostring
BUILTIN(TemporalTimeZonePrototypeToString) {
  HandleScope scope(isolate);
  const char* method_name = "Temporal.TimeZone.prototype.toString";
  // 1. Let timeZone be the this value.
  // 2. Perform ? RequireInternalSlot(timeZone,
  // [[InitializedTemporalTimeZone]]).
  CHECK_RECEIVER(JSTemporalTimeZone, time_zone, method_name);
  // 3. Return timeZone.[[Identifier]].
  RETURN_RESULT_OR_FAILURE(
      isolate, JSTemporalTimeZone::ToString(isolate, time_zone, method_name));
}

// #sec-temporal.timezone.from
BUILTIN(TemporalTimeZoneFrom) {
  HandleScope scope(isolate);
  RETURN_RESULT_OR_FAILURE(isolate, temporal::ToTemporalTimeZone(
                                        isolate, args.atOrUndefined(isolate, 1),
                                        "Temporal.TimeZone.from"));
}

#ifdef V8_INTL_SUPPORT
// Temporal.Calendar.prototype.era/eraYear
TEMPORAL_PROTOTYPE_METHOD1(Calendar, Era, era)
TEMPORAL_PROTOTYPE_METHOD1(Calendar, EraYear, eraYEar)
// get Temporal.*.prototype.era/eraYear
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDate, Era, era)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDate, EraYear, eraYear)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDateTime, Era, era)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainDateTime, EraYear, eraYear)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainYearMonth, Era, era)
TEMPORAL_GET_BY_FORWARD_CALENDAR(PlainYearMonth, EraYear, eraYear)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(Era)
TEMPORAL_ZONED_DATE_TIME_GET_BY_FORWARD_TIME_ZONE_AND_CALENDAR(EraYear)
#endif  // V8_INTL_SUPPORT
}  // namespace internal
}  // namespace v8
```