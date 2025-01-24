Response: My thought process for analyzing the C++ code and generating the summary and JavaScript examples would be as follows:

1. **Understand the Goal:** The request is to summarize the functionality of the `builtins-date.cc` file and illustrate its connection to JavaScript's `Date` object.

2. **High-Level Overview (Skimming):** I'd start by skimming the code, paying attention to:
    * **Includes:**  These tell me the dependencies and what kind of functionalities the code interacts with (e.g., `date/date.h`, `objects/js-date.h`, `strings/string-stream.h`). The presence of `#ifdef V8_INTL_SUPPORT` hints at internationalization features.
    * **Namespaces:**  The code is within `v8::internal`, which confirms it's part of V8's internal implementation.
    * **`BUILTIN()` macros:** These are key. They indicate the C++ implementations of JavaScript built-in functions. I'd look for patterns like `DateConstructor`, `DateNow`, `DateParse`, and various `DatePrototype` methods.
    * **Helper functions:**  Functions like `SetLocalDateValue`, `SetDateValue` indicate internal operations related to setting date values.
    * **Comments:**  The copyright notice and section headings (`ES6 section 20.3 Date Objects`) provide context.

3. **Identify Key Functionality Areas (Categorization):** Based on the `BUILTIN()` macros, I'd categorize the functions:
    * **Constructor:** `DateConstructor`
    * **Static Methods:**  Methods called directly on the `Date` object (`Date.now()`, `Date.parse()`, `Date.UTC()`).
    * **Prototype Methods (Getters/Setters):** Methods called on `Date` instances (`setDate`, `setFullYear`, `getHours`, `setUTCHours`, `toDateString`, etc.).
    * **Internationalization Methods:** Methods related to localization (indicated by `#ifdef V8_INTL_SUPPORT` and names like `toLocaleDateString`).
    * **Legacy Methods:**  Methods like `getYear` and `setYear` (marked as ES6 section B, indicating backward compatibility).
    * **Other Methods:** `toJSON`, `toTemporalInstant`.

4. **Analyze Individual Builtins:** For each `BUILTIN()` function, I'd try to understand its purpose by looking at:
    * **Arguments:** What parameters does it expect?
    * **Return Value:** What does it return?
    * **Internal Logic:**  What core operations are performed (e.g., `JSDate::CurrentTimeValue`, `ParseDateTimeString`, `MakeDay`, `MakeTime`, calls to `isolate->date_cache()`).
    * **Error Handling:** Are there checks for invalid input or receiver types (`CHECK_RECEIVER`)?

5. **Connect to JavaScript:**  For each identified functionality area, I'd consider the corresponding JavaScript `Date` methods or constructor usage. This involves mapping the C++ built-in names to their JavaScript equivalents.

6. **Illustrate with JavaScript Examples:** The core of the task is to demonstrate the connection. For each major function, I'd write simple JavaScript examples that would trigger the corresponding C++ code. The examples should be clear and focused on the specific functionality. For example:
    * `new Date()` will trigger the `DateConstructor`.
    * `Date.now()` will trigger the `DateNow` builtin.
    * `new Date("...")` or `Date.parse("...")` will trigger `DateParse`.
    * `dateInstance.setDate(...)` will trigger `DatePrototypeSetDate`.

7. **Summarize the Functionality:** Based on the analysis, I'd write a concise summary that covers the main responsibilities of the file: implementing the `Date` object's constructor, static methods, and prototype methods, including handling time zones, date/time calculations, and string formatting.

8. **Refine and Organize:**  I'd review the summary and examples for clarity, accuracy, and completeness. I'd ensure the explanation of the relationship between the C++ code and JavaScript is clear. I'd organize the examples logically, grouping related functionalities together.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus on the low-level details of memory management.
* **Correction:** The request is about *functionality*. Focus on the higher-level operations and their connection to JavaScript.
* **Initial thought:**  Just list all the `BUILTIN()` functions.
* **Correction:** Categorize the functions for better understanding and organization.
* **Initial thought:** Provide very complex JavaScript examples.
* **Correction:** Keep the examples simple and focused to illustrate the specific C++ function being discussed.
* **Considering the `isolate` parameter:** Realize that `isolate` is V8's way of managing its runtime environment. While important internally, it's less crucial for a functional summary from a JavaScript perspective.

By following these steps, I can systematically analyze the C++ code, understand its purpose, and effectively illustrate its relationship to JavaScript's `Date` object with clear and relevant examples.
这个C++源代码文件 `builtins-date.cc` 的主要功能是 **实现了 JavaScript 中 `Date` 对象相关的内置方法 (built-ins)**。 它定义了 `Date` 构造函数以及 `Date` 对象原型上的各种方法，这些方法允许 JavaScript 代码创建、操作和格式化日期和时间。

**具体功能归纳:**

1. **`Date` 构造函数 (`DateConstructor`)**:
   - 处理 `new Date()` 的不同调用方式：
     - 无参数：创建表示当前日期和时间的对象。
     - 单个参数：
       - 如果是 `Date` 对象，则复制该对象的时间值。
       - 如果是字符串，则尝试解析该字符串为日期。
       - 如果是数字，则将其视为 Unix 时间戳（毫秒）。
     - 多个参数 (年, 月, 日, 时, 分, 秒, 毫秒)：根据指定的年、月等创建日期对象。
   - 如果作为普通函数调用 (`Date()`)，则返回当前日期和时间的字符串表示。

2. **静态方法 (`Date.*`)**:
   - **`Date.now()`**: 返回自 Unix 纪元以来的当前时间戳（毫秒）。
   - **`Date.parse(string)`**: 解析日期字符串，返回对应的 Unix 时间戳。
   - **`Date.UTC(year, month, ...)`**:  根据给定的参数返回对应的 UTC 时间的 Unix 时间戳。

3. **原型方法 (`Date.prototype.*`)**:
   - **`set*` 方法 (如 `setDate`, `setFullYear`, `setHours`, `setMinutes`, `setSeconds`, `setMilliseconds`, `setMonth`, `setTime`, 以及对应的 `setUTC*` 方法)**:  用于设置 `Date` 对象的年、月、日、时、分、秒、毫秒等。`setUTC*` 方法设置的是 UTC 时间。
   - **`to*String` 方法 (如 `toDateString`, `toISOString`, `toString`, `toTimeString`, `toUTCString`)**:  用于将 `Date` 对象格式化为不同的字符串表示形式，包括本地时间和 UTC 时间。
   - **国际化相关方法 (`toLocaleDateString`, `toLocaleString`, `toLocaleTimeString`) (需要 `V8_INTL_SUPPORT`)**:  根据本地化设置格式化日期和时间字符串。
   - **旧版本方法 (`getYear`, `setYear`)**:  为了兼容旧版本 JavaScript 而保留的方法。
   - **`toJSON()`**: 返回日期对象的 ISO 格式字符串表示，用于 JSON 序列化。
   - **`toTemporalInstant()`**: (Temporal API 相关) 将 `Date` 对象转换为 `Temporal.Instant` 对象。

**与 JavaScript 功能的关系及示例:**

这个 C++ 文件是 V8 引擎（Chrome 和 Node.js 使用的 JavaScript 引擎）中 `Date` 对象功能的底层实现。 当你在 JavaScript 中使用 `Date` 对象及其方法时，V8 引擎会调用这个文件中相应的 C++ 函数来执行操作。

**JavaScript 示例:**

```javascript
// 创建 Date 对象
let now = new Date();
console.log(now); // 输出当前的日期和时间

let specificDate = new Date(2023, 10, 20, 10, 30, 0); // 2023年11月20日 10:30:00 (月份从 0 开始)
console.log(specificDate);

let parsedDate = new Date("October 13, 2023 11:13:00");
console.log(parsedDate);

// 获取当前时间戳
let timestamp = Date.now();
console.log(timestamp);

// 解析日期字符串
let parsedTimestamp = Date.parse("December 17, 1995 03:24:00");
console.log(parsedTimestamp);

// 使用 UTC 创建日期
let utcDate = new Date(Date.UTC(2023, 10, 20, 10, 30, 0));
console.log(utcDate);

// 设置日期和时间
let myDate = new Date();
myDate.setDate(15);
myDate.setFullYear(2024);
console.log(myDate);

// 格式化日期为字符串
console.log(myDate.toDateString());
console.log(myDate.toISOString());
console.log(myDate.toLocaleString());

// 获取年份 (注意 getYear 的兼容性问题)
console.log(myDate.getFullYear());

// 转换为 JSON 字符串
console.log(myDate.toJSON());
```

**总结:**

`builtins-date.cc` 文件是 V8 引擎中 `Date` 对象功能的核心实现，它使用 C++ 语言提供了 JavaScript 中 `Date` 对象所有的方法和构造函数的底层逻辑，负责处理日期和时间的创建、操作、格式化以及与其他时间概念（如 Unix 时间戳和 UTC 时间）的转换。  JavaScript 开发者通过 `Date` 对象及其方法进行的所有日期时间操作，最终都会委托给这个文件中的 C++ 代码来执行。

### 提示词
```
这是目录为v8/src/builtins/builtins-date.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-utils-inl.h"
#include "src/builtins/builtins.h"
#include "src/codegen/code-factory.h"
#include "src/date/date.h"
#include "src/date/dateparser-inl.h"
#include "src/logging/counters.h"
#include "src/numbers/conversions.h"
#include "src/objects/bigint.h"
#ifdef V8_INTL_SUPPORT
#include "src/objects/intl-objects.h"
#include "src/objects/js-date-time-format.h"
#endif
#include "src/objects/js-temporal-objects-inl.h"
#include "src/objects/objects-inl.h"
#include "src/strings/string-stream.h"

namespace v8 {
namespace internal {

// -----------------------------------------------------------------------------
// ES6 section 20.3 Date Objects

namespace {

Tagged<Object> SetLocalDateValue(Isolate* isolate, DirectHandle<JSDate> date,
                                 double time_val) {
  if (time_val >= -DateCache::kMaxTimeBeforeUTCInMs &&
      time_val <= DateCache::kMaxTimeBeforeUTCInMs) {
    time_val = isolate->date_cache()->ToUTC(static_cast<int64_t>(time_val));
    if (DateCache::TryTimeClip(&time_val)) {
      date->SetValue(time_val);
      return *isolate->factory()->NewNumber(time_val);
    }
  }
  date->SetNanValue();
  return ReadOnlyRoots(isolate).nan_value();
}

Tagged<Object> SetDateValue(Isolate* isolate, DirectHandle<JSDate> date,
                            double time_val) {
  if (DateCache::TryTimeClip(&time_val)) {
    date->SetValue(time_val);
    return *isolate->factory()->NewNumber(time_val);
  }
  date->SetNanValue();
  return ReadOnlyRoots(isolate).nan_value();
}

}  // namespace

// ES #sec-date-constructor
BUILTIN(DateConstructor) {
  HandleScope scope(isolate);
  if (IsUndefined(*args.new_target(), isolate)) {
    double const time_val =
        static_cast<double>(JSDate::CurrentTimeValue(isolate));
    DateBuffer buffer = ToDateString(time_val, isolate->date_cache(),
                                     ToDateStringMode::kLocalDateAndTime);
    RETURN_RESULT_OR_FAILURE(
        isolate, isolate->factory()->NewStringFromUtf8(base::VectorOf(buffer)));
  }
  // [Construct]
  int const argc = args.length() - 1;
  Handle<JSFunction> target = args.target();
  Handle<JSReceiver> new_target = Cast<JSReceiver>(args.new_target());
  double time_val;
  if (argc == 0) {
    time_val = static_cast<double>(JSDate::CurrentTimeValue(isolate));
  } else if (argc == 1) {
    Handle<Object> value = args.at(1);
    if (IsJSDate(*value)) {
      time_val = Cast<JSDate>(value)->value();
    } else {
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, value,
                                         Object::ToPrimitive(isolate, value));
      if (IsString(*value)) {
        time_val = ParseDateTimeString(isolate, Cast<String>(value));
      } else {
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, value,
                                           Object::ToNumber(isolate, value));
        time_val = Object::NumberValue(*value);
      }
    }
  } else {
    Handle<Object> year_object;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, year_object,
                                       Object::ToNumber(isolate, args.at(1)));
    Handle<Object> month_object;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, month_object,
                                       Object::ToNumber(isolate, args.at(2)));
    double year = Object::NumberValue(*year_object);
    double month = Object::NumberValue(*month_object);
    double date = 1.0, hours = 0.0, minutes = 0.0, seconds = 0.0, ms = 0.0;
    if (argc >= 3) {
      Handle<Object> date_object;
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, date_object,
                                         Object::ToNumber(isolate, args.at(3)));
      date = Object::NumberValue(*date_object);
      if (argc >= 4) {
        Handle<Object> hours_object;
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
            isolate, hours_object, Object::ToNumber(isolate, args.at(4)));
        hours = Object::NumberValue(*hours_object);
        if (argc >= 5) {
          Handle<Object> minutes_object;
          ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
              isolate, minutes_object, Object::ToNumber(isolate, args.at(5)));
          minutes = Object::NumberValue(*minutes_object);
          if (argc >= 6) {
            Handle<Object> seconds_object;
            ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
                isolate, seconds_object, Object::ToNumber(isolate, args.at(6)));
            seconds = Object::NumberValue(*seconds_object);
            if (argc >= 7) {
              Handle<Object> ms_object;
              ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
                  isolate, ms_object, Object::ToNumber(isolate, args.at(7)));
              ms = Object::NumberValue(*ms_object);
            }
          }
        }
      }
    }
    if (!std::isnan(year)) {
      double const y = DoubleToInteger(year);
      if (0.0 <= y && y <= 99) year = 1900 + y;
    }
    double const day = MakeDay(year, month, date);
    double const time = MakeTime(hours, minutes, seconds, ms);
    time_val = MakeDate(day, time);
    if (time_val >= -DateCache::kMaxTimeBeforeUTCInMs &&
        time_val <= DateCache::kMaxTimeBeforeUTCInMs) {
      time_val = isolate->date_cache()->ToUTC(static_cast<int64_t>(time_val));
    } else {
      time_val = std::numeric_limits<double>::quiet_NaN();
    }
  }
  RETURN_RESULT_OR_FAILURE(isolate, JSDate::New(target, new_target, time_val));
}

// ES6 section 20.3.3.1 Date.now ( )
BUILTIN(DateNow) {
  HandleScope scope(isolate);
  return *isolate->factory()->NewNumberFromInt64(
      JSDate::CurrentTimeValue(isolate));
}

// ES6 section 20.3.3.2 Date.parse ( string )
BUILTIN(DateParse) {
  HandleScope scope(isolate);
  Handle<String> string;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, string,
      Object::ToString(isolate, args.atOrUndefined(isolate, 1)));
  return *isolate->factory()->NewNumber(ParseDateTimeString(isolate, string));
}

// ES6 section 20.3.3.4 Date.UTC (year,month,date,hours,minutes,seconds,ms)
BUILTIN(DateUTC) {
  HandleScope scope(isolate);
  int const argc = args.length() - 1;
  double year = std::numeric_limits<double>::quiet_NaN();
  double month = 0.0, date = 1.0, hours = 0.0, minutes = 0.0, seconds = 0.0,
         ms = 0.0;
  if (argc >= 1) {
    Handle<Object> year_object;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, year_object,
                                       Object::ToNumber(isolate, args.at(1)));
    year = Object::NumberValue(*year_object);
    if (argc >= 2) {
      Handle<Object> month_object;
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, month_object,
                                         Object::ToNumber(isolate, args.at(2)));
      month = Object::NumberValue(*month_object);
      if (argc >= 3) {
        Handle<Object> date_object;
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
            isolate, date_object, Object::ToNumber(isolate, args.at(3)));
        date = Object::NumberValue(*date_object);
        if (argc >= 4) {
          Handle<Object> hours_object;
          ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
              isolate, hours_object, Object::ToNumber(isolate, args.at(4)));
          hours = Object::NumberValue(*hours_object);
          if (argc >= 5) {
            Handle<Object> minutes_object;
            ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
                isolate, minutes_object, Object::ToNumber(isolate, args.at(5)));
            minutes = Object::NumberValue(*minutes_object);
            if (argc >= 6) {
              Handle<Object> seconds_object;
              ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
                  isolate, seconds_object,
                  Object::ToNumber(isolate, args.at(6)));
              seconds = Object::NumberValue(*seconds_object);
              if (argc >= 7) {
                Handle<Object> ms_object;
                ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
                    isolate, ms_object, Object::ToNumber(isolate, args.at(7)));
                ms = Object::NumberValue(*ms_object);
              }
            }
          }
        }
      }
    }
  }
  if (!std::isnan(year)) {
    double const y = DoubleToInteger(year);
    if (0.0 <= y && y <= 99) year = 1900 + y;
  }
  double const day = MakeDay(year, month, date);
  double const time = MakeTime(hours, minutes, seconds, ms);
  double value = MakeDate(day, time);
  if (DateCache::TryTimeClip(&value)) {
    return *isolate->factory()->NewNumber(value);
  }
  return ReadOnlyRoots(isolate).nan_value();
}

// ES6 section 20.3.4.20 Date.prototype.setDate ( date )
BUILTIN(DatePrototypeSetDate) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.setDate");
  Handle<Object> value = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, value,
                                     Object::ToNumber(isolate, value));
  double time_val = date->value();
  if (!std::isnan(time_val)) {
    int64_t const time_ms = static_cast<int64_t>(time_val);
    int64_t local_time_ms = isolate->date_cache()->ToLocal(time_ms);
    int const days = isolate->date_cache()->DaysFromTime(local_time_ms);
    int time_within_day = isolate->date_cache()->TimeInDay(local_time_ms, days);
    int year, month, day;
    isolate->date_cache()->YearMonthDayFromDays(days, &year, &month, &day);
    time_val = MakeDate(MakeDay(year, month, Object::NumberValue(*value)),
                        time_within_day);
  }
  return SetLocalDateValue(isolate, date, time_val);
}

// ES6 section 20.3.4.21 Date.prototype.setFullYear (year, month, date)
BUILTIN(DatePrototypeSetFullYear) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.setFullYear");
  int const argc = args.length() - 1;
  Handle<Object> year = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, year,
                                     Object::ToNumber(isolate, year));
  double year_double = Object::NumberValue(*year), month_double = 0.0,
         day_double = 1.0;
  int time_within_day = 0;
  if (!std::isnan(date->value())) {
    int64_t const time_ms = static_cast<int64_t>(date->value());
    int64_t local_time_ms = isolate->date_cache()->ToLocal(time_ms);
    int const days = isolate->date_cache()->DaysFromTime(local_time_ms);
    time_within_day = isolate->date_cache()->TimeInDay(local_time_ms, days);
    int year_int, month_int, day_int;
    isolate->date_cache()->YearMonthDayFromDays(days, &year_int, &month_int,
                                                &day_int);
    month_double = month_int;
    day_double = day_int;
  }
  if (argc >= 2) {
    Handle<Object> month = args.at(2);
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, month,
                                       Object::ToNumber(isolate, month));
    month_double = Object::NumberValue(*month);
    if (argc >= 3) {
      Handle<Object> day = args.at(3);
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, day,
                                         Object::ToNumber(isolate, day));
      day_double = Object::NumberValue(*day);
    }
  }
  double time_val =
      MakeDate(MakeDay(year_double, month_double, day_double), time_within_day);
  return SetLocalDateValue(isolate, date, time_val);
}

// ES6 section 20.3.4.22 Date.prototype.setHours(hour, min, sec, ms)
BUILTIN(DatePrototypeSetHours) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.setHours");
  int const argc = args.length() - 1;
  Handle<Object> hour = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, hour,
                                     Object::ToNumber(isolate, hour));
  double h = Object::NumberValue(*hour);
  double time_val = date->value();
  if (!std::isnan(time_val)) {
    int64_t const time_ms = static_cast<int64_t>(time_val);
    int64_t local_time_ms = isolate->date_cache()->ToLocal(time_ms);
    int day = isolate->date_cache()->DaysFromTime(local_time_ms);
    int time_within_day = isolate->date_cache()->TimeInDay(local_time_ms, day);
    double m = (time_within_day / (60 * 1000)) % 60;
    double s = (time_within_day / 1000) % 60;
    double milli = time_within_day % 1000;
    if (argc >= 2) {
      Handle<Object> min = args.at(2);
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, min,
                                         Object::ToNumber(isolate, min));
      m = Object::NumberValue(*min);
      if (argc >= 3) {
        Handle<Object> sec = args.at(3);
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, sec,
                                           Object::ToNumber(isolate, sec));
        s = Object::NumberValue(*sec);
        if (argc >= 4) {
          Handle<Object> ms = args.at(4);
          ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, ms,
                                             Object::ToNumber(isolate, ms));
          milli = Object::NumberValue(*ms);
        }
      }
    }
    time_val = MakeDate(day, MakeTime(h, m, s, milli));
  }
  return SetLocalDateValue(isolate, date, time_val);
}

// ES6 section 20.3.4.23 Date.prototype.setMilliseconds(ms)
BUILTIN(DatePrototypeSetMilliseconds) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.setMilliseconds");
  Handle<Object> ms = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, ms,
                                     Object::ToNumber(isolate, ms));
  double time_val = date->value();
  if (!std::isnan(time_val)) {
    int64_t const time_ms = static_cast<int64_t>(time_val);
    int64_t local_time_ms = isolate->date_cache()->ToLocal(time_ms);
    int day = isolate->date_cache()->DaysFromTime(local_time_ms);
    int time_within_day = isolate->date_cache()->TimeInDay(local_time_ms, day);
    int h = time_within_day / (60 * 60 * 1000);
    int m = (time_within_day / (60 * 1000)) % 60;
    int s = (time_within_day / 1000) % 60;
    time_val = MakeDate(day, MakeTime(h, m, s, Object::NumberValue(*ms)));
  }
  return SetLocalDateValue(isolate, date, time_val);
}

// ES6 section 20.3.4.24 Date.prototype.setMinutes ( min, sec, ms )
BUILTIN(DatePrototypeSetMinutes) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.setMinutes");
  int const argc = args.length() - 1;
  Handle<Object> min = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, min,
                                     Object::ToNumber(isolate, min));
  double time_val = date->value();
  if (!std::isnan(time_val)) {
    int64_t const time_ms = static_cast<int64_t>(time_val);
    int64_t local_time_ms = isolate->date_cache()->ToLocal(time_ms);
    int day = isolate->date_cache()->DaysFromTime(local_time_ms);
    int time_within_day = isolate->date_cache()->TimeInDay(local_time_ms, day);
    int h = time_within_day / (60 * 60 * 1000);
    double m = Object::NumberValue(*min);
    double s = (time_within_day / 1000) % 60;
    double milli = time_within_day % 1000;
    if (argc >= 2) {
      Handle<Object> sec = args.at(2);
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, sec,
                                         Object::ToNumber(isolate, sec));
      s = Object::NumberValue(*sec);
      if (argc >= 3) {
        Handle<Object> ms = args.at(3);
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, ms,
                                           Object::ToNumber(isolate, ms));
        milli = Object::NumberValue(*ms);
      }
    }
    time_val = MakeDate(day, MakeTime(h, m, s, milli));
  }
  return SetLocalDateValue(isolate, date, time_val);
}

// ES6 section 20.3.4.25 Date.prototype.setMonth ( month, date )
BUILTIN(DatePrototypeSetMonth) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, this_date, "Date.prototype.setMonth");
  int const argc = args.length() - 1;
  Handle<Object> month = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, month,
                                     Object::ToNumber(isolate, month));
  double time_val = this_date->value();
  if (!std::isnan(time_val)) {
    int64_t const time_ms = static_cast<int64_t>(time_val);
    int64_t local_time_ms = isolate->date_cache()->ToLocal(time_ms);
    int days = isolate->date_cache()->DaysFromTime(local_time_ms);
    int time_within_day = isolate->date_cache()->TimeInDay(local_time_ms, days);
    int year, unused, day;
    isolate->date_cache()->YearMonthDayFromDays(days, &year, &unused, &day);
    double m = Object::NumberValue(*month);
    double dt = day;
    if (argc >= 2) {
      Handle<Object> date = args.at(2);
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, date,
                                         Object::ToNumber(isolate, date));
      dt = Object::NumberValue(*date);
    }
    time_val = MakeDate(MakeDay(year, m, dt), time_within_day);
  }
  return SetLocalDateValue(isolate, this_date, time_val);
}

// ES6 section 20.3.4.26 Date.prototype.setSeconds ( sec, ms )
BUILTIN(DatePrototypeSetSeconds) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.setSeconds");
  int const argc = args.length() - 1;
  Handle<Object> sec = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, sec,
                                     Object::ToNumber(isolate, sec));
  double time_val = date->value();
  if (!std::isnan(time_val)) {
    int64_t const time_ms = static_cast<int64_t>(time_val);
    int64_t local_time_ms = isolate->date_cache()->ToLocal(time_ms);
    int day = isolate->date_cache()->DaysFromTime(local_time_ms);
    int time_within_day = isolate->date_cache()->TimeInDay(local_time_ms, day);
    int h = time_within_day / (60 * 60 * 1000);
    double m = (time_within_day / (60 * 1000)) % 60;
    double s = Object::NumberValue(*sec);
    double milli = time_within_day % 1000;
    if (argc >= 2) {
      Handle<Object> ms = args.at(2);
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, ms,
                                         Object::ToNumber(isolate, ms));
      milli = Object::NumberValue(*ms);
    }
    time_val = MakeDate(day, MakeTime(h, m, s, milli));
  }
  return SetLocalDateValue(isolate, date, time_val);
}

// ES6 section 20.3.4.27 Date.prototype.setTime ( time )
BUILTIN(DatePrototypeSetTime) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.setTime");
  Handle<Object> value = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, value,
                                     Object::ToNumber(isolate, value));
  double value_double = Object::NumberValue(*value);

  // Don't use SetDateValue here, since we might already have a tagged value for
  // the time, and we don't want to reallocate it.
  double clipped_value = value_double;
  if (DateCache::TryTimeClip(&clipped_value)) {
    date->SetValue(clipped_value);
    // If the clipping didn't change the value (i.e. the value was already an
    // integer), we can reuse the incoming value for the return value.
    // Otherwise, we have to allocate a new value. Make sure to use
    // SameNumberValue so that -0 is _not_ treated as equal to the 0.
    if (Object::SameNumberValue(clipped_value, value_double)) {
      return *value;
    }
    return *isolate->factory()->NewNumber(clipped_value);
  }
  date->SetNanValue();
  return ReadOnlyRoots(isolate).nan_value();
}

// ES6 section 20.3.4.28 Date.prototype.setUTCDate ( date )
BUILTIN(DatePrototypeSetUTCDate) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.setUTCDate");
  Handle<Object> value = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, value,
                                     Object::ToNumber(isolate, value));
  if (std::isnan(date->value())) return ReadOnlyRoots(isolate).nan_value();
  int64_t const time_ms = static_cast<int64_t>(date->value());
  int const days = isolate->date_cache()->DaysFromTime(time_ms);
  int const time_within_day = isolate->date_cache()->TimeInDay(time_ms, days);
  int year, month, day;
  isolate->date_cache()->YearMonthDayFromDays(days, &year, &month, &day);
  double const time_val = MakeDate(
      MakeDay(year, month, Object::NumberValue(*value)), time_within_day);
  return SetDateValue(isolate, date, time_val);
}

// ES6 section 20.3.4.29 Date.prototype.setUTCFullYear (year, month, date)
BUILTIN(DatePrototypeSetUTCFullYear) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.setUTCFullYear");
  int const argc = args.length() - 1;
  Handle<Object> year = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, year,
                                     Object::ToNumber(isolate, year));
  double year_double = Object::NumberValue(*year), month_double = 0.0,
         day_double = 1.0;
  int time_within_day = 0;
  if (!std::isnan(date->value())) {
    int64_t const time_ms = static_cast<int64_t>(date->value());
    int const days = isolate->date_cache()->DaysFromTime(time_ms);
    time_within_day = isolate->date_cache()->TimeInDay(time_ms, days);
    int year_int, month_int, day_int;
    isolate->date_cache()->YearMonthDayFromDays(days, &year_int, &month_int,
                                                &day_int);
    month_double = month_int;
    day_double = day_int;
  }
  if (argc >= 2) {
    Handle<Object> month = args.at(2);
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, month,
                                       Object::ToNumber(isolate, month));
    month_double = Object::NumberValue(*month);
    if (argc >= 3) {
      Handle<Object> day = args.at(3);
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, day,
                                         Object::ToNumber(isolate, day));
      day_double = Object::NumberValue(*day);
    }
  }
  double const time_val =
      MakeDate(MakeDay(year_double, month_double, day_double), time_within_day);
  return SetDateValue(isolate, date, time_val);
}

// ES6 section 20.3.4.30 Date.prototype.setUTCHours(hour, min, sec, ms)
BUILTIN(DatePrototypeSetUTCHours) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.setUTCHours");
  int const argc = args.length() - 1;
  Handle<Object> hour = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, hour,
                                     Object::ToNumber(isolate, hour));
  double h = Object::NumberValue(*hour);
  double time_val = date->value();
  if (!std::isnan(time_val)) {
    int64_t const time_ms = static_cast<int64_t>(time_val);
    int day = isolate->date_cache()->DaysFromTime(time_ms);
    int time_within_day = isolate->date_cache()->TimeInDay(time_ms, day);
    double m = (time_within_day / (60 * 1000)) % 60;
    double s = (time_within_day / 1000) % 60;
    double milli = time_within_day % 1000;
    if (argc >= 2) {
      Handle<Object> min = args.at(2);
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, min,
                                         Object::ToNumber(isolate, min));
      m = Object::NumberValue(*min);
      if (argc >= 3) {
        Handle<Object> sec = args.at(3);
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, sec,
                                           Object::ToNumber(isolate, sec));
        s = Object::NumberValue(*sec);
        if (argc >= 4) {
          Handle<Object> ms = args.at(4);
          ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, ms,
                                             Object::ToNumber(isolate, ms));
          milli = Object::NumberValue(*ms);
        }
      }
    }
    time_val = MakeDate(day, MakeTime(h, m, s, milli));
  }
  return SetDateValue(isolate, date, time_val);
}

// ES6 section 20.3.4.31 Date.prototype.setUTCMilliseconds(ms)
BUILTIN(DatePrototypeSetUTCMilliseconds) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.setUTCMilliseconds");
  Handle<Object> ms = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, ms,
                                     Object::ToNumber(isolate, ms));
  double time_val = date->value();
  if (!std::isnan(time_val)) {
    int64_t const time_ms = static_cast<int64_t>(time_val);
    int day = isolate->date_cache()->DaysFromTime(time_ms);
    int time_within_day = isolate->date_cache()->TimeInDay(time_ms, day);
    int h = time_within_day / (60 * 60 * 1000);
    int m = (time_within_day / (60 * 1000)) % 60;
    int s = (time_within_day / 1000) % 60;
    time_val = MakeDate(day, MakeTime(h, m, s, Object::NumberValue(*ms)));
  }
  return SetDateValue(isolate, date, time_val);
}

// ES6 section 20.3.4.32 Date.prototype.setUTCMinutes ( min, sec, ms )
BUILTIN(DatePrototypeSetUTCMinutes) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.setUTCMinutes");
  int const argc = args.length() - 1;
  Handle<Object> min = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, min,
                                     Object::ToNumber(isolate, min));
  double time_val = date->value();
  if (!std::isnan(time_val)) {
    int64_t const time_ms = static_cast<int64_t>(time_val);
    int day = isolate->date_cache()->DaysFromTime(time_ms);
    int time_within_day = isolate->date_cache()->TimeInDay(time_ms, day);
    int h = time_within_day / (60 * 60 * 1000);
    double m = Object::NumberValue(*min);
    double s = (time_within_day / 1000) % 60;
    double milli = time_within_day % 1000;
    if (argc >= 2) {
      Handle<Object> sec = args.at(2);
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, sec,
                                         Object::ToNumber(isolate, sec));
      s = Object::NumberValue(*sec);
      if (argc >= 3) {
        Handle<Object> ms = args.at(3);
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, ms,
                                           Object::ToNumber(isolate, ms));
        milli = Object::NumberValue(*ms);
      }
    }
    time_val = MakeDate(day, MakeTime(h, m, s, milli));
  }
  return SetDateValue(isolate, date, time_val);
}

// ES6 section 20.3.4.31 Date.prototype.setUTCMonth ( month, date )
BUILTIN(DatePrototypeSetUTCMonth) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, this_date, "Date.prototype.setUTCMonth");
  int const argc = args.length() - 1;
  Handle<Object> month = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, month,
                                     Object::ToNumber(isolate, month));
  double time_val = this_date->value();
  if (!std::isnan(time_val)) {
    int64_t const time_ms = static_cast<int64_t>(time_val);
    int days = isolate->date_cache()->DaysFromTime(time_ms);
    int time_within_day = isolate->date_cache()->TimeInDay(time_ms, days);
    int year, unused, day;
    isolate->date_cache()->YearMonthDayFromDays(days, &year, &unused, &day);
    double m = Object::NumberValue(*month);
    double dt = day;
    if (argc >= 2) {
      Handle<Object> date = args.at(2);
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, date,
                                         Object::ToNumber(isolate, date));
      dt = Object::NumberValue(*date);
    }
    time_val = MakeDate(MakeDay(year, m, dt), time_within_day);
  }
  return SetDateValue(isolate, this_date, time_val);
}

// ES6 section 20.3.4.34 Date.prototype.setUTCSeconds ( sec, ms )
BUILTIN(DatePrototypeSetUTCSeconds) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.setUTCSeconds");
  int const argc = args.length() - 1;
  Handle<Object> sec = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, sec,
                                     Object::ToNumber(isolate, sec));
  double time_val = date->value();
  if (!std::isnan(time_val)) {
    int64_t const time_ms = static_cast<int64_t>(time_val);
    int day = isolate->date_cache()->DaysFromTime(time_ms);
    int time_within_day = isolate->date_cache()->TimeInDay(time_ms, day);
    int h = time_within_day / (60 * 60 * 1000);
    double m = (time_within_day / (60 * 1000)) % 60;
    double s = Object::NumberValue(*sec);
    double milli = time_within_day % 1000;
    if (argc >= 2) {
      Handle<Object> ms = args.at(2);
      ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, ms,
                                         Object::ToNumber(isolate, ms));
      milli = Object::NumberValue(*ms);
    }
    time_val = MakeDate(day, MakeTime(h, m, s, milli));
  }
  return SetDateValue(isolate, date, time_val);
}

// ES6 section 20.3.4.35 Date.prototype.toDateString ( )
BUILTIN(DatePrototypeToDateString) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.toDateString");
  DateBuffer buffer = ToDateString(date->value(), isolate->date_cache(),
                                   ToDateStringMode::kLocalDate);
  RETURN_RESULT_OR_FAILURE(
      isolate, isolate->factory()->NewStringFromUtf8(base::VectorOf(buffer)));
}

// ES6 section 20.3.4.36 Date.prototype.toISOString ( )
BUILTIN(DatePrototypeToISOString) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.toISOString");
  double const time_val = date->value();
  if (std::isnan(time_val)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewRangeError(MessageTemplate::kInvalidTimeValue));
  }
  DateBuffer buffer = ToDateString(time_val, isolate->date_cache(),
                                   ToDateStringMode::kISODateAndTime);
  RETURN_RESULT_OR_FAILURE(
      isolate, isolate->factory()->NewStringFromUtf8(base::VectorOf(buffer)));
}

// ES6 section 20.3.4.41 Date.prototype.toString ( )
BUILTIN(DatePrototypeToString) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.toString");
  DateBuffer buffer = ToDateString(date->value(), isolate->date_cache(),
                                   ToDateStringMode::kLocalDateAndTime);
  RETURN_RESULT_OR_FAILURE(
      isolate, isolate->factory()->NewStringFromUtf8(base::VectorOf(buffer)));
}

// ES6 section 20.3.4.42 Date.prototype.toTimeString ( )
BUILTIN(DatePrototypeToTimeString) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.toTimeString");
  DateBuffer buffer = ToDateString(date->value(), isolate->date_cache(),
                                   ToDateStringMode::kLocalTime);
  RETURN_RESULT_OR_FAILURE(
      isolate, isolate->factory()->NewStringFromUtf8(base::VectorOf(buffer)));
}

#ifdef V8_INTL_SUPPORT
// ecma402 #sup-date.prototype.tolocaledatestring
BUILTIN(DatePrototypeToLocaleDateString) {
  HandleScope scope(isolate);

  isolate->CountUsage(v8::Isolate::UseCounterFeature::kDateToLocaleDateString);

  const char* method_name = "Date.prototype.toLocaleDateString";
  CHECK_RECEIVER(JSDate, date, method_name);

  RETURN_RESULT_OR_FAILURE(
      isolate, JSDateTimeFormat::ToLocaleDateTime(
                   isolate,
                   date,                                     // date
                   args.atOrUndefined(isolate, 1),           // locales
                   args.atOrUndefined(isolate, 2),           // options
                   JSDateTimeFormat::RequiredOption::kDate,  // required
                   JSDateTimeFormat::DefaultsOption::kDate,  // defaults
                   method_name));                            // method_name
}

// ecma402 #sup-date.prototype.tolocalestring
BUILTIN(DatePrototypeToLocaleString) {
  HandleScope scope(isolate);

  isolate->CountUsage(v8::Isolate::UseCounterFeature::kDateToLocaleString);

  const char* method_name = "Date.prototype.toLocaleString";
  CHECK_RECEIVER(JSDate, date, method_name);

  RETURN_RESULT_OR_FAILURE(
      isolate, JSDateTimeFormat::ToLocaleDateTime(
                   isolate,
                   date,                                    // date
                   args.atOrUndefined(isolate, 1),          // locales
                   args.atOrUndefined(isolate, 2),          // options
                   JSDateTimeFormat::RequiredOption::kAny,  // required
                   JSDateTimeFormat::DefaultsOption::kAll,  // defaults
                   method_name));                           // method_name
}

// ecma402 #sup-date.prototype.tolocaletimestring
BUILTIN(DatePrototypeToLocaleTimeString) {
  HandleScope scope(isolate);

  isolate->CountUsage(v8::Isolate::UseCounterFeature::kDateToLocaleTimeString);

  const char* method_name = "Date.prototype.toLocaleTimeString";
  CHECK_RECEIVER(JSDate, date, method_name);

  RETURN_RESULT_OR_FAILURE(
      isolate, JSDateTimeFormat::ToLocaleDateTime(
                   isolate,
                   date,                                     // date
                   args.atOrUndefined(isolate, 1),           // locales
                   args.atOrUndefined(isolate, 2),           // options
                   JSDateTimeFormat::RequiredOption::kTime,  // required
                   JSDateTimeFormat::DefaultsOption::kTime,  // defaults
                   method_name));                            // method_name
}
#endif  // V8_INTL_SUPPORT

// ES6 section 20.3.4.43 Date.prototype.toUTCString ( )
BUILTIN(DatePrototypeToUTCString) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.toUTCString");
  DateBuffer buffer = ToDateString(date->value(), isolate->date_cache(),
                                   ToDateStringMode::kUTCDateAndTime);
  RETURN_RESULT_OR_FAILURE(
      isolate, isolate->factory()->NewStringFromUtf8(base::VectorOf(buffer)));
}

// ES6 section B.2.4.1 Date.prototype.getYear ( )
BUILTIN(DatePrototypeGetYear) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.getYear");
  double time_val = date->value();
  if (std::isnan(time_val)) return ReadOnlyRoots(isolate).nan_value();
  int64_t time_ms = static_cast<int64_t>(time_val);
  int64_t local_time_ms = isolate->date_cache()->ToLocal(time_ms);
  int days = isolate->date_cache()->DaysFromTime(local_time_ms);
  int year, month, day;
  isolate->date_cache()->YearMonthDayFromDays(days, &year, &month, &day);
  return Smi::FromInt(year - 1900);
}

// ES6 section B.2.4.2 Date.prototype.setYear ( year )
BUILTIN(DatePrototypeSetYear) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.setYear");
  Handle<Object> year = args.atOrUndefined(isolate, 1);
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, year,
                                     Object::ToNumber(isolate, year));
  double month_double = 0.0, day_double = 1.0,
         year_double = Object::NumberValue(*year);
  if (!std::isnan(year_double)) {
    double year_int = DoubleToInteger(year_double);
    if (0.0 <= year_int && year_int <= 99.0) {
      year_double = 1900.0 + year_int;
    }
  }
  int time_within_day = 0;
  if (!std::isnan(date->value())) {
    int64_t const time_ms = static_cast<int64_t>(date->value());
    int64_t local_time_ms = isolate->date_cache()->ToLocal(time_ms);
    int const days = isolate->date_cache()->DaysFromTime(local_time_ms);
    time_within_day = isolate->date_cache()->TimeInDay(local_time_ms, days);
    int year_int, month_int, day_int;
    isolate->date_cache()->YearMonthDayFromDays(days, &year_int, &month_int,
                                                &day_int);
    month_double = month_int;
    day_double = day_int;
  }
  double time_val =
      MakeDate(MakeDay(year_double, month_double, day_double), time_within_day);
  return SetLocalDateValue(isolate, date, time_val);
}

// ES6 section 20.3.4.37 Date.prototype.toJSON ( key )
BUILTIN(DatePrototypeToJson) {
  HandleScope scope(isolate);
  Handle<Object> receiver = args.atOrUndefined(isolate, 0);
  Handle<JSReceiver> receiver_obj;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver_obj,
                                     Object::ToObject(isolate, receiver));
  Handle<Object> primitive;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, primitive,
      Object::ToPrimitive(isolate, receiver_obj, ToPrimitiveHint::kNumber));
  if (IsNumber(*primitive) && !std::isfinite(Object::NumberValue(*primitive))) {
    return ReadOnlyRoots(isolate).null_value();
  } else {
    Handle<String> name =
        isolate->factory()->NewStringFromAsciiChecked("toISOString");
    Handle<Object> function;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, function, Object::GetProperty(isolate, receiver_obj, name));
    if (!IsCallable(*function)) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate, NewTypeError(MessageTemplate::kCalledNonCallable, name));
    }
    RETURN_RESULT_OR_FAILURE(
        isolate, Execution::Call(isolate, function, receiver_obj, 0, nullptr));
  }
}

// Temporal #sec-date.prototype.totemporalinstant
BUILTIN(DatePrototypeToTemporalInstant) {
  HandleScope scope(isolate);
  CHECK_RECEIVER(JSDate, date, "Date.prototype.toTemporalInstant");
  // 1. Let t be ? thisTimeValue(this value).
  Handle<BigInt> t;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, t,
      BigInt::FromNumber(isolate,
                         isolate->factory()->NewNumber(date->value())));
  // 2. Let ns be ? NumberToBigInt(t) × 10^6.
  Handle<BigInt> ns;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
      isolate, ns,
      BigInt::Multiply(isolate, t, BigInt::FromInt64(isolate, 1000000)));
  // 3. Return ! CreateTemporalInstant(ns).
  return *temporal::CreateTemporalInstant(isolate, ns).ToHandleChecked();
}

}  // namespace internal
}  // namespace v8
```