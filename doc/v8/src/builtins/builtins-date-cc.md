Response:
Let's break down the thought process for analyzing the given C++ code snippet and generating the summary.

**1. Initial Scan and Keyword Recognition:**

My first step is to quickly scan the code for recognizable keywords and patterns. I see:

* `// Copyright`:  Indicates standard copyright information, not functional.
* `#include`: Lists header files. These hint at the dependencies and areas the code interacts with (e.g., `builtins-utils-inl.h`, `date/date.h`, `objects/js-date.h`). The presence of `#ifdef V8_INTL_SUPPORT` suggests internationalization features are involved.
* `namespace v8 { namespace internal {`:  Clearly defines the scope of the code within the V8 engine.
* `BUILTIN(FunctionName)`: This is a very strong indicator of built-in JavaScript functions. I immediately start noting these down (e.g., `DateConstructor`, `DateNow`, `DateParse`, `DateUTC`, `DatePrototypeSetDate`, etc.). The naming convention strongly suggests their corresponding JavaScript `Date` methods.
* `HandleScope scope(isolate);`:  A standard V8 construct for managing memory. Important for V8 internals but less so for high-level functionality.
* `CHECK_RECEIVER(JSDate, date, "...")`:  Confirms that the built-in is operating on a `Date` object.
* `Object::ToNumber`, `Object::ToString`, `Object::ToPrimitive`:  Indicates type conversions happening, which is common in JavaScript built-ins when dealing with user input.
* `JSDate::CurrentTimeValue(isolate)`:  Obvious function to get the current time.
* `ParseDateTimeString(isolate, ...)`:  Indicates handling of date string parsing.
* `MakeDay`, `MakeTime`, `MakeDate`:  Suggests internal helper functions for constructing date/time values.
* `isolate->date_cache()`: Points to internal caching of date information for performance.
* `SetLocalDateValue`, `SetDateValue`:  Internal functions for setting the time value of a `Date` object. The "Local" prefix hints at timezone considerations.
* `ToDateString(...)`:  Indicates functions for formatting dates into strings.
* `THROW_NEW_ERROR_RETURN_FAILURE`: Standard V8 way to throw JavaScript errors.
* `#ifdef V8_INTL_SUPPORT`:  Again, highlights internationalization. Functions like `DatePrototypeToLocaleDateString` confirm this.

**2. Grouping by Functionality (Based on `BUILTIN` Macros):**

As I identify the `BUILTIN` functions, I start grouping them conceptually. The names themselves provide a strong clue:

* **Constructor and Static Methods:**  `DateConstructor`, `DateNow`, `DateParse`, `DateUTC`. These seem to be related to creating `Date` objects and providing utility functions on the `Date` object itself.
* **Prototype Setters:** `DatePrototypeSetDate`, `DatePrototypeSetFullYear`, `DatePrototypeSetHours`, etc. These clearly correspond to the `setDate()`, `setFullYear()`, `setHours()`, etc., methods on `Date.prototype`. I notice both "local" and "UTC" versions.
* **Prototype Getters (Implicit):** While not explicitly `Get...`, methods like `DatePrototypeToDateString`, `DatePrototypeToISOString`, `DatePrototypeToString`, etc., are clearly involved in getting string representations of dates. Again, local and potentially UTC variations are present.
* **Internationalization:** The `#ifdef V8_INTL_SUPPORT` block contains `DatePrototypeToLocaleDateString`, `DatePrototypeToLocaleString`, and `DatePrototypeToLocaleTimeString`. These are clearly for locale-specific formatting.

**3. Inferring Functionality from Code Logic (For Key Examples):**

For some of the more complex built-ins, I briefly examine the internal logic:

* **`DateConstructor`:**  I see different code paths depending on the number of arguments. Zero arguments get the current time, one argument tries to parse it as a date or number, and multiple arguments are treated as year, month, day, etc.
* **`DateParse`:**  Directly calls `ParseDateTimeString`, indicating its purpose.
* **`DateUTC`:** Similar to `DateConstructor` with multiple arguments, but without local time adjustments (hence "UTC").
* **`DatePrototypeSet...` functions:** They generally:
    1. Get the current time value.
    2. Extract the relevant date/time components.
    3. Update the specific component based on the arguments.
    4. Use `MakeDay`, `MakeTime`, `MakeDate` to construct a new time value.
    5. Call `SetLocalDateValue` or `SetDateValue` to update the internal `Date` object. The local vs. UTC distinction is evident here.

**4. Connecting to JavaScript:**

Based on the `BUILTIN` names and observed logic, it's straightforward to connect them to corresponding JavaScript `Date` methods. For example:

* `DateConstructor` -> `new Date()`
* `DateNow` -> `Date.now()`
* `DateParse` -> `Date.parse()`
* `DateUTC` -> `Date.UTC()`
* `DatePrototypeSetDate` -> `dateObject.setDate()`
* `DatePrototypeToISOString` -> `dateObject.toISOString()`

**5. Identifying Potential Errors:**

I consider common mistakes developers make with dates in JavaScript:

* **Incorrect argument types:** Passing strings to methods expecting numbers, or vice-versa.
* **Incorrect number of arguments:**  Not providing enough arguments for the constructor or setter methods.
* **Misunderstanding local vs. UTC:** Using the wrong methods when timezone awareness is important.
* **Parsing issues:** Providing date strings in formats that `Date.parse()` doesn't understand.
* **Range errors:** Providing invalid values for month, day, etc. (though the C++ code handles this gracefully by returning NaN).

**6. Structuring the Summary:**

Finally, I organize my findings into a coherent summary, addressing each point in the prompt:

* **Functionality Listing:**  Categorize the built-in functions based on their purpose (constructor, static methods, prototype setters, getters, internationalization).
* **Torque Source:**  Address the `.tq` question.
* **JavaScript Examples:** Provide clear JavaScript code snippets demonstrating the use of the corresponding built-in functions.
* **Logic Reasoning (Simplified):**  Give a high-level explanation of the internal logic, focusing on input, processing, and output, without getting bogged down in the C++ details. Use simple examples for illustration.
* **Common Errors:** List common JavaScript date-related errors, relating them back to the functionality of the C++ code.
* **Overall Summary:**  Provide a concise high-level summary of the file's purpose.

**Self-Correction/Refinement during the process:**

* Initially, I might just list all the `BUILTIN` functions without grouping. Then, realizing the redundancy, I would group them by their related JavaScript concepts (constructor, prototype methods, etc.).
* I might initially focus too much on the low-level C++ details. I need to remind myself the prompt is asking for the *functionality* from a JavaScript perspective.
* I ensure the JavaScript examples are accurate and easy to understand.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive and informative summary that addresses all aspects of the prompt.
好的，我们来归纳一下 `v8/src/builtins/builtins-date.cc` 的功能。

**文件功能归纳：**

`v8/src/builtins/builtins-date.cc` 文件是 V8 JavaScript 引擎中处理 `Date` 对象相关内置函数的 C++ 源代码文件。 它实现了 ECMAScript 规范中定义的 `Date` 构造函数及其原型方法，以及 `Date` 对象的静态方法。

**具体功能列举：**

1. **`Date` 构造函数 (`DateConstructor`)**:
   - 当 `Date()` 作为函数调用（非构造函数）时，返回表示当前日期和时间的字符串。
   - 当 `Date()` 作为构造函数 (`new Date()`) 调用时，创建并返回一个新的 `Date` 对象。
   - 能够处理不同数量和类型的参数来初始化 `Date` 对象，包括：
     - 无参数：创建表示当前日期和时间的对象。
     - 单个数字参数：表示自 Unix 纪元以来的毫秒数。
     - 单个字符串参数：尝试解析该字符串为日期和时间。
     - 多个数字参数：分别表示年、月、日、小时、分钟、秒、毫秒。

2. **静态方法：**
   - **`Date.now()` (`DateNow`)**: 返回自 Unix 纪元以来的当前毫秒数。
   - **`Date.parse()` (`DateParse`)**: 解析一个表示日期和时间的字符串，并返回自 Unix 纪元以来的毫秒数。
   - **`Date.UTC()` (`DateUTC`)**: 接受年、月、日等参数，并返回对应的 UTC 时间的自 Unix 纪元以来的毫秒数。

3. **原型方法（`Date.prototype` 上的方法）：**
   - **`setDate()` (`DatePrototypeSetDate`)**: 设置 `Date` 对象的本地日期。
   - **`setFullYear()` (`DatePrototypeSetFullYear`)**: 设置 `Date` 对象的本地年份、月份和日期。
   - **`setHours()` (`DatePrototypeSetHours`)**: 设置 `Date` 对象的本地小时、分钟、秒和毫秒。
   - **`setMilliseconds()` (`DatePrototypeSetMilliseconds`)**: 设置 `Date` 对象的本地毫秒。
   - **`setMinutes()` (`DatePrototypeSetMinutes`)**: 设置 `Date` 对象的本地分钟、秒和毫秒。
   - **`setMonth()` (`DatePrototypeSetMonth`)**: 设置 `Date` 对象的本地月份和日期。
   - **`setSeconds()` (`DatePrototypeSetSeconds`)**: 设置 `Date` 对象的本地秒和毫秒。
   - **`setTime()` (`DatePrototypeSetTime`)**: 设置 `Date` 对象为自 Unix 纪元以来的毫秒数。
   - **`setUTCDate()` (`DatePrototypeSetUTCDate`)**: 设置 `Date` 对象的 UTC 日期。
   - **`setUTCFullYear()` (`DatePrototypeSetUTCFullYear`)**: 设置 `Date` 对象的 UTC 年份、月份和日期。
   - **`setUTCHours()` (`DatePrototypeSetUTCHours`)**: 设置 `Date` 对象的 UTC 小时、分钟、秒和毫秒。
   - **`setUTCMilliseconds()` (`DatePrototypeSetUTCMilliseconds`)**: 设置 `Date` 对象的 UTC 毫秒。
   - **`setUTCMinutes()` (`DatePrototypeSetUTCMinutes`)**: 设置 `Date` 对象的 UTC 分钟、秒和毫秒。
   - **`setUTCMonth()` (`DatePrototypeSetUTCMonth`)**: 设置 `Date` 对象的 UTC 月份和日期。
   - **`setUTCSeconds()` (`DatePrototypeSetUTCSeconds`)**: 设置 `Date` 对象的 UTC 秒和毫秒。
   - **`toDateString()` (`DatePrototypeToDateString`)**: 返回 `Date` 对象日期部分的字符串表示形式。
   - **`toISOString()` (`DatePrototypeToISOString`)**: 返回 `Date` 对象的 ISO 格式字符串表示形式。
   - **`toString()` (`DatePrototypeToString`)**: 返回 `Date` 对象的字符串表示形式。
   - **`toTimeString()` (`DatePrototypeToTimeString`)**: 返回 `Date` 对象时间部分的字符串表示形式。
   - **`toLocaleString()` (`DatePrototypeToLocaleString`)**: 返回 `Date` 对象的本地化字符串表示形式 (如果 `V8_INTL_SUPPORT` 启用)。
   - **`toLocaleDateString()` (`DatePrototypeToLocaleDateString`)**: 返回 `Date` 对象日期部分的本地化字符串表示形式 (如果 `V8_INTL_SUPPORT` 启用)。
   - **`toLocaleTimeString()` (`DatePrototypeToLocaleTimeString`)**: 返回 `Date` 对象时间部分的本地化字符串表示形式 (如果 `V8_INTL_SUPPORT` 启用)。

**关于文件扩展名 `.tq`：**

如果 `v8/src/builtins/builtins-date.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。 Torque 是 V8 用来定义内置函数的领域特定语言，它能够生成高效的 C++ 代码。  当前的文件名是 `.cc`，表明它是直接用 C++ 编写的。

**与 JavaScript 功能的关系和示例：**

这个 C++ 文件中的代码直接实现了 JavaScript 中 `Date` 对象的各种功能。  以下是一些 JavaScript 示例，对应于文件中的内置函数：

```javascript
// Date 构造函数
const now = new Date();
const specificDate = new Date(2023, 10, 20, 10, 30, 0); // 月份从 0 开始 (10 表示 11 月)
const fromTimestamp = new Date(1679404800000);
const parsedDate = new Date("2023-11-20T10:30:00Z");

// 静态方法
const timestamp = Date.now();
const parsedTimestamp = Date.parse("October 13, 1975 11:13:00");
const utcTimestamp = Date.UTC(2023, 10, 20, 10, 30, 0);

// 原型方法
const date = new Date();
date.setDate(15);
date.setFullYear(2024, 0, 1); // 设置为 2024 年 1 月 1 日
date.setHours(14, 0, 0, 0);
const dateString = date.toDateString();
const isoString = date.toISOString();
const localString = date.toLocaleString();
```

**代码逻辑推理和示例：**

假设我们调用 `date.setDate(5)`，其中 `date` 对象表示 `2023-11-20T10:00:00`。

**假设输入：**

- `date` 对象的内部时间值（表示 `2023-11-20T10:00:00` 的时间戳）
- `setDate` 方法的参数：`5`

**代码逻辑推理（简化）：**

1. `DatePrototypeSetDate` 函数被调用，接收 `date` 对象和参数 `5`。
2. 获取 `date` 对象的当前时间值。
3. 将当前时间值转换为本地时间。
4. 提取当前的年、月、日等信息。
5. 使用新的日期值 `5` 重新计算时间戳，但保留原有的时、分、秒等信息。
6. 将新的本地时间戳转换回 UTC 时间戳。
7. 使用新的 UTC 时间戳更新 `date` 对象。

**预期输出：**

`date` 对象的内部时间值将被更新，使其表示 `2023-11-05T10:00:00` 的时间。

**用户常见的编程错误和示例：**

1. **月份从 0 开始：**  在 `Date` 构造函数中，月份是从 0 开始计数的（0 表示一月，11 表示十二月）。这是一个常见的混淆点。

   ```javascript
   // 错误：期望创建 12 月的日期，但实际上创建的是 11 月的日期
   const wrongMonth = new Date(2023, 12, 25);
   console.log(wrongMonth.getMonth()); // 输出 0 (因为 12 会溢出到下一年的一月)

   // 正确：创建 12 月的日期
   const correctMonth = new Date(2023, 11, 25);
   console.log(correctMonth.getMonth()); // 输出 11
   ```

2. **误解本地时间和 UTC 时间：**  混淆使用本地时间方法（如 `setDate`）和 UTC 时间方法（如 `setUTCDate`），导致在处理跨时区问题时出现错误。

   ```javascript
   const date = new Date();
   console.log("本地日期:", date.getDate());
   console.log("UTC 日期:", date.getUTCDate());

   // 错误：期望设置 UTC 日期，但实际上设置的是本地日期
   date.setDate(10);
   console.log("本地日期 (设置后):", date.getDate());
   console.log("UTC 日期 (设置后):", date.getUTCDate()); // UTC 日期可能没有改变

   // 正确：设置 UTC 日期
   date.setUTCDate(10);
   console.log("本地日期 (再次设置后):", date.getDate()); // 本地日期可能会改变
   console.log("UTC 日期 (再次设置后):", date.getUTCDate());
   ```

3. **不正确的日期字符串格式：** `Date.parse()` 和 `new Date(string)` 对日期字符串的格式有要求，不符合要求的字符串可能导致解析错误或得到 `Invalid Date`。

   ```javascript
   // 错误：日期字符串格式不被标准支持
   const invalidDate = new Date("2023/11/20");
   console.log(invalidDate.toString()); // 输出 "Invalid Date"

   // 推荐使用 ISO 格式
   const validDate = new Date("2023-11-20T10:00:00Z");
   console.log(validDate.toISOString());
   ```

**总结：**

总而言之，`v8/src/builtins/builtins-date.cc` 是 V8 引擎中至关重要的一个文件，它实现了 JavaScript `Date` 对象的全部核心功能，包括构造、静态方法和原型方法，使得 JavaScript 开发者能够方便地进行日期和时间的操作。理解这个文件的功能有助于深入了解 JavaScript 日期对象的工作原理。

Prompt: 
```
这是目录为v8/src/builtins/builtins-date.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-date.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
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
                   JSDateTimeFormat::RequiredOption::kTime,  /
"""


```