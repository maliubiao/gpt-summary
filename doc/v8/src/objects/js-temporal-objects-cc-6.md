Response:
My thinking process to analyze the provided V8 source code snippet goes like this:

1. **Understand the Context:** The header comment and the filename `v8/src/objects/js-temporal-objects.cc` immediately tell me this code is part of the V8 JavaScript engine and deals with the implementation of the Temporal API. The "objects" directory suggests this code defines or manipulates JavaScript objects related to Temporal.

2. **Initial Scan for Keywords and Patterns:** I quickly scan the code for recognizable keywords and patterns:
    * `#include`:  Indicates dependencies on other V8 components.
    * `Handle<...>`, `Maybe<...>`, `MaybeHandle<...>`: These are common V8 types for managing garbage-collected objects and potential failures.
    * `Isolate*`:  A pointer to the current V8 isolate, essential for many V8 operations.
    * `factory()->`: Accessing the V8 object factory for creating new objects.
    * `String`, `Number`, `JSReceiver`, `BigInt`:  Represent JavaScript types.
    * `TimeRecord`, `DateRecord`, `DateTimeRecord`, `DurationRecord`, `TimeDurationRecord`: Custom structs likely representing Temporal-specific data structures.
    * `Unit`: An enum representing time units (year, month, day, etc.).
    * `ToIntegerThrowOnInfinity`, `GetStringOption`: Utility functions for handling JavaScript value conversions.
    * `BalanceDuration`, `AddDateTime`, `CreateISODateRecord`: Functions implementing core Temporal logic.
    * `THROW_NEW_ERROR`:  Indicates potential error handling.
    * Comments like `#sec-temporal-...`: These are direct references to sections in the ECMAScript Temporal specification, which is extremely helpful for understanding the code's purpose.

3. **Focus on Key Functions:** I identify functions that seem central to the file's purpose:
    * `CanonicalizeTimeZoneName`:  Likely related to standardizing timezone names (though the current implementation just returns "UTC").
    * `ToTemporalTimeRecordOrPartialTime`, `ToPartialTime`, `ToTemporalTimeRecord`: These functions seem to convert JavaScript objects into internal `TimeRecord` structures, potentially handling partial input.
    * `GetTemporalUnit`:  This looks like it's responsible for parsing and validating time unit options from JavaScript objects.
    * `MergeLargestUnitOption`:  Seems to be about merging options related to the largest time unit.
    * `BalanceDuration`, `BalancePossiblyInfiniteDuration`:  Crucial for normalizing and balancing duration values across different units.
    * `AddDateTime`:  Implements the logic for adding durations to date/time values.

4. **Analyze Function Logic Based on Comments and Names:** I read the comments and function names carefully. The `#sec-temporal-` comments directly link the V8 code to the specification, making it easier to understand what each function is supposed to do. For example, the comments in `ToTemporalTimeRecordOrPartialTime` clearly outline the steps for extracting time components from a JavaScript object.

5. **Infer Data Structures and Relationships:** Based on the function signatures and the types being used (e.g., `TimeRecord`, `DateRecord`), I start to infer the structure of the data being manipulated. I notice the separation between date and time components in some records.

6. **Consider the "Torque" Clue:** The prompt mentions the `.tq` extension for Torque. Since this file is `.cc`, it's standard C++ code, not Torque. Torque is V8's internal language for generating optimized code, often for type-sensitive operations. This tells me this file likely deals with higher-level logic and object manipulation before potential optimization with Torque.

7. **Connect to JavaScript Functionality:** I think about how the C++ code relates to the JavaScript Temporal API. Functions like `ToTemporalTimeRecord` are clearly involved in taking JavaScript `Temporal.PlainTime`-like objects and converting them into a format V8 can work with internally. `GetTemporalUnit` handles options parsing, which is a common pattern in JavaScript APIs. `AddDateTime` implements core arithmetic operations on Temporal objects.

8. **Identify Potential Error Scenarios:** The presence of `THROW_NEW_ERROR` and specific error types like `NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR` and `NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR` points to common error conditions, such as providing invalid input types or out-of-range values.

9. **Synthesize and Summarize:**  Finally, I put all the pieces together to summarize the file's functionality. I focus on the core responsibilities: handling Temporal object creation, conversion, option parsing, and fundamental arithmetic operations like adding durations. I also note the absence of Torque and the connection to the JavaScript API.

**Self-Correction/Refinement During the Process:**

* **Initial Misinterpretation:** I might initially think `CanonicalizeTimeZoneName` does more complex timezone canonicalization. However, seeing it simply return "UTC" forces me to adjust my understanding – in this specific snippet, it's a placeholder or a very basic implementation.

* **Understanding `ToTemporalTimeRecordOrPartialTime`:**  The "partial time" aspect requires careful reading of the comments to understand how it handles missing or undefined time components.

* **The Role of `Unit` Enum:** Recognizing the `Unit` enum is crucial for understanding the logic in functions like `GetTemporalUnit` and `BalanceDuration`.

By following this process of scanning, focusing, analyzing, inferring, connecting, and summarizing, I can effectively understand the functionality of a V8 source code file even without deep, pre-existing knowledge of the entire codebase. The hints in the prompt (like the `.tq` information and the "Temporal" context) are invaluable in guiding this analysis.
好的，让我们来分析一下 `v8/src/objects/js-temporal-objects.cc` 这个文件的功能。

**文件功能归纳:**

`v8/src/objects/js-temporal-objects.cc` 文件是 V8 JavaScript 引擎中负责实现 **ECMAScript Temporal API** 相关功能的 C++ 源代码文件。它主要负责处理与 Temporal API 中的日期、时间、时区和持续时间等对象相关的底层逻辑和操作。

**具体功能列举:**

1. **Temporal 对象的创建和转换:**
   - 提供了将 JavaScript 对象转换为 V8 内部表示（例如 `TimeRecord`, `DateRecord` 等结构体）的函数，例如 `ToTemporalTimeRecordOrPartialTime`, `ToPartialTime`, `ToTemporalTimeRecord`。这些函数用于从 JavaScript 传递过来的对象中提取时间信息。
   - 提供了创建 ISO 日期记录的函数 `CreateISODateRecord`。

2. **Temporal 选项的处理:**
   - 实现了获取 Temporal 单元（例如年、月、日、小时等）的函数 `GetTemporalUnit`。该函数用于解析用户在选项对象中指定的单位，并进行验证。
   - 提供了合并 largestUnit 选项的函数 `MergeLargestUnitOption`。

3. **Temporal 值的规范化和平衡:**
   - 提供了将时间值规范化为整数的函数 `ToIntegerThrowOnInfinity`，并处理无穷大的情况。
   - 实现了比较两个 Temporal 单元大小的函数 `LargerOfTwoTemporalUnits`。
   - 提供了将 Temporal 单元转换为字符串表示的函数 `UnitToString`。
   - 实现了平衡 ISO 日期的函数 `BalanceISODate`，用于确保日期在有效的范围内。
   - 提供了平衡持续时间的函数 `BalanceDuration` 和 `BalancePossiblyInfiniteDuration`，用于将不同时间单位的持续时间进行转换和规范化。

4. **Temporal 运算:**
   - 实现了日期时间相加的函数 `AddDateTime`，用于将持续时间添加到日期时间对象上。

5. **时区处理 (部分实现):**
   - 提供了规范化时区名称的函数 `CanonicalizeTimeZoneName`，但在当前代码中，它只是简单地返回 "UTC"。这可能表示该部分功能尚未完全实现或当前简化处理。

**关于文件类型和 Torque:**

根据您的描述，如果 `v8/src/objects/js-temporal-objects.cc` 以 `.tq` 结尾，那它将是 V8 Torque 源代码。但当前的文件名以 `.cc` 结尾，这意味着它是标准的 C++ 源代码文件。Torque 是 V8 内部使用的一种领域特定语言，用于生成高效的 C++ 代码，特别是对于类型相关的操作。

**与 JavaScript 功能的关系及示例:**

这个 C++ 文件中实现的函数直接支撑着 JavaScript 中 Temporal API 的功能。以下是一些与 JavaScript 功能对应的示例：

```javascript
// Temporal.PlainTime.from()
const plainTime = Temporal.PlainTime.from({ hour: 10, minute: 30 });
console.log(plainTime.hour); // 10
console.log(plainTime.minute); // 30

// Temporal.Duration 的平衡
const duration = new Temporal.Duration({ hours: 25, minutes: 90 });
console.log(duration.hours); // 25
console.log(duration.minutes); // 90

const balancedDuration = duration.total('minutes');
console.log(balancedDuration); // 输出总分钟数，底层的 BalanceDuration 函数会被调用

// Temporal 对象的加法
const plainDateTime = new Temporal.PlainDateTime(2023, 1, 1, 10, 0, 0);
const oneDay = new Temporal.Duration({ days: 1 });
const nextDay = plainDateTime.add(oneDay);
console.log(nextDay.toString()); // 输出 2023-01-02T10:00:00，底层的 AddDateTime 函数会被调用

// 获取 Temporal 单元
const options = { largestUnit: 'hour' };
// 在某些 Temporal API 的方法中，会调用 GetTemporalUnit 来解析 largestUnit 选项
```

在这些 JavaScript 示例中，当调用 `Temporal.PlainTime.from()`, `duration.total('minutes')`, `plainDateTime.add(oneDay)` 等方法时，V8 引擎会调用 `v8/src/objects/js-temporal-objects.cc` 文件中相应的 C++ 函数来执行底层的操作，例如从 JavaScript 对象中提取时间信息、平衡持续时间、执行日期时间加法等。

**代码逻辑推理和假设输入/输出:**

**函数:** `ToTemporalTimeRecordOrPartialTime`

**假设输入:**
```javascript
const input = { hour: 10, minute: 30, second: undefined };
```

**代码逻辑推理:**

1. 函数接收一个 JavaScript 对象 `input`。
2. 遍历 `hour_string`, `minute_string`, `second_string` 等属性。
3. 使用 `JSReceiver::GetProperty` 获取 `input` 对象中对应属性的值。
4. 对于 `hour` 和 `minute`，值存在，调用 `ToIntegerThrowOnInfinity` 将其转换为整数。
5. 对于 `second`，值为 `undefined`，`any` 标志位设为 `true`，但不会设置 `result.second` 的值（因为 `skip_undefined` 为 `false`）。
6. 返回包含提取的时间信息的 `TimeRecord` 结构体。

**假设输出 (TimeRecord 结构体):**
```c++
TimeRecord result = {
  .hour = 10,
  .minute = 30,
  .second = kMinInt31, // 因为 second 是 undefined
  .millisecond = kMinInt31,
  .microsecond = kMinInt31,
  .nanosecond = kMinInt31
};
```

**用户常见的编程错误及示例:**

1. **提供无效的 Temporal 属性类型:**
   ```javascript
   // 错误：hour 应该是数字
   const invalidTime = Temporal.PlainTime.from({ hour: 'ten', minute: 30 });
   ```
   在 C++ 代码中，`ToIntegerThrowOnInfinity` 会尝试将 `'ten'` 转换为整数，这会导致抛出 `RangeError` 异常。

2. **提供超出范围的 Temporal 属性值:**
   ```javascript
   // 错误：minute 的值超出 0-59 的范围
   const invalidTime = Temporal.PlainTime.from({ hour: 10, minute: 60 });
   ```
   虽然此代码片段没有直接展示范围检查，但在 Temporal API 的其他部分或后续处理中，会对这些值进行范围验证，可能会导致错误。

3. **在需要完整时间信息的地方提供部分信息，且未处理默认值:**
   ```javascript
   // 如果某个操作期望完整的 TimeRecord，而只提供了 hour 和 minute
   const partialTime = { hour: 10, minute: 30 };
   // 某些操作可能无法正确处理缺少 second 等信息的情况，除非明确处理了 undefined 的情况
   ```
   `ToTemporalTimeRecord` 在 `any` 为 `false` 时会抛出 `TypeError`，这发生在没有提供任何有效的时间属性时。

**第 7 部分，共 25 部分的功能归纳:**

作为 Temporal API 实现的第 7 部分，这个文件主要关注以下核心功能：

- **Temporal 对象的初步构建和转换:** 将 JavaScript 传递的 Temporal 对象转换为 V8 内部易于处理的结构。
- **基本的时间单元和选项处理:**  解析和提取用户提供的关于时间单位和配置选项的信息。
- **核心的规范化和平衡操作:** 确保 Temporal 对象中的值处于有效范围内，并将不同单位的持续时间进行统一表示。

总而言之，`v8/src/objects/js-temporal-objects.cc` 是 V8 引擎中实现 ECMAScript Temporal API 的关键组成部分，它提供了处理 Temporal 对象的底层基础设施和核心逻辑。

Prompt: 
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共25部分，请归纳一下它的功能

"""
_zone, isolate));
}
// #sec-canonicalizetimezonename
Handle<String> CanonicalizeTimeZoneName(Isolate* isolate,
                                        DirectHandle<String> identifier) {
  return isolate->factory()->UTC_string();
}
#endif  // V8_INTL_SUPPORT

// Common routine shared by ToTemporalTimeRecord and ToPartialTime
// #sec-temporal-topartialtime
// #sec-temporal-totemporaltimerecord
Maybe<TimeRecord> ToTemporalTimeRecordOrPartialTime(
    Isolate* isolate, Handle<JSReceiver> temporal_time_like,
    const TimeRecord& time, bool skip_undefined, const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  TimeRecord result(time);
  Factory* factory = isolate->factory();
  // 1. Assert: Type(temporalTimeLike) is Object.
  // 2. Let result be the new Record { [[Hour]]: undefined, [[Minute]]:
  // undefined, [[Second]]: undefined, [[Millisecond]]: undefined,
  // [[Microsecond]]: undefined, [[Nanosecond]]: undefined }.
  // See https://github.com/tc39/proposal-temporal/pull/1862
  // 3. Let _any_ be *false*.
  bool any = false;
  // 4. For each row of Table 4, except the header row, in table order, do
  std::array<std::pair<Handle<String>, int32_t*>, 6> table4 = {
      {{factory->hour_string(), &result.hour},
       {factory->microsecond_string(), &result.microsecond},
       {factory->millisecond_string(), &result.millisecond},
       {factory->minute_string(), &result.minute},
       {factory->nanosecond_string(), &result.nanosecond},
       {factory->second_string(), &result.second}}};
  for (const auto& row : table4) {
    Handle<Object> value;
    // a. Let property be the Property value of the current row.
    // b. Let value be ? Get(temporalTimeLike, property).
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, value,
        JSReceiver::GetProperty(isolate, temporal_time_like, row.first),
        Nothing<TimeRecord>());
    // c. If value is not undefined, then
    if (!IsUndefined(*value)) {
      // i. Set _any_ to *true*.
      any = true;
      // If it is inside ToPartialTime, we only continue if it is not undefined.
    } else if (skip_undefined) {
      continue;
    }
    // d. / ii. Set value to ? ToIntegerThrowOnOInfinity(value).
    Handle<Number> value_number;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, value_number,
                                     ToIntegerThrowOnInfinity(isolate, value),
                                     Nothing<TimeRecord>());
    // e. / iii. Set result's internal slot whose name is the Internal Slot
    // value of the current row to value.
    *(row.second) = Object::NumberValue(*value_number);
  }

  // 5. If _any_ is *false*, then
  if (!any) {
    // a. Throw a *TypeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<TimeRecord>());
  }
  // 4. Return result.
  return Just(result);
}

// #sec-temporal-topartialtime
Maybe<TimeRecord> ToPartialTime(Isolate* isolate,
                                Handle<JSReceiver> temporal_time_like,
                                const TimeRecord& time,
                                const char* method_name) {
  return ToTemporalTimeRecordOrPartialTime(isolate, temporal_time_like, time,
                                           true, method_name);
}

// #sec-temporal-totemporaltimerecord
Maybe<TimeRecord> ToTemporalTimeRecord(Isolate* isolate,
                                       Handle<JSReceiver> temporal_time_like,
                                       const char* method_name) {
  return ToTemporalTimeRecordOrPartialTime(
      isolate, temporal_time_like,
      {kMinInt31, kMinInt31, kMinInt31, kMinInt31, kMinInt31, kMinInt31}, false,
      method_name);
}

// #sec-temporal-gettemporalunit
// In the spec text, the extraValues is defined as an optional argument of
// "a List of ECMAScript language values". Most of the caller does not pass in
// value for extraValues, which is represented by the default Unit::kNotPresent.
// For the three places in the spec text calling GetTemporalUnit with
// an extraValues argument:
// << "day" >> is passed in as in the algorithm of
//   Temporal.PlainDateTime.prototype.round() and
//   Temporal.ZonedDateTime.prototype.round();
// << "auto" >> is passed in as in the algorithm of
// Temporal.Duration.prototype.round().
// Therefore we can simply use a Unit of three possible value, the default
// Unit::kNotPresent, Unit::kDay, and Unit::kAuto to cover all the possible
// value for extraValues.
Maybe<Unit> GetTemporalUnit(Isolate* isolate,
                            Handle<JSReceiver> normalized_options,
                            const char* key, UnitGroup unit_group,
                            Unit default_value, bool default_is_required,
                            const char* method_name,
                            Unit extra_values = Unit::kNotPresent) {
  std::vector<const char*> str_values;
  std::vector<Unit> enum_values;
  switch (unit_group) {
    case UnitGroup::kDate:
      if (default_value == Unit::kAuto || extra_values == Unit::kAuto) {
        str_values = {"year",  "month",  "week",  "day", "auto",
                      "years", "months", "weeks", "days"};
        enum_values = {Unit::kYear,  Unit::kMonth, Unit::kWeek,
                       Unit::kDay,   Unit::kAuto,  Unit::kYear,
                       Unit::kMonth, Unit::kWeek,  Unit::kDay};
      } else {
        DCHECK(default_value == Unit::kNotPresent ||
               default_value == Unit::kYear || default_value == Unit::kMonth ||
               default_value == Unit::kWeek || default_value == Unit::kDay);
        str_values = {"year",  "month",  "week",  "day",
                      "years", "months", "weeks", "days"};
        enum_values = {Unit::kYear, Unit::kMonth, Unit::kWeek, Unit::kDay,
                       Unit::kYear, Unit::kMonth, Unit::kWeek, Unit::kDay};
      }
      break;
    case UnitGroup::kTime:
      if (default_value == Unit::kAuto || extra_values == Unit::kAuto) {
        str_values = {"hour",        "minute",       "second",
                      "millisecond", "microsecond",  "nanosecond",
                      "auto",        "hours",        "minutes",
                      "seconds",     "milliseconds", "microseconds",
                      "nanoseconds"};
        enum_values = {
            Unit::kHour,        Unit::kMinute,      Unit::kSecond,
            Unit::kMillisecond, Unit::kMicrosecond, Unit::kNanosecond,
            Unit::kAuto,        Unit::kHour,        Unit::kMinute,
            Unit::kSecond,      Unit::kMillisecond, Unit::kMicrosecond,
            Unit::kNanosecond};
      } else if (default_value == Unit::kDay || extra_values == Unit::kDay) {
        str_values = {"hour",        "minute",       "second",
                      "millisecond", "microsecond",  "nanosecond",
                      "day",         "hours",        "minutes",
                      "seconds",     "milliseconds", "microseconds",
                      "nanoseconds", "days"};
        enum_values = {
            Unit::kHour,        Unit::kMinute,      Unit::kSecond,
            Unit::kMillisecond, Unit::kMicrosecond, Unit::kNanosecond,
            Unit::kDay,         Unit::kHour,        Unit::kMinute,
            Unit::kSecond,      Unit::kMillisecond, Unit::kMicrosecond,
            Unit::kNanosecond,  Unit::kDay};
      } else {
        DCHECK(default_value == Unit::kNotPresent ||
               default_value == Unit::kHour || default_value == Unit::kMinute ||
               default_value == Unit::kSecond ||
               default_value == Unit::kMillisecond ||
               default_value == Unit::kMicrosecond ||
               default_value == Unit::kNanosecond);
        str_values = {"hour",         "minute",       "second",
                      "millisecond",  "microsecond",  "nanosecond",
                      "hours",        "minutes",      "seconds",
                      "milliseconds", "microseconds", "nanoseconds"};
        enum_values = {
            Unit::kHour,        Unit::kMinute,      Unit::kSecond,
            Unit::kMillisecond, Unit::kMicrosecond, Unit::kNanosecond,
            Unit::kHour,        Unit::kMinute,      Unit::kSecond,
            Unit::kMillisecond, Unit::kMicrosecond, Unit::kNanosecond};
      }
      break;
    case UnitGroup::kDateTime:
      if (default_value == Unit::kAuto || extra_values == Unit::kAuto) {
        str_values = {"year",         "month",        "week",
                      "day",          "hour",         "minute",
                      "second",       "millisecond",  "microsecond",
                      "nanosecond",   "auto",         "years",
                      "months",       "weeks",        "days",
                      "hours",        "minutes",      "seconds",
                      "milliseconds", "microseconds", "nanoseconds"};
        enum_values = {
            Unit::kYear,        Unit::kMonth,       Unit::kWeek,
            Unit::kDay,         Unit::kHour,        Unit::kMinute,
            Unit::kSecond,      Unit::kMillisecond, Unit::kMicrosecond,
            Unit::kNanosecond,  Unit::kAuto,        Unit::kYear,
            Unit::kMonth,       Unit::kWeek,        Unit::kDay,
            Unit::kHour,        Unit::kMinute,      Unit::kSecond,
            Unit::kMillisecond, Unit::kMicrosecond, Unit::kNanosecond};
      } else {
        str_values = {
            "year",        "month",        "week",         "day",
            "hour",        "minute",       "second",       "millisecond",
            "microsecond", "nanosecond",   "years",        "months",
            "weeks",       "days",         "hours",        "minutes",
            "seconds",     "milliseconds", "microseconds", "nanoseconds"};
        enum_values = {
            Unit::kYear,        Unit::kMonth,       Unit::kWeek,
            Unit::kDay,         Unit::kHour,        Unit::kMinute,
            Unit::kSecond,      Unit::kMillisecond, Unit::kMicrosecond,
            Unit::kNanosecond,  Unit::kYear,        Unit::kMonth,
            Unit::kWeek,        Unit::kDay,         Unit::kHour,
            Unit::kMinute,      Unit::kSecond,      Unit::kMillisecond,
            Unit::kMicrosecond, Unit::kNanosecond};
      }
      break;
  }

  // 4. If default is required, then
  if (default_is_required) default_value = Unit::kNotPresent;
  // a. Let defaultValue be undefined.
  // 5. Else,
  // a. Let defaultValue be default.
  // b. If defaultValue is not undefined and singularNames does not contain
  // defaultValue, then i. Append defaultValue to singularNames.

  // 9. Let value be ? GetOption(normalizedOptions, key, "string",
  // allowedValues, defaultValue).
  Unit value;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, value,
      GetStringOption<Unit>(isolate, normalized_options, key, method_name,
                            str_values, enum_values, default_value),
      Nothing<Unit>());

  // 10. If value is undefined and default is required, throw a RangeError
  // exception.
  if (default_is_required && value == Unit::kNotPresent) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(
            MessageTemplate::kValueOutOfRange,
            isolate->factory()->undefined_value(),
            isolate->factory()->NewStringFromAsciiChecked(method_name),
            isolate->factory()->NewStringFromAsciiChecked(key)),
        Nothing<Unit>());
  }
  // 12. Return value.
  return Just(value);
}

// #sec-temporal-mergelargestunitoption
MaybeHandle<JSReceiver> MergeLargestUnitOption(Isolate* isolate,
                                               Handle<JSReceiver> options,
                                               Unit largest_unit) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let merged be OrdinaryObjectCreate(null).
  Handle<JSReceiver> merged = isolate->factory()->NewJSObjectWithNullProto();
  // 2. Let keys be ? EnumerableOwnPropertyNames(options, key).
  // 3. For each element nextKey of keys, do
  // a. Let propValue be ? Get(options, nextKey).
  // b. Perform ! CreateDataPropertyOrThrow(merged, nextKey, propValue).
  JSReceiver::SetOrCopyDataProperties(
      isolate, merged, options, PropertiesEnumerationMode::kEnumerationOrder,
      {}, false)
      .Check();

  // 4. Perform ! CreateDataPropertyOrThrow(merged, "largestUnit", largestUnit).
  CHECK(JSReceiver::CreateDataProperty(
            isolate, merged, isolate->factory()->largestUnit_string(),
            UnitToString(isolate, largest_unit), Just(kThrowOnError))
            .FromJust());
  // 5. Return merged.
  return merged;
}

// #sec-temporal-tointegerthrowoninfinity
MaybeHandle<Number> ToIntegerThrowOnInfinity(Isolate* isolate,
                                             Handle<Object> argument) {
  TEMPORAL_ENTER_FUNC();

  // 1. Let integer be ? ToIntegerOrInfinity(argument).
  Handle<Number> integer;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, integer,
                             Object::ToInteger(isolate, argument));
  // 2. If integer is +∞ or -∞, throw a RangeError exception.
  if (!std::isfinite(Object::NumberValue(*integer))) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  return integer;
}

// #sec-temporal-largeroftwotemporalunits
Unit LargerOfTwoTemporalUnits(Unit u1, Unit u2) {
  // 1. If either u1 or u2 is "year", return "year".
  if (u1 == Unit::kYear || u2 == Unit::kYear) return Unit::kYear;
  // 2. If either u1 or u2 is "month", return "month".
  if (u1 == Unit::kMonth || u2 == Unit::kMonth) return Unit::kMonth;
  // 3. If either u1 or u2 is "week", return "week".
  if (u1 == Unit::kWeek || u2 == Unit::kWeek) return Unit::kWeek;
  // 4. If either u1 or u2 is "day", return "day".
  if (u1 == Unit::kDay || u2 == Unit::kDay) return Unit::kDay;
  // 5. If either u1 or u2 is "hour", return "hour".
  if (u1 == Unit::kHour || u2 == Unit::kHour) return Unit::kHour;
  // 6. If either u1 or u2 is "minute", return "minute".
  if (u1 == Unit::kMinute || u2 == Unit::kMinute) return Unit::kMinute;
  // 7. If either u1 or u2 is "second", return "second".
  if (u1 == Unit::kSecond || u2 == Unit::kSecond) return Unit::kSecond;
  // 8. If either u1 or u2 is "millisecond", return "millisecond".
  if (u1 == Unit::kMillisecond || u2 == Unit::kMillisecond)
    return Unit::kMillisecond;
  // 9. If either u1 or u2 is "microsecond", return "microsecond".
  if (u1 == Unit::kMicrosecond || u2 == Unit::kMicrosecond)
    return Unit::kMicrosecond;
  // 10. Return "nanosecond".
  return Unit::kNanosecond;
}

Handle<String> UnitToString(Isolate* isolate, Unit unit) {
  switch (unit) {
    case Unit::kYear:
      return ReadOnlyRoots(isolate).year_string_handle();
    case Unit::kMonth:
      return ReadOnlyRoots(isolate).month_string_handle();
    case Unit::kWeek:
      return ReadOnlyRoots(isolate).week_string_handle();
    case Unit::kDay:
      return ReadOnlyRoots(isolate).day_string_handle();
    case Unit::kHour:
      return ReadOnlyRoots(isolate).hour_string_handle();
    case Unit::kMinute:
      return ReadOnlyRoots(isolate).minute_string_handle();
    case Unit::kSecond:
      return ReadOnlyRoots(isolate).second_string_handle();
    case Unit::kMillisecond:
      return ReadOnlyRoots(isolate).millisecond_string_handle();
    case Unit::kMicrosecond:
      return ReadOnlyRoots(isolate).microsecond_string_handle();
    case Unit::kNanosecond:
      return ReadOnlyRoots(isolate).nanosecond_string_handle();
    case Unit::kNotPresent:
    case Unit::kAuto:
      UNREACHABLE();
  }
}

// #sec-temporal-create-iso-date-record
DateRecord CreateISODateRecord(Isolate* isolate, const DateRecord& date) {
  // 1. Assert: IsValidISODate(year, month, day) is true.
  DCHECK(IsValidISODate(isolate, date));
  // 2. Return the Record { [[Year]]: year, [[Month]]: month, [[Day]]: day }.
  return date;
}

// #sec-temporal-balanceisodate
DateRecord BalanceISODate(Isolate* isolate, const DateRecord& date) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let epochDays be MakeDay(𝔽(year), 𝔽(month - 1), 𝔽(day)).
  double epoch_days = MakeDay(date.year, date.month - 1, date.day);
  // 2. Assert: epochDays is finite.
  DCHECK(std::isfinite(epoch_days));
  // 3. Let ms be MakeDate(epochDays, +0𝔽).
  double ms = MakeDate(epoch_days, 0);
  // 4. Return CreateISODateRecordWithCalendar(ℝ(YearFromTime(ms)),
  // ℝ(MonthFromTime(ms)) + 1, ℝ(DateFromTime(ms))).
  int year = 0;
  int month = 0;
  int day = 0;
  int wday = 0;
  int hour = 0;
  int minute = 0;
  int second = 0;
  int millisecond = 0;

  DCHECK(std::isfinite(ms));
  DCHECK_LT(ms, static_cast<double>(std::numeric_limits<int64_t>::max()));
  DCHECK_GT(ms, static_cast<double>(std::numeric_limits<int64_t>::min()));
  isolate->date_cache()->BreakDownTime(ms, &year, &month, &day, &wday, &hour,
                                       &minute, &second, &millisecond);

  return CreateISODateRecord(isolate, {year, month + 1, day});
}

// #sec-temporal-adddatetime
Maybe<DateTimeRecord> AddDateTime(Isolate* isolate,
                                  const DateTimeRecord& date_time,
                                  Handle<JSReceiver> calendar,
                                  const DurationRecord& dur,
                                  Handle<Object> options) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: ISODateTimeWithinLimits(year, month, day, hour, minute, second,
  // millisecond, microsecond, nanosecond) is true.
  DCHECK(ISODateTimeWithinLimits(isolate, date_time));
  // 2. Let timeResult be ! AddTime(hour, minute, second, millisecond,
  // microsecond, nanosecond, hours, minutes, seconds, milliseconds,
  // microseconds, nanoseconds).
  const TimeDurationRecord& time = dur.time_duration;
  DateTimeRecord time_result =
      AddTime(isolate, date_time.time,
              {0, time.hours, time.minutes, time.seconds, time.milliseconds,
               time.microseconds, time.nanoseconds});

  // 3. Let datePart be ? CreateTemporalDate(year, month, day, calendar).
  Handle<JSTemporalPlainDate> date_part;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, date_part, CreateTemporalDate(isolate, date_time.date, calendar),
      Nothing<DateTimeRecord>());
  // 4. Let dateDuration be ? CreateTemporalDuration(years, months, weeks, days
  // + timeResult.[[Days]], 0, 0, 0, 0, 0, 0).
  Handle<JSTemporalDuration> date_duration;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, date_duration,
      CreateTemporalDuration(
          isolate,
          {dur.years,
           dur.months,
           dur.weeks,
           {dur.time_duration.days + time_result.date.day, 0, 0, 0, 0, 0, 0}}),
      Nothing<DateTimeRecord>());
  // 5. Let addedDate be ? CalendarDateAdd(calendar, datePart, dateDuration,
  // options).
  Handle<JSTemporalPlainDate> added_date;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, added_date,
      CalendarDateAdd(isolate, calendar, date_part, date_duration, options),
      Nothing<DateTimeRecord>());
  // 6. Return the new Record { [[Year]]: addedDate.[[ISOYear]], [[Month]]:
  // addedDate.[[ISOMonth]], [[Day]]: addedDate.[[ISODay]], [[Hour]]:
  // timeResult.[[Hour]], [[Minute]]: timeResult.[[Minute]], [[Second]]:
  // timeResult.[[Second]], [[Millisecond]]: timeResult.[[Millisecond]],
  // [[Microsecond]]: timeResult.[[Microsecond]], [[Nanosecond]]:
  // timeResult.[[Nanosecond]], }.
  time_result.date = {added_date->iso_year(), added_date->iso_month(),
                      added_date->iso_day()};
  return Just(time_result);
}

// #sec-temporal-balanceduration
Maybe<TimeDurationRecord> BalanceDuration(Isolate* isolate, Unit largest_unit,
                                          const TimeDurationRecord& duration,
                                          const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 1. If relativeTo is not present, set relativeTo to undefined.
  return BalanceDuration(isolate, largest_unit,
                         isolate->factory()->undefined_value(), duration,
                         method_name);
}

Maybe<TimeDurationRecord> BalanceDuration(Isolate* isolate, Unit largest_unit,
                                          Handle<BigInt> nanoseconds,
                                          const char* method_name) {
  // 1. Let balanceResult be ? BalancePossiblyInfiniteDuration(days, hours,
  // minutes, seconds, milliseconds, microseconds, nanoseconds, largestUnit,
  // relativeTo).
  BalancePossiblyInfiniteDurationResult balance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, balance_result,
      BalancePossiblyInfiniteDuration(isolate, largest_unit, 0, nanoseconds,
                                      method_name),
      Nothing<TimeDurationRecord>());

  // 2. If balanceResult is positive overflow or negative overflow, then
  if (balance_result.overflow != BalanceOverflow::kNone) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<TimeDurationRecord>());
    // 3. Else,
  } else {
    // a. Return balanceResult.
    return Just(balance_result.value);
  }
}

Maybe<TimeDurationRecord> BalanceDuration(Isolate* isolate, Unit largest_unit,
                                          const TimeDurationRecord& dur1,
                                          const TimeDurationRecord& dur2,
                                          const char* method_name) {
  // Add the two TimeDurationRecord as BigInt in nanoseconds.
  Handle<BigInt> nanoseconds =
      BigInt::Add(isolate, TotalDurationNanoseconds(isolate, dur1, 0),
                  TotalDurationNanoseconds(isolate, dur2, 0))
          .ToHandleChecked();
  return BalanceDuration(isolate, largest_unit, nanoseconds, method_name);
}

// #sec-temporal-balanceduration
Maybe<TimeDurationRecord> BalanceDuration(Isolate* isolate, Unit largest_unit,
                                          Handle<Object> relative_to_obj,
                                          const TimeDurationRecord& value,
                                          const char* method_name) {
  // 1. Let balanceResult be ? BalancePossiblyInfiniteDuration(days, hours,
  // minutes, seconds, milliseconds, microseconds, nanoseconds, largestUnit,
  // relativeTo).
  BalancePossiblyInfiniteDurationResult balance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, balance_result,
      BalancePossiblyInfiniteDuration(isolate, largest_unit, relative_to_obj,
                                      value, method_name),
      Nothing<TimeDurationRecord>());

  // 2. If balanceResult is positive overflow or negative overflow, then
  if (balance_result.overflow != BalanceOverflow::kNone) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<TimeDurationRecord>());
    // 3. Else,
  } else {
    // a. Return balanceResult.
    return Just(balance_result.value);
  }
}

// sec-temporal-balancepossiblyinfiniteduration
Maybe<BalancePossiblyInfiniteDurationResult> BalancePossiblyInfiniteDuration(
    Isolate* isolate, Unit largest_unit, Handle<Object> relative_to_obj,
    const TimeDurationRecord& value, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  TimeDurationRecord duration = value;
  Handle<BigInt> nanoseconds;

  // 2. If Type(relativeTo) is Object and relativeTo has an
  // [[InitializedTemporalZonedDateTime]] internal slot, then
  if (IsJSTemporalZonedDateTime(*relative_to_obj)) {
    auto relative_to = Cast<JSTemporalZonedDateTime>(relative_to_obj);
    // a. Let endNs be ? AddZonedDateTime(relativeTo.[[Nanoseconds]],
    // relativeTo.[[TimeZone]], relativeTo.[[Calendar]], 0, 0, 0, days, hours,
    // minutes, seconds, milliseconds, microseconds, nanoseconds).
    Handle<BigInt> end_ns;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, end_ns,
        AddZonedDateTime(isolate, handle(relative_to->nanoseconds(), isolate),
                         handle(relative_to->time_zone(), isolate),
                         handle(relative_to->calendar(), isolate),
                         {0, 0, 0, duration}, method_name),
        Nothing<BalancePossiblyInfiniteDurationResult>());
    // b. Set nanoseconds to endNs − relativeTo.[[Nanoseconds]].
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, nanoseconds,
        BigInt::Subtract(isolate, end_ns,
                         handle(relative_to->nanoseconds(), isolate)),
        Nothing<BalancePossiblyInfiniteDurationResult>());
    // 3. Else,
  } else {
    // a. Set nanoseconds to ℤ(! TotalDurationNanoseconds(days, hours, minutes,
    // seconds, milliseconds, microseconds, nanoseconds, 0)).
    nanoseconds = TotalDurationNanoseconds(isolate, duration, 0);
  }

  // Call the BigInt version for the same process after step 4
  // The only value need to pass in is nanoseconds and days because
  // 1) step 4 and 5 use nanoseconds and days only, and
  // 2) step 6 is "Set hours, minutes, seconds, milliseconds, and microseconds
  // to 0."
  return BalancePossiblyInfiniteDuration(isolate, largest_unit, relative_to_obj,
                                         duration.days, nanoseconds,
                                         method_name);
}

// The special case of BalancePossiblyInfiniteDuration while the nanosecond is a
// large value and days contains non-zero values but the rest are 0.
// This version has no relative_to.
Maybe<BalancePossiblyInfiniteDurationResult> BalancePossiblyInfiniteDuration(
    Isolate* isolate, Unit largest_unit, Handle<Object> relative_to_obj,
    double days, Handle<BigInt> nanoseconds, const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 4. If largestUnit is one of "year", "month", "week", or "day", then
  if (largest_unit == Unit::kYear || largest_unit == Unit::kMonth ||
      largest_unit == Unit::kWeek || largest_unit == Unit::kDay) {
    // a. Let result be ? NanosecondsToDays(nanoseconds, relativeTo).
    NanosecondsToDaysResult result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, result,
        NanosecondsToDays(isolate, nanoseconds, relative_to_obj, method_name),
        Nothing<BalancePossiblyInfiniteDurationResult>());
    // b. Set days to result.[[Days]].
    days = result.days;
    // c. Set nanoseconds to result.[[Nanoseconds]].
    nanoseconds = BigInt::FromInt64(isolate, result.nanoseconds);
    // 5. Else,
  } else {
    // a. Set days to 0.
    days = 0;
  }
  // 6. Set hours, minutes, seconds, milliseconds, and microseconds to 0.
  DirectHandle<BigInt> thousand = BigInt::FromInt64(isolate, 1000);
  DirectHandle<BigInt> sixty = BigInt::FromInt64(isolate, 60);
  Handle<BigInt> zero = BigInt::FromInt64(isolate, 0);
  DirectHandle<BigInt> hours = zero;
  Handle<BigInt> minutes = zero;
  Handle<BigInt> seconds = zero;
  Handle<BigInt> milliseconds = zero;
  Handle<BigInt> microseconds = zero;

  // 7. If nanoseconds < 0, let sign be −1; else, let sign be 1.
  // 8. Set nanoseconds to abs(nanoseconds).
  int32_t sign = 1;
  if (nanoseconds->IsNegative()) {
    sign = -1;
    nanoseconds = BigInt::UnaryMinus(isolate, nanoseconds);
  }

  // 9 If largestUnit is "year", "month", "week", "day", or "hour", then
  switch (largest_unit) {
    case Unit::kYear:
    case Unit::kMonth:
    case Unit::kWeek:
    case Unit::kDay:
    case Unit::kHour:
      // a. Set microseconds to floor(nanoseconds / 1000).
      microseconds =
          BigInt::Divide(isolate, nanoseconds, thousand).ToHandleChecked();
      // b. Set nanoseconds to nanoseconds modulo 1000.
      nanoseconds =
          BigInt::Remainder(isolate, nanoseconds, thousand).ToHandleChecked();
      // c. Set milliseconds to floor(microseconds / 1000).
      milliseconds =
          BigInt::Divide(isolate, microseconds, thousand).ToHandleChecked();
      // d. Set microseconds to microseconds modulo 1000.
      microseconds =
          BigInt::Remainder(isolate, microseconds, thousand).ToHandleChecked();
      // e. Set seconds to floor(milliseconds / 1000).
      seconds =
          BigInt::Divide(isolate, milliseconds, thousand).ToHandleChecked();
      // f. Set milliseconds to milliseconds modulo 1000.
      milliseconds =
          BigInt::Remainder(isolate, milliseconds, thousand).ToHandleChecked();
      // g. Set minutes to floor(seconds, 60).
      minutes = BigInt::Divide(isolate, seconds, sixty).ToHandleChecked();
      // h. Set seconds to seconds modulo 60.
      seconds = BigInt::Remainder(isolate, seconds, sixty).ToHandleChecked();
      // i. Set hours to floor(minutes / 60).
      hours = BigInt::Divide(isolate, minutes, sixty).ToHandleChecked();
      // j. Set minutes to minutes modulo 60.
      minutes = BigInt::Remainder(isolate, minutes, sixty).ToHandleChecked();
      break;
    // 10. Else if largestUnit is "minute", then
    case Unit::kMinute:
      // a. Set microseconds to floor(nanoseconds / 1000).
      microseconds =
          BigInt::Divide(isolate, nanoseconds, thousand).ToHandleChecked();
      // b. Set nanoseconds to nanoseconds modulo 1000.
      nanoseconds =
          BigInt::Remainder(isolate, nanoseconds, thousand).ToHandleChecked();
      // c. Set milliseconds to floor(microseconds / 1000).
      milliseconds =
          BigInt::Divide(isolate, microseconds, thousand).ToHandleChecked();
      // d. Set microseconds to microseconds modulo 1000.
      microseconds =
          BigInt::Remainder(isolate, microseconds, thousand).ToHandleChecked();
      // e. Set seconds to floor(milliseconds / 1000).
      seconds =
          BigInt::Divide(isolate, milliseconds, thousand).ToHandleChecked();
      // f. Set milliseconds to milliseconds modulo 1000.
      milliseconds =
          BigInt::Remainder(isolate, milliseconds, thousand).ToHandleChecked();
      // g. Set minutes to floor(seconds / 60).
      minutes = BigInt::Divide(isolate, seconds, sixty).ToHandleChecked();
      // h. Set seconds to seconds modulo 60.
      seconds = BigInt::Remainder(isolate, seconds, sixty).ToHandleChecked();
      break;
    // 11. Else if largestUnit is "second", then
    case Unit::kSecond:
      // a. Set microseconds to floor(nanoseconds / 1000).
      microseconds =
          BigInt::Divide(isolate, nanoseconds, thousand).ToHandleChecked();
      // b. Set nanoseconds to nanoseconds modulo 1000.
      nanoseconds =
          BigInt::Remainder(isolate, nanoseconds, thousand).ToHandleChecked();
      // c. Set milliseconds to floor(microseconds / 1000).
      milliseconds =
          BigInt::Divide(isolate, microseconds, thousand).ToHandleChecked();
      // d. Set microseconds to microseconds modulo 1000.
      microseconds =
          BigInt::Remainder(isolate, microseconds, thousand).ToHandleChecked();
      // e. Set seconds to floor(milliseconds / 1000).
      seconds =
          BigInt::Divide(isolate, milliseconds, thousand).ToHandleChecked();
      // f. Set milliseconds to milliseconds modulo 1000.
      milliseconds =
          BigInt::Remainder(isolate, milliseconds, thousand).ToHandleChecked();
      break;
    // 12. Else if largestUnit is "millisecond", then
    case Unit::kMillisecond:
      // a. Set microseconds to floor(nanoseconds / 1000).
      microseconds =
          BigInt::Divide(isolate, nanoseconds, thousand).ToHandleChecked();
      // b. Set nanoseconds to nanoseconds modulo 1000.
      nanoseconds =
          BigInt::Remainder(isolate, nanoseconds, thousand).ToHandleChecked();
      // c. Set milliseconds to floor(microseconds / 1000).
      milliseconds =
          BigInt::Divide(isolate, microseconds, thousand).ToHandleChecked();
      // d. Set microseconds to microseconds modulo 1000.
      microseconds =
          BigInt::Remainder(isolate, microseconds, thousand).ToHandleChecked();
      break;
    // 13. Else if largestUnit is "microsecond", then
    case Unit::kMicrosecond:
      // a. Set microseconds to floor(nanoseconds / 1000).
      microseconds =
          BigInt::Divide(isolate, nanoseconds, thousand).ToHandleChecked();
      // b. Set nanoseconds to nanoseconds modulo 1000.
      nanoseconds =
          BigInt::Remainder(isolate, nanoseconds, thousand).ToHandleChecked();
      break;
    // 14. Else,
    case Unit::kNanosecond:
      // a. Assert: largestUnit is "nanosecond".
      break;
    case Unit::kAuto:
    case Unit::kNotPresent:
      UNREACHABLE();
  }
  // 15. For each value v of « days, hours, minutes, seconds, milliseconds,
  // microseconds, nanoseconds », do a. If 𝔽(v) is not finite, then i. If sign
  // = 1, then
  // 1. Return positive overflow.
  // ii. Else if sign = -1, then
  // 1. Return negative overflow.
  double hou
"""


```