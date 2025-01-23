Response:
My thinking process to analyze the provided C++ code snippet for `v8/src/objects/js-temporal-objects.cc` goes through several steps:

1. **Identify the Core Purpose:** I first look for keywords and function names that give a general idea of the file's function. The presence of "TemporalTimeToString," "BuiltinTimeZoneGetPlainDateTimeFor," "GetPossibleInstantsFor," "DisambiguatePossibleInstants," and "ToTemporalInstant" immediately flags this as related to the ECMAScript Temporal API. Specifically, it's dealing with the representation and manipulation of date and time concepts.

2. **Analyze Individual Functions:** I then examine each function individually, noting its inputs, outputs, and the operations it performs. This involves understanding the C++ types involved (e.g., `Handle<String>`, `Isolate*`, `TimeRecord`, `Precision`, `JSTemporalPlainTime`, `JSReceiver`, `JSTemporalInstant`, `FixedArray`, `Disambiguation`, etc.). I also pay attention to comments that explain the steps of the algorithm, often referencing the ECMAScript specification.

3. **Group Related Functions:**  I observe that certain functions seem to work together. For instance, `GetPossibleInstantsFor` and `DisambiguatePossibleInstants` are clearly related to handling ambiguous time instants due to time zone transitions. `TemporalTimeToString` appears in two overloads, one taking a `TimeRecord` and another a `JSTemporalPlainTime`. This suggests different ways to represent time information.

4. **Identify Key Concepts:**  As I analyze the functions, I start to identify the key concepts being handled:
    * **Time Representation:**  `TimeRecord` and `JSTemporalPlainTime` represent time components.
    * **Time Zones:** Functions like `BuiltinTimeZoneGetPlainDateTimeFor` and `GetOffsetNanosecondsFor` are explicitly dealing with time zone conversions.
    * **Instants:** `JSTemporalInstant` represents a point in time independent of any time zone.
    * **Plain Date/Time:** `JSTemporalPlainDateTime` represents a date and time without time zone information.
    * **Disambiguation:** The concept of handling ambiguous date/time values in the context of time zone transitions.
    * **Calendar Systems:**  Functions involving `calendar` indicate support for different calendar systems.
    * **Formatting and Parsing:** `TemporalTimeToString` shows formatting, and the presence of `ParseTemporalInstant` (though not fully shown in this snippet) points to parsing functionality.
    * **Options and Settings:** Functions like `ToTemporalOverflow`, `ToTemporalOffset`, and `ToTemporalDisambiguation` suggest that the behavior can be customized through options.
    * **Error Handling:** The use of `MaybeHandle`, `MAYBE_ASSIGN_RETURN_ON_EXCEPTION`, and `THROW_NEW_ERROR` indicates a focus on robust error handling.

5. **Connect to JavaScript (If Applicable):**  Since the prompt specifically asks about the relationship to JavaScript, I consider how these C++ functions are likely exposed or used in the JavaScript Temporal API. For example, `TemporalTimeToString` directly relates to formatting a `Temporal.PlainTime` object into a string. Functions involving time zones are crucial for methods like `Temporal.ZonedDateTime.prototype.toInstant()`.

6. **Infer Logic and Scenarios:** I try to infer the underlying logic and potential use cases. For instance, the disambiguation functions are essential when a local date/time occurs twice or not at all due to daylight saving time changes.

7. **Identify Potential User Errors:** Based on the functionality, I think about common mistakes developers might make when working with the Temporal API. For example, forgetting about time zone conversions or not handling ambiguous times properly.

8. **Synthesize a Summary:** Finally, I combine all these observations into a concise summary that addresses the prompt's questions about functionality, potential Torque implementation, JavaScript relevance, logic, and common errors. I also make sure to note that this is only a part of the file, so my analysis is based on the provided snippet.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the low-level C++ details. I then need to step back and think about the higher-level purpose and how it relates to the JavaScript API.
* I might make assumptions about the exact implementation of certain Temporal API features. I correct this by focusing on the general functionality demonstrated by the code.
* If I see function names with "Prepare" prefixes, I deduce they are likely involved in processing and validating input data before further operations.
*  The presence of "FromFields" as a template suggests a common pattern for creating Temporal objects from a set of fields, possibly used internally by constructor implementations.

By following these steps, I can systematically analyze the C++ code snippet and provide a comprehensive and accurate summary of its functionality within the context of the V8 JavaScript engine and the Temporal API.
这是目录为 `v8/src/objects/js-temporal-objects.cc` 的一个 V8 源代码文件，它主要负责实现 ECMAScript Temporal API 中与时间相关的对象的功能。

**功能归纳:**

这个代码片段主要集中在以下几个核心功能上：

1. **格式化 `Temporal.PlainTime` 对象为字符串:**
   - `FormatSecondsStringPart`:  根据精度要求，将秒、毫秒、微秒和纳秒部分格式化为字符串。
   - `TemporalTimeToString`: 将 `Temporal.PlainTime` 对象（或其组成部分）格式化为 ISO 8601 扩展格式的时间字符串（例如 "10:30:00.123"）。

2. **在 `Temporal.TimeZone` 和 `Temporal.Instant` 之间转换 `Temporal.PlainDateTime`:**
   - `BuiltinTimeZoneGetPlainDateTimeFor`:  给定一个 `Temporal.TimeZone` 和 `Temporal.Instant`，计算出该时区中对应的 `Temporal.PlainDateTime`。这涉及到处理时区偏移。

3. **处理时区转换中的歧义情况:**
   - `GetPossibleInstantsFor`:  获取给定 `Temporal.TimeZone` 和 `Temporal.PlainDateTime` 可能对应的 `Temporal.Instant` 列表。当时间发生时区切换时，一个本地时间可能对应多个或零个 UTC 时间。
   - `DisambiguatePossibleInstants`:  根据 `disambiguation` 参数（"earlier", "later", "compatible", "reject"），从可能的 `Temporal.Instant` 列表中选择一个。这用于解决时区转换引起的歧义。

4. **获取对象的 `Temporal.Calendar`:**
   - `GetTemporalCalendarWithISODefault`:  尝试从给定的 Temporal 对象中获取 `Calendar` 属性，如果对象本身就是 `Calendar-like`，则直接返回。

5. **准备 Temporal 字段:**
   - `PrepareTemporalFieldsOrPartial`: 一个通用的函数，用于从 JavaScript 对象中提取和转换 Temporal 相关的字段（年、月、日、小时、分钟等）。它可以处理必需字段和默认值。
   - `PrepareTemporalFields`:  `PrepareTemporalFieldsOrPartial` 的一个特化版本，用于准备所有必需的 Temporal 字段。
   - `PreparePartialTemporalFields`: `PrepareTemporalFieldsOrPartial` 的一个特化版本，用于准备部分 Temporal 字段。

6. **从字段创建 Temporal 对象:**
   - `FromFields`: 一个模板函数，用于调用 Calendar 对象上的 `dateFromFields`、`yearMonthFromFields` 或 `monthDayFromFields` 方法，从而基于提供的字段创建一个新的 Temporal 对象。
   - `DateFromFields`, `YearMonthFromFields`, `MonthDayFromFields`:  使用 `FromFields` 模板创建特定 Temporal 对象的函数。

7. **处理 Temporal 选项:**
   - `ToTemporalOverflow`: 将 JavaScript 选项转换为 `ShowOverflow` 枚举（"constrain" 或 "reject"）。
   - `ToTemporalOffset`: 将 JavaScript 选项转换为 `Offset` 枚举（"prefer", "use", "ignore", "reject"）。
   - `ToTemporalDisambiguation`: 将 JavaScript 选项转换为 `Disambiguation` 枚举（"compatible", "earlier", "later", "reject"）。

8. **获取特定 `Temporal.PlainDateTime` 的 `Temporal.Instant`:**
   - `BuiltinTimeZoneGetInstantFor`:  给定一个 `Temporal.TimeZone` 和 `Temporal.PlainDateTime`，根据 `disambiguation` 选项获取对应的 `Temporal.Instant`。

9. **将对象转换为 `Temporal.Instant`:**
   - `ToTemporalInstant`:  尝试将一个 JavaScript 对象转换为 `Temporal.Instant`。它可以处理已经存在的 `Temporal.Instant` 对象、`Temporal.ZonedDateTime` 对象，或者一个表示 ISO 8601 格式日期时间字符串的字符串。

10. **将对象转换为 `Temporal.Calendar`:**
    - `ToTemporalCalendar`:  尝试将一个 JavaScript 对象转换为 `Temporal.Calendar` 对象。它可以处理 Temporal 对象实例或日历标识符字符串。

**关于 .tq 扩展名:**

如果 `v8/src/objects/js-temporal-objects.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。 Torque 是一种 V8 特有的类型安全的代码生成器，用于编写 V8 内部的 JavaScript 内置函数和运行时代码。由于这里给出的文件名是 `.cc`，所以它是一个标准的 C++ 源代码文件。尽管如此，V8 中很多 Temporal API 的实现都使用了 Torque 来生成高效的代码。

**与 JavaScript 的关系和示例:**

这段 C++ 代码是 JavaScript Temporal API 在 V8 引擎中的底层实现。JavaScript 代码会调用这些 C++ 函数来执行相应的 Temporal 操作。

**示例 (JavaScript):**

```javascript
// 格式化 Temporal.PlainTime
const time = new Temporal.PlainTime(10, 30, 0, 123);
const timeString = time.toString(); // 内部会调用 TemporalTimeToString
console.log(timeString); // 输出 "10:30:00.123"

// 在特定时区获取日期时间
const instant = Temporal.Instant.fromEpochSeconds(0);
const timeZone = Temporal.TimeZone.from("America/New_York");
const dateTime = timeZone.getPlainDateTimeFor(instant); // 内部会调用 BuiltinTimeZoneGetPlainDateTimeFor
console.log(dateTime.toString());

// 处理时区转换歧义
const ambiguousDateTime = new Temporal.PlainDateTime(2023, 10, 29, 1, 30); // 纽约时区夏令时结束时，1:00-2:00 会重复
const possibleInstants = timeZone.getPossibleInstantsFor(ambiguousDateTime); // 内部会调用 GetPossibleInstantsFor
console.log(possibleInstants.length); // 可能为 2

const earlierInstant = timeZone.getInstantFor(ambiguousDateTime, { disambiguation: 'earlier' }); // 内部会调用 DisambiguatePossibleInstants
console.log(earlierInstant.toString());

// 获取 Temporal 对象的 Calendar
const plainDate = new Temporal.PlainDate(2023, 10, 27);
const calendar = Temporal.Calendar.from(plainDate); // 内部会调用 GetTemporalCalendarWithISODefault
console.log(calendar.id); // "iso8601"

// 将字符串转换为 Temporal.Instant
const instantFromString = Temporal.Instant.from("1970-01-01T00:00:00Z"); // 内部会调用 ParseTemporalInstant (未在此片段中显示) 和 CreateTemporalInstant
console.log(instantFromString.epochSeconds);
```

**代码逻辑推理和假设输入/输出:**

**假设输入:**

```c++
TimeRecord time = {10, 30, 15, 500, 100, 0}; // 10:30:15.500100
Precision precision = Precision::kMicrosecond;
```

**输出 (通过 `FormatSecondsStringPart` 和 `TemporalTimeToString`):**

`FormatSecondsStringPart` 会生成 ".500100" 这样的字符串。
`TemporalTimeToString` 会生成 "10:30:15.500100"。

**用户常见的编程错误:**

1. **未考虑时区:**  在需要处理特定时区时，直接使用 `Temporal.PlainDateTime` 而不进行时区转换，导致时间错误。
   ```javascript
   const plainDateTime = new Temporal.PlainDateTime(2023, 10, 28, 12, 0, 0);
   // 错误地认为这是特定时区的时间
   ```

2. **时区转换歧义处理不当:** 在进行本地时间到 UTC 时间转换时，没有正确处理由于夏令时等原因造成的歧义情况。
   ```javascript
   const timeZone = Temporal.TimeZone.from("America/Los_Angeles");
   const ambiguousDateTime = new Temporal.PlainDateTime(2023, 11, 5, 1, 30, 0); // 夏令时结束时的重复时间
   const instant = timeZone.getInstantFor(ambiguousDateTime); // 如果不提供 disambiguation，会抛出 RangeError
   ```

3. **精度问题:** 在比较或格式化时间时，没有注意精度问题，导致细微的差异被忽略或显示不正确。
   ```javascript
   const time1 = new Temporal.PlainTime(10, 0, 0, 1);
   const time2 = new Temporal.PlainTime(10, 0, 0, 0, 1000000); // 纳秒表示，但毫秒是 1
   console.log(time1.equals(time2)); // true，但如果只比较毫秒可能会误判
   ```

**第 3 部分功能归纳:**

这部分代码主要负责 Temporal API 中以下核心功能：

- **时间格式化**: 将 `Temporal.PlainTime` 对象转换为字符串。
- **时区转换**:  在 `Temporal.Instant` 和 `Temporal.PlainDateTime` 之间进行基于时区的转换。
- **时区歧义处理**: 解决由于时区切换导致的本地时间对应多个或零个 UTC 时间的问题。
- **Calendar 获取**: 提供获取 Temporal 对象关联的 `Temporal.Calendar` 的能力。
- **Temporal 字段处理**:  从 JavaScript 对象中提取和准备 Temporal 相关的字段。
- **基于字段创建对象**: 允许从一组字段创建特定的 Temporal 对象。
- **Temporal 选项处理**: 解析和转换用户提供的选项，如 `overflow` 和 `disambiguation`。
- **`Temporal.Instant` 转换**: 提供将不同类型的值转换为 `Temporal.Instant` 的能力。
- **`Temporal.Calendar` 转换**: 提供将不同类型的值转换为 `Temporal.Calendar` 的能力。

总的来说，这段代码是 V8 引擎中实现 Temporal API 核心时间处理逻辑的关键部分。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
fraction %= divisor;
      divisor /= 10;
    }
  }
  // 7. Return the string-concatenation of secondsString, the code unit 0x002E
  // (FULL STOP), and fraction.
}

// #sec-temporal-temporaltimetostring
Handle<String> TemporalTimeToString(Isolate* isolate, const TimeRecord& time,
                                    Precision precision) {
  // 1. Assert: hour, minute, second, millisecond, microsecond and nanosecond
  // are integers.
  IncrementalStringBuilder builder(isolate);
  // 2. Let hour be ToZeroPaddedDecimalString(hour, 2).
  ToZeroPaddedDecimalString(&builder, time.hour, 2);
  builder.AppendCharacter(':');
  // 3. Let minute be ToZeroPaddedDecimalString(minute, 2).
  ToZeroPaddedDecimalString(&builder, time.minute, 2);
  // 4. Let seconds be ! FormatSecondsStringPart(second, millisecond,
  // microsecond, nanosecond, precision).
  FormatSecondsStringPart(&builder, time.second, time.millisecond,
                          time.microsecond, time.nanosecond, precision);
  // 5. Return the string-concatenation of hour, the code unit 0x003A (COLON),
  // minute, and seconds.
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

Handle<String> TemporalTimeToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainTime> temporal_time,
    Precision precision) {
  return TemporalTimeToString(
      isolate,
      {temporal_time->iso_hour(), temporal_time->iso_minute(),
       temporal_time->iso_second(), temporal_time->iso_millisecond(),
       temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()},
      precision);
}

}  // namespace

namespace temporal {
MaybeHandle<JSTemporalPlainDateTime> BuiltinTimeZoneGetPlainDateTimeFor(
    Isolate* isolate, Handle<JSReceiver> time_zone,
    Handle<JSTemporalInstant> instant, DirectHandle<JSReceiver> calendar,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let offsetNanoseconds be ? GetOffsetNanosecondsFor(timeZone, instant).
  int64_t offset_nanoseconds;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_nanoseconds,
      GetOffsetNanosecondsFor(isolate, time_zone, instant, method_name),
      Handle<JSTemporalPlainDateTime>());
  // 2. Let result be ! GetISOPartsFromEpoch(instant.[[Nanoseconds]]).
  DateTimeRecord result =
      GetISOPartsFromEpoch(isolate, handle(instant->nanoseconds(), isolate));

  // 3. Set result to ! BalanceISODateTime(result.[[Year]], result.[[Month]],
  // result.[[Day]], result.[[Hour]], result.[[Minute]], result.[[Second]],
  // result.[[Millisecond]], result.[[Microsecond]], result.[[Nanosecond]] +
  // offsetNanoseconds).

  // Note: Since offsetNanoseconds is bounded 86400x 10^9, the
  // result of result.[[Nanosecond]] + offsetNanoseconds may overflow int32_t
  // Therefore we distribute the sum to other fields below to make sure it won't
  // overflow each of the int32_t fields. But it will leave each field to be
  // balanced by BalanceISODateTime
  result.time.nanosecond += offset_nanoseconds % 1000;
  result.time.microsecond += (offset_nanoseconds / 1000) % 1000;
  result.time.millisecond += (offset_nanoseconds / 1000000L) % 1000;
  result.time.second += (offset_nanoseconds / 1000000000L) % 60;
  result.time.minute += (offset_nanoseconds / 60000000000L) % 60;
  result.time.hour += (offset_nanoseconds / 3600000000000L) % 24;
  result.date.day += (offset_nanoseconds / 86400000000000L);

  result = BalanceISODateTime(isolate, result);
  // 4. Return ? CreateTemporalDateTime(result.[[Year]], result.[[Month]],
  // result.[[Day]], result.[[Hour]], result.[[Minute]], result.[[Second]],
  // result.[[Millisecond]], result.[[Microsecond]], result.[[Nanosecond]],
  // calendar).
  return temporal::CreateTemporalDateTime(isolate, result, calendar);
}

}  // namespace temporal

namespace {
// #sec-temporal-getpossibleinstantsfor
MaybeHandle<FixedArray> GetPossibleInstantsFor(Isolate* isolate,
                                               Handle<JSReceiver> time_zone,
                                               Handle<Object> date_time) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let possibleInstants be ? Invoke(timeZone, "getPossibleInstantsFor", «
  // dateTime »).
  Handle<Object> function;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, function,
      Object::GetProperty(isolate, time_zone,
                          isolate->factory()->getPossibleInstantsFor_string()));
  if (!IsCallable(*function)) {
    THROW_NEW_ERROR(
        isolate,
        NewTypeError(MessageTemplate::kCalledNonCallable,
                     isolate->factory()->getPossibleInstantsFor_string()));
  }
  Handle<Object> possible_instants;
  {
    Handle<Object> argv[] = {date_time};
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, possible_instants,
        Execution::Call(isolate, function, time_zone, arraysize(argv), argv));
  }

  // Step 4-6 of GetPossibleInstantsFor is implemented inside
  // temporal_instant_fixed_array_from_iterable.
  {
    Handle<Object> argv[] = {possible_instants};
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, possible_instants,
        Execution::CallBuiltin(
            isolate, isolate->temporal_instant_fixed_array_from_iterable(),
            possible_instants, arraysize(argv), argv));
  }
  DCHECK(IsFixedArray(*possible_instants));
  // 7. Return list.
  return Cast<FixedArray>(possible_instants);
}

// #sec-temporal-disambiguatepossibleinstants
MaybeHandle<JSTemporalInstant> DisambiguatePossibleInstants(
    Isolate* isolate, Handle<FixedArray> possible_instants,
    Handle<JSReceiver> time_zone, Handle<Object> date_time_obj,
    Disambiguation disambiguation, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: dateTime has an [[InitializedTemporalDateTime]] internal slot.
  DCHECK(IsJSTemporalPlainDateTime(*date_time_obj));
  auto date_time = Cast<JSTemporalPlainDateTime>(date_time_obj);

  // 2. Let n be possibleInstants's length.
  int32_t n = possible_instants->length();

  // 3. If n = 1, then
  if (n == 1) {
    // a. Return possibleInstants[0].
    Handle<Object> ret_obj(possible_instants->get(0), isolate);
    DCHECK(IsJSTemporalInstant(*ret_obj));
    return Cast<JSTemporalInstant>(ret_obj);
  }
  // 4. If n ≠ 0, then
  if (n != 0) {
    // a. If disambiguation is "earlier" or "compatible", then
    if (disambiguation == Disambiguation::kEarlier ||
        disambiguation == Disambiguation::kCompatible) {
      // i. Return possibleInstants[0].
      Handle<Object> ret_obj(possible_instants->get(0), isolate);
      DCHECK(IsJSTemporalInstant(*ret_obj));
      return Cast<JSTemporalInstant>(ret_obj);
    }
    // b. If disambiguation is "later", then
    if (disambiguation == Disambiguation::kLater) {
      // i. Return possibleInstants[n − 1].
      Handle<Object> ret_obj(possible_instants->get(n - 1), isolate);
      DCHECK(IsJSTemporalInstant(*ret_obj));
      return Cast<JSTemporalInstant>(ret_obj);
    }
    // c. Assert: disambiguation is "reject".
    DCHECK_EQ(disambiguation, Disambiguation::kReject);
    // d. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 5. Assert: n = 0.
  DCHECK_EQ(n, 0);
  // 6. If disambiguation is "reject", then
  if (disambiguation == Disambiguation::kReject) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 7. Let epochNanoseconds be ! GetEpochFromISOParts(dateTime.[[ISOYear]],
  // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
  // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
  // dateTime.[[ISOMillisecond]], dateTime.[[ISOMicrosecond]],
  // dateTime.[[ISONanosecond]]).
  Handle<BigInt> epoch_nanoseconds = GetEpochFromISOParts(
      isolate,
      {{date_time->iso_year(), date_time->iso_month(), date_time->iso_day()},
       {date_time->iso_hour(), date_time->iso_minute(), date_time->iso_second(),
        date_time->iso_millisecond(), date_time->iso_microsecond(),
        date_time->iso_nanosecond()}});

  // 8. Let dayBeforeNs be epochNanoseconds - ℤ(nsPerDay).
  Handle<BigInt> one_day_in_ns = BigInt::FromUint64(isolate, 86400000000000ULL);
  DirectHandle<BigInt> day_before_ns =
      BigInt::Subtract(isolate, epoch_nanoseconds, one_day_in_ns)
          .ToHandleChecked();
  // 9. If ! IsValidEpochNanoseconds(dayBeforeNs) is false, throw a RangeError
  // exception.
  if (!IsValidEpochNanoseconds(isolate, day_before_ns)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 10. Let dayBefore be ! CreateTemporalInstant(dayBeforeNs).
  Handle<JSTemporalInstant> day_before =
      temporal::CreateTemporalInstant(isolate, day_before_ns).ToHandleChecked();
  // 11. Let dayAfterNs be epochNanoseconds + ℤ(nsPerDay).
  DirectHandle<BigInt> day_after_ns =
      BigInt::Add(isolate, epoch_nanoseconds, one_day_in_ns).ToHandleChecked();
  // 12. If ! IsValidEpochNanoseconds(dayAfterNs) is false, throw a RangeError
  // exception.
  if (!IsValidEpochNanoseconds(isolate, day_after_ns)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 13. Let dayAfter be ! CreateTemporalInstant(dayAfterNs).
  Handle<JSTemporalInstant> day_after =
      temporal::CreateTemporalInstant(isolate, day_after_ns).ToHandleChecked();
  // 10. Let offsetBefore be ? GetOffsetNanosecondsFor(timeZone, dayBefore).
  int64_t offset_before;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_before,
      GetOffsetNanosecondsFor(isolate, time_zone, day_before, method_name),
      Handle<JSTemporalInstant>());
  // 11. Let offsetAfter be ? GetOffsetNanosecondsFor(timeZone, dayAfter).
  int64_t offset_after;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_after,
      GetOffsetNanosecondsFor(isolate, time_zone, day_after, method_name),
      Handle<JSTemporalInstant>());

  // 12. Let nanoseconds be offsetAfter − offsetBefore.
  double nanoseconds = offset_after - offset_before;

  // 13. If disambiguation is "earlier", then
  if (disambiguation == Disambiguation::kEarlier) {
    // a. Let earlier be ? AddDateTime(dateTime.[[ISOYear]],
    // dateTime.[[ISOMonth]], dateTime.[[ISODay]], dateTime.[[ISOHour]],
    // dateTime.[[ISOMinute]], dateTime.[[ISOSecond]],
    // dateTime.[[ISOMillisecond]],
    // dateTime.[[ISOMicrosecond]], dateTime.[[ISONanosecond]],
    // dateTime.[[Calendar]], 0, 0, 0, 0, 0, 0, 0, 0, 0, −nanoseconds,
    // undefined).
    DateTimeRecord earlier;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, earlier,
        AddDateTime(
            isolate,
            {{date_time->iso_year(), date_time->iso_month(),
              date_time->iso_day()},
             {date_time->iso_hour(), date_time->iso_minute(),
              date_time->iso_second(), date_time->iso_millisecond(),
              date_time->iso_microsecond(), date_time->iso_nanosecond()}},
            handle(date_time->calendar(), isolate),
            {0, 0, 0, {0, 0, 0, 0, 0, 0, -nanoseconds}},
            isolate->factory()->undefined_value()),
        Handle<JSTemporalInstant>());
    // See https://github.com/tc39/proposal-temporal/issues/1816
    // b. Let earlierDateTime be ? CreateTemporalDateTime(earlier.[[Year]],
    // earlier.[[Month]], earlier.[[Day]], earlier.[[Hour]], earlier.[[Minute]],
    // earlier.[[Second]], earlier.[[Millisecond]], earlier.[[Microsecond]],
    // earlier.[[Nanosecond]], dateTime.[[Calendar]]).
    Handle<JSTemporalPlainDateTime> earlier_date_time;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, earlier_date_time,
        temporal::CreateTemporalDateTime(
            isolate, earlier, handle(date_time->calendar(), isolate)));

    // c. Set possibleInstants to ? GetPossibleInstantsFor(timeZone,
    // earlierDateTime).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, possible_instants,
        GetPossibleInstantsFor(isolate, time_zone, earlier_date_time));

    // d. If possibleInstants is empty, throw a RangeError exception.
    if (possible_instants->length() == 0) {
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
    }
    // e. Return possibleInstants[0].
    Handle<Object> ret_obj(possible_instants->get(0), isolate);
    DCHECK(IsJSTemporalInstant(*ret_obj));
    return Cast<JSTemporalInstant>(ret_obj);
  }
  // 14. Assert: disambiguation is "compatible" or "later".
  DCHECK(disambiguation == Disambiguation::kCompatible ||
         disambiguation == Disambiguation::kLater);
  // 15. Let later be ? AddDateTime(dateTime.[[ISOYear]], dateTime.[[ISOMonth]],
  // dateTime.[[ISODay]], dateTime.[[ISOHour]], dateTime.[[ISOMinute]],
  // dateTime.[[ISOSecond]], dateTime.[[ISOMillisecond]],
  // dateTime.[[ISOMicrosecond]], dateTime.[[ISONanosecond]],
  // dateTime.[[Calendar]], 0, 0, 0, 0, 0, 0, 0, 0, 0, nanoseconds, undefined).
  DateTimeRecord later;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, later,
      AddDateTime(isolate,
                  {{date_time->iso_year(), date_time->iso_month(),
                    date_time->iso_day()},
                   {date_time->iso_hour(), date_time->iso_minute(),
                    date_time->iso_second(), date_time->iso_millisecond(),
                    date_time->iso_microsecond(), date_time->iso_nanosecond()}},
                  handle(date_time->calendar(), isolate),
                  {0, 0, 0, {0, 0, 0, 0, 0, 0, nanoseconds}},
                  isolate->factory()->undefined_value()),
      Handle<JSTemporalInstant>());

  // See https://github.com/tc39/proposal-temporal/issues/1816
  // 16. Let laterDateTime be ? CreateTemporalDateTime(later.[[Year]],
  // later.[[Month]], later.[[Day]], later.[[Hour]], later.[[Minute]],
  // later.[[Second]], later.[[Millisecond]], later.[[Microsecond]],
  // later.[[Nanosecond]], dateTime.[[Calendar]]).

  Handle<JSTemporalPlainDateTime> later_date_time;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, later_date_time,
      temporal::CreateTemporalDateTime(isolate, later,
                                       handle(date_time->calendar(), isolate)));
  // 17. Set possibleInstants to ? GetPossibleInstantsFor(timeZone,
  // laterDateTime).
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, possible_instants,
      GetPossibleInstantsFor(isolate, time_zone, later_date_time));
  // 18. Set n to possibleInstants's length.
  n = possible_instants->length();
  // 19. If n = 0, throw a RangeError exception.
  if (n == 0) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 20. Return possibleInstants[n − 1].
  Handle<Object> ret_obj(possible_instants->get(n - 1), isolate);
  DCHECK(IsJSTemporalInstant(*ret_obj));
  return Cast<JSTemporalInstant>(ret_obj);
}

// #sec-temporal-gettemporalcalendarwithisodefault
MaybeHandle<JSReceiver> GetTemporalCalendarWithISODefault(
    Isolate* isolate, Handle<JSReceiver> item, const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 1. If item has an [[InitializedTemporalDate]],
  // [[InitializedTemporalDateTime]], [[InitializedTemporalMonthDay]],
  // [[InitializedTemporalTime]], [[InitializedTemporalYearMonth]], or
  // [[InitializedTemporalZonedDateTime]] internal slot, then a. Return
  // item.[[Calendar]].
  if (IsJSTemporalPlainDate(*item)) {
    return handle(Cast<JSTemporalPlainDate>(item)->calendar(), isolate);
  }
  if (IsJSTemporalPlainDateTime(*item)) {
    return handle(Cast<JSTemporalPlainDateTime>(item)->calendar(), isolate);
  }
  if (IsJSTemporalPlainMonthDay(*item)) {
    return handle(Cast<JSTemporalPlainMonthDay>(item)->calendar(), isolate);
  }
  if (IsJSTemporalPlainTime(*item)) {
    return handle(Cast<JSTemporalPlainTime>(item)->calendar(), isolate);
  }
  if (IsJSTemporalPlainYearMonth(*item)) {
    return handle(Cast<JSTemporalPlainYearMonth>(item)->calendar(), isolate);
  }
  if (IsJSTemporalZonedDateTime(*item)) {
    return handle(Cast<JSTemporalZonedDateTime>(item)->calendar(), isolate);
  }

  // 2. Let calendar be ? Get(item, "calendar").
  Handle<Object> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      JSReceiver::GetProperty(isolate, item, factory->calendar_string()));
  // 3. Return ? ToTemporalCalendarWithISODefault(calendar).
  return ToTemporalCalendarWithISODefault(isolate, calendar, method_name);
}

enum class RequiredFields {
  kNone,
  kTimeZone,
  kTimeZoneAndOffset,
  kDay,
  kYearAndDay
};

// The common part of PrepareTemporalFields and PreparePartialTemporalFields
// #sec-temporal-preparetemporalfields
// #sec-temporal-preparepartialtemporalfields
V8_WARN_UNUSED_RESULT MaybeHandle<JSReceiver> PrepareTemporalFieldsOrPartial(
    Isolate* isolate, Handle<JSReceiver> fields,
    DirectHandle<FixedArray> field_names, RequiredFields required,
    bool partial) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 1. Let result be OrdinaryObjectCreate(null).
  Handle<JSReceiver> result = isolate->factory()->NewJSObjectWithNullProto();
  // 2. Let any be false.
  bool any = false;
  // 3. For each value property of fieldNames, do
  int length = field_names->length();
  for (int i = 0; i < length; i++) {
    Handle<Object> property_obj(field_names->get(i), isolate);
    Handle<String> property = Cast<String>(property_obj);
    // a. Let value be ? Get(fields, property).
    Handle<Object> value;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, value, JSReceiver::GetProperty(isolate, fields, property));

    // b. If value is undefined, then
    if (IsUndefined(*value)) {
      // This part is only for PrepareTemporalFields
      // Skip for the case of PreparePartialTemporalFields.
      if (partial) continue;

      // i. If requiredFields contains property, then
      if (((required == RequiredFields::kDay ||
            required == RequiredFields::kYearAndDay) &&
           String::Equals(isolate, property, factory->day_string())) ||
          ((required == RequiredFields::kTimeZone ||
            required == RequiredFields::kTimeZoneAndOffset) &&
           String::Equals(isolate, property, factory->timeZone_string())) ||
          (required == RequiredFields::kTimeZoneAndOffset &&
           String::Equals(isolate, property, factory->offset_string())) ||
          (required == RequiredFields::kYearAndDay &&
           String::Equals(isolate, property, factory->year_string()))) {
        // 1. Throw a TypeError exception.
        THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
      }
      // ii. Else,
      // 1. If property is in the Property column of Table 13, then
      // a. Set value to the corresponding Default value of the same row.
      if (String::Equals(isolate, property, factory->hour_string()) ||
          String::Equals(isolate, property, factory->minute_string()) ||
          String::Equals(isolate, property, factory->second_string()) ||
          String::Equals(isolate, property, factory->millisecond_string()) ||
          String::Equals(isolate, property, factory->microsecond_string()) ||
          String::Equals(isolate, property, factory->nanosecond_string())) {
        value = Handle<Object>(Smi::zero(), isolate);
      }
    } else {
      // For both PrepareTemporalFields and PreparePartialTemporalFields
      any = partial;
      // c. Else,
      // i. If property is in the Property column of Table 13 and there is a
      // Conversion value in the same row, then
      // 1. Let Conversion represent the abstract operation named by the
      // Conversion value of the same row.
      // 2. Set value to ? Conversion(value).
      if (String::Equals(isolate, property, factory->month_string()) ||
          String::Equals(isolate, property, factory->day_string())) {
        ASSIGN_RETURN_ON_EXCEPTION(isolate, value,
                                   ToPositiveInteger(isolate, value));
      } else if (String::Equals(isolate, property, factory->year_string()) ||
                 String::Equals(isolate, property, factory->hour_string()) ||
                 String::Equals(isolate, property, factory->minute_string()) ||
                 String::Equals(isolate, property, factory->second_string()) ||
                 String::Equals(isolate, property,
                                factory->millisecond_string()) ||
                 String::Equals(isolate, property,
                                factory->microsecond_string()) ||
                 String::Equals(isolate, property,
                                factory->nanosecond_string()) ||
                 String::Equals(isolate, property, factory->eraYear_string())) {
        ASSIGN_RETURN_ON_EXCEPTION(isolate, value,
                                   ToIntegerThrowOnInfinity(isolate, value));
      } else if (String::Equals(isolate, property,
                                factory->monthCode_string()) ||
                 String::Equals(isolate, property, factory->offset_string()) ||
                 String::Equals(isolate, property, factory->era_string())) {
        ASSIGN_RETURN_ON_EXCEPTION(isolate, value,
                                   Object::ToString(isolate, value));
      }
    }

    // d. Perform ! CreateDataPropertyOrThrow(result, property, value).
    CHECK(JSReceiver::CreateDataProperty(isolate, result, property, value,
                                         Just(kThrowOnError))
              .FromJust());
  }

  // Only for PreparePartialTemporalFields
  if (partial) {
    // 5. If any is false, then
    if (!any) {
      // a. Throw a TypeError exception.
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
    }
  }
  // 4. Return result.
  return result;
}

// #sec-temporal-preparetemporalfields
V8_WARN_UNUSED_RESULT MaybeHandle<JSReceiver> PrepareTemporalFields(
    Isolate* isolate, Handle<JSReceiver> fields,
    DirectHandle<FixedArray> field_names, RequiredFields required) {
  TEMPORAL_ENTER_FUNC();

  return PrepareTemporalFieldsOrPartial(isolate, fields, field_names, required,
                                        false);
}

// #sec-temporal-preparepartialtemporalfields
V8_WARN_UNUSED_RESULT MaybeHandle<JSReceiver> PreparePartialTemporalFields(
    Isolate* isolate, Handle<JSReceiver> fields,
    DirectHandle<FixedArray> field_names) {
  TEMPORAL_ENTER_FUNC();

  return PrepareTemporalFieldsOrPartial(isolate, fields, field_names,
                                        RequiredFields::kNone, true);
}

// Template for DateFromFields, YearMonthFromFields, and MonthDayFromFields
template <typename T>
MaybeHandle<T> FromFields(Isolate* isolate, Handle<JSReceiver> calendar,
                          Handle<JSReceiver> fields, Handle<Object> options,
                          Handle<String> property, InstanceType type) {
  Handle<Object> function;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, function,
                             Object::GetProperty(isolate, calendar, property));
  if (!IsCallable(*function)) {
    THROW_NEW_ERROR(
        isolate, NewTypeError(MessageTemplate::kCalledNonCallable, property));
  }
  Handle<Object> argv[] = {fields, options};
  Handle<Object> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result, Execution::Call(isolate, function, calendar, 2, argv));
  if ((!IsHeapObject(*result)) ||
      Cast<HeapObject>(*result)->map()->instance_type() != type) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  return Cast<T>(result);
}

// #sec-temporal-datefromfields
MaybeHandle<JSTemporalPlainDate> DateFromFields(Isolate* isolate,
                                                Handle<JSReceiver> calendar,
                                                Handle<JSReceiver> fields,
                                                Handle<Object> options) {
  return FromFields<JSTemporalPlainDate>(
      isolate, calendar, fields, options,
      isolate->factory()->dateFromFields_string(), JS_TEMPORAL_PLAIN_DATE_TYPE);
}

// #sec-temporal-yearmonthfromfields
MaybeHandle<JSTemporalPlainYearMonth> YearMonthFromFields(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<JSReceiver> fields,
    Handle<Object> options) {
  return FromFields<JSTemporalPlainYearMonth>(
      isolate, calendar, fields, options,
      isolate->factory()->yearMonthFromFields_string(),
      JS_TEMPORAL_PLAIN_YEAR_MONTH_TYPE);
}
MaybeHandle<JSTemporalPlainYearMonth> YearMonthFromFields(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<JSReceiver> fields) {
  // 1. If options is not present, set options to undefined.
  return YearMonthFromFields(isolate, calendar, fields,
                             isolate->factory()->undefined_value());
}

// #sec-temporal-monthdayfromfields
MaybeHandle<JSTemporalPlainMonthDay> MonthDayFromFields(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<JSReceiver> fields,
    Handle<Object> options) {
  return FromFields<JSTemporalPlainMonthDay>(
      isolate, calendar, fields, options,
      isolate->factory()->monthDayFromFields_string(),
      JS_TEMPORAL_PLAIN_MONTH_DAY_TYPE);
}
MaybeHandle<JSTemporalPlainMonthDay> MonthDayFromFields(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<JSReceiver> fields) {
  // 1. If options is not present, set options to undefined.
  return MonthDayFromFields(isolate, calendar, fields,
                            isolate->factory()->undefined_value());
}

// #sec-temporal-totemporaloverflow
Maybe<ShowOverflow> ToTemporalOverflow(Isolate* isolate, Handle<Object> options,
                                       const char* method_name) {
  // 1. If options is undefined, return "constrain".
  if (IsUndefined(*options)) return Just(ShowOverflow::kConstrain);
  DCHECK(IsJSReceiver(*options));
  // 2. Return ? GetOption(options, "overflow", « String », « "constrain",
  // "reject" », "constrain").
  return GetStringOption<ShowOverflow>(
      isolate, Cast<JSReceiver>(options), "overflow", method_name,
      {"constrain", "reject"},
      {ShowOverflow::kConstrain, ShowOverflow::kReject},
      ShowOverflow::kConstrain);
}

// #sec-temporal-totemporaloffset
Maybe<Offset> ToTemporalOffset(Isolate* isolate, Handle<Object> options,
                               Offset fallback, const char* method_name) {
  // 1. If options is undefined, return fallback.
  if (IsUndefined(*options)) return Just(fallback);
  DCHECK(IsJSReceiver(*options));

  // 2. Return ? GetOption(options, "offset", « String », « "prefer", "use",
  // "ignore", "reject" », fallback).
  return GetStringOption<Offset>(
      isolate, Cast<JSReceiver>(options), "offset", method_name,
      {"prefer", "use", "ignore", "reject"},
      {Offset::kPrefer, Offset::kUse, Offset::kIgnore, Offset::kReject},
      fallback);
}

// #sec-temporal-totemporaldisambiguation
Maybe<Disambiguation> ToTemporalDisambiguation(Isolate* isolate,
                                               Handle<Object> options,
                                               const char* method_name) {
  // 1. If options is undefined, return "compatible".
  if (IsUndefined(*options)) return Just(Disambiguation::kCompatible);
  DCHECK(IsJSReceiver(*options));
  // 2. Return ? GetOption(options, "disambiguation", « String », «
  // "compatible", "earlier", "later", "reject" », "compatible").
  return GetStringOption<Disambiguation>(
      isolate, Cast<JSReceiver>(options), "disambiguation", method_name,
      {"compatible", "earlier", "later", "reject"},
      {Disambiguation::kCompatible, Disambiguation::kEarlier,
       Disambiguation::kLater, Disambiguation::kReject},
      Disambiguation::kCompatible);
}

// #sec-temporal-builtintimezonegetinstantfor
MaybeHandle<JSTemporalInstant> BuiltinTimeZoneGetInstantFor(
    Isolate* isolate, Handle<JSReceiver> time_zone,
    Handle<JSTemporalPlainDateTime> date_time, Disambiguation disambiguation,
    const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: dateTime has an [[InitializedTemporalDateTime]] internal slot.
  // 2. Let possibleInstants be ? GetPossibleInstantsFor(timeZone, dateTime).
  Handle<FixedArray> possible_instants;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, possible_instants,
      GetPossibleInstantsFor(isolate, time_zone, date_time));
  // 3. Return ? DisambiguatePossibleInstants(possibleInstants, timeZone,
  // dateTime, disambiguation).
  return DisambiguatePossibleInstants(isolate, possible_instants, time_zone,
                                      date_time, disambiguation, method_name);
}

// #sec-temporal-totemporalinstant
MaybeHandle<JSTemporalInstant> ToTemporalInstant(Isolate* isolate,
                                                 Handle<Object> item,
                                                 const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  // 1. If Type(item) is Object, then
  // a. If item has an [[InitializedTemporalInstant]] internal slot, then
  if (IsJSTemporalInstant(*item)) {
    // i. Return item.
    return Cast<JSTemporalInstant>(item);
  }
  // b. If item has an [[InitializedTemporalZonedDateTime]] internal slot, then
  if (IsJSTemporalZonedDateTime(*item)) {
    // i. Return ! CreateTemporalInstant(item.[[Nanoseconds]]).
    DirectHandle<BigInt> nanoseconds(
        Cast<JSTemporalZonedDateTime>(*item)->nanoseconds(), isolate);
    return temporal::CreateTemporalInstant(isolate, nanoseconds)
        .ToHandleChecked();
  }
  // 2. Let string be ? ToString(item).
  Handle<String> string;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, string, Object::ToString(isolate, item));

  // 3. Let epochNanoseconds be ? ParseTemporalInstant(string).
  Handle<BigInt> epoch_nanoseconds;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, epoch_nanoseconds,
                             ParseTemporalInstant(isolate, string));

  // 4. Return ? CreateTemporalInstant(ℤ(epochNanoseconds)).
  return temporal::CreateTemporalInstant(isolate, epoch_nanoseconds);
}

}  // namespace

namespace temporal {
// #sec-temporal-totemporalcalendar
MaybeHandle<JSReceiver> ToTemporalCalendar(
    Isolate* isolate, Handle<Object> temporal_calendar_like,
    const char* method_name) {
  Factory* factory = isolate->factory();
  // 1.If Type(temporalCalendarLike) is Object, then
  if (IsJSReceiver(*temporal_calendar_like)) {
    // a. If temporalCalendarLike has an [[InitializedTemporalDate]],
    // [[InitializedTemporalDateTime]], [[InitializedTemporalMonthDay]],
    // [[InitializedTemporalTime]], [[InitializedTemporalYearMonth]], or
    // [[InitializedTemporalZonedDateTime]] internal slot, then i. Return
    // temporalCalendarLike.[[Calendar]].

#define EXTRACT_CALENDAR(T, obj)                                  \
  if (IsJSTemporal##T(*obj)) {                                    \
    return handle(Cast<JSTemporal##T>(obj)->calendar(), isolate); \
  }

    EXTRACT_CALENDAR(PlainDate, temporal_calendar_like)
    EXTRACT_CALENDAR(PlainDateTime, temporal_calendar_like)
    EXTRACT_CALENDAR(PlainMonthDay, temporal_calendar_like)
    EXTRACT_CALENDAR(PlainTime, temporal_calendar_like)
    EXTRACT_CALENDAR(PlainYearMonth, temporal_calendar_like)
    EXTRACT_CALENDAR(ZonedDateTime, temporal_calendar_like)

#undef EXTRACT_CALENDAR
    Handle<JSReceiver> obj = Cast<JSReceiver>(temporal_calendar_like);

    // b. If ? HasProperty(temporalCalendarLike, "calendar") is false, return
    // temporalCalendarLike.
    bool has;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, has,
        JSReceiver::HasProperty(isolate, obj, factory->calendar_string()),
        Handle<JSReceiver>());
    if (!has) {
      return obj;
    }
    // c.  Set temporalCalendarLike to ? Get(temporalCalendarLike, "calendar").
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, temporal_calendar_like,
        JSReceiver::GetProperty(isolate, obj, factory->calendar_string()));
    // d. If Type(temporalCalendarLike) is Object
    if (IsJSReceiver(*temporal_calendar_like)) {
      obj = Cast<JSReceiver>(temporal_calendar_like);
      // and ? HasProperty(temporalCalendarLike, "calendar") is false,
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, has,
          JSReceiver::HasProperty(isolate, obj, factory->calendar_string()),
          Handle<JSReceiver>());
      if (!has) {
        // return temporalCalendarLike.
        return obj;
      }
    }
  }

  // 2. Let identifier be ? ToString(temporalCalendarLike).
  Handle<String> identifier;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, identifier,
                             Object::ToString(isolate, temporal_calendar_like));
  // 3. Let identifier be ? ParseTemporalCalendarString(identifier).
  ASSIGN_RETURN_ON_EXCEPTION(isolate, identifier,
                             ParseTemporalCalendarString(isolate, identifier));
  // 4. If IsBuiltinCalendar(identifier) is false, throw a RangeError
  // exception.
  if (!IsBuiltinCalendar(isolate, identifier)) {
    THROW_NEW_ERROR(
```