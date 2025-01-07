Response:
The user wants a summary of the functionality of the provided C++ source code file `v8/src/objects/js-temporal-objects.cc`. I need to analyze the code and identify its purpose and key functionalities.

Here's a breakdown of the code's content:

1. **Includes:** The file includes various V8 headers related to objects, dates, execution, heap, and potentially internationalization (`V8_INTL_SUPPORT`). It also includes a header for "temporal" functionality, hinting at its primary purpose.

2. **Namespaces:** The code is within the `v8::internal` namespace.

3. **Enums and Structs:** The file defines several enums and structs. These likely represent the data structures and states used in the Temporal API implementation. Examples include `Unit`, `Disambiguation`, `RoundingMode`, and structs like `UnbalancedTimeRecord`, `DateRecord`, `DurationRecord`, etc.

4. **Abstract Operations (Declared):** The code declares several functions without providing their implementation. These declarations, along with the descriptive names and the "Abstract Operations" comment, strongly suggest that this file defines the interface and data structures for implementing the ECMAScript Temporal API within V8.

5. **Helper Functions:** There are helper functions for parsing ISO 8601 strings, performing date/time calculations, and interacting with the V8 runtime environment (e.g., `SystemUTCEpochNanoseconds`, `CreateTemporalCalendar`).

6. **Constructor-like Functions:** Functions starting with `CreateTemporal...` suggest the creation of JavaScript Temporal objects within the V8 engine.

7. **Error Handling Macros:** Macros like `NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR` and `THROW_INVALID_RANGE` indicate how errors related to the Temporal API are handled.

8. **Conditional Compilation:** The `#ifdef V8_INTL_SUPPORT` block indicates that some functionality is dependent on whether internationalization support is enabled in the V8 build.

Based on this analysis, the primary function of this file is to define the internal C++ representation and fundamental operations for the ECMAScript Temporal API within the V8 JavaScript engine.

Regarding the specific questions in the prompt:

*   **`.tq` extension:** The filename ends in `.cc`, not `.tq`. Therefore, it's a regular C++ source file, not a Torque file.
*   **Relationship to JavaScript:** The file is directly related to JavaScript as it implements the Temporal API, which is a set of JavaScript built-in objects for working with dates and times.
*   **Code Logic Reasoning:**  The code defines many functions for date/time calculations and comparisons. To illustrate this with input/output, consider `BalanceISODate`. If the input is a `DateRecord` with `year=2024, month=13, day=1`, the output should be a `DateRecord` with `year=2025, month=1, day=1`, assuming standard Gregorian calendar rules.
*   **Common Programming Errors:**  Users might make mistakes when providing invalid date or time values to Temporal API functions (e.g., month 13, day 32 for a given month). The V8 implementation needs to handle these errors, likely throwing `RangeError` exceptions as suggested by the macros.

Now, I need to synthesize this information into a concise summary that answers the user's request for the file's functionality.
`v8/src/objects/js-temporal-objects.cc` 是 V8 JavaScript 引擎的源代码文件，它主要负责 **实现 ECMAScript Temporal API 的内部对象和相关操作**。

以下是该文件功能的归纳：

1. **定义 Temporal API 的内部数据结构:**  文件中定义了各种 `struct`，用于表示 Temporal API 中涉及的日期、时间、时区、持续时间等概念。例如：
    *   `DateRecord`, `TimeRecord`, `DateTimeRecord`: 用于存储日期和时间的不同部分。
    *   `TimeZoneRecord`: 用于表示时区信息。
    *   `DurationRecord`: 用于表示时间间隔。
    *   `DateRecordWithCalendar`, `TimeRecordWithCalendar`, `DateTimeRecordWithCalendar`: 包含了日期/时间和关联的日历信息。

2. **声明 Temporal API 的抽象操作:** 文件中声明了许多函数，这些函数对应着 Temporal 规范中定义的抽象操作。这些操作涵盖了 Temporal API 的核心功能，例如：
    *   日期和时间的创建、比较、加减运算。
    *   时区的处理和转换。
    *   持续时间的计算和平衡。
    *   ISO 8601 格式字符串的解析和格式化。
    *   与日历相关的操作。

3. **定义用于控制 Temporal API 行为的选项:** 文件中定义了各种 `enum class`，用于表示 Temporal API 中各种选项的取值，例如：
    *   `Disambiguation`: 用于处理时间上的歧义。
    *   `ShowOverflow`: 用于控制溢出行为。
    *   `RoundingMode`: 用于指定舍入模式。
    *   `Unit`:  用于表示时间单位（年、月、日、小时等）。

4. **提供创建 Temporal 对象的内部函数:** 文件中包含了以 `CreateTemporal...` 开头的函数，这些函数负责在 V8 引擎内部创建对应的 JavaScript Temporal 对象实例，例如 `CreateTemporalDate`, `CreateTemporalDateTime`, `CreateTemporalCalendar` 等。

5. **包含与日期和时间计算相关的辅助函数:** 文件中还包含了一些用于日期和时间计算的底层辅助函数，例如 `BalanceISODate`, `DifferenceTime`, `AddTime` 等。

**关于你的其他问题:**

*   **`.tq` 结尾:** `v8/src/objects/js-temporal-objects.cc` 以 `.cc` 结尾，因此它是 **V8 的 C++ 源代码文件**，而不是 Torque 源代码文件。Torque 文件通常用于定义 V8 的内置函数和对象。

*   **与 JavaScript 的关系及示例:**  `v8/src/objects/js-temporal-objects.cc` 中定义的 C++ 代码是 **ECMAScript Temporal API 在 V8 引擎中的底层实现**。JavaScript 代码通过调用这些底层的 C++ 函数来使用 Temporal API 的功能。

    ```javascript
    // JavaScript 示例：使用 Temporal API
    const plainDate = new Temporal.PlainDate(2024, 10, 26);
    console.log(plainDate.year); // 输出 2024
    console.log(plainDate.toString()); // 输出 "2024-10-26"

    const today = Temporal.Now.plainDateISO();
    const tomorrow = today.add({ days: 1 });
    console.log(tomorrow.toString());

    const duration = new Temporal.Duration(0, 1, 0); // 1 个月
    const nextMonth = plainDate.add(duration);
    console.log(nextMonth.toString());
    ```

    在这个 JavaScript 示例中，当我们创建 `Temporal.PlainDate` 对象或调用其方法时，V8 引擎会调用 `v8/src/objects/js-temporal-objects.cc` 中相应的 C++ 函数来执行操作。例如，创建 `Temporal.PlainDate` 可能会调用 `CreateTemporalDate` 函数。

*   **代码逻辑推理 (假设输入与输出):**

    假设我们调用一个内部函数 `BalanceISODate`，该函数负责调整日期，例如将无效的月份调整到正确的年份和月份。

    **假设输入:**  一个 `DateRecord` 结构体，表示 `2025年 0月 15日` （月份为 0，显然无效）。
    ```c++
    DateRecord input_date = {2025, 0, 15};
    ```

    **预期输出:**  `BalanceISODate` 函数会调整月份，输出的 `DateRecord` 结构体应该表示前一年的 12 月。由于日期是 15，所以结果是 `2024年 12月 15日`。
    ```c++
    // (调用 BalanceISODate 函数)
    // 输出: DateRecord output_date = {2024, 12, 15};
    ```

*   **用户常见的编程错误:**

    用户在使用 Temporal API 时，常见的错误包括：

    *   **提供无效的日期或时间值:** 例如创建 `Temporal.PlainDate(2024, 13, 1)` (月份超出范围) 或 `Temporal.PlainTime(25, 0, 0)` (小时超出范围)。V8 的 C++ 代码会进行校验，并抛出 `RangeError` 异常。

        ```javascript
        try {
          const invalidDate = new Temporal.PlainDate(2024, 13, 1);
        } catch (e) {
          console.error(e); // 输出 RangeError
        }
        ```

    *   **时区处理不当:**  在处理跨时区的日期和时间时，用户可能会混淆本地时间和 UTC 时间，或者错误地使用时区标识符。

    *   **对不同类型的 Temporal 对象进行不兼容的操作:**  例如，尝试直接比较 `Temporal.PlainDate` 和 `Temporal.ZonedDateTime` 对象，而没有先将它们转换为相同的时区。

**总结：**

`v8/src/objects/js-temporal-objects.cc` 是 V8 引擎中实现 ECMAScript Temporal API 的核心 C++ 代码，它定义了内部数据结构、抽象操作和创建函数，为 JavaScript 中的 Temporal API 功能提供了底层的实现基础。它确保了 Temporal API 的正确性和性能，并处理了用户可能遇到的各种错误情况。

Prompt: 
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共25部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/js-temporal-objects.h"

#include <optional>
#include <set>

#include "src/common/globals.h"
#include "src/date/date.h"
#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/numbers/conversions-inl.h"
#include "src/objects/js-objects-inl.h"
#include "src/objects/js-objects.h"
#include "src/objects/js-temporal-objects-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/option-utils.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/string-set.h"
#include "src/strings/string-builder-inl.h"
#include "src/temporal/temporal-parser.h"

#ifdef V8_INTL_SUPPORT
#include "src/objects/intl-objects.h"
#include "src/objects/js-date-time-format.h"
#include "src/objects/managed-inl.h"
#include "unicode/calendar.h"
#include "unicode/unistr.h"
#endif  // V8_INTL_SUPPORT

namespace v8::internal {

namespace {

enum class Unit {
  kNotPresent,
  kAuto,
  kYear,
  kMonth,
  kWeek,
  kDay,
  kHour,
  kMinute,
  kSecond,
  kMillisecond,
  kMicrosecond,
  kNanosecond
};

/**
 * This header declare the Abstract Operations defined in the
 * Temporal spec with the enum and struct for them.
 */

// Struct

// only for BalanceTime
struct UnbalancedTimeRecord {
  double hour;
  double minute;
  double second;
  double millisecond;
  double microsecond;
  double nanosecond;
};

using temporal::DateRecord;
using temporal::DateTimeRecord;
using temporal::TimeRecord;

struct DateRecordWithCalendar {
  DateRecord date;
  Handle<Object> calendar;  // String or Undefined
};

struct TimeRecordWithCalendar {
  TimeRecord time;
  Handle<Object> calendar;  // String or Undefined
};

struct TimeZoneRecord {
  bool z;
  Handle<Object> offset_string;  // String or Undefined
  Handle<Object> name;           // String or Undefined
};

struct DateTimeRecordWithCalendar {
  DateRecord date;
  TimeRecord time;
  TimeZoneRecord time_zone;
  Handle<Object> calendar;  // String or Undefined
};

struct InstantRecord {
  DateRecord date;
  TimeRecord time;
  Handle<Object> offset_string;  // String or Undefined
};

using temporal::DurationRecord;
using temporal::IsValidDuration;
using temporal::TimeDurationRecord;

struct DurationRecordWithRemainder {
  DurationRecord record;
  double remainder;
};

// #sec-temporal-date-duration-records
struct DateDurationRecord {
  double years;
  double months;
  double weeks;
  double days;
  // #sec-temporal-createdatedurationrecord
  static Maybe<DateDurationRecord> Create(Isolate* isolate, double years,
                                          double months, double weeks,
                                          double days);
};

// Options

V8_WARN_UNUSED_RESULT Handle<String> UnitToString(Isolate* isolate, Unit unit);

// #sec-temporal-totemporaldisambiguation
enum class Disambiguation { kCompatible, kEarlier, kLater, kReject };

// #sec-temporal-totemporaloverflow
enum class ShowOverflow { kConstrain, kReject };
// #sec-temporal-toshowcalendaroption
enum class ShowCalendar { kAuto, kAlways, kNever };

// #sec-temporal-toshowtimezonenameoption
enum class ShowTimeZone { kAuto, kNever };
Maybe<ShowTimeZone> ToShowTimeZoneNameOption(Isolate* isolate,
                                             Handle<JSReceiver> options,
                                             const char* method_name) {
  // 1. Return ? GetOption(normalizedOptions, "timeZoneName", "string", «
  // "auto", "never" », "auto").
  return GetStringOption<ShowTimeZone>(
      isolate, options, "timeZoneName", method_name, {"auto", "never"},
      {ShowTimeZone::kAuto, ShowTimeZone::kNever}, ShowTimeZone::kAuto);
}

// #sec-temporal-toshowoffsetoption
enum class ShowOffset { kAuto, kNever };
Maybe<ShowOffset> ToShowOffsetOption(Isolate* isolate,
                                     Handle<JSReceiver> options,
                                     const char* method_name) {
  // 1. Return ? GetOption(normalizedOptions, "offset", "string", « "auto",
  // "never" », "auto").
  return GetStringOption<ShowOffset>(
      isolate, options, "offset", method_name, {"auto", "never"},
      {ShowOffset::kAuto, ShowOffset::kNever}, ShowOffset::kAuto);
}

enum class Precision { k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, kAuto, kMinute };

// Enum for add/subtract
enum class Arithmetic { kAdd, kSubtract };

// Enum for since/until
enum class TimePreposition { kSince, kUntil };

enum class Offset { kPrefer, kUse, kIgnore, kReject };
V8_WARN_UNUSED_RESULT Maybe<Offset> ToTemporalOffset(Isolate* isolate,
                                                     Handle<Object> options,
                                                     Offset fallback,
                                                     const char* method_name);

// sec-temporal-totemporalroundingmode
enum class RoundingMode {
  kCeil,
  kFloor,
  kExpand,
  kTrunc,
  kHalfCeil,
  kHalfFloor,
  kHalfExpand,
  kHalfTrunc,
  kHalfEven
};
// #table-temporal-unsigned-rounding-modes
enum class UnsignedRoundingMode {
  kInfinity,
  kZero,
  kHalfInfinity,
  kHalfZero,
  kHalfEven
};

enum class MatchBehaviour { kMatchExactly, kMatchMinutes };

// #sec-temporal-gettemporalunit
enum class UnitGroup {
  kDate,
  kTime,
  kDateTime,
};

struct DifferenceSettings {
  Unit smallest_unit;
  Unit largest_unit;
  RoundingMode rounding_mode;
  double rounding_increment;
  Handle<JSReceiver> options;
};
enum class DisallowedUnitsInDifferenceSettings {
  kNone,
  kWeekAndDay,
};
Maybe<DifferenceSettings> GetDifferenceSettings(
    Isolate* isolate, TimePreposition operation, Handle<Object> options,
    UnitGroup unit_group, DisallowedUnitsInDifferenceSettings disallowed_units,
    Unit fallback_smallest_unit, Unit smallest_largest_default_unit,
    const char* method_name);

// #sec-temporal-totemporaloffset
// ISO8601 String Parsing

// #sec-temporal-parsetemporalcalendarstring
V8_WARN_UNUSED_RESULT MaybeHandle<String> ParseTemporalCalendarString(
    Isolate* isolate, Handle<String> iso_string);

// #sec-temporal-parsetemporaldatetimestring
V8_WARN_UNUSED_RESULT Maybe<DateTimeRecordWithCalendar>
ParseTemporalDateTimeString(Isolate* isolate, Handle<String> iso_string);

// #sec-temporal-parsetemporaldatestring
V8_WARN_UNUSED_RESULT Maybe<DateRecordWithCalendar> ParseTemporalDateString(
    Isolate* isolate, Handle<String> iso_string);

// #sec-temporal-parsetemporaltimestring
Maybe<TimeRecordWithCalendar> ParseTemporalTimeString(
    Isolate* isolate, Handle<String> iso_string);

// #sec-temporal-parsetemporaldurationstring
V8_WARN_UNUSED_RESULT Maybe<DurationRecord> ParseTemporalDurationString(
    Isolate* isolate, Handle<String> iso_string);

// #sec-temporal-parsetemporaltimezonestring
V8_WARN_UNUSED_RESULT Maybe<TimeZoneRecord> ParseTemporalTimeZoneString(
    Isolate* isolate, Handle<String> iso_string);

// #sec-temporal-parsetimezoneoffsetstring
V8_WARN_UNUSED_RESULT Maybe<int64_t> ParseTimeZoneOffsetString(
    Isolate* isolate, Handle<String> offset_string);

// #sec-temporal-parsetemporalinstant
V8_WARN_UNUSED_RESULT MaybeHandle<BigInt> ParseTemporalInstant(
    Isolate* isolate, Handle<String> iso_string);
V8_WARN_UNUSED_RESULT MaybeHandle<BigInt> ParseTemporalInstant(
    Isolate* isolate, Handle<String> iso_string);

DateRecord BalanceISODate(Isolate* isolate, const DateRecord& date);

// Math and Misc

V8_WARN_UNUSED_RESULT MaybeHandle<BigInt> AddInstant(
    Isolate* isolate, Handle<BigInt> epoch_nanoseconds,
    const TimeDurationRecord& addend);

// #sec-temporal-balanceduration
V8_WARN_UNUSED_RESULT Maybe<TimeDurationRecord> BalanceDuration(
    Isolate* isolate, Unit largest_unit, Handle<Object> relative_to,
    const TimeDurationRecord& duration, const char* method_name);
// The special case of BalanceDuration while the nanosecond is a large value
// and the rest are 0.
V8_WARN_UNUSED_RESULT Maybe<TimeDurationRecord> BalanceDuration(
    Isolate* isolate, Unit largest_unit, Handle<BigInt> nanoseconds,
    const char* method_name);
// A special version of BalanceDuration which add two TimeDurationRecord
// internally as BigInt to avoid overflow double.
V8_WARN_UNUSED_RESULT Maybe<TimeDurationRecord> BalanceDuration(
    Isolate* isolate, Unit largest_unit, const TimeDurationRecord& dur1,
    const TimeDurationRecord& dur2, const char* method_name);

// sec-temporal-balancepossiblyinfiniteduration
enum BalanceOverflow {
  kNone,
  kPositive,
  kNegative,
};
struct BalancePossiblyInfiniteDurationResult {
  TimeDurationRecord value;
  BalanceOverflow overflow;
};
V8_WARN_UNUSED_RESULT Maybe<BalancePossiblyInfiniteDurationResult>
BalancePossiblyInfiniteDuration(Isolate* isolate, Unit largest_unit,
                                Handle<Object> relative_to,
                                const TimeDurationRecord& duration,
                                const char* method_name);

// The special case of BalancePossiblyInfiniteDuration while the nanosecond is a
// large value and days contains non-zero values but the rest are 0.
// This version has no relative_to.
V8_WARN_UNUSED_RESULT Maybe<BalancePossiblyInfiniteDurationResult>
BalancePossiblyInfiniteDuration(Isolate* isolate, Unit largest_unit,
                                Handle<Object> relative_to, double days,
                                Handle<BigInt> nanoseconds,
                                const char* method_name);
V8_WARN_UNUSED_RESULT Maybe<BalancePossiblyInfiniteDurationResult>
BalancePossiblyInfiniteDuration(Isolate* isolate, Unit largest_unit,
                                double days, Handle<BigInt> nanoseconds,
                                const char* method_name) {
  return BalancePossiblyInfiniteDuration(isolate, largest_unit,
                                         isolate->factory()->undefined_value(),
                                         days, nanoseconds, method_name);
}

V8_WARN_UNUSED_RESULT Maybe<DurationRecord> DifferenceISODateTime(
    Isolate* isolate, const DateTimeRecord& date_time1,
    const DateTimeRecord& date_time2, Handle<JSReceiver> calendar,
    Unit largest_unit, Handle<JSReceiver> relative_to, const char* method_name);

// #sec-temporal-adddatetime
V8_WARN_UNUSED_RESULT Maybe<DateTimeRecord> AddDateTime(
    Isolate* isolate, const DateTimeRecord& date_time,
    Handle<JSReceiver> calendar, const DurationRecord& addend,
    Handle<Object> options);

// #sec-temporal-addzoneddatetime
V8_WARN_UNUSED_RESULT MaybeHandle<BigInt> AddZonedDateTime(
    Isolate* isolate, Handle<BigInt> eopch_nanoseconds,
    Handle<JSReceiver> time_zone, Handle<JSReceiver> calendar,
    const DurationRecord& addend, const char* method_name);

V8_WARN_UNUSED_RESULT MaybeHandle<BigInt> AddZonedDateTime(
    Isolate* isolate, Handle<BigInt> eopch_nanoseconds,
    Handle<JSReceiver> time_zone, Handle<JSReceiver> calendar,
    const DurationRecord& addend, Handle<Object> options,
    const char* method_name);

// #sec-temporal-isvalidepochnanoseconds
bool IsValidEpochNanoseconds(Isolate* isolate,
                             DirectHandle<BigInt> epoch_nanoseconds);

struct NanosecondsToDaysResult {
  double days;
  double nanoseconds;
  int64_t day_length;
};

// #sec-temporal-nanosecondstodays
V8_WARN_UNUSED_RESULT Maybe<NanosecondsToDaysResult> NanosecondsToDays(
    Isolate* isolate, Handle<BigInt> nanoseconds,
    Handle<Object> relative_to_obj, const char* method_name);

// #sec-temporal-interpretisodatetimeoffset
enum class OffsetBehaviour { kOption, kExact, kWall };

// sec-temporal-totemporalroundingmode
Maybe<RoundingMode> ToTemporalRoundingMode(Isolate* isolate,
                                           Handle<JSReceiver> options,
                                           RoundingMode fallback,
                                           const char* method_name) {
  // 1. Return ? GetOption(normalizedOptions, "roundingMode", "string", «
  // "ceil", "floor", "expand", "trunc", "halfCeil", "halfFloor", "halfExpand",
  // "halfTrunc", "halfEven" », fallback).

  return GetStringOption<RoundingMode>(
      isolate, options, "roundingMode", method_name,
      {"ceil", "floor", "expand", "trunc", "halfCeil", "halfFloor",
       "halfExpand", "halfTrunc", "halfEven"},
      {RoundingMode::kCeil, RoundingMode::kFloor, RoundingMode::kExpand,
       RoundingMode::kTrunc, RoundingMode::kHalfCeil, RoundingMode::kHalfFloor,
       RoundingMode::kHalfExpand, RoundingMode::kHalfTrunc,
       RoundingMode::kHalfEven},
      fallback);
}

V8_WARN_UNUSED_RESULT
Handle<BigInt> GetEpochFromISOParts(Isolate* isolate,
                                    const DateTimeRecord& date_time);

// #sec-temporal-isodaysinmonth
int32_t ISODaysInMonth(Isolate* isolate, int32_t year, int32_t month);

// #sec-temporal-isodaysinyear
int32_t ISODaysInYear(Isolate* isolate, int32_t year);

bool IsValidTime(Isolate* isolate, const TimeRecord& time);

// #sec-temporal-isvalidisodate
bool IsValidISODate(Isolate* isolate, const DateRecord& date);

// #sec-temporal-compareisodate
int32_t CompareISODate(const DateRecord& date1, const DateRecord& date2);

// #sec-temporal-balanceisoyearmonth
void BalanceISOYearMonth(Isolate* isolate, int32_t* year, int32_t* month);

// #sec-temporal-balancetime
V8_WARN_UNUSED_RESULT DateTimeRecord
BalanceTime(const UnbalancedTimeRecord& time);

// #sec-temporal-differencetime
V8_WARN_UNUSED_RESULT Maybe<TimeDurationRecord> DifferenceTime(
    Isolate* isolate, const TimeRecord& time1, const TimeRecord& time2);

// #sec-temporal-addtime
V8_WARN_UNUSED_RESULT DateTimeRecord AddTime(Isolate* isolate,
                                             const TimeRecord& time,
                                             const TimeDurationRecord& addend);

// #sec-temporal-totaldurationnanoseconds
Handle<BigInt> TotalDurationNanoseconds(Isolate* isolate,
                                        const TimeDurationRecord& duration,
                                        double offset_shift);

// #sec-temporal-totemporaltimerecord
Maybe<TimeRecord> ToTemporalTimeRecord(Isolate* isolate,
                                       Handle<JSReceiver> temporal_time_like,
                                       const char* method_name);
// Calendar Operations

// #sec-temporal-calendardateadd
V8_WARN_UNUSED_RESULT MaybeHandle<JSTemporalPlainDate> CalendarDateAdd(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<Object> date,
    Handle<Object> durations, Handle<Object> options, Handle<Object> date_add);
V8_WARN_UNUSED_RESULT MaybeHandle<JSTemporalPlainDate> CalendarDateAdd(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<Object> date,
    Handle<Object> durations, Handle<Object> options);
V8_WARN_UNUSED_RESULT MaybeHandle<JSTemporalPlainDate> CalendarDateAdd(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<Object> date,
    Handle<Object> durations);

// #sec-temporal-calendardateuntil
V8_WARN_UNUSED_RESULT MaybeHandle<JSTemporalDuration> CalendarDateUntil(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<Object> one,
    Handle<Object> two, Handle<Object> options, Handle<Object> date_until);

// #sec-temporal-calendarfields
MaybeHandle<FixedArray> CalendarFields(Isolate* isolate,
                                       Handle<JSReceiver> calendar,
                                       DirectHandle<FixedArray> field_names);

// #sec-temporal-getoffsetnanosecondsfor
V8_WARN_UNUSED_RESULT Maybe<int64_t> GetOffsetNanosecondsFor(
    Isolate* isolate, Handle<JSReceiver> time_zone, Handle<Object> instant,
    const char* method_name);

// #sec-temporal-totemporalcalendarwithisodefault
MaybeHandle<JSReceiver> ToTemporalCalendarWithISODefault(
    Isolate* isolate, Handle<Object> temporal_calendar_like,
    const char* method_name);

// #sec-temporal-isbuiltincalendar
bool IsBuiltinCalendar(Isolate* isolate, Handle<String> id);

// Internal Helper Function
int32_t CalendarIndex(Isolate* isolate, Handle<String> id);

// #sec-isvalidtimezonename
bool IsValidTimeZoneName(Isolate* isolate, DirectHandle<String> time_zone);

// #sec-canonicalizetimezonename
Handle<String> CanonicalizeTimeZoneName(Isolate* isolate,
                                        DirectHandle<String> identifier);

// #sec-temporal-tointegerthrowoninfinity
MaybeHandle<Number> ToIntegerThrowOnInfinity(Isolate* isolate,
                                             Handle<Object> argument);

// #sec-temporal-topositiveinteger
MaybeHandle<Number> ToPositiveInteger(Isolate* isolate,
                                      Handle<Object> argument);

inline double modulo(double a, int32_t b) { return a - std::floor(a / b) * b; }

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define AT __FILE__ ":" TOSTRING(__LINE__)

#ifdef DEBUG
#define TEMPORAL_DEBUG_INFO AT
#define TEMPORAL_ENTER_FUNC()
// #define TEMPORAL_ENTER_FUNC()  do { PrintF("Start: %s\n", __func__); } while
// (false)
#else
// #define TEMPORAL_DEBUG_INFO ""
#define TEMPORAL_DEBUG_INFO AT
#define TEMPORAL_ENTER_FUNC()
// #define TEMPORAL_ENTER_FUNC()  do { PrintF("Start: %s\n", __func__); } while
// (false)
#endif  // DEBUG

#define NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR()       \
  NewTypeError(                                     \
      MessageTemplate::kInvalidArgumentForTemporal, \
      isolate->factory()->NewStringFromStaticChars(TEMPORAL_DEBUG_INFO))

#define NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR()       \
  NewRangeError(                                     \
      MessageTemplate::kInvalidTimeValueForTemporal, \
      isolate->factory()->NewStringFromStaticChars(TEMPORAL_DEBUG_INFO))

// #sec-defaulttimezone
#ifdef V8_INTL_SUPPORT
Handle<String> DefaultTimeZone(Isolate* isolate) {
  TEMPORAL_ENTER_FUNC();
  return Intl::DefaultTimeZone(isolate);
}
#else   //  V8_INTL_SUPPORT
Handle<String> DefaultTimeZone(Isolate* isolate) {
  TEMPORAL_ENTER_FUNC();
  return isolate->factory()->UTC_string();
}
#endif  //  V8_INTL_SUPPORT

// #sec-temporal-isodatetimewithinlimits
bool ISODateTimeWithinLimits(Isolate* isolate,
                             const DateTimeRecord& date_time) {
  TEMPORAL_ENTER_FUNC();
  /**
   * Note: It is really overkill to decide within the limit by following the
   * specified algorithm literally, which require the conversion to BigInt.
   * Take a short cut and use pre-calculated year/month/day boundary instead.
   *
   * Math:
   * (-8.64 x 10^21- 8.64 x 10^13,  8.64 x 10^21 + 8.64 x 10^13) ns
   * = (-8.64 x 100000001 x 10^13,  8.64 x 100000001 x 10^13) ns
   * = (-8.64 x 100000001 x 10^10,  8.64 x 100000001 x 10^10) microsecond
   * = (-8.64 x 100000001 x 10^7,  8.64 x 100000001 x 10^7) millisecond
   * = (-8.64 x 100000001 x 10^4,  8.64 x 100000001 x 10^4) second
   * = (-86400 x 100000001 ,  86400 x 100000001 ) second
   * = (-100000001,  100000001) days => Because 60*60*24 = 86400
   * 100000001 days is about 273790 years, 11 months and 4 days.
   * Therefore 100000001 days before Jan 1 1970 is around Apr 19, -271821 and
   * 100000001 days after Jan 1 1970 is around Sept 13, 275760.
   */
  if (date_time.date.year > -271821 && date_time.date.year < 275760)
    return true;
  if (date_time.date.year < -271821 || date_time.date.year > 275760)
    return false;
  if (date_time.date.year == -271821) {
    if (date_time.date.month > 4) return true;
    if (date_time.date.month < 4) return false;
    if (date_time.date.day > 19) return true;
    if (date_time.date.day < 19) return false;
    if (date_time.time.hour > 0) return true;
    if (date_time.time.minute > 0) return true;
    if (date_time.time.second > 0) return true;
    if (date_time.time.millisecond > 0) return true;
    if (date_time.time.microsecond > 0) return true;
    return date_time.time.nanosecond > 0;
  } else {
    DCHECK_EQ(date_time.date.year, 275760);
    if (date_time.date.month > 9) return false;
    if (date_time.date.month < 9) return true;
    return date_time.date.day < 14;
  }
  // 1. Assert: year, month, day, hour, minute, second, millisecond,
  // microsecond, and nanosecond are integers.
  // 2. Let ns be ! GetEpochFromISOParts(year, month, day, hour, minute,
  // second, millisecond, microsecond, nanosecond).
  // 3. If ns ≤ -8.64 × 10^21 - 8.64 × 10^13, then
  // 4. If ns ≥ 8.64 × 10^21 + 8.64 × 10^13, then
  // 5. Return true.
}

// #sec-temporal-isoyearmonthwithinlimits
bool ISOYearMonthWithinLimits(int32_t year, int32_t month) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: year and month are integers.
  // 2. If year < −271821 or year > 275760, then
  // a. Return false.
  if (year < -271821 || year > 275760) return false;
  // 3. If year is −271821 and month < 4, then
  // a. Return false.
  if (year == -271821 && month < 4) return false;
  // 4. If year is 275760 and month > 9, then
  // a. Return false.
  if (year == 275760 && month > 9) return false;
  // 5. Return true.
  return true;
}

#define ORDINARY_CREATE_FROM_CONSTRUCTOR(obj, target, new_target, T)     \
  Handle<JSReceiver> new_target_receiver = Cast<JSReceiver>(new_target); \
  Handle<Map> map;                                                       \
  ASSIGN_RETURN_ON_EXCEPTION(                                            \
      isolate, map,                                                      \
      JSFunction::GetDerivedMap(isolate, target, new_target_receiver));  \
  Handle<T> object =                                                     \
      Cast<T>(isolate->factory()->NewFastOrSlowJSObjectFromMap(map));

#define THROW_INVALID_RANGE(T) \
  THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());

#define CONSTRUCTOR(name)                                                      \
  Handle<JSFunction>(                                                          \
      Cast<JSFunction>(                                                        \
          isolate->context()->native_context()->temporal_##name##_function()), \
      isolate)

// #sec-temporal-systemutcepochnanoseconds
Handle<BigInt> SystemUTCEpochNanoseconds(Isolate* isolate) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let ns be the approximate current UTC date and time, in nanoseconds
  // since the epoch.
  double ms =
      V8::GetCurrentPlatform()->CurrentClockTimeMillisecondsHighResolution();
  // 2. Set ns to the result of clamping ns between −8.64 × 10^21 and 8.64 ×
  // 10^21.

  // 3. Return ℤ(ns).
  double ns = ms * 1000000.0;
  ns = std::floor(std::max(-8.64e21, std::min(ns, 8.64e21)));
  return BigInt::FromNumber(isolate, isolate->factory()->NewNumber(ns))
      .ToHandleChecked();
}

// #sec-temporal-createtemporalcalendar
MaybeHandle<JSTemporalCalendar> CreateTemporalCalendar(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<String> identifier) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: ! IsBuiltinCalendar(identifier) is true.
  // 2. If newTarget is not provided, set newTarget to %Temporal.Calendar%.
  // 3. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.Calendar.prototype%", « [[InitializedTemporalCalendar]],
  // [[Identifier]] »).
  int32_t index = CalendarIndex(isolate, identifier);

  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalCalendar)

  object->set_flags(0);
  // 4. Set object.[[Identifier]] to identifier.
  object->set_calendar_index(index);
  // 5. Return object.
  return object;
}

MaybeHandle<JSTemporalCalendar> CreateTemporalCalendar(
    Isolate* isolate, Handle<String> identifier) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalCalendar(isolate, CONSTRUCTOR(calendar),
                                CONSTRUCTOR(calendar), identifier);
}

// #sec-temporal-createtemporaldate
MaybeHandle<JSTemporalPlainDate> CreateTemporalDate(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    const DateRecord& date, DirectHandle<JSReceiver> calendar) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: isoYear is an integer.
  // 2. Assert: isoMonth is an integer.
  // 3. Assert: isoDay is an integer.
  // 4. Assert: Type(calendar) is Object.
  // 5. If ! IsValidISODate(isoYear, isoMonth, isoDay) is false, throw a
  // RangeError exception.
  if (!IsValidISODate(isolate, date)) {
    THROW_INVALID_RANGE(JSTemporalPlainDate);
  }
  // 6. If ! ISODateTimeWithinLimits(isoYear, isoMonth, isoDay, 12, 0, 0, 0, 0,
  // 0) is false, throw a RangeError exception.
  if (!ISODateTimeWithinLimits(isolate, {date, {12, 0, 0, 0, 0, 0}})) {
    THROW_INVALID_RANGE(JSTemporalPlainDate);
  }
  // 7. If newTarget is not present, set it to %Temporal.PlainDate%.

  // 8. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.PlainDate.prototype%", « [[InitializedTemporalDate]],
  // [[ISOYear]], [[ISOMonth]], [[ISODay]], [[Calendar]] »).
  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalPlainDate)
  object->set_year_month_day(0);
  // 9. Set object.[[ISOYear]] to isoYear.
  object->set_iso_year(date.year);
  // 10. Set object.[[ISOMonth]] to isoMonth.
  object->set_iso_month(date.month);
  // 11. Set object.[[ISODay]] to isoDay.
  object->set_iso_day(date.day);
  // 12. Set object.[[Calendar]] to calendar.
  object->set_calendar(*calendar);
  // 13. Return object.
  return object;
}

MaybeHandle<JSTemporalPlainDate> CreateTemporalDate(
    Isolate* isolate, const DateRecord& date,
    DirectHandle<JSReceiver> calendar) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalDate(isolate, CONSTRUCTOR(plain_date),
                            CONSTRUCTOR(plain_date), date, calendar);
}

// #sec-temporal-createtemporaldatetime
MaybeHandle<JSTemporalPlainDateTime> CreateTemporalDateTime(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    const DateTimeRecord& date_time, DirectHandle<JSReceiver> calendar) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: isoYear, isoMonth, isoDay, hour, minute, second, millisecond,
  // microsecond, and nanosecond are integers.
  // 2. Assert: Type(calendar) is Object.
  // 3. If ! IsValidISODate(isoYear, isoMonth, isoDay) is false, throw a
  // RangeError exception.
  if (!IsValidISODate(isolate, date_time.date)) {
    THROW_INVALID_RANGE(JSTemporalPlainDateTime);
  }
  // 4. If ! IsValidTime(hour, minute, second, millisecond, microsecond,
  // nanosecond) is false, throw a RangeError exception.
  if (!IsValidTime(isolate, date_time.time)) {
    THROW_INVALID_RANGE(JSTemporalPlainDateTime);
  }
  // 5. If ! ISODateTimeWithinLimits(isoYear, isoMonth, isoDay, hour, minute,
  // second, millisecond, microsecond, nanosecond) is false, then
  if (!ISODateTimeWithinLimits(isolate, date_time)) {
    // a. Throw a RangeError exception.
    THROW_INVALID_RANGE(JSTemporalPlainDateTime);
  }
  // 6. If newTarget is not present, set it to %Temporal.PlainDateTime%.
  // 7. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.PlainDateTime.prototype%", « [[InitializedTemporalDateTime]],
  // [[ISOYear]], [[ISOMonth]], [[ISODay]], [[ISOHour]], [[ISOMinute]],
  // [[ISOSecond]], [[ISOMillisecond]], [[ISOMicrosecond]], [[ISONanosecond]],
  // [[Calendar]] »).
  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalPlainDateTime)

  object->set_year_month_day(0);
  object->set_hour_minute_second(0);
  object->set_second_parts(0);
  // 8. Set object.[[ISOYear]] to isoYear.
  object->set_iso_year(date_time.date.year);
  // 9. Set object.[[ISOMonth]] to isoMonth.
  object->set_iso_month(date_time.date.month);
  // 10. Set object.[[ISODay]] to isoDay.
  object->set_iso_day(date_time.date.day);
  // 11. Set object.[[ISOHour]] to hour.
  object->set_iso_hour(date_time.time.hour);
  // 12. Set object.[[ISOMinute]] to minute.
  object->set_iso_minute(date_time.time.minute);
  // 13. Set object.[[ISOSecond]] to second.
  object->set_iso_second(date_time.time.second);
  // 14. Set object.[[ISOMillisecond]] to millisecond.
  object->set_iso_millisecond(date_time.time.millisecond);
  // 15. Set object.[[ISOMicrosecond]] to microsecond.
  object->set_iso_microsecond(date_time.time.microsecond);
  // 16. Set object.[[ISONanosecond]] to nanosecond.
  object->set_iso_nanosecond(date_time.time.nanosecond);
  // 17. Set object.[[Calendar]] to calendar.
  object->set_calendar(*calendar);
  // 18. Return object.
  return object;
}

MaybeHandle<JSTemporalPlainDateTime> CreateTemporalDateTimeDefaultTarget(
    Isolate* isolate, const DateTimeRecord& date_time,
    DirectHandle<JSReceiver> calendar) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalDateTime(isolate, CONSTRUCTOR(plain_date_time),
                                CONSTRUCTOR(plain_date_time), date_time,
                                calendar);
}

}  // namespace

namespace temporal {

MaybeHandle<JSTemporalPlainDateTime> CreateTemporalDateTime(
    Isolate* isolate, const DateTimeRecord& date_time,
    DirectHandle<JSReceiver> calendar) {
  return CreateTemporalDateTimeDefaultTarget(isolate, date_time, calendar);
}

}  // namespace temporal

namespace {
// #sec-temporal-createtemporaltime
MaybeHandle<JSTemporalPlainTime> CreateTemporalTime(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    const TimeRecord& time) {
  TEMPORAL_ENTER_FUNC();
  // 2. If ! IsValidTime(hour, minute, second, millisecond, microsecond,
  // nanosecond) is false, throw a RangeError exception.
  if (!IsValidTime(isolate, time)) {
    THROW_INVALID_RANGE(JSTemporalPlainTime);
  }

  DirectHandle<JSTemporalCalendar> calendar =
      temporal::GetISO8601Calendar(isolate);

  // 4. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.PlainTime.prototype%", « [[InitializedTemporalTime]],
  // [[ISOHour]], [[ISOMinute]], [[ISOSecond]], [[ISOMillisecond]],
  // [[ISOMicrosecond]], [[ISONanosecond]], [[Calendar]] »).
  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalPlainTime)
  object->set_hour_minute_second(0);
  object->set_second_parts(0);
  // 5. Set object.[[ISOHour]] to hour.
  object->set_iso_hour(time.hour);
  // 6. Set object.[[ISOMinute]] to minute.
  object->set_iso_minute(time.minute);
  // 7. Set object.[[ISOSecond]] to second.
  object->set_iso_second(time.second);
  // 8. Set object.[[ISOMillisecond]] to millisecond.
  object->set_iso_millisecond(time.millisecond);
  // 9. Set object.[[ISOMicrosecond]] to microsecond.
  object->set_iso_microsecond(time.microsecond);
  // 10. Set object.[[ISONanosecond]] to nanosecond.
  object->set_iso_nanosecond(time.nanosecond);
  // 11. Set object.[[Calendar]] to ? GetISO8601Calendar().
  object->set_calendar(*calendar);

  // 12. Return object.
  return object;
}

MaybeHandle<JSTemporalPlainTime> CreateTemporalTime(Isolate* isolate,
                                                    const TimeRecord& time) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalTime(isolate, CONSTRUCTOR(plain_time),
                            CONSTRUCTOR(plain_time), time);
}

// #sec-temporal-createtemporalmonthday
MaybeHandle<JSTemporalPlainMonthDay> CreateTemporalMonthDay(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    int32_t iso_month, int32_t iso_day, DirectHandle<JSReceiver> calendar,
    int32_t reference_iso_year) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: isoMonth, isoDay, and referenceISOYear are integers.
  // 2. Assert: Type(calendar) is Object.
  // 3. If ! IsValidISODate(referenceISOYear, isoMonth, isoDay) is false, throw
  if (!IsValidISODate(isolate, {reference_iso_year, iso_month, iso_day})) {
    // a RangeError exception.
    THROW_INVALID_RANGE(JSTemporalPlainMonthDay);
  }
  // 4. If ISODateTimeWithinLimits(referenceISOYear, isoMonth, isoDay, 12, 0, 0,
  // 0, 0, 0) is false, throw a RangeError exception.
  if (!ISODateTimeWithinLimits(
          isolate,
          {{reference_iso_year, iso_month, iso_day}, {12, 0, 0, 0, 0, 0}})) {
    THROW_INVALID_RANGE(JSTemporalPlainMonthDay);
  }

  // 5. If newTarget is not present, set it to %Temporal.PlainMonthDay%.
  // 6. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.PlainMonthDay.prototype%", « [[InitializedTemporalMonthDay]],
  // [[ISOMonth]], [[ISODay]], [[ISOYear]], [[Calendar]] »).
  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalPlainMonthDay)
  object->set_year_month_day(0);
  // 7. Set object.[[ISOMonth]] to isoMonth.
  object->set_iso_month(iso_month);
  // 8. Set object.[[ISODay]] to isoDay.
  object->set_iso_day(iso_day);
  // 9. Set object.[[Calendar]] to calendar.
  obje
"""


```