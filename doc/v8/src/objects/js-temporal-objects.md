Response: My thinking process to summarize the C++ code goes through these stages:

1. **Identify the Core Purpose:** The filename `js-temporal-objects.cc` and the initial comments clearly indicate this code is about implementing the ECMAScript Temporal API within the V8 JavaScript engine. The copyright notice and license information confirm this is part of the V8 project.

2. **Scan for Key Data Structures and Enums:** I look for `struct` and `enum` definitions. These are the building blocks of the API. The enums like `Unit`, `Disambiguation`, `ShowOverflow`, `RoundingMode`, etc., suggest different options and behaviors within the Temporal API. The structs like `UnbalancedTimeRecord`, `DateRecord`, `TimeRecord`, `DateTimeRecord`, `DurationRecord`, etc., represent the various temporal data types.

3. **Recognize Abstract Operations:** The comment "This header declares the Abstract Operations defined in the Temporal spec..." is a massive clue. This means the code is directly translating the specifications of the Temporal API into C++. I expect to see functions that correspond to abstract operations mentioned in the spec.

4. **Spot Parsing and Formatting Functions:**  Function names like `ParseTemporalCalendarString`, `ParseTemporalDateTimeString`, `TemporalDurationToString`, and `FormatSecondsStringPart` indicate the code handles the conversion between string representations and internal representations of temporal objects.

5. **Look for Creation Functions:** Functions starting with `CreateTemporal...` (e.g., `CreateTemporalCalendar`, `CreateTemporalDate`, `CreateTemporalDuration`) are responsible for instantiating the different Temporal object types. The `ORDINARY_CREATE_FROM_CONSTRUCTOR` macro reinforces this.

6. **Identify Utility and Calculation Functions:**  Functions like `BalanceISODate`, `BalanceTime`, `DifferenceISODateTime`, `AddDateTime`, `AddInstant`, `NanosecondsToDays`, `CompareISODate`, and `TotalDurationNanoseconds` point to the core logic of performing calculations and comparisons with temporal values.

7. **Notice Internationalization (Intl) Integration:** The `#ifdef V8_INTL_SUPPORT` blocks and inclusion of `<unicode/calendar.h>` and `<unicode/unistr.h>` signal that the implementation interacts with the International Components for Unicode (ICU) library for features like time zone handling and calendar systems.

8. **Connect to JavaScript Concepts:** As I identify the different Temporal object types (like `PlainDate`, `PlainTime`, `PlainDateTime`, `Instant`, `Duration`, `Calendar`, `TimeZone`), I make the mental link to the corresponding JavaScript classes that the Temporal API defines.

9. **Formulate the Summary:** Based on the above observations, I construct the summary focusing on the main functionalities:
    * Implementation of the Temporal API.
    * Representation of Temporal objects using C++ structs.
    * Implementation of abstract operations from the specification.
    * Parsing and formatting of temporal strings.
    * Creation of Temporal objects.
    * Calculation and comparison of temporal values.
    * Integration with ICU for internationalization.

10. **Provide JavaScript Examples:** To illustrate the connection to JavaScript, I choose common Temporal API use cases and show how the C++ code likely underpins these operations. Creating dates, formatting them, and performing calculations are good examples. I focus on the core Temporal types.

11. **Address the "Part 1 of 13" aspect:** I note that this is the first part and likely focuses on core data structures and fundamental operations, with later parts potentially dealing with more complex aspects.

By following these steps, I can break down the C++ code, understand its purpose within the context of the V8 engine and the Temporal API, and clearly explain its functionality and relationship to JavaScript. The iterative nature of looking for patterns, data structures, and function names is crucial in understanding a large codebase.
这个C++源代码文件 `v8/src/objects/js-temporal-objects.cc` 的第1部分，是V8 JavaScript引擎中用于实现 ECMAScript Temporal API 的核心组成部分。 它的主要功能是：

**1. 定义和实现 Temporal API 的内部数据结构:**

*   **枚举 (Enums):** 定义了各种表示时间和日期单位、选项和行为的枚举类型，例如 `Unit` (年、月、日等)、`Disambiguation` (处理时间歧义)、`RoundingMode` (舍入模式) 等。这些枚举类型在后续的代码中用于控制 Temporal API 的各种操作。
*   **结构体 (Structs):** 定义了用于存储不同 Temporal 对象内部状态的结构体，例如 `DateRecord` (日期记录)、`TimeRecord` (时间记录)、`DateTimeRecord` (日期时间记录)、`DurationRecord` (持续时间记录) 等。这些结构体是 Temporal 对象在 C++ 层面的表示。

**2. 实现 Temporal API 的抽象操作 (Abstract Operations):**

*   文件中声明了许多函数，这些函数的名字通常与 Temporal 规范中定义的抽象操作相对应。 例如，`BalanceISODate`、`BalanceTime`、`DifferenceTime`、`AddDateTime` 等。这些函数实现了 Temporal API 内部的逻辑，用于处理日期时间的计算、比较、调整等操作。

**3. 提供与 JavaScript Temporal 对象创建和操作相关的底层支持:**

*   文件中定义了许多 `CreateTemporal...` 形式的函数，例如 `CreateTemporalDate`、`CreateTemporalTime`、`CreateTemporalDuration` 等。这些函数负责在 V8 内部创建和初始化 JavaScript 中的 Temporal 对象（如 `Temporal.PlainDate`、`Temporal.PlainTime`、`Temporal.Duration` 等）。
*   虽然这部分代码不直接暴露给 JavaScript，但它是 JavaScript Temporal 对象在底层 C++ 实现的基石。

**4. 定义和处理 Temporal API 的各种选项 (Options):**

*   文件中定义了用于解析和处理 Temporal API 方法中使用的选项的枚举和函数，例如 `ToShowTimeZoneNameOption`、`ToShowOffsetOption`。这些选项控制着 Temporal 对象的格式化、比较等行为。

**5. 提供 Temporal 字符串的解析功能:**

*   文件中包含 `ParseTemporal...String` 形式的函数，例如 `ParseTemporalCalendarString`、`ParseTemporalDateTimeString`、`ParseTemporalDurationString` 等。这些函数负责将 ISO 8601 格式的日期时间字符串解析成内部的数据结构。

**与 JavaScript 的关系及示例:**

这部分 C++ 代码是 JavaScript Temporal API 的底层实现。 当你在 JavaScript 中使用 Temporal API 时，V8 引擎会在底层调用这些 C++ 函数来执行相应的操作。

**JavaScript 示例：**

```javascript
// 创建一个 Temporal.PlainDate 对象
const plainDate = new Temporal.PlainDate(2023, 10, 26);

// 创建一个 Temporal.Duration 对象
const duration = new Temporal.Duration(1, 2, 0, 5); // 1年2个月5天

// 对日期进行加法操作
const laterDate = plainDate.add(duration);

console.log(laterDate.toString()); // 输出类似 "2024-12-31"

// 格式化日期
const formattedDate = plainDate.toLocaleString();
console.log(formattedDate); // 输出当前区域设置的日期格式
```

**在上述 JavaScript 代码的背后，`v8/src/objects/js-temporal-objects.cc` 的第1部分可能涉及到的 C++ 功能包括：**

*   `CreateTemporalDate` 函数会被调用来创建 `plainDate` 对象，其内部会使用 `DateRecord` 结构体存储日期信息。
*   `CreateTemporalDuration` 函数会被调用来创建 `duration` 对象，其内部会使用 `DurationRecord` 结构体存储持续时间信息。
*   `AddDateTime` (或者类似的函数) 会被调用来执行日期加法操作，它会读取 `plainDate` 和 `duration` 的内部数据，进行计算，并返回一个新的 `DateTimeRecord`。
*   格式化日期时，可能会涉及到读取 `plainDate` 的内部数据，并根据区域设置调用其他相关的格式化函数 (可能在其他文件中)。

**总结:**

`v8/src/objects/js-temporal-objects.cc` 的第1部分主要负责定义 Temporal API 的内部数据结构，并实现了许多基础的抽象操作，为 JavaScript 中使用 Temporal API 提供了底层的 C++ 支持。 它处理了 Temporal 对象的创建、基本数据表示和核心计算逻辑，以及 Temporal 字符串的解析。 这部分代码是构建功能完善的 Temporal API 的重要基础。 由于这是第1部分，可以推测后续的部分会涵盖更复杂的 Temporal 类型、时区处理、日历系统集成以及更高级的操作。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共13部分，请归纳一下它的功能
```

### 源代码
```
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
  object->set_calendar(*calendar);
  // 10. Set object.[[ISOYear]] to referenceISOYear.
  object->set_iso_year(reference_iso_year);
  // 11. Return object.
  return object;
}

MaybeHandle<JSTemporalPlainMonthDay> CreateTemporalMonthDay(
    Isolate* isolate, int32_t iso_month, int32_t iso_day,
    DirectHandle<JSReceiver> calendar, int32_t reference_iso_year) {
  return CreateTemporalMonthDay(isolate, CONSTRUCTOR(plain_month_day),
                                CONSTRUCTOR(plain_month_day), iso_month,
                                iso_day, calendar, reference_iso_year);
}

// #sec-temporal-createtemporalyearmonth
MaybeHandle<JSTemporalPlainYearMonth> CreateTemporalYearMonth(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    int32_t iso_year, int32_t iso_month, DirectHandle<JSReceiver> calendar,
    int32_t reference_iso_day) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: isoYear, isoMonth, and referenceISODay are integers.
  // 2. Assert: Type(calendar) is Object.
  // 3. If ! IsValidISODate(isoYear, isoMonth, referenceISODay) is false, throw
  // a RangeError exception.
  if (!IsValidISODate(isolate, {iso_year, iso_month, reference_iso_day})) {
    THROW_INVALID_RANGE(JSTemporalPlainYearMonth);
  }
  // 4. If ! ISOYearMonthWithinLimits(isoYear, isoMonth) is false, throw a
  // RangeError exception.
  if (!ISOYearMonthWithinLimits(iso_year, iso_month)) {
    THROW_INVALID_RANGE(JSTemporalPlainYearMonth);
  }
  // 5. If newTarget is not present, set it to %Temporal.PlainYearMonth%.
  // 6. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.PlainYearMonth.prototype%", « [[InitializedTemporalYearMonth]],
  // [[ISOYear]], [[ISOMonth]], [[ISODay]], [[Calendar]] »).
  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalPlainYearMonth)
  object->set_year_month_day(0);
  // 7. Set object.[[ISOYear]] to isoYear.
  object->set_iso_year(iso_year);
  // 8. Set object.[[ISOMonth]] to isoMonth.
  object->set_iso_month(iso_month);
  // 9. Set object.[[Calendar]] to calendar.
  object->set_calendar(*calendar);
  // 10. Set object.[[ISODay]] to referenceISODay.
  object->set_iso_day(reference_iso_day);
  // 11. Return object.
  return object;
}

MaybeHandle<JSTemporalPlainYearMonth> CreateTemporalYearMonth(
    Isolate* isolate, int32_t iso_year, int32_t iso_month,
    DirectHandle<JSReceiver> calendar, int32_t reference_iso_day) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalYearMonth(isolate, CONSTRUCTOR(plain_year_month),
                                 CONSTRUCTOR(plain_year_month), iso_year,
                                 iso_month, calendar, reference_iso_day);
}

// #sec-temporal-createtemporalzoneddatetime
MaybeHandle<JSTemporalZonedDateTime> CreateTemporalZonedDateTime(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    DirectHandle<BigInt> epoch_nanoseconds, DirectHandle<JSReceiver> time_zone,
    DirectHandle<JSReceiver> calendar) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: Type(epochNanoseconds) is BigInt.
  // 2. Assert: ! IsValidEpochNanoseconds(epochNanoseconds) is true.
  DCHECK(IsValidEpochNanoseconds(isolate, epoch_nanoseconds));
  // 3. Assert: Type(timeZone) is Object.
  // 4. Assert: Type(calendar) is Object.
  // 5. If newTarget is not present, set it to %Temporal.ZonedDateTime%.
  // 6. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.ZonedDateTime.prototype%", «
  // [[InitializedTemporalZonedDateTime]], [[Nanoseconds]], [[TimeZone]],
  // [[Calendar]] »).
  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalZonedDateTime)
  // 7. Set object.[[Nanoseconds]] to epochNanoseconds.
  object->set_nanoseconds(*epoch_nanoseconds);
  // 8. Set object.[[TimeZone]] to timeZone.
  object->set_time_zone(*time_zone);
  // 9. Set object.[[Calendar]] to calendar.
  object->set_calendar(*calendar);
  // 10. Return object.
  return object;
}

MaybeHandle<JSTemporalZonedDateTime> CreateTemporalZonedDateTime(
    Isolate* isolate, DirectHandle<BigInt> epoch_nanoseconds,
    DirectHandle<JSReceiver> time_zone, DirectHandle<JSReceiver> calendar) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalZonedDateTime(isolate, CONSTRUCTOR(zoned_date_time),
                                     CONSTRUCTOR(zoned_date_time),
                                     epoch_nanoseconds, time_zone, calendar);
}

inline double NormalizeMinusZero(double v) { return IsMinusZero(v) ? 0 : v; }

// #sec-temporal-createdatedurationrecord
Maybe<DateDurationRecord> DateDurationRecord::Create(
    Isolate* isolate, double years, double months, double weeks, double days) {
  // 1. If ! IsValidDuration(years, months, weeks, days, 0, 0, 0, 0, 0, 0) is
  // false, throw a RangeError exception.
  if (!IsValidDuration(isolate,
                       {years, months, weeks, {days, 0, 0, 0, 0, 0, 0}})) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateDurationRecord>());
  }
  // 2. Return the Record { [[Years]]: ℝ(𝔽(years)), [[Months]]: ℝ(𝔽(months)),
  // [[Weeks]]: ℝ(𝔽(weeks)), [[Days]]: ℝ(𝔽(days)) }.
  DateDurationRecord record = {years, months, weeks, days};
  return Just(record);
}

}  // namespace

namespace temporal {
// #sec-temporal-createtimedurationrecord
Maybe<TimeDurationRecord> TimeDurationRecord::Create(
    Isolate* isolate, double days, double hours, double minutes, double seconds,
    double milliseconds, double microseconds, double nanoseconds) {
  // 1. If ! IsValidDuration(0, 0, 0, days, hours, minutes, seconds,
  // milliseconds, microseconds, nanoseconds) is false, throw a RangeError
  // exception.
  TimeDurationRecord record = {days,         hours,        minutes,    seconds,
                               milliseconds, microseconds, nanoseconds};
  if (!IsValidDuration(isolate, {0, 0, 0, record})) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<TimeDurationRecord>());
  }
  // 2. Return the Record { [[Days]]: ℝ(𝔽(days)), [[Hours]]: ℝ(𝔽(hours)),
  // [[Minutes]]: ℝ(𝔽(minutes)), [[Seconds]]: ℝ(𝔽(seconds)), [[Milliseconds]]:
  // ℝ(𝔽(milliseconds)), [[Microseconds]]: ℝ(𝔽(microseconds)), [[Nanoseconds]]:
  // ℝ(𝔽(nanoseconds)) }.
  return Just(record);
}

// #sec-temporal-createdurationrecord
Maybe<DurationRecord> DurationRecord::Create(
    Isolate* isolate, double years, double months, double weeks, double days,
    double hours, double minutes, double seconds, double milliseconds,
    double microseconds, double nanoseconds) {
  // 1. If ! IsValidDuration(years, months, weeks, days, hours, minutes,
  // seconds, milliseconds, microseconds, nanoseconds) is false, throw a
  // RangeError exception.
  DurationRecord record = {
      years,
      months,
      weeks,
      {days, hours, minutes, seconds, milliseconds, microseconds, nanoseconds}};
  if (!IsValidDuration(isolate, record)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DurationRecord>());
  }
  // 2. Return the Record { [[Years]]: ℝ(𝔽(years)), [[Months]]: ℝ(𝔽(months)),
  // [[Weeks]]: ℝ(𝔽(weeks)), [[Days]]: ℝ(𝔽(days)), [[Hours]]: ℝ(𝔽(hours)),
  // [[Minutes]]: ℝ(𝔽(minutes)), [[Seconds]]: ℝ(𝔽(seconds)), [[Milliseconds]]:
  // ℝ(𝔽(milliseconds)), [[Microseconds]]: ℝ(𝔽(microseconds)), [[Nanoseconds]]:
  // ℝ(𝔽(nanoseconds)) }.
  return Just(record);
}
}  // namespace temporal

namespace {
// #sec-temporal-createtemporalduration
MaybeHandle<JSTemporalDuration> CreateTemporalDuration(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    const DurationRecord& duration) {
  TEMPORAL_ENTER_FUNC();
  Factory* factory = isolate->factory();
  // 1. If ! IsValidDuration(years, months, weeks, days, hours, minutes,
  // seconds, milliseconds, microseconds, nanoseconds) is false, throw a
  // RangeError exception.
  if (!IsValidDuration(isolate, duration)) {
    THROW_INVALID_RANGE(JSTemporalDuration);
  }

  // 2. If newTarget is not present, set it to %Temporal.Duration%.
  // 3. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.Duration.prototype%", « [[InitializedTemporalDuration]],
  // [[Years]], [[Months]], [[Weeks]], [[Days]], [[Hours]], [[Minutes]],
  // [[Seconds]], [[Milliseconds]], [[Microseconds]], [[Nanoseconds]] »).
  const TimeDurationRecord& time_duration = duration.time_duration;
  DirectHandle<Number> years =
      factory->NewNumber(NormalizeMinusZero(duration.years));
  DirectHandle<Number> months =
      factory->NewNumber(NormalizeMinusZero(duration.months));
  DirectHandle<Number> weeks =
      factory->NewNumber(NormalizeMinusZero(duration.weeks));
  DirectHandle<Number> days =
      factory->NewNumber(NormalizeMinusZero(time_duration.days));
  DirectHandle<Number> hours =
      factory->NewNumber(NormalizeMinusZero(time_duration.hours));
  DirectHandle<Number> minutes =
      factory->NewNumber(NormalizeMinusZero(time_duration.minutes));
  DirectHandle<Number> seconds =
      factory->NewNumber(NormalizeMinusZero(time_duration.seconds));
  DirectHandle<Number> milliseconds =
      factory->NewNumber(NormalizeMinusZero(time_duration.milliseconds));
  DirectHandle<Number> microseconds =
      factory->NewNumber(NormalizeMinusZero(time_duration.microseconds));
  DirectHandle<Number> nanoseconds =
      factory->NewNumber(NormalizeMinusZero(time_duration.nanoseconds));
  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalDuration)
  // 4. Set object.[[Years]] to ℝ(𝔽(years)).
  object->set_years(*years);
  // 5. Set object.[[Months]] to ℝ(𝔽(months)).
  object->set_months(*months);
  // 6. Set object.[[Weeks]] to ℝ(𝔽(weeks)).
  object->set_weeks(*weeks);
  // 7. Set object.[[Days]] to ℝ(𝔽(days)).
  object->set_days(*days);
  // 8. Set object.[[Hours]] to ℝ(𝔽(hours)).
  object->set_hours(*hours);
  // 9. Set object.[[Minutes]] to ℝ(𝔽(minutes)).
  object->set_minutes(*minutes);
  // 10. Set object.[[Seconds]] to ℝ(𝔽(seconds)).
  object->set_seconds(*seconds);
  // 11. Set object.[[Milliseconds]] to ℝ(𝔽(milliseconds)).
  object->set_milliseconds(*milliseconds);
  // 12. Set object.[[Microseconds]] to ℝ(𝔽(microseconds)).
  object->set_microseconds(*microseconds);
  // 13. Set object.[[Nanoseconds]] to ℝ(𝔽(nanoseconds)).
  object->set_nanoseconds(*nanoseconds);
  // 14. Return object.
  return object;
}

MaybeHandle<JSTemporalDuration> CreateTemporalDuration(
    Isolate* isolate, const DurationRecord& duration) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalDuration(isolate, CONSTRUCTOR(duration),
                                CONSTRUCTOR(duration), duration);
}

}  // namespace

namespace temporal {

// #sec-temporal-createtemporalinstant
MaybeHandle<JSTemporalInstant> CreateTemporalInstant(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    DirectHandle<BigInt> epoch_nanoseconds) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: Type(epochNanoseconds) is BigInt.
  // 2. Assert: ! IsValidEpochNanoseconds(epochNanoseconds) is true.
  DCHECK(IsValidEpochNanoseconds(isolate, epoch_nanoseconds));

  // 4. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.Instant.prototype%", « [[InitializedTemporalInstant]],
  // [[Nanoseconds]] »).
  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalInstant)
  // 5. Set object.[[Nanoseconds]] to ns.
  object->set_nanoseconds(*epoch_nanoseconds);
  return object;
}

MaybeHandle<JSTemporalInstant> CreateTemporalInstant(
    Isolate* isolate, DirectHandle<BigInt> epoch_nanoseconds) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalInstant(isolate, CONSTRUCTOR(instant),
                               CONSTRUCTOR(instant), epoch_nanoseconds);
}

}  // namespace temporal

namespace {

MaybeHandle<JSTemporalTimeZone> CreateTemporalTimeZoneFromIndex(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    int32_t index) {
  TEMPORAL_ENTER_FUNC();
  ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                   JSTemporalTimeZone)
  object->set_flags(0);
  object->set_details(0);

  object->set_is_offset(false);
  object->set_offset_milliseconds_or_time_zone_index(index);
  return object;
}

Handle<JSTemporalTimeZone> CreateTemporalTimeZoneUTC(
    Isolate* isolate, Handle<JSFunction> target,
    Handle<HeapObject> new_target) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalTimeZoneFromIndex(isolate, target, new_target, 0)
      .ToHandleChecked();
}

Handle<JSTemporalTimeZone> CreateTemporalTimeZoneUTC(Isolate* isolate) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalTimeZoneUTC(isolate, CONSTRUCTOR(time_zone),
                                   CONSTRUCTOR(time_zone));
}

bool IsUTC(Isolate* isolate, Handle<String> time_zone);

// #sec-temporal-createtemporaltimezone
MaybeHandle<JSTemporalTimeZone> CreateTemporalTimeZone(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    Handle<String> identifier) {
  TEMPORAL_ENTER_FUNC();

  // 1. If newTarget is not present, set it to %Temporal.TimeZone%.
  // 2. Let object be ? OrdinaryCreateFromConstructor(newTarget,
  // "%Temporal.TimeZone.prototype%", « [[InitializedTemporalTimeZone]],
  // [[Identifier]], [[OffsetNanoseconds]] »).

  // 3. Let offsetNanosecondsResult be ParseTimeZoneOffsetString(identifier).
  Maybe<int64_t> maybe_offset_nanoseconds =
      ParseTimeZoneOffsetString(isolate, identifier);
  // 4. If offsetNanosecondsResult is an abrupt completion, then
  if (maybe_offset_nanoseconds.IsNothing()) {
    DCHECK(isolate->has_exception());
    isolate->clear_exception();
    // a. Assert: ! CanonicalizeTimeZoneName(identifier) is identifier.
    DCHECK(String::Equals(isolate, identifier,
                          CanonicalizeTimeZoneName(isolate, identifier)));

    // b. Set object.[[Identifier]] to identifier.
    // c. Set object.[[OffsetNanoseconds]] to undefined.
    if (IsUTC(isolate, identifier)) {
      return CreateTemporalTimeZoneUTC(isolate, target, new_target);
    }
#ifdef V8_INTL_SUPPORT
    int32_t time_zone_index = Intl::GetTimeZoneIndex(isolate, identifier);
    DCHECK_GE(time_zone_index, 0);
    return CreateTemporalTimeZoneFromIndex(isolate, target, new_target,
                                           time_zone_index);
#else
    UNREACHABLE();
#endif  // V8_INTL_SUPPORT
    // 5. Else,
  } else {
    // a. Set object.[[Identifier]] to !
    // FormatTimeZoneOffsetString(offsetNanosecondsResult.[[Value]]). b. Set
    // object.[[OffsetNanoseconds]] to offsetNanosecondsResult.[[Value]].
    ORDINARY_CREATE_FROM_CONSTRUCTOR(object, target, new_target,
                                     JSTemporalTimeZone)
    object->set_flags(0);
    object->set_details(0);

    object->set_is_offset(true);
    object->set_offset_nanoseconds(maybe_offset_nanoseconds.FromJust());
    return object;
  }
  // 6. Return object.
}

MaybeHandle<JSTemporalTimeZone> CreateTemporalTimeZoneDefaultTarget(
    Isolate* isolate, Handle<String> identifier) {
  TEMPORAL_ENTER_FUNC();
  return CreateTemporalTimeZone(isolate, CONSTRUCTOR(time_zone),
                                CONSTRUCTOR(time_zone), identifier);
}

}  // namespace

namespace temporal {
MaybeHandle<JSTemporalTimeZone> CreateTemporalTimeZone(
    Isolate* isolate, Handle<String> identifier) {
  return CreateTemporalTimeZoneDefaultTarget(isolate, identifier);
}
}  // namespace temporal

namespace {

// #sec-temporal-systeminstant
Handle<JSTemporalInstant> SystemInstant(Isolate* isolate) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let ns be ! SystemUTCEpochNanoseconds().
  DirectHandle<BigInt> ns = SystemUTCEpochNanoseconds(isolate);
  // 2. Return ? CreateTemporalInstant(ns).
  return temporal::CreateTemporalInstant(isolate, ns).ToHandleChecked();
}

// #sec-temporal-systemtimezone
Handle<JSTemporalTimeZone> SystemTimeZone(Isolate* isolate) {
  TEMPORAL_ENTER_FUNC();
  Handle<String> default_time_zone = DefaultTimeZone(isolate);
  return temporal::CreateTemporalTimeZone(isolate, default_time_zone)
      .ToHandleChecked();
}

DateTimeRecord GetISOPartsFromEpoch(Isolate* isolate,
                                    Handle<BigInt> epoch_nanoseconds) {
  TEMPORAL_ENTER_FUNC();
  DateTimeRecord result;
  // 1. Assert: ! IsValidEpochNanoseconds(ℤ(epochNanoseconds)) is true.
  DCHECK(IsValidEpochNanoseconds(isolate, epoch_nanoseconds));
  // 2. Let remainderNs be epochNanoseconds modulo 10^6.
  Handle<BigInt> million = BigInt::FromUint64(isolate, 1000000);
  Handle<BigInt> remainder_ns =
      BigInt::Remainder(isolate, epoch_nanoseconds, million).ToHandleChecked();
  // Need to do some remainder magic to negative remainder.
  if (remainder_ns->IsNegative()) {
    remainder_ns =
        BigInt::Add(isolate, remainder_ns, million).ToHandleChecked();
  }

  // 3. Let epochMilliseconds be (epochNanoseconds − remainderNs) / 10^6.
  int64_t epoch_milliseconds =
      BigInt::Divide(isolate,
                     BigInt::Subtract(isolate, epoch_nanoseconds, remainder_ns)
                         .ToHandleChecked(),
                     million)
          .ToHandleChecked()
          ->AsInt64();
  int year = 0;
  int month = 0;
  int day = 0;
  int wday = 0;
  int hour = 0;
  int min = 0;
  int sec = 0;
  int ms = 0;
  isolate->date_cache()->BreakDownTime(epoch_milliseconds, &year, &month, &day,
                                       &wday, &hour, &min, &sec, &ms);

  // 4. Let year be ! YearFromTime(epochMilliseconds).
  result.date.year = year;
  // 5. Let month be ! MonthFromTime(epochMilliseconds) + 1.
  result.date.month = month + 1;
  DCHECK_GE(result.date.month, 1);
  DCHECK_LE(result.date.month, 12);
  // 6. Let day be ! DateFromTime(epochMilliseconds).
  result.date.day = day;
  DCHECK_GE(result.date.day, 1);
  DCHECK_LE(result.date.day, 31);
  // 7. Let hour be ! HourFromTime(epochMilliseconds).
  result.time.hour = hour;
  DCHECK_GE(result.time.hour, 0);
  DCHECK_LE(result.time.hour, 23);
  // 8. Let minute be ! MinFromTime(epochMilliseconds).
  result.time.minute = min;
  DCHECK_GE(result.time.minute, 0);
  DCHECK_LE(result.time.minute, 59);
  // 9. Let second be ! SecFromTime(epochMilliseconds).
  result.time.second = sec;
  DCHECK_GE(result.time.second, 0);
  DCHECK_LE(result.time.second, 59);
  // 10. Let millisecond be ! msFromTime(epochMilliseconds).
  result.time.millisecond = ms;
  DCHECK_GE(result.time.millisecond, 0);
  DCHECK_LE(result.time.millisecond, 999);
  // 11. Let microsecond be floor(remainderNs / 1000) modulo 1000.
  int64_t remainder = remainder_ns->AsInt64();
  result.time.microsecond = (remainder / 1000) % 1000;
  DCHECK_GE(result.time.microsecond, 0);
  // 12. 12. Assert: microsecond < 1000.
  DCHECK_LE(result.time.microsecond, 999);
  // 13. Let nanosecond be remainderNs modulo 1000.
  result.time.nanosecond = remainder % 1000;
  DCHECK_GE(result.time.nanosecond, 0);
  DCHECK_LE(result.time.nanosecond, 999);
  // 14. Return the Record { [[Year]]: year, [[Month]]: month, [[Day]]: day,
  // [[Hour]]: hour, [[Minute]]: minute, [[Second]]: second, [[Millisecond]]:
  // millisecond, [[Microsecond]]: microsecond, [[Nanosecond]]: nanosecond }.
  return result;
}

// #sec-temporal-balanceisodatetime
DateTimeRecord BalanceISODateTime(Isolate* isolate,
                                  const DateTimeRecord& date_time) {
  TEMPORAL_ENTER_FUNC();
  // 1. Assert: year, month, day, hour, minute, second, millisecond,
  // microsecond, and nanosecond are integers.
  // 2. Let balancedTime be ! BalanceTime(hour, minute, second, millisecond,
  // microsecond, nanosecond).
  DateTimeRecord balanced_time =
      BalanceTime({static_cast<double>(date_time.time.hour),
                   static_cast<double>(date_time.time.minute),
                   static_cast<double>(date_time.time.second),
                   static_cast<double>(date_time.time.millisecond),
                   static_cast<double>(date_time.time.microsecond),
                   static_cast<double>(date_time.time.nanosecond)});
  // 3. Let balancedDate be ! BalanceISODate(year, month, day +
  // balancedTime.[[Days]]).
  DateRecord added_date = date_time.date;
  added_date.day += balanced_time.date.day;
  DateRecord balanced_date = BalanceISODate(isolate, added_date);
  // 4. Return the Record { [[Year]]: balancedDate.[[Year]], [[Month]]:
  // balancedDate.[[Month]], [[Day]]: balancedDate.[[Day]], [[Hour]]:
  // balancedTime.[[Hour]], [[Minute]]: balancedTime.[[Minute]], [[Second]]:
  // balancedTime.[[Second]], [[Millisecond]]: balancedTime.[[Millisecond]],
  // [[Microsecond]]: balancedTime.[[Microsecond]], [[Nanosecond]]:
  // balancedTime.[[Nanosecond]] }.
  return {balanced_date, balanced_time.time};
}

// #sec-temporal-roundtowardszero
double RoundTowardsZero(double x) {
  // 1. Return the mathematical value that is the same sign as x and whose
  // magnitude is floor(abs(x)).
  if (x < 0) {
    return -std::floor(std::abs(x));
  } else {
    return std::floor(std::abs(x));
  }
}

// #sec-temporal-temporaldurationtostring
Handle<String> TemporalDurationToString(Isolate* isolate,
                                        const DurationRecord& duration,
                                        Precision precision) {
  IncrementalStringBuilder builder(isolate);
  DCHECK(precision != Precision::kMinute);
  // 1. Let sign be ! DurationSign(years, months, weeks, days, hours, minutes,
  // seconds, milliseconds, microseconds, nanoseconds).
  DurationRecord dur = duration;
  int32_t sign = DurationRecord::Sign(dur);
  // Note: for the operation below, to avoid microseconds .. seconds lost
  // precision while the resulting value may exceed the precision limit, we use
  // extra double xx_add to hold the additional temp value.
  // 2. Set microseconds to microseconds + RoundTowardsZero(nanoseconds / 1000).
  double microseconds_add =
      RoundTowardsZero(dur.time_duration.nanoseconds / 1000);
  // 3. Set nanoseconds to remainder(nanoseconds, 1000).
  dur.time_duration.nanoseconds =
      std::fmod(dur.time_duration.nanoseconds, 1000);
  // 4. Set milliseconds to milliseconds + RoundTowardsZero(microseconds /
  // 1000).
  double milliseconds_add = RoundTowardsZero(
      dur.time_duration.microseconds / 1000 + microseconds_add / 1000);
  // 5. Set microseconds to remainder(microseconds, 1000).
  dur.time_duration.microseconds =
      std::fmod(std::fmod(dur.time_duration.microseconds, 1000) +
                    std::fmod(microseconds_add, 1000),
                1000);
  // 6. Set seconds to seconds + RoundTowardsZero(milliseconds / 1000).
  double seconds_add = RoundTowardsZero(dur.time_duration.milliseconds / 1000 +
                                        milliseconds_add / 1000);
  // 7. Set milliseconds to remainder(milliseconds, 1000).
  dur.time_duration.milliseconds =
      std::fmod(std::fmod(dur.time_duration.milliseconds, 1000) +
                    std::fmod(milliseconds_add, 1000),
                1000);

  // 8. Let datePart be "".
  IncrementalStringBuilder date_part(isolate);
  // Number.MAX_VALUE.toString() is "1.7976931348623157e+308"
  // We add several more spaces to 320.
  base::ScopedVector<char> buf(320);

  // 9. If years is not 0, then
  if (dur.years != 0) {
    // a. Set datePart to the string concatenation of abs(years) formatted as a
    // decimal number and the code unit 0x0059 (LATIN CAPITAL LETTER Y).
    SNPrintF(buf, "%.0f", std::abs(dur.years));
    date_part.AppendCString(buf.data());
    date_part.AppendCharacter('Y');
  }
  // 10. If months is not 0, then
  if (dur.months != 0) {
    // a. Set datePart to the string concatenation of datePart,
    // abs(months) formatted as a decimal number, and the code unit
    // 0x004D (LATIN CAPITAL LETTER M).
    SNPrintF(buf, "%.0f", std::abs(dur.months));
    date_part.AppendCString(buf.data());
    date_part.AppendCharacter('M');
  }
  // 11. If weeks is not 0, then
  if (dur.weeks != 0) {
    // a. Set datePart to the string concatenation of datePart,
    // abs(weeks) formatted as a decimal number, and the code unit
    // 0x0057 (LATIN CAPITAL LETTER W).
    SNPrintF(buf, "%.0f", std::abs(dur.weeks));
    date_part.AppendCString(buf.data());
    date_part.AppendCharacter('W');
  }
  // 12. If days is not 0, then
  if (dur.time_duration.days != 0) {
    // a. Set datePart to the string concatenation of datePart,
    // abs(days) formatted as a decimal number, and the code unit 0x0044
    // (LATIN CAPITAL LETTER D).
    SNPrintF(buf, "%.0f", std::abs(dur.time_duration.days));
    date_part.AppendCString(buf.data());
    date_part.AppendCharacter('D');
  }
  // 13. Let timePart be "".
  IncrementalStringBuilder time_part(isolate);
  // 14. If hours is not 0, then
  if (dur.time_duration.hours != 0) {
    // a. Set timePart to the string concatenation of abs(hours) formatted as a
    // decimal number and the code unit 0x0048 (LATIN CAPITAL LETTER H).
    SNPrintF(buf, "%.0f", std::abs(dur.time_duration.hours));
    time_part.AppendCString(buf.data());
    time_part.AppendCharacter('H');
  }
  // 15. If minutes is not 0, then
  if (dur.time_duration.minutes != 0) {
    // a. Set timePart to the string concatenation of timePart,
    // abs(minutes) formatted as a decimal number, and the code unit
    // 0x004D (LATIN CAPITAL LETTER M).
    SNPrintF(buf, "%.0f", std::abs(dur.time_duration.minutes));
    time_part.AppendCString(buf.data());
    time_part.AppendCharacter('M');
  }
  IncrementalStringBuilder seconds_part(isolate);
  IncrementalStringBuilder decimal_part(isolate);
  // 16. If any of seconds, milliseconds, microseconds, and nanoseconds are not
  // 0; or years, months, weeks, days, hours, and minutes are all 0, or
  // precision is not "auto" then
  if ((dur.time_duration.seconds != 0 || seconds_add != 0 ||
       dur.time_duration.milliseconds != 0 ||
       dur.time_duration.microseconds != 0 ||
       dur.time_duration.nanoseconds != 0) ||
      (dur.years == 0 && dur.months == 0 && dur.weeks == 0 &&
       dur.time_duration.days == 0 && dur.time_duration.hours == 0 &&
       dur.time_duration.minutes == 0) ||
      precision != Precision::kAuto) {
    // a. Let fraction be abs(milliseconds) × 10^6 + abs(microseconds) × 10^3 +
    // abs(nanoseconds).
    int64_t fraction = std::abs(dur.time_duration.milliseconds) * 1e6 +
                       std::abs(dur.time_duration.microseconds) * 1e3 +
                       std::abs(dur.time_duration.nanoseconds);
    // b. Let decimalPart be fraction formatted as a nine-digit decimal number,
    // padded to the left with zeroes if necessary.
    int64_t divisor = 100000000;

    // c. If precision is "auto", then
    if (precision == Precision::kAuto) {
      // i. Set decimalPart to the longest possible substring of decimalPart
      // starting at position 0 and not ending with the code unit 0x0030 (DIGIT
      // ZERO).
      while (fraction > 0) {
        decimal_part.AppendInt(static_cast<int32_t>(fraction / divisor));
        fraction %= divisor;
        divisor /= 10;
      }
      // d. Else if precision = 0, then
    } else if (precision == Precision::k0) {
      // i. Set decimalPart to "".
      // e. Else,
    } else {
      // i. Set decimalPart to the substring of decimalPart from 0 to precision.
      int32_t precision_len = static_cast<int32_t>(precision);
      DCHECK_LE(0, precision_len);
      DCHECK_GE(9, precision_len);
      for (int32_t len = 0; len < precision_len; len++) {
        decimal_part.AppendInt(static_cast<int32_t>(fraction / divisor));
        fraction %= divisor;
        divisor /= 10;
      }
    }
    // f. Let secondsPart be abs(seconds) formatted as a decimal number.
    if (std::abs(seconds_add + dur.time_duration.seconds) < kMaxSafeInteger) {
      // Fast path: The seconds_add + dur.time_duration.seconds is in the range
      // the double could keep the precision.
      dur.time_duration.seconds += seconds_add;
      SNPrintF(buf, "%.0f", std::abs(dur.time_duration.seconds));
      seconds_part.AppendCString(buf.data());
    } else {
      // Slow path: The seconds_add + dur.time_duration.seconds is out of the
      // range which the double could keep the precision. Format by math via
      // BigInt.
      seconds_part.AppendString(
          BigInt::ToString(
              isolate,
              BigInt::Add(
                  isolate,
                  BigInt::FromNumber(isolate, isolate->factory()->NewNumber(
                                                  std::abs(seconds_add)))
                      .ToHandleChecked(),
                  BigInt::FromNumber(isolate,
                                     isolate->factory()->NewNumber(
                                         std::abs(dur.time_duration.seconds)))
                      .ToHandleChecked())
                  .ToHandleChecked())
              .ToHandleChecked());
    }

    // g. If decimalPart is not "", then
    if (decimal_part.Length() != 0) {
      // i. Set secondsPart to the string-concatenation of secondsPart, the code
      // unit 0x002E (FULL STOP), and decimalPart.
      seconds_part.AppendCharacter('.');
      seconds_part.AppendString(decimal_part.Finish().ToHandleChecked());
    }

    // h. Set timePart to the string concatenation of timePart, secondsPart, and
    // the code unit 0x0053 (LATIN CAPITAL LETTER S).
    time_part.AppendString(seconds_part.Finish().ToHandleChecked());
    time_part.AppendCharacter('S');
  }
  // 17. Let signPart be the code unit 0x002D (HYPHEN-MINUS) if sign < 0, and
  // otherwise the empty String.
  if (sign < 0) {
    builder.AppendCharacter('-');
  }

  // 18. Let result be the string concatenation of signPart, the code unit
  // 0x0050 (LATIN CAPITAL LETTER P) and datePart.
  builder.AppendCharacter('P');
  builder.AppendString(date_part.Finish().ToHandleChecked());

  // 19. If timePart is not "", then
  if (time_part.Length() > 0) {
    // a. Set result to the string concatenation of result, the code unit 0x0054
    // (LATIN CAPITAL LETTER T), and timePart.
    builder.AppendCharacter('T');
    builder.AppendString(time_part.Finish().ToHandleChecked());
  }
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

void ToZeroPaddedDecimalString(IncrementalStringBuilder* builder, int32_t n,
                               int32_t min_length);
// #sec-temporal-formatsecondsstringpart
void FormatSecondsStringPart(IncrementalStringBuilder* builder, int32_t second,
                             int32_t millisecond, int32_t microsecond,
                             int32_t nanosecond, Precision precision) {
  // 1. Assert: second, millisecond, microsecond and nanosecond are integers.
  // 2. If precision is "minute", return "".
  if (precision == Precision::kMinute) {
    return;
  }
  // 3. Let secondsString be the string-concatenation of the code unit 0x003A
  // (COLON) and second formatted as a two-digit decimal number, padded to the
  // left with zeroes if necessary.
  builder->AppendCharacter(':');
  ToZeroPaddedDecimalString(builder, second, 2);
  // 4. Let fraction be millisecond × 10^6 + microsecond × 10^3 + nanosecond.
  int64_t fraction = millisecond * 1000000 + microsecond * 1000 + nanosecond;
  int64_t divisor = 100000000;
  // 5. If precision is "auto", then
  if (precision == Precision::kAuto) {
    // a. If fraction is 0, return secondsString.
    if (fraction == 0) {
      return;
    }
    builder->AppendCharacter('.');
    // b. Set fraction to ToZeroPaddedDecimalString(fraction, 9).
    // c. Set fraction to the longest possible substring of fraction starting at
    // position 0 and not ending with the code unit 0x0030 (DIGIT ZERO).
    while (fraction > 0) {
      builder->AppendInt(static_cast<int32_t>(fraction / divisor));
      fraction %= divisor;
      divisor /= 10;
    }
    // 6. Else,
  } else {
    // a. If precision is 0, return secondsString.
    if (precision == Precision::k0) {
      return;
    }
    builder->AppendCharacter('.');
    // b. Set fraction to ToZeroPaddedDecimalString(fraction, 9).
    // c. Set fraction to the substring of fraction from 0 to precision.
    int32_t precision_len = static_cast<int32_t>(precision);
    DCHECK_LE(0, precision_len);
    DCHECK_GE(9, precision_len);
    for (int32_t len = 0; len < precision_len; len++) {
      builder->AppendInt(static_cast<int32_t>(fraction / divisor));
```