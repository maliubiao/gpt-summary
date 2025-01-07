Response:
Let's break down the thought process for analyzing this `date.cc` file.

**1. Initial Scan and Understanding the Context:**

* **File Path:** `v8/src/date/date.cc`. The `date` directory strongly suggests this code deals with date and time functionalities within the V8 JavaScript engine.
* **Copyright Header:** Confirms it's part of the V8 project.
* **Includes:**  The included headers (`limits`, `overflowing-math`, `dateparser-inl.h`, `conversions.h`, `objects-inl.h`, `intl-objects.h` (conditionally), `string-stream.h`) provide clues:
    * `limits`: Standard library for numerical limits (e.g., NaN).
    * `overflowing-math`:  Likely for handling potential overflows in calculations.
    * `dateparser-inl.h`:  Suggests parsing of date strings.
    * `conversions.h`:  Deals with converting between different data types (likely numbers).
    * `objects-inl.h`, `intl-objects.h`: Interaction with V8's internal object representation, especially for internationalization (if `V8_INTL_SUPPORT` is defined).
    * `string-stream.h`:  For efficient string building.
* **Namespace:** `v8::internal`. This indicates it's part of V8's internal implementation, not directly exposed to JavaScript.

**2. Identifying Key Components and Their Roles:**

* **Constants:**  `kDaysIn4Years`, `kDaysIn100Years`, etc. These look like calculations related to the Gregorian calendar. They likely form the basis for converting between dates and days.
* **`DateCache` Class:**  This is a prominent class. The name suggests it's for caching date-related information. Its members (`stamp_`, `tz_cache_`, `cache_`, `before_`, `after_`, `ymd_valid_`, etc.) point to its caching functionality for timezone offsets and year-month-day calculations. The methods within it (e.g., `ResetDateCache`, `YearMonthDayFromDays`, `LocalOffsetInMs`) confirm this.
* **Helper Functions:** `MakeDate`, `MakeDay`, `MakeTime`. These functions construct date/time values from their components.
* **Formatting/Parsing Functions:** `ToDateString`, `ParseDateTimeString`. These deal with converting date/time values to and from string representations.

**3. Analyzing Functionality and Connecting to JavaScript:**

* **Core Date/Time Calculations:** The constants and functions like `YearMonthDayFromDays` and `DaysFromYearMonth` are the foundation for JavaScript's `Date` object. JavaScript's `Date` object needs to be able to convert between milliseconds since the epoch and year, month, day, etc.
* **Timezone Handling:** The `DateCache` and its interaction with `base::OS::CreateTimezoneCache()` or `Intl::CreateTimeZoneCache()` are crucial for handling timezones in JavaScript. JavaScript needs to be aware of local time and UTC.
* **String Conversion:** `ToDateString` directly relates to methods like `Date.prototype.toString()`, `Date.prototype.toDateString()`, `Date.prototype.toLocaleTimeString()`, etc. `ParseDateTimeString` is the backend for `Date.parse()`.
* **Caching:** The `DateCache` is an optimization. Repeatedly calculating timezone offsets can be expensive. The cache improves performance.

**4. Considering Torque (as per the prompt):**

* **`.tq` Extension:** The prompt explicitly mentions the `.tq` extension. Since this file is `.cc`, it's **not** a Torque file. Torque is a type system and code generation tool used in V8.

**5. Generating Examples and Scenarios:**

* **JavaScript Examples:**  Think of common `Date` object usage in JavaScript that would rely on the functionality in this C++ file. Creating a `Date` object, getting/setting date components, formatting dates, parsing dates – these are good starting points.
* **Logic Inference:**  Choose a function with clear input and output. `YearMonthDayFromDays` is a good candidate. Pick a simple date, convert it to days since the epoch (you might need to look up the formula or use an online converter), and then manually trace the logic.
* **Common Errors:**  Consider typical mistakes developers make when working with dates in JavaScript:  timezone confusion, incorrect date formats for parsing, off-by-one errors with months (0-indexed), and not handling invalid date inputs.

**6. Structuring the Answer:**

Organize the findings logically:

* **Overview:** Briefly state the file's purpose.
* **Key Functions:**  List and explain the major functionalities.
* **JavaScript Relationship:**  Show how the C++ code connects to JavaScript's `Date` object.
* **Torque:** Address the `.tq` question directly.
* **Logic Inference:** Provide a clear example with input and expected output.
* **Common Errors:**  Give practical examples of mistakes developers make.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This file just does basic date calculations."
* **Correction:** "No, it also handles timezones and has a caching mechanism, making it more complex."
* **Initial thought:** "The constants are arbitrary magic numbers."
* **Correction:** "These constants are derived from the Gregorian calendar system and have a specific meaning related to leap years and the number of days in different periods."
* **Double-checking:** Ensure the JavaScript examples are accurate and clearly illustrate the connection to the C++ functionality. Verify the logic inference example.

By following these steps, you can systematically analyze a complex C++ source file like `date.cc` and extract the relevant information to answer the prompt effectively.
This `v8/src/date/date.cc` 文件是 V8 JavaScript 引擎中处理日期和时间的核心 C++ 源代码文件。它包含了实现 JavaScript `Date` 对象功能的底层逻辑。

**主要功能列举:**

1. **日期和时间的表示和计算:**
   - 定义了表示日期和时间的基础常量，例如一年中的天数、四年中的天数、100年中的天数、400年中的天数等，用于进行日期和时间的计算。
   - 提供了将日期分解为年、月、日，以及将时间分解为小时、分钟、秒、毫秒的函数（例如 `YearMonthDayFromDays`, `BreakDownTime`）。
   - 提供了将年、月转换为从某个基准日期开始的天数的函数（例如 `DaysFromYearMonth`）。
   - 实现了 `MakeDate`, `MakeDay`, `MakeTime` 等函数，用于构建日期和时间值。

2. **时区处理和转换:**
   - 包含了 `DateCache` 类，用于缓存时区信息，提高性能。
   - 提供了获取本地时区偏移量的函数 (`GetLocalOffsetFromOS`, `LocalOffsetInMs`)，用于在 UTC 时间和本地时间之间进行转换。
   - 能够处理夏令时（Daylight Saving Time, DST）。
   - 提供了获取本地时区名称的函数（虽然代码片段中没有直接展示，但 `DateCache` 中有 `tz_name_` 和 `dst_tz_name_` 成员）。

3. **日期和时间字符串的格式化和解析:**
   - 实现了将 `Date` 对象格式化为各种字符串表示的函数 (`ToDateString`)，支持不同的模式，如本地日期、本地时间、UTC 日期和时间、ISO 格式等。
   - 提供了将日期和时间字符串解析为 `Date` 对象的函数 (`ParseDateTimeString`)。

**关于 Torque 源代码:**

如果 `v8/src/date/date.cc` 以 `.tq` 结尾，那么它的确是一个 V8 Torque 源代码文件。Torque 是 V8 使用的一种类型安全的中间语言，用于生成高效的 C++ 代码。但根据你提供的文件名 `.cc`，这个文件是标准的 C++ 源代码。V8 项目中经常可以看到 `.tq` 文件，它们通常与底层的类型定义、内置函数的实现等相关。

**与 JavaScript 功能的关系以及 JavaScript 示例:**

`v8/src/date/date.cc` 文件中的功能直接支撑了 JavaScript 中的 `Date` 对象。当你使用 JavaScript 的 `Date` 对象时，V8 引擎会调用这个文件中的 C++ 代码来执行相应的操作。

以下是一些 JavaScript 示例，展示了与 `date.cc` 中功能相关的操作：

```javascript
// 创建一个 Date 对象
const now = new Date();

// 获取年、月、日、小时、分钟、秒
const year = now.getFullYear();
const month = now.getMonth(); // 注意：月份从 0 开始
const day = now.getDate();
const hour = now.getHours();
const minute = now.getMinutes();
const second = now.getSeconds();

// 获取时间戳 (毫秒)
const timestamp = now.getTime();

// 获取 UTC 时间
const utcYear = now.getUTCFullYear();
const utcMonth = now.getUTCMonth();
const utcHours = now.getUTCHours();

// 格式化日期和时间为字符串
const dateString = now.toDateString(); // "Tue Oct 24 2023"
const timeString = now.toLocaleTimeString(); // "下午4:30:00" (根据本地设置)
const isoString = now.toISOString(); // "2023-10-24T08:30:00.000Z"

// 解析日期和时间字符串
const parsedDate = new Date("2023-10-25T10:00:00Z");

// 获取时区偏移 (分钟)
const timezoneOffset = now.getTimezoneOffset();
```

这些 JavaScript 代码在底层会调用 `date.cc` 中实现的相应 C++ 函数来进行日期和时间的处理、格式化、解析以及时区转换。例如，`getFullYear()` 可能会间接调用 `YearMonthDayFromDays`，`getTimezoneOffset()` 会涉及到 `DateCache` 和时区信息的获取。

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `YearMonthDayFromDays` 函数，该函数根据从 1970-01-01 (Unix 纪元) 开始计算的天数，计算出对应的年、月、日。

**假设输入:** `days = 738832` (代表从 1970-01-01 开始的第 738832 天，对应 2023-10-24)

**预期输出:**
- `year = 2023`
- `month = 9`  (月份从 0 开始，所以 9 代表 10 月)
- `day = 24`

**代码逻辑简述:**

`YearMonthDayFromDays` 函数首先会尝试使用缓存 (`ymd_valid_`)，如果缓存命中并且在同一个月份内，可以直接计算出日期。否则，它会进行一系列的数学运算，利用预定义的常量 (`kDaysOffset`, `kDaysIn400Years` 等) 来确定年份，然后逐步计算出月份和日期，同时考虑闰年的影响。

**用户常见的编程错误:**

1. **混淆本地时间和 UTC 时间:**  开发者经常忘记 JavaScript `Date` 对象的方法分为本地时间和 UTC 时间（例如 `getFullYear()` vs. `getUTCFullYear()`），导致在不同时区下显示错误。

   ```javascript
   const date = new Date();
   console.log(date.getFullYear()); // 输出本地年份
   console.log(date.getUTCFullYear()); // 输出 UTC 年份
   ```

2. **错误的月份索引:** JavaScript 的 `Date` 对象中，月份是从 0 开始的（0 代表一月，11 代表十二月）。这是一个常见的 "off-by-one" 错误。

   ```javascript
   const date = new Date(2023, 10, 25); // 注意：10 代表 11 月
   console.log(date.getMonth()); // 输出 10
   ```

3. **解析日期字符串格式不匹配:** `Date.parse()` 和 `new Date(string)` 对日期字符串的格式有要求。如果格式不匹配，可能会得到 `Invalid Date` 或解析出错误的日期。

   ```javascript
   const invalidDate = new Date("2023/10/25"); // 某些浏览器可能无法正确解析
   const validDate = new Date("2023-10-25T10:00:00Z"); // ISO 格式通常更可靠
   ```

4. **时区处理不当:**  在处理跨时区的应用时，没有明确指定时区或进行正确的时区转换会导致时间显示错误。应该尽量使用 UTC 时间进行存储和传输，然后在用户界面上根据用户所在的时区进行显示。

   ```javascript
   // 存储 UTC 时间
   const utcDate = new Date();
   const utcTimestamp = utcDate.getTime();

   // 在本地显示 (需要考虑用户时区)
   const localDate = new Date(utcTimestamp);
   ```

`v8/src/date/date.cc` 的存在和功能对于理解 JavaScript `Date` 对象的行为至关重要。它揭示了 V8 引擎如何在底层处理复杂的日期和时间操作，包括时区转换和格式化解析。了解这些底层机制可以帮助开发者更好地理解和使用 JavaScript 的 `Date` 对象，并避免常见的编程错误。

Prompt: 
```
这是目录为v8/src/date/date.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/date/date.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/date/date.h"

#include <limits>

#include "src/base/overflowing-math.h"
#include "src/date/dateparser-inl.h"
#include "src/numbers/conversions.h"
#include "src/objects/objects-inl.h"
#ifdef V8_INTL_SUPPORT
#include "src/objects/intl-objects.h"
#endif
#include "src/strings/string-stream.h"

namespace v8 {
namespace internal {

static const int kDaysIn4Years = 4 * 365 + 1;
static const int kDaysIn100Years = 25 * kDaysIn4Years - 1;
static const int kDaysIn400Years = 4 * kDaysIn100Years + 1;
static const int kDays1970to2000 = 30 * 365 + 7;
static const int kDaysOffset =
    1000 * kDaysIn400Years + 5 * kDaysIn400Years - kDays1970to2000;
static const int kYearsOffset = 400000;
static const char kDaysInMonths[] = {31, 28, 31, 30, 31, 30,
                                     31, 31, 30, 31, 30, 31};

DateCache::DateCache()
    : stamp_(kNullAddress),
      tz_cache_(
#ifdef V8_INTL_SUPPORT
          Intl::CreateTimeZoneCache()
#else
          base::OS::CreateTimezoneCache()
#endif
      ) {
  ResetDateCache(base::TimezoneCache::TimeZoneDetection::kSkip);
}

void DateCache::ResetDateCache(
    base::TimezoneCache::TimeZoneDetection time_zone_detection) {
  if (stamp_.value() >= Smi::kMaxValue) {
    stamp_ = Smi::zero();
  } else {
    stamp_ = Smi::FromInt(stamp_.value() + 1);
  }
  DCHECK(stamp_ != Smi::FromInt(kInvalidStamp));
  for (int i = 0; i < kCacheSize; ++i) {
    ClearSegment(&cache_[i]);
  }
  cache_usage_counter_ = 0;
  before_ = &cache_[0];
  after_ = &cache_[1];
  ymd_valid_ = false;
#ifdef V8_INTL_SUPPORT
  if (!v8_flags.icu_timezone_data) {
#endif
    local_offset_ms_ = kInvalidLocalOffsetInMs;
#ifdef V8_INTL_SUPPORT
  }
#endif
  tz_cache_->Clear(time_zone_detection);
  tz_name_ = nullptr;
  dst_tz_name_ = nullptr;
}

void DateCache::ClearSegment(CacheItem* segment) {
  segment->start_ms = 0;
  segment->end_ms = -1;
  segment->offset_ms = 0;
  segment->last_used = 0;
}

void DateCache::YearMonthDayFromDays(int days, int* year, int* month,
                                     int* day) {
  if (ymd_valid_) {
    // Check conservatively if the given 'days' has
    // the same year and month as the cached 'days'.
    int new_day = ymd_day_ + (days - ymd_days_);
    if (new_day >= 1 && new_day <= 28) {
      ymd_day_ = new_day;
      ymd_days_ = days;
      *year = ymd_year_;
      *month = ymd_month_;
      *day = new_day;
      return;
    }
  }
  int save_days = days;

  days += kDaysOffset;
  *year = 400 * (days / kDaysIn400Years) - kYearsOffset;
  days %= kDaysIn400Years;

  DCHECK_EQ(save_days, DaysFromYearMonth(*year, 0) + days);

  days--;
  int yd1 = days / kDaysIn100Years;
  days %= kDaysIn100Years;
  *year += 100 * yd1;

  days++;
  int yd2 = days / kDaysIn4Years;
  days %= kDaysIn4Years;
  *year += 4 * yd2;

  days--;
  int yd3 = days / 365;
  days %= 365;
  *year += yd3;

  bool is_leap = (!yd1 || yd2) && !yd3;

  DCHECK_GE(days, -1);
  DCHECK(is_leap || (days >= 0));
  DCHECK((days < 365) || (is_leap && (days < 366)));
  DCHECK(is_leap == ((*year % 4 == 0) && (*year % 100 || (*year % 400 == 0))));
  DCHECK(is_leap || ((DaysFromYearMonth(*year, 0) + days) == save_days));
  DCHECK(!is_leap || ((DaysFromYearMonth(*year, 0) + days + 1) == save_days));

  days += is_leap;

  // Check if the date is after February.
  if (days >= 31 + 28 + (is_leap ? 1 : 0)) {
    days -= 31 + 28 + (is_leap ? 1 : 0);
    // Find the date starting from March.
    for (int i = 2; i < 12; i++) {
      if (days < kDaysInMonths[i]) {
        *month = i;
        *day = days + 1;
        break;
      }
      days -= kDaysInMonths[i];
    }
  } else {
    // Check January and February.
    if (days < 31) {
      *month = 0;
      *day = days + 1;
    } else {
      *month = 1;
      *day = days - 31 + 1;
    }
  }
  DCHECK(DaysFromYearMonth(*year, *month) + *day - 1 == save_days);
  ymd_valid_ = true;
  ymd_year_ = *year;
  ymd_month_ = *month;
  ymd_day_ = *day;
  ymd_days_ = save_days;
}

int DateCache::DaysFromYearMonth(int year, int month) {
  static const int day_from_month[] = {0,   31,  59,  90,  120, 151,
                                       181, 212, 243, 273, 304, 334};
  static const int day_from_month_leap[] = {0,   31,  60,  91,  121, 152,
                                            182, 213, 244, 274, 305, 335};

  year += month / 12;
  month %= 12;
  if (month < 0) {
    year--;
    month += 12;
  }

  DCHECK_GE(month, 0);
  DCHECK_LT(month, 12);

  // year_delta is an arbitrary number such that:
  // a) year_delta = -1 (mod 400)
  // b) year + year_delta > 0 for years in the range defined by
  //    ECMA 262 - 15.9.1.1, i.e. upto 100,000,000 days on either side of
  //    Jan 1 1970. This is required so that we don't run into integer
  //    division of negative numbers.
  // c) there shouldn't be an overflow for 32-bit integers in the following
  //    operations.
  static const int year_delta = 399999;
  static const int base_day =
      365 * (1970 + year_delta) + (1970 + year_delta) / 4 -
      (1970 + year_delta) / 100 + (1970 + year_delta) / 400;

  int year1 = year + year_delta;
  int day_from_year =
      365 * year1 + year1 / 4 - year1 / 100 + year1 / 400 - base_day;

  if ((year % 4 != 0) || (year % 100 == 0 && year % 400 != 0)) {
    return day_from_year + day_from_month[month];
  }
  return day_from_year + day_from_month_leap[month];
}

void DateCache::BreakDownTime(int64_t time_ms, int* year, int* month, int* day,
                              int* weekday, int* hour, int* min, int* sec,
                              int* ms) {
  int const days = DaysFromTime(time_ms);
  int const time_in_day_ms = TimeInDay(time_ms, days);
  YearMonthDayFromDays(days, year, month, day);
  *weekday = Weekday(days);
  *hour = time_in_day_ms / (60 * 60 * 1000);
  *min = (time_in_day_ms / (60 * 1000)) % 60;
  *sec = (time_in_day_ms / 1000) % 60;
  *ms = time_in_day_ms % 1000;
}

// Implements LocalTimeZonedjustment(t, isUTC)
// ECMA 262 - ES#sec-local-time-zone-adjustment
int DateCache::GetLocalOffsetFromOS(int64_t time_ms, bool is_utc) {
  double offset;
#ifdef V8_INTL_SUPPORT
  if (v8_flags.icu_timezone_data) {
    offset = tz_cache_->LocalTimeOffset(static_cast<double>(time_ms), is_utc);
  } else {
#endif
    // When ICU timezone data is not used, we need to compute the timezone
    // offset for a given local time.
    //
    // The following shows that using DST for (t - LocalTZA - hour) produces
    // correct conversion where LocalTZA is the timezone offset in winter (no
    // DST) and the timezone offset is assumed to have no historical change.
    // Note that it does not work for the past and the future if LocalTZA (no
    // DST) is different from the current LocalTZA (no DST). For instance,
    // this will break for Europe/Moscow in 2012 ~ 2013 because LocalTZA was
    // 4h instead of the current 3h (as of 2018).
    //
    // Consider transition to DST at local time L1.
    // Let L0 = L1 - hour, L2 = L1 + hour,
    //     U1 = UTC time that corresponds to L1,
    //     U0 = U1 - hour.
    // Transitioning to DST moves local clock one hour forward L1 => L2, so
    // U0 = UTC time that corresponds to L0 = L0 - LocalTZA,
    // U1 = UTC time that corresponds to L1 = L1 - LocalTZA,
    // U1 = UTC time that corresponds to L2 = L2 - LocalTZA - hour.
    // Note that DST(U0 - hour) = 0, DST(U0) = 0, DST(U1) = 1.
    // U0 = L0 - LocalTZA - DST(L0 - LocalTZA - hour),
    // U1 = L1 - LocalTZA - DST(L1 - LocalTZA - hour),
    // U1 = L2 - LocalTZA - DST(L2 - LocalTZA - hour).
    //
    // Consider transition from DST at local time L1.
    // Let L0 = L1 - hour,
    //     U1 = UTC time that corresponds to L1,
    //     U0 = U1 - hour, U2 = U1 + hour.
    // Transitioning from DST moves local clock one hour back L1 => L0, so
    // U0 = UTC time that corresponds to L0 (before transition)
    //    = L0 - LocalTZA - hour.
    // U1 = UTC time that corresponds to L0 (after transition)
    //    = L0 - LocalTZA = L1 - LocalTZA - hour
    // U2 = UTC time that corresponds to L1 = L1 - LocalTZA.
    // Note that DST(U0) = 1, DST(U1) = 0, DST(U2) = 0.
    // U0 = L0 - LocalTZA - DST(L0 - LocalTZA - hour) = L0 - LocalTZA - DST(U0).
    // U2 = L1 - LocalTZA - DST(L1 - LocalTZA - hour) = L1 - LocalTZA - DST(U1).
    // It is impossible to get U1 from local time.
    if (local_offset_ms_ == kInvalidLocalOffsetInMs) {
      // This gets the constant LocalTZA (arguments are ignored).
      local_offset_ms_ =
          tz_cache_->LocalTimeOffset(static_cast<double>(time_ms), is_utc);
    }
    offset = local_offset_ms_;
    if (!is_utc) {
      const int kMsPerHour = 3600 * 1000;
      time_ms -= (offset + kMsPerHour);
    }
    offset += DaylightSavingsOffsetInMs(time_ms);
#ifdef V8_INTL_SUPPORT
  }
#endif
  DCHECK_LT(offset, kInvalidLocalOffsetInMs);
  return static_cast<int>(offset);
}

void DateCache::ExtendTheAfterSegment(int64_t time_ms, int offset_ms) {
  if (!InvalidSegment(after_) && after_->offset_ms == offset_ms &&
      after_->start_ms - kDefaultTimeZoneOffsetDeltaInMs <= time_ms &&
      time_ms <= after_->end_ms) {
    // Extend the after_ segment.
    after_->start_ms = time_ms;
  } else {
    // The after_ segment is either invalid or starts too late.
    if (!InvalidSegment(after_)) {
      // If the after_ segment is valid, replace it with a new segment.
      after_ = LeastRecentlyUsedCacheItem(before_);
    }
    after_->start_ms = time_ms;
    after_->end_ms = time_ms;
    after_->offset_ms = offset_ms;
    after_->last_used = ++cache_usage_counter_;
  }
}

int DateCache::LocalOffsetInMs(int64_t time_ms, bool is_utc) {
  if (!is_utc) {
    return GetLocalOffsetFromOS(time_ms, is_utc);
  }
#ifdef ENABLE_SLOW_DCHECKS
  int known_correct_result = 0;
  if (v8_flags.enable_slow_asserts) {
    // When slow DCHECKs are enabled, we always retrieve the known good result
    // (slow) and check that the result produced by the cache matches it.
    known_correct_result = GetLocalOffsetFromOS(time_ms, is_utc);
  }
#endif  // ENABLE_SLOW_DCHECKS
  // Invalidate cache if the usage counter is close to overflow.
  // Note that cache_usage_counter is incremented less than ten times
  // in this function.
  if (cache_usage_counter_ >= kMaxInt - 10) {
    cache_usage_counter_ = 0;
    for (int i = 0; i < kCacheSize; ++i) {
      ClearSegment(&cache_[i]);
    }
  }

  // Optimistic fast check.
  if (before_->start_ms <= time_ms && time_ms <= before_->end_ms) {
    // Cache hit.
    before_->last_used = ++cache_usage_counter_;
    SLOW_DCHECK(before_->offset_ms == known_correct_result);
    return before_->offset_ms;
  }

  ProbeCache(time_ms);

  DCHECK(InvalidSegment(before_) || before_->start_ms <= time_ms);
  DCHECK(InvalidSegment(after_) || time_ms < after_->start_ms);

  if (InvalidSegment(before_)) {
    // Cache miss.
    before_->start_ms = time_ms;
    before_->end_ms = time_ms;
    before_->offset_ms = GetLocalOffsetFromOS(time_ms, is_utc);
    before_->last_used = ++cache_usage_counter_;
    SLOW_DCHECK(before_->offset_ms == known_correct_result);
    return before_->offset_ms;
  }

  if (time_ms <= before_->end_ms) {
    // Cache hit.
    before_->last_used = ++cache_usage_counter_;
    SLOW_DCHECK(before_->offset_ms == known_correct_result);
    return before_->offset_ms;
  }

  if (time_ms - kDefaultTimeZoneOffsetDeltaInMs > before_->end_ms) {
    // If the before_ segment ends too early, then just
    // query for the offset of the time_ms
    int offset_ms = GetLocalOffsetFromOS(time_ms, is_utc);
    ExtendTheAfterSegment(time_ms, offset_ms);
    // This swap helps the optimistic fast check in subsequent invocations.
    CacheItem* temp = before_;
    before_ = after_;
    after_ = temp;
    SLOW_DCHECK(offset_ms == known_correct_result);
    return offset_ms;
  }

  // Now the time_ms is between
  // before_->end_ms and before_->end_ms + default time zone offset delta.
  // Update the usage counter of before_ since it is going to be used.
  before_->last_used = ++cache_usage_counter_;

  // Check if after_ segment is invalid or starts too late.
  int64_t new_after_start_ms =
      before_->end_ms + kDefaultTimeZoneOffsetDeltaInMs;
  if (InvalidSegment(after_) || new_after_start_ms <= after_->start_ms) {
    int new_offset_ms = GetLocalOffsetFromOS(new_after_start_ms, is_utc);
    ExtendTheAfterSegment(new_after_start_ms, new_offset_ms);
  } else {
    DCHECK(!InvalidSegment(after_));
    // Update the usage counter of after_ since it is going to be used.
    after_->last_used = ++cache_usage_counter_;
  }

  // Now the time_ms is between before_->end_ms and after_->start_ms.
  // Only one daylight savings offset change can occur in this interval.

  if (before_->offset_ms == after_->offset_ms) {
    // Merge two segments if they have the same offset.
    before_->end_ms = after_->end_ms;
    ClearSegment(after_);
    SLOW_DCHECK(before_->offset_ms == known_correct_result);
    return before_->offset_ms;
  }

  // Binary search for time zone offset change point,
  // but give up if we don't find it in five iterations.
  for (int i = 4; i >= 0; --i) {
    int64_t delta = after_->start_ms - before_->end_ms;
    int64_t middle_sec = (i == 0) ? time_ms : before_->end_ms + delta / 2;
    int offset_ms = GetLocalOffsetFromOS(middle_sec, is_utc);
    if (before_->offset_ms == offset_ms) {
      before_->end_ms = middle_sec;
      if (time_ms <= before_->end_ms) {
        SLOW_DCHECK(offset_ms == known_correct_result);
        return offset_ms;
      }
      // If we didn't return, we can't be in the last iteration.
      DCHECK_GT(i, 0);
    } else {
      DCHECK(after_->offset_ms == offset_ms);
      after_->start_ms = middle_sec;
      if (time_ms >= after_->start_ms) {
        // This swap helps the optimistic fast check in subsequent invocations.
        CacheItem* temp = before_;
        before_ = after_;
        after_ = temp;
        SLOW_DCHECK(offset_ms == known_correct_result);
        return offset_ms;
      }
      // If we didn't return, we can't be in the last iteration.
      DCHECK_GT(i, 0);
    }
  }
  // During the last iteration, we set middle_sec = time_ms and return via one
  // of the two return statements above. Thus, we never end up here.
  UNREACHABLE();
}

void DateCache::ProbeCache(int64_t time_ms) {
  CacheItem* before = nullptr;
  CacheItem* after = nullptr;
  DCHECK(before_ != after_);

  for (int i = 0; i < kCacheSize; ++i) {
    if (InvalidSegment(&cache_[i])) {
      continue;
    }
    if (cache_[i].start_ms <= time_ms) {
      if (before == nullptr || before->start_ms < cache_[i].start_ms) {
        before = &cache_[i];
      }
    } else if (time_ms < cache_[i].end_ms) {
      if (after == nullptr || after->end_ms > cache_[i].end_ms) {
        after = &cache_[i];
      }
    }
  }

  // If before or after segments were not found,
  // then set them to any invalid segment.
  if (before == nullptr) {
    before =
        InvalidSegment(before_) ? before_ : LeastRecentlyUsedCacheItem(after);
  }
  if (after == nullptr) {
    after = InvalidSegment(after_) && before != after_
                ? after_
                : LeastRecentlyUsedCacheItem(before);
  }

  DCHECK_NOT_NULL(before);
  DCHECK_NOT_NULL(after);
  DCHECK(before != after);
  DCHECK(InvalidSegment(before) || before->start_ms <= time_ms);
  DCHECK(InvalidSegment(after) || time_ms < after->start_ms);
  DCHECK(InvalidSegment(before) || InvalidSegment(after) ||
         before->end_ms < after->start_ms);

  before_ = before;
  after_ = after;
}

DateCache::CacheItem* DateCache::LeastRecentlyUsedCacheItem(CacheItem* skip) {
  CacheItem* result = nullptr;
  for (int i = 0; i < kCacheSize; ++i) {
    if (&cache_[i] == skip) continue;
    if (result == nullptr || result->last_used > cache_[i].last_used) {
      result = &cache_[i];
    }
  }
  ClearSegment(result);
  return result;
}

namespace {

// ES6 section 20.3.1.1 Time Values and Time Range
const double kMinYear = -1000000.0;
const double kMaxYear = -kMinYear;
const double kMinMonth = -10000000.0;
const double kMaxMonth = -kMinMonth;

const double kMsPerDay = 86400000.0;

const double kMsPerSecond = 1000.0;
const double kMsPerMinute = 60000.0;
const double kMsPerHour = 3600000.0;

}  // namespace

double MakeDate(double day, double time) {
  if (std::isfinite(day) && std::isfinite(time)) {
    return time + day * kMsPerDay;
  }
  return std::numeric_limits<double>::quiet_NaN();
}

double MakeDay(double year, double month, double date) {
  if ((kMinYear <= year && year <= kMaxYear) &&
      (kMinMonth <= month && month <= kMaxMonth) && std::isfinite(date)) {
    int y = FastD2I(year);
    int m = FastD2I(month);
    y += m / 12;
    m %= 12;
    if (m < 0) {
      m += 12;
      y -= 1;
    }
    DCHECK_LE(0, m);
    DCHECK_LT(m, 12);

    // kYearDelta is an arbitrary number such that:
    // a) kYearDelta = -1 (mod 400)
    // b) year + kYearDelta > 0 for years in the range defined by
    //    ECMA 262 - 15.9.1.1, i.e. upto 100,000,000 days on either side of
    //    Jan 1 1970. This is required so that we don't run into integer
    //    division of negative numbers.
    // c) there shouldn't be an overflow for 32-bit integers in the following
    //    operations.
    static const int kYearDelta = 399999;
    static const int kBaseDay =
        365 * (1970 + kYearDelta) + (1970 + kYearDelta) / 4 -
        (1970 + kYearDelta) / 100 + (1970 + kYearDelta) / 400;
    int day_from_year = 365 * (y + kYearDelta) + (y + kYearDelta) / 4 -
                        (y + kYearDelta) / 100 + (y + kYearDelta) / 400 -
                        kBaseDay;
    if ((y % 4 != 0) || (y % 100 == 0 && y % 400 != 0)) {
      static const int kDayFromMonth[] = {0,   31,  59,  90,  120, 151,
                                          181, 212, 243, 273, 304, 334};
      day_from_year += kDayFromMonth[m];
    } else {
      static const int kDayFromMonth[] = {0,   31,  60,  91,  121, 152,
                                          182, 213, 244, 274, 305, 335};
      day_from_year += kDayFromMonth[m];
    }
    return static_cast<double>(day_from_year - 1) + DoubleToInteger(date);
  }
  return std::numeric_limits<double>::quiet_NaN();
}

double MakeTime(double hour, double min, double sec, double ms) {
  if (std::isfinite(hour) && std::isfinite(min) && std::isfinite(sec) &&
      std::isfinite(ms)) {
    double const h = DoubleToInteger(hour);
    double const m = DoubleToInteger(min);
    double const s = DoubleToInteger(sec);
    double const milli = DoubleToInteger(ms);
    return h * kMsPerHour + m * kMsPerMinute + s * kMsPerSecond + milli;
  }
  return std::numeric_limits<double>::quiet_NaN();
}

namespace {

const char* kShortWeekDays[] = {"Sun", "Mon", "Tue", "Wed",
                                "Thu", "Fri", "Sat"};
const char* kShortMonths[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

template <class... Args>
DateBuffer FormatDate(const char* format, Args... args) {
  DateBuffer buffer;
  SmallStringOptimizedAllocator<DateBuffer::kInlineSize> allocator(&buffer);
  StringStream sstream(&allocator);
  sstream.Add(format, args...);
  buffer.resize_no_init(sstream.length());
  return buffer;
}

}  // namespace

DateBuffer ToDateString(double time_val, DateCache* date_cache,
                        ToDateStringMode mode) {
  if (std::isnan(time_val)) {
    return FormatDate("Invalid Date");
  }
  int64_t time_ms = static_cast<int64_t>(time_val);
  int64_t local_time_ms = (mode == ToDateStringMode::kUTCDateAndTime ||
                           mode == ToDateStringMode::kISODateAndTime)
                              ? time_ms
                              : date_cache->ToLocal(time_ms);
  int year, month, day, weekday, hour, min, sec, ms;
  date_cache->BreakDownTime(local_time_ms, &year, &month, &day, &weekday, &hour,
                            &min, &sec, &ms);
  int timezone_offset = -date_cache->TimezoneOffset(time_ms);
  int timezone_hour = std::abs(timezone_offset) / 60;
  int timezone_min = std::abs(timezone_offset) % 60;
  const char* local_timezone = date_cache->LocalTimezone(time_ms);
  switch (mode) {
    case ToDateStringMode::kLocalDate:
      return FormatDate((year < 0) ? "%s %s %02d %05d" : "%s %s %02d %04d",
                        kShortWeekDays[weekday], kShortMonths[month], day,
                        year);
    case ToDateStringMode::kLocalTime:
      return FormatDate("%02d:%02d:%02d GMT%c%02d%02d (%s)", hour, min, sec,
                        (timezone_offset < 0) ? '-' : '+', timezone_hour,
                        timezone_min, local_timezone);
    case ToDateStringMode::kLocalDateAndTime:
      return FormatDate(
          (year < 0) ? "%s %s %02d %05d %02d:%02d:%02d GMT%c%02d%02d (%s)"
                     : "%s %s %02d %04d %02d:%02d:%02d GMT%c%02d%02d (%s)",
          kShortWeekDays[weekday], kShortMonths[month], day, year, hour, min,
          sec, (timezone_offset < 0) ? '-' : '+', timezone_hour, timezone_min,
          local_timezone);
    case ToDateStringMode::kUTCDateAndTime:
      return FormatDate((year < 0) ? "%s, %02d %s %05d %02d:%02d:%02d GMT"
                                   : "%s, %02d %s %04d %02d:%02d:%02d GMT",
                        kShortWeekDays[weekday], day, kShortMonths[month], year,
                        hour, min, sec);
    case ToDateStringMode::kISODateAndTime:
      if (year >= 0 && year <= 9999) {
        return FormatDate("%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", year,
                          month + 1, day, hour, min, sec, ms);
      } else if (year < 0) {
        return FormatDate("-%06d-%02d-%02dT%02d:%02d:%02d.%03dZ", -year,
                          month + 1, day, hour, min, sec, ms);
      } else {
        return FormatDate("+%06d-%02d-%02dT%02d:%02d:%02d.%03dZ", year,
                          month + 1, day, hour, min, sec, ms);
      }
  }
  UNREACHABLE();
}

// ES6 section 20.3.1.16 Date Time String Format
double ParseDateTimeString(Isolate* isolate, Handle<String> str) {
  str = String::Flatten(isolate, str);
  double out[DateParser::OUTPUT_SIZE];
  DisallowGarbageCollection no_gc;
  String::FlatContent str_content = str->GetFlatContent(no_gc);
  bool result;
  if (str_content.IsOneByte()) {
    result = DateParser::Parse(isolate, str_content.ToOneByteVector(), out);
  } else {
    result = DateParser::Parse(isolate, str_content.ToUC16Vector(), out);
  }
  if (!result) return std::numeric_limits<double>::quiet_NaN();
  double const day = MakeDay(out[DateParser::YEAR], out[DateParser::MONTH],
                             out[DateParser::DAY]);
  double const time =
      MakeTime(out[DateParser::HOUR], out[DateParser::MINUTE],
               out[DateParser::SECOND], out[DateParser::MILLISECOND]);
  double date = MakeDate(day, time);
  if (std::isnan(out[DateParser::UTC_OFFSET])) {
    if (date >= -DateCache::kMaxTimeBeforeUTCInMs &&
        date <= DateCache::kMaxTimeBeforeUTCInMs) {
      date = isolate->date_cache()->ToUTC(static_cast<int64_t>(date));
    } else {
      return std::numeric_limits<double>::quiet_NaN();
    }
  } else {
    date -= out[DateParser::UTC_OFFSET] * 1000.0;
  }
  if (!DateCache::TryTimeClip(&date)) {
    return std::numeric_limits<double>::quiet_NaN();
  }
  return date;
}

}  // namespace internal
}  // namespace v8

"""

```