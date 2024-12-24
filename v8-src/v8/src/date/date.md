Response: Let's break down the thought process for analyzing the `date.cc` file.

1. **Understand the Goal:** The primary request is to summarize the functionality of `date.cc` and illustrate its connection to JavaScript's Date object.

2. **Initial Skim for High-Level Structure:**  Quickly read through the code, looking for:
    * **Includes:** What other components does it depend on? This gives clues about its responsibilities. Seeing `<limits>`, `dateparser-inl.h`, `objects-inl.h`, and potentially `intl-objects.h` (if `V8_INTL_SUPPORT` is defined) hints at date calculations, parsing, object interaction, and internationalization aspects.
    * **Namespaces:** `v8::internal` indicates this is an internal V8 implementation detail, not directly exposed to JavaScript.
    * **Constants:**  `kDaysIn4Years`, `kDaysIn100Years`, `kDaysIn400Years`, etc., immediately suggest core date/time calculations.
    * **Classes:** The presence of `DateCache` is a major indicator of a caching mechanism, likely for performance optimization related to timezone lookups.
    * **Functions:**  Function names like `YearMonthDayFromDays`, `DaysFromYearMonth`, `BreakDownTime`, `LocalOffsetInMs`, `MakeDate`, `MakeDay`, `MakeTime`, `ToDateString`, and `ParseDateTimeString` strongly point to date manipulation, formatting, and parsing.

3. **Focus on Key Components:** The `DateCache` class appears central. Analyze its members and methods:
    * **Members:** `stamp_`, `tz_cache_`, `cache_`, `before_`, `after_`, `ymd_valid_`, `local_offset_ms_`, `tz_name_`, `dst_tz_name_`. These suggest caching timestamps, timezone information, cached date components (year, month, day), and potentially timezone names.
    * **Methods:** `ResetDateCache`, `ClearSegment`, `YearMonthDayFromDays`, `DaysFromYearMonth`, `BreakDownTime`, `GetLocalOffsetFromOS`, `LocalOffsetInMs`, `ProbeCache`, `LeastRecentlyUsedCacheItem`. These methods clearly handle date component conversions, timezone offset calculations (potentially using the OS or ICU), and cache management (resetting, clearing, probing, and evicting). The presence of `GetLocalOffsetFromOS` highlights the interaction with the operating system for timezone information.

4. **Trace Function Calls and Data Flow:**  Start following the execution flow through some of the key functions. For instance:
    * How is `YearMonthDayFromDays` implemented?  It involves calculations based on days since an epoch, including handling leap years.
    * How does `LocalOffsetInMs` work? It attempts to use the cache (`before_`, `after_`) first and then falls back to `GetLocalOffsetFromOS` if there's a cache miss. It also includes logic for handling potential DST transitions within a small interval.
    * What do `MakeDate`, `MakeDay`, and `MakeTime` do? They seem to assemble date and time components into a single numerical representation (milliseconds since the epoch).
    * What does `ToDateString` do? It takes a time value and formats it into different string representations, considering localization (if `V8_INTL_SUPPORT` is enabled).
    * What does `ParseDateTimeString` do?  It uses `DateParser` to parse a date/time string and converts it into a numerical time value.

5. **Identify the JavaScript Connection:** The function names and the overall functionality strongly resemble the capabilities of JavaScript's `Date` object. Specifically:
    * `YearMonthDayFromDays` and `DaysFromYearMonth` relate to methods like `getFullYear()`, `getMonth()`, `getDate()`, and the inverse, though JavaScript doesn't have a direct function to get the "day number."
    * `BreakDownTime` is similar to getting all the date/time components.
    * `LocalOffsetInMs` is crucial for handling timezones, which is central to `Date`'s behavior. The distinction between local and UTC time is evident.
    * `MakeDate`, `MakeDay`, `MakeTime` are internal mechanisms for creating the numerical representation of a `Date` object.
    * `ToDateString` directly mirrors methods like `toString()`, `toDateString()`, `toTimeString()`, `toLocaleString()`, `toLocaleDateString()`, `toLocaleTimeString()`, `toISOString()`, and `toUTCString()`.
    * `ParseDateTimeString` corresponds to `Date.parse()`.

6. **Construct Illustrative JavaScript Examples:**  Once the connections are clear, create concise JavaScript code snippets that demonstrate the analogous functionality:
    * Show how `new Date()` with different arguments relates to the `Make*` functions.
    * Demonstrate how methods like `getFullYear()`, `getMonth()`, `getDate()`, `getHours()`, `getMinutes()`, `getSeconds()`, `getMilliseconds()` relate to the breakdown of the time value.
    * Highlight the effect of timezones using methods like `getTimezoneOffset()`, `toLocaleDateString()`, `toLocaleTimeString()`, and `toISOString()`.
    * Show how `Date.parse()` works, connecting it to `ParseDateTimeString`.

7. **Synthesize the Summary:**  Organize the findings into a clear and concise summary that covers:
    * The main purpose of the file (implementing core date/time functionality for V8).
    * Key classes and their roles (especially `DateCache` for timezone optimization).
    * The connection to JavaScript's `Date` object, providing specific examples of corresponding functionality.
    * Important implementation details, like handling leap years, timezone offsets, and parsing.

8. **Review and Refine:** Read through the summary and examples to ensure accuracy, clarity, and completeness. Make sure the language is accessible and avoids overly technical jargon where possible. For example, initially, I might focus too much on the internal details of the `DateCache`, but the refined explanation emphasizes its role in *optimizing* timezone lookups, which is more relevant from a functional perspective. Also, ensuring the JavaScript examples are correct and clearly demonstrate the point is crucial.
这个 C++ 源代码文件 `date.cc` 位于 V8 JavaScript 引擎的 `v8/src/date` 目录下，它的主要功能是 **实现 JavaScript `Date` 对象的核心逻辑**。  它负责处理日期和时间相关的各种计算、转换、格式化和解析操作。

具体来说，`date.cc` 包含了以下关键功能：

1. **日期和时间的基本运算:**
   - 计算年、月、日之间的转换，包括处理闰年。
   - 计算给定日期是星期几。
   - 计算时间戳（自 1970 年 1 月 1 日 UTC 以来的毫秒数）与年、月、日、时、分、秒、毫秒之间的相互转换。

2. **时区处理:**
   -  管理和缓存时区信息，以提高性能。使用了 `DateCache` 类来缓存最近使用的时区偏移量。
   -  获取操作系统或 ICU (International Components for Unicode，如果启用) 提供的本地时区偏移信息。
   -  计算给定时间戳在本地时区下的偏移量。
   -  支持夏令时 (Daylight Saving Time, DST) 的计算。

3. **日期和时间的格式化:**
   -  将时间戳格式化成各种字符串表示形式，例如 `toDateString()`, `toTimeString()`, `toLocaleString()`, `toISOString()` 等 JavaScript `Date` 对象的方法所返回的格式。
   -  支持多种格式化模式，包括本地日期、本地时间、本地日期和时间、UTC 日期和时间以及 ISO 格式。

4. **日期和时间的解析:**
   -  解析日期和时间字符串，例如 `Date.parse()` 方法可以解析的字符串。
   -  使用 `DateParser` 类来完成字符串的解析工作。
   -  处理各种不同的日期和时间字符串格式。

**它与 JavaScript 的功能关系：**

`date.cc` 中的代码是 JavaScript `Date` 对象底层实现的基石。 当你在 JavaScript 中使用 `Date` 对象及其方法时，V8 引擎会调用 `date.cc` 中相应的 C++ 函数来执行实际的日期和时间操作。

**JavaScript 举例说明:**

以下 JavaScript 代码片段展示了 `date.cc` 中实现的功能在 JavaScript 中的体现：

```javascript
// 创建一个 Date 对象
let date = new Date();

// 获取年、月、日、时、分、秒等 (对应 date.cc 中的日期和时间基本运算)
let year = date.getFullYear();
let month = date.getMonth(); // 注意：月份从 0 开始
let day = date.getDate();
let hours = date.getHours();
let minutes = date.getMinutes();
let seconds = date.getSeconds();
let milliseconds = date.getMilliseconds();

console.log(`当前时间: ${year}-${month + 1}-${day} ${hours}:${minutes}:${seconds}.${milliseconds}`);

// 获取星期几 (对应 date.cc 中的日期和时间基本运算)
let weekday = date.getDay(); // 0 表示星期日
console.log(`今天是星期${weekday}`);

// 获取时间戳 (对应 date.cc 中的日期和时间基本运算)
let timestamp = date.getTime();
console.log(`当前时间戳: ${timestamp}`);

// 获取本地时区偏移量 (对应 date.cc 中的时区处理)
let timezoneOffset = date.getTimezoneOffset(); // 返回分钟
console.log(`本地时区偏移量 (分钟): ${timezoneOffset}`);

// 格式化日期和时间为本地字符串 (对应 date.cc 中的日期和时间的格式化)
let localDateString = date.toLocaleDateString();
let localTimeString = date.toLocaleTimeString();
console.log(`本地日期字符串: ${localDateString}`);
console.log(`本地时间字符串: ${localTimeString}`);

// 格式化为 ISO 字符串 (对应 date.cc 中的日期和时间的格式化)
let isoString = date.toISOString();
console.log(`ISO 字符串: ${isoString}`);

// 解析日期字符串 (对应 date.cc 中的日期和时间的解析)
let parsedDate = Date.parse("2023-10-27T10:30:00Z");
console.log(`解析后的时间戳: ${parsedDate}`);

let parsedDateObj = new Date("2023-10-27T10:30:00Z");
console.log(`解析后的 Date 对象: ${parsedDateObj}`);
```

**总结:**

`v8/src/date/date.cc` 文件是 V8 引擎中实现 JavaScript `Date` 对象核心功能的关键组成部分。 它负责处理各种底层的日期和时间计算、时区管理、格式化和解析操作，使得 JavaScript 开发者可以方便地使用 `Date` 对象来处理日期和时间相关的任务。  `DateCache` 类的存在是为了优化时区信息的获取，提升性能。

Prompt: 
```
这是目录为v8/src/date/date.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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