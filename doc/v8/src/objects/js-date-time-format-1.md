Response: Let's break down the thought process for summarizing the provided C++ code for `v8/src/objects/js-date-time-format.cc`, specifically part 2.

1. **Understand the Goal:** The primary goal is to summarize the *functionality* of this code. This means identifying what it *does*, not just listing the classes and methods. Since it's related to JavaScript, highlighting the connection and providing JavaScript examples are crucial.

2. **Initial Scan and Keyword Identification:**  Quickly read through the code, looking for important keywords and patterns. Some initial observations:
    * Lots of `icu::` namespace usage - indicates interaction with the International Components for Unicode library.
    * `TimeZone`, `Calendar`, `SimpleDateFormat`, `DateIntervalFormat` - these are all ICU classes related to date and time formatting.
    * Functions like `GetOffsetTimeZone`, `CreateTimeZone`, `CreateCalendar`, `CreateICUDateFormat`, `FormatMillisecondsByKindToArray`, `FormatRange`, `FormatRangeToParts`. These strongly suggest the code is about handling date and time formatting.
    * The presence of caching mechanisms (`CalendarCache`, `DateFormatCache`, `DateTimePatternGeneratorCache`) suggests performance optimization is a concern.
    * The frequent use of `MaybeHandle` and exception handling (`THROW_NEW_ERROR`) points to error management within the V8 engine.
    * The references to "Temporal" and the `v8_flags.harmony_temporal` check indicate integration with the ECMAScript Temporal proposal.

3. **Divide and Conquer (Logical Grouping):**  Instead of trying to understand everything at once, group related functions and concepts. Based on the keywords and the flow of the code, we can identify these logical blocks:
    * **Time Zone Handling:**  Functions like `GetOffsetTimeZone` and `CreateTimeZone` are clearly responsible for parsing and creating time zone objects.
    * **Calendar Management:**  `CalendarCache` and `CreateCalendar` deal with creating and caching `icu::Calendar` instances, which are fundamental for date/time calculations.
    * **Date/Time Pattern Handling:**  Functions like `ReplaceHourCycleInPattern`, `CreateICUDateFormat`, `CreateICUDateFormatFromCache`, and `DateTimeStylePattern` are involved in generating and managing date/time format patterns.
    * **Formatting Core:**  Functions like `FormatMillisecondsByKindToArray`, `FormatMillisecondsToArray`, `FormatToParts`, `FormatRange`, and `FormatRangeToParts` are the workhorses for actually formatting dates and times into strings or structured parts. The "Temporal" conditional logic is important here.
    * **Internal Utilities:** Functions like `IcuDateFieldIdToDateType` and `FieldPositionIteratorToArray` seem to be internal helpers for processing ICU formatting results.
    * **Options Processing and Initialization:** The `JSDateTimeFormat::New` and `CreateDateTimeFormat` functions are responsible for taking JavaScript options and configuring the internal ICU formatters.

4. **Summarize Each Group:**  For each logical group, write a concise summary of its purpose:
    * **Time Zones:**  Focus on parsing, validating, and creating ICU time zone objects from JavaScript strings. Mention the GMT offset format.
    * **Calendars:** Emphasize creating and caching calendars, including the Gregorian change handling.
    * **Patterns:** Describe the process of generating and customizing format patterns, including handling hour cycles.
    * **Formatting:** Explain the core formatting functionality, distinguishing between formatting to strings and to structured parts. Highlight the Temporal integration and the handling of date ranges.
    * **Utilities:** Briefly explain the role of helper functions in processing ICU results.
    * **Initialization:** Describe how JavaScript options are used to set up the date/time formatting.

5. **Identify JavaScript Connections and Examples:** For each summarized group, consider how it relates to JavaScript's `Intl.DateTimeFormat` object. Provide clear, illustrative JavaScript examples. Think about the common use cases of `Intl.DateTimeFormat`:
    * Setting time zones.
    * Choosing different calendar systems.
    * Formatting with various styles and components.
    * Using `formatToParts`.
    * Formatting date ranges with `formatRange` and `formatRangeToParts`.

6. **Structure the Summary:** Organize the information logically, using headings and bullet points for clarity. Start with a high-level overview and then delve into the details of each functional area. Make sure the examples are placed near the description of the corresponding functionality.

7. **Review and Refine:** Read through the summary, checking for accuracy, clarity, and completeness. Ensure the language is easy to understand and avoids excessive technical jargon. For instance, instead of just saying "it uses `icu::SimpleDateFormat`", explain *what* `SimpleDateFormat` does in the context of date formatting.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This code just formats dates."  **Correction:**  It's much more than simple formatting. It handles time zones, calendars, complex patterns, and date ranges. The caching mechanisms show optimization efforts.
* **Initial thought:**  "Just list the methods." **Correction:**  Focus on the *functionality* provided by these methods. What problems do they solve?  How do they contribute to the overall goal?
* **Initial thought:**  "The ICU details are too low-level." **Correction:** While detailed ICU knowledge isn't required for a *high-level* summary, mentioning the key ICU classes and their purpose adds valuable context. Explain *why* ICU is important here.
* **Realizing the Importance of Temporal:**  The checks for `v8_flags.harmony_temporal` are significant. It's not just a minor detail; it reflects the code's adaptation to evolving JavaScript standards. This should be a prominent point in the summary.

By following this thought process, breaking down the code into logical components, and focusing on the *functionality* and its connection to JavaScript, we arrive at a comprehensive and helpful summary like the example provided in the initial prompt.
这是对C++源代码文件 `v8/src/objects/js-date-time-format.cc` 的第二部分功能归纳。结合第一部分，我们可以得到更完整的理解。

**总体功能 (结合第一部分):**

该C++文件是V8 JavaScript引擎中关于 `Intl.DateTimeFormat` 功能的核心实现。它负责将JavaScript中提供的日期和时间信息，根据用户指定的区域设置、格式选项等，格式化成人类可读的字符串。

**第二部分功能归纳:**

这部分代码主要关注以下几个方面：

1. **时区处理:**
   - `GetOffsetTimeZone`:  尝试将特定格式的字符串 (例如 "+hh:mm", "-hh:mm") 转换为 ICU 库能够识别的时区 ID 格式 ("GMT+hhmm" 或 "GMT-hh:mm")。
   - `CreateTimeZone`:  根据 JavaScript 提供的时区字符串，创建 ICU `TimeZone` 对象。它会尝试先解析为偏移时区，如果失败则尝试解析为标准的时区 ID，并进行有效性检查。

2. **日历管理和缓存:**
   - `CalendarCache`:  使用缓存来存储已创建的 ICU `Calendar` 对象，以提高性能。缓存的键值包括时区 ID 和区域设置。
   - `CreateCalendar`:  根据指定的区域设置和时区创建 ICU `Calendar` 对象。特别地，它会设置 `GregorianCalendar` 的起始时间，以匹配 ECMAScript 的时间范围。

3. **日期/时间模式处理:**
   - `ReplaceHourCycleInPattern`:  根据用户指定的 `hourCycle` 选项（h11, h12, h23, h24），替换日期/时间模式字符串中的小时指示符 (例如 'h', 'H', 'k', 'K')。
   - `CreateICUDateFormat`:  根据提供的骨架 (skeleton) 和区域设置，利用 ICU 的 `DateTimePatternGenerator` 生成最佳的日期/时间格式模式，并创建一个 `SimpleDateFormat` 对象。
   - `DateFormatCache`:  缓存已创建的 `SimpleDateFormat` 对象，以提高性能。
   - `CreateICUDateFormatFromCache`:  从缓存中获取或创建 `SimpleDateFormat` 对象。
   - `LazyCreateDateIntervalFormat`:  延迟创建 `DateIntervalFormat` 对象，用于格式化日期范围。它会根据需要创建并缓存。
   - `HourCycleFromPattern`:  从日期/时间模式字符串中推断出所使用的 `hourCycle`。
   - `DateTimeStyleToEStyle`:  将 `Intl.DateTimeFormat` 的 `dateStyle` 或 `timeStyle` 枚举值转换为 ICU 对应的枚举值。
   - `ReplaceSkeleton`:  根据指定的 `hourCycle` 替换骨架字符串中的小时指示符。
   - `DateTimeStylePattern`:  根据 `dateStyle` 和 `timeStyle` 选项，创建 ICU `SimpleDateFormat` 对象。
   - `DateTimePatternGeneratorCache`:  缓存 `DateTimePatternGenerator` 对象。

4. **`Intl.DateTimeFormat` 对象的创建和初始化:**
   - `JSDateTimeFormat::New` 和 `JSDateTimeFormat::CreateDateTimeFormat`:  是创建 `Intl.DateTimeFormat` 对象的工厂方法。它负责处理 JavaScript 传递的区域设置和选项，解析这些选项，创建相应的 ICU 对象 (如 `Locale`, `TimeZone`, `Calendar`, `SimpleDateFormat`)，并最终初始化 `JSDateTimeFormat` 对象。这个过程包括了：
     - 规范化区域设置列表。
     - 处理 `localeMatcher` 选项。
     - 处理 `calendar` 和 `numberingSystem` 选项。
     - 处理 `hour12` 和 `hourCycle` 选项，并确定最终的 `hourCycle`。
     - 处理 `timeZone` 选项。
     - 处理各种日期和时间组件选项 (如 `year`, `month`, `day`, `hour`, `minute`, `second`, `weekday`, `timeZoneName` 等)，并生成相应的骨架字符串。
     - 处理 `dateStyle` 和 `timeStyle` 选项。
     - 创建并配置 ICU `SimpleDateFormat` 对象。
     - 缓存相关的 ICU 对象。

5. **格式化操作:**
   - `IcuDateFieldIdToDateType`:  将 ICU 的日期/时间字段 ID 映射到 `Intl.DateTimeFormat` 返回的 `parts` 数组中的类型字符串 (如 "year", "month", "day" 等)。
   - `FieldPositionIteratorToArray`:  将 ICU 格式化输出和 `FieldPositionIterator` 转换为 JavaScript 的数组，用于 `formatToParts` 方法。
   - `FormatMillisecondsByKindToArray`:  根据指定的 `PatternKind` (例如，只格式化日期部分或只格式化时间部分) 和时间戳，使用 ICU 格式化并转换为数组。
   - `FormatToPartsWithTemporalSupport`:  支持 ECMAScript Temporal 提议的 `formatToParts` 实现。
   - `FormatMillisecondsToArray`:  使用 ICU 格式化时间戳并转换为数组。
   - `JSDateTimeFormat::FormatToParts`:  实现 `Intl.DateTimeFormat.prototype.formatToParts()` 方法，将日期/时间格式化为包含类型和值的对象数组。它会处理 JavaScript 的 `Date` 对象或 Temporal 对象。
   - `JSDateTimeFormat::FormatRange`: 实现 `Intl.DateTimeFormat.prototype.formatRange()` 方法，格式化一个日期/时间范围。
   - `JSDateTimeFormat::FormatRangeToParts`: 实现 `Intl.DateTimeFormat.prototype.formatRangeToParts()` 方法，将日期/时间范围格式化为包含类型和值的对象数组。

6. **内部工具函数:**
   - 提供了诸如添加格式化范围的部件到数组、将 ICU 格式化值转换为字符串或数组等辅助函数，用于 `formatRange` 和 `formatRangeToParts` 的实现。

**与 JavaScript 功能的关系及示例:**

这部分代码直接实现了 JavaScript 的 `Intl.DateTimeFormat` 对象的行为。例如：

```javascript
// 创建一个 Intl.DateTimeFormat 对象，指定区域设置和选项
const formatter = new Intl.DateTimeFormat('zh-CN', {
  year: 'numeric',
  month: 'long',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  timeZone: 'Asia/Shanghai'
});

// 格式化一个 Date 对象
const date = new Date();
const formattedDate = formatter.format(date);
console.log(formattedDate); // 输出类似 "2023年10月27日 10:30"

// 使用 formatToParts 获取格式化的各个部分
const parts = formatter.formatToParts(date);
console.log(parts); // 输出类似 [{ type: 'year', value: '2023' }, ...]

// 格式化一个日期范围
const startDate = new Date(2023, 9, 26); // Month is 0-indexed
const endDate = new Date(2023, 9, 28);
const rangeFormatter = new Intl.DateTimeFormat('en-US', {
  month: 'short',
  day: 'numeric'
});
const formattedRange = rangeFormatter.formatRange(startDate, endDate);
console.log(formattedRange); // Output: "Oct 26 – 28"

const rangeParts = rangeFormatter.formatRangeToParts(startDate, endDate);
console.log(rangeParts); // Output: [ { type: 'month', value: 'Oct' }, ... ]
```

在上面的 JavaScript 示例中，当我们创建 `Intl.DateTimeFormat` 对象并调用其 `format`、`formatToParts` 或 `formatRange`/`formatRangeToParts` 方法时，V8 引擎内部就会调用 `js-date-time-format.cc` 文件中相应的 C++ 代码，包括这第二部分中涉及的时区处理、日历管理、模式生成和格式化逻辑。例如：

-  `timeZone: 'Asia/Shanghai'` 选项会导致 `CreateTimeZone` 函数被调用，创建对应的 ICU `TimeZone` 对象。
-  `year: 'numeric'`, `month: 'long'`, `day: 'numeric'` 等选项会被解析，并用于生成传递给 `CreateICUDateFormat` 的骨架字符串。
-  `formatter.format(date)` 会调用 `JSDateTimeFormat::FormatToParts` (最终可能会调用 `FormatMillisecondsToArray`)，利用 ICU 的 `SimpleDateFormat` 来格式化 `date` 对象。
-  `rangeFormatter.formatRange(startDate, endDate)` 会调用 `JSDateTimeFormat::FormatRange`，它会使用 `LazyCreateDateIntervalFormat` 创建 `DateIntervalFormat` 对象来处理日期范围的格式化。

总而言之，这第二部分的代码专注于 `Intl.DateTimeFormat` 的核心构建块和复杂的格式化逻辑，特别是处理时区、日历以及各种格式化选项，并将其转换为 ICU 库能够理解和执行的操作，最终将日期和时间信息以用户期望的格式呈现出来。它也体现了 V8 为了性能所做的缓存优化以及对新的 JavaScript 特性（如 Temporal）的支持。

### 提示词
```
这是目录为v8/src/objects/js-date-time-format.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
f);
}

// Convert the input in the form of
// [+-\u2212]hh:?mm  to the ID acceptable for SimpleTimeZone
// GMT[+-]hh or GMT[+-]hh:mm or empty
std::optional<std::string> GetOffsetTimeZone(Isolate* isolate,
                                             Handle<String> time_zone) {
  time_zone = String::Flatten(isolate, time_zone);
  DisallowGarbageCollection no_gc;
  const String::FlatContent& flat = time_zone->GetFlatContent(no_gc);
  int32_t len = flat.length();
  if (len < 3) {
    // Error
    return std::nullopt;
  }
  std::string tz("GMT");
  switch (flat.Get(0)) {
    case 0x2212:
    case '-':
      tz += '-';
      break;
    case '+':
      tz += '+';
      break;
    default:
      // Error
      return std::nullopt;
  }
  // 00 - 23
  uint16_t h0 = flat.Get(1);
  uint16_t h1 = flat.Get(2);

  if ((h0 >= '0' && h0 <= '1' && h1 >= '0' && h1 <= '9') ||
      (h0 == '2' && h1 >= '0' && h1 <= '3')) {
    tz += h0;
    tz += h1;
  } else {
    // Error
    return std::nullopt;
  }
  if (len == 3) {
    return tz;
  }
  int32_t p = 3;
  uint16_t m0 = flat.Get(p);
  if (m0 == ':') {
    // Ignore ':'
    p++;
    m0 = flat.Get(p);
  }
  if (len - p != 2) {
    // Error
    return std::nullopt;
  }
  uint16_t m1 = flat.Get(p + 1);
  if (m0 >= '0' && m0 <= '5' && m1 >= '0' && m1 <= '9') {
    tz += m0;
    tz += m1;
    return tz;
  }
  // Error
  return std::nullopt;
}
std::unique_ptr<icu::TimeZone> JSDateTimeFormat::CreateTimeZone(
    Isolate* isolate, Handle<String> time_zone_string) {
  // Create time zone as specified by the user. We have to re-create time zone
  // since calendar takes ownership.
  std::optional<std::string> offsetTimeZone =
      GetOffsetTimeZone(isolate, time_zone_string);
  if (offsetTimeZone.has_value()) {
    std::unique_ptr<icu::TimeZone> tz(
        icu::TimeZone::createTimeZone(offsetTimeZone->c_str()));
    return tz;
  }
  std::unique_ptr<char[]> time_zone = time_zone_string->ToCString();
  std::string canonicalized = CanonicalizeTimeZoneID(time_zone.get());
  if (canonicalized.empty()) return std::unique_ptr<icu::TimeZone>();
  std::unique_ptr<icu::TimeZone> tz(
      icu::TimeZone::createTimeZone(canonicalized.c_str()));
  // 18.b If the result of IsValidTimeZoneName(timeZone) is false, then
  // i. Throw a RangeError exception.
  if (!Intl::IsValidTimeZoneName(*tz)) return std::unique_ptr<icu::TimeZone>();
  return tz;
}

namespace {

class CalendarCache {
 public:
  icu::Calendar* CreateCalendar(const icu::Locale& locale, icu::TimeZone* tz) {
    icu::UnicodeString tz_id;
    tz->getID(tz_id);
    std::string key;
    tz_id.toUTF8String<std::string>(key);
    key += ":";
    key += locale.getName();

    base::MutexGuard guard(&mutex_);
    auto it = map_.find(key);
    if (it != map_.end()) {
      delete tz;
      return it->second->clone();
    }
    // Create a calendar using locale, and apply time zone to it.
    UErrorCode status = U_ZERO_ERROR;
    std::unique_ptr<icu::Calendar> calendar(
        icu::Calendar::createInstance(tz, locale, status));
    DCHECK(U_SUCCESS(status));
    DCHECK_NOT_NULL(calendar.get());

    if (calendar->getDynamicClassID() ==
            icu::GregorianCalendar::getStaticClassID() ||
        strcmp(calendar->getType(), "iso8601") == 0) {
      icu::GregorianCalendar* gc =
          static_cast<icu::GregorianCalendar*>(calendar.get());
      status = U_ZERO_ERROR;
      // The beginning of ECMAScript time, namely -(2**53)
      const double start_of_time = -9007199254740992;
      gc->setGregorianChange(start_of_time, status);
      DCHECK(U_SUCCESS(status));
    }

    if (map_.size() > 8) {  // Cache at most 8 calendars.
      map_.clear();
    }
    map_[key] = std::move(calendar);
    return map_[key]->clone();
  }

 private:
  std::map<std::string, std::unique_ptr<icu::Calendar>> map_;
  base::Mutex mutex_;
};

icu::Calendar* CreateCalendar(Isolate* isolate, const icu::Locale& icu_locale,
                              icu::TimeZone* tz) {
  static base::LazyInstance<CalendarCache>::type calendar_cache =
      LAZY_INSTANCE_INITIALIZER;
  return calendar_cache.Pointer()->CreateCalendar(icu_locale, tz);
}

icu::UnicodeString ReplaceHourCycleInPattern(icu::UnicodeString pattern,
                                             JSDateTimeFormat::HourCycle hc) {
  char16_t replacement;
  switch (hc) {
    case JSDateTimeFormat::HourCycle::kUndefined:
      return pattern;
    case JSDateTimeFormat::HourCycle::kH11:
      replacement = 'K';
      break;
    case JSDateTimeFormat::HourCycle::kH12:
      replacement = 'h';
      break;
    case JSDateTimeFormat::HourCycle::kH23:
      replacement = 'H';
      break;
    case JSDateTimeFormat::HourCycle::kH24:
      replacement = 'k';
      break;
  }
  bool replace = true;
  icu::UnicodeString result;
  char16_t last = u'\0';
  for (int32_t i = 0; i < pattern.length(); i++) {
    char16_t ch = pattern.charAt(i);
    switch (ch) {
      case '\'':
        replace = !replace;
        result.append(ch);
        break;
      case 'H':
        [[fallthrough]];
      case 'h':
        [[fallthrough]];
      case 'K':
        [[fallthrough]];
      case 'k':
        // If the previous field is a day, add a space before the hour.
        if (replace && last == u'd') {
          result.append(' ');
        }
        result.append(replace ? replacement : ch);
        break;
      default:
        result.append(ch);
        break;
    }
    last = ch;
  }
  return result;
}

std::unique_ptr<icu::SimpleDateFormat> CreateICUDateFormat(
    const icu::Locale& icu_locale, const icu::UnicodeString& skeleton,
    icu::DateTimePatternGenerator* generator, JSDateTimeFormat::HourCycle hc) {
  // See https://github.com/tc39/ecma402/issues/225 . The best pattern
  // generation needs to be done in the base locale according to the
  // current spec however odd it may be. See also crbug.com/826549 .
  // This is a temporary work-around to get v8's external behavior to match
  // the current spec, but does not follow the spec provisions mentioned
  // in the above Ecma 402 issue.
  // TODO(jshin): The spec may need to be revised because using the base
  // locale for the pattern match is not quite right. Moreover, what to
  // do with 'related year' part when 'chinese/dangi' calendar is specified
  // has to be discussed. Revisit once the spec is clarified/revised.
  icu::UnicodeString pattern;
  UErrorCode status = U_ZERO_ERROR;
  pattern = generator->getBestPattern(skeleton, UDATPG_MATCH_HOUR_FIELD_LENGTH,
                                      status);
  pattern = ReplaceHourCycleInPattern(pattern, hc);
  DCHECK(U_SUCCESS(status));

  // Make formatter from skeleton. Calendar and numbering system are added
  // to the locale as Unicode extension (if they were specified at all).
  status = U_ZERO_ERROR;
  std::unique_ptr<icu::SimpleDateFormat> date_format(
      new icu::SimpleDateFormat(pattern, icu_locale, status));
  if (U_FAILURE(status)) return std::unique_ptr<icu::SimpleDateFormat>();

  DCHECK_NOT_NULL(date_format.get());
  return date_format;
}

class DateFormatCache {
 public:
  icu::SimpleDateFormat* Create(const icu::Locale& icu_locale,
                                const icu::UnicodeString& skeleton,
                                icu::DateTimePatternGenerator* generator,
                                JSDateTimeFormat::HourCycle hc) {
    std::string key;
    skeleton.toUTF8String<std::string>(key);
    key += ":";
    key += icu_locale.getName();

    base::MutexGuard guard(&mutex_);
    auto it = map_.find(key);
    if (it != map_.end()) {
      return static_cast<icu::SimpleDateFormat*>(it->second->clone());
    }

    if (map_.size() > 8) {  // Cache at most 8 DateFormats.
      map_.clear();
    }
    std::unique_ptr<icu::SimpleDateFormat> instance(
        CreateICUDateFormat(icu_locale, skeleton, generator, hc));
    if (instance == nullptr) return nullptr;
    map_[key] = std::move(instance);
    return static_cast<icu::SimpleDateFormat*>(map_[key]->clone());
  }

 private:
  std::map<std::string, std::unique_ptr<icu::SimpleDateFormat>> map_;
  base::Mutex mutex_;
};

std::unique_ptr<icu::SimpleDateFormat> CreateICUDateFormatFromCache(
    const icu::Locale& icu_locale, const icu::UnicodeString& skeleton,
    icu::DateTimePatternGenerator* generator, JSDateTimeFormat::HourCycle hc) {
  static base::LazyInstance<DateFormatCache>::type cache =
      LAZY_INSTANCE_INITIALIZER;
  return std::unique_ptr<icu::SimpleDateFormat>(
      cache.Pointer()->Create(icu_locale, skeleton, generator, hc));
}

// We treat PatternKind::kDate different than other because most of the
// pre-existing usage are using the formatter with Date() and Temporal is
// new and not yet adopted by the web yet. We try to optimize the performance
// and memory usage for the pre-existing code so we cache for it.
// We may later consider caching Temporal one also if the usage increase.
// Right now we want to avoid making the constructor more expensive and
// increasing overhead in the object.
std::unique_ptr<icu::DateIntervalFormat> LazyCreateDateIntervalFormat(
    Isolate* isolate, DirectHandle<JSDateTimeFormat> date_time_format,
    PatternKind kind) {
  Tagged<Managed<icu::DateIntervalFormat>> managed_format =
      date_time_format->icu_date_interval_format();
  if (kind == PatternKind::kDate && managed_format->get()) {
    return std::unique_ptr<icu::DateIntervalFormat>(
        managed_format->raw()->clone());
  }
  UErrorCode status = U_ZERO_ERROR;

  icu::Locale loc = *(date_time_format->icu_locale()->raw());
  // We need to pass in the hc to DateIntervalFormat by using Unicode 'hc'
  // extension.
  std::string hcString = ToHourCycleString(date_time_format->hour_cycle());
  if (!hcString.empty()) {
    loc.setUnicodeKeywordValue("hc", hcString, status);
  }

  icu::SimpleDateFormat* icu_simple_date_format =
      date_time_format->icu_simple_date_format()->raw();

  icu::UnicodeString skeleton = GetSkeletonForPatternKind(
      SkeletonFromDateFormat(*icu_simple_date_format), kind);

  std::unique_ptr<icu::DateIntervalFormat> date_interval_format(
      icu::DateIntervalFormat::createInstance(skeleton, loc, status));
  DCHECK(U_SUCCESS(status));
  date_interval_format->setTimeZone(icu_simple_date_format->getTimeZone());
  if (kind != PatternKind::kDate) {
    return date_interval_format;
  }
  DirectHandle<Managed<icu::DateIntervalFormat>> managed_interval_format =
      Managed<icu::DateIntervalFormat>::From(isolate, 0,
                                             std::move(date_interval_format));
  date_time_format->set_icu_date_interval_format(*managed_interval_format);
  return std::unique_ptr<icu::DateIntervalFormat>(
      managed_interval_format->raw()->clone());
}

JSDateTimeFormat::HourCycle HourCycleFromPattern(
    const icu::UnicodeString pattern) {
  bool in_quote = false;
  for (int32_t i = 0; i < pattern.length(); i++) {
    char16_t ch = pattern[i];
    switch (ch) {
      case '\'':
        in_quote = !in_quote;
        break;
      case 'K':
        if (!in_quote) return JSDateTimeFormat::HourCycle::kH11;
        break;
      case 'h':
        if (!in_quote) return JSDateTimeFormat::HourCycle::kH12;
        break;
      case 'H':
        if (!in_quote) return JSDateTimeFormat::HourCycle::kH23;
        break;
      case 'k':
        if (!in_quote) return JSDateTimeFormat::HourCycle::kH24;
        break;
    }
  }
  return JSDateTimeFormat::HourCycle::kUndefined;
}

icu::DateFormat::EStyle DateTimeStyleToEStyle(
    JSDateTimeFormat::DateTimeStyle style) {
  switch (style) {
    case JSDateTimeFormat::DateTimeStyle::kFull:
      return icu::DateFormat::EStyle::kFull;
    case JSDateTimeFormat::DateTimeStyle::kLong:
      return icu::DateFormat::EStyle::kLong;
    case JSDateTimeFormat::DateTimeStyle::kMedium:
      return icu::DateFormat::EStyle::kMedium;
    case JSDateTimeFormat::DateTimeStyle::kShort:
      return icu::DateFormat::EStyle::kShort;
    case JSDateTimeFormat::DateTimeStyle::kUndefined:
      UNREACHABLE();
  }
}

icu::UnicodeString ReplaceSkeleton(const icu::UnicodeString input,
                                   JSDateTimeFormat::HourCycle hc) {
  icu::UnicodeString result;
  char16_t to;
  switch (hc) {
    case JSDateTimeFormat::HourCycle::kH11:
      to = 'K';
      break;
    case JSDateTimeFormat::HourCycle::kH12:
      to = 'h';
      break;
    case JSDateTimeFormat::HourCycle::kH23:
      to = 'H';
      break;
    case JSDateTimeFormat::HourCycle::kH24:
      to = 'k';
      break;
    case JSDateTimeFormat::HourCycle::kUndefined:
      UNREACHABLE();
  }
  for (int32_t i = 0; i < input.length(); i++) {
    switch (input[i]) {
      // We need to skip 'a', 'b', 'B' here due to
      // https://unicode-org.atlassian.net/browse/ICU-20437
      case 'a':
        [[fallthrough]];
      case 'b':
        [[fallthrough]];
      case 'B':
        // ignore
        break;
      case 'h':
        [[fallthrough]];
      case 'H':
        [[fallthrough]];
      case 'K':
        [[fallthrough]];
      case 'k':
        result += to;
        break;
      default:
        result += input[i];
        break;
    }
  }
  return result;
}

std::unique_ptr<icu::SimpleDateFormat> DateTimeStylePattern(
    JSDateTimeFormat::DateTimeStyle date_style,
    JSDateTimeFormat::DateTimeStyle time_style, icu::Locale& icu_locale,
    JSDateTimeFormat::HourCycle hc, icu::DateTimePatternGenerator* generator) {
  std::unique_ptr<icu::SimpleDateFormat> result;
  if (date_style != JSDateTimeFormat::DateTimeStyle::kUndefined) {
    if (time_style != JSDateTimeFormat::DateTimeStyle::kUndefined) {
      result.reset(reinterpret_cast<icu::SimpleDateFormat*>(
          icu::DateFormat::createDateTimeInstance(
              DateTimeStyleToEStyle(date_style),
              DateTimeStyleToEStyle(time_style), icu_locale)));
    } else {
      result.reset(reinterpret_cast<icu::SimpleDateFormat*>(
          icu::DateFormat::createDateInstance(DateTimeStyleToEStyle(date_style),
                                              icu_locale)));
      // For instance without time, we do not need to worry about the hour cycle
      // impact so we can return directly.
      if (result != nullptr) {
        return result;
      }
    }
  } else {
    if (time_style != JSDateTimeFormat::DateTimeStyle::kUndefined) {
      result.reset(reinterpret_cast<icu::SimpleDateFormat*>(
          icu::DateFormat::createTimeInstance(DateTimeStyleToEStyle(time_style),
                                              icu_locale)));
    } else {
      UNREACHABLE();
    }
  }

  UErrorCode status = U_ZERO_ERROR;
  // Somehow we fail to create the instance.
  if (result.get() == nullptr) {
    // Fallback to the locale without "nu".
    if (!icu_locale.getUnicodeKeywordValue<std::string>("nu", status).empty()) {
      status = U_ZERO_ERROR;
      icu_locale.setUnicodeKeywordValue("nu", nullptr, status);
      return DateTimeStylePattern(date_style, time_style, icu_locale, hc,
                                  generator);
    }
    status = U_ZERO_ERROR;
    // Fallback to the locale without "hc".
    if (!icu_locale.getUnicodeKeywordValue<std::string>("hc", status).empty()) {
      status = U_ZERO_ERROR;
      icu_locale.setUnicodeKeywordValue("hc", nullptr, status);
      return DateTimeStylePattern(date_style, time_style, icu_locale, hc,
                                  generator);
    }
    status = U_ZERO_ERROR;
    // Fallback to the locale without "ca".
    if (!icu_locale.getUnicodeKeywordValue<std::string>("ca", status).empty()) {
      status = U_ZERO_ERROR;
      icu_locale.setUnicodeKeywordValue("ca", nullptr, status);
      return DateTimeStylePattern(date_style, time_style, icu_locale, hc,
                                  generator);
    }
    return nullptr;
  }
  icu::UnicodeString pattern;
  pattern = result->toPattern(pattern);

  status = U_ZERO_ERROR;
  icu::UnicodeString skeleton =
      icu::DateTimePatternGenerator::staticGetSkeleton(pattern, status);
  DCHECK(U_SUCCESS(status));

  // If the skeleton match the HourCycle, we just return it.
  if (hc == HourCycleFromPattern(pattern)) {
    return result;
  }

  return CreateICUDateFormatFromCache(icu_locale, ReplaceSkeleton(skeleton, hc),
                                      generator, hc);
}

class DateTimePatternGeneratorCache {
 public:
  // Return a clone copy that the caller have to free.
  icu::DateTimePatternGenerator* CreateGenerator(Isolate* isolate,
                                                 const icu::Locale& locale) {
    std::string key(locale.getName());
    base::MutexGuard guard(&mutex_);
    auto it = map_.find(key);
    icu::DateTimePatternGenerator* orig;
    if (it != map_.end()) {
      DCHECK(it->second != nullptr);
      orig = it->second.get();
    } else {
      UErrorCode status = U_ZERO_ERROR;
      orig = icu::DateTimePatternGenerator::createInstance(locale, status);
      // It may not be an U_MEMORY_ALLOCATION_ERROR.
      // Fallback to use "root".
      if (U_FAILURE(status)) {
        status = U_ZERO_ERROR;
        orig = icu::DateTimePatternGenerator::createInstance("root", status);
      }
      if (U_SUCCESS(status) && orig != nullptr) {
        map_[key].reset(orig);
      } else {
        DCHECK(status == U_MEMORY_ALLOCATION_ERROR);
        V8::FatalProcessOutOfMemory(
            isolate, "DateTimePatternGeneratorCache::CreateGenerator");
      }
    }
    icu::DateTimePatternGenerator* clone = orig ? orig->clone() : nullptr;
    if (clone == nullptr) {
      V8::FatalProcessOutOfMemory(
          isolate, "DateTimePatternGeneratorCache::CreateGenerator");
    }
    return clone;
  }

 private:
  std::map<std::string, std::unique_ptr<icu::DateTimePatternGenerator>> map_;
  base::Mutex mutex_;
};

}  // namespace

enum FormatMatcherOption { kBestFit, kBasic };

// ecma402/#sec-initializedatetimeformat
MaybeHandle<JSDateTimeFormat> JSDateTimeFormat::New(
    Isolate* isolate, DirectHandle<Map> map, Handle<Object> locales,
    Handle<Object> input_options, const char* service) {
  return JSDateTimeFormat::CreateDateTimeFormat(
      isolate, map, locales, input_options, RequiredOption::kAny,
      DefaultsOption::kDate, service);
}

MaybeHandle<JSDateTimeFormat> JSDateTimeFormat::CreateDateTimeFormat(
    Isolate* isolate, DirectHandle<Map> map, Handle<Object> locales,
    Handle<Object> input_options, RequiredOption required,
    DefaultsOption defaults, const char* service) {
  Factory* factory = isolate->factory();
  // 1. Let requestedLocales be ? CanonicalizeLocaleList(locales).
  Maybe<std::vector<std::string>> maybe_requested_locales =
      Intl::CanonicalizeLocaleList(isolate, locales);
  MAYBE_RETURN(maybe_requested_locales, Handle<JSDateTimeFormat>());
  std::vector<std::string> requested_locales =
      maybe_requested_locales.FromJust();
  // 2. Let options be ? CoerceOptionsToObject(_options_).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, CoerceOptionsToObject(isolate, input_options, service));

  // 4. Let matcher be ? GetOption(options, "localeMatcher", "string",
  // « "lookup", "best fit" », "best fit").
  // 5. Set opt.[[localeMatcher]] to matcher.
  Maybe<Intl::MatcherOption> maybe_locale_matcher =
      Intl::GetLocaleMatcher(isolate, options, service);
  MAYBE_RETURN(maybe_locale_matcher, MaybeHandle<JSDateTimeFormat>());
  Intl::MatcherOption locale_matcher = maybe_locale_matcher.FromJust();

  std::unique_ptr<char[]> calendar_str = nullptr;
  std::unique_ptr<char[]> numbering_system_str = nullptr;
  const std::vector<const char*> empty_values = {};
  // 6. Let calendar be ? GetOption(options, "calendar",
  //    "string", undefined, undefined).
  Maybe<bool> maybe_calendar = GetStringOption(
      isolate, options, "calendar", empty_values, service, &calendar_str);
  MAYBE_RETURN(maybe_calendar, MaybeHandle<JSDateTimeFormat>());
  if (maybe_calendar.FromJust() && calendar_str != nullptr) {
    icu::Locale default_locale;
    if (!Intl::IsWellFormedCalendar(calendar_str.get())) {
      THROW_NEW_ERROR(
          isolate, NewRangeError(
                       MessageTemplate::kInvalid, factory->calendar_string(),
                       factory->NewStringFromAsciiChecked(calendar_str.get())));
    }
  }

  // 8. Let numberingSystem be ? GetOption(options, "numberingSystem",
  //    "string", undefined, undefined).
  Maybe<bool> maybe_numberingSystem = Intl::GetNumberingSystem(
      isolate, options, service, &numbering_system_str);
  MAYBE_RETURN(maybe_numberingSystem, MaybeHandle<JSDateTimeFormat>());

  // 6. Let hour12 be ? GetOption(options, "hour12", "boolean", undefined,
  // undefined).
  bool hour12;
  Maybe<bool> maybe_get_hour12 =
      GetBoolOption(isolate, options, "hour12", service, &hour12);
  MAYBE_RETURN(maybe_get_hour12, Handle<JSDateTimeFormat>());

  // 7. Let hourCycle be ? GetOption(options, "hourCycle", "string", « "h11",
  // "h12", "h23", "h24" », undefined).
  Maybe<HourCycle> maybe_hour_cycle = GetHourCycle(isolate, options, service);
  MAYBE_RETURN(maybe_hour_cycle, MaybeHandle<JSDateTimeFormat>());
  HourCycle hour_cycle = maybe_hour_cycle.FromJust();

  // 8. If hour12 is not undefined, then
  if (maybe_get_hour12.FromJust()) {
    // a. Let hourCycle be null.
    hour_cycle = HourCycle::kUndefined;
  }
  // 9. Set opt.[[hc]] to hourCycle.

  // ecma402/#sec-intl.datetimeformat-internal-slots
  // The value of the [[RelevantExtensionKeys]] internal slot is
  // « "ca", "nu", "hc" ».
  std::set<std::string> relevant_extension_keys = {"nu", "ca", "hc"};

  // 10. Let localeData be %DateTimeFormat%.[[LocaleData]].
  // 11. Let r be ResolveLocale( %DateTimeFormat%.[[AvailableLocales]],
  //     requestedLocales, opt, %DateTimeFormat%.[[RelevantExtensionKeys]],
  //     localeData).
  //
  Maybe<Intl::ResolvedLocale> maybe_resolve_locale = Intl::ResolveLocale(
      isolate, JSDateTimeFormat::GetAvailableLocales(), requested_locales,
      locale_matcher, relevant_extension_keys);
  if (maybe_resolve_locale.IsNothing()) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  Intl::ResolvedLocale r = maybe_resolve_locale.FromJust();

  icu::Locale icu_locale = r.icu_locale;
  DCHECK(!icu_locale.isBogus());

  UErrorCode status = U_ZERO_ERROR;
  if (calendar_str != nullptr) {
    auto ca_extension_it = r.extensions.find("ca");
    if (ca_extension_it != r.extensions.end() &&
        ca_extension_it->second != calendar_str.get()) {
      icu_locale.setUnicodeKeywordValue("ca", nullptr, status);
      DCHECK(U_SUCCESS(status));
    }
  }
  if (numbering_system_str != nullptr) {
    auto nu_extension_it = r.extensions.find("nu");
    if (nu_extension_it != r.extensions.end() &&
        nu_extension_it->second != numbering_system_str.get()) {
      icu_locale.setUnicodeKeywordValue("nu", nullptr, status);
      DCHECK(U_SUCCESS(status));
    }
  }

  // Need to keep a copy of icu_locale which not changing "ca", "nu", "hc"
  // by option.
  icu::Locale resolved_locale(icu_locale);

  if (calendar_str != nullptr &&
      Intl::IsValidCalendar(icu_locale, calendar_str.get())) {
    icu_locale.setUnicodeKeywordValue("ca", calendar_str.get(), status);
    DCHECK(U_SUCCESS(status));
  }

  if (numbering_system_str != nullptr &&
      Intl::IsValidNumberingSystem(numbering_system_str.get())) {
    icu_locale.setUnicodeKeywordValue("nu", numbering_system_str.get(), status);
    DCHECK(U_SUCCESS(status));
  }

  static base::LazyInstance<DateTimePatternGeneratorCache>::type
      generator_cache = LAZY_INSTANCE_INITIALIZER;

  std::unique_ptr<icu::DateTimePatternGenerator> generator(
      generator_cache.Pointer()->CreateGenerator(isolate, icu_locale));

  // 15.Let hcDefault be dataLocaleData.[[hourCycle]].
  HourCycle hc_default = ToHourCycle(generator->getDefaultHourCycle(status));
  DCHECK(U_SUCCESS(status));

  // 16.Let hc be r.[[hc]].
  HourCycle hc = HourCycle::kUndefined;
  if (hour_cycle == HourCycle::kUndefined) {
    auto hc_extension_it = r.extensions.find("hc");
    if (hc_extension_it != r.extensions.end()) {
      hc = ToHourCycle(hc_extension_it->second.c_str());
    }
  } else {
    hc = hour_cycle;
  }

  // 25. If hour12 is true, then
  if (maybe_get_hour12.FromJust()) {
    if (hour12) {
      // a. Let hc be dataLocaleData.[[hourCycle12]].
      hc = DefaultHourCycle12(icu_locale, hc_default);
      // 26. Else if hour12 is false, then
    } else {
      // a. Let hc be dataLocaleData.[[hourCycle24]].
      hc = DefaultHourCycle24(icu_locale, hc_default);
    }
  } else {
    // 27. Else,
    // a. Assert: hour12 is undefined.
    // b. Let hc be r.[[hc]].
    // c. If hc is null, set hc to dataLocaleData.[[hourCycle]].
    if (hc == HourCycle::kUndefined) {
      hc = hc_default;
    }
  }

  // 17. Let timeZone be ? Get(options, "timeZone").
  Handle<Object> time_zone_obj;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, time_zone_obj,
      Object::GetPropertyOrElement(isolate, options,
                                   isolate->factory()->timeZone_string()));

  std::unique_ptr<icu::TimeZone> tz;
  if (!IsUndefined(*time_zone_obj, isolate)) {
    Handle<String> time_zone;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, time_zone,
                               Object::ToString(isolate, time_zone_obj));
    tz = JSDateTimeFormat::CreateTimeZone(isolate, time_zone);
  } else {
    // 19.a. Else / Let timeZone be DefaultTimeZone().
    tz.reset(icu::TimeZone::createDefault());
  }

  if (tz.get() == nullptr) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidTimeZone,
                                           time_zone_obj));
  }

  std::unique_ptr<icu::Calendar> calendar(
      CreateCalendar(isolate, icu_locale, tz.release()));

  // 18.b If the result of IsValidTimeZoneName(timeZone) is false, then
  // i. Throw a RangeError exception.
  if (calendar.get() == nullptr) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidTimeZone,
                                           time_zone_obj));
  }

  DateTimeStyle date_style = DateTimeStyle::kUndefined;
  DateTimeStyle time_style = DateTimeStyle::kUndefined;
  std::unique_ptr<icu::SimpleDateFormat> icu_date_format;

  // 35. Let hasExplicitFormatComponents be false.
  int32_t explicit_format_components =
      0;  // The fields which are not undefined.
  // 36. For each row of Table 1, except the header row, do
  bool has_hour_option = false;
  std::string skeleton;
  for (const PatternData& item : GetPatternData(hc)) {
    // Need to read fractionalSecondDigits before reading the timeZoneName
    if (item.property == "timeZoneName") {
      // Let _value_ be ? GetNumberOption(options, "fractionalSecondDigits", 1,
      // 3, *undefined*). The *undefined* is represented by value 0 here.
      int fsd;
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, fsd,
          GetNumberOption(isolate, options,
                          factory->fractionalSecondDigits_string(), 1, 3, 0),
          Handle<JSDateTimeFormat>());
      if (fsd > 0) {
        explicit_format_components =
            FractionalSecondDigits::update(explicit_format_components, true);
      }
      // Convert fractionalSecondDigits to skeleton.
      for (int i = 0; i < fsd; i++) {
        skeleton += "S";
      }
    }
    std::unique_ptr<char[]> input;
    // i. Let prop be the name given in the Property column of the row.
    // ii. Let value be ? GetOption(options, prop, "string", « the strings
    // given in the Values column of the row », undefined).
    Maybe<bool> maybe_get_option =
        GetStringOption(isolate, options, item.property.c_str(),
                        item.allowed_values, service, &input);
    MAYBE_RETURN(maybe_get_option, Handle<JSDateTimeFormat>());
    if (maybe_get_option.FromJust()) {
      // Record which fields are not undefined into explicit_format_components.
      if (item.property == "hour") {
        has_hour_option = true;
      }
      DCHECK_NOT_NULL(input.get());
      // iii. Set opt.[[<prop>]] to value.
      skeleton += item.map.find(input.get())->second;
      // e. If value is not undefined, then
      // i. Set hasExplicitFormatComponents to true.
      explicit_format_components |= 1 << static_cast<int32_t>(item.bitShift);
    }
  }

  // 29. Let matcher be ? GetOption(options, "formatMatcher", "string", «
  // "basic", "best fit" », "best fit").
  // We implement only best fit algorithm, but still need to check
  // if the formatMatcher values are in range.
  // c. Let matcher be ? GetOption(options, "formatMatcher", "string",
  //     «  "basic", "best fit" », "best fit").
  Maybe<FormatMatcherOption> maybe_format_matcher =
      GetStringOption<FormatMatcherOption>(
          isolate, options, "formatMatcher", service, {"best fit", "basic"},
          {FormatMatcherOption::kBestFit, FormatMatcherOption::kBasic},
          FormatMatcherOption::kBestFit);
  MAYBE_RETURN(maybe_format_matcher, MaybeHandle<JSDateTimeFormat>());
  // TODO(ftang): uncomment the following line and handle format_matcher.
  // FormatMatcherOption format_matcher = maybe_format_matcher.FromJust();

  // 32. Let dateStyle be ? GetOption(options, "dateStyle", "string", «
  // "full", "long", "medium", "short" », undefined).
  Maybe<DateTimeStyle> maybe_date_style = GetStringOption<DateTimeStyle>(
      isolate, options, "dateStyle", service,
      {"full", "long", "medium", "short"},
      {DateTimeStyle::kFull, DateTimeStyle::kLong, DateTimeStyle::kMedium,
       DateTimeStyle::kShort},
      DateTimeStyle::kUndefined);
  MAYBE_RETURN(maybe_date_style, MaybeHandle<JSDateTimeFormat>());
  // 33. Set dateTimeFormat.[[DateStyle]] to dateStyle.
  date_style = maybe_date_style.FromJust();

  // 34. Let timeStyle be ? GetOption(options, "timeStyle", "string", «
  // "full", "long", "medium", "short" »).
  Maybe<DateTimeStyle> maybe_time_style = GetStringOption<DateTimeStyle>(
      isolate, options, "timeStyle", service,
      {"full", "long", "medium", "short"},
      {DateTimeStyle::kFull, DateTimeStyle::kLong, DateTimeStyle::kMedium,
       DateTimeStyle::kShort},
      DateTimeStyle::kUndefined);
  MAYBE_RETURN(maybe_time_style, MaybeHandle<JSDateTimeFormat>());

  // 35. Set dateTimeFormat.[[TimeStyle]] to timeStyle.
  time_style = maybe_time_style.FromJust();

  // 36. If timeStyle is not undefined, then
  HourCycle dateTimeFormatHourCycle = HourCycle::kUndefined;
  if (time_style != DateTimeStyle::kUndefined) {
    // a. Set dateTimeFormat.[[HourCycle]] to hc.
    dateTimeFormatHourCycle = hc;
  }

  // 37. If dateStyle or timeStyle are not undefined, then
  if (date_style != DateTimeStyle::kUndefined ||
      time_style != DateTimeStyle::kUndefined) {
    // a. If hasExplicitFormatComponents is true, then
    if (explicit_format_components != 0) {
      // i. Throw a TypeError exception.
      THROW_NEW_ERROR(
          isolate, NewTypeError(MessageTemplate::kInvalid,
                                factory->NewStringFromStaticChars("option"),
                                factory->NewStringFromStaticChars("option")));
    }
    // b. If required is ~date~ and timeStyle is not *undefined*, then
    if (required == RequiredOption::kDate &&
        time_style != DateTimeStyle::kUndefined) {
      // i. Throw a *TypeError* exception.
      THROW_NEW_ERROR(isolate,
                      NewTypeError(MessageTemplate::kInvalid,
                                   factory->NewStringFromStaticChars("option"),
                                   factory->timeStyle_string()));
    }
    // c. If required is ~time~ and dateStyle is not *undefined*, then
    if (required == RequiredOption::kTime &&
        date_style != DateTimeStyle::kUndefined) {
      // i. Throw a *TypeError* exception.
      THROW_NEW_ERROR(isolate,
                      NewTypeError(MessageTemplate::kInvalid,
                                   factory->NewStringFromStaticChars("option"),
                                   factory->dateStyle_string()));
    }
    // b. Let pattern be DateTimeStylePattern(dateStyle, timeStyle,
    // dataLocaleData, hc).
    isolate->CountUsage(
        v8::Isolate::UseCounterFeature::kDateTimeFormatDateTimeStyle);

    icu_date_format =
        DateTimeStylePattern(date_style, time_style, icu_locale,
                             dateTimeFormatHourCycle, generator.get());
    if (icu_date_format.get() == nullptr) {
      THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
    }
  } else {
    // a. Let needDefaults be *true*.
    bool needDefaults = true;
    // b. If required is ~date~ or ~any~, then
    if (required == RequiredOption::kDate || required == RequiredOption::kAny) {
      // 1. For each property name prop of << *"weekday"*, *"year"*, *"month"*,
      // *"day"* >>, do
      //    1. Let value be formatOptions.[[<prop>]].
      //    1. If value is not *undefined*, let needDefaults be *false*.

      needDefaults &= !Weekday::decode(explicit_format_components);
      needDefaults &= !Year::decode(explicit_format_components);
      needDefaults &= !Month::decode(explicit_format_components);
      needDefaults &= !Day::decode(explicit_format_components);
    }
    // c. If required is ~time~ or ~any~, then
    if (required == RequiredOption::kTime || required == RequiredOption::kAny) {
      // 1. For each property name prop of &laquo; *"dayPeriod"*, *"hour"*,
      // *"minute"*, *"second"*, *"fractionalSecondDigits"* &raquo;, do
      //    1. Let value be formatOptions.[[&lt;_prop_&gt;]].
      //    1. If value is not *undefined*, let _needDefaults_ be *false*.
      needDefaults &= !DayPeriod::decode(explicit_format_components);
      needDefaults &= !Hour::decode(explicit_format_components);
      needDefaults &= !Minute::decode(explicit_format_components);
      needDefaults &= !Second::decode(explicit_format_components);
      needDefaults &=
          !FractionalSecondDigits::decode(explicit_format_components);
    }
    // 1. If needDefaults is *true* and _defaults_ is either ~date~ or ~all~,
    // then
    if (needDefaults && ((DefaultsOption::kDate == defaults) ||
                         (DefaultsOption::kAll == defaults))) {
      // 1. For each property name prop of <<*"year"*, *"month"*, *"day"* >>, do
      // 1. Set formatOptions.[[<<prop>>]] to *"numeric"*.
      skeleton += "yMd";
    }
    // 1. If _needDefaults_ is *true* and defaults is either ~time~ or ~all~,
    // then
    if (needDefaults && ((DefaultsOption::kTime == defaults) ||
                         (DefaultsOption::kAll == defaults))) {
      // 1. For each property name prop of << *"hour"*, *"minute"*, *"second"*
      // >>, do
      // 1. Set _formatOptions_.[[<<prop>>]] to *"numeric"*.
      // See
      // https://unicode.org/reports/tr35/tr35.html#UnicodeHourCycleIdentifier
      switch (hc) {
        case HourCycle::kH12:
          skeleton += "hms";
          break;
        case HourCycle::kH23:
        case HourCycle::kUndefined:
          skeleton += "Hms";
          break;
        case HourCycle::kH11:
          skeleton += "Kms";
          break;
        case HourCycle::kH24:
          skeleton += "kms";
          break;
      }
    }
    // e. If dateTimeFormat.[[Hour]] is not undefined, then
    if (has_hour_option) {
      // v. Set dateTimeFormat.[[HourCycle]] to hc.
      dateTimeFormatHourCycle = hc;
    } else {
      // f. Else,
      // Set dateTimeFormat.[[HourCycle]] to undefined.
      dateTimeFormatHourCycle = HourCycle::kUndefined;
    }
    icu::UnicodeString skeleton_ustr(skeleton.c_str());
    icu_date_format = CreateICUDateFormatFromCache(
        icu_locale, skeleton_ustr, generator.get(), dateTimeFormatHourCycle);
    if (icu_date_format.get() == nullptr) {
      // Remove extensions and try again.
      icu_locale = icu::Locale(icu_locale.getBaseName());
      icu_date_format = CreateICUDateFormatFromCache(
          icu_locale, skeleton_ustr, generator.get(), dateTimeFormatHourCycle);
      if (icu_date_format.get() == nullptr) {
        THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
      }
    }
  }

  // The creation of Calendar depends on timeZone so we have to put 13 after 17.
  // Also icu_date_format is not created until here.
  // 13. Set dateTimeFormat.[[Calendar]] to r.[[ca]].
  icu_date_format->adoptCalendar(calendar.release());

  // 12.1.1 InitializeDateTimeFormat ( dateTimeFormat, locales, options )
  //
  // Steps 8-9 set opt.[[hc]] to value *other than undefined*
  // if "hour12" is set or "hourCycle" is set in the option.
  //
  // 9.2.6 ResolveLocale (... )
  // Step 8.h / 8.i and 8.k
  //
  // An hour12 option always overrides an hourCycle option.
  // Additionally hour12 and hourCycle both clear out any existing Unicode
  // extension key in the input locale.
  //
  // See details in https://github.com/tc39/test262/pull/2035
  if (maybe_get_hour12.FromJust() ||
      maybe_hour_cycle.FromJust() != HourCycle::kUndefined) {
    auto hc_extension_it = r.extensions.find("hc");
    if (hc_extension_it != r.extensions.end()) {
      if (dateTimeFormatHourCycle !=
          ToHourCycle(hc_extension_it->second.c_str())) {
        // Remove -hc- if it does not agree with what we used.
        status = U_ZERO_ERROR;
        resolved_locale.setUnicodeKeywordValue("hc", nullptr, status);
        DCHECK(U_SUCCESS(status));
      }
    }
  }

  Maybe<std::string> maybe_locale_str = Intl::ToLanguageTag(resolved_locale);
  MAYBE_RETURN(maybe_locale_str, MaybeHandle<JSDateTimeFormat>());
  DirectHandle<String> locale_str =
      isolate->factory()->NewStringFromAsciiChecked(
          maybe_locale_str.FromJust().c_str());

  DirectHandle<Managed<icu::Locale>> managed_locale =
      Managed<icu::Locale>::From(
          isolate, 0, std::shared_ptr<icu::Locale>{icu_locale.clone()});

  DirectHandle<Managed<icu::SimpleDateFormat>> managed_format =
      Managed<icu::SimpleDateFormat>::From(isolate, 0,
                                           std::move(icu_date_format));

  DirectHandle<Managed<icu::DateIntervalFormat>> managed_interval_format =
      Managed<icu::DateIntervalFormat>::From(isolate, 0, nullptr);

  // Now all properties are ready, so we can allocate the result object.
  Handle<JSDateTimeFormat> date_time_format = Cast<JSDateTimeFormat>(
      isolate->factory()->NewFastOrSlowJSObjectFromMap(map));
  DisallowGarbageCollection no_gc;
  date_time_format->set_flags(0);
  if (date_style != DateTimeStyle::kUndefined) {
    date_time_format->set_date_style(date_style);
  }
  if (time_style != DateTimeStyle::kUndefined) {
    date_time_format->set_time_style(time_style);
  }
  date_time_format->set_hour_cycle(dateTimeFormatHourCycle);
  date_time_format->set_locale(*locale_str);
  date_time_format->set_icu_locale(*managed_locale);
  date_time_format->set_icu_simple_date_format(*managed_format);
  date_time_format->set_icu_date_interval_format(*managed_interval_format);
  return date_time_format;
}

namespace {

// The list comes from third_party/icu/source/i18n/unicode/udat.h.
// They're mapped to DateTimeFormat components listed at
// https://tc39.github.io/ecma402/#sec-datetimeformat-abstracts .
Handle<String> IcuDateFieldIdToDateType(int32_t field_id, Isolate* isolate) {
  switch (field_id) {
    case -1:
      return isolate->factory()->literal_string();
    case UDAT_YEAR_FIELD:
    case UDAT_EXTENDED_YEAR_FIELD:
      return isolate->factory()->year_string();
    case UDAT_YEAR_NAME_FIELD:
      return isolate->factory()->yearName_string();
    case UDAT_MONTH_FIELD:
    case UDAT_STANDALONE_MONTH_FIELD:
      return isolate->factory()->month_string();
    case UDAT_DATE_FIELD:
      return isolate->factory()->day_string();
    case UDAT_HOUR_OF_DAY1_FIELD:
    case UDAT_HOUR_OF_DAY0_FIELD:
    case UDAT_HOUR1_FIELD:
    case UDAT_HOUR0_FIELD:
      return isolate->factory()->hour_string();
    case UDAT_MINUTE_FIELD:
      return isolate->factory()->minute_string();
    case UDAT_SECOND_FIELD:
      return isolate->factory()->second_string();
    case UDAT_DAY_OF_WEEK_FIELD:
    case UDAT_DOW_LOCAL_FIELD:
    case UDAT_STANDALONE_DAY_FIELD:
      return isolate->factory()->weekday_string();
    case UDAT_AM_PM_FIELD:
    case UDAT_AM_PM_MIDNIGHT_NOON_FIELD:
    case UDAT_FLEXIBLE_DAY_PERIOD_FIELD:
      return isolate->factory()->dayPeriod_string();
    case UDAT_TIMEZONE_FIELD:
    case UDAT_TIMEZONE_RFC_FIELD:
    case UDAT_TIMEZONE_GENERIC_FIELD:
    case UDAT_TIMEZONE_SPECIAL_FIELD:
    case UDAT_TIMEZONE_LOCALIZED_GMT_OFFSET_FIELD:
    case UDAT_TIMEZONE_ISO_FIELD:
    case UDAT_TIMEZONE_ISO_LOCAL_FIELD:
      return isolate->factory()->timeZoneName_string();
    case UDAT_ERA_FIELD:
      return isolate->factory()->era_string();
    case UDAT_FRACTIONAL_SECOND_FIELD:
      return isolate->factory()->fractionalSecond_string();
    case UDAT_RELATED_YEAR_FIELD:
      return isolate->factory()->relatedYear_string();

    case UDAT_QUARTER_FIELD:
    case UDAT_STANDALONE_QUARTER_FIELD:
    default:
      // Other UDAT_*_FIELD's cannot show up because there is no way to specify
      // them via options of Intl.DateTimeFormat.
      UNREACHABLE();
  }
}

MaybeHandle<JSArray> FieldPositionIteratorToArray(
    Isolate* isolate, const icu::UnicodeString& formatted,
    icu::FieldPositionIterator fp_iter, bool output_source);

MaybeHandle<JSArray> FormatMillisecondsByKindToArray(
    Isolate* isolate, const icu::SimpleDateFormat& date_format,
    PatternKind kind, double x, bool output_source) {
  icu::FieldPositionIterator fp_iter;
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString formatted =
      CallICUFormat(date_format, kind, x, &fp_iter, status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  return FieldPositionIteratorToArray(isolate, formatted, fp_iter,
                                      output_source);
}
MaybeHandle<JSArray> FormatMillisecondsByKindToArrayOutputSource(
    Isolate* isolate, const icu::SimpleDateFormat& date_format,
    PatternKind kind, double x) {
  return FormatMillisecondsByKindToArray(isolate, date_format, kind, x, true);
}

MaybeHandle<JSArray> FormatToPartsWithTemporalSupport(
    Isolate* isolate, DirectHandle<JSDateTimeFormat> date_time_format,
    Handle<Object> x, bool output_source, const char* method_name) {
  icu::SimpleDateFormat* format =
      date_time_format->icu_simple_date_format()->raw();
  DCHECK_NOT_NULL(format);

  // 1. Let x be ? HandleDateTimeValue(dateTimeFormat, x).
  DateTimeValueRecord x_record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, x_record,
      HandleDateTimeValue(isolate, *format, GetCalendar(isolate, *format), x,
                          method_name),
      Handle<JSArray>());

  return FormatMillisecondsByKindToArray(isolate, *format, x_record.kind,
                                         x_record.epoch_milliseconds,
                                         output_source);
}

MaybeHandle<JSArray> FormatMillisecondsToArray(
    Isolate* isolate, const icu::SimpleDateFormat& format, double value,
    bool output_source) {
  icu::UnicodeString formatted;
  icu::FieldPositionIterator fp_iter;
  UErrorCode status = U_ZERO_ERROR;
  format.format(value, formatted, &fp_iter, status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  return FieldPositionIteratorToArray(isolate, formatted, fp_iter,
                                      output_source);
}
MaybeHandle<JSArray> FormatMillisecondsToArrayOutputSource(
    Isolate* isolate, const icu::SimpleDateFormat& format, double value) {
  return FormatMillisecondsToArray(isolate, format, value, true);
}
}  // namespace

MaybeHandle<JSArray> JSDateTimeFormat::FormatToParts(
    Isolate* isolate, DirectHandle<JSDateTimeFormat> date_time_format,
    Handle<Object> x, bool output_source, const char* method_name) {
  Factory* factory = isolate->factory();
  if (v8_flags.harmony_temporal) {
    return FormatToPartsWithTemporalSupport(isolate, date_time_format, x,
                                            output_source, method_name);
  }

  if (IsUndefined(*x, isolate)) {
    x = factory->NewNumberFromInt64(JSDate::CurrentTimeValue(isolate));
  } else {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, x, Object::ToNumber(isolate, x));
  }

  double date_value = Object::NumberValue(*x);
  if (!DateCache::TryTimeClip(&date_value)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidTimeValue));
  }
  return FormatMillisecondsToArray(
      isolate, *(date_time_format->icu_simple_date_format()->raw()), date_value,
      output_source);
}

namespace {
MaybeHandle<JSArray> FieldPositionIteratorToArray(
    Isolate* isolate, const icu::UnicodeString& formatted,
    icu::FieldPositionIterator fp_iter, bool output_source) {
  Factory* factory = isolate->factory();
  icu::FieldPosition fp;
  Handle<JSArray> result = factory->NewJSArray(0);
  int32_t length = formatted.length();
  if (length == 0) return result;

  int index = 0;
  int32_t previous_end_pos = 0;
  Handle<String> substring;
  while (fp_iter.next(fp)) {
    int32_t begin_pos = fp.getBeginIndex();
    int32_t end_pos = fp.getEndIndex();

    if (previous_end_pos < begin_pos) {
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, substring,
          Intl::ToString(isolate, formatted, previous_end_pos, begin_pos));
      if (output_source) {
        Intl::AddElement(isolate, result, index,
                         IcuDateFieldIdToDateType(-1, isolate), substring,
                         isolate->factory()->source_string(),
                         isolate->factory()->shared_string());
      } else {
        Intl::AddElement(isolate, result, index,
                         IcuDateFieldIdToDateType(-1, isolate), substring);
      }
      ++index;
    }
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, substring,
        Intl::ToString(isolate, formatted, begin_pos, end_pos));
    if (output_source) {
      Intl::AddElement(isolate, result, index,
                       IcuDateFieldIdToDateType(fp.getField(), isolate),
                       substring, isolate->factory()->source_string(),
                       isolate->factory()->shared_string());
    } else {
      Intl::AddElement(isolate, result, index,
                       IcuDateFieldIdToDateType(fp.getField(), isolate),
                       substring);
    }
    previous_end_pos = end_pos;
    ++index;
  }
  if (previous_end_pos < length) {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, substring,
        Intl::ToString(isolate, formatted, previous_end_pos, length));
    if (output_source) {
      Intl::AddElement(isolate, result, index,
                       IcuDateFieldIdToDateType(-1, isolate), substring,
                       isolate->factory()->source_string(),
                       isolate->factory()->shared_string());
    } else {
      Intl::AddElement(isolate, result, index,
                       IcuDateFieldIdToDateType(-1, isolate), substring);
    }
  }
  JSObject::ValidateElements(*result);
  return result;
}

}  // namespace

const std::set<std::string>& JSDateTimeFormat::GetAvailableLocales() {
  return Intl::GetAvailableLocalesForDateFormat();
}

Handle<String> JSDateTimeFormat::HourCycleAsString() const {
  switch (hour_cycle()) {
    case HourCycle::kUndefined:
      return GetReadOnlyRoots().undefined_string_handle();
    case HourCycle::kH11:
      return GetReadOnlyRoots().h11_string_handle();
    case HourCycle::kH12:
      return GetReadOnlyRoots().h12_string_handle();
    case HourCycle::kH23:
      return GetReadOnlyRoots().h23_string_handle();
    case HourCycle::kH24:
      return GetReadOnlyRoots().h24_string_handle();
    default:
      UNREACHABLE();
  }
}

namespace {

Maybe<bool> AddPartForFormatRange(
    Isolate* isolate, Handle<JSArray> array, const icu::UnicodeString& string,
    int32_t index, int32_t field, int32_t start, int32_t end,
    const Intl::FormatRangeSourceTracker& tracker) {
  Handle<String> substring;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, substring,
                                   Intl::ToString(isolate, string, start, end),
                                   Nothing<bool>());
  Intl::AddElement(isolate, array, index,
                   IcuDateFieldIdToDateType(field, isolate), substring,
                   isolate->factory()->source_string(),
                   Intl::SourceString(isolate, tracker.GetSource(start, end)));
  return Just(true);
}

// If this function return a value, it could be a throw of TypeError, or normal
// formatted string. If it return a nullopt the caller should call the fallback
// function.
std::optional<MaybeHandle<String>> FormattedToString(
    Isolate* isolate, const icu::FormattedValue& formatted) {
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString result = formatted.toString(status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  icu::ConstrainedFieldPosition cfpos;
  while (formatted.nextPosition(cfpos, status)) {
    if (cfpos.getCategory() == UFIELD_CATEGORY_DATE_INTERVAL_SPAN) {
      return Intl::ToString(isolate, result);
    }
  }
  return std::nullopt;
}

// A helper function to convert the FormattedDateInterval to a
// MaybeHandle<JSArray> for the implementation of formatRangeToParts.
// If this function return a value, it could be a throw of TypeError, or normal
// formatted parts in JSArray. If it return a nullopt the caller should call
// the fallback function.
std::optional<MaybeHandle<JSArray>> FormattedDateIntervalToJSArray(
    Isolate* isolate, const icu::FormattedValue& formatted) {
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString result = formatted.toString(status);

  Factory* factory = isolate->factory();
  Handle<JSArray> array = factory->NewJSArray(0);
  icu::ConstrainedFieldPosition cfpos;
  int index = 0;
  int32_t previous_end_pos = 0;
  Intl::FormatRangeSourceTracker tracker;
  bool output_range = false;
  while (formatted.nextPosition(cfpos, status)) {
    int32_t category = cfpos.getCategory();
    int32_t field = cfpos.getField();
    int32_t start = cfpos.getStart();
    int32_t limit = cfpos.getLimit();

    if (category == UFIELD_CATEGORY_DATE_INTERVAL_SPAN) {
      DCHECK_LE(field, 2);
      output_range = true;
      tracker.Add(field, start, limit);
    } else {
      DCHECK(category == UFIELD_CATEGORY_DATE);
      if (start > previous_end_pos) {
        // Add "literal" from the previous end position to the start if
        // necessary.
        Maybe<bool> maybe_added =
            AddPartForFormatRange(isolate, array, result, index, -1,
                                  previous_end_pos, start, tracker);
        MAYBE_RETURN(maybe_added, Handle<JSArray>());
        previous_end_pos = start;
        index++;
      }
      Maybe<bool> maybe_added = AddPartForFormatRange(
          isolate, array, result, index, field, start, limit, tracker);
      MAYBE_RETURN(maybe_added, Handle<JSArray>());
      previous_end_pos = limit;
      ++index;
    }
  }
  int32_t end = result.length();
  // Add "literal" in the end if necessary.
  if (end > previous_end_pos) {
    Maybe<bool> maybe_added = AddPartForFormatRange(
        isolate, array, result, index, -1, previous_end_pos, end, tracker);
    MAYBE_RETURN(maybe_added, Handle<JSArray>());
  }

  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }

  JSObject::ValidateElements(*array);
  if (output_range) return array;
  return std::nullopt;
}

// The shared code between formatRange and formatRangeToParts
template <typename T, std::optional<MaybeHandle<T>> (*Format)(
                          Isolate*, const icu::FormattedValue&)>
std::optional<MaybeHandle<T>> CallICUFormatRange(
    Isolate* isolate, const icu::DateIntervalFormat* format,
    const icu::Calendar* calendar, double x, double y);
// #sec-partitiondatetimerangepattern
template <typename T, std::optional<MaybeHandle<T>> (*Format)(
                          Isolate*, const icu::FormattedValue&)>
std::optional<MaybeHandle<T>> PartitionDateTimeRangePattern(
    Isolate* isolate, DirectHandle<JSDateTimeFormat> date_time_format, double x,
    double y, const char* method_name) {
  // 1. Let x be TimeClip(x).
  // 2. If x is NaN, throw a RangeError exception.
  if (!DateCache::TryTimeClip(&x)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidTimeValue));
  }
  // 3. Let y be TimeClip(y).
  // 4. If y is NaN, throw a RangeError exception.
  if (!DateCache::TryTimeClip(&y)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidTimeValue));
  }

  std::unique_ptr<icu::DateIntervalFormat> format(LazyCreateDateIntervalFormat(
      isolate, date_time_format, PatternKind::kDate));
  if (format.get() == nullptr) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }

  icu::SimpleDateFormat* date_format =
      date_time_format->icu_simple_date_format()->raw();
  const icu::Calendar* calendar = date_format->getCalendar();

  return CallICUFormatRange<T, Format>(isolate, format.get(), calendar, x, y);
}

template <typename T, std::optional<MaybeHandle<T>> (*Format)(
                          Isolate*, const icu::FormattedValue&)>
std::optional<MaybeHandle<T>> CallICUFormatRange(
    Isolate* isolate, const icu::DateIntervalFormat* format,
    const icu::Calendar* calendar, double x, double y) {
  UErrorCode status = U_ZERO_ERROR;

  std::unique_ptr<icu::Calendar> c1(calendar->clone());
  std::unique_ptr<icu::Calendar> c2(calendar->clone());
  c1->setTime(x, status);
  c2->setTime(y, status);
  // We need to format by Calendar because we need the Gregorian change
  // adjustment already in the SimpleDateFormat to set the correct value of date
  // older than Oct 15, 1582.
  icu::FormattedDateInterval formatted =
      format->formatToValue(*c1, *c2, status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  return Format(isolate, formatted);
}

template <typename T,
          std::optional<MaybeHandle<T>> (*Format)(Isolate*,
                                                  const icu::FormattedValue&),
          MaybeHandle<T> (*Fallback)(Isolate*, const icu::SimpleDateFormat&,
                                     PatternKind, double)>
MaybeHandle<T> FormatRangeCommonWithTemporalSupport(
    Isolate* isolate, DirectHandle<JSDateTimeFormat> date_time_format,
    Handle<Object> x_obj, Handle<Object> y_obj, const char* method_name) {
  // 5. If either of ! IsTemporalObject(x) or ! IsTemporalObject(y) is true,
  // then
  if (IsTemporalObject(x_obj) || IsTemporalObject(y_obj)) {
    // a. If ! SameTemporalType(x, y) is false, throw a TypeError exception.
    if (!SameTemporalType(x_obj, y_obj)) {
      THROW_NEW_ERROR(
          isolate,
          NewTypeError(MessageTemplate::kInvalidArgumentForTemporal, y_obj));
    }
  }
  // 6. Let x be ? HandleDateTimeValue(dateTimeFormat, x).
  icu::SimpleDateFormat* icu_simple_date_format =
      date_time_format->icu_simple_date_format()->raw();
  Handle<String> date_time_format_calendar =
      GetCalendar(isolate, *icu_simple_date_format);
  DateTimeValueRecord x_record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, x_record,
      HandleDateTimeValue(isolate, *icu_simple_date_format,
                          date_time_format_calendar, x_obj, method_name),
      Handle<T>());

  // 7. Let y be ? HandleDateTimeValue(dateTimeFormat, y).
  DateTimeValueRecord y_record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, y_record,
      HandleDateTimeValue(isolate, *icu_simple_date_format,
                          date_time_format_calendar, y_obj, method_name),
      Handle<T>());

  std::unique_ptr<icu::DateIntervalFormat> format(
      LazyCreateDateIntervalFormat(isolate, date_time_format, x_record.kind));
  if (format.get() == nullptr) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }

  const icu::Calendar* calendar =
      date_time_format->icu_simple_date_format()->raw()->getCalendar();

  std::optional<MaybeHandle<T>> result = CallICUFormatRange<T, Format>(
      isolate, format.get(), calendar, x_record.epoch_milliseconds,
      y_record.epoch_milliseconds);
  if (result.has_value()) return *result;
  return Fallback(isolate, *icu_simple_date_format, x_record.kind,
                  x_record.epoch_milliseconds);
}

template <typename T,
          std::optional<MaybeHandle<T>> (*Format)(Isolate*,
                                                  const icu::FormattedValue&),
          MaybeHandle<T> (*Fallback)(Isolate*, const icu::SimpleDateFormat&,
                                     double)>
MaybeHandle<T> FormatRangeCommon(Isolate* isolate,
                                 Handle<JSDateTimeFormat> date_time_format,
                                 Handle<Object> x_obj, Handle<Object> y_obj,
                                 const char* method_name) {
  // 4. Let x be ? ToNumber(startDate).
  ASSIGN_RETURN_ON_EXCEPTION(isolate, x_obj, Object::ToNumber(isolate, x_obj));
  double x = Object::NumberValue(*x_obj);
  // 5. Let y be ? ToNumber(endDate).
  ASSIGN_RETURN_ON_EXCEPTION(isolate, y_obj, Object::ToNumber(isolate, y_obj));
  double y = Object::NumberValue(*y_obj);

  std::optional<MaybeHandle<T>> result =
      PartitionDateTimeRangePattern<T, Format>(isolate, date_time_format, x, y,
                                               method_name);
  if (result.has_value()) return *result;
  return Fallback(isolate, *(date_time_format->icu_simple_date_format()->raw()),
                  x);
}

}  // namespace

MaybeHandle<String> JSDateTimeFormat::FormatRange(
    Isolate* isolate, Handle<JSDateTimeFormat> date_time_format,
    Handle<Object> x, Handle<Object> y, const char* method_name) {
  // Track newer feature formateRange and formatRangeToParts
  isolate->CountUsage(v8::Isolate::UseCounterFeature::kDateTimeFormatRange);
  if (v8_flags.harmony_temporal) {
    // For Temporal enable support
    return FormatRangeCommonWithTemporalSupport<
        String, FormattedToString, FormatMillisecondsByKindToString>(
        isolate, date_time_format, x, y, method_name);
  }
  // Pre Temporal implementation
  return FormatRangeCommon<String, FormattedToString, FormatDateTime>(
      isolate, date_time_format, x, y, method_name);
}

MaybeHandle<JSArray> JSDateTimeFormat::FormatRangeToParts(
    Isolate* isolate, Handle<JSDateTimeFormat> date_time_format,
    Handle<Object> x, Handle<Object> y, const char* method_name) {
  // Track newer feature formateRange and formatRangeToParts
  isolate->CountUsage(v8::Isolate::UseCounterFeature::kDateTimeFormatRange);
  if (v8_flags.harmony_temporal) {
    // For Temporal enable support
    return FormatRangeCommonWithTemporalSupport<
        JSArray, FormattedDateIntervalToJSArray,
        FormatMillisecondsByKindToArrayOutputSource>(isolate, date_time_format,
                                                     x, y, method_name);
  }
  // Pre Temporal implementation
  return FormatRangeCommon<JSArray, FormattedDateIntervalToJSArray,
                           FormatMillisecondsToArrayOutputSource>(
      isolate, date_time_format, x, y, method_name);
}

}  // namespace v8::internal
```