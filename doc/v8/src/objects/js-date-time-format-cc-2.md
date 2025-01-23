Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/js-date-time-format.cc`. The prompt asks for:

1. **Functionality Description:** A high-level overview of what the code does.
2. **Torque Check:**  Whether the file would be a Torque file if its extension was `.tq`.
3. **JavaScript Relation:**  If the code relates to JavaScript functionality, provide a JavaScript example.
4. **Logic Inference:** If there's code logic, provide example inputs and outputs.
5. **Common Errors:**  Illustrate potential programming errors related to the code.
6. **Concise Summary:** A final, brief summary of the code's purpose.

Let's break down the provided code snippet:

- **`GetOffsetTimeZone`:** This function seems to parse a time zone string in the format `[+-\u2212]hh[:]?mm` and convert it into a format suitable for `SimpleTimeZone` (e.g., `GMT+hh` or `GMT+hhmm`). It handles potential errors in the input format.
- **`CreateTimeZone`:**  This function takes a time zone string and creates an `icu::TimeZone` object. It first tries to interpret the string as an offset time zone using `GetOffsetTimeZone`. If that fails, it tries to create a time zone using the provided ID, canonicalizing it first. It also validates the time zone name.
- **`CalendarCache`:** This class appears to be a cache for `icu::Calendar` objects. It stores calendars based on the locale and time zone to avoid repeatedly creating them. It limits the cache size.
- **`CreateCalendar` (function):** This function uses the `CalendarCache` to retrieve or create an `icu::Calendar` object for a given locale and time zone. It also sets the Gregorian change to the beginning of ECMAScript time.
- **`ReplaceHourCycleInPattern`:** This function takes an ICU date/time pattern and replaces the hour cycle specifier (e.g., 'H', 'h', 'K', 'k') based on the provided `HourCycle` enum.
- **`CreateICUDateFormat`:** This function creates an `icu::SimpleDateFormat` object based on a locale, a skeleton pattern, a `DateTimePatternGenerator`, and an `HourCycle`. It handles a temporary workaround related to locale handling.
- **`DateFormatCache`:** Similar to `CalendarCache`, this class caches `icu::SimpleDateFormat` objects.
- **`CreateICUDateFormatFromCache`:**  Uses the `DateFormatCache` to retrieve or create a `icu::SimpleDateFormat`.
- **`LazyCreateDateIntervalFormat`:** This function lazily creates an `icu::DateIntervalFormat`. It seems to cache the format for `PatternKind::kDate`.
- **`HourCycleFromPattern`:** This function extracts the `HourCycle` from an ICU date/time pattern.
- **`DateTimeStyleToEStyle`:** Converts the internal `JSDateTimeFormat::DateTimeStyle` enum to ICU's `icu::DateFormat::EStyle`.
- **`ReplaceSkeleton`:**  Replaces hour-related skeleton characters in a pattern based on the `HourCycle`.
- **`DateTimeStylePattern`:** Creates an `icu::SimpleDateFormat` based on provided date and time styles, locale, and `HourCycle`. It handles fallback scenarios if creating the instance fails.
- **`DateTimePatternGeneratorCache`:**  Caches `icu::DateTimePatternGenerator` instances.
- **`CreateGenerator`:**  Uses the `DateTimePatternGeneratorCache` to get or create a generator. It handles potential memory allocation errors.
- **`FormatMatcherOption` enum:** Defines options for format matching ("best fit" and "basic").
- **`JSDateTimeFormat::New`:** A static factory method to create a `JSDateTimeFormat` object.
- **`JSDateTimeFormat::CreateDateTimeFormat`:**  The core function for initializing a `JSDateTimeFormat` object. It handles locale resolution, option processing (calendar, numbering system, hour cycle, time zone, format components, date/time styles), and the creation of the underlying ICU formatters.

**Plan:**

1. Describe the core functionality: Parsing timezone strings, creating and caching ICU formatters (calendars, date formats, interval formats, pattern generators).
2. Address the Torque question: Explain that `.tq` files are for Torque, a TypeScript-like language for V8.
3. Provide a JavaScript example showcasing the use of `Intl.DateTimeFormat`, which this C++ code implements.
4. Give an example of `GetOffsetTimeZone` with input and output.
5. Illustrate a common error like providing an invalid time zone string to `Intl.DateTimeFormat`.
6. Summarize the code's role in providing the underlying implementation for JavaScript's `Intl.DateTimeFormat`.
这是 v8 源代码 `v8/src/objects/js-date-time-format.cc` 的第三部分，主要功能是处理和创建 ICU (International Components for Unicode) 库中的日期和时间格式化相关的对象。它涉及到时区处理、日历对象的创建和缓存、以及日期格式化模式的生成和缓存。

**功能归纳:**

1. **时区处理:**
   - `GetOffsetTimeZone`:  尝试将特定格式的字符串（例如 "+08:00", "-0530"）转换为 ICU 能够识别的时区 ID 格式（例如 "GMT+08", "GMT-0530"）。
   - `CreateTimeZone`:  根据提供的时区字符串创建一个 `icu::TimeZone` 对象。它首先尝试解析为偏移量时区，如果失败则尝试使用规范化的时区 ID。还会检查时区名称是否有效。

2. **日历对象创建和缓存:**
   - `CalendarCache`:  一个缓存类，用于存储已经创建的 `icu::Calendar` 对象。这样可以避免重复创建相同的日历对象，提高性能。缓存的键是时区 ID 和 locale 的组合。
   - `CreateCalendar`:  使用 `CalendarCache` 来获取或创建一个 `icu::Calendar` 对象。它会根据 locale 和时区创建日历，并设置 ECMAScript 的起始时间为格里高利历的变更点。

3. **日期格式化模式处理:**
   - `ReplaceHourCycleInPattern`:  根据指定的 `HourCycle` (例如 "h12", "h24") 替换日期格式模式中的小时表示符 (例如 'h', 'H', 'K', 'k')。
   - `CreateICUDateFormat`:  根据 locale、格式骨架 (skeleton)、`DateTimePatternGenerator` 和 `HourCycle` 创建一个 `icu::SimpleDateFormat` 对象。
   - `DateFormatCache`:  一个缓存类，用于存储已经创建的 `icu::SimpleDateFormat` 对象，提高性能。
   - `CreateICUDateFormatFromCache`:  使用 `DateFormatCache` 来获取或创建一个 `icu::SimpleDateFormat` 对象。
   - `LazyCreateDateIntervalFormat`: 延迟创建 `icu::DateIntervalFormat` 对象，并可能缓存 `PatternKind::kDate` 的实例。
   - `HourCycleFromPattern`: 从日期格式模式中解析出 `HourCycle`。
   - `DateTimeStyleToEStyle`: 将 V8 内部的 `DateTimeStyle` 枚举转换为 ICU 的 `DateFormat::EStyle` 枚举。
   - `ReplaceSkeleton`: 根据 `HourCycle` 替换格式骨架中的小时相关字符。
   - `DateTimeStylePattern`:  根据日期和时间风格（例如 "short", "long"）、locale 和 `HourCycle` 创建 `icu::SimpleDateFormat` 对象。如果创建失败，会尝试回退到不包含 "nu"、"hc" 或 "ca" Unicode 扩展的 locale。
   - `DateTimePatternGeneratorCache`:  缓存 `icu::DateTimePatternGenerator` 对象。
   - `CreateGenerator`: 使用 `DateTimePatternGeneratorCache` 获取或创建 `icu::DateTimePatternGenerator` 对象。

4. **`JSDateTimeFormat` 对象创建:**
   - `JSDateTimeFormat::New`:  创建 `JSDateTimeFormat` 对象的工厂方法。
   - `JSDateTimeFormat::CreateDateTimeFormat`:  初始化 `JSDateTimeFormat` 对象的关键函数。它处理 locale 解析、选项（如 calendar, numberingSystem, hourCycle, timeZone, dateStyle, timeStyle 等）的获取和验证，并最终创建底层的 ICU 格式化对象。

**如果 `v8/src/objects/js-date-time-format.cc` 以 `.tq` 结尾:**

如果该文件以 `.tq` 结尾，那么它将是一个 **v8 Torque 源代码**。Torque 是 V8 使用的一种内部领域特定语言，用于定义 V8 的内置函数和对象的操作。它类似于 TypeScript，并允许更安全和结构化的方式来编写 V8 的内部实现。

**与 JavaScript 的关系及举例:**

这段 C++ 代码是 JavaScript 中 `Intl.DateTimeFormat` API 的底层实现。`Intl.DateTimeFormat` 允许开发者根据不同的 locale 和选项格式化日期和时间。

```javascript
// JavaScript 示例：使用 Intl.DateTimeFormat 格式化日期和时间

// 创建一个日期对象
const date = new Date();

// 创建一个 Intl.DateTimeFormat 对象，指定 locale 和选项
const formatter = new Intl.DateTimeFormat('zh-CN', {
  year: 'numeric',
  month: 'long',
  day: 'numeric',
  hour: 'numeric',
  minute: '2-digit',
  second: '2-digit',
  timeZone: 'Asia/Shanghai'
});

// 格式化日期
const formattedDate = formatter.format(date);
console.log(formattedDate); // 输出类似于 "2023年10月27日 10:30:45"

// 使用不同的选项
const timeFormatter = new Intl.DateTimeFormat('en-US', {
  hour: 'numeric',
  minute: 'numeric',
  hour12: true // 使用 12 小时制
});
const formattedTime = timeFormatter.format(date);
console.log(formattedTime); // 输出类似于 "10:30 AM"
```

`v8/src/objects/js-date-time-format.cc` 中的代码负责处理 `Intl.DateTimeFormat` 构造函数中传入的 `locale` 和 `options` 参数，并使用 ICU 库创建相应的格式化器。

**代码逻辑推理及假设输入输出:**

**`GetOffsetTimeZone` 示例:**

**假设输入:**

- `isolate`: V8 的 Isolate 对象
- `time_zone`:  一个 V8 String 对象，内容为 "+08:30"

**代码逻辑:**

`GetOffsetTimeZone` 函数会解析 "+08:30":

1. 提取符号 '+'。
2. 提取小时 '0' 和 '8'。
3. 检查是否存在 ':' 并跳过。
4. 提取分钟 '3' 和 '0'。
5. 构建 "GMT+0830" 字符串。

**预期输出:**

- `std::optional<std::string>` 包含字符串 "GMT+0830"。

**假设输入:**

- `isolate`: V8 的 Isolate 对象
- `time_zone`:  一个 V8 String 对象，内容为 "invalid format"

**代码逻辑:**

`GetOffsetTimeZone` 函数会检测到格式错误，例如缺少符号或小时/分钟格式不正确。

**预期输出:**

- `std::optional<std::string>` 为 `std::nullopt`。

**用户常见的编程错误举例:**

1. **提供无效的时区字符串给 `Intl.DateTimeFormat`:**

   ```javascript
   try {
     const formatter = new Intl.DateTimeFormat('en-US', { timeZone: 'InvalidTimeZone' });
     const formattedDate = formatter.format(new Date());
   } catch (e) {
     console.error(e); // 输出 RangeError，因为 'InvalidTimeZone' 不是有效的时区
   }
   ```
   `CreateTimeZone` 函数会调用 `Intl::IsValidTimeZoneName` 检查时区有效性，如果无效则会抛出 `RangeError`。

2. **同时指定 `hour12` 和 `hourCycle` 选项:**

   ```javascript
   try {
     const formatter = new Intl.DateTimeFormat('en-US', { hour12: true, hourCycle: 'h23' });
   } catch (e) {
     console.error(e); // 输出 TypeError，因为这两个选项互斥
   }
   ```
   `JSDateTimeFormat::CreateDateTimeFormat` 函数中会检查这种情况，如果同时定义了 `hour12` 且 `hourCycle` 不是 undefined，则会抛出 `TypeError`。

**总结一下它的功能 (第3部分):**

`v8/src/objects/js-date-time-format.cc` 的第三部分主要负责 `Intl.DateTimeFormat` API 底层的核心功能实现，包括：解析和创建 ICU 时区对象，缓存和创建 ICU 日历对象，处理和缓存日期格式化模式，以及为 `JSDateTimeFormat` 对象的初始化提供关键的构建块。它确保了 JavaScript 中日期和时间格式化的正确性和性能。

### 提示词
```
这是目录为v8/src/objects/js-date-time-format.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-date-time-format.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
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
    if (required == RequiredOption::kDate || required =
```