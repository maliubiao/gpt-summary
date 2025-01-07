Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/js-date-time-format.cc`.

Here's a breakdown of the thought process to achieve the summary:

1. **Identify the Core Purpose:** The filename `js-date-time-format.cc` strongly suggests that this code is responsible for handling JavaScript's `Intl.DateTimeFormat` functionality within V8. This will be the central theme of the summary.

2. **Scan for Key Classes and Functions:** Look for significant class names, function names, and namespaces. The namespace `v8::internal` and the class `JSDateTimeFormat` are prominent. Within the anonymous namespace, functions like `ToHourCycleString`, `ToHourCycle`, `DefaultHourCycle12`, `DefaultHourCycle24`, `GetHourCycle`, `BuildPatternItems`, `GetPatternItems`, `GetPatternData`, `GetGMTTzID`, `ToTitleCaseTimezoneLocation`, and `CanonicalizeTimeZoneID` stand out. These functions likely handle specific aspects of date and time formatting.

3. **Analyze Included Headers:** The `#include` directives provide clues about dependencies and functionality:
    * `<algorithm>`, `<map>`, `<memory>`, etc.: Standard C++ utilities.
    * `"src/base/bit-field.h"`:  Indicates the use of bit fields, possibly for storing format options efficiently.
    * `"src/date/date.h"`: Likely for basic date calculations.
    * `"src/execution/isolate.h"`, `"src/heap/factory.h"`, `"src/objects/intl-objects.h"`, etc.: V8 internal headers, suggesting interaction with the JavaScript engine's object model and internationalization support.
    * `"unicode/calendar.h"`, `"unicode/dtitvfmt.h"`, `"unicode/dtptngen.h"`, `"unicode/fieldpos.h"`, `"unicode/gregocal.h"`, `"unicode/smpdtfmt.h"`, `"unicode/unistr.h"`:  Crucially, these indicate reliance on the ICU library for internationalization, particularly date and time formatting.

4. **Group Functionalities:** Based on the identified functions and headers, group related tasks:
    * **Hour Cycle Handling:** Functions like `ToHourCycleString`, `ToHourCycle`, `DefaultHourCycle12`, `DefaultHourCycle24`, and `GetHourCycle` clearly deal with the `hourCycle` option in `Intl.DateTimeFormat`.
    * **Pattern Matching and Formatting:**  The `PatternMap`, `PatternItem`, `PatternItems`, and `GetPatternData` suggest a system for mapping format options (like "long", "short", "numeric") to ICU date/time patterns (like "yyyy", "yy", "M"). The different `Trait` structs (`H11Trait`, `H12Trait`, etc.) for different hour cycles reinforce this.
    * **Timezone Handling:**  Functions like `GetGMTTzID`, `ToTitleCaseTimezoneLocation`, and `CanonicalizeTimeZoneID`, along with the `SpecialTimeZoneMap`, are involved in normalizing and canonicalizing timezone IDs.
    * **Integration with V8/JavaScript:** Functions related to `JSDateTimeFormat` and the inclusion of V8 headers indicate the class's role in representing `Intl.DateTimeFormat` objects within V8. Functions like `TimeZoneId`, `Calendar`, `TimeZone`, and `ResolvedOptions` strongly suggest methods for accessing and exposing formatted date/time information and resolved options to JavaScript.
    * **Temporal API Support:** The presence of `IsTemporalObject` and `SameTemporalType` hints at integration with the Temporal API (a newer JavaScript date/time API).

5. **Formulate the Summary:** Combine the grouped functionalities into a concise description, mentioning the core purpose and key capabilities. Highlight the reliance on the ICU library.

6. **Address the Specific Questions:**
    * **`.tq` extension:**  The code is C++, not Torque, so note that.
    * **Relationship to JavaScript:** Explain how this C++ code implements the JavaScript `Intl.DateTimeFormat` API. Provide a simple JavaScript example demonstrating its usage.
    * **Code Logic Inference (Hypothetical Input/Output):** Choose a simple example like formatting a date. Define the input (a date and `Intl.DateTimeFormat` options) and the expected output (the formatted date string).
    * **Common Programming Errors:**  Think about common mistakes when using `Intl.DateTimeFormat`, such as incorrect locale or option usage. Provide an example.

7. **Refine and Organize:** Ensure the summary is clear, well-organized, and addresses all aspects of the prompt. Use clear language and avoid overly technical jargon where possible. Structure the answer into logical sections.
好的，这是对提供的V8源代码文件 `v8/src/objects/js-date-time-format.cc` 功能的归纳：

**功能归纳:**

`v8/src/objects/js-date-time-format.cc` 文件是 V8 JavaScript 引擎中用于实现 `Intl.DateTimeFormat` 国际化日期和时间格式化功能的 C++ 源代码。  它的主要职责是：

1. **提供 JavaScript `Intl.DateTimeFormat` 对象的底层实现:** 它定义了 `JSDateTimeFormat` 类，该类在 V8 内部表示 `Intl.DateTimeFormat` 的实例。

2. **处理日期和时间格式化的各种选项:**  该代码处理 `Intl.DateTimeFormat` 构造函数中提供的各种选项，例如：
    * `locale`:  指定使用的区域设置。
    * `calendar`:  指定使用的日历系统（例如，公历、佛历）。
    * `timeZone`:  指定时区。
    * `hourCycle`: 指定小时周期（例如，"h11"、"h12"、"h23"、"h24"）。
    * `weekday`, `era`, `year`, `month`, `day`, `hour`, `minute`, `second`, `timeZoneName`, `fractionalSecondDigits`:  指定要包含在格式化输出中的日期和时间组成部分以及它们的格式（例如，"long", "short", "numeric", "2-digit"）。
    * `dateStyle`, `timeStyle`:  预定义的日期和时间格式风格（例如，"full", "long", "medium", "short"）。

3. **与 ICU 库集成:**  V8 的 `Intl.DateTimeFormat` 实现严重依赖于 [ICU (International Components for Unicode)](https://icu.unicode.org/) 库。该代码使用 ICU 提供的类和函数来执行实际的日期和时间格式化。例如，它使用了 `icu::SimpleDateFormat` 类来进行模式化的日期和时间格式化。

4. **处理时区规范化:**  代码包含用于规范化时区 ID 的逻辑，例如将 "GMT" 转换为 "UTC" 或处理 "Etc/GMT" 格式的时区。

5. **解析和应用格式化模式:**  代码内部维护了一套模式映射 (`PatternMap`, `PatternItem`)，用于将 JavaScript 的格式化选项转换为 ICU 能够理解的格式化模式字符串。

6. **提供 `resolvedOptions()` 方法的实现:**  `ResolvedOptions` 函数返回一个包含已解析和应用的格式化选项的对象。

7. **支持 Temporal API:**  代码中包含了对 [Temporal API](https://tc39.es/proposal-temporal/) 的初步支持，例如 `IsTemporalObject` 和 `SameTemporalType` 函数，用于判断对象是否是 Temporal API 的对象以及两个 Temporal 对象是否具有相同的类型。

**关于问题中的其他点:**

* **`.tq` 结尾:**  `v8/src/objects/js-date-time-format.cc` 文件以 `.cc` 结尾，表示它是一个 C++ 源代码文件，而不是 Torque 源代码文件。Torque 文件通常以 `.tq` 结尾。

* **与 JavaScript 的关系及举例:** 该文件中的 C++ 代码直接为 JavaScript 的 `Intl.DateTimeFormat` 对象提供功能支持。

   ```javascript
   // JavaScript 示例
   const formatter = new Intl.DateTimeFormat('zh-CN', {
       year: 'numeric',
       month: 'long',
       day: 'numeric',
       hour: '2-digit',
       minute: '2-digit',
       second: '2-digit',
       timeZoneName: 'short'
   });

   const date = new Date();
   const formattedDate = formatter.format(date);
   console.log(formattedDate); // 输出类似于 "2023年10月27日 10:30:45 GMT+8" 的字符串
   ```
   在这个例子中，`Intl.DateTimeFormat` 构造函数的调用会最终触发 `v8/src/objects/js-date-time-format.cc` 中的 C++ 代码来创建和配置格式化器。`formatter.format(date)` 方法的调用也会调用该文件中的代码来执行实际的格式化操作。

* **代码逻辑推理 (假设输入与输出):**

   **假设输入:**
   * `locale`: "en-US"
   * `options`: `{ month: 'short', year: 'numeric' }`
   * 要格式化的日期：一个表示 2024 年 1 月的 `Date` 对象。

   **预期输出 (大致):**
   * 格式化的字符串类似于 "Jan 2024"。

   **代码逻辑推理:**  `BuildPatternItems` 和 `GetPatternData` 等函数会根据提供的 `options` 构建 ICU 的格式化模式。对于上面的输入，模式可能类似于 "MMM yyyy"。然后，ICU 的 `SimpleDateFormat` 会使用此模式和指定的 `locale` 来格式化日期。

* **用户常见的编程错误举例:**

   ```javascript
   // 错误示例 1: 传递了不支持的 locale
   try {
       const formatter1 = new Intl.DateTimeFormat('invalid-locale', { year: 'numeric' });
   } catch (e) {
       console.error(e); // 可能抛出 RangeError
   }

   // 错误示例 2:  选项值拼写错误
   const formatter2 = new Intl.DateTimeFormat('en-US', { mont: 'short' }); // 'mont' 应该是 'month'
   const date2 = new Date();
   console.log(formatter2.format(date2)); // 'mont' 选项会被忽略，使用默认格式

   // 错误示例 3:  时区名称错误或无法识别
   const formatter3 = new Intl.DateTimeFormat('en-US', { timeZone: 'Atlantis/Somewhere' }); //  'Atlantis/Somewhere' 不是有效的时区
   const date3 = new Date();
   console.log(formatter3.format(date3)); //  时区可能回退到默认时区
   ```
   常见的错误包括：提供无效的 `locale`、选项名称拼写错误、提供无效或无法识别的时区名称等。这些错误可能导致程序抛出异常或使用默认的行为，而不是用户预期的格式。

总而言之，`v8/src/objects/js-date-time-format.cc` 是 V8 引擎中至关重要的组件，它通过与 ICU 库的紧密集成，实现了 JavaScript 中灵活且强大的国际化日期和时间格式化功能。

Prompt: 
```
这是目录为v8/src/objects/js-date-time-format.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-date-time-format.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/js-date-time-format.h"

#include <algorithm>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "src/base/bit-field.h"
#include "src/date/date.h"
#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/objects/intl-objects.h"
#include "src/objects/js-date-time-format-inl.h"
#include "src/objects/js-temporal-objects-inl.h"
#include "src/objects/managed-inl.h"
#include "src/objects/option-utils.h"
#include "unicode/calendar.h"
#include "unicode/dtitvfmt.h"
#include "unicode/dtptngen.h"
#include "unicode/fieldpos.h"
#include "unicode/gregocal.h"
#include "unicode/smpdtfmt.h"
#include "unicode/unistr.h"

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

namespace v8::internal {

namespace {

std::string ToHourCycleString(JSDateTimeFormat::HourCycle hc) {
  switch (hc) {
    case JSDateTimeFormat::HourCycle::kH11:
      return "h11";
    case JSDateTimeFormat::HourCycle::kH12:
      return "h12";
    case JSDateTimeFormat::HourCycle::kH23:
      return "h23";
    case JSDateTimeFormat::HourCycle::kH24:
      return "h24";
    case JSDateTimeFormat::HourCycle::kUndefined:
      return "";
    default:
      UNREACHABLE();
  }
}

JSDateTimeFormat::HourCycle ToHourCycle(const std::string& hc) {
  if (hc == "h11") return JSDateTimeFormat::HourCycle::kH11;
  if (hc == "h12") return JSDateTimeFormat::HourCycle::kH12;
  if (hc == "h23") return JSDateTimeFormat::HourCycle::kH23;
  if (hc == "h24") return JSDateTimeFormat::HourCycle::kH24;
  return JSDateTimeFormat::HourCycle::kUndefined;
}

JSDateTimeFormat::HourCycle ToHourCycle(UDateFormatHourCycle hc) {
  switch (hc) {
    case UDAT_HOUR_CYCLE_11:
      return JSDateTimeFormat::HourCycle::kH11;
    case UDAT_HOUR_CYCLE_12:
      return JSDateTimeFormat::HourCycle::kH12;
    case UDAT_HOUR_CYCLE_23:
      return JSDateTimeFormat::HourCycle::kH23;
    case UDAT_HOUR_CYCLE_24:
      return JSDateTimeFormat::HourCycle::kH24;
    default:
      return JSDateTimeFormat::HourCycle::kUndefined;
  }
}

// The following two functions are hack until we add necessary API to ICU
// to get default hour cycle for 12 hours system (h11 or h12) or 24 hours system
// (h23 or h24).
// From timeData in third_party/icu/source/data/misc/supplementalData.txt
// we know the preferred values are either h or H.
// And all allowed values are also h or H except in JP K (h11) is listed before
// h (h12).
JSDateTimeFormat::HourCycle DefaultHourCycle12(
    const icu::Locale& locale, JSDateTimeFormat::HourCycle defaultHourCycle) {
  if (defaultHourCycle == JSDateTimeFormat::HourCycle::kH11 ||
      defaultHourCycle == JSDateTimeFormat::HourCycle::kH12) {
    return defaultHourCycle;
  }
  if (std::strcmp(locale.getCountry(), "JP") == 0) {
    return JSDateTimeFormat::HourCycle::kH11;
  }
  return JSDateTimeFormat::HourCycle::kH12;
}

JSDateTimeFormat::HourCycle DefaultHourCycle24(
    const icu::Locale& locale, JSDateTimeFormat::HourCycle defaultHourCycle) {
  if (defaultHourCycle == JSDateTimeFormat::HourCycle::kH23 ||
      defaultHourCycle == JSDateTimeFormat::HourCycle::kH24) {
    return defaultHourCycle;
  }
  return JSDateTimeFormat::HourCycle::kH23;
}

Maybe<JSDateTimeFormat::HourCycle> GetHourCycle(Isolate* isolate,
                                                Handle<JSReceiver> options,
                                                const char* method_name) {
  return GetStringOption<JSDateTimeFormat::HourCycle>(
      isolate, options, "hourCycle", method_name, {"h11", "h12", "h23", "h24"},
      {JSDateTimeFormat::HourCycle::kH11, JSDateTimeFormat::HourCycle::kH12,
       JSDateTimeFormat::HourCycle::kH23, JSDateTimeFormat::HourCycle::kH24},
      JSDateTimeFormat::HourCycle::kUndefined);
}

class PatternMap {
 public:
  PatternMap(std::string pattern, std::string value)
      : pattern(std::move(pattern)), value(std::move(value)) {}
  virtual ~PatternMap() = default;
  std::string pattern;
  std::string value;
};

#define BIT_FIELDS(V, _)      \
  V(Era, bool, 1, _)          \
  V(Year, bool, 1, _)         \
  V(Month, bool, 1, _)        \
  V(Weekday, bool, 1, _)      \
  V(Day, bool, 1, _)          \
  V(DayPeriod, bool, 1, _)    \
  V(Hour, bool, 1, _)         \
  V(Minute, bool, 1, _)       \
  V(Second, bool, 1, _)       \
  V(TimeZoneName, bool, 1, _) \
  V(FractionalSecondDigits, bool, 1, _)
DEFINE_BIT_FIELDS(BIT_FIELDS)
#undef BIT_FIELDS

class PatternItem {
 public:
  PatternItem(int32_t shift, const std::string property,
              std::vector<PatternMap> pairs,
              std::vector<const char*> allowed_values)
      : bitShift(shift),
        property(std::move(property)),
        pairs(std::move(pairs)),
        allowed_values(allowed_values) {}
  virtual ~PatternItem() = default;

  int32_t bitShift;
  const std::string property;
  // It is important for the pattern in the pairs from longer one to shorter one
  // if the longer one contains substring of an shorter one.
  std::vector<PatternMap> pairs;
  std::vector<const char*> allowed_values;
};

static std::vector<PatternItem> BuildPatternItems() {
  const std::vector<const char*> kLongShort = {"long", "short"};
  const std::vector<const char*> kNarrowLongShort = {"narrow", "long", "short"};
  const std::vector<const char*> k2DigitNumeric = {"2-digit", "numeric"};
  const std::vector<const char*> kNarrowLongShort2DigitNumeric = {
      "narrow", "long", "short", "2-digit", "numeric"};
  std::vector<PatternItem> items = {
      PatternItem(Weekday::kShift, "weekday",
                  {{"EEEEE", "narrow"},
                   {"EEEE", "long"},
                   {"EEE", "short"},
                   {"ccccc", "narrow"},
                   {"cccc", "long"},
                   {"ccc", "short"}},
                  kNarrowLongShort),
      PatternItem(Era::kShift, "era",
                  {{"GGGGG", "narrow"}, {"GGGG", "long"}, {"GGG", "short"}},
                  kNarrowLongShort),
      PatternItem(Year::kShift, "year", {{"yy", "2-digit"}, {"y", "numeric"}},
                  k2DigitNumeric)};
  // Sometimes we get L instead of M for month - standalone name.
  items.push_back(PatternItem(Month::kShift, "month",
                              {{"MMMMM", "narrow"},
                               {"MMMM", "long"},
                               {"MMM", "short"},
                               {"MM", "2-digit"},
                               {"M", "numeric"},
                               {"LLLLL", "narrow"},
                               {"LLLL", "long"},
                               {"LLL", "short"},
                               {"LL", "2-digit"},
                               {"L", "numeric"}},
                              kNarrowLongShort2DigitNumeric));
  items.push_back(PatternItem(Day::kShift, "day",
                              {{"dd", "2-digit"}, {"d", "numeric"}},
                              k2DigitNumeric));
  items.push_back(PatternItem(DayPeriod::kShift, "dayPeriod",
                              {{"BBBBB", "narrow"},
                               {"bbbbb", "narrow"},
                               {"BBBB", "long"},
                               {"bbbb", "long"},
                               {"B", "short"},
                               {"b", "short"}},
                              kNarrowLongShort));
  items.push_back(PatternItem(Hour::kShift, "hour",
                              {{"HH", "2-digit"},
                               {"H", "numeric"},
                               {"hh", "2-digit"},
                               {"h", "numeric"},
                               {"kk", "2-digit"},
                               {"k", "numeric"},
                               {"KK", "2-digit"},
                               {"K", "numeric"}},
                              k2DigitNumeric));
  items.push_back(PatternItem(Minute::kShift, "minute",
                              {{"mm", "2-digit"}, {"m", "numeric"}},
                              k2DigitNumeric));
  items.push_back(PatternItem(Second::kShift, "second",
                              {{"ss", "2-digit"}, {"s", "numeric"}},
                              k2DigitNumeric));

  const std::vector<const char*> kTimezone = {"long",        "short",
                                              "longOffset",  "shortOffset",
                                              "longGeneric", "shortGeneric"};
  items.push_back(PatternItem(TimeZoneName::kShift, "timeZoneName",
                              {{"zzzz", "long"},
                               {"z", "short"},
                               {"OOOO", "longOffset"},
                               {"O", "shortOffset"},
                               {"vvvv", "longGeneric"},
                               {"v", "shortGeneric"}},
                              kTimezone));
  return items;
}

class PatternItems {
 public:
  PatternItems() : data(BuildPatternItems()) {}
  virtual ~PatternItems() = default;
  const std::vector<PatternItem>& Get() const { return data; }

 private:
  const std::vector<PatternItem> data;
};

static const std::vector<PatternItem>& GetPatternItems() {
  static base::LazyInstance<PatternItems>::type items =
      LAZY_INSTANCE_INITIALIZER;
  return items.Pointer()->Get();
}

class PatternData {
 public:
  PatternData(int32_t shift, const std::string property,
              std::vector<PatternMap> pairs,
              std::vector<const char*> allowed_values)
      : bitShift(shift),
        property(std::move(property)),
        allowed_values(allowed_values) {
    for (const auto& pair : pairs) {
      map.insert(std::make_pair(pair.value, pair.pattern));
    }
  }
  virtual ~PatternData() = default;

  int32_t bitShift;
  const std::string property;
  std::map<const std::string, const std::string> map;
  std::vector<const char*> allowed_values;
};

const std::vector<PatternData> CreateCommonData(const PatternData& hour_data) {
  std::vector<PatternData> build;
  for (const PatternItem& item : GetPatternItems()) {
    if (item.property == "hour") {
      build.push_back(hour_data);
    } else {
      build.push_back(PatternData(item.bitShift, item.property, item.pairs,
                                  item.allowed_values));
    }
  }
  return build;
}

const std::vector<PatternData> CreateData(const char* digit2,
                                          const char* numeric) {
  return CreateCommonData(PatternData(
      Hour::kShift, "hour", {{digit2, "2-digit"}, {numeric, "numeric"}},
      {"2-digit", "numeric"}));
}

// According to "Date Field Symbol Table" in
// http://userguide.icu-project.org/formatparse/datetime
// Symbol | Meaning              | Example(s)
//   h      hour in am/pm (1~12)    h    7
//                                  hh   07
//   H      hour in day (0~23)      H    0
//                                  HH   00
//   k      hour in day (1~24)      k    24
//                                  kk   24
//   K      hour in am/pm (0~11)    K    0
//                                  KK   00

class Pattern {
 public:
  Pattern(const char* d1, const char* d2) : data(CreateData(d1, d2)) {}
  virtual ~Pattern() = default;
  virtual const std::vector<PatternData>& Get() const { return data; }

 private:
  std::vector<PatternData> data;
};

#define DEFFINE_TRAIT(name, d1, d2)              \
  struct name {                                  \
    static void Construct(void* allocated_ptr) { \
      new (allocated_ptr) Pattern(d1, d2);       \
    }                                            \
  };
DEFFINE_TRAIT(H11Trait, "KK", "K")
DEFFINE_TRAIT(H12Trait, "hh", "h")
DEFFINE_TRAIT(H23Trait, "HH", "H")
DEFFINE_TRAIT(H24Trait, "kk", "k")
DEFFINE_TRAIT(HDefaultTrait, "jj", "j")
#undef DEFFINE_TRAIT

const std::vector<PatternData>& GetPatternData(
    JSDateTimeFormat::HourCycle hour_cycle) {
  switch (hour_cycle) {
    case JSDateTimeFormat::HourCycle::kH11: {
      static base::LazyInstance<Pattern, H11Trait>::type h11 =
          LAZY_INSTANCE_INITIALIZER;
      return h11.Pointer()->Get();
    }
    case JSDateTimeFormat::HourCycle::kH12: {
      static base::LazyInstance<Pattern, H12Trait>::type h12 =
          LAZY_INSTANCE_INITIALIZER;
      return h12.Pointer()->Get();
    }
    case JSDateTimeFormat::HourCycle::kH23: {
      static base::LazyInstance<Pattern, H23Trait>::type h23 =
          LAZY_INSTANCE_INITIALIZER;
      return h23.Pointer()->Get();
    }
    case JSDateTimeFormat::HourCycle::kH24: {
      static base::LazyInstance<Pattern, H24Trait>::type h24 =
          LAZY_INSTANCE_INITIALIZER;
      return h24.Pointer()->Get();
    }
    case JSDateTimeFormat::HourCycle::kUndefined: {
      static base::LazyInstance<Pattern, HDefaultTrait>::type hDefault =
          LAZY_INSTANCE_INITIALIZER;
      return hDefault.Pointer()->Get();
    }
    default:
      UNREACHABLE();
  }
}

std::string GetGMTTzID(const std::string& input) {
  std::string ret = "Etc/GMT";
  switch (input.length()) {
    case 8:
      if (input[7] == '0') return ret + '0';
      break;
    case 9:
      if ((input[7] == '+' || input[7] == '-') &&
          base::IsInRange(input[8], '0', '9')) {
        return ret + input[7] + input[8];
      }
      break;
    case 10:
      if ((input[7] == '+' || input[7] == '-') && (input[8] == '1') &&
          base::IsInRange(input[9], '0', '4')) {
        return ret + input[7] + input[8] + input[9];
      }
      break;
  }
  return "";
}

// Locale independenty version of isalpha for ascii range. This will return
// false if the ch is alpha but not in ascii range.
bool IsAsciiAlpha(char ch) {
  return base::IsInRange(ch, 'A', 'Z') || base::IsInRange(ch, 'a', 'z');
}

// Locale independent toupper for ascii range. This will not return İ (dotted I)
// for i under Turkish locale while std::toupper may.
char LocaleIndependentAsciiToUpper(char ch) {
  return (base::IsInRange(ch, 'a', 'z')) ? (ch - 'a' + 'A') : ch;
}

// Locale independent tolower for ascii range.
char LocaleIndependentAsciiToLower(char ch) {
  return (base::IsInRange(ch, 'A', 'Z')) ? (ch - 'A' + 'a') : ch;
}

// Returns titlecased location, bueNos_airES -> Buenos_Aires
// or ho_cHi_minH -> Ho_Chi_Minh. It is locale-agnostic and only
// deals with ASCII only characters.
// 'of', 'au' and 'es' are special-cased and lowercased.
// ICU's timezone parsing is case sensitive, but ECMAScript is case insensitive
std::string ToTitleCaseTimezoneLocation(const std::string& input) {
  std::string title_cased;
  int word_length = 0;
  for (char ch : input) {
    // Convert first char to upper case, the rest to lower case
    if (IsAsciiAlpha(ch)) {
      title_cased += word_length == 0 ? LocaleIndependentAsciiToUpper(ch)
                                      : LocaleIndependentAsciiToLower(ch);
      word_length++;
    } else if (ch == '_' || ch == '-' || ch == '/') {
      // Special case Au/Es/Of to be lower case.
      if (word_length == 2) {
        size_t pos = title_cased.length() - 2;
        std::string substr = title_cased.substr(pos, 2);
        if (substr == "Of" || substr == "Es" || substr == "Au") {
          title_cased[pos] = LocaleIndependentAsciiToLower(title_cased[pos]);
        }
      }
      title_cased += ch;
      word_length = 0;
    } else {
      // Invalid input
      return std::string();
    }
  }

  return title_cased;
}

class SpecialTimeZoneMap {
 public:
  SpecialTimeZoneMap() {
    Add("America/Argentina/ComodRivadavia");
    Add("America/Knox_IN");
    Add("Antarctica/DumontDUrville");
    Add("Antarctica/McMurdo");
    Add("Australia/ACT");
    Add("Australia/LHI");
    Add("Australia/NSW");
    Add("Brazil/DeNoronha");
    Add("Chile/EasterIsland");
    Add("GB");
    Add("GB-Eire");
    Add("Mexico/BajaNorte");
    Add("Mexico/BajaSur");
    Add("NZ");
    Add("NZ-CHAT");
    Add("W-SU");
  }

  std::string Find(const std::string& id) {
    auto it = map_.find(id);
    if (it != map_.end()) {
      return it->second;
    }
    return "";
  }

 private:
  void Add(const char* id) {
    std::string upper(id);
    transform(upper.begin(), upper.end(), upper.begin(),
              LocaleIndependentAsciiToUpper);
    map_.insert({upper, id});
  }
  std::map<std::string, std::string> map_;
};

}  // namespace

// Return the time zone id which match ICU's expectation of title casing
// return empty string when error.
std::string JSDateTimeFormat::CanonicalizeTimeZoneID(const std::string& input) {
  std::string upper = input;
  transform(upper.begin(), upper.end(), upper.begin(),
            LocaleIndependentAsciiToUpper);
  if (upper.length() == 3) {
    if (upper == "GMT") return "UTC";
    // For id such as "CET", return upper case.
    return upper;
  } else if (upper.length() == 7 && '0' <= upper[3] && upper[3] <= '9') {
    // For id such as "CST6CDT", return upper case.
    return upper;
  } else if (upper.length() > 3) {
    if (memcmp(upper.c_str(), "ETC", 3) == 0) {
      if (upper == "ETC/UTC" || upper == "ETC/GMT" || upper == "ETC/UCT") {
        return "UTC";
      }
      if (strncmp(upper.c_str(), "ETC/GMT", 7) == 0) {
        return GetGMTTzID(input);
      }
    } else if (memcmp(upper.c_str(), "GMT", 3) == 0) {
      if (upper == "GMT0" || upper == "GMT+0" || upper == "GMT-0") {
        return "UTC";
      }
    } else if (memcmp(upper.c_str(), "US/", 3) == 0) {
      std::string title = ToTitleCaseTimezoneLocation(input);
      if (title.length() >= 2) {
        // Change "Us/" to "US/"
        title[1] = 'S';
      }
      return title;
    } else if (strncmp(upper.c_str(), "SYSTEMV/", 8) == 0) {
      upper.replace(0, 8, "SystemV/");
      return upper;
    }
  }
  // We expect only _, '-' and / beside ASCII letters.

  static base::LazyInstance<SpecialTimeZoneMap>::type special_time_zone_map =
      LAZY_INSTANCE_INITIALIZER;

  std::string special_case = special_time_zone_map.Pointer()->Find(upper);
  if (!special_case.empty()) {
    return special_case;
  }
  return ToTitleCaseTimezoneLocation(input);
}

namespace {
Handle<String> DateTimeStyleAsString(Isolate* isolate,
                                     JSDateTimeFormat::DateTimeStyle style) {
  switch (style) {
    case JSDateTimeFormat::DateTimeStyle::kFull:
      return ReadOnlyRoots(isolate).full_string_handle();
    case JSDateTimeFormat::DateTimeStyle::kLong:
      return ReadOnlyRoots(isolate).long_string_handle();
    case JSDateTimeFormat::DateTimeStyle::kMedium:
      return ReadOnlyRoots(isolate).medium_string_handle();
    case JSDateTimeFormat::DateTimeStyle::kShort:
      return ReadOnlyRoots(isolate).short_string_handle();
    case JSDateTimeFormat::DateTimeStyle::kUndefined:
      UNREACHABLE();
  }
  UNREACHABLE();
}

int FractionalSecondDigitsFromPattern(const std::string& pattern) {
  int result = 0;
  for (size_t i = 0; i < pattern.length() && result < 3; i++) {
    if (pattern[i] == 'S') {
      result++;
    }
  }
  return result;
}
}  // namespace

MaybeHandle<String> JSDateTimeFormat::TimeZoneIdToString(
    Isolate* isolate, const icu::UnicodeString& id) {
  // In CLDR (http://unicode.org/cldr/trac/ticket/9943), Etc/UTC is made
  // a separate timezone ID from Etc/GMT even though they're still the same
  // timezone. We have Etc/UTC because 'UTC', 'Etc/Universal',
  // 'Etc/Zulu' and others are turned to 'Etc/UTC' by ICU. Etc/GMT comes
  // from Etc/GMT0, Etc/GMT+0, Etc/GMT-0, Etc/Greenwich.
  // ecma402#sec-canonicalizetimezonename step 3
  if (id == UNICODE_STRING_SIMPLE("Etc/UTC") ||
      id == UNICODE_STRING_SIMPLE("Etc/GMT")) {
    return isolate->factory()->UTC_string();
  }
  // If the id is in the format of GMT[+-]hh:mm, change it to
  // [+-]hh:mm.
  if (id.startsWith(u"GMT", 3)) {
    return Intl::ToString(isolate, id.tempSubString(3));
  }
  return Intl::ToString(isolate, id);
}

Handle<Object> JSDateTimeFormat::TimeZoneId(Isolate* isolate,
                                            const icu::TimeZone& tz) {
  Factory* factory = isolate->factory();
  icu::UnicodeString time_zone;
  tz.getID(time_zone);
  icu::UnicodeString canonical_time_zone;
  if (time_zone == u"GMT") {
    canonical_time_zone = u"+00:00";
  } else {
    UErrorCode status = U_ZERO_ERROR;
    icu::TimeZone::getCanonicalID(time_zone, canonical_time_zone, status);
    if (U_FAILURE(status)) {
      // When the time_zone is neither a known system time zone ID nor a
      // valid custom time zone ID, the status is a failure.
      return factory->undefined_value();
    }
  }
  Handle<String> timezone_value;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, timezone_value, TimeZoneIdToString(isolate, canonical_time_zone),
      Handle<Object>());
  return timezone_value;
}

namespace {
Handle<String> GetCalendar(Isolate* isolate,
                           const icu::SimpleDateFormat& simple_date_format) {
  // getType() returns legacy calendar type name instead of LDML/BCP47 calendar
  // key values. intl.js maps them to BCP47 values for key "ca".
  // TODO(jshin): Consider doing it here, instead.
  std::string calendar_str = simple_date_format.getCalendar()->getType();

  // Maps ICU calendar names to LDML/BCP47 types for key 'ca'.
  // See typeMap section in third_party/icu/source/data/misc/keyTypeData.txt
  // and
  // http://www.unicode.org/repos/cldr/tags/latest/common/bcp47/calendar.xml
  if (calendar_str == "gregorian") {
    calendar_str = "gregory";
  } else if (calendar_str == "ethiopic-amete-alem") {
    calendar_str = "ethioaa";
  }
  return isolate->factory()->NewStringFromAsciiChecked(calendar_str.c_str());
}

Handle<Object> GetTimeZone(Isolate* isolate,
                           const icu::SimpleDateFormat& simple_date_format) {
  return JSDateTimeFormat::TimeZoneId(
      isolate, simple_date_format.getCalendar()->getTimeZone());
}
}  // namespace

Handle<String> JSDateTimeFormat::Calendar(
    Isolate* isolate, DirectHandle<JSDateTimeFormat> date_time_format) {
  return GetCalendar(isolate,
                     *(date_time_format->icu_simple_date_format()->raw()));
}

Handle<Object> JSDateTimeFormat::TimeZone(
    Isolate* isolate, DirectHandle<JSDateTimeFormat> date_time_format) {
  return GetTimeZone(isolate,
                     *(date_time_format->icu_simple_date_format()->raw()));
}

// ecma402 #sec-intl.datetimeformat.prototype.resolvedoptions
MaybeHandle<JSObject> JSDateTimeFormat::ResolvedOptions(
    Isolate* isolate, DirectHandle<JSDateTimeFormat> date_time_format) {
  Factory* factory = isolate->factory();
  // 4. Let options be ! ObjectCreate(%ObjectPrototype%).
  Handle<JSObject> options = factory->NewJSObject(isolate->object_function());

  DirectHandle<Object> resolved_obj;

  Handle<String> locale(date_time_format->locale(), isolate);
  DCHECK(!date_time_format->icu_locale().is_null());
  DCHECK_NOT_NULL(date_time_format->icu_locale()->raw());
  icu::Locale* icu_locale = date_time_format->icu_locale()->raw();

  icu::SimpleDateFormat* icu_simple_date_format =
      date_time_format->icu_simple_date_format()->raw();
  Handle<Object> timezone =
      JSDateTimeFormat::TimeZone(isolate, date_time_format);

  // Ugly hack. ICU doesn't expose numbering system in any way, so we have
  // to assume that for given locale NumberingSystem constructor produces the
  // same digits as NumberFormat/Calendar would.
  // Tracked by https://unicode-org.atlassian.net/browse/ICU-13431
  std::string numbering_system = Intl::GetNumberingSystem(*icu_locale);

  icu::UnicodeString pattern_unicode;
  icu_simple_date_format->toPattern(pattern_unicode);
  std::string pattern;
  pattern_unicode.toUTF8String(pattern);

  // 5. For each row of Table 6, except the header row, in table order, do
  // Table 6: Resolved Options of DateTimeFormat Instances
  //  Internal Slot          Property
  //    [[Locale]]           "locale"
  //    [[Calendar]]         "calendar"
  //    [[NumberingSystem]]  "numberingSystem"
  //    [[TimeZone]]         "timeZone"
  //    [[HourCycle]]        "hourCycle"
  //                         "hour12"
  //    [[Weekday]]          "weekday"
  //    [[Era]]              "era"
  //    [[Year]]             "year"
  //    [[Month]]            "month"
  //    [[Day]]              "day"
  //    [[Hour]]             "hour"
  //    [[Minute]]           "minute"
  //    [[Second]]           "second"
  //    [[FractionalSecondDigits]]     "fractionalSecondDigits"
  //    [[TimeZoneName]]     "timeZoneName"
  Maybe<bool> maybe_create_locale = JSReceiver::CreateDataProperty(
      isolate, options, factory->locale_string(), locale, Just(kDontThrow));
  DCHECK(maybe_create_locale.FromJust());
  USE(maybe_create_locale);

  Handle<String> calendar =
      JSDateTimeFormat::Calendar(isolate, date_time_format);
  Maybe<bool> maybe_create_calendar = JSReceiver::CreateDataProperty(
      isolate, options, factory->calendar_string(), calendar, Just(kDontThrow));
  DCHECK(maybe_create_calendar.FromJust());
  USE(maybe_create_calendar);

  if (!numbering_system.empty()) {
    Maybe<bool> maybe_create_numbering_system = JSReceiver::CreateDataProperty(
        isolate, options, factory->numberingSystem_string(),
        factory->NewStringFromAsciiChecked(numbering_system.c_str()),
        Just(kDontThrow));
    DCHECK(maybe_create_numbering_system.FromJust());
    USE(maybe_create_numbering_system);
  }
  Maybe<bool> maybe_create_time_zone = JSReceiver::CreateDataProperty(
      isolate, options, factory->timeZone_string(), timezone, Just(kDontThrow));
  DCHECK(maybe_create_time_zone.FromJust());
  USE(maybe_create_time_zone);

  // 5.b.i. Let hc be dtf.[[HourCycle]].
  HourCycle hc = date_time_format->hour_cycle();

  if (hc != HourCycle::kUndefined) {
    Maybe<bool> maybe_create_hour_cycle = JSReceiver::CreateDataProperty(
        isolate, options, factory->hourCycle_string(),
        date_time_format->HourCycleAsString(), Just(kDontThrow));
    DCHECK(maybe_create_hour_cycle.FromJust());
    USE(maybe_create_hour_cycle);
    switch (hc) {
      //  ii. If hc is "h11" or "h12", let v be true.
      case HourCycle::kH11:
      case HourCycle::kH12: {
        Maybe<bool> maybe_create_hour12 = JSReceiver::CreateDataProperty(
            isolate, options, factory->hour12_string(), factory->true_value(),
            Just(kDontThrow));
        DCHECK(maybe_create_hour12.FromJust());
        USE(maybe_create_hour12);
      } break;
      // iii. Else if, hc is "h23" or "h24", let v be false.
      case HourCycle::kH23:
      case HourCycle::kH24: {
        Maybe<bool> maybe_create_hour12 = JSReceiver::CreateDataProperty(
            isolate, options, factory->hour12_string(), factory->false_value(),
            Just(kDontThrow));
        DCHECK(maybe_create_hour12.FromJust());
        USE(maybe_create_hour12);
      } break;
      // iv. Else, let v be undefined.
      case HourCycle::kUndefined:
        break;
    }
  }

  // If dateStyle and timeStyle are undefined, then internal slots
  // listed in "Table 1: Components of date and time formats" will be set
  // in Step 33.f.iii.1 of InitializeDateTimeFormat
  if (date_time_format->date_style() == DateTimeStyle::kUndefined &&
      date_time_format->time_style() == DateTimeStyle::kUndefined) {
    for (const auto& item : GetPatternItems()) {
      // fractionalSecondsDigits need to be added before timeZoneName
      if (item.property == "timeZoneName") {
        int fsd = FractionalSecondDigitsFromPattern(pattern);
        if (fsd > 0) {
          Maybe<bool> maybe_create_fractional_seconds_digits =
              JSReceiver::CreateDataProperty(
                  isolate, options, factory->fractionalSecondDigits_string(),
                  factory->NewNumberFromInt(fsd), Just(kDontThrow));
          DCHECK(maybe_create_fractional_seconds_digits.FromJust());
          USE(maybe_create_fractional_seconds_digits);
        }
      }
      for (const auto& pair : item.pairs) {
        if (pattern.find(pair.pattern) != std::string::npos) {
          Maybe<bool> maybe_create_property = JSReceiver::CreateDataProperty(
              isolate, options,
              factory->NewStringFromAsciiChecked(item.property.c_str()),
              factory->NewStringFromAsciiChecked(pair.value.c_str()),
              Just(kDontThrow));
          DCHECK(maybe_create_property.FromJust());
          USE(maybe_create_property);
          break;
        }
      }
    }
  }

  // dateStyle
  if (date_time_format->date_style() != DateTimeStyle::kUndefined) {
    Maybe<bool> maybe_create_date_style = JSReceiver::CreateDataProperty(
        isolate, options, factory->dateStyle_string(),
        DateTimeStyleAsString(isolate, date_time_format->date_style()),
        Just(kDontThrow));
    DCHECK(maybe_create_date_style.FromJust());
    USE(maybe_create_date_style);
  }

  // timeStyle
  if (date_time_format->time_style() != DateTimeStyle::kUndefined) {
    Maybe<bool> maybe_create_time_style = JSReceiver::CreateDataProperty(
        isolate, options, factory->timeStyle_string(),
        DateTimeStyleAsString(isolate, date_time_format->time_style()),
        Just(kDontThrow));
    DCHECK(maybe_create_time_style.FromJust());
    USE(maybe_create_time_style);
  }
  return options;
}

namespace {

// #sec-temporal-istemporalobject
bool IsTemporalObject(DirectHandle<Object> value) {
  // 1. If Type(value) is not Object, then
  if (!IsJSReceiver(*value)) {
    // a. Return false.
    return false;
  }
  // 2. If value does not have an [[InitializedTemporalDate]],
  // [[InitializedTemporalTime]], [[InitializedTemporalDateTime]],
  // [[InitializedTemporalZonedDateTime]], [[InitializedTemporalYearMonth]],
  // [[InitializedTemporalMonthDay]], or [[InitializedTemporalInstant]] internal
  // slot, then
  if (!IsJSTemporalPlainDate(*value) && !IsJSTemporalPlainTime(*value) &&
      !IsJSTemporalPlainDateTime(*value) &&
      !IsJSTemporalZonedDateTime(*value) &&
      !IsJSTemporalPlainYearMonth(*value) &&
      !IsJSTemporalPlainMonthDay(*value) && !IsJSTemporalInstant(*value)) {
    // a. Return false.
    return false;
  }
  // 3. Return true.
  return true;
}

// #sec-temporal-sametemporaltype
bool SameTemporalType(DirectHandle<Object> x, DirectHandle<Object> y) {
  // 1. If either of ! IsTemporalObject(x) or ! IsTemporalObject(y) is false,
  // return false.
  if (!IsTemporalObject(x)) return false;
  if (!IsTemporalObject(y)) return false;
  // 2. If x has an [[InitializedTemporalDate]] internal slot and y does not,
  // return false.
  if (IsJSTemporalPlainDate(*x) && !IsJSTemporalPlainDate(*y)) return false;
  // 3. If x has an [[InitializedTemporalTime]] internal slot and y does not,
  // return false.
  if (IsJSTemporalPlainTime(*x) && !IsJSTemporalPlainTime(*y)) return false;
  // 4. If x has an [[InitializedTemporalDateTime]] internal slot and y does
  // not, return false.
  if (IsJSTemporalPlainDateTime(*x) && !IsJSTemporalPlainDateTime(*y)) {
    return false;
  }
  // 5. If x has an [[InitializedTemporalZonedDateTime]] internal slot and y
  // does not, return false.
  if (IsJSTemporalZonedDateTime(*x) && !IsJSTemporalZonedDateTime(*y)) {
    return false;
  }
  // 6. If x has an [[InitializedTemporalYearMonth]] internal slot and y does
  // not, return false.
  if (IsJSTemporalPlainYearMonth(*x) && !IsJSTemporalPlainYearMonth(*y)) {
    return false;
  }
  // 7. If x has an [[InitializedTemporalMonthDay]] internal slot and y does
  // not, return false.
  if (IsJSTemporalPlainMonthDay(*x) && !IsJSTemporalPlainMonthDay(*y)) {
    return false;
  }
  // 8. If x has an [[InitializedTemporalInstant]] internal slot and y does not,
  // return false.
  if (IsJSTemporalInstant(*x) && !IsJSTemporalInstant(*y)) return false;
  // 9. Return true.
  return true;
}

enum class PatternKind {
  kDate,
  kPlainDate,
  kPlainDateTime,
  kPlainTime,
  kPlainYearMonth,
  kPlainMonthDay,
  kZonedDateTime,
  kInstant,
};
struct DateTimeValueRecord {
  double epoch_milliseconds;
  PatternKind kind;
};

DateTimeValueRecord TemporalInstantToRecord(
    Isolate* isolate, DirectHandle<JSTemporalInstant> instant,
    PatternKind kind) {
  double milliseconds =
      BigInt::Divide(isolate, Handle<BigInt>(instant->nanoseconds(), isolate),
                     BigInt::FromInt64(isolate, 1000000))
          .ToHandleChecked()
          ->AsInt64();
  return {milliseconds, kind};
}

Maybe<DateTimeValueRecord> TemporalPlainDateTimeToRecord(
    Isolate* isolate, const icu::SimpleDateFormat& date_time_format,
    PatternKind kind, Handle<JSTemporalPlainDateTime> plain_date_t
"""


```