Response: The user wants to understand the functionality of the C++ code in `v8/src/objects/js-date-time-format.cc`.
I need to:
1. **Summarize the code's purpose.**  It seems related to formatting and parsing dates and times, likely integrating with the JavaScript `Intl.DateTimeFormat` API.
2. **Illustrate the connection to JavaScript with an example.**  This will involve showing how a JavaScript `Intl.DateTimeFormat` call might utilize the functionality implemented in this C++ file.

Based on the includes and the code structure, here's a breakdown of the functionality:

- **Core Functionality:**  This file seems to be the core implementation for the `Intl.DateTimeFormat` JavaScript API within the V8 engine. It bridges the gap between JavaScript's date/time formatting needs and the powerful ICU (International Components for Unicode) library.
- **ICU Integration:** The code heavily relies on ICU for the actual formatting and parsing logic. It includes headers like `unicode/calendar.h`, `unicode/dtitvfmt.h`, `unicode/smpdtfmt.h`, etc., which are part of the ICU library.
- **Option Handling:**  It handles the various options provided to `Intl.DateTimeFormat` in JavaScript, such as `locale`, `timeZone`, `calendar`, and the different format components like `year`, `month`, `day`, `hour`, `minute`, `second`, etc.
- **Hour Cycle Handling:**  The code specifically manages the `hourCycle` option (`h11`, `h12`, `h23`, `h24`).
- **Pattern Mapping:** It uses pattern mapping to translate the format options into ICU date/time patterns.
- **Time Zone Canonicalization:**  It includes logic for canonicalizing time zone IDs.
- **Resolved Options:**  The `ResolvedOptions` function likely returns the finalized formatting options based on the provided input and locale.
- **Temporal API Integration:** The presence of includes like `src/objects/js-temporal-objects-inl.h` and code related to `IsTemporalObject` suggests integration with the JavaScript Temporal API (for more modern date/time handling).
- **Formatting Logic:**  The `FormatDateTime` function is a key part, taking a date/time value and applying the formatting rules.
- **Caching:** There's evidence of caching `icu::SimpleDateFormat` objects for performance.
这个C++源代码文件 `v8/src/objects/js-date-time-format.cc` 的主要功能是**实现了 JavaScript 中 `Intl.DateTimeFormat` 对象的底层逻辑**。 它负责处理日期和时间的格式化和解析，并与 ICU (International Components for Unicode) 库进行交互，以提供国际化的日期和时间格式化功能。

具体来说，这个文件的功能包括：

1. **处理 `Intl.DateTimeFormat` 的构造函数参数:** 它接收 `locales` 和 `options` 参数，并根据这些参数初始化日期和时间格式化器。
2. **管理日期和时间格式化选项:** 它解析和存储用户提供的各种格式化选项，例如 `locale` (区域设置)、`timeZone` (时区)、`calendar` (日历类型)、`hourCycle` (小时周期)、`weekday` (星期几的显示方式)、`year` (年份的显示方式)、`month` (月份的显示方式)、`day` (日期的显示方式)、`hour` (小时的显示方式)、`minute` (分钟的显示方式)、`second` (秒钟的显示方式) 等等。
3. **与 ICU 库交互:** 它使用 ICU 库来完成实际的日期和时间格式化工作。它将 JavaScript 提供的选项转换为 ICU 可以理解的格式，并调用 ICU 的 API 来生成格式化后的日期和时间字符串。
4. **处理 `resolvedOptions()` 方法:** 它实现了 `resolvedOptions()` 方法，该方法返回一个包含当前日期和时间格式化器所使用的最终选项的对象。
5. **实现 `format()` 方法:** 它实现了 `format()` 方法，该方法接收一个 `Date` 对象或者一个表示时间戳的数字，并返回一个根据当前格式化器的选项格式化后的日期和时间字符串。
6. **支持 Temporal API:** 从代码中可以看出，它还包含了对 JavaScript Temporal API 的集成，这是一种新的、更现代的日期和时间 API。
7. **时区处理:** 它包含用于规范化和处理时区 ID 的逻辑。
8. **缓存机制:** 它可能包含一些缓存机制，以提高重复使用相同配置的 `Intl.DateTimeFormat` 对象的性能。

**它与 JavaScript 的功能的关系可以用以下 JavaScript 例子说明:**

```javascript
// 创建一个 Intl.DateTimeFormat 对象，指定语言环境和一些选项
const formatter = new Intl.DateTimeFormat('zh-CN', {
  year: 'numeric',
  month: 'long',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  timeZone: 'Asia/Shanghai',
  hourCycle: 'h24'
});

// 创建一个 Date 对象
const date = new Date();

// 使用 format() 方法格式化日期
const formattedDate = formatter.format(date);

console.log(formattedDate); // 输出类似于 "2023年10月27日 10:30:45" 的字符串

// 使用 resolvedOptions() 方法查看最终的选项
const resolvedOptions = formatter.resolvedOptions();
console.log(resolvedOptions);
/* 输出类似于:
{
  locale: "zh-CN",
  calendar: "gregory",
  numberingSystem: "hanidec",
  timeZone: "Asia/Shanghai",
  hourCycle: "h24",
  year: "numeric",
  month: "long",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit"
}
*/
```

在这个例子中，当你创建 `Intl.DateTimeFormat` 对象并调用 `format()` 或 `resolvedOptions()` 方法时，V8 引擎会在底层调用 `v8/src/objects/js-date-time-format.cc` 文件中实现的相应 C++ 代码。这个 C++ 文件负责处理选项、与 ICU 交互并最终返回格式化后的字符串或解析后的选项对象。

例如，当你指定 `timeZone: 'Asia/Shanghai'` 时，`JSDateTimeFormat::CanonicalizeTimeZoneID` 函数可能会被调用来规范化时区 ID。当你指定 `hourCycle: 'h24'` 时，代码会设置相应的内部状态，并在格式化时使用 24 小时制。`formatter.format(date)` 的调用会触发 `JSDateTimeFormat::DateTimeFormat` 函数，该函数会使用 ICU 根据你提供的选项来格式化 `date` 对象。

总而言之，`v8/src/objects/js-date-time-format.cc` 是 `Intl.DateTimeFormat` 在 V8 引擎中的幕后功臣，它提供了将 JavaScript 的国际化日期和时间格式化需求转化为实际操作的关键桥梁。

Prompt: 
```
这是目录为v8/src/objects/js-date-time-format.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

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
    PatternKind kind, Handle<JSTemporalPlainDateTime> plain_date_time,
    const char* method_name) {
  // 8. Let timeZone be ! CreateTemporalTimeZone(dateTimeFormat.[[TimeZone]]).
  Handle<Object> time_zone_obj = GetTimeZone(isolate, date_time_format);
  // TODO(ftang): we should change the return type of GetTimeZone() to
  // Handle<String> by ensure it will not return undefined.
  CHECK(IsString(*time_zone_obj));
  Handle<JSTemporalTimeZone> time_zone =
      temporal::CreateTemporalTimeZone(isolate, Cast<String>(time_zone_obj))
          .ToHandleChecked();
  // 9. Let instant be ? BuiltinTimeZoneGetInstantFor(timeZone, plainDateTime,
  // "compatible").
  Handle<JSTemporalInstant> instant;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, instant,
      temporal::BuiltinTimeZoneGetInstantForCompatible(
          isolate, time_zone, plain_date_time, method_name),
      Nothing<DateTimeValueRecord>());
  // 10. If pattern is null, throw a TypeError exception.

  // 11. Return the Record { [[pattern]]: pattern.[[pattern]],
  // [[rangePatterns]]: pattern.[[rangePatterns]], [[epochNanoseconds]]:
  // instant.[[Nanoseconds]] }.
  return Just(TemporalInstantToRecord(isolate, instant, kind));
}

template <typename T>
Maybe<DateTimeValueRecord> TemporalToRecord(
    Isolate* isolate, const icu::SimpleDateFormat& date_time_format,
    PatternKind kind, Handle<T> temporal, Handle<JSReceiver> calendar,
    const char* method_name) {
  // 7. Let plainDateTime be ? CreateTemporalDateTime(temporalDate.[[ISOYear]],
  // temporalDate.[[ISOMonth]], temporalDate.[[ISODay]], 12, 0, 0, 0, 0, 0,
  // calendarOverride).
  Handle<JSTemporalPlainDateTime> plain_date_time;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, plain_date_time,
      temporal::CreateTemporalDateTime(
          isolate,
          {{temporal->iso_year(), temporal->iso_month(), temporal->iso_day()},
           {12, 0, 0, 0, 0, 0}},
          calendar),
      Nothing<DateTimeValueRecord>());
  return TemporalPlainDateTimeToRecord(isolate, date_time_format, kind,
                                       plain_date_time, method_name);
}

// #sec-temporal-handledatetimevaluetemporaldate
Maybe<DateTimeValueRecord> HandleDateTimeTemporalDate(
    Isolate* isolate, const icu::SimpleDateFormat& date_time_format,
    Handle<String> date_time_format_calendar,
    Handle<JSTemporalPlainDate> temporal_date, const char* method_name) {
  // 1. Assert: temporalDate has an [[InitializedTemporalDate]] internal slot.

  // 2. Let pattern be dateTimeFormat.[[TemporalPlainDatePattern]].

  // 3. Let calendar be ? ToString(temporalDate.[[Calendar]]).
  Handle<String> calendar;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar,
      Object::ToString(isolate, handle(temporal_date->calendar(), isolate)),
      Nothing<DateTimeValueRecord>());

  // 4. If calendar is dateTimeFormat.[[Calendar]], then
  Handle<JSReceiver> calendar_override;
  if (String::Equals(isolate, calendar, date_time_format_calendar)) {
    // a. Let calendarOverride be temporalDate.[[Calendar]].
    calendar_override = handle(temporal_date->calendar(), isolate);
    // 5. Else if calendar is "iso8601", then
  } else if (String::Equals(isolate, calendar,
                            isolate->factory()->iso8601_string())) {
    // a. Let calendarOverride be ?
    // GetBuiltinCalendar(dateTimeFormat.[[Calendar]]).
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, calendar_override,
        temporal::GetBuiltinCalendar(isolate, date_time_format_calendar),
        Nothing<DateTimeValueRecord>());
    // 6. Else,
  } else {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kInvalid,
                      isolate->factory()->calendar_string(), calendar),
        Nothing<DateTimeValueRecord>());
  }
  return TemporalToRecord<JSTemporalPlainDate>(
      isolate, date_time_format, PatternKind::kPlainDate, temporal_date,
      calendar_override, method_name);
}
// #sec-temporal-handledatetimevaluetemporaldatetime
Maybe<DateTimeValueRecord> HandleDateTimeTemporalDateTime(
    Isolate* isolate, const icu::SimpleDateFormat& date_time_format,
    Handle<String> date_time_format_calendar,
    Handle<JSTemporalPlainDateTime> date_time, const char* method_name) {
  // 1. Assert: dateTime has an [[InitializedTemporalDateTime]] internal slot.
  // 2. Let pattern be dateTimeFormat.[[TemporalPlainDateTimePattern]].
  // 3. Let calendar be ? ToString(dateTime.[[Calendar]]).
  Handle<String> calendar;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar,
      Object::ToString(isolate, handle(date_time->calendar(), isolate)),
      Nothing<DateTimeValueRecord>());
  // 4. If calendar is not "iso8601" and not equal to
  // dateTimeFormat.[[Calendar]], then
  DirectHandle<JSReceiver> calendar_override;
  if (!String::Equals(isolate, calendar,
                      isolate->factory()->iso8601_string()) &&
      !String::Equals(isolate, calendar, date_time_format_calendar)) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kInvalid,
                      isolate->factory()->calendar_string(), calendar),
        Nothing<DateTimeValueRecord>());
  }

  // 5. Let timeZone be ! CreateTemporalTimeZone(dateTimeFormat.[[TimeZone]]).
  // 6. Let instant be ? BuiltinTimeZoneGetInstantFor(timeZone, dateTime,
  // "compatible").
  // 7. If pattern is null, throw a TypeError exception.

  // 8. Return the Record { [[pattern]]: pattern.[[pattern]], [[rangePatterns]]:
  // pattern.[[rangePatterns]], [[epochNanoseconds]]: instant.[[Nanoseconds]] }.

  return TemporalPlainDateTimeToRecord(isolate, date_time_format,
                                       PatternKind::kPlainDateTime, date_time,
                                       method_name);
}

// #sec-temporal-handledatetimevaluetemporalzoneddatetime
Maybe<DateTimeValueRecord> HandleDateTimeTemporalZonedDateTime(
    Isolate* isolate, const icu::SimpleDateFormat& date_time_format,
    Handle<String> date_time_format_calendar,
    DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    const char* method_name) {
  // 1. Assert: zonedDateTime has an [[InitializedTemporalZonedDateTime]]
  // internal slot.
  // 2. Let pattern be dateTimeFormat.[[TemporalZonedDateTimePattern]].

  // 3. Let calendar be ? ToString(zonedDateTime.[[Calendar]]).
  Handle<String> calendar;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar,
      Object::ToString(isolate, handle(zoned_date_time->calendar(), isolate)),
      Nothing<DateTimeValueRecord>());
  // 4. If calendar is not "iso8601" and not equal to
  // dateTimeFormat.[[Calendar]], then
  DirectHandle<JSReceiver> calendar_override;
  if (!String::Equals(isolate, calendar,
                      isolate->factory()->iso8601_string()) &&
      !String::Equals(isolate, calendar, date_time_format_calendar)) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kInvalid,
                      isolate->factory()->calendar_string(), calendar),
        Nothing<DateTimeValueRecord>());
  }
  // 5. Let timeZone be ? ToString(zonedDateTime.[[TimeZone]]).
  Handle<String> time_zone;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, time_zone,
      Object::ToString(isolate, handle(zoned_date_time->time_zone(), isolate)),
      Nothing<DateTimeValueRecord>());
  // 6. If dateTimeFormat.[[TimeZone]] is not equal to DefaultTimeZone(), and
  // timeZone is not equal to dateTimeFormat.[[TimeZone]], then
  Handle<Object> date_time_format_time_zone =
      GetTimeZone(isolate, date_time_format);
  DCHECK(IsString(*date_time_format_time_zone));
  Handle<String> date_time_format_time_zone_string =
      Cast<String>(date_time_format_time_zone);
  if (!String::Equals(isolate, date_time_format_time_zone_string,
                      Intl::DefaultTimeZone(isolate)) &&
      !String::Equals(isolate, time_zone, date_time_format_time_zone_string)) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kInvalid,
                      isolate->factory()->timeZone_string(), time_zone),
        Nothing<DateTimeValueRecord>());
  }
  // 7. Let instant be ! CreateTemporalInstant(zonedDateTime.[[Nanoseconds]]).
  DirectHandle<JSTemporalInstant> instant =
      temporal::CreateTemporalInstant(
          isolate, handle(zoned_date_time->nanoseconds(), isolate))
          .ToHandleChecked();
  // 8. If pattern is null, throw a TypeError exception.

  // 9. Return the Record { [[pattern]]: pattern.[[pattern]], [[rangePatterns]]:
  // pattern.[[rangePatterns]], [[epochNanoseconds]]: instant.[[Nanoseconds]] }.
  return Just(
      TemporalInstantToRecord(isolate, instant, PatternKind::kZonedDateTime));
}

// #sec-temporal-handledatetimevaluetemporalinstant
Maybe<DateTimeValueRecord> HandleDateTimeTemporalInstant(
    Isolate* isolate, const icu::SimpleDateFormat& date_time_format,
    DirectHandle<JSTemporalInstant> instant, const char* method_name) {
  // 1. Assert: instant has an [[InitializedTemporalInstant]] internal slot.
  // 2. Let pattern be dateTimeFormat.[[TemporalInstantPattern]].
  // 3. If pattern is null, throw a TypeError exception.

  // 4. Return the Record { [[pattern]]: pattern.[[pattern]], [[rangePatterns]]:
  // pattern.[[rangePatterns]], [[epochNanoseconds]]: instant.[[Nanoseconds]] }.
  return Just(TemporalInstantToRecord(isolate, instant, PatternKind::kInstant));
}

// #sec-temporal-handledatetimevaluetemporaltime
Maybe<DateTimeValueRecord> HandleDateTimeTemporalTime(
    Isolate* isolate, const icu::SimpleDateFormat& date_time_format,
    DirectHandle<JSTemporalPlainTime> temporal_time, const char* method_name) {
  // 1. Assert: temporalTime has an [[InitializedTemporalTime]] internal slot.
  // 2. Let pattern be dateTimeFormat.[[TemporalPlainTimePattern]].

  // 3. Let isoCalendar be ! GetISO8601Calendar().

  DirectHandle<JSReceiver> iso_calendar = temporal::GetISO8601Calendar(isolate);
  // 4. Let plainDateTime be ? CreateTemporalDateTime(1970, 1, 1,
  // temporalTime.[[ISOHour]], temporalTime.[[ISOMinute]],
  // temporalTime.[[ISOSecond]], temporalTime.[[ISOMillisecond]],
  // temporalTime.[[ISOMicrosecond]], temporalTime.[[ISONanosecond]],
  // isoCalendar).
  Handle<JSTemporalPlainDateTime> plain_date_time;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, plain_date_time,
      temporal::CreateTemporalDateTime(
          isolate,
          {{1970, 1, 1},
           {temporal_time->iso_hour(), temporal_time->iso_minute(),
            temporal_time->iso_second(), temporal_time->iso_millisecond(),
            temporal_time->iso_microsecond(), temporal_time->iso_nanosecond()}},
          iso_calendar),
      Nothing<DateTimeValueRecord>());
  return TemporalPlainDateTimeToRecord(isolate, date_time_format,
                                       PatternKind::kPlainTime, plain_date_time,
                                       method_name);
}

template <typename T>
Maybe<DateTimeValueRecord> HandleDateTimeTemporalYearMonthOrMonthDay(
    Isolate* isolate, const icu::SimpleDateFormat& date_time_format,
    Handle<String> date_time_format_calendar, PatternKind kind,
    Handle<T> temporal, const char* method_name) {
  // 3. Let calendar be ? ToString(temporalYearMonth.[[Calendar]]).
  Handle<String> calendar;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar,
      Object::ToString(isolate, handle(temporal->calendar(), isolate)),
      Nothing<DateTimeValueRecord>());
  // 4. If calendar is not equal to dateTimeFormat.[[Calendar]], then
  // https://github.com/tc39/proposal-temporal/issues/2364
  if (!String::Equals(isolate, calendar, date_time_format_calendar)) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kInvalid,
                      isolate->factory()->calendar_string(), calendar),
        Nothing<DateTimeValueRecord>());
  }

  return TemporalToRecord<T>(isolate, date_time_format, kind, temporal,
                             handle(temporal->calendar(), isolate),
                             method_name);
}

// #sec-temporal-handledatetimevaluetemporalyearmonth
Maybe<DateTimeValueRecord> HandleDateTimeTemporalYearMonth(
    Isolate* isolate, const icu::SimpleDateFormat& date_time_format,
    Handle<String> date_time_format_calendar,
    Handle<JSTemporalPlainYearMonth> temporal_year_month,
    const char* method_name) {
  return HandleDateTimeTemporalYearMonthOrMonthDay<JSTemporalPlainYearMonth>(
      isolate, date_time_format, date_time_format_calendar,
      PatternKind::kPlainYearMonth, temporal_year_month, method_name);
}

// #sec-temporal-handledatetimevaluetemporalmonthday
Maybe<DateTimeValueRecord> HandleDateTimeTemporalMonthDay(
    Isolate* isolate, const icu::SimpleDateFormat& date_time_format,
    Handle<String> date_time_format_calendar,
    Handle<JSTemporalPlainMonthDay> temporal_month_day,
    const char* method_name) {
  return HandleDateTimeTemporalYearMonthOrMonthDay<JSTemporalPlainMonthDay>(
      isolate, date_time_format, date_time_format_calendar,
      PatternKind::kPlainMonthDay, temporal_month_day, method_name);
}

// #sec-temporal-handledatetimeothers
Maybe<DateTimeValueRecord> HandleDateTimeOthers(
    Isolate* isolate, const icu::SimpleDateFormat& date_time_format,
    Handle<Object> x_obj, const char* method_name) {
  // 1. Assert: ! IsTemporalObject(x) is false.
  DCHECK(!IsTemporalObject(x_obj));
  // 2. Let pattern be dateTimeFormat.[[Pattern]].

  // 3. Let rangePatterns be dateTimeFormat.[[RangePatterns]].

  // 4. If x is undefined, then
  double x;
  if (IsUndefined(*x_obj)) {
    // a. Set x to ! Call(%Date.now%, undefined).
    x = static_cast<double>(JSDate::CurrentTimeValue(isolate));
    // 5. Else,
  } else {
    // a. Set x to ? ToNumber(x).
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, x_obj,
                                     Object::ToNumber(isolate, x_obj),
                                     Nothing<DateTimeValueRecord>());
    x = Object::NumberValue(*x_obj);
  }
  // 6. Set x to TimeClip(x).
  // 7. If x is NaN, throw a RangeError exception.
  if (!DateCache::TryTimeClip(&x)) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NewRangeError(MessageTemplate::kInvalidTimeValue),
        Nothing<DateTimeValueRecord>());
  }

  // 8. Let epochNanoseconds be ℤ(x) × 10^6ℤ.

  // 9. Return the Record { [[pattern]]: pattern, [[rangePatterns]]:
  // rangePatterns, [[epochNanoseconds]]: epochNanoseconds }.
  return Just(DateTimeValueRecord({x, PatternKind::kDate}));
}

// #sec-temporal-handledatetimevalue
Maybe<DateTimeValueRecord> HandleDateTimeValue(
    Isolate* isolate, const icu::SimpleDateFormat& date_time_format,
    Handle<String> date_time_format_calendar, Handle<Object> x,
    const char* method_name) {
  if (IsTemporalObject(x)) {
    // a. If x has an [[InitializedTemporalDate]] internal slot, then
    if (IsJSTemporalPlainDate(*x)) {
      // i. Return ? HandleDateTimeTemporalDate(dateTimeFormat, x).
      return HandleDateTimeTemporalDate(
          isolate, date_time_format, date_time_format_calendar,
          Cast<JSTemporalPlainDate>(x), method_name);
    }
    // b. If x has an [[InitializedTemporalYearMonth]] internal slot, then
    if (IsJSTemporalPlainYearMonth(*x)) {
      // i. Return ? HandleDateTimeTemporalYearMonth(dateTimeFormat, x).
      return HandleDateTimeTemporalYearMonth(
          isolate, date_time_format, date_time_format_calendar,
          Cast<JSTemporalPlainYearMonth>(x), method_name);
    }
    // c. If x has an [[InitializedTemporalMonthDay]] internal slot, then
    if (IsJSTemporalPlainMonthDay(*x)) {
      // i. Return ? HandleDateTimeTemporalMonthDay(dateTimeFormat, x).
      return HandleDateTimeTemporalMonthDay(
          isolate, date_time_format, date_time_format_calendar,
          Cast<JSTemporalPlainMonthDay>(x), method_name);
    }
    // d. If x has an [[InitializedTemporalTime]] internal slot, then
    if (IsJSTemporalPlainTime(*x)) {
      // i. Return ? HandleDateTimeTemporalTime(dateTimeFormat, x).
      return HandleDateTimeTemporalTime(
          isolate, date_time_format, Cast<JSTemporalPlainTime>(x), method_name);
    }
    // e. If x has an [[InitializedTemporalDateTime]] internal slot, then
    if (IsJSTemporalPlainDateTime(*x)) {
      // i. Return ? HandleDateTimeTemporalDateTime(dateTimeFormat, x).
      return HandleDateTimeTemporalDateTime(
          isolate, date_time_format, date_time_format_calendar,
          Cast<JSTemporalPlainDateTime>(x), method_name);
    }
    // f. If x has an [[InitializedTemporalInstant]] internal slot, then
    if (IsJSTemporalInstant(*x)) {
      // i. Return ? HandleDateTimeTemporalInstant(dateTimeFormat, x).
      return HandleDateTimeTemporalInstant(
          isolate, date_time_format, Cast<JSTemporalInstant>(x), method_name);
    }
    // g. Assert: x has an [[InitializedTemporalZonedDateTime]] internal slot.
    DCHECK(IsJSTemporalZonedDateTime(*x));
    // h. Return ? HandleDateTimeTemporalZonedDateTime(dateTimeFormat, x).
    return HandleDateTimeTemporalZonedDateTime(
        isolate, date_time_format, date_time_format_calendar,
        Cast<JSTemporalZonedDateTime>(x), method_name);
  }

  // 2. Return ? HandleDateTimeOthers(dateTimeFormat, x).
  return HandleDateTimeOthers(isolate, date_time_format, x, method_name);
}

// This helper function handles Supported fields and Default fields in Table 16
// ( #table-temporal-patterns ).  It remove all the fields not stated in keep
// from input, and add the fields in add_default if a skeleton in the same
// category is in the input, with considering the equivalent.
// For example, if input is "yyyyMMhm", keep is {y,M,d} and add_default is
// {y,M,d}, the output will be "yyyyMMd". For example, if input is
// "yyyyMMhmOOOO", keep is {h,m,s,z,O,v} and add_default is {h,m,s}, then the
// output will be "hmOOOOs". The meaning of the skeleton letters is stated in
// UTS35
// https://www.unicode.org/reports/tr35/tr35-dates.html#table-date-field-symbol-table
icu::UnicodeString KeepSupportedAddDefault(
    const icu::UnicodeString& input, const std::set<char16_t>& keep,
    const std::set<char16_t>& add_default) {
  const std::map<char16_t, char16_t> equivalent({{'L', 'M'},
                                                 {'h', 'j'},
                                                 {'H', 'j'},
                                                 {'k', 'j'},
                                                 {'K', 'j'},
                                                 {'O', 'z'},
                                                 {'v', 'z'}});
  std::set<char16_t> to_be_added(add_default);
  icu::UnicodeString result;
  for (int32_t i = 0; i < input.length(); i++) {
    char16_t ch = input.charAt(i);
    if (keep.find(ch) != keep.end()) {
      to_be_added.erase(ch);
      auto also = equivalent.find(ch);
      if (also != equivalent.end()) {
        to_be_added.erase(also->second);
      }
      result.append(ch);
    }
  }
  for (auto it = to_be_added.begin(); it != to_be_added.end(); ++it) {
    result.append(*it);
  }
  return result;
}

icu::UnicodeString GetSkeletonForPatternKind(const icu::UnicodeString& input,
                                             PatternKind kind) {
  // [[weekday]] skeleton could be one or more 'E' or 'c'.
  // [[era]] skeleton could be one or more 'G'.
  // [[year]] skeleton could be one or more 'y'.
  // [[month]] skeleton could be one or more 'M' or 'L'.
  // [[day]] skeleton could be one or more 'd'.
  // [[hour]] skeleton could be one or more 'h', 'H', 'k', 'K', or 'j'.
  // [[minute]] skeleton could be one or more 'm'.
  // [[second]] skeleton could be one or more 's'.
  // [[dayPeriod]] skeleton could be one or more 'b', 'B' or 'a'.
  // [[fractionalSecondDigits]] skeleton could be one or more 'S'.
  // [[timeZoneName]] skeleton could be one or more 'z', 'O', or 'v'.

  switch (kind) {
    case PatternKind::kDate:
      return input;
    case PatternKind::kPlainDate:
      return KeepSupportedAddDefault(
          // Supported fields: [[weekday]], [[era]], [[year]], [[month]],
          // [[day]]
          input, {'E', 'c', 'G', 'y', 'M', 'L', 'd'},
          // Default fields: [[year]], [[month]], [[day]]
          {'y', 'M', 'd'});
    case PatternKind::kPlainYearMonth:
      return KeepSupportedAddDefault(
          // Supported fields: [[era]], [[year]], [[month]]
          input, {'G', 'y', 'M', 'L'},
          // Default fields: [[year]], [[month]]
          {'y', 'M'});
    case PatternKind::kPlainMonthDay:
      return KeepSupportedAddDefault(
          // Supported fields: [[month]] [[day]]
          input, {'M', 'L', 'd'},
          // Default fields: [[month]] [[day]]
          {'M', 'd'});

    case PatternKind::kPlainTime:
      return KeepSupportedAddDefault(
          input,
          // Supported fields: [[hour]], [[minute]], [[second]], [[dayPeriod]],
          // [[fractionalSecondDigits]]
          {'h', 'H', 'k', 'K', 'j', 'm', 's', 'B', 'b', 'a', 'S'},
          // Default fields:  [[hour]], [[minute]],
          // [[second]]
          {'j', 'm', 's'});

    case PatternKind::kPlainDateTime:
      // Row TemporalInstantPattern is the same as TemporalPlainDateTimePattern
      // in Table 16: Supported fields for Temporal patterns
      // #table-temporal-patterns
      [[fallthrough]];
    case PatternKind::kInstant:
      return KeepSupportedAddDefault(
          input,
          // Supported fields: [[weekday]], [[era]], [[year]], [[month]],
          // [[day]], [[hour]], [[minute]], [[second]], [[dayPeriod]],
          // [[fractionalSecondDigits]]
          {'E', 'c', 'G', 'y', 'M', 'L', 'd', 'h', 'H', 'k', 'K', 'j', 'm', 's',
           'B', 'b', 'a', 'S'},
          // Default fields: [[year]], [[month]], [[day]], [[hour]], [[minute]],
          // [[second]]
          {'y', 'M', 'd', 'j', 'm', 's'});

    case PatternKind::kZonedDateTime:
      return KeepSupportedAddDefault(
          // Supported fields: [[weekday]], [[era]], [[year]], [[month]],
          // [[day]], [[hour]], [[minute]], [[second]], [[dayPeriod]],
          // [[fractionalSecondDigits]], [[timeZoneName]]
          input, {'E', 'c', 'G', 'y', 'M', 'L', 'd', 'h', 'H', 'k', 'K',
                  'j', 'm', 's', 'B', 'b', 'a', 'S', 'z', 'O', 'v'},
          // Default fields: [[year]], [[month]], [[day]], [[hour]], [[minute]],
          // [[second]], [[timeZoneName]]
          {'y', 'M', 'd', 'j', 'm', 's', 'z'});
  }
}

icu::UnicodeString SkeletonFromDateFormat(
    const icu::SimpleDateFormat& icu_date_format) {
  icu::UnicodeString pattern;
  pattern = icu_date_format.toPattern(pattern);

  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString skeleton =
      icu::DateTimePatternGenerator::staticGetSkeleton(pattern, status);
  DCHECK(U_SUCCESS(status));
  return skeleton;
}

std::unique_ptr<icu::SimpleDateFormat> GetSimpleDateTimeForTemporal(
    const icu::SimpleDateFormat& date_format, PatternKind kind) {
  DCHECK_NE(kind, PatternKind::kDate);
  icu::UnicodeString skeleton =
      GetSkeletonForPatternKind(SkeletonFromDateFormat(date_format), kind);
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::SimpleDateFormat> result(
      static_cast<icu::SimpleDateFormat*>(
          icu::DateFormat::createInstanceForSkeleton(
              skeleton, date_format.getSmpFmtLocale(), status)));
  DCHECK(result);
  DCHECK(U_SUCCESS(status));
  result->setTimeZone(date_format.getTimeZone());
  return result;
}

icu::UnicodeString CallICUFormat(const icu::SimpleDateFormat& date_format,
                                 PatternKind kind, double time_in_milliseconds,
                                 icu::FieldPositionIterator* fp_iter,
                                 UErrorCode& status) {
  icu::UnicodeString result;
  // Use the date_format directly for Date value.
  if (kind == PatternKind::kDate) {
    date_format.format(time_in_milliseconds, result, fp_iter, status);
    return result;
  }
  // For other Temporal objects, lazy generate a SimpleDateFormat for the kind.
  std::unique_ptr<icu::SimpleDateFormat> pattern(
      GetSimpleDateTimeForTemporal(date_format, kind));
  pattern->format(time_in_milliseconds, result, fp_iter, status);
  return result;
}

// ecma402/#sec-formatdatetime
// FormatDateTime( dateTimeFormat, x )
MaybeHandle<String> FormatDateTime(Isolate* isolate,
                                   const icu::SimpleDateFormat& date_format,
                                   double x) {
  if (!DateCache::TryTimeClip(&x)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidTimeValue));
  }

  icu::UnicodeString result;
  date_format.format(x, result);

  // Revert ICU 72 change that introduced U+202F instead of U+0020
  // to separate time from AM/PM. See https://crbug.com/1414292.
  result = result.findAndReplace(icu::UnicodeString(0x202f),
                                 icu::UnicodeString(0x20));

  return Intl::ToString(isolate, result);
}

MaybeHandle<String> FormatMillisecondsByKindToString(
    Isolate* isolate, const icu::SimpleDateFormat& date_format,
    PatternKind kind, double x) {
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString result =
      CallICUFormat(date_format, kind, x, nullptr, status);
  DCHECK(U_SUCCESS(status));

  return Intl::ToString(isolate, result);
}
MaybeHandle<String> FormatDateTimeWithTemporalSupport(
    Isolate* isolate, const icu::SimpleDateFormat& date_format,
    Handle<String> date_time_format_calendar, Handle<Object> x,
    const char* method_name) {
  DateTimeValueRecord record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record,
      HandleDateTimeValue(isolate, date_format, date_time_format_calendar, x,
                          method_name),
      Handle<String>());
  return FormatMillisecondsByKindToString(isolate, date_format, record.kind,
                                          record.epoch_milliseconds);
}

MaybeHandle<String> FormatDateTimeWithTemporalSupport(
    Isolate* isolate, DirectHandle<JSDateTimeFormat> date_time_format,
    Handle<Object> x, const char* method_name) {
  return FormatDateTimeWithTemporalSupport(
      isolate, *(date_time_format->icu_simple_date_format()->raw()),
      JSDateTimeFormat::Calendar(isolate, date_time_format), x, method_name);
}

}  // namespace

// ecma402/#sec-datetime-format-functions
// DateTime Format Functions
MaybeHandle<String> JSDateTimeFormat::DateTimeFormat(
    Isolate* isolate, DirectHandle<JSDateTimeFormat> date_time_format,
    Handle<Object> date, const char* method_name) {
  // 2. Assert: Type(dtf) is Object and dtf has an [[InitializedDateTimeFormat]]
  // internal slot.
  if (v8_flags.harmony_temporal) {
    return FormatDateTimeWithTemporalSupport(isolate, date_time_format, date,
                                             method_name);
  }

  // 3. If date is not provided or is undefined, then
  double x;
  if (IsUndefined(*date)) {
    // 3.a Let x be Call(%Date_now%, undefined).
    x = static_cast<double>(JSDate::CurrentTimeValue(isolate));
  } else {
    // 4. Else,
    //    a. Let x be ? ToNumber(date).
    ASSIGN_RETURN_ON_EXCEPTION(isolate, date, Object::ToNumber(isolate, date));
    DCHECK(IsNumber(*date));
    x = Object::NumberValue(*date);
  }
  // 5. Return FormatDateTime(dtf, x).
  icu::SimpleDateFormat* format =
      date_time_format->icu_simple_date_format()->raw();
  return FormatDateTime(isolate, *format, x);
}

namespace {
Isolate::ICUObjectCacheType ConvertToCacheType(
    JSDateTimeFormat::DefaultsOption type) {
  switch (type) {
    case JSDateTimeFormat::DefaultsOption::kDate:
      return Isolate::ICUObjectCacheType::kDefaultSimpleDateFormatForDate;
    case JSDateTimeFormat::DefaultsOption::kTime:
      return Isolate::ICUObjectCacheType::kDefaultSimpleDateFormatForTime;
    case JSDateTimeFormat::DefaultsOption::kAll:
      return Isolate::ICUObjectCacheType::kDefaultSimpleDateFormat;
  }
}

}  // namespace

MaybeHandle<String> JSDateTimeFormat::ToLocaleDateTime(
    Isolate* isolate, Handle<Object> date, Handle<Object> locales,
    Handle<Object> options, RequiredOption required, DefaultsOption defaults,
    const char* method_name) {
  Isolate::ICUObjectCacheType cache_type = ConvertToCacheType(defaults);

  Factory* factory = isolate->factory();
  // 1. Let x be ? thisTimeValue(this value);
  if (!IsJSDate(*date)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kMethodInvokedOnWrongType,
                                 factory->Date_string()));
  }
  double const x = Cast<JSDate>(date)->value();
  // 2. If x is NaN, return "Invalid Date"
  if (std::isnan(x)) {
    return factory->Invalid_Date_string();
  }

  // We only cache the instance when locales is a string/undefined and
  // options is undefined, as that is the only case when the specified
  // side-effects of examining those arguments are unobservable.
  bool can_cache = (IsString(*locales) || IsUndefined(*locales, isolate)) &&
                   IsUndefined(*options, isolate);
  if (can_cache) {
    // Both locales and options are undefined, check the cache.
    icu::SimpleDateFormat* cached_icu_simple_date_format =
        static_cast<icu::SimpleDateFormat*>(
            isolate->get_cached_icu_object(cache_type, locales));
    if (cached_icu_simple_date_format != nullptr) {
      return FormatDateTime(isolate, *cached_icu_simple_date_format, x);
    }
  }
  // 4. Let dateFormat be ? Construct(%DateTimeFormat%, « locales, options »).
  Handle<JSFunction> constructor = Handle<JSFunction>(
      Cast<JSFunction>(isolate->context()
                           ->native_context()
                           ->intl_date_time_format_function()),
      isolate);
  Handle<Map> map;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, map,
      JSFunction::GetDerivedMap(isolate, constructor, constructor));
  Handle<JSDateTimeFormat> date_time_format;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time_format,
      JSDateTimeFormat::CreateDateTimeFormat(isolate, map, locales, options,
                                             required, defaults, method_name));

  if (can_cache) {
    isolate->set_icu_object_in_cache(
        cache_type, locales,
        std::static_pointer_cast<icu::UMemory>(
            date_time_format->icu_simple_date_format()->get()));
  }
  // 5. Return FormatDateTime(dateFormat, x).
  icu::SimpleDateFormat* format =
      date_time_format->icu_simple_date_format()->raw();
  return FormatDateTime(isolate, *format, x);
}

MaybeHandle<String> JSDateTimeFormat::TemporalToLocaleString(
    Isolate* isolate, Handle<JSReceiver> x, Handle<Object> locales,
    Handle<Object> options, const char* method_name) {
  // 4. Let dateFormat be ? Construct(%DateTimeFormat%, « locales, options »).
  Handle<JSFunction> constructor(
      isolate->context()->native_context()->intl_date_time_format_function(),
      isolate);
  DirectHandle<Map> map =
      JSFunction::GetDerivedMap(isolate, constructor, constructor)
          .ToHandleChecked();
  Handle<JSDateTimeFormat> date_time_format;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_time_format,
      JSDateTimeFormat::New(isolate, map, locales, options, method_name));

  // 5. Return FormatDateTime(dateFormat, x).
  return FormatDateTimeWithTemporalSupport(isolate, date_time_format, x,
                                           method_name);
}

MaybeHandle<JSDateTimeFormat> JSDateTimeFormat::UnwrapDateTimeFormat(
    Isolate* isolate, Handle<JSReceiver> format_holder) {
  DirectHandle<Context> native_context(isolate->context()->native_context(),
                                       isolate);
  Handle<JSFunction> constructor(
      Cast<JSFunction>(native_context->intl_date_time_format_function()),
      isolate);
  Handle<Object> dtf;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, dtf,
      Intl::LegacyUnwrapReceiver(isolate, format_holder, constructor,
                                 IsJSDateTimeFormat(*format_holder)));
  // 2. If Type(dtf) is not Object or dtf does not have an
  //    [[InitializedDateTimeFormat]] internal slot, then
  if (!IsJSDateTimeFormat(*dtf)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kIncompatibleMethodReceiver,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     "UnwrapDateTimeFormat"),
                                 format_holder));
  }
  // 3. Return dtf.
  return Cast<JSDateTimeFormat>(dt
"""


```