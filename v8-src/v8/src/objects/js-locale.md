Response: Let's break down the thought process for analyzing this C++ code and explaining its functionality in relation to JavaScript.

1. **Identify the Core Purpose:** The filename `js-locale.cc` immediately suggests it's about handling locales within the V8 JavaScript engine. The `#include "src/objects/js-locale.h"` confirms this. The error message `#error Internationalization is expected to be enabled.` further emphasizes its role in internationalization (i18n).

2. **Scan the Includes:**  The included headers provide clues about the libraries and functionalities being used:
    * `<map>`, `<memory>`, `<string>`, `<vector>`: Standard C++ data structures.
    * `"src/api/api.h"`, `"src/execution/isolate.h"`, `"src/heap/factory.h"`, `"src/objects/..."`: V8-specific headers, indicating interaction with the engine's internals (isolates, heap management, object creation).
    * `"unicode/..."`:  Headers from the ICU library (International Components for Unicode), which is the key to i18n support. This tells us the code relies heavily on ICU for locale manipulation.

3. **Examine Key Data Structures:** Look for structures and classes that represent important concepts:
    * `OptionData`:  Likely maps JavaScript options for locale construction to ICU-specific tags. The `possible_values` and `is_bool_value` members hint at handling different option types.
    * `ValueAndType`: Used in the context of `firstDayOfWeek`, suggesting a mapping between numerical and textual representations of days.

4. **Analyze Key Functions:**  Focus on functions with descriptive names:
    * `InsertOptionsIntoLocale`: This function seems responsible for translating JavaScript options (like `calendar`, `collation`) into ICU locale settings. The interaction with `icu::LocaleBuilder` is a strong indicator.
    * `UnicodeKeywordValue`: This function retrieves specific keyword values (like calendar type, collation) from an ICU locale object.
    * `Is...` functions (e.g., `IsAlpha`, `IsDigit`, `IsUnicodeLanguageSubtag`): These are validation functions, likely used to ensure the structure of locale tags and subtags is correct according to international standards.
    * `JSLocale::New`: This is almost certainly the constructor for `JSLocale` objects within V8. It takes a locale string and options and builds an internal ICU locale representation.
    * `JSLocale::Maximize`, `JSLocale::Minimize`: These suggest functionality for expanding and shortening locale identifiers, respectively, using ICU's likely subtags mechanism.
    * `JSLocale::Get...` functions (e.g., `GetCalendars`, `GetCollations`):  These are getter methods, retrieving lists of available values for specific locale attributes. The interaction with ICU enumeration classes is evident.
    * `JSLocale::GetTextInfo`, `JSLocale::GetWeekInfo`: These functions retrieve structured information about the locale, such as text direction and week-related settings.
    * `JSLocale::Language`, `JSLocale::Script`, `JSLocale::Region`, etc.: These are individual property getters for the different components of a locale.
    * `JSLocale::ToString`: Converts the internal ICU locale representation back to a standard locale string.

5. **Connect C++ Concepts to JavaScript:**  As you analyze the C++ code, think about how these functionalities manifest in JavaScript's `Intl` API:
    * `JSLocale::New` is likely called when you create an `Intl.Locale` object in JavaScript.
    * The `InsertOptionsIntoLocale` function handles the options you pass to the `Intl.Locale` constructor.
    * The `Get...` functions correspond to methods like `Intl.Locale.prototype.calendars`, `Intl.Locale.prototype.collations`, etc.
    * `Maximize` and `Minimize` directly relate to the `Intl.Locale.prototype.maximize()` and `Intl.Locale.prototype.minimize()` methods.
    * The individual property getters map to properties of `Intl.Locale` instances (e.g., `locale.language`, `locale.script`).
    * `ToString` is used when you implicitly or explicitly convert an `Intl.Locale` object to a string.

6. **Formulate the Summary:**  Based on the analysis, synthesize the main functionalities: creating, parsing, validating, and manipulating locale identifiers, and retrieving locale-specific information. Highlight the reliance on ICU and its role as a bridge between JavaScript and ICU.

7. **Construct the JavaScript Examples:**  Choose relevant `Intl` API examples that demonstrate the C++ code's functionality:
    * Creating an `Intl.Locale` object with and without options to show how `JSLocale::New` and `InsertOptionsIntoLocale` are used.
    * Using the getter methods (`calendars`, `collations`, etc.) to show the `Get...` functions in action.
    * Demonstrating `maximize()` and `minimize()` to illustrate those C++ functions.
    * Accessing the locale properties to show the individual getters.
    * Converting a locale to a string to demonstrate `ToString`.

8. **Refine and Organize:**  Ensure the explanation is clear, concise, and well-organized. Use bullet points and clear language. Explain the connection between the C++ code and the corresponding JavaScript features.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this code just stores locale strings.
* **Correction:** The inclusion of ICU headers and the use of `icu::LocaleBuilder` and `icu::Locale` objects indicate it's doing much more sophisticated locale handling.

* **Initial thought:** The `Is...` functions might be for general string validation.
* **Correction:** Their names (e.g., `IsUnicodeLanguageSubtag`) and the references to international standards (UTS 35) indicate they are specifically for validating locale tag components.

* **Initial thought:** The `Get...` methods just return simple string values.
* **Correction:** The use of `icu::StringEnumeration` suggests they are retrieving potentially multiple values (like a list of calendars or collations).

By following this structured approach, combining code analysis with knowledge of the relevant JavaScript APIs, and iteratively refining understanding, you can effectively decipher the functionality of this C++ file and its connection to JavaScript.
这个C++源代码文件 `v8/src/objects/js-locale.cc` 的主要功能是 **实现 JavaScript 中 `Intl.Locale` 对象的底层逻辑**。它负责创建、解析、验证和操作符合 BCP 47 标准的语言标记（locale tag），并提供访问与特定语言环境相关的各种信息的接口。

具体来说，这个文件做了以下几件事：

**1. `Intl.Locale` 对象的创建和初始化:**

*   当在 JavaScript 中创建一个 `Intl.Locale` 对象时（例如 `new Intl.Locale('en-US', { calendar: 'gregory' })`），V8 引擎会调用这个文件中的 C++ 代码来处理。
*   `JSLocale::New` 函数是创建 `JSLocale` 对象的入口点。
*   它使用 ICU (International Components for Unicode) 库中的 `icu::LocaleBuilder` 来解析和构建内部的 ICU Locale 对象。
*   `ApplyOptionsToTag` 函数处理传入 `Intl.Locale` 构造函数的选项，如 `language`, `script`, `region` 等，并将其应用到 locale tag。
*   `InsertOptionsIntoLocale` 函数处理其他的 Unicode 扩展选项，如 `calendar`, `collation`, `hourCycle` 等，并将它们添加到 ICU Locale 对象中。

**2. Locale Tag 的解析和验证:**

*   代码中包含一系列 `Is...` 函数（例如 `IsUnicodeLanguageSubtag`, `IsUnicodeScriptSubtag`, `IsUnicodeRegionSubtag` 等），用于验证 locale tag 的各个组成部分是否符合 BCP 47 标准。
*   `StartsWithUnicodeLanguageId` 函数检查一个字符串是否以有效的 Unicode 语言标识符开头。
*   如果传入的 locale tag 不合法，会抛出 `RangeError` 异常。

**3. 访问 Locale 的属性和信息:**

*   这个文件提供了一系列方法来获取与特定 locale 相关的各种信息，这些信息最终会暴露给 JavaScript 的 `Intl.Locale` 实例的属性和方法。
*   例如：
    *   `JSLocale::Language`, `JSLocale::Script`, `JSLocale::Region`: 获取语言、脚本和地区信息。
    *   `JSLocale::BaseName`: 获取 locale tag 的基本名称。
    *   `JSLocale::Calendar`, `JSLocale::Collation`, `JSLocale::HourCycle`, `JSLocale::NumberingSystem`: 获取日历类型、排序规则、小时周期和数字系统等信息。
    *   `JSLocale::GetCalendars`, `JSLocale::GetCollations`, `JSLocale::GetHourCycles`, `JSLocale::GetNumberingSystems`: 获取给定 locale 中可用的日历、排序规则、小时周期和数字系统的列表。
    *   `JSLocale::GetTimeZones`: 获取给定 locale 所在地区常用的时区列表。
    *   `JSLocale::GetTextInfo`: 获取文本方向信息（例如，从左到右或从右到左）。
    *   `JSLocale::GetWeekInfo`: 获取与一周相关的配置信息（例如，一周的第一天、周末）。

**4. Locale 的标准化和操作:**

*   `JSLocale::Maximize` 函数用于将一个 minimal 的 locale tag 扩展为包含更多信息的 maximized locale tag (添加可能的默认值)。
*   `JSLocale::Minimize` 函数用于将一个 maximized 的 locale tag 缩减为 minimal 的 locale tag (移除不必要的信息)。

**与 JavaScript 的关系以及示例:**

这个 C++ 文件是 JavaScript `Intl.Locale` 功能的底层实现。当你使用 `Intl.Locale` API 时，实际上是在调用这个文件中定义的 C++ 代码。

**JavaScript 示例:**

```javascript
// 创建一个 Intl.Locale 对象
const locale = new Intl.Locale('en-US', { calendar: 'gregory', hourCycle: 'h24' });

// 获取 locale 的各个属性
console.log(locale.language);        // 输出: "en"
console.log(locale.script);          // 输出: "Latn"
console.log(locale.region);          // 输出: "US"
console.log(locale.calendar);        // 输出: "gregory"
console.log(locale.hourCycle);       // 输出: "h24"

// 获取 locale 的基本名称
console.log(locale.baseName);        // 输出: "en-US"

// 标准化 locale
const maximizedLocale = locale.maximize();
console.log(maximizedLocale.toString()); // 输出类似: "en-Latn-US" (具体输出取决于 ICU 库)

const minimizedLocale = maximizedLocale.minimize();
console.log(minimizedLocale.toString());   // 输出: "en-US"

// 获取 locale 支持的日历系统
console.log(locale.calendars);       // 输出一个包含 "gregory" 的数组

// 获取 locale 的一周信息
console.log(locale.weekInfo);
// 输出类似: { firstDay: 7, weekend: [ 6, 7 ], minimalDays: 1 }

// 获取 locale 的文本方向信息
console.log(locale.textInfo);
// 输出: { direction: "ltr" }
```

**总结:**

`v8/src/objects/js-locale.cc` 文件是 V8 引擎中处理国际化和本地化的核心组件之一。它利用 ICU 库提供的功能，为 JavaScript 开发者提供了操作和查询语言环境信息的强大工具，使得 JavaScript 应用能够更好地支持多语言和文化。 `Intl.Locale` API 在 JavaScript 中的使用，背后正是这个 C++ 文件在默默地工作。

Prompt: 
```
这是目录为v8/src/objects/js-locale.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

#include "src/objects/js-locale.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "src/api/api.h"
#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/objects/intl-objects.h"
#include "src/objects/js-locale-inl.h"
#include "src/objects/managed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/option-utils.h"
#include "unicode/calendar.h"
#include "unicode/char16ptr.h"
#include "unicode/coll.h"
#include "unicode/dtptngen.h"
#include "unicode/localebuilder.h"
#include "unicode/locid.h"
#include "unicode/ucal.h"
#include "unicode/uloc.h"
#include "unicode/ulocdata.h"
#include "unicode/unistr.h"

namespace v8 {
namespace internal {

namespace {

struct OptionData {
  const char* name;
  const char* key;
  const std::vector<const char*>* possible_values;
  bool is_bool_value;
};
struct ValueAndType {
  const char* value;
  const char* type;
};

// Inserts tags from options into locale string.
Maybe<bool> InsertOptionsIntoLocale(Isolate* isolate,
                                    Handle<JSReceiver> options,
                                    icu::LocaleBuilder* builder) {
  DCHECK(isolate);

  const std::vector<const char*> hour_cycle_values = {"h11", "h12", "h23",
                                                      "h24"};
  const std::vector<const char*> case_first_values = {"upper", "lower",
                                                      "false"};
  const std::vector<const char*> empty_values = {};
  const std::array<OptionData, 7> kOptionToUnicodeTagMap = {
      {{"calendar", "ca", &empty_values, false},
       {"collation", "co", &empty_values, false},
       {"firstDayOfWeek", "fw", &empty_values, false},
       {"hourCycle", "hc", &hour_cycle_values, false},
       {"caseFirst", "kf", &case_first_values, false},
       {"numeric", "kn", &empty_values, true},
       {"numberingSystem", "nu", &empty_values, false}}};

  // TODO(cira): Pass in values as per the spec to make this to be
  // spec compliant.

  for (const auto& option_to_bcp47 : kOptionToUnicodeTagMap) {
    std::unique_ptr<char[]> value_str = nullptr;
    bool value_bool = false;
    Maybe<bool> maybe_found =
        option_to_bcp47.is_bool_value
            ? GetBoolOption(isolate, options, option_to_bcp47.name, "locale",
                            &value_bool)
            : GetStringOption(isolate, options, option_to_bcp47.name,
                              *(option_to_bcp47.possible_values), "locale",
                              &value_str);
    MAYBE_RETURN(maybe_found, Nothing<bool>());

    // TODO(cira): Use fallback value if value is not found to make
    // this spec compliant.
    if (!maybe_found.FromJust()) continue;

    const char* type = value_str.get();
    if (strcmp(option_to_bcp47.key, "fw") == 0) {
      const std::array<ValueAndType, 8> kFirstDayValuesAndTypes = {
          {{"0", "sun"},
           {"1", "mon"},
           {"2", "tue"},
           {"3", "wed"},
           {"4", "thu"},
           {"5", "fri"},
           {"6", "sat"},
           {"7", "sun"}}};
      for (const auto& value_to_type : kFirstDayValuesAndTypes) {
        if (std::strcmp(type, value_to_type.value) == 0) {
          type = value_to_type.type;
          break;
        }
      }
    } else if (option_to_bcp47.is_bool_value) {
      value_str = value_bool ? isolate->factory()->true_string()->ToCString()
                             : isolate->factory()->false_string()->ToCString();
      type = value_str.get();
    }
    DCHECK_NOT_NULL(type);

    // Overwrite existing, or insert new key-value to the locale string.
    if (!uloc_toLegacyType(uloc_toLegacyKey(option_to_bcp47.key), type)) {
      return Just(false);
    }
    builder->setUnicodeLocaleKeyword(option_to_bcp47.key, type);
  }
  return Just(true);
}

Handle<Object> UnicodeKeywordValue(Isolate* isolate,
                                   DirectHandle<JSLocale> locale,
                                   const char* key) {
  icu::Locale* icu_locale = locale->icu_locale()->raw();
  UErrorCode status = U_ZERO_ERROR;
  std::string value =
      icu_locale->getUnicodeKeywordValue<std::string>(key, status);
  if (status == U_ILLEGAL_ARGUMENT_ERROR || value.empty()) {
    return isolate->factory()->undefined_value();
  }
  if (value == "yes") {
    value = "true";
  }
  if (value == "true" && strcmp(key, "kf") == 0) {
    return isolate->factory()->NewStringFromStaticChars("");
  }
  return isolate->factory()->NewStringFromAsciiChecked(value.c_str());
}

bool IsCheckRange(const std::string& str, size_t min, size_t max,
                  bool(range_check_func)(char)) {
  if (!base::IsInRange(str.length(), min, max)) return false;
  for (size_t i = 0; i < str.length(); i++) {
    if (!range_check_func(str[i])) return false;
  }
  return true;
}
bool IsAlpha(const std::string& str, size_t min, size_t max) {
  return IsCheckRange(str, min, max, [](char c) -> bool {
    return base::IsInRange(c, 'a', 'z') || base::IsInRange(c, 'A', 'Z');
  });
}

bool IsDigit(const std::string& str, size_t min, size_t max) {
  return IsCheckRange(str, min, max, [](char c) -> bool {
    return base::IsInRange(c, '0', '9');
  });
}

bool IsAlphanum(const std::string& str, size_t min, size_t max) {
  return IsCheckRange(str, min, max, [](char c) -> bool {
    return base::IsInRange(c, 'a', 'z') || base::IsInRange(c, 'A', 'Z') ||
           base::IsInRange(c, '0', '9');
  });
}

bool IsUnicodeLanguageSubtag(const std::string& value) {
  // unicode_language_subtag = alpha{2,3} | alpha{5,8};
  return IsAlpha(value, 2, 3) || IsAlpha(value, 5, 8);
}

bool IsUnicodeScriptSubtag(const std::string& value) {
  // unicode_script_subtag = alpha{4} ;
  return IsAlpha(value, 4, 4);
}

bool IsUnicodeRegionSubtag(const std::string& value) {
  // unicode_region_subtag = (alpha{2} | digit{3});
  return IsAlpha(value, 2, 2) || IsDigit(value, 3, 3);
}

bool IsDigitAlphanum3(const std::string& value) {
  return value.length() == 4 && base::IsInRange(value[0], '0', '9') &&
         IsAlphanum(value.substr(1), 3, 3);
}

bool IsUnicodeVariantSubtag(const std::string& value) {
  // unicode_variant_subtag = (alphanum{5,8} | digit alphanum{3}) ;
  return IsAlphanum(value, 5, 8) || IsDigitAlphanum3(value);
}

bool IsExtensionSingleton(const std::string& value) {
  return IsAlphanum(value, 1, 1);
}

int32_t weekdayFromEDaysOfWeek(icu::Calendar::EDaysOfWeek eDaysOfWeek) {
  return (eDaysOfWeek == icu::Calendar::SUNDAY) ? 7 : eDaysOfWeek - 1;
}

}  // namespace

// Implemented as iteration instead of recursion to avoid stack overflow for
// very long input strings.
bool JSLocale::Is38AlphaNumList(const std::string& in) {
  std::string value = in;
  while (true) {
    std::size_t found_dash = value.find('-');
    if (found_dash == std::string::npos) {
      return IsAlphanum(value, 3, 8);
    }
    if (!IsAlphanum(value.substr(0, found_dash), 3, 8)) return false;
    value = value.substr(found_dash + 1);
  }
}

bool JSLocale::Is3Alpha(const std::string& value) {
  return IsAlpha(value, 3, 3);
}

// TODO(ftang) Replace the following check w/ icu::LocaleBuilder
// once ICU64 land in March 2019.
bool JSLocale::StartsWithUnicodeLanguageId(const std::string& value) {
  // unicode_language_id =
  // unicode_language_subtag (sep unicode_script_subtag)?
  //   (sep unicode_region_subtag)? (sep unicode_variant_subtag)* ;
  std::vector<std::string> tokens;
  std::string token;
  std::istringstream token_stream(value);
  while (std::getline(token_stream, token, '-')) {
    tokens.push_back(token);
  }
  if (tokens.empty()) return false;

  // length >= 1
  if (!IsUnicodeLanguageSubtag(tokens[0])) return false;

  if (tokens.size() == 1) return true;

  // length >= 2
  if (IsExtensionSingleton(tokens[1])) return true;

  size_t index = 1;
  if (IsUnicodeScriptSubtag(tokens[index])) {
    index++;
    if (index == tokens.size()) return true;
  }
  if (IsUnicodeRegionSubtag(tokens[index])) {
    index++;
  }
  while (index < tokens.size()) {
    if (IsExtensionSingleton(tokens[index])) return true;
    if (!IsUnicodeVariantSubtag(tokens[index])) return false;
    index++;
  }
  return true;
}

namespace {
Maybe<bool> ApplyOptionsToTag(Isolate* isolate, Handle<String> tag,
                              Handle<JSReceiver> options,
                              icu::LocaleBuilder* builder) {
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  if (tag->length() == 0) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NewRangeError(MessageTemplate::kLocaleNotEmpty),
        Nothing<bool>());
  }

  v8::String::Utf8Value bcp47_tag(v8_isolate, v8::Utils::ToLocal(tag));
  builder->setLanguageTag(
      {*bcp47_tag, static_cast<int32_t>(bcp47_tag.length())});
  DCHECK_LT(0, bcp47_tag.length());
  DCHECK_NOT_NULL(*bcp47_tag);
  // 2. If IsStructurallyValidLanguageTag(tag) is false, throw a RangeError
  // exception.
  if (!JSLocale::StartsWithUnicodeLanguageId(*bcp47_tag)) {
    return Just(false);
  }
  UErrorCode status = U_ZERO_ERROR;
  icu::Locale canonicalized = builder->build(status);
  canonicalized.canonicalize(status);
  if (U_FAILURE(status)) {
    return Just(false);
  }
  builder->setLocale(canonicalized);

  // 3. Let language be ? GetOption(options, "language", "string", undefined,
  // undefined).
  const std::vector<const char*> empty_values = {};
  std::unique_ptr<char[]> language_str = nullptr;
  Maybe<bool> maybe_language =
      GetStringOption(isolate, options, "language", empty_values,
                      "ApplyOptionsToTag", &language_str);
  MAYBE_RETURN(maybe_language, Nothing<bool>());
  // 4. If language is not undefined, then
  if (maybe_language.FromJust()) {
    builder->setLanguage(language_str.get());
    builder->build(status);
    // a. If language does not match the unicode_language_subtag production,
    //    throw a RangeError exception.
    if (U_FAILURE(status) || language_str[0] == '\0' ||
        IsAlpha(language_str.get(), 4, 4)) {
      return Just(false);
    }
  }
  // 5. Let script be ? GetOption(options, "script", "string", undefined,
  // undefined).
  std::unique_ptr<char[]> script_str = nullptr;
  Maybe<bool> maybe_script =
      GetStringOption(isolate, options, "script", empty_values,
                      "ApplyOptionsToTag", &script_str);
  MAYBE_RETURN(maybe_script, Nothing<bool>());
  // 6. If script is not undefined, then
  if (maybe_script.FromJust()) {
    builder->setScript(script_str.get());
    builder->build(status);
    // a. If script does not match the unicode_script_subtag production, throw
    //    a RangeError exception.
    if (U_FAILURE(status) || script_str[0] == '\0') {
      return Just(false);
    }
  }
  // 7. Let region be ? GetOption(options, "region", "string", undefined,
  // undefined).
  std::unique_ptr<char[]> region_str = nullptr;
  Maybe<bool> maybe_region =
      GetStringOption(isolate, options, "region", empty_values,
                      "ApplyOptionsToTag", &region_str);
  MAYBE_RETURN(maybe_region, Nothing<bool>());
  // 8. If region is not undefined, then
  if (maybe_region.FromJust()) {
    // a. If region does not match the region production, throw a RangeError
    // exception.
    builder->setRegion(region_str.get());
    builder->build(status);
    if (U_FAILURE(status) || region_str[0] == '\0') {
      return Just(false);
    }
  }

  // 9. Set tag to CanonicalizeLanguageTag(tag).
  // 10.  If language is not undefined,
  // a. Assert: tag matches the unicode_locale_id production.
  // b. Set tag to tag with the substring corresponding to the
  //    unicode_language_subtag production replaced by the string language.
  // 11. If script is not undefined, then
  // a. If tag does not contain a unicode_script_subtag production, then
  //   i. Set tag to the concatenation of the unicode_language_subtag
  //      production of tag, "-", script, and the rest of tag.
  // b. Else,
  //   i. Set tag to tag with the substring corresponding to the
  //      unicode_script_subtag production replaced by the string script.
  // 12. If region is not undefined, then
  // a. If tag does not contain a unicode_region_subtag production, then
  //   i. Set tag to the concatenation of the unicode_language_subtag
  //      production of tag, the substring corresponding to the  "-"
  //      unicode_script_subtag production if present, "-", region, and
  //      the rest of tag.
  // b. Else,
  // i. Set tag to tag with the substring corresponding to the
  //    unicode_region_subtag production replaced by the string region.
  // 13.  Return CanonicalizeLanguageTag(tag).
  return Just(true);
}

}  // namespace

MaybeHandle<JSLocale> JSLocale::New(Isolate* isolate, DirectHandle<Map> map,
                                    Handle<String> locale_str,
                                    Handle<JSReceiver> options) {
  icu::LocaleBuilder builder;
  Maybe<bool> maybe_apply =
      ApplyOptionsToTag(isolate, locale_str, options, &builder);
  MAYBE_RETURN(maybe_apply, MaybeHandle<JSLocale>());
  if (!maybe_apply.FromJust()) {
    THROW_NEW_ERROR(isolate,
                    NewRangeError(MessageTemplate::kLocaleBadParameters));
  }

  Maybe<bool> maybe_insert =
      InsertOptionsIntoLocale(isolate, options, &builder);
  MAYBE_RETURN(maybe_insert, MaybeHandle<JSLocale>());
  UErrorCode status = U_ZERO_ERROR;
  icu::Locale icu_locale = builder.build(status);

  icu_locale.canonicalize(status);

  if (!maybe_insert.FromJust() || U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate,
                    NewRangeError(MessageTemplate::kLocaleBadParameters));
  }

  // 31. Set locale.[[Locale]] to r.[[locale]].
  DirectHandle<Managed<icu::Locale>> managed_locale =
      Managed<icu::Locale>::From(
          isolate, 0, std::shared_ptr<icu::Locale>{icu_locale.clone()});

  // Now all properties are ready, so we can allocate the result object.
  Handle<JSLocale> locale =
      Cast<JSLocale>(isolate->factory()->NewFastOrSlowJSObjectFromMap(map));
  DisallowGarbageCollection no_gc;
  locale->set_icu_locale(*managed_locale);
  return locale;
}

namespace {

MaybeHandle<JSLocale> Construct(Isolate* isolate,
                                const icu::Locale& icu_locale) {
  DirectHandle<Managed<icu::Locale>> managed_locale =
      Managed<icu::Locale>::From(
          isolate, 0, std::shared_ptr<icu::Locale>{icu_locale.clone()});

  Handle<JSFunction> constructor(
      isolate->native_context()->intl_locale_function(), isolate);

  Handle<Map> map;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, map,
      JSFunction::GetDerivedMap(isolate, constructor, constructor));

  Handle<JSLocale> locale =
      Cast<JSLocale>(isolate->factory()->NewFastOrSlowJSObjectFromMap(map));
  DisallowGarbageCollection no_gc;
  locale->set_icu_locale(*managed_locale);
  return locale;
}

}  // namespace

MaybeHandle<JSLocale> JSLocale::Maximize(Isolate* isolate,
                                         DirectHandle<JSLocale> locale) {
  // ICU has limitation on the length of the locale while addLikelySubtags
  // is called. Work around the issue by only perform addLikelySubtags
  // on the base locale and merge the extension if needed.
  icu::Locale source(*(locale->icu_locale()->raw()));
  icu::Locale result = icu::Locale::createFromName(source.getBaseName());
  UErrorCode status = U_ZERO_ERROR;
  result.addLikelySubtags(status);
  if (strlen(source.getBaseName()) != strlen(result.getBaseName())) {
    // Base name is changed
    if (strlen(source.getBaseName()) != strlen(source.getName())) {
      // the source has extensions, get the extensions from the source.
      result = icu::LocaleBuilder()
                   .setLocale(source)
                   .setLanguage(result.getLanguage())
                   .setRegion(result.getCountry())
                   .setScript(result.getScript())
                   .setVariant(result.getVariant())
                   .build(status);
    }
  } else {
    // Base name is not changed
    result = source;
  }
  if (U_FAILURE(status) || result.isBogus()) {
    // Due to https://unicode-org.atlassian.net/browse/ICU-21639
    // Valid but super long locale will fail. Just throw here for now.
    THROW_NEW_ERROR(isolate,
                    NewRangeError(MessageTemplate::kLocaleBadParameters));
  }
  return Construct(isolate, result);
}

MaybeHandle<JSLocale> JSLocale::Minimize(Isolate* isolate,
                                         DirectHandle<JSLocale> locale) {
  // ICU has limitation on the length of the locale while minimizeSubtags
  // is called. Work around the issue by only perform addLikelySubtags
  // on the base locale and merge the extension if needed.
  icu::Locale source(*(locale->icu_locale()->raw()));
  icu::Locale result = icu::Locale::createFromName(source.getBaseName());
  UErrorCode status = U_ZERO_ERROR;
  result.minimizeSubtags(status);
  if (strlen(source.getBaseName()) != strlen(result.getBaseName())) {
    // Base name is changed
    if (strlen(source.getBaseName()) != strlen(source.getName())) {
      // the source has extensions, get the extensions from the source.
      result = icu::LocaleBuilder()
                   .setLocale(source)
                   .setLanguage(result.getLanguage())
                   .setRegion(result.getCountry())
                   .setScript(result.getScript())
                   .setVariant(result.getVariant())
                   .build(status);
    }
  } else {
    // Base name is not changed
    result = source;
  }
  if (U_FAILURE(status) || result.isBogus()) {
    // Due to https://unicode-org.atlassian.net/browse/ICU-21639
    // Valid but super long locale will fail. Just throw here for now.
    THROW_NEW_ERROR(isolate,
                    NewRangeError(MessageTemplate::kLocaleBadParameters));
  }
  return Construct(isolate, result);
}

template <typename T>
MaybeHandle<JSArray> GetKeywordValuesFromLocale(Isolate* isolate,
                                                const char* key,
                                                const char* unicode_key,
                                                const icu::Locale& locale,
                                                bool (*removes)(const char*),
                                                bool commonly_used, bool sort) {
  Factory* factory = isolate->factory();
  UErrorCode status = U_ZERO_ERROR;
  std::string ext =
      locale.getUnicodeKeywordValue<std::string>(unicode_key, status);
  if (!ext.empty()) {
    DirectHandle<FixedArray> fixed_array = factory->NewFixedArray(1);
    DirectHandle<String> str = factory->NewStringFromAsciiChecked(ext.c_str());
    fixed_array->set(0, *str);
    return factory->NewJSArrayWithElements(fixed_array);
  }
  status = U_ZERO_ERROR;
  std::unique_ptr<icu::StringEnumeration> enumeration(
      T::getKeywordValuesForLocale(key, locale, commonly_used, status));
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  return Intl::ToJSArray(isolate, unicode_key, enumeration.get(), removes,
                         sort);
}

namespace {

MaybeHandle<JSArray> CalendarsForLocale(Isolate* isolate,
                                        const icu::Locale& icu_locale,
                                        bool commonly_used, bool sort) {
  return GetKeywordValuesFromLocale<icu::Calendar>(
      isolate, "calendar", "ca", icu_locale, nullptr, commonly_used, sort);
}

}  // namespace

MaybeHandle<JSArray> JSLocale::GetCalendars(Isolate* isolate,
                                            DirectHandle<JSLocale> locale) {
  icu::Locale icu_locale(*(locale->icu_locale()->raw()));
  return CalendarsForLocale(isolate, icu_locale, true, false);
}

MaybeHandle<JSArray> Intl::AvailableCalendars(Isolate* isolate) {
  icu::Locale icu_locale("und");
  return CalendarsForLocale(isolate, icu_locale, false, true);
}

MaybeHandle<JSArray> JSLocale::GetCollations(Isolate* isolate,
                                             DirectHandle<JSLocale> locale) {
  icu::Locale icu_locale(*(locale->icu_locale()->raw()));
  return GetKeywordValuesFromLocale<icu::Collator>(
      isolate, "collations", "co", icu_locale, Intl::RemoveCollation, true,
      true);
}

MaybeHandle<JSArray> JSLocale::GetHourCycles(Isolate* isolate,
                                             DirectHandle<JSLocale> locale) {
  // Let preferred be loc.[[HourCycle]].
  // Let locale be loc.[[Locale]].
  icu::Locale icu_locale(*(locale->icu_locale()->raw()));
  Factory* factory = isolate->factory();

  // Assert: locale matches the unicode_locale_id production.

  // Let list be a List of 1 or more hour cycle identifiers, which must be
  // String values indicating either the 12-hour format ("h11", "h12") or the
  // 24-hour format ("h23", "h24"), sorted in descending preference of those in
  // common use in the locale for date and time formatting.

  // Return CreateArrayFromListAndPreferred( list, preferred ).
  DirectHandle<FixedArray> fixed_array = factory->NewFixedArray(1);
  UErrorCode status = U_ZERO_ERROR;
  std::string ext =
      icu_locale.getUnicodeKeywordValue<std::string>("hc", status);
  if (!ext.empty()) {
    DirectHandle<String> str = factory->NewStringFromAsciiChecked(ext.c_str());
    fixed_array->set(0, *str);
    return factory->NewJSArrayWithElements(fixed_array);
  }
  status = U_ZERO_ERROR;
  std::unique_ptr<icu::DateTimePatternGenerator> generator(
      icu::DateTimePatternGenerator::createInstance(icu_locale, status));
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }

  UDateFormatHourCycle hc = generator->getDefaultHourCycle(status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  DirectHandle<String> hour_cycle;

  switch (hc) {
    case UDAT_HOUR_CYCLE_11:
      hour_cycle = factory->h11_string();
      break;
    case UDAT_HOUR_CYCLE_12:
      hour_cycle = factory->h12_string();
      break;
    case UDAT_HOUR_CYCLE_23:
      hour_cycle = factory->h23_string();
      break;
    case UDAT_HOUR_CYCLE_24:
      hour_cycle = factory->h24_string();
      break;
    default:
      break;
  }
  fixed_array->set(0, *hour_cycle);
  return factory->NewJSArrayWithElements(fixed_array);
}

MaybeHandle<JSArray> JSLocale::GetNumberingSystems(
    Isolate* isolate, DirectHandle<JSLocale> locale) {
  // Let preferred be loc.[[NumberingSystem]].

  // Let locale be loc.[[Locale]].
  icu::Locale icu_locale(*(locale->icu_locale()->raw()));
  Factory* factory = isolate->factory();

  // Assert: locale matches the unicode_locale_id production.

  // Let list be a List of 1 or more numbering system identifiers, which must be
  // String values conforming to the type sequence from UTS 35 Unicode Locale
  // Identifier, section 3.2, sorted in descending preference of those in common
  // use in the locale for formatting numeric values.

  // Return CreateArrayFromListAndPreferred( list, preferred ).
  UErrorCode status = U_ZERO_ERROR;
  DirectHandle<FixedArray> fixed_array = factory->NewFixedArray(1);
  std::string numbering_system =
      icu_locale.getUnicodeKeywordValue<std::string>("nu", status);
  if (numbering_system.empty()) {
    numbering_system = Intl::GetNumberingSystem(icu_locale);
  }
  DirectHandle<String> str =
      factory->NewStringFromAsciiChecked(numbering_system.c_str());

  fixed_array->set(0, *str);
  return factory->NewJSArrayWithElements(fixed_array);
}

MaybeHandle<Object> JSLocale::GetTimeZones(Isolate* isolate,
                                           DirectHandle<JSLocale> locale) {
  // Let loc be the this value.

  // Perform ? RequireInternalSlot(loc, [[InitializedLocale]])

  // Let locale be loc.[[Locale]].
  icu::Locale icu_locale(*(locale->icu_locale()->raw()));
  Factory* factory = isolate->factory();

  // If the unicode_language_id production of locale does not contain the
  // ["-" unicode_region_subtag] sequence, return undefined.
  const char* region = icu_locale.getCountry();
  if (region == nullptr || strlen(region) == 0) {
    return factory->undefined_value();
  }

  // Return TimeZonesOfLocale(loc).

  // Let locale be loc.[[Locale]].

  // Assert: locale matches the unicode_locale_id production.

  // Let region be the substring of locale corresponding to the
  // unicode_region_subtag production of the unicode_language_id.

  // Let list be a List of 1 or more time zone identifiers, which must be String
  // values indicating a Zone or Link name of the IANA Time Zone Database,
  // sorted in descending preference of those in common use in region.
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::StringEnumeration> enumeration(
      icu::TimeZone::createTimeZoneIDEnumeration(UCAL_ZONE_TYPE_CANONICAL,
                                                 region, nullptr, status));
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  return Intl::ToJSArray(isolate, nullptr, enumeration.get(), nullptr, true);
}

MaybeHandle<JSObject> JSLocale::GetTextInfo(Isolate* isolate,
                                            DirectHandle<JSLocale> locale) {
  // Let loc be the this value.

  // Perform ? RequireInternalSlot(loc, [[InitializedLocale]]).

  // Let locale be loc.[[Locale]].

  // Assert: locale matches the unicode_locale_id production.

  Factory* factory = isolate->factory();
  // Let info be ! ObjectCreate(%Object.prototype%).
  Handle<JSObject> info = factory->NewJSObject(isolate->object_function());

  // Let dir be "ltr".
  Handle<String> dir = locale->icu_locale()->raw()->isRightToLeft()
                           ? factory->rtl_string()
                           : factory->ltr_string();

  // Perform ! CreateDataPropertyOrThrow(info, "direction", dir).
  CHECK(JSReceiver::CreateDataProperty(
            isolate, info, factory->direction_string(), dir, Just(kDontThrow))
            .FromJust());

  // Return info.
  return info;
}

MaybeHandle<JSObject> JSLocale::GetWeekInfo(Isolate* isolate,
                                            DirectHandle<JSLocale> locale) {
  // Let loc be the this value.

  // Perform ? RequireInternalSlot(loc, [[InitializedLocale]]).

  // Let locale be loc.[[Locale]].

  // Assert: locale matches the unicode_locale_id production.
  Factory* factory = isolate->factory();

  // Let info be ! ObjectCreate(%Object.prototype%).
  Handle<JSObject> info = factory->NewJSObject(isolate->object_function());
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::Calendar> calendar(
      icu::Calendar::createInstance(*(locale->icu_locale()->raw()), status));
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }

  // Let fd be the weekday value indicating which day of the week is considered
  // the 'first' day, for calendar purposes, in the locale.
  int32_t fd = weekdayFromEDaysOfWeek(calendar->getFirstDayOfWeek());

  // Let wi be ! WeekInfoOfLocale(loc).
  // Let we be ! CreateArrayFromList( wi.[[Weekend]] ).
  Handle<FixedArray> wi = Cast<FixedArray>(factory->NewFixedArray(2));
  int32_t length = 0;
  for (int32_t i = 1; i <= 7; i++) {
    UCalendarDaysOfWeek day =
        (i == 7) ? UCAL_SUNDAY : static_cast<UCalendarDaysOfWeek>(i + 1);
    if (UCAL_WEEKDAY != calendar->getDayOfWeekType(day, status)) {
      wi->set(length++, Smi::FromInt(i));
      CHECK_LE(length, 2);
    }
  }
  if (length != 2) {
    wi = wi->RightTrimOrEmpty(isolate, wi, length);
  }
  Handle<JSArray> we = factory->NewJSArrayWithElements(wi);

  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }

  // Let md be the minimal days required in the first week of a month or year,
  // for calendar purposes, in the locale.
  int32_t md = calendar->getMinimalDaysInFirstWeek();

  // Perform ! CreateDataPropertyOrThrow(info, "firstDay", fd).
  CHECK(JSReceiver::CreateDataProperty(
            isolate, info, factory->firstDay_string(),
            factory->NewNumberFromInt(fd), Just(kDontThrow))
            .FromJust());

  // Perform ! CreateDataPropertyOrThrow(info, "weekend", we).
  CHECK(JSReceiver::CreateDataProperty(isolate, info, factory->weekend_string(),
                                       we, Just(kDontThrow))
            .FromJust());

  // Perform ! CreateDataPropertyOrThrow(info, "minimalDays", md).
  CHECK(JSReceiver::CreateDataProperty(
            isolate, info, factory->minimalDays_string(),
            factory->NewNumberFromInt(md), Just(kDontThrow))
            .FromJust());

  // Return info.
  return info;
}

Handle<Object> JSLocale::Language(Isolate* isolate,
                                  DirectHandle<JSLocale> locale) {
  Factory* factory = isolate->factory();
  const char* language = locale->icu_locale()->raw()->getLanguage();
  if (strlen(language) == 0) return factory->undefined_value();
  return factory->NewStringFromAsciiChecked(language);
}

Handle<Object> JSLocale::Script(Isolate* isolate,
                                DirectHandle<JSLocale> locale) {
  Factory* factory = isolate->factory();
  const char* script = locale->icu_locale()->raw()->getScript();
  if (strlen(script) == 0) return factory->undefined_value();
  return factory->NewStringFromAsciiChecked(script);
}

Handle<Object> JSLocale::Region(Isolate* isolate,
                                DirectHandle<JSLocale> locale) {
  Factory* factory = isolate->factory();
  const char* region = locale->icu_locale()->raw()->getCountry();
  if (strlen(region) == 0) return factory->undefined_value();
  return factory->NewStringFromAsciiChecked(region);
}

Handle<String> JSLocale::BaseName(Isolate* isolate,
                                  DirectHandle<JSLocale> locale) {
  icu::Locale icu_locale =
      icu::Locale::createFromName(locale->icu_locale()->raw()->getBaseName());
  std::string base_name = Intl::ToLanguageTag(icu_locale).FromJust();
  return isolate->factory()->NewStringFromAsciiChecked(base_name.c_str());
}

Handle<Object> JSLocale::Calendar(Isolate* isolate,
                                  DirectHandle<JSLocale> locale) {
  return UnicodeKeywordValue(isolate, locale, "ca");
}

Handle<Object> JSLocale::CaseFirst(Isolate* isolate,
                                   DirectHandle<JSLocale> locale) {
  return UnicodeKeywordValue(isolate, locale, "kf");
}

Handle<Object> JSLocale::Collation(Isolate* isolate,
                                   DirectHandle<JSLocale> locale) {
  return UnicodeKeywordValue(isolate, locale, "co");
}

Handle<Object> JSLocale::FirstDayOfWeek(Isolate* isolate,
                                        DirectHandle<JSLocale> locale) {
  return UnicodeKeywordValue(isolate, locale, "fw");
}
Handle<Object> JSLocale::HourCycle(Isolate* isolate,
                                   DirectHandle<JSLocale> locale) {
  return UnicodeKeywordValue(isolate, locale, "hc");
}

Handle<Object> JSLocale::Numeric(Isolate* isolate,
                                 DirectHandle<JSLocale> locale) {
  Factory* factory = isolate->factory();
  icu::Locale* icu_locale = locale->icu_locale()->raw();
  UErrorCode status = U_ZERO_ERROR;
  std::string numeric =
      icu_locale->getUnicodeKeywordValue<std::string>("kn", status);
  return factory->ToBoolean(numeric == "true");
}

Handle<Object> JSLocale::NumberingSystem(Isolate* isolate,
                                         DirectHandle<JSLocale> locale) {
  return UnicodeKeywordValue(isolate, locale, "nu");
}

std::string JSLocale::ToString(DirectHandle<JSLocale> locale) {
  icu::Locale* icu_locale = locale->icu_locale()->raw();
  return Intl::ToLanguageTag(*icu_locale).FromJust();
}

Handle<String> JSLocale::ToString(Isolate* isolate,
                                  DirectHandle<JSLocale> locale) {
  std::string locale_str = JSLocale::ToString(locale);
  return isolate->factory()->NewStringFromAsciiChecked(locale_str.c_str());
}

}  // namespace internal
}  // namespace v8

"""

```