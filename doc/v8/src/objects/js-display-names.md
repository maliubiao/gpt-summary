Response: Let's break down the thought process to understand this C++ code and connect it to JavaScript.

1. **Understand the Goal:** The request asks for the functionality of the C++ code and its relation to JavaScript, providing an example if possible. The file path `v8/src/objects/js-display-names.cc` strongly suggests this code implements the `Intl.DisplayNames` JavaScript API.

2. **Initial Scan and Key Observations:**

   * **Copyright and `#ifndef V8_INTL_SUPPORT`:**  Indicates this code is part of the V8 JavaScript engine and relies on internationalization support.
   * **Includes:**  The included headers (`src/objects/js-display-names.h`, `unicode/...`) point to interaction with V8's object system and the ICU library (International Components for Unicode). This confirms the internationalization aspect.
   * **Namespace `v8::internal`:** This is a V8 internal namespace, meaning it's not directly exposed to JavaScript.
   * **`JSDisplayNames` Class:** The central class in the file, likely representing the JavaScript `Intl.DisplayNames` object.
   * **`DisplayNamesInternal` Abstract Class:**  Suggests a strategy pattern for handling different display name types.
   * **Enums (e.g., `Type`, `Style`, `Fallback`, `LanguageDisplay`):**  These likely map to options available in the JavaScript `Intl.DisplayNames` constructor.
   * **ICU Usage:**  The code heavily utilizes ICU classes like `LocaleDisplayNames`, `DateTimePatternGenerator`, `LocaleBuilder`, etc. This is the core of the internationalization functionality.
   * **Methods like `New`, `ResolvedOptions`, `Of`:** These strongly suggest the implementation of the `Intl.DisplayNames` constructor and its methods.
   * **`GetStringOption`:** A utility function for retrieving and validating options, commonly used in V8's `Intl` implementations.
   * **`MaybeHandle` and `Handle`:** V8's garbage collection-aware pointer types.
   * **Error Handling (e.g., `THROW_NEW_ERROR_RETURN_VALUE`):** Indicates how errors are reported back to JavaScript.

3. **Deconstruct the `DisplayNamesInternal` Hierarchy:**  The abstract base class `DisplayNamesInternal` and its derived classes (`LanguageNames`, `RegionNames`, `ScriptNames`, `CurrencyNames`, `CalendarNames`, `DateTimeFieldNames`) are crucial. Each derived class handles a specific `type` option for `Intl.DisplayNames`.

4. **Focus on the `of` Method:**  This method is responsible for actually retrieving the display name. Observe how each derived class implements `of` using the appropriate ICU functionality:
   * `LanguageNames`: Uses `localeDisplayName` with a language tag.
   * `RegionNames`: Uses `regionDisplayName`.
   * `ScriptNames`: Uses `scriptDisplayName`.
   * `CurrencyNames`: Uses `keyValueDisplayName` with "currency".
   * `CalendarNames`: Uses `keyValueDisplayName` with "calendar".
   * `DateTimeFieldNames`: Uses `getFieldDisplayName`.

5. **Connect to JavaScript `Intl.DisplayNames`:**  Realize that the C++ enums (`Type`, `Style`, `Fallback`, `LanguageDisplay`) directly correspond to the options passed to the `Intl.DisplayNames` constructor in JavaScript. The `of` method in C++ implements the functionality of the `Intl.DisplayNames.prototype.of()` method in JavaScript.

6. **Analyze the `New` Method:** This method corresponds to the `Intl.DisplayNames` constructor. Notice the steps:
   * **Canonicalize Locale List:**  `Intl::CanonicalizeLocaleList` mirrors the JavaScript function of the same name.
   * **Get Options Object:**  `GetOptionsObject` handles processing the options argument.
   * **Get Locale Matcher:**  `Intl::GetLocaleMatcher` deals with the `localeMatcher` option.
   * **Resolve Locale:** `Intl::ResolveLocale` performs locale negotiation.
   * **Get Option for `style`, `type`, `fallback`, `languageDisplay`:**  These extract the option values from the JavaScript object.
   * **Create Internal Object:** The `CreateInternal` function creates the appropriate `DisplayNamesInternal` subclass based on the `type`.
   * **Store Internal Object:** The created internal object is stored within the `JSDisplayNames` instance.

7. **Analyze `ResolvedOptions`:** This method implements `Intl.DisplayNames.prototype.resolvedOptions()`, returning an object with the resolved options.

8. **Construct the JavaScript Example:**  Based on the understanding of the C++ code, create a JavaScript example that demonstrates the usage of `Intl.DisplayNames` and how its options map to the C++ implementation. Choose a few key examples to illustrate different types and styles.

9. **Summarize the Functionality:** Concisely describe the purpose of the C++ file, focusing on its role in implementing the `Intl.DisplayNames` API. Highlight the connection between JavaScript options and the underlying C++ logic, particularly the use of the ICU library.

10. **Review and Refine:**  Read through the explanation and the JavaScript example to ensure accuracy and clarity. Check for any inconsistencies or areas that could be explained better. For instance, explicitly mentioning the role of ICU and how V8 bridges the gap between JavaScript and ICU is important. Also, emphasize the internal nature of the C++ code and its relationship to the exposed JavaScript API.
这个C++源代码文件 `js-display-names.cc` 是 V8 JavaScript 引擎的一部分，**主要负责实现 JavaScript 中 `Intl.DisplayNames` API 的功能。**

**功能归纳:**

1. **提供本地化的名称显示:**  它使用 ICU (International Components for Unicode) 库来获取各种对象的本地化名称，例如：
    * 语言名称 (例如 "英文"、"法语")
    * 地区名称 (例如 "美国"、"中国")
    * 脚本名称 (例如 "拉丁文"、"西里尔文")
    * 货币名称 (例如 "美元"、"人民币")
    * 日历名称 (例如 "公历"、"佛历")
    * 日期时间字段名称 (例如 "年"、"月"、"日")

2. **实现 `Intl.DisplayNames` 构造函数:**  `JSDisplayNames::New` 方法处理 `Intl.DisplayNames` 对象的创建，包括：
    * 解析传入的 `locales` 和 `options` 参数。
    * 进行本地化协商，确定最合适的语言环境。
    * 根据 `options` 中的 `type` 和 `style` 参数，创建不同的内部处理对象 (`DisplayNamesInternal` 的子类)。
    * 存储必要的内部状态，例如语言环境、样式、类型等。

3. **实现 `Intl.DisplayNames.prototype.resolvedOptions()` 方法:**  `JSDisplayNames::ResolvedOptions` 方法返回一个包含已解析的选项的对象，这些选项是创建 `Intl.DisplayNames` 对象时最终生效的设置。

4. **实现 `Intl.DisplayNames.prototype.of()` 方法:**  `JSDisplayNames::Of` 方法是核心功能，它接收一个代码 (例如语言代码、地区代码等)，并返回该代码在当前 `Intl.DisplayNames` 对象语言环境和样式下的本地化名称。

5. **使用 ICU 库:**  该文件大量使用 ICU 库提供的功能，例如 `LocaleDisplayNames` (用于获取语言、地区、脚本名称)、`DateTimePatternGenerator` (用于获取日期时间字段名称) 等，来实现本地化名称的查找。

**与 JavaScript 的关系及示例:**

该文件是 JavaScript `Intl.DisplayNames` API 在 V8 引擎中的底层实现。JavaScript 代码调用 `Intl.DisplayNames` API 时，最终会调用到这个 C++ 文件中的相应方法。

**JavaScript 示例:**

```javascript
// 创建一个显示语言名称的 Intl.DisplayNames 实例，使用中文环境，显示长名称
const languageNames = new Intl.DisplayNames('zh-CN', { type: 'language', style: 'long' });

console.log(languageNames.of('en')); // 输出 "英文"
console.log(languageNames.of('fr')); // 输出 "法文"
console.log(languageNames.of('ja')); // 输出 "日文"

// 创建一个显示地区名称的 Intl.DisplayNames 实例，使用英文环境，显示短名称
const regionNames = new Intl.DisplayNames('en-US', { type: 'region', style: 'short' });

console.log(regionNames.of('US')); // 输出 "US"
console.log(regionNames.of('CN')); // 输出 "CN"
console.log(regionNames.of('JP')); // 输出 "JP"

// 创建一个显示货币名称的 Intl.DisplayNames 实例，使用德文环境，显示窄名称
const currencyNames = new Intl.DisplayNames('de-DE', { type: 'currency', style: 'narrow' });

console.log(currencyNames.of('USD')); // 输出 "$"
console.log(currencyNames.of('EUR')); // 输出 "€"
console.log(currencyNames.of('JPY')); // 输出 "¥"

// 创建一个显示日历名称的 Intl.DisplayNames 实例，使用英文环境，显示长名称
const calendarNames = new Intl.DisplayNames('en-US', { type: 'calendar', style: 'long' });

console.log(calendarNames.of('gregory')); // 输出 "Gregorian Calendar"
console.log(calendarNames.of('buddhist')); // 输出 "Buddhist Calendar"

// 创建一个显示日期时间字段名称的 Intl.DisplayNames 实例，使用英文环境，显示短名称
const dateTimeFieldNames = new Intl.DisplayNames('en-US', { type: 'dateTimeField', style: 'short' });

console.log(dateTimeFieldNames.of('year')); // 输出 "yr."
console.log(dateTimeFieldNames.of('month')); // 输出 "mo."
console.log(dateTimeFieldNames.of('day'));   // 输出 "day"

// 获取已解析的选项
const resolvedOptions = languageNames.resolvedOptions();
console.log(resolvedOptions); // 输出类似: { locale: "zh-CN", style: "long", type: "language", fallback: "code" }
```

**总结:**

`js-display-names.cc` 文件是 V8 引擎中 `Intl.DisplayNames` API 的核心 C++ 实现，它利用 ICU 库提供的国际化功能，将 JavaScript 中对本地化名称的请求转化为实际的本地化文本输出。它负责对象的创建、选项解析、本地化协商以及最终的名称获取。

### 提示词
```
这是目录为v8/src/objects/js-display-names.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

#include "src/objects/js-display-names.h"

#include <memory>
#include <vector>

#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/objects/intl-objects.h"
#include "src/objects/js-display-names-inl.h"
#include "src/objects/js-locale.h"
#include "src/objects/managed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/option-utils.h"
#include "unicode/dtfmtsym.h"
#include "unicode/dtptngen.h"
#include "unicode/localebuilder.h"
#include "unicode/locdspnm.h"
#include "unicode/measfmt.h"
#include "unicode/timezone.h"
#include "unicode/tznames.h"
#include "unicode/uloc.h"
#include "unicode/unistr.h"
#include "unicode/uscript.h"

namespace v8 {
namespace internal {

namespace {
// Type: identifying the types of the display names.
//
// ecma402/#sec-properties-of-intl-displaynames-instances
enum class Type {
  kUndefined,
  kLanguage,
  kRegion,
  kScript,
  kCurrency,
  kCalendar,
  kDateTimeField
};

bool IsUnicodeScriptSubtag(const std::string& value) {
  UErrorCode status = U_ZERO_ERROR;
  icu::LocaleBuilder builder;
  builder.setScript(value).build(status);
  return U_SUCCESS(status);
}

bool IsUnicodeRegionSubtag(const std::string& value) {
  if (value.empty()) return false;
  UErrorCode status = U_ZERO_ERROR;
  icu::LocaleBuilder builder;
  builder.setRegion(value).build(status);
  return U_SUCCESS(status);
}

UDisplayContext ToUDisplayContext(JSDisplayNames::Style style) {
  switch (style) {
    case JSDisplayNames::Style::kLong:
      return UDISPCTX_LENGTH_FULL;
    case JSDisplayNames::Style::kShort:
    case JSDisplayNames::Style::kNarrow:
      return UDISPCTX_LENGTH_SHORT;
  }
}

}  // anonymous namespace

// Abstract class for all different types.
class DisplayNamesInternal {
 public:
  static constexpr ExternalPointerTag kManagedTag = kDisplayNamesInternalTag;

  DisplayNamesInternal() = default;
  virtual ~DisplayNamesInternal() = default;
  virtual const char* type() const = 0;
  virtual icu::Locale locale() const = 0;
  virtual Maybe<icu::UnicodeString> of(Isolate* isolate,
                                       const char* code) const = 0;
};

namespace {

class LocaleDisplayNamesCommon : public DisplayNamesInternal {
 public:
  LocaleDisplayNamesCommon(const icu::Locale& locale,
                           JSDisplayNames::Style style, bool fallback,
                           bool dialect)
      : style_(style) {
    UDisplayContext sub =
        fallback ? UDISPCTX_SUBSTITUTE : UDISPCTX_NO_SUBSTITUTE;
    UDisplayContext dialect_context =
        dialect ? UDISPCTX_DIALECT_NAMES : UDISPCTX_STANDARD_NAMES;
    UDisplayContext display_context[] = {ToUDisplayContext(style_),
                                         dialect_context,
                                         UDISPCTX_CAPITALIZATION_NONE, sub};
    ldn_.reset(
        icu::LocaleDisplayNames::createInstance(locale, display_context, 4));
  }

  ~LocaleDisplayNamesCommon() override = default;

  icu::Locale locale() const override { return ldn_->getLocale(); }

 protected:
  icu::LocaleDisplayNames* locale_display_names() const { return ldn_.get(); }

 private:
  std::unique_ptr<icu::LocaleDisplayNames> ldn_;
  JSDisplayNames::Style style_;
};

class LanguageNames : public LocaleDisplayNamesCommon {
 public:
  LanguageNames(const icu::Locale& locale, JSDisplayNames::Style style,
                bool fallback, bool dialect)
      : LocaleDisplayNamesCommon(locale, style, fallback, dialect) {}

  ~LanguageNames() override = default;

  const char* type() const override { return "language"; }

  Maybe<icu::UnicodeString> of(Isolate* isolate,
                               const char* code) const override {
    UErrorCode status = U_ZERO_ERROR;
    // 1.a If code does not match the unicode_language_id production, throw a
    // RangeError exception.
    icu::Locale tagLocale = icu::Locale::forLanguageTag(code, status);
    icu::Locale l(tagLocale.getBaseName());
    if (U_FAILURE(status) || tagLocale != l ||
        !JSLocale::StartsWithUnicodeLanguageId(code)) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate, NewRangeError(MessageTemplate::kInvalidArgument),
          Nothing<icu::UnicodeString>());
    }

    // 1.b If IsStructurallyValidLanguageTag(code) is false, throw a RangeError
    // exception.

    // 1.c Set code to CanonicalizeUnicodeLocaleId(code).
    l.canonicalize(status);
    std::string checked = l.toLanguageTag<std::string>(status);

    if (U_FAILURE(status)) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate, NewRangeError(MessageTemplate::kInvalidArgument),
          Nothing<icu::UnicodeString>());
    }

    icu::UnicodeString result;
    locale_display_names()->localeDisplayName(checked.c_str(), result);

    return Just(result);
  }
};

class RegionNames : public LocaleDisplayNamesCommon {
 public:
  RegionNames(const icu::Locale& locale, JSDisplayNames::Style style,
              bool fallback, bool dialect)
      : LocaleDisplayNamesCommon(locale, style, fallback, dialect) {}

  ~RegionNames() override = default;

  const char* type() const override { return "region"; }

  Maybe<icu::UnicodeString> of(Isolate* isolate,
                               const char* code) const override {
    std::string code_str(code);
    if (!IsUnicodeRegionSubtag(code_str)) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate, NewRangeError(MessageTemplate::kInvalidArgument),
          Nothing<icu::UnicodeString>());
    }

    icu::UnicodeString result;
    locale_display_names()->regionDisplayName(code_str.c_str(), result);
    return Just(result);
  }
};

class ScriptNames : public LocaleDisplayNamesCommon {
 public:
  ScriptNames(const icu::Locale& locale, JSDisplayNames::Style style,
              bool fallback, bool dialect)
      : LocaleDisplayNamesCommon(locale, style, fallback, dialect) {}

  ~ScriptNames() override = default;

  const char* type() const override { return "script"; }

  Maybe<icu::UnicodeString> of(Isolate* isolate,
                               const char* code) const override {
    std::string code_str(code);
    if (!IsUnicodeScriptSubtag(code_str)) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate, NewRangeError(MessageTemplate::kInvalidArgument),
          Nothing<icu::UnicodeString>());
    }

    icu::UnicodeString result;
    locale_display_names()->scriptDisplayName(code_str.c_str(), result);
    return Just(result);
  }
};

class KeyValueDisplayNames : public LocaleDisplayNamesCommon {
 public:
  KeyValueDisplayNames(const icu::Locale& locale, JSDisplayNames::Style style,
                       bool fallback, bool dialect, const char* key,
                       bool prevent_fallback)
      : LocaleDisplayNamesCommon(locale, style, fallback, dialect),
        key_(key),
        prevent_fallback_(prevent_fallback) {}

  ~KeyValueDisplayNames() override = default;

  const char* type() const override { return key_.c_str(); }

  Maybe<icu::UnicodeString> of(Isolate* isolate,
                               const char* code) const override {
    std::string code_str(code);
    icu::UnicodeString result;
    locale_display_names()->keyValueDisplayName(key_.c_str(), code_str.c_str(),
                                                result);
    // Work around the issue that the keyValueDisplayNames ignore no
    // substituion and always fallback.
    if (prevent_fallback_ && (result.length() == 3) &&
        (code_str.length() == 3) &&
        (result == icu::UnicodeString(code_str.c_str(), -1, US_INV))) {
      result.setToBogus();
    }

    return Just(result);
  }

 private:
  std::string key_;
  bool prevent_fallback_;
};

class CurrencyNames : public KeyValueDisplayNames {
 public:
  CurrencyNames(const icu::Locale& locale, JSDisplayNames::Style style,
                bool fallback, bool dialect)
      : KeyValueDisplayNames(locale, style, fallback, dialect, "currency",
                             fallback == false) {}

  ~CurrencyNames() override = default;

  Maybe<icu::UnicodeString> of(Isolate* isolate,
                               const char* code) const override {
    std::string code_str(code);
    if (!Intl::IsWellFormedCurrency(code_str)) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate, NewRangeError(MessageTemplate::kInvalidArgument),
          Nothing<icu::UnicodeString>());
    }
    return KeyValueDisplayNames::of(isolate, code);
  }
};

class CalendarNames : public KeyValueDisplayNames {
 public:
  CalendarNames(const icu::Locale& locale, JSDisplayNames::Style style,
                bool fallback, bool dialect)
      : KeyValueDisplayNames(locale, style, fallback, dialect, "calendar",
                             false) {}

  ~CalendarNames() override = default;

  Maybe<icu::UnicodeString> of(Isolate* isolate,
                               const char* code) const override {
    std::string code_str(code);
    if (!Intl::IsWellFormedCalendar(code_str)) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate, NewRangeError(MessageTemplate::kInvalidArgument),
          Nothing<icu::UnicodeString>());
    }
    return KeyValueDisplayNames::of(isolate, strcmp(code, "gregory") == 0
                                                 ? "gregorian"
                                                 : strcmp(code, "ethioaa") == 0
                                                       ? "ethiopic-amete-alem"
                                                       : code);
  }
};

UDateTimePGDisplayWidth StyleToUDateTimePGDisplayWidth(
    JSDisplayNames::Style style) {
  switch (style) {
    case JSDisplayNames::Style::kLong:
      return UDATPG_WIDE;
    case JSDisplayNames::Style::kShort:
      return UDATPG_ABBREVIATED;
    case JSDisplayNames::Style::kNarrow:
      return UDATPG_NARROW;
  }
}

UDateTimePatternField StringToUDateTimePatternField(const char* code) {
  switch (code[0]) {
    case 'd':
      if (strcmp(code, "day") == 0) return UDATPG_DAY_FIELD;
      if (strcmp(code, "dayPeriod") == 0) return UDATPG_DAYPERIOD_FIELD;
      break;
    case 'e':
      if (strcmp(code, "era") == 0) return UDATPG_ERA_FIELD;
      break;
    case 'h':
      if (strcmp(code, "hour") == 0) return UDATPG_HOUR_FIELD;
      break;
    case 'm':
      if (strcmp(code, "minute") == 0) return UDATPG_MINUTE_FIELD;
      if (strcmp(code, "month") == 0) return UDATPG_MONTH_FIELD;
      break;
    case 'q':
      if (strcmp(code, "quarter") == 0) return UDATPG_QUARTER_FIELD;
      break;
    case 's':
      if (strcmp(code, "second") == 0) return UDATPG_SECOND_FIELD;
      break;
    case 't':
      if (strcmp(code, "timeZoneName") == 0) return UDATPG_ZONE_FIELD;
      break;
    case 'w':
      if (strcmp(code, "weekOfYear") == 0) return UDATPG_WEEK_OF_YEAR_FIELD;
      if (strcmp(code, "weekday") == 0) return UDATPG_WEEKDAY_FIELD;
      break;
    case 'y':
      if (strcmp(code, "year") == 0) return UDATPG_YEAR_FIELD;
      break;
    default:
      break;
  }
  return UDATPG_FIELD_COUNT;
}

class DateTimeFieldNames : public DisplayNamesInternal {
 public:
  DateTimeFieldNames(const icu::Locale& locale, JSDisplayNames::Style style,
                     bool fallback)
      : locale_(locale), width_(StyleToUDateTimePGDisplayWidth(style)) {
    UErrorCode status = U_ZERO_ERROR;
    generator_.reset(
        icu::DateTimePatternGenerator::createInstance(locale_, status));
    DCHECK(U_SUCCESS(status));
  }

  ~DateTimeFieldNames() override = default;

  const char* type() const override { return "dateTimeField"; }

  icu::Locale locale() const override { return locale_; }

  Maybe<icu::UnicodeString> of(Isolate* isolate,
                               const char* code) const override {
    UDateTimePatternField field = StringToUDateTimePatternField(code);
    if (field == UDATPG_FIELD_COUNT) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate, NewRangeError(MessageTemplate::kInvalidArgument),
          Nothing<icu::UnicodeString>());
    }
    return Just(generator_->getFieldDisplayName(field, width_));
  }

 private:
  icu::Locale locale_;
  UDateTimePGDisplayWidth width_;
  std::unique_ptr<icu::DateTimePatternGenerator> generator_;
};

DisplayNamesInternal* CreateInternal(const icu::Locale& locale,
                                     JSDisplayNames::Style style, Type type,
                                     bool fallback, bool dialect) {
  switch (type) {
    case Type::kLanguage:
      return new LanguageNames(locale, style, fallback, dialect);
    case Type::kRegion:
      return new RegionNames(locale, style, fallback, false);
    case Type::kScript:
      return new ScriptNames(locale, style, fallback, false);
    case Type::kCurrency:
      return new CurrencyNames(locale, style, fallback, false);
    case Type::kCalendar:
      return new CalendarNames(locale, style, fallback, false);
    case Type::kDateTimeField:
      return new DateTimeFieldNames(locale, style, fallback);
    default:
      UNREACHABLE();
  }
}

}  // anonymous namespace

// ecma402 #sec-Intl.DisplayNames
MaybeHandle<JSDisplayNames> JSDisplayNames::New(Isolate* isolate,
                                                DirectHandle<Map> map,
                                                Handle<Object> locales,
                                                Handle<Object> input_options) {
  const char* service = "Intl.DisplayNames";
  Factory* factory = isolate->factory();

  Handle<JSReceiver> options;
  // 3. Let requestedLocales be ? CanonicalizeLocaleList(locales).
  Maybe<std::vector<std::string>> maybe_requested_locales =
      Intl::CanonicalizeLocaleList(isolate, locales);
  MAYBE_RETURN(maybe_requested_locales, Handle<JSDisplayNames>());
  std::vector<std::string> requested_locales =
      maybe_requested_locales.FromJust();

  // 4. Let options be ? GetOptionsObject(options).
  ASSIGN_RETURN_ON_EXCEPTION(isolate, options,
                             GetOptionsObject(isolate, input_options, service));

  // Note: No need to create a record. It's not observable.
  // 5. Let opt be a new Record.

  // 6. Let localeData be %DisplayNames%.[[LocaleData]].

  // 7. Let matcher be ? GetOption(options, "localeMatcher", "string", «
  // "lookup", "best fit" », "best fit").
  Maybe<Intl::MatcherOption> maybe_locale_matcher =
      Intl::GetLocaleMatcher(isolate, options, service);
  MAYBE_RETURN(maybe_locale_matcher, MaybeHandle<JSDisplayNames>());

  // 8. Set opt.[[localeMatcher]] to matcher.
  Intl::MatcherOption matcher = maybe_locale_matcher.FromJust();

  // ecma402/#sec-Intl.DisplayNames-internal-slots
  // The value of the [[RelevantExtensionKeys]] internal slot is
  // «  ».
  std::set<std::string> relevant_extension_keys = {};
  // 9. Let r be ResolveLocale(%DisplayNames%.[[AvailableLocales]],
  //     requestedLocales, opt, %DisplayNames%.[[RelevantExtensionKeys]]).
  Maybe<Intl::ResolvedLocale> maybe_resolve_locale =
      Intl::ResolveLocale(isolate, JSDisplayNames::GetAvailableLocales(),
                          requested_locales, matcher, relevant_extension_keys);
  if (maybe_resolve_locale.IsNothing()) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  Intl::ResolvedLocale r = maybe_resolve_locale.FromJust();

  icu::Locale icu_locale = r.icu_locale;

  // 10. Let s be ? GetOption(options, "style", "string",
  //                          «"long", "short", "narrow"», "long").
  Maybe<Style> maybe_style = GetStringOption<Style>(
      isolate, options, "style", service, {"long", "short", "narrow"},
      {Style::kLong, Style::kShort, Style::kNarrow}, Style::kLong);
  MAYBE_RETURN(maybe_style, MaybeHandle<JSDisplayNames>());
  Style style_enum = maybe_style.FromJust();

  // 11. Set displayNames.[[Style]] to style.

  // 12. Let type be ? GetOption(options, "type", "string", « "language",
  // "region", "script", "currency" , "calendar", "dateTimeField", "unit"»,
  // undefined).
  Maybe<Type> maybe_type = GetStringOption<Type>(
      isolate, options, "type", service,
      {"language", "region", "script", "currency", "calendar", "dateTimeField"},
      {Type::kLanguage, Type::kRegion, Type::kScript, Type::kCurrency,
       Type::kCalendar, Type::kDateTimeField},
      Type::kUndefined);
  MAYBE_RETURN(maybe_type, MaybeHandle<JSDisplayNames>());
  Type type_enum = maybe_type.FromJust();

  // 13. If type is undefined, throw a TypeError exception.
  if (type_enum == Type::kUndefined) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kInvalidArgument));
  }

  // 14. Set displayNames.[[Type]] to type.

  // 15. Let fallback be ? GetOption(options, "fallback", "string",
  //     « "code", "none" », "code").
  Maybe<Fallback> maybe_fallback = GetStringOption<Fallback>(
      isolate, options, "fallback", service, {"code", "none"},
      {Fallback::kCode, Fallback::kNone}, Fallback::kCode);
  MAYBE_RETURN(maybe_fallback, MaybeHandle<JSDisplayNames>());
  Fallback fallback_enum = maybe_fallback.FromJust();

  // 16. Set displayNames.[[Fallback]] to fallback.

  LanguageDisplay language_display_enum = LanguageDisplay::kDialect;
  // 24. Let languageDisplay be ? GetOption(options, "languageDisplay",
  // "string", « "dialect", "standard" », "dialect").
  Maybe<LanguageDisplay> maybe_language_display =
      GetStringOption<LanguageDisplay>(
          isolate, options, "languageDisplay", service, {"dialect", "standard"},
          {LanguageDisplay::kDialect, LanguageDisplay::kStandard},
          LanguageDisplay::kDialect);
  MAYBE_RETURN(maybe_language_display, MaybeHandle<JSDisplayNames>());
  // 25. If type is "language", then
  if (type_enum == Type::kLanguage) {
    // a. Set displayNames.[[LanguageDisplay]] to languageDisplay.
    language_display_enum = maybe_language_display.FromJust();
  }

  // Set displayNames.[[Fallback]] to fallback.

  // 17. Set displayNames.[[Locale]] to the value of r.[[Locale]].

  // Let dataLocale be r.[[dataLocale]].

  // Let dataLocaleData be localeData.[[<dataLocale>]].

  // Let types be dataLocaleData.[[types]].

  // Assert: types is a Record (see 1.3.3).

  // Let typeFields be types.[[<type>]].

  // Assert: typeFields is a Record (see 1.3.3).

  // Let styleFields be typeFields.[[<style>]].

  // Assert: styleFields is a Record (see 1.3.3).

  // Set displayNames.[[Fields]] to styleFields.

  std::shared_ptr<DisplayNamesInternal> internal{CreateInternal(
      icu_locale, style_enum, type_enum, fallback_enum == Fallback::kCode,
      language_display_enum == LanguageDisplay::kDialect)};
  if (internal == nullptr) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }

  DirectHandle<Managed<DisplayNamesInternal>> managed_internal =
      Managed<DisplayNamesInternal>::From(isolate, 0, std::move(internal));

  Handle<JSDisplayNames> display_names =
      Cast<JSDisplayNames>(factory->NewFastOrSlowJSObjectFromMap(map));
  display_names->set_flags(0);
  display_names->set_style(style_enum);
  display_names->set_fallback(fallback_enum);
  display_names->set_language_display(language_display_enum);

  DisallowGarbageCollection no_gc;
  display_names->set_internal(*managed_internal);

  // Return displayNames.
  return display_names;
}

// ecma402 #sec-Intl.DisplayNames.prototype.resolvedOptions
Handle<JSObject> JSDisplayNames::ResolvedOptions(
    Isolate* isolate, DirectHandle<JSDisplayNames> display_names) {
  Factory* factory = isolate->factory();
  // 4. Let options be ! ObjectCreate(%ObjectPrototype%).
  Handle<JSObject> options = factory->NewJSObject(isolate->object_function());

  DisplayNamesInternal* internal = display_names->internal()->raw();

  Maybe<std::string> maybe_locale = Intl::ToLanguageTag(internal->locale());
  DCHECK(maybe_locale.IsJust());
  Handle<String> locale = isolate->factory()->NewStringFromAsciiChecked(
      maybe_locale.FromJust().c_str());
  Handle<String> style = display_names->StyleAsString();
  Handle<String> type = factory->NewStringFromAsciiChecked(internal->type());
  Handle<String> fallback = display_names->FallbackAsString();
  Handle<String> language_display = display_names->LanguageDisplayAsString();

  Maybe<bool> maybe_create_locale = JSReceiver::CreateDataProperty(
      isolate, options, factory->locale_string(), locale, Just(kDontThrow));
  DCHECK(maybe_create_locale.FromJust());
  USE(maybe_create_locale);

  Maybe<bool> maybe_create_style = JSReceiver::CreateDataProperty(
      isolate, options, factory->style_string(), style, Just(kDontThrow));
  DCHECK(maybe_create_style.FromJust());
  USE(maybe_create_style);

  Maybe<bool> maybe_create_type = JSReceiver::CreateDataProperty(
      isolate, options, factory->type_string(), type, Just(kDontThrow));
  DCHECK(maybe_create_type.FromJust());
  USE(maybe_create_type);

  Maybe<bool> maybe_create_fallback = JSReceiver::CreateDataProperty(
      isolate, options, factory->fallback_string(), fallback, Just(kDontThrow));
  DCHECK(maybe_create_fallback.FromJust());
  USE(maybe_create_fallback);

    if (std::strcmp("language", internal->type()) == 0) {
      Maybe<bool> maybe_create_language_display =
          JSReceiver::CreateDataProperty(isolate, options,
                                         factory->languageDisplay_string(),
                                         language_display, Just(kDontThrow));
      DCHECK(maybe_create_language_display.FromJust());
      USE(maybe_create_language_display);
    }

  return options;
}

// ecma402 #sec-Intl.DisplayNames.prototype.of
MaybeHandle<Object> JSDisplayNames::Of(
    Isolate* isolate, DirectHandle<JSDisplayNames> display_names,
    Handle<Object> code_obj) {
  Handle<String> code;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, code,
                             Object::ToString(isolate, code_obj));
  DisplayNamesInternal* internal = display_names->internal()->raw();
  Maybe<icu::UnicodeString> maybe_result =
      internal->of(isolate, code->ToCString().get());
  MAYBE_RETURN(maybe_result, Handle<Object>());
  icu::UnicodeString result = maybe_result.FromJust();
  if (result.isBogus()) {
    return isolate->factory()->undefined_value();
  }
  return Intl::ToString(isolate, result).ToHandleChecked();
}

namespace {

struct CheckCalendar {
  static const char* key() { return "calendar"; }
  static const char* path() { return nullptr; }
};

}  // namespace

const std::set<std::string>& JSDisplayNames::GetAvailableLocales() {
  static base::LazyInstance<Intl::AvailableLocales<CheckCalendar>>::type
      available_locales = LAZY_INSTANCE_INITIALIZER;
  return available_locales.Pointer()->Get();
}

Handle<String> JSDisplayNames::StyleAsString() const {
  switch (style()) {
    case Style::kLong:
      return GetReadOnlyRoots().long_string_handle();
    case Style::kShort:
      return GetReadOnlyRoots().short_string_handle();
    case Style::kNarrow:
      return GetReadOnlyRoots().narrow_string_handle();
  }
  UNREACHABLE();
}

Handle<String> JSDisplayNames::FallbackAsString() const {
  switch (fallback()) {
    case Fallback::kCode:
      return GetReadOnlyRoots().code_string_handle();
    case Fallback::kNone:
      return GetReadOnlyRoots().none_string_handle();
  }
  UNREACHABLE();
}

Handle<String> JSDisplayNames::LanguageDisplayAsString() const {
  switch (language_display()) {
    case LanguageDisplay::kDialect:
      return GetReadOnlyRoots().dialect_string_handle();
    case LanguageDisplay::kStandard:
      return GetReadOnlyRoots().standard_string_handle();
  }
  UNREACHABLE();
}

}  // namespace internal
}  // namespace v8
```