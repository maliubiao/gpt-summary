Response: The user wants to understand the functionality of the C++ code provided, specifically the `v8/src/objects/js-plural-rules.cc` file. I need to summarize its purpose and illustrate its connection to JavaScript using a concrete example.

Here's a breakdown of the code's responsibilities and how it relates to JavaScript's `Intl.PluralRules` object:

1. **Core Functionality:** The code is responsible for implementing the core logic behind JavaScript's `Intl.PluralRules` API within the V8 JavaScript engine. This involves determining the correct plural form of a number based on the provided locale and options.

2. **ICU Integration:** It heavily relies on the International Components for Unicode (ICU) library for handling locale-specific pluralization rules. This includes creating `icu::PluralRules` objects for different locales and plural types (cardinal and ordinal).

3. **Locale Handling:**  The code handles locale negotiation and canonicalization, ensuring that the correct pluralization rules are applied for the specified language.

4. **Options Processing:**  It processes options provided to the `Intl.PluralRules` constructor, such as `localeMatcher` and `type`.

5. **Number Formatting:** It integrates with V8's number formatting capabilities, using `icu::number::LocalizedNumberFormatter` to format numbers before applying plural rules. This is important because plural rules can depend on the formatted representation of the number.

6. **Plural Category Resolution:** The central function is `ResolvePlural`, which takes a number and determines its plural category (e.g., "one", "few", "many", "other") according to the locale's rules. `ResolvePluralRange` handles pluralization for number ranges.

7. **Resolved Options:** The `ResolvedOptions` function returns an object containing the resolved options of the `Intl.PluralRules` instance, reflecting the chosen locale and other settings.

8. **Available Locales:** It provides a way to retrieve the list of locales for which pluralization rules are available.

**JavaScript Connection and Example:**

The C++ code directly implements the behavior exposed by the JavaScript `Intl.PluralRules` object. When you create an `Intl.PluralRules` instance in JavaScript and call its `select()` method, the execution eventually reaches the C++ code in this file to perform the actual plural rule evaluation using ICU.

I will construct a JavaScript example that demonstrates how the `Intl.PluralRules` API utilizes the underlying C++ implementation to determine the plural category for different numbers in a specific locale.
这个C++源代码文件 `v8/src/objects/js-plural-rules.cc` 的主要功能是**实现了 JavaScript 中 `Intl.PluralRules` 对象的底层逻辑**。它负责根据指定的语言环境（locale）和选项，将一个数字映射到其对应的复数形式类别（例如 "zero"、"one"、"two"、"few"、"many"、"other"）。

具体来说，这个文件做了以下几件事：

1. **创建 `icu::PluralRules` 对象:**  它使用 ICU (International Components for Unicode) 库来获取特定语言环境的复数规则。`icu::PluralRules` 是 ICU 库中用于处理复数形式的核心类。
2. **处理构造函数选项:**  `JSPluralRules::New` 函数负责处理 `Intl.PluralRules` 构造函数传入的 `locales` 和 `options` 参数，例如 `localeMatcher`（用于选择最佳匹配的语言环境）和 `type`（指定是处理基数 (cardinal) 还是序数 (ordinal) 复数）。
3. **解析语言环境:**  它使用 `Intl::ResolveLocale` 来解析和选择最合适的语言环境。
4. **数字格式化:**  在确定复数形式之前，它使用 `icu::number::LocalizedNumberFormatter` 来格式化输入的数字。这很重要，因为某些语言的复数规则可能依赖于数字的特定格式。
5. **确定复数形式:** `JSPluralRules::ResolvePlural` 函数是核心，它接收一个数字，并使用 ICU 的 `icu::PluralRules::select` 方法来根据当前语言环境的规则确定该数字的复数形式类别。`JSPluralRules::ResolvePluralRange` 类似，但处理的是数字范围。
6. **返回已解析的选项:** `JSPluralRules::ResolvedOptions` 函数返回一个包含已解析的 `Intl.PluralRules` 选项的对象，例如实际使用的 `locale` 和 `type`，以及从 ICU 获取的 `pluralCategories`（该语言环境所有可能的复数类别）。
7. **管理可用语言环境:**  它维护并提供可用复数规则的语言环境列表。

**与 JavaScript 功能的关系及示例：**

`v8/src/objects/js-plural-rules.cc` 中实现的逻辑直接支持 JavaScript 的 `Intl.PluralRules` API。当你创建一个 `Intl.PluralRules` 实例并在 JavaScript 中调用其 `select()` 方法时，V8 引擎最终会调用这个 C++ 文件中的相应函数来完成实际的复数形式判断。

**JavaScript 示例：**

```javascript
// 创建一个针对英语（美国）的基数复数规则实例
const pluralRulesEN = new Intl.PluralRules('en-US', { type: 'cardinal' });

console.log(pluralRulesEN.select(0));   // 输出: "other"
console.log(pluralRulesEN.select(1));   // 输出: "one"
console.log(pluralRulesEN.select(2));   // 输出: "other"
console.log(pluralRulesEN.select(10));  // 输出: "other"

// 创建一个针对俄语的基数复数规则实例
const pluralRulesRU = new Intl.PluralRules('ru', { type: 'cardinal' });

console.log(pluralRulesRU.select(0));   // 输出: "many"
console.log(pluralRulesRU.select(1));   // 输出: "one"
console.log(pluralRulesRU.select(2));   // 输出: "few"
console.log(pluralRulesRU.select(5));   // 输出: "many"
console.log(pluralRulesRU.select(21));  // 输出: "one"

// 创建一个针对阿拉伯语的基数复数规则实例
const pluralRulesAR = new Intl.PluralRules('ar', { type: 'cardinal' });

console.log(pluralRulesAR.select(0));   // 输出: "zero"
console.log(pluralRulesAR.select(1));   // 输出: "one"
console.log(pluralRulesAR.select(2));   // 输出: "two"
console.log(pluralRulesAR.select(3));   // 输出: "few"
console.log(pluralRulesAR.select(11));  // 输出: "many"
console.log(pluralRulesAR.select(100)); // 输出: "other"

// 获取已解析的选项
const resolvedOptions = pluralRulesRU.resolvedOptions();
console.log(resolvedOptions);
// 输出可能类似于: { locale: "ru", type: "cardinal", pluralCategories: [ "one", "few", "many", "other" ] }
```

在这个例子中，当你调用 `pluralRulesEN.select(1)` 时，JavaScript 引擎会调用 `v8/src/objects/js-plural-rules.cc` 中的相关代码，并使用 ICU 中针对英语的基数复数规则来判断数字 1 属于 "one" 这个类别。对于俄语和阿拉伯语的例子，底层的 C++ 代码会加载并应用各自语言的复数规则。

总结来说，`v8/src/objects/js-plural-rules.cc` 是 `Intl.PluralRules` 在 V8 引擎中的 C++ 实现，它利用 ICU 库提供的国际化能力，使得 JavaScript 能够根据不同的语言环境正确处理数字的复数形式。

Prompt: 
```
这是目录为v8/src/objects/js-plural-rules.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

#include "src/objects/js-plural-rules.h"

#include "src/execution/isolate-inl.h"
#include "src/objects/intl-objects.h"
#include "src/objects/js-number-format.h"
#include "src/objects/js-plural-rules-inl.h"
#include "src/objects/managed-inl.h"
#include "src/objects/option-utils.h"
#include "unicode/locid.h"
#include "unicode/numberformatter.h"
#include "unicode/numberrangeformatter.h"
#include "unicode/plurrule.h"
#include "unicode/unumberformatter.h"

namespace v8 {
namespace internal {

namespace {

bool CreateICUPluralRules(Isolate* isolate, const icu::Locale& icu_locale,
                          JSPluralRules::Type type,
                          std::unique_ptr<icu::PluralRules>* pl) {
  // Make formatter from options. Numbering system is added
  // to the locale as Unicode extension (if it was specified at all).
  UErrorCode status = U_ZERO_ERROR;

  UPluralType icu_type = UPLURAL_TYPE_CARDINAL;
  if (type == JSPluralRules::Type::ORDINAL) {
    icu_type = UPLURAL_TYPE_ORDINAL;
  } else {
    DCHECK_EQ(JSPluralRules::Type::CARDINAL, type);
  }

  std::unique_ptr<icu::PluralRules> plural_rules(
      icu::PluralRules::forLocale(icu_locale, icu_type, status));
  if (U_FAILURE(status)) {
    return false;
  }
  DCHECK_NOT_NULL(plural_rules.get());

  *pl = std::move(plural_rules);
  return true;
}

}  // namespace

Handle<String> JSPluralRules::TypeAsString() const {
  switch (type()) {
    case Type::CARDINAL:
      return GetReadOnlyRoots().cardinal_string_handle();
    case Type::ORDINAL:
      return GetReadOnlyRoots().ordinal_string_handle();
  }
  UNREACHABLE();
}

// static
MaybeHandle<JSPluralRules> JSPluralRules::New(Isolate* isolate,
                                              DirectHandle<Map> map,
                                              Handle<Object> locales,
                                              Handle<Object> options_obj) {
  // 1. Let requestedLocales be ? CanonicalizeLocaleList(locales).
  Maybe<std::vector<std::string>> maybe_requested_locales =
      Intl::CanonicalizeLocaleList(isolate, locales);
  MAYBE_RETURN(maybe_requested_locales, Handle<JSPluralRules>());
  std::vector<std::string> requested_locales =
      maybe_requested_locales.FromJust();

  // 2. Set options to ? CoerceOptionsToObject(options).
  Handle<JSReceiver> options;
  const char* service = "Intl.PluralRules";
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, CoerceOptionsToObject(isolate, options_obj, service));

  // 5. Let matcher be ? GetOption(options, "localeMatcher", "string",
  // « "lookup", "best fit" », "best fit").
  // 6. Set opt.[[localeMatcher]] to matcher.
  Maybe<Intl::MatcherOption> maybe_locale_matcher =
      Intl::GetLocaleMatcher(isolate, options, service);
  MAYBE_RETURN(maybe_locale_matcher, MaybeHandle<JSPluralRules>());
  Intl::MatcherOption matcher = maybe_locale_matcher.FromJust();

  // 7. Let t be ? GetOption(options, "type", "string", « "cardinal",
  // "ordinal" », "cardinal").
  Maybe<Type> maybe_type = GetStringOption<Type>(
      isolate, options, "type", service, {"cardinal", "ordinal"},
      {Type::CARDINAL, Type::ORDINAL}, Type::CARDINAL);
  MAYBE_RETURN(maybe_type, MaybeHandle<JSPluralRules>());
  Type type = maybe_type.FromJust();

  // Note: The spec says we should do ResolveLocale after performing
  // SetNumberFormatDigitOptions but we need the locale to create all
  // the ICU data structures.
  //
  // This isn't observable so we aren't violating the spec.

  // 11. Let r be ResolveLocale(%PluralRules%.[[AvailableLocales]],
  // requestedLocales, opt, %PluralRules%.[[RelevantExtensionKeys]],
  // localeData).
  Maybe<Intl::ResolvedLocale> maybe_resolve_locale =
      Intl::ResolveLocale(isolate, JSPluralRules::GetAvailableLocales(),
                          requested_locales, matcher, {});
  if (maybe_resolve_locale.IsNothing()) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  Intl::ResolvedLocale r = maybe_resolve_locale.FromJust();
  DirectHandle<String> locale_str =
      isolate->factory()->NewStringFromAsciiChecked(r.locale.c_str());

  icu::Locale icu_locale = r.icu_locale;
  icu::number::UnlocalizedNumberFormatter settings =
      icu::number::UnlocalizedNumberFormatter().roundingMode(UNUM_ROUND_HALFUP);

  std::unique_ptr<icu::PluralRules> icu_plural_rules;
  bool success =
      CreateICUPluralRules(isolate, r.icu_locale, type, &icu_plural_rules);
  if (!success || icu_plural_rules == nullptr) {
    // Remove extensions and try again.
    icu::Locale no_extension_locale(icu_locale.getBaseName());
    success = CreateICUPluralRules(isolate, no_extension_locale, type,
                                   &icu_plural_rules);
    icu_locale = no_extension_locale;

    if (!success || icu_plural_rules == nullptr) {
      THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
    }
  }

  // 9. Perform ? SetNumberFormatDigitOptions(pluralRules, options, 0, 3).
  Maybe<Intl::NumberFormatDigitOptions> maybe_digit_options =
      Intl::SetNumberFormatDigitOptions(isolate, options, 0, 3, false, service);
  MAYBE_RETURN(maybe_digit_options, MaybeHandle<JSPluralRules>());
  Intl::NumberFormatDigitOptions digit_options = maybe_digit_options.FromJust();
  settings =
      JSNumberFormat::SetDigitOptionsToFormatter(settings, digit_options);

  icu::number::LocalizedNumberFormatter icu_number_formatter =
      settings.locale(icu_locale);

  DirectHandle<Managed<icu::PluralRules>> managed_plural_rules =
      Managed<icu::PluralRules>::From(isolate, 0, std::move(icu_plural_rules));

  DirectHandle<Managed<icu::number::LocalizedNumberFormatter>>
      managed_number_formatter =
          Managed<icu::number::LocalizedNumberFormatter>::From(
              isolate, 0,
              std::make_shared<icu::number::LocalizedNumberFormatter>(
                  icu_number_formatter));

  // Now all properties are ready, so we can allocate the result object.
  Handle<JSPluralRules> plural_rules = Cast<JSPluralRules>(
      isolate->factory()->NewFastOrSlowJSObjectFromMap(map));
  DisallowGarbageCollection no_gc;
  plural_rules->set_flags(0);

  // 8. Set pluralRules.[[Type]] to t.
  plural_rules->set_type(type);

  // 12. Set pluralRules.[[Locale]] to the value of r.[[locale]].
  plural_rules->set_locale(*locale_str);

  plural_rules->set_icu_plural_rules(*managed_plural_rules);
  plural_rules->set_icu_number_formatter(*managed_number_formatter);

  // 13. Return pluralRules.
  return plural_rules;
}

MaybeHandle<String> JSPluralRules::ResolvePlural(
    Isolate* isolate, DirectHandle<JSPluralRules> plural_rules, double number) {
  icu::PluralRules* icu_plural_rules = plural_rules->icu_plural_rules()->raw();
  DCHECK_NOT_NULL(icu_plural_rules);

  icu::number::LocalizedNumberFormatter* fmt =
      plural_rules->icu_number_formatter()->raw();
  DCHECK_NOT_NULL(fmt);

  UErrorCode status = U_ZERO_ERROR;
  icu::number::FormattedNumber formatted_number =
      fmt->formatDouble(number, status);
  DCHECK(U_SUCCESS(status));

  icu::UnicodeString result =
      icu_plural_rules->select(formatted_number, status);
  DCHECK(U_SUCCESS(status));

  return Intl::ToString(isolate, result);
}

MaybeHandle<String> JSPluralRules::ResolvePluralRange(
    Isolate* isolate, DirectHandle<JSPluralRules> plural_rules, double x,
    double y) {
  icu::PluralRules* icu_plural_rules = plural_rules->icu_plural_rules()->raw();
  DCHECK_NOT_NULL(icu_plural_rules);

  Maybe<icu::number::LocalizedNumberRangeFormatter> maybe_range_formatter =
      JSNumberFormat::GetRangeFormatter(
          isolate, plural_rules->locale(),
          *plural_rules->icu_number_formatter()->raw());
  MAYBE_RETURN(maybe_range_formatter, MaybeHandle<String>());

  icu::number::LocalizedNumberRangeFormatter nrfmt =
      maybe_range_formatter.FromJust();

  UErrorCode status = U_ZERO_ERROR;
  icu::number::FormattedNumberRange formatted = nrfmt.formatFormattableRange(
      icu::Formattable(x), icu::Formattable(y), status);

  DCHECK(U_SUCCESS(status));
  icu::UnicodeString result = icu_plural_rules->select(formatted, status);
  DCHECK(U_SUCCESS(status));

  return Intl::ToString(isolate, result);
}

namespace {

void CreateDataPropertyForOptions(Isolate* isolate, Handle<JSObject> options,
                                  Handle<Object> value, const char* key) {
  Handle<String> key_str = isolate->factory()->NewStringFromAsciiChecked(key);

  // This is a brand new JSObject that shouldn't already have the same
  // key so this shouldn't fail.
  Maybe<bool> maybe = JSReceiver::CreateDataProperty(isolate, options, key_str,
                                                     value, Just(kDontThrow));
  DCHECK(maybe.FromJust());
  USE(maybe);
}

void CreateDataPropertyForOptions(Isolate* isolate, Handle<JSObject> options,
                                  int value, const char* key) {
  Handle<Smi> value_smi(Smi::FromInt(value), isolate);
  CreateDataPropertyForOptions(isolate, options, value_smi, key);
}

}  // namespace

Handle<JSObject> JSPluralRules::ResolvedOptions(
    Isolate* isolate, DirectHandle<JSPluralRules> plural_rules) {
  Handle<JSObject> options =
      isolate->factory()->NewJSObject(isolate->object_function());

  Handle<String> locale_value(plural_rules->locale(), isolate);
  CreateDataPropertyForOptions(isolate, options, locale_value, "locale");

  CreateDataPropertyForOptions(isolate, options, plural_rules->TypeAsString(),
                               "type");

  UErrorCode status = U_ZERO_ERROR;
  icu::number::LocalizedNumberFormatter* icu_number_formatter =
      plural_rules->icu_number_formatter()->raw();
  icu::UnicodeString skeleton = icu_number_formatter->toSkeleton(status);
  DCHECK(U_SUCCESS(status));

  CreateDataPropertyForOptions(
      isolate, options,
      JSNumberFormat::MinimumIntegerDigitsFromSkeleton(skeleton),
      "minimumIntegerDigits");
  int32_t min = 0, max = 0;

  if (JSNumberFormat::SignificantDigitsFromSkeleton(skeleton, &min, &max)) {
    CreateDataPropertyForOptions(isolate, options, min,
                                 "minimumSignificantDigits");
    CreateDataPropertyForOptions(isolate, options, max,
                                 "maximumSignificantDigits");
  } else {
    JSNumberFormat::FractionDigitsFromSkeleton(skeleton, &min, &max);
    CreateDataPropertyForOptions(isolate, options, min,
                                 "minimumFractionDigits");
    CreateDataPropertyForOptions(isolate, options, max,
                                 "maximumFractionDigits");
  }

  // 6. Let pluralCategories be a List of Strings containing all possible
  // results of PluralRuleSelect for the selected locale pr.[[Locale]], sorted
  // according to the following order: "zero", "one", "two", "few", "many",
  // "other".
  icu::PluralRules* icu_plural_rules = plural_rules->icu_plural_rules()->raw();
  DCHECK_NOT_NULL(icu_plural_rules);

  std::unique_ptr<icu::StringEnumeration> categories(
      icu_plural_rules->getKeywords(status));
  DCHECK(U_SUCCESS(status));
  int32_t count = categories->count(status);
  DCHECK(U_SUCCESS(status));

  Factory* factory = isolate->factory();
  DirectHandle<FixedArray> plural_categories = factory->NewFixedArray(count);
  const std::vector<const char*> kCategories = {"zero", "one",  "two",
                                                "few",  "many", "other"};
  int32_t index = 0;
  std::for_each(kCategories.cbegin(), kCategories.cend(), [&](const char* val) {
    categories->reset(status);
    DCHECK(U_SUCCESS(status));
    for (int32_t i = 0; i < count; i++) {
      int32_t len;
      const char* cat = categories->next(&len, status);
      DCHECK(U_SUCCESS(status));
      if (cat == nullptr) break;
      if (std::strcmp(val, cat) == 0) {
        DirectHandle<String> value_string =
            factory->NewStringFromAsciiChecked(val);
        plural_categories->set(index++, *value_string);
        break;
      }
    }
  });
  DCHECK(count == index);

  // 7. Perform ! CreateDataProperty(options, "pluralCategories",
  // CreateArrayFromList(pluralCategories)).
  Handle<JSArray> plural_categories_value =
      factory->NewJSArrayWithElements(plural_categories);
  CreateDataPropertyForOptions(isolate, options, plural_categories_value,
                               "pluralCategories");

  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->roundingIncrement_string(),
            JSNumberFormat::RoundingIncrement(isolate, skeleton),
            Just(kDontThrow))
            .FromJust());
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->roundingMode_string(),
            JSNumberFormat::RoundingModeString(isolate, skeleton),
            Just(kDontThrow))
            .FromJust());
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->roundingPriority_string(),
            JSNumberFormat::RoundingPriorityString(isolate, skeleton),
            Just(kDontThrow))
            .FromJust());
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->trailingZeroDisplay_string(),
            JSNumberFormat::TrailingZeroDisplayString(isolate, skeleton),
            Just(kDontThrow))
            .FromJust());

  return options;
}

namespace {

class PluralRulesAvailableLocales {
 public:
  PluralRulesAvailableLocales() {
    UErrorCode status = U_ZERO_ERROR;
    std::unique_ptr<icu::StringEnumeration> locales(
        icu::PluralRules::getAvailableLocales(status));
    DCHECK(U_SUCCESS(status));
    int32_t len = 0;
    const char* locale = nullptr;
    while ((locale = locales->next(&len, status)) != nullptr &&
           U_SUCCESS(status)) {
      std::string str(locale);
      if (len > 3) {
        std::replace(str.begin(), str.end(), '_', '-');
      }
      set_.insert(std::move(str));
    }
  }
  const std::set<std::string>& Get() const { return set_; }

 private:
  std::set<std::string> set_;
};

}  // namespace

const std::set<std::string>& JSPluralRules::GetAvailableLocales() {
  static base::LazyInstance<PluralRulesAvailableLocales>::type
      available_locales = LAZY_INSTANCE_INITIALIZER;
  return available_locales.Pointer()->Get();
}

}  // namespace internal
}  // namespace v8

"""

```