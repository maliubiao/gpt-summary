Response: Let's break down the thought process to analyze the C++ code and generate the summary and JavaScript example.

1. **Understand the Goal:** The request asks for the functionality of `js-collator.cc` and how it relates to JavaScript, with a JavaScript example.

2. **Initial Scan and Keywords:**  A quick skim reveals keywords like `JSCollator`, `icu::Collator`, `locales`, `options`, `compare`, `sort`, `search`, `sensitivity`, `caseFirst`, `numeric`, `ignorePunctuation`, and references to the ECMAScript Internationalization API (ECMA-402). This immediately suggests the file is about implementing the `Intl.Collator` object in V8.

3. **Identify Core Functionality:**  The `#include` directives point to interaction with the ICU library (`unicode/...`). The code manipulates `icu::Collator` objects. This library is the core of internationalization support in V8. The file clearly deals with comparing strings according to locale-specific rules.

4. **Key Functions and Their Roles:**

   * **`JSCollator::ResolvedOptions`:** This function takes a `JSCollator` object and extracts the resolved options from the underlying `icu::Collator`. It translates ICU attributes (like `UCOL_NUMERIC_COLLATION`, `UCOL_CASE_FIRST`, `UCOL_STRENGTH`) into their corresponding JavaScript property names (`numeric`, `caseFirst`, `sensitivity`). This is crucial for `Intl.Collator.prototype.resolvedOptions()`.

   * **`JSCollator::New`:**  This is the constructor or factory function for `JSCollator` objects. It takes locales and options from JavaScript, uses `Intl::CanonicalizeLocaleList` and `Intl::ResolveLocale` to determine the best matching locale, and then configures an `icu::Collator` instance based on the provided options. It handles the various options like `usage`, `collation`, `numeric`, `caseFirst`, `sensitivity`, and `ignorePunctuation`. This directly corresponds to the `new Intl.Collator()` constructor in JavaScript.

   * **Helper Functions (anonymous namespace):**  Functions like `GetCaseFirst`, `CreateDataPropertyForOptions`, `ToCaseFirst`, `ToUColAttributeValue`, `SetNumericOption`, `SetCaseFirstOption` are utility functions to manage options and translate between JavaScript values and ICU attributes.

5. **Mapping to JavaScript:**  The keywords and function names strongly suggest a direct mapping to the JavaScript `Intl.Collator` API.

   * `new Intl.Collator(locales, options)` likely triggers the `JSCollator::New` function.
   * `collator.compare(string1, string2)` would utilize the underlying `icu::Collator::compare` function (though this specific call isn't directly in this file, it's the logical consequence).
   * `collator.resolvedOptions()` directly corresponds to `JSCollator::ResolvedOptions`.

6. **Understanding Options and Their Impact:**  Focus on the different options (`usage`, `sensitivity`, `caseFirst`, `numeric`, `ignorePunctuation`, `collation`) and how they affect the comparison process. This understanding is key to explaining the functionality and creating a relevant JavaScript example.

7. **Constructing the Summary:**

   * Start with the main purpose: implementing `Intl.Collator`.
   * Describe the core mechanism: using ICU for locale-sensitive string comparison.
   * List the key functionalities and their corresponding options.
   * Mention the interaction with JavaScript through constructor and methods.
   * Explain the role of ICU attributes.

8. **Crafting the JavaScript Example:**

   * Choose a scenario that showcases the functionality. Comparing strings with different collator options is a good starting point.
   * Select a locale that demonstrates the effect of the options (e.g., 'en', 'de').
   * Demonstrate various options: `sensitivity`, `ignorePunctuation`, `numeric`, `caseFirst`.
   * Show how the `compare` method works and how the options influence the result.
   * Illustrate `resolvedOptions` to show the final configuration.

9. **Refinement and Review:**  Read through the generated summary and example. Ensure accuracy, clarity, and completeness. Check if the JavaScript example directly relates to the C++ code's functionality. For instance, `resolvedOptions` in the JavaScript example directly reflects the work done in the C++ function of the same name. The options passed in the JavaScript `Intl.Collator` constructor are processed by the `JSCollator::New` function.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Might focus too much on low-level details of ICU.
* **Correction:** Shift focus to the *purpose* of the C++ code within the context of V8 and JavaScript. The ICU details are implementation specifics.
* **Initial Thought:**  Maybe provide a very technical explanation of how ICU works.
* **Correction:** Keep the explanation at a level understandable to someone familiar with JavaScript and the `Intl` API. Avoid getting bogged down in ICU internals unless directly relevant to the exposed JavaScript functionality.
* **Initial Thought:**  Use a very complex JavaScript example.
* **Correction:**  Keep the JavaScript example simple and focused on illustrating the core concepts and how the options affect the comparison.

By following these steps, combining code analysis with knowledge of the JavaScript `Intl` API, and iteratively refining the explanation, we arrive at a comprehensive and accurate summary and a relevant JavaScript example.
这个C++源代码文件 `js-collator.cc` 是 V8 JavaScript 引擎中 `Intl.Collator` 对象的实现部分。它的主要功能是提供**locale-sensitive的字符串比较**，即根据不同的语言和文化习惯来进行字符串的排序和比较。

以下是对其功能的归纳：

1. **创建和初始化 `Intl.Collator` 对象:**
   - `JSCollator::New` 函数负责创建 `JSCollator` 的实例。
   - 它接收 JavaScript 传递的 `locales` (语言区域) 和 `options` (配置选项) 参数。
   - 它使用 ICU (International Components for Unicode) 库来创建和配置底层的 `icu::Collator` 对象，ICU 是一个广泛使用的国际化库。
   - 它处理各种配置选项，例如 `usage` (用于排序或搜索), `sensitivity` (区分程度，如区分大小写、重音符号等), `ignorePunctuation` (忽略标点符号), `numeric` (数字排序), `caseFirst` (大小写优先顺序), 和 `collation` (使用的排序规则)。
   - 它使用 `Intl::CanonicalizeLocaleList` 来规范化请求的语言区域列表，并使用 `Intl::ResolveLocale` 来选择最匹配的语言区域。

2. **实现 `resolvedOptions()` 方法:**
   - `JSCollator::ResolvedOptions` 函数实现了 `Intl.Collator.prototype.resolvedOptions()` 方法。
   - 它返回一个包含当前 `Intl.Collator` 对象实际生效的配置选项的 JavaScript 对象。
   - 它从底层的 `icu::Collator` 对象中获取当前的属性值，并将其转换为 JavaScript 可以理解的格式。

3. **处理 `compare()` 方法 (虽然此文件没有直接实现 `compare()`):**
   - 虽然这个文件本身没有直接实现 `compare()` 方法，但它创建的 `icu::Collator` 对象会被 `Intl.Collator.prototype.compare()` 方法使用来进行实际的字符串比较。
   - `icu::Collator` 提供了强大的字符串比较功能，能够根据配置的语言区域和选项进行排序和比较。

4. **与 ICU 库交互:**
   - 文件大量使用了 ICU 库的 API，例如 `icu::Collator::createInstance`, `icu_collator->getAttribute`, `icu_collator->setAttribute`, `icu_locale.getUnicodeKeywordValue` 等。
   - 这表明 `Intl.Collator` 的核心比较逻辑是由 ICU 库提供的。

**与 JavaScript 功能的关系和示例:**

`js-collator.cc` 实现了 JavaScript 的 `Intl.Collator` 对象，使得 JavaScript 能够进行国际化的字符串比较。

**JavaScript 示例:**

```javascript
// 创建一个英语环境的 Collator 对象，用于排序
const collatorEN = new Intl.Collator('en');

// 使用 compare 方法比较两个字符串
console.log(collatorEN.compare('apple', 'banana')); // 输出一个负数，表示 'apple' 在 'banana' 之前

// 创建一个德语环境的 Collator 对象，区分变音符号
const collatorDE = new Intl.Collator('de', { sensitivity: 'accent' });

console.log(collatorDE.compare('ö', 'o')); // 输出一个正数或负数，表示 'ö' 和 'o' 的排序关系

// 创建一个忽略标点符号的 Collator 对象
const collatorIgnorePunctuation = new Intl.Collator('en', { ignorePunctuation: true });
console.log(collatorIgnorePunctuation.compare('apple!', 'apple')); // 输出 0，表示它们相等

// 获取已解析的选项
const resolvedOptions = collatorEN.resolvedOptions();
console.log(resolvedOptions);
// 输出类似: { locale: "en", usage: "sort", sensitivity: "variant", ignorePunctuation: false, collation: "default", numeric: false, caseFirst: "false" }

// 使用 numeric 选项进行数字排序
const collatorNumeric = new Intl.Collator('en', { numeric: true });
console.log(collatorNumeric.compare('2', '10')); // 输出一个负数，表示 '2' 在 '10' 之前

// 使用 caseFirst 选项指定大小写排序
const collatorCaseFirst = new Intl.Collator('en', { caseFirst: 'upper' });
console.log(collatorCaseFirst.compare('a', 'B')); // 输出一个负数，表示 'B' 在 'a' 之前 (大写优先)

// 在数组排序中使用 Collator
const fruits = ['banana', 'Apple', 'orange'];
fruits.sort(collatorEN.compare);
console.log(fruits); // 输出: [ 'Apple', 'banana', 'orange' ] (根据英语默认排序)
```

**总结:**

`js-collator.cc` 是 V8 引擎中实现 `Intl.Collator` 这一关键国际化功能的 C++ 代码。它通过与 ICU 库的紧密结合，为 JavaScript 提供了强大且灵活的 locale-sensitive 字符串比较能力，使得开发者能够构建适应不同语言和文化习惯的应用程序。  JavaScript 代码通过 `Intl.Collator` API 与 `js-collator.cc` 中实现的底层功能进行交互。

### 提示词
```
这是目录为v8/src/objects/js-collator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

#include "src/objects/js-collator.h"

#include "src/execution/isolate.h"
#include "src/objects/js-collator-inl.h"
#include "src/objects/js-locale.h"
#include "src/objects/managed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/option-utils.h"
#include "unicode/coll.h"
#include "unicode/locid.h"
#include "unicode/strenum.h"
#include "unicode/ucol.h"
#include "unicode/udata.h"
#include "unicode/uloc.h"
#include "unicode/utypes.h"

namespace v8 {
namespace internal {

namespace {

enum class Usage {
  SORT,
  SEARCH,
};

enum class Sensitivity {
  kBase,
  kAccent,
  kCase,
  kVariant,
  kUndefined,
};

// enum for "caseFirst" option.
enum class CaseFirst { kUndefined, kUpper, kLower, kFalse };

Maybe<CaseFirst> GetCaseFirst(Isolate* isolate, Handle<JSReceiver> options,
                              const char* method_name) {
  return GetStringOption<CaseFirst>(
      isolate, options, "caseFirst", method_name, {"upper", "lower", "false"},
      {CaseFirst::kUpper, CaseFirst::kLower, CaseFirst::kFalse},
      CaseFirst::kUndefined);
}

// TODO(gsathya): Consider internalizing the value strings.
void CreateDataPropertyForOptions(Isolate* isolate, Handle<JSObject> options,
                                  Handle<String> key, const char* value) {
  DCHECK_NOT_NULL(value);
  Handle<String> value_str =
      isolate->factory()->NewStringFromAsciiChecked(value);

  // This is a brand new JSObject that shouldn't already have the same
  // key so this shouldn't fail.
  Maybe<bool> maybe = JSReceiver::CreateDataProperty(
      isolate, options, key, value_str, Just(kDontThrow));
  DCHECK(maybe.FromJust());
  USE(maybe);
}

void CreateDataPropertyForOptions(Isolate* isolate, Handle<JSObject> options,
                                  Handle<String> key, bool value) {
  Handle<Object> value_obj = isolate->factory()->ToBoolean(value);

  // This is a brand new JSObject that shouldn't already have the same
  // key so this shouldn't fail.
  Maybe<bool> maybe = JSReceiver::CreateDataProperty(
      isolate, options, key, value_obj, Just(kDontThrow));
  DCHECK(maybe.FromJust());
  USE(maybe);
}

}  // anonymous namespace

// static
Handle<JSObject> JSCollator::ResolvedOptions(
    Isolate* isolate, DirectHandle<JSCollator> collator) {
  Handle<JSObject> options =
      isolate->factory()->NewJSObject(isolate->object_function());

  icu::Collator* icu_collator = collator->icu_collator()->raw();
  DCHECK_NOT_NULL(icu_collator);

  UErrorCode status = U_ZERO_ERROR;
  bool numeric =
      icu_collator->getAttribute(UCOL_NUMERIC_COLLATION, status) == UCOL_ON;
  DCHECK(U_SUCCESS(status));

  const char* case_first = nullptr;
  status = U_ZERO_ERROR;
  switch (icu_collator->getAttribute(UCOL_CASE_FIRST, status)) {
    case UCOL_LOWER_FIRST:
      case_first = "lower";
      break;
    case UCOL_UPPER_FIRST:
      case_first = "upper";
      break;
    default:
      case_first = "false";
  }
  DCHECK(U_SUCCESS(status));

  const char* sensitivity = nullptr;
  status = U_ZERO_ERROR;
  switch (icu_collator->getAttribute(UCOL_STRENGTH, status)) {
    case UCOL_PRIMARY: {
      DCHECK(U_SUCCESS(status));
      status = U_ZERO_ERROR;
      // case level: true + s1 -> case, s1 -> base.
      if (UCOL_ON == icu_collator->getAttribute(UCOL_CASE_LEVEL, status)) {
        sensitivity = "case";
      } else {
        sensitivity = "base";
      }
      DCHECK(U_SUCCESS(status));
      break;
    }
    case UCOL_SECONDARY:
      sensitivity = "accent";
      break;
    case UCOL_TERTIARY:
      sensitivity = "variant";
      break;
    case UCOL_QUATERNARY:
      // We shouldn't get quaternary and identical from ICU, but if we do
      // put them into variant.
      sensitivity = "variant";
      break;
    default:
      sensitivity = "variant";
  }
  DCHECK(U_SUCCESS(status));

  status = U_ZERO_ERROR;
  bool ignore_punctuation = icu_collator->getAttribute(UCOL_ALTERNATE_HANDLING,
                                                       status) == UCOL_SHIFTED;
  DCHECK(U_SUCCESS(status));

  status = U_ZERO_ERROR;

  icu::Locale icu_locale(icu_collator->getLocale(ULOC_VALID_LOCALE, status));
  DCHECK(U_SUCCESS(status));

  const char* collation = "default";
  const char* usage = "sort";
  const char* collation_key = "co";
  status = U_ZERO_ERROR;
  std::string collation_value =
      icu_locale.getUnicodeKeywordValue<std::string>(collation_key, status);

  std::string locale;
  if (U_SUCCESS(status)) {
    if (collation_value == "search") {
      usage = "search";

      // Search is disallowed as a collation value per spec. Let's
      // use `default`, instead.
      //
      // https://tc39.github.io/ecma402/#sec-properties-of-intl-collator-instances
      collation = "default";

      // We clone the icu::Locale because we don't want the
      // icu_collator to be affected when we remove the collation key
      // below.
      icu::Locale new_icu_locale = icu_locale;

      // The spec forbids the search as a collation value in the
      // locale tag, so let's filter it out.
      status = U_ZERO_ERROR;
      new_icu_locale.setUnicodeKeywordValue(collation_key, nullptr, status);
      DCHECK(U_SUCCESS(status));

      locale = Intl::ToLanguageTag(new_icu_locale).FromJust();
    } else {
      collation = collation_value.c_str();
      locale = Intl::ToLanguageTag(icu_locale).FromJust();
    }
  } else {
    locale = Intl::ToLanguageTag(icu_locale).FromJust();
  }

  // 5. For each row of Table 2, except the header row, in table order, do
  //    ...
  // Table 2: Resolved Options of Collator Instances
  //  Internal Slot            Property               Extension Key
  //    [[Locale]                "locale"
  //    [[Usage]                 "usage"
  //    [[Sensitivity]]          "sensitivity"
  //    [[IgnorePunctuation]]    "ignorePunctuation"
  //    [[Collation]]            "collation"
  //    [[Numeric]]              "numeric"              kn
  //    [[CaseFirst]]            "caseFirst"            kf

  // If the collator return the locale differ from what got requested, we stored
  // it in the collator->locale. Otherwise, we just use the one from the
  // collator.
  if (collator->locale()->length() != 0) {
    // Get the locale from collator->locale() since we know in some cases
    // collator won't be able to return the requested one, such as zh_CN.
    Handle<String> locale_from_collator(collator->locale(), isolate);
    Maybe<bool> maybe = JSReceiver::CreateDataProperty(
        isolate, options, isolate->factory()->locale_string(),
        locale_from_collator, Just(kDontThrow));
    DCHECK(maybe.FromJust());
    USE(maybe);
  } else {
    // Just return from the collator for most of the cases that we can recover
    // from the collator.
    CreateDataPropertyForOptions(
        isolate, options, isolate->factory()->locale_string(), locale.c_str());
  }

  CreateDataPropertyForOptions(isolate, options,
                               isolate->factory()->usage_string(), usage);
  CreateDataPropertyForOptions(
      isolate, options, isolate->factory()->sensitivity_string(), sensitivity);
  CreateDataPropertyForOptions(isolate, options,
                               isolate->factory()->ignorePunctuation_string(),
                               ignore_punctuation);
  CreateDataPropertyForOptions(
      isolate, options, isolate->factory()->collation_string(), collation);
  CreateDataPropertyForOptions(isolate, options,
                               isolate->factory()->numeric_string(), numeric);
  CreateDataPropertyForOptions(
      isolate, options, isolate->factory()->caseFirst_string(), case_first);
  return options;
}

namespace {

CaseFirst ToCaseFirst(const char* str) {
  if (strcmp(str, "upper") == 0) return CaseFirst::kUpper;
  if (strcmp(str, "lower") == 0) return CaseFirst::kLower;
  if (strcmp(str, "false") == 0) return CaseFirst::kFalse;
  return CaseFirst::kUndefined;
}

UColAttributeValue ToUColAttributeValue(CaseFirst case_first) {
  switch (case_first) {
    case CaseFirst::kUpper:
      return UCOL_UPPER_FIRST;
    case CaseFirst::kLower:
      return UCOL_LOWER_FIRST;
    case CaseFirst::kFalse:
    case CaseFirst::kUndefined:
      return UCOL_OFF;
  }
}

void SetNumericOption(icu::Collator* icu_collator, bool numeric) {
  DCHECK_NOT_NULL(icu_collator);
  UErrorCode status = U_ZERO_ERROR;
  icu_collator->setAttribute(UCOL_NUMERIC_COLLATION,
                             numeric ? UCOL_ON : UCOL_OFF, status);
  DCHECK(U_SUCCESS(status));
}

void SetCaseFirstOption(icu::Collator* icu_collator, CaseFirst case_first) {
  DCHECK_NOT_NULL(icu_collator);
  UErrorCode status = U_ZERO_ERROR;
  icu_collator->setAttribute(UCOL_CASE_FIRST, ToUColAttributeValue(case_first),
                             status);
  DCHECK(U_SUCCESS(status));
}

}  // anonymous namespace

// static
MaybeHandle<JSCollator> JSCollator::New(Isolate* isolate, DirectHandle<Map> map,
                                        Handle<Object> locales,
                                        Handle<Object> options_obj,
                                        const char* service) {
  // 1. Let requestedLocales be ? CanonicalizeLocaleList(locales).
  Maybe<std::vector<std::string>> maybe_requested_locales =
      Intl::CanonicalizeLocaleList(isolate, locales);
  MAYBE_RETURN(maybe_requested_locales, Handle<JSCollator>());
  std::vector<std::string> requested_locales =
      maybe_requested_locales.FromJust();

  // 2. Set options to ? CoerceOptionsToObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, CoerceOptionsToObject(isolate, options_obj, service));

  // 4. Let usage be ? GetOption(options, "usage", "string", « "sort",
  // "search" », "sort").
  Maybe<Usage> maybe_usage = GetStringOption<Usage>(
      isolate, options, "usage", service, {"sort", "search"},
      {Usage::SORT, Usage::SEARCH}, Usage::SORT);
  MAYBE_RETURN(maybe_usage, MaybeHandle<JSCollator>());
  Usage usage = maybe_usage.FromJust();

  // 9. Let matcher be ? GetOption(options, "localeMatcher", "string",
  // « "lookup", "best fit" », "best fit").
  // 10. Set opt.[[localeMatcher]] to matcher.
  Maybe<Intl::MatcherOption> maybe_locale_matcher =
      Intl::GetLocaleMatcher(isolate, options, service);
  MAYBE_RETURN(maybe_locale_matcher, MaybeHandle<JSCollator>());
  Intl::MatcherOption matcher = maybe_locale_matcher.FromJust();

  // x. Let _collation_ be ? GetOption(_options_, *"collation"*, *"string"*,
  // *undefined*, *undefined*).
  std::unique_ptr<char[]> collation_str = nullptr;
  const std::vector<const char*> empty_values = {};
  Maybe<bool> maybe_collation = GetStringOption(
      isolate, options, "collation", empty_values, service, &collation_str);
  MAYBE_RETURN(maybe_collation, MaybeHandle<JSCollator>());
  // x. If _collation_ is not *undefined*, then
  if (maybe_collation.FromJust() && collation_str != nullptr) {
    // 1. If _collation_ does not match the Unicode Locale Identifier `type`
    // nonterminal, throw a *RangeError* exception.
    if (!JSLocale::Is38AlphaNumList(collation_str.get())) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kInvalid,
                        isolate->factory()->collation_string(),
                        isolate->factory()->NewStringFromAsciiChecked(
                            collation_str.get())),
          MaybeHandle<JSCollator>());
    }
  }
  // x. Set _opt_.[[co]] to _collation_.

  // 11. Let numeric be ? GetOption(options, "numeric", "boolean",
  // undefined, undefined).
  // 12. If numeric is not undefined, then
  //    a. Let numeric be ! ToString(numeric).
  //
  // Note: We omit the ToString(numeric) operation as it's not
  // observable. GetBoolOption returns a Boolean and
  // ToString(Boolean) is not side-effecting.
  //
  // 13. Set opt.[[kn]] to numeric.
  bool numeric;
  Maybe<bool> found_numeric =
      GetBoolOption(isolate, options, "numeric", service, &numeric);
  MAYBE_RETURN(found_numeric, MaybeHandle<JSCollator>());

  // 14. Let caseFirst be ? GetOption(options, "caseFirst", "string",
  //     « "upper", "lower", "false" », undefined).
  Maybe<CaseFirst> maybe_case_first = GetCaseFirst(isolate, options, service);
  MAYBE_RETURN(maybe_case_first, MaybeHandle<JSCollator>());
  CaseFirst case_first = maybe_case_first.FromJust();

  // The relevant unicode extensions accepted by Collator as specified here:
  // https://tc39.github.io/ecma402/#sec-intl-collator-internal-slots
  //
  // 16. Let relevantExtensionKeys be %Collator%.[[RelevantExtensionKeys]].
  std::set<std::string> relevant_extension_keys{"co", "kn", "kf"};

  // 17. Let r be ResolveLocale(%Collator%.[[AvailableLocales]],
  // requestedLocales, opt, %Collator%.[[RelevantExtensionKeys]],
  // localeData).
  Maybe<Intl::ResolvedLocale> maybe_resolve_locale =
      Intl::ResolveLocale(isolate, JSCollator::GetAvailableLocales(),
                          requested_locales, matcher, relevant_extension_keys);
  if (maybe_resolve_locale.IsNothing()) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  Intl::ResolvedLocale r = maybe_resolve_locale.FromJust();

  // 18. Set collator.[[Locale]] to r.[[locale]].
  icu::Locale icu_locale = r.icu_locale;
  DCHECK(!icu_locale.isBogus());

  // 19. Let collation be r.[[co]].
  UErrorCode status = U_ZERO_ERROR;
  if (collation_str != nullptr) {
    auto co_extension_it = r.extensions.find("co");
    if (co_extension_it != r.extensions.end() &&
        co_extension_it->second != collation_str.get()) {
      icu_locale.setUnicodeKeywordValue("co", nullptr, status);
      DCHECK(U_SUCCESS(status));
    }
  }

  // 5. Set collator.[[Usage]] to usage.
  //
  // 6. If usage is "sort", then
  //    a. Let localeData be %Collator%.[[SortLocaleData]].
  // 7. Else,
  //    a. Let localeData be %Collator%.[[SearchLocaleData]].
  //
  // The Intl spec doesn't allow us to use "search" as an extension
  // value for collation as per:
  // https://tc39.github.io/ecma402/#sec-intl-collator-internal-slots
  //
  // But the only way to pass the value "search" for collation from
  // the options object to ICU is to use the 'co' extension keyword.
  //
  // This will need to be filtered out when creating the
  // resolvedOptions object.
  if (usage == Usage::SEARCH) {
    UErrorCode set_status = U_ZERO_ERROR;
    icu_locale.setUnicodeKeywordValue("co", "search", set_status);
    DCHECK(U_SUCCESS(set_status));
  } else {
    if (collation_str != nullptr &&
        Intl::IsValidCollation(icu_locale, collation_str.get())) {
      icu_locale.setUnicodeKeywordValue("co", collation_str.get(), status);
      DCHECK(U_SUCCESS(status));
    }
  }

  // 20. If collation is null, let collation be "default".
  // 21. Set collator.[[Collation]] to collation.
  //
  // We don't store the collation value as per the above two steps
  // here. The collation value can be looked up from icu::Collator on
  // demand, as part of Intl.Collator.prototype.resolvedOptions.

  std::unique_ptr<icu::Collator> icu_collator(
      icu::Collator::createInstance(icu_locale, status));
  if (U_FAILURE(status) || icu_collator == nullptr) {
    status = U_ZERO_ERROR;
    // Remove extensions and try again.
    icu::Locale no_extension_locale(icu_locale.getBaseName());
    icu_collator.reset(
        icu::Collator::createInstance(no_extension_locale, status));

    if (U_FAILURE(status) || icu_collator == nullptr) {
      THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
    }
  }
  DCHECK(U_SUCCESS(status));

  icu::Locale collator_locale(
      icu_collator->getLocale(ULOC_VALID_LOCALE, status));

  // 22. If relevantExtensionKeys contains "kn", then
  //     a. Set collator.[[Numeric]] to ! SameValue(r.[[kn]], "true").
  //
  // If the numeric value is passed in through the options object,
  // then we use it. Otherwise, we check if the numeric value is
  // passed in through the unicode extensions.
  status = U_ZERO_ERROR;
  if (found_numeric.FromJust()) {
    SetNumericOption(icu_collator.get(), numeric);
  } else {
    auto kn_extension_it = r.extensions.find("kn");
    if (kn_extension_it != r.extensions.end()) {
      SetNumericOption(icu_collator.get(), (kn_extension_it->second == "true"));
    }
  }

  // 23. If relevantExtensionKeys contains "kf", then
  //     a. Set collator.[[CaseFirst]] to r.[[kf]].
  //
  // If the caseFirst value is passed in through the options object,
  // then we use it. Otherwise, we check if the caseFirst value is
  // passed in through the unicode extensions.
  if (case_first != CaseFirst::kUndefined) {
    SetCaseFirstOption(icu_collator.get(), case_first);
  } else {
    auto kf_extension_it = r.extensions.find("kf");
    if (kf_extension_it != r.extensions.end()) {
      SetCaseFirstOption(icu_collator.get(),
                         ToCaseFirst(kf_extension_it->second.c_str()));
    }
  }

  // Normalization is always on, by the spec. We are free to optimize
  // if the strings are already normalized (but we don't have a way to tell
  // that right now).
  status = U_ZERO_ERROR;
  icu_collator->setAttribute(UCOL_NORMALIZATION_MODE, UCOL_ON, status);
  DCHECK(U_SUCCESS(status));

  // 24. Let sensitivity be ? GetOption(options, "sensitivity",
  // "string", « "base", "accent", "case", "variant" », undefined).
  Maybe<Sensitivity> maybe_sensitivity =
      GetStringOption<Sensitivity>(isolate, options, "sensitivity", service,
                                   {"base", "accent", "case", "variant"},
                                   {Sensitivity::kBase, Sensitivity::kAccent,
                                    Sensitivity::kCase, Sensitivity::kVariant},
                                   Sensitivity::kUndefined);
  MAYBE_RETURN(maybe_sensitivity, MaybeHandle<JSCollator>());
  Sensitivity sensitivity = maybe_sensitivity.FromJust();

  // 25. If sensitivity is undefined, then
  if (sensitivity == Sensitivity::kUndefined) {
    // 25. a. If usage is "sort", then
    if (usage == Usage::SORT) {
      // 25. a. i. Let sensitivity be "variant".
      sensitivity = Sensitivity::kVariant;
    }
  }
  // 26. Set collator.[[Sensitivity]] to sensitivity.
  switch (sensitivity) {
    case Sensitivity::kBase:
      icu_collator->setStrength(icu::Collator::PRIMARY);
      break;
    case Sensitivity::kAccent:
      icu_collator->setStrength(icu::Collator::SECONDARY);
      break;
    case Sensitivity::kCase:
      icu_collator->setStrength(icu::Collator::PRIMARY);
      status = U_ZERO_ERROR;
      icu_collator->setAttribute(UCOL_CASE_LEVEL, UCOL_ON, status);
      DCHECK(U_SUCCESS(status));
      break;
    case Sensitivity::kVariant:
      icu_collator->setStrength(icu::Collator::TERTIARY);
      break;
    case Sensitivity::kUndefined:
      break;
  }

  // 27.Let ignorePunctuation be ? GetOption(options,
  // "ignorePunctuation", "boolean", undefined, false).
  bool ignore_punctuation = false;
  Maybe<bool> found_ignore_punctuation = GetBoolOption(
      isolate, options, "ignorePunctuation", service, &ignore_punctuation);
  MAYBE_RETURN(found_ignore_punctuation, MaybeHandle<JSCollator>());

  // 28. Set collator.[[IgnorePunctuation]] to ignorePunctuation.

  // Note: The following implementation does not strictly follow the spec text
  // due to https://github.com/tc39/ecma402/issues/832
  // If the ignorePunctuation is not defined, instead of fall back
  // to default false, we just depend on ICU to default based on the
  // built in locale collation rule, which in "th" locale that is true
  // but false on other locales.
  if (found_ignore_punctuation.FromJust()) {
    status = U_ZERO_ERROR;
    icu_collator->setAttribute(
        UCOL_ALTERNATE_HANDLING,
        ignore_punctuation ? UCOL_SHIFTED : UCOL_NON_IGNORABLE, status);
    DCHECK(U_SUCCESS(status));
  }

  DirectHandle<Managed<icu::Collator>> managed_collator =
      Managed<icu::Collator>::From(isolate, 0, std::move(icu_collator));

  // We only need to do so if it is different from the collator would return.
  DirectHandle<String> locale_str =
      isolate->factory()->NewStringFromAsciiChecked(
          (collator_locale != icu_locale) ? r.locale.c_str() : "");
  // Now all properties are ready, so we can allocate the result object.
  Handle<JSCollator> collator =
      Cast<JSCollator>(isolate->factory()->NewFastOrSlowJSObjectFromMap(map));
  DisallowGarbageCollection no_gc;
  collator->set_icu_collator(*managed_collator);
  collator->set_locale(*locale_str);

  // 29. Return collator.
  return collator;
}

namespace {

class CollatorAvailableLocales {
 public:
  CollatorAvailableLocales() {
    int32_t num_locales = 0;
    const icu::Locale* icu_available_locales =
        icu::Collator::getAvailableLocales(num_locales);
    std::vector<std::string> locales;
    locales.reserve(num_locales);
    for (int32_t i = 0; i < num_locales; ++i) {
      locales.push_back(
          Intl::ToLanguageTag(icu_available_locales[i]).FromJust());
    }
#define U_ICUDATA_COLL U_ICUDATA_NAME U_TREE_SEPARATOR_STRING "coll"
    set_ = Intl::BuildLocaleSet(locales, U_ICUDATA_COLL, nullptr);
#undef U_ICUDATA_COLL
  }
  virtual ~CollatorAvailableLocales() = default;
  const std::set<std::string>& Get() const { return set_; }

 private:
  std::set<std::string> set_;
};

}  // namespace

const std::set<std::string>& JSCollator::GetAvailableLocales() {
  static base::LazyInstance<CollatorAvailableLocales>::type available_locales =
      LAZY_INSTANCE_INITIALIZER;
  return available_locales.Pointer()->Get();
}

}  // namespace internal
}  // namespace v8
```