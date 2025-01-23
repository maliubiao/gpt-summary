Response:
Let's break down the thought process for analyzing the `v8/src/objects/js-locale.cc` file and fulfilling the request.

1. **Understanding the Core Request:** The main goal is to analyze the C++ source code and describe its functionality, especially as it relates to JavaScript, and identify potential programming errors.

2. **Initial Scan and Key Observations:**

   * **File Path:** `v8/src/objects/js-locale.cc` indicates this code is part of V8's object system and deals with locales.
   * **Copyright and License:** Standard boilerplate, not directly relevant to functionality.
   * **`#ifndef V8_INTL_SUPPORT`:** This is a crucial preprocessor directive. It immediately tells us that this code is *conditionally compiled* based on whether internationalization support is enabled in V8. If `V8_INTL_SUPPORT` is not defined, compilation will fail.
   * **Includes:** The included headers provide significant clues:
      * `src/objects/js-locale.h`: Likely the header file for the class defined in this source.
      * Standard C++ headers (`<map>`, `<memory>`, `<string>`, `<vector>`).
      * V8 API headers (`src/api/api.h`, `src/execution/isolate.h`, `src/heap/factory.h`).
      * V8 object headers (`src/objects/intl-objects.h`, `src/objects/js-locale-inl.h`, `src/objects/managed-inl.h`, `src/objects/objects-inl.h`, `src/objects/option-utils.h`).
      * **ICU Headers:**  The presence of `unicode/...` headers (`calendar.h`, `char16ptr.h`, `coll.h`, etc.) strongly indicates this code relies on the International Components for Unicode (ICU) library for locale handling.
   * **Namespace:** The code is within `v8::internal`, which suggests it's part of V8's internal implementation details, not directly exposed to JavaScript users.

3. **Dissecting Functionality (by examining key functions and structures):**

   * **`OptionData` and `ValueAndType` structs:**  These likely represent how locale options are handled internally, mapping JavaScript option names to ICU-specific keys and value types.
   * **`InsertOptionsIntoLocale`:** This function's name strongly suggests its purpose: taking JavaScript options and applying them to an ICU `LocaleBuilder`. The code iterates through `kOptionToUnicodeTagMap` and uses helper functions like `GetStringOption` and `GetBoolOption` (likely defined elsewhere in V8) to retrieve option values from the JavaScript `options` object. It then uses ICU's `LocaleBuilder` to set the corresponding locale keywords.
   * **Helper Functions for Subtag Validation (`IsAlpha`, `IsDigit`, `IsAlphanum`, `IsUnicodeLanguageSubtag`, etc.):**  These functions are clearly for validating the structure of locale subtags, ensuring they conform to BCP 47 standards.
   * **`JSLocale::Is38AlphaNumList` and `JSLocale::Is3Alpha`:** More specific validation functions.
   * **`JSLocale::StartsWithUnicodeLanguageId`:** This function attempts to parse a locale string and check if it starts with a valid Unicode language identifier, based on BCP 47 rules. The tokenization by '-' is a key indicator of this.
   * **`ApplyOptionsToTag`:** This function takes a locale tag string and options, validates the tag, and uses the `LocaleBuilder` to apply modifications based on the provided options (language, script, region). It also includes error handling (throwing `RangeError`).
   * **`JSLocale::New`:** This is likely the constructor for `JSLocale` objects within V8's internal representation. It calls `ApplyOptionsToTag` and `InsertOptionsIntoLocale` to create an ICU `Locale` object based on the provided locale string and options. It then wraps the ICU `Locale` in a `Managed` object.
   * **`JSLocale::Maximize` and `JSLocale::Minimize`:** These functions leverage ICU's `addLikelySubtags` and `minimizeSubtags` to expand and reduce locale identifiers, respectively. The comments about ICU limitations are important.
   * **`GetKeywordValuesFromLocale` and related functions (`CalendarsForLocale`, `GetCalendars`, `AvailableCalendars`, `GetCollations`, `GetHourCycles`, `GetNumberingSystems`):**  These functions retrieve specific locale-related information (calendars, collations, hour cycles, numbering systems) using ICU's APIs.
   * **`JSLocale::GetTimeZones`:** Retrieves time zone information based on the locale's region.
   * **`JSLocale::GetTextInfo` and `JSLocale::GetWeekInfo`:** Fetch text direction and week-related information using ICU.
   * **Getter methods (`Language`, `Script`, `Region`, `BaseName`, `Calendar`, `CaseFirst`, etc.):**  These functions provide access to specific components or keywords of the locale.
   * **`JSLocale::ToString`:** Converts the internal ICU locale representation back to a BCP 47 language tag string.

4. **Relating to JavaScript:**

   * The file deals with the internal representation of locales, which are directly exposed and manipulated in JavaScript through the `Intl` API (e.g., `Intl.Locale`).
   * The options and properties manipulated in the C++ code directly correspond to the options and properties available in JavaScript's `Intl.Locale` constructor and instance methods.
   * **Example:** The `calendar`, `collation`, `hourCycle` options in the C++ code directly relate to the options you can pass to the `Intl.Locale` constructor in JavaScript. Similarly, the `language`, `script`, `region`, etc., properties of the `JSLocale` class map to the properties of an `Intl.Locale` object.

5. **Identifying Potential Programming Errors:**

   * **ICU Errors:**  Many places in the code check `U_FAILURE(status)` after calling ICU functions. If these checks fail, it indicates an error in the underlying ICU library or invalid input. The code often throws a `RangeError` in such cases.
   * **Invalid Locale Tags/Subtags:** The validation functions and the checks within `ApplyOptionsToTag` are crucial for preventing the creation of invalid locale objects. If an invalid tag or subtag is provided, a `RangeError` is thrown.
   * **Uncaught Exceptions:** While the code uses `Maybe` and `MAYBE_RETURN` for some error handling, there might be scenarios where exceptions from ICU could propagate if not handled correctly in the calling code.
   * **Resource Management:** The use of `std::unique_ptr` suggests careful memory management for ICU objects. However, ensuring all ICU resources are properly released is critical to avoid leaks.
   * **Assumption of ICU Availability:** The `#ifndef V8_INTL_SUPPORT` check is important. If V8 is built without internationalization support, this code will not be compiled, and any attempt to use `Intl.Locale` in JavaScript would likely result in an error or undefined behavior.

6. **Constructing Examples and Explanations:**

   * **Functionality Summary:**  Start with a high-level overview, mentioning the connection to JavaScript's `Intl.Locale` and the use of ICU.
   * **Key Functions Explanation:**  Describe the purpose of the most important functions (like `InsertOptionsIntoLocale`, `ApplyOptionsToTag`, `JSLocale::New`, `Maximize`, `Minimize`, and the getter functions).
   * **JavaScript Examples:** Provide concrete JavaScript code snippets that demonstrate how the functionality implemented in the C++ code is used in JavaScript. Focus on the `Intl.Locale` constructor and its options and properties.
   * **Code Logic Inference:** Choose a function with clear input and output (e.g., `JSLocale::Maximize` or `ApplyOptionsToTag`) and illustrate with specific examples.
   * **Common Programming Errors:**  Focus on errors related to invalid locale tags/subtags, incorrect option usage, and the importance of understanding the `Intl` API.

7. **Review and Refine:** After drafting the initial response, review it for clarity, accuracy, and completeness. Ensure that the connection between the C++ code and the JavaScript API is clearly explained. Check for any technical jargon that might be confusing to someone not familiar with V8 internals. Make sure the examples are correct and easy to understand.
```cpp
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
  // 10. If language is not undefined,
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
  // 13. Return CanonicalizeLanguageTag(tag).
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
  // 24-
### 提示词
```
这是目录为v8/src/objects/js-locale.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-locale.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```