Response:
The user wants a summary of the provided C++ code, which is part of the V8 JavaScript engine. The code defines a class `JSDurationFormat` responsible for formatting duration values according to specified locale and formatting options.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The filename `js-duration-format.cc` and the class name `JSDurationFormat` strongly suggest this code handles formatting durations in JavaScript. The inclusion of `#include "src/objects/js-duration-format.h"` confirms this is the implementation file for the `JSDurationFormat` class.

2. **Look for key functionalities:**  Scan the code for important function calls and data structures.
    * `#include "unicode/dtfmtsym.h"`, `#include "unicode/listformatter.h"`, `#include "unicode/locid.h"`, `#include "unicode/numberformatter.h"`, etc., indicate that the code leverages the ICU library for internationalization features, especially for number and date/time formatting.
    * The `New` function is likely the constructor or a factory method for creating `JSDurationFormat` objects. Its parameters `locales` and `input_options` confirm its role in setting up the formatting.
    * The `ResolvedOptions` function seems to return the finalized formatting options.
    * The presence of `GetDurationUnitOptions` suggests that formatting can be configured for individual time units (years, months, etc.).
    * The `Output...` functions and the `Part` struct point towards the actual formatting logic, breaking down the duration into parts.

3. **Connect to JavaScript:**  The prompt specifically asks for JavaScript relevance. Consider how this C++ code would be exposed to JavaScript. The `Intl.DurationFormat` mentioned in comments like `// 1. Let style be ? GetOption(options, unit, "string", stylesList, // undefined).` strongly suggests a direct mapping to the JavaScript `Intl.DurationFormat` API.

4. **Infer functionality details:**  Analyze the logic within the key functions.
    * The `New` function performs locale negotiation, option processing (like `localeMatcher`, `numberingSystem`, `style`), and sets up internal state based on these options.
    * `GetDurationUnitOptions` determines the formatting style and display behavior for individual duration units based on user options and defaults. It handles complexities like defaulting to "numeric" or "auto" display and throwing errors for invalid combinations.
    * `ResolvedOptions` gathers the resolved formatting options into a JavaScript object, making them inspectable.
    * The `Output...` functions, combined with the `Part` structure, are responsible for generating the formatted string by iterating through the duration components and applying the appropriate formatting based on the resolved options. They handle different formatting styles (long, short, numeric, etc.) and the inclusion of separators.

5. **Consider potential programming errors:** Think about how developers might misuse the `Intl.DurationFormat` API. Common errors could involve providing invalid locale tags, incorrect option values (e.g., incompatible style and display combinations), or not understanding how the different formatting options interact.

6. **Structure the summary:** Organize the findings into logical sections covering the key aspects of the code.
    * Start with the main function: creating `JSDurationFormat` objects.
    * Detail the option processing and locale handling.
    * Explain the individual unit formatting.
    * Describe the output generation.
    * Mention the connection to JavaScript and provide an example.
    * Include potential programming errors.

7. **Address specific prompt questions:** Ensure all parts of the prompt are addressed:
    * Whether it's Torque (it's C++).
    * Its relation to JavaScript (through the `Intl.DurationFormat` API).
    * Example usage in JavaScript.
    * Code logic examples with input/output (although detailed internal logic is hard to exemplify without more context, high-level examples are possible).
    * Common programming errors.

8. **Refine and clarify:** Review the summary for clarity, accuracy, and completeness. Use precise language and avoid jargon where possible. For example, explicitly mention the ICU library's role.

By following these steps, a comprehensive and accurate summary of the `v8/src/objects/js-duration-format.cc` code can be generated, fulfilling all the requirements of the prompt.
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

#include "src/objects/js-duration-format.h"

#include <map>
#include <memory>
#include <string>
#include <string_view>

#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/objects/intl-objects.h"
#include "src/objects/js-duration-format-inl.h"
#include "src/objects/js-number-format.h"
#include "src/objects/js-temporal-objects.h"
#include "src/objects/managed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/option-utils.h"
#include "unicode/dtfmtsym.h"
#include "unicode/listformatter.h"
#include "unicode/locid.h"
#include "unicode/numberformatter.h"
#include "unicode/ulistformatter.h"
#include "unicode/unumberformatter.h"

namespace v8 {
namespace internal {

using temporal::DurationRecord;

namespace {

// #sec-getdurationunitoptions
enum class StylesList { k3Styles, k4Styles, k5Styles };
enum class Unit {
  kYears,
  kMonths,
  kWeeks,
  kDays,
  kHours,
  kMinutes,
  kSeconds,
  kMilliseconds,
  kMicroseconds,
  kNanoseconds
};
struct DurationUnitOptions {
  JSDurationFormat::FieldStyle style;
  JSDurationFormat::Display display;
};

const std::initializer_list<const char*> kLongShortNarrowStrings = {
    "long", "short", "narrow"};
const std::initializer_list<const char*> kLongShortNarrowNumericStrings = {
    "long", "short", "narrow", "numeric"};
const std::initializer_list<const char*> kLongShortNarrowNumeric2DigitStrings =
    {"long", "short", "narrow", "numeric", "2-digit"};

const std::initializer_list<JSDurationFormat::FieldStyle>
    kLongShortNarrowEnums = {JSDurationFormat::FieldStyle::kLong,
                             JSDurationFormat::FieldStyle::kShort,
                             JSDurationFormat::FieldStyle::kNarrow};
const std::initializer_list<JSDurationFormat::FieldStyle>
    kLongShortNarrowNumericEnums = {JSDurationFormat::FieldStyle::kLong,
                                    JSDurationFormat::FieldStyle::kShort,
                                    JSDurationFormat::FieldStyle::kNarrow,
                                    JSDurationFormat::FieldStyle::kNumeric};
const std::initializer_list<JSDurationFormat::FieldStyle>
    kLongShortNarrowNumeric2DigitEnums = {
        JSDurationFormat::FieldStyle::kLong,
        JSDurationFormat::FieldStyle::kShort,
        JSDurationFormat::FieldStyle::kNarrow,
        JSDurationFormat::FieldStyle::kNumeric,
        JSDurationFormat::FieldStyle::k2Digit};

Maybe<DurationUnitOptions> GetDurationUnitOptions(
    Isolate* isolate, Unit unit, const char* unit_string,
    const char* display_field, Handle<JSReceiver> options,
    JSDurationFormat::Style base_style,
    const std::vector<const char*>& value_strings,
    const std::vector<JSDurationFormat::FieldStyle>& value_enums,
    JSDurationFormat::FieldStyle digital_base,
    JSDurationFormat::FieldStyle prev_style) {
  const char* method_name = "Intl.DurationFormat";
  JSDurationFormat::FieldStyle style;
  // 1. Let style be ? GetOption(options, unit, "string", stylesList,
  // undefined).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, style,
      GetStringOption<JSDurationFormat::FieldStyle>(
          isolate, options, unit_string, method_name, value_strings,
          value_enums, JSDurationFormat::FieldStyle::kUndefined),
      Nothing<DurationUnitOptions>());

  // 2. Let displayDefault be "always".
  JSDurationFormat::Display display_default =
      JSDurationFormat::Display::kAlways;
  // 3. If style is undefined, then
  if (style == JSDurationFormat::FieldStyle::kUndefined) {
    // a. If baseStyle is "digital", then
    if (base_style == JSDurationFormat::Style::kDigital) {
      // i. If unit is not one of "hours", "minutes", or "seconds", then
      if (unit != Unit::kHours && unit != Unit::kMinutes &&
          unit != Unit::kSeconds) {
        // a. Set displayDefault to "auto".
        display_default = JSDurationFormat::Display::kAuto;
      }
      // ii. Set style to digitalBase.
      style = digital_base;
      // b. Else
    } else {
      // i. if prevStyle is "fractional", "numeric", or "2-digit", then
      if (prev_style == JSDurationFormat::FieldStyle::kFractional ||
          prev_style == JSDurationFormat::FieldStyle::kNumeric ||
          prev_style == JSDurationFormat::FieldStyle::k2Digit) {
        // 1. If unit is not one of "minutes" or "seconds", then
        if (unit != Unit::kMinutes && unit != Unit::kSeconds) {
          // a. Set displayDefault to "auto".
          display_default = JSDurationFormat::Display::kAuto;
        }
        // 2. Set style to "numeric".
        style = JSDurationFormat::FieldStyle::kNumeric;
        // iii. Else,
      } else {
        // 1. Set displayDefault to "auto".
        display_default = JSDurationFormat::Display::kAuto;
        // 2. Set style to baseStyle.
        switch (base_style) {
          case JSDurationFormat::Style::kLong:
            style = JSDurationFormat::FieldStyle::kLong;
            break;
          case JSDurationFormat::Style::kShort:
            style = JSDurationFormat::FieldStyle::kShort;
            break;
          case JSDurationFormat::Style::kNarrow:
            style = JSDurationFormat::FieldStyle::kNarrow;
            break;
          default:
            UNREACHABLE();
        }
      }
    }
  }
  // 4. If style is "numeric", then
  if (style == JSDurationFormat::FieldStyle::kNumeric) {
    // a. If unit is one of "milliseconds", "microseconds", or "nanoseconds",
    // then
    if (unit == Unit::kMilliseconds || unit == Unit::kMicroseconds ||
        unit == Unit::kNanoseconds) {
      // i. Set style to "fractional".
      style = JSDurationFormat::FieldStyle::kFractional;
      // ii. Set displayDefault to "auto".
      display_default = JSDurationFormat::Display::kAuto;
    }
  }
  // 5. Let displayField be the string-concatenation of unit and "Display".
  // 6. Let display be ? GetOption(options, displayField, "string", « "auto",
  // "always" », displayDefault).
  JSDurationFormat::Display display;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, display,
      GetStringOption<JSDurationFormat::Display>(
          isolate, options, display_field, method_name, {"auto", "always"},
          {JSDurationFormat::Display::kAuto,
           JSDurationFormat::Display::kAlways},
          display_default),
      Nothing<DurationUnitOptions>());
  // 7. If display is "always" and style is "fractional", then
  if (display == JSDurationFormat::Display::kAlways &&
      style == JSDurationFormat::FieldStyle::kFractional) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kInvalid,
                      isolate->factory()->object_string(), options),
        Nothing<DurationUnitOptions>());
  }
  // 8. If prevStyle is "fractional", then
  if (prev_style == JSDurationFormat::FieldStyle::kFractional) {
    // a. If style is not "fractional", then
    if (style != JSDurationFormat::FieldStyle::kFractional) {
      // i. Throw a RangeError exception.
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kInvalid,
                        isolate->factory()->object_string(), options),
          Nothing<DurationUnitOptions>());
    }
  }
  // 7. If prevStyle is "numeric" or "2-digit", then
  if (prev_style == JSDurationFormat::FieldStyle::kNumeric ||
      prev_style == JSDurationFormat::FieldStyle::k2Digit) {
    // a. If style is not "fractional", "numeric" or "2-digit", then
    if (style != JSDurationFormat::FieldStyle::kFractional &&
        style != JSDurationFormat::FieldStyle::kNumeric &&
        style != JSDurationFormat::FieldStyle::k2Digit) {
      // i. Throw a RangeError exception.
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kInvalid,
                        isolate->factory()->object_string(), options),
          Nothing<DurationUnitOptions>());
    }
    // b. If unit is "minutes" or "seconds", then
    if (unit == Unit::kMinutes || unit == Unit::kSeconds) {
      // i. Set style to "2-digit".
      style = JSDurationFormat::FieldStyle::k2Digit;
    }
  }
  // 8. Return the Record { [[Style]]: style, [[Display]]: display }.
  return Just(DurationUnitOptions({style, display}));
}

JSDurationFormat::Separator GetSeparator(const icu::Locale& l) {
  UErrorCode status = U_ZERO_ERROR;
  icu::DateFormatSymbols sym(l, status);
  if (U_FAILURE(status)) return JSDurationFormat::Separator::kColon;
  icu::UnicodeString sep;
  sym.getTimeSeparatorString(sep);
  if (sep.length() != 1) return JSDurationFormat::Separator::kColon;
  switch (sep.charAt(0)) {
    case u'.':
      return JSDurationFormat::Separator::kFullStop;
    case u'\uFF1A':
      return JSDurationFormat::Separator::kFullwidthColon;
    case u'\u066B':
      return JSDurationFormat::Separator::kArabicDecimalSeparator;
    // By default, or if we get anything else, just use ':'.
    default:
      return JSDurationFormat::Separator::kColon;
  }
}

}  // namespace
MaybeHandle<JSDurationFormat> JSDurationFormat::New(
    Isolate* isolate, DirectHandle<Map> map, Handle<Object> locales,
    Handle<Object> input_options) {
  Factory* factory = isolate->factory();
  const char* method_name = "Intl.DurationFormat";

  // 3. Let requestedLocales be ? CanonicalizeLocaleList(locales).
  std::vector<std::string> requested_locales;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, requested_locales,
      Intl::CanonicalizeLocaleList(isolate, locales),
      Handle<JSDurationFormat>());

  // 4. Let options be ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, input_options, method_name));

  // 5. Let matcher be ? GetOption(options, "localeMatcher", "string", «
  // "lookup", "best fit" », "best fit").
  Intl::MatcherOption matcher;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, matcher, Intl::GetLocaleMatcher(isolate, options, method_name),
      Handle<JSDurationFormat>());

  // 6. Let numberingSystem be ? GetOption(options, "numberingSystem", "string",
  // undefined, undefined).
  //
  // 7. If numberingSystem is not undefined, then
  //
  // a. If numberingSystem does not match the Unicode Locale Identifier type
  // nonterminal, throw a RangeError exception.
  // Note: The matching test and throw in Step 7-a is throw inside
  // Intl::GetNumberingSystem.
  std::unique_ptr<char[]> numbering_system_str = nullptr;
  bool get;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, get,
      Intl::GetNumberingSystem(isolate, options, method_name,
                               &numbering_system_str),
      Handle<JSDurationFormat>());

  // 8. Let opt be the Record { [[localeMatcher]]: matcher, [[nu]]:
  // numberingSystem }.
  // 9. Let r be ResolveLocale(%DurationFormat%.[[AvailableLocales]],
  // requestedLocales, opt, %DurationFormat%.[[RelevantExtensionKeys]],
  // %DurationFormat%.[[LocaleData]]).
  std::set<std::string> relevant_extension_keys{"nu"};
  Intl::ResolvedLocale r;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, r,
      Intl::ResolveLocale(isolate, JSDurationFormat::GetAvailableLocales(),
                          requested_locales, matcher, relevant_extension_keys),
      Handle<JSDurationFormat>());

  // 10. Let locale be r.[[locale]].
  icu::Locale r_locale = r.icu_locale;
  UErrorCode status = U_ZERO_ERROR;
  // 11. Set durationFormat.[[Locale]] to locale.
  // 12. Set durationFormat.[[NumberingSystem]] to r.[[nu]].
  if (numbering_system_str != nullptr) {
    auto nu_extension_it = r.extensions.find("nu");
    if (nu_extension_it != r.extensions.end() &&
        nu_extension_it->second != numbering_system_str.get()) {
      r_locale.setUnicodeKeywordValue("nu", nullptr, status);
      DCHECK(U_SUCCESS(status));
    }
  }
  icu::Locale icu_locale = r_locale;
  if (numbering_system_str != nullptr &&
      Intl::IsValidNumberingSystem(numbering_system_str.get())) {
    r_locale.setUnicodeKeywordValue("nu", numbering_system_str.get(), status);
    DCHECK(U_SUCCESS(status));
  }
  std::string numbering_system = Intl::GetNumberingSystem(r_locale);
  Separator separator = GetSeparator(r_locale);

  // 13. Let style be ? GetOption(options, "style", "string", « "long", "short",
  // "narrow", "digital" », "long").
  Style style;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, style,
      GetStringOption<Style>(
          isolate, options, "style", method_name,
          {"long", "short", "narrow", "digital"},
          {Style::kLong, Style::kShort, Style::kNarrow, Style::kDigital},
          Style::kShort),
      Handle<JSDurationFormat>());

  // 14. Set durationFormat.[[Style]] to style.
  // 15. Set durationFormat.[[DataLocale]] to r.[[dataLocale]].
  DirectHandle<Managed<icu::Locale>> managed_locale =
      Managed<icu::Locale>::From(
          isolate, 0, std::shared_ptr<icu::Locale>{icu_locale.clone()});
  // 16. Let prevStyle be the empty String.
  // 17. For each row of Table 1, except the header row, in table order, do
  //   a. Let styleSlot be the Style Slot value of the current row.
  //   b. Let displaySlot be the Display Slot value of the current row.
  //   c. Let unit be the Unit value.
  //   d. Let valueList be the Values value.
  //   e. Let digitalBase be the Digital Default value.
  //   f. Let unitOptions be ? GetDurationUnitOptions(unit, options, style,
  //      valueList, digitalBase, prevStyle).
  //      of durationFormat to unitOptions.[[Style]].
  //   h. Set the value of the
  //      displaySlot slot of durationFormat to unitOptions.[[Display]].
  //   i. If unit is one of "hours", "minutes", "seconds", "milliseconds",
  //      or "microseconds", then
  //      i. Set prevStyle to unitOptions.[[Style]].
  //   g. Set the value of the styleSlot slot
  DurationUnitOptions years_option;
  DurationUnitOptions months_option;
  DurationUnitOptions weeks_option;
  DurationUnitOptions days_option;
  DurationUnitOptions hours_option;
  DurationUnitOptions minutes_option;
  DurationUnitOptions seconds_option;
  DurationUnitOptions milliseconds_option;
  DurationUnitOptions microseconds_option;
  DurationUnitOptions nanoseconds_option;

#define CALL_GET_DURATION_UNIT_OPTIONS(unit, property, strings, enums,         \
                                       digital_base, prev_style)               \
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(                                      \
      isolate, property##_option,                                              \
      GetDurationUnitOptions(                                                  \
          isolate, Unit::unit, #property, #property "Display", options, style, \
          strings, enums, JSDurationFormat::FieldStyle::digital_base,          \
          prev_style),                                                         \
      Handle<JSDurationFormat>());

  // #table-durationformat
  // Table 3: Internal slots and property names of DurationFormat instances
  // relevant to Intl.DurationFormat constructor
  // [[YearsStyle]] [[YearsDisplay]] "years" « "long", "short",
  // "narrow" » "short"
  CALL_GET_DURATION_UNIT_OPTIONS(kYears, years, kLongShortNarrowStrings,
                                 kLongShortNarrowEnums, kShort,
                                 FieldStyle::kUndefined)
  // [[MonthsStyle]] [[MonthsDisplay]] "months" « "long",
  // "short", "narrow" » "short"
  CALL_GET_DURATION_UNIT_OPTIONS(kMonths, months, kLongShortNarrowStrings,
                                 kLongShortNarrowEnums, kShort,
                                 years_option.style)
  // [[WeeksStyle]] [[WeeksDisplay]] "weeks" « "long", "short",
  // "narrow" » "short"
  CALL_GET_DURATION_UNIT_OPTIONS(kWeeks, weeks, kLongShortNarrowStrings,
                                 kLongShortNarrowEnums, kShort,
                                 months_option.style)
  // [[DaysStyle]] [[DaysDisplay]] "days" « "long", "short", "narrow" »
  // "short"
  CALL_GET_DURATION_UNIT_OPTIONS(kDays, days, kLongShortNarrowStrings,
                                 kLongShortNarrowEnums, kShort,
                                 weeks_option.style)

  // [[HoursStyle]] [[HoursDisplay]] "hours" « "long", "short",
  // "narrow", "numeric", "2-digit" » "numeric"
  CALL_GET_DURATION_UNIT_OPTIONS(
      kHours, hours, kLongShortNarrowNumeric2DigitStrings,
      kLongShortNarrowNumeric2DigitEnums, kNumeric, days_option.style)
  // [[MinutesStyle]] [[MinutesDisplay]] "minutes" « "long",
  // "short", "narrow", "numeric", "2-digit" » "numeric"
  CALL_GET_DURATION_UNIT_OPTIONS(
      kMinutes, minutes, kLongShortNarrowNumeric2DigitStrings,
      kLongShortNarrowNumeric2DigitEnums, kNumeric, hours_option.style)

  // [[SecondsStyle]] [[SecondsDisplay]] "seconds" « "long",
  // "short", "narrow", "numeric", "2-digit" »
  CALL_GET_DURATION_UNIT_OPTIONS(
      kSeconds, seconds, kLongShortNarrowNumeric2DigitStrings,
      kLongShortNarrowNumeric2DigitEnums, kNumeric, minutes_option.style)

  // [[MillisecondsStyle]] [[MillisecondsDisplay]] "milliseconds" «
  // "long", "short", "narrow", "numeric" » "numeric"
  CALL_GET_DURATION_UNIT_OPTIONS(
      kMilliseconds, milliseconds, kLongShortNarrowNumericStrings,
      kLongShortNarrowNumericEnums, kNumeric, seconds_option.style)

  // [[MicrosecondsStyle]] [[MicrosecondsDisplay]] "microseconds" «
  // "long", "short", "narrow", "numeric" » "numeric"
  CALL_GET_DURATION_UNIT_OPTIONS(
      kMicroseconds, microseconds, kLongShortNarrowNumericStrings,
      kLongShortNarrowNumericEnums, kNumeric, milliseconds_option.style)

  // [[NanosecondsStyle]] [[NanosecondsDisplay]] "nanoseconds" «
  // "long", "short", "narrow", "numeric" » "numeric"
  CALL_GET_DURATION_UNIT_OPTIONS(
      kNanoseconds, nanoseconds, kLongShortNarrowNumericStrings,
      kLongShortNarrowNumericEnums, kNumeric, microseconds_option.style)

#undef CALL_GET_DURATION_UNIT_OPTIONS
  // 18. Set durationFormat.[[FractionalDigits]] to ? GetNumberOption(options,
  // "fractionalDigits", 0, 9, undefined).
  int fractional_digits;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, fractional_digits,
      GetNumberOption(isolate, options, factory->fractionalDigits_string(), 0,
                      9, kUndefinedFractionalDigits),
      Handle<JSDurationFormat>());

  icu::number::LocalizedNumberFormatter fmt =
      icu::number::UnlocalizedNumberFormatter()
          .roundingMode(UNUM_ROUND_HALFUP)
          .locale(icu_locale);
  if (!numbering_system.empty() && numbering_system != "latn") {
    fmt = fmt.adoptSymbols(icu::NumberingSystem::createInstanceByName(
        numbering_system.c_str(), status));
    DCHECK(U_SUCCESS(status));
  }
  DirectHandle<Managed<icu::number::LocalizedNumberFormatter>>
      managed_number_formatter =
          Managed<icu::number::LocalizedNumberFormatter>::From(
              isolate, 0,
              std::make_shared<icu::number::LocalizedNumberFormatter>(fmt));

  // 19. Return durationFormat.
  Handle<JSDurationFormat> duration_format =
      Cast<JSDurationFormat>(factory->NewFastOrSlowJSObjectFromMap(map));
  duration_format->set_style_flags(0);
  duration_format->set_display_flags(0);
  duration_format->set_style(style);
  duration_format->set_years_style(years_option.style);
  duration_format->set_months_style(months_option.style);
  duration_format->set_weeks_style(weeks_option.style);
  duration_format->set_days_style(days_option.style);
  duration_format->set_hours_style(hours_option.style);
  duration_format->set_minutes_style(minutes_option.style);
  duration_format->set_seconds_style(seconds_option.style);
  duration_format->set_milliseconds_style(milliseconds_option.style);
  duration_format->set_microseconds_style(microseconds_option.style);
  duration_format->set_nanoseconds_style(nanoseconds_option.style);
  duration_format->set_separator(separator);

  duration_format->set_years_display(years_option.display);
  duration_format->set_months_display(months_option.display);
  duration_format->set_weeks_display(weeks_option.display);
  duration_format->set_days_display(days_option.display);
  duration_format->set_hours_display(hours_option.display);
  duration_format->set_minutes_display(minutes_option.display);
  duration_format->set_seconds_display(seconds_option.display);
  duration_format->set_milliseconds_display(milliseconds_option.display);
  duration_format->set_microseconds_display(microseconds_option.display);
  duration_format->set_nanoseconds_display(nanoseconds_option.display);

  duration_format->set_fractional_digits(fractional_digits);

  duration_format->set_icu_locale(*managed_locale);
  duration_format->set_icu_number_formatter(*managed_number_formatter);

  return duration_format;
}

namespace {

Handle<String> StyleToString(Isolate* isolate, JSDurationFormat::Style style) {
  switch (style) {
    case JSDurationFormat::Style::kLong:
      return ReadOnlyRoots(isolate).long_string_handle();
    case JSDurationFormat::Style::kShort:
      return ReadOnlyRoots(isolate).short_string_handle();
    case JSDurationFormat::Style::kNarrow:
      return ReadOnlyRoots(isolate).narrow_string_handle();
    case JSDurationFormat::Style::kDigital:
      return ReadOnlyRoots(isolate).digital_string_handle();
  }
}

Handle<String> StyleToString(Isolate* isolate,
                             JSDurationFormat::FieldStyle style) {
  switch (style) {
    case JSDurationFormat::FieldStyle::kLong:
      return ReadOnlyRoots(isolate).long_string_handle();
    case JSDurationFormat::FieldStyle::kShort:
      return ReadOnlyRoots(isolate).short_string_handle();
    case JSDurationFormat::FieldStyle::kNarrow:
      return ReadOnlyRoots(isolate).narrow_string_handle();
    case JSDurationFormat::FieldStyle::kNumeric:
      return ReadOnlyRoots(isolate).numeric_string_handle();
    case JSDurationFormat::FieldStyle::k2Digit:
      return ReadOnlyRoots(isolate).two_digit_string_handle();
    case JSDurationFormat::FieldStyle::kFractional:
      // Step 3 in Intl.DurationFormat.prototype.resolvedOptions ( )
      // e. If v is "fractional", then
      // ii. Set v to "numeric".
      return ReadOnlyRoots(isolate).numeric_string_handle();
    case JSDurationFormat::FieldStyle::kUndefined:
      UNREACHABLE();
  }
}

Handle<String> DisplayToString(Isolate* isolate,
                               JSDurationFormat::Display display) {
  switch (display) {
    case JSDurationFormat::Display::kAuto:
      return ReadOnlyRoots(isolate).auto_string_handle();
    case JSDurationFormat::Display::kAlways:
      return ReadOnlyRoots(isolate).always_string_handle();
  }
}

}  // namespace

Handle<JSObject> JSDurationFormat::ResolvedOptions(
    Isolate* isolate, DirectHandle<JSDurationFormat> format) {
  Factory* factory = isolate->factory();
  Handle<JSObject> options = factory->NewJSObject(isolate->object_function());

  Handle<String> locale = factory->NewStringFromAsciiChecked(
      Intl::ToLanguageTag(*format->icu_locale()->raw()).FromJust().c_str());
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString skeleton =
      format->icu_number_formatter()->raw()->toSkeleton(status);
  DCHECK(U_SUCCESS(status));

  Handle<String> numbering_system;
  CHECK(Intl::ToString(isolate,
                       JSNumberFormat::NumberingSystemFromSkeleton(skeleton))
            .ToHandle(&numbering_system));

  bool created;

#define OUTPUT_PROPERTY(s, f)                                           \
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(                               \
      isolate, created,                                                 \
      JSReceiver::CreateDataProperty(isolate, options, factory->s(), f, \
                                     Just(kDontThrow)),                 \
      Handle<JSObject>());                                              \
  CHECK(created);
#define OUTPUT_STYLE_PROPERTY(p) \
  OUTPUT_PROPERTY(p##_string, StyleToString(isolate, format->p##_style()))
#define OUTPUT_DISPLAY_PROPERTY(p)   \
  OUTPUT_PROPERTY(p##Display_string, \
                  DisplayToString(isolate, format->p##_display()))
#define OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(p) \
  OUTPUT_STYLE_PROPERTY(p);                    \
  OUTPUT_DISPLAY_PROPERTY(p);

  // #table-durationformat-resolvedoptions-properties
  // Table 4: Resolved Options of DurationFormat Instances
  // [[Locale]] "locale"
  OUTPUT_PROPERTY(locale_string, locale);
  // [[NumberingSystem]] "numberingSystem"
  OUTPUT_PROPERTY(numberingSystem_string, numbering_system);
  // [[Style]] "style"
  OUTPUT_PROPERTY(style_string, StyleToString(isolate, format->style()));

  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(years);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(months);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(weeks);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(days);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(hours);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(minutes);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(seconds);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(milliseconds);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(microseconds);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(nanoseconds);

  // [[FractionalDigits]] "fractionalDigits"

  // c. If p is
### 提示词
```
这是目录为v8/src/objects/js-duration-format.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-duration-format.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

#include "src/objects/js-duration-format.h"

#include <map>
#include <memory>
#include <string>
#include <string_view>

#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/objects/intl-objects.h"
#include "src/objects/js-duration-format-inl.h"
#include "src/objects/js-number-format.h"
#include "src/objects/js-temporal-objects.h"
#include "src/objects/managed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/option-utils.h"
#include "unicode/dtfmtsym.h"
#include "unicode/listformatter.h"
#include "unicode/locid.h"
#include "unicode/numberformatter.h"
#include "unicode/ulistformatter.h"
#include "unicode/unumberformatter.h"

namespace v8 {
namespace internal {

using temporal::DurationRecord;

namespace {

// #sec-getdurationunitoptions
enum class StylesList { k3Styles, k4Styles, k5Styles };
enum class Unit {
  kYears,
  kMonths,
  kWeeks,
  kDays,
  kHours,
  kMinutes,
  kSeconds,
  kMilliseconds,
  kMicroseconds,
  kNanoseconds
};
struct DurationUnitOptions {
  JSDurationFormat::FieldStyle style;
  JSDurationFormat::Display display;
};

const std::initializer_list<const char*> kLongShortNarrowStrings = {
    "long", "short", "narrow"};
const std::initializer_list<const char*> kLongShortNarrowNumericStrings = {
    "long", "short", "narrow", "numeric"};
const std::initializer_list<const char*> kLongShortNarrowNumeric2DigitStrings =
    {"long", "short", "narrow", "numeric", "2-digit"};

const std::initializer_list<JSDurationFormat::FieldStyle>
    kLongShortNarrowEnums = {JSDurationFormat::FieldStyle::kLong,
                             JSDurationFormat::FieldStyle::kShort,
                             JSDurationFormat::FieldStyle::kNarrow};
const std::initializer_list<JSDurationFormat::FieldStyle>
    kLongShortNarrowNumericEnums = {JSDurationFormat::FieldStyle::kLong,
                                    JSDurationFormat::FieldStyle::kShort,
                                    JSDurationFormat::FieldStyle::kNarrow,
                                    JSDurationFormat::FieldStyle::kNumeric};
const std::initializer_list<JSDurationFormat::FieldStyle>
    kLongShortNarrowNumeric2DigitEnums = {
        JSDurationFormat::FieldStyle::kLong,
        JSDurationFormat::FieldStyle::kShort,
        JSDurationFormat::FieldStyle::kNarrow,
        JSDurationFormat::FieldStyle::kNumeric,
        JSDurationFormat::FieldStyle::k2Digit};

Maybe<DurationUnitOptions> GetDurationUnitOptions(
    Isolate* isolate, Unit unit, const char* unit_string,
    const char* display_field, Handle<JSReceiver> options,
    JSDurationFormat::Style base_style,
    const std::vector<const char*>& value_strings,
    const std::vector<JSDurationFormat::FieldStyle>& value_enums,
    JSDurationFormat::FieldStyle digital_base,
    JSDurationFormat::FieldStyle prev_style) {
  const char* method_name = "Intl.DurationFormat";
  JSDurationFormat::FieldStyle style;
  // 1. Let style be ? GetOption(options, unit, "string", stylesList,
  // undefined).
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, style,
      GetStringOption<JSDurationFormat::FieldStyle>(
          isolate, options, unit_string, method_name, value_strings,
          value_enums, JSDurationFormat::FieldStyle::kUndefined),
      Nothing<DurationUnitOptions>());

  // 2. Let displayDefault be "always".
  JSDurationFormat::Display display_default =
      JSDurationFormat::Display::kAlways;
  // 3. If style is undefined, then
  if (style == JSDurationFormat::FieldStyle::kUndefined) {
    // a. If baseStyle is "digital", then
    if (base_style == JSDurationFormat::Style::kDigital) {
      // i. If unit is not one of "hours", "minutes", or "seconds", then
      if (unit != Unit::kHours && unit != Unit::kMinutes &&
          unit != Unit::kSeconds) {
        // a. Set displayDefault to "auto".
        display_default = JSDurationFormat::Display::kAuto;
      }
      // ii. Set style to digitalBase.
      style = digital_base;
      // b. Else
    } else {
      // i. if prevStyle is "fractional", "numeric", or "2-digit", then
      if (prev_style == JSDurationFormat::FieldStyle::kFractional ||
          prev_style == JSDurationFormat::FieldStyle::kNumeric ||
          prev_style == JSDurationFormat::FieldStyle::k2Digit) {
        // 1. If unit is not one of "minutes" or "seconds", then
        if (unit != Unit::kMinutes && unit != Unit::kSeconds) {
          // a. Set displayDefault to "auto".
          display_default = JSDurationFormat::Display::kAuto;
        }
        // 2. Set style to "numeric".
        style = JSDurationFormat::FieldStyle::kNumeric;
        // iii. Else,
      } else {
        // 1. Set displayDefault to "auto".
        display_default = JSDurationFormat::Display::kAuto;
        // 2. Set style to baseStyle.
        switch (base_style) {
          case JSDurationFormat::Style::kLong:
            style = JSDurationFormat::FieldStyle::kLong;
            break;
          case JSDurationFormat::Style::kShort:
            style = JSDurationFormat::FieldStyle::kShort;
            break;
          case JSDurationFormat::Style::kNarrow:
            style = JSDurationFormat::FieldStyle::kNarrow;
            break;
          default:
            UNREACHABLE();
        }
      }
    }
  }
  // 4. If style is "numeric", then
  if (style == JSDurationFormat::FieldStyle::kNumeric) {
    // a. If unit is one of "milliseconds", "microseconds", or "nanoseconds",
    // then
    if (unit == Unit::kMilliseconds || unit == Unit::kMicroseconds ||
        unit == Unit::kNanoseconds) {
      // i. Set style to "fractional".
      style = JSDurationFormat::FieldStyle::kFractional;
      // ii. Set displayDefault to "auto".
      display_default = JSDurationFormat::Display::kAuto;
    }
  }
  // 5. Let displayField be the string-concatenation of unit and "Display".
  // 6. Let display be ? GetOption(options, displayField, "string", « "auto",
  // "always" », displayDefault).
  JSDurationFormat::Display display;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, display,
      GetStringOption<JSDurationFormat::Display>(
          isolate, options, display_field, method_name, {"auto", "always"},
          {JSDurationFormat::Display::kAuto,
           JSDurationFormat::Display::kAlways},
          display_default),
      Nothing<DurationUnitOptions>());
  // 7. If display is "always" and style is "fractional", then
  if (display == JSDurationFormat::Display::kAlways &&
      style == JSDurationFormat::FieldStyle::kFractional) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kInvalid,
                      isolate->factory()->object_string(), options),
        Nothing<DurationUnitOptions>());
  }
  // 8. If prevStyle is "fractional", then
  if (prev_style == JSDurationFormat::FieldStyle::kFractional) {
    // a. If style is not "fractional", then
    if (style != JSDurationFormat::FieldStyle::kFractional) {
      // i. Throw a RangeError exception.
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kInvalid,
                        isolate->factory()->object_string(), options),
          Nothing<DurationUnitOptions>());
    }
  }
  // 7. If prevStyle is "numeric" or "2-digit", then
  if (prev_style == JSDurationFormat::FieldStyle::kNumeric ||
      prev_style == JSDurationFormat::FieldStyle::k2Digit) {
    // a. If style is not "fractional", "numeric" or "2-digit", then
    if (style != JSDurationFormat::FieldStyle::kFractional &&
        style != JSDurationFormat::FieldStyle::kNumeric &&
        style != JSDurationFormat::FieldStyle::k2Digit) {
      // i. Throw a RangeError exception.
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kInvalid,
                        isolate->factory()->object_string(), options),
          Nothing<DurationUnitOptions>());
    }
    // b. If unit is "minutes" or "seconds", then
    if (unit == Unit::kMinutes || unit == Unit::kSeconds) {
      // i. Set style to "2-digit".
      style = JSDurationFormat::FieldStyle::k2Digit;
    }
  }
  // 8. Return the Record { [[Style]]: style, [[Display]]: display }.
  return Just(DurationUnitOptions({style, display}));
}

JSDurationFormat::Separator GetSeparator(const icu::Locale& l) {
  UErrorCode status = U_ZERO_ERROR;
  icu::DateFormatSymbols sym(l, status);
  if (U_FAILURE(status)) return JSDurationFormat::Separator::kColon;
  icu::UnicodeString sep;
  sym.getTimeSeparatorString(sep);
  if (sep.length() != 1) return JSDurationFormat::Separator::kColon;
  switch (sep.charAt(0)) {
    case u'.':
      return JSDurationFormat::Separator::kFullStop;
    case u'\uFF1A':
      return JSDurationFormat::Separator::kFullwidthColon;
    case u'\u066B':
      return JSDurationFormat::Separator::kArabicDecimalSeparator;
    // By default, or if we get anything else, just use ':'.
    default:
      return JSDurationFormat::Separator::kColon;
  }
}

}  // namespace
MaybeHandle<JSDurationFormat> JSDurationFormat::New(
    Isolate* isolate, DirectHandle<Map> map, Handle<Object> locales,
    Handle<Object> input_options) {
  Factory* factory = isolate->factory();
  const char* method_name = "Intl.DurationFormat";

  // 3. Let requestedLocales be ? CanonicalizeLocaleList(locales).
  std::vector<std::string> requested_locales;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, requested_locales,
      Intl::CanonicalizeLocaleList(isolate, locales),
      Handle<JSDurationFormat>());

  // 4. Let options be ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, input_options, method_name));

  // 5. Let matcher be ? GetOption(options, "localeMatcher", "string", «
  // "lookup", "best fit" », "best fit").
  Intl::MatcherOption matcher;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, matcher, Intl::GetLocaleMatcher(isolate, options, method_name),
      Handle<JSDurationFormat>());

  // 6. Let numberingSystem be ? GetOption(options, "numberingSystem", "string",
  // undefined, undefined).
  //
  // 7. If numberingSystem is not undefined, then
  //
  // a. If numberingSystem does not match the Unicode Locale Identifier type
  // nonterminal, throw a RangeError exception.
  // Note: The matching test and throw in Step 7-a is throw inside
  // Intl::GetNumberingSystem.
  std::unique_ptr<char[]> numbering_system_str = nullptr;
  bool get;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, get,
      Intl::GetNumberingSystem(isolate, options, method_name,
                               &numbering_system_str),
      Handle<JSDurationFormat>());

  // 8. Let opt be the Record { [[localeMatcher]]: matcher, [[nu]]:
  // numberingSystem }.
  // 9. Let r be ResolveLocale(%DurationFormat%.[[AvailableLocales]],
  // requestedLocales, opt, %DurationFormat%.[[RelevantExtensionKeys]],
  // %DurationFormat%.[[LocaleData]]).
  std::set<std::string> relevant_extension_keys{"nu"};
  Intl::ResolvedLocale r;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, r,
      Intl::ResolveLocale(isolate, JSDurationFormat::GetAvailableLocales(),
                          requested_locales, matcher, relevant_extension_keys),
      Handle<JSDurationFormat>());

  // 10. Let locale be r.[[locale]].
  icu::Locale r_locale = r.icu_locale;
  UErrorCode status = U_ZERO_ERROR;
  // 11. Set durationFormat.[[Locale]] to locale.
  // 12. Set durationFormat.[[NumberingSystem]] to r.[[nu]].
  if (numbering_system_str != nullptr) {
    auto nu_extension_it = r.extensions.find("nu");
    if (nu_extension_it != r.extensions.end() &&
        nu_extension_it->second != numbering_system_str.get()) {
      r_locale.setUnicodeKeywordValue("nu", nullptr, status);
      DCHECK(U_SUCCESS(status));
    }
  }
  icu::Locale icu_locale = r_locale;
  if (numbering_system_str != nullptr &&
      Intl::IsValidNumberingSystem(numbering_system_str.get())) {
    r_locale.setUnicodeKeywordValue("nu", numbering_system_str.get(), status);
    DCHECK(U_SUCCESS(status));
  }
  std::string numbering_system = Intl::GetNumberingSystem(r_locale);
  Separator separator = GetSeparator(r_locale);

  // 13. Let style be ? GetOption(options, "style", "string", « "long", "short",
  // "narrow", "digital" », "long").
  Style style;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, style,
      GetStringOption<Style>(
          isolate, options, "style", method_name,
          {"long", "short", "narrow", "digital"},
          {Style::kLong, Style::kShort, Style::kNarrow, Style::kDigital},
          Style::kShort),
      Handle<JSDurationFormat>());

  // 14. Set durationFormat.[[Style]] to style.
  // 15. Set durationFormat.[[DataLocale]] to r.[[dataLocale]].
  DirectHandle<Managed<icu::Locale>> managed_locale =
      Managed<icu::Locale>::From(
          isolate, 0, std::shared_ptr<icu::Locale>{icu_locale.clone()});
  // 16. Let prevStyle be the empty String.
  // 17. For each row of Table 1, except the header row, in table order, do
  //   a. Let styleSlot be the Style Slot value of the current row.
  //   b. Let displaySlot be the Display Slot value of the current row.
  //   c. Let unit be the Unit value.
  //   d. Let valueList be the Values value.
  //   e. Let digitalBase be the Digital Default value.
  //   f. Let unitOptions be ? GetDurationUnitOptions(unit, options, style,
  //      valueList, digitalBase, prevStyle).
  //      of durationFormat to unitOptions.[[Style]].
  //   h. Set the value of the
  //      displaySlot slot of durationFormat to unitOptions.[[Display]].
  //   i. If unit is one of "hours", "minutes", "seconds", "milliseconds",
  //      or "microseconds", then
  //      i. Set prevStyle to unitOptions.[[Style]].
  //   g. Set the value of the styleSlot slot
  DurationUnitOptions years_option;
  DurationUnitOptions months_option;
  DurationUnitOptions weeks_option;
  DurationUnitOptions days_option;
  DurationUnitOptions hours_option;
  DurationUnitOptions minutes_option;
  DurationUnitOptions seconds_option;
  DurationUnitOptions milliseconds_option;
  DurationUnitOptions microseconds_option;
  DurationUnitOptions nanoseconds_option;

#define CALL_GET_DURATION_UNIT_OPTIONS(unit, property, strings, enums,         \
                                       digital_base, prev_style)               \
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(                                      \
      isolate, property##_option,                                              \
      GetDurationUnitOptions(                                                  \
          isolate, Unit::unit, #property, #property "Display", options, style, \
          strings, enums, JSDurationFormat::FieldStyle::digital_base,          \
          prev_style),                                                         \
      Handle<JSDurationFormat>());

  // #table-durationformat
  // Table 3: Internal slots and property names of DurationFormat instances
  // relevant to Intl.DurationFormat constructor
  // [[YearsStyle]] [[YearsDisplay]] "years" « "long", "short",
  // "narrow" » "short"
  CALL_GET_DURATION_UNIT_OPTIONS(kYears, years, kLongShortNarrowStrings,
                                 kLongShortNarrowEnums, kShort,
                                 FieldStyle::kUndefined)
  // [[MonthsStyle]] [[MonthsDisplay]] "months" « "long",
  // "short", "narrow" » "short"
  CALL_GET_DURATION_UNIT_OPTIONS(kMonths, months, kLongShortNarrowStrings,
                                 kLongShortNarrowEnums, kShort,
                                 years_option.style)
  // [[WeeksStyle]] [[WeeksDisplay]] "weeks" « "long", "short",
  // "narrow" » "short"
  CALL_GET_DURATION_UNIT_OPTIONS(kWeeks, weeks, kLongShortNarrowStrings,
                                 kLongShortNarrowEnums, kShort,
                                 months_option.style)
  // [[DaysStyle]] [[DaysDisplay]] "days" « "long", "short", "narrow" »
  // "short"
  CALL_GET_DURATION_UNIT_OPTIONS(kDays, days, kLongShortNarrowStrings,
                                 kLongShortNarrowEnums, kShort,
                                 weeks_option.style)

  // [[HoursStyle]] [[HoursDisplay]] "hours" « "long", "short",
  // "narrow", "numeric", "2-digit" » "numeric"
  CALL_GET_DURATION_UNIT_OPTIONS(
      kHours, hours, kLongShortNarrowNumeric2DigitStrings,
      kLongShortNarrowNumeric2DigitEnums, kNumeric, days_option.style)
  // [[MinutesStyle]] [[MinutesDisplay]] "minutes" « "long",
  // "short", "narrow", "numeric", "2-digit" » "numeric"
  CALL_GET_DURATION_UNIT_OPTIONS(
      kMinutes, minutes, kLongShortNarrowNumeric2DigitStrings,
      kLongShortNarrowNumeric2DigitEnums, kNumeric, hours_option.style)

  // [[SecondsStyle]] [[SecondsDisplay]] "seconds" « "long",
  // "short", "narrow", "numeric", "2-digit" »
  CALL_GET_DURATION_UNIT_OPTIONS(
      kSeconds, seconds, kLongShortNarrowNumeric2DigitStrings,
      kLongShortNarrowNumeric2DigitEnums, kNumeric, minutes_option.style)

  // [[MillisecondsStyle]] [[MillisecondsDisplay]] "milliseconds" «
  // "long", "short", "narrow", "numeric" » "numeric"
  CALL_GET_DURATION_UNIT_OPTIONS(
      kMilliseconds, milliseconds, kLongShortNarrowNumericStrings,
      kLongShortNarrowNumericEnums, kNumeric, seconds_option.style)

  // [[MicrosecondsStyle]] [[MicrosecondsDisplay]] "microseconds" «
  // "long", "short", "narrow", "numeric" » "numeric"
  CALL_GET_DURATION_UNIT_OPTIONS(
      kMicroseconds, microseconds, kLongShortNarrowNumericStrings,
      kLongShortNarrowNumericEnums, kNumeric, milliseconds_option.style)

  // [[NanosecondsStyle]] [[NanosecondsDisplay]] "nanoseconds" «
  // "long", "short", "narrow", "numeric" » "numeric"
  CALL_GET_DURATION_UNIT_OPTIONS(
      kNanoseconds, nanoseconds, kLongShortNarrowNumericStrings,
      kLongShortNarrowNumericEnums, kNumeric, microseconds_option.style)

#undef CALL_GET_DURATION_UNIT_OPTIONS
  // 18. Set durationFormat.[[FractionalDigits]] to ? GetNumberOption(options,
  // "fractionalDigits", 0, 9, undefined).
  int fractional_digits;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, fractional_digits,
      GetNumberOption(isolate, options, factory->fractionalDigits_string(), 0,
                      9, kUndefinedFractionalDigits),
      Handle<JSDurationFormat>());

  icu::number::LocalizedNumberFormatter fmt =
      icu::number::UnlocalizedNumberFormatter()
          .roundingMode(UNUM_ROUND_HALFUP)
          .locale(icu_locale);
  if (!numbering_system.empty() && numbering_system != "latn") {
    fmt = fmt.adoptSymbols(icu::NumberingSystem::createInstanceByName(
        numbering_system.c_str(), status));
    DCHECK(U_SUCCESS(status));
  }
  DirectHandle<Managed<icu::number::LocalizedNumberFormatter>>
      managed_number_formatter =
          Managed<icu::number::LocalizedNumberFormatter>::From(
              isolate, 0,
              std::make_shared<icu::number::LocalizedNumberFormatter>(fmt));

  // 19. Return durationFormat.
  Handle<JSDurationFormat> duration_format =
      Cast<JSDurationFormat>(factory->NewFastOrSlowJSObjectFromMap(map));
  duration_format->set_style_flags(0);
  duration_format->set_display_flags(0);
  duration_format->set_style(style);
  duration_format->set_years_style(years_option.style);
  duration_format->set_months_style(months_option.style);
  duration_format->set_weeks_style(weeks_option.style);
  duration_format->set_days_style(days_option.style);
  duration_format->set_hours_style(hours_option.style);
  duration_format->set_minutes_style(minutes_option.style);
  duration_format->set_seconds_style(seconds_option.style);
  duration_format->set_milliseconds_style(milliseconds_option.style);
  duration_format->set_microseconds_style(microseconds_option.style);
  duration_format->set_nanoseconds_style(nanoseconds_option.style);
  duration_format->set_separator(separator);

  duration_format->set_years_display(years_option.display);
  duration_format->set_months_display(months_option.display);
  duration_format->set_weeks_display(weeks_option.display);
  duration_format->set_days_display(days_option.display);
  duration_format->set_hours_display(hours_option.display);
  duration_format->set_minutes_display(minutes_option.display);
  duration_format->set_seconds_display(seconds_option.display);
  duration_format->set_milliseconds_display(milliseconds_option.display);
  duration_format->set_microseconds_display(microseconds_option.display);
  duration_format->set_nanoseconds_display(nanoseconds_option.display);

  duration_format->set_fractional_digits(fractional_digits);

  duration_format->set_icu_locale(*managed_locale);
  duration_format->set_icu_number_formatter(*managed_number_formatter);

  return duration_format;
}

namespace {

Handle<String> StyleToString(Isolate* isolate, JSDurationFormat::Style style) {
  switch (style) {
    case JSDurationFormat::Style::kLong:
      return ReadOnlyRoots(isolate).long_string_handle();
    case JSDurationFormat::Style::kShort:
      return ReadOnlyRoots(isolate).short_string_handle();
    case JSDurationFormat::Style::kNarrow:
      return ReadOnlyRoots(isolate).narrow_string_handle();
    case JSDurationFormat::Style::kDigital:
      return ReadOnlyRoots(isolate).digital_string_handle();
  }
}

Handle<String> StyleToString(Isolate* isolate,
                             JSDurationFormat::FieldStyle style) {
  switch (style) {
    case JSDurationFormat::FieldStyle::kLong:
      return ReadOnlyRoots(isolate).long_string_handle();
    case JSDurationFormat::FieldStyle::kShort:
      return ReadOnlyRoots(isolate).short_string_handle();
    case JSDurationFormat::FieldStyle::kNarrow:
      return ReadOnlyRoots(isolate).narrow_string_handle();
    case JSDurationFormat::FieldStyle::kNumeric:
      return ReadOnlyRoots(isolate).numeric_string_handle();
    case JSDurationFormat::FieldStyle::k2Digit:
      return ReadOnlyRoots(isolate).two_digit_string_handle();
    case JSDurationFormat::FieldStyle::kFractional:
      // Step 3 in Intl.DurationFormat.prototype.resolvedOptions ( )
      // e. If v is "fractional", then
      // ii. Set v to "numeric".
      return ReadOnlyRoots(isolate).numeric_string_handle();
    case JSDurationFormat::FieldStyle::kUndefined:
      UNREACHABLE();
  }
}

Handle<String> DisplayToString(Isolate* isolate,
                               JSDurationFormat::Display display) {
  switch (display) {
    case JSDurationFormat::Display::kAuto:
      return ReadOnlyRoots(isolate).auto_string_handle();
    case JSDurationFormat::Display::kAlways:
      return ReadOnlyRoots(isolate).always_string_handle();
  }
}

}  // namespace

Handle<JSObject> JSDurationFormat::ResolvedOptions(
    Isolate* isolate, DirectHandle<JSDurationFormat> format) {
  Factory* factory = isolate->factory();
  Handle<JSObject> options = factory->NewJSObject(isolate->object_function());

  Handle<String> locale = factory->NewStringFromAsciiChecked(
      Intl::ToLanguageTag(*format->icu_locale()->raw()).FromJust().c_str());
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString skeleton =
      format->icu_number_formatter()->raw()->toSkeleton(status);
  DCHECK(U_SUCCESS(status));

  Handle<String> numbering_system;
  CHECK(Intl::ToString(isolate,
                       JSNumberFormat::NumberingSystemFromSkeleton(skeleton))
            .ToHandle(&numbering_system));

  bool created;

#define OUTPUT_PROPERTY(s, f)                                           \
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(                               \
      isolate, created,                                                 \
      JSReceiver::CreateDataProperty(isolate, options, factory->s(), f, \
                                     Just(kDontThrow)),                 \
      Handle<JSObject>());                                              \
  CHECK(created);
#define OUTPUT_STYLE_PROPERTY(p) \
  OUTPUT_PROPERTY(p##_string, StyleToString(isolate, format->p##_style()))
#define OUTPUT_DISPLAY_PROPERTY(p)   \
  OUTPUT_PROPERTY(p##Display_string, \
                  DisplayToString(isolate, format->p##_display()))
#define OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(p) \
  OUTPUT_STYLE_PROPERTY(p);                    \
  OUTPUT_DISPLAY_PROPERTY(p);

  // #table-durationformat-resolvedoptions-properties
  // Table 4: Resolved Options of DurationFormat Instances
  // [[Locale]] "locale"
  OUTPUT_PROPERTY(locale_string, locale);
  // [[NumberingSystem]] "numberingSystem"
  OUTPUT_PROPERTY(numberingSystem_string, numbering_system);
  // [[Style]] "style"
  OUTPUT_PROPERTY(style_string, StyleToString(isolate, format->style()));

  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(years);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(months);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(weeks);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(days);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(hours);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(minutes);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(seconds);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(milliseconds);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(microseconds);
  OUTPUT_STYLE_AND_DISPLAY_PROPERTIES(nanoseconds);

  // [[FractionalDigits]] "fractionalDigits"

  // c. If p is "fractionalDigits", then
  int32_t fractional_digits = format->fractional_digits();
  // i. If v is not undefined, set v to 𝔽(v).
  if (kUndefinedFractionalDigits != fractional_digits) {
    Handle<Smi> fractional_digits_obj =
        handle(Smi::FromInt(fractional_digits), isolate);
    // f. If v is not undefined, then
    // i. Perform ! CreateDataPropertyOrThrow(options, p, v).
    OUTPUT_PROPERTY(fractionalDigits_string, fractional_digits_obj);
  }
#undef OUTPUT_PROPERTY
#undef OUTPUT_STYLE_PROPERTY
#undef OUTPUT_DISPLAY_PROPERTY
#undef OUTPUT_STYLE_AND_DISPLAY_PROPERTIES

  return options;
}

namespace {

UNumberUnitWidth ToUNumberUnitWidth(JSDurationFormat::FieldStyle style) {
  switch (style) {
    case JSDurationFormat::FieldStyle::kShort:
      return UNumberUnitWidth::UNUM_UNIT_WIDTH_SHORT;
    case JSDurationFormat::FieldStyle::kLong:
      return UNumberUnitWidth::UNUM_UNIT_WIDTH_FULL_NAME;
    case JSDurationFormat::FieldStyle::kNarrow:
      return UNumberUnitWidth::UNUM_UNIT_WIDTH_NARROW;
    default:
      UNREACHABLE();
  }
}

struct Part {
  enum Type { kFormatted, kSeparator };
  Type part_type;
  std::string type;
  icu::number::FormattedNumber formatted;
};

char16_t SeparatorToChar(JSDurationFormat::Separator separator) {
  switch (separator) {
    case JSDurationFormat::Separator::kColon:
      return u':';
    case JSDurationFormat::Separator::kFullStop:
      return u'.';
    case JSDurationFormat::Separator::kFullwidthColon:
      return u'\uFF1A';
    case JSDurationFormat::Separator::kArabicDecimalSeparator:
      return u'\u066B';
  }
}

bool FormattedToParts(const char*, icu::number::FormattedNumber&, bool, bool,
                      JSDurationFormat::Separator,
                      std::vector<std::vector<Part>>*,
                      std::vector<icu::UnicodeString>*);

bool Output(const char* type, double value,
            const icu::number::LocalizedNumberFormatter& fmt, bool addToLast,
            bool display_negative_sign, bool negative_duration,
            JSDurationFormat::Separator separator,
            std::vector<std::vector<Part>>* parts,
            std::vector<icu::UnicodeString>* strings) {
  icu::number::LocalizedNumberFormatter nfOpts(fmt);
  // i. If displayNegativeSign is true, then
  if (display_negative_sign) {
    // 1. Set displayNegativeSign to false.
    display_negative_sign = false;
    // 2. If value is 0 and DurationRecordSign(duration) is -1, then
    if (value == 0.0 && negative_duration) {
      // a. Set value to negative-zero.
      value = -0.0;
    }
  } else {  // ii. Else,
    // 1. Perform ! CreateDataPropertyOrThrow(nfOpts, "signDisplay", "never").
    nfOpts = nfOpts.sign(UNumberSignDisplay::UNUM_SIGN_NEVER);
  }

  UErrorCode status = U_ZERO_ERROR;
  icu::number::FormattedNumber formatted = nfOpts.formatDouble(value, status);
  DCHECK(U_SUCCESS(status));
  return FormattedToParts(type, formatted, addToLast, display_negative_sign,
                          separator, parts, strings);
}

bool FormattedToParts(const char* type, icu::number::FormattedNumber& formatted,
                      bool addToLast, bool display_negative_sign,
                      JSDurationFormat::Separator separator,
                      std::vector<std::vector<Part>>* parts,
                      std::vector<icu::UnicodeString>* strings) {
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString unit_string = formatted.toString(status);
  DCHECK(U_SUCCESS(status));
  Part p = {Part::Type::kFormatted, std::string(type), std::move(formatted)};
  if (addToLast && !strings->empty()) {
    strings->back().append(SeparatorToChar(separator));
    strings->back() += unit_string;

    if (parts != nullptr) {
      icu::number::FormattedNumber dummy;
      Part s = {Part::Type::kSeparator, std::string(), std::move(dummy)};
      parts->back().push_back(std::move(s));
      parts->back().push_back(std::move(p));
    }
    return display_negative_sign;
  }
  strings->push_back(unit_string);
  if (parts != nullptr) {
    std::vector<Part> v;
    v.push_back(std::move(p));
    parts->push_back(std::move(v));
  }
  return display_negative_sign;
}

bool OutputLongShortOrNarrow(const char* type, double value,
                             JSDurationFormat::Display display,
                             const icu::number::LocalizedNumberFormatter& fmt,
                             bool addToLast, bool display_negative_sign,
                             bool negative_duration,
                             JSDurationFormat::Separator separator,
                             std::vector<std::vector<Part>>* parts,
                             std::vector<icu::UnicodeString>* strings) {
  if (value == 0 && display == JSDurationFormat::Display::kAuto)
    return display_negative_sign;
  return Output(type, value, fmt, addToLast, display_negative_sign,
                negative_duration, separator, parts, strings);
}

bool OutputLongShortNarrowOrNumeric(
    const char* type, double value, JSDurationFormat::Display display,
    JSDurationFormat::FieldStyle style,
    const icu::number::LocalizedNumberFormatter& fmt, icu::MeasureUnit unit,
    bool addToLast, bool display_negative_sign, bool negative_duration,
    JSDurationFormat::Separator separator,
    std::vector<std::vector<Part>>* parts,
    std::vector<icu::UnicodeString>* strings) {
  if (value == 0 && display == JSDurationFormat::Display::kAuto)
    return display_negative_sign;
  if (style == JSDurationFormat::FieldStyle::kNumeric) {
    return Output(type, value,
                  fmt.grouping(UNumberGroupingStrategy::UNUM_GROUPING_OFF),
                  addToLast, display_negative_sign, negative_duration,
                  separator, parts, strings);
  }
  return OutputLongShortOrNarrow(
      type, value, display, fmt.unit(unit).unitWidth(ToUNumberUnitWidth(style)),
      addToLast, display_negative_sign, negative_duration, separator, parts,
      strings);
}

bool OutputLongShortNarrowNumericOr2Digit(
    const char* type, double value, JSDurationFormat::Display display,
    JSDurationFormat::FieldStyle style,
    const icu::number::LocalizedNumberFormatter& fmt, icu::MeasureUnit unit,
    bool maybeAddToLast, bool displayRequired, bool display_negative_sign,
    bool negative_duration, JSDurationFormat::Separator separator,
    std::vector<std::vector<Part>>* parts,
    std::vector<icu::UnicodeString>* strings) {
  // k. If value is not 0 or display is not "auto" or displayRequired is "true",
  // then
  if ((value != 0) || (display != JSDurationFormat::Display::kAuto) ||
      displayRequired) {
    if (style == JSDurationFormat::FieldStyle::k2Digit) {
      return Output(type, value,
                    fmt.integerWidth(icu::number::IntegerWidth::zeroFillTo(2))
                        .grouping(UNumberGroupingStrategy::UNUM_GROUPING_OFF),
                    maybeAddToLast, display_negative_sign, negative_duration,
                    separator, parts, strings);
    }
    bool addToLast =
        maybeAddToLast && (JSDurationFormat::FieldStyle::kNumeric == style);
    return OutputLongShortNarrowOrNumeric(
        type, value, display, style, fmt, unit, addToLast,
        display_negative_sign, negative_dur
```