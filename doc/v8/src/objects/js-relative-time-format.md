Response: Let's break down the thought process to analyze the C++ code and generate the summary and JavaScript example.

1. **Understand the Goal:** The request asks for a functional summary of the C++ code and a JavaScript example illustrating its usage. The file path `v8/src/objects/js-relative-time-format.cc` strongly suggests it's part of V8, the JavaScript engine, and likely relates to the `Intl.RelativeTimeFormat` JavaScript API.

2. **Initial Scan for Keywords:** I'll quickly scan the code for recognizable terms related to internationalization and JavaScript. Keywords like `Intl`, `RelativeTimeFormat`, `locale`, `style`, `numeric`, `unit`, `format`, `JSObject`, `Handle`, `MaybeHandle`, `isolate`, etc., immediately stand out. The inclusion of ICU headers (`unicode/reldatefmt.h`, `unicode/numfmt.h`) confirms its connection to internationalization.

3. **Identify the Core Class:** The presence of `class JSRelativeTimeFormat` and methods like `New`, `ResolvedOptions`, `Format`, and `FormatToParts` strongly indicates this is the central class implementing the functionality.

4. **Analyze the `New` Method:** This method seems to be the constructor or factory function for `JSRelativeTimeFormat` objects. I'll examine its steps:
    * It takes `locales` and `input_options` as arguments, mirroring the JavaScript `Intl.RelativeTimeFormat` constructor.
    * It canonicalizes locales.
    * It handles options like `localeMatcher`, `numberingSystem`, `style`, and `numeric`.
    * It resolves the locale using ICU's `ResolveLocale`.
    * It creates an ICU `RelativeDateTimeFormatter`.
    * It stores the resolved options and the ICU formatter within the `JSRelativeTimeFormat` object.

5. **Analyze the `ResolvedOptions` Method:** This method retrieves the resolved options (locale, numbering system, style, numeric) from the `JSRelativeTimeFormat` object and returns them as a JavaScript object. This directly corresponds to the `resolvedOptions()` method in the JavaScript API.

6. **Analyze the `Format` and `FormatToParts` Methods:** These methods are clearly responsible for formatting relative time values.
    * They take a `value` (the relative time difference) and a `unit` (e.g., "day", "month") as input.
    * They use the stored ICU `RelativeDateTimeFormatter` to perform the formatting.
    * `Format` returns a string, while `FormatToParts` returns an array of parts, mirroring the behavior of the JavaScript API.

7. **Connect to JavaScript:** The function names (`New`, `ResolvedOptions`, `Format`, `FormatToParts`), the parameters they accept, and the data they return strongly suggest a direct mapping to the JavaScript `Intl.RelativeTimeFormat` API. The C++ code appears to be the underlying implementation within the V8 engine.

8. **Infer Functionality:** Based on the above analysis, I can infer the core functionality: this C++ code implements the `Intl.RelativeTimeFormat` API in V8. It handles locale negotiation, option processing, and uses ICU to format relative dates and times according to the specified locale and options.

9. **Construct the Summary:** I'll synthesize the findings into a concise summary, highlighting the key functionalities and its role in the JavaScript engine. I'll mention the core class, its methods, and the connection to the JavaScript API.

10. **Create the JavaScript Example:** To illustrate the connection, I'll create a simple JavaScript example demonstrating how to use `Intl.RelativeTimeFormat`. The example should:
    * Create an `Intl.RelativeTimeFormat` object with specific options.
    * Use the `format()` method to format different relative time values and units.
    * Use the `formatToParts()` method to show how the output can be broken down into parts.
    * Use the `resolvedOptions()` method to demonstrate how to retrieve the resolved configuration.

11. **Review and Refine:** I'll review the summary and the JavaScript example to ensure they are accurate, clear, and effectively demonstrate the functionality of the C++ code. I'll check for any inconsistencies or areas that could be explained more clearly. For instance, I'll emphasize that the C++ code *implements* the JavaScript API.

This methodical approach, starting with high-level understanding and gradually drilling down into the details of the code, allows for a comprehensive analysis and the generation of a meaningful summary and illustrative example. The key is to recognize the patterns and connections between the C++ code and the corresponding JavaScript API.
这个C++源代码文件 `v8/src/objects/js-relative-time-format.cc` 实现了 **ECMAScript 国际化 API 中 `Intl.RelativeTimeFormat` 对象的底层功能**。

**功能归纳:**

1. **对象创建和初始化 (`JSRelativeTimeFormat::New`)**:
   - 接收语言区域 (locales) 和选项 (options) 作为输入，用于创建 `Intl.RelativeTimeFormat` 对象。
   - **处理和验证选项**:  例如 `localeMatcher` (区域匹配算法), `numberingSystem` (数字系统), `style` (显示风格：long, short, narrow), `numeric` (数字显示：always, auto)。
   - **区域解析和协商**: 使用 ICU (International Components for Unicode) 库来解析和协商最合适的语言区域。
   - **创建 ICU 格式化器**:  使用 ICU 的 `RelativeDateTimeFormatter` 类，根据协商的语言区域和选项创建实际的格式化对象。
   - **存储配置信息**: 将解析后的语言区域、数字系统、样式、数字显示方式以及 ICU 格式化器的指针存储在 `JSRelativeTimeFormat` 对象中。

2. **获取已解析的选项 (`JSRelativeTimeFormat::ResolvedOptions`)**:
   - 返回一个包含 `Intl.RelativeTimeFormat` 对象已解析的配置选项的 JavaScript 对象，例如 `locale`, `numberingSystem`, `style`, `numeric`。

3. **格式化相对时间 (`JSRelativeTimeFormat::Format`)**:
   - 接收一个数值 (value) 和一个时间单位 (unit) 作为输入，例如 `-1`, "day"。
   - 使用存储的 ICU `RelativeDateTimeFormatter` 对象，根据对象的配置将数值和时间单位格式化成一个相对时间的字符串。
   - 例如，对于输入 `-1` 和 "day"，可能返回 "yesterday"。

4. **格式化相对时间并返回部件 (`JSRelativeTimeFormat::FormatToParts`)**:
   - 接收一个数值 (value) 和一个时间单位 (unit) 作为输入。
   - 使用存储的 ICU `RelativeDateTimeFormatter` 对象，将数值和时间单位格式化成一个包含多个部件的 JavaScript 数组。每个部件可能包含 `type` (例如 "literal", "number", "unit") 和 `value`。

5. **获取可用的语言区域 (`JSRelativeTimeFormat::GetAvailableLocales`)**:
   - 返回一个包含 `Intl.RelativeTimeFormat` 支持的所有语言区域的集合。

**与 JavaScript 功能的关系及示例:**

这个 C++ 文件是 V8 引擎中 `Intl.RelativeTimeFormat` API 的底层实现。当 JavaScript 代码中使用 `Intl.RelativeTimeFormat` 对象时，V8 引擎会调用这个 C++ 文件中的相应函数来完成实际的操作。

**JavaScript 示例:**

```javascript
// 创建一个 Intl.RelativeTimeFormat 对象，指定语言区域和样式
const rtf = new Intl.RelativeTimeFormat('zh', { style: 'long' });

// 使用 format 方法格式化相对时间
console.log(rtf.format(-1, 'day'));   // 输出: “昨天”
console.log(rtf.format(2, 'weeks'));  // 输出: “2周后”
console.log(rtf.format(-3, 'months')); // 输出: “3个月前”

// 创建另一个 Intl.RelativeTimeFormat 对象，指定不同的样式
const rtfShort = new Intl.RelativeTimeFormat('en', { style: 'short' });
console.log(rtfShort.format(-1, 'day'));  // 输出: "yesterday"
console.log(rtfShort.format(2, 'weeks')); // 输出: "in 2 wk."

// 使用 formatToParts 方法获取格式化结果的部件
const parts = rtf.formatToParts(-1, 'day');
console.log(parts); // 输出: [ { type: 'literal', value: '昨天' } ]

const partsWithNumber = new Intl.RelativeTimeFormat('en', { numeric: 'always' }).formatToParts(-2, 'day');
console.log(partsWithNumber);
// 可能输出:
// [
//   { type: 'literal', value: 'in ' },
//   { type: 'number', value: '2' },
//   { type: 'literal', value: ' days' }
// ]

// 获取已解析的选项
const resolvedOptions = rtf.resolvedOptions();
console.log(resolvedOptions);
// 可能输出: { locale: 'zh', numberingSystem: 'latn', style: 'long', numeric: 'auto' }
```

**总结:**

`v8/src/objects/js-relative-time-format.cc` 文件是 V8 引擎实现 `Intl.RelativeTimeFormat` 这个 JavaScript 国际化 API 的核心 C++ 代码。它负责对象的创建、选项处理、与 ICU 库交互进行本地化格式化，并提供了将相对时间格式化为字符串或分解为部件的功能。 这使得 JavaScript 开发者能够方便地在他们的应用程序中显示本地化的相对时间信息。

### 提示词
```
这是目录为v8/src/objects/js-relative-time-format.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

#include "src/objects/js-relative-time-format.h"

#include <map>
#include <memory>
#include <string>

#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/objects/intl-objects.h"
#include "src/objects/js-number-format.h"
#include "src/objects/js-relative-time-format-inl.h"
#include "src/objects/managed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/option-utils.h"
#include "unicode/decimfmt.h"
#include "unicode/numfmt.h"
#include "unicode/reldatefmt.h"
#include "unicode/unum.h"

namespace v8 {
namespace internal {

namespace {
// Style: identifying the relative time format style used.
//
// ecma402/#sec-properties-of-intl-relativetimeformat-instances

enum class Style {
  LONG,   // Everything spelled out.
  SHORT,  // Abbreviations used when possible.
  NARROW  // Use the shortest possible form.
};

UDateRelativeDateTimeFormatterStyle toIcuStyle(Style style) {
  switch (style) {
    case Style::LONG:
      return UDAT_STYLE_LONG;
    case Style::SHORT:
      return UDAT_STYLE_SHORT;
    case Style::NARROW:
      return UDAT_STYLE_NARROW;
  }
  UNREACHABLE();
}

Style fromIcuStyle(UDateRelativeDateTimeFormatterStyle icu_style) {
  switch (icu_style) {
    case UDAT_STYLE_LONG:
      return Style::LONG;
    case UDAT_STYLE_SHORT:
      return Style::SHORT;
    case UDAT_STYLE_NARROW:
      return Style::NARROW;
    case UDAT_STYLE_COUNT:
      UNREACHABLE();
  }
  UNREACHABLE();
}
}  // namespace

MaybeHandle<JSRelativeTimeFormat> JSRelativeTimeFormat::New(
    Isolate* isolate, DirectHandle<Map> map, Handle<Object> locales,
    Handle<Object> input_options) {
  // 1. Let requestedLocales be ? CanonicalizeLocaleList(locales).
  Maybe<std::vector<std::string>> maybe_requested_locales =
      Intl::CanonicalizeLocaleList(isolate, locales);
  MAYBE_RETURN(maybe_requested_locales, Handle<JSRelativeTimeFormat>());
  std::vector<std::string> requested_locales =
      maybe_requested_locales.FromJust();

  // 2. Set options to ? CoerceOptionsToObject(options).
  Handle<JSReceiver> options;
  const char* service = "Intl.RelativeTimeFormat";
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, CoerceOptionsToObject(isolate, input_options, service));

  // 4. Let opt be a new Record.
  // 5. Let matcher be ? GetOption(options, "localeMatcher", "string", «
  // "lookup", "best fit" », "best fit").
  // 6. Set opt.[[localeMatcher]] to matcher.
  Maybe<Intl::MatcherOption> maybe_locale_matcher =
      Intl::GetLocaleMatcher(isolate, options, service);
  MAYBE_RETURN(maybe_locale_matcher, MaybeHandle<JSRelativeTimeFormat>());
  Intl::MatcherOption matcher = maybe_locale_matcher.FromJust();

  // 7. Let _numberingSystem_ be ? GetOption(_options_, `"numberingSystem"`,
  //    `"string"`, *undefined*, *undefined*).
  std::unique_ptr<char[]> numbering_system_str = nullptr;
  Maybe<bool> maybe_numberingSystem = Intl::GetNumberingSystem(
      isolate, options, service, &numbering_system_str);
  // 8. If _numberingSystem_ is not *undefined*, then
  // a. If _numberingSystem_ does not match the
  //    `(3*8alphanum) *("-" (3*8alphanum))` sequence, throw a *RangeError*
  //     exception.
  MAYBE_RETURN(maybe_numberingSystem, MaybeHandle<JSRelativeTimeFormat>());

  // 9. Set _opt_.[[nu]] to _numberingSystem_.

  // 10. Let localeData be %RelativeTimeFormat%.[[LocaleData]].
  // 11. Let r be
  // ResolveLocale(%RelativeTimeFormat%.[[AvailableLocales]],
  //               requestedLocales, opt,
  //               %RelativeTimeFormat%.[[RelevantExtensionKeys]], localeData).
  Maybe<Intl::ResolvedLocale> maybe_resolve_locale =
      Intl::ResolveLocale(isolate, JSRelativeTimeFormat::GetAvailableLocales(),
                          requested_locales, matcher, {"nu"});
  if (maybe_resolve_locale.IsNothing()) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  Intl::ResolvedLocale r = maybe_resolve_locale.FromJust();

  UErrorCode status = U_ZERO_ERROR;

  icu::Locale icu_locale = r.icu_locale;
  if (numbering_system_str != nullptr) {
    auto nu_extension_it = r.extensions.find("nu");
    if (nu_extension_it != r.extensions.end() &&
        nu_extension_it->second != numbering_system_str.get()) {
      icu_locale.setUnicodeKeywordValue("nu", nullptr, status);
      DCHECK(U_SUCCESS(status));
    }
  }
  // 12. Let locale be r.[[Locale]].
  Maybe<std::string> maybe_locale_str = Intl::ToLanguageTag(icu_locale);
  MAYBE_RETURN(maybe_locale_str, MaybeHandle<JSRelativeTimeFormat>());

  // 13. Set relativeTimeFormat.[[Locale]] to locale.
  DirectHandle<String> locale_str =
      isolate->factory()->NewStringFromAsciiChecked(
          maybe_locale_str.FromJust().c_str());

  // 14. Set relativeTimeFormat.[[NumberingSystem]] to r.[[nu]].
  if (numbering_system_str != nullptr &&
      Intl::IsValidNumberingSystem(numbering_system_str.get())) {
    icu_locale.setUnicodeKeywordValue("nu", numbering_system_str.get(), status);
    DCHECK(U_SUCCESS(status));
  }
  // 15. Let dataLocale be r.[[DataLocale]].

  // 16. Let s be ? GetOption(options, "style", "string",
  //                          «"long", "short", "narrow"», "long").
  Maybe<Style> maybe_style = GetStringOption<Style>(
      isolate, options, "style", service, {"long", "short", "narrow"},
      {Style::LONG, Style::SHORT, Style::NARROW}, Style::LONG);
  MAYBE_RETURN(maybe_style, MaybeHandle<JSRelativeTimeFormat>());
  Style style_enum = maybe_style.FromJust();

  // 17. Set relativeTimeFormat.[[Style]] to s.

  // 18. Let numeric be ? GetOption(options, "numeric", "string",
  //                                «"always", "auto"», "always").
  Maybe<Numeric> maybe_numeric = GetStringOption<Numeric>(
      isolate, options, "numeric", service, {"always", "auto"},
      {Numeric::ALWAYS, Numeric::AUTO}, Numeric::ALWAYS);
  MAYBE_RETURN(maybe_numeric, MaybeHandle<JSRelativeTimeFormat>());
  Numeric numeric_enum = maybe_numeric.FromJust();

  // 19. Set relativeTimeFormat.[[Numeric]] to numeric.

  // 23. Let relativeTimeFormat.[[NumberFormat]] be
  //     ? Construct(%NumberFormat%, « nfLocale, nfOptions »).
  icu::NumberFormat* number_format =
      icu::NumberFormat::createInstance(icu_locale, UNUM_DECIMAL, status);
  if (U_FAILURE(status)) {
    // Data build filter files excluded data in "rbnf_tree" since ECMA402 does
    // not support "algorithmic" numbering systems. Therefore we may get the
    // U_MISSING_RESOURCE_ERROR here. Fallback to locale without the numbering
    // system and create the object again.
    if (status == U_MISSING_RESOURCE_ERROR) {
      delete number_format;
      status = U_ZERO_ERROR;
      icu_locale.setUnicodeKeywordValue("nu", nullptr, status);
      DCHECK(U_SUCCESS(status));
      number_format =
          icu::NumberFormat::createInstance(icu_locale, UNUM_DECIMAL, status);
    }
    if (U_FAILURE(status) || number_format == nullptr) {
      delete number_format;
      THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
    }
  }

  if (number_format->getDynamicClassID() ==
      icu::DecimalFormat::getStaticClassID()) {
    icu::DecimalFormat* decimal_format =
        static_cast<icu::DecimalFormat*>(number_format);
    decimal_format->setMinimumGroupingDigits(-2);
  }

  // Change UDISPCTX_CAPITALIZATION_NONE to other values if
  // ECMA402 later include option to change capitalization.
  // Ref: https://github.com/tc39/proposal-intl-relative-time/issues/11
  std::shared_ptr<icu::RelativeDateTimeFormatter> icu_formatter =
      std::make_shared<icu::RelativeDateTimeFormatter>(
          icu_locale, number_format, toIcuStyle(style_enum),
          UDISPCTX_CAPITALIZATION_NONE, status);
  if (U_FAILURE(status) || icu_formatter == nullptr) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }

  DirectHandle<String> numbering_system_string =
      isolate->factory()->NewStringFromAsciiChecked(
          Intl::GetNumberingSystem(icu_locale).c_str());

  DirectHandle<Managed<icu::RelativeDateTimeFormatter>> managed_formatter =
      Managed<icu::RelativeDateTimeFormatter>::From(isolate, 0,
                                                    std::move(icu_formatter));

  Handle<JSRelativeTimeFormat> relative_time_format_holder =
      Cast<JSRelativeTimeFormat>(
          isolate->factory()->NewFastOrSlowJSObjectFromMap(map));

  DisallowGarbageCollection no_gc;
  relative_time_format_holder->set_flags(0);
  relative_time_format_holder->set_locale(*locale_str);
  relative_time_format_holder->set_numberingSystem(*numbering_system_string);
  relative_time_format_holder->set_numeric(numeric_enum);
  relative_time_format_holder->set_icu_formatter(*managed_formatter);

  // 25. Return relativeTimeFormat.
  return relative_time_format_holder;
}

namespace {

Handle<String> StyleAsString(Isolate* isolate, Style style) {
  switch (style) {
    case Style::LONG:
      return ReadOnlyRoots(isolate).long_string_handle();
    case Style::SHORT:
      return ReadOnlyRoots(isolate).short_string_handle();
    case Style::NARROW:
      return ReadOnlyRoots(isolate).narrow_string_handle();
  }
  UNREACHABLE();
}

}  // namespace

Handle<JSObject> JSRelativeTimeFormat::ResolvedOptions(
    Isolate* isolate, DirectHandle<JSRelativeTimeFormat> format_holder) {
  Factory* factory = isolate->factory();
  icu::RelativeDateTimeFormatter* formatter =
      format_holder->icu_formatter()->raw();
  DCHECK_NOT_NULL(formatter);
  Handle<JSObject> result = factory->NewJSObject(isolate->object_function());
  DirectHandle<String> locale(format_holder->locale(), isolate);
  DirectHandle<String> numberingSystem(format_holder->numberingSystem(),
                                       isolate);
  JSObject::AddProperty(isolate, result, factory->locale_string(), locale,
                        NONE);
  JSObject::AddProperty(
      isolate, result, factory->style_string(),
      StyleAsString(isolate, fromIcuStyle(formatter->getFormatStyle())), NONE);
  JSObject::AddProperty(isolate, result, factory->numeric_string(),
                        format_holder->NumericAsString(), NONE);
  JSObject::AddProperty(isolate, result, factory->numberingSystem_string(),
                        numberingSystem, NONE);
  return result;
}

Handle<String> JSRelativeTimeFormat::NumericAsString() const {
  switch (numeric()) {
    case Numeric::ALWAYS:
      return GetReadOnlyRoots().always_string_handle();
    case Numeric::AUTO:
      return GetReadOnlyRoots().auto_string_handle();
  }
  UNREACHABLE();
}

namespace {

Handle<String> UnitAsString(Isolate* isolate, URelativeDateTimeUnit unit_enum) {
  Factory* factory = isolate->factory();
  switch (unit_enum) {
    case UDAT_REL_UNIT_SECOND:
      return factory->second_string();
    case UDAT_REL_UNIT_MINUTE:
      return factory->minute_string();
    case UDAT_REL_UNIT_HOUR:
      return factory->hour_string();
    case UDAT_REL_UNIT_DAY:
      return factory->day_string();
    case UDAT_REL_UNIT_WEEK:
      return factory->week_string();
    case UDAT_REL_UNIT_MONTH:
      return factory->month_string();
    case UDAT_REL_UNIT_QUARTER:
      return factory->quarter_string();
    case UDAT_REL_UNIT_YEAR:
      return factory->year_string();
    default:
      UNREACHABLE();
  }
}

bool GetURelativeDateTimeUnit(DirectHandle<String> unit,
                              URelativeDateTimeUnit* unit_enum) {
  std::unique_ptr<char[]> unit_str = unit->ToCString();
  if ((strcmp("second", unit_str.get()) == 0) ||
      (strcmp("seconds", unit_str.get()) == 0)) {
    *unit_enum = UDAT_REL_UNIT_SECOND;
  } else if ((strcmp("minute", unit_str.get()) == 0) ||
             (strcmp("minutes", unit_str.get()) == 0)) {
    *unit_enum = UDAT_REL_UNIT_MINUTE;
  } else if ((strcmp("hour", unit_str.get()) == 0) ||
             (strcmp("hours", unit_str.get()) == 0)) {
    *unit_enum = UDAT_REL_UNIT_HOUR;
  } else if ((strcmp("day", unit_str.get()) == 0) ||
             (strcmp("days", unit_str.get()) == 0)) {
    *unit_enum = UDAT_REL_UNIT_DAY;
  } else if ((strcmp("week", unit_str.get()) == 0) ||
             (strcmp("weeks", unit_str.get()) == 0)) {
    *unit_enum = UDAT_REL_UNIT_WEEK;
  } else if ((strcmp("month", unit_str.get()) == 0) ||
             (strcmp("months", unit_str.get()) == 0)) {
    *unit_enum = UDAT_REL_UNIT_MONTH;
  } else if ((strcmp("quarter", unit_str.get()) == 0) ||
             (strcmp("quarters", unit_str.get()) == 0)) {
    *unit_enum = UDAT_REL_UNIT_QUARTER;
  } else if ((strcmp("year", unit_str.get()) == 0) ||
             (strcmp("years", unit_str.get()) == 0)) {
    *unit_enum = UDAT_REL_UNIT_YEAR;
  } else {
    return false;
  }
  return true;
}

template <typename T>
MaybeHandle<T> FormatCommon(
    Isolate* isolate, DirectHandle<JSRelativeTimeFormat> format,
    Handle<Object> value_obj, Handle<Object> unit_obj, const char* func_name,
    MaybeHandle<T> (*formatToResult)(Isolate*,
                                     const icu::FormattedRelativeDateTime&,
                                     DirectHandle<String>, bool)) {
  // 3. Let value be ? ToNumber(value).
  Handle<Object> value;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, value,
                             Object::ToNumber(isolate, value_obj));
  double number = Object::NumberValue(*value);
  // 4. Let unit be ? ToString(unit).
  Handle<String> unit;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, unit,
                             Object::ToString(isolate, unit_obj));
  // 4. If isFinite(value) is false, then throw a RangeError exception.
  if (!std::isfinite(number)) {
    THROW_NEW_ERROR(
        isolate, NewRangeError(
                     MessageTemplate::kNotFiniteNumber,
                     isolate->factory()->NewStringFromAsciiChecked(func_name)));
  }
  icu::RelativeDateTimeFormatter* formatter = format->icu_formatter()->raw();
  DCHECK_NOT_NULL(formatter);
  URelativeDateTimeUnit unit_enum;
  if (!GetURelativeDateTimeUnit(unit, &unit_enum)) {
    THROW_NEW_ERROR(
        isolate,
        NewRangeError(MessageTemplate::kInvalidUnit,
                      isolate->factory()->NewStringFromAsciiChecked(func_name),
                      unit));
  }
  UErrorCode status = U_ZERO_ERROR;
  icu::FormattedRelativeDateTime formatted =
      (format->numeric() == JSRelativeTimeFormat::Numeric::ALWAYS)
          ? formatter->formatNumericToValue(number, unit_enum, status)
          : formatter->formatToValue(number, unit_enum, status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  return formatToResult(isolate, formatted, UnitAsString(isolate, unit_enum),
                        IsNaN(*value));
}

MaybeHandle<String> FormatToString(
    Isolate* isolate, const icu::FormattedRelativeDateTime& formatted,
    DirectHandle<String> unit, bool is_nan) {
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString result = formatted.toString(status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  return Intl::ToString(isolate, result);
}

Maybe<bool> AddLiteral(Isolate* isolate, Handle<JSArray> array,
                       const icu::UnicodeString& string, int32_t index,
                       int32_t start, int32_t limit) {
  Handle<String> substring;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, substring, Intl::ToString(isolate, string, start, limit),
      Nothing<bool>());
  Intl::AddElement(isolate, array, index, isolate->factory()->literal_string(),
                   substring);
  return Just(true);
}

Maybe<bool> AddUnit(Isolate* isolate, Handle<JSArray> array,
                    const icu::UnicodeString& string, int32_t index,
                    const NumberFormatSpan& part, DirectHandle<String> unit,
                    bool is_nan) {
  Handle<String> substring;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, substring,
      Intl::ToString(isolate, string, part.begin_pos, part.end_pos),
      Nothing<bool>());
  Intl::AddElement(isolate, array, index,
                   Intl::NumberFieldToType(isolate, part, string, is_nan),
                   substring, isolate->factory()->unit_string(), unit);
  return Just(true);
}

MaybeHandle<JSArray> FormatToJSArray(
    Isolate* isolate, const icu::FormattedRelativeDateTime& formatted,
    DirectHandle<String> unit, bool is_nan) {
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString string = formatted.toString(status);

  Factory* factory = isolate->factory();
  Handle<JSArray> array = factory->NewJSArray(0);
  icu::ConstrainedFieldPosition cfpos;
  cfpos.constrainCategory(UFIELD_CATEGORY_NUMBER);
  int32_t index = 0;

  int32_t previous_end = 0;
  DirectHandle<String> substring;
  std::vector<std::pair<int32_t, int32_t>> groups;
  while (formatted.nextPosition(cfpos, status) && U_SUCCESS(status)) {
    int32_t category = cfpos.getCategory();
    int32_t field = cfpos.getField();
    int32_t start = cfpos.getStart();
    int32_t limit = cfpos.getLimit();
    if (category == UFIELD_CATEGORY_NUMBER) {
      if (field == UNUM_GROUPING_SEPARATOR_FIELD) {
        groups.push_back(std::pair<int32_t, int32_t>(start, limit));
        continue;
      }
      if (start > previous_end) {
        Maybe<bool> maybe_added =
            AddLiteral(isolate, array, string, index++, previous_end, start);
        MAYBE_RETURN(maybe_added, Handle<JSArray>());
      }
      if (field == UNUM_INTEGER_FIELD) {
        for (auto start_limit : groups) {
          if (start_limit.first > start) {
            Maybe<bool> maybe_added =
                AddUnit(isolate, array, string, index++,
                        NumberFormatSpan(field, start, start_limit.first), unit,
                        is_nan);
            MAYBE_RETURN(maybe_added, Handle<JSArray>());
            maybe_added =
                AddUnit(isolate, array, string, index++,
                        NumberFormatSpan(UNUM_GROUPING_SEPARATOR_FIELD,
                                         start_limit.first, start_limit.second),
                        unit, is_nan);
            MAYBE_RETURN(maybe_added, Handle<JSArray>());
            start = start_limit.second;
          }
        }
      }
      Maybe<bool> maybe_added =
          AddUnit(isolate, array, string, index++,
                  NumberFormatSpan(field, start, limit), unit, is_nan);
      MAYBE_RETURN(maybe_added, Handle<JSArray>());
      previous_end = limit;
    }
  }
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  if (string.length() > previous_end) {
    Maybe<bool> maybe_added = AddLiteral(isolate, array, string, index,
                                         previous_end, string.length());
    MAYBE_RETURN(maybe_added, Handle<JSArray>());
  }

  JSObject::ValidateElements(*array);
  return array;
}

}  // namespace

MaybeHandle<String> JSRelativeTimeFormat::Format(
    Isolate* isolate, Handle<Object> value_obj, Handle<Object> unit_obj,
    DirectHandle<JSRelativeTimeFormat> format) {
  return FormatCommon<String>(isolate, format, value_obj, unit_obj,
                              "Intl.RelativeTimeFormat.prototype.format",
                              FormatToString);
}

MaybeHandle<JSArray> JSRelativeTimeFormat::FormatToParts(
    Isolate* isolate, Handle<Object> value_obj, Handle<Object> unit_obj,
    DirectHandle<JSRelativeTimeFormat> format) {
  return FormatCommon<JSArray>(
      isolate, format, value_obj, unit_obj,
      "Intl.RelativeTimeFormat.prototype.formatToParts", FormatToJSArray);
}

const std::set<std::string>& JSRelativeTimeFormat::GetAvailableLocales() {
  // Since RelativeTimeFormatter does not have a method to list all
  // available locales, work around by calling the DateFormat.
  return Intl::GetAvailableLocalesForDateFormat();
}

}  // namespace internal
}  // namespace v8
```