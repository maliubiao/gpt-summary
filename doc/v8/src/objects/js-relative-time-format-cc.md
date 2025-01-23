Response:
Let's break down the thought process for analyzing this V8 source code.

1. **Understand the Goal:** The request asks for the functionality of `v8/src/objects/js-relative-time-format.cc`, how it relates to JavaScript, potential errors, and if it's Torque.

2. **Initial Scan and Keywords:**  I'd first scan the code for obvious keywords and patterns:
    * `JSRelativeTimeFormat`:  This strongly suggests a C++ class representing a JavaScript object.
    * `#include "src/objects/js-relative-time-format.h"`:  Indicates a header file likely containing the class definition.
    * `#include "unicode/reldatefmt.h"`:  This is a major clue! `reldatefmt` probably stands for "relative date/time format," which aligns with the filename. This points towards internationalization (Intl) functionality.
    * `Intl::`, `icu::`:  These namespaces confirm the use of the ICU library for internationalization.
    * `MaybeHandle`, `Handle`: These are V8's smart pointers for garbage-collected objects.
    * `Format`, `ResolvedOptions`: These look like methods exposed to JavaScript.
    * `// ecma402`:  This comment references the ECMAScript Internationalization API specification.

3. **Identify the Core Functionality:** Based on the filename and ICU includes, the primary function is clearly to handle relative time formatting. This involves taking a number and a unit (e.g., `-1`, `day`) and formatting it according to a specific locale (e.g., "yesterday" in English).

4. **Examine Key Methods:**  I'd then look at the most important methods:
    * `JSRelativeTimeFormat::New`: This looks like the constructor or factory function. It takes `locales` and `input_options`, which are standard for Intl APIs. The logic involves canonicalizing locales, resolving the best matching locale, and creating an ICU `RelativeDateTimeFormatter`.
    * `JSRelativeTimeFormat::ResolvedOptions`: This method returns the resolved options of the formatter (locale, numbering system, style, numeric). This is standard behavior for Intl objects.
    * `JSRelativeTimeFormat::Format`: This is the core formatting method. It takes a `value` and a `unit`, and uses the underlying ICU formatter to produce a string.
    * `JSRelativeTimeFormat::FormatToParts`:  This method returns the formatted string as an array of parts, which is a feature of newer Intl APIs for finer-grained control.

5. **Connect to JavaScript:**  The prefix `JS` in `JSRelativeTimeFormat` is the key. This C++ code implements the functionality of the JavaScript `Intl.RelativeTimeFormat` object. I would then create a simple JavaScript example to illustrate its usage.

6. **Check for Torque:** The prompt specifically asks about `.tq` files. The provided file is `.cc`, so it's not a Torque file. I'd explicitly state this.

7. **Infer Code Logic (Input/Output):**  I'd analyze the `Format` method and construct simple examples of input (value, unit, options) and the expected output, considering different locales and styles.

8. **Identify Potential Errors:** I'd look for error handling (`THROW_NEW_ERROR`) and specific checks that could lead to errors. The code checks for invalid locales, numbering systems, and units. It also handles non-finite numbers. I'd provide JavaScript examples of how these errors might occur.

9. **Structure the Answer:**  Finally, I'd organize the findings into the requested categories: Functionality, Torque, JavaScript Example, Code Logic, and Common Errors. I'd use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Is this just about formatting numbers?  *Correction:* The presence of `reldatefmt` and mentions of "relative" clearly indicate it's specifically about formatting *relative* times (e.g., "yesterday", "in 5 minutes").
* **Doubt:**  How does the C++ code interact with JavaScript? *Clarification:* V8 uses C++ for performance-critical parts, and these C++ classes are exposed as JavaScript objects through V8's internal mechanisms. The `JSRelativeTimeFormat` is the C++ representation of the JavaScript `Intl.RelativeTimeFormat`.
* **Missing detail:**  What exactly does `FormatToParts` do? *Research/Code Analysis:* Looking at the code, it breaks down the formatted string into an array of objects, each representing a part (literal, number, unit).

By following these steps, analyzing the code snippets, and drawing upon general knowledge of V8 and internationalization, I can construct a comprehensive and accurate answer to the request.
好的，让我们来分析一下 `v8/src/objects/js-relative-time-format.cc` 这个 V8 源代码文件的功能。

**功能概览:**

`v8/src/objects/js-relative-time-format.cc` 实现了 JavaScript 中的 `Intl.RelativeTimeFormat` 对象的功能。这个对象用于以语言敏感的方式格式化相对时间，例如“昨天”、“3 小时后”或“下周”。

更具体地说，这个文件负责：

1. **对象的创建和初始化:**  `JSRelativeTimeFormat::New` 函数负责创建 `Intl.RelativeTimeFormat` 的实例。这包括处理传入的 `locales` 和 `options` 参数，并利用 ICU 库来初始化底层的相对时间格式化器。

2. **语言环境 (Locale) 处理:** 代码处理语言环境的协商和选择，确保根据用户的请求和可用的数据选择合适的语言环境。它还处理诸如数字系统 (numbering system) 等与语言环境相关的选项。

3. **选项处理:**  代码解析和验证 `Intl.RelativeTimeFormat` 构造函数的可选参数，例如 `style`（"long", "short", "narrow"）和 `numeric`（"always", "auto"）。

4. **与 ICU 库的集成:**  该文件大量使用了 ICU (International Components for Unicode) 库，特别是 `icu::RelativeDateTimeFormatter` 类，来进行实际的相对时间格式化。

5. **格式化核心逻辑:** `JSRelativeTimeFormat::Format` 和 `JSRelativeTimeFormat::FormatToParts` 函数实现了主要的格式化逻辑。它们接收一个数值和一个时间单位（例如，-1 和 "day"），并返回格式化后的字符串或包含格式化部件的数组。

6. **解析选项:** `JSRelativeTimeFormat::ResolvedOptions` 函数返回一个包含当前 `Intl.RelativeTimeFormat` 对象已解析选项的新对象。

**关于 Torque:**

根据您提供的代码，`v8/src/objects/js-relative-time-format.cc` **不是**以 `.tq` 结尾，因此它是一个标准的 **C++ 源代码文件**，而不是 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。

**与 JavaScript 功能的关系和示例:**

`v8/src/objects/js-relative-time-format.cc` 文件中的 C++ 代码直接支持 JavaScript 中的 `Intl.RelativeTimeFormat` API。

**JavaScript 示例:**

```javascript
// 创建一个英语环境的相对时间格式化器
const rtfEN = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });

console.log(rtfEN.format(-1, 'day')); // 输出: "yesterday"
console.log(rtfEN.format(1, 'day'));  // 输出: "tomorrow"
console.log(rtfEN.format(-3, 'hour')); // 输出: "3 hours ago"
console.log(rtfEN.format(5, 'minute')); // 输出: "in 5 minutes"

// 创建一个德语环境的相对时间格式化器，使用 'long' 样式
const rtfDE = new Intl.RelativeTimeFormat('de', { numeric: 'always', style: 'long' });

console.log(rtfDE.format(-1, 'day')); // 输出: "vor 1 Tag"
console.log(rtfDE.format(1, 'day'));  // 输出: "in 1 Tag"

// 使用 formatToParts 获取格式化部件
const rtfFR = new Intl.RelativeTimeFormat('fr', { numeric: 'auto' });
const parts = rtfFR.formatToParts(-2, 'month');
console.log(parts);
// 可能输出:
// [
//   { type: "literal", value: "il y a " },
//   { type: "integer", value: "2", unit: "month" },
//   { type: "literal", value: " mois" }
// ]
```

**代码逻辑推理 (假设输入与输出):**

假设我们有以下 JavaScript 代码：

```javascript
const rtf = new Intl.RelativeTimeFormat('zh-CN', { style: 'short' });
const formattedString = rtf.format(-1, 'week');
```

**假设输入:**

* `locales`:  `'zh-CN'`
* `options`: `{ style: 'short' }`
* `value`: `-1`
* `unit`: `'week'`

**代码逻辑推理:**

1. **`JSRelativeTimeFormat::New`:**
   - 接收 `locales` 和 `options`。
   - 使用 `Intl::CanonicalizeLocaleList` 将 `'zh-CN'` 规范化。
   - 使用 `Intl::ResolveLocale` 确定最佳匹配的语言环境（很可能就是 `zh-CN`）。
   - 从 `options` 中提取 `style` 并设置为 `Style::SHORT`。
   - 创建一个 ICU 的 `RelativeDateTimeFormatter` 实例，配置为中文环境和 `short` 样式。

2. **`rtf.format(-1, 'week')` 调用映射到 `JSRelativeTimeFormat::Format`:**
   - 接收 `value` `-1` 和 `unit` `'week'`。
   - `GetURelativeDateTimeUnit` 函数将字符串 `'week'` 转换为 ICU 的枚举值 `UDAT_REL_UNIT_WEEK`。
   - ICU 的 `RelativeDateTimeFormatter` 的 `formatNumericToValue` 或 `formatToValue` 方法会被调用，传入 `-1` 和 `UDAT_REL_UNIT_WEEK`。
   - ICU 会根据中文的 `short` 样式规则，将 `-1` 和 `'week'` 格式化为相应的字符串。

**假设输出:**

根据中文的习惯和 `short` 样式，预期的输出可能是：`"上周"`。

**涉及用户常见的编程错误:**

1. **拼写错误的单位:**

   ```javascript
   const rtf = new Intl.RelativeTimeFormat('en');
   console.log(rtf.format(-1, 'wek')); // 错误！'wek' 不是有效的单位
   ```

   **错误:**  `JSRelativeTimeFormat::Format` 中的 `GetURelativeDateTimeUnit` 函数会返回 `false`，导致抛出一个 `RangeError`，提示单位无效。

2. **传入非有限的数值:**

   ```javascript
   const rtf = new Intl.RelativeTimeFormat('en');
   console.log(rtf.format(Infinity, 'day')); // 错误！Infinity 不是有限数值
   ```

   **错误:** `JSRelativeTimeFormat::FormatCommon` 函数会检查 `isFinite(number)`，如果为 `false`，则抛出一个 `RangeError`。

3. **不支持的语言环境或选项:**

   ```javascript
   try {
     const rtf = new Intl.RelativeTimeFormat('xx-XX', { style: 'weird' });
   } catch (e) {
     console.error(e); // 可能抛出 RangeError 或其他错误
   }
   ```

   **错误:** `JSRelativeTimeFormat::New` 中，如果提供的语言环境无法被解析或没有匹配的 ICU 数据，或者 `options` 中包含无效的值，可能会抛出错误。对于无效的 `style`，`GetStringOption` 函数会返回错误。

4. **期望 `formatToParts` 返回特定类型的部件，但未正确处理:**

   ```javascript
   const rtf = new Intl.RelativeTimeFormat('en');
   const parts = rtf.formatToParts(-1, 'day');
   parts.forEach(part => {
     if (part.type === 'integer') { // 实际上没有 'integer' 类型，应该是 'number'
       console.log('Number part:', part.value);
     }
   });
   ```

   **错误:**  用户可能误解 `formatToParts` 返回的部件类型。正确的类型包括 `'literal'`, `'number'`, 和 `'unit'`。查看 `FormatToJSArray` 函数可以了解如何创建这些部件。

总而言之，`v8/src/objects/js-relative-time-format.cc` 是 V8 引擎中实现 `Intl.RelativeTimeFormat` 功能的关键 C++ 代码，它依赖于 ICU 库来提供国际化的相对时间格式化能力。理解这个文件有助于深入了解 JavaScript 国际化 API 的底层实现。

### 提示词
```
这是目录为v8/src/objects/js-relative-time-format.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-relative-time-format.cc以.tq结尾，那它是个v8 torque源代码，
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