Response:
Let's break down the thought process for analyzing this V8 source code.

1. **Understand the Goal:** The request asks for a breakdown of the functionality of `v8/src/objects/js-display-names.cc`. It also includes specific follow-up questions related to Torque, JavaScript interaction, logic, and potential errors.

2. **Initial Scan and Keywords:**  Quickly read through the code, looking for key terms and patterns. I noticed:
    * `// Copyright 2019 the V8 project authors.` - Standard V8 header.
    * `#ifndef V8_INTL_SUPPORT`, `#error Internationalization is expected to be enabled.` -  Immediately tells me this file is about internationalization.
    * `#include "src/objects/js-display-names.h"` -  The header file for this source file, confirming the focus.
    * `#include "unicode/..."` -  Lots of includes from the ICU (International Components for Unicode) library, heavily reinforcing the internationalization aspect.
    * `namespace v8 { namespace internal {` - Standard V8 internal namespace.
    * `class DisplayNamesInternal` -  An abstract base class, indicating a hierarchy.
    * `class LocaleDisplayNamesCommon`, `class LanguageNames`, `class RegionNames`, etc. - Concrete implementations inheriting from the base, suggesting different types of display names.
    * `JSDisplayNames::New`, `JSDisplayNames::ResolvedOptions`, `JSDisplayNames::Of` -  Methods on the `JSDisplayNames` class, which are likely called from JavaScript.
    * `Intl::...` -  Calls to other V8 internationalization utilities.
    * `THROW_NEW_ERROR_RETURN_VALUE`, `THROW_NEW_ERROR`, `THROW_NEW_TYPE_ERROR` - Error handling, often related to invalid input.

3. **Core Functionality Identification:** Based on the keywords and class names, the core functionality seems to be:
    * **Providing localized display names:** This is the primary purpose of `Intl.DisplayNames` in JavaScript.
    * **Handling different types:**  Languages, regions, scripts, currencies, calendars, and date/time fields are explicitly mentioned.
    * **Supporting different styles:** "long", "short", and "narrow" are used to control the verbosity of the names.
    * **Locale handling:** The code interacts with locales to retrieve the correct localized names.
    * **Option processing:**  The `New` method takes options like `localeMatcher`, `style`, `type`, `fallback`, and `languageDisplay`.

4. **Structure and Class Hierarchy:**  The class hierarchy is important to understand the organization:
    * `DisplayNamesInternal` (abstract): Defines the interface for fetching display names.
    * `LocaleDisplayNamesCommon`: Provides common functionality for locale-based display names, using ICU's `LocaleDisplayNames`.
    * Concrete subclasses (e.g., `LanguageNames`, `RegionNames`): Implement the `of` method specific to the type.
    * `JSDisplayNames`: The JavaScript-visible class that manages the internal implementation.

5. **Workflow of `JSDisplayNames::New`:**  This is the constructor, so it's crucial. I traced the steps:
    * Canonicalize the requested locales.
    * Get and process options.
    * Resolve the locale using `Intl::ResolveLocale`.
    * Determine the style and type.
    * Create the appropriate `DisplayNamesInternal` subclass based on the `type`.
    * Store the internal object in the `JSDisplayNames` instance.

6. **Workflow of `JSDisplayNames::Of`:** This is the method called to get a display name. It:
    * Takes a code as input.
    * Delegates the actual lookup to the `of` method of the internal object.
    * Handles potential errors and returns the result as a JavaScript string.

7. **JavaScript Relationship:** The `JSDisplayNames::New`, `ResolvedOptions`, and `Of` methods strongly suggest a direct mapping to the JavaScript `Intl.DisplayNames` API. I considered how a JavaScript call like `new Intl.DisplayNames('en', { type: 'language' }).of('fr')` would translate to the C++ code.

8. **Torque Consideration:** The prompt asks about `.tq`. I noted that this file is `.cc`, so it's *not* a Torque file. However, I explained what Torque is and how it's used in V8 for optimization.

9. **Logic and Examples:**  I started thinking about how the `of` methods work for different types. For example, `LanguageNames::of` canonicalizes the language tag before looking it up. I formulated example inputs and expected outputs based on my understanding of the ICU library and language/region/script codes.

10. **Common Programming Errors:** I considered common mistakes developers might make when using `Intl.DisplayNames`, such as:
    * Providing invalid language/region/script codes.
    * Incorrect option usage.
    * Not handling potential `undefined` results.

11. **Refinement and Structure:** I organized my findings into clear sections, following the structure requested in the prompt. I used headings and bullet points for better readability. I also made sure to explicitly answer each part of the initial request.

12. **Review and Accuracy:** Finally, I reread the code and my analysis to ensure accuracy and completeness. I double-checked the mappings between the C++ code and the JavaScript API. I verified that the examples made sense in the context of internationalization.

This iterative process of scanning, identifying key elements, understanding the flow, connecting to JavaScript, and providing concrete examples allowed me to generate a comprehensive and accurate explanation of the `js-display-names.cc` source code.
## 功能列举：

`v8/src/objects/js-display-names.cc` 文件的主要功能是 **实现了 JavaScript 的 `Intl.DisplayNames` API**。  更具体地说，它负责：

1. **提供本地化的名称显示:**  根据指定的 `locale` 和 `type`，返回语言、区域、脚本、货币、日历和日期/时间字段的本地化显示名称。
2. **处理 `Intl.DisplayNames` 构造函数的选项:**  例如 `localeMatcher`，`style`，`type`，`fallback` 和 `languageDisplay`。
3. **与 ICU 库交互:**  该文件大量使用了 ICU (International Components for Unicode) 库来获取本地化的数据和执行名称查找。
4. **实现 `resolvedOptions()` 方法:**  返回 `Intl.DisplayNames` 实例的已解析选项。
5. **实现 `of()` 方法:**  根据提供的代码（例如语言代码 "en"，区域代码 "US"），返回对应的本地化显示名称。

**详细功能点:**

* **类型支持:** 支持获取以下类型的显示名称：
    * `language` (语言)
    * `region` (区域)
    * `script` (脚本)
    * `currency` (货币)
    * `calendar` (日历)
    * `dateTimeField` (日期/时间字段，例如 "month", "day")
* **样式支持:** 支持不同的显示样式：
    * `long` (完整名称，例如 "English")
    * `short` (缩写名称，例如 "en")
    * `narrow` (更简洁的缩写名称，在某些语言中可能与 `short` 相同)
* **回退机制:**  处理在给定 `locale` 下找不到对应名称的情况，可以选择回退到其他语言的名称或者返回提供的代码本身。
* **语言显示选项:**  对于语言名称，可以控制显示方言名称还是标准名称。
* **错误处理:**  当提供无效的参数（例如无效的语言代码）时，抛出 `RangeError` 或 `TypeError`。

**如果 `v8/src/objects/js-display-names.cc` 以 `.tq` 结尾：**

如果文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是一种 V8 特有的领域特定语言，用于编写 V8 内部函数的类型安全的 C++ 代码，并能更好地进行性能优化。  这意味着该文件的功能逻辑将以 Torque 语法实现，而不是标准的 C++。

**与 JavaScript 功能的关系 (及示例):**

`v8/src/objects/js-display-names.cc` 文件是 JavaScript `Intl.DisplayNames` API 的底层实现。  JavaScript 代码通过 V8 引擎调用该文件中的 C++ 代码来完成本地化名称的获取。

**JavaScript 示例:**

```javascript
// 创建一个 Intl.DisplayNames 实例，用于显示英文语言的名称
const enNames = new Intl.DisplayNames('en', { type: 'language' });

// 获取法语的英文显示名称
console.log(enNames.of('fr')); // 输出: French

// 创建一个用于显示中文区域名称的实例，使用繁体中文
const zhTWNames = new Intl.DisplayNames('zh-TW', { type: 'region' });

// 获取美国的繁体中文显示名称
console.log(zhTWNames.of('US')); // 输出: 美國

// 创建一个用于显示日历名称的实例
const calendarNames = new Intl.DisplayNames('en', { type: 'calendar' });

// 获取公历的英文显示名称
console.log(calendarNames.of('gregory')); // 输出: Gregorian

// 创建一个用于显示货币名称的实例，使用短样式
const currencyNamesShort = new Intl.DisplayNames('en', { type: 'currency', style: 'short' });

// 获取美元的英文短显示名称
console.log(currencyNamesShort.of('USD')); // 输出: US$

// 创建一个用于显示日期/时间字段名称的实例
const dateTimeFieldNames = new Intl.DisplayNames('en', { type: 'dateTimeField' });

// 获取月份的英文显示名称
console.log(dateTimeFieldNames.of('month')); // 输出: month
```

在这个例子中，`new Intl.DisplayNames(...)` 会在 V8 内部调用 `JSDisplayNames::New` 函数，而 `enNames.of('fr')` 则会调用 `JSDisplayNames::Of` 函数，最终由 `v8/src/objects/js-display-names.cc` 中的 C++ 代码使用 ICU 库来查找并返回本地化的名称。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下 JavaScript 代码：

```javascript
const names = new Intl.DisplayNames('de-DE', { type: 'region', style: 'short' });
const result = names.of('FR');
```

**假设输入:**

* `locale`: "de-DE" (德国德语)
* `type`: "region"
* `style`: "short"
* `code`: "FR" (法国的 ISO 3166-1 alpha-2 代码)

**代码逻辑推理过程:**

1. `Intl.DisplayNames` 构造函数被调用，V8 会调用 `JSDisplayNames::New` 函数。
2. `JSDisplayNames::New` 会解析选项，并创建一个 `RegionNames` 类的实例，因为 `type` 是 "region"。
3. `names.of('FR')` 被调用，V8 会调用 `JSDisplayNames::Of` 函数。
4. `JSDisplayNames::Of` 函数会调用 `RegionNames` 实例的 `of` 方法。
5. `RegionNames::of` 方法会使用 ICU 库的 `regionDisplayName` 函数，以 "de-DE" locale 和 "FR" 代码查找对应的短名称。
6. ICU 库会返回法国的德语短名称。

**预期输出:**

* `result` 的值将会是 "FR" (德语中法国的短名称通常与国家代码相同)。

**另一个例子：**

```javascript
const names = new Intl.DisplayNames('ja', { type: 'language', style: 'long' });
const result = names.of('en');
```

**假设输入:**

* `locale`: "ja" (日语)
* `type`: "language"
* `style`: "long"
* `code`: "en" (英语的语言代码)

**代码逻辑推理过程:**

1. `Intl.DisplayNames` 构造函数被调用，V8 会调用 `JSDisplayNames::New` 函数。
2. `JSDisplayNames::New` 会解析选项，并创建一个 `LanguageNames` 类的实例，因为 `type` 是 "language"。
3. `names.of('en')` 被调用，V8 会调用 `JSDisplayNames::Of` 函数。
4. `JSDisplayNames::Of` 函数会调用 `LanguageNames` 实例的 `of` 方法。
5. `LanguageNames::of` 方法会使用 ICU 库的 `localeDisplayName` 函数，以 "ja" locale 和 "en" 代码查找对应的长名称。
6. ICU 库会返回英语的日语长名称。

**预期输出:**

* `result` 的值将会是 "英語" (日语中英语的长名称)。

**涉及用户常见的编程错误 (及示例):**

1. **提供无效的 `type` 值:**

   ```javascript
   try {
     const names = new Intl.DisplayNames('en', { type: 'invalidType' });
   } catch (e) {
     console.error(e); // 输出 TypeError
   }
   ```

2. **提供无效的语言、区域或脚本代码:**

   ```javascript
   const names = new Intl.DisplayNames('en', { type: 'language' });
   try {
     console.log(names.of('xyz')); // 输出 RangeError
   } catch (e) {
     console.error(e);
   }
   ```

3. **期望所有 `style` 都存在对应的名称:**  并非所有语言和类型都支持所有样式 (`long`, `short`, `narrow`)。 如果请求的样式不可用，ICU 可能会返回一个回退值或空值。

   ```javascript
   const names = new Intl.DisplayNames('en', { type: 'currency', style: 'narrow' });
   console.log(names.of('USD')); // 输出可能与 short 样式相同，或者是一个更窄的表示 (如果存在)
   ```

4. **忘记处理 `of()` 方法可能返回 `undefined` 的情况:**  当 `fallback` 设置为 `'none'` 并且找不到对应的名称时，`of()` 方法会返回 `undefined`。

   ```javascript
   const names = new Intl.DisplayNames('en', { type: 'language', fallback: 'none' });
   const name = names.of('xx'); // 'xx' 是一个无效的语言代码
   console.log(name); // 输出 undefined

   if (name) {
     console.log(`The name is: ${name}`);
   } else {
     console.log('Name not found.');
   }
   ```

理解 `v8/src/objects/js-display-names.cc` 的功能对于理解 JavaScript 国际化 API 的底层实现至关重要。 它展示了 V8 如何利用 ICU 库来提供强大的本地化能力。

Prompt: 
```
这是目录为v8/src/objects/js-display-names.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-display-names.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
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

"""

```