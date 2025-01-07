Response:
Let's break down the thought process for analyzing the `js-list-format.cc` file.

1. **Understand the Goal:** The core request is to understand the functionality of this C++ file within the V8 JavaScript engine, particularly in relation to the JavaScript `Intl.ListFormat` API. Key areas to cover are its purpose, connection to JavaScript, code logic, and potential errors.

2. **Initial Scan and Keywords:**  Quickly scan the code for recognizable keywords and patterns.
    * `#include`:  Indicates dependencies. Notice the inclusion of `<unicode/...>`, hinting at internationalization support, and files like `js-list-format.h`, `js-array-inl.h`, `intl-objects.h`, suggesting this file deals with list formatting within V8's object system and internationalization features.
    * `namespace v8::internal`: Confirms this is internal V8 code, not public API.
    * `JSListFormat`: This is a central class. Pay close attention to its methods.
    * `New`, `ResolvedOptions`, `FormatList`, `FormatListToParts`: These look like the core functions. The names are highly suggestive of the `Intl.ListFormat` methods.
    * `GetIcuWidth`, `GetIcuType`:  These conversion functions likely bridge V8's internal representation with ICU's (International Components for Unicode) representation.
    * `UListFormatter...`:  Further confirmation of ICU integration.
    * `MaybeHandle`, `Handle`: V8's smart pointers for managing garbage-collected objects.
    * Error handling (`MAYBE_RETURN`, `THROW_NEW_ERROR`):  Important for understanding how failures are handled.

3. **Focus on `JSListFormat::New`:** This function is likely responsible for creating `Intl.ListFormat` objects. Go through it step-by-step:
    * `CanonicalizeLocaleList`: The first step in internationalization: ensuring locale strings are in a standard format.
    * `GetOptionsObject`:  Handles the options passed to the `Intl.ListFormat` constructor.
    * `GetLocaleMatcher`: Deals with locale negotiation strategies ("lookup" or "best fit").
    * `ResolveLocale`: The core of locale negotiation, finding the best matching locale.
    * `GetStringOption`:  Retrieves the "type" and "style" options.
    * `icu::ListFormatter::createInstance`:  The actual creation of the ICU list formatter object, using the negotiated locale, type, and style.
    * Object allocation and setting properties: `NewFastOrSlowJSObjectFromMap`, `set_locale`, `set_type`, `set_style`.

4. **Analyze Other Key Functions:**
    * `ResolvedOptions`:  Seems to return the resolved options of the `Intl.ListFormat` object, corresponding to the `resolvedOptions()` method in JavaScript.
    * `FormatList`:  Takes a list (presumably a JavaScript array) and formats it into a single string. It uses `icu::ListFormatter::formatStringsToValue`.
    * `FormatListToParts`:  Similar to `FormatList`, but returns an array of "parts" (literal text and list elements) instead of a single string. It uses `icu::FormattedValue` and iterates through the formatted output.

5. **Connect to JavaScript:** At this point, the connection to the JavaScript `Intl.ListFormat` API becomes clear. Each C++ function closely mirrors a JavaScript method.

6. **Infer Functionality:** Based on the code and the connection to the JavaScript API, we can describe the file's functionality: creating, configuring, and using ICU's list formatting capabilities within V8 to support `Intl.ListFormat`.

7. **Construct JavaScript Examples:**  Create simple JavaScript code snippets that demonstrate the usage of `Intl.ListFormat` and how the options map to the C++ code. This helps illustrate the relationship between the C++ implementation and the JavaScript API.

8. **Reason about Code Logic (with Assumptions):**
    * **Input:**  Focus on the inputs to `FormatList` and `FormatListToParts`: a `JSListFormat` object (already initialized with locale, type, and style) and a `FixedArray` (representing the JavaScript array).
    * **Process:** The core logic involves converting the JavaScript strings to ICU's `UnicodeString`, using the ICU formatter, and then converting the result back to V8 strings or an array of parts.
    * **Output:**  Either a formatted string or an array of objects representing the parts.

9. **Identify Potential Programming Errors:** Think about common mistakes developers might make when using `Intl.ListFormat`:
    * Incorrect locale tags.
    * Invalid or misspelled options.
    * Providing non-string elements in the list to be formatted.

10. **Consider `.tq` Extension:** The prompt mentions the `.tq` extension. Explain that Torque is V8's type system and that if the file had that extension, it would involve type definitions and more low-level implementation details.

11. **Structure the Output:** Organize the findings into clear sections as requested by the prompt: functionality, Torque information, JavaScript examples, code logic inference, and common errors.

12. **Refine and Review:**  Read through the analysis to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or missing information. For instance, initially, I might have focused too much on the ICU details. The refinement step would bring the focus back to how V8 uses ICU to implement the JavaScript API. Also, ensure the JavaScript examples directly relate to the C++ code being analyzed.

By following these steps, we can systematically analyze the C++ code and provide a comprehensive explanation of its functionality within the context of V8 and the JavaScript `Intl.ListFormat` API.
好的，让我们来分析一下 `v8/src/objects/js-list-format.cc` 这个 V8 源代码文件的功能。

**文件功能概述:**

`v8/src/objects/js-list-format.cc` 实现了 JavaScript `Intl.ListFormat` API 的核心功能。`Intl.ListFormat` 用于根据给定的语言环境和样式，将一个字符串数组格式化成一个人类可读的列表字符串。

更具体地说，这个文件负责：

1. **创建 `JSListFormat` 对象:**  它定义了 `JSListFormat` 类，该类是 V8 内部表示 `Intl.ListFormat` 对象的结构。`JSListFormat::New` 方法负责创建和初始化这些对象，包括处理传入的 `locales` 和 `options` 参数。
2. **处理选项:**  它解析并处理 `Intl.ListFormat` 构造函数中传入的选项，例如 `localeMatcher`、`type` (conjunction, disjunction, unit) 和 `style` (long, short, narrow)。
3. **国际化支持:**  它利用 ICU (International Components for Unicode) 库来执行实际的列表格式化操作。`icu::ListFormatter` 类是 ICU 提供的用于此目的的类。
4. **`resolvedOptions()` 方法的实现:** `JSListFormat::ResolvedOptions` 方法返回一个包含已解析的语言环境、类型和样式选项的对象，对应于 JavaScript 中 `Intl.ListFormat.prototype.resolvedOptions()` 的行为。
5. **`format()` 方法的实现:**  `JSListFormat::FormatList` 方法接收一个字符串数组，并使用 ICU 的 `ListFormatter` 将其格式化成一个单一的字符串。
6. **`formatToParts()` 方法的实现:** `JSListFormat::FormatListToParts` 方法接收一个字符串数组，并返回一个包含格式化结果各个部分的数组，每个部分包含 `type`（例如 "literal", "element"）和 `value`。

**关于 `.tq` 扩展名:**

如果 `v8/src/objects/js-list-format.cc` 的文件名以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码**文件。Torque 是 V8 用来定义对象布局、内置函数和运行时调用的类型化中间语言。在这个例子中，文件名为 `.cc`，所以它是标准的 C++ 源代码。

**与 JavaScript 功能的关系及示例:**

`v8/src/objects/js-list-format.cc` 文件直接实现了 `Intl.ListFormat` 的功能。以下 JavaScript 示例演示了 `Intl.ListFormat` 的使用，其背后就是这个 C++ 文件的代码在工作：

```javascript
// 创建一个 Intl.ListFormat 对象，指定语言环境和样式
const listFormatter = new Intl.ListFormat('en', { style: 'short', type: 'conjunction' });

// 格式化一个字符串数组
const myList = ['apples', 'bananas', 'oranges'];
const formattedList = listFormatter.format(myList);
console.log(formattedList); // 输出: "apples, bananas, and oranges"

// 使用不同的类型
const disjunctionFormatter = new Intl.ListFormat('en', { type: 'disjunction' });
const formattedDisjunction = disjunctionFormatter.format(myList);
console.log(formattedDisjunction); // 输出: "apples, bananas, or oranges"

// 使用 formatToParts 获取格式化结果的各个部分
const partsFormatter = new Intl.ListFormat('en', { style: 'narrow', type: 'unit' });
const parts = partsFormatter.formatToParts(myList);
console.log(parts);
/*
输出类似:
[
  { type: 'element', value: 'apples' },
  { type: 'literal', value: ' ' },
  { type: 'element', value: 'bananas' },
  { type: 'literal', value: ' ' },
  { type: 'element', value: 'oranges' }
]
*/

// 获取已解析的选项
const resolvedOptions = listFormatter.resolvedOptions();
console.log(resolvedOptions); // 输出类似: { locale: "en", type: "conjunction", style: "short" }
```

在这个例子中，JavaScript 代码创建了 `Intl.ListFormat` 的实例，并调用了 `format()` 和 `formatToParts()` 方法。V8 引擎在执行这些 JavaScript 代码时，会调用 `v8/src/objects/js-list-format.cc` 中相应的 C++ 函数来完成实际的格式化工作。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下 JavaScript 代码：

```javascript
const formatter = new Intl.ListFormat('zh-CN', { type: 'conjunction' });
const items = ['北京', '上海', '广州'];
const result = formatter.format(items);
```

**假设输入:**

* `locales`:  `"zh-CN"`
* `options`: `{ type: 'conjunction' }`
* 传递给 `format()` 方法的数组: `['北京', '上海', '广州']`

**代码逻辑推理:**

1. **`JSListFormat::New` 被调用:** 当创建 `Intl.ListFormat` 对象时，`JSListFormat::New` 方法会被调用。
2. **选项解析:**  `New` 方法会解析 `locales` 和 `options`，确定语言环境为 "zh-CN"，类型为 "conjunction"。
3. **ICU 初始化:**  `New` 方法会创建一个 ICU 的 `ListFormatter` 实例，使用 "zh-CN" 语言环境和 conjunction 类型对应的 ICU 设置。
4. **`JSListFormat` 对象创建:**  创建一个 `JSListFormat` 对象，存储解析后的语言环境、类型等信息，以及 ICU `ListFormatter` 的指针。
5. **`JSListFormat::FormatList` 被调用:**  当调用 `formatter.format(items)` 时，`JSListFormat::FormatList` 方法会被调用。
6. **字符串转换:**  `FormatList` 方法会将 JavaScript 字符串 "北京"、"上海"、"广州" 转换为 ICU 的 `UnicodeString` 类型。
7. **ICU 格式化:**  调用 ICU `ListFormatter` 的格式化方法，传入这些 `UnicodeString`。ICU 会根据 "zh-CN" 和 "conjunction" 的规则生成格式化后的字符串。
8. **结果返回:**  ICU 返回的格式化后的字符串（例如："北京、上海和广州"）会被转换回 V8 的 `String` 对象，并作为 `formatter.format(items)` 的结果返回。

**预期输出:**

```
"北京、上海和广州"
```

**用户常见的编程错误举例:**

1. **使用了无效的 locale 代码:**

   ```javascript
   try {
     const formatter = new Intl.ListFormat('invalid-locale');
   } catch (error) {
     console.error(error); // 可能抛出 RangeError 或其他错误
   }
   ```
   **解释:**  如果提供了 V8 或 ICU 不支持的 locale 代码，`Intl.ListFormat` 的构造函数可能会抛出错误。

2. **使用了错误的选项名称或值:**

   ```javascript
   try {
     const formatter = new Intl.ListFormat('en', { style: 'extraLong' }); // 'extraLong' 不是有效的 style 值
   } catch (error) {
     console.error(error); // 可能抛出 RangeError
   }
   ```
   **解释:**  `style` 选项只接受 "long"、"short" 和 "narrow" 这几个值。提供了其他值会导致错误。

3. **传递给 `format()` 的不是字符串数组:**

   ```javascript
   const formatter = new Intl.ListFormat('en');
   const notAnArray = { 0: 'apple', 1: 'banana', length: 2 };
   try {
     formatter.format(notAnArray);
   } catch (error) {
     console.error(error); // 可能抛出 TypeError
   }
   ```
   **解释:** `format()` 方法期望接收一个可迭代的字符串数组。传递其他类型的对象可能会导致错误。

4. **忘记处理可能的异常:**

   虽然 `Intl.ListFormat` 的使用通常很安全，但在某些极端情况下（例如，系统资源不足），底层的 ICU 库可能会抛出异常。最佳实践是在使用 `Intl.ListFormat` 时考虑潜在的错误情况。

总而言之，`v8/src/objects/js-list-format.cc` 是 V8 引擎中实现 `Intl.ListFormat` 核心功能的重要组成部分，它连接了 JavaScript API 和底层的 ICU 国际化库，使得开发者能够在 JavaScript 中方便地进行列表的本地化格式化。

Prompt: 
```
这是目录为v8/src/objects/js-list-format.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-list-format.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

#include "src/objects/js-list-format.h"

#include <memory>
#include <vector>

#include "src/execution/isolate.h"
#include "src/heap/factory.h"
#include "src/objects/elements-inl.h"
#include "src/objects/elements.h"
#include "src/objects/intl-objects.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-list-format-inl.h"
#include "src/objects/managed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/option-utils.h"
#include "unicode/fieldpos.h"
#include "unicode/fpositer.h"
#include "unicode/listformatter.h"
#include "unicode/ulistformatter.h"

namespace v8 {
namespace internal {

namespace {

UListFormatterWidth GetIcuWidth(JSListFormat::Style style) {
  switch (style) {
    case JSListFormat::Style::LONG:
      return ULISTFMT_WIDTH_WIDE;
    case JSListFormat::Style::SHORT:
      return ULISTFMT_WIDTH_SHORT;
    case JSListFormat::Style::NARROW:
      return ULISTFMT_WIDTH_NARROW;
  }
  UNREACHABLE();
}

UListFormatterType GetIcuType(JSListFormat::Type type) {
  switch (type) {
    case JSListFormat::Type::CONJUNCTION:
      return ULISTFMT_TYPE_AND;
    case JSListFormat::Type::DISJUNCTION:
      return ULISTFMT_TYPE_OR;
    case JSListFormat::Type::UNIT:
      return ULISTFMT_TYPE_UNITS;
  }
  UNREACHABLE();
}

}  // namespace

MaybeHandle<JSListFormat> JSListFormat::New(Isolate* isolate,
                                            DirectHandle<Map> map,
                                            Handle<Object> locales,
                                            Handle<Object> input_options) {
  // 3. Let requestedLocales be ? CanonicalizeLocaleList(locales).
  Maybe<std::vector<std::string>> maybe_requested_locales =
      Intl::CanonicalizeLocaleList(isolate, locales);
  MAYBE_RETURN(maybe_requested_locales, Handle<JSListFormat>());
  std::vector<std::string> requested_locales =
      maybe_requested_locales.FromJust();

  Handle<JSReceiver> options;
  const char* service = "Intl.ListFormat";
  // 4. Let options be GetOptionsObject(_options_).
  ASSIGN_RETURN_ON_EXCEPTION(isolate, options,
                             GetOptionsObject(isolate, input_options, service));

  // Note: No need to create a record. It's not observable.
  // 6. Let opt be a new Record.

  // 7. Let matcher be ? GetOption(options, "localeMatcher", "string", «
  // "lookup", "best fit" », "best fit").
  Maybe<Intl::MatcherOption> maybe_locale_matcher =
      Intl::GetLocaleMatcher(isolate, options, service);
  MAYBE_RETURN(maybe_locale_matcher, MaybeHandle<JSListFormat>());

  // 8. Set opt.[[localeMatcher]] to matcher.
  Intl::MatcherOption matcher = maybe_locale_matcher.FromJust();

  // 10. Let r be ResolveLocale(%ListFormat%.[[AvailableLocales]],
  // requestedLocales, opt, undefined, localeData).
  Maybe<Intl::ResolvedLocale> maybe_resolve_locale =
      Intl::ResolveLocale(isolate, JSListFormat::GetAvailableLocales(),
                          requested_locales, matcher, {});
  if (maybe_resolve_locale.IsNothing()) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  Intl::ResolvedLocale r = maybe_resolve_locale.FromJust();
  DirectHandle<String> locale_str =
      isolate->factory()->NewStringFromAsciiChecked(r.locale.c_str());

  // 12. Let t be GetOption(options, "type", "string", «"conjunction",
  //    "disjunction", "unit"», "conjunction").
  Maybe<Type> maybe_type = GetStringOption<Type>(
      isolate, options, "type", service, {"conjunction", "disjunction", "unit"},
      {Type::CONJUNCTION, Type::DISJUNCTION, Type::UNIT}, Type::CONJUNCTION);
  MAYBE_RETURN(maybe_type, MaybeHandle<JSListFormat>());
  Type type_enum = maybe_type.FromJust();

  // 14. Let s be ? GetOption(options, "style", "string",
  //                          «"long", "short", "narrow"», "long").
  Maybe<Style> maybe_style = GetStringOption<Style>(
      isolate, options, "style", service, {"long", "short", "narrow"},
      {Style::LONG, Style::SHORT, Style::NARROW}, Style::LONG);
  MAYBE_RETURN(maybe_style, MaybeHandle<JSListFormat>());
  Style style_enum = maybe_style.FromJust();

  icu::Locale icu_locale = r.icu_locale;
  UErrorCode status = U_ZERO_ERROR;
  std::shared_ptr<icu::ListFormatter> formatter{
      icu::ListFormatter::createInstance(icu_locale, GetIcuType(type_enum),
                                         GetIcuWidth(style_enum), status)};
  if (U_FAILURE(status) || formatter == nullptr) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }

  DirectHandle<Managed<icu::ListFormatter>> managed_formatter =
      Managed<icu::ListFormatter>::From(isolate, 0, std::move(formatter));

  // Now all properties are ready, so we can allocate the result object.
  Handle<JSListFormat> list_format =
      Cast<JSListFormat>(isolate->factory()->NewFastOrSlowJSObjectFromMap(map));
  DisallowGarbageCollection no_gc;
  list_format->set_flags(0);
  list_format->set_icu_formatter(*managed_formatter);

  // 11. Set listFormat.[[Locale]] to r.[[Locale]].
  list_format->set_locale(*locale_str);

  // 13. Set listFormat.[[Type]] to t.
  list_format->set_type(type_enum);

  // 15. Set listFormat.[[Style]] to s.
  list_format->set_style(style_enum);

  return list_format;
}

// ecma402 #sec-intl.pluralrules.prototype.resolvedoptions
Handle<JSObject> JSListFormat::ResolvedOptions(
    Isolate* isolate, DirectHandle<JSListFormat> format) {
  Factory* factory = isolate->factory();
  // 4. Let options be ! ObjectCreate(%ObjectPrototype%).
  Handle<JSObject> result = factory->NewJSObject(isolate->object_function());

  // 5.  For each row of Table 1, except the header row, do
  //  Table 1: Resolved Options of ListFormat Instances
  //  Internal Slot    Property
  //  [[Locale]]       "locale"
  //  [[Type]]         "type"
  //  [[Style]]        "style"
  DirectHandle<String> locale(format->locale(), isolate);
  JSObject::AddProperty(isolate, result, factory->locale_string(), locale,
                        NONE);
  JSObject::AddProperty(isolate, result, factory->type_string(),
                        format->TypeAsString(), NONE);
  JSObject::AddProperty(isolate, result, factory->style_string(),
                        format->StyleAsString(), NONE);
  // 6. Return options.
  return result;
}

Handle<String> JSListFormat::StyleAsString() const {
  switch (style()) {
    case Style::LONG:
      return GetReadOnlyRoots().long_string_handle();
    case Style::SHORT:
      return GetReadOnlyRoots().short_string_handle();
    case Style::NARROW:
      return GetReadOnlyRoots().narrow_string_handle();
  }
  UNREACHABLE();
}

Handle<String> JSListFormat::TypeAsString() const {
  switch (type()) {
    case Type::CONJUNCTION:
      return GetReadOnlyRoots().conjunction_string_handle();
    case Type::DISJUNCTION:
      return GetReadOnlyRoots().disjunction_string_handle();
    case Type::UNIT:
      return GetReadOnlyRoots().unit_string_handle();
  }
  UNREACHABLE();
}

namespace {

// Extract String from FixedArray into array of UnicodeString
Maybe<std::vector<icu::UnicodeString>> ToUnicodeStringArray(
    Isolate* isolate, DirectHandle<FixedArray> array) {
  int length = array->length();
  std::vector<icu::UnicodeString> result;
  for (int i = 0; i < length; i++) {
    Handle<Object> item(array->get(i), isolate);
    DCHECK(IsString(*item));
    Handle<String> item_str = Cast<String>(item);
    if (!item_str->IsFlat()) item_str = String::Flatten(isolate, item_str);
    result.push_back(Intl::ToICUUnicodeString(isolate, item_str));
  }
  return Just(result);
}

template <typename T>
MaybeHandle<T> FormatListCommon(
    Isolate* isolate, DirectHandle<JSListFormat> format,
    DirectHandle<FixedArray> list,
    const std::function<MaybeHandle<T>(Isolate*, const icu::FormattedValue&)>&
        formatToResult) {
  DCHECK(!IsUndefined(*list));
  Maybe<std::vector<icu::UnicodeString>> maybe_array =
      ToUnicodeStringArray(isolate, list);
  MAYBE_RETURN(maybe_array, Handle<T>());
  std::vector<icu::UnicodeString> array = maybe_array.FromJust();

  icu::ListFormatter* formatter = format->icu_formatter()->raw();
  DCHECK_NOT_NULL(formatter);

  UErrorCode status = U_ZERO_ERROR;
  icu::FormattedList formatted = formatter->formatStringsToValue(
      array.data(), static_cast<int32_t>(array.size()), status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  return formatToResult(isolate, formatted);
}

Handle<String> IcuFieldIdToType(Isolate* isolate, int32_t field_id) {
  switch (field_id) {
    case ULISTFMT_LITERAL_FIELD:
      return isolate->factory()->literal_string();
    case ULISTFMT_ELEMENT_FIELD:
      return isolate->factory()->element_string();
    default:
      UNREACHABLE();
  }
}

// A helper function to convert the FormattedList to a
// MaybeHandle<JSArray> for the implementation of formatToParts.
MaybeHandle<JSArray> FormattedListToJSArray(
    Isolate* isolate, const icu::FormattedValue& formatted) {
  Handle<JSArray> array = isolate->factory()->NewJSArray(0);
  icu::ConstrainedFieldPosition cfpos;
  cfpos.constrainCategory(UFIELD_CATEGORY_LIST);
  int index = 0;
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString string = formatted.toString(status);
  Handle<String> substring;
  while (formatted.nextPosition(cfpos, status) && U_SUCCESS(status)) {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, substring,
        Intl::ToString(isolate, string, cfpos.getStart(), cfpos.getLimit()));
    Intl::AddElement(isolate, array, index++,
                     IcuFieldIdToType(isolate, cfpos.getField()), substring);
  }
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  JSObject::ValidateElements(*array);
  return array;
}

}  // namespace

// ecma402 #sec-formatlist
MaybeHandle<String> JSListFormat::FormatList(Isolate* isolate,
                                             DirectHandle<JSListFormat> format,
                                             DirectHandle<FixedArray> list) {
  return FormatListCommon<String>(isolate, format, list,
                                  Intl::FormattedToString);
}

// ecma42 #sec-formatlisttoparts
MaybeHandle<JSArray> JSListFormat::FormatListToParts(
    Isolate* isolate, DirectHandle<JSListFormat> format,
    DirectHandle<FixedArray> list) {
  return FormatListCommon<JSArray>(isolate, format, list,
                                   FormattedListToJSArray);
}

namespace {

struct CheckListPattern {
  static const char* key() { return "listPattern"; }
  static const char* path() { return nullptr; }
};

}  // namespace

const std::set<std::string>& JSListFormat::GetAvailableLocales() {
  static base::LazyInstance<Intl::AvailableLocales<CheckListPattern>>::type
      available_locales = LAZY_INSTANCE_INITIALIZER;
  return available_locales.Pointer()->Get();
}

}  // namespace internal
}  // namespace v8

"""

```