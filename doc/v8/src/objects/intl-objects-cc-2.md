Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of V8's `intl-objects.cc` file.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the Core Purpose:** The code deals with internationalization (intl) functionalities in V8. Keywords like `Locale`, `NumberFormat`, `Collator`, `Calendar`, `Currency`, etc., strongly suggest this.

2. **Categorize Functionality:**  The code can be broadly categorized into:
    * **Locale Handling:**  Finding the best available locale, parsing locales, canonicalizing them, and matching requested locales against available ones.
    * **Number Formatting Options:** Processing and validating options related to significant digits, fraction digits, and rounding.
    * **Supported Values:**  Retrieving lists of available calendars, collations, currencies, numbering systems, and time zones.
    * **Validation:** Checking if certain values (like currency codes, calendar names, etc.) are well-formed or valid.

3. **Analyze Code Sections:** Go through each significant block of code and understand its role.
    * The initial section deals with `NumberFormatDigitOptions`. It's clearly about setting and validating options for number formatting based on input parameters.
    * The `BestAvailableLocale`, `ParseBCP47Locale`, `LookupSupportedLocales`, and `BestFitMatcher` functions are all related to locale negotiation and matching.
    * `CreateArrayFromList` is a utility for converting C++ vectors to JavaScript arrays.
    * `SupportedLocales` combines locale matching algorithms with options processing.
    * `GetCanonicalLocales` handles the process of getting canonical locale names.
    * The functions for `AvailableCollations`, `AvailableCurrencies`, etc., focus on fetching lists of supported intl values.
    * `SupportedValuesOf` acts as a dispatcher to get the available values based on a given key.
    * `SupportedLocalesOf` is a higher-level function combining locale canonicalization and the `SupportedLocales` logic.
    * The `IsValid...` functions are validation checks for different intl components.
    * `LookupAndValidateUnicodeExtensions` extracts and validates Unicode locale extensions.
    * `LookupMatcher` implements a specific locale matching algorithm.

4. **Address Specific Instructions:**
    * **`.tq` extension:**  The code snippet is in C++, not Torque, so this is false.
    * **JavaScript Relationship:**  Many functions directly correspond to JavaScript Intl API methods. Provide examples.
    * **Code Logic Reasoning:** Focus on the `NumberFormatDigitOptions` section. Create a hypothetical input and trace the logic to predict the output.
    * **Common Programming Errors:** Think about how users might misuse the Intl API or provide incorrect input, which the code handles (e.g., range errors for out-of-bounds values, type errors for incorrect types).
    * **Overall Functionality (Part 3):**  Summarize the main purpose of the code within the context of the larger `intl-objects.cc` file (which was hinted at in part 1 and 2).

5. **Structure the Output:** Organize the findings logically, following the user's request format:
    * Overall Functionality
    * `.tq` Extension
    * JavaScript Relationship and Examples
    * Code Logic Reasoning (with assumptions, input, and output)
    * Common Programming Errors (with examples)
    * Summary of Functionality (Part 3)

6. **Refine and Elaborate:** Add details and explanations to make the summary clear and informative. For example, explain what canonicalization means, what the different locale matching algorithms do, and why certain error conditions are checked. Ensure the JavaScript examples are practical and demonstrate the connection to the C++ code. Clarify the assumptions made in the code logic reasoning.

7. **Review and Verify:** Double-check the summary for accuracy and completeness. Ensure all parts of the user's prompt have been addressed.

By following these steps, the comprehensive summary of the `intl-objects.cc` code snippet can be generated. The key is to break down the code into manageable parts, understand the purpose of each part, and then connect those parts to the broader context of internationalization in JavaScript and V8.
好的，让我们来分析一下这段V8源代码的功能。

**功能归纳**

这段代码是 V8 引擎中 `v8/src/objects/intl-objects.cc` 文件的一部分，主要负责处理 ECMAScript 国际化 API (ECMA-402) 中与数字格式化相关的操作。具体来说，这段代码实现了以下功能：

1. **处理数字格式化选项：**  它负责解析和验证用户提供的数字格式化选项，例如 `minimumIntegerDigits`、`maximumFractionDigits`、`minimumSignificantDigits`、`maximumSignificantDigits`、`roundingPriority` 和 `roundingIncrement`。
2. **确定最终的数字格式化属性：**  根据用户提供的选项和默认值，以及一些逻辑规则，计算出最终的数字格式化属性，例如最小和最大整数/小数位数，最小和最大有效位数，以及舍入类型。
3. **实现 Locale 协商和匹配：** 实现了 `BestAvailableLocale`、`ParseBCP47Locale`、`LookupSupportedLocales` 和 `BestFitMatcher` 等算法，用于在用户请求的 locale 列表和 V8 支持的 locale 列表中找到最佳匹配的 locale。
4. **提供支持的国际化值：**  实现了 `AvailableCollations`、`AvailableCurrencies`、`AvailableNumberingSystems`、`AvailableTimeZones` 和 `AvailableUnits` 等函数，用于获取 V8 支持的各种国际化相关的值，例如可用的排序规则、货币、数字系统、时区和单位。
5. **实现 `supportedLocalesOf`：** 实现了 `SupportedLocales` 和 `SupportedLocalesOf` 函数，用于确定在给定的 locale 列表中，V8 实际支持哪些 locale。
6. **验证国际化值：**  提供了一系列 `IsValid...` 函数，用于验证各种国际化值的有效性，例如 `IsValidCollation`、`IsWellFormedCurrency`、`IsValidCalendar` 和 `IsValidNumberingSystem`。
7. **处理 Unicode 扩展：** 实现了 `LookupAndValidateUnicodeExtensions` 函数，用于解析和验证 locale 字符串中的 Unicode 扩展。
8. **实现 `getCanonicalLocales`：**  实现了 `GetCanonicalLocales` 函数，用于将用户提供的 locale 列表转换为规范化的 locale 列表。

**关于源代码类型**

`v8/src/objects/intl-objects.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码**文件，而不是 Torque 源代码。Torque 源代码的文件名通常以 `.tq` 结尾。

**与 JavaScript 的关系及示例**

这段代码直接关联到 JavaScript 的 `Intl` 对象及其子对象的各种功能，例如 `Intl.NumberFormat`、`Intl.getCanonicalLocales` 和 `Intl.supportedValuesOf`。

**JavaScript 示例：数字格式化选项**

```javascript
const number = 1234.567;

// 使用不同的选项创建 NumberFormat 对象
const formatter1 = new Intl.NumberFormat('en-US', {
  minimumFractionDigits: 2,
  maximumFractionDigits: 4
});
console.log(formatter1.format(number)); // 输出 "1,234.57"

const formatter2 = new Intl.NumberFormat('en-US', {
  minimumSignificantDigits: 3,
  maximumSignificantDigits: 5
});
console.log(formatter2.format(number)); // 输出 "1,235"

const formatter3 = new Intl.NumberFormat('en-US', {
  roundingPriority: "lessPrecision",
  maximumFractionDigits: 0
});
console.log(formatter3.format(number)); // 输出 "1,235" (具体输出可能因实现而异)
```

这段 C++ 代码中的逻辑，尤其是关于 `NumberFormatDigitOptions` 的处理，正是 V8 引擎在背后实现这些 JavaScript `Intl.NumberFormat` 选项解析和值计算的关键部分。

**JavaScript 示例：`getCanonicalLocales`**

```javascript
console.log(Intl.getCanonicalLocales("en_US"));     // 输出 ["en-US"]
console.log(Intl.getCanonicalLocales(["zh-CN-Hans-CN"])); // 输出 ["zh-Hans-CN"]
```

这段 C++ 代码中的 `Intl::GetCanonicalLocales` 函数，以及其调用的 `CanonicalizeLocaleList` 函数，负责将这些非标准的 locale 标识符转换为标准的 BCP 47 格式。

**JavaScript 示例：`supportedValuesOf`**

```javascript
console.log(Intl.supportedValuesOf('currency'));
// 可能输出类似 ["AED", "AFN", "ALL", ...] 的数组

console.log(Intl.supportedValuesOf('calendar'));
// 可能输出类似 ["buddhist", "gregory", ...] 的数组
```

这段 C++ 代码中的 `Intl::SupportedValuesOf` 函数，根据传入的 `key` (例如 'currency' 或 'calendar')，调用相应的 C++ 函数（例如 `AvailableCurrencies` 或 `Intl::AvailableCalendars`）来获取并返回支持的值列表。

**代码逻辑推理：`NumberFormatDigitOptions` 部分**

**假设输入：**

* `mnfd_obj` (minimumFractionDigits):  `Handle` 指向值为 2 的 JavaScript 对象。
* `mxfd_obj` (maximumFractionDigits): `Handle` 指向值为 4 的 JavaScript 对象。
* `mnsd_obj` (minimumSignificantDigits): `Handle` 指向 `undefined`。
* `mxsd_obj` (maximumSignificantDigits): `Handle` 指向 `undefined`。
* `roundingPriority`: `RoundingPriority::kAuto`
* `notation_is_compact`: `false`
* `mnfd_default`: 0
* `mxfd_default`: 3

**推理过程：**

1. `has_sd` 为 `false`，`has_fd` 为 `true` (因为 `mnfd_obj` 和 `mxfd_obj` 不是 undefined)。
2. `roundingPriority` 是 `kAuto`。
3. `need_sd` 被设置为 `has_sd`，即 `false`。
4. `need_fd` 初始为 `true`。
5. 由于 `need_sd` 为 `false`，且 `notation_is_compact` 为 `false`，所以 `need_fd` 仍然为 `true`。
6. 进入 `if (need_fd)` 代码块。
7. 进入 `if (has_fd)` 代码块。
8. `mnfd` 被设置为从 `mnfd_obj` 获取的值 2。
9. `mxfd` 被设置为从 `mxfd_obj` 获取的值 4。
10. `mnfd_obj` 和 `mxfd_obj` 都不为 `undefined`，且 `mnfd` (2) 不大于 `mxfd` (4)。
11. `digit_options.minimum_fraction_digits` 被设置为 2。
12. `digit_options.maximum_fraction_digits` 被设置为 4。
13. 跳过 `if ((!need_sd) && (!need_fd))` 代码块。
14. 跳过其他的 `else if` 代码块，因为 `has_sd` 为 `false`。
15. 假设 `digit_options.rounding_increment` 为 1。

**预期输出：**

`digit_options` 结构体将包含以下值：

* `minimum_fraction_digits`: 2
* `maximum_fraction_digits`: 4
* `minimum_significant_digits`: (默认值，可能为 1)
* `maximum_significant_digits`: (默认值，可能为 21)
* `rounding_type`: `RoundingType::kFractionDigits` (因为 `has_fd` 为真，且之前的条件都不满足)

**用户常见的编程错误**

1. **`RangeError`：提供的选项值超出允许范围。**

   ```javascript
   // maximumFractionDigits 不能小于 minimumFractionDigits
   const formatter = new Intl.NumberFormat('en-US', {
     minimumFractionDigits: 3,
     maximumFractionDigits: 1
   }); // 抛出 RangeError
   ```
   这段 C++ 代码中的 `THROW_NEW_ERROR_RETURN_VALUE` 语句，在检测到 `mnfd > mxfd` 时，会抛出相应的 `RangeError`。

2. **`TypeError`：使用了错误的舍入类型与 `roundingIncrement` 组合。**

   ```javascript
   // roundingIncrement 只有在 roundingType 为 fractionDigits 时才能使用
   const formatter = new Intl.NumberFormat('en-US', {
     roundingPriority: "significantDigits",
     roundingIncrement: 5
   }); // 抛出 TypeError
   ```
   这段 C++ 代码中检查 `digit_options.rounding_type != RoundingType::kFractionDigits` 时会抛出 `TypeError`。

3. **`RangeError`：当使用 `roundingIncrement` 时，`minimumFractionDigits` 和 `maximumFractionDigits` 不相等。**

   ```javascript
   const formatter = new Intl.NumberFormat('en-US', {
     minimumFractionDigits: 1,
     maximumFractionDigits: 2,
     roundingIncrement: 5
   }); // 抛出 RangeError
   ```
   这段 C++ 代码中检查 `digit_options.maximum_fraction_digits != digit_options.minimum_fraction_digits` 时会抛出 `RangeError`。

4. **提供了无效的 locale 字符串。**

   ```javascript
   try {
     const formatter = new Intl.NumberFormat('invalid-locale');
   } catch (e) {
     console.error(e); // 可能抛出 RangeError 或其他错误
   }
   ```
   尽管这段 C++ 代码主要关注数字格式化选项，但其他部分，例如 locale 协商，会处理无效的 locale 输入。

5. **在 `supportedValuesOf` 中使用了无效的 key。**

   ```javascript
   try {
     Intl.supportedValuesOf('invalid-key');
   } catch (e) {
     console.error(e); // 抛出 RangeError
   }
   ```
   这段 C++ 代码中的 `Intl::SupportedValuesOf` 函数在接收到未知的 `key` 时会抛出 `RangeError`。

**归纳其功能 (作为第 3 部分)**

作为 `v8/src/objects/intl-objects.cc` 文件的第 3 部分，这段代码的核心功能是 **处理和验证 `Intl.NumberFormat` 构造函数接收的数字格式化选项，并确定最终的格式化属性。** 此外，它还涉及一些底层的 locale 协商和匹配机制，为后续的格式化操作做准备。 这部分代码是 V8 引擎实现 JavaScript 国际化 API 中数字格式化功能的重要组成部分，确保了数字能够按照用户指定的或默认的国际化规则进行格式化。它还提供了查询和验证 V8 支持的各种国际化值的能力。

Prompt: 
```
这是目录为v8/src/objects/intl-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/intl-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
 true.
  bool need_fd = true;
  // 23. If roundingPriority is "auto", then
  if (RoundingPriority::kAuto == digit_options.rounding_priority) {
    // a. Set needSd to hasSd.
    need_sd = has_sd;
    // b. If needSd is true, or hasFd is false and notation is "compact", then
    if (need_sd || ((!has_fd) && notation_is_compact)) {
      // i. Set needFd to false.
      need_fd = false;
    }
  }
  // 24. If needSd is true, then
  if (need_sd) {
    // 24.a If hasSd is true, then
    if (has_sd) {
      // i. Set intlObj.[[MinimumSignificantDigits]] to ?
      // DefaultNumberOption(mnsd, 1, 21, 1).
      int mnsd;
      if (!DefaultNumberOption(isolate, mnsd_obj, 1, 21, 1,
                               factory->minimumSignificantDigits_string())
               .To(&mnsd)) {
        return Nothing<NumberFormatDigitOptions>();
      }
      digit_options.minimum_significant_digits = mnsd;
      // ii. Set intlObj.[[MaximumSignificantDigits]] to ?
      // DefaultNumberOption(mxsd, intlObj.[[MinimumSignificantDigits]], 21,
      // 21).
      int mxsd;
      if (!DefaultNumberOption(isolate, mxsd_obj, mnsd, 21, 21,
                               factory->maximumSignificantDigits_string())
               .To(&mxsd)) {
        return Nothing<NumberFormatDigitOptions>();
      }
      digit_options.maximum_significant_digits = mxsd;
    } else {
      // 24.b Else
      // 24.b.i Set intlObj.[[MinimumSignificantDigits]] to 1.
      digit_options.minimum_significant_digits = 1;
      // 24.b.ii Set intlObj.[[MaximumSignificantDigits]] to 21.
      digit_options.maximum_significant_digits = 21;
    }
  }

  Handle<String> mxfd_str = factory->maximumFractionDigits_string();
  // 25. If needFd is true, then
  if (need_fd) {
    // a. If hasFd is true, then
    if (has_fd) {
      Handle<String> mnfd_str = factory->minimumFractionDigits_string();
      // i. Let mnfd be ? DefaultNumberOption(mnfd, 0, 100, undefined).
      int mnfd;
      if (!DefaultNumberOption(isolate, mnfd_obj, 0, 100, -1, mnfd_str)
               .To(&mnfd)) {
        return Nothing<NumberFormatDigitOptions>();
      }
      // ii. Let mxfd be ? DefaultNumberOption(mxfd, 0, 100, undefined).
      int mxfd;
      if (!DefaultNumberOption(isolate, mxfd_obj, 0, 100, -1, mxfd_str)
               .To(&mxfd)) {
        return Nothing<NumberFormatDigitOptions>();
      }
      // iii. If mnfd is undefined, set mnfd to min(mnfdDefault, mxfd).
      if (IsUndefined(*mnfd_obj, isolate)) {
        mnfd = std::min(mnfd_default, mxfd);
      } else if (IsUndefined(*mxfd_obj, isolate)) {
        // iv. Else if mxfd is undefined, set mxfd to max(mxfdDefault,
        // mnfd).
        mxfd = std::max(mxfd_default, mnfd);
      } else if (mnfd > mxfd) {
        // v. Else if mnfd is greater than mxfd, throw a RangeError
        // exception.
        THROW_NEW_ERROR_RETURN_VALUE(
            isolate,
            NewRangeError(MessageTemplate::kPropertyValueOutOfRange, mxfd_str),
            Nothing<NumberFormatDigitOptions>());
      }
      // vi. Set intlObj.[[MinimumFractionDigits]] to mnfd.
      digit_options.minimum_fraction_digits = mnfd;
      // vii. Set intlObj.[[MaximumFractionDigits]] to mxfd.
      digit_options.maximum_fraction_digits = mxfd;
    } else {  // b. Else
      // i. Set intlObj.[[MinimumFractionDigits]] to mnfdDefault.
      digit_options.minimum_fraction_digits = mnfd_default;
      // ii. Set intlObj.[[MaximumFractionDigits]] to mxfdDefault.
      digit_options.maximum_fraction_digits = mxfd_default;
    }
  }

  // 26. If needSd is false and needFd is false, then
  if ((!need_sd) && (!need_fd)) {
    // a. Set intlObj.[[MinimumFractionDigits]] to 0.
    digit_options.minimum_fraction_digits = 0;
    // b. Set intlObj.[[MaximumFractionDigits]] to 0.
    digit_options.maximum_fraction_digits = 0;
    // c. Set intlObj.[[MinimumSignificantDigits]] to 1.
    digit_options.minimum_significant_digits = 1;
    // d. Set intlObj.[[MaximumSignificantDigits]] to 2.
    digit_options.maximum_significant_digits = 2;
    // e. Set intlObj.[[RoundingType]] to morePrecision.
    digit_options.rounding_type = RoundingType::kMorePrecision;
    // 27. Else if roundingPriority is "morePrecision", then
  } else if (digit_options.rounding_priority ==
             RoundingPriority::kMorePrecision) {
    // i. Set intlObj.[[RoundingType]] to morePrecision.
    digit_options.rounding_type = RoundingType::kMorePrecision;
    // 28. Else if roundingPriority is "lessPrecision", then
  } else if (digit_options.rounding_priority ==
             RoundingPriority::kLessPrecision) {
    // i. Set intlObj.[[RoundingType]] to lessPrecision.
    digit_options.rounding_type = RoundingType::kLessPrecision;
    // 29. Else if hasSd, then
  } else if (has_sd) {
    // i. Set intlObj.[[RoundingType]] to significantDigits.
    digit_options.rounding_type = RoundingType::kSignificantDigits;
    // 30. Else,
  } else {
    // i.Set intlObj.[[RoundingType]] to fractionDigits.
    digit_options.rounding_type = RoundingType::kFractionDigits;
  }
  // 31. If roundingIncrement is not 1, then
  if (digit_options.rounding_increment != 1) {
    // a. If intlObj.[[RoundingType]] is not fractionDigits, throw a TypeError
    // exception.
    if (digit_options.rounding_type != RoundingType::kFractionDigits) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate, NewTypeError(MessageTemplate::kBadRoundingType),
          Nothing<NumberFormatDigitOptions>());
    }
    // b. If intlObj.[[MaximumFractionDigits]] is not equal to
    // intlObj.[[MinimumFractionDigits]], throw a RangeError exception.
    if (digit_options.maximum_fraction_digits !=
        digit_options.minimum_fraction_digits) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(MessageTemplate::kPropertyValueOutOfRange, mxfd_str),
          Nothing<NumberFormatDigitOptions>());
    }
  }
  return Just(digit_options);
}

namespace {

// ecma402/#sec-bestavailablelocale
std::string BestAvailableLocale(const std::set<std::string>& available_locales,
                                const std::string& locale) {
  // 1. Let candidate be locale.
  std::string candidate = locale;

  // 2. Repeat,
  while (true) {
    // 2.a. If availableLocales contains an element equal to candidate, return
    //      candidate.
    if (available_locales.find(candidate) != available_locales.end()) {
      return candidate;
    }

    // 2.b. Let pos be the character index of the last occurrence of "-"
    //      (U+002D) within candidate. If that character does not occur, return
    //      undefined.
    size_t pos = candidate.rfind('-');
    if (pos == std::string::npos) {
      return std::string();
    }

    // 2.c. If pos ≥ 2 and the character "-" occurs at index pos-2 of candidate,
    //      decrease pos by 2.
    if (pos >= 2 && candidate[pos - 2] == '-') {
      pos -= 2;
    }

    // 2.d. Let candidate be the substring of candidate from position 0,
    //      inclusive, to position pos, exclusive.
    candidate = candidate.substr(0, pos);
  }
}

struct ParsedLocale {
  std::string no_extensions_locale;
  std::string extension;
};

// Returns a struct containing a bcp47 tag without unicode extensions
// and the removed unicode extensions.
//
// For example, given 'en-US-u-co-emoji' returns 'en-US' and
// 'u-co-emoji'.
ParsedLocale ParseBCP47Locale(const std::string& locale) {
  size_t length = locale.length();
  ParsedLocale parsed_locale;

  // Privateuse or grandfathered locales have no extension sequences.
  if ((length > 1) && (locale[1] == '-')) {
    // Check to make sure that this really is a grandfathered or
    // privateuse extension. ICU can sometimes mess up the
    // canonicalization.
    DCHECK(locale[0] == 'x' || locale[0] == 'i');
    parsed_locale.no_extensions_locale = locale;
    return parsed_locale;
  }

  size_t unicode_extension_start = locale.find("-u-");

  // No unicode extensions found.
  if (unicode_extension_start == std::string::npos) {
    parsed_locale.no_extensions_locale = locale;
    return parsed_locale;
  }

  size_t private_extension_start = locale.find("-x-");

  // Unicode extensions found within privateuse subtags don't count.
  if (private_extension_start != std::string::npos &&
      private_extension_start < unicode_extension_start) {
    parsed_locale.no_extensions_locale = locale;
    return parsed_locale;
  }

  const std::string beginning = locale.substr(0, unicode_extension_start);
  size_t unicode_extension_end = length;
  DCHECK_GT(length, 2);

  // Find the end of the extension production as per the bcp47 grammar
  // by looking for '-' followed by 2 chars and then another '-'.
  for (size_t i = unicode_extension_start + 1; i < length - 2; i++) {
    if (locale[i] != '-') continue;

    if (locale[i + 2] == '-') {
      unicode_extension_end = i;
      break;
    }

    i += 2;
  }

  const std::string end = locale.substr(unicode_extension_end);
  parsed_locale.no_extensions_locale = beginning + end;
  parsed_locale.extension = locale.substr(
      unicode_extension_start, unicode_extension_end - unicode_extension_start);
  return parsed_locale;
}

// ecma402/#sec-lookupsupportedlocales
std::vector<std::string> LookupSupportedLocales(
    const std::set<std::string>& available_locales,
    const std::vector<std::string>& requested_locales) {
  // 1. Let subset be a new empty List.
  std::vector<std::string> subset;

  // 2. For each element locale of requestedLocales in List order, do
  for (const std::string& locale : requested_locales) {
    // 2. a. Let noExtensionsLocale be the String value that is locale
    //       with all Unicode locale extension sequences removed.
    std::string no_extension_locale =
        ParseBCP47Locale(locale).no_extensions_locale;

    // 2. b. Let availableLocale be
    //       BestAvailableLocale(availableLocales, noExtensionsLocale).
    std::string available_locale =
        BestAvailableLocale(available_locales, no_extension_locale);

    // 2. c. If availableLocale is not undefined, append locale to the
    //       end of subset.
    if (!available_locale.empty()) {
      subset.push_back(locale);
    }
  }

  // 3. Return subset.
  return subset;
}

icu::LocaleMatcher BuildLocaleMatcher(
    Isolate* isolate, const std::set<std::string>& available_locales,
    UErrorCode* status) {
  icu::Locale default_locale =
      icu::Locale::forLanguageTag(isolate->DefaultLocale(), *status);
  icu::LocaleMatcher::Builder builder;
  if (U_FAILURE(*status)) {
    return builder.build(*status);
  }
  builder.setDefaultLocale(&default_locale);
  for (auto it = available_locales.begin(); it != available_locales.end();
       ++it) {
    *status = U_ZERO_ERROR;
    icu::Locale l = icu::Locale::forLanguageTag(it->c_str(), *status);
    // skip invalid locale such as no-NO-NY
    if (U_SUCCESS(*status)) {
      builder.addSupportedLocale(l);
    }
  }
  return builder.build(*status);
}

class Iterator : public icu::Locale::Iterator {
 public:
  Iterator(std::vector<std::string>::const_iterator begin,
           std::vector<std::string>::const_iterator end)
      : iter_(begin), end_(end) {}
  ~Iterator() override = default;

  UBool hasNext() const override { return iter_ != end_; }

  const icu::Locale& next() override {
    UErrorCode status = U_ZERO_ERROR;
    locale_ = icu::Locale::forLanguageTag(iter_->c_str(), status);
    DCHECK(U_SUCCESS(status));
    ++iter_;
    return locale_;
  }

 private:
  std::vector<std::string>::const_iterator iter_;
  std::vector<std::string>::const_iterator end_;
  icu::Locale locale_;
};

// ecma402/#sec-bestfitmatcher
// The BestFitMatcher abstract operation compares requestedLocales, which must
// be a List as returned by CanonicalizeLocaleList, against the locales in
// availableLocales and determines the best available language to meet the
// request. The algorithm is implementation dependent, but should produce
// results that a typical user of the requested locales would perceive
// as at least as good as those produced by the LookupMatcher abstract
// operation. Options specified through Unicode locale extension sequences must
// be ignored by the algorithm. Information about such subsequences is returned
// separately. The abstract operation returns a record with a [[locale]] field,
// whose value is the language tag of the selected locale, which must be an
// element of availableLocales. If the language tag of the request locale that
// led to the selected locale contained a Unicode locale extension sequence,
// then the returned record also contains an [[extension]] field whose value is
// the first Unicode locale extension sequence within the request locale
// language tag.
std::string BestFitMatcher(Isolate* isolate,
                           const std::set<std::string>& available_locales,
                           const std::vector<std::string>& requested_locales) {
  UErrorCode status = U_ZERO_ERROR;
  Iterator iter(requested_locales.cbegin(), requested_locales.cend());
  std::string bestfit = BuildLocaleMatcher(isolate, available_locales, &status)
                            .getBestMatchResult(iter, status)
                            .makeResolvedLocale(status)
                            .toLanguageTag<std::string>(status);
  DCHECK(U_SUCCESS(status));
  return bestfit;
}

// ECMA 402 9.2.8 BestFitSupportedLocales(availableLocales, requestedLocales)
// https://tc39.github.io/ecma402/#sec-bestfitsupportedlocales
std::vector<std::string> BestFitSupportedLocales(
    Isolate* isolate, const std::set<std::string>& available_locales,
    const std::vector<std::string>& requested_locales) {
  UErrorCode status = U_ZERO_ERROR;
  icu::LocaleMatcher matcher =
      BuildLocaleMatcher(isolate, available_locales, &status);
  std::vector<std::string> result;
  if (U_SUCCESS(status)) {
    for (auto it = requested_locales.cbegin(); it != requested_locales.cend();
         it++) {
      status = U_ZERO_ERROR;
      icu::Locale desired = icu::Locale::forLanguageTag(it->c_str(), status);
      icu::LocaleMatcher::Result matched =
          matcher.getBestMatchResult(desired, status);
      if (U_FAILURE(status)) continue;
      if (matched.getSupportedIndex() < 0) continue;

      // The BestFitSupportedLocales abstract operation returns the *SUBSET* of
      // the provided BCP 47 language priority list requestedLocales for which
      // availableLocales has a matching locale when using the Best Fit Matcher
      // algorithm. Locales appear in the same order in the returned list as in
      // requestedLocales. The steps taken are implementation dependent.
      std::string bestfit = desired.toLanguageTag<std::string>(status);
      if (U_FAILURE(status)) continue;
      result.push_back(bestfit);
    }
  }
  return result;
}

// ecma262 #sec-createarrayfromlist
MaybeHandle<JSArray> CreateArrayFromList(Isolate* isolate,
                                         std::vector<std::string> elements,
                                         PropertyAttributes attr) {
  Factory* factory = isolate->factory();
  // Let array be ! ArrayCreate(0).
  Handle<JSArray> array = factory->NewJSArray(0);

  uint32_t length = static_cast<uint32_t>(elements.size());
  // 3. Let n be 0.
  // 4. For each element e of elements, do
  for (uint32_t i = 0; i < length; i++) {
    // a. Let status be CreateDataProperty(array, ! ToString(n), e).
    const std::string& part = elements[i];
    DirectHandle<String> value =
        factory->NewStringFromUtf8(base::CStrVector(part.c_str()))
            .ToHandleChecked();
    MAYBE_RETURN(JSObject::AddDataElement(array, i, value, attr),
                 MaybeHandle<JSArray>());
  }
  // 5. Return array.
  return MaybeHandle<JSArray>(array);
}

// ECMA 402 9.2.9 SupportedLocales(availableLocales, requestedLocales, options)
// https://tc39.github.io/ecma402/#sec-supportedlocales
MaybeHandle<JSObject> SupportedLocales(
    Isolate* isolate, const char* method_name,
    const std::set<std::string>& available_locales,
    const std::vector<std::string>& requested_locales, Handle<Object> options) {
  std::vector<std::string> supported_locales;

  // 1. Set options to ? CoerceOptionsToObject(options).
  Handle<JSReceiver> options_obj;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options_obj,
      CoerceOptionsToObject(isolate, options, method_name));

  // 2. Let matcher be ? GetOption(options, "localeMatcher", "string",
  //       « "lookup", "best fit" », "best fit").
  Maybe<Intl::MatcherOption> maybe_locale_matcher =
      Intl::GetLocaleMatcher(isolate, options_obj, method_name);
  MAYBE_RETURN(maybe_locale_matcher, MaybeHandle<JSObject>());
  Intl::MatcherOption matcher = maybe_locale_matcher.FromJust();

  // 3. If matcher is "best fit", then
  //    a. Let supportedLocales be BestFitSupportedLocales(availableLocales,
  //       requestedLocales).
  if (matcher == Intl::MatcherOption::kBestFit &&
      v8_flags.harmony_intl_best_fit_matcher) {
    supported_locales =
        BestFitSupportedLocales(isolate, available_locales, requested_locales);
  } else {
    // 4. Else,
    //    a. Let supportedLocales be LookupSupportedLocales(availableLocales,
    //       requestedLocales).
    supported_locales =
        LookupSupportedLocales(available_locales, requested_locales);
  }

  // 5. Return CreateArrayFromList(supportedLocales).
  return CreateArrayFromList(isolate, supported_locales,
                             PropertyAttributes::NONE);
}

}  // namespace

// ecma-402 #sec-intl.getcanonicallocales
MaybeHandle<JSArray> Intl::GetCanonicalLocales(Isolate* isolate,
                                               Handle<Object> locales) {
  // 1. Let ll be ? CanonicalizeLocaleList(locales).
  Maybe<std::vector<std::string>> maybe_ll =
      CanonicalizeLocaleList(isolate, locales, false);
  MAYBE_RETURN(maybe_ll, MaybeHandle<JSArray>());

  // 2. Return CreateArrayFromList(ll).
  return CreateArrayFromList(isolate, maybe_ll.FromJust(),
                             PropertyAttributes::NONE);
}

namespace {

MaybeHandle<JSArray> AvailableCollations(Isolate* isolate) {
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::StringEnumeration> enumeration(
      icu::Collator::getKeywordValues("collation", status));
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  return Intl::ToJSArray(isolate, "co", enumeration.get(),
                         Intl::RemoveCollation, true);
}

MaybeHandle<JSArray> VectorToJSArray(Isolate* isolate,
                                     const std::vector<std::string>& array) {
  Factory* factory = isolate->factory();
  DirectHandle<FixedArray> fixed_array =
      factory->NewFixedArray(static_cast<int32_t>(array.size()));
  int32_t index = 0;
  for (const std::string& item : array) {
    DirectHandle<String> str = factory->NewStringFromAsciiChecked(item.c_str());
    fixed_array->set(index++, *str);
  }
  return factory->NewJSArrayWithElements(fixed_array);
}

namespace {

class ResourceAvailableCurrencies {
 public:
  ResourceAvailableCurrencies() {
    UErrorCode status = U_ZERO_ERROR;
    UEnumeration* uenum =
        ucurr_openISOCurrencies(UCURR_COMMON | UCURR_NON_DEPRECATED, &status);
    DCHECK(U_SUCCESS(status));
    const char* next = nullptr;
    while (U_SUCCESS(status) &&
           (next = uenum_next(uenum, nullptr, &status)) != nullptr) {
      // Work around the issue that we do not support VEF currency code
      // in DisplayNames by not reporting it.
      if (strcmp(next, "VEF") == 0) continue;
      AddIfAvailable(next);
    }
    // Work around the issue that we do support the following currency codes
    // in DisplayNames but the ICU API is not reporting it.
    AddIfAvailable("SVC");
    AddIfAvailable("XDR");
    AddIfAvailable("XSU");
    AddIfAvailable("ZWL");
    std::sort(list_.begin(), list_.end());
    uenum_close(uenum);
  }

  const std::vector<std::string>& Get() const { return list_; }

  void AddIfAvailable(const char* currency) {
    icu::UnicodeString code(currency, -1, US_INV);
    UErrorCode status = U_ZERO_ERROR;
    int32_t len = 0;
    const UChar* result =
        ucurr_getName(code.getTerminatedBuffer(), "en", UCURR_LONG_NAME,
                      nullptr, &len, &status);
    if (U_SUCCESS(status) &&
        u_strcmp(result, code.getTerminatedBuffer()) != 0) {
      list_.push_back(currency);
    }
  }

 private:
  std::vector<std::string> list_;
};

const std::vector<std::string>& GetAvailableCurrencies() {
  static base::LazyInstance<ResourceAvailableCurrencies>::type
      available_currencies = LAZY_INSTANCE_INITIALIZER;
  return available_currencies.Pointer()->Get();
}
}  // namespace

MaybeHandle<JSArray> AvailableCurrencies(Isolate* isolate) {
  return VectorToJSArray(isolate, GetAvailableCurrencies());
}

MaybeHandle<JSArray> AvailableNumberingSystems(Isolate* isolate) {
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::StringEnumeration> enumeration(
      icu::NumberingSystem::getAvailableNames(status));
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  // Need to filter out isAlgorithmic
  return Intl::ToJSArray(
      isolate, "nu", enumeration.get(),
      [](const char* value) {
        UErrorCode status = U_ZERO_ERROR;
        std::unique_ptr<icu::NumberingSystem> numbering_system(
            icu::NumberingSystem::createInstanceByName(value, status));
        // Skip algorithmic one since chrome filter out the resource.
        return U_FAILURE(status) || numbering_system->isAlgorithmic();
      },
      true);
}

MaybeHandle<JSArray> AvailableTimeZones(Isolate* isolate) {
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::StringEnumeration> enumeration(
      icu::TimeZone::createTimeZoneIDEnumeration(
          UCAL_ZONE_TYPE_CANONICAL_LOCATION, nullptr, nullptr, status));
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  return Intl::ToJSArray(isolate, nullptr, enumeration.get(), nullptr, true);
}

MaybeHandle<JSArray> AvailableUnits(Isolate* isolate) {
  Factory* factory = isolate->factory();
  std::set<std::string> sanctioned(Intl::SanctionedSimpleUnits());
  DirectHandle<FixedArray> fixed_array =
      factory->NewFixedArray(static_cast<int32_t>(sanctioned.size()));
  int32_t index = 0;
  for (const std::string& item : sanctioned) {
    DirectHandle<String> str = factory->NewStringFromAsciiChecked(item.c_str());
    fixed_array->set(index++, *str);
  }
  return factory->NewJSArrayWithElements(fixed_array);
}

}  // namespace

// ecma-402 #sec-intl.supportedvaluesof
MaybeHandle<JSArray> Intl::SupportedValuesOf(Isolate* isolate,
                                             Handle<Object> key_obj) {
  Factory* factory = isolate->factory();
  // 1. 1. Let key be ? ToString(key).
  Handle<String> key_str;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, key_str,
                             Object::ToString(isolate, key_obj));
  // 2. If key is "calendar", then
  if (factory->calendar_string()->Equals(*key_str)) {
    // a. Let list be ! AvailableCalendars( ).
    return Intl::AvailableCalendars(isolate);
  }
  // 3. Else if key is "collation", then
  if (factory->collation_string()->Equals(*key_str)) {
    // a. Let list be ! AvailableCollations( ).
    return AvailableCollations(isolate);
  }
  // 4. Else if key is "currency", then
  if (factory->currency_string()->Equals(*key_str)) {
    // a. Let list be ! AvailableCurrencies( ).
    return AvailableCurrencies(isolate);
  }
  // 5. Else if key is "numberingSystem", then
  if (factory->numberingSystem_string()->Equals(*key_str)) {
    // a. Let list be ! AvailableNumberingSystems( ).
    return AvailableNumberingSystems(isolate);
  }
  // 6. Else if key is "timeZone", then
  if (factory->timeZone_string()->Equals(*key_str)) {
    // a. Let list be ! AvailableTimeZones( ).
    return AvailableTimeZones(isolate);
  }
  // 7. Else if key is "unit", then
  if (factory->unit_string()->Equals(*key_str)) {
    // a. Let list be ! AvailableUnits( ).
    return AvailableUnits(isolate);
  }
  // 8. Else,
  // a. Throw a RangeError exception.
  // 9. Return ! CreateArrayFromList( list ).

  THROW_NEW_ERROR(
      isolate,
      NewRangeError(MessageTemplate::kInvalid,
                    factory->NewStringFromStaticChars("key"), key_str));
}

// ECMA 402 Intl.*.supportedLocalesOf
MaybeHandle<JSObject> Intl::SupportedLocalesOf(
    Isolate* isolate, const char* method_name,
    const std::set<std::string>& available_locales, Handle<Object> locales,
    Handle<Object> options) {
  // Let availableLocales be %Collator%.[[AvailableLocales]].

  // Let requestedLocales be ? CanonicalizeLocaleList(locales).
  Maybe<std::vector<std::string>> requested_locales =
      CanonicalizeLocaleList(isolate, locales, false);
  MAYBE_RETURN(requested_locales, MaybeHandle<JSObject>());

  // Return ? SupportedLocales(availableLocales, requestedLocales, options).
  return SupportedLocales(isolate, method_name, available_locales,
                          requested_locales.FromJust(), options);
}

namespace {

template <typename T>
bool IsValidExtension(const icu::Locale& locale, const char* key,
                      const std::string& value) {
  const char* legacy_type = uloc_toLegacyType(key, value.c_str());
  if (legacy_type == nullptr) {
    return false;
  }
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::StringEnumeration> enumeration(
      T::getKeywordValuesForLocale(key, icu::Locale(locale.getBaseName()),
                                   false, status));
  if (U_FAILURE(status)) {
    return false;
  }
  int32_t length;
  for (const char* item = enumeration->next(&length, status);
       U_SUCCESS(status) && item != nullptr;
       item = enumeration->next(&length, status)) {
    if (strcmp(legacy_type, item) == 0) {
      return true;
    }
  }
  return false;
}

}  // namespace

bool Intl::IsValidCollation(const icu::Locale& locale,
                            const std::string& value) {
  std::set<std::string> invalid_values = {"standard", "search"};
  if (invalid_values.find(value) != invalid_values.end()) return false;
  return IsValidExtension<icu::Collator>(locale, "collation", value);
}

bool Intl::IsWellFormedCalendar(const std::string& value) {
  return JSLocale::Is38AlphaNumList(value);
}

// ecma402/#sec-iswellformedcurrencycode
bool Intl::IsWellFormedCurrency(const std::string& currency) {
  return JSLocale::Is3Alpha(currency);
}

bool Intl::IsValidCalendar(const icu::Locale& locale,
                           const std::string& value) {
  return IsValidExtension<icu::Calendar>(locale, "calendar", value);
}

bool Intl::IsValidNumberingSystem(const std::string& value) {
  std::set<std::string> invalid_values = {"native", "traditio", "finance"};
  if (invalid_values.find(value) != invalid_values.end()) return false;
  UErrorCode status = U_ZERO_ERROR;
  std::unique_ptr<icu::NumberingSystem> numbering_system(
      icu::NumberingSystem::createInstanceByName(value.c_str(), status));
  return U_SUCCESS(status) && numbering_system != nullptr &&
         !numbering_system->isAlgorithmic();
}

namespace {

bool IsWellFormedNumberingSystem(const std::string& value) {
  return JSLocale::Is38AlphaNumList(value);
}

std::map<std::string, std::string> LookupAndValidateUnicodeExtensions(
    icu::Locale* icu_locale, const std::set<std::string>& relevant_keys) {
  std::map<std::string, std::string> extensions;

  UErrorCode status = U_ZERO_ERROR;
  icu::LocaleBuilder builder;
  builder.setLocale(*icu_locale).clearExtensions();
  std::unique_ptr<icu::StringEnumeration> keywords(
      icu_locale->createKeywords(status));
  if (U_FAILURE(status)) return extensions;

  if (!keywords) return extensions;
  char value[ULOC_FULLNAME_CAPACITY];

  int32_t length;
  status = U_ZERO_ERROR;
  for (const char* keyword = keywords->next(&length, status);
       keyword != nullptr; keyword = keywords->next(&length, status)) {
    // Ignore failures in ICU and skip to the next keyword.
    //
    // This is fine.™
    if (U_FAILURE(status)) {
      status = U_ZERO_ERROR;
      continue;
    }

    icu_locale->getKeywordValue(keyword, value, ULOC_FULLNAME_CAPACITY, status);

    // Ignore failures in ICU and skip to the next keyword.
    //
    // This is fine.™
    if (U_FAILURE(status)) {
      status = U_ZERO_ERROR;
      continue;
    }

    const char* bcp47_key = uloc_toUnicodeLocaleKey(keyword);

    if (bcp47_key && (relevant_keys.find(bcp47_key) != relevant_keys.end())) {
      const char* bcp47_value = uloc_toUnicodeLocaleType(bcp47_key, value);
      bool is_valid_value = false;
      // 8.h.ii.1.a If keyLocaleData contains requestedValue, then
      if (strcmp("ca", bcp47_key) == 0) {
        is_valid_value = Intl::IsValidCalendar(*icu_locale, bcp47_value);
      } else if (strcmp("co", bcp47_key) == 0) {
        is_valid_value = Intl::IsValidCollation(*icu_locale, bcp47_value);
      } else if (strcmp("hc", bcp47_key) == 0) {
        // https://www.unicode.org/repos/cldr/tags/latest/common/bcp47/calendar.xml
        std::set<std::string> valid_values = {"h11", "h12", "h23", "h24"};
        is_valid_value = valid_values.find(bcp47_value) != valid_values.end();
      } else if (strcmp("lb", bcp47_key) == 0) {
        // https://www.unicode.org/repos/cldr/tags/latest/common/bcp47/segmentation.xml
        std::set<std::string> valid_values = {"strict", "normal", "loose"};
        is_valid_value = valid_values.find(bcp47_value) != valid_values.end();
      } else if (strcmp("kn", bcp47_key) == 0) {
        // https://www.unicode.org/repos/cldr/tags/latest/common/bcp47/collation.xml
        std::set<std::string> valid_values = {"true", "false"};
        is_valid_value = valid_values.find(bcp47_value) != valid_values.end();
      } else if (strcmp("kf", bcp47_key) == 0) {
        // https://www.unicode.org/repos/cldr/tags/latest/common/bcp47/collation.xml
        std::set<std::string> valid_values = {"upper", "lower", "false"};
        is_valid_value = valid_values.find(bcp47_value) != valid_values.end();
      } else if (strcmp("nu", bcp47_key) == 0) {
        is_valid_value = Intl::IsValidNumberingSystem(bcp47_value);
      }
      if (is_valid_value) {
        extensions.insert(
            std::pair<std::string, std::string>(bcp47_key, bcp47_value));
        builder.setUnicodeLocaleKeyword(bcp47_key, bcp47_value);
      }
    }
  }

  status = U_ZERO_ERROR;
  *icu_locale = builder.build(status);

  return extensions;
}

// ecma402/#sec-lookupmatcher
std::string LookupMatcher(Isolate* isolate,
                          const std::set<std::string>& available_locales,
                          const std::vector<std::string>& requested_locales) {
  // 1. Let result be a new Record.
  std::string result;

  // 2. For each element locale of requestedLocales in List order, do
  for (const std::string& locale : requested_locales) {
    // 2. a. Let noExtensionsLocale be the String value that is locale
    //       with all Unicode locale extension sequences removed.
    ParsedLocale parsed_locale = ParseBCP47Locale(locale);
    std::string no_extensions_locale = parsed_locale.no_extensions_locale;

    // 2. b. Let availableLocale be
    //       BestAvailableLocale(availableLocales, noExtensionsLocale).
    std::string available_locale =
        BestAvailableLocale(available_locales, no_extensions_locale);

    // 2. c. If availableLocale is not undefined, append locale to the
    //       end of subset.
    if (!available_locale.empty()) {
      // Note: The following steps are not performed here because we
      // can use ICU to parse the unicode locale extension sequence
      // as part of Intl::ResolveLocale.
      //
      // There's no need to separate the unicode locale extensions
      // right here. Instead just return the available locale with the
      // extensions.
      //
      // 2. c. i. Set result.[[locale]] to availableLocale.
      // 2. c. ii. If locale and noExtensionsLocale are not the same
      // String value, then
      // 2. c. ii. 1. Let extension be the String value consisting of
      // the first substring of locale that is a Unicode locale
      // extension sequence.
      // 2. c. ii. 2. Set result.[[extension]] to extension.
      // 2. c. iii. Return result.
      return available_locale + parsed_locale.extension;
    }
  }

  // 3. Let defLocale be DefaultLocale();
  // 4. Set result.[[locale]] to defLocale.
  // 5. Return result.
  return isolate->DefaultLocale();
}

}  // namespace

// This function doesn't correspond exactly with the spec. Instead
// we use I
"""


```