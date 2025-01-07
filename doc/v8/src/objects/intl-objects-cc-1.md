Response:
The user wants me to summarize the functionality of the provided C++ code snippet from `v8/src/objects/intl-objects.cc`.

Here's a breakdown of the code's functionalities:

1. **`CanonicalizeLocaleList` (Partially Shown):** This function takes a list of locales (likely from a JavaScript `Intl` API call) and converts them into a standardized, canonical form. It iterates through the provided locales, validates them, and stores the canonicalized versions.

2. **`Intl::StringLocaleConvertCase`:** This function performs locale-sensitive case conversion (to uppercase or lowercase) on a string. It uses the provided locales (or the default locale if none are provided) to determine the correct conversion rules. It has special handling for certain languages like Turkish, Greek, Lithuanian, and Azerbaijani.

3. **`Intl::CompareStringsOptionsFor`:** This function determines whether a fast path can be used for string comparison based on the provided locales and options. It checks against a hardcoded list of locales known to work with the fast path.

4. **`Intl::StringLocaleCompare`:** This function compares two strings in a locale-sensitive manner. It leverages the `icu::Collator` object for the actual comparison. It also includes logic for caching `icu::Collator` instances for performance when the locales and options are simple (string/undefined locales and undefined options). It tries to use a fast path if possible.

5. **Fast String Comparison (`TryFastCompareStrings`, helper functions):**  A significant portion of the code deals with a fast path for string comparison. This involves:
    *   Precomputed weight tables (`kCollationWeightsL1`, `kCollationWeightsL3`) for ASCII characters.
    *   `FastCompareFlatString` and `FastCompareStringFlatContent`: Functions that compare the flattened string contents character by character using the weight tables.
    *   `CanFastCompare`:  A function to check if a character is eligible for fast comparison (within the ASCII range with a non-zero L1 weight).
    *   `CollatorAllowsFastComparison` (in debug builds): A function that verifies if an `icu::Collator` instance has the necessary attributes for fast comparison.

6. **`Intl::CompareStrings`:**  This is the core string comparison function. It first checks for identical strings, then attempts the fast path if configured. If the fast path doesn't apply or fails partway, it uses the full ICU collator for comparison.

7. **`Intl::NumberToLocaleString`:**  This function formats a number into a locale-sensitive string. It uses `icu::number::LocalizedNumberFormatter`. Similar to string comparison, it includes caching for performance in simple cases.

8. **`Intl::SetNumberFormatDigitOptions` (Partially Shown):** This function extracts and validates digit-related options from the `options` object passed to the `Intl.NumberFormat` constructor. It handles options like `minimumIntegerDigits`, `minimumFractionDigits`, `maximumFractionDigits`, `minimumSignificantDigits`, `maximumSignificantDigits`, `roundingIncrement`, `roundingMode`, `roundingPriority`, and `trailingZeroDisplay`.

**Focusing on the provided snippet (part 2):**

The code snippet in part 2 primarily focuses on:

*   **Iterating through properties of an object to collect locale tags:** The loop involving `okupIterator` aims to extract locale tags from the properties of an object. It checks if the property value is a valid locale tag (either a `JSLocale` object or a string that can be canonicalized).
*   **Locale-sensitive case conversion:** The `Intl::StringLocaleConvertCase` function handles converting strings to uppercase or lowercase based on the specified locale. It includes optimizations for common cases and special handling for certain languages.
*   **Determining fast-path eligibility for string comparison:**  The `Intl::CompareStringsOptionsFor` function checks if the current locales and options allow for a faster string comparison algorithm.

I will now formulate the detailed explanation and examples.

好的，这是第2部分的功能归纳：

**功能归纳 (第 2 部分):**

这段代码主要包含以下功能：

1. **规范化区域设置列表:**
    *   `CanonicalizeLocaleList`:  此函数（在代码片段的开头被调用）负责将传入的区域设置列表规范化。它会遍历对象 `o` 的属性，尝试将每个属性值视为区域设置标记。
    *   它会检查属性值是否已经是 `JSLocale` 对象。如果是，则直接提取其内部的区域设置标记。
    *   如果不是 `JSLocale` 对象，则尝试将其转换为字符串，并使用 `CanonicalizeLanguageTag` 函数对其进行规范化。
    *   它会维护一个 `seen` 向量来存储已规范化的唯一区域设置标记。
    *   此函数允许传入一个布尔值 `only_return_one_result`，用于优化只需要单个结果的情况。

    **与 JavaScript 的关系:** 这段代码与 JavaScript 的 `Intl` API 紧密相关，例如 `Intl.getCanonicalLocales()` 等方法会使用到规范化区域设置列表的功能。

    ```javascript
    console.log(Intl.getCanonicalLocales(['en-US', 'zh-CN-u-nu-hanidec'])); // 输出: ["en-US", "zh-CN-u-nu-hanidec"]
    console.log(Intl.getCanonicalLocales(['EN-us', 'ZH-CN'])); // 输出: ["en-US", "zh-CN"]
    ```

2. **区域设置敏感的大小写转换:**
    *   `Intl::StringLocaleConvertCase`: 此函数根据指定的区域设置将字符串转换为大写或小写。
    *   它首先调用 `CanonicalizeLocaleList` 来处理传入的区域设置参数。
    *   如果没有提供区域设置，则使用默认区域设置。
    *   对于某些特定的双字母语言代码（如土耳其语 "tr"、希腊语 "el"、立陶宛语 "lt"、阿塞拜疆语 "az"），它会调用 `LocaleConvertCase` 进行特殊处理。
    *   对于其他情况，它会使用通用的 `ConvertToUpper` 或 `ConvertToLower` 函数。

    **与 JavaScript 的关系:**  对应 JavaScript 中字符串的 `toLocaleUpperCase()` 和 `toLocaleLowerCase()` 方法。

    ```javascript
    const text = 'istanbul';
    console.log(text.toLocaleUpperCase('en-US')); // 输出: ISTANBUL
    console.log(text.toLocaleUpperCase('tr-TR')); // 输出: İSTANBUL (注意带点的 'İ')

    const text2 = 'IZMIR';
    console.log(text2.toLocaleLowerCase('en-US')); // 输出: izmir
    console.log(text2.toLocaleLowerCase('tr-TR')); // 输出: ızmir (注意不带点的 'ı')
    ```

3. **字符串比较选项的确定 (快速路径):**
    *   `Intl::CompareStringsOptionsFor`: 此函数根据传入的 `locales` 和 `options` 参数，判断是否可以使用优化的快速路径进行字符串比较。
    *   它维护一个静态的 `kFastLocales` 列表，其中包含已知可以进行快速比较的区域设置。
    *   如果 `locales` 为 `undefined`，则会检查默认区域设置是否在 `kFastLocales` 中。
    *   如果 `locales` 是一个字符串，则会检查该字符串是否与 `kFastLocales` 中的某个值匹配。
    *   仅当 `options` 为 `undefined` 时才会考虑快速路径。

    **与 JavaScript 的关系:** 尽管用户无法直接控制是否使用快速路径，但此逻辑影响着 `Intl.Collator.prototype.compare()` 和字符串的 `localeCompare()` 方法的性能。

    ```javascript
    const collator = new Intl.Collator('en-US');
    const result = collator.compare('apple', 'banana');
    ```

4. **区域设置敏感的字符串比较:**
    *   `Intl::StringLocaleCompare`: 此函数执行区域设置敏感的字符串比较。
    *   它首先判断是否可以进行缓存 (当 `locales` 是字符串或 `undefined`，且 `options` 是 `undefined` 时)。
    *   如果可以缓存，则尝试从缓存中获取 `icu::Collator` 实例。
    *   如果缓存中没有，则创建一个新的 `Intl.Collator` 实例，并将其缓存起来。
    *   它调用 `Intl::CompareStrings` 来执行实际的比较操作。

    **与 JavaScript 的关系:** 对应 JavaScript 中 `Intl.Collator.prototype.compare()` 方法和字符串的 `localeCompare()` 方法。

    ```javascript
    const collator = new Intl.Collator('de');
    console.log(collator.compare('ä', 'z')); // 输出: -1 (ä 在 z 之前)
    console.log(collator.compare('Ae', 'ä')); // 输出: 0 (在某些德语排序规则中，Ae 等于 ä)
    ```

5. **快速字符串比较的实现 (`TryFastCompareStrings` 及相关辅助函数):**
    *   包含 `kCollationWeightsL1` 和 `kCollationWeightsL3` 两个常量数组，存储了 ASCII 字符的 Unicode 排序算法的权重。
    *   `FastCompareFlatString` 和 `FastCompareStringFlatContent` 函数实现了对扁平字符串的快速比较，直接比较字符的 L1 和 L3 权重。
    *   `CanFastCompare` 函数判断一个字符是否在可以进行快速比较的范围内。
    *   `CollatorAllowsFastComparison` 函数（仅在 DEBUG 模式下）用于断言 `icu::Collator` 的配置是否允许快速比较。
    *   `TryFastCompareStrings` 函数尝试使用这些优化手段进行快速比较，如果遇到不能快速比较的字符，则返回 `std::optional` 空值，表示快速比较失败。

    **代码逻辑推理示例:**

    **假设输入:** `string1 = "abc"`, `string2 = "abd"`, 使用英文区域设置 (属于 `kFastLocales`)。

    **推理:**
    *   `Intl::CompareStringsOptionsFor` 会返回 `CompareStringsOptions::kTryFastPath`。
    *   `TryFastCompareStrings` 会被调用。
    *   前两个字符 'a' 和 'b' 的 L1 权重相同。
    *   比较第三个字符 'c' 和 'd' 的 L1 权重，`kCollationWeightsL1['c']` < `kCollationWeightsL1['d']`。
    *   `TryFastCompareStrings` 将返回 `UCollationResult::UCOL_LESS`。
    *   `Intl::StringLocaleCompare` 最终会返回一个负数。

    **假设输入:** `string1 = "abé"`, `string2 = "abc"`, 使用英文区域设置。

    **推理:**
    *   `Intl::CompareStringsOptionsFor` 会返回 `CompareStringsOptions::kTryFastPath`。
    *   `TryFastCompareStrings` 会被调用。
    *   前两个字符 'a' 和 'b' 可以快速比较。
    *   第三个字符 'é' 不在 ASCII 范围内，`CanFastCompare('é')` 返回 `false`。
    *   `TryFastCompareStrings` 将返回 `std::optional` 空值。
    *   `Intl::StringLocaleCompare` 将使用完整的 ICU 比较逻辑。

6. **数字的本地化字符串表示:**
    *   `Intl::NumberToLocaleString`: 此函数将数字转换为本地化的字符串表示形式。
    *   它与字符串比较类似，也实现了缓存机制来复用 `icu::number::LocalizedNumberFormatter` 实例。
    *   如果可以缓存，则尝试从缓存中获取。否则，创建一个新的 `Intl.NumberFormat` 实例并缓存。
    *   最终调用 `JSNumberFormat::FormatNumeric` 来执行格式化。

    **与 JavaScript 的关系:** 对应 JavaScript 中 `Number.prototype.toLocaleString()` 方法。

    ```javascript
    const number = 123456.789;
    console.log(number.toLocaleString('en-US')); // 输出: 123,456.789
    console.log(number.toLocaleString('de-DE')); // 输出: 123.456,789
    ```

7. **数字格式化选项的设置 (部分展示):**
    *   `Intl::SetNumberFormatDigitOptions`: 此函数（部分代码展示）负责从 `Intl.NumberFormat` 的 `options` 对象中提取和验证与数字位数相关的选项。
    *   它处理诸如 `minimumIntegerDigits`、`minimumFractionDigits`、`maximumFractionDigits`、`minimumSignificantDigits`、`maximumSignificantDigits`、`roundingIncrement`、`roundingMode`、`roundingPriority` 和 `trailingZeroDisplay` 等选项。
    *   它会检查 `roundingIncrement` 是否为有效值（在预定义的列表中）。

    **与 JavaScript 的关系:** 此函数在 `Intl.NumberFormat` 构造函数内部被调用，用于解析用户提供的选项。

    ```javascript
    const formatter = new Intl.NumberFormat('en-US', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 4,
      roundingIncrement: 5, // 例如，只允许 1, 2, 5, 10...
    });
    console.log(formatter.format(12.34567));
    ```

**用户常见的编程错误示例:**

*   **在 `toLocaleUpperCase` 或 `toLocaleLowerCase` 中使用错误的区域设置格式:**

    ```javascript
    const text = 'hello';
    console.log(text.toLocaleUpperCase('en_US')); // 错误: 应该使用连字符 '-' 而不是下划线 '_'
    ```

*   **假设快速比较适用于所有区域设置:** 开发者不应该假设所有区域设置下的字符串比较都很快，因为快速路径只适用于一部分预定义的区域设置。

*   **在 `Intl.NumberFormat` 的 `roundingIncrement` 选项中使用无效的值:**

    ```javascript
    const formatter = new Intl.NumberFormat('en-US', { roundingIncrement: 3 }); // 错误: 3 不在允许的列表中
    ```

总而言之，第 2 部分的代码主要负责处理与国际化相关的字符串操作（大小写转换、比较）以及数字的本地化格式化，并包含了为了提升性能的快速比较优化逻辑和缓存机制。它紧密地服务于 JavaScript 的 `Intl` API。

Prompt: 
```
这是目录为v8/src/objects/intl-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/intl-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
okupIterator it(isolate, o, k);
    Maybe<bool> maybe_found = JSReceiver::HasProperty(&it);
    MAYBE_RETURN(maybe_found, Nothing<std::vector<std::string>>());
    // 7c. If kPresent is true, then
    if (!maybe_found.FromJust()) continue;
    // 7c i. Let kValue be ? Get(O, Pk).
    Handle<Object> k_value;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, k_value, Object::GetProperty(&it),
                                     Nothing<std::vector<std::string>>());
    // 7c ii. If Type(kValue) is not String or Object, throw a TypeError
    // exception.
    // 7c iii. If Type(kValue) is Object and kValue has an [[InitializedLocale]]
    // internal slot, then
    std::string canonicalized_tag;
    if (IsJSLocale(*k_value)) {
      // 7c iii. 1. Let tag be kValue.[[Locale]].
      canonicalized_tag = JSLocale::ToString(Cast<JSLocale>(k_value));
      // 7c iv. Else,
    } else {
      // 7c iv 1. Let tag be ? ToString(kValue).
      // 7c v. If IsStructurallyValidLanguageTag(tag) is false, throw a
      // RangeError exception.
      // 7c vi. Let canonicalizedTag be CanonicalizeLanguageTag(tag).
      if (!CanonicalizeLanguageTag(isolate, k_value).To(&canonicalized_tag)) {
        return Nothing<std::vector<std::string>>();
      }
    }
    // 7c vi. If canonicalizedTag is not an element of seen, append
    // canonicalizedTag as the last element of seen.
    if (std::find(seen.begin(), seen.end(), canonicalized_tag) == seen.end()) {
      seen.push_back(canonicalized_tag);
    }
    // 7d. Increase k by 1. (See loop header.)
    // Optimization: some callers only need one result.
    if (only_return_one_result) return Just(seen);
  }
  // 8. Return seen.
  return Just(seen);
}

// ecma402 #sup-string.prototype.tolocalelowercase
// ecma402 #sup-string.prototype.tolocaleuppercase
MaybeHandle<String> Intl::StringLocaleConvertCase(Isolate* isolate,
                                                  Handle<String> s,
                                                  bool to_upper,
                                                  Handle<Object> locales) {
  std::vector<std::string> requested_locales;
  if (!CanonicalizeLocaleList(isolate, locales, true).To(&requested_locales)) {
    return MaybeHandle<String>();
  }
  std::string requested_locale = requested_locales.empty()
                                     ? isolate->DefaultLocale()
                                     : requested_locales[0];
  size_t dash = requested_locale.find('-');
  if (dash != std::string::npos) {
    requested_locale = requested_locale.substr(0, dash);
  }

  // Primary language tag can be up to 8 characters long in theory.
  // https://tools.ietf.org/html/bcp47#section-2.2.1
  DCHECK_LE(requested_locale.length(), 8);
  s = String::Flatten(isolate, s);

  // All the languages requiring special-handling have two-letter codes.
  // Note that we have to check for '!= 2' here because private-use language
  // tags (x-foo) or grandfathered irregular tags (e.g. i-enochian) would have
  // only 'x' or 'i' when they get here.
  if (V8_UNLIKELY(requested_locale.length() != 2)) {
    if (to_upper) {
      return ConvertToUpper(isolate, s);
    }
    return ConvertToLower(isolate, s);
  }
  // TODO(jshin): Consider adding a fast path for ASCII or Latin-1. The fastpath
  // in the root locale needs to be adjusted for az, lt and tr because even case
  // mapping of ASCII range characters are different in those locales.
  // Greek (el) does not require any adjustment.
  if (V8_UNLIKELY((requested_locale == "tr") || (requested_locale == "el") ||
                  (requested_locale == "lt") || (requested_locale == "az"))) {
    return LocaleConvertCase(isolate, s, to_upper, requested_locale.c_str());
  } else {
    if (to_upper) {
      return ConvertToUpper(isolate, s);
    }
    return ConvertToLower(isolate, s);
  }
}

// static
template <class IsolateT>
Intl::CompareStringsOptions Intl::CompareStringsOptionsFor(
    IsolateT* isolate, DirectHandle<Object> locales,
    DirectHandle<Object> options) {
  if (!IsUndefined(*options, isolate)) {
    return CompareStringsOptions::kNone;
  }

  // Lists all of the available locales that are statically known to fulfill
  // fast path conditions. See the StringLocaleCompareFastPath test as a
  // starting point to update this list.
  //
  // Locale entries are roughly sorted s.t. common locales come first.
  //
  // The actual conditions are verified in debug builds in
  // CollatorAllowsFastComparison.
  static const char* const kFastLocales[] = {
      "en-US", "en", "fr", "es",    "de",    "pt",    "it", "ca",
      "de-AT", "fi", "id", "id-ID", "ms",    "nl",    "pl", "ro",
      "sl",    "sv", "sw", "vi",    "en-DE", "en-GB",
  };

  if (IsUndefined(*locales, isolate)) {
    const std::string& default_locale = isolate->DefaultLocale();
    for (const char* fast_locale : kFastLocales) {
      if (strcmp(fast_locale, default_locale.c_str()) == 0) {
        return CompareStringsOptions::kTryFastPath;
      }
    }

    return CompareStringsOptions::kNone;
  }

  if (!IsString(*locales)) return CompareStringsOptions::kNone;

  auto locales_string = Cast<String>(locales);
  for (const char* fast_locale : kFastLocales) {
    if (locales_string->IsEqualTo(base::CStrVector(fast_locale), isolate)) {
      return CompareStringsOptions::kTryFastPath;
    }
  }

  return CompareStringsOptions::kNone;
}

// Instantiations.
template Intl::CompareStringsOptions Intl::CompareStringsOptionsFor(
    Isolate*, DirectHandle<Object>, DirectHandle<Object>);
template Intl::CompareStringsOptions Intl::CompareStringsOptionsFor(
    LocalIsolate*, DirectHandle<Object>, DirectHandle<Object>);

std::optional<int> Intl::StringLocaleCompare(
    Isolate* isolate, Handle<String> string1, Handle<String> string2,
    Handle<Object> locales, Handle<Object> options, const char* method_name) {
  // We only cache the instance when locales is a string/undefined and
  // options is undefined, as that is the only case when the specified
  // side-effects of examining those arguments are unobservable.
  const bool can_cache =
      (IsString(*locales) || IsUndefined(*locales, isolate)) &&
      IsUndefined(*options, isolate);
  // We may be able to take the fast path, depending on the `locales` and
  // `options` arguments.
  const CompareStringsOptions compare_strings_options =
      CompareStringsOptionsFor(isolate, locales, options);
  if (can_cache) {
    // Both locales and options are undefined, check the cache.
    icu::Collator* cached_icu_collator =
        static_cast<icu::Collator*>(isolate->get_cached_icu_object(
            Isolate::ICUObjectCacheType::kDefaultCollator, locales));
    // We may use the cached icu::Collator for a fast path.
    if (cached_icu_collator != nullptr) {
      return Intl::CompareStrings(isolate, *cached_icu_collator, string1,
                                  string2, compare_strings_options);
    }
  }

  Handle<JSFunction> constructor = Handle<JSFunction>(
      Cast<JSFunction>(
          isolate->context()->native_context()->intl_collator_function()),
      isolate);

  Handle<JSCollator> collator;
  MaybeHandle<JSCollator> maybe_collator =
      New<JSCollator>(isolate, constructor, locales, options, method_name);
  if (!maybe_collator.ToHandle(&collator)) return {};
  if (can_cache) {
    isolate->set_icu_object_in_cache(
        Isolate::ICUObjectCacheType::kDefaultCollator, locales,
        std::static_pointer_cast<icu::UMemory>(
            collator->icu_collator()->get()));
  }
  icu::Collator* icu_collator = collator->icu_collator()->raw();
  return Intl::CompareStrings(isolate, *icu_collator, string1, string2,
                              compare_strings_options);
}

namespace {

// Weights for the Unicode Collation Algorithm for charcodes [0x00,0x7F].
// https://unicode.org/reports/tr10/.
//
// Generated from:
//
// $ wget http://www.unicode.org/Public/UCA/latest/allkeys.txt
// $ cat ~/allkeys.txt | grep '^00[0-7].  ;' | sort | sed 's/[*.]/ /g' |\
//   sed 's/.*\[ \(.*\)\].*/\1/' | python ~/gen_weights.py
//
// Where gen_weights.py does an ordinal rank s.t. weights fit in a uint8_t:
//
//   import sys
//
//   def to_ordinal(ws):
//       weight_map = {}
//       weights_uniq_sorted = sorted(set(ws))
//       for i in range(0, len(weights_uniq_sorted)):
//           weight_map[weights_uniq_sorted[i]] = i
//       return [weight_map[x] for x in ws]
//
//   def print_weight_list(array_name, ws):
//       print("constexpr uint8_t %s[256] = {" % array_name, end = "")
//       i = 0
//       for w in ws:
//           if (i % 16) == 0:
//               print("\n  ", end = "")
//           print("%3d," % w, end = "")
//           i += 1
//       print("\n};\n")
//
//   if __name__ == "__main__":
//       l1s = []
//       l3s = []
//       for line in sys.stdin:
//           weights = line.split()
//           l1s.append(int(weights[0], 16))
//           l3s.append(int(weights[2], 16))
//       print_weight_list("kCollationWeightsL1", to_ordinal(l1s))
//       print_weight_list("kCollationWeightsL3", to_ordinal(l3s))

// clang-format off
constexpr uint8_t kCollationWeightsL1[256] = {
    0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    6, 12, 16, 28, 38, 29, 27, 15, 17, 18, 24, 32,  9,  8, 14, 25,
   39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 11, 10, 33, 34, 35, 13,
   23, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
   64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 19, 26, 20, 31,  7,
   30, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
   64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 21, 36, 22, 37,  0,
};
constexpr uint8_t kCollationWeightsL3[256] = {
    0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  1,  1,  1,  1,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
    2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
    1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,
};
constexpr int kCollationWeightsLength = arraysize(kCollationWeightsL1);
static_assert(kCollationWeightsLength == arraysize(kCollationWeightsL3));
// clang-format on

// Normalize a comparison delta (usually `lhs - rhs`) to UCollationResult
// values.
constexpr UCollationResult ToUCollationResult(int delta) {
  return delta < 0 ? UCollationResult::UCOL_LESS
                   : (delta > 0 ? UCollationResult::UCOL_GREATER
                                : UCollationResult::UCOL_EQUAL);
}

struct FastCompareStringsData {
  UCollationResult l1_result = UCollationResult::UCOL_EQUAL;
  UCollationResult l3_result = UCollationResult::UCOL_EQUAL;
  int processed_until = 0;
  int first_diff_at = 0;  // The first relevant diff (L1 if exists, else L3).
  bool has_diff = false;

  std::optional<UCollationResult> FastCompareFailed(
      int* processed_until_out) const {
    if (has_diff) {
      // Found some difference, continue there to ensure the generic algorithm
      // picks it up.
      *processed_until_out = first_diff_at;
    } else {
      // No difference found, reprocess the last processed character since it
      // may be followed by a unicode combining character (which alters it's
      // meaning).
      *processed_until_out = std::max(processed_until - 1, 0);
    }
    return {};
  }
};

template <class CharT>
constexpr bool CanFastCompare(CharT c) {
  return c < kCollationWeightsLength && kCollationWeightsL1[c] != 0;
}

template <class Char1T, class Char2T>
bool FastCompareFlatString(const Char1T* lhs, const Char2T* rhs, int length,
                           FastCompareStringsData* d) {
  for (int i = 0; i < length; i++) {
    const Char1T l = lhs[i];
    const Char2T r = rhs[i];
    if (!CanFastCompare(l) || !CanFastCompare(r)) {
      d->processed_until = i;
      return false;
    }
    UCollationResult l1_result =
        ToUCollationResult(kCollationWeightsL1[l] - kCollationWeightsL1[r]);
    if (l1_result != UCollationResult::UCOL_EQUAL) {
      d->has_diff = true;
      d->first_diff_at = i;
      d->processed_until = i;
      d->l1_result = l1_result;
      return true;
    }
    if (l != r && d->l3_result == UCollationResult::UCOL_EQUAL) {
      // Collapse the two-pass algorithm into one: if we find a difference in
      // L1 weights, that is our result. If not, use the first L3 weight
      // difference.
      UCollationResult l3_result =
          ToUCollationResult(kCollationWeightsL3[l] - kCollationWeightsL3[r]);
      d->l3_result = l3_result;
      if (!d->has_diff) {
        d->has_diff = true;
        d->first_diff_at = i;
      }
    }
  }
  d->processed_until = length;
  return true;
}

bool FastCompareStringFlatContent(const String::FlatContent& lhs,
                                  const String::FlatContent& rhs, int length,
                                  FastCompareStringsData* d) {
  if (lhs.IsOneByte()) {
    base::Vector<const uint8_t> l = lhs.ToOneByteVector();
    if (rhs.IsOneByte()) {
      base::Vector<const uint8_t> r = rhs.ToOneByteVector();
      return FastCompareFlatString(l.data(), r.data(), length, d);
    } else {
      base::Vector<const uint16_t> r = rhs.ToUC16Vector();
      return FastCompareFlatString(l.data(), r.data(), length, d);
    }
  } else {
    base::Vector<const uint16_t> l = lhs.ToUC16Vector();
    if (rhs.IsOneByte()) {
      base::Vector<const uint8_t> r = rhs.ToOneByteVector();
      return FastCompareFlatString(l.data(), r.data(), length, d);
    } else {
      base::Vector<const uint16_t> r = rhs.ToUC16Vector();
      return FastCompareFlatString(l.data(), r.data(), length, d);
    }
  }
  UNREACHABLE();
}

bool CharIsAsciiOrOutOfBounds(const String::FlatContent& string,
                              int string_length, int index) {
  DCHECK_EQ(string.length(), string_length);
  return index >= string_length || isascii(string.Get(index));
}

bool CharCanFastCompareOrOutOfBounds(const String::FlatContent& string,
                                     int string_length, int index) {
  DCHECK_EQ(string.length(), string_length);
  return index >= string_length || CanFastCompare(string.Get(index));
}

#ifdef DEBUG
bool USetContainsAllAsciiItem(USet* set) {
  static constexpr int kBufferSize = 64;
  UChar buffer[kBufferSize];

  const int length = uset_getItemCount(set);
  for (int i = 0; i < length; i++) {
    UChar32 start, end;
    UErrorCode status = U_ZERO_ERROR;
    const int item_length =
        uset_getItem(set, i, &start, &end, buffer, kBufferSize, &status);
    CHECK(U_SUCCESS(status));
    DCHECK_GE(item_length, 0);

    if (item_length == 0) {
      // Empty string or a range.
      if (isascii(start)) return true;
    } else {
      // A non-empty string.
      bool all_ascii = true;
      for (int j = 0; j < item_length; j++) {
        if (!isascii(buffer[j])) {
          all_ascii = false;
          break;
        }
      }

      if (all_ascii) return true;
    }
  }

  return false;
}

bool CollatorAllowsFastComparison(const icu::Collator& icu_collator) {
  UErrorCode status = U_ZERO_ERROR;

  icu::Locale icu_locale(icu_collator.getLocale(ULOC_VALID_LOCALE, status));
  DCHECK(U_SUCCESS(status));

  static constexpr int kBufferSize = 64;
  char buffer[kBufferSize];
  const int collation_keyword_length =
      icu_locale.getKeywordValue("collation", buffer, kBufferSize, status);
  DCHECK(U_SUCCESS(status));
  if (collation_keyword_length != 0) return false;

  // These attributes must be set to the expected value for fast comparisons.
  static constexpr struct {
    UColAttribute attribute;
    UColAttributeValue legal_value;
  } kAttributeChecks[] = {
      {UCOL_ALTERNATE_HANDLING, UCOL_NON_IGNORABLE},
      {UCOL_CASE_FIRST, UCOL_OFF},
      {UCOL_CASE_LEVEL, UCOL_OFF},
      {UCOL_FRENCH_COLLATION, UCOL_OFF},
      {UCOL_NUMERIC_COLLATION, UCOL_OFF},
      {UCOL_STRENGTH, UCOL_TERTIARY},
  };

  for (const auto& check : kAttributeChecks) {
    if (icu_collator.getAttribute(check.attribute, status) !=
        check.legal_value) {
      return false;
    }
    DCHECK(U_SUCCESS(status));
  }

  // No reordering codes are allowed.
  int num_reorder_codes =
      ucol_getReorderCodes(icu_collator.toUCollator(), nullptr, 0, &status);
  if (num_reorder_codes != 0) return false;
  DCHECK(U_SUCCESS(status));  // Must check *after* num_reorder_codes != 0.

  // No tailored rules are allowed.
  int32_t rules_length = 0;
  ucol_getRules(icu_collator.toUCollator(), &rules_length);
  if (rules_length != 0) return false;

  USet* tailored_set = ucol_getTailoredSet(icu_collator.toUCollator(), &status);
  DCHECK(U_SUCCESS(status));
  if (USetContainsAllAsciiItem(tailored_set)) return false;
  uset_close(tailored_set);

  // No ASCII contractions or expansions are allowed.
  USet* contractions = uset_openEmpty();
  USet* expansions = uset_openEmpty();
  ucol_getContractionsAndExpansions(icu_collator.toUCollator(), contractions,
                                    expansions, true, &status);
  if (USetContainsAllAsciiItem(contractions)) return false;
  if (USetContainsAllAsciiItem(expansions)) return false;
  DCHECK(U_SUCCESS(status));
  uset_close(contractions);
  uset_close(expansions);

  return true;
}
#endif  // DEBUG

// Fast comparison is implemented for charcodes for which the L1 collation
// weight (see kCollactionWeightsL1 above) is not 0.
//
// Note it's possible to partially process strings as long as their leading
// characters all satisfy the above criteria. In that case, and if the L3
// result is EQUAL, we set `processed_until_out` to the first non-processed
// index - future processing can begin at that offset.
//
// This fast path looks somewhat complex; mostly because it combines multiple
// passes into one. The pseudo-code for simplified multi-pass algorithm is:
//
// {
//   // We can only fast-compare a certain subset of the ASCII range.
//   // Additionally, unicode characters can change the meaning of preceding
//   // characters, for example: "o\u0308" is treated like "ö".
//   //
//   // Note, in the actual single-pass algorithm below, we tolerate non-ASCII
//   // contents outside the relevant range.
//   for (int i = 0; i < string1.length; i++) {
//     if (!CanFastCompare(string1[i])) return {};
//   }
//   for (int i = 0; i < string2.length; i++) {
//     if (!CanFastCompare(string2[i])) return {};
//   }
//
//   // Apply L1 weights.
//   for (int i = 0; i < common_length; i++) {
//     Char1T c1 = string1[i];
//     Char2T c2 = string2[i];
//     if (L1Weight[c1] != L1Weight[c2]) {
//       return L1Weight[c1] - L1Weight[c2];
//     }
//   }
//
//   // Strings are L1-equal up to the common length; if lengths differ, the
//   // longer string is treated as 'greater'.
//   if (string1.length != string2.length) string1.length - string2.length;
//
//   // Apply L3 weights.
//   for (int i = 0; i < common_length; i++) {
//     Char1T c1 = string1[i];
//     Char2T c2 = string2[i];
//     if (L3Weight[c1] != L3Weight[c2]) {
//       return L3Weight[c1] - L3Weight[c2];
//     }
//   }
//
//   return UCOL_EQUAL;
// }
std::optional<UCollationResult> TryFastCompareStrings(
    Isolate* isolate, const icu::Collator& icu_collator,
    DirectHandle<String> string1, DirectHandle<String> string2,
    int* processed_until_out) {
  // TODO(jgruber): We could avoid the flattening (done by the caller) as well
  // by implementing comparison through string iteration. This has visible
  // performance benefits (e.g. 7% on CDJS) but complicates the code. Consider
  // doing this in the future.
  DCHECK(string1->IsFlat());
  DCHECK(string2->IsFlat());

  *processed_until_out = 0;

#ifdef DEBUG
  // Checked by the caller, see CompareStringsOptionsFor.
  SLOW_DCHECK(CollatorAllowsFastComparison(icu_collator));
  USE(CollatorAllowsFastComparison);
#endif  // DEBUG

  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(*string1));
  DCHECK(!SharedStringAccessGuardIfNeeded::IsNeeded(*string2));

  const int length1 = string1->length();
  const int length2 = string2->length();
  int common_length = std::min(length1, length2);

  FastCompareStringsData d;
  DisallowGarbageCollection no_gc;
  const String::FlatContent& flat1 = string1->GetFlatContent(no_gc);
  const String::FlatContent& flat2 = string2->GetFlatContent(no_gc);
  if (!FastCompareStringFlatContent(flat1, flat2, common_length, &d)) {
    DCHECK_EQ(d.l1_result, UCollationResult::UCOL_EQUAL);
    return d.FastCompareFailed(processed_until_out);
  }

  // The result is only valid if the last processed character is not followed
  // by a unicode combining character (we are overly strict and restrict to
  // ASCII).
  if (!CharIsAsciiOrOutOfBounds(flat1, length1, d.processed_until + 1) ||
      !CharIsAsciiOrOutOfBounds(flat2, length2, d.processed_until + 1)) {
    return d.FastCompareFailed(processed_until_out);
  }

  if (d.l1_result != UCollationResult::UCOL_EQUAL) {
    return d.l1_result;
  }

  // Strings are L1-equal up to their common length, length differences win.
  UCollationResult length_result = ToUCollationResult(length1 - length2);
  if (length_result != UCollationResult::UCOL_EQUAL) {
    // Strings of different lengths may still compare as equal if the longer
    // string has a fully ignored suffix, e.g. "a" vs. "a\u{1}".
    if (!CharCanFastCompareOrOutOfBounds(flat1, length1, common_length) ||
        !CharCanFastCompareOrOutOfBounds(flat2, length2, common_length)) {
      return d.FastCompareFailed(processed_until_out);
    }
    return length_result;
  }

  // L1-equal and same length, the L3 result wins.
  return d.l3_result;
}

}  // namespace

// static
const uint8_t* Intl::AsciiCollationWeightsL1() {
  return &kCollationWeightsL1[0];
}

// static
const uint8_t* Intl::AsciiCollationWeightsL3() {
  return &kCollationWeightsL3[0];
}

// static
const int Intl::kAsciiCollationWeightsLength = kCollationWeightsLength;

// ecma402/#sec-collator-comparestrings
int Intl::CompareStrings(Isolate* isolate, const icu::Collator& icu_collator,
                         Handle<String> string1, Handle<String> string2,
                         CompareStringsOptions compare_strings_options) {
  // Early return for identical strings.
  if (string1.is_identical_to(string2)) {
    return UCollationResult::UCOL_EQUAL;
  }

  // We cannot return early for 0-length strings because of Unicode
  // ignorable characters. See also crbug.com/1347690.

  string1 = String::Flatten(isolate, string1);
  string2 = String::Flatten(isolate, string2);

  int processed_until = 0;
  if (compare_strings_options == CompareStringsOptions::kTryFastPath) {
    std::optional<int> maybe_result = TryFastCompareStrings(
        isolate, icu_collator, string1, string2, &processed_until);
    if (maybe_result.has_value()) return maybe_result.value();
  }

  UCollationResult result;
  UErrorCode status = U_ZERO_ERROR;
  icu::StringPiece string_piece1 =
      ToICUStringPiece(isolate, string1, processed_until);
  if (!string_piece1.empty()) {
    icu::StringPiece string_piece2 =
        ToICUStringPiece(isolate, string2, processed_until);
    if (!string_piece2.empty()) {
      result = icu_collator.compareUTF8(string_piece1, string_piece2, status);
      DCHECK(U_SUCCESS(status));
      return result;
    }
  }

  icu::UnicodeString string_val1 =
      Intl::ToICUUnicodeString(isolate, string1, processed_until);
  icu::UnicodeString string_val2 =
      Intl::ToICUUnicodeString(isolate, string2, processed_until);
  result = icu_collator.compare(string_val1, string_val2, status);
  DCHECK(U_SUCCESS(status));
  return result;
}

// ecma402/#sup-properties-of-the-number-prototype-object
MaybeHandle<String> Intl::NumberToLocaleString(Isolate* isolate,
                                               Handle<Object> num,
                                               Handle<Object> locales,
                                               Handle<Object> options,
                                               const char* method_name) {
  Handle<Object> numeric_obj;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, numeric_obj,
                             Object::ToNumeric(isolate, num));

  // We only cache the instance when locales is a string/undefined and
  // options is undefined, as that is the only case when the specified
  // side-effects of examining those arguments are unobservable.
  bool can_cache = (IsString(*locales) || IsUndefined(*locales, isolate)) &&
                   IsUndefined(*options, isolate);
  if (can_cache) {
    icu::number::LocalizedNumberFormatter* cached_number_format =
        static_cast<icu::number::LocalizedNumberFormatter*>(
            isolate->get_cached_icu_object(
                Isolate::ICUObjectCacheType::kDefaultNumberFormat, locales));
    // We may use the cached icu::NumberFormat for a fast path.
    if (cached_number_format != nullptr) {
      return JSNumberFormat::FormatNumeric(isolate, *cached_number_format,
                                           numeric_obj);
    }
  }

  Handle<JSFunction> constructor = Handle<JSFunction>(
      Cast<JSFunction>(
          isolate->context()->native_context()->intl_number_format_function()),
      isolate);
  Handle<JSNumberFormat> number_format;
  // 2. Let numberFormat be ? Construct(%NumberFormat%, « locales, options »).
  StackLimitCheck stack_check(isolate);
  // New<JSNumberFormat>() requires a lot of stack space.
  const int kStackSpaceRequiredForNewJSNumberFormat = 16 * KB;
  if (stack_check.JsHasOverflowed(kStackSpaceRequiredForNewJSNumberFormat)) {
    isolate->StackOverflow();
    return MaybeHandle<String>();
  }
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, number_format,
      New<JSNumberFormat>(isolate, constructor, locales, options, method_name));

  if (can_cache) {
    isolate->set_icu_object_in_cache(
        Isolate::ICUObjectCacheType::kDefaultNumberFormat, locales,
        std::static_pointer_cast<icu::UMemory>(
            number_format->icu_number_formatter()->get()));
  }

  // Return FormatNumber(numberFormat, x).
  icu::number::LocalizedNumberFormatter* icu_number_format =
      number_format->icu_number_formatter()->raw();
  return JSNumberFormat::FormatNumeric(isolate, *icu_number_format,
                                       numeric_obj);
}

namespace {

// 22. is in « 1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 2500,
// 5000 »
bool IsValidRoundingIncrement(int value) {
  switch (value) {
    case 1:
    case 2:
    case 5:
    case 10:
    case 20:
    case 25:
    case 50:
    case 100:
    case 200:
    case 250:
    case 500:
    case 1000:
    case 2000:
    case 2500:
    case 5000:
      return true;
    default:
      return false;
  }
}

}  // namespace

Maybe<Intl::NumberFormatDigitOptions> Intl::SetNumberFormatDigitOptions(
    Isolate* isolate, Handle<JSReceiver> options, int mnfd_default,
    int mxfd_default, bool notation_is_compact, const char* service) {
  Factory* factory = isolate->factory();
  Intl::NumberFormatDigitOptions digit_options;

  // 1. Let mnid be ? GetNumberOption(options, "minimumIntegerDigits,", 1, 21,
  // 1).
  int mnid = 1;
  if (!GetNumberOption(isolate, options, factory->minimumIntegerDigits_string(),
                       1, 21, 1)
           .To(&mnid)) {
    return Nothing<NumberFormatDigitOptions>();
  }

  // 2. Let mnfd be ? Get(options, "minimumFractionDigits").
  Handle<Object> mnfd_obj;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, mnfd_obj,
      JSReceiver::GetProperty(isolate, options,
                              factory->minimumFractionDigits_string()),
      Nothing<NumberFormatDigitOptions>());

  // 3. Let mxfd be ? Get(options, "maximumFractionDigits").
  Handle<Object> mxfd_obj;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, mxfd_obj,
      JSReceiver::GetProperty(isolate, options,
                              factory->maximumFractionDigits_string()),
      Nothing<NumberFormatDigitOptions>());

  // 4.  Let mnsd be ? Get(options, "minimumSignificantDigits").
  Handle<Object> mnsd_obj;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, mnsd_obj,
      JSReceiver::GetProperty(isolate, options,
                              factory->minimumSignificantDigits_string()),
      Nothing<NumberFormatDigitOptions>());

  // 5. Let mxsd be ? Get(options, "maximumSignificantDigits").
  Handle<Object> mxsd_obj;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, mxsd_obj,
      JSReceiver::GetProperty(isolate, options,
                              factory->maximumSignificantDigits_string()),
      Nothing<NumberFormatDigitOptions>());

  digit_options.rounding_priority = RoundingPriority::kAuto;
  digit_options.minimum_significant_digits = 0;
  digit_options.maximum_significant_digits = 0;

  // 6. Set intlObj.[[MinimumIntegerDigits]] to mnid.
  digit_options.minimum_integer_digits = mnid;

  // 7. Let roundingIncrement be ? GetNumberOption(options, "roundingIncrement",
  // 1, 5000, 1).
  Maybe<int> maybe_rounding_increment = GetNumberOption(
      isolate, options, factory->roundingIncrement_string(), 1, 5000, 1);
  if (!maybe_rounding_increment.To(&digit_options.rounding_increment)) {
    return Nothing<NumberFormatDigitOptions>();
  }
  // 8. If roundingIncrement is not in « 1, 2, 5, 10, 20, 25, 50, 100, 200, 250,
  // 500, 1000, 2000, 2500, 5000 », throw a RangeError exception.
  if (!IsValidRoundingIncrement(digit_options.rounding_increment)) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kPropertyValueOutOfRange,
                      factory->roundingIncrement_string()),
        Nothing<NumberFormatDigitOptions>());
  }

  // 9. Let roundingMode be ? GetOption(options, "roundingMode", string, «
  // "ceil", "floor", "expand", "trunc", "halfCeil", "halfFloor", "halfExpand",
  // "halfTrunc", "halfEven" », "halfExpand").
  Maybe<RoundingMode> maybe_rounding_mode = GetStringOption<RoundingMode>(
      isolate, options, "roundingMode", service,
      {"ceil", "floor", "expand", "trunc", "halfCeil", "halfFloor",
       "halfExpand", "halfTrunc", "halfEven"},
      {RoundingMode::kCeil, RoundingMode::kFloor, RoundingMode::kExpand,
       RoundingMode::kTrunc, RoundingMode::kHalfCeil, RoundingMode::kHalfFloor,
       RoundingMode::kHalfExpand, RoundingMode::kHalfTrunc,
       RoundingMode::kHalfEven},
      RoundingMode::kHalfExpand);
  MAYBE_RETURN(maybe_rounding_mode, Nothing<NumberFormatDigitOptions>());
  digit_options.rounding_mode = maybe_rounding_mode.FromJust();

  // 10. Let roundingPriority be ? GetOption(options, "roundingPriority",
  // "string", « "auto", "morePrecision", "lessPrecision" », "auto").

  Maybe<RoundingPriority> maybe_rounding_priority =
      GetStringOption<RoundingPriority>(
          isolate, options, "roundingPriority", service,
          {"auto", "morePrecision", "lessPrecision"},
          {RoundingPriority::kAuto, RoundingPriority::kMorePrecision,
           RoundingPriority::kLessPrecision},
          RoundingPriority::kAuto);
  MAYBE_RETURN(maybe_rounding_priority, Nothing<NumberFormatDigitOptions>());
  digit_options.rounding_priority = maybe_rounding_priority.FromJust();

  // 11. Let trailingZeroDisplay be ? GetOption(options, "trailingZeroDisplay",
  // string, « "auto", "stripIfInteger" », "auto").
  Maybe<TrailingZeroDisplay> maybe_trailing_zero_display =
      GetStringOption<TrailingZeroDisplay>(
          isolate, options, "trailingZeroDisplay", service,
          {"auto", "stripIfInteger"},
          {TrailingZeroDisplay::kAuto, TrailingZeroDisplay::kStripIfInteger},
          TrailingZeroDisplay::kAuto);
  MAYBE_RETURN(maybe_trailing_zero_display,
               Nothing<NumberFormatDigitOptions>());
  digit_options.trailing_zero_display = maybe_trailing_zero_display.FromJust();

  // 12. NOTE: All fields required by SetNumberFormatDigitOptions have now been
  // read from options. The remainder of this AO interprets the options and may
  // throw exceptions.

  // 17. If mnsd is not undefined or mxsd is not undefined, then
  // a. Set hasSd to true.
  // 18. Else,
  // a. Set hasSd to false.
  bool has_sd =
      (!IsUndefined(*mnsd_obj, isolate)) || (!IsUndefined(*mxsd_obj, isolate));

  // 19. If mnfd is not undefined or mxfd is not undefined, then
  // a. Set hasFd to true.
  // 22. Else,
  // a. Set hasFd to false.
  bool has_fd =
      (!IsUndefined(*mnfd_obj, isolate)) || (!IsUndefined(*mxfd_obj, isolate));

  // 21. Let needSd be true.
  bool need_sd = true;
  // 22. Let needFd be
"""


```