Response:
The user wants a summary of the functionalities present in the provided C++ code snippet from `v8/src/objects/intl-objects.cc`. I need to go through each function and class, understand its purpose, and then provide a high-level overview.

Here's a breakdown of the thinking process:

1. **Identify the core purpose of the file:** The file name suggests it's related to the implementation of ECMAScript Internationalization API (Intl) objects within the V8 engine.

2. **Analyze each function/class:**  Go through each function and class declaration and try to understand its role based on its name and parameters. Look for keywords related to internationalization like "locale," "timezone," "normalization," "collation," "calendar," etc.

3. **Group related functionalities:**  Notice that several functions deal with locales (resolution, matching), others with text manipulation (normalization, break iteration), and some with time zones (caching, offset calculations).

4. **Check for Torque usage:** The prompt explicitly asks about `.tq` files. This file is `.cc`, so it's standard C++.

5. **Identify JavaScript connections:**  Determine if the C++ code implements functionality exposed to JavaScript. For example, `Intl.Collator`, `Intl.DateTimeFormat`, `Intl.NumberFormat`, `String.prototype.normalize`, and the Temporal API are key candidates.

6. **Provide JavaScript examples:**  For the identified JavaScript connections, create simple code snippets demonstrating the usage of the corresponding functionality.

7. **Look for logic and potential inputs/outputs:**  For functions like `ResolveLocale` or `Normalize`, try to envision simple input scenarios and the expected output. This helps in understanding the transformation performed by the function.

8. **Identify common programming errors:**  Think about how a JavaScript developer might misuse the Intl API or related functionalities. Incorrect locale codes, invalid normalization forms, or improper handling of time zones are common pitfalls.

9. **Address the "归纳一下它的功能" (summarize its functions) requirement:**  Based on the analysis of individual functions and classes, create a concise summary highlighting the main areas covered by the code.

10. **Structure the response:**  Organize the information clearly with headings for each aspect (functionalities, JavaScript examples, logic, errors, summary).

**Detailed analysis of specific functions (internal thought process):**

* **`Intl::ResolveLocale`:** The name clearly indicates locale resolution. It takes available and requested locales, a matching algorithm, and extension keys. It returns a resolved locale. The JavaScript connection is obviously any Intl constructor that takes a `locales` argument.

* **`Intl::SetTextToBreakIterator`:**  Involves setting text for a break iterator, which is used for tasks like word segmentation. Connects to `Intl.Segmenter`.

* **`Intl::Normalize`:** Directly implements `String.prototype.normalize`. The code handles different normalization forms (NFC, NFD, NFKC, NFKD).

* **`ICUTimezoneCache`:** This is a custom timezone cache using ICU. It has methods for getting local timezone, daylight savings offset, and local time offset. It's used internally by V8's date/time handling.

* **`Intl::GetLocaleMatcher`, `Intl::GetNumberingSystem`:** These are helper functions to extract options from JavaScript `options` objects passed to Intl constructors.

* **`Intl::GetAvailableLocales`, `Intl::GetAvailableLocalesForDateFormat`:**  Provide sets of available locales, potentially filtered by specific features.

* **`Intl::NumberFieldToType`:**  Used to map number formatting fields (integer, fraction, currency, etc.) to string representations. This is for the `Intl.NumberFormat` parts API.

* **`Intl::FormattedToString`:** Converts the output of ICU formatters to JavaScript strings.

* **`Intl::ToJSArray`:**  A utility to convert ICU string enumerations to JavaScript arrays, often used for getting lists of available values.

* **`Intl::SanctionedSimpleUnits`:**  Defines a set of valid units for `Intl.NumberFormat` with unit formatting.

* **Timezone related functions (`CanonicalizeTimeZoneName`, `IsValidTimeZoneName`, `TimeZoneIdFromIndex`, `GetTimeZoneIndex`, `GetTimeZoneOffsetTransitionNanoseconds`, `GetTimeZonePossibleOffsetNanoseconds`, `GetTimeZoneOffsetNanoseconds`):** These are related to handling time zones, especially for the Temporal API. They involve converting between timezone names and indices, checking validity, and calculating offset transitions.

* **`Intl::FormatRangeSourceTracker` and related:**  Support the `formatRange` method in `Intl.DateTimeFormat`.

By systematically analyzing each part and considering the broader context of the Intl API, I can construct a comprehensive answer to the user's request.
这是对 V8 源代码文件 `v8/src/objects/intl-objects.cc` 中代码的分析。根据您提供的代码片段，该文件主要负责实现与 ECMAScript 国际化 API (ECMA-402) 相关的底层功能。

**功能归纳:**

`v8/src/objects/intl-objects.cc` 文件包含了 V8 引擎中用于支持 JavaScript 国际化功能的 C++ 代码。其主要功能可以归纳为以下几点：

1. **本地化协商 (Locale Resolution):**
   - `Intl::ResolveLocale`:  实现了 ECMA-402 规范中定义的本地化协商算法。它接收一组可用的本地化标识符、请求的本地化标识符以及匹配器选项，并返回一个解析后的最佳匹配本地化标识符及其扩展信息。

2. **文本处理:**
   - `Intl::SetTextToBreakIterator`: 用于为 ICU 的 `BreakIterator` 对象设置文本，这在文本分段（例如，单词、句子、行）时使用。
   - `Intl::Normalize`:  实现了 `String.prototype.normalize()` 方法，用于将字符串规范化为指定的 Unicode 规范化形式（NFC, NFD, NFKC, NFKD）。

3. **时区处理:**
   - `ICUTimezoneCache`:  实现了一个基于 ICU 的时区缓存，用于高效地获取本地时区信息、夏令时偏移和本地时间偏移。
   - `Intl::CreateTimeZoneCache`:  根据配置选择创建 ICU 时区缓存或操作系统提供的时区缓存。
   - `Intl::CanonicalizeTimeZoneName`: 将给定的时区标识符规范化为标准形式。
   - `Intl::IsValidTimeZoneName`: 检查给定的时区标识符是否有效。
   - `Intl::TimeZoneIdFromIndex`, `Intl::GetTimeZoneIndex`:  用于在时区标识符和内部索引之间进行转换，主要用于支持 Temporal API。
   - `Intl::GetTimeZoneOffsetTransitionNanoseconds`, `Intl::GetTimeZonePossibleOffsetNanoseconds`, `Intl::GetTimeZoneOffsetNanoseconds`:  用于获取指定时间点的时区偏移信息，包括可能的偏移量和转换点，精度为纳秒，主要用于支持 Temporal API。
   - `Intl::DefaultTimeZone`: 获取系统的默认时区。

4. **国际化选项处理:**
   - `Intl::GetLocaleMatcher`:  从选项对象中获取 `localeMatcher` 属性的值。
   - `Intl::GetNumberingSystem`: 从选项对象中获取 `numberingSystem` 属性的值，并验证其格式。

5. **获取可用本地化信息:**
   - `Intl::GetAvailableLocales`:  获取所有可用的本地化标识符。
   - `Intl::GetAvailableLocalesForDateFormat`: 获取用于日期/时间格式化的可用本地化标识符。

6. **数字格式化辅助:**
   - `Intl::NumberFieldToType`:  将 ICU 数字格式化中的字段类型映射到 JavaScript 中使用的字符串类型（例如，"integer", "fraction", "currency"）。
   - `Intl::FormattedToString`:  将 ICU 的 `FormattedValue` 对象转换为 JavaScript 字符串。

7. **通用工具函数:**
   - `Intl::ToJSArray`:  将 ICU 的字符串枚举转换为 JavaScript 数组。

8. **其他国际化相关支持:**
   - `Intl::SanctionedSimpleUnits`:  定义了 `Intl.NumberFormat` 中允许使用的标准单位。
   - `Intl::RemoveCollation`:  用于判断是否应该移除特定的排序规则。
   - `Intl::FormatRangeSourceTracker`:  用于跟踪 `Intl.DateTimeFormat.formatRange` 方法中日期范围的来源部分。

**关于 `.tq` 文件:**

根据您提供的描述，如果 `v8/src/objects/intl-objects.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种 V8 自研的类型化的中间语言，用于生成高效的 C++ 代码。然而，**您提供的文件是 `.cc` 结尾，所以它是一个标准的 C++ 源代码文件，而不是 Torque 文件。**

**与 JavaScript 功能的关系及示例:**

`v8/src/objects/intl-objects.cc` 中的代码直接支持了 JavaScript 中 `Intl` 对象的功能，例如 `Intl.Collator`, `Intl.NumberFormat`, `Intl.DateTimeFormat`, `Intl.PluralRules`, `Intl.RelativeTimeFormat`, `Intl.ListFormat`, `Intl.Segmenter` 以及 `String.prototype.normalize()` 等方法，并且为新的 Temporal API 提供了底层的时区支持。

以下是一些 JavaScript 示例，展示了与该文件中 C++ 代码相关的特性：

```javascript
// Intl.Collator (与本地化协商和排序相关)
const collator = new Intl.Collator('en-US', { sensitivity: 'accent' });
const result = collator.compare('apple', 'ápple');
console.log(result);

// Intl.NumberFormat (与数字格式化相关)
const numberFormat = new Intl.NumberFormat('de-DE', { style: 'currency', currency: 'EUR' });
const formattedNumber = numberFormat.format(1234.56);
console.log(formattedNumber);

// Intl.DateTimeFormat (与日期和时间格式化相关)
const dateTimeFormat = new Intl.DateTimeFormat('ja-JP', { year: 'numeric', month: 'long', day: 'numeric' });
const formattedDate = dateTimeFormat.format(new Date());
console.log(formattedDate);

// String.prototype.normalize (与文本规范化相关)
const str1 = '\u00F1'; // ñ (单个组合字符)
const str2 = 'n\u0303'; // n + ̃ (组合字符)
console.log(str1.normalize('NFC') === str2.normalize('NFC')); // true

// Intl.Segmenter (与文本分段相关)
const segmenter = new Intl.Segmenter('en', { granularity: 'word' });
const segments = segmenter.segment('This is a sentence.');
for (const segment of segments) {
  console.log(segment.segment);
}

// Temporal API (与时区处理相关，需要启用实验性功能)
// 注意：Temporal API 仍在发展中，以下代码可能需要特定版本的 V8 或 Node.js
// const now = Temporal.Now.zonedDateTimeISO();
// console.log(now.toLocaleString());
```

**代码逻辑推理和假设输入/输出:**

以 `Intl::ResolveLocale` 函数为例：

**假设输入:**

* `available_locales`: `{"en-US", "de-DE", "fr-FR"}`
* `requested_locales`: `{"de", "en-GB"}`
* `matcher`: `Intl::MatcherOption::kBestFit`
* `relevant_extension_keys`: `{}`

**可能的输出:**

* `canonicalized_locale`: `"de-DE"` (因为 "de" 是一个通用的德语语言代码，而 "de-DE" 是一个更具体的德国德语，在可用 locale 中更匹配)
* `icu_locale`: 一个代表 "de-DE" 的 `icu::Locale` 对象
* `extensions`: 一个空的 `std::map`，因为 `relevant_extension_keys` 是空的。

**用户常见的编程错误:**

1. **使用无效的本地化标识符:**
   ```javascript
   // 错误：'xx-YY' 不是有效的本地化标识符
   const numberFormat = new Intl.NumberFormat('xx-YY');
   ```
   这可能导致运行时错误或回退到默认的本地化设置。

2. **不理解 `localeMatcher` 的作用:**
   ```javascript
   // 可能的误解：认为会精确匹配 'en-GB'，但如果不可用，可能回退到 'en-US'
   const collator = new Intl.Collator(['en-GB'], { localeMatcher: 'lookup' });
   ```
   用户可能期望 `lookup` 匹配器总是返回完全匹配的 locale，但如果没有完全匹配，则会返回 `undefined`。

3. **错误地使用 `String.prototype.normalize` 的参数:**
   ```javascript
   const str = 'café';
   // 错误：normalization form 应该是 "NFC", "NFD", "NFKC", 或 "NFKD"
   const normalizedStr = str.normalize('INVALID_FORM');
   ```
   这会抛出一个 `RangeError`。

4. **混淆时区名称:**
   ```javascript
   // 错误：可能输入了非标准的时区名称
   const dateTimeFormat = new Intl.DateTimeFormat('en-US', { timeZone: 'America/LosAngeles' }); // 正确写法
   const dateTimeFormatWrong = new Intl.DateTimeFormat('en-US', { timeZone: 'Los Angeles Time' }); // 错误写法
   ```
   使用非标准的或拼写错误的 Time Zone Identifier 会导致错误。

**总结:**

`v8/src/objects/intl-objects.cc` 是 V8 引擎中实现 ECMAScript 国际化 API 核心功能的关键 C++ 文件。它处理本地化协商、文本规范化、时区管理、数字和日期/时间格式化等多种国际化相关的任务，为 JavaScript 开发者提供了强大的跨语言和文化支持。 虽然您提到以 `.tq` 结尾，但根据您提供的代码内容来看，它实际上是一个标准的 `.cc` 文件。

Prompt: 
```
这是目录为v8/src/objects/intl-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/intl-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
CU to do all the string manipulations that the spec
// peforms.
//
// The spec uses this function to normalize values for various
// relevant extension keys (such as disallowing "search" for
// collation). Instead of doing this here, we let the callers of
// this method perform such normalization.
//
// ecma402/#sec-resolvelocale
Maybe<Intl::ResolvedLocale> Intl::ResolveLocale(
    Isolate* isolate, const std::set<std::string>& available_locales,
    const std::vector<std::string>& requested_locales, MatcherOption matcher,
    const std::set<std::string>& relevant_extension_keys) {
  std::string locale;
  if (matcher == Intl::MatcherOption::kBestFit &&
      v8_flags.harmony_intl_best_fit_matcher) {
    locale = BestFitMatcher(isolate, available_locales, requested_locales);
  } else {
    locale = LookupMatcher(isolate, available_locales, requested_locales);
  }

  Maybe<icu::Locale> maybe_icu_locale = CreateICULocale(locale);
  MAYBE_RETURN(maybe_icu_locale, Nothing<Intl::ResolvedLocale>());
  icu::Locale icu_locale = maybe_icu_locale.FromJust();
  std::map<std::string, std::string> extensions =
      LookupAndValidateUnicodeExtensions(&icu_locale, relevant_extension_keys);

  std::string canonicalized_locale = Intl::ToLanguageTag(icu_locale).FromJust();

  // TODO(gsathya): Remove privateuse subtags from extensions.

  return Just(
      Intl::ResolvedLocale{canonicalized_locale, icu_locale, extensions});
}

Handle<Managed<icu::UnicodeString>> Intl::SetTextToBreakIterator(
    Isolate* isolate, Handle<String> text, icu::BreakIterator* break_iterator) {
  text = String::Flatten(isolate, text);
  std::shared_ptr<icu::UnicodeString> u_text{static_cast<icu::UnicodeString*>(
      Intl::ToICUUnicodeString(isolate, text).clone())};

  Handle<Managed<icu::UnicodeString>> new_u_text =
      Managed<icu::UnicodeString>::From(isolate, 0, u_text);

  break_iterator->setText(*u_text);
  return new_u_text;
}

// ecma262 #sec-string.prototype.normalize
MaybeHandle<String> Intl::Normalize(Isolate* isolate, Handle<String> string,
                                    Handle<Object> form_input) {
  const char* form_name;
  UNormalization2Mode form_mode;
  if (IsUndefined(*form_input, isolate)) {
    // default is FNC
    form_name = "nfc";
    form_mode = UNORM2_COMPOSE;
  } else {
    Handle<String> form;
    ASSIGN_RETURN_ON_EXCEPTION(isolate, form,
                               Object::ToString(isolate, form_input));

    if (String::Equals(isolate, form, isolate->factory()->NFC_string())) {
      form_name = "nfc";
      form_mode = UNORM2_COMPOSE;
    } else if (String::Equals(isolate, form,
                              isolate->factory()->NFD_string())) {
      form_name = "nfc";
      form_mode = UNORM2_DECOMPOSE;
    } else if (String::Equals(isolate, form,
                              isolate->factory()->NFKC_string())) {
      form_name = "nfkc";
      form_mode = UNORM2_COMPOSE;
    } else if (String::Equals(isolate, form,
                              isolate->factory()->NFKD_string())) {
      form_name = "nfkc";
      form_mode = UNORM2_DECOMPOSE;
    } else {
      Handle<String> valid_forms =
          isolate->factory()->NewStringFromStaticChars("NFC, NFD, NFKC, NFKD");
      THROW_NEW_ERROR(
          isolate,
          NewRangeError(MessageTemplate::kNormalizationForm, valid_forms));
    }
  }

  uint32_t length = string->length();
  string = String::Flatten(isolate, string);
  icu::UnicodeString result;
  std::unique_ptr<base::uc16[]> sap;
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString input = ToICUUnicodeString(isolate, string);
  // Getting a singleton. Should not free it.
  const icu::Normalizer2* normalizer =
      icu::Normalizer2::getInstance(nullptr, form_name, form_mode, status);
  DCHECK(U_SUCCESS(status));
  DCHECK_NOT_NULL(normalizer);
  uint32_t normalized_prefix_length =
      normalizer->spanQuickCheckYes(input, status);
  // Quick return if the input is already normalized.
  if (length == normalized_prefix_length) return string;
  icu::UnicodeString unnormalized =
      input.tempSubString(normalized_prefix_length);
  // Read-only alias of the normalized prefix.
  result.setTo(false, input.getBuffer(), normalized_prefix_length);
  // copy-on-write; normalize the suffix and append to |result|.
  normalizer->normalizeSecondAndAppend(result, unnormalized, status);

  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }

  return Intl::ToString(isolate, result);
}

// ICUTimezoneCache calls out to ICU for TimezoneCache
// functionality in a straightforward way.
class ICUTimezoneCache : public base::TimezoneCache {
 public:
  ICUTimezoneCache() : timezone_(nullptr) { Clear(TimeZoneDetection::kSkip); }

  ~ICUTimezoneCache() override { Clear(TimeZoneDetection::kSkip); }

  const char* LocalTimezone(double time_ms) override;

  double DaylightSavingsOffset(double time_ms) override;

  double LocalTimeOffset(double time_ms, bool is_utc) override;

  void Clear(TimeZoneDetection time_zone_detection) override;

 private:
  icu::TimeZone* GetTimeZone();

  bool GetOffsets(double time_ms, bool is_utc, int32_t* raw_offset,
                  int32_t* dst_offset);

  icu::TimeZone* timezone_;

  std::string timezone_name_;
  std::string dst_timezone_name_;
};

const char* ICUTimezoneCache::LocalTimezone(double time_ms) {
  bool is_dst = DaylightSavingsOffset(time_ms) != 0;
  std::string* name = is_dst ? &dst_timezone_name_ : &timezone_name_;
  if (name->empty()) {
    icu::UnicodeString result;
    GetTimeZone()->getDisplayName(is_dst, icu::TimeZone::LONG, result);
    result += '\0';

    icu::StringByteSink<std::string> byte_sink(name);
    result.toUTF8(byte_sink);
  }
  DCHECK(!name->empty());
  return name->c_str();
}

icu::TimeZone* ICUTimezoneCache::GetTimeZone() {
  if (timezone_ == nullptr) {
    timezone_ = icu::TimeZone::createDefault();
  }
  return timezone_;
}

bool ICUTimezoneCache::GetOffsets(double time_ms, bool is_utc,
                                  int32_t* raw_offset, int32_t* dst_offset) {
  UErrorCode status = U_ZERO_ERROR;
  if (is_utc) {
    GetTimeZone()->getOffset(time_ms, false, *raw_offset, *dst_offset, status);
  } else {
    // Note that casting TimeZone to BasicTimeZone is safe because we know that
    // icu::TimeZone used here is a BasicTimeZone.
    static_cast<const icu::BasicTimeZone*>(GetTimeZone())
        ->getOffsetFromLocal(time_ms, UCAL_TZ_LOCAL_FORMER,
                             UCAL_TZ_LOCAL_FORMER, *raw_offset, *dst_offset,
                             status);
  }

  return U_SUCCESS(status);
}

double ICUTimezoneCache::DaylightSavingsOffset(double time_ms) {
  int32_t raw_offset, dst_offset;
  if (!GetOffsets(time_ms, true, &raw_offset, &dst_offset)) return 0;
  return dst_offset;
}

double ICUTimezoneCache::LocalTimeOffset(double time_ms, bool is_utc) {
  int32_t raw_offset, dst_offset;
  if (!GetOffsets(time_ms, is_utc, &raw_offset, &dst_offset)) return 0;
  return raw_offset + dst_offset;
}

void ICUTimezoneCache::Clear(TimeZoneDetection time_zone_detection) {
  delete timezone_;
  timezone_ = nullptr;
  timezone_name_.clear();
  dst_timezone_name_.clear();
  if (time_zone_detection == TimeZoneDetection::kRedetect) {
    icu::TimeZone::adoptDefault(icu::TimeZone::detectHostTimeZone());
  }
}

base::TimezoneCache* Intl::CreateTimeZoneCache() {
  return v8_flags.icu_timezone_data ? new ICUTimezoneCache()
                                    : base::OS::CreateTimezoneCache();
}

Maybe<Intl::MatcherOption> Intl::GetLocaleMatcher(Isolate* isolate,
                                                  Handle<JSReceiver> options,
                                                  const char* method_name) {
  return GetStringOption<Intl::MatcherOption>(
      isolate, options, "localeMatcher", method_name, {"best fit", "lookup"},
      {Intl::MatcherOption::kBestFit, Intl::MatcherOption::kLookup},
      Intl::MatcherOption::kBestFit);
}

Maybe<bool> Intl::GetNumberingSystem(Isolate* isolate,
                                     Handle<JSReceiver> options,
                                     const char* method_name,
                                     std::unique_ptr<char[]>* result) {
  const std::vector<const char*> empty_values = {};
  Maybe<bool> maybe = GetStringOption(isolate, options, "numberingSystem",
                                      empty_values, method_name, result);
  MAYBE_RETURN(maybe, Nothing<bool>());
  if (maybe.FromJust() && *result != nullptr) {
    if (!IsWellFormedNumberingSystem(result->get())) {
      THROW_NEW_ERROR_RETURN_VALUE(
          isolate,
          NewRangeError(
              MessageTemplate::kInvalid,
              isolate->factory()->numberingSystem_string(),
              isolate->factory()->NewStringFromAsciiChecked(result->get())),
          Nothing<bool>());
    }
    return Just(true);
  }
  return Just(false);
}

const std::set<std::string>& Intl::GetAvailableLocales() {
  static base::LazyInstance<Intl::AvailableLocales<>>::type available_locales =
      LAZY_INSTANCE_INITIALIZER;
  return available_locales.Pointer()->Get();
}

namespace {

struct CheckCalendar {
  static const char* key() { return "calendar"; }
  static const char* path() { return nullptr; }
};

}  // namespace

const std::set<std::string>& Intl::GetAvailableLocalesForDateFormat() {
  static base::LazyInstance<Intl::AvailableLocales<CheckCalendar>>::type
      available_locales = LAZY_INSTANCE_INITIALIZER;
  return available_locales.Pointer()->Get();
}

constexpr uint16_t kInfinityChar = 0x221e;

Handle<String> Intl::NumberFieldToType(Isolate* isolate,
                                       const NumberFormatSpan& part,
                                       const icu::UnicodeString& text,
                                       bool is_nan) {
  switch (static_cast<UNumberFormatFields>(part.field_id)) {
    case UNUM_INTEGER_FIELD:
      if (is_nan) return isolate->factory()->nan_string();
      if (text.charAt(part.begin_pos) == kInfinityChar ||
          // en-US-POSIX output "INF" for Infinity
          (part.end_pos - part.begin_pos == 3 &&
           text.tempSubString(part.begin_pos, 3) == "INF")) {
        return isolate->factory()->infinity_string();
      }
      return isolate->factory()->integer_string();
    case UNUM_FRACTION_FIELD:
      return isolate->factory()->fraction_string();
    case UNUM_DECIMAL_SEPARATOR_FIELD:
      return isolate->factory()->decimal_string();
    case UNUM_GROUPING_SEPARATOR_FIELD:
      return isolate->factory()->group_string();
    case UNUM_CURRENCY_FIELD:
      return isolate->factory()->currency_string();
    case UNUM_PERCENT_FIELD:
      return isolate->factory()->percentSign_string();
    case UNUM_SIGN_FIELD:
      return (text.charAt(part.begin_pos) == '+')
                 ? isolate->factory()->plusSign_string()
                 : isolate->factory()->minusSign_string();
    case UNUM_EXPONENT_SYMBOL_FIELD:
      return isolate->factory()->exponentSeparator_string();

    case UNUM_EXPONENT_SIGN_FIELD:
      return isolate->factory()->exponentMinusSign_string();

    case UNUM_EXPONENT_FIELD:
      return isolate->factory()->exponentInteger_string();

    case UNUM_PERMILL_FIELD:
      // We're not creating any permill formatter, and it's not even clear how
      // that would be possible with the ICU API.
      UNREACHABLE();

    case UNUM_COMPACT_FIELD:
      return isolate->factory()->compact_string();
    case UNUM_MEASURE_UNIT_FIELD:
      return isolate->factory()->unit_string();

    case UNUM_APPROXIMATELY_SIGN_FIELD:
      return isolate->factory()->approximatelySign_string();

    default:
      UNREACHABLE();
  }
}

// A helper function to convert the FormattedValue for several Intl objects.
MaybeHandle<String> Intl::FormattedToString(
    Isolate* isolate, const icu::FormattedValue& formatted) {
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString result = formatted.toString(status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  return Intl::ToString(isolate, result);
}

MaybeHandle<JSArray> Intl::ToJSArray(
    Isolate* isolate, const char* unicode_key,
    icu::StringEnumeration* enumeration,
    const std::function<bool(const char*)>& removes, bool sort) {
  UErrorCode status = U_ZERO_ERROR;
  std::vector<std::string> array;
  for (const char* item = enumeration->next(nullptr, status);
       U_SUCCESS(status) && item != nullptr;
       item = enumeration->next(nullptr, status)) {
    if (unicode_key != nullptr) {
      item = uloc_toUnicodeLocaleType(unicode_key, item);
    }
    if (removes == nullptr || !(removes)(item)) {
      array.push_back(item);
    }
  }

  if (sort) {
    std::sort(array.begin(), array.end());
  }
  return VectorToJSArray(isolate, array);
}

bool Intl::RemoveCollation(const char* collation) {
  return strcmp("standard", collation) == 0 || strcmp("search", collation) == 0;
}

// See the list in ecma402 #sec-issanctionedsimpleunitidentifier
std::set<std::string> Intl::SanctionedSimpleUnits() {
  return std::set<std::string>(
      {"acre",        "bit",         "byte",        "celsius",
       "centimeter",  "day",         "degree",      "fahrenheit",
       "fluid-ounce", "foot",        "gallon",      "gigabit",
       "gigabyte",    "gram",        "hectare",     "hour",
       "inch",        "kilobit",     "kilobyte",    "kilogram",
       "kilometer",   "liter",       "megabit",     "megabyte",
       "meter",       "microsecond", "mile",        "mile-scandinavian",
       "millimeter",  "milliliter",  "millisecond", "minute",
       "month",       "nanosecond",  "ounce",       "percent",
       "petabyte",    "pound",       "second",      "stone",
       "terabit",     "terabyte",    "week",        "yard",
       "year"});
}

// ecma-402/#sec-isvalidtimezonename

namespace {
bool IsUnicodeStringValidTimeZoneName(const icu::UnicodeString& id) {
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString canonical;
  icu::TimeZone::getCanonicalID(id, canonical, status);
  return U_SUCCESS(status) &&
         canonical != icu::UnicodeString("Etc/Unknown", -1, US_INV);
}
}  // namespace

MaybeHandle<String> Intl::CanonicalizeTimeZoneName(
    Isolate* isolate, DirectHandle<String> identifier) {
  UErrorCode status = U_ZERO_ERROR;
  std::string time_zone =
      JSDateTimeFormat::CanonicalizeTimeZoneID(identifier->ToCString().get());
  icu::UnicodeString time_zone_ustring =
      icu::UnicodeString(time_zone.c_str(), -1, US_INV);
  icu::UnicodeString canonical;
  icu::TimeZone::getCanonicalID(time_zone_ustring, canonical, status);
  CHECK(U_SUCCESS(status));

  return JSDateTimeFormat::TimeZoneIdToString(isolate, canonical);
}

bool Intl::IsValidTimeZoneName(Isolate* isolate, DirectHandle<String> id) {
  std::string time_zone =
      JSDateTimeFormat::CanonicalizeTimeZoneID(id->ToCString().get());
  icu::UnicodeString time_zone_ustring =
      icu::UnicodeString(time_zone.c_str(), -1, US_INV);
  return IsUnicodeStringValidTimeZoneName(time_zone_ustring);
}

bool Intl::IsValidTimeZoneName(const icu::TimeZone& tz) {
  icu::UnicodeString id;
  tz.getID(id);
  return IsUnicodeStringValidTimeZoneName(id);
}

// Function to support Temporal
std::string Intl::TimeZoneIdFromIndex(int32_t index) {
  if (index == JSTemporalTimeZone::kUTCTimeZoneIndex) {
    return "UTC";
  }
  std::unique_ptr<icu::StringEnumeration> enumeration(
      icu::TimeZone::createEnumeration());
  int32_t curr = 0;
  const char* id;

  UErrorCode status = U_ZERO_ERROR;
  while (U_SUCCESS(status) && curr < index &&
         ((id = enumeration->next(nullptr, status)) != nullptr)) {
    CHECK(U_SUCCESS(status));
    curr++;
  }
  CHECK(U_SUCCESS(status));
  CHECK(id != nullptr);
  return id;
}

int32_t Intl::GetTimeZoneIndex(Isolate* isolate,
                               DirectHandle<String> identifier) {
  if (identifier->Equals(*isolate->factory()->UTC_string())) {
    return 0;
  }

  std::string identifier_str(identifier->ToCString().get());
  std::unique_ptr<icu::TimeZone> tz(
      icu::TimeZone::createTimeZone(identifier_str.c_str()));
  if (!IsValidTimeZoneName(*tz)) {
    return -1;
  }

  std::unique_ptr<icu::StringEnumeration> enumeration(
      icu::TimeZone::createEnumeration());
  int32_t curr = 0;
  const char* id;

  UErrorCode status = U_ZERO_ERROR;
  while (U_SUCCESS(status) &&
         (id = enumeration->next(nullptr, status)) != nullptr) {
    curr++;
    if (identifier_str == id) {
      return curr;
    }
  }
  CHECK(U_SUCCESS(status));
  // We should not reach here, the !IsValidTimeZoneName should return earlier
  UNREACHABLE();
}

Intl::FormatRangeSourceTracker::FormatRangeSourceTracker() {
  start_[0] = start_[1] = limit_[0] = limit_[1] = 0;
}

void Intl::FormatRangeSourceTracker::Add(int32_t field, int32_t start,
                                         int32_t limit) {
  DCHECK_LT(field, 2);
  start_[field] = start;
  limit_[field] = limit;
}

Intl::FormatRangeSource Intl::FormatRangeSourceTracker::GetSource(
    int32_t start, int32_t limit) const {
  FormatRangeSource source = FormatRangeSource::kShared;
  if (FieldContains(0, start, limit)) {
    source = FormatRangeSource::kStartRange;
  } else if (FieldContains(1, start, limit)) {
    source = FormatRangeSource::kEndRange;
  }
  return source;
}

bool Intl::FormatRangeSourceTracker::FieldContains(int32_t field, int32_t start,
                                                   int32_t limit) const {
  DCHECK_LT(field, 2);
  return (start_[field] <= start) && (start <= limit_[field]) &&
         (start_[field] <= limit) && (limit <= limit_[field]);
}

Handle<String> Intl::SourceString(Isolate* isolate, FormatRangeSource source) {
  switch (source) {
    case FormatRangeSource::kShared:
      return ReadOnlyRoots(isolate).shared_string_handle();
    case FormatRangeSource::kStartRange:
      return ReadOnlyRoots(isolate).startRange_string_handle();
    case FormatRangeSource::kEndRange:
      return ReadOnlyRoots(isolate).endRange_string_handle();
  }
}

Handle<String> Intl::DefaultTimeZone(Isolate* isolate) {
  icu::UnicodeString id;
  {
    std::unique_ptr<icu::TimeZone> tz(icu::TimeZone::createDefault());
    tz->getID(id);
  }
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString canonical;
  icu::TimeZone::getCanonicalID(id, canonical, status);
  DCHECK(U_SUCCESS(status));
  return JSDateTimeFormat::TimeZoneIdToString(isolate, canonical)
      .ToHandleChecked();
}

namespace {

const icu::BasicTimeZone* CreateBasicTimeZoneFromIndex(
    int32_t time_zone_index) {
  DCHECK_NE(time_zone_index, 0);
  return static_cast<const icu::BasicTimeZone*>(
      icu::TimeZone::createTimeZone(icu::UnicodeString(
          Intl::TimeZoneIdFromIndex(time_zone_index).c_str(), -1, US_INV)));
}

// ICU only support TimeZone information in millisecond but Temporal require
// nanosecond. For most of the case, we find an approximate millisecond by
// floor to the millisecond just past the nanosecond_epoch. For negative epoch
// value, the BigInt Divide will floor closer to zero so we need to minus 1 if
// the remainder is not zero. For the case of finding previous transition, we
// need to ceil to the millisecond in the near future of the nanosecond_epoch.
enum class Direction { kPast, kFuture };
int64_t ApproximateMillisecondEpoch(Isolate* isolate,
                                    Handle<BigInt> nanosecond_epoch,
                                    Direction direction = Direction::kPast) {
  DirectHandle<BigInt> one_million = BigInt::FromUint64(isolate, 1000000);
  int64_t ms = BigInt::Divide(isolate, nanosecond_epoch, one_million)
                   .ToHandleChecked()
                   ->AsInt64();
  DirectHandle<BigInt> remainder =
      BigInt::Remainder(isolate, nanosecond_epoch, one_million)
          .ToHandleChecked();
  // If the nanosecond_epoch is not on the exact millisecond
  if (remainder->ToBoolean()) {
    if (direction == Direction::kPast) {
      if (remainder->IsNegative()) {
        // If the remaninder is negative, we know we have an negative epoch
        // We need to decrease one millisecond.
        // Move to the previous millisecond
        ms -= 1;
      }
    } else {
      if (!remainder->IsNegative()) {
        // Move to the future millisecond
        ms += 1;
      }
    }
  }
  return ms;
}

// Helper function to convert the milliseconds in int64_t
// to a BigInt in nanoseconds.
Handle<BigInt> MillisecondToNanosecond(Isolate* isolate, int64_t ms) {
  return BigInt::Multiply(isolate, BigInt::FromInt64(isolate, ms),
                          BigInt::FromUint64(isolate, 1000000))
      .ToHandleChecked();
}

}  // namespace

Handle<Object> Intl::GetTimeZoneOffsetTransitionNanoseconds(
    Isolate* isolate, int32_t time_zone_index, Handle<BigInt> nanosecond_epoch,
    Intl::Transition transition) {
  std::unique_ptr<const icu::BasicTimeZone> basic_time_zone(
      CreateBasicTimeZoneFromIndex(time_zone_index));

  icu::TimeZoneTransition icu_transition;
  UBool has_transition;
  switch (transition) {
    case Intl::Transition::kNext:
      has_transition = basic_time_zone->getNextTransition(
          ApproximateMillisecondEpoch(isolate, nanosecond_epoch), false,
          icu_transition);
      break;
    case Intl::Transition::kPrevious:
      has_transition = basic_time_zone->getPreviousTransition(
          ApproximateMillisecondEpoch(isolate, nanosecond_epoch,
                                      Direction::kFuture),
          false, icu_transition);
      break;
  }

  if (!has_transition) {
    return isolate->factory()->null_value();
  }
  // #sec-temporal-getianatimezonenexttransition and
  // #sec-temporal-getianatimezoneprevioustransition states:
  // "The operation returns null if no such transition exists for which t ≤
  // ℤ(nsMaxInstant)." and "The operation returns null if no such transition
  // exists for which t ≥ ℤ(nsMinInstant)."
  //
  // nsMinInstant = -nsMaxInstant = -8.64 × 10^21 => msMinInstant = -8.64 x
  // 10^15
  constexpr int64_t kMsMinInstant = -8.64e15;
  // nsMaxInstant = 10^8 × nsPerDay = 8.64 × 10^21 => msMaxInstant = 8.64 x
  // 10^15
  constexpr int64_t kMsMaxInstant = 8.64e15;
  int64_t time_ms = static_cast<int64_t>(icu_transition.getTime());
  if (time_ms < kMsMinInstant || time_ms > kMsMaxInstant) {
    return isolate->factory()->null_value();
  }
  return MillisecondToNanosecond(isolate, time_ms);
}

std::vector<Handle<BigInt>> Intl::GetTimeZonePossibleOffsetNanoseconds(
    Isolate* isolate, int32_t time_zone_index,
    Handle<BigInt> nanosecond_epoch) {
  std::unique_ptr<const icu::BasicTimeZone> basic_time_zone(
      CreateBasicTimeZoneFromIndex(time_zone_index));
  int64_t time_ms = ApproximateMillisecondEpoch(isolate, nanosecond_epoch);
  int32_t raw_offset;
  int32_t dst_offset;
  UErrorCode status = U_ZERO_ERROR;
  basic_time_zone->getOffsetFromLocal(time_ms, UCAL_TZ_LOCAL_FORMER,
                                      UCAL_TZ_LOCAL_FORMER, raw_offset,
                                      dst_offset, status);
  DCHECK(U_SUCCESS(status));
  // offset for time_ms interpretted as before a time zone
  // transition
  int64_t offset_former = raw_offset + dst_offset;

  basic_time_zone->getOffsetFromLocal(time_ms, UCAL_TZ_LOCAL_LATTER,
                                      UCAL_TZ_LOCAL_LATTER, raw_offset,
                                      dst_offset, status);
  DCHECK(U_SUCCESS(status));
  // offset for time_ms interpretted as after a time zone
  // transition
  int64_t offset_latter = raw_offset + dst_offset;

  std::vector<Handle<BigInt>> result;
  if (offset_former == offset_latter) {
    // For most of the time, when either interpretation are the same, we are not
    // in a moment of offset transition based on rule changing: Just return that
    // value.
    result.push_back(MillisecondToNanosecond(isolate, offset_former));
  } else if (offset_former > offset_latter) {
    // When the input represents a local time repeating multiple times at a
    // negative time zone transition (e.g. when the daylight saving time ends
    // or the time zone offset is decreased due to a time zone rule change).
    result.push_back(MillisecondToNanosecond(isolate, offset_former));
    result.push_back(MillisecondToNanosecond(isolate, offset_latter));
  } else {
    // If the offset after the transition is greater than the offset before the
    // transition, that mean it is in the moment the time "skip" an hour, or two
    // (or six in a Time Zone in south pole) in that case there are no possible
    // Time Zone offset for that moment and nothing will be added to the result.
  }
  return result;
}

int64_t Intl::GetTimeZoneOffsetNanoseconds(Isolate* isolate,
                                           int32_t time_zone_index,
                                           Handle<BigInt> nanosecond_epoch) {
  std::unique_ptr<const icu::BasicTimeZone> basic_time_zone(
      CreateBasicTimeZoneFromIndex(time_zone_index));
  int64_t time_ms = ApproximateMillisecondEpoch(isolate, nanosecond_epoch);
  int32_t raw_offset;
  int32_t dst_offset;
  UErrorCode status = U_ZERO_ERROR;
  basic_time_zone->getOffset(time_ms, false, raw_offset, dst_offset, status);
  DCHECK(U_SUCCESS(status));
  // Turn ms into ns
  return static_cast<int64_t>(raw_offset + dst_offset) * 1000000;
}

}  // namespace v8::internal

"""


```