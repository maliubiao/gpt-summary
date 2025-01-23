Response:
My thinking process to answer the request about `v8/src/objects/intl-objects.h` went something like this:

1. **Understand the Request:** The user wants to know the functionality of this header file, whether it's Torque, its relationship to JavaScript, any logical inference possibilities, and common user errors.

2. **Initial Scan for Clues:** I first scanned the code for obvious keywords and patterns:
    * `#ifndef`, `#define`, `#include`: Standard C++ header file structure. This confirms it's a C++ header, *not* a Torque file (which would end in `.tq`). This immediately addresses one of the user's specific questions.
    * `// Copyright`, license information: Standard boilerplate.
    * `V8_OBJECTS_INTL_OBJECTS_H_`:  The header guard, confirming the file name and its purpose.
    * `#include <...>`: Includes for standard library components (`map`, `memory`, `string`, etc.) and V8-specific headers (`contexts.h`, `objects.h`). These inclusions suggest the file deals with managing internationalization objects within the V8 object system.
    * `#include "unicode/..."`:  Crucially, includes for ICU (International Components for Unicode) headers. This strongly indicates the file is responsible for integrating ICU's internationalization capabilities into V8.
    * `#ifndef V8_INTL_SUPPORT`:  A conditional compilation check. This confirms that internationalization support is expected to be enabled when this header is used.
    * `#define ICU_EXTERNAL_POINTER_TAG_LIST(...)`: A macro defining tags for different ICU object types. This hints at how V8 manages external ICU objects.
    * `namespace v8::internal`:  Indicates this code is part of V8's internal implementation details.
    * `class Intl`:  A central class name related to internationalization. This is the core of the file.
    * `enum class`: Various enumerations within the `Intl` class related to formatting, rounding, and locale matching.
    * `static` methods within `Intl`: Utility functions for locale handling, string comparison, number formatting, etc. The `V8_WARN_UNUSED_RESULT` annotation suggests these functions are important and their return values shouldn't be ignored.
    * `struct`:  Data structures like `NumberFormatSpan`, `NumberFormatDigitOptions`, and `ResolvedLocale` used for internal representation of internationalization data.
    * `template class AvailableLocales`:  A template for managing available locales, demonstrating a more advanced C++ feature being used.

3. **Categorizing Functionality:** Based on the scanned keywords and patterns, I started to group the functionalities:
    * **Core Internationalization:** Handling locales, canonicalization, supported values, etc.
    * **String Operations:** Case conversion, locale-aware comparison, normalization.
    * **Number Formatting:**  Formatting numbers based on locale, handling different options (digits, rounding, etc.).
    * **Date/Time (Implied):** While not explicitly detailed in *this* header, the presence of `SimpleDateFormat`, `DateIntervalFormat`, and mentions of calendars and time zones strongly suggest related functionalities exist, likely in other files that use this header.
    * **Locale Matching:** Implementing best-fit and lookup algorithms for locale negotiation.
    * **ICU Integration:** Managing and interacting with ICU library objects.
    * **Temporal API Support:**  Functions specifically mentioned as supporting the Temporal API (a modern JavaScript date/time API).

4. **Addressing Specific User Questions:**
    * **Functionality:**  I compiled the categorized functionalities into a concise list.
    * **Torque:** The initial scan clearly showed it's a `.h` file, so it's C++, not Torque.
    * **JavaScript Relationship:**  I looked for connections between the C++ code and JavaScript concepts. The `Intl` class name itself is a strong clue, as is the mention of ECMA-402 (the ECMAScript Internationalization API specification). I then identified specific functions that directly relate to JavaScript `Intl` object methods (e.g., `NumberToLocaleString`, `CanonicalizeLocaleList`). I then crafted JavaScript examples to demonstrate this connection.
    * **Logical Inference:** I examined functions like `CompareStrings` and considered how they might be used. I came up with a simple example of comparing strings with different locales and how the output (order) would vary.
    * **Common Errors:** I thought about common mistakes developers make when working with internationalization: incorrect locale strings, forgetting to handle potential errors, and assuming default behavior is always sufficient.

5. **Structuring the Answer:** I organized the information logically:
    * Start with a clear statement of the file's purpose.
    * Address the Torque question directly.
    * Explain the relationship with JavaScript and provide examples.
    * Detail logical inference with input/output examples.
    * Provide examples of common programming errors.
    * Use clear and concise language.
    * Highlight key concepts (ICU, ECMA-402).

6. **Refinement:** I reviewed my answer to ensure accuracy, clarity, and completeness, double-checking the code snippets and explanations.

By following this process, I was able to systematically analyze the provided C++ header file and generate a comprehensive and informative answer that directly addressed all aspects of the user's request. The key was to look for the "big picture" first (the role of internationalization and ICU), then delve into the specifics of the code and its connection to JavaScript.

The `v8/src/objects/intl-objects.h` header file in the V8 JavaScript engine defines the interface for objects related to internationalization (often abbreviated as Intl). It acts as a bridge between V8's internal object representation and the ICU (International Components for Unicode) library, which provides the actual implementation for many internationalization features.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Defines C++ Classes for Intl Objects:** This header declares the `Intl` class and related structures and enums. While it doesn't define the full implementation (that's in `.cc` files), it sets up the blueprint for how V8 represents Intl-related data internally.
* **Integration with ICU:**  A major purpose is to manage and interact with ICU library components. This is evident from the inclusion of ICU headers (`unicode/...`) and the `ICU_EXTERNAL_POINTER_TAG_LIST` macro. This macro likely defines tags used by V8's garbage collector to track and manage pointers to ICU objects (like `icu::Locale`, `icu::Collator`, etc.).
* **Abstraction Layer:** It provides an abstraction layer over the raw ICU API, making it easier for V8's JavaScript engine to interact with internationalization features in a consistent and safe manner.
* **Defines Structures for Intl Options:** Structures like `NumberFormatDigitOptions` are defined to hold and pass options related to formatting numbers, dates, times, etc. These structures correspond to the options objects used in the JavaScript Intl API.
* **Utility Functions:** It contains various static utility functions for common Intl-related tasks, such as:
    * Locale handling (`BuildLocaleSet`, `ToLanguageTag`, `CanonicalizeLocaleList`, `ResolveLocale`).
    * String manipulation (`StringLocaleConvertCase`, `CompareStrings`, `Normalize`).
    * Number formatting (`NumberToLocaleString`, `SetNumberFormatDigitOptions`).
    * Interaction with ICU objects (converting between V8 strings and ICU strings).
    * Supporting the Temporal API (a modern JavaScript date/time API).

**Is `v8/src/objects/intl-objects.h` a Torque file?**

No, `v8/src/objects/intl-objects.h` is a standard C++ header file. The `.h` extension signifies this. Torque source files in V8 typically have a `.tq` extension.

**Relationship with JavaScript Functionality:**

This header file is **directly related** to the functionality of the global `Intl` object in JavaScript. The classes, structures, and functions defined here are the C++ underpinnings of the JavaScript Intl API.

**JavaScript Examples:**

The C++ code in this header provides the implementation for JavaScript Intl objects like `Intl.Collator`, `Intl.NumberFormat`, `Intl.DateTimeFormat`, etc. Here are some examples showing the connection:

```javascript
// Using Intl.Collator for locale-aware string comparison
const collator = new Intl.Collator('en-US');
const result = collator.compare('apple', 'banana'); // The C++ CompareStrings function is likely involved here.

// Using Intl.NumberFormat for formatting numbers according to locale
const numberFormat = new Intl.NumberFormat('de-DE', { style: 'currency', currency: 'EUR' });
const formattedNumber = numberFormat.format(1234.56); // The C++ NumberToLocaleString function and related options structures are used.

// Getting a canonicalized list of locales
const locales = Intl.getCanonicalLocales(['en-US', 'fr-CA', 'EN-GB']); // The C++ GetCanonicalLocales function is called.

// Checking supported locales for NumberFormat
const supportedLocales = Intl.NumberFormat.supportedLocalesOf(['en-US', 'de-DE', 'ja-JP']); // The C++ SupportedLocalesOf function is involved.
```

**Code Logic Inference (Hypothetical):**

Let's take the `CompareStrings` function as an example.

**Hypothetical Input:**

* `isolate`: A pointer to the V8 isolate (the execution environment).
* `collator`: An `icu::Collator` object configured for a specific locale (e.g., 'en-US').
* `s1`: A V8 string object representing "apple".
* `s2`: A V8 string object representing "banana".

**Expected Output:**

The `CompareStrings` function (or the underlying ICU collator) would likely return a negative number (e.g., -1) because "apple" comes before "banana" alphabetically in the 'en-US' locale. If the locale were different (e.g., with special sorting rules), the output might vary.

**Common User Programming Errors:**

* **Incorrect Locale Strings:** Providing invalid or malformed locale strings (e.g., "en_US" instead of "en-US") to Intl constructors or methods. This can lead to errors or unexpected behavior.

   ```javascript
   // Error: Using underscore instead of hyphen
   const formatter = new Intl.NumberFormat('en_US'); // Might not work as expected
   ```

* **Not Handling `supportedLocalesOf` Correctly:**  Assuming a locale is supported without checking. If a requested locale isn't supported, the Intl object might fall back to a default locale, leading to unexpected formatting or comparison results.

   ```javascript
   const requestedLocales = ['xx-XX', 'en-US']; // 'xx-XX' is likely invalid
   const supported = Intl.NumberFormat.supportedLocalesOf(requestedLocales);
   if (supported.includes('xx-XX')) { // This check is important
       const formatter = new Intl.NumberFormat('xx-XX');
   } else {
       console.log("Locale 'xx-XX' is not supported.");
       const formatter = new Intl.NumberFormat('en-US'); // Fallback
   }
   ```

* **Ignoring Options:** Not understanding or using the various options available in Intl constructors (e.g., `sensitivity` in `Intl.Collator`, `style` and `currency` in `Intl.NumberFormat`). This can result in output that doesn't meet the desired formatting or comparison requirements.

   ```javascript
   // Comparing strings with default sensitivity (case-sensitive)
   const collator = new Intl.Collator('en', {});
   console.log(collator.compare('Apple', 'apple')); // Likely a non-zero result

   // Comparing strings with case-insensitive sensitivity
   const collatorWithOptions = new Intl.Collator('en', { sensitivity: 'base' });
   console.log(collatorWithOptions.compare('Apple', 'apple')); // Likely 0 (equal)
   ```

* **Misunderstanding Locale Matching Algorithms:**  Not being aware of how locale negotiation works (e.g., "best fit" vs. "lookup") when providing a list of preferred locales. This can lead to the selection of a different locale than intended.

In summary, `v8/src/objects/intl-objects.h` is a crucial C++ header file that defines the interface for V8's internationalization features, bridging the gap between JavaScript's `Intl` API and the underlying ICU library. It's not a Torque file but plays a fundamental role in how V8 handles internationalized data.

### 提示词
```
这是目录为v8/src/objects/intl-objects.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/intl-objects.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2013 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_INTL_OBJECTS_H_
#define V8_OBJECTS_INTL_OBJECTS_H_

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>

#include "src/base/timezone-cache.h"
#include "src/objects/contexts.h"
#include "src/objects/managed.h"
#include "src/objects/objects.h"
#include "unicode/locid.h"
#include "unicode/uversion.h"

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

#define V8_MINIMUM_ICU_VERSION 73

namespace U_ICU_NAMESPACE {
class BreakIterator;
class Locale;
class ListFormatter;
class RelativeDateTimeFormatter;
class SimpleDateFormat;
class DateIntervalFormat;
class PluralRules;
class Collator;
class FormattedValue;
class StringEnumeration;
class TimeZone;
class UnicodeString;
namespace number {
class LocalizedNumberFormatter;
}  //  namespace number
}  // namespace U_ICU_NAMESPACE

namespace v8::internal {

#define ICU_EXTERNAL_POINTER_TAG_LIST(V)                              \
  V(icu::UnicodeString, kIcuUnicodeStringTag)                         \
  V(icu::BreakIterator, kIcuBreakIteratorTag)                         \
  V(icu::Locale, kIcuLocaleTag)                                       \
  V(icu::SimpleDateFormat, kIcuSimpleDateFormatTag)                   \
  V(icu::DateIntervalFormat, kIcuDateIntervalFormatTag)               \
  V(icu::RelativeDateTimeFormatter, kIcuRelativeDateTimeFormatterTag) \
  V(icu::ListFormatter, kIcuListFormatterTag)                         \
  V(icu::Collator, kIcuCollatorTag)                                   \
  V(icu::PluralRules, kIcuPluralRulesTag)                             \
  V(icu::number::LocalizedNumberFormatter, kIcuLocalizedNumberFormatterTag)
ICU_EXTERNAL_POINTER_TAG_LIST(ASSIGN_EXTERNAL_POINTER_TAG_FOR_MANAGED)
#undef ICU_EXTERNAL_POINTER_TAG_LIST

struct NumberFormatSpan {
  int32_t field_id;
  int32_t begin_pos;
  int32_t end_pos;

  NumberFormatSpan() = default;
  NumberFormatSpan(int32_t field_id, int32_t begin_pos, int32_t end_pos)
      : field_id(field_id), begin_pos(begin_pos), end_pos(end_pos) {}
};

V8_EXPORT_PRIVATE std::vector<NumberFormatSpan> FlattenRegionsToParts(
    std::vector<NumberFormatSpan>* regions);

class JSCollator;

class Intl {
 public:
  enum class BoundFunctionContextSlot {
    kBoundFunction = Context::MIN_CONTEXT_SLOTS,
    kLength
  };

  enum class FormatRangeSource { kShared, kStartRange, kEndRange };

  class FormatRangeSourceTracker {
   public:
    FormatRangeSourceTracker();
    void Add(int32_t field, int32_t start, int32_t limit);
    FormatRangeSource GetSource(int32_t start, int32_t limit) const;

   private:
    int32_t start_[2];
    int32_t limit_[2];

    bool FieldContains(int32_t field, int32_t start, int32_t limit) const;
  };

  static Handle<String> SourceString(Isolate* isolate,
                                     FormatRangeSource source);

  // Build a set of ICU locales from a list of Locales. If there is a locale
  // with a script tag then the locales also include a locale without the
  // script; eg, pa_Guru_IN (language=Panjabi, script=Gurmukhi, country-India)
  // would include pa_IN.
  static std::set<std::string> BuildLocaleSet(
      const std::vector<std::string>& locales, const char* path,
      const char* validate_key);

  static Maybe<std::string> ToLanguageTag(const icu::Locale& locale);

  // Get the name of the numbering system from locale.
  // ICU doesn't expose numbering system in any way, so we have to assume that
  // for given locale NumberingSystem constructor produces the same digits as
  // NumberFormat/Calendar would.
  static std::string GetNumberingSystem(const icu::Locale& icu_locale);

  static V8_WARN_UNUSED_RESULT MaybeHandle<JSObject> SupportedLocalesOf(
      Isolate* isolate, const char* method_name,
      const std::set<std::string>& available_locales, Handle<Object> locales_in,
      Handle<Object> options_in);

  // https://tc39.github.io/ecma402/#sec-canonicalizelocalelist
  // {only_return_one_result} is an optimization for callers that only
  // care about the first result.
  static Maybe<std::vector<std::string>> CanonicalizeLocaleList(
      Isolate* isolate, Handle<Object> locales,
      bool only_return_one_result = false);

  // ecma-402 #sec-intl.getcanonicallocales
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSArray> GetCanonicalLocales(
      Isolate* isolate, Handle<Object> locales);

  // ecma-402 #sec-intl.supportedvaluesof
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSArray> SupportedValuesOf(
      Isolate* isolate, Handle<Object> key);

  // For locale sensitive functions
  V8_WARN_UNUSED_RESULT static MaybeHandle<String> StringLocaleConvertCase(
      Isolate* isolate, Handle<String> s, bool is_upper,
      Handle<Object> locales);

  V8_WARN_UNUSED_RESULT static MaybeHandle<String> ConvertToUpper(
      Isolate* isolate, Handle<String> s);

  V8_WARN_UNUSED_RESULT static MaybeHandle<String> ConvertToLower(
      Isolate* isolate, Handle<String> s);

  V8_WARN_UNUSED_RESULT static std::optional<int> StringLocaleCompare(
      Isolate* isolate, Handle<String> s1, Handle<String> s2,
      Handle<Object> locales, Handle<Object> options, const char* method_name);

  enum class CompareStringsOptions {
    kNone,
    kTryFastPath,
  };
  template <class IsolateT>
  V8_EXPORT_PRIVATE static CompareStringsOptions CompareStringsOptionsFor(
      IsolateT* isolate, DirectHandle<Object> locales,
      DirectHandle<Object> options);
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static int CompareStrings(
      Isolate* isolate, const icu::Collator& collator, Handle<String> s1,
      Handle<String> s2,
      CompareStringsOptions compare_strings_options =
          CompareStringsOptions::kNone);

  // ecma402/#sup-properties-of-the-number-prototype-object
  V8_WARN_UNUSED_RESULT static MaybeHandle<String> NumberToLocaleString(
      Isolate* isolate, Handle<Object> num, Handle<Object> locales,
      Handle<Object> options, const char* method_name);

  // [[RoundingPriority]] is one of the String values "auto", "morePrecision",
  // or "lessPrecision", specifying the rounding priority for the number.
  enum class RoundingPriority {
    kAuto,
    kMorePrecision,
    kLessPrecision,
  };

  enum class RoundingType {
    kFractionDigits,
    kSignificantDigits,
    kMorePrecision,
    kLessPrecision,
  };

  // [[RoundingMode]] is one of the String values "ceil", "floor", "expand",
  // "trunc", "halfCeil", "halfFloor", "halfExpand", "halfTrunc", or "halfEven",
  // specifying the rounding strategy for the number.
  enum class RoundingMode {
    kCeil,
    kFloor,
    kExpand,
    kTrunc,
    kHalfCeil,
    kHalfFloor,
    kHalfExpand,
    kHalfTrunc,
    kHalfEven,
  };

  // [[TrailingZeroDisplay]] is one of the String values "auto" or
  // "stripIfInteger", specifying the strategy for displaying trailing zeros on
  // whole number.
  enum class TrailingZeroDisplay {
    kAuto,
    kStripIfInteger,
  };

  // ecma402/#sec-setnfdigitoptions
  struct NumberFormatDigitOptions {
    int minimum_integer_digits;
    int minimum_fraction_digits;
    int maximum_fraction_digits;
    int minimum_significant_digits;
    int maximum_significant_digits;
    RoundingPriority rounding_priority;
    RoundingType rounding_type;
    int rounding_increment;
    RoundingMode rounding_mode;
    TrailingZeroDisplay trailing_zero_display;
  };
  V8_WARN_UNUSED_RESULT static Maybe<NumberFormatDigitOptions>
  SetNumberFormatDigitOptions(Isolate* isolate, Handle<JSReceiver> options,
                              int mnfd_default, int mxfd_default,
                              bool notation_is_compact, const char* service);

  // Helper function to convert a UnicodeString to a Handle<String>
  V8_WARN_UNUSED_RESULT static MaybeHandle<String> ToString(
      Isolate* isolate, const icu::UnicodeString& string);

  // Helper function to convert a substring of UnicodeString to a Handle<String>
  V8_WARN_UNUSED_RESULT static MaybeHandle<String> ToString(
      Isolate* isolate, const icu::UnicodeString& string, int32_t begin,
      int32_t end);

  // Helper function to convert a FormattedValue to String
  V8_WARN_UNUSED_RESULT static MaybeHandle<String> FormattedToString(
      Isolate* isolate, const icu::FormattedValue& formatted);

  // Helper function to convert number field id to type string.
  static Handle<String> NumberFieldToType(Isolate* isolate,
                                          const NumberFormatSpan& part,
                                          const icu::UnicodeString& text,
                                          bool is_nan);

  // A helper function to implement formatToParts which add element to array as
  // $array[$index] = { type: $field_type_string, value: $value }
  static void AddElement(Isolate* isolate, Handle<JSArray> array, int index,
                         DirectHandle<String> field_type_string,
                         DirectHandle<String> value);

  // A helper function to implement formatToParts which add element to array as
  // $array[$index] = {
  //   type: $field_type_string, value: $value,
  //   $additional_property_name: $additional_property_value
  // }
  static void AddElement(Isolate* isolate, Handle<JSArray> array, int index,
                         DirectHandle<String> field_type_string,
                         DirectHandle<String> value,
                         Handle<String> additional_property_name,
                         DirectHandle<String> additional_property_value);

  // A helper function to implement formatToParts which add element to array
  static Maybe<int> AddNumberElements(Isolate* isolate,
                                      const icu::FormattedValue& formatted,
                                      Handle<JSArray> result, int start_index,
                                      DirectHandle<String> unit);

  // In ECMA 402 v1, Intl constructors supported a mode of operation
  // where calling them with an existing object as a receiver would
  // transform the receiver into the relevant Intl instance with all
  // internal slots. In ECMA 402 v2, this capability was removed, to
  // avoid adding internal slots on existing objects. In ECMA 402 v3,
  // the capability was re-added as "normative optional" in a mode
  // which chains the underlying Intl instance on any object, when the
  // constructor is called
  //
  // See ecma402/#legacy-constructor.
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> LegacyUnwrapReceiver(
      Isolate* isolate, Handle<JSReceiver> receiver,
      Handle<JSFunction> constructor, bool has_initialized_slot);

  // enum for "localeMatcher" option: shared by many Intl objects.
  enum class MatcherOption { kBestFit, kLookup };

  // Shared function to read the "localeMatcher" option.
  V8_WARN_UNUSED_RESULT static Maybe<MatcherOption> GetLocaleMatcher(
      Isolate* isolate, Handle<JSReceiver> options, const char* method_name);

  // Shared function to read the "numberingSystem" option.
  V8_WARN_UNUSED_RESULT static Maybe<bool> GetNumberingSystem(
      Isolate* isolate, Handle<JSReceiver> options, const char* method_name,
      std::unique_ptr<char[]>* result);

  // Check the calendar is valid or not for that locale.
  static bool IsValidCalendar(const icu::Locale& locale,
                              const std::string& value);

  // Check the collation is valid or not for that locale.
  static bool IsValidCollation(const icu::Locale& locale,
                               const std::string& value);

  // Check the numberingSystem is valid.
  static bool IsValidNumberingSystem(const std::string& value);

  // Check the calendar is well formed.
  static bool IsWellFormedCalendar(const std::string& value);

  // Check the currency is well formed.
  static bool IsWellFormedCurrency(const std::string& value);

  struct ResolvedLocale {
    std::string locale;
    icu::Locale icu_locale;
    std::map<std::string, std::string> extensions;
  };

  static Maybe<ResolvedLocale> ResolveLocale(
      Isolate* isolate, const std::set<std::string>& available_locales,
      const std::vector<std::string>& requested_locales, MatcherOption options,
      const std::set<std::string>& relevant_extension_keys);

  // A helper template to implement the GetAvailableLocales
  // Usage in src/objects/js-XXX.cc
  // const std::set<std::string>& JSXxx::GetAvailableLocales() {
  //   static base::LazyInstance<Intl::AvailableLocales<icu::YYY>>::type
  //       available_locales = LAZY_INSTANCE_INITIALIZER;
  //   return available_locales.Pointer()->Get();
  // }

  struct SkipResourceCheck {
    static const char* key() { return nullptr; }
    static const char* path() { return nullptr; }
  };

  template <typename C = SkipResourceCheck>
  class AvailableLocales {
   public:
    AvailableLocales() {
      UErrorCode status = U_ZERO_ERROR;
      UEnumeration* uenum =
          uloc_openAvailableByType(ULOC_AVAILABLE_WITH_LEGACY_ALIASES, &status);
      DCHECK(U_SUCCESS(status));

      std::vector<std::string> all_locales;
      const char* loc;
      while ((loc = uenum_next(uenum, nullptr, &status)) != nullptr) {
        DCHECK(U_SUCCESS(status));
        std::string locstr(loc);
        std::replace(locstr.begin(), locstr.end(), '_', '-');
        // Handle special case
        if (locstr == "en-US-POSIX") locstr = "en-US-u-va-posix";
        all_locales.push_back(locstr);
      }
      uenum_close(uenum);

      set_ = Intl::BuildLocaleSet(all_locales, C::path(), C::key());
    }
    const std::set<std::string>& Get() const { return set_; }

   private:
    std::set<std::string> set_;
  };

  // Utility function to set text to BreakIterator.
  static Handle<Managed<icu::UnicodeString>> SetTextToBreakIterator(
      Isolate* isolate, Handle<String> text,
      icu::BreakIterator* break_iterator);

  // ecma262 #sec-string.prototype.normalize
  V8_WARN_UNUSED_RESULT static MaybeHandle<String> Normalize(
      Isolate* isolate, Handle<String> string, Handle<Object> form_input);
  static base::TimezoneCache* CreateTimeZoneCache();

  // Convert a Handle<String> to icu::UnicodeString
  static icu::UnicodeString ToICUUnicodeString(Isolate* isolate,
                                               DirectHandle<String> string,
                                               int offset = 0);

  static const uint8_t* ToLatin1LowerTable();

  static const uint8_t* AsciiCollationWeightsL1();
  static const uint8_t* AsciiCollationWeightsL3();
  static const int kAsciiCollationWeightsLength;

  static Tagged<String> ConvertOneByteToLower(Tagged<String> src,
                                              Tagged<String> dst);

  static const std::set<std::string>& GetAvailableLocales();

  static const std::set<std::string>& GetAvailableLocalesForDateFormat();

  V8_WARN_UNUSED_RESULT static MaybeHandle<JSArray> ToJSArray(
      Isolate* isolate, const char* unicode_key,
      icu::StringEnumeration* enumeration,
      const std::function<bool(const char*)>& removes, bool sort);

  static bool RemoveCollation(const char* collation);

  static std::set<std::string> SanctionedSimpleUnits();

  V8_WARN_UNUSED_RESULT static MaybeHandle<JSArray> AvailableCalendars(
      Isolate* isolate);

  V8_WARN_UNUSED_RESULT static bool IsValidTimeZoneName(
      const icu::TimeZone& tz);
  V8_WARN_UNUSED_RESULT static bool IsValidTimeZoneName(Isolate* isolate,
                                                        const std::string& id);
  V8_WARN_UNUSED_RESULT static bool IsValidTimeZoneName(
      Isolate* isolate, DirectHandle<String> id);

  // Function to support Temporal
  V8_WARN_UNUSED_RESULT static std::string TimeZoneIdFromIndex(int32_t index);

  // Return the index of timezone which later could be used with
  // TimeZoneIdFromIndex. Returns -1 while the identifier is not a built-in
  // TimeZone name.
  static int32_t GetTimeZoneIndex(Isolate* isolate,
                                  DirectHandle<String> identifier);

  enum class Transition { kNext, kPrevious };

  // Functions to support Temporal

  // Return the epoch of transition in BigInt or null if there are no
  // transition.
  static Handle<Object> GetTimeZoneOffsetTransitionNanoseconds(
      Isolate* isolate, int32_t time_zone_index,
      Handle<BigInt> nanosecond_epoch, Transition transition);

  // Return the Time Zone offset, in the unit of nanosecond by int64_t, during
  // the time of the nanosecond_epoch.
  static int64_t GetTimeZoneOffsetNanoseconds(Isolate* isolate,
                                              int32_t time_zone_index,
                                              Handle<BigInt> nanosecond_epoch);

  // This function may return the result, the std::vector<int64_t> in one of
  // the following three condictions:
  // 1. While nanosecond_epoch fall into the daylight saving time change
  // moment that skipped one (or two or even six, in some Time Zone) hours
  // later in local time:
  //    [],
  // 2. In other moment not during daylight saving time change:
  //    [offset_former], and
  // 3. when nanosecond_epoch fall into they daylight saving time change hour
  // which the clock time roll back one (or two or six, in some Time Zone) hour:
  //    [offset_former, offset_later]
  // The unit of the return values in BigInt is nanosecond.
  static std::vector<Handle<BigInt>> GetTimeZonePossibleOffsetNanoseconds(
      Isolate* isolate, int32_t time_zone_index,
      Handle<BigInt> nanosecond_epoch);

  static Handle<String> DefaultTimeZone(Isolate* isolate);

  V8_WARN_UNUSED_RESULT static MaybeHandle<String> CanonicalizeTimeZoneName(
      Isolate* isolate, DirectHandle<String> identifier);

  // ecma402/#sec-coerceoptionstoobject
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSReceiver> CoerceOptionsToObject(
      Isolate* isolate, Handle<Object> options, const char* service);
};

}  // namespace v8::internal

#endif  // V8_OBJECTS_INTL_OBJECTS_H_
```