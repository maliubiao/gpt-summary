Response:
Let's break down the thought process for analyzing the `case_map.cc` file.

**1. Understanding the Core Purpose:**

The filename `case_map.cc` immediately suggests this file deals with case conversion of text. Keywords like "lower", "upper", "invariant", and "locale" in the code further confirm this. The inclusion of `<unicode/casemap.h>` reinforces the connection to Unicode case mapping.

**2. Identifying Key Functions:**

I'd scan the file for public functions, which are usually declared outside the anonymous namespace. This reveals functions like:

* `TryFastToLowerInvariant`
* `FastToLowerInvariant`
* `ToLowerInvariant`
* `ToUpperInvariant`
* `ToLower` (two overloads)
* `ToUpper` (two overloads)
* The `Locale` class constructor

These functions are the primary entry points for using the case mapping functionality.

**3. Analyzing Individual Function Functionality:**

For each key function, I'd try to understand its specific role:

* **`TryFastToLowerInvariant`:** The name suggests an attempt at an optimized, potentially simpler, lowercasing. The code confirms this by first checking for all-ASCII strings and handling them efficiently. The return of `nullptr` indicates a fallback mechanism.

* **`FastToLowerInvariant`:**  This likely calls `TryFastToLowerInvariant` and falls back to a more general solution if the fast path fails. The use of `CaseConvert` confirms this.

* **`ToLowerInvariant` and `ToUpperInvariant`:**  These seem to be the core functions for locale-insensitive case conversion. The `Invariant` part is a key hint. They also utilize `CaseConvert`.

* **`ToLower` and `ToUpper`:** These versions take a `Locale` object, indicating locale-sensitive case conversion. They delegate to `CaseConvert` with a potentially specific locale.

* **`Locale` Constructor:** This determines the specific locale to use based on an `AtomicString`. The hardcoded language codes ("tr", "az", "el", "lt") are important to note.

**4. Examining Helper Functions and Data Structures:**

* **Anonymous Namespace:**  Functions and enums within this namespace are internal to the `case_map.cc` file. `CaseConvert` and `CaseMapType` are important examples.

* **`CaseConvert`:** This is the workhorse function, using the ICU library (`icu::CaseMap`) for the actual conversion. It handles buffer allocation and resizing, and optionally updates a `TextOffsetMap`.

* **`LocaleIdMatchesLang`:** A helper to check if a locale ID matches a specific language code.

* **`CaseMapType`:** A simple enum to distinguish between lower and upper case conversion.

* **`TextOffsetMap`:** The inclusion of this class suggests that the case conversion might change the length of the string in certain cases (e.g., the German 'ß' to 'SS'). This is important for maintaining mappings between the original and converted strings.

**5. Identifying Relationships with Web Technologies:**

This requires knowledge of how text processing and internationalization are handled in web browsers.

* **JavaScript:**  JavaScript's `toLowerCase()` and `toUpperCase()` methods are the most direct link. The `CaseMap` functionality is likely used to implement these methods efficiently and correctly, especially for locale-aware conversions.

* **HTML:**  HTML attributes like `lang` and the content itself can influence how text is displayed and processed. The `Locale` class in `case_map.cc` directly relates to the `lang` attribute. Case conversion is relevant for case-insensitive comparisons and data normalization.

* **CSS:** CSS properties like `text-transform: uppercase` and `text-transform: lowercase` directly trigger case conversion. The browser's rendering engine will utilize code like this to apply these transformations. Also, case-insensitive attribute selectors in CSS could potentially benefit from this.

**6. Inferring Logic and Potential Issues:**

* **Locale Handling:** The specific handling of "tr", "az", "el", and "lt" suggests these languages have special case conversion rules. A user setting an incorrect `lang` attribute in HTML could lead to unexpected case conversions.

* **Performance Optimizations:** The `TryFastToLowerInvariant` function highlights the focus on performance, especially for common ASCII cases.

* **Unicode Complexity:** The use of ICU and the handling of potential buffer overflows demonstrate the complexities of handling case conversion across the entire Unicode range.

* **`TextOffsetMap`:** This indicates that the length of strings can change during case conversion, which is a crucial detail for developers who need to maintain character positions. Forgetting to account for this could lead to errors when working with string indices.

**7. Structuring the Answer:**

Finally, I'd organize the findings into clear categories (Functionality, Relationship to Web Technologies, Logic and Assumptions, Common Errors) and provide concrete examples to illustrate the points. Using bullet points and code snippets makes the information easier to digest. The thought process involves moving from the general purpose of the file to the specific details of each function and then connecting those details back to the broader context of web development.
This `case_map.cc` file in the Chromium Blink engine is responsible for performing **case mapping** operations on strings. This means converting strings to lowercase or uppercase, potentially taking into account locale-specific rules.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Locale-Aware Case Conversion:** It provides functions to convert strings to lowercase and uppercase, respecting the rules of different languages (locales). This is crucial for proper internationalization.
2. **Locale-Insensitive Case Conversion (Invariant):** It also offers functions for case conversion that are independent of any specific locale. This is often used for internal comparisons and normalization where consistent casing is needed regardless of the user's language.
3. **Optimized ASCII Handling:** The code includes optimizations for strings containing only ASCII characters, making common cases faster.
4. **Handling Unicode Complexity:** It utilizes the ICU (International Components for Unicode) library to handle the complexities of case mapping across the entire Unicode range, including characters with special case conversion rules (e.g., German sharp S 'ß' to 'SS').
5. **Tracking Offset Changes (Optional):**  It can optionally track how the character offsets change during case conversion. This is important when the number of characters changes (like 'ß' to 'SS').

**Relationship with JavaScript, HTML, and CSS:**

This file plays a crucial role in implementing case conversion functionalities exposed to web developers through JavaScript, HTML, and CSS.

**JavaScript:**

* **`String.prototype.toLowerCase()` and `String.prototype.toUpperCase()`:** These JavaScript methods are likely implemented using the functions provided in `case_map.cc`.
    * **Example:**
        ```javascript
        let text = "Hello World";
        let lowercaseText = text.toLowerCase(); // Calls into Blink's case mapping
        console.log(lowercaseText); // Output: "hello world"

        let localeSpecificText = "турбина";
        let uppercaseTextRU = localeSpecificText.toUpperCase('ru'); // Might use locale-aware logic
        console.log(uppercaseTextRU); // Output: "ТУРБИНА" (Russian uppercase)
        ```
    * **Logic Inference:** When `toLowerCase()` or `toUpperCase()` is called without a locale, the "invariant" functions in `case_map.cc` might be used. When a locale is provided, the locale-aware functions are invoked.
    * **Assumption Input/Output:** Input: "EXAMPLE". Output (toLowerCase()): "example". Input: "ﬃ" (Latin small ligature ffi). Output (toUpperCase()): "FFI".

**HTML:**

* **`lang` attribute:** The `CaseMap::Locale` class directly interacts with the `lang` attribute in HTML. The browser uses the `lang` attribute to determine the locale for various operations, including case conversion.
    * **Example:**
        ```html
        <p lang="tr">BURADA</p>
        <script>
          let element = document.querySelector('p');
          console.log(element.textContent.toLowerCase()); // Might use Turkish locale rules
        </script>
        ```
    * **Logic Inference:** When the browser renders text or JavaScript manipulates text within an element with a specific `lang` attribute, the locale information is used to select the appropriate case mapping rules. The `LocaleIdMatchesLang` function in the C++ code is directly related to checking these language codes.
    * **Assumption Input/Output:** Input: "ı" (Latin small letter dotless i, Turkish), locale: "tr". Output (toUpperCase()): "I" (Latin capital letter I). Input: "i", locale: "tr". Output (toUpperCase()): "İ" (Latin capital letter I with dot above).

* **Text transformation via CSS:** CSS properties like `text-transform: uppercase` and `text-transform: lowercase` ultimately rely on the case mapping functionality.
    * **Example:**
        ```html
        <style>
          .uppercase { text-transform: uppercase; }
        </style>
        <p class="uppercase">hello</p>
        ```
    * **Logic Inference:** The rendering engine, when applying the `text-transform` style, calls into the Blink's case mapping functions to convert the text before displaying it.

**CSS:**

* **Case-insensitive attribute selectors:** While not directly related to transforming text, case mapping can be used internally to implement case-insensitive attribute selectors.
    * **Example:**
        ```css
        a[href*="example.com" i] { /* Case-insensitive matching */
          color: blue;
        }
        ```
    * **Logic Inference:**  To perform the case-insensitive comparison, the browser might internally convert both the attribute value and the selector string to the same case using the functions in `case_map.cc`.

**Logic Inference and Assumptions:**

* **`LocaleIdMatchesLang` Function:** This function assumes that locale IDs generally follow a structure where the language code is at the beginning, optionally followed by a hyphen, underscore, or at symbol and further specifiers.
    * **Assumption Input:** `locale_id` = "en-US", `lang` = "en". **Output:** `true`.
    * **Assumption Input:** `locale_id` = "fr_CA", `lang` = "fr". **Output:** `true`.
    * **Assumption Input:** `locale_id` = "de@collation=phonebook", `lang` = "de". **Output:** `true`.
    * **Assumption Input:** `locale_id` = "es", `lang` = "pt". **Output:** `false`.

* **Fast Path for ASCII:** The `TryFastToLowerInvariant` function assumes that if a string is entirely ASCII and contains no uppercase letters, no conversion is needed, providing a performance optimization.
    * **Assumption Input:** "lowercase". **Output:** Returns the original string without modification.
    * **Assumption Input:** "MixedCase". **Output:** Returns `nullptr` (fast path failed).
    * **Assumption Input:** "ALLCAPS". **Output:** Returns `nullptr` (fast path failed).
    * **Assumption Input:** "withNonASCIIé". **Output:** Returns `nullptr` (fast path failed).

* **Handling German Sharp S:** The `ToUpperInvariant` function explicitly handles the case of the German lowercase sharp S (`ß`) being converted to the uppercase "SS". This demonstrates awareness of language-specific case changes that increase string length.
    * **Assumption Input:** "straße". **Output (ToUpperInvariant):** "STRASSE".

**Common Usage Errors and Examples:**

1. **Incorrect Locale:** Providing an incorrect or unsupported locale string can lead to unexpected or incorrect case conversion results.
    * **Example (JavaScript):**
        ```javascript
        let text = "DER";
        let lowercaseText = text.toLowerCase('xx-YY'); // 'xx-YY' is likely not a valid locale
        console.log(lowercaseText); // The result might be the same as toLowerCase() without a locale, or an error might occur.
        ```

2. **Assuming Invariant Conversion is Always Simple:** Developers might incorrectly assume that invariant case conversion is always a simple character-by-character mapping. However, Unicode has characters whose case conversion is more complex even in a locale-insensitive context.
    * **Example (Conceptual):** A developer might write code expecting `toUpperCase("ﬃ")` to always result in "FFI", but depending on the underlying implementation and Unicode version, there might be edge cases or variations.

3. **Ignoring Potential Length Changes:** When performing uppercase conversion, especially in languages like German, the string length can change. Failing to account for this can lead to buffer overflows or incorrect string manipulation.
    * **Example (Conceptual):** A developer might allocate a buffer assuming the uppercase version of a string will have the same length, which would be wrong if the string contains "ß".

4. **Mixing Locale-Sensitive and -Insensitive Operations:** Inconsistent use of locale-aware and locale-insensitive functions can lead to bugs, especially when comparing strings or normalizing data.
    * **Example (Conceptual):** Comparing a string converted to lowercase using a specific locale with another string converted to lowercase using the invariant rules might yield unexpected results if the locale has special case conversion rules.

5. **Forgetting the `lang` Attribute:** When dealing with HTML content, forgetting to set the appropriate `lang` attribute can result in the browser applying default or incorrect locale rules for case conversion and other language-specific operations.

This `case_map.cc` file is a fundamental part of how Chromium handles text in a multilingual environment, ensuring that case conversion is performed correctly according to the rules of different languages. It bridges the gap between low-level Unicode handling and the high-level APIs exposed to web developers.

Prompt: 
```
这是目录为blink/renderer/platform/wtf/text/case_map.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/wtf/text/case_map.h"

#include <unicode/casemap.h>

#include "base/notreached.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_impl.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/text/text_offset_map.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace WTF {

namespace {

// `lang` - Language code.  Now it is one of "tr", "az", "el", and "lt".
inline bool LocaleIdMatchesLang(const AtomicString& locale_id,
                                const StringView lang) {
  const wtf_size_t lang_length = lang.length();
  CHECK(lang_length == 2u || lang_length == 3u);
  const StringImpl* locale_id_impl = locale_id.Impl();
  if (!locale_id_impl || !locale_id_impl->StartsWithIgnoringASCIICase(lang)) {
    return false;
  }
  if (locale_id_impl->length() == lang_length) {
    return true;
  }
  const UChar maybe_delimiter = (*locale_id_impl)[lang_length];
  return maybe_delimiter == '-' || maybe_delimiter == '_' ||
         maybe_delimiter == '@';
}

enum class CaseMapType { kLower, kUpper };

scoped_refptr<StringImpl> CaseConvert(CaseMapType type,
                                      StringImpl* source,
                                      const char* locale,
                                      TextOffsetMap* offset_map = nullptr) {
  DCHECK(source);
  CHECK_LE(source->length(),
           static_cast<wtf_size_t>(std::numeric_limits<int32_t>::max()));

  scoped_refptr<StringImpl> upconverted = source->UpconvertedString();
  const base::span<const UChar> source16 = upconverted->Span16();

  base::span<UChar> data16;
  scoped_refptr<StringImpl> output =
      StringImpl::CreateUninitialized(source16.size(), data16);
  while (true) {
    UErrorCode status = U_ZERO_ERROR;
    icu::Edits edits;
    wtf_size_t target_length;
    switch (type) {
      case CaseMapType::kLower:
        target_length = icu::CaseMap::toLower(
            locale, /* options */ 0,
            reinterpret_cast<const char16_t*>(source16.data()), source16.size(),
            reinterpret_cast<char16_t*>(data16.data()), data16.size(), &edits,
            status);
        break;
      case CaseMapType::kUpper:
        target_length = icu::CaseMap::toUpper(
            locale, /* options */ 0,
            reinterpret_cast<const char16_t*>(source16.data()), source16.size(),
            reinterpret_cast<char16_t*>(data16.data()), data16.size(), &edits,
            status);
        break;
    }
    if (U_SUCCESS(status)) {
      if (!edits.hasChanges())
        return source;

      if (offset_map)
        offset_map->Append(edits);

      if (source16.size() == target_length) {
        return output;
      }
      return output->Substring(0, target_length);
    }

    // Expand the buffer and retry if the target is longer.
    if (status == U_BUFFER_OVERFLOW_ERROR) {
      output = StringImpl::CreateUninitialized(target_length, data16);
      continue;
    }

    NOTREACHED();
  }
}

}  // namespace

const char* CaseMap::Locale::turkic_or_azeri_ = "tr";
const char* CaseMap::Locale::greek_ = "el";
const char* CaseMap::Locale::lithuanian_ = "lt";

CaseMap::Locale::Locale(const AtomicString& locale) {
  // Use the more optimized code path most of the time.
  //
  // Only Turkic (tr and az) languages and Lithuanian requires
  // locale-specific lowercasing rules. Even though CLDR has el-Lower,
  // it's identical to the locale-agnostic lowercasing. Context-dependent
  // handling of Greek capital sigma is built into the common lowercasing
  // function in ICU.
  //
  // Only Turkic (tr and az) languages, Greek and Lithuanian require
  // locale-specific uppercasing rules.
  if (LocaleIdMatchesLang(locale, "tr") || LocaleIdMatchesLang(locale, "az"))
      [[unlikely]] {
    case_map_locale_ = turkic_or_azeri_;
  } else if (LocaleIdMatchesLang(locale, "el")) [[unlikely]] {
    case_map_locale_ = greek_;
  } else if (LocaleIdMatchesLang(locale, "lt")) [[unlikely]] {
    case_map_locale_ = lithuanian_;
  } else {
    case_map_locale_ = nullptr;
  }
}

scoped_refptr<StringImpl> CaseMap::TryFastToLowerInvariant(StringImpl* source) {
  DCHECK(source);

  // Note: This is a hot function in the Dromaeo benchmark, specifically the
  // no-op code path up through the first 'return' statement.

  // First scan the string for uppercase and non-ASCII characters:
  if (source->Is8Bit()) {
    const base::span<const LChar> source8 = source->Span8();
    size_t first_index_to_be_lowered = source8.size();
    for (size_t i = 0; i < source8.size(); ++i) {
      const LChar ch = source8[i];
      if (IsASCIIUpper(ch) || ch & ~0x7F) [[unlikely]] {
        first_index_to_be_lowered = i;
        break;
      }
    }

    // Nothing to do if the string is all ASCII with no uppercase.
    if (first_index_to_be_lowered == source8.size()) {
      return source;
    }

    base::span<LChar> data8;
    scoped_refptr<StringImpl> new_impl =
        StringImpl::CreateUninitialized(source8.size(), data8);

    auto [source8_already_lowercase, source8_tail] =
        source8.split_at(first_index_to_be_lowered);
    auto [data8_already_lowercase, data8_tail] =
        data8.split_at(first_index_to_be_lowered);

    data8_already_lowercase.copy_from(source8_already_lowercase);

    for (size_t i = 0; i < source8_tail.size(); ++i) {
      const LChar ch = source8_tail[i];
      LChar lowered_ch;
      if (ch & ~0x7F) [[unlikely]] {
        lowered_ch = static_cast<LChar>(unicode::ToLower(ch));
      } else {
        lowered_ch = ToASCIILower(ch);
      }
      data8_tail[i] = lowered_ch;
    }
    return new_impl;
  }

  bool no_upper = true;
  UChar ored = 0;

  const base::span<const UChar> source16 = source->Span16();
  for (size_t i = 0; i < source16.size(); ++i) {
    const UChar ch = source16[i];
    if (IsASCIIUpper(ch)) [[unlikely]] {
      no_upper = false;
    }
    ored |= ch;
  }
  // Nothing to do if the string is all ASCII with no uppercase.
  if (no_upper && !(ored & ~0x7F))
    return source;

  CHECK_LE(source16.size(),
           static_cast<wtf_size_t>(std::numeric_limits<int32_t>::max()));

  if (!(ored & ~0x7F)) {
    base::span<UChar> data16;
    scoped_refptr<StringImpl> new_impl =
        StringImpl::CreateUninitialized(source16.size(), data16);

    for (size_t i = 0; i < source16.size(); ++i) {
      data16[i] = ToASCIILower(source16[i]);
    }
    return new_impl;
  }

  // The fast code path was not able to handle this case.
  return nullptr;
}

scoped_refptr<StringImpl> CaseMap::FastToLowerInvariant(StringImpl* source) {
  // Note: This is a hot function in the Dromaeo benchmark.
  DCHECK(source);
  if (scoped_refptr<StringImpl> result = TryFastToLowerInvariant(source))
    return result;
  const char* locale = "";  // "" = root locale.
  return CaseConvert(CaseMapType::kLower, source, locale);
}

scoped_refptr<StringImpl> CaseMap::ToLowerInvariant(StringImpl* source,
                                                    TextOffsetMap* offset_map) {
  DCHECK(source);
  DCHECK(!offset_map || offset_map->IsEmpty());
  if (scoped_refptr<StringImpl> result = TryFastToLowerInvariant(source))
    return result;
  const char* locale = "";  // "" = root locale.
  return CaseConvert(CaseMapType::kLower, source, locale, offset_map);
}

scoped_refptr<StringImpl> CaseMap::ToUpperInvariant(StringImpl* source,
                                                    TextOffsetMap* offset_map) {
  DCHECK(source);
  DCHECK(!offset_map || offset_map->IsEmpty());

  // This function could be optimized for no-op cases the way LowerUnicode() is,
  // but in empirical testing, few actual calls to UpperUnicode() are no-ops, so
  // it wouldn't be worth the extra time for pre-scanning.

  CHECK_LE(source->length(),
           static_cast<wtf_size_t>(std::numeric_limits<int32_t>::max()));

  if (source->Is8Bit()) {
    const base::span<const LChar> source8 = source->Span8();
    base::span<LChar> data8;
    scoped_refptr<StringImpl> new_impl =
        StringImpl::CreateUninitialized(source8.size(), data8);

    // Do a faster loop for the case where all the characters are ASCII.
    LChar ored = 0;
    for (size_t i = 0; i < source8.size(); ++i) {
      const LChar c = source8[i];
      ored |= c;
      data8[i] = ToASCIIUpper(c);
    }
    if (!(ored & ~0x7F))
      return new_impl;

    // Do a slower implementation for cases that include non-ASCII Latin-1
    // characters.
    size_t count_sharp_s_characters = 0;

    // There are two special cases.
    //  1. latin-1 characters when converted to upper case are 16 bit
    //     characters.
    //  2. Lower case sharp-S converts to "SS" (two characters)
    for (size_t i = 0; i < source8.size(); ++i) {
      const LChar c = source8[i];
      if (c == kSmallLetterSharpSCharacter) [[unlikely]] {
        ++count_sharp_s_characters;
      }
      const UChar upper = static_cast<UChar>(unicode::ToUpper(c));
      if (upper > 0xff) [[unlikely]] {
        // Since this upper-cased character does not fit in an 8-bit string, we
        // need to take the 16-bit path.
        goto upconvert;
      }
      data8[i] = static_cast<LChar>(upper);
    }

    if (!count_sharp_s_characters) {
      return new_impl;
    }

    // We have numberSSCharacters sharp-s characters, but none of the other
    // special characters.
    new_impl = StringImpl::CreateUninitialized(
        source8.size() + count_sharp_s_characters, data8);

    size_t dest_index = 0;
    for (size_t i = 0; i < source8.size(); ++i) {
      const LChar c = source8[i];
      if (c == kSmallLetterSharpSCharacter) {
        data8[dest_index++] = 'S';
        data8[dest_index++] = 'S';
        if (offset_map)
          offset_map->Append(i + 1, dest_index);
      } else {
        data8[dest_index++] = static_cast<LChar>(unicode::ToUpper(c));
      }
    }
    return new_impl;
  }

upconvert:
  scoped_refptr<StringImpl> upconverted = source->UpconvertedString();
  base::span<const UChar> source16 = upconverted->Span16();

  base::span<UChar> data16;
  scoped_refptr<StringImpl> new_impl =
      StringImpl::CreateUninitialized(source16.size(), data16);

  // Do a faster loop for the case where all the characters are ASCII.
  UChar ored = 0;
  for (size_t i = 0; i < source16.size(); ++i) {
    const UChar c = source16[i];
    ored |= c;
    data16[i] = ToASCIIUpper(c);
  }
  if (!(ored & ~0x7F))
    return new_impl;

  // Do a slower implementation for cases that include non-ASCII characters.
  const char* locale = "";  // "" = root locale.
  return CaseConvert(CaseMapType::kUpper, source, locale, offset_map);
}

scoped_refptr<StringImpl> CaseMap::ToLower(StringImpl* source,
                                           TextOffsetMap* offset_map) const {
  DCHECK(source);
  DCHECK(!offset_map || offset_map->IsEmpty());

  if (!case_map_locale_)
    return ToLowerInvariant(source, offset_map);
  return CaseConvert(CaseMapType::kLower, source, case_map_locale_, offset_map);
}

scoped_refptr<StringImpl> CaseMap::ToUpper(StringImpl* source,
                                           TextOffsetMap* offset_map) const {
  DCHECK(source);
  DCHECK(!offset_map || offset_map->IsEmpty());

  if (!case_map_locale_)
    return ToUpperInvariant(source, offset_map);
  return CaseConvert(CaseMapType::kUpper, source, case_map_locale_, offset_map);
}

String CaseMap::ToLower(const String& source, TextOffsetMap* offset_map) const {
  DCHECK(!offset_map || offset_map->IsEmpty());

  if (StringImpl* impl = source.Impl())
    return ToLower(impl, offset_map);
  return String();
}

String CaseMap::ToUpper(const String& source, TextOffsetMap* offset_map) const {
  DCHECK(!offset_map || offset_map->IsEmpty());

  if (StringImpl* impl = source.Impl())
    return ToUpper(impl, offset_map);
  return String();
}

}  // namespace WTF

"""

```