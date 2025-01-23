Response: The user wants a summary of the C++ code in `v8/src/objects/js-number-format.cc`.
The request is for the first part of the file.
The goal is to understand the functionality of this part of the code, particularly its relation to JavaScript's number formatting capabilities.

**Plan:**
1. Read through the code, identifying key data structures, enums, and functions.
2. Summarize the purpose of the defined enums and their relation to number formatting options.
3. Identify functions related to parsing number format options from strings (skeletons).
4. Look for functions that interact with the ICU library for internationalization.
5. If any direct connection to JavaScript functionality is apparent, note it down and prepare a JavaScript example.
This C++ code file (`v8/src/objects/js-number-format.cc`) is a part of the V8 JavaScript engine and focuses on implementing the functionality for internationalized number formatting, which is exposed to JavaScript through the `Intl.NumberFormat` object.

Here's a breakdown of the functionality in this first part of the file:

**Core Functionality:**

* **Defines enums representing various number formatting options:**  The code defines several enums like `Style`, `CurrencyDisplay`, `CurrencySign`, `UnitDisplay`, `Notation`, `CompactDisplay`, `SignDisplay`, and `UseGrouping`. These enums correspond directly to the options that can be set when creating an `Intl.NumberFormat` object in JavaScript.
* **Provides mappings between JavaScript option names and ICU library constants:** Functions like `ToUNumberUnitWidth`, `ToUNumberSignDisplay`, `ToICUNotation`, `ToUNumberFormatRoundingMode`, and `ToUNumberGroupingStrategy` translate the enum values (representing JavaScript options) into the corresponding constants used by the ICU (International Components for Unicode) library, which handles the actual formatting.
* **Handles unit identifiers:** The code includes functions `IsSanctionedUnitIdentifier` and `IsWellFormedUnitIdentifier` to validate unit strings used in number formatting, ensuring they conform to the specifications. This relates to the `unit` option in `Intl.NumberFormat`.
* **Manages currency information:**  The `CurrencyDigits` function retrieves the default number of fraction digits for a given currency, crucial for currency formatting. `IsWellFormedCurrencyCode` validates currency codes.
* **Parses formatting information from "skeletons":**  The code contains several functions (e.g., `StyleAsString`, `CurrencyDisplayString`, `UseGroupingFromSkeleton`, `CurrencyFromSkeleton`, `NumberingSystemFromSkeleton`) that extract formatting information from ICU "skeletons". Skeletons are compact string representations of formatting patterns used by ICU. These functions help in understanding the formatting rules after they have been resolved by ICU.

**Relationship to JavaScript:**

This C++ code directly supports the functionality of the `Intl.NumberFormat` object in JavaScript. When you create an `Intl.NumberFormat` instance in JavaScript with specific options, the V8 engine internally uses this C++ code to:

1. **Validate the provided options:**  The enums and validation functions ensure the options are valid according to the ECMAScript Internationalization API specification.
2. **Translate JavaScript options to ICU settings:** The mapping functions convert the JavaScript options into parameters that the ICU library understands.
3. **Utilize the ICU library for formatting:**  ICU is the underlying library used for performing the actual number formatting according to the specified locale and options.

**JavaScript Example:**

```javascript
// Creating an Intl.NumberFormat object with specific options
const formatter = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  currencyDisplay: 'symbol',
  signDisplay: 'exceptZero'
});

// Formatting a number
const formattedNumber = formatter.format(-123.45);
console.log(formattedNumber); // Output: -$123.45

const formatterAccounting = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  currencySign: 'accounting',
  signDisplay: 'always'
});
const formattedAccounting = formatterAccounting.format(-123.45);
console.log(formattedAccounting); // Output: ($123.45)

const formatterUnit = new Intl.NumberFormat('en-US', {
  style: 'unit',
  unit: 'mile-per-hour',
  unitDisplay: 'short'
});
const formattedUnit = formatterUnit.format(60);
console.log(formattedUnit); // Output: 60 mph
```

In this example:

* The `style: 'currency'` in JavaScript corresponds to the `Style::CURRENCY` enum in the C++ code.
* `currency: 'USD'` is used by the C++ code to fetch the correct currency symbol and default fraction digits.
* `currencyDisplay: 'symbol'` maps to the `CurrencyDisplay::SYMBOL` enum.
* `signDisplay: 'exceptZero'` maps to the `SignDisplay::EXCEPT_ZERO` enum.
* `currencySign: 'accounting'` maps to the `CurrencySign::ACCOUNTING` enum.
* `style: 'unit'` and `unit: 'mile-per-hour'` utilize the unit handling logic within the C++ code.
* `unitDisplay: 'short'` maps to the `UnitDisplay::SHORT` enum.

The C++ code you provided is responsible for setting up and configuring the ICU library based on the options provided in the JavaScript `Intl.NumberFormat` constructor, enabling the correct internationalized number formatting.

### 提示词
```
这是目录为v8/src/objects/js-number-format.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_INTL_SUPPORT
#error Internationalization is expected to be enabled.
#endif  // V8_INTL_SUPPORT

#include "src/objects/js-number-format.h"

#include <set>
#include <string>

#include "src/execution/isolate.h"
#include "src/numbers/conversions.h"
#include "src/objects/intl-objects.h"
#include "src/objects/js-number-format-inl.h"
#include "src/objects/managed-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/option-utils.h"
#include "src/strings/char-predicates-inl.h"
#include "unicode/currunit.h"
#include "unicode/locid.h"
#include "unicode/numberformatter.h"
#include "unicode/numberrangeformatter.h"
#include "unicode/numsys.h"
#include "unicode/ucurr.h"
#include "unicode/uloc.h"
#include "unicode/unumberformatter.h"
#include "unicode/uvernum.h"  // for U_ICU_VERSION_MAJOR_NUM

namespace v8 {
namespace internal {

namespace {

// This is to work around ICU's comparison operators not being compliant with
// clang's -Wambiguous-reversed-operator in >=C++20.
#define AVOID_AMBIGUOUS_OP_WARNING(x) *static_cast<icu::UObject*>(&x)

// [[Style]] is one of the values "decimal", "percent", "currency",
// or "unit" identifying the style of the number format.
enum class Style { DECIMAL, PERCENT, CURRENCY, UNIT };

// [[CurrencyDisplay]] is one of the values "code", "symbol", "name",
// or "narrowSymbol" identifying the display of the currency number format.
enum class CurrencyDisplay {
  CODE,
  SYMBOL,
  NAME,
  NARROW_SYMBOL,
};

// [[CurrencySign]] is one of the String values "standard" or "accounting",
// specifying whether to render negative numbers in accounting format, often
// signified by parenthesis. It is only used when [[Style]] has the value
// "currency" and when [[SignDisplay]] is not "never".
enum class CurrencySign {
  STANDARD,
  ACCOUNTING,
};

// [[UnitDisplay]] is one of the String values "short", "narrow", or "long",
// specifying whether to display the unit as a symbol, narrow symbol, or
// localized long name if formatting with the "unit" style. It is
// only used when [[Style]] has the value "unit".
enum class UnitDisplay {
  SHORT,
  NARROW,
  LONG,
};

// [[Notation]] is one of the String values "standard", "scientific",
// "engineering", or "compact", specifying whether the number should be
// displayed without scaling, scaled to the units place with the power of ten
// in scientific notation, scaled to the nearest thousand with the power of
// ten in scientific notation, or scaled to the nearest locale-dependent
// compact decimal notation power of ten with the corresponding compact
// decimal notation affix.

enum class Notation {
  STANDARD,
  SCIENTIFIC,
  ENGINEERING,
  COMPACT,
};

// [[CompactDisplay]] is one of the String values "short" or "long",
// specifying whether to display compact notation affixes in short form ("5K")
// or long form ("5 thousand") if formatting with the "compact" notation. It
// is only used when [[Notation]] has the value "compact".
enum class CompactDisplay {
  SHORT,
  LONG,
};

// [[SignDisplay]] is one of the String values "auto", "always", "never", or
// "exceptZero", specifying whether to show the sign on negative numbers
// only, positive and negative numbers including zero, neither positive nor
// negative numbers, or positive and negative numbers but not zero.
enum class SignDisplay {
  AUTO,
  ALWAYS,
  NEVER,
  EXCEPT_ZERO,
  NEGATIVE,
};

// [[UseGrouping]] is ....
enum class UseGrouping {
  OFF,
  MIN2,
  AUTO,
  ALWAYS,
};

UNumberUnitWidth ToUNumberUnitWidth(CurrencyDisplay currency_display) {
  switch (currency_display) {
    case CurrencyDisplay::SYMBOL:
      return UNumberUnitWidth::UNUM_UNIT_WIDTH_SHORT;
    case CurrencyDisplay::CODE:
      return UNumberUnitWidth::UNUM_UNIT_WIDTH_ISO_CODE;
    case CurrencyDisplay::NAME:
      return UNumberUnitWidth::UNUM_UNIT_WIDTH_FULL_NAME;
    case CurrencyDisplay::NARROW_SYMBOL:
      return UNumberUnitWidth::UNUM_UNIT_WIDTH_NARROW;
  }
}

UNumberUnitWidth ToUNumberUnitWidth(UnitDisplay unit_display) {
  switch (unit_display) {
    case UnitDisplay::SHORT:
      return UNumberUnitWidth::UNUM_UNIT_WIDTH_SHORT;
    case UnitDisplay::LONG:
      return UNumberUnitWidth::UNUM_UNIT_WIDTH_FULL_NAME;
    case UnitDisplay::NARROW:
      return UNumberUnitWidth::UNUM_UNIT_WIDTH_NARROW;
  }
}

UNumberSignDisplay ToUNumberSignDisplay(SignDisplay sign_display,
                                        CurrencySign currency_sign) {
  switch (sign_display) {
    case SignDisplay::AUTO:
      if (currency_sign == CurrencySign::ACCOUNTING) {
        return UNumberSignDisplay::UNUM_SIGN_ACCOUNTING;
      }
      DCHECK(currency_sign == CurrencySign::STANDARD);
      return UNumberSignDisplay::UNUM_SIGN_AUTO;
    case SignDisplay::NEVER:
      return UNumberSignDisplay::UNUM_SIGN_NEVER;
    case SignDisplay::ALWAYS:
      if (currency_sign == CurrencySign::ACCOUNTING) {
        return UNumberSignDisplay::UNUM_SIGN_ACCOUNTING_ALWAYS;
      }
      DCHECK(currency_sign == CurrencySign::STANDARD);
      return UNumberSignDisplay::UNUM_SIGN_ALWAYS;
    case SignDisplay::EXCEPT_ZERO:
      if (currency_sign == CurrencySign::ACCOUNTING) {
        return UNumberSignDisplay::UNUM_SIGN_ACCOUNTING_EXCEPT_ZERO;
      }
      DCHECK(currency_sign == CurrencySign::STANDARD);
      return UNumberSignDisplay::UNUM_SIGN_EXCEPT_ZERO;
    case SignDisplay::NEGATIVE:
      if (currency_sign == CurrencySign::ACCOUNTING) {
        return UNumberSignDisplay::UNUM_SIGN_ACCOUNTING_NEGATIVE;
      }
      DCHECK(currency_sign == CurrencySign::STANDARD);
      return UNumberSignDisplay::UNUM_SIGN_NEGATIVE;
  }
}

icu::number::Notation ToICUNotation(Notation notation,
                                    CompactDisplay compact_display) {
  switch (notation) {
    case Notation::STANDARD:
      return icu::number::Notation::simple();
    case Notation::SCIENTIFIC:
      return icu::number::Notation::scientific();
    case Notation::ENGINEERING:
      return icu::number::Notation::engineering();
    // 29. If notation is "compact", then
    case Notation::COMPACT:
      // 29. a. Set numberFormat.[[CompactDisplay]] to compactDisplay.
      if (compact_display == CompactDisplay::SHORT) {
        return icu::number::Notation::compactShort();
      }
      DCHECK(compact_display == CompactDisplay::LONG);
      return icu::number::Notation::compactLong();
  }
}

UNumberFormatRoundingMode ToUNumberFormatRoundingMode(
    Intl::RoundingMode rounding_mode) {
  switch (rounding_mode) {
    case Intl::RoundingMode::kCeil:
      return UNumberFormatRoundingMode::UNUM_ROUND_CEILING;
    case Intl::RoundingMode::kFloor:
      return UNumberFormatRoundingMode::UNUM_ROUND_FLOOR;
    case Intl::RoundingMode::kExpand:
      return UNumberFormatRoundingMode::UNUM_ROUND_UP;
    case Intl::RoundingMode::kTrunc:
      return UNumberFormatRoundingMode::UNUM_ROUND_DOWN;
    case Intl::RoundingMode::kHalfCeil:
      return UNumberFormatRoundingMode::UNUM_ROUND_HALF_CEILING;
    case Intl::RoundingMode::kHalfFloor:
      return UNumberFormatRoundingMode::UNUM_ROUND_HALF_FLOOR;
    case Intl::RoundingMode::kHalfExpand:
      return UNumberFormatRoundingMode::UNUM_ROUND_HALFUP;
    case Intl::RoundingMode::kHalfTrunc:
      return UNumberFormatRoundingMode::UNUM_ROUND_HALFDOWN;
    case Intl::RoundingMode::kHalfEven:
      return UNumberFormatRoundingMode::UNUM_ROUND_HALFEVEN;
  }
}

UNumberGroupingStrategy ToUNumberGroupingStrategy(UseGrouping use_grouping) {
  switch (use_grouping) {
    case UseGrouping::OFF:
      return UNumberGroupingStrategy::UNUM_GROUPING_OFF;
    case UseGrouping::MIN2:
      return UNumberGroupingStrategy::UNUM_GROUPING_MIN2;
    case UseGrouping::AUTO:
      return UNumberGroupingStrategy::UNUM_GROUPING_AUTO;
    case UseGrouping::ALWAYS:
      return UNumberGroupingStrategy::UNUM_GROUPING_ON_ALIGNED;
  }
}

std::map<const std::string, icu::MeasureUnit> CreateUnitMap() {
  UErrorCode status = U_ZERO_ERROR;
  int32_t total = icu::MeasureUnit::getAvailable(nullptr, 0, status);
  DCHECK(U_FAILURE(status));
  status = U_ZERO_ERROR;
  std::vector<icu::MeasureUnit> units(total);
  total = icu::MeasureUnit::getAvailable(units.data(), total, status);
  DCHECK(U_SUCCESS(status));
  std::map<const std::string, icu::MeasureUnit> map;
  std::set<std::string> sanctioned(Intl::SanctionedSimpleUnits());
  for (auto it = units.begin(); it != units.end(); ++it) {
    // Need to skip none/percent
    if (sanctioned.count(it->getSubtype()) > 0 &&
        strcmp("none", it->getType()) != 0) {
      map[it->getSubtype()] = *it;
    }
  }
  return map;
}

class UnitFactory {
 public:
  UnitFactory() : map_(CreateUnitMap()) {}
  virtual ~UnitFactory() = default;

  // ecma402 #sec-issanctionedsimpleunitidentifier
  icu::MeasureUnit create(const std::string& unitIdentifier) {
    // 1. If unitIdentifier is in the following list, return true.
    auto found = map_.find(unitIdentifier);
    if (found != map_.end()) {
      return found->second;
    }
    // 2. Return false.
    return icu::MeasureUnit();
  }

 private:
  std::map<const std::string, icu::MeasureUnit> map_;
};

// ecma402 #sec-issanctionedsimpleunitidentifier
icu::MeasureUnit IsSanctionedUnitIdentifier(const std::string& unit) {
  static base::LazyInstance<UnitFactory>::type factory =
      LAZY_INSTANCE_INITIALIZER;
  return factory.Pointer()->create(unit);
}

// ecma402 #sec-iswellformedunitidentifier
Maybe<std::pair<icu::MeasureUnit, icu::MeasureUnit>> IsWellFormedUnitIdentifier(
    Isolate* isolate, const std::string& unit) {
  icu::MeasureUnit result = IsSanctionedUnitIdentifier(unit);
  icu::MeasureUnit none = icu::MeasureUnit();
  // 1. If the result of IsSanctionedUnitIdentifier(unitIdentifier) is true,
  // then
  if (result != AVOID_AMBIGUOUS_OP_WARNING(none)) {
    // a. Return true.
    std::pair<icu::MeasureUnit, icu::MeasureUnit> pair(result, none);
    return Just(pair);
  }
  // 2. If the substring "-per-" does not occur exactly once in unitIdentifier,
  // then
  size_t first_per = unit.find("-per-");
  if (first_per == std::string::npos ||
      unit.find("-per-", first_per + 5) != std::string::npos) {
    // a. Return false.
    return Nothing<std::pair<icu::MeasureUnit, icu::MeasureUnit>>();
  }
  // 3. Let numerator be the substring of unitIdentifier from the beginning to
  // just before "-per-".
  std::string numerator = unit.substr(0, first_per);

  // 4. If the result of IsSanctionedUnitIdentifier(numerator) is false, then
  result = IsSanctionedUnitIdentifier(numerator);
  if (result == AVOID_AMBIGUOUS_OP_WARNING(none)) {
    // a. Return false.
    return Nothing<std::pair<icu::MeasureUnit, icu::MeasureUnit>>();
  }
  // 5. Let denominator be the substring of unitIdentifier from just after
  // "-per-" to the end.
  std::string denominator = unit.substr(first_per + 5);

  // 6. If the result of IsSanctionedUnitIdentifier(denominator) is false, then
  icu::MeasureUnit den_result = IsSanctionedUnitIdentifier(denominator);
  if (den_result == AVOID_AMBIGUOUS_OP_WARNING(none)) {
    // a. Return false.
    return Nothing<std::pair<icu::MeasureUnit, icu::MeasureUnit>>();
  }
  // 7. Return true.
  std::pair<icu::MeasureUnit, icu::MeasureUnit> pair(result, den_result);
  return Just(pair);
}

// ecma-402/#sec-currencydigits
// The currency is expected to an all upper case string value.
int CurrencyDigits(const icu::UnicodeString& currency) {
  UErrorCode status = U_ZERO_ERROR;
  uint32_t fraction_digits = ucurr_getDefaultFractionDigits(
      reinterpret_cast<const UChar*>(currency.getBuffer()), &status);
  // For missing currency codes, default to the most common, 2
  return U_SUCCESS(status) ? fraction_digits : 2;
}

bool IsAToZ(char ch) {
  return base::IsInRange(AsciiAlphaToLower(ch), 'a', 'z');
}

// ecma402/#sec-iswellformedcurrencycode
bool IsWellFormedCurrencyCode(const std::string& currency) {
  // Verifies that the input is a well-formed ISO 4217 currency code.
  // ecma402/#sec-currency-codes
  // 2. If the number of elements in normalized is not 3, return false.
  if (currency.length() != 3) return false;
  // 1. Let normalized be the result of mapping currency to upper case as
  //   described in 6.1.
  //
  // 3. If normalized contains any character that is not in
  // the range "A" to "Z" (U+0041 to U+005A), return false.
  //
  // 4. Return true.
  // Don't uppercase to test. It could convert invalid code into a valid one.
  // For example \u00DFP (Eszett+P) becomes SSP.
  return (IsAToZ(currency[0]) && IsAToZ(currency[1]) && IsAToZ(currency[2]));
}

// Return the style as a String.
Handle<String> StyleAsString(Isolate* isolate, Style style) {
  switch (style) {
    case Style::PERCENT:
      return ReadOnlyRoots(isolate).percent_string_handle();
    case Style::CURRENCY:
      return ReadOnlyRoots(isolate).currency_string_handle();
    case Style::UNIT:
      return ReadOnlyRoots(isolate).unit_string_handle();
    case Style::DECIMAL:
      return ReadOnlyRoots(isolate).decimal_string_handle();
  }
  UNREACHABLE();
}

// Parse the 'currencyDisplay' from the skeleton.
Handle<String> CurrencyDisplayString(Isolate* isolate,
                                     const icu::UnicodeString& skeleton) {
  // Ex: skeleton as
  // "currency/TWD .00 rounding-mode-half-up unit-width-iso-code"
  if (skeleton.indexOf("unit-width-iso-code") >= 0) {
    return ReadOnlyRoots(isolate).code_string_handle();
  }
  // Ex: skeleton as
  // "currency/TWD .00 rounding-mode-half-up unit-width-full-name;"
  if (skeleton.indexOf("unit-width-full-name") >= 0) {
    return ReadOnlyRoots(isolate).name_string_handle();
  }
  // Ex: skeleton as
  // "currency/TWD .00 rounding-mode-half-up unit-width-narrow;
  if (skeleton.indexOf("unit-width-narrow") >= 0) {
    return ReadOnlyRoots(isolate).narrowSymbol_string_handle();
  }
  // Ex: skeleton as "currency/TWD .00 rounding-mode-half-up"
  return ReadOnlyRoots(isolate).symbol_string_handle();
}

Handle<Object> UseGroupingFromSkeleton(Isolate* isolate,
                                       const icu::UnicodeString& skeleton) {
  Factory* factory = isolate->factory();
  static const char* group = "group-";
  int32_t start = skeleton.indexOf(group);
  if (start >= 0) {
    DCHECK_EQ(6, strlen(group));
    icu::UnicodeString check = skeleton.tempSubString(start + 6);
    // Ex: skeleton as
    // .### rounding-mode-half-up group-off
    if (check.startsWith("off")) {
      return factory->false_value();
    }
    // Ex: skeleton as
    // .### rounding-mode-half-up group-min2
    if (check.startsWith("min2")) {
      return ReadOnlyRoots(isolate).min2_string_handle();
    }
    // Ex: skeleton as
    // .### rounding-mode-half-up group-on-aligned
    if (check.startsWith("on-aligned")) {
      return ReadOnlyRoots(isolate).always_string_handle();
    }
  }
  // Ex: skeleton as
  // .###
  return ReadOnlyRoots(isolate).auto_string_handle();
}

// Parse currency code from skeleton. For example, skeleton as
// "currency/TWD .00 rounding-mode-half-up unit-width-full-name;"
const icu::UnicodeString CurrencyFromSkeleton(
    const icu::UnicodeString& skeleton) {
  const char currency[] = "currency/";
  int32_t index = skeleton.indexOf(currency);
  if (index < 0) return "";
  index += static_cast<int32_t>(std::strlen(currency));
  return skeleton.tempSubString(index, 3);
}

}  // namespace
const icu::UnicodeString JSNumberFormat::NumberingSystemFromSkeleton(
    const icu::UnicodeString& skeleton) {
  const char numbering_system[] = "numbering-system/";
  int32_t index = skeleton.indexOf(numbering_system);
  if (index < 0) return "latn";
  index += static_cast<int32_t>(std::strlen(numbering_system));
  const icu::UnicodeString res = skeleton.tempSubString(index);
  index = res.indexOf(" ");
  if (index < 0) return res;
  return res.tempSubString(0, index);
}

namespace {

// Return CurrencySign as string based on skeleton.
Handle<String> CurrencySignString(Isolate* isolate,
                                  const icu::UnicodeString& skeleton) {
  // Ex: skeleton as
  // "currency/TWD .00 rounding-mode-half-up sign-accounting-always" OR
  // "currency/TWD .00 rounding-mode-half-up sign-accounting-except-zero"
  if (skeleton.indexOf("sign-accounting") >= 0) {
    return ReadOnlyRoots(isolate).accounting_string_handle();
  }
  return ReadOnlyRoots(isolate).standard_string_handle();
}

// Return UnitDisplay as string based on skeleton.
Handle<String> UnitDisplayString(Isolate* isolate,
                                 const icu::UnicodeString& skeleton) {
  // Ex: skeleton as
  // "unit/length-meter .### rounding-mode-half-up unit-width-full-name"
  if (skeleton.indexOf("unit-width-full-name") >= 0) {
    return ReadOnlyRoots(isolate).long_string_handle();
  }
  // Ex: skeleton as
  // "unit/length-meter .### rounding-mode-half-up unit-width-narrow".
  if (skeleton.indexOf("unit-width-narrow") >= 0) {
    return ReadOnlyRoots(isolate).narrow_string_handle();
  }
  // Ex: skeleton as
  // "unit/length-foot .### rounding-mode-half-up"
  return ReadOnlyRoots(isolate).short_string_handle();
}

// Parse Notation from skeleton.
Notation NotationFromSkeleton(const icu::UnicodeString& skeleton) {
  // Ex: skeleton as
  // "scientific .### rounding-mode-half-up"
  if (skeleton.indexOf("scientific") >= 0) {
    return Notation::SCIENTIFIC;
  }
  // Ex: skeleton as
  // "engineering .### rounding-mode-half-up"
  if (skeleton.indexOf("engineering") >= 0) {
    return Notation::ENGINEERING;
  }
  // Ex: skeleton as
  // "compact-short .### rounding-mode-half-up" or
  // "compact-long .### rounding-mode-half-up
  if (skeleton.indexOf("compact-") >= 0) {
    return Notation::COMPACT;
  }
  // Ex: skeleton as
  // "unit/length-foot .### rounding-mode-half-up"
  return Notation::STANDARD;
}

Handle<String> NotationAsString(Isolate* isolate, Notation notation) {
  switch (notation) {
    case Notation::SCIENTIFIC:
      return ReadOnlyRoots(isolate).scientific_string_handle();
    case Notation::ENGINEERING:
      return ReadOnlyRoots(isolate).engineering_string_handle();
    case Notation::COMPACT:
      return ReadOnlyRoots(isolate).compact_string_handle();
    case Notation::STANDARD:
      return ReadOnlyRoots(isolate).standard_string_handle();
  }
  UNREACHABLE();
}

// Return CompactString as string based on skeleton.
Handle<String> CompactDisplayString(Isolate* isolate,
                                    const icu::UnicodeString& skeleton) {
  // Ex: skeleton as
  // "compact-long .### rounding-mode-half-up"
  if (skeleton.indexOf("compact-long") >= 0) {
    return ReadOnlyRoots(isolate).long_string_handle();
  }
  // Ex: skeleton as
  // "compact-short .### rounding-mode-half-up"
  DCHECK_GE(skeleton.indexOf("compact-short"), 0);
  return ReadOnlyRoots(isolate).short_string_handle();
}

// Return SignDisplay as string based on skeleton.
Handle<String> SignDisplayString(Isolate* isolate,
                                 const icu::UnicodeString& skeleton) {
  // Ex: skeleton as
  // "currency/TWD .00 rounding-mode-half-up sign-never"
  if (skeleton.indexOf("sign-never") >= 0) {
    return ReadOnlyRoots(isolate).never_string_handle();
  }
  // Ex: skeleton as
  // ".### rounding-mode-half-up sign-always" or
  // "currency/TWD .00 rounding-mode-half-up sign-accounting-always"
  if (skeleton.indexOf("sign-always") >= 0 ||
      skeleton.indexOf("sign-accounting-always") >= 0) {
    return ReadOnlyRoots(isolate).always_string_handle();
  }
  // Ex: skeleton as
  // "currency/TWD .00 rounding-mode-half-up sign-accounting-except-zero" or
  // "currency/TWD .00 rounding-mode-half-up sign-except-zero"
  if (skeleton.indexOf("sign-accounting-except-zero") >= 0 ||
      skeleton.indexOf("sign-except-zero") >= 0) {
    return ReadOnlyRoots(isolate).exceptZero_string_handle();
  }
  // Ex: skeleton as
  // ".### rounding-mode-half-up sign-negative" or
  // "currency/TWD .00 rounding-mode-half-up sign-accounting-negative"
  if (skeleton.indexOf("sign-accounting-negative") >= 0 ||
      skeleton.indexOf("sign-negative") >= 0) {
    return ReadOnlyRoots(isolate).negative_string_handle();
  }
  return ReadOnlyRoots(isolate).auto_string_handle();
}

}  // anonymous namespace

// Return RoundingMode as string based on skeleton.
Handle<String> JSNumberFormat::RoundingModeString(
    Isolate* isolate, const icu::UnicodeString& skeleton) {
  static const char* rounding_mode = "rounding-mode-";
  int32_t start = skeleton.indexOf(rounding_mode);
  if (start >= 0) {
    DCHECK_EQ(14, strlen(rounding_mode));
    icu::UnicodeString check = skeleton.tempSubString(start + 14);

    // Ex: skeleton as
    // .### rounding-mode-ceiling
    if (check.startsWith("ceiling")) {
      return ReadOnlyRoots(isolate).ceil_string_handle();
    }
    // Ex: skeleton as
    // .### rounding-mode-down
    if (check.startsWith("down")) {
      return ReadOnlyRoots(isolate).trunc_string_handle();
    }
    // Ex: skeleton as
    // .### rounding-mode-floor
    if (check.startsWith("floor")) {
      return ReadOnlyRoots(isolate).floor_string_handle();
    }
    // Ex: skeleton as
    // .### rounding-mode-half-ceiling
    if (check.startsWith("half-ceiling")) {
      return ReadOnlyRoots(isolate).halfCeil_string_handle();
    }
    // Ex: skeleton as
    // .### rounding-mode-half-down
    if (check.startsWith("half-down")) {
      return ReadOnlyRoots(isolate).halfTrunc_string_handle();
    }
    // Ex: skeleton as
    // .### rounding-mode-half-floor
    if (check.startsWith("half-floor")) {
      return ReadOnlyRoots(isolate).halfFloor_string_handle();
    }
    // Ex: skeleton as
    // .### rounding-mode-half-up
    if (check.startsWith("half-up")) {
      return ReadOnlyRoots(isolate).halfExpand_string_handle();
    }
    // Ex: skeleton as
    // .### rounding-mode-up
    if (check.startsWith("up")) {
      return ReadOnlyRoots(isolate).expand_string_handle();
    }
  }
  // Ex: skeleton as
  // .###
  return ReadOnlyRoots(isolate).halfEven_string_handle();
}

Handle<Object> JSNumberFormat::RoundingIncrement(
    Isolate* isolate, const icu::UnicodeString& skeleton) {
  int32_t cur = skeleton.indexOf(u"precision-increment/");
  if (cur < 0) return isolate->factory()->NewNumberFromInt(1);
  cur += 20;  // length of "precision-increment/"
  int32_t increment = 0;
  while (cur < skeleton.length()) {
    char16_t c = skeleton[cur++];
    if (c == u'.') continue;
    if (!IsDecimalDigit(c)) break;
    increment = increment * 10 + (c - '0');
  }
  return isolate->factory()->NewNumberFromInt(increment);
}

// Return RoundingPriority as string based on skeleton.
Handle<String> JSNumberFormat::RoundingPriorityString(
    Isolate* isolate, const icu::UnicodeString& skeleton) {
  int32_t found;
  // If #r or @r is followed by a SPACE or in the end of line.
  if ((found = skeleton.indexOf("#r")) >= 0 ||
      (found = skeleton.indexOf("@r")) >= 0) {
    if (found + 2 == skeleton.length() || skeleton[found + 2] == ' ') {
      return ReadOnlyRoots(isolate).morePrecision_string_handle();
    }
  }
  // If #s or @s is followed by a SPACE or in the end of line.
  if ((found = skeleton.indexOf("#s")) >= 0 ||
      (found = skeleton.indexOf("@s")) >= 0) {
    if (found + 2 == skeleton.length() || skeleton[found + 2] == ' ') {
      return ReadOnlyRoots(isolate).lessPrecision_string_handle();
    }
  }
  return ReadOnlyRoots(isolate).auto_string_handle();
}

// Return trailingZeroDisplay as string based on skeleton.
Handle<String> JSNumberFormat::TrailingZeroDisplayString(
    Isolate* isolate, const icu::UnicodeString& skeleton) {
  int32_t found;
  if ((found = skeleton.indexOf("/w")) >= 0) {
    if (found + 2 == skeleton.length() || skeleton[found + 2] == ' ') {
      return ReadOnlyRoots(isolate).stripIfInteger_string_handle();
    }
  }
  return ReadOnlyRoots(isolate).auto_string_handle();
}

// Return the minimum integer digits by counting the number of '0' after
// "integer-width/*" in the skeleton.
// Ex: Return 15 for skeleton as
// “currency/TWD .00 rounding-mode-half-up integer-width/*000000000000000”
//                                                                 1
//                                                        123456789012345
// Return default value as 1 if there are no "integer-width/*".
int32_t JSNumberFormat::MinimumIntegerDigitsFromSkeleton(
    const icu::UnicodeString& skeleton) {
  // count the number of 0 after "integer-width/*"
  icu::UnicodeString search("integer-width/*");
  int32_t index = skeleton.indexOf(search);
  if (index < 0) return 1;  // return 1 if cannot find it.
  index += search.length();
  int32_t matched = 0;
  while (index < skeleton.length() && skeleton[index] == '0') {
    matched++;
    index++;
  }
  DCHECK_GT(matched, 0);
  return matched;
}

// Return true if there are fraction digits, false if not.
// The minimum fraction digits is the number of '0' after '.' in the skeleton
// The maximum fraction digits is the number of '#' after the above '0's plus
// the minimum fraction digits.
// For example, as skeleton “.000#### rounding-mode-half-up”
//                            123
//                               4567
// Set The minimum as 3 and maximum as 7.
// We also treat the following  special cases as both minimum and maximum are 0
// while there are no . in the skeleton:
// 1. While there are "precision-integer" in the skeleton.
// 2. While there are "precision-increment/" in the skeleton but no . after it.
// Examples:
// "currency/JPY precision-integer rounding-mode-half-up"
// "precision-increment/2 rounding-mode-half-up"
bool JSNumberFormat::FractionDigitsFromSkeleton(
    const icu::UnicodeString& skeleton, int32_t* minimum, int32_t* maximum) {
  int32_t index = skeleton.indexOf(".");
  if (index < 0) {
    // https://unicode-org.github.io/icu/userguide/format_parse/numbers/skeletons.html#precision
    // Note that the stem . is considered valid and is equivalent to
    // precision-integer.
    // Also, if there are "precision-increment/" but no "." we consider both
    // minimum and maximum fraction digits as 0.
    if (skeleton.indexOf("precision-integer") >= 0 ||
        skeleton.indexOf("precision-increment/") >= 0) {
      *minimum = *maximum = 0;
      return true;
    }
    return false;
  }
  *minimum = 0;
  index++;  // skip the '.'
  while (index < skeleton.length() && IsDecimalDigit(skeleton[index])) {
    (*minimum)++;
    index++;
  }
  *maximum = *minimum;
  while (index < skeleton.length() && skeleton[index] == '#') {
    (*maximum)++;
    index++;
  }
  return true;
}

// Return true if there are significant digits, false if not.
// The minimum significant digits is the number of '@' in the skeleton
// The maximum significant digits is the number of '#' after these '@'s plus
// the minimum significant digits.
// Ex: Skeleton as "@@@@@####### rounding-mode-half-up"
//                  12345
//                       6789012
// Set The minimum as 5 and maximum as 12.
bool JSNumberFormat::SignificantDigitsFromSkeleton(
    const icu::UnicodeString& skeleton, int32_t* minimum, int32_t* maximum) {
  int32_t index = skeleton.indexOf("@");
  if (index < 0) return false;
  *minimum = 1;
  index++;  // skip the first '@'
  while (index < skeleton.length() && skeleton[index] == '@') {
    (*minimum)++;
    index++;
  }
  *maximum = *minimum;
  while (index < skeleton.length() && skeleton[index] == '#') {
    (*maximum)++;
    index++;
  }
  return true;
}

namespace {

// Ex: percent .### rounding-mode-half-up
// Special case for "percent"
// Ex: "unit/milliliter-per-acre .### rounding-mode-half-up"
// should return "milliliter-per-acre".
// Ex: "unit/year .### rounding-mode-half-up" should return
// "year".
std::string UnitFromSkeleton(const icu::UnicodeString& skeleton) {
  std::string str;
  str = skeleton.toUTF8String<std::string>(str);
  std::string search("unit/");
  size_t begin = str.find(search);
  if (begin == str.npos) {
    // Special case for "percent".
    if (str.find("percent") != str.npos) {
      return "percent";
    }
    return "";
  }
  // Ex:
  // "unit/acre .### rounding-mode-half-up"
  //       b
  // Ex:
  // "unit/milliliter-per-acre .### rounding-mode-half-up"
  //       b
  begin += search.size();
  if (begin == str.npos) {
    return "";
  }
  // Find the end of the subtype.
  size_t end = str.find(' ', begin);
  // Ex:
  // "unit/acre .### rounding-mode-half-up"
  //       b   e
  // Ex:
  // "unit/milliliter-per-acre .### rounding-mode-half-up"
  //       b                  e
  if (end == str.npos) {
    end = str.size();
  }
  return str.substr(begin, end - begin);
}

Style StyleFromSkeleton(const icu::UnicodeString& skeleton) {
  if (skeleton.indexOf("currency/") >= 0) {
    return Style::CURRENCY;
  }
  if (skeleton.indexOf("percent") >= 0) {
    // percent precision-integer rounding-mode-half-up scale/100
    if (skeleton.indexOf("scale/100") >= 0) {
      return Style::PERCENT;
    } else {
      return Style::UNIT;
    }
  }
  // Before ICU68: "measure-unit/", since ICU68 "unit/"
  if (skeleton.indexOf("unit/") >= 0) {
    return Style::UNIT;
  }
  return Style::DECIMAL;
}

}  // anonymous namespace

icu::number::UnlocalizedNumberFormatter
JSNumberFormat::SetDigitOptionsToFormatter(
    const icu::number::UnlocalizedNumberFormatter& settings,
    const Intl::NumberFormatDigitOptions& digit_options) {
  icu::number::UnlocalizedNumberFormatter result = settings.roundingMode(
      ToUNumberFormatRoundingMode(digit_options.rounding_mode));

  if (digit_options.minimum_integer_digits > 1) {
    result = result.integerWidth(icu::number::IntegerWidth::zeroFillTo(
        digit_options.minimum_integer_digits));
  }

  icu::number::Precision precision = icu::number::Precision::unlimited();
  bool relaxed = false;
  switch (digit_options.rounding_type) {
    case Intl::RoundingType::kSignificantDigits:
      precision = icu::number::Precision::minMaxSignificantDigits(
          digit_options.minimum_significant_digits,
          digit_options.maximum_significant_digits);
      break;
    case Intl::RoundingType::kFractionDigits:
      precision = icu::number::Precision::minMaxFraction(
          digit_options.minimum_fraction_digits,
          digit_options.maximum_fraction_digits);
      break;
    case Intl::RoundingType::kMorePrecision:
      relaxed = true;
      [[fallthrough]];
    case Intl::RoundingType::kLessPrecision:
      precision =
          icu::number::Precision::minMaxFraction(
              digit_options.minimum_fraction_digits,
              digit_options.maximum_fraction_digits)
              .withSignificantDigits(digit_options.minimum_significant_digits,
                                     digit_options.maximum_significant_digits,
                                     relaxed ? UNUM_ROUNDING_PRIORITY_RELAXED
                                             : UNUM_ROUNDING_PRIORITY_STRICT);
      break;
  }
  if (digit_options.rounding_increment != 1) {
    precision = ::icu::number::Precision::incrementExact(
                    digit_options.rounding_increment,
                    -digit_options.maximum_fraction_digits)
                    .withMinFraction(digit_options.minimum_fraction_digits);
  }
  if (digit_options.trailing_zero_display ==
      Intl::TrailingZeroDisplay::kStripIfInteger) {
    precision = precision.trailingZeroDisplay(UNUM_TRAILING_ZERO_HIDE_IF_WHOLE);
  }
  return result.precision(precision);
}

// static
// ecma402 #sec-intl.numberformat.prototype.resolvedoptions
Handle<JSObject> JSNumberFormat::ResolvedOptions(
    Isolate* isolate, DirectHandle<JSNumberFormat> number_format) {
  Factory* factory = isolate->factory();

  UErrorCode status = U_ZERO_ERROR;
  icu::number::LocalizedNumberFormatter* fmt =
      number_format->icu_number_formatter()->raw();
  icu::UnicodeString skeleton = fmt->toSkeleton(status);
  DCHECK(U_SUCCESS(status));

  // 4. Let options be ! ObjectCreate(%ObjectPrototype%).
  Handle<JSObject> options = factory->NewJSObject(isolate->object_function());

  Handle<String> locale = Handle<String>(number_format->locale(), isolate);
  const icu::UnicodeString numberingSystem_ustr =
      JSNumberFormat::NumberingSystemFromSkeleton(skeleton);
  // 5. For each row of Table 4, except the header row, in table order, do
  // Table 4: Resolved Options of NumberFormat Instances
  //  Internal Slot                    Property
  //    [[Locale]]                      "locale"
  //    [[NumberingSystem]]             "numberingSystem"
  //    [[Style]]                       "style"
  //    [[Currency]]                    "currency"
  //    [[CurrencyDisplay]]             "currencyDisplay"
  //    [[CurrencySign]]                "currencySign"
  //    [[Unit]]                        "unit"
  //    [[UnitDisplay]]                 "unitDisplay"
  //    [[MinimumIntegerDigits]]        "minimumIntegerDigits"
  //    [[MinimumFractionDigits]]       "minimumFractionDigits"
  //    [[MaximumFractionDigits]]       "maximumFractionDigits"
  //    [[MinimumSignificantDigits]]    "minimumSignificantDigits"
  //    [[MaximumSignificantDigits]]    "maximumSignificantDigits"
  //    [[UseGrouping]]                 "useGrouping"
  //    [[Notation]]                    "notation"
  //    [[CompactDisplay]]              "compactDisplay"
  //    [[SignDisplay]]                 "signDisplay"
  //    [[RoundingIncrement]]           "roundingIncrement"
  //    [[RoundingMode]]                "roundingMode"
  //    [[ComputedRoundingPriority]]    "roundingPriority"
  //    [[TrailingZeroDisplay]]         "trailingZeroDisplay"

  CHECK(JSReceiver::CreateDataProperty(isolate, options,
                                       factory->locale_string(), locale,
                                       Just(kDontThrow))
            .FromJust());
  Handle<String> numberingSystem_string;
  CHECK(Intl::ToString(isolate, numberingSystem_ustr)
            .ToHandle(&numberingSystem_string));
  CHECK(JSReceiver::CreateDataProperty(isolate, options,
                                       factory->numberingSystem_string(),
                                       numberingSystem_string, Just(kDontThrow))
            .FromJust());
  Style style = StyleFromSkeleton(skeleton);
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->style_string(),
            StyleAsString(isolate, style), Just(kDontThrow))
            .FromJust());
  const icu::UnicodeString currency_ustr = CurrencyFromSkeleton(skeleton);
  if (!currency_ustr.isEmpty()) {
    Handle<String> currency_string;
    CHECK(Intl::ToString(isolate, currency_ustr).ToHandle(&currency_string));
    CHECK(JSReceiver::CreateDataProperty(isolate, options,
                                         factory->currency_string(),
                                         currency_string, Just(kDontThrow))
              .FromJust());

    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->currencyDisplay_string(),
              CurrencyDisplayString(isolate, skeleton), Just(kDontThrow))
              .FromJust());
    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->currencySign_string(),
              CurrencySignString(isolate, skeleton), Just(kDontThrow))
              .FromJust());
  }

  if (style == Style::UNIT) {
    std::string unit = UnitFromSkeleton(skeleton);
    if (!unit.empty()) {
      CHECK(JSReceiver::CreateDataProperty(
                isolate, options, factory->unit_string(),
                isolate->factory()->NewStringFromAsciiChecked(unit.c_str()),
                Just(kDontThrow))
                .FromJust());
    }
    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->unitDisplay_string(),
              UnitDisplayString(isolate, skeleton), Just(kDontThrow))
              .FromJust());
  }

  CHECK(
      JSReceiver::CreateDataProperty(
          isolate, options, factory->minimumIntegerDigits_string(),
          factory->NewNumberFromInt(MinimumIntegerDigitsFromSkeleton(skeleton)),
          Just(kDontThrow))
          .FromJust());

  int32_t mnsd = 0, mxsd = 0, mnfd = 0, mxfd = 0;
  if (FractionDigitsFromSkeleton(skeleton, &mnfd, &mxfd)) {
    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->minimumFractionDigits_string(),
              factory->NewNumberFromInt(mnfd), Just(kDontThrow))
              .FromJust());
    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->maximumFractionDigits_string(),
              factory->NewNumberFromInt(mxfd), Just(kDontThrow))
              .FromJust());
  }
  if (SignificantDigitsFromSkeleton(skeleton, &mnsd, &mxsd)) {
    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->minimumSignificantDigits_string(),
              factory->NewNumberFromInt(mnsd), Just(kDontThrow))
              .FromJust());
    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->maximumSignificantDigits_string(),
              factory->NewNumberFromInt(mxsd), Just(kDontThrow))
              .FromJust());
  }

  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->useGrouping_string(),
            UseGroupingFromSkeleton(isolate, skeleton), Just(kDontThrow))
            .FromJust());

  Notation notation = NotationFromSkeleton(skeleton);
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->notation_string(),
            NotationAsString(isolate, notation), Just(kDontThrow))
            .FromJust());
  // Only output compactDisplay when notation is compact.
  if (notation == Notation::COMPACT) {
    CHECK(JSReceiver::CreateDataProperty(
              isolate, options, factory->compactDisplay_string(),
              CompactDisplayString(isolate, skeleton), Just(kDontThrow))
              .FromJust());
  }
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->signDisplay_string(),
            SignDisplayString(isolate, skeleton), Just(kDontThrow))
            .FromJust());
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->roundingIncrement_string(),
            RoundingIncrement(isolate, skeleton), Just(kDontThrow))
            .FromJust());
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->roundingMode_string(),
            RoundingModeString(isolate, skeleton), Just(kDontThrow))
            .FromJust());
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->roundingPriority_string(),
            RoundingPriorityString(isolate, skeleton), Just(kDontThrow))
            .FromJust());
  CHECK(JSReceiver::CreateDataProperty(
            isolate, options, factory->trailingZeroDisplay_string(),
            TrailingZeroDisplayString(isolate, skeleton), Just(kDontThrow))
            .FromJust());
  return options;
}

// ecma402/#sec-unwrapnumberformat
MaybeHandle<JSNumberFormat> JSNumberFormat::UnwrapNumberFormat(
    Isolate* isolate, Handle<JSReceiver> format_holder) {
  // old code copy from NumberFormat::Unwrap that has no spec comment and
  // compiled but fail unit tests.
  DirectHandle<Context> native_context(isolate->context()->native_context(),
                                       isolate);
  Handle<JSFunction> constructor(
      Cast<JSFunction>(native_context->intl_number_format_function()), isolate);
  Handle<Object> object;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, object,
      Intl::LegacyUnwrapReceiver(isolate, format_holder, constructor,
                                 IsJSNumberFormat(*format_holder)));
  // 4. If ... or nf does not have an [[InitializedNumberFormat]] internal slot,
  // then
  if (!IsJSNumberFormat(*object)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kIncompatibleMethodReceiver,
                                 isolate->factory()->NewStringFromAsciiChecked(
                                     "UnwrapNumberFormat")));
  }
  // 5. Return nf.
  return Cast<JSNumberFormat>(object);
}

// static
MaybeHandle<JSNumberFormat> JSNumberFormat::New(Isolate* isolate,
                                                DirectHandle<Map> map,
                                                Handle<Object> locales,
                                                Handle<Object> options_obj,
                                                const char* service) {
  Factory* factory = isolate->factory();

  // 1. Let requestedLocales be ? CanonicalizeLocaleList(locales).
  Maybe<std::vector<std::string>> maybe_requested_locales =
      Intl::CanonicalizeLocaleList(isolate, locales);
  MAYBE_RETURN(maybe_requested_locales, Handle<JSNumberFormat>());
  std::vector<std::string> requested_locales =
      maybe_requested_locales.FromJust();

  // 2. Set options to ? CoerceOptionsToObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, CoerceOptionsToObject(isolate, options_obj, service));

  // 3. Let opt be a new Record.
  // 4. Let matcher be ? GetOption(options, "localeMatcher", "string", «
  // "lookup", "best fit" », "best fit").
  // 5. Set opt.[[localeMatcher]] to matcher.
  Maybe<Intl::MatcherOption> maybe_locale_matcher =
      Intl::GetLocaleMatcher(isolate, options, service);
  MAYBE_RETURN(maybe_locale_matcher, MaybeHandle<JSNumberFormat>());
  Intl::MatcherOption matcher = maybe_locale_matcher.FromJust();

  std::unique_ptr<char[]> numbering_system_str = nullptr;
  // 6. Let _numberingSystem_ be ? GetOption(_options_, `"numberingSystem"`,
  //    `"string"`, *undefined*, *undefined*).
  Maybe<bool> maybe_numberingSystem = Intl::GetNumberingSystem(
      isolate, options, service, &numbering_system_str);
  // 7. If _numberingSystem_ is not *undefined*, then
  // 8. If _numberingSystem_ does not match the
  //    `(3*8alphanum) *("-" (3*8alphanum))` sequence, throw a *RangeError*
  //     exception.
  MAYBE_RETURN(maybe_numberingSystem, MaybeHandle<JSNumberFormat>());

  // 9. Let localeData be %NumberFormat%.[[LocaleData]].
  // 10. Let r be ResolveLocale(%NumberFormat%.[[AvailableLocales]],
  // requestedLocales, opt,  %NumberFormat%.[[RelevantExtensionKeys]],
  // localeData).
  std::set<std::string> relevant_extension_keys{"nu"};
  Maybe<Intl::ResolvedLocale> maybe_resolve_locale =
      Intl::ResolveLocale(isolate, JSNumberFormat::GetAvailableLocales(),
                          requested_locales, matcher, relevant_extension_keys);
  if (maybe_resolve_locale.IsNothing()) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
  }
  Intl::ResolvedLocale r = maybe_resolve_locale.FromJust();

  icu::Locale icu_locale = r.icu_locale;
  UErrorCode status = U_ZERO_ERROR;
  if (numbering_system_str != nullptr) {
    auto nu_extension_it = r.extensions.find("nu");
    if (nu_extension_it != r.extensions.end() &&
        nu_extension_it->second != numbering_system_str.get()) {
      icu_locale.setUnicodeKeywordValue("nu", nullptr, status);
      DCHECK(U_SUCCESS(status));
    }
  }

  // 9. Set numberFormat.[[Locale]] to r.[[locale]].
  Maybe<std::string> maybe_locale_str = Intl::ToLanguageTag(icu_locale);
  MAYBE_RETURN(maybe_locale_str, MaybeHandle<JSNumberFormat>());
  DirectHandle<String> locale_str =
      isolate->factory()->NewStringFromAsciiChecked(
          maybe_locale_str.FromJust().c_str());

  if (numbering_system_str != nullptr &&
      Intl::IsValidNumberingSystem(numbering_system_str.get())) {
    icu_locale.setUnicodeKeywordValue("nu", numbering_system_str.get(), status);
    DCHECK(U_SUCCESS(status));
  }

  std::string numbering_system = Intl::GetNumberingSystem(icu_locale);

  // 11. Let dataLocale be r.[[dataLocale]].

  icu::number::UnlocalizedNumberFormatter settings =
      icu::number::UnlocalizedNumberFormatter().roundingMode(UNUM_ROUND_HALFUP);

  // For 'latn' numbering system, skip the adoptSymbols which would cause
  // 10.1%-13.7% of regression of JSTests/Intl-NewIntlNumberFormat
  // See crbug/1052751 so we skip calling adoptSymbols and depending on the
  // default instead.
  if (!numbering_system.empty() && numbering_system != "latn") {
    settings = settings.adoptSymbols(icu::NumberingSystem::createInstanceByName(
        numbering_system.c_str(), status));
    DCHECK(U_SUCCESS(status));
  }

  // ==== Start SetNumberFormatUnitOptions ====
  // 3. Let style be ? GetOption(options, "style", "string",  « "decimal",
  // "percent", "currency", "unit" », "decimal").

  Maybe<Style> maybe_style = GetStringOption<Style>(
      isolate, options, "style", service,
      {"decimal", "percent", "currency", "unit"},
      {Style::DECIMAL, Style::PERCENT, Style::CURRENCY, Style::UNIT},
      Style::DECIMAL);
  MAYBE_RETURN(maybe_style, MaybeHandle<JSNumberFormat>());
  Style style = maybe_style.FromJust();

  // 4. Set intlObj.[[Style]] to style.

  // 5. Let currency be ? GetOption(options, "currency", "string", undefined,
  // undefined).
  std::unique_ptr<char[]> currency_cstr;
  const std::vector<const char*> empty_values = {};
  Maybe<bool> found_currency = GetStringOption(
      isolate, options, "currency", empty_values, service, &currency_cstr);
  MAYBE_RETURN(found_currency, MaybeHandle<JSNumberFormat>());

  std::string currency;
  // 6. If currency is not undefined, then
  if (found_currency.FromJust()) {
    DCHECK_NOT_NULL(currency_cstr.get());
    currency = currency_cstr.get();
    // 6. a. If the result of IsWellFormedCurrencyCode(currency) is false,
    // throw a RangeError exception.
    if (!IsWellFormedCurrencyCode(currency)) {
      THROW_NEW_ERROR(
          isolate,
          NewRangeError(MessageTemplate::kInvalid,
                        factory->NewStringFromStaticChars("currency code"),
                        factory->NewStringFromAsciiChecked(currency.c_str())));
    }
  } else {
    // 7. If style is "currency" and currency is undefined, throw a TypeError
    // exception.
    if (style == Style::CURRENCY) {
      THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kCurrencyCode));
    }
  }
  // 8. Let currencyDisplay be ? GetOption(options, "currencyDisplay",
  // "string", « "code",  "symbol", "name", "narrowSymbol" », "symbol").
  Maybe<CurrencyDisplay> maybe_currency_display =
      GetStringOption<CurrencyDisplay>(
          isolate, options, "currencyDisplay", service,
          {"code", "symbol", "name", "narrowSymbol"},
          {CurrencyDisplay::CODE, CurrencyDisplay::SYMBOL,
           CurrencyDisplay::NAME, CurrencyDisplay::NARROW_SYMBOL},
          CurrencyDisplay::SYMBOL);
  MAYBE_RETURN(maybe_currency_display, MaybeHandle<JSNumberFormat>());
  CurrencyDisplay currency_display = maybe_currency_display.FromJust();

  CurrencySign currency_sign = CurrencySign::STANDARD;
  // 9. Let currencySign be ? GetOption(options, "currencySign", "string", «
  // "standard",  "accounting" », "standard").
  Maybe<CurrencySign> maybe_currency_sign = GetStringOption<CurrencySign>(
      isolate, options, "currencySign", service, {"standard", "accounting"},
      {CurrencySign::STANDARD, CurrencySign::ACCOUNTING},
      CurrencySign::STANDARD);
  MAYBE_RETURN(maybe_currency_sign, MaybeHandle<JSNumberFormat>());
  currency_sign = maybe_currency_sign.FromJust();

  // 10. Let unit be ? GetOption(options, "unit", "string", undefined,
  // undefined).
  std::unique_ptr<char[]> unit_cstr;
  Maybe<bool> found_unit = GetStringOption(isolate, options, "unit",
                                           empty_values, service, &unit_cstr);
  MAYBE_RETURN(found_unit, MaybeHandle<JSNumberFormat>());

  std::pair<icu::MeasureUnit, icu::MeasureUnit> unit_pair;
  // 11. If unit is not undefined, then
  if (found_unit.FromJust()) {
    DCHECK_NOT_NULL(unit_cstr.get());
    std::string unit = unit_cstr.get();
    // 11.a If the result of IsWellFormedUnitIdentifier(unit) is false, throw a
    // RangeError exception.
    Maybe<std::pair<icu::MeasureUnit, icu::MeasureUnit>> maybe_wellformed_unit =
        IsWellFormedUnitIdentifier(isolate, unit);
    if (maybe_wellformed_unit.IsNothing()) {
      THROW_NEW_ERROR(
          isolate,
          NewRangeError(MessageTemplate::kInvalidUnit,
                        factory->NewStringFromAsciiChecked(service),
                        factory->NewStringFromAsciiChecked(unit.c_str())));
    }
    unit_pair = maybe_wellformed_unit.FromJust();
  } else {
    // 12. If style is "unit" and unit is undefined, throw a TypeError
    // exception.
    if (style == Style::UNIT) {
      THROW_NEW_ERROR(isolate,
                      NewTypeError(MessageTemplate::kInvalidUnit,
                                   factory->NewStringFromAsciiChecked(service),
                                   factory->empty_string()));
    }
  }

  // 13. Let unitDisplay be ? GetOption(options, "unitDisplay", "string", «
  // "short", "narrow", "long" »,  "short").
  Maybe<UnitDisplay> maybe_unit_display = GetStringOption<UnitDisplay>(
      isolate, options, "unitDisplay", service, {"short", "narrow", "long"},
      {UnitDisplay::SHORT, UnitDisplay::NARROW, UnitDisplay::LONG},
      UnitDisplay::SHORT);
  MAYBE_RETURN(maybe_unit_display, MaybeHandle<JSNumberFormat>());
  UnitDisplay unit_display = maybe_unit_display.FromJust();

  // 14. If style is "currency", then
  icu::UnicodeString currency_ustr;
  if (style == Style::CURRENCY) {
    // 14.a. If currency is undefined, throw a TypeError exception.
    if (!found_currency.FromJust()) {
      THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kCurrencyCode));
    }
    // 14.a. Let currency be the result of converting currency to upper case as
    //    specified in 6.1
    std::transform(currency.begin(), currency.end(), currency.begin(), toupper);
    currency_ustr = currency.c_str();

    // 14.b. Set numberFormat.[[Currency]] to currency.
    if (!currency_ustr.isEmpty()) {
      Handle<String> currency_string;
      ASSIGN_RETURN_ON_EXCEPTION(isolate, currency_string,
                                 Intl::ToString(isolate, currency_ustr));

      settings =
          settings.unit(icu::CurrencyUnit(currency_ustr.getBuffer(), status));
      DCHECK(U_SUCCESS(status));
      // 14.c Set intlObj.[[CurrencyDisplay]] to currencyDisplay.
      // The default unitWidth is SHORT in ICU and that mapped from
      // Symbol so we can skip the setting for optimization.
      if (currency_display != CurrencyDisplay::SYMBOL) {
        settings = settings.unitWidth(ToUNumberUnitWidth(currency_display));
      }
      DCHECK(U_SUCCESS(status));
    }
  }

  // 15. If style is "unit", then
  if (style == Style::UNIT) {
    // Track newer style "unit".
    isolate->CountUsage(v8::Isolate::UseCounterFeature::kNumberFormatStyleUnit);

    icu::MeasureUnit none = icu::MeasureUnit();
    // 13.b Set intlObj.[[Unit]] to unit.
    if (unit_pair.first != AVOID_AMBIGUOUS_OP_WARNING(none)) {
      settings = settings.unit(unit_pair.first);
    }
    if (unit_pair.second != AVOID_AMBIGUOUS_OP_WARNING(none)) {
      settings = settings.perUnit(unit_pair.second);
    }

    // The default unitWidth is SHORT in ICU and that mapped from
    // Symbol so we can skip the setting for optimization.
    if (unit_display != UnitDisplay::SHORT) {
      settings = settings.unitWidth(ToUNumberUnitWidth(unit_display));
    }
  }

  // === End of SetNumberFormatUnitOptions

  if (style == Style::PERCENT) {
    settings = settings.unit(icu::MeasureUnit::getPercent())
                   .scale(icu::number::Scale::powerOfTen(2));
  }

  Notation notation = Notation::STANDARD;
  // xx. Let notation be ? GetOption(options, "notation", "string", «
  // "standard", "scientific",  "engineering", "compact" », "standard").
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, notation,
      GetStringOption<Notation>(
          isolate, options, "notation", service,
          {"standard", "scientific", "engineering", "compact"},
          {Notation::STANDARD, Notation::SCIENTIFIC, Notation::ENGINEERING,
           Notation::COMPACT},
          Notation::STANDARD),
      Handle<JSNumberFormat>());
  // xx. Set numberFormat.[[Notation]] to notation.

  // xx. If style is *"currency"* and *"notation"* is *"standard"*, then
  int mnfd_default, mxfd_default;
  if (style == Style::CURRENCY && notation == Notation::STANDARD) {
    // b. Let cDigits be CurrencyDigits(currency).
    int c_digits = CurrencyDigits(currency_ustr);
    // c. Let mnfdDefault be cDigits.
    // d. Let mxfdDefault be cDigits.
    mnfd_default = c_digits;
    mxfd_default = c_digits;
    // 17. Else,
  } else {
    // a. Let mnfdDefault be 0.
    mnfd_default = 0;
    // b. If style is "percent", then
    if (style == Style::PERCENT) {
      // i. Let mxfdDefault be 0.
      mxfd_default = 0;
    } else {
      // c. Else,
      // i. Let mxfdDefault be 3.
      mxfd_default = 3;
    }
  }

  // 23. Perform ? SetNumberFormatDigitOptions(numberFormat, options,
  // mnfdDefault, mxfdDefault).
  Maybe<Intl::NumberFormatDigitOptions> maybe_digit_options =
      Intl::SetNumberFormatDigitOptions(isolate, options, mnfd_default,
                                        mxfd_default,
                                        notation == Notation::COMPACT, service);
  MAYBE_RETURN(maybe_digit_options, Handle<JSNumberFormat>());
  Intl::NumberFormatDigitOptions digit_options = maybe_digit_options.FromJust();

  // 13. If roundingIncrement is not 1, set mxfdDefault to mnfdDefault.
  if (digit_options.rounding_increment != 1) {
    mxfd_default = mnfd_default;
  }
  // 14. Set intlObj.[[RoundingIncrement]] to roundingIncrement.

  // 15. Set intlObj.[[RoundingMode]] to roundingMode.

  // 16. Set intlObj.[[TrailingZeroDisplay]] to trailingZeroDisplay.
  settings = SetDigitOptionsToFormatter(settings, digit_options);

  // 28. Let compactDisplay be ? GetOption(options, "compactDisplay",
  // "string", « "short", "long" »,  "short").
  Maybe<CompactDisplay> maybe_compact_display = GetStringOption<CompactDisplay>(
      isolate, options, "compactDisplay", service, {"short", "long"},
      {CompactDisplay::SHORT, CompactDisplay::LONG}, CompactDisplay::SHORT);
  MAYBE_RETURN(maybe_compact_display, MaybeHandle<JSNumberFormat>());
  CompactDisplay compact_display = maybe_compact_display.FromJust();

  // The default notation in ICU is Simple, which mapped from STANDARD
  // so we can skip setting it.
  if (notation != Notation::STANDARD) {
    settings = settings.notation(ToICUNotation(notation, compact_display));
  }

  // 28. Let defaultUseGrouping be "auto".
  UseGrouping default_use_grouping = UseGrouping::AUTO;

  // 29. If notation is "compact", then
  if (notation == Notation::COMPACT) {
    // a. Set numberFormat.[[CompactDisplay]] to compactDisplay.
    // Done in above together
    // b. Set defaultUseGrouping to "min2".
    default_use_grouping = UseGrouping::MIN2;
  }

  // 30. Let useGrouping be ? GetStringOrBooleanOption(options, "useGrouping",
  // « "min2", "auto", "always" », "always", false, defaultUseGrouping).
  Maybe<UseGrouping> maybe_use_grouping = GetStringOrBooleanOption<UseGrouping>(
      isolate, options, "useGrouping", service, {"min2", "auto", "always"},
      {UseGrouping::MIN2, UseGrouping::AUTO, UseGrouping::ALWAYS},
      UseGrouping::ALWAYS,    // trueValue
      UseGrouping::OFF,       // falseValue
      default_use_grouping);  // fallbackValue
  MAYBE_RETURN(maybe_use_grouping, MaybeHandle<JSNumberFormat>());
  UseGrouping use_grouping = maybe_use_grouping.FromJust();
  // 31. Set numberFormat.[[UseGrouping]] to useGrouping.
  if (use_grouping != UseGrouping::AUTO) {
    settings = settings.grouping(ToUNumberGroupingStrategy(use_grouping));
  }

  // 32. Let signDisplay be ? GetOption(options, "signDisplay", "string", «
  // "auto", "never", "always",  "exceptZero", "negative" », "auto").
  Maybe<SignDisplay> maybe_sign_display = Nothing<SignDisplay>();
  maybe_sign_display = GetStringOption<SignDisplay>(
      isolate, options, "signDisplay", service,
      {"auto", "never", "always", "exceptZero", "negative"},
      {SignDisplay::AUTO, SignDisplay::NEVER, SignDisplay::ALWAYS,
       SignDisplay::EXCEPT_ZERO, SignDisplay::NEGATIVE},
      SignDisplay::AUTO);
  MAYBE_RETURN(maybe_sign_display, MaybeHandle<JSNumberFormat>());
  SignDisplay sign_display = maybe_sign_display.FromJust();

  // 33. Set numberFormat.[[SignDisplay]] to signDisplay.
  // The default sign in ICU is UNUM_SIGN_AUTO which is mapped from
  // SignDisplay::AUTO and CurrencySign::STANDARD so we can skip setting
  // under that values for optimization.
  if (sign_display != SignDisplay::AUTO ||
      currency_sign != CurrencySign::STANDARD) {
    settings = settings.sign(ToUNumberSignDisplay(sign_display, currency_sign));
  }

  // 25. Let dataLocaleData be localeData.[[<dataLocale>]].
  //
  // 26. Let patterns be dataLocaleData.[[patterns]].
  //
  // 27. Assert: patterns is a record (see 11.3.3).
  //
  // 28. Let stylePatterns be patterns.[[<style>]].
  //
  // 29. Set numberFormat.[[PositivePattern]] to
  // stylePatterns.[[positivePattern]].
  //
  // 30. Set numberFormat.[[NegativePattern]] to
  // stylePatterns.[[negativePattern]].
  //
  icu::number::LocalizedNumberFormatter fmt = settings.locale(icu_locale);

  DirectHandle<Managed<icu::number::LocalizedNumberFormatter>>
      managed_number_formatter =
          Managed<icu::number::LocalizedNumberFormatter>::From(
              isolate, 0,
              std::make_shared<icu::number::LocalizedNumberFormatter>(fmt));

  // Now all properties are ready, so we can allocate the result object.
  Handle<JSNumberFormat> number_format = Cast<JSNumberFormat>(
      isolate->factory()->NewFastOrSlowJSObjectFromMap(map));
  DisallowGarbageCollection no_gc;
  number_format->set_locale(*locale_str);

  number_format->set_icu_number_formatter(*managed_number_formatter);
  number_format->set_bound_format(*factory->undefined_value());

  // 31. Return numberFormat.
  return number_format;
}

namespace {

icu::number::FormattedNumber FormatDecimalString(
    Isolate* isolate,
    const icu::number::LocalizedNumberFormatter& number_format,
    Handle<String> string, UErrorCode& status) {
  string = String::Flatten(isolate, string);
  DisallowGarbageCollection no_gc;
  const String::FlatContent& flat = string->GetFlatContent(no_gc);
  int32_t length = static_cast<int32_t>(string->length());
  if (flat.IsOneByte()) {
    const char* char_buffer =
        reinterpret_cast<const char*>(flat.ToOneByteVector().begin());
    return number_format.formatDecimal({char_buffer, length}, status);
  }
  return number_format.formatDecimal({string->ToCString().get(), length},
                                     status);
}

}  // namespace

bool IntlMathematicalValue::IsNaN() const { return i::IsNaN(*value_); }

MaybeHandle<String> IntlMathematicalValue::ToString(Isolate* isolate) const {
  DirectHandle<String> string;
  if (IsNumber(*value_)) {
    return isolate->factory()->NumberToString(value_);
  }
  if (IsBigInt(*value_)) {
    return BigInt::ToString(isolate, Cast<BigInt>(value_));
  }
  DCHECK(IsString(*value_));
  return Cast<String>(value_);
}

namespace {
Maybe<icu::number::FormattedNumber> IcuFormatNumber(
    Isolate* isolate,
    const icu::number::LocalizedNumberFormatter& number_format,
    Handle<Object> numeric_obj) {
  icu::number::FormattedNumber formatted;
  // If it is BigInt, handle it differently.
  UErrorCode status = U_ZERO_ERROR;
  if (IsBigInt(*numeric_obj)) {
    auto big_int = Cast<BigInt>(numeric_obj);
    Handle<String> big_int_string;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, big_int_string,
                                     BigInt::ToString(isolate, big_int),
                                     Nothing<icu::number::FormattedNumber>());
    big_int_string = String::Flatten(isolate, big_int_string);
    DisallowGarbageCollection no_gc;
    const String::FlatContent& flat = big_int_string->GetFlatContent(no_gc);
    int32_t length = static_cast<int32_t>(big_int_string->length());
    DCHECK(flat.IsOneByte());
    const char* char_buffer =
        reinterpret_cast<const char*>(flat.ToOneByteVector().begin());
    formatted = number_format.formatDecimal({char_buffer, length}, status);
  } else {
    if (IsString(*numeric_obj)) {
      // TODO(ftang) Correct the handling of string after the resolution of
      // https://github.com/tc39/proposal-intl-numberformat-v3/pull/82
      DirectHandle<String> string =
          String::Flatten(isolate, Cast<String>(numeric_obj));
      DisallowGarbageCollection no_gc;
      const String::FlatContent& flat = string->GetFlatContent(no_gc);
      int32_t length = static_cast<int32_t>(string->length());
      if (flat.IsOneByte()) {
        const char* char_buffer =
            reinterpret_cast<const char*>(flat.ToOneByteVector().begin());
        formatted = number_format.formatDecimal({char_buffer, length}, status);
      } else {
        // We may have two bytes string such as "漢 123456789".substring(2)
        // The value will be "123456789" only in ASCII range, but encoded
        // in two bytes string.
        // ICU accepts UTF8 string, so if the source is two-byte encoded,
        // copy into a UTF8 string via ToCString.
        int32_t length = static_cast<int32_t>(string->length());
        formatted = number_format.formatDecimal(
            {string->ToCString().get(), length}, status);
      }
    } else {
      double number = IsNaN(*numeric_obj)
                          ? std::numeric_limits<double>::quiet_NaN()
                          : Object::NumberValue(*numeric_obj);
      formatted = number_format.formatDouble(number, status);
    }
  }
  if (U_FAILURE(status)) {
    // This happen because of icu data trimming trim out "unit".
    // See https://bugs.chromium.org/p/v8/issues/detail?id=8641
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NewTypeError(MessageTemplate::kIcuError),
                                 Nothing<icu::number::FormattedNumber>());
  }
  return Just(std::move(formatted));
}

}  // namespace

Maybe<icu::number::FormattedNumber> IntlMathematicalValue::FormatNumeric(
    Isolate* isolate,
    const icu::number::LocalizedNumberFormatter& number_format,
    const IntlMathematicalValue& x) {
  if (IsString(*x.value_)) {
    Handle<String> string;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, string, x.ToString(isolate),
                                     Nothing<icu::number::FormattedNumber>());
    UErrorCode status = U_ZERO_ERROR;
    icu::number::FormattedNumber result =
        FormatDecimalString(isolate, number_format, string, status);
    if (U_FAILURE(status)) {
      THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                   NewTypeError(MessageTemplate::kIcuError),
                                   Nothing<icu::number::FormattedNumber>());
    }
    return Just(std::move(result));
  }
  CHECK(IsNumber(*x.value_) || IsBigInt(*x.value_));
  return IcuFormatNumber(isolate, number_format, x.value_);
}

Maybe<icu::number::FormattedNumberRange> IntlMathematicalValue::FormatRange(
    Isolate* isolate,
    const icu::number::LocalizedNumberRangeFormatter& number_range_format,
    const IntlMathematicalValue& x, const IntlMathematicalValue& y) {
  icu::Formattable x_formatable;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, x_formatable, x.ToFormattable(isolate),
      Nothing<icu::number::FormattedNumberRange>());

  icu::Formattable y_formatable;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, y_formatable, y.ToFormattable(isolate),
      Nothing<icu::number::FormattedNumberRange>());

  UErrorCode status = U_ZERO_ERROR;
  icu::number::FormattedNumberRange result =
      number_range_format.formatFormattableRange(x_formatable, y_formatable,
                                                 status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NewTypeError(MessageTemplate::kIcuError),
                                 Nothing<icu::number::FormattedNumberRange>());
  }

  return Just(std::move(result));
}

namespace {
// Return the index of the end of leading white space or line terminator
// and the index of the start of trailing white space or line terminator.
template <typename Char>
std::pair<int, int> FindLeadingAndTrailingWhiteSpaceOrLineTerminator(
    base::Vector<const Char> src) {
  size_t leading_end = 0;

  // Find the length of leading StrWhiteSpaceChar.
  while (leading_end < src.size() &&
         IsWhiteSpaceOrLineTerminator(
             static_cast<uint16_t>(src.at(leading_end)))) {
    leading_end++;
  }
  size_t trailing_start = src.size();
  // Find the start of the trailing StrWhiteSpaceChar
  while (trailing_start > leading_end &&
         IsWhiteSpaceOrLineTerminator(
             static_cast<uint16_t>(src.at(trailing_start - 1)))) {
    trailing_start--;
  }
  return std::make_pair(leading_end, trailing_start);
}

Handle<String> TrimWhiteSpaceOrLineTerminator(Isolate* isolate,
                                              Handle<String> string) {
  string = String::Flatten(isolate, string);
  std::pair<int, uint32_t> whitespace_offsets;
  {
    DisallowGarbageCollection no_gc;
    String::Fl
```