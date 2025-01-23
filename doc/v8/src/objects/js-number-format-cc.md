Response:
The user wants me to analyze the provided C++ code snippet from `v8/src/objects/js-number-format.cc`.

Here's a breakdown of the request and my plan:

1. **List the functionalities of the code:** I need to carefully read the code and identify its main purposes. Keywords like "format," "rounding," "currency," "unit," and references to ICU libraries will be important.

2. **Check for `.tq` extension:** I need to examine the filename to see if it ends with `.tq`. This will determine if it's a Torque file.

3. **Relationship to JavaScript:** I need to determine if the code interacts with JavaScript functionality. Since it's within the `v8` directory and the filename mentions "js-number-format," it's highly likely. I need to provide a JavaScript example if a relationship exists.

4. **Code logic and reasoning (with assumptions):**  If the code performs calculations or transformations based on inputs, I need to provide an example with assumed inputs and the expected output. This might involve tracing the execution flow for specific functions.

5. **Common programming errors:** Based on the code's functionality, I need to identify potential errors developers might make when using the related JavaScript API.

6. **Summarize the functionality:** Finally, I need to provide a concise summary of the code's overall purpose.

**Detailed Plan:**

* **Functionality Identification:** I'll focus on the defined enums (`Style`, `CurrencyDisplay`, etc.), the functions that convert these enums to ICU types (`ToUNumberUnitWidth`, `ToICUNotation`, etc.), and functions that parse information from the ICU skeleton (`CurrencyFromSkeleton`, `NotationFromSkeleton`, etc.). The presence of ICU-related headers (`unicode/numberformatter.h`, `unicode/ucurr.h`) strongly indicates internationalization and formatting capabilities.

* **`.tq` Check:**  The prompt explicitly provides the filename. I just need to check the extension.

* **JavaScript Relationship:** The "js-number-format" in the filename strongly suggests a link to the JavaScript `Intl.NumberFormat` object. I will focus on how the C++ code likely implements the underlying logic for this API.

* **Code Logic Example:** I'll look for a function that takes some input related to formatting options and produces a formatted output or modifies a formatting object. The functions dealing with the ICU skeleton seem like good candidates. I can create a hypothetical skeleton string and infer what the output of functions like `CurrencyFromSkeleton` or `NotationFromSkeleton` would be.

* **Common Errors:** I'll consider common mistakes when using `Intl.NumberFormat` in JavaScript, such as providing invalid locale codes, currency codes, or unit identifiers.

* **Summary:** I'll synthesize the identified functionalities into a brief overview of the code's role.

**Self-Correction/Refinement during thought process:**

* Initially, I might focus too much on the low-level details of the ICU library. I need to keep the focus on the role of *this specific* C++ file within the context of V8 and its connection to JavaScript.
* I need to be careful to distinguish between parsing information from the skeleton and actually *formatting* numbers. The current code seems more focused on setting up the formatter based on options.
* When generating the JavaScript example, I need to ensure it directly relates to the C++ code's functionality. For instance, if the C++ code handles currency display, the JavaScript example should demonstrate setting the `currencyDisplay` option.
```cpp
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
  icu::UnicodeString search("
### 提示词
```
这是目录为v8/src/objects/js-number-format.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-number-format.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  //    [[Currency]]
```