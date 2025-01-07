Response:
The user wants a summary of the provided C++ code snippet from `v8/src/objects/js-number-format.cc`.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core functionality:** The filename `js-number-format.cc` strongly suggests this code deals with the JavaScript `Intl.NumberFormat` object. Scanning the code confirms this, with functions like `FormatNumeric`, `FormatToParts`, and `FormatNumericRange`.

2. **Analyze key classes and functions:**
    * `IntlMathematicalValue`: This class seems to represent a number in a way that's suitable for internationalization. It handles conversions from various JavaScript types (Number, BigInt, String) to a unified representation.
    * `TrimWhiteSpaceOrLineTerminator`:  A utility function for trimming whitespace from strings.
    * `FlattenRegionsToParts`: A core algorithm for breaking down a formatted number string into its constituent parts (e.g., integer part, decimal separator, fraction part). This is crucial for `formatToParts`.
    * `ConstructParts`:  Uses the flattened regions to create JavaScript objects representing the parts of a formatted number.
    * `JSNumberFormat::FormatNumeric`, `JSNumberFormat::FormatToParts`, `JSNumberFormat::FormatNumericRange`, `JSNumberFormat::FormatNumericRangeToParts`: These are the main functions that expose the formatting logic to JavaScript. They interact with the ICU library.
    * `GetRangeFormatter`:  Handles formatting number ranges.

3. **Connect the functionality to JavaScript:**  The prompt asks for JavaScript examples. Consider the standard usage of `Intl.NumberFormat`: formatting numbers and getting the parts. This leads to the examples using `format()` and `formatToParts()`. The `formatRange()` example comes from the functions handling number ranges.

4. **Identify potential errors:** Think about common mistakes users might make when working with number formatting. Invalid input types and out-of-range numbers are good candidates.

5. **Address the `.tq` question:** The prompt specifically asks about `.tq` files (Torque). The code provided is C++, so explicitly state that it's not a Torque file.

6. **Structure the summary:** Organize the information logically into sections like "Core Functionality," "Relationship to JavaScript," "Code Logic and Input/Output," and "Common Programming Errors."  This makes the summary easier to understand.

7. **Infer assumptions and outputs:** For the code logic examples, choose simple cases to illustrate the trimming and the `IntlMathematicalValue::From` conversion.

8. **Review and refine:** Read through the generated summary to ensure accuracy, clarity, and completeness. Make sure it directly answers all parts of the prompt. For example, the initial thought might have focused solely on formatting, but the prompt also mentions the `IntlMathematicalValue` conversion, which needs to be highlighted.
Based on the provided C++ source code snippet from `v8/src/objects/js-number-format.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This code snippet is primarily responsible for the core logic behind the JavaScript `Intl.NumberFormat` object in V8. It handles the formatting of numbers according to specified locales and options. Key aspects include:

* **Converting JavaScript values to a unified mathematical representation:** The `IntlMathematicalValue` class is central to this. It takes a JavaScript value (Number, BigInt, String, etc.) and converts it into a representation that can be easily handled by the ICU library for formatting. This involves:
    * Handling different primitive types (BigInt, Number, Oddball).
    * Parsing strings into numbers, including handling non-decimal integer literals (binary, octal, hexadecimal).
    * Trimming whitespace from input strings before parsing.
    * Detecting and handling `NaN`, `Infinity`, and `-Infinity`.
* **Interfacing with the ICU (International Components for Unicode) library:**  The code utilizes ICU to perform the actual number formatting. It interacts with ICU's `number::LocalizedNumberFormatter` and `number::LocalizedNumberRangeFormatter` to apply locale-specific formatting rules.
* **Formatting numbers and number ranges:** The code provides functions like `FormatNumeric` and `FormatNumericRange` to format single numbers and ranges of numbers, respectively.
* **Generating "parts" of a formatted number:** The `FormatToParts` and `FormatNumericRangeToParts` functions are crucial for the `formatToParts()` method in JavaScript. They break down the formatted number string into an array of objects, each representing a specific part (e.g., integer part, decimal separator, fraction part, currency symbol). The `FlattenRegionsToParts` function plays a key role in this by resolving overlapping "regions" of formatting.
* **Handling unit formatting:** There's logic to handle the special case when the `style` option is "unit".
* **Providing available locales:** The `GetAvailableLocales` function provides a list of locales supported by the number formatter.

**Relationship to JavaScript (with examples):**

This C++ code directly implements the functionality exposed by the `Intl.NumberFormat` object in JavaScript.

```javascript
// Example using Intl.NumberFormat to format a number
const formatter = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' });
const formattedNumber = formatter.format(123456.789);
console.log(formattedNumber); // Output: "$123,456.79"

// Example using formatToParts to get the individual parts
const partsFormatter = new Intl.NumberFormat('de-DE');
const parts = partsFormatter.formatToParts(1234.56);
console.log(parts);
// Output (approximately):
// [
//   { type: "integer", value: "1" },
//   { type: "group", value: "." },
//   { type: "integer", value: "234" },
//   { type: "decimal", value: "," },
//   { type: "fraction", value: "56" }
// ]

// Example using formatRange for number ranges
const rangeFormatter = new Intl.NumberFormat('en-US');
const formattedRange = rangeFormatter.formatRange(10, 20);
console.log(formattedRange); // Output: "10 – 20"

// Example using formatRangeToParts for number ranges
const rangePartsFormatter = new Intl.NumberFormat('en-US');
const rangeParts = rangePartsFormatter.formatRangeToParts(10, 20);
console.log(rangeParts);
// Output (approximately):
// [
//   { type: "integer", value: "10", source: "startRange" },
//   { type: "literal", value: " – ", source: "shared" },
//   { type: "integer", value: "20", source: "endRange" }
// ]
```

**Code Logic Inference (with assumptions and I/O):**

**Assumption:**  Input is a JavaScript string representing a number with leading/trailing whitespace.

**Input:**  `string = "  123.45  "`

**Function Called:** `TrimWhiteSpaceOrLineTerminator(isolate, string)`

**Logic:** The function will identify the leading and trailing whitespace characters.

**Output:** A new JavaScript string: `"123.45"`

**Assumption:** Input is a JavaScript string representing a non-decimal integer literal.

**Input:** `value` is a JavaScript string `"0x1A"`

**Function Called:** `IntlMathematicalValue::From(isolate, value)`

**Logic:** The function will detect the `"0x"` prefix, parse it as a hexadecimal number (26), and create an `IntlMathematicalValue` object representing this number.

**Output:** An `IntlMathematicalValue` object where `result.approx_` would be `26`, and `result.value_` would likely be a Number object representing 26.

**Common Programming Errors (and how this code handles them):**

* **Passing non-numeric strings to `Intl.NumberFormat.format()`:**
    * **Example:** `formatter.format("abc");`
    * **Handling:** The `IntlMathematicalValue::From` function will attempt to convert the string to a number. If it fails (e.g., "abc"), it will result in `NaN`, which is then handled appropriately by the formatting logic.
* **Providing invalid locale strings to the `Intl.NumberFormat` constructor:**
    * **Example:** `new Intl.NumberFormat('xx-YY');` (invalid locale)
    * **Handling:** While this specific snippet doesn't directly handle constructor errors, the `GetAvailableLocales` function and the interaction with ICU at a higher level would detect and potentially throw errors or fallback to a default locale.
* **Passing `null` or `undefined` without proper handling:**
    * **Example:** `formatter.format(null);`
    * **Handling:** `IntlMathematicalValue::From` handles `Oddball` values like `null` and converts them to their numeric equivalents (0 for `null`).

**归纳一下它的功能 (Summary of its function):**

This C++ code implements the core number formatting functionality of JavaScript's `Intl.NumberFormat` object within the V8 JavaScript engine. It acts as a bridge between JavaScript values and the ICU library, handling the conversion of JavaScript numbers and strings into a format suitable for internationalized number formatting. It provides the logic to format numbers, number ranges, and to break down formatted numbers into their constituent parts for granular control. The code is crucial for providing correct and locale-aware number representation in JavaScript applications.

**Regarding the `.tq` question:**

The code snippet you provided is written in **C++**, not Torque. If `v8/src/objects/js-number-format.cc` had a `.tq` extension, it would indeed be a V8 Torque source file. Torque is a domain-specific language used within V8 for implementing built-in JavaScript functions and objects in a more type-safe and performance-oriented way than pure C++. However, based on the content you've provided, this file is standard C++.

Prompt: 
```
这是目录为v8/src/objects/js-number-format.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-number-format.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
atContent flat = string->GetFlatContent(no_gc);
    if (flat.IsOneByte()) {
      whitespace_offsets = FindLeadingAndTrailingWhiteSpaceOrLineTerminator(
          flat.ToOneByteVector());
    } else {
      whitespace_offsets =
          FindLeadingAndTrailingWhiteSpaceOrLineTerminator(flat.ToUC16Vector());
    }
  }
  if (whitespace_offsets.first == 0 &&
      string->length() == whitespace_offsets.second) {
    return string;
  }
  return isolate->factory()->NewSubString(string, whitespace_offsets.first,
                                          whitespace_offsets.second);
}

}  // namespace

// #sec-tointlmathematicalvalue
Maybe<IntlMathematicalValue> IntlMathematicalValue::From(Isolate* isolate,
                                                         Handle<Object> value) {
  Factory* factory = isolate->factory();
  // 1. Let primValue be ? ToPrimitive(value, number).
  Handle<Object> prim_value;
  if (IsJSReceiver(*value)) {
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, prim_value,
        JSReceiver::ToPrimitive(isolate, Cast<JSReceiver>(value),
                                ToPrimitiveHint::kNumber),
        Nothing<IntlMathematicalValue>());
  } else {
    prim_value = value;
  }
  IntlMathematicalValue result;
  // 2. If Type(primValue) is BigInt, return the mathematical value of
  // primValue.
  if (IsBigInt(*prim_value)) {
    result.value_ = prim_value;
    result.approx_ = Cast<BigInt>(prim_value)->AsInt64();
    return Just(result);
  }
  if (IsOddball(*prim_value)) {
    prim_value = Oddball::ToNumber(isolate, Cast<Oddball>(prim_value));
  }
  if (IsNumber(*prim_value)) {
    result.value_ = prim_value;
    result.approx_ = Object::NumberValue(*prim_value);
    return Just(result);
  }
  if (!IsString(*prim_value)) {
    // No need to convert from Number to String, just call ToNumber.
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, result.value_,
                                     Object::ToNumber(isolate, prim_value),
                                     Nothing<IntlMathematicalValue>());
    result.approx_ = Object::NumberValue(*result.value_);
    return Just(result);
  }
  Handle<String> string = Cast<String>(prim_value);

  string = TrimWhiteSpaceOrLineTerminator(isolate, string);
  if (string->length() == 0) {
    result.value_ = handle(Smi::zero(), isolate);
    result.approx_ = 0;
    return Just(result);
  }
  // We may have a NonDecimalIntegerLiteral:
  if (2 < string->length() && string->Get(0) == '0') {
    uint16_t ch = string->Get(1);
    if (ch == 'b' || ch == 'B' || ch == 'o' || ch == 'O' || ch == 'x' ||
        ch == 'X') {
      result.approx_ =
          StringToDouble(isolate, string, ALLOW_NON_DECIMAL_PREFIX, 0);
      // If approx is within the precision, just return as Number.
      if (result.approx_ < kMaxSafeInteger) {
        result.value_ = isolate->factory()->NewNumber(result.approx_);
        return Just(result);
      }
      // Otherwise return the BigInt
      MaybeHandle<BigInt> maybe_bigint = StringToBigInt(isolate, string);
      // If the parsing of BigInt fail, return nan
      if (maybe_bigint.is_null()) {
        isolate->clear_exception();
        result.value_ = factory->nan_value();
        return Just(result);
      }
      result.value_ = maybe_bigint.ToHandleChecked();
      return Just(result);
    }
  }
  // If it does not fit StrDecimalLiteral StrWhiteSpace_opt, StringToDouble will
  // parse it as NaN, in that case, return NaN.
  result.approx_ = StringToDouble(isolate, string, NO_CONVERSION_FLAG, 0);
  if (std::isnan(result.approx_)) {
    result.value_ = factory->nan_value();
    return Just(result);
  }
  // Handle Infinity / +Infinity / -Infinity
  if (!std::isfinite(result.approx_)) {
    if (result.approx_ < 0) {
      result.value_ = factory->minus_infinity_value();
    } else {
      result.value_ = factory->infinity_value();
    }
    return Just(result);
  }
  // At this point, str is for sure fit
  // "StrNumericLiteral StrWhiteSpace_opt" excluding "(+|-)?Infinity"
  result.value_ = string;

  return Just(result);
}

Maybe<icu::Formattable> IntlMathematicalValue::ToFormattable(
    Isolate* isolate) const {
  if (IsNumber(*value_)) {
    return Just(icu::Formattable(approx_));
  }
  Handle<String> string;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, string, ToString(isolate),
                                   Nothing<icu::Formattable>());
  UErrorCode status = U_ZERO_ERROR;
  {
    DisallowGarbageCollection no_gc;
    const String::FlatContent& flat = string->GetFlatContent(no_gc);
    int32_t length = static_cast<int32_t>(string->length());
    if (flat.IsOneByte()) {
      icu::Formattable result(
          {reinterpret_cast<const char*>(flat.ToOneByteVector().begin()),
           length},
          status);
      if (U_SUCCESS(status)) return Just(result);
    } else {
      icu::Formattable result({string->ToCString().get(), length}, status);
      if (U_SUCCESS(status)) return Just(result);
    }
  }
  THROW_NEW_ERROR_RETURN_VALUE(isolate,
                               NewTypeError(MessageTemplate::kIcuError),
                               Nothing<icu::Formattable>());
}

namespace {
bool cmp_NumberFormatSpan(const NumberFormatSpan& a,
                          const NumberFormatSpan& b) {
  // Regions that start earlier should be encountered earlier.
  if (a.begin_pos < b.begin_pos) return true;
  if (a.begin_pos > b.begin_pos) return false;
  // For regions that start in the same place, regions that last longer should
  // be encountered earlier.
  if (a.end_pos < b.end_pos) return false;
  if (a.end_pos > b.end_pos) return true;
  // For regions that are exactly the same, one of them must be the "literal"
  // backdrop we added, which has a field_id of -1, so consider higher field_ids
  // to be later.
  return a.field_id < b.field_id;
}

}  // namespace

// Flattens a list of possibly-overlapping "regions" to a list of
// non-overlapping "parts". At least one of the input regions must span the
// entire space of possible indexes. The regions parameter will sorted in-place
// according to some criteria; this is done for performance to avoid copying the
// input.
std::vector<NumberFormatSpan> FlattenRegionsToParts(
    std::vector<NumberFormatSpan>* regions) {
  // The intention of this algorithm is that it's used to translate ICU "fields"
  // to JavaScript "parts" of a formatted string. Each ICU field and JavaScript
  // part has an integer field_id, which corresponds to something like "grouping
  // separator", "fraction", or "percent sign", and has a begin and end
  // position. Here's a diagram of:

  // var nf = new Intl.NumberFormat(['de'], {style:'currency',currency:'EUR'});
  // nf.formatToParts(123456.78);

  //               :       6
  //  input regions:    0000000211 7
  // ('-' means -1):    ------------
  // formatted string: "123.456,78 €"
  // output parts:      0006000211-7

  // To illustrate the requirements of this algorithm, here's a contrived and
  // convoluted example of inputs and expected outputs:

  //              :          4
  //              :      22 33    3
  //              :      11111   22
  // input regions:     0000000  111
  //              :     ------------
  // formatted string: "abcdefghijkl"
  // output parts:      0221340--231
  // (The characters in the formatted string are irrelevant to this function.)

  // We arrange the overlapping input regions like a mountain range where
  // smaller regions are "on top" of larger regions, and we output a birds-eye
  // view of the mountains, so that smaller regions take priority over larger
  // regions.
  std::sort(regions->begin(), regions->end(), cmp_NumberFormatSpan);
  std::vector<size_t> overlapping_region_index_stack;
  // At least one item in regions must be a region spanning the entire string.
  // Due to the sorting above, the first item in the vector will be one of them.
  overlapping_region_index_stack.push_back(0);
  NumberFormatSpan top_region = regions->at(0);
  size_t region_iterator = 1;
  int32_t entire_size = top_region.end_pos;

  std::vector<NumberFormatSpan> out_parts;

  // The "climber" is a cursor that advances from left to right climbing "up"
  // and "down" the mountains. Whenever the climber moves to the right, that
  // represents an item of output.
  int32_t climber = 0;
  while (climber < entire_size) {
    int32_t next_region_begin_pos;
    if (region_iterator < regions->size()) {
      next_region_begin_pos = regions->at(region_iterator).begin_pos;
    } else {
      // finish off the rest of the input by proceeding to the end.
      next_region_begin_pos = entire_size;
    }

    if (climber < next_region_begin_pos) {
      while (top_region.end_pos < next_region_begin_pos) {
        if (climber < top_region.end_pos) {
          // step down
          out_parts.push_back(NumberFormatSpan(top_region.field_id, climber,
                                               top_region.end_pos));
          climber = top_region.end_pos;
        } else {
          // drop down
        }
        overlapping_region_index_stack.pop_back();
        top_region = regions->at(overlapping_region_index_stack.back());
      }
      if (climber < next_region_begin_pos) {
        // cross a plateau/mesa/valley
        out_parts.push_back(NumberFormatSpan(top_region.field_id, climber,
                                             next_region_begin_pos));
        climber = next_region_begin_pos;
      }
    }
    if (region_iterator < regions->size()) {
      overlapping_region_index_stack.push_back(region_iterator++);
      top_region = regions->at(overlapping_region_index_stack.back());
    }
  }
  return out_parts;
}

namespace {
Maybe<int> ConstructParts(Isolate* isolate,
                          const icu::FormattedValue& formatted,
                          Handle<JSArray> result, int start_index,
                          bool style_is_unit, bool is_nan, bool output_source,
                          bool output_unit, DirectHandle<String> unit) {
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString formatted_text = formatted.toString(status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NewTypeError(MessageTemplate::kIcuError), Nothing<int>());
  }
  int32_t length = formatted_text.length();
  int index = start_index;
  if (length == 0) return Just(index);

  std::vector<NumberFormatSpan> regions;
  // Add a "literal" backdrop for the entire string. This will be used if no
  // other region covers some part of the formatted string. It's possible
  // there's another field with exactly the same begin and end as this backdrop,
  // in which case the backdrop's field_id of -1 will give it lower priority.
  regions.push_back(NumberFormatSpan(-1, 0, formatted_text.length()));
  Intl::FormatRangeSourceTracker tracker;
  {
    icu::ConstrainedFieldPosition cfpos;
    while (formatted.nextPosition(cfpos, status)) {
      int32_t category = cfpos.getCategory();
      int32_t field = cfpos.getField();
      int32_t start = cfpos.getStart();
      int32_t limit = cfpos.getLimit();
      if (category == UFIELD_CATEGORY_NUMBER_RANGE_SPAN) {
        DCHECK_LE(field, 2);
        tracker.Add(field, start, limit);
      } else {
        regions.push_back(NumberFormatSpan(field, start, limit));
      }
    }
  }

  std::vector<NumberFormatSpan> parts = FlattenRegionsToParts(&regions);

  for (auto it = parts.begin(); it < parts.end(); it++) {
    NumberFormatSpan part = *it;
    DirectHandle<String> field_type_string =
        isolate->factory()->literal_string();
    if (part.field_id != -1) {
      if (style_is_unit && static_cast<UNumberFormatFields>(part.field_id) ==
                               UNUM_PERCENT_FIELD) {
        // Special case when style is unit.
        field_type_string = isolate->factory()->unit_string();
      } else {
        field_type_string =
            Intl::NumberFieldToType(isolate, part, formatted_text, is_nan);
      }
    }
    Handle<String> substring;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, substring,
        Intl::ToString(isolate, formatted_text, part.begin_pos, part.end_pos),
        Nothing<int>());

    if (output_source) {
      Intl::AddElement(
          isolate, result, index, field_type_string, substring,
          isolate->factory()->source_string(),
          Intl::SourceString(isolate,
                             tracker.GetSource(part.begin_pos, part.end_pos)));
    } else {
      if (output_unit) {
        Intl::AddElement(isolate, result, index, field_type_string, substring,
                         isolate->factory()->unit_string(), unit);
      } else {
        Intl::AddElement(isolate, result, index, field_type_string, substring);
      }
    }
    ++index;
  }
  JSObject::ValidateElements(*result);
  return Just(index);
}

}  // namespace

Maybe<int> Intl::AddNumberElements(Isolate* isolate,
                                   const icu::FormattedValue& formatted,
                                   Handle<JSArray> result, int start_index,
                                   DirectHandle<String> unit) {
  return ConstructParts(isolate, formatted, result, start_index, true, false,
                        false, true, unit);
}

namespace {

// #sec-partitionnumberrangepattern
template <typename T, MaybeHandle<T> (*F)(
                          Isolate*, const icu::FormattedValue&,
                          const icu::number::LocalizedNumberFormatter&, bool)>
MaybeHandle<T> PartitionNumberRangePattern(
    Isolate* isolate, DirectHandle<JSNumberFormat> number_format,
    Handle<Object> start, Handle<Object> end, const char* func_name) {
  Factory* factory = isolate->factory();
  // 4. Let x be ? ToIntlMathematicalValue(start).
  IntlMathematicalValue x;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, x, IntlMathematicalValue::From(isolate, start), Handle<T>());

  // 5. Let y be ? ToIntlMathematicalValue(end).
  IntlMathematicalValue y;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, y, IntlMathematicalValue::From(isolate, end), Handle<T>());

  // 1. If x is not-a-number or y is not-a-number, throw a RangeError exception.
  if (x.IsNaN()) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kInvalid,
                      factory->NewStringFromStaticChars("start"), start),
        MaybeHandle<T>());
  }
  if (y.IsNaN()) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kInvalid,
                      factory->NewStringFromStaticChars("end"), end),
        MaybeHandle<T>());
  }

  Maybe<icu::number::LocalizedNumberRangeFormatter> maybe_range_formatter =
      JSNumberFormat::GetRangeFormatter(
          isolate, number_format->locale(),
          *number_format->icu_number_formatter()->raw());
  MAYBE_RETURN(maybe_range_formatter, MaybeHandle<T>());

  icu::number::LocalizedNumberRangeFormatter nrfmt =
      maybe_range_formatter.FromJust();

  Maybe<icu::number::FormattedNumberRange> maybe_formatted =
      IntlMathematicalValue::FormatRange(isolate, nrfmt, x, y);
  MAYBE_RETURN(maybe_formatted, Handle<T>());
  icu::number::FormattedNumberRange formatted =
      std::move(maybe_formatted).FromJust();

  return F(isolate, formatted, *(number_format->icu_number_formatter()->raw()),
           false /* is_nan */);
}

MaybeHandle<String> FormatToString(Isolate* isolate,
                                   const icu::FormattedValue& formatted,
                                   const icu::number::LocalizedNumberFormatter&,
                                   bool) {
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString result = formatted.toString(status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  return Intl::ToString(isolate, result);
}

MaybeHandle<JSArray> FormatToJSArray(
    Isolate* isolate, const icu::FormattedValue& formatted,
    const icu::number::LocalizedNumberFormatter& nfmt, bool is_nan,
    bool output_source) {
  UErrorCode status = U_ZERO_ERROR;
  bool is_unit = Style::UNIT == StyleFromSkeleton(nfmt.toSkeleton(status));
  CHECK(U_SUCCESS(status));

  Factory* factory = isolate->factory();
  Handle<JSArray> result = factory->NewJSArray(0);

  int format_to_parts;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, format_to_parts,
      ConstructParts(isolate, formatted, result, 0, is_unit, is_nan,
                     output_source, false, Handle<String>()),
      Handle<JSArray>());
  USE(format_to_parts);

  return result;
}

MaybeHandle<JSArray> FormatRangeToJSArray(
    Isolate* isolate, const icu::FormattedValue& formatted,
    const icu::number::LocalizedNumberFormatter& nfmt, bool is_nan) {
  return FormatToJSArray(isolate, formatted, nfmt, is_nan, true);
}

}  // namespace

Maybe<icu::number::LocalizedNumberRangeFormatter>
JSNumberFormat::GetRangeFormatter(
    Isolate* isolate, Tagged<String> locale,
    const icu::number::LocalizedNumberFormatter& number_formatter) {
  UErrorCode status = U_ZERO_ERROR;
  UParseError perror;
  icu::number::LocalizedNumberRangeFormatter range_formatter =
      icu::number::UnlocalizedNumberRangeFormatter()
          .numberFormatterBoth(icu::number::NumberFormatter::forSkeleton(
              number_formatter.toSkeleton(status), perror, status))
          .locale(
              icu::Locale::forLanguageTag(locale->ToCString().get(), status));
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NewTypeError(MessageTemplate::kIcuError),
        Nothing<icu::number::LocalizedNumberRangeFormatter>());
  }
  return Just(range_formatter);
}

MaybeHandle<String> JSNumberFormat::FormatNumeric(
    Isolate* isolate,
    const icu::number::LocalizedNumberFormatter& number_format,
    Handle<Object> numeric_obj) {
  Maybe<icu::number::FormattedNumber> maybe_format =
      IcuFormatNumber(isolate, number_format, numeric_obj);
  MAYBE_RETURN(maybe_format, Handle<String>());
  icu::number::FormattedNumber formatted = std::move(maybe_format).FromJust();

  return FormatToString(isolate, formatted, number_format, IsNaN(*numeric_obj));
}

MaybeHandle<String> JSNumberFormat::NumberFormatFunction(
    Isolate* isolate, DirectHandle<JSNumberFormat> number_format,
    Handle<Object> value) {
  icu::number::LocalizedNumberFormatter* fmt =
      number_format->icu_number_formatter()->raw();
  CHECK_NOT_NULL(fmt);

  // 4. Let x be ? ToIntlMathematicalValue(value).
  IntlMathematicalValue x;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, x, IntlMathematicalValue::From(isolate, value),
      Handle<String>());

  // 5. Return FormatNumeric(nf, x).
  Maybe<icu::number::FormattedNumber> maybe_formatted =
      IntlMathematicalValue::FormatNumeric(isolate, *fmt, x);
  MAYBE_RETURN(maybe_formatted, Handle<String>());
  icu::number::FormattedNumber formatted =
      std::move(maybe_formatted).FromJust();

  return FormatToString(isolate, formatted, *fmt, x.IsNaN());
}

MaybeHandle<JSArray> JSNumberFormat::FormatToParts(
    Isolate* isolate, DirectHandle<JSNumberFormat> number_format,
    Handle<Object> numeric_obj) {
  icu::number::LocalizedNumberFormatter* fmt =
      number_format->icu_number_formatter()->raw();
  DCHECK_NOT_NULL(fmt);
  IntlMathematicalValue value;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, value, IntlMathematicalValue::From(isolate, numeric_obj),
      Handle<JSArray>());

  Maybe<icu::number::FormattedNumber> maybe_formatted =
      IntlMathematicalValue::FormatNumeric(isolate, *fmt, value);
  MAYBE_RETURN(maybe_formatted, Handle<JSArray>());
  icu::number::FormattedNumber formatted =
      std::move(maybe_formatted).FromJust();

  return FormatToJSArray(isolate, formatted, *fmt, value.IsNaN(), false);
}

// #sec-number-format-functions

MaybeHandle<String> JSNumberFormat::FormatNumericRange(
    Isolate* isolate, DirectHandle<JSNumberFormat> number_format,
    Handle<Object> x_obj, Handle<Object> y_obj) {
  return PartitionNumberRangePattern<String, FormatToString>(
      isolate, number_format, x_obj, y_obj,
      "Intl.NumberFormat.prototype.formatRange");
}

MaybeHandle<JSArray> JSNumberFormat::FormatNumericRangeToParts(
    Isolate* isolate, DirectHandle<JSNumberFormat> number_format,
    Handle<Object> x_obj, Handle<Object> y_obj) {
  return PartitionNumberRangePattern<JSArray, FormatRangeToJSArray>(
      isolate, number_format, x_obj, y_obj,
      "Intl.NumberFormat.prototype.formatRangeToParts");
}

namespace {

struct CheckNumberElements {
  static const char* key() { return "NumberElements"; }
  static const char* path() { return nullptr; }
};

}  // namespace

const std::set<std::string>& JSNumberFormat::GetAvailableLocales() {
  static base::LazyInstance<Intl::AvailableLocales<CheckNumberElements>>::type
      available_locales = LAZY_INSTANCE_INITIALIZER;
  return available_locales.Pointer()->Get();
}

}  // namespace internal
}  // namespace v8

"""


```