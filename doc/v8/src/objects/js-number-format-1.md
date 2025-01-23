Response: The user wants a summary of the C++ source code provided.
This is the second part of the file `v8/src/objects/js-number-format.cc`.
I need to understand the functions and classes defined in this part and explain their purpose.
Specifically, I need to highlight the connection to JavaScript functionalities and provide examples.

Looking at the code, I see functions related to:
- Handling mathematical values (`IntlMathematicalValue`).
- Formatting numbers and ranges of numbers.
- Converting formatted numbers into parts (useful for `formatToParts` in JavaScript).
- Interacting with ICU (International Components for Unicode) for number formatting.

Key classes and functions to explain:
- `IntlMathematicalValue`: Represents a number value that can be a Number or a BigInt. It handles conversion from various JavaScript types.
- `FlattenRegionsToParts`:  A crucial function for breaking down a formatted string into meaningful parts based on ICU's field information. This is directly related to JavaScript's `formatToParts`.
- `ConstructParts`: Uses the flattened regions to create an array of parts suitable for JavaScript.
- `JSNumberFormat::FormatNumeric`: Formats a single numeric value.
- `JSNumberFormat::NumberFormatFunction`: The core formatting function called when `Intl.NumberFormat.prototype.format` is invoked.
- `JSNumberFormat::FormatToParts`: Implements the `formatToParts` functionality.
- `JSNumberFormat::FormatNumericRange` and `JSNumberFormat::FormatNumericRangeToParts`: Handle formatting of number ranges.

For the JavaScript examples, I can demonstrate:
- How `IntlMathematicalValue::From` relates to implicit type conversions in JavaScript when passing values to `NumberFormat`.
- How `FlattenRegionsToParts` and `ConstructParts` are used behind the scenes for `formatToParts`.
- Basic usage of `format`, `formatToParts`, and `formatRange`, `formatRangeToParts`.
这段C++代码文件 `v8/src/objects/js-number-format.cc` 的第二部分主要负责以下功能：

**1. 处理和转换数值类型 (`IntlMathematicalValue`)**

- 提供了一个 `IntlMathematicalValue` 类，用于表示可以被 `Intl.NumberFormat` 处理的数值。
- `IntlMathematicalValue::From` 函数负责将 JavaScript 的各种类型的值（包括 `Number`, `BigInt`, `String` 等）转换为 `IntlMathematicalValue` 对象。它会进行必要的类型转换，例如将字符串解析为数字或 BigInt。
- `IntlMathematicalValue::ToFormattable` 函数将 `IntlMathematicalValue` 对象转换为 ICU 可以处理的 `icu::Formattable` 类型。

**JavaScript 示例:**

```javascript
const nf = new Intl.NumberFormat('en-US');

// JavaScript Number 类型直接被处理
console.log(nf.format(12345.67)); // 输出取决于 locale，例如 "12,345.67"

// JavaScript BigInt 类型也被支持
console.log(nf.format(12345678901234567890n)); // 输出取决于 locale，例如 "12,345,678,901,234,567,890"

// JavaScript String 类型如果可以解析为数字，也会被处理
console.log(nf.format("123.45")); // 输出取决于 locale，例如 "123.45"

// 无法解析为数字的字符串会抛出错误（在 `IntlMathematicalValue::From` 中处理）
// try {
//   nf.format("abc"); // 会导致错误
// } catch (e) {
//   console.error(e);
// }
```

**2. 将格式化后的字符串分解为组成部分 (`FlattenRegionsToParts`, `ConstructParts`)**

- `FlattenRegionsToParts` 函数接收一个描述格式化字符串中不同区域（例如整数部分、小数部分、分隔符等）的列表，并将这些可能重叠的区域展平为一组不重叠的 "parts"。这个过程是为了后续生成 `formatToParts` 方法返回的数组。
- `ConstructParts` 函数使用 ICU 的 `FormattedValue` 对象以及 `FlattenRegionsToParts` 的结果，构建一个 JavaScript 数组，其中每个元素描述了格式化字符串的一个部分（例如类型和值）。

**JavaScript 示例:**

```javascript
const nf = new Intl.NumberFormat('de', { style: 'currency', currency: 'EUR' });
const parts = nf.formatToParts(123456.78);
console.log(parts);
// 可能的输出（顺序可能不同）:
// [
//   { type: 'integer', value: '123' },
//   { type: 'group', value: '.' },
//   { type: 'integer', value: '456' },
//   { type: 'decimal', value: ',' },
//   { type: 'fraction', value: '78' },
//   { type: 'literal', value: '\xa0' }, // No-break space
//   { type: 'currency', value: '€' }
// ]
```

**3. 实现 `Intl.NumberFormat` 的核心格式化功能 (`JSNumberFormat::FormatNumeric`, `JSNumberFormat::NumberFormatFunction`, `JSNumberFormat::FormatToParts`)**

- `JSNumberFormat::FormatNumeric` 函数使用 ICU 的 `LocalizedNumberFormatter` 对数值进行格式化，并返回格式化后的字符串。
- `JSNumberFormat::NumberFormatFunction` 是 `Intl.NumberFormat.prototype.format` 方法的底层实现。它首先将 JavaScript 的值转换为 `IntlMathematicalValue`，然后调用 ICU 进行格式化。
- `JSNumberFormat::FormatToParts` 是 `Intl.NumberFormat.prototype.formatToParts` 方法的底层实现。它使用 ICU 进行格式化，然后调用 `ConstructParts` 将结果分解为 parts 数组。

**4. 实现 `Intl.NumberFormat` 的范围格式化功能 (`JSNumberFormat::FormatNumericRange`, `JSNumberFormat::FormatNumericRangeToParts`)**

- `JSNumberFormat::FormatNumericRange` 是 `Intl.NumberFormat.prototype.formatRange` 方法的底层实现，用于格式化一个数值范围。
- `JSNumberFormat::FormatNumericRangeToParts` 是 `Intl.NumberFormat.prototype.formatRangeToParts` 方法的底层实现，用于将格式化后的数值范围分解为 parts 数组。

**JavaScript 示例 (范围格式化):**

```javascript
const nf = new Intl.NumberFormat('en-US');
const formattedRange = nf.formatRange(10, 20);
console.log(formattedRange); // 可能的输出: "10 – 20"

const rangeParts = nf.formatRangeToParts(10, 20);
console.log(rangeParts);
// 可能的输出:
// [
//   { type: 'integer', value: '10' },
//   { type: 'literal', value: ' – ' },
//   { type: 'integer', value: '20' }
// ]
```

**5. 其他辅助功能**

- `TrimWhiteSpaceOrLineTerminator` 函数用于去除字符串开头和结尾的空白字符或行终止符。
- `GetRangeFormatter` 函数用于获取 ICU 的 `LocalizedNumberRangeFormatter` 对象，用于范围格式化。
- `AddNumberElements` 函数用于向 JavaScript 数组中添加格式化数字的组成部分，通常用于 `formatToParts` 的实现。

总而言之，这段代码是 V8 引擎中 `Intl.NumberFormat` 功能的核心实现部分，它负责将 JavaScript 中的数值按照指定的 locale 和选项进行格式化，并支持将格式化后的结果分解为更细粒度的组成部分，这与 JavaScript 的 `format` 和 `formatToParts` 方法直接相关。它也处理了数值范围的格式化。该代码严重依赖 ICU 库来完成实际的国际化处理工作。

### 提示词
```
这是目录为v8/src/objects/js-number-format.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
```