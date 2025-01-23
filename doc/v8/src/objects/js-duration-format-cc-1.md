Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/js-duration-format.cc`. I need to explain what this code does within the V8 JavaScript engine, relating it to JavaScript functionality if applicable, and providing examples. Specifically, I need to address the possibility of it being a Torque file, illustrate its JavaScript relevance, offer code logic with input/output examples, point out common programming errors, and finally summarize its overall function.

Here’s a breakdown of the code's functionalities:

1. **Formatting Durations:** The code is responsible for formatting duration values into human-readable strings. This involves taking a duration represented as a combination of years, months, weeks, days, hours, minutes, seconds, milliseconds, microseconds, and nanoseconds, and formatting it according to specified styles and locales.

2. **Handling Different Styles and Displays:** The code considers different styles for displaying duration components (e.g., "long", "short", "narrow", "numeric", "2-digit") and whether a component should always be displayed.

3. **Localization:** The code utilizes ICU (International Components for Unicode) to handle localization, ensuring that the output is culturally appropriate for different locales. This includes number formatting and list formatting.

4. **Negative Duration Support:** The code handles negative durations and determines when to display the negative sign.

5. **Fractional Seconds:** The code supports displaying fractional seconds with varying levels of precision.

6. **`format` and `formatToParts` Methods:**  The code implements functionalities similar to the `format` and `formatToParts` methods found in JavaScript's `Intl.DurationFormat` proposal (now part of ECMAScript). `format` returns a formatted string, while `formatToParts` returns an array of parts representing the formatted duration.

Now, let's structure the response according to the user's requests.
这是对 `v8/src/objects/js-duration-format.cc` 源代码的功能归纳：

**功能归纳:**

这段 C++ 代码是 V8 JavaScript 引擎中 `Intl.DurationFormat` 功能的核心实现部分。它负责将表示时间长度的对象（DurationRecord）按照用户指定的格式和区域设置（locale）转换成可读的字符串或包含格式化片段的数组。

**具体功能点:**

* **Duration 格式化:** 代码定义了将 `DurationRecord` 对象格式化为字符串的逻辑。`DurationRecord` 内部表示了时间的各个组成部分，如年、月、日、时、分、秒、毫秒、微秒和纳秒。
* **支持多种格式样式 (Style):**  代码支持 `long`, `short`, `narrow` 和 `digital` 等不同的格式样式，这些样式决定了时间单位名称的显示方式（例如 "years" vs. "yr" vs. "y"）。
* **支持不同的显示方式 (Display):** 代码允许配置是否总是显示某个时间单位（`always`），或者只有当其值非零时才显示。
* **数值和两位数格式:** 对于小时等时间单位，支持 `numeric` 和 `2-digit` 两种数值显示格式。
* **处理负数 Duration:** 代码能够正确处理负的时间长度，并根据需要显示负号。
* **小数秒处理:**  代码支持以小数形式显示秒、毫秒和微秒，并允许指定小数位数 (`fractionalDigits`).
* **使用 ICU 库进行国际化:**  代码深度依赖 ICU (International Components for Unicode) 库来进行本地化处理，包括数字格式化和列表格式化，以确保输出的字符串符合不同语言和地区的习惯。
* **实现 `format` 和 `formatToParts` 方法:**  代码实现了类似于 JavaScript 中 `Intl.DurationFormat` 对象的 `format` 和 `formatToParts` 方法。
    * `format` 方法返回一个格式化后的字符串。
    * `formatToParts` 方法返回一个包含格式化片段（如数值和单位）的数组，方便用户进行更灵活的处理。
* **与 JavaScript 交互:** 虽然是 C++ 代码，但它直接服务于 V8 引擎中的 JavaScript `Intl.DurationFormat` 对象的功能。

**关于 .tq 结尾:**

如果 `v8/src/objects/js-duration-format.cc` 以 `.tq` 结尾，那么它就是一个 **v8 Torque 源代码**。Torque 是一种 V8 内部使用的类型安全语言，用于编写性能关键的代码。目前提供的代码片段是 `.cc` 结尾，表明它是标准的 C++ 源代码。

**与 JavaScript 功能的关系及举例:**

这段 C++ 代码是 JavaScript 中 `Intl.DurationFormat` 规范的底层实现。 `Intl.DurationFormat` 允许开发者根据用户的区域设置和指定的选项格式化表示时间长度的对象。

**JavaScript 示例:**

```javascript
const duration = { hours: 1, minutes: 30, seconds: 15 };

// 使用默认设置格式化
const df1 = new Intl.DurationFormat('en');
console.log(df1.format(duration)); // 输出类似 "1 hr, 30 min, 15 sec"

// 指定更详细的格式
const df2 = new Intl.DurationFormat('zh-CN', { style: 'long' });
console.log(df2.format(duration)); // 输出类似 "1 小时 30 分钟 15 秒"

// 使用 formatToParts 获取格式化片段
const df3 = new Intl.DurationFormat('en', { style: 'short' });
console.log(df3.formatToParts(duration));
// 输出类似:
// [
//   { type: 'integer', value: '1' },
//   { type: 'literal', value: ' ' },
//   { type: 'unit', value: 'hr' },
//   { type: 'literal', value: ', ' },
//   { type: 'integer', value: '30' },
//   { type: 'literal', value: ' ' },
//   { type: 'unit', value: 'min' },
//   { type: 'literal', value: ', ' },
//   { type: 'integer', value: '15' },
//   { type: 'literal', value: ' ' },
//   { type: 'unit', value: 'sec' }
// ]
```

**代码逻辑推理及假设输入与输出:**

**假设输入:**

* `df` (DirectHandle<JSDurationFormat>): 一个配置好的 `Intl.DurationFormat` 对象的内部表示，例如，locale 为 "en"，style 为 "short"。
* `record` (DurationRecord):  `{ years: 0, months: 0, weeks: 0, time_duration: { days: 0, hours: 2, minutes: 5, seconds: 30, milliseconds: 0, microseconds: 0, nanoseconds: 0 } }`

**代码逻辑:**  `PartitionDurationFormatPattern` 函数会被调用，它会根据 `df` 的配置和 `record` 的值，使用 ICU 的格式化功能生成格式化的字符串片段。  `DurationRecordToListOfFormattedNumber` 会将 `record` 中的数值和单位信息转换为 ICU 可以处理的格式。 `OutputLongShortNarrowNumericOr2Digit` 等函数会根据 `df` 的配置决定如何格式化每个时间单位。最后，使用 `ListFormatter` 将这些片段组合成最终的字符串。

**预期输出 (对于 `format` 方法):**

对于上述假设输入，并且 `df` 的 style 为 "short"，预期输出的字符串可能类似于 "2 hr, 5 min, 30 sec"。

**涉及用户常见的编程错误:**

* **传递错误的 Duration 对象:** 用户可能会传递一个不符合 `Intl.DurationFormat` 期望结构的 JavaScript 对象作为 duration 参数，导致运行时错误。例如，缺少必要的属性或属性类型不正确。

  ```javascript
  const df = new Intl.DurationFormat('en');
  // 错误：缺少 hours 属性
  const invalidDuration = { minutes: 30 };
  // df.format(invalidDuration); // 这可能会抛出错误
  ```

* **区域设置 (locale) 不存在或拼写错误:**  如果用户提供的 locale 字符串 V8 引擎或 ICU 库不支持，可能会导致 `RangeError`。

  ```javascript
  // 错误：'en-USSSS' 是一个无效的 locale
  // const df = new Intl.DurationFormat('en-USSSS'); // 这会抛出 RangeError
  const df = new Intl.DurationFormat('en-US'); // 正确
  ```

* **误解格式选项:** 用户可能对 `Intl.DurationFormat` 的格式选项（如 `style`, `hours`, `minutes` 的 `display` 等）的含义理解有偏差，导致输出结果不符合预期。需要仔细查阅文档。

**总结 `v8/src/objects/js-duration-format.cc` 的功能 (第 2 部分):**

总而言之，`v8/src/objects/js-duration-format.cc` 的主要功能是 **将表示时间长度的内部数据结构 `DurationRecord`，根据 `Intl.DurationFormat` 对象指定的格式和区域设置，转换为用户可读的字符串或格式化片段数组。** 它利用 ICU 库实现了国际化的支持，并提供了 `format` 和 `formatToParts` 两个核心方法，对应于 JavaScript 中 `Intl.DurationFormat` 的功能。 这段代码是 V8 引擎中实现 `Intl.DurationFormat` 的关键组成部分。

### 提示词
```
这是目录为v8/src/objects/js-duration-format.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-duration-format.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ation, separator, parts, strings);
  }
  return display_negative_sign;
}

bool DisplayRequired(DirectHandle<JSDurationFormat> df,
                     const DurationRecord& record) {
  // 9-h. Let displayRequired be "false".
  // 9-i. Let hoursStyle be durationFormat.[[HoursStyle]].
  // 9-j-i. If hoursStyle is "numeric" or "2-digit", then
  if (df->hours_style() == JSDurationFormat::FieldStyle::kNumeric ||
      df->hours_style() == JSDurationFormat::FieldStyle::k2Digit) {
    // 1. Let hoursDisplay be durationFormat.[[HoursDisplay]].
    // 2. Let hoursValue be durationFormat.[[HoursValue]].
    // 3. If hoursDisplay is "always" or hoursValue is not 0, then
    if (df->hours_display() == JSDurationFormat::Display::kAlways ||
        record.time_duration.hours != 0) {
      // a. Let secondsDisplay be durationFormat.[[SecondsDisplay]].
      // c. If secondsDisplay is "always" or duration.[[Second]] is not 0, or
      // duration.[[Milliseconds]] is not 0, or duration.[[Microseconds]] is not
      // 0, or duration.[[Nanoseconds]] is not 0, then
      if (df->seconds_display() == JSDurationFormat::Display::kAlways ||
          record.time_duration.seconds != 0 ||
          record.time_duration.milliseconds != 0 ||
          record.time_duration.microseconds != 0 ||
          record.time_duration.nanoseconds != 0) {
        // i. Set displayRequired to "true".
        return true;
      }
    }
  }
  return false;
}

void DurationRecordToListOfFormattedNumber(
    DirectHandle<JSDurationFormat> df,
    const icu::number::LocalizedNumberFormatter& fmt,
    const DurationRecord& record, std::vector<std::vector<Part>>* parts,
    std::vector<icu::UnicodeString>* strings) {
  JSDurationFormat::Separator separator = df->separator();
  // 4. Let displayNegativeSign be true.
  bool display_negative_sign = true;
  bool negative_duration = DurationRecord::Sign(record) == -1;

  display_negative_sign = OutputLongShortOrNarrow(
      "year", record.years, df->years_display(),
      fmt.unit(icu::MeasureUnit::getYear())
          .unitWidth(ToUNumberUnitWidth(df->years_style())),
      false, display_negative_sign, negative_duration, separator, parts,
      strings);
  display_negative_sign = OutputLongShortOrNarrow(
      "month", record.months, df->months_display(),
      fmt.unit(icu::MeasureUnit::getMonth())
          .unitWidth(ToUNumberUnitWidth(df->months_style())),
      false, display_negative_sign, negative_duration, separator, parts,
      strings);
  display_negative_sign = OutputLongShortOrNarrow(
      "week", record.weeks, df->weeks_display(),
      fmt.unit(icu::MeasureUnit::getWeek())
          .unitWidth(ToUNumberUnitWidth(df->weeks_style())),
      false, display_negative_sign, negative_duration, separator, parts,
      strings);
  display_negative_sign = OutputLongShortOrNarrow(
      "day", record.time_duration.days, df->days_display(),
      fmt.unit(icu::MeasureUnit::getDay())
          .unitWidth(ToUNumberUnitWidth(df->days_style())),
      false, display_negative_sign, negative_duration, separator, parts,
      strings);
  display_negative_sign = OutputLongShortNarrowNumericOr2Digit(
      "hour", record.time_duration.hours, df->hours_display(),
      df->hours_style(), fmt, icu::MeasureUnit::getHour(), false, false,
      display_negative_sign, negative_duration, separator, parts, strings);
  bool minuteCouldAddToLast =
      df->hours_style() == JSDurationFormat::FieldStyle::kNumeric ||
      df->hours_style() == JSDurationFormat::FieldStyle::k2Digit;
  display_negative_sign = OutputLongShortNarrowNumericOr2Digit(
      "minute", record.time_duration.minutes, df->minutes_display(),
      df->minutes_style(), fmt, icu::MeasureUnit::getMinute(),
      minuteCouldAddToLast, DisplayRequired(df, record), display_negative_sign,
      negative_duration, separator, parts, strings);
  int32_t fractional_digits = df->fractional_digits();
  int32_t maximumFractionDigits;
  int32_t minimumFractionDigits;
  // 2. If durationFormat.[[FractionalDigits]] is undefined, then
  if (fractional_digits == JSDurationFormat::kUndefinedFractionalDigits) {
    // a. Let maximumFractionDigits be 9𝔽.
    maximumFractionDigits = 9;
    // b. Let minimumFractionDigits be +0𝔽.
    minimumFractionDigits = 0;
  } else {  // 3. Else,
    // a. Let maximumFractionDigits be 𝔽(durationFormat.[[FractionalDigits]]).
    maximumFractionDigits = fractional_digits;
    // b. Let minimumFractionDigits be 𝔽(durationFormat.[[FractionalDigits]]).
    minimumFractionDigits = fractional_digits;
  }
  // 4. Perform ! CreateDataPropertyOrThrow(nfOpts, "maximumFractionDigits",
  // maximumFractionDigits ).
  // 5. Perform ! CreateDataPropertyOrThrow(nfOpts, "minimumFractionDigits",
  // minimumFractionDigits ).
  icu::number::LocalizedNumberFormatter nfOps =
      fmt.precision(icu::number::Precision::minMaxFraction(
                        minimumFractionDigits, maximumFractionDigits))
          // 6. Perform ! CreateDataPropertyOrThrow(nfOpts, "roundingMode",
          // "trunc").
          .roundingMode(UNumberFormatRoundingMode::UNUM_ROUND_DOWN);

  if (df->milliseconds_style() == JSDurationFormat::FieldStyle::kFractional) {
    // 1. Set value to value + AddFractionalDigits(durationFormat, duration).
    double value = record.time_duration.nanoseconds / 1e9 +
                   record.time_duration.microseconds / 1e6 +
                   record.time_duration.milliseconds / 1e3 +
                   record.time_duration.seconds;

    OutputLongShortNarrowNumericOr2Digit(
        "second", value, df->seconds_display(), df->seconds_style(), nfOps,
        icu::MeasureUnit::getSecond(), true, false, display_negative_sign,
        negative_duration, separator, parts, strings);
    return;
  }
  display_negative_sign = OutputLongShortNarrowNumericOr2Digit(
      "second", record.time_duration.seconds, df->seconds_display(),
      df->seconds_style(), fmt, icu::MeasureUnit::getSecond(), true, false,
      display_negative_sign, negative_duration, separator, parts, strings);

  if (df->microseconds_style() == JSDurationFormat::FieldStyle::kFractional) {
    // 1. Set value to value + AddFractionalDigits(durationFormat, duration).
    double value = record.time_duration.nanoseconds / 1e6 +
                   record.time_duration.microseconds / 1e3 +
                   record.time_duration.milliseconds;

    OutputLongShortNarrowOrNumeric(
        "millisecond", value, df->milliseconds_display(),
        df->milliseconds_style(), nfOps, icu::MeasureUnit::getMillisecond(),
        false, display_negative_sign, negative_duration, separator, parts,
        strings);
    return;
  }
  display_negative_sign = OutputLongShortNarrowOrNumeric(
      "millisecond", record.time_duration.milliseconds,
      df->milliseconds_display(), df->milliseconds_style(), fmt,
      icu::MeasureUnit::getMillisecond(), false, display_negative_sign,
      negative_duration, separator, parts, strings);

  if (df->nanoseconds_style() == JSDurationFormat::FieldStyle::kFractional) {
    // 1. Set value to value + AddFractionalDigits(durationFormat, duration).
    double value = record.time_duration.nanoseconds / 1e3 +
                   record.time_duration.microseconds;
    OutputLongShortNarrowOrNumeric(
        "microsecond", value, df->microseconds_display(),
        df->microseconds_style(), nfOps, icu::MeasureUnit::getMicrosecond(),
        false, display_negative_sign, negative_duration, separator, parts,
        strings);
    return;
  }
  display_negative_sign = OutputLongShortNarrowOrNumeric(
      "microsecond", record.time_duration.microseconds,
      df->microseconds_display(), df->microseconds_style(), fmt,
      icu::MeasureUnit::getMicrosecond(), false, display_negative_sign,
      negative_duration, separator, parts, strings);

  OutputLongShortNarrowOrNumeric(
      "nanosecond", record.time_duration.nanoseconds, df->nanoseconds_display(),
      df->nanoseconds_style(), fmt, icu::MeasureUnit::getNanosecond(), false,
      display_negative_sign, negative_duration, separator, parts, strings);
}

UListFormatterWidth StyleToWidth(JSDurationFormat::Style style) {
  switch (style) {
    case JSDurationFormat::Style::kLong:
      return ULISTFMT_WIDTH_WIDE;
    case JSDurationFormat::Style::kNarrow:
      return ULISTFMT_WIDTH_NARROW;
    case JSDurationFormat::Style::kShort:
    case JSDurationFormat::Style::kDigital:
      return ULISTFMT_WIDTH_SHORT;
  }
  UNREACHABLE();
}

// The last two arguments passed to the  Format function is only needed
// for Format function to output detail structure and not needed if the
// Format only needs to output a String.
template <typename T, bool Details,
          MaybeHandle<T> (*Format)(Isolate*, const icu::FormattedValue&,
                                   const std::vector<std::vector<Part>>*,
                                   JSDurationFormat::Separator separator)>
MaybeHandle<T> PartitionDurationFormatPattern(Isolate* isolate,
                                              DirectHandle<JSDurationFormat> df,
                                              const DurationRecord& record,
                                              const char* method_name) {
  // 4. Let lfOpts be ! OrdinaryObjectCreate(null).
  // 5. Perform ! CreateDataPropertyOrThrow(lfOpts, "type", "unit").
  UListFormatterType type = ULISTFMT_TYPE_UNITS;
  // 6. Let listStyle be durationFormat.[[Style]].
  // 7. If listStyle is "digital", then
  // a. Set listStyle to "short".
  // 8. Perform ! CreateDataPropertyOrThrow(lfOpts, "style", listStyle).
  UListFormatterWidth list_style = StyleToWidth(df->style());
  // 9. Let lf be ! Construct(%ListFormat%, « durationFormat.[[Locale]], lfOpts
  // »).
  UErrorCode status = U_ZERO_ERROR;
  icu::Locale icu_locale = *df->icu_locale()->raw();
  std::unique_ptr<icu::ListFormatter> formatter(
      icu::ListFormatter::createInstance(icu_locale, type, list_style, status));
  DCHECK(U_SUCCESS(status));

  std::vector<std::vector<Part>> list;
  std::vector<std::vector<Part>>* parts = Details ? &list : nullptr;
  std::vector<icu::UnicodeString> string_list;

  DurationRecordToListOfFormattedNumber(
      df, *(df->icu_number_formatter()->raw()), record, parts, &string_list);

  icu::FormattedList formatted = formatter->formatStringsToValue(
      string_list.data(), static_cast<int32_t>(string_list.size()), status);
  DCHECK(U_SUCCESS(status));
  return Format(isolate, formatted, parts, df->separator());
}

// #sec-todurationrecord
// ToDurationRecord is almost the same as temporal::ToPartialDuration
// except:
// 1) In the beginning it will throw RangeError if the type of input is String,
// 2) In the end it will throw RangeError if IsValidDurationRecord return false.
Maybe<DurationRecord> ToDurationRecord(Isolate* isolate, Handle<Object> input,
                                       const DurationRecord& default_value) {
  // 1-a. If Type(input) is String, throw a RangeError exception.
  if (IsString(*input)) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kInvalid,
                      isolate->factory()->object_string(), input),
        Nothing<DurationRecord>());
  }
  // Step 1-b - 23. Same as ToTemporalPartialDurationRecord.
  DurationRecord record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record,
      temporal::ToPartialDuration(isolate, input, default_value),
      Nothing<DurationRecord>());
  // 24. If IsValidDurationRecord(result) is false, throw a RangeError
  // exception.
  if (!temporal::IsValidDuration(isolate, record)) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewRangeError(MessageTemplate::kInvalid,
                      isolate->factory()->object_string(), input),
        Nothing<DurationRecord>());
  }
  return Just(record);
}

template <typename T, bool Details,
          MaybeHandle<T> (*Format)(Isolate*, const icu::FormattedValue&,
                                   const std::vector<std::vector<Part>>*,
                                   JSDurationFormat::Separator)>
MaybeHandle<T> FormatCommon(Isolate* isolate, Handle<JSDurationFormat> df,
                            Handle<Object> duration, const char* method_name) {
  // 1. Let df be this value.
  // 2. Perform ? RequireInternalSlot(df, [[InitializedDurationFormat]]).
  // 3. Let record be ? ToDurationRecord(duration).
  DurationRecord record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record,
      ToDurationRecord(isolate, duration, {0, 0, 0, {0, 0, 0, 0, 0, 0, 0}}),
      Handle<T>());
  // 5. Let parts be ! PartitionDurationFormatPattern(df, record).
  return PartitionDurationFormatPattern<T, Details, Format>(isolate, df, record,
                                                            method_name);
}

}  // namespace

MaybeHandle<String> FormattedToString(
    Isolate* isolate, const icu::FormattedValue& formatted,
    const std::vector<std::vector<Part>>* parts, JSDurationFormat::Separator) {
  DCHECK_NULL(parts);
  return Intl::FormattedToString(isolate, formatted);
}

MaybeHandle<JSArray> FormattedListToJSArray(
    Isolate* isolate, const icu::FormattedValue& formatted,
    const std::vector<std::vector<Part>>* parts,
    JSDurationFormat::Separator separator) {
  DCHECK_NOT_NULL(parts);
  Factory* factory = isolate->factory();
  Handle<JSArray> array = factory->NewJSArray(0);
  icu::ConstrainedFieldPosition cfpos;
  cfpos.constrainCategory(UFIELD_CATEGORY_LIST);
  int index = 0;
  int part_index = 0;
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString string = formatted.toString(status);
  while (formatted.nextPosition(cfpos, status) && U_SUCCESS(status)) {
    if (cfpos.getField() == ULISTFMT_ELEMENT_FIELD) {
      for (auto& it : parts->at(part_index++)) {
        switch (it.part_type) {
          case Part::Type::kSeparator: {
            icu::UnicodeString sep(SeparatorToChar(separator));
            Handle<String> separator_string;
            ASSIGN_RETURN_ON_EXCEPTION(isolate, separator_string,
                                       Intl::ToString(isolate, sep));
            Intl::AddElement(isolate, array, index++, factory->literal_string(),
                             separator_string);
          } break;
          case Part::Type::kFormatted:
            DirectHandle<String> type_string =
                factory->NewStringFromAsciiChecked(it.type.c_str());
            Maybe<int> index_after_add = Intl::AddNumberElements(
                isolate, it.formatted, array, index, type_string);
            MAYBE_RETURN(index_after_add, MaybeHandle<JSArray>());
            index = index_after_add.FromJust();
            break;
        }
      }
    } else {
      Handle<String> substring;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, substring,
          Intl::ToString(isolate, string, cfpos.getStart(), cfpos.getLimit()));
      Intl::AddElement(isolate, array, index++, factory->literal_string(),
                       substring);
    }
  }
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  JSObject::ValidateElements(*array);
  return array;
}

MaybeHandle<String> JSDurationFormat::Format(Isolate* isolate,
                                             Handle<JSDurationFormat> df,
                                             Handle<Object> duration) {
  const char* method_name = "Intl.DurationFormat.prototype.format";
  return FormatCommon<String, false, FormattedToString>(isolate, df, duration,
                                                        method_name);
}

MaybeHandle<JSArray> JSDurationFormat::FormatToParts(
    Isolate* isolate, Handle<JSDurationFormat> df, Handle<Object> duration) {
  const char* method_name = "Intl.DurationFormat.prototype.formatToParts";
  return FormatCommon<JSArray, true, FormattedListToJSArray>(
      isolate, df, duration, method_name);
}

const std::set<std::string>& JSDurationFormat::GetAvailableLocales() {
  return JSNumberFormat::GetAvailableLocales();
}

}  // namespace internal
}  // namespace v8
```