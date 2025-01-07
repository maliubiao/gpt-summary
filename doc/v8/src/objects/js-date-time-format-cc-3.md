Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/objects/js-date-time-format.cc`. I need to analyze the code and explain its purpose, relating it to JavaScript functionality where applicable. I should also consider the possibility of it being a Torque file (though the prompt says it's `.cc`), provide examples, and discuss potential user errors. Finally, I need to summarize the overall function.

Here's a breakdown of the tasks:

1. **Functionality Listing:**  Identify the core operations performed by the code. This includes handling date and time formatting, locale resolution, and interaction with ICU (International Components for Unicode).
2. **Torque Check:** Confirm that the file extension is `.cc` and not `.tq`.
3. **JavaScript Relationship:**  Illustrate how the C++ code connects to JavaScript's `Intl.DateTimeFormat` API.
4. **Code Logic Inference:**  Analyze the code flow, especially the `InitializeDateTimeFormat` function and the formatting logic, to provide examples of input and output.
5. **Common Programming Errors:**  Identify typical mistakes users might make when using the related JavaScript API.
6. **Summary:** Condense the identified functionalities into a concise overview.
```
v8/src/objects/js-date-time-format.cc 的功能：

1. **初始化 `Intl.DateTimeFormat` 对象:** 该代码负责创建和初始化 `Intl.DateTimeFormat` 对象的内部表示。这包括处理传入的 `locales` 和 `options` 参数，并根据这些参数配置 ICU (International Components for Unicode) 库来进行日期和时间格式化。

2. **处理日期和时间格式选项:** 代码解析 `Intl.DateTimeFormat` 的选项，例如 `weekday`, `year`, `month`, `day`, `hour`, `minute`, `second`, `timeZone`, `hour12`, `hourCycle` 等，并将它们映射到 ICU 相应的格式化规则。

3. **根据选项构建 ICU 格式化模式 (skeleton):**  代码根据提供的选项生成一个 ICU 可以理解的格式化模式字符串 (skeleton)。例如，如果选项中包含 `year: 'numeric'`, `month: '2-digit'`, `day: 'numeric'`，则会生成类似于 "yMd" 的 skeleton。

4. **使用 ICU 进行本地化:** 代码利用 ICU 库来处理不同语言和地区的日期和时间格式。它根据提供的 `locales` 参数选择合适的 ICU `Locale` 对象，并使用该 `Locale` 创建 `icu::SimpleDateFormat` 或 `icu::DateIntervalFormat` 对象。

5. **缓存 ICU 格式化对象:** 代码中使用了缓存 (`CreateICUDateFormatFromCache`) 来避免重复创建相同的 ICU 格式化对象，从而提高性能。

6. **格式化日期和时间:**  `FormatToParts` 函数使用 ICU 格式化给定的日期对象，并将其分解为包含类型 (例如 "year", "month", "day") 和值的部件数组。

7. **格式化日期和时间范围:** `FormatRange` 和 `FormatRangeToParts` 函数使用 ICU 格式化给定的日期范围，并将其格式化为字符串或分解为部件数组。

8. **处理 Temporal API (如果启用):** 代码中包含对 ECMAScript Temporal API 的支持 (`v8_flags.harmony_temporal`)，允许使用 Temporal 类型 (例如 `Temporal.PlainDate`, `Temporal.ZonedDateTime`) 进行格式化。

9. **处理 `hourCycle` 选项:** 代码根据 `hour12` 和 `hourCycle` 选项正确设置 `dateTimeFormat.[[HourCycle]]` 内部槽，并处理与 Unicode 扩展键 "hc" 的冲突。

10. **错误处理:** 代码中包含了对 ICU 错误 (`U_FAILURE(status)`) 的检查，并在发生错误时抛出 JavaScript 异常 (例如 `TypeError`, `RangeError`)。

**如果 v8/src/objects/js-date-time-format.cc 以 .tq 结尾，那它是个 v8 torque 源代码：**

当前代码片段的文件名是 `js-date-time-format.cc`，以 `.cc` 结尾，所以它是 C++ 源代码，而不是 Torque 源代码。 Torque 文件通常用于定义运行时函数的签名和类型，而 C++ 文件则包含具体的实现逻辑。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

`v8/src/objects/js-date-time-format.cc` 的主要功能是为 JavaScript 的 `Intl.DateTimeFormat` API 提供底层实现。

```javascript
// 创建一个日期对象
const date = new Date(2023, 10, 20, 10, 30, 0); // 2023年11月20日 10:30:00

// 创建一个 Intl.DateTimeFormat 对象，指定语言环境和选项
const formatter = new Intl.DateTimeFormat('zh-CN', {
  year: 'numeric',
  month: 'long',
  day: 'numeric',
  hour: 'numeric',
  minute: '2-digit',
  second: '2-digit'
});

// 使用 formatter 格式化日期
const formattedDate = formatter.format(date);
console.log(formattedDate); // 输出类似于 "2023年11月20日 10:30:00"

// 使用 formatToParts 获取格式化的部件
const parts = formatter.formatToParts(date);
console.log(parts);
/* 输出类似：
[
  { type: 'year', value: '2023' },
  { type: 'literal', value: '年' },
  { type: 'month', value: '十一月' },
  { type: 'literal', value: '日' },
  { type: 'day', value: '20' },
  { type: 'literal', value: ' ' },
  { type: 'hour', value: '10' },
  { type: 'literal', value: ':' },
  { type: 'minute', value: '30' },
  { type: 'literal', value: ':' },
  { type: 'second', value: '00' }
]
*/

// 格式化日期范围
const startDate = new Date(2023, 10, 15);
const endDate = new Date(2023, 10, 20);
const rangeFormatter = new Intl.DateTimeFormat('zh-CN', {
  year: 'numeric',
  month: 'long',
  day: 'numeric'
});
const formattedRange = rangeFormatter.formatRange(startDate, endDate);
console.log(formattedRange); // 输出类似于 "2023年11月15日 - 2023年11月20日"

const rangeParts = rangeFormatter.formatRangeToParts(startDate, endDate);
console.log(rangeParts);
/* 输出类似：
[
  { type: 'month', value: '十一月', source: 'startRange' },
  { type: 'literal', value: '日', source: 'startRange' },
  { type: 'day', value: '15', source: 'startRange' },
  { type: 'literal', value: ' - ', source: 'shared' },
  { type: 'month', value: '十一月', source: 'endRange' },
  { type: 'literal', value: '日', source: 'endRange' },
  { type: 'day', value: '20', source: 'endRange' }
]
*/
```

在幕后，V8 引擎会调用 `v8/src/objects/js-date-time-format.cc` 中的 C++ 代码来处理这些 `Intl.DateTimeFormat` 的操作。

**如果有代码逻辑推理，请给出假设输入与输出:**

假设 JavaScript 代码创建了一个 `Intl.DateTimeFormat` 对象如下：

```javascript
const formatter = new Intl.DateTimeFormat('en-US', {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  weekday: 'short'
});
```

当调用 `formatter.format(new Date(2024, 0, 25))` 时，`v8/src/objects/js-date-time-format.cc` 中的 `InitializeDateTimeFormat` 函数会接收到语言环境 'en-US' 和选项 `{ year: 'numeric', month: 'short', day: 'numeric', weekday: 'short' }`。

**假设输入 (C++ 端):**

* `icu_locale`: 一个表示 "en-US" 的 `icu::Locale` 对象。
* `formatOptions`:  一个内部数据结构，表示 JavaScript 传递的选项，包含：
    * `year`: "numeric"
    * `month`: "short"
    * `day`: "numeric"
    * `weekday`: "short"

**代码逻辑推理:**

1. 代码会根据 `formatOptions` 构建一个 ICU 格式化模式 (skeleton)。由于指定了 `year`, `month`, `day`, 和 `weekday`，skeleton 可能会是 "yMdE"。
2. 代码会尝试从缓存中获取与 "en-US" 和 "yMdE" 对应的 `icu::SimpleDateFormat` 对象。
3. 如果缓存中没有，则会创建一个新的 `icu::SimpleDateFormat` 对象，并使用 "en-US" locale 和 "yMdE" 模式进行初始化。
4. 当调用 `format` 方法时，C++ 代码会使用这个 `icu::SimpleDateFormat` 对象来格式化 `new Date(2024, 0, 25)` (对应 2024 年 1 月 25 日)。

**假设输出 (JavaScript 端):**

调用 `formatter.format(new Date(2024, 0, 25))` 将会返回字符串 "Thu, Jan 25, 2024"。

**如果涉及用户常见的编程错误，请举例说明:**

1. **错误的 locale 代码:** 用户可能提供了无效的 locale 代码，例如 `'en-AAAA'`。这将导致 `Intl.DateTimeFormat` 初始化失败或使用默认的 locale。

   ```javascript
   try {
     const formatter = new Intl.DateTimeFormat('en-AAAA', { year: 'numeric' });
     formatter.format(new Date());
   } catch (error) {
     console.error(error); // 可能抛出 RangeError: Invalid language tag: en-AAAA
   }
   ```

2. **选项值错误:**  用户可能提供了无效的选项值。

   ```javascript
   try {
     const formatter = new Intl.DateTimeFormat('en-US', { month: 'incorrect' });
     formatter.format(new Date());
   } catch (error) {
     console.error(error); // 可能抛出 RangeError: Invalid value for option "month"
   }
   ```

3. **期望 `formatToParts` 返回所有可能的类型:** 用户可能期望 `formatToParts` 返回所有可能的日期/时间部件类型，即使这些类型在选项中没有指定。实际上，它只会返回选项中指定的部件。

   ```javascript
   const formatter = new Intl.DateTimeFormat('en-US', { year: 'numeric' });
   const parts = formatter.formatToParts(new Date());
   console.log(parts); // 只会包含 year 的信息，例如: [ { type: 'year', value: '2023' } ]
   ```

4. **在 `formatRange` 中传递顺序错误的日期:** 用户可能会在 `formatRange` 中将结束日期放在开始日期之前。虽然 ICU 能够处理这种情况并自动调整顺序，但这可能不是用户的本意。

   ```javascript
   const startDate = new Date(2023, 10, 20);
   const endDate = new Date(2023, 10, 15);
   const formatter = new Intl.DateTimeFormat('zh-CN', { day: 'numeric', month: 'numeric', year: 'numeric' });
   const formattedRange = formatter.formatRange(endDate, startDate);
   console.log(formattedRange); // 输出 "2023/11/15 - 2023/11/20"，顺序会被调整
   ```

**这是第 4 部分，共 4 部分，请归纳一下它的功能:**

总而言之，`v8/src/objects/js-date-time-format.cc` 文件的核心功能是 **为 JavaScript 的 `Intl.DateTimeFormat` API 提供高效且符合国际化标准的日期和时间格式化支持**。它负责处理用户提供的 locale 和选项，利用 ICU 库执行实际的格式化操作，并提供将格式化结果分解为部件的能力。该代码是 V8 引擎实现 JavaScript 国际化功能的重要组成部分。
```
Prompt: 
```
这是目录为v8/src/objects/js-date-time-format.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-date-time-format.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
= RequiredOption::kAny) {
      // 1. For each property name prop of << *"weekday"*, *"year"*, *"month"*,
      // *"day"* >>, do
      //    1. Let value be formatOptions.[[<prop>]].
      //    1. If value is not *undefined*, let needDefaults be *false*.

      needDefaults &= !Weekday::decode(explicit_format_components);
      needDefaults &= !Year::decode(explicit_format_components);
      needDefaults &= !Month::decode(explicit_format_components);
      needDefaults &= !Day::decode(explicit_format_components);
    }
    // c. If required is ~time~ or ~any~, then
    if (required == RequiredOption::kTime || required == RequiredOption::kAny) {
      // 1. For each property name prop of &laquo; *"dayPeriod"*, *"hour"*,
      // *"minute"*, *"second"*, *"fractionalSecondDigits"* &raquo;, do
      //    1. Let value be formatOptions.[[&lt;_prop_&gt;]].
      //    1. If value is not *undefined*, let _needDefaults_ be *false*.
      needDefaults &= !DayPeriod::decode(explicit_format_components);
      needDefaults &= !Hour::decode(explicit_format_components);
      needDefaults &= !Minute::decode(explicit_format_components);
      needDefaults &= !Second::decode(explicit_format_components);
      needDefaults &=
          !FractionalSecondDigits::decode(explicit_format_components);
    }
    // 1. If needDefaults is *true* and _defaults_ is either ~date~ or ~all~,
    // then
    if (needDefaults && ((DefaultsOption::kDate == defaults) ||
                         (DefaultsOption::kAll == defaults))) {
      // 1. For each property name prop of <<*"year"*, *"month"*, *"day"* >>, do
      // 1. Set formatOptions.[[<<prop>>]] to *"numeric"*.
      skeleton += "yMd";
    }
    // 1. If _needDefaults_ is *true* and defaults is either ~time~ or ~all~,
    // then
    if (needDefaults && ((DefaultsOption::kTime == defaults) ||
                         (DefaultsOption::kAll == defaults))) {
      // 1. For each property name prop of << *"hour"*, *"minute"*, *"second"*
      // >>, do
      // 1. Set _formatOptions_.[[<<prop>>]] to *"numeric"*.
      // See
      // https://unicode.org/reports/tr35/tr35.html#UnicodeHourCycleIdentifier
      switch (hc) {
        case HourCycle::kH12:
          skeleton += "hms";
          break;
        case HourCycle::kH23:
        case HourCycle::kUndefined:
          skeleton += "Hms";
          break;
        case HourCycle::kH11:
          skeleton += "Kms";
          break;
        case HourCycle::kH24:
          skeleton += "kms";
          break;
      }
    }
    // e. If dateTimeFormat.[[Hour]] is not undefined, then
    if (has_hour_option) {
      // v. Set dateTimeFormat.[[HourCycle]] to hc.
      dateTimeFormatHourCycle = hc;
    } else {
      // f. Else,
      // Set dateTimeFormat.[[HourCycle]] to undefined.
      dateTimeFormatHourCycle = HourCycle::kUndefined;
    }
    icu::UnicodeString skeleton_ustr(skeleton.c_str());
    icu_date_format = CreateICUDateFormatFromCache(
        icu_locale, skeleton_ustr, generator.get(), dateTimeFormatHourCycle);
    if (icu_date_format.get() == nullptr) {
      // Remove extensions and try again.
      icu_locale = icu::Locale(icu_locale.getBaseName());
      icu_date_format = CreateICUDateFormatFromCache(
          icu_locale, skeleton_ustr, generator.get(), dateTimeFormatHourCycle);
      if (icu_date_format.get() == nullptr) {
        THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kIcuError));
      }
    }
  }

  // The creation of Calendar depends on timeZone so we have to put 13 after 17.
  // Also icu_date_format is not created until here.
  // 13. Set dateTimeFormat.[[Calendar]] to r.[[ca]].
  icu_date_format->adoptCalendar(calendar.release());

  // 12.1.1 InitializeDateTimeFormat ( dateTimeFormat, locales, options )
  //
  // Steps 8-9 set opt.[[hc]] to value *other than undefined*
  // if "hour12" is set or "hourCycle" is set in the option.
  //
  // 9.2.6 ResolveLocale (... )
  // Step 8.h / 8.i and 8.k
  //
  // An hour12 option always overrides an hourCycle option.
  // Additionally hour12 and hourCycle both clear out any existing Unicode
  // extension key in the input locale.
  //
  // See details in https://github.com/tc39/test262/pull/2035
  if (maybe_get_hour12.FromJust() ||
      maybe_hour_cycle.FromJust() != HourCycle::kUndefined) {
    auto hc_extension_it = r.extensions.find("hc");
    if (hc_extension_it != r.extensions.end()) {
      if (dateTimeFormatHourCycle !=
          ToHourCycle(hc_extension_it->second.c_str())) {
        // Remove -hc- if it does not agree with what we used.
        status = U_ZERO_ERROR;
        resolved_locale.setUnicodeKeywordValue("hc", nullptr, status);
        DCHECK(U_SUCCESS(status));
      }
    }
  }

  Maybe<std::string> maybe_locale_str = Intl::ToLanguageTag(resolved_locale);
  MAYBE_RETURN(maybe_locale_str, MaybeHandle<JSDateTimeFormat>());
  DirectHandle<String> locale_str =
      isolate->factory()->NewStringFromAsciiChecked(
          maybe_locale_str.FromJust().c_str());

  DirectHandle<Managed<icu::Locale>> managed_locale =
      Managed<icu::Locale>::From(
          isolate, 0, std::shared_ptr<icu::Locale>{icu_locale.clone()});

  DirectHandle<Managed<icu::SimpleDateFormat>> managed_format =
      Managed<icu::SimpleDateFormat>::From(isolate, 0,
                                           std::move(icu_date_format));

  DirectHandle<Managed<icu::DateIntervalFormat>> managed_interval_format =
      Managed<icu::DateIntervalFormat>::From(isolate, 0, nullptr);

  // Now all properties are ready, so we can allocate the result object.
  Handle<JSDateTimeFormat> date_time_format = Cast<JSDateTimeFormat>(
      isolate->factory()->NewFastOrSlowJSObjectFromMap(map));
  DisallowGarbageCollection no_gc;
  date_time_format->set_flags(0);
  if (date_style != DateTimeStyle::kUndefined) {
    date_time_format->set_date_style(date_style);
  }
  if (time_style != DateTimeStyle::kUndefined) {
    date_time_format->set_time_style(time_style);
  }
  date_time_format->set_hour_cycle(dateTimeFormatHourCycle);
  date_time_format->set_locale(*locale_str);
  date_time_format->set_icu_locale(*managed_locale);
  date_time_format->set_icu_simple_date_format(*managed_format);
  date_time_format->set_icu_date_interval_format(*managed_interval_format);
  return date_time_format;
}

namespace {

// The list comes from third_party/icu/source/i18n/unicode/udat.h.
// They're mapped to DateTimeFormat components listed at
// https://tc39.github.io/ecma402/#sec-datetimeformat-abstracts .
Handle<String> IcuDateFieldIdToDateType(int32_t field_id, Isolate* isolate) {
  switch (field_id) {
    case -1:
      return isolate->factory()->literal_string();
    case UDAT_YEAR_FIELD:
    case UDAT_EXTENDED_YEAR_FIELD:
      return isolate->factory()->year_string();
    case UDAT_YEAR_NAME_FIELD:
      return isolate->factory()->yearName_string();
    case UDAT_MONTH_FIELD:
    case UDAT_STANDALONE_MONTH_FIELD:
      return isolate->factory()->month_string();
    case UDAT_DATE_FIELD:
      return isolate->factory()->day_string();
    case UDAT_HOUR_OF_DAY1_FIELD:
    case UDAT_HOUR_OF_DAY0_FIELD:
    case UDAT_HOUR1_FIELD:
    case UDAT_HOUR0_FIELD:
      return isolate->factory()->hour_string();
    case UDAT_MINUTE_FIELD:
      return isolate->factory()->minute_string();
    case UDAT_SECOND_FIELD:
      return isolate->factory()->second_string();
    case UDAT_DAY_OF_WEEK_FIELD:
    case UDAT_DOW_LOCAL_FIELD:
    case UDAT_STANDALONE_DAY_FIELD:
      return isolate->factory()->weekday_string();
    case UDAT_AM_PM_FIELD:
    case UDAT_AM_PM_MIDNIGHT_NOON_FIELD:
    case UDAT_FLEXIBLE_DAY_PERIOD_FIELD:
      return isolate->factory()->dayPeriod_string();
    case UDAT_TIMEZONE_FIELD:
    case UDAT_TIMEZONE_RFC_FIELD:
    case UDAT_TIMEZONE_GENERIC_FIELD:
    case UDAT_TIMEZONE_SPECIAL_FIELD:
    case UDAT_TIMEZONE_LOCALIZED_GMT_OFFSET_FIELD:
    case UDAT_TIMEZONE_ISO_FIELD:
    case UDAT_TIMEZONE_ISO_LOCAL_FIELD:
      return isolate->factory()->timeZoneName_string();
    case UDAT_ERA_FIELD:
      return isolate->factory()->era_string();
    case UDAT_FRACTIONAL_SECOND_FIELD:
      return isolate->factory()->fractionalSecond_string();
    case UDAT_RELATED_YEAR_FIELD:
      return isolate->factory()->relatedYear_string();

    case UDAT_QUARTER_FIELD:
    case UDAT_STANDALONE_QUARTER_FIELD:
    default:
      // Other UDAT_*_FIELD's cannot show up because there is no way to specify
      // them via options of Intl.DateTimeFormat.
      UNREACHABLE();
  }
}

MaybeHandle<JSArray> FieldPositionIteratorToArray(
    Isolate* isolate, const icu::UnicodeString& formatted,
    icu::FieldPositionIterator fp_iter, bool output_source);

MaybeHandle<JSArray> FormatMillisecondsByKindToArray(
    Isolate* isolate, const icu::SimpleDateFormat& date_format,
    PatternKind kind, double x, bool output_source) {
  icu::FieldPositionIterator fp_iter;
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString formatted =
      CallICUFormat(date_format, kind, x, &fp_iter, status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  return FieldPositionIteratorToArray(isolate, formatted, fp_iter,
                                      output_source);
}
MaybeHandle<JSArray> FormatMillisecondsByKindToArrayOutputSource(
    Isolate* isolate, const icu::SimpleDateFormat& date_format,
    PatternKind kind, double x) {
  return FormatMillisecondsByKindToArray(isolate, date_format, kind, x, true);
}

MaybeHandle<JSArray> FormatToPartsWithTemporalSupport(
    Isolate* isolate, DirectHandle<JSDateTimeFormat> date_time_format,
    Handle<Object> x, bool output_source, const char* method_name) {
  icu::SimpleDateFormat* format =
      date_time_format->icu_simple_date_format()->raw();
  DCHECK_NOT_NULL(format);

  // 1. Let x be ? HandleDateTimeValue(dateTimeFormat, x).
  DateTimeValueRecord x_record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, x_record,
      HandleDateTimeValue(isolate, *format, GetCalendar(isolate, *format), x,
                          method_name),
      Handle<JSArray>());

  return FormatMillisecondsByKindToArray(isolate, *format, x_record.kind,
                                         x_record.epoch_milliseconds,
                                         output_source);
}

MaybeHandle<JSArray> FormatMillisecondsToArray(
    Isolate* isolate, const icu::SimpleDateFormat& format, double value,
    bool output_source) {
  icu::UnicodeString formatted;
  icu::FieldPositionIterator fp_iter;
  UErrorCode status = U_ZERO_ERROR;
  format.format(value, formatted, &fp_iter, status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  return FieldPositionIteratorToArray(isolate, formatted, fp_iter,
                                      output_source);
}
MaybeHandle<JSArray> FormatMillisecondsToArrayOutputSource(
    Isolate* isolate, const icu::SimpleDateFormat& format, double value) {
  return FormatMillisecondsToArray(isolate, format, value, true);
}
}  // namespace

MaybeHandle<JSArray> JSDateTimeFormat::FormatToParts(
    Isolate* isolate, DirectHandle<JSDateTimeFormat> date_time_format,
    Handle<Object> x, bool output_source, const char* method_name) {
  Factory* factory = isolate->factory();
  if (v8_flags.harmony_temporal) {
    return FormatToPartsWithTemporalSupport(isolate, date_time_format, x,
                                            output_source, method_name);
  }

  if (IsUndefined(*x, isolate)) {
    x = factory->NewNumberFromInt64(JSDate::CurrentTimeValue(isolate));
  } else {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, x, Object::ToNumber(isolate, x));
  }

  double date_value = Object::NumberValue(*x);
  if (!DateCache::TryTimeClip(&date_value)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidTimeValue));
  }
  return FormatMillisecondsToArray(
      isolate, *(date_time_format->icu_simple_date_format()->raw()), date_value,
      output_source);
}

namespace {
MaybeHandle<JSArray> FieldPositionIteratorToArray(
    Isolate* isolate, const icu::UnicodeString& formatted,
    icu::FieldPositionIterator fp_iter, bool output_source) {
  Factory* factory = isolate->factory();
  icu::FieldPosition fp;
  Handle<JSArray> result = factory->NewJSArray(0);
  int32_t length = formatted.length();
  if (length == 0) return result;

  int index = 0;
  int32_t previous_end_pos = 0;
  Handle<String> substring;
  while (fp_iter.next(fp)) {
    int32_t begin_pos = fp.getBeginIndex();
    int32_t end_pos = fp.getEndIndex();

    if (previous_end_pos < begin_pos) {
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, substring,
          Intl::ToString(isolate, formatted, previous_end_pos, begin_pos));
      if (output_source) {
        Intl::AddElement(isolate, result, index,
                         IcuDateFieldIdToDateType(-1, isolate), substring,
                         isolate->factory()->source_string(),
                         isolate->factory()->shared_string());
      } else {
        Intl::AddElement(isolate, result, index,
                         IcuDateFieldIdToDateType(-1, isolate), substring);
      }
      ++index;
    }
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, substring,
        Intl::ToString(isolate, formatted, begin_pos, end_pos));
    if (output_source) {
      Intl::AddElement(isolate, result, index,
                       IcuDateFieldIdToDateType(fp.getField(), isolate),
                       substring, isolate->factory()->source_string(),
                       isolate->factory()->shared_string());
    } else {
      Intl::AddElement(isolate, result, index,
                       IcuDateFieldIdToDateType(fp.getField(), isolate),
                       substring);
    }
    previous_end_pos = end_pos;
    ++index;
  }
  if (previous_end_pos < length) {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, substring,
        Intl::ToString(isolate, formatted, previous_end_pos, length));
    if (output_source) {
      Intl::AddElement(isolate, result, index,
                       IcuDateFieldIdToDateType(-1, isolate), substring,
                       isolate->factory()->source_string(),
                       isolate->factory()->shared_string());
    } else {
      Intl::AddElement(isolate, result, index,
                       IcuDateFieldIdToDateType(-1, isolate), substring);
    }
  }
  JSObject::ValidateElements(*result);
  return result;
}

}  // namespace

const std::set<std::string>& JSDateTimeFormat::GetAvailableLocales() {
  return Intl::GetAvailableLocalesForDateFormat();
}

Handle<String> JSDateTimeFormat::HourCycleAsString() const {
  switch (hour_cycle()) {
    case HourCycle::kUndefined:
      return GetReadOnlyRoots().undefined_string_handle();
    case HourCycle::kH11:
      return GetReadOnlyRoots().h11_string_handle();
    case HourCycle::kH12:
      return GetReadOnlyRoots().h12_string_handle();
    case HourCycle::kH23:
      return GetReadOnlyRoots().h23_string_handle();
    case HourCycle::kH24:
      return GetReadOnlyRoots().h24_string_handle();
    default:
      UNREACHABLE();
  }
}

namespace {

Maybe<bool> AddPartForFormatRange(
    Isolate* isolate, Handle<JSArray> array, const icu::UnicodeString& string,
    int32_t index, int32_t field, int32_t start, int32_t end,
    const Intl::FormatRangeSourceTracker& tracker) {
  Handle<String> substring;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, substring,
                                   Intl::ToString(isolate, string, start, end),
                                   Nothing<bool>());
  Intl::AddElement(isolate, array, index,
                   IcuDateFieldIdToDateType(field, isolate), substring,
                   isolate->factory()->source_string(),
                   Intl::SourceString(isolate, tracker.GetSource(start, end)));
  return Just(true);
}

// If this function return a value, it could be a throw of TypeError, or normal
// formatted string. If it return a nullopt the caller should call the fallback
// function.
std::optional<MaybeHandle<String>> FormattedToString(
    Isolate* isolate, const icu::FormattedValue& formatted) {
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString result = formatted.toString(status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  icu::ConstrainedFieldPosition cfpos;
  while (formatted.nextPosition(cfpos, status)) {
    if (cfpos.getCategory() == UFIELD_CATEGORY_DATE_INTERVAL_SPAN) {
      return Intl::ToString(isolate, result);
    }
  }
  return std::nullopt;
}

// A helper function to convert the FormattedDateInterval to a
// MaybeHandle<JSArray> for the implementation of formatRangeToParts.
// If this function return a value, it could be a throw of TypeError, or normal
// formatted parts in JSArray. If it return a nullopt the caller should call
// the fallback function.
std::optional<MaybeHandle<JSArray>> FormattedDateIntervalToJSArray(
    Isolate* isolate, const icu::FormattedValue& formatted) {
  UErrorCode status = U_ZERO_ERROR;
  icu::UnicodeString result = formatted.toString(status);

  Factory* factory = isolate->factory();
  Handle<JSArray> array = factory->NewJSArray(0);
  icu::ConstrainedFieldPosition cfpos;
  int index = 0;
  int32_t previous_end_pos = 0;
  Intl::FormatRangeSourceTracker tracker;
  bool output_range = false;
  while (formatted.nextPosition(cfpos, status)) {
    int32_t category = cfpos.getCategory();
    int32_t field = cfpos.getField();
    int32_t start = cfpos.getStart();
    int32_t limit = cfpos.getLimit();

    if (category == UFIELD_CATEGORY_DATE_INTERVAL_SPAN) {
      DCHECK_LE(field, 2);
      output_range = true;
      tracker.Add(field, start, limit);
    } else {
      DCHECK(category == UFIELD_CATEGORY_DATE);
      if (start > previous_end_pos) {
        // Add "literal" from the previous end position to the start if
        // necessary.
        Maybe<bool> maybe_added =
            AddPartForFormatRange(isolate, array, result, index, -1,
                                  previous_end_pos, start, tracker);
        MAYBE_RETURN(maybe_added, Handle<JSArray>());
        previous_end_pos = start;
        index++;
      }
      Maybe<bool> maybe_added = AddPartForFormatRange(
          isolate, array, result, index, field, start, limit, tracker);
      MAYBE_RETURN(maybe_added, Handle<JSArray>());
      previous_end_pos = limit;
      ++index;
    }
  }
  int32_t end = result.length();
  // Add "literal" in the end if necessary.
  if (end > previous_end_pos) {
    Maybe<bool> maybe_added = AddPartForFormatRange(
        isolate, array, result, index, -1, previous_end_pos, end, tracker);
    MAYBE_RETURN(maybe_added, Handle<JSArray>());
  }

  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }

  JSObject::ValidateElements(*array);
  if (output_range) return array;
  return std::nullopt;
}

// The shared code between formatRange and formatRangeToParts
template <typename T, std::optional<MaybeHandle<T>> (*Format)(
                          Isolate*, const icu::FormattedValue&)>
std::optional<MaybeHandle<T>> CallICUFormatRange(
    Isolate* isolate, const icu::DateIntervalFormat* format,
    const icu::Calendar* calendar, double x, double y);
// #sec-partitiondatetimerangepattern
template <typename T, std::optional<MaybeHandle<T>> (*Format)(
                          Isolate*, const icu::FormattedValue&)>
std::optional<MaybeHandle<T>> PartitionDateTimeRangePattern(
    Isolate* isolate, DirectHandle<JSDateTimeFormat> date_time_format, double x,
    double y, const char* method_name) {
  // 1. Let x be TimeClip(x).
  // 2. If x is NaN, throw a RangeError exception.
  if (!DateCache::TryTimeClip(&x)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidTimeValue));
  }
  // 3. Let y be TimeClip(y).
  // 4. If y is NaN, throw a RangeError exception.
  if (!DateCache::TryTimeClip(&y)) {
    THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidTimeValue));
  }

  std::unique_ptr<icu::DateIntervalFormat> format(LazyCreateDateIntervalFormat(
      isolate, date_time_format, PatternKind::kDate));
  if (format.get() == nullptr) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }

  icu::SimpleDateFormat* date_format =
      date_time_format->icu_simple_date_format()->raw();
  const icu::Calendar* calendar = date_format->getCalendar();

  return CallICUFormatRange<T, Format>(isolate, format.get(), calendar, x, y);
}

template <typename T, std::optional<MaybeHandle<T>> (*Format)(
                          Isolate*, const icu::FormattedValue&)>
std::optional<MaybeHandle<T>> CallICUFormatRange(
    Isolate* isolate, const icu::DateIntervalFormat* format,
    const icu::Calendar* calendar, double x, double y) {
  UErrorCode status = U_ZERO_ERROR;

  std::unique_ptr<icu::Calendar> c1(calendar->clone());
  std::unique_ptr<icu::Calendar> c2(calendar->clone());
  c1->setTime(x, status);
  c2->setTime(y, status);
  // We need to format by Calendar because we need the Gregorian change
  // adjustment already in the SimpleDateFormat to set the correct value of date
  // older than Oct 15, 1582.
  icu::FormattedDateInterval formatted =
      format->formatToValue(*c1, *c2, status);
  if (U_FAILURE(status)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }
  return Format(isolate, formatted);
}

template <typename T,
          std::optional<MaybeHandle<T>> (*Format)(Isolate*,
                                                  const icu::FormattedValue&),
          MaybeHandle<T> (*Fallback)(Isolate*, const icu::SimpleDateFormat&,
                                     PatternKind, double)>
MaybeHandle<T> FormatRangeCommonWithTemporalSupport(
    Isolate* isolate, DirectHandle<JSDateTimeFormat> date_time_format,
    Handle<Object> x_obj, Handle<Object> y_obj, const char* method_name) {
  // 5. If either of ! IsTemporalObject(x) or ! IsTemporalObject(y) is true,
  // then
  if (IsTemporalObject(x_obj) || IsTemporalObject(y_obj)) {
    // a. If ! SameTemporalType(x, y) is false, throw a TypeError exception.
    if (!SameTemporalType(x_obj, y_obj)) {
      THROW_NEW_ERROR(
          isolate,
          NewTypeError(MessageTemplate::kInvalidArgumentForTemporal, y_obj));
    }
  }
  // 6. Let x be ? HandleDateTimeValue(dateTimeFormat, x).
  icu::SimpleDateFormat* icu_simple_date_format =
      date_time_format->icu_simple_date_format()->raw();
  Handle<String> date_time_format_calendar =
      GetCalendar(isolate, *icu_simple_date_format);
  DateTimeValueRecord x_record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, x_record,
      HandleDateTimeValue(isolate, *icu_simple_date_format,
                          date_time_format_calendar, x_obj, method_name),
      Handle<T>());

  // 7. Let y be ? HandleDateTimeValue(dateTimeFormat, y).
  DateTimeValueRecord y_record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, y_record,
      HandleDateTimeValue(isolate, *icu_simple_date_format,
                          date_time_format_calendar, y_obj, method_name),
      Handle<T>());

  std::unique_ptr<icu::DateIntervalFormat> format(
      LazyCreateDateIntervalFormat(isolate, date_time_format, x_record.kind));
  if (format.get() == nullptr) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kIcuError));
  }

  const icu::Calendar* calendar =
      date_time_format->icu_simple_date_format()->raw()->getCalendar();

  std::optional<MaybeHandle<T>> result = CallICUFormatRange<T, Format>(
      isolate, format.get(), calendar, x_record.epoch_milliseconds,
      y_record.epoch_milliseconds);
  if (result.has_value()) return *result;
  return Fallback(isolate, *icu_simple_date_format, x_record.kind,
                  x_record.epoch_milliseconds);
}

template <typename T,
          std::optional<MaybeHandle<T>> (*Format)(Isolate*,
                                                  const icu::FormattedValue&),
          MaybeHandle<T> (*Fallback)(Isolate*, const icu::SimpleDateFormat&,
                                     double)>
MaybeHandle<T> FormatRangeCommon(Isolate* isolate,
                                 Handle<JSDateTimeFormat> date_time_format,
                                 Handle<Object> x_obj, Handle<Object> y_obj,
                                 const char* method_name) {
  // 4. Let x be ? ToNumber(startDate).
  ASSIGN_RETURN_ON_EXCEPTION(isolate, x_obj, Object::ToNumber(isolate, x_obj));
  double x = Object::NumberValue(*x_obj);
  // 5. Let y be ? ToNumber(endDate).
  ASSIGN_RETURN_ON_EXCEPTION(isolate, y_obj, Object::ToNumber(isolate, y_obj));
  double y = Object::NumberValue(*y_obj);

  std::optional<MaybeHandle<T>> result =
      PartitionDateTimeRangePattern<T, Format>(isolate, date_time_format, x, y,
                                               method_name);
  if (result.has_value()) return *result;
  return Fallback(isolate, *(date_time_format->icu_simple_date_format()->raw()),
                  x);
}

}  // namespace

MaybeHandle<String> JSDateTimeFormat::FormatRange(
    Isolate* isolate, Handle<JSDateTimeFormat> date_time_format,
    Handle<Object> x, Handle<Object> y, const char* method_name) {
  // Track newer feature formateRange and formatRangeToParts
  isolate->CountUsage(v8::Isolate::UseCounterFeature::kDateTimeFormatRange);
  if (v8_flags.harmony_temporal) {
    // For Temporal enable support
    return FormatRangeCommonWithTemporalSupport<
        String, FormattedToString, FormatMillisecondsByKindToString>(
        isolate, date_time_format, x, y, method_name);
  }
  // Pre Temporal implementation
  return FormatRangeCommon<String, FormattedToString, FormatDateTime>(
      isolate, date_time_format, x, y, method_name);
}

MaybeHandle<JSArray> JSDateTimeFormat::FormatRangeToParts(
    Isolate* isolate, Handle<JSDateTimeFormat> date_time_format,
    Handle<Object> x, Handle<Object> y, const char* method_name) {
  // Track newer feature formateRange and formatRangeToParts
  isolate->CountUsage(v8::Isolate::UseCounterFeature::kDateTimeFormatRange);
  if (v8_flags.harmony_temporal) {
    // For Temporal enable support
    return FormatRangeCommonWithTemporalSupport<
        JSArray, FormattedDateIntervalToJSArray,
        FormatMillisecondsByKindToArrayOutputSource>(isolate, date_time_format,
                                                     x, y, method_name);
  }
  // Pre Temporal implementation
  return FormatRangeCommon<JSArray, FormattedDateIntervalToJSArray,
                           FormatMillisecondsToArrayOutputSource>(
      isolate, date_time_format, x, y, method_name);
}

}  // namespace v8::internal

"""


```