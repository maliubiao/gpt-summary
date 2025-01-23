Response: The user is asking for a summary of the C++ source code file `v8/src/objects/js-temporal-objects.cc`, specifically the third part of it. They also want to know how it relates to JavaScript, with examples if applicable.

Based on the code provided, this part of the file seems to focus on:

1. **String Formatting and Parsing for Temporal API Objects:** It contains functions to format and parse strings representing dates, times, timezones, and durations according to the ISO 8601 standard, which is central to the JavaScript Temporal API. This includes functions like `FormatISOTimeString`, `FormatISOTimeZoneOffsetString`, `ToZeroPaddedDecimalString`, `PadISOYear`, `ParseISODateTime`, `ParseTemporalDateString`, `ParseTemporalTimeString`, `ParseTemporalInstantString`, `ParseTemporalDurationString`, `ParseTemporalTimeZoneString`, and `ParseTimeZoneOffsetString`.

2. **Calendar Handling:** It includes functions for formatting and parsing calendar annotations (`FormatCalendarAnnotation`, `MaybeFormatCalendarAnnotation`), checking calendar equality (`CalendarEquals`, `CalendarEqualsBool`), retrieving calendar fields (`CalendarFields`), and interacting with calendar methods (like `dateAdd`, `dateUntil`) through abstract operations (`CalendarYear`, `CalendarMonth`, `CalendarDay`, etc.). It also has logic to determine if a calendar is a built-in calendar (like "iso8601").

3. **Timezone Offset Handling:** Functions like `BuiltinTimeZoneGetOffsetStringFor` and `GetOffsetNanosecondsFor` are used to retrieve and format timezone offsets.

4. **Duration Handling:** The `CreateDurationRecord` and `ParseTemporalDurationString` functions are crucial for working with duration objects in the Temporal API.

5. **Error Handling:** The code uses `THROW_NEW_ERROR_RETURN_VALUE` and `THROW_NEW_ERROR` extensively, indicating a focus on robust error handling during parsing and validation.

**Relationship to JavaScript:**

This C++ code directly implements the underlying logic for many of the string conversion and parsing operations of the JavaScript Temporal API. The Temporal API in JavaScript allows developers to work with dates, times, and timezones in a more modern and standardized way compared to the built-in `Date` object. The C++ code handles the low-level details of these operations.

**JavaScript Examples:**

Let's illustrate the connection with some JavaScript examples that would internally utilize the C++ functions defined here.

* **Formatting a `Temporal.PlainTime`:**

```javascript
const plainTime = new Temporal.PlainTime(10, 30, 45, 500, 200, 100);
const isoTimeString = plainTime.toString(); // Internally calls a C++ function like FormatISOTimeString
console.log(isoTimeString); // Output: "10:30:45.500200100"
```

* **Parsing a `Temporal.PlainDate` string:**

```javascript
const plainDate = Temporal.PlainDate.from("2023-10-27"); // Internally calls a C++ function like ParseTemporalDateString
console.log(plainDate.year, plainDate.month, plainDate.day); // Output: 2023 10 27
```

* **Formatting a `Temporal.ZonedDateTime` with a timezone offset:**

```javascript
const zonedDateTime = Temporal.ZonedDateTime.from("2023-10-27T12:00:00-08:00[America/Los_Angeles]");
const isoString = zonedDateTime.toString(); // Internally uses functions like FormatISOTimeZoneOffsetString
console.log(isoString); // Output will include the offset, e.g., "2023-10-27T12:00:00-08:00[America/Los_Angeles]"
```

* **Parsing a `Temporal.Duration` string:**

```javascript
const duration = Temporal.Duration.from("P1Y2M3DT4H5M6S"); // Internally calls ParseTemporalDurationString
console.log(duration.years, duration.months, duration.days, duration.hours, duration.minutes, duration.seconds); // Output: 1 2 3 4 5 6
```

* **Using a custom calendar:**

```javascript
const plainDateWithCalendar = Temporal.PlainDate.from("2023-10-27[u-ca=buddhist]");
const calendarId = plainDateWithCalendar.calendar.id; // Accessing the calendar identifier
console.log(calendarId); // Output: "buddhist" (calls underlying C++ logic to handle the calendar)
```

These JavaScript examples demonstrate how the higher-level API relies on the lower-level C++ code in `js-temporal-objects.cc` to handle the intricacies of string formatting, parsing, and calendar/timezone calculations.

这是 `v8/src/objects/js-temporal-objects.cc` 源代码文件的第三部分，主要负责以下功能：

**1. 时间和日期字符串的格式化:**

*   **`FormatISOTimeString`:**  将小时、分钟、秒和纳秒格式化为 ISO 8601 时间字符串，例如 "10:30:45.123"。它处理了纳秒部分是否存在的情况，并根据需要添加小数点和尾部的零。
*   **`FormatISOTimeZoneOffsetString`:** 将以纳秒为单位的时区偏移量格式化为 ISO 8601 偏移字符串，例如 "+08:00" 或 "-05:30"。它确保偏移量被正确地四舍五入，并添加正负号。
*   **`ToZeroPaddedDecimalString`:**  将数字填充零到指定的最小长度，用于确保日期和时间的各个部分始终以两位数字表示（例如，将月份 5 格式化为 "05"）。
*   **`PadISOYear`:**  处理 ISO 年份的格式化，特别是对于超出四位数的年份，会添加 "+" 或 "-" 前缀，并将年份填充到六位。

**2. 日历注解的格式化:**

*   **`FormatCalendarAnnotation`:**  根据 `ShowCalendar` 参数和日历 ID 格式化日历注解字符串，例如 "[u-ca=buddhist]"。如果 `showCalendar` 是 "never" 或 "auto" 且日历 ID 是 "iso8601"，则返回空字符串。
*   **`MaybeFormatCalendarAnnotation`:**  与 `FormatCalendarAnnotation` 类似，但它接受一个日历对象作为输入，并首先将其转换为字符串。

**3. 将 Temporal 对象转换为字符串:**

*   **`TemporalDateToString`:** 将 `Temporal.PlainDate` 对象格式化为 ISO 8601 日期字符串，包括可能的日历注解。
*   **`TemporalMonthDayToString`:** 将 `Temporal.PlainMonthDay` 对象格式化为字符串，处理是否需要包含年份以及日历注解。
*   **`TemporalYearMonthToString`:** 将 `Temporal.PlainYearMonth` 对象格式化为字符串，处理是否需要包含日期以及日历注解。

**4. 获取内置时区的偏移字符串:**

*   **`BuiltinTimeZoneGetOffsetStringFor`:**  用于获取给定时间和 `Temporal.TimeZone` 对象的偏移量，并将其格式化为字符串。

**5. 解析 ISO 8601 日期时间字符串:**

*   **`ParseISODateTime` (两个重载):**  用于解析各种 ISO 8601 日期时间字符串，包括 `TemporalDateTimeString`、`TemporalInstantString` 等。它将字符串分解为年、月、日、时、分、秒、毫秒、微秒、纳秒以及时区信息和日历信息。它还执行一些基本的有效性检查。

**6. 解析特定的 Temporal 字符串:**

*   **`ParseTemporalDateString`:**  专门用于解析 `Temporal.PlainDate` 字符串。
*   **`ParseTemporalTimeString`:**  专门用于解析 `Temporal.PlainTime` 字符串。
*   **`ParseTemporalInstantString`:** 专门用于解析 `Temporal.Instant` 字符串。
*   **`ParseTemporalRelativeToString`:** 用于解析与相对时间相关的字符串。
*   **`ParseTemporalInstant`:** 解析 `Temporal.Instant` 字符串并返回以纳秒为单位的纪元时间。
*   **`ParseTemporalZonedDateTimeString`:** 专门用于解析 `Temporal.ZonedDateTime` 字符串。

**7. 解析 Temporal Duration 字符串:**

*   **`CreateDurationRecord`:**  根据提供的年、月、周、日、时、分、秒、毫秒、微秒和纳秒创建 `DurationRecord`。它首先验证 Duration 的有效性。
*   **`ParseTemporalDurationString`:**  用于解析 `Temporal.Duration` 字符串，将其分解为各个组成部分（年、月、日、时、分、秒等），并创建 `DurationRecord`。

**8. 解析 Temporal 时区字符串:**

*   **`ParseTemporalTimeZoneString`:**  用于解析时区字符串，可以是时区名称（例如 "America/Los_Angeles"）或 UTC 偏移量（例如 "+08:00"）。

**9. 解析时区偏移字符串:**

*   **`ParseTimeZoneOffsetString`:**  专门用于解析 ISO 8601 时区偏移量字符串，并将其转换为以纳秒为单位的数值。
*   **`IsValidTimeZoneNumericUTCOffsetString`:** 检查给定的字符串是否是有效的 ISO 8601 数字 UTC 偏移字符串。

**10. 解析 Temporal 日历字符串:**

*   **`ParseTemporalCalendarString`:** 用于解析日历字符串。如果字符串可以解析为日期时间，则提取日历信息；否则，将其视为日历名称。

**11. 日历对象的比较:**

*   **`CalendarEqualsBool` 和 `CalendarEquals`:**  用于比较两个日历对象是否相等。

**12. 获取日历字段:**

*   **`CalendarFields`:**  调用日历对象的 "fields" 方法来获取其支持的字段列表。

**13. 日历的日期加法和减法:**

*   **`CalendarDateAdd` (多个重载):**  调用日历对象的 "dateAdd" 方法来向日期添加一个 duration。
*   **`CalendarDateUntil` (多个重载):** 调用日历对象的 "dateUntil" 方法来计算两个日期之间的 duration。

**14. 默认合并字段:**

*   **`DefaultMergeFields`:**  用于合并两个包含日期或时间字段的对象，处理 "month" 和 "monthCode" 的特殊情况。

**15. 获取时区偏移量（以纳秒为单位）:**

*   **`GetOffsetNanosecondsFor`:**  调用时区对象的 "getOffsetNanosecondsFor" 方法来获取给定时间点的偏移量。

**16. 转换为正整数:**

*   **`ToPositiveInteger`:** 将一个值转换为正整数，如果不是正整数则抛出 RangeError。

**17. 调用日历方法的辅助函数:**

*   **`InvokeCalendarMethod`:**  一个通用的辅助函数，用于调用日历对象上的指定方法。
*   **`CalendarYear`、`CalendarMonth`、`CalendarDay` 等一系列 `CALENDAR_ABSTRACT_OPERATION` 宏定义的函数:**  用于方便地调用日历对象上的 year、month、day 等方法，并对结果进行类型转换和错误处理。

**18. 获取 ISO 8601 日历对象:**

*   **`GetISO8601Calendar`:**  返回一个表示 ISO 8601 日历的 `JSTemporalCalendar` 对象。

**19. 判断是否为 UTC 时区:**

*   **`IsUTC`:**  判断给定的字符串是否表示 UTC 时区（大小写不敏感）。

**20. 处理内置日历（带有或不带有国际化支持）：**

*   **`IsBuiltinCalendar`:**  判断给定的日历 ID 是否是内置日历（例如 "iso8601"）。在启用了国际化支持的情况下，它会查询 ICU 库以获取可用的日历。
*   **`CalendarIdentifier`:**  根据索引返回内置日历的 ID。
*   **`CalendarIndex`:**  根据日历 ID 返回其索引。

**21. 处理时区名称（带有国际化支持）：**

*   **`IsValidTimeZoneName`:**  判断给定的字符串是否是有效的时区名称。
*   **`CanonicalizeTimeZoneName`:**  规范化给定的时区名称。

**与 JavaScript 的关系及示例:**

这个 C++ 文件是 V8 引擎中实现 JavaScript Temporal API 的核心部分。Temporal API 旨在提供一种更现代、更易于使用的方式来处理日期和时间，取代了 JavaScript 内置的 `Date` 对象的一些不足之处。

文件中定义的 C++ 函数直接对应于 JavaScript Temporal API 中许多核心功能的底层实现。当你在 JavaScript 中使用 Temporal API 时，V8 引擎会在幕后调用这些 C++ 函数来完成诸如日期时间字符串的解析、格式化、日历计算和时区处理等操作。

**JavaScript 示例:**

```javascript
// 使用 Temporal.PlainDate.from 解析日期字符串
const plainDate = Temporal.PlainDate.from("2023-10-27"); // 内部调用 ParseTemporalDateString

// 格式化 Temporal.PlainTime 对象为字符串
const plainTime = new Temporal.PlainTime(10, 30, 0);
const timeString = plainTime.toString(); // 内部调用 FormatISOTimeString

// 创建带有时区偏移量的 Temporal.Instant
const instant = Temporal.Instant.from("2023-10-27T10:30:00Z"); // 内部调用 ParseTemporalInstantString

// 使用不同的日历
const buddhistDate = Temporal.PlainDate.from("2566-10-27[u-ca=buddhist]"); // 内部调用 ParseTemporalDateString 并处理日历信息

// 计算两个日期之间的 Duration
const date1 = new Temporal.PlainDate(2023, 10, 27);
const date2 = new Temporal.PlainDate(2023, 10, 30);
const duration = date1.until(date2); // 内部调用 CalendarDateUntil

// 获取时区的偏移量
const timezone = Temporal.TimeZone.from("America/Los_Angeles");
const now = Temporal.Now.instant();
const offsetNanoseconds = timezone.getOffsetNanosecondsFor(now); // 内部调用 GetOffsetNanosecondsFor
```

总而言之，这个 C++ 文件提供了 JavaScript Temporal API 中日期、时间、时区和日历操作的核心底层实现。它负责字符串的解析和格式化，以及与日历和时区相关的计算和处理。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共13部分，请归纳一下它的功能
```

### 源代码
```
dDecimalString(&builder, minutes, 2);

  // 10. Let s be ToZeroPaddedDecimalString(seconds, 2).
  // 11. If nanoseconds ≠ 0, then
  if (nanoseconds != 0) {
    // a. Let fraction be ToZeroPaddedDecimalString(nanoseconds, 9).
    // b. Set fraction to the longest possible substring of fraction starting at
    // position 0 and not ending with the code unit 0x0030 (DIGIT ZERO). c. Let
    // post be the string-concatenation of the code unit 0x003A (COLON), s, the
    // code unit 0x002E (FULL STOP), and fraction.
    builder.AppendCharacter(':');
    ToZeroPaddedDecimalString(&builder, seconds, 2);
    builder.AppendCharacter('.');
    int64_t divisor = 100000000;
    do {
      builder.AppendInt(static_cast<int>(nanoseconds / divisor));
      nanoseconds %= divisor;
      divisor /= 10;
    } while (nanoseconds > 0);
    // 11. Else if seconds ≠ 0, then
  } else if (seconds != 0) {
    // a. Let post be the string-concatenation of the code unit 0x003A (COLON)
    // and s.
    builder.AppendCharacter(':');
    ToZeroPaddedDecimalString(&builder, seconds, 2);
  }
  // 12. Return the string-concatenation of sign, h, the code unit 0x003A
  // (COLON), m, and post.
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

double RoundNumberToIncrement(Isolate* isolate, double x, double increment,
                              RoundingMode rounding_mode);

// #sec-temporal-formatisotimezoneoffsetstring
Handle<String> FormatISOTimeZoneOffsetString(Isolate* isolate,
                                             int64_t offset_nanoseconds) {
  IncrementalStringBuilder builder(isolate);
  // 1. Assert: offsetNanoseconds is an integer.
  // 2. Set offsetNanoseconds to ! RoundNumberToIncrement(offsetNanoseconds, 60
  // × 10^9, "halfExpand").
  offset_nanoseconds = RoundNumberToIncrement(
      isolate, offset_nanoseconds, 60000000000, RoundingMode::kHalfExpand);
  // 3. If offsetNanoseconds ≥ 0, let sign be "+"; otherwise, let sign be "-".
  builder.AppendCharacter((offset_nanoseconds >= 0) ? '+' : '-');
  // 4. Set offsetNanoseconds to abs(offsetNanoseconds).
  offset_nanoseconds = std::abs(offset_nanoseconds);
  // 5. Let minutes be offsetNanoseconds / (60 × 10^9) modulo 60.
  int32_t minutes = (offset_nanoseconds / 60000000000) % 60;
  // 6. Let hours be floor(offsetNanoseconds / (3600 × 10^9)).
  int32_t hours = offset_nanoseconds / 3600000000000;
  // 7. Let h be ToZeroPaddedDecimalString(hours, 2).
  ToZeroPaddedDecimalString(&builder, hours, 2);

  // 8. Let m be ToZeroPaddedDecimalString(minutes, 2).
  builder.AppendCharacter(':');
  ToZeroPaddedDecimalString(&builder, minutes, 2);
  // 9. Return the string-concatenation of sign, h, the code unit 0x003A
  // (COLON), and m.
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

int32_t DecimalLength(int32_t n) {
  int32_t i = 1;
  while (n >= 10) {
    n /= 10;
    i++;
  }
  return i;
}

// #sec-tozeropaddeddecimalstring
void ToZeroPaddedDecimalString(IncrementalStringBuilder* builder, int32_t n,
                               int32_t min_length) {
  for (int32_t pad = min_length - DecimalLength(n); pad > 0; pad--) {
    builder->AppendCharacter('0');
  }
  builder->AppendInt(n);
}

// #sec-temporal-padisoyear
void PadISOYear(IncrementalStringBuilder* builder, int32_t y) {
  // 1. Assert: y is an integer.
  // 2. If y ≥ 0 and y ≤ 9999, then
  if (y >= 0 && y <= 9999) {
    // a. Return ToZeroPaddedDecimalString(y, 4).
    ToZeroPaddedDecimalString(builder, y, 4);
    return;
  }
  // 3. If y > 0, let yearSign be "+"; otherwise, let yearSign be "-".
  if (y > 0) {
    builder->AppendCharacter('+');
  } else {
    builder->AppendCharacter('-');
  }
  // 4. Let year be ToZeroPaddedDecimalString(abs(y), 6).
  ToZeroPaddedDecimalString(builder, std::abs(y), 6);
  // 5. Return the string-concatenation of yearSign and year.
}

// #sec-temporal-formatcalendarannotation
Handle<String> FormatCalendarAnnotation(Isolate* isolate, Handle<String> id,
                                        ShowCalendar show_calendar) {
  // 1.Assert: showCalendar is "auto", "always", or "never".
  // 2. If showCalendar is "never", return the empty String.
  if (show_calendar == ShowCalendar::kNever) {
    return isolate->factory()->empty_string();
  }
  // 3. If showCalendar is "auto" and id is "iso8601", return the empty String.
  if (show_calendar == ShowCalendar::kAuto &&
      String::Equals(isolate, id, isolate->factory()->iso8601_string())) {
    return isolate->factory()->empty_string();
  }
  // 4. Return the string-concatenation of "[u-ca=", id, and "]".
  IncrementalStringBuilder builder(isolate);
  builder.AppendCStringLiteral("[u-ca=");
  builder.AppendString(id);
  builder.AppendCharacter(']');
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

// #sec-temporal-maybeformatcalendarannotation
MaybeHandle<String> MaybeFormatCalendarAnnotation(
    Isolate* isolate, Handle<JSReceiver> calendar_object,
    ShowCalendar show_calendar) {
  // 1. If showCalendar is "never", return the empty String.
  if (show_calendar == ShowCalendar::kNever) {
    return isolate->factory()->empty_string();
  }
  // 2. Let calendarID be ? ToString(calendarObject).
  Handle<String> calendar_id;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, calendar_id,
                             Object::ToString(isolate, calendar_object));
  // 3. Return FormatCalendarAnnotation(calendarID, showCalendar).
  return FormatCalendarAnnotation(isolate, calendar_id, show_calendar);
}

// #sec-temporal-temporaldatetostring
MaybeHandle<String> TemporalDateToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainDate> temporal_date,
    ShowCalendar show_calendar) {
  IncrementalStringBuilder builder(isolate);
  // 1. Assert: Type(temporalDate) is Object.
  // 2. Assert: temporalDate has an [[InitializedTemporalDate]] internal slot.
  // 3. Let year be ! PadISOYear(temporalDate.[[ISOYear]]).
  PadISOYear(&builder, temporal_date->iso_year());
  // 4. Let month be ToZeroPaddedDecimalString(temporalDate.[[ISOMonth]], 2).
  builder.AppendCharacter('-');
  ToZeroPaddedDecimalString(&builder, temporal_date->iso_month(), 2);
  // 5. Let day be ToZeroPaddedDecimalString(temporalDate.[[ISODay]], 2).
  builder.AppendCharacter('-');
  ToZeroPaddedDecimalString(&builder, temporal_date->iso_day(), 2);
  // 6. Let calendar be ?
  // MaybeFormatCalendarAnnotation(temporalDate.[[Calendar]], showCalendar).
  Handle<String> calendar;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar,
      MaybeFormatCalendarAnnotation(
          isolate, handle(temporal_date->calendar(), isolate), show_calendar));

  // 7. Return the string-concatenation of year, the code unit 0x002D
  // (HYPHEN-MINUS), month, the code unit 0x002D (HYPHEN-MINUS), day, and
  // calendar.
  builder.AppendString(calendar);
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

// #sec-temporal-temporalmonthdaytostring
MaybeHandle<String> TemporalMonthDayToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainMonthDay> month_day,
    ShowCalendar show_calendar) {
  // 1. Assert: Type(monthDay) is Object.
  // 2. Assert: monthDay has an [[InitializedTemporalMonthDay]] internal slot.
  IncrementalStringBuilder builder(isolate);
  // 6. Let calendarID be ? ToString(monthDay.[[Calendar]]).
  Handle<String> calendar_id;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar_id,
      Object::ToString(isolate, handle(month_day->calendar(), isolate)));
  // 7. If showCalendar is "always" or if calendarID is not "iso8601", then
  if (show_calendar == ShowCalendar::kAlways ||
      !String::Equals(isolate, calendar_id,
                      isolate->factory()->iso8601_string())) {
    // a. Let year be ! PadISOYear(monthDay.[[ISOYear]]).
    PadISOYear(&builder, month_day->iso_year());
    // b. Set result to the string-concatenation of year, the code unit
    // 0x002D (HYPHEN-MINUS), and result.
    builder.AppendCharacter('-');
  }
  // 3. Let month be ToZeroPaddedDecimalString(monthDay.[[ISOMonth]], 2).
  ToZeroPaddedDecimalString(&builder, month_day->iso_month(), 2);
  // 5. Let result be the string-concatenation of month, the code unit 0x002D
  // (HYPHEN-MINUS), and day.
  builder.AppendCharacter('-');
  // 4. Let day be ToZeroPaddedDecimalString(monthDay.[[ISODay]], 2).
  ToZeroPaddedDecimalString(&builder, month_day->iso_day(), 2);
  // 8. Let calendarString be ! FormatCalendarAnnotation(calendarID,
  // showCalendar).
  DirectHandle<String> calendar_string =
      FormatCalendarAnnotation(isolate, calendar_id, show_calendar);
  // 9. Set result to the string-concatenation of result and calendarString.
  builder.AppendString(calendar_string);
  // 10. Return result.
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

// #sec-temporal-temporalyearmonthtostring
MaybeHandle<String> TemporalYearMonthToString(
    Isolate* isolate, DirectHandle<JSTemporalPlainYearMonth> year_month,
    ShowCalendar show_calendar) {
  // 1. Assert: Type(yearMonth) is Object.
  // 2. Assert: yearMonth has an [[InitializedTemporalYearMonth]] internal slot.
  IncrementalStringBuilder builder(isolate);
  // 3. Let year be ! PadISOYear(yearMonth.[[ISOYear]]).
  PadISOYear(&builder, year_month->iso_year());
  // 4. Let month be ToZeroPaddedDecimalString(yearMonth.[[ISOMonth]], 2).
  // 5. Let result be the string-concatenation of year, the code unit 0x002D
  // (HYPHEN-MINUS), and month.
  builder.AppendCharacter('-');
  ToZeroPaddedDecimalString(&builder, year_month->iso_month(), 2);
  // 6. Let calendarID be ? ToString(yearMonth.[[Calendar]]).
  Handle<String> calendar_id;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, calendar_id,
      Object::ToString(isolate, handle(year_month->calendar(), isolate)));
  // 7. If showCalendar is "always" or if *_calendarID_ is not *"iso8601", then
  if (show_calendar == ShowCalendar::kAlways ||
      !String::Equals(isolate, calendar_id,
                      isolate->factory()->iso8601_string())) {
    // a. Let day be ToZeroPaddedDecimalString(yearMonth.[[ISODay]], 2).
    // b. Set result to the string-concatenation of result, the code unit 0x002D
    // (HYPHEN-MINUS), and day.
    builder.AppendCharacter('-');
    ToZeroPaddedDecimalString(&builder, year_month->iso_day(), 2);
  }
  // 8. Let calendarString be ! FormatCalendarAnnotation(calendarID,
  // showCalendar).
  DirectHandle<String> calendar_string =
      FormatCalendarAnnotation(isolate, calendar_id, show_calendar);
  // 9. Set result to the string-concatenation of result and calendarString.
  builder.AppendString(calendar_string);
  // 10. Return result.
  return indirect_handle(builder.Finish().ToHandleChecked(), isolate);
}

// #sec-temporal-builtintimezonegetoffsetstringfor
MaybeHandle<String> BuiltinTimeZoneGetOffsetStringFor(
    Isolate* isolate, Handle<JSReceiver> time_zone,
    Handle<JSTemporalInstant> instant, const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let offsetNanoseconds be ? GetOffsetNanosecondsFor(timeZone, instant).
  int64_t offset_nanoseconds;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_nanoseconds,
      GetOffsetNanosecondsFor(isolate, time_zone, instant, method_name),
      Handle<String>());

  // 2. Return ! FormatTimeZoneOffsetString(offsetNanoseconds).
  return FormatTimeZoneOffsetString(isolate, offset_nanoseconds);
}

// #sec-temporal-parseisodatetime
Maybe<DateTimeRecordWithCalendar> ParseISODateTime(
    Isolate* isolate, Handle<String> iso_string,
    const ParsedISO8601Result& parsed);
// Note: We split ParseISODateTime to two function because the spec text
// repeates some parsing unnecessary. If a function is calling ParseISODateTime
// from a AO which already call ParseText() for TemporalDateTimeString,
// TemporalInstantString, TemporalMonthDayString, TemporalTimeString,
// TemporalYearMonthString, TemporalZonedDateTimeString. But for the usage in
// ParseTemporalTimeZoneString, we use the following version.
Maybe<DateTimeRecordWithCalendar> ParseISODateTime(Isolate* isolate,
                                                   Handle<String> iso_string) {
  // 2. For each nonterminal goal of « TemporalDateTimeString,
  // TemporalInstantString, TemporalMonthDayString, TemporalTimeString,
  // TemporalYearMonthString, TemporalZonedDateTimeString », do

  // a. If parseResult is not a Parse Node, set parseResult to
  // ParseText(StringToCodePoints(isoString), goal).
  std::optional<ParsedISO8601Result> parsed;
  if ((parsed =
           TemporalParser::ParseTemporalDateTimeString(isolate, iso_string))
          .has_value() ||
      (parsed = TemporalParser::ParseTemporalInstantString(isolate, iso_string))
          .has_value() ||
      (parsed =
           TemporalParser::ParseTemporalMonthDayString(isolate, iso_string))
          .has_value() ||
      (parsed = TemporalParser::ParseTemporalTimeString(isolate, iso_string))
          .has_value() ||
      (parsed =
           TemporalParser::ParseTemporalYearMonthString(isolate, iso_string))
          .has_value() ||
      (parsed = TemporalParser::ParseTemporalZonedDateTimeString(isolate,
                                                                 iso_string))
          .has_value()) {
    return ParseISODateTime(isolate, iso_string, *parsed);
  }

  // 3. If parseResult is not a Parse Node, throw a RangeError exception.
  THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                               Nothing<DateTimeRecordWithCalendar>());
}

Maybe<DateTimeRecordWithCalendar> ParseISODateTime(
    Isolate* isolate, Handle<String> iso_string,
    const ParsedISO8601Result& parsed) {
  TEMPORAL_ENTER_FUNC();

  DateTimeRecordWithCalendar result;
  // 6. Set yearMV to ! ToIntegerOrInfinity(year).
  result.date.year = parsed.date_year;
  // 7. If month is undefined, then
  if (parsed.date_month_is_undefined()) {
    // a. Set monthMV to 1.
    result.date.month = 1;
    // 8. Else,
  } else {
    // a. Set monthMV to ! ToIntegerOrInfinity(month).
    result.date.month = parsed.date_month;
  }

  // 9. If day is undefined, then
  if (parsed.date_day_is_undefined()) {
    // a. Set dayMV to 1.
    result.date.day = 1;
    // 10. Else,
  } else {
    // a. Set dayMV to ! ToIntegerOrInfinity(day).
    result.date.day = parsed.date_day;
  }
  // 11. Set hourMV to ! ToIntegerOrInfinity(hour).
  result.time.hour = parsed.time_hour_is_undefined() ? 0 : parsed.time_hour;
  // 12. Set minuteMV to ! ToIntegerOrInfinity(minute).
  result.time.minute =
      parsed.time_minute_is_undefined() ? 0 : parsed.time_minute;
  // 13. Set secondMV to ! ToIntegerOrInfinity(second).
  result.time.second =
      parsed.time_second_is_undefined() ? 0 : parsed.time_second;
  // 14. If secondMV is 60, then
  if (result.time.second == 60) {
    // a. Set secondMV to 59.
    result.time.second = 59;
  }
  // 15. If fSeconds is not empty, then
  if (!parsed.time_nanosecond_is_undefined()) {
    // a. Let fSecondsDigits be the substring of CodePointsToString(fSeconds)
    // from 1.
    //
    // b. Let fSecondsDigitsExtended be the string-concatenation of
    // fSecondsDigits and "000000000".
    //
    // c. Let millisecond be the substring of fSecondsDigitsExtended from 0 to
    // 3.
    //
    // d. Let microsecond be the substring of fSecondsDigitsExtended from 3 to
    // 6.
    //
    // e. Let nanosecond be the substring of fSecondsDigitsExtended from 6 to 9.
    //
    // f. Let millisecondMV be ! ToIntegerOrInfinity(millisecond).
    result.time.millisecond = parsed.time_nanosecond / 1000000;
    // g. Let microsecondMV be ! ToIntegerOrInfinity(microsecond).
    result.time.microsecond = (parsed.time_nanosecond / 1000) % 1000;
    // h. Let nanosecondMV be ! ToIntegerOrInfinity(nanosecond).
    result.time.nanosecond = (parsed.time_nanosecond % 1000);
    // 16. Else,
  } else {
    // a. Let millisecondMV be 0.
    result.time.millisecond = 0;
    // b. Let microsecondMV be 0.
    result.time.microsecond = 0;
    // c. Let nanosecondMV be 0.
    result.time.nanosecond = 0;
  }
  // 17. If ! IsValidISODate(yearMV, monthMV, dayMV) is false, throw a
  // RangeError exception.
  if (!IsValidISODate(isolate, result.date)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateTimeRecordWithCalendar>());
  }
  // 18. If ! IsValidTime(hourMV, minuteMV, secondMV, millisecondMV,
  // microsecondMV, nanosecond) is false, throw a RangeError exception.
  if (!IsValidTime(isolate, result.time)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateTimeRecordWithCalendar>());
  }

  // 19. Let timeZoneResult be the Record { [[Z]]: false, [[OffsetString]]:
  // undefined, [[Name]]: undefined }.
  result.time_zone = {false, isolate->factory()->undefined_value(),
                      isolate->factory()->undefined_value()};
  // 20. If parseResult contains a TimeZoneIdentifier Parse Node, then
  if (parsed.tzi_name_length != 0) {
    // a. Let name be the source text matched by the TimeZoneIdentifier Parse
    // Node contained within parseResult.
    //
    // b. Set timeZoneResult.[[Name]] to CodePointsToString(name).
    result.time_zone.name = isolate->factory()->NewSubString(
        iso_string, parsed.tzi_name_start,
        parsed.tzi_name_start + parsed.tzi_name_length);
  }
  // 21. If parseResult contains a UTCDesignator Parse Node, then
  if (parsed.utc_designator) {
    // a. Set timeZoneResult.[[Z]] to true.
    result.time_zone.z = true;
    // 22. Else,
  } else {
    // a. If parseResult contains a TimeZoneNumericUTCOffset Parse Node, then
    if (parsed.offset_string_length != 0) {
      // i. Let offset be the source text matched by the
      // TimeZoneNumericUTCOffset Parse Node contained within parseResult.
      // ii. Set timeZoneResult.[[OffsetString]] to CodePointsToString(offset).
      result.time_zone.offset_string = isolate->factory()->NewSubString(
          iso_string, parsed.offset_string_start,
          parsed.offset_string_start + parsed.offset_string_length);
    }
  }

  // 23. If calendar is empty, then
  if (parsed.calendar_name_length == 0) {
    // a. Let calendarVal be undefined.
    result.calendar = isolate->factory()->undefined_value();
    // 24. Else,
  } else {
    // a. Let calendarVal be CodePointsToString(calendar).
    result.calendar = isolate->factory()->NewSubString(
        iso_string, parsed.calendar_name_start,
        parsed.calendar_name_start + parsed.calendar_name_length);
  }
  // 24. Return the Record { [[Year]]: yearMV, [[Month]]: monthMV, [[Day]]:
  // dayMV, [[Hour]]: hourMV, [[Minute]]: minuteMV, [[Second]]: secondMV,
  // [[Millisecond]]: millisecondMV, [[Microsecond]]: microsecondMV,
  // [[Nanosecond]]: nanosecondMV, [[TimeZone]]: timeZoneResult,
  // [[Calendar]]: calendarVal, }.
  return Just(result);
}

// #sec-temporal-parsetemporaldatestring
Maybe<DateRecordWithCalendar> ParseTemporalDateString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let parts be ? ParseTemporalDateTimeString(isoString).
  // 2. Return the Record { [[Year]]: parts.[[Year]], [[Month]]:
  // parts.[[Month]], [[Day]]: parts.[[Day]], [[Calendar]]: parts.[[Calendar]]
  // }.
  DateTimeRecordWithCalendar record;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, record, ParseTemporalDateTimeString(isolate, iso_string),
      Nothing<DateRecordWithCalendar>());
  DateRecordWithCalendar result = {record.date, record.calendar};
  return Just(result);
}

// #sec-temporal-parsetemporaltimestring
Maybe<TimeRecordWithCalendar> ParseTemporalTimeString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: Type(isoString) is String.
  // 2. If isoString does not satisfy the syntax of a TemporalTimeString
  // (see 13.33), then
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalTimeString(isolate, iso_string);
  if (!parsed.has_value()) {
    // a. Throw a *RangeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<TimeRecordWithCalendar>());
  }

  // 3. If _isoString_ contains a |UTCDesignator|, then
  if (parsed->utc_designator) {
    // a. Throw a *RangeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<TimeRecordWithCalendar>());
  }

  // 3. Let result be ? ParseISODateTime(isoString).
  DateTimeRecordWithCalendar result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseISODateTime(isolate, iso_string, *parsed),
      Nothing<TimeRecordWithCalendar>());
  // 4. Return the Record { [[Hour]]: result.[[Hour]], [[Minute]]:
  // result.[[Minute]], [[Second]]: result.[[Second]], [[Millisecond]]:
  // result.[[Millisecond]], [[Microsecond]]: result.[[Microsecond]],
  // [[Nanosecond]]: result.[[Nanosecond]], [[Calendar]]: result.[[Calendar]] }.
  TimeRecordWithCalendar ret = {result.time, result.calendar};
  return Just(ret);
}

// #sec-temporal-parsetemporalinstantstring
Maybe<InstantRecord> ParseTemporalInstantString(Isolate* isolate,
                                                Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. If ParseText(StringToCodePoints(isoString), TemporalInstantString) is a
  // List of errors, throw a RangeError exception.
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalInstantString(isolate, iso_string);
  if (!parsed.has_value()) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<InstantRecord>());
  }

  // 2. Let result be ? ParseISODateTime(isoString).
  DateTimeRecordWithCalendar result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseISODateTime(isolate, iso_string, *parsed),
      Nothing<InstantRecord>());

  // 3. Let offsetString be result.[[TimeZone]].[[OffsetString]].
  Handle<Object> offset_string = result.time_zone.offset_string;

  // 4. If result.[[TimeZone]].[[Z]] is true, then
  if (result.time_zone.z) {
    // a. Set offsetString to "+00:00".
    offset_string = isolate->factory()->NewStringFromStaticChars("+00:00");
  }
  // 5. Assert: offsetString is not undefined.
  DCHECK(!IsUndefined(*offset_string));

  // 6. Return the new Record { [[Year]]: result.[[Year]],
  // [[Month]]: result.[[Month]], [[Day]]: result.[[Day]],
  // [[Hour]]: result.[[Hour]], [[Minute]]: result.[[Minute]],
  // [[Second]]: result.[[Second]],
  // [[Millisecond]]: result.[[Millisecond]],
  // [[Microsecond]]: result.[[Microsecond]],
  // [[Nanosecond]]: result.[[Nanosecond]],
  // [[TimeZoneOffsetString]]: offsetString }.
  InstantRecord record({result.date, result.time, offset_string});
  return Just(record);
}

// #sec-temporal-parsetemporalrelativetostring
Maybe<DateTimeRecordWithCalendar> ParseTemporalRelativeToString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. If ParseText(StringToCodePoints(isoString), TemporalDateTimeString) is a
  // List of errors, throw a RangeError exception.
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalDateTimeString(isolate, iso_string);
  if (!parsed.has_value()) {
    // a. Throw a *RangeError* exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateTimeRecordWithCalendar>());
  }
  // 2. Returns ? ParseISODateTime(isoString).
  return ParseISODateTime(isolate, iso_string, *parsed);
}

// #sec-temporal-parsetemporalinstant
MaybeHandle<BigInt> ParseTemporalInstant(Isolate* isolate,
                                         Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: Type(isoString) is String.
  // 2. Let result be ? ParseTemporalInstantString(isoString).
  InstantRecord result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseTemporalInstantString(isolate, iso_string),
      Handle<BigInt>());

  // 3. Let offsetString be result.[[TimeZoneOffsetString]].
  // 4. Assert: offsetString is not undefined.
  DCHECK(!IsUndefined(*result.offset_string));

  // 5. Let utc be ? GetEpochFromISOParts(result.[[Year]], result.[[Month]],
  // result.[[Day]], result.[[Hour]], result.[[Minute]], result.[[Second]],
  // result.[[Millisecond]], result.[[Microsecond]], result.[[Nanosecond]]).
  Handle<BigInt> utc =
      GetEpochFromISOParts(isolate, {result.date, result.time});

  // 6. Let offsetNanoseconds be ? ParseTimeZoneOffsetString(offsetString).
  int64_t offset_nanoseconds;
  DCHECK(IsString(*result.offset_string));
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_nanoseconds,
      ParseTimeZoneOffsetString(isolate, Cast<String>(result.offset_string)),
      Handle<BigInt>());

  // 7. Let result be utc - ℤ(offsetNanoseconds).
  Handle<BigInt> result_value =
      BigInt::Subtract(isolate, utc,
                       BigInt::FromInt64(isolate, offset_nanoseconds))
          .ToHandleChecked();
  // 8. If ! IsValidEpochNanoseconds(result) is false, then
  if (!IsValidEpochNanoseconds(isolate, result_value)) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 9. Return result.
  return result_value;
}

// #sec-temporal-parsetemporalzoneddatetimestring
Maybe<DateTimeRecordWithCalendar> ParseTemporalZonedDateTimeString(
    Isolate* isolate, Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();
  // 1. If ParseText(StringToCodePoints(isoString), TemporalZonedDateTimeString)
  // is a List of errors, throw a RangeError exception.
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTemporalZonedDateTimeString(isolate, iso_string);
  if (!parsed.has_value()) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateTimeRecordWithCalendar>());
  }

  // 2. Return ? ParseISODateTime(isoString).
  return ParseISODateTime(isolate, iso_string, *parsed);
}

// #sec-temporal-createdurationrecord
Maybe<DurationRecord> CreateDurationRecord(Isolate* isolate,
                                           const DurationRecord& duration) {
  //   1. If ! IsValidDuration(years, months, weeks, days, hours, minutes,
  //   seconds, milliseconds, microseconds, nanoseconds) is false, throw a
  //   RangeError exception.
  if (!IsValidDuration(isolate, duration)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DurationRecord>());
  }
  // 2. Return the Record { [[Years]]: ℝ(𝔽(years)), [[Months]]: ℝ(𝔽(months)),
  // [[Weeks]]: ℝ(𝔽(weeks)), [[Days]]: ℝ(𝔽(days)), [[Hours]]: ℝ(𝔽(hours)),
  // [[Minutes]]: ℝ(𝔽(minutes)), [[Seconds]]: ℝ(𝔽(seconds)), [[Milliseconds]]:
  // ℝ(𝔽(milliseconds)), [[Microseconds]]: ℝ(𝔽(microseconds)), [[Nanoseconds]]:
  // ℝ(𝔽(nanoseconds)) }.
  return Just(duration);
}

inline double IfEmptyReturnZero(double value) {
  return value == ParsedISO8601Duration::kEmpty ? 0 : value;
}

// #sec-temporal-parsetemporaldurationstring
Maybe<DurationRecord> ParseTemporalDurationString(Isolate* isolate,
                                                  Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();
  // In this funciton, we use 'double' as type for all mathematical values
  // because in
  // https://tc39.es/proposal-temporal/#sec-properties-of-temporal-duration-instances
  // they are "A float64-representable integer representing the number" in the
  // internal slots.
  // 1. Let duration be ParseText(StringToCodePoints(isoString),
  // TemporalDurationString).
  // 2. If duration is a List of errors, throw a RangeError exception.
  // 3. Let each of sign, years, months, weeks, days, hours, fHours, minutes,
  // fMinutes, seconds, and fSeconds be the source text matched by the
  // respective Sign, DurationYears, DurationMonths, DurationWeeks,
  // DurationDays, DurationWholeHours, DurationHoursFraction,
  // DurationWholeMinutes, DurationMinutesFraction, DurationWholeSeconds, and
  // DurationSecondsFraction Parse Node enclosed by duration, or an empty
  // sequence of code points if not present.
  std::optional<ParsedISO8601Duration> parsed =
      TemporalParser::ParseTemporalDurationString(isolate, iso_string);
  if (!parsed.has_value()) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DurationRecord>());
  }
  // 4. Let yearsMV be ! ToIntegerOrInfinity(CodePointsToString(years)).
  double years_mv = IfEmptyReturnZero(parsed->years);
  // 5. Let monthsMV be ! ToIntegerOrInfinity(CodePointsToString(months)).
  double months_mv = IfEmptyReturnZero(parsed->months);
  // 6. Let weeksMV be ! ToIntegerOrInfinity(CodePointsToString(weeks)).
  double weeks_mv = IfEmptyReturnZero(parsed->weeks);
  // 7. Let daysMV be ! ToIntegerOrInfinity(CodePointsToString(days)).
  double days_mv = IfEmptyReturnZero(parsed->days);
  // 8. Let hoursMV be ! ToIntegerOrInfinity(CodePointsToString(hours)).
  double hours_mv = IfEmptyReturnZero(parsed->whole_hours);
  // 9. If fHours is not empty, then
  double minutes_mv;
  if (parsed->hours_fraction != ParsedISO8601Duration::kEmpty) {
    // a. If any of minutes, fMinutes, seconds, fSeconds is not empty, throw a
    // RangeError exception.
    if (parsed->whole_minutes != ParsedISO8601Duration::kEmpty ||
        parsed->minutes_fraction != ParsedISO8601Duration::kEmpty ||
        parsed->whole_seconds != ParsedISO8601Duration::kEmpty ||
        parsed->seconds_fraction != ParsedISO8601Duration::kEmpty) {
      THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                   NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                   Nothing<DurationRecord>());
    }
    // b. Let fHoursDigits be the substring of CodePointsToString(fHours)
    // from 1.
    //
    // c. Let fHoursScale be the length of fHoursDigits.
    //
    // d. Let
    // minutesMV be ! ToIntegerOrInfinity(fHoursDigits) / 10^fHoursScale × 60.
    minutes_mv = IfEmptyReturnZero(parsed->hours_fraction) * 60.0 / 1e9;
    // 10. Else,
  } else {
    // a. Let minutesMV be ! ToIntegerOrInfinity(CodePointsToString(minutes)).
    minutes_mv = IfEmptyReturnZero(parsed->whole_minutes);
  }
  double seconds_mv;
  // 11. If fMinutes is not empty, then
  if (parsed->minutes_fraction != ParsedISO8601Duration::kEmpty) {
    // a. If any of seconds, fSeconds is not empty, throw a RangeError
    // exception.
    if (parsed->whole_seconds != ParsedISO8601Duration::kEmpty ||
        parsed->seconds_fraction != ParsedISO8601Duration::kEmpty) {
      THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                   NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                   Nothing<DurationRecord>());
    }
    // b. Let fMinutesDigits be the substring of CodePointsToString(fMinutes)
    // from 1.
    //
    // c. Let fMinutesScale be the length of fMinutesDigits.
    //
    // d. Let secondsMV be ! ToIntegerOrInfinity(fMinutesDigits) /
    // 10^fMinutesScale × 60.
    seconds_mv = IfEmptyReturnZero(parsed->minutes_fraction) * 60.0 / 1e9;
    // 12. Else if seconds is not empty, then
  } else if (parsed->whole_seconds != ParsedISO8601Duration::kEmpty) {
    // a. Let secondsMV be ! ToIntegerOrInfinity(CodePointsToString(seconds)).
    seconds_mv = parsed->whole_seconds;
    // 13. Else,
  } else {
    // a. Let secondsMV be remainder(minutesMV, 1) × 60.
    seconds_mv = (minutes_mv - std::floor(minutes_mv)) * 60.0;
  }
  double milliseconds_mv, microseconds_mv, nanoseconds_mv;
  // Note: In step 14-17, we calculate from nanoseconds_mv to miilliseconds_mv
  // in the reversee order of the spec text to avoid numerical errors would be
  // introduced by multiple division inside the remainder operations. If we
  // strickly follow the order by using double, the end result of nanoseconds_mv
  // will be wrong due to numerical errors.
  //
  // 14. If fSeconds is not empty, then
  if (parsed->seconds_fraction != ParsedISO8601Duration::kEmpty) {
    // a. Let fSecondsDigits be the substring of CodePointsToString(fSeconds)
    // from 1.
    //
    // b. Let fSecondsScale be the length of fSecondsDigits.
    //
    // c. Let millisecondsMV be ! ToIntegerOrInfinity(fSecondsDigits) /
    // 10^fSecondsScale × 1000.
    DCHECK_LE(IfEmptyReturnZero(parsed->seconds_fraction), 1e9);
    nanoseconds_mv = std::round(IfEmptyReturnZero(parsed->seconds_fraction));
    // 15. Else,
  } else {
    // a. Let millisecondsMV be remainder(secondsMV, 1) × 1000.
    nanoseconds_mv = std::round((seconds_mv - std::floor(seconds_mv)) * 1e9);
  }
  milliseconds_mv = std::floor(nanoseconds_mv / 1000000);
  // 16. Let microsecondsMV be remainder(millisecondsMV, 1) × 1000.
  microseconds_mv = std::floor(nanoseconds_mv / 1000) -
                    std::floor(nanoseconds_mv / 1000000) * 1000;
  // 17. Let nanosecondsMV be remainder(microsecondsMV, 1) × 1000.
  nanoseconds_mv -= std::floor(nanoseconds_mv / 1000) * 1000;

  // 18. If sign contains the code point 0x002D (HYPHEN-MINUS) or 0x2212 (MINUS
  // SIGN), then a. Let factor be −1.
  // 19. Else,
  // a. Let factor be 1.
  double factor = parsed->sign;

  // 20. Return ? CreateDurationRecord(yearsMV × factor, monthsMV × factor,
  // weeksMV × factor, daysMV × factor, hoursMV × factor, floor(minutesMV) ×
  // factor, floor(secondsMV) × factor, floor(millisecondsMV) × factor,
  // floor(microsecondsMV) × factor, floor(nanosecondsMV) × factor).

  return CreateDurationRecord(
      isolate,
      {years_mv * factor,
       months_mv * factor,
       weeks_mv * factor,
       {days_mv * factor, hours_mv * factor, std::floor(minutes_mv) * factor,
        std::floor(seconds_mv) * factor, milliseconds_mv * factor,
        microseconds_mv * factor, nanoseconds_mv * factor}});
}

// #sec-temporal-parsetemporaltimezonestring
Maybe<TimeZoneRecord> ParseTemporalTimeZoneString(
    Isolate* isolate, Handle<String> time_zone_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Let parseResult be ParseText(StringToCodePoints(timeZoneString),
  // TimeZoneIdentifier).
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTimeZoneIdentifier(isolate, time_zone_string);
  // 2. If parseResult is a Parse Node, then
  if (parsed.has_value()) {
    // a. Return the Record { [[Z]]: false, [[OffsetString]]: undefined,
    // [[Name]]: timeZoneString }.
    return Just(TimeZoneRecord(
        {false, isolate->factory()->undefined_value(), time_zone_string}));
  }

  // 3. Let result be ? ParseISODateTime(timeZoneString).
  DateTimeRecordWithCalendar result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, result, ParseISODateTime(isolate, time_zone_string),
      Nothing<TimeZoneRecord>());

  // 4. Let timeZoneResult be result.[[TimeZone]].
  // 5. If timeZoneResult.[[Z]] is false, timeZoneResult.[[OffsetString]] is
  // undefined, and timeZoneResult.[[Name]] is undefined, throw a RangeError
  // exception.
  if (!result.time_zone.z && IsUndefined(*result.time_zone.offset_string) &&
      IsUndefined(*result.time_zone.name)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<TimeZoneRecord>());
  }
  // 6. Return timeZoneResult.
  return Just(result.time_zone);
}

Maybe<int64_t> ParseTimeZoneOffsetString(Isolate* isolate,
                                         Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Assert: Type(offsetString) is String.
  // 2. If offsetString does not satisfy the syntax of a
  // TimeZoneNumericUTCOffset (see 13.33), then
  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTimeZoneNumericUTCOffset(isolate, iso_string);
  if (!parsed.has_value()) {
    /* a. Throw a RangeError exception. */
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(), Nothing<int64_t>());
  }
  // 3. Let sign, hours, minutes, seconds, and fraction be the parts of
  // offsetString produced respectively by the TimeZoneUTCOffsetSign,
  // TimeZoneUTCOffsetHour, TimeZoneUTCOffsetMinute, TimeZoneUTCOffsetSecond,
  // and TimeZoneUTCOffsetFraction productions, or undefined if not present.
  // 4. If either hours or sign are undefined, throw a RangeError exception.
  if (parsed->tzuo_hour_is_undefined() || parsed->tzuo_sign_is_undefined()) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(), Nothing<int64_t>());
  }
  // 5. If sign is the code unit 0x002D (HYPHEN-MINUS) or 0x2212 (MINUS SIGN),
  // then a. Set sign to −1.
  // 6. Else,
  // a. Set sign to 1.
  int64_t sign = parsed->tzuo_sign;

  // 7. Set hours to ! ToIntegerOrInfinity(hours).
  int64_t hours = parsed->tzuo_hour;
  // 8. Set minutes to ! ToIntegerOrInfinity(minutes).
  int64_t minutes =
      parsed->tzuo_minute_is_undefined() ? 0 : parsed->tzuo_minute;
  // 9. Set seconds to ! ToIntegerOrInfinity(seconds).
  int64_t seconds =
      parsed->tzuo_second_is_undefined() ? 0 : parsed->tzuo_second;
  // 10. If fraction is not undefined, then
  int64_t nanoseconds;
  if (!parsed->tzuo_nanosecond_is_undefined()) {
    // a. Set fraction to the string-concatenation of the previous value of
    // fraction and the string "000000000".
    // b. Let nanoseconds be the String value equal to the substring of fraction
    // consisting of the code units with indices 0 (inclusive) through 9
    // (exclusive). c. Set nanoseconds to ! ToIntegerOrInfinity(nanoseconds).
    nanoseconds = parsed->tzuo_nanosecond;
    // 11. Else,
  } else {
    // a. Let nanoseconds be 0.
    nanoseconds = 0;
  }
  // 12. Return sign × (((hours × 60 + minutes) × 60 + seconds) × 10^9 +
  // nanoseconds).
  return Just(sign * (((hours * 60 + minutes) * 60 + seconds) * 1000000000 +
                      nanoseconds));
}

bool IsValidTimeZoneNumericUTCOffsetString(Isolate* isolate,
                                           Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  std::optional<ParsedISO8601Result> parsed =
      TemporalParser::ParseTimeZoneNumericUTCOffset(isolate, iso_string);
  return parsed.has_value();
}

// #sec-temporal-parsetemporalcalendarstring
MaybeHandle<String> ParseTemporalCalendarString(Isolate* isolate,
                                                Handle<String> iso_string) {
  TEMPORAL_ENTER_FUNC();

  // 1. Let parseResult be Completion(ParseISODateTime(isoString)).
  Maybe<DateTimeRecordWithCalendar> parse_result =
      ParseISODateTime(isolate, iso_string);
  // 2. If parseResult is a normal completion, then
  if (parse_result.IsJust()) {
    // a. Let calendar be parseResult.[[Value]].[[Calendar]].
    Handle<Object> calendar = parse_result.FromJust().calendar;
    // b. If calendar is undefined, return "iso8601".
    if (IsUndefined(*calendar)) {
      return isolate->factory()->iso8601_string();
      // c. Else, return calendar.
    } else {
      CHECK(IsString(*calendar));
      return Cast<String>(calendar);
    }
    // 3. Else,
  } else {
    DCHECK(isolate->has_exception());
    isolate->clear_exception();
    // a. Set parseResult to ParseText(StringToCodePoints(isoString),
    // CalendarName).
    std::optional<ParsedISO8601Result> parsed =
        TemporalParser::ParseCalendarName(isolate, iso_string);
    // b. If parseResult is a List of errors, throw a RangeError exception.
    if (!parsed.has_value()) {
      THROW_NEW_ERROR(isolate, NewRangeError(MessageTemplate::kInvalidCalendar,
                                             iso_string));
    }
    // c. Else, return isoString.
    return iso_string;
  }
}

// #sec-temporal-calendarequals
Maybe<bool> CalendarEqualsBool(Isolate* isolate, Handle<JSReceiver> one,
                               Handle<JSReceiver> two) {
  // 1. If one and two are the same Object value, return true.
  if (one.is_identical_to(two)) {
    return Just(true);
  }
  // 2. Let calendarOne be ? ToString(one).
  Handle<String> calendar_one;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar_one, Object::ToString(isolate, one), Nothing<bool>());
  // 3. Let calendarTwo be ? ToString(two).
  Handle<String> calendar_two;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, calendar_two, Object::ToString(isolate, two), Nothing<bool>());
  // 4. If calendarOne is calendarTwo, return true.
  if (String::Equals(isolate, calendar_one, calendar_two)) {
    return Just(true);
  }
  // 5. Return false.
  return Just(false);
}
MaybeHandle<Oddball> CalendarEquals(Isolate* isolate, Handle<JSReceiver> one,
                                    Handle<JSReceiver> two) {
  bool result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, result,
                                         CalendarEqualsBool(isolate, one, two),
                                         Handle<Oddball>());
  return isolate->factory()->ToBoolean(result);
}

// #sec-temporal-calendarfields
MaybeHandle<FixedArray> CalendarFields(Isolate* isolate,
                                       Handle<JSReceiver> calendar,
                                       DirectHandle<FixedArray> field_names) {
  // 1. Let fields be ? GetMethod(calendar, "fields").
  Handle<Object> fields;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields,
      Object::GetMethod(isolate, calendar,
                        isolate->factory()->fields_string()));
  // 2. Let fieldsArray be ! CreateArrayFromList(fieldNames).
  Handle<Object> fields_array =
      isolate->factory()->NewJSArrayWithElements(field_names);
  // 3. If fields is not undefined, then
  if (!IsUndefined(*fields)) {
    // a. Set fieldsArray to ? Call(fields, calendar, « fieldsArray »).
    Handle<Object> argv[] = {fields_array};
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, fields_array,
        Execution::Call(isolate, fields, calendar, 1, argv));
  }
  // 4. Return ? IterableToListOfType(fieldsArray, « String »).
  Handle<Object> argv[] = {fields_array};
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, fields_array,
      Execution::CallBuiltin(isolate,
                             isolate->string_fixed_array_from_iterable(),
                             fields_array, 1, argv));
  DCHECK(IsFixedArray(*fields_array));
  return Cast<FixedArray>(fields_array);
}

MaybeHandle<JSTemporalPlainDate> CalendarDateAdd(Isolate* isolate,
                                                 Handle<JSReceiver> calendar,
                                                 Handle<Object> date,
                                                 Handle<Object> duration) {
  // 2. If options is not present, set options to undefined.
  return CalendarDateAdd(isolate, calendar, date, duration,
                         isolate->factory()->undefined_value());
}

MaybeHandle<JSTemporalPlainDate> CalendarDateAdd(Isolate* isolate,
                                                 Handle<JSReceiver> calendar,
                                                 Handle<Object> date,
                                                 Handle<Object> duration,
                                                 Handle<Object> options) {
  Handle<Object> date_add;
  // 4. If dateAdd is not present, set dateAdd to ? GetMethod(calendar,
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, date_add,
      Object::GetMethod(isolate, calendar,
                        isolate->factory()->dateAdd_string()));
  return CalendarDateAdd(isolate, calendar, date, duration, options, date_add);
}

MaybeHandle<JSTemporalPlainDate> CalendarDateAdd(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<Object> date,
    Handle<Object> duration, Handle<Object> options, Handle<Object> date_add) {
  // 1. Assert: Type(options) is Object or Undefined.
  DCHECK(IsJSReceiver(*options) || IsUndefined(*options));

  // 3. Let addedDate be ? Call(dateAdd, calendar, « date, duration, options »).
  Handle<Object> argv[] = {date, duration, options};
  Handle<Object> added_date;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, added_date,
      Execution::Call(isolate, date_add, calendar, arraysize(argv), argv));
  // 4. Perform ? RequireInternalSlot(addedDate, [[InitializedTemporalDate]]).
  if (!IsJSTemporalPlainDate(*added_date)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  // 5. Return addedDate.
  return Cast<JSTemporalPlainDate>(added_date);
}

MaybeHandle<JSTemporalDuration> CalendarDateUntil(Isolate* isolate,
                                                  Handle<JSReceiver> calendar,
                                                  Handle<Object> one,
                                                  Handle<Object> two,
                                                  Handle<Object> options) {
  return CalendarDateUntil(isolate, calendar, one, two, options,
                           isolate->factory()->undefined_value());
}

MaybeHandle<JSTemporalDuration> CalendarDateUntil(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<Object> one,
    Handle<Object> two, Handle<Object> options, Handle<Object> date_until) {
  // 1. Assert: Type(calendar) is Object.
  // 2. If dateUntil is not present, set dateUntil to ? GetMethod(calendar,
  // "dateUntil").
  if (IsUndefined(*date_until)) {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, date_until,
        Object::GetMethod(isolate, calendar,
                          isolate->factory()->dateUntil_string()));
  }
  // 3. Let duration be ? Call(dateUntil, calendar, « one, two, options »).
  Handle<Object> argv[] = {one, two, options};
  Handle<Object> duration;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, duration,
      Execution::Call(isolate, date_until, calendar, arraysize(argv), argv));
  // 4. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  if (!IsJSTemporalDuration(*duration)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  // 5. Return duration.
  return Cast<JSTemporalDuration>(duration);
}

// #sec-temporal-defaultmergefields
MaybeHandle<JSReceiver> DefaultMergeFields(
    Isolate* isolate, Handle<JSReceiver> fields,
    Handle<JSReceiver> additional_fields) {
  Factory* factory = isolate->factory();
  // 1. Let merged be ! OrdinaryObjectCreate(%Object.prototype%).
  Handle<JSObject> merged =
      isolate->factory()->NewJSObject(isolate->object_function());

  // 2. Let originalKeys be ? EnumerableOwnPropertyNames(fields, key).
  Handle<FixedArray> original_keys;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, original_keys,
      KeyAccumulator::GetKeys(isolate, fields, KeyCollectionMode::kOwnOnly,
                              ENUMERABLE_STRINGS,
                              GetKeysConversion::kConvertToString));
  // 3. For each element nextKey of originalKeys, do
  for (int i = 0; i < original_keys->length(); i++) {
    // a. If nextKey is not "month" or "monthCode", then
    Handle<Object> next_key(original_keys->get(i), isolate);
    DCHECK(IsString(*next_key));
    Handle<String> next_key_string = Cast<String>(next_key);
    if (!(String::Equals(isolate, factory->month_string(), next_key_string) ||
          String::Equals(isolate, factory->monthCode_string(),
                         next_key_string))) {
      // i. Let propValue be ? Get(fields, nextKey).
      Handle<Object> prop_value;
      ASSIGN_RETURN_ON_EXCEPTION(
          isolate, prop_value,
          Object::GetPropertyOrElement(isolate, fields, next_key_string));
      // ii. If propValue is not undefined, then
      if (!IsUndefined(*prop_value)) {
        // 1. Perform ! CreateDataPropertyOrThrow(merged, nextKey,
        // propValue).
        CHECK(JSReceiver::CreateDataProperty(isolate, merged, next_key_string,
                                             prop_value, Just(kDontThrow))
                  .FromJust());
      }
    }
  }
  // 4. Let newKeys be ? EnumerableOwnPropertyNames(additionalFields, key).
  Handle<FixedArray> new_keys;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, new_keys,
      KeyAccumulator::GetKeys(isolate, additional_fields,
                              KeyCollectionMode::kOwnOnly, ENUMERABLE_STRINGS,
                              GetKeysConversion::kConvertToString));
  bool new_keys_has_month_or_month_code = false;
  // 5. For each element nextKey of newKeys, do
  for (int i = 0; i < new_keys->length(); i++) {
    Handle<Object> next_key(new_keys->get(i), isolate);
    DCHECK(IsString(*next_key));
    Handle<String> next_key_string = Cast<String>(next_key);
    // a. Let propValue be ? Get(additionalFields, nextKey).
    Handle<Object> prop_value;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, prop_value,
        Object::GetPropertyOrElement(isolate, additional_fields,
                                     next_key_string));
    // b. If propValue is not undefined, then
    if (!IsUndefined(*prop_value)) {
      // 1. Perform ! CreateDataPropertyOrThrow(merged, nextKey, propValue).
      CHECK(JSReceiver::CreateDataProperty(isolate, merged, next_key_string,
                                           prop_value, Just(kDontThrow))
                .FromJust());
    }
    new_keys_has_month_or_month_code |=
        String::Equals(isolate, factory->month_string(), next_key_string) ||
        String::Equals(isolate, factory->monthCode_string(), next_key_string);
  }
  // 6. If newKeys does not contain either "month" or "monthCode", then
  if (!new_keys_has_month_or_month_code) {
    // a. Let month be ? Get(fields, "month").
    Handle<Object> month;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, month,
        JSReceiver::GetProperty(isolate, fields, factory->month_string()));
    // b. If month is not undefined, then
    if (!IsUndefined(*month)) {
      // i. Perform ! CreateDataPropertyOrThrow(merged, "month", month).
      CHECK(JSReceiver::CreateDataProperty(isolate, merged,
                                           factory->month_string(), month,
                                           Just(kDontThrow))
                .FromJust());
    }
    // c. Let monthCode be ? Get(fields, "monthCode").
    Handle<Object> month_code;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, month_code,
        JSReceiver::GetProperty(isolate, fields, factory->monthCode_string()));
    // d. If monthCode is not undefined, then
    if (!IsUndefined(*month_code)) {
      // i. Perform ! CreateDataPropertyOrThrow(merged, "monthCode", monthCode).
      CHECK(JSReceiver::CreateDataProperty(isolate, merged,
                                           factory->monthCode_string(),
                                           month_code, Just(kDontThrow))
                .FromJust());
    }
  }
  // 7. Return merged.
  return merged;
}

// #sec-temporal-getoffsetnanosecondsfor
Maybe<int64_t> GetOffsetNanosecondsFor(Isolate* isolate,
                                       Handle<JSReceiver> time_zone_obj,
                                       Handle<Object> instant,
                                       const char* method_name) {
  TEMPORAL_ENTER_FUNC();
  // 1. Let getOffsetNanosecondsFor be ? GetMethod(timeZone,
  // "getOffsetNanosecondsFor").
  Handle<Object> get_offset_nanoseconds_for;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, get_offset_nanoseconds_for,
      Object::GetMethod(isolate, time_zone_obj,
                        isolate->factory()->getOffsetNanosecondsFor_string()),
      Nothing<int64_t>());
  if (!IsCallable(*get_offset_nanoseconds_for)) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate,
        NewTypeError(MessageTemplate::kCalledNonCallable,
                     isolate->factory()->getOffsetNanosecondsFor_string()),
        Nothing<int64_t>());
  }
  Handle<Object> offset_nanoseconds_obj;
  // 3. Let offsetNanoseconds be ? Call(getOffsetNanosecondsFor, timeZone, «
  // instant »).
  Handle<Object> argv[] = {instant};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, offset_nanoseconds_obj,
      Execution::Call(isolate, get_offset_nanoseconds_for, time_zone_obj, 1,
                      argv),
      Nothing<int64_t>());

  // 4. If Type(offsetNanoseconds) is not Number, throw a TypeError exception.
  if (!IsNumber(*offset_nanoseconds_obj)) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR(),
                                 Nothing<int64_t>());
  }

  // 5. If ! IsIntegralNumber(offsetNanoseconds) is false, throw a RangeError
  // exception.
  if (!IsIntegralNumber(isolate, offset_nanoseconds_obj)) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(), Nothing<int64_t>());
  }
  double offset_nanoseconds =
      Object::NumberValue(Cast<Number>(*offset_nanoseconds_obj));

  // 6. Set offsetNanoseconds to ℝ(offsetNanoseconds).
  int64_t offset_nanoseconds_int = static_cast<int64_t>(offset_nanoseconds);
  // 7. If abs(offsetNanoseconds) >= 86400 × 10^9, throw a RangeError exception.
  if (std::abs(offset_nanoseconds_int) >= 86400e9) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(), Nothing<int64_t>());
  }
  // 8. Return offsetNanoseconds.
  return Just(offset_nanoseconds_int);
}

// #sec-temporal-topositiveinteger
MaybeHandle<Number> ToPositiveInteger(Isolate* isolate,
                                      Handle<Object> argument) {
  TEMPORAL_ENTER_FUNC();

  // 1. Let integer be ? ToInteger(argument).
  Handle<Number> integer;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, integer,
                             ToIntegerThrowOnInfinity(isolate, argument));
  // 2. If integer ≤ 0, then
  if (NumberToInt32(*integer) <= 0) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  return integer;
}

}  // namespace

namespace temporal {
MaybeHandle<Object> InvokeCalendarMethod(Isolate* isolate,
                                         Handle<JSReceiver> calendar,
                                         Handle<String> name,
                                         Handle<JSReceiver> date_like) {
  Handle<Object> result;
  /* 1. Assert: Type(calendar) is Object. */
  DCHECK(calendar->TaggedImpl::IsObject());
  /* 2. Let result be ? Invoke(calendar, #name, « dateLike »). */
  Handle<Object> function;
  ASSIGN_RETURN_ON_EXCEPTION(isolate, function,
                             Object::GetProperty(isolate, calendar, name));
  if (!IsCallable(*function)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kCalledNonCallable, name));
  }
  Handle<Object> argv[] = {date_like};
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result,
      Execution::Call(isolate, function, calendar, arraysize(argv), argv));
  return result;
}

#define CALENDAR_ABSTRACT_OPERATION_INT_ACTION(Name, name, Action)             \
  MaybeHandle<Smi> Calendar##Name(Isolate* isolate,                            \
                                  Handle<JSReceiver> calendar,                 \
                                  Handle<JSReceiver> date_like) {              \
    /* 1. Assert: Type(calendar) is Object.   */                               \
    /* 2. Let result be ? Invoke(calendar, property, « dateLike »). */       \
    Handle<Object> result;                                                     \
    ASSIGN_RETURN_ON_EXCEPTION(                                                \
        isolate, result,                                                       \
        InvokeCalendarMethod(isolate, calendar,                                \
                             isolate->factory()->name##_string(), date_like)); \
    /* 3. If result is undefined, throw a RangeError exception. */             \
    if (IsUndefined(*result)) {                                                \
      THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());        \
    }                                                                          \
    /* 4. Return ? Action(result). */                                          \
    ASSIGN_RETURN_ON_EXCEPTION(isolate, result, Action(isolate, result));      \
    return handle(Smi::FromInt(Object::NumberValue(Cast<Number>(*result))),    \
                  isolate);                                                    \
  }

#define CALENDAR_ABSTRACT_OPERATION(Name, property)                      \
  MaybeHandle<Object> Calendar##Name(Isolate* isolate,                   \
                                     Handle<JSReceiver> calendar,        \
                                     Handle<JSReceiver> date_like) {     \
    return InvokeCalendarMethod(isolate, calendar,                       \
                                isolate->factory()->property##_string(), \
                                date_like);                              \
  }

// #sec-temporal-calendaryear
CALENDAR_ABSTRACT_OPERATION_INT_ACTION(Year, year, ToIntegerThrowOnInfinity)
// #sec-temporal-calendarmonth
CALENDAR_ABSTRACT_OPERATION_INT_ACTION(Month, month, ToPositiveInteger)
// #sec-temporal-calendarday
CALENDAR_ABSTRACT_OPERATION_INT_ACTION(Day, day, ToPositiveInteger)
// #sec-temporal-calendarmonthcode
MaybeHandle<Object> CalendarMonthCode(Isolate* isolate,
                                      Handle<JSReceiver> calendar,
                                      Handle<JSReceiver> date_like) {
  // 1. Assert: Type(calendar) is Object.
  // 2. Let result be ? Invoke(calendar, monthCode , « dateLike »).
  Handle<Object> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result,
      InvokeCalendarMethod(isolate, calendar,
                           isolate->factory()->monthCode_string(), date_like));
  /* 3. If result is undefined, throw a RangeError exception. */
  if (IsUndefined(*result)) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 4. Return ? ToString(result).
  return Object::ToString(isolate, result);
}

#ifdef V8_INTL_SUPPORT
// #sec-temporal-calendarerayear
MaybeHandle<Object> CalendarEraYear(Isolate* isolate,
                                    Handle<JSReceiver> calendar,
                                    Handle<JSReceiver> date_like) {
  // 1. Assert: Type(calendar) is Object.
  // 2. Let result be ? Invoke(calendar, eraYear , « dateLike »).
  Handle<Object> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result,
      InvokeCalendarMethod(isolate, calendar,
                           isolate->factory()->eraYear_string(), date_like));
  // 3. If result is not undefined, set result to ? ToIntegerOrInfinity(result).
  if (!IsUndefined(*result)) {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, result,
                               ToIntegerThrowOnInfinity(isolate, result));
  }
  // 4. Return result.
  return result;
}

// #sec-temporal-calendarera
MaybeHandle<Object> CalendarEra(Isolate* isolate, Handle<JSReceiver> calendar,
                                Handle<JSReceiver> date_like) {
  // 1. Assert: Type(calendar) is Object.
  // 2. Let result be ? Invoke(calendar, era , « dateLike »).
  Handle<Object> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, result,
      InvokeCalendarMethod(isolate, calendar, isolate->factory()->era_string(),
                           date_like));
  // 3. If result is not undefined, set result to ? ToString(result).
  if (!IsUndefined(*result)) {
    ASSIGN_RETURN_ON_EXCEPTION(isolate, result,
                               Object::ToString(isolate, result));
  }
  // 4. Return result.
  return result;
}

#endif  //  V8_INTL_SUPPORT

// #sec-temporal-calendardayofweek
CALENDAR_ABSTRACT_OPERATION(DayOfWeek, dayOfWeek)
// #sec-temporal-calendardayofyear
CALENDAR_ABSTRACT_OPERATION(DayOfYear, dayOfYear)
// #sec-temporal-calendarweekofyear
CALENDAR_ABSTRACT_OPERATION(WeekOfYear, weekOfYear)
// #sec-temporal-calendardaysinweek
CALENDAR_ABSTRACT_OPERATION(DaysInWeek, daysInWeek)
// #sec-temporal-calendardaysinmonth
CALENDAR_ABSTRACT_OPERATION(DaysInMonth, daysInMonth)
// #sec-temporal-calendardaysinyear
CALENDAR_ABSTRACT_OPERATION(DaysInYear, daysInYear)
// #sec-temporal-calendarmonthsinyear
CALENDAR_ABSTRACT_OPERATION(MonthsInYear, monthsInYear)
// #sec-temporal-calendarinleapyear
CALENDAR_ABSTRACT_OPERATION(InLeapYear, inLeapYear)

// #sec-temporal-getiso8601calendar
Handle<JSTemporalCalendar> GetISO8601Calendar(Isolate* isolate) {
  return CreateTemporalCalendar(isolate, isolate->factory()->iso8601_string())
      .ToHandleChecked();
}

}  // namespace temporal

namespace {

bool IsUTC(Isolate* isolate, Handle<String> time_zone) {
  // 1. Assert: Type(timeZone) is String.
  // 2. Let tzText be ! StringToCodePoints(timeZone).
  // 3. Let tzUpperText be the result of toUppercase(tzText), according to the
  // Unicode Default Case Conversion algorithm.
  // 4. Let tzUpper be ! CodePointsToString(tzUpperText).
  // 5. If tzUpper and "UTC" are the same sequence of code points, return true.
  // 6. Return false.
  if (time_zone->length() != 3) return false;
  time_zone = String::Flatten(isolate, time_zone);
  DisallowGarbageCollection no_gc;
  const String::FlatContent& flat = time_zone->GetFlatContent(no_gc);
  return (flat.Get(0) == u'U' || flat.Get(0) == u'u') &&
         (flat.Get(1) == u'T' || flat.Get(1) == u't') &&
         (flat.Get(2) == u'C' || flat.Get(2) == u'c');
}

#ifdef V8_INTL_SUPPORT
class CalendarMap final {
 public:
  CalendarMap() {
    icu::Locale locale("und");
    UErrorCode status = U_ZERO_ERROR;
    std::unique_ptr<icu::StringEnumeration> enumeration(
        icu::Calendar::getKeywordValuesForLocale("ca", locale, false, status));
    calendar_ids.push_back("iso8601");
    calendar_id_indices.insert({"iso8601", 0});
    int32_t i = 1;
    for (const char* item = enumeration->next(nullptr, status);
         U_SUCCESS(status) && item != nullptr;
         item = enumeration->next(nullptr, status)) {
      if (strcmp(item, "iso8601") != 0) {
        const char* type = uloc_toUnicodeLocaleType("ca", item);
        calendar_ids.push_back(type);
        calendar_id_indices.insert({type, i++});
      }
    }
  }
  bool Contains(const std::string& id) const {
    return calendar_id_indices.find(id) != calendar_id_indices.end();
  }

  std::string Id(int32_t index) const {
    DCHECK_LT(index, calendar_ids.size());
    return calendar_ids[index];
  }

  int32_t Index(const char* id) const {
    return calendar_id_indices.find(id)->second;
  }

 private:
  std::map<std::string, int32_t> calendar_id_indices;
  std::vector<std::string> calendar_ids;
};

DEFINE_LAZY_LEAKY_OBJECT_GETTER(CalendarMap, GetCalendarMap)

bool IsBuiltinCalendar(Isolate* isolate, Handle<String> id) {
  // 1. Let calendars be AvailableCalendars().
  // 2. If calendars contains the ASCII-lowercase of id, return true.
  // 3. Return false.
  id = Intl::ConvertToLower(isolate, String::Flatten(isolate, id))
           .ToHandleChecked();
  return GetCalendarMap()->Contains(id->ToCString().get());
}

Handle<String> CalendarIdentifier(Isolate* isolate, int32_t index) {
  return isolate->factory()->NewStringFromAsciiChecked(
      GetCalendarMap()->Id(index).c_str());
}

int32_t CalendarIndex(Isolate* isolate, Handle<String> id) {
  id = Intl::ConvertToLower(isolate, String::Flatten(isolate, id))
           .ToHandleChecked();
  return GetCalendarMap()->Index(id->ToCString().get());
}

bool IsValidTimeZoneName(Isolate* isolate, DirectHandle<String> time_zone) {
  return Intl::IsValidTimeZoneName(isolate, time_zone);
}

Handle<String> CanonicalizeTimeZoneName(Isolate* isolate,
                                        DirectHandle<String> identifier) {
  return Intl::CanonicalizeTimeZoneName(isolate, identifier).ToHandleChecked();
}

#else   // V8_INTL_SUPPORT
Handle<String> CalendarIdentifier(Isolate* isolate, int32_t index) {
  DCHECK_EQ(index, 0);
  return isolate->factory()->iso8601_string();
}

// #sec-temporal-isbuiltincalendar
bool IsBuiltinCalendar(Isolate* isolate, Handle<String> id) {
  // Note: For build without intl support, the only item in AvailableCalendars()
  // is "iso8601".
  // 1. Let calendars be AvailableCalendars().
  // 2. If calendars contains the ASCII-lowercase of id, return true.
  // 3. Return false.

  // Fast path
  if (isolate->factory()->iso8601_string()->Equals(*id)) return true;
  if (id->length() != 7) return false;
  id = String::Flatten(isolate, id);

  DisallowGarbageCollection no_gc;
  const String::FlatContent& flat = id->GetFlatContent(no_gc);
  // Return true if id is case insensitive equals to "iso8601".
  return AsciiAlphaToLower(flat.Get(0)) == 'i' &&
         AsciiAlphaToLower(flat.Get(1)) == 's' &&
         AsciiAlphaToLower(flat.Get(2)) == 'o' && flat.Get(3) == '8' &&
         flat.Get(4) == '6' && flat.Get(5) == '0' && flat.Get(6) == '1';
}

int32_t CalendarIndex(Isolate* isolate, Handle<String> id) { return 0; }
// #sec-isvalidtimezonename
bool IsValidTimeZoneName(Isolate* isolate, DirectHandle<String> time_zone) {
  return IsUTC(isolate, indirect_handle(time
```