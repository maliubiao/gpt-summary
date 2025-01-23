Response:
My thinking process to analyze the provided V8 code snippet goes like this:

1. **Understand the Request:** The core request is to analyze a specific C++ file within the V8 JavaScript engine, `v8/src/objects/js-temporal-objects.cc`. The prompt also gives hints about Torque files and relationships with JavaScript. It's part 10 of 25, suggesting this is a larger code analysis exercise.

2. **Initial Scan for Keywords:** I quickly scan the code for relevant terms like:
    * `Temporal` (repeated many times - a strong indicator of the code's purpose)
    * `Duration` (also frequent)
    * `Date`, `Month`, `Year`, `Week`, `Day` (time units)
    * `BalanceDurationRelative`, `UnbalanceDurationRelative`, `MoveRelativeDate`, `CalendarDateUntil`, `CalendarDateAdd` (function names suggesting manipulation of date/time components)
    * `Compare`, `From`, `Round` (method names indicating operations on durations)
    * `javascript` (in comments, providing crucial context)
    * Error handling related keywords like `Throw`, `RangeError`, `TypeError`

3. **Identify Core Functionality:** The frequent appearance of "Temporal" and "Duration" strongly suggests this code implements parts of the ECMAScript Temporal API related to `Temporal.Duration`. The function names further reinforce this, indicating operations for balancing, unbalancing, moving, comparing, creating, and rounding durations.

4. **Analyze Individual Code Blocks:** I start breaking down the code into logical blocks, focusing on the function definitions:

    * **`UnbalanceDurationRelative`:** This function seems to adjust a duration by converting larger units (years, months, weeks) into days, relative to a specific date and calendar. The logic involves iteratively moving forward or backward by years/months/weeks and accumulating the resulting day difference. The presence of a `calendar` object and calls to `MoveRelativeDate` are key indicators.

    * **`BalanceDurationRelative`:**  This function appears to be the inverse of `UnbalanceDurationRelative`. It takes a duration and attempts to balance the smaller units (days) into larger ones (weeks, months, years) based on a `largest_unit` and a relative date. It also uses the calendar to determine the actual number of days in a month or year.

    * **`JSTemporalDuration::Compare`:** This method compares two `Temporal.Duration` objects. It handles potential imbalances by using `UnbalanceDurationRelative` to convert both durations to a day-based representation. It also considers the time components (hours, minutes, seconds, etc.) and uses nanosecond-level precision for the final comparison. The `CalculateOffsetShift` function suggests dealing with time zone offsets if a relative date with a time zone is provided.

    * **`JSTemporalDuration::From`:** This function creates a `Temporal.Duration` object from various input types, including existing `Temporal.Duration` objects and other objects that can be converted to durations. It delegates to `ToTemporalDuration` for non-`Temporal.Duration` inputs.

    * **`JSTemporalDuration::Round`:** This is a complex function for rounding a `Temporal.Duration` to a specified unit or increment. It involves determining the smallest and largest units for rounding, validating the inputs, and using `UnbalanceDurationRelative` and `RoundDuration` (not shown in the snippet) to perform the actual rounding.

5. **Infer Relationships and Data Flow:** I connect the functions based on their calls to each other. For example, `Compare` uses `UnbalanceDurationRelative`. Both `BalanceDurationRelative` and `UnbalanceDurationRelative` interact with a `calendar` object. This helps visualize how the different parts contribute to the overall functionality.

6. **Address Specific Prompt Questions:**  I go back to the prompt and specifically address each point:

    * **Functionality:** Summarize the purpose of each function based on my analysis.
    * **Torque:** Note that the file ends in `.cc`, so it's C++, not Torque.
    * **JavaScript Relation:** Identify the connection to the ECMAScript Temporal API and provide JavaScript examples illustrating the use of `Temporal.Duration` methods that likely correspond to the analyzed C++ code.
    * **Code Logic Inference:**  Provide hypothetical inputs and outputs for key functions like `UnbalanceDurationRelative` and `BalanceDurationRelative` to demonstrate their behavior. Focus on how they convert between different time units.
    * **Common Programming Errors:**  Think about common mistakes developers might make when using the Temporal API, such as providing invalid units or not considering calendar-specific behavior.
    * **Overall Functionality (Part 10):** Combine the individual function summaries into a higher-level description of the code's role within the larger Temporal API implementation. Emphasize the core concepts like duration manipulation, comparison, and rounding.

7. **Refine and Organize:**  I organize my findings into a clear and structured format, using headings and bullet points to improve readability. I double-check for accuracy and consistency in my explanations. I ensure that the JavaScript examples accurately reflect the functionality of the C++ code.

By following these steps, I can systematically analyze the provided V8 source code snippet and provide a comprehensive and informative response that addresses all aspects of the user's request. The key is to start with a high-level understanding, break down the code into manageable parts, and then connect the pieces back together to understand the overall picture.
好的，让我们来分析一下这段 V8 源代码 `v8/src/objects/js-temporal-objects.cc` 的功能。

**功能归纳:**

这段代码片段主要实现了与 ECMAScript Temporal API 中 `Temporal.Duration` 对象相关的内部操作，特别是关于**平衡 (balancing)** 和 **非平衡 (unbalancing)** 日期部分 duration 的功能。它还包含了 `Temporal.Duration.compare` 和 `Temporal.Duration.round` 方法的部分实现。

**详细功能拆解:**

1. **`UnbalanceDurationRelative` 函数:**
   - **功能:**  该函数负责将一个包含年、月、周、日的 duration 对象转换为一个主要以天为单位的 duration，同时考虑了相对日期和日历的影响。这意味着它会将年、月、周尽可能地转换为天数。
   - **过程:**
     - 它会根据 `largest_unit` 参数决定转换到哪个最大的单位为止。例如，如果 `largest_unit` 是 "month"，则只将年转换为月，而周和日保持不变。
     - 它使用 `MoveRelativeDate` 函数来计算移动一年或一个月后，相对于给定日期的天数变化。
     - 对于 "year" 和 "month" 作为 `largest_unit` 的情况，它会使用 `CalendarDateUntil` 函数来精确计算一年或一个月包含多少个月。
   - **与 JavaScript 的关系:** 这与 JavaScript 中对 `Temporal.Duration` 对象进行诸如加减运算时，内部需要将不同单位统一起来的过程相关。

2. **`BalanceDurationRelative` 函数:**
   - **功能:**  该函数与 `UnbalanceDurationRelative` 相反，它尝试将一个主要以天为单位的 duration 平衡回包含年、月、周的表示形式。
   - **过程:**
     - 它会根据 `largest_unit` 参数决定平衡到哪个最大的单位。
     - 它使用 `MoveRelativeDate` 来计算移动一年、一个月或一周会增加多少天。
     - 它会循环地将天数转换回较大的单位，直到无法再转换为止。
     - 对于 "year" 作为 `largest_unit` 的情况，它使用 `CalendarDateUntil` 来计算一年包含多少个月，从而平衡月份。
   - **与 JavaScript 的关系:**  这与 JavaScript 中 `Temporal.Duration` 对象的规范化表示有关。例如，用户创建一个包含很多天的 duration，内部可能会将其平衡成包含一些周、一些天等更易读的形式。

3. **`JSTemporalDuration::Compare` 函数:**
   - **功能:**  实现 `Temporal.Duration.compare` 方法，用于比较两个 `Temporal.Duration` 对象的大小。
   - **过程:**
     - 它首先将两个输入转换为 `Temporal.Duration` 对象。
     - 它使用 `UnbalanceDurationRelative` 将两个 duration 都转换为以天为主要单位的形式，以便进行比较（如果 duration 中包含年、月、周）。
     - 它调用 `TotalDurationNanoseconds` 将转换后的天数以及时、分、秒、毫秒、微秒、纳秒都转换为纳秒，进行精确比较。
   - **与 JavaScript 的关系:**  直接对应 JavaScript 中 `Temporal.Duration.compare()` 方法的功能。

4. **`JSTemporalDuration::From` 函数:**
   - **功能:** 实现 `Temporal.Duration.from` 方法，用于从各种输入创建 `Temporal.Duration` 对象。
   - **过程:**
     - 如果输入已经是 `Temporal.Duration` 对象，则直接复制其内部值。
     - 否则，它会调用 `ToTemporalDuration` 将输入转换为 `Temporal.Duration` 对象。
   - **与 JavaScript 的关系:**  直接对应 JavaScript 中 `Temporal.Duration.from()` 方法的功能。

5. **`JSTemporalDuration::Round` 函数:**
   - **功能:** 实现 `Temporal.Duration.prototype.round` 方法，用于将 duration 舍入到指定的单位。
   - **过程:**
     - 它解析传入的 `roundTo` 参数，确定要舍入到的最小和最大单位，以及舍入模式。
     - 它使用 `UnbalanceDurationRelative` 将 duration 转换为以 `largestUnit` 为主要单位的形式。
     - 它调用 `RoundDuration` 函数（这段代码中未完整展示）来执行实际的舍入操作。
   - **与 JavaScript 的关系:** 直接对应 JavaScript 中 `Temporal.Duration.prototype.round()` 方法的功能。

**关于 .tq 结尾的文件:**

如果 `v8/src/objects/js-temporal-objects.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。Torque 是一种 V8 内部使用的类型安全的高级语言，用于生成高效的 C++ 代码。`.cc` 结尾表示这是一个标准的 C++ 源代码文件。**根据你的描述，它是 `.cc` 结尾，所以是 C++ 源代码。**

**与 JavaScript 的关系及示例:**

这段 C++ 代码直接实现了 JavaScript Temporal API 中 `Temporal.Duration` 对象的内部逻辑。以下是一些 JavaScript 示例，可以对应到这段 C++ 代码的功能：

```javascript
const duration1 = new Temporal.Duration(1, 2, 1, 5); // 1年 2个月 1周 5天
const duration2 = new Temporal.Duration(0, 14, 0, 12); // 14个月 12天

// 对应 UnbalanceDurationRelative 和 BalanceDurationRelative 的内部操作
// 例如，当进行加法运算时，内部会进行平衡和非平衡操作
const sum = duration1.add(duration2, { relativeTo: Temporal.PlainDate.today() });
console.log(sum); // 输出结果会是一个平衡后的 Duration

// 对应 JSTemporalDuration::Compare
const comparisonResult = Temporal.Duration.compare(duration1, duration2);
console.log(comparisonResult); // 输出 1 (duration1 大于 duration2)

// 对应 JSTemporalDuration::From
const durationFromString = Temporal.Duration.from("P1Y2M1W5D");
console.log(durationFromString);

// 对应 JSTemporalDuration::Round
const durationToRound = new Temporal.Duration(0, 0, 0, 15, 10, 30, 45, 500, 600, 700);
const roundedDuration = durationToRound.round({ smallestUnit: 'day' });
console.log(roundedDuration); // 输出一个舍入到天的 Duration
```

**代码逻辑推理 (假设输入与输出):**

**假设 `UnbalanceDurationRelative` 输入:**

- `dur`: `{ years: 1, months: 2, weeks: 1, days: 5 }`
- `largest_unit`: `"day"`
- `relative_to_obj`: 代表 2024-01-01 的 `Temporal.PlainDate` 对象
- `calendar`: 该日期的日历

**预期输出:**

函数会计算 1 年、2 个月、1 周相对于 2024-01-01 增加了多少天，并将这些天数加到原始的 5 天上。输出的 `DateDurationRecord` 将包含接近以下的值（实际天数会根据日历和闰年等因素变化）：

- `years`: 0
- `months`: 0
- `weeks`: 0
- `days`:  大约 365 + 60 (假设非闰年) + 7 + 5 = 437 天

**假设 `BalanceDurationRelative` 输入:**

- `dur`: `{ years: 0, months: 0, weeks: 0, days: 30 }`
- `largest_unit`: `"month"`
- `relative_to_obj`: 代表 2024-01-01 的 `Temporal.PlainDate` 对象
- `calendar`: 该日期的日历

**预期输出:**

函数会尝试将 30 天平衡到月份。如果从 2024-01-01 开始计算，30 天大约是一个月。输出的 `DateDurationRecord` 可能包含：

- `years`: 0
- `months`: 1
- `weeks`: 0
- `days`:  取决于该月有多少天，如果是一月份，则剩余 30 - 31 = -1 天，可能会向前借一个月，变成 0 个月，-1 + 31 = 30 天。 具体实现逻辑会更复杂，涉及到借位等。

**用户常见的编程错误:**

1. **在需要相对日期的操作中忘记提供 `relativeTo`:**  像 `UnbalanceDurationRelative` 和 `BalanceDurationRelative` 这样的函数在处理年、月等不固定长度的单位时，需要一个相对日期来确定具体的时长。如果用户在 JavaScript 中调用 `Temporal.Duration` 的相关方法时忘记提供 `relativeTo` 选项，就会导致错误。

   ```javascript
   const duration = new Temporal.Duration(1, 0, 0, 0); // 1 年
   // 错误：缺少 relativeTo，无法确定这一年具体是多少天
   // duration.addTo(Temporal.PlainDate.today());

   // 正确：提供 relativeTo
   duration.addTo(Temporal.PlainDate.today(), { relativeTo: Temporal.PlainDate.today() });
   ```

2. **假设月份总是 30 天:**  在进行 duration 计算时，新手可能会简单地将 1 个月视为 30 天。Temporal API 正确地处理了不同月份的长度差异，依赖于底层的日历系统。

   ```javascript
   const oneMonth = new Temporal.Duration(0, 1, 0, 0);
   const today = Temporal.PlainDate.from('2024-02-01');
   const nextMonth = today.add(oneMonth);
   console.log(nextMonth.toString()); // 输出 2024-03-01，正确处理了二月份的长度
   ```

3. **混淆绝对时间和相对时间的概念:**  `Temporal.Duration` 表示一段时间的长度，是相对的。而 `Temporal.PlainDate`、`Temporal.ZonedDateTime` 等表示时间上的一个确切的点。在进行 duration 的加减运算时，需要明确相对于哪个时间点。

**第 10 部分功能归纳:**

作为 25 个部分中的第 10 部分，这段代码主要负责 `Temporal.Duration` 对象中与日期部分（年、月、周、日）的平衡、非平衡以及比较操作相关的核心逻辑实现。它确保了在进行 duration 运算时，能够正确地处理不同时间单位之间的转换，并考虑了日历的影响。此外，它还包含了创建和舍入 duration 的初步实现。可以认为这是 `Temporal.Duration` 实现中至关重要的一部分，涉及到其基本运算的正确性。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第10部分，共25部分，请归纳一下它的功能
```

### 源代码
```cpp
i. Perform ! CreateDataPropertyOrThrow(untilOptions, "largestUnit",
      // "month").
      CHECK(JSReceiver::CreateDataProperty(
                isolate, until_options, factory->largestUnit_string(),
                factory->month_string(), Just(kThrowOnError))
                .FromJust());
      // iv. Let untilResult be ? CalendarDateUntil(calendar, relativeTo,
      // newRelativeTo, untilOptions, dateUntil).
      Handle<JSTemporalDuration> until_result;
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, until_result,
          CalendarDateUntil(isolate, calendar, relative_to, new_relative_to,
                            until_options, date_until),
          Nothing<DateDurationRecord>());
      // v. Let oneYearMonths be untilResult.[[Months]].
      double one_year_months = Object::NumberValue(until_result->months());
      // vi. Set relativeTo to newRelativeTo.
      relative_to = new_relative_to;
      // vii. Set years to years − sign.
      result.years -= sign;
      // viii. Set months to months + oneYearMonths.
      result.months += one_year_months;
    }
    // 10. Else if largestUnit is "week", then
  } else if (largest_unit == Unit::kWeek) {
    // a. If calendar is undefined, then
    if (calendar.is_null()) {
      // i. Throw a RangeError exception.
      THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                   NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                   Nothing<DateDurationRecord>());
    }
    // b. Repeat, while years ≠ 0,
    while (result.years != 0) {
      // i. Let moveResult be ? MoveRelativeDate(calendar, relativeTo, oneYear).
      MoveRelativeDateResult move_result;
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar, relative_to, one_year,
                           method_name),
          Nothing<DateDurationRecord>());
      // ii. Set relativeTo to moveResult.[[RelativeTo]].
      relative_to = move_result.relative_to;
      // iii. Set days to days + moveResult.[[Days]].
      result.days += move_result.days;
      // iv. Set years to years - sign.
      result.years -= sign;
    }
    // c. Repeat, while months ≠ 0,
    while (result.months != 0) {
      // i. Let moveResult be ? MoveRelativeDate(calendar, relativeTo,
      // oneMonth).
      MoveRelativeDateResult move_result;
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar, relative_to, one_month,
                           method_name),
          Nothing<DateDurationRecord>());
      // ii. Set relativeTo to moveResult.[[RelativeTo]].
      relative_to = move_result.relative_to;
      // iii. Set days to days + moveResult.[[Days]].
      result.days += move_result.days;
      // iv. Set months to months - sign.
      result.months -= sign;
    }
    // 11. Else,
  } else {
    // a. If any of years, months, and weeks are not zero, then
    if ((result.years != 0) || (result.months != 0) || (result.weeks != 0)) {
      // i. If calendar is undefined, then
      if (calendar.is_null()) {
        // i. Throw a RangeError exception.
        THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                     NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                     Nothing<DateDurationRecord>());
      }
      // b. Repeat, while years ≠ 0,
      while (result.years != 0) {
        // i. Let moveResult be ? MoveRelativeDate(calendar, relativeTo,
        // oneYear).
        MoveRelativeDateResult move_result;
        MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, move_result,
            MoveRelativeDate(isolate, calendar, relative_to, one_year,
                             method_name),
            Nothing<DateDurationRecord>());
        // ii. Set relativeTo to moveResult.[[RelativeTo]].
        relative_to = move_result.relative_to;
        // iii. Set days to days + moveResult.[[Days]].
        result.days += move_result.days;
        // iv. Set years to years - sign.
        result.years -= sign;
      }
      // c. Repeat, while months ≠ 0,
      while (result.months != 0) {
        // i. Let moveResult be ? MoveRelativeDate(calendar, relativeTo,
        // oneMonth).
        MoveRelativeDateResult move_result;
        MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, move_result,
            MoveRelativeDate(isolate, calendar, relative_to, one_month,
                             method_name),
            Nothing<DateDurationRecord>());
        // ii. Set relativeTo to moveResult.[[RelativeTo]].
        relative_to = move_result.relative_to;
        // iii. Set days to days + moveResult.[[Days]].
        result.days += move_result.days;
        // iv. Set months to years - sign.
        result.months -= sign;
      }
      // d. Repeat, while weeks ≠ 0,
      while (result.weeks != 0) {
        // i. Let moveResult be ? MoveRelativeDate(calendar, relativeTo,
        // oneWeek).
        MoveRelativeDateResult move_result;
        MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, move_result,
            MoveRelativeDate(isolate, calendar, relative_to, one_week,
                             method_name),
            Nothing<DateDurationRecord>());
        // ii. Set relativeTo to moveResult.[[RelativeTo]].
        relative_to = move_result.relative_to;
        // iii. Set days to days + moveResult.[[Days]].
        result.days += move_result.days;
        // iv. Set weeks to years - sign.
        result.weeks -= sign;
      }
    }
  }
  // 12. Return ? CreateDateDurationRecord(years, months, weeks, days).
  return DateDurationRecord::Create(isolate, result.years, result.months,
                                    result.weeks, result.days);
}

// #sec-temporal-balancedurationrelative
Maybe<DateDurationRecord> BalanceDurationRelative(
    Isolate* isolate, const DateDurationRecord& dur, Unit largest_unit,
    Handle<Object> relative_to_obj, const char* method_name) {
  TEMPORAL_ENTER_FUNC();

  Factory* factory = isolate->factory();
  // 1. If largestUnit is not one of "year", "month", or "week", or years,
  // months, weeks, and days are all 0, then

  if ((largest_unit != Unit::kYear && largest_unit != Unit::kMonth &&
       largest_unit != Unit::kWeek) ||
      (dur.years == 0 && dur.months == 0 && dur.weeks == 0 && dur.days == 0)) {
    // a. Return ! CreateDateDurationRecord(years, months, weeks, days).
    return Just(DateDurationRecord::Create(isolate, dur.years, dur.months,
                                           dur.weeks, dur.days)
                    .ToChecked());
  }
  // 2. If relativeTo is undefined, then
  if (IsUndefined(*relative_to_obj)) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR_RETURN_VALUE(isolate,
                                 NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR(),
                                 Nothing<DateDurationRecord>());
  }

  // 3. Let sign be ! DurationSign(years, months, weeks, days, 0, 0, 0, 0, 0,
  // 0).
  double sign = DurationRecord::Sign(
      {dur.years, dur.months, dur.weeks, {dur.days, 0, 0, 0, 0, 0, 0}});
  // 4. Assert: sign ≠ 0.
  DCHECK_NE(sign, 0);
  // 5. Let oneYear be ! CreateTemporalDuration(sign, 0, 0, 0, 0, 0, 0, 0, 0,
  // 0).
  Handle<JSTemporalDuration> one_year =
      CreateTemporalDuration(isolate, {sign, 0, 0, {0, 0, 0, 0, 0, 0, 0}})
          .ToHandleChecked();
  // 6. Let oneMonth be ! CreateTemporalDuration(0, sign, 0, 0, 0, 0, 0, 0, 0,
  // 0).
  Handle<JSTemporalDuration> one_month =
      CreateTemporalDuration(isolate, {0, sign, 0, {0, 0, 0, 0, 0, 0, 0}})
          .ToHandleChecked();
  // 7. Let oneWeek be ! CreateTemporalDuration(0, 0, sign, 0, 0, 0, 0, 0, 0,
  // 0).
  Handle<JSTemporalDuration> one_week =
      CreateTemporalDuration(isolate, {0, 0, sign, {0, 0, 0, 0, 0, 0, 0}})
          .ToHandleChecked();
  // 8. Set relativeTo to ? ToTemporalDate(relativeTo).
  Handle<JSTemporalPlainDate> relative_to;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, relative_to,
      ToTemporalDate(isolate, relative_to_obj, method_name),
      Nothing<DateDurationRecord>());
  // 9. Let calendar be relativeTo.[[Calendar]].
  Handle<JSReceiver> calendar(relative_to->calendar(), isolate);

  DateDurationRecord result = dur;
  // 10.  If largestUnit is "year", then
  if (largest_unit == Unit::kYear) {
    // a. Let moveResult be ? MoveRelativeDate(calendar, relativeTo, oneYear).
    MoveRelativeDateResult move_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, move_result,
        MoveRelativeDate(isolate, calendar, relative_to, one_year, method_name),
        Nothing<DateDurationRecord>());
    // b. Let newRelativeTo be moveResult.[[RelativeTo]].
    Handle<JSTemporalPlainDate> new_relative_to = move_result.relative_to;
    // c. Let oneYearDays be moveResult.[[Days]].
    double one_year_days = move_result.days;
    // d. Repeat, while abs(days) ≥ abs(oneYearDays),
    while (std::abs(result.days) >= std::abs(one_year_days)) {
      // i. Set days to days - oneYearDays.
      result.days -= one_year_days;
      // ii. Set years to years + sign.
      result.years += sign;
      // iii. Set relativeTo to newRelativeTo.
      relative_to = new_relative_to;
      // iv. Set moveResult to ? MoveRelativeDate(calendar, relativeTo,
      // oneYear).
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar, relative_to, one_year,
                           method_name),
          Nothing<DateDurationRecord>());

      // iv. Set newRelativeTo to moveResult.[[RelativeTo]].
      new_relative_to = move_result.relative_to;
      // v. Set oneYearDays to moveResult.[[Days]].
      one_year_days = move_result.days;
    }
    // e. Set moveResult to ? MoveRelativeDate(calendar, relativeTo, oneMonth).
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, move_result,
        MoveRelativeDate(isolate, calendar, relative_to, one_month,
                         method_name),
        Nothing<DateDurationRecord>());
    // f. Set newRelativeTo to moveResult.[[RelativeTo]].
    new_relative_to = move_result.relative_to;
    // g. Let oneMonthDays be moveResult.[[Days]].
    double one_month_days = move_result.days;
    // h. Repeat, while abs(days) ≥ abs(oneMonthDays),
    while (std::abs(result.days) >= std::abs(one_month_days)) {
      // i. Set days to days - oneMonthDays.
      result.days -= one_month_days;
      // ii. Set months to months + sign.
      result.months += sign;
      // iii. Set relativeTo to newRelativeTo.
      relative_to = new_relative_to;
      // iv. Set moveResult to ? MoveRelativeDate(calendar, relativeTo,
      // oneMonth).
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar, relative_to, one_month,
                           method_name),
          Nothing<DateDurationRecord>());
      // iv. Set newRrelativeTo to moveResult.[[RelativeTo]].
      new_relative_to = move_result.relative_to;
      // v. Set oneMonthDays to moveResult.[[Days]].
      one_month_days = move_result.days;
    }
    // i. Let dateAdd be ? GetMethod(calendar, "dateAdd").
    Handle<Object> date_add;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, date_add,
        Object::GetMethod(isolate, calendar, factory->dateAdd_string()),
        Nothing<DateDurationRecord>());
    // j. Set newRelativeTo be ? CalendarDateAdd(calendar, relativeTo, oneYear,
    // undefined, dateAdd).
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, new_relative_to,
        CalendarDateAdd(isolate, calendar, relative_to, one_year,
                        factory->undefined_value(), date_add),
        Nothing<DateDurationRecord>());
    // k. Let dateUntil be ? GetMethod(calendar, "dateUntil").
    Handle<Object> date_until;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, date_until,
        Object::GetMethod(isolate, calendar, factory->dateUntil_string()),
        Nothing<DateDurationRecord>());
    // l. Let untilOptions be OrdinaryObjectCreate(null).
    Handle<JSObject> until_options = factory->NewJSObjectWithNullProto();
    // m. Perform ! CreateDataPropertyOrThrow(untilOptions, "largestUnit",
    // "month").
    CHECK(JSReceiver::CreateDataProperty(
              isolate, until_options, factory->largestUnit_string(),
              factory->month_string(), Just(kThrowOnError))
              .FromJust());
    // n. Let untilResult be ? CalendarDateUntil(calendar, relativeTo,
    // newRelativeTo, untilOptions, dateUntil).
    Handle<JSTemporalDuration> until_result;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, until_result,
        CalendarDateUntil(isolate, calendar, relative_to, new_relative_to,
                          until_options, date_until),
        Nothing<DateDurationRecord>());
    // o. Let oneYearMonths be untilResult.[[Months]].
    double one_year_months = Object::NumberValue(until_result->months());
    // p. Repeat, while abs(months) ≥ abs(oneYearMonths),
    while (std::abs(result.months) >= std::abs(one_year_months)) {
      // i. Set months to months - oneYearMonths.
      result.months -= one_year_months;
      // ii. Set years to years + sign.
      result.years += sign;
      // iii. Set relativeTo to newRelativeTo.
      relative_to = new_relative_to;
      // iv. Set newRelativeTo to ? CalendarDateAdd(calendar, relativeTo,
      // oneYear, undefined, dateAdd).
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, new_relative_to,
          CalendarDateAdd(isolate, calendar, relative_to, one_year,
                          factory->undefined_value(), date_add),
          Nothing<DateDurationRecord>());
      // v. Set untilOptions to OrdinaryObjectCreate(null).
      until_options = factory->NewJSObjectWithNullProto();
      // vi. Perform ! CreateDataPropertyOrThrow(untilOptions, "largestUnit",
      // "month").
      CHECK(JSReceiver::CreateDataProperty(
                isolate, until_options, factory->largestUnit_string(),
                factory->month_string(), Just(kThrowOnError))
                .FromJust());
      // vii. Set untilResult to ? CalendarDateUntil(calendar, relativeTo,
      // newRelativeTo, untilOptions, dateUntil).
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, until_result,
          CalendarDateUntil(isolate, calendar, relative_to, new_relative_to,
                            until_options, date_until),
          Nothing<DateDurationRecord>());
      // viii. Set oneYearMonths to untilResult.[[Months]].
      one_year_months = Object::NumberValue(until_result->months());
    }
    // 11. Else if largestUnit is "month", then
  } else if (largest_unit == Unit::kMonth) {
    // a. Let moveResult be ? MoveRelativeDate(calendar, relativeTo, oneMonth).
    MoveRelativeDateResult move_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, move_result,
        MoveRelativeDate(isolate, calendar, relative_to, one_month,
                         method_name),
        Nothing<DateDurationRecord>());
    // b. Let newRelativeTo be moveResult.[[RelativeTo]].
    Handle<JSTemporalPlainDate> new_relative_to = move_result.relative_to;
    // c. Let oneMonthDays be moveResult.[[Days]].
    double one_month_days = move_result.days;
    // d. Repeat, while abs(days) ≥ abs(oneMonthDays),
    while (std::abs(result.days) >= std::abs(one_month_days)) {
      // i. Set days to days - oneMonthDays.
      result.days -= one_month_days;
      // ii. Set months to months + sign.
      result.months += sign;
      // iii. Set relativeTo to newRelativeTo.
      relative_to = new_relative_to;
      // iv. Set moveResult to ? MoveRelativeDate(calendar, relativeTo,
      // oneMonth).
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar, relative_to, one_month,
                           method_name),
          Nothing<DateDurationRecord>());
      // v. Set newRelativeTo to moveResult.[[RelativeTo]].
      new_relative_to = move_result.relative_to;
      // vi. Set oneMonthDays to moveResult.[[Days]].
      one_month_days = move_result.days;
    }
    // 12. Else
  } else {
    // a. Assert: largestUnit is "week".
    DCHECK_EQ(largest_unit, Unit::kWeek);
    // b. Let moveResult be ? MoveRelativeDate(calendar, relativeTo, oneWeek).
    MoveRelativeDateResult move_result;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, move_result,
        MoveRelativeDate(isolate, calendar, relative_to, one_week, method_name),
        Nothing<DateDurationRecord>());
    // c. Let newRelativeTo be moveResult.[[RelativeTo]].
    Handle<JSTemporalPlainDate> new_relative_to = move_result.relative_to;
    // d. Let oneWeekDays be moveResult.[[Days]].
    double one_week_days = move_result.days;
    // e. Repeat, while abs(days) ≥ abs(oneWeekDays),
    while (std::abs(result.days) >= std::abs(one_week_days)) {
      // i. Set days to days - oneWeekDays.
      result.days -= one_week_days;
      // ii. Set weeks to weeks + sign.
      result.weeks += sign;
      // iii. Set relativeTo to newRelativeTo.
      relative_to = new_relative_to;
      // v. Set moveResult to ? MoveRelativeDate(calendar, relativeTo,
      // oneWeek).
      MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, move_result,
          MoveRelativeDate(isolate, calendar, relative_to, one_week,
                           method_name),
          Nothing<DateDurationRecord>());
      // v. Set newRelativeTo to moveResult.[[RelativeTo]].
      new_relative_to = move_result.relative_to;
      // vi. Set oneWeekDays to moveResult.[[Days]].
      one_week_days = move_result.days;
    }
  }
  // 12. Return ? CreateDateDurationRecord(years, months, weeks, days).
  return DateDurationRecord::Create(isolate, result.years, result.months,
                                    result.weeks, result.days);
}

}  // namespace

// #sec-temporal.duration.compare
MaybeHandle<Smi> JSTemporalDuration::Compare(Isolate* isolate,
                                             Handle<Object> one_obj,
                                             Handle<Object> two_obj,
                                             Handle<Object> options_obj) {
  const char* method_name = "Temporal.Duration.compare";
  // 1. Set one to ? ToTemporalDuration(one).
  Handle<JSTemporalDuration> one;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, one,
      temporal::ToTemporalDuration(isolate, one_obj, method_name));
  // 2. Set two to ? ToTemporalDuration(two).
  Handle<JSTemporalDuration> two;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, two,
      temporal::ToTemporalDuration(isolate, two_obj, method_name));
  // 3. Set options to ? GetOptionsObject(options).
  Handle<JSReceiver> options;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, options, GetOptionsObject(isolate, options_obj, method_name));
  // 4. Let relativeTo be ? ToRelativeTemporalObject(options).
  Handle<Object> relative_to;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, relative_to,
      ToRelativeTemporalObject(isolate, options, method_name));
  // 5. LetCalculateOffsetShift shift1 be ? CalculateOffsetShift(relativeTo,
  // one.[[Years]], one.[[Months]], one.[[Weeks]], one.[[Days]]).
  int64_t shift1;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, shift1,
      CalculateOffsetShift(
          isolate, relative_to,
          {Object::NumberValue(one->years()),
           Object::NumberValue(one->months()),
           Object::NumberValue(one->weeks()), Object::NumberValue(one->days())},
          method_name),
      Handle<Smi>());
  // 6. Let shift2 be ? CalculateOffsetShift(relativeTo, two.[[Years]],
  // two.[[Months]], two.[[Weeks]], two.[[Days]]).
  int64_t shift2;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, shift2,
      CalculateOffsetShift(
          isolate, relative_to,
          {Object::NumberValue(two->years()),
           Object::NumberValue(two->months()),
           Object::NumberValue(two->weeks()), Object::NumberValue(two->days())},
          method_name),
      Handle<Smi>());
  // 7. If any of one.[[Years]], two.[[Years]], one.[[Months]], two.[[Months]],
  // one.[[Weeks]], or two.[[Weeks]] are not 0, then
  double days1, days2;
  if (Object::NumberValue(one->years()) != 0 ||
      Object::NumberValue(two->years()) != 0 ||
      Object::NumberValue(one->months()) != 0 ||
      Object::NumberValue(two->months()) != 0 ||
      Object::NumberValue(one->weeks()) != 0 ||
      Object::NumberValue(two->weeks()) != 0) {
    // a. Let unbalanceResult1 be ? UnbalanceDurationRelative(one.[[Years]],
    // one.[[Months]], one.[[Weeks]], one.[[Days]], "day", relativeTo).
    DateDurationRecord unbalance_result1;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, unbalance_result1,
        UnbalanceDurationRelative(isolate,
                                  {Object::NumberValue(one->years()),
                                   Object::NumberValue(one->months()),
                                   Object::NumberValue(one->weeks()),
                                   Object::NumberValue(one->days())},
                                  Unit::kDay, relative_to, method_name),
        Handle<Smi>());
    // b. Let unbalanceResult2 be ? UnbalanceDurationRelative(two.[[Years]],
    // two.[[Months]], two.[[Weeks]], two.[[Days]], "day", relativeTo).
    DateDurationRecord unbalance_result2;
    MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, unbalance_result2,
        UnbalanceDurationRelative(isolate,
                                  {Object::NumberValue(two->years()),
                                   Object::NumberValue(two->months()),
                                   Object::NumberValue(two->weeks()),
                                   Object::NumberValue(two->days())},
                                  Unit::kDay, relative_to, method_name),
        Handle<Smi>());
    // c. Let days1 be unbalanceResult1.[[Days]].
    days1 = unbalance_result1.days;
    // d. Let days2 be unbalanceResult2.[[Days]].
    days2 = unbalance_result2.days;
    // 8. Else,
  } else {
    // a. Let days1 be one.[[Days]].
    days1 = Object::NumberValue(one->days());
    // b. Let days2 be two.[[Days]].
    days2 = Object::NumberValue(two->days());
  }
  // 9. Let ns1 be ! TotalDurationNanoseconds(days1, one.[[Hours]],
  // one.[[Minutes]], one.[[Seconds]], one.[[Milliseconds]],
  // one.[[Microseconds]], one.[[Nanoseconds]], shift1).
  DirectHandle<BigInt> ns1 = TotalDurationNanoseconds(
      isolate,
      {days1, Object::NumberValue(one->hours()),
       Object::NumberValue(one->minutes()), Object::NumberValue(one->seconds()),
       Object::NumberValue(one->milliseconds()),
       Object::NumberValue(one->microseconds()),
       Object::NumberValue(one->nanoseconds())},
      shift1);
  // 10. Let ns2 be ! TotalDurationNanoseconds(days2, two.[[Hours]],
  // two.[[Minutes]], two.[[Seconds]], two.[[Milliseconds]],
  // two.[[Microseconds]], two.[[Nanoseconds]], shift2).
  DirectHandle<BigInt> ns2 = TotalDurationNanoseconds(
      isolate,
      {days2, Object::NumberValue(two->hours()),
       Object::NumberValue(two->minutes()), Object::NumberValue(two->seconds()),
       Object::NumberValue(two->milliseconds()),
       Object::NumberValue(two->microseconds()),
       Object::NumberValue(two->nanoseconds())},
      shift2);
  switch (BigInt::CompareToBigInt(ns1, ns2)) {
    // 11. If ns1 > ns2, return 1𝔽.
    case ComparisonResult::kGreaterThan:
      return handle(Smi::FromInt(1), isolate);
    // 12. If ns1 < ns2, return -1𝔽.
    case ComparisonResult::kLessThan:
      return handle(Smi::FromInt(-1), isolate);
    // 13. Return +0𝔽.
    default:
      return handle(Smi::FromInt(0), isolate);
  }
}

// #sec-temporal.duration.from
MaybeHandle<JSTemporalDuration> JSTemporalDuration::From(Isolate* isolate,
                                                         Handle<Object> item) {
  //  1. If Type(item) is Object and item has an [[InitializedTemporalDuration]]
  //  internal slot, then
  if (IsJSTemporalDuration(*item)) {
    // a. Return ? CreateTemporalDuration(item.[[Years]], item.[[Months]],
    // item.[[Weeks]], item.[[Days]], item.[[Hours]], item.[[Minutes]],
    // item.[[Seconds]], item.[[Milliseconds]], item.[[Microseconds]],
    // item.[[Nanoseconds]]).
    auto duration = Cast<JSTemporalDuration>(item);
    return CreateTemporalDuration(
        isolate, {Object::NumberValue(duration->years()),
                  Object::NumberValue(duration->months()),
                  Object::NumberValue(duration->weeks()),
                  {Object::NumberValue(duration->days()),
                   Object::NumberValue(duration->hours()),
                   Object::NumberValue(duration->minutes()),
                   Object::NumberValue(duration->seconds()),
                   Object::NumberValue(duration->milliseconds()),
                   Object::NumberValue(duration->microseconds()),
                   Object::NumberValue(duration->nanoseconds())}});
  }
  // 2. Return ? ToTemporalDuration(item).
  return temporal::ToTemporalDuration(isolate, item, "Temporal.Duration.from");
}

namespace {
// #sec-temporal-maximumtemporaldurationroundingincrement
struct Maximum {
  bool defined;
  double value;
};
Maximum MaximumTemporalDurationRoundingIncrement(Unit unit);
// #sec-temporal-totemporalroundingincrement
Maybe<double> ToTemporalRoundingIncrement(Isolate* isolate,
                                          Handle<JSReceiver> normalized_options,
                                          double dividend,
                                          bool dividend_is_defined,
                                          bool inclusive);

// #sec-temporal-moverelativezoneddatetime
MaybeHandle<JSTemporalZonedDateTime> MoveRelativeZonedDateTime(
    Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
    const DateDurationRecord& duration, const char* method_name);

// #sec-temporal-roundduration
Maybe<DurationRecordWithRemainder> RoundDuration(Isolate* isolate,
                                                 const DurationRecord& duration,
                                                 double increment, Unit unit,
                                                 RoundingMode rounding_mode,
                                                 Handle<Object> relative_to,
                                                 const char* method_name);
}  // namespace

// #sec-temporal.duration.prototype.round
MaybeHandle<JSTemporalDuration> JSTemporalDuration::Round(
    Isolate* isolate, DirectHandle<JSTemporalDuration> duration,
    Handle<Object> round_to_obj) {
  const char* method_name = "Temporal.Duration.prototype.round";
  Factory* factory = isolate->factory();
  // 1. Let duration be the this value.
  // 2. Perform ? RequireInternalSlot(duration,
  // [[InitializedTemporalDuration]]).
  // 3. If roundTo is undefined, then
  if (IsUndefined(*round_to_obj)) {
    // a. Throw a TypeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_TYPE_ERROR());
  }
  Handle<JSReceiver> round_to;
  // 4. If Type(roundTo) is String, then
  if (IsString(*round_to_obj)) {
    // a. Let paramString be roundTo.
    Handle<String> param_string = Cast<String>(round_to_obj);
    // b. Set roundTo to ! OrdinaryObjectCreate(null).
    round_to = factory->NewJSObjectWithNullProto();
    // c. Perform ! CreateDataPropertyOrThrow(roundTo, "_smallestUnit_",
    // paramString).
    CHECK(JSReceiver::CreateDataProperty(isolate, round_to,
                                         factory->smallestUnit_string(),
                                         param_string, Just(kThrowOnError))
              .FromJust());
  } else {
    // a. Set roundTo to ? GetOptionsObject(roundTo).
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate, round_to,
        GetOptionsObject(isolate, round_to_obj, method_name));
  }
  // 6. Let smallestUnitPresent be true.
  bool smallest_unit_present = true;
  // 7. Let largestUnitPresent be true.
  bool largest_unit_present = true;
  // 8. Let smallestUnit be ? GetTemporalUnit(roundTo, "smallestUnit", datetime,
  // undefined).
  Unit smallest_unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, smallest_unit,
      GetTemporalUnit(isolate, round_to, "smallestUnit", UnitGroup::kDateTime,
                      Unit::kNotPresent, false, method_name),
      Handle<JSTemporalDuration>());
  // 9. If smallestUnit is undefined, then
  if (smallest_unit == Unit::kNotPresent) {
    // a. Set smallestUnitPresent to false.
    smallest_unit_present = false;
    // b. Set smallestUnit to "nanosecond".
    smallest_unit = Unit::kNanosecond;
  }
  // 10. Let defaultLargestUnit be !
  // DefaultTemporalLargestUnit(duration.[[Years]], duration.[[Months]],
  // duration.[[Weeks]], duration.[[Days]], duration.[[Hours]],
  // duration.[[Minutes]], duration.[[Seconds]], duration.[[Milliseconds]],
  // duration.[[Microseconds]]).
  Unit default_largest_unit = DefaultTemporalLargestUnit(
      {Object::NumberValue(duration->years()),
       Object::NumberValue(duration->months()),
       Object::NumberValue(duration->weeks()),
       {Object::NumberValue(duration->days()),
        Object::NumberValue(duration->hours()),
        Object::NumberValue(duration->minutes()),
        Object::NumberValue(duration->seconds()),
        Object::NumberValue(duration->milliseconds()),
        Object::NumberValue(duration->microseconds()),
        Object::NumberValue(duration->nanoseconds())}});

  // 11. Set defaultLargestUnit to !
  // LargerOfTwoTemporalUnits(defaultLargestUnit, smallestUnit).
  default_largest_unit =
      LargerOfTwoTemporalUnits(default_largest_unit, smallest_unit);
  // 12. Let largestUnit be ? GetTemporalUnit(roundTo, "largestUnit", datetime,
  // undefined, « "auto" »).
  Unit largest_unit;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, largest_unit,
      GetTemporalUnit(isolate, round_to, "largestUnit", UnitGroup::kDateTime,
                      Unit::kNotPresent, false, method_name, Unit::kAuto),
      Handle<JSTemporalDuration>());
  // 13. If largestUnit is undefined, then
  if (largest_unit == Unit::kNotPresent) {
    // a. Set largestUnitPresent to false.
    largest_unit_present = false;
    // b. Set largestUnit to defaultLargestUnit.
    largest_unit = default_largest_unit;
    // 14. Else if largestUnit is "auto", then
  } else if (largest_unit == Unit::kAuto) {
    // a. Set largestUnit to defaultLargestUnit.
    largest_unit = default_largest_unit;
  }
  // 15. If smallestUnitPresent is false and largestUnitPresent is false, then
  if (!smallest_unit_present && !largest_unit_present) {
    // a. Throw a RangeError exception.
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 16. If LargerOfTwoTemporalUnits(largestUnit, smallestUnit) is not
  // largestUnit, throw a RangeError exception.
  if (LargerOfTwoTemporalUnits(largest_unit, smallest_unit) != largest_unit) {
    THROW_NEW_ERROR(isolate, NEW_TEMPORAL_INVALID_ARG_RANGE_ERROR());
  }
  // 17. Let roundingMode be ? ToTemporalRoundingMode(roundTo, "halfExpand").
  RoundingMode rounding_mode;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_mode,
      ToTemporalRoundingMode(isolate, round_to, RoundingMode::kHalfExpand,
                             method_name),
      Handle<JSTemporalDuration>());
  // 18. Let maximum be !
  // MaximumTemporalDurationRoundingIncrement(smallestUnit).
  Maximum maximum = MaximumTemporalDurationRoundingIncrement(smallest_unit);

  // 19. Let roundingIncrement be ? ToTemporalRoundingIncrement(roundTo,
  // maximum, false).
  double rounding_increment;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, rounding_increment,
      ToTemporalRoundingIncrement(isolate, round_to, maximum.value,
                                  maximum.defined, false),
      Handle<JSTemporalDuration>());
  // 20. Let relativeTo be ? ToRelativeTemporalObject(roundTo).
  Handle<Object> relative_to;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, relative_to,
      ToRelativeTemporalObject(isolate, round_to, method_name));
  // 21. Let unbalanceResult be ? UnbalanceDurationRelative(duration.[[Years]],
  // duration.[[Months]], duration.[[Weeks]], duration.[[Days]], largestUnit,
  // relativeTo).
  DateDurationRecord unbalance_result;
  MAYBE_ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, unbalance_result,
      UnbalanceDurationRelative(isolate,
                                {Object::NumberValue(duration->years()),
                                 Object::NumberValue(duration-
```