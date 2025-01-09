Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/builtins/builtins-definitions.h`. This file seems to define a list of built-in functions for V8, the JavaScript engine used in Chrome and Node.js.

Here's a breakdown of how to address each point:

1. **Functionality:** The core purpose is defining and enumerating built-in functions. Each line seems to define a specific built-in, likely linking a C++ implementation with its JavaScript counterpart.

2. **.tq extension:** The user is correctly inferring that if the file had a `.tq` extension, it would be related to Torque, V8's internal language for defining built-ins. Since it's `.h`, it's a C++ header file.

3. **Relationship to JavaScript:** The defined built-ins directly correspond to JavaScript functionalities, especially those related to the `Temporal` API for date and time manipulation.

4. **JavaScript Examples:**  Provide clear examples showing how the listed built-ins are used in JavaScript. Focus on the `Temporal` API.

5. **Code Logic/Assumptions:** The provided snippet is declarative, defining the built-ins. There's no explicit logic to trace with inputs and outputs *within this snippet*. The logic resides in the *implementation* of these built-ins in other C++ or Torque files. Therefore, focus on the *purpose* of each defined built-in.

6. **Common Programming Errors:**  Illustrate typical mistakes developers might make when using the `Temporal` API, like incorrect formatting or misunderstanding time zones.

7. **Part 5 of 6:** Acknowledge the context and ensure the summary aligns with the content provided in this specific part. This part focuses heavily on the `Temporal` API.

**Mental Sandbox Simulation:**

Imagine this file as a table of contents for V8's built-in functions. Each entry points to the actual code that makes that function work. For example, `TemporalZonedDateTimePrototypeAdd` in this file doesn't *add* time to a `ZonedDateTime`, but it *declares* that there's a function that does that. The actual addition logic is elsewhere. The macros like `CPP` are likely used to generate boilerplate code or register these built-ins within the V8 engine.

For the JavaScript examples, I need to pick representative functions from the list, like `TemporalZonedDateTime.prototype.add()` or `TemporalDuration.compare()`.

Regarding common errors, I can think of scenarios like:

* Trying to use `Date` methods for `Temporal` objects (or vice-versa).
* Incorrectly parsing date/time strings.
* Not handling time zones correctly.

The summary should emphasize the role of this file in defining built-in functions, specifically for the `Temporal` API.

Strategizing complete. I will now generate the response based on these considerations.
## 功能归纳：v8/src/builtins/builtins-definitions.h (第 5/6 部分)

这个代码片段是 `v8/src/builtins/builtins-definitions.h` 文件的一部分，它是一个 C++ 头文件，用于**定义和声明 V8 JavaScript 引擎的内置函数 (built-ins)**。

**主要功能：**

1. **声明内置函数：**  这个文件使用宏 (`CPP`, `TFJ`) 来声明一系列的内置函数。每一行定义了一个特定的内置函数，通常对应 JavaScript 中全局对象或原型对象上的方法。

2. **关联 C++ 实现：**  宏 `CPP`  表明这些内置函数是用 C++ 实现的。宏的第一个参数 (例如 `TemporalZonedDateTimePrototypeAdd`) 通常对应 C++ 中实现该功能的函数名。

3. **指定参数处理方式：** 像 `kDontAdaptArgumentsSentinel` 和 `JSParameterCount(0)` 这样的参数用于指定 V8 如何处理传递给这些内置函数的参数。`kDontAdaptArgumentsSentinel` 通常意味着按原样传递参数，而 `JSParameterCount(0)` 指示该函数不期望接收任何 JavaScript 参数。

4. **与 JavaScript 功能的映射：**  这个代码片段主要定义了与 **ECMAScript Temporal API** 相关的内置函数。Temporal API 是 JavaScript 中用于处理日期和时间的新标准。 例如，`TemporalZonedDateTimePrototypeAdd` 对应于 `Temporal.ZonedDateTime.prototype.add` 方法。

**关于文件扩展名和 Torque：**

你提供的代码片段是 C++ 头文件 (`.h`)。 如果 `v8/src/builtins/builtins-definitions.h` 以 `.tq` 结尾，那么它确实会是一个 V8 Torque 源代码文件。 Torque 是 V8 专门用于定义内置函数的领域特定语言，它提供了更高级的抽象和类型安全。

**与 JavaScript 功能的关系及举例：**

这个代码片段中定义的大部分内置函数都与 JavaScript 的 **Temporal API** 直接相关。Temporal API 旨在解决 JavaScript 中现有的 `Date` 对象的一些问题，提供更强大、更易用的日期和时间处理能力。

**JavaScript 示例：**

```javascript
// 使用 Temporal.ZonedDateTime.prototype.add 添加时间
const zonedDateTime = Temporal.ZonedDateTime.from('2023-10-27T10:00:00+08:00[Asia/Shanghai]');
const later = zonedDateTime.add({ hours: 2 });
console.log(later.toString()); // 输出类似：2023-10-27T12:00:00+08:00[Asia/Shanghai]

// 使用 Temporal.Duration.compare 比较两个 Duration
const duration1 = new Temporal.Duration(1, 2, 0, 5); // 1年2个月5天
const duration2 = new Temporal.Duration(1, 1, 0, 10); // 1年1个月10天
const comparisonResult = Temporal.Duration.compare(duration1, duration2);
console.log(comparisonResult); // 输出 1 (duration1 比 duration2 大)

// 使用 Temporal.Instant 获取时间戳
const instant = Temporal.Instant.from('2023-10-27T02:00:00Z');
console.log(instant.epochSeconds); // 输出从 Unix 纪元开始的秒数

// 使用 Temporal.PlainYearMonth 创建年月对象
const yearMonth = Temporal.PlainYearMonth.from('2023-10');
console.log(yearMonth.daysInMonth); // 输出 31 (十月份的天数)
```

在这些 JavaScript 示例中，你调用的 `add`、`compare`、`epochSeconds`、`daysInMonth` 等方法，其底层的实现就可能对应着 `builtins-definitions.h` 中定义的 `TemporalZonedDateTimePrototypeAdd`、`TemporalDurationCompare` 等内置函数。

**代码逻辑推理（基于假设）：**

假设我们调用了 JavaScript 代码 `zonedDateTime.add({ hours: 2 })`，其中 `zonedDateTime` 是一个 `Temporal.ZonedDateTime` 对象。

**假设输入：**

* `this`:  一个 `Temporal.ZonedDateTime` 对象的实例。
* `arguments[0]`: 一个包含要添加的时间单位的对象，例如 `{ hours: 2 }`。

**可能的输出（取决于具体的 C++ 实现）：**

* 返回一个新的 `Temporal.ZonedDateTime` 对象，其时间比原始对象增加了 2 小时。

**用户常见的编程错误举例：**

1. **混淆 `Date` 和 `Temporal` 对象：** 开发者可能会尝试在 `Temporal` 对象上使用 `Date` 对象的方法，反之亦然。

   ```javascript
   const zonedDateTime = Temporal.ZonedDateTime.from('2023-10-27T10:00:00+08:00[Asia/Shanghai]');
   // 错误：getTime() 是 Date 对象的方法，不能直接用于 Temporal 对象
   console.log(zonedDateTime.getTime()); // TypeError: zonedDateTime.getTime is not a function

   const date = new Date();
   // 错误：add() 是 Temporal 对象的方法，不能直接用于 Date 对象
   date.add({ days: 1 }); // TypeError: date.add is not a function
   ```

2. **不理解时区的重要性：** 在使用 `Temporal.ZonedDateTime` 时，忽略或错误地处理时区可能导致计算错误。

   ```javascript
   // 假设用户期望得到北京时间的第二天
   const zonedDateTime = Temporal.ZonedDateTime.from('2023-10-27T00:00:00', 'America/New_York');
   const nextDay = zonedDateTime.add({ days: 1 });
   console.log(nextDay.toString()); // 输出的可能不是期望的北京时间

   // 正确的做法是指定正确的时区
   const zonedDateTimeBeijing = Temporal.ZonedDateTime.from('2023-10-27T00:00:00', 'Asia/Shanghai');
   const nextDayBeijing = zonedDateTimeBeijing.add({ days: 1 });
   console.log(nextDayBeijing.toString());
   ```

**本部分功能归纳（第 5 部分）：**

这部分 `builtins-definitions.h` 文件主要负责声明 **Temporal API** 中 `Temporal.Duration`、`Temporal.Instant`、`Temporal.PlainYearMonth` 和 `Temporal.PlainMonthDay` 及其原型对象上的各种方法（构造函数、`from`、`compare`、`add`、`subtract`、`toString` 等）的内置函数。它定义了 V8 引擎中实现这些 JavaScript 时间日期功能的底层 C++ 函数入口点。 这些定义是 V8 引擎将 JavaScript 代码翻译成高效机器码的关键步骤。

Prompt: 
```
这是目录为v8/src/builtins/builtins-definitions.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-definitions.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
ralZonedDateTimePrototypeWithCalendar, kDontAdaptArgumentsSentinel) \
  /* Temporal #sec-temporal.zoneddatetime.prototype.add */                     \
  CPP(TemporalZonedDateTimePrototypeAdd, kDontAdaptArgumentsSentinel)          \
  /* Temporal #sec-temporal.zoneddatetime.prototype.subtract */                \
  CPP(TemporalZonedDateTimePrototypeSubtract, kDontAdaptArgumentsSentinel)     \
  /* Temporal #sec-temporal.zoneddatetime.prototype.until */                   \
  CPP(TemporalZonedDateTimePrototypeUntil, kDontAdaptArgumentsSentinel)        \
  /* Temporal #sec-temporal.zoneddatetime.prototype.since */                   \
  CPP(TemporalZonedDateTimePrototypeSince, kDontAdaptArgumentsSentinel)        \
  /* Temporal #sec-temporal.zoneddatetime.prototype.round */                   \
  CPP(TemporalZonedDateTimePrototypeRound, kDontAdaptArgumentsSentinel)        \
  /* Temporal #sec-temporal.zoneddatetime.prototype.equals */                  \
  CPP(TemporalZonedDateTimePrototypeEquals, kDontAdaptArgumentsSentinel)       \
  /* Temporal #sec-temporal.zoneddatetime.prototype.tostring */                \
  CPP(TemporalZonedDateTimePrototypeToString, kDontAdaptArgumentsSentinel)     \
  /* Temporal #sec-temporal.zonedddatetimeprototype.tojson */                  \
  CPP(TemporalZonedDateTimePrototypeToJSON, kDontAdaptArgumentsSentinel)       \
  /* Temporal #sec-temporal.zoneddatetime.prototype.tolocalestring */          \
  CPP(TemporalZonedDateTimePrototypeToLocaleString,                            \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.zoneddatetime.prototype.valueof */                 \
  CPP(TemporalZonedDateTimePrototypeValueOf, kDontAdaptArgumentsSentinel)      \
  /* Temporal #sec-temporal.zoneddatetime.prototype.startofday */              \
  CPP(TemporalZonedDateTimePrototypeStartOfDay, kDontAdaptArgumentsSentinel)   \
  /* Temporal #sec-temporal.zoneddatetime.prototype.toinstant */               \
  CPP(TemporalZonedDateTimePrototypeToInstant, kDontAdaptArgumentsSentinel)    \
  /* Temporal #sec-temporal.zoneddatetime.prototype.toplaindate */             \
  CPP(TemporalZonedDateTimePrototypeToPlainDate, kDontAdaptArgumentsSentinel)  \
  /* Temporal #sec-temporal.zoneddatetime.prototype.toplaintime */             \
  CPP(TemporalZonedDateTimePrototypeToPlainTime, kDontAdaptArgumentsSentinel)  \
  /* Temporal #sec-temporal.zoneddatetime.prototype.toplaindatetime */         \
  CPP(TemporalZonedDateTimePrototypeToPlainDateTime,                           \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.zoneddatetime.prototype.toplainyearmonth */        \
  CPP(TemporalZonedDateTimePrototypeToPlainYearMonth,                          \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.zoneddatetime.prototype.toplainmonthday */         \
  CPP(TemporalZonedDateTimePrototypeToPlainMonthDay,                           \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.zoneddatetime.prototype.getisofields */            \
  CPP(TemporalZonedDateTimePrototypeGetISOFields, kDontAdaptArgumentsSentinel) \
                                                                               \
  /* Temporal.Duration */                                                      \
  /* Temporal #sec-temporal.duration */                                        \
  CPP(TemporalDurationConstructor, kDontAdaptArgumentsSentinel)                \
  /* Temporal #sec-temporal.duration.from */                                   \
  CPP(TemporalDurationFrom, kDontAdaptArgumentsSentinel)                       \
  /* Temporal #sec-temporal.duration.compare */                                \
  CPP(TemporalDurationCompare, kDontAdaptArgumentsSentinel)                    \
  /* Temporal #sec-get-temporal.duration.prototype.years */                    \
  CPP(TemporalDurationPrototypeYears, JSParameterCount(0))                     \
  /* Temporal #sec-get-temporal.duration.prototype.months */                   \
  CPP(TemporalDurationPrototypeMonths, JSParameterCount(0))                    \
  /* Temporal #sec-get-temporal.duration.prototype.weeks */                    \
  CPP(TemporalDurationPrototypeWeeks, JSParameterCount(0))                     \
  /* Temporal #sec-get-temporal.duration.prototype.days */                     \
  CPP(TemporalDurationPrototypeDays, JSParameterCount(0))                      \
  /* Temporal #sec-get-temporal.duration.prototype.hours */                    \
  CPP(TemporalDurationPrototypeHours, JSParameterCount(0))                     \
  /* Temporal #sec-get-temporal.duration.prototype.minutes */                  \
  CPP(TemporalDurationPrototypeMinutes, JSParameterCount(0))                   \
  /* Temporal #sec-get-temporal.duration.prototype.seconds */                  \
  CPP(TemporalDurationPrototypeSeconds, JSParameterCount(0))                   \
  /* Temporal #sec-get-temporal.duration.prototype.milliseconds */             \
  CPP(TemporalDurationPrototypeMilliseconds, JSParameterCount(0))              \
  /* Temporal #sec-get-temporal.duration.prototype.microseconds */             \
  CPP(TemporalDurationPrototypeMicroseconds, JSParameterCount(0))              \
  /* Temporal #sec-get-temporal.duration.prototype.nanoseconds */              \
  CPP(TemporalDurationPrototypeNanoseconds, JSParameterCount(0))               \
  /* Temporal #sec-get-temporal.duration.prototype.sign */                     \
  CPP(TemporalDurationPrototypeSign, JSParameterCount(0))                      \
  /* Temporal #sec-get-temporal.duration.prototype.blank */                    \
  CPP(TemporalDurationPrototypeBlank, JSParameterCount(0))                     \
  /* Temporal #sec-temporal.duration.prototype.with */                         \
  CPP(TemporalDurationPrototypeWith, kDontAdaptArgumentsSentinel)              \
  /* Temporal #sec-temporal.duration.prototype.negated */                      \
  CPP(TemporalDurationPrototypeNegated, kDontAdaptArgumentsSentinel)           \
  /* Temporal #sec-temporal.duration.prototype.abs */                          \
  CPP(TemporalDurationPrototypeAbs, kDontAdaptArgumentsSentinel)               \
  /* Temporal #sec-temporal.duration.prototype.add */                          \
  CPP(TemporalDurationPrototypeAdd, kDontAdaptArgumentsSentinel)               \
  /* Temporal #sec-temporal.duration.prototype.subtract */                     \
  CPP(TemporalDurationPrototypeSubtract, kDontAdaptArgumentsSentinel)          \
  /* Temporal #sec-temporal.duration.prototype.round */                        \
  CPP(TemporalDurationPrototypeRound, kDontAdaptArgumentsSentinel)             \
  /* Temporal #sec-temporal.duration.prototype.total */                        \
  CPP(TemporalDurationPrototypeTotal, kDontAdaptArgumentsSentinel)             \
  /* Temporal #sec-temporal.duration.prototype.tostring */                     \
  CPP(TemporalDurationPrototypeToString, kDontAdaptArgumentsSentinel)          \
  /* Temporal #sec-temporal.duration.tojson */                                 \
  CPP(TemporalDurationPrototypeToJSON, kDontAdaptArgumentsSentinel)            \
  /* Temporal #sec-temporal.duration.prototype.tolocalestring */               \
  CPP(TemporalDurationPrototypeToLocaleString, kDontAdaptArgumentsSentinel)    \
  /* Temporal #sec-temporal.duration.prototype.valueof */                      \
  CPP(TemporalDurationPrototypeValueOf, kDontAdaptArgumentsSentinel)           \
                                                                               \
  /* Temporal.Instant */                                                       \
  /* Temporal #sec-temporal.instant */                                         \
  CPP(TemporalInstantConstructor, kDontAdaptArgumentsSentinel)                 \
  /* Temporal #sec-temporal.instant.from */                                    \
  CPP(TemporalInstantFrom, kDontAdaptArgumentsSentinel)                        \
  /* Temporal #sec-temporal.instant.fromepochseconds */                        \
  CPP(TemporalInstantFromEpochSeconds, kDontAdaptArgumentsSentinel)            \
  /* Temporal #sec-temporal.instant.fromepochmilliseconds */                   \
  CPP(TemporalInstantFromEpochMilliseconds, kDontAdaptArgumentsSentinel)       \
  /* Temporal #sec-temporal.instant.fromepochmicroseconds */                   \
  CPP(TemporalInstantFromEpochMicroseconds, kDontAdaptArgumentsSentinel)       \
  /* Temporal #sec-temporal.instant.fromepochnanoseconds */                    \
  CPP(TemporalInstantFromEpochNanoseconds, kDontAdaptArgumentsSentinel)        \
  /* Temporal #sec-temporal.instant.compare */                                 \
  CPP(TemporalInstantCompare, kDontAdaptArgumentsSentinel)                     \
  /* Temporal #sec-get-temporal.instant.prototype.epochseconds */              \
  CPP(TemporalInstantPrototypeEpochSeconds, JSParameterCount(0))               \
  /* Temporal #sec-get-temporal.instant.prototype.epochmilliseconds */         \
  CPP(TemporalInstantPrototypeEpochMilliseconds, JSParameterCount(0))          \
  /* Temporal #sec-get-temporal.instant.prototype.epochmicroseconds */         \
  CPP(TemporalInstantPrototypeEpochMicroseconds, JSParameterCount(0))          \
  /* Temporal #sec-get-temporal.instant.prototype.epochnanoseconds */          \
  CPP(TemporalInstantPrototypeEpochNanoseconds, JSParameterCount(0))           \
  /* Temporal #sec-temporal.instant.prototype.add */                           \
  CPP(TemporalInstantPrototypeAdd, kDontAdaptArgumentsSentinel)                \
  /* Temporal #sec-temporal.instant.prototype.subtract */                      \
  CPP(TemporalInstantPrototypeSubtract, kDontAdaptArgumentsSentinel)           \
  /* Temporal #sec-temporal.instant.prototype.until */                         \
  CPP(TemporalInstantPrototypeUntil, kDontAdaptArgumentsSentinel)              \
  /* Temporal #sec-temporal.instant.prototype.since */                         \
  CPP(TemporalInstantPrototypeSince, kDontAdaptArgumentsSentinel)              \
  /* Temporal #sec-temporal.instant.prototype.round */                         \
  CPP(TemporalInstantPrototypeRound, kDontAdaptArgumentsSentinel)              \
  /* Temporal #sec-temporal.instant.prototype.equals */                        \
  CPP(TemporalInstantPrototypeEquals, kDontAdaptArgumentsSentinel)             \
  /* Temporal #sec-temporal.instant.prototype.tostring */                      \
  CPP(TemporalInstantPrototypeToString, kDontAdaptArgumentsSentinel)           \
  /* Temporal #sec-temporal.instant.tojson */                                  \
  CPP(TemporalInstantPrototypeToJSON, kDontAdaptArgumentsSentinel)             \
  /* Temporal #sec-temporal.instant.prototype.tolocalestring */                \
  CPP(TemporalInstantPrototypeToLocaleString, kDontAdaptArgumentsSentinel)     \
  /* Temporal #sec-temporal.instant.prototype.valueof */                       \
  CPP(TemporalInstantPrototypeValueOf, kDontAdaptArgumentsSentinel)            \
  /* Temporal #sec-temporal.instant.prototype.tozoneddatetime */               \
  CPP(TemporalInstantPrototypeToZonedDateTime, kDontAdaptArgumentsSentinel)    \
  /* Temporal #sec-temporal.instant.prototype.tozoneddatetimeiso */            \
  CPP(TemporalInstantPrototypeToZonedDateTimeISO, kDontAdaptArgumentsSentinel) \
                                                                               \
  /* Temporal.PlainYearMonth */                                                \
  /* Temporal #sec-temporal.plainyearmonth */                                  \
  CPP(TemporalPlainYearMonthConstructor, kDontAdaptArgumentsSentinel)          \
  /* Temporal #sec-temporal.plainyearmonth.from */                             \
  CPP(TemporalPlainYearMonthFrom, kDontAdaptArgumentsSentinel)                 \
  /* Temporal #sec-temporal.plainyearmonth.compare */                          \
  CPP(TemporalPlainYearMonthCompare, kDontAdaptArgumentsSentinel)              \
  /* Temporal #sec-get-temporal.plainyearmonth.prototype.calendar */           \
  CPP(TemporalPlainYearMonthPrototypeCalendar, JSParameterCount(0))            \
  /* Temporal #sec-get-temporal.plainyearmonth.prototype.year */               \
  CPP(TemporalPlainYearMonthPrototypeYear, JSParameterCount(0))                \
  /* Temporal #sec-get-temporal.plainyearmonth.prototype.month */              \
  CPP(TemporalPlainYearMonthPrototypeMonth, JSParameterCount(0))               \
  /* Temporal #sec-get-temporal.plainyearmonth.prototype.monthcode */          \
  CPP(TemporalPlainYearMonthPrototypeMonthCode, JSParameterCount(0))           \
  /* Temporal #sec-get-temporal.plainyearmonth.prototype.daysinyear */         \
  CPP(TemporalPlainYearMonthPrototypeDaysInYear, JSParameterCount(0))          \
  /* Temporal #sec-get-temporal.plainyearmonth.prototype.daysinmonth */        \
  CPP(TemporalPlainYearMonthPrototypeDaysInMonth, JSParameterCount(0))         \
  /* Temporal #sec-get-temporal.plainyearmonth.prototype.monthsinyear */       \
  CPP(TemporalPlainYearMonthPrototypeMonthsInYear, JSParameterCount(0))        \
  /* Temporal #sec-get-temporal.plainyearmonth.prototype.inleapyear */         \
  CPP(TemporalPlainYearMonthPrototypeInLeapYear, JSParameterCount(0))          \
  /* Temporal #sec-temporal.plainyearmonth.prototype.with */                   \
  CPP(TemporalPlainYearMonthPrototypeWith, kDontAdaptArgumentsSentinel)        \
  /* Temporal #sec-temporal.plainyearmonth.prototype.add */                    \
  CPP(TemporalPlainYearMonthPrototypeAdd, kDontAdaptArgumentsSentinel)         \
  /* Temporal #sec-temporal.plainyearmonth.prototype.subtract */               \
  CPP(TemporalPlainYearMonthPrototypeSubtract, kDontAdaptArgumentsSentinel)    \
  /* Temporal #sec-temporal.plainyearmonth.prototype.until */                  \
  CPP(TemporalPlainYearMonthPrototypeUntil, kDontAdaptArgumentsSentinel)       \
  /* Temporal #sec-temporal.plainyearmonth.prototype.since */                  \
  CPP(TemporalPlainYearMonthPrototypeSince, kDontAdaptArgumentsSentinel)       \
  /* Temporal #sec-temporal.plainyearmonth.prototype.equals */                 \
  CPP(TemporalPlainYearMonthPrototypeEquals, kDontAdaptArgumentsSentinel)      \
  /* Temporal #sec-temporal.plainyearmonth.tostring */                         \
  CPP(TemporalPlainYearMonthPrototypeToString, kDontAdaptArgumentsSentinel)    \
  /* Temporal #sec-temporal.plainyearmonth.tojson */                           \
  CPP(TemporalPlainYearMonthPrototypeToJSON, kDontAdaptArgumentsSentinel)      \
  /* Temporal #sec-temporal.plainyearmonth.prototype.tolocalestring */         \
  CPP(TemporalPlainYearMonthPrototypeToLocaleString,                           \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.plainyearmonth.prototype.valueof */                \
  CPP(TemporalPlainYearMonthPrototypeValueOf, kDontAdaptArgumentsSentinel)     \
  /* Temporal #sec-temporal.plainyearmonth.prototype.toplaindate */            \
  CPP(TemporalPlainYearMonthPrototypeToPlainDate, kDontAdaptArgumentsSentinel) \
  /* Temporal #sec-temporal.plainyearmonth.prototype.getisofields */           \
  CPP(TemporalPlainYearMonthPrototypeGetISOFields,                             \
      kDontAdaptArgumentsSentinel)                                             \
                                                                               \
  /* Temporal.PlainMonthDay */                                                 \
  /* Temporal #sec-temporal.plainmonthday */                                   \
  CPP(TemporalPlainMonthDayConstructor, kDontAdaptArgumentsSentinel)           \
  /* Temporal #sec-temporal.plainmonthday.from */                              \
  CPP(TemporalPlainMonthDayFrom, kDontAdaptArgumentsSentinel)                  \
  /* There are no compare for PlainMonthDay */                                 \
  /* See https://github.com/tc39/proposal-temporal/issues/1547 */              \
  /* Temporal #sec-get-temporal.plainmonthday.prototype.calendar */            \
  CPP(TemporalPlainMonthDayPrototypeCalendar, JSParameterCount(0))             \
  /* Temporal #sec-get-temporal.plainmonthday.prototype.monthcode */           \
  CPP(TemporalPlainMonthDayPrototypeMonthCode, JSParameterCount(0))            \
  /* Temporal #sec-get-temporal.plainmonthday.prototype.day */                 \
  CPP(TemporalPlainMonthDayPrototypeDay, JSParameterCount(0))                  \
  /* Temporal #sec-temporal.plainmonthday.prototype.with */                    \
  CPP(TemporalPlainMonthDayPrototypeWith, kDontAdaptArgumentsSentinel)         \
  /* Temporal #sec-temporal.plainmonthday.prototype.equals */                  \
  CPP(TemporalPlainMonthDayPrototypeEquals, kDontAdaptArgumentsSentinel)       \
  /* Temporal #sec-temporal.plainmonthday.prototype.tostring */                \
  CPP(TemporalPlainMonthDayPrototypeToString, kDontAdaptArgumentsSentinel)     \
  /* Temporal #sec-temporal.plainmonthday.tojson */                            \
  CPP(TemporalPlainMonthDayPrototypeToJSON, kDontAdaptArgumentsSentinel)       \
  /* Temporal #sec-temporal.plainmonthday.prototype.tolocalestring */          \
  CPP(TemporalPlainMonthDayPrototypeToLocaleString,                            \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.plainmonthday.prototype.valueof */                 \
  CPP(TemporalPlainMonthDayPrototypeValueOf, kDontAdaptArgumentsSentinel)      \
  /* Temporal #sec-temporal.plainmonthday.prototype.toplaindate */             \
  CPP(TemporalPlainMonthDayPrototypeToPlainDate, kDontAdaptArgumentsSentinel)  \
  /* Temporal #sec-temporal.plainmonthday.prototype.getisofields */            \
  CPP(TemporalPlainMonthDayPrototypeGetISOFields, kDontAdaptArgumentsSentinel) \
                                                                               \
  /* Temporal.TimeZone */                                                      \
  /* Temporal #sec-temporal.timezone */                                        \
  CPP(TemporalTimeZoneConstructor, kDontAdaptArgumentsSentinel)                \
  /* Temporal #sec-temporal.timezone.from */                                   \
  CPP(TemporalTimeZoneFrom, kDontAdaptArgumentsSentinel)                       \
  /* Temporal #sec-get-temporal.timezone.prototype.id */                       \
  CPP(TemporalTimeZonePrototypeId, JSParameterCount(0))                        \
  /* Temporal #sec-temporal.timezone.prototype.getoffsetnanosecondsfor */      \
  CPP(TemporalTimeZonePrototypeGetOffsetNanosecondsFor,                        \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.timezone.prototype.getoffsetstringfor */           \
  CPP(TemporalTimeZonePrototypeGetOffsetStringFor,                             \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.timezone.prototype.getplaindatetimefor */          \
  CPP(TemporalTimeZonePrototypeGetPlainDateTimeFor,                            \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.timezone.prototype.getinstantfor */                \
  CPP(TemporalTimeZonePrototypeGetInstantFor, kDontAdaptArgumentsSentinel)     \
  /* Temporal #sec-temporal.timezone.prototype.getpossibleinstantsfor */       \
  CPP(TemporalTimeZonePrototypeGetPossibleInstantsFor,                         \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.timezone.prototype.getnexttransition */            \
  CPP(TemporalTimeZonePrototypeGetNextTransition, kDontAdaptArgumentsSentinel) \
  /* Temporal #sec-temporal.timezone.prototype.getprevioustransition */        \
  CPP(TemporalTimeZonePrototypeGetPreviousTransition,                          \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.timezone.prototype.tostring */                     \
  CPP(TemporalTimeZonePrototypeToString, kDontAdaptArgumentsSentinel)          \
  /* Temporal #sec-temporal.timezone.prototype.tojson */                       \
  CPP(TemporalTimeZonePrototypeToJSON, kDontAdaptArgumentsSentinel)            \
                                                                               \
  /* Temporal.Calendar */                                                      \
  /* Temporal #sec-temporal.calendar */                                        \
  CPP(TemporalCalendarConstructor, kDontAdaptArgumentsSentinel)                \
  /* Temporal #sec-temporal.calendar.from */                                   \
  CPP(TemporalCalendarFrom, kDontAdaptArgumentsSentinel)                       \
  /* Temporal #sec-get-temporal.calendar.prototype.id */                       \
  CPP(TemporalCalendarPrototypeId, JSParameterCount(0))                        \
  /* Temporal #sec-temporal.calendar.prototype.datefromfields */               \
  CPP(TemporalCalendarPrototypeDateFromFields, kDontAdaptArgumentsSentinel)    \
  /* Temporal #sec-temporal.calendar.prototype.yearmonthfromfields */          \
  CPP(TemporalCalendarPrototypeYearMonthFromFields,                            \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.calendar.prototype.monthdayfromfields */           \
  CPP(TemporalCalendarPrototypeMonthDayFromFields,                             \
      kDontAdaptArgumentsSentinel)                                             \
  /* Temporal #sec-temporal.calendar.prototype.dateadd */                      \
  CPP(TemporalCalendarPrototypeDateAdd, kDontAdaptArgumentsSentinel)           \
  /* Temporal #sec-temporal.calendar.prototype.dateuntil */                    \
  CPP(TemporalCalendarPrototypeDateUntil, kDontAdaptArgumentsSentinel)         \
  /* Temporal #sec-temporal.calendar.prototype.year */                         \
  CPP(TemporalCalendarPrototypeYear, kDontAdaptArgumentsSentinel)              \
  /* Temporal #sec-temporal.calendar.prototype.month */                        \
  CPP(TemporalCalendarPrototypeMonth, kDontAdaptArgumentsSentinel)             \
  /* Temporal #sec-temporal.calendar.prototype.monthcode */                    \
  CPP(TemporalCalendarPrototypeMonthCode, kDontAdaptArgumentsSentinel)         \
  /* Temporal #sec-temporal.calendar.prototype.day */                          \
  CPP(TemporalCalendarPrototypeDay, kDontAdaptArgumentsSentinel)               \
  /* Temporal #sec-temporal.calendar.prototype.dayofweek */                    \
  CPP(TemporalCalendarPrototypeDayOfWeek, kDontAdaptArgumentsSentinel)         \
  /* Temporal #sec-temporal.calendar.prototype.dayofyear */                    \
  CPP(TemporalCalendarPrototypeDayOfYear, kDontAdaptArgumentsSentinel)         \
  /* Temporal #sec-temporal.calendar.prototype.weekofyear */                   \
  CPP(TemporalCalendarPrototypeWeekOfYear, kDontAdaptArgumentsSentinel)        \
  /* Temporal #sec-temporal.calendar.prototype.daysinweek */                   \
  CPP(TemporalCalendarPrototypeDaysInWeek, kDontAdaptArgumentsSentinel)        \
  /* Temporal #sec-temporal.calendar.prototype.daysinmonth */                  \
  CPP(TemporalCalendarPrototypeDaysInMonth, kDontAdaptArgumentsSentinel)       \
  /* Temporal #sec-temporal.calendar.prototype.daysinyear */                   \
  CPP(TemporalCalendarPrototypeDaysInYear, kDontAdaptArgumentsSentinel)        \
  /* Temporal #sec-temporal.calendar.prototype.monthsinyear */                 \
  CPP(TemporalCalendarPrototypeMonthsInYear, kDontAdaptArgumentsSentinel)      \
  /* Temporal #sec-temporal.calendar.prototype.inleapyear */                   \
  CPP(TemporalCalendarPrototypeInLeapYear, kDontAdaptArgumentsSentinel)        \
  /* Temporal #sec-temporal.calendar.prototype.fields */                       \
  TFJ(TemporalCalendarPrototypeFields, kJSArgcReceiverSlots + 1, kReceiver,    \
      kIterable)                                                               \
  /* Temporal #sec-temporal.calendar.prototype.mergefields */                  \
  CPP(TemporalCalendarPrototypeMergeFields, kDontAdaptArgumentsSentinel)       \
  /* Temporal #sec-temporal.calendar.prototype.tostring */                     \
  CPP(TemporalCalendarPrototypeToString, kDontAdaptArgumentsSentinel)          \
  /* Temporal #sec-temporal.calendar.prototype.tojson */                       \
  CPP(TemporalCalendarPrototypeToJSON, kDontAdaptArgumentsSentinel)            \
  /* Temporal #sec-date.prototype.totemporalinstant */                         \
  CPP(DatePrototypeToTemporalInstant, kDontAdaptArgumentsSentinel)             \
                                                                               \
  /* "Private" (created but not exposed) Bulitins needed by Temporal */        \
  TFJ(StringFixedArrayFromIterable, kJSArgcReceiverSlots + 1, kReceiver,       \
      kIterable)                                                               \
  TFJ(TemporalInstantFixedArrayFromIterable, kJSArgcReceiverSlots + 1,         \
      kReceiver, kIterable)

#define BUILTIN_LIST_BASE(CPP, TSJ, TFJ, TSC, TFC, TFS, TFH, ASM) \
  BUILTIN_LIST_BASE_TIER0(CPP, TFJ, TFC, TFS, TFH, ASM)           \
  BUILTIN_LIST_BASE_TIER1(CPP, TSJ, TFJ, TSC, TFC, TFS, TFH, ASM)

#ifdef V8_INTL_SUPPORT
#define BUILTIN_LIST_INTL(CPP, TFJ, TFS)                                       \
  /* ecma402 #sec-intl.collator */                                             \
  CPP(CollatorConstructor, kDontAdaptArgumentsSentinel)                        \
  /* ecma 402 #sec-collator-compare-functions*/                                \
  CPP(CollatorInternalCompare, JSParameterCount(2))                            \
  /* ecma402 #sec-intl.collator.prototype.compare */                           \
  CPP(CollatorPrototypeCompare, kDontAdaptArgumentsSentinel)                   \
  /* ecma402 #sec-intl.collator.supportedlocalesof */                          \
  CPP(CollatorSupportedLocalesOf, kDontAdaptArgumentsSentinel)                 \
  /* ecma402 #sec-intl.collator.prototype.resolvedoptions */                   \
  CPP(CollatorPrototypeResolvedOptions, kDontAdaptArgumentsSentinel)           \
  /* ecma402 #sup-date.prototype.tolocaledatestring */                         \
  CPP(DatePrototypeToLocaleDateString, kDontAdaptArgumentsSentinel)            \
  /* ecma402 #sup-date.prototype.tolocalestring */                             \
  CPP(DatePrototypeToLocaleString, kDontAdaptArgumentsSentinel)                \
  /* ecma402 #sup-date.prototype.tolocaletimestring */                         \
  CPP(DatePrototypeToLocaleTimeString, kDontAdaptArgumentsSentinel)            \
  /* ecma402 #sec-intl.datetimeformat */                                       \
  CPP(DateTimeFormatConstructor, kDontAdaptArgumentsSentinel)                  \
  /* ecma402 #sec-datetime-format-functions */                                 \
  CPP(DateTimeFormatInternalFormat, JSParameterCount(1))                       \
  /* ecma402 #sec-intl.datetimeformat.prototype.format */                      \
  CPP(DateTimeFormatPrototypeFormat, kDontAdaptArgumentsSentinel)              \
  /* ecma402 #sec-intl.datetimeformat.prototype.formatrange */                 \
  CPP(DateTimeFormatPrototypeFormatRange, kDontAdaptArgumentsSentinel)         \
  /* ecma402 #sec-intl.datetimeformat.prototype.formatrangetoparts */          \
  CPP(DateTimeFormatPrototypeFormatRangeToParts, kDontAdaptArgumentsSentinel)  \
  /* ecma402 #sec-intl.datetimeformat.prototype.formattoparts */               \
  CPP(DateTimeFormatPrototypeFormatToParts, kDontAdaptArgumentsSentinel)       \
  /* ecma402 #sec-intl.datetimeformat.prototype.resolvedoptions */             \
  CPP(DateTimeFormatPrototypeResolvedOptions, kDontAdaptArgumentsSentinel)     \
  /* ecma402 #sec-intl.datetimeformat.supportedlocalesof */                    \
  CPP(DateTimeFormatSupportedLocalesOf, kDontAdaptArgumentsSentinel)           \
  /* ecma402 #sec-Intl.DisplayNames */                                         \
  CPP(DisplayNamesConstructor, kDontAdaptArgumentsSentinel)                    \
  /* ecma402 #sec-Intl.DisplayNames.prototype.of */                            \
  CPP(DisplayNamesPrototypeOf, kDontAdaptArgumentsSentinel)                    \
  /* ecma402 #sec-Intl.DisplayNames.prototype.resolvedOptions */               \
  CPP(DisplayNamesPrototypeResolvedOptions, kDontAdaptArgumentsSentinel)       \
  /* ecma402 #sec-Intl.DisplayNames.supportedLocalesOf */                      \
  CPP(DisplayNamesSupportedLocalesOf, kDontAdaptArgumentsSentinel)             \
  /* ecma402 #sec-intl-durationformat-constructor */                           \
  CPP(DurationFormatConstructor, kDontAdaptArgumentsSentinel)                  \
  /* ecma402 #sec-Intl.DurationFormat.prototype.format */                      \
  CPP(DurationFormatPrototypeFormat, kDontAdaptArgumentsSentinel)              \
  /* ecma402 #sec-Intl.DurationFormat.prototype.formatToParts */               \
  CPP(DurationFormatPrototypeFormatToParts, kDontAdaptArgumentsSentinel)       \
  /* ecma402 #sec-Intl.DurationFormat.prototype.resolvedOptions */             \
  CPP(DurationFormatPrototypeResolvedOptions, kDontAdaptArgumentsSentinel)     \
  /* ecma402 #sec-Intl.DurationFormat.supportedLocalesOf */                    \
  CPP(DurationFormatSupportedLocalesOf, kDontAdaptArgumentsSentinel)           \
  /* ecma402 #sec-intl.getcanonicallocales */                                  \
  CPP(IntlGetCanonicalLocales, kDontAdaptArgumentsSentinel)                    \
  /* ecma402 #sec-intl.supportedvaluesof */                                    \
  CPP(IntlSupportedValuesOf, kDontAdaptArgumentsSentinel)                      \
  /* ecma402 #sec-intl-listformat-constructor */                               \
  CPP(ListFormatConstructor, kDontAdaptArgumentsSentinel)                      \
  /* ecma402 #sec-intl-list-format.prototype.format */                         \
  TFJ(ListFormatPrototypeFormat, kDontAdaptArgumentsSentinel)                  \
  /* ecma402 #sec-intl-list-format.prototype.formattoparts */                  \
  TFJ(ListFormatPrototypeFormatToParts, kDontAdaptArgumentsSentinel)           \
  /* ecma402 #sec-intl.listformat.prototype.resolvedoptions */                 \
  CPP(ListFormatPrototypeResolvedOptions, kDontAdaptArgumentsSentinel)         \
  /* ecma402 #sec-intl.ListFormat.supportedlocalesof */                        \
  CPP(ListFormatSupportedLocalesOf, kDontAdaptArgumentsSentinel)               \
  /* ecma402 #sec-intl-locale-constructor */                                   \
  CPP(LocaleConstructor, kDontAdaptArgumentsSentinel)                          \
  /* ecma402 #sec-Intl.Locale.prototype.baseName */                            \
  CPP(LocalePrototypeBaseName, JSParameterCount(0))                            \
  /* ecma402 #sec-Intl.Locale.prototype.calendar */                            \
  CPP(LocalePrototypeCalendar, JSParameterCount(0))                            \
  /* ecma402 #sec-Intl.Locale.prototype.calendars */                           \
  CPP(LocalePrototypeCalendars, JSParameterCount(0))                           \
  /* ecma402 #sec-Intl.Locale.prototype.caseFirst */                           \
  CPP(LocalePrototypeCaseFirst, JSParameterCount(0))                           \
  /* ecma402 #sec-Intl.Locale.prototype.collation */                           \
  CPP(LocalePrototypeCollation, JSParameterCount(0))                           \
  /* ecma402 #sec-Intl.Locale.prototype.collations */                          \
  CPP(LocalePrototypeCollations, JSParameterCount(0))                          \
  /* ecma402 #sec-Intl.Locale.prototype.firstDayOfWeek */                      \
  CPP(LocalePrototypeFirstDayOfWeek, JSParameterCount(0))                      \
  /* ecma402 #sec-Intl.Locale.prototype.getCalendars */                        \
  CPP(LocalePrototypeGetCalendars, kDontAdaptArgumentsSentinel)                \
  /* ecma402 #sec-Intl.Locale.prototype.getCollations */                       \
  CPP(LocalePrototypeGetCollations, kDontAdaptArgumentsSentinel)               \
  /* ecma402 #sec-Intl.Locale.prototype.getHourCycles */                       \
  CPP(LocalePrototypeGetHourCycles, kDontAd
"""


```