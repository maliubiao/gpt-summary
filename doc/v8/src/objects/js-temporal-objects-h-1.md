Response:
The user wants a summary of the functionality of the provided C++ header file.

Here's a breakdown of the thought process to achieve that:

1. **Identify the file's purpose:** The filename `js-temporal-objects.h` and the content clearly indicate this file defines the structure and interface for JavaScript Temporal API objects within the V8 engine.

2. **Examine the class definitions:**  The file primarily contains declarations of C++ classes corresponding to JavaScript Temporal API objects. These classes are:
    * `JSTemporalPlainYearMonth`
    * `JSTemporalTimeZone`
    * `JSTemporalZonedDateTime`

3. **Analyze the methods within each class:** Each class has various static methods. The names of these methods, along with the comments prefixed with `// #sec-temporal.`, directly correlate to the specifications of the Temporal API in JavaScript. Recognize the pattern:
    * `Constructor`:  Creating new instances.
    * `From`:  Parsing or converting from other types.
    * `Compare`: Comparing instances.
    * `Equals`: Checking for equality.
    * `With`: Creating a new instance with modified properties.
    * `To...`: Converting to other Temporal types or primitive values.
    * `Add`, `Subtract`, `Until`, `Since`: Performing date/time arithmetic.
    * `Get...`: Accessing specific components or information.

4. **Identify supporting structures and functions:** Beyond the main classes, notice the presence of:
    * `DateRecord`, `TimeRecord`, `DateTimeRecord`:  Helper structs for representing date and time components.
    * `CreateTemporal...`: Functions for creating instances of Temporal objects programmatically within V8.
    * `Calendar...`:  Functions that abstract calendar operations, highlighting the pluggable nature of calendars in the Temporal API.
    * `GetISO8601Calendar`, `GetBuiltinCalendar`:  Functions to access specific calendar implementations.
    * `BuiltinTimeZoneGet...`: Functions dealing with time zone operations.
    * `TimeDurationRecord`, `DurationRecord`: Structs to represent durations.
    * `ToPartialDuration`, `IsValidDuration`: Functions for working with duration objects.

5. **Connect the C++ definitions to JavaScript usage:**  Since this is about JavaScript integration, consider how these C++ classes and methods manifest in JavaScript. The comments like `#sec-temporal.plainyearmonth.from` directly link to the JavaScript API. Think of corresponding JavaScript code snippets for the most common operations.

6. **Address the ".tq" question:** The prompt specifically asks about `.tq` files and Torque. Note that the file ends in `.h`, so it's a C++ header, *not* a Torque file. Explain the role of Torque in generating some of the code.

7. **Identify potential programming errors:**  Based on the API functions, think about common mistakes developers might make when using these features in JavaScript. For example, providing invalid input types, incorrect option objects, or misunderstanding the immutability of Temporal objects.

8. **Structure the summary:** Organize the findings into logical sections:
    * Overall purpose of the header file.
    * Detailed breakdown of each major class (`JSTemporalPlainYearMonth`, `JSTemporalTimeZone`, `JSTemporalZonedDateTime`), highlighting their functionalities and corresponding JavaScript examples.
    * Explanation of the supporting structures and functions.
    * Discussion of the `.tq` file question.
    * Examples of common programming errors.

9. **Refine the language:** Use clear and concise language. Explain technical terms where necessary.

10. **Address the "part 2" instruction:**  The prompt indicates this is the second part, implying the first part already covered some ground. Therefore, the summary should focus on the classes and functions presented in *this* specific file. The request to "summarize its functionality" should be interpreted within the context of *this* code snippet.

**(Self-Correction during the process):**  Initially, I might be tempted to explain the entire Temporal API. However, the prompt specifically asks about the functionality *within this header file*. Therefore, the focus should be on the C++ declarations and how they relate to the JavaScript API elements they represent. Avoid going into excessive detail about the JavaScript API itself unless it directly clarifies the purpose of the C++ code. Also, double-check the prompt's constraints regarding examples and specific questions.
好的，这是第二部分，我们来归纳一下 `v8/src/objects/js-temporal-objects.h` 的功能。

**功能归纳**

总的来说，`v8/src/objects/js-temporal-objects.h` 文件是 V8 引擎中用于定义和实现 JavaScript Temporal API 中核心日期和时间相关对象的 C++ 头文件。它定义了以下主要内容：

1. **JavaScript Temporal API 对象的 C++ 表示:**  它声明了与 JavaScript Temporal API 中关键类相对应的 C++ 类，例如 `JSTemporalPlainYearMonth`, `JSTemporalTimeZone`, 和 `JSTemporalZonedDateTime`。这些 C++ 类是 JavaScript 中相应 Temporal 对象在 V8 内部的表示形式。

2. **Temporal 对象的属性和方法:**  每个 C++ 类中声明的静态方法都对应于 JavaScript Temporal 对象上的方法（例如 `from`, `compare`, `equals`, `with`, `add`, `subtract` 等）。这些方法定义了如何操作和处理 Temporal 对象。方法前的注释 `// #sec-temporal...` 引用了 ECMA-402 (Temporal) 规范中的章节，表明了这些方法实现的规范依据。

3. **Temporal 对象的创建和转换:**  文件中包含了用于创建 Temporal 对象实例的静态方法（例如 `Constructor`, `From`）以及在不同 Temporal 类型之间进行转换的方法（例如 `ToPlainDate`, `ToPlainTime`）。

4. **对日历和时区的抽象操作:** 文件中定义了一些辅助的结构体（例如 `DateRecord`, `TimeRecord`) 和函数，用于处理日期和时间的不同组成部分。  更重要的是，它声明了 `Calendar...` 和 `BuiltinTimeZoneGet...` 等一系列函数，用于抽象日历系统和时区处理的底层操作。这体现了 Temporal API 的可扩展性和对不同日历系统的支持。

5. **Duration 的表示:**  定义了 `TimeDurationRecord` 和 `DurationRecord` 结构体，用于表示时间间隔和完整的 Duration 对象。

**针对之前问题的补充说明：**

* **.tq 文件：**  正如您在第一部分中提到的，如果文件以 `.tq` 结尾，那它就是 V8 Torque 源代码。此文件以 `.h` 结尾，所以它是标准的 C++ 头文件。但是，请注意，在这些 C++ 类的声明中，您会看到 `DEFINE_TORQUE_GENERATED_...` 这样的宏。这表明 V8 使用 Torque 语言来生成部分 C++ 代码，以提高性能和安全性。因此，虽然此文件本身不是 `.tq` 文件，但它依赖于 Torque 生成的代码。

* **与 JavaScript 功能的关系：**  这个文件的核心目的就是为 JavaScript Temporal API 提供底层的 C++ 实现。JavaScript 中对 Temporal 对象的任何操作，最终都会调用到这里定义的 C++ 方法。

* **代码逻辑推理 (示例 - `Compare` 方法):**
    * **假设输入：**
        * JavaScript 代码创建了两个 `Temporal.PlainYearMonth` 对象：`ym1 = Temporal.PlainYearMonth.from('2023-04')` 和 `ym2 = Temporal.PlainYearMonth.from('2023-05')`。
    * **C++ 层的调用：**  当 JavaScript 执行 `Temporal.PlainYearMonth.compare(ym1, ym2)` 时，V8 引擎会调用到 `JSTemporalPlainYearMonth::Compare` 方法，并将 `ym1` 和 `ym2` 的内部表示传递给它。
    * **C++ 逻辑推理 (简化)：**  `Compare` 方法会提取两个 `JSTemporalPlainYearMonth` 对象的年份和月份，然后进行比较。在这个例子中，它会比较 `ym1` 的 2023 年 4 月和 `ym2` 的 2023 年 5 月。
    * **输出：**  由于 4 月早于 5 月，`Compare` 方法会返回一个负的 `Smi` 值（V8 中用于表示小整数）。这个返回值会被传递回 JavaScript 层，最终 JavaScript 的 `compare` 方法会返回一个负数。

* **用户常见的编程错误 (示例 - `with` 方法):**
    * **错误示例 (JavaScript):**
    ```javascript
    const yearMonth = Temporal.PlainYearMonth.from('2023-10');
    yearMonth.with({ month: 11 }); // 期望修改 yearMonth 对象
    console.log(yearMonth.toString()); // 输出仍然是 2023-10
    ```
    * **解释：**  Temporal API 的对象是不可变的。 `with` 方法不会修改原始对象，而是返回一个新的 `Temporal.PlainYearMonth` 对象。
    * **正确做法：**
    ```javascript
    const yearMonth = Temporal.PlainYearMonth.from('2023-10');
    const newYearMonth = yearMonth.with({ month: 11 });
    console.log(newYearMonth.toString()); // 输出 2023-11
    ```
    * **C++ 层面：**  `JSTemporalPlainYearMonth::With` 方法的实现会创建并返回一个新的 `JSTemporalPlainYearMonth` 对象，而不是修改传入的 `year_month` 对象。

总而言之，`v8/src/objects/js-temporal-objects.h` 是 V8 引擎中至关重要的一个头文件，它定义了 JavaScript Temporal API 的核心数据结构和操作，使得 JavaScript 能够以规范且高效的方式处理日期和时间。

### 提示词
```
这是目录为v8/src/objects/js-temporal-objects.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-temporal-objects.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
class JSTemporalPlainYearMonth
    : public TorqueGeneratedJSTemporalPlainYearMonth<JSTemporalPlainYearMonth,
                                                     JSObject> {
 public:
  // ##sec-temporal.plainyearmonth
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalPlainYearMonth>
  Constructor(Isolate* isolate, Handle<JSFunction> target,
              Handle<HeapObject> new_target, Handle<Object> iso_year,
              Handle<Object> iso_month, Handle<Object> calendar_like,
              Handle<Object> reference_iso_day);

  // #sec-temporal.plainyearmonth.from
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalPlainYearMonth> From(
      Isolate* isolate, Handle<Object> item, Handle<Object> options);

  // #sec-temporal.plainyearmonth.compare
  V8_WARN_UNUSED_RESULT static MaybeHandle<Smi> Compare(Isolate* isolate,
                                                        Handle<Object> one,
                                                        Handle<Object> two);

  // #sec-temporal.plainyearmonth.prototype.equals
  V8_WARN_UNUSED_RESULT static MaybeHandle<Oddball> Equals(
      Isolate* isolate, DirectHandle<JSTemporalPlainYearMonth> year_month,
      Handle<Object> other);

  // #sec-temporal.plainyearmonth.prototype.with
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalPlainYearMonth> With(
      Isolate* isolate, Handle<JSTemporalPlainYearMonth> year_month,
      Handle<Object> temporal_year_month_like, Handle<Object> options);

  // #sec-temporal.plainyearmonth.prototype.toplaindate
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalPlainDate> ToPlainDate(
      Isolate* isolate, Handle<JSTemporalPlainYearMonth> year_month,
      Handle<Object> item);

  // #sec-temporal.plainyearmonth.prototype.getisofields
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSReceiver> GetISOFields(
      Isolate* isolate, DirectHandle<JSTemporalPlainYearMonth> year_month);

  // #sec-temporal.plainyearmonth.prototype.add
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalPlainYearMonth> Add(
      Isolate* isolate, Handle<JSTemporalPlainYearMonth> year_month,
      Handle<Object> temporal_duration_like, Handle<Object> options);

  // #sec-temporal.plainyearmonth.prototype.subtract
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalPlainYearMonth> Subtract(
      Isolate* isolate, Handle<JSTemporalPlainYearMonth> year_month,
      Handle<Object> temporal_duration_like, Handle<Object> options);

  // #sec-temporal.plainyearmonth.prototype.until
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalDuration> Until(
      Isolate* isolate, Handle<JSTemporalPlainYearMonth> year_month,
      Handle<Object> other, Handle<Object> options);

  // #sec-temporal.plaindyearmonth.prototype.since
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalDuration> Since(
      Isolate* isolate, Handle<JSTemporalPlainYearMonth> year_month,
      Handle<Object> other, Handle<Object> options);

  // #sec-temporal.plainyearmonth.prototype.tostring
  V8_WARN_UNUSED_RESULT static MaybeHandle<String> ToString(
      Isolate* isolate, DirectHandle<JSTemporalPlainYearMonth> year_month,
      Handle<Object> options);

  // #sec-temporal.plainyearmonth.prototype.tojson
  V8_WARN_UNUSED_RESULT static MaybeHandle<String> ToJSON(
      Isolate* isolate, DirectHandle<JSTemporalPlainYearMonth> year_month);

  // #sec-temporal.plainyearmonth.prototype.tolocalestring
  V8_WARN_UNUSED_RESULT static MaybeHandle<String> ToLocaleString(
      Isolate* isolate, Handle<JSTemporalPlainYearMonth> plain_date,
      Handle<Object> locales, Handle<Object> options);

  // Abstract Operations

  DECL_PRINTER(JSTemporalPlainYearMonth)

  DEFINE_TORQUE_GENERATED_JS_TEMPORAL_YEAR_MONTH_DAY()

  DECLARE_TEMPORAL_DATE_INLINE_GETTER_SETTER()

  TQ_OBJECT_CONSTRUCTORS(JSTemporalPlainYearMonth)
};

class JSTemporalTimeZone
    : public TorqueGeneratedJSTemporalTimeZone<JSTemporalTimeZone, JSObject> {
 public:
  // #sec-temporal.now.timezone
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalTimeZone> Now(
      Isolate* isolate);

  // #sec-temporal.timezone
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalTimeZone> Constructor(
      Isolate* isolate, Handle<JSFunction> target,
      Handle<HeapObject> new_target, Handle<Object> identifier);

  // #sec-temporal.timezone.prototype.getinstantfor
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalInstant> GetInstantFor(
      Isolate* isolate, Handle<JSTemporalTimeZone> time_zone,
      Handle<Object> dateTime, Handle<Object> options);

  // #sec-temporal.timezone.prototype.getplaindatetimefor
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalPlainDateTime>
  GetPlainDateTimeFor(Isolate* isolate, Handle<JSTemporalTimeZone> time_zone,
                      Handle<Object> instance, Handle<Object> calendar_like);

  // #sec-temporal.timezone.prototype.getnexttransition
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> GetNextTransition(
      Isolate* isolate, DirectHandle<JSTemporalTimeZone> time_zone,
      Handle<Object> starting_point);

  // #sec-temporal.timezone.prototype.getprevioustransition
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> GetPreviousTransition(
      Isolate* isolate, DirectHandle<JSTemporalTimeZone> time_zone,
      Handle<Object> starting_point);

  // #sec-temporal.timezone.prototype.getpossibleinstantsfor
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSArray> GetPossibleInstantsFor(
      Isolate* isolate, DirectHandle<JSTemporalTimeZone> time_zone,
      Handle<Object> date_time);

  // #sec-temporal.timezone.prototype.getoffsetnanosecondsfor
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> GetOffsetNanosecondsFor(
      Isolate* isolate, DirectHandle<JSTemporalTimeZone> time_zone,
      Handle<Object> instance);

  // #sec-temporal.timezone.prototype.getoffsetstringfor
  V8_WARN_UNUSED_RESULT static MaybeHandle<String> GetOffsetStringFor(
      Isolate* isolate, Handle<JSTemporalTimeZone> time_zone,
      Handle<Object> instance);

  // #sec-temporal.timezone.prototype.tostring
  static MaybeHandle<Object> ToString(
      Isolate* isolate, DirectHandle<JSTemporalTimeZone> time_zone,
      const char* method_name);

  DECL_PRINTER(JSTemporalTimeZone)

  DEFINE_TORQUE_GENERATED_JS_TEMPORAL_TIME_ZONE_FLAGS()
  DEFINE_TORQUE_GENERATED_JS_TEMPORAL_TIME_ZONE_SUB_MILLISECONDS()

  DECL_BOOLEAN_ACCESSORS(is_offset)
  DECL_INT_ACCESSORS(offset_milliseconds_or_time_zone_index)

  DECLARE_TEMPORAL_INLINE_GETTER_SETTER(offset_milliseconds)
  DECLARE_TEMPORAL_INLINE_GETTER_SETTER(offset_sub_milliseconds)

  int32_t time_zone_index() const;
  static constexpr int32_t kUTCTimeZoneIndex = 0;

  int64_t offset_nanoseconds() const;
  void set_offset_nanoseconds(int64_t offset_nanoseconds);

  MaybeHandle<String> id(Isolate* isolate) const;

  TQ_OBJECT_CONSTRUCTORS(JSTemporalTimeZone)
};

class JSTemporalZonedDateTime
    : public TorqueGeneratedJSTemporalZonedDateTime<JSTemporalZonedDateTime,
                                                    JSObject> {
 public:
  // #sec-temporal.zoneddatetime
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalZonedDateTime> Constructor(
      Isolate* isolate, Handle<JSFunction> target,
      Handle<HeapObject> new_target, Handle<Object> epoch_nanoseconds,
      Handle<Object> time_zone_like, Handle<Object> calendar_like);

  // #sec-temporal.zoneddatetime.from
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalZonedDateTime> From(
      Isolate* isolate, Handle<Object> item, Handle<Object> options);

  // #sec-temporal.zoneddatetime.compare
  V8_WARN_UNUSED_RESULT static MaybeHandle<Smi> Compare(Isolate* isolate,
                                                        Handle<Object> one,
                                                        Handle<Object> two);

  // #sec-temporal.zoneddatetime.prototype.equals
  V8_WARN_UNUSED_RESULT static MaybeHandle<Oddball> Equals(
      Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
      Handle<Object> other);

  // #sec-temporal.zoneddatetime.prototype.with
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalZonedDateTime> With(
      Isolate* isolate, Handle<JSTemporalZonedDateTime> zoned_date_time,
      Handle<Object> temporal_zoned_date_time_like, Handle<Object> options);

  // #sec-temporal.zoneddatetime.prototype.withcalendar
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalZonedDateTime>
  WithCalendar(Isolate* isolate,
               DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
               Handle<Object> calendar_like);

  // #sec-temporal.zoneddatetime.prototype.withplaindate
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalZonedDateTime>
  WithPlainDate(Isolate* isolate,
                DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
                Handle<Object> plain_date_like);

  // #sec-temporal.zoneddatetime.prototype.withplaintime
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalZonedDateTime>
  WithPlainTime(Isolate* isolate,
                DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
                Handle<Object> plain_time_like);

  // #sec-temporal.zoneddatetime.prototype.withtimezone
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalZonedDateTime>
  WithTimeZone(Isolate* isolate,
               DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
               Handle<Object> time_zone_like);

  // #sec-get-temporal.zoneddatetime.prototype.hoursinday
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> HoursInDay(
      Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time);

  // #sec-temporal.zoneddatetime.prototype.round
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalZonedDateTime> Round(
      Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
      Handle<Object> round_to);

  // #sec-temporal.zoneddatetime.prototype.until
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalDuration> Until(
      Isolate* isolate, Handle<JSTemporalZonedDateTime> date_time,
      Handle<Object> other, Handle<Object> options);

  // #sec-temporal.zoneddatetime.prototype.since
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalDuration> Since(
      Isolate* isolate, Handle<JSTemporalZonedDateTime> date_time,
      Handle<Object> other, Handle<Object> options);

  // #sec-temporal.zoneddatetime.prototype.add
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalZonedDateTime> Add(
      Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
      Handle<Object> temporal_duration_like, Handle<Object> options);

  // #sec-temporal.zoneddatetime.prototype.subtract
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalZonedDateTime> Subtract(
      Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
      Handle<Object> temporal_duration_like, Handle<Object> options);

  // #sec-temporal.zoneddatetime.prototype.getisofields
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSReceiver> GetISOFields(
      Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time);

  // #sec-temporal.zoneddatetime.prototype.toplainyearmonth
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalPlainYearMonth>
  ToPlainYearMonth(Isolate* isolate,
                   DirectHandle<JSTemporalZonedDateTime> zoned_date_time);

  // #sec-temporal.zoneddatetime.prototype.toplainmonthday
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalPlainMonthDay>
  ToPlainMonthDay(Isolate* isolate,
                  DirectHandle<JSTemporalZonedDateTime> zoned_date_time);

  // #sec-temporal.now.zoneddatetime
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalZonedDateTime> Now(
      Isolate* isolate, Handle<Object> calendar_like,
      Handle<Object> temporal_time_zone_like);

  // #sec-temporal.now.zoneddatetimeiso
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalZonedDateTime> NowISO(
      Isolate* isolate, Handle<Object> temporal_time_zone_like);

  // #sec-get-temporal.zoneddatetime.prototype.offsetnanoseconds
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> OffsetNanoseconds(
      Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time);

  // #sec-get-temporal.zoneddatetime.prototype.offset
  V8_WARN_UNUSED_RESULT static MaybeHandle<String> Offset(
      Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time);

  // #sec-temporal.zoneddatetime.prototype.startofday
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalZonedDateTime> StartOfDay(
      Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time);

  // #sec-temporal.zoneddatetime.prototype.toinstant
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalInstant> ToInstant(
      Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time);

  // #sec-temporal.zoneddatetime.prototype.toplaindate
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalPlainDate> ToPlainDate(
      Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time);

  // #sec-temporal.zoneddatetime.prototype.toplaintime
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalPlainTime> ToPlainTime(
      Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time);

  // #sec-temporal.zoneddatetime.prototype.toplaindatetime
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSTemporalPlainDateTime>
  ToPlainDateTime(Isolate* isolate,
                  DirectHandle<JSTemporalZonedDateTime> zoned_date_time);

  // #sec-temporal.zoneddatetime.prototype.tojson
  V8_WARN_UNUSED_RESULT static MaybeHandle<String> ToJSON(
      Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time);

  // #sec-temporal.zoneddatetime.prototype.tolocalestring
  V8_WARN_UNUSED_RESULT static MaybeHandle<String> ToLocaleString(
      Isolate* isolate, Handle<JSTemporalZonedDateTime> zoned_date_time,
      Handle<Object> locales, Handle<Object> options);

  // #sec-temporal.zoneddatetime.prototype.tostring
  V8_WARN_UNUSED_RESULT static MaybeHandle<String> ToString(
      Isolate* isolate, DirectHandle<JSTemporalZonedDateTime> zoned_date_time,
      Handle<Object> options);

  DECL_PRINTER(JSTemporalZonedDateTime)

  TQ_OBJECT_CONSTRUCTORS(JSTemporalZonedDateTime)
};

namespace temporal {

struct DateRecord {
  int32_t year;
  int32_t month;
  int32_t day;
};

struct TimeRecord {
  int32_t hour;
  int32_t minute;
  int32_t second;
  int32_t millisecond;
  int32_t microsecond;
  int32_t nanosecond;
};

struct DateTimeRecord {
  DateRecord date;
  TimeRecord time;
};

// #sec-temporal-createtemporaldatetime
V8_WARN_UNUSED_RESULT MaybeHandle<JSTemporalPlainDateTime>
CreateTemporalDateTime(Isolate* isolate, const DateTimeRecord& date_time,
                       DirectHandle<JSReceiver> calendar);

// #sec-temporal-createtemporaltimezone
MaybeHandle<JSTemporalTimeZone> CreateTemporalTimeZone(
    Isolate* isolate, Handle<String> identifier);

// #sec-temporal-createtemporalinstant
V8_WARN_UNUSED_RESULT MaybeHandle<JSTemporalInstant> CreateTemporalInstant(
    Isolate* isolate, Handle<JSFunction> target, Handle<HeapObject> new_target,
    DirectHandle<BigInt> epoch_nanoseconds);
V8_WARN_UNUSED_RESULT MaybeHandle<JSTemporalInstant> CreateTemporalInstant(
    Isolate* isolate, DirectHandle<BigInt> epoch_nanoseconds);

// #sec-temporal-calendaryear
#define DECLARE_CALENDAR_ABSTRACT_INT_OPERATION(Name)    \
  V8_WARN_UNUSED_RESULT MaybeHandle<Smi> Calendar##Name( \
      Isolate* isolate, Handle<JSReceiver> calendar,     \
      Handle<JSReceiver> date_like);
#define DECLARE_CALENDAR_ABSTRACT_OPERATION(Name)           \
  V8_WARN_UNUSED_RESULT MaybeHandle<Object> Calendar##Name( \
      Isolate* isolate, Handle<JSReceiver> calendar,        \
      Handle<JSReceiver> date_like);
DECLARE_CALENDAR_ABSTRACT_INT_OPERATION(Year)
DECLARE_CALENDAR_ABSTRACT_INT_OPERATION(Month)
DECLARE_CALENDAR_ABSTRACT_OPERATION(MonthCode)
DECLARE_CALENDAR_ABSTRACT_INT_OPERATION(Day)
DECLARE_CALENDAR_ABSTRACT_OPERATION(DayOfWeek)
DECLARE_CALENDAR_ABSTRACT_OPERATION(DayOfYear)
DECLARE_CALENDAR_ABSTRACT_OPERATION(WeekOfYear)
DECLARE_CALENDAR_ABSTRACT_OPERATION(DaysInWeek)
DECLARE_CALENDAR_ABSTRACT_OPERATION(DaysInMonth)
DECLARE_CALENDAR_ABSTRACT_OPERATION(DaysInYear)
DECLARE_CALENDAR_ABSTRACT_OPERATION(MonthsInYear)
DECLARE_CALENDAR_ABSTRACT_OPERATION(InLeapYear)

#ifdef V8_INTL_SUPPORT
DECLARE_CALENDAR_ABSTRACT_OPERATION(Era)
DECLARE_CALENDAR_ABSTRACT_OPERATION(EraYear)
#endif  //  V8_INTL_SUPPORT

#undef DECLARE_CALENDAR_ABSTRACT_OPERATION

// #sec-temporal-getiso8601calendar
Handle<JSTemporalCalendar> GetISO8601Calendar(Isolate* isolate);

// #sec-temporal-builtintimezonegetplaindatetimefor
V8_WARN_UNUSED_RESULT MaybeHandle<JSTemporalPlainDateTime>
BuiltinTimeZoneGetPlainDateTimeFor(Isolate* isolate,
                                   Handle<JSReceiver> time_zone,
                                   Handle<JSTemporalInstant> instant,
                                   DirectHandle<JSReceiver> calendar,
                                   const char* method_name);

V8_WARN_UNUSED_RESULT MaybeHandle<Object> InvokeCalendarMethod(
    Isolate* isolate, Handle<JSReceiver> calendar, Handle<String> name,
    Handle<JSReceiver> temporal_like);

V8_WARN_UNUSED_RESULT MaybeHandle<JSReceiver> ToTemporalCalendar(
    Isolate* isolate, Handle<Object> temporal_calendar_like,
    const char* method_name);

V8_WARN_UNUSED_RESULT MaybeHandle<JSReceiver> ToTemporalTimeZone(
    Isolate* isolate, Handle<Object> temporal_time_zone_like,
    const char* method_name);

V8_WARN_UNUSED_RESULT MaybeHandle<Oddball> IsInvalidTemporalCalendarField(
    Isolate* isolate, Handle<String> string,
    DirectHandle<FixedArray> field_names);

// #sec-temporal-getbuiltincalendar
V8_WARN_UNUSED_RESULT MaybeHandle<JSTemporalCalendar> GetBuiltinCalendar(
    Isolate* isolate, Handle<String> id);

MaybeHandle<JSTemporalInstant> BuiltinTimeZoneGetInstantForCompatible(
    Isolate* isolate, Handle<JSReceiver> time_zone,
    Handle<JSTemporalPlainDateTime> date_time, const char* method_name);

// For Intl.DurationFormat

// #sec-temporal-time-duration-records
struct TimeDurationRecord {
  double days;
  double hours;
  double minutes;
  double seconds;
  double milliseconds;
  double microseconds;
  double nanoseconds;

  // #sec-temporal-createtimedurationrecord
  static Maybe<TimeDurationRecord> Create(Isolate* isolate, double days,
                                          double hours, double minutes,
                                          double seconds, double milliseconds,
                                          double microseconds,
                                          double nanoseconds);
};

// #sec-temporal-duration-records
// Cannot reuse DateDurationRecord here due to duplicate days.
struct DurationRecord {
  double years;
  double months;
  double weeks;
  TimeDurationRecord time_duration;
  // #sec-temporal-createdurationrecord
  static Maybe<DurationRecord> Create(Isolate* isolate, double years,
                                      double months, double weeks, double days,
                                      double hours, double minutes,
                                      double seconds, double milliseconds,
                                      double microseconds, double nanoseconds);

  static int32_t Sign(const DurationRecord& dur);
};

// #sec-temporal-topartialduration
Maybe<DurationRecord> ToPartialDuration(
    Isolate* isolate, Handle<Object> temporal_duration_like_obj,
    const DurationRecord& input);

// #sec-temporal-isvalidduration
bool IsValidDuration(Isolate* isolate, const DurationRecord& dur);

}  // namespace temporal
}  // namespace internal
}  // namespace v8
#include "src/objects/object-macros-undef.h"
#endif  // V8_OBJECTS_JS_TEMPORAL_OBJECTS_H_
```