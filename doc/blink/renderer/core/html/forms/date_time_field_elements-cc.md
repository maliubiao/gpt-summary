Response:
The user wants to understand the functionality of the `date_time_field_elements.cc` file in the Chromium Blink rendering engine. I need to analyze the code and identify the purpose of each class defined in this file. Specifically, I need to:

1. **List the functionalities**: Describe what each class in the file does. These classes seem related to handling different parts of date and time input fields.
2. **Relate to HTML, CSS, and JavaScript**:  Explain how these C++ classes interact with web technologies. Consider how these elements manifest in HTML forms, how they might be styled with CSS, and how JavaScript might interact with them.
3. **Provide logical reasoning with input/output examples**: For some of the more complex classes (like the hour fields), illustrate their behavior with examples. Show what input to the class results in what kind of internal state change or output.
4. **Highlight common usage errors**: Identify potential mistakes developers or users might make when interacting with these date/time fields in a web context.
这个文件 `date_time_field_elements.cc` 是 Chromium Blink 引擎中负责处理 HTML 表单中日期和时间相关输入元素的核心代码。它定义了多个 C++ 类，这些类代表了日期和时间输入控件的不同组成部分，例如月份、日期、年份、小时、分钟、秒、AM/PM 等。

**主要功能列举:**

1. **定义日期和时间字段元素的基类和子类:** 该文件定义了各种用于表示日期和时间字段的 C++ 类，这些类继承自更通用的 `DateTimeFieldElement` 和 `DateTimeNumericFieldElement` 或 `DateTimeSymbolicFieldElement`。
    * `DateTimeAMPMFieldElement`:  表示 AM/PM 选择字段。
    * `DateTimeDayFieldElement`: 表示日期（月份中的第几天）字段。
    * `DateTimeHourFieldBase`:  作为小时字段的基类。
    * `DateTimeHour11FieldElement`: 表示 12 小时制的小时字段（0-11）。
    * `DateTimeHour12FieldElement`: 表示 12 小时制的小时字段（1-12）。
    * `DateTimeHour23FieldElement`: 表示 24 小时制的小时字段（0-23）。
    * `DateTimeHour24FieldElement`: 表示 24 小时制的小时字段（1-24）。
    * `DateTimeMillisecondFieldElement`: 表示毫秒字段。
    * `DateTimeMinuteFieldElement`: 表示分钟字段。
    * `DateTimeMonthFieldElement`: 表示月份数字字段。
    * `DateTimeSecondFieldElement`: 表示秒字段。
    * `DateTimeSymbolicMonthFieldElement`: 表示月份符号字段（例如，"January", "February"）。
    * `DateTimeWeekFieldElement`: 表示一年中的第几周字段。
    * `DateTimeYearFieldElement`: 表示年份字段。

2. **管理字段的值和范围:** 这些类负责存储和管理其表示的日期或时间部分的值。它们还定义了允许的取值范围（例如，月份是 1-12，小时是 0-23 或 1-12）。

3. **与 `DateTimeFieldsState` 交互:**  这些类与 `DateTimeFieldsState` 类协同工作，`DateTimeFieldsState` 用于存储整个日期和时间输入控件的状态。每个字段元素都有方法 (`PopulateDateTimeFieldsState` 和 `SetValueAsDateTimeFieldsState`) 来更新和从 `DateTimeFieldsState` 中读取其对应的值。

4. **与 `DateComponents` 交互:** 这些类可以从 `DateComponents` 对象中设置其值，并将它们的值同步到 `DateComponents` 对象中。 `DateComponents` 是一个用于表示日期和时间的平台无关的结构。

5. **处理输入和值更新:** 这些类处理用户在日期和时间字段中的输入，并更新其内部值。它们还负责在值发生变化时通知其所有者 (`FieldOwner`)。

6. **支持本地化:**  通过使用 `Locale::DefaultLocale().QueryString()`，这些类可以获取本地化的字符串，例如辅助功能文本。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * 这些 C++ 类对应于 HTML5 中新的日期和时间输入类型，例如 `<input type="date">`, `<input type="time">`, `<input type="datetime-local">`, `<input type="month">`, `<input type="week">` 等。
    * 例如，当 HTML 中有一个 `<input type="time">` 元素时，Blink 引擎可能会创建 `DateTimeHour11FieldElement` 或 `DateTimeHour23FieldElement` 的实例来处理小时部分的输入。`<input type="month">` 可能会对应 `DateTimeMonthFieldElement` 或 `DateTimeSymbolicMonthFieldElement`。
    *  `<input type="time">` 元素中可能会包含不同的子元素来表示小时、分钟和 AM/PM，这些子元素分别对应着这里定义的不同的 FieldElement 类。

* **CSS:**
    * 虽然这些 C++ 代码本身不涉及 CSS 样式，但它们定义的元素的呈现方式可以通过 CSS 来定制。
    * 例如，可以使用 CSS 选择器（如 `-webkit-datetime-edit-ampm-field`, `-webkit-datetime-edit-day-field` 等，在代码中以伪元素 ID 的形式定义）来为日期和时间输入控件的不同部分设置样式，例如字体、颜色、边距等。
    * 示例：
      ```css
      input::-webkit-datetime-edit-hour-field {
        color: blue;
      }
      ```
      这段 CSS 将会把时间输入框的小时字段文字颜色设置为蓝色。

* **JavaScript:**
    * JavaScript 可以通过 DOM API 与这些日期和时间输入元素进行交互。
    * 可以使用 JavaScript 获取或设置输入元素的值 (`element.value`)，这将最终反映在这些 C++ 类的内部状态中。
    * JavaScript 还可以监听输入元素的 `change` 事件，以便在用户更改日期或时间时执行某些操作。
    * 示例：
      ```javascript
      const timeInput = document.querySelector('input[type="time"]');
      timeInput.addEventListener('change', () => {
        console.log('时间已更改:', timeInput.value);
      });
      ```
      这段 JavaScript 代码监听时间输入框的 `change` 事件，并在时间发生改变时将新的值打印到控制台。

**逻辑推理与假设输入输出举例:**

**假设输入:** 用户在一个 `<input type="time">` 元素的小时字段中输入了 "10"，并且该时间输入框是 12 小时制。

**处理过程 (可能涉及 `DateTimeHour12FieldElement`):**

1. 用户输入 "10"。
2. `DateTimeHour12FieldElement` 接收到输入。
3. `SetValueAsInteger(10)` 方法被调用。
4. 由于范围是 1-12，输入有效。
5. 内部状态更新，小时值设置为 10。
6. 如果 AM/PM 字段为 "AM"，则 `DateTimeFieldsState` 的小时部分可能设置为 10。如果 AM/PM 字段为 "PM"，则可能设置为 22。

**假设输入:** 用户在一个 `<input type="date">` 元素的月份字段中输入了 "13"。

**处理过程 (可能涉及 `DateTimeMonthFieldElement`):**

1. 用户输入 "13"。
2. `DateTimeMonthFieldElement` 接收到输入。
3. `SetValueAsInteger(13)` 方法被调用。
4. 由于月份的有效范围是 1-12，输入无效。
5. 输入可能被拒绝，或者值被限制在有效范围内（例如，回滚到 12）。具体的行为取决于浏览器的实现。

**用户或编程常见的使用错误举例:**

1. **未正确设置输入元素的 `type` 属性:** 如果开发者忘记将 `<input>` 元素的 `type` 属性设置为 `date`, `time`, `datetime-local` 等，浏览器将不会将其渲染为日期或时间选择器，这些 C++ 类也不会被有效地使用。

   ```html
   <!-- 错误示例 -->
   <input>
   ```

2. **JavaScript 中错误地处理日期和时间字符串:** 当使用 JavaScript 获取或设置日期和时间输入框的值时，需要注意字符串的格式。不同的浏览器或本地化设置可能使用不同的日期和时间格式。

   ```javascript
   // 假设日期输入框的值是 "2023-10-27"
   const dateInput = document.querySelector('input[type="date"]');
   const dateValue = dateInput.value; // dateValue 是 "2023-10-27"

   // 错误地尝试创建 Date 对象，可能导致解析错误
   const wrongDate = new Date(dateValue);
   ```

3. **CSS 样式冲突导致日期和时间控件显示异常:** 开发者可能会应用一些全局 CSS 样式，意外地影响到日期和时间输入控件的内部结构，导致显示错乱或功能异常。例如，过度使用 `!important` 可能会覆盖浏览器默认样式。

4. **假设日期和时间输入框在所有浏览器中行为一致:** 虽然 HTML5 定义了日期和时间输入类型，但不同浏览器在实现上可能存在细微差别，例如对无效输入的处理、默认的日期格式等。开发者应该进行跨浏览器测试。

5. **不理解不同日期和时间输入类型的差异:** 例如，混淆了 `<input type="datetime-local">` 和 `<input type="datetime">` 的区别，前者没有时区信息，后者已弃用。错误地使用会导致日期和时间信息丢失或不准确。

总而言之，`date_time_field_elements.cc` 文件是 Blink 引擎中处理 HTML 日期和时间输入的核心，它定义了各种 C++ 类来表示和管理这些输入的各个组成部分，并负责与内部数据结构和外部接口进行交互。理解这些类的功能有助于理解浏览器如何解析和处理用户在网页上输入的日期和时间信息。

### 提示词
```
这是目录为blink/renderer/core/html/forms/date_time_field_elements.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/html/forms/date_time_field_elements.h"

#include "third_party/blink/renderer/core/html/forms/date_time_field_element.h"
#include "third_party/blink/renderer/core/html/forms/date_time_fields_state.h"
#include "third_party/blink/renderer/platform/text/date_components.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"
#include "ui/strings/grit/ax_strings.h"

namespace blink {

static String QueryString(int resource_id) {
  return Locale::DefaultLocale().QueryString(resource_id);
}

DateTimeAMPMFieldElement::DateTimeAMPMFieldElement(
    Document& document,
    FieldOwner& field_owner,
    const Vector<String>& ampm_labels)
    : DateTimeSymbolicFieldElement(document,
                                   field_owner,
                                   DateTimeField::kAMPM,
                                   ampm_labels,
                                   0,
                                   1) {
  DEFINE_STATIC_LOCAL(AtomicString, ampm_pseudo_id,
                      ("-webkit-datetime-edit-ampm-field"));
  Initialize(ampm_pseudo_id, QueryString(IDS_AX_AM_PM_FIELD_TEXT));
}

void DateTimeAMPMFieldElement::PopulateDateTimeFieldsState(
    DateTimeFieldsState& date_time_fields_state) {
  if (HasValue())
    date_time_fields_state.SetAMPM(ValueAsInteger()
                                       ? DateTimeFieldsState::kAMPMValuePM
                                       : DateTimeFieldsState::kAMPMValueAM);
  else
    date_time_fields_state.SetAMPM(DateTimeFieldsState::kAMPMValueEmpty);
}

void DateTimeAMPMFieldElement::SetValueAsDate(const DateComponents& date) {
  SetValueAsInteger(date.Hour() >= 12 ? 1 : 0);
}

void DateTimeAMPMFieldElement::SetValueAsDateTimeFieldsState(
    const DateTimeFieldsState& date_time_fields_state) {
  if (date_time_fields_state.HasAMPM())
    SetValueAsInteger(date_time_fields_state.Ampm());
  else
    SetEmptyValue();
}

// ----------------------------

DateTimeDayFieldElement::DateTimeDayFieldElement(Document& document,
                                                 FieldOwner& field_owner,
                                                 const String& placeholder,
                                                 const Range& range)
    : DateTimeNumericFieldElement(document,
                                  field_owner,
                                  DateTimeField::kDay,
                                  range,
                                  Range(1, 31),
                                  placeholder.empty() ? "--" : placeholder) {
  DEFINE_STATIC_LOCAL(AtomicString, day_pseudo_id,
                      ("-webkit-datetime-edit-day-field"));
  Initialize(day_pseudo_id, QueryString(IDS_AX_DAY_OF_MONTH_FIELD_TEXT));
}

void DateTimeDayFieldElement::PopulateDateTimeFieldsState(
    DateTimeFieldsState& date_time_fields_state) {
  date_time_fields_state.SetDayOfMonth(
      HasValue() ? ValueAsInteger() : DateTimeFieldsState::kEmptyValue);
}

void DateTimeDayFieldElement::SetValueAsDate(const DateComponents& date) {
  SetValueAsInteger(date.MonthDay());
}

void DateTimeDayFieldElement::SetValueAsDateTimeFieldsState(
    const DateTimeFieldsState& date_time_fields_state) {
  if (!date_time_fields_state.HasDayOfMonth()) {
    SetEmptyValue();
    return;
  }

  const unsigned value = date_time_fields_state.DayOfMonth();
  if (GetRange().IsInRange(static_cast<int>(value))) {
    SetValueAsInteger(value);
    return;
  }

  SetEmptyValue();
}

// ----------------------------

DateTimeHourFieldElementBase::DateTimeHourFieldElementBase(
    Document& document,
    FieldOwner& field_owner,
    const Range& range,
    const Range& hard_limits,
    const Step& step)
    : DateTimeNumericFieldElement(document,
                                  field_owner,
                                  DateTimeField::kHour,
                                  range,
                                  hard_limits,
                                  "--",
                                  step) {}

void DateTimeHourFieldElementBase::Initialize() {
  DEFINE_STATIC_LOCAL(AtomicString, hour_pseudo_id,
                      ("-webkit-datetime-edit-hour-field"));
  DateTimeNumericFieldElement::Initialize(hour_pseudo_id,
                                          QueryString(IDS_AX_HOUR_FIELD_TEXT));
}

void DateTimeHourFieldElementBase::SetValueAsDate(const DateComponents& date) {
  SetValueAsInteger(date.Hour());
}

void DateTimeHourFieldElementBase::SetValueAsDateTimeFieldsState(
    const DateTimeFieldsState& date_time_fields_state) {
  if (!date_time_fields_state.HasHour()) {
    SetEmptyValue();
    return;
  }

  const int hour12 = date_time_fields_state.Hour();
  if (hour12 < 1 || hour12 > 12) {
    SetEmptyValue();
    return;
  }

  const int hour11 = hour12 == 12 ? 0 : hour12;
  const int hour23 =
      date_time_fields_state.Ampm() == DateTimeFieldsState::kAMPMValuePM
          ? hour11 + 12
          : hour11;
  SetValueAsInteger(hour23);
}
// ----------------------------

namespace {

const DateTimeNumericFieldElement::Range Range11From23(
    const DateTimeNumericFieldElement::Range& hour23_range) {
  DCHECK_GE(hour23_range.minimum, 0);
  DCHECK_LE(hour23_range.maximum, 23);
  DCHECK_LE(hour23_range.minimum, hour23_range.maximum);
  DateTimeNumericFieldElement::Range range(0, 11);
  if (hour23_range.maximum < 12) {
    range = hour23_range;
  } else if (hour23_range.minimum >= 12) {
    range.minimum = hour23_range.minimum - 12;
    range.maximum = hour23_range.maximum - 12;
  }

  return range;
}

}  // namespace

DateTimeHour11FieldElement::DateTimeHour11FieldElement(
    Document& document,
    FieldOwner& field_owner,
    const Range& hour23_range,
    const Step& step)
    : DateTimeHourFieldElementBase(document,
                                   field_owner,
                                   Range11From23(hour23_range),
                                   Range(0, 11),
                                   step) {
  Initialize();
}

void DateTimeHour11FieldElement::PopulateDateTimeFieldsState(
    DateTimeFieldsState& date_time_fields_state) {
  if (!HasValue()) {
    date_time_fields_state.SetHour(DateTimeFieldsState::kEmptyValue);
    return;
  }
  const int value = ValueAsInteger();
  date_time_fields_state.SetHour(value ? value : 12);
}

void DateTimeHour11FieldElement::SetValueAsInteger(
    int value,
    EventBehavior event_behavior) {
  if (value > 12)
    DateTimeNumericFieldElement::HandleAmPmRollover(FieldRolloverType::kToPm);
  value = Range(0, 23).ClampValue(value) % 12;
  DateTimeNumericFieldElement::SetValueAsInteger(value, event_behavior);
}

// ----------------------------

namespace {

const DateTimeNumericFieldElement::Range Range12From23(
    const DateTimeNumericFieldElement::Range& hour23_range) {
  DCHECK_GE(hour23_range.minimum, 0);
  DCHECK_LE(hour23_range.maximum, 23);
  DCHECK_LE(hour23_range.minimum, hour23_range.maximum);
  DateTimeNumericFieldElement::Range range(1, 12);
  if (hour23_range.maximum < 12) {
    range = hour23_range;
  } else if (hour23_range.minimum >= 12) {
    range.minimum = hour23_range.minimum - 12;
    range.maximum = hour23_range.maximum - 12;
  }
  if (!range.minimum)
    range.minimum = 12;
  if (!range.maximum)
    range.maximum = 12;
  if (range.minimum > range.maximum) {
    range.minimum = 1;
    range.maximum = 12;
  }

  return range;
}

}  // namespace

DateTimeHour12FieldElement::DateTimeHour12FieldElement(Document& document,
                                                       FieldOwner& field_owner,
                                                       const Range& range,
                                                       const Step& step)
    : DateTimeHourFieldElementBase(document,
                                   field_owner,
                                   Range12From23(range),
                                   Range(1, 12),
                                   step) {
  Initialize();
}

void DateTimeHour12FieldElement::PopulateDateTimeFieldsState(
    DateTimeFieldsState& date_time_fields_state) {
  date_time_fields_state.SetHour(HasValue() ? ValueAsInteger()
                                            : DateTimeFieldsState::kEmptyValue);
}

void DateTimeHour12FieldElement::SetValueAsInteger(
    int value,
    EventBehavior event_behavior) {
  if (value > 12)
    DateTimeNumericFieldElement::HandleAmPmRollover(FieldRolloverType::kToPm);
  value = Range(0, 24).ClampValue(value) % 12;
  DateTimeNumericFieldElement::SetValueAsInteger(value ? value : 12,
                                                 event_behavior);
}
void DateTimeHour12FieldElement::NotifyOwnerIfStepDownRollOver(bool has_value,
                                                               Step step,
                                                               int old_value,
                                                               int new_value) {
  if (!has_value || old_value == new_value || step.step > 12 ||
      old_value - step.step != new_value)
    return;
  if (old_value > 11 && new_value <= 11)
    HandleAmPmRollover(DateTimeFieldElement::FieldRolloverType::kPastMin);
}
void DateTimeHour12FieldElement::NotifyOwnerIfStepUpRollOver(bool has_value,
                                                             Step step,
                                                             int old_value,
                                                             int new_value) {
  if (!has_value || old_value == new_value || step.step > 12 ||
      old_value + step.step != new_value)
    return;
  if (new_value == 12)
    HandleAmPmRollover(DateTimeFieldElement::FieldRolloverType::kPastMax);
}

// ----------------------------

DateTimeHour23FieldElement::DateTimeHour23FieldElement(
    Document& document,
    FieldOwner& field_owner,
    const Range& hour23_range,
    const Step& step)
    : DateTimeHourFieldElementBase(document,
                                   field_owner,
                                   hour23_range,
                                   Range(0, 23),
                                   step) {
  DCHECK_GE(hour23_range.minimum, 0);
  DCHECK_LE(hour23_range.maximum, 23);
  DCHECK_LE(hour23_range.minimum, hour23_range.maximum);

  Initialize();
}

void DateTimeHour23FieldElement::PopulateDateTimeFieldsState(
    DateTimeFieldsState& date_time_fields_state) {
  if (!HasValue()) {
    date_time_fields_state.SetHour(DateTimeFieldsState::kEmptyValue);
    return;
  }

  const int value = ValueAsInteger();

  date_time_fields_state.SetHour(value % 12 ? value % 12 : 12);
  date_time_fields_state.SetAMPM(value >= 12
                                     ? DateTimeFieldsState::kAMPMValuePM
                                     : DateTimeFieldsState::kAMPMValueAM);
}

void DateTimeHour23FieldElement::SetValueAsInteger(
    int value,
    EventBehavior event_behavior) {
  value = Range(0, 23).ClampValue(value);
  DateTimeNumericFieldElement::SetValueAsInteger(value, event_behavior);
}

// ----------------------------

namespace {

const DateTimeNumericFieldElement::Range Range24From23(
    const DateTimeNumericFieldElement::Range& hour23_range) {
  DCHECK_GE(hour23_range.minimum, 0);
  DCHECK_LE(hour23_range.maximum, 23);
  DCHECK_LE(hour23_range.minimum, hour23_range.maximum);
  DateTimeNumericFieldElement::Range range(
      hour23_range.minimum ? hour23_range.minimum : 24,
      hour23_range.maximum ? hour23_range.maximum : 24);
  if (range.minimum > range.maximum) {
    range.minimum = 1;
    range.maximum = 24;
  }

  return range;
}

}  // namespace

DateTimeHour24FieldElement::DateTimeHour24FieldElement(
    Document& document,
    FieldOwner& field_owner,
    const Range& hour23_range,
    const Step& step)
    : DateTimeHourFieldElementBase(document,
                                   field_owner,
                                   Range24From23(hour23_range),
                                   Range(1, 24),
                                   step) {
  Initialize();
}

void DateTimeHour24FieldElement::PopulateDateTimeFieldsState(
    DateTimeFieldsState& date_time_fields_state) {
  if (!HasValue()) {
    date_time_fields_state.SetHour(DateTimeFieldsState::kEmptyValue);
    return;
  }

  const int value = ValueAsInteger();

  if (value == 24) {
    date_time_fields_state.SetHour(12);
    date_time_fields_state.SetAMPM(DateTimeFieldsState::kAMPMValueAM);
  } else {
    date_time_fields_state.SetHour(value == 12 ? 12 : value % 12);
    date_time_fields_state.SetAMPM(value >= 12
                                       ? DateTimeFieldsState::kAMPMValuePM
                                       : DateTimeFieldsState::kAMPMValueAM);
  }
}

void DateTimeHour24FieldElement::SetValueAsInteger(
    int value,
    EventBehavior event_behavior) {
  value = Range(0, 24).ClampValue(value);
  DateTimeNumericFieldElement::SetValueAsInteger(value ? value : 24,
                                                 event_behavior);
}

// ----------------------------

DateTimeMillisecondFieldElement::DateTimeMillisecondFieldElement(
    Document& document,
    FieldOwner& field_owner,
    const Range& range,
    const Step& step)
    : DateTimeNumericFieldElement(document,
                                  field_owner,
                                  DateTimeField::kMillisecond,
                                  range,
                                  Range(0, 999),
                                  "---",
                                  step) {
  DEFINE_STATIC_LOCAL(AtomicString, millisecond_pseudo_id,
                      ("-webkit-datetime-edit-millisecond-field"));
  Initialize(millisecond_pseudo_id, QueryString(IDS_AX_MILLISECOND_FIELD_TEXT));
}

void DateTimeMillisecondFieldElement::PopulateDateTimeFieldsState(
    DateTimeFieldsState& date_time_fields_state) {
  date_time_fields_state.SetMillisecond(
      HasValue() ? ValueAsInteger() : DateTimeFieldsState::kEmptyValue);
}

void DateTimeMillisecondFieldElement::SetValueAsDate(
    const DateComponents& date) {
  SetValueAsInteger(date.Millisecond());
}

void DateTimeMillisecondFieldElement::SetValueAsDateTimeFieldsState(
    const DateTimeFieldsState& date_time_fields_state) {
  if (!date_time_fields_state.HasMillisecond()) {
    SetEmptyValue();
    return;
  }

  const unsigned value = date_time_fields_state.Millisecond();
  if (value > static_cast<unsigned>(Maximum())) {
    SetEmptyValue();
    return;
  }

  SetValueAsInteger(value);
}

// ----------------------------

DateTimeMinuteFieldElement::DateTimeMinuteFieldElement(Document& document,
                                                       FieldOwner& field_owner,
                                                       const Range& range,
                                                       const Step& step)
    : DateTimeNumericFieldElement(document,
                                  field_owner,
                                  DateTimeField::kMinute,
                                  range,
                                  Range(0, 59),
                                  "--",
                                  step) {
  DEFINE_STATIC_LOCAL(AtomicString, minute_pseudo_id,
                      ("-webkit-datetime-edit-minute-field"));
  Initialize(minute_pseudo_id, QueryString(IDS_AX_MINUTE_FIELD_TEXT));
}

void DateTimeMinuteFieldElement::PopulateDateTimeFieldsState(
    DateTimeFieldsState& date_time_fields_state) {
  date_time_fields_state.SetMinute(
      HasValue() ? ValueAsInteger() : DateTimeFieldsState::kEmptyValue);
}

void DateTimeMinuteFieldElement::SetValueAsDate(const DateComponents& date) {
  SetValueAsInteger(date.Minute());
}

void DateTimeMinuteFieldElement::SetValueAsDateTimeFieldsState(
    const DateTimeFieldsState& date_time_fields_state) {
  if (!date_time_fields_state.HasMinute()) {
    SetEmptyValue();
    return;
  }

  const unsigned value = date_time_fields_state.Minute();
  if (value > static_cast<unsigned>(Maximum())) {
    SetEmptyValue();
    return;
  }

  SetValueAsInteger(value);
}

// ----------------------------

DateTimeMonthFieldElement::DateTimeMonthFieldElement(Document& document,
                                                     FieldOwner& field_owner,
                                                     const String& placeholder,
                                                     const Range& range)
    : DateTimeNumericFieldElement(document,
                                  field_owner,
                                  DateTimeField::kMonth,
                                  range,
                                  Range(1, 12),
                                  placeholder.empty() ? "--" : placeholder) {
  DEFINE_STATIC_LOCAL(AtomicString, month_pseudo_id,
                      ("-webkit-datetime-edit-month-field"));
  Initialize(month_pseudo_id, QueryString(IDS_AX_MONTH_FIELD_TEXT));
}

void DateTimeMonthFieldElement::PopulateDateTimeFieldsState(
    DateTimeFieldsState& date_time_fields_state) {
  date_time_fields_state.SetMonth(
      HasValue() ? ValueAsInteger() : DateTimeFieldsState::kEmptyValue);
}

void DateTimeMonthFieldElement::SetValueAsDate(const DateComponents& date) {
  SetValueAsInteger(date.Month() + 1);
}

void DateTimeMonthFieldElement::SetValueAsDateTimeFieldsState(
    const DateTimeFieldsState& date_time_fields_state) {
  if (!date_time_fields_state.HasMonth()) {
    SetEmptyValue();
    return;
  }

  const unsigned value = date_time_fields_state.Month();
  if (GetRange().IsInRange(static_cast<int>(value))) {
    SetValueAsInteger(value);
    return;
  }

  SetEmptyValue();
}

// ----------------------------

DateTimeSecondFieldElement::DateTimeSecondFieldElement(Document& document,
                                                       FieldOwner& field_owner,
                                                       const Range& range,
                                                       const Step& step)
    : DateTimeNumericFieldElement(document,
                                  field_owner,
                                  DateTimeField::kSecond,
                                  range,
                                  Range(0, 59),
                                  "--",
                                  step) {
  DEFINE_STATIC_LOCAL(AtomicString, second_pseudo_id,
                      ("-webkit-datetime-edit-second-field"));
  Initialize(second_pseudo_id, QueryString(IDS_AX_SECOND_FIELD_TEXT));
}

void DateTimeSecondFieldElement::PopulateDateTimeFieldsState(
    DateTimeFieldsState& date_time_fields_state) {
  date_time_fields_state.SetSecond(
      HasValue() ? ValueAsInteger() : DateTimeFieldsState::kEmptyValue);
}

void DateTimeSecondFieldElement::SetValueAsDate(const DateComponents& date) {
  SetValueAsInteger(date.Second());
}

void DateTimeSecondFieldElement::SetValueAsDateTimeFieldsState(
    const DateTimeFieldsState& date_time_fields_state) {
  if (!date_time_fields_state.HasSecond()) {
    SetEmptyValue();
    return;
  }

  const unsigned value = date_time_fields_state.Second();
  if (value > static_cast<unsigned>(Maximum())) {
    SetEmptyValue();
    return;
  }

  SetValueAsInteger(value);
}

// ----------------------------

DateTimeSymbolicMonthFieldElement::DateTimeSymbolicMonthFieldElement(
    Document& document,
    FieldOwner& field_owner,
    const Vector<String>& labels,
    int minimum,
    int maximum)
    : DateTimeSymbolicFieldElement(document,
                                   field_owner,
                                   DateTimeField::kMonth,
                                   labels,
                                   minimum,
                                   maximum) {
  DEFINE_STATIC_LOCAL(AtomicString, month_pseudo_id,
                      ("-webkit-datetime-edit-month-field"));
  Initialize(month_pseudo_id, QueryString(IDS_AX_MONTH_FIELD_TEXT));
}

void DateTimeSymbolicMonthFieldElement::PopulateDateTimeFieldsState(
    DateTimeFieldsState& date_time_fields_state) {
  if (!HasValue())
    date_time_fields_state.SetMonth(DateTimeFieldsState::kEmptyValue);
  DCHECK_LT(ValueAsInteger(), static_cast<int>(SymbolsSize()));
  date_time_fields_state.SetMonth(ValueAsInteger() + 1);
}

void DateTimeSymbolicMonthFieldElement::SetValueAsDate(
    const DateComponents& date) {
  SetValueAsInteger(date.Month());
}

void DateTimeSymbolicMonthFieldElement::SetValueAsDateTimeFieldsState(
    const DateTimeFieldsState& date_time_fields_state) {
  if (!date_time_fields_state.HasMonth()) {
    SetEmptyValue();
    return;
  }

  const unsigned value = date_time_fields_state.Month() - 1;
  if (value >= SymbolsSize()) {
    SetEmptyValue();
    return;
  }

  SetValueAsInteger(value);
}

// ----------------------------

DateTimeWeekFieldElement::DateTimeWeekFieldElement(Document& document,
                                                   FieldOwner& field_owner,
                                                   const Range& range)
    : DateTimeNumericFieldElement(document,
                                  field_owner,
                                  DateTimeField::kWeek,
                                  range,
                                  Range(DateComponents::kMinimumWeekNumber,
                                        DateComponents::kMaximumWeekNumber),
                                  "--") {
  DEFINE_STATIC_LOCAL(AtomicString, week_pseudo_id,
                      ("-webkit-datetime-edit-week-field"));
  Initialize(week_pseudo_id, QueryString(IDS_AX_WEEK_OF_YEAR_FIELD_TEXT));
}

void DateTimeWeekFieldElement::PopulateDateTimeFieldsState(
    DateTimeFieldsState& date_time_fields_state) {
  date_time_fields_state.SetWeekOfYear(
      HasValue() ? ValueAsInteger() : DateTimeFieldsState::kEmptyValue);
}

void DateTimeWeekFieldElement::SetValueAsDate(const DateComponents& date) {
  SetValueAsInteger(date.Week());
}

void DateTimeWeekFieldElement::SetValueAsDateTimeFieldsState(
    const DateTimeFieldsState& date_time_fields_state) {
  if (!date_time_fields_state.HasWeekOfYear()) {
    SetEmptyValue();
    return;
  }

  const unsigned value = date_time_fields_state.WeekOfYear();
  if (GetRange().IsInRange(static_cast<int>(value))) {
    SetValueAsInteger(value);
    return;
  }

  SetEmptyValue();
}

// ----------------------------

DateTimeYearFieldElement::DateTimeYearFieldElement(
    Document& document,
    FieldOwner& field_owner,
    const DateTimeYearFieldElement::Parameters& parameters)
    : DateTimeNumericFieldElement(
          document,
          field_owner,
          DateTimeField::kYear,
          Range(parameters.minimum_year, parameters.maximum_year),
          Range(DateComponents::MinimumYear(), DateComponents::MaximumYear()),
          parameters.placeholder.empty() ? "----" : parameters.placeholder),
      min_is_specified_(parameters.min_is_specified),
      max_is_specified_(parameters.max_is_specified) {
  DCHECK_GE(parameters.minimum_year, DateComponents::MinimumYear());
  DCHECK_LE(parameters.maximum_year, DateComponents::MaximumYear());

  DEFINE_STATIC_LOCAL(AtomicString, year_pseudo_id,
                      ("-webkit-datetime-edit-year-field"));
  Initialize(year_pseudo_id, QueryString(IDS_AX_YEAR_FIELD_TEXT));
}

static int CurrentFullYear() {
  DateComponents date;
  date.SetMillisecondsSinceEpochForMonth(
      ConvertToLocalTime(base::Time::Now()).InMillisecondsF());
  return date.FullYear();
}

int DateTimeYearFieldElement::DefaultValueForStepDown() const {
  return max_is_specified_
             ? DateTimeNumericFieldElement::DefaultValueForStepDown()
             : CurrentFullYear();
}

int DateTimeYearFieldElement::DefaultValueForStepUp() const {
  return min_is_specified_
             ? DateTimeNumericFieldElement::DefaultValueForStepUp()
             : CurrentFullYear();
}

void DateTimeYearFieldElement::PopulateDateTimeFieldsState(
    DateTimeFieldsState& date_time_fields_state) {
  date_time_fields_state.SetYear(HasValue() ? ValueAsInteger()
                                            : DateTimeFieldsState::kEmptyValue);
}

void DateTimeYearFieldElement::SetValueAsDate(const DateComponents& date) {
  SetValueAsInteger(date.FullYear());
}

void DateTimeYearFieldElement::SetValueAsDateTimeFieldsState(
    const DateTimeFieldsState& date_time_fields_state) {
  if (!date_time_fields_state.HasYear()) {
    SetEmptyValue();
    return;
  }

  const unsigned value = date_time_fields_state.Year();
  if (GetRange().IsInRange(static_cast<int>(value))) {
    SetValueAsInteger(value);
    return;
  }

  SetEmptyValue();
}

}  // namespace blink
```