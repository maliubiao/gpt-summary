Response:
The user wants to understand the functionality of the provided C++ source code file `date_time_edit_element.cc`. I need to:

1. **Identify the core purpose:** Analyze the code to determine what this component does in the Blink rendering engine.
2. **Relate to web technologies:** Explain how this code interacts with HTML, CSS, and JavaScript, providing concrete examples.
3. **Infer logic and provide examples:** Based on the code, deduce the input and output of certain logical operations.
4. **Highlight potential errors:** Identify common mistakes users or programmers might make when using or interacting with this component.
5. **Summarize the functionality:** Concisely describe the role of this code snippet.

Based on the provided code, it seems this file is responsible for creating and managing the interactive date and time input fields within a web form. It handles the layout and behavior of these fields based on the specified format and constraints.
这是 Chromium Blink 引擎中 `date_time_edit_element.cc` 文件的第一部分，主要功能是 **构建和管理日期和时间编辑元素的用户界面 (UI)**。

以下是更详细的功能说明，并结合了与 JavaScript、HTML 和 CSS 的关系，逻辑推理，以及常见错误示例：

**主要功能归纳:**

* **创建和排列日期/时间字段:**  该文件负责根据指定的日期/时间格式（例如 "MM/DD/YYYY", "HH:mm:ss"）创建相应的 UI 元素来编辑日期和时间的不同部分（年、月、日、时、分、秒、毫秒、AM/PM 等）。
* **应用本地化格式:** 它使用 `DateTimeFormat` 类来解析格式字符串，并根据用户的本地化设置（例如，日期分隔符、月份名称、AM/PM 标签）来渲染 UI。
* **处理字段的约束:**  该代码会考虑 `<input>` 元素的 `min`、`max` 和 `step` 属性，来设置日期/时间字段的有效范围和步进值，并在 UI 上反映这些约束（例如，禁用超出范围的月份或年份）。
* **管理字段的状态:** 它跟踪各个字段的禁用状态，这可能取决于 `min`、`max` 和 `step` 属性的设置，以及当前已选的值。
* **与焦点管理交互:**  代码涉及到字段的聚焦和失焦处理，以便用户可以使用键盘导航和输入。
* **提供字段值的访问:** 尽管这部分代码没有直接展示，但可以推断出它提供了访问和设置各个字段值的方法，以便与底层的数据模型同步。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**
    * **`<input type="date">`, `<input type="time">`, `<input type="datetime-local">` 等:**  这个 C++ 代码是这些 HTML 表单控件在 Blink 渲染引擎中的具体实现的一部分。当浏览器解析到这些 HTML 标签时，会调用 Blink 引擎的相关代码来创建并管理其 UI。
    * **Shadow DOM:** 代码中使用了 `SetShadowPseudoId`，表明这些日期/时间编辑元素的内部结构是使用 Shadow DOM 构建的。这使得浏览器的默认样式和脚本能够封装起来，并允许开发者通过 CSS pseudo-elements (例如 `::-webkit-datetime-edit-field`) 来定制样式。
    * **示例:**  当你在 HTML 中写下 `<input type="date">`，Blink 引擎会利用 `DateTimeEditElement` 来渲染出年、月、日的选择框或输入框。

* **JavaScript:**
    * **事件处理:**  虽然这部分代码没有直接展示 JavaScript 交互，但可以推断出它会触发或监听 JavaScript 事件，例如 `change` 事件，当用户修改了日期或时间值时。
    * **DOM 操作:** JavaScript 可以通过 DOM API 获取到这些 `<input>` 元素，并读取或设置它们的值。Blink 引擎中的 `DateTimeEditElement` 需要与这些操作保持同步。
    * **示例:**  JavaScript 可以通过 `document.getElementById('myDate').value` 获取日期输入框的值，或者使用 `element.addEventListener('change', ...)` 监听值改变事件。

* **CSS:**
    * **样式定制:**  CSS 可以通过 Shadow DOM 的 pseudo-elements 来定制日期/时间编辑元素的样式，例如改变字段的颜色、边框、字体等。
    * **布局控制:** CSS 用于控制各个字段的排列方式（水平或垂直），间距等。
    * **示例:**  可以使用 CSS  `input[type="date"]::-webkit-calendar-picker-indicator` 来定制日期选择器的图标。

**逻辑推理与假设输入/输出:**

**假设输入:**

* **日期/时间格式字符串:**  "yyyy-MM-dd"
* **最小日期:** 2023-01-01
* **最大日期:** 2023-01-31
* **当前日期:** 2023-01-15

**逻辑推理:**

* `DateTimeEditBuilder` 会解析格式字符串 "yyyy-MM-dd"。
* 它会创建三个字段：一个年份字段，一个月份字段，一个日期字段。
* 年份字段的范围会被限制在 2023。
* 月份字段的范围会被限制在 01。
* 日期字段的范围会被限制在 01 到 31。
* 初始时，这些字段会显示当前日期 2023-01-15。

**可能的输出 (UI 呈现):**

一个包含三个可编辑字段的 UI 元素，可能如下所示：

```
[ 2023 ] - [ 01 ] - [ 15 ]
```

**用户或编程常见的使用错误:**

* **HTML 属性设置错误:**
    * **`min` 和 `max` 属性格式不正确:** 例如，`<input type="date" min="2023/01/01">`，日期格式应该符合 ISO 8601 (YYYY-MM-DD)。
    * **`step` 属性值不合法:**  例如，对于 `<input type="time">`，`step` 应该是一个表示秒数的正数。

* **JavaScript 操作错误:**
    * **尝试设置超出 `min` 或 `max` 范围的值:**  例如，如果 `min="2023-01-01"`，尝试通过 JavaScript 设置 `input.value = "2022-12-31"`。
    * **错误地假设日期/时间格式:** JavaScript 获取到的 `value` 始终是特定格式的字符串，需要进行正确的解析和格式化才能使用。

* **CSS 样式问题:**
    * **过度定制导致 UI 不可用:**  例如，将所有字段的文字颜色设置为背景色，导致用户无法看清输入的内容。
    * **错误地使用了 Shadow DOM pseudo-elements:**  可能使用了不正确的 pseudo-element 名称，或者在不支持 Shadow DOM 的浏览器上使用。

**对第一部分的总结:**

`date_time_edit_element.cc` 的第一部分主要负责根据指定的格式和约束，动态构建和初始化日期和时间编辑元素的 UI 结构。它涉及到解析格式字符串，创建并排列不同的日期/时间字段，并根据 `min`, `max`, `step` 等属性设置字段的初始状态和约束。  它为后续的用户交互和数据处理奠定了基础。

Prompt: 
```
这是目录为blink/renderer/core/html/forms/date_time_edit_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
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

#include "third_party/blink/renderer/core/html/forms/date_time_edit_element.h"

#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/frame/use_counter_impl.h"
#include "third_party/blink/renderer/core/html/forms/date_time_field_elements.h"
#include "third_party/blink/renderer/core/html/forms/date_time_fields_state.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/text_utils.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/text/date_time_format.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"

namespace blink {

class DateTimeEditBuilder : private DateTimeFormat::TokenHandler {
 public:
  // The argument objects must be alive until this object dies.
  DateTimeEditBuilder(DateTimeEditElement&,
                      const DateTimeEditElement::LayoutParameters&,
                      const DateComponents&);

  bool Build(const String&);

 private:
  bool NeedMillisecondField() const;
  bool ShouldAMPMFieldDisabled() const;
  bool ShouldDayOfMonthFieldDisabled() const;
  bool ShouldHourFieldDisabled() const;
  bool ShouldMillisecondFieldDisabled() const;
  bool ShouldMinuteFieldDisabled() const;
  bool ShouldSecondFieldDisabled() const;
  bool ShouldYearFieldDisabled() const;
  inline const StepRange& GetStepRange() const {
    return parameters_.step_range;
  }
  DateTimeNumericFieldElement::Step CreateStep(double ms_per_field_unit,
                                               double ms_per_field_size) const;

  // DateTimeFormat::TokenHandler functions.
  void VisitField(DateTimeFormat::FieldType, int) final;
  void VisitLiteral(const String&) final;

  DateTimeEditElement& EditElement() const;

  DateTimeEditElement* edit_element_;
  const DateComponents date_value_;
  const DateTimeEditElement::LayoutParameters& parameters_;
  DateTimeNumericFieldElement::Range day_range_;
  DateTimeNumericFieldElement::Range hour23_range_;
  DateTimeNumericFieldElement::Range minute_range_;
  DateTimeNumericFieldElement::Range second_range_;
  DateTimeNumericFieldElement::Range millisecond_range_;
};

DateTimeEditBuilder::DateTimeEditBuilder(
    DateTimeEditElement& element,
    const DateTimeEditElement::LayoutParameters& layout_parameters,
    const DateComponents& date_value)
    : edit_element_(&element),
      date_value_(date_value),
      parameters_(layout_parameters),
      day_range_(1, 31),
      hour23_range_(0, 23),
      minute_range_(0, 59),
      second_range_(0, 59),
      millisecond_range_(0, 999) {
  if (date_value_.GetType() == DateComponents::kDate ||
      date_value_.GetType() == DateComponents::kDateTimeLocal) {
    if (parameters_.minimum.GetType() != DateComponents::kInvalid &&
        parameters_.maximum.GetType() != DateComponents::kInvalid &&
        parameters_.minimum.FullYear() == parameters_.maximum.FullYear() &&
        parameters_.minimum.Month() == parameters_.maximum.Month() &&
        parameters_.minimum.MonthDay() <= parameters_.maximum.MonthDay()) {
      day_range_.minimum = parameters_.minimum.MonthDay();
      day_range_.maximum = parameters_.maximum.MonthDay();
    }
  }

  if (date_value_.GetType() == DateComponents::kTime ||
      day_range_.IsSingleton()) {
    if (parameters_.minimum.GetType() != DateComponents::kInvalid &&
        parameters_.maximum.GetType() != DateComponents::kInvalid &&
        parameters_.minimum.Hour() <= parameters_.maximum.Hour()) {
      hour23_range_.minimum = parameters_.minimum.Hour();
      hour23_range_.maximum = parameters_.maximum.Hour();
    }
  }

  if (hour23_range_.IsSingleton() &&
      parameters_.minimum.Minute() <= parameters_.maximum.Minute()) {
    minute_range_.minimum = parameters_.minimum.Minute();
    minute_range_.maximum = parameters_.maximum.Minute();
  }
  if (minute_range_.IsSingleton() &&
      parameters_.minimum.Second() <= parameters_.maximum.Second()) {
    second_range_.minimum = parameters_.minimum.Second();
    second_range_.maximum = parameters_.maximum.Second();
  }
  if (second_range_.IsSingleton() &&
      parameters_.minimum.Millisecond() <= parameters_.maximum.Millisecond()) {
    millisecond_range_.minimum = parameters_.minimum.Millisecond();
    millisecond_range_.maximum = parameters_.maximum.Millisecond();
  }
}

bool DateTimeEditBuilder::Build(const String& format_string) {
  EditElement().ResetFields();

  // Mute UseCounter when constructing the DateTime object, to avoid counting
  // attributes on elements inside the user-agent shadow DOM.
  UseCounterMuteScope scope(EditElement());
  return DateTimeFormat::Parse(format_string, *this);
}

bool DateTimeEditBuilder::NeedMillisecondField() const {
  return date_value_.Millisecond() ||
         !GetStepRange()
              .Minimum()
              .Remainder(static_cast<int>(kMsPerSecond))
              .IsZero() ||
         !GetStepRange()
              .Step()
              .Remainder(static_cast<int>(kMsPerSecond))
              .IsZero();
}

void DateTimeEditBuilder::VisitField(DateTimeFormat::FieldType field_type,
                                     int count) {
  const int kCountForAbbreviatedMonth = 3;
  const int kCountForFullMonth = 4;
  const int kCountForNarrowMonth = 5;
  Document& document = EditElement().GetDocument();

  switch (field_type) {
    case DateTimeFormat::kFieldTypeDayOfMonth: {
      DateTimeFieldElement* field =
          MakeGarbageCollected<DateTimeDayFieldElement>(
              document, EditElement(), parameters_.placeholder_for_day,
              day_range_);
      EditElement().AddField(field);
      if (ShouldDayOfMonthFieldDisabled()) {
        field->SetValueAsDate(date_value_);
        field->SetDisabled();
      }
      return;
    }

    case DateTimeFormat::kFieldTypeHour11: {
      DateTimeNumericFieldElement::Step step =
          CreateStep(kMsPerHour, kMsPerHour * 12);
      DateTimeFieldElement* field =
          MakeGarbageCollected<DateTimeHour11FieldElement>(
              document, EditElement(), hour23_range_, step);
      EditElement().AddField(field);
      if (ShouldHourFieldDisabled()) {
        field->SetValueAsDate(date_value_);
        field->SetDisabled();
      }
      return;
    }

    case DateTimeFormat::kFieldTypeHour12: {
      DateTimeNumericFieldElement::Step step =
          CreateStep(kMsPerHour, kMsPerHour * 12);
      DateTimeFieldElement* field =
          MakeGarbageCollected<DateTimeHour12FieldElement>(
              document, EditElement(), hour23_range_, step);
      EditElement().AddField(field);
      if (ShouldHourFieldDisabled()) {
        field->SetValueAsDate(date_value_);
        field->SetDisabled();
      }
      return;
    }

    case DateTimeFormat::kFieldTypeHour23: {
      DateTimeNumericFieldElement::Step step =
          CreateStep(kMsPerHour, kMsPerDay);
      DateTimeFieldElement* field =
          MakeGarbageCollected<DateTimeHour23FieldElement>(
              document, EditElement(), hour23_range_, step);
      EditElement().AddField(field);
      if (ShouldHourFieldDisabled()) {
        field->SetValueAsDate(date_value_);
        field->SetDisabled();
      }
      return;
    }

    case DateTimeFormat::kFieldTypeHour24: {
      DateTimeNumericFieldElement::Step step =
          CreateStep(kMsPerHour, kMsPerDay);
      DateTimeFieldElement* field =
          MakeGarbageCollected<DateTimeHour24FieldElement>(
              document, EditElement(), hour23_range_, step);
      EditElement().AddField(field);
      if (ShouldHourFieldDisabled()) {
        field->SetValueAsDate(date_value_);
        field->SetDisabled();
      }
      return;
    }

    case DateTimeFormat::kFieldTypeMinute: {
      DateTimeNumericFieldElement::Step step =
          CreateStep(kMsPerMinute, kMsPerHour);
      DateTimeNumericFieldElement* field =
          MakeGarbageCollected<DateTimeMinuteFieldElement>(
              document, EditElement(), minute_range_, step);
      EditElement().AddField(field);
      if (ShouldMinuteFieldDisabled()) {
        field->SetValueAsDate(date_value_);
        field->SetDisabled();
      }
      return;
    }

    case DateTimeFormat::kFieldTypeMonth:  // Fallthrough.
    case DateTimeFormat::kFieldTypeMonthStandAlone: {
      int min_month = 0, max_month = 11;
      if (parameters_.minimum.GetType() != DateComponents::kInvalid &&
          parameters_.maximum.GetType() != DateComponents::kInvalid &&
          parameters_.minimum.FullYear() == parameters_.maximum.FullYear() &&
          parameters_.minimum.Month() <= parameters_.maximum.Month()) {
        min_month = parameters_.minimum.Month();
        max_month = parameters_.maximum.Month();
      }
      DateTimeFieldElement* field;
      switch (count) {
        case kCountForNarrowMonth:  // Fallthrough.
        case kCountForAbbreviatedMonth:
          field = MakeGarbageCollected<DateTimeSymbolicMonthFieldElement>(
              document, EditElement(),
              field_type == DateTimeFormat::kFieldTypeMonth
                  ? parameters_.locale.ShortMonthLabels()
                  : parameters_.locale.ShortStandAloneMonthLabels(),
              min_month, max_month);
          break;
        case kCountForFullMonth:
          field = MakeGarbageCollected<DateTimeSymbolicMonthFieldElement>(
              document, EditElement(),
              field_type == DateTimeFormat::kFieldTypeMonth
                  ? parameters_.locale.MonthLabels()
                  : parameters_.locale.StandAloneMonthLabels(),
              min_month, max_month);
          break;
        default:
          field = MakeGarbageCollected<DateTimeMonthFieldElement>(
              document, EditElement(), parameters_.placeholder_for_month,
              DateTimeNumericFieldElement::Range(min_month + 1, max_month + 1));
          break;
      }
      EditElement().AddField(field);
      if (min_month == max_month && min_month == date_value_.Month() &&
          date_value_.GetType() != DateComponents::kMonth) {
        field->SetValueAsDate(date_value_);
        field->SetDisabled();
      }
      return;
    }

    // TODO(crbug.com/1261272): We don't support UI for
    // kFieldTypePeriodAmPmNoonMidnight and kFieldTypePeriodFlexible. Apply
    // the normal am/pm UI instead.
    case DateTimeFormat::kFieldTypePeriod:
    case DateTimeFormat::kFieldTypePeriodAmPmNoonMidnight:
    case DateTimeFormat::kFieldTypePeriodFlexible: {
      DateTimeFieldElement* field =
          MakeGarbageCollected<DateTimeAMPMFieldElement>(
              document, EditElement(), parameters_.locale.TimeAMPMLabels());
      EditElement().AddField(field);
      if (ShouldAMPMFieldDisabled()) {
        field->SetValueAsDate(date_value_);
        field->SetDisabled();
      }
      return;
    }

    case DateTimeFormat::kFieldTypeSecond: {
      DateTimeNumericFieldElement::Step step =
          CreateStep(kMsPerSecond, kMsPerMinute);
      DateTimeNumericFieldElement* field =
          MakeGarbageCollected<DateTimeSecondFieldElement>(
              document, EditElement(), second_range_, step);
      EditElement().AddField(field);
      if (ShouldSecondFieldDisabled()) {
        field->SetValueAsDate(date_value_);
        field->SetDisabled();
      }

      if (NeedMillisecondField()) {
        VisitLiteral(parameters_.locale.LocalizedDecimalSeparator());
        VisitField(DateTimeFormat::kFieldTypeFractionalSecond, 3);
      }
      return;
    }

    case DateTimeFormat::kFieldTypeFractionalSecond: {
      DateTimeNumericFieldElement::Step step = CreateStep(1, kMsPerSecond);
      DateTimeNumericFieldElement* field =
          MakeGarbageCollected<DateTimeMillisecondFieldElement>(
              document, EditElement(), millisecond_range_, step);
      EditElement().AddField(field);
      if (ShouldMillisecondFieldDisabled()) {
        field->SetValueAsDate(date_value_);
        field->SetDisabled();
      }
      return;
    }

    case DateTimeFormat::kFieldTypeWeekOfYear: {
      DateTimeNumericFieldElement::Range range(
          DateComponents::kMinimumWeekNumber,
          DateComponents::kMaximumWeekNumber);
      if (parameters_.minimum.GetType() != DateComponents::kInvalid &&
          parameters_.maximum.GetType() != DateComponents::kInvalid &&
          parameters_.minimum.FullYear() == parameters_.maximum.FullYear() &&
          parameters_.minimum.Week() <= parameters_.maximum.Week()) {
        range.minimum = parameters_.minimum.Week();
        range.maximum = parameters_.maximum.Week();
      }
      EditElement().AddField(MakeGarbageCollected<DateTimeWeekFieldElement>(
          document, EditElement(), range));
      return;
    }

    case DateTimeFormat::kFieldTypeYear: {
      DateTimeYearFieldElement::Parameters year_params;
      if (parameters_.minimum.GetType() == DateComponents::kInvalid) {
        year_params.minimum_year = DateComponents::MinimumYear();
        year_params.min_is_specified = false;
      } else {
        year_params.minimum_year = parameters_.minimum.FullYear();
        year_params.min_is_specified = true;
      }
      if (parameters_.maximum.GetType() == DateComponents::kInvalid) {
        year_params.maximum_year = DateComponents::MaximumYear();
        year_params.max_is_specified = false;
      } else {
        year_params.maximum_year = parameters_.maximum.FullYear();
        year_params.max_is_specified = true;
      }
      if (year_params.minimum_year > year_params.maximum_year) {
        std::swap(year_params.minimum_year, year_params.maximum_year);
        std::swap(year_params.min_is_specified, year_params.max_is_specified);
      }
      year_params.placeholder = parameters_.placeholder_for_year;
      DateTimeFieldElement* field =
          MakeGarbageCollected<DateTimeYearFieldElement>(
              document, EditElement(), year_params);
      EditElement().AddField(field);
      if (ShouldYearFieldDisabled()) {
        field->SetValueAsDate(date_value_);
        field->SetDisabled();
      }
      return;
    }

    default:
      return;
  }
}

bool DateTimeEditBuilder::ShouldAMPMFieldDisabled() const {
  return ShouldHourFieldDisabled() ||
         (hour23_range_.minimum < 12 && hour23_range_.maximum < 12 &&
          date_value_.Hour() < 12) ||
         (hour23_range_.minimum >= 12 && hour23_range_.maximum >= 12 &&
          date_value_.Hour() >= 12);
}

bool DateTimeEditBuilder::ShouldDayOfMonthFieldDisabled() const {
  return day_range_.IsSingleton() &&
         day_range_.minimum == date_value_.MonthDay() &&
         date_value_.GetType() != DateComponents::kDate;
}

bool DateTimeEditBuilder::ShouldHourFieldDisabled() const {
  if (hour23_range_.IsSingleton() &&
      hour23_range_.minimum == date_value_.Hour() &&
      !(ShouldMinuteFieldDisabled() && ShouldSecondFieldDisabled() &&
        ShouldMillisecondFieldDisabled()))
    return true;

  if (date_value_.GetType() == DateComponents::kTime)
    return false;
  DCHECK_EQ(date_value_.GetType(), DateComponents::kDateTimeLocal);

  if (ShouldDayOfMonthFieldDisabled()) {
    DCHECK_EQ(parameters_.minimum.FullYear(), parameters_.maximum.FullYear());
    DCHECK_EQ(parameters_.minimum.Month(), parameters_.maximum.Month());
    return false;
  }

  const Decimal decimal_ms_per_day(static_cast<int>(kMsPerDay));
  Decimal hour_part_of_minimum =
      (GetStepRange().StepBase().Abs().Remainder(decimal_ms_per_day) /
       static_cast<int>(kMsPerHour))
          .Floor();
  return hour_part_of_minimum == date_value_.Hour() &&
         GetStepRange().Step().Remainder(decimal_ms_per_day).IsZero();
}

bool DateTimeEditBuilder::ShouldMillisecondFieldDisabled() const {
  if (millisecond_range_.IsSingleton() &&
      millisecond_range_.minimum == date_value_.Millisecond())
    return true;

  const Decimal decimal_ms_per_second(static_cast<int>(kMsPerSecond));
  return GetStepRange().StepBase().Abs().Remainder(decimal_ms_per_second) ==
             date_value_.Millisecond() &&
         GetStepRange().Step().Remainder(decimal_ms_per_second).IsZero();
}

bool DateTimeEditBuilder::ShouldMinuteFieldDisabled() const {
  if (minute_range_.IsSingleton() &&
      minute_range_.minimum == date_value_.Minute())
    return true;

  const Decimal decimal_ms_per_hour(static_cast<int>(kMsPerHour));
  Decimal minute_part_of_minimum =
      (GetStepRange().StepBase().Abs().Remainder(decimal_ms_per_hour) /
       static_cast<int>(kMsPerMinute))
          .Floor();
  return minute_part_of_minimum == date_value_.Minute() &&
         GetStepRange().Step().Remainder(decimal_ms_per_hour).IsZero();
}

bool DateTimeEditBuilder::ShouldSecondFieldDisabled() const {
  if (second_range_.IsSingleton() &&
      second_range_.minimum == date_value_.Second())
    return true;

  const Decimal decimal_ms_per_minute(static_cast<int>(kMsPerMinute));
  Decimal second_part_of_minimum =
      (GetStepRange().StepBase().Abs().Remainder(decimal_ms_per_minute) /
       static_cast<int>(kMsPerSecond))
          .Floor();
  return second_part_of_minimum == date_value_.Second() &&
         GetStepRange().Step().Remainder(decimal_ms_per_minute).IsZero();
}

bool DateTimeEditBuilder::ShouldYearFieldDisabled() const {
  return parameters_.minimum.GetType() != DateComponents::kInvalid &&
         parameters_.maximum.GetType() != DateComponents::kInvalid &&
         parameters_.minimum.FullYear() == parameters_.maximum.FullYear() &&
         parameters_.minimum.FullYear() == date_value_.FullYear();
}

void DateTimeEditBuilder::VisitLiteral(const String& text) {
  DEFINE_STATIC_LOCAL(AtomicString, text_pseudo_id,
                      ("-webkit-datetime-edit-text"));
  DCHECK_GT(text.length(), 0u);
  auto* element =
      MakeGarbageCollected<HTMLDivElement>(EditElement().GetDocument());
  element->SetShadowPseudoId(text_pseudo_id);
  element->SetInlineStyleProperty(CSSPropertyID::kUnicodeBidi,
                                  CSSValueID::kNormal);
  if (parameters_.locale.IsRTL() && text.length()) {
    WTF::unicode::CharDirection dir = WTF::unicode::Direction(text[0]);
    if (dir == WTF::unicode::kSegmentSeparator ||
        dir == WTF::unicode::kWhiteSpaceNeutral ||
        dir == WTF::unicode::kOtherNeutral) {
      element->AppendChild(
          Text::Create(EditElement().GetDocument(),
                       String(base::span_from_ref(kRightToLeftMarkCharacter))));
    }
  }
  element->AppendChild(Text::Create(EditElement().GetDocument(), text));
  EditElement().FieldsWrapperElement()->AppendChild(element);
}

DateTimeEditElement& DateTimeEditBuilder::EditElement() const {
  return *edit_element_;
}

DateTimeNumericFieldElement::Step DateTimeEditBuilder::CreateStep(
    double ms_per_field_unit,
    double ms_per_field_size) const {
  const Decimal ms_per_field_unit_decimal(static_cast<int>(ms_per_field_unit));
  const Decimal ms_per_field_size_decimal(static_cast<int>(ms_per_field_size));
  Decimal step_milliseconds = GetStepRange().Step();
  DCHECK(!ms_per_field_unit_decimal.IsZero());
  DCHECK(!ms_per_field_size_decimal.IsZero());
  DCHECK(!step_milliseconds.IsZero());

  DateTimeNumericFieldElement::Step step(1, 0);

  if (step_milliseconds.Remainder(ms_per_field_size_decimal).IsZero())
    step_milliseconds = ms_per_field_size_decimal;

  if (ms_per_field_size_decimal.Remainder(step_milliseconds).IsZero() &&
      step_milliseconds.Remainder(ms_per_field_unit_decimal).IsZero()) {
    step.step = static_cast<int>(
        (step_milliseconds / ms_per_field_unit_decimal).ToDouble());
    step.step_base = static_cast<int>(
        (GetStepRange().StepBase() / ms_per_field_unit_decimal)
            .Floor()
            .Remainder(ms_per_field_size_decimal / ms_per_field_unit_decimal)
            .ToDouble());
  }
  return step;
}

// ----------------------------

DateTimeEditElement::EditControlOwner::~EditControlOwner() = default;

DateTimeEditElement::DateTimeEditElement(Document& document,
                                         EditControlOwner& edit_control_owner)
    : HTMLDivElement(document), edit_control_owner_(&edit_control_owner) {
  SetHasCustomStyleCallbacks();
  SetShadowPseudoId(AtomicString("-webkit-datetime-edit"));
  setAttribute(html_names::kIdAttr, shadow_element_names::kIdDateTimeEdit);
  SetInlineStyleProperty(CSSPropertyID::kUnicodeBidi, CSSValueID::kNormal);
}

DateTimeEditElement::~DateTimeEditElement() = default;

void DateTimeEditElement::Trace(Visitor* visitor) const {
  visitor->Trace(fields_);
  visitor->Trace(edit_control_owner_);
  HTMLDivElement::Trace(visitor);
}

inline Element* DateTimeEditElement::FieldsWrapperElement() const {
  CHECK(!firstChild() || IsA<Element>(firstChild()));
  return To<Element>(firstChild());
}

void DateTimeEditElement::AddField(DateTimeFieldElement* field) {
  if (fields_.size() >= kMaximumNumberOfFields)
    return;
  fields_.push_back(field);
  FieldsWrapperElement()->AppendChild(field);
}

bool DateTimeEditElement::AnyEditableFieldsHaveValues() const {
  for (const auto& field : fields_) {
    if (!field->IsDisabled() && field->HasValue())
      return true;
  }
  return false;
}

void DateTimeEditElement::BlurByOwner() {
  if (DateTimeFieldElement* field = FocusedField())
    field->blur();
}

const ComputedStyle* DateTimeEditElement::CustomStyleForLayoutObject(
    const StyleRecalcContext& style_recalc_context) {
  // TODO(crbug.com/1181868): This is a kind of layout. We might want to
  // introduce new LayoutObject.
  const ComputedStyle* original_style =
      OriginalStyleForLayoutObject(style_recalc_context);
  float width = 0;
  for (Node* child = FieldsWrapperElement()->firstChild(); child;
       child = child->nextSibling()) {
    auto* child_element = DynamicTo<Element>(child);
    if (!child_element)
      continue;
    if (child_element->IsDateTimeFieldElement()) {
      // We need to pass the ComputedStyle of this element because child
      // elements can't resolve inherited style at this timing.
      width += static_cast<DateTimeFieldElement*>(child_element)
                   ->MaximumWidth(*original_style);
    } else {
      // ::-webkit-datetime-edit-text case. It has no
      // border/padding/margin in html.css.
      width += ComputeTextWidth(child_element->textContent(), *original_style);
    }
  }
  ComputedStyleBuilder builder(*original_style);
  if (original_style->IsHorizontalWritingMode()) {
    builder.SetWidth(Length::Fixed(ceilf(width)));
  } else {
    builder.SetHeight(Length::Fixed(ceilf(width)));
  }
  builder.SetCustomStyleCallbackDependsOnFont();
  return builder.TakeStyle();
}

void DateTimeEditElement::DidBlurFromField(mojom::blink::FocusType focus_type) {
  if (edit_control_owner_)
    edit_control_owner_->DidBlurFromControl(focus_type);
}

void DateTimeEditElement::DidFocusOnField(mojom::blink::FocusType focus_type) {
  if (edit_control_owner_)
    edit_control_owner_->DidFocusOnControl(focus_type);
}

void DateTimeEditElement::DisabledStateChanged() {
  UpdateUIState();
}

DateTimeFieldElement* DateTimeEditElement::FieldAt(
    wtf_size_t field_index) const {
  return field_index < fields_.size() ? fields_[field_index].Get() : nullptr;
}

wtf_size_t DateTimeEditElement::FieldIndexOf(
    const DateTimeFieldElement& field) const {
  for (wtf_size_t field_index = 0; field_index < fields_.size();
       ++field_index) {
    if (fields_[field_index] == &field)
      return field_index;
  }
  return kInvalidFieldIndex;
}

void DateTimeEditElement::FocusIfNoFocus() {
  if (FocusedFieldIndex() != kInvalidFieldIndex)
    return;
  FocusOnNextFocusableField(0);
}

void DateTimeEditElement::FocusByOwner(Element* old_focused_element) {
  if (old_focused_element && old_focused_element->IsDateTimeFieldElement()) {
    DateTimeFieldElement* old_focused_field =
        static_cast<DateTimeFieldElement*>(old_focused_element);
    wtf_size_t index = FieldIndexOf(*old_focused_field);
    GetDocument().UpdateStyleAndLayoutTreeForElement(
        old_focused_field, DocumentUpdateReason::kFocus);
    if (index != kInvalidFieldIndex && old_focused_field->IsFocusable()) {
      old_focused_field->Focus(FocusParams(FocusTrigger::kUserGesture));
      return;
    }
  }
  FocusOnNextFocusableField(0);
}

DateTimeFieldElement* DateTimeEditElement::FocusedField() const {
  return FieldAt(FocusedFieldIndex());
}

wtf_size_t DateTimeEditElement::FocusedFieldIndex() const {
  Element* const focused_field_element = GetDocument().FocusedElement();
  for (wtf_size_t field_index = 0; field_index < fields_.size();
       ++field_index) {
    if (fields_[field_index] == focused_field_element)
      return field_index;
  }
  return kInvalidFieldIndex;
}

void DateTimeEditElement::FieldValueChanged() {
  if (edit_control_owner_)
    edit_control_owner_->EditControlValueChanged();
}

bool DateTimeEditElement::FocusOnNextFocusableField(wtf_size_t start_index) {
  GetDocument().UpdateStyleAndLayoutTree();
  for (wtf_size_t field_index = start_index; field_index < fields_.size();
       ++field_index) {
    if (fields_[field_index]->IsFocusable()) {
      fields_[field_index]->Focus(FocusParams(FocusTrigger::kUserGesture));
      return true;
    }
  }
  return false;
}

bool DateTimeEditElement::FocusOnNextField(const DateTimeFieldElement& field) {
  const wtf_size_t start_field_index = FieldIndexOf(field);
  if (start_field_index == kInvalidFieldIndex)
    return false;
  return FocusOnNextFocusableField(start_field_index + 1);
}

bool DateTimeEditElement::FocusOnPreviousField(
    const DateTimeFieldElement& field) {
  const wtf_size_t start_field_index = FieldIndexOf(field);
  if (start_field_index == kInvalidFieldIndex)
    return false;
  GetDocument().UpdateStyleAndLayoutTree();
  wtf_size_t field_index = start_field_index;
  while (field_index > 0) {
    --field_index;
    if (fields_[field_index]->IsFocusable()) {
      fields_[field_index]->Focus(FocusParams(FocusTrigger::kUserGesture));
      return true;
    }
  }
  return false;
}

void DateTimeEditElement::HandleAmPmRollover(
    DateTimeFieldElement::FieldRolloverType rollover_type) {
  auto* ampm_field = GetField(DateTimeField::kAMPM);
  if (!ampm_field)
    return;
  DateTimeFieldsState date_time_fields_state = ValueAsDateTimeFieldsState();
  ampm_field->PopulateDateTimeFieldsState(date_time_fields_state);
  bool was_am =
      (date_time_fields_state.Ampm() == DateTimeFieldsState::kAMPMValueAM);
  date_time_fields_state.SetAMPM(DateTimeFieldsState::kAMPMValuePM);
  if (rollover_type != DateTimeFieldElement::FieldRolloverType::kToPm &&
      !was_am)
    date_time_fields_state.SetAMPM(DateTimeFieldsState::kAMPMValueAM);
  ampm_field->SetValueAsDateTimeFieldsState(date_time_fields_state);
  // No need to call EditControlValueChanged since change that triggered
  // rollover will do so.
}

bool DateTimeEditElement::IsDateTimeEditElement() const {
  return true;
}

bool DateTimeEditElement::IsDisabled() const {
  return edit_control_owner_ &&
         edit_control_owner_->IsEditControlOwnerDisabled();
}

bool DateTimeEditElement::IsFieldOwnerDisabled() const {
  return IsDisabled();
}

bool DateTimeEditElement::IsFieldOwnerReadOnly() const {
  return IsReadOnly();
}

bool DateTimeEditElement::IsReadOnly() const {
  return edit_control_owner_ &&
         edit_control_owner_->IsEditControlOwnerReadOnly();
}

void DateTimeEditElement::GetLayout(const LayoutParameters& layout_parameters,
                                    const DateComponents& date_value) {
  // TODO(tkent): We assume this function never dispatches events. However this
  // can dispatch 'blur' event in Node::removeChild().

  DEFINE_STATIC_LOCAL(AtomicString, fields_wrapper_pseudo_id,
                      ("-webkit-datetime-edit-fields-wrapper"));
  if (!HasChildren()) {
    auto* element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
    element->SetShadowPseudoId(fields_wrapper_pseudo_id);
    element->SetInlineStyleProperty(CSSPropertyID::kUnicodeBidi,
                                    CSSValueID::kNormal);
    AppendChild(element);
  }
  Element* fields_wrapper = FieldsWrapperElement();

  wtf_size_t focused_field_index = FocusedFieldIndex();
  DateTimeFieldElement* const focused_field = FieldAt(focused_field_index);
  const AtomicString focused_field_id =
      focused_field ? focused_field->ShadowPseudoId() : g_null_atom;

  DateTimeEditBuilder builder(*this, layout_parameters, date_value);
  Node* last_child_to_be_removed = fields_wrapper->lastChild();
  if (!builder.Build(layout_parameters.date_time_format) || fields_.empty()) {
    last_child_to_be_removed = fields_wrapper->lastChild();
    builder.Build(layout_parameters.fallback_date_time_format);
  }

  if (focused_field_index != kInvalidFieldIndex) {
    for (wtf_size_t field_index = 0; field_index < fields_.size();
         ++field_index) {
      if (fields_[field_index]->ShadowPseudoId() == focused_field_id) {
        focused_field_index = field_index;
        break;
      }
    }
    if (DateTimeFieldElement* field =
            FieldAt(std::min(focused_field_index, fields_.size() - 1)))
      field->Focus(FocusParams(FocusTrigger::kUserGesture));
  }

  if (last_child_to_be_removed) {
    for (Node* child_node = fields_wrapper->firstChild(); child_node;
         child_node = fields_wrapper->firstChild()) {
      fields_wrapper->RemoveChild(child_node);
      if (child_node == last_child_to_be_removed)
        break;
    }
    SetNeedsStyleRecalc(
        kSubtreeStyleChange,
        StyleChangeReasonForTracing::Create(style_change_reason::kControl));
  }
}

AtomicString DateTimeEditElement::LocaleIdentifier() const {
  return edit_control_owner_ ? edit_control_owner_->LocaleIdentifier()
                             : g_null_atom;
}

void DateTimeEditElement::FieldDidChangeValueByKeyboard() {
  if (edit_control_owner_)
    edit_control_owner_->EditControlDidChangeValueByKeyboard();
}

void DateTimeEditElement::ReadOnlyStateChanged() {
  UpdateUIState();
}

void DateTimeEditElement::ResetFields() {
  for (const auto& field : fields_)
    field->RemoveEventHandler();
  fields_.Shrink(0);
}

void DateTimeEditElement::DefaultEventHandler(Event& event) {
  // In case of control owner forward event to control, e.g. DOM
  // dispatchEvent method.
  if (DateTimeFieldElement* field = FocusedField()) {
    field->DefaultEventHandler(event);
    if (event.DefaultHandled())
      return;
  }

  HTMLDivElement::DefaultEventHandler(event);
}

void DateTimeEditElement::SetValueAsDate(
    const LayoutParameters& layout_parameters,
    const DateComponents& date) {
  GetLayout(layout_parameters, date);
  for (c
"""


```