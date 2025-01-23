Response:
Let's break down the thought process for analyzing the provided C++ code for `NumberInputType`.

**1. Initial Understanding of the Context:**

The file path `blink/renderer/core/html/forms/number_input_type.cc` immediately tells us this code is part of the Chromium Blink rendering engine, specifically dealing with the `<input type="number">` HTML element. The `.cc` extension signifies a C++ source file.

**2. High-Level Goal: Summarize Functionality and Connections:**

The request asks for:
* Functionality of the file.
* Relationship to JavaScript, HTML, and CSS.
* Logical reasoning with input/output examples.
* Common user/programming errors.

**3. Code Examination - Core Functionality:**

The code contains a class `NumberInputType`. This strongly suggests it's responsible for handling the specific behavior of the `number` input type. I started by looking at the public methods of this class:

* **`CountUsage()`:**  Likely tracks usage of this input type for metrics.
* **`SetValue()`:**  Sets the value of the input field. The arguments suggest it handles updates from both internal logic and user input.
* **`ValueAsDouble()` and `SetValueAsDouble()`/`SetValueAsDecimal()`:** These clearly handle getting and setting the numeric value of the input. The distinction between `double` and `Decimal` suggests handling both floating-point and arbitrary-precision numbers.
* **`TypeMismatchFor()` and `TypeMismatch()`:** These functions are for validation, checking if the input value conforms to the `number` type.
* **`CreateStepRange()`:** This relates to the `step`, `min`, and `max` attributes, defining the valid range and increment/decrement steps.
* **`SizeShouldIncludeDecoration()`:**  This seems related to how the input field's width is calculated, potentially taking into account the `min`, `max`, and `step` attributes to accommodate the expected range of values.
* **`HandleKeydownEvent()` and `HandleBeforeTextInsertedEvent()`:** These are crucial for handling user input, filtering and validating characters as the user types. This is where the core input sanitization logic resides.
* **`ParseToNumber()` and `Serialize()`:**  These functions handle converting between string representations and internal numeric representations (likely `Decimal`).
* **`LocalizeValue()` and `ConvertFromVisibleValue()`:** These are important for internationalization, handling different number formats based on the user's locale (e.g., using commas or periods as decimal separators).
* **`SanitizeValue()`:**  This function cleans up the input value, removing invalid characters.
* **`WarnIfValueIsInvalid()`:**  Logs warnings to the browser console if an invalid value is detected.
* **`HasBadInput()` and `BadInputText()`:**  More validation-related functions, indicating if the input is currently invalid and providing a user-friendly error message.
* **`ValueNotEqualText()`, `RangeOverflowText()`, `RangeUnderflowText()`, `RangeInvalidText()`:**  These functions provide localized error messages for specific validation failures related to the `min`, `max`, and `step` attributes.
* **`SupportsPlaceholder()`:**  Indicates whether the `placeholder` attribute is supported.
* **`MinOrMaxAttributeChanged()` and `StepAttributeChanged()`:** These methods are called when the `min`, `max`, or `step` attributes are modified, likely triggering layout updates.
* **`SupportsSelectionAPI()`:** Indicates support for programmatic selection of text within the input field.

**4. Connecting to HTML, CSS, and JavaScript:**

* **HTML:** The code directly implements the behavior of `<input type="number">`. It interacts with HTML attributes like `min`, `max`, `step`, and `value`.
* **CSS:** While the C++ code doesn't directly manipulate CSS, the `SizeShouldIncludeDecoration()` and the `*AttributeChanged()` methods influence the rendering and layout of the input element, which CSS styles.
* **JavaScript:**  JavaScript can interact with the `number` input type through its DOM API. JavaScript can get and set the `value` property, which this C++ code manages. JavaScript can also trigger validation and handle events related to the input.

**5. Logical Reasoning and Examples:**

For each significant function, I considered how it would behave with different inputs. For example:

* **`HandleBeforeTextInsertedEvent()`:** I imagined scenarios like pasting text, typing numbers, decimal points, 'e' for scientific notation, and signs. I then considered how the sanitization logic would filter these inputs based on the current state of the input field and the locale.
* **`SanitizeValue()`:**  I thought about valid and invalid numeric strings and how this function would either return the valid string or an empty string.
* **Validation functions:** I considered how different `min`, `max`, and `step` values would affect the validity of user input.

**6. Common Errors:**

Thinking from a user and developer perspective, I considered common mistakes:

* **User Errors:** Entering non-numeric characters, values outside the `min`/`max` range, or values that don't adhere to the `step`.
* **Developer Errors:**  Incorrectly setting the `min`, `max`, or `step` attributes, assuming a specific number format without considering localization.

**7. Structuring the Output:**

Finally, I organized the findings into the requested categories:

* **Functionality:**  A summary of the main responsibilities of the class.
* **Relationship to JS/HTML/CSS:**  Concrete examples of how the C++ code interacts with these web technologies.
* **Logical Reasoning:**  Specific input/output examples to illustrate the behavior of key functions.
* **Common Errors:**  Examples of mistakes users or developers might make.

This iterative process of code examination, considering the context, and thinking about interactions with other web technologies allowed me to generate a comprehensive and informative summary of the `NumberInputType` code.
这个文件 `blink/renderer/core/html/forms/number_input_type.cc` 是 Chromium Blink 渲染引擎中负责实现 `<input type="number">` HTML 表单元素功能的 C++ 代码。 它定义了 `NumberInputType` 类，该类处理与数字输入框相关的特定行为和逻辑。

以下是该文件的主要功能及其与 JavaScript、HTML 和 CSS 的关系，以及逻辑推理示例和常见错误：

**功能列表:**

1. **处理用户输入:**
   - 拦截和处理键盘事件 (`HandleKeydownEvent`)，例如方向键（用于步进增减）。
   - 在文本插入之前进行处理 (`HandleBeforeTextInsertedEvent`)，以确保只允许输入有效的数字字符（数字、小数点、正负号、科学计数法的 'e'）。 这涉及到根据用户的区域设置 (`Locale`) 来进行不同的字符过滤。
   - 清理和验证用户输入，确保输入的值是有效的数字。

2. **管理和操作输入值:**
   - 获取和设置输入框的值 (`SetValue`, `ValueAsDouble`, `SetValueAsDouble`, `SetValueAsDecimal`)。
   - 提供将输入值解析为数字 (`ParseToDoubleForNumberType`, `ParseToDecimalForNumberType`) 和将数字序列化为字符串 (`SerializeForNumberType`) 的方法。
   - 实现 `valueAsNumber` JavaScript 属性的功能。

3. **实现输入限制和验证:**
   - 检查类型不匹配 (`TypeMismatchFor`, `TypeMismatch`)，即输入的值是否能被解析为有效的数字。
   - 创建步进范围 (`CreateStepRange`)，考虑到 `step`、`min` 和 `max` 属性，以控制数值的增减步幅和范围。
   - 根据 `min`、`max` 和 `step` 属性进行输入验证。

4. **处理属性变化:**
   - 响应 `min`、`max` 和 `step` 属性的变化 (`MinOrMaxAttributeChanged`, `StepAttributeChanged`)，并可能触发布局更新。

5. **本地化支持:**
   - 提供将内部数值本地化为用户可见格式 (`LocalizeValue`) 以及将用户输入的本地化数值转换回内部格式 (`ConvertFromVisibleValue`) 的功能。例如，处理不同地区的小数点符号（逗号或句点）。

6. **提供用户友好的提示和错误信息:**
   - 当输入值无效时，向控制台发出警告 (`WarnIfValueIsInvalid`)。
   - 提供本地化的错误消息，用于表单验证 (`BadInputText`, `ValueNotEqualText`, `RangeOverflowText`, `RangeUnderflowText`, `RangeInvalidText`)。

7. **支持占位符:**
   - 指示是否支持 `placeholder` 属性 (`SupportsPlaceholder`)。

8. **计算输入框的尺寸:**
   - 根据 `min`、`max` 和 `step` 属性，计算输入框的首选尺寸 (`SizeShouldIncludeDecoration`)，以确保能容纳可能的最大值和步进值。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**
    - `NumberInputType` 类直接对应于 HTML 中的 `<input type="number">` 元素。
    - 它读取和处理 `<input>` 元素的属性，如 `min`、`max`、`step` 和 `value`。
    - 例如，`CreateStepRange` 函数会读取 HTML 属性 `step`、`min` 和 `max` 的值来确定有效的数字范围和步进值。
    - 当 HTML 属性（如 `min` 或 `max`）改变时，`MinOrMaxAttributeChanged` 等函数会被调用，从而影响输入框的行为。

* **JavaScript:**
    - JavaScript 可以通过 DOM API 与 `<input type="number">` 元素交互。
    - `ValueAsDouble` 和 `SetValueAsDouble` 等方法实现了 JavaScript 中 `HTMLInputElement` 对象的 `valueAsNumber` 属性的获取和设置。 例如，JavaScript 代码 `inputElement.valueAsNumber = 10;` 会调用 `SetValueAsDouble` 方法。
    - JavaScript 可以监听输入框的 `input` 或 `change` 事件，这些事件的触发与 `NumberInputType` 中处理用户输入和值变更的逻辑有关。
    - JavaScript 的表单验证 API 会利用 `NumberInputType` 提供的验证功能，例如 `TypeMismatch` 和相关的错误消息。

* **CSS:**
    - 虽然 `NumberInputType` 的 C++ 代码本身不直接操作 CSS，但它会影响输入框的渲染和布局。
    - `SizeShouldIncludeDecoration` 函数计算的首选尺寸会影响输入框的默认宽度，这反过来会受到 CSS 样式的影响。
    - CSS 可以用来设置输入框的外观，例如字体、颜色、边框等，但其核心行为由 `NumberInputType` 控制。

**逻辑推理示例:**

**假设输入:** 用户在 `<input type="number" min="0" max="10" step="2">` 的输入框中输入 "1.5"。

**`HandleBeforeTextInsertedEvent` 中的逻辑:**

1. 该方法会被调用，`event.GetText()` 将返回 "1.5"。
2. `StripInvalidNumberCharacters` 方法会检查 "1.5" 中的字符是否有效，在这个上下文中都是有效的数字字符。
3. 由于 `step` 属性是 2，后续的验证（虽然不在 `HandleBeforeTextInsertedEvent` 中直接发生，但与之相关）会检查输入的值是否符合步进规则。 "1.5" 不符合从 `min` 值 0 开始以 2 为步进的规则。
4. 最终，如果后续的验证失败，输入框的值可能不会更新，或者会显示一个错误指示。

**假设输入:** 用户点击输入框的向上箭头，而当前值为 "4"，步进值为 "2"。

**`HandleKeydownEventForSpinButton` 中的逻辑（虽然代码中没有直接展示该函数，但可以推断其功能）:**

1. `HandleKeydownEvent` 会捕获到向上箭头的事件。
2. 相关逻辑会根据当前的 `value` ("4") 和 `step` ("2") 计算下一个有效值。
3. 下一个有效值将是 4 + 2 = 6。
4. 输入框的值会被更新为 "6"。

**常见的使用错误:**

1. **用户错误:**
   - 在数字输入框中输入非数字字符（例如字母）。`HandleBeforeTextInsertedEvent` 会阻止这些字符的插入。
   - 输入超出 `min` 或 `max` 范围的值。表单提交时或通过 JavaScript 访问 `validity` 属性时会检测到错误。
   - 输入不符合 `step` 属性的值。同样，表单提交或 JavaScript 验证会报告错误。

2. **编程错误:**
   - 未正确设置 `min`、`max` 或 `step` 属性，导致意料之外的输入限制或行为。 例如，设置 `step="0.1"` 可能导致浮点数精度问题。
   - 依赖浏览器的默认本地化行为而不进行显式处理，可能导致在不同地区显示或解析数字时出现问题。 开发者应该注意使用 JavaScript 或服务器端代码来统一处理数字格式。
   - 假设 `valueAsNumber` 总是返回一个有效的数字，而没有检查 `validity.badInput` 属性。如果用户输入了无法解析为数字的值，`valueAsNumber` 将返回 `NaN`。

总而言之，`number_input_type.cc` 文件是 Blink 引擎中实现 `<input type="number">` 元素核心功能的重要组成部分，它负责处理用户输入、数据验证、本地化和与 JavaScript 及 HTML 的交互。

### 提示词
```
这是目录为blink/renderer/core/html/forms/number_input_type.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
 * Copyright (C) 2011 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/html/forms/number_input_type.h"

#include <limits>
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/events/before_text_inserted_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"

namespace blink {

static const int kNumberDefaultStep = 1;
static const int kNumberDefaultStepBase = 0;
static const int kNumberStepScaleFactor = 1;

struct RealNumberRenderSize {
  unsigned size_before_decimal_point;
  unsigned size_afte_decimal_point;

  RealNumberRenderSize(unsigned before, unsigned after)
      : size_before_decimal_point(before), size_afte_decimal_point(after) {}

  RealNumberRenderSize Max(const RealNumberRenderSize& other) const {
    return RealNumberRenderSize(
        std::max(size_before_decimal_point, other.size_before_decimal_point),
        std::max(size_afte_decimal_point, other.size_afte_decimal_point));
  }
};

static RealNumberRenderSize CalculateRenderSize(const Decimal& value) {
  DCHECK(value.IsFinite());
  const unsigned size_of_digits =
      String::Number(value.Value().Coefficient()).length();
  const unsigned size_of_sign = value.IsNegative() ? 1 : 0;
  const int exponent = value.Exponent();
  if (exponent >= 0)
    return RealNumberRenderSize(size_of_sign + size_of_digits, 0);

  const int size_before_decimal_point = exponent + size_of_digits;
  if (size_before_decimal_point > 0) {
    // In case of "123.456"
    return RealNumberRenderSize(size_of_sign + size_before_decimal_point,
                                size_of_digits - size_before_decimal_point);
  }

  // In case of "0.00012345"
  const unsigned kSizeOfZero = 1;
  const unsigned number_of_zero_after_decimal_point =
      -size_before_decimal_point;
  return RealNumberRenderSize(
      size_of_sign + kSizeOfZero,
      number_of_zero_after_decimal_point + size_of_digits);
}

void NumberInputType::CountUsage() {
  CountUsageIfVisible(WebFeature::kInputTypeNumber);
}

void NumberInputType::SetValue(const String& sanitized_value,
                               bool value_changed,
                               TextFieldEventBehavior event_behavior,
                               TextControlSetValueSelection selection) {
  if (!value_changed && sanitized_value.empty() &&
      !GetElement().InnerEditorValue().empty())
    GetElement().UpdateView();
  TextFieldInputType::SetValue(sanitized_value, value_changed, event_behavior,
                               selection);
}

double NumberInputType::ValueAsDouble() const {
  return ParseToDoubleForNumberType(GetElement().Value());
}

void NumberInputType::SetValueAsDouble(double new_value,
                                       TextFieldEventBehavior event_behavior,
                                       ExceptionState& exception_state) const {
  GetElement().SetValue(SerializeForNumberType(new_value), event_behavior);
}

void NumberInputType::SetValueAsDecimal(const Decimal& new_value,
                                        TextFieldEventBehavior event_behavior,
                                        ExceptionState& exception_state) const {
  GetElement().SetValue(SerializeForNumberType(new_value), event_behavior);
}

bool NumberInputType::TypeMismatchFor(const String& value) const {
  return !value.empty() && !std::isfinite(ParseToDoubleForNumberType(value));
}

bool NumberInputType::TypeMismatch() const {
  DCHECK(!TypeMismatchFor(GetElement().Value()));
  return false;
}

StepRange NumberInputType::CreateStepRange(
    AnyStepHandling any_step_handling) const {
  DEFINE_STATIC_LOCAL(
      const StepRange::StepDescription, step_description,
      (kNumberDefaultStep, kNumberDefaultStepBase, kNumberStepScaleFactor));
  const Decimal double_max =
      Decimal::FromDouble(std::numeric_limits<double>::max());
  return InputType::CreateStepRange(any_step_handling, kNumberDefaultStepBase,
                                    -double_max, double_max, step_description);
}

bool NumberInputType::SizeShouldIncludeDecoration(int default_size,
                                                  int& preferred_size) const {
  preferred_size = default_size;

  const String step_string =
      GetElement().FastGetAttribute(html_names::kStepAttr);
  if (EqualIgnoringASCIICase(step_string, "any"))
    return false;

  const Decimal minimum = ParseToDecimalForNumberType(
      GetElement().FastGetAttribute(html_names::kMinAttr));
  if (!minimum.IsFinite())
    return false;

  const Decimal maximum = ParseToDecimalForNumberType(
      GetElement().FastGetAttribute(html_names::kMaxAttr));
  if (!maximum.IsFinite())
    return false;

  const Decimal step = ParseToDecimalForNumberType(step_string, 1);
  DCHECK(step.IsFinite());

  RealNumberRenderSize size = CalculateRenderSize(minimum).Max(
      CalculateRenderSize(maximum).Max(CalculateRenderSize(step)));

  preferred_size = size.size_before_decimal_point +
                   size.size_afte_decimal_point +
                   (size.size_afte_decimal_point ? 1 : 0);

  return true;
}

static bool IsE(UChar ch) {
  return ch == 'e' || ch == 'E';
}

void NumberInputType::HandleKeydownEvent(KeyboardEvent& event) {
  EventQueueScope scope;
  HandleKeydownEventForSpinButton(event);
  if (!event.DefaultHandled())
    TextFieldInputType::HandleKeydownEvent(event);
}

void NumberInputType::HandleBeforeTextInsertedEvent(
    BeforeTextInsertedEvent& event) {
  Locale& locale = GetLocale();

  // If the cleaned up text doesn't match input text, don't insert partial input
  // since it could be an incorrect paste.
  String updated_event_text =
      locale.StripInvalidNumberCharacters(event.GetText(), "0123456789.Ee-+");

  // Check if locale supports more cleanup rules
  if (!locale.UsesSingleCharNumberFiltering()) {
    event.SetText(updated_event_text);
    return;
  }

  // Get left and right of cursor
  String original_value = GetElement().InnerEditorValue();
  String left_half = original_value.Substring(0, GetElement().selectionStart());
  String right_half = original_value.Substring(GetElement().selectionEnd());

  // Process 1 char at a time
  unsigned len = updated_event_text.length();
  StringBuilder final_event_text;
  for (unsigned i = 0; i < len; ++i) {
    UChar c = updated_event_text[i];

    // For a decimal point input:
    // - Reject if the editing value already contains another decimal point
    // - Reject if the editing value contains 'e' and the caret is placed
    // after the 'e'.
    // - Reject if the editing value contains '+' or '-' and the caret is
    // placed before it unless it's after an e
    if (locale.IsDecimalSeparator(c)) {
      if (locale.HasDecimalSeparator(left_half) ||
          locale.HasDecimalSeparator(right_half) ||
          left_half.Find(IsE) != kNotFound ||
          locale.HasSignNotAfterE(right_half))
        continue;
    }
    // For 'e' input:
    // - Reject if the editing value already contains another 'e'
    // - Reject if the editing value contains a decimal point, and the caret
    // is placed before it
    else if (IsE(c)) {
      if (left_half.Find(IsE) != kNotFound ||
          right_half.Find(IsE) != kNotFound ||
          locale.HasDecimalSeparator(right_half))
        continue;
    }
    // For '-' or '+' input:
    // - Reject if the editing value already contains two signs
    // - Reject if the editing value contains 'e' and the caret is placed
    // neither at the beginning of the value nor just after 'e'
    else if (locale.IsSignPrefix(c)) {
      String both_halves = left_half + right_half;
      if (locale.HasTwoSignChars(both_halves) ||
          (both_halves.Find(IsE) != kNotFound &&
           !(left_half == "" || IsE(left_half[left_half.length() - 1]))))
        continue;
    }
    // For a digit input:
    // - Reject if the first letter of the editing value is a sign and the
    // caret is placed just before it
    // - Reject if the editing value contains 'e' + a sign, and the caret is
    // placed between them.
    else if (locale.IsDigit(c)) {
      if ((left_half.empty() && !right_half.empty() &&
           locale.IsSignPrefix(right_half[0])) ||
          (!left_half.empty() && IsE(left_half[left_half.length() - 1]) &&
           !right_half.empty() && locale.IsSignPrefix(right_half[0])))
        continue;
    }

    // Add character
    left_half = left_half + c;
    final_event_text.Append(c);
  }
  event.SetText(final_event_text.ToString());
}

Decimal NumberInputType::ParseToNumber(const String& src,
                                       const Decimal& default_value) const {
  return ParseToDecimalForNumberType(src, default_value);
}

String NumberInputType::Serialize(const Decimal& value) const {
  if (!value.IsFinite())
    return String();
  return SerializeForNumberType(value);
}

String NumberInputType::LocalizeValue(const String& proposed_value) const {
  if (proposed_value.empty())
    return proposed_value;
  // We don't localize scientific notations.
  if (proposed_value.Find(IsE) != kNotFound)
    return proposed_value;
  return GetElement().GetLocale().ConvertToLocalizedNumber(proposed_value);
}

String NumberInputType::VisibleValue() const {
  return LocalizeValue(GetElement().Value());
}

String NumberInputType::ConvertFromVisibleValue(
    const String& visible_value) const {
  if (visible_value.empty())
    return visible_value;
  // We don't localize scientific notations.
  if (visible_value.Find(IsE) != kNotFound)
    return visible_value;
  return GetElement().GetLocale().ConvertFromLocalizedNumber(visible_value);
}

String NumberInputType::SanitizeValue(const String& proposed_value) const {
  if (proposed_value.empty())
    return proposed_value;
  return std::isfinite(ParseToDoubleForNumberType(proposed_value))
             ? proposed_value
             : g_empty_string;
}

void NumberInputType::WarnIfValueIsInvalid(const String& value) const {
  if (value.empty() || !GetElement().SanitizeValue(value).empty())
    return;
  AddWarningToConsole(
      "The specified value %s cannot be parsed, or is out of range.", value);
}

bool NumberInputType::HasBadInput() const {
  String standard_value =
      ConvertFromVisibleValue(GetElement().InnerEditorValue());
  return !standard_value.empty() &&
         !std::isfinite(ParseToDoubleForNumberType(standard_value));
}

String NumberInputType::BadInputText() const {
  return GetLocale().QueryString(IDS_FORM_VALIDATION_BAD_INPUT_NUMBER);
}

String NumberInputType::ValueNotEqualText(const Decimal& value) const {
  return GetLocale().QueryString(IDS_FORM_VALIDATION_VALUE_NOT_EQUAL,
                                 LocalizeValue(Serialize(value)));
}

String NumberInputType::RangeOverflowText(const Decimal& maximum) const {
  return GetLocale().QueryString(IDS_FORM_VALIDATION_RANGE_OVERFLOW,
                                 LocalizeValue(Serialize(maximum)));
}

String NumberInputType::RangeUnderflowText(const Decimal& minimum) const {
  return GetLocale().QueryString(IDS_FORM_VALIDATION_RANGE_UNDERFLOW,
                                 LocalizeValue(Serialize(minimum)));
}

String NumberInputType::RangeInvalidText(const Decimal& minimum,
                                         const Decimal& maximum) const {
  return GetLocale().QueryString(IDS_FORM_VALIDATION_RANGE_REVERSED,
                                 LocalizeValue(Serialize(minimum)),
                                 LocalizeValue(Serialize(maximum)));
}

bool NumberInputType::SupportsPlaceholder() const {
  return true;
}

void NumberInputType::MinOrMaxAttributeChanged() {
  TextFieldInputType::MinOrMaxAttributeChanged();

  if (GetElement().GetLayoutObject()) {
    GetElement()
        .GetLayoutObject()
        ->SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
            layout_invalidation_reason::kAttributeChanged);
  }
}

void NumberInputType::StepAttributeChanged() {
  TextFieldInputType::StepAttributeChanged();

  if (GetElement().GetLayoutObject()) {
    GetElement()
        .GetLayoutObject()
        ->SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
            layout_invalidation_reason::kAttributeChanged);
  }
}

bool NumberInputType::SupportsSelectionAPI() const {
  return false;
}

}  // namespace blink
```