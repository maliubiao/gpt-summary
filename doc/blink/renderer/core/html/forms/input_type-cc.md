Response:
My thinking process for summarizing the provided C++ code snippet went something like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of `input_type.cc`, focusing on its relationship with HTML, CSS, and JavaScript, any logic it performs, and potential user errors. It's explicitly stated as "part 1" and asks for a general overview.

2. **Identify the Core Class:** The filename `input_type.cc` and the initial `#include "third_party/blink/renderer/core/html/forms/input_type.h"` strongly suggest that the core functionality revolves around the `InputType` class.

3. **Examine the Includes:**  The `#include` directives provide significant clues about the file's responsibilities. I looked for patterns and categories:
    * **Core Blink/DOM:** Includes like `HTMLInputElement`, `HTMLFormElement`, `Event`, `KeyboardEvent`, `FileList`, `FormData`, `AXObjectCache` point to interactions with the Document Object Model and browser rendering engine.
    * **Specific Input Types:**  Includes like `ButtonInputType`, `CheckboxInputType`, `ColorInputType`, etc., indicate that this file acts as a central point for managing different types of HTML `<input>` elements.
    * **Utility/Platform:**  Includes like `memory`, `utility`, `string`, `limits`, `base/debug`, `platform/text`, `platform/json` suggest supporting functionality for memory management, string manipulation, error handling, and potentially internationalization.
    * **Styling and Layout:** Includes like `LayoutTheme` and `ComputedStyle` hint at the interaction of input elements with the rendering pipeline.
    * **Parsing:**  `HTMLParserIdioms` indicates involvement in handling how HTML input elements are parsed.

4. **Analyze the `InputType` Class Structure:** I scanned the code for key methods and their purposes:
    * **`Create()` and `NormalizeTypeName()`:**  These functions are clearly responsible for creating specific `InputType` subclasses based on the `type` attribute of the `<input>` element and for ensuring consistent type names. This is a core function of the file.
    * **`IsValidValue()`:** This suggests validation logic.
    * **`AppendToFormData()`:**  Indicates involvement in form submission.
    * **`ValueAs...()` and `SetValueAs...()`:** These point to handling different data types associated with input values (date, double, decimal).
    * **Validation-related methods:** `TypeMismatch`, `ValueMissing`, `PatternMismatch`, `RangeUnderflow`, `RangeOverflow`, `StepMismatch`, `ValidationMessage`. This is a major part of the file's responsibility – ensuring the validity of user input.
    * **Event Handling:**  Methods like `DispatchSearchEvent`, and the mentions of `TextFieldEventBehavior` suggest involvement in triggering events based on user interaction.
    * **Styling and Accessibility:** Methods related to pseudo-classes (`InRangeChanged`) and accessibility (`AXObjectCache`) show interaction with the rendering and accessibility layers.
    * **Virtual Keyboard:** `MayTriggerVirtualKeyboard()` indicates a connection to mobile/touch interfaces.

5. **Identify Relationships with Web Technologies:**
    * **HTML:**  The code directly manipulates and interprets HTML `<input>` elements and their attributes (`type`, `value`, `name`, `required`, `pattern`, `min`, `max`, `step`, etc.). The entire file's purpose is to implement the behavior of these elements.
    * **CSS:** The code interacts with CSS through pseudo-classes (e.g., `:in-range`, `:out-of-range`) and by querying computed styles. This indicates how the visual presentation of input elements is affected by their state.
    * **JavaScript:**  While the C++ code doesn't directly execute JavaScript, it provides the underlying functionality that JavaScript APIs interact with. For example, JavaScript can set and get input values, trigger validation, and listen to events that are managed by this C++ code.

6. **Infer Logic and Data Flow:** I considered how the different parts of the code work together. When an `<input>` element is created, `InputType::Create()` is likely called. When the user interacts with an input, validation methods are invoked. When a form is submitted, `AppendToFormData()` is used. This helps to understand the overall flow of data.

7. **Consider User/Programming Errors:** The validation logic inherently addresses potential user errors (entering invalid data). Programming errors might involve incorrect attribute usage or misunderstanding how the different input types behave.

8. **Structure the Summary:** I organized the findings into logical categories as requested:

    * **Core Functionality:** Start with the primary purpose of the file.
    * **Relationship with Web Technologies:** Explicitly link the code to HTML, CSS, and JavaScript, providing examples.
    * **Logic and Data Flow:** Describe the key processes the code handles.
    * **User/Programming Errors:** Give concrete examples of potential issues.

9. **Refine and Elaborate:** I reviewed the initial draft to add more detail and clarity, ensuring the summary was comprehensive and easy to understand. I specifically made sure to include examples for the web technology relationships and to suggest potential inputs/outputs for the logical parts. I also made sure to highlight the use of a factory pattern for creating different input type objects.

This iterative process of examining the code, inferring its purpose, and connecting it to broader web technologies allowed me to construct a detailed and accurate summary.
## 功能归纳：blink/renderer/core/html/forms/input_type.cc (第1部分)

这个C++源文件 `input_type.cc` 是 Chromium Blink 渲染引擎中关于 **HTML `<input>` 元素类型的核心实现**。 它定义了 `InputType` 类及其相关的子类，负责处理各种不同类型的 `<input>` 元素的行为和属性。

**核心功能可以归纳为:**

1. **定义和管理 `<input>` 元素的不同类型:**  `InputType` 类作为一个基类，通过子类化来代表 HTML 中不同的 `<input>` 类型，例如 `text`, `password`, `checkbox`, `radio`, `date`, `file` 等。

2. **创建特定类型的 `InputType` 对象:**  `InputType::Create()` 函数根据 `<input>` 元素的 `type` 属性值，动态创建相应的 `InputType` 子类实例。这使用了工厂模式。

3. **规范化和验证 `type` 属性:** `InputType::NormalizeTypeName()` 函数负责将输入的字符串规范化为标准的 `<input>` 类型名称（例如将 "datetime-local" 转换为 "datetime-local"）。

4. **处理通用 `<input>` 元素的行为:** `InputType` 基类定义了所有 `<input>` 元素通用的行为，例如：
    *  是否参与表单数据的提交 (`IsFormDataAppendable`, `AppendToFormData`).
    *  获取和设置元素的值 (`GetElement().Value()`).
    *  处理表单提交时的结果 (`ResultForDialogSubmit`).
    *  判断是否需要保存和恢复表单控件状态 (`ShouldSaveAndRestoreFormControlState`).
    *  处理键盘焦点 (`IsKeyboardFocusable`).
    *  处理无障碍功能 (`AXObjectCache`).
    *  与布局相关的操作 (`LayoutObjectIsNeeded`).

5. **提供验证框架:** `InputType` 及其子类实现了多种验证方法，用于检查用户输入是否符合要求，例如：
    *  `IsValidValue`: 检查值是否有效。
    *  `TypeMismatch`: 检查值是否与类型不符。
    *  `ValueMissing`: 检查是否缺少值 (配合 `required` 属性).
    *  `PatternMismatch`: 检查值是否不符合 `pattern` 属性指定的正则表达式。
    *  `RangeUnderflow`, `RangeOverflow`: 检查数值是否超出 `min` 和 `max` 属性指定的范围。
    *  `StepMismatch`: 检查数值是否不符合 `step` 属性指定的步长。
    *  `ValidationMessage`:  返回用于显示给用户的验证消息。

6. **与不同数据类型交互:** `InputType` 提供了处理不同数据类型的方法，例如日期 (`ValueAsDate`, `SetValueAsDate`), 数字 (`ValueAsDouble`, `SetValueAsDouble`), 以及 Decimal 类型 (`SetValueAsDecimal`).

7. **处理事件:**  虽然这个文件本身不直接处理所有事件，但它定义了一些与事件相关的逻辑，例如在值改变时触发 `change` 或 `input` 事件 (`SetValue`).

8. **与本地化相关:**  通过 `GetLocale()` 方法获取本地化信息，用于生成本地化的验证消息。

**与 javascript, html, css 的功能关系以及举例说明:**

* **HTML:**
    * **功能关系:**  `input_type.cc` 的核心作用是实现 HTML 中 `<input>` 元素的各种行为。它直接对应了 HTML 规范中关于 `<input>` 元素的定义和功能。
    * **举例说明:** 当浏览器解析到 `<input type="text">` 时，`InputType::Create()` 会创建一个 `TextInputType` 对象来管理这个元素。这个 `TextInputType` 对象负责处理文本输入的相关逻辑，例如光标移动、文本选择等。

* **CSS:**
    * **功能关系:** `InputType` 可以影响 `<input>` 元素的样式，例如通过伪类 `:in-range` 和 `:out-of-range` 来指示数值输入是否在有效范围内。
    * **举例说明:**  对于 `<input type="number" min="10" max="20">`，当用户输入的值小于 10 或大于 20 时，Blink 可以通过 `InRangeChanged()` 方法更新元素的状态，使得 CSS 可以根据 `:out-of-range` 伪类来应用不同的样式（例如添加红色边框）。

* **JavaScript:**
    * **功能关系:** JavaScript 可以通过 DOM API 与 `<input>` 元素进行交互，例如获取和设置 `value` 属性，触发验证，监听事件等。`InputType` 提供了这些底层实现。
    * **举例说明:** 当 JavaScript 代码使用 `inputElement.value = "some text";` 修改一个 `<input type="text">` 元素的值时，最终会调用到 `TextInputType` 对象的 `SetValue` 方法来更新内部状态并触发相应的事件。 JavaScript 还可以调用 `inputElement.checkValidity()` 来触发 `InputType` 中的验证逻辑。

**逻辑推理的假设输入与输出 (以数字类型为例):**

**假设输入:** 一个 `<input type="number" min="5" max="10" step="2">` 元素，用户输入字符串 "7"。

**逻辑推理过程:**

1. `InputType::Create()` 根据 `type="number"` 创建一个 `NumberInputType` 对象。
2. 当用户输入 "7" 时，`NumberInputType` 的 `IsValidValue("7")` 方法会被调用。
3. `IsValidValue` 会检查：
    * `TypeMismatch`: "7" 可以解析为数字，所以没有类型不匹配。
    * `RangeUnderflow`: 7 大于等于 `min` 值 5，所以没有下溢。
    * `RangeOverflow`: 7 小于等于 `max` 值 10，所以没有上溢。
    * `StepMismatch`: 7 减去 `min` 值 5 的差是 2，可以被 `step` 值 2 整除，所以没有步长不匹配。
4. **输出:** `IsValidValue("7")` 返回 `true`。

**假设输入:** 同上，用户输入字符串 "4"。

**逻辑推理过程:**

1. 同上，创建 `NumberInputType` 对象。
2. 调用 `IsValidValue("4")`。
3. 检查：
    * `TypeMismatch`: 没有类型不匹配。
    * `RangeUnderflow`: 4 小于 `min` 值 5，所以存在下溢。
4. **输出:** `IsValidValue("4")` 返回 `false`。  同时，如果调用 `ValidationMessage`，会返回一个表示范围下溢的错误消息。

**涉及用户或者编程常见的使用错误，并举例说明:**

1. **用户输入错误的值:**
    * **例子:** 对于 `<input type="number">`，用户输入了 "abc"。`TypeMismatch()` 方法会返回 `true`，指示类型不匹配。浏览器会阻止表单提交或显示相应的错误提示。

2. **编程时属性设置错误:**
    * **例子:**  设置了 `min` 值大于 `max` 值，例如 `<input type="number" min="10" max="5">`。虽然代码层面不会直接报错，但 `RangeInvalidText` 方法可能会被调用，提示一个无效的范围。 在某些实现中，浏览器可能会忽略这些无效的属性。

3. **JavaScript 代码未正确处理验证结果:**
    * **例子:**  JavaScript 代码调用了 `inputElement.checkValidity()`，但没有根据返回的 `false` 结果来阻止表单提交或向用户显示错误信息。 这会导致用户提交无效的数据，服务端可能无法处理。

4. **误解不同 `input` 类型的行为:**
    * **例子:** 错误地认为 `<input type="file">` 的 `value` 属性可以用于获取用户选择的文件路径。 实际上，出于安全考虑，`value` 属性通常只包含文件名（有时不包含），而不能直接访问完整路径。 应该使用 `files` 属性来访问 `FileList` 对象。

**总结第1部分的功能:**

总而言之，`blink/renderer/core/html/forms/input_type.cc` 的第 1 部分主要负责 **构建和管理各种 HTML `<input>` 元素类型的基本框架**。 它定义了 `InputType` 基类，提供了创建不同类型 `InputType` 对象的机制，并实现了通用的行为和基础的验证逻辑。 它是 Blink 引擎处理 HTML 表单输入的核心组成部分，与 HTML 结构、CSS 样式以及 JavaScript 交互密切相关，并致力于保证用户输入的有效性和提供友好的用户体验。

### 提示词
```
这是目录为blink/renderer/core/html/forms/input_type.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc. All
 * rights reserved.
 *           (C) 2006 Alexey Proskuryakov (ap@nypop.com)
 * Copyright (C) 2007 Samuel Weinig (sam@webkit.org)
 * Copyright (C) 2009, 2010, 2011, 2012 Google Inc. All rights reserved.
 * Copyright (C) 2012 Samsung Electronics. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "third_party/blink/renderer/core/html/forms/input_type.h"

#include <limits>
#include <memory>
#include <utility>

#include "base/debug/crash_logging.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/fileapi/file_list.h"
#include "third_party/blink/renderer/core/html/forms/button_input_type.h"
#include "third_party/blink/renderer/core/html/forms/checkbox_input_type.h"
#include "third_party/blink/renderer/core/html/forms/color_chooser.h"
#include "third_party/blink/renderer/core/html/forms/color_input_type.h"
#include "third_party/blink/renderer/core/html/forms/date_input_type.h"
#include "third_party/blink/renderer/core/html/forms/date_time_local_input_type.h"
#include "third_party/blink/renderer/core/html/forms/email_input_type.h"
#include "third_party/blink/renderer/core/html/forms/file_input_type.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/html/forms/hidden_input_type.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/image_input_type.h"
#include "third_party/blink/renderer/core/html/forms/month_input_type.h"
#include "third_party/blink/renderer/core/html/forms/number_input_type.h"
#include "third_party/blink/renderer/core/html/forms/password_input_type.h"
#include "third_party/blink/renderer/core/html/forms/radio_input_type.h"
#include "third_party/blink/renderer/core/html/forms/range_input_type.h"
#include "third_party/blink/renderer/core/html/forms/reset_input_type.h"
#include "third_party/blink/renderer/core/html/forms/search_input_type.h"
#include "third_party/blink/renderer/core/html/forms/submit_input_type.h"
#include "third_party/blink/renderer/core/html/forms/telephone_input_type.h"
#include "third_party/blink/renderer/core/html/forms/text_input_type.h"
#include "third_party/blink/renderer/core/html/forms/time_input_type.h"
#include "third_party/blink/renderer/core/html/forms/url_input_type.h"
#include "third_party/blink/renderer/core/html/forms/week_input_type.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"

namespace blink {

const AtomicString& InputType::TypeToString(Type type) {
  switch (type) {
    case Type::kButton:
      return input_type_names::kButton;
    case Type::kCheckbox:
      return input_type_names::kCheckbox;
    case Type::kColor:
      return input_type_names::kColor;
    case Type::kDate:
      return input_type_names::kDate;
    case Type::kDateTimeLocal:
      return input_type_names::kDatetimeLocal;
    case Type::kEmail:
      return input_type_names::kEmail;
    case Type::kFile:
      return input_type_names::kFile;
    case Type::kHidden:
      return input_type_names::kHidden;
    case Type::kImage:
      return input_type_names::kImage;
    case Type::kMonth:
      return input_type_names::kMonth;
    case Type::kNumber:
      return input_type_names::kNumber;
    case Type::kPassword:
      return input_type_names::kPassword;
    case Type::kRadio:
      return input_type_names::kRadio;
    case Type::kRange:
      return input_type_names::kRange;
    case Type::kReset:
      return input_type_names::kReset;
    case Type::kSearch:
      return input_type_names::kSearch;
    case Type::kSubmit:
      return input_type_names::kSubmit;
    case Type::kTelephone:
      return input_type_names::kTel;
    case Type::kText:
      return input_type_names::kText;
    case Type::kTime:
      return input_type_names::kTime;
    case Type::kURL:
      return input_type_names::kUrl;
    case Type::kWeek:
      return input_type_names::kWeek;
  }
  NOTREACHED();
}

// Listed once to avoid any discrepancy between InputType::Create and
// InputType::NormalizeTypeName.
//
// No need to register "text" because it is the default type.
#define INPUT_TYPES(INPUT_TYPE)                      \
  INPUT_TYPE(kButton, ButtonInputType)               \
  INPUT_TYPE(kCheckbox, CheckboxInputType)           \
  INPUT_TYPE(kColor, ColorInputType)                 \
  INPUT_TYPE(kDate, DateInputType)                   \
  INPUT_TYPE(kDatetimeLocal, DateTimeLocalInputType) \
  INPUT_TYPE(kEmail, EmailInputType)                 \
  INPUT_TYPE(kFile, FileInputType)                   \
  INPUT_TYPE(kHidden, HiddenInputType)               \
  INPUT_TYPE(kImage, ImageInputType)                 \
  INPUT_TYPE(kMonth, MonthInputType)                 \
  INPUT_TYPE(kNumber, NumberInputType)               \
  INPUT_TYPE(kPassword, PasswordInputType)           \
  INPUT_TYPE(kRadio, RadioInputType)                 \
  INPUT_TYPE(kRange, RangeInputType)                 \
  INPUT_TYPE(kReset, ResetInputType)                 \
  INPUT_TYPE(kSearch, SearchInputType)               \
  INPUT_TYPE(kSubmit, SubmitInputType)               \
  INPUT_TYPE(kTel, TelephoneInputType)               \
  INPUT_TYPE(kTime, TimeInputType)                   \
  INPUT_TYPE(kUrl, URLInputType)                     \
  INPUT_TYPE(kWeek, WeekInputType)

InputType* InputType::Create(HTMLInputElement& element,
                             const AtomicString& type_name) {
  if (type_name.empty())
    return MakeGarbageCollected<TextInputType>(element);

#define INPUT_TYPE_FACTORY(input_type, class_name) \
  if (type_name == input_type_names::input_type)   \
    return MakeGarbageCollected<class_name>(element);
  INPUT_TYPES(INPUT_TYPE_FACTORY)
#undef INPUT_TYPE_FACTORY

  return MakeGarbageCollected<TextInputType>(element);
}

const AtomicString& InputType::NormalizeTypeName(
    const AtomicString& type_name) {
  if (type_name.empty())
    return input_type_names::kText;

  AtomicString type_name_lower = type_name.LowerASCII();

#define NORMALIZE_INPUT_TYPE(input_type, class_name)   \
  if (type_name_lower == input_type_names::input_type) \
    return input_type_names::input_type;
  INPUT_TYPES(NORMALIZE_INPUT_TYPE)
#undef NORMALIZE_INPUT_TYPE

  return input_type_names::kText;
}

InputType::~InputType() = default;

void InputType::Trace(Visitor* visitor) const {
  visitor->Trace(element_);
}

const AtomicString& InputType::FormControlTypeAsString() const {
  return TypeToString(type_);
}

bool InputType::IsAutoDirectionalityFormAssociated() const {
  return false;
}

template <typename T>
bool ValidateInputType(const T& input_type, const String& value) {
  if (!input_type.CanSetStringValue()) {
    NOTREACHED();
  }
  return !input_type.TypeMismatchFor(value) &&
         !input_type.StepMismatch(value) && !input_type.RangeUnderflow(value) &&
         !input_type.RangeOverflow(value) &&
         !input_type.PatternMismatch(value) && !input_type.ValueMissing(value);
}

// Do not use virtual function for performance reason.
bool InputType::IsValidValue(const String& value) const {
  switch (type_) {
    case Type::kButton:
      return ValidateInputType(To<ButtonInputType>(*this), value);
    case Type::kCheckbox:
      return ValidateInputType(To<CheckboxInputType>(*this), value);
    case Type::kColor:
      return ValidateInputType(To<ColorInputType>(*this), value);
    case Type::kDate:
      return ValidateInputType(To<DateInputType>(*this), value);
    case Type::kDateTimeLocal:
      return ValidateInputType(To<DateTimeLocalInputType>(*this), value);
    case Type::kEmail:
      return ValidateInputType(To<EmailInputType>(*this), value);
    case Type::kFile:
      return ValidateInputType(To<FileInputType>(*this), value);
    case Type::kHidden:
      return ValidateInputType(To<HiddenInputType>(*this), value);
    case Type::kImage:
      return ValidateInputType(To<ImageInputType>(*this), value);
    case Type::kMonth:
      return ValidateInputType(To<MonthInputType>(*this), value);
    case Type::kNumber:
      return ValidateInputType(To<NumberInputType>(*this), value);
    case Type::kPassword:
      return ValidateInputType(To<PasswordInputType>(*this), value);
    case Type::kRadio:
      return ValidateInputType(To<RadioInputType>(*this), value);
    case Type::kRange:
      return ValidateInputType(To<RangeInputType>(*this), value);
    case Type::kReset:
      return ValidateInputType(To<ResetInputType>(*this), value);
    case Type::kSearch:
      return ValidateInputType(To<SearchInputType>(*this), value);
    case Type::kSubmit:
      return ValidateInputType(To<SubmitInputType>(*this), value);
    case Type::kTelephone:
      return ValidateInputType(To<TelephoneInputType>(*this), value);
    case Type::kTime:
      return ValidateInputType(To<TimeInputType>(*this), value);
    case Type::kURL:
      return ValidateInputType(To<URLInputType>(*this), value);
    case Type::kWeek:
      return ValidateInputType(To<WeekInputType>(*this), value);
    case Type::kText:
      return ValidateInputType(To<TextInputType>(*this), value);
  }
  NOTREACHED();
}

bool InputType::ShouldSaveAndRestoreFormControlState() const {
  return true;
}

bool InputType::IsFormDataAppendable() const {
  // There is no form data unless there's a name for non-image types.
  return !GetElement().GetName().empty();
}

void InputType::AppendToFormData(FormData& form_data) const {
  if (!IsSubmitInputType()) {
    form_data.AppendFromElement(GetElement().GetName(), GetElement().Value());
  }
  if (IsAutoDirectionalityFormAssociated()) {
    const AtomicString& dirname_attr_value =
        GetElement().FastGetAttribute(html_names::kDirnameAttr);
    if (!dirname_attr_value.IsNull()) {
      form_data.AppendFromElement(dirname_attr_value,
                                  GetElement().DirectionForFormData());
    }
  }
}

String InputType::ResultForDialogSubmit() const {
  return GetElement().FastGetAttribute(html_names::kValueAttr);
}

double InputType::ValueAsDate() const {
  return DateComponents::InvalidMilliseconds();
}

void InputType::SetValueAsDate(const std::optional<base::Time>&,
                               ExceptionState& exception_state) const {
  exception_state.ThrowDOMException(
      DOMExceptionCode::kInvalidStateError,
      "This input element does not support Date values.");
}

double InputType::ValueAsDouble() const {
  return std::numeric_limits<double>::quiet_NaN();
}

void InputType::SetValueAsDouble(double double_value,
                                 TextFieldEventBehavior event_behavior,
                                 ExceptionState& exception_state) const {
  exception_state.ThrowDOMException(
      DOMExceptionCode::kInvalidStateError,
      "This input element does not support Number values.");
}

void InputType::SetValueAsDecimal(const Decimal& new_value,
                                  TextFieldEventBehavior event_behavior,
                                  ExceptionState&) const {
  GetElement().SetValue(Serialize(new_value), event_behavior);
}

void InputType::ReadingChecked() const {}

void InputType::WillUpdateCheckedness(bool) {}

bool InputType::SupportsValidation() const {
  return true;
}

// Do not use virtual function for performance reason.
bool InputType::TypeMismatchFor(const String& value) const {
  switch (type_) {
    case Type::kDate:
    case Type::kDateTimeLocal:
    case Type::kMonth:
    case Type::kTime:
    case Type::kWeek:
      return To<BaseTemporalInputType>(*this).TypeMismatchFor(value);
    case Type::kColor:
      return To<ColorInputType>(*this).TypeMismatchFor(value);
    case Type::kEmail:
      return To<EmailInputType>(*this).TypeMismatchFor(value);
    case Type::kRange:
      return To<RangeInputType>(*this).TypeMismatchFor(value);
    case Type::kURL:
      return To<URLInputType>(*this).TypeMismatchFor(value);
    case Type::kNumber:
    case Type::kButton:
    case Type::kCheckbox:
    case Type::kFile:
    case Type::kHidden:
    case Type::kImage:
    case Type::kPassword:
    case Type::kRadio:
    case Type::kReset:
    case Type::kSearch:
    case Type::kSubmit:
    case Type::kTelephone:
    case Type::kText:
      return false;
  }
  NOTREACHED();
}

bool InputType::TypeMismatch() const {
  return false;
}

bool InputType::SupportsRequired() const {
  // Almost all validatable types support @required.
  return SupportsValidation();
}

// Do not use virtual function for performance reason.
bool InputType::ValueMissing(const String& value) const {
  switch (type_) {
    case Type::kDate:
    case Type::kDateTimeLocal:
    case Type::kMonth:
    case Type::kTime:
    case Type::kWeek:
      return To<BaseTemporalInputType>(*this).ValueMissing(value);
    case Type::kCheckbox:
      return To<CheckboxInputType>(*this).ValueMissing(value);
    case Type::kFile:
      return To<FileInputType>(*this).ValueMissing(value);
    case Type::kRadio:
      return To<RadioInputType>(*this).ValueMissing(value);
    case Type::kEmail:
    case Type::kPassword:
    case Type::kSearch:
    case Type::kTelephone:
    case Type::kURL:
    case Type::kText:
    case Type::kNumber:
      return To<TextFieldInputType>(*this).ValueMissing(value);
    case Type::kColor:
    case Type::kRange:
    case Type::kButton:
    case Type::kHidden:
    case Type::kImage:
    case Type::kReset:
    case Type::kSubmit:
      return false;
  }
  NOTREACHED();
}

bool InputType::TooLong(const String&,
                        TextControlElement::NeedsToCheckDirtyFlag) const {
  return false;
}

bool InputType::TooShort(const String&,
                         TextControlElement::NeedsToCheckDirtyFlag) const {
  return false;
}

// Do not use virtual function for performance reason.
bool InputType::PatternMismatch(const String& value) const {
  switch (type_) {
    case Type::kEmail:
    case Type::kPassword:
    case Type::kSearch:
    case Type::kTelephone:
    case Type::kURL:
    case Type::kText:
      return To<BaseTextInputType>(*this).PatternMismatch(value);
    case Type::kDate:
    case Type::kDateTimeLocal:
    case Type::kMonth:
    case Type::kTime:
    case Type::kWeek:
    case Type::kCheckbox:
    case Type::kFile:
    case Type::kRadio:
    case Type::kNumber:
    case Type::kColor:
    case Type::kRange:
    case Type::kButton:
    case Type::kHidden:
    case Type::kImage:
    case Type::kReset:
    case Type::kSubmit:
      return false;
  }
  NOTREACHED();
}

bool InputType::RangeUnderflow(const String& value) const {
  if (!IsSteppable())
    return false;

  const Decimal numeric_value = ParseToNumberOrNaN(value);
  if (!numeric_value.IsFinite())
    return false;

  StepRange step_range = CreateStepRange(kRejectAny);
  if (step_range.HasReversedRange()) {
    // With a reversed range, any value outside of the midnight-crossing valid
    // range is considered underflow and overflow.
    return numeric_value > step_range.Maximum() &&
           numeric_value < step_range.Minimum();
  } else {
    return numeric_value < step_range.Minimum();
  }
}

bool InputType::RangeOverflow(const String& value) const {
  if (!IsSteppable())
    return false;

  const Decimal numeric_value = ParseToNumberOrNaN(value);
  if (!numeric_value.IsFinite())
    return false;

  StepRange step_range = CreateStepRange(kRejectAny);
  if (step_range.HasReversedRange()) {
    // With a reversed range, any value outside of the midnight-crossing valid
    // range is considered underflow and overflow.
    return numeric_value > step_range.Maximum() &&
           numeric_value < step_range.Minimum();
  } else {
    return numeric_value > step_range.Maximum();
  }
}

Decimal InputType::DefaultValueForStepUp() const {
  return 0;
}

double InputType::Minimum() const {
  return CreateStepRange(kRejectAny).Minimum().ToDouble();
}

double InputType::Maximum() const {
  return CreateStepRange(kRejectAny).Maximum().ToDouble();
}

bool InputType::IsInRange(const String& value) const {
  if (!IsSteppable())
    return false;

  // This function should return true if both of validity.rangeUnderflow and
  // validity.rangeOverflow are false.
  // If the INPUT has no value, they are false.
  const Decimal numeric_value = ParseToNumberOrNaN(value);
  if (!numeric_value.IsFinite())
    return true;

  StepRange step_range(CreateStepRange(kRejectAny));
  return step_range.HasRangeLimitations() &&
         numeric_value >= step_range.Minimum() &&
         numeric_value <= step_range.Maximum();
}

bool InputType::IsOutOfRange(const String& value) const {
  if (!IsSteppable())
    return false;

  // This function should return true if either validity.rangeUnderflow or
  // validity.rangeOverflow are true.
  // If the INPUT has no value, they are false.
  const Decimal numeric_value = ParseToNumberOrNaN(value);
  if (!numeric_value.IsFinite())
    return false;

  StepRange step_range(CreateStepRange(kRejectAny));
  return step_range.HasRangeLimitations() &&
         (numeric_value < step_range.Minimum() ||
          numeric_value > step_range.Maximum());
}

void InputType::InRangeChanged() const {
  if (IsSteppable()) {
    GetElement().PseudoStateChanged(CSSSelector::kPseudoInRange);
    GetElement().PseudoStateChanged(CSSSelector::kPseudoOutOfRange);
  }
}

bool InputType::StepMismatch(const String& value) const {
  if (!IsSteppable())
    return false;

  const Decimal numeric_value = ParseToNumberOrNaN(value);
  if (!numeric_value.IsFinite())
    return false;

  return CreateStepRange(kRejectAny).StepMismatch(numeric_value);
}

String InputType::BadInputText() const {
  NOTREACHED();
}

String InputType::ValueNotEqualText(const Decimal& value) const {
  DUMP_WILL_BE_NOTREACHED();
  return String();
}

String InputType::RangeOverflowText(const Decimal&) const {
  static auto* input_type = base::debug::AllocateCrashKeyString(
      "input-type", base::debug::CrashKeySize::Size32);
  base::debug::SetCrashKeyString(
      input_type, FormControlTypeAsString().GetString().Utf8().c_str());
  NOTREACHED() << "This should not get called. Check if input type '"
               << FormControlTypeAsString()
               << "' should have a RangeOverflowText implementation."
               << "See crbug.com/1423280";
}

String InputType::RangeUnderflowText(const Decimal&) const {
  static auto* input_type = base::debug::AllocateCrashKeyString(
      "input-type", base::debug::CrashKeySize::Size32);
  base::debug::SetCrashKeyString(
      input_type, FormControlTypeAsString().GetString().Utf8().c_str());
  NOTREACHED() << "This should not get called. Check if input type '"
               << FormControlTypeAsString()
               << "' should have a RangeUnderflowText implementation."
               << "See crbug.com/1423280";
}

String InputType::ReversedRangeOutOfRangeText(const Decimal&,
                                              const Decimal&) const {
  NOTREACHED();
}

String InputType::RangeInvalidText(const Decimal&, const Decimal&) const {
  static auto* input_type = base::debug::AllocateCrashKeyString(
      "input-type", base::debug::CrashKeySize::Size32);
  base::debug::SetCrashKeyString(
      input_type, FormControlTypeAsString().GetString().Utf8().c_str());
  NOTREACHED() << "This should not get called. Check if input type '"
               << FormControlTypeAsString()
               << "' should have a RangeInvalidText implementation."
               << "See crbug.com/1474270";
}

String InputType::TypeMismatchText() const {
  return GetLocale().QueryString(IDS_FORM_VALIDATION_TYPE_MISMATCH);
}

String InputType::ValueMissingText() const {
  return GetLocale().QueryString(IDS_FORM_VALIDATION_VALUE_MISSING);
}

std::pair<String, String> InputType::ValidationMessage(
    const InputTypeView& input_type_view) const {
  const String value = GetElement().Value();

  // The order of the following checks is meaningful. e.g. We'd like to show the
  // badInput message even if the control has other validation errors.
  if (input_type_view.HasBadInput())
    return std::make_pair(BadInputText(), g_empty_string);

  if (ValueMissing(value))
    return std::make_pair(ValueMissingText(), g_empty_string);

  if (TypeMismatch())
    return std::make_pair(TypeMismatchText(), g_empty_string);

  if (PatternMismatch(value)) {
    // https://html.spec.whatwg.org/C/#attr-input-pattern
    //   When an input element has a pattern attribute specified, authors
    //   should include a title attribute to give a description of the
    //   pattern. User agents may use the contents of this attribute, if it
    //   is present, when informing the user that the pattern is not matched
    return std::make_pair(
        GetLocale().QueryString(IDS_FORM_VALIDATION_PATTERN_MISMATCH),
        GetElement().FastGetAttribute(html_names::kTitleAttr).GetString());
  }

  if (GetElement().TooLong()) {
    return std::make_pair(GetLocale().ValidationMessageTooLongText(
                              value.length(), GetElement().maxLength()),
                          g_empty_string);
  }

  if (GetElement().TooShort()) {
    return std::make_pair(GetLocale().ValidationMessageTooShortText(
                              value.length(), GetElement().minLength()),
                          g_empty_string);
  }

  if (!IsSteppable())
    return std::make_pair(g_empty_string, g_empty_string);

  const Decimal numeric_value = ParseToNumberOrNaN(value);
  if (!numeric_value.IsFinite())
    return std::make_pair(g_empty_string, g_empty_string);

  StepRange step_range(CreateStepRange(kRejectAny));

  if (step_range.Minimum() > step_range.Maximum() &&
      !step_range.HasReversedRange()) {
    return std::make_pair(
        RangeInvalidText(step_range.Minimum(), step_range.Maximum()),
        g_empty_string);
  }

  if (step_range.HasReversedRange() && numeric_value < step_range.Minimum() &&
      numeric_value > step_range.Maximum()) {
    return std::make_pair(
        ReversedRangeOutOfRangeText(step_range.Minimum(), step_range.Maximum()),
        g_empty_string);
  }

  if (numeric_value != step_range.Minimum() &&
      step_range.Minimum() == step_range.Maximum()) {
    return std::make_pair(ValueNotEqualText(step_range.Minimum()),
                          g_empty_string);
  }

  if (numeric_value < step_range.Minimum())
    return std::make_pair(RangeUnderflowText(step_range.Minimum()),
                          g_empty_string);

  if (numeric_value > step_range.Maximum())
    return std::make_pair(RangeOverflowText(step_range.Maximum()),
                          g_empty_string);

  if (step_range.StepMismatch(numeric_value)) {
    DCHECK(step_range.HasStep());
    Decimal candidate1 = step_range.ClampValue(numeric_value);
    String localized_candidate1 = LocalizeValue(Serialize(candidate1));
    Decimal candidate2 = candidate1 < numeric_value
                             ? candidate1 + step_range.Step()
                             : candidate1 - step_range.Step();
    if (!candidate2.IsFinite() || candidate2 < step_range.Minimum() ||
        candidate2 > step_range.Maximum()) {
      return std::make_pair(
          GetLocale().QueryString(
              IDS_FORM_VALIDATION_STEP_MISMATCH_CLOSE_TO_LIMIT,
              localized_candidate1),
          g_empty_string);
    }
    String localized_candidate2 = LocalizeValue(Serialize(candidate2));
    if (candidate1 < candidate2) {
      return std::make_pair(
          GetLocale().QueryString(IDS_FORM_VALIDATION_STEP_MISMATCH,
                                  localized_candidate1, localized_candidate2),
          g_empty_string);
    }
    return std::make_pair(
        GetLocale().QueryString(IDS_FORM_VALIDATION_STEP_MISMATCH,
                                localized_candidate2, localized_candidate1),
        g_empty_string);
  }

  return std::make_pair(g_empty_string, g_empty_string);
}

Decimal InputType::ParseToNumber(const String&,
                                 const Decimal& default_value) const {
  NOTREACHED();
}

Decimal InputType::ParseToNumberOrNaN(const String& string) const {
  return ParseToNumber(string, Decimal::Nan());
}

String InputType::Serialize(const Decimal&) const {
  NOTREACHED();
}

ChromeClient* InputType::GetChromeClient() const {
  if (Page* page = GetElement().GetDocument().GetPage())
    return &page->GetChromeClient();
  return nullptr;
}

Locale& InputType::GetLocale() const {
  return GetElement().GetLocale();
}

// Do not use virtual function for performance reason.
bool InputType::CanSetStringValue() const {
  switch (type_) {
    case Type::kRadio:
    case Type::kCheckbox:
      return To<BaseCheckableInputType>(*this).CanSetStringValue();
    case Type::kFile:
      return To<FileInputType>(*this).CanSetStringValue();
    case Type::kEmail:
    case Type::kPassword:
    case Type::kSearch:
    case Type::kTelephone:
    case Type::kURL:
    case Type::kText:
    case Type::kDate:
    case Type::kDateTimeLocal:
    case Type::kMonth:
    case Type::kTime:
    case Type::kWeek:
    case Type::kNumber:
    case Type::kColor:
    case Type::kRange:
    case Type::kButton:
    case Type::kHidden:
    case Type::kImage:
    case Type::kReset:
    case Type::kSubmit:
      return true;
  }
  NOTREACHED();
}

bool InputType::IsKeyboardFocusable(
    Element::UpdateBehavior update_behavior) const {
  // Inputs are always keyboard focusable if they are focusable at all,
  // and don't have a negative tabindex set.
  return GetElement().IsFocusable(update_behavior) &&
         GetElement().tabIndex() >= 0;
}

bool InputType::MayTriggerVirtualKeyboard() const {
  return false;
}

void InputType::CountUsage() {}

void InputType::DidRecalcStyle(const StyleRecalcChange) {}

bool InputType::ShouldRespectAlignAttribute() {
  return false;
}

void InputType::SanitizeValueInResponseToMinOrMaxAttributeChange() {}

bool InputType::CanBeSuccessfulSubmitButton() {
  return false;
}

bool InputType::MatchesDefaultPseudoClass() {
  return false;
}

bool InputType::LayoutObjectIsNeeded() {
  return true;
}

FileList* InputType::Files() {
  return nullptr;
}

bool InputType::SetFiles(FileList*) {
  return false;
}

void InputType::SetFilesAndDispatchEvents(FileList*) {}

void InputType::SetFilesFromPaths(const Vector<String>& paths) {}

String InputType::ValueInFilenameValueMode() const {
  NOTREACHED();
}

String InputType::DefaultLabel() const {
  return String();
}

bool InputType::CanSetSuggestedValue() {
  return false;
}

bool InputType::ShouldSendChangeEventAfterCheckedChanged() {
  return true;
}

void InputType::DispatchSearchEvent() {}

void InputType::SetValue(const String& sanitized_value,
                         bool value_changed,
                         TextFieldEventBehavior event_behavior,
                         TextControlSetValueSelection) {
  // This setValue() implementation is used only for ValueMode::kValue except
  // TextFieldInputType. That is to say, type=color, type=range, and temporal
  // input types.
  DCHECK_EQ(GetValueMode(), ValueMode::kValue);
  if (event_behavior == TextFieldEventBehavior::kDispatchNoEvent)
    GetElement().SetNonAttributeValue(sanitized_value);
  else
    GetElement().SetNonAttributeValueByUserEdit(sanitized_value);
  if (!value_changed)
    return;
  switch (event_behavior) {
    case TextFieldEventBehavior::kDispatchChangeEvent:
      GetElement().DispatchFormControlChangeEvent();
      break;
    case TextFieldEventBehavior::kDispatchInputEvent:
      GetElement().DispatchInputEvent();
      break;
    case TextFieldEventBehavior::kDispatchInputAndChangeEvent:
      GetElement().DispatchInputEvent();
      GetElement().DispatchFormControlChangeEvent();
      break;
    case TextFieldEventBehavior::kDispatchNoEvent:
      break;
  }
}

bool InputType::CanSetValue(const String&) {
  return true;
}

String InputType::LocalizeValue(const String& proposed_value) const {
  return proposed_value;
}

String InputType::VisibleValue() const {
  return GetElement().Value();
}

String InputType::SanitizeValue(const String& proposed_value) const {
  return proposed_value;
}

String InputType::SanitizeUserInputValue(const String& proposed_value) const {
  return SanitizeValue(proposed_value);
}

void InputType::WarnIfValueIsInvalidAndElementIsVisible(
    const String& value) const {
  // Don't warn if the value is set in Modernizr.
  const ComputedStyle* style = GetElement().GetComputedStyle();
  if (style && style->Visibility() != EVisibility::kHidden) {
    WarnIfValueIsInvalid(value);
  }
}

void InputType::WarnIfValueIsInvalid(const String&) const {}

bool InputType::ReceiveDroppedFiles(const DragData*) {
  NOTREACHED();
}

String InputType::DroppedFileSystemId() {
  NOTREACHED();
}

bool InputType::ShouldRespectListAttribute() {
  return false;
}

bool InputType::IsInteractiveContent() const {
  return true;
}

bool InputType::IsEnumeratable() {
  return true;
}

bool InputType::IsCheckable() {
  return false;
}

// Do not use virtual function for performance reason.
bool InputType::IsSteppable() const {
  switch (type_) {
    case Type::kDate:
    case Type::kDateTimeLocal:
    case Type::kMonth:
    case Type::kTime:
    case Type::kWeek:
    case Type::kNumber:
    case Type::kRange:
      return true;
    case Type::kButton:
    case Type::kCheckbox:
    case Type::kColor:
    case Type::kEmail:
    case Type::kFile:
    case Type::kHidden:
    case Type::kImage:
    case Type::kPassword:
    case Type::kRadio:
    case Type::kReset:
    case Type::kSearch:
    case Type::kSubmit:
    case Type::kTelephone:
    case Type::kURL:
    case Type::kText:
      return false;
  }
  NOTREACHED();
}

HTMLFormControlElement::PopoverTriggerSupport
InputType::SupportsPopoverTriggering() const {
  return HTMLFormControlElement::PopoverTriggerSupport::kNone;
}

bool InputType::ShouldRespectHeightAndWidthAttributes() {
  return false;
}

int InputType::MaxLength() const {
  return -1;
}

int InputType::MinLength() const {
  return 0;
}

bool InputType::SupportsPlaceholder() const {
  return false;
}

bool InputType::SupportsReadOnly() const {
  return false;
}

String InputType::DefaultToolTip(const InputTypeView& input_type_view) const {
  if (GetElement().Form() && GetElement().Form()->NoValidate())
    return String();
  return ValidationMessage(input_type_view).first;
}

Decimal InputType::FindClosestTickMarkValue(const Decimal&) {
  NOTREACHED();
}

bool InputType::HasLegalLinkAttribute(const QualifiedName&) const {
  return false;
}

void InputType::CopyNonAttributeProperties(const HTMLInputElement&) {}

void InputType::OnAttachWithLayoutObject() {}

bool InputType::ShouldAppearIndeterminate() const {
  return false;
}

bool InputType::
```