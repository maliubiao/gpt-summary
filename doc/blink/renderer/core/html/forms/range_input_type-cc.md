Response:
Let's break down the thought process for analyzing this `range_input_type.cc` file.

1. **Understand the Goal:** The request is to understand the functionality of this specific Chromium Blink source file (`range_input_type.cc`), its relations to web technologies (HTML, CSS, JavaScript), potential user errors, and the user journey that leads to its execution.

2. **Initial Scan and Keyword Identification:**  Quickly read through the file, looking for prominent keywords and class names. Notice things like:
    * `RangeInputType` (the central class)
    * `HTMLInputElement`
    * `SliderThumbElement`, `SliderTrackElement`
    * `HandleMouseDownEvent`, `HandleKeydownEvent`
    * `CreateShadowSubtree`
    * `ValueAsDouble`, `SetValueAsDouble`
    * `StepRange`
    * `kInputTypeRange` (UseCounter)
    * `kSliderHorizontalPart`, `kSliderVerticalPart`
    * `HTMLDataListElement`, `HTMLOptionElement` (tick marks)

3. **Core Functionality - Deconstruct the Class:** The class name `RangeInputType` immediately suggests this code is responsible for the behavior of `<input type="range">` elements in a web page. Focus on the methods:
    * **Constructor:**  Sets up initial state.
    * **`CreateView()`:** Returns `this`, indicating this class handles the view logic.
    * **`GetValueMode()`:** Returns `kValue`, suggesting it primarily deals with the input's value.
    * **`CountUsage()` and `DidRecalcStyle()`:**  Related to tracking feature usage and style changes, connecting to browser metrics and CSS.
    * **`ValueAsDouble()` and `SetValueAsDouble()`:**  Handle getting and setting the numerical value, relating to JavaScript interaction.
    * **`TypeMismatchFor()`:**  Validates input, important for form submission and client-side validation.
    * **`SupportsRequired()`:**  Indicates whether the `required` attribute is supported (it's not for range inputs).
    * **`CreateStepRange()`:**  Calculates the valid steps based on `min`, `max`, and `step` attributes – crucial for the range input's constraints.
    * **Event Handlers (`HandleMouseDownEvent`, `HandleKeydownEvent`):** Implement the interactive behavior when the user clicks or presses keys, directly linked to user interaction.
    * **`CreateShadowSubtree()`:**  Creates the internal structure (thumb and track) of the range input, demonstrating the use of Shadow DOM.
    * **`CreateLayoutObject()` and `AdjustStyle()`:** Relate to how the range input is rendered on the page, connecting to the browser's layout engine and CSS.
    * **`ParseToNumber()`, `Serialize()`:** Handle converting between string and numerical representations of the value.
    * **`AccessKeyAction()`:**  Handles keyboard shortcuts.
    * **`SanitizeValueInResponseToMinOrMaxAttributeChange()`, `StepAttributeChanged()`:**  React to changes in HTML attributes.
    * **`DidSetValue()`:** Updates the view when the value changes.
    * **`UpdateView()`:**  Visually updates the slider thumb's position based on the value.
    * **`SanitizeValue()`:** Ensures the value is within the valid range and respects the `step`.
    * **Validation-related methods (`RangeOverflowText`, `RangeUnderflowText`, `RangeInvalidText`):** Provide localized error messages.
    * **`DisabledAttributeChanged()`:** Handles changes to the `disabled` attribute.
    * **`ShouldRespectListAttribute()`:** Indicates that the `datalist` attribute is relevant.
    * **Tick mark related methods (`ListAttributeTargetChanged`, `UpdateTickMarkValues`, `FindClosestTickMarkValue`):** Implement the functionality for displaying and snapping to predefined values from a `datalist`.
    * **`ValueAttributeChanged()`:** Updates the view when the `value` attribute changes directly.
    * **`IsDraggedSlider()`:**  Indicates if the user is currently dragging the slider thumb.

4. **Relating to Web Technologies:**
    * **HTML:** The core purpose is to implement `<input type="range">`. The code directly interacts with HTML attributes like `min`, `max`, `step`, `value`, `disabled`, and `list`.
    * **CSS:** The `DidRecalcStyle()` method shows how the code tracks CSS styles, particularly the `appearance` property for vertical sliders and writing direction. `AdjustStyle()` hints at how the input's layout is influenced by CSS. The shadow DOM also encapsulates styling.
    * **JavaScript:**  Methods like `ValueAsDouble()` and `SetValueAsDouble()` are the bridge for JavaScript to get and set the range input's value. Event handlers like `HandleMouseDownEvent` and `HandleKeydownEvent` respond to user interactions that JavaScript can trigger or observe.

5. **Logic and Examples:**
    * Focus on the `HandleKeydownEvent`. Trace the logic for different key presses (arrow keys, Page Up/Down, Home/End) and how the `StepRange` is used to calculate the new value. Create simple input/output examples.
    * Consider the `SanitizeValue()` method and how it ensures the value adheres to the `min`, `max`, and `step` attributes.

6. **User/Programming Errors:** Think about common mistakes when using range inputs:
    * Setting `min` greater than `max`.
    * Providing non-numeric or out-of-range values via JavaScript.
    * Incorrectly using the `step` attribute.
    * Not understanding how the `datalist` works for tick marks.

7. **User Journey:** Imagine a user interacting with a range input:
    * The browser parses the HTML and creates the `HTMLInputElement`.
    * Blink's rendering engine uses `RangeInputType` to create the interactive slider.
    * The user moves the slider thumb (triggering mouse events handled by `HandleMouseDownEvent`).
    * The user adjusts the value using the keyboard (`HandleKeydownEvent`).
    * JavaScript might read or set the value using `element.value` (calling `ValueAsDouble` or `SetValueAsDouble` internally).
    * Form submission would use the current value.

8. **Structure and Refine:** Organize the findings into logical sections (Functionality, Web Technology Relations, Logic Examples, Errors, User Journey). Use clear and concise language. Add code snippets where relevant for illustration. Ensure the explanation is understandable to someone with some web development knowledge but perhaps not deep into Blink's internals.

9. **Review and Enhance:** Read through the generated response. Are there any ambiguities?  Could examples be clearer? Is the connection to the source code evident?  For example, explicitly mention the files and methods involved.

Self-Correction Example during the process:  Initially, I might just say "handles mouse clicks."  But the code is more specific: it checks for left clicks, ensures the target is within the slider, and initiates dragging of the thumb. So, refine the description to be more precise. Similarly, initially I might overlook the `datalist` functionality, but noticing the `ListAttributeTargetChanged`, `UpdateTickMarkValues`, and `FindClosestTickMarkValue` methods prompts a deeper look and inclusion of this feature in the explanation.
好的，让我们来详细分析一下 `blink/renderer/core/html/forms/range_input_type.cc` 这个文件。

**文件功能总览:**

`range_input_type.cc` 文件是 Chromium Blink 渲染引擎中负责处理 `<input type="range">` HTML 元素的核心逻辑。它定义了 `RangeInputType` 类，该类继承自 `InputType` 并实现了 `InputTypeView` 接口，从而负责了 range 类型 input 元素的行为、渲染和与用户的交互。

**具体功能分解:**

1. **类型定义和注册:**  该文件定义了 `RangeInputType` 类，并将其注册为处理 `type="range"` 的 input 元素。

2. **默认值和常量:**  定义了 range 输入框的默认最小值 (`kRangeDefaultMinimum`)、最大值 (`kRangeDefaultMaximum`)、步长 (`kRangeDefaultStep`) 和步长基准 (`kRangeDefaultStepBase`)。

3. **值处理:**
   - `ValueAsDouble()`:  将 input 元素的当前字符串值解析为浮点数。这与 JavaScript 中访问 `inputElement.value` 属性并将其转换为数字的行为相关。
   - `SetValueAsDouble()`:  设置 input 元素的数值，并将该值转换为字符串存储。这对应于 JavaScript 中设置 `inputElement.value` 属性。
   - `TypeMismatchFor()`:  检查给定的字符串值是否能被解析为有效的数字。这与 HTML 表单验证中检查输入类型是否匹配有关。
   - `SanitizeValue()`:  根据 `min`, `max`, 和 `step` 属性，对用户输入的值进行规范化。例如，如果用户输入的值不在范围内，则会将其调整到最近的有效值。这影响了用户在输入时以及通过 JavaScript 设置值时看到的结果。
   - `ParseToNumber()` 和 `Serialize()`:  在字符串和 `Decimal` 类型之间进行转换，`Decimal` 用于更精确地处理数值。

4. **属性处理:**
   - `SupportsRequired()`:  明确指出 `range` 类型的 input 不支持 `required` 属性。
   - `CreateStepRange()`:  根据 `min`, `max`, 和 `step` 属性创建 `StepRange` 对象，该对象负责处理步进逻辑。
   - `SanitizeValueInResponseToMinOrMaxAttributeChange()` 和 `StepAttributeChanged()`:  当 `min`, `max`, 或 `step` 属性发生变化时，更新 input 元素的内部状态和视图。

5. **事件处理:**
   - `HandleMouseDownEvent()`:  处理鼠标按下事件。当用户点击滑块的轨道时，会触发滑块的拖动。这与用户通过鼠标与滑块进行交互直接相关。
   - `HandleKeydownEvent()`:  处理键盘事件。允许用户通过键盘上的方向键 (上/右增大，下/左减小)、Page Up/Down (大步长调整) 和 Home/End 键 (移动到最小值/最大值) 来调整滑块的值。
      - **假设输入:** 用户选中 range 输入框，并按下 "ArrowRight" 键。
      - **逻辑推理:** 代码会读取当前的 value，根据 `step` 属性计算新的值，并更新输入框的 value。
      - **输出:**  滑块的位置会相应移动，`inputElement.value` 的值会更新。
   - `AccessKeyAction()`:  处理访问键 (accesskey) 的触发。

6. **渲染和UI:**
   - `CreateShadowSubtree()`:  创建 range 输入框的 Shadow DOM 结构，包括滑块轨道 (`SliderTrackElement`) 和滑块拇指 (`SliderThumbElement`)。这使得浏览器的默认样式和行为可以被封装起来。
   - `CreateLayoutObject()`:  创建用于布局的 `LayoutFlexibleBox` 对象。
   - `AdjustStyle()`:  调整元素的样式，例如设置基线。
   - `UpdateView()`:  根据当前的 value 更新滑块拇指的位置。
   - `DidRecalcStyle()`:  当样式重新计算时被调用，用于统计 range 类型 input 的使用情况，例如区分水平和垂直滑块，以及文字方向。
      - **CSS 关系举例:**  如果 CSS 中设置了 `appearance: slider-vertical;`，该方法会检测到并增加 `kInputTypeRangeVerticalAppearance` 的计数器。

7. **可访问性:**  在值改变时，会通知可访问性对象缓存 (`AXObjectCache`)，以便屏幕阅读器等辅助技术能够获取到值的变化。

8. **表单集成:**
   -  提供了 `RangeOverflowText()`, `RangeUnderflowText()`, 和 `RangeInvalidText()` 方法，用于生成本地化的验证错误消息，当输入值超出范围或 min/max 设置不正确时显示。

9. **`list` 属性支持 (Tick Marks):**
    - `ShouldRespectListAttribute()`: 返回 `true`，表示 range 输入框可以关联一个 `<datalist>` 元素。
    - `ListAttributeTargetChanged()`: 当关联的 `<datalist>` 元素发生变化时被调用。
    - `UpdateTickMarkValues()`:  从关联的 `<datalist>` 中的 `<option>` 元素提取值，作为滑块上的刻度标记。
    - `FindClosestTickMarkValue()`:  查找最接近当前值的刻度标记，可能用于实现滑块值的吸附效果。
      - **HTML 关系举例:**
        ```html
        <input type="range" min="0" max="100" list="tickmarks">
        <datalist id="tickmarks">
          <option value="10"></option>
          <option value="30"></option>
          <option value="70"></option>
        </datalist>
        ```
        在这个例子中，`UpdateTickMarkValues()` 会提取 10, 30, 和 70 作为刻度标记。

10. **禁用状态处理:**
    - `DisabledAttributeChanged()`: 当 `disabled` 属性改变时，停止滑块的拖动。

**与 JavaScript, HTML, CSS 的功能关系举例:**

* **HTML:**
    - `<input type="range" min="10" max="50" step="5" value="25">`:  这些 HTML 属性 (`min`, `max`, `step`, `value`) 的值会被 `RangeInputType` 读取并用于初始化和限制滑块的行为。
* **CSS:**
    - `input[type="range"]::-webkit-slider-thumb`:  CSS 可以用来定制滑块拇指的外观。`RangeInputType` 创建的 Shadow DOM 结构使得这些伪元素可以被样式化。
    - `appearance: slider-vertical;`:  CSS 属性可以改变滑块的显示方向，`DidRecalcStyle()` 方法会检测到这种变化。
* **JavaScript:**
    - `const rangeInput = document.querySelector('input[type="range"]');`
    - `console.log(rangeInput.value);` // 会调用 `RangeInputType::ValueAsDouble()`
    - `rangeInput.value = 40;` // 会调用 `RangeInputType::SetValueAsDouble()` 和 `RangeInputType::SanitizeValue()`
    - `rangeInput.addEventListener('input', () => { console.log('value changed'); });` // 当用户拖动滑块时，`RangeInputType` 会触发 'input' 事件。

**逻辑推理举例:**

* **假设输入:** 用户拖动滑块拇指到某个位置，使得计算出的新值为 37，但 `step` 属性设置为 5，且 `min` 为 10。
* **逻辑推理:** `SanitizeValue()` 方法会被调用。它会检查 37 是否是 5 的倍数。由于不是，它会将值调整到最接近的有效值，即 35 或 40。具体选择哪个取决于实现细节（通常是更接近的那个）。
* **输出:**  `inputElement.value` 会被设置为 35 或 40，滑块拇指会移动到对应的位置。

**用户或编程常见的使用错误举例:**

1. **`min` 大于 `max`:**
   - **用户操作:**  在 HTML 中设置 `<input type="range" min="100" max="50">`。
   - **后果:** `RangeInputType::CreateStepRange()` 中的逻辑会处理这种情况，通常会将 `max` 调整为不小于 `min` 的值，或者在表单验证时报错。`RangeInvalidText()` 方法会生成相应的错误信息。

2. **通过 JavaScript 设置超出范围的值:**
   - **编程错误:** `rangeInput.value = 200;`，而 `max` 属性为 100。
   - **后果:** `RangeInputType::SanitizeValue()` 会将值规范化为 `max` 值 (100)，用户不会看到 200 这个值。

3. **误解 `step="any"` 的含义:**  虽然代码中提到了处理 `step="any"` 的情况，但 HTML 规范中 `range` 类型的 `step` 属性通常应该是一个正数。使用 `step="any"` 可能导致不一致的行为，且不是标准用法。

**用户操作如何一步步到达这里:**

1. **用户在 HTML 文件中使用了 `<input type="range">` 标签。**
2. **浏览器解析 HTML 代码，创建 `HTMLInputElement` 对象。**
3. **Blink 渲染引擎根据 `type` 属性，创建对应的 `RangeInputType` 对象，并将其与 `HTMLInputElement` 关联。**
4. **浏览器进行布局和渲染，`CreateShadowSubtree()` 被调用，创建滑块的 UI 结构。**
5. **用户与滑块进行交互：**
   - **鼠标拖动:**  鼠标按下事件被捕获，`HandleMouseDownEvent()` 被调用，开始滑块的拖动。鼠标移动事件 (未在此文件中直接显示) 会被处理，更新滑块的位置。鼠标释放后，可能会触发 'change' 或 'input' 事件。
   - **键盘操作:**  用户选中滑块后按下方向键，`HandleKeydownEvent()` 被调用，根据按键调整滑块的值。
6. **JavaScript 交互:**
   - JavaScript 代码可以通过 `element.value` 读取滑块的当前值，这会间接调用 `ValueAsDouble()`。
   - JavaScript 代码可以通过 `element.value = newValue` 设置滑块的值，这会间接调用 `SetValueAsDouble()` 和 `SanitizeValue()`。
7. **表单提交:**  当包含 range 输入框的表单被提交时，`RangeInputType` 的值会被包含在提交的数据中。

总而言之，`range_input_type.cc` 文件是 `<input type="range">` 元素在 Blink 渲染引擎中的“大脑”，它处理了与用户交互、数据验证、UI 更新和与 JavaScript 及 HTML 的集成等所有关键方面。

Prompt: 
```
这是目录为blink/renderer/core/html/forms/range_input_type.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。

"""
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

#include "third_party/blink/renderer/core/html/forms/range_input_type.h"

#include <algorithm>
#include <limits>

#include "third_party/blink/public/common/input/web_pointer_properties.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/dom/events/simulated_click_options.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/html_data_list_element.h"
#include "third_party/blink/renderer/core/html/forms/html_data_list_options_collection.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/slider_thumb_element.h"
#include "third_party/blink/renderer/core/html/forms/slider_track_element.h"
#include "third_party/blink/renderer/core/html/forms/step_range.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/flex/layout_flexible_box.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/text/text_direction.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"

namespace blink {

static const int kRangeDefaultMinimum = 0;
static const int kRangeDefaultMaximum = 100;
static const int kRangeDefaultStep = 1;
static const int kRangeDefaultStepBase = 0;
static const int kRangeStepScaleFactor = 1;

static Decimal EnsureMaximum(const Decimal& proposed_value,
                             const Decimal& minimum) {
  return proposed_value >= minimum ? proposed_value : minimum;
}

RangeInputType::RangeInputType(HTMLInputElement& element)
    : InputType(Type::kRange, element),
      InputTypeView(element),
      tick_mark_values_dirty_(true) {}

void RangeInputType::Trace(Visitor* visitor) const {
  InputTypeView::Trace(visitor);
  InputType::Trace(visitor);
}

InputTypeView* RangeInputType::CreateView() {
  return this;
}

InputType::ValueMode RangeInputType::GetValueMode() const {
  return ValueMode::kValue;
}

void RangeInputType::CountUsage() {
  CountUsageIfVisible(WebFeature::kInputTypeRange);
}

void RangeInputType::DidRecalcStyle(const StyleRecalcChange) {
  if (const ComputedStyle* style = GetElement().GetComputedStyle()) {
    if (RuntimeEnabledFeatures::
            NonStandardAppearanceValueSliderVerticalEnabled() &&
        style->EffectiveAppearance() == kSliderVerticalPart) {
      UseCounter::Count(GetElement().GetDocument(),
                        WebFeature::kInputTypeRangeVerticalAppearance);
    } else {
      bool is_horizontal = style->IsHorizontalWritingMode();
      bool is_ltr = style->IsLeftToRightDirection();
      if (is_horizontal && is_ltr) {
        UseCounter::Count(GetElement().GetDocument(),
                          WebFeature::kInputTypeRangeHorizontalLtr);
      } else if (is_horizontal && !is_ltr) {
        UseCounter::Count(GetElement().GetDocument(),
                          WebFeature::kInputTypeRangeHorizontalRtl);
      } else if (is_ltr) {
        UseCounter::Count(GetElement().GetDocument(),
                          WebFeature::kInputTypeRangeVerticalLtr);
      } else {
        UseCounter::Count(GetElement().GetDocument(),
                          WebFeature::kInputTypeRangeVerticalRtl);
      }
    }
  }
}

double RangeInputType::ValueAsDouble() const {
  return ParseToDoubleForNumberType(GetElement().Value());
}

void RangeInputType::SetValueAsDouble(double new_value,
                                      TextFieldEventBehavior event_behavior,
                                      ExceptionState& exception_state) const {
  SetValueAsDecimal(Decimal::FromDouble(new_value), event_behavior,
                    exception_state);
}

bool RangeInputType::TypeMismatchFor(const String& value) const {
  return !value.empty() && !std::isfinite(ParseToDoubleForNumberType(value));
}

bool RangeInputType::SupportsRequired() const {
  return false;
}

StepRange RangeInputType::CreateStepRange(
    AnyStepHandling any_step_handling) const {
  DEFINE_STATIC_LOCAL(
      const StepRange::StepDescription, step_description,
      (kRangeDefaultStep, kRangeDefaultStepBase, kRangeStepScaleFactor));

  const Decimal step_base = FindStepBase(kRangeDefaultStepBase);
  const Decimal minimum =
      ParseToNumber(GetElement().FastGetAttribute(html_names::kMinAttr),
                    kRangeDefaultMinimum);
  const Decimal maximum = EnsureMaximum(
      ParseToNumber(GetElement().FastGetAttribute(html_names::kMaxAttr),
                    kRangeDefaultMaximum),
      minimum);

  const Decimal step = StepRange::ParseStep(
      any_step_handling, step_description,
      GetElement().FastGetAttribute(html_names::kStepAttr));
  // Range type always has range limitations because it has default
  // minimum/maximum.
  // https://html.spec.whatwg.org/C/#range-state-(type=range):concept-input-min-default
  const bool kHasRangeLimitations = true;
  return StepRange(step_base, minimum, maximum, kHasRangeLimitations,
                   /*has_reversed_range=*/false, step, step_description);
}

void RangeInputType::HandleMouseDownEvent(MouseEvent& event) {
  if (!HasCreatedShadowSubtree()) {
    return;
  }

  if (GetElement().IsDisabledFormControl())
    return;

  Node* target_node = event.target()->ToNode();
  if (event.button() !=
          static_cast<int16_t>(WebPointerProperties::Button::kLeft) ||
      !target_node)
    return;
  DCHECK(IsShadowHost(GetElement()));
  if (target_node != GetElement() &&
      !target_node->IsDescendantOf(GetElement().UserAgentShadowRoot()))
    return;
  SliderThumbElement* thumb = GetSliderThumbElement();
  if (target_node == thumb)
    return;
  thumb->DragFrom(PhysicalOffset::FromPointFFloor(event.AbsoluteLocation()));
}

void RangeInputType::HandleKeydownEvent(KeyboardEvent& event) {
  if (GetElement().IsDisabledFormControl())
    return;

  const AtomicString key(event.key());

  const Decimal current = ParseToNumberOrNaN(GetElement().Value());
  DCHECK(current.IsFinite());

  StepRange step_range(CreateStepRange(kRejectAny));

  // FIXME: We can't use stepUp() for the step value "any". So, we increase
  // or decrease the value by 1/100 of the value range. Is it reasonable?
  const Decimal step =
      EqualIgnoringASCIICase(
          GetElement().FastGetAttribute(html_names::kStepAttr), "any")
          ? (step_range.Maximum() - step_range.Minimum()) / 100
          : step_range.Step();
  const Decimal big_step =
      std::max((step_range.Maximum() - step_range.Minimum()) / 10, step);

  bool is_up = false;
  bool is_down = false;
  WritingDirectionMode writing_direction = {WritingMode::kHorizontalTb,
                                            TextDirection::kLtr};
  if (const auto* style = GetElement().GetComputedStyle()) {
    writing_direction = style->GetWritingDirection();
    // `appearance: slider-vertical` is equivalent to `writing-mode:
    // vertical-rl; direction: rtl`.
    if (RuntimeEnabledFeatures::
            NonStandardAppearanceValueSliderVerticalEnabled() &&
        writing_direction.IsHorizontal() &&
        style->EffectiveAppearance() == kSliderVerticalPart) {
      writing_direction = {WritingMode::kVerticalRl, TextDirection::kRtl};
    }
  }
  const PhysicalToLogical<const AtomicString*> key_mapper(
      writing_direction, &keywords::kArrowUp, &keywords::kArrowRight,
      &keywords::kArrowDown, &keywords::kArrowLeft);
  is_up = key == *key_mapper.InlineEnd() || key == *key_mapper.LineOver();
  is_down = key == *key_mapper.InlineStart() || key == *key_mapper.LineUnder();

  Decimal new_value;
  if (is_up) {
    new_value = current + step;
  } else if (is_down) {
    new_value = current - step;
  } else if (key == keywords::kPageUp) {
    new_value = current + big_step;
  } else if (key == keywords::kPageDown) {
    new_value = current - big_step;
  } else if (key == keywords::kHome) {
    new_value = step_range.Minimum();
  } else if (key == keywords::kEnd) {
    new_value = step_range.Maximum();
  } else {
    return;  // Did not match any key binding.
  }

  new_value = step_range.ClampValue(new_value);

  if (new_value != current) {
    EventQueueScope scope;
    TextFieldEventBehavior event_behavior =
        TextFieldEventBehavior::kDispatchInputAndChangeEvent;
    SetValueAsDecimal(new_value, event_behavior, IGNORE_EXCEPTION_FOR_TESTING);

    if (AXObjectCache* cache =
            GetElement().GetDocument().ExistingAXObjectCache())
      cache->HandleValueChanged(&GetElement());
  }

  event.SetDefaultHandled();
}

void RangeInputType::CreateShadowSubtree() {
  DCHECK(IsShadowHost(GetElement()));

  Document& document = GetElement().GetDocument();
  auto* track = MakeGarbageCollected<blink::SliderTrackElement>(document);
  track->SetShadowPseudoId(shadow_element_names::kPseudoSliderTrack);
  track->setAttribute(html_names::kIdAttr,
                      shadow_element_names::kIdSliderTrack);
  track->AppendChild(MakeGarbageCollected<SliderThumbElement>(document));
  auto* container = MakeGarbageCollected<SliderContainerElement>(document);
  container->AppendChild(track);
  GetElement().UserAgentShadowRoot()->AppendChild(container);
}

LayoutObject* RangeInputType::CreateLayoutObject(const ComputedStyle&) const {
  // TODO(crbug.com/1131352): input[type=range] should not use flexbox.
  return MakeGarbageCollected<LayoutFlexibleBox>(&GetElement());
}

void RangeInputType::AdjustStyle(ComputedStyleBuilder& builder) {
  builder.SetInlineBlockBaselineEdge(EInlineBlockBaselineEdge::kBorderBox);
  InputTypeView::AdjustStyle(builder);
}

Decimal RangeInputType::ParseToNumber(const String& src,
                                      const Decimal& default_value) const {
  return ParseToDecimalForNumberType(src, default_value);
}

String RangeInputType::Serialize(const Decimal& value) const {
  if (!value.IsFinite())
    return String();
  return SerializeForNumberType(value);
}

// FIXME: Could share this with KeyboardClickableInputTypeView and
// BaseCheckableInputType if we had a common base class.
void RangeInputType::AccessKeyAction(
    SimulatedClickCreationScope creation_scope) {
  InputTypeView::AccessKeyAction(creation_scope);
  GetElement().DispatchSimulatedClick(nullptr, creation_scope);
}

void RangeInputType::SanitizeValueInResponseToMinOrMaxAttributeChange() {
  if (GetElement().HasDirtyValue())
    GetElement().SetValue(GetElement().Value());
  else
    GetElement().SetNonDirtyValue(GetElement().Value());
  GetElement().UpdateView();
}

void RangeInputType::StepAttributeChanged() {
  if (GetElement().HasDirtyValue())
    GetElement().SetValue(GetElement().Value());
  else
    GetElement().SetNonDirtyValue(GetElement().Value());
  GetElement().UpdateView();
}

void RangeInputType::DidSetValue(const String&, bool value_changed) {
  if (value_changed)
    GetElement().UpdateView();
}

ControlPart RangeInputType::AutoAppearance() const {
  return kSliderHorizontalPart;
}

void RangeInputType::UpdateView() {
  if (HasCreatedShadowSubtree()) {
    GetSliderThumbElement()->SetPositionFromValue();
  }
}

String RangeInputType::SanitizeValue(const String& proposed_value) const {
  StepRange step_range(CreateStepRange(kRejectAny));
  const Decimal proposed_numeric_value =
      ParseToNumber(proposed_value, step_range.DefaultValue());
  return SerializeForNumberType(step_range.ClampValue(proposed_numeric_value));
}

void RangeInputType::WarnIfValueIsInvalid(const String& value) const {
  if (value.empty() || !GetElement().SanitizeValue(value).empty())
    return;
  AddWarningToConsole(
      "The specified value %s cannot be parsed, or is out of range.", value);
}

String RangeInputType::RangeOverflowText(const Decimal& maximum) const {
  return GetLocale().QueryString(IDS_FORM_VALIDATION_RANGE_OVERFLOW,
                                 LocalizeValue(Serialize(maximum)));
}

String RangeInputType::RangeUnderflowText(const Decimal& minimum) const {
  return GetLocale().QueryString(IDS_FORM_VALIDATION_RANGE_UNDERFLOW,
                                 LocalizeValue(Serialize(minimum)));
}

String RangeInputType::RangeInvalidText(const Decimal& minimum,
                                        const Decimal& maximum) const {
  return GetLocale().QueryString(IDS_FORM_VALIDATION_RANGE_REVERSED,
                                 LocalizeValue(Serialize(minimum)),
                                 LocalizeValue(Serialize(maximum)));
}

void RangeInputType::DisabledAttributeChanged() {
  if (!HasCreatedShadowSubtree()) {
    return;
  }
  if (GetElement().IsDisabledFormControl())
    GetSliderThumbElement()->StopDragging();
}

bool RangeInputType::ShouldRespectListAttribute() {
  return true;
}

inline SliderThumbElement* RangeInputType::GetSliderThumbElement() const {
  return To<SliderThumbElement>(
      GetElement().UserAgentShadowRoot()->getElementById(
          shadow_element_names::kIdSliderThumb));
}

inline Element* RangeInputType::SliderTrackElement() const {
  if (!HasCreatedShadowSubtree()) {
    return nullptr;
  }

  return GetElement().UserAgentShadowRoot()->getElementById(
      shadow_element_names::kIdSliderTrack);
}

void RangeInputType::ListAttributeTargetChanged() {
  tick_mark_values_dirty_ = true;
  if (auto* object = GetElement().GetLayoutObject())
    object->SetSubtreeShouldDoFullPaintInvalidation();
  Element* slider_track_element = SliderTrackElement();
  if (slider_track_element && slider_track_element->GetLayoutObject()) {
    slider_track_element->GetLayoutObject()->SetNeedsLayout(
        layout_invalidation_reason::kAttributeChanged);
  }
}

static bool DecimalCompare(const Decimal& a, const Decimal& b) {
  return a < b;
}

void RangeInputType::UpdateTickMarkValues() {
  if (!tick_mark_values_dirty_)
    return;
  tick_mark_values_.clear();
  tick_mark_values_dirty_ = false;
  HTMLDataListElement* data_list = GetElement().DataList();
  if (!data_list)
    return;
  HTMLDataListOptionsCollection* options = data_list->options();
  tick_mark_values_.reserve(options->length());
  for (unsigned i = 0; i < options->length(); ++i) {
    HTMLOptionElement* option_element = options->Item(i);
    String option_value = option_element->value();
    if (option_element->IsDisabledFormControl() || option_value.empty())
      continue;
    if (!GetElement().IsValidValue(option_value))
      continue;
    tick_mark_values_.push_back(ParseToNumber(option_value, Decimal::Nan()));
  }
  tick_mark_values_.shrink_to_fit();
  std::sort(tick_mark_values_.begin(), tick_mark_values_.end(), DecimalCompare);
}

Decimal RangeInputType::FindClosestTickMarkValue(const Decimal& value) {
  UpdateTickMarkValues();
  if (!tick_mark_values_.size())
    return Decimal::Nan();

  wtf_size_t left = 0;
  wtf_size_t right = tick_mark_values_.size();
  wtf_size_t middle;
  while (true) {
    DCHECK_LE(left, right);
    middle = left + (right - left) / 2;
    if (!middle)
      break;
    if (middle == tick_mark_values_.size() - 1 &&
        tick_mark_values_[middle] < value) {
      middle++;
      break;
    }
    if (tick_mark_values_[middle - 1] <= value &&
        tick_mark_values_[middle] >= value)
      break;

    if (tick_mark_values_[middle] < value)
      left = middle;
    else
      right = middle;
  }
  const Decimal closest_left = middle ? tick_mark_values_[middle - 1]
                                      : Decimal::Infinity(Decimal::kNegative);
  const Decimal closest_right = middle != tick_mark_values_.size()
                                    ? tick_mark_values_[middle]
                                    : Decimal::Infinity(Decimal::kPositive);
  if (closest_right - value < value - closest_left)
    return closest_right;
  return closest_left;
}

void RangeInputType::ValueAttributeChanged() {
  UpdateView();
}

bool RangeInputType::IsDraggedSlider() const {
  return GetSliderThumbElement()->IsActive();
}

}  // namespace blink

"""

```