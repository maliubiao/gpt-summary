Response:
Let's break down the thought process for analyzing the `svg_angle.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to web technologies (JS, HTML, CSS), example inputs/outputs, common errors, and debugging context.

2. **Initial Scan and High-Level Purpose:**  The filename `svg_angle.cc` immediately suggests it deals with angles in SVG. The copyright notices indicate it's part of the Chromium/Blink rendering engine. The `#include` directives confirm this and point to related SVG components (`smil_animation_effect_parameters.h`, `svg_enumeration_map.h`, `svg_parser_utilities.h`). This suggests the file is responsible for representing, parsing, and manipulating SVG angle values.

3. **Core Class Identification:** The presence of the `SVGAngle` class is obvious. This is the central entity.

4. **Functionality Breakdown (Line by Line/Section by Section):**

   * **Copyright and Licensing:** Acknowledge the licensing information. It's good practice.

   * **Includes:** Note the included headers and what they imply. For instance, `smil_animation_effect_parameters.h` suggests involvement in SVG animations.

   * **`GetEnumerationMap<SVGMarkerOrientType>()`:** Recognize this as a utility for managing string-to-enum mappings, specifically for `SVGMarkerOrientType` (related to marker orientation). List the possible values ("auto", "angle", "auto-start-reverse").

   * **`SVGMarkerOrientEnumeration`:**  This looks like a helper class *within* `SVGAngle` to manage the `orient` attribute. It holds a pointer to the `SVGAngle` object and calls `OrientTypeChanged()` when the orientation changes. This hints at a state management aspect.

   * **`ConvertAngleToUnit`:**  This is a crucial function for unit conversion between different SVG angle units (deg, rad, grad, turn). Carefully analyze the nested `switch` statements to understand the conversion logic. This is a prime candidate for input/output examples.

   * **`ConvertDegreesToUnit`:** A simplified version of the above, converting *to* a specific unit *from* degrees.

   * **`SVGAngle` Constructors:**  Note the different ways an `SVGAngle` object can be initialized (default, with unit and value, with unit, value, and orientation).

   * **`Trace`:** Recognize this as part of Blink's garbage collection mechanism.

   * **`Clone`:**  A standard method for creating copies of the object.

   * **`Value()`:**  Returns the angle in degrees, regardless of the stored unit. This requires conversion.

   * **`SetValue()`:** Sets the angle value, converting the input (assumed to be degrees) to the internal unit.

   * **`StringToAngleType`:**  Parses a string to determine the angle unit (deg, rad, grad, turn). Handles the case of no unit (unspecified). This is important for parsing SVG attributes.

   * **`ValueAsString()`:**  Converts the internal representation back to a string with the appropriate unit.

   * **`ParseValue`:**  The core parsing logic. It uses `ParseNumber` (from `svg_parser_utilities.h`) to extract the numeric value and then uses `StringToAngleType` to determine the unit. This is where errors during parsing can occur.

   * **`SetValueAsString()`:**  The main entry point for setting the angle from a string (likely from an SVG attribute). It handles the "auto" and "auto-start-reverse" keywords for marker orientation and delegates the actual parsing to `ParseValue`. This is a key point for relating to HTML and CSS.

   * **`NewValueSpecifiedUnits()`:**  An internal method to set the unit and value, ensuring the `orient_type_` is set to "angle".

   * **`ConvertToSpecifiedUnits()`:** Converts the stored value to a different unit.

   * **`Add()`:**  Handles adding another `SVGAngle` to the current one, likely for animation purposes. It only works if both angles are numeric.

   * **`Assign()`:** Copies the value and orientation from another `SVGAngle`.

   * **`CalculateAnimatedValue()`:**  Implements the logic for animating angle values using SMIL. It handles both numeric and non-numeric cases (discrete animation).

   * **`CalculateDistance()`:**  Calculates the difference between two angles.

   * **`OrientTypeChanged()`:**  Resets the unit and value when the orientation changes (e.g., to "auto").

   * **`OrientTypeValue()`:** Returns the current orientation type.

   * **`IsNumeric()`:**  Checks if the angle has a numeric value (i.e., not "auto" or "auto-start-reverse").

5. **Relating to Web Technologies:**

   * **HTML:** SVG is embedded in HTML. The `SVGAngle` is used to represent angle attributes within SVG elements (e.g., `rotate` on a `<g>` element, `marker-orient` on `<marker>`).

   * **CSS:** CSS can style SVG. While direct CSS properties for angles might be limited, CSS transforms often involve angles, and the parsing logic here is crucial when CSS animations or transitions affect SVG attributes involving angles.

   * **JavaScript:** JavaScript can manipulate the DOM, including SVG attributes. When JS sets an angle attribute, the `SetValueAsString()` method is likely called internally to parse and set the `SVGAngle` value.

6. **Input/Output Examples:** Focus on the core conversion and parsing functions. Choose different units and edge cases (no unit).

7. **Common Errors:** Think about what could go wrong during parsing. Invalid unit strings, non-numeric values where a number is expected, etc.

8. **Debugging Scenario:**  Consider how a developer might end up looking at this code. Likely while investigating a problem with SVG angle rendering, animation, or parsing errors. Trace the user action leading to the issue.

9. **Structure and Refine:** Organize the information logically. Start with a general overview, then detail the functionality, connections to web technologies, examples, errors, and debugging. Use clear and concise language. Ensure the code snippets and examples are accurate. Review for clarity and completeness.
好的，这是对 `blink/renderer/core/svg/svg_angle.cc` 文件功能的详细分析：

**文件功能总览:**

`svg_angle.cc` 文件定义了 Blink 渲染引擎中用于处理 SVG 角度值的 `SVGAngle` 类。它负责以下关键功能：

1. **表示 SVG 角度值:**  `SVGAngle` 类存储了角度的数值以及其单位（例如 `deg`, `rad`, `grad`, `turn`）。
2. **角度单位转换:**  提供了在不同角度单位之间进行转换的方法（例如，度到弧度，弧度到梯度等）。
3. **解析 SVG 角度字符串:**  能够将 SVG 属性中表示角度的字符串解析成 `SVGAngle` 对象。例如，将 "45deg" 解析为表示 45 度的 `SVGAngle` 对象。
4. **格式化 SVG 角度字符串:**  能够将 `SVGAngle` 对象转换回字符串表示形式。
5. **支持 SVG 动画:**  参与 SVG 动画的计算，例如在两个角度值之间进行插值。
6. **处理 `marker-orient` 属性:** 特别地，它处理 SVG `<marker>` 元素的 `orient` 属性，该属性可以是角度值，也可以是关键字 "auto" 或 "auto-start-reverse"。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`SVGAngle` 类在 Blink 渲染引擎中扮演着连接 HTML 中 SVG 元素、CSS 样式以及 JavaScript 操作的关键角色。

* **HTML:**
    * **SVG 属性:** 当 HTML 中嵌入的 SVG 元素的属性值表示角度时，例如 `<rect transform="rotate(45deg)">` 中的 `rotate` 属性，或者 `<marker orient="30rad">` 中的 `orient` 属性，Blink 引擎会使用 `SVGAngle` 类来解析和存储这些值。
    * **示例:**
        ```html
        <svg width="200" height="200">
          <rect x="50" y="50" width="100" height="100" transform="rotate(30deg 100 100)" fill="blue" />
        </svg>
        ```
        在这个例子中，`SVGAngle` 类会处理 `rotate(30deg 100 100)` 中的 "30deg"。

* **CSS:**
    * **CSS 变换:**  CSS 的 `transform` 属性可以应用于 SVG 元素，其中可能包含角度值，例如 `transform: rotate(90deg);`。Blink 引擎在解析和应用这些样式时，会用到 `SVGAngle` 类。
    * **CSS 动画和过渡:**  CSS 动画和过渡如果涉及到变换，也可能需要处理角度值，`SVGAngle` 会参与到这些动画和过渡的计算中。
    * **示例:**
        ```css
        rect {
          animation: rotateRect 2s infinite linear;
        }

        @keyframes rotateRect {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        ```
        在这里，`SVGAngle` 用于表示动画中 "0deg" 和 "360deg" 这两个角度值。

* **JavaScript:**
    * **DOM 操作:** JavaScript 可以通过 DOM API 获取和设置 SVG 元素的属性。当操作涉及角度属性时，会间接地使用到 `SVGAngle` 类。
    * **`get/setAttribute()`:** 例如，使用 `element.getAttribute('transform')` 获取变换属性，或使用 `element.setAttribute('transform', 'rotate(60rad)')` 设置变换属性时，Blink 引擎会调用 `SVGAngle` 的相关方法进行解析和设置。
    * **`style` 属性:**  通过 JavaScript 修改元素的 `style` 属性，例如 `element.style.transform = 'rotate(1.5turn)';`，同样会用到 `SVGAngle` 来处理角度值。
    * **SVG DOM 接口:** SVG DOM 提供了特定的接口来操作角度值，例如 `SVGTransform` 对象的 `setRotate()` 方法，它接受角度值作为参数，这些参数在底层由 `SVGAngle` 表示。
    * **示例:**
        ```javascript
        const rect = document.querySelector('rect');
        let angle = 0;
        setInterval(() => {
          angle += 10;
          rect.setAttribute('transform', `rotate(${angle}deg 100 100)`);
        }, 100);
        ```
        在这个 JavaScript 代码中，每次更新 `transform` 属性时，引擎都会使用 `SVGAngle` 来处理 `angle + 'deg'` 这个字符串。

**逻辑推理的假设输入与输出:**

假设 `SetValueAsString()` 函数被调用，用于解析不同的角度字符串：

| 假设输入 (字符串) | 预期输出 (内部 `SVGAngle` 状态)                               |
|-----------------|-----------------------------------------------------------------|
| "45deg"         | `unit_type_` = `kSvgAngletypeDeg`, `value_in_specified_units_` = 45 |
| "1.5rad"        | `unit_type_` = `kSvgAngletypeRad`, `value_in_specified_units_` = 1.5 |
| "200grad"       | `unit_type_` = `kSvgAngletypeGrad`, `value_in_specified_units_` = 200 |
| "0.25turn"      | `unit_type_` = `kSvgAngletypeTurn`, `value_in_specified_units_` = 0.25 |
| "90"            | `unit_type_` = `kSvgAngletypeUnspecified`, `value_in_specified_units_` = 90 (默认为度) |
| "auto"          | `orient_type_` = `kSVGMarkerOrientAuto`                          |
| "auto-start-reverse" | `orient_type_` = `kSVGMarkerOrientAutoStartReverse`            |
| "invalid unit" | 返回错误状态 (但 `SVGAngle` 对象可能保持不变或置为默认值)           |

假设 `Value()` 函数被调用，获取角度的度数值：

| 假设内部 `SVGAngle` 状态 (`unit_type_`, `value_in_specified_units_`) | 预期输出 (浮点数) |
|----------------------------------------------------------------------|-----------------|
| `kSvgAngletypeDeg`, 45                                               | 45.0            |
| `kSvgAngletypeRad`, π/2                                            | 90.0            |
| `kSvgAngletypeGrad`, 100                                              | 90.0            |
| `kSvgAngletypeTurn`, 0.5                                            | 180.0           |
| `kSvgAngletypeUnspecified`, 60                                       | 60.0            |

假设 `ConvertToSpecifiedUnits()` 函数被调用进行单位转换：

| 假设内部 `SVGAngle` 状态 (`unit_type_`, `value_in_specified_units_`) | 调用 `ConvertToSpecifiedUnits()` 参数 | 预期转换后的 `SVGAngle` 状态                                   |
|----------------------------------------------------------------------|-----------------------------------|-----------------------------------------------------------------|
| `kSvgAngletypeDeg`, 90                                               | `kSvgAngletypeRad`                | `unit_type_` = `kSvgAngletypeRad`, `value_in_specified_units_` ≈ 1.5708 |
| `kSvgAngletypeRad`, π                                               | `kSvgAngletypeGrad`               | `unit_type_` = `kSvgAngletypeGrad`, `value_in_specified_units_` = 200    |
| `kSvgAngletypeGrad`, 400                                              | `kSvgAngletypeTurn`               | `unit_type_` = `kSvgAngletypeTurn`, `value_in_specified_units_` = 1.0    |

**用户或编程常见的使用错误:**

1. **单位拼写错误或使用无效单位:** 用户在编写 SVG 或 CSS 时，可能会错误地拼写单位，例如 "degs" 而不是 "deg"，或者使用引擎不支持的单位。这会导致解析失败。
   * **示例:** `<rect transform="rotate(45degs)">` 或 `transform: rotate(100foo);`

2. **缺少单位:**  虽然对于某些情况，缺少单位会被视为度，但在某些上下文中可能会导致意外的结果或解析错误。
   * **示例:** `<marker orient="90">` （如果期望的是非度单位）。

3. **在需要数值的地方使用了 "auto" 或 "auto-start-reverse":**  这两个关键字只在 `marker-orient` 属性中有效，如果在其他需要角度数值的属性中使用，会导致解析错误或被忽略。
   * **示例:** `<rect transform="rotate(auto)">`

4. **在动画中混合使用不同单位且未进行转换:**  如果 SVG 动画的起始值和结束值使用了不同的角度单位，且没有进行显式转换，可能会导致非预期的动画效果，因为引擎需要先将它们转换到相同的单位才能进行插值。

5. **JavaScript 操作 DOM 时设置了格式错误的角度字符串:**  如果 JavaScript 代码尝试设置一个格式错误的角度字符串到 SVG 属性，`SetValueAsString()` 解析时会出错。
   * **示例:** `element.setAttribute('transform', 'rotate(45 degree)');` (缺少 'g')

**用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者在调试一个 SVG 旋转动画不正常的问题，动画的目标元素使用了 `transform: rotate()` 属性。以下是可能到达 `svg_angle.cc` 的调试步骤：

1. **用户在浏览器中加载包含 SVG 动画的 HTML 页面。**
2. **动画开始执行，但用户观察到旋转效果不正确。** 可能旋转速度过快、过慢，或者方向错误。
3. **开发者打开浏览器的开发者工具，检查元素的 Computed Styles (计算样式)。** 他们可能会看到 `transform` 属性的值与预期不符。
4. **开发者查看 Elements (元素) 面板，检查元素的属性。** 如果动画是通过 JavaScript 操作 `style` 属性或 `setAttribute()` 实现的，他们可能会检查这些代码。
5. **开发者怀疑是角度值的问题。** 他们可能会在开发者工具的 Console (控制台) 中使用 JavaScript 获取元素的 `transform` 属性值，并尝试手动解析。
6. **如果问题涉及到角度单位转换或解析，开发者可能会尝试在搜索引擎中搜索 "blink svg angle parsing error" 等关键词，或者查看 Blink 渲染引擎的源代码。**
7. **在 Blink 源代码中，他们可能会找到 `svg_angle.cc` 文件，并开始研究 `SetValueAsString()`、`Value()`、`ConvertToSpecifiedUnits()` 等方法。**
8. **他们可能会在 `svg_angle.cc` 文件中设置断点，例如在 `SetValueAsString()` 的解析逻辑处，或者在单位转换函数中。**
9. **重新加载页面，触发动画。当代码执行到断点时，他们可以检查传入的角度字符串、当前的单位类型和数值，以及转换后的值，从而定位问题所在。**

例如，开发者可能发现：

* **解析错误:** `SetValueAsString()` 返回了错误，因为传入了格式错误的字符串。
* **单位不匹配:** 动画的起始值和结束值单位不一致，导致插值计算错误。
* **JavaScript 代码错误:**  JavaScript 代码计算的角度值有误，导致传递给 `setAttribute()` 的字符串不正确。

通过以上步骤，开发者可以利用 `svg_angle.cc` 中的代码和调试信息，深入了解 Blink 引擎是如何处理 SVG 角度值的，从而解决动画问题。

Prompt: 
```
这是目录为blink/renderer/core/svg/svg_angle.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2004, 2005, 2007, 2008 Nikolas Zimmermann <zimmermann@kde.org>
 * Copyright (C) 2004, 2005, 2006 Rob Buis <buis@kde.org>
 * Copyright (C) Research In Motion Limited 2010. All rights reserved.
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
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/svg/svg_angle.h"

#include "third_party/blink/renderer/core/svg/animation/smil_animation_effect_parameters.h"
#include "third_party/blink/renderer/core/svg/svg_enumeration_map.h"
#include "third_party/blink/renderer/core/svg/svg_parser_utilities.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/character_visitor.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

template <>
const SVGEnumerationMap& GetEnumerationMap<SVGMarkerOrientType>() {
  static constexpr auto enum_items = std::to_array<const char* const>({
      "auto",
      "angle",
      "auto-start-reverse",
  });
  static const SVGEnumerationMap entries(enum_items, kSVGMarkerOrientAngle);
  return entries;
}

namespace {

class SVGMarkerOrientEnumeration final : public SVGEnumeration {
 public:
  explicit SVGMarkerOrientEnumeration(SVGAngle* angle)
      : SVGEnumeration(kSVGMarkerOrientAngle), angle_(angle) {}

  void Trace(Visitor* visitor) const override {
    visitor->Trace(angle_);
    SVGEnumeration::Trace(visitor);
  }

 private:
  void NotifyChange() override {
    DCHECK(angle_);
    angle_->OrientTypeChanged();
  }

  Member<SVGAngle> angle_;
};

float ConvertAngleToUnit(SVGAngle::SVGAngleType from_unit,
                         float value,
                         SVGAngle::SVGAngleType to_unit) {
  switch (from_unit) {
    case SVGAngle::kSvgAngletypeTurn:
      switch (to_unit) {
        case SVGAngle::kSvgAngletypeGrad:
          return Turn2grad(value);
        case SVGAngle::kSvgAngletypeUnspecified:
        case SVGAngle::kSvgAngletypeDeg:
          return Turn2deg(value);
        case SVGAngle::kSvgAngletypeRad:
          return Deg2rad(Turn2deg(value));
        case SVGAngle::kSvgAngletypeTurn:
        case SVGAngle::kSvgAngletypeUnknown:
          NOTREACHED();
      }
      break;
    case SVGAngle::kSvgAngletypeRad:
      switch (to_unit) {
        case SVGAngle::kSvgAngletypeGrad:
          return Rad2grad(value);
        case SVGAngle::kSvgAngletypeUnspecified:
        case SVGAngle::kSvgAngletypeDeg:
          return Rad2deg(value);
        case SVGAngle::kSvgAngletypeTurn:
          return Deg2turn(Rad2deg(value));
        case SVGAngle::kSvgAngletypeRad:
        case SVGAngle::kSvgAngletypeUnknown:
          NOTREACHED();
      }
      break;
    case SVGAngle::kSvgAngletypeGrad:
      switch (to_unit) {
        case SVGAngle::kSvgAngletypeRad:
          return Grad2rad(value);
        case SVGAngle::kSvgAngletypeUnspecified:
        case SVGAngle::kSvgAngletypeDeg:
          return Grad2deg(value);
        case SVGAngle::kSvgAngletypeTurn:
          return Grad2turn(value);
        case SVGAngle::kSvgAngletypeGrad:
        case SVGAngle::kSvgAngletypeUnknown:
          NOTREACHED();
      }
      break;
    // Spec: For angles, a unitless value is treated the same as if degrees
    // were specified.
    case SVGAngle::kSvgAngletypeUnspecified:
    case SVGAngle::kSvgAngletypeDeg:
      switch (to_unit) {
        case SVGAngle::kSvgAngletypeRad:
          return Deg2rad(value);
        case SVGAngle::kSvgAngletypeGrad:
          return Deg2grad(value);
        case SVGAngle::kSvgAngletypeTurn:
          return Deg2turn(value);
        case SVGAngle::kSvgAngletypeUnspecified:
        case SVGAngle::kSvgAngletypeDeg:
          return value;
        case SVGAngle::kSvgAngletypeUnknown:
          NOTREACHED();
      }
      break;
    case SVGAngle::kSvgAngletypeUnknown:
      NOTREACHED();
  }
}

float ConvertDegreesToUnit(float degrees, SVGAngle::SVGAngleType unit) {
  switch (unit) {
    case SVGAngle::kSvgAngletypeGrad:
      return Deg2grad(degrees);
    case SVGAngle::kSvgAngletypeRad:
      return Deg2rad(degrees);
    case SVGAngle::kSvgAngletypeTurn:
      return Deg2turn(degrees);
    case SVGAngle::kSvgAngletypeUnspecified:
    case SVGAngle::kSvgAngletypeUnknown:
    case SVGAngle::kSvgAngletypeDeg:
      return degrees;
  }
}

}  // namespace

SVGAngle::SVGAngle()
    : unit_type_(kSvgAngletypeUnspecified),
      value_in_specified_units_(0),
      orient_type_(MakeGarbageCollected<SVGMarkerOrientEnumeration>(this)) {}

SVGAngle::SVGAngle(SVGAngleType unit_type,
                   float value_in_specified_units,
                   SVGMarkerOrientType orient_type)
    : unit_type_(unit_type),
      value_in_specified_units_(value_in_specified_units),
      orient_type_(MakeGarbageCollected<SVGMarkerOrientEnumeration>(this)) {
  orient_type_->SetEnumValue(orient_type);
}

SVGAngle::~SVGAngle() = default;

void SVGAngle::Trace(Visitor* visitor) const {
  visitor->Trace(orient_type_);
  SVGPropertyHelper<SVGAngle>::Trace(visitor);
}

SVGAngle* SVGAngle::Clone() const {
  return MakeGarbageCollected<SVGAngle>(unit_type_, value_in_specified_units_,
                                        OrientTypeValue());
}

float SVGAngle::Value() const {
  switch (unit_type_) {
    case kSvgAngletypeGrad:
      return Grad2deg(value_in_specified_units_);
    case kSvgAngletypeRad:
      return Rad2deg(value_in_specified_units_);
    case kSvgAngletypeTurn:
      return Turn2deg(value_in_specified_units_);
    case kSvgAngletypeUnspecified:
    case kSvgAngletypeUnknown:
    case kSvgAngletypeDeg:
      return value_in_specified_units_;
  }

  NOTREACHED();
}

void SVGAngle::SetValue(float value) {
  NewValueSpecifiedUnits(unit_type_, ConvertDegreesToUnit(value, unit_type_));
}

template <typename CharType>
static SVGAngle::SVGAngleType StringToAngleType(const CharType*& ptr,
                                                const CharType* end) {
  // If there's no unit given, the angle type is unspecified.
  if (ptr == end)
    return SVGAngle::kSvgAngletypeUnspecified;

  SVGAngle::SVGAngleType type = SVGAngle::kSvgAngletypeUnknown;
  if (IsHTMLSpace<CharType>(ptr[0])) {
    type = SVGAngle::kSvgAngletypeUnspecified;
    ptr++;
  } else if (end - ptr >= 3) {
    if (ptr[0] == 'd' && ptr[1] == 'e' && ptr[2] == 'g') {
      type = SVGAngle::kSvgAngletypeDeg;
      ptr += 3;
    } else if (ptr[0] == 'r' && ptr[1] == 'a' && ptr[2] == 'd') {
      type = SVGAngle::kSvgAngletypeRad;
      ptr += 3;
    } else if (end - ptr >= 4) {
      if (ptr[0] == 'g' && ptr[1] == 'r' && ptr[2] == 'a' && ptr[3] == 'd') {
        type = SVGAngle::kSvgAngletypeGrad;
        ptr += 4;
      } else if (ptr[0] == 't' && ptr[1] == 'u' && ptr[2] == 'r' &&
                 ptr[3] == 'n') {
        type = SVGAngle::kSvgAngletypeTurn;
        ptr += 4;
      }
    }
  }

  if (!SkipOptionalSVGSpaces(ptr, end))
    return type;

  return SVGAngle::kSvgAngletypeUnknown;
}

String SVGAngle::ValueAsString() const {
  base::span<const char> unit_string;
  switch (unit_type_) {
    case kSvgAngletypeDeg:
      unit_string = base::span_from_cstring("deg");
      break;
    case kSvgAngletypeRad:
      unit_string = base::span_from_cstring("rad");
      break;
    case kSvgAngletypeGrad:
      unit_string = base::span_from_cstring("grad");
      break;
    case kSvgAngletypeTurn:
      unit_string = base::span_from_cstring("turn");
      break;
    case kSvgAngletypeUnspecified:
    case kSvgAngletypeUnknown:
      break;
  }
  StringBuilder builder;
  builder.AppendNumber(value_in_specified_units_);
  builder.Append(base::as_bytes(unit_string));
  return builder.ToString();
}

template <typename CharType>
static SVGParsingError ParseValue(const CharType* start,
                                  const CharType* end,
                                  float& value_in_specified_units,
                                  SVGAngle::SVGAngleType& unit_type) {
  const CharType* ptr = start;
  if (!ParseNumber(ptr, end, value_in_specified_units, kAllowLeadingWhitespace))
    return SVGParsingError(SVGParseStatus::kExpectedAngle, ptr - start);

  unit_type = StringToAngleType(ptr, end);
  if (unit_type == SVGAngle::kSvgAngletypeUnknown)
    return SVGParsingError(SVGParseStatus::kExpectedAngle, ptr - start);

  return SVGParseStatus::kNoError;
}

SVGParsingError SVGAngle::SetValueAsString(const String& value) {
  if (value.empty()) {
    NewValueSpecifiedUnits(kSvgAngletypeUnspecified, 0);
    return SVGParseStatus::kNoError;
  }

  if (value == "auto") {
    NewValueSpecifiedUnits(kSvgAngletypeUnspecified, 0);
    orient_type_->SetEnumValue(kSVGMarkerOrientAuto);
    return SVGParseStatus::kNoError;
  }
  if (value == "auto-start-reverse") {
    NewValueSpecifiedUnits(kSvgAngletypeUnspecified, 0);
    orient_type_->SetEnumValue(kSVGMarkerOrientAutoStartReverse);
    return SVGParseStatus::kNoError;
  }

  float value_in_specified_units = 0;
  SVGAngleType unit_type = kSvgAngletypeUnknown;

  SVGParsingError error = WTF::VisitCharacters(value, [&](auto chars) {
    return ParseValue(chars.data(), chars.data() + chars.size(),
                      value_in_specified_units, unit_type);
  });
  if (error != SVGParseStatus::kNoError)
    return error;

  NewValueSpecifiedUnits(unit_type, value_in_specified_units);
  return SVGParseStatus::kNoError;
}

void SVGAngle::NewValueSpecifiedUnits(SVGAngleType unit_type,
                                      float value_in_specified_units) {
  orient_type_->SetEnumValue(kSVGMarkerOrientAngle);
  unit_type_ = unit_type;
  value_in_specified_units_ = value_in_specified_units;
}

void SVGAngle::ConvertToSpecifiedUnits(SVGAngleType new_unit) {
  if (new_unit == unit_type_) {
    return;
  }
  const float new_value =
      ConvertAngleToUnit(unit_type_, value_in_specified_units_, new_unit);
  NewValueSpecifiedUnits(new_unit, new_value);
}

void SVGAngle::Add(const SVGPropertyBase* other, const SVGElement*) {
  auto* other_angle = To<SVGAngle>(other);

  // Only respect by animations, if from and by are both specified in angles
  // (and not, for example, 'auto').
  if (!IsNumeric() || !other_angle->IsNumeric())
    return;

  SetValue(Value() + other_angle->Value());
}

void SVGAngle::Assign(const SVGAngle& other) {
  if (other.IsNumeric()) {
    NewValueSpecifiedUnits(other.UnitType(), other.ValueInSpecifiedUnits());
    return;
  }
  value_in_specified_units_ = 0;
  orient_type_->SetEnumValue(other.OrientTypeValue());
}

void SVGAngle::CalculateAnimatedValue(
    const SMILAnimationEffectParameters& parameters,
    float percentage,
    unsigned repeat_count,
    const SVGPropertyBase* from,
    const SVGPropertyBase* to,
    const SVGPropertyBase* to_at_end_of_duration,
    const SVGElement*) {
  auto* from_angle = To<SVGAngle>(from);
  auto* to_angle = To<SVGAngle>(to);

  // We can only interpolate between two SVGAngles with orient-type 'angle',
  // all other cases will use discrete animation.
  if (!from_angle->IsNumeric() || !to_angle->IsNumeric()) {
    Assign(percentage < 0.5f ? *from_angle : *to_angle);
    return;
  }

  float result = ComputeAnimatedNumber(
      parameters, percentage, repeat_count, from_angle->Value(),
      to_angle->Value(), To<SVGAngle>(to_at_end_of_duration)->Value());
  if (parameters.is_additive)
    result += Value();

  SetValue(result);
}

float SVGAngle::CalculateDistance(const SVGPropertyBase* other,
                                  const SVGElement*) const {
  return fabsf(Value() - To<SVGAngle>(other)->Value());
}

void SVGAngle::OrientTypeChanged() {
  if (IsNumeric())
    return;
  unit_type_ = kSvgAngletypeUnspecified;
  value_in_specified_units_ = 0;
}

SVGMarkerOrientType SVGAngle::OrientTypeValue() const {
  return orient_type_->EnumValue<SVGMarkerOrientType>();
}

bool SVGAngle::IsNumeric() const {
  return OrientTypeValue() == kSVGMarkerOrientAngle;
}

}  // namespace blink

"""

```