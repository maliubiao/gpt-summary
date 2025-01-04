Response:
Let's break down the thought process for analyzing the `transform_builder.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to web technologies, examples, logical reasoning, common errors, and debugging hints.

2. **Identify the Core Functionality:** The file name `transform_builder.cc` strongly suggests it's involved in building or creating something related to "transformations."  Looking at the `#include` directives confirms this:
    * Includes like `matrix_3d_transform_operation.h`, `scale_transform_operation.h`, etc., clearly point to handling CSS transformations.
    * The namespace `blink` and the directory `blink/renderer/core/css/resolver/` place it within the CSS resolution process of the Blink rendering engine.

3. **Analyze Key Functions:**
    * **`ConvertToFloatLength`:** A simple helper to convert CSS primitive values to lengths. This immediately tells us it deals with units and measurements.
    * **`GetTransformOperationType`:** This function maps CSS function names (like `scale`, `rotate`) to internal `TransformOperation::OperationType` enums. This is crucial for understanding how CSS transform functions are interpreted.
    * **`HasRelativeLengths`:**  This iterates through the CSS values and checks for relative length units (like `em`, `%`, `vw`). This hints at the handling of dynamic sizing.
    * **`CreateTransformOperation`:** This is the *core* function. It takes a `CSSFunctionValue` (e.g., `scale(2)`) and the conversion data, and *creates* the appropriate `TransformOperation` object (e.g., `ScaleTransformOperation`). The large `switch` statement within this function is the key to understanding how each CSS transform function is processed.
    * **`CreateTransformOperations`:** This function handles both single transform functions and lists of transform functions (the `transform` CSS property can take multiple functions).

4. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **CSS:** The file's purpose is directly tied to the `transform` CSS property. The examples in the `CreateTransformOperation` function illustrate how CSS functions like `scale()`, `rotate()`, `translate()` are parsed and converted into internal representations.
    * **HTML:**  The `transform` property is applied to HTML elements. Therefore, this code is part of the process of rendering HTML elements with applied transformations.
    * **JavaScript:** JavaScript can manipulate the `transform` style of HTML elements. When JavaScript changes the style, the CSS resolver, including this `transform_builder.cc` file, will be involved in interpreting the new transformation.

5. **Logical Reasoning (Input/Output):** Focus on the `CreateTransformOperation` function.
    * **Input:** A `CSSFunctionValue` representing a CSS transform function and `CSSToLengthConversionData`.
    * **Output:** A `TransformOperation` object.
    * The `switch` statement demonstrates the logical branching based on the input CSS function. For example, if the input is `scale(2)`, the code creates a `ScaleTransformOperation` with the scale factor of 2.

6. **Common User/Programming Errors:** Consider how developers might misuse CSS transforms.
    * **Incorrect Units:** Using incompatible units or missing units.
    * **Syntax Errors:**  Typing errors in the function name or the number of arguments.
    * **Order of Operations:** The order of transforms matters. Applying rotation after translation is different from applying translation after rotation. Although this file *parses* the transforms, the order is determined by the CSS. However, the code *could* potentially catch some syntax errors.
    * **Performance Issues:**  While not directly caused by this file, complex transforms can impact rendering performance.

7. **Debugging Clues (User Actions to Reach This Code):** Think about the user's interaction with a webpage that leads to CSS transformations being applied.
    * **Page Load:**  When a page with CSS `transform` rules loads, the browser needs to parse and apply these rules.
    * **User Interaction:** Hovering over an element, clicking a button, or scrolling might trigger CSS transitions or animations that involve transformations.
    * **JavaScript Manipulation:**  JavaScript code that modifies the `transform` style property of an element will lead to this code being executed.

8. **Structure and Refine:** Organize the information into clear sections. Use headings and bullet points for readability. Make sure the examples are concrete and easy to understand. Review the code comments for additional insights.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file directly *applies* the transformations.
* **Correction:**  The file name `builder` suggests it *creates* the internal representation of the transformations, which are then likely applied by other parts of the rendering engine. The code confirms this by creating `TransformOperation` objects.
* **Initial thought:** Focus heavily on the mathematical details of the transformations.
* **Correction:** The request is more about the *functionality* and its connection to web technologies. While the underlying math is important, the explanation should focus on *what* the code does in the context of CSS processing.
* **Consider the audience:** The explanation should be understandable to someone familiar with web development concepts but perhaps not deeply familiar with the Blink rendering engine's internals.

By following these steps and iteratively refining the understanding, we can arrive at a comprehensive and accurate description of the `transform_builder.cc` file.
这个 `transform_builder.cc` 文件的主要功能是**解析 CSS `transform` 属性的值，并将其转换为 Blink 渲染引擎内部使用的 `TransformOperation` 对象**。这些 `TransformOperation` 对象描述了具体的 2D 或 3D 变换操作，例如平移、旋转、缩放、倾斜和透视。

以下是其更详细的功能分解：

**核心功能：**

1. **解析 CSS 函数值：**  它接收 CSS `transform` 属性的值，该值通常是一个或多个 CSS 函数，如 `translate()`, `rotate()`, `scale()`, `matrix()` 等。它会解析这些函数的名字和参数。

2. **创建 `TransformOperation` 对象：**  根据解析出的 CSS 函数，它会创建相应的 `TransformOperation` 子类的实例。例如：
    * `translate()` 函数会创建 `TranslateTransformOperation` 对象。
    * `rotate()` 函数会创建 `RotateTransformOperation` 对象。
    * `scale()` 函数会创建 `ScaleTransformOperation` 对象。
    * `matrix()` 函数会创建 `MatrixTransformOperation` 对象。
    * `perspective()` 函数会创建 `PerspectiveTransformOperation` 对象。

3. **处理不同的参数类型和单位：**  它能够处理 CSS 函数中不同类型的参数，例如数值、长度（`px`, `em`, `%` 等）、角度（`deg`, `rad` 等）。它会使用 `CSSToLengthConversionData` 来进行长度单位的转换和计算。

4. **处理 2D 和 3D 变换：**  它支持所有标准的 CSS 2D 和 3D 变换函数，包括 `translateX`, `translateY`, `translateZ`, `rotateX`, `rotateY`, `rotateZ`, `scaleX`, `scaleY`, `scaleZ`, `scale3d`, `translate3d`, `rotate3d`, `matrix3d` 等。

5. **处理单个和多个变换：**  `transform` 属性可以包含单个变换函数或多个变换函数的列表。这个文件能够处理这两种情况，并生成一个包含所有 `TransformOperation` 对象的列表。

**与 JavaScript, HTML, CSS 的关系：**

这个文件位于 Blink 引擎的 CSS 解析和布局流程中，直接关联着 CSS 的 `transform` 属性，并通过它影响 HTML 元素的渲染。

* **CSS:** 这是最直接的关联。`transform_builder.cc` 负责解析 CSS `transform` 属性中定义的变换。例如，当 CSS 规则中包含 `transform: translateX(10px) rotate(45deg);` 时，这个文件会解析出 `translateX` 和 `rotate` 两个函数，并创建相应的 `TranslateTransformOperation` 和 `RotateTransformOperation` 对象。

* **HTML:**  `transform` 属性应用于 HTML 元素。这个文件解析出的 `TransformOperation` 对象最终会被用于改变 HTML 元素在屏幕上的位置、大小、旋转等。例如，如果一个 `<div>` 元素的样式中设置了 `transform: scale(1.5);`，那么这个文件会创建一个缩放变换对象，导致该 `<div>` 元素在渲染时放大 50%。

* **JavaScript:** JavaScript 可以通过修改元素的 `style.transform` 属性来动态改变元素的变换。当 JavaScript 设置或修改 `transform` 属性时，Blink 引擎会重新解析 CSS 样式，并再次调用 `transform_builder.cc` 来创建新的 `TransformOperation` 对象。例如，以下 JavaScript 代码会使一个元素水平移动：
  ```javascript
  document.getElementById('myElement').style.transform = 'translateX(50px)';
  ```
  这时，`transform_builder.cc` 会解析 `'translateX(50px)'` 并创建一个相应的平移变换对象。

**逻辑推理 (假设输入与输出)：**

假设输入是一个 CSS 函数值字符串 `"rotate(30deg)"`。

* **输入:** `CSSFunctionValue` 对象，表示 `rotate(30deg)`，其中函数类型是 `CSSValueID::kRotate`，参数列表包含一个 `CSSPrimitiveValue` 对象，表示 `30deg`。
* **处理过程:** `GetTransformOperationType` 函数会根据 `CSSValueID::kRotate` 返回 `TransformOperation::kRotate`。`CreateTransformOperation` 函数的 `switch` 语句会匹配到 `kRotate` 分支，并读取参数 `30deg`。它会创建一个 `RotateTransformOperation` 对象，其中包含旋转角度为 30 度。
* **输出:** 一个指向 `RotateTransformOperation` 对象的指针，该对象表示绕 Z 轴旋转 30 度的变换。

假设输入是一个 CSS 函数值字符串 `"translate(10px, 20px)"`。

* **输入:** `CSSFunctionValue` 对象，表示 `translate(10px, 20px)`，函数类型是 `CSSValueID::kTranslate`，参数列表包含两个 `CSSPrimitiveValue` 对象，分别表示 `10px` 和 `20px`。
* **处理过程:** `GetTransformOperationType` 函数会根据 `CSSValueID::kTranslate` 返回 `TransformOperation::kTranslate`。`CreateTransformOperation` 函数的 `switch` 语句会匹配到 `kTranslate` 分支，并读取参数 `10px` 和 `20px`。它会创建一个 `TranslateTransformOperation` 对象，其中包含水平平移 10 像素和垂直平移 20 像素。
* **输出:** 一个指向 `TranslateTransformOperation` 对象的指针。

**用户或编程常见的使用错误：**

1. **拼写错误或使用了不存在的 CSS 变换函数:** 例如，用户可能会写成 `transalte()` 而不是 `translate()`。这将导致 CSS 解析失败，`transform_builder.cc` 不会被调用，或者如果调用了，则无法识别该函数。
   * **例子:** CSS 中写了 `transform: transalteX(10px);`。Blink 引擎的 CSS 解析器会遇到未知的函数名，可能忽略该属性或产生错误。

2. **参数数量或类型错误:**  每个 CSS 变换函数都有特定的参数数量和类型要求。例如，`rotate()` 只需要一个角度参数，而 `matrix()` 需要六个或十六个数值参数。
   * **例子:** CSS 中写了 `transform: rotate(10px);` (应该使用角度单位，如 `deg` 或 `rad`) 或 `transform: matrix(1, 0, 0, 1);` (`matrix()` 至少需要 6 个参数)。`transform_builder.cc` 在解析参数时会发现类型不匹配，导致创建 `TransformOperation` 对象失败或创建出不正确的变换。

3. **使用了不支持的单位:** 某些 CSS 属性可能不支持所有长度单位。虽然 `transform` 属性对于长度单位的支持较好，但在更复杂的场景中可能会出现问题。
   * **例子:** 理论上，如果使用了不被允许的长度单位（虽然 `px`, `em`, `%` 等在 `transform` 中常用且被支持），`transform_builder.cc` 在单位转换时可能会出错。

**用户操作是如何一步步的到达这里 (调试线索)：**

假设用户遇到了一个 HTML 元素变换不正确的 bug，想要了解 `transform_builder.cc` 的工作原理：

1. **用户在 HTML 文件中定义元素，并在 CSS 中为其设置了 `transform` 属性。**
   ```html
   <div id="myDiv">Hello</div>
   ```
   ```css
   #myDiv {
       transform: rotate(45deg) scale(1.2);
   }
   ```

2. **浏览器加载 HTML 文件，并开始解析 CSS 样式。**  Blink 引擎的 CSS 解析器会读取到 `#myDiv` 的 `transform` 属性值 `"rotate(45deg) scale(1.2)"`。

3. **CSS 解析器将 `transform` 属性值传递给 CSS 样式解析和计算的相关模块。**  在这个阶段，`transform_builder.cc` 就开始发挥作用了。

4. **`transform_builder.cc` 中的 `CreateTransformOperations` 函数被调用，接收 `transform` 属性的 `CSSValueList`（包含 `rotate` 和 `scale` 两个 `CSSFunctionValue` 对象）。**

5. **对于每个 `CSSFunctionValue`，`CreateTransformOperation` 函数会被调用：**
   * **对于 `rotate(45deg)`:**  `GetTransformOperationType` 返回 `TransformOperation::kRotate`，然后创建一个 `RotateTransformOperation` 对象，角度为 45 度。
   * **对于 `scale(1.2)`:** `GetTransformOperationType` 返回 `TransformOperation::kScale`，然后创建一个 `ScaleTransformOperation` 对象，水平和垂直缩放比例均为 1.2。

6. **`CreateTransformOperations` 函数返回一个包含创建的 `RotateTransformOperation` 和 `ScaleTransformOperation` 对象的 `TransformOperations` 列表。**

7. **这些 `TransformOperation` 对象会被传递到 Blink 引擎的布局和渲染阶段。**  渲染引擎会根据这些变换操作来计算 `myDiv` 元素在屏幕上的最终位置和外观。

**作为调试线索：**

* **断点设置:** 可以在 `transform_builder.cc` 的 `CreateTransformOperation` 函数入口处设置断点，查看传递进来的 `CSSFunctionValue` 的内容，确认 CSS 函数是否被正确解析。
* **单步调试:** 可以单步执行 `CreateTransformOperation` 函数，观察它是如何根据不同的 CSS 函数创建不同的 `TransformOperation` 对象的，以及如何解析参数的。
* **查看 `TransformOperation` 对象的内容:**  调试器可以查看创建的 `TransformOperation` 对象内部的数据，例如旋转角度、缩放比例、平移距离等，以验证解析是否正确。
* **检查 CSS 解析结果:**  在更早的 CSS 解析阶段设置断点，可以查看 `transform` 属性值是如何被解析成 `CSSValueList` 和 `CSSFunctionValue` 对象的，以排除 CSS 解析本身的问题。

通过以上分析，我们可以理解 `transform_builder.cc` 在 Chromium Blink 引擎中扮演着关键的角色，它连接了 CSS 声明式的变换描述和引擎内部的变换操作表示，是实现网页元素视觉效果的重要组成部分。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/transform_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 2004-2005 Allan Sandfeld Jensen (kde@carewolf.com)
 * Copyright (C) 2006, 2007 Nicholas Shanks (webkit@nickshanks.com)
 * Copyright (C) 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013 Apple Inc.
 * All rights reserved.
 * Copyright (C) 2007 Alexey Proskuryakov <ap@webkit.org>
 * Copyright (C) 2007, 2008 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2008, 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (c) 2011, Code Aurora Forum. All rights reserved.
 * Copyright (C) Research In Motion Limited 2011. All rights reserved.
 * Copyright (C) 2012 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/css/resolver/transform_builder.h"

#include "third_party/blink/renderer/core/css/css_function_value.h"
#include "third_party/blink/renderer/core/css/css_math_expression_node.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/platform/transforms/matrix_3d_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/matrix_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/perspective_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/rotate_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/scale_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/skew_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/translate_transform_operation.h"
#include "ui/gfx/geometry/transform.h"

namespace blink {

static Length ConvertToFloatLength(
    const CSSPrimitiveValue& primitive_value,
    const CSSToLengthConversionData& conversion_data) {
  return primitive_value.ConvertToLength(conversion_data);
}

static TransformOperation::OperationType GetTransformOperationType(
    CSSValueID type) {
  switch (type) {
    default:
      NOTREACHED();
    case CSSValueID::kScale:
      return TransformOperation::kScale;
    case CSSValueID::kScaleX:
      return TransformOperation::kScaleX;
    case CSSValueID::kScaleY:
      return TransformOperation::kScaleY;
    case CSSValueID::kScaleZ:
      return TransformOperation::kScaleZ;
    case CSSValueID::kScale3d:
      return TransformOperation::kScale3D;
    case CSSValueID::kTranslate:
      return TransformOperation::kTranslate;
    case CSSValueID::kTranslateX:
      return TransformOperation::kTranslateX;
    case CSSValueID::kTranslateY:
      return TransformOperation::kTranslateY;
    case CSSValueID::kTranslateZ:
      return TransformOperation::kTranslateZ;
    case CSSValueID::kTranslate3d:
      return TransformOperation::kTranslate3D;
    case CSSValueID::kRotate:
      return TransformOperation::kRotate;
    case CSSValueID::kRotateX:
      return TransformOperation::kRotateX;
    case CSSValueID::kRotateY:
      return TransformOperation::kRotateY;
    case CSSValueID::kRotateZ:
      return TransformOperation::kRotateZ;
    case CSSValueID::kRotate3d:
      return TransformOperation::kRotate3D;
    case CSSValueID::kSkew:
      return TransformOperation::kSkew;
    case CSSValueID::kSkewX:
      return TransformOperation::kSkewX;
    case CSSValueID::kSkewY:
      return TransformOperation::kSkewY;
    case CSSValueID::kMatrix:
      return TransformOperation::kMatrix;
    case CSSValueID::kMatrix3d:
      return TransformOperation::kMatrix3D;
    case CSSValueID::kPerspective:
      return TransformOperation::kPerspective;
  }
}

bool TransformBuilder::HasRelativeLengths(const CSSValueList& value_list) {
  for (auto& value : value_list) {
    const auto* transform_value = To<CSSFunctionValue>(value.Get());

    for (const CSSValue* item : *transform_value) {
      const auto& primitive_value = To<CSSPrimitiveValue>(*item);
      if (primitive_value.IsCalculated()) {
        if (To<CSSMathFunctionValue>(primitive_value).MayHaveRelativeUnit()) {
          return true;
        }
      } else {
        CSSPrimitiveValue::UnitType unit_type =
            To<CSSNumericLiteralValue>(primitive_value).GetType();
        if (CSSPrimitiveValue::IsRelativeUnit(unit_type)) {
          return true;
        }
      }
    }
  }
  return false;
}

namespace {

TransformOperation* CreateTransformOperation(
    const CSSFunctionValue& transform_value,
    const CSSToLengthConversionData& conversion_data) {
  TransformOperation::OperationType transform_type =
      GetTransformOperationType(transform_value.FunctionType());
  switch (transform_type) {
    case TransformOperation::kScale:
    case TransformOperation::kScaleX:
    case TransformOperation::kScaleY: {
      const auto& first_value = To<CSSPrimitiveValue>(transform_value.Item(0));
      double sx = 1.0;
      double sy = 1.0;
      if (transform_type == TransformOperation::kScaleY) {
        sy = first_value.ComputeNumber(conversion_data);
      } else {
        sx = first_value.ComputeNumber(conversion_data);
        if (transform_type != TransformOperation::kScaleX) {
          if (transform_value.length() > 1) {
            const auto& second_value =
                To<CSSPrimitiveValue>(transform_value.Item(1));
            sy = second_value.ComputeNumber(conversion_data);
          } else {
            sy = sx;
          }
        }
      }
      return MakeGarbageCollected<ScaleTransformOperation>(sx, sy, 1.0,
                                                           transform_type);
    }
    case TransformOperation::kScaleZ:
    case TransformOperation::kScale3D: {
      const auto& first_value = To<CSSPrimitiveValue>(transform_value.Item(0));
      double sx = 1.0;
      double sy = 1.0;
      double sz = 1.0;
      if (transform_type == TransformOperation::kScaleZ) {
        sz = first_value.ComputeNumber(conversion_data);
      } else {
        sx = first_value.ComputeNumber(conversion_data);
        sy = To<CSSPrimitiveValue>(transform_value.Item(1))
                 .ComputeNumber(conversion_data);
        sz = To<CSSPrimitiveValue>(transform_value.Item(2))
                 .ComputeNumber(conversion_data);
      }
      return MakeGarbageCollected<ScaleTransformOperation>(sx, sy, sz,
                                                           transform_type);
    }
    case TransformOperation::kTranslate:
    case TransformOperation::kTranslateX:
    case TransformOperation::kTranslateY: {
      const auto& first_value = To<CSSPrimitiveValue>(transform_value.Item(0));
      Length tx = Length::Fixed(0);
      Length ty = Length::Fixed(0);
      if (transform_type == TransformOperation::kTranslateY) {
        ty = ConvertToFloatLength(first_value, conversion_data);
      } else {
        tx = ConvertToFloatLength(first_value, conversion_data);
        if (transform_type != TransformOperation::kTranslateX) {
          if (transform_value.length() > 1) {
            const auto& second_value =
                To<CSSPrimitiveValue>(transform_value.Item(1));
            ty = ConvertToFloatLength(second_value, conversion_data);
          }
        }
      }
      return MakeGarbageCollected<TranslateTransformOperation>(tx, ty, 0,
                                                               transform_type);
    }
    case TransformOperation::kTranslateZ:
    case TransformOperation::kTranslate3D: {
      const auto& first_value = To<CSSPrimitiveValue>(transform_value.Item(0));
      Length tx = Length::Fixed(0);
      Length ty = Length::Fixed(0);
      double tz = 0;
      if (transform_type == TransformOperation::kTranslateZ) {
        tz = first_value.ComputeLength<double>(conversion_data);
      } else {
        tx = ConvertToFloatLength(first_value, conversion_data);
        ty = ConvertToFloatLength(
            To<CSSPrimitiveValue>(transform_value.Item(1)), conversion_data);
        tz = To<CSSPrimitiveValue>(transform_value.Item(2))
                 .ComputeLength<double>(conversion_data);
      }

      return MakeGarbageCollected<TranslateTransformOperation>(tx, ty, tz,
                                                               transform_type);
    }
    case TransformOperation::kRotateX:
    case TransformOperation::kRotateY:
    case TransformOperation::kRotateZ:
    case TransformOperation::kRotate: {
      const auto& first_value = To<CSSPrimitiveValue>(transform_value.Item(0));
      double angle = first_value.ComputeDegrees(conversion_data);
      if (transform_value.length() == 1) {
        double x = transform_type == TransformOperation::kRotateX;
        double y = transform_type == TransformOperation::kRotateY;
        double z = transform_type == TransformOperation::kRotateZ ||
                   transform_type == TransformOperation::kRotate;
        return MakeGarbageCollected<RotateTransformOperation>(x, y, z, angle,
                                                              transform_type);
      } else {
        // For SVG 'transform' attributes we generate 3-argument rotate()
        // functions.
        DCHECK_EQ(transform_value.length(), 3u);
        const auto& second_value =
            To<CSSPrimitiveValue>(transform_value.Item(1));
        const CSSPrimitiveValue& third_value =
            To<CSSPrimitiveValue>(transform_value.Item(2));
        return MakeGarbageCollected<RotateAroundOriginTransformOperation>(
            angle, second_value.ComputeLength<double>(conversion_data),
            third_value.ComputeLength<double>(conversion_data));
      }
    }
    case TransformOperation::kRotate3D: {
      const auto& first_value = To<CSSPrimitiveValue>(transform_value.Item(0));
      const auto& second_value = To<CSSPrimitiveValue>(transform_value.Item(1));
      const auto& third_value = To<CSSPrimitiveValue>(transform_value.Item(2));
      const auto& fourth_value = To<CSSPrimitiveValue>(transform_value.Item(3));
      double x = first_value.ComputeNumber(conversion_data);
      double y = second_value.ComputeNumber(conversion_data);
      double z = third_value.ComputeNumber(conversion_data);
      double angle = fourth_value.ComputeDegrees(conversion_data);
      return MakeGarbageCollected<RotateTransformOperation>(x, y, z, angle,
                                                            transform_type);
    }
    case TransformOperation::kSkew:
    case TransformOperation::kSkewX:
    case TransformOperation::kSkewY: {
      const auto& first_value = To<CSSPrimitiveValue>(transform_value.Item(0));
      double angle_x = 0;
      double angle_y = 0;
      double angle = first_value.ComputeDegrees(conversion_data);
      if (transform_type == TransformOperation::kSkewY) {
        angle_y = angle;
      } else {
        angle_x = angle;
        if (transform_type == TransformOperation::kSkew) {
          if (transform_value.length() > 1) {
            const auto& second_value =
                To<CSSPrimitiveValue>(transform_value.Item(1));
            angle_y = second_value.ComputeDegrees(conversion_data);
          }
        }
      }
      return MakeGarbageCollected<SkewTransformOperation>(angle_x, angle_y,
                                                          transform_type);
    }
    case TransformOperation::kMatrix: {
      double a = To<CSSPrimitiveValue>(transform_value.Item(0))
                     .ComputeNumber(conversion_data);
      double b = To<CSSPrimitiveValue>(transform_value.Item(1))
                     .ComputeNumber(conversion_data);
      double c = To<CSSPrimitiveValue>(transform_value.Item(2))
                     .ComputeNumber(conversion_data);
      double d = To<CSSPrimitiveValue>(transform_value.Item(3))
                     .ComputeNumber(conversion_data);
      double e = conversion_data.Zoom() *
                 To<CSSPrimitiveValue>(transform_value.Item(4))
                     .ComputeNumber(conversion_data);
      double f = conversion_data.Zoom() *
                 To<CSSPrimitiveValue>(transform_value.Item(5))
                     .ComputeNumber(conversion_data);
      return MakeGarbageCollected<MatrixTransformOperation>(a, b, c, d, e, f);
    }
    case TransformOperation::kMatrix3D: {
      auto matrix = gfx::Transform::ColMajor(
          To<CSSPrimitiveValue>(transform_value.Item(0))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(1))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(2))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(3))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(4))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(5))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(6))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(7))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(8))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(9))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(10))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(11))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(12))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(13))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(14))
              .ComputeNumber(conversion_data),
          To<CSSPrimitiveValue>(transform_value.Item(15))
              .ComputeNumber(conversion_data));
      matrix.Zoom(conversion_data.Zoom());
      return MakeGarbageCollected<Matrix3DTransformOperation>(matrix);
    }
    case TransformOperation::kPerspective: {
      std::optional<double> p;
      const auto& first_value = transform_value.Item(0);
      const auto* primitive_value = DynamicTo<CSSPrimitiveValue>(first_value);
      if (primitive_value) {
        p = primitive_value->ComputeLength<double>(conversion_data);
        DCHECK_GE(*p, 0);
      } else {
        DCHECK_EQ(To<CSSIdentifierValue>(first_value).GetValueID(),
                  CSSValueID::kNone);
        // leave p as nullopt to represent 'none'
      }
      return MakeGarbageCollected<PerspectiveTransformOperation>(p);
    }
    default:
      NOTREACHED();
  }
}

}  // namespace

TransformOperations TransformBuilder::CreateTransformOperations(
    const CSSValue& in_value,
    const CSSToLengthConversionData& conversion_data) {
  TransformOperations operations;
  if (auto* in_value_function = DynamicTo<CSSFunctionValue>(in_value)) {
    operations.Operations().push_back(
        CreateTransformOperation(*in_value_function, conversion_data));
  } else if (auto* in_value_list = DynamicTo<CSSValueList>(in_value)) {
    for (auto& value : *in_value_list) {
      const auto* transform_value = To<CSSFunctionValue>(value.Get());
      operations.Operations().push_back(
          CreateTransformOperation(*transform_value, conversion_data));
    }
  } else {
    DCHECK_EQ(To<CSSIdentifierValue>(in_value).GetValueID(), CSSValueID::kNone);
  }
  return operations;
}

}  // namespace blink

"""

```