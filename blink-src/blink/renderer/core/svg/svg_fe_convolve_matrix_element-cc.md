Response:
Let's break down the thought process for analyzing this C++ file.

1. **Identify the Core Purpose:** The filename `svg_fe_convolve_matrix_element.cc` and the inclusion of `<svg>` in the path strongly suggest this file is about SVG functionality within the Blink rendering engine. The `FEConvolveMatrix` part immediately hints at a specific SVG filter primitive.

2. **Scan for Keywords and Classes:** Look for significant class names and keywords. Here, `SVGFEConvolveMatrixElement`, `FEConvolveMatrix`, `SVGAnimated...`, `SVGFilterBuilder`, `FilterEffect`, `SVGElement`, and attribute names like `kOrderAttr`, `kBiasAttr`, etc., stand out. These provide initial clues about the file's responsibilities.

3. **Analyze the Class Definition (`SVGFEConvolveMatrixElement`):**
    * **Inheritance:** It inherits from `SVGFilterPrimitiveStandardAttributes`. This tells us it's part of a larger system for handling SVG filter primitives and will likely share common functionality.
    * **Member Variables:** The member variables (e.g., `bias_`, `divisor_`, `in1_`, `edge_mode_`, `kernel_matrix_`, etc.) are wrapped in `MakeGarbageCollected<SVGAnimated...>`, indicating they represent animatable SVG attributes. Their names directly correspond to attributes of the `<feConvolveMatrix>` SVG filter.
    * **Constructor:** The constructor initializes these `SVGAnimated...` objects, linking them to specific SVG attributes and potentially providing default values.

4. **Examine Key Methods:** Focus on the methods that seem to have a significant impact:
    * **`MatrixOrder()` and `TargetPoint()`:** These methods calculate derived values based on the `order` and `targetX`/`targetY` attributes. Notice the logic for default values when the attributes are not specified. This is crucial for understanding how the filter behaves.
    * **`ComputeDivisor()`:** This method shows how the `divisor` attribute is calculated, potentially falling back to a sum of the `kernelMatrix` if `divisor` isn't specified. This reveals a dependency and a fallback mechanism.
    * **`SetFilterEffectAttribute()`:**  This is where the connection to the underlying filter effect (`FEConvolveMatrix`) happens. It maps SVG attributes to properties of the `FEConvolveMatrix` object. This is the bridge between the DOM representation and the actual filtering operation.
    * **`SvgAttributeChanged()`:**  This method is called when an SVG attribute on the `<feConvolveMatrix>` element changes. It triggers either a primitive attribute update or invalidation, signaling the need for a re-render or recalculation.
    * **`Build()`:** This is the core logic for creating the `FEConvolveMatrix` object used in the actual filtering process. It takes input from other filter effects and uses the values of the animatable attributes.
    * **`PropertyFromAttribute()`:**  This acts as a lookup, returning the `SVGAnimatedPropertyBase` associated with a given SVG attribute. This is important for the animation system.
    * **`SynchronizeAllSVGAttributes()`:** This method likely ensures the C++ representation stays in sync with the DOM attributes.

5. **Connect to SVG Concepts:**  Relate the code back to the SVG `<feConvolveMatrix>` filter. The attributes like `kernelMatrix`, `order`, `targetX`, `targetY`, `divisor`, `bias`, and `edgeMode` are directly from the SVG specification. Understanding the purpose of these attributes in SVG is key to understanding the C++ code.

6. **Consider Interactions with Other Technologies (JavaScript, HTML, CSS):**
    * **HTML:** The `<feConvolveMatrix>` element is part of the SVG markup embedded in HTML.
    * **CSS:** CSS can style the SVG element containing the filter or potentially animate the filter attributes using CSS animations or transitions (though direct manipulation of filter attributes via CSS is more limited than JavaScript).
    * **JavaScript:** JavaScript can directly manipulate the attributes of the `<feConvolveMatrix>` element in the DOM, triggering the `SvgAttributeChanged()` method and leading to updates in the rendering.

7. **Infer Potential User Errors and Debugging:**  Think about what could go wrong when using this filter:
    * Incorrect `kernelMatrix` size compared to `order`.
    * Invalid `order` values (negative or zero, which are explicitly checked).
    * Incorrect or missing `in` attribute.
    * Performance issues with large kernel matrices.

8. **Trace User Actions:**  Imagine a user interacting with a web page that uses this filter. How would they trigger this code?  By loading the page, by JavaScript manipulating the filter, or by CSS animations.

9. **Formulate the Explanation:**  Organize the findings into clear sections covering the file's function, relationships to other technologies, logical inferences, potential errors, and debugging. Use examples to illustrate the connections to HTML, CSS, and JavaScript. Explain the steps a user might take to reach this code.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file just handles the `<feConvolveMatrix>` element."
* **Correction:** "It does handle that element, but specifically the *Blink* representation of it, managing its attributes, interacting with the filter effect, and integrating with the rendering pipeline."
* **Initial thought:**  "The `SVGAnimated...` stuff is just boilerplate."
* **Correction:** "No, `SVGAnimated...` is crucial for handling attribute changes and animations, it's how the dynamic nature of SVG is implemented."
* **Initial thought:** "The `Build()` method just creates the `FEConvolveMatrix` object."
* **Correction:** "It creates it *using the current attribute values* and connects it to the input filter effect. This is a key step in the filter application process."

By iteratively examining the code, relating it to SVG concepts, and considering the broader context of a web browser, a comprehensive understanding of the file's functionality can be achieved.
好的，让我们来详细分析一下 `blink/renderer/core/svg/svg_fe_convolve_matrix_element.cc` 这个文件。

**文件功能概述**

`svg_fe_convolve_matrix_element.cc` 文件定义了 `SVGFEConvolveMatrixElement` 类，该类是 Chromium Blink 渲染引擎中用来表示 SVG `<feConvolveMatrix>` 滤镜元素的 C++ 实现。  `<feConvolveMatrix>` 滤镜用于对输入图像应用卷积矩阵效果，可以实现模糊、锐化、边缘检测等图像处理。

该文件的核心功能包括：

1. **表示和管理 SVG `<feConvolveMatrix>` 元素:**
   - 定义了 `SVGFEConvolveMatrixElement` 类，继承自 `SVGFilterPrimitiveStandardAttributes`，代表了 DOM 树中的 `<feConvolveMatrix>` 节点。
   - 包含了与 `<feConvolveMatrix>` 元素属性对应的成员变量，例如 `kernelMatrix`（卷积核矩阵）、`order`（卷积核尺寸）、`targetX/Y`（卷积核中心偏移）、`divisor`（除数）、`bias`（偏移量）、`edgeMode`（边缘处理模式）和 `preserveAlpha`（是否保留 Alpha 通道）。
   - 使用 `SVGAnimatedXXX` 模板类来表示这些属性，以支持 SVG 动画。

2. **解析和存储 SVG 属性:**
   - 在构造函数中初始化了与 `<feConvolveMatrix>` 元素属性关联的 `SVGAnimatedXXX` 对象。
   - 实现了 `PropertyFromAttribute()` 方法，用于根据属性名返回对应的 `SVGAnimatedPropertyBase` 对象，方便属性的访问和修改。
   - 实现了 `SvgAttributeChanged()` 方法，用于处理 SVG 属性值的变化，并根据变化的属性触发相应的操作，例如标记需要重新构建滤镜效果。

3. **构建和应用滤镜效果:**
   - 实现了 `Build()` 方法，该方法在渲染时被调用，用于创建实际的滤镜效果对象 `FEConvolveMatrix`。
   - `Build()` 方法会读取当前元素的属性值，并将其传递给 `FEConvolveMatrix` 构造函数，从而创建一个表示当前 `<feConvolveMatrix>` 滤镜效果的 C++ 对象。
   - `Build()` 方法还负责获取输入源（通过 `in` 属性指定）并将其添加到滤镜效果的输入列表中。

4. **处理属性变化并更新滤镜效果:**
   - `SetFilterEffectAttribute()` 方法用于将 SVG 属性的变化同步到实际的滤镜效果对象 `FEConvolveMatrix` 中。
   - 当某些关键属性（如 `edgeMode`, `divisor`, `bias`, `targetX`, `targetY`, `preserveAlpha`) 发生变化时，会调用此方法来更新 `FEConvolveMatrix` 对象的相应属性。

5. **提供辅助方法:**
   - `MatrixOrder()` 方法用于获取卷积核的尺寸。
   - `TargetPoint()` 方法用于获取卷积核的中心点。
   - `ComputeDivisor()` 方法用于计算 `divisor` 属性的值，如果未指定则根据 `kernelMatrix` 计算。

**与 JavaScript, HTML, CSS 的关系**

`SVGFEConvolveMatrixElement` 类直接关联到以下前端技术：

* **HTML:**  `<feConvolveMatrix>` 元素是 SVG 规范的一部分，它被嵌入到 HTML 文档中的 `<svg>` 元素内。Blink 引擎解析 HTML 时遇到 `<feConvolveMatrix>` 标签，会创建 `SVGFEConvolveMatrixElement` 的实例来表示这个 DOM 节点。

   **举例:**

   ```html
   <!DOCTYPE html>
   <html>
   <body>

   <svg width="300" height="300">
     <filter id="convolutionFilter" x="0" y="0" width="200%" height="200%">
       <feConvolveMatrix in="SourceGraphic"
                         kernelMatrix="0 1 0 1 -4 1 0 1 0"
                         order="3"
                         divisor="1"
                         bias="0"
                         targetX="1"
                         targetY="1"
                         edgeMode="duplicate"
                         preserveAlpha="true"/>
     </filter>
     <rect width="100" height="100" fill="red" filter="url(#convolutionFilter)" />
   </svg>

   </body>
   </html>
   ```
   在这个例子中，`<feConvolveMatrix>` 元素定义了一个卷积滤镜，`SVGFEConvolveMatrixElement` 对象会在 Blink 解析这段 HTML 时被创建，并负责处理 `kernelMatrix`、`order` 等属性。

* **JavaScript:** JavaScript 可以通过 DOM API 来访问和修改 `<feConvolveMatrix>` 元素的属性。当这些属性被修改时，会触发 `SVGFEConvolveMatrixElement::SvgAttributeChanged()` 方法，从而更新内部状态和重新构建滤镜效果。

   **举例:**

   ```javascript
   const convolveMatrix = document.querySelector('feConvolveMatrix');
   convolveMatrix.setAttribute('bias', '0.5'); // 修改 bias 属性
   ```
   这段 JavaScript 代码会修改 HTML 中 `<feConvolveMatrix>` 元素的 `bias` 属性。Blink 引擎接收到这个变化后，会调用 `SVGFEConvolveMatrixElement` 实例的 `SvgAttributeChanged()` 方法，进而可能调用 `SetFilterEffectAttribute()` 更新底层的 `FEConvolveMatrix` 对象。

* **CSS:** 虽然 CSS 不能直接操作 `<feConvolveMatrix>` 元素的内部属性，但可以通过 CSS 滤镜效果（`filter` 属性）来引用定义好的 SVG 滤镜。  CSS 动画和过渡可以改变应用了滤镜的元素的属性，从而间接地触发 SVG 滤镜的更新。

   **举例:**

   ```css
   .blurred-image {
     filter: url(#convolutionFilter);
     transition: filter 1s ease-in-out;
   }

   .blurred-image:hover {
     filter: none;
   }
   ```
   在这个例子中，CSS 将 ID 为 `convolutionFilter` 的 SVG 滤镜应用到一个元素上。虽然 CSS 没有直接修改 `<feConvolveMatrix>` 的属性，但 CSS 的 `filter` 属性的改变会触发渲染流程，从而使用到 `SVGFEConvolveMatrixElement` 构建的滤镜效果。

**逻辑推理、假设输入与输出**

假设有以下 SVG 代码：

```xml
<feConvolveMatrix in="SourceGraphic" kernelMatrix="1 2 1 0 0 0 -1 -2 -1" order="3"/>
```

**假设输入:**

-  `<feConvolveMatrix>` 元素的 `kernelMatrix` 属性值为字符串 "1 2 1 0 0 0 -1 -2 -1"。
-  `<feConvolveMatrix>` 元素的 `order` 属性值为字符串 "3"。
-  其他属性使用默认值。

**逻辑推理:**

1. **属性解析:** `SVGFEConvolveMatrixElement` 的构造函数和 `SvgAttributeChanged()` 方法会解析 `kernelMatrix` 和 `order` 属性。`kernelMatrix_` 成员变量会被设置为包含浮点数值 `[1, 2, 1, 0, 0, 0, -1, -2, -1]` 的 `SVGNumberList` 对象。 `order_` 成员变量会被设置为 `3`。

2. **`MatrixOrder()` 输出:** 当调用 `MatrixOrder()` 方法时，由于 `order` 属性已指定为 "3"，方法会返回 `gfx::Size(3, 3)`。

3. **`TargetPoint()` 输出:**  由于 `targetX` 和 `targetY` 未指定，方法会使用默认值 `floor(orderX / 2)` 和 `floor(orderY / 2)`。 因此，`TargetPoint()` 会返回 `gfx::Point(1, 1)`。

4. **`ComputeDivisor()` 输出:** 如果 `divisor` 属性未指定，`ComputeDivisor()` 会计算 `kernelMatrix` 中所有元素的和：`1 + 2 + 1 + 0 + 0 + 0 + (-1) + (-2) + (-1) = 0`。  由于和为 0，最终 `ComputeDivisor()` 会返回默认值 `1`。

5. **`Build()` 输出:**  `Build()` 方法会创建一个 `FEConvolveMatrix` 对象，其参数会根据上述解析和计算的值来设置：
   - `order`: `gfx::Size(3, 3)`
   - `divisor`: `1`
   - `bias`: `0.0f` (默认值)
   - `targetOffset`: `gfx::Vector2dF(1, 1)`
   - `edgeMode`: `FEConvolveMatrix::EDGEMODE_DUPLICATE` (默认值)
   - `preserveAlpha`: `false` (默认值)
   - `kernel`: `[1, 2, 1, 0, 0, 0, -1, -2, -1]`

**用户或编程常见的使用错误**

1. **`kernelMatrix` 的长度与 `order` 不匹配:**
   - **错误:**  `order="3"` 但 `kernelMatrix="1 2 3 4"` (长度为 4，应该为 9)。
   - **后果:**  滤镜效果可能不正确或根本不生效。Blink 可能会有相关的错误日志输出。

2. **`order` 值为负数或零:**
   - **错误:** `order="-1"` 或 `order="0"`.
   - **后果:** `SVGAnimatedOrder::CheckValue` 会返回 `SVGParseStatus::kNegativeValue` 或 `SVGParseStatus::kZeroValue` 错误，导致属性解析失败。

3. **未设置 `in` 属性或 `in` 属性指向不存在的滤镜结果:**
   - **错误:** `<feConvolveMatrix kernelMatrix="..." order="3"/>` (缺少 `in` 属性)。
   - **后果:** `filter_builder->GetEffectById()` 返回空指针，导致 `DCHECK(input1)` 失败，程序可能崩溃或产生未定义的行为。

4. **`divisor` 属性设置为零，但 `kernelMatrix` 的和也为零:**
   - **错误:** `<feConvolveMatrix kernelMatrix="0 0 0" order="3" divisor="0"/>`
   - **后果:**  虽然代码中有 `divisor_value ? divisor_value : 1` 的处理，但如果用户显式设置 `divisor="0"`，可能会导致除零错误，具体取决于后续的实现。最佳实践是避免将 `divisor` 显式设置为零。

5. **`targetX` 或 `targetY` 的值超出卷积核的范围:**
   - **错误:**  `order="3" targetX="5"`
   - **后果:** 卷积核的中心点会超出预期，可能导致滤镜效果不正确。

**用户操作如何一步步到达这里 (调试线索)**

1. **用户在 HTML 中添加了 `<svg>` 元素，并在其中包含了 `<filter>` 和 `<feConvolveMatrix>` 元素。**
2. **浏览器解析 HTML 代码，当解析到 `<feConvolveMatrix>` 标签时，Blink 引擎会创建 `SVGFEConvolveMatrixElement` 的实例。**  可以通过在 `SVGFEConvolveMatrixElement` 的构造函数中设置断点来验证这一点。
3. **浏览器会解析 `<feConvolveMatrix>` 元素的属性（例如 `kernelMatrix`, `order`），并调用 `SVGFEConvolveMatrixElement::SvgAttributeChanged()` 方法。**  可以在这个方法中设置断点，查看属性值是如何被解析的。
4. **如果用户通过 JavaScript 修改了 `<feConvolveMatrix>` 的属性，例如使用 `element.setAttribute('bias', '0.8')`，也会触发 `SvgAttributeChanged()` 方法。** 可以在 JavaScript 代码执行后，检查 `SVGFEConvolveMatrixElement` 对象的状态是否发生了变化。
5. **当需要渲染应用了此滤镜的 SVG 元素时，Blink 的渲染流程会调用 `SVGFEConvolveMatrixElement::Build()` 方法来创建实际的滤镜效果对象 `FEConvolveMatrix`。** 可以在 `Build()` 方法中设置断点，查看滤镜效果是如何构建的。
6. **Blink 最终会将 `FEConvolveMatrix` 对象传递给图形处理管线，进行实际的图像卷积操作。**  可以使用图形调试工具（如 Chrome 的 DevTools 中的 Layers 面板或第三方 GPU 调试器）来检查滤镜效果的输出。

总而言之，`svg_fe_convolve_matrix_element.cc` 文件在 Chromium Blink 引擎中扮演着至关重要的角色，它负责将 SVG 标准中的 `<feConvolveMatrix>` 元素转化为内部的 C++ 对象，并管理其属性和行为，最终驱动图像滤镜效果的渲染。理解这个文件的工作原理，有助于理解浏览器如何处理 SVG 滤镜，并能帮助开发者调试相关的渲染问题。

Prompt: 
```
这是目录为blink/renderer/core/svg/svg_fe_convolve_matrix_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2009 Dirk Schulze <krit@webkit.org>
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

#include "third_party/blink/renderer/core/svg/svg_fe_convolve_matrix_element.h"

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/svg/graphics/filters/svg_filter_builder.h"
#include "third_party/blink/renderer/core/svg/svg_animated_boolean.h"
#include "third_party/blink/renderer/core/svg/svg_animated_integer.h"
#include "third_party/blink/renderer/core/svg/svg_animated_integer_optional_integer.h"
#include "third_party/blink/renderer/core/svg/svg_animated_number.h"
#include "third_party/blink/renderer/core/svg/svg_animated_number_list.h"
#include "third_party/blink/renderer/core/svg/svg_animated_number_optional_number.h"
#include "third_party/blink/renderer/core/svg/svg_animated_string.h"
#include "third_party/blink/renderer/core/svg/svg_enumeration_map.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

template <>
CORE_EXPORT const SVGEnumerationMap&
GetEnumerationMap<FEConvolveMatrix::EdgeModeType>() {
  static constexpr auto enum_items = std::to_array<const char* const>({
      "duplicate",
      "wrap",
      "none",
  });
  static const SVGEnumerationMap entries(enum_items);
  return entries;
}

class SVGAnimatedOrder : public SVGAnimatedIntegerOptionalInteger {
 public:
  SVGAnimatedOrder(SVGElement* context_element)
      : SVGAnimatedIntegerOptionalInteger(context_element,
                                          svg_names::kOrderAttr,
                                          3) {}

  SVGParsingError AttributeChanged(const String&) override;

 protected:
  static SVGParsingError CheckValue(SVGParsingError parse_status, int value) {
    if (parse_status != SVGParseStatus::kNoError)
      return parse_status;
    if (value < 0)
      return SVGParseStatus::kNegativeValue;
    if (value == 0)
      return SVGParseStatus::kZeroValue;
    return SVGParseStatus::kNoError;
  }
};

SVGParsingError SVGAnimatedOrder::AttributeChanged(const String& value) {
  SVGParsingError parse_status =
      SVGAnimatedIntegerOptionalInteger::AttributeChanged(value);
  // Check for semantic errors.
  parse_status = CheckValue(parse_status, FirstInteger()->BaseValue()->Value());
  parse_status =
      CheckValue(parse_status, SecondInteger()->BaseValue()->Value());
  return parse_status;
}

SVGFEConvolveMatrixElement::SVGFEConvolveMatrixElement(Document& document)
    : SVGFilterPrimitiveStandardAttributes(svg_names::kFEConvolveMatrixTag,
                                           document),
      bias_(MakeGarbageCollected<SVGAnimatedNumber>(this,
                                                    svg_names::kBiasAttr,
                                                    0.0f)),
      divisor_(MakeGarbageCollected<SVGAnimatedNumber>(this,
                                                       svg_names::kDivisorAttr,
                                                       1)),
      in1_(MakeGarbageCollected<SVGAnimatedString>(this, svg_names::kInAttr)),
      edge_mode_(MakeGarbageCollected<
                 SVGAnimatedEnumeration<FEConvolveMatrix::EdgeModeType>>(
          this,
          svg_names::kEdgeModeAttr,
          FEConvolveMatrix::EDGEMODE_DUPLICATE)),
      kernel_matrix_(MakeGarbageCollected<SVGAnimatedNumberList>(
          this,
          svg_names::kKernelMatrixAttr)),
      kernel_unit_length_(MakeGarbageCollected<SVGAnimatedNumberOptionalNumber>(
          this,
          svg_names::kKernelUnitLengthAttr,
          0.0f)),
      order_(MakeGarbageCollected<SVGAnimatedOrder>(this)),
      preserve_alpha_(MakeGarbageCollected<SVGAnimatedBoolean>(
          this,
          svg_names::kPreserveAlphaAttr)),
      target_x_(
          MakeGarbageCollected<SVGAnimatedInteger>(this,
                                                   svg_names::kTargetXAttr,
                                                   0)),
      target_y_(
          MakeGarbageCollected<SVGAnimatedInteger>(this,
                                                   svg_names::kTargetYAttr,
                                                   0)) {}

SVGAnimatedNumber* SVGFEConvolveMatrixElement::kernelUnitLengthX() {
  return kernel_unit_length_->FirstNumber();
}

SVGAnimatedNumber* SVGFEConvolveMatrixElement::kernelUnitLengthY() {
  return kernel_unit_length_->SecondNumber();
}

SVGAnimatedInteger* SVGFEConvolveMatrixElement::orderX() const {
  return order_->FirstInteger();
}

SVGAnimatedInteger* SVGFEConvolveMatrixElement::orderY() const {
  return order_->SecondInteger();
}

void SVGFEConvolveMatrixElement::Trace(Visitor* visitor) const {
  visitor->Trace(bias_);
  visitor->Trace(divisor_);
  visitor->Trace(in1_);
  visitor->Trace(edge_mode_);
  visitor->Trace(kernel_matrix_);
  visitor->Trace(kernel_unit_length_);
  visitor->Trace(order_);
  visitor->Trace(preserve_alpha_);
  visitor->Trace(target_x_);
  visitor->Trace(target_y_);
  SVGFilterPrimitiveStandardAttributes::Trace(visitor);
}

gfx::Size SVGFEConvolveMatrixElement::MatrixOrder() const {
  if (!order_->IsSpecified())
    return gfx::Size(3, 3);
  return gfx::Size(orderX()->CurrentValue()->Value(),
                   orderY()->CurrentValue()->Value());
}

gfx::Point SVGFEConvolveMatrixElement::TargetPoint() const {
  gfx::Size order = MatrixOrder();
  gfx::Point target(target_x_->CurrentValue()->Value(),
                    target_y_->CurrentValue()->Value());
  // The spec says the default value is: targetX = floor ( orderX / 2 ))
  if (!target_x_->IsSpecified())
    target.set_x(order.width() / 2);
  // The spec says the default value is: targetY = floor ( orderY / 2 ))
  if (!target_y_->IsSpecified())
    target.set_y(order.height() / 2);
  return target;
}

float SVGFEConvolveMatrixElement::ComputeDivisor() const {
  if (divisor_->IsSpecified())
    return divisor_->CurrentValue()->Value();
  float divisor_value = 0;
  SVGNumberList* kernel_matrix = kernel_matrix_->CurrentValue();
  uint32_t kernel_matrix_size = kernel_matrix->length();
  for (uint32_t i = 0; i < kernel_matrix_size; ++i)
    divisor_value += kernel_matrix->at(i)->Value();
  return divisor_value ? divisor_value : 1;
}

bool SVGFEConvolveMatrixElement::SetFilterEffectAttribute(
    FilterEffect* effect,
    const QualifiedName& attr_name) {
  FEConvolveMatrix* convolve_matrix = static_cast<FEConvolveMatrix*>(effect);
  if (attr_name == svg_names::kEdgeModeAttr)
    return convolve_matrix->SetEdgeMode(edge_mode_->CurrentEnumValue());
  if (attr_name == svg_names::kDivisorAttr)
    return convolve_matrix->SetDivisor(ComputeDivisor());
  if (attr_name == svg_names::kBiasAttr)
    return convolve_matrix->SetBias(bias_->CurrentValue()->Value());
  if (attr_name == svg_names::kTargetXAttr ||
      attr_name == svg_names::kTargetYAttr)
    return convolve_matrix->SetTargetOffset(TargetPoint().OffsetFromOrigin());
  if (attr_name == svg_names::kPreserveAlphaAttr)
    return convolve_matrix->SetPreserveAlpha(
        preserve_alpha_->CurrentValue()->Value());
  return SVGFilterPrimitiveStandardAttributes::SetFilterEffectAttribute(
      effect, attr_name);
}

void SVGFEConvolveMatrixElement::SvgAttributeChanged(
    const SvgAttributeChangedParams& params) {
  const QualifiedName& attr_name = params.name;
  if (attr_name == svg_names::kEdgeModeAttr ||
      attr_name == svg_names::kDivisorAttr ||
      attr_name == svg_names::kBiasAttr ||
      attr_name == svg_names::kTargetXAttr ||
      attr_name == svg_names::kTargetYAttr ||
      attr_name == svg_names::kPreserveAlphaAttr) {
    PrimitiveAttributeChanged(attr_name);
    return;
  }

  if (attr_name == svg_names::kInAttr || attr_name == svg_names::kOrderAttr ||
      attr_name == svg_names::kKernelMatrixAttr) {
    Invalidate();
    return;
  }

  SVGFilterPrimitiveStandardAttributes::SvgAttributeChanged(params);
}

FilterEffect* SVGFEConvolveMatrixElement::Build(
    SVGFilterBuilder* filter_builder,
    Filter* filter) {
  FilterEffect* input1 = filter_builder->GetEffectById(
      AtomicString(in1_->CurrentValue()->Value()));
  DCHECK(input1);

  auto* effect = MakeGarbageCollected<FEConvolveMatrix>(
      filter, MatrixOrder(), ComputeDivisor(), bias_->CurrentValue()->Value(),
      TargetPoint().OffsetFromOrigin(), edge_mode_->CurrentEnumValue(),
      preserve_alpha_->CurrentValue()->Value(),
      kernel_matrix_->CurrentValue()->ToFloatVector());
  effect->InputEffects().push_back(input1);
  return effect;
}

SVGAnimatedPropertyBase* SVGFEConvolveMatrixElement::PropertyFromAttribute(
    const QualifiedName& attribute_name) const {
  if (attribute_name == svg_names::kPreserveAlphaAttr) {
    return preserve_alpha_.Get();
  } else if (attribute_name == svg_names::kDivisorAttr) {
    return divisor_.Get();
  } else if (attribute_name == svg_names::kBiasAttr) {
    return bias_.Get();
  } else if (attribute_name == svg_names::kKernelUnitLengthAttr) {
    return kernel_unit_length_.Get();
  } else if (attribute_name == svg_names::kKernelMatrixAttr) {
    return kernel_matrix_.Get();
  } else if (attribute_name == svg_names::kInAttr) {
    return in1_.Get();
  } else if (attribute_name == svg_names::kEdgeModeAttr) {
    return edge_mode_.Get();
  } else if (attribute_name == order_->AttributeName()) {
    return order_.Get();
  } else if (attribute_name == svg_names::kTargetXAttr) {
    return target_x_.Get();
  } else if (attribute_name == svg_names::kTargetYAttr) {
    return target_y_.Get();
  } else {
    return SVGFilterPrimitiveStandardAttributes::PropertyFromAttribute(
        attribute_name);
  }
}

void SVGFEConvolveMatrixElement::SynchronizeAllSVGAttributes() const {
  SVGAnimatedPropertyBase* attrs[]{
      preserve_alpha_.Get(), divisor_.Get(),
      bias_.Get(),           kernel_unit_length_.Get(),
      kernel_matrix_.Get(),  in1_.Get(),
      edge_mode_.Get(),      order_.Get(),
      target_x_.Get(),       target_y_.Get()};
  SynchronizeListOfSVGAttributes(attrs);
  SVGFilterPrimitiveStandardAttributes::SynchronizeAllSVGAttributes();
}

}  // namespace blink

"""

```