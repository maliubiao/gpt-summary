Response:
Let's break down the thought process for analyzing this C++ source code file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to web technologies (HTML, CSS, JavaScript), examples, potential user errors, and debugging hints.

2. **Initial Scan and Keyword Spotting:**  A quick skim reveals key terms like "basic_shape", "CSSValue", "StyleRay", "BasicShapeCircle", "BasicShapeEllipse", "BasicShapePolygon", "BasicShapeInset", "StyleResolverState", and function names like `ValueForBasicShape`, `BasicShapeForValue`, and `ConvertTo...`. These strongly suggest the file is involved in processing CSS shapes.

3. **Identify Core Functionality (First Pass):**  The presence of `ValueForBasicShape` and `BasicShapeForValue` immediately suggests bidirectional conversion between internal Blink representations of basic shapes and their corresponding CSS value representations. The "Convert" functions reinforce this.

4. **Analyze `ValueForBasicShape`:** This function takes a `ComputedStyle` and a `BasicShape` object and returns a `CSSValue*`. The `switch` statement based on `basic_shape->GetType()` clearly indicates it handles different types of basic shapes (ray, path, circle, ellipse, polygon, inset). For each type, it creates a corresponding `CSSValue` object (e.g., `CSSRayValue`, `CSSBasicShapeCircleValue`) and populates it with data from the `BasicShape` object. This function seems to be *serializing* the internal representation to a CSS value.

5. **Analyze `BasicShapeForValue`:** This function takes a `StyleResolverState` and a `CSSValue` and returns a `BasicShape`. Again, a `switch` statement based on the `CSSValue`'s type indicates it handles different CSS basic shape value types (CSSBasicShapeCircleValue, CSSBasicShapeEllipseValue, etc.). It extracts data from the `CSSValue` and constructs the corresponding `BasicShape` object. This function seems to be *deserializing* a CSS value into the internal representation.

6. **Analyze "Convert" Functions:** Functions like `ConvertToLength`, `ConvertToLengthSize`, `ConvertToCenterCoordinate`, and `CssValueToBasicShapeRadius` handle the conversion of CSS values (potentially with different units and keywords) into Blink's internal length and coordinate representations. They also handle default values and different ways of expressing the same information (e.g., 'top', 'left' vs. 'right', 'bottom').

7. **Connect to Web Technologies:**
    * **CSS:** The file directly deals with CSS basic shape functions like `circle()`, `ellipse()`, `polygon()`, `inset()`, `ray()`, and `path()`. It's responsible for parsing and representing these CSS features.
    * **HTML:** While not directly manipulating HTML, this code is crucial for *rendering* HTML elements that use CSS shapes. The browser needs to understand the CSS to visually present the shaped elements.
    * **JavaScript:** JavaScript can indirectly interact through CSSOM (CSS Object Model). Scripts can read and modify CSS properties that use basic shapes, and this file is part of the engine that interprets those changes.

8. **Provide Examples:** Concrete CSS examples demonstrating each basic shape function are essential to illustrate the connection to web development. Matching these CSS examples with the corresponding C++ code paths helps clarify the functionality.

9. **Infer Logical Reasoning and Input/Output:**  Consider a specific CSS example, like `clip-path: circle(50%);`. Trace the likely execution flow: the CSS parser encounters this, the `StyleResolverState` is involved, and `BasicShapeForValue` would be called with the parsed `CSSBasicShapeCircleValue`. The output would be a `BasicShapeCircle` object with a radius of 50% and a default center. Similarly, the reverse would occur with `ValueForBasicShape`.

10. **Identify Potential User/Programming Errors:**  Common mistakes when using CSS shapes include incorrect syntax, invalid units, and misunderstandings of how coordinate systems and radii work. Relate these to how the C++ code might handle such errors (though the C++ code itself primarily *processes* valid input). The `NOTREACHED()` macros hint at assumptions about valid input.

11. **Debugging Clues and User Operations:** Think about how a developer might end up investigating this file. Likely scenarios involve:
    * A web page not rendering shapes correctly.
    * Errors or unexpected behavior when using CSS shape properties.
    * Performance issues related to rendering complex shapes.
    * Inspecting the "Styles" tab in browser DevTools and seeing computed `clip-path` or `shape-outside` values.

12. **Refine and Organize:** Structure the analysis logically, starting with the overall function, then diving into specifics. Use clear headings and bullet points. Ensure the examples are relevant and easy to understand.

13. **Review and Verify:**  Read through the analysis to ensure accuracy and completeness. Double-check the connections between the C++ code and the web technologies.

Self-Correction/Refinement Example During Thought Process:

* **Initial thought:**  This file just *creates* basic shape objects.
* **Correction:**  No, it *converts* between CSS representations and internal objects. The `ValueFor...` functions suggest serialization, and `...ForValue` suggests deserialization. This is a crucial distinction.
* **Initial thought:** The user directly interacts with this C++ code.
* **Correction:** The user interacts with HTML, CSS, and JavaScript. This C++ code is part of the *browser engine* that interprets and renders those technologies. The interaction is indirect.

By following this iterative process of scanning, analyzing, connecting, exemplifying, and refining, a comprehensive understanding of the C++ source file's role can be achieved.
这个文件 `basic_shape_functions.cc` 是 Chromium Blink 渲染引擎的一部分，它负责处理 **CSS 基础图形 (Basic Shapes)** 的相关功能。 它的主要功能是 **在 CSS 值的表示和 Blink 内部的图形表示之间进行转换**。

更具体地说，这个文件包含了以下关键功能：

1. **将 CSS 基础图形值转换为内部表示 (Blink 的 `BasicShape` 类及其子类):**  当浏览器解析 CSS 样式时，如果遇到了像 `circle()`, `ellipse()`, `polygon()`, `inset()`, `ray()` 或 `path()` 这样的基础图形函数，这个文件中的函数会将这些 CSS 值转换为 Blink 内部更容易处理和渲染的 `BasicShape` 对象。  例如，CSS 的 `circle(50px)` 会被转换成一个 `BasicShapeCircle` 对象，其中半径属性被设置为 50 像素。

2. **将内部图形表示转换回 CSS 值:**  在某些情况下，例如在计算样式或序列化样式时，需要将 Blink 内部的 `BasicShape` 对象转换回 CSS 值的表示形式。这个文件中的函数也负责执行这个逆向转换。

3. **处理各种基础图形类型:**  文件中的代码针对不同的基础图形类型（圆形、椭圆、多边形、内切矩形、射线、路径）提供了专门的处理逻辑，确保每种类型的图形都能正确地在 CSS 值和内部表示之间转换。

4. **处理基础图形的各种属性:**  对于每种基础图形，文件中的代码还负责处理其相关的属性，例如圆的半径和中心点，椭圆的两个半径和中心点，多边形的顶点坐标，内切矩形的偏移量和圆角半径，射线的角度和尺寸等等。

5. **与样式解析过程集成:**  这些转换函数被集成到 Blink 的样式解析流程中，在样式计算的不同阶段被调用，以确保正确地理解和应用 CSS 基础图形。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件直接参与了 **CSS** 基础图形功能的实现，并间接地与 **HTML** 和 **JavaScript** 相关。

* **CSS:**  这是这个文件最直接相关的部分。CSS 基础图形允许开发者在 CSS 中定义各种形状，用于裁剪元素 (`clip-path`)、定义浮动区域 (`shape-outside`) 等。

    * **举例：**
        * CSS 代码：`clip-path: circle(50px at 100px 100px);`
        * `basic_shape_functions.cc` 的功能：`BasicShapeForValue` 函数会解析这个 CSS 值，创建一个 `BasicShapeCircle` 对象，其 `radius` 属性为 50 像素，`centerX` 和 `centerY` 属性分别为 100 像素。
        * CSS 代码：`shape-outside: polygon(0 0, 100px 0, 50px 100px);`
        * `basic_shape_functions.cc` 的功能：`BasicShapeForValue` 函数会解析这个 CSS 值，创建一个 `BasicShapePolygon` 对象，其 `values` 属性包含三个点的坐标。
        * 反向转换：如果需要获取某个元素的 `clip-path` 的计算值，并且该值是一个圆形，`ValueForBasicShape` 函数会将内部的 `BasicShapeCircle` 对象转换回类似 `circle(50px at 100px 100px)` 的 CSS 值表示。

* **HTML:** HTML 元素是 CSS 样式应用的对象。CSS 基础图形用于控制 HTML 元素的渲染和布局。

    * **举例：**  一个 `<div>` 元素应用了 `clip-path: circle(50%);` 样式，那么 `basic_shape_functions.cc` 中的代码负责解析这个 CSS 值，并将生成的圆形应用到该 `<div>` 元素的裁剪上，从而决定哪些部分可见。

* **JavaScript:** JavaScript 可以通过 CSSOM (CSS Object Model) 来访问和修改元素的 CSS 样式。当 JavaScript 操作涉及到包含基础图形的 CSS 属性时，这个文件中的功能也会被间接调用。

    * **举例：**
        * JavaScript 代码：`element.style.clipPath = 'ellipse(30% 50% at 50% 50%)';`
        * 当浏览器执行这段 JavaScript 代码时，会触发样式更新，`basic_shape_functions.cc` 中的 `BasicShapeForValue` 函数会被调用来解析新的 CSS 值并更新元素的裁剪路径。
        * JavaScript 代码：`getComputedStyle(element).clipPath;`
        * 当执行这段代码时，如果元素的 `clip-path` 是一个基础图形，`basic_shape_functions.cc` 中的 `ValueForBasicShape` 函数可能会被调用来将内部的图形表示转换回 CSS 字符串表示，以便 JavaScript 获取。

**逻辑推理、假设输入与输出:**

假设有以下 CSS 样式应用于一个元素：

```css
.shaped {
  clip-path: inset(10px 20px 30px 40px round 5px);
}
```

* **假设输入 (CSS 值):**  一个 `cssvalue::CSSBasicShapeInsetValue` 对象，包含了 top, right, bottom, left 的长度值以及 top-left, top-right, bottom-right, bottom-left 的 `CSSValuePair` 对象表示圆角半径。
* **`BasicShapeForValue` 的逻辑推理:**
    1. `BasicShapeForValue` 函数接收到 `CSSBasicShapeInsetValue` 对象。
    2. 它会分别调用 `ConvertToLength` 函数将 "10px", "20px", "30px", "40px" 转换为 Blink 内部的 `Length` 对象，分别赋值给 `BasicShapeInset` 对象的 `top`, `right`, `bottom`, `left` 属性。
    3. 它会调用 `ConvertToLengthSize` 函数将圆角半径的 `CSSValuePair` (例如表示 "5px" 的 `CSSPrimitiveValue`) 转换为 `LengthSize` 对象，并分别赋值给 `BasicShapeInset` 对象的 `topLeftRadius`, `topRightRadius` 等属性。
* **假设输出 (内部表示):** 一个 `BasicShapeInset` 对象，其属性如下：
    * `top`: `Length` 对象，值为 10px。
    * `right`: `Length` 对象，值为 20px。
    * `bottom`: `Length` 对象，值为 30px。
    * `left`: `Length` 对象，值为 40px。
    * `topLeftRadius`: `LengthSize` 对象，宽度和高度都为 5px。
    * `topRightRadius`: `LengthSize` 对象，宽度和高度都为 5px。
    * `bottomRightRadius`: `LengthSize` 对象，宽度和高度都为 5px。
    * `bottomLeftRadius`: `LengthSize` 对象，宽度和高度都为 5px。

**用户或编程常见的使用错误:**

1. **CSS 语法错误:** 用户在编写 CSS 时可能会犯语法错误，例如拼写错误、缺少单位、参数顺序错误等。
    * **举例：**  `clip-path: cicle(50px);` (拼写错误)，`clip-path: circle(50);` (缺少单位)。
    * **`basic_shape_functions.cc` 的处理:**  虽然这个文件不负责 CSS 解析，但如果解析器能容忍某些错误，或者需要对解析后的值进行进一步的验证，这里可能会遇到无效的 `CSSValue` 对象，导致 `BasicShapeForValue` 返回 `nullptr` 或产生未定义的行为。代码中的 `NOTREACHED()` 宏在某些情况下表明了对输入有效性的假设。

2. **使用了不支持的单位或关键字:**  某些基础图形的属性可能只支持特定的单位或关键字。
    * **举例：**  在 `ray()` 函数中使用了非角度单位的角度值。
    * **`basic_shape_functions.cc` 的处理:**  转换函数（例如 `ConvertToLength`）会根据支持的单位进行转换。如果遇到不支持的单位，转换可能会失败，导致创建不正确的 `BasicShape` 对象或抛出错误。

3. **逻辑错误导致生成无效的形状:**  即使语法正确，用户也可能因为逻辑错误而定义出无意义或无效的形状。
    * **举例：**  `clip-path: circle(0px);` (半径为 0 的圆)，`clip-path: polygon(0 0);` (少于三个顶点的多边形)。
    * **`basic_shape_functions.cc` 的处理:**  这个文件主要负责转换，对于图形的有效性验证可能在更上层的代码中进行。但是，如果转换过程中需要特定的参数数量或范围，这里可能会进行一些基本的检查。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在 HTML 文件中编写 CSS 样式，其中使用了基础图形函数。**
   ```html
   <div style="clip-path: circle(75px);">...</div>
   ```

2. **浏览器加载 HTML 文件并开始解析 CSS。**  渲染引擎的 CSS 解析器会解析这段 CSS 规则。

3. **当解析到 `clip-path: circle(75px);` 时，** CSS 解析器会创建一个表示 `circle()` 函数的 `CSSValue` 对象（可能是 `cssvalue::CSSBasicShapeCircleValue`）。

4. **在样式计算阶段，需要将这个 CSS 值转换为内部的图形表示。**  Blink 的样式解析器会调用 `basic_shape_functions.cc` 中的 `BasicShapeForValue` 函数，并将 `cssvalue::CSSBasicShapeCircleValue` 对象作为参数传递给它。

5. **`BasicShapeForValue` 函数会提取 `CSSBasicShapeCircleValue` 中的半径信息 "75px"，** 并调用 `ConvertToLength` 函数将其转换为 Blink 内部的 `Length` 对象。

6. **`BasicShapeForValue` 函数创建一个 `BasicShapeCircle` 对象，** 并将转换后的半径值设置到该对象的 `radius` 属性上。

7. **最终，这个 `BasicShapeCircle` 对象会被用于后续的渲染过程，** 例如确定元素的裁剪区域。

**调试线索:**

* **在 Chromium 的开发者工具中，查看元素的 "Styles" 面板，** 可以看到应用到元素的 `clip-path` 或 `shape-outside` 属性的计算值。如果计算值与预期不符，可能表明在 CSS 值到内部表示的转换过程中出现了问题。
* **在 Chromium 的源代码中设置断点，** 特别是在 `BasicShapeForValue` 函数内部，可以观察传递给函数的 `CSSValue` 对象的内容，以及函数创建的 `BasicShape` 对象的状态，从而了解转换过程是否正确。
* **检查与 `StyleResolverState` 相关的参数，** 因为它包含了样式解析的上下文信息，可能影响单位转换和值解析。
* **查看与 `CSSBasicShapeCircleValue`, `CSSBasicShapePolygonValue` 等 CSS 值类型相关的代码，** 了解 CSS 值是如何被表示和传递的。

总之，`basic_shape_functions.cc` 是 Blink 渲染引擎中一个关键的文件，它负责将 CSS 基础图形的文本表示转换为内部的、易于处理的图形对象，并在需要时执行反向转换，是实现 CSS 基础图形功能的核心组成部分。

### 提示词
```
这是目录为blink/renderer/core/css/basic_shape_functions.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Adobe Systems Incorporated. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/css/basic_shape_functions.h"

#include "base/memory/scoped_refptr.h"
#include "third_party/blink/renderer/core/css/css_basic_shape_values.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_path_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/core/css/css_ray_value.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/style/basic_shapes.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/style_ray.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

static StyleRay::RaySize KeywordToRaySize(CSSValueID id) {
  switch (id) {
    case CSSValueID::kClosestSide:
      return StyleRay::RaySize::kClosestSide;
    case CSSValueID::kClosestCorner:
      return StyleRay::RaySize::kClosestCorner;
    case CSSValueID::kFarthestSide:
      return StyleRay::RaySize::kFarthestSide;
    case CSSValueID::kFarthestCorner:
      return StyleRay::RaySize::kFarthestCorner;
    case CSSValueID::kSides:
      return StyleRay::RaySize::kSides;
    default:
      NOTREACHED();
  }
}

static CSSValueID RaySizeToKeyword(StyleRay::RaySize size) {
  switch (size) {
    case StyleRay::RaySize::kClosestSide:
      return CSSValueID::kClosestSide;
    case StyleRay::RaySize::kClosestCorner:
      return CSSValueID::kClosestCorner;
    case StyleRay::RaySize::kFarthestSide:
      return CSSValueID::kFarthestSide;
    case StyleRay::RaySize::kFarthestCorner:
      return CSSValueID::kFarthestCorner;
    case StyleRay::RaySize::kSides:
      return CSSValueID::kSides;
  }
  NOTREACHED();
}

static CSSValue* ValueForCenterCoordinate(
    const ComputedStyle& style,
    const BasicShapeCenterCoordinate& center,
    EBoxOrient orientation) {
  if (center.GetDirection() == BasicShapeCenterCoordinate::kTopLeft) {
    return CSSValue::Create(center.length(), style.EffectiveZoom());
  }

  CSSValueID keyword = orientation == EBoxOrient::kHorizontal
                           ? CSSValueID::kRight
                           : CSSValueID::kBottom;

  return MakeGarbageCollected<CSSValuePair>(
      CSSIdentifierValue::Create(keyword),
      CSSValue::Create(center.length(), style.EffectiveZoom()),
      CSSValuePair::kDropIdenticalValues);
}

static CSSValuePair* ValueForLengthSize(const LengthSize& length_size,
                                        const ComputedStyle& style) {
  return MakeGarbageCollected<CSSValuePair>(
      CSSValue::Create(length_size.Width(), style.EffectiveZoom()),
      CSSValue::Create(length_size.Height(), style.EffectiveZoom()),
      CSSValuePair::kKeepIdenticalValues);
}

static CSSValue* BasicShapeRadiusToCSSValue(const ComputedStyle& style,
                                            const BasicShapeRadius& radius) {
  switch (radius.GetType()) {
    case BasicShapeRadius::kValue:
      return CSSValue::Create(radius.Value(), style.EffectiveZoom());
    case BasicShapeRadius::kClosestSide:
      return CSSIdentifierValue::Create(CSSValueID::kClosestSide);
    case BasicShapeRadius::kFarthestSide:
      return CSSIdentifierValue::Create(CSSValueID::kFarthestSide);
  }

  NOTREACHED();
}

template <typename BasicShapeClass, typename CSSValueClass>
static void InitializeBorderRadius(BasicShapeClass* rect,
                                   const StyleResolverState& state,
                                   const CSSValueClass& rect_value) {
  rect->SetTopLeftRadius(
      ConvertToLengthSize(state, rect_value.TopLeftRadius()));
  rect->SetTopRightRadius(
      ConvertToLengthSize(state, rect_value.TopRightRadius()));
  rect->SetBottomRightRadius(
      ConvertToLengthSize(state, rect_value.BottomRightRadius()));
  rect->SetBottomLeftRadius(
      ConvertToLengthSize(state, rect_value.BottomLeftRadius()));
}

template <typename BasicShapeClass, typename CSSValueClass>
static void InitializeBorderRadius(CSSValueClass* css_value,
                                   const ComputedStyle& style,
                                   const BasicShapeClass* rect) {
  css_value->SetTopLeftRadius(ValueForLengthSize(rect->TopLeftRadius(), style));
  css_value->SetTopRightRadius(
      ValueForLengthSize(rect->TopRightRadius(), style));
  css_value->SetBottomRightRadius(
      ValueForLengthSize(rect->BottomRightRadius(), style));
  css_value->SetBottomLeftRadius(
      ValueForLengthSize(rect->BottomLeftRadius(), style));
}

CSSValue* ValueForBasicShape(const ComputedStyle& style,
                             const BasicShape* basic_shape) {
  switch (basic_shape->GetType()) {
    case BasicShape::kStyleRayType: {
      const StyleRay& ray = To<StyleRay>(*basic_shape);
      const CSSValue* center_x =
          ray.HasExplicitCenter()
              ? ValueForCenterCoordinate(style, ray.CenterX(),
                                         EBoxOrient::kHorizontal)
              : nullptr;
      const CSSValue* center_y =
          ray.HasExplicitCenter()
              ? ValueForCenterCoordinate(style, ray.CenterY(),
                                         EBoxOrient::kVertical)
              : nullptr;
      return MakeGarbageCollected<cssvalue::CSSRayValue>(
          *CSSNumericLiteralValue::Create(
              ray.Angle(), CSSPrimitiveValue::UnitType::kDegrees),
          *CSSIdentifierValue::Create(RaySizeToKeyword(ray.Size())),
          (ray.Contain() ? CSSIdentifierValue::Create(CSSValueID::kContain)
                         : nullptr),
          center_x, center_y);
    }

    case BasicShape::kStylePathType:
      return To<StylePath>(basic_shape)->ComputedCSSValue();

    case BasicShape::kBasicShapeCircleType: {
      const BasicShapeCircle* circle = To<BasicShapeCircle>(basic_shape);
      cssvalue::CSSBasicShapeCircleValue* circle_value =
          MakeGarbageCollected<cssvalue::CSSBasicShapeCircleValue>();

      if (circle->HasExplicitCenter()) {
        circle_value->SetCenterX(ValueForCenterCoordinate(
            style, circle->CenterX(), EBoxOrient::kHorizontal));
        circle_value->SetCenterY(ValueForCenterCoordinate(
            style, circle->CenterY(), EBoxOrient::kVertical));
      }
      circle_value->SetRadius(
          BasicShapeRadiusToCSSValue(style, circle->Radius()));
      return circle_value;
    }
    case BasicShape::kBasicShapeEllipseType: {
      const BasicShapeEllipse* ellipse = To<BasicShapeEllipse>(basic_shape);
      auto* ellipse_value =
          MakeGarbageCollected<cssvalue::CSSBasicShapeEllipseValue>();

      if (ellipse->HasExplicitCenter()) {
        ellipse_value->SetCenterX(ValueForCenterCoordinate(
            style, ellipse->CenterX(), EBoxOrient::kHorizontal));
        ellipse_value->SetCenterY(ValueForCenterCoordinate(
            style, ellipse->CenterY(), EBoxOrient::kVertical));
      }
      ellipse_value->SetRadiusX(
          BasicShapeRadiusToCSSValue(style, ellipse->RadiusX()));
      ellipse_value->SetRadiusY(
          BasicShapeRadiusToCSSValue(style, ellipse->RadiusY()));
      return ellipse_value;
    }
    case BasicShape::kBasicShapePolygonType: {
      const BasicShapePolygon* polygon = To<BasicShapePolygon>(basic_shape);
      auto* polygon_value =
          MakeGarbageCollected<cssvalue::CSSBasicShapePolygonValue>();

      polygon_value->SetWindRule(polygon->GetWindRule());
      const Vector<Length>& values = polygon->Values();
      for (unsigned i = 0; i < values.size(); i += 2) {
        polygon_value->AppendPoint(
            CSSPrimitiveValue::CreateFromLength(values.at(i),
                                                style.EffectiveZoom()),
            CSSPrimitiveValue::CreateFromLength(values.at(i + 1),
                                                style.EffectiveZoom()));
      }
      return polygon_value;
    }
    case BasicShape::kBasicShapeInsetType: {
      const BasicShapeInset* inset = To<BasicShapeInset>(basic_shape);
      cssvalue::CSSBasicShapeInsetValue* inset_value =
          MakeGarbageCollected<cssvalue::CSSBasicShapeInsetValue>();

      inset_value->SetTop(CSSPrimitiveValue::CreateFromLength(
          inset->Top(), style.EffectiveZoom()));
      inset_value->SetRight(CSSPrimitiveValue::CreateFromLength(
          inset->Right(), style.EffectiveZoom()));
      inset_value->SetBottom(CSSPrimitiveValue::CreateFromLength(
          inset->Bottom(), style.EffectiveZoom()));
      inset_value->SetLeft(CSSPrimitiveValue::CreateFromLength(
          inset->Left(), style.EffectiveZoom()));

      InitializeBorderRadius(inset_value, style, inset);
      return inset_value;
    }
    default:
      return nullptr;
  }
}

static Length ConvertToLength(const StyleResolverState& state,
                              const CSSPrimitiveValue* value) {
  if (!value) {
    return Length::Fixed(0);
  }
  return value->ConvertToLength(state.CssToLengthConversionData());
}

static LengthSize ConvertToLengthSize(const StyleResolverState& state,
                                      const CSSValuePair* value) {
  if (!value) {
    return LengthSize(Length::Fixed(0), Length::Fixed(0));
  }

  return LengthSize(
      ConvertToLength(state, &To<CSSPrimitiveValue>(value->First())),
      ConvertToLength(state, &To<CSSPrimitiveValue>(value->Second())));
}

static BasicShapeCenterCoordinate ConvertToCenterCoordinate(
    const StyleResolverState& state,
    const CSSValue* value) {
  BasicShapeCenterCoordinate::Direction direction;
  Length offset = Length::Fixed(0);

  CSSValueID keyword = CSSValueID::kTop;
  if (!value) {
    keyword = CSSValueID::kCenter;
  } else if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    keyword = identifier_value->GetValueID();
  } else if (auto* value_pair = DynamicTo<CSSValuePair>(value)) {
    keyword = To<CSSIdentifierValue>(value_pair->First()).GetValueID();
    offset =
        ConvertToLength(state, &To<CSSPrimitiveValue>(value_pair->Second()));
  } else {
    offset = ConvertToLength(state, To<CSSPrimitiveValue>(value));
  }

  switch (keyword) {
    case CSSValueID::kTop:
    case CSSValueID::kLeft:
      direction = BasicShapeCenterCoordinate::kTopLeft;
      break;
    case CSSValueID::kRight:
    case CSSValueID::kBottom:
      direction = BasicShapeCenterCoordinate::kBottomRight;
      break;
    case CSSValueID::kCenter:
      direction = BasicShapeCenterCoordinate::kTopLeft;
      offset = Length::Percent(50);
      break;
    default:
      NOTREACHED();
  }

  return BasicShapeCenterCoordinate(direction, offset);
}

static BasicShapeRadius CssValueToBasicShapeRadius(
    const StyleResolverState& state,
    const CSSValue* radius) {
  if (!radius) {
    return BasicShapeRadius(BasicShapeRadius::kClosestSide);
  }

  if (auto* radius_identifier_value = DynamicTo<CSSIdentifierValue>(radius)) {
    switch (radius_identifier_value->GetValueID()) {
      case CSSValueID::kClosestSide:
        return BasicShapeRadius(BasicShapeRadius::kClosestSide);
      case CSSValueID::kFarthestSide:
        return BasicShapeRadius(BasicShapeRadius::kFarthestSide);
      default:
        NOTREACHED();
    }
  }

  return BasicShapeRadius(
      ConvertToLength(state, To<CSSPrimitiveValue>(radius)));
}

scoped_refptr<BasicShape> BasicShapeForValue(
    const StyleResolverState& state,
    const CSSValue& basic_shape_value) {
  scoped_refptr<BasicShape> basic_shape;

  if (const auto* circle_value =
          DynamicTo<cssvalue::CSSBasicShapeCircleValue>(basic_shape_value)) {
    scoped_refptr<BasicShapeCircle> circle = BasicShapeCircle::Create();

    circle->SetCenterX(
        ConvertToCenterCoordinate(state, circle_value->CenterX()));
    circle->SetCenterY(
        ConvertToCenterCoordinate(state, circle_value->CenterY()));
    circle->SetRadius(
        CssValueToBasicShapeRadius(state, circle_value->Radius()));
    circle->SetHasExplicitCenter(circle_value->CenterX());

    basic_shape = std::move(circle);
  } else if (const auto* ellipse_value =
                 DynamicTo<cssvalue::CSSBasicShapeEllipseValue>(
                     basic_shape_value)) {
    scoped_refptr<BasicShapeEllipse> ellipse = BasicShapeEllipse::Create();

    ellipse->SetCenterX(
        ConvertToCenterCoordinate(state, ellipse_value->CenterX()));
    ellipse->SetCenterY(
        ConvertToCenterCoordinate(state, ellipse_value->CenterY()));
    ellipse->SetRadiusX(
        CssValueToBasicShapeRadius(state, ellipse_value->RadiusX()));
    ellipse->SetRadiusY(
        CssValueToBasicShapeRadius(state, ellipse_value->RadiusY()));
    ellipse->SetHasExplicitCenter(ellipse_value->CenterX());

    basic_shape = std::move(ellipse);
  } else if (const auto* polygon_value =
                 DynamicTo<cssvalue::CSSBasicShapePolygonValue>(
                     basic_shape_value)) {
    scoped_refptr<BasicShapePolygon> polygon = BasicShapePolygon::Create();

    polygon->SetWindRule(polygon_value->GetWindRule());
    const HeapVector<Member<CSSPrimitiveValue>>& values =
        polygon_value->Values();
    for (unsigned i = 0; i < values.size(); i += 2) {
      polygon->AppendPoint(ConvertToLength(state, values.at(i).Get()),
                           ConvertToLength(state, values.at(i + 1).Get()));
    }

    basic_shape = std::move(polygon);
  } else if (const auto* inset_value =
                 DynamicTo<cssvalue::CSSBasicShapeInsetValue>(
                     basic_shape_value)) {
    scoped_refptr<BasicShapeInset> rect = BasicShapeInset::Create();

    rect->SetTop(
        ConvertToLength(state, To<CSSPrimitiveValue>(inset_value->Top())));
    rect->SetRight(
        ConvertToLength(state, To<CSSPrimitiveValue>(inset_value->Right())));
    rect->SetBottom(
        ConvertToLength(state, To<CSSPrimitiveValue>(inset_value->Bottom())));
    rect->SetLeft(
        ConvertToLength(state, To<CSSPrimitiveValue>(inset_value->Left())));

    InitializeBorderRadius(rect.get(), state, *inset_value);
    basic_shape = std::move(rect);
  } else if (const auto* rect_value =
                 DynamicTo<cssvalue::CSSBasicShapeRectValue>(
                     basic_shape_value)) {
    scoped_refptr<BasicShapeInset> inset = BasicShapeInset::Create();

    // Spec: All <basic-shape-rect> functions compute to the equivalent
    // inset() function. NOTE: Given `rect(t r b l)`, the equivalent function
    // is `inset(t calc(100% - r) calc(100% - b) l)`.
    // See: https://drafts.csswg.org/css-shapes/#basic-shape-computed-values
    auto get_inset_length = [&](const CSSValue& edge,
                                bool is_right_or_bottom) -> Length {
      // Auto values coincide with the corresponding edge of the reference
      // box (https://drafts.csswg.org/css-shapes/#funcdef-basic-shape-rect),
      // so the inset of any auto value will be 0.
      if (auto* auto_value = DynamicTo<CSSIdentifierValue>(edge)) {
        DCHECK_EQ(auto_value->GetValueID(), CSSValueID::kAuto);
        return Length::Percent(0);
      }
      Length edge_length = ConvertToLength(state, &To<CSSPrimitiveValue>(edge));
      return is_right_or_bottom ? edge_length.SubtractFromOneHundredPercent()
                                : edge_length;
    };
    inset->SetTop(get_inset_length(*rect_value->Top(), false));
    inset->SetRight(get_inset_length(*rect_value->Right(), true));
    inset->SetBottom(get_inset_length(*rect_value->Bottom(), true));
    inset->SetLeft(get_inset_length(*rect_value->Left(), false));

    InitializeBorderRadius(inset.get(), state, *rect_value);
    basic_shape = std::move(inset);
  } else if (const auto* xywh_value =
                 DynamicTo<cssvalue::CSSBasicShapeXYWHValue>(
                     basic_shape_value)) {
    scoped_refptr<BasicShapeInset> inset = BasicShapeInset::Create();

    // Spec: All <basic-shape-rect> functions compute to the equivalent
    // inset() function. NOTE: Given `xywh(x y w h)`, the equivalent function
    // is `inset(y calc(100% - x - w) calc(100% - y - h) x)`.
    // See: https://drafts.csswg.org/css-shapes/#basic-shape-computed-values
    // and https://github.com/w3c/csswg-drafts/issues/9053
    inset->SetLeft(ConvertToLength(state, xywh_value->X()));
    // calc(100% - (x + w)) = calc(100% - x - w).
    inset->SetRight(inset->Left()
                        .Add(ConvertToLength(state, xywh_value->Width()))
                        .SubtractFromOneHundredPercent());
    inset->SetTop(ConvertToLength(state, xywh_value->Y()));
    // calc(100% - (y + h)) = calc(100% - y - h).
    inset->SetBottom(inset->Top()
                         .Add(ConvertToLength(state, xywh_value->Height()))
                         .SubtractFromOneHundredPercent());

    InitializeBorderRadius(inset.get(), state, *xywh_value);
    basic_shape = std::move(inset);
  } else if (const auto* ray_value =
                 DynamicTo<cssvalue::CSSRayValue>(basic_shape_value)) {
    float angle =
        ray_value->Angle().ComputeDegrees(state.CssToLengthConversionData());
    StyleRay::RaySize size = KeywordToRaySize(ray_value->Size().GetValueID());
    bool contain = !!ray_value->Contain();
    basic_shape =
        StyleRay::Create(angle, size, contain,
                         ConvertToCenterCoordinate(state, ray_value->CenterX()),
                         ConvertToCenterCoordinate(state, ray_value->CenterY()),
                         ray_value->CenterX());
  } else if (const auto* path_value =
                 DynamicTo<cssvalue::CSSPathValue>(basic_shape_value)) {
    basic_shape = path_value->GetStylePath();
  } else {
    NOTREACHED();
  }

  return basic_shape;
}

}  // namespace blink
```