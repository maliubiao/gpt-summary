Response:
Thinking Process:

1. **Understand the Goal:** The request asks for the functionality of the given C++ file, its relation to web technologies (HTML, CSS, JavaScript), examples, logical reasoning (input/output), and common usage errors.

2. **Identify the Core Function:** The file name `svg_layout_tree_as_text.cc` and the included headers (like `layout_tree_as_text.h`, `layout_svg_*.h`) strongly suggest this file is responsible for generating a textual representation of the SVG layout tree within the Blink rendering engine. The code itself confirms this by defining functions like `Write`, `WriteSVGContainer`, `WriteSVGResourceContainer`, etc., which take layout objects and write their properties to a `StringBuilder`.

3. **Break Down Functionality:**  Analyze the code to understand the specific tasks it performs:
    * **Traversal:** The `WriteChildren` function indicates it iterates through the layout tree.
    * **Property Extraction:** The various `WriteNameValuePair`, `WriteIfNotDefault`, and direct access to object properties (e.g., `object.ObjectBoundingBox()`, `style.Opacity()`) show it extracts data from layout objects.
    * **Formatting:**  The use of `StringBuilder`, `TextStreamSeparator`, and `WriteIndent` suggests it formats the output for readability.
    * **SVG Specifics:** The code handles SVG-specific layout objects (`LayoutSVGShape`, `LayoutSVGRoot`, etc.) and properties (like `stroke`, `fill`, `gradientUnits`, `markerUnits`). It also deals with SVG resources (gradients, patterns, filters, clip paths, markers).
    * **Style Handling:** It accesses and formats CSS properties relevant to SVG, like `opacity`, `transform`, `fill`, `stroke`, etc.
    * **Resource Linking:** It handles references to SVG resources using URLs and extracts the fragment identifier (ID).

4. **Relate to Web Technologies:**
    * **HTML:** SVG elements are embedded in HTML. This file deals with the *rendering* of those SVG elements, so it's directly related to how HTML structures are visually presented.
    * **CSS:** CSS styles SVG elements. This file extracts and displays relevant CSS properties applied to SVG elements.
    * **JavaScript:** While this file doesn't *execute* JavaScript, JavaScript can manipulate the DOM, including SVG elements and their attributes. Changes made by JavaScript will affect the layout tree, which this file visualizes.

5. **Provide Examples:**  Think of common SVG scenarios and how this file would represent them:
    * Basic shapes (rect, circle, path) and their attributes.
    * Styling with fill, stroke, opacity.
    * Use of gradients, patterns, filters, clip paths, and markers. Show how the resource IDs are linked.

6. **Consider Logical Reasoning (Input/Output):**  What does this file *do* given some input?
    * **Input:** A rendered SVG layout tree (data structures representing the calculated positions, sizes, and styles of SVG elements).
    * **Output:** A textual representation of that tree, showing the hierarchy, object types, positions, sizes, and relevant style attributes. Invent a simple example to illustrate this.

7. **Identify Potential Usage Errors:** Who uses this file, and how might they misuse it or misunderstand its output?
    * **Developers/Debuggers:** This is primarily a debugging tool. Common errors involve misinterpreting the output, especially with complex SVG structures or resource references. Highlight potential pitfalls like incorrect ID references or understanding the order of transformations.

8. **Structure the Answer:** Organize the information logically:
    * Start with a concise summary of the file's purpose.
    * Detail the key functionalities.
    * Explain the relationship to HTML, CSS, and JavaScript with examples.
    * Provide a clear input/output example demonstrating the logical reasoning.
    * Discuss potential usage errors with illustrative cases.

9. **Refine and Review:** Read through the answer to ensure clarity, accuracy, and completeness. Check for any jargon that needs explanation. Ensure the examples are easy to understand. Make sure the limitations and potential issues are clearly stated. For instance, emphasize that this is a *debugging* tool and not for general users.

By following these steps, I can generate a comprehensive and informative answer that addresses all aspects of the request.
这个文件 `blink/renderer/core/layout/svg/svg_layout_tree_as_text.cc` 的主要功能是**将 SVG 渲染树（Layout Tree）的结构和属性以文本形式输出，用于调试和诊断目的。**  它类似于一个 "SVG 布局树的打印机"，能够让你看到 Blink 引擎如何布局和渲染 SVG 内容的内部表示。

以下是它的具体功能点：

**1. 布局树的文本化表示:**
    * 它遍历 SVG 渲染树的各个节点（例如，`LayoutSVGRoot`, `LayoutSVGShape`, `LayoutSVGImage` 等）。
    * 对于每个节点，它会输出节点的类型、基本信息（如内存地址）、以及与布局相关的属性，例如位置 (`ObjectBoundingBox`) 和尺寸。

**2. 样式信息的输出:**
    * 它会提取并输出应用于 SVG 元素的 CSS 样式信息，特别是影响 SVG 渲染的属性，例如：
        * `transform`:  元素的变换矩阵。
        * `opacity`: 透明度。
        * `fill`: 填充颜色或图案。
        * `stroke`: 描边颜色或图案。
        * `stroke-width`: 描边宽度。
        * `stroke-dasharray`: 虚线模式。
        * `fill-rule`:  填充规则 (nonzero 或 evenodd)。
        * `clip-path`:  裁剪路径的引用。
        * `filter`:  滤镜效果的引用。
        * `marker-start`, `marker-mid`, `marker-end`:  标记的引用。

**3. SVG 特定属性的输出:**
    * 它会输出 SVG 元素特有的属性，例如：
        * 对于 `<rect>`: `x`, `y`, `width`, `height`。
        * 对于 `<line>`: `x1`, `y1`, `x2`, `y2`。
        * 对于 `<ellipse>` 和 `<circle>`: `cx`, `cy`, `rx`, `ry`, `r`。
        * 对于 `<polygon>` 和 `<polyline>`: `points` 属性的值。
        * 对于 `<path>`: `d` 属性的值（路径数据）。
        * 对于渐变 (`<linearGradient>`, `<radialGradient>`) 和图案 (`<pattern>`) 等资源，会输出它们的定义属性，例如渐变的方向、颜色停止点、图案的平铺方式等。

**4. SVG 资源引用的解析和输出:**
    * 当 SVG 元素引用了其他 SVG 资源（如渐变、图案、滤镜、裁剪路径、标记）时，它会尝试解析这些引用，并输出被引用资源的 ID 和类型。这有助于理解 SVG 元素之间的依赖关系。

**5. 滤镜效果的结构输出:**
    * 对于应用的 SVG 滤镜，它能够输出滤镜效果的内部结构，例如各个滤镜原语（feGaussianBlur, feColorMatrix 等）的连接方式。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件本身是 C++ 代码，是 Blink 渲染引擎的一部分，不直接与 JavaScript, HTML, 或 CSS 代码交互。但是，它的功能是服务于这些 web 技术的，因为它帮助开发者理解浏览器如何处理和渲染由这些技术描述的内容。

**HTML:**

* **关系:** HTML 用来组织文档结构，包括嵌入 SVG 内容。`svg_layout_tree_as_text.cc` 的作用是展现这些嵌入的 SVG 元素在渲染过程中是如何被布局的。
* **举例:**  假设有以下 HTML 代码：
  ```html
  <!DOCTYPE html>
  <html>
  <body>
    <svg width="100" height="100">
      <rect x="10" y="10" width="80" height="80" fill="red" />
    </svg>
  </body>
  </html>
  ```
  `svg_layout_tree_as_text.cc` 的输出可能会包含类似这样的信息：
  ```
  LayoutSVGRoot {svg}  [x=0 y=0 width=100 height=100]
    LayoutSVGShape {rect}  [x=10 y=10 width=80 height=80] [fill={ [type=SOLID] [color=rgba(255,0,0,1)] }]
  ```
  这显示了 `<svg>` 元素作为根节点，以及内部 `<rect>` 元素的布局位置、尺寸和填充颜色。

**CSS:**

* **关系:** CSS 用来控制 SVG 元素的样式。`svg_layout_tree_as_text.cc` 会显示由 CSS 应用的样式属性值，这对于调试样式问题非常有用。
* **举例:** 假设有以下 HTML 和 CSS：
  ```html
  <!DOCTYPE html>
  <html>
  <head>
    <style>
      .my-circle {
        fill: url(#myGradient);
        stroke: blue;
        stroke-width: 5;
      }
    </style>
  </head>
  <body>
    <svg width="100" height="100">
      <defs>
        <linearGradient id="myGradient" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%"   stop-color="red" />
          <stop offset="100%" stop-color="yellow" />
        </linearGradient>
      </defs>
      <circle class="my-circle" cx="50" cy="50" r="40" />
    </svg>
  </body>
  </html>
  ```
  `svg_layout_tree_as_text.cc` 的输出可能会包含类似这样的信息：
  ```
  LayoutSVGRoot {svg}  [x=0 y=0 width=100 height=100]
    LayoutSVGResourceContainer {defs}
      LayoutSVGResourceLinearGradient {linearGradient} [id="myGradient"] [gradientUnits=OBJECT-BOUNDING-BOX] [stops=( rgba(255,0,0,1)@0 rgba(255,255,0,1)@1 )] [start=(0,0) end=(1,0)]
    LayoutSVGShape {circle}  [cx=50 cy=50 r=40] [fill={ [type=LINEAR-GRADIENT] [id="myGradient"] }] [stroke={ [type=SOLID] [color=rgba(0,0,255,1)] }] [stroke width=5]
  ```
  这显示了 `<circle>` 元素使用了 ID 为 `myGradient` 的线性渐变填充，以及描边颜色和宽度。

**JavaScript:**

* **关系:** JavaScript 可以动态地修改 SVG DOM 结构和属性。这些修改会影响渲染树，而 `svg_layout_tree_as_text.cc` 可以用来观察这些修改对布局的影响。
* **举例:** 假设有以下 HTML 和 JavaScript：
  ```html
  <!DOCTYPE html>
  <html>
  <body>
    <svg id="mySVG" width="100" height="100">
      <rect id="myRect" x="10" y="10" width="80" height="80" fill="green" />
    </svg>
    <script>
      document.getElementById('myRect').setAttribute('x', 20);
    </script>
  </body>
  </html>
  ```
  在 JavaScript 执行后，`svg_layout_tree_as_text.cc` 的输出中，`LayoutSVGShape {rect}` 节点的 `x` 属性将会是 `20` 而不是初始的 `10`。

**逻辑推理的假设输入与输出:**

**假设输入:**  一个简单的 SVG 元素 `<circle cx="50" cy="50" r="30" fill="blue" />` 被添加到 DOM 并触发渲染。

**输出 (可能包含的部分):**
```
LayoutSVGRoot {svg}  [x=0 y=0 width=... height=...]
  LayoutSVGShape {circle}  [cx=50 cy=50 r=30] [fill={ [type=SOLID] [color=rgba(0,0,255,1)] }]
```
* **推理:**  渲染引擎会创建一个 `LayoutSVGShape` 对象来表示 `<circle>` 元素。  输出会显示其中心点坐标 (`cx`, `cy`)，半径 (`r`) 以及填充颜色 (`fill`)。 填充颜色会被解析为 RGBA 值。

**涉及用户或者编程常见的使用错误及举例说明:**

由于这个文件是内部的调试工具，用户通常不会直接“使用”它。  但是，开发者在使用 Blink 引擎进行开发或调试时，可能会遇到以下与理解其输出相关的问题：

1. **误解坐标系统:** SVG 有不同的坐标系统（用户空间、对象边界框等）。开发者可能会错误地理解输出中的坐标值是相对于哪个坐标系的。
   * **例子:**  一个元素使用了 `transform` 属性进行旋转和平移，其 `ObjectBoundingBox` 输出的坐标可能与元素在最终渲染时的屏幕坐标不同。开发者需要理解变换是如何应用的。

2. **忽略继承和层叠:**  SVG 属性可以通过 CSS 继承和层叠来确定最终值。输出可能只显示最终计算后的值，开发者需要结合 CSS 规则来理解这个值的来源。
   * **例子:**  一个元素的 `fill` 属性在 CSS 中被设置为 `currentColor`，而父元素的 `color` 属性被设置为红色。 输出中 `fill` 可能会显示为红色，但开发者需要理解这是通过继承得到的。

3. **不理解 SVG 资源引用:**  当输出中显示了对渐变、图案或滤镜的引用时，开发者可能没有理解这些资源是如何定义的，或者引用的资源 ID 是否正确。
   * **例子:**  一个元素的 `fill` 属性设置为 `url(#myGradient)`，但 `#myGradient`  在 SVG 中没有定义，或者定义有误。输出会显示引用了 `myGradient`，但开发者需要去检查资源的定义。

4. **混淆布局树和 DOM 树:**  布局树是渲染引擎对 DOM 树的优化表示，并不完全一一对应。开发者可能会假设布局树的结构和 DOM 树完全一致，但某些 DOM 节点可能不会生成布局对象。
   * **例子:**  一些仅用于定义资源的 SVG 元素（如 `<defs>`）可能不会直接对应布局对象，或者其布局对象可能不直接包含其子元素的布局对象。

**总结:**

`blink/renderer/core/layout/svg/svg_layout_tree_as_text.cc` 是一个关键的内部调试工具，用于生成 SVG 布局树的文本表示。它帮助开发者理解 Blink 引擎如何处理和渲染 SVG 内容，以及 CSS 样式和 SVG 属性如何影响布局。虽然用户不会直接使用它，但理解其输出对于使用 Blink 引擎进行开发和调试至关重要。

### 提示词
```
这是目录为blink/renderer/core/layout/svg/svg_layout_tree_as_text.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2007, 2009 Apple Inc. All rights reserved.
 *           (C) 2005 Rob Buis <buis@kde.org>
 *           (C) 2006 Alexander Kellett <lypanov@kde.org>
 * Copyright (C) Research In Motion Limited 2010. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/layout/svg/svg_layout_tree_as_text.h"

#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/layout/layout_tree_as_text.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_image.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_clipper.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_filter.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_linear_gradient.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_marker.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_masker.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_pattern.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_radial_gradient.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_shape.h"
#include "third_party/blink/renderer/core/layout/svg/svg_layout_support.h"
#include "third_party/blink/renderer/core/layout/svg/svg_resources.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/style/reference_clip_path_operation.h"
#include "third_party/blink/renderer/core/style/style_svg_resource.h"
#include "third_party/blink/renderer/core/svg/graphics/filters/svg_filter_builder.h"
#include "third_party/blink/renderer/core/svg/linear_gradient_attributes.h"
#include "third_party/blink/renderer/core/svg/pattern_attributes.h"
#include "third_party/blink/renderer/core/svg/radial_gradient_attributes.h"
#include "third_party/blink/renderer/core/svg/svg_animated_angle.h"
#include "third_party/blink/renderer/core/svg/svg_animated_length.h"
#include "third_party/blink/renderer/core/svg/svg_animated_point_list.h"
#include "third_party/blink/renderer/core/svg/svg_circle_element.h"
#include "third_party/blink/renderer/core/svg/svg_ellipse_element.h"
#include "third_party/blink/renderer/core/svg/svg_enumeration_map.h"
#include "third_party/blink/renderer/core/svg/svg_filter_element.h"
#include "third_party/blink/renderer/core/svg/svg_length_context.h"
#include "third_party/blink/renderer/core/svg/svg_length_functions.h"
#include "third_party/blink/renderer/core/svg/svg_line_element.h"
#include "third_party/blink/renderer/core/svg/svg_linear_gradient_element.h"
#include "third_party/blink/renderer/core/svg/svg_path_element.h"
#include "third_party/blink/renderer/core/svg/svg_path_utilities.h"
#include "third_party/blink/renderer/core/svg/svg_pattern_element.h"
#include "third_party/blink/renderer/core/svg/svg_point_list.h"
#include "third_party/blink/renderer/core/svg/svg_poly_element.h"
#include "third_party/blink/renderer/core/svg/svg_radial_gradient_element.h"
#include "third_party/blink/renderer/core/svg/svg_rect_element.h"
#include "third_party/blink/renderer/platform/graphics/dash_array.h"
#include "third_party/blink/renderer/platform/graphics/filters/filter.h"
#include "third_party/blink/renderer/platform/graphics/filters/source_graphic.h"
#include "third_party/blink/renderer/platform/graphics/graphics_types.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

/** class + iomanip to help streaming list separators, i.e. ", " in string "a,
 * b, c, d"
 * Can be used in cases where you don't know which item in the list is the first
 * one to be printed, but still want to avoid strings like ", b, c".
 */
class TextStreamSeparator {
 public:
  TextStreamSeparator(const String& s)
      : separator_(s), need_to_separate_(false) {}

 private:
  friend StringBuilder& operator<<(StringBuilder&, TextStreamSeparator&);

  String separator_;
  bool need_to_separate_;
};

StringBuilder& operator<<(StringBuilder& ts, TextStreamSeparator& sep) {
  if (sep.need_to_separate_)
    ts << sep.separator_;
  else
    sep.need_to_separate_ = true;
  return ts;
}

template <typename ValueType>
static void WriteNameValuePair(StringBuilder& ts,
                               const char* name,
                               const ValueType& value) {
  ts << " [" << name << "=" << value << "]";
}

static void WriteSVGResourceIfNotNull(StringBuilder& ts,
                                      const char* name,
                                      const StyleSVGResource* value,
                                      TreeScope& tree_scope) {
  if (!value)
    return;
  AtomicString id = SVGURIReference::FragmentIdentifierFromIRIString(
      value->Url(), tree_scope);
  WriteNameValuePair(ts, name, id);
}

template <typename ValueType>
static void WriteNameAndQuotedValue(StringBuilder& ts,
                                    const char* name,
                                    ValueType value) {
  ts << " [" << name << "=\"" << value << "\"]";
}

template <typename ValueType>
static void WriteIfNotDefault(StringBuilder& ts,
                              const char* name,
                              ValueType value,
                              ValueType default_value) {
  if (value != default_value)
    WriteNameValuePair(ts, name, value);
}

StringBuilder& operator<<(StringBuilder& ts, const AffineTransform& transform) {
  if (transform.IsIdentity()) {
    ts << "identity";
  } else {
    ts << "{m=((" << transform.A() << "," << transform.B() << ")("
       << transform.C() << "," << transform.D() << ")) t=(" << transform.E()
       << "," << transform.F() << ")}";
  }

  return ts;
}

static StringBuilder& operator<<(StringBuilder& ts, const WindRule rule) {
  switch (rule) {
    case RULE_NONZERO:
      ts << "NON-ZERO";
      break;
    case RULE_EVENODD:
      ts << "EVEN-ODD";
      break;
  }

  return ts;
}

static StringBuilder& operator<<(StringBuilder& ts,
                                 const SVGUnitTypes::SVGUnitType& unit_type) {
  ts << GetEnumerationMap<SVGUnitTypes::SVGUnitType>().NameFromValue(unit_type);
  return ts;
}

static StringBuilder& operator<<(StringBuilder& ts,
                                 const SVGMarkerUnitsType& marker_unit) {
  ts << GetEnumerationMap<SVGMarkerUnitsType>().NameFromValue(marker_unit);
  return ts;
}

static StringBuilder& operator<<(StringBuilder& ts,
                                 const SVGMarkerOrientType& orient_type) {
  ts << GetEnumerationMap<SVGMarkerOrientType>().NameFromValue(orient_type);
  return ts;
}

// FIXME: Maybe this should be in platform/graphics/graphics_types.cc
static StringBuilder& operator<<(StringBuilder& ts, LineCap style) {
  switch (style) {
    case kButtCap:
      ts << "BUTT";
      break;
    case kRoundCap:
      ts << "ROUND";
      break;
    case kSquareCap:
      ts << "SQUARE";
      break;
  }
  return ts;
}

// FIXME: Maybe this should be in platform/graphics/graphics_types.cc
static StringBuilder& operator<<(StringBuilder& ts, LineJoin style) {
  switch (style) {
    case kMiterJoin:
      ts << "MITER";
      break;
    case kRoundJoin:
      ts << "ROUND";
      break;
    case kBevelJoin:
      ts << "BEVEL";
      break;
  }
  return ts;
}

static StringBuilder& operator<<(StringBuilder& ts,
                                 const SVGSpreadMethodType& type) {
  auto* name = GetEnumerationMap<SVGSpreadMethodType>().NameFromValue(type);
  ts << String(name).UpperASCII();
  return ts;
}

static void WriteSVGPaintingResource(StringBuilder& ts,
                                     const SVGResource& resource) {
  const LayoutSVGResourceContainer* container =
      resource.ResourceContainerNoCycleCheck();
  DCHECK(container);
  switch (container->ResourceType()) {
    case kPatternResourceType:
      ts << "[type=PATTERN]";
      break;
    case kLinearGradientResourceType:
      ts << "[type=LINEAR-GRADIENT]";
      break;
    case kRadialGradientResourceType:
      ts << "[type=RADIAL-GRADIENT]";
      break;
    default:
      NOTREACHED();
  }
  ts << " [id=\"" << resource.Target()->GetIdAttribute() << "\"]";
}

static bool WriteSVGPaint(StringBuilder& ts,
                          const LayoutObject& object,
                          const SVGPaint& paint,
                          const Longhand& property,
                          const char* paint_name) {
  TextStreamSeparator s(" ");
  const ComputedStyle& style = object.StyleRef();
  if (const StyleSVGResource* resource = paint.Resource()) {
    const SVGResource* paint_resource = resource->Resource();
    SVGResourceClient* client = SVGResources::GetClient(object);
    if (GetSVGResourceAsType<LayoutSVGResourcePaintServer>(*client,
                                                           paint_resource)) {
      ts << " [" << paint_name << "={" << s;
      WriteSVGPaintingResource(ts, *paint_resource);
      return true;
    }
  }
  if (paint.HasColor()) {
    Color color = style.VisitedDependentColor(property);
    ts << " [" << paint_name << "={" << s;
    ts << "[type=SOLID] [color=" << color << "]";
    return true;
  }
  if (paint.type == SVGPaintType::kContextFill) {
    ts << " [" << paint_name << "={" << s;
    ts << "[type=CONTEXT-FILL]";
    return true;
  }
  if (paint.type == SVGPaintType::kContextStroke) {
    ts << " [" << paint_name << "={" << s;
    ts << "[type=CONTEXT-STROKE]";
    return true;
  }
  return false;
}

static void WriteStyle(StringBuilder& ts, const LayoutObject& object) {
  const ComputedStyle& style = object.StyleRef();

  if (!object.LocalSVGTransform().IsIdentity())
    WriteNameValuePair(ts, "transform", object.LocalSVGTransform());
  WriteIfNotDefault(
      ts, "image rendering", static_cast<int>(style.ImageRendering()),
      static_cast<int>(ComputedStyleInitialValues::InitialImageRendering()));
  WriteIfNotDefault(ts, "opacity", style.Opacity(),
                    ComputedStyleInitialValues::InitialOpacity());
  if (object.IsSVGShape()) {
    if (WriteSVGPaint(ts, object, style.StrokePaint(), GetCSSPropertyStroke(),
                      "stroke")) {
      const SVGViewportResolver viewport_resolver(object);
      double dash_offset =
          ValueForLength(style.StrokeDashOffset(), viewport_resolver, style);
      double stroke_width =
          ValueForLength(style.StrokeWidth(), viewport_resolver);
      DashArray dash_array = SVGLayoutSupport::ResolveSVGDashArray(
          *style.StrokeDashArray(), style, viewport_resolver);

      WriteIfNotDefault(ts, "opacity", style.StrokeOpacity(), 1.0f);
      WriteIfNotDefault(ts, "stroke width", stroke_width, 1.0);
      WriteIfNotDefault(ts, "miter limit", style.StrokeMiterLimit(), 4.0f);
      WriteIfNotDefault(ts, "line cap", style.CapStyle(), kButtCap);
      WriteIfNotDefault(ts, "line join", style.JoinStyle(), kMiterJoin);
      WriteIfNotDefault(ts, "dash offset", dash_offset, 0.0);
      if (!dash_array.empty())
        WriteNameValuePair(ts, "dash array", dash_array);

      ts << "}]";
    }

    if (WriteSVGPaint(ts, object, style.FillPaint(), GetCSSPropertyFill(),
                      "fill")) {
      WriteIfNotDefault(ts, "opacity", style.FillOpacity(), 1.0f);
      WriteIfNotDefault(ts, "fill rule", style.FillRule(), RULE_NONZERO);
      ts << "}]";
    }
    WriteIfNotDefault(ts, "clip rule", style.ClipRule(), RULE_NONZERO);
  }

  TreeScope& tree_scope = object.GetDocument();
  WriteSVGResourceIfNotNull(ts, "start marker", style.MarkerStartResource(),
                            tree_scope);
  WriteSVGResourceIfNotNull(ts, "middle marker", style.MarkerMidResource(),
                            tree_scope);
  WriteSVGResourceIfNotNull(ts, "end marker", style.MarkerEndResource(),
                            tree_scope);
}

static StringBuilder& WritePositionAndStyle(StringBuilder& ts,
                                            const LayoutObject& object) {
  ts << " " << object.ObjectBoundingBox();
  WriteStyle(ts, object);
  return ts;
}

static StringBuilder& operator<<(StringBuilder& ts,
                                 const LayoutSVGShape& shape) {
  WritePositionAndStyle(ts, shape);

  SVGElement* svg_element = shape.GetElement();
  DCHECK(svg_element);
  const SVGViewportResolver viewport_resolver(shape);
  const ComputedStyle& style = shape.StyleRef();

  if (IsA<SVGRectElement>(*svg_element)) {
    WriteNameValuePair(ts, "x",
                       ValueForLength(style.X(), viewport_resolver, style,
                                      SVGLengthMode::kWidth));
    WriteNameValuePair(ts, "y",
                       ValueForLength(style.Y(), viewport_resolver, style,
                                      SVGLengthMode::kHeight));
    WriteNameValuePair(ts, "width",
                       ValueForLength(style.Width(), viewport_resolver, style,
                                      SVGLengthMode::kWidth));
    WriteNameValuePair(ts, "height",
                       ValueForLength(style.Height(), viewport_resolver, style,
                                      SVGLengthMode::kHeight));
  } else if (auto* element = DynamicTo<SVGLineElement>(*svg_element)) {
    const SVGLengthContext length_context(svg_element);
    WriteNameValuePair(ts, "x1",
                       element->x1()->CurrentValue()->Value(length_context));
    WriteNameValuePair(ts, "y1",
                       element->y1()->CurrentValue()->Value(length_context));
    WriteNameValuePair(ts, "x2",
                       element->x2()->CurrentValue()->Value(length_context));
    WriteNameValuePair(ts, "y2",
                       element->y2()->CurrentValue()->Value(length_context));
  } else if (IsA<SVGEllipseElement>(*svg_element)) {
    WriteNameValuePair(ts, "cx",
                       ValueForLength(style.Cx(), viewport_resolver, style,
                                      SVGLengthMode::kWidth));
    WriteNameValuePair(ts, "cy",
                       ValueForLength(style.Cy(), viewport_resolver, style,
                                      SVGLengthMode::kHeight));
    WriteNameValuePair(ts, "rx",
                       ValueForLength(style.Rx(), viewport_resolver, style,
                                      SVGLengthMode::kWidth));
    WriteNameValuePair(ts, "ry",
                       ValueForLength(style.Ry(), viewport_resolver, style,
                                      SVGLengthMode::kHeight));
  } else if (IsA<SVGCircleElement>(*svg_element)) {
    WriteNameValuePair(ts, "cx",
                       ValueForLength(style.Cx(), viewport_resolver, style,
                                      SVGLengthMode::kWidth));
    WriteNameValuePair(ts, "cy",
                       ValueForLength(style.Cy(), viewport_resolver, style,
                                      SVGLengthMode::kHeight));
    WriteNameValuePair(ts, "r",
                       ValueForLength(style.R(), viewport_resolver, style,
                                      SVGLengthMode::kOther));
  } else if (auto* svg_poly_element = DynamicTo<SVGPolyElement>(svg_element)) {
    WriteNameAndQuotedValue(
        ts, "points",
        svg_poly_element->Points()->CurrentValue()->ValueAsString());
  } else if (IsA<SVGPathElement>(*svg_element)) {
    const StylePath& path = style.D() ? *style.D() : *StylePath::EmptyPath();
    WriteNameAndQuotedValue(
        ts, "data",
        BuildStringFromByteStream(path.ByteStream(), kNoTransformation));
  } else {
    NOTREACHED();
  }
  return ts;
}

static StringBuilder& operator<<(StringBuilder& ts, const LayoutSVGRoot& root) {
  ts << " " << PhysicalRect(root.PhysicalLocation(), root.Size());
  WriteStyle(ts, root);
  return ts;
}

static void WriteStandardPrefix(StringBuilder& ts,
                                const LayoutObject& object,
                                wtf_size_t indent) {
  WriteIndent(ts, indent);
  ts << object.DecoratedName();

  if (object.GetNode())
    ts << " {" << object.GetNode()->nodeName() << "}";
}

static void WriteChildren(StringBuilder& ts,
                          const LayoutObject& object,
                          wtf_size_t indent) {
  for (LayoutObject* child = object.SlowFirstChild(); child;
       child = child->NextSibling())
    Write(ts, *child, indent + 1);
}

static inline void WriteCommonGradientProperties(
    StringBuilder& ts,
    const GradientAttributes& attrs) {
  WriteNameValuePair(ts, "gradientUnits", attrs.GradientUnits());

  if (attrs.SpreadMethod() != kSVGSpreadMethodPad)
    ts << " [spreadMethod=" << attrs.SpreadMethod() << "]";

  if (!attrs.GradientTransform().IsIdentity())
    ts << " [gradientTransform=" << attrs.GradientTransform() << "]";

  if (attrs.HasStops()) {
    ts << " [stops=( ";
    for (const auto& stop : attrs.Stops())
      ts << stop.color << "@" << stop.stop << " ";
    ts << ")]";
  }
}

void WriteSVGResourceContainer(StringBuilder& ts,
                               const LayoutObject& object,
                               wtf_size_t indent) {
  WriteStandardPrefix(ts, object, indent);

  auto* element = To<Element>(object.GetNode());
  const AtomicString& id = element->GetIdAttribute();
  WriteNameAndQuotedValue(ts, "id", id);

  auto* resource =
      To<LayoutSVGResourceContainer>(const_cast<LayoutObject*>(&object));
  DCHECK(resource);

  if (resource->ResourceType() == kMaskerResourceType) {
    auto* masker = To<LayoutSVGResourceMasker>(resource);
    WriteNameValuePair(ts, "maskUnits", masker->MaskUnits());
    WriteNameValuePair(ts, "maskContentUnits", masker->MaskContentUnits());
    ts << "\n";
  } else if (resource->ResourceType() == kFilterResourceType) {
    auto* filter = To<LayoutSVGResourceFilter>(resource);
    WriteNameValuePair(ts, "filterUnits", filter->FilterUnits());
    WriteNameValuePair(ts, "primitiveUnits", filter->PrimitiveUnits());
    ts << "\n";
    // Creating a placeholder filter which is passed to the builder.
    gfx::RectF dummy_rect;
    auto* dummy_filter = MakeGarbageCollected<Filter>(dummy_rect, dummy_rect, 1,
                                                      Filter::kBoundingBox);
    SVGFilterBuilder builder(dummy_filter->GetSourceGraphic());
    builder.BuildGraph(dummy_filter,
                       To<SVGFilterElement>(*filter->GetElement()), dummy_rect);
    if (FilterEffect* last_effect = builder.LastEffect())
      last_effect->ExternalRepresentation(ts, indent + 1);
  } else if (resource->ResourceType() == kClipperResourceType) {
    WriteNameValuePair(ts, "clipPathUnits",
                       To<LayoutSVGResourceClipper>(resource)->ClipPathUnits());
    ts << "\n";
  } else if (resource->ResourceType() == kMarkerResourceType) {
    auto* marker = To<LayoutSVGResourceMarker>(resource);
    WriteNameValuePair(ts, "markerUnits", marker->MarkerUnits());
    ts << " [ref at " << marker->ReferencePoint() << "]";
    ts << " [angle=";
    if (marker->OrientType() != kSVGMarkerOrientAngle)
      ts << marker->OrientType() << "]\n";
    else
      ts << marker->Angle() << "]\n";
  } else if (resource->ResourceType() == kPatternResourceType) {
    LayoutSVGResourcePattern* pattern =
        static_cast<LayoutSVGResourcePattern*>(resource);

    // Dump final results that are used for layout. No use in asking
    // SVGPatternElement for its patternUnits(), as it may link to other
    // patterns using xlink:href, we need to build the full inheritance chain,
    // aka. collectPatternProperties()
    PatternAttributes attributes = To<SVGPatternElement>(*pattern->GetElement())
                                       .CollectPatternAttributes();

    WriteNameValuePair(ts, "patternUnits", attributes.PatternUnits());
    WriteNameValuePair(ts, "patternContentUnits",
                       attributes.PatternContentUnits());

    AffineTransform transform = attributes.PatternTransform();
    if (!transform.IsIdentity())
      ts << " [patternTransform=" << transform << "]";
    ts << "\n";
  } else if (resource->ResourceType() == kLinearGradientResourceType) {
    LayoutSVGResourceLinearGradient* gradient =
        static_cast<LayoutSVGResourceLinearGradient*>(resource);

    // Dump final results that are used for layout. No use in asking
    // SVGGradientElement for its gradientUnits(), as it may link to other
    // gradients using xlink:href, we need to build the full inheritance chain,
    // aka. collectGradientProperties()
    LinearGradientAttributes attributes =
        To<SVGLinearGradientElement>(*gradient->GetElement())
            .CollectGradientAttributes();
    WriteCommonGradientProperties(ts, attributes);

    ts << " [start=" << gradient->StartPoint(attributes)
       << "] [end=" << gradient->EndPoint(attributes) << "]\n";
  } else if (resource->ResourceType() == kRadialGradientResourceType) {
    auto* gradient = To<LayoutSVGResourceRadialGradient>(resource);

    // Dump final results that are used for layout. No use in asking
    // SVGGradientElement for its gradientUnits(), as it may link to other
    // gradients using xlink:href, we need to build the full inheritance chain,
    // aka. collectGradientProperties()
    RadialGradientAttributes attributes =
        To<SVGRadialGradientElement>(*gradient->GetElement())
            .CollectGradientAttributes();
    WriteCommonGradientProperties(ts, attributes);

    gfx::PointF focal_point = gradient->FocalPoint(attributes);
    gfx::PointF center_point = gradient->CenterPoint(attributes);
    float radius = gradient->Radius(attributes);
    float focal_radius = gradient->FocalRadius(attributes);

    ts << " [center=" << center_point << "] [focal=" << focal_point
       << "] [radius=" << radius << "] [focalRadius=" << focal_radius << "]\n";
  } else {
    ts << "\n";
  }
  WriteChildren(ts, object, indent);
}

void WriteSVGContainer(StringBuilder& ts,
                       const LayoutObject& container,
                       wtf_size_t indent) {
  WriteStandardPrefix(ts, container, indent);
  WritePositionAndStyle(ts, container);
  ts << "\n";
  WriteResources(ts, container, indent);
  WriteChildren(ts, container, indent);
}

void Write(StringBuilder& ts, const LayoutSVGRoot& root, wtf_size_t indent) {
  WriteStandardPrefix(ts, root, indent);
  ts << root << "\n";
  WriteChildren(ts, root, indent);
}

void WriteSVGInline(StringBuilder& ts,
                    const LayoutSVGInline& text,
                    wtf_size_t indent) {
  WriteStandardPrefix(ts, text, indent);
  WritePositionAndStyle(ts, text);
  ts << "\n";
  WriteResources(ts, text, indent);
  WriteChildren(ts, text, indent);
}

void WriteSVGInlineText(StringBuilder& ts,
                        const LayoutSVGInlineText& text,
                        wtf_size_t indent) {
  WriteStandardPrefix(ts, text, indent);
  WritePositionAndStyle(ts, text);
  ts << "\n";
}

void WriteSVGImage(StringBuilder& ts,
                   const LayoutSVGImage& image,
                   wtf_size_t indent) {
  WriteStandardPrefix(ts, image, indent);
  WritePositionAndStyle(ts, image);
  ts << "\n";
  WriteResources(ts, image, indent);
}

void Write(StringBuilder& ts, const LayoutSVGShape& shape, wtf_size_t indent) {
  WriteStandardPrefix(ts, shape, indent);
  ts << shape << "\n";
  WriteResources(ts, shape, indent);
}

// Get the LayoutSVGResourceFilter from the 'filter' property iff the 'filter'
// is a single url(...) reference.
static LayoutSVGResourceFilter* GetFilterResourceForSVG(
    SVGResourceClient& client,
    const ComputedStyle& style) {
  if (!style.HasFilter())
    return nullptr;
  const FilterOperations& operations = style.Filter();
  if (operations.size() != 1)
    return nullptr;
  const auto* reference_filter =
      DynamicTo<ReferenceFilterOperation>(*operations.at(0));
  if (!reference_filter)
    return nullptr;
  return GetSVGResourceAsType<LayoutSVGResourceFilter>(
      client, reference_filter->Resource());
}

static void WriteSVGResourceReferencePrefix(
    StringBuilder& ts,
    const char* resource_name,
    const LayoutSVGResourceContainer* resource_object,
    const AtomicString& url,
    const TreeScope& tree_scope,
    wtf_size_t indent) {
  AtomicString id =
      SVGURIReference::FragmentIdentifierFromIRIString(url, tree_scope);
  WriteIndent(ts, indent);
  ts << " ";
  WriteNameAndQuotedValue(ts, resource_name, id);
  ts << " ";
  WriteStandardPrefix(ts, *resource_object, 0);
}

void WriteResources(StringBuilder& ts,
                    const LayoutObject& object,
                    wtf_size_t indent) {
  const gfx::RectF reference_box = object.ObjectBoundingBox();
  const ComputedStyle& style = object.StyleRef();
  TreeScope& tree_scope = object.GetDocument();
  SVGResourceClient* client = SVGResources::GetClient(object);
  if (!client)
    return;
  if (const ClipPathOperation* clip_path = style.ClipPath()) {
    if (LayoutSVGResourceClipper* clipper =
            GetSVGResourceAsType(*client, clip_path)) {
      DCHECK_EQ(clip_path->GetType(), ClipPathOperation::kReference);
      const auto& clip_path_reference =
          To<ReferenceClipPathOperation>(*clip_path);
      WriteSVGResourceReferencePrefix(ts, "clipPath", clipper,
                                      clip_path_reference.Url(), tree_scope,
                                      indent);
      ts << " " << clipper->ResourceBoundingBox(reference_box) << "\n";
    }
  }
  // TODO(fs): Only handles the single url(...) case. Do we care?
  if (LayoutSVGResourceFilter* filter =
          GetFilterResourceForSVG(*client, style)) {
    DCHECK(style.HasFilter());
    DCHECK_EQ(style.Filter().size(), 1u);
    const FilterOperation& filter_operation = *style.Filter().at(0);
    DCHECK_EQ(filter_operation.GetType(),
              FilterOperation::OperationType::kReference);
    const auto& reference_filter_operation =
        To<ReferenceFilterOperation>(filter_operation);
    WriteSVGResourceReferencePrefix(ts, "filter", filter,
                                    reference_filter_operation.Url(),
                                    tree_scope, indent);
    ts << " " << filter->ResourceBoundingBox(reference_box) << "\n";
  }
}

}  // namespace blink
```