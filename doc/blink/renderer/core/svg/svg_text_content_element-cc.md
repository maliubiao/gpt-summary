Response:
Let's break down the thought process for analyzing the `SVGTextContentElement.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific C++ file within the Chromium Blink rendering engine. We also need to identify its relationships with web technologies (HTML, CSS, JavaScript), potential user errors, and debugging strategies.

2. **Initial Code Scan (Keywords and Structure):**  A quick skim of the code reveals key terms: `SVGTextContentElement`, `SVG`, `textLength`, `lengthAdjust`, `getNumberOfChars`, `getComputedTextLength`, `getSubStringLength`, `getStartPositionOfChar`, `getEndPositionOfChar`, `getExtentOfChar`, `getRotationOfChar`, `getCharNumAtPosition`, `selectSubString`. These immediately suggest this file deals with the rendering and manipulation of text within SVG elements. The presence of `ExceptionState` hints at error handling. The `#include` directives at the top tell us about dependencies on other Blink components (CSS, Editing, Frame, Layout, SVG).

3. **Identify Core Responsibilities:** Based on the initial scan, we can infer the following core responsibilities:
    * **Representing SVG Text:**  This class likely represents the underlying implementation for SVG text elements (like `<text>`, `<tspan>`, etc.).
    * **Text Measurement:**  Functions like `getComputedTextLength`, `getSubStringLength`, `getExtentOfChar` clearly relate to measuring the dimensions and positions of text.
    * **Text Manipulation:** Functions like `selectSubString` indicate interaction with text selection.
    * **Attribute Handling:** The presence of `SVGAnimatedTextLength` and `SVGAnimatedEnumeration` suggests handling of SVG attributes specific to text elements, such as `textLength` and `lengthAdjust`.
    * **Interaction with Layout:** The mentions of `LayoutSVGText` and `SvgTextQuery` indicate interaction with the layout engine to determine the visual representation of the text.
    * **JavaScript API:** The `getNumberOfChars`, `getComputedTextLength`, etc., methods are likely exposed to JavaScript, allowing web developers to interact with SVG text properties.

4. **Delve into Key Methods:** Now, we need to examine the details of the key methods identified earlier.

    * **`getNumberOfChars()`:**  Fetches the number of characters in the SVG text element. The `UpdateStyleAndLayoutForNode` call is important – it ensures the layout is up-to-date before querying the text. The conditional check `IsNGTextOrInline` indicates different rendering paths for SVG text.
    * **`getComputedTextLength()`:** Calculates the rendered length of the entire text. It also uses `UpdateStyleAndLayoutForNode`. The `SVGAnimatedTextLength` class's special handling here (returning this computed value when `textLength` isn't explicitly set) is a key detail.
    * **`getSubStringLength()`:** Calculates the length of a portion of the text. It includes error handling (`IndexSizeError`).
    * **`getStartPositionOfChar()`, `getEndPositionOfChar()`, `getExtentOfChar()`, `getRotationOfChar()`:** These methods retrieve geometric information (position, bounding box, rotation) about individual characters. They also perform bounds checking.
    * **`getCharNumAtPosition()`:**  Performs the reverse operation – finding the character at a given point.
    * **`selectSubString()`:**  Implements the logic for programmatically selecting a portion of the SVG text.
    * **`SvgAttributeChanged()`:** Handles changes to SVG attributes. The special handling of `textLength` and `lengthAdjust` is significant. It triggers relayout if necessary.

5. **Analyze Relationships with Web Technologies:**

    * **JavaScript:**  The public methods (`getNumberOfChars`, etc.) form the JavaScript API for interacting with SVG text. We can provide examples of how these methods would be used in JavaScript.
    * **HTML:** The `<text>`, `<tspan>`, etc., elements in HTML are the elements this C++ code implements the behavior for.
    * **CSS:** CSS properties (like `white-space`) can influence the rendering of SVG text. The `CollectStyleForPresentationAttribute` method shows how SVG attributes map to CSS properties.

6. **Consider Logic and Assumptions:**

    * **Assumptions:**  We can infer assumptions about the input and output of the methods. For example, `getSubStringLength` assumes valid character indices.
    * **Logic:** The code uses conditional logic to handle different scenarios (e.g., whether `textLength` is user-specified, the rendering engine in use).

7. **Identify Potential User/Programming Errors:**

    * **Index Out of Bounds:**  The `IndexSizeError` exceptions point to a common error: providing invalid character indices to methods like `getSubStringLength`.
    * **Incorrect Attribute Usage:**  Misusing the `textLength` and `lengthAdjust` attributes can lead to unexpected text rendering.

8. **Think About Debugging:**

    * **User Actions:** How does a user interact with a webpage to trigger the execution of this code?  Selecting text, hovering over text, or JavaScript manipulating SVG text are potential triggers.
    * **Debugging Steps:**  Setting breakpoints in this file, examining the values of variables, and tracing the execution flow would be common debugging steps. The `UpdateStyleAndLayoutForNode` calls are crucial points to investigate layout issues.

9. **Structure the Output:**  Organize the findings into logical sections: Functionality, Relationships with Web Technologies, Logic and Assumptions, User Errors, Debugging. Use clear and concise language, providing code examples where relevant.

10. **Refine and Review:**  Read through the analysis to ensure accuracy and completeness. Check for any ambiguities or areas that need further clarification. For example, initially, I might have missed the nuance of `SVGAnimatedTextLength`'s behavior regarding the `textLength` attribute. Reviewing the code helps catch such details.
好的，让我们来详细分析 `blink/renderer/core/svg/svg_text_content_element.cc` 这个文件。

**文件功能概述:**

`svg_text_content_element.cc` 文件是 Chromium Blink 渲染引擎中负责处理 SVG 文本相关元素的 C++ 源代码文件。它实现了 `SVGTextContentElement` 类，该类是所有能包含文本内容的 SVG 元素的基类，例如 `<text>`, `<tspan>`, `<tref>`, `<textPath>`, `<altGlyph>`.

**主要功能可以归纳为:**

1. **表示和管理 SVG 文本内容:**  该类维护了 SVG 文本元素的一些关键属性和状态，例如 `textLength` 和 `lengthAdjust`。
2. **提供 JavaScript API 接口:**  它实现了 Web API 中定义的与 SVG 文本操作相关的接口，允许 JavaScript 代码获取和操作 SVG 文本的属性和几何信息。这些接口包括：
    * `getNumberOfChars()`: 获取文本元素中的字符总数。
    * `getComputedTextLength()`: 获取渲染后的文本长度。
    * `getSubStringLength()`: 获取指定子字符串的渲染长度。
    * `getStartPositionOfChar()`: 获取指定字符的起始位置。
    * `getEndPositionOfChar()`: 获取指定字符的结束位置。
    * `getExtentOfChar()`: 获取指定字符的边界框。
    * `getRotationOfChar()`: 获取指定字符的旋转角度。
    * `getCharNumAtPosition()`: 获取给定位置的字符索引。
    * `selectSubString()`: 选中指定范围的文本。
3. **处理 SVG 属性:**  它负责处理与文本相关的 SVG 属性的解析、存储和更新，例如 `textLength`, `lengthAdjust`, 和继承自父类的图形属性。
4. **与布局引擎交互:**  它与 Blink 的布局引擎协同工作，计算文本的渲染位置和尺寸。它使用 `LayoutSVGText` 和 `SvgTextQuery` 类来完成这些任务。
5. **处理文本选择:**  它支持在 SVG 文本中进行选择操作。
6. **处理 `xml:space` 属性:**  它处理 `xml:space` 属性，该属性决定了如何处理文本中的空白字符。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  `SVGTextContentElement` 提供了大量的 JavaScript API，允许开发者通过 JavaScript 代码动态地获取和操作 SVG 文本的属性和几何信息。

   **举例:**

   ```javascript
   const textElement = document.getElementById('myText');
   const numberOfChars = textElement.getNumberOfChars();
   console.log("Number of characters:", numberOfChars);

   const textLength = textElement.getComputedTextLength();
   console.log("Computed text length:", textLength);

   const startPosition = textElement.getStartPositionOfChar(2);
   console.log("Start position of character 2:", startPosition.x, startPosition.y);
   ```

* **HTML:**  在 HTML 文档中可以使用 `<svg>` 元素嵌入 SVG 内容。`SVGTextContentElement` 对应的 HTML 元素包括 `<text>`, `<tspan>` 等。

   **举例:**

   ```html
   <!DOCTYPE html>
   <html>
   <body>

   <svg width="200" height="100">
     <text id="myText" x="10" y="30" fill="red">
       This is some SVG text.
       <tspan x="10" y="50">More text on a new line.</tspan>
     </text>
   </svg>

   <script>
     // 上面的 JavaScript 代码可以操作这个 HTML 中定义的 SVG 文本元素
   </script>

   </body>
   </html>
   ```

* **CSS:**  CSS 可以用来设置 SVG 文本元素的样式，例如 `fill`, `font-size`, `font-family` 等。`SVGTextContentElement` 中的 `CollectStyleForPresentationAttribute` 方法负责处理 SVG 属性作为 CSS 样式属性的情况，特别是 `xml:space` 属性。

   **举例:**

   ```css
   #myText {
     font-size: 16px;
     font-family: sans-serif;
   }
   ```

   **关于 `xml:space` 的例子:**

   ```html
   <svg>
     <text xml:space="preserve">  This   text   has   spaces. </text>
     <text>  This   text   has   spaces. </text>
   </svg>
   ```

   在这个例子中，设置了 `xml:space="preserve"` 的文本元素会保留所有的空格和换行符，而没有设置的文本元素会折叠连续的空格。 `CollectStyleForPresentationAttribute` 方法会将 `xml:space="preserve"` 转换为 CSS 的 `white-space: pre` 和 `text-wrap-mode: nowrap`，将没有设置或设置为其他值的转换为 `white-space: nowrap` 和 `text-wrap-mode: nowrap`。

**逻辑推理、假设输入与输出:**

假设我们有一个 `<text>` 元素，内容为 "Hello"，并且我们调用了一些 `SVGTextContentElement` 的方法：

**假设输入:**

* `textElement.getNumberOfChars()`:  文本内容为 "Hello"。
* `textElement.getComputedTextLength()`:  假设渲染后的 "Hello" 宽度为 50 像素 (取决于字体、大小等)。
* `textElement.getSubStringLength(1, 3)`:  获取从索引 1 开始的 3 个字符的长度，即 "ell"。假设渲染后的 "ell" 宽度为 30 像素。
* `textElement.getStartPositionOfChar(0)`: 获取第一个字符 'H' 的起始位置，假设为 (10, 30)。
* `textElement.getCharNumAtPosition({x: 60, y: 30})`:  给定位置 (60, 30)，假设该位置在 'o' 字符的范围内。

**预期输出:**

* `getNumberOfChars()`: 输出 `5`。
* `getComputedTextLength()`: 输出 `50`。
* `getSubStringLength(1, 3)`: 输出 `30`。
* `getStartPositionOfChar(0)`: 返回一个表示点 (10, 30) 的 `SVGPointTearOff` 对象。
* `getCharNumAtPosition({x: 60, y: 30})`: 输出 `4` (字符 'o' 的索引)。

**用户或编程常见的使用错误:**

1. **索引越界:**  在调用 `getSubStringLength`, `getStartPositionOfChar`, `getEndPositionOfChar`, `getExtentOfChar`, `getRotationOfChar`, `selectSubString` 等方法时，如果提供的字符索引 `charnum` 超出了文本的字符总数，会抛出 `DOMException` (IndexSizeError)。

   **例子:**

   ```javascript
   const textElement = document.getElementById('myText');
   // 假设文本只有 5 个字符
   try {
     textElement.getStartPositionOfChar(10); // 错误：索引 10 超出范围
   } catch (e) {
     console.error(e); // 输出 DOMException: Index or size is negative or greater than the allowed amount
   }
   ```

2. **对 `textLength` 和 `lengthAdjust` 的误用:**

   * **`textLength`:**  用户可能会错误地认为设置了 `textLength` 就能强制文本缩放或拉伸到指定的长度，而忽略了 `lengthAdjust` 属性的影响。如果 `lengthAdjust` 的值为 `spacing` (默认值)，浏览器可能会通过调整字符间距来适应 `textLength`，而不是缩放字形。
   * **`lengthAdjust`:** 用户可能不理解 `spacing` 和 `spacingAndGlyphs` 之间的区别。
      * `spacing`:  浏览器主要通过调整字符间距来适应 `textLength`。
      * `spacingAndGlyphs`: 浏览器会同时调整字符间距和字形的缩放来适应 `textLength`。

   **例子:**

   ```html
   <svg>
     <!-- 可能达不到预期，只是调整间距 -->
     <text textLength="100" lengthAdjust="spacing">Short</text>

     <!-- 可能会拉伸字形 -->
     <text textLength="100" lengthAdjust="spacingAndGlyphs">Short</text>
   </svg>
   ```

3. **在文本内容尚未渲染时尝试获取几何信息:**  在 JavaScript 中，如果尝试在 SVG 文本内容尚未完成布局和渲染之前调用获取几何信息的方法（例如在页面加载初期），可能会得到不准确的结果或错误。

**用户操作是如何一步步到达这里的，作为调试线索:**

假设用户在网页上与包含 SVG 文本的内容进行交互，以下是一些可能触发 `svg_text_content_element.cc` 中代码执行的场景：

1. **页面加载和渲染:**
   * 浏览器解析 HTML，遇到 `<svg>` 标签。
   * Blink 引擎创建 `SVGSVGElement` 对象。
   * 解析 SVG 内容，遇到 `<text>` 或其他文本内容元素。
   * Blink 引擎创建 `SVGTextContentElement` 对象。
   * 布局引擎计算文本的渲染位置和尺寸，这会调用 `SVGTextContentElement` 中的相关方法。

2. **JavaScript 操作 SVG 文本:**
   * 用户与网页交互，触发 JavaScript 代码执行。
   * JavaScript 代码获取 SVG 文本元素，例如通过 `document.getElementById()`.
   * JavaScript 代码调用 `SVGTextContentElement` 提供的 API，例如 `getNumberOfChars()`, `getComputedTextLength()`, `getStartPositionOfChar()`, `selectSubString()` 等。这些调用会最终进入 `svg_text_content_element.cc` 中的对应方法。

3. **用户选择 SVG 文本:**
   * 用户使用鼠标在 SVG 文本上拖动进行选择。
   * 浏览器的事件处理机制会调用 Blink 引擎的文本选择相关代码。
   * 对于 SVG 文本的选择，会涉及到 `SVGTextContentElement` 中的 `selectSubString()` 方法以及与布局引擎的交互，以确定选区的范围。

4. **CSS 样式更改导致重绘和重排:**
   * 用户交互或 JavaScript 代码修改了影响 SVG 文本外观的 CSS 属性（例如 `font-size`, `fill`）。
   * 浏览器触发重绘和重排。
   * 布局引擎重新计算文本的布局，这可能会再次调用 `SVGTextContentElement` 中的方法来获取文本的尺寸和位置信息。

**作为调试线索:**

* **断点:** 在 `svg_text_content_element.cc` 中设置断点，例如在 `getNumberOfChars`, `getComputedTextLength`, `SvgAttributeChanged` 等方法入口处，可以观察代码执行流程和变量值。
* **日志输出:** 在关键位置添加日志输出，例如打印字符数、计算出的长度、属性值等，可以帮助理解代码的执行状态。
* **查看调用栈:** 当程序在断点处停止时，查看调用栈可以追踪用户操作或 JavaScript 代码是如何最终调用到 `SVGTextContentElement` 的方法的。
* **检查布局树:** 使用 Chromium 的开发者工具查看渲染树和布局树，可以了解 SVG 文本元素的布局信息，例如位置、尺寸等，从而判断是否与 `SVGTextContentElement` 的计算结果一致。
* **分析事件监听器:** 检查与 SVG 文本元素相关的事件监听器，了解哪些 JavaScript 代码正在操作这些元素。

总而言之，`blink/renderer/core/svg/svg_text_content_element.cc` 文件是 Blink 引擎中处理 SVG 文本的核心组件，它连接了 HTML 结构、CSS 样式和 JavaScript 脚本，负责 SVG 文本的渲染、交互和操作。理解这个文件的功能对于深入理解浏览器如何处理 SVG 文本至关重要。

### 提示词
```
这是目录为blink/renderer/core/svg/svg_text_content_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2007, 2008 Nikolas Zimmermann <zimmermann@kde.org>
 * Copyright (C) 2004, 2005, 2006, 2007, 2008 Rob Buis <buis@kde.org>
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

#include "third_party/blink/renderer/core/svg/svg_text_content_element.h"

#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_text.h"
#include "third_party/blink/renderer/core/layout/svg/svg_text_query.h"
#include "third_party/blink/renderer/core/svg/svg_animated_length.h"
#include "third_party/blink/renderer/core/svg/svg_enumeration_map.h"
#include "third_party/blink/renderer/core/svg/svg_point_tear_off.h"
#include "third_party/blink/renderer/core/svg/svg_rect_tear_off.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/xml_names.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

namespace blink {

namespace {

bool IsNGTextOrInline(const LayoutObject* object) {
  return object &&
         (object->IsSVGText() || object->IsInLayoutNGInlineFormattingContext());
}

}  // namespace

template <>
const SVGEnumerationMap& GetEnumerationMap<SVGLengthAdjustType>() {
  static constexpr auto enum_items = std::to_array<const char* const>({
      "spacing",
      "spacingAndGlyphs",
  });
  static const SVGEnumerationMap entries(enum_items);
  return entries;
}

// SVGTextContentElement's 'textLength' attribute needs special handling.
// It should return getComputedTextLength() when textLength is not specified
// manually.
class SVGAnimatedTextLength final : public SVGAnimatedLength {
 public:
  SVGAnimatedTextLength(SVGTextContentElement* context_element)
      : SVGAnimatedLength(context_element,
                          svg_names::kTextLengthAttr,
                          SVGLengthMode::kWidth,
                          SVGLength::Initial::kUnitlessZero) {}

  SVGLengthTearOff* baseVal() override {
    auto* text_content_element = To<SVGTextContentElement>(ContextElement());
    if (!text_content_element->TextLengthIsSpecifiedByUser())
      BaseValue()->NewValueSpecifiedUnits(
          CSSPrimitiveValue::UnitType::kNumber,
          text_content_element->getComputedTextLength());

    return SVGAnimatedLength::baseVal();
  }
};

SVGTextContentElement::SVGTextContentElement(const QualifiedName& tag_name,
                                             Document& document)
    : SVGGraphicsElement(tag_name, document),
      text_length_(MakeGarbageCollected<SVGAnimatedTextLength>(this)),
      text_length_is_specified_by_user_(false),
      length_adjust_(
          MakeGarbageCollected<SVGAnimatedEnumeration<SVGLengthAdjustType>>(
              this,
              svg_names::kLengthAdjustAttr,
              kSVGLengthAdjustSpacing)) {}

void SVGTextContentElement::Trace(Visitor* visitor) const {
  visitor->Trace(text_length_);
  visitor->Trace(length_adjust_);
  SVGGraphicsElement::Trace(visitor);
}

unsigned SVGTextContentElement::getNumberOfChars() {
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);
  auto* layout_object = GetLayoutObject();
  if (IsNGTextOrInline(layout_object))
    return SvgTextQuery(*layout_object).NumberOfCharacters();
  return 0;
}

float SVGTextContentElement::getComputedTextLength() {
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);
  auto* layout_object = GetLayoutObject();
  if (IsNGTextOrInline(layout_object)) {
    SvgTextQuery query(*layout_object);
    return query.SubStringLength(0, query.NumberOfCharacters());
  }
  return 0;
}

float SVGTextContentElement::getSubStringLength(
    unsigned charnum,
    unsigned nchars,
    ExceptionState& exception_state) {
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  unsigned number_of_chars = getNumberOfChars();
  if (charnum >= number_of_chars) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        ExceptionMessages::IndexExceedsMaximumBound("charnum", charnum,
                                                    getNumberOfChars()));
    return 0.0f;
  }

  if (nchars > number_of_chars - charnum)
    nchars = number_of_chars - charnum;

  auto* layout_object = GetLayoutObject();
  if (IsNGTextOrInline(layout_object))
    return SvgTextQuery(*layout_object).SubStringLength(charnum, nchars);
  return 0;
}

SVGPointTearOff* SVGTextContentElement::getStartPositionOfChar(
    unsigned charnum,
    ExceptionState& exception_state) {
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  if (charnum >= getNumberOfChars()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        ExceptionMessages::IndexExceedsMaximumBound("charnum", charnum,
                                                    getNumberOfChars()));
    return nullptr;
  }

  gfx::PointF point;
  auto* layout_object = GetLayoutObject();
  if (IsNGTextOrInline(layout_object)) {
    point = SvgTextQuery(*layout_object).StartPositionOfCharacter(charnum);
  }
  return SVGPointTearOff::CreateDetached(point);
}

SVGPointTearOff* SVGTextContentElement::getEndPositionOfChar(
    unsigned charnum,
    ExceptionState& exception_state) {
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  if (charnum >= getNumberOfChars()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        ExceptionMessages::IndexExceedsMaximumBound("charnum", charnum,
                                                    getNumberOfChars()));
    return nullptr;
  }

  gfx::PointF point;
  auto* layout_object = GetLayoutObject();
  if (IsNGTextOrInline(layout_object)) {
    point = SvgTextQuery(*layout_object).EndPositionOfCharacter(charnum);
  }
  return SVGPointTearOff::CreateDetached(point);
}

SVGRectTearOff* SVGTextContentElement::getExtentOfChar(
    unsigned charnum,
    ExceptionState& exception_state) {
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  if (charnum >= getNumberOfChars()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        ExceptionMessages::IndexExceedsMaximumBound("charnum", charnum,
                                                    getNumberOfChars()));
    return nullptr;
  }

  gfx::RectF rect;
  auto* layout_object = GetLayoutObject();
  if (IsNGTextOrInline(layout_object)) {
    rect = SvgTextQuery(*layout_object).ExtentOfCharacter(charnum);
  }
  return SVGRectTearOff::CreateDetached(rect);
}

float SVGTextContentElement::getRotationOfChar(
    unsigned charnum,
    ExceptionState& exception_state) {
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  if (charnum >= getNumberOfChars()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        ExceptionMessages::IndexExceedsMaximumBound("charnum", charnum,
                                                    getNumberOfChars()));
    return 0.0f;
  }

  auto* layout_object = GetLayoutObject();
  if (IsNGTextOrInline(layout_object))
    return SvgTextQuery(*layout_object).RotationOfCharacter(charnum);
  return 0.0f;
}

int SVGTextContentElement::getCharNumAtPosition(
    SVGPointTearOff* point,
    ExceptionState& exception_state) {
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);
  auto* layout_object = GetLayoutObject();
  if (IsNGTextOrInline(layout_object)) {
    return SvgTextQuery(*layout_object)
        .CharacterNumberAtPosition(point->Target()->Value());
  }
  return -1;
}

void SVGTextContentElement::selectSubString(unsigned charnum,
                                            unsigned nchars,
                                            ExceptionState& exception_state) {
  unsigned number_of_chars = getNumberOfChars();
  if (charnum >= number_of_chars) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        ExceptionMessages::IndexExceedsMaximumBound("charnum", charnum,
                                                    getNumberOfChars()));
    return;
  }

  if (nchars > number_of_chars - charnum)
    nchars = number_of_chars - charnum;

  DCHECK(GetDocument().GetFrame());
  GetDocument().GetFrame()->Selection().SelectSubString(*this, charnum, nchars);
}

bool SVGTextContentElement::IsPresentationAttribute(
    const QualifiedName& name) const {
  if (name.Matches(xml_names::kSpaceAttr))
    return true;
  return SVGGraphicsElement::IsPresentationAttribute(name);
}

void SVGTextContentElement::CollectStyleForPresentationAttribute(
    const QualifiedName& name,
    const AtomicString& value,
    MutableCSSPropertyValueSet* style) {
  if (name.Matches(xml_names::kSpaceAttr)) {
    DEFINE_STATIC_LOCAL(const AtomicString, preserve_string, ("preserve"));

    if (value == preserve_string) {
      UseCounter::Count(GetDocument(), WebFeature::kWhiteSpacePreFromXMLSpace);
      // Longhands of `white-space: pre`.
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kWhiteSpaceCollapse, CSSValueID::kPreserve);
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kTextWrapMode, CSSValueID::kNowrap);
    } else {
      UseCounter::Count(GetDocument(),
                        WebFeature::kWhiteSpaceNowrapFromXMLSpace);
      // Longhands of `white-space: nowrap`.
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kWhiteSpaceCollapse, CSSValueID::kCollapse);
      AddPropertyToPresentationAttributeStyle(
          style, CSSPropertyID::kTextWrapMode, CSSValueID::kNowrap);
    }
  } else {
    SVGGraphicsElement::CollectStyleForPresentationAttribute(name, value,
                                                             style);
  }
}

void SVGTextContentElement::SvgAttributeChanged(
    const SvgAttributeChangedParams& params) {
  const QualifiedName& attr_name = params.name;
  if (attr_name == svg_names::kTextLengthAttr)
    text_length_is_specified_by_user_ = true;

  if (attr_name == svg_names::kTextLengthAttr ||
      attr_name == svg_names::kLengthAdjustAttr ||
      attr_name == xml_names::kSpaceAttr) {
    if (LayoutObject* layout_object = GetLayoutObject()) {
      if (auto* ng_text =
              LayoutSVGText::LocateLayoutSVGTextAncestor(layout_object)) {
        ng_text->SetNeedsPositioningValuesUpdate();
      }
      MarkForLayoutAndParentResourceInvalidation(*layout_object);
    }

    return;
  }

  SVGGraphicsElement::SvgAttributeChanged(params);
}

bool SVGTextContentElement::SelfHasRelativeLengths() const {
  // Any element of the <text> subtree is advertized as using relative lengths.
  // On any window size change, we have to relayout the text subtree, as the
  // effective 'on-screen' font size may change.
  return true;
}

SVGTextContentElement* SVGTextContentElement::ElementFromLineLayoutItem(
    const LineLayoutItem& line_layout_item) {
  return nullptr;
}

SVGAnimatedPropertyBase* SVGTextContentElement::PropertyFromAttribute(
    const QualifiedName& attribute_name) const {
  if (attribute_name == text_length_->AttributeName()) {
    return text_length_.Get();
  } else if (attribute_name == svg_names::kLengthAdjustAttr) {
    return length_adjust_.Get();
  } else {
    return SVGGraphicsElement::PropertyFromAttribute(attribute_name);
  }
}

void SVGTextContentElement::SynchronizeAllSVGAttributes() const {
  SVGAnimatedPropertyBase* attrs[]{text_length_.Get(), length_adjust_.Get()};
  SynchronizeListOfSVGAttributes(attrs);
  SVGGraphicsElement::SynchronizeAllSVGAttributes();
}

}  // namespace blink
```