Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Understanding the Goal:**

The request asks for the functionality of the `layout_tree_as_text.cc` file in the Chromium Blink engine. It also requires relating this functionality to web technologies (HTML, CSS, JavaScript), providing examples, and mentioning potential user/programming errors.

**2. Initial Scan and Keyword Identification:**

My first step is to quickly scan the code for prominent keywords and function names. I notice terms like:

* `LayoutTreeAsText` (in the file name and namespace)
* `Write`, `WriteLayoutObject`, `WriteLayers`, `WriteTextFragment`, `WritePaintProperties`
* `StringBuilder` (indicating string manipulation)
* `LayoutObject`, `PaintLayer` (core Blink layout concepts)
* `Element`, `Node`, `Document` (DOM related)
* `CSS` properties (e.g., `color`, `background-color`, `border`)
* `Selection` (editing functionality)
* `ExternalRepresentation` (a key function for generating output)
* `PseudoElement`
* `Counter`
* `Marker`

These keywords give me a strong indication that the file is about *representing the layout tree structure of a web page as text*.

**3. Dissecting Key Functions:**

Next, I focus on the most important functions:

* **`WriteLayoutObject`:**  This seems to be the core function for describing a single layout object. I see it extracting information like tag name, dimensions, colors, borders, IDs, classes, and layout state.

* **`WriteLayers`:** This function clearly deals with *paint layers*. It handles the hierarchical structure of layers, their offsets, transforms, scrolling information, and the order in which they are painted (negative z-order, normal flow, positive z-order).

* **`WriteTextFragment`:** This specifically handles text content within the layout.

* **`ExternalRepresentation` (multiple overloads):** This seems to be the entry point for generating the textual representation. The overloads suggest it can handle the entire frame, a specific element, etc. The function updates the layout and potentially handles printing mode.

* **`CounterValueForElement` and `MarkerTextForListItem`:** These suggest specific functionalities related to list markers and CSS counters.

**4. Mapping to Web Technologies:**

Now, I start connecting the C++ concepts to their counterparts in web development:

* **HTML:** The `<...>` tags, element IDs and classes directly correspond to the information extracted in `WriteLayoutObject`.
* **CSS:** CSS properties like `color`, `background-color`, `border`, `z-index`, `visibility`, `transform`, `blend-mode`, and counter styles are clearly being accessed and represented. The concept of paint layers is a direct result of CSS properties that trigger layer creation (e.g., `transform`, `opacity`).
* **JavaScript:** While this C++ code doesn't directly interact with JavaScript, the *output* it generates is invaluable for debugging and understanding how JavaScript manipulations of the DOM and CSS affect the rendered layout.

**5. Generating Examples:**

With the connections established, I can construct concrete examples:

* **HTML/CSS Example:** A simple div with styling (color, border, size) demonstrates how `WriteLayoutObject` would represent it.
* **JavaScript Example:** Showing how adding a class via JavaScript can be reflected in the output helps illustrate the dynamic nature of the layout.
* **CSS Counters Example:**  A numbered list demonstrates the functionality of `CounterValueForElement`.
* **List Markers Example:** A basic unordered list highlights `MarkerTextForListItem`.

**6. Identifying Logical Reasoning and Assumptions:**

I look for places where the code makes decisions or assumptions:

* **Layout Updates:** The `ExternalRepresentation` function explicitly updates the layout. This implies that the output reflects the *current* layout state. The `kLayoutAsTextDontUpdateLayout` flag suggests the user can control this behavior.
* **Paint Layer Ordering:** The code follows a specific order for traversing paint layers (negative, normal, positive z-order), reflecting how the rendering engine composites layers.

**7. Considering User/Programming Errors:**

I think about common mistakes developers might make and how this code helps reveal them:

* **Incorrect CSS:** If a CSS rule isn't applied as expected, the layout tree output can show discrepancies in computed styles, dimensions, or even the presence of a layer.
* **JavaScript DOM Manipulation Issues:** If JavaScript code modifies the DOM in a way that leads to unexpected layout changes, the output can be used to pinpoint the affected elements and their properties.
* **Z-index Issues:**  Problems with overlapping elements and incorrect stacking order can be diagnosed by examining the paint layer output.

**8. Structuring the Output:**

Finally, I organize the information logically, starting with the core functionality, then relating it to web technologies, providing examples, explaining reasoning, and concluding with potential errors. Using clear headings and bullet points makes the explanation easier to understand. I also pay attention to wording, ensuring it's technically accurate yet accessible.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This is just about dumping the layout tree."
* **Correction:**  Realized it also includes paint layer information, which is crucial for understanding rendering.
* **Initial thought:** "JavaScript isn't directly involved."
* **Correction:** Recognized that the *output* is essential for understanding the *effects* of JavaScript DOM manipulation.
* **Ensuring clarity:** Made sure to explain the `LayoutAsTextBehavior` flags and their implications.

By following these steps, I arrive at a comprehensive explanation of the `layout_tree_as_text.cc` file's functionality and its relevance to web development.
这个文件 `blink/renderer/core/layout/layout_tree_as_text.cc` 的主要功能是 **将 Blink 渲染引擎的布局树（Layout Tree）以易于阅读的文本形式输出**。  这对于调试、测试和理解 Blink 的布局过程非常有用。

下面我们详细列举其功能，并说明与 JavaScript、HTML、CSS 的关系：

**主要功能：**

1. **遍历布局树:** 代码的核心功能是递归地遍历由 `LayoutObject` 组成的布局树结构。

2. **输出布局对象的信息:** 对于每个 `LayoutObject`，它会提取并格式化输出以下关键信息：
   - **类型:**  如 `LayoutBlock`, `LayoutInline`, `LayoutText` 等。
   - **内存地址:**  通过 `kLayoutAsTextShowAddresses` 行为选项可以显示对象的内存地址，用于更精细的调试。
   - **层叠上下文 (z-index):** 如果对象定义了 `z-index`，则会显示其值。
   - **关联的 DOM 节点:**  显示与 `LayoutObject` 关联的 HTML 标签名或伪元素名 (如 `::before`, `::after`)。
   - **几何尺寸和位置:**  输出对象的矩形区域 (`at (x,y) size widthxheight`)。
   - **颜色和背景色:**  显示对象的文本颜色和背景色。
   - **边框 (border):**  详细输出上下左右边框的宽度、样式和颜色。
   - **表格信息:** 对于表格单元格 (`LayoutTableCell`)，显示其行索引、列索引、行跨度和列跨度。
   - **ID 和 Class:**  通过 `kLayoutAsTextShowIDAndClass` 行为选项可以显示 HTML 元素的 `id` 和 `class` 属性。
   - **布局状态:** 通过 `kLayoutAsTextShowLayoutState` 行为选项可以显示对象是否需要布局 (needs layout)。
   - **文本内容:** 对于 `LayoutText` 对象，会输出其包含的文本内容。

3. **处理 Paint Layers:**  除了布局对象，该文件还能输出 **Paint Layers (绘制层)** 的信息，这对于理解渲染层叠和性能优化至关重要。
   - **层叠顺序:**  输出负 z-order、正常流和正 z-order 的子层。
   - **偏移量:**  显示每个图层相对于其父图层的偏移。
   - **变换 (transform):**  指示图层是否应用了 CSS 变换。
   - **透明度:**  指示图层是否是透明的。
   - **滚动信息:**  对于滚动容器，显示其滚动位置和滚动区域大小。
   - **绘制属性:** 通过 `kLayoutAsTextShowPaintProperties` 行为选项可以显示更多绘制相关的属性，例如裁剪矩形。
   - **是否需要重绘:** 指示图层或其后代是否需要重绘。

4. **输出文本片段 (Text Fragments):** 对于文本内容，会详细输出每个文本片段的位置和宽度。

5. **输出选择 (Selection) 信息:**  可以输出当前选中文本的位置和所在的 DOM 节点。

6. **支持打印模式:**  通过 `kLayoutAsTextPrintingMode` 行为选项，可以模拟打印模式下的布局。

7. **CSS Counter 和 List Marker 支持:** 提供专门的函数 `CounterValueForElement` 和 `MarkerTextForListItem` 来获取 CSS 计数器和列表标记的文本值。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:**
    - 该工具通过遍历布局树，反映了 HTML 元素的结构和层级关系。
    - **例子:**  对于以下 HTML 代码：
      ```html
      <div id="container" class="main">
          <p>Hello</p>
      </div>
      ```
      输出可能包含类似的信息：
      ```
      LayoutBlock#container {DIV} at (0,0) size 100x50 id="container" class="main"
        LayoutBlock {P} at (0,0) size 100x16
          LayoutText "Hello" at (0,0) size 35x16
      ```

* **CSS:**
    - 该工具会显示 CSS 样式影响布局的结果，例如元素的尺寸、位置、颜色、边框等。
    - **例子:**  如果 CSS 设置了 `div#container { width: 200px; background-color: red; border: 1px solid black; }`，那么输出中 `LayoutBlock#container` 的 `size` 会是 `200x50` (假设内容高度不变)，并且会显示 `[bgcolor=rgb(255,0,0)]` 和 `[border: (1px solid rgb(0,0,0))]`。
    - **Paint Layers 的关系:** CSS 属性如 `transform`, `opacity`, `will-change` 等会触发创建新的 Paint Layer。`layout_tree_as_text.cc` 可以展示这些层的存在和属性，帮助理解渲染优化。

* **JavaScript:**
    - JavaScript 可以动态修改 DOM 结构和 CSS 样式，从而影响布局树。
    - **例子:**  如果 JavaScript 代码执行 `document.getElementById('container').style.width = '300px';`，并触发了布局更新，那么再次运行此工具，`LayoutBlock#container` 的 `size` 会变为 `300x50`。
    - **事件调试:**  当 JavaScript 导致的布局问题难以排查时，可以在 JavaScript 执行前后分别生成布局树文本，对比差异，找出问题所在。

**逻辑推理和假设输入与输出:**

假设我们有以下简单的 HTML 和 CSS：

**输入 (HTML):**
```html
<!DOCTYPE html>
<html>
<head>
<style>
  .box { width: 100px; height: 100px; background-color: blue; }
</style>
</head>
<body>
  <div class="box"></div>
</body>
</html>
```

**假设输出:**

```
layer at (0,0)
  RenderView {HTML} at (0,0) size 800x600
    LayoutBlock {BODY} at (8,8) size 800x600
      LayoutBlock.box {DIV} at (8,8) size 100x100 [bgcolor=rgb(0,0,255)]
```

**解释:**

- `layer at (0,0)` 表示根绘制层。
- `RenderView` 是顶层的布局对象，对应 `<html>` 标签。
- `LayoutBlock {BODY}` 对应 `<body>` 标签。
- `LayoutBlock.box {DIV}` 对应 `<div class="box">` 标签，并显示了其类名、尺寸和背景色。

**用户或编程常见的使用错误举例说明:**

1. **CSS 属性拼写错误或值不合法:**
   - **错误:**  如果 CSS 写成 `background-colr: bluue;`，Blink 引擎可能无法识别，导致样式不生效。
   - **`layout_tree_as_text.cc` 的体现:**  输出中可能不会显示预期的背景色 `[bgcolor=...]`，或者显示默认的背景色。

2. **JavaScript DOM 操作顺序错误导致布局异常:**
   - **错误:**  例如，先隐藏一个元素，然后尝试获取其尺寸，可能会得到错误的结果。
   - **`layout_tree_as_text.cc` 的体现:**  可以在 JavaScript 操作前后分别生成布局树文本，对比元素的尺寸和可见性，帮助定位问题。

3. **滥用 `position: absolute` 或 `float` 导致意外的布局结果:**
   - **错误:**  没有正确理解绝对定位和浮动的行为，可能导致元素重叠或脱离文档流。
   - **`layout_tree_as_text.cc` 的体现:**  输出会显示元素的位置和包含块，帮助理解元素的定位上下文。观察 Paint Layers 的结构也能揭示层叠关系是否符合预期。

4. **Z-index 使用不当造成的层叠问题:**
   - **错误:**  在没有创建层叠上下文的情况下使用 `z-index` 可能不会生效。
   - **`layout_tree_as_text.cc` 的体现:**  输出会显示元素的 `zI: value`，但结合 Paint Layers 的结构，可以判断是否创建了预期的层叠上下文。

总之，`blink/renderer/core/layout/layout_tree_as_text.cc` 是一个强大的内部工具，用于理解 Blink 渲染引擎的布局和渲染过程。它可以帮助开发者深入了解 HTML、CSS 和 JavaScript 如何影响页面的最终呈现，并有效地进行调试和性能优化。

### 提示词
```
这是目录为blink/renderer/core/layout/layout_tree_as_text.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2006, 2007 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/layout/layout_tree_as_text.h"

#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_value_id_mappings.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_context.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/list/layout_list_item.h"
#include "third_party/blink/renderer/core/layout/list/list_marker.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_image.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_shape.h"
#include "third_party/blink/renderer/core/layout/svg/svg_layout_tree_as_text.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/page/print_context.h"
#include "third_party/blink/renderer/core/paint/fragment_data_iterator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_paint_order_iterator.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

inline bool HasFractions(double val) {
  // We use 0.011 to more than match the number of significant digits we print
  // out when dumping the render tree.
  static const double kEpsilon = 0.011;
  int ival = static_cast<int>(round(val));
  double dval = static_cast<double>(ival);
  return fabs(val - dval) > kEpsilon;
}

String FormatNumberRespectingIntegers(double value) {
  if (HasFractions(value)) {
    return String::NumberToStringFixedWidth(value, 2);
  }
  return String::Number(static_cast<int>(round(value)));
}

StringBuilder& operator<<(StringBuilder& ts, const LayoutUnit& unit) {
  return ts << FormatNumberRespectingIntegers(unit.ToDouble());
}

}  // namespace

static void WriteLayers(StringBuilder&,
                        PaintLayer*,
                        wtf_size_t indent = 0,
                        LayoutAsTextBehavior = kLayoutAsTextBehaviorNormal,
                        const PaintLayer* marked_layer = nullptr);

static void PrintBorderStyle(StringBuilder& ts,
                             const EBorderStyle border_style) {
  ts << GetCSSValueNameAs<StringView>(PlatformEnumToCSSValueID(border_style))
     << " ";
}

static String GetTagName(Node* n) {
  if (n->IsDocumentNode())
    return "";
  if (n->getNodeType() == Node::kCommentNode)
    return "COMMENT";
  if (const auto* element = DynamicTo<Element>(n)) {
    const AtomicString& pseudo = element->ShadowPseudoId();
    if (!pseudo.empty())
      return "::" + pseudo;
  }
  return n->nodeName();
}

String QuoteAndEscapeNonPrintables(const String& s) {
  StringBuilder result;
  result.Append('"');
  for (unsigned i = 0; i != s.length(); ++i) {
    UChar c = s[i];
    if (c == '\\') {
      result.Append('\\');
      result.Append('\\');
    } else if (c == '"') {
      result.Append('\\');
      result.Append('"');
    } else if (c == '\n' || c == kNoBreakSpaceCharacter) {
      result.Append(' ');
    } else {
      if (c >= 0x20 && c < 0x7F) {
        result.Append(c);
      } else {
        result.AppendFormat("\\x{%X}", c);
      }
    }
  }
  result.Append('"');
  return result.ToString();
}

StringBuilder& operator<<(StringBuilder& ts, const Color& c) {
  return ts << c.NameForLayoutTreeAsText();
}

StringBuilder& operator<<(StringBuilder& ts, const PhysicalRect& r) {
  ts << "at (" << FormatNumberRespectingIntegers(r.X().ToFloat());
  ts << "," << FormatNumberRespectingIntegers(r.Y().ToFloat());
  ts << ") size " << FormatNumberRespectingIntegers(r.Width().ToFloat());
  ts << "x" << FormatNumberRespectingIntegers(r.Height().ToFloat());
  return ts;
}

StringBuilder& operator<<(StringBuilder& ts, const gfx::Point& p) {
  return ts << "(" << p.x() << "," << p.y() << ")";
}

StringBuilder& operator<<(StringBuilder& ts, const gfx::PointF& p) {
  ts << "(" << FormatNumberRespectingIntegers(p.x());
  ts << "," << FormatNumberRespectingIntegers(p.y());
  ts << ")";
  return ts;
}

StringBuilder& operator<<(StringBuilder& ts, const gfx::RectF& r) {
  ts << "at " << r.origin();
  ts << " size " << FormatNumberRespectingIntegers(r.width());
  ts << "x" << FormatNumberRespectingIntegers(r.height());
  return ts;
}

void WriteLayoutObject(StringBuilder& ts,
                       const LayoutObject& o,
                       LayoutAsTextBehavior behavior) {
  ts << o.DecoratedName();

  if (behavior & kLayoutAsTextShowAddresses)
    ts << String::Format(" %p", &o);

  if (o.Style() && o.StyleRef().ZIndex())
    ts << " zI: " << o.StyleRef().ZIndex();

  if (o.GetNode()) {
    String tag_name = GetTagName(o.GetNode());
    if (!tag_name.empty())
      ts << " {" << tag_name << "}";
  }

  PhysicalRect rect = o.DebugRect();
  ts << " " << rect;

  if (!(o.IsText() && !o.IsBR())) {
    if (o.Parent()) {
      Color color = o.ResolveColor(GetCSSPropertyColor());
      if (o.Parent()->ResolveColor(GetCSSPropertyColor()) != color)
        ts << " [color=" << color << "]";

      // Do not dump invalid or transparent backgrounds, since that is the
      // default.
      Color background_color = o.ResolveColor(GetCSSPropertyBackgroundColor());
      if (o.Parent()->ResolveColor(GetCSSPropertyBackgroundColor()) !=
              background_color &&
          background_color.Rgb())
        ts << " [bgcolor=" << background_color << "]";

      Color text_fill_color =
          o.ResolveColor(GetCSSPropertyWebkitTextFillColor());
      if (o.Parent()->ResolveColor(GetCSSPropertyWebkitTextFillColor()) !=
              text_fill_color &&
          text_fill_color != color && text_fill_color.Rgb())
        ts << " [textFillColor=" << text_fill_color << "]";

      Color text_stroke_color =
          o.ResolveColor(GetCSSPropertyWebkitTextStrokeColor());
      if (o.Parent()->ResolveColor(GetCSSPropertyWebkitTextStrokeColor()) !=
              text_stroke_color &&
          text_stroke_color != color && text_stroke_color.Rgb())
        ts << " [textStrokeColor=" << text_stroke_color << "]";

      if (o.Parent()->StyleRef().TextStrokeWidth() !=
              o.StyleRef().TextStrokeWidth() &&
          o.StyleRef().TextStrokeWidth() > 0)
        ts << " [textStrokeWidth=" << o.StyleRef().TextStrokeWidth() << "]";
    }

    if (!o.IsBoxModelObject())
      return;

    const auto& box = To<LayoutBoxModelObject>(o);
    if (box.BorderTop() || box.BorderRight() || box.BorderBottom() ||
        box.BorderLeft()) {
      ts << " [border:";

      if (!box.BorderTop()) {
        ts << " none";
      } else {
        ts << " (" << box.BorderTop() << "px ";
        PrintBorderStyle(ts, o.StyleRef().BorderTopStyle());
        ts << o.ResolveColor(GetCSSPropertyBorderTopColor()) << ")";
      }

      if (!box.BorderRight()) {
        ts << " none";
      } else {
        ts << " (" << box.BorderRight() << "px ";
        PrintBorderStyle(ts, o.StyleRef().BorderRightStyle());
        ts << o.ResolveColor(GetCSSPropertyBorderRightColor()) << ")";
      }

      if (!box.BorderBottom()) {
        ts << " none";
      } else {
        ts << " (" << box.BorderBottom() << "px ";
        PrintBorderStyle(ts, o.StyleRef().BorderBottomStyle());
        ts << o.ResolveColor(GetCSSPropertyBorderBottomColor()) << ")";
      }

      if (!box.BorderLeft()) {
        ts << " none";
      } else {
        ts << " (" << box.BorderLeft() << "px ";
        PrintBorderStyle(ts, o.StyleRef().BorderLeftStyle());
        ts << o.ResolveColor(GetCSSPropertyBorderLeftColor()) << ")";
      }

      ts << "]";
    }
  }

  if (o.IsTableCell()) {
    const auto& c = To<LayoutTableCell>(o);
    ts << " [r=" << c.RowIndex() << " c=" << c.AbsoluteColumnIndex()
       << " rs=" << c.ResolvedRowSpan() << " cs=" << c.ColSpan() << "]";
  }

  if (behavior & kLayoutAsTextShowIDAndClass) {
    if (auto* element = DynamicTo<Element>(o.GetNode())) {
      if (element->HasID())
        ts << " id=\"" << element->GetIdAttribute() << "\"";

      if (element->HasClass()) {
        ts << " class=\"";
        for (wtf_size_t i = 0; i < element->ClassNames().size(); ++i) {
          if (i > 0)
            ts << " ";
          ts << element->ClassNames()[i];
        }
        ts << "\"";
      }
    }
  }

  if (behavior & kLayoutAsTextShowLayoutState) {
    bool needs_layout = o.NeedsLayout();
    if (needs_layout)
      ts << " (needs layout:";

    bool have_previous = false;
    if (o.SelfNeedsFullLayout()) {
      ts << " self";
      have_previous = true;
    }

    if (o.ChildNeedsFullLayout()) {
      if (have_previous)
        ts << ",";
      have_previous = true;
      ts << " child";
    }

    if (o.NeedsSimplifiedLayout()) {
      if (have_previous) {
        ts << ",";
      }
      have_previous = true;
      ts << " simplified";
    }

    if (needs_layout)
      ts << ")";
  }

  if (o.ChildLayoutBlockedByDisplayLock())
    ts << " (display-locked)";
}

static void WriteTextFragment(StringBuilder& ts,
                              PhysicalRect rect,
                              StringView text,
                              LayoutUnit inline_size) {
  // See WriteTextRun() for why we convert to int.
  int x = rect.offset.left.ToInt();
  int y = rect.offset.top.ToInt();
  int logical_width = (rect.offset.left + inline_size).Ceil() - x;
  ts << "text run at (" << x << "," << y << ") width " << logical_width;
  ts << ": " << QuoteAndEscapeNonPrintables(text.ToString());
  ts << "\n";
}

static void WriteTextFragment(StringBuilder& ts, const InlineCursor& cursor) {
  DCHECK(cursor.CurrentItem());
  const FragmentItem& item = *cursor.CurrentItem();
  DCHECK(item.Type() == FragmentItem::kText ||
         item.Type() == FragmentItem::kGeneratedText);
  const LayoutUnit inline_size =
      item.IsHorizontal() ? item.Size().width : item.Size().height;
  WriteTextFragment(ts, item.RectInContainerFragment(),
                    item.Text(cursor.Items()), inline_size);
}

static void WritePaintProperties(StringBuilder& ts,
                                 const LayoutObject& o,
                                 wtf_size_t indent) {
  bool has_fragments = o.IsFragmented();
  if (has_fragments) {
    WriteIndent(ts, indent);
    ts << "fragments:\n";
  }
  int fragment_index = 0;
  for (const FragmentData& fragment : FragmentDataIterator(o)) {
    WriteIndent(ts, indent);
    if (has_fragments)
      ts << " " << fragment_index++ << ":";
    ts << " paint_offset=(" << fragment.PaintOffset().ToString() << ")";
    if (fragment.HasLocalBorderBoxProperties()) {
      // To know where they point into the paint property tree, you can dump
      // the tree using ShowAllPropertyTrees(frame_view).
      ts << " state=(" << fragment.LocalBorderBoxProperties().ToString() << ")";
    }
    if (o.HasLayer()) {
      ts << " cull_rect=(" << fragment.GetCullRect().ToString()
         << ") contents_cull_rect=("
         << fragment.GetContentsCullRect().ToString() << ")";
    }
    ts << "\n";
  }
}

void Write(StringBuilder& ts,
           const LayoutObject& o,
           wtf_size_t indent,
           LayoutAsTextBehavior behavior) {
  if (o.IsSVGShape()) {
    Write(ts, To<LayoutSVGShape>(o), indent);
    return;
  }
  if (o.IsSVGResourceContainer()) {
    WriteSVGResourceContainer(ts, o, indent);
    return;
  }
  if (o.IsSVGContainer()) {
    WriteSVGContainer(ts, o, indent);
    return;
  }
  if (o.IsSVGRoot()) {
    Write(ts, To<LayoutSVGRoot>(o), indent);
    return;
  }
  if (o.IsSVGInline()) {
    WriteSVGInline(ts, To<LayoutSVGInline>(o), indent);
    return;
  }
  if (o.IsSVGInlineText()) {
    WriteSVGInlineText(ts, To<LayoutSVGInlineText>(o), indent);
    return;
  }
  if (o.IsSVGImage()) {
    WriteSVGImage(ts, To<LayoutSVGImage>(o), indent);
    return;
  }

  WriteIndent(ts, indent);

  WriteLayoutObject(ts, o, behavior);
  ts << "\n";

  if (behavior & kLayoutAsTextShowPaintProperties) {
    WritePaintProperties(ts, o, indent + 1);
  }

  if (o.IsText() && !o.IsBR()) {
    const auto& text = To<LayoutText>(o);
    if (const LayoutBlockFlow* block_flow = text.FragmentItemsContainer()) {
      InlineCursor cursor(*block_flow);
      cursor.MoveTo(text);
      for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
        WriteIndent(ts, indent + 1);
        WriteTextFragment(ts, cursor);
      }
    }
  }

  if (!o.ChildLayoutBlockedByDisplayLock()) {
    for (LayoutObject* child = o.SlowFirstChild(); child;
         child = child->NextSibling()) {
      if (child->HasLayer())
        continue;
      Write(ts, *child, indent + 1, behavior);
    }

    if (o.IsLayoutEmbeddedContent()) {
      FrameView* frame_view = To<LayoutEmbeddedContent>(o).ChildFrameView();
      if (auto* local_frame_view = DynamicTo<LocalFrameView>(frame_view)) {
        if (auto* layout_view = local_frame_view->GetLayoutView()) {
          layout_view->GetDocument().UpdateStyleAndLayout(
              DocumentUpdateReason::kTest);
          if (auto* layer = layout_view->Layer()) {
            WriteLayers(ts, layer, indent + 1, behavior);
          }
        }
      }
    }
  }
}

enum LayerPaintPhase {
  kLayerPaintPhaseAll = 0,
  kLayerPaintPhaseBackground = -1,
  kLayerPaintPhaseForeground = 1
};

static void Write(StringBuilder& ts,
                  PaintLayer& layer,
                  const PhysicalOffset& layer_offset,
                  LayerPaintPhase paint_phase = kLayerPaintPhaseAll,
                  wtf_size_t indent = 0,
                  LayoutAsTextBehavior behavior = kLayoutAsTextBehaviorNormal,
                  const PaintLayer* marked_layer = nullptr) {
  gfx::Point adjusted_layer_offset = ToRoundedPoint(layer_offset);

  if (marked_layer)
    ts << (marked_layer == &layer ? "*" : " ");

  WriteIndent(ts, indent);

  if (layer.GetLayoutObject().StyleRef().Visibility() == EVisibility::kHidden) {
    ts << "hidden ";
  }

  ts << "layer ";

  if (behavior & kLayoutAsTextShowAddresses)
    ts << String::Format("%p ", &layer);

  ts << "at " << adjusted_layer_offset;

  if (layer.Transform())
    ts << " hasTransform";
  if (layer.IsTransparent())
    ts << " transparent";

  if (layer.GetLayoutObject().IsScrollContainer()) {
    gfx::PointF scroll_position = layer.GetScrollableArea()->ScrollPosition();
    if (scroll_position.x())
      ts << " scrollX " << scroll_position.x();
    if (scroll_position.y())
      ts << " scrollY " << scroll_position.y();
    if (layer.GetLayoutBox() && layer.GetLayoutBox()->ClientWidth() !=
                                    layer.GetLayoutBox()->ScrollWidth()) {
      ts << " scrollWidth " << layer.GetLayoutBox()->ScrollWidth();
    }
    if (layer.GetLayoutBox() && layer.GetLayoutBox()->ClientHeight() !=
                                    layer.GetLayoutBox()->ScrollHeight()) {
      ts << " scrollHeight " << layer.GetLayoutBox()->ScrollHeight();
    }
  }

  if (paint_phase == kLayerPaintPhaseBackground)
    ts << " layerType: background only";
  else if (paint_phase == kLayerPaintPhaseForeground)
    ts << " layerType: foreground only";

  if (layer.GetLayoutObject().StyleRef().HasBlendMode()) {
    ts << " blendMode: "
       << BlendModeToString(layer.GetLayoutObject().StyleRef().GetBlendMode());
  }

  if (behavior & kLayoutAsTextShowPaintProperties) {
    if (layer.SelfOrDescendantNeedsRepaint())
      ts << " needsRepaint";
    if (layer.NeedsCullRectUpdate())
      ts << " needsCullRectUpdate";
    if (layer.DescendantNeedsCullRectUpdate())
      ts << " descendantNeedsCullRectUpdate";
  }

  ts << "\n";

  if (paint_phase != kLayerPaintPhaseBackground)
    Write(ts, layer.GetLayoutObject(), indent + 1, behavior);
}

static HeapVector<Member<PaintLayer>> ChildLayers(
    const PaintLayer* layer,
    PaintLayerIteration which_children) {
  HeapVector<Member<PaintLayer>> vector;
  PaintLayerPaintOrderIterator it(layer, which_children);
  while (PaintLayer* child = it.Next())
    vector.push_back(child);
  return vector;
}

void WriteLayers(StringBuilder& ts,
                 PaintLayer* layer,
                 wtf_size_t indent,
                 LayoutAsTextBehavior behavior,
                 const PaintLayer* marked_layer) {
  const LayoutObject& layer_object = layer->GetLayoutObject();
  PhysicalOffset layer_offset =
      layer_object.LocalToAbsolutePoint(PhysicalOffset());

  bool should_dump = true;
  auto* embedded = DynamicTo<LayoutEmbeddedContent>(layer_object);
  if (embedded && embedded->IsThrottledFrameView())
    should_dump = false;

  bool should_dump_children = !layer_object.ChildLayoutBlockedByDisplayLock();

  const auto& neg_list = ChildLayers(layer, kNegativeZOrderChildren);
  bool paints_background_separately = !neg_list.empty();
  if (should_dump && paints_background_separately) {
    Write(ts, *layer, layer_offset, kLayerPaintPhaseBackground, indent,
          behavior, marked_layer);
  }

  if (should_dump_children && !neg_list.empty()) {
    int curr_indent = indent;
    if (behavior & kLayoutAsTextShowLayerNesting) {
      WriteIndent(ts, indent);
      ts << " negative z-order list(" << neg_list.size() << ")\n";
      ++curr_indent;
    }
    for (auto& child_layer : neg_list) {
      WriteLayers(ts, child_layer, curr_indent, behavior, marked_layer);
    }
  }

  if (should_dump) {
    Write(ts, *layer, layer_offset,
          paints_background_separately ? kLayerPaintPhaseForeground
                                       : kLayerPaintPhaseAll,
          indent, behavior, marked_layer);
  }

  const auto& normal_flow_list = ChildLayers(layer, kNormalFlowChildren);
  if (should_dump_children && !normal_flow_list.empty()) {
    int curr_indent = indent;
    if (behavior & kLayoutAsTextShowLayerNesting) {
      WriteIndent(ts, indent);
      ts << " normal flow list(" << normal_flow_list.size() << ")\n";
      ++curr_indent;
    }
    for (auto& child_layer : normal_flow_list) {
      WriteLayers(ts, child_layer, curr_indent, behavior, marked_layer);
    }
  }

  const auto& pos_list = ChildLayers(layer, kPositiveZOrderChildren);
  if (should_dump_children && !pos_list.empty()) {
    int curr_indent = indent;
    if (behavior & kLayoutAsTextShowLayerNesting) {
      WriteIndent(ts, indent);
      ts << " positive z-order list(" << pos_list.size() << ")\n";
      ++curr_indent;
    }
    for (auto& child_layer : pos_list) {
      WriteLayers(ts, child_layer, curr_indent, behavior, marked_layer);
    }
  }
}

static String NodePosition(Node* node) {
  StringBuilder result;

  Element* body = node->GetDocument().body();
  Node* parent;
  for (Node* n = node; n; n = parent) {
    parent = n->ParentOrShadowHostNode();
    if (n != node)
      result.Append(" of ");
    if (parent) {
      if (body && n == body) {
        // We don't care what offset body may be in the document.
        result.Append("body");
        break;
      }
      if (n->IsShadowRoot()) {
        result.Append('{');
        result.Append(GetTagName(n));
        result.Append('}');
      } else {
        result.Append("child ");
        result.AppendNumber(n->NodeIndex());
        result.Append(" {");
        result.Append(GetTagName(n));
        result.Append('}');
      }
    } else {
      result.Append("document");
    }
  }

  return result.ToString();
}

static void WriteSelection(StringBuilder& ts, const LayoutObject* o) {
  Document* doc = DynamicTo<Document>(o->GetNode());
  if (!doc)
    return;

  LocalFrame* frame = doc->GetFrame();
  if (!frame)
    return;

  const VisibleSelection& selection =
      frame->Selection().ComputeVisibleSelectionInDOMTree();
  if (selection.IsCaret()) {
    ts << "caret: position " << selection.Start().ComputeEditingOffset()
       << " of " << NodePosition(selection.Start().AnchorNode());
    if (selection.Affinity() == TextAffinity::kUpstream)
      ts << " (upstream affinity)";
    ts << "\n";
  } else if (selection.IsRange()) {
    ts << "selection start: position "
       << selection.Start().ComputeEditingOffset() << " of "
       << NodePosition(selection.Start().AnchorNode()) << "\n"
       << "selection end:   position " << selection.End().ComputeEditingOffset()
       << " of " << NodePosition(selection.End().AnchorNode()) << "\n";
  }
}

static String ExternalRepresentation(LayoutBox* layout_object,
                                     LayoutAsTextBehavior behavior,
                                     const PaintLayer* marked_layer = nullptr) {
  StringBuilder ts;
  if (!layout_object->HasLayer())
    return ts.ReleaseString();

  PaintLayer* layer = layout_object->Layer();
  WriteLayers(ts, layer, 0, behavior, marked_layer);
  WriteSelection(ts, layout_object);
  return ts.ReleaseString();
}

String ExternalRepresentation(LocalFrame* frame,
                              LayoutAsTextBehavior behavior,
                              const PaintLayer* marked_layer) {
  if (!(behavior & kLayoutAsTextDontUpdateLayout)) {
    bool success = frame->View()->UpdateAllLifecyclePhasesExceptPaint(
        DocumentUpdateReason::kTest);
    DCHECK(success);
  };

  LayoutObject* layout_object = frame->ContentLayoutObject();
  if (!layout_object || !layout_object->IsBox())
    return String();
  auto* layout_box = To<LayoutBox>(layout_object);

  PrintContext* print_context = MakeGarbageCollected<PrintContext>(frame);
  bool is_text_printing_mode = !!(behavior & kLayoutAsTextPrintingMode);
  if (is_text_printing_mode) {
    gfx::SizeF page_size(layout_box->ClientWidth(), layout_box->ClientHeight());
    print_context->BeginPrintMode(WebPrintParams(page_size));

    // The lifecycle needs to be run again after changing printing mode,
    // to account for any style updates due to media query change.
    if (!(behavior & kLayoutAsTextDontUpdateLayout))
      frame->View()->UpdateLifecyclePhasesForPrinting();
  }

  String representation =
      ExternalRepresentation(layout_box, behavior, marked_layer);
  if (is_text_printing_mode)
    print_context->EndPrintMode();
  return representation;
}

String ExternalRepresentation(Element* element, LayoutAsTextBehavior behavior) {
  // Doesn't support printing mode.
  DCHECK(!(behavior & kLayoutAsTextPrintingMode));
  if (!(behavior & kLayoutAsTextDontUpdateLayout)) {
    element->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  }

  LayoutObject* layout_object = element->GetLayoutObject();
  if (!layout_object || !layout_object->IsBox())
    return String();

  return ExternalRepresentation(To<LayoutBox>(layout_object), behavior);
}

static void WriteCounterValuesFromChildren(StringBuilder& stream,
                                           LayoutObject* parent,
                                           bool& is_first_counter) {
  for (LayoutObject* child = parent->SlowFirstChild(); child;
       child = child->NextSibling()) {
    if (child->IsCounter()) {
      if (!is_first_counter)
        stream << " ";
      is_first_counter = false;
      stream << To<LayoutText>(child)->TransformedText();
    }
  }
}

String CounterValueForElement(Element* element) {
  element->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  StringBuilder stream;
  bool is_first_counter = true;
  // The counter LayoutObjects should be children of ::marker, ::before or
  // ::after pseudo-elements.
  if (LayoutObject* marker =
          element->PseudoElementLayoutObject(kPseudoIdMarker))
    WriteCounterValuesFromChildren(stream, marker, is_first_counter);
  if (LayoutObject* check =
          element->PseudoElementLayoutObject(kPseudoIdCheck)) {
    WriteCounterValuesFromChildren(stream, check, is_first_counter);
  }
  if (LayoutObject* before =
          element->PseudoElementLayoutObject(kPseudoIdBefore)) {
    WriteCounterValuesFromChildren(stream, before, is_first_counter);
  }
  if (LayoutObject* after = element->PseudoElementLayoutObject(kPseudoIdAfter))
    WriteCounterValuesFromChildren(stream, after, is_first_counter);
  if (LayoutObject* select_arrow =
          element->PseudoElementLayoutObject(kPseudoIdSelectArrow)) {
    WriteCounterValuesFromChildren(stream, select_arrow, is_first_counter);
  }
  return stream.ReleaseString();
}

String MarkerTextForListItem(Element* element) {
  element->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  LayoutObject* layout_object = element->GetLayoutObject();
  LayoutObject* marker = ListMarker::MarkerFromListItem(layout_object);
  if (ListMarker* list_marker = ListMarker::Get(marker))
    return list_marker->MarkerTextWithoutSuffix(*marker);
  return String();
}

}  // namespace blink
```