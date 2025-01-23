Response:
Let's break down the thought process for analyzing the `inspector_contrast.cc` file.

1. **Understand the Goal:** The fundamental purpose is to analyze the contrast between text and its background in a web page, specifically for accessibility purposes (WCAG guidelines). This immediately signals that it's part of the browser's developer tools.

2. **Identify Key Classes and Functions:** Scan the file for class names and prominent function names. `InspectorContrast`, `GetContrast`, `GetBackgroundColors`, `GetElementsWithContrastIssues`, and `SortElementsByPaintOrder` stand out. These are the core components of the functionality.

3. **Trace the Workflow (High-Level):**  Think about the steps involved in checking contrast:
    * **Gather Elements:** Need a list of relevant elements to check.
    * **Get Text Color:** Determine the color of the text content.
    * **Get Background Color(s):**  Figure out the background color(s) behind the text. This is more complex than it sounds due to layering and transparency.
    * **Calculate Contrast Ratio:** Use a formula (likely the one defined by WCAG) to compare the text and background colors.
    * **Check Against Thresholds:**  Compare the calculated ratio against the WCAG AA and AAA contrast requirements, considering font size and weight.
    * **Report Issues:**  Identify elements that don't meet the contrast requirements.

4. **Examine Individual Functions:** Now, delve into the details of each key function:

    * **`InspectorContrast` Constructor:**  Initializes the object, potentially handling cross-frame scenarios (important for iframes). The mention of using the "top level document" is a key detail.

    * **`CollectNodesAndBuildRTreeIfNeeded`:** The "IfNeeded" part suggests optimization. The function name strongly implies gathering elements and building some sort of spatial index (`RTree`) for efficient searching. The call to `InspectorDOMAgent::CollectNodes` confirms element gathering. Sorting by paint order is also crucial for accurate background color determination.

    * **`GetElementsWithContrastIssues`:** This function iterates through the collected elements, calls `GetContrast` for each, and filters based on the contrast ratio and thresholds. The `report_aaa` parameter indicates support for different WCAG levels.

    * **`GetContrast`:** This is the core contrast calculation logic. It focuses on elements with a single text child. It retrieves text and background colors, blends them if necessary (due to transparency), calculates the contrast ratio using `color_utils::GetContrastRatio`, and determines if it meets the AA and AAA thresholds, considering `IsLargeFont`.

    * **`GetTextInfo`:**  Simple function to extract font size and weight, which are used to determine the correct contrast thresholds.

    * **`GetBackgroundColors`:** This is the most complex part. It involves:
        * Getting the bounding box of the text.
        * Starting with the default page background color.
        * Calling `GetColorsFromRect` to find overlapping elements and their background colors.

    * **`GetColorsFromRect`:** This function is crucial for handling overlapping elements and transparency. It uses the `RTree` (`ElementsFromRect`) to efficiently find elements under the text. It iterates through these elements, considering their background colors, opacities, and special element types (like canvas and images). The logic for blending colors and handling opacity is important to understand. The check for whether an element "contains" the rectangle is key to determining if a background is truly behind the text.

    * **`ElementsFromRect`:**  A helper function that leverages the `RTree` to find elements overlapping a given rectangle.

    * **`SortElementsByPaintOrder`:** This function uses `InspectorDOMSnapshotAgent::BuildPaintLayerTree` to get the painting order of elements, ensuring that when determining background colors, elements painted later (on top) are considered first.

5. **Identify Relationships with Web Technologies:**  Think about how this code interacts with HTML, CSS, and JavaScript:

    * **HTML:** The code operates on `Element` and `Text` nodes, which are fundamental HTML concepts. It needs to traverse the DOM tree.
    * **CSS:**  It retrieves computed styles (font size, font weight, background color, opacity, visibility). It deals with different types of CSS values (colors, gradients).
    * **JavaScript:**  While this C++ code isn't JavaScript, it's part of the browser's DevTools, which are often exposed and controlled through JavaScript APIs. The DevTools UI would use JavaScript to trigger these contrast checks and display the results.

6. **Look for Logic and Assumptions:**

    * **Single Text Child Assumption:** The `GetContrast` and `GetBackgroundColors` functions initially seem to assume the target element has a single text child. This is a significant simplification and a potential area for improvement (as the TODO comments suggest).
    * **RTree Optimization:**  The use of an R-tree is a clear optimization for efficiently finding overlapping elements.
    * **Paint Order Importance:** The sorting by paint order highlights the importance of visual layering in determining the effective background.

7. **Consider Potential Errors:** Think about what could go wrong or what common developer mistakes this code might help identify:

    * **Insufficient Contrast:** The primary error this detects is text that doesn't have enough contrast with its background, making it hard to read for people with visual impairments.
    * **Incorrect Color Combinations:** Developers might choose color combinations that look good to them but fail accessibility checks.
    * **Opacity Issues:** Using too much transparency can reduce contrast.
    * **Overlapping Elements:**  The code handles overlapping elements, but developers might not be aware of how background colors from different elements are interacting.

8. **Formulate Examples:**  Based on the understanding of the code, create concrete examples for inputs and outputs, as well as common errors. These examples make the abstract code more tangible.

9. **Structure the Output:** Organize the findings into clear categories (functionality, relationships, logic, errors, examples) for better readability and understanding.

By following these steps, one can systematically analyze a complex piece of code like `inspector_contrast.cc` and extract its key features, relationships, and implications. The process involves a combination of code reading, domain knowledge (web technologies, accessibility), and logical reasoning.
这个文件 `blink/renderer/core/inspector/inspector_contrast.cc` 的主要功能是**检查网页元素（特别是文本元素）的前景色和背景色之间的对比度，以帮助开发者识别可能存在可访问性问题的低对比度文本。** 这是浏览器开发者工具（DevTools）中用于辅助网页可访问性检查的一部分。

以下是更详细的功能说明：

**1. 对比度计算核心功能:**

* **`GetContrast(Element* top_element)`:** 这是计算对比度的核心函数。它接收一个元素作为输入，通常是一个包含文本的元素。
* 它会尝试获取该元素的文本颜色（前景色）。
* 它会调用 `GetBackgroundColors` 来确定该元素文本内容背后的背景色。
* 使用 `color_utils::GetContrastRatio` (来自 `ui/gfx/color_utils.h`) 计算前景色和背景色之间的对比度。
* 它会根据文本的大小和粗细（通过 `IsLargeFont` 函数判断）来应用不同的 WCAG（Web Content Accessibility Guidelines）对比度阈值（AA 和 AAA 级别）。
* 返回一个 `ContrastInfo` 结构，包含计算出的对比度、阈值、字体信息以及是否能够计算对比度等信息。

**2. 获取背景色:**

* **`GetBackgroundColors(Element* element, float* text_opacity)`:**  这个函数负责确定指定元素文本内容背后的有效背景色。
* 它考虑了层叠样式，会查找覆盖在文本内容下方的所有元素的背景色。
* 它使用 `ElementsFromRect` 来查找与文本内容区域重叠的其他元素。
* 它会递归地向上遍历 DOM 树，查找祖先元素的背景色。
* 它会考虑元素的 `opacity` 属性，并将其应用到背景色和文本的透明度计算中。
* 它处理不同类型的背景，包括纯色和渐变色（`AddColorsFromImageStyle` 和 `BlendWithColorsFromGradient`）。
* 它会忽略隐藏元素（`style->Visibility() == EVisibility::kHidden`）的背景色。
* 对于像 `<canvas>`, `<img>`, `<video>` 等特定元素，它会清空当前的背景色，因为这些元素可能具有复杂的渲染内容，无法简单地用背景色来概括。

**3. 查找重叠元素:**

* **`ElementsFromRect(const PhysicalRect& rect, Document& document)`:** 这个函数使用一个 R 树（`rtree_`）数据结构来高效地查找与给定矩形区域重叠的所有元素。
* `CollectNodesAndBuildRTreeIfNeeded` 负责收集所有带有布局对象的元素，并将它们的边界框信息构建到 R 树中。这是一种空间索引，可以加速查找过程。

**4. 处理字体大小和粗细:**

* **`IsLargeFont(const TextInfo& text_info)`:**  判断文本是否属于“大文本”，根据 WCAG 的定义，大文本的对比度要求较低。它会解析 `font-size` 和 `font-weight` CSS 属性的值来进行判断。
* **`GetTextInfo(Element* element)`:**  获取元素的 `font-size` 和 `font-weight` CSS 属性值。

**5. 元素收集和排序:**

* **`CollectNodesAndBuildRTreeIfNeeded()`:**  负责收集文档中所有具有布局对象（`LayoutObject`）的元素，并将它们的边界框信息构建到 R 树中，以便进行快速的空间查询。
* **`SortElementsByPaintOrder(HeapVector<Member<Node>>& unsorted_elements, Document* document)`:**  按照元素的绘制顺序（paint order）对元素进行排序。这对于确定背景色非常重要，因为绘制在后面的元素会覆盖前面的元素。它使用了 `InspectorDOMSnapshotAgent::BuildPaintLayerTree` 来获取绘制顺序信息。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:** 该代码处理 HTML 元素 (`Element`) 和文本节点 (`Text`)，遍历 DOM 树来查找元素和它们的层叠关系。例如，它需要找到包含文本的元素，以及覆盖在其下方的其他元素。
* **CSS:**  该代码大量依赖 CSS 样式信息。它获取元素的计算样式 (`ComputedStyle`)，包括 `color`, `background-color`, `background-image` (用于处理渐变), `opacity`, `font-size`, `font-weight`, `visibility` 等属性。例如，`ComputedStyleUtils::ComputedPropertyValue` 用于获取 CSS 属性值。
* **JavaScript:** 虽然这个文件是 C++ 代码，但它是 Chrome 浏览器 DevTools 的一部分，而 DevTools 的用户界面通常是用 JavaScript 构建的。JavaScript 代码会调用 DevTools 后端的 C++ 功能，例如调用 `InspectorContrast::GetElementsWithContrastIssues` 来获取对比度问题的列表，并在 DevTools 的 "检查器" 或 "辅助功能" 面板中显示结果。

**逻辑推理、假设输入与输出:**

假设我们有以下简单的 HTML 结构和 CSS：

```html
<div style="background-color: white;">
  <p style="color: gray; font-size: 16px;">灰色的文字</p>
</div>
```

**假设输入:**  `GetContrast` 函数接收到 `<p>` 元素。

**逻辑推理:**

1. **获取文本颜色:** `GetContrast` 会获取 `<p>` 元素的 `color` 样式，得到灰色。
2. **获取背景色:** `GetBackgroundColors` 会查找 `<p>` 元素内容区域下的背景色。
   - 它会找到父元素 `<div>`，并获取其 `background-color` 样式，得到白色。
3. **计算对比度:**  `color_utils::GetContrastRatio` 会计算灰色和白色之间的对比度。假设计算结果为 4.0。
4. **判断是否是大文本:** `IsLargeFont` 会检查 `<p>` 元素的 `font-size` (16px) 和 `font-weight`。假设不是大文本。
5. **比较阈值:**  对于非大文本，AA 阈值为 4.5，AAA 阈值为 7.0。
6. **输出:** `GetContrast` 返回的 `ContrastInfo` 结构会包含：
   - `able_to_compute_contrast`: `true`
   - `contrast_ratio`: `4.0`
   - `threshold_aa`: `4.5`
   - `threshold_aaa`: `7.0`
   - `font_size`: `"16px"`
   - `font_weight`: (可能为空或根据具体样式给出)
   - `element`: 指向 `<p>` 元素的指针。

`GetElementsWithContrastIssues` 函数会遍历所有元素，调用 `GetContrast`，并返回对比度低于阈值的元素列表。在这个例子中，如果只检查这一个 `<p>` 元素，且 `report_aaa` 为 `false`，则该元素会被包含在结果中，因为它低于 AA 阈值 4.5。

**用户或编程常见的使用错误:**

1. **未考虑背景透明度:** 开发者可能只关注元素的 `background-color` 属性，而忽略了可能存在的 `opacity` 属性，导致实际的背景色与预期不同，对比度计算错误。
   ```html
   <div style="background-color: rgba(255, 255, 255, 0.5);"> <!-- 半透明白色 -->
     <p style="color: gray;">文字</p>
   </div>
   ```
   `InspectorContrast` 会正确地混合背景色和透明度来计算实际的背景色。

2. **层叠上下文下的背景色覆盖:** 开发者可能没有考虑到元素的层叠关系，导致文本下方的背景色不是他们预期的颜色。例如，一个绝对定位的元素覆盖在文本上方，其背景色会影响对比度。
   ```html
   <div style="background-color: white; position: relative;">
     <div style="position: absolute; top: 0; left: 0; background-color: red; width: 100%; height: 100%; z-index: -1;"></div>
     <p style="color: black;">文字</p>
   </div>
   ```
   即使 `div` 的 `background-color` 是白色，但由于 `z-index` 的关系，红色的 `div` 会在 `p` 元素的下方，`InspectorContrast` 会检测到黑色文字在红色背景上的对比度。

3. **忽略了渐变背景:** 开发者可能只测试了纯色背景的情况，而忽略了渐变背景下的对比度。渐变背景的对比度计算更加复杂，需要考虑渐变色标之间的颜色过渡。
   ```css
   .gradient-bg {
     background-image: linear-gradient(to right, white, gray);
   }
   .text-on-gradient {
     color: black;
   }
   ```
   `InspectorContrast` 会处理渐变背景，并尝试根据渐变的颜色停止点来确定有效的背景色。

4. **误判大文本的阈值:** 开发者可能不清楚 WCAG 对大文本的定义和不同的对比度要求，导致使用不符合要求的颜色组合。`InspectorContrast` 会根据 `IsLargeFont` 的判断来应用正确的阈值。

5. **动态修改样式导致对比度问题:**  开发者可能通过 JavaScript 动态地修改元素的颜色或背景色，导致在某些状态下出现对比度问题。`InspectorContrast` 可以在运行时检查页面的对比度。

总而言之，`inspector_contrast.cc` 是 Blink 引擎中一个重要的可访问性工具，它通过分析元素的样式和层叠关系，帮助开发者识别和修复网页中潜在的低对比度问题，从而提升网页的可访问性。

### 提示词
```
这是目录为blink/renderer/core/inspector/inspector_contrast.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/inspector/inspector_contrast.h"

#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"
#include "third_party/blink/renderer/core/css/css_gradient_value.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/html_embed_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/html_picture_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_snapshot_agent.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/style/style_generated_image.h"
#include "ui/gfx/color_utils.h"

namespace blink {

namespace {

bool NodeIsElementWithLayoutObject(Node* node) {
  if (auto* element = DynamicTo<Element>(node)) {
    if (element->GetLayoutObject())
      return true;
  }
  return false;
}

// Blends the colors from the given gradient with the existing colors.
void BlendWithColorsFromGradient(cssvalue::CSSGradientValue* gradient,
                                 Vector<Color>& colors,
                                 bool& found_non_transparent_color,
                                 bool& found_opaque_color,
                                 const LayoutObject& layout_object) {
  const Document& document = layout_object.GetDocument();
  const ComputedStyle& style = layout_object.StyleRef();

  Vector<Color> stop_colors = gradient->GetStopColors(document, style);
  if (colors.empty()) {
    colors.AppendRange(stop_colors.begin(), stop_colors.end());
  } else {
    if (colors.size() > 1) {
      // Gradient on gradient is too complicated, bail out.
      colors.clear();
      return;
    }

    Color existing_color = colors.front();
    colors.clear();
    for (auto stop_color : stop_colors) {
      found_non_transparent_color =
          found_non_transparent_color || !stop_color.IsFullyTransparent();
      colors.push_back(existing_color.Blend(stop_color));
    }
  }
  found_opaque_color =
      found_opaque_color || gradient->KnownToBeOpaque(document, style);
}

// Gets the colors from an image style, if one exists and it is a gradient.
void AddColorsFromImageStyle(const ComputedStyle& style,
                             const LayoutObject& layout_object,
                             Vector<Color>& colors,
                             bool& found_opaque_color,
                             bool& found_non_transparent_color) {
  const FillLayer& background_layers = style.BackgroundLayers();
  if (!background_layers.AnyLayerHasImage())
    return;

  StyleImage* style_image = background_layers.GetImage();
  // hasImage() does not always indicate that this is non-null
  if (!style_image)
    return;

  if (!style_image->IsGeneratedImage()) {
    // Make no assertions about the colors in non-generated images
    colors.clear();
    found_opaque_color = false;
    return;
  }

  StyleGeneratedImage* gen_image = To<StyleGeneratedImage>(style_image);
  CSSValue* image_css = gen_image->CssValue();
  if (auto* gradient = DynamicTo<cssvalue::CSSGradientValue>(image_css)) {
    BlendWithColorsFromGradient(gradient, colors, found_non_transparent_color,
                                found_opaque_color, layout_object);
  }
}

PhysicalRect GetNodeRect(Node* node) {
  PhysicalRect rect = node->BoundingBox();
  Document* document = &node->GetDocument();
  while (!document->IsInMainFrame()) {
    HTMLFrameOwnerElement* owner_element = document->LocalOwner();
    if (!owner_element)
      break;
    rect.offset.left += owner_element->BoundingBox().offset.left;
    rect.offset.top += owner_element->BoundingBox().offset.top;
    document = &owner_element->GetDocument();
  }
  return rect;
}

}  // namespace

InspectorContrast::InspectorContrast(Document* document) {
  if (!document->IsInMainFrame()) {
    // If document is in a frame, use the top level document to collect nodes
    // for all frames.
    for (HTMLFrameOwnerElement* owner_element = document->LocalOwner();
         owner_element;
         owner_element = owner_element->GetDocument().LocalOwner()) {
      document = &owner_element->GetDocument();
    }
  }

  document_ = document;
}

void InspectorContrast::CollectNodesAndBuildRTreeIfNeeded() {
  TRACE_EVENT0("devtools.contrast",
               "InspectorContrast::CollectNodesAndBuildRTreeIfNeeded");

  if (rtree_built_)
    return;

  LocalFrame* frame = document_->GetFrame();
  if (!frame)
    return;
  LayoutView* layout_view = frame->ContentLayoutObject();
  if (!layout_view)
    return;

  if (!layout_view->GetFrameView()->UpdateAllLifecyclePhasesExceptPaint(
          DocumentUpdateReason::kInspector)) {
    return;
  }

  InspectorDOMAgent::CollectNodes(
      document_, INT_MAX, true, InspectorDOMAgent::IncludeWhitespaceEnum::NONE,
      WTF::BindRepeating(&NodeIsElementWithLayoutObject), &elements_);
  SortElementsByPaintOrder(elements_, document_);
  rtree_.Build(
      elements_.size(),
      [this](size_t index) {
        return ToPixelSnappedRect(
            GetNodeRect(elements_[static_cast<wtf_size_t>(index)]));
      },
      [this](size_t index) {
        return elements_[static_cast<wtf_size_t>(index)];
      });

  rtree_built_ = true;
}

std::vector<ContrastInfo> InspectorContrast::GetElementsWithContrastIssues(
    bool report_aaa,
    size_t max_elements = 0) {
  TRACE_EVENT0("devtools.contrast",
               "InspectorContrast::GetElementsWithContrastIssues");
  CollectNodesAndBuildRTreeIfNeeded();
  std::vector<ContrastInfo> result;
  for (Node* node : elements_) {
    auto info = GetContrast(To<Element>(node));
    if (info.able_to_compute_contrast &&
        ((info.contrast_ratio < info.threshold_aa) ||
         (info.contrast_ratio < info.threshold_aaa && report_aaa))) {
      result.push_back(std::move(info));
      if (max_elements && result.size() >= max_elements)
        return result;
    }
  }
  return result;
}

static bool IsLargeFont(const TextInfo& text_info) {
  String font_size_css = text_info.font_size;
  String font_weight = text_info.font_weight;
  // font_size_css always has 'px' appended at the end;
  String font_size_str = font_size_css.Substring(0, font_size_css.length() - 2);
  double font_size_px = font_size_str.ToDouble();
  double font_size_pt = font_size_px * 72 / 96;
  bool is_bold = font_weight == "bold" || font_weight == "bolder" ||
                 font_weight == "600" || font_weight == "700" ||
                 font_weight == "800" || font_weight == "900";
  if (is_bold) {
    return font_size_pt >= 14;
  }
  return font_size_pt >= 18;
}

ContrastInfo InspectorContrast::GetContrast(Element* top_element) {
  TRACE_EVENT0("devtools.contrast", "InspectorContrast::GetContrast");

  ContrastInfo result;

  auto* text_node = DynamicTo<Text>(top_element->firstChild());
  if (!text_node || text_node->nextSibling())
    return result;

  const String& text = text_node->data().StripWhiteSpace();
  if (text.empty())
    return result;

  const LayoutObject* layout_object = top_element->GetLayoutObject();
  const CSSValue* text_color_value = ComputedStyleUtils::ComputedPropertyValue(
      CSSProperty::Get(CSSPropertyID::kColor), layout_object->StyleRef());
  if (!text_color_value->IsColorValue())
    return result;

  float text_opacity = 1.0f;
  Vector<Color> bgcolors = GetBackgroundColors(top_element, &text_opacity);
  // TODO(crbug/1174511): Compute contrast only if the element has a single
  // color background to be consistent with the current UI. In the future, we
  // should return a range of contrast values.
  if (bgcolors.size() != 1)
    return result;

  Color text_color =
      static_cast<const cssvalue::CSSColor*>(text_color_value)->Value();

  text_color.SetAlpha(text_opacity * text_color.Alpha());

  float contrast_ratio = color_utils::GetContrastRatio(
      bgcolors.at(0).Blend(text_color).toSkColor4f(),
      bgcolors.at(0).toSkColor4f());

  auto text_info = GetTextInfo(top_element);
  bool is_large_font = IsLargeFont(text_info);

  result.able_to_compute_contrast = true;
  result.contrast_ratio = contrast_ratio;
  result.threshold_aa = is_large_font ? 3.0 : 4.5;
  result.threshold_aaa = is_large_font ? 4.5 : 7.0;
  result.font_size = text_info.font_size;
  result.font_weight = text_info.font_weight;
  result.element = top_element;

  return result;
}

TextInfo InspectorContrast::GetTextInfo(Element* element) {
  TextInfo info;
  auto* computed_style_info =
      MakeGarbageCollected<CSSComputedStyleDeclaration>(element, true);
  const CSSValue* font_size =
      computed_style_info->GetPropertyCSSValue(CSSPropertyID::kFontSize);
  if (font_size)
    info.font_size = font_size->CssText();
  const CSSValue* font_weight =
      computed_style_info->GetPropertyCSSValue(CSSPropertyID::kFontWeight);
  if (font_weight)
    info.font_weight = font_weight->CssText();
  return info;
}

Vector<Color> InspectorContrast::GetBackgroundColors(Element* element,
                                                     float* text_opacity) {
  Vector<Color> colors;
  // TODO: only support the single text child node here.
  // Follow up with a larger fix post-merge.
  auto* text_node = DynamicTo<Text>(element->firstChild());
  if (!text_node || element->firstChild()->nextSibling()) {
    return colors;
  }

  PhysicalRect content_bounds = GetNodeRect(text_node);
  LocalFrameView* view = text_node->GetDocument().View();
  if (!view)
    return colors;

  // Start with the "default" page color (typically white).
  colors.push_back(view->BaseBackgroundColor());

  GetColorsFromRect(content_bounds, text_node->GetDocument(), element, colors,
                    text_opacity);

  return colors;
}

// Get the elements which overlap the given rectangle.
HeapVector<Member<Node>> InspectorContrast::ElementsFromRect(
    const PhysicalRect& rect,
    Document& document) {
  CollectNodesAndBuildRTreeIfNeeded();
  HeapVector<Member<Node>> overlapping_elements;
  rtree_.Search(ToPixelSnappedRect(rect),
                [&overlapping_elements](const Member<Node>& payload,
                                        const gfx::Rect& rect) {
                  overlapping_elements.push_back(payload);
                });
  return overlapping_elements;
}

bool InspectorContrast::GetColorsFromRect(PhysicalRect rect,
                                          Document& document,
                                          Element* top_element,
                                          Vector<Color>& colors,
                                          float* text_opacity) {
  HeapVector<Member<Node>> elements_under_rect =
      ElementsFromRect(rect, document);

  bool found_opaque_color = false;
  bool found_top_element = false;

  *text_opacity = 1.0f;

  for (const Member<Node>& node : elements_under_rect) {
    if (found_top_element) {
      break;
    }
    const Element* element = To<Element>(node.Get());
    if (element == top_element)
      found_top_element = true;

    const LayoutObject* layout_object = element->GetLayoutObject();

    if (IsA<HTMLCanvasElement>(element) || IsA<HTMLEmbedElement>(element) ||
        IsA<HTMLImageElement>(element) || IsA<HTMLObjectElement>(element) ||
        IsA<HTMLPictureElement>(element) || element->IsSVGElement() ||
        IsA<HTMLVideoElement>(element)) {
      colors.clear();
      found_opaque_color = false;
      continue;
    }

    const ComputedStyle* style = layout_object->Style();
    if (!style)
      continue;

    // If background elements are hidden, ignore their background colors.
    if (element != top_element && style->Visibility() == EVisibility::kHidden) {
      continue;
    }

    Color background_color =
        style->VisitedDependentColor(GetCSSPropertyBackgroundColor());

    // Opacity applies to the entire element so mix it with the alpha channel.
    if (style->HasOpacity()) {
      background_color.SetAlpha(background_color.Alpha() * style->Opacity());
      // If the background element is the ancestor of the top element or is the
      // top element, the opacity affects the text color of the top element.
      if (element == top_element ||
          FlatTreeTraversal::IsDescendantOf(*top_element, *element)) {
        *text_opacity *= style->Opacity();
      }
    }

    bool found_non_transparent_color = false;
    if (!background_color.IsFullyTransparent()) {
      found_non_transparent_color = true;
      if (!background_color.IsOpaque()) {
        if (colors.empty()) {
          colors.push_back(background_color);
        } else {
          for (auto& color : colors)
            color = color.Blend(background_color);
        }
      } else {
        colors.clear();
        colors.push_back(background_color);
        found_opaque_color = true;
      }
    }

    AddColorsFromImageStyle(*style, *layout_object, colors, found_opaque_color,
                            found_non_transparent_color);

    bool contains = found_top_element || GetNodeRect(node).Contains(rect);
    if (!contains && found_non_transparent_color) {
      // Only return colors if some opaque element covers up this one.
      colors.clear();
      found_opaque_color = false;
    }
  }
  return found_opaque_color;
}

// Sorts unsorted_elements in place, first painted go first.
void InspectorContrast::SortElementsByPaintOrder(
    HeapVector<Member<Node>>& unsorted_elements,
    Document* document) {
  InspectorDOMSnapshotAgent::PaintOrderMap* paint_layer_tree =
      InspectorDOMSnapshotAgent::BuildPaintLayerTree(document);

  std::stable_sort(
      unsorted_elements.begin(), unsorted_elements.end(),
      [&paint_layer_tree = paint_layer_tree](Node* a, Node* b) {
        const LayoutObject* a_layout = To<Element>(a)->GetLayoutObject();
        const LayoutObject* b_layout = To<Element>(b)->GetLayoutObject();
        int a_order = 0;
        int b_order = 0;

        auto a_item = paint_layer_tree->find(a_layout->PaintingLayer());
        if (a_item != paint_layer_tree->end())
          a_order = a_item->value;

        auto b_item = paint_layer_tree->find(b_layout->PaintingLayer());
        if (b_item != paint_layer_tree->end())
          b_order = b_item->value;

        return a_order < b_order;
      });
}

}  // namespace blink
```