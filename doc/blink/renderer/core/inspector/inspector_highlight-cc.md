Response:
My thinking process to answer the request about `inspector_highlight.cc` went through these steps:

1. **Understand the Core Request:** The request asks for the functionalities of the `inspector_highlight.cc` file, its relationship with web technologies (HTML, CSS, JavaScript), potential logical deductions, common usage errors, and a summary of the provided code snippet.

2. **Initial Scan and Keywords:** I quickly scanned the code for prominent keywords and concepts. Words like "inspector," "highlight," "overlay," "CSS," "layout," "DOM," "protocol," "gfx," "SkColor," and various layout-related terms (`LayoutBox`, `LayoutGrid`, `LayoutFlexBox`) stood out. These immediately suggested the file's purpose:  related to the browser's developer tools, specifically the element highlighting feature.

3. **Identify Key Functionalities (High-Level):** Based on the keywords and the file name, I deduced the primary functions:
    * **Highlighting DOM elements:**  This is the most obvious function. The file likely handles drawing visual indicators around elements in the inspected page.
    * **Providing information about highlighted elements:** The presence of `BuildElementInfo` and related functions suggested that the file prepares data to be displayed in the inspector's UI (like size, class names, etc.).
    * **Handling different layout models:** The mentions of Flexbox and Grid layout hinted at specialized highlighting logic for these.
    * **Communicating with the DevTools frontend:**  The use of "protocol" and structures like `protocol::DictionaryValue` pointed to the file's role in sending data to the DevTools frontend.

4. **Detailed Function Analysis (Code Snippet):** I then examined the provided code snippet more closely, focusing on the functions and classes defined:
    * **`PathBuilder` and `ShapePathBuilder`:**  These classes are clearly responsible for generating SVG path data, likely used to draw the highlight outlines. `ShapePathBuilder` specifically deals with shapes defined by CSS `shape-outside`.
    * **Helper functions for Quads and Points:** Functions like `BuildArrayForQuad`, `QuadToPath`, and `FramePointToViewport` indicate the file's manipulation of geometric data to represent element boundaries.
    * **Color Conversion Functions:** `ToHEXA` and `ToRGBAList` show the conversion of color values into formats suitable for the DevTools protocol.
    * **`AppendStyleInfo`:** This function directly links to CSS, extracting computed styles (color, font, margins, padding) to be displayed in the inspector.
    * **`BuildElementInfo`:** This function gathers various element properties (tag name, ID, classes, size, accessibility information) for the inspector.
    * **`BuildTextNodeInfo`:**  A specialized function to get information for text nodes.
    * **`Build...HighlightConfigInfo` functions (Flex, Grid, Container Query, Isolation Mode):** These functions demonstrate specific highlighting configurations for different CSS layout features, suggesting detailed visual debugging capabilities.
    * **Grid Layout Helper Functions:** Functions like `TranslateRTLCoordinate`, `GetPositionForTrackAt`, `BuildGridTrackSizes`, and `BuildGridPositiveLineNumberPositions` confirm the file's involvement in visualizing Grid layout structures.

5. **Relating to Web Technologies:**
    * **HTML:** The file directly interacts with the DOM (`Element`, `Text`, `Node`) to identify elements for highlighting and extract their properties. The tag name, ID, and class names are HTML attributes.
    * **CSS:**  The file heavily relies on CSS concepts. It retrieves computed styles, handles different CSS layout models (Flexbox, Grid, `shape-outside`), and converts CSS color values. The highlighting itself is a visual representation of CSS layout and styling.
    * **JavaScript:** While the C++ code doesn't directly execute JavaScript, it provides the *data* that the JavaScript-based DevTools frontend uses to display the highlighting and related information. The DevTools protocol acts as the communication bridge.

6. **Logical Deductions (Hypothetical Inputs and Outputs):** I considered how the functions might operate with specific inputs:
    * **Input:** A specific `Element` object.
    * **Output:**  `BuildElementInfo` would produce a `protocol::DictionaryValue` containing the element's tag name, ID, classes, dimensions, etc.
    * **Input:** A `LayoutGrid` object and highlighting configuration for grid lines.
    * **Output:** Functions like `BuildGridPositiveLineNumberPositions` would generate a list of coordinates for drawing the grid line numbers on the overlay.

7. **Common Usage Errors (Developer Perspective):**  I thought about how developers might misuse or misunderstand the highlighting feature:
    * **Incorrectly assuming highlight reflects *all* styles:** Developers might expect the highlight to show every single style applied, but the tool focuses on layout and key properties.
    * **Misinterpreting highlight colors:** If the highlight colors are customized or default, developers might misinterpret what the different colors represent (e.g., margin vs. padding).
    * **Not understanding the limitations of specific highlights:**  For example, the grid highlighting might not perfectly represent very complex or dynamically changing grid layouts.

8. **Summarization (Part 1):** Finally, I synthesized the information gathered into a concise summary for the first part of the file:  Its core function is to enable the "inspect element" highlighting feature in Chromium's DevTools, focusing on visual representation and providing information about DOM elements based on their layout and styles, particularly for CSS layout mechanisms like Flexbox and Grid. It uses the DevTools protocol to communicate this information to the frontend.

This methodical approach, starting broad and then narrowing down to specifics within the code snippet, allowed me to generate a comprehensive and accurate answer to the request. The key was to understand the context of the file within the larger Chromium project and the purpose of the DevTools.
好的，让我们来分析一下 `blink/renderer/core/inspector/inspector_highlight.cc` 文件的功能。

**功能归纳:**

根据提供的代码片段，`inspector_highlight.cc` 文件的主要功能是**负责在 Chromium 的开发者工具 (DevTools) 中高亮显示 HTML 元素及其相关布局信息**。 它生成用于在浏览器窗口上绘制叠加层 (overlay) 的数据，以便用户可以直观地理解元素的边界、外边距、内边距、内容、形状、以及特定的 CSS 布局特性（如 Flexbox 和 Grid）。

**具体功能点:**

1. **构建高亮显示的路径 (Path Building):**
   - `PathBuilder` 和 `ShapePathBuilder` 类用于创建表示高亮区域形状的路径数据。这些路径可以基于元素的几何形状、`shape-outside` 属性等生成。
   - `AppendPathElement` 等方法用于向路径中添加线段、曲线等元素。
   - `ShapePathBuilder` 特别处理了带有 `shape-outside` 属性的元素的路径构建，它需要将坐标转换到正确的坐标系。

2. **处理不同类型的几何图形 (Geometry Handling):**
   - 提供了将 `gfx::QuadF` (四边形) 转换为路径的方法 (`QuadToPath`)。
   - 提供了将元素的布局信息（如 `PhysicalRect`）转换为可以在屏幕上绘制的四边形的方法。
   - `FramePointToViewport` 和 `FrameQuadToViewport` 等函数负责将元素在文档坐标系中的坐标转换到视口坐标系，以便在屏幕上正确绘制高亮。

3. **提取和格式化元素信息 (Element Information):**
   - `BuildElementInfo` 函数用于提取被高亮元素的各种属性，例如标签名、ID、类名、宽度、高度、是否可聚焦、可访问性名称和角色、布局对象名称等。这些信息会显示在 DevTools 的元素面板中。
   - `AppendStyleInfo` 函数用于提取元素的计算样式信息，例如颜色、字体、内外边距、背景颜色等，并将其格式化为 DevTools 可以理解的数据结构。

4. **支持特定的 CSS 布局高亮 (CSS Layout Highlighting):**
   - 提供了专门的函数来构建 Flexbox 和 Grid 布局的高亮配置信息：
     - `BuildFlexContainerHighlightConfigInfo` 和 `BuildFlexItemHighlightConfigInfo` 用于配置 Flexbox 容器和项目的高亮样式（如边框、分隔线、间距等）。
     - `BuildGridHighlightConfigInfo` 用于配置 Grid 布局的高亮样式（如网格线、间隙、区域名称等）。
   - 这些配置信息允许 DevTools 以可视化的方式展示 Flexbox 和 Grid 布局的结构。

5. **处理颜色和不透明度 (Color and Opacity):**
   - `ToHEXA` 和 `ToRGBAList` 函数用于将 `Color` 对象转换为十六进制字符串和 RGBA 列表，以便在 DevTools 中显示颜色信息。

6. **处理滚动捕捉 (Scroll Snap):**
   - 提供了与滚动捕捉相关的函数，如 `BuildSnapAlignment`，用于提取和格式化元素的滚动捕捉对齐方式信息。

7. **处理容器查询 (Container Queries):**
   - `BuildContainerQueryContainerHighlightConfigInfo` 用于配置容器查询容器的高亮样式。

8. **处理隔离模式 (Isolation Mode):**
   - `BuildIsolationModeHighlightConfigInfo` 用于配置隔离模式下的高亮样式。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

- **HTML:** 该文件处理的是 HTML 元素的高亮显示。`BuildElementInfo` 函数接收 `Element*` 指针作为输入，并从中提取诸如 `tagName` (例如 "div", "p", "span")，`idValue` (例如 "my-element")，`className` (例如 "container item") 等 HTML 属性。
  ```c++
  // 假设输入一个 <div> 元素 <div id="myDiv" class="container box"></div>
  // BuildElementInfo 函数的输出可能包含:
  // {"tagName": "div", "idValue": "myDiv", "className": ".container.box", ...}
  ```

- **CSS:**  该文件会读取和使用元素的 CSS 样式信息进行高亮显示。`AppendStyleInfo` 函数会提取元素的计算样式，例如 `backgroundColor`，`padding`，`margin` 等。
  ```c++
  // 假设输入一个设置了背景颜色和内边距的元素
  // AppendStyleInfo 函数可能会提取并格式化以下 CSS 属性:
  // computed_style->setString("backgroundColor", "#FF0000"); // 如果背景色是红色
  // computed_style->setString("padding", "10px");
  ```
  对于 Flexbox 和 Grid 布局，该文件会根据元素的 CSS 属性（如 `display: flex`, `display: grid`）来确定是否需要应用特定的高亮逻辑，并读取相应的 Flexbox 或 Grid 布局属性（如 `justify-content`, `grid-template-columns`）来生成高亮信息。

- **JavaScript:**  虽然 `inspector_highlight.cc` 是 C++ 代码，但它生成的数据会被 DevTools 的 JavaScript 前端使用来渲染高亮叠加层。DevTools 的前端会通过 Chromium 的调试协议 (DevTools Protocol)  接收来自后端 (包括 `inspector_highlight.cc` 生成的数据) 的信息，并使用 JavaScript 和相关的 Web 技术 (HTML, CSS) 将高亮显示在浏览器窗口中。

**逻辑推理及假设输入与输出:**

假设有一个 `LayoutGrid` 对象，并且启用了 Grid 布局的高亮显示。

- **假设输入:**
  - 一个 `LayoutGrid*` 指针，表示一个应用了 `display: grid` 的 HTML 元素。
  - 一个 `InspectorGridHighlightConfig` 对象，其中 `showGridExtensionLines` 为 `true`，`gridBorderColor` 被设置为红色。
  - 该 Grid 布局具有 3 列和 2 行，并且定义了一些间隙 (gap)。

- **逻辑推理:**
  - `BuildGridHighlightConfigInfo` 函数会根据 `InspectorGridHighlightConfig` 中的设置，创建一个包含高亮样式的 `protocol::DictionaryValue`。
  - 相关的 Grid 布局计算逻辑会确定网格线的准确位置。
  - 代码会生成表示网格线和扩展线的路径数据，并使用红色作为网格边框的颜色。

- **假设输出:**
  - `BuildGridHighlightConfigInfo` 函数会输出一个 `protocol::DictionaryValue`，其中包含 `gridBorderColor` 为红色，`showGridExtensionLines` 为 `true`。
  - 其他函数会生成一系列的坐标点和路径命令，用于绘制红色的网格线和扩展线在屏幕上。

**用户或编程常见的使用错误举例:**

- **用户错误:** 用户可能会误解高亮颜色代表的含义。例如，默认情况下，外边距、边框、内边距和内容区域可能有不同的高亮颜色，用户可能不清楚这些颜色分别代表什么。DevTools 通常会提供图例来帮助用户理解。
- **编程错误:**  在开发与高亮显示相关的代码时，可能会出现以下错误：
  - **坐标转换错误:** 在 `ShapePathBuilder` 中，如果 `ShapeToLayoutObjectPoint` 或 `LocalToAbsolutePoint` 的转换逻辑不正确，会导致 `shape-outside` 的高亮显示位置错误。
  - **样式信息提取错误:** 在 `AppendStyleInfo` 中，如果提取 CSS 属性的方式不正确，可能会导致 DevTools 显示错误的样式信息。例如，错误地使用了非计算样式。
  - **内存管理错误:** 在 C++ 代码中，如果没有正确管理内存 (例如，使用 `new` 但没有 `delete`)，可能会导致内存泄漏。

**总结 (第1部分功能):**

总而言之，提供的代码片段主要负责构建用于高亮显示 DOM 元素以及其基本属性和样式信息的叠加层数据。它涉及几何图形的处理、CSS 样式的提取和格式化，并且为后续在 DevTools 前端渲染高亮奠定了基础。特别是 `PathBuilder` 相关的类和函数，以及 `BuildElementInfo` 和 `AppendStyleInfo` 函数，是理解这部分代码功能的核心。 这部分代码是实现 "检查元素" 功能的重要组成部分。

Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_highlight.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/inspector/inspector_highlight.h"

#include <memory>

#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"
#include "third_party/blink/renderer/core/css/css_grid_auto_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_grid_integer_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_property_name.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/inspector/dom_traversal_utils.h"
#include "third_party/blink/renderer/core/inspector/inspector_dom_agent.h"
#include "third_party/blink/renderer/core/inspector/node_content_visibility_state.h"
#include "third_party/blink/renderer/core/inspector/protocol/overlay.h"
#include "third_party/blink/renderer/core/layout/adjust_for_absolute_zoom.h"
#include "third_party/blink/renderer/core/layout/flex/devtools_flex_info.h"
#include "third_party/blink/renderer/core/layout/flex/layout_flexible_box.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_offset.h"
#include "third_party/blink/renderer/core/layout/grid/layout_grid.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/shapes/shape_outside_info.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/graphics/path.h"
#include "third_party/blink/renderer/platform/text/writing_mode.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "third_party/skia/include/core/SkColor.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/rect_f.h"

namespace blink {

namespace {

class PathBuilder {
  STACK_ALLOCATED();

 public:
  PathBuilder() : path_(protocol::ListValue::create()) {}
  PathBuilder(const PathBuilder&) = delete;
  PathBuilder& operator=(const PathBuilder&) = delete;
  virtual ~PathBuilder() = default;

  std::unique_ptr<protocol::ListValue> Release() { return std::move(path_); }

  void AppendPath(const Path& path, float scale) {
    Path transform_path(path);
    transform_path.Transform(AffineTransform().Scale(scale));
    transform_path.Apply(this, &PathBuilder::AppendPathElement);
  }

 protected:
  virtual gfx::PointF TranslatePoint(const gfx::PointF& point) { return point; }

 private:
  static void AppendPathElement(void* path_builder,
                                const PathElement& path_element) {
    static_cast<PathBuilder*>(path_builder)->AppendPathElement(path_element);
  }

  void AppendPathElement(const PathElement&);
  void AppendPathCommandAndPoints(const char* command,
                                  base::span<const gfx::PointF> points);

  std::unique_ptr<protocol::ListValue> path_;
};

void PathBuilder::AppendPathCommandAndPoints(
    const char* command,
    base::span<const gfx::PointF> points) {
  path_->pushValue(protocol::StringValue::create(command));
  for (const auto& orig_point : points) {
    gfx::PointF point = TranslatePoint(orig_point);
    path_->pushValue(protocol::FundamentalValue::create(point.x()));
    path_->pushValue(protocol::FundamentalValue::create(point.y()));
  }
}

void PathBuilder::AppendPathElement(const PathElement& path_element) {
  switch (path_element.type) {
    // The points member will contain 1 value.
    case kPathElementMoveToPoint:
      AppendPathCommandAndPoints("M", path_element.points);
      break;
    // The points member will contain 1 value.
    case kPathElementAddLineToPoint:
      AppendPathCommandAndPoints("L", path_element.points);
      break;
    // The points member will contain 3 values.
    case kPathElementAddCurveToPoint:
      AppendPathCommandAndPoints("C", path_element.points);
      break;
    // The points member will contain 2 values.
    case kPathElementAddQuadCurveToPoint:
      AppendPathCommandAndPoints("Q", path_element.points);
      break;
    // The points member will contain no values.
    case kPathElementCloseSubpath:
      AppendPathCommandAndPoints("Z", path_element.points);
      break;
  }
}

class ShapePathBuilder : public PathBuilder {
 public:
  ShapePathBuilder(LocalFrameView& view,
                   LayoutObject& layout_object,
                   const ShapeOutsideInfo& shape_outside_info)
      : view_(&view),
        layout_object_(&layout_object),
        shape_outside_info_(shape_outside_info) {}

  static std::unique_ptr<protocol::ListValue> BuildPath(
      LocalFrameView& view,
      LayoutObject& layout_object,
      const ShapeOutsideInfo& shape_outside_info,
      const Path& path,
      float scale) {
    ShapePathBuilder builder(view, layout_object, shape_outside_info);
    builder.AppendPath(path, scale);
    return builder.Release();
  }

 protected:
  gfx::PointF TranslatePoint(const gfx::PointF& point) override {
    PhysicalOffset layout_object_point = PhysicalOffset::FromPointFRound(
        shape_outside_info_.ShapeToLayoutObjectPoint(point));
    // TODO(pfeldman): Is this kIgnoreTransforms correct?
    return gfx::PointF(view_->FrameToViewport(
        ToRoundedPoint(layout_object_->LocalToAbsolutePoint(
            layout_object_point, kIgnoreTransforms))));
  }

 private:
  LocalFrameView* view_;
  LayoutObject* const layout_object_;
  const ShapeOutsideInfo& shape_outside_info_;
};

std::unique_ptr<protocol::Array<double>> BuildArrayForQuad(
    const gfx::QuadF& quad) {
  return std::make_unique<std::vector<double>, std::initializer_list<double>>(
      {quad.p1().x(), quad.p1().y(), quad.p2().x(), quad.p2().y(),
       quad.p3().x(), quad.p3().y(), quad.p4().x(), quad.p4().y()});
}

Path QuadToPath(const gfx::QuadF& quad) {
  Path quad_path;
  quad_path.MoveTo(quad.p1());
  quad_path.AddLineTo(quad.p2());
  quad_path.AddLineTo(quad.p3());
  quad_path.AddLineTo(quad.p4());
  quad_path.CloseSubpath();
  return quad_path;
}

Path RowQuadToPath(const gfx::QuadF& quad, bool draw_end_line) {
  Path quad_path;
  quad_path.MoveTo(quad.p1());
  quad_path.AddLineTo(quad.p2());
  if (draw_end_line) {
    quad_path.MoveTo(quad.p3());
    quad_path.AddLineTo(quad.p4());
  }
  return quad_path;
}

Path ColumnQuadToPath(const gfx::QuadF& quad, bool draw_end_line) {
  Path quad_path;
  quad_path.MoveTo(quad.p1());
  quad_path.AddLineTo(quad.p4());
  if (draw_end_line) {
    quad_path.MoveTo(quad.p3());
    quad_path.AddLineTo(quad.p2());
  }
  return quad_path;
}

gfx::PointF FramePointToViewport(const LocalFrameView* view,
                                 gfx::PointF point_in_frame) {
  gfx::PointF point_in_root_frame = view->ConvertToRootFrame(point_in_frame);
  return view->GetPage()->GetVisualViewport().RootFrameToViewport(
      point_in_root_frame);
}

float PageScaleFromFrameView(const LocalFrameView* frame_view) {
  return 1.f / frame_view->GetPage()->GetVisualViewport().Scale();
}

float DeviceScaleFromFrameView(const LocalFrameView* frame_view) {
  return 1.f / frame_view->GetChromeClient()->WindowToViewportScalar(
                   &frame_view->GetFrame(), 1.f);
}

void FrameQuadToViewport(const LocalFrameView* view, gfx::QuadF& quad) {
  quad.set_p1(FramePointToViewport(view, quad.p1()));
  quad.set_p2(FramePointToViewport(view, quad.p2()));
  quad.set_p3(FramePointToViewport(view, quad.p3()));
  quad.set_p4(FramePointToViewport(view, quad.p4()));
}

const ShapeOutsideInfo* ShapeOutsideInfoForNode(Node* node,
                                                Shape::DisplayPaths* paths,
                                                gfx::QuadF* bounds) {
  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object || !layout_object->IsBox() ||
      !To<LayoutBox>(layout_object)->GetShapeOutsideInfo())
    return nullptr;

  LocalFrameView* containing_view = node->GetDocument().View();
  auto* layout_box = To<LayoutBox>(layout_object);
  const ShapeOutsideInfo* shape_outside_info =
      layout_box->GetShapeOutsideInfo();

  shape_outside_info->ComputedShape().BuildDisplayPaths(*paths);

  PhysicalRect shape_bounds =
      shape_outside_info->ComputedShapePhysicalBoundingBox();
  *bounds = layout_box->LocalRectToAbsoluteQuad(shape_bounds);
  FrameQuadToViewport(containing_view, *bounds);

  return shape_outside_info;
}

String ToHEXA(const Color& color) {
  return String::Format("#%02X%02X%02X%02X", color.Red(), color.Green(),
                        color.Blue(), color.AlphaAsInteger());
}

std::unique_ptr<protocol::ListValue> ToRGBAList(const Color& color) {
  SkColor4f skColor = color.toSkColor4f();

  std::unique_ptr<protocol::ListValue> list = protocol::ListValue::create();
  list->pushValue(protocol::FundamentalValue::create(skColor.fR));
  list->pushValue(protocol::FundamentalValue::create(skColor.fG));
  list->pushValue(protocol::FundamentalValue::create(skColor.fB));
  list->pushValue(protocol::FundamentalValue::create(skColor.fA));
  return list;
}

namespace ContrastAlgorithmEnum = protocol::Overlay::ContrastAlgorithmEnum;

String ContrastAlgorithmToString(const ContrastAlgorithm& contrast_algorithm) {
  // It reuses the protocol string constants to avoid duplicating the string
  // values. These string values are sent to the overlay code that is expected
  // to handle them properly.
  switch (contrast_algorithm) {
    case ContrastAlgorithm::kAa:
      return ContrastAlgorithmEnum::Aa;
    case ContrastAlgorithm::kAaa:
      return ContrastAlgorithmEnum::Aaa;
    case ContrastAlgorithm::kApca:
      return ContrastAlgorithmEnum::Apca;
  }
}
}  // namespace

void AppendStyleInfo(Element* element,
                     protocol::DictionaryValue* element_info,
                     const InspectorHighlightContrastInfo& node_contrast,
                     const ContrastAlgorithm& contrast_algorithm) {
  std::unique_ptr<protocol::DictionaryValue> computed_style =
      protocol::DictionaryValue::create();
  CSSComputedStyleDeclaration* style =
      MakeGarbageCollected<CSSComputedStyleDeclaration>(element, true);
  Vector<CSSPropertyID> properties;

  // For text nodes, we can show color & font properties.
  bool has_text_children = false;
  for (Node* child = element->firstChild(); !has_text_children && child;
       child = child->nextSibling()) {
    has_text_children = child->IsTextNode();
  }
  if (has_text_children) {
    properties.push_back(CSSPropertyID::kColor);
    properties.push_back(CSSPropertyID::kFontFamily);
    properties.push_back(CSSPropertyID::kFontSize);
    properties.push_back(CSSPropertyID::kLineHeight);
  }

  properties.push_back(CSSPropertyID::kPadding);
  properties.push_back(CSSPropertyID::kMargin);
  properties.push_back(CSSPropertyID::kBackgroundColor);

  for (wtf_size_t i = 0; i < properties.size(); ++i) {
    const CSSValue* value = style->GetPropertyCSSValue(properties[i]);
    if (!value)
      continue;
    AtomicString name = CSSPropertyName(properties[i]).ToAtomicString();
    if (value->IsColorValue()) {
      Color color = static_cast<const cssvalue::CSSColor*>(value)->Value();
      computed_style->setArray(name + "-unclamped-rgba", ToRGBAList(color));
      if (!Color::IsLegacyColorSpace(color.GetColorSpace())) {
        computed_style->setString(name + "-css-text", value->CssText());
      }
      computed_style->setString(name, ToHEXA(color));
    } else {
      computed_style->setString(name, value->CssText());
    }
  }
  element_info->setValue("style", std::move(computed_style));

  if (!node_contrast.font_size.empty()) {
    std::unique_ptr<protocol::DictionaryValue> contrast =
        protocol::DictionaryValue::create();
    contrast->setString("fontSize", node_contrast.font_size);
    contrast->setString("fontWeight", node_contrast.font_weight);
    contrast->setString("backgroundColor",
                        ToHEXA(node_contrast.background_color));
    contrast->setArray("backgroundColorUnclampedRgba",
                       ToRGBAList(node_contrast.background_color));
    contrast->setString("backgroundColorCssText",
                        node_contrast.background_color.SerializeAsCSSColor());
    contrast->setString("contrastAlgorithm",
                        ContrastAlgorithmToString(contrast_algorithm));
    contrast->setDouble("textOpacity", node_contrast.text_opacity);
    element_info->setValue("contrast", std::move(contrast));
  }
}

std::unique_ptr<protocol::DictionaryValue> BuildElementInfo(Element* element) {
  std::unique_ptr<protocol::DictionaryValue> element_info =
      protocol::DictionaryValue::create();
  Element* real_element = element;
  auto* pseudo_element = DynamicTo<PseudoElement>(element);
  if (pseudo_element) {
    real_element = element->ParentOrShadowHostElement();
  }
  bool is_xhtml = real_element->GetDocument().IsXHTMLDocument();
  element_info->setString(
      "tagName", is_xhtml ? real_element->nodeName()
                          : real_element->nodeName().DeprecatedLower());
  element_info->setString("idValue", real_element->GetIdAttribute());
  StringBuilder class_names;
  if (real_element->HasClass() && real_element->IsStyledElement()) {
    HashSet<AtomicString> used_class_names;
    const SpaceSplitString& class_names_string = real_element->ClassNames();
    wtf_size_t class_name_count = class_names_string.size();
    for (wtf_size_t i = 0; i < class_name_count; ++i) {
      const AtomicString& class_name = class_names_string[i];
      if (!used_class_names.insert(class_name).is_new_entry)
        continue;
      class_names.Append('.');
      class_names.Append(class_name);
    }
  }
  if (pseudo_element) {
    if (pseudo_element->GetPseudoId() == kPseudoIdCheck) {
      class_names.Append("::check");
    } else if (pseudo_element->GetPseudoId() == kPseudoIdBefore) {
      class_names.Append("::before");
    } else if (pseudo_element->GetPseudoId() == kPseudoIdAfter) {
      class_names.Append("::after");
    } else if (pseudo_element->GetPseudoId() == kPseudoIdSelectArrow) {
      class_names.Append("::select-arrow");
    } else if (pseudo_element->GetPseudoId() == kPseudoIdMarker) {
      class_names.Append("::marker");
    } else if (pseudo_element->GetPseudoIdForStyling() ==
               kPseudoIdScrollMarkerGroup) {
      class_names.Append("::scroll-marker-group");
    } else if (pseudo_element->GetPseudoId() == kPseudoIdScrollMarker) {
      class_names.Append("::scroll-marker");
    } else if (pseudo_element->GetPseudoId() == kPseudoIdScrollNextButton) {
      class_names.Append("::scroll-next-button");
    } else if (pseudo_element->GetPseudoId() == kPseudoIdScrollPrevButton) {
      class_names.Append("::scroll-prev-button");
    }
  }
  if (!class_names.empty())
    element_info->setString("className", class_names.ToString());

  LayoutObject* layout_object = element->GetLayoutObject();
  LocalFrameView* containing_view = element->GetDocument().View();
  if (!layout_object || !containing_view)
    return element_info;

  // layoutObject the GetBoundingClientRect() data in the tooltip
  // to be consistent with the rulers (see http://crbug.com/262338).

  DCHECK(element->GetDocument().Lifecycle().GetState() >=
         DocumentLifecycle::kLayoutClean);
  gfx::RectF bounding_box = element->GetBoundingClientRectNoLifecycleUpdate();
  element_info->setString("nodeWidth", String::Number(bounding_box.width()));
  element_info->setString("nodeHeight", String::Number(bounding_box.height()));

  element_info->setBoolean("isKeyboardFocusable",
                           element->IsKeyboardFocusable());
  element_info->setString("accessibleName",
                          element->ComputedNameNoLifecycleUpdate());
  element_info->setString("accessibleRole",
                          element->ComputedRoleNoLifecycleUpdate());

  element_info->setString("layoutObjectName", layout_object->GetName());

  return element_info;
}

namespace {
std::unique_ptr<protocol::DictionaryValue> BuildTextNodeInfo(Text* text_node) {
  std::unique_ptr<protocol::DictionaryValue> text_info =
      protocol::DictionaryValue::create();
  LayoutObject* layout_object = text_node->GetLayoutObject();
  if (!layout_object || !layout_object->IsText())
    return text_info;
  PhysicalRect bounding_box =
      To<LayoutText>(layout_object)->VisualOverflowRect();
  text_info->setString("nodeWidth", bounding_box.Width().ToString());
  text_info->setString("nodeHeight", bounding_box.Height().ToString());
  text_info->setString("tagName", "#text");
  text_info->setBoolean("showAccessibilityInfo", false);
  return text_info;
}

void AppendLineStyleConfig(
    const std::optional<LineStyle>& line_style,
    std::unique_ptr<protocol::DictionaryValue>& parent_config,
    String line_name) {
  if (!line_style || line_style->IsFullyTransparent()) {
    return;
  }

  std::unique_ptr<protocol::DictionaryValue> config =
      protocol::DictionaryValue::create();
  config->setString("color", line_style->color.SerializeAsCSSColor());
  config->setString("pattern", line_style->pattern);

  parent_config->setValue(line_name, std::move(config));
}

void AppendBoxStyleConfig(
    const std::optional<BoxStyle>& box_style,
    std::unique_ptr<protocol::DictionaryValue>& parent_config,
    String box_name) {
  if (!box_style || box_style->IsFullyTransparent()) {
    return;
  }

  std::unique_ptr<protocol::DictionaryValue> config =
      protocol::DictionaryValue::create();
  config->setString("fillColor", box_style->fill_color.SerializeAsCSSColor());
  config->setString("hatchColor", box_style->hatch_color.SerializeAsCSSColor());

  parent_config->setValue(box_name, std::move(config));
}

std::unique_ptr<protocol::DictionaryValue>
BuildFlexContainerHighlightConfigInfo(
    const InspectorFlexContainerHighlightConfig& flex_config) {
  std::unique_ptr<protocol::DictionaryValue> flex_config_info =
      protocol::DictionaryValue::create();

  AppendLineStyleConfig(flex_config.container_border, flex_config_info,
                        "containerBorder");
  AppendLineStyleConfig(flex_config.line_separator, flex_config_info,
                        "lineSeparator");
  AppendLineStyleConfig(flex_config.item_separator, flex_config_info,
                        "itemSeparator");

  AppendBoxStyleConfig(flex_config.main_distributed_space, flex_config_info,
                       "mainDistributedSpace");
  AppendBoxStyleConfig(flex_config.cross_distributed_space, flex_config_info,
                       "crossDistributedSpace");
  AppendBoxStyleConfig(flex_config.row_gap_space, flex_config_info,
                       "rowGapSpace");
  AppendBoxStyleConfig(flex_config.column_gap_space, flex_config_info,
                       "columnGapSpace");
  AppendLineStyleConfig(flex_config.cross_alignment, flex_config_info,
                        "crossAlignment");

  return flex_config_info;
}

std::unique_ptr<protocol::DictionaryValue> BuildFlexItemHighlightConfigInfo(
    const InspectorFlexItemHighlightConfig& flex_config) {
  std::unique_ptr<protocol::DictionaryValue> flex_config_info =
      protocol::DictionaryValue::create();

  AppendBoxStyleConfig(flex_config.base_size_box, flex_config_info,
                       "baseSizeBox");
  AppendLineStyleConfig(flex_config.base_size_border, flex_config_info,
                        "baseSizeBorder");
  AppendLineStyleConfig(flex_config.flexibility_arrow, flex_config_info,
                        "flexibilityArrow");

  return flex_config_info;
}

std::unique_ptr<protocol::DictionaryValue> BuildGridHighlightConfigInfo(
    const InspectorGridHighlightConfig& grid_config) {
  std::unique_ptr<protocol::DictionaryValue> grid_config_info =
      protocol::DictionaryValue::create();
  grid_config_info->setBoolean("gridBorderDash", grid_config.grid_border_dash);
  grid_config_info->setBoolean("rowLineDash", grid_config.row_line_dash);
  grid_config_info->setBoolean("columnLineDash", grid_config.column_line_dash);
  grid_config_info->setBoolean("showGridExtensionLines",
                               grid_config.show_grid_extension_lines);
  grid_config_info->setBoolean("showPositiveLineNumbers",
                               grid_config.show_positive_line_numbers);
  grid_config_info->setBoolean("showNegativeLineNumbers",
                               grid_config.show_negative_line_numbers);
  grid_config_info->setBoolean("showAreaNames", grid_config.show_area_names);
  grid_config_info->setBoolean("showLineNames", grid_config.show_line_names);

  if (grid_config.grid_color != Color::kTransparent) {
    grid_config_info->setString("gridBorderColor",
                                grid_config.grid_color.SerializeAsCSSColor());
  }
  if (grid_config.row_line_color != Color::kTransparent) {
    grid_config_info->setString(
        "rowLineColor", grid_config.row_line_color.SerializeAsCSSColor());
  }
  if (grid_config.column_line_color != Color::kTransparent) {
    grid_config_info->setString(
        "columnLineColor", grid_config.column_line_color.SerializeAsCSSColor());
  }
  if (grid_config.row_gap_color != Color::kTransparent) {
    grid_config_info->setString(
        "rowGapColor", grid_config.row_gap_color.SerializeAsCSSColor());
  }
  if (grid_config.column_gap_color != Color::kTransparent) {
    grid_config_info->setString(
        "columnGapColor", grid_config.column_gap_color.SerializeAsCSSColor());
  }
  if (grid_config.row_hatch_color != Color::kTransparent) {
    grid_config_info->setString(
        "rowHatchColor", grid_config.row_hatch_color.SerializeAsCSSColor());
  }
  if (grid_config.column_hatch_color != Color::kTransparent) {
    grid_config_info->setString(
        "columnHatchColor",
        grid_config.column_hatch_color.SerializeAsCSSColor());
  }
  if (grid_config.area_border_color != Color::kTransparent) {
    grid_config_info->setString(
        "areaBorderColor", grid_config.area_border_color.SerializeAsCSSColor());
  }
  if (grid_config.grid_background_color != Color::kTransparent) {
    grid_config_info->setString(
        "gridBackgroundColor",
        grid_config.grid_background_color.SerializeAsCSSColor());
  }
  return grid_config_info;
}

std::unique_ptr<protocol::DictionaryValue>
BuildContainerQueryContainerHighlightConfigInfo(
    const InspectorContainerQueryContainerHighlightConfig& container_config) {
  std::unique_ptr<protocol::DictionaryValue> container_config_info =
      protocol::DictionaryValue::create();

  AppendLineStyleConfig(container_config.container_border,
                        container_config_info, "containerBorder");
  AppendLineStyleConfig(container_config.descendant_border,
                        container_config_info, "descendantBorder");

  return container_config_info;
}

std::unique_ptr<protocol::DictionaryValue>
BuildIsolationModeHighlightConfigInfo(
    const InspectorIsolationModeHighlightConfig& config) {
  std::unique_ptr<protocol::DictionaryValue> config_info =
      protocol::DictionaryValue::create();

  config_info->setString("resizerColor",
                         config.resizer_color.SerializeAsCSSColor());
  config_info->setString("resizerHandleColor",
                         config.resizer_handle_color.SerializeAsCSSColor());
  config_info->setString("maskColor", config.mask_color.SerializeAsCSSColor());

  return config_info;
}

// Swaps |left| and |top| of an offset.
PhysicalOffset Transpose(PhysicalOffset& offset) {
  return PhysicalOffset(offset.top, offset.left);
}

LayoutUnit TranslateRTLCoordinate(const LayoutObject* layout_object,
                                  LayoutUnit position,
                                  const Vector<LayoutUnit>& column_positions) {
  // This should only be called on grid layout objects.
  DCHECK(layout_object->IsLayoutGrid());
  DCHECK(!layout_object->StyleRef().IsLeftToRightDirection());

  LayoutUnit alignment_offset = column_positions.front();
  LayoutUnit right_grid_edge_position = column_positions.back();
  return right_grid_edge_position + alignment_offset - position;
}

LayoutUnit GetPositionForTrackAt(const LayoutObject* layout_object,
                                 wtf_size_t index,
                                 GridTrackSizingDirection direction,
                                 const Vector<LayoutUnit>& positions) {
  if (direction == kForRows)
    return positions.at(index);

  LayoutUnit position = positions.at(index);
  return layout_object->StyleRef().IsLeftToRightDirection()
             ? position
             : TranslateRTLCoordinate(layout_object, position, positions);
}

LayoutUnit GetPositionForFirstTrack(const LayoutObject* layout_object,
                                    GridTrackSizingDirection direction,
                                    const Vector<LayoutUnit>& positions) {
  return GetPositionForTrackAt(layout_object, 0, direction, positions);
}

LayoutUnit GetPositionForLastTrack(const LayoutObject* layout_object,
                                   GridTrackSizingDirection direction,
                                   const Vector<LayoutUnit>& positions) {
  wtf_size_t index = positions.size() - 1;
  return GetPositionForTrackAt(layout_object, index, direction, positions);
}

PhysicalOffset LocalToAbsolutePoint(Node* node,
                                    PhysicalOffset local,
                                    float scale) {
  LayoutObject* layout_object = node->GetLayoutObject();
  PhysicalOffset abs_point = layout_object->LocalToAbsolutePoint(local);
  gfx::PointF abs_point_in_viewport = FramePointToViewport(
      node->GetDocument().View(), gfx::PointF(abs_point.left, abs_point.top));
  PhysicalOffset scaled_abs_point =
      PhysicalOffset::FromPointFRound(abs_point_in_viewport);
  scaled_abs_point.Scale(scale);
  return scaled_abs_point;
}

String SnapAlignToString(const cc::SnapAlignment& value) {
  switch (value) {
    case cc::SnapAlignment::kNone:
      return "none";
    case cc::SnapAlignment::kStart:
      return "start";
    case cc::SnapAlignment::kEnd:
      return "end";
    case cc::SnapAlignment::kCenter:
      return "center";
  }
}

std::unique_ptr<protocol::ListValue> BuildPathFromQuad(
    const blink::LocalFrameView* containing_view,
    gfx::QuadF quad) {
  FrameQuadToViewport(containing_view, quad);
  PathBuilder builder;
  builder.AppendPath(QuadToPath(quad),
                     DeviceScaleFromFrameView(containing_view));
  return builder.Release();
}

void BuildSnapAlignment(const cc::ScrollSnapType& snap_type,
                        const cc::SnapAlignment& alignment_block,
                        const cc::SnapAlignment& alignment_inline,
                        std::unique_ptr<protocol::DictionaryValue>& result) {
  if (snap_type.axis == cc::SnapAxis::kBlock ||
      snap_type.axis == cc::SnapAxis::kBoth ||
      snap_type.axis == cc::SnapAxis::kY) {
    result->setString("alignBlock", SnapAlignToString(alignment_block));
  }
  if (snap_type.axis == cc::SnapAxis::kInline ||
      snap_type.axis == cc::SnapAxis::kBoth ||
      snap_type.axis == cc::SnapAxis::kX) {
    result->setString("alignInline", SnapAlignToString(alignment_inline));
  }
}

std::unique_ptr<protocol::DictionaryValue> BuildPosition(
    PhysicalOffset position) {
  std::unique_ptr<protocol::DictionaryValue> result =
      protocol::DictionaryValue::create();
  result->setDouble("x", position.left);
  result->setDouble("y", position.top);
  return result;
}

std::unique_ptr<protocol::ListValue> BuildGridTrackSizes(
    Node* node,
    GridTrackSizingDirection direction,
    float scale,
    LayoutUnit gap,
    LayoutUnit rtl_offset,
    const Vector<LayoutUnit>& positions,
    const Vector<LayoutUnit>& alt_axis_positions,
    const Vector<String>* authored_values) {
  LayoutObject* layout_object = node->GetLayoutObject();
  bool is_rtl = !layout_object->StyleRef().IsLeftToRightDirection();

  std::unique_ptr<protocol::ListValue> sizes = protocol::ListValue::create();
  wtf_size_t track_count = positions.size();
  LayoutUnit alt_axis_pos = GetPositionForFirstTrack(
      layout_object, direction == kForRows ? kForColumns : kForRows,
      alt_axis_positions);
  if (is_rtl && direction == kForRows)
    alt_axis_pos += rtl_offset;

  for (wtf_size_t i = 1; i < track_count; i++) {
    LayoutUnit current_position =
        GetPositionForTrackAt(layout_object, i, direction, positions);
    LayoutUnit prev_position =
        GetPositionForTrackAt(layout_object, i - 1, direction, positions);

    LayoutUnit gap_offset = i < track_count - 1 ? gap : LayoutUnit();
    LayoutUnit width = current_position - prev_position - gap_offset;
    if (is_rtl && direction == kForColumns)
      width = prev_position - current_position - gap_offset;
    LayoutUnit main_axis_pos = prev_position + width / 2;
    if (is_rtl && direction == kForColumns)
      main_axis_pos = rtl_offset + prev_position - width / 2;
    auto adjusted_size = AdjustForAbsoluteZoom::AdjustFloat(
        width * scale, layout_object->StyleRef());
    PhysicalOffset track_size_pos(main_axis_pos, alt_axis_pos);
    if (direction == kForRows)
      track_size_pos = Transpose(track_size_pos);
    std::unique_ptr<protocol::DictionaryValue> size_info =
        BuildPosition(LocalToAbsolutePoint(node, track_size_pos, scale));
    size_info->setDouble("computedSize", adjusted_size);
    if (i - 1 < authored_values->size()) {
      size_info->setString("authoredSize", authored_values->at(i - 1));
    }
    sizes->pushValue(std::move(size_info));
  }

  return sizes;
}

std::unique_ptr<protocol::ListValue> BuildGridPositiveLineNumberPositions(
    Node* node,
    const LayoutUnit& grid_gap,
    GridTrackSizingDirection direction,
    float scale,
    LayoutUnit rtl_offset,
    const Vector<LayoutUnit>& positions,
    const Vector<LayoutUnit>& alt_axis_positions) {
  auto* grid = To<LayoutGrid>(node->GetLayoutObject());
  bool is_rtl = !grid->StyleRef().IsLeftToRightDirection();

  std::unique_ptr<protocol::ListValue> number_positions =
      protocol::ListValue::create();

  wtf_size_t track_count = positions.size();
  LayoutUnit alt_axis_pos = GetPositionForFirstTrack(
      grid, direction == kForRows ? kForColumns : kForRows, alt_axis_positions);

  if (is_rtl && direction == kForRows)
    alt_axis_pos += rtl_offset;

  // Find index of the first explicit Grid Line.
  wtf_size_t first_explicit_index =
      grid->ExplicitGridStartForDirection(direction);

  // Go line by line, calculating the offset to fall in the middle of gaps
  // if needed.
  for (wtf_size_t i = first_explicit_index; i < track_count; ++i) {
    LayoutUnit gapOffset = grid_gap / 2;
    if (is_rtl && direction == kForColumns)
      gapOffset *= -1;
    // No need for a gap offset if there is no gap, or the first line is
    // explicit, or this is the last line.
    if (grid_gap == 0 || i == 0 || i == track_count - 1) {
      gapOffset = LayoutUnit();
    }
    LayoutUnit offset = GetPositionForTrackAt(grid, i, direction, positions);
    if (is_rtl && direction == kForColumns)
      offset += rtl_offset;
    PhysicalOffset number_position(offset - gapOffset, alt_axis_pos);
    if (direction == kForRows)
      number_position = Transpose(number_position);
    number_positions->pushValue(
        BuildPosition(LocalToAbsolutePoint(node, number_position, scale)));
  }

  return number_positions;
}

std::unique_ptr<protocol::ListValue> BuildGridNegativeLineNumberPositions(
    Node* node,
    const LayoutUnit& grid_gap,
    GridTrackSizingDirection direction,
    float scale,
    Layou
"""


```