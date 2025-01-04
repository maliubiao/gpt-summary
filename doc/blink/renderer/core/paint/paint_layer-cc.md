Response:
My thought process to answer the request about the `paint_layer.cc` file goes like this:

1. **Understand the Goal:** The user wants a summary of the file's functionality, specifically highlighting connections to web technologies (JavaScript, HTML, CSS), providing examples, considering common errors, and explaining how a user might reach this code.

2. **Initial Scan and Keyword Spotting:** I quickly read through the provided header comments and the included headers. Keywords that jump out are:
    * **PaintLayer:** This is clearly the central entity.
    * **Paint:**  Suggests responsibility for rendering.
    * **Layout:**  Indicates interaction with the layout engine.
    * **CSS/Style:**  Strong connection to styling.
    * **Transform:**  Implicates CSS transformations.
    * **Clip:**  Suggests clipping regions.
    * **Filter:** Points to CSS filters.
    * **Scroll:**  Relates to scrolling behavior.
    * **Compositing:**  A key optimization for performance.
    * **Hit Testing:**  Handling user interactions (like clicks).

3. **Core Functionality Deduction:** Based on the keywords, I can infer the core functions of `PaintLayer`:
    * **Representation:**  It's a data structure representing a layer in the rendering process.
    * **Styling Application:** It stores and applies styling information from CSS.
    * **Transformation Management:** It handles CSS transformations (translate, rotate, scale).
    * **Clipping:**  It manages how content is clipped.
    * **Filtering:** It applies CSS filters and backdrop filters.
    * **Scrolling:** It interacts with scrollable areas.
    * **Compositing Control:** It plays a role in determining which parts of the page are composited for better performance.
    * **Hit Testing Support:** It helps determine which element the user interacts with.

4. **Relationship to Web Technologies:**

    * **HTML:**  `PaintLayer`s are created for elements in the HTML document. The structure of `PaintLayer`s mirrors the DOM tree to some extent.
    * **CSS:** This is a very strong relationship. CSS properties (like `transform`, `clip-path`, `filter`, `opacity`, `z-index`, `position`, `overflow`, etc.) directly influence the creation, properties, and behavior of `PaintLayer`s.
    * **JavaScript:** JavaScript can manipulate the DOM and CSS, indirectly affecting `PaintLayer`s. Animations and dynamic style changes in JavaScript will trigger updates to `PaintLayer` properties and potentially their structure.

5. **Examples:**  To illustrate the relationships, I need concrete examples:

    * **CSS Transform:**  `transform: rotate(45deg);` creates a `PaintLayer` (if one doesn't exist already) and sets its transform property.
    * **CSS Clip-path:** `clip-path: circle(50%);`  affects the clipping region of a `PaintLayer`.
    * **CSS Filter:** `filter: blur(5px);` applies a blur effect via the `PaintLayer`.
    * **CSS `overflow: scroll;`:**  Creates a scrollable area managed by the `PaintLayer`.
    * **JavaScript Animation:**  `element.style.opacity = 0.5;` or using the Web Animations API will trigger `PaintLayer` updates.

6. **Logical Reasoning (Hypothetical Input/Output):** This is about demonstrating how the `PaintLayer` might process data.

    * **Input:** A CSS rule `transform: translateX(10px);` applied to an HTML element.
    * **Processing:** The browser's style engine calculates the transform. The `PaintLayer` associated with the element receives this information and updates its internal transform matrix.
    * **Output:** When the page is painted, the element is rendered with the 10px horizontal translation.

7. **Common Usage Errors:** These are situations where a developer's actions might lead to unexpected rendering behavior or trigger code in `paint_layer.cc`.

    * **Incorrect `z-index`:**  Misunderstanding stacking contexts can lead to elements being hidden unexpectedly.
    * **Forgetting `position: relative/absolute` for `z-index`:**  `z-index` only works on positioned elements.
    * **Performance issues with excessive filters/compositing:** Overusing these features can strain rendering performance.
    * **Conflicting transformations:**  Applying multiple transformations without understanding their order can lead to unexpected results.

8. **User Actions and Debugging:**  How does a user end up triggering code in `paint_layer.cc`?  This is about the user's interaction leading to rendering events.

    * **Page Load:** The initial rendering of the page creates and configures `PaintLayer`s.
    * **Scrolling:** Triggers updates to scroll positions within `PaintLayer`s.
    * **Mouse Hover/Click:** Initiates hit testing, involving `PaintLayer`s.
    * **Resizing the window:**  Can cause layout changes and `PaintLayer` updates.
    * **JavaScript interactions:**  As mentioned before, dynamic changes.

    For debugging, I'd mention using the browser's developer tools (especially the Layers panel) to inspect `PaintLayer`s and their properties.

9. **Structure and Flow:**  I organize the information logically, starting with the main function, then delving into relationships, examples, errors, and debugging. I also make sure to address all parts of the user's prompt.

10. **Refinement and Language:** I review the generated text, ensuring it's clear, concise, and uses appropriate technical terminology. I also make sure the tone is helpful and informative. For example, I explicitly label assumptions when making inferences. I also ensure I'm not just listing keywords but explaining their significance in the context of `PaintLayer`.

By following these steps, I can construct a comprehensive and accurate answer that addresses all aspects of the user's request about the `paint_layer.cc` file. The process involves understanding the code's purpose, connecting it to relevant web technologies, providing illustrative examples, and considering practical developer scenarios.
```
文件功能归纳：

`blink/renderer/core/paint/paint_layer.cc` 文件是 Chromium Blink 渲染引擎中的核心组件，它定义了 `PaintLayer` 类。`PaintLayer` 对象是渲染过程中用于组织和管理页面元素绘制顺序、应用视觉效果（如变换、裁剪、滤镜等）以及处理滚动等交互的关键数据结构。

**核心功能总结：**

1. **表示渲染层：** `PaintLayer` 是一个用于表示页面元素渲染层的数据结构。每个 `LayoutBoxModelObject` (布局对象) 可以拥有一个关联的 `PaintLayer`。
2. **管理绘制属性：**  它存储和管理与绘制相关的各种属性，例如变换 (transform)、裁剪路径 (clip path)、滤镜 (filter)、滚动 (scroll) 信息、透明度 (opacity) 等。
3. **组织层级结构：** `PaintLayer` 对象通过父子关系组织成树状结构，反映了页面元素的层叠上下文和包含关系。
4. **控制绘制顺序：**  通过维护子 `PaintLayer` 的列表，它控制着子元素在屏幕上的绘制顺序。
5. **处理视觉效果：** 它负责应用 CSS 样式中定义的各种视觉效果，例如变换、裁剪、滤镜和混合模式等。
6. **支持滚动：**  对于可滚动元素，它关联一个 `PaintLayerScrollableArea` 对象来管理滚动条和滚动行为。
7. **参与合成 (Compositing)：**  `PaintLayer` 是合成的关键组成部分，它决定哪些部分需要被提升为独立的合成层，以提高渲染性能。
8. **进行命中测试 (Hit Testing)：**  它参与确定用户交互（例如鼠标点击）发生在哪个元素上。
9. **管理重绘 (Repaint)：**  它跟踪自身及其子树是否需要重绘。
10. **维护各种状态标志：**  它包含许多布尔标志，用于跟踪其自身和后代的状态，例如是否需要更新子树依赖的标志、是否需要重新计算视觉溢出、是否存在 3D 变换的后代等等。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:**  每个需要渲染的 HTML 元素（通常对应一个 `LayoutBoxModelObject`）都会关联一个 `PaintLayer` 对象。`PaintLayer` 的树形结构在很大程度上反映了 HTML 的 DOM 树结构。
    * **举例：**  一个 `<div>` 元素在 HTML 中定义，Blink 引擎会为其创建一个 `LayoutBoxModelObject`，并可能创建一个关联的 `PaintLayer`。

* **CSS:**  CSS 样式是 `PaintLayer` 属性值的来源。CSS 属性（如 `transform`, `clip-path`, `filter`, `opacity`, `z-index`, `position`, `overflow` 等）会直接影响 `PaintLayer` 的属性和行为。
    * **举例：**
        * CSS `transform: rotate(45deg);` 会导致 `PaintLayer` 的 `transform_` 成员被设置为对应的旋转变换矩阵。
        * CSS `clip-path: circle(50%);` 会影响 `PaintLayer` 的裁剪区域。
        * CSS `filter: blur(5px);` 会导致 `PaintLayer` 需要应用模糊滤镜。
        * CSS `overflow: scroll;` 会触发 `PaintLayer` 创建并关联一个 `PaintLayerScrollableArea` 对象。
        * CSS `position: fixed;` 会影响 `PaintLayer` 的包含层查找逻辑。
        * CSS `z-index` 会影响 `PaintLayer` 在层叠上下文中的排序。

* **JavaScript:**  JavaScript 可以通过操作 DOM 和 CSSOM 来间接影响 `PaintLayer`。当 JavaScript 修改元素的样式或属性时，Blink 引擎会更新相应的 `LayoutObject` 和 `PaintLayer`。
    * **举例：**
        * JavaScript 代码 `element.style.transform = 'translateX(10px)';` 会导致与该元素关联的 `PaintLayer` 的变换属性更新。
        * 使用 JavaScript 动画库（如 Web Animations API）改变元素的 `opacity`，会触发 `PaintLayer` 相应的更新。

**逻辑推理及假设输入与输出：**

假设输入：
1. 一个 HTML `<div>` 元素，应用了 CSS `transform: translateX(50px);`。
2. 该 `<div>` 元素没有其他特殊的 CSS 属性影响其 `PaintLayer` 的创建或行为。

逻辑推理：
* Blink 引擎会为该 `<div>` 创建一个 `LayoutBoxModelObject`。
* 由于应用了 `transform` 属性，该 `LayoutBoxModelObject` 会关联一个 `PaintLayer`。
* `PaintLayer` 的 `transform_` 成员会被设置为一个表示水平平移 50px 的变换矩阵。

假设输出：
* 该 `PaintLayer` 的 `Transform()` 方法将返回一个表示 `translateX(50px)` 的 `gfx::Transform` 对象。
* 在后续的绘制过程中，该 `PaintLayer` 负责绘制的内容会被应用这个变换，从而在屏幕上向右平移 50 像素。

**用户或编程常见的使用错误及举例说明：**

* **错误使用 `z-index` 导致层叠顺序混乱：**  开发者可能没有正确理解层叠上下文的概念，错误地设置 `z-index` 值，导致元素被意外地遮挡或显示在错误的位置。
    * **举例：** 一个绝对定位的元素想要显示在另一个元素之上，但其父元素没有设置 `position: relative;`，导致 `z-index` 不生效。`PaintLayer` 的层叠顺序计算会受到影响。

* **过度使用 `transform` 或 `filter` 导致性能问题：**  频繁地或在大型元素上应用复杂的 `transform` 或 `filter` 会增加 GPU 的负担，可能导致页面卡顿。这会导致 Blink 引擎需要更频繁地更新和重新绘制 `PaintLayer`。

* **忘记 `position: relative` 或 `position: absolute` 来创建新的层叠上下文：** 有些 CSS 属性（如 `transform`, `opacity`, `filter` 等）会隐式创建新的层叠上下文。但如果开发者想要显式控制层叠顺序，需要使用 `position: relative`, `position: absolute`, 或 `position: fixed` 并配合 `z-index`。 错误的使用会导致 `PaintLayer` 的层叠关系不符合预期。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器中打开一个网页。**
2. **浏览器解析 HTML 代码，构建 DOM 树。**
3. **浏览器解析 CSS 样式，构建 CSSOM 树。**
4. **Blink 引擎结合 DOM 树和 CSSOM 树，创建渲染树 (Render Tree)，其中包括 `LayoutObject` 及其相关的样式信息。**
5. **对于渲染树中的 `LayoutBoxModelObject`，Blink 引擎会决定是否需要为其创建 `PaintLayer` 对象。**  例如，如果元素有 `transform`, `clip-path`, `filter` 等属性，或者是一个滚动容器，通常会创建 `PaintLayer`。
6. **`paint_layer.cc` 中的代码会被调用来创建和初始化 `PaintLayer` 对象，并设置其各种属性。**
7. **当页面需要绘制时，Blink 引擎会遍历 `PaintLayer` 树，按照一定的顺序进行绘制。**
8. **如果用户与页面进行交互，例如滚动页面或点击元素，Blink 引擎会进行命中测试，这也会涉及到 `PaintLayer` 的相关计算。**
9. **如果用户操作或 JavaScript 代码修改了元素的样式，Blink 引擎会更新相应的 `LayoutObject` 和 `PaintLayer`，可能触发重绘。**

**调试线索：**

* **使用 Chrome 开发者工具的 "Layers" 面板:** 可以查看页面的 `PaintLayer` 结构，了解哪些元素创建了独立的层，以及它们的层叠关系和合成原因。
* **检查元素的 CSS 属性:**  特别是 `transform`, `clip-path`, `filter`, `opacity`, `z-index`, `position`, `overflow` 等，这些属性直接影响 `PaintLayer` 的行为。
* **使用 "Rendering" 面板的 "Paint Flashing" 或 "Layer Borders":**  可以高亮显示发生重绘的区域或显示 `PaintLayer` 的边界，帮助理解绘制过程。
* **断点调试 `paint_layer.cc` 中的代码:**  如果需要深入了解 `PaintLayer` 的具体行为，可以在相关函数中设置断点，例如构造函数、`UpdateTransform()`、`Paint()` 等。

**这是第1部分，共3部分，请归纳一下它的功能:**

作为第一部分，此文件主要负责定义 `PaintLayer` 类的**基本结构和核心功能**。它涵盖了 `PaintLayer` 的创建、销毁、基本属性的维护、与其他渲染引擎组件（如 `LayoutObject`) 的关联，以及处理一些基本的视觉属性（如变换）的功能。  它奠定了后续章节中更复杂的功能实现的基础，例如合成和绘制。 简而言之，**这部分主要关注 `PaintLayer` 的“是什么”和一部分“如何创建和管理”**。

Prompt: 
```
这是目录为blink/renderer/core/paint/paint_layer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011, 2012 Apple Inc. All rights
 * reserved.
 *
 * Portions are Copyright (C) 1998 Netscape Communications Corporation.
 *
 * Other contributors:
 *   Robert O'Callahan <roc+@cs.cmu.edu>
 *   David Baron <dbaron@dbaron.org>
 *   Christian Biesinger <cbiesinger@web.de>
 *   Randall Jesup <rjesup@wgate.com>
 *   Roland Mainz <roland.mainz@informatik.med.uni-giessen.de>
 *   Josh Soref <timeless@mac.com>
 *   Boris Zbarsky <bzbarsky@mit.edu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Alternatively, the contents of this file may be used under the terms
 * of either the Mozilla Public License Version 1.1, found at
 * http://www.mozilla.org/MPL/ (the "MPL") or the GNU General Public
 * License Version 2.0, found at http://www.fsf.org/copyleft/gpl.html
 * (the "GPL"), in which case the provisions of the MPL or the GPL are
 * applicable instead of those above.  If you wish to allow use of your
 * version of this file only under the terms of one of those two
 * licenses (the MPL or the GPL) and not to allow others to use your
 * version of this file under the LGPL, indicate your decision by
 * deletingthe provisions above and replace them with the notice and
 * other provisions required by the MPL or the GPL, as the case may be.
 * If you do not delete the provisions above, a recipient may use your
 * version of this file under any of the LGPL, the MPL or the GPL.
 */

#include "third_party/blink/renderer/core/paint/paint_layer.h"

#include <limits>

#include "base/containers/adapters.h"
#include "build/build_config.h"
#include "cc/input/scroll_snap_data.h"
#include "partition_alloc/partition_alloc.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/animation/scroll_timeline.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/style_request.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/anchor_position_scroll_data.h"
#include "third_party/blink/renderer/core/layout/fragmentainer_iterator.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/transform_state.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_request.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_flow_thread.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_tree_as_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/sticky_position_scrolling_constraints.h"
#include "third_party/blink/renderer/core/paint/box_fragment_painter.h"
#include "third_party/blink/renderer/core/paint/box_reflection_utils.h"
#include "third_party/blink/renderer/core/paint/clip_path_clipper.h"
#include "third_party/blink/renderer/core/paint/compositing/compositing_reason_finder.h"
#include "third_party/blink/renderer/core/paint/cull_rect_updater.h"
#include "third_party/blink/renderer/core/paint/filter_effect_builder.h"
#include "third_party/blink/renderer/core/paint/fragment_data_iterator.h"
#include "third_party/blink/renderer/core/paint/hit_testing_transform_state.h"
#include "third_party/blink/renderer/core/paint/object_paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/paint_layer_paint_order_iterator.h"
#include "third_party/blink/renderer/core/paint/paint_layer_painter.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/paint_property_tree_builder.h"
#include "third_party/blink/renderer/core/paint/rounded_border_geometry.h"
#include "third_party/blink/renderer/core/paint/transform_utils.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/reference_clip_path_operation.h"
#include "third_party/blink/renderer/core/style/reference_offset_path_operation.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/bindings/runtime_call_stats.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "third_party/blink/renderer/platform/graphics/compositor_filter_operations.h"
#include "third_party/blink/renderer/platform/graphics/filters/filter.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/heap/collection_support/clear_collection_scope.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "ui/gfx/geometry/point3_f.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/geometry/transform.h"

namespace blink {

namespace {

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
struct SameSizeAsPaintLayer : GarbageCollected<PaintLayer>, DisplayItemClient {
  // The bit fields may fit into the machine word of DisplayItemClient which
  // has only 8-bit data.
  unsigned bit_fields1 : 24;
  unsigned bit_fields2 : 24;
#if DCHECK_IS_ON()
  bool is_destroyed;
#endif
  Member<void*> members[9];
  LayoutUnit layout_units[2];
  std::unique_ptr<void*> pointer;
};

ASSERT_SIZE(PaintLayer, SameSizeAsPaintLayer);
#endif

inline PhysicalRect PhysicalVisualOverflowRectAllowingUnset(
    const LayoutBoxModelObject& layout_object) {
#if DCHECK_IS_ON()
  InkOverflow::ReadUnsetAsNoneScope read_unset_as_none;
#endif
  return layout_object.VisualOverflowRect();
}

PaintLayer* SlowContainingLayer(LayoutObject& layout_object) {
  // This is a universal approach to find the containing layer, but it is
  // slower.
  auto* container = layout_object.Container(nullptr);
  while (container) {
    if (container->HasLayer())
      return To<LayoutBoxModelObject>(container)->Layer();
    container = container->Container(nullptr);
  }
  return nullptr;
}

std::optional<gfx::SizeF> ComputeFilterViewport(const PaintLayer& layer) {
  if (const auto* layout_inline =
          DynamicTo<LayoutInline>(layer.GetLayoutObject())) {
    return gfx::SizeF(layout_inline->PhysicalLinesBoundingBox().size);
  }
  const auto* box = layer.GetLayoutBox();
  if (box->IsSVGForeignObject()) {
    return std::nullopt;
  }
  return gfx::SizeF(box->Size());
}

}  // namespace

PaintLayer::PaintLayer(LayoutBoxModelObject* layout_object)
    : is_root_layer_(IsA<LayoutView>(layout_object)),
      has_visible_content_(false),
      needs_descendant_dependent_flags_update_(true),
      needs_visual_overflow_recalc_(true),
      has_visible_self_painting_descendant_(false),
      has3d_transformed_descendant_(false),
      self_needs_repaint_(false),
      descendant_needs_repaint_(false),
      needs_cull_rect_update_(false),
      forces_children_cull_rect_update_(false),
      descendant_needs_cull_rect_update_(false),
      previous_paint_result_(kMayBeClippedByCullRect),
      needs_paint_phase_descendant_outlines_(false),
      needs_paint_phase_float_(false),
      has_non_isolated_descendant_with_blend_mode_(false),
      has_fixed_position_descendant_(false),
      has_non_contained_absolute_position_descendant_(false),
      has_stacked_descendant_in_current_stacking_context_(false),
      filter_on_effect_node_dirty_(false),
      backdrop_filter_on_effect_node_dirty_(false),
      has_filter_that_moves_pixels_(false),
      is_under_svg_hidden_container_(false),
      has_self_painting_layer_descendant_(false),
      needs_reorder_overlay_overflow_controls_(false),
      static_inline_edge_(InlineEdge::kInlineStart),
      static_block_edge_(BlockEdge::kBlockStart),
#if DCHECK_IS_ON()
      layer_list_mutation_allowed_(true),
#endif
      layout_object_(layout_object),
      parent_(nullptr),
      previous_(nullptr),
      next_(nullptr),
      first_(nullptr),
      last_(nullptr),
      static_inline_position_(0),
      static_block_position_(0) {
  is_self_painting_layer_ = ShouldBeSelfPaintingLayer();

  UpdateScrollableArea();
}

PaintLayer::~PaintLayer() {
#if DCHECK_IS_ON()
  DCHECK(is_destroyed_);
#endif
}

void PaintLayer::Destroy() {
#if DCHECK_IS_ON()
  DCHECK(!is_destroyed_);
#endif
  if (resource_info_) {
    const ComputedStyle& style = GetLayoutObject().StyleRef();
    if (style.HasFilter())
      style.Filter().RemoveClient(*resource_info_);
    if (style.HasBackdropFilter()) {
      style.BackdropFilter().RemoveClient(*resource_info_);
    }
    if (auto* reference_clip =
            DynamicTo<ReferenceClipPathOperation>(style.ClipPath()))
      reference_clip->RemoveClient(*resource_info_);
    if (auto* reference_offset =
            DynamicTo<ReferenceOffsetPathOperation>(style.OffsetPath())) {
      reference_offset->RemoveClient(*resource_info_);
    }
    resource_info_->ClearLayer();
  }

  // Reset this flag before disposing scrollable_area_ to prevent
  // PaintLayerScrollableArea::WillRemoveScrollbar() from dirtying the z-order
  // list of the stacking context. If this layer is removed from the parent,
  // the z-order list should have been invalidated in RemoveChild().
  needs_reorder_overlay_overflow_controls_ = false;

  if (scrollable_area_)
    scrollable_area_->Dispose();

#if DCHECK_IS_ON()
  is_destroyed_ = true;
#endif
}

String PaintLayer::DebugName() const {
  return GetLayoutObject().DebugName();
}

DOMNodeId PaintLayer::OwnerNodeId() const {
  return static_cast<const DisplayItemClient&>(GetLayoutObject()).OwnerNodeId();
}

bool PaintLayer::PaintsWithFilters() const {
  if (!GetLayoutObject().HasFilterInducingProperty())
    return false;
  return true;
}

const PaintLayer* PaintLayer::ContainingScrollContainerLayer(
    bool* is_fixed_to_view) const {
  bool is_fixed = GetLayoutObject().IsFixedPositioned();
  for (const PaintLayer* container = ContainingLayer(); container;
       container = container->ContainingLayer()) {
    if (container->GetLayoutObject().IsScrollContainer()) {
      if (is_fixed_to_view)
        *is_fixed_to_view = is_fixed && container->IsRootLayer();
      DCHECK(container->GetScrollableArea());
      return container;
    }
    is_fixed = container->GetLayoutObject().IsFixedPositioned();
  }
  DCHECK(IsRootLayer());
  if (is_fixed_to_view)
    *is_fixed_to_view = true;
  return nullptr;
}

void PaintLayer::UpdateTransform() {
  if (gfx::Transform* transform = Transform()) {
    const LayoutBox* box = GetLayoutBox();
    DCHECK(box);
    transform->MakeIdentity();
    const PhysicalRect reference_box = ComputeReferenceBox(*box);
    box->StyleRef().ApplyTransform(
        *transform, box, reference_box,
        ComputedStyle::kIncludeTransformOperations,
        ComputedStyle::kIncludeTransformOrigin,
        ComputedStyle::kIncludeMotionPath,
        ComputedStyle::kIncludeIndependentTransformProperties);
  }
}

void PaintLayer::UpdateTransformAfterStyleChange(
    StyleDifference diff,
    const ComputedStyle* old_style,
    const ComputedStyle& new_style) {
  // It's possible for the old and new style transform data to be equivalent
  // while HasTransform() differs, as it checks a number of conditions aside
  // from just the matrix, including but not limited to animation state.
  bool had_transform = Transform();
  bool has_transform = GetLayoutObject().HasTransform();
  if (had_transform == has_transform && old_style &&
      !diff.TransformDataChanged()) {
    return;
  }
  bool had_3d_transform = Has3DTransform();

  if (has_transform != had_transform) {
    if (has_transform)
      transform_ = std::make_unique<gfx::Transform>();
    else
      transform_.reset();
  }

  UpdateTransform();

  if (had_3d_transform != Has3DTransform())
    MarkAncestorChainForFlagsUpdate();

  if (LocalFrameView* frame_view = GetLayoutObject().GetDocument().View())
    frame_view->SetNeedsUpdateGeometries();
}

gfx::Transform PaintLayer::CurrentTransform() const {
  if (gfx::Transform* transform = Transform())
    return *transform;
  return gfx::Transform();
}

void PaintLayer::DirtyVisibleContentStatus() {
  MarkAncestorChainForFlagsUpdate();
  // Non-self-painting layers paint into their ancestor layer, and count as part
  // of the "visible contents" of the parent, so we need to dirty it.
  if (!IsSelfPaintingLayer())
    Parent()->DirtyVisibleContentStatus();
}

void PaintLayer::MarkAncestorChainForFlagsUpdate(
    DescendantDependentFlagsUpdateFlag flag) {
#if DCHECK_IS_ON()
  DCHECK(flag == kDoesNotNeedDescendantDependentUpdate ||
         !layout_object_->GetDocument()
              .View()
              ->IsUpdatingDescendantDependentFlags());
#endif
  for (PaintLayer* layer = this; layer; layer = layer->Parent()) {
    if (layer->needs_descendant_dependent_flags_update_ &&
        layer->GetLayoutObject().NeedsPaintPropertyUpdate())
      break;
    if (flag == kNeedsDescendantDependentUpdate)
      layer->needs_descendant_dependent_flags_update_ = true;
    layer->GetLayoutObject().SetNeedsPaintPropertyUpdate();
  }
}

void PaintLayer::SetNeedsDescendantDependentFlagsUpdate() {
  for (PaintLayer* layer = this; layer; layer = layer->Parent()) {
    if (layer->needs_descendant_dependent_flags_update_)
      break;
    layer->needs_descendant_dependent_flags_update_ = true;
  }
}

void PaintLayer::UpdateDescendantDependentFlags() {
  if (needs_descendant_dependent_flags_update_) {
    bool old_has_non_isolated_descendant_with_blend_mode =
        has_non_isolated_descendant_with_blend_mode_;
    has_visible_self_painting_descendant_ = false;
    has_non_isolated_descendant_with_blend_mode_ = false;
    has_fixed_position_descendant_ = false;
    has_non_contained_absolute_position_descendant_ = false;
    has_stacked_descendant_in_current_stacking_context_ = false;
    has_self_painting_layer_descendant_ = false;
    descendant_needs_check_position_visibility_ = false;

    bool can_contain_abs =
        GetLayoutObject().CanContainAbsolutePositionObjects();

    auto* first_child = [this]() -> PaintLayer* {
      if (GetLayoutObject().ChildPrePaintBlockedByDisplayLock()) {
        GetLayoutObject()
            .GetDisplayLockContext()
            ->NotifyCompositingDescendantDependentFlagUpdateWasBlocked();
        return nullptr;
      }
      return FirstChild();
    }();

    for (PaintLayer* child = first_child; child; child = child->NextSibling()) {
      const ComputedStyle& child_style = child->GetLayoutObject().StyleRef();

      child->UpdateDescendantDependentFlags();

      if ((child->has_visible_content_ && child->IsSelfPaintingLayer()) ||
          child->has_visible_self_painting_descendant_)
        has_visible_self_painting_descendant_ = true;

      has_non_isolated_descendant_with_blend_mode_ |=
          (!child->GetLayoutObject().IsStackingContext() &&
           child->HasNonIsolatedDescendantWithBlendMode()) ||
          child_style.HasBlendMode();

      has_fixed_position_descendant_ |=
          child->HasFixedPositionDescendant() ||
          child_style.GetPosition() == EPosition::kFixed;

      if (!can_contain_abs) {
        has_non_contained_absolute_position_descendant_ |=
            (child->HasNonContainedAbsolutePositionDescendant() ||
             child_style.GetPosition() == EPosition::kAbsolute);
      }

      if (!has_stacked_descendant_in_current_stacking_context_) {
        if (child->GetLayoutObject().IsStacked()) {
          has_stacked_descendant_in_current_stacking_context_ = true;
        } else if (!child->GetLayoutObject().IsStackingContext()) {
          has_stacked_descendant_in_current_stacking_context_ =
              child->has_stacked_descendant_in_current_stacking_context_;
        }
      }

      has_self_painting_layer_descendant_ =
          has_self_painting_layer_descendant_ ||
          child->HasSelfPaintingLayerDescendant() ||
          child->IsSelfPaintingLayer();
    }

    // See SetInvisibleForPositionVisibility() for explanation for
    // descendant_needs_check_position_visibility_.
    if (InvisibleForPositionVisibility() &&
        !GetLayoutObject().IsStackingContext() &&
        has_self_painting_layer_descendant_) {
      AncestorStackingContext()->descendant_needs_check_position_visibility_ =
          true;
    }

    UpdateStackingNode();

    if (old_has_non_isolated_descendant_with_blend_mode !=
        static_cast<bool>(has_non_isolated_descendant_with_blend_mode_)) {
      // The LayoutView DisplayItemClient owns painting of the background
      // of the HTML element. When blending isolation of the HTML element's
      // descendants change, there will be an addition or removal of an
      // isolation effect node for the HTML element to add (or remove)
      // isolated blending, and that case we need to re-paint the LayoutView.
      if (Parent() && Parent()->IsRootLayer())
        GetLayoutObject().View()->SetBackgroundNeedsFullPaintInvalidation();
      GetLayoutObject().SetNeedsPaintPropertyUpdate();
    }
    needs_descendant_dependent_flags_update_ = false;

    if (IsSelfPaintingLayer() && needs_visual_overflow_recalc_) {
      PhysicalRect old_visual_rect =
          PhysicalVisualOverflowRectAllowingUnset(GetLayoutObject());
      GetLayoutObject().RecalcVisualOverflow();
      if (old_visual_rect != GetLayoutObject().VisualOverflowRect()) {
        MarkAncestorChainForFlagsUpdate(kDoesNotNeedDescendantDependentUpdate);
      }
    }
    needs_visual_overflow_recalc_ = false;
  }

  bool previously_has_visible_content = has_visible_content_;
  if (GetLayoutObject().StyleRef().Visibility() == EVisibility::kVisible) {
    has_visible_content_ = true;
  } else {
    // layer may be hidden but still have some visible content, check for this
    has_visible_content_ = false;
    LayoutObject* r = GetLayoutObject().SlowFirstChild();
    while (r) {
      if (r->StyleRef().Visibility() == EVisibility::kVisible &&
          (!r->HasLayer() || !r->EnclosingLayer()->IsSelfPaintingLayer())) {
        has_visible_content_ = true;
        break;
      }
      LayoutObject* layout_object_first_child = r->SlowFirstChild();
      if (layout_object_first_child &&
          (!r->HasLayer() || !r->EnclosingLayer()->IsSelfPaintingLayer())) {
        r = layout_object_first_child;
      } else if (r->NextSibling()) {
        r = r->NextSibling();
      } else {
        do {
          r = r->Parent();
          if (r == &GetLayoutObject())
            r = nullptr;
        } while (r && !r->NextSibling());
        if (r)
          r = r->NextSibling();
      }
    }
  }

  if (HasVisibleContent() != previously_has_visible_content) {
    // We need to tell layout_object_ to recheck its rect because we pretend
    // that invisible LayoutObjects have 0x0 rects. Changing visibility
    // therefore changes our rect and we need to visit this LayoutObject during
    // the PrePaintTreeWalk.
    layout_object_->SetShouldCheckForPaintInvalidation();
  }

  Update3DTransformedDescendantStatus();
}

void PaintLayer::Update3DTransformedDescendantStatus() {
  has3d_transformed_descendant_ = false;

  // Transformed or preserve-3d descendants can only be in the z-order lists,
  // not in the normal flow list, so we only need to check those.
  PaintLayerPaintOrderIterator iterator(this, kStackedChildren);
  while (PaintLayer* child_layer = iterator.Next()) {
    bool child_has3d = false;
    // If the child lives in a 3d hierarchy, then the layer at the root of
    // that hierarchy needs the m_has3DTransformedDescendant set.
    if (child_layer->Preserves3D() &&
        (child_layer->Has3DTransform() ||
         child_layer->Has3DTransformedDescendant()))
      child_has3d = true;
    else if (child_layer->Has3DTransform())
      child_has3d = true;

    if (child_has3d) {
      has3d_transformed_descendant_ = true;
      break;
    }
  }
}

void PaintLayer::UpdateScrollingAfterLayout() {
  if (RequiresScrollableArea()) {
    DCHECK(scrollable_area_);
    scrollable_area_->UpdateAfterLayout();
    LayoutBox* layout_box = GetLayoutBox();
    if (layout_box->ScrollableAreaSizeChanged()) {
      scrollable_area_->VisibleSizeChanged();
      layout_box->SetScrollableAreaSizeChanged(false);
    }
  }
}

PaintLayer* PaintLayer::ContainingLayer() const {
  LayoutObject& layout_object = GetLayoutObject();
  if (layout_object.IsOutOfFlowPositioned()) {
    // In NG, the containing block chain goes directly from a column spanner to
    // the multi-column container. Thus, for an OOF nested inside a spanner, we
    // need to find its containing layer through its containing block to handle
    // this case correctly. Therefore, we technically only need to take this
    // path for OOFs inside an NG spanner. However, doing so for all OOF
    // descendants of a multicol container is reasonable enough.
    if (layout_object.IsInsideFlowThread())
      return SlowContainingLayer(layout_object);
    auto can_contain_this_layer =
        layout_object.IsFixedPositioned()
            ? &LayoutObject::CanContainFixedPositionObjects
            : &LayoutObject::CanContainAbsolutePositionObjects;

    PaintLayer* curr = Parent();
    while (curr && !((&curr->GetLayoutObject())->*can_contain_this_layer)()) {
      curr = curr->Parent();
    }
    return curr;
  }

  // If the parent layer is not a block, there might be floating objects
  // between this layer (included) and parent layer which need to escape the
  // inline parent to find the actual containing layer through the containing
  // block chain.
  // Column span need to find the containing layer through its containing block.
  if ((!Parent() || Parent()->GetLayoutObject().IsLayoutBlock()) &&
      !layout_object.IsColumnSpanAll())
    return Parent();

  return SlowContainingLayer(layout_object);
}

PaintLayer* PaintLayer::CompositingContainer() const {
  if (IsReplacedNormalFlowStacking())
    return Parent();
  if (!GetLayoutObject().IsStacked()) {
    if (IsSelfPaintingLayer() || GetLayoutObject().IsColumnSpanAll())
      return Parent();
    return ContainingLayer();
  }
  return AncestorStackingContext();
}

PaintLayer* PaintLayer::AncestorStackingContext() const {
  for (PaintLayer* ancestor = Parent(); ancestor;
       ancestor = ancestor->Parent()) {
    if (ancestor->GetLayoutObject().IsStackingContext())
      return ancestor;
  }
  return nullptr;
}

void PaintLayer::SetNeedsCompositingInputsUpdate() {
  // TODO(chrishtr): These are a bit of a heavy hammer, because not all
  // things which require compositing inputs update require a descendant-
  // dependent flags update. Reduce call sites after CAP launch allows
  /// removal of CompositingInputsUpdater.
  MarkAncestorChainForFlagsUpdate();
}

void PaintLayer::ScrollContainerStatusChanged() {
  SetNeedsCompositingInputsUpdate();
}

void PaintLayer::SetNeedsVisualOverflowRecalc() {
  DCHECK(IsSelfPaintingLayer());
#if DCHECK_IS_ON()
  GetLayoutObject().InvalidateVisualOverflowForDCheck();
#endif
  needs_visual_overflow_recalc_ = true;
  // |MarkAncestorChainForFlagsUpdate| will cause a paint property update which
  // is only needed if visual overflow actually changes. To avoid this, only
  // mark this as needing a descendant dependent flags update, which will
  // cause a paint property update if needed (see:
  // PaintLayer::UpdateDescendantDependentFlags).
  SetNeedsDescendantDependentFlagsUpdate();
}

bool PaintLayer::HasNonIsolatedDescendantWithBlendMode() const {
  DCHECK(!needs_descendant_dependent_flags_update_);
  if (has_non_isolated_descendant_with_blend_mode_) {
    return true;
  }
  if (GetLayoutObject().IsSVGRoot()) {
    return To<LayoutSVGRoot>(GetLayoutObject())
        .HasNonIsolatedBlendingDescendants();
  }
  return false;
}

void PaintLayer::AddChild(PaintLayer* child, PaintLayer* before_child) {
#if DCHECK_IS_ON()
  DCHECK(layer_list_mutation_allowed_);
#endif

  PaintLayer* prev_sibling =
      before_child ? before_child->PreviousSibling() : LastChild();
  if (prev_sibling) {
    child->SetPreviousSibling(prev_sibling);
    prev_sibling->SetNextSibling(child);
    DCHECK_NE(prev_sibling, child);
  } else {
    SetFirstChild(child);
  }

  if (before_child) {
    before_child->SetPreviousSibling(child);
    child->SetNextSibling(before_child);
    DCHECK_NE(before_child, child);
  } else {
    SetLastChild(child);
  }

  child->parent_ = this;

  if (child->GetLayoutObject().IsStacked() || child->FirstChild()) {
    // Dirty the z-order list in which we are contained. The
    // ancestorStackingContextNode() can be null in the case where we're
    // building up generated content layers. This is ok, since the lists will
    // start off dirty in that case anyway.
    child->DirtyStackingContextZOrderLists();
  }

  // Non-self-painting children paint into this layer, so the visible contents
  // status of this layer is affected.
  if (!child->IsSelfPaintingLayer())
    DirtyVisibleContentStatus();

  MarkAncestorChainForFlagsUpdate();

  if (child->SelfNeedsRepaint())
    MarkCompositingContainerChainForNeedsRepaint();
  else
    child->SetNeedsRepaint();

  if (child->NeedsCullRectUpdate()) {
    SetDescendantNeedsCullRectUpdate();
  } else {
    child->SetNeedsCullRectUpdate();
  }
}

void PaintLayer::RemoveChild(PaintLayer* old_child) {
#if DCHECK_IS_ON()
  DCHECK(layer_list_mutation_allowed_);
#endif

  old_child->MarkCompositingContainerChainForNeedsRepaint();

  if (old_child->PreviousSibling())
    old_child->PreviousSibling()->SetNextSibling(old_child->NextSibling());
  if (old_child->NextSibling())
    old_child->NextSibling()->SetPreviousSibling(old_child->PreviousSibling());

  if (first_ == old_child)
    first_ = old_child->NextSibling();
  if (last_ == old_child)
    last_ = old_child->PreviousSibling();

  if (!GetLayoutObject().DocumentBeingDestroyed()) {
    // Dirty the z-order list in which we are contained.
    old_child->DirtyStackingContextZOrderLists();
    MarkAncestorChainForFlagsUpdate();
  }

  if (GetLayoutObject().StyleRef().Visibility() != EVisibility::kVisible) {
    DirtyVisibleContentStatus();
  }

  old_child->SetPreviousSibling(nullptr);
  old_child->SetNextSibling(nullptr);
  old_child->parent_ = nullptr;

  if (old_child->has_visible_content_ ||
      old_child->has_visible_self_painting_descendant_)
    MarkAncestorChainForFlagsUpdate();
}

void PaintLayer::RemoveOnlyThisLayerAfterStyleChange(
    const ComputedStyle* old_style) {
  if (!parent_)
    return;

  if (old_style) {
    if (GetLayoutObject().IsStacked(*old_style))
      DirtyStackingContextZOrderLists();

    if (PaintLayerPainter::PaintedOutputInvisible(*old_style)) {
      // PaintedOutputInvisible() was true because opacity was near zero, and
      // this layer is to be removed because opacity becomes 1. Do the same as
      // StyleDidChange() on change of PaintedOutputInvisible().
      GetLayoutObject().SetSubtreeShouldDoFullPaintInvalidation();
    }
  }

  if (IsSelfPaintingLayer()) {
    if (PaintLayer* enclosing_self_painting_layer =
            parent_->EnclosingSelfPaintingLayer())
      enclosing_self_painting_layer->MergeNeedsPaintPhaseFlagsFrom(*this);
  }

  PaintLayer* next_sib = NextSibling();

  // Now walk our kids and reattach them to our parent.
  PaintLayer* current = first_;
  while (current) {
    PaintLayer* next = current->NextSibling();
    RemoveChild(current);
    parent_->AddChild(current, next_sib);
    current = next;
  }

  // Remove us from the parent.
  parent_->RemoveChild(this);
  layout_object_->DestroyLayer();
}

void PaintLayer::InsertOnlyThisLayerAfterStyleChange() {
  if (!parent_ && GetLayoutObject().Parent()) {
    // We need to connect ourselves when our layoutObject() has a parent.
    // Find our enclosingLayer and add ourselves.
    PaintLayer* parent_layer = GetLayoutObject().Parent()->EnclosingLayer();
    DCHECK(parent_layer);
    PaintLayer* before_child = GetLayoutObject().Parent()->FindNextLayer(
        parent_layer, &GetLayoutObject());
    parent_layer->AddChild(this, before_child);
  }

  // Remove all descendant layers from the hierarchy and add them to the new
  // position.
  for (LayoutObject* curr = GetLayoutObject().SlowFirstChild(); curr;
       curr = curr->NextSibling())
    curr->MoveLayers(parent_, this);

  if (IsSelfPaintingLayer() && parent_) {
    if (PaintLayer* enclosing_self_painting_layer =
            parent_->EnclosingSelfPaintingLayer())
      MergeNeedsPaintPhaseFlagsFrom(*enclosing_self_painting_layer);
  }
}

void PaintLayer::DidUpdateScrollsOverflow() {
  UpdateSelfPaintingLayer();
}

void PaintLayer::UpdateStackingNode() {
#if DCHECK_IS_ON()
  DCHECK(layer_list_mutation_allowed_);
#endif

  bool needs_stacking_node =
      has_stacked_descendant_in_current_stacking_context_ &&
      GetLayoutObject().IsStackingContext();

  if (needs_stacking_node != !!stacking_node_) {
    if (needs_stacking_node) {
      stacking_node_ = MakeGarbageCollected<PaintLayerStackingNode>(this);
    } else {
      stacking_node_.Clear();
    }
  }

  if (stacking_node_)
    stacking_node_->UpdateZOrderLists();
}

bool PaintLayer::RequiresScrollableArea() const {
  if (!GetLayoutBox())
    return false;
  if (GetLayoutObject().IsScrollContainer())
    return true;
  // Iframes with the resize property can be resized. This requires
  // scroll corner painting, which is implemented, in part, by
  // PaintLayerScrollableArea.
  if (GetLayoutBox()->CanResize())
    return true;
  return false;
}

void PaintLayer::UpdateScrollableArea() {
  if (RequiresScrollableArea() == !!scrollable_area_)
    return;

  if (!scrollable_area_) {
    scrollable_area_ = MakeGarbageCollected<PaintLayerScrollableArea>(*this);
    const ComputedStyle& style = GetLayoutObject().StyleRef();
    // A newly created snap container may need to be made aware of snap areas
    // within it which are targeted or contain a targeted element. Such a
    // container may also change the snap areas associated with snap containers
    // higher in the DOM.
    if (!style.GetScrollSnapType().is_none) {
      if (Element* css_target = GetLayoutObject().GetDocument().CssTarget()) {
        css_target->SetTargetedSnapAreaIdsForSnapContainers();
      }
    }
  } else {
    scrollable_area_->Dispose();
    scrollable_area_.Clear();
  }

  GetLayoutObject().SetNeedsPaintPropertyUpdate();
  // To clear z-ordering information of overlay overflow controls.
  if (NeedsReorderOverlayOverflowControls())
    DirtyStackingContextZOrderLists();
}

void PaintLayer::AppendSingleFragmentForHitTesting(
    PaintLayerFragments& fragments,
    const PaintLayerFrag
"""


```