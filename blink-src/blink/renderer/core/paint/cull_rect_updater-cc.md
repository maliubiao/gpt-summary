Response:
My thought process to answer the request about `cull_rect_updater.cc` goes through these stages:

1. **Understand the Core Purpose:** The file name itself, "cull_rect_updater," strongly suggests its primary function: updating cull rectangles. Cull rectangles are optimization techniques used in rendering to avoid drawing objects that are not visible within the viewport or a clipping region.

2. **Scan for Key Concepts and Data Structures:** I'd quickly scan the code for recurring terms and data structures. "CullRect," "PaintLayer," "FragmentData," "LayoutObject," and "PaintProperties" stand out. These are central to Blink's rendering pipeline. The presence of `OverriddenCullRectScope` suggests a mechanism for temporarily modifying cull rectangles.

3. **Identify Key Functions:**  I'd look for the main public methods. `Update()`, `UpdateInternal()`, `UpdateForDescendants()`, `UpdateRecursively()`, `UpdateForSelf()`, `ComputeFragmentCullRect()`, and `ComputeFragmentContentsCullRect()` are clearly important for the update process. `PaintPropertiesChanged()` indicates a reaction to style or layout changes.

4. **Infer Functionality from Function Names and Logic:**
    * **`Update()` and `UpdateInternal()`:**  These are likely the entry points for the cull rect update process. `Update()` probably handles high-level setup, while `UpdateInternal()` performs the core recursive logic.
    * **`UpdateForDescendants()` and `UpdateRecursively()`:**  Suggest a tree traversal to update cull rectangles for each layer in the rendering hierarchy.
    * **`UpdateForSelf()`:** Focuses on calculating and setting the cull rectangle for a specific layer.
    * **`ComputeFragmentCullRect()` and `ComputeFragmentContentsCullRect()`:**  Perform the calculations for the actual cull rectangle values, considering factors like transforms, clips, and scrolling.
    * **`PaintPropertiesChanged()`:**  This function reacts to changes in CSS properties and determines if a cull rect update is needed.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**  This requires understanding how Blink's rendering relates to these technologies.
    * **HTML:**  The structure of the HTML document dictates the layout hierarchy, which corresponds to the `PaintLayer` tree.
    * **CSS:** CSS properties like `overflow`, `clip-path`, `transform`, and `position: fixed` directly influence the calculation of cull rectangles. Changes to these properties trigger `PaintPropertiesChanged()`. Scrolling, managed through CSS and browser UI, is also a key factor.
    * **JavaScript:** JavaScript can manipulate the DOM and CSS styles, leading to layout changes and triggering cull rect updates. Animations and transitions, often controlled by JavaScript or CSS, can also impact cull rects.

6. **Consider Edge Cases and Optimizations:** The code contains logic related to `InfiniteCullRect`, view transitions, and performance optimizations (e.g., checking `HasScrolledEnough`). These point to efforts to handle specific scenarios efficiently.

7. **Think About Debugging and User Errors:**  The code uses logging and assertions (`DCHECK`). Common user errors might involve unexpected clipping or performance issues due to incorrect use of CSS properties that affect culling. The explanation of how user actions lead to this code is crucial for debugging.

8. **Structure the Answer:** Organize the findings logically, starting with a summary of the file's purpose, then detailing its functions, relationships with web technologies, logical reasoning, potential errors, and debugging information.

**Pre-computation/Pre-analysis (Internal "Mental" Steps):**

* **Blink Architecture Knowledge:**  A foundational understanding of Blink's rendering pipeline, including the role of `LayoutObject`, `PaintLayer`, and property trees, is essential.
* **Culling Concept:**  A clear grasp of what culling is and why it's important for performance.
* **CSS Properties' Impact:** Knowing how various CSS properties affect the rendering process.

By following these steps, I can generate a comprehensive and accurate answer that addresses all aspects of the request. The process involves a combination of code analysis, knowledge of web technologies, and logical deduction.
好的，让我们来详细分析一下 `blink/renderer/core/paint/cull_rect_updater.cc` 这个文件的功能。

**文件功能概述**

`cull_rect_updater.cc` 文件的主要职责是 **更新渲染对象（`LayoutObject`）关联的裁剪矩形（Cull Rect）**。裁剪矩形是一种性能优化技术，用于确定哪些内容是可见的，从而避免绘制屏幕外或被遮挡的内容，提高渲染效率。

更具体地说，这个文件负责：

1. **计算和设置每个渲染片段（`FragmentData`）的裁剪矩形和内容裁剪矩形。**
2. **根据各种因素（例如滚动、变换、裁剪属性、是否在视口内等）来决定是否需要更新裁剪矩形。**
3. **处理特殊情况，例如固定定位元素、带有滤镜的元素、动画元素以及视图过渡等。**
4. **管理裁剪矩形的继承和传播，确保子元素的裁剪矩形受到父元素的影响。**
5. **提供一种临时覆盖裁剪矩形的机制，用于某些特殊绘制场景。**

**与 JavaScript, HTML, CSS 的关系及举例说明**

`cull_rect_updater.cc` 的功能与 Web 前端的三大核心技术 JavaScript、HTML 和 CSS 都有着密切的联系：

* **HTML (结构):** HTML 定义了页面的结构，而这种结构会被 Blink 转换为 `LayoutObject` 树和 `PaintLayer` 树。`cull_rect_updater` 正是在这些树的基础上进行裁剪矩形的计算和更新。例如，一个 `<div>` 元素对应一个 `LayoutBlock`，可能会对应一个 `PaintLayer`，并拥有自己的裁剪矩形。

* **CSS (样式):** CSS 样式属性直接影响裁剪矩形的计算：
    * **`overflow: hidden | scroll | auto`:**  会创建裁剪容器，影响子元素的裁剪矩形。例如，如果一个 `<div>` 设置了 `overflow: hidden`，那么其子元素超出该 `<div>` 范围的部分将被裁剪掉。`cull_rect_updater` 会考虑这个 `overflow` 属性来计算子元素的裁剪矩形。
    * **`clip-path`:**  定义复杂的裁剪路径，也会被 `cull_rect_updater` 考虑在内。
    * **`transform` (translate, rotate, scale):** 变换会改变元素的位置和形状，从而影响其裁剪矩形。`cull_rect_updater` 需要进行矩阵运算来映射变换后的裁剪矩形。
        ```css
        .transformed {
          transform: translateX(50px);
        }
        ```
        当元素应用了这个 CSS 规则后，`cull_rect_updater` 会计算出平移 50px 后的裁剪矩形。
    * **`position: fixed`:** 固定定位元素的裁剪行为比较特殊，它们相对于视口定位。`cull_rect_updater` 中有专门的逻辑来处理固定定位元素的裁剪矩形。
    * **滚动:**  当用户滚动页面时，视口发生变化，`cull_rect_updater` 会更新屏幕上可见元素的裁剪矩形。

* **JavaScript (交互):** JavaScript 可以动态地修改 HTML 结构和 CSS 样式，这些修改可能会触发裁剪矩形的更新：
    * **动态添加或删除元素:**  改变了渲染树的结构，需要重新计算相关元素的裁剪矩形。
    * **修改 CSS 样式:**  例如，通过 JavaScript 改变元素的 `transform` 属性或 `overflow` 属性，会触发 `cull_rect_updater` 重新计算裁剪矩形。
        ```javascript
        document.getElementById('myDiv').style.transform = 'rotate(45deg)';
        ```
        这段 JavaScript 代码会修改元素的 `transform` 属性，导致 `cull_rect_updater` 重新计算该元素的裁剪矩形。
    * **滚动事件:** JavaScript 可以监听滚动事件，虽然不是直接调用 `cull_rect_updater`，但滚动行为是触发裁剪矩形更新的关键因素。
    * **动画和过渡:**  JavaScript 可以创建动画和 CSS 过渡效果，这些效果涉及到元素位置、大小和形状的改变，从而需要 `cull_rect_updater` 不断地更新裁剪矩形。

**逻辑推理的假设输入与输出**

假设我们有一个简单的 HTML 结构：

```html
<div style="width: 200px; height: 100px; overflow: hidden;">
  <div style="width: 300px; height: 50px; background-color: red;"></div>
</div>
```

**假设输入：**

* 根 `LayoutView` 的初始裁剪矩形等于视口大小 (例如：`CullRect(0, 0, 800, 600)`)。
* 父 `div` (`overflow: hidden`) 的布局信息：位置 `(10, 10)`，大小 `(200, 100)`。
* 子 `div` 的布局信息：相对于父元素的位置 `(0, 0)`，大小 `(300, 50)`。

**逻辑推理：**

1. `cull_rect_updater` 首先会处理根 `LayoutView` 的裁剪矩形，通常初始化为无限大或视口大小。
2. 接着处理父 `div`。由于设置了 `overflow: hidden`，它会创建一个裁剪边界。
3. 在计算子 `div` 的裁剪矩形时，`cull_rect_updater` 会考虑父 `div` 的裁剪边界。子 `div` 的宽度是 300px，超出父 `div` 的 200px 宽度。
4. `cull_rect_updater` 会将子 `div` 的裁剪矩形限制在父 `div` 的内容区域内。

**预期输出：**

* 父 `div` 的内容裁剪矩形大致为 `CullRect(10, 10, 210, 110)` (考虑边框等因素)。
* 子 `div` 的裁剪矩形会被父 `div` 的内容裁剪矩形裁剪，最终的裁剪矩形大致为 `CullRect(10, 10, 210, 60)`。这意味着子 `div` 只有宽度为 200px 的部分会最终被绘制。

**用户或编程常见的使用错误及举例说明**

* **过度依赖 `overflow: hidden` 进行裁剪：**  虽然 `overflow: hidden` 可以实现裁剪，但过度使用可能会导致性能问题，因为每次布局或滚动都可能触发裁剪矩形的重新计算。开发者应该谨慎使用，并考虑其他更高效的裁剪方式，例如 `clip-path` 在某些场景下可能更合适。

* **忘记考虑 `transform` 对裁剪的影响：** 当对元素应用 `transform` 时，元素的视觉位置和边界会发生变化，开发者需要确保裁剪逻辑能够正确处理这些变换。例如，如果一个元素旋转后超出了父元素的 `overflow: hidden` 区域，但开发者仍然期望它被裁剪，就需要仔细检查裁剪矩形的计算。

* **在 JavaScript 中频繁修改影响布局的样式：**  频繁地修改元素的 `width`、`height`、`transform` 等属性会导致浏览器频繁地进行布局和绘制，其中包括裁剪矩形的更新。这可能会导致性能下降，尤其是在复杂的页面中。开发者应该尽量批量更新样式或使用更高效的动画技术。

**用户操作如何一步步到达这里（作为调试线索）**

假设用户在一个网页上滚动页面：

1. **用户操作：** 用户使用鼠标滚轮、拖动滚动条或使用键盘方向键滚动网页。
2. **浏览器事件触发：** 用户的滚动操作会触发浏览器的滚动事件。
3. **LayoutView 的变化：** 滚动事件会导致 `LocalFrameView` 的滚动偏移发生变化。
4. **需要更新裁剪矩形的标记：** `LocalFrameView` 会标记根 `PaintLayer` (通常对应 `LayoutView`) 需要更新裁剪矩形。
5. **进入 `CullRectUpdater::Update()`：**  在渲染管线的某个阶段，会调用 `CullRectUpdater::Update()` 来更新裁剪矩形。这通常发生在绘制前的更新阶段。
6. **遍历 PaintLayer 树：** `Update()` 方法会递归地遍历 `PaintLayer` 树，从根节点开始。
7. **计算每个 Fragment 的裁剪矩形：** 对于每个需要更新裁剪矩形的 `PaintLayer` 和其关联的 `FragmentData`，会调用 `ComputeFragmentCullRect()` 和 `ComputeFragmentContentsCullRect()` 等方法来计算新的裁剪矩形。
8. **设置裁剪矩形并触发重绘（如果需要）：**  如果计算出的裁剪矩形与之前的不同，则会调用 `SetFragmentCullRect()` 和 `SetFragmentContentsCullRect()` 来设置新的裁剪矩形。如果裁剪矩形发生变化，并且影响到元素的可见性，可能会触发相应图层的重绘。

**其他调试线索：**

* **断点调试：** 在 `cull_rect_updater.cc` 中设置断点，例如在 `UpdateInternal()`、`ComputeFragmentCullRect()` 等关键函数中设置断点，可以观察裁剪矩形的计算过程和变量值。
* **渲染树查看器：** Chromium 开发者工具中的 "Layers" 面板可以查看页面的渲染层叠上下文和每个图层的裁剪信息。
* **性能分析工具：** 使用 Chrome 开发者工具的 "Performance" 面板可以分析渲染过程中的性能瓶颈，查看裁剪矩形更新是否频繁或耗时过长。
* **日志输出：**  虽然这段代码中没有明显的日志输出，但在 Blink 的其他部分可能存在与裁剪相关的日志，可以帮助理解裁剪行为。

希望以上分析能够帮助你理解 `blink/renderer/core/paint/cull_rect_updater.cc` 文件的功能及其与 Web 前端技术的联系。

Prompt: 
```
这是目录为blink/renderer/core/paint/cull_rect_updater.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/cull_rect_updater.h"

#include "base/auto_reset.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/pagination_state.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/paint/fragment_data_iterator.h"
#include "third_party/blink/renderer/core/paint/object_paint_properties.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_paint_order_iterator.h"
#include "third_party/blink/renderer/core/paint/paint_layer_painter.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/paint_property_tree_builder.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {

float ExpansionRatio(const LayoutObject& object) {
  const int dpr_coef = features::kCullRectExpansionDPRCoef.Get();
  float device_pixel_ratio =
      object.GetFrame()->LocalFrameRoot().GetDocument()->DevicePixelRatio();
  return 1 + (device_pixel_ratio - 1) * dpr_coef;
}

using FragmentCullRects = OverriddenCullRectScope::FragmentCullRects;
// This is set to non-null when we are updating overridden cull rects for
// special painting. The current cull rects will be saved during the update,
// and will be restored when we exit the OverriddenCullRectScope.
Vector<FragmentCullRects>* g_original_cull_rects = nullptr;

void SetLayerNeedsRepaintOnCullRectChange(PaintLayer& layer) {
  if (layer.PreviousPaintResult() == kMayBeClippedByCullRect ||
      RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled()) {
    layer.SetNeedsRepaint();
  }
}

void SetFragmentCullRect(PaintLayer& layer,
                         FragmentData& fragment,
                         const CullRect& cull_rect) {
  if (cull_rect == fragment.GetCullRect())
    return;

  if (g_original_cull_rects) {
    g_original_cull_rects->emplace_back(fragment);
  } else {
    SetLayerNeedsRepaintOnCullRectChange(layer);
  }

  fragment.SetCullRect(cull_rect);
}

// Returns true if the contents cull rect changed.
bool SetFragmentContentsCullRect(PaintLayer& layer,
                                 FragmentData& fragment,
                                 const CullRect& contents_cull_rect) {
  if (contents_cull_rect == fragment.GetContentsCullRect())
    return false;

  if (g_original_cull_rects) {
    if (g_original_cull_rects->empty() ||
        g_original_cull_rects->back().fragment != &fragment) {
      g_original_cull_rects->emplace_back(fragment);
    }
  } else {
    SetLayerNeedsRepaintOnCullRectChange(layer);
    if (auto* scrollable_area = layer.GetScrollableArea())
      scrollable_area->DidUpdateCullRect();
  }

  fragment.SetContentsCullRect(contents_cull_rect);
  return true;
}

bool ShouldUseInfiniteCullRect(
    const PaintLayer& layer,
    ViewTransitionSupplement* view_transition_supplement,
    bool& subtree_should_use_infinite_cull_rect) {
  if (RuntimeEnabledFeatures::InfiniteCullRectEnabled())
    return true;

  if (subtree_should_use_infinite_cull_rect)
    return true;

  const LayoutObject& object = layer.GetLayoutObject();
  bool is_printing = object.GetDocument().Printing();
  if (IsA<LayoutView>(object) && !object.GetFrame()->ClipsContent() &&
      // We use custom top cull rect per page when printing.
      !is_printing) {
    return true;
  }

  if (const auto* properties = object.FirstFragment().PaintProperties()) {
    // Cull rects and clips can't be propagated across a filter which moves
    // pixels, since the input of the filter may be outside the cull rect /
    // clips yet still result in painted output.
    if (properties->Filter() &&
        properties->Filter()->HasFilterThatMovesPixels() &&
        // However during printing, we don't want filter outset to cross page
        // boundaries. This also avoids performance issue because the PDF
        // renderer is super slow for big filters.
        !is_printing) {
      return true;
    }

    // Cull rect mapping doesn't work under perspective in some cases.
    // See http://crbug.com/887558 for details.
    if (properties->Perspective()) {
      subtree_should_use_infinite_cull_rect = true;
      return true;
    }

    const TransformPaintPropertyNode* transform_nodes[] = {
        properties->Transform(), properties->Offset(), properties->Scale(),
        properties->Rotate(), properties->Translate()};
    for (const auto* transform : transform_nodes) {
      if (!transform)
        continue;

      // A CSS transform can also have perspective like
      // "transform: perspective(100px) rotateY(45deg)". In these cases, we
      // also want to skip cull rect mapping. See http://crbug.com/887558 for
      // details.
      if (transform->Matrix().HasPerspective()) {
        subtree_should_use_infinite_cull_rect = true;
        return true;
      }

      // Ensure content under animating transforms is not culled out.
      if (transform->HasActiveTransformAnimation())
        return true;

      // As an optimization, skip cull rect updating for non-composited
      // transforms which have already been painted. This is because the cull
      // rect update, which needs to do complex mapping of the cull rect, can
      // be more expensive than over-painting.
      if (!transform->HasDirectCompositingReasons() &&
          layer.PreviousPaintResult() == kFullyPainted) {
        return true;
      }
    }
  }

  if (view_transition_supplement) {
    auto* transition = view_transition_supplement->GetTransition();

    // This means that the contents of the object are drawn elsewhere, so we
    // shouldn't cull it.
    if (transition && transition->IsRepresentedViaPseudoElements(object))
      return true;
  }

  return false;
}

bool HasScrolledEnough(const LayoutObject& object) {
  if (const auto* properties = object.FirstFragment().PaintProperties()) {
    if (const auto* scroll_translation = properties->ScrollTranslation()) {
      const auto* scrollable_area = To<LayoutBox>(object).GetScrollableArea();
      DCHECK(scrollable_area);
      gfx::Vector2dF delta = -scroll_translation->Get2dTranslation() -
                             scrollable_area->LastCullRectUpdateScrollPosition()
                                 .OffsetFromOrigin();
      return object.FirstFragment().GetContentsCullRect().HasScrolledEnough(
          delta, *scroll_translation, ExpansionRatio(object));
    }
  }
  return false;
}

}  // anonymous namespace

CullRectUpdater::CullRectUpdater(PaintLayer& starting_layer,
                                 bool disable_expansion)
    : starting_layer_(starting_layer),
      expansion_ratio_(disable_expansion
                           ? 0.f
                           : ExpansionRatio(starting_layer.GetLayoutObject())) {
  view_transition_supplement_ = ViewTransitionSupplement::FromIfExists(
      starting_layer.GetLayoutObject().GetDocument());
}

void CullRectUpdater::Update() {
  DCHECK(starting_layer_.IsRootLayer());
  TRACE_EVENT0("blink,benchmark", "CullRectUpdate");
  SCOPED_BLINK_UMA_HISTOGRAM_TIMER_HIGHRES("Blink.CullRect.UpdateTime");

  UpdateInternal(CullRect::Infinite());

#if DCHECK_IS_ON()
  if (VLOG_IS_ON(2)) {
    VLOG(2) << "PaintLayer tree after cull rect update:";
    ShowLayerTree(&starting_layer_);
  }
#endif
}

void CullRectUpdater::UpdateForTesting(const CullRect& input_cull_rect) {
  DCHECK(starting_layer_.IsRootLayer());
  UpdateInternal(input_cull_rect);
}

void CullRectUpdater::UpdateInternal(const CullRect& input_cull_rect) {
  const auto& object = starting_layer_.GetLayoutObject();
  if (object.GetFrameView()->ShouldThrottleRendering())
    return;
  if (object.IsFragmentLessBox()) {
    return;
  }

  object.GetFrameView()->SetCullRectNeedsUpdateForFrames(
      /*disable_expansion=*/expansion_ratio_ == 0);

  if (!starting_layer_.NeedsCullRectUpdate() &&
      !starting_layer_.DescendantNeedsCullRectUpdate() &&
      // This allows proactive cull rect update for direct children that will
      // be repainted.
      !starting_layer_.SelfOrDescendantNeedsRepaint() &&
      // Don't skip cull rect update with custom input_cull_rect.
      input_cull_rect.IsInfinite()) {
    return;
  }

  root_state_ =
      object.View()->FirstFragment().LocalBorderBoxProperties().Unalias();
  Context context;
  context.current.container = &starting_layer_;
  bool should_use_infinite = ShouldUseInfiniteCullRect(
      starting_layer_, view_transition_supplement_,
      context.current.subtree_should_use_infinite_cull_rect);

  auto& fragment = object.GetMutableForPainting().FirstFragment();
  SetFragmentCullRect(
      starting_layer_, fragment,
      should_use_infinite ? CullRect::Infinite() : input_cull_rect);
  context.current.force_update_children = SetFragmentContentsCullRect(
      starting_layer_, fragment,
      should_use_infinite
          ? CullRect::Infinite()
          : ComputeFragmentContentsCullRect(context, starting_layer_, fragment,
                                            input_cull_rect));

  context.absolute = context.fixed = context.current;
  UpdateForDescendants(context, starting_layer_);

  if (!g_original_cull_rects)
    starting_layer_.ClearNeedsCullRectUpdate();
}

// See UpdateForDescendants for how |force_update_self| is propagated.
void CullRectUpdater::UpdateRecursively(const Context& parent_context,
                                        PaintLayer& layer) {
  if (layer.IsUnderSVGHiddenContainer())
    return;

  const auto& object = layer.GetLayoutObject();
  if (object.IsFragmentLessBox()) {
    return;
  }

  Context context = parent_context;
  if (object.IsAbsolutePositioned())
    context.current = context.absolute;
  if (object.IsFixedPositioned())
    context.current = context.fixed;

  bool should_proactively_update = ShouldProactivelyUpdate(context, layer);
  bool force_update_self = context.current.force_update_children;
  context.current.force_update_children =
      should_proactively_update || layer.ForcesChildrenCullRectUpdate();

  if (force_update_self || should_proactively_update ||
      layer.NeedsCullRectUpdate()) {
    context.current.force_update_children |= UpdateForSelf(context, layer);
  }

  if (!context.current.subtree_is_out_of_cull_rect &&
      object.ShouldClipOverflowAlongBothAxis() && !object.IsFragmented()) {
    const auto* box = layer.GetLayoutBox();
    DCHECK(box);
    PhysicalRect clip_rect =
        box->OverflowClipRect(box->FirstFragment().PaintOffset());
    if (!box->FirstFragment().GetCullRect().Intersects(
            ToEnclosingRect(clip_rect))) {
      context.current.subtree_is_out_of_cull_rect = true;
    }
  }

  bool should_traverse_children =
      context.current.force_update_children ||
      layer.DescendantNeedsCullRectUpdate() ||
      (context.absolute.force_update_children &&
       layer.HasNonContainedAbsolutePositionDescendant()) ||
      (context.fixed.force_update_children &&
       !object.CanContainFixedPositionObjects() &&
       layer.HasFixedPositionDescendant());
  if (should_traverse_children) {
    context.current.container = &layer;
    // We pretend the starting layer can contain all descendants.
    if (&layer == &starting_layer_ ||
        object.CanContainAbsolutePositionObjects()) {
      context.absolute = context.current;
    }
    if (&layer == &starting_layer_ || object.CanContainFixedPositionObjects()) {
      context.fixed = context.current;
    }
    UpdateForDescendants(context, layer);
  }

  if (!g_original_cull_rects)
    layer.ClearNeedsCullRectUpdate();
}

// "Children" in |force_update_children| means children in the containing block
// tree. The flag is set by the containing block whose contents cull rect
// changed.
void CullRectUpdater::UpdateForDescendants(const Context& context,
                                           PaintLayer& layer) {
  const auto& object = layer.GetLayoutObject();

  // DisplayLockContext will force cull rect update of the subtree on unlock.
  if (object.ChildPaintBlockedByDisplayLock())
    return;

  for (auto* child = layer.FirstChild(); child; child = child->NextSibling())
    UpdateRecursively(context, *child);

  if (auto* embedded_content = DynamicTo<LayoutEmbeddedContent>(object)) {
    if (auto* embedded_view = embedded_content->GetEmbeddedContentView()) {
      if (auto* embedded_frame_view =
              DynamicTo<LocalFrameView>(embedded_view)) {
        PaintLayer* subframe_root_layer = nullptr;
        if (auto* sub_layout_view = embedded_frame_view->GetLayoutView())
          subframe_root_layer = sub_layout_view->Layer();
        if (embedded_frame_view->ShouldThrottleRendering()) {
          if (context.current.force_update_children && subframe_root_layer)
            subframe_root_layer->SetNeedsCullRectUpdate();
        } else {
          DCHECK(subframe_root_layer);

          Context subframe_context = {context.current, context.current,
                                      context.current};
          UpdateRecursively(subframe_context, *subframe_root_layer);
        }
      }
    }
  }
}

bool CullRectUpdater::UpdateForSelf(Context& context, PaintLayer& layer) {
  const auto& parent_object = context.current.container->GetLayoutObject();
  // If the containing layer is fragmented, try to match fragments from the
  // container to |layer|, so that any fragment clip for
  // |context.current.container|'s fragment matches |layer|'s.
  //
  // TODO(paint-dev): If nested fragmentation is involved, we're not matching
  // correctly here. In order to fix that, we most likely need to move over to
  // some sort of fragment tree traversal (rather than pure PaintLayer tree
  // traversal).
  bool should_match_fragments = parent_object.IsFragmented();
  bool force_update_children = false;
  bool should_use_infinite_cull_rect =
      !context.current.subtree_is_out_of_cull_rect &&
      ShouldUseInfiniteCullRect(
          layer, view_transition_supplement_,
          context.current.subtree_should_use_infinite_cull_rect);

  for (FragmentData& fragment :
       MutableFragmentDataIterator(layer.GetLayoutObject())) {
    CullRect cull_rect;
    CullRect contents_cull_rect;
    if (context.current.subtree_is_out_of_cull_rect) {
      // PaintLayerPainter may skip the subtree including this layer, so we
      // need to SetPreviousPaintResult() here.
      layer.SetPreviousPaintResult(kMayBeClippedByCullRect);
    } else {
      const FragmentData* parent_fragment = nullptr;
      if (!should_use_infinite_cull_rect) {
        if (should_match_fragments) {
          for (const FragmentData& walker :
               FragmentDataIterator(parent_object)) {
            parent_fragment = &walker;
            if (parent_fragment->FragmentID() == fragment.FragmentID()) {
              break;
            }
          }
        } else {
          parent_fragment = &parent_object.FirstFragment();
        }
      }

      if (should_use_infinite_cull_rect || !parent_fragment) {
        cull_rect = CullRect::Infinite();
        contents_cull_rect = CullRect::Infinite();
      } else {
        cull_rect =
            ComputeFragmentCullRect(context, layer, fragment, *parent_fragment);
        contents_cull_rect = ComputeFragmentContentsCullRect(
            context, layer, fragment, cull_rect);
      }
    }

    SetFragmentCullRect(layer, fragment, cull_rect);
    force_update_children |=
        SetFragmentContentsCullRect(layer, fragment, contents_cull_rect);
  }

  return force_update_children;
}

CullRect CullRectUpdater::ComputeFragmentCullRect(
    Context& context,
    PaintLayer& layer,
    const FragmentData& fragment,
    const FragmentData& parent_fragment) {
  auto local_state = fragment.LocalBorderBoxProperties().Unalias();
  CullRect cull_rect = parent_fragment.GetContentsCullRect();
  auto parent_state = parent_fragment.ContentsProperties().Unalias();
  const LayoutObject& object = layer.GetLayoutObject();
  const auto& parent_object = context.current.container->GetLayoutObject();
  const LocalFrameView* frame_view = object.GetFrameView();
  const LayoutView& layout_view = *object.View();
  const PaginationState* pagination_state = frame_view->GetPaginationState();
  if (parent_object.IsLayoutView() && pagination_state) {
    parent_state = pagination_state->ContentAreaPropertyTreeStateForCurrentPage(
        layout_view);
  }

  if (object.IsFixedPositioned()) {
    if (const auto* properties = fragment.PaintProperties()) {
      if (const auto* translation = properties->PaintOffsetTranslation()) {
        const auto& view_fragment = object.View()->FirstFragment();
        auto root_contents_state =
            view_fragment.LocalBorderBoxProperties().Unalias();
        if (pagination_state) {
          // Document contents are parented under the pagination properties,
          // which in turn are parented under the LayoutView.
          root_contents_state =
              pagination_state->ContentAreaPropertyTreeStateForCurrentPage(
                  layout_view);
        }
        if (translation->Parent() == &root_contents_state.Transform()) {
          // Use the viewport / page area clip and ignore additional clips
          // (e.g. clip-paths) because they are applied on this fixed-position
          // layer by non-containers which may change location relative to this
          // layer on viewport scroll for which we don't want to change
          // fixed-position cull rects for performance.
          if (pagination_state) {
            local_state.SetClip(root_contents_state.Clip());
          } else {
            local_state.SetClip(
                view_fragment.ContentsProperties().Clip().Unalias());
          }
          parent_state = root_contents_state;
          cull_rect = view_fragment.GetCullRect();
        }
      }
    }
  }

  if (parent_state != local_state) {
    std::optional<CullRect> old_cull_rect;
    // Not using |old_cull_rect| will force the cull rect to be updated
    // (skipping |ChangedEnough|) in |ApplyPaintProperties|.
    if (!ShouldProactivelyUpdate(context, layer))
      old_cull_rect = fragment.GetCullRect();
    bool expanded =
        cull_rect.ApplyPaintProperties(root_state_, parent_state, local_state,
                                       old_cull_rect, expansion_ratio_);
    if (expanded && fragment.GetCullRect() != cull_rect)
      context.current.force_proactive_update = true;
  }
  return cull_rect;
}

CullRect CullRectUpdater::ComputeFragmentContentsCullRect(
    Context& context,
    PaintLayer& layer,
    const FragmentData& fragment,
    const CullRect& cull_rect) {
  auto local_state = fragment.LocalBorderBoxProperties().Unalias();
  CullRect contents_cull_rect = cull_rect;
  auto contents_state = fragment.ContentsProperties().Unalias();
  if (contents_state != local_state) {
    std::optional<CullRect> old_contents_cull_rect;
    // Not using |old_cull_rect| will force the cull rect to be updated
    // (skipping |CullRect::ChangedEnough|) in |ApplyPaintProperties|.
    if (!ShouldProactivelyUpdate(context, layer))
      old_contents_cull_rect = fragment.GetContentsCullRect();
    bool expanded = contents_cull_rect.ApplyPaintProperties(
        root_state_, local_state, contents_state, old_contents_cull_rect,
        expansion_ratio_);
    if (expanded && fragment.GetContentsCullRect() != contents_cull_rect)
      context.current.force_proactive_update = true;
  }
  return contents_cull_rect;
}

bool CullRectUpdater::ShouldProactivelyUpdate(const Context& context,
                                              const PaintLayer& layer) const {
  if (context.current.force_proactive_update)
    return true;

  // If we will repaint anyway, proactively refresh cull rect. A sliding
  // window (aka hysteresis, see: CullRect::ChangedEnough()) is used to
  // avoid frequent cull rect updates because they force a repaint (see:
  // |CullRectUpdater::SetFragmentCullRects|). Proactively updating the cull
  // rect resets the sliding window which will minimize the need to update
  // the cull rect again.
  return layer.SelfOrDescendantNeedsRepaint();
}

void CullRectUpdater::PaintPropertiesChanged(
    const LayoutObject& object,
    const PaintPropertiesChangeInfo& properties_changed) {
  // We don't need to update cull rect for kChangedOnlyCompositedValues (except
  // for some paint translation changes, see below) because we expect no repaint
  // or PAC update for performance.
  // Clip nodes and scroll nodes don't have kChangedOnlyCompositedValues, so we
  // don't need to check ShouldUseInfiniteCullRect before the early return
  // below.
  DCHECK_NE(properties_changed.clip_changed,
            PaintPropertyChangeType::kChangedOnlyCompositedValues);
  DCHECK_NE(properties_changed.scroll_changed,
            PaintPropertyChangeType::kChangedOnlyCompositedValues);

  bool should_use_infinite_cull_rect = false;
  if (object.HasLayer()) {
    bool subtree_should_use_infinite_cull_rect = false;
    auto* view_transition_supplement =
        ViewTransitionSupplement::FromIfExists(object.GetDocument());
    should_use_infinite_cull_rect = ShouldUseInfiniteCullRect(
        *To<LayoutBoxModelObject>(object).Layer(), view_transition_supplement,
        subtree_should_use_infinite_cull_rect);
    if (should_use_infinite_cull_rect &&
        object.FirstFragment().GetCullRect().IsInfinite() &&
        object.FirstFragment().GetContentsCullRect().IsInfinite()) {
      return;
    }
  }

  // Cull rects depend on transforms, clip rects, scroll contents sizes and
  // scroll offsets.
  bool needs_cull_rect_update =
      properties_changed.transform_changed >=
          PaintPropertyChangeType::kChangedOnlySimpleValues ||
      properties_changed.clip_changed >=
          PaintPropertyChangeType::kChangedOnlySimpleValues ||
      properties_changed.scroll_changed >=
          PaintPropertyChangeType::kChangedOnlySimpleValues ||
      HasScrolledEnough(object);

  if (!needs_cull_rect_update) {
    // For cases that the transform change can be directly updated, we should
    // use infinite cull rect or rect expanded for composied scroll (in case of
    // not scrolled enough) to avoid cull rect change and repaint.
    DCHECK(properties_changed.transform_changed !=
               PaintPropertyChangeType::kChangedOnlyCompositedValues ||
           object.IsSVGChild() || should_use_infinite_cull_rect ||
           !HasScrolledEnough(object));
    return;
  }

  if (object.HasLayer()) {
    To<LayoutBoxModelObject>(object).Layer()->SetNeedsCullRectUpdate();
    // Fixed-position cull rects depend on view clip. See
    // ComputeFragmentCullRect().
    if (const auto* layout_view = DynamicTo<LayoutView>(object)) {
      if (const auto* clip_node =
              object.FirstFragment().PaintProperties()->OverflowClip()) {
        if (clip_node->NodeChanged() != PaintPropertyChangeType::kUnchanged) {
          for (const auto& fragment : layout_view->PhysicalFragments()) {
            if (!fragment.HasOutOfFlowFragmentChild()) {
              continue;
            }
            for (const auto& fragment_child : fragment.Children()) {
              if (!fragment_child->IsFixedPositioned()) {
                continue;
              }
              To<LayoutBox>(fragment_child->GetLayoutObject())
                  ->Layer()
                  ->SetNeedsCullRectUpdate();
            }
          }
        }
      }
    }
    return;
  }

  if (object.SlowFirstChild()) {
    // This ensures cull rect update of the child PaintLayers affected by the
    // paint property change on a non-PaintLayer. Though this may unnecessarily
    // force update of unrelated children, the situation is rare and this is
    // much easier.
    object.EnclosingLayer()->SetForcesChildrenCullRectUpdate();
  }
}

bool CullRectUpdater::IsOverridingCullRects() {
  return !!g_original_cull_rects;
}

FragmentCullRects::FragmentCullRects(FragmentData& fragment)
    : fragment(&fragment),
      cull_rect(fragment.GetCullRect()),
      contents_cull_rect(fragment.GetContentsCullRect()) {}

OverriddenCullRectScope::OverriddenCullRectScope(PaintLayer& starting_layer,
                                                 const CullRect& cull_rect,
                                                 bool disable_expansion) {
  outer_original_cull_rects_ = g_original_cull_rects;

  if (starting_layer.IsRootLayer() &&
      starting_layer.GetLayoutObject().GetFrame()->IsLocalRoot() &&
      !starting_layer.NeedsCullRectUpdate() &&
      !starting_layer.DescendantNeedsCullRectUpdate() &&
      cull_rect ==
          starting_layer.GetLayoutObject().FirstFragment().GetCullRect()) {
    // The current cull rects are good.
    return;
  }

  g_original_cull_rects = &original_cull_rects_;
  CullRectUpdater updater(starting_layer, disable_expansion);
  updater.UpdateInternal(cull_rect);
}

OverriddenCullRectScope::~OverriddenCullRectScope() {
  if (outer_original_cull_rects_ == g_original_cull_rects)
    return;

  DCHECK_EQ(g_original_cull_rects, &original_cull_rects_);
  g_original_cull_rects = outer_original_cull_rects_;
  for (FragmentCullRects& cull_rects : original_cull_rects_) {
    cull_rects.fragment->SetCullRect(cull_rects.cull_rect);
    cull_rects.fragment->SetContentsCullRect(cull_rects.contents_cull_rect);
  }
}

}  // namespace blink

"""

```