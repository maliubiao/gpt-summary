Response:
The user wants a summary of the provided C++ code, specifically the `paint_artifact_compositor.cc` file from the Chromium Blink engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The filename and the class name `PaintArtifactCompositor` strongly suggest this code is responsible for managing how paint artifacts (results of rendering) are turned into composited layers. Compositing is a key optimization technique for smooth scrolling and animations.

2. **Scan for key data structures and classes:**
    * `PaintArtifact`:  This is likely the input – the description of what to render.
    * `PendingLayer`:  This seems to be an intermediate representation, a planned composited layer.
    * `cc::Layer`: This is the actual compositing layer from Chromium's Compositor (CC) library.
    * `cc::PaintFlags`, `cc::DisplayItemList`, `cc::EffectNode`, `cc::TransformNode`, `cc::ClipNode`: These are all related to the details of how things are drawn and positioned.
    * `painted_scroll_translations_`:  Indicates handling of scrolling.

3. **Analyze the key methods and their actions:**
    * `Update()` (not shown in this part, but implied): Likely the main function to process a `PaintArtifact`.
    * `CollectPendingLayers()` (within `Update`, not shown):  A crucial step in deciding which parts of the rendering should be separate composited layers.
    * `LayerizeGroup()` and `Layerize()`:  The logic for organizing paint chunks into `PendingLayer`s. This involves decisions about merging and overlapping.
    * `ComputeNeedsCompositedScrolling()`: Determines if a scrolling region should be handled by the compositor.
    * `SetNeedsUpdate()`: Marks that the compositor needs to re-process the `PaintArtifact`.
    * Methods related to JSON output (`GetPendingLayersAsJSON`, `GetLayersAsJSON`): For debugging and introspection.

4. **Connect the code to web concepts (JavaScript, HTML, CSS):**
    * **CSS:**  Properties like `transform`, `clip-path`, `opacity`, `background-color`, `overflow: scroll` directly influence the creation and properties of composited layers.
    * **HTML:**  The structure of the DOM and elements with specific attributes can trigger compositing (e.g., elements with CSS transforms).
    * **JavaScript:** JavaScript animations and interactions that modify CSS properties can lead to compositing decisions. Specifically, scroll events are clearly handled.

5. **Look for logic and decision-making:** The code mentions "merging" and "overlapping" of paint chunks. This points to optimization strategies to reduce the number of composited layers. The decision of whether to composite a scrolling area is also a key logical step.

6. **Identify potential errors and assumptions:** The code comments mention scenarios where a "full update" is required, suggesting that incremental updates are not always possible. The logic around matching "old" and "new" layers implies potential problems with inconsistent updates.

7. **Focus on the provided code snippet (Part 1):**  This part mainly deals with initialization, tracking of pending layers, determining if a full update is needed after paint, and the core logic of grouping paint chunks into preliminary layers (`PendingLayer`) based on properties and compositing needs.

8. **Structure the summary:** Organize the findings into logical categories: core function, relation to web technologies, logical reasoning, potential errors, and finally, a summary of Part 1.

**(Self-Correction during the process):** Initially, I might focus too heavily on the direct translation of code lines. However, the prompt asks for *functionality*. It's important to abstract away from the low-level implementation details and focus on *what* the code achieves in the broader context of web rendering. For instance, instead of just saying "it iterates through paint chunks," say "it organizes paint chunks into preliminary layers."
好的，根据你提供的代码片段，`blink/renderer/platform/graphics/compositing/paint_artifact_compositor.cc` 文件的第 1 部分主要负责以下功能：

**核心功能：管理和组织渲染结果（Paint Artifacts）以创建和更新合成图层（Composited Layers）。**

更具体地说，它做了以下事情：

1. **追踪待处理的图层（Pending Layers）：**  维护一个 `pending_layers_` 列表，用于存储即将被创建或更新的合成图层的相关信息。

2. **决定是否需要完整的图层更新：**  `SetNeedsFullUpdateAfterPaintIfNeeded` 函数会比较之前的渲染结果 (`previous`) 和新的渲染结果 (`repainted`)，来判断是否需要执行完整的合成图层更新。如果只是某些绘制属性发生变化，而图层的结构或合成策略不需要改变，则可能不需要完整的更新。

3. **判断元素是否已经合成：** `HasComposited` 函数检查指定的元素 (`CompositorElementId`) 是否已经创建了对应的合成图层。

4. **核心的图层化逻辑（Layerization）：**  通过 `Layerizer` 类，将渲染结果中的绘制块（Paint Chunks）组织成 `PendingLayer` 对象。这个过程包括：
    * **分组 (Grouping):**  根据绘制属性树（尤其是 Effect 属性节点）将绘制块分组。
    * **合并 (Merging):**  尝试将可以合并的连续或非连续的绘制块合并到同一个 `PendingLayer` 中，以减少合成图层的数量，提升性能。合并的条件包括属性状态兼容且不会跨越直接合成边界。
    * **重叠处理 (Overlap Handling):** 如果新的图层可能与之前的图层重叠，会设置相应的合成类型 (`SetCompositingTypeToOverlap`)。
    * **分解效果 (Decompositing Effect):**  在满足特定条件的情况下，可以将子分组的图层“分解”并合并到父分组的图层中。

5. **处理滚动 (Scrolling)：**
    * 维护一个 `painted_scroll_translations_` 映射，记录了滚动相关的变换属性节点及其合成信息。
    * `ComputeNeedsCompositedScrolling` 函数根据滚动属性、用户是否允许滚动、LCD 文本渲染偏好以及背景是否不透明等因素，判断一个滚动区域是否需要使用合成滚动。
    * `UpdatePaintedScrollTranslationsBeforeLayerization` 函数在图层化之前更新 `painted_scroll_translations_`，记录哪些滚动区域需要合成，以及是否需要强制主线程重绘。
    * `NeedsCompositedScrolling` 函数判断给定的滚动变换属性节点是否需要合成滚动。
    * `ShouldForceMainThreadRepaint` 函数判断给定的滚动变换属性节点是否需要强制主线程重绘。

6. **追踪栅格化失效 (Raster Invalidations)：**  如果启用了追踪栅格化失效的功能，会记录相关的无效区域。

7. **提供 JSON 格式的图层信息：** 提供 `GetPendingLayersAsJSON` 和 `GetLayersAsJSON` 函数，用于以 JSON 格式输出待处理的图层信息和已创建的图层信息，用于调试和分析。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:**  该文件的核心功能是根据渲染结果创建合成图层，而渲染结果很大程度上取决于 CSS 样式。
    * **`transform` 属性:** CSS 的 `transform` 属性会导致创建合成图层，并影响 `TransformPaintPropertyNode` 的信息。代码中会判断是否需要为具有 `transform` 属性的元素创建单独的合成图层。
    * **`opacity` 属性:** CSS 的 `opacity` 属性会影响 `EffectPaintPropertyNode`，并可能导致创建合成图层。
    * **`clip-path` 和 `overflow: hidden` 等裁剪属性:** 这些属性会影响 `ClipPaintPropertyNode`，并可能导致创建合成图层。代码中会处理裁剪区域。
    * **`position: fixed` 和 `overflow: scroll` 等属性:** 这些属性会影响滚动行为，代码中会判断是否需要为可滚动的元素创建合成图层，以及如何处理固定定位的元素。
    * **`background-color` 属性:** 背景颜色的不透明度会影响合成决策，例如，不透明的背景可能允许对包含 LCD 渲染文本的区域进行合成。
    * **`will-change` 属性:**  虽然代码中没有直接提及，但 `will-change` 属性可以提示浏览器哪些元素可能会发生变化，从而影响合成策略。

* **HTML:** HTML 的结构和元素的属性也会影响合成。
    * **`<video>` 和 `<iframe>` 等元素:** 这些元素通常会创建自己的合成图层。
    * **具有 CSS 动画或过渡效果的元素:** 这些动画和过渡通常需要在合成图层上进行。

* **JavaScript:** JavaScript 可以通过修改元素的 CSS 样式来触发合成图层的创建和更新。
    * **使用 JavaScript 动画库（例如 GSAP）或 `requestAnimationFrame` 修改 `transform`、`opacity` 等属性:** 这些操作会直接影响合成图层的状态。
    * **监听滚动事件并修改元素样式:** 这会触发滚动相关的合成逻辑。

**逻辑推理示例（假设输入与输出）：**

**假设输入:**

* **`previous` (之前的 `PaintArtifact`):** 代表一个简单的 div 元素，没有特殊的 CSS 属性。
* **`repainted` (当前的 `PaintArtifact`):**  同一个 div 元素，但添加了 `transform: translate(10px, 10px);` 的 CSS 属性。

**逻辑推理:**

1. `SetNeedsFullUpdateAfterPaintIfNeeded` 函数会比较 `previous` 和 `repainted` 的绘制块。
2. 由于 `repainted` 的变换属性发生了变化，`NeedsFullUpdateAfterPaintingChunk` 函数会返回 `true`。
3. `SetNeedsFullUpdateAfterPaintIfNeeded` 将会调用 `SetNeedsUpdate()`，标记需要进行完整的合成图层更新。

**假设输出:**

* `needs_update_` 标志被设置为 `true`。

**用户或编程常见的使用错误示例：**

1. **频繁且不必要的样式更改:** 如果 JavaScript 代码频繁地修改元素的 CSS 属性（即使这些修改不会导致视觉上的变化），可能会导致不必要的合成图层更新，从而降低性能。例如，在一个循环中不断设置一个实际上没有变化的 `opacity` 值。

2. **过度使用 `will-change` 属性:**  虽然 `will-change` 可以提示浏览器进行优化，但过度使用或不恰当的使用可能会导致浏览器分配过多的资源，反而降低性能。

3. **在主线程执行耗时的 JavaScript 计算，导致合成线程等待:**  即使使用了合成图层来优化动画和滚动，如果主线程上的 JavaScript 计算过于耗时，仍然会阻塞合成线程，导致卡顿。

4. **不理解合成的原理，错误地认为所有动画都需要合成:**  某些简单的动画或样式更改可能不需要创建新的合成图层，直接在主线程渲染即可。过度依赖合成可能会增加内存消耗。

**归纳一下它的功能（针对第 1 部分）：**

`PaintArtifactCompositor` 的第 1 部分主要负责**接收渲染结果（Paint Artifacts），并根据渲染结果的差异以及元素的 CSS 属性等信息，决定是否需要进行完整的合成图层更新。它还负责将渲染结果中的绘制块组织成初步的图层表示（Pending Layers），并初步处理滚动相关的合成决策。**  这部分是合成过程的准备阶段，为后续创建实际的合成图层奠定了基础。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/compositing/paint_artifact_compositor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"

#include <memory>
#include <utility>

#include "base/debug/dump_without_crashing.h"
#include "base/logging.h"
#include "base/ranges/algorithm.h"
#include "cc/base/features.h"
#include "cc/layers/solid_color_scrollbar_layer.h"
#include "cc/paint/display_item_list.h"
#include "cc/paint/paint_flags.h"
#include "cc/trees/effect_node.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/mutator_host.h"
#include "cc/view_transition/view_transition_request.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/geometry/geometry_as_json.h"
#include "third_party/blink/renderer/platform/graphics/compositing/adjust_mask_layer_geometry.h"
#include "third_party/blink/renderer/platform/graphics/compositing/content_layer_client_impl.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/clip_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/foreign_layer_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_artifact.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_chunk_subset.h"
#include "third_party/blink/renderer/platform/graphics/paint/property_tree_state.h"
#include "third_party/blink/renderer/platform/graphics/paint/raster_invalidation_tracking.h"
#include "third_party/blink/renderer/platform/graphics/paint/scroll_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/scrollbar_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/transform_paint_property_node.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "ui/gfx/geometry/rect.h"

namespace blink {

// cc property trees make use of a sequence number to identify when tree
// topology changes. For now we naively increment the sequence number each time
// we update the property trees. We should explore optimizing our management of
// the sequence number through the use of a dirty bit or similar. See
// http://crbug.com/692842#c4.
static int g_s_property_tree_sequence_number = 1;

class PaintArtifactCompositor::OldPendingLayerMatcher {
  STACK_ALLOCATED();

 public:
  explicit OldPendingLayerMatcher(PendingLayers pending_layers)
      : pending_layers_(std::move(pending_layers)) {}

  // Finds the next PendingLayer that can be matched by |new_layer|.
  // It's efficient if most of the pending layers can be matched sequentially.
  PendingLayer* Find(const PendingLayer& new_layer) {
    if (pending_layers_.empty())
      return nullptr;
    if (!new_layer.FirstPaintChunk().CanMatchOldChunk())
      return nullptr;
    wtf_size_t i = next_index_;
    do {
      wtf_size_t next = (i + 1) % pending_layers_.size();
      if (new_layer.Matches(pending_layers_[i])) {
        next_index_ = next;
        return &pending_layers_[i];
      }
      i = next;
    } while (i != next_index_);
    return nullptr;
  }

 private:
  wtf_size_t next_index_ = 0;
  PendingLayers pending_layers_;
};

PaintArtifactCompositor::PaintArtifactCompositor(
    base::WeakPtr<CompositorScrollCallbacks> scroll_callbacks)
    : scroll_callbacks_(std::move(scroll_callbacks)),
      tracks_raster_invalidations_(VLOG_IS_ON(3)) {
  root_layer_ = cc::Layer::Create();
}

PaintArtifactCompositor::~PaintArtifactCompositor() {}

void PaintArtifactCompositor::Trace(Visitor* visitor) const {
  visitor->Trace(pending_layers_);
  visitor->Trace(painted_scroll_translations_);
  visitor->Trace(synthesized_clip_cache_);
}

void PaintArtifactCompositor::SetTracksRasterInvalidations(bool should_track) {
  tracks_raster_invalidations_ = should_track || VLOG_IS_ON(3);
  for (auto& pending_layer : pending_layers_) {
    if (auto* client = pending_layer.GetContentLayerClient())
      client->GetRasterInvalidator().SetTracksRasterInvalidations(should_track);
  }
}

void PaintArtifactCompositor::WillBeRemovedFromFrame() {
  root_layer_->RemoveAllChildren();
}

void PaintArtifactCompositor::SetLCDTextPreference(
    LCDTextPreference preference) {
  if (lcd_text_preference_ == preference) {
    return;
  }
  SetNeedsUpdate();
  lcd_text_preference_ = preference;
}

std::unique_ptr<JSONArray> PaintArtifactCompositor::GetPendingLayersAsJSON()
    const {
  std::unique_ptr<JSONArray> result = std::make_unique<JSONArray>();
  for (const PendingLayer& pending_layer : pending_layers_)
    result->PushObject(pending_layer.ToJSON());
  return result;
}

// Get a JSON representation of what layers exist for this PAC.
std::unique_ptr<JSONObject> PaintArtifactCompositor::GetLayersAsJSON(
    LayerTreeFlags flags) const {
  if (!tracks_raster_invalidations_) {
    flags &= ~(kLayerTreeIncludesInvalidations |
               kLayerTreeIncludesDetailedInvalidations);
  }

  LayersAsJSON layers_as_json(flags);
  for (const auto& layer : root_layer_->children()) {
    const ContentLayerClientImpl* layer_client = nullptr;
    const TransformPaintPropertyNode* transform = nullptr;
    for (const auto& pending_layer : pending_layers_) {
      if (layer.get() == &pending_layer.CcLayer()) {
        layer_client = pending_layer.GetContentLayerClient();
        transform = &pending_layer.GetPropertyTreeState().Transform();
        break;
      }
    }
    if (!transform) {
      for (const auto& pending_layer : pending_layers_) {
        if (pending_layer.GetPropertyTreeState().Transform().CcNodeId(
                layer->property_tree_sequence_number()) ==
            layer->transform_tree_index()) {
          transform = &pending_layer.GetPropertyTreeState().Transform();
          break;
        }
      }
    }
    DCHECK(transform);
    layers_as_json.AddLayer(*layer, *transform, layer_client);
  }
  return layers_as_json.Finalize();
}

const TransformPaintPropertyNode&
PaintArtifactCompositor::ScrollTranslationStateForLayer(
    const PendingLayer& pending_layer) {
  if (pending_layer.GetCompositingType() == PendingLayer::kScrollHitTestLayer) {
    return pending_layer.ScrollTranslationForScrollHitTestLayer();
  }

  // When HitTestOpaqueness is enabled, use the correct scroll state for fixed
  // position content, so scrolls on fixed content is correctly handled on the
  // compositor if the fixed content is opaque to hit test.
  const auto& transform = pending_layer.GetPropertyTreeState().Transform();
  return RuntimeEnabledFeatures::HitTestOpaquenessEnabled()
             ? transform.ScrollTranslationState()
             : transform.NearestScrollTranslationNode();
}

bool PaintArtifactCompositor::NeedsCompositedScrolling(
    const TransformPaintPropertyNode& scroll_translation) const {
  // This function needs painted_scroll_translations_ which is only available
  // during full update.
  DCHECK(needs_update_);
  DCHECK(scroll_translation.ScrollNode());
  if (scroll_translation.HasDirectCompositingReasons()) {
    return true;
  }
  // Note: main thread scrolling reasons are not checked here because even if
  // the scroller needs main thread to update scroll, compositing the scroller
  // can still benefit performance by reducing raster invalidations.
  auto it = painted_scroll_translations_.find(&scroll_translation);
  if (it == painted_scroll_translations_.end()) {
    // Negative z-index scrolling contents in a non-stacking-context scroller
    // appear earlier than the ScrollHitTest of the scroller, and this
    // method can be called before ComputeNeedsCompositedScrolling() for the
    // ScrollHitTest. If LCD-text is strongly preferred, here we assume the
    // scroller is not composited. Even if later the scroller is found to
    // have an opaque background and composited, not compositing the negative
    // z-index contents won't cause any problem because they (with possible
    // wrong rendering) are obscured by the opaque background.
    return lcd_text_preference_ != LCDTextPreference::kStronglyPreferred;
  }
  return it->value.is_composited;
}

bool PaintArtifactCompositor::ShouldForceMainThreadRepaint(
    const TransformPaintPropertyNode& scroll_translation) const {
  DCHECK(!NeedsCompositedScrolling(scroll_translation));
  auto it = painted_scroll_translations_.find(&scroll_translation);
  return it != painted_scroll_translations_.end() &&
         it->value.force_main_thread_repaint;
}

bool PaintArtifactCompositor::ComputeNeedsCompositedScrolling(
    const PaintArtifact& artifact,
    PaintChunks::const_iterator chunk_cursor) const {
  // The chunk must be a ScrollHitTest chunk which contains no display items.
  DCHECK(chunk_cursor->hit_test_data);
  DCHECK(chunk_cursor->hit_test_data->scroll_translation);
  DCHECK_EQ(chunk_cursor->size(), 0u);
  const auto& scroll_translation =
      *chunk_cursor->hit_test_data->scroll_translation;
  DCHECK(scroll_translation.ScrollNode());
  if (scroll_translation.HasDirectCompositingReasons()) {
    return true;
  }
  // Don't automatically composite non-user-scrollable scrollers.
  if (!scroll_translation.ScrollNode()->UserScrollable()) {
    return false;
  }
  auto preference =
      scroll_translation.ScrollNode()->GetCompositedScrollingPreference();
  if (preference == CompositedScrollingPreference::kNotPreferred) {
    return false;
  }
  if (preference == CompositedScrollingPreference::kPreferred) {
    return true;
  }
  if (lcd_text_preference_ != LCDTextPreference::kStronglyPreferred) {
    return true;
  }
  // Find the chunk containing the scrolling background which normally defines
  // the opaqueness of the scrolling contents. If it has an opaque rect
  // covering the whole scrolling contents, we can use composited scrolling
  // without losing LCD text.
  for (auto next = chunk_cursor + 1; next != artifact.GetPaintChunks().end();
       ++next) {
    if (&next->properties.Transform() ==
        &chunk_cursor->properties.Transform()) {
      // Skip scroll controls that are painted in the same transform space
      // as the ScrollHitTest.
      continue;
    }
    return &next->properties.Transform().Unalias() == &scroll_translation &&
           &next->properties.Clip().Unalias() ==
               scroll_translation.ScrollNode()->OverflowClipNode() &&
           &next->properties.Effect().Unalias() ==
               &chunk_cursor->properties.Effect().Unalias() &&
           next->rect_known_to_be_opaque.Contains(
               scroll_translation.ScrollNode()->ContentsRect());
  }
  return true;
}

void PaintArtifactCompositor::UpdatePaintedScrollTranslationsBeforeLayerization(
    const PaintArtifact& artifact,
    PaintChunks::const_iterator chunk_cursor) {
  const PaintChunk& chunk = *chunk_cursor;
  const HitTestData* hit_test_data = chunk.hit_test_data.Get();
  if (hit_test_data && hit_test_data->scroll_translation) {
    const auto& scroll_translation = *hit_test_data->scroll_translation;
    bool is_composited =
        ComputeNeedsCompositedScrolling(artifact, chunk_cursor);
    auto it = painted_scroll_translations_.find(&scroll_translation);
    if (it == painted_scroll_translations_.end()) {
      painted_scroll_translations_.insert(
          &scroll_translation,
          ScrollTranslationInfo{.scrolling_contents_cull_rect =
                                    hit_test_data->scrolling_contents_cull_rect,
                                .is_composited = is_composited});
    } else {
      // The node was added in the second half of this function before.
      // Update the is_composited field now.
      it->value.scrolling_contents_cull_rect =
          hit_test_data->scrolling_contents_cull_rect;
      if (is_composited) {
        it->value.is_composited = true;
        it->value.force_main_thread_repaint = false;
      } else {
        CHECK(!it->value.is_composited);
      }
    }
  }

  // Touch action region, wheel event region, region capture and selection
  // under a non-composited scroller depend on the scroll offset so need to
  // force main-thread repaint. Non-fast scrollable region doesn't matter
  // because that of a nested non-composited scroller is always covered by
  // that of the parent non-composited scroller.
  if (RuntimeEnabledFeatures::RasterInducingScrollEnabled() &&
      ((hit_test_data &&
        (!hit_test_data->touch_action_rects.empty() ||
         !hit_test_data->wheel_event_rects.empty() ||
         // HitTestData of these types induce touch action regions.
         chunk.id.type == DisplayItem::Type::kScrollbarHitTest ||
         chunk.id.type == DisplayItem::Type::kResizerScrollHitTest)) ||
       chunk.region_capture_data || chunk.layer_selection_data)) {
    const auto& transform = chunk.properties.Transform().Unalias();
    // Mark all non-composited scroll ancestors within the same direct
    // compositing boundary (ideally we should check for both direct and
    // indirect compositing boundaries but that's impossible before full
    // layerization) also needing main thread repaint.
    const auto* composited_ancestor =
        transform.NearestDirectlyCompositedAncestor();
    for (const auto* scroll_translation =
             &transform.NearestScrollTranslationNode();
         scroll_translation;
         scroll_translation =
             scroll_translation->ParentScrollTranslationNode()) {
      if (scroll_translation->NearestDirectlyCompositedAncestor() !=
          composited_ancestor) {
        break;
      }
      auto it = painted_scroll_translations_.find(scroll_translation);
      if (it == painted_scroll_translations_.end()) {
        // The paint chunk appears before the ScrollHitTest of the scroll
        // translation. We'll complete the data when we see the ScrollHitTest.
        painted_scroll_translations_.insert(
            scroll_translation,
            ScrollTranslationInfo{.force_main_thread_repaint = true});
      } else {
        if (it->value.is_composited || it->value.force_main_thread_repaint) {
          break;
        }
        it->value.force_main_thread_repaint = true;
      }
    }
  }
}

PendingLayer::CompositingType PaintArtifactCompositor::ChunkCompositingType(
    const PaintArtifact& artifact,
    const PaintChunk& chunk) const {
  if (chunk.hit_test_data && chunk.hit_test_data->scroll_translation &&
      NeedsCompositedScrolling(*chunk.hit_test_data->scroll_translation)) {
    return PendingLayer::kScrollHitTestLayer;
  }
  if (chunk.size() == 1) {
    const auto& item = artifact.GetDisplayItemList()[chunk.begin_index];
    if (item.IsForeignLayer()) {
      return PendingLayer::kForeignLayer;
    }
    if (const auto* scrollbar = DynamicTo<ScrollbarDisplayItem>(item)) {
      if (const auto* scroll_translation = scrollbar->ScrollTranslation()) {
        if (RuntimeEnabledFeatures::RasterInducingScrollEnabled() ||
            NeedsCompositedScrolling(*scroll_translation)) {
          return PendingLayer::kScrollbarLayer;
        }
      }
    }
  }
  return PendingLayer::kOther;
}

namespace {

cc::Layer* ForeignLayer(const PaintChunk& chunk,
                        const PaintArtifact& artifact) {
  if (chunk.size() != 1)
    return nullptr;
  const auto& first_display_item =
      artifact.GetDisplayItemList()[chunk.begin_index];
  auto* foreign_layer = DynamicTo<ForeignLayerDisplayItem>(first_display_item);
  return foreign_layer ? foreign_layer->GetLayer() : nullptr;
}

// True if the paint chunk change affects the result of |Update|, such as the
// compositing decisions in |CollectPendingLayers|. This will return false for
// repaint updates that can be handled by |UpdateRepaintedLayers|, such as
// background color changes.
bool NeedsFullUpdateAfterPaintingChunk(
    const PaintChunk& previous,
    const PaintArtifact& previous_artifact,
    const PaintChunk& repainted,
    const PaintArtifact& repainted_artifact) {
  if (!repainted.Matches(previous))
    return true;

  if (repainted.is_moved_from_cached_subsequence) {
    DCHECK_EQ(previous.bounds, repainted.bounds);
    DCHECK_EQ(previous.DrawsContent(), repainted.DrawsContent());
    DCHECK_EQ(previous.rect_known_to_be_opaque,
              repainted.rect_known_to_be_opaque);
    DCHECK_EQ(previous.text_known_to_be_on_opaque_background,
              repainted.text_known_to_be_on_opaque_background);
    DCHECK_EQ(previous.has_text, repainted.has_text);

    // Debugging for https://crbug.com/1237389 and https://crbug.com/1230104.
    // Before returning that a full update is not needed, check that the
    // properties are changed, which would indicate a missing call to
    // SetNeedsUpdate.
    if (previous.properties != repainted.properties) {
      base::debug::DumpWithoutCrashing();
      return true;
    }

    // Not checking ForeignLayer() here because the old ForeignDisplayItem
    // was set to 0 when we moved the cached subsequence. This is also the
    // reason why we check is_moved_from_cached_subsequence before checking
    // ForeignLayer().
    return false;
  }

  // Bounds are used in overlap testing.
  // TODO(pdr): If the bounds shrink, that does affect overlap testing but we
  // could return false to continue using less-than-optimal overlap testing in
  // order to save a full compositing update.
  if (previous.bounds != repainted.bounds)
    return true;

  // Changing foreign layers requires a full update to push the new cc::Layers.
  if (ForeignLayer(previous, previous_artifact) !=
      ForeignLayer(repainted, repainted_artifact)) {
    return true;
  }

  // Opaqueness of individual chunks is used to set the cc::Layer's contents
  // opaque property.
  if (previous.rect_known_to_be_opaque != repainted.rect_known_to_be_opaque)
    return true;
  // Similar to opaqueness, opaqueness for text is used to set the cc::Layer's
  // contents opaque for text property.
  if (previous.text_known_to_be_on_opaque_background !=
      repainted.text_known_to_be_on_opaque_background) {
    return true;
  }
  // Whether background color is transparent affects cc::Layers's contents
  // opaque property.
  if ((previous.background_color.color == SkColors::kTransparent) !=
      (repainted.background_color.color == SkColors::kTransparent)) {
    return true;
  }

  // |has_text| affects compositing decisions (see:
  // |PendingLayer::MergeInternal|).
  if (previous.has_text != repainted.has_text)
    return true;

  // |PaintChunk::DrawsContent()| affects whether a layer draws content which
  // affects whether mask layers are created (see:
  // |SwitchToEffectNodeWithSynthesizedClip|).
  if (previous.DrawsContent() != repainted.DrawsContent())
    return true;

  // Solid color status change requires full update to change the cc::Layer
  // type.
  if (previous.background_color.is_solid_color !=
      repainted.background_color.is_solid_color) {
    return true;
  }

  // Hit test opaqueness of the paint chunk may affect that of cc::Layer.
  if (previous.hit_test_opaqueness != repainted.hit_test_opaqueness) {
    return true;
  }

  // Debugging for https://crbug.com/1237389 and https://crbug.com/1230104.
  // Before returning that a full update is not needed, check that the
  // properties are changed, which would indicate a missing call to
  // SetNeedsUpdate.
  if (previous.properties != repainted.properties) {
    base::debug::DumpWithoutCrashing();
    return true;
  }

  return false;
}

}  // namespace

void PaintArtifactCompositor::SetNeedsFullUpdateAfterPaintIfNeeded(
    const PaintArtifact& previous,
    const PaintArtifact& repainted) {
  if (needs_update_)
    return;

  // Adding or removing chunks requires a full update to add/remove cc::layers.
  if (previous.GetPaintChunks().size() != repainted.GetPaintChunks().size()) {
    SetNeedsUpdate();
    return;
  }

  // Loop over both paint chunk subsets in order.
  for (wtf_size_t i = 0; i < previous.GetPaintChunks().size(); i++) {
    if (NeedsFullUpdateAfterPaintingChunk(
            previous.GetPaintChunks()[i], previous,
            repainted.GetPaintChunks()[i], repainted)) {
      SetNeedsUpdate();
      return;
    }
  }
}

bool PaintArtifactCompositor::HasComposited(
    CompositorElementId element_id) const {
  // |Update| creates PropertyTrees on the LayerTreeHost to represent the
  // composited page state. Check if it has created a property tree node for
  // the given |element_id|.
  DCHECK(!NeedsUpdate()) << "This should only be called after an update";
  return root_layer_->layer_tree_host()->property_trees()->HasElement(
      element_id);
}

class PaintArtifactCompositor::Layerizer {
  STACK_ALLOCATED();

 public:
  Layerizer(PaintArtifactCompositor& compositor,
            const PaintArtifact& artifact,
            wtf_size_t reserve_capacity)
      : compositor_(compositor),
        artifact_(artifact),
        chunk_cursor_(artifact.GetPaintChunks().begin()) {
    pending_layers_.reserve(reserve_capacity);
  }

  PendingLayers Layerize();

 private:
  // This is the internal recursion of Layerize(). This function loops over the
  // list of paint chunks, scoped by an isolated group (i.e. effect node).
  // Inside of the loop, chunks are tested for overlap and merge compatibility.
  // Subgroups are handled by recursion, and will be tested for "decompositing"
  // upon return.
  //
  // Merge compatibility means consecutive chunks may be layerized into the
  // same backing (i.e. merged) if their property states don't cross
  // direct-compositing boundary.
  //
  // Non-consecutive chunks that are nevertheless compatible may still be
  // merged, if reordering of the chunks won't affect the ultimate result.
  // This is determined by overlap testing such that chunks can be safely
  // reordered if their effective bounds in screen space can't overlap.
  //
  // The recursion only tests merge & overlap for chunks scoped by the same
  // group. This is where "decompositing" came in. Upon returning from a
  // recursion, the layerization of the subgroup may be tested for merge &
  // overlap with other chunks in the parent group, if grouping requirement
  // can be satisfied (and the effect node has no direct reason).
  void LayerizeGroup(const EffectPaintPropertyNode&, bool force_draws_content);
  bool DecompositeEffect(const EffectPaintPropertyNode& parent_effect,
                         wtf_size_t first_layer_in_parent_group_index,
                         const EffectPaintPropertyNode& effect,
                         wtf_size_t layer_index);

  PaintArtifactCompositor& compositor_;
  const PaintArtifact& artifact_;
  PaintChunks::const_iterator chunk_cursor_;
  PendingLayers pending_layers_;
  // This is to optimize the first time a paint property tree node is
  // encountered that has direct compositing reasons. This case will always
  // start a new layer and can skip merge tests. New values are added when
  // transform nodes are first encountered.
  HeapHashSet<Member<const TransformPaintPropertyNode>>
      directly_composited_transforms_;
};

// Returns nullptr if 'ancestor' is not a strict ancestor of 'node'.
// Otherwise, return the child of 'ancestor' that is an ancestor of 'node' or
// 'node' itself.
static const EffectPaintPropertyNode* StrictUnaliasedChildOfAlongPath(
    const EffectPaintPropertyNode& ancestor,
    const EffectPaintPropertyNode& node) {
  const auto* n = &node;
  while (n) {
    const auto* parent = n->UnaliasedParent();
    if (parent == &ancestor)
      return n;
    n = parent;
  }
  return nullptr;
}

bool PaintArtifactCompositor::Layerizer::DecompositeEffect(
    const EffectPaintPropertyNode& parent_effect,
    wtf_size_t first_layer_in_parent_group_index,
    const EffectPaintPropertyNode& effect,
    wtf_size_t layer_index) {
  // The layer must be the last layer in pending_layers_.
  DCHECK_EQ(layer_index, pending_layers_.size() - 1);

  // If the effect associated with the layer is deeper than than the effect
  // we are attempting to decomposite, than implies some previous decision
  // did not allow to decomposite intermediate effects.
  PendingLayer& layer = pending_layers_[layer_index];
  if (&layer.GetPropertyTreeState().Effect() != &effect)
    return false;
  if (layer.ChunkRequiresOwnLayer())
    return false;
  if (effect.HasDirectCompositingReasons())
    return false;

  PropertyTreeState group_state(effect.LocalTransformSpace().Unalias(),
                                effect.OutputClip()
                                    ? effect.OutputClip()->Unalias()
                                    : layer.GetPropertyTreeState().Clip(),
                                effect);
  auto is_composited_scroll = [this](const TransformPaintPropertyNode& t) {
    return compositor_.NeedsCompositedScrolling(t);
  };
  std::optional<PropertyTreeState> upcast_state = group_state.CanUpcastWith(
      layer.GetPropertyTreeState(), is_composited_scroll);
  if (!upcast_state)
    return false;

  upcast_state->SetEffect(parent_effect);

  // An exotic blend mode can be decomposited only if the src (`layer`) and
  // the dest (previous layers in the parent group) will be in the same
  // composited layer to ensure the blend mode has access to both the src and
  // the dest.
  if (effect.BlendMode() != SkBlendMode::kSrcOver) {
    auto num_previous_siblings =
        layer_index - first_layer_in_parent_group_index;
    // If num_previous_siblings is zero, the dest is empty, and the blend mode
    // can be decomposited.
    if (num_previous_siblings) {
      if (num_previous_siblings > 2) {
        // If the dest has multiple composited layers, the blend mode must be
        // composited, too.
        return false;
      }
      if (num_previous_siblings == 2 &&
          // Same as the above, but if the first layer doesn't draw content,
          // only the second layer is the dest, and we'll check CanMerge()
          // with the second layer below.
          pending_layers_[first_layer_in_parent_group_index].DrawsContent()) {
        return false;
      }
      // The previous sibling is the dest. Check whether the src (`layer`), if
      // it's upcasted, can be merged with the dest so that they will be in
      // the same composited layer.
      const auto& previous_sibling = pending_layers_[layer_index - 1];
      if (previous_sibling.DrawsContent() &&
          !previous_sibling.CanMergeWithDecompositedBlendMode(
              layer, *upcast_state, is_composited_scroll)) {
        return false;
      }
    }
  }

  layer.Upcast(*upcast_state);
  return true;
}

void PaintArtifactCompositor::Layerizer::LayerizeGroup(
    const EffectPaintPropertyNode& current_group,
    bool force_draws_content) {
  wtf_size_t first_layer_in_current_group = pending_layers_.size();
  // The worst case time complexity of the algorithm is O(pqd), where
  // p = the number of paint chunks.
  // q = average number of trials to find a squash layer or rejected
  //     for overlapping.
  // d = (sum of) the depth of property trees.
  // The analysis as follows:
  // Every paint chunk will be visited by the main loop below for exactly
  // once, except for chunks that enter or exit groups (case B & C below). For
  // normal chunk visit (case A), the only cost is determining squash, which
  // costs O(qd), where d came from |CanUpcastWith| and geometry mapping.
  // Subtotal: O(pqd)
  // For group entering and exiting, it could cost O(d) for each group, for
  // searching the shallowest subgroup (StrictChildOfAlongPath), thus O(d^2)
  // in total.
  // Also when exiting group, the group may be decomposited and squashed to a
  // previous layer. Again finding the host costs O(qd). Merging would cost
  // O(p) due to copying the chunk list. Subtotal: O((qd + p)d) = O(qd^2 + pd)
  // Assuming p > d, the total complexity would be O(pqd + qd^2 + pd) = O(pqd)
  while (chunk_cursor_ != artifact_.GetPaintChunks().end()) {
    // Look at the effect node of the next chunk. There are 3 possible cases:
    // A. The next chunk belongs to the current group but no subgroup.
    // B. The next chunk does not belong to the current group.
    // C. The next chunk belongs to some subgroup of the current group.
    const auto& chunk_effect = chunk_cursor_->properties.Effect().Unalias();
    if (&chunk_effect == &current_group) {
      compositor_.UpdatePaintedScrollTranslationsBeforeLayerization(
          artifact_, chunk_cursor_);
      pending_layers_.emplace_back(
          artifact_, *chunk_cursor_,
          compositor_.ChunkCompositingType(artifact_, *chunk_cursor_));
      ++chunk_cursor_;
      // force_draws_content doesn't apply to pending layers that require own
      // layer, specifically scrollbar layers, foreign layers, scroll hit
      // testing layers.
      if (pending_layers_.back().ChunkRequiresOwnLayer()) {
        continue;
      }
    } else {
      const EffectPaintPropertyNode* subgroup =
          StrictUnaliasedChildOfAlongPath(current_group, chunk_effect);
      // Case B: This means we need to close the current group without
      //         processing the next chunk.
      if (!subgroup)
        break;
      // Case C: The following chunks belong to a subgroup. Process them by
      //         a recursion call.
      wtf_size_t first_layer_in_subgroup = pending_layers_.size();
      LayerizeGroup(*subgroup, force_draws_content || subgroup->DrawsContent());
      // The above LayerizeGroup generated new layers in pending_layers_
      // [first_layer_in_subgroup .. pending_layers.size() - 1]. If it
      // generated 2 or more layer that we already know can't be merged
      // together, we should not decomposite and try to merge any of them into
      // the previous layers.
      if (first_layer_in_subgroup != pending_layers_.size() - 1)
        continue;
      if (!DecompositeEffect(current_group, first_layer_in_current_group,
                             *subgroup, first_layer_in_subgroup))
        continue;
    }
    // At this point pending_layers_.back() is the either a layer from a
    // "decomposited" subgroup or a layer created from a chunk we just
    // processed. Now determine whether it could be merged into a previous
    // layer.
    PendingLayer& new_layer = pending_layers_.back();
    DCHECK(!new_layer.ChunkRequiresOwnLayer());
    DCHECK_EQ(&current_group, &new_layer.GetPropertyTreeState().Effect());
    if (force_draws_content)
      new_layer.ForceDrawsContent();

    // If the new layer is the first using the nearest directly composited
    // ancestor, it can't be merged into any previous layers, so skip the merge
    // and overlap loop below.
    if (const auto* composited_transform =
            new_layer.GetPropertyTreeState()
                .Transform()
                .NearestDirectlyCompositedAncestor()) {
      if (directly_composited_transforms_.insert(composited_transform)
              .is_new_entry) {
        continue;
      }
    }

    // This iterates pending_layers_[first_layer_in_current_group:-1] in
    // reverse.
    auto is_composited_scroll = [this](const TransformPaintPropertyNode& t) {
      return compositor_.NeedsCompositedScrolling(t);
    };
    for (wtf_size_t candidate_index = pending_layers_.size() - 1;
         candidate_index-- > first_layer_in_current_group;) {
      PendingLayer& candidate_layer = pending_layers_[candidate_index];
      if (candidate_layer.Merge(new_layer, compositor_.lcd_text_preference_,
                                is_composited_scroll)) {
        pending_layers_.pop_back();
        break;
      }
      if (new_layer.MightOverlap(candidate_layer)) {
        new_layer.SetCompositingTypeToOverlap();
        break;
      }
    }
  }
}

PendingLayers PaintArtifactCompositor::Layerizer::Layerize() {
  LayerizeGroup(EffectPaintPropertyNode::Root(), /*force_draws_content=*/false);
  DCHECK(chunk_cursor_ == artifact_.GetPaintChunks().end());
  pending_layers_.ShrinkToReasonableCapacity();
  return std::move(pending_layers_);
}

void SynthesizedClip::UpdateLayer(const ClipPaintPropertyNode& clip,
                                  const TransformPaintPropertyNode& transform) {
  if (!layer_) {
    layer_ = cc::PictureLayer::Create(this);
    layer_->SetIsDrawable(true);
    // The clip
"""


```