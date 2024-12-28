Response:
My thinking process for summarizing the `VisualViewport` class functionality goes through these stages:

1. **Identify the Core Purpose:** The filename and the class name itself, `VisualViewport`, immediately suggest its primary responsibility: managing the visual presentation of the viewport in a web page. This is the entry point for understanding its functions.

2. **Scan for Key Members and Methods:** I'd quickly scan the provided code, looking for significant member variables and methods. These reveal the data the class holds and the actions it can perform. I'd note things like `scale_`, `offset_`, `size_`, `scroll_layer_`, `SetSize`, `SetScale`, `SetLocation`, `ScrollIntoView`, etc.

3. **Categorize Functionality:**  As I identify key members and methods, I'd start grouping them into functional categories. This helps organize the information and understand the class's responsibilities at a higher level. Initial categories might include:
    * Size and Position Management (setting size, location, offset)
    * Scaling (setting and getting scale)
    * Scrolling (managing scroll offset, smooth scrolling, `ScrollIntoView`)
    * Layer Management (creation and updating of layers, especially the scroll layer)
    * Paint Property Tree Integration (related to compositing)
    * Event Handling (enqueueing scroll and resize events)
    * Interaction with other Blink components (e.g., `Page`, `LocalFrame`, `ScrollingCoordinator`)

4. **Analyze Relationships with Web Technologies (JavaScript, HTML, CSS):**  Based on the categorized functionality, I'd consider how each category relates to web technologies:
    * **JavaScript:**  Methods like `OffsetLeft`, `OffsetTop`, `Width`, `Height`, and `ScaleForVisualViewport` directly correspond to properties exposed to JavaScript through the `DOMVisualViewport` API. Scrolling and zooming initiated by JavaScript would also interact with this class.
    * **HTML:**  The initial viewport size and zoom level can be influenced by the `<meta name="viewport">` tag in HTML. The visual viewport manages the interpretation and application of these settings.
    * **CSS:**  CSS properties affecting scrolling behavior (e.g., `overflow`, `scroll-behavior`) and visual presentation (e.g., scrollbar styling) interact with the `VisualViewport`. The code explicitly mentions CSS scrollbar width and colors.

5. **Consider Logic and Assumptions:** I'd look for conditional logic and assumptions made within the code. For example, the handling of `is_pinch_gesture_active_` or the different behavior depending on whether the viewport is "active."  I'd think about potential inputs and outputs in these scenarios (though the prompt didn't require detailed input/output mapping for *every* function in this section).

6. **Identify Potential User/Programming Errors:**  I'd think about common mistakes developers might make when dealing with viewport concepts. This might include:
    * Incorrectly calculating or setting viewport dimensions.
    * Issues with zoom level and how it affects layout.
    * Misunderstanding the difference between the visual and layout viewport.
    * Not accounting for browser controls or address bar.
    * Problems with `scrollIntoView` behavior.

7. **Synthesize and Summarize:** Finally, I'd synthesize the information gathered into a concise summary, highlighting the key responsibilities and relationships of the `VisualViewport` class. I'd focus on the "what" and "why" rather than getting bogged down in low-level implementation details. I would structure the summary logically, often following the categories identified earlier.

**Applying this to the provided code snippet:**

* **Core Purpose:**  Confirmed - managing the visual viewport.
* **Key Members/Methods:** I'd note the variables related to size, scale, offset, and layers. The `Set...` methods are crucial for understanding how these properties are manipulated. `UpdatePaintPropertyNodesIfNeeded` points to its role in the rendering pipeline.
* **Categorization:**  I'd see clear groupings around:
    * Size and Position (`SetSize`, `SetLocation`, `Move`)
    * Scaling (`SetScale`, `SetScaleAndLocation`)
    * Scrolling (`SetScrollOffset`, `ScrollIntoView`)
    * Paint Property Tree (`UpdatePaintPropertyNodesIfNeeded`, getter methods for nodes)
    * Layer Management (`CreateLayers`, `InitializeScrollbars`)
    * Event Handling (`EnqueueScrollEvent`, `EnqueueResizeEvent`)
* **Web Technologies:** The connections to JavaScript through the getter methods for viewport properties are evident. The mention of CSS scrollbar styles also stands out.
* **Logic/Assumptions:**  The checks for `IsActiveViewport()` are important, as is the clamping of scale and scroll offsets.
* **Potential Errors:** I'd consider mistakes in setting viewport dimensions or handling zoom.

By following these steps, I can arrive at the comprehensive and well-structured summary provided in the initial example. The process involves understanding the code's intent, dissecting its components, and then reassembling the information in a clear and organized way.
## blink/renderer/core/frame/visual_viewport.cc 功能归纳 (第 1部分)

该文件 `visual_viewport.cc` 是 Chromium Blink 引擎中负责管理**视觉视口 (Visual Viewport)** 的核心代码。视觉视口是用户在屏幕上实际看到的内容区域，它可能小于布局视口（文档的完整逻辑尺寸）。

**主要功能可以归纳为以下几点：**

1. **维护视觉视口的状态:**
    * **大小 (size_)**: 存储视觉视口的当前像素尺寸 (宽度和高度)。
    * **偏移 (offset_)**: 存储视觉视口相对于布局视口的滚动偏移量。
    * **缩放比例 (scale_)**: 存储当前的视觉视口缩放比例。
    * **Pinch 手势状态 (is_pinch_gesture_active_)**: 标记当前是否有 pinch-to-zoom 手势正在进行。
    * **浏览器控件调整 (browser_controls_adjustment_)**: 记录由于浏览器控件 (如地址栏) 显示/隐藏导致的视口调整量。

2. **管理视觉视口的变换和滚动:**
    * **`SetSize()`**:  设置视觉视口的大小，并触发必要的更新 (例如，重绘 overlay 滚动条，触发 resize 事件)。
    * **`SetLocation()`**: 设置视觉视口的滚动偏移量。
    * **`Move()`**:  按指定的偏移量移动视觉视口。
    * **`SetScale()`**: 设置视觉视口的缩放比例。
    * **`SetScaleAndLocation()`**: 同时设置视觉视口的缩放比例和滚动偏移量。
    * **`ClampScrollOffset()`**:  确保滚动偏移量在允许的范围内。
    * **`ScrollIntoView()`**: 将指定区域滚动到视觉视口内。
    * **平滑滚动 (Smooth Scrolling)**: 集成了平滑滚动功能，可以根据用户或程序的请求进行平滑滚动。

3. **与渲染流程集成 (通过 Paint Property Tree):**
    * **`UpdatePaintPropertyNodesIfNeeded()`**:  负责创建和更新与视觉视口相关的 Paint Property Nodes，这些节点用于在合成线程进行渲染。这包括：
        * **Device Emulation Transform Node**: 用于设备模拟的变换。
        * **Overscroll Elasticity Transform Node**: 处理弹性滚动效果的变换。
        * **Page Scale Node**: 应用页面缩放比例的变换。
        * **Scroll Translation Node**: 应用滚动偏移的变换。
        * **Scroll Node**: 表示可滚动区域的节点。
        * **Horizontal/Vertical Scrollbar Effect Node**:  用于控制滚动条效果的节点。
    * 这些节点构成渲染属性树的一部分，指导着图层的变换和渲染。

4. **处理事件:**
    * **`EnqueueScrollEvent()`**: 将视觉视口的滚动事件添加到队列中，以便 JavaScript 可以捕获和处理。
    * **`EnqueueResizeEvent()`**: 将视觉视口的 resize 事件添加到队列中。

5. **与 Blink 引擎的其他组件交互:**
    * **`Page`**: 持有 `Page` 对象的引用，以便访问页面的其他信息和功能。
    * **`LocalFrame`**:  与主框架 (`LocalMainFrame`) 交互，获取文档、视图等信息。
    * **`LocalFrameView`**: 通知 `LocalFrameView` 需要重绘，特别是在视觉视口或 overlay 滚动条发生变化时。
    * **`ScrollingCoordinator`**:  在启用合成的情况下，与 `ScrollingCoordinator` 协调视觉视口的滚动和缩放。
    * **`ChromeClient`**:  通知 Chrome 客户端页面缩放比例已更改。
    * **`Settings`**:  获取页面设置，例如是否启用加速合成、viewport 功能、隐藏滚动条等。

6. **提供 JavaScript 可访问的属性:**
    * **`OffsetLeft()`**, **`OffsetTop()`**, **`Width()`**, **`Height()`**, **`ScaleForVisualViewport()`**:  这些方法返回视觉视口的属性值，这些值会暴露给 JavaScript 的 `DOMVisualViewport` API。

7. **管理滚动条:**
    * **`InitializeScrollbars()`**: 初始化视觉视口的滚动条图层。
    * **`UpdateScrollbarLayer()`**:  更新指定方向滚动条图层的属性和状态。
    * **`ScrollbarThickness()`**: 获取滚动条的厚度。
    * **`VisualViewportSuppliesScrollbars()`**: 判断视觉视口是否负责提供滚动条。
    * **与 `ScrollbarThemeOverlayMobile` 交互**:  获取移动端滚动条的主题和样式信息。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**  当 JavaScript 代码访问 `window.visualViewport.offsetLeft` 时，会调用 `VisualViewport::OffsetLeft()` 方法来获取值。例如：
    ```javascript
    console.log(window.visualViewport.offsetLeft);
    ```
* **HTML:**  `<meta name="viewport" content="width=device-width, initial-scale=1.0">` 标签中的 `initial-scale` 属性会影响 `VisualViewport` 的初始 `scale_` 值。
* **CSS:**  CSS 属性 `overflow: scroll` 或 `overflow: auto` 可以触发视觉视口显示滚动条，这会影响 `VisualViewport::InitializeScrollbars()` 和 `VisualViewport::UpdateScrollbarLayer()` 的行为。CSS 自定义的滚动条样式 (通过 `-webkit-scrollbar-*` 属性) 会影响 `VisualViewport::CSSScrollbarWidth()` 和 `VisualViewport::UpdateScrollbarColor()` 等方法。

**逻辑推理的假设输入与输出示例:**

**假设输入:**
* `SetScaleAndLocation(2.0, true, gfx::PointF(100, 200))` 被调用。
* 当前的 `scale_` 为 1.0， `offset_` 为 (0, 0)。
* 页面缩放约束允许缩放到 2.0。

**输出:**
* `scale_` 更新为 2.0。
* `is_pinch_gesture_active_` 更新为 `true`。
* `offset_` 更新为 (100, 200)，但可能会被 `ClampScrollOffset()` 调整到有效范围内。
* 触发 `EnqueueResizeEvent()`，因为缩放比例发生了变化。
* 如果启用了合成，则会更新相关的 Paint Property Nodes。

**用户或编程常见的使用错误举例:**

* **错误地假设视觉视口的大小等于屏幕大小:**  用户可能会认为 `window.visualViewport.width` 和 `window.visualViewport.height` 始终返回设备的物理屏幕尺寸，但实际上，浏览器控件的显示/隐藏会影响视觉视口的大小。
* **在 JavaScript 中直接修改视觉视口的内部状态:**  开发者不应该尝试直接修改 `VisualViewport` 对象的内部成员变量 (这是 C++ 代码，JavaScript 无法直接访问)，而应该通过提供的 JavaScript API (`window.visualViewport` 的属性和方法) 来操作。
* **不理解视觉视口和布局视口的区别:**  混淆视觉视口和布局视口可能导致对滚动行为和坐标计算的误解。例如，在处理触摸事件时，需要明确是在哪个视口的坐标系下进行计算。

**功能归纳:**

总而言之，`blink/renderer/core/frame/visual_viewport.cc` 文件定义的 `VisualViewport` 类是 Blink 渲染引擎中至关重要的组件，它负责**管理用户在屏幕上实际看到的网页内容区域的大小、位置和缩放，并将其状态同步到渲染流程和 JavaScript 环境中**。它处理用户的交互 (如 pinch-to-zoom 和滚动)，并与浏览器的其他组件紧密协作，确保网页内容能够正确地呈现和交互。

Prompt: 
```
这是目录为blink/renderer/core/frame/visual_viewport.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/frame/visual_viewport.h"

#include <memory>

#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_functions.h"
#include "base/task/single_thread_task_runner.h"
#include "cc/input/main_thread_scrolling_reason.h"
#include "cc/layers/solid_color_scrollbar_layer.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints_set.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/root_scroller_controller.h"
#include "third_party/blink/renderer/core/page/scrolling/scrolling_coordinator.h"
#include "third_party/blink/renderer/core/page/scrolling/snap_coordinator.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/paint_property_tree_builder.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/scroll/scroll_alignment.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/scroll/scrollbar.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme_overlay_mobile.h"
#include "third_party/blink/renderer/core/scroll/smooth_scroll_sequencer.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/effect_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/foreign_layer_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/transform_paint_property_node.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/traced_value.h"
#include "third_party/skia/include/core/SkColor.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/geometry/size_f.h"

namespace blink {

namespace {

OverscrollType ComputeOverscrollType() {
  if (!Platform::Current()->IsElasticOverscrollEnabled())
    return OverscrollType::kNone;
  return OverscrollType::kTransform;
}

}  // anonymous namespace

VisualViewport::VisualViewport(Page& owner)
    : ScrollableArea(owner.GetAgentGroupScheduler().CompositorTaskRunner()),
      page_(&owner),
      scale_(1),
      is_pinch_gesture_active_(false),
      browser_controls_adjustment_(0),
      needs_paint_property_update_(true),
      overscroll_type_(ComputeOverscrollType()) {
  UniqueObjectId unique_id = NewUniqueObjectId();
  page_scale_element_id_ = CompositorElementIdFromUniqueObjectId(
      unique_id, CompositorElementIdNamespace::kPrimary);
  scroll_element_id_ = CompositorElementIdFromUniqueObjectId(
      unique_id, CompositorElementIdNamespace::kScroll);
  Reset();
}

const TransformPaintPropertyNode*
VisualViewport::GetDeviceEmulationTransformNode() const {
  return device_emulation_transform_node_.Get();
}

const TransformPaintPropertyNode*
VisualViewport::GetOverscrollElasticityTransformNode() const {
  return overscroll_elasticity_transform_node_.Get();
}

const TransformPaintPropertyNode* VisualViewport::GetPageScaleNode() const {
  return page_scale_node_.Get();
}

const TransformPaintPropertyNode* VisualViewport::GetScrollTranslationNode()
    const {
  return scroll_translation_node_.Get();
}

const ScrollPaintPropertyNode* VisualViewport::GetScrollNode() const {
  return scroll_node_.Get();
}

const TransformPaintPropertyNode*
VisualViewport::TransformNodeForViewportScrollbars() const {
  // Viewport scrollbars don't move with elastic overscroll or scale with
  // page scale.
  if (overscroll_elasticity_transform_node_)
    return overscroll_elasticity_transform_node_->UnaliasedParent();
  if (page_scale_node_)
    return page_scale_node_->UnaliasedParent();
  return nullptr;
}

PaintPropertyChangeType VisualViewport::UpdatePaintPropertyNodesIfNeeded(
    PaintPropertyTreeBuilderFragmentContext& context) {
  DCHECK(IsActiveViewport());
  PaintPropertyChangeType change = PaintPropertyChangeType::kUnchanged;

  if (!scroll_layer_)
    CreateLayers();

  if (!needs_paint_property_update_)
    return change;

  needs_paint_property_update_ = false;

  auto* transform_parent = context.current.transform;
  auto* scroll_parent = context.current.scroll;
  auto* clip_parent = context.current.clip;
  auto* effect_parent = context.current_effect;

  DCHECK(transform_parent);
  DCHECK(scroll_parent);
  DCHECK(clip_parent);
  DCHECK(effect_parent);

  {
    const auto& device_emulation_transform =
        GetChromeClient()->GetDeviceEmulationTransform();
    if (!device_emulation_transform.IsIdentity()) {
      TransformPaintPropertyNode::State state{{device_emulation_transform}};
      state.in_subtree_of_page_scale = false;
      if (!device_emulation_transform_node_) {
        device_emulation_transform_node_ = TransformPaintPropertyNode::Create(
            *transform_parent, std::move(state));
        change = PaintPropertyChangeType::kNodeAddedOrRemoved;
      } else {
        change = std::max(change, device_emulation_transform_node_->Update(
                                      *transform_parent, std::move(state)));
      }
      transform_parent = device_emulation_transform_node_.Get();
    } else if (device_emulation_transform_node_) {
      device_emulation_transform_node_ = nullptr;
      change = PaintPropertyChangeType::kNodeAddedOrRemoved;
    }
  }

  if (overscroll_type_ == OverscrollType::kTransform) {
    DCHECK(!transform_parent->Unalias().IsInSubtreeOfPageScale());

    TransformPaintPropertyNode::State state;
    state.in_subtree_of_page_scale = false;
    // TODO(crbug.com/877794) Should create overscroll elasticity transform node
    // based on settings.
    if (!overscroll_elasticity_transform_node_) {
      overscroll_elasticity_transform_node_ =
          TransformPaintPropertyNode::Create(*transform_parent,
                                             std::move(state));
      change = PaintPropertyChangeType::kNodeAddedOrRemoved;
    } else {
      change = std::max(change, overscroll_elasticity_transform_node_->Update(
                                    *transform_parent, std::move(state)));
    }
  } else {
    DCHECK(!overscroll_elasticity_transform_node_);
  }

  {
    auto* parent = overscroll_elasticity_transform_node_
                       ? overscroll_elasticity_transform_node_.Get()
                       : transform_parent;
    DCHECK(!parent->Unalias().IsInSubtreeOfPageScale());

    TransformPaintPropertyNode::State state;
    if (scale_ != 1.f)
      state.transform_and_origin.matrix = gfx::Transform::MakeScale(scale_);
    state.in_subtree_of_page_scale = false;
    state.direct_compositing_reasons = CompositingReason::kViewport;
    state.compositor_element_id = page_scale_element_id_;

    if (!page_scale_node_) {
      page_scale_node_ =
          TransformPaintPropertyNode::Create(*parent, std::move(state));
      change = PaintPropertyChangeType::kNodeAddedOrRemoved;
    } else {
      auto effective_change_type =
          page_scale_node_->Update(*parent, std::move(state));
      // As an optimization, attempt to directly update the compositor
      // scale translation node and return kChangedOnlyCompositedValues which
      // avoids an expensive PaintArtifactCompositor update.
      if (effective_change_type ==
          PaintPropertyChangeType::kChangedOnlySimpleValues) {
        if (auto* paint_artifact_compositor = GetPaintArtifactCompositor()) {
          bool updated =
              paint_artifact_compositor->DirectlyUpdatePageScaleTransform(
                  *page_scale_node_);
          if (updated) {
            effective_change_type =
                PaintPropertyChangeType::kChangedOnlyCompositedValues;
            page_scale_node_->CompositorSimpleValuesUpdated();
          }
        }
      }
      change = std::max(change, effective_change_type);
    }
  }

  {
    ScrollPaintPropertyNode::State state;
    state.container_rect = gfx::Rect(size_);
    state.contents_size = ContentsSize();

    state.user_scrollable_horizontal =
        UserInputScrollable(kHorizontalScrollbar);
    state.user_scrollable_vertical = UserInputScrollable(kVerticalScrollbar);
    state.max_scroll_offset_affected_by_page_scale = true;
    state.compositor_element_id = GetScrollElementId();

    if (IsActiveViewport()) {
      if (const Document* document = LocalMainFrame().GetDocument()) {
        bool uses_default_root_scroller =
            &document->GetRootScrollerController().EffectiveRootScroller() ==
            document;

        // All position: fixed elements will chain scrolling directly up to the
        // visual viewport's scroll node. In the case of a default root scroller
        // (i.e. the LayoutView), we actually want to scroll the "full
        // viewport". i.e. scrolling from the position: fixed element should
        // cause the page to scroll. This is not the case when we have a
        // different root scroller. We set
        // |prevent_viewport_scrolling_from_inner| so the compositor can know to
        // use the correct chaining behavior. This would be better fixed by
        // setting the correct scroll_tree_index in PAC::Update on the fixed
        // layer but that's a larger change. See https://crbug.com/977954 for
        // details.
        state.prevent_viewport_scrolling_from_inner =
            !uses_default_root_scroller;
      }
    }

    if (!scroll_node_) {
      scroll_node_ =
          ScrollPaintPropertyNode::Create(*scroll_parent, std::move(state));
      change = PaintPropertyChangeType::kNodeAddedOrRemoved;
    } else {
      change = std::max(change,
                        scroll_node_->Update(*scroll_parent, std::move(state)));
    }
  }

  {
    TransformPaintPropertyNode::State state{
        {gfx::Transform::MakeTranslation(-offset_)}};
    state.scroll = scroll_node_;
    state.direct_compositing_reasons = CompositingReason::kViewport;
    if (!scroll_translation_node_) {
      scroll_translation_node_ = TransformPaintPropertyNode::Create(
          *page_scale_node_, std::move(state));
      change = PaintPropertyChangeType::kNodeAddedOrRemoved;
    } else {
      auto effective_change_type =
          scroll_translation_node_->Update(*page_scale_node_, std::move(state));
      // As an optimization, attempt to directly update the compositor
      // translation node and return kChangedOnlyCompositedValues which avoids
      // an expensive PaintArtifactCompositor update.
      if (effective_change_type ==
          PaintPropertyChangeType::kChangedOnlySimpleValues) {
        if (auto* paint_artifact_compositor = GetPaintArtifactCompositor()) {
          bool updated =
              paint_artifact_compositor->DirectlyUpdateScrollOffsetTransform(
                  *scroll_translation_node_);
          if (updated) {
            effective_change_type =
                PaintPropertyChangeType::kChangedOnlyCompositedValues;
            scroll_translation_node_->CompositorSimpleValuesUpdated();
          }
        }
      }
    }
  }

  if (scrollbar_layer_horizontal_) {
    EffectPaintPropertyNode::State state;
    state.local_transform_space = transform_parent;
    state.direct_compositing_reasons =
        CompositingReason::kActiveOpacityAnimation;
    state.compositor_element_id =
        GetScrollbarElementId(ScrollbarOrientation::kHorizontalScrollbar);
    if (!horizontal_scrollbar_effect_node_) {
      horizontal_scrollbar_effect_node_ =
          EffectPaintPropertyNode::Create(*effect_parent, std::move(state));
      change = PaintPropertyChangeType::kNodeAddedOrRemoved;
    } else {
      change = std::max(change, horizontal_scrollbar_effect_node_->Update(
                                    *effect_parent, std::move(state)));
    }
  }

  if (scrollbar_layer_vertical_) {
    EffectPaintPropertyNode::State state;
    state.local_transform_space = transform_parent;
    state.direct_compositing_reasons =
        CompositingReason::kActiveOpacityAnimation;
    state.compositor_element_id =
        GetScrollbarElementId(ScrollbarOrientation::kVerticalScrollbar);
    if (!vertical_scrollbar_effect_node_) {
      vertical_scrollbar_effect_node_ =
          EffectPaintPropertyNode::Create(*effect_parent, std::move(state));
      change = PaintPropertyChangeType::kNodeAddedOrRemoved;
    } else {
      change = std::max(change, vertical_scrollbar_effect_node_->Update(
                                    *effect_parent, std::move(state)));
    }
  }

  parent_property_tree_state_ = TraceablePropertyTreeStateOrAlias(
      *transform_parent, *clip_parent, *effect_parent);

  if (change == PaintPropertyChangeType::kNodeAddedOrRemoved &&
      IsActiveViewport()) {
    DCHECK(LocalMainFrame().View());
    LocalMainFrame().View()->SetVisualViewportOrOverlayNeedsRepaint();
  }

  return change;
}

VisualViewport::~VisualViewport() = default;

void VisualViewport::Trace(Visitor* visitor) const {
  visitor->Trace(page_);
  visitor->Trace(parent_property_tree_state_);
  visitor->Trace(device_emulation_transform_node_);
  visitor->Trace(overscroll_elasticity_transform_node_);
  visitor->Trace(page_scale_node_);
  visitor->Trace(scroll_translation_node_);
  visitor->Trace(scroll_node_);
  visitor->Trace(horizontal_scrollbar_effect_node_);
  visitor->Trace(vertical_scrollbar_effect_node_);
  ScrollableArea::Trace(visitor);
}

void VisualViewport::EnqueueScrollEvent() {
  DCHECK(IsActiveViewport());
  if (Document* document = LocalMainFrame().GetDocument())
    document->EnqueueVisualViewportScrollEvent();
}

void VisualViewport::EnqueueResizeEvent() {
  DCHECK(IsActiveViewport());
  if (Document* document = LocalMainFrame().GetDocument())
    document->EnqueueVisualViewportResizeEvent();
}

void VisualViewport::SetSize(const gfx::Size& size) {
  if (size_ == size)
    return;

  TRACE_EVENT2("blink", "VisualViewport::setSize", "width", size.width(),
               "height", size.height());
  size_ = size;

  TRACE_EVENT_INSTANT1("loading", "viewport", TRACE_EVENT_SCOPE_THREAD, "data",
                       ViewportToTracedValue());

  if (!IsActiveViewport())
    return;

  needs_paint_property_update_ = true;

  // Need to re-compute sizes for the overlay scrollbars.
  if (scrollbar_layer_horizontal_ && LocalMainFrame().View()) {
    DCHECK(scrollbar_layer_vertical_);
    UpdateScrollbarLayer(kHorizontalScrollbar);
    UpdateScrollbarLayer(kVerticalScrollbar);
    LocalMainFrame().View()->SetVisualViewportOrOverlayNeedsRepaint();
  }

  EnqueueResizeEvent();
}

void VisualViewport::Reset() {
  SetScaleAndLocation(1, is_pinch_gesture_active_, gfx::PointF());
}

void VisualViewport::MainFrameDidChangeSize() {
  if (!IsActiveViewport())
    return;

  TRACE_EVENT0("blink", "VisualViewport::mainFrameDidChangeSize");

  // In unit tests we may not have initialized the layer tree.
  if (scroll_layer_)
    scroll_layer_->SetBounds(ContentsSize());

  needs_paint_property_update_ = true;
  ClampToBoundaries();
}

gfx::RectF VisualViewport::VisibleRect(
    IncludeScrollbarsInRect scrollbar_inclusion) const {
  if (!IsActiveViewport())
    return gfx::RectF(gfx::PointF(), gfx::SizeF(size_));

  gfx::SizeF visible_size(size_);

  if (scrollbar_inclusion == kExcludeScrollbars)
    visible_size = gfx::SizeF(ExcludeScrollbars(size_));

  visible_size.Enlarge(0, browser_controls_adjustment_);
  visible_size.Scale(1 / scale_);

  return gfx::RectF(ScrollPosition(), visible_size);
}

gfx::PointF VisualViewport::ViewportCSSPixelsToRootFrame(
    const gfx::PointF& point) const {
  // Note, this is in CSS Pixels so we don't apply scale.
  gfx::PointF point_in_root_frame = point;
  point_in_root_frame += GetScrollOffset();
  return point_in_root_frame;
}

void VisualViewport::SetLocation(const gfx::PointF& new_location) {
  SetScaleAndLocation(scale_, is_pinch_gesture_active_, new_location);
}

void VisualViewport::Move(const ScrollOffset& delta) {
  SetLocation(gfx::PointAtOffsetFromOrigin(offset_ + delta));
}

void VisualViewport::SetScale(float scale) {
  SetScaleAndLocation(scale, is_pinch_gesture_active_,
                      gfx::PointAtOffsetFromOrigin(offset_));
}

double VisualViewport::OffsetLeft() const {
  // Offset{Left|Top} and Width|Height are used by the DOMVisualViewport to
  // expose values to JS. We'll only ever ask the visual viewport for these
  // values for the outermost main frame. All other cases are based on layout
  // of subframes.
  DCHECK(IsActiveViewport());
  if (Document* document = LocalMainFrame().GetDocument())
    document->UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);
  return VisibleRect().x() / LocalMainFrame().LayoutZoomFactor();
}

double VisualViewport::OffsetTop() const {
  DCHECK(IsActiveViewport());
  if (Document* document = LocalMainFrame().GetDocument())
    document->UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);
  return VisibleRect().y() / LocalMainFrame().LayoutZoomFactor();
}

double VisualViewport::Width() const {
  DCHECK(IsActiveViewport());
  if (Document* document = LocalMainFrame().GetDocument())
    document->UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);
  return VisibleWidthCSSPx();
}

double VisualViewport::Height() const {
  DCHECK(IsActiveViewport());
  if (Document* document = LocalMainFrame().GetDocument())
    document->UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);
  return VisibleHeightCSSPx();
}

double VisualViewport::ScaleForVisualViewport() const {
  return Scale();
}

void VisualViewport::SetScaleAndLocation(float scale,
                                         bool is_pinch_gesture_active,
                                         const gfx::PointF& location) {
  if (DidSetScaleOrLocation(scale, is_pinch_gesture_active, location)) {
    // In remote or nested main frame cases, the visual viewport is inert so it
    // cannot be moved or scaled. This is enforced by setting page scale
    // constraints.
    DCHECK(IsActiveViewport());
    NotifyRootFrameViewport();
  }
}

double VisualViewport::VisibleWidthCSSPx() const {
  if (!IsActiveViewport())
    return VisibleRect().width();

  float zoom = LocalMainFrame().LayoutZoomFactor();
  float width_css_px = VisibleRect().width() / zoom;
  return width_css_px;
}

double VisualViewport::VisibleHeightCSSPx() const {
  if (!IsActiveViewport())
    return VisibleRect().height();

  float zoom = LocalMainFrame().LayoutZoomFactor();
  float height_css_px = VisibleRect().height() / zoom;
  return height_css_px;
}

bool VisualViewport::DidSetScaleOrLocation(float scale,
                                           bool is_pinch_gesture_active,
                                           const gfx::PointF& location) {
  if (!IsActiveViewport()) {
    is_pinch_gesture_active_ = is_pinch_gesture_active;
    // The VisualViewport in an embedded widget must always be 1.0 or else
    // event targeting will fail.
    DCHECK(scale == 1.f);
    scale_ = scale;
    offset_ = ScrollOffset();
    return false;
  }

  bool values_changed = false;

  bool notify_page_scale_factor_changed =
      is_pinch_gesture_active_ != is_pinch_gesture_active;
  is_pinch_gesture_active_ = is_pinch_gesture_active;
  if (std::isfinite(scale)) {
    float clamped_scale = GetPage()
                              .GetPageScaleConstraintsSet()
                              .FinalConstraints()
                              .ClampToConstraints(scale);
    if (clamped_scale != scale_) {
      scale_ = clamped_scale;
      values_changed = true;
      notify_page_scale_factor_changed = true;
      EnqueueResizeEvent();
    }
  }
  if (notify_page_scale_factor_changed)
    GetPage().GetChromeClient().PageScaleFactorChanged();

  ScrollOffset clamped_offset = ClampScrollOffset(location.OffsetFromOrigin());

  // TODO(bokan): If the offset is invalid, we might end up in an infinite
  // recursion as we reenter this function on clamping. It would be cleaner to
  // avoid reentrancy but for now just prevent the stack overflow.
  // crbug.com/702771.
  if (!std::isfinite(clamped_offset.x()) ||
      !std::isfinite(clamped_offset.y())) {
    return false;
  }

  if (clamped_offset != offset_) {
    DCHECK(LocalMainFrame().View());

    offset_ = clamped_offset;
    GetScrollAnimator().SetCurrentOffset(offset_);

    // SVG runs with accelerated compositing disabled so no
    // ScrollingCoordinator.
    if (auto* coordinator = GetPage().GetScrollingCoordinator()) {
      if (scroll_layer_)
        coordinator->UpdateCompositorScrollOffset(LocalMainFrame(), *this);
    }

    EnqueueScrollEvent();

    LocalMainFrame().View()->DidChangeScrollOffset();
    values_changed = true;
  }

  if (!values_changed)
    return false;

  probe::DidChangeViewport(&LocalMainFrame());
  LocalMainFrame().Loader().SaveScrollState();

  ClampToBoundaries();

  needs_paint_property_update_ = true;
  if (notify_page_scale_factor_changed) {
    TRACE_EVENT_INSTANT1("loading", "viewport", TRACE_EVENT_SCOPE_THREAD,
                         "data", ViewportToTracedValue());
  }
  return true;
}

void VisualViewport::CreateLayers() {
  DCHECK(IsActiveViewport());

  if (scroll_layer_)
    return;

  if (!GetPage().GetSettings().GetAcceleratedCompositingEnabled())
    return;

  DCHECK(!scrollbar_layer_horizontal_);
  DCHECK(!scrollbar_layer_vertical_);

  needs_paint_property_update_ = true;

  scroll_layer_ = cc::Layer::Create();
  scroll_layer_->SetBounds(ContentsSize());
  scroll_layer_->SetElementId(GetScrollElementId());

  InitializeScrollbars();

  if (IsActiveViewport()) {
    ScrollingCoordinator* coordinator = GetPage().GetScrollingCoordinator();
    DCHECK(coordinator);
    coordinator->UpdateCompositorScrollOffset(LocalMainFrame(), *this);
  }
}

void VisualViewport::InitializeScrollbars() {
  DCHECK(IsActiveViewport());
  // Do nothing if we haven't created the layer tree yet.
  if (!scroll_layer_)
    return;

  needs_paint_property_update_ = true;

  scrollbar_layer_horizontal_ = nullptr;
  scrollbar_layer_vertical_ = nullptr;
  if (VisualViewportSuppliesScrollbars() &&
      !GetPage().GetSettings().GetHideScrollbars()) {
    UpdateScrollbarLayer(kHorizontalScrollbar);
    UpdateScrollbarLayer(kVerticalScrollbar);
  }

  // Ensure existing LocalFrameView scrollbars are removed if the visual
  // viewport scrollbars are now supplied, or created if the visual viewport no
  // longer supplies scrollbars.
  if (IsActiveViewport()) {
    if (LocalFrameView* frame_view = LocalMainFrame().View())
      frame_view->SetVisualViewportOrOverlayNeedsRepaint();
  }
}

EScrollbarWidth VisualViewport::CSSScrollbarWidth() const {
  DCHECK(IsActiveViewport());
  if (Document* main_document = LocalMainFrame().GetDocument())
    return main_document->GetLayoutView()->StyleRef().UsedScrollbarWidth();

  return EScrollbarWidth::kAuto;
}

std::optional<blink::Color> VisualViewport::CSSScrollbarThumbColor() const {
  DCHECK(IsActiveViewport());
  if (Document* main_document = LocalMainFrame().GetDocument()) {
    return main_document->GetLayoutView()
        ->StyleRef()
        .ScrollbarThumbColorResolved();
  }

  return std::nullopt;
}

void VisualViewport::DropCompositorScrollDeltaNextCommit() {
  if (auto* paint_artifact_compositor = GetPaintArtifactCompositor()) {
    paint_artifact_compositor->DropCompositorScrollDeltaNextCommit(
        scroll_element_id_);
  }
}

int VisualViewport::ScrollbarThickness() const {
  DCHECK(IsActiveViewport());
  return ScrollbarThemeOverlayMobile::GetInstance().ScrollbarThickness(
      ScaleFromDIP(), CSSScrollbarWidth());
}

void VisualViewport::UpdateScrollbarLayer(ScrollbarOrientation orientation) {
  DCHECK(IsActiveViewport());
  bool is_horizontal = orientation == kHorizontalScrollbar;
  scoped_refptr<cc::SolidColorScrollbarLayer>& scrollbar_layer =
      is_horizontal ? scrollbar_layer_horizontal_ : scrollbar_layer_vertical_;
  if (!scrollbar_layer) {
    auto& theme = ScrollbarThemeOverlayMobile::GetInstance();
    float scale = ScaleFromDIP();
    int thumb_thickness = theme.ThumbThickness(scale, CSSScrollbarWidth());
    int scrollbar_margin = theme.ScrollbarMargin(scale, CSSScrollbarWidth());
    cc::ScrollbarOrientation cc_orientation =
        orientation == kHorizontalScrollbar
            ? cc::ScrollbarOrientation::kHorizontal
            : cc::ScrollbarOrientation::kVertical;
    scrollbar_layer = cc::SolidColorScrollbarLayer::Create(
        cc_orientation, thumb_thickness, scrollbar_margin,
        /*is_left_side_vertical_scrollbar*/ false);
    scrollbar_layer->SetElementId(GetScrollbarElementId(orientation));
    scrollbar_layer->SetScrollElementId(scroll_layer_->element_id());
    scrollbar_layer->SetIsDrawable(true);
  }

  scrollbar_layer->SetBounds(
      orientation == kHorizontalScrollbar
          ? gfx::Size(size_.width() - ScrollbarThickness(),
                      ScrollbarThickness())
          : gfx::Size(ScrollbarThickness(),
                      size_.height() - ScrollbarThickness()));

  UpdateScrollbarColor(*scrollbar_layer);
}

bool VisualViewport::VisualViewportSuppliesScrollbars() const {
  return IsActiveViewport() && GetPage().GetSettings().GetViewportEnabled();
}

const Document* VisualViewport::GetDocument() const {
  return IsActiveViewport() ? LocalMainFrame().GetDocument() : nullptr;
}

CompositorElementId VisualViewport::GetScrollElementId() const {
  return scroll_element_id_;
}

bool VisualViewport::ScrollAnimatorEnabled() const {
  return GetPage().GetSettings().GetScrollAnimatorEnabled();
}

ChromeClient* VisualViewport::GetChromeClient() const {
  return &GetPage().GetChromeClient();
}

SmoothScrollSequencer* VisualViewport::GetSmoothScrollSequencer() const {
  if (!IsActiveViewport())
    return nullptr;
  return LocalMainFrame().GetSmoothScrollSequencer();
}

bool VisualViewport::SetScrollOffset(
    const ScrollOffset& offset,
    mojom::blink::ScrollType scroll_type,
    mojom::blink::ScrollBehavior scroll_behavior,
    ScrollCallback on_finish) {
  // We clamp the offset here, because the ScrollAnimator may otherwise be
  // set to a non-clamped offset by ScrollableArea::setScrollOffset,
  // which may lead to incorrect scrolling behavior in RootFrameViewport down
  // the line.
  // TODO(eseckler): Solve this instead by ensuring that ScrollableArea and
  // ScrollAnimator are kept in sync. This requires that ScrollableArea always
  // stores fractional offsets and that truncation happens elsewhere, see
  // crbug.com/626315.
  ScrollOffset new_scroll_offset = ClampScrollOffset(offset);
  return ScrollableArea::SetScrollOffset(new_scroll_offset, scroll_type,
                                         scroll_behavior, std::move(on_finish));
}

bool VisualViewport::SetScrollOffset(
    const ScrollOffset& offset,
    mojom::blink::ScrollType scroll_type,
    mojom::blink::ScrollBehavior scroll_behavior) {
  return SetScrollOffset(offset, scroll_type, scroll_behavior,
                         ScrollCallback());
}

PhysicalOffset VisualViewport::LocalToScrollOriginOffset() const {
  return {};
}

PhysicalRect VisualViewport::ScrollIntoView(
    const PhysicalRect& rect_in_absolute,
    const PhysicalBoxStrut& scroll_margin,
    const mojom::blink::ScrollIntoViewParamsPtr& params) {
  if (!IsActiveViewport())
    return rect_in_absolute;

  ScrollOffset new_scroll_offset =
      ClampScrollOffset(scroll_into_view_util::GetScrollOffsetToExpose(
          *this, rect_in_absolute, scroll_margin, *params->align_x.get(),
          *params->align_y.get()));

  if (new_scroll_offset != GetScrollOffset()) {
    if (params->is_for_scroll_sequence) {
      if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled()) {
        SetScrollOffset(new_scroll_offset, params->type, params->behavior);
      } else {
        DCHECK(params->type == mojom::blink::ScrollType::kProgrammatic ||
               params->type == mojom::blink::ScrollType::kUser);
        CHECK(GetSmoothScrollSequencer());
        GetSmoothScrollSequencer()->QueueAnimation(this, new_scroll_offset,
                                                   params->behavior);
      }
    } else {
      SetScrollOffset(new_scroll_offset, params->type, params->behavior,
                      ScrollCallback());
    }
  }

  return rect_in_absolute;
}

int VisualViewport::ScrollSize(ScrollbarOrientation orientation) const {
  gfx::Vector2d scroll_dimensions =
      MaximumScrollOffsetInt() - MinimumScrollOffsetInt();
  return (orientation == kHorizontalScrollbar) ? scroll_dimensions.x()
                                               : scroll_dimensions.y();
}

gfx::Vector2d VisualViewport::MinimumScrollOffsetInt() const {
  return gfx::Vector2d();
}

gfx::Vector2d VisualViewport::MaximumScrollOffsetInt() const {
  return gfx::ToFlooredVector2d(MaximumScrollOffset());
}

ScrollOffset VisualViewport::MaximumScrollOffset() const {
  return MaximumScrollOffsetAtScale(scale_);
}

ScrollOffset VisualViewport::MaximumScrollOffsetAtScale(float scale) const {
  if (!IsActiveViewport())
    return ScrollOffset();

  // TODO(bokan): We probably shouldn't be storing the bounds in a float.
  // crbug.com/470718.
  gfx::SizeF frame_view_size(ContentsSize());

  if (browser_controls_adjustment_) {
    float min_scale =
        GetPage().GetPageScaleConstraintsSet().FinalConstraints().minimum_scale;
    frame_view_size.Enlarge(0, browser_controls_adjustment_ / min_scale);
  }

  frame_view_size.Scale(scale);
  frame_view_size = gfx::SizeF(ToFlooredSize(frame_view_size));

  gfx::SizeF viewport_size(size_);
  viewport_size.Enlarge(0, ceilf(browser_controls_adjustment_));

  gfx::SizeF max_position = frame_view_size - viewport_size;
  max_position.Scale(1 / scale);
  return ScrollOffset(max_position.width(), max_position.height());
}

gfx::Point VisualViewport::Clam
"""


```