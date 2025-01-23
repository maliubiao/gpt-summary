Response:
My thinking process to analyze the given C++ code and fulfill the prompt's requirements goes like this:

1. **Understand the Core Task:** The primary goal is to understand the functionality of `PropertyTreeManager` in the Blink rendering engine and its interactions with other parts of the system, particularly concerning JavaScript, HTML, and CSS. The prompt also asks for logical inference examples, common usage errors, and a high-level summary.

2. **Identify Key Data Structures and Classes:**  I scanned the includes and the class definition to pinpoint the crucial components:
    * `PropertyTreeManager`: The central class.
    * `cc::PropertyTrees`:  A core Chromium Compositor class managing property trees (transform, clip, effect, scroll).
    * `cc::Layer`:  Represents a composited layer.
    * `cc::TransformNode`, `cc::ClipNode`, `cc::EffectNode`, `cc::ScrollNode`: Nodes within the respective property trees in the compositor.
    * `TransformPaintPropertyNode`, `ClipPaintPropertyNode`, `EffectPaintPropertyNode`, `ScrollPaintPropertyNode`: Blink's representation of property nodes, mirroring the compositor's but at the paint/style level.
    * `LayerListBuilder`:  Responsible for building the list of composited layers.

3. **Trace Initialization and Setup:** The constructor `PropertyTreeManager(...)` clearly initializes the connection to `cc::PropertyTrees` and sets up the root nodes of each property tree (`SetupRootTransformNode`, `SetupRootClipNode`, etc.). This immediately tells me that this class is responsible for *creating and managing* these property trees based on Blink's internal representation.

4. **Analyze Core Functionality - Property Tree Management:**  I focused on the methods that manipulate the property trees:
    * `EnsureCompositorTransformNode`, `EnsureCompositorClipNode`, `EnsureCompositorScrollNode`, `EnsureCompositorEffectNode` (though not fully shown in the extract). These functions are crucial. The "Ensure" prefix suggests they either find an existing compositor node or create a new one if it doesn't exist. They link Blink's paint property nodes to the compositor's nodes.
    * `UpdateCcTransformLocalMatrix`:  This method clearly updates the transformation matrix in the compositor's `TransformNode` based on Blink's `TransformPaintPropertyNode`.
    * `SetTransformTreePageScaleFactor`:  Handles page scaling at the compositor level.
    * Direct update methods (`DirectlyUpdateCompositedOpacityValue`, `DirectlyUpdateScrollOffsetTransform`, `DirectlyUpdateTransform`, `DirectlyUpdatePageScaleTransform`, `DirectlySetScrollOffset`): These methods allow for direct manipulation of compositor properties, often for performance optimizations or specific scenarios where main-thread involvement needs to be bypassed.

5. **Connect to CSS, HTML, and JavaScript:**  This required reasoning about *why* these property trees exist. CSS styles applied to HTML elements lead to the creation of Blink's paint property nodes. JavaScript can dynamically modify these styles or even directly manipulate properties that influence compositing. Therefore:
    * **CSS:** Changes to CSS properties like `transform`, `opacity`, `clip-path`, `overflow: scroll`, etc., will eventually be reflected in the Blink paint property nodes and then translated by `PropertyTreeManager` into the compositor's property trees.
    * **HTML:** The structure of the HTML document influences the hierarchy of these property trees. For example, nested elements will have nested transform and clip contexts.
    * **JavaScript:** JavaScript animations that change transforms or opacities, or scrolling actions initiated by JavaScript, will trigger updates handled by `PropertyTreeManager`.

6. **Infer Logical Relationships (Input/Output):** I considered scenarios where Blink's paint property nodes are inputs, and the corresponding compositor property tree nodes are the outputs. The "Ensure" methods are excellent examples. For instance, if `EnsureCompositorTransformNode` is called with a `TransformPaintPropertyNode` representing a 2D translation, it will create a `cc::TransformNode` with the corresponding `local` matrix updated.

7. **Identify Potential Usage Errors:** I thought about how developers might misuse features related to compositing. Incorrectly applying CSS transforms that lead to unintended stacking contexts or performance issues are relevant. Manipulating scroll offsets directly through JavaScript when the element is compositor-scrolled can lead to inconsistencies.

8. **Summarize Functionality:** I synthesized the information gathered into a concise description, focusing on the core responsibility of `PropertyTreeManager`: bridging the gap between Blink's paint representation and the compositor's representation of visual properties.

9. **Structure the Answer:** I organized the information into logical sections based on the prompt's requests: core functionality, relationship to web technologies, logical inference, usage errors, and a summary.

10. **Refine and Elaborate:** I reviewed my initial thoughts and added more detail and specific examples to make the explanation clearer and more comprehensive. For example, I elaborated on the direct update methods and the role of `LayerListBuilder`. I also paid attention to the specific terms used in the code (like "synthetic clip" and "pixel-moving filter").

By following this methodical process, I could dissect the provided code snippet and generate a comprehensive answer that addresses all aspects of the prompt.
## 功能归纳： PropertyTreeManager (第1部分)

`PropertyTreeManager` 是 Chromium Blink 渲染引擎中负责**管理和同步渲染属性树**的关键组件。它的主要功能是：

**核心职责：**

1. **构建和维护 Compositor 的属性树 (Property Trees):**  将 Blink 内部的渲染属性（例如变换、裁剪、效果和滚动）转换为 Chromium Compositor (cc) 理解的 `cc::PropertyTrees` 结构。这包括 `cc::TransformTree`, `cc::ClipTree`, `cc::EffectTree`, 和 `cc::ScrollTree`。
2. **同步 Blink 和 Compositor 的属性节点:**  在 Blink 的 `PaintPropertyNode` (例如 `TransformPaintPropertyNode`) 和 Compositor 的 `cc::*Node` 之间建立关联，并保持同步。这意味着当 Blink 的渲染属性发生变化时，`PropertyTreeManager` 会更新对应的 Compositor 属性节点。
3. **处理合成 (Compositing) 相关逻辑:**  决定哪些元素需要合成到独立的 Layer 上，并创建相应的 Compositor Layer 和属性节点。它处理例如固定定位、滚动、变换、透明度等影响合成的关键属性。
4. **优化 Compositor 性能:** 通过直接更新 Compositor 的属性值（在某些特定条件下），避免不必要的重新合成。

**具体功能点：**

* **初始化根节点:** 在创建 `PropertyTreeManager` 时，初始化 Compositor 的根变换、裁剪、效果和滚动节点。
* **创建和关联属性节点:** 提供方法 (`EnsureCompositorTransformNode`, `EnsureCompositorClipNode`, `EnsureCompositorScrollNode`) 来创建或查找 Compositor 中与 Blink 的 `PaintPropertyNode` 对应的节点，并建立双向关联。
* **更新 Compositor 节点属性:** 提供方法将 Blink 的 `PaintPropertyNode` 的属性值同步到对应的 Compositor 节点，例如更新变换矩阵、裁剪区域、滚动偏移等。
* **处理滚动:**  识别滚动容器，创建 Compositor 的滚动节点，并处理主线程和合成线程的滚动逻辑。
* **处理固定定位:**  创建必要的变换节点来支持固定定位元素的行为。
* **处理裁剪和遮罩:** 创建 Compositor 的裁剪节点，并处理由 `clip-path` 等 CSS 属性产生的遮罩效果。
* **处理视觉效果:** 创建 Compositor 的效果节点，处理例如 `opacity`, `filter`, `blend-mode` 等 CSS 属性。
* **直接更新 Compositor 属性:** 提供方法在特定条件下直接修改 Compositor 的属性值，例如直接更新透明度、滚动偏移和变换，以提高性能。
* **管理合成遮罩层 (Clip Mask Layer):** 当存在需要合成的裁剪效果时，创建并管理用于实现遮罩的合成层。
* **处理合成隔离 (Synthetic Clip):**  为了某些特定的裁剪效果，会创建临时的合成效果节点和裁剪节点。

**与 JavaScript, HTML, CSS 的关系：**

`PropertyTreeManager` 是连接前端技术（HTML, CSS, JavaScript）和底层渲染引擎的关键桥梁。

* **HTML:** HTML 的元素结构决定了属性树的层级关系。例如，嵌套的 `div` 元素会形成嵌套的变换和裁剪上下文。`PropertyTreeManager` 会根据 HTML 的 DOM 树结构来构建相应的 Compositor 属性树。
    * **举例:**  一个包含多个嵌套 `div` 的 HTML 结构，每个 `div` 都可能对应 Compositor 属性树中的一系列节点。
* **CSS:** CSS 样式是渲染属性的来源。CSS 属性如 `transform`, `opacity`, `clip-path`, `overflow`, `position: fixed` 等会直接影响 Blink 的 `PaintPropertyNode` 的值，而 `PropertyTreeManager` 会将这些变化同步到 Compositor 的属性树中。
    * **举例:**
        * CSS 设置 `div { transform: translate(10px, 20px); }` 会导致 `PropertyTreeManager` 更新对应 Compositor 变换节点的本地矩阵。
        * CSS 设置 `div { opacity: 0.5; }` 会导致 `PropertyTreeManager` 更新对应 Compositor 效果节点的透明度。
        * CSS 设置 `div { overflow: auto; }` 会触发 `PropertyTreeManager` 创建 Compositor 的滚动节点。
* **JavaScript:** JavaScript 可以动态修改 HTML 结构和 CSS 样式，这些修改最终也会反映到 `PropertyTreeManager` 所管理的属性树中。例如，通过 JavaScript 改变元素的 `transform` 或 `scrollTop` 属性，会触发 `PropertyTreeManager` 更新 Compositor 的属性节点。
    * **举例:**
        * JavaScript 代码 `element.style.transform = 'rotate(45deg)';` 会导致 `PropertyTreeManager` 更新对应 Compositor 变换节点的本地矩阵。
        * JavaScript 代码 `element.scrollTop = 100;` 会导致 `PropertyTreeManager` 更新对应 Compositor 滚动节点的滚动偏移。

**逻辑推理 (假设输入与输出):**

假设有以下简单的 HTML 和 CSS：

```html
<div id="container" style="transform: scale(0.8);">
  <div id="child" style="opacity: 0.6;">Content</div>
</div>
```

**假设输入 (Blink 的 PaintPropertyNode):**

* **Container TransformPaintPropertyNode:**
    * `Matrix()` 返回一个缩放 0.8 的矩阵。
* **Child EffectPaintPropertyNode:**
    * `Opacity()` 返回 0.6。
    * `Parent()` 指向 Container 的 `TransformPaintPropertyNode` 所对应的效果节点。

**逻辑推理:**

`PropertyTreeManager` 的 `EnsureCompositorTransformNode` 方法会被调用处理 Container 的变换。

**假设输出 (Compositor 的 cc::TransformNode):**

* 创建一个新的 `cc::TransformNode`。
* `local` 属性会被设置为缩放 0.8 的矩阵。
* 该节点的 ID 会被记录在 Container 的 `TransformPaintPropertyNode` 中。

接着，`PropertyTreeManager` 在处理 Child 的效果时，会调用 `EnsureCompositorEffectNode` (在提供的代码片段中未完全显示，但存在类似逻辑)。

**假设输出 (Compositor 的 cc::EffectNode):**

* 创建一个新的 `cc::EffectNode`。
* `opacity` 属性会被设置为 0.6。
* `transform_id` 属性会设置为 Container 对应的 `cc::TransformNode` 的 ID，建立父子关系。
* 该节点的 ID 会被记录在 Child 的 `EffectPaintPropertyNode` 中。

**用户或编程常见的使用错误：**

1. **过度使用 `will-change`:**  开发者可能会滥用 CSS 的 `will-change` 属性来尝试强制元素合成，但这可能会导致不必要的内存消耗和性能下降。`PropertyTreeManager` 可能会为这些元素创建不必要的合成层。
2. **在合成元素上进行非合成的动画:**  如果开发者使用 JavaScript 或 CSS 动画来修改一个已经合成的元素，但修改的属性并没有触发 Compositor 动画，那么动画可能会在主线程上执行，导致性能问题。`PropertyTreeManager` 已经将该元素移交给 Compositor 管理，主线程的修改可能不会高效地同步。
3. **不理解合成的边界:**  开发者可能不清楚哪些 CSS 属性会触发合成，导致意外的合成行为或合成失败。例如，误以为修改一个元素的背景颜色会触发合成，但实际上通常不会。
4. **直接操作 Compositor 属性的时机不当:** 虽然 `PropertyTreeManager` 提供了直接更新 Compositor 属性的方法，但如果使用不当，可能会导致状态不一致。例如，在 Compositor 正在进行动画时直接修改属性，可能会导致动画被打断或出现错误。

**总结：**

`PropertyTreeManager` 的核心功能是作为 Blink 渲染引擎和 Chromium Compositor 之间的桥梁，负责将 Blink 内部的渲染属性转换为 Compositor 可以理解和使用的格式，并管理合成相关的逻辑。它通过维护和同步属性树，确保渲染效果的正确性和性能。它与 JavaScript, HTML, CSS 紧密相关，因为这些技术定义了页面的结构、样式和交互行为，最终都会通过 `PropertyTreeManager` 反映到渲染流水线中。

### 提示词
```
这是目录为blink/renderer/platform/graphics/compositing/property_tree_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/compositing/property_tree_manager.h"

#include "base/numerics/safe_conversions.h"
#include "build/build_config.h"
#include "cc/base/features.h"
#include "cc/input/overscroll_behavior.h"
#include "cc/layers/layer.h"
#include "cc/trees/clip_node.h"
#include "cc/trees/effect_node.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/property_tree.h"
#include "cc/trees/scroll_node.h"
#include "cc/trees/transform_node.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/graphics/paint/clip_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/effect_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/geometry_mapper.h"
#include "third_party/blink/renderer/platform/graphics/paint/scroll_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/paint/transform_paint_property_node.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

PropertyTreeManager::EffectState::EffectState(const CurrentEffectState& other)
    : effect_id(other.effect_id),
      effect(other.effect),
      clip(other.clip),
      transform(other.transform),
      may_be_2d_axis_misaligned_to_render_surface(
          other.may_be_2d_axis_misaligned_to_render_surface),
      contained_by_non_render_surface_synthetic_rounded_clip(
          other.contained_by_non_render_surface_synthetic_rounded_clip) {}

PropertyTreeManager::CurrentEffectState::CurrentEffectState(
    const EffectState& other)
    : effect_id(other.effect_id),
      effect(other.effect),
      clip(other.clip),
      transform(other.transform),
      may_be_2d_axis_misaligned_to_render_surface(
          other.may_be_2d_axis_misaligned_to_render_surface),
      contained_by_non_render_surface_synthetic_rounded_clip(
          other.contained_by_non_render_surface_synthetic_rounded_clip) {}

PropertyTreeManager::PropertyTreeManager(PropertyTreeManagerClient& client,
                                         cc::PropertyTrees& property_trees,
                                         cc::Layer& root_layer,
                                         LayerListBuilder& layer_list_builder,
                                         int new_sequence_number)
    : client_(client),
      clip_tree_(property_trees.clip_tree_mutable()),
      effect_tree_(property_trees.effect_tree_mutable()),
      scroll_tree_(property_trees.scroll_tree_mutable()),
      transform_tree_(property_trees.transform_tree_mutable()),
      root_layer_(root_layer),
      layer_list_builder_(layer_list_builder),
      new_sequence_number_(new_sequence_number) {
  SetupRootTransformNode();
  SetupRootClipNode();
  SetupRootEffectNode();
  SetupRootScrollNode();
}

PropertyTreeManager::~PropertyTreeManager() {
  DCHECK(!effect_stack_.size()) << "PropertyTreeManager::Finalize() must be "
                                   "called at the end of tree conversion.";
}

void PropertyTreeManager::Finalize() {
  while (effect_stack_.size())
    CloseCcEffect();

  DCHECK(effect_stack_.empty());

  UpdatePixelMovingFilterClipExpanders();
}

static void UpdateCcTransformLocalMatrix(
    cc::TransformNode& compositor_node,
    const TransformPaintPropertyNode& transform_node) {
  if (transform_node.GetStickyConstraint() ||
      transform_node.GetAnchorPositionScrollData()) {
    // The sticky offset on the blink transform node is pre-computed and stored
    // to the local matrix. Cc applies sticky offset dynamically on top of the
    // local matrix. We should not set the local matrix on cc node if it is a
    // sticky node because the sticky offset would be applied twice otherwise.
    // Same for anchor positioning.
    DCHECK(compositor_node.local.IsIdentity());
    DCHECK_EQ(gfx::Point3F(), compositor_node.origin);
  } else if (transform_node.ScrollNode()) {
    DCHECK(transform_node.IsIdentityOr2dTranslation());
    // Blink creates a 2d transform node just for scroll offset whereas cc's
    // transform node has a special scroll offset field.
    compositor_node.scroll_offset =
        gfx::PointAtOffsetFromOrigin(-transform_node.Get2dTranslation());
    DCHECK(compositor_node.local.IsIdentity());
    DCHECK_EQ(gfx::Point3F(), compositor_node.origin);
  } else {
    DCHECK(!transform_node.ScrollNode());
    compositor_node.local = transform_node.Matrix();
    compositor_node.origin = transform_node.Origin();
  }
  compositor_node.needs_local_transform_update = true;
}

static void SetTransformTreePageScaleFactor(
    cc::TransformTree& transform_tree,
    const cc::TransformNode& page_scale_node) {
  DCHECK(page_scale_node.local.IsScale2d());
  auto page_scale = page_scale_node.local.To2dScale();
  DCHECK_EQ(page_scale.x(), page_scale.y());
  transform_tree.set_page_scale_factor(page_scale.x());
}

bool PropertyTreeManager::DirectlyUpdateCompositedOpacityValue(
    cc::LayerTreeHost& host,
    const EffectPaintPropertyNode& effect) {
  host.WaitForProtectedSequenceCompletion();
  auto* property_trees = host.property_trees();
  auto* cc_effect = property_trees->effect_tree_mutable().Node(
      effect.CcNodeId(property_trees->sequence_number()));
  if (!cc_effect)
    return false;

  // We directly update opacity only when it's not animating in compositor. If
  // the compositor has not cleared is_currently_animating_opacity, we should
  // clear it now to let the compositor respect the new value.
  cc_effect->is_currently_animating_opacity = false;

  cc_effect->opacity = effect.Opacity();
  cc_effect->effect_changed = true;
  property_trees->effect_tree_mutable().set_needs_update(true);
  host.SetNeedsCommit();
  return true;
}

bool PropertyTreeManager::DirectlyUpdateScrollOffsetTransform(
    cc::LayerTreeHost& host,
    const TransformPaintPropertyNode& transform) {
  host.WaitForProtectedSequenceCompletion();
  auto* scroll_node = transform.ScrollNode();
  // Only handle scroll adjustments.
  if (!scroll_node)
    return false;

  auto* property_trees = host.property_trees();
  auto& scroll_tree = property_trees->scroll_tree_mutable();
  auto* cc_scroll_node = scroll_tree.Node(
      scroll_node->CcNodeId(property_trees->sequence_number()));
  if (!cc_scroll_node ||
      scroll_tree.ShouldRealizeScrollsOnMain(*cc_scroll_node)) {
    return false;
  }

  auto* cc_transform = property_trees->transform_tree_mutable().Node(
      transform.CcNodeId(property_trees->sequence_number()));
  if (!cc_transform)
    return false;

  DCHECK(!cc_transform->is_currently_animating);

  gfx::PointF scroll_offset =
      gfx::PointAtOffsetFromOrigin(-transform.Get2dTranslation());
  DirectlySetScrollOffset(host, scroll_node->GetCompositorElementId(),
                          scroll_offset);
  if (cc_transform->scroll_offset != scroll_offset) {
    UpdateCcTransformLocalMatrix(*cc_transform, transform);
    cc_transform->transform_changed = true;
    property_trees->transform_tree_mutable().set_needs_update(true);
    host.SetNeedsCommit();
  }
  return true;
}

bool PropertyTreeManager::DirectlyUpdateTransform(
    cc::LayerTreeHost& host,
    const TransformPaintPropertyNode& transform) {
  host.WaitForProtectedSequenceCompletion();
  // If we have a ScrollNode, we should be using
  // DirectlyUpdateScrollOffsetTransform().
  DCHECK(!transform.ScrollNode());

  auto* property_trees = host.property_trees();
  auto* cc_transform = property_trees->transform_tree_mutable().Node(
      transform.CcNodeId(property_trees->sequence_number()));
  if (!cc_transform)
    return false;

  UpdateCcTransformLocalMatrix(*cc_transform, transform);

  // We directly update transform only when the transform is not animating in
  // compositor. If the compositor has not cleared the is_currently_animating
  // flag, we should clear it to let the compositor respect the new value.
  cc_transform->is_currently_animating = false;

  cc_transform->transform_changed = true;
  property_trees->transform_tree_mutable().set_needs_update(true);
  host.SetNeedsCommit();
  return true;
}

bool PropertyTreeManager::DirectlyUpdatePageScaleTransform(
    cc::LayerTreeHost& host,
    const TransformPaintPropertyNode& transform) {
  host.WaitForProtectedSequenceCompletion();
  DCHECK(!transform.ScrollNode());

  auto* property_trees = host.property_trees();
  auto* cc_transform = property_trees->transform_tree_mutable().Node(
      transform.CcNodeId(property_trees->sequence_number()));
  if (!cc_transform)
    return false;

  UpdateCcTransformLocalMatrix(*cc_transform, transform);
  SetTransformTreePageScaleFactor(property_trees->transform_tree_mutable(),
                                  *cc_transform);
  cc_transform->transform_changed = true;
  property_trees->transform_tree_mutable().set_needs_update(true);
  return true;
}

void PropertyTreeManager::DirectlySetScrollOffset(
    cc::LayerTreeHost& host,
    CompositorElementId element_id,
    const gfx::PointF& scroll_offset) {
  host.WaitForProtectedSequenceCompletion();
  auto* property_trees = host.property_trees();
  if (property_trees->scroll_tree_mutable().SetScrollOffset(element_id,
                                                            scroll_offset)) {
    // Scroll offset animations are clobbered via |Layer::PushPropertiesTo|.
    if (auto* layer = host.LayerByElementId(element_id))
      layer->SetNeedsPushProperties();
    host.SetNeedsCommit();
  }
}

void PropertyTreeManager::DropCompositorScrollDeltaNextCommit(
    cc::LayerTreeHost& host,
    CompositorElementId element_id) {
  host.DropActiveScrollDeltaNextCommit(element_id);
}

uint32_t PropertyTreeManager::NonCompositedMainThreadRepaintReasons(
    const TransformPaintPropertyNode& scroll_translation) const {
  if (scroll_translation.ScrollNode()->GetCompositedScrollingPreference() ==
      CompositedScrollingPreference::kNotPreferred) {
    return cc::MainThreadScrollingReason::kPreferNonCompositedScrolling;
  }
  if (RuntimeEnabledFeatures::RasterInducingScrollEnabled() &&
      !client_.ShouldForceMainThreadRepaint(scroll_translation)) {
    return cc::MainThreadScrollingReason::kNotScrollingOnMain;
  }
  return cc::MainThreadScrollingReason::kNotOpaqueForTextAndLCDText;
}

uint32_t PropertyTreeManager::GetMainThreadRepaintReasons(
    const cc::LayerTreeHost& host,
    const ScrollPaintPropertyNode& scroll) {
  const auto* property_trees = host.property_trees();
  const auto* cc_scroll = property_trees->scroll_tree().Node(
      scroll.CcNodeId(property_trees->sequence_number()));
  return cc_scroll
             ? cc_scroll->main_thread_repaint_reasons
             : cc::MainThreadScrollingReason::kPreferNonCompositedScrolling;
}

bool PropertyTreeManager::UsesCompositedScrolling(
    const cc::LayerTreeHost& host,
    const ScrollPaintPropertyNode& scroll) {
  CHECK(!RuntimeEnabledFeatures::RasterInducingScrollEnabled());
  const auto* property_trees = host.property_trees();
  const auto* cc_scroll = property_trees->scroll_tree().Node(
      scroll.CcNodeId(property_trees->sequence_number()));
  return cc_scroll && cc_scroll->is_composited;
}

void PropertyTreeManager::SetupRootTransformNode() {
  // cc is hardcoded to use transform node index 1 for device scale and
  // transform.
  transform_tree_.clear();
  cc::TransformNode& transform_node = *transform_tree_.Node(
      transform_tree_.Insert(cc::TransformNode(), cc::kRootPropertyNodeId));
  DCHECK_EQ(transform_node.id, cc::kSecondaryRootPropertyNodeId);

  // TODO(jaydasika): We shouldn't set ToScreen and FromScreen of root
  // transform node here. They should be set while updating transform tree in
  // cc.
  float device_scale_factor =
      root_layer_.layer_tree_host()->device_scale_factor();
  transform_tree_.set_device_scale_factor(device_scale_factor);
  gfx::Transform to_screen;
  to_screen.Scale(device_scale_factor, device_scale_factor);
  transform_tree_.SetToScreen(cc::kRootPropertyNodeId, to_screen);
  gfx::Transform from_screen = to_screen.GetCheckedInverse();
  transform_tree_.SetFromScreen(cc::kRootPropertyNodeId, from_screen);
  transform_tree_.set_needs_update(true);

  TransformPaintPropertyNode::Root().SetCcNodeId(new_sequence_number_,
                                                 transform_node.id);
  root_layer_.SetTransformTreeIndex(transform_node.id);
}

void PropertyTreeManager::SetupRootClipNode() {
  // cc is hardcoded to use clip node index 1 for viewport clip.
  clip_tree_.clear();
  cc::ClipNode& clip_node = *clip_tree_.Node(
      clip_tree_.Insert(cc::ClipNode(), cc::kRootPropertyNodeId));
  DCHECK_EQ(clip_node.id, cc::kSecondaryRootPropertyNodeId);

  // TODO(bokan): This needs to come from the Visual Viewport which will
  // correctly account for the URL bar. In fact, the visual viewport property
  // tree builder should probably be the one to create the property tree state
  // and have this created in the same way as other layers.
  clip_node.clip =
      gfx::RectF(root_layer_.layer_tree_host()->device_viewport_rect());
  clip_node.transform_id = cc::kRootPropertyNodeId;

  ClipPaintPropertyNode::Root().SetCcNodeId(new_sequence_number_, clip_node.id);
  root_layer_.SetClipTreeIndex(clip_node.id);
}

void PropertyTreeManager::SetupRootEffectNode() {
  // cc is hardcoded to use effect node index 1 for root render surface.
  effect_tree_.clear();
  cc::EffectNode& effect_node = *effect_tree_.Node(
      effect_tree_.Insert(cc::EffectNode(), cc::kInvalidPropertyNodeId));
  DCHECK_EQ(effect_node.id, cc::kSecondaryRootPropertyNodeId);

  static UniqueObjectId unique_id = NewUniqueObjectId();

  effect_node.element_id = CompositorElementIdFromUniqueObjectId(unique_id);
  effect_node.transform_id = cc::kRootPropertyNodeId;
  effect_node.clip_id = cc::kSecondaryRootPropertyNodeId;
  effect_node.render_surface_reason = cc::RenderSurfaceReason::kRoot;
  root_layer_.SetEffectTreeIndex(effect_node.id);

  EffectPaintPropertyNode::Root().SetCcNodeId(new_sequence_number_,
                                              effect_node.id);
  SetCurrentEffectState(
      effect_node, CcEffectType::kEffect, EffectPaintPropertyNode::Root(),
      ClipPaintPropertyNode::Root(), TransformPaintPropertyNode::Root());
}

void PropertyTreeManager::SetupRootScrollNode() {
  scroll_tree_.clear();
  cc::ScrollNode& scroll_node = *scroll_tree_.Node(
      scroll_tree_.Insert(cc::ScrollNode(), cc::kRootPropertyNodeId));
  DCHECK_EQ(scroll_node.id, cc::kSecondaryRootPropertyNodeId);
  scroll_node.transform_id = cc::kSecondaryRootPropertyNodeId;

  ScrollPaintPropertyNode::Root().SetCcNodeId(new_sequence_number_,
                                              scroll_node.id);
  root_layer_.SetScrollTreeIndex(scroll_node.id);
}

static bool TransformsToAncestorHaveNonAxisAlignedActiveAnimation(
    const TransformPaintPropertyNode& descendant,
    const TransformPaintPropertyNode& ancestor) {
  if (&descendant == &ancestor)
    return false;
  for (const auto* n = &descendant; n != &ancestor; n = n->UnaliasedParent()) {
    if (n->HasActiveTransformAnimation() &&
        !n->TransformAnimationIsAxisAligned()) {
      return true;
    }
  }
  return false;
}

bool TransformsMayBe2dAxisMisaligned(const TransformPaintPropertyNode& a,
                                     const TransformPaintPropertyNode& b) {
  if (&a == &b)
    return false;
  if (!GeometryMapper::SourceToDestinationProjection(a, b)
           .Preserves2dAxisAlignment()) {
    return true;
  }
  const auto& lca = a.LowestCommonAncestor(b).Unalias();
  if (TransformsToAncestorHaveNonAxisAlignedActiveAnimation(a, lca) ||
      TransformsToAncestorHaveNonAxisAlignedActiveAnimation(b, lca))
    return true;
  return false;
}

// A reason is conditional if it can be omitted if it controls less than two
// composited layers or render surfaces. We set the reason on an effect node
// when updating the cc effect property tree, and remove unnecessary ones in
// UpdateConditionalRenderSurfaceReasons() after layerization.
static bool IsConditionalRenderSurfaceReason(cc::RenderSurfaceReason reason) {
  return reason == cc::RenderSurfaceReason::kBlendModeDstIn ||
         reason == cc::RenderSurfaceReason::kOpacity ||
         reason == cc::RenderSurfaceReason::kOpacityAnimation;
}

void PropertyTreeManager::SetCurrentEffectState(
    const cc::EffectNode& cc_effect_node,
    CcEffectType effect_type,
    const EffectPaintPropertyNode& effect,
    const ClipPaintPropertyNode& clip,
    const TransformPaintPropertyNode& transform) {
  const auto* previous_transform =
      effect.IsRoot() ? nullptr : current_.transform.Get();
  current_.effect_id = cc_effect_node.id;
  current_.effect_type = effect_type;
  current_.effect = &effect;
  current_.clip = &clip;
  current_.transform = &transform;

  if (cc_effect_node.HasRenderSurface() &&
      !IsConditionalRenderSurfaceReason(cc_effect_node.render_surface_reason)) {
    current_.may_be_2d_axis_misaligned_to_render_surface =
        EffectState::kAligned;
    current_.contained_by_non_render_surface_synthetic_rounded_clip = false;
  } else {
    if (current_.may_be_2d_axis_misaligned_to_render_surface ==
            EffectState::kAligned &&
        previous_transform != current_.transform) {
      current_.may_be_2d_axis_misaligned_to_render_surface =
          EffectState::kUnknown;
    }
    current_.contained_by_non_render_surface_synthetic_rounded_clip |=
        (effect_type & CcEffectType::kSyntheticForNonTrivialClip);
  }
}

int PropertyTreeManager::EnsureCompositorTransformNode(
    const TransformPaintPropertyNode& transform_node) {
  int id = transform_node.CcNodeId(new_sequence_number_);
  if (id != cc::kInvalidPropertyNodeId) {
    DCHECK(transform_tree_.Node(id));
    return id;
  }

  DCHECK(transform_node.Parent());
  int parent_id =
      EnsureCompositorTransformNode(transform_node.Parent()->Unalias());
  id = transform_tree_.Insert(cc::TransformNode(), parent_id);

  if (auto* scroll_translation_for_fixed =
          transform_node.ScrollTranslationForFixed()) {
    // Fixed-position can cause different topologies of the transform tree and
    // the scroll tree. This ensures the ancestor scroll nodes of the scroll
    // node for a descendant transform node below is created.
    EnsureCompositorTransformNode(*scroll_translation_for_fixed);
  }

  cc::TransformNode& compositor_node = *transform_tree_.Node(id);
  UpdateCcTransformLocalMatrix(compositor_node, transform_node);

  compositor_node.should_undo_overscroll =
      transform_node.RequiresCompositingForFixedToViewport();
  compositor_node.transform_changed = transform_node.NodeChangeAffectsRaster();
  compositor_node.flattens_inherited_transform =
      transform_node.FlattensInheritedTransform();
  compositor_node.sorting_context_id = transform_node.RenderingContextId();
  compositor_node.delegates_to_parent_for_backface =
      transform_node.DelegatesToParentForBackface();

  if (transform_node.IsAffectedByOuterViewportBoundsDelta()) {
    compositor_node.moved_by_outer_viewport_bounds_delta_y = true;
    transform_tree_.AddNodeAffectedByOuterViewportBoundsDelta(id);
  }

  compositor_node.in_subtree_of_page_scale_layer =
      transform_node.IsInSubtreeOfPageScale();

  compositor_node.will_change_transform =
      transform_node.RequiresCompositingForWillChangeTransform() &&
      // cc assumes preference of performance over raster quality for
      // will-change:transform, but for SVG we still prefer raster quality, so
      // don't pass will-change:transform to cc for SVG.
      // TODO(crbug.com/1186020): find a better way to handle this.
      !transform_node.IsForSVGChild();

  if (const auto* sticky_constraint = transform_node.GetStickyConstraint()) {
    cc::StickyPositionNodeData& sticky_data =
        transform_tree_.EnsureStickyPositionData(id);
    sticky_data.constraints = *sticky_constraint;
    const auto& scroll_ancestor = transform_node.NearestScrollTranslationNode();
    sticky_data.scroll_ancestor = EnsureCompositorScrollAndTransformNode(
        scroll_ancestor, InfiniteIntRect());
    const auto& scroll_ancestor_compositor_node =
        *scroll_tree_.Node(sticky_data.scroll_ancestor);
    if (scroll_ancestor_compositor_node.scrolls_outer_viewport)
      transform_tree_.AddNodeAffectedByOuterViewportBoundsDelta(id);
    if (auto shifting_sticky_box_element_id =
            sticky_data.constraints.nearest_element_shifting_sticky_box) {
      sticky_data.nearest_node_shifting_sticky_box =
          transform_tree_.FindNodeFromElementId(shifting_sticky_box_element_id)
              ->id;
    }
    if (auto shifting_containing_block_element_id =
            sticky_data.constraints.nearest_element_shifting_containing_block) {
      // TODO(crbug.com/1224888): Get rid of the nullptr check below:
      if (cc::TransformNode* node = transform_tree_.FindNodeFromElementId(
              shifting_containing_block_element_id)) {
        sticky_data.nearest_node_shifting_containing_block = node->id;
      }
    }
  }

  if (const auto* data = transform_node.GetAnchorPositionScrollData()) {
    transform_tree_.EnsureAnchorPositionScrollData(id) = *data;
  }

  auto compositor_element_id = transform_node.GetCompositorElementId();
  if (compositor_element_id) {
    transform_tree_.SetElementIdForNodeId(id, compositor_element_id);
    compositor_node.element_id = compositor_element_id;
  }

  transform_node.SetCcNodeId(new_sequence_number_, id);

  // If this transform is a scroll offset translation, create the associated
  // compositor scroll property node and adjust the compositor transform node's
  // scroll offset.
  if (transform_node.ScrollNode()) {
    compositor_node.scrolls = true;
    compositor_node.should_be_snapped = true;
    int scroll_id = EnsureCompositorScrollNode(transform_node);
    cc::ScrollNode* scroll_node = scroll_tree_.Node(scroll_id);
    scroll_node->transform_id = id;
    scroll_node->is_composited =
        client_.NeedsCompositedScrolling(transform_node);
    if (!scroll_node->is_composited) {
      scroll_node->main_thread_repaint_reasons |=
          NonCompositedMainThreadRepaintReasons(transform_node);
    }
  }

  compositor_node.visible_frame_element_id =
      transform_node.GetVisibleFrameElementId();

  // Attach the index of the nearest parent node associated with a frame.
  int parent_frame_id = cc::kInvalidPropertyNodeId;
  if (const auto* parent = transform_node.UnaliasedParent()) {
    if (parent->IsFramePaintOffsetTranslation()) {
      parent_frame_id = parent_id;
    } else {
      const auto* parent_compositor_node = transform_tree_.Node(parent_id);
      DCHECK(parent_compositor_node);
      parent_frame_id = parent_compositor_node->parent_frame_id;
    }
  }
  compositor_node.parent_frame_id = parent_frame_id;

  transform_tree_.set_needs_update(true);

  return id;
}

int PropertyTreeManager::EnsureCompositorPageScaleTransformNode(
    const TransformPaintPropertyNode& node) {
  DCHECK(!node.IsInSubtreeOfPageScale());
  int id = EnsureCompositorTransformNode(node);
  DCHECK(transform_tree_.Node(id));
  cc::TransformNode& compositor_node = *transform_tree_.Node(id);
  SetTransformTreePageScaleFactor(transform_tree_, compositor_node);
  transform_tree_.set_needs_update(true);
  return id;
}

int PropertyTreeManager::EnsureCompositorClipNode(
    const ClipPaintPropertyNode& clip_node) {
  int id = clip_node.CcNodeId(new_sequence_number_);
  if (id != cc::kInvalidPropertyNodeId) {
    DCHECK(clip_tree_.Node(id));
    return id;
  }

  DCHECK(clip_node.UnaliasedParent());
  int parent_id = EnsureCompositorClipNode(*clip_node.UnaliasedParent());
  id = clip_tree_.Insert(cc::ClipNode(), parent_id);

  cc::ClipNode& compositor_node = *clip_tree_.Node(id);

  compositor_node.clip = clip_node.PaintClipRect().Rect();
  compositor_node.transform_id =
      EnsureCompositorTransformNode(clip_node.LocalTransformSpace().Unalias());
  if (clip_node.PixelMovingFilter()) {
    // We have to wait until the cc effect node for the filter is ready before
    // setting compositor_node.pixel_moving_filter_id.
    pixel_moving_filter_clip_expanders_.push_back(&clip_node);
  }

  clip_node.SetCcNodeId(new_sequence_number_, id);
  clip_tree_.set_needs_update(true);
  return id;
}

int PropertyTreeManager::EnsureCompositorScrollNode(
    const TransformPaintPropertyNode& scroll_translation) {
  const auto* scroll_node = scroll_translation.ScrollNode();
  CHECK(scroll_node);
  int scroll_id = EnsureCompositorScrollNodeInternal(*scroll_node);
  scroll_tree_.SetScrollOffset(
      scroll_node->GetCompositorElementId(),
      gfx::PointAtOffsetFromOrigin(-scroll_translation.Get2dTranslation()));
  return scroll_id;
}

int PropertyTreeManager::EnsureCompositorScrollNodeInternal(
    const ScrollPaintPropertyNode& scroll_node) {
  int id = scroll_node.CcNodeId(new_sequence_number_);
  if (id != cc::kInvalidPropertyNodeId) {
    return id;
  }

  CHECK(scroll_node.Parent());
  int parent_id = EnsureCompositorScrollNodeInternal(*scroll_node.Parent());
  id = scroll_tree_.Insert(cc::ScrollNode(), parent_id);

  cc::ScrollNode& compositor_node = *scroll_tree_.Node(id);
  compositor_node.container_origin = scroll_node.ContainerRect().origin();
  compositor_node.container_bounds = scroll_node.ContainerRect().size();
  compositor_node.bounds = scroll_node.ContentsRect().size();
  compositor_node.user_scrollable_horizontal =
      scroll_node.UserScrollableHorizontal();
  compositor_node.user_scrollable_vertical =
      scroll_node.UserScrollableVertical();
  compositor_node.prevent_viewport_scrolling_from_inner =
      scroll_node.PreventViewportScrollingFromInner();

  compositor_node.max_scroll_offset_affected_by_page_scale =
      scroll_node.MaxScrollOffsetAffectedByPageScale();
  compositor_node.overscroll_behavior =
      cc::OverscrollBehavior(static_cast<cc::OverscrollBehavior::Type>(
                                 scroll_node.OverscrollBehaviorX()),
                             static_cast<cc::OverscrollBehavior::Type>(
                                 scroll_node.OverscrollBehaviorY()));
  compositor_node.snap_container_data = scroll_node.GetSnapContainerData();

  auto compositor_element_id = scroll_node.GetCompositorElementId();
  if (compositor_element_id) {
    compositor_node.element_id = compositor_element_id;
    scroll_tree_.SetElementIdForNodeId(id, compositor_element_id);
  }

  // These three fields are either permanent for unpainted scrolls, or will be
  // overridden when we handle the painted scroll.
  compositor_node.transform_id = cc::kInvalidPropertyNodeId;
  compositor_node.is_composited = false;
  compositor_node.main_thread_repaint_reasons =
      scroll_node.GetMainThreadRepaintReasons();
  CHECK_EQ(compositor_node.main_thread_repaint_reasons,
           scroll_tree_.GetMainThreadRepaintReasons(compositor_node));

  scroll_node.SetCcNodeId(new_sequence_number_, id);
  return id;
}

int PropertyTreeManager::EnsureCompositorScrollAndTransformNode(
    const TransformPaintPropertyNode& scroll_translation,
    const gfx::Rect& scrolling_contents_cull_rect) {
  EnsureCompositorTransformNode(scroll_translation);
  int id = scroll_translation.ScrollNode()->CcNodeId(new_sequence_number_);
  DCHECK(scroll_tree_.Node(id));
  return id;
}

int PropertyTreeManager::EnsureCompositorInnerScrollAndTransformNode(
    const TransformPaintPropertyNode& scroll_translation) {
  int node_id = EnsureCompositorScrollAndTransformNode(scroll_translation,
                                                       InfiniteIntRect());
  scroll_tree_.Node(node_id)->scrolls_inner_viewport = true;
  return node_id;
}

int PropertyTreeManager::EnsureCompositorOuterScrollAndTransformNode(
    const TransformPaintPropertyNode& scroll_translation) {
  int node_id = EnsureCompositorScrollAndTransformNode(scroll_translation,
                                                       InfiniteIntRect());
  scroll_tree_.Node(node_id)->scrolls_outer_viewport = true;
  return node_id;
}

void PropertyTreeManager::EmitClipMaskLayer() {
  cc::EffectNode* mask_isolation = effect_tree_.Node(current_.effect_id);
  DCHECK(mask_isolation);
  bool needs_layer =
      !pending_synthetic_mask_layers_.Contains(mask_isolation->id) &&
      mask_isolation->mask_filter_info.IsEmpty();

  CompositorElementId mask_isolation_id, mask_effect_id;
  SynthesizedClip& clip = client_.CreateOrReuseSynthesizedClipLayer(
      *current_.clip, *current_.transform, needs_layer, mask_isolation_id,
      mask_effect_id);

  // Now we know the actual mask_isolation.element_id.
  // This overrides the element_id set in PopulateCcEffectNode() if the
  // backdrop effect was moved up to |mask_isolation|.
  mask_isolation->element_id = mask_isolation_id;

  if (!needs_layer)
    return;

  cc::EffectNode& mask_effect = *effect_tree_.Node(
      effect_tree_.Insert(cc::EffectNode(), current_.effect_id));
  // The address of mask_isolation may have changed when we insert
  // |mask_effect| into the tree.
  mask_isolation = effect_tree_.Node(current_.effect_id);

  mask_effect.element_id = mask_effect_id;
  mask_effect.clip_id = mask_isolation->clip_id;
  mask_effect.blend_mode = SkBlendMode::kDstIn;

  cc::PictureLayer* mask_layer = clip.Layer();

  layer_list_builder_.Add(mask_layer);
  mask_layer->set_property_tree_sequence_number(
      root_layer_.property_tree_sequence_number());
  mask_layer->SetTransformTreeIndex(
      EnsureCompositorTransformNode(*current_.transform));
  int scroll_id = EnsureCompositorScrollAndTransformNode(
      current_.transform->NearestScrollTranslationNode(), InfiniteIntRect());
  mask_layer->SetScrollTreeIndex(scroll_id);
  mask_layer->SetClipTreeIndex(mask_effect.clip_id);
  mask_layer->SetEffectTreeIndex(mask_effect.id);

  if (!mask_isolation->backdrop_filters.IsEmpty()) {
    mask_layer->SetIsBackdropFilterMask(true);
    auto element_id = CompositorElementIdWithNamespace(
        mask_effect.element_id, CompositorElementIdNamespace::kEffectMask);
    mask_layer->SetElementId(element_id);
    mask_isolation->backdrop_mask_element_id = element_id;
  }
}

void PropertyTreeManager::CloseCcEffect() {
  DCHECK(effect_stack_.size());
  const auto& previous_state = effect_stack_.back();

  // A backdrop effect (exotic blending or backdrop filter) that is masked by a
  // synthesized clip must have its effect to the outermost synthesized clip.
  // These operations need access to the backdrop of the enclosing effect. With
  // the isolation for a synthesized clip, a blank backdrop will be seen.
  // Therefore the backdrop effect is delegated to the outermost synthesized
  // clip, thus the clip can't be shared with sibling layers, and must be
  // closed now.
  bool clear_synthetic_effects =
      !IsCurrentCcEffectSynthetic() && current_.effect->MayHaveBackdropEffect();

  // We are about to close an effect that was synthesized for isolating
  // a clip mask. Now emit the actual clip mask that will be composited on
  // top of masked contents with SkBlendMode::kDstIn.
  if (IsCurrentCcEffectSyntheticForNonTrivialClip())
    EmitClipMaskLayer();

  if (IsCurrentCcEffectSynthetic())
    pending_synthetic_mask_layers_.erase(current_.effect_id);

  current_ = previous_state;
  effect_stack_.pop_back();

  if (clear_synthetic_effects) {
    while (IsCurrentCcEffectSynthetic())
      CloseCcEffect();
  }
}

int PropertyTreeManager::SwitchToEffectNodeWithSynthesizedClip(
    const EffectPaintPropertyNode& next_effect,
    const ClipPaintPropertyNode& next_clip,
    bool layer_draws_content) {
  // This function is expected to be invoked right before emitting each layer.
  // It keeps track of the nesting of clip and effects, output a composited
  // effect node whenever an effect is entered, or a non-trivial clip is
  // entered. In the latter case, the generated composited effect node is
  // called a "synthetic effect", and the corresponding clip a "synthesized
  // clip". Upon exiting a synthesized clip, a mask layer will be appended,
  // which will be kDstIn blended on top of contents enclosed by the synthetic
  // effect, i.e. applying the clip as a mask.
  //
  // For example with the following clip and effect tree and pending layers:
  // E0 <-- E1
  // C0 <-- C1(rounded)
  // [P0(E1,C0), P1(E1,C1), P2(E0,C1)]
  // In effect stack diagram:
  // P0(C0) P1(C1)
  // [    E1     ] P2(C1)
  // [        E0        ]
  //
  // The following cc property trees and layers will be generated:
  // E0 <+- E1 <-- E_C1_1 <-- E
```