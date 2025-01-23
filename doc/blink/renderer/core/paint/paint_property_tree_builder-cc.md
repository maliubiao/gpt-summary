Response:
My thinking process to answer the prompt about `paint_property_tree_builder.cc` involved several steps, focusing on understanding the code's purpose and its relation to web technologies:

1. **Initial Skim for Keywords and Core Concepts:** I first scanned the included header files and the namespace to identify key terms. "Paint," "Property Tree," "Layout," "Transform," "Clip," "Scroll," "Effect," "Compositing," "Animation," "CSS," "HTML," and "JavaScript" immediately stood out. These keywords provided a high-level indication of the file's domain. The filename itself, `paint_property_tree_builder.cc`, strongly suggested its primary function: constructing a tree-like data structure representing paint properties.

2. **Deduce Core Functionality:** Based on the keywords, I deduced that this file is responsible for building the Paint Property Tree. This tree is crucial for the rendering process, as it organizes how visual properties (like transforms, clipping, and effects) are applied to elements on a web page. It likely optimizes rendering by grouping elements with shared properties.

3. **Identify Relationships with Web Technologies:**  I considered how the identified keywords connect to the core web technologies:
    * **CSS:** Properties like `transform`, `clip-path`, `opacity`, `filter`, `overflow`, and `scroll` are directly represented in the code.
    * **HTML:** The structure of the HTML document (DOM) influences the creation of the Paint Property Tree. Elements in the DOM will have corresponding nodes in this tree.
    * **JavaScript:** While not directly manipulated *by* this code, JavaScript can *trigger* changes that necessitate rebuilding the Paint Property Tree (e.g., manipulating styles or element positions). Animations, often controlled by JavaScript or CSS transitions, are explicitly mentioned in the includes.

4. **Examine Included Headers for Specific Functionality:**  I paid closer attention to the included header files:
    * Headers like `core/layout/...` indicated the code's interaction with the layout engine, which determines the size and position of elements.
    * Headers related to `core/paint/...` confirmed its central role in the painting process.
    * Headers like `platform/graphics/compositing/...` suggested involvement in hardware acceleration (compositing).
    * The presence of `core/animation/element_animations.h` highlighted the connection to animations.
    * Headers referencing specific HTML elements (`html_input_element.h`, `html_select_element.h`) suggested that the Paint Property Tree might have specific considerations for form elements.

5. **Infer Logic and Data Flow (High Level):** I reasoned that the `PaintPropertyTreeBuilder` likely traverses the layout tree (or a related structure) and, based on the CSS properties and other factors, creates nodes in the Paint Property Tree. Each node would store information about specific paint properties. The code likely handles inheritance of properties and the creation of new property nodes when necessary.

6. **Consider Potential Use Cases and Errors:**  I brainstormed scenarios where this code would be invoked and potential issues:
    * **Initial page load:** The tree needs to be built initially.
    * **Dynamic style changes:** JavaScript modifying CSS properties will require updates.
    * **Scrolling:**  Scroll-related properties and nodes are clearly important.
    * **Animations and transitions:** These constantly change properties, leading to tree updates.
    * **Common user errors:**  Incorrect CSS can lead to unexpected paint property behavior, which this code needs to handle correctly. For example, complex combinations of transforms and clips might be challenging.

7. **Structure the Answer:** I organized my findings into the categories requested by the prompt:
    * **Functionality:** A concise summary of the main purpose.
    * **Relationships with Web Technologies:**  Specific examples illustrating the connections to JavaScript, HTML, and CSS.
    * **Logical Reasoning (Hypothetical Input/Output):** A simplified scenario to demonstrate how the builder might process input and generate output.
    * **Common User/Programming Errors:** Examples of mistakes that could relate to this code.
    * **User Operation as Debugging Clue:** Steps a user might take to trigger this code.
    * **Summary of Functionality (for Part 1):** A concluding sentence for the first part.

8. **Refine and Elaborate:** I reviewed my initial thoughts and added more detail and specific examples. For instance, for CSS, I listed concrete CSS properties. For JavaScript, I mentioned triggering style changes.

Essentially, my process was a combination of:

* **Keyword analysis:** Identifying key terms to understand the domain.
* **Deductive reasoning:** Inferring the code's purpose from its name and included headers.
* **Connecting to prior knowledge:**  Relating the concepts to my understanding of web technologies.
* **Hypothetical reasoning:** Imagining scenarios to understand the code's behavior and potential issues.

This iterative process of exploring the code snippet, relating it to broader concepts, and structuring the information allowed me to generate a comprehensive answer even without diving deeply into the implementation details of the provided code. The focus was on understanding the *what* and the *why* rather than the *how* at this stage.
这是对 Chromium Blink 引擎源代码文件 `blink/renderer/core/paint/paint_property_tree_builder.cc` 的第一部分代码的分析。根据提供的代码片段，可以归纳出以下功能：

**主要功能：构建和更新渲染属性树 (Paint Property Tree)**

`paint_property_tree_builder.cc` 的核心职责是构建和维护一个表示页面元素渲染属性的树形结构，即 Paint Property Tree。这个树结构优化了渲染过程，因为它将共享相同渲染属性的元素组合在一起，减少了重复计算和资源消耗。

**具体功能点：**

1. **管理不同类型的渲染属性节点:** 代码中包含了对 `TransformPaintPropertyNode`, `ClipPaintPropertyNode`, `EffectPaintPropertyNode`, 和 `ScrollPaintPropertyNode` 的引用和操作。这意味着该文件负责构建和连接这些不同类型的节点，形成属性树。

2. **处理 VisualViewport 的属性更新:** `VisualViewportPaintPropertyTreeBuilder::Update` 函数专门负责更新与视口 (VisualViewport) 相关的渲染属性，例如滚动和变换。这与用户在页面上滚动和缩放操作密切相关。

3. **为 Frame 设置上下文:** `PaintPropertyTreeBuilder::SetupContextForFrame` 函数用于为一个新的 Frame (例如 iframe) 初始化属性树构建的上下文信息，包括偏移、渲染上下文 ID 等。

4. **处理元素的渲染属性更新:**  `FragmentPaintPropertyTreeBuilder` 类是核心，负责处理单个 LayoutObject (页面元素的布局对象) 的渲染属性更新。它包含了大量的 `UpdateForSelf` 和 `UpdateForChildren` 方法，以及各种 `Update...` 函数，用于根据元素的样式和布局信息，更新其对应的属性节点。

5. **处理各种 CSS 属性的影响:** 代码中涉及到许多与 CSS 属性相关的逻辑，例如：
    * **Transform (变换):**  `UpdateTransform`, `UpdateTranslate`, `UpdateRotate`, `UpdateScale`, `UpdateOffset`, `UpdateTransformForSVGChild`.
    * **Clip (裁剪):** `UpdateCssClip`, `UpdateClipPathClip`, `UpdateOverflowClip`.
    * **Effect (效果):** `UpdateEffect`, `UpdateFilter`, `UpdateViewTransitionEffect`.
    * **Scroll (滚动):** `UpdateScrollAndScrollTranslation`, `UpdateScrollNode`, `UpdateScrollTranslation`.
    * **其他:**  `UpdatePerspective`, `UpdateReplacedContentTransform`, `UpdateBackgroundClip`, `UpdateOverflowControlsClip` 等。

6. **处理 Compositing (合成) 的影响:** 代码中多次提到 "compositing reasons"，这表明属性树的构建还考虑了元素是否需要被合成到独立的 layer 中进行渲染，以提升性能。

7. **处理 Isolation (隔离) 的概念:**  代码中包含了 `UpdateTransformIsolationNode`, `UpdateEffectIsolationNode`, `UpdateClipIsolationNode`，这与 CSS 的 `isolation` 属性以及一些特殊的渲染上下文有关，用于创建新的 stacking context 并限制属性的传播。

8. **处理 Sticky Position (粘性定位):** `UpdateStickyTranslation` 函数专门处理 `position: sticky` 元素的渲染属性。

9. **处理 Anchor Position Scrolling (锚点定位滚动):** `UpdateAnchorPositionScrollTranslation` 函数处理与锚点定位滚动相关的属性。

10. **处理 View Transitions (视图过渡):** `UpdateViewTransitionSubframeRootEffect` 和 `UpdateViewTransitionEffect` 函数与实验性的视图过渡 API 相关。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** HTML 结构定义了页面的元素，`paint_property_tree_builder.cc` 基于 HTML 元素创建对应的 LayoutObject，并为这些对象构建渲染属性。
    * **举例:**  一个 `<div>` 元素在 HTML 中定义，Blink 引擎会为其创建一个 LayoutBlock 对象，`paint_property_tree_builder.cc` 会根据该 `<div>` 的 CSS 样式，例如 `width`, `height`, `background-color` 等，来构建或更新其渲染属性节点。

* **CSS:** CSS 样式规则直接影响渲染属性树的构建。`paint_property_tree_builder.cc` 解析 CSS 属性，并根据这些属性的值来创建和修改渲染属性节点。
    * **举例:** 当一个元素的 CSS `transform: rotate(45deg)` 被设置时，`UpdateTransform` 或相关的 `UpdateRotate` 函数会被调用，创建一个或更新 `TransformPaintPropertyNode`，记录这个旋转变换。
    * **举例:** 当元素的 CSS `clip-path: polygon(...)` 被设置时，`UpdateClipPathClip` 函数会被调用，创建一个 `ClipPaintPropertyNode` 来表示这个复杂的裁剪路径。

* **JavaScript:** JavaScript 可以动态地修改 HTML 结构和 CSS 样式，这些修改会触发 `paint_property_tree_builder.cc` 重新构建或更新渲染属性树。
    * **举例:**  JavaScript 通过 `element.style.opacity = 0.5` 修改元素的透明度，这会导致 `UpdateEffect` 函数被调用，更新或创建 `EffectPaintPropertyNode` 来反映新的透明度。
    * **举例:** JavaScript 通过 `element.classList.add('animated')` 添加一个包含 `transform` 动画的 CSS 类，这会触发 `UpdateTransform` 等函数，并可能涉及动画相关的渲染属性更新。

**逻辑推理 (假设输入与输出):**

**假设输入:**  一个简单的 HTML 结构如下：

```html
<div style="width: 100px; height: 100px; transform: translate(10px, 20px);"></div>
```

**过程:**

1. Blink 引擎解析 HTML，创建 `<div>` 元素的 LayoutBlock 对象。
2. `paint_property_tree_builder.cc` 接收到该 LayoutBlock 对象。
3. `UpdateForSelf` 或相关的函数被调用。
4. `UpdateTransform` 函数被调用，因为它检测到 `transform` 属性。
5. `UpdateTranslate` 函数被调用，解析 `translate(10px, 20px)`。
6. 创建或更新一个 `TransformPaintPropertyNode`，其中包含 `translateX = 10px`, `translateY = 20px` 的信息。

**假设输出:**  该 `<div>` 元素对应的渲染属性树片段包含一个 `TransformPaintPropertyNode`，其状态为：

```
TransformPaintPropertyNode {
  transform: translate(10px, 20px);
  // ... 其他属性
}
```

**用户或编程常见的使用错误:**

* **CSS 属性值错误:** 用户在 CSS 中写了错误的属性值，例如 `transform: rotata(45deg);`（拼写错误），这可能导致 `paint_property_tree_builder.cc` 无法正确解析和构建属性树，最终导致渲染错误或效果不符合预期。
* **复杂的 CSS 交互导致性能问题:** 过度使用复杂的 CSS 属性，例如大量的 3D transform 或 clip-path，可能导致渲染属性树过于复杂，增加计算量，影响页面性能。
* **JavaScript 频繁修改样式触发不必要的重绘:** JavaScript 代码中频繁地修改元素的样式，即使这些修改对渲染结果没有明显影响，也可能触发 `paint_property_tree_builder.cc` 重新构建或更新属性树，导致不必要的重绘和性能损耗。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户加载网页:** 当用户在浏览器中输入网址或点击链接加载网页时，Blink 引擎开始解析 HTML、CSS 和 JavaScript。
2. **解析 HTML 和 CSS:**  HTML 解析器构建 DOM 树，CSS 解析器解析 CSS 样式规则。
3. **创建 Layout Tree:**  Blink 的 Layout 引擎根据 DOM 树和 CSS 样式计算元素的布局信息，创建 Layout Tree。
4. **构建 Paint Property Tree:** `paint_property_tree_builder.cc` 遍历 Layout Tree，并根据元素的 CSS 属性和布局信息，逐步构建 Paint Property Tree。这个过程会在初始渲染以及后续的样式变化、动画、滚动等操作中发生。
5. **渲染:**  Paint Property Tree 构建完成后，Blink 的 Paint 引擎会利用这个树结构进行绘制操作，将页面内容渲染到屏幕上。

**调试线索:** 如果在渲染过程中出现问题，例如元素的位置、裁剪、效果等不正确，开发者可以使用浏览器的开发者工具进行调试：

* **检查元素的 computed style:** 查看元素的最终计算样式，确认 CSS 属性是否如预期。
* **使用 "Show Paint Rects" 或 "Layer Borders" 等渲染调试工具:**  这些工具可以帮助开发者可视化哪些区域被重绘，以及元素是否被提升为合成层。
* **在 `paint_property_tree_builder.cc` 中设置断点:** 如果怀疑问题出在渲染属性树的构建过程，开发者可以在相关的 `Update...` 函数中设置断点，跟踪代码的执行流程，查看属性节点是如何被创建和更新的。

**归纳一下它的功能 (针对第 1 部分):**

代码的第 1 部分主要定义了 `PaintPropertyTreeBuilderFragmentContext` 和 `VisualViewportPaintPropertyTreeBuilder` 类，并初步展示了 `PaintPropertyTreeBuilder` 和 `FragmentPaintPropertyTreeBuilder` 的结构和部分核心功能。其主要职责是为渲染过程准备必要的上下文信息，并处理视口相关的渲染属性更新。 核心目标是开始构建用于组织和优化页面元素渲染属性的树形结构。

### 提示词
```
这是目录为blink/renderer/core/paint/paint_property_tree_builder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/paint_property_tree_builder.h"

#include <memory>

#include "base/check_op.h"
#include "base/feature_list.h"
#include "base/memory/ptr_util.h"
#include "cc/base/features.h"
#include "cc/input/main_thread_scrolling_reason.h"
#include "cc/input/overscroll_behavior.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/layout/anchor_position_scroll_data.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/fragmentainer_iterator.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/transform_state.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_image.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_replaced.h"
#include "third_party/blink/renderer/core/layout/layout_video.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/pagination_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_clipper.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_root.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_viewport_container.h"
#include "third_party/blink/renderer/core/layout/svg/svg_layout_support.h"
#include "third_party/blink/renderer/core/layout/svg/svg_resources.h"
#include "third_party/blink/renderer/core/layout/svg/transform_helper.h"
#include "third_party/blink/renderer/core/layout/table/layout_table.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_row.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_section.h"
#include "third_party/blink/renderer/core/page/link_highlight.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/snap_coordinator.h"
#include "third_party/blink/renderer/core/page/scrolling/sticky_position_scrolling_constraints.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/paint/clip_path_clipper.h"
#include "third_party/blink/renderer/core/paint/compositing/compositing_reason_finder.h"
#include "third_party/blink/renderer/core/paint/css_mask_painter.h"
#include "third_party/blink/renderer/core/paint/cull_rect_updater.h"
#include "third_party/blink/renderer/core/paint/find_paint_offset_needing_update.h"
#include "third_party/blink/renderer/core/paint/find_properties_needing_update.h"
#include "third_party/blink/renderer/core/paint/object_paint_properties.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/paint_property_tree_printer.h"
#include "third_party/blink/renderer/core/paint/pre_paint_disable_side_effects_scope.h"
#include "third_party/blink/renderer/core/paint/rounded_border_geometry.h"
#include "third_party/blink/renderer/core/paint/svg_root_painter.h"
#include "third_party/blink/renderer/core/paint/transform_utils.h"
#include "third_party/blink/renderer/core/style/computed_style_base_constants.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/style/style_overflow_clip_margin.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/graphics/paint/effect_paint_property_node.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/skia/include/core/SkRRect.h"
#include "ui/gfx/geometry/outsets_f.h"
#include "ui/gfx/geometry/transform.h"
#include "ui/gfx/geometry/vector2d_conversions.h"

namespace blink {

namespace {

// This function is for convenience of debugging. For example, we can set a
// breakpoint at the assignment to track new property changes.
void UpdatePropertyChange(PaintPropertyChangeType& target,
                          PaintPropertyChangeType new_change) {
  if (target < new_change) {
    target = new_change;
  }
}

bool AreSubtreeUpdateReasonsIsolationPiercing(unsigned reasons) {
  // This is written to mean that if we have any reason other than the specified
  // ones then the reasons are isolation piercing. This means that if new
  // reasons are added, they will be isolation piercing by default.
  //  - Isolation establishes a containing block for all descendants, so it is
  //    not piercing.
  // TODO(vmpstr): Investigate if transform style is also isolated.
  return reasons &
         ~(static_cast<unsigned>(
             SubtreePaintPropertyUpdateReason::kContainerChainMayChange));
}

}  // namespace

PaintPropertyTreeBuilderFragmentContext::
    PaintPropertyTreeBuilderFragmentContext()
    : current_effect(&EffectPaintPropertyNode::Root()) {
  current.clip = absolute_position.clip = fixed_position.clip =
      &ClipPaintPropertyNode::Root();
  current.transform = absolute_position.transform = fixed_position.transform =
      &TransformPaintPropertyNode::Root();
  current.scroll = absolute_position.scroll = fixed_position.scroll =
      &ScrollPaintPropertyNode::Root();
}

void VisualViewportPaintPropertyTreeBuilder::Update(
    LocalFrameView& main_frame_view,
    VisualViewport& visual_viewport,
    PaintPropertyTreeBuilderContext& full_context) {
  PaintPropertyTreeBuilderFragmentContext& context =
      full_context.fragment_context;

  auto property_changed =
      visual_viewport.UpdatePaintPropertyNodesIfNeeded(context);

  context.current.transform = visual_viewport.GetScrollTranslationNode();
  context.absolute_position.transform =
      visual_viewport.GetScrollTranslationNode();
  context.fixed_position.transform = visual_viewport.GetScrollTranslationNode();

  context.current.scroll = visual_viewport.GetScrollNode();
  context.absolute_position.scroll = visual_viewport.GetScrollNode();
  context.fixed_position.scroll = visual_viewport.GetScrollNode();

  if (property_changed >= PaintPropertyChangeType::kNodeAddedOrRemoved) {
    // Force piercing subtree update for the worst case (scroll node added/
    // removed). Not a big deal for performance because this is rare.
    full_context.force_subtree_update_reasons |=
        PaintPropertyTreeBuilderContext::kSubtreeUpdateIsolationPiercing;
    // The main frame's paint chunks (e.g. scrollbars) may reference paint
    // properties of the visual viewport.
    if (auto* layout_view = main_frame_view.GetLayoutView())
      layout_view->Layer()->SetNeedsRepaint();
  }

  if (property_changed >
      PaintPropertyChangeType::kChangedOnlyCompositedValues) {
    main_frame_view.SetPaintArtifactCompositorNeedsUpdate();
  }

#if DCHECK_IS_ON()
  paint_property_tree_printer::UpdateDebugNames(visual_viewport);
#endif
}

void PaintPropertyTreeBuilder::SetupContextForFrame(
    LocalFrameView& frame_view,
    PaintPropertyTreeBuilderContext& full_context) {
  PaintPropertyTreeBuilderFragmentContext& context =
      full_context.fragment_context;

  // Block fragmentation doesn't cross frame boundaries.
  context.current.is_in_block_fragmentation = false;

  context.current.paint_offset += PhysicalOffset(frame_view.Location());
  context.rendering_context_id = 0;
  context.should_flatten_inherited_transform = true;
  context.absolute_position = context.current;
  full_context.container_for_absolute_position = nullptr;
  full_context.container_for_fixed_position = nullptr;
  context.fixed_position = context.current;
  context.fixed_position.fixed_position_children_fixed_to_root = true;
}

namespace {

class FragmentPaintPropertyTreeBuilder {
  STACK_ALLOCATED();

 public:
  FragmentPaintPropertyTreeBuilder(
      const LayoutObject& object,
      PrePaintInfo* pre_paint_info,
      PaintPropertyTreeBuilderContext& full_context,
      FragmentData& fragment_data)
      : object_(object),
        pre_paint_info_(pre_paint_info),
        full_context_(full_context),
        context_(full_context.fragment_context),
        fragment_data_(fragment_data),
        properties_(fragment_data.PaintProperties()) {}

#if DCHECK_IS_ON()
  ~FragmentPaintPropertyTreeBuilder() {
    if (properties_)
      paint_property_tree_printer::UpdateDebugNames(object_, *properties_);
  }
#endif

  ALWAYS_INLINE void UpdateForSelf();
  ALWAYS_INLINE void UpdateForChildren();

  const PaintPropertiesChangeInfo& PropertiesChanged() const {
    return properties_changed_;
  }

  bool HasIsolationNodes() const {
    // All or nothing check on the isolation nodes.
    DCHECK(!properties_ ||
           (properties_->TransformIsolationNode() &&
            properties_->ClipIsolationNode() &&
            properties_->EffectIsolationNode()) ||
           (!properties_->TransformIsolationNode() &&
            !properties_->ClipIsolationNode() &&
            !properties_->EffectIsolationNode()));
    return properties_ && properties_->TransformIsolationNode();
  }

 private:
  ALWAYS_INLINE bool CanPropagateSubpixelAccumulation() const;
  ALWAYS_INLINE void UpdatePaintOffset();
  ALWAYS_INLINE void UpdateForPaintOffsetTranslation(
      std::optional<gfx::Vector2d>&);
  ALWAYS_INLINE void UpdatePaintOffsetTranslation(
      const std::optional<gfx::Vector2d>&);
  ALWAYS_INLINE void SetNeedsPaintPropertyUpdateIfNeeded();
  ALWAYS_INLINE void UpdateForObjectLocation(
      std::optional<gfx::Vector2d>& paint_offset_translation);
  ALWAYS_INLINE void UpdateStickyTranslation();
  ALWAYS_INLINE void UpdateAnchorPositionScrollTranslation();

  void UpdateIndividualTransform(
      bool (*needs_property)(const LayoutObject&, CompositingReasons),
      void (*compute_matrix)(const LayoutBox& box,
                             const PhysicalRect& reference_box,
                             gfx::Transform& matrix),
      CompositingReasons compositing_reasons_for_property,
      CompositorElementIdNamespace compositor_namespace,
      bool (ComputedStyle::*running_on_compositor_test)() const,
      const TransformPaintPropertyNode* (ObjectPaintProperties::*getter)()
          const,
      PaintPropertyChangeType (ObjectPaintProperties::*updater)(
          const TransformPaintPropertyNodeOrAlias&,
          TransformPaintPropertyNode::State&&,
          const TransformPaintPropertyNode::AnimationState&),
      bool (ObjectPaintProperties::*clearer)());
  ALWAYS_INLINE void UpdateTranslate();
  ALWAYS_INLINE void UpdateRotate();
  ALWAYS_INLINE void UpdateScale();
  ALWAYS_INLINE void UpdateOffset();
  ALWAYS_INLINE void UpdateTransform();
  ALWAYS_INLINE void UpdateTransformForSVGChild(CompositingReasons);
  ALWAYS_INLINE bool NeedsEffect() const;
  ALWAYS_INLINE bool EffectCanUseCurrentClipAsOutputClip() const;
  ALWAYS_INLINE void UpdateViewTransitionSubframeRootEffect();
  ALWAYS_INLINE void UpdateViewTransitionEffect();
  ALWAYS_INLINE void UpdateViewTransitionClip();
  ALWAYS_INLINE void UpdateEffect();
  ALWAYS_INLINE void UpdateElementCaptureEffect();
  ALWAYS_INLINE void UpdateFilter();
  ALWAYS_INLINE void UpdateCssClip();
  ALWAYS_INLINE void UpdateClipPathClip();
  ALWAYS_INLINE void UpdateLocalBorderBoxContext();
  ALWAYS_INLINE bool NeedsOverflowControlsClip() const;
  ALWAYS_INLINE void UpdateOverflowControlsClip();
  ALWAYS_INLINE void UpdateBackgroundClip();
  ALWAYS_INLINE void UpdateInnerBorderRadiusClip();
  ALWAYS_INLINE void UpdateOverflowClip();
  ALWAYS_INLINE void UpdatePerspective();
  ALWAYS_INLINE void UpdateReplacedContentTransform();
  ALWAYS_INLINE void UpdateScrollAndScrollTranslation();
  ALWAYS_INLINE void UpdateScrollNode();
  ALWAYS_INLINE void UpdateScrollTranslation();
  ALWAYS_INLINE void UpdateOverflowControlEffects();
  ALWAYS_INLINE void UpdateOutOfFlowContext();
  // See core/paint/README.md for the description of isolation nodes.
  ALWAYS_INLINE void UpdateTransformIsolationNode();
  ALWAYS_INLINE void UpdateEffectIsolationNode();
  ALWAYS_INLINE void UpdateClipIsolationNode();
  ALWAYS_INLINE TransformPaintPropertyNode::TransformAndOrigin
  TransformAndOriginForSVGChild() const;
  ALWAYS_INLINE void UpdateLayoutShiftRootChanged(bool is_layout_shift_root);

  bool NeedsPaintPropertyUpdate() const {
    return object_.NeedsPaintPropertyUpdate() ||
           full_context_.force_subtree_update_reasons;
  }

  const PhysicalBoxFragment& BoxFragment() const {
    const auto& box = To<LayoutBox>(object_);
    if (pre_paint_info_) {
      if (pre_paint_info_->box_fragment) {
        return *pre_paint_info_->box_fragment;
      }
      // Just return the first fragment if we weren't provided with one. This
      // happens when rebuilding the property context objects before walking a
      // missed descendant. Depending on the purpose, callers might want to
      // check IsMissingActualFragment() and do something appropriate for the
      // situation, rather than using a half-bogus fragment in its full glory.
      // Block-offset and block-size will typically be wrong, for instance,
      // whereas inline-offset and inline-size may be useful, if we assume that
      // all fragmentainers have the same inline-size.
      return *box.GetPhysicalFragment(0);
    }
    // We only get here if we're not inside block fragmentation, so there should
    // only be one fragment.
    DCHECK_EQ(box.PhysicalFragmentCount(), 1u);
    return *box.GetPhysicalFragment(0);
  }

  // Return true if we haven't been provided with a physical fragment for this
  // object. BoxFragment() will still return one, but it's most likely not the
  // right one, so some special handling may be necessary.
  bool IsMissingActualFragment() const {
    bool is_missing = pre_paint_info_ && !pre_paint_info_->box_fragment;
    DCHECK(!is_missing || PrePaintDisableSideEffectsScope::IsDisabled());
    return is_missing;
  }

  bool IsInNGFragmentTraversal() const { return pre_paint_info_; }

  void SwitchToOOFContext(
      PaintPropertyTreeBuilderFragmentContext::ContainingBlockContext&
          oof_context) const {
    context_.current = oof_context;

    // If we're not block-fragmented, simply setting a new context is all we
    // have to do.
    if (!oof_context.is_in_block_fragmentation)
      return;

    // Inside NG block fragmentation we have to perform an offset adjustment.
    // An OOF fragment that is contained by something inside a fragmentainer
    // will be a direct child of the fragmentainer, rather than a child of its
    // actual containing block. Set the paint offset to the correct one.
    context_.current.paint_offset =
        context_.current.paint_offset_for_oof_in_fragmentainer;
  }

  void ResetPaintOffset(PhysicalOffset new_offset = PhysicalOffset()) {
    context_.current.paint_offset_for_oof_in_fragmentainer -=
        context_.current.paint_offset - new_offset;
    context_.current.paint_offset = new_offset;
  }

  void OnUpdateTransform(PaintPropertyChangeType change) {
    if (change != PaintPropertyChangeType::kUnchanged) {
      UpdatePropertyChange(properties_changed_.transform_changed, change);
      properties_changed_.transform_change_is_scroll_translation_only = false;
    }
  }
  void OnUpdateScrollTranslation(PaintPropertyChangeType change) {
    UpdatePropertyChange(properties_changed_.transform_changed, change);
  }
  void OnClearTransform(bool cleared) {
    if (cleared) {
      UpdatePropertyChange(properties_changed_.transform_changed,
                           PaintPropertyChangeType::kNodeAddedOrRemoved);
      properties_changed_.transform_change_is_scroll_translation_only = false;
    }
  }

  void OnUpdateClip(PaintPropertyChangeType change) {
    UpdatePropertyChange(properties_changed_.clip_changed, change);
  }
  void OnClearClip(bool cleared) {
    if (cleared) {
      UpdatePropertyChange(properties_changed_.clip_changed,
                           PaintPropertyChangeType::kNodeAddedOrRemoved);
    }
  }

  void OnUpdateEffect(PaintPropertyChangeType change) {
    UpdatePropertyChange(properties_changed_.effect_changed, change);
  }
  void OnClearEffect(bool cleared) {
    if (cleared) {
      UpdatePropertyChange(properties_changed_.effect_changed,
                           PaintPropertyChangeType::kNodeAddedOrRemoved);
    }
  }

  void OnUpdateScroll(PaintPropertyChangeType change) {
    UpdatePropertyChange(properties_changed_.scroll_changed, change);
  }
  void OnClearScroll(bool cleared) {
    if (cleared) {
      UpdatePropertyChange(properties_changed_.scroll_changed,
                           PaintPropertyChangeType::kNodeAddedOrRemoved);
    }
  }

  CompositorElementId GetCompositorElementId(
      CompositorElementIdNamespace namespace_id) const {
    return CompositorElementIdFromUniqueObjectId(fragment_data_.UniqueId(),
                                                 namespace_id);
  }

  MainThreadScrollingReasons GetMainThreadRepaintReasonsForScroll(
      bool user_scrollable) const;

  const LayoutObject& object_;
  PrePaintInfo* pre_paint_info_;
  // The tree builder context for the whole object.
  PaintPropertyTreeBuilderContext& full_context_;
  // The tree builder context for the current fragment, which is one of the
  // entries in |full_context.fragments|.
  PaintPropertyTreeBuilderFragmentContext& context_;
  FragmentData& fragment_data_;
  ObjectPaintProperties* properties_;
  PaintPropertiesChangeInfo properties_changed_;
  // These are updated in UpdateClipPathClip() and used in UpdateEffect() if
  // needs_mask_base_clip_path_ is true.
  bool needs_mask_based_clip_path_ = false;
  std::optional<gfx::RectF> clip_path_bounding_box_;
};

// True if a scroll node and a ScrollTranslation transform node are needed.
static bool NeedsScrollAndScrollTranslation(
    const LayoutObject& object,
    CompositingReasons direct_compositing_reasons) {
  if (!object.IsScrollContainer()) {
    return false;
  }
  if (direct_compositing_reasons & CompositingReason::kRootScroller) {
    return true;
  }

  auto* scrollable_area = To<LayoutBox>(object).GetScrollableArea();
  CHECK(scrollable_area);
  if (scrollable_area->ScrollsOverflow()) {
    return true;
  }
  // ScrollsOverflow is false for overflow:hidden, so we additionally check
  // if the offset/position is non-zero.
  if (!scrollable_area->ScrollPosition().IsOrigin() ||
      !scrollable_area->GetScrollOffset().IsZero()) {
    return true;
  }
  return false;
}

static bool NeedsReplacedContentTransform(const LayoutObject& object) {
  if (object.IsSVGRoot())
    return true;

  if (auto* layout_embedded_object = DynamicTo<LayoutEmbeddedContent>(object))
    return layout_embedded_object->FrozenFrameSize().has_value();

  return false;
}

static bool NeedsPaintOffsetTranslationForOverflowControls(
    const LayoutBoxModelObject& object) {
  if (auto* area = object.GetScrollableArea()) {
    if (area->HorizontalScrollbar() || area->VerticalScrollbar() ||
        area->Resizer()) {
      return true;
    }
  }
  return false;
}

static bool IsInLocalSubframe(const LayoutObject& object) {
  const auto* parent_frame = object.GetFrame()->Tree().Parent();
  return parent_frame && parent_frame->IsLocalFrame();
}

static bool NeedsIsolationNodes(const LayoutObject& object) {
  if (!object.HasLayer())
    return false;

  // Paint containment establishes isolation.
  // Style & Layout containment also establish isolation.
  if (object.ShouldApplyPaintContainment() ||
      (object.ShouldApplyStyleContainment() &&
       object.ShouldApplyLayoutContainment())) {
    return true;
  }

  // Layout view establishes isolation with the exception of local roots (since
  // they are already essentially isolated).
  if (object.IsLayoutView() && IsInLocalSubframe(object)) {
    return true;
  }

  return false;
}

static bool NeedsStickyTranslation(const LayoutObject& object) {
  if (!object.IsBoxModelObject())
    return false;

  return To<LayoutBoxModelObject>(object).StickyConstraints();
}

static bool NeedsAnchorPositionScrollTranslation(const LayoutObject& object) {
  if (const LayoutBox* box = DynamicTo<LayoutBox>(object))
    return box->NeedsAnchorPositionScrollAdjustment();
  return false;
}

static bool NeedsPaintOffsetTranslation(
    const LayoutObject& object,
    CompositingReasons direct_compositing_reasons,
    const LayoutObject* container_for_fixed_position,
    const PaintLayer* painting_layer) {
  if (!object.IsBoxModelObject())
    return false;

  // An SVG children inherits no paint offset, because there is no such concept
  // within SVG. Though <foreignObject> can have its own paint offset due to the
  // x and y parameters of the element, which affects the offset of painting of
  // the <foreignObject> element and its children, it still behaves like other
  // SVG elements, in that the x and y offset is applied *after* any transform,
  // instead of before.
  if (object.IsSVGChild())
    return false;

  const auto& box_model = To<LayoutBoxModelObject>(object);

  if (IsA<LayoutView>(box_model)) {
    // A translation node for LayoutView is always created to ensure fixed and
    // absolute contexts use the correct transform space.
    return true;
  }

  if (NeedsIsolationNodes(box_model)) {
    DCHECK(box_model.HasLayer());
    return true;
  }

  if (box_model.HasTransform())
    return true;
  if (NeedsScrollAndScrollTranslation(object, direct_compositing_reasons)) {
    return true;
  }
  if (NeedsStickyTranslation(object))
    return true;
  if (NeedsAnchorPositionScrollTranslation(object)) {
    return true;
  }
  if (NeedsPaintOffsetTranslationForOverflowControls(box_model))
    return true;
  if (NeedsReplacedContentTransform(object))
    return true;

  // Reference filter and reflection (which creates a reference filter) requires
  // zero paint offset.
  if (box_model.HasLayer() &&
      (object.StyleRef().Filter().HasReferenceFilter() ||
       object.HasReflection()))
    return true;

  if (auto* box = DynamicTo<LayoutBox>(box_model)) {
    if (box->IsFixedToView(container_for_fixed_position))
      return true;
  }

  // Though we don't treat hidden backface as a direct compositing reason, it's
  // very likely that the object will be composited, so a paint offset
  // translation will be beneficial.
  bool has_paint_offset_compositing_reason =
      direct_compositing_reasons != CompositingReason::kNone ||
      box_model.StyleRef().BackfaceVisibility() == EBackfaceVisibility::kHidden;
  if (has_paint_offset_compositing_reason) {
    // Don't let paint offset cross composited layer boundaries when possible,
    // to avoid unnecessary full layer paint/raster invalidation when paint
    // offset in ancestor transform node changes which should not affect the
    // descendants of the composited layer. For now because of
    // crbug.com/780242, this is limited to LayoutBlocks and LayoutReplaceds
    // that won't be escaped by floating objects and column spans when finding
    // their containing blocks. TODO(crbug.com/780242): This can be avoided if
    // we have fully correct paint property tree states for floating objects
    // and column spans.
    if (box_model.IsLayoutBlock() || object.IsLayoutReplaced() ||
        (direct_compositing_reasons &
         CompositingReason::kViewTransitionElement) ||
        (direct_compositing_reasons & CompositingReason::kElementCapture)) {
      return true;
    }
  }

  return false;
}

bool FragmentPaintPropertyTreeBuilder::CanPropagateSubpixelAccumulation()
    const {
  if (!object_.HasLayer())
    return true;

  if (full_context_.direct_compositing_reasons &
      CompositingReason::kPreventingSubpixelAccumulationReasons) {
    return false;
  }
  if (full_context_.direct_compositing_reasons &
      (CompositingReason::kActiveTransformAnimation |
       CompositingReason::kActiveRotateAnimation |
       CompositingReason::kActiveScaleAnimation)) {
    if (const auto* element = DynamicTo<Element>(object_.GetNode())) {
      DCHECK(element->GetElementAnimations());
      return element->GetElementAnimations()->IsIdentityOrTranslation();
    }
    return false;
  }

  const PaintLayer* layer = To<LayoutBoxModelObject>(object_).Layer();
  return !layer->Transform() || layer->Transform()->IsIdentityOrTranslation();
}

void FragmentPaintPropertyTreeBuilder::UpdateForPaintOffsetTranslation(
    std::optional<gfx::Vector2d>& paint_offset_translation) {
  if (!NeedsPaintOffsetTranslation(object_,
                                   full_context_.direct_compositing_reasons,
                                   full_context_.container_for_fixed_position,
                                   full_context_.painting_layer)) {
    return;
  }

  // We should use the same subpixel paint offset values for snapping regardless
  // of paint offset translation. If we create a paint offset translation we
  // round the paint offset but keep around the residual fractional component
  // (i.e. subpixel accumulation) for the transformed content to paint with.
  paint_offset_translation = ToRoundedVector2d(context_.current.paint_offset);
  // Don't propagate subpixel accumulation through paint isolation.
  if (NeedsIsolationNodes(object_)) {
    ResetPaintOffset();
    context_.current.directly_composited_container_paint_offset_subpixel_delta =
        PhysicalOffset();
    return;
  }

  PhysicalOffset subpixel_accumulation =
      context_.current.paint_offset - PhysicalOffset(*paint_offset_translation);
  if (!subpixel_accumulation.IsZero() ||
      !context_.current
           .directly_composited_container_paint_offset_subpixel_delta
           .IsZero()) {
    // If the object has a non-translation transform, discard the fractional
    // paint offset which can't be transformed by the transform.
    if (!CanPropagateSubpixelAccumulation()) {
      ResetPaintOffset();
      context_.current
          .directly_composited_container_paint_offset_subpixel_delta =
          PhysicalOffset();
      return;
    }
  }

  ResetPaintOffset(subpixel_accumulation);

  if (full_context_.direct_compositing_reasons == CompositingReason::kNone)
    return;

  if (paint_offset_translation && properties_ &&
      properties_->PaintOffsetTranslation()) {
    // The composited subpixel movement optimization applies only if the
    // composited layer has and had PaintOffsetTranslation, so that both the
    // the old and new paint offsets are just subpixel accumulations.
    DCHECK_EQ(gfx::Point(), ToRoundedPoint(fragment_data_.PaintOffset()));
    context_.current.directly_composited_container_paint_offset_subpixel_delta =
        context_.current.paint_offset - fragment_data_.PaintOffset();
  } else {
    // Otherwise disable the optimization.
    context_.current.directly_composited_container_paint_offset_subpixel_delta =
        PhysicalOffset();
  }
}

void FragmentPaintPropertyTreeBuilder::UpdatePaintOffsetTranslation(
    const std::optional<gfx::Vector2d>& paint_offset_translation) {
  DCHECK(properties_);

  if (paint_offset_translation) {
    TransformPaintPropertyNode::State state{
        {gfx::Transform::MakeTranslation(*paint_offset_translation)}};
    state.flattens_inherited_transform =
        context_.should_flatten_inherited_transform;
    state.rendering_context_id = context_.rendering_context_id;
    state.direct_compositing_reasons =
        full_context_.direct_compositing_reasons &
        CompositingReason::kDirectReasonsForPaintOffsetTranslationProperty;
    if (auto* box = DynamicTo<LayoutBox>(object_)) {
      if (box->IsFixedToView(full_context_.container_for_fixed_position) &&
          object_.View()->FirstFragment().PaintProperties()->Scroll()) {
        state.scroll_translation_for_fixed = object_.View()
                                                 ->FirstFragment()
                                                 .PaintProperties()
                                                 ->ScrollTranslation();
      }
    }

    if (IsA<LayoutView>(object_)) {
      DCHECK(object_.GetFrame());
      state.is_frame_paint_offset_translation = true;
      state.visible_frame_element_id =
          object_.GetFrame()->GetVisibleToHitTesting()
              ? CompositorElementIdFromUniqueObjectId(
                    object_.GetDocument().GetDomNodeId(),
                    CompositorElementIdNamespace::kDOMNodeId)
              : cc::ElementId();
    }
    OnUpdateTransform(properties_->UpdatePaintOffsetTranslation(
        *context_.current.transform, std::move(state)));
    context_.current.transform = properties_->PaintOffsetTranslation();
    if (IsA<LayoutView>(object_)) {
      context_.absolute_position.transform =
          properties_->PaintOffsetTranslation();
      context_.fixed_position.transform = properties_->PaintOffsetTranslation();
    }

    if (!object_.ShouldAssumePaintOffsetTranslationForLayoutShiftTracking()) {
      context_.current.additional_offset_to_layout_shift_root_delta +=
          PhysicalOffset(*paint_offset_translation);
    }
  } else {
    OnClearTransform(properties_->ClearPaintOffsetTranslation());
  }
}

void FragmentPaintPropertyTreeBuilder::UpdateStickyTranslation() {
  DCHECK(properties_);

  if (NeedsPaintPropertyUpdate()) {
    if (NeedsStickyTranslation(object_)) {
      const auto& box_model = To<LayoutBoxModelObject>(object_);
      TransformPaintPropertyNode::State state{{gfx::Transform::MakeTranslation(
          gfx::Vector2dF(box_model.StickyPositionOffset()))}};
      state.direct_compositing_reasons =
          full_context_.direct_compositing_reasons &
          CompositingReason::kStickyPosition;
      // TODO(wangxianzhu): Not using GetCompositorElementId() here because
      // sticky elements don't work properly under multicol for now, to keep
      // consistency with CompositorElementIdFromUniqueObjectId() below.
      // This will be fixed by LayoutNG block fragments.
      state.compositor_element_id = CompositorElementIdFromUniqueObjectId(
          box_model.UniqueId(),
          CompositorElementIdNamespace::kStickyTranslation);
      state.rendering_context_id = context_.rendering_context_id;
      state.flattens_inherited_transform =
          context_.should_flatten_inherited_transform;

      if (state.direct_compositing_reasons) {
        const auto* layout_constraint = box_model.StickyConstraints();
        DCHECK(layout_constraint);
        const auto* scroll_container_properties =
            layout_constraint->containing_scroll_container_layer
                ->GetLayoutObject()
                .FirstFragment()
                .PaintProperties();
        // A scroll node is created conditionally (see
        // NeedsScrollAndScrollTranslation), while sticky position attaches to
        // anything that clips overflow. No need to (actually can't) setup
        // composited sticky constraint if the clipping ancestor we attach to
        // doesn't have a scroll node.
        bool scroll_container_scrolls =
            scroll_container_properties &&
            scroll_container_properties->Scroll() == context_.c
```