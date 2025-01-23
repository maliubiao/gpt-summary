Response:
The user wants to understand the functionality of the provided C++ source code file `pre_paint_tree_walk.cc` from the Chromium Blink rendering engine. They are particularly interested in:

1. **General Functionality:** What does this code do?
2. **Relation to Web Technologies:** How does it interact with JavaScript, HTML, and CSS?
3. **Logical Reasoning:** Can I infer inputs and outputs of specific code sections?
4. **Common Errors:** What mistakes do developers or users make that relate to this code?
5. **User Actions and Debugging:** How do user interactions lead to this code being executed, and how can it be used for debugging?
6. **Summary:** A concise overview of the file's purpose.

Since this is part 1 of 2, the focus should be on summarizing the core functionality presented in this snippet.

**Plan:**

1. **Analyze the Includes:** Identify the key Blink components involved based on the included header files. This will give clues about the file's domain.
2. **Examine the `WalkTree` Function:** This appears to be a central entry point, so understanding its steps is crucial.
3. **Examine the `Walk` Functions:** These are likely recursive traversal mechanisms.
4. **Focus on Core Concepts:** Pay attention to terms like "paint," "layout," "fragment," and "property tree," as they are central to rendering.
5. **Infer Functionality from Names:** The names of functions like `UpdateEffectiveAllowedTouchAction`, `InvalidatePaintForHitTesting`, and `NeedsTreeBuilderContextUpdate` are indicative of their purpose.
6. **Connect to Web Technologies:**  Relate the identified functionalities to concepts in HTML, CSS, and JavaScript where possible.
7. **Formulate Examples:** Create hypothetical scenarios to illustrate how these functionalities might be triggered by web content or user interactions.
8. **Address Potential Errors:**  Consider common issues related to rendering, painting, and event handling.
9. **Structure the Response:** Organize the information clearly, addressing each of the user's requests.
```
这是目录为blink/renderer/core/paint/pre_paint_tree_walk.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

根据提供的代码片段，`blink/renderer/core/paint/pre_paint_tree_walk.cc` 文件的主要功能是 **在绘制之前遍历渲染树，执行一系列预备操作，为后续的绘制过程做准备和优化。**

以下是对其功能的详细分解：

**1. 核心功能：预绘制树遍历 (Pre-Paint Tree Walk)**

* **遍历渲染树:** 该文件中的 `PrePaintTreeWalk` 类负责遍历由 LayoutObjects 组成的渲染树。遍历从根 FrameView 开始，递归地访问所有可见的渲染对象。
* **收集信息和标记:**  在遍历过程中，它会收集与绘制相关的信息，并根据需要标记渲染对象，例如：
    * **标记需要更新绘制属性的对象:**  `NeedsPaintPropertyUpdate()`, `DescendantNeedsPaintPropertyUpdate()`, `ShouldCheckLayoutForPaintInvalidation()`, `DescendantShouldCheckLayoutForPaintInvalidation()` 等方法表明了对象或其后代需要更新绘制相关的属性。
    * **处理触摸事件和滚轮事件:** 检查是否存在阻止触摸或滚轮事件的处理器 (`HasBlockingTouchEventHandler()`, `HasBlockingWheelEventHandler()`)，并更新对象内部的状态 (`UpdateEffectiveAllowedTouchAction()`, `UpdateBlockingWheelEventHandler()`).
    * **处理命中测试:** 标记需要为命中测试更新绘制的对象 (`ShouldInvalidatePaintForHitTestOnly()`).
    * **管理分片 (Fragmentation):** 处理内容在分页、多列布局等场景下的分片情况。
* **执行副作用受限的操作:**  通过 `PrePaintDisableSideEffectsScope` 确保在某些特定的上下文中执行的操作不会产生不希望有的副作用。
* **管理 FragmentData:**  负责管理和更新与 LayoutObject 相关的 `FragmentData`，这些数据描述了对象在分片环境中的信息。
* **触发绘制失效:** 当检测到需要重新绘制时，会通过 `paint_invalidator_` 对象触发绘制失效 (`InvalidatePaint()`).
* **更新 Property Trees:**  如果需要，会使用 `PaintPropertyTreeBuilder` 更新绘制属性树 (Paint Property Trees)，例如变换树 (Transform Tree)、裁剪树 (Clip Tree)、效果树 (Effect Tree) 等。

**2. 与 JavaScript, HTML, CSS 的关系**

这个文件处于 Blink 渲染引擎的核心位置，直接负责将 HTML、CSS 的样式规则和 JavaScript 的动态修改转化为最终的视觉呈现。

* **HTML:**  `PrePaintTreeWalk` 遍历的渲染树是由 HTML 结构构建的。HTML 元素的类型和属性会影响 LayoutObject 的创建和属性。例如，`<div>` 元素会创建 `LayoutBlock` 对象，`<span>` 会创建 `LayoutInline` 对象。
* **CSS:** CSS 样式规则决定了 LayoutObject 的各种绘制属性，例如颜色、大小、位置、边框、背景等。`PrePaintTreeWalk` 会检查这些样式是否需要更新，例如，当 CSS 属性发生变化时，需要重新计算绘制属性。
    * **例子:** 如果 CSS 中一个元素的 `opacity` 属性被修改，`PrePaintTreeWalk` 可能会标记该元素需要更新效果树 (Effect Tree)。
    * **例子:** 如果 CSS 中一个元素的 `transform` 属性被修改，`PrePaintTreeWalk` 可能会标记该元素需要更新变换树 (Transform Tree)。
* **JavaScript:** JavaScript 可以动态修改 DOM 结构和 CSS 样式。这些修改会触发布局 (Layout) 和绘制 (Paint)。`PrePaintTreeWalk` 在绘制之前执行，能够感知到这些由 JavaScript 引起的修改，并进行相应的处理。
    * **例子:** 当 JavaScript 通过 `element.style.display = 'none'` 隐藏一个元素时，`PrePaintTreeWalk` 在遍历时会识别到该元素不再需要绘制。
    * **例子:** 当 JavaScript 通过 `element.classList.add('active')` 添加一个 CSS 类，并且该类定义了新的样式时，`PrePaintTreeWalk` 会标记相关的 LayoutObject 需要更新绘制属性。

**3. 逻辑推理：假设输入与输出**

* **假设输入:** 一个 HTML 页面加载完成，并且一些 CSS 样式已经应用，渲染树已经构建完成。页面上有一个带有 `onclick` 事件的按钮，并且定义了一些 CSS 动画。
* **操作:** 用户点击了该按钮。
* **中间过程:**
    * JavaScript 的 `onclick` 事件处理器被触发。
    * 假设事件处理器修改了按钮的样式（例如，改变了背景颜色）或者触发了一个 CSS 动画。
    * 这会触发 Blink 引擎的重绘流程。
    * 在绘制之前，`PrePaintTreeWalk::WalkTree` 会被调用。
* **`PrePaintTreeWalk` 的内部逻辑 (部分推断):**
    * `WalkTree` 会遍历渲染树，从根 FrameView 开始。
    * 当遍历到按钮对应的 LayoutObject 时，会检查其样式是否发生了变化。
    * 由于 JavaScript 修改了样式，或者 CSS 动画正在进行，`PrePaintTreeWalk` 可能会标记该按钮的 LayoutObject 需要更新绘制属性。
    * 如果涉及到 CSS 动画，可能还会检查相关的变换树或效果树。
    * `paint_invalidator_` 对象会被用来标记需要重绘的区域。
* **假设输出:** `PrePaintTreeWalk` 完成后，渲染树中的某些 LayoutObject 被标记为需要更新绘制信息或需要重绘。这些标记将作为后续绘制过程的输入，指导 Blink 如何高效地进行绘制。

**4. 用户或编程常见的使用错误**

* **频繁的样式修改导致不必要的重绘:**  JavaScript 代码如果过于频繁地修改元素的样式，即使是很小的改动，也会导致 `PrePaintTreeWalk` 和后续的绘制过程被多次触发，影响性能。
    * **例子:** 在 `mousemove` 事件中不断地修改元素的 `left` 和 `top` 属性，而不是使用 `transform`，会导致浏览器不断地进行布局和绘制。
* **不必要的强制同步布局 (Forced Synchronous Layout):**  在 JavaScript 中，如果先读取某些布局信息（例如 `offsetWidth`, `offsetHeight`），然后立即修改样式，浏览器可能会被迫执行同步布局，这会阻塞渲染流水线。`PrePaintTreeWalk` 会在绘制之前执行，如果之前的布局不正确，可能会导致预绘制过程的额外计算。
    * **例子:**
    ```javascript
    const width = element.offsetWidth; // 读取布局信息
    element.style.width = '200px';    // 修改样式
    ```
* **CSS 属性使用不当导致性能问题:** 某些 CSS 属性（例如复杂的 `filter` 或 `clip-path`）可能需要更多的计算资源来进行绘制。`PrePaintTreeWalk` 会参与到这些属性的计算准备工作中。

**5. 用户操作如何一步步到达这里 (调试线索)**

1. **用户发起操作:** 用户与网页进行交互，例如：
    * **页面加载:** 当用户首次访问一个网页时。
    * **滚动页面:** 滚动事件可能触发新的内容进入视口，需要重新绘制。
    * **鼠标悬停/点击:** 鼠标事件可能触发元素的样式变化 (例如 `:hover` 伪类)。
    * **输入文本:** 在表单字段中输入文本可能导致元素尺寸变化或内容更新。
    * **触发 JavaScript 动画/过渡:**  用户的操作或定时器触发 JavaScript 代码，进而启动 CSS 动画或过渡。
2. **事件触发:** 用户的操作触发相应的事件（例如 `scroll`, `mousemove`, `click`）。
3. **事件处理:**
    * 浏览器内部的事件处理机制捕获这些事件。
    * 如果事件导致 DOM 结构或样式发生变化，Blink 引擎会标记需要进行布局或绘制。
4. **进入绘制流程:**  当浏览器决定需要更新屏幕时，会启动绘制流程。
5. **PrePaintTreeWalk 执行:** 在真正的绘制之前，`PrePaintTreeWalk::WalkTree` 函数会被调用，开始遍历渲染树，执行预备操作。

**调试线索:**

* **断点调试:** 在 `pre_paint_tree_walk.cc` 相关的函数中设置断点，例如 `WalkTree`, `Walk`, `InvalidatePaint` 等，可以观察代码的执行流程和相关变量的值。
* **Performance 面板:** 使用 Chrome 开发者工具的 Performance 面板，可以记录页面的性能，查看 "Paint" 活动，了解绘制发生的频率和耗时。这可以帮助判断是否发生了不必要的重绘。
* **Layers 面板:**  使用 Chrome 开发者工具的 Layers 面板，可以查看页面的分层情况，了解哪些元素被提升为合成层。这与绘制性能密切相关。
* **`chrome://tracing`:**  可以使用 Chromium 的 tracing 工具 (`chrome://tracing`) 记录更底层的渲染事件，包括 `PrePaintTreeWalk` 的执行情况。

**6. 功能归纳 (第 1 部分)**

这部分代码的主要功能是实现了 **预绘制树遍历** 的核心逻辑。它负责在正式绘制之前，系统地检查和标记渲染树中的元素，为后续的绘制过程收集必要的信息，并进行初步的优化。这包括识别需要更新绘制属性的对象，处理与事件相关的状态，管理分片信息，以及触发绘制失效。 它的目的是确保在实际绘制发生时，能够以高效和正确的方式进行渲染。
```
### 提示词
```
这是目录为blink/renderer/core/paint/pre_paint_tree_walk.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/pre_paint_tree_walk.h"

#include "base/types/optional_util.h"
#include "third_party/blink/renderer/core/dom/document_lifecycle.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/pagination_state.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_controller.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_flow_thread.h"
#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/pagination_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/link_highlight.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/clip_path_clipper.h"
#include "third_party/blink/renderer/core/paint/object_paint_invalidator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_property_tree_printer.h"
#include "third_party/blink/renderer/core/paint/pre_paint_disable_side_effects_scope.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {

bool IsLinkHighlighted(const LayoutObject& object) {
  return object.GetFrame()->GetPage()->GetLinkHighlight().IsHighlighting(
      object);
}

}  // anonymous namespace

bool PrePaintTreeWalk::ContainingFragment::IsInFragmentationContext() const {
  return fragment && fragment->IsFragmentainerBox();
}

void PrePaintTreeWalk::WalkTree(LocalFrameView& root_frame_view) {
  if (root_frame_view.ShouldThrottleRendering()) {
    // Skip the throttled frame. Will update it when it becomes unthrottled.
    return;
  }

  DCHECK_EQ(root_frame_view.GetFrame().GetDocument()->Lifecycle().GetState(),
            DocumentLifecycle::kInPrePaint);

  PrePaintTreeWalkContext context;

#if DCHECK_IS_ON()
  bool needed_tree_builder_context_update =
      NeedsTreeBuilderContextUpdate(root_frame_view, context);
#endif

  VisualViewport& visual_viewport =
      root_frame_view.GetPage()->GetVisualViewport();
  if (visual_viewport.IsActiveViewport() &&
      root_frame_view.GetFrame().IsMainFrame()) {
    VisualViewportPaintPropertyTreeBuilder::Update(
        root_frame_view, visual_viewport, *context.tree_builder_context);
  }

  Walk(root_frame_view, context);
  paint_invalidator_.ProcessPendingDelayedPaintInvalidations();

  bool updates_executed = root_frame_view.ExecuteAllPendingUpdates();
  if (updates_executed) {
    needs_invalidate_chrome_client_and_intersection_ = true;
  }

#if DCHECK_IS_ON()
  if ((needed_tree_builder_context_update || updates_executed) &&
      VLOG_IS_ON(1)) {
    ShowAllPropertyTrees(root_frame_view);
  }
#endif

  // If the page has anything changed, we need to inform the chrome client
  // so that the client will initiate repaint of the contents if needed (e.g.
  // when this page is embedded as a non-composited content of another page).
  if (needs_invalidate_chrome_client_and_intersection_) {
    if (auto* client = root_frame_view.GetChromeClient()) {
      client->InvalidateContainer();
    }
    // If any change needs a more significant intersection update in a frame
    // view, we should have set the state on that frame view during the tree
    // walk or earlier.
    root_frame_view.SetIntersectionObservationState(
        LocalFrameView::kScrollAndVisibilityOnly);
  }
}

void PrePaintTreeWalk::Walk(LocalFrameView& frame_view,
                            const PrePaintTreeWalkContext& parent_context) {
  bool needs_tree_builder_context_update =
      NeedsTreeBuilderContextUpdate(frame_view, parent_context);

  if (frame_view.ShouldThrottleRendering()) {
    // Skip the throttled frame, and set dirty bits that will be applied when it
    // becomes unthrottled.
    if (LayoutView* layout_view = frame_view.GetLayoutView()) {
      if (needs_tree_builder_context_update) {
        layout_view->AddSubtreePaintPropertyUpdateReason(
            SubtreePaintPropertyUpdateReason::kPreviouslySkipped);
      }
      if (parent_context.paint_invalidator_context.NeedsSubtreeWalk())
        layout_view->SetSubtreeShouldDoFullPaintInvalidation();
      if (parent_context.effective_allowed_touch_action_changed)
        layout_view->MarkEffectiveAllowedTouchActionChanged();
      if (parent_context.blocking_wheel_event_handler_changed)
        layout_view->MarkBlockingWheelEventHandlerChanged();
    }
    return;
  }

  PrePaintTreeWalkContext context(parent_context,
                                  needs_tree_builder_context_update);

  // Block fragmentation doesn't cross frame boundaries.
  context.ResetFragmentation();

  if (context.tree_builder_context) {
    PaintPropertyTreeBuilder::SetupContextForFrame(
        frame_view, *context.tree_builder_context);
  }

  if (LayoutView* view = frame_view.GetLayoutView()) {
#if DCHECK_IS_ON()
    if (VLOG_IS_ON(3) && needs_tree_builder_context_update) {
      VLOG(3) << "PrePaintTreeWalk::Walk(frame_view=" << &frame_view
              << ")\nLayout tree:";
      ShowLayoutTree(view);
      VLOG(3) << "Fragment tree:";
      ShowFragmentTree(*view);
    }
#endif
    Walk(*view, context, /* pre_paint_info */ nullptr);
#if DCHECK_IS_ON()
    view->AssertSubtreeClearedPaintInvalidationFlags();
#endif
  }

  // Ensure the cached previous layout block in CaretDisplayItemClient is
  // invalidated and cleared even if the layout block is display locked.
  frame_view.GetFrame().Selection().EnsureInvalidationOfPreviousLayoutBlock();

  frame_view.GetLayoutShiftTracker().NotifyPrePaintFinished();
}

namespace {

enum class BlockingEventHandlerType {
  kNone,
  kTouchStartOrMoveBlockingEventHandler,
  kWheelBlockingEventHandler,
};

bool HasBlockingEventHandlerHelper(const LocalFrame& frame,
                                   EventTarget& target,
                                   BlockingEventHandlerType event_type) {
  if (!target.HasEventListeners())
    return false;
  const auto& registry = frame.GetEventHandlerRegistry();
  if (BlockingEventHandlerType::kTouchStartOrMoveBlockingEventHandler ==
      event_type) {
    const auto* blocking = registry.EventHandlerTargets(
        EventHandlerRegistry::kTouchStartOrMoveEventBlocking);
    const auto* blocking_low_latency = registry.EventHandlerTargets(
        EventHandlerRegistry::kTouchStartOrMoveEventBlockingLowLatency);
    return blocking->Contains(&target) ||
           blocking_low_latency->Contains(&target);
  } else if (BlockingEventHandlerType::kWheelBlockingEventHandler ==
             event_type) {
    const auto* blocking =
        registry.EventHandlerTargets(EventHandlerRegistry::kWheelEventBlocking);
    return blocking->Contains(&target);
  }
  NOTREACHED();
}

bool HasBlockingEventHandlerHelper(const LayoutObject& object,
                                   BlockingEventHandlerType event_type) {
  if (IsA<LayoutView>(object)) {
    auto* frame = object.GetFrame();
    if (HasBlockingEventHandlerHelper(*frame, *frame->DomWindow(), event_type))
      return true;
  }

  if (auto* node = object.GetNode()) {
    return HasBlockingEventHandlerHelper(*object.GetFrame(), *node, event_type);
  }

  return false;
}

bool HasBlockingTouchEventHandler(const LayoutObject& object) {
  return HasBlockingEventHandlerHelper(
      object, BlockingEventHandlerType::kTouchStartOrMoveBlockingEventHandler);
}

bool HasBlockingWheelEventHandler(const LayoutObject& object) {
  return HasBlockingEventHandlerHelper(
      object, BlockingEventHandlerType::kWheelBlockingEventHandler);
}
}  // namespace

void PrePaintTreeWalk::UpdateEffectiveAllowedTouchAction(
    const LayoutObject& object,
    PrePaintTreeWalk::PrePaintTreeWalkContext& context) {
  if (object.EffectiveAllowedTouchActionChanged())
    context.effective_allowed_touch_action_changed = true;

  if (context.effective_allowed_touch_action_changed) {
    object.GetMutableForPainting().UpdateInsideBlockingTouchEventHandler(
        context.inside_blocking_touch_event_handler ||
        HasBlockingTouchEventHandler(object));
  }

  if (object.InsideBlockingTouchEventHandler())
    context.inside_blocking_touch_event_handler = true;
}

void PrePaintTreeWalk::UpdateBlockingWheelEventHandler(
    const LayoutObject& object,
    PrePaintTreeWalk::PrePaintTreeWalkContext& context) {
  if (object.BlockingWheelEventHandlerChanged())
    context.blocking_wheel_event_handler_changed = true;

  if (context.blocking_wheel_event_handler_changed) {
    object.GetMutableForPainting().UpdateInsideBlockingWheelEventHandler(
        context.inside_blocking_wheel_event_handler ||
        HasBlockingWheelEventHandler(object));
  }

  if (object.InsideBlockingWheelEventHandler())
    context.inside_blocking_wheel_event_handler = true;
}

void PrePaintTreeWalk::InvalidatePaintForHitTesting(
    const LayoutObject& object,
    PrePaintTreeWalk::PrePaintTreeWalkContext& context) {
  if (context.paint_invalidator_context.subtree_flags &
      PaintInvalidatorContext::kSubtreeNoInvalidation)
    return;

  if (!context.effective_allowed_touch_action_changed &&
      !context.blocking_wheel_event_handler_changed &&
      !object.ShouldInvalidatePaintForHitTestOnly()) {
    return;
  }

  context.paint_invalidator_context.painting_layer->SetNeedsRepaint();
  // We record hit test data when the painting layer repaints. No need to
  // invalidate the display item client.
  if (!RuntimeEnabledFeatures::HitTestOpaquenessEnabled()) {
    ObjectPaintInvalidator(object).InvalidateDisplayItemClient(
        object, PaintInvalidationReason::kHitTest);
  }
}

bool PrePaintTreeWalk::NeedsTreeBuilderContextUpdate(
    const LocalFrameView& frame_view,
    const PrePaintTreeWalkContext& context) {
  if (frame_view.GetFrame().IsMainFrame() &&
      frame_view.GetPage()->GetVisualViewport().IsActiveViewport() &&
      frame_view.GetPage()->GetVisualViewport().NeedsPaintPropertyUpdate()) {
    return true;
  }

  return frame_view.GetLayoutView() &&
         NeedsTreeBuilderContextUpdate(*frame_view.GetLayoutView(), context);
}

bool PrePaintTreeWalk::NeedsTreeBuilderContextUpdate(
    const LayoutObject& object,
    const PrePaintTreeWalkContext& parent_context) {
  return ContextRequiresChildTreeBuilderContext(parent_context) ||
         ObjectRequiresTreeBuilderContext(object);
}

bool PrePaintTreeWalk::ObjectRequiresPrePaint(const LayoutObject& object) {
  return object.ShouldCheckForPaintInvalidation() ||
         object.EffectiveAllowedTouchActionChanged() ||
         object.DescendantEffectiveAllowedTouchActionChanged() ||
         object.BlockingWheelEventHandlerChanged() ||
         object.DescendantBlockingWheelEventHandlerChanged();
}

bool PrePaintTreeWalk::ContextRequiresChildPrePaint(
    const PrePaintTreeWalkContext& context) {
  return context.paint_invalidator_context.NeedsSubtreeWalk() ||
         context.effective_allowed_touch_action_changed ||
         context.blocking_wheel_event_handler_changed;
}

bool PrePaintTreeWalk::ObjectRequiresTreeBuilderContext(
    const LayoutObject& object) {
  return object.NeedsPaintPropertyUpdate() ||
         object.ShouldCheckLayoutForPaintInvalidation() ||
         (!object.ChildPrePaintBlockedByDisplayLock() &&
          (object.DescendantNeedsPaintPropertyUpdate() ||
           object.DescendantShouldCheckLayoutForPaintInvalidation()));
}

bool PrePaintTreeWalk::ContextRequiresChildTreeBuilderContext(
    const PrePaintTreeWalkContext& context) {
  if (!context.NeedsTreeBuilderContext()) {
    DCHECK(!context.tree_builder_context ||
           !context.tree_builder_context->force_subtree_update_reasons);
    DCHECK(!context.paint_invalidator_context.NeedsSubtreeWalk());
    return false;
  }
  return context.tree_builder_context->force_subtree_update_reasons ||
         // PaintInvalidator forced subtree walk implies geometry update.
         context.paint_invalidator_context.NeedsSubtreeWalk();
}

#if DCHECK_IS_ON()
void PrePaintTreeWalk::CheckTreeBuilderContextState(
    const LayoutObject& object,
    const PrePaintTreeWalkContext& parent_context) {
  if (parent_context.tree_builder_context ||
      (!ObjectRequiresTreeBuilderContext(object) &&
       !ContextRequiresChildTreeBuilderContext(parent_context))) {
    return;
  }

  DCHECK(!object.NeedsPaintPropertyUpdate());
  DCHECK(!object.DescendantNeedsPaintPropertyUpdate());
  DCHECK(!object.DescendantShouldCheckLayoutForPaintInvalidation());
  DCHECK(!object.ShouldCheckLayoutForPaintInvalidation());
  NOTREACHED() << "Unknown reason.";
}
#endif

PrePaintInfo PrePaintTreeWalk::CreatePrePaintInfo(
    const PhysicalFragmentLink& child,
    const PrePaintTreeWalkContext& context) {
  const auto* fragment = To<PhysicalBoxFragment>(child.fragment.Get());
  return PrePaintInfo(fragment, child.offset,
                      context.current_container.fragmentainer_idx,
                      fragment->IsFirstForNode(), !fragment->GetBreakToken(),
                      /* is_inside_fragment_child */ false,
                      context.current_container.IsInFragmentationContext());
}

FragmentData* PrePaintTreeWalk::GetOrCreateFragmentData(
    const LayoutObject& object,
    const PrePaintTreeWalkContext& context,
    const PrePaintInfo& pre_paint_info) {
  // If |allow_update| is set, we're allowed to add, remove and modify
  // FragmentData objects. Otherwise they will be left alone.
  bool allow_update = context.NeedsTreeBuilderContext();

  FragmentDataList& fragment_list =
      object.GetMutableForPainting().FragmentList();
  FragmentData* fragment_data = &fragment_list;

  // BR elements never fragment. While there are parts of the code that depend
  // on the correct paint offset (GetBoundingClientRect(), etc.), we don't need
  // to set fragmentation info (nor create multiple FragmentData entries). BR
  // elements aren't necessarily marked for invalidation when laid out (which
  // means that allow_update won't be set when it should, and the code below
  // would get confused).
  if (object.IsBR())
    return fragment_data;

  // The need for paint properties is the same across all fragments, so if the
  // first FragmentData needs it, so do all the others.
  bool needs_paint_properties = fragment_data->PaintProperties();

  wtf_size_t fragment_data_idx = 0;
  if (pre_paint_info.is_first_for_node) {
    if (const auto* layout_box = DynamicTo<LayoutBox>(&object)) {
      if (layout_box->PhysicalFragmentCount() != fragment_list.size()) {
        object.GetMutableForPainting().FragmentCountChanged();
      }
    }
  } else {
    if (pre_paint_info.is_inside_fragment_child) {
      if (!object.HasInlineFragments() && !IsLinkHighlighted(object)) {
        // We don't need any additional fragments for culled inlines - unless
        // this is the highlighted link (in which case even culled inlines get
        // paint effects).
        return nullptr;
      }

      const auto& parent_fragment = *pre_paint_info.box_fragment;
      // Find the start container fragment for this inline element, so that we
      // can figure out how far we've got, compared to that.
      InlineCursor cursor(
          *To<LayoutBlockFlow>(parent_fragment.GetLayoutObject()));
      cursor.MoveToIncludingCulledInline(object);
      DCHECK_GE(BoxFragmentIndex(parent_fragment),
                cursor.ContainerFragmentIndex());
      wtf_size_t parent_fragment_idx = BoxFragmentIndex(parent_fragment);

      const auto& container =
          *To<LayoutBlockFlow>(parent_fragment.GetLayoutObject());
      if (container.MayBeNonContiguousIfc()) {
        // The number of FragmentData entries must agree with the number of
        // fragments with items. Unfortunately, text and non-atomic inlines may
        // be "non-contiguous". This is for instance the case if there's a float
        // that takes up the entire fragmentainer somewhere in the middle (or at
        // the beginning, or at the end). Another example is during printing, if
        // monolithic content overflows and takes up the entire next page,
        // leaving no space for any line boxes that would otherwise be there.
        wtf_size_t walker_idx = cursor.ContainerFragmentIndex();
        bool found_in_parent = false;
        while (cursor.Current()) {
          cursor.MoveToNextForSameLayoutObject();
          wtf_size_t idx = cursor.ContainerFragmentIndex();
          if (walker_idx < idx) {
            // We've moved to the next fragmentainer where the object occurs.
            // Note that |idx| may have skipped fragmentainers here, if the
            // object isn't represented in some fragmentainer.
            if (idx > parent_fragment_idx) {
              // We've walked past the parent fragment.
              break;
            }
            fragment_data_idx++;
            walker_idx = idx;
          }
          if (idx == parent_fragment_idx) {
            found_in_parent = true;
            break;
          }
        }

        if (!found_in_parent) {
          return nullptr;
        }
      } else {
        // The inline formatting context is contiguous.
        fragment_data_idx =
            parent_fragment_idx - cursor.ContainerFragmentIndex();
      }
    } else {
      // Box fragments are always contiguous, i.e. fragmentainers are never
      // skipped.
      fragment_data_idx = BoxFragmentIndex(*pre_paint_info.box_fragment);
    }

    if (fragment_data_idx < fragment_list.size()) {
      fragment_data = &fragment_list.at(fragment_data_idx);
    } else {
      DCHECK(allow_update);
      fragment_data = &fragment_list.AppendNewFragment();
      DCHECK_EQ(fragment_data_idx + 1, fragment_list.size());

      // When we add FragmentData entries, we need to make sure that we update
      // paint properties. The object may not have been marked for an update, if
      // the reason for creating an additional FragmentData was that the
      // fragmentainer block-size shrunk, for instance.
      object.GetMutableForPainting().SetOnlyThisNeedsPaintPropertyUpdate();
    }
  }

  if (pre_paint_info.is_last_for_node) {
    // We have reached the end. There may be more data entries that were
    // needed in the previous layout, but not any more. Clear them.
    if (allow_update) {
      fragment_list.Shrink(fragment_data_idx + 1);
    } else {
      DCHECK_EQ(fragment_data_idx + 1, fragment_list.size());
    }
  }

  if (allow_update) {
    fragment_data->SetFragmentID(pre_paint_info.fragmentainer_idx);
    if (needs_paint_properties)
      fragment_data->EnsurePaintProperties();
  } else {
    DCHECK_EQ(fragment_data->FragmentID(), pre_paint_info.fragmentainer_idx);
    DCHECK(!needs_paint_properties || fragment_data->PaintProperties());
  }

  return fragment_data;
}

void PrePaintTreeWalk::UpdateContextForOOFContainer(
    const LayoutObject& object,
    PrePaintTreeWalkContext& context,
    const PhysicalBoxFragment* fragment) {
  // Flow threads don't exist, as far as LayoutNG is concerned. Yet, we
  // encounter them here when performing an NG fragment accompanied LayoutObject
  // subtree walk. Just ignore.
  if (object.IsLayoutFlowThread())
    return;

  // If we're in a fragmentation context, the parent fragment of OOFs is the
  // fragmentainer, unless the object is monolithic, in which case nothing
  // contained by the object participates in the current block fragmentation
  // context. If we're not participating in block fragmentation, the containing
  // fragment of an OOF fragment is always simply the parent.
  if (!context.current_container.IsInFragmentationContext() ||
      (fragment && fragment->IsMonolithic())) {
    // Anonymous blocks are not allowed to be containing blocks, so we should
    // skip over any such elements.
    if (!fragment || !fragment->IsAnonymousBlock()) {
      context.current_container.fragment = fragment;
    }
  }

  if (!object.CanContainAbsolutePositionObjects())
    return;

  // The OOF containing block structure is special under block fragmentation: A
  // fragmentable OOF is always a direct child of a fragmentainer.
  context.absolute_positioned_container = context.current_container;
  if (object.CanContainFixedPositionObjects())
    context.fixed_positioned_container = context.absolute_positioned_container;
}

void PrePaintTreeWalk::WalkInternal(const LayoutObject& object,
                                    PrePaintTreeWalkContext& context,
                                    PrePaintInfo* pre_paint_info) {
  PaintInvalidatorContext& paint_invalidator_context =
      context.paint_invalidator_context;

  if (pre_paint_info) {
    DCHECK(!pre_paint_info->fragment_data);
    // Find, update or create a FragmentData object to match the current block
    // fragment.
    //
    // TODO(mstensho): If this is collapsed text or a culled inline, we might
    // not have any work to do (we could just return early here), as there'll be
    // no need for paint property updates or invalidation. However, this is a
    // bit tricky to determine, because of things like LinkHighlight, which
    // might set paint properties on a culled inline.
    pre_paint_info->fragment_data =
        GetOrCreateFragmentData(object, context, *pre_paint_info);
    if (!pre_paint_info->fragment_data)
      return;
  } else if (object.IsFragmentLessBox()) {
    return;
  }

  std::optional<PaintPropertyTreeBuilder> property_tree_builder;
  if (context.tree_builder_context) {
    property_tree_builder.emplace(object, pre_paint_info,
                                  *context.tree_builder_context);
    property_tree_builder->UpdateForSelf();
  }

  // This must happen before paint invalidation because background painting
  // depends on the effective allowed touch action and blocking wheel event
  // handlers.
  UpdateEffectiveAllowedTouchAction(object, context);
  UpdateBlockingWheelEventHandler(object, context);

  if (paint_invalidator_.InvalidatePaint(
          object, pre_paint_info,
          base::OptionalToPtr(context.tree_builder_context),
          paint_invalidator_context)) {
    needs_invalidate_chrome_client_and_intersection_ = true;
  }

  InvalidatePaintForHitTesting(object, context);

  if (context.tree_builder_context) {
    property_tree_builder->UpdateForChildren();
    property_tree_builder->IssueInvalidationsAfterUpdate();
    needs_invalidate_chrome_client_and_intersection_ |=
        property_tree_builder->PropertiesChanged();
  }
}

bool PrePaintTreeWalk::CollectMissableChildren(
    PrePaintTreeWalkContext& context,
    const PhysicalBoxFragment& parent) {
  bool has_missable_children = false;
  for (const PhysicalFragmentLink& child : parent.Children()) {
    if (child->IsLayoutObjectDestroyedOrMoved()) [[unlikely]] {
      continue;
    }
    if (child->IsOutOfFlowPositioned() &&
        (context.current_container.fragment || child->IsFixedPositioned())) {
      // Add all out-of-flow positioned fragments inside a fragmentation
      // context. If a fragment is fixed-positioned, we even need to add those
      // that aren't inside a fragmentation context, because they may have an
      // ancestor LayoutObject inside one, and one of those ancestors may be
      // out-of-flow positioned, which may be missed, in which case we'll miss
      // this fixed-positioned one as well (since we don't enter descendant OOFs
      // when walking missed children) (example: fixedpos inside missed abspos
      // in relpos in multicol).
      pending_missables_.insert(child.fragment);
      has_missable_children = true;
    }
  }
  return has_missable_children;
}

const PhysicalBoxFragment* PrePaintTreeWalk::RebuildContextForMissedDescendant(
    const PhysicalBoxFragment& ancestor,
    const LayoutObject& object,
    bool update_tree_builder_context,
    PrePaintTreeWalkContext& context) {
  // Walk up to the ancestor and, on the way down again, adjust the context with
  // info about OOF containing blocks.
  if (&object == ancestor.OwnerLayoutBox()) {
    return &ancestor;
  }
  const PhysicalBoxFragment* search_fragment =
      RebuildContextForMissedDescendant(ancestor, *object.Parent(),
                                        update_tree_builder_context, context);

  if (object.IsLayoutFlowThread()) {
    // A flow threads doesn't create fragments. Just ignore it.
    return search_fragment;
  }

  const PhysicalBoxFragment* box_fragment = nullptr;
  if (context.tree_builder_context && update_tree_builder_context) {
    PhysicalOffset paint_offset;
    wtf_size_t fragmentainer_idx = context.current_container.fragmentainer_idx;

    // TODO(mstensho): We're doing a simplified version of what
    // WalkLayoutObjectChildren() does. Consider refactoring so that we can
    // share.
    if (object.IsOutOfFlowPositioned()) {
      // The fragment tree follows the structure of containing blocks closely,
      // while here we're walking down the LayoutObject tree spine (which
      // follows the structure of the flat DOM tree, more or less). This means
      // that for out-of-flow positioned objects, the fragment of the parent
      // LayoutObject might not be the right place to search.
      const ContainingFragment& oof_containing_fragment_info =
          object.IsFixedPositioned() ? context.fixed_positioned_container
                                     : context.absolute_positioned_container;
      search_fragment = oof_containing_fragment_info.fragment;
      fragmentainer_idx = oof_containing_fragment_info.fragmentainer_idx;
    }
    // If we have a parent fragment to search inside, do that. If we find it, we
    // can use its paint offset and size in the paint property builder. If we
    // have no parent fragment, or don't find the child, we won't be passing a
    // fragment to the property builder, and then it needs to behave
    // accordingly, e.g. assume that the fragment is at the fragmentainer
    // origin, and has zero block-size.
    // See e.g. https://www.w3.org/TR/css-break-3/#transforms
    if (search_fragment) {
      for (PhysicalFragmentLink link : search_fragment->Children()) {
        if (link->GetLayoutObject() == object) {
          box_fragment = To<PhysicalBoxFragment>(link.get());
          paint_offset = link.offset;
          break;
        }
      }
    }

    // TODO(mstensho): Some of the bool parameters here are meaningless when
    // only used with PaintPropertyTreeBuilder (only used by
    // PrePaintTreeWalker). Consider cleaning this up, by splitting up
    // PrePaintInfo into one walker part and one builder part, so that we
    // don't have to specify them as false here.
    PrePaintInfo pre_paint_info(
        box_fragment, paint_offset, fragmentainer_idx,
        /* is_first_for_node */ false, /* is_last_for_node */ false,
        /* is_inside_fragment_child */ false,
        context.current_container.IsInFragmentationContext());

    // We're going to set up paint properties for the missing ancestors, and
    // update the context, but it should have no side-effects. That is, the
    // LayoutObject(s) should be left untouched. PaintPropertyTreeBuilder
    // normally calls LayoutObject::GetMutableForPainting() and does stuff, but
    // we need to avoid that in this case.
    PrePaintDisableSideEffectsScope leave_layout_object_alone_kthanksbye;

    // Also just create a dummy FragmentData object. We don't want any
    // side-effect, but the paint property tree builder requires a FragmentData
    // object to write stuff into.
    pre_paint_info.fragment_data = MakeGarbageCollected<FragmentData>();

    PaintPropertyTreeBuilderContext& builder_context =
        context.tree_builder_context.value();
    auto original_force_update = builder_context.force_subtree_update_reasons;
    // Since we're running without any old paint properties (since we're passing
    // a dummy FragmentData object), we need to recalculate all properties.
    builder_context.force_subtree_update_reasons |=
        PaintPropertyTreeBuilderContext::kSubtreeUpdateIsolationPiercing;

    PaintPropertyTreeBuilder property_tree_builder(object, &pre_paint_info,
                                                   builder_context);
    property_tree_builder.UpdateForSelf();
    property_tree_builder.UpdateForChildren();
    builder_context.force_subtree_update_reasons = original_force_update;
  }

  UpdateContextForOOFContainer(object, context, box_fragment);

  if (!object.CanContainAbsolutePositionObjects() ||
      !context.tree_builder_context) {
    return box_fragment;
  }

  PaintPropertyTreeBuilderContext& property_context =
      *context.tree_builder_context;
  PaintPropertyTreeBuilderFragmentContext& fragment_context =
      property_context.fragment_context;
  // Reset the relevant OOF context to this fragmentainer, since this is its
  // containing block, as far as the NG fragment structure is concerned.
  property_context.container_for_absolute_position = &object;
  fragment_context.absolute_position = fragment_context.current;
  if (object.CanContainFixedPositionObjects()) {
    property_context.container_for_fixed_position = &object;
    fragment_context.fixed_position = fragment_context.current;
  }

  return box_fragment;
}

void PrePaintTreeWalk::WalkMissedChildren(
    const PhysicalBoxFragment& fragment,
    bool is_in_fragment_traversal,
    const PrePaintTreeWalkContext& context) {
  if (pending_missables_.empty())
    return;

  // Missing fragments are assumed to be at the start block edge of the
  // fragmentainer. When generating fragments, layout sets their correct
  // block-offset (obviously), as a physical offset. But since we're just
  // pretending to have a fragment in this case, we have to do it ourselves. For
  // vertical-rl and sideways-rl, the block-start offset is at the right edge of
  // the fragmentainer, not at the left (vertical-lr) (which is zero), and not
  // at the top (horizontal-tb) (also zero). So we need to adjust for
  // vertical-rl and sideways-rl.
  PhysicalOffset offset_to_block_start_edge;
  if (fragment.IsFragmentainerBox() &&
      fragment.Style().IsFlippedBlocksWritingMode()) {
    offset_to_block_start_edge.left = fragment.Size().width;
  }

  for (const PhysicalFragmentLink& child : fragment.Children()) {
    if (child->IsLayoutObjectDestroyedOrMoved()) [[unlikely]] {
      continue;
    }
    if (!child->IsOutOfFlowPositioned()) {
      continue;
    }
    if (!pending_missables_.Contains(child.fragment))
      continue;
    const LayoutObject& descendant_object = *child->GetLayoutObject();
    PrePaintTreeWalkContext descendant_context(
        context, NeedsTreeBuilderContextUpdate(descendant_object, context));
    if (child->IsOutOfFlowPositioned()) {
      if (descendant_context.tree_builder_context.has_value()) {
        PaintPropertyTreeBuilderContext* builder_context =
            &descendant_context.tree_builder_context.value();
        builder_context->fragment_context.current.paint_offset +=
            offset_to_block_start_edge;
      }

      bool update_tree_builder_context =
          NeedsTreeBuilderContextUpdate(descendant_object, descendant_context);

      RebuildContextForMissedDescendant(fragment, *descendant_object.Parent(),
                                        update_tree_builder_context,
                                        descendant_context);
    }

    if (is_in_fragment_traversal) {
      PrePaintInfo pre_paint_info =
          CreatePrePaintInfo(child, descendant_context);
      Walk(descendant_object, descendant_context, &pre_paint_info);
    } else {
      Walk(descendant_object, d
```