Response:
Let's break down the thought process for analyzing the `DocumentAnimations.cc` file.

1. **Identify the Core Purpose:** The filename and the initial includes (`document_animations.h`) immediately suggest this file is central to managing animations within a document in the Blink rendering engine.

2. **Scan Included Headers:**  The included headers provide crucial context:
    * `cc/animation/animation_host.h` and `cc/animation/animation_timeline.h`: Indicate interaction with the Chromium Compositor for hardware-accelerated animations.
    * `third_party/blink/public/platform/platform.h`: Suggests platform-specific considerations.
    * `third_party/blink/renderer/core/animation/...`:  Confirms this file deals with core animation concepts within Blink.
    * `third_party/blink/renderer/core/css/style_engine.h`:  Points to the link between CSS styling and animations.
    * `third_party/blink/renderer/core/dom/document.h`, `element.h`:  Highlights the connection to the Document Object Model.
    * `third_party/blink/renderer/core/execution_context/agent.h`:  Implies interaction with the JavaScript execution environment.
    * `third_party/blink/renderer/core/frame/...`: Shows the context within a browser frame.
    * `third_party/blink/renderer/core/page/...`: Indicates higher-level page management involvement.

3. **Analyze the Class Definition:**  The `DocumentAnimations` class is the main entity. Its constructor takes a `Document*`, confirming its role as a per-document animation manager.

4. **Examine Public Methods (Signatures are Key):**  Go through the public methods and deduce their functionality:
    * `AddTimeline`:  Simple enough - adds an animation timeline.
    * `UpdateAnimationTimingForAnimationFrame`:  Clearly related to the browser's animation frame lifecycle.
    * `NeedsAnimationTimingUpdate`: Checks if updates are required.
    * `UpdateAnimationTimingIfNeeded`: Triggers updates conditionally.
    * `UpdateAnimations`: A more comprehensive update method, likely triggered by layout or paint.
    * `MarkPendingIfCompositorPropertyAnimationChanges`: Indicates handling of animations that affect compositor properties.
    * `GetAnimationsCount`: Returns the number of active animations.
    * `MarkAnimationsCompositorPending`: Marks animations for compositor processing.
    * `getAnimations`:  Returns a list of animations, suggesting an API for accessing them.
    * `DetachCompositorTimelines`:  Handles detaching from the compositor.

5. **Examine Private/Internal Methods and Logic:**
    * `UpdateAnimationTiming`:  A helper function to update timeline times.
    * `CompareAnimations`:  Used for sorting animations based on compositing order. This is important for proper application of animation effects.
    * `GetAnimationsTargetingTreeScope`:  Filters animations based on a DOM subtree.
    * `RemoveReplacedAnimations`:  Handles the logic for removing animations that are superseded by higher-priority ones (especially in CSS transitions/animations). This is a more complex area, so pay attention to the conditions for removal.

6. **Identify Connections to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `getAnimations` method directly corresponds to the JavaScript API. The microtask checkpointing suggests handling promises and asynchronous operations triggered by JavaScript animation manipulation.
    * **HTML:** The class operates on `Document` and `Element` objects, which are the building blocks of HTML. The concept of "TreeScope" is directly related to the DOM tree structure.
    * **CSS:** The reference to `KeyframeEffect`, the sorting of animations based on compositing order (influenced by CSS stacking contexts and animation properties), and the handling of replaced animations strongly link this to CSS animations and transitions.

7. **Infer Logical Relationships (Hypothetical Inputs and Outputs):**
    * **`UpdateAnimationTimingForAnimationFrame`:**  Input: Browser is ready to render the next frame. Output: Animation times are updated, replaced animations are removed, microtasks are processed.
    * **`RemoveReplacedAnimations`:** Input: A set of animations on the same element with potential overlaps. Output: Some animations are marked for removal based on priority and replaced properties.
    * **`getAnimations`:** Input: A `TreeScope`. Output: A sorted list of `Animation` objects active within that scope.

8. **Consider Potential User/Programming Errors:**
    * Incorrectly setting animation priorities in CSS, leading to unexpected replacement behavior.
    * Relying on the order of animation application without understanding compositing order.
    * Not understanding the timing of animation updates and microtasks, which can affect the order of event firing.
    * Manipulating animations directly in JavaScript without considering potential conflicts with CSS-defined animations.

9. **Structure the Explanation:** Organize the findings into logical categories: core functionality, relationships to web technologies, logical inferences, and potential errors. Use clear language and examples.

10. **Review and Refine:** Read through the explanation to ensure accuracy and clarity. Check for any missing connections or areas that could be explained better. For example, initially, I might not have explicitly mentioned the microtask checkpoint's purpose so clearly, but after reviewing, I'd realize its significance for promise resolution and add that detail.

This iterative process of examining the code, connecting it to known concepts, and inferring behavior allows for a comprehensive understanding of the `DocumentAnimations.cc` file's role in the Blink rendering engine.
这个文件 `blink/renderer/core/animation/document_animations.cc` 是 Chromium Blink 引擎中负责管理 **文档级别动画** 的核心组件。它的主要功能是：

**核心功能：**

1. **管理动画时间线 (Animation Timelines):**
   - 它维护着与当前文档关联的所有动画时间线 (`AnimationTimeline`) 的集合 (`timelines_`)。
   - 负责添加新的时间线 (`AddTimeline`)。
   - 能够遍历并操作这些时间线。

2. **驱动动画时间更新:**
   - 提供机制来更新文档中所有动画时间线的当前时间 (`UpdateAnimationTimingForAnimationFrame`, `UpdateAnimationTimingIfNeeded`, `UpdateAnimationTiming`)。
   - `UpdateAnimationTimingForAnimationFrame` 在每个浏览器动画帧（requestAnimationFrame）时被调用，以确保动画与渲染同步。
   - `UpdateAnimationTimingIfNeeded` 根据需要按需更新动画时间。
   - 这些更新会触发时间线上关联的动画效果的计算和更新。

3. **处理被替换的动画 (Replaced Animations):**
   - 实现了移除被更高优先级动画替换掉的动画的逻辑 (`RemoveReplacedAnimations`)。这对于 CSS 动画和过渡非常重要，确保只有最“有效”的动画在运行。

4. **与 Compositor 交互:**
   - 涉及到与 Chromium 的 Compositor 组件的交互，以实现硬件加速的动画。
   - `MarkPendingIfCompositorPropertyAnimationChanges` 标记那些影响 Compositor 属性的动画。
   - `MarkAnimationsCompositorPending` 标记动画为 Compositor 待处理。
   - `DetachCompositorTimelines` 在适当的时候分离 Compositor 动画时间线。

5. **提供访问文档中所有动画的接口:**
   - `getAnimations` 方法允许获取文档中所有正在运行的动画的列表。

6. **与文档生命周期管理集成:**
   - `UpdateAnimations` 方法在文档生命周期的不同阶段被调用，以更新动画状态。

7. **性能优化:**
   - 包含一些优化的逻辑，例如避免不必要的动画更新 (`NeedsAnimationTimingUpdate`).

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个文件是 Blink 引擎处理 Web 开发者通过 JavaScript, HTML, CSS 定义的动画的核心。

* **CSS 动画和过渡:**
    - **功能关系:** 当 CSS 动画或过渡被应用到一个元素时，Blink 会创建一个或多个 `Animation` 对象，并将它们关联到文档的某个 `AnimationTimeline` 上。 `DocumentAnimations` 负责驱动这些动画的执行。
    - **举例说明:**
      ```css
      .element {
        width: 100px;
        transition: width 1s ease-in-out;
      }
      .element:hover {
        width: 200px;
      }

      @keyframes slidein {
        from {
          margin-left: 100%;
          width: 300%;
        }
        to {
          margin-left: 0%;
          width: 100%;
        }
      }
      .element-animated {
        animation: slidein 2s infinite alternate;
      }
      ```
      当 `.element` 被 hover 时，或者 `.element-animated` 出现在文档中时，`DocumentAnimations` 会管理与之相关的过渡和动画。`RemoveReplacedAnimations` 会确保，如果一个元素同时应用了多个影响相同属性的动画或过渡，优先级更高的那个会生效。

* **JavaScript Web Animations API:**
    - **功能关系:**  `DocumentAnimations::getAnimations` 方法直接对应了 JavaScript 中的 `document.getAnimations()` 方法。通过这个 API，JavaScript 可以获取和控制文档中的所有动画。
    - **举例说明:**
      ```javascript
      const element = document.querySelector('.element-animated');
      const animations = document.getAnimations();
      console.log(animations); // 输出所有正在运行的动画

      const animation = element.animate([
        { opacity: 0 },
        { opacity: 1 }
      ], {
        duration: 1000,
        iterations: Infinity
      });
      ```
      当使用 JavaScript 的 `element.animate()` 方法创建动画时，`DocumentAnimations` 会管理这些动画的生命周期和时间更新。

* **HTML (DOM 结构):**
    - **功能关系:**  动画是应用到 DOM 元素上的。`DocumentAnimations` 需要知道哪些元素拥有哪些动画。`GetAnimationsTargetingTreeScope` 方法可以根据 DOM 树的范围获取动画。
    - **举例说明:**  HTML 结构决定了动画可能应用的目标元素。`DocumentAnimations` 能够识别特定 `TreeScope` (例如，整个文档或 Shadow DOM) 内的动画。

**逻辑推理及假设输入与输出:**

**假设输入:** 浏览器即将渲染一个新的动画帧。

**触发的方法:** `DocumentAnimations::UpdateAnimationTimingForAnimationFrame()`

**内部逻辑推理:**

1. **更新时间线:** 遍历 `timelines_` 中的所有 `AnimationTimeline` 对象，调用它们的 `ServiceAnimations` 方法，传入 `kTimingUpdateForAnimationFrame` 作为原因。这会更新每个时间线上的当前时间。
2. **移除被替换动画:**  收集所有可被替换的动画 (`timeline->getReplaceableAnimations(&replaceable_animations_map)`)。
3. **比较动画优先级:**  对于每个元素上可能被替换的动画集合，根据它们的优先级（由 CSS 和动画属性决定）进行排序 (`std::sort(animations->begin(), animations->end(), CompareAnimations)`)。
4. **确定被替换的动画:**  遍历排序后的动画，判断哪些动画的属性被更高优先级的动画覆盖。
5. **触发移除事件:**  对于被替换的动画，将其加入待移除的列表，并安排一个微任务来执行实际的移除操作 (`Animation::RemoveReplacedAnimation`).
6. **微任务检查点:** 执行微任务检查点 (`document_->GetAgent().event_loop()->PerformMicrotaskCheckpoint()`)，确保在生成下一帧之前处理完动画相关的 Promise 和回调。

**输出:**

- 所有动画时间线的当前时间已更新。
- 被更高优先级动画替换的动画已被标记为移除，并将在微任务中执行移除操作。
- 相关的 JavaScript Promise 得到解决或拒绝，并且回调函数被执行。

**用户或编程常见的使用错误举例说明:**

1. **忘记考虑动画的优先级和替换规则:**
   - **错误示例:**  开发者在一个元素上同时定义了两个 CSS 动画，都改变了 `opacity` 属性，但没有明确设置它们的优先级（例如，通过 `!important` 或动画定义的顺序）。
   - **结果:**  可能会出现动画冲突，实际效果不确定，或者只有其中一个动画生效，这取决于 Blink 引擎内部的优先级计算。开发者可能期望两个动画都运行，或者按照某种特定的混合方式运行，但实际并非如此。

2. **在 JavaScript 中频繁地创建和销毁动画对象:**
   - **错误示例:**  在循环或事件处理程序中，每次都使用 `element.animate()` 创建新的动画对象，而不复用或清理旧的动画。
   - **结果:**  会导致大量的 `Animation` 对象被创建，增加内存消耗和性能开销。`DocumentAnimations` 需要管理所有这些对象，频繁的创建和销毁会影响其效率。

3. **误解 `document.getAnimations()` 的返回值:**
   - **错误示例:**  开发者期望 `document.getAnimations()` 返回的动画列表是动态更新的，并在动画状态发生变化时立即反映出来。
   - **实际:**  虽然返回的列表会包含当前正在运行的动画，但对其进行修改（例如，直接修改动画的属性）通常不会直接影响动画的播放。应该使用动画对象自身的方法（如 `play()`, `pause()`, `cancel()`) 来控制动画。

4. **在不恰当的时机操作动画时间线:**
   - **错误示例:**  尝试在动画回调函数内部同步地修改同一个动画的时间线或属性，可能导致竞争条件或意外行为。
   - **推荐做法:**  动画的修改最好在浏览器的下一次渲染更新周期中进行，或者通过异步操作来避免冲突。

总而言之，`blink/renderer/core/animation/document_animations.cc` 是 Blink 引擎中一个至关重要的组件，它负责协调和管理文档中的各种动画，确保它们能够按照 Web 标准的定义正确、高效地运行，并与 JavaScript 和 Compositor 等其他组件协同工作。理解其功能有助于开发者更好地理解浏览器如何处理动画，并避免常见的编程错误。

Prompt: 
```
这是目录为blink/renderer/core/animation/document_animations.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

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

#include "third_party/blink/renderer/core/animation/document_animations.h"

#include <algorithm>

#include "cc/animation/animation_host.h"
#include "cc/animation/animation_timeline.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/animation/animation_clock.h"
#include "third_party/blink/renderer/core/animation/animation_timeline.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect.h"
#include "third_party/blink/renderer/core/animation/pending_animations.h"
#include "third_party/blink/renderer/core/animation/worklet_animation_controller.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"

namespace blink {

namespace {

void UpdateAnimationTiming(
    Document& document,
    HeapHashSet<WeakMember<AnimationTimeline>>& timelines,
    TimingUpdateReason reason) {
  for (auto& timeline : timelines)
    timeline->ServiceAnimations(reason);
  document.GetWorkletAnimationController().UpdateAnimationTimings(reason);
}

bool CompareAnimations(const Member<Animation>& left,
                       const Member<Animation>& right) {
  return Animation::HasLowerCompositeOrdering(
      left.Get(), right.Get(),
      Animation::CompareAnimationsOrdering::kTreeOrder);
}
}  // namespace

DocumentAnimations::DocumentAnimations(Document* document)
    : document_(document) {}

void DocumentAnimations::AddTimeline(AnimationTimeline& timeline) {
  timelines_.insert(&timeline);
}

void DocumentAnimations::UpdateAnimationTimingForAnimationFrame() {
  // https://w3.org/TR/web-animations-1/#timelines

  // 1. Update the current time of all timelines associated with doc passing now
  //    as the timestamp.
  UpdateAnimationTiming(*document_, timelines_, kTimingUpdateForAnimationFrame);

  // 2. Remove replaced animations for doc.
  ReplaceableAnimationsMap replaceable_animations_map;
  for (auto& timeline : timelines_)
    timeline->getReplaceableAnimations(&replaceable_animations_map);
  RemoveReplacedAnimations(&replaceable_animations_map);

  // 3. Perform a microtask checkpoint
  // This is to ensure that any microtasks queued up as a result of resolving or
  // rejecting Promise objects as part of updating timelines run their callbacks
  // prior to dispatching animation events and generating the next main frame.
  document_->GetAgent().event_loop()->PerformMicrotaskCheckpoint();
}

bool DocumentAnimations::NeedsAnimationTimingUpdate() {
  for (auto& timeline : timelines_) {
    if (timeline->HasOutdatedAnimation() ||
        timeline->NeedsAnimationTimingUpdate())
      return true;
  }
  return false;
}

void DocumentAnimations::UpdateAnimationTimingIfNeeded() {
  if (NeedsAnimationTimingUpdate())
    UpdateAnimationTiming(*document_, timelines_, kTimingUpdateOnDemand);
}

void DocumentAnimations::UpdateAnimations(
    DocumentLifecycle::LifecycleState required_lifecycle_state,
    const PaintArtifactCompositor* paint_artifact_compositor,
    bool compositor_properties_updated) {
  DCHECK(document_->Lifecycle().GetState() >= required_lifecycle_state);

  if (compositor_properties_updated)
    MarkPendingIfCompositorPropertyAnimationChanges(paint_artifact_compositor);

  if (document_->GetPendingAnimations().Update(paint_artifact_compositor)) {
    DCHECK(document_->View());
    document_->View()->ScheduleAnimation();
  }

  document_->GetWorkletAnimationController().UpdateAnimationStates();
  document_->GetFrame()->ScheduleNextServiceForScrollSnapshotClients();
  for (auto& timeline : timelines_) {
    // ScrollSnapshotTimelines are already handled as ScrollSnapshotClients
    // above.
    if (!timeline->IsScrollSnapshotTimeline()) {
      timeline->ScheduleNextService();
    }
  }
}

void DocumentAnimations::MarkPendingIfCompositorPropertyAnimationChanges(
    const PaintArtifactCompositor* paint_artifact_compositor) {
  for (auto& timeline : timelines_) {
    timeline->MarkPendingIfCompositorPropertyAnimationChanges(
        paint_artifact_compositor);
  }
}

size_t DocumentAnimations::GetAnimationsCount() {
  wtf_size_t total_animations_count = 0;
  if (document_->View()) {
    if (document_->View()->GetCompositorAnimationHost()) {
      for (auto& timeline : timelines_) {
        if (timeline->HasAnimations())
          total_animations_count += timeline->AnimationsNeedingUpdateCount();
      }
    }
  }
  return total_animations_count;
}

void DocumentAnimations::MarkAnimationsCompositorPending() {
  for (auto& timeline : timelines_)
    timeline->MarkAnimationsCompositorPending();
}

HeapVector<Member<Animation>> DocumentAnimations::getAnimations(
    const TreeScope& tree_scope) {
  // This method implements the Document::getAnimations method defined in the
  // web-animations-1 spec.
  // https://w3.org/TR/web-animations-1/#extensions-to-the-documentorshadowroot-interface-mixin
  document_->UpdateStyleAndLayoutTree();
  HeapVector<Member<Animation>> animations;
  if (document_->GetPage())
    animations = document_->GetPage()->Animator().GetAnimations(tree_scope);
  else
    GetAnimationsTargetingTreeScope(animations, tree_scope);

  std::sort(animations.begin(), animations.end(), CompareAnimations);
  return animations;
}

void DocumentAnimations::DetachCompositorTimelines() {
  if (!Platform::Current()->IsThreadedAnimationEnabled() ||
      !document_->GetSettings()->GetAcceleratedCompositingEnabled() ||
      !document_->GetPage())
    return;

  for (auto& timeline : timelines_) {
    cc::AnimationTimeline* compositor_timeline = timeline->CompositorTimeline();
    if (!compositor_timeline)
      continue;

    if (cc::AnimationHost* host =
            document_->GetPage()->GetChromeClient().GetCompositorAnimationHost(
                *document_->GetFrame())) {
      host->DetachAnimationTimeline(compositor_timeline);
    }
  }
}

void DocumentAnimations::Trace(Visitor* visitor) const {
  visitor->Trace(document_);
  visitor->Trace(timelines_);
}

void DocumentAnimations::GetAnimationsTargetingTreeScope(
    HeapVector<Member<Animation>>& animations,
    const TreeScope& tree_scope) {
  // This method follows the timelines in a given docmuent and append all the
  // animations to the reference animations.
  for (auto& timeline : timelines_) {
    for (const auto& animation : timeline->GetAnimations()) {
      if (animation->ReplaceStateRemoved())
        continue;
      if (!animation->effect() || (!animation->effect()->IsCurrent() &&
                                   !animation->effect()->IsInEffect())) {
        continue;
      }
      auto* effect = DynamicTo<KeyframeEffect>(animation->effect());
      Element* target = effect->target();
      if (!target || !target->isConnected())
        continue;
      if (&tree_scope != &target->GetTreeScope())
        continue;
      animations.push_back(animation);
    }
  }
}

void DocumentAnimations::RemoveReplacedAnimations(
    DocumentAnimations::ReplaceableAnimationsMap* replaceable_animations_map) {
  HeapVector<Member<Animation>> animations_to_remove;
  for (auto& elem_it : *replaceable_animations_map) {
    HeapVector<Member<Animation>>* animations = elem_it.value;

    // Only elements with multiple animations in the replaceable state need to
    // be checked.
    if (animations->size() == 1)
      continue;

    // By processing in decreasing order by priority, we can perform a single
    // pass for discovery of replaced properties.
    std::sort(animations->begin(), animations->end(), CompareAnimations);
    PropertyHandleSet replaced_properties;
    for (auto anim_it = animations->rbegin(); anim_it != animations->rend();
         anim_it++) {
      // Remaining conditions for removal:
      // * has a replace state of active,  and
      // * for which there exists for each target property of every animation
      //   effect associated with animation, an animation effect associated with
      //   a replaceable animation with a higher composite order than animation
      //   that includes the same target property.

      // Only active animations can be removed. We still need to go through
      // the process of iterating over properties if not removable to update
      // the set of properties being replaced.
      bool replace = (*anim_it)->ReplaceStateActive();
      PropertyHandleSet animation_properties =
          To<KeyframeEffect>((*anim_it)->effect())->Model()->Properties();
      for (const auto& property : animation_properties) {
        auto inserted = replaced_properties.insert(property);
        if (inserted.is_new_entry) {
          // Top-most compositor order animation affecting this property.
          replace = false;
        }
      }
      if (replace)
        animations_to_remove.push_back(*anim_it);
    }
  }
  scoped_refptr<scheduler::EventLoop> event_loop =
      document_->GetAgent().event_loop();

  // The list of animations for removal is constructed in reverse composite
  // ordering for efficiency. Flip the ordering to ensure that events are
  // dispatched in composite order.  Queue as a microtask so that the finished
  // event is dispatched ahead of the remove event.
  for (auto it = animations_to_remove.rbegin();
       it != animations_to_remove.rend(); it++) {
    Animation* animation = *it;
    event_loop->EnqueueMicrotask(WTF::BindOnce(
        &Animation::RemoveReplacedAnimation, WrapWeakPersistent(animation)));
  }
}

}  // namespace blink

"""

```