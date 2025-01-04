Response:
Let's break down the thought process for analyzing the `PageAnimator.cc` file.

1. **Understand the Core Purpose:** The filename `PageAnimator.cc` and the surrounding directory `blink/renderer/core/page/` strongly suggest this class is responsible for managing animations within a web page in the Blink rendering engine. The `#include` directives confirm this by bringing in components like `DocumentAnimations`, `DocumentTimeline`, `ScriptedAnimationController`, etc.

2. **Identify Key Responsibilities by Examining Public Methods:**  The public methods are the primary interface of the class. Scanning them reveals the following likely functions:
    * `ServiceScriptedAnimations`: This appears to be the core method for processing animations driven by JavaScript (requestAnimationFrame). The two overloads suggest handling different contexts or data.
    * `PostAnimate`: This likely handles cleanup or updates after the main animation processing.
    * `ReportFrameAnimations`: This suggests reporting animation-related information to another component (`cc::AnimationHost`), likely for compositing.
    * `Set...` methods (e.g., `SetHasCanvasInvalidation`, `SetHasInlineStyleMutation`): These indicate flags or state variables the `PageAnimator` maintains to track different types of animation activity.
    * `ScheduleVisualUpdate`:  This seems to trigger the rendering pipeline when animations need to update the display.
    * `UpdateAllLifecyclePhases...`:  These methods strongly point to managing the rendering lifecycle (style, layout, paint) in relation to animations.
    * `GetAnimations`: This provides a way to retrieve active animations.

3. **Connect Public Methods to Underlying Mechanisms (Private Members and Included Headers):**  Now, let's look at how these methods are implemented and what dependencies they have.
    * `ServiceScriptedAnimations`:
        * Uses `GetAllDocuments` to process animations across all frames.
        * Interacts with `DocumentTimeline` and `AnimationClock` for timing.
        * Calls `UpdateAnimationTimingForAnimationFrame` on `DocumentAnimations`.
        * Invokes `ServiceScrollAnimations` on `LocalFrameView`.
        * Uses `ScriptedAnimationController` to manage JavaScript-driven animations (requestAnimationFrame, events).
        * Dispatches events like `resize`, `scroll`, and potentially custom events related to view transitions.
        * Handles the `pagereveal` event related to view transitions.
    * `PostAnimate`: Resets flags and potentially allows the animation clock to update independently.
    * `ReportFrameAnimations`: Sends boolean flags to `cc::AnimationHost`. The names of these flags (canvas invalidation, inline style mutation, etc.) give insight into what the compositor needs to know.
    * `ScheduleVisualUpdate`:  Uses `ChromeClient::ScheduleAnimation`, suggesting it interacts with the browser's scheduling mechanisms.
    * `UpdateAllLifecyclePhases...`: Directly calls the corresponding methods on `LocalFrameView`, indicating it coordinates with the frame's rendering process.
    * `GetAnimations`: Iterates through documents and uses `DocumentAnimations` to gather the animations.

4. **Identify Relationships with Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `ServiceScriptedAnimations` method heavily involves `ScriptedAnimationController`, which is directly related to the `requestAnimationFrame` API in JavaScript. The dispatching of events (resize, scroll, etc.) also connects to JavaScript event handling. The execution of video frame callbacks further ties it to JavaScript APIs for video manipulation.
    * **HTML:** The processing of events on `LocalDOMWindow` and `Document` links to the HTML DOM structure. The focus on frame management indicates the handling of iframes. The mention of view transitions is a feature affecting how entire pages or parts of pages transition, a high-level HTML/browser concept.
    * **CSS:** The inclusion of `CSSValue` hints at the manipulation of CSS properties through animations. The mention of `@view-transition` in the context of `pagereveal` directly links to CSS view transitions.

5. **Infer Logic and Assumptions (Input/Output):**
    * **Input:** `monotonic_animation_start_time` is a key input to `ServiceScriptedAnimations`, representing the time at which the animation frame begins. Other inputs include the state of the DOM (elements, styles, etc.) and JavaScript animation callbacks.
    * **Output:** The primary output is the triggering of rendering updates, leading to visual changes on the screen. Internally, it updates the state of animations and notifies other components (like the compositor). The boolean flags passed to `cc::AnimationHost` are also outputs.

6. **Consider User/Developer Errors:**
    * **JavaScript Errors:**  Incorrect usage of `requestAnimationFrame` (e.g., not setting up proper exit conditions) can lead to excessive animation processing. Manipulating styles in a way that causes constant layout thrashing is a performance issue.
    * **CSS Errors:**  Poorly designed CSS transitions or animations can be janky or inefficient. Incorrect use of view transition properties might lead to unexpected transitions.

7. **Trace User Actions to Code:** This requires understanding the browser's architecture. A user action like a JavaScript-initiated animation or a CSS transition will eventually trigger the rendering pipeline. The `PageAnimator` sits within that pipeline, specifically when it's time to process animations. The sequence is roughly: User Interaction -> Event Handling (JavaScript) ->  `requestAnimationFrame` call or CSS transition starts -> Rendering Pipeline Triggered -> `PageAnimator::ServiceScriptedAnimations` gets called.

8. **Refine and Organize:**  Finally, structure the findings logically, separating the functionalities, relationships, logic, errors, and debugging aspects. Use clear examples to illustrate the connections to JavaScript, HTML, and CSS.

**(Self-Correction/Refinement during the process):**

* Initially, I might focus too much on the `ServiceScriptedAnimations` method. Realizing the significance of the `Set...` methods and `ReportFrameAnimations` helps paint a more complete picture of the class's role in communicating animation state to the compositor.
* Understanding the different lifecycle phases (`UpdateAllLifecyclePhases...`) is crucial for grasping how animations interact with the rendering process.
*  The connection to view transitions might not be immediately obvious without looking at the `pagereveal` event handling. Recognizing the importance of this newer feature requires deeper inspection.
*  Remembering the broader context of the Blink rendering engine and its multi-process architecture is essential for understanding why information is being passed to `cc::AnimationHost`.好的，让我们详细分析一下 `blink/renderer/core/page/page_animator.cc` 文件的功能。

**核心功能：管理和协调网页动画**

`PageAnimator` 类的核心职责是管理和协调网页中的各种动画，确保动画的平滑运行并与浏览器的渲染流程同步。它充当了动画驱动引擎的角色，负责在适当的时机触发和更新动画。

**主要功能点：**

1. **服务脚本动画 (Service Scripted Animations):**
   - 这是 `PageAnimator` 最核心的功能之一。它负责处理由 JavaScript `requestAnimationFrame` API 驱动的动画。
   - 它会遍历页面中所有文档（包括主文档和 iframe 中的文档），并针对每个文档执行以下操作：
     - 更新动画时钟，确保所有动画基于相同的时间基准。
     - 调用 `DocumentAnimations::UpdateAnimationTimingForAnimationFrame()` 来更新 CSS 动画和 Web Animations API 创建的动画的时间。
     - 如果文档可见且未被节流（can_throttle 为 false），则调用 `LocalFrameView::ServiceScrollAnimations()` 来处理与滚动相关的动画效果（例如，CSS `scroll-behavior: smooth;`）。
     - 运行每个文档的 `ScriptedAnimationController`，执行通过 `requestAnimationFrame` 注册的回调函数。这使得 JavaScript 能够每帧更新动画状态。
     - 处理与 View Transitions API 相关的 `pagereveal` 事件，用于跨文档或同文档的平滑过渡动画。
     - 触发 `resize`、`scroll` 等事件的处理。
     - 执行媒体查询的更新。
     - 执行 `fullscreen` 相关的步骤。
     - 执行视频帧回调（用于 `requestVideoFrameCallback`）。

   **与 JavaScript, HTML, CSS 的关系举例：**

   - **JavaScript:** 当 JavaScript 代码调用 `requestAnimationFrame(callback)` 时，浏览器会在下一次重绘之前调用 `callback` 函数。`PageAnimator::ServiceScriptedAnimations` 负责在合适的时机执行这些 `callback` 函数。
     ```javascript
     function animate(timestamp) {
       // 使用 timestamp 更新动画状态
       element.style.transform = `translateX(${timestamp / 10}px)`;
       requestAnimationFrame(animate);
     }
     requestAnimationFrame(animate);
     ```
   - **HTML:** `PageAnimator` 遍历页面中的所有 `Document` 对象，这意味着它处理的动画可能发生在 HTML 文档的任何元素上。
   - **CSS:**  `PageAnimator` 会间接影响 CSS 动画的执行。通过 `DocumentAnimations::UpdateAnimationTimingForAnimationFrame()`，CSS 动画的时间会被更新，从而驱动 CSS 动画的播放。例如，以下 CSS 动画的进度由 `PageAnimator` 管理的时间驱动：
     ```css
     .animated-element {
       animation-name: slide;
       animation-duration: 1s;
     }

     @keyframes slide {
       from { transform: translateX(0); }
       to { transform: translateX(100px); }
     }
     ```

   **假设输入与输出：**

   * **假设输入:**
     - `monotonic_animation_start_time`:  浏览器主线程提供的单调递增的时间戳，表示当前动画帧的开始时间。
     - 页面上注册了 `requestAnimationFrame` 的 JavaScript 回调函数。
     - 页面上存在定义了 CSS 动画的元素。
     - 用户可能正在滚动页面。
   * **假设输出:**
     - 执行 JavaScript 的 `requestAnimationFrame` 回调，使得 JavaScript 代码可以更新 DOM 元素的样式。
     - 更新 CSS 动画的当前时间，使得 CSS 动画能够平滑播放。
     - 如果用户正在滚动，可能会触发平滑滚动效果。
     - 可能会触发与 View Transitions API 相关的动画效果。

2. **`PostAnimate()`:**
   - 在动画服务完成后调用。
   - 如果没有即将到来的新的动画帧（由 `next_frame_has_pending_raf_` 标志指示），它会允许动画时钟动态更新时间。这对于处理非 `requestAnimationFrame` 驱动的动画，例如 `setInterval` 设置的动画非常重要。

3. **`ReportFrameAnimations(cc::AnimationHost* animation_host)`:**
   - 将当前帧的动画相关信息报告给 Compositor 线程的 `cc::AnimationHost`。Compositor 线程负责实际的屏幕绘制。
   - 报告的信息包括：
     - `has_canvas_invalidation_`: 是否有 Canvas 元素需要重绘。
     - `has_inline_style_mutation_`: 是否有内联样式被修改，这可能影响动画。
     - `has_smil_animation_`: 是否有 SMIL 动画在运行。
     - `current_frame_had_raf_`: 当前帧是否执行了 `requestAnimationFrame` 回调。
     - `next_frame_has_pending_raf_`:  是否有待执行的 `requestAnimationFrame` 回调，预示着下一帧可能有动画。
     - `has_view_transition_`: 是否有 View Transition 正在进行。
   - 这些信息帮助 Compositor 做出更优化的渲染决策。

4. **`ScheduleVisualUpdate(LocalFrame* frame)`:**
   - 当需要进行视觉更新时被调用，通常是因为动画导致了样式或布局的改变。
   - 它会调用 `page_->GetChromeClient().ScheduleAnimation(frame->View())`，通知浏览器安排下一次渲染。

5. **`UpdateAllLifecyclePhases(...)` 和其他 `UpdateLifecycleTo...` 方法:**
   - 这些方法用于强制更新渲染流水线的不同阶段（样式计算、布局、绘制）。
   - 动画通常会导致样式的改变，进而可能触发布局和绘制。`PageAnimator` 需要在合适的时机触发这些更新，以确保动画效果能够反映在屏幕上。

6. **设置动画相关标志 (`SetHasCanvasInvalidation()`, `SetHasInlineStyleMutation()`, 等.):**
   - 这些方法用于设置内部的布尔标志，指示当前帧发生了哪些类型的动画活动。这些标志随后会通过 `ReportFrameAnimations` 传递给 Compositor。

7. **`GetAnimations(const TreeScope& tree_scope)`:**
   -  返回指定 `TreeScope`（通常是 `Document`）中所有活动的动画对象。

**用户或编程常见的使用错误举例：**

1. **过度使用 `requestAnimationFrame`:**  如果在不需要动画时也持续调用 `requestAnimationFrame`，会导致不必要的 CPU 消耗和性能下降。
   ```javascript
   // 错误示例：没有停止条件
   function gameLoop() {
     // ... 游戏逻辑 ...
     requestAnimationFrame(gameLoop);
   }
   requestAnimationFrame(gameLoop);
   ```
   **用户操作如何到达这里作为调试线索：** 用户可能会发现页面持续占用 CPU 资源，即使没有明显的动画在运行。开发者可以通过 Performance 工具 (例如 Chrome DevTools 的 Performance 面板) 看到大量的 `requestAnimationFrame` 回调被执行。

2. **在 `requestAnimationFrame` 回调中执行耗时操作:** `requestAnimationFrame` 回调应该尽可能轻量级，避免执行阻塞主线程的长时间操作。否则会导致动画卡顿。
   ```javascript
   function animate() {
     // ... 更新动画 ...
     // 错误示例：执行了复杂的计算
     for (let i = 0; i < 1000000; i++) {
       // ... 一些计算 ...
     }
     requestAnimationFrame(animate);
   }
   ```
   **用户操作如何到达这里作为调试线索：** 用户会看到动画不流畅，出现明显的卡顿。开发者可以通过 Performance 工具看到在 `requestAnimationFrame` 回调函数中花费了大量时间。

3. **错误地使用 CSS 动画和 Transitions:**  不正确的 CSS 动画或 Transitions 定义可能导致意外的动画效果或性能问题。例如，对触发布局的属性进行动画可能会导致频繁的重排。
   ```css
   /* 错误示例：对会触发布局的 width 进行动画 */
   .element {
     transition: width 0.3s ease-in-out;
   }
   ```
   **用户操作如何到达这里作为调试线索：** 用户会看到动画不流畅，可能导致页面其他部分的布局发生变化。开发者可以使用 DevTools 的 Layers 面板或 Performance 面板来分析布局重排的情况。

**用户操作如何一步步的到达这里，作为调试线索：**

假设用户正在浏览一个网页，并且页面上有一个使用 JavaScript `requestAnimationFrame` 实现的动画效果：

1. **用户触发动画:** 用户可能通过鼠标悬停、点击按钮或其他交互操作触发了 JavaScript 代码开始执行动画。
2. **JavaScript 调用 `requestAnimationFrame`:**  JavaScript 代码中调用了 `requestAnimationFrame(animate)`，其中 `animate` 是动画的回调函数。
3. **浏览器进入渲染循环:** 浏览器的主线程在处理完当前的任务后，会进入渲染循环。
4. **`PageAnimator::ServiceScriptedAnimations` 被调用:** 在渲染循环的适当阶段，Blink 引擎会调用 `PageAnimator::ServiceScriptedAnimations` 来处理待执行的脚本动画。
5. **执行 JavaScript 回调:**  `ServiceScriptedAnimations` 会执行之前通过 `requestAnimationFrame` 注册的 `animate` 回调函数。
6. **回调函数修改 DOM:** `animate` 回调函数中会修改 DOM 元素的样式或其他属性，以实现动画效果。
7. **触发布局和绘制 (可能):** DOM 的修改可能会导致浏览器的布局和绘制阶段重新执行。
8. **`PageAnimator::ReportFrameAnimations` 被调用:** 在渲染帧的末尾，`PageAnimator` 会将动画信息报告给 Compositor 线程。
9. **Compositor 线程进行合成和绘制:** Compositor 线程基于收到的信息进行图层的合成和最终的屏幕绘制。

**作为调试线索:**

当开发者需要调试动画相关问题时，可以关注以下几点，这些都与 `PageAnimator` 的功能相关：

* **Performance 面板:** 查看帧率、CPU 占用情况，以及 `requestAnimationFrame` 回调的执行情况，可以帮助识别性能瓶颈。
* **Elements 面板:** 检查动画元素的样式变化，可以确认 CSS 动画或 JavaScript 动画是否按预期工作。
* **Layers 面板:**  分析图层合成情况，可以帮助理解动画是否触发了不必要的图层创建或重绘。
* **断点调试:** 在 `PageAnimator::ServiceScriptedAnimations` 或相关的 JavaScript 代码中设置断点，可以逐步跟踪动画的执行流程，查看变量的值和函数调用顺序。
* **Tracing (例如使用 `TRACE_EVENT`):**  Blink 源码中使用了 `TRACE_EVENT` 来记录关键事件，开发者可以通过 Chromium 的 tracing 工具 (chrome://tracing) 来分析动画的执行过程。

总结来说，`PageAnimator` 是 Blink 渲染引擎中负责管理和驱动网页动画的关键组件，它连接了 JavaScript、HTML 和 CSS 的动画机制，并与浏览器的渲染流程紧密配合，最终呈现给用户流畅的动画体验。理解 `PageAnimator` 的工作原理对于开发高性能的 Web 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/core/page/page_animator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/page_animator.h"

#include "base/auto_reset.h"
#include "base/time/time.h"
#include "cc/animation/animation_host.h"
#include "third_party/blink/renderer/core/animation/document_animations.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/dom/document_lifecycle.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/scripted_animation_controller.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/sync_scroll_attempt_heuristic.h"
#include "third_party/blink/renderer/core/page/validation_message_client.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/svg/svg_document_extensions.h"
#include "third_party/blink/renderer/core/timing/time_clamper.h"
#include "third_party/blink/renderer/core/view_transition/page_reveal_event.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

// We walk through all the frames in DOM tree order and get all the documents
DocumentsVector GetAllDocuments(Frame* main_frame) {
  DocumentsVector documents;
  for (Frame* frame = main_frame; frame; frame = frame->Tree().TraverseNext()) {
    if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
      Document* document = local_frame->GetDocument();
      bool can_throttle =
          document->View() ? document->View()->CanThrottleRendering() : false;
      documents.emplace_back(std::make_pair(document, can_throttle));
    }
  }
  return documents;
}

}  // namespace

PageAnimator::PageAnimator(Page& page)
    : page_(page),
      servicing_animations_(false),
      updating_layout_and_style_for_painting_(false) {}

void PageAnimator::Trace(Visitor* visitor) const {
  visitor->Trace(page_);
}

void PageAnimator::ServiceScriptedAnimations(
    base::TimeTicks monotonic_animation_start_time) {
  base::AutoReset<bool> servicing(&servicing_animations_, true);

  // Once we are inside a frame's lifecycle, the AnimationClock should hold its
  // time value until the end of the frame.
  Clock().SetAllowedToDynamicallyUpdateTime(false);
  Clock().UpdateTime(monotonic_animation_start_time);

  DocumentsVector documents = GetAllDocuments(page_->MainFrame());
  for (const auto& [document, can_throttle] : documents) {
    static TimeClamper time_clamper;
    base::TimeTicks animation_time = document->Timeline().CalculateZeroTime();
    if (monotonic_animation_start_time > animation_time) {
      animation_time += time_clamper.ClampTimeResolution(
          monotonic_animation_start_time - animation_time,
          document->domWindow()->CrossOriginIsolatedCapability());
    }
    document->GetAnimationClock().SetAllowedToDynamicallyUpdateTime(false);
    // TODO(crbug.com/1497922) timestamps outside rendering updates should also
    // be coarsened.
    document->GetAnimationClock().UpdateTime(animation_time);
  }

  TRACE_EVENT0("blink,rail", "PageAnimator::serviceScriptedAnimations");
  for (const auto& [document, can_throttle] : documents) {
    if (!document->View()) {
      document->GetDocumentAnimations()
          .UpdateAnimationTimingForAnimationFrame();
    } else {
      if (!can_throttle) {
        document->View()->ServiceScrollAnimations(
            monotonic_animation_start_time);
      }
    }
  }
  ControllersVector controllers{};
  for (const auto& document : documents) {
    controllers.emplace_back(document.first->GetScriptedAnimationController(),
                             document.second);
  }
  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic heuristic(page_->MainFrame());
  ServiceScriptedAnimations(monotonic_animation_start_time, controllers);
  page_->GetValidationMessageClient().LayoutOverlay();
}

void PageAnimator::ServiceScriptedAnimations(
    base::TimeTicks monotonic_time_now,
    const ControllersVector& controllers) {
  Vector<wtf_size_t> active_controllers_ids{};
  HeapVector<Member<ScriptedAnimationController>> active_controllers{};
  for (wtf_size_t i = 0; i < controllers.size(); ++i) {
    auto& [controller, can_throttle] = controllers[i];
    if (!controller->GetExecutionContext() ||
        controller->GetExecutionContext()->IsContextFrozenOrPaused()) {
      continue;
    }

    LocalDOMWindow* window = controller->GetWindow();
    auto* loader = window->document()->Loader();
    if (!loader) {
      continue;
    }

    controller->SetCurrentFrameTimeMs(
        window->document()->Timeline().CurrentTimeMilliseconds().value());
    controller->SetCurrentFrameLegacyTimeMs(
        loader->GetTiming()
            .MonotonicTimeToPseudoWallTime(monotonic_time_now)
            .InMillisecondsF());
    if (can_throttle) {
      continue;
    }
    auto* animator = controller->GetPageAnimator();
    if (animator && controller->HasFrameCallback()) {
      animator->SetCurrentFrameHadRaf();
    }
    if (!controller->HasScheduledFrameTasks()) {
      continue;
    }
    active_controllers_ids.emplace_back(i);
    active_controllers.emplace_back(controller);
  }

  Vector<base::TimeDelta> time_intervals(active_controllers.size());
  // TODO(rendering-dev): calls to Now() are expensive on ARM architectures.
  // We can avoid some of these calls by filtering out calls to controllers
  // where the function() invocation won't do any work (e.g., because there
  // are no events to dispatch).
  const auto run_for_all_active_controllers_with_timing =
      [&](const auto& function) {
        auto start_time = base::TimeTicks::Now();
        for (wtf_size_t i = 0; i < active_controllers.size(); ++i) {
          function(i);
          auto end_time = base::TimeTicks::Now();
          time_intervals[i] += end_time - start_time;
          start_time = end_time;
        }
      };

  // https://html.spec.whatwg.org/multipage/webappapis.html#event-loop-processing-model

  // For each fully active Document doc in docs, run the reveal steps for doc.
  // Not currently in spec but comes from monkeypatch in:
  // https://drafts.csswg.org/css-view-transitions-2/#monkey-patch-to-html
  if (RuntimeEnabledFeatures::PageRevealEventEnabled()) {
    // The event will be dispatched if the filter returns true. The sequencing
    // here is important:
    // 1. Resolve the view transition based on @view-transition and set it to
    //    the event. This happens in the filter so before the event is fired.
    // 2. Dispatch the pagereveal event
    // 3. Activate the view transition
    auto page_reveal_event_filter =
        WTF::BindRepeating([](const LocalDOMWindow* window, Event* event) {
          PageRevealEvent* page_reveal = DynamicTo<PageRevealEvent>(event);
          if (!page_reveal) {
            return false;
          }

          // pagereveal is only fired on Documents.
          CHECK(window);
          CHECK(window->document());
          CHECK(!window->HasBeenRevealed());

          if (RuntimeEnabledFeatures::ViewTransitionOnNavigationEnabled()) {
            if (auto* supplement = ViewTransitionSupplement::FromIfExists(
                    *window->document())) {
              DOMViewTransition* view_transition =
                  supplement->ResolveCrossDocumentViewTransition();
              page_reveal->SetViewTransition(view_transition);
            }
          }

          return true;
        });

    run_for_all_active_controllers_with_timing([&](wtf_size_t i) {
      LocalDOMWindow* window = active_controllers[i]->GetWindow();
      bool pagereveal_dispatched = active_controllers[i]->DispatchEvents(
          WTF::BindRepeating(page_reveal_event_filter, WrapPersistent(window)));

      if (pagereveal_dispatched) {
        window->SetHasBeenRevealed(true);
        if (RuntimeEnabledFeatures::ViewTransitionOnNavigationEnabled()) {
          if (ViewTransition* transition =
                  ViewTransitionUtils::GetTransition(*window->document());
              transition && transition->IsForNavigationOnNewDocument()) {
            transition->ActivateFromSnapshot();
          }
        }
      }
    });
  }

  // 6. For each fully active Document in docs, flush autofocus
  // candidates for that Document if its browsing context is a top-level
  // browsing context.
  run_for_all_active_controllers_with_timing([&](wtf_size_t i) {
    if (const auto* window = active_controllers[i]->GetWindow()) {
      window->document()->FlushAutofocusCandidates();
    }
  });

  // 7. For each fully active Document in docs, run the resize steps
  // for that Document, passing in now as the timestamp.
  wtf_size_t active_controller_id = 0;
  auto start_time = base::TimeTicks::Now();
  for (wtf_size_t i = 0; i < controllers.size(); ++i) {
    auto& [controller, can_throttle] = controllers[i];
    controller->DispatchEvents(WTF::BindRepeating([](Event* event) {
      return event->type() == event_type_names::kResize;
    }));
    auto end_time = base::TimeTicks::Now();
    if (active_controller_id < active_controllers_ids.size() &&
        i == active_controllers_ids[active_controller_id]) {
      time_intervals[active_controller_id++] += end_time - start_time;
    } else {
      // For non active controllers (e.g. which can throttle)
      // that's the only timing we need to measure.
      if (const auto* window = controller->GetWindow()) {
        if (auto* frame = window->document()->GetFrame()) {
          frame->GetFrameScheduler()->AddTaskTime(end_time - start_time);
        }
      }
    }
    start_time = end_time;
  }

  // 8. For each fully active Document in docs, run the scroll steps
  // for that Document, passing in now as the timestamp.
  run_for_all_active_controllers_with_timing([&](wtf_size_t i) {
    auto scope = SyncScrollAttemptHeuristic::GetScrollHandlerScope();
    active_controllers[i]->DispatchEvents(WTF::BindRepeating([](Event* event) {
      return event->type() == event_type_names::kScroll ||
             event->type() == event_type_names::kScrollsnapchange ||
             event->type() == event_type_names::kScrollsnapchanging ||
             event->type() == event_type_names::kScrollend;
    }));
  });

  // 9. For each fully active Document in docs, evaluate media
  // queries and report changes for that Document, passing in now as the
  // timestamp
  run_for_all_active_controllers_with_timing([&](wtf_size_t i) {
    active_controllers[i]->CallMediaQueryListListeners();
  });

  // 10. For each fully active Document in docs, update animations and
  // send events for that Document, passing in now as the timestamp.
  run_for_all_active_controllers_with_timing(
      [&](wtf_size_t i) { active_controllers[i]->DispatchEvents(); });

  // 11. For each fully active Document in docs, run the fullscreen
  // steps for that Document, passing in now as the timestamp.
  run_for_all_active_controllers_with_timing(
      [&](wtf_size_t i) { active_controllers[i]->RunTasks(); });

  // Run the fulfilled HTMLVideoELement.requestVideoFrameCallback() callbacks.
  // See https://wicg.github.io/video-rvfc/.
  run_for_all_active_controllers_with_timing([&](wtf_size_t i) {
    active_controllers[i]->ExecuteVideoFrameCallbacks();
  });

  // 13. For each fully active Document in docs, run the animation
  // frame callbacks for that Document, passing in now as the timestamp.
  run_for_all_active_controllers_with_timing([&](wtf_size_t i) {
    auto scope = SyncScrollAttemptHeuristic::GetRequestAnimationFrameScope();
    active_controllers[i]->ExecuteFrameCallbacks();
    if (!active_controllers[i]->GetExecutionContext()) {
      return;
    }
    auto* animator = active_controllers[i]->GetPageAnimator();
    if (animator && active_controllers[i]->HasFrameCallback()) {
      animator->SetNextFrameHasPendingRaf();
    }
    // See LocalFrameView::RunPostLifecycleSteps() for 14.
    active_controllers[i]->ScheduleAnimationIfNeeded();
  });

  // Add task timings.
  for (wtf_size_t i = 0; i < active_controllers.size(); ++i) {
    if (const auto* window = active_controllers[i]->GetWindow()) {
      if (auto* frame = window->document()->GetFrame()) {
        frame->GetFrameScheduler()->AddTaskTime(time_intervals[i]);
      }
    }
  }
}

void PageAnimator::PostAnimate() {
  // If we don't have an imminently incoming frame, we need to let the
  // AnimationClock update its own time to properly service out-of-lifecycle
  // events such as setInterval (see https://crbug.com/995806). This isn't a
  // perfect heuristic, but at the very least we know that if there is a pending
  // RAF we will be getting a new frame and thus don't need to unlock the clock.
  if (!next_frame_has_pending_raf_) {
    Clock().SetAllowedToDynamicallyUpdateTime(true);
    DocumentsVector documents = GetAllDocuments(page_->MainFrame());
    for (const auto& [document, can_throttle] : documents) {
      document->GetAnimationClock().SetAllowedToDynamicallyUpdateTime(true);
    }
  }
  next_frame_has_pending_raf_ = false;
}

void PageAnimator::SetHasCanvasInvalidation() {
  has_canvas_invalidation_ = true;
}

void PageAnimator::ReportFrameAnimations(cc::AnimationHost* animation_host) {
  if (animation_host) {
    animation_host->SetHasCanvasInvalidation(has_canvas_invalidation_);
    animation_host->SetHasInlineStyleMutation(has_inline_style_mutation_);
    animation_host->SetHasSmilAnimation(has_smil_animation_);
    animation_host->SetCurrentFrameHadRaf(current_frame_had_raf_);
    animation_host->SetNextFrameHasPendingRaf(next_frame_has_pending_raf_);
    animation_host->SetHasViewTransition(has_view_transition_);
  }
  has_canvas_invalidation_ = false;
  has_inline_style_mutation_ = false;
  has_smil_animation_ = false;
  current_frame_had_raf_ = false;
  // next_frame_has_pending_raf_ is reset at PostAnimate().
  // has_view_transition_ is reset when the transition ends.
}

void PageAnimator::SetSuppressFrameRequestsWorkaroundFor704763Only(
    bool suppress_frame_requests) {
  // If we are enabling the suppression and it was already enabled then we must
  // have missed disabling it at the end of a previous frame.
  DCHECK(!suppress_frame_requests_workaround_for704763_only_ ||
         !suppress_frame_requests);
  suppress_frame_requests_workaround_for704763_only_ = suppress_frame_requests;
}

void PageAnimator::SetHasInlineStyleMutation() {
  has_inline_style_mutation_ = true;
}

void PageAnimator::SetHasSmilAnimation() {
  has_smil_animation_ = true;
}

void PageAnimator::SetCurrentFrameHadRaf() {
  current_frame_had_raf_ = true;
}

void PageAnimator::SetNextFrameHasPendingRaf() {
  next_frame_has_pending_raf_ = true;
}

void PageAnimator::SetHasViewTransition(bool has_view_transition) {
  has_view_transition_ = has_view_transition;
}

DISABLE_CFI_PERF
void PageAnimator::ScheduleVisualUpdate(LocalFrame* frame) {
  if (servicing_animations_ || updating_layout_and_style_for_painting_ ||
      suppress_frame_requests_workaround_for704763_only_) {
    return;
  }
  page_->GetChromeClient().ScheduleAnimation(frame->View());
}

void PageAnimator::UpdateAllLifecyclePhases(LocalFrame& root_frame,
                                            DocumentUpdateReason reason) {
  LocalFrameView* view = root_frame.View();
  base::AutoReset<bool> servicing(&updating_layout_and_style_for_painting_,
                                  true);
  view->UpdateAllLifecyclePhases(reason);
}

void PageAnimator::UpdateAllLifecyclePhasesExceptPaint(
    LocalFrame& root_frame,
    DocumentUpdateReason reason) {
  LocalFrameView* view = root_frame.View();
  base::AutoReset<bool> servicing(&updating_layout_and_style_for_painting_,
                                  true);
  view->UpdateAllLifecyclePhasesExceptPaint(reason);
}

void PageAnimator::UpdateLifecycleToLayoutClean(LocalFrame& root_frame,
                                                DocumentUpdateReason reason) {
  LocalFrameView* view = root_frame.View();
  base::AutoReset<bool> servicing(&updating_layout_and_style_for_painting_,
                                  true);
  view->UpdateLifecycleToLayoutClean(reason);
}

HeapVector<Member<Animation>> PageAnimator::GetAnimations(
    const TreeScope& tree_scope) {
  HeapVector<Member<Animation>> animations;
  DocumentsVector documents = GetAllDocuments(page_->MainFrame());
  for (auto& [document, can_throttle] : documents) {
    document->GetDocumentAnimations().GetAnimationsTargetingTreeScope(
        animations, tree_scope);
  }
  return animations;
}

}  // namespace blink

"""

```