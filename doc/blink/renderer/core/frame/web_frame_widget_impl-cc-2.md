Response:
My thinking process to analyze the provided C++ code snippet and generate the summary involved several steps:

1. **Identify the Core Purpose:**  The first thing I noticed was the class name `WebFrameWidgetImpl`. The "Impl" suffix often indicates an implementation detail of a larger interface. The "WebFrameWidget" part suggests it's related to displaying web content within a frame. The file path `blink/renderer/core/frame/` reinforces this, placing it firmly within the rendering engine's frame management.

2. **Scan for Key Function Names and Patterns:**  I then scanned the code for recurring themes and important function names. I looked for verbs and nouns that hinted at actions and data being manipulated. Keywords like "Did...", "Report...", "Set...", "Update...", "Get...", "Allocate...", "Should...", "ForEach...", "Apply..." are strong indicators of functionality.

3. **Group Related Functions:**  As I identified key functions, I mentally grouped them based on their apparent purpose. For example, functions related to size, zoom, and visual properties seemed to form a cluster. Functions with "Report..." and timing in their names likely dealt with performance monitoring. Functions mentioning "LayerTreeHost" suggested compositing.

4. **Focus on Interactions with Web Technologies (JavaScript, HTML, CSS):** The prompt specifically asked about connections to JavaScript, HTML, and CSS. I searched for clues about how the C++ code interacts with these web technologies. This included:
    * **DOM Manipulation:**  Functions like `ForEachLocalFrameControlledByWidget` which iterates through frames, and mentions of `Document`, `DOMWindow`, and `Element` directly point to interaction with the Document Object Model, the representation of HTML structure and content accessible to JavaScript.
    * **CSS Effects:**  Functions like `SetBackgroundColor`, mentions of `zoom_level`, `css_zoom_factor`, and `compositing_scale_factor` clearly relate to how CSS properties are applied and managed during rendering.
    * **JavaScript APIs:**  Functions like `ReportLongAnimationFrameTiming`, `ReportLongTaskTiming`, and mentions of `performance` directly connect to JavaScript's Performance API used for measuring website performance. The interaction with input events (mouse, touch) is also crucial for JavaScript event handling.
    * **Lifecycle Management:** Functions like `DidBeginMainFrame`, `UpdateLifecycle`, and mentions of parsing and loading status are fundamental to the web page loading process, which involves HTML parsing and JavaScript execution.
    * **Events:** The handling of various input events (mouse, touch, scroll) is essential for the interactivity of web pages, heavily reliant on JavaScript.

5. **Infer Functionality from Code Logic (even without deep understanding):**  Even without being an expert in the Chromium codebase, I could infer some functionality from the structure of the code:
    * **Conditional Logic:** `if` statements, particularly those checking for `local_root_`, `GetPage()`, or certain states, indicate conditions under which specific actions are taken.
    * **Iteration:** `ForEachLocalFrameControlledByWidget` suggests actions being applied to multiple frames within the widget.
    * **Data Structures:** The use of `base::TimeDelta`, `base::TimeTicks`, `gfx::Size`, `gfx::Rect`, and other custom types suggests the manipulation of time, geometry, and other rendering-related data.
    * **Delegation:** Calls to `widget_base_->...` and `local_frame->Client()->...` indicate delegation of responsibilities to other objects, a common pattern in object-oriented programming.

6. **Consider User and Programming Errors:** I thought about common issues that arise in web development and how this code might be involved:
    * **Input Handling:**  Ignoring input events, issues with focus, and handling different types of input are common areas for bugs.
    * **Performance Problems:** Long tasks and animation delays are frequent performance bottlenecks.
    * **Rendering Issues:** Incorrect sizing, scaling, and visual updates can lead to display errors.
    * **Lifecycle Problems:** Incorrect handling of the page load lifecycle can cause unexpected behavior.

7. **Formulate Assumptions and Examples:**  Based on my understanding, I formulated assumptions about inputs and outputs for certain functions. For example, I assumed that `SetZoomLevel` with a positive value would increase the perceived size of content. I created examples to illustrate the connection between the C++ code and web technologies, such as how `DidMeaningfulLayout` relates to performance metrics and JavaScript events.

8. **Structure the Summary:** Finally, I organized my findings into a clear and structured summary, addressing the prompt's specific requests:
    * Listing the core functionalities.
    * Explaining the relationships with JavaScript, HTML, and CSS with illustrative examples.
    * Providing examples of logical reasoning with assumptions about inputs and outputs.
    * Identifying potential user and programming errors.
    * Concluding with a concise overall summary.

Essentially, my approach involved a combination of code scanning, pattern recognition, logical deduction, and connecting the low-level C++ implementation to the high-level concepts of web development. Even without knowing every detail of the Chromium codebase, the naming conventions and general structure of the code provide valuable clues about its purpose and interactions.
这是 `blink/renderer/core/frame/web_frame_widget_impl.cc` 文件的第三部分，主要负责 `WebFrameWidgetImpl` 类中关于**生命周期管理、视觉属性更新、渲染合成以及与外部交互**相关的实现。

以下是该部分代码的功能归纳和与 Web 技术关系的说明：

**核心功能归纳：**

* **完成合成器帧绘制通知:** `DidCommitAndDrawCompositorFrame` 通知所有由该 Widget 控制的本地 frame，合成器帧已经提交并绘制。这与渲染流程的最后阶段有关。
* **观察首次滚动延迟:** `DidObserveFirstScrollDelay` 记录首次滚动事件的延迟，用于性能分析，特别是与用户体验相关的交互性指标。
* **判断是否忽略输入事件:** `ShouldIgnoreInputEvents` 查询是否应该忽略输入事件，这可能发生在某些状态下，例如页面加载或特定动画过程中。
* **报告长动画帧和长任务:** `ReportLongAnimationFrameTiming` 和 `ReportLongTaskTiming` 将长于阈值的动画帧和 JavaScript 任务的性能数据报告给 Performance API，供开发者分析性能瓶颈。
* **判断是否应该报告长动画帧:** `ShouldReportLongAnimationFrameTiming` 根据 Widget 的可见性和状态判断是否需要报告长动画帧数据。
* **任务完成通知:** `OnTaskCompletedForFrame` 通知动画帧时序监控器有任务完成，用于更精细的性能追踪。
* **主帧开始事件:** `DidBeginMainFrame` 在主帧开始时执行一些操作，例如运行生命周期后的步骤和触发动画。
* **更新生命周期:** `UpdateLifecycle` 驱动整个页面的生命周期更新，包括样式计算、布局和绘制。它也负责在生命周期更新时处理一些特定的事件，例如首次有意义的布局。
* **完成页面缩放动画通知:** `DidCompletePageScaleAnimation` 在页面缩放动画结束后执行一些操作，例如通知自动填充客户端。
* **调度动画:** `ScheduleAnimation` 触发渲染更新，无论是通过合成器还是传统的非合成方式。
* **焦点改变处理:** `FocusChanged` 处理 Widget 的焦点状态变化，并更新视图的激活状态和页面焦点状态。
* **判断是否立即确认合成输入:** `ShouldAckSyntheticInputImmediately` 判断是否需要立即确认合成输入事件，这可能与某些特定模式（如 VR）有关。
* **更新视觉属性:** `UpdateVisualProperties` 接收并应用来自浏览器的各种视觉属性更新，包括缩放级别、显示模式、窗口状态、可调整大小性、视口大小、页面缩放因子、合成缩放因子、光标辅助缩放因子等。这是该文件中非常核心的功能之一。
* **应用视觉属性中的尺寸信息:** `ApplyVisualPropertiesSizing` 具体应用视觉属性中的尺寸信息，包括合成器视口大小、可见视口大小等。
* **判断全屏状态是否改变:** `DidChangeFullscreenState` 判断当前的视觉属性是否表示全屏状态的改变。
* **获取 LayerTree ID 和设置:** `GetLayerTreeId` 和 `GetLayerTreeSettings` 提供访问 LayerTreeHost 的接口，用于获取渲染合成的相关信息。
* **更新浏览器控件状态:** `UpdateBrowserControlsState` 更新浏览器控件（例如地址栏）的状态，影响页面布局。
* **设置是否有滚动事件处理器:** `SetHaveScrollEventHandlers` 通知合成器是否有 JavaScript 注册了滚动事件处理器。
* **设置事件监听器属性:** `SetEventListenerProperties` 设置特定类型事件监听器的属性，例如是否被动监听，影响合成器的优化。
* **获取显示模式、窗口状态、可调整大小性、视口分段:** `DisplayMode`, `WindowShowState`, `Resizable`, `ViewportSegments` 提供访问 Widget 属性的接口。
* **延迟和停止提交:** `StartDeferringCommits` 和 `StopDeferringCommits` 控制渲染提交的延迟，用于优化性能，例如在页面不可见时。
* **暂停渲染:** `PauseRendering` 暂停渲染合成。
* **获取最大渲染缓冲区边界:** `GetMaxRenderBufferBounds` 获取最大渲染缓冲区的边界。
* **延迟主帧更新:** `DeferMainFrameUpdate` 延迟主帧的更新。
* **设置浏览器控件显示比例和参数:** `SetBrowserControlsShownRatio` 和 `SetBrowserControlsParams` 设置浏览器控件的显示比例和参数。
* **同步合成（测试用）:** `SynchronouslyCompositeForTesting` 用于测试，强制同步执行合成。
* **设置设备颜色空间（测试用）:** `SetDeviceColorSpaceForTesting` 用于测试，设置设备的颜色空间。
* **处理指针锁定鼠标事件:** `PointerLockMouseEvent` 处理在指针锁定状态下的鼠标事件。
* **判断是否指针锁定:** `IsPointerLocked` 判断当前是否处于指针锁定状态。
* **显示上下文菜单:** `ShowContextMenu` 触发显示上下文菜单。
* **设置视口交叉状态:** `SetViewportIntersection` 和 `ApplyViewportIntersection` 用于处理嵌套 frame 的视口交叉信息，优化渲染。
* **启用和禁用设备模拟:** `EnableDeviceEmulation` 和 `DisableDeviceEmulation` 用于模拟不同设备的屏幕尺寸和特性。
* **设置子 Frame 是否为惰性:** `SetIsInertForSubFrame` 设置子 Frame 是否为惰性，减少不必要的渲染。
* **获取并重置上下文菜单位置:** `GetAndResetContextMenuLocation` 获取并清除上下文菜单的位置信息。
* **获取和设置缩放级别:** `GetZoomLevel` 和 `SetZoomLevel` 用于获取和设置页面的缩放级别。
* **内部设置缩放级别:** `SetZoomInternal` 是设置缩放级别的内部实现，考虑了 CSS 缩放因子。
* **设置自动调整大小模式:** `SetAutoResizeMode` 启用或禁用自动调整大小模式，并设置最小和最大窗口尺寸。
* **自动调整大小完成通知:** `DidAutoResize` 在自动调整大小完成后更新内部状态。
* **获取 Widget 内焦点所在的本地 Frame:** `FocusedLocalFrameInWidget` 获取当前 Widget 内拥有焦点的本地 Frame。
* **获取 Widget 内焦点所在的 WebLocalFrameImpl:** `FocusedWebLocalFrameInWidget` 获取当前 Widget 内拥有焦点的 WebLocalFrameImpl。
* **滚动焦点可编辑元素到可见区域:** `ScrollFocusedEditableElementIntoView` 将当前获得焦点的可编辑元素滚动到可视区域。

**与 Javascript, HTML, CSS 的关系及举例说明：**

* **Javascript:**
    * **Performance API:** `ReportLongAnimationFrameTiming` 和 `ReportLongTaskTiming` 直接将数据传递给 Javascript 的 Performance API，例如可以通过 `performance.measure()` 或 `performance.getEntriesByType('longtask')` 获取。
        * **假设输入:** 一个 JavaScript 函数执行时间超过 50 毫秒。
        * **输出:** `ReportLongTaskTiming` 会被调用，Performance API 中会出现一个 "longtask" 条目，开发者可以通过 JavaScript 代码获取到这个信息。
    * **事件处理:** `SetHaveScrollEventHandlers` 影响合成器是否需要等待 JavaScript 的滚动事件处理，如果 JavaScript 注册了 `scroll` 事件监听器，合成器可能需要更谨慎地处理滚动。
        * **假设输入:** HTML 中有 `<div style="overflow: scroll;">` 并且 JavaScript 代码中添加了 `div.addEventListener('scroll', ...)`。
        * **输出:** `SetHaveScrollEventHandlers` 会被设置为 `true`，合成器可能会采取不同的滚动处理策略。
    * **焦点事件:** `FocusChanged` 与 JavaScript 的 `focus` 和 `blur` 事件相关。当 Widget 获得或失去焦点时，会触发相应的 JavaScript 事件。
        * **假设输入:** 用户点击一个输入框，使该 Widget 获得焦点。
        * **输出:** `FocusChanged` 会被调用，并且 JavaScript 中该输入框会触发 `focus` 事件。
    * **Pointer Lock API:** `PointerLockMouseEvent` 和 `IsPointerLocked` 与 JavaScript 的 Pointer Lock API 相关。
        * **假设输入:** JavaScript 调用了 `element.requestPointerLock()`。
        * **输出:** `IsPointerLocked` 会返回 `true`，并且后续的鼠标移动事件会通过 `PointerLockMouseEvent` 传递。
    * **动画帧:** `ScheduleAnimation` 间接与 `requestAnimationFrame` API 相关。当需要进行动画更新时，`ScheduleAnimation` 会被调用，最终触发渲染，从而使得 `requestAnimationFrame` 的回调能够执行。

* **HTML:**
    * **页面生命周期:** `UpdateLifecycle` 与 HTML 文档的加载和渲染过程密切相关。`DidMeaningfulLayout` 可以在不同的 HTML 加载阶段（例如解析完成、资源加载完成）被触发，用于标记重要的渲染时刻。
        * **假设输入:** 一个 HTML 页面加载完成，所有资源都已下载。
        * **输出:** `UpdateLifecycle` 会被调用，并且当满足条件时，`DidMeaningfulLayout` 会以 `kFinishedLoading` 的参数被调用。
    * **焦点元素:** `ScrollFocusedEditableElementIntoView` 用于将 HTML 中获得焦点的可编辑元素（例如 `<input>` 或 `contenteditable` 的 `div`）滚动到可视区域。
        * **假设输入:** 用户点击了一个位于当前视口之外的输入框。
        * **输出:** `ScrollFocusedEditableElementIntoView` 会被调用，页面会滚动，使得该输入框可见。

* **CSS:**
    * **缩放:** `SetZoomLevel` 和 `SetZoomInternal` 直接影响页面的视觉缩放效果，这与 CSS 的 `zoom` 属性类似，但通常是由浏览器控制的。
        * **假设输入:** 用户在浏览器中将页面缩放级别设置为 150%。
        * **输出:** `SetZoomLevel` 会被调用，影响页面的布局和渲染，使得所有元素看起来都放大了。
    * **背景颜色:** 在 `UpdateLifecycle` 中，背景颜色会被设置。这与 CSS 的 `background-color` 属性相关。
        * **假设输入:** HTML 中设置了 `body { background-color: red; }`。
        * **输出:** 在生命周期更新时，`SetBackgroundColor` 会被调用，将 Widget 的背景颜色设置为红色。
    * **视口 (Viewport):** `UpdateVisualProperties` 中处理的视口大小、缩放因子等信息直接影响 CSS 布局中视口的计算和使用，例如 `@viewport` 规则和 `vw`, `vh` 单位。
        * **假设输入:** 浏览器窗口大小改变。
        * **输出:** `UpdateVisualProperties` 会接收新的视口大小信息，并更新内部状态，这会影响 CSS 布局的计算。
    * **媒体查询 (Media Queries):** `UpdateVisualProperties` 中设置的 `display_mode` 和窗口状态等信息可能会触发 CSS 中的媒体查询，例如 `@media (display-mode: fullscreen)`。
        * **假设输入:** 用户进入全屏模式。
        * **输出:** `UpdateVisualProperties` 会将 `display_mode` 设置为 `kFullscreen`，这可能会触发 CSS 中相应的媒体查询规则。

**逻辑推理的假设输入与输出举例：**

* **假设输入:** 用户在页面上进行了首次滚动操作。
* **输出:** `DidObserveFirstScrollDelay` 会被调用，记录从用户发起滚动到页面开始响应的时间差。

* **假设输入:** JavaScript 代码调用了 `requestAnimationFrame`。
* **输出:** `ScheduleAnimation` 会被调用，通知渲染引擎在下一次刷新时进行渲染更新，从而执行 `requestAnimationFrame` 的回调。

**用户或编程常见的使用错误举例：**

* **未正确处理焦点:** 开发者可能在 JavaScript 中错误地操作焦点，导致 `FocusChanged` 的状态与预期不符，从而引起 UI 行为异常。例如，在复杂的 Web 应用中，焦点可能会意外地丢失或转移。
* **过度依赖同步操作:**  在滚动事件处理中执行耗时的同步 JavaScript 操作可能导致 `DidObserveFirstScrollDelay` 的值过高，造成用户感知到的卡顿。开发者应该尽量使用异步操作或将耗时操作放在 Web Worker 中执行。
* **错误地假设渲染时机:** 开发者可能错误地假设某些 DOM 操作会立即触发渲染更新，而实际上渲染是由浏览器调度的。理解 `ScheduleAnimation` 的作用有助于开发者更好地管理渲染时机。
* **不理解生命周期阶段:**  开发者可能在错误的生命周期阶段执行某些操作，例如在 DOMContentLoaded 事件之前尝试访问某些元素，这可能导致错误。理解 `UpdateLifecycle` 的各个阶段对于编写健壮的 Web 应用至关重要。

**总结来说，`WebFrameWidgetImpl` 的这一部分代码主要负责管理 WebFrame 的生命周期，接收并应用视觉属性的更新，驱动渲染合成流程，并与浏览器和外部环境进行交互。它在 Blink 渲染引擎中扮演着至关重要的角色，直接影响着页面的显示、性能和用户交互。**

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_widget_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
otExpected(request);
}

void WebFrameWidgetImpl::DidCommitAndDrawCompositorFrame() {
  ForEachLocalFrameControlledByWidget(
      local_root_->GetFrame(), [](WebLocalFrameImpl* local_frame) {
        local_frame->Client()->DidCommitAndDrawCompositorFrame();
      });
}

void WebFrameWidgetImpl::DidObserveFirstScrollDelay(
    base::TimeDelta first_scroll_delay,
    base::TimeTicks first_scroll_timestamp) {
  if (!local_root_ || !(local_root_->GetFrame()) ||
      !(local_root_->GetFrame()->GetDocument())) {
    return;
  }
  InteractiveDetector* interactive_detector =
      InteractiveDetector::From(*(local_root_->GetFrame()->GetDocument()));
  if (interactive_detector) {
    interactive_detector->DidObserveFirstScrollDelay(first_scroll_delay,
                                                     first_scroll_timestamp);
  }
}

bool WebFrameWidgetImpl::ShouldIgnoreInputEvents() {
  CHECK(GetPage());
  return IgnoreInputEvents(GetPage()->BrowsingContextGroupToken());
}

std::unique_ptr<cc::LayerTreeFrameSink>
WebFrameWidgetImpl::AllocateNewLayerTreeFrameSink() {
  return nullptr;
}

void WebFrameWidgetImpl::ReportLongAnimationFrameTiming(
    AnimationFrameTimingInfo* timing_info) {
  WebSecurityOrigin root_origin = local_root_->GetSecurityOrigin();
  ForEachLocalFrameControlledByWidget(
      local_root_->GetFrame(), [&](WebLocalFrameImpl* local_frame) {
        if (local_frame == local_root_ ||
            !local_frame->GetSecurityOrigin().IsSameOriginWith(root_origin)) {
          DOMWindowPerformance::performance(
              *local_frame->GetFrame()->DomWindow())
              ->ReportLongAnimationFrameTiming(timing_info);
        }
      });
}

void WebFrameWidgetImpl::ReportLongTaskTiming(base::TimeTicks start_time,
                                              base::TimeTicks end_time,
                                              ExecutionContext* task_context) {
  CHECK(local_root_);
  CHECK(local_root_->GetFrame());
  ForEachLocalFrameControlledByWidget(
      local_root_->GetFrame(), [&](WebLocalFrameImpl* local_frame) {
        CHECK(local_frame->GetFrame());
        CHECK(local_frame->GetFrame()->DomWindow());
        // Note: |task_context| could be the execution context of any same-agent
        // frame.
        DOMWindowPerformance::performance(*local_frame->GetFrame()->DomWindow())
            ->ReportLongTask(start_time, end_time, task_context,
                             /*has_multiple_contexts=*/false);
      });
}

bool WebFrameWidgetImpl::ShouldReportLongAnimationFrameTiming() const {
  return widget_base_ && !IsHidden();
}
void WebFrameWidgetImpl::OnTaskCompletedForFrame(
    base::TimeTicks start_time,
    base::TimeTicks end_time,
    LocalFrame* frame) {
  if (animation_frame_timing_monitor_) {
    animation_frame_timing_monitor_->OnTaskCompleted(start_time, end_time,
                                                     frame);
  }
}

void WebFrameWidgetImpl::DidBeginMainFrame() {
  LocalFrame* local_root_frame = LocalRootImpl()->GetFrame();
  CHECK(local_root_frame);

  if (LocalFrameView* frame_view = local_root_frame->View()) {
    frame_view->RunPostLifecycleSteps();
  }

  if (animation_frame_timing_monitor_) {
    CHECK(local_root_frame->DomWindow());
    animation_frame_timing_monitor_->DidBeginMainFrame(
        *local_root_frame->DomWindow());
  }

  if (Page* page = local_root_frame->GetPage()) {
    page->Animator().PostAnimate();
  }
}

void WebFrameWidgetImpl::UpdateLifecycle(WebLifecycleUpdate requested_update,
                                         DocumentUpdateReason reason) {
  TRACE_EVENT0("blink", "WebFrameWidgetImpl::UpdateLifecycle");
  if (!LocalRootImpl())
    return;

  if (requested_update == WebLifecycleUpdate::kAll &&
      animation_frame_timing_monitor_) {
    animation_frame_timing_monitor_->WillPerformStyleAndLayoutCalculation();
  }

  GetPage()->UpdateLifecycle(*LocalRootImpl()->GetFrame(), requested_update,
                             reason);
  if (requested_update != WebLifecycleUpdate::kAll)
    return;

  View()->UpdatePagePopup();

  // Meaningful layout events and background colors only apply to main frames.
  if (ForMainFrame()) {
    MainFrameData& data = main_data();

    // There is no background color for non-composited WebViews (eg
    // printing).
    if (View()->does_composite()) {
      SkColor background_color = View()->BackgroundColor();
      SetBackgroundColor(background_color);
      if (background_color != data.last_background_color) {
        LocalRootImpl()->GetFrame()->DidChangeBackgroundColor(
            SkColor4f::FromColor(background_color), false /* color_adjust */);
        data.last_background_color = background_color;
      }
    }

    if (LocalFrameView* view = LocalRootImpl()->GetFrameView()) {
      LocalFrame* frame = LocalRootImpl()->GetFrame();

      if (data.should_dispatch_first_visually_non_empty_layout &&
          view->IsVisuallyNonEmpty()) {
        data.should_dispatch_first_visually_non_empty_layout = false;
        // TODO(esprehn): Move users of this callback to something
        // better, the heuristic for "visually non-empty" is bad.
        DidMeaningfulLayout(WebMeaningfulLayout::kVisuallyNonEmpty);
      }

      if (data.should_dispatch_first_layout_after_finished_parsing &&
          frame->GetDocument()->HasFinishedParsing()) {
        data.should_dispatch_first_layout_after_finished_parsing = false;
        DidMeaningfulLayout(WebMeaningfulLayout::kFinishedParsing);
      }

      if (data.should_dispatch_first_layout_after_finished_loading &&
          frame->GetDocument()->IsLoadCompleted()) {
        data.should_dispatch_first_layout_after_finished_loading = false;
        DidMeaningfulLayout(WebMeaningfulLayout::kFinishedLoading);
      }
    }
  }
}

void WebFrameWidgetImpl::DidCompletePageScaleAnimation() {
  // Page scale animations only happen on the main frame.
  DCHECK(ForMainFrame());
  if (auto* focused_frame = View()->FocusedFrame()) {
    if (focused_frame->AutofillClient())
      focused_frame->AutofillClient()->DidCompleteFocusChangeInFrame();
  }

  if (page_scale_animation_for_testing_callback_)
    std::move(page_scale_animation_for_testing_callback_).Run();
}

void WebFrameWidgetImpl::ScheduleAnimation() {
  if (!View()->does_composite()) {
    non_composited_client_->ScheduleNonCompositedAnimation();
    return;
  }

  if (widget_base_->WillBeDestroyed()) {
    return;
  }

  widget_base_->LayerTreeHost()->SetNeedsAnimate();
}

void WebFrameWidgetImpl::FocusChanged(mojom::blink::FocusState focus_state) {
  // TODO(crbug.com/689777): FocusChange events are only sent to the MainFrame
  // these maybe should goto the local root so that the rest of input messages
  // sent to those are preserved in order.
  DCHECK(ForMainFrame());
  View()->SetIsActive(focus_state == mojom::blink::FocusState::kFocused ||
                      focus_state ==
                          mojom::blink::FocusState::kNotFocusedAndActive);
  View()->SetPageFocus(focus_state == mojom::blink::FocusState::kFocused);
}

bool WebFrameWidgetImpl::ShouldAckSyntheticInputImmediately() {
  // TODO(bokan): The RequestPresentation API appears not to function in VR. As
  // a short term workaround for https://crbug.com/940063, ACK input
  // immediately rather than using RequestPresentation.
  if (GetPage()->GetSettings().GetImmersiveModeEnabled())
    return true;
  return false;
}

void WebFrameWidgetImpl::UpdateVisualProperties(
    const VisualProperties& visual_properties) {
  SetZoomInternal(visual_properties.zoom_level,
                  visual_properties.css_zoom_factor);

  // TODO(danakj): In order to synchronize updates between local roots, the
  // display mode should be propagated to RenderFrameProxies and down through
  // their RenderWidgetHosts to child WebFrameWidgetImpl via the
  // VisualProperties waterfall, instead of coming to each WebFrameWidgetImpl
  // independently.
  // https://developer.mozilla.org/en-US/docs/Web/CSS/@media/display-mode
  SetDisplayMode(visual_properties.display_mode);
  SetWindowShowState(visual_properties.window_show_state);
  SetResizable(visual_properties.resizable);

  if (ForMainFrame()) {
    SetAutoResizeMode(
        visual_properties.auto_resize_enabled,
        visual_properties.min_size_for_auto_resize,
        visual_properties.max_size_for_auto_resize,
        visual_properties.screen_infos.current().device_scale_factor);
  }

  bool capture_sequence_number_changed =
      visual_properties.capture_sequence_number !=
      last_capture_sequence_number_;
  if (capture_sequence_number_changed) {
    last_capture_sequence_number_ = visual_properties.capture_sequence_number;

    // Send the capture sequence number to RemoteFrames that are below the
    // local root for this widget.
    ForEachRemoteFrameControlledByWidget(
        [capture_sequence_number = visual_properties.capture_sequence_number](
            RemoteFrame* remote_frame) {
          remote_frame->UpdateCaptureSequenceNumber(capture_sequence_number);
        });
  }

  if (!View()->AutoResizeMode()) {
    // This needs to run before ApplyVisualPropertiesSizing below,
    // which updates the current set of screen_infos from visual properties.
    if (DidChangeFullscreenState(visual_properties)) {
      is_fullscreen_granted_ = visual_properties.is_fullscreen_granted;
      if (is_fullscreen_granted_)
        View()->DidEnterFullscreen();
      else
        View()->DidExitFullscreen();
    }
  }

  gfx::Size old_visible_viewport_size_in_dips =
      widget_base_->VisibleViewportSizeInDIPs();
  ApplyVisualPropertiesSizing(visual_properties);

  if (old_visible_viewport_size_in_dips !=
      widget_base_->VisibleViewportSizeInDIPs()) {
    ForEachLocalFrameControlledByWidget(
        local_root_->GetFrame(),
        &WebLocalFrameImpl::ResetHasScrolledFocusedEditableIntoView);

    // Propagate changes down to child local root RenderWidgets and
    // BrowserPlugins in other frame trees/processes.
    ForEachRemoteFrameControlledByWidget(
        [visible_viewport_size = widget_base_->VisibleViewportSizeInDIPs()](
            RemoteFrame* remote_frame) {
          remote_frame->DidChangeVisibleViewportSize(visible_viewport_size);
        });
  }

  // All non-top-level Widgets (child local-root frames, GuestViews,
  // etc.) propagate and consume the page scale factor as "external", meaning
  // that it comes from the top level widget's page scale.
  if (!ForTopMostMainFrame()) {
    // The main frame controls the page scale factor, from blink. For other
    // frame widgets, the page scale from pinch zoom and compositing scale is
    // received from its parent as part of the visual properties here. While
    // blink doesn't need to know this page scale factor outside the main frame,
    // the compositor does in order to produce its output at the correct scale.
    float combined_scale_factor = visual_properties.page_scale_factor *
                                  visual_properties.compositing_scale_factor;
    widget_base_->LayerTreeHost()->SetExternalPageScaleFactor(
        combined_scale_factor, visual_properties.is_pinch_gesture_active);

    NotifyPageScaleFactorChanged(visual_properties.page_scale_factor,
                                 visual_properties.is_pinch_gesture_active);

    NotifyCompositingScaleFactorChanged(
        visual_properties.compositing_scale_factor);
  } else {
    // Ensure the external scale factor in top-level widgets is reset as it may
    // be leftover from when a widget was nested and was promoted to top level.
    widget_base_->LayerTreeHost()->SetExternalPageScaleFactor(
        1.f,
        /*is_pinch_gesture_active=*/false);
  }

  EventHandler& event_handler = local_root_->GetFrame()->GetEventHandler();
  if (event_handler.cursor_accessibility_scale_factor() !=
      visual_properties.cursor_accessibility_scale_factor) {
    ForEachLocalFrameControlledByWidget(
        local_root_->GetFrame(), [&](WebLocalFrameImpl* local_frame) {
          local_frame->GetFrame()
              ->GetEventHandler()
              .set_cursor_accessibility_scale_factor(
                  visual_properties.cursor_accessibility_scale_factor);
        });
    // Propagate changes down to any child RemoteFrames.
    ForEachRemoteFrameControlledByWidget(
        [scale_factor = visual_properties.cursor_accessibility_scale_factor](
            RemoteFrame* remote_frame) {
          remote_frame->CursorAccessibilityScaleFactorChanged(scale_factor);
        });
  }

  // TODO(crbug.com/939118): This code path where scroll_focused_node_into_view
  // is set is used only for WebView, crbug 939118 tracks fixing webviews to
  // not use scroll_focused_node_into_view.
  if (visual_properties.scroll_focused_node_into_view)
    ScrollFocusedEditableElementIntoView();
}

void WebFrameWidgetImpl::ApplyVisualPropertiesSizing(
    const VisualProperties& visual_properties) {
  gfx::Rect new_compositor_viewport_pixel_rect =
      visual_properties.compositor_viewport_pixel_rect;
  if (ForMainFrame()) {
    if (size_ !=
        widget_base_->DIPsToCeiledBlinkSpace(visual_properties.new_size)) {
      // Only hide popups when the size changes. Eg https://crbug.com/761908.
      View()->CancelPagePopup();
    }

    if (auto* device_emulator = DeviceEmulator()) {
      device_emulator->UpdateVisualProperties(visual_properties);
      return;
    }

    if (AutoResizeMode()) {
      new_compositor_viewport_pixel_rect = gfx::Rect(gfx::ScaleToCeiledSize(
          widget_base_->BlinkSpaceToFlooredDIPs(size_.value_or(gfx::Size())),
          visual_properties.screen_infos.current().device_scale_factor));
    }
  }

  SetViewportSegments(visual_properties.root_widget_viewport_segments);

  widget_base_->UpdateSurfaceAndScreenInfo(
      visual_properties.local_surface_id.value_or(viz::LocalSurfaceId()),
      new_compositor_viewport_pixel_rect, visual_properties.screen_infos);

  // Store this even when auto-resizing, it is the size of the full viewport
  // used for clipping, and this value is propagated down the Widget
  // hierarchy via the VisualProperties waterfall.
  widget_base_->SetVisibleViewportSizeInDIPs(
      visual_properties.visible_viewport_size);

  virtual_keyboard_resize_height_physical_px_ =
      visual_properties.virtual_keyboard_resize_height_physical_px;
  DCHECK(!virtual_keyboard_resize_height_physical_px_ || ForTopMostMainFrame());

  if (ForMainFrame()) {
    if (!AutoResizeMode()) {
      size_ = widget_base_->DIPsToCeiledBlinkSpace(visual_properties.new_size);

      View()->ResizeWithBrowserControls(
          size_.value(),
          widget_base_->DIPsToCeiledBlinkSpace(
              widget_base_->VisibleViewportSizeInDIPs()),
          visual_properties.browser_controls_params);
    }

#if !BUILDFLAG(IS_ANDROID)
    LocalRootImpl()->GetFrame()->UpdateWindowControlsOverlay(
        visual_properties.window_controls_overlay_rect);
#endif

  } else {
    // Widgets in a WebView's frame tree without a local main frame
    // set the size of the WebView to be the |visible_viewport_size|, in order
    // to limit compositing in (out of process) child frames to what is visible.
    //
    // Note that child frames in the same process/WebView frame tree as the
    // main frame do not do this in order to not clobber the source of truth in
    // the main frame.
    if (!View()->MainFrameImpl()) {
      View()->Resize(widget_base_->DIPsToCeiledBlinkSpace(
          widget_base_->VisibleViewportSizeInDIPs()));
    }

    Resize(widget_base_->DIPsToCeiledBlinkSpace(visual_properties.new_size));
  }
}

bool WebFrameWidgetImpl::DidChangeFullscreenState(
    const VisualProperties& visual_properties) const {
  if (visual_properties.is_fullscreen_granted != is_fullscreen_granted_)
    return true;
  // If changing fullscreen from one display to another, the fullscreen
  // granted state will not change, but we still need to resolve promises
  // by considering this a change.
  return visual_properties.is_fullscreen_granted &&
         widget_base_->screen_infos().current().display_id !=
             visual_properties.screen_infos.current().display_id;
}

int WebFrameWidgetImpl::GetLayerTreeId() {
  if (!View()->does_composite())
    return 0;
  return widget_base_->LayerTreeHost()->GetId();
}

const cc::LayerTreeSettings* WebFrameWidgetImpl::GetLayerTreeSettings() {
  if (!View()->does_composite()) {
    return nullptr;
  }
  return &widget_base_->LayerTreeHost()->GetSettings();
}

void WebFrameWidgetImpl::UpdateBrowserControlsState(
    cc::BrowserControlsState constraints,
    cc::BrowserControlsState current,
    bool animate,
    base::optional_ref<const cc::BrowserControlsOffsetTagsInfo>
        offset_tags_info) {
  DCHECK(View()->does_composite());
  widget_base_->LayerTreeHost()->UpdateBrowserControlsState(
      constraints, current, animate, offset_tags_info);
}

void WebFrameWidgetImpl::SetHaveScrollEventHandlers(bool has_handlers) {
  widget_base_->LayerTreeHost()->SetHaveScrollEventHandlers(has_handlers);
}

void WebFrameWidgetImpl::SetEventListenerProperties(
    cc::EventListenerClass listener_class,
    cc::EventListenerProperties listener_properties) {
  if (widget_base_->WillBeDestroyed()) {
    return;
  }

  widget_base_->LayerTreeHost()->SetEventListenerProperties(
      listener_class, listener_properties);

  if (listener_class == cc::EventListenerClass::kTouchStartOrMove ||
      listener_class == cc::EventListenerClass::kTouchEndOrCancel) {
    bool has_touch_handlers =
        EventListenerProperties(cc::EventListenerClass::kTouchStartOrMove) !=
            cc::EventListenerProperties::kNone ||
        EventListenerProperties(cc::EventListenerClass::kTouchEndOrCancel) !=
            cc::EventListenerProperties::kNone;
    if (!has_touch_handlers_ || *has_touch_handlers_ != has_touch_handlers) {
      has_touch_handlers_ = has_touch_handlers;

      // Set touch event consumers based on whether there are touch event
      // handlers or the page has hit testable scrollbars.
      auto touch_event_consumers = mojom::blink::TouchEventConsumers::New(
          has_touch_handlers, GetPage()->GetScrollbarTheme().AllowsHitTest());
      frame_widget_host_->SetHasTouchEventConsumers(
          std::move(touch_event_consumers));
    }
  } else if (listener_class == cc::EventListenerClass::kPointerRawUpdate) {
    SetHasPointerRawUpdateEventHandlers(listener_properties !=
                                        cc::EventListenerProperties::kNone);
  }
}

cc::EventListenerProperties WebFrameWidgetImpl::EventListenerProperties(
    cc::EventListenerClass listener_class) const {
  return widget_base_->LayerTreeHost()->event_listener_properties(
      listener_class);
}

mojom::blink::DisplayMode WebFrameWidgetImpl::DisplayMode() const {
  return display_mode_;
}

ui::mojom::blink::WindowShowState WebFrameWidgetImpl::WindowShowState() const {
  return window_show_state_;
}

bool WebFrameWidgetImpl::Resizable() const {
  return resizable_;
}

const WebVector<gfx::Rect>& WebFrameWidgetImpl::ViewportSegments() const {
  return viewport_segments_;
}

bool WebFrameWidgetImpl::StartDeferringCommits(base::TimeDelta timeout,
                                               cc::PaintHoldingReason reason) {
  if (!View()->does_composite())
    return false;
  return widget_base_->LayerTreeHost()->StartDeferringCommits(timeout, reason);
}

void WebFrameWidgetImpl::StopDeferringCommits(
    cc::PaintHoldingCommitTrigger triggger) {
  if (!View()->does_composite())
    return;
  widget_base_->LayerTreeHost()->StopDeferringCommits(triggger);
}

std::unique_ptr<cc::ScopedPauseRendering> WebFrameWidgetImpl::PauseRendering() {
  if (!View()->does_composite())
    return nullptr;
  return widget_base_->LayerTreeHost()->PauseRendering();
}

std::optional<int> WebFrameWidgetImpl::GetMaxRenderBufferBounds() const {
  if (!View()->does_composite()) {
    return std::nullopt;
  }
  return widget_base_->GetMaxRenderBufferBounds();
}

std::unique_ptr<cc::ScopedDeferMainFrameUpdate>
WebFrameWidgetImpl::DeferMainFrameUpdate() {
  return widget_base_->LayerTreeHost()->DeferMainFrameUpdate();
}

void WebFrameWidgetImpl::SetBrowserControlsShownRatio(float top_ratio,
                                                      float bottom_ratio) {
  widget_base_->LayerTreeHost()->SetBrowserControlsShownRatio(top_ratio,
                                                              bottom_ratio);
}

void WebFrameWidgetImpl::SetBrowserControlsParams(
    cc::BrowserControlsParams params) {
  widget_base_->LayerTreeHost()->SetBrowserControlsParams(params);
}

void WebFrameWidgetImpl::SynchronouslyCompositeForTesting(
    base::TimeTicks frame_time) {
  widget_base_->LayerTreeHost()->CompositeForTest(frame_time, false,
                                                  base::OnceClosure());
}

void WebFrameWidgetImpl::SetDeviceColorSpaceForTesting(
    const gfx::ColorSpace& color_space) {
  DCHECK(ForMainFrame());
  // We are changing the device color space from the renderer, so allocate a
  // new viz::LocalSurfaceId to avoid surface invariants violations in tests.
  widget_base_->LayerTreeHost()->RequestNewLocalSurfaceId();

  display::ScreenInfos screen_infos = widget_base_->screen_infos();
  for (display::ScreenInfo& screen_info : screen_infos.screen_infos)
    screen_info.display_color_spaces = gfx::DisplayColorSpaces(color_space);
  widget_base_->UpdateScreenInfo(screen_infos);
}

// TODO(665924): Remove direct dispatches of mouse events from
// PointerLockController, instead passing them through EventHandler.
void WebFrameWidgetImpl::PointerLockMouseEvent(
    const WebCoalescedInputEvent& coalesced_event) {
  const WebInputEvent& input_event = coalesced_event.Event();
  const WebMouseEvent& mouse_event =
      static_cast<const WebMouseEvent&>(input_event);
  WebMouseEvent transformed_event =
      TransformWebMouseEvent(local_root_->GetFrameView(), mouse_event);

  AtomicString event_type;
  switch (input_event.GetType()) {
    case WebInputEvent::Type::kMouseDown:
      event_type = event_type_names::kMousedown;
      if (!GetPage() || !GetPage()->GetPointerLockController().GetElement())
        break;
      LocalFrame::NotifyUserActivation(
          GetPage()
              ->GetPointerLockController()
              .GetElement()
              ->GetDocument()
              .GetFrame(),
          mojom::blink::UserActivationNotificationType::kInteraction);
      break;
    case WebInputEvent::Type::kMouseUp:
      event_type = event_type_names::kMouseup;
      break;
    case WebInputEvent::Type::kMouseMove:
      event_type = event_type_names::kMousemove;
      break;
    case WebInputEvent::Type::kMouseEnter:
    case WebInputEvent::Type::kMouseLeave:
    case WebInputEvent::Type::kContextMenu:
      // These should not be normally dispatched but may be due to timing
      // because pointer lost messaging happens on separate mojo channel.
      return;
    default:
      NOTREACHED() << input_event.GetType();
  }

  if (GetPage()) {
    GetPage()->GetPointerLockController().DispatchLockedMouseEvent(
        transformed_event,
        TransformWebMouseEventVector(
            local_root_->GetFrameView(),
            coalesced_event.GetCoalescedEventsPointers()),
        TransformWebMouseEventVector(
            local_root_->GetFrameView(),
            coalesced_event.GetPredictedEventsPointers()),
        event_type);
  }
}
bool WebFrameWidgetImpl::IsPointerLocked() {
  if (GetPage()) {
    return GetPage()->GetPointerLockController().IsPointerLocked();
  }
  return false;
}

void WebFrameWidgetImpl::ShowContextMenu(
    ui::mojom::blink::MenuSourceType source_type,
    const gfx::Point& location) {
  host_context_menu_location_ = location;

  if (!GetPage())
    return;
  GetPage()->GetContextMenuController().ClearContextMenu();
  {
    ContextMenuAllowedScope scope;
    if (LocalFrame* focused_frame =
            GetPage()->GetFocusController().FocusedFrame()) {
      focused_frame->GetEventHandler().ShowNonLocatedContextMenu(
          nullptr, static_cast<blink::WebMenuSourceType>(source_type));
    }
  }
  host_context_menu_location_.reset();
}

void WebFrameWidgetImpl::SetViewportIntersection(
    mojom::blink::ViewportIntersectionStatePtr intersection_state,
    const std::optional<VisualProperties>& visual_properties) {
  // Remote viewports are only applicable to local frames with remote ancestors.
  DCHECK(ForSubframe() || !LocalRootImpl()->GetFrame()->IsOutermostMainFrame());

  if (visual_properties.has_value())
    UpdateVisualProperties(visual_properties.value());
  ApplyViewportIntersection(std::move(intersection_state));
}

void WebFrameWidgetImpl::ApplyViewportIntersectionForTesting(
    mojom::blink::ViewportIntersectionStatePtr intersection_state) {
  ApplyViewportIntersection(std::move(intersection_state));
}

void WebFrameWidgetImpl::ApplyViewportIntersection(
    mojom::blink::ViewportIntersectionStatePtr intersection_state) {
  if (ForSubframe()) {
    // This information is propagated to LTH to define the region for filling
    // the on-screen text content.
    // TODO(khushalsagar) : This needs to also be done for main frames which are
    // embedded pages (see Frame::IsOutermostMainFrame()).
    child_data().compositor_visible_rect =
        intersection_state->compositor_visible_rect;
    widget_base_->LayerTreeHost()->SetVisualDeviceViewportIntersectionRect(
        intersection_state->compositor_visible_rect);
  }
  LocalRootImpl()->GetFrame()->SetViewportIntersectionFromParent(
      *intersection_state);
}

void WebFrameWidgetImpl::EnableDeviceEmulation(
    const DeviceEmulationParams& parameters) {
  // Device Emaulation is only supported for the main frame.
  DCHECK(ForMainFrame());
  if (!device_emulator_) {
    gfx::Size size_in_dips = widget_base_->BlinkSpaceToFlooredDIPs(Size());

    device_emulator_ = MakeGarbageCollected<ScreenMetricsEmulator>(
        this, widget_base_->screen_infos(), size_in_dips,
        widget_base_->VisibleViewportSizeInDIPs(),
        widget_base_->WidgetScreenRect(), widget_base_->WindowScreenRect());
  }
  device_emulator_->ChangeEmulationParams(parameters);
}

void WebFrameWidgetImpl::DisableDeviceEmulation() {
  if (!device_emulator_)
    return;
  device_emulator_->DisableAndApply();
  device_emulator_ = nullptr;
}

void WebFrameWidgetImpl::SetIsInertForSubFrame(bool inert) {
  DCHECK(ForSubframe());
  LocalRootImpl()->GetFrame()->SetIsInert(inert);
}

std::optional<gfx::Point> WebFrameWidgetImpl::GetAndResetContextMenuLocation() {
  return std::move(host_context_menu_location_);
}

double WebFrameWidgetImpl::GetZoomLevel() {
  return zoom_level_;
}

void WebFrameWidgetImpl::SetZoomLevel(double zoom_level) {
  SetZoomInternal(zoom_level, css_zoom_factor_);
}

// There are four main values that go into zoom arithmetic:
//
// - "zoom level", a log-based value which represents the zoom level from the
//   browser UI. The log base for zoom level is kTextSizeMultiplierRatio.
// - "css zoom factor", which represents the effect of the CSS "zoom" property
//   applied to the embedding point (e.g. <iframe>) of this widget, if any. For
//   a top-level widget this is 1.0.
// - Hardware device scale factor, which is stored on WebViewImpl as
//   zoom_factor_for_device_scale_factor_.
// - "layout zoom factor", which is calculated from the previous three values,
//   with override mechanisms for testing and device emulation. This is the
//   value that is used by the rendering system.
void WebFrameWidgetImpl::SetZoomInternal(double zoom_level,
                                         double css_zoom_factor) {
  zoom_level = View()->ClampZoomLevel(zoom_level);
  if (zoom_level_for_testing_ != -INFINITY) {
    zoom_level = zoom_level_for_testing_;
  }
  bool zoom_changed =
      (zoom_level != zoom_level_ || css_zoom_factor != css_zoom_factor_);
  zoom_level_ = zoom_level;
  css_zoom_factor_ = css_zoom_factor;

  if (auto* local_frame = LocalRootImpl()->GetFrame()) {
    if (Document* document = local_frame->GetDocument()) {
      double layout_zoom_factor = View()->ZoomFactorForViewportLayout() *
                                  View()->ZoomLevelToZoomFactor(zoom_level) *
                                  css_zoom_factor;
      if (zoom_changed) {
        // Set the layout shift exclusion window for the zoom level change.
        if (LocalFrameView* view = document->View()) {
          view->GetLayoutShiftTracker().NotifyZoomLevelChanged();
#if BUILDFLAG(IS_ANDROID)
          if (ForTopMostMainFrame()) {
            // Zoom levels are the exponent in the calculation of zoom. The zoom
            // factor is the value shown to the user (e.g. 50% to 300%).
            UMA_HISTOGRAM_CUSTOM_EXACT_LINEAR(
                "Accessibility.Android.PageZoom.MainFrameZoomFactor",
                layout_zoom_factor * 100, 50, 300, 52);
          }
#endif
        }
      }

      // layout_zoom_factor may have changed even if !zoom_changed, so we
      // unconditionally propagate to the local root frame.
      auto* plugin_document = DynamicTo<PluginDocument>(document);
      if (!plugin_document || !plugin_document->GetPluginView()) {
        // The local root is responsible for propagating to its connected tree
        // of Frame descendants.
        local_frame->SetLayoutZoomFactor(layout_zoom_factor);
      }
    }
  }
}

void WebFrameWidgetImpl::SetAutoResizeMode(bool auto_resize,
                                           const gfx::Size& min_window_size,
                                           const gfx::Size& max_window_size,
                                           float device_scale_factor) {
  // Auto resize only applies to main frames.
  DCHECK(ForMainFrame());

  if (auto_resize) {
    View()->EnableAutoResizeMode(
        gfx::ScaleToCeiledSize(min_window_size, device_scale_factor),
        gfx::ScaleToCeiledSize(max_window_size, device_scale_factor));
  } else if (AutoResizeMode()) {
    View()->DisableAutoResizeMode();
  }
}

void WebFrameWidgetImpl::DidAutoResize(const gfx::Size& size) {
  DCHECK(ForMainFrame());
  gfx::Size size_in_dips = widget_base_->BlinkSpaceToFlooredDIPs(size);
  size_ = size;

  // TODO(ccameron): Note that this destroys any information differentiating
  // |size| from the compositor's viewport size.
  gfx::Rect size_with_dsf = gfx::Rect(gfx::ScaleToCeiledSize(
      gfx::Rect(size_in_dips).size(),
      widget_base_->GetScreenInfo().device_scale_factor));
  widget_base_->LayerTreeHost()->RequestNewLocalSurfaceId();
  widget_base_->UpdateCompositorViewportRect(size_with_dsf);
}

LocalFrame* WebFrameWidgetImpl::FocusedLocalFrameInWidget() const {
  if (!local_root_) {
    // WebFrameWidget is created in the call to CreateFrame. The corresponding
    // RenderWidget, however, might not swap in right away (InstallNewDocument()
    // will lead to it swapping in). During this interval local_root_ is nullptr
    // (see https://crbug.com/792345).
    return nullptr;
  }

  LocalFrame* frame = GetPage()->GetFocusController().FocusedFrame();
  return (frame && frame->LocalFrameRoot() == local_root_->GetFrame())
             ? frame
             : nullptr;
}

WebLocalFrameImpl* WebFrameWidgetImpl::FocusedWebLocalFrameInWidget() const {
  return WebLocalFrameImpl::FromFrame(FocusedLocalFrameInWidget());
}

bool WebFrameWidgetImpl::ScrollFocusedEditableElementIntoView() {
  Element* element = FocusedElement();
  if (!element)
    return false;

  EditContext* edit_context = element->GetDocument()
                                  .GetFrame()
                                  ->GetInputMethodController()
                                  .GetActiveEditContext();

  if (!WebElement(element).IsEditable() && !edit_context)
    return false;

  element->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kSelection);

  if (!element->GetLayoutObject())
    return false;

  // The page scale animation started by ZoomAndScrollToFocusedEditableRect
  // will scroll only the visual and layout viewports. Call ScrollRectToVisible
  // first to ensure the editable is visible within the document (i.e. scroll
  // it into view in any subscrollers). By setting `for_focused_editable`,
  // ScrollRectToVisible will stop bubbling when it reaches the layout viewport
  // so that can be animated by the PageScaleAnimation.
  mojom::blink::ScrollIntoViewParamsPtr params =
      scroll_into_view_util::CreateScrollIntoViewParams(
          ScrollAlignment::CenterIfNeeded(), ScrollAlignment::CenterIfNeeded(),
          mojom::blink::ScrollType::kProgrammatic,
          /*make_visible_in_visual_viewport=*/false,
          mojom::blink::ScrollBe
```