Response:
My thought process to analyze the C++ code and generate the explanation went something like this:

1. **Understand the Core Purpose:** The file name `web_test_web_frame_widget_impl.cc` immediately suggests this is a *test implementation* of a `WebFrameWidget`. The `web_test` part is key. This isn't production code; it's for web browser testing.

2. **Identify Key Inheritance and Relationships:**  The `#include` statements are crucial. They reveal the class inherits from `WebFrameWidgetImpl` and interacts with various other Blink components like `WebLocalFrame`, `WebView`, `EventHandler`, `LayerTreeHost`, and crucially, `content::TestRunner` and `content::EventSender`. This points to its role in simulating browser behavior for testing.

3. **Analyze the Constructor and `CreateTestWebFrameWidget`:** These functions show how instances of `WebTestWebFrameWidgetImpl` are created. The parameters reveal what data is needed:  Mojo interfaces for communication (frame and widget hosts/receivers), task runner, frame sink ID, visibility flags, and the `TestRunner`. This confirms its integration into the testing framework.

4. **Focus on Overridden Methods:**  The most informative parts are the overridden methods from `WebFrameWidgetImpl`. I went through each one, asking "Why is this overridden here?"

    * **`BindLocalRoot`:**  The comment highlights the crucial addition of `event_sender_` initialization *after* binding the local root. This suggests a dependency related to the frame being ready.

    * **`WillBeginMainFrame`:**  The comment clearly states the purpose: to call `FinishTestIfReady` *before* the base class method. This directly ties into the web testing lifecycle.

    * **`ScheduleAnimation` and `ScheduleAnimationForWebTests`:**  The distinction between these two is important. The web test version forces rasterization, indicating a need for immediate visual updates in the test environment. The comment about single-threaded web tests reinforces this.

    * **`WasShown`:** The logic around `animation_deferred_while_hidden_` is interesting. It shows how the test environment handles animations when a frame becomes visible.

    * **`UpdateAllLifecyclePhasesAndComposite`:** This method explicitly triggers a composite and uses a presentation time callback, demonstrating control over the rendering pipeline for testing.

    * **`ScheduleAnimationInternal`:**  The conditional logic based on `Thread::CompositorThread()` reveals how animation scheduling differs between threaded and single-threaded compositing in the test environment.

    * **`RequestedMainFramePending`:**  Again, the distinction based on compositing thread is important for understanding how the test environment tracks pending main frame updates.

    * **`StartDragging`:** The check for `AutomaticDragDropEnabled()` and the use of `event_sender_->DoDragDrop` highlights the simulation of drag-and-drop operations in tests.

    * **`Reset`:**  This method is clearly for cleaning up state after a test, involving resetting the event sender, edit commands, zoom level, and mouse position.

    * **`SynchronouslyCompositeAfterTest` and `SynchronouslyComposite`:** These methods provide fine-grained control over the compositing process, crucial for deterministic testing. The handling of popups is a detail to note.

    * **`AnimateNow`:** This method drives the animation process in the single-threaded test environment.

    * **`RequestDecode`:**  The explicit call to `ScheduleAnimationForWebTests` after requesting a decode shows how to trigger a frame update in the test context.

    * **`DidAutoResize`:** The special handling for single-threaded compositing to set the window rect demonstrates how the test environment compensates for differences in rendering behavior.

5. **Identify Connections to Web Technologies:**  While the code itself is C++, its purpose is to test web rendering. I looked for places where it directly interacts with or simulates concepts from JavaScript, HTML, and CSS:

    * **JavaScript:** Animation scheduling (`ScheduleAnimation`), event handling (`EventSender`), drag and drop.
    * **HTML:** Frame structure (`WebLocalFrame`), viewports/size (`DidAutoResize`), potentially visibility (`WasShown`).
    * **CSS:**  The compositing and rendering aspects are closely related to how CSS styles are applied and rendered. The `SetNeedsCommitWithForcedRedraw()` suggests forcing a style recalculation and repaint.

6. **Consider Logical Reasoning and Assumptions:**  The code makes assumptions about the test environment. For example, it assumes the existence of a `TestRunner` and `EventSender`. The logic in `ScheduleAnimationInternal` makes different choices based on whether compositing is threaded or not. This requires understanding the different test configurations.

7. **Think About Common Usage Errors:** Since this is a testing class, potential "errors" are more about misunderstandings of how to use the testing framework. For example, not understanding why `ScheduleAnimationForWebTests` is needed in single-threaded tests, or not realizing that drag-and-drop is simulated.

8. **Structure the Explanation:** I aimed for a clear and organized explanation, starting with the overall purpose and then diving into specifics. I used headings and bullet points to improve readability and included examples to illustrate the connections to web technologies. I also specifically addressed the points requested in the prompt: functionality, relationships to web technologies, logical reasoning, and common usage errors (or misunderstandings in this case).

By following these steps, I could dissect the C++ code and generate a comprehensive explanation of its functionality within the context of Chromium's web testing framework.
这个文件 `web_test_web_frame_widget_impl.cc` 是 Chromium Blink 渲染引擎的一部分，专门用于 **Web 测试环境**。它提供了一个 `WebFrameWidget` 接口的测试实现，用于模拟和控制网页框架的渲染和交互行为，以便进行自动化测试。

**核心功能:**

1. **创建和管理测试用的 WebFrameWidget:**  `CreateTestWebFrameWidget` 函数负责创建 `WebTestWebFrameWidgetImpl` 的实例。这个类继承自 `WebFrameWidgetImpl`，并添加了专门用于测试的功能。

2. **集成测试框架:**  该类与 `content::TestRunner` 和 `content::EventSender` 紧密集成。`TestRunner` 用于控制测试的生命周期和收集测试结果，而 `EventSender` 则用于模拟用户输入事件（例如鼠标点击、键盘输入）和拖放操作。

3. **控制渲染流程:**  `WebTestWebFrameWidgetImpl` 允许更细粒度地控制渲染流程，例如强制提交和合成图层 (`ScheduleAnimationForWebTests`, `SynchronouslyComposite`)，这在测试需要精确控制帧生成时非常有用。

4. **模拟用户交互:** 通过 `EventSender`，可以模拟各种用户交互，例如点击、滚动、键盘输入和拖放，用于测试网页对这些交互的响应。

5. **提供测试辅助方法:**  例如 `Reset` 方法用于在测试结束后重置 widget 的状态，确保测试的独立性。`GetEventSender` 可以获取用于发送事件的 `EventSender` 实例。

6. **处理动画:** 提供了 `ScheduleAnimation` 和 `ScheduleAnimationForWebTests` 方法来处理动画的调度，尤其是在测试环境中需要更精确地控制动画帧的生成。

7. **处理显示和隐藏:**  `WasShown` 方法用于处理 widget 显示时的行为，例如恢复被延迟的动画。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`WebTestWebFrameWidgetImpl` 的主要目的是测试网页的渲染和交互，因此它与 JavaScript, HTML, 和 CSS 有着密切的关系：

* **JavaScript:**
    * **模拟事件触发:** `EventSender` 可以模拟 JavaScript 事件，例如 `click`，`mouseover`，`keydown` 等。
        * **假设输入:**  JavaScript 代码监听了按钮的 `click` 事件，当点击时会修改页面文本。
        * **测试代码:**  使用 `event_sender_->Click(x, y)` 模拟点击按钮。
        * **预期输出:** 页面文本被修改。
    * **控制动画:**  测试代码可以调用 `ScheduleAnimationForWebTests` 来触发 JavaScript 使用 `requestAnimationFrame` 创建的动画。
        * **假设输入:** JavaScript 代码使用 `requestAnimationFrame` 创建了一个简单的动画。
        * **测试代码:** 调用 `ScheduleAnimationForWebTests` 来推进动画的帧。
        * **预期输出:** 动画的下一帧被渲染出来。
    * **测试拖放:** `StartDragging` 方法与 `event_sender_->DoDragDrop` 结合使用，可以模拟 HTML5 的拖放 API。
        * **假设输入:** HTML 页面实现了拖放功能。
        * **测试代码:** 使用 `StartDragging` 发起拖动，然后使用 `event_sender_->DoDragDrop` 模拟释放。
        * **预期输出:** 拖放操作的 JavaScript 处理程序被调用。

* **HTML:**
    * **测试页面结构和渲染:**  `WebTestWebFrameWidgetImpl` 渲染由 HTML 构建的页面结构。测试可以验证特定 HTML 元素是否正确渲染。
        * **假设输入:** HTML 包含一个 `<div>` 元素，其 `id` 为 "myDiv"。
        * **测试代码:**  虽然 `WebTestWebFrameWidgetImpl` 本身不直接操作 DOM，但其渲染结果可以通过其他测试机制（例如像素测试）来验证 `myDiv` 是否存在并位于正确的位置。
    * **测试表单交互:**  可以使用 `EventSender` 模拟用户在 HTML 表单中的输入和提交操作。
        * **假设输入:** HTML 包含一个 `<input>` 元素和一个 `<button>` 元素。
        * **测试代码:** 使用 `event_sender_->SetTextFieldValue` 设置输入框的值，然后使用 `event_sender_->Click` 点击按钮。
        * **预期输出:** 表单被提交，或者触发相应的 JavaScript 处理程序。

* **CSS:**
    * **测试样式应用和布局:** `WebTestWebFrameWidgetImpl` 负责根据 CSS 规则渲染页面的样式和布局。
        * **假设输入:** CSS 规则设置了某个元素的背景颜色为红色。
        * **测试代码:**  可以通过像素测试来验证该元素的背景颜色是否为红色。
    * **测试媒体查询:** 可以通过调整窗口大小或设备像素比等参数，来测试 CSS 媒体查询是否按预期生效。
        * **假设输入:** CSS 包含一个当屏幕宽度小于 600px 时将某个元素的宽度设置为 100px 的媒体查询。
        * **测试代码:**  设置一个小于 600px 的视口大小。
        * **预期输出:**  该元素的宽度被渲染为 100px。

**逻辑推理的假设输入与输出:**

* **假设输入:**  调用 `ScheduleAnimationForWebTests()`。
* **逻辑推理:**  该方法会设置 `composite_requested_` 为 `true`，并如果动画未被调度，则会向内部测试任务队列提交一个延时任务来调用 `AnimateNow()`。
* **预期输出:** 在单线程测试环境中，经过一段延迟后，`AnimateNow()` 会被调用，它会触发同步合成 (`SynchronouslyComposite`)，强制渲染下一帧。

* **假设输入:**  调用 `StartDragging` 并且 `GetTestRunner()->AutomaticDragDropEnabled()` 返回 `true`.
* **逻辑推理:**  代码会设置 `doing_drag_and_drop_` 为 `true`，并调用 `GetTestRunner()->SetDragImage` 设置拖动图像，然后调用 `event_sender_->DoDragDrop` 模拟拖放操作。
* **预期输出:**  模拟的拖放事件被发送，可以触发页面上的 JavaScript 拖放处理程序。

**涉及用户或编程常见的使用错误:**

由于这是一个测试框架的内部实现，直接的用户使用错误较少。更多的是在编写 web 测试时可能出现的错误：

* **没有正确理解 `ScheduleAnimation` 和 `ScheduleAnimationForWebTests` 的区别:** 在单线程测试中，仅仅调用 `ScheduleAnimation` 可能不会立即触发合成，导致测试无法按预期进行。应该使用 `ScheduleAnimationForWebTests` 来强制合成。
* **忘记在测试结束后 `Reset` widget 状态:** 这可能导致测试之间相互影响，产生难以调试的错误。例如，一个测试中设置的缩放级别可能会影响后续的测试。
* **在异步操作完成前就检查结果:** 例如，模拟点击一个按钮后，如果按钮的操作是异步的，测试代码需要等待操作完成后再检查页面状态，否则可能会得到错误的结果。`SynchronouslyComposite` 可以用于确保渲染完成。
* **没有考虑到测试环境的特殊性:**  例如，拖放操作在测试环境中是被模拟的，而不是真实的操作系统拖放。编写测试时需要考虑到这一点。
* **过度依赖于实现细节:**  测试应该关注最终的用户可见行为，而不是底层的实现细节。过度依赖于 `WebTestWebFrameWidgetImpl` 的内部行为可能会导致测试脆弱，当 Chromium 内部实现改变时容易失效。

总而言之，`web_test_web_frame_widget_impl.cc` 是 Blink 渲染引擎测试基础设施的关键组成部分，它允许开发者编写细粒度的、可控的 web 页面行为测试，确保 Chromium 的渲染和交互功能的正确性。

### 提示词
```
这是目录为blink/renderer/core/web_test/web_test_web_frame_widget_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/web_test/web_test_web_frame_widget_impl.h"

#include "base/task/single_thread_task_runner.h"
#include "content/web_test/renderer/event_sender.h"
#include "content/web_test/renderer/test_runner.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/web/web_frame_widget.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_page_popup.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/blink/public/web/web_widget.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"

namespace blink {

WebFrameWidget* FrameWidgetTestHelper::CreateTestWebFrameWidget(
    base::PassKey<WebLocalFrame> pass_key,
    CrossVariantMojoAssociatedRemote<mojom::blink::FrameWidgetHostInterfaceBase>
        frame_widget_host,
    CrossVariantMojoAssociatedReceiver<mojom::blink::FrameWidgetInterfaceBase>
        frame_widget,
    CrossVariantMojoAssociatedRemote<mojom::blink::WidgetHostInterfaceBase>
        widget_host,
    CrossVariantMojoAssociatedReceiver<mojom::blink::WidgetInterfaceBase>
        widget,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    const viz::FrameSinkId& frame_sink_id,
    bool hidden,
    bool never_composited,
    bool is_for_child_local_root,
    bool is_for_nested_main_frame,
    bool is_for_scalable_page,
    content::TestRunner* test_runner) {
  return MakeGarbageCollected<WebTestWebFrameWidgetImpl>(
      pass_key, std::move(frame_widget_host), std::move(frame_widget),
      std::move(widget_host), std::move(widget), std::move(task_runner),
      frame_sink_id, hidden, never_composited, is_for_child_local_root,
      is_for_nested_main_frame, is_for_scalable_page, test_runner);
}

WebTestWebFrameWidgetImpl::WebTestWebFrameWidgetImpl(
    base::PassKey<WebLocalFrame> pass_key,
    CrossVariantMojoAssociatedRemote<mojom::blink::FrameWidgetHostInterfaceBase>
        frame_widget_host,
    CrossVariantMojoAssociatedReceiver<mojom::blink::FrameWidgetInterfaceBase>
        frame_widget,
    CrossVariantMojoAssociatedRemote<mojom::blink::WidgetHostInterfaceBase>
        widget_host,
    CrossVariantMojoAssociatedReceiver<mojom::blink::WidgetInterfaceBase>
        widget,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    const viz::FrameSinkId& frame_sink_id,
    bool hidden,
    bool never_composited,
    bool is_for_child_local_root,
    bool is_for_nested_main_frame,
    bool is_for_scalable_page,
    content::TestRunner* test_runner)
    : WebFrameWidgetImpl(pass_key,
                         std::move(frame_widget_host),
                         std::move(frame_widget),
                         std::move(widget_host),
                         std::move(widget),
                         std::move(task_runner),
                         frame_sink_id,
                         hidden,
                         never_composited,
                         is_for_child_local_root,
                         is_for_nested_main_frame,
                         is_for_scalable_page),
      test_runner_(test_runner) {}

WebTestWebFrameWidgetImpl::~WebTestWebFrameWidgetImpl() = default;

void WebTestWebFrameWidgetImpl::BindLocalRoot(WebLocalFrame& local_root) {
  WebFrameWidgetImpl::BindLocalRoot(local_root);
  // We need to initialize EventSender after the binding of the local root
  // as the EventSender constructor accesses LocalRoot and that is not
  // set until BindLocalRoot is called.
  event_sender_ = std::make_unique<content::EventSender>(this, test_runner_);
}

void WebTestWebFrameWidgetImpl::WillBeginMainFrame() {
  // WillBeginMainFrame occurs before we run BeginMainFrame() in the base
  // class, which will change states. TestFinished() wants to grab the current
  // state.
  GetTestRunner()->FinishTestIfReady(*LocalRootImpl());

  WebFrameWidgetImpl::WillBeginMainFrame();
}

void WebTestWebFrameWidgetImpl::ScheduleAnimation() {
  ScheduleAnimationInternal(GetTestRunner()->animation_requires_raster());
}

void WebTestWebFrameWidgetImpl::ScheduleAnimationForWebTests() {
  // Single threaded web tests must explicitly schedule commits.
  //
  // Pass true for |do_raster| to ensure the compositor is actually run, rather
  // than just doing the main frame animate step. That way we know it will
  // submit a frame and later trigger the presentation callback in order to make
  // progress in the test.
  ScheduleAnimationInternal(/*do_raster=*/true);
}

void WebTestWebFrameWidgetImpl::WasShown(bool was_evicted) {
  WebFrameWidgetImpl::WasShown(was_evicted);

  if (animation_deferred_while_hidden_) {
    animation_deferred_while_hidden_ = false;
    ScheduleAnimationInternal(composite_requested_);
  }
}

void WebTestWebFrameWidgetImpl::UpdateAllLifecyclePhasesAndComposite(
    base::OnceClosure callback) {
  LayerTreeHost()->RequestSuccessfulPresentationTimeForNextFrame(
      base::IgnoreArgs<const viz::FrameTimingDetails&>(std::move(callback)));
  LayerTreeHost()->SetNeedsCommitWithForcedRedraw();
  ScheduleAnimationForWebTests();
}

void WebTestWebFrameWidgetImpl::ScheduleAnimationInternal(bool do_raster) {
  if (!GetTestRunner()->TestIsRunning()) {
    return;
  }

  // When using threaded compositing, have the WeFrameWidgetImpl normally
  // schedule a request for a frame, as we use the compositor's scheduler.
  if (Thread::CompositorThread()) {
    WebFrameWidgetImpl::ScheduleAnimation();
    return;
  }

  // If an animation already scheduled we'll make it composite, otherwise we'll
  // schedule another animation step with composite now.
  composite_requested_ |= do_raster;

  if (!animation_scheduled_) {
    animation_scheduled_ = true;

    WebLocalFrame* frame = LocalRoot();

    frame->GetTaskRunner(TaskType::kInternalTest)
        ->PostDelayedTask(FROM_HERE,
                          WTF::BindOnce(&WebTestWebFrameWidgetImpl::AnimateNow,
                                        WrapWeakPersistent(this)),
                          base::Milliseconds(1));
  }
}

bool WebTestWebFrameWidgetImpl::RequestedMainFramePending() {
  if (Thread::CompositorThread()) {
    return WebFrameWidgetImpl::RequestedMainFramePending();
  }
  return animation_scheduled_;
}

void WebTestWebFrameWidgetImpl::StartDragging(
    LocalFrame* source_frame,
    const WebDragData& data,
    DragOperationsMask mask,
    const SkBitmap& drag_image,
    const gfx::Vector2d& cursor_offset,
    const gfx::Rect& drag_obj_rect) {
  if (!GetTestRunner()->AutomaticDragDropEnabled()) {
    return WebFrameWidgetImpl::StartDragging(
        source_frame, data, mask, drag_image, cursor_offset, drag_obj_rect);
  }

  // When running a test, we need to fake a drag drop operation otherwise
  // Windows waits for real mouse events to know when the drag is over.
  doing_drag_and_drop_ = true;
  GetTestRunner()->SetDragImage(drag_image);
  event_sender_->DoDragDrop(data, mask);
}

FrameWidgetTestHelper*
WebTestWebFrameWidgetImpl::GetFrameWidgetTestHelperForTesting() {
  return this;
}

void WebTestWebFrameWidgetImpl::Reset() {
  event_sender_->Reset();

  // Ends any synthetic gestures started in |event_sender_|.
  FlushInputProcessedCallback();

  // Reset state in the  base class.
  ClearEditCommands();

  SetDeviceScaleFactorForTesting(0);
  ReleaseMouseLockAndPointerCaptureForTesting();

  // These things are only modified/valid for the main frame's widget.
  if (ForMainFrame()) {
    ResetZoomLevelForTesting();

    SetMainFrameOverlayColor(SK_ColorTRANSPARENT);
    SetTextZoomFactor(1);
    LocalRootImpl()
        ->GetFrame()
        ->GetEventHandler()
        .ResetLastMousePositionForWebTest();
  }
}

content::EventSender* WebTestWebFrameWidgetImpl::GetEventSender() {
  return event_sender_.get();
}

void WebTestWebFrameWidgetImpl::SynchronouslyCompositeAfterTest(
    base::OnceClosure callback) {
  // We could DCHECK(!GetTestRunner()->TestIsRunning()) except that frames in
  // other processes than the main frame do not hear when the test ends.

  // This would be very weird and prevent us from producing pixels.
  DCHECK(!in_synchronous_composite_);

  SynchronouslyComposite(std::move(callback), /*do_raster=*/true);
}

content::TestRunner* WebTestWebFrameWidgetImpl::GetTestRunner() {
  return test_runner_;
}

// static
void WebTestWebFrameWidgetImpl::DoComposite(cc::LayerTreeHost* layer_tree_host,
                                            bool do_raster,
                                            base::OnceClosure callback) {
  // Ensure that there is damage so that the compositor submits, and the display
  // compositor draws this frame.
  if (do_raster) {
    layer_tree_host->SetNeedsCommitWithForcedRedraw();
  }

  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), do_raster,
                                    std::move(callback));
}

void WebTestWebFrameWidgetImpl::SynchronouslyComposite(
    base::OnceClosure callback,
    bool do_raster) {
  if (!LocalRootImpl()->ViewImpl()->does_composite()) {
    if (callback) {
      std::move(callback).Run();
    }
    return;
  }
  DCHECK(!LayerTreeHost()->GetSettings().single_thread_proxy_scheduler);

  if (!LayerTreeHost()->IsVisible()) {
    if (callback) {
      std::move(callback).Run();
    }
    return;
  }

  if (base::FeatureList::IsEnabled(
          blink::features::kNoForcedFrameUpdatesForWebTests) &&
      LayerTreeHost()->MainFrameUpdatesAreDeferred()) {
    if (callback) {
      std::move(callback).Run();
    }
    return;
  }

  if (in_synchronous_composite_) {
    // Web tests can use a nested message loop to pump frames while inside a
    // frame, but the compositor does not support this. In this case, we only
    // run blink's lifecycle updates.
    UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
    if (callback) {
      std::move(callback).Run();
    }
    return;
  }

  in_synchronous_composite_ = true;

  auto wrapped_callback = WTF::BindOnce(
      [](base::OnceClosure cb, bool* in_synchronous_composite) {
        *in_synchronous_composite = false;
        if (cb) {
          std::move(cb).Run();
        }
      },
      // base::Unretained is safe by construction, because WebFrameWidgetImpl
      // must always outlive the compositing machinery.
      std::move(callback), base::Unretained(&in_synchronous_composite_));

  // If there's a visible popup, then we will update its compositing after
  // updating the host frame.
  WebPagePopupImpl* popup = LocalRootImpl()->ViewImpl()->GetPagePopup();

  if (!popup) {
    DoComposite(LayerTreeHost(), do_raster, std::move(wrapped_callback));
    return;
  }

  DoComposite(LayerTreeHost(), do_raster, base::OnceClosure());

  // DoComposite() can detach the frame, in which case we don't update the
  // popup. Because DoComposite was called with a no-op callback, we need to run
  // the actual callback here.
  if (!LocalRoot()) {
    std::move(wrapped_callback).Run();
    return;
  }

  DoComposite(popup->LayerTreeHostForTesting(), do_raster,
              std::move(wrapped_callback));
}

void WebTestWebFrameWidgetImpl::AnimateNow() {
  // If we have been Closed but not destroyed yet, return early.
  if (!LocalRootImpl()) {
    return;
  }

  animation_scheduled_ = false;

  if (LocalRootImpl()->ViewImpl()->does_composite() &&
      !LayerTreeHost()->IsVisible()) {
    // If the widget is hidden, SynchronouslyComposite will early-out which may
    // leave a test waiting (e.g. waiting on a requestAnimationFrame). Setting
    // this bit will reschedule the animation request when the widget becomes
    // visible.
    animation_deferred_while_hidden_ = true;
    return;
  }

  bool do_raster = composite_requested_;
  composite_requested_ = false;
  // Composite may destroy |this|, so don't use it afterward.
  SynchronouslyComposite(base::OnceClosure(), do_raster);
}

void WebTestWebFrameWidgetImpl::RequestDecode(
    const PaintImage& image,
    base::OnceCallback<void(bool)> callback) {
  WebFrameWidgetImpl::RequestDecode(image, std::move(callback));

  // In web tests the request does not actually cause a commit, because the
  // compositor is scheduled by the test runner to avoid flakiness. So for this
  // case we must request a main frame.
  ScheduleAnimationForWebTests();
}

void WebTestWebFrameWidgetImpl::DidAutoResize(const gfx::Size& size) {
  WebFrameWidgetImpl::DidAutoResize(size);

  // Window rect resize for threaded compositing is delivered via requesting a
  // new surface. The browser then reacts to the bounds of the surface changing
  // and adjusts the WindowRect. For single threaded compositing the
  // surface size is never processed so we force the WindowRect to be the
  // same size as the WidgetSize when AutoResize is applied.
  if (LayerTreeHost()->IsSingleThreaded()) {
    gfx::Rect new_pos(Size());
    SetWindowRect(new_pos, new_pos);
  }
}

}  // namespace blink
```