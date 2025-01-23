Response:
Let's break down the thought process for analyzing the `layer_tree_view.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the `LayerTreeView` class, its relation to web technologies (JavaScript, HTML, CSS), potential logic inference with examples, and common usage errors.

2. **Initial Scan and Keyword Identification:**  Quickly read through the code, looking for keywords and class names that provide hints about its purpose. Some immediate takeaways:
    * `LayerTreeView`: The core class. Likely manages a tree of layers.
    * `compositing`:  Indicates involvement in the compositing process.
    * `cc::LayerTreeHost`:  A crucial dependency, suggesting this class acts as an intermediary.
    * `delegate`:  Suggests a delegation pattern, where `LayerTreeView` informs another object (`LayerTreeViewDelegate`) about events.
    * `FrameSink`, `RenderFrameMetadataObserver`:  Related to the output and synchronization of frames.
    * `SetVisible`, `UpdateLayers`, `BeginMainFrame`, `DidCommit`:  These look like lifecycle methods or event handlers in a rendering pipeline.
    * `animation`:  Mentions of `cc::AnimationHost`.
    * `ukm`:  Integration with user metrics.
    * `widget_scheduler`:  Interaction with a scheduler.

3. **Core Functionality -  The Big Picture:** Based on the keywords, the central purpose seems to be managing the compositing layer tree for a part of the web page (a "widget"). It acts as a bridge between the Blink rendering engine and the Chromium Compositor (`cc`).

4. **Identifying Key Responsibilities (Function Grouping):**  Go through the methods and group them by their apparent purpose. This helps to structure the explanation:
    * **Initialization and Setup:** `LayerTreeView`, `Initialize`, `Disconnect`, `ClearPreviousDelegateAndReattachIfNeeded`. These manage the lifecycle and setup of the `LayerTreeView`.
    * **Visibility Control:** `SetVisible`, `SetShouldWarmUp`. Controlling when the compositor is active.
    * **Frame Synchronization and Output:** `RequestNewLayerTreeFrameSink`, `SetLayerTreeFrameSink`, `DidInitializeLayerTreeFrameSink`, `DidFailToInitializeLayerTreeFrameSink`. Handling the creation and management of the output mechanism.
    * **Main Frame Integration:** `WillBeginMainFrame`, `DidBeginMainFrame`, `BeginMainFrame`, `BeginMainFrameNotExpectedSoon`, `BeginMainFrameNotExpectedUntil`, `DidRunBeginMainFrame`. Interfacing with the main thread's rendering pipeline.
    * **Layer Updates:** `WillUpdateLayers`, `DidUpdateLayers`. Signals for when the layer tree is being updated.
    * **Commits:** `WillCommit`, `DidCommit`, `DidCommitAndDrawFrame`, `OnCommitRequested`, `OnDeferCommitsChanged`. Handling the process of committing changes to the compositor.
    * **Viewport and Scroll:** `ApplyViewportChanges`, `UpdateCompositorScrollState`. Relaying viewport and scroll information.
    * **Presentation Feedback:** `DidPresentCompositorFrame`, `AddPresentationCallback`, `AddCoreAnimationErrorCodeCallback`. Handling the timing and errors of frame presentation.
    * **Metrics and Debugging:** `RecordStartOfFrameMetrics`, `RecordEndOfFrameMetrics`, `RunPaintBenchmark`, `GetPausedDebuggerLocalizedMessage`. Collecting performance data and providing debugging information.
    * **Animation:**  Interaction with `animation_host_`.
    * **Web Tests:** `ScheduleAnimationForWebTests`. Specific hooks for testing.

5. **Relating to Web Technologies (JavaScript, HTML, CSS):** Now consider how the functionality connects to the front-end:
    * **CSS and Layout:** Changes in CSS trigger layout calculations, which ultimately affect the structure and properties of the compositing layers managed by `LayerTreeView`. Think of CSS properties like `transform`, `opacity`, `position: fixed`.
    * **HTML Structure:** The DOM tree created from HTML is mapped to the layer tree. Different HTML elements might become different layers or parts of layers.
    * **JavaScript Interactions:** JavaScript can manipulate the DOM and CSS, leading to layer tree updates and animations that `LayerTreeView` handles. Specifically, consider animations created with JavaScript or via CSS transitions/animations.

6. **Logic Inference and Examples:**  For methods that seem to involve some decision-making, try to create simple scenarios:
    * **`SetVisible` and `RequestNewLayerTreeFrameSink`:** If `SetVisible(true)` is called, and there's no frame sink, a request is triggered. If `SetVisible(false)`, requests might be buffered.
    * **`DidPresentCompositorFrame` and Callbacks:**  Callbacks are executed only after a successful presentation and are processed based on the frame token order.

7. **Common Usage Errors:** Think about how a developer using the Blink/Chromium APIs might misuse this class or its related interfaces:
    * **Incorrect Delegate Implementation:** The `LayerTreeViewDelegate` is crucial. If it doesn't provide the correct information or handle callbacks properly, things will break.
    * **Mismatched Threading:**  Compositor operations happen on a separate thread. Incorrectly trying to access compositor state from the main thread (or vice versa without proper synchronization) is a classic error.
    * **Frame Sink Issues:**  Problems in creating or managing the `LayerTreeFrameSink` will prevent rendering.

8. **Structuring the Output:** Organize the findings logically:
    * Start with a high-level summary of the class's purpose.
    * Detail the core functionalities using the grouped methods.
    * Explain the relationship to web technologies with concrete examples.
    * Provide illustrative examples for logic inference.
    * Highlight common usage errors.

9. **Refinement and Review:**  Read through the generated explanation to ensure clarity, accuracy, and completeness. Check for any jargon that needs explanation or any areas where more detail would be helpful. For example, initially, I might just say "manages layers," but refining it to "manages the compositing layer tree" is more accurate. Also, initially, I might forget to mention the UKM integration, but a second pass would catch that.

This systematic approach helps in dissecting complex code and generating a comprehensive explanation. It's a mix of top-down (understanding the overall goal) and bottom-up (examining individual methods) analysis.
这个文件 `blink/renderer/platform/widget/compositing/layer_tree_view.cc` 是 Chromium Blink 渲染引擎中 `LayerTreeView` 类的实现。`LayerTreeView` 的主要职责是 **管理和协调渲染过程中的合成（compositing）**。它充当了 Blink 渲染引擎和 Chromium Compositor 之间的桥梁。

以下是 `LayerTreeView` 的主要功能：

**1. 合成管理核心:**

* **创建和管理 `cc::LayerTreeHost`:**  `LayerTreeView` 内部持有一个 `cc::LayerTreeHost` 实例。`LayerTreeHost` 是 Chromium Compositor 中负责管理合成层树的核心类。`LayerTreeView` 通过 `LayerTreeHost` 与 Compositor 进行交互。
* **同步 Blink 和 Compositor 的状态:**  它负责将 Blink 渲染引擎中的渲染状态（例如，层树结构、属性、动画等）同步到 Compositor 中。
* **处理来自 Compositor 的回调:**  接收来自 Compositor 的事件通知，例如帧的提交、绘制完成、动画完成等，并通知相应的 Blink 组件。

**2. 与渲染流程的集成:**

* **开始和结束主线程更新:**  在 Blink 主线程更新渲染层时接收通知 (`WillUpdateLayers`, `DidUpdateLayers`)。
* **管理主线程帧的开始:**  接收来自 Compositor 的 `BeginFrame` 信号，并通知 Blink 渲染流程开始处理新的一帧 (`BeginMainFrame`)。
* **处理提交 (Commit):**  在 Blink 主线程完成渲染更新并准备提交到 Compositor 时接收通知 (`WillCommit`, `DidCommit`)。
* **管理视口变化:**  接收并处理视口变化 (`ApplyViewportChanges`)，并将这些变化传递给 Blink 渲染引擎。
* **管理滚动:**  接收并处理 Compositor 的滚动状态更新 (`UpdateCompositorScrollState`)。

**3. 与 `LayerTreeFrameSink` 的交互:**

* **请求新的 `LayerTreeFrameSink`:** 当需要与 Compositor 建立新的渲染通道时，请求创建 `LayerTreeFrameSink`。`LayerTreeFrameSink` 是 Compositor 端用于接收渲染内容的接口。
* **设置 `LayerTreeFrameSink`:**  接收由 Compositor 创建的 `LayerTreeFrameSink`，并将其传递给 `LayerTreeHost`。
* **处理 `LayerTreeFrameSink` 的丢失:**  当与 Compositor 的渲染通道断开时接收通知 (`DidLoseLayerTreeFrameSink`)。

**4. 处理动画:**

* **集成 Compositor 动画:**  通过 `cc::AnimationHost` 管理 Compositor 驱动的动画。

**5. 可见性控制:**

* **设置可见性:**  通过 `SetVisible` 方法控制 Compositor 是否应该渲染内容。

**6. 性能监控和调试:**

* **记录帧指标:**  在帧的开始和结束时记录性能指标 (`RecordStartOfFrameMetrics`, `RecordEndOfFrameMetrics`)。
* **运行绘制性能基准测试:**  支持运行绘制性能基准测试 (`RunPaintBenchmark`)。
* **提供调试信息:**  提供用于调试的信息，例如当调试器暂停时显示的消息 (`GetPausedDebuggerLocalizedMessage`)。

**7. 与 `LayerTreeViewDelegate` 的交互:**

* **使用委托模式:**  `LayerTreeView` 使用委托模式，通过 `LayerTreeViewDelegate` 接口与 Blink 渲染引擎的其他部分进行通信。它会将关键事件通知给 `delegate_` 指向的对象。

**它与 JavaScript, HTML, CSS 的功能的关系:**

`LayerTreeView` 本身是用 C++ 实现的，不直接涉及 JavaScript, HTML, 或 CSS 的解析和执行。但是，它的功能是渲染这些技术最终呈现到屏幕上的关键环节。

* **HTML:**  HTML 定义了页面的结构。Blink 渲染引擎会根据 HTML 构建 DOM 树。`LayerTreeView` 负责将 DOM 树的一部分或全部转化为可用于合成的层树。例如，带有 `position: fixed` 或 `transform` 属性的 HTML 元素通常会创建自己的合成层。
    * **例子:**  一个包含大量嵌套 `div` 元素的复杂页面，某些 `div` 可能因为 CSS 属性被提升为单独的合成层，`LayerTreeView` 就负责管理这些层。
* **CSS:** CSS 定义了元素的样式和布局。CSS 属性（如 `opacity`, `transform`, `will-change`, 滤镜等）会影响是否需要创建新的合成层以及层的属性。`LayerTreeView` 根据这些信息构建和更新合成层树。
    * **例子:**  一个 CSS 动画，如 `transition: opacity 1s;`，可能会在 Compositor 线程上执行，`LayerTreeView` 负责将动画信息传递给 Compositor。
* **JavaScript:** JavaScript 可以动态地修改 DOM 和 CSS，从而间接地影响 `LayerTreeView` 的行为。例如，JavaScript 可以添加或删除元素，修改元素的 CSS 属性，或者创建 CSS 动画。这些修改会导致 Blink 重新计算布局和样式，并最终更新 `LayerTreeView` 管理的合成层树。
    * **例子:**  一个 JavaScript 库使用 `requestAnimationFrame` 来创建流畅的动画。JavaScript 代码会修改元素的 `transform` 属性，`LayerTreeView` 会将这些变化反映到 Compositor 的层上。

**逻辑推理的例子 (假设输入与输出):**

**假设输入:**

1. JavaScript 代码修改了一个 `div` 元素的 `transform` 属性，例如 `element.style.transform = 'translateX(100px)';`
2. Blink 的样式计算和布局过程确定该 `div` 需要提升为自己的合成层。

**逻辑推理过程:**

1. Blink 渲染引擎将这个 `transform` 变化传递给 `LayerTreeView`。
2. `LayerTreeView` 更新其内部的 `cc::Layer` 树，设置对应层的 `transform` 属性。
3. 在下一次提交过程中，`LayerTreeView` 将更新后的层树信息发送到 Compositor。

**输出:**

Compositor 接收到新的层树信息后，会重新合成帧，使得该 `div` 元素在屏幕上水平移动了 100 像素。

**用户或编程常见的使用错误举例:**

1. **Delegate 未正确设置或销毁:** 如果 `LayerTreeViewDelegate` 没有被正确地设置，`LayerTreeView` 将无法与 Blink 渲染引擎的其他部分通信，导致渲染错误或崩溃。同样，如果 `delegate_` 指向的对象在 `LayerTreeView` 仍然需要使用它时被销毁，也会导致问题。
2. **在非主线程访问 `LayerTreeView` 的状态:**  `LayerTreeView` 的某些状态只能在 Blink 的主线程上访问。如果在 Compositor 线程或其他线程上直接访问这些状态，可能会导致数据竞争和未定义的行为。需要通过线程安全的机制进行通信。
3. **`LayerTreeFrameSink` 相关操作的顺序错误:**  例如，在没有请求新的 `LayerTreeFrameSink` 的情况下就尝试设置它，或者在 `LayerTreeFrameSink` 已经存在的情况下再次请求创建。这会导致与 Compositor 的通信出现问题。
4. **不理解合成层的影响:**  开发者可能会过度使用 CSS 属性（例如 `will-change`）来尝试创建过多的合成层，反而导致性能下降，因为合成层的管理和内存开销都比较大。`LayerTreeView` 虽然负责管理这些层，但最终的性能还是取决于 Blink 渲染引擎如何利用它。
5. **在 `LayerTreeViewDelegate` 的回调中执行耗时操作:** `LayerTreeView` 的某些回调方法是在渲染的关键路径上调用的。如果在这些回调中执行耗时操作，会导致帧率下降和页面卡顿。这些操作应该尽快完成，或者异步执行。

总而言之，`LayerTreeView` 是 Blink 渲染引擎中一个至关重要的组件，它负责将渲染结果转化为 Compositor 可以理解和处理的合成层树，最终将网页内容高效地绘制到屏幕上。它虽然不直接操作 JavaScript, HTML, CSS，但它的行为和状态直接受到这些技术的影响，并且为它们的最终呈现提供了基础。

### 提示词
```
这是目录为blink/renderer/platform/widget/compositing/layer_tree_view.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/compositing/layer_tree_view.h"

#include <stddef.h>

#include <string>
#include <utility>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/task_traits.h"
#include "base/task/thread_pool.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/time/time.h"
#include "base/values.h"
#include "cc/animation/animation_host.h"
#include "cc/animation/animation_timeline.h"
#include "cc/base/region.h"
#include "cc/benchmarks/micro_benchmark.h"
#include "cc/debug/layer_tree_debug_state.h"
#include "cc/input/layer_selection_bound.h"
#include "cc/layers/layer.h"
#include "cc/metrics/ukm_manager.h"
#include "cc/tiles/raster_dark_mode_filter.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/layer_tree_mutator.h"
#include "cc/trees/paint_holding_reason.h"
#include "cc/trees/presentation_time_callback_buffer.h"
#include "cc/trees/render_frame_metadata_observer.h"
#include "cc/trees/swap_promise.h"
#include "components/viz/common/frame_sinks/begin_frame_args.h"
#include "components/viz/common/frame_sinks/begin_frame_source.h"
#include "components/viz/common/quads/compositor_frame_metadata.h"
#include "services/metrics/public/cpp/mojo_ukm_recorder.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/strings/grit/blink_strings.h"
#include "third_party/blink/renderer/platform/graphics/dark_mode_filter.h"
#include "third_party/blink/renderer/platform/graphics/dark_mode_settings_builder.h"
#include "third_party/blink/renderer/platform/graphics/raster_dark_mode_filter_impl.h"
#include "third_party/blink/renderer/platform/scheduler/public/widget_scheduler.h"
#include "ui/gfx/presentation_feedback.h"

namespace cc {
class Layer;
}

namespace blink {

namespace {
// This factory is used to defer binding of the InterfacePtr to the compositor
// thread.
class UkmRecorderFactoryImpl : public cc::UkmRecorderFactory {
 public:
  UkmRecorderFactoryImpl() = default;
  ~UkmRecorderFactoryImpl() override = default;

  // This method gets called on the compositor thread.
  std::unique_ptr<ukm::UkmRecorder> CreateRecorder() override {
    mojo::Remote<ukm::mojom::UkmRecorderFactory> factory;

    // Calling these methods on the compositor thread are thread safe.
    Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
        factory.BindNewPipeAndPassReceiver());
    return ukm::MojoUkmRecorder::Create(*factory);
  }
};

}  // namespace

LayerTreeView::LayerTreeView(
    LayerTreeViewDelegate* delegate,
    scoped_refptr<scheduler::WidgetScheduler> scheduler)
    : widget_scheduler_(std::move(scheduler)),
      animation_host_(cc::AnimationHost::CreateMainInstance()),
      delegate_(delegate) {}

LayerTreeView::~LayerTreeView() = default;

void LayerTreeView::Initialize(
    const cc::LayerTreeSettings& settings,
    scoped_refptr<base::SingleThreadTaskRunner> main_thread,
    scoped_refptr<base::SingleThreadTaskRunner> compositor_thread,
    cc::TaskGraphRunner* task_graph_runner) {
  DCHECK(delegate_);
  const bool is_threaded = !!compositor_thread;

  cc::LayerTreeHost::InitParams params;
  params.client = this;
  params.scheduling_client = this;
  params.settings = &settings;
  params.task_graph_runner = task_graph_runner;
  params.main_task_runner = std::move(main_thread);
  params.mutator_host = animation_host_.get();
  params.dark_mode_filter = &RasterDarkModeFilterImpl::Instance();
  params.ukm_recorder_factory = std::make_unique<UkmRecorderFactoryImpl>();
  if (base::ThreadPoolInstance::Get()) {
    // The image worker thread needs to allow waiting since it makes discardable
    // shared memory allocations which need to make synchronous calls to the
    // IO thread.
    params.image_worker_task_runner =
        base::ThreadPool::CreateSequencedTaskRunner(
            {base::WithBaseSyncPrimitives(), base::TaskPriority::USER_VISIBLE,
             base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN});
  }
  if (!is_threaded) {
    // Single-threaded web tests, and unit tests.
    layer_tree_host_ =
        cc::LayerTreeHost::CreateSingleThreaded(this, std::move(params));
  } else {
    layer_tree_host_ =
        cc::LayerTreeHost::CreateThreaded(std::move(compositor_thread), std::move(params));
  }

  first_source_frame_for_current_delegate_ =
      layer_tree_host_->SourceFrameNumber();
}

void LayerTreeView::Disconnect() {
  DCHECK(delegate_);
  // Drop compositor resources immediately, while keeping the compositor alive
  // until after this class is destroyed.
  layer_tree_host_->WaitForProtectedSequenceCompletion();
  layer_tree_host_->SetVisible(false);
  layer_tree_host_->ReleaseLayerTreeFrameSink();
  delegate_ = nullptr;
}

void LayerTreeView::ClearPreviousDelegateAndReattachIfNeeded(
    LayerTreeViewDelegate* delegate,
    scoped_refptr<scheduler::WidgetScheduler> scheduler) {
  // Reset state tied to the previous `delegate_`.
  layer_tree_host_->WaitForProtectedSequenceCompletion();
  layer_tree_host_->DetachInputDelegateAndRenderFrameObserver();
  layer_tree_host_->StopDeferringCommits(
      cc::PaintHoldingCommitTrigger::kWidgetSwapped);
  for (uint32_t i = 0;
       i <= static_cast<uint32_t>(cc::EventListenerClass::kLast); ++i) {
    layer_tree_host_->SetEventListenerProperties(
        static_cast<cc::EventListenerClass>(i),
        cc::EventListenerProperties::kNone);
  }

  delegate_ = delegate;
  CHECK_GE(layer_tree_host_->SourceFrameNumber(),
           first_source_frame_for_current_delegate_)
      << "SourceFrameNumber() must be monotonically increasing";
  first_source_frame_for_current_delegate_ =
      layer_tree_host_->SourceFrameNumber();
  widget_scheduler_ = std::move(scheduler);

  // Invalidate weak ptrs so callbacks from the previous delegate are dropped.
  weak_factory_for_delegate_.InvalidateWeakPtrs();

  if (!delegate) {
    // If we're not reattaching to a new delegate, return early as there's no
    // need to request a new frame sink. Also, ensure that the LayerTreeHost is
    // no longer visible.
    layer_tree_host_->SetVisible(false);
    return;
  }

  switch (frame_sink_state_) {
    case FrameSinkState::kNoFrameSink:
      // No frame sink, the LTH should issue a request which will set both the
      // frame sink and RenderFrameObserver.
      break;
    case FrameSinkState::kRequestBufferedInvisible:
      // The frame sink request was buffered because it was made when the LTH
      // was invisible. It will be issued when the LTH is made visible.
      break;
    case FrameSinkState::kRequestPending:
      // If the request was pending, it targeted the previous delegate and we
      // cancelled it by invalidating the weak pointers above. Re-issue it
      // targeting the new delegate.
      DidFailToInitializeLayerTreeFrameSink();
      break;
    case FrameSinkState::kInitializing:
      // The LTH is initializing a new FrameSink which can be reused but we need
      // a new RenderFrameObserver associated with the new delegate.
    case FrameSinkState::kInitialized:
      // The LTH has an initialized FrameSink which can be reused but we need a
      // new RenderFrameObserver associated with the new delegate.
      if (auto render_frame_observer = delegate_->CreateRenderFrameObserver()) {
        layer_tree_host_->SetRenderFrameObserver(
            std::move(render_frame_observer));
      }
      break;
  }
}

void LayerTreeView::SetVisible(bool visible) {
  DCHECK(delegate_);
  layer_tree_host_->SetVisible(visible);

  if (visible &&
      frame_sink_state_ == FrameSinkState::kRequestBufferedInvisible) {
    DidFailToInitializeLayerTreeFrameSink();
  }
}

void LayerTreeView::SetShouldWarmUp() {
  DCHECK(delegate_);
  layer_tree_host_->SetShouldWarmUp();
}

void LayerTreeView::SetLayerTreeFrameSink(
    std::unique_ptr<cc::LayerTreeFrameSink> layer_tree_frame_sink,
    std::unique_ptr<cc::RenderFrameMetadataObserver>
        render_frame_metadata_observer) {
  DCHECK(delegate_);

  CHECK_EQ(frame_sink_state_, FrameSinkState::kRequestPending);
  frame_sink_state_ = FrameSinkState::kInitializing;

  if (!layer_tree_frame_sink) {
    DidFailToInitializeLayerTreeFrameSink();
    return;
  }
  if (render_frame_metadata_observer) {
    layer_tree_host_->SetRenderFrameObserver(
        std::move(render_frame_metadata_observer));
  }
  layer_tree_host_->SetLayerTreeFrameSink(std::move(layer_tree_frame_sink));
}

void LayerTreeView::WillBeginMainFrame() {
  if (!delegate_)
    return;
  delegate_->WillBeginMainFrame();
}

void LayerTreeView::DidBeginMainFrame() {
  if (!delegate_)
    return;
  delegate_->DidBeginMainFrame();
}

void LayerTreeView::WillUpdateLayers() {
  if (!delegate_)
    return;
  delegate_->BeginUpdateLayers();
}

void LayerTreeView::DidUpdateLayers() {
  if (!delegate_)
    return;
  delegate_->EndUpdateLayers();
  // Dump property trees and layers if run with:
  //   --vmodule=layer_tree_view=3
  VLOG(3) << "After updating layers:\n"
          << "property trees:\n"
          << layer_tree_host_->property_trees()->ToString() << "\n"
          << "cc::Layers:\n"
          << layer_tree_host_->LayersAsString();
}

void LayerTreeView::BeginMainFrame(const viz::BeginFrameArgs& args) {
  if (!delegate_)
    return;
  widget_scheduler_->WillBeginFrame(args);
  delegate_->BeginMainFrame(args.frame_time);
}

void LayerTreeView::OnDeferMainFrameUpdatesChanged(bool status) {
  if (!delegate_)
    return;
  delegate_->OnDeferMainFrameUpdatesChanged(status);
}

void LayerTreeView::OnCommitRequested() {
  if (!delegate_)
    return;
  delegate_->OnCommitRequested();
}

void LayerTreeView::OnDeferCommitsChanged(
    bool status,
    cc::PaintHoldingReason reason,
    std::optional<cc::PaintHoldingCommitTrigger> trigger) {
  if (!delegate_)
    return;
  delegate_->OnDeferCommitsChanged(status, reason, trigger);
}

void LayerTreeView::BeginMainFrameNotExpectedSoon() {
  if (!delegate_)
    return;
  widget_scheduler_->BeginFrameNotExpectedSoon();
}

void LayerTreeView::BeginMainFrameNotExpectedUntil(base::TimeTicks time) {
  if (!delegate_)
    return;
  widget_scheduler_->BeginMainFrameNotExpectedUntil(time);
}

void LayerTreeView::UpdateLayerTreeHost() {
  if (!delegate_)
    return;
  delegate_->UpdateVisualState();
}

void LayerTreeView::ApplyViewportChanges(
    const cc::ApplyViewportChangesArgs& args) {
  if (!delegate_)
    return;
  delegate_->ApplyViewportChanges(args);
}

void LayerTreeView::UpdateCompositorScrollState(
    const cc::CompositorCommitData& commit_data) {
  if (!delegate_)
    return;
  delegate_->UpdateCompositorScrollState(commit_data);
}

void LayerTreeView::RequestNewLayerTreeFrameSink() {
  if (!delegate_)
    return;

  CHECK(frame_sink_state_ == FrameSinkState::kNoFrameSink ||
        frame_sink_state_ == FrameSinkState::kInitialized);

  // When the compositor is not visible it would not request a
  // LayerTreeFrameSink so this is a race where it requested one on the
  // compositor thread while becoming non-visible on the main thread. In that
  // case, we can wait for it to become visible again before replying. If
  // `kWarmUpCompositor` is enabled and warm-up is triggered, a
  // LayerTreeFrameSink is requested even if non-visible state. We can ignore
  // this branch in that case. If not enabled, `ShouldWarmUp()` is always false.
  if (!layer_tree_host_->ShouldWarmUp() && !layer_tree_host_->IsVisible()) {
    frame_sink_state_ = FrameSinkState::kRequestBufferedInvisible;
    return;
  }

  frame_sink_state_ = FrameSinkState::kRequestPending;
  delegate_->RequestNewLayerTreeFrameSink(
      base::BindOnce(&LayerTreeView::SetLayerTreeFrameSink,
                     weak_factory_for_delegate_.GetWeakPtr()));
}

void LayerTreeView::DidInitializeLayerTreeFrameSink() {
  CHECK_EQ(frame_sink_state_, FrameSinkState::kInitializing);
  frame_sink_state_ = FrameSinkState::kInitialized;
}

void LayerTreeView::DidFailToInitializeLayerTreeFrameSink() {
  if (!delegate_)
    return;

  CHECK(frame_sink_state_ == FrameSinkState::kRequestBufferedInvisible ||
        frame_sink_state_ == FrameSinkState::kInitializing ||
        frame_sink_state_ == FrameSinkState::kRequestPending);

  // When the RenderWidget is made hidden while an async request for a
  // LayerTreeFrameSink is being processed, then if it fails we would arrive
  // here. Since the compositor does not request a LayerTreeFrameSink while not
  // visible, we can delay trying again until becoming visible again.
  // If `kWarmUpCompositor` is enabled and warm-up is
  // triggered, a LayerTreeFrameSink is requested even if non-visible state. We
  // can ignore this branch in that case. If not enabled, `ShouldWarmUp()` is
  // always false.
  if (!layer_tree_host_->ShouldWarmUp() && !layer_tree_host_->IsVisible()) {
    frame_sink_state_ = FrameSinkState::kRequestBufferedInvisible;
    return;
  }

  frame_sink_state_ = FrameSinkState::kNoFrameSink;
  // The GPU channel cannot be established when gpu_remote is disconnected. Stop
  // calling RequestNewLayerTreeFrameSink because it's going to fail again and
  // it will be stuck in a forever loop of retries. This makes the processes
  // unable to be killed after Chrome is closed.
  // https://issues.chromium.org/336164423
  if (!Platform::Current()->IsGpuRemoteDisconnected()) {
    layer_tree_host_->GetTaskRunnerProvider()->MainThreadTaskRunner()->PostTask(
        FROM_HERE, base::BindOnce(&LayerTreeView::RequestNewLayerTreeFrameSink,
                                  weak_factory_.GetWeakPtr()));
  }
}

void LayerTreeView::WillCommit(const cc::CommitState&) {
  if (!delegate_)
    return;
  delegate_->WillCommitCompositorFrame();
  widget_scheduler_->DidCommitFrameToCompositor();
}

void LayerTreeView::DidCommit(int source_frame_number,
                              base::TimeTicks commit_start_time,
                              base::TimeTicks commit_finish_time) {
  if (!delegate_ ||
      source_frame_number < first_source_frame_for_current_delegate_) {
    return;
  }
  delegate_->DidCommitCompositorFrame(commit_start_time, commit_finish_time);
}

void LayerTreeView::DidCommitAndDrawFrame(int source_frame_number) {
  if (!delegate_ ||
      source_frame_number < first_source_frame_for_current_delegate_) {
    return;
  }
  delegate_->DidCommitAndDrawCompositorFrame();
}

void LayerTreeView::DidCompletePageScaleAnimation(int source_frame_number) {
  if (!delegate_ ||
      source_frame_number < first_source_frame_for_current_delegate_) {
    return;
  }
  delegate_->DidCompletePageScaleAnimation();
}

void LayerTreeView::DidPresentCompositorFrame(
    uint32_t frame_token,
    const viz::FrameTimingDetails& frame_timing_details) {
  if (!delegate_)
    return;
  DCHECK(layer_tree_host_->GetTaskRunnerProvider()
             ->MainThreadTaskRunner()
             ->RunsTasksInCurrentSequence());
  // Only run callbacks on successful presentations.
  if (frame_timing_details.presentation_feedback.failed()) {
    return;
  }
  while (!presentation_callbacks_.empty()) {
    const auto& front = presentation_callbacks_.begin();
    if (viz::FrameTokenGT(front->first, frame_token))
      break;
    for (auto& callback : front->second)
      std::move(callback).Run(frame_timing_details);
    presentation_callbacks_.erase(front);
  }

#if BUILDFLAG(IS_APPLE)
  while (!core_animation_error_code_callbacks_.empty()) {
    const auto& front = core_animation_error_code_callbacks_.begin();
    if (viz::FrameTokenGT(front->first, frame_token))
      break;
    for (auto& callback : front->second) {
      std::move(callback).Run(
          frame_timing_details.presentation_feedback.ca_layer_error_code);
    }
    core_animation_error_code_callbacks_.erase(front);
  }
#endif
}

void LayerTreeView::RecordStartOfFrameMetrics() {
  if (!delegate_)
    return;
  delegate_->RecordStartOfFrameMetrics();
}

void LayerTreeView::RecordEndOfFrameMetrics(
    base::TimeTicks frame_begin_time,
    cc::ActiveFrameSequenceTrackers trackers) {
  if (!delegate_)
    return;
  delegate_->RecordEndOfFrameMetrics(frame_begin_time, trackers);
}

std::unique_ptr<cc::BeginMainFrameMetrics>
LayerTreeView::GetBeginMainFrameMetrics() {
  if (!delegate_)
    return nullptr;
  return delegate_->GetBeginMainFrameMetrics();
}

void LayerTreeView::NotifyThroughputTrackerResults(
    cc::CustomTrackerResults results) {
  NOTREACHED();
}

void LayerTreeView::DidObserveFirstScrollDelay(
    int source_frame_number,
    base::TimeDelta first_scroll_delay,
    base::TimeTicks first_scroll_timestamp) {
  if (!delegate_ ||
      source_frame_number < first_source_frame_for_current_delegate_) {
    return;
  }
  delegate_->DidObserveFirstScrollDelay(first_scroll_delay,
                                        first_scroll_timestamp);
}

void LayerTreeView::RunPaintBenchmark(int repeat_count,
                                      cc::PaintBenchmarkResult& result) {
  if (delegate_)
    delegate_->RunPaintBenchmark(repeat_count, result);
}

std::string LayerTreeView::GetPausedDebuggerLocalizedMessage() {
  return Platform::Current()
      ->QueryLocalizedString(IDS_DEBUGGER_PAUSED_IN_ANOTHER_TAB)
      .Utf8();
}

void LayerTreeView::DidRunBeginMainFrame() {
  if (!delegate_)
    return;

  widget_scheduler_->DidRunBeginMainFrame();
}

void LayerTreeView::DidSubmitCompositorFrame() {}

void LayerTreeView::DidLoseLayerTreeFrameSink() {}

void LayerTreeView::ScheduleAnimationForWebTests() {
  if (!delegate_)
    return;

  delegate_->ScheduleAnimationForWebTests();
}

void LayerTreeView::AddPresentationCallback(
    uint32_t frame_token,
    base::OnceCallback<void(const viz::FrameTimingDetails&)> callback) {
  AddCallback(frame_token, std::move(callback), presentation_callbacks_);
}

#if BUILDFLAG(IS_APPLE)
void LayerTreeView::AddCoreAnimationErrorCodeCallback(
    uint32_t frame_token,
    base::OnceCallback<void(gfx::CALayerResult)> callback) {
  AddCallback(frame_token, std::move(callback),
              core_animation_error_code_callbacks_);
}
#endif

template <typename Callback>
void LayerTreeView::AddCallback(
    uint32_t frame_token,
    Callback callback,
    base::circular_deque<std::pair<uint32_t, std::vector<Callback>>>&
        callbacks) {
  DCHECK(delegate_);
  if (!callbacks.empty()) {
    auto& previous = callbacks.back();
    uint32_t previous_frame_token = previous.first;
    if (previous_frame_token == frame_token) {
      previous.second.push_back(std::move(callback));
      DCHECK_LE(previous.second.size(), 250u);
      return;
    }
    DCHECK(viz::FrameTokenGT(frame_token, previous_frame_token));
  }
  std::vector<Callback> new_callbacks;
  new_callbacks.push_back(std::move(callback));
  callbacks.emplace_back(frame_token, std::move(new_callbacks));
  DCHECK_LE(callbacks.size(),
            cc::PresentationTimeCallbackBuffer::kMaxBufferSize);
}

}  // namespace blink
```