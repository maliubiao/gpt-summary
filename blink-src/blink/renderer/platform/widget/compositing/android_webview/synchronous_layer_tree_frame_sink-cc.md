Response:
Let's break down the thought process to analyze the `SynchronousLayerTreeFrameSink.cc` file.

1. **Understand the Core Purpose:** The filename itself is highly descriptive: `synchronous_layer_tree_frame_sink.cc`. This immediately suggests a mechanism for rendering content synchronously, likely within a specific context (Android WebView). The "FrameSink" part indicates it's involved in the composition and submission of rendering frames.

2. **Identify Key Dependencies and Concepts:**  Scanning the includes reveals several important areas:
    * **`cc/`:**  This strongly points to the Chromium Compositor. Concepts like `LayerTreeFrameSinkClient`, `RasterContextProvider`, etc., are central to the compositor.
    * **`components/viz/`:** This indicates interaction with Viz, Chromium's visualization and compositing service. Key elements here include `CompositorFrame`, `SurfaceDrawQuad`, `Display`, `FrameSinkManagerImpl`.
    * **`gpu/`:**  This suggests interaction with the GPU, likely for hardware acceleration.
    * **`third_party/blink/`:** This confirms the file is part of the Blink rendering engine.
    * **Android WebView:** The directory path clearly indicates this is specific to Android WebView.
    * **Synchronous Operations:** The "synchronous" keyword implies a blocking or tightly controlled rendering flow, unlike typical asynchronous compositor operations.

3. **Analyze Key Classes and Methods:**  Focus on the main class, `SynchronousLayerTreeFrameSink`, and its public methods.

    * **Constructor/Destructor:** Understand initialization and cleanup. Note the dependencies passed in the constructor.
    * **`BindToClient()`:** This is crucial for establishing the connection with the `LayerTreeFrameSinkClient` (typically the `WebViewContents`). Observe the setup of `viz::FrameSinkManagerImpl`, `viz::Display`, and the begin frame source.
    * **`SubmitCompositorFrame()`:**  This is the heart of the frame submission process. Analyze the logic for both hardware and software rendering paths. Pay attention to how `viz::CompositorFrame`s are handled and the creation of `SurfaceDrawQuad`s for embedding.
    * **`DemandDrawHw()` and `DemandDrawSw()`:**  These methods trigger rendering on demand, either using hardware or software rendering. Note the handling of viewports and transformations.
    * **`SetLocalSurfaceId()`:**  Understand how the surface ID for embedding is managed.
    * **`SetMemoryPolicy()`:**  See how memory limits are applied.
    * **`DidActivatePendingTree()` and other `Did...` methods:** These are callbacks from the compositor.
    * **`OnBeginFrame()`:** How begin frame signals are received and handled.

4. **Differentiate Hardware and Software Rendering:** A significant portion of the logic in `SubmitCompositorFrame()` and `DemandDraw...()` deals with the distinction between hardware and software rendering paths. Understand why this distinction exists in the Android WebView context. The introduction of `use_zero_copy_sw_draw_` is also important.

5. **Trace the Data Flow:**  Imagine a rendering request coming in. How does it flow through the methods? How are `CompositorFrame`s constructed and submitted? How does the `viz::Display` come into play, especially for software rendering?

6. **Look for Specific Behaviors and Edge Cases:**
    * **Synchronous Nature:**  How does this class enforce synchronicity?  The interaction with `SynchronousCompositorRegistry` and the blocking nature of `DemandDraw` are key.
    * **Android WebView Specifics:**  Why is software rendering still relevant here?  Consider the embedding scenario and potential fallback mechanisms.
    * **Resource Management:**  How are resources reclaimed?
    * **Local Surface IDs:**  How are they generated and used for embedding?

7. **Connect to User-Facing Features (JavaScript, HTML, CSS):**  Think about how the rendering process relates to the web content. JavaScript might trigger animations or layout changes, HTML defines the structure, and CSS styles the elements. How do these changes ultimately lead to `CompositorFrame`s being submitted?

8. **Consider Potential Errors:**  What could go wrong?  Incorrect usage of the API, problems with resource management, issues with the synchronization mechanism.

9. **Structure the Explanation:** Organize the findings logically, starting with a high-level overview of the file's purpose. Then delve into specifics, providing examples and clarifying the relationships between different parts of the code. Use clear and concise language. Address each aspect of the prompt (functionality, relation to web technologies, logical reasoning, common errors).

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This is just about submitting frames."  **Correction:** Realized the synchronous nature and the distinction between hardware and software paths are critical aspects.
* **Initial thought:** "The `viz::Display` is always used." **Correction:**  Discovered that `viz::Display` is primarily used for the *software* rendering path in this context. Hardware rendering might directly submit to a different sink.
* **Confusion about LocalSurfaceIds:**  Needed to clarify when and why new `LocalSurfaceId`s are generated, especially in the context of embedding.
* **Overlooking the `SynchronousCompositorRegistry`:**  Realized its importance in the synchronous communication flow.

By following these steps and continuously refining the understanding, we can arrive at a comprehensive and accurate explanation of the `SynchronousLayerTreeFrameSink.cc` file.
这个文件 `synchronous_layer_tree_frame_sink.cc` 是 Chromium Blink 引擎中专门为 Android WebView 设计的，用于同步渲染的机制的核心组件。它的主要功能是作为渲染管道的末端，负责接收来自渲染器进程的图层树，并将其转换为可以被 Android 系统理解和绘制的帧。

以下是该文件的详细功能列表和相关说明：

**核心功能:**

1. **作为同步渲染的桥梁:**  Android WebView 需要一种同步的方式来绘制内容，以便与 Android 的 View 系统集成。这个类作为 Blink 渲染器和 Android 绘图系统之间的桥梁，确保渲染过程的同步性。

2. **接收和处理 CompositorFrame:** 它接收来自 Blink 渲染器进程的 `viz::CompositorFrame`。这个帧包含了渲染所需的所有信息，例如渲染通道、绘制四边形（draw quads）、资源等。

3. **管理 Surface 及其生命周期:**  它管理用于渲染的 `viz::Surface`，包括创建、提交帧和回收资源。它为渲染的内容分配一个 `viz::LocalSurfaceId`，用于在合成器中唯一标识这个渲染表面。

4. **处理硬件加速渲染 (Hardware Compositing):**  当设备支持硬件加速时，它会将 `CompositorFrame` 提交给 `viz::CompositorFrameSink`，以便 Viz 合成器进行硬件加速合成。

5. **支持软件渲染 (Software Compositing):**  在某些情况下，或者为了特定的优化（如零拷贝软件绘制），它也支持软件渲染。它会创建一个 `viz::Display` 对象，并在软件画布上进行绘制。

6. **与 `SynchronousCompositorRegistry` 交互:**  它与 `SynchronousCompositorRegistry` 协同工作，该注册表负责跟踪所有同步的 `LayerTreeFrameSink` 实例，并允许主进程（或嵌入器）与之通信。

7. **处理 `DemandDraw` 请求:** 它响应来自 WebView 的 `DemandDraw` 请求，这些请求指示何时需要进行渲染。根据是硬件渲染还是软件渲染，它会调用相应的合成流程。

8. **管理内存策略:**  它可以设置内存策略，例如限制在可见状态下的内存使用量，这有助于管理 WebView 的内存占用。

9. **处理 BeginFrame 信号:**  它可以接收和处理来自 Viz 的 `BeginFrame` 信号，这些信号用于驱动渲染过程。

**与 JavaScript, HTML, CSS 的关系:**

`SynchronousLayerTreeFrameSink` 本身不直接解析 JavaScript, HTML, CSS。这些工作发生在 Blink 渲染管道的上游阶段，例如布局、样式计算和图层树构建。然而，`SynchronousLayerTreeFrameSink` 是这些工作的最终结果的呈现者。

* **JavaScript:** JavaScript 可以通过 DOM 操作、动画或其他方式改变页面内容和样式。这些改变会触发 Blink 渲染管道的重新运行，最终生成新的图层树和 `CompositorFrame`，并被 `SynchronousLayerTreeFrameSink` 接收并绘制。
    * **例子:** 一个 JavaScript 动画改变了一个元素的 `transform` 属性。这会导致该元素的图层发生变化，Blink 会生成一个新的 `CompositorFrame`，其中包含更新后的变换信息，`SynchronousLayerTreeFrameSink` 负责将其渲染到屏幕上。

* **HTML:** HTML 定义了页面的结构。Blink 的渲染引擎会根据 HTML 构建 DOM 树，然后基于 DOM 树创建渲染树和图层树。`SynchronousLayerTreeFrameSink` 接收到的 `CompositorFrame` 就是对这些 HTML 元素最终渲染结果的描述。
    * **例子:**  一个包含多个 `<div>` 元素的 HTML 页面，每个 `<div>` 都有不同的内容和样式。Blink 会为这些元素创建不同的图层，并将它们的绘制信息组织到 `CompositorFrame` 中，`SynchronousLayerTreeFrameSink` 负责将这些图层组合并绘制出来。

* **CSS:** CSS 决定了页面的样式和布局。Blink 的样式计算引擎会解析 CSS 并将其应用于 DOM 元素，影响元素的尺寸、颜色、位置等。这些样式信息会被反映在图层树和最终的 `CompositorFrame` 中。
    * **例子:**  CSS 规则设置了一个元素的背景颜色和边框样式。这些样式信息会被编码到 `CompositorFrame` 中的绘制指令中，`SynchronousLayerTreeFrameSink` 会按照这些指令在屏幕上绘制出带有指定背景和边框的元素。

**逻辑推理与假设输入输出:**

**假设输入:** 一个包含复杂动画和 CSS 变换的网页，用户正在滚动页面。

**内部处理逻辑推理:**

1. **JavaScript 触发动画:**  JavaScript 代码正在驱动一个元素的动画，不断更新其 `transform` 属性。
2. **Blink 渲染器构建新的 CompositorFrame:**  由于动画导致图层属性变化，Blink 渲染器会重新运行渲染管道，生成一个新的 `viz::CompositorFrame`。这个帧会包含更新后的图层变换信息。
3. **`SynchronousLayerTreeFrameSink::SubmitCompositorFrame` 被调用:** 渲染器将新的 `CompositorFrame` 提交给 `SynchronousLayerTreeFrameSink`。
4. **硬件加速渲染路径 (假设):**  如果设备支持硬件加速，`SynchronousLayerTreeFrameSink` 会将 `CompositorFrame` 传递给 Viz 的 `CompositorFrameSink`。
5. **Viz 合成和渲染:** Viz 合成器会利用 GPU 对 `CompositorFrame` 进行合成，生成最终的图像。
6. **Android WebView 接收渲染结果:**  合成后的图像会被传递回 Android WebView。
7. **`DemandDraw` 请求 (由于滚动):**  用户滚动页面，WebView 会发出 `DemandDraw` 请求。
8. **`SynchronousLayerTreeFrameSink` 响应 `DemandDraw`:**  根据当前的图层树状态和需要绘制的区域，`SynchronousLayerTreeFrameSink` 可能会触发新的渲染或重用之前的渲染结果。

**假设输出:**  屏幕上流畅地显示动画效果，并且在滚动过程中内容能够及时更新，没有明显的卡顿或闪烁。

**涉及用户或编程常见的使用错误:**

1. **在不适当的时机调用 `DemandDraw`:**  如果 WebView 或嵌入器在没有必要的时候频繁调用 `DemandDraw`，可能会导致不必要的渲染，浪费资源并可能影响性能。
    * **例子:** 在屏幕内容没有发生变化时，仍然持续调用 `DemandDraw`。

2. **错误地配置内存策略:**  如果设置了过于严格的内存策略，可能会导致资源被过早回收，影响渲染质量或导致需要重新加载资源。
    * **例子:**  将内存限制设置得过低，导致图片等资源被频繁回收和重新加载，引起页面闪烁。

3. **在软件渲染模式下进行过于复杂的渲染操作:**  如果设备不支持硬件加速或被强制使用软件渲染，执行过于复杂的渲染操作（例如大量的复杂动画或滤镜）可能会导致性能问题。
    * **例子:**  在软件渲染模式下，尝试渲染包含大量 CSS 阴影和模糊效果的页面，可能会导致渲染速度很慢。

4. **不正确地处理 `LocalSurfaceId`:**  如果 `LocalSurfaceId` 的管理不当，可能会导致渲染表面失效，出现渲染错误或空白。
    * **例子:**  在嵌套的 WebView 中，如果父 WebView 和子 WebView 的 `LocalSurfaceId` 处理不当，可能会导致子 WebView 的内容无法正确显示。

5. **在同步渲染的上下文中执行耗时操作:**  由于 `SynchronousLayerTreeFrameSink` 涉及到同步渲染，如果在其调用的路径上执行耗时的操作（例如在 `OnDraw` 中进行复杂的计算），可能会阻塞 UI 线程，导致应用无响应。
    * **例子:**  在 `InvokeComposite` 或 `OnDraw` 等方法中执行网络请求或大量的同步文件 I/O 操作。

总而言之，`synchronous_layer_tree_frame_sink.cc` 文件是 Android WebView 中实现同步渲染的关键组件，它接收来自 Blink 渲染器的输出，并负责将其转化为 Android 系统可以绘制的内容。它与 JavaScript, HTML, CSS 的关系在于它是这些技术最终渲染结果的呈现者。理解其工作原理和潜在的错误使用场景对于开发高性能的 Android WebView 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/widget/compositing/android_webview/synchronous_layer_tree_frame_sink.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/compositing/android_webview/synchronous_layer_tree_frame_sink.h"

#include <vector>

#include "base/auto_reset.h"
#include "base/check.h"
#include "base/command_line.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/notreached.h"
#include "base/task/single_thread_task_runner.h"
#include "cc/trees/layer_tree_frame_sink_client.h"
#include "components/viz/common/display/renderer_settings.h"
#include "components/viz/common/features.h"
#include "components/viz/common/gpu/context_provider.h"
#include "components/viz/common/quads/compositor_frame.h"
#include "components/viz/common/quads/compositor_render_pass.h"
#include "components/viz/common/quads/surface_draw_quad.h"
#include "components/viz/common/surfaces/parent_local_surface_id_allocator.h"
#include "components/viz/service/display/display.h"
#include "components/viz/service/display/output_surface.h"
#include "components/viz/service/display/output_surface_frame.h"
#include "components/viz/service/display/overlay_processor_stub.h"
#include "components/viz/service/display/software_output_device.h"
#include "components/viz/service/frame_sinks/compositor_frame_sink_support.h"
#include "components/viz/service/frame_sinks/frame_sink_manager_impl.h"
#include "gpu/command_buffer/client/context_support.h"
#include "gpu/command_buffer/client/gles2_interface.h"
#include "gpu/command_buffer/common/gpu_memory_allocation.h"
#include "gpu/command_buffer/common/swap_buffers_complete_params.h"
#include "gpu/ipc/client/client_shared_image_interface.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/skia_conversions.h"
#include "ui/gfx/geometry/transform.h"

namespace blink {

namespace {

const viz::FrameSinkId kRootFrameSinkId(1, 1);
const viz::FrameSinkId kChildFrameSinkId(1, 2);

// Do not limit number of resources, so use an unrealistically high value.
const size_t kNumResourcesLimit = 10 * 1000 * 1000;

class SoftwareDevice : public viz::SoftwareOutputDevice {
 public:
  explicit SoftwareDevice(raw_ptr<SkCanvas>* canvas) : canvas_(canvas) {}
  SoftwareDevice(const SoftwareDevice&) = delete;
  SoftwareDevice& operator=(const SoftwareDevice&) = delete;

  void Resize(const gfx::Size& pixel_size, float device_scale_factor) override {
    // Intentional no-op: canvas size is controlled by the embedder.
  }
  SkCanvas* BeginPaint(const gfx::Rect& damage_rect) override {
    DCHECK(*canvas_) << "BeginPaint with no canvas set";
    return *canvas_;
  }
  void EndPaint() override {}

 private:
  raw_ptr<raw_ptr<SkCanvas>> canvas_;
};

// This is used with resourceless software draws.
class SoftwareCompositorFrameSinkClient
    : public viz::mojom::CompositorFrameSinkClient {
 public:
  SoftwareCompositorFrameSinkClient() = default;
  SoftwareCompositorFrameSinkClient(const SoftwareCompositorFrameSinkClient&) =
      delete;
  SoftwareCompositorFrameSinkClient& operator=(
      const SoftwareCompositorFrameSinkClient&) = delete;
  ~SoftwareCompositorFrameSinkClient() override = default;

  void DidReceiveCompositorFrameAck(
      std::vector<viz::ReturnedResource> resources) override {
    DCHECK(resources.empty());
  }
  void OnBeginFrame(const viz::BeginFrameArgs& args,
                    const viz::FrameTimingDetailsMap& timing_details,
                    bool frame_ack,
                    std::vector<viz::ReturnedResource> resources) override {
    DCHECK(resources.empty());
  }
  void ReclaimResources(std::vector<viz::ReturnedResource> resources) override {
    DCHECK(resources.empty());
  }
  void OnBeginFramePausedChanged(bool paused) override {}
  void OnCompositorFrameTransitionDirectiveProcessed(
      uint32_t sequence_id) override {}
  void OnSurfaceEvicted(const viz::LocalSurfaceId& local_surface_id) override {}
};

}  // namespace

class SynchronousLayerTreeFrameSink::SoftwareOutputSurface
    : public viz::OutputSurface {
 public:
  SoftwareOutputSurface(std::unique_ptr<SoftwareDevice> software_device)
      : viz::OutputSurface(std::move(software_device)) {}

  // viz::OutputSurface implementation.
  void BindToClient(viz::OutputSurfaceClient* client) override {}
  void EnsureBackbuffer() override {}
  void DiscardBackbuffer() override {}
  void SwapBuffers(viz::OutputSurfaceFrame frame) override {}
  void Reshape(const ReshapeParams& params) override {}
  void SetUpdateVSyncParametersCallback(
      viz::UpdateVSyncParametersCallback callback) override {}
  void SetDisplayTransformHint(gfx::OverlayTransform transform) override {}
  gfx::OverlayTransform GetDisplayTransform() override {
    return gfx::OVERLAY_TRANSFORM_NONE;
  }
};

base::TimeDelta SynchronousLayerTreeFrameSink::StubDisplayClient::
    GetPreferredFrameIntervalForFrameSinkId(
        const viz::FrameSinkId& id,
        viz::mojom::blink::CompositorFrameSinkType* type) {
  return viz::BeginFrameArgs::MinInterval();
}

SynchronousLayerTreeFrameSink::SynchronousLayerTreeFrameSink(
    scoped_refptr<viz::RasterContextProvider> context_provider,
    scoped_refptr<cc::RasterContextProviderWrapper>
        worker_context_provider_wrapper,
    scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner,
    gpu::GpuMemoryBufferManager* gpu_memory_buffer_manager,
    uint32_t layer_tree_frame_sink_id,
    std::unique_ptr<viz::BeginFrameSource> synthetic_begin_frame_source,
    SynchronousCompositorRegistry* registry,
    mojo::PendingRemote<viz::mojom::blink::CompositorFrameSink>
        compositor_frame_sink_remote,
    mojo::PendingReceiver<viz::mojom::blink::CompositorFrameSinkClient>
        client_receiver)
    : cc::LayerTreeFrameSink(std::move(context_provider),
                             std::move(worker_context_provider_wrapper),
                             std::move(compositor_task_runner),
                             gpu_memory_buffer_manager,
                             /*shared_image_interface=*/nullptr),
      layer_tree_frame_sink_id_(layer_tree_frame_sink_id),
      registry_(registry),
      memory_policy_(0u),
      unbound_compositor_frame_sink_(std::move(compositor_frame_sink_remote)),
      unbound_client_(std::move(client_receiver)),
      synthetic_begin_frame_source_(std::move(synthetic_begin_frame_source)),
      viz_frame_submission_enabled_(
          ::features::IsUsingVizFrameSubmissionForWebView()),
      use_zero_copy_sw_draw_(
          Platform::Current()
              ->IsZeroCopySynchronousSwDrawEnabledForAndroidWebView()) {
  DCHECK(registry_);
  DETACH_FROM_THREAD(thread_checker_);
  memory_policy_.priority_cutoff_when_visible =
      gpu::MemoryAllocation::CUTOFF_ALLOW_NICE_TO_HAVE;
}

SynchronousLayerTreeFrameSink::~SynchronousLayerTreeFrameSink() = default;

void SynchronousLayerTreeFrameSink::SetSyncClient(
    SynchronousLayerTreeFrameSinkClient* compositor) {
  sync_client_ = compositor;
}

bool SynchronousLayerTreeFrameSink::BindToClient(
    cc::LayerTreeFrameSinkClient* sink_client) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!cc::LayerTreeFrameSink::BindToClient(sink_client))
    return false;

  if (viz_frame_submission_enabled_) {
    compositor_frame_sink_.Bind(std::move(unbound_compositor_frame_sink_));
    client_receiver_.Bind(std::move(unbound_client_), compositor_task_runner_);
  }

  // The SharedBitmapManager is null since software compositing is not supported
  // or used on Android.
  frame_sink_manager_ = std::make_unique<viz::FrameSinkManagerImpl>(
      viz::FrameSinkManagerImpl::InitParams(
          /*shared_bitmap_manager=*/nullptr));

  if (synthetic_begin_frame_source_) {
    client_->SetBeginFrameSource(synthetic_begin_frame_source_.get());
  } else {
    external_begin_frame_source_ =
        std::make_unique<viz::ExternalBeginFrameSource>(this);
    external_begin_frame_source_->OnSetBeginFrameSourcePaused(
        begin_frames_paused_);
    client_->SetBeginFrameSource(external_begin_frame_source_.get());
  }

  client_->SetMemoryPolicy(memory_policy_);
  client_->SetTreeActivationCallback(base::BindRepeating(
      &SynchronousLayerTreeFrameSink::DidActivatePendingTree,
      base::Unretained(this)));
  registry_->RegisterLayerTreeFrameSink(this);

  software_frame_sink_client_ =
      std::make_unique<SoftwareCompositorFrameSinkClient>();
  constexpr bool root_support_is_root = true;
  constexpr bool child_support_is_root = false;
  root_support_ = std::make_unique<viz::CompositorFrameSinkSupport>(
      software_frame_sink_client_.get(), frame_sink_manager_.get(),
      kRootFrameSinkId, root_support_is_root);
  child_support_ = std::make_unique<viz::CompositorFrameSinkSupport>(
      software_frame_sink_client_.get(), frame_sink_manager_.get(),
      kChildFrameSinkId, child_support_is_root);

  viz::RendererSettings software_renderer_settings;

  auto output_surface = std::make_unique<SoftwareOutputSurface>(
      std::make_unique<SoftwareDevice>(&current_sw_canvas_));
  software_output_surface_ = output_surface.get();

  auto overlay_processor = std::make_unique<viz::OverlayProcessorStub>();

  // The gpu_memory_buffer_manager here is null as the Display is only used for
  // resourcesless software draws, where no resources are included in the frame
  // swapped from the compositor. So there is no need for it.
  // The shared_bitmap_manager_ is provided for the Display to allocate
  // resources.
  // TODO(crbug.com/692814): The Display never sends its resources out of
  // process so there is no reason for it to use a SharedBitmapManager.
  // The gpu::GpuTaskSchedulerHelper here is null as the OutputSurface is
  // software only and the overlay processor is a stub.
  display_ = std::make_unique<viz::Display>(
      &shared_bitmap_manager_, /*shared_image_manager=*/nullptr,
      /*gpu_scheduler=*/nullptr, software_renderer_settings, &debug_settings_,
      kRootFrameSinkId, nullptr /* gpu::GpuTaskSchedulerHelper */,
      std::move(output_surface), std::move(overlay_processor),
      nullptr /* scheduler */, nullptr /* current_task_runner */);
  display_->Initialize(&display_client_,
                       frame_sink_manager_->surface_manager());
  display_->SetVisible(true);
  return true;
}

void SynchronousLayerTreeFrameSink::DetachFromClient() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  client_->SetBeginFrameSource(nullptr);
  // Destroy the begin frame source on the same thread it was bound on.
  synthetic_begin_frame_source_ = nullptr;
  external_begin_frame_source_ = nullptr;
  if (sync_client_)
    sync_client_->SinkDestroyed();
  registry_->UnregisterLayerTreeFrameSink(this);
  client_->SetTreeActivationCallback(base::RepeatingClosure());
  root_support_.reset();
  child_support_.reset();
  software_frame_sink_client_ = nullptr;
  software_output_surface_ = nullptr;
  display_ = nullptr;
  frame_sink_manager_ = nullptr;

  client_receiver_.reset();
  compositor_frame_sink_.reset();

  cc::LayerTreeFrameSink::DetachFromClient();
}

void SynchronousLayerTreeFrameSink::SetLocalSurfaceId(
    const viz::LocalSurfaceId& local_surface_id) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  local_surface_id_ = local_surface_id;
}

void SynchronousLayerTreeFrameSink::SubmitCompositorFrame(
    viz::CompositorFrame frame,
    bool hit_test_data_changed) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(sync_client_);

  std::optional<viz::CompositorFrame> submit_frame;
  gfx::Size child_size = in_software_draw_
                             ? sw_viewport_for_current_draw_.size()
                             : frame.size_in_pixels();
  if (!child_local_surface_id_.is_valid() || child_size_ != child_size ||
      device_scale_factor_ != frame.metadata.device_scale_factor) {
    child_local_surface_id_allocator_.GenerateId();
    child_local_surface_id_ =
        child_local_surface_id_allocator_.GetCurrentLocalSurfaceId();
    child_size_ = child_size;
    device_scale_factor_ = frame.metadata.device_scale_factor;
  }

  if (in_software_draw_) {
    // The frame we send to the client is actually just the metadata. Preserve
    // the |frame| for the software path below.
    submit_frame.emplace();
    submit_frame->metadata = frame.metadata.Clone();

    // The layer compositor should be giving a frame that covers the
    // |sw_viewport_for_current_draw_| but at 0,0.
    DCHECK(gfx::Rect(child_size) == frame.render_pass_list.back()->output_rect);

    // Make a size that covers from 0,0 and includes the area coming from the
    // layer compositor.
    gfx::Size display_size(sw_viewport_for_current_draw_.right(),
                           sw_viewport_for_current_draw_.bottom());
    display_->Resize(display_size);

    if (!root_local_surface_id_.is_valid() || display_size_ != display_size ||
        root_device_scale_factor_ != frame.metadata.device_scale_factor) {
      root_local_surface_id_allocator_.GenerateId();
      root_local_surface_id_ =
          root_local_surface_id_allocator_.GetCurrentLocalSurfaceId();
      display_size_ = display_size;
      root_device_scale_factor_ = frame.metadata.device_scale_factor;
    }

    display_->SetLocalSurfaceId(root_local_surface_id_,
                                frame.metadata.device_scale_factor);

    // The offset for the child frame relative to the origin of the canvas being
    // drawn into.
    gfx::Transform child_transform;
    child_transform.Translate(
        gfx::Vector2dF(sw_viewport_for_current_draw_.OffsetFromOrigin()));

    // Make a root frame that embeds the frame coming from the layer compositor
    // and positions it based on the provided viewport.
    // TODO(danakj): We could apply the transform here instead of passing it to
    // the LayerTreeFrameSink client too? (We'd have to do the same for
    // hardware frames in SurfacesInstance?)
    viz::CompositorFrame embed_frame;
    embed_frame.metadata.frame_token = ++root_next_frame_token_;
    embed_frame.metadata.begin_frame_ack = frame.metadata.begin_frame_ack;
    embed_frame.metadata.device_scale_factor =
        frame.metadata.device_scale_factor;
    embed_frame.render_pass_list.push_back(viz::CompositorRenderPass::Create());

    // The embedding RenderPass covers the entire Display's area.
    const auto& embed_render_pass = embed_frame.render_pass_list.back();
    embed_render_pass->SetNew(viz::CompositorRenderPassId{1},
                              gfx::Rect(display_size), gfx::Rect(display_size),
                              gfx::Transform());
    embed_render_pass->has_transparent_background = false;

    // The RenderPass has a single SurfaceDrawQuad (and SharedQuadState for it).
    bool are_contents_opaque =
        !frame.render_pass_list.back()->has_transparent_background;
    auto* shared_quad_state =
        embed_render_pass->CreateAndAppendSharedQuadState();
    auto* surface_quad =
        embed_render_pass->CreateAndAppendDrawQuad<viz::SurfaceDrawQuad>();
    shared_quad_state->SetAll(
        child_transform, gfx::Rect(child_size), gfx::Rect(child_size),
        gfx::MaskFilterInfo(), /*clip=*/std::nullopt,
        /*contents_opaque=*/are_contents_opaque, /*opacity_f=*/1.f,
        SkBlendMode::kSrcOver, /*sorting_context=*/0,
        /*layer_id=*/0u, /*fast_rounded_corner=*/false);
    surface_quad->SetNew(
        shared_quad_state, gfx::Rect(child_size), gfx::Rect(child_size),
        viz::SurfaceRange(
            std::nullopt,
            viz::SurfaceId(kChildFrameSinkId, child_local_surface_id_)),
        SkColors::kWhite, false /* stretch_content_to_fill_bounds */);

    child_support_->SubmitCompositorFrame(child_local_surface_id_,
                                          std::move(frame));
    root_support_->SubmitCompositorFrame(root_local_surface_id_,
                                         std::move(embed_frame));
    base::TimeTicks now = base::TimeTicks::Now();
    display_->DrawAndSwap({now, now});

    // We don't track metrics for frames submitted to |display_| but it still
    // expects that every frame will receive a swap ack and presentation
    // feedback so we send null signals here.
    now = base::TimeTicks::Now();
    gpu::SwapBuffersCompleteParams params;
    params.swap_response.timings = {now, now};
    params.swap_response.result = gfx::SwapResult::SWAP_ACK;
    display_->DidReceiveSwapBuffersAck(params,
                                       /*release_fence=*/gfx::GpuFenceHandle());
    display_->DidReceivePresentationFeedback(
        gfx::PresentationFeedback::Failure());

    viz::FrameTimingDetails details;
    details.received_compositor_frame_timestamp = now;
    details.draw_start_timestamp = now;
    details.swap_timings = {now, now, now, now};
    details.presentation_feedback = {now, base::TimeDelta(), 0};
    client_->DidPresentCompositorFrame(submit_frame->metadata.frame_token,
                                       details);
  } else {
    if (viz_frame_submission_enabled_) {
      frame.metadata.begin_frame_ack =
          viz::BeginFrameAck::CreateManualAckWithDamage();

      // For hardware draws with viz we send frame to compositor_frame_sink_
      compositor_frame_sink_->SubmitCompositorFrame(
          local_surface_id_, std::move(frame), client_->BuildHitTestData(), 0);
    } else {
      // For hardware draws without viz we send the whole frame to the client so
      // it can draw the content in it.
      submit_frame = std::move(frame);
    }
  }

  // NOTE: submit_frame will be empty if viz_frame_submission_enabled_ enabled,
  // but it won't be used upstream
  // Because OnDraw can synchronously override the viewport without going
  // through commit and activation, we generate our own LocalSurfaceId by
  // checking the submitted frame instead of using the one set here.
  sync_client_->SubmitCompositorFrame(
      layer_tree_frame_sink_id_,
      viz_frame_submission_enabled_ ? local_surface_id_
                                    : child_local_surface_id_,
      std::move(submit_frame), client_->BuildHitTestData());
  did_submit_frame_ = true;
}

void SynchronousLayerTreeFrameSink::DidNotProduceFrame(
    const viz::BeginFrameAck& ack,
    cc::FrameSkippedReason reason) {
  // We do not call CompositorFrameSink::DidNotProduceFrame here because
  // submission of frame depends on DemandDraw calls.
}

void SynchronousLayerTreeFrameSink::DidAllocateSharedBitmap(
    base::ReadOnlySharedMemoryRegion region,
    const viz::SharedBitmapId& id) {
  // Webview does not use software compositing (other than resourceless draws,
  // but this is called for software /resources/).
  NOTREACHED();
}

void SynchronousLayerTreeFrameSink::DidDeleteSharedBitmap(
    const viz::SharedBitmapId& id) {
  // Webview does not use software compositing (other than resourceless draws,
  // but this is called for software /resources/).
  NOTREACHED();
}

void SynchronousLayerTreeFrameSink::Invalidate(bool needs_draw) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (sync_client_)
    sync_client_->Invalidate(needs_draw);
}

void SynchronousLayerTreeFrameSink::DemandDrawHw(
    const gfx::Size& viewport_size,
    const gfx::Rect& viewport_rect_for_tile_priority,
    const gfx::Transform& transform_for_tile_priority,
    bool need_new_local_surface_id) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(HasClient());
  DCHECK(context_provider_.get());

  if (need_new_local_surface_id) {
    child_local_surface_id_ = viz::LocalSurfaceId();
  }

  client_->SetExternalTilePriorityConstraints(viewport_rect_for_tile_priority,
                                              transform_for_tile_priority);
  InvokeComposite(gfx::Transform(), gfx::Rect(viewport_size));
}

void SynchronousLayerTreeFrameSink::DemandDrawSwZeroCopy() {
  DCHECK(use_zero_copy_sw_draw_);
  DemandDrawSw(
      Platform::Current()->SynchronousCompositorGetSkCanvasForAndroidWebView());
}

void SynchronousLayerTreeFrameSink::DemandDrawSw(SkCanvas* canvas) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(canvas);
  DCHECK(!current_sw_canvas_);

  base::AutoReset<raw_ptr<SkCanvas>> canvas_resetter(&current_sw_canvas_,
                                                     canvas);

  SkIRect canvas_clip = canvas->getDeviceClipBounds();
  gfx::Rect viewport = gfx::SkIRectToRect(canvas_clip);

  // Converts 3x3 matrix to 4x4.
  gfx::Transform transform = gfx::SkMatrixToTransform(canvas->getTotalMatrix());

  // We will resize the Display to ensure it covers the entire |viewport|, so
  // save it for later.
  sw_viewport_for_current_draw_ = viewport;

  base::AutoReset<bool> set_in_software_draw(&in_software_draw_, true);
  InvokeComposite(transform, viewport);
}

void SynchronousLayerTreeFrameSink::WillSkipDraw() {
  client_->OnDraw(gfx::Transform(), gfx::Rect(), in_software_draw_,
                  true /*skip_draw*/);
}

bool SynchronousLayerTreeFrameSink::UseZeroCopySoftwareDraw() {
  return use_zero_copy_sw_draw_;
}

void SynchronousLayerTreeFrameSink::InvokeComposite(
    const gfx::Transform& transform,
    const gfx::Rect& viewport) {
  did_submit_frame_ = false;
  // Adjust transform so that the layer compositor draws the |viewport| rect
  // at its origin. The offset of the |viewport| we pass to the layer compositor
  // must also be zero, since the rect needs to be in the coordinates of the
  // layer compositor.
  gfx::Transform adjusted_transform = transform;
  adjusted_transform.PostTranslate(-viewport.OffsetFromOrigin());
  // Don't propagate the viewport origin, as it will affect the clip rect.
  client_->OnDraw(adjusted_transform, gfx::Rect(viewport.size()),
                  in_software_draw_, false /*skip_draw*/);

  if (did_submit_frame_) {
    // This must happen after unwinding the stack and leaving the compositor.
    // Usually it is a separate task but we just defer it until OnDraw
    // completes instead.
    client_->DidReceiveCompositorFrameAck();
  }
}

void SynchronousLayerTreeFrameSink::ReclaimResources(
    uint32_t layer_tree_frame_sink_id,
    Vector<viz::ReturnedResource> resources) {
  // Ignore message if it's a stale one coming from a different output surface
  // (e.g. after a lost context).
  if (layer_tree_frame_sink_id != layer_tree_frame_sink_id_)
    return;
  client_->ReclaimResources(std::vector<viz::ReturnedResource>(
      std::make_move_iterator(resources.begin()),
      std::make_move_iterator(resources.end())));
}

void SynchronousLayerTreeFrameSink::
    OnCompositorFrameTransitionDirectiveProcessed(
        uint32_t layer_tree_frame_sink_id,
        uint32_t sequence_id) {
  if (layer_tree_frame_sink_id != layer_tree_frame_sink_id_)
    return;
  client_->OnCompositorFrameTransitionDirectiveProcessed(sequence_id);
}

void SynchronousLayerTreeFrameSink::SetMemoryPolicy(size_t bytes_limit) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  bool became_zero = memory_policy_.bytes_limit_when_visible && !bytes_limit;
  bool became_non_zero =
      !memory_policy_.bytes_limit_when_visible && bytes_limit;
  memory_policy_.bytes_limit_when_visible = bytes_limit;
  memory_policy_.num_resources_limit = kNumResourcesLimit;

  if (client_)
    client_->SetMemoryPolicy(memory_policy_);

  if (became_zero) {
    // This is small hack to drop context resources without destroying it
    // when this compositor is put into the background.
    context_provider()->ContextSupport()->SetAggressivelyFreeResources(
        true /* aggressively_free_resources */);
  } else if (became_non_zero) {
    context_provider()->ContextSupport()->SetAggressivelyFreeResources(
        false /* aggressively_free_resources */);
  }
}

void SynchronousLayerTreeFrameSink::DidActivatePendingTree() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (sync_client_)
    sync_client_->DidActivatePendingTree();
}

void SynchronousLayerTreeFrameSink::DidReceiveCompositorFrameAck(
    Vector<viz::ReturnedResource> resources) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(viz_frame_submission_enabled_);
  client_->ReclaimResources(std::vector<viz::ReturnedResource>(
      std::make_move_iterator(resources.begin()),
      std::make_move_iterator(resources.end())));
  // client_->DidReceiveCompositorFrameAck() is called just after frame
  // submission so cc won't be throttled on actual draw which can happen late
  // (or not happen at all) for WebView.
}

void SynchronousLayerTreeFrameSink::OnBeginFrame(
    const viz::BeginFrameArgs& args,
    const HashMap<uint32_t, viz::FrameTimingDetails>& timing_details,
    bool frame_ack,
    Vector<viz::ReturnedResource> resources) {
  DCHECK(viz_frame_submission_enabled_);
  if (::features::IsOnBeginFrameAcksEnabled()) {
    if (frame_ack) {
      DidReceiveCompositorFrameAck(std::move(resources));
    } else if (!resources.empty()) {
      ReclaimResources(std::move(resources));
    }
  }

  // We do not receive BeginFrames via CompositorFrameSink, so we do not forward
  // it to cc. We still might get one with FrameTimingDetailsMap, so we report
  // it here.

  if (client_) {
    for (const auto& pair : timing_details) {
      client_->DidPresentCompositorFrame(pair.key, pair.value);
    }
  }
}

void SynchronousLayerTreeFrameSink::ReclaimResources(
    Vector<viz::ReturnedResource> resources) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(viz_frame_submission_enabled_);
  client_->ReclaimResources(std::vector<viz::ReturnedResource>(
      std::make_move_iterator(resources.begin()),
      std::make_move_iterator(resources.end())));
}

void SynchronousLayerTreeFrameSink::OnBeginFramePausedChanged(bool paused) {
  DCHECK(viz_frame_submission_enabled_);
}

void SynchronousLayerTreeFrameSink::OnNeedsBeginFrames(
    bool needs_begin_frames) {
  if (needs_begin_frames_ != needs_begin_frames) {
    if (needs_begin_frames) {
      TRACE_EVENT_NESTABLE_ASYNC_BEGIN0("cc,benchmark", "NeedsBeginFrames",
                                        this);
    } else {
      TRACE_EVENT_NESTABLE_ASYNC_END0("cc,benchmark", "NeedsBeginFrames", this);
    }
  }
  needs_begin_frames_ = needs_begin_frames;
  if (sync_client_) {
    sync_client_->SetNeedsBeginFrames(needs_begin_frames);
  }
}

void SynchronousLayerTreeFrameSink::DidPresentCompositorFrame(
    const viz::FrameTimingDetailsMap& timing_details) {
  DCHECK(!viz_frame_submission_enabled_ || timing_details.empty());

  if (!client_)
    return;
  for (const auto& pair : timing_details)
    client_->DidPresentCompositorFrame(pair.first, pair.second);
}

void SynchronousLayerTreeFrameSink::BeginFrame(
    const viz::BeginFrameArgs& args) {
  if (!external_begin_frame_source_)
    return;
  external_begin_frame_source_->OnBeginFrame(args);
}

void SynchronousLayerTreeFrameSink::SetBeginFrameSourcePaused(bool paused) {
  if (external_begin_frame_source_)
    external_begin_frame_source_->OnSetBeginFrameSourcePaused(paused);
}

}  // namespace blink

"""

```