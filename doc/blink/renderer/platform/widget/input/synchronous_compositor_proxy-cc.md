Response:
Let's break down the thought process to analyze the provided C++ code for `SynchronousCompositorProxy`.

1. **Understand the Purpose:** The file path `blink/renderer/platform/widget/input/synchronous_compositor_proxy.cc` immediately suggests this class acts as an intermediary or a proxy related to composition and input handling, specifically in a *synchronous* manner. The "proxy" suffix is a strong hint.

2. **Identify Key Dependencies:** Look at the `#include` directives. This reveals core functionalities and external components the class interacts with:
    * `InputHandlerProxy`:  Clearly related to input events.
    * `viz/common/features.h`:  Indicates interaction with the Viz compositor framework and feature flags.
    * `SkBitmap`, `SkCanvas`, etc.:  Signals involvement in drawing and rendering, likely using Skia.
    * `ui/gfx/geometry/skia_conversions.h`: More evidence of Skia usage for geometry conversions.
    * `base/functional/bind.h`, `base/memory/shared_memory_mapping.h`:  Points to asynchronous operations and shared memory usage.
    * `mojom::blink::...`:  Indicates Mojo interface definitions, suggesting communication with other processes.

3. **Analyze the Constructor and Destructor:**
    * Constructor: Takes an `InputHandlerProxy*`, initializes various flags related to Viz, page scale, and invalidation. Crucially, it asserts that the `input_handler_proxy_` is not null.
    * Destructor:  Asserts that `layer_tree_frame_sink_` is null and unregisters itself with the `input_handler_proxy_`. This hints at a lifecycle tied to the frame sink.

4. **Examine Key Methods and Group Functionality:** Go through the public methods and try to categorize them:
    * **Initialization and Setup:** `Init()`, `SetLayerTreeFrameSink()`, `BindChannel()`, `SetSharedMemory()`. These methods are about setting up the communication channels and resources.
    * **State Management:** `UpdateRootLayerState()`. This likely updates internal state based on information from other parts of the rendering pipeline.
    * **Invalidation and Drawing:** `Invalidate()`, `DemandDrawHw()`, `DemandDrawSw()`, `WillSkipDraw()`, `SubmitCompositorFrame()`, `ZeroSharedMemory()`, `DoDemandDrawSw()`. These are central to the class's purpose of handling drawing requests. The "Hw" and "Sw" suffixes likely mean hardware and software drawing.
    * **Synchronization and Control:** `SetNeedsBeginFrames()`, `SetBeginFrameSourcePaused()`, `BeginFrame()`, `SetScroll()`, `SetMemoryPolicy()`, `ReclaimResources()`, `OnCompositorFrameTransitionDirectiveProcessed()`. These control the timing and resource management of the compositor.
    * **Zooming:** `ZoomBy()`. A specific type of interaction.
    * **Communication (Mojo):** `SendDemandDrawHwAsyncReply()`, `SendBeginFrameResponse()`, `SendAsyncRendererStateIfNeeded()`, `LayerTreeFrameSinkCreated()`, `HostDisconnected()`. These handle sending and receiving messages via Mojo.
    * **Internal Helpers:** `PopulateNewCommonParams()`, `NextMetadataVersion()`. These prepare data for communication.

5. **Identify Relationships with Web Technologies:**
    * **HTML:** The concept of scrolling (`UpdateRootLayerState`, `SetScroll`) directly relates to how web pages are displayed and navigated. The `scrollable_size` and scroll offsets are properties of HTML elements.
    * **CSS:** Page scale (`page_scale_factor`, `min_page_scale_factor`, `max_page_scale_factor`) is influenced by CSS zoom properties and viewport settings. The `transform` parameter in `DemandDrawSw` relates to CSS transformations. The `clip` parameter in `DemandDrawSw` relates to CSS clipping.
    * **JavaScript:** JavaScript can trigger layout changes that necessitate invalidation (`Invalidate`). It can also initiate scrolling and zooming actions that this proxy handles.

6. **Look for Logic and Assumptions:**
    * The class maintains a version number (`version_`, `metadata_version_`) for synchronization.
    * It uses shared memory for software drawing, optimizing data transfer.
    * It distinguishes between hardware and software drawing paths.
    * It tracks invalidation state to optimize drawing.

7. **Consider Potential Usage Errors:**
    * Setting the LayerTreeFrameSink multiple times without proper cleanup.
    * Issues with shared memory management (e.g., incorrect size, access violations).
    * Incorrectly managing the paused state of the begin frame source.

8. **Structure the Output:** Organize the findings into logical sections: Functionality, Relationship with Web Technologies (with examples), Logical Inferences (with assumptions and I/O), and Potential Usage Errors.

9. **Refine and Elaborate:** Flesh out the descriptions with more detail and clarity. For instance, instead of just saying "handles drawing," explain the different drawing methods and their implications. Provide specific examples of how JavaScript, HTML, and CSS interact with the proxy's functions.

Self-Correction/Refinement during the process:

* Initially, I might have missed the significance of the `viz_frame_submission_enabled_` flag. Reviewing the `SubmitCompositorFrame` method highlights its role in determining how compositor frames are submitted.
* I might initially oversimplify the relationship with JavaScript. Realizing that JavaScript doesn't directly call this class but rather triggers actions that *lead* to its methods being called is important.
* Ensuring the assumptions and I/O examples are concrete and easy to understand is crucial for demonstrating logical reasoning.

By following these steps, we can systematically analyze the C++ code and provide a comprehensive explanation of its functionality and interactions.这个C++源代码文件 `synchronous_compositor_proxy.cc` 定义了 `blink::SynchronousCompositorProxy` 类，它是 Chromium Blink 渲染引擎中用于处理同步合成的一个关键组件。它的主要功能是作为渲染器进程中负责合成（将网页内容绘制到屏幕上）的部分与浏览器进程中的合成器之间的桥梁。由于是“同步”合成，它通常用于一些特定的场景，例如 WebView 或插件，在这些场景下，渲染过程需要更直接的控制。

以下是 `SynchronousCompositorProxy` 的主要功能列表：

**核心功能：**

1. **管理和同步合成状态：**  维护并同步渲染器的合成状态信息，例如滚动偏移、页面缩放因子等，到浏览器进程。
2. **处理绘制请求：**  接收来自渲染器的绘制请求（硬件加速和软件绘制），并将其转发到浏览器进程的合成器。
3. **管理 `LayerTreeFrameSink`：**  负责与 `SynchronousLayerTreeFrameSink` 实例交互，该实例是实际执行合成的组件。
4. **处理输入事件：** 虽然文件本身不直接处理原始输入事件，但它与 `InputHandlerProxy` 关联，后者负责将输入事件传递给合成器。
5. **管理共享内存：**  在软件绘制的情况下，管理用于存储绘制结果的共享内存。
6. **控制合成器的行为：**  例如，可以暂停和恢复合成器的帧生成。
7. **与浏览器进程通信：**  通过 Mojo 接口 `SynchronousCompositorControlHost` 和 `SynchronousCompositorHost` 与浏览器进程进行通信。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`SynchronousCompositorProxy` 虽然是用 C++ 实现的，但它直接服务于渲染网页的目的，因此与 JavaScript, HTML, CSS 的功能息息相关。

* **HTML (结构):**
    * **滚动：** 当用户滚动网页时，JavaScript 或浏览器默认行为会改变页面的滚动偏移。`SynchronousCompositorProxy::UpdateRootLayerState` 会接收到更新后的 `total_scroll_offset`，并将其同步到浏览器进程。这保证了浏览器进程中的合成器也能感知到滚动位置，从而正确渲染可见区域。
        * **假设输入：** 用户向下滚动网页，导致 `total_scroll_offset` 从 `(0, 0)` 变为 `(0, 100)`.
        * **输出：** `SynchronousCompositorProxy` 将新的 `total_scroll_offset` `(0, 100)` 发送给浏览器进程。
    * **页面大小和可滚动区域：**  HTML 内容的尺寸决定了 `scrollable_size` 和 `max_scroll_offset`。`SynchronousCompositorProxy::UpdateRootLayerState` 会同步这些信息，确保合成器知道页面的完整尺寸。
        * **假设输入：**  一个 HTML 文档的 `body` 元素的高度为 `1000px`，视口高度为 `600px`。
        * **输出：** `SynchronousCompositorProxy` 将 `scrollable_size` 设置为合适的尺寸，并将 `max_scroll_offset` 更新为 `(0, 400)`（假设垂直滚动）。

* **CSS (样式):**
    * **缩放：** CSS 的 `zoom` 属性或用户的缩放操作会改变页面的缩放因子。`SynchronousCompositorProxy::UpdateRootLayerState` 会同步 `page_scale_factor`，`min_page_scale_factor` 和 `max_page_scale_factor`。
        * **假设输入：** 用户使用 Ctrl + 加号键放大页面，导致 `page_scale_factor` 从 `1.0` 变为 `1.2`.
        * **输出：** `SynchronousCompositorProxy` 将新的 `page_scale_factor` `1.2` 发送给浏览器进程。
    * **变换 (Transform)：**  CSS 的 `transform` 属性可以改变元素的位置、旋转、缩放等。在软件绘制的情况下，`SynchronousCompositorProxy::DemandDrawSw` 接收到的 `params->transform` 就反映了这些 CSS 变换，用于正确地在共享内存中绘制内容。
        * **假设输入：** 一个带有 `transform: rotate(45deg);` CSS 规则的元素需要进行软件绘制。
        * **输出：** `DemandDrawSw` 的 `params->transform` 将包含一个表示 45 度旋转的变换矩阵。
    * **裁剪 (Clip)：** CSS 的 `clip` 或 `overflow: hidden` 等属性可以裁剪元素的可视区域。`SynchronousCompositorProxy::DemandDrawSw` 接收到的 `params->clip` 定义了需要绘制的区域。
        * **假设输入：** 一个元素的 `overflow: hidden;` 导致其内容被裁剪到一个 `100x100` 的矩形区域。
        * **输出：** `DemandDrawSw` 的 `params->clip` 将是一个 `gfx::Rect`，表示 `(0, 0)` 到 `(100, 100)` 的区域。

* **JavaScript (行为):**
    * **触发重绘/重排：** JavaScript 代码修改 DOM 结构或 CSS 样式可能会触发浏览器的重绘或重排。这可能导致 `SynchronousCompositorProxy::Invalidate` 被调用，通知合成器需要重新绘制部分或全部内容。
        * **假设输入：** JavaScript 代码通过 `element.style.backgroundColor = 'red';` 修改了一个元素的背景颜色。
        * **输出：** `SynchronousCompositorProxy::Invalidate(true)` 被调用，`invalidate_needs_draw_` 被设置为 `true`，表明需要重新绘制。
    * **滚动操作：** JavaScript 可以通过 `window.scrollTo()` 或修改元素的 `scrollTop` 和 `scrollLeft` 属性来控制滚动。这些操作最终会影响 `SynchronousCompositorProxy::UpdateRootLayerState` 中同步的滚动偏移。
        * **假设输入：** JavaScript 代码执行 `window.scrollTo(0, 500);`。
        * **输出：** `SynchronousCompositorProxy::UpdateRootLayerState` 将接收到新的 `total_scroll_offset` `(0, 500)`。
    * **请求动画帧 (requestAnimationFrame)：** 虽然不直接调用 `SynchronousCompositorProxy` 的方法，但 `requestAnimationFrame` 的回调通常会触发 DOM 或 CSS 的变化，最终导致合成过程的发生。

**逻辑推理的假设输入与输出：**

* **假设输入：**  `SynchronousCompositorProxy::Invalidate(true)` 被调用，然后 `SynchronousCompositorProxy::DemandDrawHw` 被调用。
* **输出：**  `invalidate_needs_draw_` 标志会被设置为 `true`，并且在 `DemandDrawHw` 的处理过程中，可能会触发硬件加速的绘制流程，并将绘制结果通过 `SubmitCompositorFrame` 发送回浏览器进程。同时，`invalidate_needs_draw_` 会在 `DemandDrawHw` 开始时被重置为 `false`。

**用户或编程常见的使用错误举例：**

1. **未正确初始化 `LayerTreeFrameSink`：** 如果在没有设置有效的 `LayerTreeFrameSink` 的情况下调用需要它的方法（例如 `DemandDrawHw`），会导致程序崩溃或出现未定义行为。
    * **错误代码示例：**
      ```c++
      SynchronousCompositorProxy proxy(input_handler);
      // ... 没有调用 SetLayerTreeFrameSink ...
      proxy.DemandDrawHw(params, callback); // 错误：layer_tree_frame_sink_ 为空
      ```
2. **共享内存管理错误：** 在软件绘制中，如果共享内存的分配、大小或使用方式不正确，会导致绘制失败或内存错误。例如，尝试写入超出共享内存范围的数据。
    * **错误代码示例：**
      ```c++
      // 假设分配的共享内存大小为 1024 字节
      SkBitmap bitmap;
      bitmap.installPixels(info, mem.data(), stride); // info 导致需要写入超过 1024 字节的数据
      SkCanvas canvas(bitmap);
      canvas.drawRect( SkRect::MakeWH(2048, 2048), paint); // 尝试绘制超出共享内存的区域
      ```
3. **不匹配的 `BeginFrame` 和绘制流程：**  如果 `SynchronousCompositorProxy` 收到了 `BeginFrame` 事件，但没有及时响应并进行绘制，可能会导致页面卡顿或动画不流畅。
4. **在不应该同步合成的场景下使用：**  `SynchronousCompositorProxy` 主要用于特定的同步合成场景。在常规的网页渲染流程中使用可能会引入性能问题或不必要的复杂性。

总而言之，`SynchronousCompositorProxy` 是 Blink 渲染引擎中一个负责连接渲染器进程和浏览器进程合成器的关键组件，它处理绘制请求、同步状态，并与网页技术（HTML, CSS, JavaScript）的功能紧密相关，以确保网页内容能够正确且及时地渲染到屏幕上。开发者在使用相关 API 时需要注意正确的初始化、资源管理以及流程控制，以避免潜在的错误。

Prompt: 
```
这是目录为blink/renderer/platform/widget/input/synchronous_compositor_proxy.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/input/synchronous_compositor_proxy.h"

#include "base/functional/bind.h"
#include "base/memory/shared_memory_mapping.h"
#include "components/viz/common/features.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "third_party/skia/include/core/SkImageInfo.h"
#include "third_party/skia/include/core/SkRegion.h"
#include "ui/gfx/geometry/skia_conversions.h"

namespace blink {

SynchronousCompositorProxy::SynchronousCompositorProxy(
    InputHandlerProxy* input_handler_proxy)
    : input_handler_proxy_(input_handler_proxy),
      viz_frame_submission_enabled_(
          features::IsUsingVizFrameSubmissionForWebView()),
      page_scale_factor_(0.f),
      min_page_scale_factor_(0.f),
      max_page_scale_factor_(0.f),
      need_invalidate_count_(0u),
      invalidate_needs_draw_(false),
      did_activate_pending_tree_count_(0u) {
  DCHECK(input_handler_proxy_);
}

SynchronousCompositorProxy::~SynchronousCompositorProxy() {
  // The LayerTreeFrameSink is destroyed/removed by the compositor before
  // shutting down everything.
  DCHECK_EQ(layer_tree_frame_sink_, nullptr);
  input_handler_proxy_->SetSynchronousInputHandler(nullptr);
}

void SynchronousCompositorProxy::Init() {
  input_handler_proxy_->SetSynchronousInputHandler(this);
}

void SynchronousCompositorProxy::SetLayerTreeFrameSink(
    SynchronousLayerTreeFrameSink* layer_tree_frame_sink) {
  DCHECK_NE(layer_tree_frame_sink_, layer_tree_frame_sink);
  DCHECK(layer_tree_frame_sink);
  if (layer_tree_frame_sink_) {
    layer_tree_frame_sink_->SetSyncClient(nullptr);
  }
  layer_tree_frame_sink_ = layer_tree_frame_sink;
  use_in_process_zero_copy_software_draw_ =
      layer_tree_frame_sink_->UseZeroCopySoftwareDraw();
  layer_tree_frame_sink_->SetSyncClient(this);
  LayerTreeFrameSinkCreated();
  if (begin_frame_paused_)
    layer_tree_frame_sink_->SetBeginFrameSourcePaused(true);
}

void SynchronousCompositorProxy::UpdateRootLayerState(
    const gfx::PointF& total_scroll_offset,
    const gfx::PointF& max_scroll_offset,
    const gfx::SizeF& scrollable_size,
    float page_scale_factor,
    float min_page_scale_factor,
    float max_page_scale_factor) {
  if (total_scroll_offset_ != total_scroll_offset ||
      max_scroll_offset_ != max_scroll_offset ||
      scrollable_size_ != scrollable_size ||
      page_scale_factor_ != page_scale_factor ||
      min_page_scale_factor_ != min_page_scale_factor ||
      max_page_scale_factor_ != max_page_scale_factor) {
    total_scroll_offset_ = total_scroll_offset;
    max_scroll_offset_ = max_scroll_offset;
    scrollable_size_ = scrollable_size;
    page_scale_factor_ = page_scale_factor;
    min_page_scale_factor_ = min_page_scale_factor;
    max_page_scale_factor_ = max_page_scale_factor;

    SendAsyncRendererStateIfNeeded();
  }
}

void SynchronousCompositorProxy::Invalidate(bool needs_draw) {
  ++need_invalidate_count_;
  invalidate_needs_draw_ |= needs_draw;
  SendAsyncRendererStateIfNeeded();
}

void SynchronousCompositorProxy::DidActivatePendingTree() {
  ++did_activate_pending_tree_count_;
  SendAsyncRendererStateIfNeeded();
}

mojom::blink::SyncCompositorCommonRendererParamsPtr
SynchronousCompositorProxy::PopulateNewCommonParams() {
  mojom::blink::SyncCompositorCommonRendererParamsPtr params =
      mojom::blink::SyncCompositorCommonRendererParams::New();
  params->version = ++version_;
  params->total_scroll_offset = total_scroll_offset_;
  params->max_scroll_offset = max_scroll_offset_;
  params->scrollable_size = scrollable_size_;
  params->page_scale_factor = page_scale_factor_;
  params->min_page_scale_factor = min_page_scale_factor_;
  params->max_page_scale_factor = max_page_scale_factor_;
  params->need_invalidate_count = need_invalidate_count_;
  params->invalidate_needs_draw = invalidate_needs_draw_;
  params->did_activate_pending_tree_count = did_activate_pending_tree_count_;
  return params;
}

void SynchronousCompositorProxy::DemandDrawHwAsync(
    mojom::blink::SyncCompositorDemandDrawHwParamsPtr params) {
  DemandDrawHw(
      std::move(params),
      base::BindOnce(&SynchronousCompositorProxy::SendDemandDrawHwAsyncReply,
                     base::Unretained(this)));
}

void SynchronousCompositorProxy::DemandDrawHw(
    mojom::blink::SyncCompositorDemandDrawHwParamsPtr params,
    DemandDrawHwCallback callback) {
  invalidate_needs_draw_ = false;
  hardware_draw_reply_ = std::move(callback);

  if (layer_tree_frame_sink_) {
    layer_tree_frame_sink_->DemandDrawHw(
        params->viewport_size, params->viewport_rect_for_tile_priority,
        params->transform_for_tile_priority, params->need_new_local_surface_id);
  }

  // Ensure that a response is always sent even if the reply hasn't
  // generated a compostior frame.
  if (hardware_draw_reply_) {
    // Did not swap.
    std::move(hardware_draw_reply_)
        .Run(PopulateNewCommonParams(), 0u, 0u, std::nullopt, std::nullopt,
             std::nullopt);
  }
}

void SynchronousCompositorProxy::WillSkipDraw() {
  if (layer_tree_frame_sink_) {
    layer_tree_frame_sink_->WillSkipDraw();
  }
}

struct SynchronousCompositorProxy::SharedMemoryWithSize {
  base::WritableSharedMemoryMapping shared_memory;
  const size_t buffer_size;
  bool zeroed;

  SharedMemoryWithSize(base::WritableSharedMemoryMapping shm_mapping,
                       size_t buffer_size)
      : shared_memory(std::move(shm_mapping)),
        buffer_size(buffer_size),
        zeroed(true) {}
};

void SynchronousCompositorProxy::ZeroSharedMemory() {
  // It is possible for this to get called twice, eg. if draw is called before
  // the LayerTreeFrameSink is ready. Just ignore duplicated calls rather than
  // inventing a complicated system to avoid it.
  if (software_draw_shm_->zeroed)
    return;

  base::span<uint8_t> mem(software_draw_shm_->shared_memory);
  std::ranges::fill(mem.first(software_draw_shm_->buffer_size), 0u);
  software_draw_shm_->zeroed = true;
}

void SynchronousCompositorProxy::DemandDrawSw(
    mojom::blink::SyncCompositorDemandDrawSwParamsPtr params,
    DemandDrawSwCallback callback) {
  invalidate_needs_draw_ = false;

  software_draw_reply_ = std::move(callback);
  if (layer_tree_frame_sink_) {
    if (use_in_process_zero_copy_software_draw_) {
      layer_tree_frame_sink_->DemandDrawSwZeroCopy();
    } else {
      DoDemandDrawSw(std::move(params));
    }
  }

  // Ensure that a response is always sent even if the reply hasn't
  // generated a compostior frame.
  if (software_draw_reply_) {
    // Did not swap.
    std::move(software_draw_reply_)
        .Run(PopulateNewCommonParams(), 0u, std::nullopt);
  }
}

void SynchronousCompositorProxy::DoDemandDrawSw(
    mojom::blink::SyncCompositorDemandDrawSwParamsPtr params) {
  DCHECK(layer_tree_frame_sink_);
  DCHECK(software_draw_shm_->zeroed);
  software_draw_shm_->zeroed = false;

  SkImageInfo info =
      SkImageInfo::MakeN32Premul(params->size.width(), params->size.height());
  size_t stride = info.minRowBytes();
  size_t buffer_size = info.computeByteSize(stride);
  DCHECK_EQ(software_draw_shm_->buffer_size, buffer_size);

  base::span<uint8_t> mem(software_draw_shm_->shared_memory);
  CHECK_GE(mem.size(), buffer_size);
  SkBitmap bitmap;
  if (!bitmap.installPixels(info, mem.data(), stride)) {
    return;
  }
  SkCanvas canvas(bitmap);
  canvas.clipRect(gfx::RectToSkRect(params->clip));
  canvas.concat(gfx::TransformToFlattenedSkMatrix(params->transform));

  layer_tree_frame_sink_->DemandDrawSw(&canvas);
}

void SynchronousCompositorProxy::SubmitCompositorFrame(
    uint32_t layer_tree_frame_sink_id,
    const viz::LocalSurfaceId& local_surface_id,
    std::optional<viz::CompositorFrame> frame,
    std::optional<viz::HitTestRegionList> hit_test_region_list) {
  // Verify that exactly one of these is true.
  DCHECK(hardware_draw_reply_.is_null() ^ software_draw_reply_.is_null());
  mojom::blink::SyncCompositorCommonRendererParamsPtr common_renderer_params =
      PopulateNewCommonParams();

  if (hardware_draw_reply_) {
    // For viz the CF was submitted directly via CompositorFrameSink
    DCHECK(frame || viz_frame_submission_enabled_);
    DCHECK(local_surface_id.is_valid());
    std::move(hardware_draw_reply_)
        .Run(std::move(common_renderer_params), layer_tree_frame_sink_id,
             NextMetadataVersion(), local_surface_id, std::move(frame),
             std::move(hit_test_region_list));
  } else if (software_draw_reply_) {
    DCHECK(frame);
    std::move(software_draw_reply_)
        .Run(std::move(common_renderer_params), NextMetadataVersion(),
             std::move(frame->metadata));
  } else {
    NOTREACHED();
  }
}

void SynchronousCompositorProxy::SetNeedsBeginFrames(bool needs_begin_frames) {
  if (needs_begin_frames_ == needs_begin_frames)
    return;
  needs_begin_frames_ = needs_begin_frames;
  if (host_)
    host_->SetNeedsBeginFrames(needs_begin_frames);
}

void SynchronousCompositorProxy::SinkDestroyed() {
  layer_tree_frame_sink_ = nullptr;
}

void SynchronousCompositorProxy::SetThreads(
    const Vector<viz::Thread>& threads) {
  if (threads_ == threads) {
    return;
  }
  threads_ = threads;
  if (host_) {
    host_->SetThreads(threads_);
  }
}

void SynchronousCompositorProxy::SetBeginFrameSourcePaused(bool paused) {
  begin_frame_paused_ = paused;
  if (layer_tree_frame_sink_)
    layer_tree_frame_sink_->SetBeginFrameSourcePaused(paused);
}

void SynchronousCompositorProxy::BeginFrame(
    const viz::BeginFrameArgs& args,
    const HashMap<uint32_t, viz::FrameTimingDetails>& timing_details) {
  if (layer_tree_frame_sink_) {
    base::flat_map<uint32_t, viz::FrameTimingDetails> timings;
    for (const auto& pair : timing_details) {
      timings[pair.key] = pair.value;
    }
    layer_tree_frame_sink_->DidPresentCompositorFrame(timings);
    if (needs_begin_frames_)
      layer_tree_frame_sink_->BeginFrame(args);
  }

  SendBeginFrameResponse(PopulateNewCommonParams());
}

void SynchronousCompositorProxy::SetScroll(
    const gfx::PointF& new_total_scroll_offset) {
  if (total_scroll_offset_ == new_total_scroll_offset)
    return;
  total_scroll_offset_ = new_total_scroll_offset;
  input_handler_proxy_->SynchronouslySetRootScrollOffset(total_scroll_offset_);
}

void SynchronousCompositorProxy::SetMemoryPolicy(uint32_t bytes_limit) {
  if (!layer_tree_frame_sink_)
    return;
  layer_tree_frame_sink_->SetMemoryPolicy(bytes_limit);
}

void SynchronousCompositorProxy::ReclaimResources(
    uint32_t layer_tree_frame_sink_id,
    Vector<viz::ReturnedResource> resources) {
  if (!layer_tree_frame_sink_)
    return;
  layer_tree_frame_sink_->ReclaimResources(layer_tree_frame_sink_id,
                                           std::move(resources));
}

void SynchronousCompositorProxy::OnCompositorFrameTransitionDirectiveProcessed(
    uint32_t layer_tree_frame_sink_id,
    uint32_t sequence_id) {
  if (!layer_tree_frame_sink_)
    return;
  layer_tree_frame_sink_->OnCompositorFrameTransitionDirectiveProcessed(
      layer_tree_frame_sink_id, sequence_id);
}

void SynchronousCompositorProxy::SetSharedMemory(
    base::WritableSharedMemoryRegion shm_region,
    SetSharedMemoryCallback callback) {
  bool success = false;
  mojom::blink::SyncCompositorCommonRendererParamsPtr common_renderer_params;
  if (shm_region.IsValid()) {
    base::WritableSharedMemoryMapping shm_mapping = shm_region.Map();
    if (shm_mapping.IsValid()) {
      software_draw_shm_ = std::make_unique<SharedMemoryWithSize>(
          std::move(shm_mapping), shm_mapping.size());
      common_renderer_params = PopulateNewCommonParams();
      success = true;
    }
  }
  if (!common_renderer_params) {
    common_renderer_params =
        mojom::blink::SyncCompositorCommonRendererParams::New();
  }
  std::move(callback).Run(success, std::move(common_renderer_params));
}

void SynchronousCompositorProxy::ZoomBy(float zoom_delta,
                                        const gfx::Point& anchor,
                                        ZoomByCallback callback) {
  zoom_by_reply_ = std::move(callback);
  input_handler_proxy_->SynchronouslyZoomBy(zoom_delta, anchor);
  std::move(zoom_by_reply_).Run(PopulateNewCommonParams());
}

uint32_t SynchronousCompositorProxy::NextMetadataVersion() {
  return ++metadata_version_;
}

void SynchronousCompositorProxy::SendDemandDrawHwAsyncReply(
    mojom::blink::SyncCompositorCommonRendererParamsPtr,
    uint32_t layer_tree_frame_sink_id,
    uint32_t metadata_version,
    const std::optional<viz::LocalSurfaceId>& local_surface_id,
    std::optional<viz::CompositorFrame> frame,
    std::optional<viz::HitTestRegionList> hit_test_region_list) {
  control_host_->ReturnFrame(layer_tree_frame_sink_id, metadata_version,
                             local_surface_id, std::move(frame),
                             std::move(hit_test_region_list));
}

void SynchronousCompositorProxy::SendBeginFrameResponse(
    mojom::blink::SyncCompositorCommonRendererParamsPtr param) {
  control_host_->BeginFrameResponse(std::move(param));
}

void SynchronousCompositorProxy::SendAsyncRendererStateIfNeeded() {
  if (hardware_draw_reply_ || software_draw_reply_ || zoom_by_reply_ || !host_)
    return;

  host_->UpdateState(PopulateNewCommonParams());
}

void SynchronousCompositorProxy::LayerTreeFrameSinkCreated() {
  DCHECK(layer_tree_frame_sink_);
  if (host_)
    host_->LayerTreeFrameSinkCreated();
}

void SynchronousCompositorProxy::BindChannel(
    mojo::PendingRemote<mojom::blink::SynchronousCompositorControlHost>
        control_host,
    mojo::PendingAssociatedRemote<mojom::blink::SynchronousCompositorHost> host,
    mojo::PendingAssociatedReceiver<mojom::blink::SynchronousCompositor>
        compositor_request) {
  // Reset bound mojo channels before rebinding new variants as the
  // associated RenderWidgetHost may be reused.
  control_host_.reset();
  host_.reset();
  receiver_.reset();
  control_host_.Bind(std::move(control_host));
  host_.Bind(std::move(host));
  receiver_.Bind(std::move(compositor_request));
  receiver_.set_disconnect_handler(base::BindOnce(
      &SynchronousCompositorProxy::HostDisconnected, base::Unretained(this)));

  if (layer_tree_frame_sink_)
    LayerTreeFrameSinkCreated();

  if (needs_begin_frames_)
    host_->SetNeedsBeginFrames(true);
  if (!threads_.empty()) {
    host_->SetThreads(threads_);
  }
}

void SynchronousCompositorProxy::HostDisconnected() {
  // It is possible due to bugs that the Host is disconnected without pausing
  // begin frames. This causes hard-to-reproduce but catastrophic bug of
  // blocking the renderer main thread forever on a commit. See
  // crbug.com/1010478 for when this happened. This is to prevent a similar
  // bug in the future.
  SetBeginFrameSourcePaused(true);
}

}  // namespace blink

"""

```