Response:
Let's break down the thought process for analyzing this `CanvasResourceDispatcher.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific Chromium Blink source code file. This involves identifying its purpose, its interactions with other parts of the rendering pipeline (especially JavaScript, HTML, and CSS), and potential usage errors.

2. **Initial Code Scan and Keyword Identification:**  Start by quickly scanning the code for significant keywords and patterns. Look for:
    * **Class Name:** `CanvasResourceDispatcher` - This is the central entity and gives a hint about its role (dispatching canvas resources).
    * **Includes:**  These reveal dependencies and what kind of functionality the class relies on. Pay attention to:
        * `CanvasResource`:  Likely the core resource being managed.
        * `viz::*`:  Indicates interaction with the Viz compositor.
        * `mojom::blink::*`: Suggests communication via Mojo interfaces.
        * `OffscreenCanvasPlaceholder`:  Hints at the connection to OffscreenCanvas.
        * `base::task::SingleThreadTaskRunner`:  Implies thread management and asynchronous operations.
        * `TRACE_EVENT`:  Used for performance monitoring and debugging, can indicate important functions.
    * **Member Variables:** These hold the state and context of the dispatcher. Look for things like `frame_sink_id_`, `size_`, `resources_`, `pending_compositor_frames_`, `client_`, `sink_`, etc. These provide clues about what data the dispatcher manages.
    * **Methods:**  These are the actions the dispatcher can perform. Focus on names like `DispatchFrame`, `SubmitCompositorFrame`, `ReclaimResource`, `PostImageToPlaceholder`, `SetNeedsBeginFrame`, `Reshape`. These verbs describe the core operations.

3. **Infer High-Level Functionality:** Based on the keywords and initial scan, formulate a high-level understanding of the class's role. It seems to be responsible for:
    * Taking canvas resources (likely images or textures).
    * Communicating with the Viz compositor to display these resources.
    * Managing the lifecycle of these resources, including reclamation.
    * Interacting with OffscreenCanvas.
    * Handling synchronization and threading.

4. **Delve into Key Methods:** Focus on the most important methods to understand the workflow:
    * **`DispatchFrame` and `DispatchFrameSync`:** These clearly send canvas content to the compositor. Notice the creation of `viz::CompositorFrame` and `viz::TextureDrawQuad`. This indicates how the canvas is represented in the compositor's scene graph.
    * **`PrepareFrame`:**  This is the core logic for preparing the `CompositorFrame`. Pay attention to how it creates the `viz::TextureDrawQuad`, sets up the `viz::TransferableResource`, and manages resource IDs. The handling of `y_flipped` is also interesting.
    * **`PostImageToPlaceholder` and `PostImageToPlaceholderIfNotBlocked`:**  These methods deal with sending canvas resources to the `OffscreenCanvasPlaceholder`. The "not blocked" version introduces the concept of limiting the number of pending frames, which is crucial for performance and avoiding blocking the main thread.
    * **`ReclaimResources` and `ReclaimResourceInternal`:** These handle the cleanup of resources when they are no longer needed by the compositor. The `spare_lock` mechanism is a detail to note.
    * **`SetNeedsBeginFrame`:**  This relates to how the dispatcher requests new frames from the compositor, often tied to animation or rendering updates.
    * **`OnBeginFrame`:**  This is the response from the compositor, triggering the client to produce a new frame.

5. **Identify Relationships with Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The most direct link is through the `<canvas>` element and the `OffscreenCanvas` API. JavaScript code uses these APIs to draw graphics. This dispatcher is the mechanism that takes the results of those drawing operations and sends them to the rendering pipeline. Think about how JavaScript calls to `drawImage` or drawing primitives eventually lead to the creation of `CanvasResource` objects that this dispatcher handles.
    * **HTML:** The `<canvas>` element in the HTML structure is the starting point. The `id` of the canvas might be related to the `placeholder_canvas_id_`.
    * **CSS:**  CSS properties like `opacity` or transforms applied to the canvas element will eventually influence the `viz::SharedQuadState` created by this dispatcher. The `is_opaque` parameter in `DispatchFrame` is a direct connection.

6. **Consider Logical Inferences and Examples:**
    * **Input/Output:** Think about the inputs to key methods (e.g., a `CanvasResource`, damage rectangle) and the outputs (a `CompositorFrame` sent to Viz).
    * **Assumptions:** What assumptions does the code make? For example, the size of the canvas resource should match the dispatcher's size.

7. **Anticipate Common Usage Errors:** Based on the code's functionality, consider what mistakes a developer might make:
    * Trying to dispatch frames before the compositor is ready.
    * Not reclaiming resources properly, leading to memory leaks.
    * Mismatched canvas sizes.
    * Blocking the main thread by submitting too many frames.

8. **Structure the Output:** Organize the findings logically:
    * **Functionality Summary:**  Provide a concise overview.
    * **Relationship to Web Technologies:** Explain the connections with JavaScript, HTML, and CSS with concrete examples.
    * **Logical Inferences:** Present assumptions, inputs, and outputs.
    * **Common Usage Errors:**  List potential pitfalls.

9. **Review and Refine:** Read through the analysis, ensuring accuracy and clarity. Check if any important aspects were missed. For instance,  the role of `FrameSinkId` and the Mojo communication becomes clearer upon closer inspection. The handling of `suspend_animation_` is another detail worth highlighting.

By following this structured approach, you can effectively analyze and understand the functionality of complex source code files like `CanvasResourceDispatcher.cc`. The key is to move from a high-level overview to detailed examination of key components and their interactions.
This C++ source code file, `canvas_resource_dispatcher.cc`, located within the Chromium Blink rendering engine, plays a crucial role in managing and dispatching resources (specifically textures) associated with `<canvas>` and `OffscreenCanvas` elements to the compositor (Viz). It acts as a bridge between the rasterization of canvas content and its display on the screen.

Here's a breakdown of its functionality:

**Core Functionalities:**

1. **Resource Management:**
   - **Accepts Canvas Resources:** It receives `CanvasResource` objects, which encapsulate the rendered content of a canvas. These resources are typically backed by GPU textures.
   - **Tracks Resource Lifecycles:** It maintains a record of allocated canvas resources and their associated metadata (e.g., `viz::ResourceId`, sync tokens).
   - **Handles Resource Reclamation:** When the compositor is finished using a canvas resource, it sends back a "release" acknowledgment. This dispatcher is responsible for reclaiming those resources, potentially freeing up GPU memory. It uses a two-stage reclamation process (`spare_lock`) to ensure both the compositor and the placeholder canvas have released the resource.

2. **Communication with the Compositor (Viz):**
   - **Submits Compositor Frames:** The core function is to package canvas resources into `viz::CompositorFrame` objects and submit them to the Viz compositor. These frames contain drawing instructions (quads) that reference the canvas textures.
   - **Manages Frame Synchronization:** It interacts with the compositor's frame scheduling mechanism (via `BeginFrame` and `BeginFrameAck`) to synchronize canvas updates with the overall rendering pipeline.
   - **Handles Local Surface IDs:** It manages `LocalSurfaceId` to identify the drawing surface associated with the canvas in the compositor.
   - **Handles Shared Bitmaps:** It can allocate and delete shared memory regions for bitmaps, allowing for efficient transfer of data to the compositor.

3. **Interaction with OffscreenCanvas:**
   - **Placeholder Management:** It plays a key role in the implementation of `OffscreenCanvas`. For each `OffscreenCanvas`, a `CanvasResourceDispatcher` is created.
   - **Posts Images to Placeholder:**  It sends the `CanvasResource` and its `viz::ResourceId` to the associated `OffscreenCanvasPlaceholder` on the main thread. This allows the `OffscreenCanvas` to track and potentially reuse the resource.
   - **Handles Backpressure:** It has a mechanism (`kMaxUnreclaimedPlaceholderFrames`) to limit the number of unreclaimed frames sent to the placeholder, preventing the main thread from being overwhelmed if the placeholder isn't processing resources quickly enough.

4. **Thread Management:**
   - **Runs on a Dedicated Task Runner:**  The dispatcher often operates on a separate thread (the compositor thread) to avoid blocking the main rendering thread.
   - **Cross-Thread Communication:** It uses `PostCrossThreadTask` to communicate with the main thread, especially for updating the `OffscreenCanvasPlaceholder`.

**Relationships with JavaScript, HTML, and CSS:**

* **JavaScript:**
    - **`<canvas>` API:** When JavaScript code draws on a `<canvas>` element using the 2D or WebGL API, the resulting rendering commands eventually lead to the creation of a `CanvasResource`. This dispatcher is then used to send that resource to the compositor for display.
    - **`OffscreenCanvas` API:** When using `OffscreenCanvas`, the rendering happens off the main thread. This dispatcher is directly associated with the `OffscreenCanvas` and manages the flow of its rendered output to the compositor.
    - **Example:**
        ```javascript
        // Using <canvas>
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = 'red';
        ctx.fillRect(10, 10, 50, 50); // This drawing eventually results in a CanvasResource being dispatched.

        // Using OffscreenCanvas
        const offscreenCanvas = new OffscreenCanvas(200, 100);
        const ctxOffscreen = offscreenCanvas.getContext('2d');
        ctxOffscreen.fillStyle = 'blue';
        ctxOffscreen.fillRect(0, 0, 200, 100); // The rendering here is managed by a CanvasResourceDispatcher.
        ```

* **HTML:**
    - **`<canvas>` element:** The presence of a `<canvas>` element in the HTML document triggers the creation of associated rendering infrastructure, including (potentially) a `CanvasResourceDispatcher`.
    - **`OffscreenCanvas` element (in workers):** While `OffscreenCanvas` itself isn't a direct HTML element in the main document, its use is initiated from JavaScript running in the context of a web page.

* **CSS:**
    - **Canvas Styling:** CSS properties applied to the `<canvas>` element (e.g., `width`, `height`, `opacity`, `transform`) can influence how the compositor renders the canvas content. While this dispatcher doesn't directly interpret CSS, the final composition performed by Viz will be affected by these styles.
    - **Example:** If you set `opacity: 0.5` on a canvas, the compositor will blend it accordingly when rendering the frame generated by this dispatcher.

**Logical Inference (Hypothetical Input and Output):**

**Hypothetical Input:**

* **`canvas_resource`:** A `scoped_refptr<CanvasResource>` representing a rendered image of a 100x100 pixel canvas with a red square drawn on it.
* **`commit_start_time`:**  The timestamp when the rendering process began.
* **`damage_rect`:** A `SkIRect` specifying the area of the canvas that has changed (e.g., `{10, 10, 50, 50}` for the red square).
* **`is_opaque`:** `true` if the canvas content is fully opaque, `false` otherwise.

**Hypothetical Output:**

* A `viz::CompositorFrame` object will be created. This frame will contain:
    * **Metadata:** Information about the frame, including the device scale factor, begin frame acknowledgment, and frame token.
    * **Render Pass:** A `viz::CompositorRenderPass` describing how to render the content.
    * **Draw Quad:** A `viz::TextureDrawQuad` within the render pass. This quad will:
        * Reference the `viz::ResourceId` associated with the input `canvas_resource`.
        * Specify the dimensions and position of the canvas content.
        * Potentially include information about opacity and blending.
        * Indicate whether the texture is y-flipped (depending on the canvas origin).
    * **Transferable Resource:** The `canvas_resource` will be prepared as a `viz::TransferableResource` with its `viz::ResourceId`. This resource will be added to the frame's resource list.

**Common Usage Errors (from a developer's perspective interacting with the Canvas/OffscreenCanvas APIs):**

1. **Not Reclaiming Resources (Indirectly):** While developers don't directly interact with this dispatcher, they can indirectly cause issues by creating many `OffscreenCanvas` objects or frequently redrawing on canvases without proper cleanup. This can lead to a buildup of unreclaimed resources, potentially causing memory pressure and performance problems.

2. **Mismatched Canvas and Dispatcher Sizes:** If the size of the `CanvasResource` being dispatched doesn't match the size the dispatcher is configured for (`size_`), the `VerifyImageSize` check will fail, and the frame might be dropped. This could happen if there's a bug in the code managing canvas resizing.

3. **Blocking the Main Thread with Synchronous Operations on OffscreenCanvas (Anti-pattern):** While `OffscreenCanvas` is designed for off-thread rendering, performing excessively long synchronous operations within the `OffscreenCanvas` context can still lead to jank on the main thread, even though this dispatcher itself runs on a separate thread.

4. **Incorrectly Managing `needsBeginFrame` for Animation:** If a developer manually calls `SetNeedsBeginFrame` incorrectly, they might either cause unnecessary frame submissions (wasting resources) or fail to trigger animations smoothly. This is usually handled by the browser, but understanding the underlying mechanism is helpful for advanced scenarios.

5. **Unexpected Behavior with `is_opaque`:**  Incorrectly setting or assuming the `is_opaque` flag can lead to unexpected blending behavior. For instance, if a canvas is not fully opaque but is marked as such, the compositor might skip necessary blending operations.

In summary, `canvas_resource_dispatcher.cc` is a critical component in Blink's rendering pipeline, responsible for efficiently transferring rendered canvas content to the compositor for display. It plays a key role in enabling both the traditional `<canvas>` element and the more advanced `OffscreenCanvas` API.

Prompt: 
```
这是目录为blink/renderer/platform/graphics/canvas_resource_dispatcher.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/canvas_resource_dispatcher.h"

#include <utility>

#include "base/debug/stack_trace.h"
#include "base/not_fatal_until.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/trace_event.h"
#include "components/viz/common/features.h"
#include "components/viz/common/quads/compositor_frame.h"
#include "components/viz/common/quads/texture_draw_quad.h"
#include "components/viz/common/resources/release_callback.h"
#include "services/viz/public/mojom/compositing/frame_timing_details.mojom-blink.h"
#include "services/viz/public/mojom/hit_test/hit_test_region_list.mojom-blink.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/frame_sinks/embedded_frame_sink.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_graphics_context_3d_provider.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/offscreen_canvas_placeholder.h"
#include "third_party/blink/renderer/platform/graphics/resource_id_traits.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "ui/gfx/mojom/presentation_feedback.mojom-blink.h"

namespace blink {

struct CanvasResourceDispatcher::FrameResource {
  FrameResource() = default;
  ~FrameResource() {
    if (release_callback) {
      std::move(release_callback)
          .Run(std::move(canvas_resource), sync_token, is_lost);
    }
  }

  // This is to ensure the resource only gets reclaimed for real at the second
  // reclaim attempt.  This is because the resource needs to be returned by
  // both the compositor and the placeholder canvas before it is safe to
  // reclaim it.
  bool spare_lock = true;

  // The 'canvas_resource' field is not set at construction time: It gets set
  // when the placeholder canvas returns it. This makes it simpler to write
  // DCHECKs that detect potential concurrency issues by checking
  // RefCounted::HasOneRef() in critical places. This also allows
  // OffscreenCanvasPlaceholder to detect when to return a resource by using
  // CanvasResource::SetLastUnrefCallback.
  scoped_refptr<CanvasResource> canvas_resource;
  CanvasResource::ReleaseCallback release_callback;
  gpu::SyncToken sync_token;
  bool is_lost = false;
};

CanvasResourceDispatcher::CanvasResourceDispatcher(
    CanvasResourceDispatcherClient* client,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    scoped_refptr<base::SingleThreadTaskRunner>
        agent_group_scheduler_compositor_task_runner,
    uint32_t client_id,
    uint32_t sink_id,
    int canvas_id,
    const gfx::Size& size)
    : frame_sink_id_(viz::FrameSinkId(client_id, sink_id)),
      size_(size),
      change_size_for_next_commit_(false),
      placeholder_canvas_id_(canvas_id),
      num_unreclaimed_frames_posted_(0),
      client_(client),
      task_runner_(std::move(task_runner)),
      agent_group_scheduler_compositor_task_runner_(
          std::move(agent_group_scheduler_compositor_task_runner)) {
  // Frameless canvas pass an invalid |frame_sink_id_|; don't create mojo
  // channel for this special case.
  if (!frame_sink_id_.is_valid())
    return;

  DCHECK(!sink_.is_bound());
  mojo::Remote<mojom::blink::EmbeddedFrameSinkProvider> provider;
  Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
      provider.BindNewPipeAndPassReceiver());

  DCHECK(provider);
  provider->CreateCompositorFrameSink(frame_sink_id_,
                                      receiver_.BindNewPipeAndPassRemote(),
                                      sink_.BindNewPipeAndPassReceiver());
  provider->ConnectToEmbedder(frame_sink_id_,
                              surface_embedder_.BindNewPipeAndPassReceiver());
}

CanvasResourceDispatcher::~CanvasResourceDispatcher() = default;

namespace {

void UpdatePlaceholderImage(
    int placeholder_canvas_id,
    scoped_refptr<blink::CanvasResource>&& canvas_resource,
    viz::ResourceId resource_id) {
  DCHECK(IsMainThread());
  OffscreenCanvasPlaceholder* placeholder_canvas =
      OffscreenCanvasPlaceholder::GetPlaceholderCanvasById(
          placeholder_canvas_id);
  if (placeholder_canvas) {
    placeholder_canvas->SetOffscreenCanvasResource(std::move(canvas_resource),
                                                   resource_id);
  }
}

void UpdatePlaceholderDispatcher(
    base::WeakPtr<CanvasResourceDispatcher> dispatcher,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    int placeholder_canvas_id) {
  OffscreenCanvasPlaceholder* placeholder_canvas =
      OffscreenCanvasPlaceholder::GetPlaceholderCanvasById(
          placeholder_canvas_id);
  // Note that the placeholder canvas may be destroyed when this post task get
  // to executed.
  if (placeholder_canvas)
    placeholder_canvas->SetOffscreenCanvasDispatcher(dispatcher, task_runner);
}

}  // namespace

void CanvasResourceDispatcher::PostImageToPlaceholderIfNotBlocked(
    scoped_refptr<CanvasResource>&& canvas_resource,
    viz::ResourceId resource_id) {
  if (placeholder_canvas_id_ == kInvalidPlaceholderCanvasId) {
    ReclaimResourceInternal(resource_id, std::move(canvas_resource));
    return;
  }
  // Determines whether the main thread may be blocked. If unblocked, post
  // |canvas_resource|. Otherwise, save it but do not post it.
  if (num_unreclaimed_frames_posted_ < kMaxUnreclaimedPlaceholderFrames) {
    PostImageToPlaceholder(std::move(canvas_resource), resource_id);
    num_unreclaimed_frames_posted_++;
  } else {
    DCHECK(num_unreclaimed_frames_posted_ == kMaxUnreclaimedPlaceholderFrames);
    if (latest_unposted_image_) {
      // The previous unposted resource becomes obsolete now.
      ReclaimResourceInternal(latest_unposted_resource_id_,
                              std::move(latest_unposted_image_));
    }

    latest_unposted_image_ = std::move(canvas_resource);
    latest_unposted_resource_id_ = resource_id;
  }
}

void CanvasResourceDispatcher::PostImageToPlaceholder(
    scoped_refptr<CanvasResource>&& canvas_resource,
    viz::ResourceId resource_id) {
  // After this point, |canvas_resource| can only be used on the main thread,
  // until it is returned.
  canvas_resource->Transfer();

  // `agent_group_scheduler_compositor_task_runner_` may be null if this
  // was created from a SharedWorker.
  if (!agent_group_scheduler_compositor_task_runner_)
    return;
  PostCrossThreadTask(
      *agent_group_scheduler_compositor_task_runner_, FROM_HERE,
      CrossThreadBindOnce(UpdatePlaceholderImage, placeholder_canvas_id_,
                          std::move(canvas_resource), resource_id));
}

void CanvasResourceDispatcher::DispatchFrameSync(
    scoped_refptr<CanvasResource>&& canvas_resource,
    base::TimeTicks commit_start_time,
    const SkIRect& damage_rect,
    bool is_opaque) {
  TRACE_EVENT0("blink", "CanvasResourceDispatcher::DispatchFrameSync");
  viz::CompositorFrame frame;
  if (!PrepareFrame(std::move(canvas_resource), commit_start_time, damage_rect,
                    is_opaque, &frame)) {
    return;
  }

  pending_compositor_frames_++;
  WTF::Vector<viz::ReturnedResource> resources;
  sink_->SubmitCompositorFrameSync(
      parent_local_surface_id_allocator_.GetCurrentLocalSurfaceId(),
      std::move(frame), std::nullopt, 0, &resources);
  DidReceiveCompositorFrameAck(std::move(resources));
}

void CanvasResourceDispatcher::DispatchFrame(
    scoped_refptr<CanvasResource>&& canvas_resource,
    base::TimeTicks commit_start_time,
    const SkIRect& damage_rect,
    bool is_opaque) {
  TRACE_EVENT0("blink", "CanvasResourceDispatcher::DispatchFrame");
  viz::CompositorFrame frame;
  if (!PrepareFrame(std::move(canvas_resource), commit_start_time, damage_rect,
                    is_opaque, &frame)) {
    return;
  }

  pending_compositor_frames_++;
  sink_->SubmitCompositorFrame(
      parent_local_surface_id_allocator_.GetCurrentLocalSurfaceId(),
      std::move(frame), std::nullopt, 0);
}

bool CanvasResourceDispatcher::PrepareFrame(
    scoped_refptr<CanvasResource>&& canvas_resource,
    base::TimeTicks commit_start_time,
    const SkIRect& damage_rect,
    bool is_opaque,
    viz::CompositorFrame* frame) {
  TRACE_EVENT0("blink", "CanvasResourceDispatcher::PrepareFrame");
  if (!canvas_resource || !VerifyImageSize(canvas_resource->Size())) {
    return false;
  }

  auto next_resource_id = id_generator_.GenerateNextId();

  // For frameless canvas, we don't get a valid frame_sink_id and should drop.
  if (!frame_sink_id_.is_valid()) {
    PostImageToPlaceholderIfNotBlocked(std::move(canvas_resource),
                                       next_resource_id);
    return false;
  }

  // TODO(crbug.com/652931): update the device_scale_factor
  frame->metadata.device_scale_factor = 1.0f;
  if (!current_begin_frame_ack_.frame_id.IsSequenceValid()) {
    // TODO(eseckler): This shouldn't be necessary when OffscreenCanvas no
    // longer submits CompositorFrames without prior BeginFrame.
    current_begin_frame_ack_ = viz::BeginFrameAck::CreateManualAckWithDamage();
  } else {
    current_begin_frame_ack_.has_damage = true;
  }
  frame->metadata.begin_frame_ack = current_begin_frame_ack_;

  frame->metadata.frame_token = ++next_frame_token_;

  // Ask viz not to throttle us if we've not voluntarily suspended animation.
  // Typically, we'll suspend if we're hidden, unless we're hidden-but-painting.
  // In that case, we can still submit frames that will contribute, possibly
  // indirectly, to picture-in-picture content even if those frames are not
  // consumed by a viz frame sink directly.  In those cases, it might choose to
  // throttle us, incorrectly.
  frame->metadata.may_throttle_if_undrawn_frames = suspend_animation_;

  const gfx::Rect bounds(size_.width(), size_.height());
  constexpr viz::CompositorRenderPassId kRenderPassId{1};
  auto pass =
      viz::CompositorRenderPass::Create(/*shared_quad_state_list_size=*/1u,
                                        /*quad_list_size=*/1u);
  pass->SetNew(kRenderPassId, bounds,
               gfx::Rect(damage_rect.x(), damage_rect.y(), damage_rect.width(),
                         damage_rect.height()),
               gfx::Transform());

  viz::SharedQuadState* sqs = pass->CreateAndAppendSharedQuadState();
  sqs->SetAll(gfx::Transform(), bounds, bounds, gfx::MaskFilterInfo(),
              /*clip=*/std::nullopt, is_opaque, /*opacity_f=*/1.f,
              SkBlendMode::kSrcOver, /*sorting_context=*/0, /*layer_id=*/0u,
              /*fast_rounded_corner=*/false);

  viz::TransferableResource resource;
  auto frame_resource = std::make_unique<FrameResource>();

  bool nearest_neighbor =
      canvas_resource->FilterQuality() == cc::PaintFlags::FilterQuality::kNone;

  canvas_resource->PrepareTransferableResource(
      &resource, &frame_resource->release_callback,
      /*needs_verified_synctoken=*/true);
  const viz::ResourceId resource_id = next_resource_id;
  resource.id = resource_id;

  resources_.insert(resource_id, std::move(frame_resource));

  // TODO(crbug.com/869913): add unit testing for this.
  const gfx::Size canvas_resource_size = canvas_resource->Size();

  // Software canvases always have top left origin, accelerated canvases can
  // have bottom left origin if they come from webgl.
  // TODO(crbug.com/378688985) Remove gpu composition condition.
  const bool yflipped = SharedGpuContext::IsGpuCompositingEnabled() &&
                        !canvas_resource->IsOriginTopLeft();

  PostImageToPlaceholderIfNotBlocked(std::move(canvas_resource), resource_id);

  frame->resource_list.push_back(std::move(resource));

  viz::TextureDrawQuad* quad =
      pass->CreateAndAppendDrawQuad<viz::TextureDrawQuad>();

  const bool needs_blending = !is_opaque;
  // TODO(crbug.com/645993): this should be inherited from WebGL context's
  // creation settings.
  constexpr bool kPremultipliedAlpha = true;
  constexpr gfx::PointF uv_top_left(0.f, 0.f);
  constexpr gfx::PointF uv_bottom_right(1.f, 1.f);
  quad->SetAll(sqs, bounds, bounds, needs_blending, resource_id,
               canvas_resource_size, kPremultipliedAlpha, uv_top_left,
               uv_bottom_right, SkColors::kTransparent, nearest_neighbor,
               /*secure_output=*/false, gfx::ProtectedVideoType::kClear);
  quad->y_flipped = yflipped;
  frame->render_pass_list.push_back(std::move(pass));

  if (change_size_for_next_commit_ ||
      !parent_local_surface_id_allocator_.HasValidLocalSurfaceId()) {
    parent_local_surface_id_allocator_.GenerateId();
    surface_embedder_->SetLocalSurfaceId(
        parent_local_surface_id_allocator_.GetCurrentLocalSurfaceId());
    change_size_for_next_commit_ = false;
  }

  return true;
}

void CanvasResourceDispatcher::DidReceiveCompositorFrameAck(
    WTF::Vector<viz::ReturnedResource> resources) {
  ReclaimResources(std::move(resources));
  pending_compositor_frames_--;
  DCHECK_GE(pending_compositor_frames_, 0u);
}

void CanvasResourceDispatcher::SetNeedsBeginFrame(bool needs_begin_frame) {
  if (needs_begin_frame_ == needs_begin_frame) {
    // If the offscreencanvas is in the same tread as the canvas, and we are
    // trying for a second time to request the being frame, and we are in a
    // capture_stream scenario, we will call a BeginFrame right away. So
    // Offscreen Canvas can behave in a more synchronous way when it's on the
    // main thread.
    if (needs_begin_frame_ && IsMainThread()) {
      OffscreenCanvasPlaceholder* placeholder_canvas =
          OffscreenCanvasPlaceholder::GetPlaceholderCanvasById(
              placeholder_canvas_id_);
      if (placeholder_canvas &&
          placeholder_canvas->IsOffscreenCanvasRegistered() &&
          placeholder_canvas->HasCanvasCapture() && Client()) {
        Client()->BeginFrame();
      }
    }
    return;
  }
  needs_begin_frame_ = needs_begin_frame;
  if (!suspend_animation_)
    SetNeedsBeginFrameInternal();
}

void CanvasResourceDispatcher::SetSuspendAnimation(bool suspend_animation) {
  if (suspend_animation_ == suspend_animation)
    return;
  suspend_animation_ = suspend_animation;
  if (needs_begin_frame_)
    SetNeedsBeginFrameInternal();
}

void CanvasResourceDispatcher::SetNeedsBeginFrameInternal() {
  if (!sink_)
    return;

  bool needs_begin_frame = needs_begin_frame_ && !suspend_animation_;
  sink_->SetNeedsBeginFrame(needs_begin_frame);
}

bool CanvasResourceDispatcher::HasTooManyPendingFrames() const {
  return pending_compositor_frames_ >= kMaxPendingCompositorFrames;
}

void CanvasResourceDispatcher::OnBeginFrame(
    const viz::BeginFrameArgs& begin_frame_args,
    const WTF::HashMap<uint32_t, viz::FrameTimingDetails>&,
    bool frame_ack,
    WTF::Vector<viz::ReturnedResource> resources) {
  if (features::IsOnBeginFrameAcksEnabled()) {
    if (frame_ack) {
      DidReceiveCompositorFrameAck(std::move(resources));
    } else if (!resources.empty()) {
      ReclaimResources(std::move(resources));
    }
  }
  current_begin_frame_ack_ = viz::BeginFrameAck(begin_frame_args, false);
  if (HasTooManyPendingFrames() ||
      (begin_frame_args.type == viz::BeginFrameArgs::MISSED &&
       base::TimeTicks::Now() > begin_frame_args.deadline)) {
    sink_->DidNotProduceFrame(current_begin_frame_ack_);
    return;
  }

  // TODO(fserb): should EnqueueMicrotask BeginFrame().
  // We usually never get to BeginFrame if we are on RAF mode. But it could
  // still happen that begin frame gets requested and we don't have a frame
  // anymore, so we shouldn't let the compositor wait.
  bool submitted_frame = Client() && Client()->BeginFrame();
  if (!submitted_frame) {
    sink_->DidNotProduceFrame(current_begin_frame_ack_);
  }

  // TODO(fserb): Update this with the correct value if we are on RAF submit.
  current_begin_frame_ack_.frame_id.sequence_number =
      viz::BeginFrameArgs::kInvalidFrameNumber;
}

void CanvasResourceDispatcher::ReclaimResources(
    WTF::Vector<viz::ReturnedResource> resources) {
  for (const auto& resource : resources) {
    auto it = resources_.find(resource.id);

    CHECK(it != resources_.end(), base::NotFatalUntil::M130);
    if (it == resources_.end())
      continue;

    it->value->sync_token = resource.sync_token;
    it->value->is_lost = resource.lost;
    ReclaimResourceInternal(it);
  }
}

void CanvasResourceDispatcher::ReclaimResource(
    viz::ResourceId resource_id,
    scoped_refptr<CanvasResource>&& canvas_resource) {
  ReclaimResourceInternal(resource_id, std::move(canvas_resource));

  num_unreclaimed_frames_posted_--;

  // The main thread has become unblocked recently and we have an image that
  // have not been posted yet.
  if (latest_unposted_image_) {
    DCHECK(num_unreclaimed_frames_posted_ ==
           kMaxUnreclaimedPlaceholderFrames - 1);
    PostImageToPlaceholderIfNotBlocked(std::move(latest_unposted_image_),
                                       latest_unposted_resource_id_);
    // To make it safe to use/check latest_unposted_image_ after using
    // std::move on it, we need to force a reset because the move above is
    // elide-able.
    latest_unposted_image_.reset();
    latest_unposted_resource_id_ = viz::kInvalidResourceId;
  }
}

bool CanvasResourceDispatcher::VerifyImageSize(const gfx::Size& image_size) {
  return image_size == size_;
}

void CanvasResourceDispatcher::Reshape(const gfx::Size& size) {
  if (size_ != size) {
    size_ = size;
    change_size_for_next_commit_ = true;
  }
}

void CanvasResourceDispatcher::DidAllocateSharedBitmap(
    base::ReadOnlySharedMemoryRegion region,
    const viz::SharedBitmapId& id) {
  if (sink_)
    sink_->DidAllocateSharedBitmap(std::move(region), id);
}

void CanvasResourceDispatcher::DidDeleteSharedBitmap(
    const viz::SharedBitmapId& id) {
  if (sink_)
    sink_->DidDeleteSharedBitmap(id);
}

void CanvasResourceDispatcher::SetFilterQuality(
    cc::PaintFlags::FilterQuality filter_quality) {
  if (Client())
    Client()->SetFilterQualityInResource(filter_quality);
}

void CanvasResourceDispatcher::SetPlaceholderCanvasDispatcher(
    int placeholder_canvas_id) {
  // `agent_group_scheduler_compositor_task_runner_` may be null if this
  // was created from a SharedWorker.
  if (!agent_group_scheduler_compositor_task_runner_)
    return;

  // If the offscreencanvas is in the same thread as the canvas, we will update
  // the canvas resource dispatcher directly. So Offscreen Canvas can behave in
  // a more synchronous way when it's on the main thread.
  if (IsMainThread()) {
    UpdatePlaceholderDispatcher(GetWeakPtr(), task_runner_,
                                placeholder_canvas_id);
  } else {
    PostCrossThreadTask(
        *agent_group_scheduler_compositor_task_runner_, FROM_HERE,
        CrossThreadBindOnce(UpdatePlaceholderDispatcher, GetWeakPtr(),
                            task_runner_, placeholder_canvas_id));
  }
}

void CanvasResourceDispatcher::ReclaimResourceInternal(
    viz::ResourceId resource_id,
    scoped_refptr<CanvasResource>&& canvas_resource) {
  auto it = resources_.find(resource_id);
  if (it != resources_.end()) {
    it->value->canvas_resource = std::move(canvas_resource);
    ReclaimResourceInternal(it);
  }
}

void CanvasResourceDispatcher::ReclaimResourceInternal(
    const ResourceMap::iterator& it) {
  if (it->value->spare_lock) {
    it->value->spare_lock = false;
    return;
  }
  DCHECK(it->value->canvas_resource);
  resources_.erase(it);
}

}  // namespace blink

"""

```