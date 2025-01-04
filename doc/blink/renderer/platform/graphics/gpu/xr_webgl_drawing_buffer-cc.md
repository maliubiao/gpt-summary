Response:
Let's break down the thought process for analyzing the `xr_webgl_drawing_buffer.cc` file.

1. **Understand the Goal:** The request asks for the file's functionality, its relationship to web technologies (JavaScript, HTML, CSS), logical reasoning with input/output, and common usage errors.

2. **Initial Skim and Identify Key Components:**  Read through the code quickly to get a general sense of its purpose. Look for class names, key functions, and included headers. Immediately noticeable are:
    * `XRWebGLDrawingBuffer` class
    * Inclusion of `DrawingBuffer.h`
    * Mentions of WebGL (in the file name)
    * Interaction with GPU concepts like textures, framebuffers, shared images.

3. **Focus on the Core Class: `XRWebGLDrawingBuffer`:**  This is the central piece. Analyze its methods:
    * `Create()`:  Likely responsible for instantiation. Notice the parameters related to antialiasing, depth/stencil buffers.
    * Constructor and Destructor:  Handle setup and teardown.
    * `Initialize()`:  Sets up GL resources and checks capabilities.
    * `Resize()`: Handles changes in the drawing buffer size.
    * `UseSharedBuffer()` and `DoneWithSharedBuffer()`:  These strongly suggest interaction with shared memory or inter-process communication for rendering.
    * `SwapColorBuffers()`:  A common pattern in double-buffered rendering.
    * `TransferToStaticBitmapImage()`:  Indicates a way to capture the rendered output.
    * `CreateColorBuffer()` and `CreateOrRecycleColorBuffer()`:  Manage the allocation and reuse of color buffers.
    * Helper methods like `AdjustSize()`, `WantExplicitResolve()`, `BindAndResolveDestinationFramebuffer()`, `ClearBoundFramebuffer()`.

4. **Identify Relationships with Web Technologies:**
    * **WebGL:** The file name itself (`xr_webgl_drawing_buffer.cc`) and the frequent use of `gpu::gles2::GLES2Interface` strongly link this code to WebGL.
    * **JavaScript:** WebGL APIs are exposed to JavaScript. This file is part of the underlying implementation that makes those APIs work. Think about how JavaScript calls to `getContext('webgl')` and drawing commands eventually translate to actions within this C++ code.
    * **HTML `<canvas>` Element:** WebGL rendering happens on a `<canvas>` element. This code is responsible for managing the GPU resources associated with that canvas.
    * **CSS (Indirectly):** CSS affects the size and layout of the `<canvas>` element, which in turn influences the size of the drawing buffer handled by this code.

5. **Logical Reasoning and Input/Output:**
    * **Assumption:**  A WebGL application wants to render to a canvas.
    * **Input:** The `Create()` function takes parameters like `size`, `want_alpha_channel`, `want_antialiasing`. These represent the desired properties of the rendering target.
    * **Processing:** The `Initialize()` and `Resize()` methods use these inputs to configure OpenGL resources (framebuffers, textures, renderbuffers).
    * **Output:**  The `TransferToStaticBitmapImage()` function produces a `StaticBitmapImage`, which can be used to display the rendered content (e.g., by painting it onto another canvas or as an image source). The `SwapColorBuffers()` method makes the rendered content visible.
    * **Shared Buffer Scenario:**  The `UseSharedBuffer()` function takes a `gpu::ClientSharedImage` and `gpu::SyncToken` as input. This suggests that the rendering might be synchronized with other GPU processes or contexts. The output is the rendered content within that shared buffer.

6. **Common Usage Errors:** Think from the perspective of a web developer using WebGL:
    * **Resizing Issues:** Incorrectly handling canvas resizing or attempting to resize to extremely large dimensions could lead to errors (handled by `AdjustSize()`, but the developer might misuse it or misunderstand its limitations).
    * **Context Loss:**  WebGL contexts can be lost. This code tries to handle it, but a developer might not properly check for context loss before making WebGL calls, leading to crashes or unexpected behavior.
    * **Asynchronous Operations:** Shared buffers and sync tokens imply asynchronicity. Developers need to ensure proper synchronization, or they might see incomplete or corrupted rendering.
    * **Resource Management (Less Direct):** Although this code handles some resource management, developers who create many WebGL contexts or drawing buffers without proper cleanup can still exhaust GPU resources.

7. **Structure the Answer:** Organize the information logically with clear headings and examples. Start with a high-level overview of the file's purpose and then delve into specific functionalities. Use bullet points for clarity and provide concrete examples for each section.

8. **Refine and Review:** Read through the generated answer to ensure accuracy, clarity, and completeness. Check if the examples are relevant and easy to understand. Make sure the logical reasoning is sound and the assumptions are stated. Ensure that the explanation of the relationships to web technologies is clear. For example, initially I might have just said "related to WebGL."  Refining it means explaining *how* it's related (underlying implementation, manages resources, etc.).

This iterative process of skimming, analyzing, connecting to web technologies, reasoning about input/output, considering errors, structuring, and refining helps to produce a comprehensive and accurate answer to the request.
这个文件 `xr_webgl_drawing_buffer.cc` 是 Chromium Blink 渲染引擎中用于在 WebXR (Web Extended Reality) 环境下支持 WebGL 渲染到一个特定的绘制缓冲区的实现。它专注于处理与 XR 设备相关的渲染输出，并与底层的 GPU 交互。

以下是它的主要功能以及与 JavaScript, HTML, CSS 的关系、逻辑推理和常见错误：

**主要功能:**

1. **管理渲染目标:**  该文件中的 `XRWebGLDrawingBuffer` 类负责管理 WebGL 内容渲染的目标，特别是在 XR 环境中。这包括创建、调整和管理用于渲染的 GPU 资源，如纹理和帧缓冲区。

2. **支持多采样抗锯齿 (MSAA):**  代码中包含了处理多采样抗锯齿的逻辑，可以根据设备和浏览器的支持情况选择不同的 MSAA 实现方式 (`kMSAAExplicitResolve`, `kMSAAImplicitResolve`)，以提高渲染质量。

3. **共享缓冲区的处理:**  该文件涉及处理共享缓冲区 (`SharedImage`)，这是一种在不同进程或线程之间高效共享 GPU 纹理的方式。在 XR 场景中，渲染内容可能需要在 compositor 进程中进行合成显示，共享缓冲区是关键。

4. **帧缓冲区的管理:**  代码中直接操作 OpenGL 的帧缓冲区 (`framebuffer_`)，用于将渲染结果输出到纹理中。它还处理了显式解析多采样缓冲区的情况，可能需要额外的帧缓冲区 (`resolved_framebuffer_`)。

5. **与 `DrawingBuffer` 的协作:** `XRWebGLDrawingBuffer` 依赖于 `DrawingBuffer` 类，后者是 Blink 中更通用的 WebGL 绘制缓冲区抽象。`XRWebGLDrawingBuffer` 可以被视为 `DrawingBuffer` 在 XR 场景下的一个专门版本。

6. **处理大小调整:**  当渲染目标的大小发生变化时（例如，用户调整了 XR 显示的视口），`Resize()` 方法负责更新底层的 GPU 资源。

7. **与 compositor 的同步:**  通过 `gpu::SyncToken` 机制，该文件能够与 compositor 进行同步，确保渲染结果在正确的时间点被 compositor 使用。

8. **转换为静态位图:**  `TransferToStaticBitmapImage()` 方法可以将当前渲染缓冲区的内容转换为 `StaticBitmapImage` 对象，这可以用于进一步的处理或显示。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**  WebGL API 是通过 JavaScript 暴露给开发者的。当 WebXR 应用使用 WebGL 进行渲染时，JavaScript 代码会调用 WebGL 的绘图命令。Blink 引擎会将这些命令转化为底层的 GPU 操作，其中 `XRWebGLDrawingBuffer` 就参与了管理渲染目标的过程。
    * **示例:**  一个 WebXR 应用可能使用 JavaScript 的 `requestAnimationFrame` 来驱动渲染循环，并在 WebGL 上绘制场景。`XRWebGLDrawingBuffer` 负责确保这些绘制操作输出到正确的 XR 显示缓冲区。

* **HTML `<canvas>` 元素:**  WebGL 内容通常渲染到一个 HTML `<canvas>` 元素上。虽然这个文件本身不直接操作 DOM，但它所管理的渲染缓冲区是与 `<canvas>` 关联的 WebGL 上下文的一部分。
    * **示例:**  WebXR 会创建一个 `XRWebGLLayer`，它关联到一个 `<canvas>` 元素和一个 WebGL 上下文。`XRWebGLDrawingBuffer` 负责管理该 WebGL 上下文的渲染输出。

* **CSS (间接关系):**  CSS 可以影响 `<canvas>` 元素的大小和布局。当 `<canvas>` 的大小改变时，可能会触发 `XRWebGLDrawingBuffer` 中的 `Resize()` 方法，以调整渲染缓冲区的大小。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. `Create()` 方法被调用，传入一个 `DrawingBuffer` 实例，目标渲染尺寸 `size` 为 800x600，要求开启抗锯齿 (`want_antialiasing` 为 true)。
2. `Resize()` 方法被调用，传入新的尺寸 1024x768。
3. `SwapColorBuffers()` 方法被调用，用于切换前后缓冲区。
4. `TransferToStaticBitmapImage()` 方法被调用，请求将当前渲染结果转换为位图。

**逻辑输出:**

1. `Create()` 方法会创建一个 `XRWebGLDrawingBuffer` 实例，并初始化相关的 OpenGL 资源，例如帧缓冲区和纹理。由于 `want_antialiasing` 为 true，它会尝试启用 MSAA。
2. `Resize()` 方法会释放旧的渲染缓冲区资源，并根据新的尺寸创建新的缓冲区。如果 MSAA 已启用，新的缓冲区也会配置为多采样。
3. `SwapColorBuffers()` 方法会将当前用于渲染的后缓冲区切换为前缓冲区，并将之前的前缓冲区（如果存在）回收。
4. `TransferToStaticBitmapImage()` 方法会从当前的前缓冲区读取像素数据，并创建一个 `AcceleratedStaticBitmapImage` 实例，其中包含了渲染结果的 GPU 纹理和同步令牌。

**用户或编程常见的使用错误:**

1. **在 WebGL 上下文丢失后尝试操作 `XRWebGLDrawingBuffer`:**  WebGL 上下文可能会因为各种原因丢失（例如，GPU 驱动崩溃、用户切换标签页等）。如果在上下文丢失后继续调用 `XRWebGLDrawingBuffer` 的方法，可能会导致程序崩溃或产生未定义的行为。
    * **示例:**  在 JavaScript 中没有正确监听 `webglcontextlost` 事件，并在上下文恢复前继续进行渲染操作。

2. **不匹配的缓冲区大小:**  在与共享缓冲区交互时，如果 `XRWebGLDrawingBuffer` 期望的缓冲区大小与实际共享的缓冲区大小不一致，可能会导致渲染错误或崩溃。
    * **示例:**  在多进程渲染架构中，负责渲染的进程和 compositor 进程对渲染目标的大小理解不一致。

3. **忘记处理同步令牌:**  在使用共享缓冲区时，必须正确处理 `gpu::SyncToken`，以确保 GPU 操作的顺序和数据的一致性。忘记等待同步令牌可能导致渲染结果不完整或出现撕裂。
    * **示例:**  在调用 `TransferToStaticBitmapImage()` 后，没有等待 `produce_sync_token` 完成就尝试使用返回的位图，可能导致数据不一致。

4. **资源泄漏:**  如果在 `XRWebGLDrawingBuffer` 不再需要时没有正确地释放其持有的 GPU 资源，可能会导致 GPU 内存泄漏。
    * **示例:**  在 WebXR 会话结束后，没有清理相关的 `XRWebGLDrawingBuffer` 对象。

5. **在错误的线程上操作:**  某些操作，特别是涉及 OpenGL 上下文的操作，必须在拥有该上下文的线程上进行。在错误的线程上调用 `XRWebGLDrawingBuffer` 的方法可能会导致崩溃。
    * **示例:**  在非渲染线程上尝试直接修改渲染缓冲区的内容。

**总结:**

`xr_webgl_drawing_buffer.cc` 文件在 Chromium Blink 引擎中扮演着关键角色，负责管理 WebXR 应用中 WebGL 渲染的目标和相关的 GPU 资源。它与 JavaScript WebGL API 和 HTML `<canvas>` 元素紧密相关，并需要与 compositor 进行同步以正确显示渲染结果。理解其功能和潜在的错误有助于开发者构建稳定可靠的 WebXR 应用。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/gpu/xr_webgl_drawing_buffer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/gpu/xr_webgl_drawing_buffer.h"

#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "build/build_config.h"
#include "components/viz/common/resources/shared_image_format.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "gpu/command_buffer/client/client_shared_image.h"
#include "gpu/command_buffer/client/shared_image_interface.h"
#include "gpu/command_buffer/common/shared_image_usage.h"
#include "gpu/config/gpu_driver_bug_workaround_type.h"
#include "third_party/blink/renderer/platform/graphics/accelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/gpu/drawing_buffer.h"
#include "third_party/blink/renderer/platform/graphics/gpu/extensions_3d_util.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/skia/include/core/SkSurface.h"

namespace {

class ScopedPixelLocalStorageInterrupt {
 public:
  explicit ScopedPixelLocalStorageInterrupt(
      blink::DrawingBuffer::Client* client)
      : client_(client) {
    if (client_) {
      client_->DrawingBufferClientInterruptPixelLocalStorage();
    }
  }
  ~ScopedPixelLocalStorageInterrupt() {
    if (client_) {
      client_->DrawingBufferClientRestorePixelLocalStorage();
    }
  }

 private:
  const raw_ptr<blink::DrawingBuffer::Client> client_;
};

}  // namespace

namespace blink {

// Large parts of this file have been shamelessly borrowed from
// platform/graphics/gpu/DrawingBuffer.cpp and simplified where applicable due
// to the more narrow use case. It may make sense in the future to abstract out
// some of the common bits into a base class?

XRWebGLDrawingBuffer::ColorBuffer::ColorBuffer(
    base::WeakPtr<XRWebGLDrawingBuffer> drawing_buffer,
    const gfx::Size& size,
    scoped_refptr<gpu::ClientSharedImage> shared_image,
    GLuint texture_id)
    : owning_thread_ref(base::PlatformThread::CurrentRef()),
      drawing_buffer(std::move(drawing_buffer)),
      size(size),
      texture_id(texture_id),
      shared_image(std::move(shared_image)) {}

XRWebGLDrawingBuffer::ColorBuffer::~ColorBuffer() {
  if (base::PlatformThread::CurrentRef() != owning_thread_ref ||
      !drawing_buffer) {
    // If the context has been destroyed no cleanup is necessary since all
    // resources below are automatically destroyed. Note that if a ColorBuffer
    // is being destroyed on a different thread, it implies that the owning
    // thread was destroyed which means the associated context was also
    // destroyed.
    return;
  }

  gpu::gles2::GLES2Interface* gl = drawing_buffer->ContextGL();
  if (receive_sync_token.HasData())
    gl->WaitSyncTokenCHROMIUM(receive_sync_token.GetConstData());
  gl->DeleteTextures(1, &texture_id);
  gpu::SyncToken sync_token;
  gl->GenUnverifiedSyncTokenCHROMIUM(sync_token.GetData());
  shared_image->UpdateDestructionSyncToken(sync_token);
}

scoped_refptr<XRWebGLDrawingBuffer> XRWebGLDrawingBuffer::Create(
    DrawingBuffer* drawing_buffer,
    GLuint framebuffer,
    const gfx::Size& size,
    bool want_alpha_channel,
    bool want_depth_buffer,
    bool want_stencil_buffer,
    bool want_antialiasing) {
  DCHECK(drawing_buffer);

  // Don't proceeed if the context is already lost.
  if (drawing_buffer->destroyed())
    return nullptr;

  gpu::gles2::GLES2Interface* gl = drawing_buffer->ContextGL();

  std::unique_ptr<Extensions3DUtil> extensions_util =
      Extensions3DUtil::Create(gl);
  if (!extensions_util->IsValid()) {
    return nullptr;
  }

  DCHECK(extensions_util->SupportsExtension("GL_OES_packed_depth_stencil"));
  extensions_util->EnsureExtensionEnabled("GL_OES_packed_depth_stencil");
  bool multisample_supported =
      want_antialiasing &&
      (extensions_util->SupportsExtension(
           "GL_CHROMIUM_framebuffer_multisample") ||
       extensions_util->SupportsExtension(
           "GL_EXT_multisampled_render_to_texture")) &&
      extensions_util->SupportsExtension("GL_OES_rgb8_rgba8");
  if (multisample_supported) {
    extensions_util->EnsureExtensionEnabled("GL_OES_rgb8_rgba8");
    if (extensions_util->SupportsExtension(
            "GL_CHROMIUM_framebuffer_multisample")) {
      extensions_util->EnsureExtensionEnabled(
          "GL_CHROMIUM_framebuffer_multisample");
    } else {
      extensions_util->EnsureExtensionEnabled(
          "GL_EXT_multisampled_render_to_texture");
    }
  }
  bool discard_framebuffer_supported =
      extensions_util->SupportsExtension("GL_EXT_discard_framebuffer");
  if (discard_framebuffer_supported)
    extensions_util->EnsureExtensionEnabled("GL_EXT_discard_framebuffer");

  scoped_refptr<XRWebGLDrawingBuffer> xr_drawing_buffer =
      base::AdoptRef(new XRWebGLDrawingBuffer(
          drawing_buffer, framebuffer, discard_framebuffer_supported,
          want_alpha_channel, want_depth_buffer, want_stencil_buffer));
  if (!xr_drawing_buffer->Initialize(size, multisample_supported)) {
    DLOG(ERROR) << "XRWebGLDrawingBuffer Initialization Failed";
    return nullptr;
  }

  return xr_drawing_buffer;
}

XRWebGLDrawingBuffer::XRWebGLDrawingBuffer(DrawingBuffer* drawing_buffer,
                                           GLuint framebuffer,
                                           bool discard_framebuffer_supported,
                                           bool want_alpha_channel,
                                           bool want_depth_buffer,
                                           bool want_stencil_buffer)
    : drawing_buffer_(drawing_buffer),
      framebuffer_(framebuffer),
      discard_framebuffer_supported_(discard_framebuffer_supported),
      depth_(want_depth_buffer),
      stencil_(want_stencil_buffer),
      alpha_(want_alpha_channel),
      weak_factory_(this) {}

void XRWebGLDrawingBuffer::BeginDestruction() {
  if (back_color_buffer_) {
    gpu::gles2::GLES2Interface* gl = drawing_buffer_->ContextGL();
    gl->EndSharedImageAccessDirectCHROMIUM(back_color_buffer_->texture_id);
    back_color_buffer_ = nullptr;
  }

  front_color_buffer_ = nullptr;
  recycled_color_buffer_queue_.clear();
}

// TODO(bajones): The GL resources allocated in this function are leaking. Add
// a way to clean up the buffers when the layer is GCed or the session ends.
bool XRWebGLDrawingBuffer::Initialize(const gfx::Size& size,
                                      bool use_multisampling) {
  gpu::gles2::GLES2Interface* gl = drawing_buffer_->ContextGL();

  std::unique_ptr<Extensions3DUtil> extensions_util =
      Extensions3DUtil::Create(gl);

  gl->GetIntegerv(GL_MAX_TEXTURE_SIZE, &max_texture_size_);
  DVLOG(2) << __FUNCTION__ << ": max_texture_size_=" << max_texture_size_;

  // Check context capabilities
  int max_sample_count = 0;
  anti_aliasing_mode_ = kNone;
  if (use_multisampling) {
    gl->GetIntegerv(GL_MAX_SAMPLES_ANGLE, &max_sample_count);
    anti_aliasing_mode_ = kMSAAExplicitResolve;
    const auto& gpu_feature_info =
        drawing_buffer_->ContextProvider()->GetGpuFeatureInfo();
    const bool is_using_graphite =
        gpu_feature_info.status_values[gpu::GPU_FEATURE_TYPE_SKIA_GRAPHITE] ==
        gpu::kGpuFeatureStatusEnabled;
    // With Graphite, Skia is not using ANGLE, so ANGLE cannot do an implicit
    // resolve when the back buffer is sampled by Skia.
    if (!is_using_graphite && extensions_util->SupportsExtension(
                                  "GL_EXT_multisampled_render_to_texture")) {
      anti_aliasing_mode_ = kMSAAImplicitResolve;
    }
  }
  DVLOG(2) << __FUNCTION__
           << ": anti_aliasing_mode_=" << static_cast<int>(anti_aliasing_mode_);

#if BUILDFLAG(IS_ANDROID)
  // On Android devices use a smaller number of samples to provide more breathing
  // room for fill-rate-bound applications.
  sample_count_ = std::min(2, max_sample_count);
#else
  sample_count_ = std::min(4, max_sample_count);
#endif

  Resize(size);

  // It's possible that the drawing buffer allocation provokes a context loss,
  // so check again just in case.
  if (gl->GetGraphicsResetStatusKHR() != GL_NO_ERROR) {
    return false;
  }

  return true;
}

gpu::gles2::GLES2Interface* XRWebGLDrawingBuffer::ContextGL() {
  return drawing_buffer_->ContextGL();
}

bool XRWebGLDrawingBuffer::ContextLost() {
  return drawing_buffer_->destroyed();
}

gfx::Size XRWebGLDrawingBuffer::AdjustSize(const gfx::Size& new_size) {
  // Ensure we always have at least a 1x1 buffer
  float width = std::max(1, new_size.width());
  float height = std::max(1, new_size.height());

  float adjusted_scale =
      std::min(static_cast<float>(max_texture_size_) / width,
               static_cast<float>(max_texture_size_) / height);

  // Clamp if the desired size is greater than the maximum texture size for the
  // device. Scale both dimensions proportionally so that we avoid stretching.
  if (adjusted_scale < 1.0f) {
    width *= adjusted_scale;
    height *= adjusted_scale;
  }

  return gfx::Size(width, height);
}

void XRWebGLDrawingBuffer::UseSharedBuffer(
    const scoped_refptr<gpu::ClientSharedImage>& buffer_shared_image,
    const gpu::SyncToken& buffer_sync_token) {
  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(
      drawing_buffer_->client());
  gpu::gles2::GLES2Interface* gl = drawing_buffer_->ContextGL();

  // Ensure that the shared image is ready to use, the following actions need
  // to be sequenced after setup steps that were done through a different
  // process's GPU command buffer context.
  //
  // TODO(https://crbug.com/1111526): Investigate handling context loss and
  // recovery for cases where these assumptions may not be accurate.
  DCHECK(buffer_sync_token.HasData());
  DCHECK(buffer_shared_image);
  DVLOG(3) << __func__
           << ": mailbox=" << buffer_shared_image->mailbox().ToDebugString()
           << ", SyncToken=" << buffer_sync_token.ToDebugString();
  gl->WaitSyncTokenCHROMIUM(buffer_sync_token.GetConstData());

  // Create a texture backed by the shared buffer image.
  DCHECK(!shared_buffer_texture_id_);
  shared_buffer_texture_id_ = gl->CreateAndTexStorage2DSharedImageCHROMIUM(
      buffer_shared_image->mailbox().name);

  gl->BeginSharedImageAccessDirectCHROMIUM(
      shared_buffer_texture_id_,
      GL_SHARED_IMAGE_ACCESS_MODE_READWRITE_CHROMIUM);

  if (WantExplicitResolve()) {
    // Bind the shared texture to the destination framebuffer of
    // the explicit resolve step.
    if (!resolved_framebuffer_) {
      gl->GenFramebuffers(1, &resolved_framebuffer_);
    }
    gl->BindFramebuffer(GL_FRAMEBUFFER, resolved_framebuffer_);
  } else {
    // Bind the shared texture directly to the drawing framebuffer.
    gl->BindFramebuffer(GL_FRAMEBUFFER, framebuffer_);
  }

  if (anti_aliasing_mode_ == kMSAAImplicitResolve) {
    gl->FramebufferTexture2DMultisampleEXT(
        GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
        shared_buffer_texture_id_, 0, sample_count_);
  } else {
    // Explicit resolve, screen space antialiasing, or no antialiasing.
    gl->FramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                             GL_TEXTURE_2D, shared_buffer_texture_id_, 0);
  }

  if (!framebuffer_complete_checked_for_sharedbuffer_) {
    DCHECK(gl->CheckFramebufferStatus(GL_FRAMEBUFFER) ==
           GL_FRAMEBUFFER_COMPLETE);
    framebuffer_complete_checked_for_sharedbuffer_ = true;
  }

  if (WantExplicitResolve()) {
    // Bind the drawing framebuffer if it wasn't bound previously.
    gl->BindFramebuffer(GL_FRAMEBUFFER, framebuffer_);
  }

  ClearBoundFramebuffer();

  DrawingBuffer::Client* client = drawing_buffer_->client();
  if (!client)
    return;
  client->DrawingBufferClientRestoreFramebufferBinding();
}

void XRWebGLDrawingBuffer::DoneWithSharedBuffer() {
  DVLOG(3) << __FUNCTION__;

  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(
      drawing_buffer_->client());
  BindAndResolveDestinationFramebuffer();

  gpu::gles2::GLES2Interface* gl = drawing_buffer_->ContextGL();

  // Discard the depth and stencil attachments since we're done with them.
  // Don't discard the color buffer, we do need this rendered into the
  // shared buffer.
  if (discard_framebuffer_supported_) {
    const GLenum kAttachments[3] = {GL_DEPTH_ATTACHMENT, GL_STENCIL_ATTACHMENT};
    gl->BindFramebuffer(GL_FRAMEBUFFER, framebuffer_);
    gl->DiscardFramebufferEXT(GL_FRAMEBUFFER, 2, kAttachments);
  }

  // Always bind to the default framebuffer as a hint to the GPU to start
  // rendering now.
  gl->BindFramebuffer(GL_FRAMEBUFFER, 0);

  // Done with the texture created by CreateAndTexStorage2DSharedImageCHROMIUM
  // finish accessing and delete it.
  DCHECK(shared_buffer_texture_id_);
  gl->EndSharedImageAccessDirectCHROMIUM(shared_buffer_texture_id_);
  gl->DeleteTextures(1, &shared_buffer_texture_id_);
  shared_buffer_texture_id_ = 0;

  DrawingBuffer::Client* client = drawing_buffer_->client();
  if (!client)
    return;
  client->DrawingBufferClientRestoreFramebufferBinding();
}

void XRWebGLDrawingBuffer::ClearBoundFramebuffer() {
  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(
      drawing_buffer_->client());
  gpu::gles2::GLES2Interface* gl = drawing_buffer_->ContextGL();

  GLbitfield clear_bits = GL_COLOR_BUFFER_BIT;
  gl->ColorMask(true, true, true, true);
  gl->ClearColor(0.0f, 0.0f, 0.0f, 0.0f);

  if (depth_) {
    clear_bits |= GL_DEPTH_BUFFER_BIT;
    gl->DepthMask(true);
    gl->ClearDepthf(1.0f);
  }

  if (stencil_) {
    clear_bits |= GL_STENCIL_BUFFER_BIT;
    gl->StencilMaskSeparate(GL_FRONT, true);
    gl->ClearStencil(0);
  }

  gl->Disable(GL_SCISSOR_TEST);

  gl->Clear(clear_bits);

  DrawingBuffer::Client* client = drawing_buffer_->client();
  if (!client)
    return;

  client->DrawingBufferClientRestoreScissorTest();
  client->DrawingBufferClientRestoreMaskAndClearValues();
}

void XRWebGLDrawingBuffer::Resize(const gfx::Size& new_size) {
  gfx::Size adjusted_size = AdjustSize(new_size);

  if (adjusted_size == size_)
    return;

  // Don't attempt to resize if the context is lost.
  if (ContextLost())
    return;

  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(
      drawing_buffer_->client());
  gpu::gles2::GLES2Interface* gl = drawing_buffer_->ContextGL();

  size_ = adjusted_size;

  // Free all mailboxes, because they are now of the wrong size. Only the
  // first call in this loop has any effect.
  recycled_color_buffer_queue_.clear();

  gl->BindFramebuffer(GL_FRAMEBUFFER, framebuffer_);

  // Provide a depth and/or stencil buffer if requested.
  if (depth_ || stencil_) {
    if (depth_stencil_buffer_) {
      gl->DeleteRenderbuffers(1, &depth_stencil_buffer_);
      depth_stencil_buffer_ = 0;
    }
    gl->GenRenderbuffers(1, &depth_stencil_buffer_);
    gl->BindRenderbuffer(GL_RENDERBUFFER, depth_stencil_buffer_);

    if (anti_aliasing_mode_ == kMSAAImplicitResolve) {
      gl->RenderbufferStorageMultisampleEXT(GL_RENDERBUFFER, sample_count_,
                                            GL_DEPTH24_STENCIL8_OES,
                                            size_.width(), size_.height());
    } else if (anti_aliasing_mode_ == kMSAAExplicitResolve) {
      gl->RenderbufferStorageMultisampleCHROMIUM(GL_RENDERBUFFER, sample_count_,
                                                 GL_DEPTH24_STENCIL8_OES,
                                                 size_.width(), size_.height());
    } else {
      gl->RenderbufferStorage(GL_RENDERBUFFER, GL_DEPTH24_STENCIL8_OES,
                              size_.width(), size_.height());
    }

    gl->FramebufferRenderbuffer(GL_FRAMEBUFFER, GL_DEPTH_STENCIL_ATTACHMENT,
                                GL_RENDERBUFFER, depth_stencil_buffer_);
  }

  if (WantExplicitResolve()) {
    // If we're doing an explicit multisample resolve use the main framebuffer
    // as the multisample target and resolve into resolved_fbo_ when needed.
    GLenum multisample_format = alpha_ ? GL_RGBA8_OES : GL_RGB8_OES;

    if (multisample_renderbuffer_) {
      gl->DeleteRenderbuffers(1, &multisample_renderbuffer_);
      multisample_renderbuffer_ = 0;
    }

    gl->GenRenderbuffers(1, &multisample_renderbuffer_);
    gl->BindRenderbuffer(GL_RENDERBUFFER, multisample_renderbuffer_);
    gl->RenderbufferStorageMultisampleCHROMIUM(GL_RENDERBUFFER, sample_count_,
                                               multisample_format,
                                               size_.width(), size_.height());

    gl->FramebufferRenderbuffer(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                                GL_RENDERBUFFER, multisample_renderbuffer_);

    // Now bind the resolve target framebuffer to attach the color textures to.
    if (!resolved_framebuffer_) {
      gl->GenFramebuffers(1, &resolved_framebuffer_);
    }
    gl->BindFramebuffer(GL_FRAMEBUFFER, resolved_framebuffer_);
  }

  if (back_color_buffer_) {
    gl->EndSharedImageAccessDirectCHROMIUM(back_color_buffer_->texture_id);
  }

  back_color_buffer_ = CreateColorBuffer();
  front_color_buffer_ = nullptr;

  gl->BeginSharedImageAccessDirectCHROMIUM(
      back_color_buffer_->texture_id,
      GL_SHARED_IMAGE_ACCESS_MODE_READWRITE_CHROMIUM);

  if (anti_aliasing_mode_ == kMSAAImplicitResolve) {
    gl->FramebufferTexture2DMultisampleEXT(
        GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
        back_color_buffer_->texture_id, 0, sample_count_);
  } else {
    gl->FramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                             GL_TEXTURE_2D, back_color_buffer_->texture_id, 0);
  }

  if (!framebuffer_complete_checked_for_resize_) {
    DCHECK(gl->CheckFramebufferStatus(GL_FRAMEBUFFER) ==
           GL_FRAMEBUFFER_COMPLETE);
    framebuffer_complete_checked_for_resize_ = true;
  }

  DrawingBuffer::Client* client = drawing_buffer_->client();
  client->DrawingBufferClientRestoreRenderbufferBinding();
  client->DrawingBufferClientRestoreFramebufferBinding();
}

scoped_refptr<XRWebGLDrawingBuffer::ColorBuffer>
XRWebGLDrawingBuffer::CreateColorBuffer() {
  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(
      drawing_buffer_->client());
  auto* sii = drawing_buffer_->ContextProvider()->SharedImageInterface();

  // These shared images will be imported into textures on the GL context. We
  // take a read/write access scope whenever the color buffer is used as the
  // back buffer.
  gpu::SharedImageUsageSet usage = gpu::SHARED_IMAGE_USAGE_DISPLAY_READ |
                                   gpu::SHARED_IMAGE_USAGE_GLES2_READ |
                                   gpu::SHARED_IMAGE_USAGE_GLES2_WRITE;
  auto client_shared_image = sii->CreateSharedImage(
      {alpha_ ? viz::SinglePlaneFormat::kRGBA_8888
              : viz::SinglePlaneFormat::kRGBX_8888,
       size_, gfx::ColorSpace(), usage, "XRWebGLDrawingBuffer"},
      gpu::kNullSurfaceHandle);
  CHECK(client_shared_image);

  gpu::gles2::GLES2Interface* gl = drawing_buffer_->ContextGL();
  gl->WaitSyncTokenCHROMIUM(sii->GenUnverifiedSyncToken().GetConstData());

  GLuint texture_id = gl->CreateAndTexStorage2DSharedImageCHROMIUM(
      client_shared_image->mailbox().name);

  DrawingBuffer::Client* client = drawing_buffer_->client();
  client->DrawingBufferClientRestoreTexture2DBinding();

  return base::MakeRefCounted<ColorBuffer>(weak_factory_.GetWeakPtr(), size_,
                                           std::move(client_shared_image),
                                           texture_id);
}

scoped_refptr<XRWebGLDrawingBuffer::ColorBuffer>
XRWebGLDrawingBuffer::CreateOrRecycleColorBuffer() {
  if (!recycled_color_buffer_queue_.empty()) {
    scoped_refptr<ColorBuffer> recycled =
        recycled_color_buffer_queue_.TakeLast();
    if (recycled->receive_sync_token.HasData()) {
      gpu::gles2::GLES2Interface* gl = drawing_buffer_->ContextGL();
      gl->WaitSyncTokenCHROMIUM(recycled->receive_sync_token.GetData());
    }
    DCHECK(recycled->size == size_);
    return recycled;
  }
  return CreateColorBuffer();
}

bool XRWebGLDrawingBuffer::WantExplicitResolve() const {
  return anti_aliasing_mode_ == kMSAAExplicitResolve;
}

void XRWebGLDrawingBuffer::BindAndResolveDestinationFramebuffer() {
  // Ensure that the mode-appropriate destination framebuffer's color
  // attachment contains the drawn content after any antialiasing steps needed.

  gpu::gles2::GLES2Interface* gl = drawing_buffer_->ContextGL();

  DrawingBuffer::Client* client = drawing_buffer_->client();
  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(client);

  // Resolve multisample buffers if needed
  if (WantExplicitResolve()) {
    DVLOG(3) << __FUNCTION__ << ": explicit resolve";
    gl->BindFramebuffer(GL_READ_FRAMEBUFFER_ANGLE, framebuffer_);
    gl->BindFramebuffer(GL_DRAW_FRAMEBUFFER_ANGLE, resolved_framebuffer_);
    gl->Disable(GL_SCISSOR_TEST);

    int width = size_.width();
    int height = size_.height();
    // Use NEAREST, because there is no scale performed during the blit.
    gl->BlitFramebufferCHROMIUM(0, 0, width, height, 0, 0, width, height,
                                GL_COLOR_BUFFER_BIT, GL_NEAREST);

    gl->BindFramebuffer(GL_FRAMEBUFFER, resolved_framebuffer_);

    client->DrawingBufferClientRestoreScissorTest();
  } else {
    gl->BindFramebuffer(GL_FRAMEBUFFER, framebuffer_);
    DVLOG(3) << __FUNCTION__ << ": nothing to do";
  }

  // On exit, leaves the destination framebuffer active. Caller is responsible
  // for restoring client bindings.
}

// Swap the front and back buffers. After this call the front buffer should
// contain the previously rendered content, resolved from the multisample
// renderbuffer if needed.
void XRWebGLDrawingBuffer::SwapColorBuffers() {
  gpu::gles2::GLES2Interface* gl = drawing_buffer_->ContextGL();

  DrawingBuffer::Client* client = drawing_buffer_->client();
  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(client);

  BindAndResolveDestinationFramebuffer();

  if (back_color_buffer_) {
    gl->EndSharedImageAccessDirectCHROMIUM(back_color_buffer_->texture_id);
  }

  // Swap buffers
  front_color_buffer_ = back_color_buffer_;
  back_color_buffer_ = CreateOrRecycleColorBuffer();

  gl->BeginSharedImageAccessDirectCHROMIUM(
      back_color_buffer_->texture_id,
      GL_SHARED_IMAGE_ACCESS_MODE_READWRITE_CHROMIUM);

  if (anti_aliasing_mode_ == kMSAAImplicitResolve) {
    gl->FramebufferTexture2DMultisampleEXT(
        GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
        back_color_buffer_->texture_id, 0, sample_count_);
  } else {
    gl->FramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                             GL_TEXTURE_2D, back_color_buffer_->texture_id, 0);
  }

  if (!framebuffer_complete_checked_for_swap_) {
    DCHECK(gl->CheckFramebufferStatus(GL_FRAMEBUFFER) ==
           GL_FRAMEBUFFER_COMPLETE);
    framebuffer_complete_checked_for_swap_ = true;
  }

  if (WantExplicitResolve()) {
    // Bind the drawing framebuffer if it wasn't bound previously.
    gl->BindFramebuffer(GL_FRAMEBUFFER, framebuffer_);
  }

  ClearBoundFramebuffer();

  client->DrawingBufferClientRestoreFramebufferBinding();
}

scoped_refptr<StaticBitmapImage>
XRWebGLDrawingBuffer::TransferToStaticBitmapImage() {
  gpu::gles2::GLES2Interface* gl = drawing_buffer_->ContextGL();
  scoped_refptr<ColorBuffer> buffer;
  bool success = false;

  // Ensure the context isn't lost and the framebuffer is complete before
  // continuing.
  if (!ContextLost()) {
    SwapColorBuffers();

    buffer = front_color_buffer_;

    gl->GenUnverifiedSyncTokenCHROMIUM(buffer->produce_sync_token.GetData());

    // This should only fail if the context is lost during the buffer swap.
    if (buffer->produce_sync_token.HasData()) {
      success = true;
    }
  }

  if (!success) {
    // If we can't get a mailbox, return an transparent black ImageBitmap.
    // The only situation in which this could happen is when two or more calls
    // to transferToImageBitmap are made back-to-back, if the framebuffer is
    // incomplete (likely due to a failed buffer allocation), or when the
    // context gets lost.
    sk_sp<SkSurface> surface = SkSurfaces::Raster(
        SkImageInfo::MakeN32Premul(size_.width(), size_.height()));
    return UnacceleratedStaticBitmapImage::Create(surface->makeImageSnapshot());
  }

  // This holds a ref on the XRWebGLDrawingBuffer that will keep it alive
  // until the mailbox is released (and while the callback is running).
  viz::ReleaseCallback release_callback =
      base::BindOnce(&XRWebGLDrawingBuffer::NotifyMailboxReleased, buffer);
  const SkImageInfo sk_image_info =
      SkImageInfo::MakeN32Premul(size_.width(), size_.height());

  const bool is_origin_top_left =
      buffer->shared_image->surface_origin() == kTopLeft_GrSurfaceOrigin;
  return AcceleratedStaticBitmapImage::CreateFromCanvasSharedImage(
      buffer->shared_image, buffer->produce_sync_token,
      /* shared_image_texture_id = */ 0, sk_image_info, GL_TEXTURE_2D,
      /* is_origin_top_left = */ is_origin_top_left,
      drawing_buffer_->ContextProviderWeakPtr(),
      base::PlatformThread::CurrentRef(),
      ThreadScheduler::Current()->CleanupTaskRunner(),
      std::move(release_callback),
      /*supports_display_compositing=*/true,
      // CreateColorBuffer() never sets the SCANOUT usage bit.
      /*is_overlay_candidate=*/false);
}

// static
void XRWebGLDrawingBuffer::NotifyMailboxReleased(
    scoped_refptr<ColorBuffer> color_buffer,
    const gpu::SyncToken& sync_token,
    bool lost_resource) {
  DCHECK(color_buffer->owning_thread_ref == base::PlatformThread::CurrentRef());

  // Update the SyncToken to ensure that we will wait for it even if we
  // immediately destroy this buffer.
  color_buffer->receive_sync_token = sync_token;
  if (color_buffer->drawing_buffer) {
    color_buffer->drawing_buffer->MailboxReleased(color_buffer, lost_resource);
  }
}

void XRWebGLDrawingBuffer::MailboxReleased(
    scoped_refptr<ColorBuffer> color_buffer,
    bool lost_resource) {
  // If the mailbox has been returned by the compositor then it is no
  // longer being presented, and so is no longer the front buffer.
  if (color_buffer == front_color_buffer_)
    front_color_buffer_ = nullptr;

  if (drawing_buffer_->destroyed() || color_buffer->size != size_ ||
      lost_resource) {
    return;
  }

  const size_t cache_limit = 2;
  while (recycled_color_buffer_queue_.size() >= cache_limit)
    recycled_color_buffer_queue_.TakeLast();

  recycled_color_buffer_queue_.push_front(color_buffer);
}

}  // namespace blink

"""

```