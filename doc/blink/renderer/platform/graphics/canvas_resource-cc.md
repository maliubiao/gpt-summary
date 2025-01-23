Response:
Let's break down the thought process for analyzing the `canvas_resource.cc` file and generating the response.

**1. Initial Understanding and Goal:**

The core request is to understand the functionality of this specific Chromium Blink engine source file. Key aspects to identify are its purpose, relationships to web technologies (JavaScript, HTML, CSS), logical operations, and potential usage errors.

**2. Core Functionality Identification (Keywords and Code Structure):**

The first step is to scan the code for recurring keywords and structural elements that suggest the file's purpose.

* **`CanvasResource` class:** This is the central entity. Its constructor, destructor, and methods will reveal core responsibilities.
* **`SharedImage` and related terms:**  `SharedImageFormat`, `ClientSharedImage`, `SharedImageInterface`, `gpu::SHARED_IMAGE_USAGE_*`. This strongly suggests the file deals with GPU-backed resources shared between processes.
* **`SkImage`, `SkSurface`, `SkPixmap`:**  These are Skia graphics library components, indicating image data manipulation.
* **`viz::TransferableResource`:**  This points to the mechanisms for transferring GPU resources between compositing layers and processes.
* **`gpu::SyncToken`:**  This indicates synchronization between the CPU and GPU.
* **`ContextProviderWrapper`:** This suggests interaction with the GPU context.
* **Specific subclasses (e.g., `CanvasResourceSharedBitmap`, `CanvasResourceSharedImage`, `ExternalCanvasResource`, `CanvasResourceSwapChain`):** These represent different types of canvas resources, likely with distinct characteristics and use cases.
* **Methods like `Bitmap()`, `PrepareTransferableResource()`, `UploadSoftwareRenderingResults()`, `PresentSwapChain()`:**  These are action verbs that describe the operations the class performs.

**3. Deconstructing Subclasses and Their Roles:**

Once the `CanvasResource` base class is recognized as an abstraction, examine its subclasses:

* **`CanvasResourceSharedBitmap`:**  The name and the use of `base::span` and `SkImages::RasterFromPixmap` suggest this handles CPU-backed bitmaps shared via memory.
* **`CanvasResourceSharedImage`:**  The connection to `WebGraphicsContext3DProviderWrapper` and the handling of `gpu::ClientSharedImage` make it clear this deals with GPU-backed textures. The presence of `BeginWriteAccess` and `EndWriteAccess` indicates it manages GPU access.
* **`ExternalCanvasResource`:**  The name and the acceptance of a `viz::TransferableResource` in the constructor imply this represents a canvas resource created *outside* the current context and being imported.
* **`CanvasResourceSwapChain`:** The `PresentSwapChain()` method strongly indicates this handles the double-buffering mechanism for rendering, often used in `<canvas>` elements configured for WebGL.

**4. Mapping to Web Technologies:**

Now, connect the identified functionalities to JavaScript, HTML, and CSS:

* **`<canvas>` element (HTML):** This is the most direct link. The `CanvasResource` is the underlying representation of the drawing surface.
* **Canvas 2D API (JavaScript):**  Methods like `getContext('2d')`, drawing operations (rectangles, paths, text, images), and `getImageData()` interact with these `CanvasResource` objects. `CanvasResourceSharedBitmap` is a likely backing for software-rendered canvases.
* **WebGL API (JavaScript):** Methods like `getContext('webgl')` or `getContext('webgl2')` and operations involving textures and framebuffers are closely tied to `CanvasResourceSharedImage` and `CanvasResourceSwapChain`.
* **`OffscreenCanvas` (JavaScript):**  `ExternalCanvasResource` seems relevant here as it handles resources created and transferred from other contexts (like an `OffscreenCanvas`).
* **CSS (indirectly):** While CSS doesn't directly manipulate `CanvasResource`, it affects the layout and rendering of the `<canvas>` element, which indirectly influences how the `CanvasResource` is used.

**5. Identifying Logical Operations and Assumptions:**

Focus on methods that involve decision-making or resource management:

* **`PrepareTransferableResource()`:**  This method encapsulates the logic for creating the `viz::TransferableResource`, which depends on whether the resource is GPU-backed or CPU-backed. The different branches for `UsesClientSharedImage()` are key.
* **`ReleaseFrameResources()`:** This function handles the complex logic of releasing resources back to the pool, considering sync tokens and potential loss of resources. The `HasLastUnrefCallback()` check is important for understanding lifetime management.
* **`GetSyncTokenWithOptionalVerification()`:**  This illustrates the need for synchronization between the CPU and GPU, with optional verification steps.
* **The constructors of the subclasses:**  The initialization logic, especially for `CanvasResourceSharedImage` and `CanvasResourceSwapChain`, reveals how GPU resources are allocated and configured.

**6. Considering User/Programming Errors:**

Think about common mistakes developers might make when working with canvases:

* **Accessing resources on the wrong thread:** The `is_cross_thread()` checks are a big clue here. This is a common issue with multi-threaded graphics programming.
* **Not handling lost contexts:** The `NotifyResourceLost()` method and the checks for `IsValid()` point to the need to handle situations where the GPU context is lost.
* **Incorrectly managing sync tokens:** While the file handles synchronization internally, a user might introduce errors if they try to manually interact with GPU resources outside the intended Blink mechanisms. (Though this file mostly hides that complexity).
* **Memory leaks (less direct in this file):** While not explicitly causing leaks, improper resource management within `CanvasResource` *could* contribute if not handled correctly in the larger system.

**7. Structuring the Response:**

Organize the findings logically:

* **Overview of Functionality:** Start with a high-level summary.
* **Detailed Functionalities (Subclasses):**  Explain the role of each subclass.
* **Relationship to Web Technologies:**  Provide concrete examples of how the code interacts with JavaScript, HTML, and CSS.
* **Logical Inferences:** Present assumptions, inputs, and outputs for key methods.
* **Common Usage Errors:**  List potential pitfalls for developers.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This file manages canvas drawing."  **Correction:** While related to canvas drawing, it's more about the *underlying resources* that enable it, particularly GPU resources.
* **Overemphasis on drawing operations:**  The file doesn't implement the drawing algorithms themselves, but rather manages the surfaces and textures that drawing occurs on.
* **Missing the cross-thread aspect:** Realizing the significance of `owning_thread_ref_`, `is_cross_thread()`, and the thread-safe ref counting mechanisms is crucial.
* **Focusing too narrowly on a single subclass:** Recognizing the interconnectedness of the subclasses and the base `CanvasResource` is important.

By following this thought process, combining code analysis with an understanding of web graphics concepts, a comprehensive and accurate explanation of the `canvas_resource.cc` file can be constructed.
这个文件 `blink/renderer/platform/graphics/canvas_resource.cc` 是 Chromium Blink 渲染引擎中负责管理 Canvas 资源的核心组件。它定义了 `CanvasResource` 及其子类，用于封装和管理 `<canvas>` 元素在渲染过程中使用的各种底层资源，包括 CPU 内存和 GPU 纹理。

以下是该文件的主要功能：

**1. 抽象 Canvas 资源:**

* `CanvasResource` 是一个抽象基类，它定义了所有 Canvas 资源共享的基本属性和行为，例如：
    * **提供者 (`CanvasResourceProvider`):**  用于与资源提供者进行交互，管理资源的生命周期和回收。
    * **过滤质量 (`filter_quality`):**  控制图像缩放和变换时的抗锯齿程度。
    * **尺寸 (`size`):**  资源的宽度和高度。
    * **像素格式 (`format_`):**  资源中像素数据的格式，例如 `BGRA_8888`。
    * **Alpha 类型 (`sk_alpha_type_`):**  指定像素是否包含透明度信息以及如何处理。
    * **颜色空间 (`color_space_`):**  定义颜色的解释方式。
* 它使用线程安全的引用计数 (`WTF::ThreadSafeRefCounted`) 来管理资源的生命周期。

**2. 管理不同类型的 Canvas 资源:**

该文件定义了 `CanvasResource` 的几个子类，用于处理不同类型的 Canvas 资源及其特性：

* **`CanvasResourceSharedBitmap`:**  用于管理基于共享内存的 Canvas 资源。这种资源类型主要用于软件渲染或 CPU 访问的场景。
* **`CanvasResourceSharedImage`:**  用于管理基于 GPU `SharedImage` 的 Canvas 资源。这种资源类型用于硬件加速渲染，可以被 GPU 直接访问。
* **`ExternalCanvasResource`:**  用于管理来自外部的 Canvas 资源，例如从 `OffscreenCanvas` 传递过来的资源。
* **`CanvasResourceSwapChain`:**  用于管理双缓冲的 Canvas 资源，通常用于 WebGL 上下文，实现流畅的动画渲染。

**3. 提供资源访问接口:**

* **`Bitmap()`:**  提供一个 `StaticBitmapImage` 对象，允许 CPU 端访问 Canvas 资源的像素数据。根据不同的子类，它可能返回基于共享内存或从 GPU 纹理读取的位图。
* **`PrepareTransferableResource()`:**  将 Canvas 资源转换为 `viz::TransferableResource` 对象，用于在渲染进程和合成器进程之间传递资源。这对于硬件加速的 Canvas 非常重要。
* **`GetClientSharedImage()`:** (仅限 `CanvasResourceSharedImage` 和 `ExternalCanvasResource`) 返回底层的 GPU `ClientSharedImage` 对象，允许进行更底层的 GPU 操作。
* **`CreateGrTexture()`:** (仅限 `CanvasResourceSharedImage`)  创建一个 Skia 的 `GrBackendTexture` 对象，用于在 Skia 中使用 GPU 纹理。

**4. 处理资源同步和释放:**

* **`WaitSyncToken()`:**  等待指定的 GPU 同步令牌完成，确保 GPU 操作在 CPU 继续执行前完成。
* **`Release()`:**  释放 Canvas 资源的引用。当引用计数降为零时，资源会被销毁。
* **`ReleaseFrameResources()`:** 一个静态函数，用于处理 Canvas 资源在合成器线程的释放，包括等待同步令牌和将资源返回给提供者进行回收。
* **`NotifyResourceLost()`:**  通知资源已丢失，例如由于 GPU 上下文丢失。

**5. 与 GPU 通信:**

* 文件中使用了 `gpu::gles2::GLES2Interface`, `gpu::raster::RasterInterface`, 和 `gpu::webgpu::WebGPUInterface` 等接口与 GPU 进行通信，进行纹理的创建、访问、同步等操作。
* 利用 `gpu::SharedImageInterface` 创建和管理 GPU 共享图像。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`canvas_resource.cc` 文件虽然是 C++ 代码，但它直接支撑着 `<canvas>` 元素在 Web 页面中的渲染，因此与 JavaScript、HTML 和 CSS 都有密切关系：

* **HTML (`<canvas>` 元素):**
    * **关系:**  当浏览器解析到 `<canvas>` 元素时，Blink 引擎会创建对应的 `HTMLCanvasElement` 对象，并最终会创建一个或多个 `CanvasResource` 对象来管理其渲染所需的资源。
    * **举例:**  一个简单的 `<canvas id="myCanvas" width="200" height="100"></canvas>` 标签，在 Blink 内部会被关联到一个 `CanvasResource` 对象，其 `size_` 属性会是 `{200, 100}`。

* **JavaScript (Canvas 2D API, WebGL API, OffscreenCanvas):**
    * **关系:**  JavaScript 通过 Canvas API（例如 `getContext('2d')` 或 `getContext('webgl')`）操作 `<canvas>` 元素时，最终会调用 Blink 内部的代码来操作 `CanvasResource` 对象。
    * **Canvas 2D API 举例:** 当 JavaScript 调用 `ctx.fillRect(10, 10, 50, 50)` 时，Blink 会使用与该 `<canvas>` 关联的 `CanvasResourceSharedBitmap` (如果使用软件渲染) 或 `CanvasResourceSharedImage` (如果使用硬件加速) 进行绘制。
    * **WebGL API 举例:** 当 JavaScript 创建一个 WebGL 纹理时，可能会创建一个 `CanvasResourceSharedImage` 来管理这个纹理。当 WebGL 渲染到 Canvas 上时，`CanvasResourceSwapChain` 用于管理前后缓冲区。
    * **OffscreenCanvas 举例:** 当一个 `OffscreenCanvas` 的内容通过 `transferToImageBitmap()` 传输到主线程的 Canvas 时，会创建一个 `ExternalCanvasResource` 来表示这个来自外部的资源。

* **CSS (间接关系):**
    * **关系:** CSS 样式会影响 `<canvas>` 元素的布局、大小和可见性。这些属性的变化可能会导致 `CanvasResource` 的重新创建或调整。
    * **举例:**  如果 CSS 将 Canvas 的宽度设置为 `width: 300px;`，那么与该 Canvas 关联的 `CanvasResource` 的 `size_` 属性也会相应更新为 `{300, 原始高度}`。

**逻辑推理的假设输入与输出:**

以下举例说明 `PrepareTransferableResource()` 方法的逻辑推理：

**假设输入:**

* 一个 `CanvasResourceSharedImage` 对象 (GPU 加速的 Canvas 资源)。
* `needs_verified_synctoken` 为 `true`。

**逻辑推理:**

1. 因为是 `CanvasResourceSharedImage`，所以 `SupportsAcceleratedCompositing()` 返回 `true`。
2. 因为使用了 `SharedImage`，所以 `UsesClientSharedImage()` 返回 `true`。
3. 获取底层的 `ClientSharedImage` 对象。
4. 创建一个 `viz::TransferableResource` 对象：
    * `mailbox` 从 `ClientSharedImage` 获取。
    * `texture_target` 从 `ClientSharedImage` 获取。
    * `sync_token` 通过 `GetSyncTokenWithOptionalVerification(true)` 获取，由于 `needs_verified_synctoken` 为 `true`，会确保返回一个已验证的同步令牌。
    * `size` 从 `CanvasResource` 获取。
    * `format` 从 `CanvasResource` 获取。
    * 其他属性根据资源特性设置。
5. 设置 `out_resource->color_space`。
6. 如果未使用硬件加速栅格化 (`!UsesAcceleratedRaster()`)，则设置 `out_resource->synchronization_type` 为 `kGpuCommandsCompleted`。

**输出:**

* `out_resource` 指向的 `viz::TransferableResource` 对象被填充了描述 GPU 纹理的信息，包括 Mailbox、Texture Target 和已验证的同步令牌。
* 函数返回 `true`。

**用户或编程常见的使用错误举例:**

* **在非拥有线程访问 Canvas 资源:**
    * **错误:**  JavaScript 代码在一个 Web Worker 中尝试直接操作主线程的 Canvas 上下文，或者尝试跨线程访问 `CanvasResource` 对象。
    * **后果:**  由于 `CanvasResource` 的某些操作（特别是涉及 GPU 资源的）只能在创建它的线程上执行，这会导致程序崩溃、数据损坏或未定义的行为。文件中大量的 `is_cross_thread()` 检查就是为了防止此类错误。
    * **示例:**

    ```javascript
    // 主线程
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    // Web Worker 线程
    const worker = new Worker('worker.js');
    worker.postMessage({ imageData: imageData.data.buffer }, [imageData.data.buffer]); // 尝试传递 ImageData 的 ArrayBuffer

    // worker.js
    onmessage = function(e) {
      const data = new Uint8ClampedArray(e.data.imageData);
      // 尝试在 Worker 中修改 Canvas 的像素数据 (这是错误的)
      for (let i = 0; i < data.length; i++) {
        // ... 修改 data
      }
      // ... 无法直接将修改后的数据写回主线程的 CanvasResource
    }
    ```

* **忘记处理 GPU 上下文丢失:**
    * **错误:**  程序没有监听 `webglcontextlost` 和 `webglcontextrestored` 事件，导致在 GPU 上下文丢失后继续尝试使用失效的 `CanvasResourceSharedImage` 或 `CanvasResourceSwapChain`。
    * **后果:**  WebGL 调用会失败，导致渲染错误或程序崩溃。
    * **示例:**

    ```javascript
    const canvas = document.getElementById('myCanvas');
    const gl = canvas.getContext('webgl');
    let texture;

    function initTexture() {
      texture = gl.createTexture();
      // ... 初始化纹理
    }

    initTexture();

    function render() {
      // ... 使用 texture 进行渲染
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      requestAnimationFrame(render);
    }

    render();

    canvas.addEventListener('webglcontextlost', function(event) {
      event.preventDefault();
      console.log('WebGL context lost!');
      // 清理对失效资源的引用，但可能忘记清理所有相关的 CanvasResource 的引用
      texture = null;
    });

    canvas.addEventListener('webglcontextrestored', function() {
      console.log('WebGL context restored!');
      initTexture(); // 重新初始化纹理
      render();      // 重新开始渲染
    });
    ```

* **不正确的同步处理:**
    * **错误:**  在多进程架构中，没有正确地使用同步令牌来确保 CPU 和 GPU 之间的操作顺序，特别是在涉及到跨进程传递 Canvas 资源时。
    * **后果:**  可能出现渲染不同步、内容丢失或撕裂等问题。`PrepareTransferableResource` 和 `ReleaseFrameResources` 中的同步令牌处理就是为了避免这类错误。

总而言之，`canvas_resource.cc` 是 Blink 引擎中一个关键的文件，它抽象并管理了 `<canvas>` 元素渲染所需的各种底层资源，并处理了复杂的资源生命周期管理、同步和跨进程通信等问题，是实现 Canvas 功能的核心组成部分。

### 提示词
```
这是目录为blink/renderer/platform/graphics/canvas_resource.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/canvas_resource.h"

#include <string>
#include <utility>

#include "base/functional/callback_helpers.h"
#include "base/memory/read_only_shared_memory_region.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "components/viz/common/resources/shared_image_format.h"
#include "components/viz/common/resources/shared_image_format_utils.h"
#include "components/viz/common/resources/transferable_resource.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "gpu/command_buffer/client/client_shared_image.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "gpu/command_buffer/client/shared_image_interface.h"
#include "gpu/command_buffer/client/webgpu_interface.h"
#include "gpu/command_buffer/common/capabilities.h"
#include "gpu/command_buffer/common/mailbox.h"
#include "gpu/command_buffer/common/shared_image_trace_utils.h"
#include "gpu/command_buffer/common/shared_image_usage.h"
#include "gpu/command_buffer/common/sync_token.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/graphics/accelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_gpu.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/skia/include/core/SkAlphaType.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkImageInfo.h"
#include "third_party/skia/include/core/SkPixmap.h"
#include "third_party/skia/include/core/SkSize.h"
#include "third_party/skia/include/gpu/GpuTypes.h"
#include "third_party/skia/include/gpu/ganesh/GrBackendSurface.h"
#include "third_party/skia/include/gpu/ganesh/GrTypes.h"
#include "third_party/skia/include/gpu/ganesh/gl/GrGLBackendSurface.h"
#include "third_party/skia/include/gpu/ganesh/gl/GrGLTypes.h"
#include "ui/gfx/buffer_format_util.h"
#include "ui/gfx/color_space.h"

namespace blink {

CanvasResource::CanvasResource(base::WeakPtr<CanvasResourceProvider> provider,
                               cc::PaintFlags::FilterQuality filter_quality,
                               gfx::Size size,
                               viz::SharedImageFormat format,
                               SkAlphaType sk_alpha_type,
                               sk_sp<SkColorSpace> sk_color_space)
    : owning_thread_ref_(base::PlatformThread::CurrentRef()),
      owning_thread_task_runner_(
          ThreadScheduler::Current()->CleanupTaskRunner()),
      provider_(std::move(provider)),
      size_(size),
      format_(format),
      sk_alpha_type_(sk_alpha_type),
      color_space_(sk_color_space ? gfx::ColorSpace(*sk_color_space)
                                  : gfx::ColorSpace::CreateSRGB()),
      filter_quality_(filter_quality) {}

CanvasResource::~CanvasResource() {}

void CanvasResource::Release() {
  if (last_unref_callback_ && HasOneRef()) {
    // "this" will not be destroyed if last_unref_callback_ retains the
    // reference.
#if DCHECK_IS_ON()
    auto last_ref = base::WrapRefCounted(this);
    WTF::ThreadSafeRefCounted<CanvasResource>::Release();  // does not destroy.
#else
    // In a DCHECK build, AdoptRef would fail because it is only supposed to be
    // used on new objects.  Nonetheless, we prefer to use AdoptRef "illegally"
    // in non-DCHECK builds to avoid unnecessary atomic operations.
    auto last_ref = base::AdoptRef(this);
#endif
    std::move(last_unref_callback_).Run(std::move(last_ref));
  } else {
    WTF::ThreadSafeRefCounted<CanvasResource>::Release();
  }
}

gpu::InterfaceBase* CanvasResource::InterfaceBase() const {
  if (!ContextProviderWrapper())
    return nullptr;
  return ContextProviderWrapper()->ContextProvider()->InterfaceBase();
}

gpu::gles2::GLES2Interface* CanvasResource::ContextGL() const {
  if (!ContextProviderWrapper())
    return nullptr;
  return ContextProviderWrapper()->ContextProvider()->ContextGL();
}

gpu::raster::RasterInterface* CanvasResource::RasterInterface() const {
  if (!ContextProviderWrapper())
    return nullptr;
  return ContextProviderWrapper()->ContextProvider()->RasterInterface();
}

gpu::webgpu::WebGPUInterface* CanvasResource::WebGPUInterface() const {
  if (!ContextProviderWrapper())
    return nullptr;
  return ContextProviderWrapper()->ContextProvider()->WebGPUInterface();
}

void CanvasResource::WaitSyncToken(const gpu::SyncToken& sync_token) {
  if (sync_token.HasData()) {
    if (auto* interface_base = InterfaceBase())
      interface_base->WaitSyncTokenCHROMIUM(sync_token.GetConstData());
  }
}

static void ReleaseFrameResources(
    base::WeakPtr<CanvasResourceProvider> resource_provider,
    viz::ReleaseCallback&& viz_release_callback,
    scoped_refptr<CanvasResource>&& resource,
    const gpu::SyncToken& sync_token,
    bool lost_resource) {
  // If there is a LastUnrefCallback, we need to abort because recycling the
  // resource now will prevent the LastUnrefCallback from ever being called.
  // In such cases, ReleaseFrameResources will be called again when
  // CanvasResourceDispatcher destroys the corresponding FrameResource object,
  // at which time this resource will be safely recycled.
  if (!resource) {
    return;
  }

  if (resource->HasLastUnrefCallback()) {
    // Currently, there is no code path that should end up here with
    // a viz_release_callback, but if we ever change ExternalCanvasResource's
    // Bitmap() method to register a non-trivial release callback that needs
    // to call the viz_release_callback, then we'll need to find another way
    // hold on to the viz_release_callback in the current thread.  The CHECK
    // below guards the current assumption that only the
    // CanvasResourceDispatcher triggers calls to this method for
    // ExternalCanvasResource objects.
    CHECK(!viz_release_callback);
    return;
  }

  resource->SetVizReleaseCallback(std::move(viz_release_callback));

  resource->WaitSyncToken(sync_token);

  if (resource_provider)
    resource_provider->NotifyTexParamsModified(resource.get());

  // TODO(khushalsagar): If multiple readers had access to this resource, losing
  // it once should make sure subsequent releases don't try to recycle this
  // resource.
  if (lost_resource)
    resource->NotifyResourceLost();
  if (resource_provider && !lost_resource && resource->IsRecycleable() &&
      resource->HasOneRef()) {
    resource_provider->RecycleResource(std::move(resource));
  }
}

bool CanvasResource::PrepareTransferableResource(
    viz::TransferableResource* out_resource,
    CanvasResource::ReleaseCallback* out_callback,
    bool needs_verified_synctoken) {
  DCHECK(IsValid());

  DCHECK(out_callback);
  // out_callback is stored in CanvasResourceDispatcher, which never leaves
  // the current thread, so we used a bound argument to hold onto the
  // viz::ReleaseCallback, which is not thread safe.  We will re-attach
  // the callback to this CanvasResource in ReleaseFrameResources(), after
  // references held by other threads have been released.
  *out_callback = WTF::BindOnce(&ReleaseFrameResources, provider_,
                                TakeVizReleaseCallback());

  if (!out_resource)
    return true;
  if (SupportsAcceleratedCompositing()) {
    return UsesClientSharedImage()
               ? PrepareAcceleratedTransferableResourceFromClientSI(
                     out_resource, needs_verified_synctoken)
               : PrepareAcceleratedTransferableResourceWithoutClientSI(
                     out_resource);
  }
  return PrepareUnacceleratedTransferableResource(out_resource);
}

bool CanvasResource::PrepareAcceleratedTransferableResourceFromClientSI(
    viz::TransferableResource* out_resource,
    bool needs_verified_synctoken) {
  TRACE_EVENT0("blink",
               "CanvasResource::PrepareAcceleratedTransferableResource");
  // This method should only be called if this instance actually supports
  // accelerated compositing and uses ClientSharedImage.
  CHECK(SupportsAcceleratedCompositing());
  CHECK(UsesClientSharedImage());

  // Gpu compositing is a prerequisite for compositing an accelerated resource
  DCHECK(SharedGpuContext::IsGpuCompositingEnabled());
  if (!ContextProviderWrapper())
    return false;
  auto client_shared_image = GetClientSharedImage();

  // The SharedImage should exist as long as the ContextProviderWrapper exists.
  CHECK(client_shared_image);

  *out_resource = viz::TransferableResource::MakeGpu(
      client_shared_image->mailbox(), client_shared_image->GetTextureTarget(),
      GetSyncTokenWithOptionalVerification(needs_verified_synctoken), Size(),
      GetSharedImageFormat(), IsOverlayCandidate(),
      viz::TransferableResource::ResourceSource::kCanvas);

  out_resource->color_space = GetColorSpace();

  // When a resource is returned by the display compositor, a sync token is
  // provided to indicate when the compositor's commands using the resource are
  // executed on the GPU thread. However, if the *CPU* is used for raster we
  // need to ensure that the display compositor's GPU-side reads have actually
  // completed before the compositor returns the resource for reuse, as after
  // that point the resource will be written via the CPU without any further
  // synchronization with those GPU-side reads.
  if (!UsesAcceleratedRaster()) {
    out_resource->synchronization_type =
        viz::TransferableResource::SynchronizationType::kGpuCommandsCompleted;
  }

  return true;
}

SkImageInfo CanvasResource::CreateSkImageInfo() const {
  return SkImageInfo::Make(
      SkISize::Make(Size().width(), Size().height()),
      viz::ToClosestSkColorType(/*gpu_compositing=*/true, format_),
      sk_alpha_type_, color_space_.ToSkColorSpace());
}

viz::SharedImageFormat CanvasResource::GetSharedImageFormat() const {
  return format_;
}

gfx::ColorSpace CanvasResource::GetColorSpace() const {
  return color_space_;
}

// CanvasResourceSharedBitmap
//==============================================================================

CanvasResourceSharedBitmap::CanvasResourceSharedBitmap(
    gfx::Size size,
    SkColorType sk_color_type,
    SkAlphaType sk_alpha_type,
    sk_sp<SkColorSpace> sk_color_space,
    base::WeakPtr<CanvasResourceProvider> provider,
    base::WeakPtr<WebGraphicsSharedImageInterfaceProvider>
        shared_image_interface_provider,
    cc::PaintFlags::FilterQuality filter_quality)
    : CanvasResource(
          std::move(provider),
          filter_quality,
          size,
          viz::SkColorTypeToSinglePlaneSharedImageFormat(sk_color_type),
          sk_alpha_type,
          std::move(sk_color_space)) {
  if (!shared_image_interface_provider) {
    return;
  }
  auto* shared_image_interface =
      shared_image_interface_provider->SharedImageInterface();
  if (!shared_image_interface) {
    return;
  }

  auto shared_image_mapping = shared_image_interface->CreateSharedImage(
      {viz::SinglePlaneFormat::kBGRA_8888, Size(), gfx::ColorSpace(),
       gpu::SHARED_IMAGE_USAGE_CPU_WRITE, "CanvasResourceSharedBitmap"});
  shared_image_ = std::move(shared_image_mapping.shared_image);
  shared_mapping_ = std::move(shared_image_mapping.mapping);
  sync_token_ = shared_image_interface->GenVerifiedSyncToken();
}

CanvasResourceSharedBitmap::~CanvasResourceSharedBitmap() {
  if (is_cross_thread()) {
    // Destroyed on wrong thread. This can happen when the thread of origin was
    // torn down, in which case the GPU context owning any underlying resources
    // no longer exists and it is not possible to do cleanup of any GPU
    // context-associated state.
    return;
  }

  if (Provider()) {
    Provider()->OnDestroyResource();
  }
}

bool CanvasResourceSharedBitmap::IsValid() const {
  return shared_mapping_.IsValid();
}

scoped_refptr<StaticBitmapImage> CanvasResourceSharedBitmap::Bitmap() {
  if (!IsValid())
    return nullptr;
  // Construct an SkImage that references the shared memory buffer.
  // The release callback holds a reference to |this| to ensure that the
  // canvas resource that owns the shared memory stays alive at least until
  // the SkImage is destroyed.
  SkImageInfo image_info = CreateSkImageInfo();
  base::span<uint8_t> bytes(shared_mapping_);
  CHECK_GE(bytes.size(), image_info.computeByteSize(image_info.minRowBytes()));
  SkPixmap pixmap(image_info, bytes.data(), image_info.minRowBytes());
  AddRef();
  sk_sp<SkImage> sk_image = SkImages::RasterFromPixmap(
      pixmap,
      [](const void*, SkImages::ReleaseContext resource_to_unref) {
        static_cast<CanvasResourceSharedBitmap*>(resource_to_unref)->Release();
      },
      this);
  auto image = UnacceleratedStaticBitmapImage::Create(sk_image);
  image->SetOriginClean(is_origin_clean_);
  return image;
}

scoped_refptr<CanvasResourceSharedBitmap> CanvasResourceSharedBitmap::Create(
    gfx::Size size,
    SkColorType sk_color_type,
    SkAlphaType sk_alpha_type,
    sk_sp<SkColorSpace> sk_color_space,
    base::WeakPtr<CanvasResourceProvider> provider,
    base::WeakPtr<WebGraphicsSharedImageInterfaceProvider>
        shared_image_interface_provider,
    cc::PaintFlags::FilterQuality filter_quality) {
  auto resource = AdoptRef(new CanvasResourceSharedBitmap(
      size, sk_color_type, sk_alpha_type, std::move(sk_color_space),
      std::move(provider), std::move(shared_image_interface_provider),
      filter_quality));
  return resource->IsValid() ? resource : nullptr;
}

bool CanvasResourceSharedBitmap::PrepareUnacceleratedTransferableResource(
    viz::TransferableResource* out_resource) {
  TRACE_EVENT0(
      "blink",
      "CanvasResourceSharedBitmap::PrepareUnacceleratedTransferableResource");
  if (!shared_image_) {
    return false;
  }

  // For software compositing, the display compositor assumes an N32 format for
  // the resource type and completely ignores the format set on the
  // TransferableResource. Clients are expected to render in N32 format but use
  // RGBA as the tagged format on resources.
  *out_resource = viz::TransferableResource::MakeSoftwareSharedImage(
      shared_image_, sync_token_, Size(), viz::SinglePlaneFormat::kBGRA_8888,
      viz::TransferableResource::ResourceSource::kCanvas);

  out_resource->color_space = GetColorSpace();

  return true;
}

void CanvasResourceSharedBitmap::NotifyResourceLost() {
  // Release our reference to the shared memory mapping since the resource can
  // no longer be safely recycled and this memory is needed for copy-on-write.
  shared_mapping_ = {};
}

void CanvasResourceSharedBitmap::UploadSoftwareRenderingResults(
    SkSurface* sk_surface) {
  auto image = sk_surface->makeImageSnapshot();
  if (!image) {
    return;
  }

  SkImageInfo image_info = CreateSkImageInfo();
  base::span<uint8_t> bytes(shared_mapping_);
  CHECK_GE(bytes.size(), image_info.computeByteSize(image_info.minRowBytes()));
  bool read_pixels_successful = image->readPixels(
      image_info, bytes.data(), image_info.minRowBytes(), 0, 0);
  DCHECK(read_pixels_successful);
}

// CanvasResourceSharedImage
//==============================================================================

CanvasResourceSharedImage::CanvasResourceSharedImage(
    gfx::Size size,
    SkColorType sk_color_type,
    SkAlphaType sk_alpha_type,
    sk_sp<SkColorSpace> sk_color_space,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceProvider> provider,
    cc::PaintFlags::FilterQuality filter_quality,
    bool is_accelerated,
    gpu::SharedImageUsageSet shared_image_usage_flags)
    : CanvasResource(
          std::move(provider),
          filter_quality,
          size,
          viz::SkColorTypeToSinglePlaneSharedImageFormat(sk_color_type),
          sk_alpha_type,
          std::move(sk_color_space)),
      context_provider_wrapper_(std::move(context_provider_wrapper)),
      is_accelerated_(is_accelerated),
      is_overlay_candidate_(
          shared_image_usage_flags.Has(gpu::SHARED_IMAGE_USAGE_SCANOUT)),
      supports_display_compositing_(
          shared_image_usage_flags.Has(gpu::SHARED_IMAGE_USAGE_DISPLAY_READ)),
      use_oop_rasterization_(is_accelerated &&
                             context_provider_wrapper_->ContextProvider()
                                 ->GetCapabilities()
                                 .gpu_rasterization) {
  auto* shared_image_interface =
      context_provider_wrapper_->ContextProvider()->SharedImageInterface();
  DCHECK(shared_image_interface);

  // These SharedImages are both read and written by the raster interface (both
  // occur, for example, when copying canvas resources between canvases).
  // Additionally, these SharedImages can be put into
  // AcceleratedStaticBitmapImages (via Bitmap()) that are then copied into GL
  // textures by WebGL (via AcceleratedStaticBitmapImage::CopyToTexture()).
  // Hence, GLES2_READ usage is necessary regardless of whether raster is over
  // GLES.
  shared_image_usage_flags =
      shared_image_usage_flags | gpu::SHARED_IMAGE_USAGE_RASTER_READ |
      gpu::SHARED_IMAGE_USAGE_RASTER_WRITE | gpu::SHARED_IMAGE_USAGE_GLES2_READ;
  if (use_oop_rasterization_) {
    shared_image_usage_flags =
        shared_image_usage_flags | gpu::SHARED_IMAGE_USAGE_OOP_RASTERIZATION;
  } else {
    // The GLES2_WRITE flag is needed due to raster being over GL.
    shared_image_usage_flags =
        shared_image_usage_flags | gpu::SHARED_IMAGE_USAGE_GLES2_WRITE;
  }

  scoped_refptr<gpu::ClientSharedImage> client_shared_image;
  if (!is_accelerated_) {
    // Ideally we should add SHARED_IMAGE_USAGE_CPU_WRITE to the shared image
    // usage flag here since mailbox will be used for CPU writes
    // by the client. But doing that stops us from using CompoundImagebacking as
    // many backings do not support SHARED_IMAGE_USAGE_CPU_WRITE.
    // TODO(crbug.com/1478238): Add that usage flag back here once the issue is
    // resolved.

    client_shared_image = shared_image_interface->CreateSharedImage(
        {GetSharedImageFormat(), Size(), GetColorSpace(),
         kTopLeft_GrSurfaceOrigin, sk_alpha_type,
         gpu::SharedImageUsageSet(shared_image_usage_flags),
         "CanvasResourceRasterGmb"},
        gpu::kNullSurfaceHandle, gfx::BufferUsage::SCANOUT_CPU_READ_WRITE);
    if (!client_shared_image) {
      return;
    }
  } else {
    client_shared_image = shared_image_interface->CreateSharedImage(
        {GetSharedImageFormat(), Size(), GetColorSpace(),
         kTopLeft_GrSurfaceOrigin, sk_alpha_type,
         gpu::SharedImageUsageSet(shared_image_usage_flags),
         "CanvasResourceRaster"},
        gpu::kNullSurfaceHandle);
    CHECK(client_shared_image);
  }

  // Wait for the mailbox to be ready to be used.
  WaitSyncToken(shared_image_interface->GenUnverifiedSyncToken());

  auto* raster_interface = RasterInterface();
  DCHECK(raster_interface);
  owning_thread_data().client_shared_image = client_shared_image;

  if (use_oop_rasterization_)
    return;

  // For the non-accelerated case, writes are done on the CPU. So we don't need
  // a texture for reads or writes.
  if (!is_accelerated_)
    return;

  owning_thread_data().texture_id_for_read_access =
      raster_interface->CreateAndConsumeForGpuRaster(client_shared_image);

  if (shared_image_usage_flags.Has(
          gpu::SHARED_IMAGE_USAGE_CONCURRENT_READ_WRITE)) {
    owning_thread_data().texture_id_for_write_access =
        raster_interface->CreateAndConsumeForGpuRaster(client_shared_image);
  } else {
    owning_thread_data().texture_id_for_write_access =
        owning_thread_data().texture_id_for_read_access;
  }
}

scoped_refptr<CanvasResourceSharedImage> CanvasResourceSharedImage::Create(
    gfx::Size size,
    SkColorType sk_color_type,
    SkAlphaType sk_alpha_type,
    sk_sp<SkColorSpace> sk_color_space,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceProvider> provider,
    cc::PaintFlags::FilterQuality filter_quality,
    bool is_accelerated,
    gpu::SharedImageUsageSet shared_image_usage_flags) {
  TRACE_EVENT0("blink", "CanvasResourceSharedImage::Create");
  auto resource = base::AdoptRef(new CanvasResourceSharedImage(
      size, sk_color_type, sk_alpha_type, std::move(sk_color_space),
      std::move(context_provider_wrapper), std::move(provider), filter_quality,
      is_accelerated, shared_image_usage_flags));
  return resource->IsValid() ? resource : nullptr;
}

bool CanvasResourceSharedImage::IsValid() const {
  return !!owning_thread_data_.client_shared_image;
}

void CanvasResourceSharedImage::BeginWriteAccess() {
  RasterInterface()->BeginSharedImageAccessDirectCHROMIUM(
      GetTextureIdForWriteAccess(),
      GL_SHARED_IMAGE_ACCESS_MODE_READWRITE_CHROMIUM);
}

void CanvasResourceSharedImage::EndWriteAccess() {
  RasterInterface()->EndSharedImageAccessDirectCHROMIUM(
      GetTextureIdForWriteAccess());
}

GrBackendTexture CanvasResourceSharedImage::CreateGrTexture() const {
  GrGLTextureInfo texture_info = {};
  texture_info.fID = GetTextureIdForWriteAccess();
  texture_info.fTarget = GetClientSharedImage()->GetTextureTarget();
  texture_info.fFormat =
      context_provider_wrapper_->ContextProvider()->GetGrGLTextureFormat(
          GetSharedImageFormat());
  return GrBackendTextures::MakeGL(Size().width(), Size().height(),
                                   skgpu::Mipmapped::kNo, texture_info);
}

CanvasResourceSharedImage::~CanvasResourceSharedImage() {
  if (is_cross_thread()) {
    // Destroyed on wrong thread. This can happen when the thread of origin was
    // torn down, in which case the GPU context owning any underlying resources
    // no longer exists and it is not possible to do cleanup of any GPU
    // context-associated state.
    return;
  }

  if (Provider()) {
    Provider()->OnDestroyResource();
  }

  // The context deletes all shared images on destruction which means no
  // cleanup is needed if the context was lost.
  if (ContextProviderWrapper() && IsValid()) {
    auto* raster_interface = RasterInterface();
    auto* shared_image_interface =
        ContextProviderWrapper()->ContextProvider()->SharedImageInterface();
    if (raster_interface && shared_image_interface) {
      gpu::SyncToken shared_image_sync_token;
      raster_interface->GenUnverifiedSyncTokenCHROMIUM(
          shared_image_sync_token.GetData());
      owning_thread_data().client_shared_image->UpdateDestructionSyncToken(
          shared_image_sync_token);
    }
    if (raster_interface) {
      if (owning_thread_data().texture_id_for_read_access) {
        raster_interface->DeleteGpuRasterTexture(
            owning_thread_data().texture_id_for_read_access);
      }
      if (owning_thread_data().texture_id_for_write_access &&
          owning_thread_data().texture_id_for_write_access !=
              owning_thread_data().texture_id_for_read_access) {
        raster_interface->DeleteGpuRasterTexture(
            owning_thread_data().texture_id_for_write_access);
      }
    }
  }

  owning_thread_data().texture_id_for_read_access = 0u;
  owning_thread_data().texture_id_for_write_access = 0u;
}

void CanvasResourceSharedImage::WillDraw() {
  DCHECK(!is_cross_thread())
      << "Write access is only allowed on the owning thread";

  // Sync token for software mode is generated from SharedImageInterface each
  // time the GMB is updated.
  if (!is_accelerated_)
    return;

  owning_thread_data().mailbox_needs_new_sync_token = true;
}

// static
void CanvasResourceSharedImage::OnBitmapImageDestroyed(
    scoped_refptr<CanvasResourceSharedImage> resource,
    bool has_read_ref_on_texture,
    const gpu::SyncToken& sync_token,
    bool is_lost) {
  DCHECK(!resource->is_cross_thread());

  if (has_read_ref_on_texture) {
    DCHECK(!resource->use_oop_rasterization_);
    DCHECK_GT(resource->owning_thread_data().bitmap_image_read_refs, 0u);

    resource->owning_thread_data().bitmap_image_read_refs--;
    if (resource->owning_thread_data().bitmap_image_read_refs == 0u &&
        resource->RasterInterface()) {
      resource->RasterInterface()->EndSharedImageAccessDirectCHROMIUM(
          resource->owning_thread_data().texture_id_for_read_access);
    }
  }

  auto weak_provider = resource->WeakProvider();
  ReleaseFrameResources(std::move(weak_provider), viz::ReleaseCallback(),
                        std::move(resource), sync_token, is_lost);
}

void CanvasResourceSharedImage::Transfer() {
  if (is_cross_thread() || !ContextProviderWrapper())
    return;

  // TODO(khushalsagar): This is for consistency with MailboxTextureHolder
  // transfer path. It's unclear why the verification can not be deferred until
  // the resource needs to be transferred cross-process.
  GetSyncTokenWithOptionalVerification(true);
}

scoped_refptr<StaticBitmapImage> CanvasResourceSharedImage::Bitmap() {
  TRACE_EVENT0("blink", "CanvasResourceSharedImage::Bitmap");

  SkImageInfo image_info = CreateSkImageInfo();
  if (!is_accelerated_) {
    std::unique_ptr<gpu::ClientSharedImage::ScopedMapping> mapping =
        GetClientSharedImage()->Map();
    if (!mapping) {
      LOG(ERROR) << "MapSharedImage Failed.";
      return nullptr;
    }
    auto sk_image = SkImages::RasterFromPixmapCopy(
        mapping->GetSkPixmapForPlane(0, CreateSkImageInfo()));

    // Unmap the underlying buffer.
    mapping.reset();
    return sk_image ? UnacceleratedStaticBitmapImage::Create(sk_image)
                    : nullptr;
  }

  // In order to avoid creating multiple representations for this shared image
  // on the same context, the AcceleratedStaticBitmapImage uses the texture id
  // of the resource here. We keep a count of pending shared image releases to
  // correctly scope the read lock for this texture.
  // If this resource is accessed across threads, or the
  // AcceleratedStaticBitmapImage is accessed on a different thread after being
  // created here, the image will create a new representation from the mailbox
  // rather than referring to the shared image's texture ID if it was provided
  // below.
  const bool has_read_ref_on_texture =
      !is_cross_thread() && !use_oop_rasterization_;
  GLuint texture_id_for_image = 0u;
  if (has_read_ref_on_texture) {
    texture_id_for_image = owning_thread_data().texture_id_for_read_access;
    owning_thread_data().bitmap_image_read_refs++;
    if (owning_thread_data().bitmap_image_read_refs == 1u &&
        RasterInterface()) {
      RasterInterface()->BeginSharedImageAccessDirectCHROMIUM(
          texture_id_for_image, GL_SHARED_IMAGE_ACCESS_MODE_READ_CHROMIUM);
    }
  }

  // The |release_callback| keeps a ref on this resource to ensure the backing
  // shared image is kept alive until the lifetime of the image.
  // Note that the code in CanvasResourceProvider::RecycleResource also uses the
  // ref-count on the resource as a proxy for a read lock to allow recycling the
  // resource once all refs have been released.
  auto release_callback = base::BindOnce(
      &OnBitmapImageDestroyed, scoped_refptr<CanvasResourceSharedImage>(this),
      has_read_ref_on_texture);

  scoped_refptr<StaticBitmapImage> image;
  auto client_shared_image = GetClientSharedImage();
  uint32_t texture_target = client_shared_image->GetTextureTarget();

  CHECK_EQ(client_shared_image->surface_origin(), kTopLeft_GrSurfaceOrigin);
  // If its cross thread, then the sync token was already verified.
  image = AcceleratedStaticBitmapImage::CreateFromCanvasSharedImage(
      std::move(client_shared_image), GetSyncToken(), texture_id_for_image,
      image_info, texture_target, /*is_origin_top_left=*/true,
      context_provider_wrapper_, owning_thread_ref_, owning_thread_task_runner_,
      std::move(release_callback), supports_display_compositing_,
      is_overlay_candidate_);

  DCHECK(image);
  return image;
}

void CanvasResourceSharedImage::UploadSoftwareRenderingResults(
    SkSurface* sk_surface) {
  DCHECK(!is_cross_thread());

  const sk_sp<SkImage>& image = sk_surface->makeImageSnapshot();

  if (!ContextProviderWrapper()) {
    return;
  }
  auto* sii =
      ContextProviderWrapper()->ContextProvider()->SharedImageInterface();
  std::unique_ptr<gpu::ClientSharedImage::ScopedMapping> mapping =
      GetClientSharedImage()->Map();
  if (!mapping) {
    LOG(ERROR) << "MapSharedImage failed.";
    return;
  }

  auto surface = SkSurfaces::WrapPixels(
      mapping->GetSkPixmapForPlane(0, CreateSkImageInfo()));
  SkPixmap pixmap;
  image->peekPixels(&pixmap);
  surface->writePixels(pixmap, 0, 0);

  // Unmap the underlying buffer.
  mapping.reset();
  sii->UpdateSharedImage(gpu::SyncToken(), GetClientSharedImage()->mailbox());
  owning_thread_data().sync_token = sii->GenUnverifiedSyncToken();
}

scoped_refptr<gpu::ClientSharedImage>
CanvasResourceSharedImage::GetClientSharedImage() {
  CHECK(owning_thread_data_.client_shared_image);
  return owning_thread_data_.client_shared_image;
}

const scoped_refptr<gpu::ClientSharedImage>&
CanvasResourceSharedImage::GetClientSharedImage() const {
  CHECK(owning_thread_data_.client_shared_image);
  return owning_thread_data_.client_shared_image;
}

const gpu::SyncToken
CanvasResourceSharedImage::GetSyncTokenWithOptionalVerification(
    bool needs_verified_token) {
  if (is_cross_thread()) {
    // Sync token should be generated at Transfer time, which must always be
    // called before cross-thread usage. And since we don't allow writes on
    // another thread, the sync token generated at Transfer time shouldn't
    // have been invalidated.
    DCHECK(!mailbox_needs_new_sync_token());
    DCHECK(sync_token().verified_flush());

    return sync_token();
  }

  if (mailbox_needs_new_sync_token()) {
    auto* raster_interface = RasterInterface();
    DCHECK(raster_interface);  // caller should already have early exited if
                               // !raster_interface.
    raster_interface->GenUnverifiedSyncTokenCHROMIUM(
        owning_thread_data().sync_token.GetData());
    owning_thread_data().mailbox_needs_new_sync_token = false;
  }

  if (needs_verified_token &&
      !owning_thread_data().sync_token.verified_flush()) {
    int8_t* token_data = owning_thread_data().sync_token.GetData();
    auto* raster_interface = RasterInterface();
    raster_interface->ShallowFlushCHROMIUM();
    raster_interface->VerifySyncTokensCHROMIUM(&token_data, 1);
    owning_thread_data().sync_token.SetVerifyFlush();
  }

  return sync_token();
}

void CanvasResourceSharedImage::NotifyResourceLost() {
  owning_thread_data().is_lost = true;

  if (WeakProvider())
    Provider()->NotifyTexParamsModified(this);
}

base::WeakPtr<WebGraphicsContext3DProviderWrapper>
CanvasResourceSharedImage::ContextProviderWrapper() const {
  DCHECK(!is_cross_thread());
  return context_provider_wrapper_;
}

void CanvasResourceSharedImage::OnMemoryDump(
    base::trace_event::ProcessMemoryDump* pmd,
    const std::string& parent_path,
    size_t bytes_per_pixel) const {
  if (!IsValid())
    return;

  std::string dump_name =
      base::StringPrintf("%s/CanvasResource_0x%" PRIXPTR, parent_path.c_str(),
                         reinterpret_cast<uintptr_t>(this));
  auto* dump = pmd->CreateAllocatorDump(dump_name);
  size_t memory_size = Size().height() * Size().width() * bytes_per_pixel;
  dump->AddScalar(base::trace_event::MemoryAllocatorDump::kNameSize,
                  base::trace_event::MemoryAllocatorDump::kUnitsBytes,
                  memory_size);

  auto guid = GetClientSharedImage()->GetGUIDForTracing();
  pmd->CreateSharedGlobalAllocatorDump(guid);
  pmd->AddOwnershipEdge(dump->guid(), guid,
                        static_cast<int>(gpu::TracingImportance::kClientOwner));
}

// ExternalCanvasResource
//==============================================================================
scoped_refptr<ExternalCanvasResource> ExternalCanvasResource::Create(
    scoped_refptr<gpu::ClientSharedImage> client_si,
    const viz::TransferableResource& transferable_resource,
    viz::ReleaseCallback release_callback,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceProvider> provider,
    cc::PaintFlags::FilterQuality filter_quality) {
  TRACE_EVENT0("blink", "ExternalCanvasResource::Create");
  CHECK(client_si);
  CHECK(client_si->mailbox() == transferable_resource.mailbox());
  auto resource = AdoptRef(new ExternalCanvasResource(
      std::move(client_si), transferable_resource, std::move(release_callback),
      std::move(context_provider_wrapper), std::move(provider),
      filter_quality));
  return resource->IsValid() ? resource : nullptr;
}

ExternalCanvasResource::~ExternalCanvasResource() {
  if (is_cross_thread()) {
    // Destroyed on wrong thread. This can happen when the thread of origin was
    // torn down, in which case the GPU context owning any underlying resources
    // no longer exists and it is not possible to do cleanup of any GPU
    // context-associated state.
    return;
  }

  if (Provider()) {
    Provider()->OnDestroyResource();
  }

  if (release_callback_) {
    std::move(release_callback_).Run(GetSyncToken(), resource_is_lost_);
  }
}

bool ExternalCanvasResource::IsValid() const {
  // On same thread we need to make sure context was not dropped, but
  // in the cross-thread case, checking a WeakPtr in not thread safe, not
  // to mention that we will use a shared context rather than the context
  // of origin to access the resource. In that case we will find out
  // whether the resource was dropped later, when we attempt to access the
  // mailbox.
  return is_cross_thread() || context_provider_wrapper_;
}

scoped_refptr<StaticBitmapImage> ExternalCanvasResource::Bitmap() {
  TRACE_EVENT0("blink", "ExternalCanvasResource::Bitmap");
  if (!IsValid())
    return nullptr;

  // The |release_callback| keeps a ref on this resource to ensure the backing
  // shared image is kept alive until the lifetime of the image.
  auto release_callback = base::BindOnce(
      [](scoped_refptr<ExternalCanvasResource> resource,
         const gpu::SyncToken& sync_token, bool is_lost) {
        // Do nothing but hold onto the refptr.
      },
      base::RetainedRef(this));

  const bool is_origin_top_left =
      client_si_->surface_origin() == kTopLeft_GrSurfaceOrigin;
  return AcceleratedStaticBitmapImage::CreateFromCanvasSharedImage(
      client_si_, GetSyncToken(), /*shared_image_texture_id=*/0u,
      CreateSkImageInfo(), transferable_resource_.texture_target(),
      is_origin_top_left, context_provider_wrapper_, owning_thread_ref_,
      owning_thread_task_runner_, std::move(release_callback),
      /*supports_display_compositing=*/true,
      transferable_resource_.is_overlay_candidate);
}

const gpu::SyncToken
ExternalCanvasResource::GetSyncTokenWithOptionalVerification(
    bool needs_verified_token) {
  GenOrFlushSyncToken();
  return transferable_resource_.sync_token();
}

void ExternalCanvasResource::GenOrFlushSyncToken() {
  TRACE_EVENT0("blink", "ExternalCanvasResource::GenOrFlushSyncToken");
  auto& sync_token = transferable_resource_.mutable_sync_token();
  // This method is expected to be used both in WebGL and WebGPU, that's why it
  // uses InterfaceBase.
  if (!sync_token.HasData()) {
    auto* interface = InterfaceBase();
    if (interface)
      interface->GenSyncTokenCHROMIUM(sync_token.GetData());
  } else if (!sync_token.verified_flush()) {
    // The offscreencanvas usage needs the sync_token to be verified in order to
    // be able to use it by the compositor.
    int8_t* token_data = sync_token.GetData();
    auto* interface = InterfaceBase();
    DCHECK(interface);
    interface->ShallowFlushCHROMIUM();
    interface->VerifySyncTokensCHROMIUM(&token_data, 1);
    sync_token.SetVerifyFlush();
  }
}

base::WeakPtr<WebGraphicsContext3DProviderWrapper>
ExternalCanvasResource::ContextProviderWrapper() const {
  // The context provider is not thread-safe, nor is the WeakPtr that holds it.
  DCHECK(!is_cross_thread());
  return context_provider_wrapper_;
}

bool ExternalCanvasResource::
    PrepareAcceleratedTransferableResourceWithoutClientSI(
        viz::TransferableResource* out_resource) {
  TRACE_EVENT0(
      "blink",
      "ExternalCanvasResource::PrepareAcceleratedTransferableResource");
  GenOrFlushSyncToken();
  *out_resource = transferable_resource_;
  return true;
}

ExternalCanvasResource::ExternalCanvasResource(
    scoped_refptr<gpu::ClientSharedImage> client_si,
    const viz::TransferableResource& transferable_resource,
    viz::ReleaseCallback out_callback,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceProvider> provider,
    cc::PaintFlags::FilterQuality filter_quality)
    : CanvasResource(std::move(provider),
                     filter_quality,
                     transferable_resource.size,
                     transferable_resource.format,
                     kPremul_SkAlphaType,
                     transferable_resource.color_space.ToSkColorSpace()),
      client_si_(std::move(client_si)),
      context_provider_wrapper_(std::move(context_provider_wrapper)),
      transferable_resource_(transferable_resource),
      release_callback_(std::move(out_callback)) {
  CHECK(client_si_);
  CHECK(client_si_->mailbox() == transferable_resource_.mailbox());
  DCHECK(!release_callback_ || transferable_resource_.sync_token().HasData());
}

// CanvasResourceSwapChain
//==============================================================================
scoped_refptr<CanvasResourceSwapChain> CanvasResourceSwapChain::Create(
    gfx::Size size,
    SkColorType sk_color_type,
    SkAlphaType sk_alpha_type,
    sk_sp<SkColorSpace> sk_color_space,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceProvider> provider,
    cc::PaintFlags::FilterQuality filter_quality) {
  TRACE_EVENT0("blink", "CanvasResourceSwapChain::Create");
  auto resource = AdoptRef(new CanvasResourceSwapChain(
      size, sk_color_type, sk_alpha_type, std::move(sk_color_space),
      std::move(context_provider_wrapper), std::move(provider),
      filter_quality));
  return resource->IsValid() ? resource : nullptr;
}

CanvasResourceSwapChain::~CanvasResourceSwapChain() {
  if (is_cross_thread()) {
    // Destroyed on wrong thread. This can happen when the thread of origin was
    // torn down, in which case the GPU context owning any underlying resources
    // no longer exists and it is not possible to do cleanup of any GPU
    // context-associated state.
    return;
  }

  if (Provider()) {
    Provider()->OnDestroyResource();
  }

  // The context deletes all shared images on destruction which means no
  // cleanup is needed if the context was lost.
  if (!context_provider_wrapper_) {
    return;
  }

  if (!use_oop_rasterization_) {
    auto* raster_interface =
        context_provider_wrapper_->ContextProvider()->RasterInterface();
    DCHECK(raster_interface);
    raster_interface->EndSharedImageAccessDirectCHROMIUM(
        back_buffer_texture_id_);
    raster_interface->DeleteGpuRasterTexture(back_buffer_texture_id_);
  }

  // No synchronization is needed here because the GL SharedImageRepresentation
  // will keep the backing alive on the service until the textures are deleted.
  front_buffer_shared_image_->UpdateDestructionSyncToken(gpu::SyncToken());
  back_buffer_shared_image_->UpdateDestructionSyncToken(gpu::SyncToken());
}

bool CanvasResourceSwapChain::IsValid() const {
  return !!context_provider_wrapper_;
}

scoped_refptr<StaticBitmapImage> CanvasResourceSwapChain::Bitmap() {
  SkImageInfo image_info = CreateSkImageInfo();

  // It's safe to share the back buffer texture id if we're on the same thread
  // since the |release_callback| ensures this resource will be alive.
  GLuint shared_texture_id = !is_cross_thread() ? back_buffer_texture_id_ : 0u;

  // The |release_callback| keeps a ref on this resource to ensure the backing
  // shared image is kept alive until the lifetime of the image.
  auto release_callback = base::BindOnce(
      [](scoped_refptr<CanvasResourceSwapChain>, const gpu::SyncToken&, bool) {
        // Do nothing but hold onto the refptr.
      },
      base::RetainedRef(this));

  return AcceleratedStaticBitmapImage::CreateFromCanvasSharedImage(
      back_buffer_shared_image_, GetSyncToken(), shared_texture_id, image_info,
      back_buffer_shared_image_->GetTextureTarget(),
      true /*is_origin_top_left*/, context_provider_wrapper_,
      owning_thread_ref_, owning_thread_task_runner_,
      std::move(release_callback), /*supports_display_compositing=*/true,
      /*is_overlay_candidate=*/true);
}

scoped_refptr<gpu::ClientSharedImage>
CanvasResourceSwapChain::GetClientSharedImage() {
  return front_buffer_shared_image_;
}

const gpu::SyncToken
CanvasResourceSwapChain::GetSyncTokenWithOptionalVerification(
    bool needs_verified_token) {
  DCHECK(sync_token_.verified_flush());
  return sync_token_;
}

void CanvasResourceSwapChain::PresentSwapChain() {
  DCHECK(!is_cross_thread());
  DCHECK(context_provider_wrapper_);
  TRACE_EVENT0("blink", "CanvasResourceSwapChain::PresentSwapChain");

  auto* raster_interface =
      context_provider_wrapper_->ContextProvider()->RasterInterface();
  DCHECK(raster_interface);

  auto* sii =
      context_provider_wrapper_->ContextProvider()->SharedImageInterface();
  DCHECK(sii);

  // Synchronize presentation and rendering.
  raster_interface->GenUnverifiedSyncTokenCHROMIUM(sync_token_.GetData());
  sii->PresentSwapChain(sync_token_, back_buffer_shared_image_->mailbox());
  // This only gets called via the CanvasResourceDispatcher export path so a
  // verified sync token will be needed ultimately.
  sync_token_ = sii->GenVerifiedSyncToken();
  raster_interface->WaitSyncTokenCHROMIUM(sync_token_.GetData());

  // Relinquish shared image access before copy when using legacy GL raster.
  if (!use_oop_rasterization_) {
    raster_interface->EndSharedImageAccessDirectCHROMIUM(
        back_buffer_texture_id_);
  }
  // PresentSwapChain() flips the front and back buffers, but the mailboxes
  // still refer to the current front and back buffer after present.  So the
  // front buffer contains the content we just rendered, and it needs to be
  // copied into the back buffer to support a retained mode like canvas expects.
  // The wait sync token ensure that the present executes before we do the copy.
  // Don't generate sync token after the copy so that it's not on critical path.
  raster_interface->CopySharedImage(front_buffer_shared_image_->mailbox(),
                                    back_buffer_shared_image_->mailbox(), 0, 0,
                                    0, 0, Size().width(), Size().height());
  // Restore shared image access after copy when using legacy GL raster.
  if (!use_oop_rasterization_) {
    raster_interface->BeginSharedImageAccessDirectCHROMIUM(
        back_buffer_texture_id_,
        GL_SHARED_IMAGE_ACCESS_MODE_READWRITE_CHROMIUM);
  }
}

base::WeakPtr<WebGraphicsContext3DProviderWrapper>
CanvasResourceSwapChain::ContextProviderWrapper() const {
  return context_provider_wrapper_;
}

CanvasResourceSwapChain::CanvasResourceSwapChain(
    gfx::Size size,
    SkColorType sk_color_type,
    SkAlphaType sk_alpha_type,
    sk_sp<SkColorSpace> sk_color_space,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceProvider> provider,
    cc::PaintFlags::FilterQuality filter_quality)
    : CanvasResource(
          std::move(provider),
          filter_quality,
          size,
          viz::SkColorTypeToSinglePlaneSharedImageFormat(sk_color_type),
          sk_alpha_type,
          std::move(sk_color_space)),
      context_provider_wrapper_(std::move(context_provider_wrapper)),
      use_oop_rasterization_(context_provider_wrapper_->ContextProvider()
                                 ->GetCapabilities()
                                 .gpu_rasterization) {
  if (!context_provider_wrapper_)
    return;

  // These SharedImages are both read and written by the raster interface (both
  // occur, for example, when copying canvas resources between canvases).
  // Additionally, these SharedImages can be put into
  // AcceleratedStaticBitmapImages (via Bitmap()) that are then copied into GL
  // textures by WebGL (via AcceleratedStaticBitmapImage::CopyToTexture()).
  // Hence, GLES2_READ usage is necessary regardless of whether raster is over
  // GLES.
  gpu::SharedImageUsageSet usage = gpu::SHARED_IMAGE_USAGE_DISPLAY_READ |
                                   gpu::SHARED_IMAGE_USAGE_GLES2_READ |
                                   gpu::SHARED_IMAGE_USAGE_SCANOUT |
                                   gpu::SHARED_IMAGE_USAGE_RASTER_READ |
                                   gpu::SHARED_IMAGE_USAGE_RASTER_WRITE;
  if (use_oop_rasterization_) {
    usage = usage | gpu::SHARED_IMAGE_USAGE_OOP_RASTERIZATION;
  } else {
    // The GLES2_WRITE flag is needed due to raster being over GL.
    usage = usage | gpu::SHARED_IMAGE_USAGE_GLES2_WRITE;
  }

  auto* sii =
      context_provider_wrapper_->ContextProvider()->SharedImageInterface();
  DCHECK(sii);
  gpu::SharedImageInterface::SwapChainSharedImages shared_images =
      sii->CreateSwapChain(GetSharedImageFormat(), Size(), GetColorSpace(),
                           kTopLeft_GrSurfaceOrigin, kPremul_SkAlphaType,
                           usage);
  CHECK(shared_images.back_buffer);
  CHECK(shared_images.front_buffer);
  back_buffer_shared_image_ = std::move(shared_images.back_buffer);
  front_buffer_shared_image_ = std::move(shared_images.front_buffer);
  sync_token_ = sii->GenVerifiedSyncToken();

  // Wait for the mailboxes to be ready to be used.
  auto* raster_interface =
      context_provider_wrapper_->ContextProvider()->RasterInterface();
  DCHECK(raster_interface);
  raster_interface->WaitSyncTokenCHROMIUM(sync_token_.GetData());

  // In OOPR mode we use mailboxes directly. We early out here because
  // we don't need a texture id, as access is managed in the gpu process.
  if (use_oop_rasterization_)
    return;

  back_buffer_texture_id_ = raster_interface->CreateAndConsumeForGpuRaster(
      back_buffer_shared_image_->mailbox());
  raster_interface->BeginSharedImageAccessDirectCHROMIUM(
      back_buffer_texture_id_, GL_SHARED_IMAGE_ACCESS_MODE_READWRITE_CHROMIUM);
}

}  // namespace blink
```