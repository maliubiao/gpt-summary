Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understanding the Goal:** The request asks for a breakdown of the functionality of `CanvasRenderingContextHost.cc`, its relationship to web technologies, potential user/developer errors, and how a user might trigger its execution.

2. **Initial Code Scan and Keyword Identification:**  A quick read-through reveals key terms and concepts:
    * `CanvasRenderingContextHost`:  The central class.
    * `CanvasRenderingContext`: Likely the JavaScript interface counterpart.
    * `WebGL`, `WebGPU`, `RenderingContext2D`, `ImageBitmapRenderingContext`:  Different canvas rendering APIs.
    * `CanvasResourceProvider`:  Handles the underlying storage and rendering.
    * `SharedImage`, `SharedBitmap`, `Bitmap`, `SwapChain`:  Different types of backing stores.
    * `UMA_HISTOGRAM_*`:  Metrics and telemetry.
    * `gfx::Size`: Represents dimensions.
    * `Skia`:  The graphics library used.
    * `Commit`, `Paintable`, `InitializeForRecording`:  Lifecycle and rendering related methods.
    * `IdentifiabilityInputDigest`:  Privacy-related functionality.
    * `PageVisibilityChanged`: Handles visibility changes.

3. **Deconstructing the Class Structure and Purpose:**
    * The constructor takes a `HostType` (likely distinguishing between `<canvas>` and OffscreenCanvas) and a `gfx::Size`. This suggests it's responsible for managing the underlying resources for a canvas element of a specific type and size.
    * The `RecordCanvasSizeToUMA` method indicates this class tracks canvas size for telemetry purposes.
    * The `CreateTransparentImage` method suggests it can create blank images.

4. **Analyzing Key Methods and Their Functionality:**  This is where the core understanding forms. For each important method, ask: *What does it do? Why is it needed? How does it relate to the canvas API?*

    * **`CreateCanvasResourceProvider*()` methods:** These are crucial. They handle the complex logic of choosing the best backing store (`CanvasResourceProvider`) based on:
        * The rendering context type (WebGL, 2D, WebGPU).
        * System capabilities (GPU compositing, shared memory).
        * Enabled features (low latency, image chromium).
        * Performance hints.
        * This directly connects to the canvas element's ability to render content, and performance implications.

    * **`IsWebGL()`, `IsWebGPU()`, `IsRenderingContext2D()`, `IsImageBitmapRenderingContext()`:** These methods check the type of rendering context, which is fundamental to how the canvas is used.

    * **`Commit()`:**  Marked as `NOTIMPLEMENTED`. This suggests this *host* class might delegate the actual drawing commands.

    * **`IsPaintable()`:** Determines if the canvas has content to draw. This relates to whether the canvas will be rendered on the screen.

    * **`InitializeForRecording()`:**  Deals with preparing the canvas for recording drawing operations (likely for the rendering pipeline).

    * **`IdentifiabilityInputDigest()`:**  This clearly relates to privacy and fingerprinting concerns related to canvas usage. It combines information about the context and its operations.

    * **`PageVisibilityChanged()`:**  Manages resource allocation and cleanup based on whether the page is visible. This is an optimization to save resources when the canvas is not visible.

5. **Connecting to Web Technologies (JavaScript, HTML, CSS):**

    * **HTML:** The `<canvas>` element in HTML directly instantiates this class (or a related one). OffscreenCanvas also uses this. The `HostType` enum reflects this.
    * **JavaScript:** The methods on the JavaScript `CanvasRenderingContext2D`, `WebGLRenderingContext`, and `GPUCanvasContext` interfaces directly map to actions that eventually involve this C++ code. For example, a `drawImage()` call in JavaScript will lead to operations managed by the `CanvasResourceProvider`.
    * **CSS:** While CSS doesn't directly *control* the content drawn on the canvas, it affects the size and visibility of the `<canvas>` element. The `gfx::Size` passed to the constructor reflects the CSS dimensions. `PageVisibilityChanged` is triggered by browser visibility changes, which can be influenced by CSS.

6. **Identifying User/Developer Errors:** Focus on the points where incorrect usage or assumptions could lead to problems:

    * **Large Canvas Sizes:** The code includes UMA metrics on canvas size, suggesting performance can be affected by very large canvases. A user creating an excessively large canvas without considering performance implications is an error.
    * **Incorrect Context Type:** Trying to call WebGL methods on a 2D context (or vice versa) is a common error. The type checking methods highlight this.
    * **Resource Limits:**  The resource provider creation logic deals with system limitations. While not directly a user error, developers might encounter issues if they don't handle potential resource allocation failures gracefully.
    * **Asynchronous Operations:**  While not explicitly in *this* code snippet, canvas operations can be asynchronous (e.g., image loading). Incorrectly handling these can lead to drawing errors.

7. **Tracing User Actions:** Think about the chain of events:

    * User opens a webpage.
    * The HTML parser encounters a `<canvas>` tag (or JavaScript creates an `OffscreenCanvas`).
    * Blink creates a `HTMLCanvasElement` (or `OffscreenCanvas`) object.
    * A JavaScript call like `canvas.getContext('2d')` or `canvas.getContext('webgl')` is made.
    * This triggers the creation of a `CanvasRenderingContext` object (the JavaScript interface).
    * This `CanvasRenderingContext` is associated with a `CanvasRenderingContextHost` (the C++ implementation).
    * Drawing commands in JavaScript (e.g., `fillRect()`, `drawImage()`) are translated into operations on the `CanvasRenderingContextHost` and its `CanvasResourceProvider`.
    * The browser's rendering engine uses the `CanvasResourceProvider` to draw the canvas content on the screen.

8. **Logical Reasoning and Assumptions:**  When explaining the code, sometimes you need to infer the *why* behind certain choices:

    * The complex logic in `CreateCanvasResourceProvider*` suggests performance is a major concern, and the browser tries to pick the most efficient backing store.
    * The privacy-related code indicates that canvas can be used for fingerprinting, and the browser is taking steps to mitigate this.
    * The `PageVisibilityChanged` logic implies resource management is important.

9. **Structuring the Answer:**  Organize the information logically using headings and bullet points for clarity. Start with a high-level summary and then delve into specifics. Use examples to illustrate the connections to web technologies and potential errors.

10. **Refinement and Review:** After drafting the answer, reread it to ensure accuracy, clarity, and completeness. Check that the examples are relevant and easy to understand. Make sure all aspects of the prompt have been addressed.

By following this thought process, combining code analysis with an understanding of web technologies and common development practices, we can effectively break down the functionality of a complex piece of code like `CanvasRenderingContextHost.cc`.
好的，我们来详细分析一下 `blink/renderer/core/html/canvas/canvas_rendering_context_host.cc` 文件的功能。

**文件功能概述**

`CanvasRenderingContextHost.cc` 文件是 Chromium Blink 渲染引擎中，负责管理 Canvas 渲染上下文宿主（host）的类 `CanvasRenderingContextHost` 的实现。它的核心职责是：

1. **管理 Canvas 的底层资源:**  它持有并管理与 Canvas 关联的图形资源，例如像素缓冲区（backing store）。
2. **作为 CanvasRenderingContext 的 C++ 端代理:** 它接收来自 JavaScript `CanvasRenderingContext2D`, `WebGLRenderingContext`, `OffscreenCanvasRenderingContext2D` 等不同 Canvas 上下文的请求，并协调底层的资源操作。
3. **根据不同的 Canvas 类型和系统能力选择合适的资源提供器 (CanvasResourceProvider):**  它会根据是 2D Canvas, WebGL Canvas 还是 WebGPU Canvas，以及 GPU 是否可用，低延迟模式是否开启等因素，选择最佳的 `CanvasResourceProvider` 来管理 Canvas 的像素数据。这包括使用共享内存、GPU 纹理等技术。
4. **处理 Canvas 相关的生命周期事件:** 例如，当页面可见性改变时，它会通知渲染上下文并可能释放资源。
5. **参与 Canvas 内容的绘制和合成:** 它提供的资源会被用于将 Canvas 内容绘制到屏幕上。
6. **提供 Canvas 相关的性能和隐私指标的收集:**  通过 UMA 宏记录 Canvas 的大小等信息，并参与 Canvas 指纹识别的隐私保护工作。

**与 Javascript, HTML, CSS 的关系及举例说明**

`CanvasRenderingContextHost` 是 Canvas API 在 C++ 层的核心实现，它与 JavaScript, HTML 紧密相关，CSS 则间接影响 Canvas 的行为。

* **HTML (`<canvas>` 元素):**
    * **关系:**  当 HTML 中存在 `<canvas>` 元素时，Blink 渲染引擎会创建对应的 `HTMLCanvasElement` 对象。这个对象会关联一个 `CanvasRenderingContextHost` 实例。
    * **举例:**  当你在 HTML 中写下 `<canvas id="myCanvas" width="200" height="100"></canvas>` 时，就会在 C++ 层创建一个 `CanvasRenderingContextHost` 对象，其初始大小为 200x100。`host_type_` 会被设置为 `HostType::kCanvasHost`。

* **Javascript (Canvas API):**
    * **关系:** JavaScript 代码通过 `HTMLCanvasElement` 的 `getContext()` 方法获取不同的渲染上下文（如 `CanvasRenderingContext2D` 或 `WebGLRenderingContext`）。这些 JavaScript 上下文对象在底层会与 `CanvasRenderingContextHost` 交互，调用其方法来执行绘图操作、获取图像数据等。
    * **举例 (2D Context):**
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = 'red';
        ctx.fillRect(10, 10, 50, 50);
        ```
        这段 JavaScript 代码中的 `fillRect()` 调用最终会通过 `CanvasRenderingContext2D` 对象传递到其关联的 `CanvasRenderingContextHost`，由它协调底层的绘制操作，例如修改 `CanvasResourceProvider` 管理的像素缓冲区。
    * **举例 (WebGL Context):**
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const gl = canvas.getContext('webgl');
        // ... WebGL 绘图命令 ...
        ```
        类似地，WebGL 的绘图命令也会通过 `WebGLRenderingContext` 传递到 `CanvasRenderingContextHost`，并使用特定的 WebGL `CanvasResourceProvider` 来管理 GPU 资源。
    * **举例 (OffscreenCanvas):**
        ```javascript
        const offscreenCanvas = new OffscreenCanvas(256, 256);
        const ctx = offscreenCanvas.getContext('2d');
        ctx.fillStyle = 'blue';
        ctx.fillRect(0, 0, 256, 256);
        ```
        对于 `OffscreenCanvas`，也会创建一个 `CanvasRenderingContextHost`，但其 `host_type_` 会是 `HostType::kOffscreenCanvasHost`。

* **CSS:**
    * **关系:** CSS 可以影响 `<canvas>` 元素的尺寸和可见性。
    * **举例:**
        ```css
        #myCanvas {
          width: 300px;
          height: 150px;
          display: block;
        }
        ```
        这段 CSS 代码会改变 Canvas 在页面上渲染的尺寸。当 Canvas 的尺寸改变时，`CanvasRenderingContextHost` 需要更新其管理的资源，例如重新分配像素缓冲区。`PageVisibilityChanged()` 方法的触发也与 CSS 的 `visibility` 属性有关。

**逻辑推理、假设输入与输出**

假设我们有一个 `<canvas>` 元素，其 id 为 "testCanvas"，初始尺寸为 100x100。

* **假设输入:**
    1. HTML 中存在 `<canvas id="testCanvas" width="100" height="100"></canvas>`。
    2. JavaScript 代码获取 2D 渲染上下文：`const ctx = document.getElementById('testCanvas').getContext('2d');`
* **逻辑推理:**
    1. Blink 引擎会创建一个 `HTMLCanvasElement` 对象，其 `id` 为 "testCanvas"，尺寸为 100x100。
    2. 同时，会创建一个 `CanvasRenderingContextHost` 对象，其 `host_type_` 为 `kCanvasHost`，`Size()` 返回 `gfx::Size(100, 100)`。
    3. 当调用 `getContext('2d')` 时，会创建一个 `CanvasRenderingContext2D` 对象，并将其与该 `CanvasRenderingContextHost` 关联。
    4. `CreateCanvasResourceProvider2D()` 方法会被调用，根据系统配置选择合适的 `CanvasResourceProvider`，例如 `BitmapProvider` 或 `SharedImageProvider`。
* **预期输出:**
    1. `CanvasRenderingContextHost` 对象被成功创建并持有 Canvas 的资源信息。
    2. `ResourceProvider()` 方法会返回一个有效的 `CanvasResourceProvider` 对象。
    3. `IsRenderingContext2D()` 方法会返回 `true`。

**用户或编程常见的使用错误及举例说明**

1. **在 OffscreenCanvas 上调用不适用的 API:**
   * **错误:**  尝试在 `OffscreenCanvas` 的 2D 上下文中使用 `drawImage()` 绘制一个 `<video>` 元素。
   * **原因:** `OffscreenCanvas` 在 worker 线程中运行，无法直接访问 DOM 元素。
   * **示例:**
     ```javascript
     const offscreenCanvas = new OffscreenCanvas(100, 100);
     const ctx = offscreenCanvas.getContext('2d');
     const video = document.getElementById('myVideo'); // 错误：OffscreenCanvas无法访问
     ctx.drawImage(video, 0, 0);
     ```

2. **在 WebGL 上下文中使用了 2D 上下文的 API，反之亦然:**
   * **错误:**  尝试在 WebGL 上下文中使用 `fillRect()` 方法。
   * **原因:** 不同的上下文有不同的 API 集合。
   * **示例:**
     ```javascript
     const canvas = document.getElementById('myCanvas');
     const gl = canvas.getContext('webgl');
     gl.fillRect(10, 10, 50, 50); // 错误：WebGL 没有 fillRect
     ```

3. **创建过大的 Canvas 导致性能问题或崩溃:**
   * **错误:**  创建一个尺寸非常大的 Canvas，例如 `new OffscreenCanvas(10000, 10000)`.
   * **原因:**  过大的 Canvas 需要大量的内存来存储像素数据，可能超出系统资源限制。
   * **`CanvasRenderingContextHost::RecordCanvasSizeToUMA()` 的作用:**  这个方法会记录 Canvas 的尺寸，帮助 Chromium 团队分析实际使用情况，以便进行优化或发现潜在问题。

4. **没有处理 `getContext()` 返回 `null` 的情况:**
   * **错误:**  假设 `getContext()` 一定会返回有效的上下文对象。
   * **原因:**  `getContext()` 可能因为不支持的上下文类型或浏览器限制而返回 `null`。
   * **示例:**
     ```javascript
     const canvas = document.getElementById('myCanvas');
     const ctx = canvas.getContext('webgl2'); // 某些浏览器可能不支持 webgl2
     ctx.fillStyle = 'red'; // 如果 ctx 为 null，这里会报错
     ctx.fillRect(0, 0, 100, 100);
     ```

**用户操作如何一步步到达这里**

1. **用户在浏览器中打开一个包含 `<canvas>` 元素的网页。**
2. **浏览器解析 HTML，遇到 `<canvas>` 标签。**
3. **Blink 渲染引擎创建一个 `HTMLCanvasElement` 对象。**
4. **JavaScript 代码执行，调用 `document.getElementById('...')` 获取 Canvas 元素。**
5. **JavaScript 代码调用 `canvas.getContext('2d')` 或 `canvas.getContext('webgl')`。**
6. **Blink 引擎根据请求的上下文类型创建相应的 `CanvasRenderingContext2D` 或 `WebGLRenderingContext` 对象。**
7. **在创建渲染上下文的过程中，或者在后续的渲染操作中，会创建并初始化与该 Canvas 关联的 `CanvasRenderingContextHost` 对象。**  构造函数 `CanvasRenderingContextHost(HostType host_type, const gfx::Size& size)` 会被调用，传入 Canvas 的类型（例如 `kCanvasHost`）和尺寸。
8. **用户在 JavaScript 中调用 Canvas API 的方法（例如 `fillRect()`, `drawImage()`, `gl.drawArrays()` 等）。**
9. **这些 JavaScript 方法的调用会通过 Blink 的绑定机制，最终调用到 `CanvasRenderingContextHost` 对象的相关方法，例如需要访问或修改 Canvas 的像素数据时，会与 `CanvasResourceProvider` 交互。**
10. **当页面可见性改变（例如用户切换标签页）时，浏览器的渲染进程会通知 `CanvasRenderingContextHost`，触发 `PageVisibilityChanged()` 方法。**

总而言之，`CanvasRenderingContextHost.cc` 中的代码是 Web 开发者使用 Canvas API 的基石，它在幕后默默地管理着 Canvas 的底层资源和渲染过程。理解它的功能有助于我们更好地理解 Canvas API 的工作原理，并避免一些常见的错误。

### 提示词
```
这是目录为blink/renderer/core/html/canvas/canvas_rendering_context_host.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/canvas/canvas_rendering_context_host.h"

#include "base/feature_list.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "gpu/command_buffer/common/shared_image_usage.h"
#include "gpu/config/gpu_feature_info.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_encode_options.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_async_blob_creator.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_rendering_context.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_dispatcher.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/skia/include/core/SkSurface.h"
#include "ui/gfx/geometry/skia_conversions.h"

namespace blink {

CanvasRenderingContextHost::CanvasRenderingContextHost(HostType host_type,
                                                       const gfx::Size& size)
    : CanvasResourceHost(size), host_type_(host_type) {}

void CanvasRenderingContextHost::RecordCanvasSizeToUMA() {
  if (did_record_canvas_size_to_uma_)
    return;
  did_record_canvas_size_to_uma_ = true;

  switch (host_type_) {
    case HostType::kNone:
      NOTREACHED();
    case HostType::kCanvasHost:
      UMA_HISTOGRAM_CUSTOM_COUNTS("Blink.Canvas.SqrtNumberOfPixels",
                                  std::sqrt(Size().Area64()), 1, 5000, 100);
      break;
    case HostType::kOffscreenCanvasHost:
      UMA_HISTOGRAM_CUSTOM_COUNTS("Blink.OffscreenCanvas.SqrtNumberOfPixels",
                                  std::sqrt(Size().Area64()), 1, 5000, 100);
      break;
  }
}

scoped_refptr<StaticBitmapImage>
CanvasRenderingContextHost::CreateTransparentImage(
    const gfx::Size& size) const {
  if (!IsValidImageSize(size))
    return nullptr;
  SkImageInfo info = SkImageInfo::Make(
      gfx::SizeToSkISize(size),
      GetRenderingContextSkColorInfo().makeAlphaType(kPremul_SkAlphaType));
  sk_sp<SkSurface> surface =
      SkSurfaces::Raster(info, info.minRowBytes(), nullptr);
  if (!surface)
    return nullptr;
  return UnacceleratedStaticBitmapImage::Create(surface->makeImageSnapshot());
}

void CanvasRenderingContextHost::Commit(scoped_refptr<CanvasResource>&&,
                                        const SkIRect&) {
  NOTIMPLEMENTED();
}

bool CanvasRenderingContextHost::IsPaintable() const {
  return (RenderingContext() && RenderingContext()->IsPaintable()) ||
         IsValidImageSize(Size());
}

bool CanvasRenderingContextHost::PrintedInCurrentTask() const {
  return RenderingContext() && RenderingContext()->did_print_in_current_task();
}

void CanvasRenderingContextHost::InitializeForRecording(
    cc::PaintCanvas* canvas) const {
  if (RenderingContext())
    RenderingContext()->RestoreCanvasMatrixClipStack(canvas);
}

bool CanvasRenderingContextHost::IsWebGL() const {
  return RenderingContext() && RenderingContext()->IsWebGL();
}

bool CanvasRenderingContextHost::IsWebGPU() const {
  return RenderingContext() && RenderingContext()->IsWebGPU();
}

bool CanvasRenderingContextHost::IsRenderingContext2D() const {
  return RenderingContext() && RenderingContext()->IsRenderingContext2D();
}

bool CanvasRenderingContextHost::IsImageBitmapRenderingContext() const {
  return RenderingContext() &&
         RenderingContext()->IsImageBitmapRenderingContext();
}

CanvasResourceProvider*
CanvasRenderingContextHost::GetOrCreateCanvasResourceProvider(
    RasterModeHint hint) {
  return GetOrCreateCanvasResourceProviderImpl(hint);
}

CanvasResourceProvider*
CanvasRenderingContextHost::GetOrCreateCanvasResourceProviderImpl(
    RasterModeHint hint) {
  if (!ResourceProvider() && !did_fail_to_create_resource_provider_) {
    if (IsValidImageSize(Size())) {
      if (IsWebGPU()) {
        CreateCanvasResourceProviderWebGPU();
      } else if (IsWebGL()) {
        CreateCanvasResourceProviderWebGL();
      } else {
        CreateCanvasResourceProvider2D(hint);
      }
    }
    if (!ResourceProvider())
      did_fail_to_create_resource_provider_ = true;
  }
  return ResourceProvider();
}

void CanvasRenderingContextHost::CreateCanvasResourceProviderWebGPU() {
  const SkImageInfo resource_info =
      SkImageInfo::Make(SkISize::Make(Size().width(), Size().height()),
                        GetRenderingContextSkColorInfo());
  std::unique_ptr<CanvasResourceProvider> provider;
  if (SharedGpuContext::IsGpuCompositingEnabled()) {
    provider = CanvasResourceProvider::CreateWebGPUImageProvider(
        resource_info, gpu::SharedImageUsageSet(), this);
  }
  ReplaceResourceProvider(std::move(provider));
  if (ResourceProvider() && ResourceProvider()->IsValid()) {
    base::UmaHistogramBoolean("Blink.Canvas.ResourceProviderIsAccelerated",
                              ResourceProvider()->IsAccelerated());
    base::UmaHistogramEnumeration("Blink.Canvas.ResourceProviderType",
                                  ResourceProvider()->GetType());
  }
}

void CanvasRenderingContextHost::CreateCanvasResourceProviderWebGL() {
  DCHECK(IsWebGL());

  base::WeakPtr<CanvasResourceDispatcher> dispatcher =
      GetOrCreateResourceDispatcher()
          ? GetOrCreateResourceDispatcher()->GetWeakPtr()
          : nullptr;

  std::unique_ptr<CanvasResourceProvider> provider;
  const SkImageInfo resource_info =
      SkImageInfo::Make(SkISize::Make(Size().width(), Size().height()),
                        GetRenderingContextSkColorInfo());
  // Do not initialize the CRP using Skia. The CRP can have bottom left origin
  // in which case Skia Graphite won't be able to render into it, and WebGL is
  // responsible for clearing the CRP when it renders anyway and we have clear
  // rect tracking in the shared image system to enforce this.
  constexpr auto kShouldInitialize =
      CanvasResourceProvider::ShouldInitialize::kNo;
  if (SharedGpuContext::IsGpuCompositingEnabled() && LowLatencyEnabled()) {
    // If LowLatency is enabled, we need a resource that is able to perform well
    // in such mode. It will first try a PassThrough provider and, if that is
    // not possible, it will try a SharedImage with the appropriate flags.
    bool using_swapchain =
        RenderingContext() && RenderingContext()->UsingSwapChain();
    bool using_webgl_image_chromium =
        SharedGpuContext::MaySupportImageChromium() &&
        (RuntimeEnabledFeatures::WebGLImageChromiumEnabled() ||
         base::FeatureList::IsEnabled(features::kLowLatencyWebGLImageChromium));
    if (using_swapchain || using_webgl_image_chromium) {
      // If either SwapChain is enabled or WebGLImage mode is enabled, we can
      // try a passthrough provider.
      DCHECK(LowLatencyEnabled());
      provider = CanvasResourceProvider::CreatePassThroughProvider(
          resource_info, FilterQuality(),
          SharedGpuContext::ContextProviderWrapper(), dispatcher,
          RenderingContext()->IsOriginTopLeft(), this);
    }
    if (!provider) {
      // If PassThrough failed, try a SharedImage with usage display enabled,
      // and if WebGLImageChromium is enabled, add concurrent read write and
      // usage scanout (overlay).
      gpu::SharedImageUsageSet shared_image_usage_flags =
          gpu::SHARED_IMAGE_USAGE_DISPLAY_READ;
      if (using_webgl_image_chromium) {
        shared_image_usage_flags |= gpu::SHARED_IMAGE_USAGE_SCANOUT;
        shared_image_usage_flags |=
            gpu::SHARED_IMAGE_USAGE_CONCURRENT_READ_WRITE;
      }
      provider = CanvasResourceProvider::CreateSharedImageProvider(
          resource_info, FilterQuality(), kShouldInitialize,
          SharedGpuContext::ContextProviderWrapper(), RasterMode::kGPU,
          shared_image_usage_flags, this);
    }
  } else if (SharedGpuContext::IsGpuCompositingEnabled()) {
    // If there is no LowLatency mode, and GPU is enabled, will try a GPU
    // SharedImage that should support Usage Display and probably Usage Scanout
    // if WebGLImageChromium is enabled.
    gpu::SharedImageUsageSet shared_image_usage_flags =
        gpu::SHARED_IMAGE_USAGE_DISPLAY_READ;
    if (SharedGpuContext::MaySupportImageChromium() &&
        RuntimeEnabledFeatures::WebGLImageChromiumEnabled()) {
      shared_image_usage_flags |= gpu::SHARED_IMAGE_USAGE_SCANOUT;
    }
    provider = CanvasResourceProvider::CreateSharedImageProvider(
        resource_info, FilterQuality(), kShouldInitialize,
        SharedGpuContext::ContextProviderWrapper(), RasterMode::kGPU,
        shared_image_usage_flags, this);
  }

  // If either of the other modes failed and / or it was not possible to do, we
  // will backup with a SharedBitmap, and if that was not possible with a Bitmap
  // provider.
  if (!provider) {
    provider = CanvasResourceProvider::CreateSharedBitmapProvider(
        resource_info, FilterQuality(), kShouldInitialize, dispatcher,
        SharedGpuContext::SharedImageInterfaceProvider(), this);
  }
  if (!provider) {
    provider = CanvasResourceProvider::CreateBitmapProvider(
        resource_info, FilterQuality(), kShouldInitialize, this);
  }

  ReplaceResourceProvider(std::move(provider));
  if (ResourceProvider() && ResourceProvider()->IsValid()) {
    base::UmaHistogramBoolean("Blink.Canvas.ResourceProviderIsAccelerated",
                              ResourceProvider()->IsAccelerated());
    base::UmaHistogramEnumeration("Blink.Canvas.ResourceProviderType",
                                  ResourceProvider()->GetType());
  }
}

void CanvasRenderingContextHost::CreateCanvasResourceProvider2D(
    RasterModeHint hint) {
  DCHECK(IsRenderingContext2D() || IsImageBitmapRenderingContext());
  base::WeakPtr<CanvasResourceDispatcher> dispatcher =
      GetOrCreateResourceDispatcher()
          ? GetOrCreateResourceDispatcher()->GetWeakPtr()
          : nullptr;

  std::unique_ptr<CanvasResourceProvider> provider;
  const SkImageInfo resource_info =
      SkImageInfo::Make(SkISize::Make(Size().width(), Size().height()),
                        GetRenderingContextSkColorInfo());
  const bool use_gpu =
      hint == RasterModeHint::kPreferGPU && ShouldAccelerate2dContext();
  constexpr auto kShouldInitialize =
      CanvasResourceProvider::ShouldInitialize::kCallClear;
  if (use_gpu && LowLatencyEnabled()) {
    // If we can use the gpu and low latency is enabled, we will try to use a
    // SwapChain if possible.
    provider = CanvasResourceProvider::CreateSwapChainProvider(
        resource_info, FilterQuality(), kShouldInitialize,
        SharedGpuContext::ContextProviderWrapper(), dispatcher, this);
    // If SwapChain failed or it was not possible, we will try a SharedImage
    // with a set of flags trying to add Usage Display and Usage Scanout and
    // Concurrent Read and Write if possible.
    if (!provider) {
      gpu::SharedImageUsageSet shared_image_usage_flags =
          gpu::SHARED_IMAGE_USAGE_DISPLAY_READ;
      if (SharedGpuContext::MaySupportImageChromium() &&
          (RuntimeEnabledFeatures::Canvas2dImageChromiumEnabled() ||
           base::FeatureList::IsEnabled(
               features::kLowLatencyCanvas2dImageChromium))) {
        shared_image_usage_flags |= gpu::SHARED_IMAGE_USAGE_SCANOUT;
        shared_image_usage_flags |=
            gpu::SHARED_IMAGE_USAGE_CONCURRENT_READ_WRITE;
      }
      provider = CanvasResourceProvider::CreateSharedImageProvider(
          resource_info, FilterQuality(), kShouldInitialize,
          SharedGpuContext::ContextProviderWrapper(), RasterMode::kGPU,
          shared_image_usage_flags, this);
    }
  } else if (use_gpu) {
    // First try to be optimized for displaying on screen. In the case we are
    // hardware compositing, we also try to enable the usage of the image as
    // scanout buffer (overlay)
    gpu::SharedImageUsageSet shared_image_usage_flags =
        gpu::SHARED_IMAGE_USAGE_DISPLAY_READ;
    if (SharedGpuContext::MaySupportImageChromium() &&
        RuntimeEnabledFeatures::Canvas2dImageChromiumEnabled()) {
      shared_image_usage_flags |= gpu::SHARED_IMAGE_USAGE_SCANOUT;
    }
    provider = CanvasResourceProvider::CreateSharedImageProvider(
        resource_info, FilterQuality(), kShouldInitialize,
        SharedGpuContext::ContextProviderWrapper(), RasterMode::kGPU,
        shared_image_usage_flags, this);
  } else if (SharedGpuContext::MaySupportImageChromium() &&
             RuntimeEnabledFeatures::Canvas2dImageChromiumEnabled()) {
    const gpu::SharedImageUsageSet shared_image_usage_flags =
        gpu::SHARED_IMAGE_USAGE_DISPLAY_READ | gpu::SHARED_IMAGE_USAGE_SCANOUT;
    provider = CanvasResourceProvider::CreateSharedImageProvider(
        resource_info, FilterQuality(), kShouldInitialize,
        SharedGpuContext::ContextProviderWrapper(), RasterMode::kCPU,
        shared_image_usage_flags, this);
  }

  // If either of the other modes failed and / or it was not possible to do, we
  // will backup with a SharedBitmap, and if that was not possible with a Bitmap
  // provider.
  if (!provider) {
    provider = CanvasResourceProvider::CreateSharedBitmapProvider(
        resource_info, FilterQuality(), kShouldInitialize, dispatcher,
        SharedGpuContext::SharedImageInterfaceProvider(), this);
  }
  if (!provider) {
    provider = CanvasResourceProvider::CreateBitmapProvider(
        resource_info, FilterQuality(), kShouldInitialize, this);
  }

  ReplaceResourceProvider(std::move(provider));

  if (ResourceProvider()) {
    if (ResourceProvider()->IsValid()) {
      base::UmaHistogramBoolean("Blink.Canvas.ResourceProviderIsAccelerated",
                                ResourceProvider()->IsAccelerated());
      base::UmaHistogramEnumeration("Blink.Canvas.ResourceProviderType",
                                    ResourceProvider()->GetType());
    }
    ResourceProvider()->SetFilterQuality(FilterQuality());
    ResourceProvider()->SetResourceRecyclingEnabled(true);
  }
}

SkColorInfo CanvasRenderingContextHost::GetRenderingContextSkColorInfo() const {
  if (RenderingContext())
    return RenderingContext()->CanvasRenderingContextSkColorInfo();
  return SkColorInfo(kN32_SkColorType, kPremul_SkAlphaType,
                     SkColorSpace::MakeSRGB());
}

bool CanvasRenderingContextHost::IsOffscreenCanvas() const {
  return host_type_ == HostType::kOffscreenCanvasHost;
}

IdentifiableToken CanvasRenderingContextHost::IdentifiabilityInputDigest(
    const CanvasRenderingContext* const context) const {
  const uint64_t context_digest =
      context ? context->IdentifiableTextToken().ToUkmMetricValue() : 0;
  const uint64_t context_type = static_cast<uint64_t>(
      context ? context->GetRenderingAPI()
              : CanvasRenderingContext::CanvasRenderingAPI::kUnknown);
  const bool encountered_skipped_ops =
      context && context->IdentifiabilityEncounteredSkippedOps();
  const bool encountered_sensitive_ops =
      context && context->IdentifiabilityEncounteredSensitiveOps();
  const bool encountered_partially_digested_image =
      context && context->IdentifiabilityEncounteredPartiallyDigestedImage();
  // Bits [0-3] are the context type, bits [4-6] are skipped ops, sensitive
  // ops, and partial image ops bits, respectively. The remaining bits are
  // for the canvas digest.
  uint64_t final_digest = (context_digest << 7) | context_type;
  if (encountered_skipped_ops)
    final_digest |= IdentifiableSurface::CanvasTaintBit::kSkipped;
  if (encountered_sensitive_ops)
    final_digest |= IdentifiableSurface::CanvasTaintBit::kSensitive;
  if (encountered_partially_digested_image)
    final_digest |= IdentifiableSurface::CanvasTaintBit::kPartiallyDigested;
  return final_digest;
}

void CanvasRenderingContextHost::PageVisibilityChanged() {
  bool page_visible = IsPageVisible();
  if (RenderingContext()) {
    RenderingContext()->PageVisibilityChanged();
    if (page_visible) {
      RenderingContext()->SendContextLostEventIfNeeded();
    }
  }
  if (!page_visible && (IsWebGL() || IsWebGPU())) {
    DiscardResourceProvider();
  }
}

bool CanvasRenderingContextHost::ContextHasOpenLayers(
    const CanvasRenderingContext* context) const {
  return context != nullptr && context->IsRenderingContext2D() &&
         context->LayerCount() != 0;
}

}  // namespace blink
```