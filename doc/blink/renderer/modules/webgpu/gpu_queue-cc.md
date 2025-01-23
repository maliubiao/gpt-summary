Response:
The user wants to understand the functionality of the `gpu_queue.cc` file in the Chromium Blink engine. The request has multiple parts:

1. **List the functionalities:** I need to analyze the code and identify the primary responsibilities of this file.
2. **Relationship with web technologies:** I need to explain how the functionalities connect to JavaScript, HTML, and CSS.
3. **Logic reasoning with examples:**  For any logical operations, provide hypothetical inputs and outputs.
4. **Common usage errors:** Describe common mistakes developers might make when using these functionalities.
5. **User operation leading to this code:** Explain the sequence of user actions that would trigger this part of the code.
6. **Summarize the functionality:** Provide a high-level overview of the file's purpose.

Based on the included headers and the initial part of the source code, I can see that `GPUQueue` is a class that manages the submission of commands to the GPU for WebGPU. It handles operations like writing to buffers and textures, and copying data from various sources (like video elements, canvases, images) to textures.

Here's a breakdown of my thought process to address each point:

* **Functionalities:**  Scanning the methods of the `GPUQueue` class will give me a list of its capabilities. I see `submit`, `onSubmittedWorkDone`, `writeBuffer` (multiple overloads), `writeTexture` (multiple overloads), and `copyExternalImageToTexture`. These directly represent the main functions. Helper functions like `GetExternalSourceFromExternalImage` and `CreateCopyTextureForBrowserOptions` support these core functions.

* **Relationship with web technologies:**  The function names and the included headers (like `HTMLCanvasElement`, `HTMLVideoElement`, `ImageBitmap`) strongly suggest interaction with JavaScript APIs. For instance, `copyExternalImageToTexture` clearly relates to the `copyExternalImageToTexture()` method in the WebGPU JavaScript API. The data sources (HTML elements, `ImageData`) are directly from HTML. CSS might indirectly influence rendering on canvases or videos that are later copied, but the direct interaction is with JavaScript and HTML.

* **Logic reasoning with examples:**  The `writeBuffer` and `writeTexture` functions involve checks for valid offsets and sizes. I can create hypothetical scenarios where these checks pass or fail, demonstrating the input/output. For `copyExternalImageToTexture`, the logic around source image validity and bounds checking provides opportunities for examples.

* **Common usage errors:**  Based on the validation checks within the code, I can infer common errors. Incorrect buffer/texture offsets, sizes that exceed the available data, and attempting to copy from cross-origin sources are likely candidates.

* **User operation leading to this code:**  A typical user interaction would involve a web page using the WebGPU API. The sequence would be something like: creating a WebGPU device, creating buffers and textures, obtaining data (e.g., from a canvas), and then calling methods on the `GPUQueue` (like `writeBuffer` or `copyExternalImageToTexture`).

* **Summarize the functionality:**  I need to synthesize the above points into a concise summary of the file's purpose. It's responsible for executing commands on the GPU, specifically for WebGPU, and manages the transfer of data between the CPU and GPU.

Given that the prompt explicitly requests me to consider the provided code snippet for the first part of a two-part response, I will focus my analysis on the functions and data structures present in this snippet. I will note that `CopyFromVideoElement` and the end of `copyExternalImageToTexture` are truncated, indicating that a complete analysis will require the second part.
这是 `blink/renderer/modules/webgpu/gpu_queue.cc` 文件的第一部分，主要负责实现 WebGPU `GPUQueue` 接口的功能。`GPUQueue` 对象用于提交命令缓冲区到 GPU 执行，以及执行一些直接的 GPU 操作，例如写入缓冲区和纹理。

**主要功能归纳:**

1. **命令提交 (Command Submission):**
   - `submit()`: 接收一个或多个 `GPUCommandBuffer` 对象，并将它们提交到 GPU 执行。这与 JavaScript 中调用 `GPUQueue.submit()` 方法相对应。

2. **异步操作完成通知:**
   - `onSubmittedWorkDone()`: 返回一个 Promise，该 Promise 在所有已提交的工作完成时 resolve。这允许 JavaScript 代码在 GPU 操作完成后执行回调。

3. **数据写入缓冲区 (Write Buffer):**
   - `writeBuffer()`:  提供多个重载版本，允许将 JavaScript 中的 `ArrayBufferView` 或 `ArrayBuffer` 的数据写入到 WebGPU `GPUBuffer` 对象中指定的偏移量。

4. **数据写入纹理 (Write Texture):**
   - `writeTexture()`: 提供多个重载版本，允许将 JavaScript 中的 `ArrayBufferView` 或 `ArrayBuffer` 的数据写入到 WebGPU `GPUTexture` 对象中指定的区域。

5. **从外部图像复制到纹理 (Copy External Image to Texture):**
   - `copyExternalImageToTexture()`:  允许将各种 HTML 元素 (如 `<video>`, `<canvas>`, `<img>`) 或 `ImageBitmap`, `ImageData` 的内容复制到 WebGPU `GPUTexture` 对象中。这使得在 WebGPU 中使用来自 DOM 的图像数据成为可能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  `GPUQueue` 的所有功能都直接对应于 WebGPU JavaScript API 中的 `GPUQueue` 接口的方法。
    * **`submit()`:**  当 JavaScript 代码调用 `gpuQueue.submit(commandBuffers)` 时，Blink 引擎会调用 `GPUQueue::submit()` 方法。
    * **`onSubmittedWorkDone()`:**  对应 JavaScript 中的 `gpuQueue.onSubmittedWorkDone().then(...)`。
    * **`writeBuffer()`:** 对应 JavaScript 中的 `gpuQueue.writeBuffer(buffer, offset, data)`。
    * **`writeTexture()`:** 对应 JavaScript 中的 `gpuQueue.writeTexture(destination, source, copySize)`，其中 source 是 `ArrayBufferView` 或 `ArrayBuffer`。
    * **`copyExternalImageToTexture()`:** 对应 JavaScript 中的 `gpuQueue.copyExternalImageToTexture(source, destination, copySize)`，其中 source 可以是 HTML 元素或 `ImageBitmap` 等。

* **HTML:**  `copyExternalImageToTexture()` 方法可以直接操作 HTML 元素的内容。
    * **`<canvas>`:**  JavaScript 可以将 2D 或 3D 图形渲染到 `<canvas>` 元素上，然后使用 `copyExternalImageToTexture()` 将其内容作为纹理上传到 GPU 用于 WebGPU 的渲染。
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const gpuTexture = device.createTexture(...);
        const encoder = device.createCommandEncoder();
        encoder.copyExternalImageToTexture({ source: canvas }, { texture: gpuTexture }, [canvas.width, canvas.height]);
        gpuQueue.submit([encoder.finish()]);
        ```
    * **`<img>`:**  可以使用 `copyExternalImageToTexture()` 将图片元素的内容加载到 GPU 纹理，例如用于图像处理或作为 3D 模型的纹理。
        ```javascript
        const image = document.getElementById('myImage');
        const gpuTexture = device.createTexture(...);
        const encoder = device.createCommandEncoder();
        encoder.copyExternalImageToTexture({ source: image }, { texture: gpuTexture }, [image.naturalWidth, image.naturalHeight]);
        gpuQueue.submit([encoder.finish()]);
        ```
    * **`<video>`:** 可以将视频的当前帧捕获并上传到 GPU 纹理，用于视频处理或在 3D 场景中显示视频。
        ```javascript
        const video = document.getElementById('myVideo');
        const gpuTexture = device.createTexture(...);
        const encoder = device.createCommandEncoder();
        encoder.copyExternalImageToTexture({ source: video }, { texture: gpuTexture }, [video.videoWidth, video.videoHeight]);
        gpuQueue.submit([encoder.finish()]);
        ```

* **CSS:** CSS 本身不直接与 `GPUQueue` 交互。然而，CSS 样式会影响 HTML 元素的呈现，例如 `<canvas>` 的尺寸或 `<img>` 的显示，这些呈现最终可能被 `copyExternalImageToTexture()` 捕获并上传到 GPU。

**逻辑推理的假设输入与输出举例 (以 `writeBuffer` 为例):**

**假设输入:**

* `buffer`: 一个已创建的 `GPUBuffer` 对象，例如大小为 256 字节。
* `buffer_offset`: 16 (从缓冲区的第 16 个字节开始写入)。
* `data`: 一个 `Uint32Array`，包含 4 个元素，即 16 字节的数据：`[1, 2, 3, 4]`。
* `data_element_offset`: 0 (从 `Uint32Array` 的第一个元素开始读取)。
* `data_element_count`: 2 (写入 `Uint32Array` 的前 2 个元素)。

**逻辑推理:**

`WriteBufferImpl` 方法会计算要写入的字节数 (2 个元素 * 4 字节/元素 = 8 字节)，并检查偏移量和写入大小是否有效。

**预期输出:**

`GPUBuffer` 从偏移量 16 开始的 8 个字节将被更新为 `Uint32Array` 的前两个元素的值（假设字节序一致）。如果初始缓冲区内容是未定义的，则写入后这 8 个字节将包含表示数字 1 和 2 的二进制数据。

**用户或编程常见的使用错误举例:**

1. **`writeBuffer` 或 `writeTexture` 越界写入:**  用户提供的 `buffer_offset` 或写入的数据大小超过了 `GPUBuffer` 或 `GPUTexture` 的范围。
   ```javascript
   // 错误示例：尝试写入超出缓冲区大小的数据
   const buffer = device.createBuffer({ size: 10 });
   const data = new Uint8Array(20);
   gpuQueue.writeBuffer(buffer, 0, data); // 错误：data 大于 buffer
   ```

2. **`copyExternalImageToTexture` 的源图像未加载完成:**  尝试复制尚未完全加载的图像或视频帧。
   ```javascript
   const image = new Image();
   image.src = 'my-image.png';
   const gpuTexture = device.createTexture(...);
   const encoder = device.createCommandEncoder();
   // 潜在错误：image 可能尚未加载完成
   encoder.copyExternalImageToTexture({ source: image }, { texture: gpuTexture }, [image.naturalWidth, image.naturalHeight]);
   gpuQueue.submit([encoder.finish()]);
   ```
   **调试线索:** 浏览器控制台可能会显示警告或错误，指出图像尚未准备好。可以通过监听图像的 `onload` 事件来确保图像已加载。

3. **`copyExternalImageToTexture` 的跨域问题:** 尝试复制来自不同域的图像或视频，而没有正确的 CORS 配置。
   **用户操作步骤:** 用户在一个网站上加载了一个包含来自另一个域的图像的页面，然后 JavaScript 代码尝试使用 `copyExternalImageToTexture()` 将该图像复制到 WebGPU 纹理。
   **调试线索:** 浏览器控制台会抛出 CORS 相关的错误，阻止访问跨域资源。需要在服务器端配置 CORS 头信息以允许跨域访问。

4. **`writeTexture` 数据布局不匹配:**  提供的 `GPUImageDataLayout` 与要写入的数据的实际布局不匹配，例如 `bytesPerRow` 设置不正确。
   **用户操作步骤:**  开发者尝试使用自定义的数据排布方式将数据写入纹理，但提供的 `GPUImageDataLayout` 参数与实际数据不符。
   **调试线索:**  渲染结果可能出现错乱或纹理数据损坏。WebGPU 验证层可能会报告数据布局错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问一个使用了 WebGPU 的网页:** 用户通过浏览器访问一个使用了 WebGPU API 的网站。
2. **JavaScript 代码执行 WebGPU 操作:** 网页上的 JavaScript 代码调用 WebGPU API 的方法，例如创建设备、缓冲区、纹理等。
3. **提交命令到队列:** JavaScript 代码创建 `GPUCommandBuffer` 对象，并通过 `gpuQueue.submit()` 方法将其提交到 `GPUQueue`。 这会触发 `GPUQueue::submit()` 方法。
4. **写入缓冲区或纹理:** JavaScript 代码调用 `gpuQueue.writeBuffer()` 或 `gpuQueue.writeTexture()` 方法，尝试将数据上传到 GPU 资源。这分别对应 `GPUQueue::writeBuffer()` 和 `GPUQueue::writeTexture()` 的实现。
5. **从外部源复制图像:** JavaScript 代码调用 `gpuQueue.copyExternalImageToTexture()` 方法，尝试将 HTML 元素或 `ImageBitmap` 的内容复制到 GPU 纹理。 这会调用 `GPUQueue::copyExternalImageToTexture()` 方法。

作为调试线索，如果代码执行到 `gpu_queue.cc` 文件，通常意味着 WebGPU 的 JavaScript API 已经被调用，并且 Blink 引擎正在处理这些调用，与 Chromium 的 GPU 进程进行交互以执行 GPU 命令。如果出现错误，可以检查 JavaScript 代码中传递给 `GPUQueue` 方法的参数是否正确，以及 HTML 元素的状态（例如，是否已加载，是否存在跨域问题）。

### 提示词
```
这是目录为blink/renderer/modules/webgpu/gpu_queue.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webgpu/gpu_queue.h"

#include "build/build_config.h"
#include "gpu/command_buffer/client/shared_image_interface.h"
#include "gpu/command_buffer/client/webgpu_interface.h"
#include "gpu/command_buffer/common/shared_image_usage.h"
#include "gpu/config/gpu_finch_features.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_command_buffer_descriptor.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_image_copy_external_image.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_image_copy_image_bitmap.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_image_copy_texture.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gpu_image_copy_texture_tagged.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_htmlcanvaselement_htmlimageelement_htmlvideoelement_imagebitmap_imagedata_offscreencanvas_videoframe.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_rendering_context_host.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/html/canvas/predefined_color_space.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/offscreencanvas/offscreen_canvas.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/modules/webgpu/dawn_conversions.h"
#include "third_party/blink/renderer/modules/webgpu/external_texture_helper.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_adapter.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_buffer.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_command_buffer.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_device.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_texture.h"
#include "third_party/blink/renderer/modules/webgpu/texture_utils.h"
#include "third_party/blink/renderer/platform/graphics/gpu/image_extractor.h"
#include "third_party/blink/renderer/platform/graphics/gpu/webgpu_mailbox_texture.h"
#include "third_party/blink/renderer/platform/graphics/graphics_types.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

namespace {

bool IsValidExternalImageDestinationFormat(
    wgpu::TextureFormat dawn_texture_format) {
  switch (dawn_texture_format) {
    case wgpu::TextureFormat::R8Unorm:
    case wgpu::TextureFormat::R16Float:
    case wgpu::TextureFormat::R32Float:
    case wgpu::TextureFormat::RG8Unorm:
    case wgpu::TextureFormat::RG16Float:
    case wgpu::TextureFormat::RG32Float:
    case wgpu::TextureFormat::RGBA8Unorm:
    case wgpu::TextureFormat::RGBA8UnormSrgb:
    case wgpu::TextureFormat::BGRA8Unorm:
    case wgpu::TextureFormat::BGRA8UnormSrgb:
    case wgpu::TextureFormat::RGB10A2Unorm:
    case wgpu::TextureFormat::RGBA16Float:
    case wgpu::TextureFormat::RGBA32Float:
      return true;
    default:
      return false;
  }
}

wgpu::TextureFormat SkColorTypeToDawnColorFormat(SkColorType sk_color_type) {
  switch (sk_color_type) {
    case SkColorType::kRGBA_8888_SkColorType:
      return wgpu::TextureFormat::RGBA8Unorm;
    case SkColorType::kBGRA_8888_SkColorType:
      return wgpu::TextureFormat::BGRA8Unorm;
    default:
      NOTREACHED();
  }
}

static constexpr uint64_t kDawnBytesPerRowAlignmentBits = 8;

// Calculate bytes per row for T2B/B2T copy
// TODO(shaobo.yan@intel.com): Using Dawn's constants once they are exposed
uint64_t AlignBytesPerRow(uint64_t bytesPerRow) {
  return (((bytesPerRow - 1) >> kDawnBytesPerRowAlignmentBits) + 1)
         << kDawnBytesPerRowAlignmentBits;
}

struct ExternalSource {
  ExternalTextureSource external_texture_source;
  scoped_refptr<StaticBitmapImage> image = nullptr;
  uint32_t width = 0;
  uint32_t height = 0;
  bool valid = false;
};

struct ExternalImageDstInfo {
  bool premultiplied_alpha;
  PredefinedColorSpace color_space;
};

// TODO(crbug.com/1471372): Avoid extra copy.
scoped_refptr<StaticBitmapImage> GetImageFromImageData(
    const ImageData* image_data) {
  SkPixmap image_data_pixmap = image_data->GetSkPixmap();
  SkImageInfo info = image_data_pixmap.info().makeColorType(kN32_SkColorType);
  size_t image_pixels_size = info.computeMinByteSize();
  if (SkImageInfo::ByteSizeOverflowed(image_pixels_size)) {
    return nullptr;
  }
  sk_sp<SkData> image_pixels = TryAllocateSkData(image_pixels_size);
  if (!image_pixels) {
    return nullptr;
  }
  if (!image_data_pixmap.readPixels(info, image_pixels->writable_data(),
                                    info.minRowBytes(), 0, 0)) {
    return nullptr;
  }
  return StaticBitmapImage::Create(std::move(image_pixels), info);
}

ExternalSource GetExternalSourceFromExternalImage(
    const V8GPUImageCopyExternalImageSource* external_image,
    const ExternalImageDstInfo& external_image_dst_info,
    ExceptionState& exception_state) {
  ExternalSource external_source;
  ExternalTextureSource external_texture_source;
  CanvasImageSource* canvas_image_source = nullptr;
  CanvasRenderingContextHost* canvas = nullptr;
  VideoFrame* video_frame = nullptr;

  switch (external_image->GetContentType()) {
    case V8GPUImageCopyExternalImageSource::ContentType::kHTMLVideoElement:
      external_texture_source = GetExternalTextureSourceFromVideoElement(
          external_image->GetAsHTMLVideoElement(), exception_state);
      if (external_texture_source.valid) {
        external_source.external_texture_source = external_texture_source;
        CHECK(external_texture_source.media_video_frame);

        // Use display size to handle rotated video frame.
        auto media_video_frame = external_texture_source.media_video_frame;

        const auto transform =
            media_video_frame->metadata().transformation.value_or(
                media::kNoTransformation);
        if (transform == media::kNoTransformation ||
            transform.rotation == media::VIDEO_ROTATION_0 ||
            transform.rotation == media::VIDEO_ROTATION_180) {
          external_source.width =
              static_cast<uint32_t>(media_video_frame->natural_size().width());
          external_source.height =
              static_cast<uint32_t>(media_video_frame->natural_size().height());
        } else {
          external_source.width =
              static_cast<uint32_t>(media_video_frame->natural_size().height());
          external_source.height =
              static_cast<uint32_t>(media_video_frame->natural_size().width());
        }
        external_source.valid = true;
      }
      return external_source;
    case V8GPUImageCopyExternalImageSource::ContentType::kVideoFrame:
      video_frame = external_image->GetAsVideoFrame();
      external_texture_source =
          GetExternalTextureSourceFromVideoFrame(video_frame, exception_state);
      if (external_texture_source.valid) {
        external_source.external_texture_source = external_texture_source;
        CHECK(external_texture_source.media_video_frame);
        external_source.width = video_frame->displayWidth();
        external_source.height = video_frame->displayHeight();
        external_source.valid = true;
      }
      return external_source;
    case V8GPUImageCopyExternalImageSource::ContentType::kHTMLCanvasElement:
      canvas_image_source = external_image->GetAsHTMLCanvasElement();
      canvas = external_image->GetAsHTMLCanvasElement();
      break;
    case V8GPUImageCopyExternalImageSource::ContentType::kImageBitmap:
      canvas_image_source = external_image->GetAsImageBitmap();
      break;
    case V8GPUImageCopyExternalImageSource::ContentType::kImageData: {
      auto image = GetImageFromImageData(external_image->GetAsImageData());
      if (!image) {
        exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                          "Cannot get image.");
        return external_source;
      }
      external_source.image = image;
      external_source.width = static_cast<uint32_t>(image->width());
      external_source.height = static_cast<uint32_t>(image->height());
      external_source.valid = true;
      return external_source;
    }
    case V8GPUImageCopyExternalImageSource::ContentType::kHTMLImageElement:
      canvas_image_source = external_image->GetAsHTMLImageElement();
      break;
    case V8GPUImageCopyExternalImageSource::ContentType::kOffscreenCanvas:
      canvas_image_source = external_image->GetAsOffscreenCanvas();
      canvas = external_image->GetAsOffscreenCanvas();
      break;
  }

  // Neutered external image.
  if (canvas_image_source->IsNeutered()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "External Image has been detached.");
    return external_source;
  }

  // Placeholder source is not allowed.
  if (canvas_image_source->IsPlaceholder()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot copy from a canvas that has had "
                                      "transferControlToOffscreen() called.");
    return external_source;
  }

  // Canvas element contains cross-origin data and may not be loaded
  if (canvas_image_source->WouldTaintOrigin()) {
    exception_state.ThrowSecurityError(
        "The external image is tainted by cross-origin data.");
    return external_source;
  }

  if (canvas &&
      !(canvas->IsWebGL() || canvas->IsRenderingContext2D() ||
        canvas->IsWebGPU() || canvas->IsImageBitmapRenderingContext())) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kOperationError,
        "CopyExternalImageToTexture doesn't support canvas without rendering "
        "context");
    return external_source;
  }

  // HTMLCanvasElement and OffscreenCanvas won't care image orientation. But for
  // ImageBitmap, use kRespectImageOrientation will make ElementSize() behave
  // as Size().
  gfx::SizeF image_size = canvas_image_source->ElementSize(
      gfx::SizeF(),  // It will be ignored and won't affect size.
      kRespectImageOrientation);

  // TODO(crbug.com/1197369): Ensure kUnpremultiplyAlpha impl will also make
  // image live on GPU if possible.
  // Use kDontChangeAlpha here to bypass the alpha type conversion here.
  // Left the alpha op to CopyTextureForBrowser() and CopyContentFromCPU().
  // This will help combine more transforms (e.g. flipY, color-space)
  // into a single blit.
  SourceImageStatus source_image_status = kInvalidSourceImageStatus;
  auto image_for_canvas = canvas_image_source->GetSourceImageForCanvas(
      FlushReason::kWebGPUExternalImage, &source_image_status, image_size,
      kDontChangeAlpha);
  if (source_image_status != kNormalSourceImageStatus) {
    // Canvas back resource is broken, zero size, incomplete or invalid.
    // but developer can do nothing. Return nullptr and issue an noop.
    return external_source;
  }

  // TODO(crbug.com/1471372): It would be better if GetSourceImageForCanvas()
  // would always return a StaticBitmapImage.
  if (auto* image = DynamicTo<StaticBitmapImage>(image_for_canvas.get())) {
    external_source.image = image;
  } else {
    // HTMLImageElement input
    ImageExtractor image_extractor(image_for_canvas.get(),
                                   external_image_dst_info.premultiplied_alpha,
                                   PredefinedColorSpaceToSkColorSpace(
                                       external_image_dst_info.color_space));
    auto sk_image = image_extractor.GetSkImage();

    if (!sk_image) {
      return external_source;
    }
    // Handle LazyGenerated images.
    if (sk_image->isLazyGenerated()) {
      SkBitmap bitmap;
      auto image_info = sk_image->imageInfo();
      bitmap.allocPixels(image_info, image_info.minRowBytes());
      if (!sk_image->readPixels(bitmap.pixmap(), 0, 0)) {
        return external_source;
      }

      sk_image = SkImages::RasterFromBitmap(bitmap);
    }

    external_source.image = UnacceleratedStaticBitmapImage::Create(
        std::move(sk_image), image_for_canvas->CurrentFrameOrientation());
  }
  external_source.width = static_cast<uint32_t>(external_source.image->width());
  external_source.height =
      static_cast<uint32_t>(external_source.image->height());
  external_source.valid = true;

  return external_source;
}

// CopyExternalImageToTexture() needs to set src/dst AlphaMode, flipY and color
// space conversion related params. This helper function also initializes
// ColorSpaceConversionConstants param.
wgpu::CopyTextureForBrowserOptions CreateCopyTextureForBrowserOptions(
    const StaticBitmapImage* image,
    const PaintImage* paint_image,
    PredefinedColorSpace dst_color_space,
    bool dst_premultiplied_alpha,
    bool flipY,
    ColorSpaceConversionConstants* color_space_conversion_constants) {
  wgpu::CopyTextureForBrowserOptions options = {
      .srcAlphaMode = image->IsPremultiplied()
                          ? wgpu::AlphaMode::Premultiplied
                          : wgpu::AlphaMode::Unpremultiplied,
      .dstAlphaMode = dst_premultiplied_alpha
                          ? wgpu::AlphaMode::Premultiplied
                          : wgpu::AlphaMode::Unpremultiplied,
  };

  // Set color space conversion params
  sk_sp<SkColorSpace> sk_src_color_space =
      paint_image->GetSkImageInfo().refColorSpace();

  // If source input discard the color space info(e.g. ImageBitmap created with
  // flag colorSpaceConversion: none). Treat the source color space as sRGB.
  if (sk_src_color_space == nullptr) {
    sk_src_color_space = SkColorSpace::MakeSRGB();
  }

  gfx::ColorSpace gfx_src_color_space = gfx::ColorSpace(*sk_src_color_space);
  gfx::ColorSpace gfx_dst_color_space =
      PredefinedColorSpaceToGfxColorSpace(dst_color_space);

  *color_space_conversion_constants = GetColorSpaceConversionConstants(
      gfx_src_color_space, gfx_dst_color_space);

  if (gfx_src_color_space != gfx_dst_color_space) {
    options.needsColorSpaceConversion = true;
    options.srcTransferFunctionParameters =
        color_space_conversion_constants->src_transfer_constants.data();
    options.dstTransferFunctionParameters =
        color_space_conversion_constants->dst_transfer_constants.data();
    options.conversionMatrix =
        color_space_conversion_constants->gamut_conversion_matrix.data();
  }
  // The source texture, which is either a WebGPUMailboxTexture for
  // accelerated images or an intermediate texture created for unaccelerated
  // images, is always origin top left, so no additional flip is needed apart
  // from the client specified flip in GPUImageCopyExternalImage i.e. |flipY|.
  options.flipY = flipY;

  return options;
}

// Helper function to get clipped rect from source image. Using in
// CopyExternalImageToTexture().
gfx::Rect GetSourceImageSubrect(StaticBitmapImage* image,
                                gfx::Rect source_image_rect,
                                const wgpu::Origin2D& origin,
                                const wgpu::Extent3D& copy_size) {
  int width = static_cast<int>(copy_size.width);
  int height = static_cast<int>(copy_size.height);
  int x = static_cast<int>(origin.x) + source_image_rect.x();
  int y = static_cast<int>(origin.y) + source_image_rect.y();

  // Ensure generated source image subrect is into source image rect.
  CHECK(width <= source_image_rect.width() - source_image_rect.x() &&
        height <= source_image_rect.height() - source_image_rect.y() &&
        x <= source_image_rect.width() - source_image_rect.x() - width &&
        y <= source_image_rect.height() - source_image_rect.y() - height);

  return gfx::Rect(x, y, width, height);
}

}  // namespace

GPUQueue::GPUQueue(GPUDevice* device, wgpu::Queue queue, const String& label)
    : DawnObject<wgpu::Queue>(device, std::move(queue), label) {}

void GPUQueue::submit(ScriptState* script_state,
                      const HeapVector<Member<GPUCommandBuffer>>& buffers) {
  std::unique_ptr<wgpu::CommandBuffer[]> commandBuffers = AsDawnType(buffers);

  GetHandle().Submit(buffers.size(), commandBuffers.get());
  // WebGPU guarantees that submitted commands finish in finite time so we
  // need to ensure commands are flushed. Flush immediately so the GPU process
  // eagerly processes commands to maximize throughput.
  FlushNow();

  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  UseCounter::Count(execution_context, WebFeature::kWebGPUQueueSubmit);
}

void OnWorkDoneCallback(ScriptPromiseResolver<IDLUndefined>* resolver,
                        wgpu::QueueWorkDoneStatus status) {
  switch (status) {
    case wgpu::QueueWorkDoneStatus::Success:
      resolver->Resolve();
      break;
    case wgpu::QueueWorkDoneStatus::Error:
      resolver->RejectWithDOMException(
          DOMExceptionCode::kOperationError,
          "Unexpected failure in onSubmittedWorkDone");
      break;
    case wgpu::QueueWorkDoneStatus::Unknown:
      resolver->RejectWithDOMException(
          DOMExceptionCode::kOperationError,
          "Unknown failure in onSubmittedWorkDone");
      break;
    case wgpu::QueueWorkDoneStatus::InstanceDropped:
      resolver->RejectWithDOMException(
          DOMExceptionCode::kOperationError,
          "Instance dropped in onSubmittedWorkDone");
      break;
    case wgpu::QueueWorkDoneStatus::DeviceLost:
      resolver->RejectWithDOMException(
          DOMExceptionCode::kOperationError,
          "Device lost during onSubmittedWorkDone (do not use this error for "
          "recovery - it is NOT guaranteed to happen on device loss)");
      break;
  }
}

ScriptPromise<IDLUndefined> GPUQueue::onSubmittedWorkDone(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();

  auto* callback = MakeWGPUOnceCallback(
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(&OnWorkDoneCallback)));

  GetHandle().OnSubmittedWorkDone(wgpu::CallbackMode::AllowSpontaneous,
                                  callback->UnboundCallback(),
                                  callback->AsUserdata());
  // WebGPU guarantees that promises are resolved in finite time so we
  // need to ensure commands are flushed.
  EnsureFlush(ToEventLoop(script_state));
  return promise;
}

void GPUQueue::writeBuffer(ScriptState* script_state,
                           GPUBuffer* buffer,
                           uint64_t buffer_offset,
                           const MaybeShared<DOMArrayBufferView>& data,
                           uint64_t data_element_offset,
                           ExceptionState& exception_state) {
  WriteBufferImpl(script_state, buffer, buffer_offset, data->byteLength(),
                  data->BaseAddressMaybeShared(), data->TypeSize(),
                  data_element_offset, {}, exception_state);
}

void GPUQueue::writeBuffer(ScriptState* script_state,
                           GPUBuffer* buffer,
                           uint64_t buffer_offset,
                           const MaybeShared<DOMArrayBufferView>& data,
                           uint64_t data_element_offset,
                           uint64_t data_element_count,
                           ExceptionState& exception_state) {
  WriteBufferImpl(script_state, buffer, buffer_offset, data->byteLength(),
                  data->BaseAddressMaybeShared(), data->TypeSize(),
                  data_element_offset, data_element_count, exception_state);
}

void GPUQueue::writeBuffer(ScriptState* script_state,
                           GPUBuffer* buffer,
                           uint64_t buffer_offset,
                           const DOMArrayBufferBase* data,
                           uint64_t data_byte_offset,
                           ExceptionState& exception_state) {
  WriteBufferImpl(script_state, buffer, buffer_offset, data->ByteLength(),
                  data->DataMaybeShared(), 1, data_byte_offset, {},
                  exception_state);
}

void GPUQueue::writeBuffer(ScriptState* script_state,
                           GPUBuffer* buffer,
                           uint64_t buffer_offset,
                           const DOMArrayBufferBase* data,
                           uint64_t data_byte_offset,
                           uint64_t byte_size,
                           ExceptionState& exception_state) {
  WriteBufferImpl(script_state, buffer, buffer_offset, data->ByteLength(),
                  data->DataMaybeShared(), 1, data_byte_offset, byte_size,
                  exception_state);
}

void GPUQueue::WriteBufferImpl(ScriptState* script_state,
                               GPUBuffer* buffer,
                               uint64_t buffer_offset,
                               uint64_t data_byte_length,
                               const void* data_base_ptr,
                               unsigned data_bytes_per_element,
                               uint64_t data_element_offset,
                               std::optional<uint64_t> data_element_count,
                               ExceptionState& exception_state) {
  CHECK_LE(data_bytes_per_element, 8u);

  if (data_element_offset > data_byte_length / data_bytes_per_element) {
    exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                      "Data offset is too large");
    return;
  }

  uint64_t data_byte_offset = data_element_offset * data_bytes_per_element;
  uint64_t max_write_size = data_byte_length - data_byte_offset;

  uint64_t write_byte_size = max_write_size;
  if (data_element_count.has_value()) {
    if (data_element_count.value() > max_write_size / data_bytes_per_element) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kOperationError,
          "Number of bytes to write is too large");
      return;
    }
    write_byte_size = data_element_count.value() * data_bytes_per_element;
  }
  if (write_byte_size % 4 != 0) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kOperationError,
        "Number of bytes to write must be a multiple of 4");
    return;
  }

  // Check that the write size can be cast to a size_t. This should always be
  // the case since data_byte_length comes from an ArrayBuffer size.
  if (write_byte_size > uint64_t(std::numeric_limits<size_t>::max())) {
    exception_state.ThrowRangeError(
        "writeSize larger than size_t (please report a bug if you see this)");
    return;
  }

  // SAFETY: Bounds already checked
  auto data_span =
      UNSAFE_BUFFERS(
          base::span<const uint8_t>(static_cast<const uint8_t*>(data_base_ptr),
                                    static_cast<size_t>(data_byte_length)))
          .subspan(static_cast<size_t>(data_byte_offset),
                   static_cast<size_t>(write_byte_size));

  GetHandle().WriteBuffer(buffer->GetHandle(), buffer_offset, data_span.data(),
                          data_span.size());
  EnsureFlush(ToEventLoop(script_state));
}

void GPUQueue::writeTexture(ScriptState* script_state,
                            GPUImageCopyTexture* destination,
                            const MaybeShared<DOMArrayBufferView>& data,
                            GPUImageDataLayout* data_layout,
                            const V8GPUExtent3D* write_size,
                            ExceptionState& exception_state) {
  WriteTextureImpl(script_state, destination, data->BaseAddressMaybeShared(),
                   data->byteLength(), data_layout, write_size,
                   exception_state);
}

void GPUQueue::writeTexture(ScriptState* script_state,
                            GPUImageCopyTexture* destination,
                            const DOMArrayBufferBase* data,
                            GPUImageDataLayout* data_layout,
                            const V8GPUExtent3D* write_size,
                            ExceptionState& exception_state) {
  WriteTextureImpl(script_state, destination, data->DataMaybeShared(),
                   data->ByteLength(), data_layout, write_size,
                   exception_state);
}

// TODO(crbug.com/351564777): should be UNSAFE_BUFFER_USAGE
void GPUQueue::WriteTextureImpl(ScriptState* script_state,
                                GPUImageCopyTexture* destination,
                                const void* data,
                                size_t data_size,
                                GPUImageDataLayout* data_layout,
                                const V8GPUExtent3D* write_size,
                                ExceptionState& exception_state) {
  wgpu::Extent3D dawn_write_size;
  wgpu::ImageCopyTexture dawn_destination;
  if (!ConvertToDawn(write_size, &dawn_write_size, device_, exception_state) ||
      !ConvertToDawn(destination, &dawn_destination, exception_state)) {
    return;
  }

  wgpu::TextureDataLayout dawn_data_layout = {};
  {
    const char* error =
        ValidateTextureDataLayout(data_layout, &dawn_data_layout);
    if (error) {
      device_->InjectError(wgpu::ErrorType::Validation, error);
      return;
    }
  }

  if (dawn_data_layout.offset > data_size) {
    device_->InjectError(wgpu::ErrorType::Validation,
                         "Data offset is too large");
    return;
  }

  // SAFETY: Required from caller
  // Handle the data layout offset by offsetting the data pointer instead. This
  // helps move less data between then renderer and GPU process (otherwise all
  // the data from 0 to offset would be copied over as well).
  auto data_span =
      UNSAFE_BUFFERS(base::span<const uint8_t>(
                         static_cast<const uint8_t*>(data), data_size))
          .subspan(base::checked_cast<size_t>(dawn_data_layout.offset));
  dawn_data_layout.offset = 0;

  // Compute a tight upper bound of the number of bytes to send for this
  // WriteTexture. This can be 0 for some cases that produce validation errors,
  // but we don't create an error in Blink since Dawn can produce better error
  // messages (and this is more up-to-spec because the errors must be created on
  // the device timeline).
  size_t data_size_upper_bound = EstimateWriteTextureBytesUpperBound(
      dawn_data_layout, dawn_write_size, destination->texture()->Format(),
      dawn_destination.aspect);
  size_t required_copy_size = std::min(data_span.size(), data_size_upper_bound);

  GetHandle().WriteTexture(&dawn_destination, data_span.data(),
                           required_copy_size, &dawn_data_layout,
                           &dawn_write_size);
  EnsureFlush(ToEventLoop(script_state));
  return;
}

void GPUQueue::copyExternalImageToTexture(
    GPUImageCopyExternalImage* copyImage,
    GPUImageCopyTextureTagged* destination,
    const V8GPUExtent3D* copy_size,
    ExceptionState& exception_state) {

  // Extract color space info before getting source image to handle some
  // redecoded cases like ImageElement.
  PredefinedColorSpace color_space;
  if (!ValidateAndConvertColorSpace(destination->colorSpace(), color_space,
                                    exception_state)) {
    return;
  }

  ExternalSource source = GetExternalSourceFromExternalImage(
      copyImage->source(), {destination->premultipliedAlpha(), color_space},
      exception_state);
  if (!source.valid) {
    device_->AddConsoleWarning(
        "CopyExternalImageToTexture(): Browser fails extracting valid resource"
        "from external image. This API call will return early.");
    return;
  }

  wgpu::Extent3D dawn_copy_size;
  wgpu::Origin2D origin_in_external_image;
  wgpu::ImageCopyTexture dawn_destination;
  if (!ConvertToDawn(copy_size, &dawn_copy_size, device_, exception_state) ||
      !ConvertToDawn(copyImage->origin(), &origin_in_external_image,
                     exception_state) ||
      !ConvertToDawn(destination, &dawn_destination, exception_state)) {
    return;
  }

  const bool copyRectOutOfBounds =
      source.width < origin_in_external_image.x ||
      source.height < origin_in_external_image.y ||
      source.width - origin_in_external_image.x < dawn_copy_size.width ||
      source.height - origin_in_external_image.y < dawn_copy_size.height;

  if (copyRectOutOfBounds) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kOperationError,
        "Copy rect is out of bounds of external image");
    return;
  }

  // Check copy depth.
  // the validation rule is origin.z + copy_size.depth <= 1.
  // Since origin in external image is 2D Origin(z always equals to 0),
  // checks copy size here only.
  if (dawn_copy_size.depthOrArrayLayers > 1) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kOperationError,
        "Copy depth is out of bounds of external image.");
    return;
  }

  if (!IsValidExternalImageDestinationFormat(
          destination->texture()->Format())) {
    device_->GetHandle().InjectError(wgpu::ErrorType::Validation,
                                     "Invalid destination gpu texture format.");
    return;
  }

  if (destination->texture()->Dimension() != wgpu::TextureDimension::e2D) {
    device_->GetHandle().InjectError(wgpu::ErrorType::Validation,
                                     "Dst gpu texture must be 2d.");
    return;
  }

  wgpu::TextureUsage dst_texture_usage = destination->texture()->Usage();

  if ((dst_texture_usage & wgpu::TextureUsage::RenderAttachment) !=
          wgpu::TextureUsage::RenderAttachment ||
      (dst_texture_usage & wgpu::TextureUsage::CopyDst) !=
          wgpu::TextureUsage::CopyDst) {
    device_->GetHandle().InjectError(
        wgpu::ErrorType::Validation,
        "Destination texture needs to have CopyDst and RenderAttachment "
        "usage.");
    return;
  }

  // Issue the noop copy to continue validation to destination textures
  if (dawn_copy_size.width == 0 || dawn_copy_size.height == 0 ||
      dawn_copy_size.depthOrArrayLayers == 0) {
    device_->AddConsoleWarning(
        "CopyExternalImageToTexture(): It is a noop copy"
        "({width|height|depthOrArrayLayers} equals to 0).");
  }

  if (source.external_texture_source.valid) {
    // Use display size which is based on natural size but considering
    // transformation metadata.
    wgpu::Extent2D video_frame_display_size = {source.width, source.height};
    CopyFromVideoElement(
        source.external_texture_source, video_frame_display_size,
        origin_in_external_image, dawn_copy_size, dawn_destination,
        destination->premultipliedAlpha(), color_space, copyImage->flipY());
    return;
  }

  if (!CopyFromCanvasSourceImage(source.image.get(), origin_in_external_image,
                                 dawn_copy_size, dawn_destination,
                                 destination->premultipliedAlpha(), color_space,
                                 copyImage->flipY())) {
    exception_state.ThrowTypeError(
        "Failed to copy content from external image.");
    return;
  }
}

void GPUQueue::CopyFromVideoElement(
    const ExternalTextureSource source,
    const wgpu::Extent2D& video_frame_natural_size,
    const wgpu::Origin2D& origin,
    const wgpu::Extent3D& copy_size,
    const wgpu::ImageCopyTexture& destination,
    bool dst_premultiplied_alpha,
    PredefinedColorSpace dst_color_space,
    bool flipY) {
  CHECK(source.valid);

  // Create External Texture with dst color space. No color space conversion
  // happens during copy step.
  ExternalTexture external_texture =
      CreateExternalTexture(device_, dst_color_space, source.media_video_frame,
                            source.video_renderer);

  wgpu::CopyTextureForBrowserOptions options = {
      // Extracting contents from HTMLVideoElement (e.g.
      // CreateStaticBitmapImage(),
      // GetSourceImageForCanvas) always assume alpha mode as premultiplied.
      // Keep this assumption here.
      .srcAlphaMode = wgpu::AlphaMode::Premultiplied,
      .dstAlphaMode = dst_premultiplied_alpha
                          ? wgpu::Alpha
```