Response:
Let's break down the thought process for analyzing the `external_texture_helper.cc` file.

**1. Initial Understanding of the File's Purpose:**

The file name `external_texture_helper.cc` immediately suggests it deals with "external textures" in the context of WebGPU within the Blink rendering engine. The `.cc` extension confirms it's a C++ source file. The inclusion of `<third_party/blink/renderer/modules/webgpu/...>` further reinforces its role within the WebGPU module.

**2. Identifying Key Functionalities by Examining Includes and Namespaces:**

* **Includes:**  The `#include` directives are a goldmine of information. I'd go through them, noting the areas each header relates to:
    * `media/base/video_frame.h`, `media/base/video_transformation.h`, `media/renderers/paint_canvas_video_renderer.h`: Indicate interaction with media (video) processing.
    * `third_party/blink/renderer/core/html/media/html_video_element.h`: Points to handling HTML `<video>` elements.
    * `third_party/blink/renderer/modules/webcodecs/video_frame.h`:  Suggests integration with the WebCodecs API.
    * `third_party/blink/renderer/modules/webgpu/*`:  Confirms this file is central to WebGPU external texture handling. Specific headers like `dawn_conversions.h`, `gpu_adapter.h`, `gpu_device.h`, `gpu_texture.h`, `gpu_texture_view.h` give insights into the WebGPU API elements involved.
    * `third_party/blink/renderer/platform/graphics/*`:  Signifies interaction with graphics-related platform functionalities, including canvas and GPU contexts (`canvas_color_params.h`, `canvas_resource_provider.h`, `gpu/shared_gpu_context.h`, `gpu/webgpu_mailbox_texture.h`).
    * `third_party/blink/renderer/platform/graphics/video_frame_image_util.h`: More evidence of video frame to image manipulation.
    * `third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h`: Hints at the use of tracing for performance analysis.
    * `third_party/skia/include/effects/SkColorMatrix.h`, `third_party/skia/modules/skcms/skcms.h`: Indicates the use of the Skia graphics library for color space management.

* **Namespaces:** The `namespace blink { namespace { ... } namespace blink {` structure shows the code belongs to the `blink` namespace, with an anonymous namespace for internal helper functions.

**3. Analyzing the Functions and their Logic:**

* **Helper Functions in the Anonymous Namespace:**  I would examine functions like `FromVideoRotation` and `DstColorSpaceSupportedByZeroCopy`. These appear to be internal utility functions. `FromVideoRotation` clearly maps media video rotation enums to WebGPU equivalents. `DstColorSpaceSupportedByZeroCopy` checks for specific color spaces supported by a "zero-copy" path. This immediately raises the question: what is the zero-copy path?

* **Key Public Functions:**  Focus on the functions exposed outside the anonymous namespace:
    * `GetYUVToRGBMatrix`:  Calculates a matrix for converting YUV color spaces to RGB. The use of Skia's `SkColorMatrix` is evident.
    * `GetColorSpaceConversionConstants`: Computes constants for converting between different RGB color spaces. The manipulation of Skia's color space matrices (`skcms_Matrix3x3`) is central here.
    * `IsSameGamutAndGamma`: Checks if two color spaces have the same gamut and gamma.
    * `GetExternalTextureSourceFromVideoElement`: Extracts video frame information from an `HTMLVideoElement`. It performs security checks (cross-origin) and retrieves the current video frame.
    * `GetExternalTextureSourceFromVideoFrame`:  Similar to the above, but takes a `VideoFrame` directly.
    * `CreateExternalTexture`: This is the core function. It takes a `GPUDevice`, a destination color space, and a video frame (and optionally a renderer). It seems responsible for creating the actual WebGPU external texture.

**4. Identifying the "Zero-Copy" Path and the "One-Copy" Path:**

The code clearly distinguishes between a "zero-copy" path and a fallback path (which I'd refer to as "one-copy" or "copy" path).

* **Zero-Copy:** The condition `media_video_frame->HasSharedImage() && (media_video_frame->format() == media::PIXEL_FORMAT_NV12) && device_support_zero_copy && media_video_frame->metadata().is_webgpu_compatible && DstColorSpaceSupportedByZeroCopy(dst_predefined_color_space)` defines the criteria for this path. This suggests directly using a shared image for efficiency, particularly for NV12 format. The code involving `WebGPUMailboxTexture::FromVideoFrame` confirms this.

* **One-Copy (Fallback):** If the zero-copy conditions are not met, the code falls back to using `PaintCanvasVideoRenderer` to draw the video frame onto a canvas-backed texture. The use of `RecyclableCanvasResource` and `WebGPUMailboxTexture::FromCanvasResource` indicates this. The code comments highlight trade-offs and potential improvements in this path.

**5. Relating to JavaScript, HTML, and CSS:**

* **JavaScript:** The interaction with the WebGPU API (`GPUDevice`, `GPUTexture`, `GPUTextureView`, `GPUExternalTexture`) is the primary link to JavaScript. The `navigator.gpu` API in JavaScript allows access to WebGPU functionality, including creating external textures from `<video>` elements or `VideoFrame` objects.
* **HTML:**  The `GetExternalTextureSourceFromVideoElement` function directly deals with `<video>` elements, demonstrating the connection. The external texture can then be used in WebGPU rendering pipelines to display video content on canvases or other surfaces.
* **CSS:** While this file doesn't directly manipulate CSS, the visual output of WebGPU rendering (including video textures) can be styled and positioned using CSS. For instance, a `<canvas>` element displaying a WebGPU scene with a video texture would be subject to CSS styling.

**6. Considering User/Programming Errors and Debugging:**

I'd look for potential error conditions:

* **Missing Video Source:**  The checks in `GetExternalTextureSourceFromVideoElement` and `GetExternalTextureSourceFromVideoFrame` for null pointers and the throwing of `DOMException` indicate handling of missing video sources.
* **Cross-Origin Taint:** The security check for `video->WouldTaintOrigin()` is important.
* **Zero-Sized Frames:** The check for zero-sized video frames in `GetExternalTextureSourceFromVideoFrame` prevents issues with invalid input.
* **Context Loss:** The code checks for lost GPU contexts.
* **Unsupported Formats/Color Spaces:** The limitations of the zero-copy and one-copy paths with respect to video formats and color spaces are important to note as potential sources of errors or unexpected behavior.

**7. Tracing User Operations and Debugging:**

I'd think about the typical user flow:

1. User loads an HTML page with a `<video>` element.
2. JavaScript code uses the WebGPU API (`navigator.gpu`).
3. The JavaScript calls a method to create an external texture, passing the `<video>` element or a `VideoFrame`.
4. The browser's rendering engine (Blink) calls into the C++ WebGPU implementation, eventually reaching the code in `external_texture_helper.cc`.
5. The functions in this file handle the creation of the `GPUExternalTexture` based on the provided video source.

For debugging, I'd look for log messages, use WebGPU debugging tools, and potentially set breakpoints in this C++ code to understand the flow and identify issues.

By following these steps, I can systematically analyze the code, understand its purpose, identify its relationships to web technologies, and anticipate potential issues and debugging strategies.
这个文件 `blink/renderer/modules/webgpu/external_texture_helper.cc` 的主要功能是 **帮助 WebGPU 从外部资源（主要是视频帧）创建和管理外部纹理 (External Texture)**。 外部纹理允许 WebGPU shader 访问和采样来自非 WebGPU 创建的纹理数据，例如来自 `<video>` 元素或 WebCodecs `VideoFrame` 的视频帧。

以下是该文件的功能列表：

**核心功能:**

1. **从视频源创建外部纹理:**
   - 提供了从 `HTMLVideoElement` 和 WebCodecs `VideoFrame` 创建 WebGPU `GPUExternalTexture` 的功能。
   - `GetExternalTextureSourceFromVideoElement`:  接收一个 `HTMLVideoElement`，检查其是否可以作为外部纹理的来源（例如，没有跨域污染），并提取当前的视频帧。
   - `GetExternalTextureSourceFromVideoFrame`: 接收一个 WebCodecs `VideoFrame`，并检查其是否可以作为外部纹理的来源。
   - `CreateExternalTexture`:  这是创建 `GPUExternalTexture` 的核心函数。它接收一个 `GPUDevice`、目标颜色空间以及视频帧数据。它会根据视频帧的特性和设备的 capabilities 选择合适的创建路径（零拷贝或拷贝）。

2. **处理视频帧的各种属性:**
   - **颜色空间转换:**  处理源视频帧和目标 WebGPU 纹理之间的颜色空间差异，进行必要的转换。使用了 Skia 库进行颜色空间矩阵计算。
   - `GetYUVToRGBMatrix`:  计算 YUV 到 RGB 的转换矩阵。
   - `GetColorSpaceConversionConstants`:  计算更通用的颜色空间转换常量。
   - `IsSameGamutAndGamma`:  判断两个颜色空间是否具有相同的色域和 Gamma 值，这可以用于优化，跳过不必要的颜色空间转换。
   - **视频变换:**  考虑视频帧的旋转和镜像变换，并将其应用到 `GPUExternalTexture` 的描述符中。
   - `FromVideoRotation`: 将媒体库的视频旋转枚举转换为 WebGPU 的枚举。
   - **可见区域和自然大小:**  处理视频帧的可见区域 (`visible_rect`) 和自然大小 (`natural_size`)，这会影响 WebGPU shader 如何采样纹理。

3. **实现零拷贝路径 (Zero-Copy Path):**
   - 尝试利用零拷贝机制，直接将视频帧的共享内存映射到 WebGPU 纹理，避免不必要的内存拷贝，提高性能。
   - 这通常依赖于特定的视频帧格式 (例如 NV12)、设备的支持以及目标颜色空间。
   - 使用 `WebGPUMailboxTexture` 来封装共享的视频帧数据。
   - `DstColorSpaceSupportedByZeroCopy`:  判断目标颜色空间是否支持零拷贝路径。

4. **实现拷贝路径 (Copy Path):**
   - 如果零拷贝路径不可用，则会将视频帧数据拷贝到 WebGPU 可用的纹理中。
   - 使用 `PaintCanvasVideoRenderer` 将视频帧绘制到 `CanvasResourceProvider` 提供的可回收资源上。
   - 同样使用 `WebGPUMailboxTexture` 来封装拷贝后的纹理数据。

**与 JavaScript, HTML, CSS 的关系:**

该文件是 Chromium 渲染引擎内部实现，直接与 JavaScript 的 WebGPU API 交互，并处理来自 HTML `<video>` 元素的内容。

* **JavaScript:**
    - **`navigator.gpu.importExternalTexture()`:**  JavaScript 代码会调用这个 WebGPU API 来创建外部纹理。这个 API 的实现最终会调用到 `external_texture_helper.cc` 中的函数。
    - **`HTMLVideoElement`:**  JavaScript 可以获取一个 `<video>` 元素的引用，并将其传递给 `importExternalTexture()`。
    - **`VideoFrame` (WebCodecs API):**  JavaScript 可以使用 WebCodecs API 解码视频帧，并将 `VideoFrame` 对象传递给 `importExternalTexture()`。

    **举例说明:**

    ```javascript
    const videoElement = document.getElementById('myVideo');
    const gpu = navigator.gpu;
    const device = await gpu.requestAdapter().requestDevice();

    const externalTexture = device.importExternalTexture({
      source: videoElement
    });

    // 在渲染管线中使用 externalTexture
    ```

* **HTML:**
    - **`<video>` 元素:**  该文件直接处理来自 HTML `<video>` 元素作为外部纹理源的情况.

    **举例说明:**

    ```html
    <video id="myVideo" src="my-video.mp4" autoplay muted></video>
    ```

* **CSS:**
    - 虽然该文件本身不直接涉及 CSS，但通过 WebGPU 创建的包含外部纹理的渲染结果最终会显示在 HTML 页面上，其布局和样式可以通过 CSS 进行控制。例如，可以将包含渲染结果的 `<canvas>` 元素进行定位、缩放等。

    **举例说明:**

    ```css
    #myCanvas {
      width: 640px;
      height: 480px;
    }
    ```

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **`GetExternalTextureSourceFromVideoElement`:**
   - **输入:** 一个 HTML `<video>` 元素，其 `src` 属性指向一个有效的视频文件，并且视频已经加载了一些帧。
   - **输出:** 一个 `ExternalTextureSource` 结构体，包含指向当前视频帧的指针 (`media_video_frame`) 和一个用于渲染视频的 `PaintCanvasVideoRenderer` 指针。 `valid` 标志为 `true`。

2. **`CreateExternalTexture` (零拷贝路径):**
   - **输入:**
     - 一个 `GPUDevice` 对象。
     - 目标颜色空间 `PredefinedColorSpace::kSRGB`.
     - 一个 NV12 格式的 `media::VideoFrame`，具有共享内存，且 `is_webgpu_compatible` 为 `true`。
   - **输出:** 一个 `ExternalTexture` 结构体，其 `wgpu_external_texture` 成员指向一个新创建的 `wgpu::ExternalTexture` 对象，该对象直接映射了视频帧的共享内存。`is_zero_copy` 为 `true`。

3. **`CreateExternalTexture` (拷贝路径):**
   - **输入:**
     - 一个 `GPUDevice` 对象。
     - 目标颜色空间 `PredefinedColorSpace::kRec2020`.
     - 一个非 NV12 格式的 `media::VideoFrame`。
   - **输出:** 一个 `ExternalTexture` 结构体，其 `wgpu_external_texture` 成员指向一个新创建的 `wgpu::ExternalTexture` 对象，该对象的数据来源于将视频帧拷贝到 `CanvasResourceProvider` 提供的纹理。`is_zero_copy` 为 `false`。

**用户或编程常见的使用错误:**

1. **跨域问题:** 用户尝试从一个与当前页面不同源的 `<video>` 元素创建外部纹理，但该视频元素没有设置 CORS 头信息以允许跨域访问。
   - **错误现象:** `GetExternalTextureSourceFromVideoElement` 会抛出一个 `SecurityError`。
   - **代码示例:**
     ```javascript
     const video = document.createElement('video');
     video.src = 'https://another-domain.com/video.mp4'; // 跨域
     const externalTexture = device.importExternalTexture({ source: video }); // 抛出异常
     ```

2. **在视频帧准备好之前尝试创建外部纹理:** 用户可能在视频元素还没有加载任何帧的时候就尝试创建外部纹理。
   - **错误现象:** `GetExternalTextureSourceFromVideoElement` 可能会抛出一个 `DOMException`，因为无法获取有效的视频帧。
   - **代码示例:**
     ```javascript
     const video = document.createElement('video');
     video.src = 'my-video.mp4';
     const externalTexture = device.importExternalTexture({ source: video }); // 可能在视频加载前调用
     ```

3. **使用已被释放的 `VideoFrame`:**  如果用户使用 WebCodecs API，可能会错误地释放了 `VideoFrame` 对象，然后尝试用它创建外部纹理。
   - **错误现象:** `GetExternalTextureSourceFromVideoFrame` 可能会抛出一个 `DOMException`，或者导致程序崩溃，因为访问了无效的内存。

4. **目标颜色空间不支持零拷贝:** 用户指定的目标颜色空间不支持零拷贝路径，但可能期望获得零拷贝的性能。
   - **结果:**  `CreateExternalTexture` 会回退到拷贝路径，性能可能不如预期。开发者需要了解不同颜色空间对零拷贝的支持情况。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页。**
2. **网页的 HTML 包含一个 `<video>` 元素，并设置了 `src` 属性指向视频文件。** 或者，网页使用了 WebCodecs API 来解码视频帧。
3. **网页的 JavaScript 代码使用 WebGPU API。**
4. **JavaScript 代码调用 `navigator.gpu.requestAdapter()` 和 `adapter.requestDevice()` 获取 GPU 设备。**
5. **JavaScript 代码获取 `<video>` 元素的引用 (例如，通过 `document.getElementById()`) 或者创建了一个 `VideoFrame` 对象。**
6. **JavaScript 代码调用 `device.importExternalTexture({ source: videoElement })` 或 `device.importExternalTexture({ source: videoFrame })`。**
7. **浏览器接收到 `importExternalTexture` 的调用，并将其路由到 Chromium 渲染引擎的 WebGPU 实现。**
8. **在 `external_texture_helper.cc` 文件中，相应的函数 (`GetExternalTextureSourceFromVideoElement` 或 `GetExternalTextureSourceFromVideoFrame`) 被调用，以提取视频源信息。**
9. **`CreateExternalTexture` 函数被调用，根据视频源信息和设备 capabilities 创建 `GPUExternalTexture` 对象。** 这可能涉及到零拷贝或拷贝路径。
10. **创建的 `GPUExternalTexture` 对象被返回给 JavaScript 代码。**
11. **JavaScript 代码可以使用这个 `GPUExternalTexture` 在 WebGPU 渲染管线中采样视频帧。**

**调试线索:**

* **控制台错误信息:**  检查浏览器的开发者工具控制台是否有与 WebGPU 或跨域相关的错误信息。
* **WebGPU 调试工具:**  使用 Chrome 的 "WebGPU Internals" 或其他 WebGPU 调试工具，可以查看 `GPUExternalTexture` 的创建和使用情况，以及可能的错误。
* **断点调试:**  如果需要深入了解，可以在 `external_texture_helper.cc` 中的关键函数（如 `GetExternalTextureSourceFromVideoElement`, `CreateExternalTexture`）设置断点，查看代码执行流程和变量值。
* **Trace 事件:**  该文件使用了 `TRACE_EVENT`，可以通过 Chrome 的 tracing 工具 (about:tracing) 收集和分析性能数据，查看 `CreateExternalTexture` 的耗时和选择的路径 (零拷贝或拷贝)。
* **检查视频元素状态:**  在 JavaScript 中检查 `<video>` 元素的状态 (例如，`readyState`, `error`)，确保视频已经加载并且没有错误。
* **检查视频帧信息:**  如果使用 WebCodecs，检查 `VideoFrame` 的格式、颜色空间等属性，确保其符合预期。

通过以上分析，可以了解 `external_texture_helper.cc` 在 WebGPU 中处理外部视频纹理的关键作用，以及其与 Web 技术栈的联系，并能帮助开发者理解可能遇到的问题和调试方向。

Prompt: 
```
这是目录为blink/renderer/modules/webgpu/external_texture_helper.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webgpu/external_texture_helper.h"

#include "media/base/video_frame.h"
#include "media/base/video_transformation.h"
#include "media/renderers/paint_canvas_video_renderer.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/modules/webgpu/dawn_conversions.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_adapter.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_device.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_supported_features.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_texture.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_texture_view.h"
#include "third_party/blink/renderer/platform/graphics/canvas_color_params.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/gpu/webgpu_mailbox_texture.h"
#include "third_party/blink/renderer/platform/graphics/video_frame_image_util.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/skia/include/effects/SkColorMatrix.h"
#include "third_party/skia/modules/skcms/skcms.h"

namespace blink {
namespace {
wgpu::ExternalTextureRotation FromVideoRotation(media::VideoRotation rotation) {
  switch (rotation) {
    case media::VIDEO_ROTATION_0:
      return wgpu::ExternalTextureRotation::Rotate0Degrees;
    case media::VIDEO_ROTATION_90:
      return wgpu::ExternalTextureRotation::Rotate90Degrees;
    case media::VIDEO_ROTATION_180:
      return wgpu::ExternalTextureRotation::Rotate180Degrees;
    case media::VIDEO_ROTATION_270:
      return wgpu::ExternalTextureRotation::Rotate270Degrees;
  }
  NOTREACHED();
}

// TODO(crbug.com/40227105): Support HDR color space and color range in
// generated wgsl shader to enable all color space for zero-copy path.
bool DstColorSpaceSupportedByZeroCopy(
    PredefinedColorSpace dst_predefined_color_space) {
  switch (dst_predefined_color_space) {
    case PredefinedColorSpace::kSRGB:
    case PredefinedColorSpace::kP3:
      return true;
    default:
      break;
  }
  return false;
}
}  // namespace

std::array<float, 12> GetYUVToRGBMatrix(gfx::ColorSpace color_space,
                                        size_t bit_depth) {
  // Get the appropriate YUV to RGB conversion matrix.
  SkYUVColorSpace src_sk_color_space;
  color_space.ToSkYUVColorSpace(static_cast<int>(bit_depth),
                                &src_sk_color_space);
  SkColorMatrix sk_color_matrix = SkColorMatrix::YUVtoRGB(src_sk_color_space);
  float yuv_matrix[20];
  sk_color_matrix.getRowMajor(yuv_matrix);
  // Only use columns 1-3 (3x3 conversion matrix) and column 5 (bias values)
  return std::array<float, 12>{yuv_matrix[0],  yuv_matrix[1],  yuv_matrix[2],
                               yuv_matrix[4],  yuv_matrix[5],  yuv_matrix[6],
                               yuv_matrix[7],  yuv_matrix[9],  yuv_matrix[10],
                               yuv_matrix[11], yuv_matrix[12], yuv_matrix[14]};
}

ColorSpaceConversionConstants GetColorSpaceConversionConstants(
    gfx::ColorSpace src_color_space,
    gfx::ColorSpace dst_color_space) {
  ColorSpaceConversionConstants color_space_conversion_constants;
  // Get primary matrices for the source and destination color spaces.
  // Multiply the source primary matrix with the inverse destination primary
  // matrix to create a single transformation matrix.
  skcms_Matrix3x3 src_primary_matrix_to_XYZD50;
  skcms_Matrix3x3 dst_primary_matrix_to_XYZD50;
  src_color_space.GetPrimaryMatrix(&src_primary_matrix_to_XYZD50);
  dst_color_space.GetPrimaryMatrix(&dst_primary_matrix_to_XYZD50);

  skcms_Matrix3x3 dst_primary_matrix_from_XYZD50;
  skcms_Matrix3x3_invert(&dst_primary_matrix_to_XYZD50,
                         &dst_primary_matrix_from_XYZD50);

  skcms_Matrix3x3 transform_matrix = skcms_Matrix3x3_concat(
      &dst_primary_matrix_from_XYZD50, &src_primary_matrix_to_XYZD50);
  // From row major matrix to col major matrix
  // SAFETY: skcms_Matrix3x3_concat always creates 3x3 array
  color_space_conversion_constants.gamut_conversion_matrix =
      UNSAFE_BUFFERS(std::array<float, 9>{
          transform_matrix.vals[0][0], transform_matrix.vals[1][0],
          transform_matrix.vals[2][0], transform_matrix.vals[0][1],
          transform_matrix.vals[1][1], transform_matrix.vals[2][1],
          transform_matrix.vals[0][2], transform_matrix.vals[1][2],
          transform_matrix.vals[2][2]});

  // Set constants for source transfer function.
  skcms_TransferFunction src_transfer_fn;
  src_color_space.GetTransferFunction(&src_transfer_fn);
  color_space_conversion_constants.src_transfer_constants =
      std::array<float, 7>{src_transfer_fn.g, src_transfer_fn.a,
                           src_transfer_fn.b, src_transfer_fn.c,
                           src_transfer_fn.d, src_transfer_fn.e,
                           src_transfer_fn.f};

  // Set constants for destination transfer function.
  skcms_TransferFunction dst_transfer_fn;
  dst_color_space.GetInverseTransferFunction(&dst_transfer_fn);
  color_space_conversion_constants.dst_transfer_constants =
      std::array<float, 7>{dst_transfer_fn.g, dst_transfer_fn.a,
                           dst_transfer_fn.b, dst_transfer_fn.c,
                           dst_transfer_fn.d, dst_transfer_fn.e,
                           dst_transfer_fn.f};

  return color_space_conversion_constants;
}

bool IsSameGamutAndGamma(gfx::ColorSpace src_color_space,
                         gfx::ColorSpace dst_color_space) {
  if (src_color_space.GetPrimaryID() == dst_color_space.GetPrimaryID()) {
    skcms_TransferFunction src;
    skcms_TransferFunction dst;
    if (src_color_space.GetTransferFunction(&src) &&
        dst_color_space.GetTransferFunction(&dst)) {
      return (src.a == dst.a && src.b == dst.b && src.c == dst.c &&
              src.d == dst.d && src.e == dst.e && src.f == dst.f &&
              src.g == dst.g);
    }
  }
  return false;
}

ExternalTextureSource GetExternalTextureSourceFromVideoElement(
    HTMLVideoElement* video,
    ExceptionState& exception_state) {
  ExternalTextureSource source;

  if (!video) {
    exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                      "Missing video source");
    return source;
  }

  if (video->WouldTaintOrigin()) {
    exception_state.ThrowSecurityError(
        "Video element is tainted by cross-origin data and may not be "
        "loaded.");
    return source;
  }

  if (auto* wmp = video->GetWebMediaPlayer()) {
    source.media_video_frame = wmp->GetCurrentFrameThenUpdate();
    source.video_renderer = wmp->GetPaintCanvasVideoRenderer();
  }

  if (!source.media_video_frame) {
    exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                      "Failed to import texture from video "
                                      "element that doesn't have back "
                                      "resource.");
    return source;
  }

  source.media_video_frame_unique_id = source.media_video_frame->unique_id();
  source.valid = true;

  return source;
}

ExternalTextureSource GetExternalTextureSourceFromVideoFrame(
    VideoFrame* frame,
    ExceptionState& exception_state) {
  ExternalTextureSource source;

  if (!frame) {
    exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                      "Missing video frame");
    return source;
  }
  // Tainted blink::VideoFrames are not supposed to be possible.
  DCHECK(!frame->WouldTaintOrigin());

  source.media_video_frame = frame->frame();
  if (!source.media_video_frame) {
    exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                      "Failed to import texture from video "
                                      "frame that doesn't have back resource");
    return source;
  }

  if (!source.media_video_frame->coded_size().width() ||
      !source.media_video_frame->coded_size().height()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kOperationError,
        "Cannot import from zero sized video frame");
    return source;
  }

  source.valid = true;

  return source;
}

ExternalTexture CreateExternalTexture(
    GPUDevice* device,
    PredefinedColorSpace dst_predefined_color_space,
    scoped_refptr<media::VideoFrame> media_video_frame,
    media::PaintCanvasVideoRenderer* video_renderer) {
  DCHECK(media_video_frame);
  gfx::ColorSpace src_color_space = media_video_frame->ColorSpace();
  gfx::ColorSpace dst_color_space =
      PredefinedColorSpaceToGfxColorSpace(dst_predefined_color_space);

  // It should be very rare that a frame didn't get a valid colorspace through
  // the guessing process:
  // https://source.chromium.org/chromium/chromium/src/+/main:media/base/video_color_space.cc;l=69;drc=6c9cfff09be8397270b376a4e4407328694e97fa
  // The historical rule for this was to use BT.601 for SD content and BT.709
  // for HD content:
  // https://source.chromium.org/chromium/chromium/src/+/main:media/ffmpeg/ffmpeg_common.cc;l=683;drc=1946212ac0100668f14eb9e2843bdd846e510a1e)
  // We prefer always using BT.709 since SD content in practice is down-scaled
  // HD content, not NTSC broadcast content.
  if (!src_color_space.IsValid()) {
    src_color_space = gfx::ColorSpace::CreateREC709();
  }

  ExternalTexture external_texture = {};

  // TODO(crbug.com/1306753): Use SharedImageProducer and CompositeSharedImage
  // rather than check 'is_webgpu_compatible'.
  bool device_support_zero_copy =
      device->adapter()->SupportsMultiPlanarFormats();

  wgpu::ExternalTextureDescriptor external_texture_desc = {};

  // Set the ExternalTexture cropSize/Origin and apparentSize. The 0-copy path
  // uses this metadata.
  gfx::Rect visible_rect = media_video_frame->visible_rect();
  gfx::Size natural_size = media_video_frame->natural_size();
  DCHECK(visible_rect.x() >= 0 && visible_rect.y() >= 0 &&
         visible_rect.width() >= 0 && visible_rect.height() >= 0);
  DCHECK(natural_size.width() >= 0 && natural_size.height() >= 0);

  // TODO(377574981): Remove once Dawn starts using cropSize/Origin and
  // apparentSize;
  external_texture_desc.visibleOrigin = {
      static_cast<uint32_t>(visible_rect.x()),
      static_cast<uint32_t>(visible_rect.y())};
  external_texture_desc.visibleSize = {
      static_cast<uint32_t>(visible_rect.width()),
      static_cast<uint32_t>(visible_rect.height())};

  // The visible_rect denotes the part of the coded image that's visible when
  // displaying the frame. For Dawn it is considered as a crop rectangle applied
  // in plane0 (and adapted for plane1 if present).
  external_texture_desc.cropOrigin = {static_cast<uint32_t>(visible_rect.x()),
                                      static_cast<uint32_t>(visible_rect.y())};
  external_texture_desc.cropSize = {
      static_cast<uint32_t>(visible_rect.width()),
      static_cast<uint32_t>(visible_rect.height())};

  // The natural_size is shown as VideoFrame.displayWidth/Height in JS and
  // WebGPU requires that the imported GPUExternalTexture appears to be that
  // size when used in WGSL. It is the apparent size of the texture from the
  // perspective of the WGSL author.
  external_texture_desc.apparentSize = {
      static_cast<uint32_t>(natural_size.width()),
      static_cast<uint32_t>(natural_size.height())};

  // Set ExternalTexture rotation and mirrored state.
  const media::VideoFrameMetadata& metadata = media_video_frame->metadata();
  if (metadata.transformation) {
    external_texture_desc.rotation =
        FromVideoRotation(metadata.transformation->rotation);
    external_texture_desc.mirrored = metadata.transformation->mirrored;
  }

  const bool zero_copy =
      (media_video_frame->HasSharedImage() &&
       (media_video_frame->format() == media::PIXEL_FORMAT_NV12) &&
       device_support_zero_copy &&
       media_video_frame->metadata().is_webgpu_compatible &&
       DstColorSpaceSupportedByZeroCopy(dst_predefined_color_space));

  TRACE_EVENT_INSTANT2(TRACE_DISABLED_BY_DEFAULT("webgpu"),
                       "CreateExternalTexture", TRACE_EVENT_SCOPE_THREAD,
                       "zero_copy", !!zero_copy, "video_frame",
                       media_video_frame->AsHumanReadableString());
  if (zero_copy) {
    scoped_refptr<WebGPUMailboxTexture> mailbox_texture =
        WebGPUMailboxTexture::FromVideoFrame(
            device->GetDawnControlClient(), device->GetHandle(),
            wgpu::TextureUsage::TextureBinding, media_video_frame);
    if (!mailbox_texture) {
      return {};
    }

    wgpu::TextureViewDescriptor view_desc = {
        .format = wgpu::TextureFormat::R8Unorm,
        .aspect = wgpu::TextureAspect::Plane0Only};
    wgpu::TextureView plane0 =
        mailbox_texture->GetTexture().CreateView(&view_desc);
    view_desc.format = wgpu::TextureFormat::RG8Unorm;
    view_desc.aspect = wgpu::TextureAspect::Plane1Only;
    wgpu::TextureView plane1 =
        mailbox_texture->GetTexture().CreateView(&view_desc);

    // Set Planes for ExternalTexture
    external_texture_desc.plane0 = plane0;
    external_texture_desc.plane1 = plane1;

    // Set color space transformation metas for ExternalTexture
    std::array<float, 12> yuvToRgbMatrix =
        GetYUVToRGBMatrix(src_color_space, media_video_frame->BitDepth());
    external_texture_desc.yuvToRgbConversionMatrix = yuvToRgbMatrix.data();

    // Decide whether color space conversion could be skipped.
    external_texture_desc.doYuvToRgbConversionOnly =
        IsSameGamutAndGamma(src_color_space, dst_color_space);

    ColorSpaceConversionConstants color_space_conversion_constants =
        GetColorSpaceConversionConstants(src_color_space, dst_color_space);

    external_texture_desc.gamutConversionMatrix =
        color_space_conversion_constants.gamut_conversion_matrix.data();
    external_texture_desc.srcTransferFunctionParameters =
        color_space_conversion_constants.src_transfer_constants.data();
    external_texture_desc.dstTransferFunctionParameters =
        color_space_conversion_constants.dst_transfer_constants.data();

    external_texture.wgpu_external_texture =
        device->GetHandle().CreateExternalTexture(&external_texture_desc);

    external_texture.mailbox_texture = std::move(mailbox_texture);
    external_texture.is_zero_copy = true;
    return external_texture;
  }
  // If the context is lost, the resource provider would be invalid.
  auto context_provider_wrapper = SharedGpuContext::ContextProviderWrapper();
  if (!context_provider_wrapper ||
      context_provider_wrapper->ContextProvider()->IsContextLost())
    return external_texture;

  // In 0-copy path, uploading shares the whole frame into dawn and apply
  // visible rect and sample from it. For 1-copy path, we should obey the
  // same behaviour by:
  // - Get recycle cache with video frame visible size.
  // - Draw video frame visible rect into recycle cache, uses visible size.
  // - Reset origin of visible rect in ExternalTextureDesc and use internal
  // shader to
  //   handle visible rect.
  external_texture_desc.visibleOrigin = {};
  external_texture_desc.cropOrigin = {};

  std::unique_ptr<media::PaintCanvasVideoRenderer> local_video_renderer;
  if (!video_renderer) {
    local_video_renderer = std::make_unique<media::PaintCanvasVideoRenderer>();
    video_renderer = local_video_renderer.get();
  }

  // Using CopyVideoFrameToSharedImage() is an optional one copy upload path.
  // However, the formats this path supports are quite limited. Check whether
  // the current video frame could be uploaded through this one copy upload
  // path. If not, fallback to DrawVideoFrameIntoResourceProvider().
  // CopyVideoFrameToSharedImage also doesn't support rescaling the image so we
  // cannot use it if the visible_rect isn't the same size as natural_size.
  // TODO(crbug.com/327270287): Expand CopyVideoFrameToSharedImage() to
  // support all valid video frame formats and remove the draw path.
  bool use_copy_to_shared_image =
      video_renderer->CanUseCopyVideoFrameToSharedImage(*media_video_frame) &&
      visible_rect.size() == natural_size;

  // Get a recyclable resource for producing WebGPU-compatible shared images.
  // The recyclable resource's color space is the same as source color space
  // with the YUV to RGB transform stripped out since that's handled by the
  // PaintCanvasVideoRenderer.
  gfx::ColorSpace resource_color_space = src_color_space.GetAsRGB();

  // Using DrawVideoFrameIntoResourceProvider() for uploading. Need to
  // workaround issue crbug.com/1407112. It requires no color space
  // conversion when drawing video frame to resource provider.
  // Leverage Dawn to do the color space conversion.
  // TODO(crbug.com/1407112): Don't use compatRgbColorSpace but the
  // exact color space after fixing this issue.
  if (!use_copy_to_shared_image) {
    resource_color_space = media_video_frame->CompatRGBColorSpace();
  }

  std::unique_ptr<RecyclableCanvasResource> recyclable_canvas_resource =
      device->GetDawnControlClient()->GetOrCreateCanvasResource(
          SkImageInfo::MakeN32Premul(natural_size.width(),
                                     natural_size.height(),
                                     resource_color_space.ToSkColorSpace()));
  if (!recyclable_canvas_resource) {
    return external_texture;
  }

  CanvasResourceProvider* resource_provider =
      recyclable_canvas_resource->resource_provider();
  DCHECK(resource_provider);

  viz::RasterContextProvider* raster_context_provider =
      context_provider_wrapper->ContextProvider()->RasterContextProvider();

  if (use_copy_to_shared_image) {
    // We don't need to specify a sync token since both CanvasResourceProvider
    // and PaintCanvasVideoRenderer use the SharedGpuContext.
    auto client_si =
        resource_provider->GetBackingClientSharedImageForOverwrite();
    gpu::MailboxHolder dst_mailbox(
        client_si ? client_si->mailbox() : gpu::Mailbox(), gpu::SyncToken(),
        client_si ? client_si->GetTextureTarget() : GL_TEXTURE_2D);

    // The returned sync token is from the SharedGpuContext - it's ok to drop it
    // here since WebGPUMailboxTexture::FromCanvasResource will generate a new
    // sync token from the SharedContextState and wait on it anyway.
    std::ignore = video_renderer->CopyVideoFrameToSharedImage(
        raster_context_provider, std::move(media_video_frame), dst_mailbox,
        /*use_visible_rect=*/true);
  } else {
    const gfx::Rect dest_rect = gfx::Rect(media_video_frame->natural_size());
    // Delegate video transformation to Dawn.
    if (!DrawVideoFrameIntoResourceProvider(
            std::move(media_video_frame), resource_provider,
            raster_context_provider, dest_rect, video_renderer,
            /* ignore_video_transformation */ true)) {
      return {};
    }
  }

  scoped_refptr<WebGPUMailboxTexture> mailbox_texture =
      WebGPUMailboxTexture::FromCanvasResource(
          device->GetDawnControlClient(), device->GetHandle(),
          wgpu::TextureUsage::TextureBinding,
          std::move(recyclable_canvas_resource));
  if (!mailbox_texture) {
    return {};
  }

  wgpu::TextureViewDescriptor view_desc = {};
  wgpu::TextureView plane0 =
      mailbox_texture->GetTexture().CreateView(&view_desc);

  // Set plane for ExternalTexture
  external_texture_desc.plane0 = plane0;

  // Decide whether color space conversion could be skipped.
  external_texture_desc.doYuvToRgbConversionOnly =
      IsSameGamutAndGamma(resource_color_space, dst_color_space);

  // Set color space transformation metas for ExternalTexture
  ColorSpaceConversionConstants color_space_conversion_constants =
      GetColorSpaceConversionConstants(resource_color_space, dst_color_space);

  external_texture_desc.gamutConversionMatrix =
      color_space_conversion_constants.gamut_conversion_matrix.data();
  external_texture_desc.srcTransferFunctionParameters =
      color_space_conversion_constants.src_transfer_constants.data();
  external_texture_desc.dstTransferFunctionParameters =
      color_space_conversion_constants.dst_transfer_constants.data();

  external_texture.wgpu_external_texture =
      device->GetHandle().CreateExternalTexture(&external_texture_desc);
  external_texture.mailbox_texture = std::move(mailbox_texture);

  return external_texture;
}

}  // namespace blink

"""

```