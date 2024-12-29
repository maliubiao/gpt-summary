Response:
Let's break down the thought process for analyzing this code snippet and generating the summary.

**1. Understanding the Request:**

The core request is to analyze a C++ file (`video_frame.cc`) from the Chromium Blink engine, specifically focusing on its functionalities, relationships to web technologies (JavaScript, HTML, CSS), providing examples, illustrating potential errors, outlining user interaction leading to this code, and finally, summarizing its functions. The request emphasizes this is part 1 of 2, hinting at further analysis later.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code, looking for key terms and patterns. This involves noticing:

* **Includes:**  Headers like `video_frame.h`, `media/base/video_frame.h`, `v8_video_frame*.h`, `html/canvas/`, `imagebitmap/`, indicating the file deals with video frames, their representation in the media layer, integration with JavaScript via V8 bindings, and interaction with canvas and image bitmap APIs.
* **Namespaces:** `blink`, indicating this is part of the Blink rendering engine.
* **Class Definition:** The central class `VideoFrame`.
* **Static Methods:**  `Create()`, hinting at how `VideoFrame` objects are instantiated.
* **Methods related to copying:** `CopyTo()`, `convertToCanvasImageBitmap()`, suggesting functionality for transferring video frame data.
* **Methods retrieving information:** `format()`, `codedWidth()`, `codedHeight()`, `timestamp()`, etc.
* **Comments:**  Look for any helpful explanations within the code itself. For example, the `// Copyright` and `// TODO` comments are informative but not directly functional.
* **Feature Flags:**  `BASE_FEATURE(kVideoFrameAsyncCopyTo, ...)`, indicating conditional functionality.
* **Helper Functions:**  Functions like `ToMediaPixelFormat`, `ToV8VideoPixelFormat`, `CopyMappablePlanes`, `CopyTexturablePlanes`, `ParseCopyToOptions`, suggesting internal logic for format conversion and data manipulation.
* **Cached Resource Management:** The presence of `CachedVideoFramePool` and `CanvasResourceProviderCache` classes, suggesting optimization techniques.
* **JavaScript Bindings:**  The inclusion of `v8_*.h` files strongly suggests the file is responsible for bridging the gap between C++ video frame objects and their JavaScript counterparts.

**3. Identifying Core Functionalities:**

Based on the initial scan, we can start to identify the main responsibilities of `video_frame.cc`:

* **Creation of `VideoFrame` objects:** The `Create()` method handles this, taking various sources like `<video>`, `<canvas>`, `ImageBitmap`, and even other `VideoFrame` objects.
* **Accessing `VideoFrame` properties:** Methods like `format()`, `codedWidth()`, `timestamp()`, etc., provide access to the underlying video frame data and metadata.
* **Copying `VideoFrame` data:** The `CopyTo()` and `convertToCanvasImageBitmap()` methods enable transferring the video frame's pixel data to other buffers or `ImageBitmap` objects.
* **Managing underlying `media::VideoFrame`:** The code interacts extensively with `media::VideoFrame`, indicating that `blink::VideoFrame` is a wrapper or bridge to the media layer's video frame representation.
* **Resource Management:** The cached pools suggest optimizing the creation and management of `media::VideoFrame` and `CanvasResourceProvider` objects.
* **Integration with Web APIs:**  The file connects video frames to JavaScript via the WebCodecs API and enables their use in `<canvas>` and `ImageBitmap`.

**4. Analyzing Interactions with Web Technologies:**

Now, let's consider how this C++ code relates to JavaScript, HTML, and CSS:

* **JavaScript:** The presence of V8 bindings (`v8_*.h`) is a clear indicator. The `Create()` method is directly called from JavaScript when a `VideoFrame` is constructed. Methods like `CopyTo()` and `convertToCanvasImageBitmap()` are exposed to JavaScript.
* **HTML:** The code handles creating `VideoFrame` from `<video>` elements, accessing their video frames.
* **CSS:**  While not directly manipulating CSS, the visual representation of video frames (e.g., in a `<video>` element or drawn on a `<canvas>`) is ultimately influenced by CSS styling. The code is part of the rendering pipeline that makes this visual presentation possible.

**5. Constructing Examples and Scenarios:**

To further illustrate the functionalities, we can create examples:

* **JavaScript Creation:**  Show how to create a `VideoFrame` from a `<video>` element and specify properties like `timestamp`.
* **`CopyTo()` Usage:** Demonstrate copying a `VideoFrame`'s data to an `ArrayBuffer`.
* **`convertToCanvasImageBitmap()` Usage:**  Illustrate creating an `ImageBitmap` from a `VideoFrame`.

**6. Identifying Potential Errors:**

Consider common mistakes developers might make:

* **Incorrect `timestamp`:**  Forgetting to provide or providing an invalid timestamp during `VideoFrame` creation.
* **Mismatched formats in `CopyTo()`:** Trying to copy to an unsupported format.
* **Invalid `rect` in `CopyTo()`:** Providing a rectangle that goes outside the bounds of the `VideoFrame`.
* **Using a closed `VideoFrame`:** Attempting to call methods on a `VideoFrame` after it has been closed.

**7. Tracing User Operations:**

Think about how a user's actions in a web browser can lead to this code being executed:

* **Playing a video:** The browser fetches and decodes video frames, which can be represented by `media::VideoFrame` and wrapped by `blink::VideoFrame`.
* **Using the WebCodecs API:** JavaScript code explicitly creates and manipulates `VideoFrame` objects using the `VideoFrame` constructor and methods like `CopyTo()`.
* **Drawing video on a canvas:** Using the `drawImage()` method of a canvas with a `<video>` element or a `VideoFrame` as the source.
* **Creating an `ImageBitmap` from a video frame:**  Using `createImageBitmap()` with a `<video>` element or a `VideoFrame`.

**8. Structuring the Summary (Iterative Process):**

Now, organize the gathered information into a coherent summary. This is often an iterative process:

* **Start with a high-level overview:**  What is the primary purpose of the file?
* **Break down into key functions:** List the major functionalities identified earlier.
* **Connect to web technologies:** Explain how these functions relate to JavaScript, HTML, and CSS.
* **Provide concrete examples:**  Illustrate the usage of the key functionalities.
* **Mention potential errors:**  Highlight common pitfalls for developers.
* **Describe user interactions:** Explain how users trigger this code.
* **Refine and organize:** Ensure the summary is clear, concise, and easy to understand.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:**  "This file just manages video frame data."  **Correction:**  Realize it's more than just data; it involves integration with web APIs, resource management, and format conversions.
* **Focusing too much on low-level details:**  **Correction:** Shift the focus to the high-level functionalities and their relevance to web developers.
* **Missing the JavaScript connection:** **Correction:** Emphasize the V8 bindings and how the C++ code is exposed to JavaScript.
* **Overlooking error scenarios:** **Correction:** Actively think about common mistakes developers might make when using the `VideoFrame` API.

By following these steps and iteratively refining the analysis, we can arrive at a comprehensive and informative summary like the example provided in the prompt.
好的，根据您提供的 blink 引擎源代码文件 `blink/renderer/modules/webcodecs/video_frame.cc` 的内容，这是第一部分，我来归纳一下它的功能：

**核心功能：  定义和实现了 JavaScript WebCodecs API 中的 `VideoFrame` 类。**

**详细功能分解：**

1. **作为 JavaScript `VideoFrame` 类的 C++ 实现：**
   - 该文件是 Blink 渲染引擎中 WebCodecs API 的一部分，负责在 C++ 层面实现 `VideoFrame` 这个 JavaScript 可访问的对象。
   - 它桥接了底层的媒体 (media/) 库中的 `media::VideoFrame` 对象，使其能够在 JavaScript 环境中使用。

2. **`VideoFrame` 对象的创建：**
   - 提供了 `Create` 静态方法，允许从多种来源创建 `VideoFrame` 对象，包括：
     - HTML `<img>`, `<video>`, `<canvas>` 元素
     - `ImageBitmap` 对象
     - 另一个 `VideoFrame` 对象
   - 在创建过程中处理各种参数，例如时间戳 (`timestamp`)、持续时间 (`duration`)、裁剪区域 (`visibleRect`)、显示尺寸 (`displayWidth`) 以及可能的旋转和翻转 (`rotation`, `flip`)。
   - 实现了从不同图像源获取图像数据并将其转换为 `media::VideoFrame` 的逻辑。

3. **`VideoFrame` 属性的访问：**
   - 提供了方法来访问 `VideoFrame` 对象的各种属性，例如：
     - 编码宽度 (`codedWidth()`) 和高度 (`codedHeight()`)
     - 可见宽度 (`displayWidth()`) 和高度 (`displayHeight()`)
     - 时间戳 (`timestamp()`) 和持续时间 (`duration()`)
     - 像素格式 (`format()`)
     - 色彩空间 (`colorSpace()`)
     - 是否已关闭 (`closed()`)

4. **`VideoFrame` 数据的复制和转换：**
   - 实现了 `CopyTo()` 方法，允许将 `VideoFrame` 的像素数据复制到 `ArrayBuffer` 中。
   - 实现了 `convertToCanvasImageBitmap()` 方法，允许将 `VideoFrame` 转换为 `ImageBitmap` 对象，以便在 Canvas 2D API 或 WebGL 中使用。
   - 在复制和转换过程中，处理像素格式的转换和颜色空间的管理。

5. **资源管理：**
   - 使用 `CachedVideoFramePool` 和 `CanvasResourceProviderCache` 来缓存 `media::VideoFrame` 和 `CanvasResourceProvider` 对象，以提高性能并减少内存分配开销。
   - 监听 ExecutionContext 的生命周期事件，以便在不再需要时释放缓存的资源。

6. **与图形上下文的交互：**
   - 涉及到与 GPU 图形上下文的交互，例如在 `CopyTo()` 操作中，如果源 `VideoFrame` 存储在 GPU 纹理中，需要从 GPU 读回数据。
   - 使用 `CanvasResourceProvider` 来提供用于在 Canvas 上绘制 `VideoFrame` 的图形资源。

7. **与媒体库的集成：**
   - 紧密依赖于 `media/base/video_frame.h` 中定义的 `media::VideoFrame` 类及其相关类型，例如 `media::VideoPixelFormat` 和 `media::VideoColorSpace`。

8. **支持多种像素格式和颜色空间：**
   - 代码中定义了 JavaScript `VideoPixelFormat` 枚举到 `media::VideoPixelFormat` 的映射。
   - 支持多种 YUV 和 RGB 像素格式，以及高位深格式（如果启用了相应的特性）。
   - 处理 `VideoColorSpace` 相关的初始化和转换。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:**
    ```javascript
    // 从 <video> 元素创建一个 VideoFrame
    const video = document.getElementById('myVideo');
    const videoFrame = new VideoFrame(video, { timestamp: performance.now() });

    // 将 VideoFrame 的数据复制到 ArrayBuffer
    const buffer = new ArrayBuffer(videoFrame.allocationSize());
    videoFrame.copyTo(buffer).then(() => {
      console.log('VideoFrame 数据已复制');
    });

    // 将 VideoFrame 绘制到 Canvas
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    ctx.drawImage(videoFrame, 0, 0);

    // 将 VideoFrame 转换为 ImageBitmap
    createImageBitmap(videoFrame).then(imageBitmap => {
      // 使用 imageBitmap
    });
    ```
    以上 JavaScript 代码直接使用了 `VideoFrame` 构造函数和相关方法，这些功能的底层实现就在 `video_frame.cc` 文件中。

* **HTML:**
    ```html
    <video id="myVideo" src="myvideo.mp4"></video>
    <canvas id="myCanvas"></canvas>
    ```
    `VideoFrame` 可以从 HTML 的 `<video>` 元素创建，并且可以用于在 `<canvas>` 元素上绘制视频帧。

* **CSS:**
    虽然 `video_frame.cc` 本身不直接操作 CSS，但 `VideoFrame` 对象最终渲染到页面上时，其显示效果会受到 CSS 样式的影响，例如 `<video>` 元素或 `<canvas>` 元素的尺寸、位置等。

**假设输入与输出的逻辑推理：**

**假设输入：** 一个 HTML `<video>` 元素正在播放，JavaScript 代码尝试创建一个 `VideoFrame` 对象。

**输出：** `video_frame.cc` 中的 `VideoFrame::Create` 方法会被调用。该方法会：
1. 获取 `<video>` 元素的当前视频帧 ( `wmp->GetCurrentFrameThenUpdate()` )。
2. 根据传入的 `VideoFrameInit` 参数（例如 `timestamp`）创建一个新的 `blink::VideoFrame` 对象，并包装底层的 `media::VideoFrame`。
3. 返回新创建的 `VideoFrame` 对象，该对象可以在 JavaScript 中使用。

**用户或编程常见的使用错误举例：**

1. **忘记设置 `timestamp`：** 在创建 `VideoFrame` 时，如果 `VideoFrameInit` 中没有提供 `timestamp` 属性，会导致 `Create` 方法抛出 `TypeError` 异常。
   ```javascript
   // 错误示例：缺少 timestamp
   const videoFrame = new VideoFrame(video); // 这会抛出异常
   ```

2. **在 `CopyTo()` 中使用不支持的格式转换：** 尝试将 `VideoFrame` 复制到 `ArrayBuffer` 时，如果目标格式与源格式不兼容，或者不支持该格式转换，会导致 `CopyTo()` 操作失败。

3. **对已关闭的 `VideoFrame` 调用方法：** `VideoFrame` 对象有一个 `close()` 方法，一旦调用，就不能再使用该对象。如果尝试对已关闭的 `VideoFrame` 调用 `copyTo()` 或其他方法，会导致错误。
   ```javascript
   const videoFrame = new VideoFrame(video, { timestamp: performance.now() });
   videoFrame.close();
   videoFrame.copyTo(buffer); // 错误：VideoFrame 已关闭
   ```

**用户操作如何一步步到达这里作为调试线索：**

1. **用户观看网页上的视频：** 当用户访问包含 `<video>` 元素的网页并开始播放视频时，浏览器会解码视频帧，这些帧可能会被创建为 `media::VideoFrame` 对象。
2. **JavaScript 代码与 WebCodecs API 交互：**  如果网页的 JavaScript 代码使用了 WebCodecs API 中的 `VideoFrame` 构造函数（例如 `new VideoFrame(video, ...)`），那么 `blink/renderer/modules/webcodecs/video_frame.cc` 中的 `VideoFrame::Create` 方法会被调用。
3. **开发者使用 `CopyTo()` 或 `convertToCanvasImageBitmap()`：**  当开发者在 JavaScript 中调用 `videoFrame.copyTo(buffer)` 或 `createImageBitmap(videoFrame)` 时，会触发 `video_frame.cc` 中相应方法的执行。
4. **调试信息：** 如果在调试过程中，你看到了涉及 `blink::VideoFrame` 类的堆栈信息或日志输出，那么可以确定代码执行到了 `blink/renderer/modules/webcodecs/video_frame.cc` 文件中的相关逻辑。

总而言之，`blink/renderer/modules/webcodecs/video_frame.cc` 文件是 WebCodecs API 中 `VideoFrame` 功能的核心实现，负责创建、管理、访问和转换视频帧数据，是连接 JavaScript 和底层媒体处理的关键桥梁。

Prompt: 
```
这是目录为blink/renderer/modules/webcodecs/video_frame.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"

#include <limits>
#include <utility>

#include "base/containers/span.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/scoped_refptr.h"
#include "base/numerics/checked_math.h"
#include "base/task/bind_post_task.h"
#include "base/time/time.h"
#include "components/viz/common/gpu/raster_context_provider.h"
#include "media/base/limits.h"
#include "media/base/timestamp_constants.h"
#include "media/base/video_frame.h"
#include "media/base/video_frame_metadata.h"
#include "media/base/video_frame_pool.h"
#include "media/base/video_types.h"
#include "media/base/video_util.h"
#include "media/renderers/paint_canvas_video_renderer.h"
#include "third_party/blink/public/mojom/frame/lifecycle.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_graphics_context_3d_provider.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_background_blur.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_plane_layout.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_cssimagevalue_htmlcanvaselement_htmlimageelement_htmlvideoelement_imagebitmap_offscreencanvas_svgimageelement_videoframe.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_color_space_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame_buffer_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame_copy_to_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame_metadata.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_pixel_format.h"
#include "third_party/blink/renderer/core/execution_context/execution_context_lifecycle_state_observer.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/geometry/dom_rect_read_only.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_image_source.h"
#include "third_party/blink/renderer/core/html/canvas/predefined_color_space.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/canvas/imagebitmap/image_bitmap_factories.h"
#include "third_party/blink/renderer/modules/webcodecs/array_buffer_util.h"
#include "third_party/blink/renderer/modules/webcodecs/background_readback.h"
#include "third_party/blink/renderer/modules/webcodecs/video_color_space.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame_init_util.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame_rect_util.h"
#include "third_party/blink/renderer/platform/geometry/geometry_hash_traits.h"
#include "third_party/blink/renderer/platform/graphics/canvas_color_params.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_types.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/graphics/skia/sk_image_info_hash.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/video_frame_image_util.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/libyuv/include/libyuv/planar_functions.h"
#include "third_party/skia/include/gpu/ganesh/GrDirectContext.h"
#include "ui/gfx/geometry/skia_conversions.h"
#include "v8/include/v8.h"

namespace WTF {

template <>
struct CrossThreadCopier<blink::VideoFrameLayout>
    : public CrossThreadCopierPassThrough<blink::VideoFrameLayout> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {

namespace {

// Controls if VideoFrame.copyTo() reads GPU frames asynchronously
BASE_FEATURE(kVideoFrameAsyncCopyTo,
             "VideoFrameAsyncCopyTo",
             base::FEATURE_DISABLED_BY_DEFAULT);

media::VideoPixelFormat ToMediaPixelFormat(V8VideoPixelFormat::Enum fmt) {
  switch (fmt) {
    case V8VideoPixelFormat::Enum::kI420:
      return media::PIXEL_FORMAT_I420;
    case V8VideoPixelFormat::Enum::kI420P10:
      return media::PIXEL_FORMAT_YUV420P10;
    case V8VideoPixelFormat::Enum::kI420P12:
      return media::PIXEL_FORMAT_YUV420P12;
    case V8VideoPixelFormat::Enum::kI420A:
      return media::PIXEL_FORMAT_I420A;
    case V8VideoPixelFormat::Enum::kI420AP10:
      return media::PIXEL_FORMAT_YUV420AP10;
    case V8VideoPixelFormat::Enum::kI422:
      return media::PIXEL_FORMAT_I422;
    case V8VideoPixelFormat::Enum::kI422P10:
      return media::PIXEL_FORMAT_YUV422P10;
    case V8VideoPixelFormat::Enum::kI422P12:
      return media::PIXEL_FORMAT_YUV422P12;
    case V8VideoPixelFormat::Enum::kI422A:
      return media::PIXEL_FORMAT_I422A;
    case V8VideoPixelFormat::Enum::kI422AP10:
      return media::PIXEL_FORMAT_YUV422AP10;
    case V8VideoPixelFormat::Enum::kI444:
      return media::PIXEL_FORMAT_I444;
    case V8VideoPixelFormat::Enum::kI444P10:
      return media::PIXEL_FORMAT_YUV444P10;
    case V8VideoPixelFormat::Enum::kI444P12:
      return media::PIXEL_FORMAT_YUV444P12;
    case V8VideoPixelFormat::Enum::kI444A:
      return media::PIXEL_FORMAT_I444A;
    case V8VideoPixelFormat::Enum::kI444AP10:
      return media::PIXEL_FORMAT_YUV422AP10;
    case V8VideoPixelFormat::Enum::kNV12:
      return media::PIXEL_FORMAT_NV12;
    case V8VideoPixelFormat::Enum::kRGBA:
      return media::PIXEL_FORMAT_ABGR;
    case V8VideoPixelFormat::Enum::kRGBX:
      return media::PIXEL_FORMAT_XBGR;
    case V8VideoPixelFormat::Enum::kBGRA:
      return media::PIXEL_FORMAT_ARGB;
    case V8VideoPixelFormat::Enum::kBGRX:
      return media::PIXEL_FORMAT_XRGB;
  }
}

// TODO(crbug.com/40215121): This is very similar to the method in
// video_encoder.cc.
media::VideoPixelFormat ToOpaqueMediaPixelFormat(media::VideoPixelFormat fmt) {
  DCHECK(!media::IsOpaque(fmt));
  switch (fmt) {
    case media::PIXEL_FORMAT_I420A:
      return media::PIXEL_FORMAT_I420;
    case media::PIXEL_FORMAT_YUV420AP10:
      return media::PIXEL_FORMAT_YUV420P10;
    case media::PIXEL_FORMAT_I422A:
      return media::PIXEL_FORMAT_I422;
    case media::PIXEL_FORMAT_YUV422AP10:
      return media::PIXEL_FORMAT_YUV422P10;
    case media::PIXEL_FORMAT_I444A:
      return media::PIXEL_FORMAT_I444;
    case media::PIXEL_FORMAT_YUV444AP10:
      return media::PIXEL_FORMAT_YUV444P10;
    case media::PIXEL_FORMAT_ARGB:
      return media::PIXEL_FORMAT_XRGB;
    case media::PIXEL_FORMAT_ABGR:
      return media::PIXEL_FORMAT_XBGR;
    default:
      NOTIMPLEMENTED() << "Missing support for making " << fmt << " opaque.";
      return fmt;
  }
}

std::optional<V8VideoPixelFormat> ToV8VideoPixelFormat(
    media::VideoPixelFormat fmt) {
  switch (fmt) {
    case media::PIXEL_FORMAT_I420:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI420);
    case media::PIXEL_FORMAT_YUV420P10:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI420P10);
    case media::PIXEL_FORMAT_YUV420P12:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI420P12);
    case media::PIXEL_FORMAT_I420A:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI420A);
    case media::PIXEL_FORMAT_YUV420AP10:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI420AP10);
    case media::PIXEL_FORMAT_I422:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI422);
    case media::PIXEL_FORMAT_YUV422P10:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI422P10);
    case media::PIXEL_FORMAT_YUV422P12:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI422P12);
    case media::PIXEL_FORMAT_I422A:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI422A);
    case media::PIXEL_FORMAT_YUV422AP10:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI422AP10);
    case media::PIXEL_FORMAT_I444:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI444);
    case media::PIXEL_FORMAT_YUV444P10:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI444P10);
    case media::PIXEL_FORMAT_YUV444P12:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI444P12);
    case media::PIXEL_FORMAT_I444A:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI444A);
    case media::PIXEL_FORMAT_YUV444AP10:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kI444AP10);
    case media::PIXEL_FORMAT_NV12:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kNV12);
    case media::PIXEL_FORMAT_ABGR:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kRGBA);
    case media::PIXEL_FORMAT_XBGR:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kRGBX);
    case media::PIXEL_FORMAT_ARGB:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kBGRA);
    case media::PIXEL_FORMAT_XRGB:
      return V8VideoPixelFormat(V8VideoPixelFormat::Enum::kBGRX);
    default:
      NOTREACHED();
  }
}

bool IsFormatEnabled(media::VideoPixelFormat fmt) {
  switch (fmt) {
    case media::PIXEL_FORMAT_I420:
    case media::PIXEL_FORMAT_I420A:
    case media::PIXEL_FORMAT_I422:
    case media::PIXEL_FORMAT_I444:
    case media::PIXEL_FORMAT_NV12:
    case media::PIXEL_FORMAT_ABGR:
    case media::PIXEL_FORMAT_XBGR:
    case media::PIXEL_FORMAT_ARGB:
    case media::PIXEL_FORMAT_XRGB:
      return true;
    case media::PIXEL_FORMAT_YUV420P10:
    case media::PIXEL_FORMAT_YUV420P12:
    case media::PIXEL_FORMAT_YUV420AP10:
    case media::PIXEL_FORMAT_YUV422P10:
    case media::PIXEL_FORMAT_YUV422P12:
    case media::PIXEL_FORMAT_I422A:
    case media::PIXEL_FORMAT_YUV422AP10:
    case media::PIXEL_FORMAT_YUV444P10:
    case media::PIXEL_FORMAT_YUV444P12:
    case media::PIXEL_FORMAT_I444A:
    case media::PIXEL_FORMAT_YUV444AP10:
      return RuntimeEnabledFeatures::WebCodecsHBDFormatsEnabled();
    default:
      return false;
  }
}

class CachedVideoFramePool : public GarbageCollected<CachedVideoFramePool>,
                             public Supplement<ExecutionContext>,
                             public ExecutionContextLifecycleStateObserver {
 public:
  static const char kSupplementName[];

  static CachedVideoFramePool& From(ExecutionContext& context) {
    CachedVideoFramePool* supplement =
        Supplement<ExecutionContext>::From<CachedVideoFramePool>(context);
    if (!supplement) {
      supplement = MakeGarbageCollected<CachedVideoFramePool>(context);
      Supplement<ExecutionContext>::ProvideTo(context, supplement);
    }
    return *supplement;
  }

  explicit CachedVideoFramePool(ExecutionContext& context)
      : Supplement<ExecutionContext>(context),
        ExecutionContextLifecycleStateObserver(&context) {
    UpdateStateIfNeeded();
  }
  ~CachedVideoFramePool() override = default;

  // Disallow copy and assign.
  CachedVideoFramePool& operator=(const CachedVideoFramePool&) = delete;
  CachedVideoFramePool(const CachedVideoFramePool&) = delete;

  scoped_refptr<media::VideoFrame> CreateFrame(media::VideoPixelFormat format,
                                               const gfx::Size& coded_size,
                                               const gfx::Rect& visible_rect,
                                               const gfx::Size& natural_size,
                                               base::TimeDelta timestamp) {
    if (!frame_pool_)
      CreatePoolAndStartIdleObsever();

    last_frame_creation_ = base::TimeTicks::Now();
    return frame_pool_->CreateFrame(format, coded_size, visible_rect,
                                    natural_size, timestamp);
  }

  void Trace(Visitor* visitor) const override {
    Supplement<ExecutionContext>::Trace(visitor);
    ExecutionContextLifecycleStateObserver::Trace(visitor);
  }

  void ContextLifecycleStateChanged(
      mojom::blink::FrameLifecycleState state) override {
    if (state == mojom::blink::FrameLifecycleState::kRunning)
      return;
    // Reset `frame_pool_` because the task runner for purging will get paused.
    frame_pool_.reset();
    task_handle_.Cancel();
  }

  void ContextDestroyed() override { frame_pool_.reset(); }

 private:
  static const base::TimeDelta kIdleTimeout;

  void PostMonitoringTask() {
    DCHECK(!task_handle_.IsActive());
    task_handle_ = PostDelayedCancellableTask(
        *GetSupplementable()->GetTaskRunner(TaskType::kInternalMedia),
        FROM_HERE,
        WTF::BindOnce(&CachedVideoFramePool::PurgeIdleFramePool,
                      WrapWeakPersistent(this)),
        kIdleTimeout);
  }

  void CreatePoolAndStartIdleObsever() {
    DCHECK(!frame_pool_);
    frame_pool_ = std::make_unique<media::VideoFramePool>();
    PostMonitoringTask();
  }

  // We don't want a VideoFramePool to stick around forever wasting memory, so
  // once we haven't issued any VideoFrames for a while, turn down the pool.
  void PurgeIdleFramePool() {
    if (base::TimeTicks::Now() - last_frame_creation_ > kIdleTimeout) {
      frame_pool_.reset();
      return;
    }
    PostMonitoringTask();
  }

  std::unique_ptr<media::VideoFramePool> frame_pool_;
  base::TimeTicks last_frame_creation_;
  TaskHandle task_handle_;
};

// static -- defined out of line to satisfy link time requirements.
const char CachedVideoFramePool::kSupplementName[] = "CachedVideoFramePool";
const base::TimeDelta CachedVideoFramePool::kIdleTimeout = base::Seconds(10);

class CanvasResourceProviderCache
    : public GarbageCollected<CanvasResourceProviderCache>,
      public Supplement<ExecutionContext>,
      public ExecutionContextLifecycleStateObserver {
 public:
  static const char kSupplementName[];

  static CanvasResourceProviderCache& From(ExecutionContext& context) {
    CanvasResourceProviderCache* supplement =
        Supplement<ExecutionContext>::From<CanvasResourceProviderCache>(
            context);
    if (!supplement) {
      supplement = MakeGarbageCollected<CanvasResourceProviderCache>(context);
      Supplement<ExecutionContext>::ProvideTo(context, supplement);
    }
    return *supplement;
  }

  explicit CanvasResourceProviderCache(ExecutionContext& context)
      : Supplement<ExecutionContext>(context),
        ExecutionContextLifecycleStateObserver(&context) {
    UpdateStateIfNeeded();
  }
  ~CanvasResourceProviderCache() override = default;

  // Disallow copy and assign.
  CanvasResourceProviderCache& operator=(const CanvasResourceProviderCache&) =
      delete;
  CanvasResourceProviderCache(const CanvasResourceProviderCache&) = delete;

  CanvasResourceProvider* CreateProvider(const SkImageInfo& info) {
    if (info_to_provider_.empty())
      PostMonitoringTask();

    last_access_time_ = base::TimeTicks::Now();

    auto iter = info_to_provider_.find(info);
    if (iter != info_to_provider_.end()) {
      auto* result = iter->value.get();
      if (result && result->IsValid())
        return result;
    }

    if (info_to_provider_.size() >= kMaxSize)
      info_to_provider_.clear();

    auto provider = CreateResourceProviderForVideoFrame(
        info, GetRasterContextProvider().get());
    auto* result = provider.get();
    info_to_provider_.Set(info, std::move(provider));
    return result;
  }

  void Trace(Visitor* visitor) const override {
    Supplement<ExecutionContext>::Trace(visitor);
    ExecutionContextLifecycleStateObserver::Trace(visitor);
  }

  void ContextLifecycleStateChanged(
      mojom::blink::FrameLifecycleState state) override {
    if (state == mojom::blink::FrameLifecycleState::kRunning)
      return;
    // Reset `info_to_provider_` because the task runner for purging will get
    // paused.
    info_to_provider_.clear();
    task_handle_.Cancel();
  }

  void ContextDestroyed() override { info_to_provider_.clear(); }

 private:
  static constexpr int kMaxSize = 50;
  static const base::TimeDelta kIdleTimeout;

  void PostMonitoringTask() {
    DCHECK(!task_handle_.IsActive());
    task_handle_ = PostDelayedCancellableTask(
        *GetSupplementable()->GetTaskRunner(TaskType::kInternalMedia),
        FROM_HERE,
        WTF::BindOnce(&CanvasResourceProviderCache::PurgeIdleFramePool,
                      WrapWeakPersistent(this)),
        kIdleTimeout);
  }

  void PurgeIdleFramePool() {
    if (base::TimeTicks::Now() - last_access_time_ > kIdleTimeout) {
      info_to_provider_.clear();
      return;
    }
    PostMonitoringTask();
  }

  HashMap<SkImageInfo, std::unique_ptr<CanvasResourceProvider>>
      info_to_provider_;
  base::TimeTicks last_access_time_;
  TaskHandle task_handle_;
};

// static -- defined out of line to satisfy link time requirements.
const char CanvasResourceProviderCache::kSupplementName[] =
    "CanvasResourceProviderCache";
const base::TimeDelta CanvasResourceProviderCache::kIdleTimeout =
    base::Seconds(10);

std::optional<media::VideoPixelFormat> CopyToFormat(
    const media::VideoFrame& frame) {
  const bool mappable = frame.IsMappable() || frame.HasMappableGpuBuffer();
  const bool texturable = frame.HasSharedImage();
  if (!(mappable || texturable)) {
    return std::nullopt;
  }

  // Readback is not supported for high bit-depth formats.
  if (!mappable && frame.BitDepth() != 8u) {
    return std::nullopt;
  }

  bool si_prefers_external_sampler =
      frame.HasSharedImage() &&
      frame.shared_image()->format().PrefersExternalSampler();
  // Externally-sampled frames read back as RGB, regardless of the format.
  // TODO(crbug.com/40215121): Enable alpha readback for supported formats.
  if (!mappable && si_prefers_external_sampler) {
    DCHECK(frame.HasSharedImage());
    return media::PIXEL_FORMAT_XRGB;
  }

  if (!IsFormatEnabled(frame.format())) {
    return std::nullopt;
  }

  if (mappable) {
    DCHECK_EQ(frame.layout().num_planes(),
              media::VideoFrame::NumPlanes(frame.format()));
    return frame.format();
  }

  return frame.format();
}

void CopyMappablePlanes(const media::VideoFrame& src_frame,
                        const gfx::Rect& src_rect,
                        const VideoFrameLayout& dest_layout,
                        base::span<uint8_t> dest_buffer) {
  for (wtf_size_t i = 0; i < dest_layout.NumPlanes(); i++) {
    const gfx::Size sample_size =
        media::VideoFrame::SampleSize(dest_layout.Format(), i);
    const int sample_bytes =
        media::VideoFrame::BytesPerElement(dest_layout.Format(), i);
    const uint8_t* src =
        src_frame.data(i) +
        src_rect.y() / sample_size.height() * src_frame.stride(i) +
        src_rect.x() / sample_size.width() * sample_bytes;
    libyuv::CopyPlane(
        src, static_cast<int>(src_frame.stride(i)),
        dest_buffer.data() + dest_layout.Offset(i),
        static_cast<int>(dest_layout.Stride(i)),
        PlaneSize(src_rect.width(), sample_size.width()) * sample_bytes,
        PlaneSize(src_rect.height(), sample_size.height()));
  }
}

bool CopyTexturablePlanes(media::VideoFrame& src_frame,
                          const gfx::Rect& src_rect,
                          const VideoFrameLayout& dest_layout,
                          base::span<uint8_t> dest_buffer) {
  auto wrapper = SharedGpuContext::ContextProviderWrapper();
  if (!wrapper)
    return false;

  auto* provider = wrapper->ContextProvider();
  auto* ri = provider->RasterInterface();
  if (!ri)
    return false;

  for (wtf_size_t i = 0; i < dest_layout.NumPlanes(); i++) {
    const gfx::Size sample_size =
        media::VideoFrame::SampleSize(dest_layout.Format(), i);
    gfx::Rect plane_src_rect = PlaneRect(src_rect, sample_size);
    uint8_t* dest_pixels = dest_buffer.data() + dest_layout.Offset(i);
    if (!media::ReadbackTexturePlaneToMemorySync(
            src_frame, i, plane_src_rect, dest_pixels, dest_layout.Stride(i),
            ri, provider->GetCapabilities())) {
      // It's possible to fail after copying some but not all planes, leaving
      // the output buffer in a corrupt state D:
      return false;
    }
  }

  return true;
}

bool ParseCopyToOptions(const media::VideoFrame& frame,
                        VideoFrameCopyToOptions* options,
                        ExceptionState& exception_state,
                        VideoFrameLayout* dest_layout_out,
                        gfx::Rect* src_rect_out = nullptr) {
  DCHECK(dest_layout_out);

  auto frame_format = CopyToFormat(frame);
  if (!frame_format.has_value()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "Operation is not supported when format is null.");
    return false;
  }

  media::VideoPixelFormat copy_to_format = frame_format.value();
  if (options->hasFormat()) {
    copy_to_format = ToMediaPixelFormat(options->format().AsEnum());
    if (!IsFormatEnabled(copy_to_format)) {
      exception_state.ThrowTypeError("Unsupported format.");
      return false;
    }
  }

  if (options->hasColorSpace() &&
      options->colorSpace() != V8PredefinedColorSpace::Enum::kSRGB &&
      options->colorSpace() != V8PredefinedColorSpace::Enum::kDisplayP3) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "This pixel conversion to this color space is not supported.");
  }

  if (copy_to_format != frame.format() && !media::IsRGB(copy_to_format)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "This pixel format conversion is not supported.");
    return false;
  }

  gfx::Rect src_rect = frame.visible_rect();
  if (options->hasRect()) {
    src_rect =
        ToGfxRect(options->rect(), "rect", frame.coded_size(), exception_state);
    if (exception_state.HadException())
      return false;
  }
  if (!ValidateOffsetAlignment(copy_to_format, src_rect,
                               options->hasRect() ? "rect" : "visibleRect",
                               exception_state)) {
    return false;
  }

  gfx::Size dest_coded_size = src_rect.size();
  VideoFrameLayout dest_layout(copy_to_format, dest_coded_size,
                               exception_state);
  if (exception_state.HadException())
    return false;
  if (options->hasLayout()) {
    dest_layout = VideoFrameLayout(copy_to_format, dest_coded_size,
                                   options->layout(), exception_state);
    if (exception_state.HadException())
      return false;
  }

  *dest_layout_out = dest_layout;
  if (src_rect_out)
    *src_rect_out = src_rect;
  return true;
}

// Convert and return |dest_layout|.
HeapVector<Member<PlaneLayout>> ConvertLayout(
    const VideoFrameLayout& dest_layout) {
  HeapVector<Member<PlaneLayout>> result;
  for (wtf_size_t i = 0; i < dest_layout.NumPlanes(); i++) {
    auto* plane = MakeGarbageCollected<PlaneLayout>();
    plane->setOffset(dest_layout.Offset(i));
    plane->setStride(dest_layout.Stride(i));
    result.push_back(plane);
  }
  return result;
}

}  // namespace

VideoFrame::VideoFrame(scoped_refptr<media::VideoFrame> frame,
                       ExecutionContext* context,
                       std::string monitoring_source_id,
                       sk_sp<SkImage> sk_image,
                       bool use_capture_timestamp) {
  DCHECK(frame);
  handle_ = base::MakeRefCounted<VideoFrameHandle>(
      frame, std::move(sk_image), context, std::move(monitoring_source_id),
      use_capture_timestamp);
  size_t external_allocated_memory =
      media::VideoFrame::AllocationSize(frame->format(), frame->coded_size());
  external_memory_accounter_.Increase(context->GetIsolate(),
                                      external_allocated_memory);
}

VideoFrame::VideoFrame(scoped_refptr<VideoFrameHandle> handle)
    : handle_(std::move(handle)) {
  DCHECK(handle_);

  // The provided |handle| may be invalid if close() was called while
  // it was being sent to another thread.
  auto local_frame = handle_->frame();
  if (!local_frame)
    return;

  size_t external_allocated_memory = media::VideoFrame::AllocationSize(
      local_frame->format(), local_frame->coded_size());
  external_memory_accounter_.Increase(v8::Isolate::GetCurrent(),
                                      external_allocated_memory);
}

VideoFrame::~VideoFrame() {
  ResetExternalMemory();
}

// static
VideoFrame* VideoFrame::Create(ScriptState* script_state,
                               const V8CanvasImageSource* source,
                               const VideoFrameInit* init,
                               ExceptionState& exception_state) {
  auto* image_source = ToCanvasImageSource(source, exception_state);
  if (!image_source) {
    // ToCanvasImageSource() will throw a source appropriate exception.
    return nullptr;
  }

  if (image_source->WouldTaintOrigin()) {
    exception_state.ThrowSecurityError(
        "VideoFrames can't be created from tainted sources.");
    return nullptr;
  }

  media::VideoTransformation transformation = media::kNoTransformation;
  bool transformed = false;
  if (RuntimeEnabledFeatures::WebCodecsOrientationEnabled()) {
    transformation = media::VideoTransformation(init->rotation(), init->flip());
    transformed = transformation != media::kNoTransformation;
  }

  constexpr char kAlphaDiscard[] = "discard";

  // Special case <video> and VideoFrame to directly use the underlying frame.
  if (source->IsVideoFrame() || source->IsHTMLVideoElement()) {
    scoped_refptr<media::VideoFrame> source_frame;
    switch (source->GetContentType()) {
      case V8CanvasImageSource::ContentType::kVideoFrame:
        source_frame = source->GetAsVideoFrame()->frame();
        break;
      case V8CanvasImageSource::ContentType::kHTMLVideoElement:
        if (auto* wmp = source->GetAsHTMLVideoElement()->GetWebMediaPlayer())
          source_frame = wmp->GetCurrentFrameThenUpdate();
        break;
      default:
        NOTREACHED();
    }

    if (!source_frame) {
      exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                        "Invalid source state");
      return nullptr;
    }

    const bool force_opaque = init->alpha() == kAlphaDiscard &&
                              !media::IsOpaque(source_frame->format());

    const auto wrapped_format =
        force_opaque ? ToOpaqueMediaPixelFormat(source_frame->format())
                     : source_frame->format();
    const gfx::Size& coded_size = source_frame->coded_size();
    const gfx::Rect default_visible_rect = source_frame->visible_rect();
    const gfx::Size default_display_size = source_frame->natural_size();
    ParsedVideoFrameInit parsed_init(init, wrapped_format, coded_size,
                                     default_visible_rect, default_display_size,
                                     exception_state);
    if (exception_state.HadException())
      return nullptr;

    // We can't modify frame metadata directly since there may be other owners
    // accessing these fields concurrently.
    if (init->hasTimestamp() || init->hasDuration() || force_opaque ||
        init->hasVisibleRect() || transformed || init->hasDisplayWidth()) {
      auto wrapped_frame = media::VideoFrame::WrapVideoFrame(
          source_frame, wrapped_format, parsed_init.visible_rect,
          parsed_init.display_size);
      if (!wrapped_frame) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kOperationError,
            String::Format("Failed to create a VideoFrame from "
                           "CanvasImageSource with format: %s, "
                           "coded size: %s, visibleRect: %s, display size: %s.",
                           VideoPixelFormatToString(wrapped_format).c_str(),
                           source_frame->coded_size().ToString().c_str(),
                           parsed_init.visible_rect.ToString().c_str(),
                           parsed_init.display_size.ToString().c_str()));
        return nullptr;
      }

      wrapped_frame->set_color_space(source_frame->ColorSpace());
      if (init->hasTimestamp()) {
        wrapped_frame->set_timestamp(base::Microseconds(init->timestamp()));
      }
      if (init->hasDuration()) {
        wrapped_frame->metadata().frame_duration =
            base::Microseconds(init->duration());
      }
      if (transformed) {
        wrapped_frame->metadata().transformation =
            wrapped_frame->metadata()
                .transformation.value_or(media::kNoTransformation)
                .add(transformation);
      }
      source_frame = std::move(wrapped_frame);
    }

    // Re-use the sk_image if available and not obsoleted by metadata overrides.
    sk_sp<SkImage> sk_image;
    if (source->GetContentType() ==
        V8CanvasImageSource::ContentType::kVideoFrame) {
      auto local_handle =
          source->GetAsVideoFrame()->handle()->CloneForInternalUse();
      // Note: It's possible for another realm (Worker) to destroy our handle if
      // this frame was transferred via BroadcastChannel to multiple realms.
      if (local_handle && local_handle->sk_image() && !force_opaque &&
          !init->hasVisibleRect() && !transformed && !init->hasDisplayWidth()) {
        sk_image = local_handle->sk_image();
      }
    }

    return MakeGarbageCollected<VideoFrame>(
        std::move(source_frame), ExecutionContext::From(script_state),
        /* monitoring_source_id */ std::string(), std::move(sk_image));
  }

  // Some elements like OffscreenCanvas won't choose a default size, so we must
  // ask them what size they think they are first.
  auto source_size =
      image_source->ElementSize(gfx::SizeF(), kRespectImageOrientation);

  SourceImageStatus status = kInvalidSourceImageStatus;
  auto image = image_source->GetSourceImageForCanvas(
      FlushReason::kCreateVideoFrame, &status, source_size, kPremultiplyAlpha);
  if (!image || status != kNormalSourceImageStatus) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Invalid source state");
    return nullptr;
  }

  const auto timestamp = base::Microseconds(
      (init && init->hasTimestamp()) ? init->timestamp() : 0);
  if (!init || !init->hasTimestamp()) {
    exception_state.ThrowTypeError("VideoFrameInit must provide timestamp");
    return nullptr;
  }

  const auto paint_image = image->PaintImageForCurrentFrame();
  const auto sk_image_info = paint_image.GetSkImageInfo();
  auto sk_color_space = sk_image_info.refColorSpace();
  if (!sk_color_space)
    sk_color_space = SkColorSpace::MakeSRGB();

  auto gfx_color_space = gfx::ColorSpace(*sk_color_space);
  if (!gfx_color_space.IsValid()) {
    exception_state.ThrowTypeError("Invalid color space");
    return nullptr;
  }

  const auto orientation = image->CurrentFrameOrientation().Orientation();
  const gfx::Size coded_size(sk_image_info.width(), sk_image_info.height());
  const gfx::Rect default_visible_rect(coded_size);
  const gfx::Size default_display_size(coded_size);

  sk_sp<SkImage> sk_image;
  scoped_refptr<media::VideoFrame> frame;
  if (image->IsTextureBacked() && SharedGpuContext::IsGpuCompositingEnabled()) {
    DCHECK(image->IsStaticBitmapImage());
    const auto format = media::VideoPixelFormatFromSkColorType(
        paint_image.GetColorType(),
        image->CurrentFrameKnownToBeOpaque() || init->alpha() == kAlphaDiscard);

    ParsedVideoFrameInit parsed_init(init, format, coded_size,
                                     default_visible_rect, default_display_size,
                                     exception_state);
    if (exception_state.HadException())
      return nullptr;

    auto* sbi = static_cast<StaticBitmapImage*>(image.get());
    gpu::MailboxHolder mailbox_holder = sbi->GetMailboxHolder
"""


```