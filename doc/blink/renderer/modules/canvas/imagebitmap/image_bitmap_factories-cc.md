Response:
Let's break down the thought process for analyzing this C++ code snippet and generating the requested information.

1. **Understand the Goal:** The request asks for a breakdown of the functionality of `image_bitmap_factories.cc`, its relationships to web technologies (JavaScript, HTML, CSS), examples, debugging tips, and potential errors.

2. **Initial Scan and Keyword Identification:**  Quickly read through the code, looking for key terms and structures. I noticed:
    * `ImageBitmapFactories` (the central class)
    * `CreateImageBitmap` (the main functions)
    * `Blob`, `HTMLCanvasElement`, `HTMLImageElement`, `HTMLVideoElement`, `ImageData`, `OffscreenCanvas`, `SVGImageElement`, `VideoFrame` (various source types)
    * `ScriptPromise` (asynchronous operations)
    * `ImageBitmapOptions` (configuration)
    * `gfx::Rect` (cropping)
    * `ImageDecoder` (decoding images)
    * `FileReaderLoader` (handling Blobs)
    * `UMA_HISTOGRAM_ENUMERATION` (metrics)
    * `Deprecation` (tracking obsolete features)
    * `ExceptionState` (error handling)

3. **Identify Core Functionality:** From the keywords, it's clear the primary purpose is to create `ImageBitmap` objects from various source types. The "factories" naming convention reinforces this.

4. **Trace the `CreateImageBitmap` Methods:**  Focus on the different `CreateImageBitmap` overloads. Notice they take different arguments, indicating flexibility in how the creation process can be initiated (with or without cropping). The core logic seems to funnel down to a function that handles various source types.

5. **Analyze Source Type Handling:** The `ToImageBitmapSourceInternal` function is crucial. It uses a `switch` statement based on the `ContentType` of a `V8ImageBitmapSource` to determine the underlying DOM object (Blob, Canvas, Image, etc.). The `UMA_HISTOGRAM_ENUMERATION` calls here suggest tracking usage patterns.

6. **Blob Handling - Asynchronous Nature:**  The `CreateImageBitmapFromBlob` function stands out. It creates an `ImageBitmapLoader`, suggesting an asynchronous process. This makes sense since fetching and decoding Blobs can be time-consuming. The `ScriptPromise` return type confirms the asynchronous nature.

7. **ImageBitmapLoader - The Asynchronous Worker:** Examine the `ImageBitmapLoader` class. It uses a `FileReaderLoader` to handle Blob data. The `ScheduleAsyncImageBitmapDecoding` function and `DecodeImageOnDecoderThread` further confirm the use of a separate thread for decoding. The promise resolution logic within `ResolvePromiseOnOriginalThread` is important.

8. **Options and Cropping:** Observe how `ImageBitmapOptions` (like `premultiplyAlpha`, `colorSpaceConversion`, `imageOrientation`) and `gfx::Rect` (for cropping) are used in the creation process.

9. **Error Handling:** Look for `ExceptionState` and the throwing of `RangeError` and `DOMException`. This indicates how errors during the creation process are reported to JavaScript.

10. **JavaScript, HTML, CSS Relationships:**  Consider how the functionality relates to web technologies:
    * **JavaScript:**  The functions are called from JavaScript using the `createImageBitmap()` method. The return type is a `Promise`, a core JavaScript concept for asynchronous operations.
    * **HTML:**  The source can be HTML elements (`<canvas>`, `<img>`, `<video>`).
    * **CSS:** While not directly involved in *creating* `ImageBitmap`s, CSS can *use* them once created (e.g., as background images).

11. **Examples and Use Cases:**  Think about practical scenarios where `createImageBitmap()` would be used:
    * Optimizing canvas rendering.
    * Efficiently processing image data from various sources.
    * Working with image data in web workers.

12. **Common Errors and Debugging:**  Based on the code, consider potential user errors (e.g., invalid crop rectangles, zero-sized sources) and debugging strategies (breakpoints, logging).

13. **User Steps to Reach the Code:**  Trace back the user actions that would trigger this code, starting from a web page interacting with the `createImageBitmap()` API.

14. **Structure and Refine:** Organize the findings into the requested categories (functionality, relationships, examples, errors, debugging). Ensure clarity and provide specific details where necessary. For example, instead of just saying "handles errors," list the types of errors and when they might occur.

15. **Self-Correction/Review:** Reread the code and the generated explanation to ensure accuracy and completeness. Did I miss any important aspects? Are the examples clear?  Is the debugging information helpful?  For instance, I initially focused heavily on Blob handling but needed to ensure I covered the synchronous paths for other source types adequately. I also made sure to connect the C++ code back to the JavaScript API it implements.
好的，让我们来分析一下 `blink/renderer/modules/canvas/imagebitmap/image_bitmap_factories.cc` 文件的功能。

**文件功能概述**

`image_bitmap_factories.cc` 文件的主要功能是为 Blink 渲染引擎提供创建 `ImageBitmap` 对象的工厂方法。`ImageBitmap` 是一个接口，表示可以被绘制到 canvas 上的位图图像，它提供了比直接使用 `HTMLImageElement` 或 `HTMLCanvasElement` 更高效的图像处理方式。

这个文件定义了 `ImageBitmapFactories` 类，该类作为 Blink 中与 `ImageBitmap` 创建相关的中心点。它处理来自不同来源的图像数据，并将其转换为 `ImageBitmap` 对象。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个文件直接实现了 JavaScript 中 `createImageBitmap()` 方法的功能。该方法允许开发者从多种来源（如 `HTMLImageElement`, `HTMLCanvasElement`, `Blob`, `ImageData` 等）异步创建 `ImageBitmap` 对象。

**JavaScript 方面：**

* **`createImageBitmap()` 方法的实现:**  这个文件中的代码逻辑是 `createImageBitmap()` 方法在 Blink 引擎中的具体实现。当 JavaScript 调用 `createImageBitmap()` 时，最终会调用到这个文件中的 C++ 代码。

   ```javascript
   // JavaScript 代码
   const imageElement = document.getElementById('myImage');
   createImageBitmap(imageElement).then(imageBitmap => {
     // imageBitmap 现在是一个 ImageBitmap 对象
     // 可以用于 canvas 的绘制
   });
   ```
   在这个例子中，JavaScript 调用 `createImageBitmap(imageElement)`，Blink 引擎会接收到这个调用，并使用 `image_bitmap_factories.cc` 中的代码来处理 `imageElement` 并创建 `ImageBitmap`。

* **Promise 的使用:** `createImageBitmap()` 返回一个 Promise，因为图像的解码和 `ImageBitmap` 的创建可能是异步的。这个文件中的 `ScriptPromiseResolver` 和 `ScriptPromise` 类用于处理 Promise 的创建和解决。

**HTML 方面：**

* **支持多种 HTML 元素作为来源:**  `createImageBitmap()` 可以接受 `HTMLImageElement`, `HTMLCanvasElement`, `HTMLVideoElement`, `SVGImageElement` 等 HTML 元素作为图像数据的来源。这个文件中的代码会根据传入的元素类型进行相应的处理。

   ```html
   <!DOCTYPE html>
   <html>
   <body>
     <img id="myImage" src="image.png">
     <canvas id="myCanvas" width="200" height="100"></canvas>
     <script>
       const imageElement = document.getElementById('myImage');
       const canvasElement = document.getElementById('myCanvas');

       createImageBitmap(imageElement).then(bitmapFromImage => { /* ... */ });
       createImageBitmap(canvasElement).then(bitmapFromCanvas => { /* ... */ });
     </script>
   </body>
   </html>
   ```
   在这个例子中，`image_bitmap_factories.cc` 中的代码会处理来自 `<img>` 和 `<canvas>` 元素的图像数据。

**CSS 方面：**

* **间接关系:**  CSS 本身不直接参与 `ImageBitmap` 的创建过程。然而，一旦 `ImageBitmap` 对象被创建，它可以用于 CanvasRenderingContext2D 的 `drawImage()` 方法，从而在由 HTML 和 CSS 布局的页面上渲染图像。

   ```javascript
   const canvas = document.getElementById('myCanvas');
   const ctx = canvas.getContext('2d');
   const imageElement = document.getElementById('myImage');

   createImageBitmap(imageElement).then(imageBitmap => {
     ctx.drawImage(imageBitmap, 0, 0); // 使用 ImageBitmap 绘制
   });
   ```
   CSS 负责 `myCanvas` 元素在页面上的布局和样式，而 `ImageBitmap` 用于填充 canvas 的内容。

**逻辑推理 (假设输入与输出)**

假设 JavaScript 代码调用 `createImageBitmap()` 并传入一个 `HTMLImageElement` 对象：

**假设输入:**

* `script_state`: 当前 JavaScript 的执行状态。
* `bitmap_source`: 一个指向 `HTMLImageElement` 的指针。
* `options`:  一个包含 `ImageBitmapOptions` 的对象，可能包含如 `imageOrientation` 或 `premultiplyAlpha` 等属性。
* `sx`, `sy`, `sw`, `sh`: 可选的裁剪参数，如果提供则用于指定源图像的裁剪区域。

**处理过程:**

1. `CreateImageBitmap` 函数被调用，接收上述参数。
2. `ToImageBitmapSourceInternal` 函数根据 `bitmap_source` 的类型（`kHTMLImageElement`) 返回对应的内部表示。
3. 如果提供了裁剪参数，`NormalizedCropRect` 函数会将这些参数规范化为 `gfx::Rect` 对象。
4. `HTMLImageElement::CreateImageBitmap` 方法会被调用（尽管这个文件的主要功能是作为工厂，实际的 `ImageBitmap` 创建逻辑可能在 `HTMLImageElement` 类中实现）。
5. 可能会创建一个异步任务来解码图像数据。
6. 创建一个 `ImageBitmap` 对象。
7. Promise 被解决，并将 `ImageBitmap` 对象返回给 JavaScript。

**假设输出:**

* 一个 `ScriptPromise<ImageBitmap>` 对象，当图像数据成功解码和 `ImageBitmap` 创建后，该 Promise 会 resolve 并返回创建的 `ImageBitmap` 实例。
* 如果发生错误（例如，无法解码图像），Promise 会 reject 并返回一个错误信息。

**用户或编程常见的使用错误及举例说明**

1. **无效的裁剪参数:**  提供的裁剪参数 `sx`, `sy`, `sw`, `sh` 超出了源图像的边界，或者 `sw` 或 `sh` 为负数或零。
   ```javascript
   const imageElement = document.getElementById('myImage');
   createImageBitmap(imageElement, 10, 10, -5, 20) // 宽度为负数，会导致错误
     .catch(error => console.error(error)); // 捕获 RangeError
   ```
   这个文件中的 `NormalizedCropRect` 会处理负数宽度和高度，将其转换为有效的裁剪区域。如果最终的宽度或高度为 0，则会抛出 `RangeError`。

2. **源图像加载失败:**  尝试从一个加载失败的 `HTMLImageElement` 或其他来源创建 `ImageBitmap`。
   ```javascript
   const imageElement = new Image();
   imageElement.src = 'nonexistent.png';
   imageElement.onerror = () => {
     createImageBitmap(imageElement)
       .catch(error => console.error(error)); // 可能会抛出 InvalidStateError
   };
   ```
   在这种情况下，`bitmap_source->BitmapSourceSize()` 可能会返回 0，导致抛出 `DOMException` ( `kInvalidStateError`)。

3. **在不支持 `createImageBitmap` 的浏览器中使用:** 尽管现代浏览器都支持 `createImageBitmap`，但在旧版本浏览器中调用该方法会导致错误。

4. **滥用或不当的 `imageOrientation` 选项:**  错误地使用 `imageOrientation: 'none'` (已被弃用，应使用 `'from-image'`) 可能导致不期望的图像方向。代码中对此进行了检查并添加了弃用警告。

**用户操作是如何一步步的到达这里，作为调试线索**

1. **用户在网页上触发了某些操作:** 例如，点击了一个按钮，或者页面加载完成。
2. **JavaScript 代码被执行:** 响应用户操作，JavaScript 代码调用了 `createImageBitmap()` 方法。
3. **浏览器引擎接收到 `createImageBitmap()` 调用:**  V8 引擎（Chrome 的 JavaScript 引擎）执行到 `createImageBitmap()` 调用时，会将其转发给 Blink 渲染引擎的相应模块。
4. **Blink 调用 `image_bitmap_factories.cc` 中的代码:**  具体来说，会调用 `ImageBitmapFactories` 类中的 `CreateImageBitmap` 方法的某个重载版本。
5. **图像数据源被处理:** 根据传入的源类型（例如，`HTMLImageElement`），会执行相应的逻辑来获取图像数据。
6. **图像解码 (如果需要):**  对于某些来源（如 Blob），图像数据可能需要异步解码。这涉及到将任务提交到解码线程。
7. **`ImageBitmap` 对象被创建:**  使用解码后的数据或直接从源数据创建 `ImageBitmap` 对象。
8. **Promise 被解决或拒绝:**  操作成功，Promise resolve 并返回 `ImageBitmap`；操作失败，Promise reject 并返回错误信息。
9. **JavaScript Promise 的 then 或 catch 回调被执行:**  根据 Promise 的状态，JavaScript 代码会继续执行相应的逻辑。

**调试线索:**

* **在 JavaScript 代码中设置断点:**  在调用 `createImageBitmap()` 的地方设置断点，查看传入的参数，例如源对象、裁剪参数和选项。
* **在 `image_bitmap_factories.cc` 中设置断点:**  在 `CreateImageBitmap` 方法的入口、`ToImageBitmapSourceInternal` 函数、以及处理不同源类型的分支中设置断点，可以跟踪代码的执行流程，查看中间变量的值，例如裁剪矩形、图像尺寸等。
* **查看浏览器的开发者工具的 Network 面板:**  如果源是 `<img>` 元素或 `Blob`，可以查看网络请求是否成功，以及图像的 MIME 类型是否正确。
* **使用 `console.log` 输出调试信息:**  在 JavaScript 代码中输出相关变量的值。
* **检查浏览器的控制台错误信息:**  查看是否有与 `createImageBitmap()` 调用相关的错误或警告信息。

总而言之，`image_bitmap_factories.cc` 是 Blink 引擎中实现 `createImageBitmap()` 功能的关键组件，它负责处理各种图像源，进行必要的解码和转换，最终生成可供 canvas 使用的高效 `ImageBitmap` 对象。它的工作直接影响着 Web 开发者在 JavaScript 中使用 `createImageBitmap()` API 的行为和结果。

### 提示词
```
这是目录为blink/renderer/modules/canvas/imagebitmap/image_bitmap_factories.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/canvas/imagebitmap/image_bitmap_factories.h"

#include <memory>
#include <utility>

#include "base/location.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_bitmap_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_blob_htmlcanvaselement_htmlimageelement_htmlvideoelement_imagebitmap_imagedata_offscreencanvas_svgimageelement_videoframe.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/offscreencanvas/offscreen_canvas.h"
#include "third_party/blink/renderer/core/svg/svg_image_element.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_pool.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_skia.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "v8/include/v8.h"

namespace blink {

namespace {
// This enum is used in a UMA histogram.
enum CreateImageBitmapSource {
  kCreateImageBitmapSourceBlob = 0,
  kCreateImageBitmapSourceImageBitmap = 1,
  kCreateImageBitmapSourceImageData = 2,
  kCreateImageBitmapSourceHTMLCanvasElement = 3,
  kCreateImageBitmapSourceHTMLImageElement = 4,
  kCreateImageBitmapSourceHTMLVideoElement = 5,
  kCreateImageBitmapSourceOffscreenCanvas = 6,
  kCreateImageBitmapSourceSVGImageElement = 7,
  kCreateImageBitmapSourceVideoFrame = 8,
  kMaxValue = kCreateImageBitmapSourceVideoFrame,
};

constexpr const char* kImageBitmapOptionNone = "none";

gfx::Rect NormalizedCropRect(int x, int y, int width, int height) {
  if (width < 0) {
    x = base::ClampAdd(x, width);
    width = base::ClampSub(0, width);
  }
  if (height < 0) {
    y = base::ClampAdd(y, height);
    height = base::ClampSub(0, height);
  }
  return gfx::Rect(x, y, width, height);
}

}  // namespace

inline ImageBitmapSource* ToImageBitmapSourceInternal(
    const V8ImageBitmapSource* value,
    const ImageBitmapOptions* options,
    bool has_crop_rect) {
  DCHECK(value);

  switch (value->GetContentType()) {
    case V8ImageBitmapSource::ContentType::kBlob:
      UMA_HISTOGRAM_ENUMERATION("Blink.Canvas.CreateImageBitmapSource",
                                kCreateImageBitmapSourceBlob);
      return value->GetAsBlob();
    case V8ImageBitmapSource::ContentType::kHTMLCanvasElement:
      UMA_HISTOGRAM_ENUMERATION("Blink.Canvas.CreateImageBitmapSource",
                                kCreateImageBitmapSourceHTMLCanvasElement);
      return value->GetAsHTMLCanvasElement();
    case V8ImageBitmapSource::ContentType::kHTMLImageElement:
      UMA_HISTOGRAM_ENUMERATION("Blink.Canvas.CreateImageBitmapSource",
                                kCreateImageBitmapSourceHTMLImageElement);
      return value->GetAsHTMLImageElement();
    case V8ImageBitmapSource::ContentType::kHTMLVideoElement:
      UMA_HISTOGRAM_ENUMERATION("Blink.Canvas.CreateImageBitmapSource",
                                kCreateImageBitmapSourceHTMLVideoElement);
      return value->GetAsHTMLVideoElement();
    case V8ImageBitmapSource::ContentType::kImageBitmap:
      UMA_HISTOGRAM_ENUMERATION("Blink.Canvas.CreateImageBitmapSource",
                                kCreateImageBitmapSourceImageBitmap);
      return value->GetAsImageBitmap();
    case V8ImageBitmapSource::ContentType::kImageData:
      UMA_HISTOGRAM_ENUMERATION("Blink.Canvas.CreateImageBitmapSource",
                                kCreateImageBitmapSourceImageData);
      return value->GetAsImageData();
    case V8ImageBitmapSource::ContentType::kOffscreenCanvas:
      UMA_HISTOGRAM_ENUMERATION("Blink.Canvas.CreateImageBitmapSource",
                                kCreateImageBitmapSourceOffscreenCanvas);
      return value->GetAsOffscreenCanvas();
    case V8ImageBitmapSource::ContentType::kSVGImageElement:
      UMA_HISTOGRAM_ENUMERATION("Blink.Canvas.CreateImageBitmapSource",
                                kCreateImageBitmapSourceSVGImageElement);
      return value->GetAsSVGImageElement();
    case V8ImageBitmapSource::ContentType::kVideoFrame:
      UMA_HISTOGRAM_ENUMERATION("Blink.Canvas.CreateImageBitmapSource",
                                kCreateImageBitmapSourceVideoFrame);
      return value->GetAsVideoFrame();
  }

  NOTREACHED();
}

ScriptPromise<ImageBitmap> ImageBitmapFactories::CreateImageBitmapFromBlob(
    ScriptState* script_state,
    ImageBitmapSource* bitmap_source,
    std::optional<gfx::Rect> crop_rect,
    const ImageBitmapOptions* options) {
  if (!script_state->ContextIsValid()) {
    return EmptyPromise();
  }

  // imageOrientation: 'from-image' will be used to replace imageOrientation:
  // 'none'. Adding a deprecation warning when 'none' is called in
  // createImageBitmap.
  if (options->imageOrientation() == kImageBitmapOptionNone) {
    auto* execution_context =
        ExecutionContext::From(script_state->GetContext());
    Deprecation::CountDeprecation(
        execution_context,
        WebFeature::kObsoleteCreateImageBitmapImageOrientationNone);
  }

  ImageBitmapFactories& factory = From(*ExecutionContext::From(script_state));
  ImageBitmapLoader* loader = ImageBitmapFactories::ImageBitmapLoader::Create(
      factory, crop_rect, options, script_state);
  factory.AddLoader(loader);
  loader->LoadBlobAsync(static_cast<Blob*>(bitmap_source));
  return loader->Promise();
}

ScriptPromise<ImageBitmap> ImageBitmapFactories::CreateImageBitmap(
    ScriptState* script_state,
    const V8ImageBitmapSource* bitmap_source,
    const ImageBitmapOptions* options,
    ExceptionState& exception_state) {
  WebFeature feature = WebFeature::kCreateImageBitmap;
  UseCounter::Count(ExecutionContext::From(script_state), feature);
  ImageBitmapSource* bitmap_source_internal =
      ToImageBitmapSourceInternal(bitmap_source, options, false);
  if (!bitmap_source_internal)
    return EmptyPromise();
  return CreateImageBitmap(script_state, bitmap_source_internal, std::nullopt,
                           options, exception_state);
}

ScriptPromise<ImageBitmap> ImageBitmapFactories::CreateImageBitmap(
    ScriptState* script_state,
    const V8ImageBitmapSource* bitmap_source,
    int sx,
    int sy,
    int sw,
    int sh,
    const ImageBitmapOptions* options,
    ExceptionState& exception_state) {
  WebFeature feature = WebFeature::kCreateImageBitmap;
  UseCounter::Count(ExecutionContext::From(script_state), feature);
  ImageBitmapSource* bitmap_source_internal =
      ToImageBitmapSourceInternal(bitmap_source, options, true);
  if (!bitmap_source_internal)
    return EmptyPromise();
  gfx::Rect crop_rect = NormalizedCropRect(sx, sy, sw, sh);
  return CreateImageBitmap(script_state, bitmap_source_internal, crop_rect,
                           options, exception_state);
}

ScriptPromise<ImageBitmap> ImageBitmapFactories::CreateImageBitmap(
    ScriptState* script_state,
    ImageBitmapSource* bitmap_source,
    std::optional<gfx::Rect> crop_rect,
    const ImageBitmapOptions* options,
    ExceptionState& exception_state) {
  if (crop_rect && (crop_rect->width() == 0 || crop_rect->height() == 0)) {
    exception_state.ThrowRangeError(String::Format(
        "The crop rect %s is 0.", crop_rect->width() ? "height" : "width"));
    return EmptyPromise();
  }

  if (bitmap_source->IsBlob()) {
    return CreateImageBitmapFromBlob(script_state, bitmap_source, crop_rect,
                                     options);
  }

  if (bitmap_source->BitmapSourceSize().width() == 0 ||
      bitmap_source->BitmapSourceSize().height() == 0) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        String::Format(
            "The source image %s is 0.",
            bitmap_source->BitmapSourceSize().width() ? "height" : "width"));
    return EmptyPromise();
  }

  return bitmap_source->CreateImageBitmap(script_state, crop_rect, options,
                                          exception_state);
}

const char ImageBitmapFactories::kSupplementName[] = "ImageBitmapFactories";

ImageBitmapFactories& ImageBitmapFactories::From(ExecutionContext& context) {
  ImageBitmapFactories* supplement =
      Supplement<ExecutionContext>::From<ImageBitmapFactories>(context);
  if (!supplement) {
    supplement = MakeGarbageCollected<ImageBitmapFactories>(context);
    Supplement<ExecutionContext>::ProvideTo(context, supplement);
  }
  return *supplement;
}

ImageBitmapFactories::ImageBitmapFactories(ExecutionContext& context)
    : Supplement(context) {}

void ImageBitmapFactories::AddLoader(ImageBitmapLoader* loader) {
  pending_loaders_.insert(loader);
}

void ImageBitmapFactories::DidFinishLoading(ImageBitmapLoader* loader) {
  DCHECK(pending_loaders_.Contains(loader));
  pending_loaders_.erase(loader);
}

void ImageBitmapFactories::Trace(Visitor* visitor) const {
  visitor->Trace(pending_loaders_);
  Supplement<ExecutionContext>::Trace(visitor);
}

ImageBitmapFactories::ImageBitmapLoader::ImageBitmapLoader(
    ImageBitmapFactories& factory,
    std::optional<gfx::Rect> crop_rect,
    ScriptState* script_state,
    const ImageBitmapOptions* options)
    : ExecutionContextLifecycleObserver(ExecutionContext::From(script_state)),
      loader_(MakeGarbageCollected<FileReaderLoader>(
          this,
          GetExecutionContext()->GetTaskRunner(TaskType::kFileReading))),
      factory_(&factory),
      resolver_(MakeGarbageCollected<ScriptPromiseResolver<ImageBitmap>>(
          script_state)),
      crop_rect_(crop_rect),
      options_(options) {}

void ImageBitmapFactories::ImageBitmapLoader::LoadBlobAsync(Blob* blob) {
  loader_->Start(blob->GetBlobDataHandle());
}

ImageBitmapFactories::ImageBitmapLoader::~ImageBitmapLoader() {
  DCHECK(!loader_);
}

void ImageBitmapFactories::ImageBitmapLoader::RejectPromise(
    ImageBitmapRejectionReason reason) {
  CHECK(resolver_);
  ScriptState* resolver_script_state = resolver_->GetScriptState();
  if (!IsInParallelAlgorithmRunnable(resolver_->GetExecutionContext(),
                                     resolver_script_state)) {
    if (loader_) {
      loader_->Cancel();
      loader_.Clear();
    }
    factory_->DidFinishLoading(this);
    return;
  }
  ScriptState::Scope script_state_scope(resolver_script_state);
  switch (reason) {
    case kUndecodableImageBitmapRejectionReason:
      resolver_->Reject(V8ThrowDOMException::CreateOrEmpty(
          resolver_script_state->GetIsolate(),
          DOMExceptionCode::kInvalidStateError,
          "The source image could not be decoded."));
      break;
    case kAllocationFailureImageBitmapRejectionReason:
      resolver_->Reject(V8ThrowDOMException::CreateOrEmpty(
          resolver_script_state->GetIsolate(),
          DOMExceptionCode::kInvalidStateError,
          "The ImageBitmap could not be allocated."));
      break;
    default:
      NOTREACHED();
  }
  if (loader_) {
    loader_->Cancel();
    loader_.Clear();
  }
  factory_->DidFinishLoading(this);
}

void ImageBitmapFactories::ImageBitmapLoader::ContextDestroyed() {
  if (loader_) {
    factory_->DidFinishLoading(this);
    loader_->Cancel();
    loader_.Clear();
  }
}

void ImageBitmapFactories::ImageBitmapLoader::DidFinishLoading(
    FileReaderData data) {
  auto contents = std::move(data).AsArrayBufferContents();
  loader_.Clear();
  if (!contents.IsValid()) {
    RejectPromise(kAllocationFailureImageBitmapRejectionReason);
    return;
  }
  ScheduleAsyncImageBitmapDecoding(std::move(contents));
}

void ImageBitmapFactories::ImageBitmapLoader::DidFail(
    FileErrorCode error_code) {
  FileReaderAccumulator::DidFail(error_code);
  RejectPromise(kUndecodableImageBitmapRejectionReason);
}

namespace {
void DecodeImageOnDecoderThread(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    ArrayBufferContents contents,
    ImageDecoder::AlphaOption alpha_option,
    ColorBehavior color_behavior,
    WTF::CrossThreadOnceFunction<
        void(sk_sp<SkImage>, const ImageOrientationEnum)> result_callback) {
  const bool data_complete = true;
  std::unique_ptr<ImageDecoder> decoder = ImageDecoder::Create(
      SegmentReader::CreateFromSkData(
          SkData::MakeWithoutCopy(contents.Data(), contents.DataLength())),
      data_complete, alpha_option, ImageDecoder::kDefaultBitDepth,
      color_behavior, cc::AuxImage::kDefault,
      Platform::GetMaxDecodedImageBytes());
  sk_sp<SkImage> frame;
  ImageOrientationEnum orientation = ImageOrientationEnum::kDefault;
  if (decoder) {
    orientation = decoder->Orientation();
    frame = ImageBitmap::GetSkImageFromDecoder(std::move(decoder));
  }
  PostCrossThreadTask(*task_runner, FROM_HERE,
                      CrossThreadBindOnce(std::move(result_callback),
                                          std::move(frame), orientation));
}
}  // namespace

void ImageBitmapFactories::ImageBitmapLoader::ScheduleAsyncImageBitmapDecoding(
    ArrayBufferContents contents) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetExecutionContext()->GetTaskRunner(TaskType::kNetworking);
  ImageDecoder::AlphaOption alpha_option =
      options_->premultiplyAlpha() != "none"
          ? ImageDecoder::AlphaOption::kAlphaPremultiplied
          : ImageDecoder::AlphaOption::kAlphaNotPremultiplied;
  ColorBehavior color_behavior = options_->colorSpaceConversion() == "none"
                                     ? ColorBehavior::kIgnore
                                     : ColorBehavior::kTag;
  worker_pool::PostTask(
      FROM_HERE,
      CrossThreadBindOnce(
          DecodeImageOnDecoderThread, std::move(task_runner),
          std::move(contents), alpha_option, color_behavior,
          CrossThreadBindOnce(&ImageBitmapFactories::ImageBitmapLoader::
                                  ResolvePromiseOnOriginalThread,
                              MakeUnwrappingCrossThreadWeakHandle(this))));
}

void ImageBitmapFactories::ImageBitmapLoader::ResolvePromiseOnOriginalThread(
    sk_sp<SkImage> frame,
    const ImageOrientationEnum orientation) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!frame) {
    RejectPromise(kUndecodableImageBitmapRejectionReason);
    return;
  }
  DCHECK(frame->width());
  DCHECK(frame->height());
  scoped_refptr<StaticBitmapImage> image =
      UnacceleratedStaticBitmapImage::Create(std::move(frame), orientation);

  image->SetOriginClean(true);
  auto* image_bitmap =
      MakeGarbageCollected<ImageBitmap>(image, crop_rect_, options_);
  if (image_bitmap && image_bitmap->BitmapImage()) {
    resolver_->Resolve(image_bitmap);
  } else {
    RejectPromise(kAllocationFailureImageBitmapRejectionReason);
    return;
  }
  factory_->DidFinishLoading(this);
}

void ImageBitmapFactories::ImageBitmapLoader::Trace(Visitor* visitor) const {
  ExecutionContextLifecycleObserver::Trace(visitor);
  FileReaderAccumulator::Trace(visitor);
  visitor->Trace(factory_);
  visitor->Trace(resolver_);
  visitor->Trace(options_);
  visitor->Trace(loader_);
}

}  // namespace blink
```