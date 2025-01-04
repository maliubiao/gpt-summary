Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. I need to analyze the code and identify the key features and how they relate to web technologies like JavaScript, HTML, and CSS.

Here's a plan:
1. **Identify the core purpose of the code:** Look for class names, function names, and comments that indicate the main tasks.
2. **Analyze individual functions:**  Understand what each function does and its inputs/outputs.
3. **Relate to web technologies:**  Connect the C++ functionality to corresponding JavaScript Canvas 2D API methods, HTML elements, and CSS properties.
4. **Infer logic and assumptions:**  Based on the code, deduce the expected behavior and any underlying assumptions. Provide hypothetical input/output examples where appropriate.
5. **Identify potential errors:**  Pinpoint common mistakes users or programmers might make when using the related features.
6. **Trace user interaction:** Describe the steps a user might take in a browser to trigger this code.
7. **Synthesize a summary:** Concisely summarize the identified functionalities.

Based on the provided snippet, the code seems to handle the following:
- Creating canvas patterns from image sources.
- Creating vertex, UV, and index buffers for 2D meshes.
- Drawing meshes on the canvas.
- Getting and putting image data to/from the canvas.
- Managing image smoothing settings.
- Handling text drawing properties (spacing, rendering, alignment, baseline, kerning, stretch, variant caps).
- Tracking usage counters for canvas features.
- Handling canvas overwriting and font management.
- Managing text direction.

I'll go through each of these areas and elaborate on their functionality and connections to web technologies.
这是对 `blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc` 文件代码片段的第四部分分析。基于这段代码，我们可以归纳出以下功能：

**主要功能归纳：**

1. **创建和使用 Mesh2D 图形数据:**  这段代码提供了创建和使用 Mesh2D 数据的接口，包括顶点缓冲 (VertexBuffer)、UV 缓冲 (UVBuffer) 和索引缓冲 (IndexBuffer)。`drawMesh` 函数则负责将这些数据渲染到 canvas 上。

2. **获取和设置 ImageData:**  代码包含了 `createImageData` 和 `getImageData` 函数，允许从 canvas 中读取像素数据，以及创建新的 `ImageData` 对象。`putImageData` 函数则可以将 `ImageData` 的像素数据写回到 canvas 上。

3. **控制图像平滑:**  提供了 `imageSmoothingEnabled` 和 `imageSmoothingQuality` 属性的 getter 和 setter，用于控制图像在缩放时的平滑处理方式。

4. **管理文本属性:**  包含了一系列与文本渲染相关的属性的 getter 和 setter，例如 `letterSpacing`（字母间距）、`wordSpacing`（单词间距）、`textRendering`（文本渲染质量）、`textAlign`（文本对齐方式）、`textBaseline`（文本基线）、`fontKerning`（字距调整）、`fontStretch`（字体拉伸）、`fontVariantCaps`（小型大写字母）。

5. **跟踪 Canvas 的使用情况:**  定义了一个 `UsageCounters` 结构体，用于统计各种 Canvas 2D API 的调用次数和相关指标，例如绘制调用次数、填充类型面积、渐变数量、图案数量、`getImageData`/`putImageData` 调用等。

6. **管理字体:** 提供了 `font` 属性的 getter 和 setter，用于设置和获取 canvas 上使用的字体样式。同时也包含了检查字体是否已解析和更新的方法。

7. **处理文本方向:** 提供了 `direction` 属性的 getter 和 setter，用于控制文本的书写方向（从左到右或从右到左）。

8. **绘制文本:** 包含了 `fillText` 和 `strokeText` 函数的不同重载，用于在 canvas 上绘制填充或描边的文本。

**与 JavaScript, HTML, CSS 的关系举例说明：**

1. **Mesh2D 图形 (JavaScript Canvas API 的 `drawMesh` 方法):**
    *   **JavaScript:**  开发者可以使用 JavaScript 的 `CanvasRenderingContext2D.drawMesh()` 方法来绘制网格图形。该方法需要传入顶点、UV 坐标和索引数据。
    *   **HTML:**  `drawMesh` 操作的目标是在 HTML 中的 `<canvas>` 元素上进行渲染。
    *   **C++ (`createMesh2DVertexBuffer`, `createMesh2DUVBuffer`, `createMesh2DIndexBuffer`, `drawMesh`):**  C++ 代码实现了 `drawMesh` 方法背后的逻辑，负责接收 JavaScript 传递的数组数据，创建内部的缓冲对象，并将图像应用到网格上进行绘制。
    *   **假设输入与输出:**
        *   **假设 JavaScript 输入:**
            ```javascript
            const canvas = document.getElementById('myCanvas');
            const ctx = canvas.getContext('2d');
            const vertices = new Float32Array([0, 0, 100, 0, 100, 100, 0, 100]);
            const uvs = new Float32Array([0, 0, 1, 0, 1, 1, 0, 1]);
            const indices = new Uint16Array([0, 1, 2, 0, 2, 3]);
            const image = document.getElementById('myImage');
            const vertexBuffer = ctx.createVertexBuffer(vertices);
            const uvBuffer = ctx.createUVBuffer(uvs);
            const indexBuffer = ctx.createIndexBuffer(indices);
            ctx.drawMesh(vertexBuffer, uvBuffer, indexBuffer, image);
            ```
        *   **C++ 输出 (推测):**  `drawMesh` 函数会根据顶点、UV 和索引数据，将 `myImage` 的内容映射到 canvas 上定义的四边形区域。

2. **ImageData 操作 (JavaScript Canvas API 的 `createImageData`, `getImageData`, `putImageData` 方法):**
    *   **JavaScript:**  开发者可以使用 `ctx.createImageData()`, `ctx.getImageData()`, 和 `ctx.putImageData()` 来创建、读取和写入 canvas 像素数据。
    *   **HTML:**  这些操作作用于 HTML 中的 `<canvas>` 元素。
    *   **C++ (`createImageData`, `getImageDataInternal`, `putImageData`):**  C++ 代码实现了这些方法的底层逻辑，负责分配内存存储像素数据，从 Skia 图形库中读取或写入像素，并处理跨域安全限制。
    *   **假设输入与输出:**
        *   **假设 JavaScript 输入 (`getImageData`):**
            ```javascript
            const canvas = document.getElementById('myCanvas');
            const ctx = canvas.getContext('2d');
            const imageData = ctx.getImageData(10, 20, 50, 60);
            console.log(imageData.data); // 输出像素数据
            ```
        *   **C++ 输出 (推测):** `getImageDataInternal` 函数会从 canvas 的 (10, 20) 位置读取一个 50x60 像素的矩形区域的像素数据，并将其存储到 `ImageData` 对象中。
        *   **假设 JavaScript 输入 (`putImageData`):**
            ```javascript
            const canvas = document.getElementById('myCanvas');
            const ctx = canvas.getContext('2d');
            const imageData = new ImageData(100, 100);
            // ... 修改 imageData.data ...
            ctx.putImageData(imageData, 50, 50);
            ```
        *   **C++ 输入 (推测):** `putImageData` 函数接收 `imageData` 对象的像素数据，并将其写入到 canvas 的 (50, 50) 位置。

3. **图像平滑 (JavaScript Canvas API 的 `imageSmoothingEnabled` 和 `imageSmoothingQuality` 属性):**
    *   **JavaScript:**  开发者可以使用 `ctx.imageSmoothingEnabled = true/false;` 和 `ctx.imageSmoothingQuality = 'low' | 'medium' | 'high';` 来控制图像平滑。
    *   **CSS:**  虽然 CSS 也有 `image-rendering` 属性，但 Canvas 的图像平滑设置是独立的。
    *   **C++ (`imageSmoothingEnabled`, `setImageSmoothingEnabled`, `imageSmoothingQuality`, `setImageSmoothingQuality`):**  C++ 代码负责存储和应用这些设置，并传递给底层的 Skia 图形库进行渲染。

4. **文本属性 (JavaScript Canvas API 的相关属性):**
    *   **JavaScript:**  开发者可以使用 `ctx.letterSpacing = '5px';`, `ctx.textAlign = 'center';`, `ctx.font = 'bold 16px Arial';` 等属性来设置文本样式。
    *   **CSS:**  Canvas 的文本属性与 CSS 的文本属性类似，但它们是独立控制的。
    *   **C++ (例如 `setTextAlign`, `setTextBaseline`, `setFont`):** C++ 代码解析 JavaScript 传递的字符串值，并更新内部的状态，以便在绘制文本时使用正确的样式。

5. **字体 (JavaScript Canvas API 的 `font` 属性):**
    *   **JavaScript:** 使用 `ctx.font = 'italic 20px sans-serif';` 设置字体。
    *   **CSS:**  虽然 Canvas 的 `font` 属性语法与 CSS 的 `font` 属性类似，但它们的解析和应用是独立的。
    *   **C++ (`setFont`, `font`):**  C++ 代码负责解析 `font` 字符串，创建或获取相应的 `Font` 对象，并确保字体资源可用。

6. **文本方向 (JavaScript Canvas API 的 `direction` 属性):**
    *   **JavaScript:** 使用 `ctx.direction = 'rtl';` 或 `ctx.direction = 'ltr';` 设置文本方向。
    *   **HTML:**  HTML 元素的 `dir` 属性也会影响文本方向，Canvas 的 `direction` 属性可以覆盖或继承自 HTML。
    *   **C++ (`direction`, `setDirection`):** C++ 代码解析 JavaScript 传递的字符串，并设置内部的文本方向状态，这会影响文本的布局和绘制顺序。

7. **绘制文本 (JavaScript Canvas API 的 `fillText` 和 `strokeText` 方法):**
    *   **JavaScript:** 使用 `ctx.fillText('Hello', 50, 50);` 或 `ctx.strokeText('World', 100, 100);` 绘制文本。
    *   **C++ (`fillText`, `strokeText`, `DrawTextInternal`):** C++ 代码接收 JavaScript 传递的文本内容、坐标和绘制类型，并调用底层的 Skia 库进行实际的文本渲染。

**用户或编程常见的使用错误举例说明：**

1. **`drawMesh` 参数错误:**
    *   **错误:** 传递给 `drawMesh` 的顶点、UV 或索引缓冲区的长度不匹配或者不是期望的类型 (例如，顶点缓冲区长度为奇数或不是 `Float32Array`)。
    *   **C++ 错误处理:** `MakeSkPointBuffer` 函数会检查数组长度，如果长度为 0 或不是偶数，则会抛出 `RangeError` 异常。
    *   **用户操作导致:**  开发者在 JavaScript 中创建或操作 `Float32Array` 或 `Uint16Array` 时出现逻辑错误，导致传递给 `drawMesh` 的数据不正确。

2. **跨域 `getImageData` 错误:**
    *   **错误:**  尝试使用 `getImageData` 读取来自不同源的图像绘制到 canvas 上的像素数据，而没有进行适当的跨域资源共享 (CORS) 设置。
    *   **C++ 错误处理:** `getImageDataInternal` 函数会检查 `OriginClean()`，如果 canvas 被跨域数据污染，则会抛出 `SecurityError` 异常。
    *   **用户操作导致:**
        1. 用户在一个域名的网站上加载了一个来自另一个域名的图片到 `<canvas>` 中。
        2. JavaScript 代码尝试调用 `getImageData()` 来读取 canvas 的像素数据。

3. **在有打开的 Layer 的情况下调用 `getImageData` 或 `putImageData`:**
    *   **错误:**  在调用了 `ctx.beginPath()` 或使用了其他 layer 管理 API 后，但在调用 `ctx.closePath()` 或相关的 layer 结束方法之前，尝试调用 `getImageData()` 或 `putImageData()`。
    *   **C++ 错误处理:** `getImageDataInternal` 和 `putImageData` 函数会检查 `layer_count_`，如果大于 0，则会抛出 `InvalidStateError` 异常。
    *   **用户操作导致:**  开发者在 JavaScript 中使用了 layer 相关的 API，但忘记正确关闭 layer，然后尝试进行像素数据操作。

4. **`putImageData` 的数据源被 detached:**
    *   **错误:**  尝试使用一个已经被分离 (detached) 的 `ImageData` 对象作为 `putImageData` 的数据源。这通常发生在 Web Workers 中传递 `ImageData` 对象时。
    *   **C++ 错误处理:** `putImageData` 函数会检查 `data->IsBufferBaseDetached()`，如果是 true，则抛出 `InvalidStateError` 异常。
    *   **用户操作导致:**
        1. 在主线程创建了一个 `ImageData` 对象。
        2. 将该 `ImageData` 对象传递给一个 Web Worker (例如使用 `postMessage`)。
        3. 在 Worker 中对该 `ImageData` 进行操作或传递。
        4. 尝试在主线程中使用原始的 `ImageData` 对象调用 `putImageData`。

5. **`font` 属性设置错误:**
    *   **错误:**  设置了无效的 `font` 字符串，导致字体解析失败。
    *   **C++ 行为:** `setFont` 函数会尝试解析字体字符串，如果解析失败，则字体设置不会生效。
    *   **用户操作导致:**  开发者在 JavaScript 中编写了错误的 `font` 字符串，例如拼写错误或使用了浏览器不支持的字体属性。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在一个网页上与一个使用了 Canvas 2D API 的交互式图形进行交互。以下是一些可能的操作路径，最终会触发这段 C++ 代码：

1. **绘制 Mesh2D 图形:**
    1. 用户加载包含 `<canvas>` 元素的 HTML 页面。
    2. JavaScript 代码获取 canvas 上下文 (e.g., `canvas.getContext('2d')`)。
    3. JavaScript 代码创建 `Float32Array` 和 `Uint16Array` 来定义网格的顶点、UV 坐标和索引。
    4. JavaScript 代码调用 `ctx.createVertexBuffer()`, `ctx.createUVBuffer()`, `ctx.createIndexBuffer()`，这些调用会映射到 C++ 的相应函数，创建缓冲对象。
    5. JavaScript 代码加载一个图像。
    6. JavaScript 代码调用 `ctx.drawMesh(vertexBuffer, uvBuffer, indexBuffer, image)`，这会触发 C++ 的 `BaseRenderingContext2D::drawMesh` 函数。

2. **获取 Canvas 像素数据:**
    1. 用户在网页上进行某些操作，导致 canvas 上绘制了一些内容。
    2. JavaScript 代码调用 `ctx.getImageData(x, y, width, height)`，这会触发 C++ 的 `BaseRenderingContext2D::getImageDataInternal` 函数。

3. **修改 Canvas 像素数据:**
    1. JavaScript 代码创建一个 `ImageData` 对象 (可能使用 `ctx.createImageData()` 或 `ctx.getImageData()`)。
    2. JavaScript 代码修改 `ImageData.data` 数组中的像素值。
    3. JavaScript 代码调用 `ctx.putImageData(imageData, x, y)`，这会触发 C++ 的 `BaseRenderingContext2D::putImageData` 函数。

4. **改变图像平滑设置:**
    1. JavaScript 代码执行 `ctx.imageSmoothingEnabled = true;` 或 `ctx.imageSmoothingQuality = 'high';`，这些操作会调用 C++ 中相应的 setter 方法 (`setImageSmoothingEnabled`, `setImageSmoothingQuality`)。

5. **设置文本样式并绘制文本:**
    1. JavaScript 代码设置 canvas 的文本相关属性，例如 `ctx.font = '...'`, `ctx.textAlign = '...'`, `ctx.direction = '...'`。这些操作会调用 C++ 中相应的 setter 方法。
    2. JavaScript 代码调用 `ctx.fillText('...', x, y)` 或 `ctx.strokeText('...', x, y)`，这会触发 C++ 的 `BaseRenderingContext2D::fillText` 或 `BaseRenderingContext2D::strokeText` 函数。

作为调试线索，如果开发者在这些 JavaScript API 调用中遇到了问题，例如性能问题、渲染错误或异常，他们可能会查看 Blink 渲染引擎的源代码 (如 `base_rendering_context_2d.cc`)，以了解这些 API 背后的具体实现逻辑和可能出现的错误情况。例如，如果 `drawMesh` 渲染结果不正确，开发者可能会检查 C++ 代码中顶点数据的处理方式和图像的映射逻辑。如果 `getImageData` 抛出安全错误，开发者可能会检查 C++ 代码中关于跨域检查的实现。

**总结这段代码的功能:**

这段代码是 Chromium Blink 引擎中 `BaseRenderingContext2D` 类的一部分，负责实现 HTML Canvas 2D API 中与 Mesh2D 图形绘制、像素数据操作 (getImageData/putImageData)、图像平滑控制以及文本属性管理相关的核心功能。它连接了 JavaScript API 和底层的 Skia 图形库，处理用户通过 JavaScript 与 Canvas 交互时触发的各种操作。

Prompt: 
```
这是目录为blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能

"""
ntCanvasOrigin(image_source);

  auto* pattern = MakeGarbageCollected<CanvasPattern>(
      std::move(image_for_rendering), repeat_mode, origin_clean);
  pattern->SetExecutionContext(
      identifiability_study_helper_.execution_context());
  return pattern;
}

namespace {

scoped_refptr<cc::RefCountedBuffer<SkPoint>> MakeSkPointBuffer(
    NotShared<DOMFloat32Array> array,
    ExceptionState& exception_state,
    const char* msg) {
  if ((array->length() == 0) || (array->length() % 2)) {
    exception_state.ThrowRangeError(msg);
    return nullptr;
  }

  static_assert(std::is_trivially_copyable<SkPoint>::value);
  static_assert(sizeof(SkPoint) == sizeof(float) * 2);

  const size_t size = array->length() / 2;
  std::vector<SkPoint> skpoints(size);
  std::memcpy(skpoints.data(), array->Data(), size * sizeof(SkPoint));

  return base::MakeRefCounted<cc::RefCountedBuffer<SkPoint>>(
      std::move(skpoints));
}

}  // namespace

Mesh2DVertexBuffer* BaseRenderingContext2D::createMesh2DVertexBuffer(
    NotShared<DOMFloat32Array> array,
    ExceptionState& exception_state) {
  scoped_refptr<cc::RefCountedBuffer<SkPoint>> buffer = MakeSkPointBuffer(
      array, exception_state,
      "The vertex buffer must contain a non-zero, even number of floats.");

  return buffer ? MakeGarbageCollected<Mesh2DVertexBuffer>(std::move(buffer))
                : nullptr;
}

Mesh2DUVBuffer* BaseRenderingContext2D::createMesh2DUVBuffer(
    NotShared<DOMFloat32Array> array,
    ExceptionState& exception_state) {
  scoped_refptr<cc::RefCountedBuffer<SkPoint>> buffer = MakeSkPointBuffer(
      array, exception_state,
      "The UV buffer must contain a non-zero, even number of floats.");

  return buffer ? MakeGarbageCollected<Mesh2DUVBuffer>(std::move(buffer))
                : nullptr;
}

Mesh2DIndexBuffer* BaseRenderingContext2D::createMesh2DIndexBuffer(
    NotShared<DOMUint16Array> array,
    ExceptionState& exception_state) {
  if ((array->length() == 0) || (array->length() % 3)) {
    exception_state.ThrowRangeError(
        "The index buffer must contain a non-zero, multiple of three number of "
        "uints.");
    return nullptr;
  }

  return MakeGarbageCollected<Mesh2DIndexBuffer>(
      base::MakeRefCounted<cc::RefCountedBuffer<uint16_t>>(
          std::vector<uint16_t>(array->Data(),
                                array->Data() + array->length())));
}

void BaseRenderingContext2D::drawMesh(
    const Mesh2DVertexBuffer* vertex_buffer,
    const Mesh2DUVBuffer* uv_buffer,
    const Mesh2DIndexBuffer* index_buffer,
    const V8CanvasImageSource* v8_image_source,
    ExceptionState& exception_state) {
  CanvasImageSource* image_source =
      ToCanvasImageSource(v8_image_source, exception_state);
  if (!image_source) {
    return;
  }

  SourceImageStatus source_image_status = kInvalidSourceImageStatus;
  scoped_refptr<Image> image = image_source->GetSourceImageForCanvas(
      FlushReason::kDrawMesh, &source_image_status,
      gfx::SizeF(Width(), Height()), kPremultiplyAlpha);
  switch (source_image_status) {
    case kUndecodableSourceImageStatus:
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "The HTMLImageElement provided is in the 'broken' state.");
      return;
    case kLayersOpenInCanvasSource:
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "`drawMesh()` with a canvas as a source cannot be called while "
          "layers are open in the the source canvas.");
      return;
    default:
      break;
  }

  if (!image || image->IsNull()) {
    return;
  }

  scoped_refptr<cc::RefCountedBuffer<SkPoint>> vertex_data =
      vertex_buffer->GetBuffer();
  CHECK_NE(vertex_data, nullptr);
  scoped_refptr<cc::RefCountedBuffer<SkPoint>> uv_data = uv_buffer->GetBuffer();
  CHECK_NE(uv_data, nullptr);
  scoped_refptr<cc::RefCountedBuffer<uint16_t>> index_data =
      index_buffer->GetBuffer();
  CHECK_NE(index_data, nullptr);

  WillDrawImage(image_source);

  if (!origin_tainted_by_content_ && WouldTaintCanvasOrigin(image_source)) {
    SetOriginTaintedByContent();
  }

  SkRect bounds;
  bounds.setBounds(vertex_data->data().data(),
                   SkToInt(vertex_data->data().size()));

  Draw<OverdrawOp::kNone>(
      /*draw_func=*/
      [&image, &vertex_data, &uv_data, &index_data](
          cc::PaintCanvas* c, const cc::PaintFlags* flags) {
        const gfx::RectF src(image->width(), image->height());
        // UV coordinates are normalized, relative to the texture size.
        const SkMatrix local_matrix =
            SkMatrix::Scale(1.0f / image->width(), 1.0f / image->height());

        cc::PaintFlags scoped_flags(*flags);
        image->ApplyShader(scoped_flags, local_matrix, src, ImageDrawOptions());
        c->drawVertices(vertex_data, uv_data, index_data, scoped_flags);
      },
      kNoOverdraw,
      gfx::RectF(bounds.x(), bounds.y(), bounds.width(), bounds.height()),
      CanvasRenderingContext2DState::PaintType::kFillPaintType,
      image_source->IsOpaque() ? CanvasRenderingContext2DState::kOpaqueImage
                               : CanvasRenderingContext2DState::kNonOpaqueImage,
      CanvasPerformanceMonitor::DrawType::kOther);
}

bool BaseRenderingContext2D::ComputeDirtyRect(const gfx::RectF& local_rect,
                                              SkIRect* dirty_rect) {
  SkIRect clip_bounds;
  cc::PaintCanvas* paint_canvas = GetOrCreatePaintCanvas();
  if (!paint_canvas || !paint_canvas->getDeviceClipBounds(&clip_bounds))
    return false;
  return ComputeDirtyRect(local_rect, clip_bounds, dirty_rect);
}

ImageData* BaseRenderingContext2D::createImageData(
    ImageData* image_data,
    ExceptionState& exception_state) const {
  ImageData::ValidateAndCreateParams params;
  params.context_2d_error_mode = true;
  return ImageData::ValidateAndCreate(
      image_data->Size().width(), image_data->Size().height(), std::nullopt,
      image_data->getSettings(), params, exception_state);
}

ImageData* BaseRenderingContext2D::createImageData(
    int sw,
    int sh,
    ExceptionState& exception_state) const {
  ImageData::ValidateAndCreateParams params;
  params.context_2d_error_mode = true;
  params.default_color_space = GetDefaultImageDataColorSpace();
  return ImageData::ValidateAndCreate(std::abs(sw), std::abs(sh), std::nullopt,
                                      /*settings=*/nullptr, params,
                                      exception_state);
}

ImageData* BaseRenderingContext2D::createImageData(
    int sw,
    int sh,
    ImageDataSettings* image_data_settings,
    ExceptionState& exception_state) const {
  ImageData::ValidateAndCreateParams params;
  params.context_2d_error_mode = true;
  params.default_color_space = GetDefaultImageDataColorSpace();
  return ImageData::ValidateAndCreate(std::abs(sw), std::abs(sh), std::nullopt,
                                      image_data_settings, params,
                                      exception_state);
}

ImageData* BaseRenderingContext2D::getImageData(
    int sx,
    int sy,
    int sw,
    int sh,
    ExceptionState& exception_state) {
  return getImageDataInternal(sx, sy, sw, sh, /*image_data_settings=*/nullptr,
                              exception_state);
}

ImageData* BaseRenderingContext2D::getImageData(
    int sx,
    int sy,
    int sw,
    int sh,
    ImageDataSettings* image_data_settings,
    ExceptionState& exception_state) {
  return getImageDataInternal(sx, sy, sw, sh, image_data_settings,
                              exception_state);
}
perfetto::EventContext GetEventContext();

ImageData* BaseRenderingContext2D::getImageDataInternal(
    int sx,
    int sy,
    int sw,
    int sh,
    ImageDataSettings* image_data_settings,
    ExceptionState& exception_state) {
  if (!base::CheckMul(sw, sh).IsValid<int>()) {
    exception_state.ThrowRangeError("Out of memory at ImageData creation");
    return nullptr;
  }

  if (layer_count_ != 0) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "`getImageData()` cannot be called with open layers.");
    return nullptr;
  }

  if (!OriginClean()) {
    exception_state.ThrowSecurityError(
        "The canvas has been tainted by cross-origin data.");
  } else if (!sw || !sh) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        String::Format("The source %s is 0.", sw ? "height" : "width"));
  }

  if (exception_state.HadException())
    return nullptr;

  if (sw < 0) {
    if (!base::CheckAdd(sx, sw).IsValid<int>()) {
      exception_state.ThrowRangeError("Out of memory at ImageData creation");
      return nullptr;
    }
    sx += sw;
    sw = base::saturated_cast<int>(base::SafeUnsignedAbs(sw));
  }
  if (sh < 0) {
    if (!base::CheckAdd(sy, sh).IsValid<int>()) {
      exception_state.ThrowRangeError("Out of memory at ImageData creation");
      return nullptr;
    }
    sy += sh;
    sh = base::saturated_cast<int>(base::SafeUnsignedAbs(sh));
  }

  if (!base::CheckAdd(sx, sw).IsValid<int>() ||
      !base::CheckAdd(sy, sh).IsValid<int>()) {
    exception_state.ThrowRangeError("Out of memory at ImageData creation");
    return nullptr;
  }

  const gfx::Rect image_data_rect(sx, sy, sw, sh);

  ImageData::ValidateAndCreateParams validate_and_create_params;
  validate_and_create_params.context_2d_error_mode = true;
  validate_and_create_params.default_color_space =
      GetDefaultImageDataColorSpace();

  if (isContextLost() || !CanCreateCanvas2dResourceProvider()) [[unlikely]] {
    return ImageData::ValidateAndCreate(
        sw, sh, std::nullopt, image_data_settings, validate_and_create_params,
        exception_state);
  }

  // Deferred offscreen canvases might have recorded commands, make sure
  // that those get drawn here
  FinalizeFrame(FlushReason::kGetImageData);

  num_readbacks_performed_++;
  CanvasContextCreationAttributesCore::WillReadFrequently
      will_read_frequently_value = GetCanvasRenderingContextHost()
                                       ->RenderingContext()
                                       ->CreationAttributes()
                                       .will_read_frequently;
  if (num_readbacks_performed_ == 2 && GetCanvasRenderingContextHost() &&
      GetCanvasRenderingContextHost()->RenderingContext()) {
    if (will_read_frequently_value ==
        CanvasContextCreationAttributesCore::WillReadFrequently::kUndefined) {
      if (auto* execution_context = GetTopExecutionContext()) {
        const String& message =
            "Canvas2D: Multiple readback operations using getImageData are "
            "faster with the willReadFrequently attribute set to true. See: "
            "https://html.spec.whatwg.org/multipage/"
            "canvas.html#concept-canvas-will-read-frequently";
        execution_context->AddConsoleMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::blink::ConsoleMessageSource::kRendering,
                mojom::blink::ConsoleMessageLevel::kWarning, message));
      }
    }
  }

  // The default behavior before the willReadFrequently feature existed:
  // Accelerated canvases fall back to CPU when there is a readback.
  if (will_read_frequently_value ==
      CanvasContextCreationAttributesCore::WillReadFrequently::kUndefined) {
    // GetImageData is faster in Unaccelerated canvases.
    // In Desynchronized canvas disabling the acceleration will break
    // putImageData: crbug.com/1112060.
    if (IsAccelerated() && !IsDesynchronized()) {
      read_count_++;
      if (read_count_ >= kFallbackToCPUAfterReadbacks ||
          ShouldDisableAccelerationBecauseOfReadback()) {
        DisableAcceleration();
        base::UmaHistogramEnumeration("Blink.Canvas.GPUFallbackToCPU",
                                      GPUFallbackToCPUScenario::kGetImageData);
      }
    }
  }

  scoped_refptr<StaticBitmapImage> snapshot =
      GetImage(FlushReason::kGetImageData);

  TRACE_EVENT_INSTANT(
      TRACE_DISABLED_BY_DEFAULT("identifiability.high_entropy_api"),
      "CanvasReadback", perfetto::Flow::FromPointer(this),
      [&](perfetto::EventContext ctx) {
        String data = "data:,";
        if (snapshot) {
          std::unique_ptr<ImageDataBuffer> data_buffer =
              ImageDataBuffer::Create(snapshot);
          if (data_buffer) {
            data = data_buffer->ToDataURL(ImageEncodingMimeType::kMimeTypePng,
                                          -1.0);
          }
        }
        ctx.AddDebugAnnotation("data_url", data.Utf8());
      });

  // Determine if the array should be zero initialized, or if it will be
  // completely overwritten.
  validate_and_create_params.zero_initialize = false;
  if (IsAccelerated()) {
    // GPU readback may fail silently.
    validate_and_create_params.zero_initialize = true;
  } else if (snapshot) {
    // Zero-initialize if some of the readback area is out of bounds.
    if (image_data_rect.x() < 0 || image_data_rect.y() < 0 ||
        image_data_rect.right() > snapshot->Size().width() ||
        image_data_rect.bottom() > snapshot->Size().height()) {
      validate_and_create_params.zero_initialize = true;
    }
  }

  ImageData* image_data =
      ImageData::ValidateAndCreate(sw, sh, std::nullopt, image_data_settings,
                                   validate_and_create_params, exception_state);
  if (!image_data)
    return nullptr;

  // Read pixels into |image_data|.
  if (snapshot) {
    gfx::Rect snapshot_rect{snapshot->Size()};
    if (!snapshot_rect.Intersects(image_data_rect)) {
      // If the readback area is completely out of bounds just return a zero
      // initialized buffer. No point in trying to perform out of bounds read.
      CHECK(validate_and_create_params.zero_initialize);
      return image_data;
    }

    SkPixmap image_data_pixmap = image_data->GetSkPixmap();
    const bool read_pixels_successful =
        snapshot->PaintImageForCurrentFrame().readPixels(
            image_data_pixmap.info(), image_data_pixmap.writable_addr(),
            image_data_pixmap.rowBytes(), sx, sy);
    if (!read_pixels_successful) {
      SkIRect bounds =
          snapshot->PaintImageForCurrentFrame().GetSkImageInfo().bounds();
      DCHECK(!bounds.intersect(SkIRect::MakeXYWH(sx, sy, sw, sh)));
    }
  }

  return image_data;
}

void BaseRenderingContext2D::putImageData(ImageData* data,
                                          int dx,
                                          int dy,
                                          ExceptionState& exception_state) {
  putImageData(data, dx, dy, 0, 0, data->width(), data->height(),
               exception_state);
}

void BaseRenderingContext2D::putImageData(ImageData* data,
                                          int dx,
                                          int dy,
                                          int dirty_x,
                                          int dirty_y,
                                          int dirty_width,
                                          int dirty_height,
                                          ExceptionState& exception_state) {
  if (!base::CheckMul(dirty_width, dirty_height).IsValid<int>()) {
    return;
  }

  if (data->IsBufferBaseDetached()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The source data has been detached.");
    return;
  }

  if (layer_count_ != 0) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "`putImageData()` cannot be called with open layers.");
    return;
  }

  bool hasResourceProvider = CanCreateCanvas2dResourceProvider();
  if (!hasResourceProvider)
    return;

  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        CanvasOps::kPutImageData, data->width(), data->height(),
        data->GetPredefinedColorSpace(), data->GetImageDataStorageFormat(), dx,
        dy, dirty_x, dirty_y, dirty_width, dirty_height);
    identifiability_study_helper_.set_encountered_partially_digested_image();
  }

  if (dirty_width < 0) {
    if (dirty_x < 0) {
      dirty_x = dirty_width = 0;
    } else {
      dirty_x += dirty_width;
      dirty_width =
          base::saturated_cast<int>(base::SafeUnsignedAbs(dirty_width));
    }
  }

  if (dirty_height < 0) {
    if (dirty_y < 0) {
      dirty_y = dirty_height = 0;
    } else {
      dirty_y += dirty_height;
      dirty_height =
          base::saturated_cast<int>(base::SafeUnsignedAbs(dirty_height));
    }
  }

  gfx::Rect dest_rect(dirty_x, dirty_y, dirty_width, dirty_height);
  dest_rect.Intersect(gfx::Rect(0, 0, data->width(), data->height()));
  gfx::Vector2d dest_offset(static_cast<int>(dx), static_cast<int>(dy));
  dest_rect.Offset(dest_offset);
  dest_rect.Intersect(gfx::Rect(0, 0, Width(), Height()));
  if (dest_rect.IsEmpty())
    return;

  gfx::Rect source_rect = dest_rect;
  source_rect.Offset(-dest_offset);

  SkPixmap data_pixmap = data->GetSkPixmap();

  // WritePixels (called by PutByteArray) requires that the source and
  // destination pixel formats have the same bytes per pixel.
  if (auto* host = GetCanvasRenderingContextHost()) {
    SkColorType dest_color_type =
        host->GetRenderingContextSkColorInfo().colorType();
    if (SkColorTypeBytesPerPixel(dest_color_type) !=
        SkColorTypeBytesPerPixel(data_pixmap.colorType())) {
      SkImageInfo converted_info =
          data_pixmap.info().makeColorType(dest_color_type);
      SkBitmap converted_bitmap;
      if (!converted_bitmap.tryAllocPixels(converted_info)) {
        exception_state.ThrowRangeError("Out of memory in putImageData");
        return;
      }
      if (!converted_bitmap.writePixels(data_pixmap, 0, 0)) {
        NOTREACHED() << "Failed to convert ImageData with writePixels.";
      }

      PutByteArray(converted_bitmap.pixmap(), source_rect, dest_offset);
      if (GetPaintCanvas()) {
        WillDraw(gfx::RectToSkIRect(dest_rect),
                 CanvasPerformanceMonitor::DrawType::kImageData);
      }
      return;
    }
  }

  PutByteArray(data_pixmap, source_rect, dest_offset);
  if (GetPaintCanvas()) {
    WillDraw(gfx::RectToSkIRect(dest_rect),
             CanvasPerformanceMonitor::DrawType::kImageData);
  }
}

void BaseRenderingContext2D::PutByteArray(const SkPixmap& source,
                                          const gfx::Rect& source_rect,
                                          const gfx::Vector2d& dest_offset) {
  if (!IsCanvas2DBufferValid())
    return;

  DCHECK(gfx::Rect(source.width(), source.height()).Contains(source_rect));
  int dest_x = dest_offset.x() + source_rect.x();
  DCHECK_GE(dest_x, 0);
  DCHECK_LT(dest_x, Width());
  int dest_y = dest_offset.y() + source_rect.y();
  DCHECK_GE(dest_y, 0);
  DCHECK_LT(dest_y, Height());

  SkImageInfo info =
      source.info().makeWH(source_rect.width(), source_rect.height());
  if (!HasAlpha()) {
    // If the surface is opaque, tell it that we are writing opaque
    // pixels.  Writing non-opaque pixels to opaque is undefined in
    // Skia.  There is some discussion about whether it should be
    // defined in skbug.com/6157.  For now, we can get the desired
    // behavior (memcpy) by pretending the write is opaque.
    info = info.makeAlphaType(kOpaque_SkAlphaType);
  } else {
    info = info.makeAlphaType(kUnpremul_SkAlphaType);
  }

  WritePixels(info, source.addr(source_rect.x(), source_rect.y()),
              source.rowBytes(), dest_x, dest_y);
}

void BaseRenderingContext2D::InflateStrokeRect(gfx::RectF& rect) const {
  // Fast approximation of the stroke's bounding rect.
  // This yields a slightly oversized rect but is very fast
  // compared to Path::strokeBoundingRect().
  static const double kRoot2 = sqrtf(2);
  const CanvasRenderingContext2DState& state = GetState();
  double delta = state.LineWidth() / 2;
  if (state.GetLineJoin() == kMiterJoin) {
    delta *= state.MiterLimit();
  } else if (state.GetLineCap() == kSquareCap) {
    delta *= kRoot2;
  }

  rect.Outset(ClampTo<float>(delta));
}

bool BaseRenderingContext2D::imageSmoothingEnabled() const {
  return GetState().ImageSmoothingEnabled();
}

void BaseRenderingContext2D::setImageSmoothingEnabled(bool enabled) {
  CanvasRenderingContext2DState& state = GetState();
  if (enabled == state.ImageSmoothingEnabled()) {
    return;
  }
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        CanvasOps::kSetImageSmoothingEnabled, enabled);
  }

  state.SetImageSmoothingEnabled(enabled);
}

V8ImageSmoothingQuality BaseRenderingContext2D::imageSmoothingQuality() const {
  return GetState().ImageSmoothingQuality();
}

void BaseRenderingContext2D::setImageSmoothingQuality(
    const V8ImageSmoothingQuality& quality) {
  CanvasRenderingContext2DState& state = GetState();
  if (quality == state.ImageSmoothingQuality()) {
    return;
  }

  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        CanvasOps::kSetImageSmoothingQuality,
        IdentifiabilitySensitiveStringToken(quality.AsString()));
  }
  state.SetImageSmoothingQuality(quality);
}

String BaseRenderingContext2D::letterSpacing() const {
  return GetState().GetLetterSpacing();
}

String BaseRenderingContext2D::wordSpacing() const {
  return GetState().GetWordSpacing();
}

String BaseRenderingContext2D::textRenderingAsString() const {
  return GetState().GetTextRendering().AsString();
}

V8CanvasTextRendering BaseRenderingContext2D::textRendering() const {
  return GetState().GetTextRendering();
}

float BaseRenderingContext2D::GetFontBaseline(
    const SimpleFontData& font_data) const {
  return TextMetrics::GetFontBaseline(GetState().GetTextBaseline(), font_data);
}

String BaseRenderingContext2D::textAlign() const {
  return TextAlignName(GetState().GetTextAlign());
}

void BaseRenderingContext2D::setTextAlign(const String& s) {
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        CanvasOps::kSetTextAlign, IdentifiabilityBenignStringToken(s));
  }
  TextAlign align;
  if (!ParseTextAlign(s, align))
    return;
  CanvasRenderingContext2DState& state = GetState();
  if (state.GetTextAlign() == align) {
    return;
  }
  state.SetTextAlign(align);
}

String BaseRenderingContext2D::textBaseline() const {
  return TextBaselineName(GetState().GetTextBaseline());
}

void BaseRenderingContext2D::setTextBaseline(const String& s) {
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        CanvasOps::kSetTextBaseline, IdentifiabilityBenignStringToken(s));
  }
  TextBaseline baseline;
  if (!ParseTextBaseline(s, baseline))
    return;
  CanvasRenderingContext2DState& state = GetState();
  if (state.GetTextBaseline() == baseline) {
    return;
  }
  state.SetTextBaseline(baseline);
}

String BaseRenderingContext2D::fontKerning() const {
  return FontDescription::ToString(GetState().GetFontKerning()).LowerASCII();
}

V8CanvasFontStretch BaseRenderingContext2D::fontStretch() const {
  return GetState().GetFontStretch();
}

String BaseRenderingContext2D::fontStretchAsString() const {
  return GetState().GetFontStretch().AsString();
}

String BaseRenderingContext2D::fontVariantCaps() const {
  return FontDescription::ToStringForIdl(GetState().GetFontVariantCaps());
}

void BaseRenderingContext2D::Trace(Visitor* visitor) const {
  visitor->Trace(state_stack_);
  visitor->Trace(dispatch_context_lost_event_timer_);
  visitor->Trace(dispatch_context_restored_event_timer_);
  visitor->Trace(try_restore_context_event_timer_);
  visitor->Trace(color_cache_);
  visitor->Trace(webgpu_access_texture_);
  visitor->Trace(placed_elements_);
  CanvasPath::Trace(visitor);
}

BaseRenderingContext2D::UsageCounters::UsageCounters()
    : num_draw_calls{0, 0, 0, 0, 0, 0, 0},
      bounding_box_perimeter_draw_calls{0.0f, 0.0f, 0.0f, 0.0f,
                                        0.0f, 0.0f, 0.0f},
      bounding_box_area_draw_calls{0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f},
      bounding_box_area_fill_type{0.0f, 0.0f, 0.0f, 0.0f},
      num_non_convex_fill_path_calls(0),
      non_convex_fill_path_area(0.0f),
      num_radial_gradients(0),
      num_linear_gradients(0),
      num_patterns(0),
      num_draw_with_complex_clips(0),
      num_blurred_shadows(0),
      bounding_box_area_times_shadow_blur_squared(0.0f),
      bounding_box_perimeter_times_shadow_blur_squared(0.0f),
      num_filters(0),
      num_get_image_data_calls(0),
      area_get_image_data_calls(0.0),
      num_put_image_data_calls(0),
      area_put_image_data_calls(0.0),
      num_clear_rect_calls(0),
      num_draw_focus_calls(0),
      num_frames_since_reset(0) {}

namespace {

void CanvasOverdrawHistogram(BaseRenderingContext2D::OverdrawOp op) {
  UMA_HISTOGRAM_ENUMERATION("Blink.Canvas.OverdrawOp", op);
}

}  // unnamed namespace

void BaseRenderingContext2D::WillOverwriteCanvas(
    BaseRenderingContext2D::OverdrawOp op) {
  auto* host = GetCanvasRenderingContextHost();
  if (host) {  // CSS paint use cases not counted.
    UseCounter::Count(GetTopExecutionContext(),
                      WebFeature::kCanvasRenderingContext2DHasOverdraw);
    CanvasOverdrawHistogram(op);
    CanvasOverdrawHistogram(OverdrawOp::kTotal);
  }

  // We only hit the kHasTransform bucket if the op is affected by transforms.
  if (op == OverdrawOp::kClearRect || op == OverdrawOp::kDrawImage) {
    const CanvasRenderingContext2DState& state = GetState();
    bool has_clip = state.HasClip();
    bool has_transform = !state.GetTransform().IsIdentity();
    if (has_clip && has_transform) {
      CanvasOverdrawHistogram(OverdrawOp::kHasClipAndTransform);
    }
    if (has_clip) {
      CanvasOverdrawHistogram(OverdrawOp::kHasClip);
    }
    if (has_transform) {
      CanvasOverdrawHistogram(OverdrawOp::kHasTransform);
    }
  }

  if (MemoryManagedPaintRecorder* recorder = Recorder(); recorder != nullptr) {
    recorder->RestartCurrentLayer();
  }
}

void BaseRenderingContext2D::WillUseCurrentFont() const {
  if (HTMLCanvasElement* canvas = HostAsHTMLCanvasElement();
      canvas != nullptr) {
    canvas->GetDocument().GetCanvasFontCache()->WillUseCurrentFont();
  }
}

String BaseRenderingContext2D::font() const {
  const CanvasRenderingContext2DState& state = GetState();
  if (!state.HasRealizedFont()) {
    return kDefaultFont;
  }

  WillUseCurrentFont();
  StringBuilder serialized_font;
  const FontDescription& font_description = state.GetFontDescription();

  if (font_description.Style() == kItalicSlopeValue) {
    serialized_font.Append("italic ");
  }
  if (font_description.Weight() == kBoldWeightValue) {
    serialized_font.Append("bold ");
  } else if (font_description.Weight() != kNormalWeightValue) {
    int weight_as_int = static_cast<int>((float)font_description.Weight());
    serialized_font.AppendNumber(weight_as_int);
    serialized_font.Append(" ");
  }
  if (font_description.VariantCaps() == FontDescription::kSmallCaps) {
    serialized_font.Append("small-caps ");
  }

  serialized_font.AppendNumber(font_description.ComputedSize());
  serialized_font.Append("px ");

  serialized_font.Append(
      ComputedStyleUtils::ValueForFontFamily(font_description.Family())
          ->CssText());

  return serialized_font.ToString();
}

bool BaseRenderingContext2D::WillSetFont() const {
  return true;
}

bool BaseRenderingContext2D::CurrentFontResolvedAndUpToDate() const {
  return GetState().HasRealizedFont();
}

void BaseRenderingContext2D::setFont(const String& new_font) {
  if (!WillSetFont()) [[unlikely]] {
    return;
  }

  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        CanvasOps::kSetFont, IdentifiabilityBenignStringToken(new_font));
  }

  CanvasRenderingContext2DState& state = GetState();
  if (new_font == state.UnparsedFont() && CurrentFontResolvedAndUpToDate()) {
    return;
  }

  if (!ResolveFont(new_font)) {
    return;
  }

  // The parse succeeded.
  state.SetUnparsedFont(new_font);
}

static inline TextDirection ToTextDirection(
    CanvasRenderingContext2DState::Direction direction,
    HTMLCanvasElement* canvas,
    const ComputedStyle** computed_style = nullptr) {
  const ComputedStyle* style =
      (canvas &&
       (computed_style ||
        direction == CanvasRenderingContext2DState::kDirectionInherit))
          ? canvas->EnsureComputedStyle()
          : nullptr;
  if (computed_style) {
    *computed_style = style;
  }
  switch (direction) {
    case CanvasRenderingContext2DState::kDirectionInherit:
      return style ? style->Direction() : TextDirection::kLtr;
    case CanvasRenderingContext2DState::kDirectionRTL:
      return TextDirection::kRtl;
    case CanvasRenderingContext2DState::kDirectionLTR:
      return TextDirection::kLtr;
  }
  NOTREACHED();
}

HTMLCanvasElement* BaseRenderingContext2D::HostAsHTMLCanvasElement() const {
  return nullptr;
}

OffscreenCanvas* BaseRenderingContext2D::HostAsOffscreenCanvas() const {
  return nullptr;
}

String BaseRenderingContext2D::direction() const {
  HTMLCanvasElement* canvas = HostAsHTMLCanvasElement();
  const CanvasRenderingContext2DState& state = GetState();
  if (state.GetDirection() ==
          CanvasRenderingContext2DState::kDirectionInherit &&
      canvas) {
    canvas->GetDocument().UpdateStyleAndLayoutTreeForElement(
        canvas, DocumentUpdateReason::kCanvas);
  }
  return ToTextDirection(state.GetDirection(), canvas) == TextDirection::kRtl
             ? kRtlDirectionString
             : kLtrDirectionString;
}

void BaseRenderingContext2D::setDirection(const String& direction_string) {
  CanvasRenderingContext2DState::Direction direction;
  if (direction_string == kInheritDirectionString) {
    direction = CanvasRenderingContext2DState::kDirectionInherit;
  } else if (direction_string == kRtlDirectionString) {
    direction = CanvasRenderingContext2DState::kDirectionRTL;
  } else if (direction_string == kLtrDirectionString) {
    direction = CanvasRenderingContext2DState::kDirectionLTR;
  } else {
    return;
  }

  CanvasRenderingContext2DState& state = GetState();
  if (state.GetDirection() == direction) {
    return;
  }

  state.SetDirection(direction);
}

void BaseRenderingContext2D::fillText(const String& text, double x, double y) {
  DrawTextInternal(text, x, y, CanvasRenderingContext2DState::kFillPaintType);
}

void BaseRenderingContext2D::fillText(const String& text,
                                      double x,
                                      double y,
                                      double max_width) {
  DrawTextInternal(text, x, y, CanvasRenderingContext2DState::kFillPaintType,
                   &max_width);
}

void BaseRenderingContext2D::fillTextCluster(const TextCluster* text_cluster,
                                             double x,
                                             double y) {
  DrawTextInternal(
      text_cluster->text(), text_cluster->x() + x, text_cluster->y() + y,
      CanvasRenderingContext2DState::kFillPaintType, nullptr, text_cluster);
}

void BaseRenderingContext2D::strokeText(const String& text,
                                        double x,
                                        double y) {
  DrawTextInternal(text, x, y, CanvasRenderingContext2DState::kStrokePaintType);
}

void BaseRenderingContext2D::strokeText(const String& text,
                                        double x,
                                        double y,
                                        double max_width) {
  DrawTextInternal(text, x, y, CanvasRenderingContext2DState::kStrokePaintType,
                   &max_width);
}

const Font& BaseRenderingContext2D::AccessFont(HTMLCanvasElement* canvas) {
  const CanvasRenderingContext2DState& state = GetState();
  if (!state.HasRealizedFont()) {
    setFont(state.UnparsedFont());
  }
  if (canvas) {
    canvas->GetDocument().GetCanvasFontCache()->WillUseCurrentFont();
  }
  return state.GetFont();
}

void BaseRenderingContext2D::DrawTextInternal(
    const String& text,
    double x,
    double y,
    CanvasRenderingContext2DState::PaintType paint_type,
    double* max_width,
    const TextCluster* text_cluster) {
  HTMLCanvasElement* canvas = HostAsHTMLCanvasElement();
  if (canvas) {
    // The style resolution required for fonts is not available in frame-less
    // documents.
    if (!canvas->GetDocument().GetFrame()) {
      return;
    }

    // accessFont needs the styl
"""


```