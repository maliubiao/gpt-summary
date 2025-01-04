Response:
The user wants a summary of the functionalities implemented in the provided C++ code snippet from `html_canvas_element.cc`.

Here's a breakdown of the thought process to achieve the summary:

1. **Identify the Core Functionality:** The code snippet focuses on actions performed when the canvas content changes and how the canvas content is handled for various purposes like drawing, printing, and creating image bitmaps/blobs.

2. **Analyze Key Methods and Their Purpose:**
    * `NotifyListenersCanvasChanged()`:  This is the central point for informing listeners about canvas changes. It involves optimizing the copy process to video frames.
    * `BrokenCanvas()`: Handles displaying a broken image placeholder when the canvas context is lost.
    * `Paint()` and `PaintInternal()`:  Deals with drawing the canvas content onto a `GraphicsContext`, including handling lost contexts and printing scenarios.
    * `Snapshot()`: Creates a bitmap image of the canvas content.
    * `ToDataURLInternal()` and `toDataURL()`: Converts canvas content to a data URL.
    * `toBlob()`: Converts canvas content to a Blob.
    * `AddListener()` and `RemoveListener()`: Manages listeners for canvas draw events.
    * `OriginClean()`: Checks if the canvas content is from the same origin.
    * `GetSourceImageForCanvasInternal()`: Retrieves the canvas content as an image.
    * `CreateImageBitmap()`: Creates an `ImageBitmap` from the canvas.

3. **Group Functionalities by Purpose:** This helps in creating a structured summary. The functionalities can be grouped as:
    * **Notification:** Informing listeners about changes.
    * **Error Handling:** Displaying broken canvas.
    * **Drawing/Painting:** Rendering the canvas content.
    * **Data Export:** Converting to data URLs and Blobs.
    * **Image Acquisition:**  Getting the canvas content as an image.
    * **Image Bitmap Creation:** Creating `ImageBitmap` objects.
    * **Security:** Checking origin cleanliness.

4. **Identify Relationships to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `toDataURL` and `toBlob` methods are directly exposed to JavaScript. The listeners mechanism is related to JavaScript APIs for observing canvas changes. `createImageBitmap` is another JavaScript API.
    * **HTML:** The `HTMLCanvasElement` itself is an HTML element. The `width` and `height` attributes influence the canvas dimensions.
    * **CSS:** The `image-rendering` CSS property affects the rendering quality, as seen in the `SetFilterQuality` method. The `visibility` CSS property affects whether the canvas is drawn.

5. **Infer Assumptions, Inputs, and Outputs (Logical Reasoning):** For example, in `NotifyListenersCanvasChanged`, a key assumption is that there are listeners. The input is the changed canvas content. The output is either a direct copy to a video frame or a bitmap image.

6. **Identify Potential User/Programming Errors:**  Calling `toDataURL` or `toBlob` on a tainted canvas (cross-origin content without CORS) is a common error. Calling these methods when layers are open is another potential error.

7. **Consider User Actions:**  User actions like drawing on the canvas using JavaScript APIs (`getContext('2d')`, `drawImage`, etc.) will eventually trigger the logic in this file when the canvas needs to be rendered, exported, or listened to. Capturing the canvas content using browser APIs for recording or screenshots also involves this code.

8. **Structure the Summary:** Organize the identified functionalities, relationships, reasoning, and potential errors into a clear and concise summary.

9. **Refine and Iterate:** Review the summary to ensure accuracy and completeness, removing redundancy and improving clarity. Specifically for "Part 2 of 3," focus on the functionalities within the provided snippet, acknowledging that it's not the entirety of the file.

By following these steps, the detailed and informative summary provided earlier can be constructed. The key is to break down the code into its fundamental components and understand how those components interact and relate to the broader web ecosystem.
这个代码片段是 `blink/renderer/core/html/canvas/html_canvas_element.cc` 文件的一部分，主要负责处理 `HTMLCanvasElement` 在画布内容发生变化时通知监听器，以及在特定情况下获取画布内容的图像数据并进行处理。

**功能归纳：**

这段代码片段的主要功能可以归纳为以下几点：

1. **通知画布内容变化的监听器 (NotifyListenersCanvasChanged):**
   - 遍历所有注册的 `CanvasDrawListener`。
   - 对于需要新帧的监听器，尝试将渲染结果直接复制到视频帧 (One-Copy 优化)。
   - 如果直接复制失败，则获取画布内容的 `StaticBitmapImage`，并使用 `StaticBitmapImageToVideoFrameCopier` 将其转换为视频帧。

2. **处理画布错误状态 (BrokenCanvas):**
   - 当画布的渲染上下文丢失时，返回一个预定义的“破损画布”图像，用于显示给用户。根据设备像素比率返回不同分辨率的图像。

3. **图像数据获取优化 (GetSourceImageForCanvasInternal):**
   - 提供了一种获取画布内容图像的方法，并考虑了性能优化，例如尝试零拷贝的方式。

**与 JavaScript, HTML, CSS 的关系及举例：**

* **JavaScript:**
    * **事件监听:** `CanvasDrawListener` 通常与 JavaScript 中的事件监听器关联。例如，一个 JavaScript 程序可能注册一个监听器，以便在画布内容被绘制后执行某些操作，比如实时处理画布上的动画帧。
    * **`toDataURL()` 和 `toBlob()`:** 虽然这段代码本身不直接实现 `toDataURL` 或 `toBlob`，但它为这些功能提供了基础，通过 `GetSourceImageForCanvasInternal` 获取画布内容作为图像数据，然后可以被编码成 Data URL 或 Blob。
    * **`requestAnimationFrame()`:**  监听器可能与 `requestAnimationFrame()` 结合使用，以在每次浏览器准备好重新绘制动画帧时收到通知。
    * **`captureStream()`:**  `NotifyListenersCanvasChanged` 中的视频帧复制功能是 `captureStream()` API 的关键组成部分，允许 JavaScript 获取画布内容的实时视频流。

    **举例 (JavaScript):**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const stream = canvas.captureStream();
    stream.getVideoTracks()[0].onframeavailable = (event) => {
      // 在这里处理新的画布帧
      console.log('New canvas frame available!');
    };
    ```
    当画布内容发生变化时，`HTMLCanvasElement::NotifyListenersCanvasChanged` 会被调用，进而通知到 JavaScript 的 `onframeavailable` 回调。

* **HTML:**
    * **`<canvas>` 元素:**  这段代码是 `HTMLCanvasElement` 类的实现，直接关联到 HTML 中的 `<canvas>` 元素。当一个 `<canvas>` 元素被创建并绘制内容时，这段代码会被执行。

    **举例 (HTML):**
    ```html
    <canvas id="myCanvas" width="200" height="100"></canvas>
    ```

* **CSS:**
    * **`image-rendering`:** 虽然这段代码没有直接操作 CSS 属性，但 `HTMLCanvasElement` 会根据 CSS 的 `image-rendering` 属性设置不同的过滤质量，影响 `GetSourceImageForCanvasInternal` 返回的图像质量。

    **举例 (CSS):**
    ```css
    #myCanvas {
      image-rendering: pixelated; /* 告知浏览器以像素化的方式渲染画布 */
    }
    ```
    当 `image-rendering` 为 `pixelated` 时，`HTMLCanvasElement` 可能会选择不进行平滑处理，这会影响到通过 `GetSourceImageForCanvasInternal` 获取的图像。

**逻辑推理、假设输入与输出：**

**假设输入：**
1. `HTMLCanvasElement` 对象 `canvas_element` 已经存在，并且其上注册了若干个 `CanvasDrawListener` 对象。
2. 画布的内容因为 JavaScript 代码的绘制操作发生了变化。
3. `kOneCopyCanvasCapture` 功能处于启用状态。
4. 监听器 `listener1` 的 `NeedsNewFrame()` 返回 `true`，`CanDiscardAlpha()` 返回 `false`。
5. 监听器 `listener2` 的 `NeedsNewFrame()` 返回 `true`，`CanDiscardAlpha()` 返回 `true`。
6. 画布的渲染上下文 `context_` 是不透明的 (`context_->CanvasRenderingContextSkColorInfo().isOpaque()` 为 `true`)。

**输出与推理：**

1. **处理 `listener1`:**
   - 进入 `NotifyListenersCanvasChanged` 的循环。
   - `listener1->NeedsNewFrame()` 为 `true`，继续处理。
   - `context_color_is_opaque` 为 `true`，`can_discard_alpha` 为 `false`，`kOneCopyCanvasCapture` 已启用。
   - 尝试调用 `context_->CopyRenderingResultsToVideoFrame(...)`。
   - **假设** `context_->CopyRenderingResultsToVideoFrame(...)` **成功**：`TRACE_EVENT1` 会记录 `one_copy_canvas_capture` 为 `true`，并继续处理下一个监听器。
   - **假设** `context_->CopyRenderingResultsToVideoFrame(...)` **失败**：`TRACE_EVENT1` 会记录 `one_copy_canvas_capture` 为 `false`。由于 `source_image` 为空，会调用 `GetSourceImageForCanvasInternal(...)` 获取图像。然后使用 `copier_->Convert(...)` 将 `source_image` 转换为视频帧，并通过 `split_callback.second` 调用监听器的回调。

2. **处理 `listener2`:**
   - `listener2->NeedsNewFrame()` 为 `true`，继续处理。
   - `context_color_is_opaque` 为 `true`，`can_discard_alpha` 为 `true`，`kOneCopyCanvasCapture` 已启用。
   - 尝试调用 `context_->CopyRenderingResultsToVideoFrame(...)`。
   - **假设** `context_->CopyRenderingResultsToVideoFrame(...)` **成功**：`TRACE_EVENT1` 会记录 `one_copy_canvas_capture` 为 `true`，并继续处理下一个监听器。
   - **假设** `context_->CopyRenderingResultsToVideoFrame(...)` **失败**：`TRACE_EVENT1` 会记录 `one_copy_canvas_capture` 为 `false`。由于 `source_image` 可能已经被 `listener1` 获取，这里会检查 `source_image` 是否为空。如果非空，则直接使用 `copier_->Convert(...)`。否则，先调用 `GetSourceImageForCanvasInternal(...)`。

**用户或编程常见的使用错误：**

1. **忘记注册监听器:**  如果开发者希望在画布内容变化时执行某些操作，但忘记注册 `CanvasDrawListener`，那么 `NotifyListenersCanvasChanged` 中的循环不会执行任何与该操作相关的代码。
2. **误判 `NeedsNewFrame()`:** 如果监听器的 `NeedsNewFrame()` 方法实现不正确，可能会导致不必要的处理或错过重要的帧更新。
3. **不理解 One-Copy 机制的限制:** 开发者可能期望 One-Copy 始终生效，但实际上它受到多种条件限制（上下文是否不透明，是否可以丢弃 Alpha 通道，特性是否启用）。
4. **在没有绘制操作的情况下期望收到通知:** `NotifyListenersCanvasChanged` 通常在画布发生实际绘制操作后被触发。如果画布只是被创建但没有绘制内容，可能不会立即触发通知。

**用户操作如何一步步到达这里：**

1. **用户在浏览器中打开包含 `<canvas>` 元素的网页。**
2. **JavaScript 代码获取到 `canvas` 元素的引用。**
3. **JavaScript 代码使用 Canvas API（例如 `getContext('2d')` 并调用绘图方法）在画布上进行绘制操作。**
4. **Blink 渲染引擎处理这些绘制操作，并更新画布的渲染结果。**
5. **当画布的内容发生变化，并且有注册的 `CanvasDrawListener` 时，Blink 内部会调用 `HTMLCanvasElement::NotifyListenersCanvasChanged()`。**
6. **`NotifyListenersCanvasChanged()` 遍历监听器，并尝试通知它们画布内容的变化。**
7. **如果启用了 `captureStream()` 并且 JavaScript 代码正在监听 `onframeavailable` 事件，那么复制到视频帧的操作将会把新的画布帧传递给 JavaScript。**

**总结这段代码片段的功能：**

这段代码片段的核心在于**高效地通知监听器画布内容的变化**，并**优化画布内容到视频帧的转换过程**。它还负责在画布渲染上下文丢失时提供错误显示的机制。  其目标是为诸如 `captureStream()` 这样的功能提供底层支持，确保画布内容的实时更新能够被高效地传递到需要的地方（例如 JavaScript 代码或视频编码器）。

Prompt: 
```
这是目录为blink/renderer/core/html/canvas/html_canvas_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
这是第2部分，共3部分，请归纳一下它的功能

"""
<StaticBitmapImageToVideoFrameCopier>(
        WebGraphicsContext3DVideoFramePool::
            IsGpuMemoryBufferReadbackFromTextureEnabled());
  }

  const bool context_color_is_opaque =
      context_ ? context_->CanvasRenderingContextSkColorInfo().isOpaque()
               : false;

  for (CanvasDrawListener* listener : listeners_) {
    if (!listener->NeedsNewFrame())
      continue;

    // Split the listener's callback so that it can be used with both the one
    // copy path and fallback two copy path below.
    auto split_callback =
        base::SplitOnceCallback(listener->GetNewFrameCallback());
    const bool can_discard_alpha = listener->CanDiscardAlpha();

    // First attempt to copy directly from the rendering context to a video
    // frame. Not all rendering contexts need to support this (for contexts
    // where GetSourceImageForCanvasInternal is zero-copy, this is superfluous).
    if (context_ && (context_color_is_opaque || can_discard_alpha) &&
        base::FeatureList::IsEnabled(kOneCopyCanvasCapture)) {
      if (context_->CopyRenderingResultsToVideoFrame(
              copier_->GetAcceleratedVideoFramePool(
                  SharedGpuContext::ContextProviderWrapper()),
              kBackBuffer, gfx::ColorSpace::CreateREC709(),
              std::move(split_callback.first))) {
        TRACE_EVENT1("blink", "HTMLCanvasElement::NotifyListenersCanvasChanged",
                     "one_copy_canvas_capture", true);
        continue;
      }
    }

    // If that fails, then create a StaticBitmapImage for the contents of
    // the RenderingContext.
    TRACE_EVENT1("blink", "HTMLCanvasElement::NotifyListenersCanvasChanged",
                 "one_copy_canvas_capture", false);

    if (!source_image) {
      SourceImageStatus status;
      source_image =
          GetSourceImageForCanvasInternal(FlushReason::kDrawListener, &status);
      if (status != kNormalSourceImageStatus)
        continue;
    }

    // Here we need to use the SharedGpuContext as some of the images may
    // have been originated with other contextProvider, but we internally
    // need a context_provider that has a RasterInterface available.
    copier_->Convert(source_image, can_discard_alpha,
                     SharedGpuContext::ContextProviderWrapper(),
                     std::move(split_callback.second));
  }
}

// Returns an image and the image's resolution scale factor.
std::pair<blink::Image*, float> HTMLCanvasElement::BrokenCanvas(
    float device_scale_factor) {
  if (device_scale_factor >= 2) {
    DEFINE_STATIC_REF(blink::Image, broken_canvas_hi_res,
                      (blink::Image::LoadPlatformResource(IDR_BROKENCANVAS,
                                                          ui::k200Percent)));
    return std::make_pair(broken_canvas_hi_res, 2);
  }

  DEFINE_STATIC_REF(blink::Image, broken_canvas_lo_res,
                    (blink::Image::LoadPlatformResource(IDR_BROKENCANVAS)));
  return std::make_pair(broken_canvas_lo_res, 1);
}

bool HTMLCanvasElement::LowLatencyEnabled() const {
  return !!frame_dispatcher_;
}

void HTMLCanvasElement::SetFilterQuality(
    cc::PaintFlags::FilterQuality filter_quality) {
  CanvasResourceHost::SetFilterQuality(filter_quality);
  if (IsOffscreenCanvasRegistered())
    UpdateOffscreenCanvasFilterQuality(filter_quality);

  if (context_ &&
      (IsWebGL() || IsWebGPU() || IsImageBitmapRenderingContext())) {
    context_->SetFilterQuality(filter_quality);
  }
}

// In some instances we don't actually want to paint to the parent layer
// We still might want to set filter quality and MarkFirstContentfulPaint though
void HTMLCanvasElement::Paint(GraphicsContext& context,
                              const PhysicalRect& r,
                              bool flatten_composited_layers) {
  if (context_creation_was_blocked_ ||
      (context_ && context_->isContextLost())) {
    float dpr = GetDocument().DevicePixelRatio();
    std::pair<Image*, float> broken_canvas_and_image_scale_factor =
        BrokenCanvas(dpr);
    Image* broken_canvas = broken_canvas_and_image_scale_factor.first;
    context.Save();
    context.FillRect(
        gfx::RectF(r), Color::kWhite,
        PaintAutoDarkMode(ComputedStyleRef(),
                          DarkModeFilter::ElementRole::kBackground),
        SkBlendMode::kSrc);
    // Place the icon near the upper left, like the missing image icon
    // for image elements. Offset it a bit from the upper corner.
    gfx::SizeF icon_size(broken_canvas->Size());
    icon_size.Scale(0.5f);
    gfx::PointF upper_left =
        gfx::PointF(r.PixelSnappedOffset()) +
        gfx::Vector2dF(icon_size.width(), icon_size.height());
    // Make the icon more visually prominent on high-DPI displays.
    icon_size.Scale(dpr);
    context.DrawImage(*broken_canvas, Image::kSyncDecode,
                      ImageAutoDarkMode::Disabled(), ImagePaintTimingInfo(),
                      gfx::RectF(upper_left, icon_size));
    context.Restore();
    return;
  }

  // FIXME: crbug.com/438240; there is a bug with the new CSS blending and
  // compositing feature.
  if (!context_ && !OffscreenCanvasFrame())
    return;

  // If the canvas is gpu composited, it has another way of getting to screen
  if (!PaintsIntoCanvasBuffer()) {
    // For click-and-drag or printing we still want to draw
    if (!(flatten_composited_layers || GetDocument().Printing()))
      return;
  }

  if (OffscreenCanvasFrame()) {
    DCHECK(GetDocument().Printing());
    scoped_refptr<StaticBitmapImage> image_for_printing =
        OffscreenCanvasFrame()->Bitmap()->MakeUnaccelerated();
    if (!image_for_printing)
      return;
    context.DrawImage(*image_for_printing, Image::kSyncDecode,
                      ImageAutoDarkMode::Disabled(), ImagePaintTimingInfo(),
                      gfx::RectF(ToPixelSnappedRect(r)));
    return;
  }

  PaintInternal(context, r);
}

void HTMLCanvasElement::PaintInternal(GraphicsContext& context,
                                      const PhysicalRect& r) {
  context_->PaintRenderingResultsToCanvas(kFrontBuffer);
  CanvasResourceProvider* provider = ResourceProvider();
  if (provider != nullptr) {
    // For 2D Canvas, there are two ways of render Canvas for printing:
    // display list or image snapshot. Display list allows better PDF printing
    // and we prefer this method.
    // Here are the requirements for display list to be used:
    //    1. We must have had a full repaint of the Canvas after beforeprint
    //       event has been fired. Otherwise, we don't have a PaintRecord.
    //    2. CSS property 'image-rendering' must not be 'pixelated'.

    // display list rendering: we replay the last full PaintRecord, if Canvas
    // has been redraw since beforeprint happened.

    // Note: Test coverage for this is assured by manual (non-automated)
    // web test printing/manual/canvas2d-vector-text.html
    // That test should be run manually against CLs that touch this code.
    if (IsPrinting() && IsRenderingContext2D() && canvas2d_bridge_) {
      FlushRecording(FlushReason::kPrinting);
      // `FlushRecording` might be a no-op if a flush already happened before.
      // Fortunately, the last flush recording was kept by the provider.
      const std::optional<cc::PaintRecord>& last_recording =
          provider->LastRecording();
      if (last_recording.has_value() &&
          FilterQuality() != cc::PaintFlags::FilterQuality::kNone) {
        context.Canvas()->save();
        context.Canvas()->translate(r.X(), r.Y());
        context.Canvas()->scale(r.Width() / Size().width(),
                                r.Height() / Size().height());
        context.Canvas()->drawPicture(*last_recording);
        context.Canvas()->restore();
        UMA_HISTOGRAM_BOOLEAN("Blink.Canvas.2DPrintingAsVector", true);
        return;
      }
      UMA_HISTOGRAM_ENUMERATION("Blink.Canvas.VectorPrintFallbackReason",
                                provider->printing_fallback_reason());
      UMA_HISTOGRAM_BOOLEAN("Blink.Canvas.2DPrintingAsVector", false);
    }
    // or image snapshot rendering: grab a snapshot and raster it.
    SkBlendMode composite_operator =
        !context_ || context_->CreationAttributes().alpha
            ? SkBlendMode::kSrcOver
            : SkBlendMode::kSrc;
    gfx::RectF src_rect((gfx::SizeF(Size())));

    // Note: If hibernation is supported (i.e., there is a non-null hibernation
    // handler), go through the context to take a snapshot - this will result in
    // the snapshot being taken via the hibernation handler in the case where
    // the canvas is hibernating. Otherwise, get the snapshot directly from the
    // CanvasResourceProvider.
    bool has_hibernation_handler = GetHibernationHandler() != nullptr;
    scoped_refptr<StaticBitmapImage> snapshot =
        has_hibernation_handler
            ? context_->GetImage(FlushReason::kPaint)
            : (ResourceProvider()
                   ? ResourceProvider()->Snapshot(FlushReason::kPaint)
                   : nullptr);
    if (snapshot) {
      // GraphicsContext cannot handle gpu resource serialization.
      snapshot = snapshot->MakeUnaccelerated();
      DCHECK(!snapshot->IsTextureBacked());
      context.DrawImage(*snapshot, Image::kSyncDecode,
                        ImageAutoDarkMode::Disabled(), ImagePaintTimingInfo(),
                        gfx::RectF(ToPixelSnappedRect(r)), &src_rect,
                        composite_operator);
    }
  } else {
    // When alpha is false, we should draw to opaque black.
    if (!context_->CreationAttributes().alpha) {
      context.FillRect(
          gfx::RectF(r), Color(0, 0, 0),
          PaintAutoDarkMode(ComputedStyleRef(),
                            DarkModeFilter::ElementRole::kBackground));
    }
  }

  if (IsWebGL() && PaintsIntoCanvasBuffer())
    context_->MarkLayerComposited();
}

bool HTMLCanvasElement::IsPrinting() const {
  return GetDocument().BeforePrintingOrPrinting();
}

UkmParameters HTMLCanvasElement::GetUkmParameters() {
  return {GetDocument().UkmRecorder(), GetDocument().UkmSourceID()};
}

void HTMLCanvasElement::SetSurfaceSize(gfx::Size size) {
  CanvasResourceHost::SetSize(size);
  did_fail_to_create_resource_provider_ = false;
  DiscardResourceProvider();
  if (IsRenderingContext2D() && context_->isContextLost())
    context_->RestoreProviderAndContextIfPossible();
  if (frame_dispatcher_)
    frame_dispatcher_->Reshape(Size());
}

const AtomicString HTMLCanvasElement::ImageSourceURL() const {
  return AtomicString(ToDataURLInternal(
      ImageEncoderUtils::kDefaultRequestedMimeType, 0, kFrontBuffer));
}

scoped_refptr<StaticBitmapImage> HTMLCanvasElement::Snapshot(
    FlushReason reason,
    SourceDrawingBuffer source_buffer) const {
  if (Size().IsEmpty()) {
    return nullptr;
  }

  scoped_refptr<StaticBitmapImage> image_bitmap;
  if (OffscreenCanvasFrame()) {  // Offscreen Canvas
    DCHECK(OffscreenCanvasFrame()->OriginClean());
    image_bitmap = OffscreenCanvasFrame()->Bitmap();
  } else if (IsWebGL()) {
    if (context_->CreationAttributes().premultiplied_alpha) {
      context_->PaintRenderingResultsToCanvas(source_buffer);
      if (ResourceProvider())
        image_bitmap = ResourceProvider()->Snapshot(reason);
    } else {
      sk_sp<SkData> pixel_data =
          context_->PaintRenderingResultsToDataArray(source_buffer);
      if (pixel_data) {
        // If the accelerated canvas is too big, there is a logic in WebGL code
        // path that scales down the drawing buffer to the maximum supported
        // size. Hence, we need to query the adjusted size of DrawingBuffer.
        gfx::Size adjusted_size = context_->DrawingBufferSize();
        if (!adjusted_size.IsEmpty()) {
          SkColorInfo color_info =
              GetRenderingContextSkColorInfo().makeAlphaType(
                  kUnpremul_SkAlphaType);
          if (color_info.colorType() == kN32_SkColorType)
            color_info = color_info.makeColorType(kRGBA_8888_SkColorType);
          else
            color_info = color_info.makeColorType(kRGBA_F16_SkColorType);
          image_bitmap = StaticBitmapImage::Create(
              std::move(pixel_data),
              SkImageInfo::Make(
                  SkISize::Make(adjusted_size.width(), adjusted_size.height()),
                  color_info));
        }
      }
    }
  } else if (context_) {
    DCHECK(IsRenderingContext2D() || IsImageBitmapRenderingContext() ||
           IsWebGPU());
    image_bitmap = context_->GetImage(reason);
  }

  if (image_bitmap)
    DCHECK(image_bitmap->SupportsDisplayCompositing());
  else
    image_bitmap = CreateTransparentImage(Size());

  return image_bitmap;
}

String HTMLCanvasElement::ToDataURLInternal(
    const String& mime_type,
    const double& quality,
    SourceDrawingBuffer source_buffer) const {
  base::TimeTicks start_time = base::TimeTicks::Now();
  if (!IsPaintable())
    return String("data:,");

  ImageEncodingMimeType encoding_mime_type =
      ImageEncoderUtils::ToEncodingMimeType(
          mime_type, ImageEncoderUtils::kEncodeReasonToDataURL);

  scoped_refptr<StaticBitmapImage> image_bitmap =
      Snapshot(FlushReason::kToDataURL, source_buffer);
  if (image_bitmap) {
    std::unique_ptr<ImageDataBuffer> data_buffer =
        ImageDataBuffer::Create(image_bitmap);
    if (!data_buffer)
      return String("data:,");

    String data_url = data_buffer->ToDataURL(encoding_mime_type, quality);
    base::TimeDelta elapsed_time = base::TimeTicks::Now() - start_time;
    float sqrt_pixels =
        std::sqrt(image_bitmap->width()) * std::sqrt(image_bitmap->height());
    float scaled_time_float = elapsed_time.InMicrosecondsF() /
                              (sqrt_pixels == 0 ? 1.0f : sqrt_pixels);

    // If scaled_time_float overflows as integer, CheckedNumeric will store it
    // as invalid, then ValueOrDefault will return the maximum int.
    base::CheckedNumeric<int> checked_scaled_time = scaled_time_float;
    int scaled_time_int =
        checked_scaled_time.ValueOrDefault(std::numeric_limits<int>::max());

    if (encoding_mime_type == kMimeTypePng) {
      UMA_HISTOGRAM_COUNTS_100000("Blink.Canvas.ToDataURLScaledDuration.PNG",
                                  scaled_time_int);
    } else if (encoding_mime_type == kMimeTypeJpeg) {
      UMA_HISTOGRAM_COUNTS_100000("Blink.Canvas.ToDataURLScaledDuration.JPEG",
                                  scaled_time_int);
    } else if (encoding_mime_type == kMimeTypeWebp) {
      UMA_HISTOGRAM_COUNTS_100000("Blink.Canvas.ToDataURLScaledDuration.WEBP",
                                  scaled_time_int);
    } else {
      // Currently we only support three encoding types.
      NOTREACHED();
    }
    IdentifiabilityReportWithDigest(IdentifiabilityBenignStringToken(data_url));
    return data_url;
  }

  return String("data:,");
}

String HTMLCanvasElement::toDataURL(const String& mime_type,
                                    const ScriptValue& quality_argument,
                                    ExceptionState& exception_state) const {
  if (ContextHasOpenLayers(context_)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "`toDataURL()` cannot be called with open layers.");
    return String();
  }

  if (!OriginClean()) {
    exception_state.ThrowSecurityError("Tainted canvases may not be exported.");
    return String();
  }

  double quality = kUndefinedQualityValue;
  if (!quality_argument.IsEmpty()) {
    v8::Local<v8::Value> v8_value = quality_argument.V8Value();
    if (v8_value->IsNumber())
      quality = v8_value.As<v8::Number>()->Value();
  }
  String data = ToDataURLInternal(mime_type, quality, kBackBuffer);
  TRACE_EVENT_INSTANT(
      TRACE_DISABLED_BY_DEFAULT("identifiability.high_entropy_api"),
      "CanvasReadback", "data_url", data.Utf8());
  return data;
}

void HTMLCanvasElement::toBlob(V8BlobCallback* callback,
                               const String& mime_type,
                               const ScriptValue& quality_argument,
                               ExceptionState& exception_state) {
  if (!OriginClean()) {
    exception_state.ThrowSecurityError("Tainted canvases may not be exported.");
    return;
  }

  if (!GetExecutionContext())
    return;

  if (ContextHasOpenLayers(context_)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "`toBlob()` cannot be called with open layers.");
    return;
  }

  if (!IsPaintable()) {
    // If the canvas element's bitmap has no pixels
    GetDocument()
        .GetTaskRunner(TaskType::kCanvasBlobSerialization)
        ->PostTask(FROM_HERE,
                   WTF::BindOnce(&V8BlobCallback::InvokeAndReportException,
                                 WrapPersistent(callback), nullptr, nullptr));
    return;
  }

  base::TimeTicks start_time = base::TimeTicks::Now();
  double quality = kUndefinedQualityValue;
  if (!quality_argument.IsEmpty()) {
    v8::Local<v8::Value> v8_value = quality_argument.V8Value();
    if (v8_value->IsNumber())
      quality = v8_value.As<v8::Number>()->Value();
  }

  ImageEncodingMimeType encoding_mime_type =
      ImageEncoderUtils::ToEncodingMimeType(
          mime_type, ImageEncoderUtils::kEncodeReasonToBlobCallback);

  CanvasAsyncBlobCreator* async_creator = nullptr;
  scoped_refptr<StaticBitmapImage> image_bitmap =
      Snapshot(FlushReason::kToBlob, kBackBuffer);
  if (image_bitmap) {
    auto* options = ImageEncodeOptions::Create();
    options->setType(ImageEncodingMimeTypeName(encoding_mime_type));
    async_creator = MakeGarbageCollected<CanvasAsyncBlobCreator>(
        image_bitmap, options,
        CanvasAsyncBlobCreator::kHTMLCanvasToBlobCallback, callback, start_time,
        GetExecutionContext(),
        IdentifiabilityStudySettings::Get()->ShouldSampleType(
            IdentifiableSurface::Type::kCanvasReadback)
            ? IdentifiabilityInputDigest(context_)
            : 0);
  }

  if (async_creator) {
    async_creator->ScheduleAsyncBlobCreation(quality);
  } else {
    GetDocument()
        .GetTaskRunner(TaskType::kCanvasBlobSerialization)
        ->PostTask(FROM_HERE,
                   WTF::BindOnce(&V8BlobCallback::InvokeAndReportException,
                                 WrapPersistent(callback), nullptr, nullptr));
  }
}

bool HTMLCanvasElement::IsPresentationAttribute(
    const QualifiedName& name) const {
  if (name == html_names::kWidthAttr || name == html_names::kHeightAttr)
    return true;
  return HTMLElement::IsPresentationAttribute(name);
}

void HTMLCanvasElement::CollectStyleForPresentationAttribute(
    const QualifiedName& name,
    const AtomicString& value,
    MutableCSSPropertyValueSet* style) {
  if (name == html_names::kWidthAttr) {
    const AtomicString& height = FastGetAttribute(html_names::kHeightAttr);
    if (!height.IsNull())
      ApplyIntegerAspectRatioToStyle(value, height, style);
  } else if (name == html_names::kHeightAttr) {
    const AtomicString& width = FastGetAttribute(html_names::kWidthAttr);
    if (!width.IsNull())
      ApplyIntegerAspectRatioToStyle(width, value, style);
  } else {
    HTMLElement::CollectStyleForPresentationAttribute(name, value, style);
  }
}

void HTMLCanvasElement::AddListener(CanvasDrawListener* listener) {
  // The presence of a listener forces OffscrenCanvas animations to be active
  listeners_.insert(listener);
  UpdateSuspendOffscreenCanvasAnimation();
}

void HTMLCanvasElement::RemoveListener(CanvasDrawListener* listener) {
  listeners_.erase(listener);
  UpdateSuspendOffscreenCanvasAnimation();
}

bool HTMLCanvasElement::OriginClean() const {
  if (GetDocument().GetSettings() &&
      GetDocument().GetSettings()->GetDisableReadingFromCanvas()) {
    return false;
  }
  if (OffscreenCanvasFrame())
    return OffscreenCanvasFrame()->OriginClean();
  return origin_clean_;
}

bool HTMLCanvasElement::ShouldAccelerate2dContext() const {
  return ShouldAccelerate();
}

CanvasResourceDispatcher* HTMLCanvasElement::GetOrCreateResourceDispatcher() {
  // The HTMLCanvasElement override of this method never needs to 'create'
  // because the frame_dispatcher is only used in low latency mode, in which
  // case the dispatcher is created upfront.
  return frame_dispatcher_.get();
}

bool HTMLCanvasElement::PushFrame(scoped_refptr<CanvasResource>&& image,
                                  const SkIRect& damage_rect) {
  NOTIMPLEMENTED();
  return false;
}

bool HTMLCanvasElement::ShouldAccelerate() const {
  if (context_ && !IsRenderingContext2D())
    return false;

  // The command line flag --disable-accelerated-2d-canvas toggles this option
  if (!RuntimeEnabledFeatures::Accelerated2dCanvasEnabled())
    return false;

  // Webview crashes with accelerated small canvases (crbug.com/1004304)
  // Experimenting to see if this still causes crashes (crbug.com/1136603)
  if (!RuntimeEnabledFeatures::AcceleratedSmallCanvasesEnabled() &&
      !base::FeatureList::IsEnabled(
          features::kWebviewAccelerateSmallCanvases)) {
    base::CheckedNumeric<int> checked_canvas_pixel_count =
        Size().GetCheckedArea();
    if (!checked_canvas_pixel_count.IsValid())
      return false;
    int canvas_pixel_count = checked_canvas_pixel_count.ValueOrDie();

    if (canvas_pixel_count < kMinimumAccelerated2dCanvasSize)
      return false;
  }

  // The following is necessary for handling the special case of canvases in
  // the dev tools overlay, which run in a process that supports accelerated
  // 2d canvas but in a special compositing context that does not.
  auto* settings = GetDocument().GetSettings();
  if (settings && !settings->GetAcceleratedCompositingEnabled())
    return false;

  // Avoid creating |contextProvider| until we're sure we want to try use it,
  // since it costs us GPU memory.
  base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper =
      SharedGpuContext::ContextProviderWrapper();
  if (!context_provider_wrapper)
    return false;

  if (context_ &&
      context_->CreationAttributes().will_read_frequently ==
          CanvasContextCreationAttributesCore::WillReadFrequently::kUndefined &&
      DisabledAccelerationCounterSupplement::From(GetDocument())
          .ShouldDisableAcceleration()) {
    return false;
  }

  return context_provider_wrapper->Utils()->Accelerated2DCanvasFeatureEnabled();
}

bool HTMLCanvasElement::ShouldDisableAccelerationBecauseOfReadback() const {
  return DisabledAccelerationCounterSupplement::From(GetDocument())
      .ShouldDisableAcceleration();
}

void HTMLCanvasElement::NotifyGpuContextLost() {
  if (IsRenderingContext2D()) {
    context_->LoseContext(CanvasRenderingContext::kRealLostContext);
  }

  // TODO(juonv): Do we need to do anything about frame_dispatcher_ here?
  // Desynchronized canvases seem to continue to work after recovering from a
  // GPU context loss, so maybe the status quo is fine.
}

void HTMLCanvasElement::Trace(Visitor* visitor) const {
  visitor->Trace(listeners_);
  visitor->Trace(context_);
  ExecutionContextLifecycleObserver::Trace(visitor);
  PageVisibilityObserver::Trace(visitor);
  HTMLElement::Trace(visitor);
}

CanvasHibernationHandler* HTMLCanvasElement::GetHibernationHandler() const {
  return canvas2d_bridge_ ? &canvas2d_bridge_->GetHibernationHandler()
                          : nullptr;
}

Canvas2DLayerBridge* HTMLCanvasElement::GetOrCreateCanvas2DLayerBridge() {
  DCHECK(IsRenderingContext2D());

  if (canvas2d_bridge_) {
    return canvas2d_bridge_.get();
  }

  if (did_fail_to_create_resource_provider_) {
    return nullptr;
  }

  if (!IsValidImageSize(Size())) {
    did_fail_to_create_resource_provider_ = true;
    if (!Size().IsEmpty() && context_) {
      context_->LoseContext(CanvasRenderingContext::kSyntheticLostContext);
    }
    return nullptr;
  }

  // If the canvas meets the criteria to use accelerated-GPU rendering, and
  // the user signals that the canvas will not be read frequently through
  // getImageData, which is a slow operation with GPU, the canvas will try to
  // use accelerated-GPU rendering.
  // If any of the two conditions fails, or if the creation of accelerated
  // resource provider fails, the canvas will fallback to CPU rendering.
  UMA_HISTOGRAM_BOOLEAN(
      "Blink.Canvas.2DLayerBridge.WillReadFrequently",
      context_ &&
          context_->CreationAttributes().will_read_frequently ==
              CanvasContextCreationAttributesCore::WillReadFrequently::kTrue);

  bool will_read_frequently =
      context_->CreationAttributes().will_read_frequently ==
      CanvasContextCreationAttributesCore::WillReadFrequently::kTrue;
  RasterModeHint hint = ShouldAccelerate() && context_ && !will_read_frequently
                            ? RasterModeHint::kPreferGPU
                            : RasterModeHint::kPreferCPU;
  SetPreferred2DRasterMode(hint);
  canvas2d_bridge_ = std::make_unique<Canvas2DLayerBridge>(*this);

  UpdateMemoryUsage();

  if (context_) {
    SetNeedsCompositingUpdate();
  }

  return canvas2d_bridge_.get();
}

void HTMLCanvasElement::SetResourceProviderForTesting(
    std::unique_ptr<CanvasResourceProvider> provider,
    const gfx::Size& size) {
  DiscardResourceProvider();
  SetIntegralAttribute(html_names::kWidthAttr, size.width());
  SetIntegralAttribute(html_names::kHeightAttr, size.height());
  CanvasResourceHost::SetSize(size);
  canvas2d_bridge_ = std::make_unique<Canvas2DLayerBridge>(*this);
  ReplaceResourceProvider(std::move(provider));
}

void HTMLCanvasElement::DiscardResourceProvider() {
  canvas2d_bridge_.reset();
  ResetLayer();
  CanvasResourceHost::DiscardResourceProvider();
  dirty_rect_ = gfx::Rect();
}

void HTMLCanvasElement::UpdateSuspendOffscreenCanvasAnimation() {
  if (GetPage()) {
    SetSuspendOffscreenCanvasAnimation(
        GetPage()->GetVisibilityState() ==
            mojom::blink::PageVisibilityState::kHidden &&
        !HasCanvasCapture());
  }
}

void HTMLCanvasElement::PageVisibilityChanged() {
  // If we are still painting, then continue to allow animations, even if the
  // page is otherwise hidden.
  CanvasRenderingContextHost::PageVisibilityChanged();
  UpdateSuspendOffscreenCanvasAnimation();
}

void HTMLCanvasElement::ContextDestroyed() {
  if (context_)
    context_->Stop();
}

bool HTMLCanvasElement::StyleChangeNeedsDidDraw(
    const ComputedStyle* old_style,
    const ComputedStyle& new_style) {
  // It will only need to redraw for a style change, if the new imageRendering
  // is different than the previous one, and only if one of the two are
  // pixelated.
  return old_style &&
         old_style->ImageRendering() != new_style.ImageRendering() &&
         (old_style->ImageRendering() == EImageRendering::kPixelated ||
          new_style.ImageRendering() == EImageRendering::kPixelated);
}

void HTMLCanvasElement::StyleDidChange(const ComputedStyle* old_style,
                                       const ComputedStyle& new_style) {
  cc::PaintFlags::FilterQuality filter_quality =
      cc::PaintFlags::FilterQuality::kLow;
  if (new_style.ImageRendering() == EImageRendering::kPixelated)
    filter_quality = cc::PaintFlags::FilterQuality::kNone;
  SetFilterQuality(filter_quality);
  style_is_visible_ = new_style.Visibility() == EVisibility::kVisible;
  bool is_displayed = GetLayoutObject() && style_is_visible_;
  SetIsDisplayed(is_displayed);
  if (context_) {
    context_->StyleDidChange(old_style, new_style);
  }
  if (StyleChangeNeedsDidDraw(old_style, new_style))
    DidDraw();
}

void HTMLCanvasElement::LayoutObjectDestroyed() {
  // If the canvas has no layout object then it definitely isn't being
  // displayed any more.
  SetIsDisplayed(false);
}

void HTMLCanvasElement::DidMoveToNewDocument(Document& old_document) {
  SetExecutionContext(GetExecutionContext());
  SetPage(GetDocument().GetPage());
  HTMLElement::DidMoveToNewDocument(old_document);
}

void HTMLCanvasElement::DidRecalcStyle(const StyleRecalcChange change) {
  HTMLElement::DidRecalcStyle(change);
  ColorSchemeMayHaveChanged();
}

void HTMLCanvasElement::RemovedFrom(ContainerNode& insertion_point) {
  HTMLElement::RemovedFrom(insertion_point);
  ColorSchemeMayHaveChanged();
}

void HTMLCanvasElement::WillDrawImageTo2DContext(CanvasImageSource* source) {
  // If the source is GPU-accelerated, and the canvas is not, but could be...
  if (source->IsAccelerated() && ShouldAccelerate() &&
      GetRasterMode() == RasterMode::kCPU) {
    // Recreate the canvas in GPU raster mode, and update its contents.
    if (RecreateCanvasInGPURasterMode()) {
      SetNeedsCompositingUpdate();
    }
  }
}

bool HTMLCanvasElement::EnableAcceleration() {
  return GetRasterMode() == RasterMode::kCPU ? RecreateCanvasInGPURasterMode()
                                             : true;
}

bool HTMLCanvasElement::RecreateCanvasInGPURasterMode() {
  if (!SharedGpuContext::AllowSoftwareToAcceleratedCanvasUpgrade()) {
    return false;
  }
  SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  ReplaceExisting2dLayerBridge();
  return true;
}

scoped_refptr<Image> HTMLCanvasElement::GetSourceImageForCanvas(
    FlushReason reason,
    SourceImageStatus* status,
    const gfx::SizeF&,
    const AlphaDisposition alpha_disposition) {
  return GetSourceImageForCanvasInternal(reason, status, alpha_disposition);
}

scoped_refptr<StaticBitmapImage>
HTMLCanvasElement::GetSourceImageForCanvasInternal(
    FlushReason reason,
    SourceImageStatus* status,
    const AlphaDisposition alpha_disposition) {
  if (ContextHasOpenLayers(context_)) {
    *status = kLayersOpenInCanvasSource;
    return nullptr;
  }

  if (!width() || !height()) {
    *status = kZeroSizeCanvasSourceImageStatus;
    return nullptr;
  }

  if (!IsPaintable()) {
    *status = kInvalidSourceImageStatus;
    return nullptr;
  }

  scoped_refptr<StaticBitmapImage> image;

  if (OffscreenCanvasFrame()) {
    // This may be false to set status to normal if a valid image can be got
    // even if this HTMLCanvasElement has been transferred
    // control to an offscreenCanvas. As offscreencanvas with the
    // TransferControlToOffscreen is asynchronous, this will need to finish the
    // first Frame in order to have a first OffscreenCanvasFrame.
    image = OffscreenCanvasFrame()->Bitmap();
  } else {
    if (IsWebGL() || IsWebGPU()) {
      // TODO(https://crbug.com/672299): Canvas should produce sRGB images.
      // Because WebGL/WebGPU sources always require copying the back buffer,
      // we use PaintRenderingResultsToCanvas instead of GetImage in order to
      // keep a cached copy of the backing in the canvas's resource provider.
      RenderingContext()->PaintRenderingResultsToCanvas(kBackBuffer);
      // TODO(sunnyps): Check what PaintRenderingResultsToCanvas returns. It
      // seems the above returns false unexpectedly in some tests.
      if (ResourceProvider()) {
        image = ResourceProvider()->Snapshot(reason);
      }
    } else if (RenderingContext()) {
      // This is either CanvasRenderingContext2D or ImageBitmapRenderingContext.
      image = RenderingContext()->GetImage(reason);
    }
    if (!image) {
      image = GetTransparentImage();
    }
  }

  if (!image) {
    // All other possible error statuses were checked earlier.
    *status = kInvalidSourceImageStatus;
    return image;
  }

  *status = kNormalSourceImageStatus;

  // If the alpha_disposition is already correct, or the image is opaque, this
  // is a no-op.
  return StaticBitmapImageTransform::GetWithAlphaDisposition(
      reason, std::move(image), alpha_disposition);
}

bool HTMLCanvasElement::WouldTaintOrigin() const {
  return !OriginClean();
}

gfx::SizeF HTMLCanvasElement::ElementSize(
    const gfx::SizeF&,
    const RespectImageOrientationEnum) const {
  if (IsImageBitmapRenderingContext()) {
    scoped_refptr<Image> image =
        RenderingContext()->GetImage(FlushReason::kNone);
    if (image) {
      return gfx::SizeF(image->width(), image->height());
    }
    return gfx::SizeF(0, 0);
  }
  if (OffscreenCanvasFrame()) {
    return gfx::SizeF(OffscreenCanvasFrame()->Size());
  }
  return gfx::SizeF(width(), height());
}

gfx::Size HTMLCanvasElement::BitmapSourceSize() const {
  return Size();
}

ScriptPromise<ImageBitmap> HTMLCanvasElement::CreateImageBitmap(
    ScriptState* script_state,
    std::optional<gfx::Rect> crop_rect,
    const ImageBitmapOptions* options,
    ExceptionState& exception_state) {
  if (ContextHasOpenLayers(context_)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "`createImageBitmap()` cannot be called with open layers.");
    return EmptyPromise();
  }
  return ImageBitmapSource::FulfillImageBitmap(
      script_
"""


```