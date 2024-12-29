Response:
The user wants a summary of the functionality of the provided C++ code for `blink/renderer/modules/webcodecs/video_frame.cc`. This is the second part of a two-part request, so I need to summarize the functionality described in *this* specific code block.

Here's a breakdown of the code's main actions:

1. **`VideoFrame::Create` (from `PaintImage`)**: This function creates a `VideoFrame` from a `PaintImage`. It handles cases where the `PaintImage` is backed by a `StaticBitmapImage` (potentially hardware-accelerated) or a regular `SkImage`. It ensures correct color space and metadata are set.

2. **`VideoFrame::Create` (from `AllowSharedBufferSource`)**: This function creates a `VideoFrame` from raw pixel data provided in a `SharedBuffer` (or similar). It validates input parameters like dimensions, visible rectangle, and data size. It also handles memory management, potentially transferring ownership of the underlying buffer.

3. **Getter methods**:  The code provides various getter methods to access properties of the `VideoFrame`, such as:
    - `format()`: Pixel format.
    - `codedWidth()`, `codedHeight()`: Dimensions of the encoded frame.
    - `codedRect()`, `visibleRect()`: Rectangles representing the coded and visible areas.
    - `rotation()`, `flip()`: Transformation applied to the frame.
    - `displayWidth()`, `displayHeight()`: Dimensions for display.
    - `timestamp()`, `duration()`: Timing information.
    - `colorSpace()`: Color space information.
    - `metadata()`:  Additional metadata.
    - `allocationSize()`:  Size required for copying.

4. **`VideoFrame::ConvertAndCopyToRGB`**:  A utility function to convert the `VideoFrame` to an RGB format and copy it to a provided buffer. This involves using Skia for the conversion.

5. **`VideoFrame::CopyToAsync`**:  Handles asynchronous copying of the `VideoFrame` data to a provided buffer, especially for texture-backed frames.

6. **`VideoFrame::copyTo`**:  The main function for copying the `VideoFrame`'s data to a provided buffer. It handles different scenarios, including:
    - Direct copying for mappable frames.
    - Copying from memory-mapped GPU buffers.
    - Asynchronous copying for texture-backed frames.
    - Potentially using `ConvertAndCopyToRGB` for explicit RGB format requests.

7. **`VideoFrame::close`**: Invalidates the `VideoFrame`, releasing underlying resources.

8. **`VideoFrame::clone`**: Creates a new `VideoFrame` that is a copy of the original.

9. **`VideoFrame::GetSourceImageForCanvas`**:  Provides a way to get an `Image` representation of the `VideoFrame` suitable for rendering on a `<canvas>`. It handles both software and hardware-backed frames.

10. **`VideoFrame::WouldTaintOrigin`**: Indicates whether the `VideoFrame` would introduce a cross-origin taint (currently always false).

11. **`VideoFrame::ElementSize`**: Returns the display size of the `VideoFrame`, optionally taking into account its orientation.

12. **`VideoFrame::IsVideoFrame`**:  A simple check to confirm the object is a `VideoFrame`.

13. **`VideoFrame::IsOpaque`**: Checks if the `VideoFrame` is opaque.

14. **`VideoFrame::IsAccelerated`**:  Checks if the `VideoFrame` is backed by hardware acceleration.

15. **`VideoFrame::ResetExternalMemory`**: Clears external memory accounting.

16. **`VideoFrame::BitmapSourceSize`**: Returns the natural size of the `VideoFrame`.

17. **`VideoFrame::CreateImageBitmap`**: Creates an `ImageBitmap` from the `VideoFrame`. It handles both software and hardware-backed frames, ensuring a copy is made as per the specification.

20. **`VideoFrame::Trace`**:  Handles garbage collection tracing.

Now, I need to organize this information into the requested format, including examples and potential errors.
Based on the provided code snippet for `blink/renderer/modules/webcodecs/video_frame.cc`, here's a summary of its functionality, focusing on the code within this specific section:

**Core Functionality:**

This code defines the `VideoFrame` class, a core component of the WebCodecs API in Chromium. It provides the ability to represent and manipulate video frames within the browser's rendering engine. The primary functions within this snippet revolve around:

1. **Creating `VideoFrame` objects:**
   - **From `PaintImage`:**  Allows creating a `VideoFrame` from an existing image (`PaintImage`). This is useful for scenarios where you want to process still images as video frames. It handles both software-backed and potentially hardware-accelerated images.
   - **From raw data:**  Provides a mechanism to construct a `VideoFrame` from a buffer of raw pixel data along with metadata describing its format, size, and layout. This enables working with decoded or manually created video frames.

2. **Accessing `VideoFrame` properties:**
   - A set of getter methods (`format`, `codedWidth`, `codedHeight`, `codedRect`, `visibleRect`, `rotation`, `flip`, `displayWidth`, `displayHeight`, `timestamp`, `duration`, `colorSpace`, `metadata`, `allocationSize`) allow retrieving various attributes of the `VideoFrame`. These properties describe the frame's dimensions, visible region, transformations, timing, color information, and memory requirements.

3. **Copying `VideoFrame` data:**
   - The `copyTo` method enables copying the pixel data of a `VideoFrame` into a provided `ArrayBuffer`. It supports different copying strategies depending on whether the underlying frame is mappable in memory or resides on the GPU. It also includes an experimental feature for direct copying to RGB formats.

4. **Managing `VideoFrame` lifecycle:**
   - The `close` method releases the resources held by the `VideoFrame`, making it unusable.
   - The `clone` method creates a new `VideoFrame` that is a copy of the original.

5. **Interoperability with the rendering pipeline:**
   - The `GetSourceImageForCanvas` method allows obtaining an `Image` representation of the `VideoFrame`, suitable for rendering on a `<canvas>` element. This bridges the gap between WebCodecs and the 2D graphics API.
   - The `CreateImageBitmap` method creates an `ImageBitmap` from the `VideoFrame`, offering another way to integrate video frames with the browser's graphics capabilities.

**Relationship with Javascript, HTML, and CSS:**

* **Javascript:** This C++ code directly implements the functionality exposed to JavaScript through the `VideoFrame` interface of the WebCodecs API. JavaScript code would call methods like `new VideoFrame(...)`, `videoFrame.copyTo(...)`, `videoFrame.close()`, etc., which are ultimately implemented by the C++ code in this file.

   ```javascript
   // Example in JavaScript:
   const videoFrame = new VideoFrame(imageData, {
     format: 'RGBA',
     codedWidth: 640,
     codedHeight: 480,
     timestamp: 0,
   });

   const buffer = new ArrayBuffer(videoFrame.allocationSize());
   videoFrame.copyTo(buffer).then(planeLayouts => {
     // Process the copied data
   });

   videoFrame.close();
   ```

* **HTML:** While this code doesn't directly manipulate HTML elements, the `VideoFrame` objects created here can be used in conjunction with HTML elements, primarily the `<canvas>` element. The `GetSourceImageForCanvas` and `CreateImageBitmap` methods facilitate this integration.

   ```html
   <canvas id="myCanvas" width="640" height="480"></canvas>
   <script>
     const canvas = document.getElementById('myCanvas');
     const ctx = canvas.getContext('2d');

     // Assume videoFrame is a VideoFrame object
     canvas.getContext('bitmaprenderer').transferFromImageBitmap(await createImageBitmap(videoFrame));
     // OR
     const image = await createImageBitmap(videoFrame);
     ctx.drawImage(image, 0, 0);
   </script>
   ```

* **CSS:** CSS has no direct interaction with the core logic of `VideoFrame` creation and manipulation. However, CSS styles would be used to control the visual presentation of the `<canvas>` element where the `VideoFrame` content might be rendered.

**Logic Reasoning with Assumptions:**

**Scenario 1: Creating a `VideoFrame` from a `PaintImage`**

* **Assumption Input:** A `PaintImage` object representing a PNG image loaded from the network.
* **Code Path:** The `VideoFrame::Create(ScriptState* script_state, const PaintImage& paint_image, ...)` function would be called.
* **Internal Logic:**
    * The code checks if the `PaintImage` is backed by a `StaticBitmapImage` (potentially hardware-accelerated).
    * If it is, it tries to wrap the underlying GPU texture into a `media::VideoFrame` to avoid unnecessary copying.
    * If not, it rasterizes the `PaintImage` into an `SkImage`.
    * It determines the appropriate `media::VideoPixelFormat` based on the `SkImage`'s color type and opacity.
    * It creates a `media::VideoFrame` from the `SkImage`.
* **Output:** A newly created `VideoFrame` object containing the pixel data of the PNG image.

**Scenario 2: Copying a `VideoFrame` to an `ArrayBuffer`**

* **Assumption Input:** A `VideoFrame` object with YUV420 format and a pre-allocated `ArrayBuffer` of sufficient size.
* **Code Path:** The `VideoFrame::copyTo(ScriptState* script_state, const AllowSharedBufferSource* destination, ...)` function would be invoked.
* **Internal Logic:**
    * The code determines if the underlying `media::VideoFrame` is mappable in memory.
    * If mappable, it directly copies the plane data to the `ArrayBuffer`.
    * If not mappable (likely residing on the GPU), it might perform a texture download to the CPU memory before copying. The `CopyToAsync` function handles this asynchronous operation.
* **Output:** The `ArrayBuffer` is filled with the pixel data from the `VideoFrame` according to its layout (planes, strides, offsets). The returned `Promise` resolves with information about the plane layout.

**User or Programming Common Usage Errors:**

1. **Incorrect `ArrayBuffer` size in `copyTo`:**
   - **Error:** Providing an `ArrayBuffer` that is smaller than the value returned by `allocationSize()`.
   - **Example:**
     ```javascript
     const videoFrame = ...;
     const buffer = new ArrayBuffer(100); // Too small!
     videoFrame.copyTo(buffer).catch(error => {
       console.error("Error copying:", error); // Likely "destination is not large enough."
     });
     ```
   - **Debugging:** Check the `allocationSize()` of the `VideoFrame` and ensure the `ArrayBuffer` is at least that large.

2. **Using a closed `VideoFrame`:**
   - **Error:** Attempting to call methods like `copyTo` or access properties on a `VideoFrame` after its `close()` method has been called.
   - **Example:**
     ```javascript
     const videoFrame = ...;
     videoFrame.close();
     videoFrame.copyTo(new ArrayBuffer(videoFrame.allocationSize())).catch(error => {
       console.error("Error copying:", error); // Likely "Cannot copy closed VideoFrame." or similar.
     });
     ```
   - **Debugging:** Ensure that `VideoFrame` objects are only used within their valid lifecycle and that `close()` is called appropriately when they are no longer needed.

3. **Unsupported format in `VideoFrame::Create` (from raw data):**
   - **Error:** Providing a `format` string that is not recognized or supported by the WebCodecs implementation.
   - **Example:**
     ```javascript
     const buffer = new ArrayBuffer(...);
     try {
       const videoFrame = new VideoFrame(buffer, { format: 'UNSUPPORTED_FORMAT', ... });
     } catch (error) {
       console.error("Error creating VideoFrame:", error); // Likely "Unsupported format."
     }
     ```
   - **Debugging:** Refer to the WebCodecs specification for valid `VideoPixelFormat` values.

**User Operations Leading to This Code (as Debugging Clues):**

1. **Decoding video using `VideoDecoder`:** When a `VideoDecoder` decodes a video frame, it often results in the creation of a `VideoFrame` object. The code in this file would be involved in creating and managing these decoded frames.

2. **Processing video from `<canvas>` using `captureStream()` and `VideoFrame` constructor:** A user might capture frames from a canvas and create `VideoFrame` objects for further processing.

3. **Manipulating images using `createImageBitmap()` and then creating a `VideoFrame`:** If a user creates an `ImageBitmap` and then uses the `VideoFrame` constructor with that `ImageBitmap`, the `VideoFrame::Create` method handling `PaintImage` will be invoked.

4. **Receiving raw video data over a network (e.g., WebSockets) and constructing a `VideoFrame`:** A web application might receive raw pixel data and use the `VideoFrame` constructor with a `SharedBuffer` to create a video frame.

5. **Implementing custom video processing pipelines:** Developers might use the `VideoFrame` API to build custom video processing logic, creating, manipulating, and copying video frames as needed.

**Summary of Functionality (Part 2):**

This portion of the `VideoFrame.cc` file primarily focuses on **creating `VideoFrame` objects from various sources (images and raw data), providing access to their properties, enabling the copying of frame data to memory buffers, managing the lifecycle of `VideoFrame` objects, and facilitating their integration with the browser's rendering pipeline (specifically `<canvas>` and `ImageBitmap`).** It encapsulates the core mechanisms for representing and interacting with video frame data within the WebCodecs API.

Prompt: 
```
这是目录为blink/renderer/modules/webcodecs/video_frame.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
();
    const bool is_origin_top_left = sbi->IsOriginTopLeft();

    // The sync token needs to be updated when |frame| is released, but
    // AcceleratedStaticBitmapImage::UpdateSyncToken() is not thread-safe.
    auto release_cb = base::BindPostTaskToCurrentDefault(
        ConvertToBaseOnceCallback(CrossThreadBindOnce(
            [](scoped_refptr<Image> image, const gpu::SyncToken& sync_token) {
              static_cast<StaticBitmapImage*>(image.get())
                  ->UpdateSyncToken(sync_token);
            },
            std::move(image))));

    auto client_shared_image = sbi->GetSharedImage();
    CHECK(client_shared_image);
    frame = media::VideoFrame::WrapSharedImage(
        format, std::move(client_shared_image), mailbox_holder.sync_token,
        std::move(release_cb), coded_size, parsed_init.visible_rect,
        parsed_init.display_size, timestamp);

    if (frame)
      frame->metadata().texture_origin_is_top_left = is_origin_top_left;

    // Note: We could add the StaticBitmapImage to the VideoFrameHandle so we
    // can round trip through VideoFrame back to canvas w/o any copies, but
    // this doesn't seem like a common use case.
  } else {
    // Note: The current PaintImage may be lazy generated, for simplicity, we
    // just ask Skia to rasterize the image for us.
    //
    // A potential optimization could use PaintImage::DecodeYuv() to decode
    // directly into a media::VideoFrame. This would improve VideoFrame from
    // <img> creation, but probably such users should be using ImageDecoder
    // directly.
    sk_image = paint_image.GetSwSkImage();
    if (!sk_image) {
      // Can happen if, for example, |paint_image| is texture-backed and the
      // context was lost.
      exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                        "Failed to create video frame");
      return nullptr;
    }
    if (sk_image->isLazyGenerated()) {
      sk_image = sk_image->makeRasterImage();
      if (!sk_image) {
        exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                          "Failed to create video frame");
        return nullptr;
      }
    }

    const bool force_opaque =
        init && init->alpha() == kAlphaDiscard && !sk_image->isOpaque();

    const auto format = media::VideoPixelFormatFromSkColorType(
        sk_image->colorType(), sk_image->isOpaque() || force_opaque);
    ParsedVideoFrameInit parsed_init(init, format, coded_size,
                                     default_visible_rect, default_display_size,
                                     exception_state);
    if (exception_state.HadException())
      return nullptr;

    frame = media::CreateFromSkImage(sk_image, parsed_init.visible_rect,
                                     parsed_init.display_size, timestamp,
                                     force_opaque);

    // Above format determination unfortunately uses a bit of internal knowledge
    // from CreateFromSkImage(). Make sure they stay in sync.
    DCHECK(!frame || frame->format() == format);

    // If |sk_image| isn't rendered identically to |frame|, don't pass it along
    // when creating the blink::VideoFrame below.
    if (force_opaque || parsed_init.visible_rect != default_visible_rect ||
        parsed_init.display_size != default_display_size) {
      sk_image.reset();
    }
  }

  if (!frame) {
    exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                      "Failed to create video frame");
    return nullptr;
  }

  frame->set_color_space(gfx_color_space);
  if (init->hasDuration()) {
    frame->metadata().frame_duration = base::Microseconds(init->duration());
  }
  frame->metadata().transformation =
      ImageOrientationToVideoTransformation(orientation).add(transformation);
  return MakeGarbageCollected<VideoFrame>(
      base::MakeRefCounted<VideoFrameHandle>(
          std::move(frame), std::move(sk_image),
          ExecutionContext::From(script_state)));
}

VideoFrame* VideoFrame::Create(ScriptState* script_state,
                               const AllowSharedBufferSource* data,
                               const VideoFrameBufferInit* init,
                               ExceptionState& exception_state) {
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  auto* isolate = script_state->GetIsolate();
  auto media_fmt = ToMediaPixelFormat(init->format().AsEnum());

  if (!IsFormatEnabled(media_fmt)) {
    exception_state.ThrowTypeError("Unsupported format.");
    return nullptr;
  }

  // Validate coded size.
  uint32_t coded_width = init->codedWidth();
  uint32_t coded_height = init->codedHeight();
  if (coded_width == 0) {
    exception_state.ThrowTypeError("codedWidth must be nonzero.");
    return nullptr;
  }
  if (coded_height == 0) {
    exception_state.ThrowTypeError("codedHeight must be nonzero.");
    return nullptr;
  }
  if (coded_width > media::limits::kMaxDimension ||
      coded_height > media::limits::kMaxDimension ||
      coded_width * coded_height > media::limits::kMaxCanvas) {
    exception_state.ThrowTypeError(
        String::Format("Coded size %u x %u exceeds implementation limit.",
                       coded_width, coded_height));
    return nullptr;
  }
  const gfx::Size src_coded_size(static_cast<int>(coded_width),
                                 static_cast<int>(coded_height));

  // Validate visibleRect.
  gfx::Rect src_visible_rect(src_coded_size);
  if (init->hasVisibleRect()) {
    src_visible_rect = ToGfxRect(init->visibleRect(), "visibleRect",
                                 src_coded_size, exception_state);
    if (exception_state.HadException() ||
        !ValidateOffsetAlignment(media_fmt, src_visible_rect, "visibleRect",
                                 exception_state)) {
      return nullptr;
    }
  }

  // Validate layout.
  VideoFrameLayout src_layout(media_fmt, src_coded_size, exception_state);
  if (exception_state.HadException())
    return nullptr;
  if (init->hasLayout()) {
    src_layout = VideoFrameLayout(media_fmt, src_coded_size, init->layout(),
                                  exception_state);
    if (exception_state.HadException())
      return nullptr;
  }

  // Validate data.
  auto buffer = AsSpan<const uint8_t>(data);
  if (!buffer.data()) {
    exception_state.ThrowTypeError("data is detached.");
    return nullptr;
  }
  if (buffer.size() < src_layout.Size()) {
    exception_state.ThrowTypeError("data is not large enough.");
    return nullptr;
  }

  auto frame_contents = TransferArrayBufferForSpan(init->transfer(), buffer,
                                                   exception_state, isolate);
  if (exception_state.HadException()) {
    return nullptr;
  }

  // Validate display (natural) size.
  gfx::Size display_size = src_visible_rect.size();
  if (init->hasDisplayWidth() || init->hasDisplayHeight()) {
    display_size = ParseAndValidateDisplaySize(init, exception_state);
    if (exception_state.HadException())
      return nullptr;
  }

  // Set up the copy to be minimally-sized.
  gfx::Rect crop = src_visible_rect;
  gfx::Size dest_coded_size = crop.size();
  gfx::Rect dest_visible_rect = gfx::Rect(crop.size());

  // Create a frame.
  const auto timestamp = base::Microseconds(init->timestamp());
  scoped_refptr<media::VideoFrame> frame;
  if (frame_contents.IsValid()) {
    // We can directly use memory from the array buffer, no need to copy.
    frame = media::VideoFrame::WrapExternalDataWithLayout(
        src_layout.ToMediaLayout(), dest_visible_rect, display_size,
        buffer.data(), buffer.size(), timestamp);
    if (frame) {
      base::OnceCallback<void()> cleanup_cb =
          base::DoNothingWithBoundArgs(std::move(frame_contents));
      auto runner = execution_context->GetTaskRunner(TaskType::kInternalMedia);
      frame->AddDestructionObserver(
          base::BindPostTask(runner, std::move(cleanup_cb)));
    }

  } else {
    // The array buffer hasn't been transferred, we need to allocate and
    // copy pixel data.
    auto& frame_pool = CachedVideoFramePool::From(*execution_context);
    frame = frame_pool.CreateFrame(media_fmt, dest_coded_size,
                                   dest_visible_rect, display_size, timestamp);

    if (frame) {
      for (wtf_size_t i = 0; i < media::VideoFrame::NumPlanes(media_fmt); i++) {
        const gfx::Size sample_size =
            media::VideoFrame::SampleSize(media_fmt, i);
        const int sample_bytes =
            media::VideoFrame::BytesPerElement(media_fmt, i);
        const int rows = PlaneSize(crop.height(), sample_size.height());
        const int columns = PlaneSize(crop.width(), sample_size.width());
        const int row_bytes = columns * sample_bytes;
        libyuv::CopyPlane(buffer.data() + src_layout.Offset(i),
                          static_cast<int>(src_layout.Stride(i)),
                          frame->writable_data(i),
                          static_cast<int>(frame->stride(i)), row_bytes, rows);
      }
    }
  }

  if (!frame) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kOperationError,
        String::Format("Failed to create a VideoFrame with format: %s, "
                       "coded size: %s, visibleRect: %s, display size: %s.",
                       VideoPixelFormatToString(media_fmt).c_str(),
                       dest_coded_size.ToString().c_str(),
                       dest_visible_rect.ToString().c_str(),
                       display_size.ToString().c_str()));
    return nullptr;
  }

  if (init->hasColorSpace()) {
    VideoColorSpace* video_color_space =
        MakeGarbageCollected<VideoColorSpace>(init->colorSpace());
    frame->set_color_space(video_color_space->ToGfxColorSpace());
  } else {
    // So far all WebCodecs YUV formats are planar, so this test works. That
    // might not be the case in the future.
    frame->set_color_space(media::IsYuvPlanar(media_fmt)
                               ? gfx::ColorSpace::CreateREC709()
                               : gfx::ColorSpace::CreateSRGB());
  }

  if (init->hasDuration()) {
    frame->metadata().frame_duration = base::Microseconds(init->duration());
  }

  if (RuntimeEnabledFeatures::WebCodecsOrientationEnabled()) {
    frame->metadata().transformation =
        media::VideoTransformation(init->rotation(), init->flip());
  }

  return MakeGarbageCollected<VideoFrame>(std::move(frame),
                                          ExecutionContext::From(script_state));
}

std::optional<V8VideoPixelFormat> VideoFrame::format() const {
  auto local_frame = handle_->frame();
  if (!local_frame)
    return std::nullopt;

  auto copy_to_format = CopyToFormat(*local_frame);
  if (!copy_to_format)
    return std::nullopt;

  return ToV8VideoPixelFormat(*copy_to_format);
}

uint32_t VideoFrame::codedWidth() const {
  auto local_frame = handle_->frame();
  if (!local_frame)
    return 0;
  return local_frame->coded_size().width();
}

uint32_t VideoFrame::codedHeight() const {
  auto local_frame = handle_->frame();
  if (!local_frame)
    return 0;
  return local_frame->coded_size().height();
}

DOMRectReadOnly* VideoFrame::codedRect() {
  auto local_frame = handle_->frame();
  if (!local_frame)
    return nullptr;

  if (!coded_rect_) {
    coded_rect_ = MakeGarbageCollected<DOMRectReadOnly>(
        0, 0, local_frame->coded_size().width(),
        local_frame->coded_size().height());
  }
  return coded_rect_.Get();
}

DOMRectReadOnly* VideoFrame::visibleRect() {
  auto local_frame = handle_->frame();
  if (!local_frame)
    return nullptr;

  if (!visible_rect_) {
    visible_rect_ = MakeGarbageCollected<DOMRectReadOnly>(
        local_frame->visible_rect().x(), local_frame->visible_rect().y(),
        local_frame->visible_rect().width(),
        local_frame->visible_rect().height());
  }
  return visible_rect_.Get();
}

uint32_t VideoFrame::rotation() const {
  auto local_frame = handle_->frame();
  if (!local_frame) {
    return 0;
  }

  const auto transform =
      local_frame->metadata().transformation.value_or(media::kNoTransformation);
  switch (transform.rotation) {
    case media::VIDEO_ROTATION_0:
      return 0;
    case media::VIDEO_ROTATION_90:
      return 90;
    case media::VIDEO_ROTATION_180:
      return 180;
    case media::VIDEO_ROTATION_270:
      return 270;
  }
}

bool VideoFrame::flip() const {
  auto local_frame = handle_->frame();
  if (!local_frame) {
    return false;
  }

  const auto transform =
      local_frame->metadata().transformation.value_or(media::kNoTransformation);
  return transform.mirrored;
}

uint32_t VideoFrame::displayWidth() const {
  auto local_frame = handle_->frame();
  if (!local_frame)
    return 0;

  const auto transform =
      local_frame->metadata().transformation.value_or(media::kNoTransformation);
  if (transform.rotation == media::VIDEO_ROTATION_0 ||
      transform.rotation == media::VIDEO_ROTATION_180) {
    return local_frame->natural_size().width();
  }
  return local_frame->natural_size().height();
}

uint32_t VideoFrame::displayHeight() const {
  auto local_frame = handle_->frame();
  if (!local_frame)
    return 0;

  const auto transform =
      local_frame->metadata().transformation.value_or(media::kNoTransformation);
  if (transform.rotation == media::VIDEO_ROTATION_0 ||
      transform.rotation == media::VIDEO_ROTATION_180) {
    return local_frame->natural_size().height();
  }
  return local_frame->natural_size().width();
}

int64_t VideoFrame::timestamp() const {
  return handle_->timestamp().InMicroseconds();
}

std::optional<uint64_t> VideoFrame::duration() const {
  if (auto duration = handle_->duration())
    return duration->InMicroseconds();
  return std::nullopt;
}

VideoColorSpace* VideoFrame::colorSpace() {
  auto local_frame = handle_->frame();
  if (!local_frame) {
    if (!empty_color_space_)
      empty_color_space_ = MakeGarbageCollected<VideoColorSpace>();

    return empty_color_space_.Get();
  }

  if (!color_space_) {
    color_space_ =
        MakeGarbageCollected<VideoColorSpace>(local_frame->ColorSpace());
  }
  return color_space_.Get();
}

VideoFrameMetadata* VideoFrame::metadata(ExceptionState& exception_state) {
  auto local_frame = handle_->frame();
  if (!local_frame) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "VideoFrame is closed.");
    return nullptr;
  }

  auto* metadata = VideoFrameMetadata::Create();

  if (!local_frame->metadata().background_blur) {
    return metadata;
  }

  auto* background_blur = BackgroundBlur::Create();
  background_blur->setEnabled(local_frame->metadata().background_blur->enabled);
  metadata->setBackgroundBlur(background_blur);

  return metadata;
}

uint32_t VideoFrame::allocationSize(VideoFrameCopyToOptions* options,
                                    ExceptionState& exception_state) {
  auto local_frame = handle_->frame();
  if (!local_frame) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "VideoFrame is closed.");
    return 0;
  }

  VideoFrameLayout dest_layout;
  if (!ParseCopyToOptions(*local_frame, options, exception_state, &dest_layout))
    return 0;

  return dest_layout.Size();
}

void VideoFrame::ConvertAndCopyToRGB(scoped_refptr<media::VideoFrame> frame,
                                     const gfx::Rect& src_rect,
                                     const VideoFrameLayout& dest_layout,
                                     base::span<uint8_t> buffer,
                                     PredefinedColorSpace target_color_space) {
  DCHECK(media::IsRGB(dest_layout.Format()));
  SkColorType skia_pixel_format = media::SkColorTypeForPlane(
      dest_layout.Format(), media::VideoFrame::Plane::kARGB);

  if (frame->visible_rect() != src_rect) {
    frame = media::VideoFrame::WrapVideoFrame(frame, frame->format(), src_rect,
                                              src_rect.size());
  }

  auto sk_color_space = PredefinedColorSpaceToSkColorSpace(target_color_space);
  SkImageInfo dst_image_info =
      SkImageInfo::Make(src_rect.width(), src_rect.height(), skia_pixel_format,
                        kUnpremul_SkAlphaType, sk_color_space);

  const wtf_size_t plane = 0;
  DCHECK_EQ(dest_layout.NumPlanes(), 1u);
  uint8_t* dst = buffer.data() + dest_layout.Offset(plane);
  auto sk_canvas = SkCanvas::MakeRasterDirect(dst_image_info, dst,
                                              dest_layout.Stride(plane));

  cc::PaintFlags flags;
  flags.setBlendMode(SkBlendMode::kSrc);
  flags.setFilterQuality(cc::PaintFlags::FilterQuality::kNone);

  cc::SkiaPaintCanvas canvas(sk_canvas.get());
  // TODO(crbug.com/1442991): Cache this instance of PaintCanvasVideoRenderer
  media::PaintCanvasVideoRenderer renderer;
  media::PaintCanvasVideoRenderer::PaintParams paint_params;
  paint_params.dest_rect = gfx::RectF(src_rect.size());
  auto context_provider = GetRasterContextProvider();
  renderer.Paint(std::move(frame), &canvas, flags, paint_params,
                 context_provider.get());
}

bool VideoFrame::CopyToAsync(
    ScriptPromiseResolver<IDLSequence<PlaneLayout>>* resolver,
    scoped_refptr<media::VideoFrame> frame,
    gfx::Rect src_rect,
    const AllowSharedBufferSource* destination,
    const VideoFrameLayout& dest_layout) {
  auto* background_readback = BackgroundReadback::From(
      *ExecutionContext::From(resolver->GetScriptState()));
  if (!background_readback)
    return false;

  ArrayBufferContents contents = PinArrayBufferContent(destination);
  if (!contents.DataLength())
    return false;

  auto readback_done_handler =
      [](ArrayBufferContents contents,
         ScriptPromiseResolver<IDLSequence<PlaneLayout>>* resolver,
         VideoFrameLayout dest_layout, bool success) {
        if (success) {
          resolver->Resolve(ConvertLayout(dest_layout));
        } else {
          resolver->Reject();
        }
      };
  auto done_cb = WTF::BindOnce(readback_done_handler, std::move(contents),
                               WrapPersistent(resolver), dest_layout);

  auto buffer = AsSpan<uint8_t>(destination);
  background_readback->ReadbackTextureBackedFrameToBuffer(
      std::move(frame), src_rect, dest_layout, buffer, std::move(done_cb));
  return true;
}

ScriptPromise<IDLSequence<PlaneLayout>> VideoFrame::copyTo(
    ScriptState* script_state,
    const AllowSharedBufferSource* destination,
    VideoFrameCopyToOptions* options,
    ExceptionState& exception_state) {
  auto local_frame = handle_->frame();
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLSequence<PlaneLayout>>>(
          script_state);
  auto promise = resolver->Promise();
  if (!local_frame) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot copy closed VideoFrame.");
    return promise;
  }

  VideoFrameLayout dest_layout;
  gfx::Rect src_rect;
  if (!ParseCopyToOptions(*local_frame, options, exception_state, &dest_layout,
                          &src_rect)) {
    return promise;
  }

  // Validate destination buffer.
  auto buffer = AsSpan<uint8_t>(destination);
  if (!buffer.data()) {
    exception_state.ThrowTypeError("destination is detached.");
    return promise;
  }
  if (buffer.size() < dest_layout.Size()) {
    exception_state.ThrowTypeError("destination is not large enough.");
    return promise;
  }

  if (RuntimeEnabledFeatures::WebCodecsCopyToRGBEnabled() &&
      options->hasFormat()) {
    if (!media::IsRGB(dest_layout.Format())) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotSupportedError,
          "copyTo() doesn't support explicit copy to non-RGB formats. Remove "
          "format parameter to use VideoFrame's pixel format.");
    }
    PredefinedColorSpace target_color_space = PredefinedColorSpace::kSRGB;
    if (options->hasColorSpace()) {
      if (!ValidateAndConvertColorSpace(options->colorSpace(),
                                        target_color_space, exception_state)) {
        return ScriptPromise<IDLSequence<PlaneLayout>>();
      }
    }
    ConvertAndCopyToRGB(local_frame, src_rect, dest_layout, buffer,
                        target_color_space);
  } else if (local_frame->IsMappable()) {
    CopyMappablePlanes(*local_frame, src_rect, dest_layout, buffer);
  } else if (local_frame->HasMappableGpuBuffer()) {
    auto mapped_frame = media::ConvertToMemoryMappedFrame(local_frame);
    if (!mapped_frame) {
      exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                        "Failed to read VideoFrame data.");
      return promise;
    }
    CopyMappablePlanes(*mapped_frame, src_rect, dest_layout, buffer);
  } else {
    DCHECK(local_frame->HasSharedImage());

    if (base::FeatureList::IsEnabled(kVideoFrameAsyncCopyTo)) {
      if (CopyToAsync(resolver, local_frame, src_rect, destination,
                      dest_layout)) {
        return promise;
      }
    }

    if (!CopyTexturablePlanes(*local_frame, src_rect, dest_layout, buffer)) {
      exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                        "Failed to read VideoFrame data.");
      return promise;
    }
  }

  resolver->Resolve(ConvertLayout(dest_layout));
  return promise;
}

void VideoFrame::close() {
  handle_->Invalidate();
  ResetExternalMemory();
}

VideoFrame* VideoFrame::clone(ExceptionState& exception_state) {
  auto handle = handle_->Clone();
  if (!handle) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot clone closed VideoFrame.");
    return nullptr;
  }

  return MakeGarbageCollected<VideoFrame>(std::move(handle));
}

scoped_refptr<Image> VideoFrame::GetSourceImageForCanvas(
    FlushReason,
    SourceImageStatus* status,
    const gfx::SizeF&,
    const AlphaDisposition alpha_disposition) {
  // UnpremultiplyAlpha is not implemented yet.
  DCHECK_EQ(alpha_disposition, kPremultiplyAlpha);

  const auto local_handle = handle_->CloneForInternalUse();
  if (!local_handle) {
    DLOG(ERROR) << "GetSourceImageForCanvas() called for closed frame.";
    *status = kInvalidSourceImageStatus;
    return nullptr;
  }

  const auto orientation_enum = VideoTransformationToImageOrientation(
      local_handle->frame()->metadata().transformation.value_or(
          media::kNoTransformation));
  if (auto sk_img = local_handle->sk_image()) {
    *status = kNormalSourceImageStatus;
    return UnacceleratedStaticBitmapImage::Create(std::move(sk_img),
                                                  orientation_enum);
  }

  auto* execution_context =
      ExecutionContext::From(v8::Isolate::GetCurrent()->GetCurrentContext());
  auto& provider_cache = CanvasResourceProviderCache::From(*execution_context);

  // TODO(https://crbug.com/1341235): The choice of color type, alpha type, and
  // color space is inappropriate in many circumstances.
  const auto& resource_provider_size = local_handle->frame()->natural_size();
  const auto resource_provider_info =
      SkImageInfo::Make(gfx::SizeToSkISize(resource_provider_size),
                        kN32_SkColorType, kPremul_SkAlphaType, nullptr);
  auto* resource_provider =
      provider_cache.CreateProvider(resource_provider_info);

  const auto dest_rect = gfx::Rect(resource_provider_size);
  auto image = CreateImageFromVideoFrame(local_handle->frame(),
                                         /*allow_zero_copy_images=*/true,
                                         resource_provider,
                                         /*video_renderer=*/nullptr, dest_rect);
  if (!image) {
    *status = kInvalidSourceImageStatus;
    return nullptr;
  }

  *status = kNormalSourceImageStatus;
  return image;
}

bool VideoFrame::WouldTaintOrigin() const {
  // VideoFrames can't be created from untainted sources currently. If we ever
  // add that ability we will need a tainting signal on the VideoFrame itself.
  // One example would be allowing <video> elements to provide a VideoFrame.
  return false;
}

gfx::SizeF VideoFrame::ElementSize(
    const gfx::SizeF& default_object_size,
    const RespectImageOrientationEnum respect_orientation) const {
  // BitmapSourceSize() will always ignore orientation.
  if (respect_orientation == kRespectImageOrientation) {
    auto local_frame = handle_->frame();
    if (!local_frame)
      return gfx::SizeF();

    const auto orientation_enum = VideoTransformationToImageOrientation(
        local_frame->metadata().transformation.value_or(
            media::kNoTransformation));
    auto orientation_adjusted_size = gfx::SizeF(local_frame->natural_size());
    if (ImageOrientation(orientation_enum).UsesWidthAsHeight())
      orientation_adjusted_size.Transpose();
    return orientation_adjusted_size;
  }
  return gfx::SizeF(BitmapSourceSize());
}

bool VideoFrame::IsVideoFrame() const {
  return true;
}

bool VideoFrame::IsOpaque() const {
  if (auto local_frame = handle_->frame())
    return media::IsOpaque(local_frame->format());
  return false;
}

bool VideoFrame::IsAccelerated() const {
  if (auto local_handle = handle_->CloneForInternalUse()) {
    return handle_->sk_image() ? false
                               : WillCreateAcceleratedImagesFromVideoFrame(
                                     local_handle->frame().get());
  }
  return false;
}

void VideoFrame::ResetExternalMemory() {
  external_memory_accounter_.Clear(v8::Isolate::GetCurrent());
}

gfx::Size VideoFrame::BitmapSourceSize() const {
  auto local_frame = handle_->frame();
  if (!local_frame)
    return gfx::Size();

  // ImageBitmaps should always return the size w/o respecting orientation.
  return local_frame->natural_size();
}

ScriptPromise<ImageBitmap> VideoFrame::CreateImageBitmap(
    ScriptState* script_state,
    std::optional<gfx::Rect> crop_rect,
    const ImageBitmapOptions* options,
    ExceptionState& exception_state) {
  const auto local_handle = handle_->CloneForInternalUse();
  if (!local_handle) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot create ImageBitmap from closed VideoFrame.");
    return EmptyPromise();
  }

  // SkImages are always immutable, so we don't actually need to make a copy of
  // the image to satisfy the ImageBitmap spec.
  const auto orientation_enum = VideoTransformationToImageOrientation(
      local_handle->frame()->metadata().transformation.value_or(
          media::kNoTransformation));
  if (auto sk_img = local_handle->sk_image()) {
    auto* image_bitmap = MakeGarbageCollected<ImageBitmap>(
        UnacceleratedStaticBitmapImage::Create(std::move(sk_img),
                                               orientation_enum),
        crop_rect, options);
    return ImageBitmapSource::FulfillImageBitmap(script_state, image_bitmap,
                                                 options, exception_state);
  }

  auto* execution_context =
      ExecutionContext::From(v8::Isolate::GetCurrent()->GetCurrentContext());
  auto& provider_cache = CanvasResourceProviderCache::From(*execution_context);

  // TODO(https://crbug.com/1341235): The choice of color type, alpha type, and
  // color space is inappropriate in many circumstances.
  const auto& resource_provider_size = local_handle->frame()->natural_size();
  const auto resource_provider_info =
      SkImageInfo::Make(gfx::SizeToSkISize(resource_provider_size),
                        kN32_SkColorType, kPremul_SkAlphaType, nullptr);
  auto* resource_provider =
      provider_cache.CreateProvider(resource_provider_info);

  // We disable zero copy images since the ImageBitmap spec says created bitmaps
  // are copies. Many other paths can avoid doing this w/o issue, but hardware
  // decoders may have a limited number of outputs, so not making a copy becomes
  // an observable issues to clients.
  const auto dest_rect = gfx::Rect(resource_provider_size);
  auto image = CreateImageFromVideoFrame(local_handle->frame(),
                                         /*allow_zero_copy_images=*/false,
                                         resource_provider,
                                         /*video_renderer=*/nullptr, dest_rect);
  if (!image) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        String(("Unsupported VideoFrame: " +
                local_handle->frame()->AsHumanReadableString())
                   .c_str()));
    return EmptyPromise();
  }

  auto* image_bitmap =
      MakeGarbageCollected<ImageBitmap>(image, crop_rect, options);
  return ImageBitmapSource::FulfillImageBitmap(script_state, image_bitmap,
                                               options, exception_state);
}

void VideoFrame::Trace(Visitor* visitor) const {
  visitor->Trace(coded_rect_);
  visitor->Trace(visible_rect_);
  visitor->Trace(color_space_);
  visitor->Trace(empty_color_space_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink

"""


```