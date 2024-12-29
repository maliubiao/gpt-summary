Response:
The user wants to understand the functionality of the `video_frame_test.cc` file in the Chromium Blink engine. I need to analyze the code and explain its purpose, its relation to web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning (input/output), common user/programming errors, and how a user's action might lead to this code being executed during debugging.

**Plan:**

1. **General Functionality:** Identify the core purpose of the file based on its name, included headers, and the tests it contains. It seems to be a unit test file for the `VideoFrame` class.

2. **Relationship to Web Technologies:**  Examine how `VideoFrame` interacts with JavaScript APIs (like the WebCodecs API), HTML elements (like `<video>`, `<canvas>`), and CSS (potentially through visual rendering aspects).

3. **Logical Reasoning (Input/Output):**  Select a few representative test cases and demonstrate the input data and the expected output/assertions.

4. **Common Errors:** Think about scenarios where developers might misuse the `VideoFrame` API or encounter errors related to its lifecycle or resource management.

5. **User Journey (Debugging):** Describe a potential user action in a web browser that would trigger code involving `VideoFrame` and thus could lead a developer to debug this test file.
This C++ file, `video_frame_test.cc`, is a unit test file within the Chromium Blink rendering engine. Its primary function is to **test the functionality of the `blink::VideoFrame` class**, which is part of the WebCodecs API implementation in Blink.

Here's a breakdown of its functions and connections:

**Core Functionality:**

* **Instantiation and Basic Attributes:** Tests the creation of `blink::VideoFrame` objects from `media::VideoFrame` (the underlying media representation) and verifies that basic attributes like timestamp, coded width, and coded height are correctly set and accessible.
* **`copyTo()` Method:** Tests the ability to copy the video frame's pixel data to a buffer. It checks if the pixel data is copied correctly, potentially with format conversion (e.g., to RGBA).
* **Shared Handles and Closing:** Examines how `blink::VideoFrame` objects can share underlying `media::VideoFrame` resources through `VideoFrameHandle`. It verifies that closing one `blink::VideoFrame` can affect others sharing the same handle and explores scenarios where handles are independent.
* **Cloning:** Tests the `clone()` method, ensuring that cloning a `blink::VideoFrame` creates a new object that initially shares the underlying media data but can be managed independently regarding its lifecycle. It also checks error handling when cloning a closed frame.
* **Resource Management and Leaks:** Includes tests to ensure proper resource management. It verifies that if `VideoFrameHandle` objects are not correctly closed (or invalidated), the system detects these potential leaks. Conversely, it checks that invalidated handles don't trigger leak reports.
* **Interaction with `ImageBitmap`:** Tests the ability to create `blink::VideoFrame` objects from `ImageBitmap` and vice-versa, including zero-copy scenarios where the underlying image data is shared efficiently.
* **GPU ImageBitmap Support:** Verifies the creation of `blink::VideoFrame` from GPU-backed `ImageBitmap` objects.
* **Monitoring and Debugging:** Uses `VideoFrameMonitor` to track the creation and destruction of `blink::VideoFrame` objects, especially for debugging purposes and identifying potential leaks.
* **External Memory Reporting:** Checks that the memory allocated for `blink::VideoFrame` (especially when backed by external resources) is correctly tracked and reported to the V8 JavaScript engine's memory management.
* **Metadata Handling:** Tests how metadata associated with the underlying `media::VideoFrame`, such as background blur information, is exposed and accessible through the `blink::VideoFrame` object.

**Relationship to JavaScript, HTML, and CSS:**

The `blink::VideoFrame` class is a crucial bridge between the underlying media processing in the browser and the WebCodecs API exposed to JavaScript.

* **JavaScript:**
    * **WebCodecs API:** This test file directly relates to the JavaScript WebCodecs API, specifically the `VideoFrame` interface. JavaScript code uses this API to:
        * **Receive decoded video frames:**  When a video stream is decoded using `VideoDecoder`, the output frames are often represented as `VideoFrame` objects.
        * **Create video frames:** JavaScript can create `VideoFrame` objects from various sources like `<canvas>`, `<img>`, `<video>` elements, or even raw pixel data.
        * **Process video frames:** JavaScript can use methods like `copyTo()` to access the raw pixel data of a `VideoFrame` for further manipulation (e.g., applying filters, sending over WebSockets).
        * **Example:**
          ```javascript
          // Assuming 'decoder' is a configured VideoDecoder
          decoder.decode(encodedChunk);
          decoder.ondequeue = (frame) => {
            console.log("Decoded a frame:", frame);
            // Access frame properties like timestamp, width, height
            console.log("Timestamp:", frame.timestamp);
            // Copy frame data to an ArrayBuffer
            frame.copyTo(new ArrayBuffer(frame.allocationSize()), { format: 'RGBA' })
              .then(() => frame.close());
          };
          ```

* **HTML:**
    * **`<canvas>` element:** JavaScript can draw on a `<canvas>` element and then create a `VideoFrame` from the canvas's content. This allows for manipulating canvas graphics and using them as video frames.
    * **`<img>` element:** A `VideoFrame` can be created from the image data of an `<img>` element.
    * **`<video>` element:** While not directly creating `VideoFrame` objects for playback, the browser internally uses similar mechanisms for rendering video from the `<video>` element. The WebCodecs API allows access to the raw video frames that would otherwise be used for `<video>` playback.
    * **Example:**
      ```html
      <canvas id="myCanvas" width="100" height="100"></canvas>
      <script>
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = 'red';
        ctx.fillRect(0, 0, 100, 100);

        const videoFrame = new VideoFrame(canvas);
        console.log(videoFrame);
        videoFrame.close();
      </script>
      ```

* **CSS:**
    * **Indirect Relationship:** CSS styles the visual presentation of HTML elements. While CSS doesn't directly interact with `VideoFrame` objects, the results of processing `VideoFrame` data (e.g., drawing on a canvas with frame data) will be affected by CSS styling applied to the relevant elements. For instance, the size and positioning of a `<canvas>` element displaying video frame data are controlled by CSS.
    * **CSS Image Values:**  The inclusion of `v8_union_cssimagevalue_htmlcanvaselement_htmlimageelement_htmlvideoelement_imagebitmap_offscreencanvas_svgimageelement_videoframe.h` in the headers suggests that `VideoFrame` objects might be representable as CSS image values in some contexts, potentially for advanced visual effects.

**Logical Reasoning (Hypothetical Inputs and Outputs):**

Let's take the `CopyToRGB` test case as an example:

* **Hypothetical Input:**
    * A `blink::VideoFrame` object (`blink_frame`) is created from a black `media::VideoFrame` with:
        * `timestamp`: 1000 microseconds
        * `codedWidth`: 64 pixels
        * `codedHeight`: 48 pixels
        * `format`: `media::PIXEL_FORMAT_I420` (YUV format)
    * A destination `DOMArrayBuffer` (`buffer`) is created with enough space to hold the RGBA representation of the video frame (64 * 48 * 4 bytes).
    * The `buffer` is initially filled with white pixel data (all bytes set to 0xff).
    * `CopyToOptions` is set to copy to the `RGBA` format.

* **Expected Output/Assertions:**
    * After calling `blink_frame->copyTo()` and the promise resolves successfully:
        * The `buffer` will contain the RGBA representation of the original black video frame. This means every group of 4 bytes in the buffer (representing R, G, B, A) will be 0, 0, 0, and some alpha value (likely 255).
        * The assertions in the test verify that each pixel in the `buffer` is indeed black (R=0, G=0, B=0).

**Common User or Programming Errors:**

* **Incorrect Buffer Size:** Providing a buffer to `copyTo()` that is too small to hold the video frame data in the specified format. This would likely lead to an error or data corruption.
    * **Example:**  The user might calculate the buffer size based on the coded width and height but forget to account for the number of bytes per pixel for the target format (e.g., using 3 bytes per pixel for RGB instead of 4 for RGBA).
* **Using a Closed VideoFrame:** Trying to call methods like `copyTo()` or `clone()` on a `VideoFrame` object that has already been closed using `close()`. This would result in an error or undefined behavior.
    * **Example:**  The user might have a callback that tries to process a `VideoFrame` after it has been explicitly closed elsewhere in the code.
* **Forgetting to Close VideoFrames:** Failing to call `close()` on `VideoFrame` objects when they are no longer needed, leading to potential resource leaks (especially if the `VideoFrame` holds onto significant memory).
    * **Example:**  The user might create many `VideoFrame` objects in a loop without properly managing their lifecycle, exhausting memory.
* **Incorrect Format in `copyTo()`:** Specifying an unsupported or incorrect pixel format in the `CopyToOptions`.
    * **Example:** Trying to copy to a format that the underlying video frame cannot be converted to.
* **Asynchronous Operations and Promises:** Misunderstanding how the asynchronous `copyTo()` method and its associated promise work. For example, trying to access the buffer data before the promise has resolved.
    * **Example:**  The user might try to read the data from the buffer immediately after calling `copyTo()` without waiting for the promise to fulfill.

**User Operation and Debugging Lineage:**

Imagine a web application that uses the WebCodecs API to process video frames from a user's webcam:

1. **User grants webcam access:** The user allows the web application to access their webcam.
2. **Video stream starts:** The browser starts receiving video frames from the webcam.
3. **WebCodecs `VideoDecoder`:** The application uses a `VideoDecoder` to decode the incoming video stream (which is typically encoded).
4. **`VideoFrame` output:** The `VideoDecoder`'s `ondequeue` event provides decoded video frames as `VideoFrame` objects in JavaScript.
5. **Processing in JavaScript:** The JavaScript code might then:
    * Use `frame.copyTo()` to get the pixel data.
    * Draw the frame onto a `<canvas>` element.
    * Apply image processing filters to the pixel data.
    * Send the raw frame data over a network.
6. **Bug Encountered:**  Let's say the video on the canvas appears black, even though the webcam is working correctly.

**Debugging Lineage to `video_frame_test.cc`:**

When a developer investigates this black video issue, they might:

* **Inspect the `VideoFrame` object in the browser's developer tools:** They would check the frame's properties (width, height, timestamp).
* **Step through the JavaScript code:** They would examine the values of variables and the flow of execution.
* **Suspect an issue with the `copyTo()` operation:** If the canvas is always black, they might suspect that the pixel data is not being copied correctly or is all zeros.
* **Look for related Chromium source code:**  They might search for "VideoFrame copyTo chromium" to understand how this method is implemented.
* **Find `blink/renderer/modules/webcodecs/video_frame.cc`:** This file contains the C++ implementation of the `VideoFrame` class and its methods.
* **Examine `video_frame_test.cc`:**  To understand how the `copyTo()` method is *supposed* to work, they would look at the unit tests in `video_frame_test.cc`, specifically the `CopyToRGB` test. This test provides a clear example of how to use `copyTo()`, the expected input (a black frame), and the expected output (the buffer should contain black pixel data).

By studying the unit tests, the developer can:

* **Verify their understanding of the API:** Ensure they are using `copyTo()` correctly.
* **Identify potential issues in the Chromium implementation:** If the unit tests are failing, it could indicate a bug in the browser's code itself.
* **Reproduce the issue in a controlled environment:** The unit tests provide a simple, isolated way to test the `copyTo()` functionality.

Therefore, `video_frame_test.cc` acts as a crucial reference and validation tool for developers working with the WebCodecs API and debugging related issues in the Chromium browser.

Prompt: 
```
这是目录为blink/renderer/modules/webcodecs/video_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"

#include "components/viz/test/test_context_provider.h"
#include "media/base/video_frame.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_rect_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_background_blur.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_plane_layout.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_blob_htmlcanvaselement_htmlimageelement_htmlvideoelement_imagebitmap_imagedata_offscreencanvas_svgimageelement_videoframe.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_cssimagevalue_htmlcanvaselement_htmlimageelement_htmlvideoelement_imagebitmap_offscreencanvas_svgimageelement_videoframe.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame_copy_to_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame_metadata.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/modules/canvas/imagebitmap/image_bitmap_factories.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame_handle.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame_monitor.h"
#include "third_party/blink/renderer/modules/webcodecs/webcodecs_logger.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/test/gpu_test_utils.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/skia/include/core/SkSurface.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

namespace {

ImageBitmap* ToImageBitmap(V8TestingScope* v8_scope, ScriptValue value) {
  return NativeValueTraits<ImageBitmap>::NativeValue(
      v8_scope->GetIsolate(), value.V8Value(), v8_scope->GetExceptionState());
}

class VideoFrameTest : public testing::Test {
 public:
  void SetUp() override {
    test_context_provider_ = viz::TestContextProvider::Create();
    InitializeSharedGpuContextGLES2(test_context_provider_.get());
  }

  void TearDown() override { SharedGpuContext::Reset(); }

  VideoFrame* CreateBlinkVideoFrame(
      scoped_refptr<media::VideoFrame> media_frame,
      ExecutionContext* context) {
    return MakeGarbageCollected<VideoFrame>(std::move(media_frame), context);
  }
  VideoFrame* CreateBlinkVideoFrameFromHandle(
      scoped_refptr<VideoFrameHandle> handle) {
    return MakeGarbageCollected<VideoFrame>(std::move(handle));
  }
  scoped_refptr<media::VideoFrame> CreateDefaultBlackMediaVideoFrame() {
    return CreateBlackMediaVideoFrame(base::Microseconds(1000),
                                      media::PIXEL_FORMAT_I420,
                                      gfx::Size(112, 208) /* coded_size */,
                                      gfx::Size(100, 200) /* visible_size */);
  }

  scoped_refptr<media::VideoFrame> CreateBlackMediaVideoFrame(
      base::TimeDelta timestamp,
      media::VideoPixelFormat format,
      const gfx::Size& coded_size,
      const gfx::Size& visible_size) {
    scoped_refptr<media::VideoFrame> media_frame =
        media::VideoFrame::WrapVideoFrame(
            media::VideoFrame::CreateBlackFrame(coded_size), format,
            gfx::Rect(visible_size) /* visible_rect */,
            visible_size /* natural_size */);
    media_frame->set_timestamp(timestamp);
    return media_frame;
  }

 private:
  test::TaskEnvironment task_environment_;
  scoped_refptr<viz::TestContextProvider> test_context_provider_;
};

TEST_F(VideoFrameTest, ConstructorAndAttributes) {
  V8TestingScope scope;

  scoped_refptr<media::VideoFrame> media_frame = CreateBlackMediaVideoFrame(
      base::Microseconds(1000), media::PIXEL_FORMAT_I420,
      gfx::Size(112, 208) /* coded_size */,
      gfx::Size(100, 200) /* visible_size */);
  VideoFrame* blink_frame =
      CreateBlinkVideoFrame(media_frame, scope.GetExecutionContext());

  EXPECT_EQ(1000u, blink_frame->timestamp());
  EXPECT_EQ(112u, blink_frame->codedWidth());
  EXPECT_EQ(208u, blink_frame->codedHeight());
  EXPECT_EQ(media_frame, blink_frame->frame());

  blink_frame->close();

  EXPECT_EQ(1000u, blink_frame->timestamp());
  EXPECT_EQ(0u, blink_frame->codedWidth());
  EXPECT_EQ(0u, blink_frame->codedHeight());
  EXPECT_EQ(nullptr, blink_frame->frame());
}

TEST_F(VideoFrameTest, CopyToRGB) {
  V8TestingScope scope;

  ScopedWebCodecsCopyToRGBForTest feature(true);
  scoped_refptr<media::VideoFrame> media_frame = CreateBlackMediaVideoFrame(
      base::Microseconds(1000), media::PIXEL_FORMAT_I420,
      /* coded_size= */ gfx::Size(64, 48),
      /* visible_size= */ gfx::Size(64, 48));
  VideoFrame* blink_frame =
      CreateBlinkVideoFrame(media_frame, scope.GetExecutionContext());
  VideoFrameCopyToOptions* options = VideoFrameCopyToOptions::Create();
  options->setFormat(V8VideoPixelFormat::Enum::kRGBA);

  uint32_t buffer_size =
      blink_frame->allocationSize(options, scope.GetExceptionState());
  auto* buffer = DOMArrayBuffer::Create(buffer_size, 1);
  uint8_t* data = static_cast<uint8_t*>(buffer->Data());

  // Set buffer to white pixels.
  memset(data, 0xff, buffer_size);
  AllowSharedBufferSource* destination =
      MakeGarbageCollected<AllowSharedBufferSource>(buffer);

  auto promise = blink_frame->copyTo(scope.GetScriptState(), destination,
                                     options, scope.GetExceptionState());

  ScriptPromiseTester tester(scope.GetScriptState(), promise);
  tester.WaitUntilSettled();
  ASSERT_TRUE(tester.IsFulfilled());

  // Check that after copyTo() all the pixels are black.
  for (int y = 0; y < media_frame->coded_size().height(); y++) {
    for (int x = 0; x < media_frame->coded_size().width(); x++) {
      uint8_t* addr = &data[y * media_frame->stride(0) + x * 4];
      ASSERT_EQ(addr[0], 0) << " R x: " << x << " y: " << y;
      ASSERT_EQ(addr[1], 0) << " G x: " << x << " y: " << y;
      ASSERT_EQ(addr[2], 0) << " B x: " << x << " y: " << y;
    }
  }

  blink_frame->close();
}

TEST_F(VideoFrameTest, FramesSharingHandleClose) {
  V8TestingScope scope;

  scoped_refptr<media::VideoFrame> media_frame =
      CreateDefaultBlackMediaVideoFrame();
  VideoFrame* blink_frame =
      CreateBlinkVideoFrame(media_frame, scope.GetExecutionContext());

  VideoFrame* frame_with_shared_handle =
      CreateBlinkVideoFrameFromHandle(blink_frame->handle());

  // A blink::VideoFrame created from a handle should share the same
  // media::VideoFrame reference.
  EXPECT_EQ(media_frame, frame_with_shared_handle->frame());

  // Closing a frame should invalidate all frames sharing the same handle.
  blink_frame->close();
  EXPECT_EQ(nullptr, frame_with_shared_handle->frame());
}

TEST_F(VideoFrameTest, FramesNotSharingHandleClose) {
  V8TestingScope scope;

  scoped_refptr<media::VideoFrame> media_frame =
      CreateDefaultBlackMediaVideoFrame();
  VideoFrame* blink_frame =
      CreateBlinkVideoFrame(media_frame, scope.GetExecutionContext());

  auto new_handle = base::MakeRefCounted<VideoFrameHandle>(
      blink_frame->frame(), scope.GetExecutionContext());

  VideoFrame* frame_with_new_handle =
      CreateBlinkVideoFrameFromHandle(std::move(new_handle));

  EXPECT_EQ(media_frame, frame_with_new_handle->frame());

  // If a frame was created a new handle reference the same media::VideoFrame,
  // one frame's closure should not affect the other.
  blink_frame->close();
  EXPECT_EQ(media_frame, frame_with_new_handle->frame());
}

TEST_F(VideoFrameTest, ClonedFrame) {
  V8TestingScope scope;

  scoped_refptr<media::VideoFrame> media_frame =
      CreateDefaultBlackMediaVideoFrame();
  VideoFrame* blink_frame =
      CreateBlinkVideoFrame(media_frame, scope.GetExecutionContext());

  VideoFrame* cloned_frame = blink_frame->clone(scope.GetExceptionState());

  // The cloned frame should be referencing the same media::VideoFrame.
  EXPECT_EQ(blink_frame->frame(), cloned_frame->frame());
  EXPECT_EQ(media_frame, cloned_frame->frame());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  blink_frame->close();

  // Closing the original frame should not affect the cloned frame.
  EXPECT_EQ(media_frame, cloned_frame->frame());
}

TEST_F(VideoFrameTest, CloningClosedFrame) {
  V8TestingScope scope;

  scoped_refptr<media::VideoFrame> media_frame =
      CreateDefaultBlackMediaVideoFrame();
  VideoFrame* blink_frame =
      CreateBlinkVideoFrame(media_frame, scope.GetExecutionContext());

  blink_frame->close();

  VideoFrame* cloned_frame = blink_frame->clone(scope.GetExceptionState());

  // No frame should have been created, and there should be an exception.
  EXPECT_EQ(nullptr, cloned_frame);
  EXPECT_TRUE(scope.GetExceptionState().HadException());
}

TEST_F(VideoFrameTest, LeakedHandlesReportLeaks) {
  V8TestingScope scope;

  // Create a handle directly instead of a video frame, to avoid dealing with
  // the GarbageCollector.
  scoped_refptr<media::VideoFrame> media_frame =
      CreateDefaultBlackMediaVideoFrame();
  auto handle = base::MakeRefCounted<VideoFrameHandle>(
      media_frame, scope.GetExecutionContext());

  // Remove the last reference to the handle without calling Invalidate().
  handle.reset();

  auto& logger = WebCodecsLogger::From(*scope.GetExecutionContext());

  EXPECT_TRUE(logger.GetCloseAuditor()->were_frames_not_closed());
}

TEST_F(VideoFrameTest, InvalidatedHandlesDontReportLeaks) {
  V8TestingScope scope;

  // Create a handle directly instead of a video frame, to avoid dealing with
  // the GarbageCollector.
  scoped_refptr<media::VideoFrame> media_frame =
      CreateDefaultBlackMediaVideoFrame();
  auto handle = base::MakeRefCounted<VideoFrameHandle>(
      media_frame, scope.GetExecutionContext());

  handle->Invalidate();
  handle.reset();

  auto& logger = WebCodecsLogger::From(*scope.GetExecutionContext());

  EXPECT_FALSE(logger.GetCloseAuditor()->were_frames_not_closed());
}

TEST_F(VideoFrameTest, ImageBitmapCreationAndZeroCopyRoundTrip) {
  V8TestingScope scope;

  auto* init = VideoFrameInit::Create();
  init->setTimestamp(0);

  sk_sp<SkSurface> surface(SkSurfaces::Raster(
      SkImageInfo::MakeN32Premul(5, 5, SkColorSpace::MakeSRGB())));
  sk_sp<SkImage> original_image = surface->makeImageSnapshot();

  const auto* default_options = ImageBitmapOptions::Create();
  auto* image_bitmap = MakeGarbageCollected<ImageBitmap>(
      UnacceleratedStaticBitmapImage::Create(original_image), std::nullopt,
      default_options);
  auto* source = MakeGarbageCollected<V8CanvasImageSource>(image_bitmap);
  auto* video_frame = VideoFrame::Create(scope.GetScriptState(), source, init,
                                         scope.GetExceptionState());

  EXPECT_EQ(video_frame->handle()->sk_image(), original_image);

  {
    auto* ibs_source = MakeGarbageCollected<V8ImageBitmapSource>(video_frame);
    auto promise = ImageBitmapFactories::CreateImageBitmap(
        scope.GetScriptState(), ibs_source, default_options,
        scope.GetExceptionState());
    ScriptPromiseTester tester(scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
    auto* new_bitmap = ToImageBitmap(&scope, tester.Value());
    ASSERT_TRUE(new_bitmap);

    auto bitmap_image =
        new_bitmap->BitmapImage()->PaintImageForCurrentFrame().GetSwSkImage();
    EXPECT_EQ(bitmap_image, original_image);
  }

  auto* clone = video_frame->clone(scope.GetExceptionState());
  EXPECT_EQ(clone->handle()->sk_image(), original_image);
}

// Wraps |source| in a VideoFrame and checks for SkImage re-use where feasible.
void TestWrappedVideoFrameImageReuse(V8TestingScope& scope,
                                     const sk_sp<SkImage> orig_image,
                                     const V8CanvasImageSource* source) {
  // Wrapping image in a VideoFrame without changing any metadata should reuse
  // the original image.
  auto* init = VideoFrameInit::Create();
  init->setTimestamp(0);  // Timestamp is required since ImageBitmap lacks.
  auto* video_frame = VideoFrame::Create(scope.GetScriptState(), source, init,
                                         scope.GetExceptionState());
  EXPECT_EQ(video_frame->handle()->sk_image(), orig_image);

  // Duration metadata doesn't impact drawing so VideoFrame should still reuse
  // the original image.
  init->setDuration(1000);
  video_frame = VideoFrame::Create(scope.GetScriptState(), source, init,
                                   scope.GetExceptionState());
  EXPECT_EQ(video_frame->handle()->sk_image(), orig_image);

  // VisibleRect change does impact drawing, so VideoFrame should NOT re-use the
  // original image.
  DOMRectInit* visible_rect = DOMRectInit::Create();
  visible_rect->setX(1);
  visible_rect->setY(1);
  visible_rect->setWidth(2);
  visible_rect->setHeight(2);
  init->setVisibleRect(visible_rect);
  video_frame = VideoFrame::Create(scope.GetScriptState(), source, init,
                                   scope.GetExceptionState());
  EXPECT_NE(video_frame->handle()->sk_image(), orig_image);
}

// Wraps an ImageBitmap in a VideoFrame and checks for SkImage re-use where
// feasible.
TEST_F(VideoFrameTest, ImageReuse_VideoFrameFromImage) {
  V8TestingScope scope;

  sk_sp<SkSurface> surface(SkSurfaces::Raster(
      SkImageInfo::MakeN32Premul(5, 5, SkColorSpace::MakeSRGB())));
  sk_sp<SkImage> original_image = surface->makeImageSnapshot();

  const auto* default_options = ImageBitmapOptions::Create();
  auto* image_bitmap_layer = MakeGarbageCollected<ImageBitmap>(
      UnacceleratedStaticBitmapImage::Create(original_image), std::nullopt,
      default_options);

  TestWrappedVideoFrameImageReuse(
      scope, original_image,
      MakeGarbageCollected<V8CanvasImageSource>(image_bitmap_layer));
}

// Like ImageReuse_VideoFrameFromImage, but adds an intermediate VideoFrame
// to the sandwich (which triggers distinct code paths).
TEST_F(VideoFrameTest, ImageReuse_VideoFrameFromVideoFrameFromImage) {
  V8TestingScope scope;

  sk_sp<SkSurface> surface(SkSurfaces::Raster(
      SkImageInfo::MakeN32Premul(5, 5, SkColorSpace::MakeSRGB())));
  sk_sp<SkImage> original_image = surface->makeImageSnapshot();

  const auto* default_options = ImageBitmapOptions::Create();
  auto* image_bitmap = MakeGarbageCollected<ImageBitmap>(
      UnacceleratedStaticBitmapImage::Create(original_image), std::nullopt,
      default_options);

  auto* init = VideoFrameInit::Create();
  init->setTimestamp(0);  // Timestamp is required since ImageBitmap lacks.
  auto* video_frame = VideoFrame::Create(
      scope.GetScriptState(),
      MakeGarbageCollected<V8CanvasImageSource>(image_bitmap), init,
      scope.GetExceptionState());

  TestWrappedVideoFrameImageReuse(
      scope, original_image,
      MakeGarbageCollected<V8CanvasImageSource>(video_frame));
}

TEST_F(VideoFrameTest, VideoFrameFromGPUImageBitmap) {
  V8TestingScope scope;

  auto context_provider_wrapper = SharedGpuContext::ContextProviderWrapper();
  auto resource_provider = CanvasResourceProvider::CreateSharedImageProvider(
      SkImageInfo::MakeN32Premul(100, 100), cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kNo, context_provider_wrapper,
      RasterMode::kGPU, gpu::SharedImageUsageSet());

  scoped_refptr<StaticBitmapImage> bitmap =
      resource_provider->Snapshot(FlushReason::kTesting);
  ASSERT_TRUE(bitmap->IsTextureBacked());

  auto* image_bitmap = MakeGarbageCollected<ImageBitmap>(bitmap);
  EXPECT_TRUE(image_bitmap);
  EXPECT_TRUE(image_bitmap->BitmapImage()->IsTextureBacked());

  auto* init = VideoFrameInit::Create();
  init->setTimestamp(0);

  auto* source = MakeGarbageCollected<V8CanvasImageSource>(image_bitmap);
  auto* video_frame = VideoFrame::Create(scope.GetScriptState(), source, init,
                                         scope.GetExceptionState());
  ASSERT_TRUE(video_frame);
}

TEST_F(VideoFrameTest, HandleMonitoring) {
  V8TestingScope scope;
  VideoFrameMonitor& monitor = VideoFrameMonitor::Instance();
  const std::string source1 = "source1";
  const std::string source2 = "source2";
  EXPECT_TRUE(monitor.IsEmpty());

  // Test all constructors.
  scoped_refptr<media::VideoFrame> media_frame1 =
      CreateDefaultBlackMediaVideoFrame();
  scoped_refptr<media::VideoFrame> media_frame2 =
      CreateDefaultBlackMediaVideoFrame();

  auto verify_expectations =
      [&](wtf_size_t num_frames_source1, int num_refs_frame1_source1,
          int num_refs_frame2_source1, wtf_size_t num_frames_source2,
          int num_refs_frame1_source2, int num_refs_frame2_source2) {
        EXPECT_EQ(monitor.NumFrames(source1), num_frames_source1);
        EXPECT_EQ(monitor.NumRefs(source1, media_frame1->unique_id()),
                  num_refs_frame1_source1);
        EXPECT_EQ(monitor.NumRefs(source1, media_frame2->unique_id()),
                  num_refs_frame2_source1);
        EXPECT_EQ(monitor.NumFrames(source2), num_frames_source2);
        EXPECT_EQ(monitor.NumRefs(source2, media_frame1->unique_id()),
                  num_refs_frame1_source2);
        EXPECT_EQ(monitor.NumRefs(source2, media_frame2->unique_id()),
                  num_refs_frame2_source2);
      };

  auto handle_1_1 = base::MakeRefCounted<VideoFrameHandle>(
      media_frame1, scope.GetExecutionContext(), source1);
  verify_expectations(/* source1 */ 1, 1, 0, /* source2 */ 0, 0, 0);

  sk_sp<SkSurface> surface(SkSurfaces::Raster(
      SkImageInfo::MakeN32Premul(5, 5, SkColorSpace::MakeSRGB())));
  sk_sp<SkImage> sk_image = surface->makeImageSnapshot();
  auto handle_2_1 = base::MakeRefCounted<VideoFrameHandle>(
      media_frame2, sk_image, scope.GetExecutionContext(), source1);
  verify_expectations(/* source1 */ 2, 1, 1, /* source2 */ 0, 0, 0);

  auto& logger = WebCodecsLogger::From(*scope.GetExecutionContext());
  auto handle_1_1b = base::MakeRefCounted<VideoFrameHandle>(
      media_frame1, sk_image, logger.GetCloseAuditor(), source1);
  verify_expectations(/* source1 */ 2, 2, 1, /* source2 */ 0, 0, 0);

  auto handle_1_2 =
      base::MakeRefCounted<VideoFrameHandle>(media_frame1, sk_image, source2);
  verify_expectations(/* source1 */ 2, 2, 1, /* source2 */ 1, 1, 0);

  auto non_monitored1 = base::MakeRefCounted<VideoFrameHandle>(
      media_frame2, sk_image, scope.GetExecutionContext());
  verify_expectations(/* source1 */ 2, 2, 1, /* source2 */ 1, 1, 0);

  auto non_monitored2 =
      base::MakeRefCounted<VideoFrameHandle>(media_frame1, sk_image);
  verify_expectations(/* source1 */ 2, 2, 1, /* source2 */ 1, 1, 0);

  // Move constructor
  auto handle_1_1c = std::move(handle_1_1b);
  verify_expectations(/* source1 */ 2, 2, 1, /* source2 */ 1, 1, 0);

  // Test all clone methods.
  auto clone_1_1a = handle_1_1->Clone();
  verify_expectations(/* source1 */ 2, 3, 1, /* source2 */ 1, 1, 0);

  auto clone_1_1b = handle_1_1->CloneForInternalUse();
  verify_expectations(/* source1 */ 2, 4, 1, /* source2 */ 1, 1, 0);

  // Clone non-monitored frame
  auto non_monitored_clone = non_monitored2->CloneForInternalUse();
  verify_expectations(/* source1 */ 2, 4, 1, /* source2 */ 1, 1, 0);

  // Test invalidate
  handle_1_1->Invalidate();
  verify_expectations(/* source1 */ 2, 3, 1, /* source2 */ 1, 1, 0);

  // handle_1_1b was moved to handle_1_1c
  handle_1_1c->Invalidate();
  verify_expectations(/* source1 */ 2, 2, 1, /* source2 */ 1, 1, 0);

  handle_2_1->Invalidate();
  verify_expectations(/* source1 */ 1, 2, 0, /* source2 */ 1, 1, 0);

  non_monitored1->Invalidate();
  verify_expectations(/* source1 */ 1, 2, 0, /* source2 */ 1, 1, 0);

  non_monitored2->Invalidate();
  verify_expectations(/* source1 */ 1, 2, 0, /* source2 */ 1, 1, 0);

  clone_1_1a->Invalidate();
  verify_expectations(/* source1 */ 1, 1, 0, /* source2 */ 1, 1, 0);

  // Resetting handles instead of invalidating.
  handle_1_2.reset();
  verify_expectations(/* source1 */ 1, 1, 0, /* source2 */ 0, 0, 0);

  clone_1_1b.reset();
  EXPECT_TRUE(monitor.IsEmpty());

  // handle10 is not monitored
  non_monitored_clone.reset();
  EXPECT_TRUE(monitor.IsEmpty());
}

TEST_F(VideoFrameTest, VideoFrameMonitoring) {
  V8TestingScope scope;
  VideoFrameMonitor& monitor = VideoFrameMonitor::Instance();
  const std::string source = "source";
  scoped_refptr<media::VideoFrame> media_frame =
      CreateDefaultBlackMediaVideoFrame();
  auto verify_expectations = [&](wtf_size_t num_frames, int num_refs) {
    EXPECT_EQ(monitor.NumFrames(source), num_frames);
    EXPECT_EQ(monitor.NumRefs(source, media_frame->unique_id()), num_refs);
  };
  EXPECT_TRUE(monitor.IsEmpty());

  // Test all constructors
  auto* frame1 = MakeGarbageCollected<VideoFrame>(
      media_frame, scope.GetExecutionContext(), source);
  verify_expectations(1u, 1);

  auto* non_monitored1 = MakeGarbageCollected<VideoFrame>(
      media_frame, scope.GetExecutionContext());
  verify_expectations(1u, 1);

  auto monitored_handle = base::MakeRefCounted<VideoFrameHandle>(
      media_frame, scope.GetExecutionContext(), source);
  auto* frame2 = MakeGarbageCollected<VideoFrame>(std::move(monitored_handle));
  verify_expectations(1u, 2);

  auto non_monitored_handle = base::MakeRefCounted<VideoFrameHandle>(
      media_frame, scope.GetExecutionContext());
  auto* non_monitored2 =
      MakeGarbageCollected<VideoFrame>(std::move(non_monitored_handle));
  verify_expectations(1u, 2);

  frame1->clone(scope.GetExceptionState());
  verify_expectations(1u, 3);

  auto* non_monitored_clone = non_monitored1->clone(scope.GetExceptionState());
  verify_expectations(1u, 3);

  frame1->close();
  verify_expectations(1u, 2);

  frame2->close();
  verify_expectations(1u, 1);

  non_monitored1->close();
  non_monitored2->close();
  non_monitored_clone->close();
  verify_expectations(1u, 1);

  // Garbage-collecting a non-closed monitored frame should reclaim it and
  // update the monitor.
  blink::WebHeap::CollectAllGarbageForTesting();
  EXPECT_TRUE(monitor.IsEmpty());
}

TEST_F(VideoFrameTest, TestExternalAllocatedMemoryIsReportedCorrectlyOnClose) {
  V8TestingScope scope;

  scoped_refptr<media::VideoFrame> media_frame = CreateBlackMediaVideoFrame(
      base::Microseconds(1000), media::PIXEL_FORMAT_I420,
      gfx::Size(112, 208) /* coded_size */,
      gfx::Size(100, 200) /* visible_size */);

  int64_t initial_external_memory =
      scope.GetIsolate()->AdjustAmountOfExternalAllocatedMemory(0);

  VideoFrame* blink_frame =
      CreateBlinkVideoFrame(media_frame, scope.GetExecutionContext());

  EXPECT_GT(scope.GetIsolate()->AdjustAmountOfExternalAllocatedMemory(0),
            initial_external_memory);

  // Calling close should decrement externally allocated memory.
  blink_frame->close();

  EXPECT_EQ(scope.GetIsolate()->AdjustAmountOfExternalAllocatedMemory(0),
            initial_external_memory);

  // Calling close another time should not decrement external memory twice.
  blink_frame->close();

  EXPECT_EQ(scope.GetIsolate()->AdjustAmountOfExternalAllocatedMemory(0),
            initial_external_memory);

  blink_frame = nullptr;
  blink::WebHeap::CollectAllGarbageForTesting();

  // Check the destructor does not double decrement the external memory.
  EXPECT_EQ(scope.GetIsolate()->AdjustAmountOfExternalAllocatedMemory(0),
            initial_external_memory);
}

TEST_F(VideoFrameTest,
       TestExternalAllocatedMemoryIsReportedCorrectlyOnDestruction) {
  V8TestingScope scope;

  scoped_refptr<media::VideoFrame> media_frame = CreateBlackMediaVideoFrame(
      base::Microseconds(1000), media::PIXEL_FORMAT_I420,
      gfx::Size(112, 208) /* coded_size */,
      gfx::Size(100, 200) /* visible_size */);

  int64_t initial_external_memory =
      scope.GetIsolate()->AdjustAmountOfExternalAllocatedMemory(0);

  CreateBlinkVideoFrame(media_frame, scope.GetExecutionContext());

  EXPECT_GT(scope.GetIsolate()->AdjustAmountOfExternalAllocatedMemory(0),
            initial_external_memory);

  blink::WebHeap::CollectAllGarbageForTesting();

  // Check the destructor correctly decrements the reported
  // externally allocated memory  when close has not been called before.
  EXPECT_EQ(scope.GetIsolate()->AdjustAmountOfExternalAllocatedMemory(0),
            initial_external_memory);
}

TEST_F(VideoFrameTest, MetadataBackgroundBlurIsExposedCorrectly) {
  V8TestingScope scope;

  scoped_refptr<media::VideoFrame> media_frame =
      CreateDefaultBlackMediaVideoFrame();
  auto* blink_frame =
      CreateBlinkVideoFrame(media_frame, scope.GetExecutionContext());

  // Background blur not populated when it isn't present on `media_frame`.
  EXPECT_EQ(
      blink_frame->metadata(scope.GetExceptionState())->hasBackgroundBlur(),
      false);

  // Background blur enabled is passed through.
  media_frame->metadata().background_blur = media::EffectInfo{.enabled = true};
  EXPECT_EQ(blink_frame->metadata(scope.GetExceptionState())
                ->backgroundBlur()
                ->enabled(),
            true);

  // Background blur disabled is passed through.
  media_frame->metadata().background_blur = media::EffectInfo{.enabled = false};
  EXPECT_EQ(blink_frame->metadata(scope.GetExceptionState())
                ->backgroundBlur()
                ->enabled(),
            false);
}

}  // namespace

}  // namespace blink

"""

```