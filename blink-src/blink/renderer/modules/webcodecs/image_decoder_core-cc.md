Response:
My thought process to analyze the provided C++ code and generate the comprehensive explanation goes through these steps:

1. **Understand the Goal:** The request is to understand the functionality of the `image_decoder_core.cc` file within the Chromium Blink rendering engine. The explanation needs to cover its core purpose, its relation to web technologies (JavaScript, HTML, CSS), illustrate logic with examples, identify potential user errors, and provide a debugging perspective.

2. **Initial Code Scan (Keywords and Structure):** I quickly scan the code for key terms and structural elements:
    * `#include`: Identifies dependencies on other Chromium components (like `media`, `platform`, `graphics`) and third-party libraries (like `skia`). This suggests the file deals with media decoding and rendering.
    * `namespace blink`: Confirms it's part of the Blink rendering engine.
    * `class ImageDecoderCore`:  The central class. Its methods likely define the core functionalities.
    * Constructor (`ImageDecoderCore(...)`):  Handles initialization, taking MIME type, data, and other options.
    * `DecodeMetadata()`, `Decode()`: Core decoding functionalities. `DecodeMetadata` likely gets basic image info, while `Decode` processes frames.
    * `AppendData()`:  Deals with feeding image data.
    * `Clear()`, `Reinitialize()`:  Lifecycle management.
    * `MaybeDecodeToYuv()`: Suggests handling YUV color spaces, crucial for video and some image formats.
    * `GetTimestampForFrame()`:  Related to animation timing.
    * Usage of `base::UmaHistogramEnumeration`: Indicates metric tracking for performance analysis.
    * Use of `SkImage`, `media::VideoFrame`:  Confirms interaction with Skia for image manipulation and the media framework for video frames.

3. **Deconstruct Functionality by Method:** I go through each significant method to understand its specific role:
    * **Constructor:**  Sets up the decoder based on the provided parameters. Crucially, it initializes an `ImageDecoder` (likely an interface or abstract class handled by platform-specific implementations).
    * **`DecodeMetadata()`:**  Focuses on retrieving basic image properties without fully decoding pixel data. This is important for quickly getting information like image size and frame count.
    * **`Decode()`:** This is the core decoding method. I break down its logic:
        * Handles abortion.
        * Checks for decoding errors and available size.
        * Manages YUV decoding as a potentially separate path.
        * Decodes individual frames using the underlying `ImageDecoder`.
        * Handles complete vs. incomplete frames.
        * Converts decoded data to `SkImage` and `media::VideoFrame`.
        * Manages frame timestamps and durations (for animations).
        * Implements a simple optimization for in-order decoding.
    * **`AppendData()`:** Manages the input stream of image data.
    * **`Clear()`:** Resets the decoder state.
    * **`Reinitialize()`:** Creates a new decoder instance.
    * **`MaybeDecodeToYuv()`:** Handles the specific logic for decoding to YUV format. This includes color space conversions.
    * **`GetTimestampForFrame()`:** Calculates or retrieves frame timestamps, crucial for animation synchronization.

4. **Identify Relationships with Web Technologies:**
    * **JavaScript:** The `ImageDecoderCore` is part of the implementation for the WebCodecs API's `ImageDecoder` interface. JavaScript code interacts with this API to decode image data provided through `fetch` or other means.
    * **HTML:** The decoded image data is ultimately used to render images within HTML elements like `<img>` or `<canvas>`. The `src` attribute of `<img>` or drawing operations on `<canvas>` trigger the decoding process.
    * **CSS:** CSS properties like `background-image` can also trigger image loading and decoding. However, the direct interaction with `ImageDecoderCore` is less direct compared to JavaScript.

5. **Construct Examples (Logic and User Errors):**
    * **Logic:** I think of common scenarios and how the code handles them. For example, decoding the first frame vs. subsequent frames, handling animated images, dealing with incomplete data, and the YUV decoding path.
    * **User Errors:** I consider common mistakes developers might make when using the WebCodecs API, such as providing incorrect data, trying to decode beyond the available frames, or misunderstanding the asynchronous nature of the decoding process.

6. **Develop Debugging Scenarios:** I imagine a typical debugging situation: an image not displaying correctly. I then trace the steps a developer might take, starting from inspecting network requests, checking JavaScript code, and potentially diving into the browser's developer tools to examine the decoding process. The `AppendData` method becomes a key point for verifying data flow.

7. **Organize and Refine:**  Finally, I structure the information logically, starting with a high-level overview and then going into more detail for each aspect. I use clear headings and bullet points to improve readability. I ensure the explanation is comprehensive and addresses all parts of the original request. I also review for clarity and accuracy.

Essentially, I'm playing the role of a code reviewer or documentation writer, trying to understand the purpose and intricacies of the code and explain it in a way that is accessible and useful to others, especially developers working with web technologies.


This C++ source file, `image_decoder_core.cc`, located within the `blink/renderer/modules/webcodecs` directory of the Chromium project, implements the core logic for decoding image data within the WebCodecs API. WebCodecs allows web developers to work with raw video and image data in a more performant way.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Image Decoding Management:**
   - It acts as a central point for managing the decoding process of various image formats.
   - It utilizes the platform's image decoding capabilities through the `ImageDecoder` class (likely an interface with platform-specific implementations).
   - It handles the lifecycle of the decoding process, including initialization, data feeding, decoding, and clearing resources.

2. **Asynchronous Data Handling:**
   - It receives image data incrementally through the `AppendData` method. This allows for efficient handling of large image files or streaming scenarios.
   - It maintains a `SharedBuffer` (`stream_buffer_`) to store the received data.

3. **Metadata Extraction:**
   - The `DecodeMetadata` method retrieves essential information about the image without fully decoding it, such as:
     - Whether the data is complete.
     - If the image size is available.
     - The number of frames in animated images.
     - The repetition count for animations.
     - Whether the image has both still and animated sub-images.
     - If the decoding process has failed.

4. **Frame-by-Frame Decoding:**
   - The `Decode` method is responsible for decoding individual frames of the image.
   - It can decode either to an `SkImage` (Skia's representation of an image) or a `media::VideoFrame` (Chromium's representation for video frames).
   - It supports both complete frame decoding and partial decoding.
   - It handles aborting the decoding process if an abort flag is set.

5. **YUV Decoding Support:**
   - It includes logic for decoding images directly into the YUV color space, which is often more efficient for video processing.
   - The `MaybeDecodeToYuv` method handles this specific decoding path.
   - It converts between Skia's YUV color space and Chromium's `gfx::ColorSpace`.

6. **Color Space Management:**
   - It manages color space information for decoded images, converting between different representations (Skia and Chromium's `gfx::ColorSpace`).
   - It attempts to guess the color primary and transfer characteristics based on the YUV color space if explicit information is not available.

7. **Timestamp and Duration Handling (for Animations):**
   - It calculates and stores timestamps for each frame in animated images using the `GetTimestampForFrame` method.
   - It uses frame durations provided by the underlying `ImageDecoder`.

8. **Memory Management:**
   - It clears cached data to optimize memory usage, especially for animated images, using `decoder_->ClearCacheExceptFrame()`.

9. **Metrics Reporting:**
   - It uses `base::UmaHistogramEnumeration` to record the types of images being decoded, likely for performance analysis and usage tracking.

**Relationship with JavaScript, HTML, and CSS:**

This C++ file is a low-level implementation detail of the WebCodecs API, which is exposed to JavaScript. Here's how it relates:

* **JavaScript (WebCodecs API):**
    - The `ImageDecoderCore` class directly supports the functionality of the `ImageDecoder` interface in the WebCodecs API.
    - **Example:** In JavaScript, you might create an `ImageDecoder` instance and feed it data using its `decode()` method. The underlying implementation in `image_decoder_core.cc` would handle the actual decoding.
    ```javascript
    const decoder = new ImageDecoder({ type: 'image/jpeg' });
    fetch('image.jpg')
      .then(response => response.arrayBuffer())
      .then(buffer => decoder.decode(buffer))
      .then(frame => {
        // 'frame' contains the decoded image data
        console.log(frame.image); // An ImageBitmap
      });
    ```
    - The `AppendData` method in C++ is called when you provide data to the JavaScript `ImageDecoder`. The `Decode` method in C++ is triggered when the JavaScript `decode()` method needs to produce a result.

* **HTML:**
    - While not directly interacting with this specific C++ file, the output of the decoding process (the decoded image data) is often used to render images in HTML elements.
    - **Example:** The `ImageBitmap` obtained from the WebCodecs `ImageDecoder` can be used as the `src` of an `<img>` tag or drawn onto a `<canvas>` element.
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    // ... after decoding ...
    ctx.drawImage(frame.image, 0, 0);
    ```

* **CSS:**
    - Similar to HTML, CSS can trigger image loading (e.g., `background-image`). While WebCodecs offers more control, the browser's built-in image decoding mechanisms (which might involve similar but separate C++ code) are typically used for CSS images. WebCodecs provides a more direct and controllable way to handle image data, often used for advanced manipulations or performance-critical scenarios.

**Logic Reasoning with Assumptions:**

**Assumption:** A user wants to decode a multi-frame animated GIF image.

**Input:**
- `mime_type_`: "image/gif"
- `data`: A `SharedBuffer` containing the raw bytes of the GIF file.
- `frame_index`: 1 (to decode the second frame)

**Process within `Decode()`:**

1. The method checks if decoding is aborted or if there's a previous error.
2. It checks if the decoder knows the image size.
3. It verifies if the requested `frame_index` is within the valid range.
4. **YUV Decoding Check:** For GIFs (typically RGB), this path is likely skipped or doesn't apply.
5. `decoder_->DecodeFrameBufferAtIndex(frame_index)` is called. This is where the underlying GIF decoding logic (likely in a platform-specific decoder) is executed to produce the raw pixel data for the second frame.
6. If decoding fails, an error status is returned.
7. If no image data is available for the requested frame yet, `Status::kNoImage` is returned.
8. The `ImageFrame` object returned contains the decoded pixel data.
9. The code checks if the frame is completely decoded (`ImageFrame::kFrameComplete`).
10. The decoded data is converted to an `SkImage`.
11. Frame duration for this frame is retrieved using `decoder_->FrameDurationAtIndex(frame_index)`.
12. A `media::VideoFrame` is created, wrapping the `SkImage` and including the timestamp and duration.

**Output:**
- `result->status`: `Status::kOk`
- `result->sk_image`: An `SkImage` object containing the pixel data of the second frame of the GIF.
- `result->frame`: A `media::VideoFrame` object representing the second frame, including its timestamp and duration.
- `result->complete`: `true` (assuming the frame is fully decoded).

**User or Programming Common Usage Errors:**

1. **Providing Incorrect MIME Type:**
   - **Example:**  Creating an `ImageDecoderCore` with `mime_type_` set to "image/png" but providing JPEG data.
   - **Consequence:** The underlying `ImageDecoder::CreateByMimeType` will likely fail to create the correct decoder, leading to decoding errors later.

2. **Calling `Decode` with an Invalid `frame_index`:**
   - **Example:**  For a GIF with 5 frames (indices 0-4), calling `Decode(5, ...)` when `data_complete_` is true.
   - **Consequence:** The `Decode` method will return `Status::kIndexError`.

3. **Not Providing Enough Data:**
   - **Example:**  Calling `Decode` with `complete_frames_only` set to `true` before all the data for a frame has been appended via `AppendData`.
   - **Consequence:** The `Decode` method will return `Status::kNoImage` until enough data is available.

4. **Incorrectly Handling Asynchronous Decoding:**
   - **Example:**  Trying to access decoded image data immediately after calling `AppendData` without waiting for the decoding to complete (which is typically handled via Promises in the JavaScript WebCodecs API).
   - **Consequence:** The image might not be fully decoded yet, leading to incomplete or missing data.

5. **Memory Leaks (Less likely with proper WebCodecs API usage but possible in internal debugging):**
   - **Example:**  Not properly calling `Clear()` or allowing the `ImageDecoderCore` object to be deallocated, potentially leaving allocated memory associated with the underlying decoder.

**User Operation Steps to Reach Here (Debugging Clues):**

Let's imagine a scenario where a web developer is using the WebCodecs API to decode an animated WebP image and is encountering issues with frame rendering. Here's how the execution might reach `image_decoder_core.cc`:

1. **User Interaction (JavaScript):** The user's JavaScript code initiates the decoding process:
   ```javascript
   const decoder = new ImageDecoder({ type: 'image/webp' });
   fetch('animated.webp')
     .then(response => response.arrayBuffer())
     .then(buffer => {
       decoder.decode(buffer).then(frame1 => {
         // Process frame 1
         decoder.decode().then(frame2 => { // Request next frame
           // Process frame 2
         });
       });
     });
   ```

2. **WebCodecs API Call (Browser Internals):** When `decoder.decode(buffer)` or `decoder.decode()` is called in JavaScript, the browser's WebCodecs implementation (likely in JavaScript and C++ bindings) receives this request.

3. **`ImageDecoder` Instantiation (C++):** The JavaScript call leads to the creation of an `ImageDecoderCore` instance in C++. The `mime_type_` will be "image/webp", and the initial data (if provided) will be passed to the constructor.

4. **Data Appending (`AppendData`):** If the image data is fetched in chunks, the `AppendData` method will be called multiple times as data arrives. The `stream_buffer_` will accumulate the image bytes.

5. **Decoding Triggered (`Decode`):** When the JavaScript `decode()` method's Promise resolves (or when a specific frame is requested), the `Decode` method in `image_decoder_core.cc` is invoked. The `frame_index` will indicate which frame is being requested.

6. **Stepping Through `Decode` (Debugger):**  If the developer is debugging, they might set breakpoints within the `Decode` method in `image_decoder_core.cc` to inspect the state:
   - Check the value of `frame_index`.
   - Examine the contents of the `stream_buffer_`.
   - Step into the call to `decoder_->DecodeFrameBufferAtIndex(frame_index)` to see if the underlying WebP decoder is functioning correctly.
   - Inspect the `ImageFrame` object to see if the pixel data is as expected.
   - Verify the calculated timestamp and duration for the frame.

7. **YUV Path (If Applicable):** For certain WebP images or if the developer explicitly requests YUV output (though less common for WebP), the execution might go through the `MaybeDecodeToYuv` path.

8. **Error Handling:** If the decoding process encounters an error (e.g., invalid WebP data), the `decoder_->Failed()` check will return `true`, and the `Decode` method will return an error status.

By stepping through the code in `image_decoder_core.cc`, a developer can understand:

- If the image data is being received correctly in `AppendData`.
- If the correct underlying decoder is being used for the given MIME type.
- If the decoding process within `decoder_->DecodeFrameBufferAtIndex()` is successful.
- If there are any issues with timestamp or duration calculation.
- The exact point where a decoding error might be occurring.

This detailed breakdown helps in understanding the crucial role of `image_decoder_core.cc` in the image decoding pipeline within the Chromium browser and its interaction with the WebCodecs API.

Prompt: 
```
这是目录为blink/renderer/modules/webcodecs/image_decoder_core.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/image_decoder_core.h"

#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/safe_conversions.h"
#include "base/time/time.h"
#include "media/base/timestamp_constants.h"
#include "media/base/video_frame.h"
#include "media/base/video_util.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image_metrics.h"
#include "third_party/blink/renderer/platform/graphics/video_frame_image_util.h"
#include "third_party/blink/renderer/platform/image-decoders/segment_reader.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkYUVAPixmaps.h"

namespace blink {

namespace {

media::VideoPixelFormat YUVSubsamplingToMediaPixelFormat(
    cc::YUVSubsampling sampling,
    int depth) {
  // TODO(crbug.com/1073995): Add support for high bit depth format.
  if (depth != 8)
    return media::PIXEL_FORMAT_UNKNOWN;

  switch (sampling) {
    case cc::YUVSubsampling::k420:
      return media::PIXEL_FORMAT_I420;
    case cc::YUVSubsampling::k422:
      return media::PIXEL_FORMAT_I422;
    case cc::YUVSubsampling::k444:
      return media::PIXEL_FORMAT_I444;
    default:
      return media::PIXEL_FORMAT_UNKNOWN;
  }
}

std::pair<gfx::ColorSpace::PrimaryID, gfx::ColorSpace::TransferID>
GuessPrimaryAndTransfer(SkYUVColorSpace yuv_cs) {
  switch (yuv_cs) {
    case kJPEG_Full_SkYUVColorSpace:
      return {gfx::ColorSpace::PrimaryID::BT709,
              gfx::ColorSpace::TransferID::SRGB};
    case kFCC_Full_SkYUVColorSpace:
    case kFCC_Limited_SkYUVColorSpace:
    case kRec601_Limited_SkYUVColorSpace:
      return {gfx::ColorSpace::PrimaryID::SMPTE170M,
              gfx::ColorSpace::TransferID::SMPTE170M};
    case kRec709_Limited_SkYUVColorSpace:
    case kRec709_Full_SkYUVColorSpace:
    // Unclear what these should be, so guess BT.709.
    case kYDZDX_Full_SkYUVColorSpace:
    case kYDZDX_Limited_SkYUVColorSpace:
    case kYCgCo_8bit_Full_SkYUVColorSpace:
    case kYCgCo_10bit_Full_SkYUVColorSpace:
    case kYCgCo_12bit_Full_SkYUVColorSpace:
    case kYCgCo_16bit_Full_SkYUVColorSpace:
    case kYCgCo_8bit_Limited_SkYUVColorSpace:
    case kYCgCo_10bit_Limited_SkYUVColorSpace:
    case kYCgCo_12bit_Limited_SkYUVColorSpace:
    case kYCgCo_16bit_Limited_SkYUVColorSpace:
      return {gfx::ColorSpace::PrimaryID::BT709,
              gfx::ColorSpace::TransferID::BT709};
    case kBT2020_8bit_Full_SkYUVColorSpace:
    case kBT2020_10bit_Full_SkYUVColorSpace:
    case kBT2020_8bit_Limited_SkYUVColorSpace:
    case kBT2020_10bit_Limited_SkYUVColorSpace:
      return {gfx::ColorSpace::PrimaryID::BT2020,
              gfx::ColorSpace::TransferID::BT2020_10};
    case kBT2020_12bit_Full_SkYUVColorSpace:
    case kBT2020_16bit_Full_SkYUVColorSpace:
    case kBT2020_12bit_Limited_SkYUVColorSpace:
    case kBT2020_16bit_Limited_SkYUVColorSpace:
      return {gfx::ColorSpace::PrimaryID::BT2020,
              gfx::ColorSpace::TransferID::BT2020_12};
    case kSMPTE240_Full_SkYUVColorSpace:
    case kSMPTE240_Limited_SkYUVColorSpace:
      return {gfx::ColorSpace::PrimaryID::SMPTE240M,
              gfx::ColorSpace::TransferID::SMPTE240M};
    case kGBR_Full_SkYUVColorSpace:
    case kGBR_Limited_SkYUVColorSpace:
      return {gfx::ColorSpace::PrimaryID::BT709,
              gfx::ColorSpace::TransferID::SRGB};
    case kIdentity_SkYUVColorSpace:
      NOTREACHED();
  };
}

gfx::ColorSpace YUVColorSpaceToGfxColorSpace(SkYUVColorSpace yuv_cs,
                                             const gfx::ColorSpace& gfx_cs) {
  auto primary_id = gfx_cs.GetPrimaryID();
  auto transfer_id = gfx_cs.GetTransferID();
  if (!gfx_cs.IsValid()) {
    std::tie(primary_id, transfer_id) = GuessPrimaryAndTransfer(yuv_cs);
  }
  skcms_Matrix3x3 custom_primaries;
  skcms_Matrix3x3* custom_primaries_ptr = nullptr;
  if (primary_id == gfx::ColorSpace::PrimaryID::CUSTOM) {
    gfx_cs.GetPrimaryMatrix(&custom_primaries);
    custom_primaries_ptr = &custom_primaries;
  }

  skcms_TransferFunction custom_transfer;
  skcms_TransferFunction* custom_transfer_ptr = nullptr;
  if (transfer_id == gfx::ColorSpace::TransferID::CUSTOM ||
      transfer_id == gfx::ColorSpace::TransferID::CUSTOM_HDR) {
    const auto success = gfx_cs.GetTransferFunction(&custom_transfer);
    DCHECK(success);  // Should never fail for CUSTOM*.
    custom_transfer_ptr = &custom_transfer;
  }

  switch (yuv_cs) {
    case kJPEG_Full_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::SMPTE170M,
                             gfx::ColorSpace::RangeID::FULL,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kRec601_Limited_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::SMPTE170M,
                             gfx::ColorSpace::RangeID::LIMITED,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kRec709_Full_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::BT709,
                             gfx::ColorSpace::RangeID::FULL,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kRec709_Limited_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::BT709,
                             gfx::ColorSpace::RangeID::LIMITED,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kBT2020_8bit_Full_SkYUVColorSpace:
    case kBT2020_10bit_Full_SkYUVColorSpace:
    case kBT2020_12bit_Full_SkYUVColorSpace:
    case kBT2020_16bit_Full_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::BT2020_NCL,
                             gfx::ColorSpace::RangeID::FULL,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kBT2020_8bit_Limited_SkYUVColorSpace:
    case kBT2020_10bit_Limited_SkYUVColorSpace:
    case kBT2020_12bit_Limited_SkYUVColorSpace:
    case kBT2020_16bit_Limited_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::BT2020_NCL,
                             gfx::ColorSpace::RangeID::LIMITED,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kFCC_Full_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::FCC,
                             gfx::ColorSpace::RangeID::FULL,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kFCC_Limited_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::FCC,
                             gfx::ColorSpace::RangeID::LIMITED,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kSMPTE240_Full_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::SMPTE240M,
                             gfx::ColorSpace::RangeID::FULL,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kSMPTE240_Limited_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::SMPTE240M,
                             gfx::ColorSpace::RangeID::LIMITED,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kYDZDX_Full_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::YDZDX,
                             gfx::ColorSpace::RangeID::FULL,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kYDZDX_Limited_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::YDZDX,
                             gfx::ColorSpace::RangeID::LIMITED,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kGBR_Full_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::GBR,
                             gfx::ColorSpace::RangeID::FULL,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kGBR_Limited_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::GBR,
                             gfx::ColorSpace::RangeID::LIMITED,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kYCgCo_8bit_Full_SkYUVColorSpace:
    case kYCgCo_10bit_Full_SkYUVColorSpace:
    case kYCgCo_12bit_Full_SkYUVColorSpace:
    case kYCgCo_16bit_Full_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::YCOCG,
                             gfx::ColorSpace::RangeID::FULL,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kYCgCo_8bit_Limited_SkYUVColorSpace:
    case kYCgCo_10bit_Limited_SkYUVColorSpace:
    case kYCgCo_12bit_Limited_SkYUVColorSpace:
    case kYCgCo_16bit_Limited_SkYUVColorSpace:
      return gfx::ColorSpace(primary_id, transfer_id,
                             gfx::ColorSpace::MatrixID::YCOCG,
                             gfx::ColorSpace::RangeID::LIMITED,
                             custom_primaries_ptr, custom_transfer_ptr);
    case kIdentity_SkYUVColorSpace:
      NOTREACHED();
  };
}

}  // namespace

ImageDecoderCore::ImageDecoderCore(
    String mime_type,
    scoped_refptr<SegmentReader> data,
    bool data_complete,
    ColorBehavior color_behavior,
    const SkISize& desired_size,
    ImageDecoder::AnimationOption animation_option)
    : mime_type_(mime_type),
      color_behavior_(color_behavior),
      desired_size_(desired_size),
      animation_option_(animation_option),
      data_complete_(data_complete),
      segment_reader_(std::move(data)) {
  if (!segment_reader_) {
    stream_buffer_ = WTF::SharedBuffer::Create();
    segment_reader_ = SegmentReader::CreateFromSharedBuffer(stream_buffer_);
  }

  Reinitialize(animation_option_);

  base::UmaHistogramEnumeration("Blink.WebCodecs.ImageDecoder.Type",
                                BitmapImageMetrics::StringToDecodedImageType(
                                    decoder_->FilenameExtension()));
}

ImageDecoderCore::~ImageDecoderCore() = default;

ImageDecoderCore::ImageMetadata ImageDecoderCore::DecodeMetadata() {
  DCHECK(decoder_);

  ImageDecoderCore::ImageMetadata metadata;
  metadata.data_complete = data_complete_;

  if (!decoder_->IsSizeAvailable()) {
    // Decoding has failed if we have no size and no more data.
    metadata.failed = decoder_->Failed() || data_complete_;
    return metadata;
  }

  metadata.has_size = true;
  metadata.frame_count = base::checked_cast<uint32_t>(decoder_->FrameCount());
  metadata.repetition_count = decoder_->RepetitionCount();
  metadata.image_has_both_still_and_animated_sub_images =
      decoder_->ImageHasBothStillAndAnimatedSubImages();

  // It's important that |failed| is set last since some of the methods above
  // may trigger operations which can lead to failure.
  metadata.failed = decoder_->Failed();
  return metadata;
}

std::unique_ptr<ImageDecoderCore::ImageDecodeResult> ImageDecoderCore::Decode(
    uint32_t frame_index,
    bool complete_frames_only,
    const base::AtomicFlag* abort_flag) {
  DCHECK(decoder_);

  auto result = std::make_unique<ImageDecodeResult>();
  result->frame_index = frame_index;

  if (abort_flag->IsSet()) {
    result->status = Status::kAborted;
    return result;
  }

  if (decoder_->Failed()) {
    result->status = Status::kDecodeError;
    return result;
  }

  if (!decoder_->IsSizeAvailable()) {
    result->status = Status::kNoImage;
    return result;
  }

  if (data_complete_ && frame_index >= decoder_->FrameCount()) {
    result->status = Status::kIndexError;
    return result;
  }

  // Due to implementation limitations YUV support for some formats is only
  // known once all data is received. Animated images are never supported.
  if (decoder_->CanDecodeToYUV() && !have_completed_rgb_decode_ &&
      frame_index == 0u) {
    if (!have_completed_yuv_decode_) {
      MaybeDecodeToYuv();
      if (decoder_->Failed()) {
        result->status = Status::kDecodeError;
        return result;
      }
    }

    if (have_completed_yuv_decode_) {
      result->status = Status::kOk;
      result->frame = yuv_frame_;
      result->complete = true;
      return result;
    }
  }

  auto* image = decoder_->DecodeFrameBufferAtIndex(frame_index);
  if (decoder_->Failed()) {
    result->status = Status::kDecodeError;
    return result;
  }

  if (!image) {
    result->status = Status::kNoImage;
    return result;
  }

  // Nothing to do if nothing has been decoded yet.
  if (image->GetStatus() == ImageFrame::kFrameEmpty ||
      image->GetStatus() == ImageFrame::kFrameInitialized) {
    result->status = Status::kNoImage;
    return result;
  }

  have_completed_rgb_decode_ = true;

  // Only satisfy fully complete decode requests. Treat partial decodes as
  // complete if we've received all the data we ever will.
  const bool is_complete = image->GetStatus() == ImageFrame::kFrameComplete;
  if (!is_complete && complete_frames_only) {
    result->status = Status::kNoImage;
    return result;
  }

  // Prefer FinalizePixelsAndGetImage() since that will mark the underlying
  // bitmap as immutable, which allows copies to be avoided.
  auto sk_image = is_complete ? image->FinalizePixelsAndGetImage()
                              : SkImages::RasterFromBitmap(image->Bitmap());
  if (!sk_image) {
    NOTREACHED() << "Failed to retrieve SkImage for decoded image.";
  }

  if (!is_complete) {
    auto generation_id = image->Bitmap().getGenerationID();
    auto it = incomplete_frames_.find(frame_index);
    if (it == incomplete_frames_.end()) {
      incomplete_frames_.Set(frame_index, generation_id);
    } else {
      // Don't fulfill the promise until a new bitmap is seen.
      if (it->value == generation_id) {
        result->status = Status::kNoImage;
        return result;
      }

      it->value = generation_id;
    }
  } else {
    incomplete_frames_.erase(frame_index);
  }

  // This is zero copy; the VideoFrame points into the SkBitmap.
  const gfx::Size coded_size(sk_image->width(), sk_image->height());
  auto frame =
      media::CreateFromSkImage(sk_image, gfx::Rect(coded_size), coded_size,
                               GetTimestampForFrame(frame_index));
  if (!frame) {
    result->status = Status::kDecodeError;
    return result;
  }

  if (auto sk_cs = decoder_->ColorSpaceForSkImages()) {
    auto gfx_cs = gfx::ColorSpace(*sk_cs);
    if (gfx_cs.IsValid()) {
      frame->set_color_space(gfx_cs);
    }
  }

  frame->metadata().transformation =
      ImageOrientationToVideoTransformation(decoder_->Orientation());

  // Only animated images have frame durations.
  if (decoder_->FrameCount() > 1 ||
      decoder_->RepetitionCount() != kAnimationNone) {
    frame->metadata().frame_duration =
        decoder_->FrameDurationAtIndex(frame_index);
  }

  if (is_decoding_in_order_) {
    // Stop aggressive purging when out of order decoding is detected.
    if (last_decoded_frame_ != frame_index &&
        ((last_decoded_frame_ + 1) % decoder_->FrameCount()) != frame_index) {
      is_decoding_in_order_ = false;
    } else {
      decoder_->ClearCacheExceptFrame(frame_index);
    }
    last_decoded_frame_ = frame_index;
  }

  result->status = Status::kOk;
  result->sk_image = std::move(sk_image);
  result->frame = std::move(frame);
  result->complete = is_complete;
  return result;
}

void ImageDecoderCore::AppendData(Vector<uint8_t> data, bool data_complete) {
  DCHECK(stream_buffer_);
  DCHECK(stream_buffer_);
  DCHECK(!data_complete_);
  data_complete_ = data_complete;
  if (!data.empty()) {
    stream_buffer_->Append(std::move(data));
  }

  // We may not have a decoder if Clear() was called while data arrives.
  if (decoder_)
    decoder_->SetData(stream_buffer_, data_complete_);
}

void ImageDecoderCore::Clear() {
  decoder_.reset();
  incomplete_frames_.clear();
  yuv_frame_ = nullptr;
  have_completed_rgb_decode_ = false;
  have_completed_yuv_decode_ = false;
  last_decoded_frame_ = 0u;
  is_decoding_in_order_ = true;
  timestamp_cache_.clear();
  timestamp_cache_.emplace_back();
}

void ImageDecoderCore::Reinitialize(
    ImageDecoder::AnimationOption animation_option) {
  Clear();
  animation_option_ = animation_option;
  decoder_ = ImageDecoder::CreateByMimeType(
      mime_type_, segment_reader_, data_complete_,
      ImageDecoder::kAlphaNotPremultiplied,
      ImageDecoder::HighBitDepthDecodingOption::kDefaultBitDepth,
      color_behavior_, cc::AuxImage::kDefault,
      Platform::GetMaxDecodedImageBytes(), desired_size_, animation_option_);
  DCHECK(decoder_);
}

bool ImageDecoderCore::FrameIsDecodedAtIndexForTesting(
    uint32_t frame_index) const {
  return decoder_->FrameIsDecodedAtIndex(frame_index);
}

void ImageDecoderCore::MaybeDecodeToYuv() {
  DCHECK(!have_completed_rgb_decode_);
  DCHECK(!have_completed_yuv_decode_);

  const auto format = YUVSubsamplingToMediaPixelFormat(
      decoder_->GetYUVSubsampling(), decoder_->GetYUVBitDepth());
  if (format == media::PIXEL_FORMAT_UNKNOWN)
    return;

  // In the event of a partial decode |yuv_frame_| may have been created, but
  // not populated with image data. To avoid thrashing as bytes come in, only
  // create the frame once.
  if (!yuv_frame_) {
    const auto coded_size = decoder_->DecodedYUVSize(cc::YUVIndex::kY);

    // Plane sizes are guaranteed to fit in an int32_t by
    // ImageDecoder::SetSize(); since YUV is 1 byte-per-channel, we can just
    // check width * height.
    DCHECK(coded_size.GetCheckedArea().IsValid());
    auto layout = media::VideoFrameLayout::CreateWithStrides(
        format, coded_size,
        {decoder_->DecodedYUVWidthBytes(cc::YUVIndex::kY),
         decoder_->DecodedYUVWidthBytes(cc::YUVIndex::kU),
         decoder_->DecodedYUVWidthBytes(cc::YUVIndex::kV)});
    if (!layout)
      return;

    yuv_frame_ = media::VideoFrame::CreateFrameWithLayout(
        *layout, gfx::Rect(coded_size), coded_size, media::kNoTimestamp,
        /*zero_initialize_memory=*/false);
    if (!yuv_frame_)
      return;
  }

  void* planes[cc::kNumYUVPlanes] = {yuv_frame_->writable_data(0),
                                     yuv_frame_->writable_data(1),
                                     yuv_frame_->writable_data(2)};
  wtf_size_t row_bytes[cc::kNumYUVPlanes] = {
      static_cast<wtf_size_t>(yuv_frame_->stride(0)),
      static_cast<wtf_size_t>(yuv_frame_->stride(1)),
      static_cast<wtf_size_t>(yuv_frame_->stride(2))};

  // TODO(crbug.com/1073995): Add support for high bit depth format.
  const auto color_type = kGray_8_SkColorType;

  auto image_planes =
      std::make_unique<ImagePlanes>(planes, row_bytes, color_type);
  decoder_->SetImagePlanes(std::move(image_planes));
  decoder_->DecodeToYUV();
  if (decoder_->Failed() || !decoder_->HasDisplayableYUVData())
    return;

  have_completed_yuv_decode_ = true;

  gfx::ColorSpace gfx_cs;
  if (auto sk_cs = decoder_->ColorSpaceForSkImages())
    gfx_cs = gfx::ColorSpace(*sk_cs);

  const auto skyuv_cs = decoder_->GetYUVColorSpace();
  DCHECK_NE(skyuv_cs, kIdentity_SkYUVColorSpace);

  yuv_frame_->set_timestamp(GetTimestampForFrame(0));
  yuv_frame_->metadata().transformation =
      ImageOrientationToVideoTransformation(decoder_->Orientation());
  yuv_frame_->set_color_space(YUVColorSpaceToGfxColorSpace(skyuv_cs, gfx_cs));
}

base::TimeDelta ImageDecoderCore::GetTimestampForFrame(uint32_t index) const {
  // The zero entry is always populated by this point.
  DCHECK_GE(timestamp_cache_.size(), 1u);

  auto ts = decoder_->FrameTimestampAtIndex(index);
  if (ts.has_value())
    return *ts;

  if (index < timestamp_cache_.size())
    return timestamp_cache_[index];

  // Calling FrameCount() ensures duration information is populated for every
  // frame up to the current count. DecodeFrameBufferAtIndex() or DecodeToYUV()
  // have also been called this point, so index is always valid.
  DCHECK_LT(index, decoder_->FrameCount());
  DCHECK(!decoder_->Failed());

  const auto old_size = timestamp_cache_.size();
  timestamp_cache_.resize(decoder_->FrameCount());
  for (auto i = old_size; i < timestamp_cache_.size(); ++i) {
    timestamp_cache_[i] =
        timestamp_cache_[i - 1] + decoder_->FrameDurationAtIndex(i - 1);
  }

  return timestamp_cache_[index];
}

}  // namespace blink

"""

```